"""校验敏感常量编码:SecretConstants 的密文与 encode_secrets.py 的编码结果一致。

纯 JVM + 主机 clang,不需要设备。桌面校验两件事:
  1. 密文 = 明文表经「常量名派生 HKDF 子密钥 + XOR」编码的结果;
  2. secret_crypto.inc 的 HKDF-SHA256 派生与 encode_secrets.py 的 derive_subkey 逐字节一致
     (C 与 Python 两份实现必须同源,否则真机上全解错)。
明文解码在 so 里,由 run-device.py 在真机上验证。
"""
import argparse
import importlib.util
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LOADER = ROOT / "app/src/main/java/github/shadowbaby/wechatxposed/hook/loader"
HERE = Path(__file__).resolve().parent


def load_encoder():
    """加载 encode_secrets.py,并按 --master-key / WXH_MASTER_KEY 设定主密钥。"""
    spec = importlib.util.spec_from_file_location(
        "encode_secrets", ROOT / "scripts/encode_secrets.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.apply_master_key(os.environ.get("WXH_MASTER_KEY"))
    return module


def secrets_table():
    """明文表(本机的 scripts/secrets_table.py);同时校验常量名与 NAMES 一致。"""
    spec = importlib.util.spec_from_file_location(
        "secrets_table", ROOT / "scripts/secrets_table.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    names = importlib.util.spec_from_file_location(
        "encode_secrets", ROOT / "scripts/encode_secrets.py")
    names_module = importlib.util.module_from_spec(names)
    names.loader.exec_module(names_module)
    missing = [name for name in names_module.NAMES if name not in module.SECRETS]
    extra = [name for name in module.SECRETS if name not in names_module.NAMES]
    if missing or extra:
        raise SystemExit("常量名与 NAMES 不一致: 缺 %s,多 %s" % (missing, extra))
    return module.SECRETS


def run(*command, timeout=180):
    result = subprocess.run([str(part) for part in command], capture_output=True,
                            timeout=timeout, cwd=ROOT)
    if result.returncode != 0:
        raise RuntimeError(result.stdout.decode("utf-8", "replace")
                           + result.stderr.decode("utf-8", "replace"))
    return result.stdout.decode("utf-8", "replace")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jdk", type=Path, required=True)
    parser.add_argument("--clang", type=Path,
                        help="主机 clang(NDK 的 windows-x86_64/linux-x86_64 clang 即可);"
                             "不给则跳过 C/Python 派生一致性检查")
    args = parser.parse_args()
    output = ROOT / "build/secret-encoding"
    classes = output / "classes"
    classes.mkdir(parents=True, exist_ok=True)
    sources = [LOADER / "SecretConstants.java", HERE / "SecretCheck.java"]
    run(args.jdk / "bin/javac.exe", "-encoding", "UTF-8", "-source", "17", "-target", "17",
        "-d", classes, *sources)
    printed = run(args.jdk / "bin/java.exe", "-Dfile.encoding=UTF-8", "-cp", classes,
                  "github.shadowbaby.wechatxposed.hook.loader.SecretCheck")

    actual = {}
    for line in printed.splitlines():
        if "=" in line:
            name, value = line.split("=", 1)
            actual[name] = value

    expected = secrets_table()
    encoder_module = load_encoder()

    failures = 0
    for name, plain in expected.items():
        if name not in actual:
            print("FAIL %s -> 生成的文件里没有这个常量" % name)
            failures += 1
            continue
        want = encoder_module.encode(plain, name)
        if actual[name] != want:
            print("FAIL %s -> 密文与脚本编码结果不一致" % name)
            failures += 1
    extra = set(actual) - set(expected)
    for name in sorted(extra):
        print("FAIL %s -> 脚本表里没有这个常量" % name)
        failures += 1

    derived = 0
    if args.clang:
        derived = check_derivation(args.clang, encoder_module)
        failures += derived

    total = len(expected)
    print(("PASS" if not failures else "FAIL") + ": "
          + str(total - (failures - derived)) + "/" + str(total) + " 个常量密文"
          + (", HKDF 派生一致" if args.clang and not derived else "")
          + (":主密钥来自 WXH_MASTER_KEY" if os.environ.get("WXH_MASTER_KEY") else ""))
    return 1 if failures else 0


def check_derivation(clang: Path, encoder_module) -> int:
    """编 secret_crypto.inc,比对 C 侧 HKDF 派生与 Python 的 derive_subkey。"""
    output = ROOT / "build/secret-encoding"
    output.mkdir(parents=True, exist_ok=True)
    exe = output / ("secret_crypto_check.exe" if os.name == "nt" else "secret_crypto_check")
    command = [str(clang), "-O1", "-I", str(ROOT)]
    # 设了 WXH_MASTER_KEY 时,给 C 侧喂同一把(与 Gradle 给 so 的宏一致),否则编的是默认值。
    if os.environ.get("WXH_MASTER_KEY"):
        byte_list = ", ".join("0x%02x" % byte for byte in encoder_module.MASTER_KEY)
        command.append("-DWXH_MASTER_KEY_BYTES=" + byte_list)
    command += ["-o", str(exe), str(HERE / "secret_crypto_check.c")]
    result = subprocess.run(
        command,
        capture_output=True, cwd=ROOT, timeout=180)
    if result.returncode != 0:
        raise RuntimeError(result.stdout.decode("utf-8", "replace")
                           + result.stderr.decode("utf-8", "replace"))
    printed = subprocess.run([str(exe)] + encoder_module.NAMES, capture_output=True,
                             cwd=ROOT, timeout=60)
    if printed.returncode != 0:
        raise RuntimeError(printed.stderr.decode("utf-8", "replace"))
    mismatches = 0
    lines = 0
    for line in printed.stdout.decode("utf-8", "replace").splitlines():
        if not line.strip():
            continue
        name, hexed = line.split()
        lines += 1
        if encoder_module.derive_subkey(name).hex() != hexed:
            print("FAIL %s -> C 的 HKDF 派生与 Python 不一致" % name)
            mismatches += 1
    if lines != len(encoder_module.NAMES):
        print("FAIL -> C 侧只派生出了 %d 项,应有 %d 项" % (lines, len(encoder_module.NAMES)))
        mismatches += 1
    return mismatches


if __name__ == "__main__":
    sys.exit(main())
