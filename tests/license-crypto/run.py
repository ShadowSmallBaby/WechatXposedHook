"""桌面校验 native 授权加密链路:license_crypto.inc 与 Python 参考实现逐项对照。

用主机 clang 直接编 app/src/main/jni/license_crypto.inc(纯算法,无 JNI),
跑一组命令与 scripts/generate_min_db.py 的输出比对:
  - 第一层加密(AES-256-CBC + Base64);
  - LIC 第 3 段(SHA-256(账号) 派生 + AES);
  - 段 3 的逆运算;
  - blob 编码;
  - isUsable 的四个分支(对/错账号 × LIC/verifier6)。

主机是 x86_64,arm64 的 so 加载不了,所以这里验证算法本身;
真机上 so 的加载与 JNI 绑定由 tests/license-data/run.py 覆盖。

需要主机 clang(NDK 里的 windows-x86_64 clang 即可)。
"""
import argparse
import importlib.util
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
INC = ROOT / "app/src/main/jni/license_crypto.inc"
SOURCE = HERE / "license_crypto_check.c"

# 覆盖 ASCII、多字节 UTF-8 与空串;账号用固定串(不涉及真实账号)。
PLAINS = ("hello world", "LIC:wxid_00000000000000", "verifier6#D:wxid_a1b2c3d4e5f6g7", "")
ACCOUNTS = ("wxid_00000000000000", "wxid_abcdefghijklmn", "wxid_a1b2c3d4e5f6g7")
WRONG_ACCOUNT = "wxid_zzzzzzzzzzzzzz"


def reference():
    spec = importlib.util.spec_from_file_location(
        "generate_min_db", ROOT / "scripts/generate_min_db.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def build(clang, output):
    output.mkdir(parents=True, exist_ok=True)
    exe = output / "license_crypto_check.exe"
    result = subprocess.run(
        [str(clang), "-O1", "-I", str(ROOT), "-o", str(exe), str(SOURCE)],
        capture_output=True, cwd=ROOT, timeout=180)
    if result.returncode != 0:
        raise RuntimeError(result.stdout.decode("utf-8", "replace")
                           + result.stderr.decode("utf-8", "replace"))
    return exe


def call(exe, *arguments):
    result = subprocess.run([str(exe)] + [str(part) for part in arguments],
                            capture_output=True, cwd=ROOT, timeout=60)
    if result.returncode != 0:
        raise RuntimeError(result.stdout.decode("utf-8", "replace")
                           + result.stderr.decode("utf-8", "replace"))
    return result.stdout.decode("utf-8", "replace").rstrip("\r\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clang", type=Path, required=True,
                        help="主机 clang(NDK 的 windows-x86_64 clang)")
    args = parser.parse_args()
    module = reference()
    exe = build(args.clang, ROOT / "build/license-crypto")

    checks = 0
    failures = 0

    def expect(label, actual, wanted):
        nonlocal checks, failures
        checks += 1
        if actual != wanted:
            failures += 1
            print(f"FAIL {label}\n  c   : {actual!r}\n  py  : {wanted!r}")

    for plain in PLAINS:
        expect(f"encrypt {plain!r}", call(exe, "encrypt", plain), module.enc(plain))
        expect(f"encodeblob {plain!r}", call(exe, "encodeblob", plain),
               module.encode_blob(plain))

    for account in ACCOUNTS:
        segment = module.lic_seg3(account)
        expect(f"segment3 {account}", call(exe, "segment3", account), segment)
        expect(f"decode3 {account}", call(exe, "decode3", segment, account),
               module.lic_seg3_decrypt(segment, account))

    # isUsable 的四个分支:LIC / verifier6 × 对账号 / 错账号。
    for account in ACCOUNTS:
        rows = {tag: value for tag, _, value in module.build_rows(account)}
        expect(f"LIC usable {account}",
               call(exe, "usable", rows["LIC"], account, "0"), "1")
        expect(f"LIC wrong {account}",
               call(exe, "usable", rows["LIC"], WRONG_ACCOUNT, "0"), "0")
        expect(f"verifier6 usable {account}",
               call(exe, "usable", rows["verifier6"], account, "1"), "1")
        expect(f"verifier6 wrong {account}",
               call(exe, "usable", rows["verifier6"], WRONG_ACCOUNT, "1"), "0")

    print(f"{'FAIL' if failures else 'PASS'}: {checks - failures}/{checks} 项与参考实现一致")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())