"""对照 scripts/generate_min_db.py 校验 LicenseData 的 Java 实现(需要设备)。

两边输入同一个账号字符串,输出是 FKZ_WX_DATA 那 10 行的 TAG/TYPE/VALUE。
generate_min_db.py 已与设备上被微X 接受的库逐字节一致(data/FKZ_WX_DATA),
所以这里只要两边相等,Java 实现就是可用的。

必须在设备上跑:LicenseData 的 AES 密钥来自 libwexhook.so(敏感常量解码),
桌面 JVM 加载不了 arm64 的 so。
"""
import argparse
import importlib.util
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests"))
import _apk
REMOTE_DIR = "/data/local/tmp"
REMOTE_JAR = REMOTE_DIR + "/license-data-check.jar"
REMOTE_LIB = REMOTE_DIR + "/license-data-lib"

# 账号只影响编码内容,用固定串即可(不涉及真实账号)
ACCOUNTS = ("wxid_00000000000000", "wxid_abcdefghijklmn", "wxid_a1b2c3d4e5f6g7")


def generate_expected():
    spec = importlib.util.spec_from_file_location(
        "generate_min_db", ROOT / "scripts/generate_min_db.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return {account: [(tag, type_, value) for tag, type_, value in module.build_rows(account)]
            for account in ACCOUNTS}


def run_java(sdk, jdk, serial):
    output = ROOT / "build/license-data"
    output.mkdir(parents=True, exist_ok=True)
    classes = output / "classes"
    classes.mkdir(exist_ok=True)
    android = sdk / "platforms/android-36/android.jar"
    sources = [ROOT / "app/src/main/java/github/shadowbaby/wechatxposed/hook/license/LicenseCrypto.java",
               ROOT / "app/src/main/java/github/shadowbaby/wechatxposed/hook/license/LicenseData.java",
               ROOT / "app/src/main/java/github/shadowbaby/wechatxposed/hook/loader/Secret.java",
               ROOT / "app/src/main/java/github/shadowbaby/wechatxposed/hook/loader/SecretConstants.java",
               Path(__file__).parent / "LicenseDataCheck.java"]
    subprocess.run([str(jdk / "bin/javac.exe"), "-encoding", "UTF-8", "-source", "17", "-target", "17",
                    "-classpath", str(android), "-d", str(classes)]
                   + [str(source) for source in sources],
                   cwd=ROOT, check=True, timeout=120)
    subprocess.run([str(jdk / "bin/java.exe"), "-cp", str(sdk / "build-tools/36.0.0/lib/d8.jar"),
                    "com.android.tools.r8.D8", "--lib", str(android), "--min-api", "26",
                    "--output", str(output)] + [str(p) for p in sorted(classes.rglob("*.class"))],
                   cwd=ROOT, check=True, timeout=180)
    jar = output / "license-data-check.jar"
    with zipfile.ZipFile(jar, "w") as archive:
        archive.write(output / "classes.dex", "classes.dex")

    adb = sdk / "platform-tools/adb.exe"
    subprocess.run([str(adb), "-s", serial, "push", str(jar), REMOTE_JAR],
                   cwd=ROOT, check=True, timeout=120)
    lib = output / _apk.LIB_NAME
    lib.write_bytes(_apk.read_lib())
    subprocess.run([str(adb), "-s", serial, "shell", "mkdir -p " + REMOTE_LIB],
                   cwd=ROOT, check=True, timeout=60)
    subprocess.run([str(adb), "-s", serial, "push", str(lib), REMOTE_LIB + "/" + _apk.LIB_NAME],
                   cwd=ROOT, check=True, timeout=120)
    command = ("CLASSPATH=" + REMOTE_JAR + " LD_LIBRARY_PATH=" + REMOTE_LIB
               + " app_process /system/bin LicenseDataCheck " + " ".join(ACCOUNTS))
    result = subprocess.run([str(adb), "-s", serial, "shell", command], cwd=ROOT,
                            capture_output=True, timeout=180)
    return (result.stdout + result.stderr).decode("utf-8", "replace")


def parse(printed):
    parsed = {}
    account = None
    for line in printed.splitlines():
        if line.startswith("account "):
            account = line[len("account "):]
            parsed[account] = []
        elif line.startswith("  ") and account is not None:
            tag, rest = line[2:].split(" [", 1)
            type_, value = rest.split("] ", 1)
            parsed[account].append((tag, type_, value))
    return parsed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk", type=Path, required=True)
    parser.add_argument("--jdk", type=Path, required=True)
    parser.add_argument("--serial", required=True)
    args = parser.parse_args()

    expected = generate_expected()
    actual = parse(run_java(args.sdk, args.jdk, args.serial))
    failures = 0
    for account in ACCOUNTS:
        rows = actual.get(account)
        if rows != expected[account]:
            failures += 1
            print(f"FAIL {account}")
            for left, right in zip(rows or [], expected[account]):
                if left != right:
                    print(f"  java: {left}")
                    print(f"  py  : {right}")
        else:
            print(f"OK   {account} ({len(rows)} 行)")
    print(f"{'FAIL' if failures else 'PASS'}: {len(ACCOUNTS) - failures}/{len(ACCOUNTS)} 个账号与参考实现一致")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
