"""在设备上验证 native 解码路径:libwexhook.so 解出的明文必须与明文表一致。

桌面 run.py 走的是 Java 回退路径;这里跑真正的 so(arm64),证明两条路径同源。
需要 JDK17、Android SDK、adb,以及一份已构建的 release APK(含 libwexhook.so)。
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
LOADER = ROOT / "app/build/generated/secrets/fullEdition/java/github/shadowbaby/wechatxposed/hook/loader"
HERE = Path(__file__).resolve().parent
REMOTE_DIR = "/data/local/tmp"
REMOTE_JAR = REMOTE_DIR + "/secret-native-check.jar"
REMOTE_LIB = REMOTE_DIR + "/secret-native-lib"


def secrets_table():
    spec = importlib.util.spec_from_file_location(
        "secrets_table", ROOT / "scripts/secrets_table.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.SECRETS


def run(*command, timeout=300):
    result = subprocess.run([str(part) for part in command], capture_output=True,
                            timeout=timeout, cwd=ROOT)
    if result.returncode != 0:
        raise RuntimeError(result.stdout.decode("utf-8", "replace")
                           + result.stderr.decode("utf-8", "replace"))
    return result.stdout.decode("utf-8", "replace")


def build(sdk, jdk, output):
    classes = output / "classes"
    classes.mkdir(parents=True, exist_ok=True)
    android = sdk / "platforms/android-36/android.jar"
    sources = [LOADER / "Secret.java", LOADER / "SecretConstants.java",
               HERE / "SecretNativeCheck.java"]
    run(jdk / "bin/javac.exe", "-encoding", "UTF-8", "-source", "17", "-target", "17",
        "-classpath", android, "-d", classes, *sources)
    run(jdk / "bin/java.exe", "-cp", sdk / "build-tools/36.0.0/lib/d8.jar",
        "com.android.tools.r8.D8", "--lib", android, "--min-api", "26",
        "--output", output, *sorted(classes.rglob("*.class")))
    jar = output / "secret-native-check.jar"
    with zipfile.ZipFile(jar, "w") as archive:
        archive.write(output / "classes.dex", "classes.dex")
    return jar


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk", type=Path, required=True)
    parser.add_argument("--jdk", type=Path, required=True)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--apk", type=Path, default=_apk.APK)
    args = parser.parse_args()
    if not args.apk.exists():
        raise SystemExit("缺少已构建的 APK:" + str(args.apk))
    adb = args.sdk / "platform-tools/adb.exe"
    output = ROOT / "build/secret-encoding/device"
    output.mkdir(parents=True, exist_ok=True)

    jar = build(args.sdk, args.jdk, output)
    run(adb, "-s", args.serial, "push", jar, REMOTE_JAR)
    # 从 APK 里取出 so,推到设备(与 APK 里的是同一个文件)。
    lib = output / _apk.LIB_NAME
    with zipfile.ZipFile(args.apk) as apk:
        lib.write_bytes(apk.read(_apk.LIB_ENTRY))
    run(adb, "-s", args.serial, "shell", "mkdir -p " + REMOTE_LIB)
    run(adb, "-s", args.serial, "push", lib, REMOTE_LIB + "/" + _apk.LIB_NAME)

    command = ("CLASSPATH=" + REMOTE_JAR + " LD_LIBRARY_PATH=" + REMOTE_LIB
               + " app_process /system/bin"
               + " github.shadowbaby.wechatxposed.hook.loader.SecretNativeCheck")
    printed = run(adb, "-s", args.serial, "shell", command)

    decoded = {}
    for line in printed.splitlines():
        if "=" in line:
            name, value = line.split("=", 1)
            decoded[name] = value

    expected = secrets_table()
    failures = 0
    if not decoded:
        print("FAIL: 设备上没有输出(so 可能没加载成功)")
        failures += 1
    for name, plain in expected.items():
        if decoded.get(name) != plain:
            print("FAIL %s -> native 还原值不一致" % name)
            failures += 1
    print(("PASS" if not failures else "FAIL") + ": "
          + str(len(expected) - failures) + "/" + str(len(expected)) + " 个常量(native)")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
