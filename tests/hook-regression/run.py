"""Build/run an isolated Android harness; no APK installation or real Xposed hooks."""
import argparse
from pathlib import Path
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[2]


def run(*command):
    subprocess.run([str(part) for part in command], cwd=ROOT, check=True, timeout=90)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk", type=Path, required=True)
    parser.add_argument("--jdk", type=Path, required=True)
    parser.add_argument("--original", type=Path, default=ROOT / "data/refs/WxModuleHook-1.2.apk")
    parser.add_argument("--serial")
    args = parser.parse_args()
    output = ROOT / "build/hook-regression"
    output.mkdir(parents=True, exist_ok=True)
    classes = output / "classes"
    classes.mkdir(exist_ok=True)
    android = args.sdk / "platforms/android-36/android.jar"
    sources = sorted((ROOT / "app/src/main/java").rglob("*.java"))
    sources += sorted((Path(__file__).parent / "src").rglob("*.java"))
    argfile = output / "javac.args"
    argfile.write_text("\n".join('"' + p.as_posix() + '"' for p in sources), encoding="utf-8")
    run(args.jdk / "bin/javac.exe", "-encoding", "UTF-8", "-source", "17", "-target", "17",
        "-classpath", android, "-d", classes, "@" + str(argfile))
    jar = output / "harness.jar"
    with zipfile.ZipFile(jar, "w") as archive:
        for path in sorted(classes.rglob("*.class")):
            archive.write(path, path.relative_to(classes).as_posix())
    run(args.jdk / "bin/java.exe", "-cp", args.sdk / "build-tools/36.0.0/lib/d8.jar",
        "com.android.tools.r8.D8", "--lib", android, "--min-api", "26", "--output", output, jar)
    combined = output / "regression.jar"
    with zipfile.ZipFile(combined, "w") as archive, zipfile.ZipFile(args.original) as original:
        archive.write(output / "classes.dex", "classes.dex")
        archive.writestr("classes2.dex", original.read("classes.dex"))
    adb = [args.sdk / "platform-tools/adb.exe"]
    if args.serial:
        adb += ["-s", args.serial]
    remote = "/data/local/tmp/wxmodulehook-regression.jar"
    run(*adb, "push", combined, remote)
    run(*adb, "shell", "env", "CLASSPATH=" + remote, "app_process", "/system/bin", "HookRegression")


if __name__ == "__main__":
    main()
