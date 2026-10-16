"""校验 App 里的类名常量能真的解析出来(点号形式),斜杠形式不行。

需要 JDK17、Android SDK、adb,以及一份微X 组件的明文 dex(默认 data/refs/device_dump/BaseDex.dex)。
"""
import argparse
import re
import subprocess
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REMOTE_DIR = "/data/local/tmp"
REMOTE_JAR = REMOTE_DIR + "/dex-probe.jar"
REMOTE_DEX = REMOTE_DIR + "/dex-probe.dex"
REMOTE_NAMES = REMOTE_DIR + "/dex-probe-names.txt"

# (源文件, 常量名):App 里挂微X 混淆类时用的名字,必须能从真的 dex 里解析出来。
CONSTANTS = [
    ("app/src/main/java/github/shadowbaby/wechatxposed/hook/support/WxComponentHooks.java",
     "BASE_ENTRY_CLASS"),
]


def run(*command, timeout=180):
    result = subprocess.run([str(part) for part in command], capture_output=True, timeout=timeout,
                            cwd=ROOT)
    if result.returncode != 0:
        raise RuntimeError(result.stdout.decode("utf-8", "replace")
                           + result.stderr.decode("utf-8", "replace"))
    return result.stdout.decode("utf-8", "replace")


def literal(source, name):
    """把 App源码里的 String 常量取出来(反解 \\uXXXX 转义)。"""
    text = (ROOT / source).read_text(encoding="utf-8")
    match = re.search(r'String\s+' + name + r'\s*=\s*"([^"]*)"', text)
    if match is None:
        raise RuntimeError("找不到常量 " + name + " @ " + source)
    return re.sub(r"\\u([0-9A-Fa-f]{4})", lambda m: chr(int(m.group(1), 16)), match.group(1))


def build(sdk, jdk, output):
    classes = output / "classes"
    classes.mkdir(parents=True, exist_ok=True)
    android = sdk / "platforms/android-36/android.jar"
    run(jdk / "bin/javac.exe", "-encoding", "UTF-8", "-source", "17", "-target", "17",
        "-classpath", android, "-d", classes, Path(__file__).parent / "ClassProbe.java")
    run(jdk / "bin/java.exe", "-cp", sdk / "build-tools/36.0.0/lib/d8.jar",
        "com.android.tools.r8.D8", "--lib", android, "--min-api", "26",
        "--output", output, *sorted(classes.rglob("*.class")))
    jar = output / "dex-probe.jar"
    with zipfile.ZipFile(jar, "w") as archive:
        archive.write(output / "classes.dex", "classes.dex")
    return jar


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk", type=Path, required=True)
    parser.add_argument("--jdk", type=Path, required=True)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--dex", type=Path, default=ROOT / "data/refs/device_dump/BaseDex.dex")
    args = parser.parse_args()
    if not args.dex.exists():
        raise SystemExit("缺少明文 dex:" + str(args.dex))
    adb = args.sdk / "platform-tools/adb.exe"
    output = ROOT / "build/dex-probe"
    output.mkdir(parents=True, exist_ok=True)

    names = [(source, name, literal(source, name)) for source, name in CONSTANTS]
    names_file = output / "names.txt"
    names_file.write_text("\n".join(name for _, _, name in names), encoding="utf-8")

    jar = build(args.sdk, args.jdk, output)
    for local, remote in ((jar, REMOTE_JAR), (args.dex, REMOTE_DEX), (names_file, REMOTE_NAMES)):
        run(adb, "-s", args.serial, "push", local, remote)
    lines = run(adb, "-s", args.serial, "shell",
                "CLASSPATH=" + REMOTE_JAR + " app_process /system/bin ClassProbe "
                + REMOTE_DEX + " " + REMOTE_NAMES).splitlines()

    parsed = {}
    for line in lines:
        if line.startswith("NAME "):
            _, name, dotted, slashed = line.split(" ")
            parsed[name] = (dotted.split("=", 1)[1], slashed.split("=", 1)[1])

    failures = 0
    for source, constant, name in names:
        found = parsed.get(name)
        path = "%s#%s" % (source, constant)
        if found is None:
            failures += 1
            print("FAIL %s -> 探针没报这个类名" % path)
            continue
        dotted, slashed = found
        ok = dotted == "ok" and slashed != "ok"
        print("%s %s -> dotted=%s slashed=%s" % ("OK  " if ok else "FAIL", path, dotted, slashed))
        if not ok:
            failures += 1
    print(("PASS" if not failures else "FAIL") + ": " + str(len(names) - failures) + "/"
          + str(len(names)) + " 个类名常量")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
