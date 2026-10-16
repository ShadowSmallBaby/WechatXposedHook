"""对照 Java 与 Python 两套 dex 解析器,确认 App 里的 DexStrings 读得对。

Java 侧直接跑 app 源码里的 DexStrings;Python 侧是 tests/dex-strings/_reference.py。
两边对同一批 dex 反查同一组字符串,命中类数必须逐行相同。

需要 JDK17;--dex-dir 指向微信 base.apk 解出来的 dex 目录(不入库)。
"""
import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
APP_DEXSTRINGS = (ROOT / "app/src/main/java/github/shadowbaby/wechatxposed/hook"
                  / "support/DexStrings.java")
HERE = Path(__file__).resolve().parent


def run(*command, timeout=300):
    result = subprocess.run([str(part) for part in command], capture_output=True, timeout=timeout,
                            cwd=ROOT)
    if result.returncode != 0:
        raise RuntimeError(result.stdout.decode("utf-8", "replace")
                           + result.stderr.decode("utf-8", "replace"))
    return result.stdout.decode("utf-8", "replace")


def java_lines(jdk, dex_dir, work):
    classes = work / "classes"
    classes.mkdir(parents=True, exist_ok=True)
    run(jdk / "bin/javac.exe", "-encoding", "UTF-8", "-d", classes,
        APP_DEXSTRINGS, HERE / "DexStringsCheck.java")
    out = run(jdk / "bin/java.exe", "-cp", classes, "DexStringsCheck", dex_dir)
    return [line for line in out.splitlines() if line.strip()]


def python_lines(dex_dir):
    out = run(sys.executable, "-X", "utf8", HERE / "_reference.py", dex_dir)
    return [line for line in out.splitlines() if line.strip()]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jdk", type=Path, required=True)
    parser.add_argument("--dex-dir", type=Path, default=ROOT / "data/tmp/edit/dex")
    parser.add_argument("--work", type=Path, default=ROOT / "build/dex-strings")
    arguments = parser.parse_args()

    dex_dir = arguments.dex_dir
    if not dex_dir.is_dir() or not any(dex_dir.glob("*.dex")):
        print("跳过: " + str(dex_dir) + " 里没有 dex(需要从微信 base.apk 解出来)")
        return 0

    arguments.work.mkdir(parents=True, exist_ok=True)
    java = java_lines(arguments.jdk, dex_dir, arguments.work)
    reference = python_lines(dex_dir)

    failures = 0
    if not java:
        print("失败: Java 侧没有输出")
        failures += 1
    if java != reference:
        print("失败: 两边结果不一致")
        for left, right in zip(java, reference):
            if left != right:
                print("  java: " + left)
                print("  py  : " + right)
        failures += 1
    else:
        print("一致: " + str(len(java)) + " 个 dex 逐行相同")

    launch = [line for line in java if "MicroMsg.AppBrand.CgiLaunchWxaApp|func:1122=1" in line]
    if len(launch) != 1:
        print("失败: 启动构造器锚点应恰好命中 1 个 dex,实际 " + str(len(launch)))
        failures += 1
    open_url = [line for line in java if "private_openUrl=1" in line]
    if len(open_url) != 1:
        print("失败: private_openUrl 锚点应恰好命中 1 个 dex,实际 " + str(len(open_url)))
        failures += 1

    print("PASS" if failures == 0 else "FAIL: " + str(failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
