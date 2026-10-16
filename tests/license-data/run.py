"""对照 scripts/generate_min_db.py 校验 LicenseData 的 Java 实现(纯 JVM,不需设备)。

两边输入同一个账号字符串,输出是 FKZ_WX_DATA 那 10 行的 TAG/TYPE/VALUE。
generate_min_db.py 已与设备上被微X 接受的库逐字节一致(data/FKZ_WX_DATA),
所以这里只要两边相等,Java 实现就是可用的。
"""
import argparse
import importlib.util
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# 账号只影响编码内容,用固定串即可(不涉及真实账号)
ACCOUNTS = ("wxid_00000000000000", "wxid_abcdefghijklmn", "wxid_a1b2c3d4e5f6g7")


def generate_expected():
    spec = importlib.util.spec_from_file_location(
        "generate_min_db", ROOT / "scripts/generate_min_db.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return {account: [(tag, type_, value) for tag, type_, value in module.build_rows(account)]
            for account in ACCOUNTS}


def run_java(jdk):
    output = ROOT / "build/license-data"
    output.mkdir(parents=True, exist_ok=True)
    classes = output / "classes"
    classes.mkdir(exist_ok=True)
    sources = [ROOT / "app/src/main/java/github/shadowbaby/wechatxposed/hook/license/LicenseData.java",
               Path(__file__).parent / "LicenseDataCheck.java"]
    subprocess.run([str(jdk / "bin/javac.exe"), "-encoding", "UTF-8", "-source", "17", "-target", "17",
                    "-d", str(classes)] + [str(source) for source in sources],
                   cwd=ROOT, check=True, timeout=120)
    result = subprocess.run([str(jdk / "bin/java.exe"), "-cp", str(classes), "LicenseDataCheck",
                             *ACCOUNTS], cwd=ROOT, check=True, capture_output=True, text=True,
                            encoding="utf-8", timeout=120)
    return result.stdout


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
    parser.add_argument("--jdk", type=Path, required=True)
    args = parser.parse_args()

    expected = generate_expected()
    actual = parse(run_java(args.jdk))
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
