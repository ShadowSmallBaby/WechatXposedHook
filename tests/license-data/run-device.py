"""在设备上用真正的 LicenseDatabase.ensure 跑一遍「库已存在 / 账号已存在」的各种场景。

需要 JDK17、Android SDK、adb、以及一份 FKZ_WX_DATA 样本(默认 data/FKZ_WX_DATA,用 --source 指定)。
样本只用来铺场景:每次都推副本到 /data/local/tmp,不碰设备上真实的库。
"""
import argparse
import importlib.util
import shutil
import sqlite3
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REMOTE_DIR = "/data/local/tmp"
REMOTE_JAR = REMOTE_DIR + "/license-db-check.jar"
REMOTE_DB = REMOTE_DIR + "/license-check.db"
REMOTE_LIB = REMOTE_DIR + "/license-db-lib"
MISSING_ACCOUNT = "wxid_fixtureabsent0000"
REQUIRED = ("hookFail", "disclaimer_disable", "is_new_user", "LatestVersions", "FPVersions",
            "valid", "fp", "fp_async", "LIC", "verifier6")

# LicenseDatabase.Result 的期望值:新建 / 插入 10 行 / 重算两行 / 原值保留
CREATED_FRESH = {"created": "true", "inserted": "10", "refreshed": "0", "kept": "0"}
INSERTED_TEN = {"created": "false", "inserted": "10", "refreshed": "0", "kept": "0"}
REFRESHED_BOTH = {"created": "false", "inserted": "0", "refreshed": "2", "kept": "0"}
KEPT_BOTH = {"created": "false", "inserted": "0", "refreshed": "0", "kept": "2"}
KEPT_ONE_INSERTED_ONE = {"created": "false", "inserted": "1", "refreshed": "0", "kept": "1"}
KEPT_ONE_REFRESHED_ONE = {"created": "false", "inserted": "0", "refreshed": "1", "kept": "1"}


def expected_rows(account):
    spec = importlib.util.spec_from_file_location(
        "generate_min_db", ROOT / "scripts/generate_min_db.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return {tag: value for tag, _, value in module.build_rows(account)}


def build_and_push(sdk, jdk, adb, serial):
    output = ROOT / "build/license-data/device"
    classes = output / "classes"
    classes.mkdir(parents=True, exist_ok=True)
    sources = [ROOT / "app/src/main/java/github/shadowbaby/wechatxposed/hook/license/LicenseCrypto.java",
               ROOT / "app/src/main/java/github/shadowbaby/wechatxposed/hook/license/LicenseData.java",
               ROOT / "app/src/main/java/github/shadowbaby/wechatxposed/hook/license/LicenseDatabase.java",
               ROOT / "app/src/main/java/github/shadowbaby/wechatxposed/hook/loader/Secret.java",
               ROOT / "app/src/main/java/github/shadowbaby/wechatxposed/hook/loader/SecretConstants.java",
               Path(__file__).parent / "LicenseDatabaseCheck.java"]
    android = sdk / "platforms/android-36/android.jar"
    subprocess.run([str(jdk / "bin/javac.exe"), "-encoding", "UTF-8", "-source", "17", "-target", "17",
                    "-classpath", str(android), "-d", str(classes)] + [str(s) for s in sources],
                   cwd=ROOT, check=True, timeout=180)
    subprocess.run([str(jdk / "bin/java.exe"), "-cp", str(sdk / "build-tools/36.0.0/lib/d8.jar"),
                    "com.android.tools.r8.D8", "--lib", str(android), "--min-api", "26",
                    "--output", str(output)] + [str(p) for p in sorted(classes.rglob("*.class"))],
                   cwd=ROOT, check=True, timeout=180)
    jar = output / "license-db-check.jar"
    import zipfile
    with zipfile.ZipFile(jar, "w") as archive:
        archive.write(output / "classes.dex", "classes.dex")
    run(adb, serial, "push", jar, REMOTE_JAR)
    # 敏感常量解码与授权加密链路都在 so 里,没有它 ensure 会抛异常。
    lib = output / _apk.LIB_NAME
    lib.write_bytes(_apk.read_lib())
    run(adb, serial, "shell", "mkdir -p " + REMOTE_LIB)
    run(adb, serial, "push", lib, REMOTE_LIB + "/" + _apk.LIB_NAME)


def run(adb, serial, *command):
    result = subprocess.run([str(adb), "-s", serial, *[str(part) for part in command]],
                            capture_output=True, timeout=120)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.decode("utf-8", "replace"))
    return result.stdout.decode("utf-8", "replace")


def run_tolerant(adb, serial, *command):
    """app_process 退出时可能被 SIGKILL(退出码 137),输出照样有效,所以不看返回码。"""
    result = subprocess.run([str(adb), "-s", serial, *[str(part) for part in command]],
                            capture_output=True, timeout=120)
    return (result.stdout + result.stderr).decode("utf-8", "replace")


def run_check(adb, serial, account, mode=None):
    command = ("CLASSPATH=" + REMOTE_JAR + " LD_LIBRARY_PATH=" + REMOTE_LIB
               + " app_process /system/bin LicenseDatabaseCheck "
               + REMOTE_DB + " " + account)
    if mode:
        command += " " + mode
    output = run_tolerant(adb, serial, "shell", command)
    parsed = {}
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("ensure"):
            label, rest = line.split(" ", 1)
            parsed[label] = dict(part.split("=") for part in rest.split(" "))
        elif line and all("=" in part for part in line.split(" ")):
            for part in line.split(" "):
                key, value = part.split("=", 1)
                parsed[key] = value
    return parsed


def copy_for_scenario(source, destination, mutate=None):
    shutil.copyfile(source, destination)
    if mutate is not None:
        database = sqlite3.connect(destination)
        mutate(database)
        database.commit()
        database.close()


def accounts_of(path):
    database = sqlite3.connect(path)
    try:
        return [row[0] for row in database.execute(
            "SELECT ACCOUNT, COUNT(*) FROM DATA GROUP BY ACCOUNT ORDER BY COUNT(*) DESC")]
    finally:
        database.close()


def failed(parsed, label):
    """ensure 抛异常时打印的是 error=<类名>,解析出来是个 dict。"""
    value = parsed[label]
    return isinstance(value, dict) and "error" in value


def scenario(results, label, condition, detail):
    results.append((label, bool(condition), detail))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk", type=Path, required=True)
    parser.add_argument("--jdk", type=Path, required=True)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--source", type=Path, default=ROOT / "data/FKZ_WX_DATA")
    args = parser.parse_args()
    adb = args.sdk / "platform-tools/adb.exe"
    work = ROOT / "build/license-data/device"
    work.mkdir(parents=True, exist_ok=True)

    build_and_push(args.sdk, args.jdk, adb, args.serial)
    accounts = accounts_of(args.source)
    results = []

    # 场景 1:库不存在 -> 新建
    run(adb, args.serial, "shell", "rm -f " + REMOTE_DB)
    parsed = run_check(adb, args.serial, MISSING_ACCOUNT)
    scenario(results, "库不存在", parsed["ensure1"] == CREATED_FRESH
             and parsed["rows"] == "10" and parsed["accounts"] == "1"
             and parsed["version"] == "1", parsed)

    # 场景 2:库已存在、账号已存在且 10 行齐全
    existing = accounts[0]
    copy_for_scenario(args.source, work / "existing.db")
    run(adb, args.serial, "push", work / "existing.db", REMOTE_DB)
    source = sqlite3.connect(args.source)
    before = source.execute("SELECT COUNT(*) FROM DATA WHERE ACCOUNT=?", (existing,)).fetchone()[0]
    was = {tag: source.execute("SELECT VALUE FROM DATA WHERE ACCOUNT=? AND TAG=?",
                               (existing, tag)).fetchone()[0] for tag in ("LIC", "verifier6")}
    parsed = run_check(adb, args.serial, existing)
    scenario(results, "账号已存在且完整(原值保留)",
             parsed["ensure1"] == KEPT_BOTH and parsed["rows"] == str(before)
             and parsed["version"] == "1"
             and parsed["lic"] == was["LIC"] and parsed["verifier6"] == was["verifier6"], parsed)

    # 场景 3:库已存在、账号不存在 -> 只补这个账号
    parsed = run_check(adb, args.serial, MISSING_ACCOUNT)
    want = expected_rows(MISSING_ACCOUNT)
    scenario(results, "库已存在但账号不在",
             parsed["ensure1"] == INSERTED_TEN
             and parsed["rows"] == "10" and parsed["accounts"] == str(len(accounts) + 1)
             and parsed["lic"] == want["LIC"], parsed)

    # 场景 4:账号已存在但 LIC/verifier6 是别的账号的(锦贝库)
    victim, donor = accounts[0], accounts[1]
    def break_license(database):
        for tag in ("LIC", "verifier6"):
            stolen = database.execute("SELECT VALUE FROM DATA WHERE ACCOUNT=? AND TAG=?",
                                      (donor, tag)).fetchone()[0]
            database.execute("UPDATE DATA SET VALUE=? WHERE ACCOUNT=? AND TAG=?",
                             (stolen, victim, tag))
    copy_for_scenario(args.source, work / "stale.db", break_license)
    run(adb, args.serial, "push", work / "stale.db", REMOTE_DB)
    parsed = run_check(adb, args.serial, victim)
    want = expected_rows(victim)
    scenario(results, "账号已存在但 LIC 是别人的",
             parsed["ensure1"] == REFRESHED_BOTH
             and parsed["lic"] == want["LIC"] and parsed["verifier6"] == want["verifier6"]
             and parsed["accounts"] == str(len(accounts)), parsed)
    recheck = parsed

    # 场景 5:库已存在但 user_version 不是 1(微X 会重建表 -> "table DATA already exists")
    def break_version(database):
        database.execute("PRAGMA user_version=0")
    copy_for_scenario(args.source, work / "version.db", break_version)
    run(adb, args.serial, "push", work / "version.db", REMOTE_DB)
    parsed = run_check(adb, args.serial, existing)
    scenario(results, "库已存在但 user_version 不是 1",
             parsed["ensure1"] == KEPT_BOTH and parsed["version"] == "1"
             and parsed["rows"] == str(before) and parsed["lic"] == was["LIC"], parsed)

    # 场景 6:账号已存在、LIC 是本账号的,但 verifier6 缺行
    def drop_verifier(database):
        database.execute("DELETE FROM DATA WHERE ACCOUNT=? AND TAG=?", (victim, "verifier6"))
    copy_for_scenario(args.source, work / "noverifier.db", drop_verifier)
    run(adb, args.serial, "push", work / "noverifier.db", REMOTE_DB)
    parsed = run_check(adb, args.serial, victim)
    want = expected_rows(victim)
    scenario(results, "账号已存在但 verifier6 缺失",
             parsed["ensure1"] == KEPT_ONE_INSERTED_ONE and parsed["lic"] == was["LIC"]
             and parsed["verifier6"] == want["verifier6"]
             and parsed["accounts"] == str(len(accounts)), parsed)

    # 场景 7:账号已存在、LIC 是本账号的,但 verifier6 是别人的
    def steal_verifier(database):
        stolen = database.execute("SELECT VALUE FROM DATA WHERE ACCOUNT=? AND TAG=?",
                                  (donor, "verifier6")).fetchone()[0]
        database.execute("UPDATE DATA SET VALUE=? WHERE ACCOUNT=? AND TAG=?",
                         (stolen, victim, "verifier6"))
    copy_for_scenario(args.source, work / "stealverifier.db", steal_verifier)
    run(adb, args.serial, "push", work / "stealverifier.db", REMOTE_DB)
    parsed = run_check(adb, args.serial, victim)
    scenario(results, "账号已存在但 verifier6 是别人的",
             parsed["ensure1"] == KEPT_ONE_REFRESHED_ONE and parsed["lic"] == was["LIC"]
             and parsed["verifier6"] == want["verifier6"]
             and parsed["accounts"] == str(len(accounts)), parsed)

    # 场景 8:库已存在且微X 自己那条连接也开着(模块是在微信进程里写的)
    copy_for_scenario(args.source, work / "held.db")
    run(adb, args.serial, "push", work / "held.db", REMOTE_DB)
    parsed = run_check(adb, args.serial, existing, mode="hold")
    scenario(results, "库被微X 占用时写入(第二条连接)",
             parsed["ensure1"] == KEPT_BOTH and parsed["rows"] == str(before)
             and parsed["lic"] == was["LIC"], parsed)

    # 场景 9:微X 占着一个写事务
    copy_for_scenario(args.source, work / "held-txn.db")
    run(adb, args.serial, "push", work / "held-txn.db", REMOTE_DB)
    parsed = run_check(adb, args.serial, existing, mode="hold-txn")
    scenario(results, "微X 占着写事务时写入(失败但不影响微X)",
             failed(parsed, "ensure1"), parsed)

    # 场景 10:库文件存在但是空文件(0 字节,SQLite 会当成空库)
    (work / "empty.db").write_bytes(b"")
    run(adb, args.serial, "push", work / "empty.db", REMOTE_DB)
    parsed = run_check(adb, args.serial, MISSING_ACCOUNT)
    scenario(results, "库文件存在但 0 字节",
             parsed["ensure1"] == INSERTED_TEN and parsed["rows"] == "10"
             and parsed["version"] == "1", parsed)

    # 场景 11:库文件存在但不是 SQLite(损坏/被换过)
    (work / "garbage.db").write_bytes(b"not a sqlite file" * 64)
    run(adb, args.serial, "push", work / "garbage.db", REMOTE_DB)
    parsed = run_check(adb, args.serial, MISSING_ACCOUNT)
    # 坏文件由 android.database.sqlite 自己删掉重建,ensure 照常写;原文件已在写入前备份成 .bak
    scenario(results, "库文件损坏(不是 SQLite)",
             parsed["ensure1"] == INSERTED_TEN and parsed["rows"] == "10"
             and parsed["version"] == "1", parsed)

    # 每个场景的第二次调用都应当是幂等的
    idempotent = recheck["ensure2"] == KEPT_BOTH
    scenario(results, "重复执行幂等", idempotent, recheck["ensure2"])

    failures = 0
    for label, ok, detail in results:
        if not ok:
            failures += 1
            print("FAIL " + label)
            for key, value in detail.items():
                print("   " + key + " = " + str(value)[:120])
        else:
            print("OK   " + label)
    print(("FAIL" if failures else "PASS") + ": " + str(len(results) - failures) + "/"
          + str(len(results)) + " 个场景")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
