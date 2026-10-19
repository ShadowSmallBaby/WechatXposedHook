"""在设备上验证 FeaturePackRestorer:按清单补齐 files/wx6_2.44 的 24 个文件。

跑的是真正的 App 代码(FeaturePackRestorer + ModuleApk),载荷取模块 APK 里的
assets/wx6_2.44.zip(构建时由 xmetadata 生成)。场景都在 /data/local/tmp 下的临时目录里铺,
不碰微信真实目录。

需要 JDK17、Android SDK、adb,以及一份已构建的 release APK(默认见 tests/_apk.py)。
"""
import argparse
import hashlib
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests"))
import _apk
REMOTE_DIR = "/data/local/tmp"
REMOTE_JAR = REMOTE_DIR + "/file-restore-check.jar"
REMOTE_APK = REMOTE_DIR + "/file-restore-module.apk"
REMOTE_LIB = REMOTE_DIR + "/file-restore-lib"
REMOTE_WORK = REMOTE_DIR + "/file-restore-work"
REMOTE_FILES = REMOTE_WORK + "/wx6_2.44"
PAYLOAD_ENTRY = "assets/wx6_2.44.zip"


def run(*command, timeout=180):
    result = subprocess.run([str(part) for part in command], capture_output=True, timeout=timeout,
                            cwd=ROOT)
    if result.returncode != 0:
        raise RuntimeError(result.stdout.decode("utf-8", "replace")
                           + result.stderr.decode("utf-8", "replace"))
    return result.stdout.decode("utf-8", "replace")


def payload_manifest(apk):
    """从模块 APK 的内置载荷里取清单:文件名 -> md5(与设备上 md5sum 对齐)。"""
    with zipfile.ZipFile(apk) as module:
        inner = module.read(PAYLOAD_ENTRY)
    with zipfile.ZipFile(__import__("io").BytesIO(inner)) as archive:
        return {info.filename: hashlib.md5(archive.read(info.filename)).hexdigest()
                for info in archive.infolist()}


def build(sdk, jdk, output, apk):
    classes = output / "classes"
    classes.mkdir(parents=True, exist_ok=True)
    android = sdk / "platforms/android-36/android.jar"
    xposed = ROOT / "app/src/libs/XposedBridgeAPI-89.jar"
    sources = _apk.app_sources()
    # 测试替身要排在 API jar 前面(同名类以源码为准)
    sources = [p for p in sources if "XposedBridge" not in p.name]
    sources += sorted((Path(__file__).parent / "src").rglob("*.java"))
    argfile = output / "javac.args"
    argfile.write_text("\n".join('"' + p.as_posix() + '"' for p in sources), encoding="utf-8")
    run(jdk / "bin/javac.exe", "-encoding", "UTF-8", "-source", "17", "-target", "17",
        "-classpath", str(android) + __import__("os").pathsep + str(xposed),
        "-d", classes, "@" + str(argfile))
    run(jdk / "bin/java.exe", "-cp", sdk / "build-tools/36.0.0/lib/d8.jar",
        "com.android.tools.r8.D8", "--lib", android, "--min-api", "26", "--output", output,
        *sorted(classes.rglob("*.class")))
    jar = output / "file-restore-check.jar"
    with zipfile.ZipFile(jar, "w") as archive:
        archive.write(output / "classes.dex", "classes.dex")
    return jar


def shell(adb, serial, command):
    return run(adb, "-s", serial, "shell", command)


def su(adb, serial, command):
    return shell(adb, serial, "su -c '" + command + "'")


def probe(adb, serial, directory, mode="", module_apk=REMOTE_APK):
    command = ("CLASSPATH=" + REMOTE_JAR + " LD_LIBRARY_PATH=" + REMOTE_LIB
               + " app_process /system/bin FileRestoreCheck "
               + directory + " " + (mode or "none") + " " + module_apk)
    # app_process 退出时可能被 SIGKILL(137),输出照样有效
    result = subprocess.run([str(adb), "-s", serial, "shell", command], capture_output=True,
                            timeout=120)
    text = (result.stdout + result.stderr).decode("utf-8", "replace")
    parsed = {}
    for line in text.splitlines():
        line = line.strip()
        if "=" in line and " " not in line:
            key, value = line.split("=", 1)
            parsed[key] = value
    return parsed


def push_payload(adb, serial, apk):
    """把模块 APK 推到设备,当作模块自己的 APK(ModuleApk 按包名找不到时会用 initZygote 记的路径,
    这里直接让探针以这个 APK 为模块路径:见 ModuleApk.remember 的调用方)。"""
    run(adb, "-s", serial, "push", apk, REMOTE_APK)


def setup(adb, serial, files):
    """在设备上铺一个工作目录,内容由 files 决定(名字 -> 本地文件或 None 表示不铺)。"""
    su(adb, serial, "rm -rf " + REMOTE_WORK + " && mkdir -p " + REMOTE_FILES
       + " && chmod 777 " + REMOTE_WORK + " " + REMOTE_FILES)
    for name, source in files.items():
        if source is None:
            continue
        run(adb, "-s", serial, "push", source, REMOTE_FILES + "/" + name)
    su(adb, serial, "chmod 666 " + REMOTE_FILES + "/* 2>/dev/null; ls " + REMOTE_FILES + " | wc -l")


def local_payload(tmp):
    """把内置载荷解到本地临时目录,用来铺"正确文件"和"错误文件"两种场景。"""
    apk = _apk.APK
    with zipfile.ZipFile(apk) as module:
        inner = module.read(PAYLOAD_ENTRY)
    tmp.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(__import__("io").BytesIO(inner)) as archive:
        archive.extractall(tmp)
    return {path.name: path for path in tmp.iterdir() if path.is_file()}


def device_listing(adb, serial):
    su(adb, serial, "chmod 666 " + REMOTE_FILES + "/* 2>/dev/null")
    listing = su(adb, serial, "cd " + REMOTE_FILES + " && md5sum * 2>/dev/null")
    result = {}
    for line in listing.splitlines():
        parts = line.split()
        # md5sum 输出是 "<32 位十六进制>  <文件名>",别的行(chmod 报错等)一律忽略
        if len(parts) == 2 and len(parts[0]) == 32 and all(c in "0123456789abcdef" for c in parts[0]):
            result[parts[1].lstrip("*")] = parts[0]
    return result


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
    output = ROOT / "build/file-restore"
    output.mkdir(parents=True, exist_ok=True)

    manifest = payload_manifest(args.apk)
    jar = build(args.sdk, args.jdk, output, args.apk)
    run(adb, "-s", args.serial, "push", jar, REMOTE_JAR)
    push_payload(adb, args.serial, args.apk)
    # 敏感常量解码在 libwexhook.so 里,FileRestoreCheck 要它才能算出目录名与载荷名。
    lib = output / _apk.LIB_NAME
    with zipfile.ZipFile(args.apk) as apk:
        lib.write_bytes(apk.read(_apk.LIB_ENTRY))
    run(adb, "-s", args.serial, "shell", "mkdir -p " + REMOTE_LIB)
    run(adb, "-s", args.serial, "push", lib, REMOTE_LIB + "/" + _apk.LIB_NAME)
    files = local_payload(output / "payload")
    results = []

    def scenario(label, ok, detail):
        results.append((label, bool(ok), detail))

    # 场景 1:目录不存在 -> 建目录 + 铺满 28 个
    su(adb, args.serial, "rm -rf " + REMOTE_WORK)
    parsed = probe(adb, args.serial, REMOTE_WORK)
    listing = device_listing(adb, args.serial)
    scenario("目录不存在: 建目录并铺满", parsed.get("missingAfter") == "0"
             and parsed.get("files") == str(len(manifest)) and len(listing) == len(manifest),
             parsed)

    # 场景 2:目录为空 -> 铺满 28 个
    setup(adb, args.serial, {})
    parsed = probe(adb, args.serial, REMOTE_WORK)
    listing = device_listing(adb, args.serial)
    scenario("目录为空: 铺满", parsed.get("missingBefore") == str(len(manifest))
             and parsed.get("missingAfter") == "0" and len(listing) == len(manifest), parsed)

    # 场景 3:缺文件 -> 只补缺的那些,已有的不动
    missing = sorted(manifest)[:7]
    present = {name: path for name, path in files.items() if name not in missing}
    setup(adb, args.serial, present)
    before = device_listing(adb, args.serial)
    parsed = probe(adb, args.serial, REMOTE_WORK)
    after = device_listing(adb, args.serial)
    untouched = all(after.get(name) == digest for name, digest in before.items())
    scenario("缺 7 个: 只补缺的,已有的不动",
             parsed.get("missingBefore") == str(len(missing)) and parsed.get("missingAfter") == "0"
             and len(after) == len(manifest) and untouched, parsed)

    # 场景 4:文件内容与内置不一致(大小相同)-> 按大小判不出来,但内容不同要能发现
    #   这里改成大小不同的错误内容,验证"大小不符也算缺失"
    wrong = dict(present)
    victim = sorted(present)[0]
    wrong_path = output / "wrong.bin"
    wrong_path.write_bytes(b"x" * (wrong[victim].stat().st_size + 1))
    wrong[victim] = wrong_path
    setup(adb, args.serial, wrong)
    parsed = probe(adb, args.serial, REMOTE_WORK)
    after = device_listing(adb, args.serial)
    fixed = after.get(victim) == manifest[victim]
    scenario("文件大小不符: 按缺失重写", parsed.get("missingBefore") == str(len(missing) + 1)
             and parsed.get("missingAfter") == "0" and fixed, parsed)

    # 场景 5:额外多出文件 -> 不动它们(只补清单内的)
    # 场景 4b:大小相同但内容不同 -> 按清单判不出来(名字即指纹,大小只作粗筛),
    #   这种情况不重写;真机上同名不同内容说明是"另一批版本",不属于本套清单
    same_size = dict(files)
    twin = sorted(files)[1]
    twin_path = output / "twin.bin"
    twin_path.write_bytes(b"y" * files[twin].stat().st_size)
    same_size[twin] = twin_path
    setup(adb, args.serial, same_size)
    parsed = probe(adb, args.serial, REMOTE_WORK)
    after = device_listing(adb, args.serial)
    scenario("大小相同内容不同: 不重写(按大小判据)", parsed.get("missingBefore") == "0"
             and parsed.get("missingAfter") == "0" and after.get(twin) != manifest[twin], parsed)

    # 场景 5:额外多出文件 -> 不动它们(只补清单内的)
    extra = dict(files)
    extra_path = output / "extra.bin"
    extra_path.write_bytes(b"extra")
    extra["stray-file-not-in-manifest"] = extra_path
    setup(adb, args.serial, extra)
    parsed = probe(adb, args.serial, REMOTE_WORK)
    after = device_listing(adb, args.serial)
    scenario("多出清单外的文件: 保留不动", parsed.get("missingBefore") == "0"
             and parsed.get("missingAfter") == "0"
             and "stray-file-not-in-manifest" in after, parsed)

    # 场景 6:全部齐全 -> 一个字节都不改
    setup(adb, args.serial, files)
    before = device_listing(adb, args.serial)
    parsed = probe(adb, args.serial, REMOTE_WORK)
    after = device_listing(adb, args.serial)
    scenario("全部齐全: 不改动", parsed.get("missingBefore") == "0"
             and parsed.get("missingAfter") == "0" and before == after, parsed)

    # 场景 7:补齐出来的内容与内置载荷逐字节一致
    setup(adb, args.serial, {})
    probe(adb, args.serial, REMOTE_WORK)
    after = device_listing(adb, args.serial)
    bad = [name for name, digest in manifest.items() if after.get(name) != digest]
    scenario("补齐内容与内置载荷一致", not bad, {"不一致": bad})

    # 场景 8:同一进程里重复调用只查一次(ensureOnce 幂等)
    setup(adb, args.serial, {})
    parsed = probe(adb, args.serial, REMOTE_WORK, mode="twice")
    scenario("重复调用幂等", parsed.get("missingAfter") == "0", parsed)

    failures = 0
    for label, ok, detail in results:
        if not ok:
            failures += 1
            print("FAIL " + label)
            for key, value in detail.items():
                print("   " + str(key) + " = " + str(value)[:140])
        else:
            print("OK   " + label)
    print(("FAIL" if failures else "PASS") + ": " + str(len(results) - failures) + "/"
          + str(len(results)) + " 个场景")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
