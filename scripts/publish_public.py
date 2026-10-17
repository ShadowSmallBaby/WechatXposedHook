# -*- coding: utf-8 -*-
"""把内部仓(阿里云效)里该公开的部分同步到公开仓(GitHub)工作区。

两个仓的分工:

    内部仓(阿里云效)  完整的开发仓:提交 native 源码(app/src/main/jni)、逆向文档、
                      分析脚本、测试;构建时用 clang 现编 so;密钥走环境变量。
    公开仓(GitHub)    只放 app 与编译好的 so:没有 jni/,没有逆向文档与分析脚本,
                      CI 拿随仓提交的 jniLibs/<abi>/libwexhook.so 打 APK。

公开仓的 CI **只负责构建**:能进公开仓的文件默认就满足构建条件,不再在 CI 里做
密钥、so、私有材料之类的检测。所有前置检测都在本脚本里,同步前一次性做完:
密钥格式、密钥与密文是否配套、构建必需文件是否齐全、内容扫描、多余文件与空目录。

公开仓**不含任何脚本**:`scripts/encode_secrets.py` 里有默认主密钥与完整编码算法,
`scripts/secrets_table.py` 是明文表,两者都不能公开。密文表 `SecretConstants.java`
在内部仓生成好后随源码一起同步过去,公开仓构建时直接用它(encodeSecrets 任务自动跳过)。

公开仓的 README 不是内部仓的 `README.md`,而是由 `README.public.md` 改名同步过去的
(只保留功能介绍、APK 选择和使用指南,不写内部流程)。

**默认拒绝**:只有 ALLOW 里列出的路径会过去,其余一律不复制。新增内部文件
(文档、脚本、样本)默认不会泄到公开仓,要公开必须显式加进 ALLOW。

**发布密钥必填**:公开仓的 so 必须用发布主密钥编出来。没设 WXH_MASTER_KEY 时脚本
直接退出 —— 否则会把用内置默认密钥编的 so 推到公开仓,密文等于没加密。
本机调试确实要用默认密钥时,显式加 --allow-default-key。

**密钥配套**:脚本加载 `encode_secrets.py`,用 WXH_MASTER_KEY 把明文表重新编码一遍,
逐项比对工作区的 `SecretConstants.java`;任何一项不一致都说明密文不是这把密钥生成的。

**构建必需文件**:同步清单里必须包含 AndroidManifest、两个 ABI 的 so、
SecretConstants、gradle wrapper 等;缺一个就直接中止,不指望 CI 发现。

**内容扫描**:ALLOW 是目录粒度(app/src 整棵树),新塞进资源目录的私钥、token 也会
被同步。复制前会扫内容(内置主密钥的原始值 / hex / Base64、私钥头、常见 token),
命中即中止;确认无害再加 --allow-sensitive。

**清空目录**:公开仓 CI 校验 docs/、tests/、jni/ 这些目录不存在;脚本会删掉白名单外
的多余文件,并把因此变空的目录一并删掉,避免空目录让 `test ! -e docs` 误判。

本脚本只写文件,**不提交、不推送**;公开仓里的提交与推送由你自己确认。

用法:
    python -X utf8 scripts/publish_public.py --to <公开仓工作区路径> [--check]
        [--allow-default-key] [--allow-sensitive]

    --check   只比对不写,列出「会写哪些 / 公开仓里哪些多余」,有差异退出码为 1。
"""
import argparse
import base64
import filecmp
import importlib.util
import os
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# 允许出现在公开仓的路径(相对仓库根)。文件或目录;目录递归复制。
ALLOW = [
    "README.public.md",            # 同步到公开仓时改名为 README.md
    "build.gradle",
    "settings.gradle",
    "gradle.properties",
    "gradlew",
    "gradlew.bat",
    "gradle/wrapper",
    ".github",                     # GitHub Actions 工作流
    "app/build.gradle.public",     # 同步到公开仓时改名为 app/build.gradle
    "app/proguard-rules.pro",
    "app/src",                     # 含 main/legacy/modern 与 jniLibs/<abi>/*.so
]

# 源文件 -> 公开仓里的名字。公开仓的构建脚本与 README 都是裁剪版。
RENAMES = {
    "README.public.md": "README.md",
    "app/build.gradle.public": "app/build.gradle",
}

# 即使落在 ALLOW 的目录里也要排除的(相对仓库根)。
DENY = [
    "app/src/main/jni",            # native 源码:只在内部仓
    "scripts/secrets_table.py",    # 敏感常量明文表
    "scripts/encode_secrets.py",   # 含默认主密钥与完整编码算法,不能公开
    "app/代码结构说明.md",          # 内部设计说明:只在内部仓
]

# 生成到公开仓的 .gitignore:让 so 成为唯一入库的二进制。
PUBLIC_GITIGNORE = """\
.gradle
build
/app/build
.idea
*.iml
local.properties
.env
/data/
.DS_Store
__pycache__/
*.pyc
"""


def matches(relative: str, patterns) -> bool:
    for pattern in patterns:
        if relative == pattern or relative.startswith(pattern + "/"):
            return True
    return False


def allowed_source(relative: str) -> bool:
    """内部仓里的源路径是否允许同步。"""
    if matches(relative, DENY):
        return False
    return matches(relative, ALLOW)


def allowed_target(relative: str) -> bool:
    """公开仓里的路径是否允许存在(含重命名后的目标名)。"""
    if matches(relative, DENY):
        return False
    if relative in RENAMES.values():
        return True
    return matches(relative, ALLOW)


def collect():
    """内部仓里应该出现在公开仓的文件:(公开仓路径, 源文件)。"""
    entries = []
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file() or ".git" in path.relative_to(ROOT).parts:
            continue
        relative = path.relative_to(ROOT).as_posix()
        if allowed_source(relative):
            entries.append((RENAMES.get(relative, relative), path))
    return entries


def stale_files(target: Path):
    """公开仓里存在、但按 ALLOW/DENY 不该存在的文件。"""
    stale = []
    for path in sorted(target.rglob("*")):
        if ".git" in path.relative_to(target).parts:
            continue
        relative = path.relative_to(target).as_posix()
        if path.is_file() and relative != ".gitignore" and not allowed_target(relative):
            stale.append(relative)
    return stale


def empty_dirs(target: Path, ignored=(), virtual=()):
    """删掉多余文件后变空的目录(自底向上,含连锁变空的父目录)。

    CI 用 `test ! -e docs` 校验内部目录不存在,而 `-e` 对空目录也为真:只删文件
    不删目录,公开仓会一直卡在这条校验上。删掉 tests/secret-encoding 之后 tests/
    才变空,所以要反复扫到没有新的空目录为止。

    virtual 是「check 模式下即将写入、但还没落盘的文件」:不把它们算进来,会把
    app/、app/src 这类马上就有内容的目录误报成多余空目录。
    """
    ignored = set(ignored)
    virtual = [name for name in virtual if name not in ignored]
    result = []
    removed = set()
    changed = True
    while changed:
        changed = False
        paths = sorted(target.rglob("*"), key=lambda item: len(item.parts), reverse=True)
        for path in paths:
            relative = path.relative_to(target)
            key = relative.as_posix()
            if ".git" in relative.parts or path.is_symlink() or key in removed:
                continue
            if not path.is_dir():
                continue
            children = [child for child in path.iterdir()
                        if child.relative_to(target).as_posix() not in ignored
                        and child.relative_to(target).as_posix() not in removed]
            prefix = key + "/"
            planned = any(name.startswith(prefix) for name in virtual)
            if not children and not planned:
                removed.add(key)
                result.append(path)
                changed = True
    return result


# 白名单是目录粒度(app/src 整棵树),内容级兜底:这些模式一旦出现就中止同步。
SENSITIVE_PATTERNS = [
    (re.compile(rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "私钥"),
    (re.compile(rb"AKIA[0-9A-Z]{16}"), "AWS access key"),
    (re.compile(rb"gh[pousr]_[A-Za-z0-9]{36}"), "GitHub token"),
    (re.compile(rb"xox[baprs]-[A-Za-z0-9-]{10,}"), "Slack token"),
    (re.compile(rb'WXH_MASTER_KEY\s*[=:]\s*["\']?[0-9a-fA-F]{64}'), "主密钥明文"),
    (re.compile(rb'WXH_(?:STORE|KEY)_PASSWORD\s*[=:]\s*["\'][^"\']+["\']'), "签名口令明文"),
]


def load_encoder():
    """加载 encode_secrets.py,复用它的密钥解析与编码实现(不执行 main)。"""
    script = ROOT / "scripts/encode_secrets.py"
    if not script.is_file():
        raise SystemExit("找不到 scripts/encode_secrets.py:同步必须在内部仓执行")
    spec = importlib.util.spec_from_file_location("wxh_encode_secrets", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def default_master_key():
    """内置默认主密钥,只给内容扫描用。"""
    return bytes(load_encoder().DEFAULT_MASTER_KEY)


def verify_ciphertext(key_text: str) -> None:
    """用当前主密钥重新编码明文表,逐项比对工作区的 SecretConstants.java。

    比「指纹没变」更直接:密文里每一项都必须是这把密钥编出来的,否则同步出去的
    APK 运行时全部解不出来。key_text 为空时用内置默认值(仅在 --allow-default-key
    放行后才会走到这里)。
    """
    encoder = load_encoder()
    encoder.apply_master_key(key_text)
    table, _source = encoder.secrets_table()
    path = (ROOT / "app/src/main/java/github/shadowbaby/wechatxposed/hook/loader"
            / "SecretConstants.java")
    if not path.is_file():
        raise SystemExit("找不到 %s:先在内部仓跑 ./gradlew encodeSecrets" % path)
    actual = dict(re.findall(
        r'public static final String (\w+) =\s*\n\s*"([^"]+)"',
        path.read_text(encoding="utf-8")))
    mismatched = [name for name, plain in table.items()
                  if actual.get(name) != encoder.encode(plain, name)]
    if mismatched:
        shown = ", ".join(mismatched[:5])
        if len(mismatched) > 5:
            shown += " 等 %d 项" % len(mismatched)
        raise SystemExit("SecretConstants.java 与当前主密钥不配套(不一致: %s)。"
                         "设同一把 WXH_MASTER_KEY 后重跑 ./gradlew encodeSecrets" % shown)


# 公开仓构建必需的路径。缺一个就会在 CI 里构建失败,所以同步前先在本机拦住。
REQUIRED = [
    "README.md",
    ".github/workflows/build.yml",
    "app/build.gradle",
    "app/src/main/AndroidManifest.xml",
    "app/src/main/java/github/shadowbaby/wechatxposed/hook/loader/SecretConstants.java",
    "app/src/main/jniLibs/arm64-v8a/libwexhook.so",
    "app/src/main/jniLibs/armeabi-v7a/libwexhook.so",
    "gradle/wrapper/gradle-wrapper.jar",
    "gradlew",
]


def verify_required(entries):
    """同步清单必须覆盖所有构建必需文件。"""
    names = {name for name, _ in entries}
    missing = [name for name in REQUIRED if name not in names]
    if missing:
        raise SystemExit("同步清单缺少构建必需文件: " + ", ".join(missing))


def scan_sensitive(entries):
    """扫待同步文件的内容,返回 [(相对路径, 命中类型)]。

    用默认密钥编出来的 so 会命中「内置默认主密钥」——这正是要拦的情况。
    """
    key = default_master_key()
    variants = []
    if key:
        variants = [key, key.hex().encode("ascii"),
                    key.hex().upper().encode("ascii"),
                    base64.b64encode(key)]
    hits = []
    for relative, path in entries:
        data = path.read_bytes()
        label = None
        if any(variant in data for variant in variants):
            label = "内置默认主密钥"
        else:
            for pattern, name in SENSITIVE_PATTERNS:
                if pattern.search(data):
                    label = name
                    break
        if label:
            hits.append((relative, label))
    return hits


def main() -> int:
    parser = argparse.ArgumentParser(description="同步内部仓 -> 公开仓(只写文件,不提交)")
    parser.add_argument("--to", type=Path, required=True, help="公开仓工作区路径")
    parser.add_argument("--check", action="store_true", help="只比对,不写文件")
    parser.add_argument("--allow-default-key", action="store_true",
                        help="确实要用内置默认主密钥时放行(仅本机调试,发布不要用)")
    parser.add_argument("--allow-sensitive", action="store_true",
                        help="内容扫描命中时仍然同步(确认过命中项无害再用)")
    args = parser.parse_args()

    target = args.to.resolve()
    if not target.is_dir():
        raise SystemExit("公开仓路径不存在: " + str(target))
    if target == ROOT:
        raise SystemExit("--to 不能是本仓")

    # so 必须先由内部仓构建出来(内部仓 .gitignore 忽略 jniLibs,只在这里同步)。
    for abi in ("arm64-v8a", "armeabi-v7a"):
        name = "app/src/main/jniLibs/%s/libwexhook.so" % abi
        if not (ROOT / name).is_file():
            raise SystemExit("缺 %s:先跑 ./gradlew buildNativeSecret 再发布" % name)

    # 本地前置检测(CI 只构建,这些都在同步前做完):
    #   1) 密钥必须存在(或显式允许默认值);2) 用密钥重算密文逐项比对;
    #   3) 构建必需文件齐全。
    message = ("没有设 WXH_MASTER_KEY:当前工作区的 so 是用内置默认主密钥编的,"
               "同步到公开仓等于让密文失效。\n"
               "先设发布密钥、重建 so 再同步;确认只是本机调试时加 --allow-default-key")
    key_text = os.environ.get("WXH_MASTER_KEY", "").strip()
    if not key_text:
        if not args.allow_default_key:
            raise SystemExit(message)
        print("警告:" + message)
    verify_ciphertext(key_text)
    print("主密钥与 SecretConstants 密文一致")

    entries = collect()
    verify_required(entries)
    hits = scan_sensitive(entries)
    changed = [name for name, source in entries
               if not (target / name).is_file()
               or not filecmp.cmp(source, target / name, shallow=False)]
    if not (target / ".gitignore").is_file() \
            or (target / ".gitignore").read_text(encoding="utf-8") != PUBLIC_GITIGNORE:
        changed.append(".gitignore")
    stale = stale_files(target)

    if args.check:
        for name in changed:
            print("待更新: " + name)
        for name in stale:
            print("公开仓多余(该删): " + name)
        empties = empty_dirs(target, stale, changed)
        for path in empties:
            print("多余空目录(该删): " + path.relative_to(target).as_posix())
        for name, label in hits:
            print("敏感内容(会中止): %s (%s)" % (name, label))
        blocked = bool(hits) and not args.allow_sensitive
        if blocked:
            print("有敏感内容,正式同步会被中止(确认无害后加 --allow-sensitive)")
        print("共 %d 个待更新,%d 个多余文件,%d 个空目录,%d 个敏感命中"
              % (len(changed), len(stale), len(empties), len(hits)))
        return 1 if changed or stale or empties or blocked else 0

    if hits:
        for name, label in hits:
            print("敏感内容: %s (%s)" % (name, label))
        if not args.allow_sensitive:
            raise SystemExit("同步已中止:上面的文件命中敏感内容。"
                             "确认无害(例如 so 本来就用默认密钥编的)后加 --allow-sensitive")
        print("已按 --allow-sensitive 继续")

    for name, source in entries:
        destination = target / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    (target / ".gitignore").write_text(PUBLIC_GITIGNORE, encoding="utf-8")
    for name in stale:
        (target / name).unlink()
    removed_dirs = 0
    for path in empty_dirs(target):
        path.rmdir()
        removed_dirs += 1
    print("已同步 %d 个文件到 %s" % (len(entries) + 1, target))
    print("删除多余文件 %d 个、空目录 %d 个" % (len(stale), removed_dirs))
    print("公开仓里请自行 git status / commit / push(本脚本不碰版本库)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
