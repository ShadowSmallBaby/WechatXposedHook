"""测试共用的路径与源码集。

模块现在有两个 flavor(legacy / modern),产物与 sourceSet 都分开了:

    app/src/main/java      两端共用的业务代码
    app/src/legacy/java    legacy 入口与框架适配层
    app/src/modern/java    modern 入口与框架适配层

    app/build/outputs/apk/legacyWx30FullEdition/release/WeXposedHook-legacy-wx3.0-*.apk
    app/build/outputs/apk/modernWx30FullEdition/release/WeXposedHook-modern-wx3.0-*.apk

这些测试都跑在真机上,用 legacy 包(含 assets/xposed_init 与两个 ABI 的 so);
两个 flavor 的 so 内容相同,主密钥与密文表也相同,所以取哪一份都行。
测试机都是 arm64,所以这里固定取 lib/arm64-v8a/ 那份。
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# 测试用的 flavor:legacy 包与 modern 包除了 Xposed 描述符外没有差别。
FLAVOR = "legacy"

APK = ROOT / "app/build/outputs/apk/legacyWx30FullEdition/release" / (
    "WeXposedHook-legacy-wx3.0-v1.3.6-full.apk")

# 模块的 so 名(两个 flavor 相同)。
LIB_NAME = "libwexhook.so"

# so 在 APK 里的路径。
LIB_ENTRY = "lib/arm64-v8a/" + LIB_NAME


def app_sources(*extra_flavors):
    """app 的 Java 源码(含 flavor 目录);extra_flavors 可指定额外的 flavor 源码目录。"""
    sources = sorted((ROOT / "app/src/main/java").rglob("*.java"))
    for flavor in (FLAVOR,) + tuple(extra_flavors):
        sources += sorted((ROOT / "app/src" / flavor / "java").rglob("*.java"))
    return sources


def read_lib(apk=None):
    """从 APK 里取出 so 的字节。"""
    import zipfile
    with zipfile.ZipFile(apk or APK) as archive:
        return archive.read(LIB_ENTRY)