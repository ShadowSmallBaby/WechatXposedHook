"""把敏感常量编码成 SecretConstants.java(构建前运行)。

用法:
    python -X utf8 scripts/encode_secrets.py [--master-key <32 字节 hex 或 Base64>]

明文来源(按优先级):
   1. 环境变量 WXH_SECRETS_B64:整张表 JSON 序列化后 Base64;
   2. scripts/secrets_table.py:本地明文表(可选)。

本文件不含明文。NAMES 列出全部常量名,用于校验明文表是否齐全。

编码后写入 app/build/generated/secrets/<edition>/.../SecretConstants.java。
主密钥用 --master-key 或 WXH_MASTER_KEY 覆盖;每个常量以常量名作为
HKDF-SHA256 的 salt 派生独立子密钥,再做逐字节 XOR + 位置混合并 Base64。
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = Path("java/github/shadowbaby/wechatxposed/hook/loader")
EDITIONS = ("publicEdition", "fullEdition")

ADVANCED_FEATURES = {
    "multichat_autoforward",
    "moments_auto_forward",
    "secret_friend",
    "auto_accept_chatroom_invite",
    "integrated_mode",
}

# 全部常量名(不含明文)。与源码里 Secret.of(SecretConstants.XXX) 的引用一一对应。
NAMES = [
    # XposedInit
    "WECHAT_PACKAGE",
    "APPBRAND_0",
    "APPBRAND_1",
    "IN_MEMORY_DEX_LOADER",

    # InMemoryDexLoadHook
    "COMPONENT_BASE",
    "COMPONENT_CORE",
    "COMPONENT_DONATION",
    "COMPONENT_THEMES",
    "COMPONENT_X30",
    "X30_BRIDGE_CLASS",
    "X30_LOADER_CLASS",
    "X30_LICENSE_CLASS",
    "X30_UPDATE_CLASS",
    "X30_SETTINGS_CLASS",
    "X30_LICENSE_CLASS_V207",
    "X30_UPDATE_CLASS_V207",
    "X30_SETTINGS_CLASS_V207",
    "X30_PARAMS_APPLY",
    "X30_PARAMS_APPLY_V207",
    "X30_PARAMS_VERIFY",
    "X30_PARAMS_VERIFY_V207",
    "X30_VERIFIER_EXPIRED",
    "X30_VERIFIER_EXPIRED_V207",
    "X30_DOWNLOAD_PARAMS",
    "X30_DOWNLOAD_PARAMS_V207",
    "X30_DOWNLOAD_CORE",
    "X30_DOWNLOAD_CORE_V207",
    "X30_BRIDGE_WRAPPER",
    "X30_BRIDGE_WRAPPER_V207",
    "X30_BRIDGE_CALL",
    "X30_BRIDGE_CALL_V207",
    "X30_SET_DISABLE",
    "X30_SET_DISABLE_V207",
    "X30_DISABLE_FEATURES",
    "X30_DISABLE_FEATURES_V207",
    "X30_CALL_METHOD",
    # X 3.0 guard / UI / feature registry
    "X30_GUARD_DISABLE_EXTRA",
    "X30_UI_CLASS",
    "X30_UI_OPTIONS",
    "X30_UI_KEYWORDS",
    "X30_UI_GATE",
    "X30_UI_ADAPTER",
    "X30_ADAPTER_GROUPS",
    "X30_ADAPTER_ITEMS",
    "X30_CORE_DATA_CLASS",
    "X30_CORE_DATA_GET",
    "X30_FEATURE_MANAGER",
    "X30_FEATURE_UNLOAD",
    "X30_FEATURE_UNLOAD_ONE",
    "X30_FEATURE_LOAD_ONE",
    "X30_FEATURE_LOAD_CLASS",
    "X30_FEATURE_LOAD_DEX",
    "X30_UNLOAD_HANDLER",
    "X30_UNLOAD_HANDLER_CALL",
    "X30_SETTINGS_WRAPPER",
    "X30_SETTINGS_BOOL",
    "X30_REGISTRATION",
    "X30_PARAMS_FILE_METHOD",
    "X30_MENU_CLASS_1",
    "X30_MENU_METHOD_1",
    "X30_MENU_CLASS_2",
    "X30_MENU_METHOD_2",
    "X30_MENU_CLASS_3",
    "X30_MENU_METHOD_3",
    "X30_COMPONENT_UNLOAD_CLASS",
    "X30_CORE_DATA_INSTANCE_METHOD",
    "X30_UPDATE_INIT_METHOD",
    "X30_COMPONENT_NAME_METHOD",
    "X30_FORCE_FLAG_1",
    "X30_FORCE_FLAG_2",
    "X30_FORCE_FLAG_3",
    "X30_FORCE_FLAG_4",
    "X30_FORCE_FLAG_5",
    "X30_FORCE_FLAG_6",
    "X30_ENTRY_BASE",
    "X30_ENTRY_DONATION",
    "X30_ENTRY_THEMES",
    "X30_BASE_SETTINGS",
    "X30_BASE_REGISTRY",
    "X30_REGISTRY_REMOVE",
    "X30_REGISTRY_PUBLISH",
    "X30_REGISTRY_GET_DATA",
    "X30_BASE_DISABLE_GETTER",
    "COMPONENT_NAME_BASE",
    "COMPONENT_NAME_CORE",
    "COMPONENT_NAME_DONATION",
    "COMPONENT_NAME_THEMES",
    "METHOD_ON_UPDATE_CHECK",
    "METHOD_DISABLE",
    "METHOD_PROCESS_METADATA",
    "METHOD_UPDATE_LICENSE",
    "METHOD_DELAYED_CHECK",

    # WxComponentHooks
    "BASE_ENTRY_CLASS",
    "BASE_ENTRY_METHOD",
    "BASE_HOOK_ARGUMENT_CLASS",
    "WX_JNI_CORE_BRIDGE",
    "CALL_METHOD",
    "CORE_VERIFIER_CLASS",
    "CORE_VERIFY_SIGNATURE_METHOD",
    "CORE_VERIFY_BOOLEAN_STRING_METHOD",
    "CORE_VERIFY_UPDATED_TIPS_METHOD",
    "CORE_POLLING_CLASS",
    "CORE_POLLING_METHOD",
    "CORE_LICENSE_CLASS",
    "CORE_LICENSE_METHOD",
    "THEMES_ENTRY_CLASS",
    "THEMES_ENTRY_METHOD",
    "THEMES_HOOK_ARGUMENT_CLASS",
    "DONATION_ENTRY_CLASS",
    "DONATION_ENTRY_METHOD",
    "DONATION_HOOK_ARGUMENT_CLASS",

    # CallMethodBypassHook
    "VERIFIER_SERVICE",
    "ACTION_PARAM",
    "MIN_SUPPORTED_VERSION",
    "UNLIMITED",
    "REMOTE_COMMAND",
    "OBJECTS_CLASS",
    "OBJECTS_EQUALS_METHOD",
    "VERIFIER_SERVICE_CLASS",
    "VERIFIER_SERVICE_FACTORY",
    "LICENSE_FIELD",
    "LICENSE_GETTER_METHOD",
    "RELEASE_LICENSE_METHOD",
    "CLEANUP_CLASS",
    "CLEANUP_FACTORY_METHOD",
    "SET_INTERNAL_VERSION_METHOD",
    "WXID_PREFIX",
    "FEATURES",

    # LicenseData
    "LATEST_VERSIONS",
    "FP_VERSIONS",
    "FP",
    "FP_ASYNC",
    "LICENSE_FEATURE_SET",
    "LICENSE_TAG",
    "VERIFIER6_TAG",

    # StartupCheck / ModuleApk
    "PREFS_PATH",
    "ACCOUNT_KEY",
    "MODULE_PACKAGE",

    # FeaturePackRestorer
    "FEATURE_DIR",
    "FEATURE_PAYLOAD",

    # HostVersionSpoof / DexPaths
    "CLIENT_VERSION_CLASS",
    "CLIENT_VERSION_FIELD",
    "OPEN_URL_ANCHOR_MAIN",
    "OPEN_URL_ANCHOR_APPID",
    "OPEN_URL_ANCHOR_STYLE",
    "UPGRADE_URL_1",
    "UPGRADE_URL_2",
    "DEX_SUFFIX",
    "DEX_PREFIX",
]


def encode(plain: str, name: str) -> str:
    """编码一个常量:子密钥按常量名派生,密文前缀带上名字(so 要用它派生)。"""
    subkey = derive_subkey(name)
    raw = plain.encode("utf-8")
    out = bytearray(len(raw))
    for index, value in enumerate(raw):
        out[index] = value ^ subkey[index % len(subkey)] ^ ((index * 31) & 0xFF)
    return name + ":" + base64.b64encode(bytes(out)).decode("ascii")


# 默认主密钥:32 字节,必须与 app/src/main/jni/secret_crypto.inc 的 SECRET_MASTER_KEY
# 逐字节一致。它编译进 so,dex 里没有;每项的子密钥由它 + 常量名经 HKDF-SHA256 派生。
# 换密钥:用 --master-key / WXH_MASTER_KEY 覆盖(见 parse_master_key),两边同时改。
DEFAULT_MASTER_KEY = bytes([
    0x7b, 0x1e, 0x4d, 0x92, 0x35, 0xa8, 0x0f, 0xc6,
    0x51, 0x3b, 0xe7, 0x28, 0x9d, 0x64, 0x02, 0xfa,
    0x8c, 0x17, 0xb3, 0x5e, 0xd0, 0x49, 0x26, 0x7f,
    0xa1, 0x38, 0xcb, 0x06, 0x94, 0x5d, 0xe2, 0x70,
])

# 当前生效的主密钥;由 main() 按 --master-key / WXH_MASTER_KEY 覆盖后再派生。
MASTER_KEY = DEFAULT_MASTER_KEY

SUBKEY_LEN = 32

# HKDF 的 info 串;必须与 app/src/main/jni/secret_crypto.inc 的 SECRET_HKDF_INFO 一致。
HKDF_INFO = b"wexhook-v2"


def parse_master_key(text: str) -> bytes:
    """解析 32 字节主密钥:64 位 hex 或标准 Base64;两者都必须恰好解出 32 字节。"""
    compact = text.strip()
    if len(compact) == 64 and all(ch in "0123456789abcdefABCDEF" for ch in compact):
        key = bytes.fromhex(compact)
    else:
        try:
            key = base64.b64decode(compact, validate=True)
        except Exception:
            raise SystemExit("主密钥既不是 64 位 hex,也不是合法 Base64: " + text)
    if len(key) != 32:
        raise SystemExit("主密钥必须是 32 字节(256 bit),实际 %d 字节" % len(key))
    return key


def apply_master_key(argument: str) -> str:
    """把 --master-key / WXH_MASTER_KEY 应用到全局 MASTER_KEY,返回来源说明。"""
    global MASTER_KEY
    text = argument if argument else os.environ.get("WXH_MASTER_KEY")
    if not text:
        MASTER_KEY = DEFAULT_MASTER_KEY
        return "内置默认值"
    MASTER_KEY = parse_master_key(text)
    if MASTER_KEY == DEFAULT_MASTER_KEY:
        return "命令行 / 环境变量(与内置默认值相同)"
    return "命令行 / 环境变量"


def _hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 的 extract + expand,输出 length 字节。"""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def derive_subkey(name: str) -> bytes:
    """与 app/src/main/jni/secret.c 的 derive_subkey 一致:主密钥 + 常量名 -> 子密钥。"""
    return _hkdf_sha256(MASTER_KEY, name.encode("utf-8"), HKDF_INFO, SUBKEY_LEN)


def java_string(name: str, value: str) -> str:
    """常量声明;明文只出现在脚本里,生成的文件只有密文。"""
    return '    public static final String %s =\n            "%s";' % (name, value)


def secrets_table() -> dict:
    """取常量表:优先环境变量 WXH_SECRETS_B64(JSON + Base64),否则读本机的 secrets_table.py。"""
    encoded = os.environ.get("WXH_SECRETS_B64")
    source = "WXH_SECRETS_B64"
    if encoded:
        table = json.loads(base64.b64decode(encoded).decode("utf-8"))
        if not isinstance(table, dict) or not table:
            raise SystemExit("WXH_SECRETS_B64 解出来不是非空 JSON 对象")
    else:
        source = "scripts/secrets_table.py"
        table_file = ROOT / "scripts/secrets_table.py"
        if not table_file.is_file():
            raise SystemExit("没有 WXH_SECRETS_B64,也找不到 " + str(table_file)
                             + "(公开仓没有明文表,改用 CI Secrets 注入 WXH_SECRETS_B64)")
        import importlib.util
        spec = importlib.util.spec_from_file_location("secrets_table", table_file)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        table = module.SECRETS
    validate(table)
    return table, source


def validate(table: dict) -> None:
    """常量名必须与 NAMES 完全一致:缺项会让源码引用编译不过,多项说明表过期了。"""
    missing = [name for name in NAMES if name not in table]
    extra = [name for name in table if name not in NAMES]
    if missing or extra:
        raise SystemExit("常量名与 NAMES 不一致: 缺 %s,多 %s"
                         % (sorted(missing), sorted(extra)))


def public_table(table: dict) -> dict:
    result = dict(table)
    features = [item for item in result["FEATURES"].split(",")
                if item not in ADVANCED_FEATURES]
    result["FEATURES"] = ",".join(features)
    return result


def write_constants(table: dict, target: Path, source: str, key_source: str) -> None:
    lines = [
        "package github.shadowbaby.wechatxposed.hook.loader;",
        "",
        "public final class SecretConstants {",
        "",
    ]
    for name, plain in table.items():
        lines.append(java_string(name, encode(plain, name)))
        lines.append("")
    lines += [
        "    private SecretConstants() {",
        "    }",
        "}",
        "",
    ]
    target.mkdir(parents=True, exist_ok=True)
    (target / "SecretConstants.java").write_text("\n".join(lines), encoding="utf-8")
    print("已生成 %d 个常量密文 -> %s(来源 %s;主密钥 %s)"
          % (len(table), target, source, key_source))


def main():
    parser = argparse.ArgumentParser(description="把敏感常量编码成 SecretConstants.java")
    parser.add_argument("--master-key",
                        help="32 字节主密钥(64 位 hex 或标准 Base64);缺省用 WXH_MASTER_KEY"
                             " 或内置默认值,必须与 so 里 secret_crypto.inc 的取值一致")
    parser.add_argument("--output-root", type=Path,
                        default=ROOT / "app" / "build" / "generated" / "secrets",
                        help="生成目录（默认 app/build/generated/secrets）")
    args = parser.parse_args()
    # 每项的子密钥按常量名派生(与 so 里的 derive_subkey 一致),dex 里没有密钥。
    key_source = apply_master_key(args.master_key)
    table, source = secrets_table()
    for edition, edition_table in (
            ("fullEdition", table),
            ("publicEdition", public_table(table))):
        target = args.output_root / edition / PACKAGE
        write_constants(edition_table, target, source, key_source)


if __name__ == "__main__":
    main()
