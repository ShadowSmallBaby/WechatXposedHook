#!/usr/bin/env python3
"""生成 native 侧的 PBE/pack 表（pack_tables.inc）。

这些值以前明文写在 Java（PbePasswordHook / FeatureDexDecoder），
会直接出现在 classes.dex 里。现在用固定 key 做异或混淆后嵌进 .so，
Java 只保留 JNI 调用。

生成：
    python -X utf8 scripts/gen_native_pack_tables.py
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "app" / "src" / "main" / "jni" / "pack_tables.inc"

sys.path.insert(0, str(Path(__file__).resolve().parent))
from runtime_names import BRIDGE, CORE, UTILITY, runtime

# salt -> 原版 PBE password（13 组）
SALT_PASSWORDS = [
    ("d633214bb4d850dd", "e6aee704494ab6acd79bc868a75135b"),
    ("d32d773b563946f3", "fafba0be93dfdc4c824e1f55836337a"),
    ("d160390cf774897a", "ac282e135a29e137cf97b7677676c520"),
    ("64a6cec00efffe95", "bf36c57719f36670d8698e4eae462b7a"),
    ("df6ebf06ff084612", "5d456b83a6d59d629f857b5fb6a373f"),
    ("6c19de68765e453d", "c22e742b6568af04cac4a8e9d058ef"),
    ("4ef8d6e5975bc791", "4912fbaa87edab22b7f737b794b4a39"),
    ("6ce21e9a6e7bdf13", "dbba162ca04f5e34992738651a2666f"),
    ("6ab1b76617b99bfe", "4f74d05b691fd81abe1838b3bffbb9e9"),
    ("7b246fe6504fe9a2", "46d94ff9016e397dc16a4e99d98fbd"),
    ("cbc70f4d090f2a91", "80752d1605bf6235493bb1e113c3e8c"),
    ("b3bd7a8b8bc5c7ea", "b44dc02d7003e24ffb11d41d5d31323"),
    ("58b92e5fa34d938e", "4f61bb9ec1e854c9753f878a883a294"),
]

# role -> 外层 password | 内层 password | 容器文件 1 | 容器文件 2
PACK_PLANS = [
    ("x30-sf", "80752d1605bf6235493bb1e113c3e8c",
     "5c897b16c61610673c398e6553f3b",
     "aa894d53fa41c9b675eec6f80331085",
     "60d31eb37595dd44584be5ef363283e3"),
    ("x30-mf", "4f61bb9ec1e854c9753f878a883a294",
     "e82b5260fd15c04fd7f1dea075738c1",
     "665c7b62836222d48164bc1c5f93fb2",
     "ea81aa7df47d74c6737bf98fabf3ff82"),
    ("x30-af", "4f74d05b691fd81abe1838b3bffbb9e9",
     "5b4f49dc184d84d15cf14915e854449",
     "3e9bf1b973f6b1617f4f6df9a88f39d",
     "f0357a3f154bc2ffe2bff55055457068"),
]

# 功能包 DB 参数：索引 -> 值（AES key、默认 fp/版本）。
PACK_DB_VALUES = [
    "FKZ_WX_DATA",
    "31d019ea56d574133508b10d944b413c4fb9eb58a90e1a015c62729f7459c66d",
    "themes,af,sf,mf",
    "base,vidurlparser,donation",
    "{\"themes\":113,\"donation\":71,\"base\":525,\"vidurlparser\":30,"
    "\"sf\":75,\"mf\":137,\"af\":171}",
    "{\"themes\":116,\"vidurlparser\":31,\"donation\":72,\"base\":519,"
    "\"af\":175,\"sf\":76,\"mf\":132}",
    "1065821554",
]

# 运行目录 + 四个由项目私钥签名的包（name|body length）。
PACK_GUARD_VALUES = [
    "x7_3.0",
    "14e777717682cce8a53cfcb34a22d65|994250",
    "802766a4a4bd401c145a57463274d4dd|200554",
    "a89eaf67dc796cb3af54d94fac0198b|121962",
    "df4e6fd144fab2389ece8cb79eaa8f|129498",
]

# 运行时恢复清单：基础包 26、扩展包 3、扩展包别名 3。
RESTORE_META = ["x30", "x7_3.0", "x30-ext"]

# 能算的名字走 runtime_names，厂商固定 ID 走 BRIDGE / UTILITY，避免手抄漂移。
BASE = runtime("base")
THEMES = runtime("themes")
DONATION = runtime("donation")
VIDURLPARSER = runtime("vidurlparser")
SF, MF, AF = runtime("sf"), runtime("mf"), runtime("af")

# (xmetadata 源, 运行时名, 侧车角色)。清单顺序就是恢复顺序。
BASE_SOURCES = [
    ("r/fp/base", BASE, "base"),
    ("r/L", BRIDGE, "L"),
    ("pr/P", UTILITY["pr/P"], None),
    ("D", UTILITY["D"], None),
    ("S", UTILITY["S"], None),
    ("H_p", UTILITY["H_p"], None),
    ("M", UTILITY["M"], None),
    ("pr/P_8049", UTILITY["pr/P_8049"], None),
    ("Xmd", UTILITY["Xmd"], None),
    ("r/fp/themes", THEMES, "themes"),
    ("r/fp/donation", DONATION, "donation"),
    ("3.0/r/C", CORE, "C"),
    ("r/fp/vidurlparser", VIDURLPARSER, "vidurlparser"),
    ("LD64", UTILITY["LD64"], None),
]

EXT_SOURCES = [
    ("r/fp/sf", SF, None),
    ("r/fp/mf", MF, None),
    ("r/fp/af", AF, None),
]

SOURCE_ROOT = ROOT / "xmetadata" / "wx7"

# 迁移前的长度；源目录换错时尽早报错，避免把错误清单烧进 .so。
EXPECTED_SIZES = {
    BASE: 994250,
    BASE + "_c": 599,
    BASE + "_s": 256,
    BRIDGE: 597288,
    BRIDGE + "_c": 599,
    BRIDGE + "_s": 256,
    UTILITY["pr/P"]: 4568,
    UTILITY["D"]: 1159,
    UTILITY["S"]: 258922,
    UTILITY["H_p"]: 48008,
    UTILITY["M"]: 41464,
    UTILITY["pr/P_8049"]: 43336,
    UTILITY["Xmd"]: 98264,
    THEMES: 200554,
    THEMES + "_c": 599,
    THEMES + "_s": 256,
    DONATION: 121962,
    DONATION + "_c": 599,
    DONATION + "_s": 256,
    CORE: 370042,
    CORE + "_c": 599,
    CORE + "_s": 256,
    VIDURLPARSER: 129498,
    VIDURLPARSER + "_c": 599,
    VIDURLPARSER + "_s": 256,
    UTILITY["LD64"]: 533080,
    SF: 91594,
    MF: 148186,
    AF: 182538,
}


def payload(relative: str) -> bytes:
    """读取 32B SHA-256 + body 的源文件，返回校验过的 body。"""
    path = SOURCE_ROOT / relative
    data = path.read_bytes()
    if len(data) < 32:
        raise SystemExit(f"{path}: 源文件过短")
    body = data[32:]
    if hashlib.sha256(body).digest() != data[:32]:
        raise SystemExit(f"{path}: 前 32 字节不是 body 的 SHA-256")
    return body


def sidecar(role: str, suffix: str) -> bytes:
    path = SOURCE_ROOT / "cfg" / (role + suffix)
    data = path.read_bytes()
    expected = 599 if suffix == ".c" else 256
    if len(data) != expected:
        raise SystemExit(f"{path}: 应为 {expected} 字节，实际 {len(data)}")
    return data


def restore_entries(sources) -> list[tuple[str, int, str]]:
    entries: list[tuple[str, int, str]] = []

    def add(name: str, data: bytes) -> None:
        expected = EXPECTED_SIZES.get(name)
        if expected is not None and len(data) != expected:
            raise SystemExit(
                f"{name}: 源长度 {len(data)} != 迁移前清单 {expected}；"
                "确认 xmetadata 是否已更新，更新后同步 EXPECTED_SIZES"
            )
        entries.append((name, len(data), hashlib.sha256(data).hexdigest()))

    for relative, name, role in sources:
        add(name, payload(relative))
        if role is not None:
            add(name + "_c", sidecar(role, ".c"))
            add(name + "_s", sidecar(role, ".s"))
    return entries


RESTORE_BASE = restore_entries(BASE_SOURCES)
RESTORE_EXT = restore_entries(EXT_SOURCES)

RESTORE_ALIASES = [
    ("aa894d53fa41c9b675eec6f80331085", "60d31eb37595dd44584be5ef363283e3"),
    ("665c7b62836222d48164bc1c5f93fb2", "ea81aa7df47d74c6737bf98fabf3ff82"),
    ("3e9bf1b973f6b1617f4f6df9a88f39d", "f0357a3f154bc2ffe2bff55055457068"),
]

KEY = bytes.fromhex("9f2c41d8b73ea60551cc7e20f4a9d38b")

# 项目自签公钥（X.509 SubjectPublicKeyInfo DER）；私钥只在 .env/CI secret。
PACK_SIGN_PUBLIC_KEY = bytes.fromhex(
    "30820122300d06092a864886f70d01010105000382010f003082010a028201010096a1530ecdbbd574e7461e6c1d4c14387e647c575cd6776931c378252d9eb109fccf93aa43e875dd8fdbbeb8171bb20507ede448edee05d0108fdbe48ee0e3a3231cbdc5e9999a855772cf07c6ca8c0580710e6089a84ec73b7be2b0416178697fd503e1379ece8b220ea943e29d099dbd082106e10a0fba7624a7f1003ee987e49218ee3eaf743b653b2386bfcd9850ae19f96366ae746c0ea780f689d7d16ba9b1234c30c9076557350a8e75efb71a1ef82aed525245ca7b47b1c27149fca62681de70ca8fb7a0e08e8f9a24a5522c9da5c4a9742d2d1a4535dae00354cdfe3bd7d29e59d987d331a6ee3de857b3c4efa2ce36620153350c2d09f5109055b30203010001")


def obfuscate(text: str) -> bytes:
    raw = text.encode("ascii")
    return bytes(
        value ^ KEY[index % len(KEY)] ^ ((index * 77 + 13) & 0xFF)
        for index, value in enumerate(raw)
    )


def c_array(name: str, data: bytes) -> list[str]:
    body = ", ".join(f"0x{value:02x}" for value in data)
    return [f"static const uint8_t {name}[] = {{{body}}};"]


def emit_table(prefix: str, entries: list[tuple[str, ...]]) -> tuple[list[str], list[str]]:
    lines: list[str] = []
    names: list[str] = []
    for index, entry in enumerate(entries):
        name = f"{prefix}_{index}"
        names.append(name)
        lines += c_array(name, obfuscate("|".join(entry)))
    return lines, names


def main() -> int:
    lines = [
        "/* 由 scripts/gen_native_pack_tables.py 生成，请勿手改。 */",
        "#ifndef WEXPOSEDHOOK_PACK_TABLES_INC",
        "#define WEXPOSEDHOOK_PACK_TABLES_INC",
        "",
        "#include <stddef.h>",
        "#include <stdint.h>",
        "",
        "typedef struct {",
        "    const uint8_t *data;",
        "    size_t length;",
        "} PackTableEntry;",
        "",
    ]
    salt_lines, salt_names = emit_table("PACK_SALT", SALT_PASSWORDS)
    plan_lines, plan_names = emit_table("PACK_PLAN", PACK_PLANS)
    db_lines = [line for index, value in enumerate(PACK_DB_VALUES)
                for line in c_array("PACK_DB_%d" % index, obfuscate(value))]
    guard_lines = [line for index, value in enumerate(PACK_GUARD_VALUES)
                   for line in c_array("PACK_GUARD_%d" % index, obfuscate(value))]
    restore_meta_lines = [line for index, value in enumerate(RESTORE_META)
                          for line in c_array("RESTORE_META_%d" % index, obfuscate(value))]
    restore_base_lines = [
        line for index, value in enumerate(RESTORE_BASE)
        for line in c_array("RESTORE_BASE_%d" % index,
                            obfuscate("%s|%d|%s" % value))]
    restore_ext_lines = [
        line for index, value in enumerate(RESTORE_EXT)
        for line in c_array("RESTORE_EXT_%d" % index,
                            obfuscate("%s|%d|%s" % value))]
    restore_alias_lines = [
        line for index, value in enumerate(RESTORE_ALIASES)
        for line in c_array("RESTORE_ALIAS_%d" % index,
                            obfuscate("%s|%s" % value))]
    key_body = ", ".join(f"0x{value:02x}" for value in PACK_SIGN_PUBLIC_KEY)
    lines += (salt_lines + [""] + plan_lines + [""] + db_lines + [""]
              + guard_lines + [""] + restore_meta_lines + [""]
              + restore_base_lines + [""] + restore_ext_lines + [""]
              + restore_alias_lines + [""])
    lines.append("static const uint8_t PACK_SIGN_PUBLIC_KEY[] = {%s};" % key_body)
    lines.append("")
    lines.append("static const PackTableEntry PACK_SALT_TABLE[] = {")
    for name in salt_names:
        lines.append(f"    {{{name}, sizeof({name})}},")
    lines.append("};")
    lines.append("static const PackTableEntry PACK_PLAN_TABLE[] = {")
    for name in plan_names:
        lines.append(f"    {{{name}, sizeof({name})}},")
    lines.append("};")
    lines.append("static const PackTableEntry PACK_DB_TABLE[] = {")
    for index in range(len(PACK_DB_VALUES)):
        lines.append(f"    {{PACK_DB_{index}, sizeof(PACK_DB_{index})}},")
    lines.append("};")
    lines.append("static const PackTableEntry PACK_GUARD_TABLE[] = {")
    for index in range(len(PACK_GUARD_VALUES)):
        lines.append(f"    {{PACK_GUARD_{index}, sizeof(PACK_GUARD_{index})}},")
    lines.append("};")
    lines.append("static const PackTableEntry RESTORE_META_TABLE[] = {")
    for index in range(len(RESTORE_META)):
        lines.append(f"    {{RESTORE_META_{index}, sizeof(RESTORE_META_{index})}},")
    lines.append("};")
    lines.append("static const PackTableEntry RESTORE_BASE_TABLE[] = {")
    for index in range(len(RESTORE_BASE)):
        lines.append(f"    {{RESTORE_BASE_{index}, sizeof(RESTORE_BASE_{index})}},")
    lines.append("};")
    lines.append("static const PackTableEntry RESTORE_EXT_TABLE[] = {")
    for index in range(len(RESTORE_EXT)):
        lines.append(f"    {{RESTORE_EXT_{index}, sizeof(RESTORE_EXT_{index})}},")
    lines.append("};")
    lines.append("static const PackTableEntry RESTORE_ALIAS_TABLE[] = {")
    for index in range(len(RESTORE_ALIASES)):
        lines.append(f"    {{RESTORE_ALIAS_{index}, sizeof(RESTORE_ALIAS_{index})}},")
    lines.append("};")
    lines += [
        "",
        "#define PACK_SALT_COUNT (sizeof(PACK_SALT_TABLE) / sizeof(PACK_SALT_TABLE[0]))",
        "#define PACK_PLAN_COUNT (sizeof(PACK_PLAN_TABLE) / sizeof(PACK_PLAN_TABLE[0]))",
        "#define PACK_DB_COUNT (sizeof(PACK_DB_TABLE) / sizeof(PACK_DB_TABLE[0]))",
        "#define PACK_GUARD_COUNT (sizeof(PACK_GUARD_TABLE) / sizeof(PACK_GUARD_TABLE[0]))",
        "#define RESTORE_META_COUNT (sizeof(RESTORE_META_TABLE) / sizeof(RESTORE_META_TABLE[0]))",
        "#define RESTORE_BASE_COUNT (sizeof(RESTORE_BASE_TABLE) / sizeof(RESTORE_BASE_TABLE[0]))",
        "#define RESTORE_EXT_COUNT (sizeof(RESTORE_EXT_TABLE) / sizeof(RESTORE_EXT_TABLE[0]))",
        "#define RESTORE_ALIAS_COUNT (sizeof(RESTORE_ALIAS_TABLE) / sizeof(RESTORE_ALIAS_TABLE[0]))",
        "",
        "#endif",
    ]
    OUTPUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"{OUTPUT}: {len(SALT_PASSWORDS)} salts, {len(PACK_PLANS)} plans")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
