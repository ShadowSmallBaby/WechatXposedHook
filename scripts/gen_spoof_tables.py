#!/usr/bin/env python3
"""Generate app/src/main/jni/spoof_tables.inc (XOR-obfuscated URI tables)."""
from pathlib import Path

KEY = bytes([0x3C, 0x91, 0x5E, 0x27, 0xD4, 0x6A, 0x0B, 0xF8,
             0x45, 0xA2, 0x7D, 0x19, 0xC6, 0x38, 0x9B, 0x64])

TABLES = {
    "STARTUP": ["getonlineinfo"],
    "CALL_START": [
        "voipilinkgetsdkmode", "voipilinkinvite",
        "voipinvite", "getfriendringback",
    ],
    "CALL": [
        "voipilink", "voipinvite", "getfriendringback",
        "mmilinktransfer", "voipspeedtest", "voipshutdown",
    ],
    "CALL_SHUTDOWN": ["voipshutdown"],
    "MINI_PROGRAM": ["launchwxaapp"],
    "WALLET_URI": [
        "mmpay", "tenpay", "wallet", "remit", "transfer",
        "redpacket", "lucky", "hongbao",
    ],
    "EXT_UNAVAILABLE": ["mf_unlocked", "af_unlocked", "sf_unlocked"],
    "WALLET_CLASS": [
        "wallet", "mmpay", "tenpay", "remit", "kinda",
        "redpacket", "hongbao", "lucky", "plugin.pay", "plugin.hb",
    ],
}

VERSION_HIGH = 0x28004F00
VERSION_MASK = 0x5A5A5A5A


def encode(text: str) -> bytes:
    return bytes(
        (ch ^ KEY[i & 15] ^ ((i * 77 + 13) & 0xFF)) & 0xFF
        for i, ch in enumerate(text.encode("utf-8"))
    )


def hex_array(data: bytes) -> str:
    return ", ".join(f"0x{b:02x}" for b in data)


def main() -> None:
    out = [
        "/* 由 scripts/gen_spoof_tables.py 生成，请勿手改。 */",
        "#ifndef WEXPOSEDHOOK_SPOOF_TABLES_INC",
        "#define WEXPOSEDHOOK_SPOOF_TABLES_INC",
        "",
        "#include <stddef.h>",
        "#include <stdint.h>",
        "",
        "typedef struct {",
        "    const uint8_t *data;",
        "    size_t length;",
        "} SpoofEntry;",
        "",
        "static const uint8_t SPOOF_KEY[16] = {" + hex_array(KEY) + "};",
        f"static const uint32_t SPOOF_VERSION_HIGH_ENC = "
        f"0x{VERSION_HIGH ^ VERSION_MASK:08x}u;",
        f"static const uint32_t SPOOF_VERSION_MASK = 0x{VERSION_MASK:08x}u;",
        "",
    ]
    for table, values in TABLES.items():
        for index, value in enumerate(values):
            out.append(
                f"static const uint8_t SPOOF_{table}_{index}[] = "
                f"{{{hex_array(encode(value))}}};"
            )
        out.append(f"static const SpoofEntry SPOOF_{table}_TABLE[] = {{")
        for index in range(len(values)):
            out.append(f"    {{SPOOF_{table}_{index}, sizeof(SPOOF_{table}_{index})}},")
        out.append("};")
        out.append(f"#define SPOOF_{table}_COUNT {len(values)}")
        out.append("")

    out.append("#endif")
    output = Path(__file__).resolve().parent.parent / "app/src/main/jni/spoof_tables.inc"
    output.write_text("\n".join(out) + "\n", encoding="utf-8")
    print("written", output)


if __name__ == "__main__":
    main()
