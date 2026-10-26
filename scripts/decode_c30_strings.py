#!/usr/bin/env python3
"""离线解密 X 3.0 core dex（c.**）的字符串常量。

表来自 c.ʾˎ.ⁱˋ.<clinit> 里 5 个 const-string 常量，
混合函数是 c.ʾˎ.ʾʻ.ⁱˋ(J)（16 位短整型循环移位，按 int 宽度移位后再截断）。
"""
import sys

from androguard.core.dex import DEX

MASK16 = 0xFFFF
MASK32 = 0xFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF
TABLE_CLASS = "Lc/ʾˎ/ⁱˋ;"


def s16(value):
    value &= MASK16
    return value - 0x10000 if value & 0x8000 else value


def rol_short(value, bits):
    """c.ʾˎ.ʾʻ.ﾞⁱ(S, I)S：int 宽度左移，逻辑右移补位，结果截成 short。"""
    raw = value & MASK32
    return s16(((raw << bits) | (raw >> (32 - bits))) & MASK32)


def hash64(value):
    """c.ʾˎ.ʾʻ.ʾʻ(J)J"""
    value &= MASK64
    value ^= value >> 33
    value = (value * 7109453100751455733) & MASK64
    value ^= value >> 28
    value = (value * (-3808689974395783757 & MASK64)) & MASK64
    return value >> 32


def mix(value):
    """c.ʾˎ.ʾʻ.ⁱˋ(J)J：三个 short 符号扩展到 long 后拼接。"""
    value &= MASK64
    v2 = s16(value & MASK16)
    v4 = s16((value >> 16) & MASK16)
    v5 = s16(v2 + v4)
    v5 = rol_short(v5, 9)
    v5 = s16(v5 + v2)
    v4 = s16(v4 ^ v2)
    v0 = rol_short(v2, 13)
    v0 = s16(v0 ^ v4)
    v0 = s16(v0 ^ (v4 << 5))
    v4 = rol_short(v4, 10)
    return (((v5 << 32) | (v4 << 16) | v0) & MASK64)


def load_table(path):
    dex = DEX(open(path, "rb").read())
    for cls in dex.get_classes():
        if cls.get_name() != TABLE_CLASS:
            continue
        for method in cls.get_methods():
            if method.get_name() != "<clinit>":
                continue
            table = []
            for instruction in method.get_instructions():
                if instruction.get_name() == "const-string":
                    table.append(instruction.get_string())
            if table:
                print("table chunks:", len(table),
                      [len(t) for t in table], file=sys.stderr)
                return table
    raise SystemExit("table not found")


def decode(table, key, debug=False):
    key &= MASK64
    value = hash64(key & MASK32)
    value = mix(value)
    v3 = (value >> 32) & MASK16
    value = mix(value)
    v7 = (value >> 16) & 0xFFFF0000
    index = ((key >> 32) ^ v3 ^ v7) & MASK32
    cur = mix(value) ^ ((ord(table[index // 8191][index % 8191]) & MASK16) << 32)
    length = (cur >> 32) & MASK16
    if debug:
        print("  index=%d length=%d table_len=%d mix2=%016x char=%04x cur=%016x"
              % (index, length, sum(len(t) for t in table), value,
                 ord(table[index // 8191][index % 8191]), cur), file=sys.stderr)
    chars = []
    for offset in range(length):
        position = index + offset + 1
        cur = mix(cur) ^ ((ord(table[position // 8191][position % 8191]) & MASK16) << 32)
        chars.append(chr((cur >> 32) & MASK16))
    return "".join(chars)


def sm64(value):
    value &= MASK64
    return value - (1 << 64) if value & (1 << 63) else value


def main():
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    args = sys.argv[1:]
    debug = "--debug" in args
    args = [item for item in args if item != "--debug"]
    if len(args) < 2:
        print("用法: python -X utf8 scripts/decode_c30_strings.py "
              "<core.dex> <long> [long ...] [--debug]", file=sys.stderr)
        return 2
    table = load_table(args[0])
    for raw in args[1:]:
        try:
            print("%-20s %s" % (raw, decode(table, sm64(int(raw)), debug=debug)))
        except Exception as error:
            print("%-20s FAILED %r" % (raw, error))
    return 0


if __name__ == "__main__":
    main()
