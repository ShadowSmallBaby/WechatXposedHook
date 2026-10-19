#!/usr/bin/env python3
"""离线解析微X功能 dex：还原字符串池 + 解出全部 const-wide 种子对应的字符串。

微X 的功能代码运行时才解密进内存，磁盘上的 30 个文件是加密的。本脚本吃
「运行时 dump 出来的明文 dex」（data/refs/device_dump/*.dex），做两件事：

1. 按 `<clinit>` 字节码还原解码器持有的 `String[]` 池（池顺序是打乱的，
   直接按 string_ids 读会得到乱序文本）；
2. 扫描所有方法的 `const-wide` 种子，用 scripts/decode_microx_strings.py 里
   复刻的算法解出明文，并按「设置键 / 高级功能键」归类。

用法:
    python scripts/dump_microx_features.py                  # 默认四个功能 dex
    python scripts/dump_microx_features.py --dex data/refs/device_dump/DonationDex.dex \
        --pool-class 'Lᵢᵎ/ʿٴ;' --out build/donation_strings.txt

只依赖标准库。
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path

M64 = (1 << 64) - 1
M32 = (1 << 32) - 1

# 下面这组位运算逐条对应 docs/reverse-engineering.md §1.2 的 Java 实现。
# 关键点：Java 里 short/long 的符号扩展必须保留，Python 需要显式做 i16/i64/u64，
# 否则高位不同，后续 mixB 会连锁算错（表现为解出空串）。


def _i32(value: int) -> int:
    value &= M32
    return value - 0x100000000 if value & 0x80000000 else value


def _i16(value: int) -> int:
    value &= 0xFFFF
    return value - 0x10000 if value & 0x8000 else value


def _i64(value: int) -> int:
    value &= M64
    return value - 0x10000000000000000 if value & 0x8000000000000000 else value


def _u64(value: int) -> int:
    return value & M64


def _rot_short(value: int, bits: int) -> int:
    shifted = (_i32(value) << (bits & 31)) & M32
    shifted |= (value & M32) >> ((32 - bits) & 31)
    return _i16(shifted & M32)


def _mix_a(value: int) -> int:
    value = _u64(value)
    value = _u64(value ^ (value >> 33))
    value = (value * 0x62A9D9ED799705F5) & M64
    value = _u64(value ^ (value >> 28))
    value = (value * 0xCB24D0A5C88C35B3) & M64
    return (value >> 32) & M64


def _mix_b(value: int) -> int:
    value = _u64(value)
    low = _i16(_i32(value & 0xFFFF))
    high = _i16(_i32((value >> 16) & 0xFFFF))
    total = _i16(low + high)
    total = _rot_short(total, 9)
    total = _i16(total + low)
    high = _i16(high ^ low)
    word = _rot_short(low, 13)
    word = _i16(word ^ high)
    word = _i16(word ^ _i32(high << 5))
    high = _rot_short(high, 10)
    upper = _u64(_i64(total) << 16)
    result = _u64((high | upper) << 16)
    return _u64(result | _u64(word))


def decode_seed(seed: int, pool: list[int]) -> str:
    """微X 的种子解码（docs/reverse-engineering.md §1.2 的 Python 版）。

    池是扁平字符序列时，索引用 8191 分段做边界钳制，越界按 0 处理。
    """
    size = len(pool)

    def char_at(index: int) -> int:
        index = (index // 8191) * 8191 + (index % 8191)
        return pool[index] if 0 <= index < size else 0

    value = _mix_a(seed & 0xFFFFFFFF)
    value = _mix_b(value)
    part = _u64(value >> 32) & 0xFFFF
    value = _mix_b(value)
    side = _u64(value >> 16) & 0xFFFF0000
    index = _i32(_u64(seed >> 32) ^ part ^ side)
    value = _mix_b(value)
    value = _u64(value ^ (_u64(char_at(index)) << 32))
    length = _i32(_u64(value >> 32) & 0xFFFF)
    if length <= 0 or length > 0x8000:
        return ""
    chars = []
    for offset in range(length):
        value = _mix_b(value)
        value = _u64(value ^ (_u64(char_at(_i32(index + offset + 1))) << 32))
        chars.append(_i16(_i32(_u64(value >> 32) & 0xFFFF)) & 0xFFFF)
    return "".join(chr(code) for code in chars)

# 每个 dex 里负责字符串解码的类（见 docs/reverse-engineering.md §1.2）
POOL_CLASSES = {
    "BaseDex": "Lʾˈ/ʿᵔ;",
    "CoreDex": "Lc/ʻⁱ/ـˋ;",
    "DonationDex": "Lᵢᵎ/ʿٴ;",
    "ThemesDex": "Lˈ/ﾞˏ;",
    "main": "Lx/ˋˊ/ˈﹶ;",
}

# 关于 → 自助获取高级功能 里的四项，key 直接来自 DonationDex 的注册状态输出
PREMIUM_KEYS = {
    "multichat_autoforward": "多群自动转发",
    "moments_auto_forward": "朋友圈自动转发",
    "secret_friend": "密友",
    "auto_accept_chatroom_invite": "自动接受群聊邀请",
}

KEY_RE = __import__("re").compile(r"^[a-z][a-z0-9_]{2,60}$")


class Dex:
    def __init__(self, path: Path):
        self.data = path.read_bytes()
        if self.data[:4] != b"dex\n":
            raise ValueError(f"{path} 不是 dex（magic={self.data[:8]!r}）")
        self.string_ids = self.u32(60)
        self.type_ids = self.u32(68)
        self.method_ids = self.u32(92)
        self.class_defs = self.u32(100)

    def u16(self, offset: int) -> int:
        return struct.unpack_from("<H", self.data, offset)[0]

    def u32(self, offset: int) -> int:
        return struct.unpack_from("<I", self.data, offset)[0]

    def uleb(self, offset: int):
        result = shift = 0
        while True:
            byte = self.data[offset]
            offset += 1
            result |= (byte & 0x7F) << shift
            if not byte & 0x80:
                return result, offset
            shift += 7

    def units(self, string_index: int) -> list[int]:
        offset = self.u32(self.string_ids + string_index * 4)
        length, cursor = self.uleb(offset)
        end = cursor
        while self.data[end] != 0:
            end += 1
        blob = self.data[cursor:end]
        out, index = [], 0
        while index < len(blob) and len(out) < length:
            byte = blob[index]
            if byte < 0x80:
                out.append(byte)
                index += 1
            elif byte & 0xE0 == 0xC0:
                out.append(((byte & 0x1F) << 6) | (blob[index + 1] & 0x3F))
                index += 2
            elif byte & 0xF0 == 0xE0:
                out.append(
                    ((byte & 0x0F) << 12)
                    | ((blob[index + 1] & 0x3F) << 6)
                    | (blob[index + 2] & 0x3F)
                )
                index += 3
            else:
                out.append(byte)
                index += 1
        return out

    def type_desc(self, type_index: int) -> str:
        return "".join(chr(c) for c in self.units(self.u32(self.type_ids + type_index * 4)))

    def method_name(self, method_index: int) -> str:
        return "".join(chr(c) for c in self.units(self.u32(self.method_ids + method_index * 8 + 4)))

    def class_count(self) -> int:
        return self.u32(96)

    def class_data(self, class_index: int):
        offset = self.class_defs + class_index * 32
        cursor = self.u32(offset + 24)
        if cursor == 0:
            return None
        static_fields, cursor = self.uleb(cursor)
        instance_fields, cursor = self.uleb(cursor)
        direct_methods, cursor = self.uleb(cursor)
        virtual_methods, cursor = self.uleb(cursor)

        def skip_fields(cursor, count):
            for _ in range(count):
                _, cursor = self.uleb(cursor)
                _, cursor = self.uleb(cursor)
            return cursor

        def read_methods(cursor, count):
            methods, index = [], 0
            for _ in range(count):
                delta, cursor = self.uleb(cursor)
                index += delta
                _, cursor = self.uleb(cursor)
                code, cursor = self.uleb(cursor)
                methods.append((index, code))
            return methods, cursor

        cursor = skip_fields(cursor, static_fields)
        cursor = skip_fields(cursor, instance_fields)
        direct, cursor = read_methods(cursor, direct_methods)
        virtual, cursor = read_methods(cursor, virtual_methods)
        return direct, virtual

    def find_class(self, descriptor: str):
        for index in range(self.class_count()):
            if self.type_desc(self.u32(self.class_defs + index * 32)) == descriptor:
                return index
        return None

    def pool_of(self, descriptor: str) -> list[int] | None:
        class_index = self.find_class(descriptor)
        if class_index is None:
            return None
        class_data = self.class_data(class_index)
        if not class_data:
            return None
        clinit = None
        for method_index, code in list(class_data[0]) + list(class_data[1]):
            if self.method_name(method_index) == "<clinit>":
                clinit = code
        if not clinit:
            return None

        insns_size = self.u32(clinit + 12)
        units = [self.u16(clinit + 16 + 2 * i) for i in range(insns_size)]
        index = 0
        current = 0
        last_string = None
        array = {}
        while index < len(units):
            opcode = units[index] & 0xFF
            aa = (units[index] >> 8) & 0xFF
            if opcode == 0x13:  # const/16 vAA, #+BBBB
                value = units[index + 1]
                if value & 0x8000:
                    value -= 0x10000
                if aa == 1:
                    current = value
                index += 2
            elif opcode == 0x12:  # const/4 vA, #+B
                value = (units[index] >> 12) & 0xF
                if value & 0x8:
                    value -= 0x10
                if ((units[index] >> 8) & 0xF) == 1:
                    current = value
                index += 1
            elif opcode == 0x1A:  # const-string vAA, string@BBBB
                if aa == 2:
                    last_string = units[index + 1]
                index += 2
            elif opcode == 0x4D:  # aput-object vAA, vBB, vCC
                bb = units[index + 1] & 0xFF
                cc = (units[index + 1] >> 8) & 0xFF
                if aa == 2 and bb == 0 and cc == 1:
                    array[current] = last_string
                index += 2
            else:
                index += 1

        pool: list[int] = []
        for key in range(len(array)):
            string_index = array.get(key)
            if string_index is not None:
                pool.extend(self.units(string_index))
        return pool

    def seeds(self) -> list[int]:
        """扫描所有方法体里的 const-wide（opcode 0x18，format 51l）字面量。

        注意不是 0x17：0x17 是 const-wide/32（3 units），微X 的种子是 64 位，
        用 0x18（5 units）。之前按 0x17 扫会全部落空。
        """
        found: set[int] = set()
        for class_index in range(self.class_count()):
            class_data = self.class_data(class_index)
            if not class_data:
                continue
            for _, code in list(class_data[0]) + list(class_data[1]):
                if not code:
                    continue
                size = self.u32(code + 12)
                start = code + 16
                i = 0
                while i < size:
                    unit = self.u16(start + 2 * i)
                    if unit & 0xFF == 0x18 and i + 4 < size:
                        low = self.u16(start + 2 * (i + 1))
                        high = self.u16(start + 2 * (i + 2))
                        high2 = self.u16(start + 2 * (i + 3))
                        high3 = self.u16(start + 2 * (i + 4))
                        seed = low | (high << 16) | (high2 << 32) | (high3 << 48)
                        found.add(seed)
                        i += 5
                    else:
                        i += 1
        return sorted(found)


def printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    good = sum(1 for ch in text if ch.isprintable() or ch in "\n\t")
    return good / len(text)


def collect(dex_path: Path, pool_class: str, threshold: float):
    dex = Dex(dex_path)
    pool = dex.pool_of(pool_class)
    if pool is None:
        raise SystemExit(f"{dex_path.name}: 找不到解码类 {pool_class} 的字符串池")
    seed_values = dex.seeds()
    strings = {}
    for seed in seed_values:
        try:
            text = decode_seed(seed, pool)
        except Exception:
            continue
        if not text or printable_ratio(text) < threshold:
            continue
        strings[seed] = text
    return pool, seed_values, strings


def key_like(strings) -> list[str]:
    return sorted({s for s in strings.values() if KEY_RE.match(s)})


def main(argv=None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(description="离线解析微X功能 dex 的字符串池与全部种子字符串")
    parser.add_argument(
        "--dump-dir",
        type=Path,
        default=Path("data/refs/device_dump"),
        help="运行时 dump 出来的明文 dex 目录",
    )
    parser.add_argument("--dex", type=Path, help="只解析指定的 dex")
    parser.add_argument("--pool-class", help="解码类描述符（--dex 时使用）")
    parser.add_argument("--threshold", type=float, default=0.9, help="明文可打印比例阈值")
    parser.add_argument("--out", type=Path, help="报告输出路径")
    parser.add_argument("--json", type=Path, help="把每个 dex 的字符串写成 JSON")
    parser.add_argument("--grep", help="只显示包含该子串的字符串")
    args = parser.parse_args(argv)

    targets: list[tuple[str, Path, str]] = []
    if args.dex:
        descriptor = args.pool_class
        if not descriptor:
            descriptor = POOL_CLASSES.get(args.dex.stem)
        if not descriptor:
            raise SystemExit("--dex 需要配套 --pool-class")
        targets.append((args.dex.stem, args.dex, descriptor))
    else:
        for name, descriptor in POOL_CLASSES.items():
            path = args.dump_dir / f"{name}.dex"
            if path.is_file():
                targets.append((name, path, descriptor))

    if not targets:
        raise SystemExit(f"没有找到可解析的 dex（目录 {args.dump_dir}）")

    lines: list[str] = []
    bundle: dict[str, list[str]] = {}
    for name, path, descriptor in targets:
        try:
            pool, seed_values, strings = collect(path, descriptor, args.threshold)
        except (ValueError, SystemExit) as error:
            lines.append(f"=== {name}: 跳过（{error}）===")
            continue
        values = sorted(set(strings.values()))
        bundle[name] = values
        lines.append(f"=== {name}：池 {len(pool)} 字符，种子 {len(seed_values)} 个，"
                     f"解出字符串 {len(values)} 条 ===")

        premium = [f"{key} -> {label}" for key, label in PREMIUM_KEYS.items() if key in strings.values()]
        if premium:
            lines.append("  高级功能键：")
            for item in premium:
                lines.append(f"    {item}")

        keys = key_like(strings)
        enables = [key for key in keys if key.endswith("_enable")]
        lines.append(f"  候选设置键 {len(keys)} 个，其中 *_enable {len(enables)} 个")

        shown = values
        if args.grep:
            shown = [value for value in values if args.grep.lower() in value.lower()]
        lines.append("  字符串：")
        for value in shown:
            lines.append(f"    {value!r}")
        lines.append("")

    output = "\n".join(lines)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(output, encoding="utf-8")
        print(f"写入 {args.out}")
    else:
        print(output)

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(bundle, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"写入 {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
