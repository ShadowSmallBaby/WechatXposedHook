#!/usr/bin/env python3
"""dex 结构与 dexdump 文本检查工具。

用于对比 APK 里的壳 / 功能 dex，定位类、方法、字符串和调用点。不依赖第三方库：

- `stats` / `diff` 自带最小 dex 解析器，直接读二进制；
- `dump` 调用 Android SDK 的 `dexdump -d`；
- `class` / `summary` / `locate` 读取 dexdump 文本，不需要再解析二进制。

用法:
    python scripts/dex_inspect.py stats path/to/classes.dex
    python scripts/dex_inspect.py stats path/to/app.apk          # 自动展开 classes*.dex
    python scripts/dex_inspect.py stats a.dex b.dex
    python scripts/dex_inspect.py diff a.apk b.apk
    python scripts/dex_inspect.py dump path/to/classes.dex -o build/classes.smali.txt
    python scripts/dex_inspect.py class build/classes.smali.txt 'Lx/foo/bar;' --inner
    python scripts/dex_inspect.py summary build/classes.smali.txt wx/repair/tool
    python scripts/dex_inspect.py locate build/classes.smali.txt 12345 23456

类描述符可能含非 ASCII 字符，`class` 子命令在 Windows 终端下建议用
`python -X utf8` 运行，或先设置 `PYTHONIOENCODING=utf-8`。
"""

from __future__ import annotations

import argparse
import bisect
import io
import re
import shutil
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

M32 = (1 << 32) - 1

# dexdump 文本里常见的锚点
RE_CLASS = re.compile(r"^Class #")
RE_DESC = re.compile(r"Class descriptor  : '(L[^']+)'")
RE_METHOD_NAME = re.compile(r"^\s+name\s+: '([^']+)'")
RE_CONST_STRING = re.compile(r'const-string v\d+, "(.*)"')
RE_INVOKE_TARGET = re.compile(r"invoke-\S+\s+\{[^}]*\},\s+(\S+)")

DEFAULT_KEYS = (
    "XposedInit", "HandleLoadPackage", "HookWrapper", "WxCoreLoader", "Wrapper",
    "Init", "Native", "Jni", "Bridge", "Loader", "Lic", "Verifier", "Settings",
    "Params", "Update", "Donate",
)


# ---------------------------------------------------------------------------
# 二进制 dex
# ---------------------------------------------------------------------------

class Dex:
    """只读 dex 头部 / 类定义，够做结构统计与类清单 diff。"""

    def __init__(self, data: bytes, label: str = ""):
        self.label = label
        self.b = data
        if self.b[:4] != b"dex\n":
            raise ValueError(f"{label or '<bytes>'} 不是 dex 文件")
        self.string_ids = self.u32(0x3C)
        self.type_ids = self.u32(0x44)
        self.method_ids = self.u32(0x5C)
        self.class_defs = self.u32(0x64)
        self.nstr = self.u32(0x38)
        self.ntype = self.u32(0x40)
        self.nmethod = self.u32(0x58)
        self.nclass = self.u32(0x60)

    def u32(self, off: int) -> int:
        return struct.unpack_from("<I", self.b, off)[0]

    def uleb(self, off: int) -> tuple[int, int]:
        value = shift = 0
        while True:
            byte = self.b[off]
            off += 1
            value |= (byte & 0x7F) << shift
            if not byte & 0x80:
                return value, off
            shift += 7

    def units(self, idx: int) -> str:
        off = self.u32(self.string_ids + idx * 4)
        length, data_off = self.uleb(off)
        end = data_off
        while self.b[end] != 0:
            end += 1
        data = self.b[data_off:end]
        out: list[str] = []
        i = 0
        while i < len(data) and len(out) < length:
            c = data[i]
            if c < 0x80:
                out.append(chr(c))
                i += 1
            elif c & 0xE0 == 0xC0:
                out.append(chr(((c & 0x1F) << 6) | (data[i + 1] & 0x3F)))
                i += 2
            elif c & 0xF0 == 0xE0:
                out.append(chr(((c & 0x0F) << 12) | ((data[i + 1] & 0x3F) << 6) | (data[i + 2] & 0x3F)))
                i += 3
            else:
                out.append(chr(c))
                i += 1
        return "".join(out)

    def tdesc(self, type_idx: int) -> str:
        return self.units(self.u32(self.type_ids + type_idx * 4))

    def mname(self, method_idx: int) -> str:
        return self.units(self.u32(self.method_ids + method_idx * 8 + 4))

    def class_data(self, class_idx: int) -> tuple[int, int, int, int]:
        off = self.u32(self.class_defs + class_idx * 32 + 24)
        if off == 0:
            return 0, 0, 0, 0
        static_fields, off = self.uleb(off)
        instance_fields, off = self.uleb(off)
        direct_methods, off = self.uleb(off)
        virtual_methods, off = self.uleb(off)
        return static_fields, instance_fields, direct_methods, virtual_methods

    def methods_of(self, class_idx: int) -> tuple[list[str], list[str]]:
        off = self.u32(self.class_defs + class_idx * 32 + 24)
        if off == 0:
            return [], []
        sf, off = self.uleb(off)
        inf, off = self.uleb(off)
        dmn, off = self.uleb(off)
        vmn, off = self.uleb(off)

        def skip_fields(pos: int, count: int) -> int:
            for _ in range(count):
                _, pos = self.uleb(pos)
                _, pos = self.uleb(pos)
            return pos

        def read_methods(pos: int, count: int) -> tuple[list[int], int]:
            indexes: list[int] = []
            current = 0
            for _ in range(count):
                delta, pos = self.uleb(pos)
                current += delta
                _, pos = self.uleb(pos)  # access_flags
                _, pos = self.uleb(pos)  # code_off
                indexes.append(current)
            return indexes, pos

        off = skip_fields(off, sf)
        off = skip_fields(off, inf)
        direct, off = read_methods(off, dmn)
        virtual, off = read_methods(off, vmn)
        return [self.mname(i) for i in direct], [self.mname(i) for i in virtual]

    def superclass(self, class_idx: int) -> str:
        return self.tdesc(self.u32(self.class_defs + class_idx * 32 + 8))

    def classes(self) -> list[str]:
        return [self.tdesc(self.u32(self.class_defs + i * 32)).strip("L;")
                for i in range(self.nclass)]


def iter_dex_sources(path: Path):
    """把 dex 文件或 APK 展开为 (label, bytes)，APK 按 classes*.dex 顺序。"""
    data = path.read_bytes()
    # 不用 zipfile.is_zipfile：二次打包的 APK 可能有重叠条目或 EOCD 之外的附加数据，
    # 导致它误判；直接看本地文件头更稳。
    if data[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for info in archive.infolist():
                name = info.filename
                if name.startswith("classes") and name.endswith(".dex"):
                    yield f"{path}!{name}", archive.read(name)
    else:
        yield str(path), data


# ---------------------------------------------------------------------------
# dexdump 文本
# ---------------------------------------------------------------------------

class ClassSpan:
    __slots__ = ("start", "end", "desc")

    def __init__(self, start: int, end: int, desc: str):
        self.start = start
        self.end = end
        self.desc = desc


def read_lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8", errors="replace").split("\n")


def parse_spans(lines: list[str]) -> list[ClassSpan]:
    starts = [i for i, line in enumerate(lines) if RE_CLASS.match(line)]
    spans: list[ClassSpan] = []
    for idx, start in enumerate(starts):
        end = starts[idx + 1] if idx + 1 < len(starts) else len(lines)
        desc = ""
        for line in lines[start:min(end, start + 6)]:
            match = RE_DESC.search(line)
            if match:
                desc = match.group(1)
                break
        if desc:
            spans.append(ClassSpan(start, end, desc))
    return spans


def summarize_span(lines: list[str], span: ClassSpan, max_strings: int, max_calls: int) -> None:
    methods: list[str] = []
    strings: dict[str, int] = {}
    calls: dict[str, int] = {}
    for line in lines[span.start:span.end]:
        match = RE_METHOD_NAME.match(line)
        if match:
            methods.append(match.group(1))
            continue
        match = RE_CONST_STRING.search(line)
        if match:
            value = match.group(1)
            if len(value) <= 120:
                strings[value] = strings.get(value, 0) + 1
            continue
        match = RE_INVOKE_TARGET.search(line)
        if match:
            target = match.group(1)
            calls[target] = calls.get(target, 0) + 1

    def render(items: dict[str, int], limit: int) -> str:
        shown = list(items.items())[:limit]
        text = " | ".join(f"{value} ×{count}" if count > 1 else value for value, count in shown)
        if len(items) > limit:
            text += f" ... (+{len(items) - limit})"
        return text

    print(f"### {span.desc}")
    print("  methods:", ", ".join(methods))
    if strings:
        print("  strings:", render(strings, max_strings))
    if calls:
        print("  calls:", render(calls, max_calls))
    print()


# ---------------------------------------------------------------------------
# 子命令
# ---------------------------------------------------------------------------

def cmd_stats(args: argparse.Namespace) -> int:
    keys = tuple(args.keys.split(",")) if args.keys else DEFAULT_KEYS
    for name in args.dex:
        for label, data in iter_dex_sources(Path(name)):
            dex = Dex(data, label)
            classes = dex.classes()
            defined = 0
            for idx in range(dex.nclass):
                _, _, direct, virtual = dex.class_data(idx)
                defined += direct + virtual
            non_ascii = sum(1 for desc in classes if not all(ord(c) < 128 for c in desc))
            packages: dict[str, int] = {}
            for desc in classes:
                parts = desc.split("/")
                key = "/".join(parts[:2]) if len(parts) > 1 else parts[0]
                packages[key] = packages.get(key, 0) + 1

            print("=" * 70)
            print(label)
            print(f"  class_defs={dex.nclass}  methods_ref={dex.nmethod}  methods_defined={defined}")
            print(f"  type_ids={dex.ntype}  strings={dex.nstr}")
            print(f"  non-ASCII 类名: {non_ascii} ({non_ascii * 100 // max(len(classes), 1)}%)")
            print("  top packages:")
            for key, count in sorted(packages.items(), key=lambda kv: kv[1], reverse=True)[:args.top]:
                print(f"    {count:5d}  {key}")
            print("  key class hits:")
            for desc in classes:
                if any(k.lower() in desc.lower() for k in keys):
                    print(f"    {desc}")
    return 0


def _class_set(path: str) -> set[str]:
    result: set[str] = set()
    for _, data in iter_dex_sources(Path(path)):
        result |= set(Dex(data).classes())
    return result


def cmd_diff(args: argparse.Namespace) -> int:
    left_set = _class_set(args.left)
    right_set = _class_set(args.right)
    print(f"A={len(left_set)}  B={len(right_set)}")
    print("--- only in A ---")
    for desc in sorted(left_set - right_set):
        print(" ", desc)
    print("--- only in B ---")
    for desc in sorted(right_set - left_set):
        print(" ", desc)
    return 0


def find_dexdump(explicit: str | None) -> str:
    if explicit:
        return explicit
    roots: list[Path] = []
    for env in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        import os
        value = os.environ.get(env)
        if value:
            roots.append(Path(value))
    local_properties = Path(__file__).resolve().parent.parent / "local.properties"
    if local_properties.is_file():
        for line in local_properties.read_text(encoding="utf-8", errors="ignore").splitlines():
            if line.startswith("sdk.dir="):
                roots.append(Path(line.split("=", 1)[1].replace("\\:", ":").replace("\\\\", "\\")))
    found = shutil.which("dexdump")
    if found:
        return found
    for root in roots:
        build_tools = root / "build-tools"
        if not build_tools.is_dir():
            continue
        candidates = sorted(build_tools.iterdir(),
                            key=lambda p: tuple(int(x) for x in re.findall(r"\d+", p.name)) or (0,),
                            reverse=True)
        for candidate in candidates:
            for name in ("dexdump.exe", "dexdump"):
                binary = candidate / name
                if binary.is_file():
                    return str(binary)
    raise SystemExit("找不到 dexdump：用 --dexdump 指定，或设置 ANDROID_HOME / local.properties")


def cmd_dump(args: argparse.Namespace) -> int:
    dexdump = find_dexdump(args.dexdump)
    output = Path(args.out) if args.out else None
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("w", encoding="utf-8", errors="replace") as handle:
            subprocess.run([dexdump, "-d", args.dex], check=True, stdout=handle)
        print(f"{dexdump} -d {args.dex} -> {output}")
    else:
        subprocess.run([dexdump, "-d", args.dex], check=True)
    return 0


def cmd_class(args: argparse.Namespace) -> int:
    lines = read_lines(Path(args.dump))
    wanted = args.descriptor
    matched = False
    for span in parse_spans(lines):
        if span.desc == wanted or (args.inner and span.desc.startswith(wanted[:-1] + "$")):
            matched = True
            print("\n".join(lines[span.start:span.end]))
    if not matched:
        print(f"未找到 {wanted}", file=sys.stderr)
        return 1
    return 0


def cmd_summary(args: argparse.Namespace) -> int:
    lines = read_lines(Path(args.dump))
    prefix = args.prefix[1:] if args.prefix.startswith("L") else args.prefix
    found = False
    for span in parse_spans(lines):
        desc = span.desc[1:] if span.desc.startswith("L") else span.desc
        if prefix and not desc.startswith(prefix):
            continue
        found = True
        summarize_span(lines, span, args.max_strings, args.max_calls)
    if not found:
        print(f"没有匹配 {args.prefix!r} 的类", file=sys.stderr)
        return 1
    return 0


def cmd_locate(args: argparse.Namespace) -> int:
    lines = read_lines(Path(args.dump))
    spans = parse_spans(lines)
    starts = [span.start for span in spans]
    for target in args.line:
        idx = bisect.bisect_right(starts, target) - 1
        if idx < 0:
            print(f"line {target}: 不在任何类中")
            continue
        span = spans[idx]
        method = "?"
        for pos in range(span.start, min(target + 1, span.end)):
            match = RE_METHOD_NAME.match(lines[pos])
            if match:
                method = match.group(1)
        print(f"line {target}: {span.desc}  ::  {method}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="dex 结构与 dexdump 文本检查工具")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("stats", help="统计类/方法/字符串规模与包分布")
    p.add_argument("dex", nargs="+")
    p.add_argument("--top", type=int, default=25, help="显示前 N 个包")
    p.add_argument("--keys", help="逗号分隔的关键类关键词")
    p.set_defaults(func=cmd_stats)

    p = sub.add_parser("diff", help="对比两个 dex 的类清单")
    p.add_argument("left")
    p.add_argument("right")
    p.set_defaults(func=cmd_diff)

    p = sub.add_parser("dump", help="调用 dexdump -d 生成文本")
    p.add_argument("dex")
    p.add_argument("-o", "--out", help="输出文件；缺省写到 stdout")
    p.add_argument("--dexdump", help="dexdump 可执行文件路径")
    p.set_defaults(func=cmd_dump)

    p = sub.add_parser("class", help="按类描述符提取 dexdump 段落")
    p.add_argument("dump")
    p.add_argument("descriptor", help="例如 'Lx/foo/bar;'")
    p.add_argument("--inner", action="store_true", help="同时匹配内部类")
    p.set_defaults(func=cmd_class)

    p = sub.add_parser("summary", help="按包前缀汇总方法/字符串/调用")
    p.add_argument("dump")
    p.add_argument("prefix", nargs="?", default="")
    p.add_argument("--max-strings", type=int, default=40)
    p.add_argument("--max-calls", type=int, default=25)
    p.set_defaults(func=cmd_summary)

    p = sub.add_parser("locate", help="按 dump 行号回溯所属类与方法")
    p.add_argument("dump")
    p.add_argument("line", type=int, nargs="+")
    p.set_defaults(func=cmd_locate)

    return parser


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
