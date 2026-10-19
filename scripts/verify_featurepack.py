#!/usr/bin/env python3
"""校验微X功能包（wx6_2.44）的完整性。

功能包是微X运行时投放到 /data/data/com.tencent.mm/files/wx6_2.44 的一批文件，
本模块的 FeaturePackRestorer 按「文件名 + 字节数」判断缺失并补齐。本脚本做同样
的校验，并额外比对 tar / zip / APK assets 三方是否同源。

用法:
    python scripts/verify_featurepack.py                     # 校验仓库内置 zip
    python scripts/verify_featurepack.py --tar data/refs/wx6_2.44.tar
    python scripts/verify_featurepack.py --apk data/refs/微X模块_2.44.apk
    python scripts/verify_featurepack.py --dir /path/to/wx6_2.44   # 校验设备上实际落地的目录

只依赖标准库。
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
import tarfile
import zipfile
from pathlib import Path

# 从 FeaturePackRestorer.java 读出来的 30 个文件名与期望字节数
EXPECTED_NAMES = [
    "14e777717682cce8a53cfcb34a22d65",
    "14e777717682cce8a53cfcb34a22d65_c",
    "14e777717682cce8a53cfcb34a22d65_s",
    "24ce1c66be23f9c731fb2db3a76954",
    "36a76b97b96b5d46742bb4bcd2ff24d",
    "36a76b97b96b5d46742bb4bcd2ff24d_c",
    "36a76b97b96b5d46742bb4bcd2ff24d_s",
    "44c29edb103a2872f519adc9afdaaa",
    "534a9729a0c461cbd7a4379978fb742",
    "55bcfe849748f60697e2b1e191321b3",
    "5dbc98dcc983a7728bd82d1a47546e",
    "62a4e566b714ea1c4349923c9ea6c35",
    "69691c7bdcc3ce6d5d8a1361f22d4ac",
    "6d6586c9c5458ecfc98981b52ee662de",
    "739440c5d87b2b8095b99f9d2a1bbf9",
    "7e72d95130d766517ea69c215f38ddd",
    "802766a4a4bd401c145a57463274d4dd",
    "802766a4a4bd401c145a57463274d4dd_c",
    "802766a4a4bd401c145a57463274d4dd_s",
    "89d9d67db0a14fc9b040cf25a28ef71",
    "a89eaf67dc796cb3af54d94fac0198b",
    "a89eaf67dc796cb3af54d94fac0198b_c",
    "a89eaf67dc796cb3af54d94fac0198b_s",
    "d61f837cad1d412f80b84d143e1257",
    "d61f837cad1d412f80b84d143e1257_c",
    "d61f837cad1d412f80b84d143e1257_s",
    "dc7be70f1898d3a58965a919740f97",
]

EXPECTED_SIZES = [
    1035962, 599, 256, 43048, 528976, 599, 256, 4568, 1159, 43240,
    259018, 48008, 41352, 43336, 98264, 42808, 200890, 599, 256, 42440,
    121466, 599, 256, 347578, 599, 256, 461560,
]

NAMES_RE = re.compile(r'"(?P<name>[0-9a-f]{20,40}(?:_[a-z]+)*)"')
SIZES_RE = re.compile(r"(\d+)L")

# 这几个是原生库/加密主体，做个标记方便看
ELF_MAGIC = b"\x7fELF"
DEX_MAGIC = b"dex\n"


def sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def kind_of(payload: bytes) -> str:
    if payload.startswith(ELF_MAGIC):
        return "ELF(native)"
    if payload.startswith(DEX_MAGIC):
        return "DEX"
    if len(payload) <= 1024:
        return "meta"
    return "blob"


def load_from_directory(root: Path) -> dict[str, bytes]:
    payloads = {}
    for name in EXPECTED_NAMES:
        path = root / name
        if path.is_file():
            payloads[name] = path.read_bytes()
    return payloads


def load_from_zip(path: Path, prefix: str = "") -> dict[str, bytes]:
    payloads = {}
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            name = info.filename
            if prefix and name.startswith(prefix):
                name = name[len(prefix) :]
            if name in EXPECTED_NAMES:
                payloads[name] = archive.read(info.filename)
    return payloads


def load_from_tar(path: Path) -> dict[str, bytes]:
    payloads = {}
    with tarfile.open(path) as archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            name = Path(member.name).name
            if name in EXPECTED_NAMES:
                handle = archive.extractfile(member)
                if handle is not None:
                    payloads[name] = handle.read()
    return payloads


def load_from_apk_assets(path: Path) -> dict[str, bytes]:
    payloads = {}
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            if not info.filename.startswith("assets/"):
                continue
            name = info.filename[len("assets/") :]
            if name in EXPECTED_NAMES:
                payloads[name] = archive.read(info.filename)
    return payloads


def verify_source(label: str, payloads: dict[str, bytes]) -> list[str]:
    lines = [f"=== {label} ==="]
    missing = []
    size_mismatch = []
    for name, expected_size in zip(EXPECTED_NAMES, EXPECTED_SIZES):
        payload = payloads.get(name)
        if payload is None:
            missing.append(name)
            continue
        if len(payload) != expected_size:
            size_mismatch.append((name, len(payload), expected_size))
    lines.append(f"  命中 {len(payloads)}/{len(EXPECTED_NAMES)} 个文件")
    if missing:
        lines.append(f"  缺失 {len(missing)} 个: {', '.join(missing)}")
    else:
        lines.append("  无缺失")
    if size_mismatch:
        for name, actual, expected in size_mismatch:
            lines.append(f"  尺寸不符 {name}: 实际 {actual} / 期望 {expected}")
    else:
        lines.append("  尺寸全部符实")
    return lines


def describe_payloads(label: str, payloads: dict[str, bytes], width: int = 72) -> list[str]:
    lines = [f"=== {label} 文件构成 ==="]
    for name, expected_size in zip(EXPECTED_NAMES, EXPECTED_SIZES):
        payload = payloads.get(name)
        if payload is None:
            continue
        digest = sha256(payload)[:16]
        lines.append(
            f"  {name:<{width}} {len(payload):>8} {kind_of(payload):<12} sha256:{digest}"
        )
    return lines


def cross_compare(sources: dict[str, dict[str, bytes]]) -> list[str]:
    lines = ["=== 交叉比对 ==="]
    labels = list(sources)
    for index, left in enumerate(labels):
        for right in labels[index + 1 :]:
            left_payloads, right_payloads = sources[left], sources[right]
            shared = sorted(set(left_payloads) & set(right_payloads))
            same = [name for name in shared if sha256(left_payloads[name]) == sha256(right_payloads[name])]
            diff = [name for name in shared if name not in same]
            lines.append(
                f"  {left} vs {right}: 共有 {len(shared)}，一致 {len(same)}，不一致 {len(diff)}"
            )
            for name in diff:
                lines.append(
                    f"     差异 {name}: {sha256(left_payloads[name])[:12]} != "
                    f"{sha256(right_payloads[name])[:12]}"
                )
            only_left = sorted(set(left_payloads) - set(right_payloads))
            only_right = sorted(set(right_payloads) - set(left_payloads))
            if only_left:
                lines.append(f"     仅 {left} 有: {', '.join(only_left)}")
            if only_right:
                lines.append(f"     仅 {right} 有: {', '.join(only_right)}")
    return lines


def parse_restorer(path: Path) -> list[str]:
    """从 FeaturePackRestorer.java 读出 NAMES / SIZES，跟脚本内表对一下，防止两边漂移。"""
    if not path.is_file():
        return [f"跳过：找不到 {path}"]
    source = path.read_text(encoding="utf-8", errors="replace")
    names_block = source.split("NAMES = {", 1)[-1].split("};", 1)[0]
    sizes_block = source.split("SIZES = {", 1)[-1].split("};", 1)[0]
    names = NAMES_RE.findall(names_block)
    sizes = [int(item) for item in SIZES_RE.findall(sizes_block)]
    lines = [f"=== 与 {path.as_posix()} 对表 ==="]
    if names == EXPECTED_NAMES and sizes == EXPECTED_SIZES:
        lines.append(f"  一致：{len(EXPECTED_NAMES)} 个文件名 + {len(EXPECTED_SIZES)} 个尺寸")
    else:
        lines.append(f"  不一致！脚本内 {len(EXPECTED_NAMES)}/{len(EXPECTED_SIZES)}，源码 {len(names)}/{len(sizes)}")
        for name in set(EXPECTED_NAMES) ^ set(names):
            lines.append(f"    名字差异: {name}")
        if sizes != EXPECTED_SIZES:
            lines.append(f"    尺寸差异: {sizes}")
    return lines


def main(argv=None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description="校验微X功能包完整性")
    parser.add_argument("--zip", type=Path,
                        default=Path("app/build/generated/featurepacks/wx244/wx6_2.44.zip"))
    parser.add_argument("--tar", type=Path, default=Path("data/refs/wx6_2.44.tar"))
    parser.add_argument("--apk", type=Path, default=Path("data/refs/微X模块_2.44.apk"))
    parser.add_argument("--dir", type=Path, help="设备上实际落地的 wx6_2.44 目录")
    parser.add_argument("--verbose", action="store_true", help="打印每个文件的类型与哈希")
    parser.add_argument("--out", type=Path, help="结果写入文件")
    args = parser.parse_args(argv)

    restorer = Path("app/src/main/java/github/shadowbaby/wechatxposed/hook/deploy/FeaturePackRestorer.java")
    lines = parse_restorer(restorer)
    lines.append("")

    sources: dict[str, dict[str, bytes]] = {}
    if args.zip.is_file():
        sources[f"zip {args.zip.name}"] = load_from_zip(args.zip)
    if args.tar.is_file():
        sources[f"tar {args.tar.name}"] = load_from_tar(args.tar)
    if args.apk.is_file():
        sources[f"apk assets {args.apk.name}"] = load_from_apk_assets(args.apk)
    if args.dir:
        if args.dir.is_dir():
            sources[f"dir {args.dir}"] = load_from_directory(args.dir)
        else:
            lines.append(f"目录不存在: {args.dir}")

    if not sources:
        lines.append("没有可用的数据源，检查 --zip / --tar / --apk / --dir 参数")

    for label, payloads in sources.items():
        lines.extend(verify_source(label, payloads))
        lines.append("")
        if args.verbose:
            lines.extend(describe_payloads(label, payloads))
            lines.append("")

    if len(sources) > 1:
        lines.extend(cross_compare(sources))
        lines.append("")

    lines.append("=== 各来源与内置 zip 的差异提示 ===")
    base_label = next((label for label in sources if label.startswith("zip ")), None)
    if base_label:
        base = sources[base_label]
        for label, payloads in sources.items():
            if label == base_label:
                continue
            extra = sorted(set(payloads) - set(base))
            if extra:
                lines.append(f"  {label} 比内置 zip 多出 {len(extra)} 个文件: {', '.join(extra)}")
            missing = sorted(set(base) - set(payloads))
            if missing:
                lines.append(f"  {label} 比内置 zip 少 {len(missing)} 个文件: {', '.join(missing)}")
        lines.append("  说明：多出的文件通常是 APK 内嵌资源或旧版本遗留，不影响运行时投放。")

    output = "\n".join(lines)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(output, encoding="utf-8")
        print(f"写入 {args.out}")
    else:
        print(output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
