#!/usr/bin/env python3
"""从微X模块 APK 抽 assets，并跟运行时功能包做差异比对。

微X APK 的 assets/ 是「安装内置资源」，运行时投放的功能包（wx6_2.44）是
「更新后的完整包」。两者文件名相同但部分文件内容不同（尺寸也不同），本脚本
把这些差异列出来，用来判断某个功能包是新版还是旧版，以及 APK 里有没有独有的
资源（例如官方发布资产）。

用法:
    python scripts/extract_asset_blobs.py --apk data/refs/微X模块_2.44.apk
    python scripts/extract_asset_blobs.py --apk ... --extract build/assets_dump
    python scripts/extract_asset_blobs.py --apk ... --featurepack app/build/generated/featurepacks/wx244/wx6_2.44.zip --json build/assets_diff.json

只依赖标准库。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import zipfile
from pathlib import Path

ELF_MAGIC = b"\x7fELF"
DEX_MAGIC = b"dex\n"

# 功能性文件后缀约定（来自功能包命名规律）
SUFFIX_MEANING = {
    "_c": "配置/索引",
    "_s": "短元数据",
    "_backup_c": "配置备份",
    "_backup_s": "元数据备份",
}


def kind_of(payload: bytes) -> str:
    if payload.startswith(ELF_MAGIC):
        return "ELF"
    if payload.startswith(DEX_MAGIC):
        return "DEX"
    if payload.startswith(b"dex\n035"):
        return "DEX"
    if len(payload) <= 1024:
        return "meta"
    return "blob"


def suffix_meaning(name: str) -> str:
    for suffix in ("_backup_c", "_backup_s", "_c", "_s"):
        if name.endswith(suffix):
            return SUFFIX_MEANING[suffix]
    return "主体"


def read_apk_assets(apk: Path) -> dict[str, bytes]:
    assets: dict[str, bytes] = {}
    with zipfile.ZipFile(apk) as archive:
        for info in archive.infolist():
            if info.filename.startswith("assets/") and not info.is_dir():
                assets[info.filename[len("assets/") :]] = archive.read(info.filename)
    return assets


def read_featurepack(path: Path) -> dict[str, bytes]:
    payloads: dict[str, bytes] = {}
    if path.suffix == ".zip":
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                payloads[Path(info.filename).name] = archive.read(info.filename)
    else:
        import tarfile

        with tarfile.open(path) as archive:
            for member in archive.getmembers():
                if member.isfile():
                    handle = archive.extractfile(member)
                    if handle is not None:
                        payloads[Path(member.name).name] = handle.read()
    return payloads


def flatten_manifest(assets: dict[str, bytes], featurepack: dict[str, bytes]):
    rows = []
    for name in sorted(set(assets) | set(featurepack)):
        asset = assets.get(name)
        pack = featurepack.get(name)
        row = {
            "name": name,
            "meaning": suffix_meaning(name),
            "size_assets": len(asset) if asset is not None else None,
            "size_featurepack": len(pack) if pack is not None else None,
            "sha256_assets": hashlib.sha256(asset).hexdigest()[:16] if asset else None,
            "sha256_featurepack": hashlib.sha256(pack).hexdigest()[:16] if pack else None,
            "kind": kind_of(asset if asset is not None else (pack or b"")),
        }
        if asset is None:
            row["status"] = "仅功能包"
        elif pack is None:
            row["status"] = "仅 APK assets"
        elif asset == pack:
            row["status"] = "一致"
        else:
            row["status"] = f"差异 {len(pack) - len(asset):+d} 字节"
        rows.append(row)
    return rows


def main(argv=None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description="抽取微X APK assets 并与功能包比对")
    parser.add_argument("--apk", type=Path, default=Path("data/refs/微X模块_2.44.apk"))
    parser.add_argument(
        "--featurepack",
        type=Path,
        default=Path("app/build/generated/featurepacks/wx244/wx6_2.44.zip"),
        help="运行时功能包（zip 或 tar）",
    )
    parser.add_argument("--extract", type=Path, help="把 APK assets 解到该目录")
    parser.add_argument("--json", type=Path, help="把比对结果写成 JSON")
    parser.add_argument("--out", type=Path, help="把可读报告写到文件")
    args = parser.parse_args(argv)

    if not args.apk.is_file():
        print(f"APK 不存在: {args.apk}")
        return 1

    assets = read_apk_assets(args.apk)
    featurepack = read_featurepack(args.featurepack) if args.featurepack.is_file() else {}

    lines = [f"APK assets: {len(assets)} 个文件（{args.apk.name}）"]
    if featurepack:
        lines.append(f"功能包: {len(featurepack)} 个文件（{args.featurepack.name}）")
    else:
        lines.append(f"功能包: 未找到 {args.featurepack}，只列 APK assets")
    lines.append("")

    rows = flatten_manifest(assets, featurepack)
    header = f"{'文件':<44}{'含义':<10}{'APK':>9}{'功能包':>9}  {'类型':<6}状态"
    lines.append(header)
    lines.append("-" * len(header))
    for row in rows:
        lines.append(
            f"{row['name']:<44}{row['meaning']:<10}"
            f"{row['size_assets'] if row['size_assets'] is not None else '-':>9}"
            f"{row['size_featurepack'] if row['size_featurepack'] is not None else '-':>9}"
            f"  {row['kind']:<6}{row['status']}"
        )

    lines.append("")
    only_assets = [row["name"] for row in rows if row["status"] == "仅 APK assets"]
    only_pack = [row["name"] for row in rows if row["status"] == "仅功能包"]
    diff = [row for row in rows if row["status"].startswith("差异 ")]
    lines.append(f"仅 APK 有 {len(only_assets)} 个: {', '.join(only_assets) or '无'}")
    lines.append(f"仅功能包有 {len(only_pack)} 个: {', '.join(only_pack) or '无'}")
    lines.append(f"内容不同 {len(diff)} 个: {', '.join(row['name'] for row in diff) or '无'}")
    lines.append("")
    lines.append("提示：名称相同但内容不同 = APK 内置旧资源 vs 运行时新功能包；")
    lines.append("      仅 APK 有的文件不参与运行时投放，通常与官方发布资产有关。")

    if args.extract:
        args.extract.mkdir(parents=True, exist_ok=True)
        for name, payload in assets.items():
            target = args.extract / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
        lines.append("")
        lines.append(f"已解出 {len(assets)} 个 assets 到 {args.extract}")

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(
            json.dumps(
                {
                    "apk": args.apk.as_posix(),
                    "featurepack": args.featurepack.as_posix() if featurepack else None,
                    "rows": rows,
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        lines.append(f"已写入 {args.json}")

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
