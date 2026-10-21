#!/usr/bin/env python3
"""从项目仓 xmetadata/wx7 生成 X 3.0 最小可运行目录。

源文件为 SHA-256(body)[32] + body；运行目录落盘时去掉 32B 前缀。
运行文件名由 runtime_names 的确定性规则推导；扩展包生成两套命名。
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from runtime_names import BRIDGE, CORE, UTILITY, runtime

ROOT = Path(__file__).resolve().parents[1]

ZIP_TIME = (2026, 1, 1, 0, 0, 0)

# (源相对路径, 运行文件名)
BASE_PACKS = [
    ("3.0/r/C", CORE),
    ("r/L", BRIDGE),
    ("r/fp/base", runtime("base")),
    ("r/fp/themes", runtime("themes")),
    ("r/fp/donation", runtime("donation")),
    ("r/fp/vidurlparser", runtime("vidurlparser")),
    ("D", UTILITY["D"]),
    ("H_p", UTILITY["H_p"]),
    ("M", UTILITY["M"]),
    ("S", UTILITY["S"]),
    ("Xmd", UTILITY["Xmd"]),
    ("pr/P", UTILITY["pr/P"]),
    ("pr/P_8049", UTILITY["pr/P_8049"]),
    ("LD64", UTILITY["LD64"]),
]

EXT_PACKS = [
    ("r/fp/sf", runtime("sf")),
    ("r/fp/sf", runtime("sf", False)),
    ("r/fp/mf", runtime("mf")),
    ("r/fp/mf", runtime("mf", False)),
    ("r/fp/af", runtime("af")),
    ("r/fp/af", runtime("af", False)),
]

SIDECARS = [
    ("cfg/C", CORE, "_c"),
    ("cfg/L", BRIDGE, "_c"),
    ("cfg/base", runtime("base"), "_c"),
    ("cfg/themes", runtime("themes"), "_c"),
    ("cfg/donation", runtime("donation"), "_c"),
    ("cfg/vidurlparser", runtime("vidurlparser"), "_c"),
    ("sig/C", CORE, "_s"),
    ("sig/L", BRIDGE, "_s"),
    ("sig/base", runtime("base"), "_s"),
    ("sig/themes", runtime("themes"), "_s"),
    ("sig/donation", runtime("donation"), "_s"),
    ("sig/vidurlparser", runtime("vidurlparser"), "_s"),
]

BASE_NAMES = [name for _, name in BASE_PACKS] + [
    name + suffix for _, name, suffix in SIDECARS]
EXT_NAMES = [name for _, name in EXT_PACKS]


def body(data: bytes) -> bytes:
    """去掉 32B SHA-256(body) 前缀。"""
    if len(data) < 32:
        return data
    payload = data[32:]
    if hashlib.sha256(payload).digest() == data[:32]:
        return payload
    return data


def build_assets(target: Path, assets: Path) -> None:
    """把最小集打成 FeaturePackRestorer 期望的两个 zip。"""
    assets.mkdir(parents=True, exist_ok=True)
    for zip_name, names in (("x7_3.0.zip", BASE_NAMES),
                            ("x7_3.0_ext.zip", EXT_NAMES)):
        target_dir = assets
        if zip_name.endswith("_ext.zip") and assets.name in ("wx30", "wx244"):
            target_dir = assets.parent / (assets.name + "-ext")
        target_dir.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(target_dir / zip_name, "w") as archive:
            for name in names:
                path = target / name
                if not path.is_file():
                    raise FileNotFoundError(path)
                info = zipfile.ZipInfo(name, date_time=ZIP_TIME)
                info.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(info, path.read_bytes())
        print(f"{target_dir / zip_name}: {len(names)} files")


def build(source: Path, output: Path, assets: Path | None = None) -> int:
    target = output / "x7_3.0"
    target.mkdir(parents=True, exist_ok=True)
    count = 0
    total = 0
    for rel, name in BASE_PACKS + EXT_PACKS:
        path = source / rel
        if not path.is_file():
            print(f"缺少 {path}")
            continue
        data = body(path.read_bytes())
        (target / name).write_bytes(data)
        count += 1
        total += len(data)
    for rel, name, suffix in SIDECARS:
        path = source / rel
        if not path.is_file():
            print(f"缺少 {path}")
            continue
        data = path.read_bytes()
        (target / (name + suffix)).write_bytes(data)
        count += 1
        total += len(data)
    print(f"生成 {target}: {count} 个文件, {total} B ({total / 1048576:.2f} MiB)")
    if assets is not None:
        build_assets(target, assets)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="生成 X 3.0 最小运行目录")
    parser.add_argument("--source", type=Path,
                        default=ROOT / "xmetadata" / "wx7",
                        help="项目仓 wx7 目录")
    parser.add_argument("-o", "--output", type=Path,
                        default=ROOT / "build" / "generated" / "x30_min",
                        help="输出根目录")
    parser.add_argument("--assets", type=Path, default=None,
                        help="同时生成 x7_3.0.zip / x7_3.0_ext.zip 到此目录")
    args = parser.parse_args()
    return build(args.source, args.output, args.assets)


if __name__ == "__main__":
    raise SystemExit(main())
