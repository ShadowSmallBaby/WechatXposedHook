#!/usr/bin/env python3
"""从 xmetadata 生成两个运行时功能包 zip。

- 源文件 = SHA-256(body)[32] + body
- 边车：<源目录>/cfg/<角色> -> <运行时文件名>_c
        <源目录>/sig/<角色> -> <运行时文件名>_s
- P 资源只取 P 与 P_8049，不带历史版本变体
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

COMMON = [
    ("r/fp/base", "14e777717682cce8a53cfcb34a22d65"),
    ("r/fp/donation", "a89eaf67dc796cb3af54d94fac0198b"),
    ("r/fp/themes", "802766a4a4bd401c145a57463274d4dd"),
    ("r/L", "36a76b97b96b5d46742bb4bcd2ff24d"),
    ("LD64", "dc7be70f1898d3a58965a919740f97"),
    ("D", "534a9729a0c461cbd7a4379978fb742"),
    ("H_p", "62a4e566b714ea1c4349923c9ea6c35"),
    ("M", "69691c7bdcc3ce6d5d8a1361f22d4ac"),
    ("S", "5dbc98dcc983a7728bd82d1a47546e"),
    ("Xmd", "739440c5d87b2b8095b99f9d2a1bbf9"),
    ("r/server_resource", "9816b5dfd637d3ce1473a9951b9e05"),
    ("pr/P", "44c29edb103a2872f519adc9afdaaa"),
    ("pr/P_8049", "6d6586c9c5458ecfc98981b52ee662de"),
]

SIDECARS = {
    "base": "14e777717682cce8a53cfcb34a22d65",
    "L": "36a76b97b96b5d46742bb4bcd2ff24d",
    "themes": "802766a4a4bd401c145a57463274d4dd",
    "donation": "a89eaf67dc796cb3af54d94fac0198b",
    "C": "d61f837cad1d412f80b84d143e1257",
    "C_backup": "d61f837cad1d412f80b84d143e1257_backup",
}

TARGETS = [
    ("wx6", "wx6_2.44.zip", "r/C", "wx244"),
    ("wx7", "x7_3.0.zip", "3.0/r/C", "wx30"),
]

ZIP_TIME = (2026, 1, 1, 0, 0, 0)


def body(path: Path) -> bytes:
    data = path.read_bytes()
    if len(data) < 32:
        raise ValueError(f"{path}: 源文件过短")
    payload = data[32:]
    if hashlib.sha256(payload).digest() != data[:32]:
        raise ValueError(f"{path}: 前 32 字节不是 body 的 SHA-256")
    return payload


def add(archive: zipfile.ZipFile, name: str, data: bytes) -> None:
    info = zipfile.ZipInfo(name, date_time=ZIP_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    archive.writestr(info, data)


def build(product: str, zip_name: str, core_source: str, flavor: str,
          output_root: Path) -> Path:
    source = ROOT / "xmetadata" / product
    entries = list(COMMON) + [(core_source, "d61f837cad1d412f80b84d143e1257")]
    output_dir = output_root / flavor
    output_dir.mkdir(parents=True, exist_ok=True)
    target = output_dir / zip_name
    with zipfile.ZipFile(target, "w") as archive:
        for rel, runtime in entries:
            add(archive, runtime, body(source / rel))
        for folder, suffix in (("cfg", "_c"), ("sig", "_s")):
            for path in sorted((source / folder).iterdir()):
                if not path.is_file():
                    continue
                runtime = SIDECARS.get(path.name)
                if runtime is None:
                    raise ValueError(f"未知边车角色: {path}")
                add(archive, runtime + suffix, path.read_bytes())
    print(f"{zip_name}: {len(zipfile.ZipFile(target).infolist())} files, "
          f"{target.stat().st_size} B")
    return target


def main(argv=None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description="生成运行时功能包 zip")
    parser.add_argument("--output-root", type=Path,
                        default=ROOT / "app" / "build" / "generated" / "featurepacks",
                        help="输出目录（默认 app/build/generated/featurepacks）")
    args = parser.parse_args(argv)
    for product, name, core, flavor in TARGETS:
        build(product, name, core, flavor, args.output_root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
