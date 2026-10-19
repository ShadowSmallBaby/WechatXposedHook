#!/usr/bin/env python3
"""从 xmetadata 生成两个运行时功能包 zip。

源文件格式为 SHA-256(body)[32] + body;边车按角色从 cfg/ 与 sig/ 读取。
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
    ("pr/P", "44c29edb103a2872f519adc9afdaaa"),
    ("pr/P_8049", "6d6586c9c5458ecfc98981b52ee662de"),
]

SIDECARS = {
    "base": "14e777717682cce8a53cfcb34a22d65",
    "L": "36a76b97b96b5d46742bb4bcd2ff24d",
    "themes": "802766a4a4bd401c145a57463274d4dd",
    "donation": "a89eaf67dc796cb3af54d94fac0198b",
    "C": "d61f837cad1d412f80b84d143e1257",
    "vidurlparser": "df4e6fd144fab2389ece8cb79eaa8f",
}

# X 3.0 按当前 xmetadata 角色打包：d61f8 主核心 + vidurlparser(df4e6) + 功能资源。
X30_BASE = list(COMMON) + [
    ("r/fp/vidurlparser", "df4e6fd144fab2389ece8cb79eaa8f"),
]
X30_EXT = [
    ("r/fp/sf", "257f23e0175be13dec231373679bedc"),
    ("r/fp/mf", "ec38a2b5b262d9c72f75edacb8875cfe"),
    ("r/fp/af", "ee06cd8f9beaf915a27b8bad9e8c2f"),
]
X30_SIDECARS = dict(SIDECARS)

WX6_BASE = [
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
    ("pr/P", "44c29edb103a2872f519adc9afdaaa"),
    ("pr/P_8049", "6d6586c9c5458ecfc98981b52ee662de"),
    ("r/fp/vidurlparser", "df4e6fd144fab2389ece8cb79eaa8f"),
]
WX6_EXT = [
    ("r/fp/sf", "257f23e0175be13dec231373679bedc"),
    ("r/fp/mf", "ec38a2b5b262d9c72f75edacb8875cfe"),
    ("r/fp/af", "ee06cd8f9beaf915a27b8bad9e8c2f"),
]
WX6_SIDECARS = dict(SIDECARS)

BASE_TARGETS = [
    ("wx6", "wx6_2.44.zip", "r/C", "wx244", WX6_BASE, WX6_SIDECARS),
    ("wx7", "x7_3.0.zip", "3.0/r/C", "wx30", X30_BASE, X30_SIDECARS),
]

EXT_TARGETS = [
    ("wx6", "wx6_2.44_ext.zip", "wx244-ext", WX6_EXT),
    ("wx7", "x7_3.0_ext.zip", "wx30-ext", X30_EXT),
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


def build(product: str, zip_name: str, core_source: str | None, flavor: str,
          common: list[tuple[str, str]], sidecars: dict[str, str],
          output_root: Path) -> Path:
    source = ROOT / "xmetadata" / product
    entries = list(common)
    if core_source is not None:
        entries.append((core_source, "d61f837cad1d412f80b84d143e1257"))
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
                runtime = sidecars.get(path.name)
                if runtime is None:
                    continue
                add(archive, runtime + suffix, path.read_bytes())
    print(f"{flavor}/{zip_name}: "
          f"{len(zipfile.ZipFile(target).infolist())} files, "
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
    for product, name, core, flavor, common, sidecars in BASE_TARGETS:
        build(product, name, core, flavor, common, sidecars, args.output_root)
    for product, name, flavor, common in EXT_TARGETS:
        build(product, name, None, flavor, common, {}, args.output_root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
