#!/usr/bin/env python3
"""从 xmetadata 生成两个运行时功能包 zip。

源文件格式为 SHA-256(body)[32] + body;边车从 sidecars/ 原样复制。
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from runtime_names import BRIDGE, CORE, UTILITY, runtime
from sidecars import build_sidecars

ROOT = Path(__file__).resolve().parents[1]

COMMON = [
    ("r/fp/base", runtime("base")),
    ("r/fp/donation", runtime("donation")),
    ("r/fp/themes", runtime("themes")),
    ("r/L", BRIDGE),
    ("LD64", UTILITY["LD64"]),
    ("D", UTILITY["D"]),
    ("H_p", UTILITY["H_p"]),
    ("M", UTILITY["M"]),
    ("S", UTILITY["S"]),
    ("Xmd", UTILITY["Xmd"]),
    ("pr/P", UTILITY["pr/P"]),
    ("pr/P_8049", UTILITY["pr/P_8049"]),
]

SIDECARS = {
    "base": runtime("base"),
    "L": BRIDGE,
    "themes": runtime("themes"),
    "donation": runtime("donation"),
    "C": CORE,
    "vidurlparser": runtime("vidurlparser"),
}

# X 3.0：主核心 + vidurlparser + 功能资源。
X30_BASE = list(COMMON) + [
    ("r/fp/vidurlparser", runtime("vidurlparser")),
]
# 扩展包只内置一套命名（MD5("FP_<role>")）；另一套别名由恢复器运行时代拷，
# 避免 APK 里重复存放同一份加密容器。
X30_EXT = [
    ("r/fp/sf", runtime("sf")),
    ("r/fp/mf", runtime("mf")),
    ("r/fp/af", runtime("af")),
]
X30_SIDECARS = dict(SIDECARS)

BASE_TARGETS = [
    ("wx7", "x7_3.0.zip", "3.0/r/C", "wx30", X30_BASE, X30_SIDECARS),
]

EXT_TARGETS = [
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
    # X 3.0 用项目仓 xmetadata/wx7（与 117 模块匹配）。
    source = ROOT / "xmetadata" / product
    if not source.is_dir():
        source = ROOT / "data" / "xmetadata" / product
    entries = list(common)
    if core_source is not None:
        entries.append((core_source, CORE))
    output_dir = output_root / flavor
    output_dir.mkdir(parents=True, exist_ok=True)
    target = output_dir / zip_name
    # X 3.0 运行时与 restorer 都期望 body（无 32B 前缀）。
    keep_prefix = False
    with zipfile.ZipFile(target, "w") as archive:
        for rel, runtime in entries:
            path = source / rel
            add(archive, runtime, path.read_bytes() if keep_prefix else body(path))
        # 旁车带厂商签名，原样从 sidecars/ 复制（见 sidecars.py）。
        for name, data in build_sidecars(source, sidecars).items():
            add(archive, name, data)
    print(f"{flavor}/{zip_name}: "
          f"{len(zipfile.ZipFile(target).infolist())} files, "
          f"{target.stat().st_size} B")
    return target


def check_names() -> None:
    expected = {
        "sf": "aa894d53fa41c9b675eec6f80331085",
        "mf": "665c7b62836222d48164bc1c5f93fb2",
        "af": "3e9bf1b973f6b1617f4f6df9a88f39d",
        "base": "14e777717682cce8a53cfcb34a22d65",
        "themes": "802766a4a4bd401c145a57463274d4dd",
        "donation": "a89eaf67dc796cb3af54d94fac0198b",
        "vidurlparser": "df4e6fd144fab2389ece8cb79eaa8f",
    }
    for role, name in expected.items():
        actual = runtime(role)
        if actual != name:
            raise SystemExit(f"运行时命名规则不匹配: {role} {actual} != {name}")
    if CORE != "d61f837cad1d412f80b84d143e1257":
        raise SystemExit(f"core 运行名不匹配: {CORE}")
    for role, name in (("sf", "60d31eb37595dd44584be5ef363283e3"),
                       ("mf", "ea81aa7df47d74c6737bf98fabf3ff82"),
                       ("af", "f0357a3f154bc2ffe2bff55055457068")):
        actual = runtime(role, prefixed=False)
        if actual != name:
            raise SystemExit(f"别名命名不匹配: {role} {actual} != {name}")


def main(argv=None) -> int:
    check_names()
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
