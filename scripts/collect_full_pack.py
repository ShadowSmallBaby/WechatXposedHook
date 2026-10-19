#!/usr/bin/env python3
"""把微X的运行时功能包「全量」收集到本地，并生成清单。

微X 的 28 个功能文件（4 个 dex 的加密体 + 配置/签名 + 2 个 ELF）随 APK assets
发布，运行时解压到 /data/data/com.tencent.mm/files/wx6_2.44。本脚本从下面任一
来源把整套文件落到一个目录：

    zip   app/build/generated/featurepacks/wx244/wx6_2.44.zip（构建生成，运行时投放用）
    tar   data/refs/wx6_2.44.tar                （设备/发行包里的 tar）
    dir   设备上 BACKUP_MODULE/wx6_2.44 目录     （adb pull 下来的实际落地目录）
    apk   微X APK 的 assets/                    （安装内置资源，可能缺文件/旧版）

默认优先用 zip（28/28 完整且与 tar 一致），其余来源只做补充与校验。

用法:
    python scripts/collect_full_pack.py
    python scripts/collect_full_pack.py --out build/microx_full_pack --include-apk-extras
    python scripts/collect_full_pack.py --dir /path/to/wx6_2.44

只依赖标准库。
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
import tarfile
import zipfile
from pathlib import Path

_here = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("verify_featurepack", _here / "verify_featurepack.py")
_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_module)
EXPECTED_NAMES = _module.EXPECTED_NAMES
EXPECTED_SIZES = dict(zip(_module.EXPECTED_NAMES, _module.EXPECTED_SIZES))

ELF_MAGIC = b"\x7fELF"
DEX_MAGIC = b"dex\n"


def kind_of(payload: bytes) -> str:
    if payload.startswith(ELF_MAGIC):
        return "ELF"
    if payload.startswith(DEX_MAGIC):
        return "DEX"
    if len(payload) <= 1024:
        return "meta"
    return "blob"


def suffix_role(name: str) -> str:
    for suffix, role in (
        ("_backup_c", "配置备份"),
        ("_backup_s", "签名备份"),
        ("_c", "配置/校验块"),
        ("_s", "RSA 签名块"),
    ):
        if name.endswith(suffix):
            return role
    return "主体/加密载荷"


def read_zip(path: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(path) as archive:
        return {
            Path(info.filename).name: archive.read(info.filename)
            for info in archive.infolist()
            if not info.is_dir()
        }


def read_tar(path: Path) -> dict[str, bytes]:
    payloads = {}
    with tarfile.open(path) as archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            handle = archive.extractfile(member)
            if handle is not None:
                payloads[Path(member.name).name] = handle.read()
    return payloads


def read_dir(path: Path) -> dict[str, bytes]:
    return {item.name: item.read_bytes() for item in path.iterdir() if item.is_file()}


def read_apk_assets(path: Path) -> dict[str, bytes]:
    payloads = {}
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            if not info.filename.startswith("assets/") or info.is_dir():
                continue
            payloads[info.filename[len("assets/"):]] = archive.read(info.filename)
    return payloads


def load_sources(args) -> list[tuple[str, Path, dict[str, bytes]]]:
    sources = []
    for label, path, reader in (
        ("zip", args.zip, read_zip),
        ("tar", args.tar, read_tar),
        ("dir", args.dir, read_dir),
        ("apk", args.apk, read_apk_assets),
    ):
        if path and path.is_file() if reader is not read_dir else path and path.is_dir():
            try:
                sources.append((label, path, reader(path)))
            except (OSError, tarfile.TarError, zipfile.BadZipFile) as error:
                print(f"跳过 {label} {path}: {error}", file=sys.stderr)
    return sources


def main(argv=None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(description="本地收集微X运行时功能包全量文件")
    parser.add_argument("--zip", type=Path,
                        default=Path("app/build/generated/featurepacks/wx244/wx6_2.44.zip"))
    parser.add_argument("--tar", type=Path, default=Path("data/refs/wx6_2.44.tar"))
    parser.add_argument("--dir", type=Path, help="adb pull 下来的 wx6_2.44 目录")
    parser.add_argument("--apk", type=Path, default=Path("data/refs/微X模块_2.44.apk"))
    parser.add_argument("--out", type=Path, default=Path("build/microx_full_pack"))
    parser.add_argument(
        "--include-apk-extras",
        action="store_true",
        help="把只存在于 APK assets 的文件也一并收集（默认只收运行时功能包的 28 个文件）",
    )
    args = parser.parse_args(argv)

    sources = load_sources(args)
    if not sources:
        raise SystemExit("没有可用来源，检查 --zip / --tar / --dir / --apk")

    pack: dict[str, tuple[str, bytes]] = {}
    for label, path, payloads in sources:
        for name in EXPECTED_NAMES:
            if name in pack:
                continue
            if name in payloads:
                pack[name] = (label, payloads[name])
        if len(pack) == len(EXPECTED_NAMES) and not args.include_apk_extras:
            # 运行时功能包已经 28/28，后续来源只做校验，不再覆盖
            break

    extras: dict[str, tuple[str, bytes]] = {}
    if args.include_apk_extras:
        for label, path, payloads in sources:
            if label != "apk":
                continue
            for name, payload in payloads.items():
                if name not in EXPECTED_NAMES:
                    extras.setdefault(name, (label, payload))

    missing = [name for name in EXPECTED_NAMES if name not in pack]
    args.out.mkdir(parents=True, exist_ok=True)
    manifest = {"sources": {}, "files": [], "missing": missing, "extras": sorted(extras)}
    for label, path, payloads in sources:
        manifest["sources"][label] = {
            "path": path.as_posix(),
            "count": len(payloads),
            "expected_hits": sum(1 for name in EXPECTED_NAMES if name in payloads),
        }

    for name in EXPECTED_NAMES:
        entry = pack.get(name)
        if entry is None:
            continue
        source, payload = entry
        target = args.out / name
        target.write_bytes(payload)
        manifest["files"].append(
            {
                "name": name,
                "source": source,
                "bytes": len(payload),
                "expected_bytes": EXPECTED_SIZES[name],
                "size_ok": len(payload) == EXPECTED_SIZES[name],
                "sha256": hashlib.sha256(payload).hexdigest(),
                "kind": kind_of(payload),
                "role": suffix_role(name),
            }
        )

    for name, (source, payload) in extras.items():
        target = args.out / "apk_extras" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
        manifest["files"].append(
            {
                "name": name,
                "source": source,
                "bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "kind": kind_of(payload),
                "role": "APK 独有资源",
            }
        )

    (args.out / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    print(f"输出目录: {args.out}")
    print(f"运行时功能包: {len(pack)}/{len(EXPECTED_NAMES)}")
    if missing:
        print(f"缺失: {', '.join(missing)}")
    for label, info in manifest["sources"].items():
        print(f"  来源 {label}: {info['path']}（命中 {info['expected_hits']}/28）")
    bad = [item["name"] for item in manifest["files"] if not item.get("size_ok", True)]
    print("  尺寸全部符实" if not bad else f"  尺寸不符: {', '.join(bad)}")
    if extras:
        print(f"  APK 独有资源: {len(extras)} 个（已放到 apk_extras/）")
    print(f"  manifest: {args.out / 'manifest.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
