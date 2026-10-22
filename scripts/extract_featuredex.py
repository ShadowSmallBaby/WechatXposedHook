#!/usr/bin/env python3
"""从 xmetadata/wx7 的扩展包容器解出 x30_{sf,mf,af}.dex。

以前这些 dex 是本地 `data/refs/featuredex` 下的离线产物，`data/` 被
gitignore，CI 干净检出会缺文件。扩展包 body 本身就在仓库里，密码也是
已确认的常量，因此构建时可以稳定重建（输出与离线产物逐字节一致）。

用法：
    python -X utf8 scripts/extract_featuredex.py \
        --source xmetadata/wx7 --output build/generated/featuredex
"""

from __future__ import annotations

import argparse
import hashlib
import io
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import decrypt_wx244 as d

SERVICES = {
    # role: (外层 password, 内层 password)
    "sf": ("80752d1605bf6235493bb1e113c3e8c", "5c897b16c61610673c398e6553f3b"),
    "mf": ("4f61bb9ec1e854c9753f878a883a294", "e82b5260fd15c04fd7f1dea075738c1"),
    "af": ("4f74d05b691fd81abe1838b3bffbb9e9", "5b4f49dc184d84d15cf14915e854449"),
}


def read_body(path: Path) -> bytes:
    raw = path.read_bytes()
    if len(raw) < 33:
        raise ValueError(f"{path}: 源文件过短")
    body = raw[32:]
    if hashlib.sha256(body).digest() != raw[:32]:
        raise ValueError(f"{path}: 前 32 字节不是 body 的 SHA-256")
    return body


def extract(role: str, outer_password: str, inner_password: str,
            source: Path) -> bytes:
    container = d.parse_container(read_body(source / "r" / "fp" / role))
    if container is None:
        raise ValueError(f"{role}: 外层容器解析失败")
    outer = d.decrypt(container, outer_password)
    if outer is None:
        raise ValueError(f"{role}: 外层解密失败")
    items = d.signed_array(outer)
    if not items:
        raise ValueError(f"{role}: 外层明文不是 3 元素数组")
    inner = d.parse_container(items[2])
    if inner is None:
        raise ValueError(f"{role}: 内层容器解析失败")
    apk = d.decrypt(inner, inner_password)
    if apk is None or apk[:2] != b"PK":
        raise ValueError(f"{role}: 内层不是 APK")
    with zipfile.ZipFile(io.BytesIO(apk)) as archive:
        return archive.read("classes.dex")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("xmetadata/wx7"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    args.output.mkdir(parents=True, exist_ok=True)
    for role, (outer_password, inner_password) in SERVICES.items():
        dex = extract(role, outer_password, inner_password, args.source)
        target = args.output / f"x30_{role}.dex"
        target.write_bytes(dex)
        print(f"{target}: {len(dex)} B")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
