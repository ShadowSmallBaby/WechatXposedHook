#!/usr/bin/env python3
"""把运行时功能包逆推成 xmetadata 的「按角色分散」源布局。

xmetadata 源文件格式：

    源文件 = SHA-256(body) 的 32 字节 + body
    body   = 运行时目录里的文件（文件名即内容 ID）

运行时文件名是内容 ID，不能直接表达角色；本脚本按内置角色表把它们放回
`r/fp/base`、`r/C`、`pr/P_80482588p`、`LD64` 等位置，并生成 `mapping.json`
记录「运行时文件名 -> 源相对路径」，供装配脚本反向使用。

用法：
    python scripts/reverse_pack_to_xmetadata.py \
        --zip app/build/generated/featurepacks/wx244/wx6_2.44.zip \
        --out xmetadata/wx6/2.44_849 \
        --label "microX 2.44 / 微信 8.0.49"
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
import zipfile
from pathlib import Path

# 运行时内容 ID -> xmetadata 角色路径。
# _c/_s 在上游源树里没有，这里沿用「与主体同目录、加后缀」的约定。
LAYOUT = {
    "14e777717682cce8a53cfcb34a22d65": "r/fp/base",
    "14e777717682cce8a53cfcb34a22d65_c": "r/fp/base_c",
    "14e777717682cce8a53cfcb34a22d65_s": "r/fp/base_s",
    "a89eaf67dc796cb3af54d94fac0198b": "r/fp/donation",
    "a89eaf67dc796cb3af54d94fac0198b_c": "r/fp/donation_c",
    "a89eaf67dc796cb3af54d94fac0198b_s": "r/fp/donation_s",
    "802766a4a4bd401c145a57463274d4dd": "r/fp/themes",
    "802766a4a4bd401c145a57463274d4dd_c": "r/fp/themes_c",
    "802766a4a4bd401c145a57463274d4dd_s": "r/fp/themes_s",
    "d61f837cad1d412f80b84d143e1257": "r/C",
    "d61f837cad1d412f80b84d143e1257_c": "r/C_c",
    "d61f837cad1d412f80b84d143e1257_s": "r/C_s",
    "d61f837cad1d412f80b84d143e1257_backup_c": "r/C_backup_c",
    "d61f837cad1d412f80b84d143e1257_backup_s": "r/C_backup_s",
    "36a76b97b96b5d46742bb4bcd2ff24d": "r/L",
    "36a76b97b96b5d46742bb4bcd2ff24d_c": "r/L_c",
    "36a76b97b96b5d46742bb4bcd2ff24d_s": "r/L_s",
    "dc7be70f1898d3a58965a919740f97": "LD64",
    "534a9729a0c461cbd7a4379978fb742": "D",
    "62a4e566b714ea1c4349923c9ea6c35": "H_p",
    "69691c7bdcc3ce6d5d8a1361f22d4ac": "M",
    "5dbc98dcc983a7728bd82d1a47546e": "S",
    "739440c5d87b2b8095b99f9d2a1bbf9": "Xmd",
    "24ce1c66be23f9c731fb2db3a76954": "pr/P_8045",
    "55bcfe849748f60697e2b1e191321b3": "pr/P_8048",
    "6d6586c9c5458ecfc98981b52ee662de": "pr/P_8049",
    "89d9d67db0a14fc9b040cf25a28ef71": "pr/P_80422428p",
    "7e72d95130d766517ea69c215f38ddd": "pr/P_80482588p",
    "44c29edb103a2872f519adc9afdaaa": "pr/P",
    # 实机修复工具 8.0.49 包里的两个额外 P_ 变体（内容与现有角色相同/重复）
    "5f184c4b7f68e4cc14bebc85dd23e95": "pr/P_80422429p",
    "ce9750a2ba134879eb33ac335f55e2d": "pr/P_8048",
}


def main(argv=None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(description="运行时功能包 -> xmetadata 源格式")
    parser.add_argument("--zip", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--label", default="")
    parser.add_argument("--mapping-out", type=Path,
                        help="映射文件路径（默认 <out>/mapping.json）")
    parser.add_argument("--include-sidecars", action="store_true",
                        help="连同 _c/_s 一起写入（默认跳过，留给项目自签）")
    args = parser.parse_args(argv)

    args.out.mkdir(parents=True, exist_ok=True)
    entries = []
    written = 0
    with zipfile.ZipFile(args.zip) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            name = Path(info.filename).name
            body = archive.read(info.filename)
            digest = hashlib.sha256(body).digest()
            is_sidecar = any(
                name.endswith(suffix)
                for suffix in ("_backup_c", "_backup_s", "_c", "_s")
            )
            if is_sidecar and not args.include_sidecars:
                entries.append(
                    {
                        "name": name,
                        "source": None,
                        "bytes": len(body),
                        "source_bytes": 0,
                        "sha256": digest.hex(),
                        "note": "sidecar skipped; self-sign later",
                    }
                )
                print(f"{name:<45} -> (待自签)")
                continue
            source = LAYOUT.get(name)
            if source is None:
                print(f"跳过未知角色: {name}", file=sys.stderr)
                continue
            target = args.out / source
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(digest + body)
            written += 1
            entries.append(
                {
                    "name": name,
                    "source": source,
                    "bytes": len(body),
                    "source_bytes": len(body) + 32,
                    "sha256": digest.hex(),
                }
            )
            print(f"{name:<45} -> {source:<22} {len(body):>9} B")

    entries.sort(key=lambda item: item["source"] or "")
    manifest = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "label": args.label,
        "runtime_zip": args.zip.as_posix(),
        "rule": "source = sha256(body)[32] + body; runtime file = body",
        "files": len(entries),
        "written": written,
        "entries": entries,
    }
    mapping_path = args.mapping_out or (args.out / "mapping.json")
    mapping_path.parent.mkdir(parents=True, exist_ok=True)
    mapping_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"\n输出 {len(entries)} 个源文件 -> {args.out}")
    print(f"映射: {mapping_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
