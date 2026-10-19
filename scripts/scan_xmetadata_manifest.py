#!/usr/bin/env python3
"""扫描 xmetadata 下各版本源文件，生成 source_manifest.json / .md 清单。

注意：这里统计的是「源文件」，不是最终运行时包。运行时包由
build_release_packs.py 在构建时生成。

清单按「版本目录」组织，例如：

    wx6_2.26、wx6_2.27、...、wx6_2.44
    wx6_r、wx6_r_fp、wx6_pr、wx6_root
    wx7_3.0、wx7_r、wx7_pr、...
    wx5_*、...

每个版本条目包含文件数、可转换数（32 字节 SHA-256 + body）、不可转换数、
容器头版本分布和逐文件明细。

用法:
    python scripts/scan_xmetadata_manifest.py
    python scripts/scan_xmetadata_manifest.py \
        --out xmetadata/source_manifest.json --md xmetadata/source_manifest.md
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from collections import Counter
from pathlib import Path

MAGIC = b"\x97\xc4\x01\x30\xc4\x05"
VERSION_RE = re.compile(rb"\x97\xc4\x01\x30\xc4\x05(\d{5})")


def kind_of(body: bytes) -> str:
    if body.startswith(b"\x7fELF"):
        return "ELF"
    if body.startswith(b"dex\n"):
        return "DEX"
    if body.startswith(b"PK\x03\x04"):
        return "ZIP"
    if body.startswith(b"\x30\x82"):
        return "DER"
    if body.startswith(MAGIC):
        return "container"
    if body[:1] in (b"{", b"["):
        return "JSON"
    return "blob"


def scan_file(root: Path, path: Path) -> dict:
    data = path.read_bytes()
    entry = {
        "path": path.relative_to(root).as_posix(),
        "bytes": len(data),
        "prefix_valid": False,
        "body_bytes": len(data),
        "kind": "unknown",
    }
    if len(data) >= 40:
        prefix, body = data[:32], data[32:]
        entry["prefix_valid"] = hashlib.sha256(body).digest() == prefix
        entry["body_bytes"] = len(body)
        entry["body_sha256"] = hashlib.sha256(body).hexdigest()[:32]
        match = VERSION_RE.match(body[:16])
        if match:
            entry["container_version"] = match.group(1).decode()
        entry["kind"] = kind_of(body)
    elif data:
        entry["kind"] = kind_of(data)
    return entry


def version_key(set_name: str, relative: Path) -> str:
    parts = relative.parts
    if not parts:
        return f"{set_name}_root"
    first = parts[0]
    if first in ("pr", "r", "rt"):
        key = f"{set_name}_{first}"
        if first == "r" and len(parts) > 2 and parts[1] in ("fp", "pl", "xm", "lc"):
            key += "_" + parts[1]
        return key
    if len(parts) == 1:
        return f"{set_name}_root"
    return f"{set_name}_{first}"


def summarize(entries: list[dict]) -> dict:
    versions = Counter(
        item.get("container_version", "") for item in entries if item.get("container_version")
    )
    return {
        "files": len(entries),
        "prefix_valid": sum(1 for item in entries if item["prefix_valid"]),
        "prefix_invalid": sum(1 for item in entries if not item["prefix_valid"] and item["bytes"] >= 40),
        "small": sum(1 for item in entries if item["bytes"] < 40),
        "kinds": dict(Counter(item["kind"] for item in entries)),
        "container_versions": dict(sorted(versions.items())),
        "body_bytes": sum(item["body_bytes"] for item in entries if item["prefix_valid"]),
    }


def render_markdown(result: dict) -> str:
    versions = result["versions"]
    lines = [
        "# xmetadata 功能包清单",
        "",
        f"- 生成时间：{result['generated_at']}",
        f"- 转换规则：`{result['rule']}`",
        f"- 版本条目：{len(versions)} 个",
        "",
        "## 汇总",
        "",
        "| 版本 | 文件 | 可转换 | 不可转换 | 小文件 | body 字节 |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for name, info in versions.items():
        lines.append(
            f"| `{name}` | {info['files']} | {info['prefix_valid']} | "
            f"{info['prefix_invalid']} | {info['small']} | {info['body_bytes']} |"
        )
    lines += ["", "## 逐版本明细", ""]
    for name, info in versions.items():
        lines.append(f"### `{name}`")
        lines.append("")
        lines.append(
            f"- 文件 {info['files']}，可转换 {info['prefix_valid']}，"
            f"不可转换 {info['prefix_invalid']}，类型 {info['kinds']}"
        )
        if info.get("container_versions"):
            lines.append(f"- 容器头版本：{info['container_versions']}")
        lines.append("")
        lines.append("| 文件 | 大小 | 可转换 | body | 类型 | 容器版本 |")
        lines.append("|---|---:|---|---:|---|---|")
        for item in info["entries"]:
            name_only = item["path"].split("/")[-1]
            lines.append(
                f"| `{name_only}` | {item['bytes']} | "
                f"{'是' if item['prefix_valid'] else '否'} | {item['body_bytes']} | "
                f"{item['kind']} | {item.get('container_version', '')} |"
            )
        lines.append("")
    return "\n".join(lines)


def main(argv=None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(description="扫描 xmetadata 生成功能包清单")
    parser.add_argument("--root", type=Path, default=Path("xmetadata"))
    parser.add_argument("--out", type=Path, default=Path("xmetadata/source_manifest.json"))
    parser.add_argument("--md", type=Path, default=Path("xmetadata/source_manifest.md"))
    parser.add_argument("--no-entries", action="store_true", help="不下逐文件明细")
    args = parser.parse_args(argv)

    if not args.root.is_dir():
        raise SystemExit(f"目录不存在: {args.root}")

    versions: dict[str, list[dict]] = {}
    for top in sorted(item for item in args.root.iterdir() if item.is_dir()):
        if top.name in ("crc", "test"):
            continue
        for path in sorted(top.rglob("*")):
            if not path.is_file():
                continue
            entry = scan_file(args.root, path)
            key = version_key(top.name, path.relative_to(top))
            versions.setdefault(key, []).append(entry)

    result = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "root": args.root.as_posix(),
        "rule": "source = sha256(body)[32] + body; runtime file = body",
        "summary": {
            "versions": len(versions),
            "files": sum(len(items) for items in versions.values()),
        },
        "versions": {},
    }
    for name, entries in sorted(versions.items()):
        info = summarize(entries)
        if not args.no_entries:
            info["entries"] = entries
        result["versions"][name] = info

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"写入 {args.out}")

    if args.md:
        args.md.parent.mkdir(parents=True, exist_ok=True)
        args.md.write_text(render_markdown(result), encoding="utf-8")
        print(f"写入 {args.md}")

    print(f"{'版本':<18}{'文件':>6}{'可转换':>8}{'不可转换':>8}")
    for name, info in result["versions"].items():
        print(f"{name:<18}{info['files']:>6}{info['prefix_valid']:>8}{info['prefix_invalid']:>8}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
