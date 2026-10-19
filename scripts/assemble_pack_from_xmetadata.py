#!/usr/bin/env python3
"""从 xmetadata 源文件装配微X运行时功能包（以源文件为主，不依赖 zip）。

已确认的转换规则（对 xmetadata 下 1395 个文件成立）：

    源文件 = SHA-256(body) 的 32 字节 + body
    body   = 微X运行时容器（97 c4 01 30 c4 05 + 5 位数字 + 负载）

所以从源文件到运行时文件只需要：校验前 32 字节 == SHA-256(其后全部内容)，
然后去掉这 32 字节。已验证 11 个文件与现有运行时包逐字节一致（D / H_p / LD64 /
M / S / Xmd / pr/P_* 等）。

两个无法从源文件补齐的东西：

1. **运行时文件名**：是服务端下发的内容 ID（31 位 hex），不是 body 的常见哈希。
   脚本用内置角色表映射已知文件；其余用 --name-map 指定。
2. **_c / _s 边车**：源树里没有。`_s` 是 RSA-SHA1 签名（用 D 证书可验签），
   没有作者私钥无法为新 body 生成；但本模块的 `SignatureVerifyBypass` 会在运行时
   跳过验签。真机对照表明 `_c`/`_s` 与 body 不配套也不影响加载。真正的限制是
   **源 body 快照必须与当前壳/微信版本匹配**：旧 xmetadata 快照的
   `wx6/r/fp/*` 在微信 8.0.49 + 微X 2.44_5.41 上会解不出
   `com.fkzhang.wxfeatures.*` 入口类。
   `--sidecars` 仅用于保持目录完整，不是加载必需。

用法:
    python scripts/assemble_pack_from_xmetadata.py --list
    python scripts/assemble_pack_from_xmetadata.py --out build/xmeta_pack
    python scripts/assemble_pack_from_xmetadata.py --out build/xmeta_pack \
        --sidecars <现有30文件目录> --strict
    python scripts/assemble_pack_from_xmetadata.py --out build/xmeta_pack \
        --name-map name_map.json

只依赖标准库。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

# 源文件（相对 xmetadata/wx6） -> 现有运行时包里的文件名。
# verified=True 表示当前快照下逐字节一致（去掉 32 字节头后）。
DEFAULT_MAP: list[dict] = [
    # 4 个功能 dex 本体（角色对应；当前源快照比仓库里的包新，尺寸不同）
    {"source": "r/fp/base", "name": "14e777717682cce8a53cfcb34a22d65", "role": "BaseDex", "verified": False},
    {"source": "r/fp/donation", "name": "a89eaf67dc796cb3af54d94fac0198b", "role": "DonationDex", "verified": False},
    {"source": "r/fp/themes", "name": "802766a4a4bd401c145a57463274d4dd", "role": "ThemesDex", "verified": False},
    # 主树 r/C 是 849 覆盖；2.44/r/C 保留原版 848
    {"source": "r/C", "name": "d61f837cad1d412f80b84d143e1257", "role": "CoreDex", "verified": False},
    # 已验证一致
    {"source": "D", "name": "534a9729a0c461cbd7a4379978fb742", "role": "证书", "verified": True},
    {"source": "H_p", "name": "62a4e566b714ea1c4349923c9ea6c35", "role": "hooks 参数", "verified": True},
    {"source": "LD64", "name": "dc7be70f1898d3a58965a919740f97", "role": "loader arm64", "verified": True},
    {"source": "M", "name": "69691c7bdcc3ce6d5d8a1361f22d4ac", "role": "参数", "verified": True},
    {"source": "S", "name": "5dbc98dcc983a7728bd82d1a47546e", "role": "字符串资源", "verified": True},
    {"source": "Xmd", "name": "739440c5d87b2b8095b99f9d2a1bbf9", "role": "xmd 资源", "verified": True},
    {"source": "pr/P_8045", "name": "24ce1c66be23f9c731fb2db3a76954", "role": "资源", "verified": True},
    {"source": "pr/P_8048", "name": "55bcfe849748f60697e2b1e191321b3", "role": "资源", "verified": True},
    {"source": "pr/P_8049", "name": "6d6586c9c5458ecfc98981b52ee662de", "role": "资源", "verified": True},
    {"source": "pr/P_80422428p", "name": "89d9d67db0a14fc9b040cf25a28ef71", "role": "资源", "verified": True},
    {"source": "pr/P_80482588p", "name": "7e72d95130d766517ea69c215f38ddd", "role": "资源", "verified": True},
]

# 现有运行时包里、当前源快照无法直接给出的条目（留给 --name-map / --sidecars）
UNMAPPED_RUNTIME = [
    "44c29edb103a2872f519adc9afdaaa",
    "9816b5dfd637d3ce1473a9951b9e05",
    "36a76b97b96b5d46742bb4bcd2ff24d",
    "14e777717682cce8a53cfcb34a22d65_c",
    "14e777717682cce8a53cfcb34a22d65_s",
    "36a76b97b96b5d46742bb4bcd2ff24d_c",
    "36a76b97b96b5d46742bb4bcd2ff24d_s",
    "802766a4a4bd401c145a57463274d4dd_c",
    "802766a4a4bd401c145a57463274d4dd_s",
    "a89eaf67dc796cb3af54d94fac0198b_c",
    "a89eaf67dc796cb3af54d94fac0198b_s",
    "d61f837cad1d412f80b84d143e1257_c",
    "d61f837cad1d412f80b84d143e1257_s",
    "d61f837cad1d412f80b84d143e1257_backup_c",
    "d61f837cad1d412f80b84d143e1257_backup_s",
]


def split_source(path: Path) -> tuple[bytes | None, bytes, str]:
    """返回 (前32字节, body, 状态)。状态: ok / missing / short / bad-hash。"""
    if not path.is_file():
        return None, b"", "missing"
    data = path.read_bytes()
    if len(data) < 40:
        return None, data, "short"
    prefix, body = data[:32], data[32:]
    if hashlib.sha256(body).digest() != prefix:
        return prefix, body, "bad-hash"
    return prefix, body, "ok"


# cfg/<角色>、sig/<角色> 里的边车对应哪个运行时文件名。
SIDECAR_RUNTIME = {
    "base": "14e777717682cce8a53cfcb34a22d65",
    "L": "36a76b97b96b5d46742bb4bcd2ff24d",
    "themes": "802766a4a4bd401c145a57463274d4dd",
    "donation": "a89eaf67dc796cb3af54d94fac0198b",
    "C": "d61f837cad1d412f80b84d143e1257",
    "C_backup": "d61f837cad1d412f80b84d143e1257_backup",
}


def load_name_map(path: Path | None) -> list[dict]:
    if path is None:
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        return [{"source": key, "name": value, "role": "name-map", "verified": False}
                for key, value in data.items()]
    if isinstance(data, list):
        return data
    raise SystemExit("--name-map 需要 {source: name} 或 [{source,name,role}] 形式")


def main(argv=None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(description="从 xmetadata 装配微X运行时功能包")
    parser.add_argument("--source", type=Path, default=Path("xmetadata/wx6"))
    parser.add_argument("--out", type=Path, default=Path("build/xmeta_pack"))
    parser.add_argument("--name-map", type=Path, help="额外的 源文件->运行时文件名 映射")
    parser.add_argument("--sidecars", type=Path, help="从该目录复制 _c/_s 边车")
    parser.add_argument("--role-sidecars", action="store_true",
                        help="从源目录的 cfg/<角色> 与 sig/<角色> 读取边车")
    parser.add_argument("--flat", action="store_true",
                        help="源目录是完整快照：每个文件名就是运行时文件名")
    parser.add_argument("--snapshot", action="store_true",
                        help="源目录含 mapping.json：按其中的 name->source 映射装配")
    parser.add_argument("--mapping", type=Path,
                        help="--snapshot 使用的映射文件（默认 <source>/mapping.json）")
    parser.add_argument("--list", action="store_true", help="只打印映射，不写文件")
    parser.add_argument("--strict", action="store_true", help="有缺失/哈希不符时返回非零")
    args = parser.parse_args(argv)

    if args.snapshot:
        # 按角色分散的快照：mapping.json 记录 运行时文件名 -> 源相对路径。
        mapping_path = args.mapping or (args.source / "mapping.json")
        manifest = json.loads(mapping_path.read_text(encoding="utf-8"))
        mapping = [
            {"source": item["source"], "name": item["name"],
             "role": "snapshot", "verified": True}
            for item in manifest["entries"]
        ]
    elif args.flat:
        # 完整快照：源文件名即运行时文件名，边车也已经在快照里。
        mapping = [
            {"source": path.name, "name": path.name, "role": "flat", "verified": True}
            for path in sorted(args.source.iterdir())
            if path.is_file() and path.name != "manifest.json"
        ]
    else:
        mapping = DEFAULT_MAP + load_name_map(args.name_map)
    # 后出现的条目覆盖前面的同名 source
    merged: dict[str, dict] = {}
    for item in mapping:
        key = item["source"] if item.get("source") else "sidecar:" + item["name"]
        merged[key] = item
    mapping = list(merged.values())
    # 同一个运行时文件名只保留第一条，避免重复写/重复复制边车
    deduped, seen_names = [], set()
    for item in mapping:
        if item["name"] in seen_names:
            print(f"跳过重复输出 {item['source']} -> {item['name']}")
            continue
        seen_names.add(item["name"])
        deduped.append(item)
    mapping = deduped

    if args.list:
        print(f"源目录: {args.source}")
        print(f"{'源文件':<24}{'运行时文件名':<36}{'角色':<16}状态")
        for item in mapping:
            if not item.get("source"):
                print(f"{'(待自签)':<24}{item['name']:<36}{item.get('role', ''):<16}跳过")
                continue
            src = args.source / item["source"]
            _, body, status = split_source(src)
            exists = "存在" if src.is_file() else "缺失"
            print(f"{item['source']:<24}{item['name']:<36}{item.get('role', ''):<16}"
                  f"{exists}/{status}")
        print(f"\n无法从当前源快照映射的运行时条目: {len(UNMAPPED_RUNTIME)} 个")
        for name in UNMAPPED_RUNTIME:
            print("  " + name)
        return 0

    args.out.mkdir(parents=True, exist_ok=True)
    manifest = []
    missing = []
    for item in mapping:
        if not item.get("source"):
            print(f"跳过待自签边车 {item['name']}")
            continue
        src = args.source / item["source"]
        prefix, body, status = split_source(src)
        if status != "ok":
            missing.append((item["source"], status))
            print(f"跳过 {item['source']}: {status}")
            continue
        target = args.out / item["name"]
        target.write_bytes(body)
        digest = hashlib.sha256(body).hexdigest()
        manifest.append(
            {
                "source": item["source"],
                "name": item["name"],
                "role": item.get("role", ""),
                "verified": item.get("verified", False),
                "bytes": len(body),
                "sha256": digest,
                "header_sha256": prefix.hex(),
            }
        )
        print(f"{item['source']:<24} -> {item['name']:<36} {len(body):>8} B")

    sidecar_count = 0
    if args.role_sidecars:
        for folder, suffix in (("cfg", "_c"), ("sig", "_s")):
            directory = args.source / folder
            if not directory.is_dir():
                continue
            for source in sorted(directory.iterdir()):
                if not source.is_file():
                    continue
                runtime = SIDECAR_RUNTIME.get(source.name)
                if runtime is None:
                    print(f"跳过未知边车角色 {source}")
                    continue
                target = args.out / (runtime + suffix)
                target.write_bytes(source.read_bytes())
                sidecar_count += 1
                print(f"边车 {source.relative_to(args.source)} -> {target.name}")
    if args.sidecars:
        for item in manifest:
            for suffix in ("_c", "_s", "_backup_c", "_backup_s"):
                source = args.sidecars / (item["name"] + suffix)
                if source.is_file():
                    target = args.out / (item["name"] + suffix)
                    target.write_bytes(source.read_bytes())
                    sidecar_count += 1
                    print(f"边车 {source.name} -> {target.name}")

    (args.out / "manifest.json").write_text(
        json.dumps(
            {
                "source": args.source.as_posix(),
                "files": manifest,
                "sidecars": sidecar_count,
                "unmapped_runtime": UNMAPPED_RUNTIME,
                "missing": [{"source": source, "status": status} for source, status in missing],
                "notes": [
                    "源文件 -> body：校验并去掉前 32 字节 SHA-256",
                    "运行时文件名是服务端内容 ID，不是 body 的常见哈希",
                    "_s 是 RSA-SHA1 签名（覆盖 body），无私钥无法为新 body 生成；"
                    "运行时由 SignatureVerifyBypass 跳过验签",
                    "真机对照：错误 _c/_s 不影响加载；阻塞点是源 body 快照与当前壳不匹配",
                ],
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    print(f"\n输出 {len(manifest)} 个主体 + {sidecar_count} 个边车 -> {args.out}")
    print(f"清单: {args.out / 'manifest.json'}")
    print(f"未映射运行时条目 {len(UNMAPPED_RUNTIME)} 个（见清单）")
    if missing:
        print(f"源文件问题 {len(missing)} 个: {missing[:5]}")
        if args.strict:
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
