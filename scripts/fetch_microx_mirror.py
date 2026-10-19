#!/usr/bin/env python3
"""从微X的 GitHub 备用镜像拉取在线资源清单（默认只列清单，不下载）。

microX 2.44 的主更新域名已经下线：

    http://v.weixiaov.club/wx6/php/init_check.php   -> HTTP 530 "Domain Not Configured"
    http://dl.weixiaov.club/wx/wx6/                 -> HTTP 530 "Domain Not Configured"
    http://www.wxp2022.vip/...                      -> 连接被重置
    http://v.weixiaov.wang/...                      -> 连接被重置

但源码里的 GitHub 镜像仍然存活：

    https://raw.githubusercontent.com/fkzhang/WechatUnrecalled/master/xmetadata/wx6/

目录结构（实测）：

    r/C                   CoreDex 加密体
    r/L, L64, L_x86*      各架构 loader（ELF）
    r/A_p, A_xv           APK / xv 资源
    r/digest              版本/哈希清单（同样是加密体）
    r/fp/base             BaseDex 加密体
    r/fp/donation         DonationDex 加密体
    r/fp/themes           ThemesDex 加密体
    r/fp/sf, af, mf, xv, vidurlparser   其余功能资源
    r/pl/pl_transcoder    转码器
    r/xm/wxany, wxtools   Xposed 小工具
    pr/P_*                不同微信版本对应的参数文件
    rt/fp/*               另一套（rt）功能包

注意：这些文件是加密态，客户端靠 native 层 + 版本/签名校验解密；本脚本只负责
按原样下载与校验，不做解密。

用法:
    python scripts/fetch_microx_mirror.py                    # 列 r/ 清单
    python scripts/fetch_microx_mirror.py --root rt          # 列 rt/ 清单
    python scripts/fetch_microx_mirror.py --download         # 下载 r/ 到 build/microx_mirror
    python scripts/fetch_microx_mirror.py --download --only fp/   # 只下 r/fp/
    python scripts/fetch_microx_mirror.py --include-pr --download  # 连 pr/ 一起

只依赖标准库。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

API = "https://api.github.com/repos/fkzhang/WechatUnrecalled/contents/"
RAW = "https://raw.githubusercontent.com/fkzhang/WechatUnrecalled/master/"
DEFAULT_BRANCH = "master"
HEADERS = {"User-Agent": "microx-mirror-tool"}


def api_get(path: str, timeout: float):
    url = API + urllib.parse.quote(path)
    request = urllib.request.Request(url, headers=HEADERS)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8", "replace"))
    except Exception:
        # 本机 urllib 偶尔会在 GitHub 上超时，API 也退到 curl
        curl = shutil.which("curl")
        if not curl:
            raise
        result = subprocess.run(
            [curl, "-fsSL", "--retry", "2", "-m", str(max(30, int(timeout * 2))),
             "-A", HEADERS["User-Agent"], url],
            capture_output=True,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.decode("utf-8", "replace")[:300])
        return json.loads(result.stdout.decode("utf-8", "replace"))


def download_file(url: str, target: Path, timeout: float) -> bytes:
    """优先用 curl 下载：本机 urllib 访问 raw.githubusercontent 会超时。"""
    curl = shutil.which("curl")
    if curl:
        target.parent.mkdir(parents=True, exist_ok=True)
        result = subprocess.run(
            [curl, "-fsSL", "--retry", "3", "--connect-timeout", "15",
             "-m", str(max(120, int(timeout * 8))),
             "-A", HEADERS["User-Agent"], "-o", str(target), url],
            capture_output=True,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.decode("utf-8", "replace")[:300])
        return target.read_bytes()
    request = urllib.request.Request(url, headers=HEADERS)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = response.read()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(payload)
    return payload


def walk(root: str, timeout: float, include_pr: bool) -> list[dict]:
    pending = [root]
    files = []
    while pending:
        path = pending.pop()
        if path.startswith("xmetadata/wx6/pr") and not include_pr:
            continue
        try:
            entries = api_get(path, timeout)
        except urllib.error.HTTPError as error:
            if error.code == 404:
                continue
            raise
        if isinstance(entries, dict):  # 单文件
            entries = [entries]
        for entry in entries:
            if entry["type"] == "dir":
                pending.append(entry["path"])
            else:
                files.append(
                    {
                        "path": entry["path"],
                        "name": entry["name"],
                        "size": entry.get("size"),
                        "download_url": entry.get("download_url")
                        or RAW + entry["path"],
                    }
                )
    return sorted(files, key=lambda item: item["path"])


def main(argv=None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(description="拉取微X GitHub 镜像的在线资源清单")
    parser.add_argument("--root", default="r", choices=["r", "rt", "pr", "all"])
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("--download", action="store_true", help="真正下载文件")
    parser.add_argument("--only", help="只下载路径包含该子串的文件，例如 fp/")
    parser.add_argument("--out", type=Path, default=Path("build/microx_mirror"))
    parser.add_argument("--include-pr", action="store_true", help="pr/ 下参数文件很多，默认跳过")
    args = parser.parse_args(argv)

    roots = ["r", "rt", "pr"] if args.root == "all" else [args.root]
    files: list[dict] = []
    for root in roots:
        base = f"xmetadata/wx6/{root}"
        print(f"列出 {base} ...")
        files.extend(walk(base, args.timeout, args.include_pr))
        print(f"  {len(files)} 个文件（累计）")

    print(f"\n共 {len(files)} 个文件：")
    for item in files:
        print(f"  {item['size'] or 0:>10}  {item['path']}")

    if not args.download:
        print("\n这是 list-only；加 --download 才会真正下载。")
        return 0

    selected = [
        item for item in files if not args.only or args.only in item["path"]
    ]
    args.out.mkdir(parents=True, exist_ok=True)
    manifest = []
    for index, item in enumerate(selected, 1):
        relative = item["path"].split("xmetadata/wx6/", 1)[-1]
        target = args.out / relative
        try:
            payload = download_file(item["download_url"], target, args.timeout)
        except Exception as error:  # noqa: BLE001
            print(f"[{index}/{len(selected)}] 失败 {item['path']}: {error}", flush=True)
            continue
        digest = hashlib.sha256(payload).hexdigest()
        manifest.append(
            {
                "path": relative,
                "bytes": len(payload),
                "declared_size": item["size"],
                "sha256": digest,
                "source": item["download_url"],
            }
        )
        print(f"[{index}/{len(selected)}] {relative}  {len(payload)} B  {digest[:16]}")

    (args.out / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"\n完成 {len(manifest)}/{len(selected)}，清单: {args.out / 'manifest.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
