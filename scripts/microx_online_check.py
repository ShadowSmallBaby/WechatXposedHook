#!/usr/bin/env python3
"""复刻微X「在线检查 / 功能包下载」的请求格式（默认只打印，不联网）。

静态分析结论（来自 microX 2.44 主 dex `Lx/ᵢـ/ـˉ;.ˆᴵ()` 与 `Lx/ʼˏ/ـﹶ;`）：

  检查接口（3 个，运行时打乱顺序）：
    http://v.weixiaov.club/wx6/php/init_check.php
    http://www.wxp2022.vip/wx6/php/init_check.php
    http://v.weixiaov.wang/wx6/php/init_check.php

  请求：POST，form 参数
    cmd=c
    args=<JSON>   字段含 wxid / time / avc / avn / apkVersionCode / apkVersionName /
                  wxVersionCode / wxVersionName / pn / arch / isARM64 / module_path /
                  sig / wxcrc / has_core / has_loader / has_lib / has_meta / has_strings /
                  has_param / has_xmd / xv 等

  下载基址（主 + 镜像，运行时打乱）：
    http://dl.weixiaov.club/wx/wx6/
    https://cdn.jsdelivr.net/gh/fkzhang/WechatUnrecalled@master/xmetadata/wx6/
    https://github.com/fkzhang/WechatUnrecalled/raw/master/xmetadata/wx6/
    http://v.weixiaov.club/wx6/

  下载 URL 拼接（`Lx/ʼˏ/ـﹶ;.ᵢٴ(Collection, String, String)`）：
    base + apkVersionName + "_t" + core
  其中 `core` 是服务端下发行里的文件指纹/名称。

注意：
  * 服务端可能按 wxid / 签名 / 版本做校验，返回内容未必对任意设备可用；
  * microX 在线下载的是「当前微信版本对应的 4 个 dex」及若干资源，不等于仓库里
    30 个文件的完整功能包，内容也可能不同（见 docs/reverse-engineering.md）；
  * 本脚本默认 dry-run，只有显式 --send 才发请求。

用法:
    python scripts/microx_online_check.py                 # 只打印请求
    python scripts/microx_online_check.py --send          # 真正请求并打印响应
    python scripts/microx_online_check.py --send --save build/online_check.json
    python scripts/microx_online_check.py --response build/online_check.json  # 从响应里找 URL

只依赖标准库。
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

CHECK_URLS = [
    "http://v.weixiaov.club/wx6/php/init_check.php",
    "http://www.wxp2022.vip/wx6/php/init_check.php",
    "http://v.weixiaov.wang/wx6/php/init_check.php",
]

DOWNLOAD_BASES = [
    "http://dl.weixiaov.club/wx/wx6/",
    "https://cdn.jsdelivr.net/gh/fkzhang/WechatUnrecalled@master/xmetadata/wx6/",
    "https://github.com/fkzhang/WechatUnrecalled/raw/master/xmetadata/wx6/",
    "http://v.weixiaov.club/wx6/",
]

URL_RE = re.compile(r"https?://[^\s\"'<>\\]+")


def build_args(
    wxid: str,
    apk_version_name: str,
    wx_version_code: str,
    wx_version_name: str,
    arch: str,
    module_path: str,
) -> dict:
    """按 `ˆᴵ()` 里的字段拼一份最小的 args。"""
    return {
        "wxid": wxid,
        "time": str(int(time.time() * 1000)),
        "acrc": "",
        "avc": "",
        "apkVersionCode": "",
        "avn": apk_version_name,
        "apkVersionName": apk_version_name,
        "wxVersionCode": wx_version_code,
        "wxVersionName": wx_version_name,
        "pn": "com.fkzhang.wechatxposed",
        "at": arch,
        "type": "",
        "isplay": "false",
        "isARM64": "true" if arch == "arm64" else "false",
        "module_path": module_path,
        "arch": arch,
        "fw": "xposed",
        "path": "",
        "sig": "",
        "wxcrc": "",
        "has_der": "false",
        "c.der": "",
        "has_lib": "true",
        "has_loader": "true",
        "has_core": "true",
        "C": "",
        "C_t": "",
        "has_hooks": "true",
        "H_": "",
        "xv": "",
        "p": "",
        "has_meta": "true",
        "M": "",
        "has_strings": "true",
        "S": "",
        "has_param": "true",
        "P": "",
        "has_xmd": "false",
        "xmd": "",
    }


def post_check(url: str, args: dict, timeout: float) -> tuple[int, str]:
    body = urllib.parse.urlencode(
        {"cmd": "c", "args": json.dumps(args, ensure_ascii=False, separators=(",", ":"))}
    ).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 16; 23127PN0CC Build/BP2A)",
        },
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.status, response.read().decode("utf-8", "replace")


def candidate_download_urls(text: str) -> list[str]:
    return sorted({url for url in URL_RE.findall(text) if "weixiaov" in url or "xmetadata" in url})


def main(argv=None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(description="复刻微X在线检查请求（默认 dry-run）")
    parser.add_argument("--send", action="store_true", help="真正发起 HTTP 请求")
    parser.add_argument("--endpoint", help="指定检查接口；缺省按顺序尝试 3 个")
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--save", type=Path, help="把响应写到文件")
    parser.add_argument("--response", type=Path, help="解析已保存的响应，列出候选下载 URL")
    parser.add_argument("--wxid", default="wxid_test")
    parser.add_argument("--apk-version-name", default="8.0.49")
    parser.add_argument("--wx-version-code", default="2600")
    parser.add_argument("--wx-version-name", default="8.0.49")
    parser.add_argument("--arch", default="arm64", choices=["arm64", "arm", "x86"])
    parser.add_argument("--module-path", default="/data/app/~~x/~~y/base.apk")
    args = parser.parse_args(argv)

    if args.response:
        if not args.response.is_file():
            raise SystemExit(f"文件不存在: {args.response}")
        text = args.response.read_text(encoding="utf-8", errors="replace")
        urls = candidate_download_urls(text)
        print(f"响应 {args.response}：{len(text)} 字符，候选 URL {len(urls)} 个")
        for url in urls:
            print("  " + url)
        if not urls:
            print("  没找到 weixiaov/xmetadata 链接，响应可能不是成功结果")
            print("  响应片段：" + text[:400].replace("\n", " "))
        return 0

    payload = build_args(
        args.wxid,
        args.apk_version_name,
        args.wx_version_code,
        args.wx_version_name,
        args.arch,
        args.module_path,
    )
    endpoints = [args.endpoint] if args.endpoint else CHECK_URLS

    print("检查接口：")
    for url in endpoints:
        print("  " + url)
    print("请求方法：POST")
    print("form: cmd=c")
    print("args=" + json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
    print("下载基址：")
    for base in DOWNLOAD_BASES:
        print("  " + base)
    print("拼接规则：base + apkVersionName + '_t' + core")

    if not args.send:
        print("\n这是 dry-run；加 --send 才会真正请求。")
        return 0

    last_error = None
    for url in endpoints:
        try:
            status, text = post_check(url, payload, args.timeout)
        except Exception as error:  # noqa: BLE001 - 命令行工具，直接报告
            last_error = error
            print(f"{url} 请求失败: {error}")
            continue
        print(f"\n{url} -> HTTP {status}, {len(text)} 字符")
        if args.save:
            args.save.parent.mkdir(parents=True, exist_ok=True)
            args.save.write_text(text, encoding="utf-8")
            print(f"已写入 {args.save}")
        urls = candidate_download_urls(text)
        if urls:
            print("候选下载 URL：")
            for item in urls:
                print("  " + item)
        else:
            print("响应片段：" + text[:600].replace("\n", " "))
        return 0

    if last_error is not None:
        print(f"全部接口失败，最后一个错误: {last_error}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
