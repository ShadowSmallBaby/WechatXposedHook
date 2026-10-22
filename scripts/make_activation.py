#!/usr/bin/env python3
"""生成 Ed25519 离线授权码（大写十六进制）。

用法:
    python -X utf8 scripts/make_activation.py \
        --mid XXXX-XXXX-XXXX-XXXX --wxid wxid_xxx \
        [--features all|sf,mf,af] [--days 365] [--out activation.dat]

私钥只从 WXH_ACTIVATION_ED25519_KEY_BASE64 / .env 读取。
码 = hex(payload 8B + Ed25519 签名 64B)，固定 144 个字符。
"""
from __future__ import annotations

import argparse
import base64
import os
import struct
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
FEATURE_BITS = {"sf": 0x02, "mf": 0x04, "af": 0x08}


def private_key() -> Ed25519PrivateKey:
    value = os.environ.get("WXH_ACTIVATION_ED25519_KEY_BASE64")
    if not value:
        env = ROOT / ".env"
        if env.is_file():
            for line in env.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line.startswith("WXH_ACTIVATION_ED25519_KEY_BASE64="):
                    value = line.split("=", 1)[1].strip()
                    break
    if not value:
        raise SystemExit("缺少 WXH_ACTIVATION_ED25519_KEY_BASE64（环境变量或 .env）")
    raw = base64.b64decode(value)
    if len(raw) != 32:
        raise SystemExit("Ed25519 私钥必须是 32 字节")
    return Ed25519PrivateKey.from_private_bytes(raw)


def main() -> int:
    parser = argparse.ArgumentParser(description="生成 WeXposedHook Ed25519 授权码")
    parser.add_argument("--mid", required=True, help="客户端显示的机器码")
    parser.add_argument("--wxid", required=True, help="绑定的微信 wxid")
    parser.add_argument("--features", default="all",
                        help="all 或逗号分隔的 sf,mf,af")
    parser.add_argument("--days", type=int, default=0,
                        help="有效天数；0 表示永久")
    parser.add_argument("--out", type=Path, default=None,
                        help="输出文件；缺省打印到 stdout")
    args = parser.parse_args()

    if args.features == "all":
        features = 0x0f
    else:
        features = 0x01
        for item in args.features.split(","):
            features |= FEATURE_BITS.get(item.strip(), 0)
    not_after = int(time.time()) + args.days * 86400 if args.days > 0 else 0
    payload = bytes([1, features]) + struct.pack(">I", not_after) + b"\0\0"
    message = (b"WXH1|" + args.mid.strip().upper().encode("ascii") + b"|"
               + args.wxid.strip().encode("utf-8") + b"|" + payload)
    signature = private_key().sign(message)
    if len(signature) != 64:
        raise SystemExit("Ed25519 签名长度异常")
    code = (payload + signature).hex().upper()
    if args.out is not None:
        args.out.write_text(code + "\n", encoding="ascii")
        print("activation -> %s (%d chars)" % (args.out, len(code)))
    else:
        print(code)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
