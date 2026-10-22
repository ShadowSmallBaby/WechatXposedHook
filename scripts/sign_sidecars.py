#!/usr/bin/env python3
"""用项目 RSA 私钥重签功能包 `_s`。

签名对象：去掉 32B SHA-256 前缀后的 runtime body（与原版 `_s` 一致）。
私钥只从环境变量或仓库根目录 `.env` 读取：
    WXH_SELF_SIGN_KEY_BASE64   私钥 PEM 的 Base64（必填）

生成后覆盖 `xmetadata/wx7/cfg/<role>.s`；`_c` 仍保留厂商原样。
"""

from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key

ROOT = Path(__file__).resolve().parents[1]
CFG = ROOT / "xmetadata" / "wx7" / "cfg"

# C/L 的验签在宿主里有复用/累积行为，先用厂商签名；
# 其余功能包用项目私钥重签。
BODIES = {
    "base": "r/fp/base",
    "donation": "r/fp/donation",
    "themes": "r/fp/themes",
    "vidurlparser": "r/fp/vidurlparser",
}


def read_env() -> str:
    value = os.environ.get("WXH_SELF_SIGN_KEY_BASE64")
    if value:
        return value.strip()
    env = ROOT / ".env"
    if env.is_file():
        for line in env.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.startswith("WXH_SELF_SIGN_KEY_BASE64="):
                return line.split("=", 1)[1].strip()
    raise SystemExit("缺少 WXH_SELF_SIGN_KEY_BASE64（环境变量或 .env）")


def main() -> int:
    key = load_pem_private_key(base64.b64decode(read_env()), password=None)
    for role, relative in BODIES.items():
        raw = (ROOT / "xmetadata" / "wx7" / relative).read_bytes()
        if len(raw) < 33:
            raise SystemExit(f"{relative}: 源文件过短")
        body = raw[32:]
        if hashlib.sha256(body).digest() != raw[:32]:
            raise SystemExit(f"{relative}: 前 32 字节不是 body 的 SHA-256")
        signature = key.sign(body, padding.PKCS1v15(), hashes.SHA1())
        key.public_key().verify(signature, body, padding.PKCS1v15(), hashes.SHA1())
        if len(signature) != 256:
            raise SystemExit(f"{role}: 签名长度 {len(signature)} != 256")
        target = CFG / (role + ".s")
        target.write_bytes(signature)
        print(f"{target}: {len(body)} B body, 256 B signature")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
