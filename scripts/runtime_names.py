#!/usr/bin/env python3
"""运行文件名的确定性规则。

feature 包：
    runtime = trim(MD5("FP_<role>")) 或 trim(MD5("<role>"))
trim = 逐字节去掉 hex 前导 0。
core：trim(MD5("C"))。
少数模块资产/桥使用厂商固定 ID，不做推导。
"""

from __future__ import annotations

import hashlib


def trim_hex(text: str) -> str:
    return "".join(text[index:index + 2].lstrip("0") or "0"
                   for index in range(0, 32, 2))


def runtime(role: str, prefixed: bool = True) -> str:
    text = ("FP_" if prefixed else "") + role
    return trim_hex(hashlib.md5(text.encode("utf-8")).hexdigest())


def aliases(role: str) -> list[str]:
    return [runtime(role), runtime(role, prefixed=False)]


CORE = runtime("C", prefixed=False)

BRIDGE = "36a76b97b96b5d46742bb4bcd2ff24d"

UTILITY = {
    "D": "534a9729a0c461cbd7a4379978fb742",
    "H_p": "62a4e566b714ea1c4349923c9ea6c35",
    "M": "69691c7bdcc3ce6d5d8a1361f22d4ac",
    "S": "5dbc98dcc983a7728bd82d1a47546e",
    "Xmd": "739440c5d87b2b8095b99f9d2a1bbf9",
    "pr/P": "44c29edb103a2872f519adc9afdaaa",
    "pr/P_8049": "6d6586c9c5458ecfc98981b52ee662de",
    "LD64": "dc7be70f1898d3a58965a919740f97",
}

if __name__ == "__main__":
    for role in ("sf", "mf", "af", "base", "themes", "donation", "vidurlparser"):
        print(role, aliases(role))
    print("core", CORE)
