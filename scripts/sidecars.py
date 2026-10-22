#!/usr/bin/env python3
"""功能包 `_c` / `_s` 旁车读取。

两类边车都带厂商 RSA-SHA1 签名：

- `_s`（256B）签名覆盖 body（原版厂商签名，body 未修改）；
- `_c`（599B）内含 256B 签名块，覆盖容器载荷；native loader 会做 RSA
  公钥运算，改动载荷或签名会直接触发 SIGSEGV。

没有厂商私钥就无法重签，因此这里不做生成，只把仓库里的
`xmetadata/wx7/cfg/<role>.{c,s}` 原样交给打包脚本。
"""

from __future__ import annotations

from pathlib import Path


def read_sidecar(source: Path, role: str, suffix: str) -> bytes:
    path = source / "cfg" / (role + suffix)
    data = path.read_bytes()
    expected = 599 if suffix == ".c" else 256
    if len(data) != expected:
        raise ValueError(f"{path}: 应为 {expected} 字节，实际 {len(data)}")
    return data


def build_sidecars(source: Path, sidecars: dict[str, str]) -> dict[str, bytes]:
    """返回 {运行时名: 内容}，键为 `<runtime>_c` / `<runtime>_s`。"""
    result: dict[str, bytes] = {}
    for role, runtime_name in sidecars.items():
        result[runtime_name + "_c"] = read_sidecar(source, role, ".c")
        result[runtime_name + "_s"] = read_sidecar(source, role, ".s")
    return result
