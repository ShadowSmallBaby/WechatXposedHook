#!/usr/bin/env python3
"""从原版 X 3.0 APK 抽取单 APK 构建真正需要的壳条目。

输出目录（默认 `app/x30/`）只保留：
    AndroidManifest.xml
    resources.arsc            （写回时必须 STORED）
    classes*.dex
    res/**                    （壳的界面资源）
    kotlin/**                 （Kotlin 反射 builtins）
    DebugProbesKt.bin
    assets/xposed_init
    assets/74fab57f…          （壳独有的 32 位 native loader）
    META-INF/services/**      （Kotlin/协程 ServiceLoader 描述）
    META-INF/*.RSA            （原版证书，运行时映射用）

其余 assets（c1d9/d2ca/d61f 等）要么由项目功能包提供，要么不使用。
"""

from __future__ import annotations

import argparse
import hashlib
import re
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

EXACT = {
    "AndroidManifest.xml",
    "resources.arsc",
    "DebugProbesKt.bin",
    "assets/xposed_init",
    "assets/74fab57f825f1328df3d731f4de24d5",
}
PREFIXES = ("res/", "kotlin/", "META-INF/services/")


def wanted(name: str) -> bool:
    if name in EXACT:
        return True
    if re.fullmatch(r"classes\d*\.dex", name):
        return True
    if name.startswith(PREFIXES):
        return True
    if name.upper().startswith("META-INF/") and name.upper().endswith(".RSA"):
        return True
    return False


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk", type=Path, default=ROOT / "data" / "refs" / "X_3.0.apk")
    parser.add_argument("--output", type=Path, default=ROOT / "app" / "x30.zip",
                        help="输出目录，或以 .zip 结尾时直接打成壳 zip")
    args = parser.parse_args(argv)
    if not args.apk.is_file():
        raise SystemExit(f"缺少壳 APK: {args.apk}")
    entries = []
    size = 0
    with zipfile.ZipFile(args.apk) as archive:
        for info in archive.infolist():
            if not wanted(info.filename):
                continue
            data = archive.read(info)
            entries.append((info.filename, data))
            size += len(data)
    digest = hashlib.sha256(args.apk.read_bytes()).hexdigest()
    newline = chr(10)
    source = ("source: " + args.apk.name + newline
              + "sha256: " + digest + newline
              + "entries: " + str(len(entries)) + newline
              + "bytes: " + str(size) + newline).encode("utf-8")
    if args.output.suffix.lower() == ".zip":
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(args.output, "w", allowZip64=True) as archive:
            for name, data in entries:
                info = zipfile.ZipInfo(name, date_time=(1981, 1, 1, 1, 1, 1))
                info.compress_type = (zipfile.ZIP_STORED
                                      if name == "resources.arsc"
                                      else zipfile.ZIP_DEFLATED)
                archive.writestr(info, data)
            info = zipfile.ZipInfo("SOURCE.txt", date_time=(1981, 1, 1, 1, 1, 1))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, source)
    else:
        args.output.mkdir(parents=True, exist_ok=True)
        for name, data in entries:
            target = args.output / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        (args.output / "SOURCE.txt").write_bytes(source)
    print(f"{args.output}: {len(entries)} entries, {size} B "
          f"(source sha256 {digest[:16]}…)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
