#!/usr/bin/env python3
"""把 scripts/make_activation.py 打包成单文件 exe。

用法:
    python -X utf8 scripts/build_activation_exe.py [--name NAME] [--icon PNG]

产物: build/activation/<NAME>.exe

exe 是 **无控制台** 程序：
  - 双击            -> 直接弹出签发/校验窗口
  - 带参数运行      -> 自动挂回父控制台，CLI 输出正常（--verify 也可用）

私钥不打包进 exe。exe 会在自己所在目录（以及向上三层父目录）找 .env，或者读环境
变量 WXH_ACTIVATION_ED25519_KEY_BASE64，所以把它放在仓库根或放 .env 的目录旁边即可。
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "scripts" / "make_activation.py"
OUTPUT = ROOT / "build" / "activation"
WORK = ROOT / "build" / "pyinstaller"
DEFAULT_NAME = "WeXposedActivation"
DEFAULT_ICON = ROOT / "data" / "wxhook_icon.png"


def make_icon(png: Path, target: Path) -> Path | None:
    """PNG -> ICO；没有 Pillow 就跳过图标。"""
    if not png.is_file():
        print("图标源不存在，跳过：%s" % png)
        return None
    try:
        from PIL import Image
    except ImportError:
        print("没装 Pillow，exe 用默认图标（pip install pillow 可生成）")
        return None
    image = Image.open(png).convert("RGBA")
    image.save(target, sizes=[(16, 16), (32, 32), (48, 48), (64, 64),
                              (128, 128), (256, 256)])
    return target


def main() -> int:
    parser = argparse.ArgumentParser(description="打包授权码签发工具为 exe")
    parser.add_argument("--name", default=DEFAULT_NAME, help="exe 文件名（不含扩展名）")
    parser.add_argument("--icon", type=Path, default=DEFAULT_ICON, help="PNG 图标")
    parser.add_argument("--no-icon", action="store_true", help="不设图标")
    args = parser.parse_args()

    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        print("缺少 PyInstaller，先安装：", file=sys.stderr)
        print("  python -m pip install pyinstaller cryptography", file=sys.stderr)
        return 2

    OUTPUT.mkdir(parents=True, exist_ok=True)
    WORK.mkdir(parents=True, exist_ok=True)
    command = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--clean", "--onefile", "--windowed",
        "--name", args.name,
        "--distpath", str(OUTPUT),
        "--workpath", str(WORK),
        "--specpath", str(WORK),
        "--paths", str(SOURCE.parent),
    ]
    if not args.no_icon:
        icon = make_icon(args.icon, WORK / "icon.ico")
        if icon is not None:
            command += ["--icon", str(icon)]
    command.append(str(SOURCE))

    print("$ " + " ".join(command))
    result = subprocess.run(command)
    if result.returncode != 0:
        return result.returncode

    exe = OUTPUT / (args.name + ".exe")
    if not exe.is_file():
        print("打包结束但没找到 %s" % exe, file=sys.stderr)
        return 1
    print("\n产物: %s (%.1f MB)" % (exe, exe.stat().st_size / 1024 / 1024))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
