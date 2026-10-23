#!/usr/bin/env python3
"""生成并校验 WeXposedHook 离线授权码（Ed25519，大写十六进制）。

用法:
    1) 图形界面（推荐）：直接运行本脚本，或用打包好的 exe
       窗口分「签发」「校验」两页
    2) 命令行签发：
        python -X utf8 scripts/make_activation.py \
            --mid XXXX-XXXX-XXXX-XXXX --wxid wxid_xxx \
            [--features all|sf,mf,af] [--days 365] [--out activation.dat]
    3) 命令行校验：
        python -X utf8 scripts/make_activation.py --verify CODE \
            --mid XXXX-XXXX-XXXX-XXXX --wxid wxid_xxx
        python -X utf8 scripts/make_activation.py --verify-file activation.dat \
            --mid XXXX-XXXX-XXXX-XXXX --wxid wxid_xxx

私钥只从 WXH_ACTIVATION_ED25519_KEY_BASE64 / .env 读取（仅签发需要）。
码 = hex(payload 8B + Ed25519 签名 64B)，固定 144 个字符。
校验只用客户端内置公钥，与 activation.c 完全一致。
每次签发追加一行到 data/activation_log.csv（不进版本库）。
"""
from __future__ import annotations

import argparse
import base64
import csv
import json
import os
import re
import struct
import sys
import time
from datetime import datetime
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

def _app_root() -> Path:
    """打包成 exe 后 __file__ 指向临时解包目录，要改用 exe 自己所在目录。"""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[1]


ROOT = _app_root()
FEATURE_BITS = {"sf": 0x02, "mf": 0x04, "af": 0x08}
FEATURE_NAMES = ((0x02, "sf"), (0x04, "mf"), (0x08, "af"))
FEATURE_CHOICES = ["all", "sf,mf,af", "sf,mf", "sf,af", "mf,af", "sf", "mf", "af"]
LOG_PATH = ROOT / "data" / "activation_log.csv"
LOG_FIELDS = ["issued_at", "mid", "wxid", "features", "days", "not_after", "code_prefix"]
MID_PATTERN = re.compile(r"^[A-Z2-7]{4}(?:-[A-Z2-7]{4}){3}$")
PAYLOAD_BYTES = 8
SIGNATURE_BYTES = 64

# 与 app/src/main/jni/activation.c 的 ED25519_PUBLIC_KEY 保持一致；
# 校验走这份公钥，才能证明码在真机上确实能过。
CLIENT_PUBLIC_KEY = bytes([
    0xa3, 0x77, 0x98, 0x15, 0x63, 0xdf, 0xfc, 0x18,
    0x61, 0xdb, 0xd4, 0xac, 0x65, 0x74, 0x0f, 0x1d,
    0x32, 0x08, 0x74, 0x89, 0x85, 0x1e, 0x2c, 0xc2,
    0xb1, 0xb3, 0xd5, 0x04, 0x0a, 0x06, 0x12, 0xa2,
])


def env_candidates() -> list[Path]:
    """私钥文件位置：项目里是仓库根，exe 里是 exe 目录及其上最多 3 层父目录。"""
    candidates = [ROOT / ".env"]
    if getattr(sys, "frozen", False):
        parent = ROOT
        for _ in range(3):
            parent = parent.parent
            candidates.append(parent / ".env")
    return candidates


def private_key() -> Ed25519PrivateKey:
    value = os.environ.get("WXH_ACTIVATION_ED25519_KEY_BASE64")
    if not value:
        for env in env_candidates():
            if not env.is_file():
                continue
            for line in env.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line.startswith("WXH_ACTIVATION_ED25519_KEY_BASE64="):
                    value = line.split("=", 1)[1].strip()
                    break
            if value:
                break
    if not value:
        raise SystemExit("缺少 WXH_ACTIVATION_ED25519_KEY_BASE64（环境变量或 .env）")
    raw = base64.b64decode(value)
    if len(raw) != 32:
        raise SystemExit("Ed25519 私钥必须是 32 字节")
    return Ed25519PrivateKey.from_private_bytes(raw)


def feature_mask(text: str) -> int:
    """all -> 0x0f；其余为 0x01 | 勾选的功能位。未知功能名直接报错。"""
    value = text.strip().lower()
    if value == "all":
        return 0x0f
    mask = 0x01
    for item in value.split(","):
        name = item.strip()
        if not name:
            continue
        if name not in FEATURE_BITS:
            raise ValueError("未知功能 %r（只支持 sf/mf/af/all）" % name)
        mask |= FEATURE_BITS[name]
    return mask


def feature_text(mask: int) -> str:
    """功能位 -> sf,mf,af 这种可读文本。"""
    names = [name for bit, name in FEATURE_NAMES if mask & bit]
    text = ",".join(names) if names else "无扩展"
    if not mask & 0x01:
        text += "（缺基础位）"
    return text


def format_time(timestamp: int) -> str:
    return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M")


def warn_mid(mid: str) -> str:
    """机器码是 16 位 Base32，分成 4 组。返回给界面看的提示，空串表示正常。"""
    if not MID_PATTERN.match(mid):
        return "⚠ 机器码格式不标准（应为 XXXX-XXXX-XXXX-XXXX）"
    return ""


def warn_wxid(wxid: str) -> str:
    if not wxid.startswith("wxid_"):
        return "⚠ wxid 通常以 wxid_ 开头，请确认没有填错"
    return ""


def extract_code(text: str) -> str:
    """从 activation.dat（JSON 或纯文本）里取出授权码。"""
    text = text.strip()
    if not text.startswith("{"):
        return text
    try:
        return str(json.loads(text).get("code", ""))
    except ValueError:
        return ""


def verify(code: str, mid: str, wxid: str, now: int | None = None) -> dict:
    """按客户端同样的规则校验授权码，返回结果字典。

    只用 CLIENT_PUBLIC_KEY，所以没有私钥也能校验；校验通过即代表
    真机 native 侧也能通过。
    """
    result = {"ok": False, "reason": "", "features": "", "not_after": 0,
              "level": 0, "notes": []}
    text = "".join((code or "").split()).upper()
    if not text:
        result["reason"] = "授权码为空"
        return result
    mid = mid.strip().upper()
    wxid = wxid.strip()
    if not mid or not wxid:
        result["reason"] = "校验需要同时提供机器码和 wxid"
        return result
    try:
        mid_bytes = mid.encode("ascii")
    except UnicodeEncodeError:
        result["reason"] = "机器码只能包含 ASCII 字符"
        return result
    try:
        raw = bytes.fromhex(text)
    except ValueError:
        result["reason"] = "不是合法的十六进制串"
        return result
    if len(raw) != PAYLOAD_BYTES + SIGNATURE_BYTES:
        result["reason"] = "长度不对：应为 144 个十六进制字符（当前 %d）" % len(text)
        return result
    payload = raw[:PAYLOAD_BYTES]
    signature = raw[PAYLOAD_BYTES:]
    message = (b"WXH1|" + mid_bytes + b"|" + wxid.encode("utf-8")
               + b"|" + payload)
    try:
        Ed25519PublicKey.from_public_bytes(CLIENT_PUBLIC_KEY).verify(
            signature, message)
    except InvalidSignature:
        result["reason"] = "签名不匹配：码被改过，或机器码/wxid 与签发时不一致"
        return result

    version = payload[0]
    mask = payload[1]
    not_after = struct.unpack(">I", payload[2:6])[0]
    if version != 1:
        result["notes"].append("版本字节为 %d（预期 1）" % version)
    result["features"] = feature_text(mask)
    result["not_after"] = not_after
    result["level"] = 2 if mask & 0x0e else 1
    if not_after and (now if now is not None else int(time.time())) > not_after:
        result["reason"] = "已过期（%s）" % format_time(not_after)
        return result
    result["ok"] = True
    return result


def log_issue(mid: str, wxid: str, features: str, days: int,
              not_after: int, code: str) -> str:
    """追加一条签发记录；失败只返回错误描述，不影响已经生成的码。"""
    row = [
        datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
        mid,
        wxid,
        features,
        str(days),
        datetime.fromtimestamp(not_after).strftime("%Y-%m-%dT%H:%M:%S")
        if not_after else "",
        code[:16],
    ]
    try:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        new_file = not LOG_PATH.exists()
        with LOG_PATH.open("a", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            if new_file:
                writer.writerow(LOG_FIELDS)
            writer.writerow(row)
    except OSError as error:
        return "签发记录写入失败：%s" % error
    return ""


def issue(mid: str, wxid: str, features: str, days: int) -> tuple[str, int]:
    """按参数签发一个授权码，返回 (码, not_after 时间戳)。"""
    mid = mid.strip().upper()
    wxid = wxid.strip()
    if not mid:
        raise ValueError("机器码不能为空")
    if not wxid:
        raise ValueError("wxid 不能为空")
    if days < 0:
        raise ValueError("有效天数不能为负数")
    mask = feature_mask(features)
    try:
        mid_bytes = mid.encode("ascii")
    except UnicodeEncodeError:
        raise ValueError("机器码只能包含 ASCII 字符")
    not_after = int(time.time()) + days * 86400 if days > 0 else 0
    payload = bytes([1, mask]) + struct.pack(">I", not_after) + b"\0\0"
    message = b"WXH1|" + mid_bytes + b"|" + wxid.encode("utf-8") + b"|" + payload
    signature = private_key().sign(message)
    if len(signature) != 64:
        raise SystemExit("Ed25519 签名长度异常")
    code = (payload + signature).hex().upper()
    error = log_issue(mid, wxid, features, days, not_after, code)
    if error:
        print(error, file=sys.stderr)
    return code, not_after


def run_cli(args: argparse.Namespace) -> int:
    try:
        code, _ = issue(args.mid, args.wxid, args.features, args.days)
    except ValueError as error:
        raise SystemExit("参数有误：%s" % error)
    if args.out is not None:
        args.out.write_text(code + "\n", encoding="ascii")
        print("activation -> %s (%d chars)" % (args.out, len(code)))
    else:
        print(code)
    return 0


def run_verify(code: str, mid: str, wxid: str) -> int:
    result = verify(code, mid, wxid)
    if not result["ok"]:
        print("授权码无效：%s" % result["reason"], file=sys.stderr)
        for note in result["notes"]:
            print("  注意：%s" % note, file=sys.stderr)
        return 1
    expiry = format_time(result["not_after"]) if result["not_after"] else "永久"
    print("授权码有效")
    print("  功能：%s" % result["features"])
    print("  有效期：%s" % expiry)
    for note in result["notes"]:
        print("  注意：%s" % note)
    return 0


def attach_console() -> None:
    """exe 按无控制台打包；带参数运行时把 stdout/stderr 找回来。

    1. 父进程重定向了输出（管道/文件）：fd 1/2 仍然有效，按 UTF-8 接管；
    2. 从终端直接运行：没有 std 流，AttachConsole 后写 CONOUT$。控制台临时切到
       UTF-8 代码页，退出时恢复，否则中文按 cp936 编码会乱码；
    3. 双击（无参数）：不会走到这里。
    """
    if not getattr(sys, "frozen", False) or sys.platform != "win32":
        return
    if sys.stdout is not None and sys.stderr is not None:
        # 有 std 流说明输出被 bash/管道/重定向接管了，默认编码是本地代码页，
        # 改成 UTF-8 才能和调用方一致（cmd.exe 直跑没有 std 流，走下面的分支）。
        for name in ("stdout", "stderr"):
            stream = getattr(sys, name)
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass
        return
    for index, name in ((1, "stdout"), (2, "stderr")):
        if getattr(sys, name) is not None:
            continue
        try:
            stream = os.fdopen(index, "w", encoding="utf-8", errors="replace",
                               buffering=1)
            stream.write("")
        except OSError:
            continue
        setattr(sys, name, stream)
    if sys.stdout is not None and sys.stderr is not None:
        return
    try:
        import atexit
        import ctypes
        if not ctypes.windll.kernel32.AttachConsole(-1):
            return
        kernel32 = ctypes.windll.kernel32
        original = kernel32.GetConsoleOutputCP()
        if original and original != 65001:
            kernel32.SetConsoleOutputCP(65001)
            atexit.register(kernel32.SetConsoleOutputCP, original)
        if sys.stdout is None:
            sys.stdout = open("CONOUT$", "w", encoding="utf-8",
                              errors="replace", buffering=1)
        if sys.stderr is None:
            sys.stderr = open("CONOUT$", "w", encoding="utf-8",
                              errors="replace", buffering=1)
    except Exception:
        pass


def run_gui() -> int:
    try:
        import tkinter as tk
        from tkinter import messagebox, ttk
    except ImportError:
        print("当前 Python 没有 tkinter，请改用命令行参数。", file=sys.stderr)
        return 2

    font = ("Microsoft YaHei UI", 10) if sys.platform == "win32" else None

    root = tk.Tk()
    root.title("WeXposedHook 授权码")
    root.minsize(560, 460)
    if font:
        ttk.Style(root).configure(".", font=font)

    mid_var = tk.StringVar()
    wxid_var = tk.StringVar()
    feature_var = tk.StringVar(value="all")
    days_var = tk.StringVar(value="0")

    frame = ttk.Frame(root, padding=12)
    frame.grid(row=0, column=0, sticky="nsew")
    root.columnconfigure(0, weight=1)
    root.rowconfigure(0, weight=1)
    frame.columnconfigure(1, weight=1)

    ttk.Label(frame, text="机器码").grid(row=0, column=0, sticky="w", pady=4)
    mid_entry = ttk.Entry(frame, textvariable=mid_var)
    mid_entry.grid(row=0, column=1, sticky="ew", padx=(8, 0), pady=4)

    ttk.Label(frame, text="绑定 wxid").grid(row=1, column=0, sticky="w", pady=4)
    ttk.Entry(frame, textvariable=wxid_var).grid(
        row=1, column=1, sticky="ew", padx=(8, 0), pady=4)

    notebook = ttk.Notebook(frame)
    notebook.grid(row=2, column=0, columnspan=2, sticky="nsew", pady=(10, 0))
    frame.rowconfigure(2, weight=1)

    # ---- 签发页 ----
    issue_tab = ttk.Frame(notebook, padding=10)
    notebook.add(issue_tab, text="签发")
    issue_tab.columnconfigure(1, weight=1)
    issue_tab.rowconfigure(4, weight=1)

    ttk.Label(issue_tab, text="功能").grid(row=0, column=0, sticky="w", pady=4)
    ttk.Combobox(issue_tab, textvariable=feature_var, values=FEATURE_CHOICES,
                 state="readonly").grid(row=0, column=1, sticky="ew",
                                        padx=(8, 0), pady=4)

    ttk.Label(issue_tab, text="有效天数").grid(row=1, column=0, sticky="w", pady=4)
    days_row = ttk.Frame(issue_tab)
    days_row.grid(row=1, column=1, sticky="ew", padx=(8, 0), pady=4)
    ttk.Entry(days_row, textvariable=days_var, width=10).grid(row=0, column=0)
    ttk.Label(days_row, text="0 = 永久").grid(row=0, column=1, padx=(8, 0))

    issue_buttons = ttk.Frame(issue_tab)
    issue_buttons.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(8, 6))
    generate_button = ttk.Button(issue_buttons, text="生成授权码")
    generate_button.grid(row=0, column=0)
    copy_button = ttk.Button(issue_buttons, text="复制", state="disabled")
    copy_button.grid(row=0, column=1, padx=(8, 0))

    issue_result = tk.Text(issue_tab, height=4, wrap="char",
                           relief="solid", borderwidth=1)
    if font:
        issue_result.configure(font=font)
    issue_result.grid(row=4, column=0, columnspan=2, sticky="nsew")

    issue_status = ttk.Label(issue_tab, text="", wraplength=500, justify="left")
    issue_status.grid(row=5, column=0, columnspan=2, sticky="w", pady=(6, 0))

    # ---- 校验页 ----
    verify_tab = ttk.Frame(notebook, padding=10)
    notebook.add(verify_tab, text="校验")
    verify_tab.columnconfigure(0, weight=1)
    verify_tab.rowconfigure(1, weight=1)

    ttk.Label(verify_tab, text="粘贴授权码（可含换行，也可粘贴 activation.dat 内容）"
              ).grid(row=0, column=0, sticky="w")
    code_text = tk.Text(verify_tab, height=4, wrap="char",
                        relief="solid", borderwidth=1)
    if font:
        code_text.configure(font=font)
    code_text.grid(row=1, column=0, sticky="nsew", pady=(4, 8))

    verify_button = ttk.Button(verify_tab, text="校验授权码")
    verify_button.grid(row=2, column=0, sticky="w")
    verify_status = ttk.Label(verify_tab, text="", wraplength=500, justify="left")
    verify_status.grid(row=3, column=0, sticky="w", pady=(8, 0))

    def read_days() -> int:
        text = days_var.get().strip()
        if not text:
            return 0
        try:
            return int(text)
        except ValueError:
            raise ValueError("有效天数必须是整数")

    def fail(title: str, detail: str) -> None:
        # 失败时清空结果，避免旧码被误复制
        issue_result.delete("1.0", "end")
        copy_button.configure(state="disabled")
        issue_status.configure(text="")
        messagebox.showerror(title, detail, parent=root)

    def generate() -> None:
        try:
            code, not_after = issue(mid_var.get(), wxid_var.get(),
                                    feature_var.get(), read_days())
        except SystemExit as error:
            fail("签发失败", str(error))
            return
        except ValueError as error:
            fail("参数有误", str(error))
            return
        issue_result.delete("1.0", "end")
        issue_result.insert("1.0", code)
        copy_button.configure(state="normal")
        root.clipboard_clear()
        root.clipboard_append(code)
        notes = [n for n in (warn_mid(mid_var.get().strip().upper()),
                             warn_wxid(wxid_var.get().strip())) if n]
        expiry = "永久" if not not_after else format_time(not_after)
        line = "已复制到剪贴板（%d 字符，有效期 %s）" % (len(code), expiry)
        issue_status.configure(text="  ".join(notes + [line]), foreground="")

    def copy() -> None:
        code = issue_result.get("1.0", "end").strip()
        if not code:
            return
        root.clipboard_clear()
        root.clipboard_append(code)
        issue_status.configure(text="已复制到剪贴板（%d 字符）" % len(code))

    def check() -> None:
        result = verify(extract_code(code_text.get("1.0", "end")),
                        mid_var.get(), wxid_var.get())
        if result["ok"]:
            expiry = (format_time(result["not_after"])
                      if result["not_after"] else "永久")
            lines = ["✔ 授权码有效",
                     "功能：%s" % result["features"],
                     "有效期：%s" % expiry] + result["notes"]
            verify_status.configure(text="\n".join(lines), foreground="#1a7f37")
        else:
            lines = ["✘ %s" % result["reason"]] + result["notes"]
            verify_status.configure(text="\n".join(lines), foreground="#b42318")

    generate_button.configure(command=generate)
    copy_button.configure(command=copy)
    verify_button.configure(command=check)
    root.bind("<Return>", lambda _event: generate())
    mid_entry.focus_set()
    root.mainloop()
    return 0


def main() -> int:
    # 带任何参数都按命令行处理，先把输出挂回父控制台（--help 也走这里）
    if len(sys.argv) > 1:
        attach_console()
    parser = argparse.ArgumentParser(description="生成并校验 WeXposedHook Ed25519 授权码")
    parser.add_argument("--mid", help="客户端显示的机器码；与 --wxid 一起用时走命令行")
    parser.add_argument("--wxid", help="绑定的微信 wxid")
    parser.add_argument("--features", default="all",
                        help="all 或逗号分隔的 sf,mf,af")
    parser.add_argument("--days", type=int, default=0,
                        help="有效天数；0 表示永久")
    parser.add_argument("--out", type=Path, default=None,
                        help="输出文件；缺省打印到 stdout")
    parser.add_argument("--verify", metavar="CODE", default=None,
                        help="校验授权码，需要同时提供 --mid 与 --wxid")
    parser.add_argument("--verify-file", type=Path, default=None,
                        help="从文件（纯码或 activation.dat）读取后校验")
    args = parser.parse_args()

    if args.verify is not None or args.verify_file is not None:
        if args.verify is not None and args.verify_file is not None:
            parser.error("--verify 与 --verify-file 只能二选一")
        if not args.mid or not args.wxid:
            parser.error("校验需要同时提供 --mid 与 --wxid")
        code = args.verify
        if args.verify_file is not None:
            code = args.verify_file.read_text(encoding="utf-8")
        return run_verify(extract_code(code), args.mid, args.wxid)

    if args.mid and args.wxid:
        return run_cli(args)
    if args.mid or args.wxid:
        parser.error("--mid 与 --wxid 必须同时提供")
    return run_gui()


if __name__ == "__main__":
    raise SystemExit(main())
