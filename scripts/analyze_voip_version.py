#!/usr/bin/env python3
"""Scan WeChat dex for the client-version transmission chain.

Usage:
    python scripts/analyze_voip_version.py <dex-dir>
"""
import os
import sys

from androguard.core.dex import DEX

try:
    from loguru import logger
    logger.remove()
except Exception:
    pass


ILINK = "Lcom/tencent/ilink/network/Proto$IlinkStartConfig$Builder;"
VERSION_FIELD = "Lc64/xe;->g:I"
VOIP_PREFIX = "Lcom/tencent/mm/plugin/voip/"


def describe_method(m):
    return "{}->{}{}".format(m.get_class_name(), m.get_name(), m.get_descriptor())


def scan(path, out):
    dex = DEX(open(path, "rb").read())
    name = os.path.basename(path)
    hits = []

    for cls in dex.get_classes():
        cname = cls.get_name()
        if cname in (ILINK, "Lc64/xe;"):
            out.write("== class {} in {}\n".format(cname, name))
            for m in cls.get_methods():
                out.write("   {}{}\n".format(m.get_name(), m.get_descriptor()))
                for ins in m.get_instructions() or ():
                    out.write("      {} | {}\n".format(
                        ins.get_name(), ins.get_output()))
            out.write("\n")

        for m in cls.get_methods():
            if not m.get_instructions():
                continue
            refs = []
            for ins in m.get_instructions():
                op = ins.get_name()
                if not (op.startswith("invoke") or op.startswith("sget")
                        or op.startswith("sput")):
                    continue
                try:
                    text = ins.get_output()
                except Exception:
                    continue
                if ("setAppVersion" in text or "IlinkStartConfig" in text
                        or VERSION_FIELD in text or "Lc64/xe;" in text):
                    refs.append("{} | {}".format(op, text))
            if refs:
                tag = "VOIP" if cname.startswith(VOIP_PREFIX) else "    "
                hits.append((tag, describe_method(m), refs))

    out.write("== references in {} ({})\n".format(name, len(hits)))
    for tag, method, refs in hits:
        out.write("[{}] {}\n".format(tag, method))
        for ref in refs:
            out.write("       {}\n".format(ref))
    out.write("\n")


def main():
    dex_dir = sys.argv[1]
    files = sorted(
        [os.path.join(dex_dir, f) for f in os.listdir(dex_dir)
         if f.startswith("classes") and f.endswith(".dex")],
        key=lambda p: (len(os.path.basename(p)), p))
    out_path = os.path.join(dex_dir, "voip_version_scan.txt")
    with open(out_path, "w", encoding="utf-8") as out:
        for path in files:
            print("scan", path, flush=True)
            scan(path, out)
    print("written", out_path)


if __name__ == "__main__":
    main()
