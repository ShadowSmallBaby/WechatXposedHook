#!/usr/bin/env python3
"""Dump one class/method from a dex directory.

Usage:
    python scripts/dump_dex_class.py <dex-dir> <class-dot-name> [method-name]
"""
import os
import sys

from androguard.core.dex import DEX

try:
    from loguru import logger
    logger.remove()
except Exception:
    pass


def main():
    dex_dir, dot_name = sys.argv[1], sys.argv[2]
    method_filter = sys.argv[3] if len(sys.argv) > 3 else None
    target = "L" + dot_name.replace(".", "/") + ";"
    for f in sorted(os.listdir(dex_dir)):
        if not (f.startswith("classes") and f.endswith(".dex")):
            continue
        dex = DEX(open(os.path.join(dex_dir, f), "rb").read())
        for cls in dex.get_classes():
            if cls.get_name() != target:
                continue
            print("# file:", f)
            print("# class:", cls.get_name(),
                  "super:", cls.get_superclassname())
            for field in cls.get_fields():
                print("FIELD", field.get_name(), field.get_descriptor(),
                      field.get_access_flags_string())
            for m in cls.get_methods():
                if method_filter and m.get_name() != method_filter:
                    continue
                print("\nMETHOD {} {}{} flags={}".format(
                    m.get_class_name(), m.get_name(), m.get_descriptor(),
                    m.get_access_flags_string()))
                for ins in m.get_instructions() or ():
                    print("  {} | {}".format(ins.get_name(), ins.get_output()))


if __name__ == "__main__":
    main()
