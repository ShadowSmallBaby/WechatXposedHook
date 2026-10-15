"""第三阶段重构:把各类里的 XOR 字符串池与 decode 调用换成最终明文。

做两件事:
  1. 生成 docs/StringPools.java —— 池原文 + (偏移, 长度, key, 常量名, 明文) 对照表。
     该文件在 app 的 sourceSet 之外,不参与编译,不打进 APK。
  2. 把 app 源码里的 decode(...) 调用换成最终字符串字面量,并删掉池、key 常量与 decode 辅助方法。

用法:
    python -I inline_string_pools.py            # 预演,只打印计划
    python -I inline_string_pools.py --apply    # 实际改写
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "app/src/main/java/github/shadowbaby/wechatxposed"
DOCS = ROOT / "docs"

# (源文件, 池变量名, 池 + 区间 + key 的说明, [(常量名, 偏移, 长度, key), ...])
SPECS = [
    ("hook/XposedInit.java", "DEX_LOADER_TARGET_POOL", "XposedInit", [
        ("TARGET_CLASS", 1, 36, 38961),
    ]),
    ("hook/rebuild/loader/InMemoryDexLoadHook.java", "LOADER_POOL", "InMemoryDexLoadHook", [
        ("ALL_DEX_HOOKED", 1, 23, 7403),
        ("IGNORED_NON_MODULE_DEX", 199, 26, 7403),
        ("LOG_FOUND", 259, 6, 7403),
        ("LOG_ENABLE_SUFFIX", 265, 10, 7403),
        ("LOG_HOOK_SUCCEEDED_SUFFIX", 275, 10, 7403),
        ("COMPONENT_ENTRY_CLASSES[0]", 24, 40, 7403),
        ("COMPONENT_ENTRY_CLASSES[1]", 64, 49, 7403),
        ("COMPONENT_ENTRY_CLASSES[2]", 113, 44, 7403),
        ("COMPONENT_ENTRY_CLASSES[3]", 157, 42, 7403),
        ("COMPONENT_NAMES[0]", 225, 7, 7403),
        ("COMPONENT_NAMES[1]", 232, 7, 7403),
        ("COMPONENT_NAMES[2]", 239, 11, 7403),
        ("COMPONENT_NAMES[3]", 250, 9, 7403),
        ("DISABLE", 300, 7, 17407),
        ("ON_UPDATE_CHECK", 307, 15, 17407),
        ("PROCESS_METADATA", 322, 16, 17407),
        ("UPDATE_LICENSE", 338, 13, 17407),
        ("DELAYED_CHECK", 351, 13, 17407),
    ]),
    ("hook/rebuild/loader/ModuleLogger.java", "LOG_POOL", "ModuleLogger", [
        ("ACTIVITY_THREAD_CLASS", 1, 26, 48914),
        ("CURRENT_ACTIVITY_THREAD", 27, 21, 48914),
        ("WECHAT_PACKAGE", 48, 14, 48914),
        ("PROBE_FILE_NAME", 62, 4, 48914),
        ("GET_SYSTEM_CONTEXT", 97, 16, 48914),
        ("LOG_PREFIX", 114, 15, 17712),
    ]),
    ("hook/rebuild/support/WxComponentHooks.java", "HOOK_POOL", "WxComponentHooks", [
        ("BASE_HOOK_ARGUMENT_CLASS", 1, 8, 52313),
        ("BASE_ENTRY_CLASS", 9, 5, 52313),
        ("BASE_ENTRY_METHOD", 14, 2, 52313),
        ("WX_JNI_CORE_BRIDGE", 16, 45, 52313),
        ("CALL_METHOD", 61, 10, 52313),
        ("CORE_VERIFIER_CLASS", 71, 7, 52313),
        ("CORE_VERIFY_SIGNATURE_METHOD", 78, 2, 52313),
        ("CORE_VERIFY_BOOLEAN_STRING_METHOD", 80, 1, 52313),
        ("CORE_POLLING_CLASS", 81, 6, 52313),
        ("CORE_POLLING_METHOD", 87, 2, 52313),
        ("CORE_VERIFY_UPDATED_TIPS_METHOD", 89, 2, 52313),
        ("CORE_LICENSE_CLASS", 91, 7, 52313),
        ("CORE_LICENSE_METHOD", 98, 2, 52313),
        ("THEMES_HOOK_ARGUMENT_CLASS", 100, 8, 52313),
        ("THEMES_ENTRY_CLASS", 108, 5, 52313),
        ("THEMES_ENTRY_METHOD", 113, 2, 52313),
        ("DONATION_HOOK_ARGUMENT_CLASS", 115, 8, 52313),
        ("DONATION_ENTRY_CLASS", 123, 5, 52313),
        ("DONATION_ENTRY_METHOD", 128, 2, 52313),
    ]),
    ("hook/rebuild/support/CallMethodBypassHook.java", "BYPASS_POOL", "CallMethodBypassHook", [
        ("WXID_PREFIX", 1, 5, 55463),
        ("VERIFIER_SERVICE", 18, 9, 5559),
        ("VERIFIER_SERVICE_CLASS", 27, 7, 5559),
        ("VERIFIER_SERVICE_FACTORY", 34, 2, 5559),
        ("ACTION_PARAM", 36, 5, 5559),
        ("NULL_TEXT", 41, 4, 5559),
        ("FIELD_SEPARATOR", 45, 1, 5559),
        ("OBJECTS_EQUALS_METHOD", 46, 6, 5559),
        ("OBJECTS_CLASS", 52, 17, 5559),
        ("RELEASE_LICENSE_METHOD", 69, 2, 5559),
        ("CLEANUP_FACTORY_METHOD", 71, 2, 5559),
        ("CLEANUP_CLASS", 73, 7, 5559),
        ("LICENSE_FIELD", 80, 3, 5559),
        ("LICENSE_GETTER_METHOD", 83, 2, 5559),
        ("MIN_SUPPORTED_VERSION", 85, 6, 5559),
        ("SET_INTERNAL_VERSION_METHOD", 102, 2, 5559),
        ("TRUE_TEXT", 104, 4, 5559),
        ("REMOTE_COMMAND", 108, 13, 5559),
        ("UNLIMITED", 121, 9, 5559),
        ("PAYLOAD_SEPARATOR", 144, 1, 5559),
    ]),
    ("hook/rebuild/support/VerifierMethodReplacement.java", "REPLACEMENT_POOL",
     "VerifierMethodReplacement", [
         ("POLLING_VERIFIER_MESSAGE", 1, 23, 55271),
         ("CHECK_API_REQUEST_MESSAGE", 24, 24, 55271),
         ("UPDATED_TIPS_MESSAGE", 48, 19, 55271),
     ]),
]

# 各文件里 key 常量的名字,用来拼出待替换的 decode(...) 调用形态。
KEY_NAMES = {
    ("hook/rebuild/loader/InMemoryDexLoadHook.java", 7403): "TEXT_KEY",
    ("hook/rebuild/loader/InMemoryDexLoadHook.java", 17407): "VERIFIER_KEY",
    ("hook/rebuild/loader/ModuleLogger.java", 48914): "ENVIRONMENT_KEY",
    ("hook/rebuild/loader/ModuleLogger.java", 17712): "PREFIX_KEY",
    ("hook/rebuild/support/WxComponentHooks.java", 52313): "POOL_KEY",
    ("hook/rebuild/support/CallMethodBypassHook.java", 5559): "POOL_KEY",
    ("hook/rebuild/support/CallMethodBypassHook.java", 55463): "AFTER_KEY",
}

# 每个文件里要整行删掉的 key 常量声明。
KEY_DECLARATIONS = {
    "hook/XposedInit.java": ["TARGET_OFFSET", "TARGET_LENGTH", "TARGET_KEY"],
    "hook/rebuild/loader/InMemoryDexLoadHook.java": ["TEXT_KEY", "VERIFIER_KEY"],
    "hook/rebuild/loader/ModuleLogger.java": ["ENVIRONMENT_KEY", "PREFIX_KEY"],
    "hook/rebuild/support/WxComponentHooks.java": ["POOL_KEY"],
    "hook/rebuild/support/CallMethodBypassHook.java": ["POOL_KEY", "AFTER_KEY"],
    "hook/rebuild/support/VerifierMethodReplacement.java": ["POOL_KEY"],
}


def load_pool(text, name):
    match = re.search(r"short\[\]\s+" + name + r"\s*=\s*\{(.*?)\};", text, re.S)
    if match is None:
        raise SystemExit("池未找到: " + name)
    return [int(token) for token in re.findall(r"-?\d+", match.group(1))]


def decode(pool, offset, length, key):
    return "".join(chr((pool[offset + i] ^ key) & 0xFFFF) for i in range(length))


def java_literal(text):
    out = []
    for ch in text:
        code = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif 0x20 <= code <= 0x7E:
            out.append(ch)
        else:
            out.append("\\u%04X" % code)
    return '"' + "".join(out) + '"'


def collect():
    """返回 [(相对路径, 池名, 池数组, 所属类, [(常量, 偏移, 长度, key, 明文)])]。"""
    result = []
    for relative, pool_name, owner, entries in SPECS:
        text = (SRC / relative).read_text(encoding="utf-8")
        pool = load_pool(text, pool_name)
        decoded = [(name, offset, length, key, decode(pool, offset, length, key))
                   for name, offset, length, key in entries]
        result.append((relative, pool_name, pool, owner, decoded))
    return result


def render_pool_array(name, pool):
    lines = ["    private static final short[] %s = {" % name]
    for start in range(0, len(pool), 12):
        chunk = pool[start:start + 12]
        tail = "," if start + 12 < len(pool) else ""
        lines.append("            " + ", ".join(str(value) for value in chunk) + tail)
    lines.append("    };")
    return lines


def render_string_pools(data):
    lines = [
        "package docs;",
        "",
        "/**",
        " * XOR 字符串池留档,仅供逆向分析对照。",
        " *",
        " * 本文件位于 app 的 sourceSet 之外:不参与编译,不打进 APK。",
        " * 第三阶段重构后,app 源码引用字符串直接用明文,池与解码调用已从源码移除;",
        " * 这里保留「池原文 + 偏移 + 长度 + key + 明文」的完整对应关系,便于回查。",
        " *",
        " * 运行(仓库根目录,JDK 11+ 单文件源码启动):",
        " *   java docs/StringPools.java",
        " */",
        "public final class StringPools {",
        "",
    ]
    for relative, pool_name, pool, owner, decoded in data:
        lines.append("    /** 原 %s 的字符池(%d 项)。 */" % (owner, len(pool)))
        lines.extend(render_pool_array(pool_name, pool))
        lines.append("")
    lines += [
        "    /** 一条解码记录:池 + 区间 + key + 明文。 */",
        "    private record Entry(short[] pool, int offset, int length, int key, String where,",
        "            String plain) {",
        "    }",
        "",
        "    private static final Entry[] ENTRIES = {",
    ]
    for index, (relative, pool_name, pool, owner, decoded) in enumerate(data):
        lines.append("            // %s" % owner)
        for name, offset, length, key, plain in decoded:
            lines.append("            new Entry(%s, %d, %d, %d, %s, %s),"
                         % (pool_name, offset, length, key,
                            java_literal(owner + "." + name), java_literal(plain)))
        if index != len(data) - 1:
            lines.append("")
    lines += [
        "    };",
        "",
        "    /** 还原 pool[offset, offset + length) 与 key 异或后的明文。 */",
        "    private static String decode(short[] pool, int offset, int length, int key) {",
        "        char[] chars = new char[length];",
        "        for (int i = 0; i < length; i++) {",
        "            chars[i] = (char) (pool[offset + i] ^ key);",
        "        }",
        "        return new String(chars);",
        "    }",
        "",
        "    public static void main(String[] args) {",
        "        int differences = 0;",
        "        for (Entry entry : ENTRIES) {",
        "            String plain = decode(entry.pool(), entry.offset(), entry.length(), entry.key());",
        "            boolean same = plain.equals(entry.plain());",
        "            if (!same) {",
        "                differences++;",
        "            }",
        "            System.out.printf(\"%s %-46s [%4d..%4d) ^ %-6d -> %s%n\",",
        "                    same ? \"ok  \" : \"DIFF\", entry.where(), entry.offset(),",
        "                    entry.offset() + entry.length(), entry.key(), plain);",
        "        }",
        "        System.out.printf(\"%d entries, %d differences%n\", ENTRIES.length, differences);",
        "    }",
        "}",
        "",
    ]
    return "\n".join(lines)


def replacement_pairs(relative, owner, decoded):
    """拼出各类里 decode(...) 的原始调用形态(A 类两参、B 类三参)。

    WxComponentHooks 与 VerifierMethodReplacement 的 decode 辅助方法只有
    (offset, length) 两个参数,key 写死在方法体里,所以调用形态是两参。
    """
    pairs = []
    for name, offset, length, key, plain in decoded:
        if relative == "hook/XposedInit.java":
            token = ("XorStrings.decode(DEX_LOADER_TARGET_POOL, TARGET_OFFSET, TARGET_LENGTH,"
                     " TARGET_KEY)")
        elif relative.endswith(("WxComponentHooks.java", "VerifierMethodReplacement.java")):
            token = "decode(%d, %d)" % (offset, length)
        else:
            token = "decode(%d, %d, %s)" % (offset, length, KEY_NAMES[(relative, key)])
        pairs.append((token, java_literal(plain)))
    return pairs


def strip_pool(text, pool_name):
    """删掉池数组声明,连同紧邻上方的注释块。"""
    lines = text.split("\n")
    start = None
    for index, line in enumerate(lines):
        if re.search(r"short\[\]\s+" + pool_name + r"\s*=\s*\{", line):
            start = index
            break
    if start is None:
        raise SystemExit("找不到池声明: " + pool_name)

    end = next((index for index in range(start, len(lines)) if "};" in lines[index]), None)
    if end is None:
        raise SystemExit("找不到池结束: " + pool_name)

    top = start
    while top > 0 and (lines[top - 1].strip().startswith("/**")
                       or lines[top - 1].strip().startswith("*")):
        top -= 1
    del lines[top:end + 1]
    return "\n".join(lines)


def strip_key_declarations(text, names):
    kept = []
    for line in text.split("\n"):
        stripped = line.strip()
        if any(stripped.startswith("private static final int " + name + " =") for name in names):
            continue
        kept.append(line)
    return "\n".join(kept)


def strip_decode_helper(text):
    """删掉类内的 private static String decode(...) 辅助方法,连同上方注释块。"""
    pattern = re.compile(
        r"\n(?:[ \t]*/\*\*(?:(?!\*/).)*?\*/\n)?[ \t]*private static String decode\([^)]*\)"
        r"\s*\{.*?\n[ \t]*\}\n", re.S)
    while True:
        match = pattern.search(text)
        if match is None:
            return text
        text = text[:match.start()] + "\n" + text[match.end():]


def rewrite(relative, pool_name, owner, decoded):
    """返回改写后的文本。校验先于任何写盘动作。"""
    path = SRC / relative
    text = path.read_text(encoding="utf-8")
    original = text

    for token, literal in replacement_pairs(relative, owner, decoded):
        count = text.count(token)
        if count != 1:
            raise SystemExit("%s 中 %s 出现 %d 次(预期 1 次)" % (relative, token, count))
        text = text.replace(token, literal)

    text = strip_pool(text, pool_name)
    text = strip_key_declarations(text, KEY_DECLARATIONS[relative])
    text = strip_decode_helper(text)
    text = text.replace(
        "import github.shadowbaby.wechatxposed.hook.rebuild.XorStrings;\n", "")
    text = re.sub(r"\n{3,}", "\n\n", text)

    if text == original:
        raise SystemExit("无改动: " + relative)
    return text


def apply_changes(data):
    # 全部先算好,任何一处校验失败都不落盘。
    pending = [(relative, rewrite(relative, pool_name, owner, decoded))
               for relative, pool_name, pool, owner, decoded in data]
    for relative, text in pending:
        (SRC / relative).write_text(text, encoding="utf-8")
        print("改写 %s" % relative)


def main():
    data = collect()
    for relative, pool_name, pool, owner, decoded in data:
        print("=== %s / %s (%d 项) ===" % (relative, pool_name, len(pool)))
        for name, offset, length, key, plain in decoded:
            print("  %-34s [%d..%d) ^ %-6d -> %s"
                  % (owner + "." + name, offset, offset + length, key, plain))
    if "--apply" not in sys.argv:
        print("\n预演结束,加 --apply 实际改写。")
        return

    (DOCS / "StringPools.java").write_text(render_string_pools(data), encoding="utf-8")
    print("\n生成 docs/StringPools.java")
    apply_changes(data)


if __name__ == "__main__":
    main()