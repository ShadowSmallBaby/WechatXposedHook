# 微X模块字符串混淆解码器复刻
# 对应微X classes.dex 中的 C1627.m7065 / C1628.m7069 / C1628.m7068 / C1627.m7066
# 用法：从 baksmali 输出提取 C1629(即 x/ˋˊ/ᵢٴ.smali) 的 const-string 池，
#       然后调用 decode(constant) 解出 C1629.m7070(<long>) 的字符串。
#
# 关键坑（Java 语义必须精确复刻）：
# 1. short 符号扩展：byte/short 位模式转 int/long 时保留符号
# 2. ushr 是逻辑移位（无符号），>> 是算术移位
# 3. m7069 的拼位顺序：p1 在 bit32-47，p0r 在 bit16-31，v0 在 bit0-15
#    （jadx 反编译的 C1628.java 里顺序有误导，以 smali 为准）
# 4. m7065 的索引计算：第一次 m7069 后取 (h>>>32)&0xFFFF，第二次后取 (h>>>16)&0xFFFF0000

M = (1 << 64) - 1

def sb(v):
    """long 位模式 → 有符号值（模拟 Java 强制转换）"""
    v &= M
    return v - (1 << 64) if v >= (1 << 63) else v

def rot(s, i):
    """C1628.m7067：short 循环移位 (short)((s >>> (32-i)) | (s << i))"""
    p0 = sb(s & 0xFFFF) & 0xFFFFFFFF          # int-to-short 之后的 int（符号扩展）
    v0 = (p0 << i) & 0xFFFFFFFF               # shl-int
    p0r = (p0 >> (32 - i)) & 0xFFFFFFFF       # ushr-int（对 32 位位模式）
    return (p0r | v0) & 0xFFFF                # int-to-short

def mix(H):
    """C1628.m7068：murmur 风格 hash，返回低 32 位"""
    p0 = (H ^ (H >> 33)) & M
    p0 = (sb(p0) * sb(0x62a9d9ed799705f5)) & M          # 7109453100751455733
    p0 = (p0 ^ (p0 >> 28)) & M
    p0 = (sb(p0) * sb((-0x34db2f5a3773ca4d) & M)) & M   # -3808689974395783757
    return (p0 >> 32) & 0xFFFFFFFF

def mix2(J):
    """C1628.m7069：splitmix 风格混合，三个 16 位量拼 long"""
    v2 = J & 0xFFFF
    s = sb(v2) & 0xFFFF
    s2 = sb((J >> 16) & 0xFFFF) & 0xFFFF
    p1 = sb((s + s2) & 0xFFFF) & 0xFFFF
    p1r = rot(p1, 9)
    p1b = sb((p1r + s) & 0xFFFF) & 0xFFFF
    p0x = sb((s2 ^ s) & 0xFFFF) & 0xFFFF
    v0 = sb((rot(s, 13) ^ p0x) & 0xFFFF) & 0xFFFF
    v1 = sb((p0x << 5) & 0xFFFF) & 0xFFFF
    v0 = sb((v0 ^ v1) & 0xFFFF) & 0xFFFF
    p0r = sb(rot(p0x, 10) & 0xFFFF) & 0xFFFF
    r = ((p1b << 16) | (p0r & 0xFFFF)) & 0xFFFFFFFF
    return ((r << 16) | (v0 & 0xFFFF)) & M

def idx(i, j, arr):
    """C1627.m7066：pool[i/8191][i%8191] 拼进 long 高 32 位，再 mix"""
    ch = ord(arr[i // 8191][i % 8191])
    return ((ch << 32) ^ mix2(j)) & M

def decode(j, arr):
    """C1627.m7065 主入口"""
    j &= M
    h = mix2(mix(j & 0xFFFFFFFF))              # m7068 → m7069
    t3 = (h >> 32) & 0xFFFF                    # 注意：t3 在第二次 m7069 之前取！
    h = mix2(h)
    t7 = (h >> 16) & 0xFFFF0000
    p1 = int((j >> 32) ^ t3 ^ t7) & 0xFFFFFFFF
    cur = idx(p1, h, arr)
    n = (cur >> 32) & 0xFFFF                   # 长度存在字符链第一项的高 16 位
    out = []
    for k in range(n):
        cur = idx(p1 + k + 1, cur, arr)
        out.append(chr((cur >> 32) & 0xFFFF))
    return ''.join(out)

def load_pool(smali_path):
    """从 baksmali 输出的 smali 文件提取字符串池（C1629.f5919）"""
    import re, json
    src = open(smali_path, encoding='utf-8').read()
    pat = re.compile(r'const-string(?:/jumbo)? [vp][0-9]+, "((?:\\.|[^"\\])*)"')
    return [json.loads('"' + l + '"') for l in pat.findall(src)]

if __name__ == '__main__':
    import sys, io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    # 用法示例：python scripts/decode_microx_strings.py <C1629.smali路径> <常量1> [常量2 ...]
    arr = load_pool(sys.argv[1])
    for arg in sys.argv[2:]:
        j = int(arg)
        print(j, '->', repr(decode(j, arr)))
    # 已知常量对照：
    #   -268301725359106 -> 9n4hZkF          （第一层 AES 盐）
    #   -255081816022018 -> FKZ_WX_DATA      （数据库名）
    #   -279318316473346 -> classes.dex      （证书读取的 jar entry）
    #   -247191961099266 -> AES/CBC/PKCS7Padding
    #   -249850545855490 -> SHA-256
    #   -277484365437954 -> modulePath
    #   -273043369253890 -> wxProcess
