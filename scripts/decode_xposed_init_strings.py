# XposedInit 字符串池解码
# f7 = XOR 加密的短整型数组，C0000.m16(sArr, off, len, key)
import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

f7 = [4960, -26539, -26544, -26531, -26553, -26536, -26534, -26593, -26558, -26552,
      -26558, -26555, -26540, -26532, -26593, -26504, -26529, -26500, -26540, -26532,
      -26530, -26557, -26552, -26507, -26540, -26551, -26510, -26531, -26544, -26558,
      -26558, -26499, -26530, -26544, -26539, -26540, -26557]

def dec(off, length, key):
    return ''.join(chr((f7[off + i] & 0xFFFF) ^ key) for i in range(length))

print('key=13296 off=1 len=36:', repr(dec(1, 36, 13296)))
print('key=38961 off=1 len=36:', repr(dec(1, 36, 38961)))
