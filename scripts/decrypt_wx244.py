"""离线解密微X / X 功能包容器（2.44 与 3.0）。

用法:
    python -X utf8 scripts/decrypt_wx244.py <文件或目录> [-o 输出目录]
        [--family 244|30|both] [--quiet]

容器格式:
    32 字节摘要前缀(可选) + msgpack 数组(7 项):
      [版本, 5 位位置置换, f1..f5]
    置换中每位数字表示该槽位存放的字段编号:
      f1 = payload(前 16 字节为 AES IV)
      f2 = 256 字节签名
      f3 = 8 字节 PBE salt
      f4 = 24 字节 PBE 加密的 AES key seed
      f5 = 256 字节签名

解密:
    key = PBEWithMD5AndDES(password, f3, 1000) 解密 f4, 去 PKCS5 padding -> 16B
    plain = AES-128-CBC(f1[:16]) 解密 f1[16:]

password 公式(MD5 后取逐字节去前导零 hex):
    公共: certFp = MD5(APK 签名证书 DER), keyFp = MD5(证书公钥 DER)
    2.44: 拼接中包含包名 com.fkzhang.wechatxposed
    3.0 : 拼接中不含包名
    各组件顺序与数字后缀见 FORMULAS / X30_FORMULAS。
"""
import argparse
import hashlib
import struct
from pathlib import Path

from Crypto.Cipher import AES, DES

MAGIC = bytes.fromhex("97c40130")

CERT_FP = "9c7b209c5977e2ea90e29f66381a3c8"
KEY_FP = "ab39dd0f5c223b636584baa3b7a1a7"
PKG = "com.fkzhang.wechatxposed"

S1 = "fkZh4n9_1211_guji_Xposed"
S2 = "FKZhang_WechatXposed_1211_GUJI"
S3 = "Gn4hZkF_1121_GUji"
S4 = "9N4hZ_1211_GUJI_0211"
S5 = "Guji_0123_WeXposed_fkzhang"

# 2.44: 公式串里 C=certFp, K=keyFp, P=pkg, S1..S5=固定盐
FORMULAS = {
    "core": ("K" "S3" "P" "C", "103021019"),
    "core207": ("S2" "C" "K" "P", "300011227"),
    "core_c": ("K" "C" "P" "S3", "100021349"),
    "base": ("K" "P" "C" "S4", "102001325"),
    "themes": ("C" "P" "S1" "K", "000213318"),
    "donation": ("P" "C" "K" "S2", "200010357"),
    "vidurlparser": ("S4" "C" "K" "P", "300010215"),
    "lang": ("S1" "C" "K" "P", "300011223"),
    "meta": ("S2" "K" "C" "P", "030110422"),
    "config": ("K" "P" "C" "S2", "010200232"),
    "classmap": ("P" "S5" "C" "K", "203000181"),
    # 扩展包（DigestProbe 捕获 preimage，已离线验证）
    "sf": ("C" "P" "K" "S4", "000211430"),
    "mf": ("C" "K" "S2" "P", "000103522"),
    "af": ("C" "S2" "P" "K", "003020167"),
}

PASSWORDS = {
    "core": "f25c4ac6bee6291acd2474dadbddb",
    "core207": "54d0e6ab3c787101ad9daea3279b1a7",
    "core_c": "2aaf7e1f81c1e1ee4c41756cf7a0cb93",
    "base": "d469a1152a7768b87418ffa3883254e",
    "themes": "c1fc2271446e83a446702ab1401f94c6",
    "donation": "7b342b1c7c9ee29d4b9785836fc76",
    "vidurlparser": "98662c7fb925bd157d0740a0d1d14d",
    "lang": "76a0bc5752e8af5f243b7842972b3416",
    "meta": "8356ffd44eef91f6ee6cb83871601840",
    "config": "90a917cb7c6511a3924fb946a23e558",
    "classmap": "f789b35e33c8fd1d44789c7885e1325",
    # 扩展包外层：2026-10-21 从 Android 13 + WeChat 8.0.49 宿主捕获。
    # data/xmetadata/wx6/r/fp 与高级包内的同名包共用同一 password。
    "sf": "376a24b4ead27fb7c9db36a4617f6b4",
    "mf": "4ac99464d3a44d3581deb34b418eff8",
    "af": "ecb9e530e46417c2a088fc26feacdd6",
}

# 扩展包内层：外层明文是 3 元素数组 [256B 签名, 599B _c 容器, 内层容器]。
# 内层容器的第 4 个槽位是 RSA 尾记录（用厂商公钥做公钥还原，见 rsa_tail），
# 得到 "<9位后缀>,<hash>,0"；再用下面的排列 + 后缀算内层 password。
INNER_FORMULAS = {
    "sf": ("S4" "C" "P" "K", "300021135"),
    "mf": ("P" "S5" "K" "C", "020301506"),
    "af": ("C" "K" "S5" "P", "001030281"),
}

INNER_PASSWORDS = {
    "sf": "7ab7732f28c291e7d93c680bf6c5337",
    "mf": "fdb4bfa5136c3658f9f849e81774a07c",
    "af": "30d26f795c278482441cb465b02b1ce7",
}

# X 3.0 扩展包内层：后缀 7 位，公式不含包名 P。
X30_INNER_FORMULAS = {
    "sf": ("K" "C" "S2", "1000217"),
    "mf": ("S3" "C" "K", "0200814"),
    "af": ("S1" "K" "C", "2011033"),
}

X30_INNER_PASSWORDS = {
    "sf": "5c897b16c61610673c398e6553f3b",
    "mf": "e82b5260fd15c04fd7f1dea075738c1",
    "af": "5b4f49dc184d84d15cf14915e854449",
}

# `_c` 旁车：599B 容器。f1=32B(IV16+AES16)，解出 msgpack fixstr 字符串；
# 另一个 256B 槽位是 RSA 公钥可还原的 "<9位后缀>,<hash>,0"。
# password 仍是 trim(MD5(常量排列 + 后缀))。
SIDECAR_FORMULAS = {
    "core_c": ("K" "P" "S3" "C", "010203304"),
    "core_c_backup": ("K" "C" "P" "S3", "100021349"),
    "base_c": ("C" "S3" "P" "K", "003021119"),
    "themes_c": ("P" "K" "C" "S4", "201001345"),
    "bridge_c": ("K" "C" "S4" "P", "100030215"),
    "donation_c": ("K" "C" "P" "S2", "100020327"),
    "vid_c": ("P" "K" "C" "S1", "201000383"),
    "sf_c": ("K" "S4" "C" "P", "010300920"),
    "mf_c": ("P" "K" "S3" "C", "020113204"),
    "af_c": ("K" "P" "S1" "C", "102030073"),
}

SIDECAR_PASSWORDS = {
    "core_c": "9cba32d68537d47fa60e1591dcede72",
    "core_c_backup": "2aaf7e1f81c1e1ee4c41756cf7a0cb93",
    "base_c": "bc33738ff8877541eea35cccab7e2d",
    "themes_c": "806ef92e11d817406eb113a654042b0",
    "bridge_c": "9da95d1ddd1d2e2ad349d2b929f32b30",
    "donation_c": "f4dda8987bdf1fc748692332e75c9f7",
    "vid_c": "44f673e8a162fa7ebade83c63764aae",
    "sf_c": "15ad2f6b9ffe4a31a20ce49f162e15",
    "mf_c": "34de1fbf37bf56ff3250a215fdaa50eb",
    "af_c": "739ffde5a1314e14d6b803dc35ecb",
}

# 厂商尾记录公钥（X509 DER，与 2.44 核心验签公钥一致）。
TAIL_PUBKEY = bytes.fromhex(
    "30820122300d06092a864886f70d01010105000382010f003082010a02820101"
    "00dc6cbd92486d90c7c01732b12076ee22597319d65a4251bca5092422f97d18"
    "18d7a604c81108f473239140a75ecef8ebfbb9f843e28a7ae78e8b2d15456a40"
    "8eb74bd6ae47aa5bb0df9d628169d17a770120e1e41437027dcc667a80d2ffff"
    "67654a83223cd3fa3da6c29114ee620db582be136a44cf7c093374a982e43b8a"
    "1c2cb0e2297868ed7f6679e81660e847ed281482514bcf8e1a8685a347a13d4c"
    "3c7117c944a03481ab5783a0461feb15399e4c12afdd2f7574a21ae7dff475b3"
    "92f46e02d37fee2e40c684dfadf0beeca24624c02e94568f9e6a46cbef8fc120"
    "d71b44d531e35f2e2cced05ad5898e48c735a1debd3672d398194cca6d3891ec"
    "a30203010001"
)

# 3.0: 公式串不含 P(包名)
X30_FORMULAS = {
    "core": ("C" "K" "S2", "0010297"),
    "core_c": ("K" "S2" "C", "0102602"),
    "config": ("S3" "C" "K", "2000139"),
    "meta": ("S5" "K" "C", "2011011"),
    "small": ("C" "K" "S1", "0010243"),
    "lang": ("K" "C" "S5", "1000271"),
    "sf_pack": ("S4" "K" "C", "2011025"),
    "mf_pack": ("S5" "K" "C", "2011031"),
    "af_pack": ("K" "S4" "C", "0102500"),
}

X30_PASSWORDS = {
    "core": "a9f3694679ccd2afee49ddae6b27ed9e",
    "core_c": "c68825987b9f66b93262645efd4a459",
    "config": "d31e32db561534aa01d2c4b56b6157d",
    "meta": "bf36c57719f36670d8698e4eae462b7a",
    "small": "abad9ea3f8c03fbd428aec13e3948dd",
    "lang": "c22e742b6568af04cac4a8e9d058ef",
    "sf_pack": "80752d1605bf6235493bb1e113c3e8c",
    "mf_pack": "4f61bb9ec1e854c9753f878a883a294",
    "af_pack": "4f74d05b691fd81abe1838b3bffbb9e9",
}

# 实测抓到但尚未还原公式的 3.0 密码
X30_EXTRA = (
    "4912fbaa87edab22b7f737b794b4a39",
    "dbba162ca04f5e34992738651a2666f",
    "46d94ff9016e397dc16a4e99d98fbd",
    "b44dc02d7003e24ffb11d41d5d31323",
    "fafba0be93dfdc4c824e1f55836337a",
    "e6aee704494ab6acd79bc868a75135b",
    "5d456b83a6d59d629f857b5fb6a373f",
    "ac282e135a29e137cf97b7677676c520",
    "ef62649872bf334e362a735146212b7",
    "4f74d05b691fd81abe1838b3bffbb9e9",
)


def derive(template: str, suffix: str, with_package: bool) -> str:
    values = {"C": CERT_FP, "K": KEY_FP, "P": PKG,
              "S1": S1, "S2": S2, "S3": S3, "S4": S4, "S5": S5}
    text = ""
    for token in _tokens(template):
        if token == "P" and not with_package:
            continue
        text += values[token]
    text += suffix
    return _trim_hex(hashlib.md5(text.encode("utf-8")).digest())


def _tokens(template: str):
    index = 0
    while index < len(template):
        if template[index] == "S" and index + 1 < len(template):
            yield template[index:index + 2]
            index += 2
        else:
            yield template[index]
            index += 1


def _trim_hex(data: bytes) -> str:
    return "".join(format(value, "x") for value in data)


def _msgpack(data: bytes, offset: int = 0):
    def read(position):
        tag = data[position]
        if tag == 0xC4:
            size = data[position + 1]
            return data[position + 2:position + 2 + size], position + 2 + size
        if tag == 0xC5:
            size = struct.unpack(">H", data[position + 1:position + 3])[0]
            return data[position + 3:position + 3 + size], position + 3 + size
        if tag == 0xC6:
            size = struct.unpack(">I", data[position + 1:position + 5])[0]
            return data[position + 5:position + 5 + size], position + 5 + size
        if 0x90 <= tag <= 0x9F:
            return ("array", tag & 0x0F), position + 1
        if tag <= 0x7F:
            return tag, position + 1
        raise ValueError("unsupported tag 0x%02x at %d" % (tag, position))

    value, position = read(offset)
    if isinstance(value, tuple):
        items = []
        for _ in range(value[1]):
            item, position = read(position)
            items.append(item)
        return items, position
    return value, position


def parse_container(data: bytes):
    offset = data.find(MAGIC)
    if offset < 0 or offset > 64:
        return None
    try:
        array, _ = _msgpack(data, offset)
    except Exception:
        return None
    if not isinstance(array, list) or len(array) != 7:
        return None
    permutation = array[1].decode("latin1")
    slots = {index: array[index + 2] for index in range(5)}
    fields = {int(permutation[index]): slots[index] for index in range(5)}
    if len(fields) != 5:
        return None
    return fields[1], fields[3], fields[4], permutation


def decrypt(container, password: str):
    payload, salt, seed, _ = container
    digest = hashlib.md5(password.encode("utf-8") + salt).digest()
    for _ in range(999):
        digest = hashlib.md5(digest).digest()
    plain_seed = DES.new(digest[:8], DES.MODE_CBC, digest[8:16]).decrypt(seed)
    padding = plain_seed[-1]
    if 1 <= padding <= 8 and plain_seed[-padding:] == bytes([padding]) * padding:
        plain_seed = plain_seed[:-padding]
    if len(plain_seed) != 16:
        return None
    plain = AES.new(plain_seed, AES.MODE_CBC, payload[:16]).decrypt(payload[16:])
    padding = plain[-1]
    if not (1 <= padding <= 16 and plain[-padding:] == bytes([padding]) * padding):
        return None
    return plain[:-padding]


def rsa_tail(block: bytes):
    """用厂商公钥还原 256B 尾记录，返回 b"<9位后缀>,<hash>,0"。"""
    from Crypto.PublicKey import RSA
    key = RSA.import_key(TAIL_PUBKEY)
    raw = pow(int.from_bytes(block, "big"), key.e, key.n).to_bytes(len(block), "big")
    if raw[:2] != b"\x00\x01":
        return None
    index = 2
    while index < len(raw) and raw[index] == 0xFF:
        index += 1
    if index >= len(raw) or raw[index] != 0:
        return None
    return raw[index + 1:]


def signed_array(data: bytes):
    """解析外层明文的 3 元素数组 [签名, _c, 内层容器]。"""
    if data[:1] != b"\x93":
        return None
    offset = 1
    items = []
    for _ in range(3):
        item, offset = _msgpack(data, offset)
        items.append(item)
    return items


def decrypt_extension(outer_plain: bytes):
    """尝试已知内层 password，返回 (名称, 内层明文)。"""
    items = signed_array(outer_plain)
    if not items:
        return None
    container = parse_container(items[2])
    if container is None:
        return None
    for name, password in INNER_PASSWORDS.items():
        plain = decrypt(container, password)
        if plain is not None:
            return name, plain
    return None


def sidecar_fields(data: bytes):
    """按位置置换展开 `_c` 容器的 5 个槽位。"""
    array, _ = _msgpack(data, data.find(MAGIC))
    if not isinstance(array, list) or len(array) != 7:
        return None
    permutation = array[1].decode("latin1")
    slots = {index: array[index + 2] for index in range(5)}
    return {int(permutation[index]): slots[index] for index in range(5)}


def sidecar_suffix(data: bytes):
    """`_c` 的 RSA 尾记录后缀（公钥可还原，无需 password）。"""
    fields = sidecar_fields(data)
    if fields is None:
        return None
    for block in fields.values():
        if len(block) != 256:
            continue
        record = rsa_tail(block)
        if record and record.count(b",") == 2:
            return record.split(b",")[0].decode()
    return None


def decrypt_sidecar(data: bytes):
    """尝试已知 `_c` password，返回 (名称, msgpack 字符串 payload)。"""
    fields = sidecar_fields(data)
    if fields is None:
        return None
    payload, salt, seed = fields[1], fields[3], fields[4]
    for name, password in SIDECAR_PASSWORDS.items():
        digest = hashlib.md5(password.encode("utf-8") + salt).digest()
        for _ in range(999):
            digest = hashlib.md5(digest).digest()
        plain_seed = DES.new(digest[:8], DES.MODE_CBC, digest[8:16]).decrypt(seed)
        padding = plain_seed[-1]
        if not (1 <= padding <= 8):
            continue
        plain_seed = plain_seed[:-padding]
        if len(plain_seed) != 16:
            continue
        plain = AES.new(plain_seed, AES.MODE_CBC, payload[:16]).decrypt(payload)
        for offset in (16, 0):
            block = plain[offset:offset + 16]
            if not block or not (0xA0 <= block[0] <= 0xBF):
                continue
            size = block[0] & 0x0F
            if 0 < size <= 15 and all(32 <= value < 127
                                      for value in block[1:1 + size]):
                return name, block[1:1 + size]
    return None


def classify(data: bytes) -> str:
    if data[:2] == b"PK":
        return "zip"
    if data[:4] == b"dex\n":
        return "dex"
    if data[:4] == b"\x7fELF":
        return "elf"
    if data[:4] == bytes.fromhex("93c50100"):
        return "signed-array"
    if data[:1] in (b"{", b"["):
        return "json"
    if data[:1] in (b"\xde", b"\xdf", b"\x89", b"\x9f"):
        return "msgpack"
    return "bin"


def password_sets(family: str):
    result = []
    if family in ("244", "both"):
        result.append(("244", list(PASSWORDS.items())))
    if family in ("30", "both"):
        items = [("30:" + name, value) for name, value in X30_PASSWORDS.items()]
        items += [("30:extra", value) for value in X30_EXTRA]
        result.append(("30", items))
    return result


def self_check() -> bool:
    for name, (template, suffix) in FORMULAS.items():
        if derive(template, suffix, True) != PASSWORDS[name]:
            print("2.44 公式自检失败: " + name)
            return False
    for name, (template, suffix) in INNER_FORMULAS.items():
        if derive(template, suffix, True) != INNER_PASSWORDS[name]:
            print("扩展内层公式自检失败: " + name)
            return False
    for name, (template, suffix) in SIDECAR_FORMULAS.items():
        if derive(template, suffix, True) != SIDECAR_PASSWORDS[name]:
            print("_c 公式自检失败: " + name)
            return False
    for name, (template, suffix) in X30_INNER_FORMULAS.items():
        if derive(template, suffix, False) != X30_INNER_PASSWORDS[name]:
            print("X 3.0 内层公式自检失败: " + name)
            return False
    for name, (template, suffix) in X30_FORMULAS.items():
        if derive(template, suffix, False) != X30_PASSWORDS[name]:
            print("3.0 公式自检失败: " + name)
            return False
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="离线解密微X / X 容器")
    parser.add_argument("path", type=Path, help="文件或目录")
    parser.add_argument("-o", "--output", type=Path, default=None, help="输出目录")
    parser.add_argument("--family", choices=("244", "30", "both"), default="both",
                        help="密码家族(默认 both)")
    parser.add_argument("--quiet", action="store_true", help="只输出汇总")
    args = parser.parse_args()

    if not self_check():
        return 2

    files = [args.path] if args.path.is_file() else sorted(
        item for item in args.path.rglob("*") if item.is_file())
    root = args.output or (args.path if args.path.is_dir() else args.path.parent)
    output = root / "decrypted" if args.path.is_dir() else root

    sets = password_sets(args.family)
    ok = 0
    skipped = 0
    for item in files:
        try:
            data = item.read_bytes()
        except OSError:
            continue
        container = parse_container(data)
        if container is None:
            continue
        plain = None
        used = None
        for family, entries in sets:
            for name, password in entries:
                plain = decrypt(container, password)
                if plain is not None:
                    used = name
                    break
            if plain is not None:
                break
        if plain is None:
            skipped += 1
            print("跳过(密码未知) %s" % item)
            continue
        kind = classify(plain)
        target = output / (item.stem + "." + kind)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(plain)
        ok += 1
        if not args.quiet:
            print("%-40s %8d -> %-12s %s" % (item.name, len(data), kind, used))
    print("完成: 解密 %d 个, 跳过 %d 个, 输出 %s" % (ok, skipped, output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
