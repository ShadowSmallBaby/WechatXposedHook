# FKZ_WX_DATA 三层解密脚本
# 第一层：AES-256-CBC（PKCS7，零 IV），VALUE 列为 Base64
# 第二层：RSA-2048 PKCS1 v1.5（公钥运算去填充，用于 verifier6/params_S6/LIC）
#
# 微X 端第一层密钥派生（C0753.m4499 + C0747.m4464/m4466 + C0726.m4375）：
#   seed = md5_hex_nopad(微X模块APK classes.dex 条目的证书DER) + "9n4hZkF"
#   aes_key = MD5(seed UTF-8)
# 提取证书 DER：
#   python -c "from cryptography.hazmat.primitives.serialization import pkcs7, Encoding; \
#     import base64; certs = pkcs7.load_der_pkcs7_certificates(open('CERT.RSA','rb').read()); \
#     print(certs[0].public_bytes(Encoding.DER).hex())"

import base64
import sqlite3
import sys
import io
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_der_public_key

AES_KEY = bytes.fromhex(
    '31d019ea56d574133508b10d944b413c4fb9eb58a90e1a015c62729f7459c66d')
IV = b'\0' * 16

RSA_PUB_B64 = (
    'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAojznXsQThMtPLgEeoVv4lF9'
    'PaY/lkEV4iZz1XOkHUG0aRhR9TiGa4V+sWZeL5Wf2sbHmD0QdvsTC2YLzbXbJ23pull'
    '6wrCl5GRujkTqT7nJl0e5yPT7CVs2FSFymzHp9BARxPK+BZi6q9icsmey4nci7SCHCN'
    'o/cNuP5jeTnWtD3c3A/kUXh9utho5dl1KEIZy04rblKkKYMgLg7mr7R0pPuTnrCLoIP'
    'k6MIOYIP50kSrgg9fwCM1KUCmnNdqceZjgeX4X9x3XD5CgQmS6RAIbTFfo4Nqfa+ZuE'
    'gekAFjP2gyljRg78dvBPBKZ1YpOfbCgCXC0Uohlad/V8+o+/FPwIDAQAB')


def strip_pkcs7(r):
    pad = r[-1]
    if 1 <= pad <= 16 and r[-pad:] == bytes([pad]) * pad:
        return r[:-pad]
    return r


def layer1(s):
    """AES-256-CBC 解第一层，返回 str"""
    d = base64.b64decode(s)
    p = Cipher(algorithms.AES(AES_KEY), modes.CBC(IV)).decryptor()
    r = p.update(d) + p.finalize()
    return strip_pkcs7(r).decode('utf-8', 'replace')


def layer1_bytes(s):
    d = base64.b64decode(s)
    p = Cipher(algorithms.AES(AES_KEY), modes.CBC(IV)).decryptor()
    return strip_pkcs7(p.update(d) + p.finalize())


def rsa_unsign(inner_b64):
    """公钥运算 + 去 PKCS1 v1.5 填充。返回 payload bytes，无结构则 None"""
    d2 = base64.b64decode(inner_b64.strip())
    pub = load_der_public_key(base64.b64decode(RSA_PUB_B64))
    n, e = pub.public_numbers().n, pub.public_numbers().e
    raw = pow(int.from_bytes(d2, 'big'), e, n).to_bytes(256, 'big')
    if raw[:2] == b'\x00\x01':
        return raw[raw.index(b'\x00', 2) + 1:]
    return None  # 无 PKCS1 结构 = 签名而非加密（LIC 部分快照如此）


def dump(db_path):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8',
                                  errors='replace')
    c = sqlite3.connect(db_path)
    tables = [r[0] for r in c.execute(
        "select name from sqlite_master where type='table' and name like 'DATA%'")]
    for t in tables:
        print('====', t)
        for (_id, acc, tag, typ, val) in c.execute(
                f'select _ID,ACCOUNT,TAG,TYPE,VALUE from {t}'):
            if not val:
                continue
            try:
                inner = layer1(val).strip()
            except Exception as ex:
                print(f'{tag} [{typ}] {acc}: <第一层解密失败 {ex}>')
                continue
            # 尝试第二层 RSA
            payload = None
            try:
                d2 = base64.b64decode(inner)
                if len(d2) == 256:
                    payload = rsa_unsign(inner)
            except Exception:
                pass
            if payload is not None:
                print(f'{tag} [{typ}] {acc}: RSA={payload.decode("utf-8", "replace")}')
            else:
                print(f'{tag} [{typ}] {acc}: {inner[:200]}')


if __name__ == '__main__':
    dump(sys.argv[1] if len(sys.argv) > 1 else 'FKZ_WX_DATA')
    # 验证样例：
    #   layer1('qIV+1vubyuQLf5EmH5rGAw==') == 'true'
    #   layer1('UcxRp5ElkKcHnzCgB+ONrQ==') == '0'    （INT 型）
    #   layer1('5xrJQSlIeY/yuH3Y/xyGrg==') == '10'
