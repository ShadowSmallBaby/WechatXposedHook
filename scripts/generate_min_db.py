# -*- coding: utf-8 -*-
# 为指定 wxid 生成一份最小 FKZ_WX_DATA 数据库（WeXposedHook 部署用）
#
# 结论来源（对四个 dex 的反汇编，见 docs/reverse-engineering.md）：
#   - 读表：Lﹶˆ/ⁱʼ;->יˋ  "SELECT * FROM DATA WHERE ACCOUNT=? AND TAG=?"
#           => ACCOUNT 必须等于当前登录 wxid，否则整表读不到
#   - 授权：CallMethodBypassHook 只取 LIC 的 "#" 前段，decodeLicenseBlob 出
#           "LIC:<user>"，再和微X传入的 userId 比对 => blob 里必须写登录 wxid
#   - getLicData(Lˎˉ/ˆᵔ;->ᵎᵔ)：LIC 按 "#" 切，必须正好 3 段，取第 3 段解出付费功能集合
#           => LIC = "<blob>#f#<tail>"，tail 内容被 hook 覆盖，结构对齐即可
#   - verifier6 = "<blob>"（blob 编码 "verifier6#D:<wxid>"）
#
# 用法：python generate_min_db.py wxid_123456 [输出路径]

import base64
import hashlib
import sqlite3
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# 第一层 AES：AES-256-CBC / PKCS7 / 零 IV（与微X C0753 一致）
AES_KEY = bytes.fromhex(
    '31d019ea56d574133508b10d944b413c4fb9eb58a90e1a015c62729f7459c66d')
IV = b'\0' * 16


def enc(value: str) -> str:
    data = value.encode('utf-8')
    pad = 16 - len(data) % 16
    data += bytes([pad]) * pad
    p = Cipher(algorithms.AES(AES_KEY), modes.CBC(IV)).encryptor()
    return base64.b64encode(p.update(data) + p.finalize()).decode()


def lic_seg3(wxid: str) -> str:
    """LIC 第 3 段:key = SHA-256(wxid)(raw digest),AES/CBC/PKCS7,零 IV。"""
    key = hashlib.sha256(wxid.encode('utf-8')).digest()
    data = LIC_FEATURE_SET.encode('utf-8')
    pad = 16 - len(data) % 16
    data += bytes([pad]) * pad
    p = Cipher(algorithms.AES(key), modes.CBC(IV)).encryptor()
    return base64.b64encode(p.update(data) + p.finalize()).decode()


def lic_seg3_decrypt(seg3: str, wxid: str) -> str:
    """lic_seg3 的逆运算,用于自检(对应 getLicData 的解密路径)。"""
    key = hashlib.sha256(wxid.encode('utf-8')).digest()
    p = Cipher(algorithms.AES(key), modes.CBC(IV)).decryptor()
    raw = p.update(base64.b64decode(seg3)) + p.finalize()
    pad = raw[-1]
    if 1 <= pad <= 16 and raw[-pad:] == bytes([pad]) * pad:
        raw = raw[:-pad]
    return raw.decode('utf-8')


def encode_blob(plain: str) -> str:
    """把 "LIC:<wxid>" / "verifier6#D:<wxid>" 编成模块 decodeLicenseBlob 能还原的数字串。"""
    n = len(plain)
    nums = []
    for i, ch in enumerate(plain):
        base = (ord(ch) << 2) - ((i << 2) + n)
        for delta in range(4):
            cand = base + delta
            if cand >= 0:
                nums.append(cand ^ (i * i))
                break
        else:
            raise ValueError('char out of range: %r' % ch)
    packed = ''.join('%d%s' % (len(str(v)), v) for v in nums)
    return base64.b64encode(packed.encode('utf-8')).decode()


# 参考最小库（FKZ_WX_DATA-wxid_kcvrpkelhtj722）里的常量，与设备无关
LATEST_VERSIONS = ('{"fp_themes":"71","fp_sf":"4b","fp_af":"ab","fp_vidurlparser":"1e",'
                   '"fp_mf":"89","fp_donation":"47","fp_xv":"1f2","fp_base":"20d",'
                   '"meta":"1902dffe702","string":"18fe3f447ec","h_p":"18eec2d7db3",'
                   '"lib":"9","core":"cf","apk":"42,2.2,821452f9"}')
FP_VERSIONS = '{"themes":113,"donation":71,"base":525,"vidurlparser":30}'
FP = 'themes'
FP_ASYNC = 'base,vidurlparser,donation'

# LIC 第 3 段(付费功能集合密文)。反汇编 getLicData:段 3 用 key = SHA-256(wxid)(UTF-8 原文,非 hex)做 AES/CBC/PKCS7Padding、零 IV 解密,再 new JSONArray 逐项 getInt。明文是 [1](授权档位);4533 与 722 两个真实授权库都解出 [1]。=> 必须按 *当前 wxid* 现算,不能照抄参考库字节:照抄后别的账号拿同一密文,用自己 wxid 派生的 key 解出来是乱码 -> JSONArray 抛异常 -> 无 VIP、无菜单。
LIC_FEATURE_SET = "[1]"

SCHEMA = '''
CREATE TABLE android_metadata (locale TEXT);
CREATE TABLE DATA(_ID INTEGER PRIMARY KEY NOT NULL,
    ACCOUNT TEXT, TAG TEXT, TYPE TEXT, VALUE TEXT, DATA BLOB);
'''


def build_rows(wxid: str):
    seg3 = lic_seg3(wxid)
    # 自检:按 getLicData 的路径解回去必须等于明文,防止段 2 与 wxid 不匹配
    assert lic_seg3_decrypt(seg3, wxid) == LIC_FEATURE_SET, 'LIC 段 3 自检失败'
    lic = enc('%s#f#%s' % (encode_blob('LIC:' + wxid), seg3))
    verifier6 = enc(encode_blob('verifier6#D:' + wxid))
    return [
        ('hookFail',           'BOOLEAN', enc('false')),
        ('disclaimer_disable', 'BOOLEAN', enc('true')),
        ('is_new_user',        'INT',     enc('10')),
        ('LatestVersions',     'JSON',    enc(LATEST_VERSIONS)),
        ('FPVersions',         'JSON',    enc(FP_VERSIONS)),
        ('valid',              'BOOLEAN', enc('true')),
        ('fp',                 'STRING',  enc(FP)),
        ('fp_async',           'STRING',  enc(FP_ASYNC)),
        ('LIC',                'STRING',  lic),
        ('verifier6',          'STRING',  verifier6),
    ]


def build(wxids, out: str):
    """把多个 wxid 各写一份最小行集到同一个库(ACCOUNT 区分,互不影响)。"""
    c = sqlite3.connect(out)
    c.executescript(SCHEMA)
    c.execute("insert into android_metadata values ('zh_CN')")
    row_id = 2
    for wxid in wxids:
        seg3 = lic_seg3(wxid)
        rows = build_rows(wxid)
        plain = lic_seg3_decrypt(seg3, wxid)
        for tag, typ, val in rows:
            c.execute('insert into DATA values (?, ?, ?, ?, ?, NULL)',
                      (row_id, wxid, tag, typ, val))
            row_id += 1
        print('  %-24s %d 行  LIC段3=%s  自检解出 %r' % (wxid, len(rows), seg3, plain))
    # 微X 的 SQLiteOpenHelper 版本号是 1(L َˆ/iʼ;-><init> 里 const/4 #1)。
    # 若 user_version=0,微X 打开时会判定需要建表,执行 CREATE TABLE DATA
    # (无 IF NOT EXISTS)→ "table DATA already exists" → 启动失败。
    c.execute('PRAGMA user_version = 1')
    c.commit()
    c.close()
    print('生成完成: %s  (%d 个账号, %d 行, user_version=1)'
          % (out, len(wxids), row_id - 2))


def main(wxid: str, out: str):
    build([wxid], out)

    seg3 = lic_seg3(wxid)
    rows = build_rows(wxid)
    c = sqlite3.connect(out)
    c.executescript(SCHEMA)
    c.execute("insert into android_metadata values ('zh_CN')")
    for i, (tag, typ, val) in enumerate(rows, start=2):
        c.execute('insert into DATA values (?, ?, ?, ?, ?, NULL)',
                  (i, wxid, tag, typ, val))
    # 微X 的 SQLiteOpenHelper 版本号是 1（Lﹶˆ/ⁱʼ;-><init> 里 const/4 #1）。
    # 若 user_version=0，微X 打开时会判定需要建表，执行 CREATE TABLE DATA
    # （无 IF NOT EXISTS）→ "table DATA already exists" → 启动失败。
    c.execute('PRAGMA user_version = 1')
    c.commit()
    c.close()
    print('生成完成: %s  (%d 行, ACCOUNT=%s, LIC段3=%s)' % (out, len(rows), wxid, seg3))
    print('  自检: LIC 段 3 用 SHA-256(%s) 解出 %r' % (wxid, lic_seg3_decrypt(seg3, wxid)))


if __name__ == '__main__':
    # wxid 必须是微X 实际传给 hook 的 userId（即当前登录账号的完整 wxid），
    # 取法是读微信 shared_prefs/com.tencent.mm_preferences.xml 里的 login_weixin_username
    # （模块启动自检就是这么拿的）。
    # 写错（或写了个不存在的账号）会导致菜单加载不出来。
    if len(sys.argv) < 2:
        sys.exit('用法: python generate_min_db.py <wxid>[,<wxid>...] [输出路径]\n'
                 '  wxid 取微信 prefs 里的 login_weixin_username。\n'
                 '  多个 wxid 用逗号分隔,写进同一个库(同一设备多账号共用一份 FKZ_WX_DATA)。')
    wxids = [w for w in sys.argv[1].split(',') if w]
    if len(sys.argv) > 2:
        out = sys.argv[2]
    elif len(wxids) == 1:
        out = 'FKZ_WX_DATA-%s' % wxids[0]
    else:
        out = 'FKZ_WX_DATA-merged-%dacct' % len(wxids)
    build(wxids, out)
