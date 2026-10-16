# FKZ_WX_DATA 授权数据库解密分析（学习笔记）

## 数据库结构

- `DATA` / `DATA1` / `DATA2` / `DATA_VIP` 四张同构表：`(_ID, ACCOUNT, TAG, TYPE, VALUE, DATA)`
- `ACCOUNT` 是微信 wxid（或 `+NO_ID+`），`DATA_VIP` 是捐赠用户的数据
- `TYPE`：`STRING / BOOLEAN / INT / JSON / JSON_ARRAY`
- 行数（完整样本库）：DATA 365 / DATA1 378 / DATA2 288 / DATA_VIP 247
- 简化库（`FKZ_WX_DATA-wxid_kcvrpkelhtj722`）只有 DATA 表 10 行，是用于学习密钥的最小样本

## 加密链路（三层）

### 第一层：AES-256-CBC（PKCS7 填充，零 IV）

- **密钥（用户提供的）**：
  ```
  31d019ea56d574133508b10d944b413c4fb9eb58a90e1a015c62729f7459c66d
  ```
- IV：全零；VALUE 列为 Base64 编码
- 验证：`qIV+1vubyuQLf5EmH5rGAw==` → `true`（BOOLEAN 型，PKCS7 填充 `0c*12`）
- 微X 端派生方式（`C0753.m4499`）：`MD5(seed UTF-8)` 作 AES key，seed 拼接方式 `m4464(f3923) = md5_hex_nopad(微X证书DER) + "9n4hZkF"`
- 读取路径：`C0726(context2=微信context, modulePath)` → `m4465()` 读自身 APK `classes.dex` 条目的证书 DER → `m4466()` md5（无零填充 hex）→ 拼 `9n4hZkF` → `C0753.m4498` 解密

### 第二层：RSA-2048（PKCS1 v1.5）

- 服务器用私钥签名，客户端用公钥验签（`rsa/ecb/pkcs1`）
- **公钥（用户提供的）**：
  ```
  MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAojznXsQThMtPLgEeoVv4lF9PaY/lkEV4iZz1XOkHUG0aRhR9TiGa4V+sWZeL5Wf2sbHmD0QdvsTC2YLzbXbJ23pull6wrCl5GRujkTqT7nJl0e5yPT7CVs2FSFymzHp9BARxPK+BZi6q9icsmey4nci7SCHCNo/cNuP5jeTnWtD3c3A/kUXh9utho5dl1KEIZy04rblKkKYMgLg7mr7R0pPuTnrCLoIPk6MIOYIP50kSrgg9fwCM1KUCmnNdqceZjgeX4X9x3XD5CgQmS6RAIbTFfo4Nqfa+ZuEgekAFjP2gyljRg78dvBPBKZ1YpOfbCgCXC0Uohlad/V8+o+/FPwIDAQAB
  ```
- **签名值（用户提供的）**：`31d019ea...` 出现的另一形态——`31d019ea56d574133508b10d944b413c4fb9eb58a90e1a015c62729f7459c66d` 在本库中即第一层 AES 密钥本身
- `verifier6` / `params_S6` / `LIC` 第一层解开后是 Base64 编码的 256 字节 RSA 块
- 公钥运算（`pow(ct, e, n)` → 去掉 `00 01 FF..FF 00` 填充）还原明文：
  ```
  verifier6  = Zezehai001,196e91507cf,3edf036bb907b21e187004374efea0c38,verifier6,196e91507cf
  params_S6  = shoujiajie3407,8.0.49,63ea1210af6132957b08bb606ae9fb0ff,param,196ee47da01
  LIC        = shoujiajie3407,b575fbf,845f01bf180ba22f09e7b1c179a3984a3,95318,196ee47d9fe
  ```
  （DATA1/DATA2 早期快照里是 `Zezehai001` 账号；当前库为 `shoujiajie3407`）
- 统一格式：`账号,字段/版本,授权key hash,类型,时间戳`
- 注意：`LIC` 在部分快照中是服务器用私钥**签的名**，公钥只能验签、不能解出明文（`pow` 后无 PKCS1 结构）

### 明文字段

`LatestVersions` 是 JSON，记录各功能 dex 指纹，与 `wx6_2.44.tar` 里按 MD5 命名的文件对应：

```json
DATA2: {"fp_themes":"74","fp_sf":"4c","fp_af":"af","fp_vidurlparser":"1f","fp_mf":"84",
        "fp_donation":"48","fp_xv":"1ef","fp_base":"207","meta":"1902e00b167",
        "string":"18fe309bb74","h_p":"18f8c15f5c1","lib":"9","core":"d4","apk":"42,2.2,821452f9"}
```

## 字段含义

| TAG | 含义 |
|---|---|
| verifier6 / xv_verifier6 | 授权校验记录（RSA 签名：wxid+时间戳+hash） |
| LIC | 授权凭证（RSA 签名/验签：账号+key hash+序号+时间） |
| params_S6 | 授权参数（RSA 签名：账号+版本+key hash） |
| valid / s_valid | 授权是否有效（AES 加密的 true/false） |
| permaban / random_fail / wx_ban_id | 封禁状态、随机失败、封禁名单 |
| app_check / system_app_check | 反检测开关（Xposed/系统应用环境检测） |
| latest_param | 服务器下发的最新版本号（如 `8.0.49`） |
| LatestVersions | 各功能模块 dex 指纹（防篡改） |
| disable_features | 服务端可禁用的功能（如 `emulator_check`） |
| _fapps / _fapps2..4 | 禁止共存的竞品模块包名列表：`com.hwf.jfsq, com.god.center, com.wsktek.center.lib, com.gxxc, com.qihoo.magic.xposey, com.yzrm.mm, com.aimajin.mo...` |
| urls_wx7 / urls_backup_wx7 / urls_activation_alt_wx7 / urls_check_alt_wx7 / urls_check_alt_free_wx7 | 激活/校验服务器地址（本库中为空） |
| usedKeys / wxExclApp / not_supported / web_notice / push_msg | 已用捐赠 key / 排除应用 / 不支持提示 / 网页公告 / 推送消息 |
| red_packet_comp / rpc_mode / scan_zombie_method / is_new_user / lspatch_int_pay / bundled_sale3 | 功能开关与配置 |
| offline_time / last_update_check / pay_update_check / donate_priority_warning / verifier6_time | 离线时间与更新检查状态 |

## 服务器下发的封禁记录

- `wx_ban_id = ljw256, wxid_zlhfzy95t1gj22, q511068174` —— 服务端封禁的账号名单
- 授权记录里的账号 `shoujiajie3407`、key hash `63ea1210af61...` 是捐赠 key

## 安全观察

- 所有授权决策由服务端签名数据驱动，客户端只验签：签名无法伪造
- WeXposedHook 的做法是直接替换校验方法让它返回 true，并屏蔽 updateLicense——即伪造客户端验签结果，而不是伪造签名
- 第一层 AES 密钥是客户端固定值（任何人可解），真正的防护在第二层 RSA 签名

## 解密脚本参考

```python
import base64, sqlite3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_der_public_key

KEY = bytes.fromhex('31d019ea56d574133508b10d944b413c4fb9eb58a90e1a015c62729f7459c66d')

def layer1(s):  # AES-CBC 解第一层
    d = base64.b64decode(s)
    p = Cipher(algorithms.AES(KEY), modes.CBC(b'\0'*16)).decryptor()
    r = p.update(d) + p.finalize()
    pad = r[-1]
    return (r[:-pad] if 1 <= pad <= 16 else r).decode('utf-8', 'replace')

def rsa_unsign(inner_b64, pubkey):  # 公钥运算 + 去 PKCS1 填充
    d2 = base64.b64decode(inner_b64)
    n, e = pubkey.public_numbers().n, pubkey.public_numbers().e
    raw = pow(int.from_bytes(d2, 'big'), e, n).to_bytes(256, 'big')
    if raw[:2] == b'\x00\x01':
        return raw[raw.index(b'\x00', 2) + 1:]
    return None  # 无 PKCS1 结构 = 签名而非加密
```
