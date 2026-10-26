# X 3.0 账号解析链路

微信 8.0.49 / wxcore 212 实测。壳的账号查询入口是 `c.ˊﹶ.ˉˎ.יⁱ()`，
三层链式兜底，任意一层命中就返回。本模块已按同一套来源复刻，不依赖壳。

## 壳的结构

```
c.ˊﹶ.ˉˎ.יⁱ()
  ├─ ① c.ˏᵎ.ʻˎ.ˈᴵ().ﾞʿ()
  │     → SELECT value FROM userinfo WHERE id = 2        (微X 自己的 /*fkz*/ 表)
  ├─ ② c.ᵎʾ.ˏי.ﾞʿ()
  │     → 反射 ConfigStorageLogicClass
  │       .ConfigStorageLogic_getUserName()                (类名/方法名走壳的映射表)
  └─ ③ c.ˊﹶ.ˉˎ.ᴵˉ()
        → 读微信 SharedPreferences / MMKV（见下表）
```

三层都是空时返回 `③` 的最后一个空串。

## 解密出的常量

core dex（`c.**`）的字符串用 `c.ʾˎ.ⁱˋ.ⁱˋ(long)` 解密，
实现在 `c.ʾˎ.ﾞⁱ.ﾞⁱ(long, String[])`，混合函数是 `c.ʾˎ.ʾʻ.ⁱˋ(long)`。

| 常量 | 明文 | 用途 |
|---|---|---|
| `-141342377606280` | `SELECT value FROM userinfo WHERE id = ` | ① 的 SQL 前缀 |
| `-141445456821384` | `value` | ① 的列名 |
| `-141475521592456` | 空串 | ① 的默认值 |
| `-158075570191496` | `/*fkz*/` | 微X 建库标记 |
| `-176350656035976` | `ConfigStorageLogicClass` | ② 的类映射键 |
| `-177591901584520` | `ConfigStorageLogic_getUserName` | ② 的方法映射键 |
| `-161820781673608` | `login_weixin_username` | ③ 的 key |
| `-161880911215752` | 空串 | ③ 的默认值 |
| `-161885206183048` | `notify_key_pref_no_account` | ③ 的 prefs 名 |
| `-162035530038408` | `login_weixin_username` | ③ 的 key（第二组） |
| `-162061299842184` | 空串 | ③ 的默认值 |
| `-162065594809480` | `switch_account_preferences` | ③ 的 prefs 名 |
| `-163315430292616` | `last_switch_account_to_wx_username` | ③ 的 key |
| `-163465754147976` | 空串 | ③ 的默认值 |
| `-163435689376904` | `com.tencent.mm_preferences_account_history` | ③ 的历史表（key 即账号） |

## 第三层的读取顺序（文件层，最早可用）

```java
sp.getString("login_weixin_username", "")
ctx.getSharedPreferences("notify_key_pref_no_account", 4)
   .getString("login_weixin_username", "")
ctx.getSharedPreferences("switch_account_preferences", 4)
   .getString("last_switch_account_to_wx_username", "")
ctx.getSharedPreferences("com.tencent.mm_preferences_account_history", 4)
   .getAll().keySet()          // key 本身就是微信号
```

微信 8.x 已把部分 prefs 迁到 MMKV（`files/mmkv/`），文件层两处都要读。

## 本模块的实现

`github.shadowbaby.wechatxposed.hook.license.WeChatAccount` 按可用时间排序：

```
① shared_prefs/*.xml          → 文件层，毫秒级
② files/mmkv/*                → 8.x 迁移后的位置
③ 反射 com.tencent.mm.model.c → 微信存储类，3 秒后
④ 壳 c.ˊﹶ.ˉˎ.יⁱ()           → 兜底
⑤ files/wxh_account           → 上次运行落盘
```

③ 有 3 秒启动门槛（`armAfter`）：进程刚绑定时主动调用微信存储类可能让它的
静态块抛异常，类被标成 Erroneous 后微信自己再加载就崩。文件层不需要这个门槛。

## 换微信版本时的排查

1. 日志里看命中的来源：
   - `account probe: prefs …` — 文件层，最理想
   - `account probe: ConfigStorageLogicClass` — 反射层
   - `activation: account from shell api` — 只剩壳兜底，说明①②都失效
2. 文件层失效：确认 `shared_prefs/` 或 `files/mmkv/` 下的文件名与 key 是否改名。
3. 反射层失效：`ConfigStorageLogicClass` 的映射在壳的 core dex 里，
   新版 core 可能改名，需要重新解 `c.ᵎʾ.ˏי.ﾞʿ()` 的字符串。

## 相关

- 解密脚本：`scripts/decode_c30_strings.py`（core dex 专用；`x.**` 的是另一套算法）
- x 包（`x.**`）的字符串解密是另一套算法，见 memory `x30-shell-string-decryptor`
