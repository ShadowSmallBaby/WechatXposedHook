# WxModuleHook 与微X模块逆向分析报告

> 分析对象：`WxModuleHook-1.2_3.apk`、`微X模块_2.44.apk`、`FKZ_WX_DATA*`、`wx6_2.44.tar`
> 工具：TTDeDroid（jadx 1.4.7 / baksmali 2.5.2）、自写 XOR/字符串池解码器、cryptography（AES/RSA）
> 用途：学习 Xposed hook 技术与授权体系设计，评估隐私风险

---

## 一、微X模块 2.44（WechatXposedHooks）

### 1.1 基本信息

- 包名 `com.fkzhang.wechatxposed`，签名证书 `META-INF/CERT.RSA`
- Xposed 模块，作用域 `com.tencent.mm`
- 架构：**壳 + 动态解密 dex**。`classes.dex` 只含壳代码，功能代码（base/core/donation/themes 等模块）运行时解密后经 `InMemoryDexClassLoader` 加载
- 代码做了**控制流混淆**（状态机式 switch 跳转）+ **字符串池加密**

### 1.2 字符串混淆复刻（学习要点）

微X 的字符串全部以**加密池 + 64 位种子**的形式存放：调用点写一个 `const-wide` 常量（种子），运行时经解码函数还原成明文。**主 dex 与 4 个功能 dex 用的是同一套算法**，只是各自的解码类/池不同：

| 位置 | 解码类 | 方法 | 池大小（char 数） |
|---|---|---|---|
| 主 `classes.dex` | `Lx/ˋˊ/ˈﹶ;` | `ˈﹶ(J[Ljava/lang/String;)` | 2 段（8191 + 2968） |
| BaseDex | `Lʾˈ/ʿᵔ;` | `ʿᵔ(J)` | 357734（44 段数组） |
| CoreDex | `Lc/ʻⁱ/ـˋ;` | `ـˋ(J)` | 38357（5 段） |
| DonationDex | `Lᵢᵎ/ʿٴ;` | `ʿٴ(J)` | 28187（4 段） |
| ThemesDex | `Lˈ/ﾞˏ;` | `ﾞˏ(J)` | 47900 |

**算法（已用 Python 逐指令复刻并与 Java 结果对齐）**，记 `M32 = 2^32`、`M64 = 2^64`，`i16` 为 Java `short` 符号扩展：

```
mixA(v):                                   # Lx/ˋˊ/ᴵˑ;.ᴵˑ(J)J
    v ^= v >>> 33
    v  = (v * 0x62a9d9ed799705f5) & M64
    v ^= v >>> 28
    v  = (v * 0xcb24d0a5c88c35b3) & M64
    return v >>> 32                        # 只取高 32 位

mixB(v):                                   # Lx/ˋˊ/ᴵˑ;.ᵢٴ(J)J
    lo = i16(v & 0xffff); hi = i16((v >>> 16) & 0xffff)
    s  = i16(rotl16(i16(lo + hi), 9) + lo)         # 注意是 16 位循环左移
    hi = i16(hi ^ lo)
    a  = i16(rotl16(lo, 13) ^ hi ^ i16(hi << 5))
    b  = i16(rotl16(hi, 10))
    return ((b | (s << 16)) << 16) | a     # 三个 16 位量拼成 48 位

decode(seed, pool):
    h = mixA(seed & 0xffffffff)
    h = mixB(h); idx  = i32((seed >>> 32) ^ (h >>> 32 & 0xffff) ^ ((h >>> 16 & 0xffff) << 16))
    h = mixB(h)
    ch = pool[idx];  h ^= ch << 32
    n  = (h >>> 32) & 0xffff               # 第一个字符是「长度」
    out = []
    for k in range(n):
        h = mixB(h)
        ch = pool[idx + k + 1];  h ^= ch << 32
        out.append((h >>> 32) & 0xffff)    # 每个字符
    return out
```

关键坑：Java `short` 符号扩展、`ushr` 逻辑移位、`mixB` 的拼位顺序（`s` 在 bit32-47）、`mixA` 只取高 32 位。用 Java 写同逻辑跑一遍比手算快得多——Python 复刻踩了 4 次位序坑才用 Java 验证通过。

**池的存放顺序是打乱的**：池不是一段连续字符串，而是一个 `[Ljava/lang/String;` 数组，在 `<clinit>` 里按**乱序**逐项赋值（`const`→`sput-object`→`aput-object`）。要还原，必须解析 `<clinit>` 字节码（opcode `0x12/0x13` 取常量、`0x1a` 取字符串 id、`0x4d aput-object` 写入），得到「数组下标 → 字符串 id」映射，再按数组顺序拼接。直接按 `string_ids` 顺序读会得到乱序文本。

### 1.3 授权体系

- 本地数据库 `FKZ_WX_DATA`（SQLite），存放授权状态与服务端下发配置
- 授权决策由**服务端 RSA 签名数据**驱动，客户端只验签
- 封禁机制：`permaban`、`app_check`、`system_app_check`、`random_fail`、`wx_ban_id` 名单

### 1.4 功能模块存储（wx6_2.44.tar）

**功能 dex 只有 4 个**（Base / Core / Donation / Themes），这是**补丁 WxModuleHook** 的加载器逻辑决定的（`b.a`/`b.c` 属于补丁，见 3.1 的类归属说明），不是按文件数决定的：

- 补丁 `b.a.<clinit>` 固定构造 4 个组件项（componentId 顺序 1=Core、0=Base、3=Themes、2=Donation），`WX_COMPONENTS` 是长度 4 的 `ArrayList`。
- 补丁 `b.c.afterHookedMethod` 遍历这 4 个组件，按 `componentId` 用 key 7403 解出**微X**组件类名去 `findClassIfExists`，命中即注入并打印 `Found <dexName>`（这些类名是微X 的）：

| componentId | dexName | 组件入口类 |
|---|---|---|
| 0 | BaseDex | `com.fkzhang.wxfeatures.base.Wrapper.Init` |
| 1 | CoreDex | `com.fkzhang.wechatxposedhooks.Wrapper.HookWrapper` |
| 2 | DonationDex | `com.fkzhang.wxfeatures.donation.Wrapper.Init` |
| 3 | ThemesDex | `com.fkzhang.wxfeatures.themes.Wrapper.Init` |

**运行时验证（决定性证据）**：hook `InMemoryDexClassLoader` 构造函数并记录每次调用的参数字节数/magic（临时调试代码，分析后已移除），重启微信后捕获到的真实 dex 构造只有 4 个，每个大小与 `dex\n035` magic 均一致：

| bytes | magic | dex |
|---|---|---|
| 3218828 | `dex\n035` | BaseDex |
| 816600 | `dex\n035` | CoreDex |
| 334792 | `dex\n035` | DonationDex |
| 545636 | `dex\n035` | ThemesDex |

**磁盘上 `wx6_2.44.tar` 里的 14 个加密文件 ≠ 14 个 dex**（其中 ELF `.so` 即 `libwxcoreloader.so`，见 3.6）：只有 4 个是功能 dex，其余是微X 的其他加密资源（配置/数据、X.509 证书 `534a97...`、ELF `.so`、license 文本等），由这 4 个 dex 内的代码按需解密读取，不是 dex。

每个功能 dex 拆成三个文件：

| 后缀 | 内容 |
|---|---|
| （无） | 加密 dex（自定义头 `97c40130c405` + 5 位版本/序号，如 `15243`） |
| `_c` | 校验/配置块（599 字节，同套加密头） |
| `_s` | RSA-2048 签名块（256 字节） |

文件名与 `LatestVersions` JSON 里的 `fp_base/fp_core/fp_donation/fp_themes` 等指纹对应（防篡改校验；`fp_sf/fp_af/fp_vidurlparser/fp_mf/fp_xv` 等是其他非 dex 资源）。

### 1.5 解密字符串的提取方法与证据基础

本报告关于「功能键」的结论，全部来自**离线解密 4 个功能 dex 的字符串池**，而不是运行时 hook。方法如下（脚本在 `data/tmp/`）：

1. **拿到明文 dex**：hook `InMemoryDexClassLoader` 构造，把微X 运行时解密出的 4 个 dex 字节落盘（`data/refs/device_dump/{BaseDex,CoreDex,DonationDex,ThemesDex}.dex`，大小见 1.4）。
2. **解析池**：对每个 dex，用 `_dexlib.Dex.pool_of(desc)` 解析解码类的 `<clinit>` 字节码，重建「数组下标 → 字符串」映射，再按数组顺序拼出完整池（见 1.2 的「池存放顺序打乱」）。
3. **全量解码**：扫描 dex 里所有 `const-wide` 种子（`#double nan // #<16hex>`），用 `_dexlib.decode(seed, pool)` 还原明文。
4. **逐方法归属**：把每个方法引用的种子 → 明文归类，得到 `_bdmethods.json`（BaseDex 2421 方法）/ `_coremethods.json`（CoreDex 619）/ `_donmethods.json`（DonationDex 252）/ ThemesDex，用于「某个功能键被哪些类使用」的取证。

产物（`data/tmp/`，均为分析中间物，不入库）：

| 文件 | 内容 |
|---|---|
| `_bddecoded.json` / `.txt` | BaseDex 全量明文（22675 条） |
| `_coredecoded.json` | CoreDex 全量明文（3205 条） |
| `_DonationDexdec.json` | DonationDex 全量明文（2066 条） |
| `_ThemesDexdec.json` | ThemesDex 全量明文（2782 条） |
| `_alldec.json` | 去重后按 dex 汇总（BaseDex 5721 / CoreDex 1300 / DonationDex 747 / ThemesDex 1054 / main 500） |
| `_bdmethods.json` 等 | 逐方法的明文引用映射 |
| `_featverify.py` | 校验补丁 58 项是否都在池里（结果：58/58 命中） |
| `_58where.py` | 逐项列出 58 个键命中的 dex/类 |

> **关于本文引用的 `data/tmp/_*.py`**:那些是分析过程中随手写的一次性脚本,产物落在 `data/`
> (已被 .gitignore 忽略),**不入库**。仓库里长期维护的工具在 `scripts/`;
> 本文结论都可由它们与 `data/refs/` 里的原始样本复核。

> 坑：smali 文本转储会破坏不成对代理项（显示为 `���`），**池字符串必须从 DEX 二进制按 MUTF-8 读**，不能从 smali 文本读；JSON 落盘时对含代理项的字符串用 `s.encode("utf-8","backslashreplace").decode("utf-8")` 转义。


### 1.6 业务设置键统计：四个 dex 到底有多少个「设置项」

问题：`BaseDex` 里能看到 300+ 个业务设置键，那么四个 dex 合起来到底有多少个业务设置键？其中「需要授权」的有几个，是不是 58？

结论先行：**dex 里不存在任何一份「设置键总表」或「授权功能总表」**。设置键是**按功能分散内嵌**在各功能类里的，所以「总数」取决于你用什么口径去数；而「需要授权的有几个」**在 dex 里没有固定答案**——授权是**按 key 动态判定**的（见下）。因此 58 这个数字**不是**微X 的授权项数，而是补丁自己写死的一份清单（见 3.5）。

#### (1) 分层口径与实测数字

对 4 个 dex 全量解码后的字符串（`_alldec.json`，去重后 BaseDex 5721 / CoreDex 1300 / DonationDex 747 / ThemesDex 1054 / main 500），按不同口径统计：

| 口径 | 定义 | 数量 |
|---|---|---|
| 候选键（宽松） | 形如 `[a-z][a-z0-9_]{2,60}` 的短标识符 | 3256（BaseDex 2597 / CoreDex 482 / DonationDex 367 / ThemesDex 315 / main 113） |
| **功能开关（最硬口径）** | 以 `_enable` 结尾的键 | **209**（BaseDex 204 / CoreDex 5 / DonationDex 3 / ThemesDex 3 / main 1） |
| 有 `_enable` 兄弟键 | 存在 `X` 且存在 `X_enable` | 81 |
| 设置定义方法里的键 | JSONObject/ContentValues 且含多个 `_` 默认值 | ~153 |
| UI 构建方法注册的键 | 签名含 LinearLayout/Menu 的方法里出现的键 | 784（其中 `_enable` 118） |
| 设置菜单分组 | 设置菜单构建器列出的顶层分组 | ~15 |

> 说明：3256 这个「宽松候选」里混入了微信自身字段名（`talker`/`content`/`nickname` 等），不是模块设置项；真正稳定的口径是 **`_enable` 开关 = 209 个**，这也是「一个开关对应一个可开/关功能」的自然定义。`_enable` 前缀（去掉 `_enable`）去重后仍是 209，说明没有重复前缀。

脚本：`data/tmp/_summary_count.py`（复现上表）、`_enlist.py`（列出 209 个 `_enable` 键）、`_uikeys.py` / `_bizfinal.py`（其他口径）。

#### (2) 「需要授权的有几个」在 dex 里没有固定值

微X 的授权**不是**「N 个功能需要授权」这种静态集合，而是**按 key 动态判定**，核心在 CoreDex 的 `Lc/ﹶˉ/ᵔˉ;`：

- `ʽʼ()Ljava/util/ArrayList;` @`0x080fd8`：读外部存储的 `license.txt`（种子 `0xffff7936eb66d3f3` 解出），按 `\n|\r`（`0xffff7942eb66d3f3`）切分，**只保留长度 == 64 的 token**，得到「已授权的 key 哈希列表」。
- `ˆⁱ(Ljava/lang/String;)Z` @`0x07f660`：真正的门禁。逻辑是——若 `ʿʼ()` 为真（`license.txt` 存在）则**直接放行**；否则取授权列表，若列表为空也放行；否则把入参字符串按 `,`（`0xffff7930eb66d3f3`）切分，**要求每个 token 都 ∈ 授权列表**，任一不命中即返回 false。
- `ʾˎ()Z` @`0x07f610`：读 `usedKeys` 设置，走 `ˆⁱ` 判定——即「当前已用 key 是否全部被授权」。
- `ʿʼ()Z` @`0x07f4c8`：判断 `license.txt` 是否存在（`Lc/ﹶˉ/ˋﹳ;.ˉˉ`）。

也就是说：**哪些功能需要授权、要几个，由服务器下发的 license 内容决定，dex 里只有「判定算法」没有「数量常量」**。DonationDex 侧同理：`Lᵔˏ/ˑˋ;.ˆⁱ()V` @`0x02565c` 把配置项 `extra_feature_`（`0xffffa63c2dfc9f92`）按 `,`（`0xffffa62d2dfc9f92`）切分后塞进 `HashSet ᵔˏ`——授权功能集是**运行时动态**的。

#### (3) 58 ≠ 授权项数

补丁的 58 项（`CallMethodBypassHook.FEATURES`，`app/src/main/java/github/shadowbaby/wechatxposed/hook/rebuild/support/CallMethodBypassHook.java:101`）是**补丁自己写死的字符串**，用于在 license 校验被 hook 时 `setResult(FEATURES)` 冒充授权列表（同文件 ~307 行）。它：

- 58/58 都是微X 真实存在的功能键（`_58where.py` 逐项命中 4 个 dex）；
- 但只有 8 项是 `_enable` 前缀（即顶层开关），其余是子项/别名；
- 分散在 BaseDex（约 50 项）、CoreDex/DonationDex/ThemesDex（少数）。

所以 58 是**补丁作者挑的一份「看起来像付费功能」的清单**，既不是 dex 里的设置键总数（209 个 `_enable`），也不是微X 的授权项数（动态、无固定值）。


### 1.7 209 个 `*_enable` 设置键明细表

下表列出 4 个 dex 全量解码后、所有以 `_enable` 结尾的业务设置键（共 **209** 个）。「定义类」是该键出现的方法所属类（取字典序首个；一个键可能被多个类引用，「定义类数」为去重后的类数）；「UI/分组方法数」是该键出现在 UI 构建方法（签名含 `LinearLayout`/`Menu`/`Activity`）中的方法数，可用来判断它是否被设置界面直接暴露。

- 覆盖 dex：BaseDex（204 键）/ CoreDex（5）/ DonationDex（3）/ ThemesDex（3）/ main（1）；去重后共 209。
- 有 UI 方法引用的：**121** 个；未被 UI 方法直接引用的：**88** 个（多为子开关，由父功能在代码里读取）。
- 生成脚本：`data/tmp/_enable_rows.py`（产出 `_enable_rows.json`）、`_enable_table.py`（产出本表）。

| # | 设置键 (`*_enable`) | dex | 定义类（首个） | 定义类数 | UI/分组方法数 |
|---|---|---|---|---|---|
| 1 | `accept_all_req_enable` | BaseDex | `Lˈˑ/ᵢי;` | 2 | 0 |
| 2 | `ad_sender_enable` | BaseDex | `Lˈˑ/ʿˋ;` | 3 | 1 |
| 3 | `add_actionbar_items_enable` | BaseDex | `Lˈˑ/ˉᐧ;` | 3 | 1 |
| 4 | `article_open_browser_enable` | BaseDex | `Lˈˑ/ˑˈ;` | 3 | 0 |
| 5 | `at_notification_enable` | BaseDex | `Lˈˑ/ˋᴵ;` | 3 | 0 |
| 6 | `audiocall_general_incoming_ringtone_enable` | BaseDex | `Lᐧʿ/ˉﹶ;` | 1 | 0 |
| 7 | `audiocall_general_outgoing_ringtone_enable` | BaseDex | `Lᐧʿ/ˉﹶ;` | 1 | 0 |
| 8 | `auto_accept_chatroom_invite_qr_enable` | BaseDex | `Lʻʾ/יˋ;` | 3 | 0 |
| 9 | `auto_accept_req_enable` | BaseDex | `Lˈˑ/ᵢי;` | 2 | 0 |
| 10 | `auto_checkin_enable` | BaseDex | `Lˈˑ/ᴵʽ;` | 3 | 0 |
| 11 | `auto_comment_allowed_filter_enable` | BaseDex | `Lˈˑ/ˑـ;` | 3 | 1 |
| 12 | `auto_comment_enable` | BaseDex | `Lˈˑ/ˑـ;` | 3 | 1 |
| 13 | `auto_comment_like_filter_enable` | BaseDex | `Lˈˑ/ˑـ;` | 4 | 2 |
| 14 | `auto_comment_only_enable` | BaseDex | `Lˈˑ/ˊˑ;` | 3 | 1 |
| 15 | `auto_comment_timeframe_enable` | BaseDex | `Lˈˑ/ˑـ;` | 2 | 1 |
| 16 | `auto_exit_chatroom_enable` | BaseDex | `Lˈˑ/ˉˏ;` | 3 | 1 |
| 17 | `auto_kick_keyword_enable` | BaseDex | `Lˈˑ/ᴵʽ;` | 4 | 2 |
| 18 | `auto_like_allowed_filter_enable` | BaseDex | `Lˈˑ/ⁱʾ;` | 3 | 1 |
| 19 | `auto_like_enable` | BaseDex | `Lˈˑ/ⁱʾ;` | 3 | 0 |
| 20 | `auto_like_timeframe_enable` | BaseDex | `Lˈˑ/ⁱʾ;` | 2 | 1 |
| 21 | `auto_remark_enable` | BaseDex | `Lˈˑ/ᵢי;` | 5 | 1 |
| 22 | `auto_shake_friend_finder_enable` | BaseDex | `Lˈˑ/ᵎᵎ;` | 3 | 1 |
| 23 | `auto_transcribe_mode_enable` | BaseDex | `Lˈˑ/ˑˈ;` | 4 | 1 |
| 24 | `auto_translate_mode_enable` | BaseDex | `Lˈˑ/ˉי;` | 3 | 0 |
| 25 | `auto_tts_enable` | BaseDex | `Lˈˑ/ٴٴ;` | 7 | 1 |
| 26 | `autoban_enable` | BaseDex | `Lˈˑ/ᴵʽ;` | 3 | 1 |
| 27 | `autojoin_openim_chatroom_enable` | BaseDex | `Lʻʾ/יˋ;` | 4 | 1 |
| 28 | `autojoinchatroom_delay_enable` | BaseDex | `Lˈˑ/ˉˏ;` | 3 | 1 |
| 29 | `autojoinqr_delay_enable` | BaseDex | `Lˈˑ/ˉˏ;` | 3 | 1 |
| 30 | `autoreply_auto_enable` | BaseDex | `Lˈˑ/ʿˋ;` | 4 | 1 |
| 31 | `autoreply_enable` | BaseDex | `Lʽᵎ/ʽﹳ;` | 3 | 0 |
| 32 | `autoreply_master_enable` | BaseDex | `Lʽᵎ/ʽﹳ;` | 7 | 1 |
| 33 | `autoreply_r_delay_enable` | BaseDex | `Lˈˑ/ᐧ;` | 1 | 0 |
| 34 | `autoreply_timeframe_enable` | BaseDex | `Lˈˑ/ᐧ;` | 1 | 0 |
| 35 | `autoresponse_keywords_enable` | BaseDex | `Lˈˑ/ˎﹶ;` | 2 | 0 |
| 36 | `autoupdate_enable` | CoreDex | `Lc/ᐧٴ/ᵎʻ;` | 8 | 2 |
| 37 | `blacklist_enable` | BaseDex | `Lˈˑ/ʿᵢ;` | 7 | 1 |
| 38 | `block_nudging_enable` | BaseDex | `Lˈˑ/ˉי;` | 2 | 0 |
| 39 | `broadcast_forward_enable` | BaseDex | `Lˈˑ/ـʼ;` | 8 | 0 |
| 40 | `chatcontainer_enable` | BaseDex | `Lʽᵎ/ⁱٴ;` | 28 | 3 |
| 41 | `chatroom_app_ban_enable` | BaseDex | `Lˈˑ/ᴵʽ;` | 4 | 2 |
| 42 | `chatroom_app_ban_warning_enable` | BaseDex | `Lˈˑ/ᴵʽ;` | 3 | 1 |
| 43 | `chatroom_article_ban_enable` | BaseDex | `Lˈˑ/ᴵʽ;` | 4 | 2 |
| 44 | `chatroom_article_ban_warning_enable` | BaseDex | `Lˈˑ/ᴵʽ;` | 3 | 1 |
| 45 | `chatroom_autoreply_member_enable` | BaseDex | `Lˈˑ/ᐧ;` | 1 | 0 |
| 46 | `chatroom_ban_sendmsg_enable` | BaseDex | `Lˈˑ/ᴵʽ;` | 3 | 1 |
| 47 | `chatroom_container_all_enable` | BaseDex | `Lʽᵎ/ⁱٴ;` | 9 | 1 |
| 48 | `chatroom_container_mute_enable` | BaseDex | `Lʽᵎ/ⁱٴ;` | 7 | 1 |
| 49 | `chatroom_container_own_enable` | BaseDex | `Lʽᵎ/ⁱٴ;` | 7 | 1 |
| 50 | `chatroom_container_public_enable` | BaseDex | `Lʽᵎ/ⁱٴ;` | 9 | 1 |
| 51 | `chatroom_container_tag_enable` | BaseDex | `Lʽᵎ/ⁱٴ;` | 8 | 1 |
| 52 | `chatroom_container_work_enable` | BaseDex | `Lʽᵎ/ⁱٴ;` | 7 | 1 |
| 53 | `chatroom_custom_at_enable` | BaseDex | `Lˈˑ/ˋᴵ;` | 4 | 1 |
| 54 | `chatroom_friendcard_ban_enable` | BaseDex | `Lˈˑ/ᴵʽ;` | 4 | 2 |
| 55 | `chatroom_friendcard_ban_warning_enable` | BaseDex | `Lˈˑ/ᴵʽ;` | 3 | 1 |
| 56 | `chatroom_images_ban_enable` | BaseDex | `Lˈˑ/ᴵʽ;` | 4 | 2 |
| 57 | `chatroom_images_ban_warning_enable` | BaseDex | `Lˈˑ/ᴵʽ;` | 3 | 1 |
| 58 | `chatroom_intro_enable` | BaseDex | `Lˈˑ/ᴵʽ;` | 3 | 0 |
| 59 | `chatroom_invite_allow_by_identity_enable` | BaseDex | `Lˈˑ/ـٴ;` | 2 | 0 |
| 60 | `chatroom_keyword_ban_warning_enable` | BaseDex | `Lˈˑ/ᴵʽ;` | 3 | 1 |
| 61 | `chatroom_qrcode_ban_enable` | BaseDex | `Lˈˑ/ᴵʽ;` | 4 | 2 |
| 62 | `chatroom_qrcode_ban_warning_enable` | BaseDex | `Lˈˑ/ᴵʽ;` | 3 | 1 |
| 63 | `chatroom_repeat_ban_enable` | BaseDex | `Lˈˑ/ᴵʽ;` | 4 | 2 |
| 64 | `checkin_enable` | BaseDex | `Lˈˑ/ᴵʽ;` | 3 | 0 |
| 65 | `click_red_packet_enable` | BaseDex | `Lˈˑ/ٴˋ;` | 3 | 1 |
| 66 | `comment_only_once_per_day_enable` | BaseDex | `Lˈˑ/ˑـ;` | 3 | 1 |
| 67 | `comment_recall_notification_enable` | BaseDex | `Lᐧʿ/ʻʽ;` | 1 | 0 |
| 68 | `config_grab_reply_enable` | BaseDex | `Lˈˑ/ˏˑ;` | 3 | 0 |
| 69 | `confirm_transfer_delay_enable` | BaseDex | `Lˈˑ/ٴˋ;` | 3 | 1 |
| 70 | `confirm_transfer_enable` | BaseDex | `Lˈˑ/ٴˋ;` | 4 | 1 |
| 71 | `confirm_transfer_random_delay_enable` | BaseDex | `Lˈˑ/ٴʻ;` | 3 | 1 |
| 72 | `confirm_transfer_specific_enable` | BaseDex | `Lˈˑ/ٴʻ;` | 4 | 1 |
| 73 | `contact_chatroom_enable` | BaseDex | `Lˈˑ/ٴᐧ;` | 1 | 1 |
| 74 | `custom_dice_enable` | BaseDex | `Lˈˑ/ˉᐧ;` | 3 | 1 |
| 75 | `custom_notification_enable` | BaseDex | `Lᐧʿ/ᵢˈ;` | 1 | 0 |
| 76 | `custom_nudging_msg_enable` | BaseDex | `Lˈˑ/ˉי;` | 3 | 0 |
| 77 | `disable_wechat_ads_enable` | BaseDex | `Lˈˑ/ﾞᐧ;` | 3 | 1 |
| 78 | `encrypted_mode_enable` | BaseDex | `Lˈˑ/ˉי;` | 4 | 1 |
| 79 | `epay_alipay_enable` | DonationDex | `Lˎʿ/ٴᐧ;` | 4 | 1 |
| 80 | `exit_room_autoban_enable` | BaseDex | `Lˈˑ/ᴵʽ;` | 3 | 1 |
| 81 | `exit_room_notice_enable` | BaseDex | `Lˈˑ/ˋᴵ;` | 6 | 0 |
| 82 | `exit_room_sendmsg_enable` | BaseDex | `Lˈˑ/ᴵʽ;` | 3 | 0 |
| 83 | `f_rp_threshold_reply_mt_enable` | BaseDex | `Lˈˑ/ٴˋ;` | 3 | 1 |
| 84 | `f_rp_threshold_reply_rp_enable` | BaseDex | `Lˈˑ/ٴˋ;` | 3 | 1 |
| 85 | `fake_amount_enable` | BaseDex | `Lˈˑ/ٴˋ;` | 5 | 2 |
| 86 | `fake_comments_enable` | BaseDex | `Lˈˑ/ˑـ;` | 3 | 1 |
| 87 | `fake_contacts_count_enable` | BaseDex | `Lˈˑ/ᵢי;` | 2 | 0 |
| 88 | `fake_friendreq_amount_enable` | BaseDex | `Lˈˑ/ᵢי;` | 2 | 0 |
| 89 | `fake_gps_enable` | BaseDex | `Lˈˑ/ˉᐧ;` | 3 | 1 |
| 90 | `fake_moment_forward_enable` | BaseDex | `Lˈˑ/ⁱʾ;` | 3 | 0 |
| 91 | `fake_owner_ban_enable` | BaseDex | `Lˈˑ/ᴵʽ;` | 3 | 1 |
| 92 | `fake_region_enable` | BaseDex | `Lˈˑ/ˉᐧ;` | 3 | 1 |
| 93 | `fast_announce_enable` | BaseDex | `Lˈˑ/ˋᴵ;` | 3 | 1 |
| 94 | `fast_switch_enable` | BaseDex | `Lˈˑ/ˉᐧ;` | 3 | 1 |
| 95 | `favorite_forward_enable` | BaseDex | `Lˈˑ/ـʼ;` | 13 | 0 |
| 96 | `float_video_enable` | BaseDex | `Lˈˑ/ˉᐧ;` | 4 | 1 |
| 97 | `force_tablet_mode_enable` | BaseDex | `Lˈˑ/ˉᐧ;` | 4 | 1 |
| 98 | `friendcard_forward_enable` | BaseDex | `Lˈˑ/ـʼ;` | 3 | 0 |
| 99 | `friendreq_notif_enable` | BaseDex | `Lʻʾ/ʽᵢ;` | 5 | 1 |
| 100 | `grab_red_packet_delay_enable` | BaseDex | `Lˈˑ/ʾˈ;` | 5 | 0 |
| 101 | `grab_red_packet_enable` | BaseDex | `Lˈˑ/ˏˑ;` | 6 | 0 |
| 102 | `grab_red_packet_filter_notopen_enable` | BaseDex | `Lˈˑ/ʼˋ;` | 9 | 1 |
| 103 | `grab_red_packet_filter_onlyopen_enable` | BaseDex | `Lˈˑ/ʼˋ;` | 9 | 1 |
| 104 | `grab_red_packet_master_enable` | BaseDex | `Lˈˑ/ᵎᵔ;` | 7 | 1 |
| 105 | `grab_red_packet_mute_enable` | BaseDex | `Lˈˑ/ˏˑ;` | 3 | 0 |
| 106 | `grab_red_packet_notprivate_enable` | BaseDex | `Lˈˑ/ٴˋ;` | 5 | 0 |
| 107 | `grab_red_packet_notself_enable` | BaseDex | `Lˈˑ/ˏˑ;` | 3 | 0 |
| 108 | `grab_red_packet_random_delay_enable` | BaseDex | `Lˈˑ/ʾˈ;` | 7 | 0 |
| 109 | `headsup_enable` | BaseDex | `Lˈˑ/ˏˑ;` | 2 | 0 |
| 110 | `hidden_chat_menu_items_enable` | BaseDex | `Lˈˑ/ˑˈ;` | 3 | 1 |
| 111 | `ignore_mute_enable` | BaseDex | `Lˈˑ/ˏˑ;` | 2 | 0 |
| 112 | `img_to_friend_forward_enable` | BaseDex | `Lˈˑ/ـʼ;` | 2 | 0 |
| 113 | `invite_member_shortcut_enable` | BaseDex | `Lˈˑ/ˋᴵ;` | 6 | 1 |
| 114 | `keyword_notification_enable` | BaseDex | `Lᐧʿ/ʾˎ;` | 2 | 0 |
| 115 | `like_only_enable` | BaseDex | `Lˈˑ/ˊˑ;` | 3 | 1 |
| 116 | `like_only_once_per_day_enable` | BaseDex | `Lˈˑ/ⁱʾ;` | 2 | 0 |
| 117 | `log_to_file_enable` | DonationDex | `Lᐧי/ʿᐧ;` | 2 | 1 |
| 118 | `manual_select_blocked_contact_enable` | BaseDex | `Lˈˑ/ᵎᵎ;` | 5 | 2 |
| 119 | `mass_repeat_sns_enable` | BaseDex | `Lˈˑ/ⁱʾ;` | 2 | 0 |
| 120 | `mod_cmd_enable` | BaseDex | `Lˈˑ/ˋᴵ;` | 3 | 0 |
| 121 | `mod_invite_only_enable` | BaseDex | `Lˈˑ/ᵢﹳ;` | 1 | 1 |
| 122 | `modify_steps_enable` | BaseDex | `Lˈˑ/ˉᐧ;` | 3 | 1 |
| 123 | `modify_steps_max_enable` | BaseDex | `Lˈˑ/ˉᐧ;` | 3 | 1 |
| 124 | `module_load_enable` | CoreDex | `Lc/ˋ/ﹶˉ;` | 1 | 1 |
| 125 | `moments_container_enable` | BaseDex | `Lˈˑ/ⁱʾ;` | 5 | 1 |
| 126 | `moments_fast_forward_enable` | BaseDex | `Lᐧʿ/ﹶᵔ;` | 1 | 0 |
| 127 | `moments_forward_enable` | BaseDex | `Lᐧʿ/ﾞﹶ$ʿᵢ;` | 14 | 2 |
| 128 | `moments_notification_enable` | BaseDex | `Lᐧʿ/ᵢˈ;` | 1 | 0 |
| 129 | `moments_post_message_enable` | BaseDex | `Lˈˑ/ⁱʾ;` | 3 | 1 |
| 130 | `msg_recall_notification_enable` | BaseDex | `Lᐧʿ/ٴٴ;` | 2 | 0 |
| 131 | `multi_broadcast_forward_enable` | BaseDex | `Lˈˑ/ـʼ;` | 4 | 0 |
| 132 | `multi_image_forward_enable` | BaseDex | `Lˈˑ/ˊˉ;` | 5 | 1 |
| 133 | `multi_selection_auto_forward_enable` | BaseDex | `Lʻʾ/ᵎᵔ;` | 5 | 0 |
| 134 | `multi_voice_forward_enable` | BaseDex | `Lˈˑ/ـʼ;` | 4 | 0 |
| 135 | `multiple_at_ban_enable` | BaseDex | `Lˈˑ/ᴵʽ;` | 3 | 1 |
| 136 | `mute_enable` | BaseDex | `Lˈˑ/ˏˑ;` | 2 | 0 |
| 137 | `mute_notifications_enable` | BaseDex | `Lˈˑ/ˈˊ;` | 1 | 0 |
| 138 | `name_change_ban_enable` | BaseDex | `Lˈˑ/ᴵʽ;` | 3 | 1 |
| 139 | `nearby_found_enable` | BaseDex | `Lˈˑ/ٴᐧ;` | 1 | 1 |
| 140 | `new_comment_notification_enable` | BaseDex | `Lᐧʿ/ᵢˈ;` | 1 | 0 |
| 141 | `nickname_change_notif_enable` | BaseDex | `Lˈˑ/ˋᴵ;` | 3 | 0 |
| 142 | `nonfriend_reply_enable` | BaseDex | `Lʽᵎ/ʽﹳ;` | 3 | 1 |
| 143 | `notification_enable` | BaseDex | `Lˈˑ/ٴʻ;` | 3 | 0 |
| 144 | `pat_all_enable` | BaseDex | `Lˈˑ/ˉי;` | 2 | 0 |
| 145 | `persistent_special_mode_enable` | BaseDex | `Lˈˑ/ᵎᵔ;` | 6 | 1 |
| 146 | `play_voice_enable` | BaseDex | `Lˈˑ/ˉי;` | 2 | 0 |
| 147 | `prevent_at_enable` | BaseDex | `Lˈˑ/ˋᴵ;` | 3 | 1 |
| 148 | `prevent_update_enable` | BaseDex | `Lˈˑ/ﾞᐧ;` | 4 | 1 |
| 149 | `progress_notif_enable` | BaseDex | `Lˈˑ/ٴᐧ;` | 1 | 1 |
| 150 | `quote_enable` | BaseDex | `Lˈˑ/ˉᐧ;` | 3 | 1 |
| 151 | `radar_found_enable` | BaseDex | `Lˈˑ/ٴᐧ;` | 1 | 1 |
| 152 | `record_forward_enable` | BaseDex | `Lˈˑ/ˊˉ;` | 6 | 1 |
| 153 | `red_packet_compatibility_enable` | BaseDex | `Lˈˑ/ˋـ;` | 1 | 1 |
| 154 | `red_packet_msg_enable` | BaseDex | `Lˈˑ/ˏˑ;` | 3 | 0 |
| 155 | `red_packet_notif_only_enable` | BaseDex | `Lˎˉ/ʼˋ;` | 4 | 1 |
| 156 | `red_packet_notification_enable` | BaseDex | `Lˈˑ/ˏˑ;` | 4 | 0 |
| 157 | `remote_excl_rp_enable` | BaseDex | `Lʽᵎ/ﹳʽ;` | 1 | 0 |
| 158 | `remove_mention_limit_enable` | BaseDex | `Lˈˑ/ⁱʾ;` | 6 | 0 |
| 159 | `reply_sign_enable` | BaseDex | `Lˈˑ/ᐧ;` | 1 | 0 |
| 160 | `ringtone_enable` | BaseDex | `Lˈˑ/ᵢﹶ;` | 2 | 0 |
| 161 | `robot_interval_delay_enable` | BaseDex | `Lˈˑ/ᐧ;` | 1 | 0 |
| 162 | `robot_keyword_enable` | BaseDex | `Lʽᵎ/ʽﹳ;` | 2 | 0 |
| 163 | `room_manangement_enable` | BaseDex | `Lˈˑ/ˋᴵ;` | 8 | 1 |
| 164 | `rp_missed_toast_enable` | BaseDex | `Lˈˑ/ᵎᵔ;` | 4 | 0 |
| 165 | `rp_timeframe_enable` | BaseDex | `Lˈˑ/ˏˑ;` | 3 | 0 |
| 166 | `search_chat_history_enable` | BaseDex | `Lˈˑ/ˉי;` | 3 | 1 |
| 167 | `selective_copy_enable` | BaseDex | `Lˈˑ/ˉᐧ;` | 3 | 1 |
| 168 | `self_like_enable` | BaseDex | `Lˈˑ/ˑـ;` | 4 | 2 |
| 169 | `selflikes_autoselect_enable` | BaseDex | `Lˈˑ/ˑـ;` | 4 | 1 |
| 170 | `send_as_gif_enable` | BaseDex | `Lˈˑ/ˉי;` | 3 | 0 |
| 171 | `set_fake_transfer_amount_enable` | BaseDex | `Lˈˑ/ٴˋ;` | 4 | 1 |
| 172 | `show_comment_content_enable` | BaseDex | `Lˈˑ/ᵢˈ;` | 3 | 0 |
| 173 | `show_invite_info_enable` | BaseDex | `Lˈˑ/ᴵʽ;` | 3 | 0 |
| 174 | `show_mark_read_enable` | BaseDex | `Lˈˑ/ˑˈ;` | 2 | 0 |
| 175 | `show_realname_label_enable` | BaseDex | `Lˈˑ/ˋᴵ;` | 4 | 0 |
| 176 | `sight_forward_large_video_enable` | BaseDex | `Lˈˑ/ـʼ;` | 8 | 0 |
| 177 | `sight_front_camera_enable` | BaseDex | `Lʻʾ/ʿᵔ;` | 4 | 0 |
| 178 | `sight_use_front_camera_enable` | BaseDex | `Lˈˑ/ˉᐧ;` | 6 | 1 |
| 179 | `sns_auto_export_enable` | BaseDex | `Lˈˑ/ⁱʾ;` | 2 | 1 |
| 180 | `sns_auto_forward_to_chat_enable` | BaseDex | `Lᐧʿ/ﾞﹶ$ʿᵢ;` | 2 | 0 |
| 181 | `sns_block_enable` | BaseDex | `Lˈˑ/ⁱʾ;` | 4 | 1 |
| 182 | `sns_export_enable` | BaseDex | `Lˈˑ/ⁱʾ;` | 2 | 0 |
| 183 | `sns_keyword_notification_enable` | BaseDex | `Lᐧʿ/ﹶᵔ;` | 1 | 0 |
| 184 | `sns_sync_enable` | BaseDex | `Lˈˑ/ⁱʾ;` | 5 | 1 |
| 185 | `song_robot_enable` | BaseDex | `Lˈˑ/ᐧ;` | 1 | 0 |
| 186 | `songrobot_self_enable` | BaseDex | `Lˈˑ/ᐧ;` | 1 | 0 |
| 187 | `tail_mode_enable` | BaseDex | `Lˈˑ/ˑˈ;` | 3 | 0 |
| 188 | `text_max_length_ban_enable` | BaseDex | `Lˈˑ/ᴵʽ;` | 4 | 2 |
| 189 | `themes_enable` | ? | `?` | 0 | 0 |
| 190 | `timeline_sync_enable` | BaseDex | `Lˈˑ/ⁱʾ;` | 6 | 2 |
| 191 | `total_amount_notification_enable` | BaseDex | `Lˈˑ/ٴˋ;` | 6 | 1 |
| 192 | `transfer_money_notification_enable` | BaseDex | `Lˈˑ/ٴˋ;` | 6 | 1 |
| 193 | `transfer_money_reply_enable` | BaseDex | `Lˈˑ/ٴˋ;` | 3 | 1 |
| 194 | `tts_enable` | BaseDex | `Lˈˑ/ٴٴ;` | 11 | 2 |
| 195 | `tts_send_mode_enable` | BaseDex | `Lˈˑ/ٴٴ;` | 4 | 1 |
| 196 | `tts_shortcut_enable` | BaseDex | `Lˈˑ/ٴٴ;` | 4 | 1 |
| 197 | `url_open_browser_enable` | BaseDex | `Lˈˑ/ˑˈ;` | 3 | 0 |
| 198 | `vibrate_enable` | BaseDex | `Lˈˑ/ᵢﹶ;` | 2 | 0 |
| 199 | `videocall_general_incoming_ringtone_enable` | BaseDex | `Lᐧʿ/ˉﹶ;` | 1 | 0 |
| 200 | `videocall_general_outgoing_ringtone_enable` | BaseDex | `Lᐧʿ/ˉﹶ;` | 1 | 0 |
| 201 | `videocall_ringtone_enable` | BaseDex | `Lᐧʿ/ˉﹶ;` | 1 | 0 |
| 202 | `voice_duration_change_enable` | BaseDex | `Lˈˑ/ﾞᐧ;` | 3 | 1 |
| 203 | `voice_forward_enable` | BaseDex | `Lˈˑ/ـʼ;` | 3 | 0 |
| 204 | `voice_wrong_length_enable` | BaseDex | `Lˈˑ/ˉי;` | 3 | 1 |
| 205 | `wakelock_enable` | BaseDex | `Lˈˑ/ﾞᐧ;` | 3 | 1 |
| 206 | `warning_enable` | BaseDex | `Lˈˑ/ᵢﹳ;` | 1 | 1 |
| 207 | `werun_autolike_enable` | BaseDex | `Lˈˑ/ˉᐧ;` | 3 | 1 |
| 208 | `whitelist_enable` | BaseDex | `Lˈˑ/ᴵʽ;` | 3 | 1 |
| 209 | `zombie_notif_enable` | BaseDex | `Lʻʾ/ⁱᵔ;` | 5 | 0 |


### 1.8 209 个 `*_enable` 键按设置分组归类

把 1.7 的 209 个开关按「所属设置页（菜单分组）」归类。判定方法：设置页构建方法的签名含 `LinearLayout`（即 `ˉˑ(Landroid/widget/LinearLayout;Landroid/view/Menu;ZZZ)V` / `ᵎᵔ(LinearLayout)V`），一个 `_enable` 键归属于**引用它、且键数最少（最具体）**的那个设置页类。

- **118 键**能归到具体设置页（22 个页面类，见下）；
- **91 键**不以设置页形式渲染，是父功能读取的子开关/内部开关（单列）。
- 分组标签由各页解码出的标题串 + 键的域前缀人工归纳；页面类名是 dex 里的原始混淆名。
- 生成脚本：`data/tmp/_enable_groups.py`（产出 `_enable_groups.json`）、`_enable_grouped.py`（产出本节）。

#### 按设置页（菜单分组）归类

**群管理 · 禁止/踢人（chatroom ban）**  
`BaseDex|Lˈˑ/ᵢﹳ;`（23 键）

| 设置键 |
|---|
| `auto_kick_keyword_enable` |
| `autoban_enable` |
| `chatroom_app_ban_enable` |
| `chatroom_app_ban_warning_enable` |
| `chatroom_article_ban_enable` |
| `chatroom_article_ban_warning_enable` |
| `chatroom_ban_sendmsg_enable` |
| `chatroom_friendcard_ban_enable` |
| `chatroom_friendcard_ban_warning_enable` |
| `chatroom_images_ban_enable` |
| `chatroom_images_ban_warning_enable` |
| `chatroom_keyword_ban_warning_enable` |
| `chatroom_qrcode_ban_enable` |
| `chatroom_qrcode_ban_warning_enable` |
| `chatroom_repeat_ban_enable` |
| `exit_room_autoban_enable` |
| `fake_owner_ban_enable` |
| `mod_invite_only_enable` |
| `multiple_at_ban_enable` |
| `name_change_ban_enable` |
| `text_max_length_ban_enable` |
| `warning_enable` |
| `whitelist_enable` |

**杂项 · 界面/伪装（fake gps/region、悬浮视频等）**  
`BaseDex|Lˈˑ/ʽי;`（13 键）

| 设置键 |
|---|
| `add_actionbar_items_enable` |
| `custom_dice_enable` |
| `fake_gps_enable` |
| `fake_region_enable` |
| `fast_switch_enable` |
| `float_video_enable` |
| `force_tablet_mode_enable` |
| `modify_steps_enable` |
| `modify_steps_max_enable` |
| `quote_enable` |
| `selective_copy_enable` |
| `sight_use_front_camera_enable` |
| `werun_autolike_enable` |

**朋友圈 · 自动点赞/评论**  
`BaseDex|Lˈˑ/ˑˏ;`（12 键）

| 设置键 |
|---|
| `auto_comment_allowed_filter_enable` |
| `auto_comment_enable` |
| `auto_comment_like_filter_enable` |
| `auto_comment_only_enable` |
| `auto_comment_timeframe_enable` |
| `auto_like_allowed_filter_enable` |
| `auto_like_timeframe_enable` |
| `comment_only_once_per_day_enable` |
| `fake_comments_enable` |
| `like_only_enable` |
| `self_like_enable` |
| `selflikes_autoselect_enable` |

**群聊 · 自动进群/容器**  
`BaseDex|Lˈˑ/ˊᵎ;`（10 键）

| 设置键 |
|---|
| `auto_exit_chatroom_enable` |
| `autojoin_openim_chatroom_enable` |
| `autojoinchatroom_delay_enable` |
| `autojoinqr_delay_enable` |
| `chatroom_container_all_enable` |
| `chatroom_container_mute_enable` |
| `chatroom_container_own_enable` |
| `chatroom_container_public_enable` |
| `chatroom_container_tag_enable` |
| `chatroom_container_work_enable` |

**红包/转账 · 确认与伪装金额**  
`BaseDex|Lˈˑ/ʻٴ;`（9 键）

| 设置键 |
|---|
| `confirm_transfer_delay_enable` |
| `confirm_transfer_enable` |
| `confirm_transfer_random_delay_enable` |
| `confirm_transfer_specific_enable` |
| `fake_amount_enable` |
| `set_fake_transfer_amount_enable` |
| `transfer_money_notification_enable` |
| `transfer_money_reply_enable` |
| `tts_enable` |

**朋友圈（moments）**  
`BaseDex|Lˈˑ/ˊˋ;`（8 键）

| 设置键 |
|---|
| `auto_comment_like_filter_enable` |
| `moments_container_enable` |
| `moments_forward_enable` |
| `moments_post_message_enable` |
| `self_like_enable` |
| `sns_auto_export_enable` |
| `sns_block_enable` |
| `timeline_sync_enable` |

**联系人 · 自动备注/摇一摇**  
`BaseDex|Lˈˑ/ٴᐧ;`（8 键）

| 设置键 |
|---|
| `auto_remark_enable` |
| `auto_shake_friend_finder_enable` |
| `contact_chatroom_enable` |
| `friendreq_notif_enable` |
| `manual_select_blocked_contact_enable` |
| `nearby_found_enable` |
| `progress_notif_enable` |
| `radar_found_enable` |

**群管理 · 禁止类（chatroom ban）**  
`BaseDex|Lᐧʿ/ˎʿ;`（8 键）

| 设置键 |
|---|
| `auto_kick_keyword_enable` |
| `chatroom_app_ban_enable` |
| `chatroom_article_ban_enable` |
| `chatroom_friendcard_ban_enable` |
| `chatroom_images_ban_enable` |
| `chatroom_qrcode_ban_enable` |
| `chatroom_repeat_ban_enable` |
| `text_max_length_ban_enable` |

**聊天过滤（filterchat）**  
`BaseDex|Lˈˑ/ˋﹳ;`（6 键）

| 设置键 |
|---|
| `auto_transcribe_mode_enable` |
| `encrypted_mode_enable` |
| `hidden_chat_menu_items_enable` |
| `persistent_special_mode_enable` |
| `search_chat_history_enable` |
| `voice_wrong_length_enable` |

**群管理（room management）**  
`BaseDex|Lˈˑ/ˈـ;`（5 键）

| 设置键 |
|---|
| `chatroom_custom_at_enable` |
| `fast_announce_enable` |
| `invite_member_shortcut_enable` |
| `prevent_at_enable` |
| `room_manangement_enable` |

**自动回复（autoreply）**  
`BaseDex|Lˈˑ/ˆˉ;`（4 键）

| 设置键 |
|---|
| `ad_sender_enable` |
| `autoreply_auto_enable` |
| `autoreply_master_enable` |
| `nonfriend_reply_enable` |

**消息/语音 · 防撤回等**  
`BaseDex|Lˈˑ/ˊˆ;`（4 键）

| 设置键 |
|---|
| `disable_wechat_ads_enable` |
| `prevent_update_enable` |
| `voice_duration_change_enable` |
| `wakelock_enable` |

**红包（red packet）**  
`BaseDex|Lˈˑ/ˋـ;`（4 键）

| 设置键 |
|---|
| `click_red_packet_enable` |
| `grab_red_packet_master_enable` |
| `red_packet_compatibility_enable` |
| `red_packet_notif_only_enable` |

**TTS 语音**  
`BaseDex|Lˈˑ/ˏᵔ;`（4 键）

| 设置键 |
|---|
| `auto_tts_enable` |
| `tts_enable` |
| `tts_send_mode_enable` |
| `tts_shortcut_enable` |

**转发（forward）**  
`BaseDex|Lˈˑ/ʽᐧ;`（3 键）

| 设置键 |
|---|
| `f_rp_threshold_reply_mt_enable` |
| `f_rp_threshold_reply_rp_enable` |
| `total_amount_notification_enable` |

**朋友圈同步（moments/sns）**  
`BaseDex|Lˈˑ/ᐧˊ;`（3 键）

| 设置键 |
|---|
| `moments_forward_enable` |
| `sns_sync_enable` |
| `timeline_sync_enable` |

**多选/录音转发**  
`BaseDex|Lˈˑ/ˊﹳ;`（2 键）

| 设置键 |
|---|
| `multi_image_forward_enable` |
| `record_forward_enable` |

**抢红包（grab red packet）**  
`BaseDex|Lᐧʿ/ˎᵔ;`（2 键）

| 设置键 |
|---|
| `grab_red_packet_filter_notopen_enable` |
| `grab_red_packet_filter_onlyopen_enable` |

**模块自身（自动更新/日志）**  
`DonationDex|Lᐧי/ᵢ;`（2 键）

| 设置键 |
|---|
| `autoupdate_enable` |
| `log_to_file_enable` |

**手动选择屏蔽联系人**  
`BaseDex|Lˎˉ/ٴᵔ;`（1 键）

| 设置键 |
|---|
| `manual_select_blocked_contact_enable` |

**红包/转账 · 伪装金额**  
`BaseDex|Lˈˑ/ʻʽ;`（1 键）

| 设置键 |
|---|
| `fake_amount_enable` |

**黑名单（blacklist）**  
`BaseDex|Lˈˑ/ʻﹳ;`（1 键）

| 设置键 |
|---|
| `blacklist_enable` |

#### 未被设置页直接渲染的 91 个子开关

这些键不以 `LinearLayout` 设置页形式出现，通常是父功能读取的子开关/内部开关：

| 设置键 | 定义类（首个） |
|---|---|
| `accept_all_req_enable` | `Lˈˑ/ᵢי;` |
| `article_open_browser_enable` | `Lˈˑ/ˑˈ;` |
| `at_notification_enable` | `Lˈˑ/ˋᴵ;` |
| `audiocall_general_incoming_ringtone_enable` | `Lᐧʿ/ˉﹶ;` |
| `audiocall_general_outgoing_ringtone_enable` | `Lᐧʿ/ˉﹶ;` |
| `auto_accept_chatroom_invite_qr_enable` | `Lʻʾ/יˋ;` |
| `auto_accept_req_enable` | `Lˈˑ/ᵢי;` |
| `auto_checkin_enable` | `Lˈˑ/ᴵʽ;` |
| `auto_like_enable` | `Lˈˑ/ⁱʾ;` |
| `auto_translate_mode_enable` | `Lˈˑ/ˉי;` |
| `autoreply_enable` | `Lʽᵎ/ʽﹳ;` |
| `autoreply_r_delay_enable` | `Lˈˑ/ᐧ;` |
| `autoreply_timeframe_enable` | `Lˈˑ/ᐧ;` |
| `autoresponse_keywords_enable` | `Lˈˑ/ˎﹶ;` |
| `block_nudging_enable` | `Lˈˑ/ˉי;` |
| `broadcast_forward_enable` | `Lˈˑ/ـʼ;` |
| `chatcontainer_enable` | `Lʽᵎ/ⁱٴ;` |
| `chatroom_autoreply_member_enable` | `Lˈˑ/ᐧ;` |
| `chatroom_intro_enable` | `Lˈˑ/ᴵʽ;` |
| `chatroom_invite_allow_by_identity_enable` | `Lˈˑ/ـٴ;` |
| `checkin_enable` | `Lˈˑ/ᴵʽ;` |
| `comment_recall_notification_enable` | `Lᐧʿ/ʻʽ;` |
| `config_grab_reply_enable` | `Lˈˑ/ˏˑ;` |
| `custom_notification_enable` | `Lᐧʿ/ᵢˈ;` |
| `custom_nudging_msg_enable` | `Lˈˑ/ˉי;` |
| `epay_alipay_enable` | `Lˎʿ/ٴᐧ;` |
| `exit_room_notice_enable` | `Lˈˑ/ˋᴵ;` |
| `exit_room_sendmsg_enable` | `Lˈˑ/ᴵʽ;` |
| `fake_contacts_count_enable` | `Lˈˑ/ᵢי;` |
| `fake_friendreq_amount_enable` | `Lˈˑ/ᵢי;` |
| `fake_moment_forward_enable` | `Lˈˑ/ⁱʾ;` |
| `favorite_forward_enable` | `Lˈˑ/ـʼ;` |
| `friendcard_forward_enable` | `Lˈˑ/ـʼ;` |
| `grab_red_packet_delay_enable` | `Lˈˑ/ʾˈ;` |
| `grab_red_packet_enable` | `Lˈˑ/ˏˑ;` |
| `grab_red_packet_mute_enable` | `Lˈˑ/ˏˑ;` |
| `grab_red_packet_notprivate_enable` | `Lˈˑ/ٴˋ;` |
| `grab_red_packet_notself_enable` | `Lˈˑ/ˏˑ;` |
| `grab_red_packet_random_delay_enable` | `Lˈˑ/ʾˈ;` |
| `headsup_enable` | `Lˈˑ/ˏˑ;` |
| `ignore_mute_enable` | `Lˈˑ/ˏˑ;` |
| `img_to_friend_forward_enable` | `Lˈˑ/ـʼ;` |
| `keyword_notification_enable` | `Lᐧʿ/ʾˎ;` |
| `like_only_once_per_day_enable` | `Lˈˑ/ⁱʾ;` |
| `mass_repeat_sns_enable` | `Lˈˑ/ⁱʾ;` |
| `mod_cmd_enable` | `Lˈˑ/ˋᴵ;` |
| `module_load_enable` | `Lc/ˋ/ﹶˉ;` |
| `moments_fast_forward_enable` | `Lᐧʿ/ﹶᵔ;` |
| `moments_notification_enable` | `Lᐧʿ/ᵢˈ;` |
| `msg_recall_notification_enable` | `Lᐧʿ/ٴٴ;` |
| `multi_broadcast_forward_enable` | `Lˈˑ/ـʼ;` |
| `multi_selection_auto_forward_enable` | `Lʻʾ/ᵎᵔ;` |
| `multi_voice_forward_enable` | `Lˈˑ/ـʼ;` |
| `mute_enable` | `Lˈˑ/ˏˑ;` |
| `mute_notifications_enable` | `Lˈˑ/ˈˊ;` |
| `new_comment_notification_enable` | `Lᐧʿ/ᵢˈ;` |
| `nickname_change_notif_enable` | `Lˈˑ/ˋᴵ;` |
| `notification_enable` | `Lˈˑ/ٴʻ;` |
| `pat_all_enable` | `Lˈˑ/ˉי;` |
| `play_voice_enable` | `Lˈˑ/ˉי;` |
| `red_packet_msg_enable` | `Lˈˑ/ˏˑ;` |
| `red_packet_notification_enable` | `Lˈˑ/ˏˑ;` |
| `remote_excl_rp_enable` | `Lʽᵎ/ﹳʽ;` |
| `remove_mention_limit_enable` | `Lˈˑ/ⁱʾ;` |
| `reply_sign_enable` | `Lˈˑ/ᐧ;` |
| `ringtone_enable` | `Lˈˑ/ᵢﹶ;` |
| `robot_interval_delay_enable` | `Lˈˑ/ᐧ;` |
| `robot_keyword_enable` | `Lʽᵎ/ʽﹳ;` |
| `rp_missed_toast_enable` | `Lˈˑ/ᵎᵔ;` |
| `rp_timeframe_enable` | `Lˈˑ/ˏˑ;` |
| `send_as_gif_enable` | `Lˈˑ/ˉי;` |
| `show_comment_content_enable` | `Lˈˑ/ᵢˈ;` |
| `show_invite_info_enable` | `Lˈˑ/ᴵʽ;` |
| `show_mark_read_enable` | `Lˈˑ/ˑˈ;` |
| `show_realname_label_enable` | `Lˈˑ/ˋᴵ;` |
| `sight_forward_large_video_enable` | `Lˈˑ/ـʼ;` |
| `sight_front_camera_enable` | `Lʻʾ/ʿᵔ;` |
| `sns_auto_forward_to_chat_enable` | `Lᐧʿ/ﾞﹶ$ʿᵢ;` |
| `sns_export_enable` | `Lˈˑ/ⁱʾ;` |
| `sns_keyword_notification_enable` | `Lᐧʿ/ﹶᵔ;` |
| `song_robot_enable` | `Lˈˑ/ᐧ;` |
| `songrobot_self_enable` | `Lˈˑ/ᐧ;` |
| `tail_mode_enable` | `Lˈˑ/ˑˈ;` |
| `themes_enable` | `?` |
| `url_open_browser_enable` | `Lˈˑ/ˑˈ;` |
| `vibrate_enable` | `Lˈˑ/ᵢﹶ;` |
| `videocall_general_incoming_ringtone_enable` | `Lᐧʿ/ˉﹶ;` |
| `videocall_general_outgoing_ringtone_enable` | `Lᐧʿ/ˉﹶ;` |
| `videocall_ringtone_enable` | `Lᐧʿ/ˉﹶ;` |
| `voice_forward_enable` | `Lˈˑ/ـʼ;` |
| `zombie_notif_enable` | `Lʻʾ/ⁱᵔ;` |



---

## 二、FKZ_WX_DATA 授权数据库

### 2.1 表结构

四张同构表 `DATA` / `DATA1` / `DATA2` / `DATA_VIP`：

```sql
CREATE TABLE DATA(_ID INTEGER PRIMARY KEY NOT NULL,
    ACCOUNT TEXT, TAG TEXT, TYPE TEXT, VALUE TEXT, DATA BLOB)
```

- `ACCOUNT`：微信 wxid（或 `+NO_ID+`）
- `DATA_VIP`：捐赠用户数据
- `TYPE`：`STRING / BOOLEAN / INT / JSON / JSON_ARRAY`

### 2.2 三层加密链路

**第一层：AES-256-CBC（PKCS7，零 IV）**

- 密钥：`31d019ea56d574133508b10d944b413c4fb9eb58a90e1a015c62729f7459c66d`
- VALUE 列为 Base64 编码
- 微X 端派生方式（`C0753.m4499`）：`MD5(seed UTF-8)` 作 AES key；
  seed = `md5_hex_nopad(微X证书DER) + "9n4hZkF"`（`9n4hZkF` 为固定盐，来自字符串池 `-268301725359106L`）
- 读取路径：`C0726(context2=微信context, modulePath)` → `m4465()` 读取自身 APK `classes.dex` 条目的证书 DER → `m4466()` md5（无零填充 hex）→ 拼 `9n4hZkF` → `C0753.m4498` 解密

**第二层：RSA-2048 (PKCS1 v1.5)**

- 服务器私钥签名，客户端公钥验签（`rsa/ecb/pkcs1`）
- `verifier6` / `params_S6` / `LIC` 第一层解开后是 Base64 的 256 字节 RSA 块
- 公钥运算还原明文（`pow(ct, e, n)` → 去掉 `00 01 FF..FF 00` 填充）：
  ```
  verifier6  = Zezehai001,196e91507cf,3edf036bb907b21e187004374efea0c38,verifier6,196e91507cf
  params_S6  = shoujiajie3407,8.0.49,63ea1210af6132957b08bb606ae9fb0ff,param,196ee47da01
  LIC        = shoujiajie3407,b575fbf,845f01bf180ba22f09e7b1c179a3984a3,95318,196ee47d9fe
  ```
- 统一格式：`账号,字段/版本,授权key hash,类型,时间戳`

**明文字段**

```json
LatestVersions = {"fp_themes":"74","fp_sf":"4c","fp_af":"af","fp_vidurlparser":"1f",
  "fp_mf":"84","fp_donation":"48","fp_xv":"1ef","fp_base":"207",
  "meta":"1902e00b167","string":"18fe309bb74","h_p":"18f8c15f5c1",
  "lib":"9","core":"d4","apk":"42,2.2,821452f9"}
```

### 2.3 字段含义

| TAG | 含义 |
|---|---|
| `verifier6` | 授权校验记录（RSA 签名：wxid+时间戳+hash） |
| `LIC` | 授权凭证（RSA 签名：账号+key hash+序号+时间） |
| `params_S6` | 授权参数（RSA 签名：账号+版本+key hash） |
| `valid` / `s_valid` | 授权是否有效（AES 加密的 true/false） |
| `permaban` / `random_fail` / `wx_ban_id` | 封禁状态、随机失败、封禁名单 |
| `app_check` / `system_app_check` | 反检测开关（Xposed/系统应用环境检测） |
| `latest_param` | 服务端下发最新版本号 |
| `LatestVersions` | 各功能 dex 指纹（防篡改） |
| `disable_features` | 服务端远程禁用功能（如 `emulator_check`） |
| `_fapps` | 竞品模块封杀列表：`com.hwf.jfsq, com.god.center, com.wsktek.center.lib, com.gxxc, com.qihoo.magic.xposey, com.yzrm.mm, com.aimajin.mo...` |
| `urls_wx7` 等 | 激活/校验服务器地址（本库中为空） |
| `usedKeys` / `wxExclApp` | 已用捐赠 key / 排除应用 |

### 2.4 服务器下发的封禁记录

```
wx_ban_id = ljw256, wxid_zlhfzy95t1gj22, q511068174
```

服务端按 wxid 下发封禁名单；授权 key hash `63ea1210af61...`（`shoujiajie3407` 的捐赠 key）。

### 2.5 最小可启动库（生成脚本对齐）

`scripts/generate_min_db.py` 用于给任意 wxid 生成一份能启动的 `FKZ_WX_DATA`。此前脚本发的是**错误的行集**（缺 `LIC/verifier6/LatestVersions/FPVersions/fp/fp_async`，多出 `s_valid/latest_param/permaban/...`），实机加载即失败。以下为反汇编四个 dex 后对齐的正确结论。

**（1）读表按 ACCOUNT 过滤**

`Lﹶˆ/ⁱʼ;->יˋ` 构造的查询是：

```sql
SELECT * FROM DATA WHERE ACCOUNT=? AND TAG=?
```

`ACCOUNT` 取 `Lﹶˆ/ⁱʼ;->ʿᵢ`（当前登录 wxid）。**ACCOUNT 必须等于当前登录 wxid**，否则整表读不到 → 启动失败。参考库文件名是 `...wxid_kcvrpkelhtj722`，但其 `ACCOUNT` 列是 `wxid_4533845336712`——文件名只是备忘，真正生效的是列值。

**（2）LIC 的三段结构**

`Lˎˉ/ˆᵔ;->ᵎᵔ`（`getLicData`）反汇编：

```
读 LIC → contains("#") → split("#") → array-length == 3（否则直接 return）
→ aget-object #2（第 3 段）→ Lﹶˆ/ʿᵔ;->ʿᵔ(段, iv) 解密 → new JSONArray → 逐项 getInt 进 HashSet<Integer>
```

即 `LIC = "<段0>#<段1>#<段2>"`：

- 段 0：`encode_blob("LIC:" + wxid)`（见下）
- 段 1:单字符标记。参考库/最小库 = `f`(frozen,离线预置),真机在线授权后微X 会改写成 `T`(token,已在线校验)。仅 4533 是 `T`。此字符**不参与**我们自己 hook 的授权判定,是微X 的状态位。
- 段 2:AES 密文。反汇编确认:`key = SHA-256(<当前 wxid> UTF-8 原文,非 hex)`、`AES/CBC/PKCS7Padding`、零 IV;解密后是授权/付费档位列表的 JSON 数组,**两个真实授权库(4533、722)明文都是 `[1]`**。

**⚠ 段 2 必须按当前 wxid 现算,不能照抄参考库字节**

`generate_min_db.py` 早期版本把段 2 写死成 722 的密文(`rBaijxThxo3WNaSFx04a1w==`)。因为 key 是 `SHA-256(wxid)`,同一段密文换个账号解出来就是乱码:

```
密文 rBaijxThxo3WNaSFx04a1w== 用 key = SHA-256(该账号 wxid) 解密:
  wxid_kcvrpkelhtj722 -> b'[1]'                 OK
  wxid_4pc5e5vgpa2f29 -> 乱码                    FAIL
  wxid_hjnpj26slcvs22 -> 乱码                    FAIL
```

乱码会让 `new JSONArray(...)` 抛异常 -> `getLicData` 走异常分支 -> 微X 判定该账号未授权 ->**不显示 `[VIP][专业]`,菜单为空**。这就是「4533 能加载、f29/hjn 加载不出来」的根因。
修复后每个 wxid 的段 2 各不相同:

```
wxid_4533845336712   -> ZAHfOuouCN64P1Xg8UjnmQ==
wxid_kcvrpkelhtj722  -> rBaijxThxo3WNaSFx04a1w==
wxid_4pc5e5vgpa2f29  -> 9R4C+tqk57kHdU7dsaoEAQ==
wxid_hjnpj26slcvs22  -> 64mJ0d+Cg+prDxW++9abUw==
```

> 注意:下面第 (4) 条「授权比对只用段 0」说的是**我们自己模块** `CallMethodBypassHook` 的绕过路径;微X **自己**的 `getLicData` 仍会解析段 2,写错照样挂。

**（3）LIC/verifier6 的 blob 编码（已逐字节复现）**

`CallMethodBypassHook.decodeLicenseBlob` 的逆运算：把 `"LIC:<wxid>"` / `"verifier6#D:<wxid>"` 编成「长度前缀 + 数字段」再 Base64：

```
对每个字符 i（明文长 N）：
    base = (ord(c) << 2) - ((i << 2) + N)
    取最小的 base+delta（delta∈0..3）使 >= 0
    nums[i] = (base+delta) ^ (i*i)
打包：每段写成  str(len(nums[i])) + nums[i]
再 base64
```

外层再套第一层 AES（`enc()`）。验证：对 `wxid_kcvrpkelhtj722` 生成，`verifier6` 与 `LIC` 均与参考库**逐字节相同**。

**（4）授权比对只用段 0**

`CallMethodBypassHook`（msgId 150/查询 0 与 6）取 `license.split("#")[0]` → `decodeLicenseBlob` → `"LIC:<user>"`，再与微X传入的 `userId` 比对。**段 2 不参与授权判定**（付费功能集合由 hook 用 58 项列表覆盖）。因此自建库只要段 0 写对登录 wxid、整体结构为 3 段即可启动。

**(5)正确行集(与参考库同构,10 行)**

> 多账号:同一设备多账号**共用一份** `FKZ_WX_DATA`,按 `ACCOUNT` 列区分。`generate_min_db.py wxid_a,wxid_b,wxid_c 输出.db` 即可一次写多个账号(每个 10 行)。关键是每个账号的 `LIC` 段 2 都必须按**自己的** wxid 现算。


| TAG | TYPE | 明文 |
|---|---|---|
| `hookFail` | BOOLEAN | `false` |
| `disclaimer_disable` | BOOLEAN | `true` |
| `is_new_user` | INT | `10` |
| `LatestVersions` | JSON | 见下方常量 |
| `FPVersions` | JSON | `{"themes":113,"donation":71,"base":525}` |
| `valid` | BOOLEAN | `true` |
| `fp` | STRING | `themes` |
| `fp_async` | STRING | `base,donation` |
| `LIC` | STRING | `enc(encode_blob("LIC:"+wxid) + "#f#" + lic_seg3(wxid))`,段 2 见 (2) |
| `verifier6` | STRING | `enc(encode_blob("verifier6#D:"+wxid))` |

`LatestVersions` 常量：

```json
{"fp_themes":"71","fp_sf":"4b","fp_af":"ab","fp_vidurlparser":"1e","fp_mf":"89",
 "fp_donation":"47","fp_xv":"1f2","fp_base":"20d","meta":"1902dffe702",
 "string":"18fe3f447ec","h_p":"18eec2d7db3","lib":"9","core":"cf","apk":"42,2.2,821452f9"}
```

> 说明：`LatestVersions`/`FPVersions`/`fp`/`fp_async` 由启动线程 `Lʻʾ/ٴˏ;->run` 读取，用于功能包下载/卸载判断；`LIC`/`verifier6` 供授权流程读取。旧的「LIC/verifier6 是 RSA 签名、可省略」注释是错的——它们是按 wxid 编码的，启动时会被读取。

**(5b)连锁反应:未授权 -> 功能包被清掉 -> 菜单空白**

段 2 写错时,微X 启动线程 `Lʻʾ/ٴˏ;->run`(含 `cleanup_files` / `unloadFeature` / `downloadFeaturePack` /
`LatestVersions` / `fp_*`)会走清理分支,把 `wx6_2.44` 里三个功能包删掉:

```
14e777717682cce8a53cfcb34a22d65   ->  BaseDex
802766a4a4bd401c145a57463274d4dd   ->  DonationDex
a89eaf67dc796cb3af54d94fac0198b   ->  ThemesDex
```

只留 `_c` / `_s` 边车文件,目录从 30 个变 27 个。logcat 对照:

```
有功能包: WeXposed: feature loaded: base 525 / donation 71 / themes 113    <- 正常
缺功能包: 只有 Found CoreDex/BaseDex/DonationDex/ThemesDex,无 feature loaded <- 空白
```

所以「删文件」不是微信或第三方行为,而是**微X 自己判定未授权后的清理**,与「无 VIP、无菜单」是同一根因的两个表现。修复后实测:

- 三个账号都显示 `[VIP][专业]`、菜单正常,重启微信依旧
- `wx6_2.44` 稳定 30 个文件,三个功能包 MD5 与参考一致(无删除)
- 微X 会补写状态行(f29 10->16、hjn 10->15),是**加载成功**的表现

> watcher 抓到 `com.tencent.mm:switch` 在切号时删文件,是「切号 -> 新账号未授权 -> cleanup」这条链的执行者,不是独立的外部删除源。

**(5c)部署产物已修正**

`data/FKZ_WX_DATA`(即 `wx6_2.44_auto.sh` / `微x恢复脚本3.4.sh` 实际部署的文件)原来也带着同样的坏段 2。已用修复后的 `lic_seg3` 重造 f29/hjn/722 三段(4533 的 365 行原样保留),现在四个账号的段 2 与实机工作状态**逐字节一致**:

```
wxid_4533845336712   -> ZAHfOuouCN64P1Xg8UjnmQ==   (seg1=T)
wxid_kcvrpkelhtj722  -> rBaijxThxo3WNaSFx04a1w==
wxid_4pc5e5vgpa2f29  -> 9R4C+tqk57kHdU7dsaoEAQ==
wxid_hjnpj26slcvs22  -> 64mJ0d+Cg+prDxW++9abUw==
```

> 若后续再有新账号加入,必须重新生成该账号的段 2,不能沿用旧行。

**（6）user_version 必须是 1（实机启动失败的真正原因）**

微X 的 DB helper `Lﹶˆ/ⁱʼ;` 继承 `SQLiteOpenHelper`，构造时 `(context, "FKZ_WX_DATA", factory, version=1)`（`<init>` 里 `const/4 #1`）。

- `onCreate` 执行 `CREATE TABLE DATA(...)`（**无 `IF NOT EXISTS`**）
- `onUpgrade` 执行 `DROP TABLE IF EXISTS DATA` 再 `onCreate`

`SQLiteOpenHelper` 用 `PRAGMA user_version` 判断版本。用 `sqlite3` 直接建库时 `user_version` 默认是 **0**，微X 打开后判定 `0 < 1` 需要升级/建表 → 执行 `CREATE TABLE DATA` → 表已存在 →

```
android.database.sqlite.SQLiteException: table DATA already exists (code 1 SQLITE_ERROR)
  while compiling: CREATE TABLE DATA(_ID INTEGER PRIMARY KEY NOT NULL, ACCOUNT TEXT, ...)
  at c.ⁱי.ˋ.ⁱי
```

日志（LSPosed）会刷出大量该异常，微X 功能菜单为空/不可用。

**修复**：生成脚本在写完行后执行 `PRAGMA user_version = 1`。参考库两份的 `user_version` 都是 1，脚本此前漏了这一步。

**（7）wxid 必须是微X 传入 hook 的真实 userId（菜单空的原因）**

`CallMethodBypassHook` 在 msgId 132 路径会把微X 传入的 `expectedUser` 以 `ModuleLogger.log(Base64(expectedUser))` 打到 LSPosed 日志。实机日志：

```
WxModuleHook-> d3hpZF80NTMzODQ1MzM2NzEy   # base64 解码 = wxid_4533845336712
```

即微X 传给 hook 的 `userId` 是**当前登录账号的完整 wxid**（`wxid_4533845336712`）。而 DB 行按 `ACCOUNT=? AND TAG=?` 查、LIC blob 里的 user 又必须与 `userId` 相等，所以：

- `ACCOUNT` 必须 = 该 userId
- `LIC` blob 必须编码 `"LIC:" + 该 userId`

若写成别的 wxid（例如猜的 `wxid_4pc5e5vgpa2f29`），DB 查不到行、授权比对失败 → 微X 设置界面能打开但**功能菜单为空**。

**取正确 wxid 的方法**：在 LSPosed 日志里搜 `WxModuleHook-> `，把后面的 base64 解码即得（也可用 `adb logcat | grep WxModuleHook`）。

---

## 三、WxModuleHook 1.2（破解补丁）

### 3.1 基本信息

- 包名 `wx.module.hook`，签名 `IKUN`（**非**微X作者签名）
- Xposed 模块，作用域 `com.tencent.mm`，仅 79KB / 1 个 classes.dex（63712 字节，10 个类，MD5 `76e18d3d5982e2976ef1eeb70d156101`）
- 入口 `assets/xposed_init` → `wx.module.hook.XposedInit`
- 同样的控制流混淆 + XOR 字符串加密（`m16/m100: sArr[i] ^ key`，key 按调用点散布；
  重建后对应 `ReflectBridgeA/B.decodeXor`）

**类归属（重要，避免与微X 混淆）**：补丁用单字母包名 `a/b/c`，与微X 的混淆命名空间不同。以下类**属于补丁**（在补丁的 classes.dex 里，**不在**微X 的任何 dex 里）：

| 补丁类 | 作用 |
|---|---|
| `Lwx/module/hook/XposedInit;` | 补丁入口 |
| `Lb/a;` | 组件描述列表容器（`WX_COMPONENTS`，4 项） |
| `Lb/b;` | dex 定位/文件路径（池 key 48914/17712） |
| `Lb/c;` | `InMemoryDexClassLoader` hook（池 key 7403/17407） |
| `Lc/a;` | 单组件注入器（池 key 52313） |
| `Lc/b;` | `CallMethod` 拦截 + 伪造授权（`BYPASS_POOL`，key 5559/55463，**58 项列表在此**） |
| `Lc/c;` | 另一处校验替换 hook |
| `Lc/۠۫۠;` `Lc/ۤ۠۫;` | 工具类（hash / XOR 解码 / 反射） |

对照：微X 2.44 的 `classes.dex` 是 2397988 字节、2829 类，入口 `com.fkzhang.wechatxposed.XposedInit`，native 桥 `com.fkzhang.xposed.hook.WxCoreLoader.CallMethod`；4 个功能 dex 里的组件入口是 `com.fkzhang.wxfeatures.*.Wrapper.Init` / `com.fkzhang.wechatxposedhooks.Wrapper.HookWrapper`。

### 3.2 工作原理（五步）

1. **拦截微X的代码加载**：挂钩 `dalvik.system.InMemoryDexClassLoader` 构造函数。微X 把加密功能代码解密进内存再加载，此模块在这一步截住
2. **识别微X组件**：在加载器里找 `com.fkzhang.wxfeatures.base.Wrapper.Init`、`com.fkzhang.wechatxposedhooks.Wrapper.HookWrapper`、donation、themes，区分 Base/Core/Donation/Themes 四个模块
3. **屏蔽在线校验**：替换**微X CoreDex 里的** `com.fkzhang.wechatxposedhooks.WxJniCoreBridge.CallMethod(I[Ljava/lang/Object;)`（`PUBLIC STATIC SYNCHRONIZED NATIVE`，实现在 native 库 `.so` 里）及 `process_metadata`、`updateLicense`、`delayed_check` 等方法，直接返回空。其日志自述：`banned polling verifier`、`banned check api request`、`banned updated tips`
4. **伪造授权**：校验结果强制返回 `true` / `unlimited` / 版本 `8.0.49`，把 58 个付费功能塞进授权列表（`fake_gps`、`fake_transfer_amount`、`zombie_auto_delete`、`export_contacts`、`sns_export`、`mass_sns_like` 等）。含一处 `startsWith("wxid_")` 判断，仅本地比较（详见 3.5）
5. **定位微X文件**：`ActivityThread.getSystemContext().createPackageContext("com.tencent.mm")` → `/data/data/com.tencent.mm/files`

### 3.3 隐私检查结论

- **无网络代码**：不引用任何网络类，无 URL
- **无文件写入**：不引用任何输出流
- **无敏感 API**：不调用 IMEI/手机号、通讯录、定位、剪贴板、已安装应用列表
- 唯一输出：`XposedBridge.log("WxModuleHook-> ...")`，写入 Xposed 日志
- 工具类（原 `C0000`/`C0001`，重建后为 `ReflectBridgeA`/`ReflectBridgeB`）封装的全部 API 已核对：字符串处理、Base64、Xposed 挂钩、反射——反射目标全部解密确认为微X内部类

**结论：补丁本体不读取也不上传隐私数据。**

### 3.4 配套脚本的真实风险（wx6_2.44_auto.sh）

脚本用于把 tar 部署到微信目录并写入授权数据库，但有两处危险操作：

```sh
chmod -R 777 "${WX_DIR}/wx6_2.44"     # 微信 files 目录
chmod -R 777 "$DB_DIR"                # 微信 databases 目录！
```

`/data/user/*/com.tencent.mm/databases` 里有微信聊天数据库 `EnMicroMsg.db`，`chmod -R 777` 使手机上任何应用都可读写——**这才是整套东西最大的隐私风险**。新版 Android 的 SELinux 可部分缓解，但已破坏微信自带隔离。若已执行，建议恢复权限。

---

### 3.5 付费功能列表为什么是 58 项

这个问题要分两层回答：**「58」这个数字来自哪里**，以及**这 58 个名字是不是微X 真正的付费功能**。

#### (1) 「58」来自补丁自己的字符串池，不是微X 的枚举

`c.b`（即 `Lc/b;`，含 `BYPASS_POOL` / key 5559 / 58 项列表）是**补丁 WxModuleHook 自己的类**，位于 **WxModuleHook-1.2.apk 的 `classes.dex`**（63712 字节，10 个类，MD5 `76e18d3d5982e2976ef1eeb70d156101`）。它**不在**微X 2.44 的 `classes.dex`（2397988 字节，2829 类）里，也不在 4 个功能 dex 里。

补丁 `c.b.beforeHookedMethod` 里，校验通过时执行：

```
setResult( decodeXor(f3, 145, 1106, 5559) )   // f3 = 补丁的 BYPASS_POOL（1251 项 short[]）
```

- `f3` 是补丁类 `Lc/b;` 的静态字段 `۬ۦۗ:[S`，1251 项，由 `<clinit>` 的 `fill-array-data` 写入（`[u2 ident=0x300][u2 elem_width=2][u4 size=1251][1251×int16]`）。
- 解码公式 `out[i] = (char)(pool[off+i] ^ key)`，key 是**字面量常量** `const/16 v0, #int 5559`（pc `0x38b0`，`move v4, v0` 后作为第 4 参数传入），不是算出来的。
- 调用点：`sget-object v15, Lc/b;.۬ۦۗ:[S` → `const/16 v12, #int 145` → `const/16 v8, #int 1106` → `invoke-static {v15, v12, v8, v4}, Lc/ۤ۠۫;.۬ۥۧ:([SIII)Ljava/lang/String;`（pc `0x015d`）。
- `off=145, len=1106` 解出 1106 个字符，恰好是逗号分隔的功能名列表；`split(",")` 得到 **58 项**（1106 字符、57 个逗号 + 1）。

**独立复现验证**（`data/tmp/_patchdec58.py`）：直接读补丁池 `۬ۦۗ`（payload 文件偏移 `0x3d18`，1251×int16）+ `pool[145+i] ^ 5559`，输出前 200 字符即
`remove_notice,priority_update,extra_df,send_raw_image,auto_comment_robot,text_rep_nickname,...`，`count(",")==57`、`len(split(","))==58`。所以「58」**就是补丁这段字符串按逗号切分的结果**，不是代码里数出来的 58 个分支，也不是微X 里的任何常量。

#### (2) 这 58 个名字确实是微X 的真实功能键（来自 4 个 dex）

虽然「58」这个数字是补丁定的，但这 58 个**名字**并非凭空捏造——它们全部是微X 4 个功能 dex 里真实存在的**设置键（feature key）**。用逐方法解密字符串映射（`data/tmp/_bdmethods.json` / `_coremethods.json` / `_donmethods.json`）核对，**58/58 全部命中**，分布为 BaseDex 55、CoreDex 5、DonationDex 4、ThemesDex 4（部分键跨 dex 复用）：

| 名字 | 命中 dex | 典型定义/使用类 |
|---|---|---|
| `fake_gps` | BaseDex | `Lˈˑ/ʽי;`、`Lˈˑ/ˈʽ;`、`Lˎˉ/ˑʽ;`、`Lᐧʿ/ˊˋ;` |
| `zombie_auto_delete` | BaseDex | `Lʻʾ/ⁱᵔ;`、`Lˈˑ/ٴᐧ;`、`Lˈˑ/ᵢי;` |
| `fake_transfer_amount` | BaseDex | `Lˈˑ/ʻٴ;`、`Lᐧʿ/ˆᴵ;`、`Lᐧʿ/ˉﹶ;` |
| `sns_export` / `export_contacts` | BaseDex | `Lˈˑ/ˊˋ;`、`Lᐧʿ/ﹶᵔ;` 等 |
| `themes` | CoreDex | `Lc/ⁱי/ᵔˆ;`、`Lc/ﹶˉ/ᴵᴵ;` |
| `extra_df` | CoreDex/DonationDex | `Lc/ﹶˉ/ᵔˉ;`、`Lˎʿ/ʼﾞ;` |
| `integrated_allowed` | CoreDex | `Lc/ﹶˉ/ᴵˉ;`、`Lc/ﹶˉ/ᵔˉ;` |
| `priority_update` | CoreDex | `Lc/ﹶˉ/ᵔˉ;`、`Lᐧי/ˑˋ;` |

这些键在 dex 里是**逐条分散**的开关名（常成对出现 `xxx` / `xxx_enable` / `xxx_...`，如 `modify_steps` / `modify_steps_enable` / `modify_steps_multiplier`），按 UI 分区归属到不同类（如 `Lˈˑ/ⁱˈ;`=通讯录/邻居、`Lˈˑ/ٴᐧ;`=僵尸粉、`Lˈˑ/ˊˋ;`=朋友圈）。**微X 的 4 个 dex 里不存在任何一份含 ≥3 个功能名的逗号分隔清单**（已用 `_commalist.py` 全量扫描，0 命中），也不存在「58」这个常量。所以补丁作者是**从微X 的设置键里挑选了 58 个**，而不是从某处直接抄来一份 58 项清单。

#### (3) 微X 真正的授权门禁机制（为什么补丁要伪造一份列表）

微X 的付费判定不在 dex 里硬编码功能清单，而是**「授权 key 携带的功能集合」**：

- CoreDex 授权管理器 `Lc/ﹶˉ/ᵔˉ;`：
  - `ˆⁱ(Ljava/lang/String;)Z`（vaddr `0x07f660`）是功能检查：若 `ʿʼ()`（授权有效）返回 true；输入为空返回 false；取 `ʽʼ()`（授权功能列表 ArrayList），若为空返回 true；否则把输入按 `,` 拆成 `HashSet`，逐条要求授权列表里都存在，否则 false。
  - `ʽʼ()Ljava/util/ArrayList;`（vaddr `0x080fd8`）从外部存储读 `license.txt`，按 `\n|\r` 切分，只保留**长度恰好 64** 的 token（`const/16 v6, #int 64`）——即授权 key 的哈希。
  - `ʻᵔ(Z...)` / `ˎˑ()` 处理服务端下发的 `disable_features` / `disable_features2` / `disable_features_` / `disable_phones_`。
- DonationDex 激活/转移：`Lˎʿ/ʼﹶ;`、`Lˎʿ/ˈˋ;` 解析 `transferkey`，错误码含 `k1_nofeature`→`transfer_activation_no_features`、`k1_valid`、`k2_valid`/`k2_used`、`k1_sameid`、`k1_donation_notsupported`；字段 `_m_advanced_features` / `_y_advanced_features`、`extra_feature_`、`disable_feature_`。
- 也就是说：**微X 的「付费功能」= 授权 key 里携带的功能名集合**，由服务端签名下发，客户端只做「请求的功能 ⊆ 授权的功能」的包含判断。

补丁正是利用这一点：它 hook 微X **CoreDex** 里的 `com.fkzhang.wechatxposedhooks.WxJniCoreBridge.CallMethod(I[Ljava/lang/Object;)`（`PUBLIC STATIC SYNCHRONIZED NATIVE`，实现在运行时解密出的 native 库 `.so` 里，APK 内不含 `.so`），把 native 的授权应答替换成**自己写死的 58 项列表**，从而让 `ˆⁱ` 的包含判断对任意请求都成立。（微X 主 dex 里另有一个同样签名的 `com.fkzhang.xposed.hook.WxCoreLoader.CallMethod` native 桥。）

#### (4) 顺带纠正：58 个 `XpMethodHook` 子类 ≠ 58 个付费功能

CoreDex 的 `Lcom/fkzhang/wechatxposedhooks/Wrapper/XpMethodHook;` 恰好有 58 个直接子类（`Lc/ˋ/ᵢˑ$...;`），但解密它们的注册键后可见全是**反检测/反 Xposed** 的 hook：`checkHookMethod`、`isRootMethod1`、`reportMethod1`、`isHookedByXposed`、`SystemClassLoaderAdderMethod1`、`RootDetectionMethod`、`tinkerClass2`……**与付费功能无关**。「58 个子类 = 58 个功能」只是数字巧合，不能作为证据。

同一池里其余明文字段（key 5559）还包括 `verifier6`(18/9)、`c.ˉˉ.ٴʻ`(27/7)、`param`(36/5)、`null`(41/4)、`8.0.49`(85/6)、`true`(104/4)、`unlimited`(121/9)、`LIC`(139/3) 等；`afterHookedMethod` 用另一套 key `55463`（pc `0x0249`）解出 `wxid_`(1/5)、`c.ﹳﹶ.ʽᵔ`(6/7)、`ᐧٴ`(13/2)、`ʽᵔ`(15/2)。

**小结**：「58」是**补丁自造列表**的长度；这 58 个名字**取自微X 的真实设置键**（可从 4 个 dex 逐条取证）；微X 原版本身**没有**一份 58 项清单，其付费集合由**授权 key 携带的功能名**决定。

### 3.6 微X 原生库 `libwxcoreloader.so` 分析（CallMethod 的真实实现）

微X 2.44 的 APK 里，`com.fkzhang.wechatxposedhooks.WxJniCoreBridge.CallMethod` 声明为 `PUBLIC STATIC SYNCHRONIZED NATIVE`，其实现**不在 APK 的 dex 里**，而在运行时解密出的原生库中。该库以**明文 ELF** 形式藏在 APK 的 `assets/` 下（文件名是 32 位十六进制哈希，无 `.so` 后缀）：

| 资产名 | 架构 | 大小 | 说明 |
|---|---|---|---|
| `assets/74fab57f825f1328df3d731f4de24d5` | ELF32 ARM | 276456 | `libwxcoreloader.so`（armeabi-v7a） |
| `assets/dc7be70f1898d3a58965a919740f97` | ELF64 AArch64 | 461560 | `libwxcoreloader.so`（arm64-v8a） |

两者 `DT_SONAME` 均为 `libwxcoreloader.so`，`DT_NEEDED` 为 liblog/libz/libc/libm/libdl。其余 `assets/*`（`92 c5 01 00` 头）是加密数据，与本库无关。

**JNI 注册表**：`JNI_OnLoad`（arm64 vaddr `0x240a0`）用一段**逐字节混淆循环**（`0x241c8`–`0x24230`）在栈上拼出宿主类名，再 `FindClass` + `RegisterNatives`，方法数 `w3=1`，方法表在 vaddr `0x721e8`。该表项经 `.rela.dyn` 的 `R_AARCH64_RELATIVE` 重定位解析后为：

```
name = "CallMethod"
sig  = "(I[Ljava/lang/Object;)Ljava/lang/Object;"
fn   = 0x22dc8
```

**`CallMethod` 的真实语义（vaddr `0x22dc8`）**：它是一个**极简分发器**，只认 3 个 `int` 模式（其余一律返回 `null`）：

| mode | 目标函数 | 作用 |
|---|---|---|
| `0` | `0x230d0` | **初始化**：从 `Object[]` 取 6 个字符串写入实例字段（`+0x30/+0x78/+0xa8/+0xc0` 等），置 `+0x8=1`，构建内部 `std::map` |
| `1` | `0x23d50` | **功能校验**：取 `String[]` 参数，调用 `0x43c64` 做路径/名字解析（按 `/` 切分，比对字面量 `"C3"`），命中后转 `0x43f28` 在 map 中按 key 查找并派发 |
| `10` | `0x46c98` | **授权/验签**：取字符串参数，在 map 中查找后调用 `0x3de80` → `0x378cc` 做签名校验（库内字符串含 `verify`/`signatures`/`digest`/`generatePublic`/`X509EncodedKeySpec`/`CertificateFactory` 等） |

**关键结论**：

1. 原生库**只实现 3 个命令**（0/1/10），其余 80+ 个 Java 侧命令码（84/82/68/115/111/133/113/79/3…）在 native 侧**直接返回 null**——它们由 Java 层（CoreDex）自行处理。
2. 原生库里**没有任何付费功能名清单**：全库可打印字符串中不存在 `vip`/`pro`/`license`/`pay`/`order`/`feature`/URL 等字样，`.rodata` 只含 JNI 反射/加密/ZIP 工具串。
3. **功能是按 `int` ID 索引的**，不是按名字。`mode==1`/`mode==10` 的 map 查找键都是整数（反汇编可见 `cmp w11,#0x2f`、`cmp w11,#0x9d` 的二叉搜索树比较），授权校验针对单个 ID 做验签。
4. 因此"58 项"既不是 native 里的常量，也不是微X 原版的清单——它是**补丁**在 Java 层伪造的字符串列表（见 3.5）。微X 真实的功能集合体现为 **dex 里的设置键名**（下节）。

**微X 真实功能/设置键名（来自解密后的 4 个 dex 字符串表）**：`BaseDex` 含 300+ 个业务设置键，例如
`auto_shake_friend_max`、`chatgpt_for_bot`、`chatgpt_for_bot_url`、`sns_auto_export`、`sns_auto_export_list`、
`extract_vid_audio`、`extract_original_audio`、`send_img_as_gif`、`send_vid_audio`、`mp3_split`、`export_as_wav`、
`openai_model`、`openai_system_msg`、`openai_proxy_type`、`exit_room_notice`、`invite_key_add`、`moment_auto_export_path`、
`start_auto_shake_friendfinder` 等。这些才是微X"功能"的实际载体（设置项），而 native 层只负责对这些功能做**授权门禁**。

**Java 侧调用链（CoreDex `Lc/ˉˉ/ٴʻ;`）**：`c.ˉˉ.ٴʻ.ٴʻ(I[Ljava/lang/Object;)` 是 `WxJniCoreBridge.CallMethod` 的 Java 包装；例如 `יᵎ:()Z`（状态查询）以 `mode=0x44(68)`、空参数调用，`ᴵᐧ:(Ljava/lang/String;)Z` 以 `mode=0x85(133)` 带一个字符串调用。可见**命令码远多于 native 实现的 3 个**，印证 native 只承担授权门禁这一小块。

## 四、复刻思路（技术层面，不含授权绕过）

WxModuleHook 的可学习技术点及其可复刻形态：

| 技术 | WxModuleHook 中的用途 | 无害复刻形态 |
|---|---|---|
| `InMemoryDexClassLoader` hook | 截获微X的动态 dex | 打印被加载 dex 内容/类名的观察模块 |
| 字符串 XOR 加密 | 隐藏 hook 目标 | 同款 `short[] ^ key` 编解码器 |
| 控制流混淆 | 反反编译 | 不建议复刻（只增维护成本） |
| `findAndHookMethod` / `callMethod` | 替换授权方法 | 挂钩任意类做日志/埋点 |

注意：指向微X授权校验的 hook（replace `updateLicense` 等）

---

## 五、密钥与工件汇总

| 工件 | 值/说明 |
|---|---|
| FKZ_WX_DATA 第一层 AES key | `31d019ea56d574133508b10d944b413c4fb9eb58a90e1a015c62729f7459c66d` |
| 第一层 IV / 填充 | 全零 / PKCS7 |
| 第一层密钥派生 | `MD5( md5_hex_nopad(微X证书DER) + "9n4hZkF" )` |
| 字符串池盐 | `9n4hZkF`（`C1629.m7070(-268301725359106L)`） |
| RSA 公钥 | 用户提供的 `MIIBIjANBgkq...`（server 侧私钥签名，客户端验签） |
| 字符串池解码常量 | `-225893218278402L→"xmd"`、`-255081816022018L→"FKZ_WX_DATA"`、`-279318316473346L→"classes.dex"` |
| tar 内 dex 头 | `97 c4 01 30 c4 05` + ASCII 版本号（如 `15243`） |
| 微X 原生库（明文 ELF，在 APK `assets/` 下） | `assets/74fab57f825f1328df3d731f4de24d5`=ELF32 ARM 276456B；`assets/dc7be70f1898d3a58965a919740f97`=ELF64 AArch64 461560B；SONAME 均为 `libwxcoreloader.so` |
| 微X 原生库注册方法 | `CallMethod` `(I[Ljava/lang/Object;)Ljava/lang/Object;` @ arm64 vaddr `0x22dc8`（方法表 `0x721e8`） |
| 微X 原生库仅实现的 mode | `0`=初始化、`1`=功能校验、`10`=授权验签；其余命令码在 native 侧返回 null |

### WxModuleHook 的密钥情况

WxModuleHook **不定义新的数据库密钥**，也不修改 FKZ_WX_DATA 的加密：

- 其字符串 XOR key 按调用点散布（c/a.java 用 52313 解 hook 目标类名；b/c.java 用 7403/17407 解 hook 流程；b/b.java 用 48914/17712 解文件定位；c/b.java 用 5559/55463 解功能列表）——只是**字符串混淆 key**，不是密码学密钥
- 它的破解方式是替换 `WxJniCoreBridge.CallMethod`、`updateLicense` 等方法返回空/true，**不碰微X的加密层（C0753）**
- 因此 FKZ_WX_DATA 的第一层 AES 密钥（`31d019ea...`，派生自微X证书 DER + 盐 `9n4hZkF`）在装了 WxModuleHook 的手机上依然是原版密钥，解密脚本通用

## 六、相关仓库

- 原始仓库（现仅更新配置与 release）：`https://github.com/fkzhang/WechatUnrecalled`
- 服务端配置备份：`https://github.com/LRFP-Team/WX-Configuration-Backups`
