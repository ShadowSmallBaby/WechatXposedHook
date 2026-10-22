# scripts/

逆向、分析与生成脚本。除 `build_shell30_replica.py` 需要 `cryptography` 外，
其余只依赖 Python 标准库；产物写到 `build/`（已忽略）。

## build_shell30_replica.py（X 3.0 单 APK 复刻）

把原版 `X_3.0.apk`、冻结的 wx30 debug hook APK、内置项目包和
`scripts/shell30/Shell30Compat.java` 合成一个可安装 APK。只做 X 3.0，
输出不含任何 2.44 资产。

```bash
python -X utf8 scripts/build_shell30_replica.py \
  --shell data/refs/X_3.0.apk \
  --hook-apk data/refs/wxh-wx30-full-debug-20261022.apk \
  --package github.shadowbaby.wechatxposed.hook \
  --output build/generated/shell30/WeXposedHook-shell30-v117.apk
```

关键点：

- 二进制 AXML string pool 只改包名相关字符串，不重编资源；
- 原样保留 `META-INF/services` 的 cp437 文件名；
- 注入原版证书/原版 APK 资产，compat dex 在运行时把壳的
  `getPackageName`/`createPackageContext`/`modulePath`/`META-INF/*.RSA`
  映射回原版；
- `zipalign -p 4` + `apksigner`（v1/v2/v3）；默认 debug 密钥库，可用
  `WXH_KEYSTORE_BASE64` 或 `--ks` 覆盖。

完整说明见 `docs/shell30-replica.md`。

## dex_inspect.py（通用结构检查）

分析任意壳 / 功能 dex 的工具，不绑定微X。`stats` / `diff` 自带最小 dex 解析器，
直接读二进制；`dump` 调用 Android SDK 的 `dexdump`；`class` / `summary` / `locate`
读取 dexdump 文本，不再解析二进制。

| 子命令 | 作用 |
|---|---|
| `stats <dex...>` | 类/方法/字符串规模、非 ASCII 类名占比、包分布、关键类命中 |
| `diff <a.dex> <b.dex>` | 两个 dex 的类清单差异 |
| `dump <dex> -o out.txt` | 调用 `dexdump -d` 生成反汇编文本 |
| `class <dump> 'Lx/foo/;' --inner` | 提取指定类（可含内部类）的段落 |
| `summary <dump> <前缀>` | 按包前缀汇总方法、字符串、调用目标（自动去重计数） |
| `locate <dump> <行号...>` | 按 dump 行号回溯所属类与方法 |

```bash
# stats / diff 可以直接吃 APK，自动展开 classes*.dex
python scripts/dex_inspect.py stats data/refs/X_3.0.apk
python scripts/dex_inspect.py diff data/refs/微X模块_2.44.apk data/refs/微不x模块2.44.apk

# 也可以先解出单个 dex
python -c "import zipfile;open('build/classes.dex','wb').write(zipfile.ZipFile('data/refs/X_3.0.apk').read('classes.dex'))"
python scripts/dex_inspect.py stats build/classes.dex
python scripts/dex_inspect.py dump build/classes.dex -o build/classes.smali.txt
python scripts/dex_inspect.py class build/classes.smali.txt 'Lcom/android/x/XposedInit;'
python scripts/dex_inspect.py summary build/classes.smali.txt com/android/x
python scripts/dex_inspect.py locate build/classes.smali.txt 30096
```

`dexdump` 的查找顺序：`--dexdump` 参数 → `ANDROID_HOME` / `ANDROID_SDK_ROOT` →
仓库根 `local.properties` 的 `sdk.dir` → `PATH` → `build-tools/` 里版本最高的一个。

用这套工具得到的 2.44 / 3.0 壳对比和第三方整合包拆解见
`docs/reverse-engineering.md` §7、§8。

## 微X 字符串怎么解

微X 的字符串不是明文，也不是简单 XOR：

- 每个功能 dex 里有一个「解码类」，`<clinit>` 把打乱顺序的 `String[]` 池逐项赋值；
- 调用点写一个 `const-wide` 64 位种子，运行时经 `mixA`/`mixB` 两条散列链从池里
  取字符并拼出明文；
- 算法与位运算细节见 `docs/reverse-engineering.md` §1.2。

因此直接 `strings` dump 出来的 dex 只能看到池里的原始片段，拿不到「种子 → 字符串」
的对应关系。`dump_microx_features.py` 就是把这一步离线做完。

## dump_microx_features.py

输入运行时 dump 出来的明文功能 dex（`data/refs/device_dump/*.dex`），输出：

- 每个 dex 的字符串池大小、种子数、解出的字符串数
- 全部明文（按 dex 分组）
- 自动标出「关于 → 自助获取高级功能」的四项对应的功能键
- `*_enable` 设置键统计

```bash
python scripts/dump_microx_features.py \
    --out build/microx_strings.txt \
    --json build/microx_strings.json

# 只解一个 dex
python scripts/dump_microx_features.py \
    --dex data/refs/device_dump/DonationDex.dex \
    --pool-class 'Lᵢᵎ/ʿٴ;' \
    --grep secret
```

脚本里的 `Dex.seeds()` 扫的是 `const-wide`（opcode `0x18`，5 units）。注意
`0x17` 是 `const-wide/32`（3 units），按它扫会全部落空。

微X 2.44 实测（设备：微信 8.0.49 / 微X 2.44_5.41）：

| dex | 池字符 | 种子 | 解出字符串 |
|---|---:|---:|---:|
| BaseDex | 357734 | 26187 | 6002 |
| CoreDex | 38357 | 3544 | 1340 |
| DonationDex | 28187 | 2383 | 778 |
| ThemesDex | 47900 | 3238 | 1146 |

### 关于 → 自助获取高级功能：四项的 key

| 界面文案 | 功能键 | 出现在 |
|---|---|---|
| 多群自动转发 | `multichat_autoforward` | CoreDex / DonationDex |
| 朋友圈自动转发 | `moments_auto_forward` | CoreDex / DonationDex |
| 密友 | `secret_friend` | CoreDex / DonationDex |
| 自动接受群聊邀请 | `auto_accept_chatroom_invite` | BaseDex / DonationDex |

这四项的授权状态由 `extra_feature_`（逗号分隔）驱动：DonationDex 的
`Lᵔˏ/ˑˋ;.ˆⁱ()V` 与 CoreDex 的 `Lc/ˉˉ/ٴʻ;.ˉˈ()V` 都按 `,` 切分后塞进 HashSet。

**与本模块的关系**：`SecretConstants.FEATURES`（见 `scripts/secrets_table.py`）是模块
自己写死的白名单，用于覆盖微X 的付费功能集。原 58 项只覆盖「打赏」那批功能，
这四项高级功能不在其中；现在已追加为 **62 项**。

真机验证（微信 8.0.49 / 微X 2.44_5.41 / 模块 62 项）：

- `微X模块 → 打赏` 页的功能列表里出现了「密友」「多群自动转发」「自动接受群聊邀请」
  「朋友圈自动转发」四项，说明微X 已把返回的授权集合映射到了这四个功能键。
- `群聊管理` 菜单里能看到「自动接受群聊邀请」入口。

另外两个键按主人要求**临时加入**，当前是 **64 项**：

| 键 | 观察结果 |
|---|---|
| `modify_message` | 加入后「打赏」列表出现「修改消息」；BaseDex 聊天长按菜单本来就有该功能 |
| `integrated_mode` | 加入后「打赏」列表出现「内置模式」；订阅页是否真正生效仍需单独验证 |

## microx_online_check.py

复刻微X 自己的在线检查/下载请求格式（默认 dry-run，只有 `--send` 才联网）。
静态分析来源：主 dex `Lx/ᵢـ/ـˉ;.ˆᴵ()` 与 `Lx/ʼˏ/ـﹶ;`。

```bash
python scripts/microx_online_check.py                 # 只打印请求
python scripts/microx_online_check.py --send          # 真正请求
python scripts/microx_online_check.py --response build/online_check.json  # 从响应里找 URL
```

请求格式：

```
POST http://v.weixiaov.club/wx6/php/init_check.php   （另有 wxp2022.vip / weixiaov.wang 两个）
form: cmd=c
form: args={"wxid":...,"time":...,"apkVersionName":...,"wxVersionCode":...,
            "arch":...,"has_core":...,"has_strings":...,"xmd":...}
```

下载基址（运行时打乱）：

```
http://dl.weixiaov.club/wx/wx6/
https://cdn.jsdelivr.net/gh/fkzhang/WechatUnrecalled@master/xmetadata/wx6/
https://github.com/fkzhang/WechatUnrecalled/raw/master/xmetadata/wx6/
http://v.weixiaov.club/wx6/
```

URL 拼接规则：`base + apkVersionName + "_t" + core`，`core` 来自服务端下发行。

注意：服务端可能按 wxid/签名/版本校验；它在线只下发「当前微信版本对应的 4 个 dex
及若干资源」，和当前运行时包（2.44 为 24 个文件）不是同一批内容（见 docs/reverse-engineering.md）。
脚本默认不联网，是否请求由主人自行决定。

**2026-10 实测结果**：主更新域名已经下线——

| 地址 | 结果 |
|---|---|
| `http://v.weixiaov.club/wx6/php/init_check.php` | HTTP 530，响应体 `Domain Not Configured` |
| `http://dl.weixiaov.club/wx/wx6/` | HTTP 530，`Domain Not Configured` |
| `http://www.wxp2022.vip/wx6/php/init_check.php` | 连接被重置（10054） |
| `http://v.weixiaov.wang/wx6/php/init_check.php` | 连接被重置（10054） |

所以微X 2.44 自带的在线更新已经不可用；但源码里的 GitHub 镜像仍存活，
见下一节的 `fetch_microx_mirror.py`。

## fetch_microx_mirror.py

从微X 的 GitHub 备用镜像拉取在线资源清单（默认只列，不下载）。

```bash
python scripts/fetch_microx_mirror.py                 # 列 r/ 清单
python scripts/fetch_microx_mirror.py --root rt       # 另一套 rt/ 清单
python scripts/fetch_microx_mirror.py --download --only fp/   # 只下功能包
python scripts/fetch_microx_mirror.py --include-pr --download # 连 pr/ 参数一起
```

镜像地址：`https://raw.githubusercontent.com/fkzhang/WechatUnrecalled/master/xmetadata/wx6/`

实测目录（`r/` 共 19 个文件）：

| 路径 | 大小 | 用途 |
|---|---:|---|
| `r/C` | 347706 | CoreDex 加密体 |
| `r/L`, `L64`, `L_x86`, `L_x86_64` | 323K~542K | 各架构 loader |
| `r/A_p`, `r/A_xv` | 4.4M / 4.2M | APK / xv 资源 |
| `r/digest` | 711 | 版本/哈希清单（加密态） |
| `r/fp/base` | 1037450 | BaseDex 加密体 |
| `r/fp/donation` | 122954 | DonationDex 加密体 |
| `r/fp/themes` | 202378 | ThemesDex 加密体 |
| `r/fp/sf/af/mf/xv/vidurlparser` | 88K~1.0M | 其余功能资源 |
| `r/pl/pl_transcoder` | 405258 | 转码器 |
| `r/xm/wxany`, `r/xm/wxtools` | ~23K | Xposed 小工具 |

这些文件都是加密态，客户端靠 native 层解密；脚本只按原样下载并生成 sha256 清单，
不做解密。在线 `fp/base`（1,037,450）与仓库内置包里的 `14e777…`（1,035,962）
大小接近但不是同一版本。

实测补充：`raw.githubusercontent.com` 在本机对部分文件限速明显，`mf` / `sf` /
`vidurlparser` / `xv` 能下完，`af` / `base` / `donation` / `themes` 可能超时；
脚本已改为优先调用 `curl`（带 3 次重试），失败的文件会跳过并在清单里体现。

## assemble_pack_from_xmetadata.py

从主人拷进来的 `xmetadata/` 源文件装配运行时功能包，不依赖 `wx6_2.44.zip`。

**转换规则（已对 xmetadata 下 1395 个文件验证）**：

```
源文件 = SHA-256(body) 的 32 字节 + body
body   = 微X运行时容器（97 c4 01 30 c4 05 + 5 位数字 + 负载）
```

所以转换就是：校验前 32 字节 == `SHA-256(其后全部内容)`，然后去掉这 32 字节。
当前快照下 **11 个文件**与现有运行时包逐字节一致（D / H_p / LD64 / M / S / Xmd /
pr/P_8045、P_8048、P_8049、P_80422428p、P_80482588p）。

```bash
python scripts/assemble_pack_from_xmetadata.py --list
python scripts/assemble_pack_from_xmetadata.py --out build/xmeta_pack
python scripts/assemble_pack_from_xmetadata.py --out build/xmeta_pack \
    --sidecars <现有28文件目录> --strict
python scripts/assemble_pack_from_xmetadata.py --out build/xmeta_pack \
    --name-map name_map.json
```

实测（旧 848 源快照）：

- 产出 15 个主体 + 10 个边车；11 个资源与现有包完全一致
- 4 个 dex 本体与运行时包**版本不同**（旧快照的 `r/fp/*` 与 CoreDex 均差 1,456 字节）
- 3 个运行时条目旧源快照里没有对应文件：`44c29edb…`、`9816b5df…`、`36a76b97…`
  （历史 849 包记录；`9816b5df…` 现已移除，不参与当前打包）

**旧源快照缺失、现已由 849 快照补齐的三类东西**：

1. **运行时文件名**是服务端下发的内容 ID（31 位 hex），不是 body 的 MD5/SHA 前缀。
   `data/xmetadata/2.44_849.mapping.json`（本地文件，不入库）记录内容 ID 与角色路径的对应。
2. **`_c` / `_s` 边车**：849 快照已按 `r/fp/base_c`、`r/C_s` 等约定保存。
   `_s` 是 RSA-SHA1 签名，运行时由 `SignatureVerifyBypass` 跳过验签。
3. **服务端资源包** `9816b5df…`：849 快照曾保存为 `r/server_resource`；现已移除，不参与当前打包。

**2026-10-18 真机验证**（微信 8.0.49 / 微X 2.44_5.41 / 原始包为基线）：

| 实验 | CoreDex | themes | base | donation |
|---|---|---|---|---|
| 旧 848 快照装配包 | 加载成功 | ClassNotFound | ClassNotFound | ClassNotFound |
| 原始 30 文件包（现 28）/ 849 合并树 | 加载成功 | 加载成功 | 加载成功 | 加载成功 |
| 原始 body + 错误 `_c` | — | — | 加载成功（525） | — |
| 原始 body + 错误 `_s` | — | — | 加载成功（525） | — |

结论：

- `_s` 的 RSA-SHA1 验签已经被 `SignatureVerifyBypass` 绕过（错误 `_s` 仍能加载）。
- `_c` 与 body 不配套也不影响加载（错误 `_c` 仍能加载）。
- 真正的阻塞点是**旧源快照的构建批次**：修复工具实测 8.0.48 (2580) 与
  8.0.49 (2600) 的 `wx6_2.44` 包完全相同，说明不是 848/849 差异；旧
  xmetadata（2024-06）的 `r/fp/*` 解不出当前壳要的
  `com.fkzhang.wxfeatures.*.Wrapper.Init`。
- 已用 `reverse_pack_to_xmetadata.py` 把本地 8.0.49 的 30 文件包（现 28）按角色合并进
  `xmetadata/wx6` 主树，映射保存在 `data/xmetadata/2.44_849.mapping.json`，
  30/30（旧包）逐字节一致；当时为 28 文件；旧 848 的差异文件可从 `data/refs/xmetadata` 的原始备份恢复。

### wx6 结构（原版 + 849 覆盖）

```
xmetadata/wx6/
├── 2.26 … 2.44/r/C       # 原版各版本核心（保留；849 只覆盖共享路径）
├── r/
│   ├── C                 # 849 覆盖
│   ├── L                 # 849 覆盖
│   ├── fp/base|donation|themes   # 849 覆盖
│   ├── A_p  A_xv  digest  fp/af|mf|sf|vidurlparser|xv  pl  xm
│   └── （server_resource 已移除）
├── pr/                   # 原版 P_*；P 覆盖为 849
└── D  H_p  H_xv  LD  LD64  M  S  X  Xmd  log  log2
```

- `_c`/`_s` 不入库：源树不再提交边车，后续改为项目自签；loader 的
  `36a7_c`/`36a7_s` 保留在运行时载荷里。
- 849 运行时包确实包含 `C_backup_c/s`；原版 2.26–2.44 版本目录只有 `r/C`，
  没有 backup 边车，这是正常的。
- `.syncthing.C.tmp` 是同步工具的临时文件，对应目录里都有完整的 `C`；
  已从仓库移除。
- 原版 848 的共享 body 在 `data/refs/xmetadata` 备份里。

### 旧版本 pr 参数补充

已补充 12 个版本专用 `P_` 文件到 `xmetadata/wx6/pr/`：

| 微信版本 / 包 | 新增文件 |
|---|---|
| 8.0.24 / wx6_2.41 | `P_8024_2100`、`P_8024_2100_b` |
| 8.0.42 / wx6_2.43 | `P_8042_2460`、`P_8042_2460_b`、`P_8042_2460_c`、`P_8045_2460` |
| 8.0.42 / x7_3.0 | `P_8042_2460_x7` |
| 8.0.43 / wx6_2.42 | `P_8043_2480_b`、`P_8043_2480_c`、`P_8043_2480_d` |
| 8.0.47 / wx6_2.44 | `P_8047_2560` |
| Play 8.0.30 / wx6_2.39 | `P_8030_2244` |

版本 `C` 与其它文件不覆盖，继续使用项目现有的最新版本。

### 正差值文件（已移除）

按“差值为正才覆盖”试验过 8.0.43 DonationDex（+192）和 Play 8.0.30 ELF64
loader（+13,584），但真机 8.0.49 上 donation 从 71 项掉到 40 项，判定不兼容；
两个文件已从项目移除，不进入主线。其余负差值/额外文件同样不进入主线。

**2026-10-18 真机验证**（不分发 backup）：

- 移除全部 `_c`/`_s`/`_backup_c`/`_backup_s` 后，`36a7_s` 缺失导致
  `wx lib (L64) verification failed` + `wx core init failed`。
- 仅保留 `36a7_c`/`36a7_s`，其余边车与 `C_backup_c/s` 不分发：
  themes 113 / base 525 / donation 71，正常加载。
- 结论：`C_backup_*` 和其它边车可以不发；**loader 的 `36a7_s` 必须保留**。

## reverse_pack_to_xmetadata.py

把运行时功能包逆推成 xmetadata 源格式（`sha256(body)[32] + body`），并按角色
分散写回主树（`r/fp/base`、`r/C`、`pr/P_80482588p`、`LD64` 等）。

```bash
python scripts/reverse_pack_to_xmetadata.py \
    --zip app/build/generated/featurepacks/wx244/wx6_2.44.zip \
    --out xmetadata/wx6 \
    --mapping-out data/xmetadata/2.44_849.mapping.json \
    --label "microX 2.44 / 微信 8.0.49"
```

默认**跳过 `_c`/`_s`**（后续项目自签）；需要完整边车时加 `--include-sidecars`。
mapping 里跳过的边车会标成 `source: null` / `待自签`。

装配回来（边车会被跳过，主体照常输出）：

```bash
python scripts/assemble_pack_from_xmetadata.py \
    --source xmetadata/wx6 \
    --mapping data/xmetadata/2.44_849.mapping.json \
    --snapshot --out build/xmeta_wx6_849 --strict
```

合并时会覆盖 6 个版本相关文件：`r/fp/base|donation|themes`、`r/C`、`r/L`、`pr/P`。
其余 11 个同名文件（含 `pr/P_8049`、`pr/P_80482588p`、`D`、`H_p`、`M`、`S`、`Xmd`、
`LD64`）逐字节一致；`server_resource` 曾是 849 新增，现已移除，不参与当前打包。10 个 `_c`/`_s` 边车不入库；
`36a7_c`/`36a7_s` 保留在运行时载荷里。旧 848 的差异文件可从
`data/refs/xmetadata` 的原始备份恢复。

`data/xmetadata/2.44_849.mapping.json`（本地文件，不入库）记录「运行时内容 ID ->
源相对路径」，装配时按它反向映射；构建清单则直接按 body SHA-256 匹配。
实测 **18/18 主体**与原始 zip 逐字节一致，10 个边车标记为待自签。

关于 `P_8049`：源树里本来就有 `P_8049`（微信 8.0.49 主标识）和 `P_80482588p`
（8.0.48 build 2588 的回退参数），两者在逆推前后逐字节一致；当前包同时携带它们。

## scan_xmetadata_manifest.py

扫描 `xmetadata/` 下各版本**源文件**，生成 `xmetadata/source_manifest.json/md`
清单（注意不是运行时包）。

```bash
python scripts/scan_xmetadata_manifest.py
```

清单统计每个版本集（wx5 / wx6 / wx7）的文件数、符合
`sha256(body)[32] + body` 格式的可转换文件数、容器头版本分布，以及逐文件的
body 大小/哈希/类型。

实测：

| 集合 | 文件 | 可转换 | 不可转换 |
|---|---:|---:|---:|
| wx5 | 946 | 944 | 2 |
| wx6 | 215 | 210 | 5 |
| wx7 | 180 | 178 | 2 |

## X 3.0 适配（2026-10-22 已跑通）

已实现：

- `DexDumper`：微信数据目录存在标记 `files/wxh_dump_dex` 时，把
  `InMemoryDexClassLoader` 传入的 dex 落到 `files/dex_dump/`。
- `FeaturePackRestorer`：每个 APK 只携带对应版本的载荷；2.44 为 24 个文件，
  3.0 为 26 基础 + 6 扩展。`build_release_packs.py` 从项目仓 `xmetadata/wx7`
  生成 zip 并打进 assets（X30 自动去 32B 前缀，`cfg/`→`_c`，`sig/`→`_s`）。
- `build_x30_min.py`：从项目仓生成 32 文件 / 4,292,161B 的最小运行目录，
  并输出 `x7_3.0.zip` / `x7_3.0_ext.zip`。
- `runtime_names.py`：运行文件名的确定性规则
  （`trim(MD5("FP_<role>"))` / `trim(MD5("<role>"))`，core=`MD5("C")`）。
- `X3ComponentHooks`：识别 `com.android.xc.Wrapper.HookWrapper`，hook
  `com.android.xc.WxJniCoreBridge.CallMethod(I,Object[])Object` 与
  `com.android.x.xposed.hook.WxCoreLoader.CallMethod`。
- `X3LicenseBypass`：hook `c.ـˉ.ˈʽ`（LIC 类）的布尔/授权列表方法。
- `X3CallMethodHook`：处理 3.0 的消息号（0 init、111 状态、130 验签、
  150 功能查询、2 类名查询等）。

3.0 主 dex 关键信息：

| 项 | 值 |
|---|---|
| 包名 / 入口 | `cn.android.x` / `com.android.x.XposedInit` |
| 组件入口 | `com.android.xc.Wrapper.HookWrapper` |
| native 桥 | `com.android.xc.WxJniCoreBridge.CallMethod(I,Object[])Object` |
| 功能包目录 | `files/x7_3.0`（26 基础 + 6 扩展） |
| 授权库 | 仍是 `FKZ_WX_DATA`，表 `DATA(_ID,ACCOUNT,TAG,TYPE,VALUE,DATA BLOB)` |

当前结果：

- 可用组合：`cn.android.x` 3.0 (117) 单开 + 项目仓最小集 + 项目自动建库；
- `com.android.xf.{af,sf,mf,base,themes,vidurlparser,donation}.Wrapper.Init`
  全部初始化，`X: Module loaded successfully!`，菜单 `3.0_5.42 [VIP][专业]`；
- 旧的 `Disabled error code: 00322` 由旧 DB/包组合导致；使用项目仓
  `370042` 核心 + 自动建库后不再出现；
- 干净环境：`files/wxh_clean_env` → `CleanEnvironment` 重命名旧目录/DB，
  restorer 恢复 26+6、`LicenseInstaller` 创建 DB、X3 成功；
- 详细链路见 `docs/extension-pack-chain.md` 第 11-13 节。

## collect_full_pack.py

把当前版本的运行时功能包文件（2.44 24 个 / 3.0 26 基础 + 6 扩展）「全量」收集到一个目录，并生成 `manifest.json`
（来源、字节数、sha256、类型、用途）。默认优先 zip，28/28 后其余来源只校验。

```bash
python scripts/collect_full_pack.py
python scripts/collect_full_pack.py --out build/microx_full_pack --include-apk-extras
python scripts/collect_full_pack.py --dir <adb pull 下来的 wx6_2.44 目录>
```

实测：`build/microx_full_pack/` 收齐 28/28，尺寸全部符实；2 个 ELF、10 个
元数据/配置、16 个加密主体。包内文件是加密态，明文 dex 只能运行时 dump。

## verify_featurepack.py

按 `FeaturePackRestorer.java` 当前版本的文件名清单（2.44 24 个 / 3.0 26 基础 + 6 扩展）与字节数校验功能包，并比对
zip / tar / APK assets / 设备目录是否同源。

```bash
python scripts/verify_featurepack.py
python scripts/verify_featurepack.py --dir <adb pull 下来的 wx6_2.44 目录> --verbose
```

脚本会先读 `FeaturePackRestorer.java` 的 `NAMES` / `SIZES` 与内置表对表，
两边漂移会直接报出来。

## extract_asset_blobs.py

把微X APK 的 `assets/` 解出来，与运行时功能包逐文件比对。

```bash
python scripts/extract_asset_blobs.py \
    --extract build/assets_dump \
    --json build/assets_diff.json
```

APK assets 15 个文件，2.44 运行时功能包 24 个；7 个同名文件里只有 2 个完全一致，
另 5 个是 APK 内置旧版资源。`74fab57f...`（ELF）、`c1d9f5f8...`、`d2caec3b...`
只在 APK 里，不参与运行时投放。

## 其他脚本

| 脚本 | 用途 |
|---|---|
| `decode_microx_strings.py` | 种子解码算法的最小复刻，用 smali 池 + 常量做单条验证 |
| `decode_fkz_db.py` | 解析授权库 `FKZ_WX_DATA` 的三层加密 |
| `secrets_table.py` | 模块敏感常量的明文表（`FEATURES` 等） |
| `encode_secrets.py` | 把明文表编码成 `SecretConstants` 里的密文 |
| `generate_min_db.py` | 生成最小授权库 |
| `publish_public.py` | 同步公开仓（去掉内部源码/敏感资料） |

## 注意：`data/decompiled` 是什么

`data/decompiled/` 是**旧模块 `WxModuleHook-1.2`（包名 `wx.module.hook`）**的反编译
结果，不是微X 本体。里面的 `short[]` + `(char)(v ^ key)` 是旧模块自己的字符串混淆，
解出来能看到它写死的 58 项 `FEATURES` 清单；不要把这份源码当成微X 的代码来分析。
微X 本体请用 `data/refs/微X模块_2.44.apk` + `data/refs/device_dump/*.dex`。
