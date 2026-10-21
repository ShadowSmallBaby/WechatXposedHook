# 微X 2.44 / X 3.0 功能包链路（实测记录）

> 2026-10-22，Android 13（Redmi K20 Pro）+ WeChat 8.0.49 + X 3.0（cn.android.x 117）+
> legacy Xposed API 82；2.44（111）与 Android 16 作为对照。
> 只记录**已实测验证**的事实。

## 0. TL;DR（2026-10-22）

- 可用组合：`cn.android.x 3.0 (117)` 单开 + 本项目 DEBUG 模块（wx30 full）+
  项目仓 `xmetadata/wx7` 生成的最小运行集；`FKZ_WX_DATA` 由项目自动创建。
- 结果：af/sf/mf/base/themes/vidurlparser/donation 全部初始化，
  `X: Module loaded successfully!`；菜单实测显示
  `3.0_5.42 ...[VIP][专业]`（导入 DB 路径；自动建库路径同样加载成功）。
- 构建：

  ```bash
  python -X utf8 scripts/build_x30_min.py --source xmetadata/wx7 \
      -o build/generated/x30_min --assets app/build/generated/featurepacks/wx30
  ./gradlew :app:assembleLegacyWx30FullEditionDebug
  ```

  Gradle 的 `generateFeaturePacks` 也会从项目仓生成 X30 资产
  （自动去 32B 前缀，`cfg/`→`_c`，`sig/`→`_s`）。
- 干净环境：root 创建 `files/wxh_clean_env` 后重启微信；`CleanEnvironment`
  把旧目录/DB 重命名为 `.cleanbak_*`，随后自动恢复 26+6 文件并建库。
- 自签：本模块存在时 `_s` 任意 256B、`_c` 可重加密 payload（保留原 RSA 记录）、
  外层/内层可用已知 password 重打包；包尾 RSA 记录复制原值。
- 方法论/排错清单：`docs/extension-pack-methodology.md`。

## 1. 运行时文件与加载列表

- 目录：`/data/data/com.tencent.mm/files/wx6_2.44/`
- 文件名：`trim(MD5("FP_<feature>"))` 或 `trim(MD5("<feature>"))`，逐字节去前导零
  （规则与示例见第 12 节；core 是 `MD5("C")`）。
  - sf：`aa894d53…` / `60d31eb3…`
  - mf：`665c7b62…` / `ea81aa7d…`
  - af：`3e9bf1b9…` / `f0357a3f…`
- 加载列表：`FKZ_WX_DATA.DATA` 的 `fp` / `fp_async`（逗号分隔）。
  - 值：Base64(AES-256-CBC，零 IV，key `31d019ea56d574133508b10d944b413c4fb9eb58a90e1a015c62729f7459c66d`)
  - 只做 hook 注入不够：宿主在 hook 安装前会读库；必须真实写库才生效。
- 版本表：`LatestVersions` / `FPVersions`（JSON）。仅补 FPVersions 不会让缺失的后缀表出现。

## 2. 容器格式

```
[可选 32B SHA-256(body) 前缀] + MsgPack 7 元组
  [version("0"), 5 位位置置换, f1..f5]
  f1 = payload（前 16B 为 AES IV）
  f3 = 8B PBE salt
  f4 = 24B PBE 加密的 seed
  f2/f5 = 256B 签名
```

解密：

```
PBEWithMD5AndDES(password, salt, 1000) -> PBKDF1-MD5 -> DES-CBC 解 seed -> 16B AES key
AES-128-CBC(IV=f1[:16]) 解 f1[16:]
```

**落盘布局（实测）**：
- 基础包（base/themes/donation/vid/core）：去掉 32B 前缀，magic `97c40130` 在偏移 0。
- 扩展包（sf/mf/af）：保留 32B SHA-256 前缀，magic 在偏移 32；
  - 高级包里的同内容文件是 20B 头（magic@20），也能被宿主解出同一 password。
- 仓库 base 包不附带 `_c`/`_s`，需要另行处理。

## 3. 密码公式与已知表

2.44：

```
password = trim(MD5( 证书指纹C / 公钥指纹K / 包名P / 固定盐S1..S5 的排列 + 9位后缀 ))
C = 9c7b209c5977e2ea90e29f66381a3c8
K = ab39dd0f5c223b636584baa3b7a1a7
P = com.fkzhang.wechatxposed
S1 = fkZh4n9_1211_guji_Xposed
S2 = FKZhang_WechatXposed_1211_GUJI
S3 = Gn4hZkF_1121_GUji
S4 = 9N4hZ_1211_GUJI_0211
S5 = Guji_0123_WeXposed_fkzhang
```

| 组件 | 后缀 | password |
|---|---|---|
| core(202) | 103021019 | f25c4ac6bee6291acd2474dadbddb |
| core207 | 300011227 | 54d0e6ab3c787101ad9daea3279b1a7 |
| core_c | 100021349 | 2aaf7e1f81c1e1ee4c41756cf7a0cb93 |
| base | 102001325 | d469a1152a7768b87418ffa3883254e |
| themes | 000213318 | c1fc2271446e83a446702ab1401f94c6 |
| donation | 200010357 | 7b342b1c7c9ee29d4b9785836fc76 |
| vidurlparser | 300010215 | 98662c7fb925bd157d0740a0d1d14d |
| lang | 300011223 | 76a0bc5752e8af5f243b7842972b3416 |
| meta | 030110422 | 8356ffd44eef91f6ee6cb83871601840 |
| config | 010200232 | 90a917cb7c6511a3924fb946a23e558 |
| classmap | 203000181 | f789b35e33c8fd1d44789c7885e1325 |
| **sf** | 000211430 | **376a24b4ead27fb7c9db36a4617f6b4**（C P K S4） |
| **mf** | 000103522 | **4ac99464d3a44d3581deb34b418eff8**（C K S2 P） |
| **af** | 003020167 | **ecb9e530e46417c2a088fc26feacdd6**（C S2 P K） |

扩展包 salt（外层）：

```
sf 289a56783f65c084
mf 0990d91099819472
af 89fda920d69d7f19
```

扩展包外层解出的是 3 元素 signed-array：

```
[256B 签名, 599B _c, 内层容器]
内层容器 salt：
  sf 1db40e43dd72c97e
  mf 4a9125e6459e3019
  af 72bfc78933d9cbef
```

宿主路径在 `133("sf"/"mf"/"af") -> "0"` 之后没有走到内层 PBE：
它直接用 **0 字节** 的 buffer 构造 `InMemoryDexClassLoader`（`Bad range`），
随后 JNI stale local abort。内层密码已由 3.1 的离线方法还原。

### 3.1 尾记录与内层密码（2026-10-21 离线还原）

容器的签名槽（256B）不是普通哈希，而是 **PKCS#1 v1.5 编码的 RSA 记录**：
用厂商公钥（X509 DER，与 2.44 验签公钥相同）做公钥还原
`m = block^e mod n`，去掉 `00 01 FF..FF 00` 前缀即得

```
"<9位后缀>,<8位hash>,0"
```

<details>
<summary>厂商尾记录公钥（X509 DER，hex）</summary>

```
30820122300d06092a864886f70d01010105000382010f003082010a0282010100dc6cbd92486d90c7c01732b12076ee22597319d65a4251bca5092422f97d1818d7a604c81108f473239140a75ecef8ebfbb9f843e28a7ae78e8b2d15456a408eb74bd6ae47aa5bb0df9d628169d17a770120e1e41437027dcc667a80d2ffff67654a83223cd3fa3da6c29114ee620db582be136a44cf7c093374a982e43b8a1c2cb0e2297868ed7f6679e81660e847ed281482514bcf8e1a8685a347a13d4c3c7117c944a03481ab5783a0461feb15399e4c12afdd2f7574a21ae7dff475b392f46e02d37fee2e40c684dfadf0beeca24624c02e94568f9e6a46cbef8fc120d71b44d531e35f2e2cced05ad5898e48c735a1debd3672d398194cca6d3891eca30203010001
```

</details>

外层 sf 的尾记录是 `000211430,804798d2,0`（与 DigestProbe 抓到的
preimage 后缀一致）。内层容器用同样方法读出自己的后缀，再按外层同款
`trim(MD5(常量排列 + 后缀))` 算 password：

| 组件 | 内层后缀 | 排列 | 内层 password | 内层明文 |
|---|---|---|---|---|
| sf | 300021135 | S4 C P K | 7ab7732f28c291e7d93c680bf6c5337 | APK 86595B，classes.dex 211064B |
| mf | 020301506 | P S5 K C | fdb4bfa5136c3658f9f849e81774a07c | APK 149637B，classes.dex 398092B |
| af | 001030281 | C K S5 P | 30d26f795c278482441cb465b02b1ce7 | APK 176486B，classes.dex 460740B |

三个内层明文都是标准签名 APK（`META-INF/CERT.RSA` + 单个 `classes.dex`），
入口类分别为 `com.fkzhang.wxfeatures.{sf,mf,af}.Wrapper.Init`。

离线脚本 `scripts/decrypt_wx244.py` 已加入 `INNER_FORMULAS` /
`INNER_PASSWORDS` / `TAIL_PUBKEY` / `rsa_tail()` / `decrypt_extension()`，
自检通过。

## 4. `_c` / `_s` 与自签

- `_s`：256B RSA-SHA1 签名（厂商 D 证书可验）。宿主通过 Java
  `Signature.verify` 校验；本模块的 `SignatureVerifyBypass` 放行所有 SHA1withRSA，
  因此可用自己的密钥重新签名——实测自签 `a38c6c9e…` 不影响 207/202 核心加载。
- `_c`：599B 旁车容器（同一 MsgPack 格式）。password 全表见 4.1（如 core_c
  主 `9cba32d6…`、backup `2aaf7e1f…`）。解出的 32B 是 msgpack `fixstr`
  字符串（如 `579e155e`），用于主包尾记录（`<9位后缀>,<hash>,0`）；
  `_c` 不是 payload 解包 key。
- 自签资源的前提：
  - `_s`：只需 256B（可自签，校验已绕过）。
  - `_c`：password 全表见 4.1（含 sf/mf/af 内嵌旁车）。重打包时可以原样
    拷贝，也可以按该 password 重新加密 payload（保留 256B RSA 记录）。
    2.44 宿主路径不会对扩展包内嵌 `_c` 做 PBE，因此拷贝最稳。
  - payload：外层 password 与内层 password 均已还原（见 3.1），
    因此 sf/mf/af 的**内层 APK 可以按原 password 重新加密/替换**；
    签名校验已被 `SignatureVerifyBypass` 放行。
  - 注意：尾记录里的 `<hash>`（如 sf `804798d2`）疑似与 payload 绑定，
    替换 payload 时是否被校验尚未验证；保留原内层 payload 则无此问题。

### 4.1 `_c` 旁车全表（2026-10-21）

`_c` 是**对称加密 + 非对称记录**的混合体：

- 32B 槽位：`IV(16) + AES-CBC(16)`，PBE 派生 AES key；
  解出 msgpack `fixstr` 字符串（如 `579e155e`），尾部为等值填充。
- 256B 槽位：RSA 公钥可还原的 `<9位后缀>,<hash>,0`（与尾记录同机制）；
  后缀只用于算 `_c` 自己的 password，不需要私钥。
- 8B salt + 24B PBE seed；password 公式与外层相同。

| `_c` | 后缀 | 排列 | password | payload |
|---|---|---|---|---|
| core_c（d61f 主） | 010203304 | K P S3 C | 9cba32d68537d47fa60e1591dcede72 | 579e155e |
| core_c（backup） | 100021349 | K C P S3 | 2aaf7e1f81c1e1ee4c41756cf7a0cb93 | — |
| base_c | 003021119 | C S3 P K | bc33738ff8877541eea35cccab7e2d | 95d5713c |
| themes_c | 201001345 | P K C S4 | 806ef92e11d817406eb113a654042b0 | 96fd0901 |
| bridge_c | 100030215 | K C S4 P | 9da95d1ddd1d2e2ad349d2b929f32b30 | 7f1a2f8a |
| donation_c | 100020327 | K C P S2 | f4dda8987bdf1fc748692332e75c9f7 | 3686bd62 |
| vid_c | 201000383 | P K C S1 | 44f673e8a162fa7ebade83c63764aae | ddc05243 |
| **sf_c（外层内嵌）** | 010300920 | K S4 C P | 15ad2f6b9ffe4a31a20ce49f162e15 | 1f33318b |
| **mf_c（外层内嵌）** | 020113204 | P K S3 C | 34de1fbf37bf56ff3250a215fdaa50eb | 6c31fdb4 |
| **af_c（外层内嵌）** | 102030073 | K P S1 C | 739ffde5a1314e14d6b803dc35ecb | f972e3a8 |

结论：`_c` 的 password 链路已完整还原（含 sf/mf/af 内嵌旁车）。
自签时保留原始 256B RSA 记录、用自己的 payload 重新 AES 加密即可；
若要换后缀才需要厂商私钥。`decrypt_wx244.py` 已加
`SIDECAR_FORMULAS` / `SIDECAR_PASSWORDS` / `sidecar_suffix()` /
`decrypt_sidecar()`，自检通过。

## 5. 核心代际

2.44：

| 代际 | 文件 | body | 说明 |
|---|---|---|---|
| 207 | `d61f…` | 347578 | 会尝试加载 sf/af，但在 native `0x56030` 崩溃 |
| 202 | `9816b5…` | 352186 | **实测可加载 sf/mf/af 外层**，并触发 PBE |
| 远程仓 2.44 | `data/xmetadata/wx6/2.44/r/C` | 349034 | 新仓核（尾 `000311326`），111 宿主跳过/回退 |
| 远程仓桥 | `data/xmetadata/wx6/r/L` | 323146 | 新桥，528976 桥不认 |

X 3.0：

| 核心 | 文件 | body | 版本尾 | password / salt | 说明 |
|---|---|---|---|---|---|
| **可用** | `xmetadata/wx7/3.0/r/C` | **370042** | **0021125** | `fafba0be…` / `d32d773b…` | 117 模块可用（package 6 同款） |
| 远程仓 | `data/xmetadata/wx7/3.0/r/C` | 371498 | 0021139 | — / `c7a5bc40…` | 117 不认，Module load error |
| APK 内置 | `X_3.0.apk` assets/d61f | 374179 | 2010033 | — / `919a9e79…` | fallback |

- 模块 111_2.44（SourceForge 最新）与高级包内模块一致，没有更新版本。
- 2.44 仓库同时有 202/207/远程仓核；WeChat 8.0.49 的实际可用组合是
  202 核 + 32B 前缀扩展包 + `fp` 真实包含扩展名。
- X 3.0 项目仓核 370042 可用；远程仓核 371498 更新但 117 不认。
- 核心尾记录可用厂商公钥还原得到 `<版本尾>,<hash>,0`。

## 6. native 关键地址（36a76b97，528976）

```
0x24b20  命令分发返回点（CallMethod）
0x28c5c  命令 133 处理
0x55d68  功能包加载
0x3fec4  容器解析/解密包装
0x4023c  解析器；失败抛 "insufficient bytes"（0x16fc4）
0x56030  失败后使用无效输出，SIGSEGV（fault 0x9）
0x56044  NewByteArray(negative)（Android 16）
```

### 模块 APK 内的 native 资源

| 文件 | 大小 | 类型 | 说明 |
|---|---|---|---|
| `36a76b97…` | 530707 | 容器 | 运行时原生桥（解密后 528976） |
| `dc7be70f…` | 461560 | ELF64 | 含 PBE/msgpack/PBEKeySpec |
| `74fab57f…` | 276456 | ELF32 | 含 PBE/msgpack/PBEKeySpec；`0x189be` 有 S4 片段 `/-9N4hZ_1211_GUJI_n` |
| `d2caec3b…` | 323411 | 容器 | 未识别 |
| `d61f…` | 353907 | 容器 | 模块内置 core |

- 两个 ELF 中都没有 9 位后缀明文（ASCII/LE32/BE32/BCD 均无）。
- 后缀与 C/K/P/S1..S5 的 MD5、SHA1、CRC、Java hash 也没有可验证的派生关系。
- 因此后缀表要么在 native 中以加密/混淆形式存在，要么在运行时按构建常量生成；
  需要运行时内存扫描（模块自身进程内扫描，避免 ptrace 权限问题）或进一步反汇编。


## 7. 宿主限制

- Android 13 上 ART 会在 native 桥 `DeleteLocalRef` 时对 stale local 引用
  `AbortIfNoCheckJNI` 直接 abort，microX 在部分加载路径会因此崩溃；
  Android 16 上表现为解密越界。
- microX 有 safe mode：`FKZ_WX_DATA` 的 `safe_mode` / `safe_mode_cnt`；
  连续失败会停止加载功能。
- 扩展包加载路径的精确失败点（Android 13 实测）：
  外层 AES/验签/尾记录都成功后，宿主用 **0 字节** 的 buffer 连续走
  `InMemoryDexClassLoader` 的三个构造器（日志 3 条 `dex buffer: 0 B`），
  `DexFile.openInMemoryDexFiles` 抛 `Bad range`，随后 native 桥在
  `DeleteLocalRef` 上因 stale local 直接 abort。即宿主的内层解包返回了空。
- 绕过思路：DEBUG 构建里在 `InMemoryDexClassLoader` 构造前，把空 buffer
  替换为已离线解出的 `classes.dex`（按 `CallMethod(102, …)` 的路径/入口类
  识别 sf/mf/af），让宿主拿到有效 ClassLoader。

## 8. af 解锁链路（已验证到哪一步）

```
fp 列表包含 af
  -> CallMethod(133, "af")                     // 宿主返回 "0" 表示成功
  -> 读取 3e9bf1b9 / f0357a3f（4KB 分块）
  -> 解析容器 + PBE(password=ecb9e530…, salt=89fda920…)
  -> 外层 plaintext = signed-array [sig, _c, inner]
  -> 校验签名（本模块已放行）
  -> 解 _c / 内层容器（password 已还原，见 3.1 / 4.1）
  -> 内层 payload（dex/zip）加载
  -> 功能出现在菜单（还受授权功能集约束）
```

- 授权功能集（目标账号）：`[0, 1, 2, 4, 101, 104]`；af 属于付费/授权功能。
- 外层/内层/`_c` 的 password 均已还原（见 3.1 / 4.1）。

## 9. 待办/结论

1. 后缀与密码：已完成。
   - 外层/内层/`_c` 的排列、后缀、password 全表见第 3、3.1、4.1 节。
   - 后缀可用尾记录公钥还原，任意容器都能读出。
2. 2.44 扩展：外层 PBE 已通，但 `133` 在 native `0x56030` 崩溃，未触达
   `id=102`/注入；见第 7、10 节。
3. X 3.0 扩展：已跑通（第 11 节）；最小集与项目仓映射见 11.1。
4. 自签：本模块存在时 `_c`/`_s` 可自签；native 包尾 RSA 记录复制原值
   （第 12 节）。
5. 远程仓新一代：core 371498/版本 0021139 与 cn.android.x 117 不兼容
   （Module load error）；项目仓 core 370042/版本 0021125 可用。

## 10. 包体盘点与运行结论（2026-10-21/22）

| 来源 | 关键内容 | 代际 |
|---|---|---|
| `data/refs/微x2.44+8.0.49高级版.zip` | wx6_2.44 旧版运行目录（base 1035962、themes 200890、core 347578/202 352186、ext 88670/151710/178558、bridge 528976）；DB 三个账号，其中一个 `fp=themes,af,sf,mf` | 旧（111 宿主期望尺寸） |
| `data/refs/wx6_2.44.tar` | 同上旧版 base/themes/bridge + `_c`/`_s`；无 ext 包 | 旧 |
| `data/xmetadata/wx6` | core 349066、base 1037450、themes 202378、ext 88682/151722/178570、r/L 323178 | 新（当前远程仓） |
| `xmetadata/wx6`（项目仓） | r/C 347610、r/L 529008、base 1035994、themes 200922、ext 88702/151742/178590；额外带 `cfg/` 旁车 | 另一旧仓（xmate） |
| `wx.repair.tool2.0.apk` / v2 | Xposed 模块 `wx.repair.tool`：导入 `FKZ_WX_DATA` 并重置 WXID | 工具 |
| `微X配置文件8.0.49+微x3.0.zip` | `X_3.0.apk`（cn.android.x 117）+ `x7_3.0`（base 994250、themes 200554、core 370042/372458、bridge 597288）+ `FKZ_WX_DATA`（账号 buai-qinglikai）+ repair v2 | X 3.0 配置包 |

- X 3.0 主包全部可离线解密（base/core 等密码来自 `X30_EXTRA`；扩展内层
  公式已还原，见第 11 节）；X 3.0 配置包本身不含 sf/mf/af，需另配扩展包。
- 2.44 运行实测：
  - 旧版 base/themes + d61f=202：themes/base 正常加载，`133 sf` 仍在
    native `0x56030` SIGSEGV（fault `0x9`），未进入 `id=102`。
  - 新仓版 base/themes：themes 的 0B dex → `Bad range` → JNI stale-local abort。
  - Android 16：`133 sf` 后 native SIGSEGV（fault 地址为 ASCII `6tencent`），
    属于 111 桥与 ART/JNI 的兼容问题。
- 注入实现已落地：`FeatureDexInjector` 在 `CallMethod(102)` 识别 sf/mf/af，
  构造 `InMemoryDexClassLoader` 前替换空 buffer；`FeaturePackUnlock` 在宿主
  进程内切换 202 核心、补 `fp`/`FPVersions`、清 safe mode。当前卡点仍是
  `133` 的 native 崩溃，注入尚未被触达。
- 已验证可用路径：X 3.0（cn.android.x 117）单开 + 项目仓最小集 +
  项目自动建库；详见第 11、12、13 节。

## 11. X 3.0 扩展包内层与运行时注入（2026-10-22 实测成功）

X 3.0 的扩展包也是 3 元素 signed-array，内层后缀是 **7 位**，公式不含包名 P：

| 组件 | 外层 password | 内层后缀 | 内层排列 | 内层 password | classes.dex |
|---|---|---|---|---|---|
| sf | 80752d1605bf6235493bb1e113c3e8c | 1000217 | K C S2 | 5c897b16c61610673c398e6553f3b | 223752B |
| mf | 4f61bb9ec1e854c9753f878a883a294 | 0200814 | S3 C K | e82b5260fd15c04fd7f1dea075738c1 | 400392B |
| af | 4f74d05b691fd81abe1838b3bffbb9e9 | 2011033 | S1 K C | 5b4f49dc184d84d15cf14915e854449 | 478884B |

注入链路（`FeatureDexInjector`）：

```
CryptoProbe 看到外层 PBE password
  -> 映射为 x30-sf / x30-mf / x30-af（另有 2.44 三组 password）
  -> InMemoryDexClassLoader 构造前，若 buffer 为空则替换为 assets 中的真实 dex
  -> 构造成功，宿主继续加载 com.android.xf.<feature>.Wrapper.Init
```

实测环境（A13）：

- 只启用 `cn.android.x` 3.0 (117)，**不启用** microX 2.44；
- `FKZ_WX_DATA`：repair tool 导入高级包配置，或由项目 `LicenseInstaller`
  自动创建（干净环境实测，见第 13 节）；fp=`themes,af,sf,mf`；
- 我们的 DEBUG 模块启用，assets 带 `x30_{sf,mf,af}.dex`。

结果：af/sf/mf/base/themes/vidurlparser/donation 全部初始化，
`Bad range` / JNI abort 均为 0，微信进程稳定（LauncherUI）。
2.44 单模块仍卡在 `133` native 0x56030，注入尚未被触达；
X 3.0 路径已可实际加载三扩展。

### 11.1 最小可运行集与项目仓映射

项目仓 `xmetadata/wx7` 已包含除 `_s` 外的全部源文件；补齐
`sig/{C,L,base,themes,donation,vidurlparser}`（各 256B）后，
`scripts/build_x30_min.py` 可直接生成与实测环境**逐字节一致**的运行目录：

```bash
python -X utf8 scripts/build_x30_min.py --source xmetadata/wx7 \
    -o build/generated/x30_min \
    --assets app/build/generated/featurepacks/wx30
# 32 个文件, 4,292,161 B (4.09 MiB)
./gradlew :app:assembleLegacyWx30FullEditionDebug
```

| 运行文件 | 项目仓源（带 32B 前缀） | 运行大小 |
|---|---|---|
| `d61f…` | `3.0/r/C`（370074） | 370042 |
| `36a76b97…` | `r/L`（597320） | 597288 |
| `14e777…` | `r/fp/base`（994282） | 994250 |
| `802766a4…` | `r/fp/themes`（200586） | 200554 |
| `a89eaf…` | `r/fp/donation`（121994） | 121962 |
| `df4e6…` | `r/fp/vidurlparser`（129530） | 129498 |
| `aa894d53…` / `60d31eb3…` | `r/fp/sf`（91626） | 91594 |
| `665c7b62…` / `ea81aa7d…` | `r/fp/mf`（148218） | 148186 |
| `3e9bf1b9…` / `f0357a3f…` | `r/fp/af`（182570） | 182538 |
| `534a9729…` | `D`（1191） | 1159 |
| `62a4e566…` | `H_p`（48040） | 48008 |
| `69691c7b…` | `M`（41496） | 41464 |
| `5dbc98dc…` | `S`（258954） | 258922 |
| `739440c5…` | `Xmd`（98296） | 98264 |
| `44c29edb…` | `pr/P`（4600） | 4568 |
| `6d6586c9…` | `pr/P_8049`（43368） | 43336 |
| `dc7be70f…` | `LD64`（533112） | 533080 |
| `_c` 旁车 | `cfg/{C,L,base,themes,donation,vidurlparser}` | 各 599 |
| `_s` 签名 | `sig/{C,L,base,themes,donation,vidurlparser}` | 各 256 |

- 扩展包源只有一份；构建脚本会把它写成宿主探测的两套命名。
- `d61f…_backup_c/_s` 不需要；`9816b5` 副核不需要。
- DB 不在项目仓：最小可用 DB 是高级包 `databases/FKZ_WX_DATA`（45,056B），
  经 `wx repair tool` 导入并重置 WXID。
- 远端仓 `data/xmetadata/wx7` 的 core/base/themes 是新版（core 371498 等），
  与本最小集不兼容；扩展包 body 则与项目仓相同。

### 11.2 X 3.0 组件密钥与 `_c` 表（2026-10-22 补全）

X 3.0 的 password 同样是 `trim(MD5(常量排列 + 7位后缀))`，但**不含包名 P**。
下表为项目仓 / package 6 实测值（salt 为容器 f3）：

| 组件 | 运行名 | 后缀 | 排列 | salt | password |
|---|---|---|---|---|---|
| core（可用） | `d61f…` 370042 | 0021125 | C S4 K | `d32d773b563946f3` | `fafba0be93dfdc4c824e1f55836337a` |
| core（9816b5） | `9816b5…` 372458 | 0010297 | C K S2 | `cb4f0dc476cf6e36` | `a9f3694679ccd2afee49ddae6b27ed9e` |
| core（APK 内置） | `d61f…` 374179 | 2010033 | S1 K C | `919a9e79dd81dda6` | `ef62649872bf334e362a735146212b7` |
| base | `14e777…` | 0002814 | C S3 K | `6ce21e9a6e7bdf13` | `dbba162ca04f5e34992738651a2666f` |
| themes | `802766a4…` | 1020071 | K S5 C | `4ef8d6e5975bc791` | `4912fbaa87edab22b7f737b794b4a39` |
| donation | `a89eaf…` | 0001720 | C K S4 | `b3bd7a8b8bc5c7ea` | `b44dc02d7003e24ffb11d41d5d31323` |
| vidurlparser | `df4e6…` | 1000243 | K C S1 | `7b246fe6504fe9a2` | `46d94ff9016e397dc16a4e99d98fbd` |
| sf（外层） | `aa894d53…` | 2011025 | S4 K C | `cbc70f4d090f2a91` | `80752d1605bf6235493bb1e113c3e8c` |
| mf（外层） | `665c7b62…` | 2011031 | S5 K C | `58b92e5fa34d938e` | `4f61bb9ec1e854c9753f878a883a294` |
| af（外层） | `3e9bf1b9…` | 0102500 | K S4 C | `6ab1b76617b99bfe` | `4f74d05b691fd81abe1838b3bffbb9e9` |
| H_p（meta） | `62a4e566…` | 2011011 | S5 K C | `64a6cec00efffe95` | `bf36c57719f36670d8698e4eae462b7a` |
| M | `69691c7b…` | 0012310 | C S4 K | `df6ebf06ff084612` | `5d456b83a6d59d629f857b5fb6a373f` |
| S（lang） | `5dbc98dc…` | 1000271 | K C S5 | `6c19de68765e453d` | `c22e742b6568af04cac4a8e9d058ef` |
| P（small） | `44c29edb…` | 0010243 | C K S1 | `f550cf3146315368` | `abad9ea3f8c03fbd428aec13e3948dd` |
| P_8049 | `6d6586c9…` | 0002318 | C S1 K | `d160390cf774897a` | `ac282e135a29e137cf97b7677676c520` |

`_c` 旁车（X30 后缀 7 位，公式同样不含 P）：

| `_c` | 后缀 | 排列 | password | payload |
|---|---|---|---|---|
| core_c（项目/package6） | 0012118 | C S1 K | `e6aee704494ab6acd79bc868a75135b` | `eb7fa7bc` |
| bridge_c | 2000149 | S3 C K | `ff7b7880eb457fdbe9337ec41741c2` | `9fd74014` |
| base_c | 0021103 | C S1 K | `6b4358ffa2a33d7d4f9efedf5ee63c39` | `ddc263dd` |
| themes_c | 1020023 | K S1 C | `65e4ed946942e8bf07f16f74328bed` | `19ff561b` |
| donation_c | 1020055 | K S4 C | `6f2a33781f1dacba6ea4d56e5c8822fb` | `ee780e4e` |
| vid_c | 2000185 | S4 C K | `8ed9e8981f2311ed5925332ef14ce19` | `afcbd05` |
| sf_c | 2000119 | S3 C K | `737ff067fc2ac1bddbbe894a526ba87` | `8241bed6` |
| mf_c | 1001227 | K C S2 | `a2d219b37ceb85a673be5125198b1f61` | `bdf54609` |
| af_c | 2010041 | S5 K C | `69be4248a1139b0cf484ba1c4cb1071` | `ab05f14` |

- 另有脚本捕获但运行时文件未定位的 `core_c`：`c68825987b9f66b93262645efd4a459`
  （K S2 C + `0102602`，X_3.0.apk 内置）与 `config`：
  `d31e32db561534aa01d2c4b56b6157d`（S3 C K + `2000139`）。
- `D`、`Xmd`、`LD64` 不是 7 元组容器（`D`/`P` 中只有 `P` 是容器，
  `LD64` 为 ELF），不需要 PBE。
- 2.44 的 9 位后缀 / 含 P 表见第 3、3.1、4.1 节。

## 12. 运行时命名规则与自签边界（2026-10-22）

运行文件名是**确定性哈希**，不是随机：

```
runtime = trim(MD5("FP_<feature>"))   或   trim(MD5("<feature>"))
trim  = 逐字节去掉 hex 的前导 0
```

| feature | MD5("FP_x") | 运行名 |
|---|---|---|
| sf | aa894d53fa41c9b675eec6f80331085 | aa894d53… |
| sf（别名） | 60d31eb37595dd44584be5ef363283e3 | 60d31eb3… |
| mf | 665c7b62836222d48164bc1c5f93fb2 | 665c7b62… |
| af | 03e9bf1b973f6b1617f4f6df9a88f39d | **3e9bf1b9…**（去首位 0） |
| base | 14e777717682cce8a503cfcb34a22d65 | 14e77771…a53c…（去 0） |
| themes | 802766a4a4bd401c145a57463274d4dd | 802766a4… |
| core | MD5("C") = d61f837cad1d412f80b84d143e1257 | d61f837c… |

- 扩展包宿主会探测两套命名，所以运行目录同时放 `FP_x` 与 `x` 两份。
- 少数模块资产（`D`、`Xmd`、`P_8049`、`LD64`、bridge）不遵循这条简单规则，
  是厂商固定 ID/其他角色名，直接按映射表使用。

**自签能力**：

- `_c`：password 链已完整还原（第 4.1 节）。保留原 256B RSA 记录（它给出后缀），
  用自己的 msgpack payload 重新 AES 加密即可；**换后缀**才需要厂商私钥。
- `_s`：厂商用 SHA1withRSA 验签。没有私钥无法生成厂商有效签名；
  但本模块的 `SignatureVerifyBypass` 放行所有 SHA1withRSA，运行环境里可用任意
  256B 自签。
- 包的 256B 尾记录同样是公钥可还原的 RSA 记录；复制原记录即可。
  若替换 payload，`<hash>` 是否被校验尚未验证；保留原 payload 则无此问题。
- 结论：**在本模块运行环境中，`_c` 与 `_s` 都可以自签/自造**；
  脱离本模块的纯厂商校验环境则不行（缺私钥）。
  本模块存在时唯一需要保留的是包尾 256B RSA 记录（native 尾解析用厂商
  公钥）；它可原样复制，不需要私钥。

> 注：`_c` 重加密流程已按格式/密码离线验证（`decrypt_wx244.py` 自检通过），
> 但尚未在设备上做完整的“自签包替换”实测；保留原 payload 与 RSA 记录时
> 风险最低。

**“只换 RSA” 的边界**：

- 换 `_s` 的 256B 签名字节：本模块 `SignatureVerifyBypass` 下可行；
  未打补丁的宿主仍用厂商公钥做 SHA1withRSA，验签失败。
- 换 `_c` / 包尾的 256B RSA 记录为我们自己的密钥：宿主用内嵌**厂商公钥**
  还原（Java 验签 + native 尾解析），换记录会解析失败；必须把宿主的
  公钥/验证路径也换掉。
- 换宿主公钥（Java `KeyFactory`/`Signature` + native 尾解析）后，才可以
  用我们自己的 RSA 完整自签；当前模块只放行了 Java 验签，native 尾解析
  仍用厂商公钥，所以**尾记录继续保留原值**。
- 因此当前最省事的组合是：`_c` payload 用已知 password 重加密、保留原
  RSA 记录；`_s` 用任意 256B（bypass）；包尾记录复制原值。

命名规则已落到 `scripts/runtime_names.py`；`build_release_packs.py` 与
`build_x30_min.py` 都改为按规则推导 feature 运行名（core=`MD5("C")`，
固定 ID 仍用常量），输出与手工验证集逐字节一致。

## 13. 项目包自动恢复与自动建库（干净环境实测）

项目模块本身就会创建运行目录和数据库：

- `FeaturePackRestorer` 从 APK assets 的 `x7_3.0.zip` / `x7_3.0_ext.zip`
  恢复 `files/x7_3.0/`；干净目录下实测恢复 **26 + 6** 个文件。
- `StartupCheck` → `LicenseInstaller.ensure()` 在 DB 不存在时创建
  `databases/FKZ_WX_DATA`，插入 10 行（LIC、verifier6、fp、fp_async、
  FPVersions、LatestVersions 等）；X 3.0 启动后补 `FP_cls_*`，最终 22 行。
  实测关键行：
  `fp=themes,af,sf,mf`、`fp_async=base,vidurlparser,donation`、
  `FPVersions={"themes":113,...,"sf":75,"mf":137,"af":171}`、
  `FPVersions_v7={"themes":116,...,"af":175,"sf":76,"mf":132}`、
  `LIC`/`verifier6` 已生成，`valid=true`、`hookFail=false`。
- `FeaturePackUnlock` 再补 `FPVersions` 的 sf/mf/af 和 `FPVersions_v7`，
  清 safe mode。

干净环境验证方式（DEBUG）：

```
touch /data/data/com.tencent.mm/files/wxh_clean_env   # root
```

`CleanEnvironment.run()` 在微信进程内把旧 `x7_3.0`、旧 DB、`wxh_skip_restore`、
`injected`、导入源等重命名为 `.cleanbak_*`，随后：
restorer 26+6 → LicenseInstaller created → X 3.0 `Module loaded successfully!`。
APK 资产由 `scripts/build_release_packs.py` 从项目仓 `xmetadata/wx7`
生成（X30 自动去 32B 前缀，`cfg/`→`_c`，`sig/`→`_s`）。

