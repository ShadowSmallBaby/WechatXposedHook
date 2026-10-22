# WeXposedHook

针对 WeXposed(微X模块 2.44) 与 X 3.0 的 Xposed 模块。挂住微X把功能 dex 解密进内存的时机,
接管它的授权校验入口,并对功能包文件、授权数据库做逆向与验证。

本仓库同时包含**可编译的模块源码**与**完整逆向分析资料**。

## 仓库结构

```
WeXposedHook/
├── .github/workflows/        CI:构建 8 个 APK,并按公开/完整版分发
├── app/                      Android 模块源码(Gradle 工程)
│   ├── src/main/jni/         native 源码(敏感常量解码 + 授权加密;只在内部仓)
│   └── 代码结构说明.md        源码组织 / 命名约定 / 字符串池对照
├── README.public.md          公开仓的 README(同步时改名为 README.md)
├── scripts/                  逆向与生成脚本(Python)
├── docs/                     逆向分析文档
│   ├── reverse-engineering.md   主报告:dex 反汇编、授权链路、设置键
│   ├── fkz-wx-data-crypto.md    授权库三层加密链路分析
│   ├── shell30-replica.md       X 3.0 单 APK 复刻（壳 + hook + 项目包）
│   └── shell-bundling.md        单 APK 全量壳方案讨论（历史）
│   └── StringPools.java          字符串池留档(不参与编译)
├── tests/hook-regression/    对照参考实现的行为回归(79 项检查)
├── tests/license-data/      授权库生成的 Java/Python 对照
├── tests/dex-probe/          类名常量能否从真 dex 解析出来(点号 vs 斜杠)
├── tests/file-restore/       功能包补齐逻辑(2.44 24 个 / 3.0 26 个,设备上跑真代码)
├── tests/license-crypto/     授权加密链路(同一份 .inc 与 Python 参考实现对照)
├── tests/secret-encoding/    敏感常量密文与脚本明文逐项对照
├── data/                     分析样本:APK / tar / 部署脚本 / 授权库(不入库)
└── README.md
```

## 编译

需要 JDK 17 与 Android SDK 37(AGP 9.4.1 要求 Gradle 9.6+;wrapper 已锁定版本):

```powershell
./gradlew assembleRelease
```

产物按「框架 × 微X版本 × 公开/完整」组合，共 8 个 APK：

| 维度 | 取值 |
|---|---|
| 框架 | `legacy`（经典 Xposed / API < 102）、`modern`（LibXposed API ≥ 102） |
| 微X版本 | `wx2.44`、`wx3.0` |
| 版本 | 公开版（无后缀）、完整版（`-full`） |

文件名格式：

```
WeXposedHook-{modern|legacy}-wx{2.44|3.0}-v{version}.apk
WeXposedHook-{modern|legacy}-wx{2.44|3.0}-v{version}-full.apk
```

输出目录：

```
app/build/outputs/apk/<framework><wx><edition>/release/
```

每个 APK 只内置对应微X版本的基础包；完整版额外内置扩展包，公开版不带扩展包。
两个 ABI 仍同时打包在同一个 APK 中。

> 功能包 zip 不再入库，构建前由 `generateFeaturePacks` 从 `xmetadata` 生成到
> `app/build/generated/featurepacks/wx244/`（基础包）、`wx244-ext/`（扩展包），
> 以及对应的 `wx30/`、`wx30-ext/`。

> 本机默认 JDK 25 的 class 文件版本(69)不被当前 Gradle 支持,需显式指定 JDK 17:
> `JAVA_HOME=<JDK17 路径> ./gradlew assembleRelease`

> native(敏感常量与授权加密)在 `preBuild` 前用 NDK 的 clang 现编成
> `app/src/main/jniLibs/<abi>/libwexhook.so`。内部仓与核心仓都有 `app/src/main/jni/`
> 源码;**so 只是构建产物**,不入库,核心仓 CI 用 Actions cache 复用。

### 三个仓

| | 内部仓(阿里云效) | 核心仓(GitHub 私有) | 公开仓(GitHub) |
|---|---|---|---|
| 角色 | 完整开发仓 | 构建/发布仓 | 源码公开仓 |
| `app/src/main/jni/` native 源码 | 提交 | 同步 | 没有 |
| `app/src/main/jniLibs/<abi>/libwexhook.so` | gitignore(构建时现编) | CI 构建后缓存,不提交 | 没有 |
| `scripts/` | 全部 | 仅 `encode_secrets.py` / `build_release_packs.py` | 没有 |
| `docs/`、`tests/`、`app/代码结构说明.md` | 有 | 没有 | 没有 |
| `xmetadata/` | 有 | 有 | 有 |
| 构建 | 本地 | GitHub Actions,8 个 APK | 不构建 |
| 发布 | 无 | Release / tag | 无,只接收 README / CHANGELOG 同步 |

核心仓构建时用 `WXH_MASTER_KEY` + `WXH_SECRETS_B64` 生成 `SecretConstants` 与两个功能包 zip;
`so` 由 native workflow 构建并写入 Actions cache,不入库。公开仓只保留 `xmetadata/`、
README、CHANGELOG、LICENSE,不构建、不发布,文档由核心仓发版时自动同步。

同步由 `scripts/publish_public.py` 做(白名单复制,默认拒绝):

```powershell
# 预演:只比对不写,列出会改哪些 / 核心仓里哪些多余(含空目录、敏感内容)
python -X utf8 scripts/publish_public.py --to <核心仓路径> --check
# 同步(只改文件,不提交不推送)
python -X utf8 scripts/publish_public.py --to <核心仓路径>
```

同步脚本在本地做完全部前置检测,CI 只构建:

- **密钥必填 + 配套**:没设 `WXH_MASTER_KEY` 直接退出(防默认密钥);设了就用它把
  明文表重新编码、逐项比对 `SecretConstants.java`,不一致中止。本机调试确实要用
  默认密钥时显式加 `--allow-default-key`。
- **构建必需文件**:同步清单里必须有 AndroidManifest、`xmetadata/`、两个构建脚本、
  gradle wrapper 等,缺一个直接中止。
- **内容扫描**:白名单是目录粒度(`app/src` 整棵树),复制前会扫内置默认主密钥的
  原始值 / hex / Base64、私钥头、常见 token,命中即中止;确认无害再加
  `--allow-sensitive`。
- **清空目录**:删掉白名单外的多余文件,并把因此变空的目录一并删掉,保证核心仓里没有
  `docs/`、`tests/`、`jni/` 之类残留。

核心仓里 `git status` 确认后自行提交、推送。换密钥、改 native、改业务代码都走同一条路:
内部仓构建 → 同步 → 核心仓提交 → 打 tag 触发 CI。

### 签名

发行签名只从环境变量读取,不落库;四个变量任缺一个即回退 debug 签名:

仓库根的 `.env` 是这些变量的模板(已在 `.gitignore` 里),填好后在构建前加载:
Git Bash 用 `set -a; source .env; set +a`,PowerShell 用文件顶部注释里的命令。
Gradle 本身不读 `.env`,必须先把变量导进当前 shell。

| 环境变量 | 内容 |
|---|---|
| `WXH_KEYSTORE_BASE64` | 发行密钥库(`.jks`)的 Base64,单行 |
| `WXH_STORE_PASSWORD` | 密钥库口令 |
| `WXH_KEY_ALIAS` | 私钥条目 alias |
| `WXH_KEY_PASSWORD` | 私钥条目口令 |

本地生成密钥库的 Base64:

```powershell
# PowerShell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\keys\release.jks"))
# Git Bash
base64 -w0 /c/keys/release.jks
```

- **本地(命令行)**:填进 `.env` 的 `WXH_KEYSTORE_BASE64`;构建时 Gradle 解码到
  `app/build/keystore/release.jks`,不要求本机存在固定路径的 jks。
- **本地(IDE)**:Run/Debug 之外的打包走 *Build → Generate Signed App Bundle / APK*,
  直接选发行密钥库即可,不需要设环境变量。
- **CI**:四个变量用 Secrets 注入,工作流原样写入 `GITHUB_ENV`,由 Gradle 解码到 build 目录。
- 密钥库与口令须异地备份,不入源码、CI 日志或发行附件;正式发布后不要更换证书身份,
  否则模块签名变更会导致覆盖安装失败(需先卸载旧版)。

### CI

`.github/workflows/build.yml` 在 push tag(`v*`)、PR 与手动触发时构建两个包:

```powershell
./gradlew assembleLegacyRelease assembleModernRelease
```

产物固定命名为 `wxmodulehook-legacy.apk` / `wxmodulehook-modern.apk` 上传为
workflow artifact;推 `v*` tag 时一并发到 GitHub Release。CI 用的 Secrets:

| Secret | 用途 |
|---|---|
| `WXH_KEYSTORE_BASE64` | 发行密钥库(`.jks`)的 Base64;缺省则回退 debug 签名 |
| `WXH_STORE_PASSWORD` / `WXH_KEY_ALIAS` / `WXH_KEY_PASSWORD` | 密钥库与私钥口令 |

CI 不做密钥库落盘:Base64 经 `GITHUB_ENV` 透传,由 Gradle 解码到
`app/build/keystore/release.jks`(构建产物目录,不留在工作区根)。
CI 只构建,不做密钥 / 文件检测:密钥配套、so 是否齐全、有没有混入内部材料,全部由
内部仓本地的 `scripts/publish_public.py` 在同步前校验(见「两个仓」一节)。
公开仓不生成密文,所以不需要 `WXH_SECRETS_B64`,也不需要 `WXH_MASTER_KEY`。

## 模块做的事

入口 `github.shadowbaby.wechatxposed.hook.XposedInit`(`assets/xposed_init` 指向),
纯 `IXposedHookZygoteInit`,无 Activity / Service。

1. `XposedInit` 挂 `dalvik.system.InMemoryDexClassLoader` 构造 —— 微X把功能 dex 解密进内存时拦截。
2. `InMemoryDexLoadHook` 在刚加载的 classLoader 里识别微X的四个组件 dex
   (Base / Core / Themes / Donation),并屏蔽 5 个授权校验入口
   (`disable` / `on_update_check` / `process_metadata` / `updateLicense` / `delayed_check`)。
3. `WxComponentHooks` 对每个 dex 注入 hook,`CallMethodBypassHook` 拦截
   `WxJniCoreBridge.CallMethod`,按 `bypassMode` 伪造授权校验结果与功能列表。
4. `XposedInit.handleLoadPackage` 在微信主进程启动时跑一次启动自检:
   - `FeaturePackRestorer` 按 APK 版本检查对应运行时目录(2.44 24 个 / 3.0 26 个文件,
     文件名是内容指纹,大小对不上也算缺失),缺哪个就从 APK 的内置载荷补写——
     载荷由构建脚本从 `xmetadata/` 生成;微X 判定未授权时会自己删掉其中一部分;
   - `PackIntegrity` 在主进程与 `:appbrand0/1` 都安装:按内置载荷校验文件数量与 SHA-256,
     `d61f8` / `36a76b` / `dc7b` 等核心文件被写入、出现 `a660e` / `a282` 自解包副本,
     或旧核心类出现时,直接对 `files/x7_3.0` 做目录级覆盖恢复;
   - `LicenseInstaller` 按账号补齐 `databases/FKZ_WX_DATA`:10 行内容、表结构与 SQL 都由
     `libwexhook.so` 生成/提供,Java 只负责调度,不再依赖设备上的 shell 脚本。账号先读微信 prefs 里的
    `login_weixin_username`,微X 校验时再把权威账号交过来补一次。
   库或账号已存在时只补缺:已经是该账号的 LIC/verifier6 原样保留,其余设置键一动不动。
   启动自检跑在微X 读文件之前,所以这两步在这次启动里就生效(实测补齐后同一进程直接
   `feature loaded: base 525 / donation 71 / themes 113`);只有库是由微X 校验回调触发补写时,
   微X 已经读过库,才需要再重启一次。
5. `HostVersionSpoof` 在微信主进程与小程序进程(`:appbrand0` / `:appbrand1`)里伪装宿主版本:
   主进程在 `LauncherUI.onResume` 时把 `c64.xe.g` 设为版本文件里的客户端版本
   (默认 8.0.79,可手动修改),文件位于 `files/X/wxh_client_version`(3.0)或
   `files/WechatXposed/wxh_client_version`(2.44)。进入钱包/转账页面
   (`WalletBaseUI` 及白名单内的页面)时临时还原真实版本,退出后恢复。
   启动约 30 秒后还会主动请求一次官方升级页(24 小时内不重复),
   减少用户看到升级页的概率。

包名说明:混淆包 `a`/`b`/`c` 的类名互相遮蔽,无法直接编译,
故整体语义化为 `loader`(dex 加载拦截与识别)/ `license`(授权库生成与写入)/
`deploy`(内置载荷与启动自检)/ `support`(对目标 dex 的 hook 实现),详见 `app/代码结构说明.md`。

### 敏感常量

微X 的混淆类名、校验方法名、58 项功能列表、AES 密钥、锚点串、功能包清单都不以明文
出现在源码或 dex 里,而是由 `scripts/encode_secrets.py` 编码成密文写进
`loader/SecretConstants.java`,运行时 `Secret.of` 还原,构建前(Gradle `encodeSecrets` 任务)
自动重新生成。明文表与编码逻辑是分开的两个文件:

- `scripts/encode_secrets.py` 是编码逻辑 + 常量名清单 + **默认主密钥**,只在内部仓;
- `scripts/secrets_table.py` 是常量名 -> 明文,**只在内部仓提交**(公开仓没有,同步时被排除);
- 内部仓本机构建:跑脚本,明文来自 `scripts/secrets_table.py` 或 `WXH_SECRETS_B64`;
- 公开仓:**没有脚本**,直接用随源码同步过去的 `SecretConstants.java`(密文)。

解码在 `libwexhook.so` 里(`app/src/main/jni/secret.c`):主密钥与算法都在 so 内,
dex 里既没有明文也没有密钥。不提供 Java 回退——回退会把主密钥写回 dex。
`libwexhook.so` 的产出与入哪个仓见「两个仓」一节。

对应关系由 `tests/secret-encoding/` 逐项校验。

#### SecretConstants.java 怎么产生、密钥是什么

1. **产生方式**:`./gradlew` 的 `preBuild` 依赖 `encodeSecrets` 任务,构建前跑
   `scripts/encode_secrets.py`,把明文表逐项编码后**覆盖写**成
   `app/.../hook/loader/SecretConstants.java`(74 个 `public static final String`,只有密文)。
   明文来源按优先级:环境变量 `WXH_SECRETS_B64` → `scripts/secrets_table.py` →
   都没有时沿用仓库里已提交的密文(不打断构建)。
2. **密钥固定还是随机**:固定。`MASTER_KEY`(32 字节)硬编码在 `app/src/main/jni/secret_crypto.inc`
   与 `scripts/encode_secrets.py` 里,两份必须逐字节一致;每项的子密钥由它 + 常量名派生
   (与随机数无关)。所以同一份明文表每次生成出的密文完全相同。
   换密钥只需设一个环境变量:构建时设 `WXH_MASTER_KEY`(32 字节 hex 或 Base64),
   Gradle 会同时喂给 clang(编进 so)和 `encode_secrets.py`(生成密文),两边保证一致;
   没设就用 `secret_crypto.inc` 与 `encode_secrets.py` 里的内置默认值。要求与自检见下节「换主密钥」。
3. **对称还是非对称**:对称。算法是「HKDF-SHA256 派生子密钥 + 逐字节 XOR + 位置混合(`index*31`)」
   再 Base64,加解密用同一把密钥,没有公私钥对。这不是密码学意义上的加密(AES 之类),
   目的是让 `strings classes.dex` 拿不到明文,把门槛抬到「逆 so 的 native 代码 + 复现 HKDF」。

#### 每项一把子密钥(HKDF)

密文格式是 `"<常量名>:<Base64>"`,常量名随密文一起进 dex;so 拿它当 HKDF-SHA256 的 salt,
从 `MASTER_KEY` 派生该常量专属的 32 字节子密钥:

```
子密钥 = HKDF-SHA256(ikm=MASTER_KEY, salt=常量名, info="wexhook-v2", L=32)
密文   = Base64( 逐字节 XOR(明文, 子密钥, index*31) )
```

所以**逆出某一项的子密钥推不出其它项**,这也是它比「全体共用一把种子」强的地方。
`Secret.of(encoded)` 的签名不变(名字从密文前缀里取)。
C 与 Python 两份 HKDF 实现必须同源,由 `tests/secret-encoding/run.py --clang <clang>` 逐项比对。

#### 换主密钥

主密钥就是这一套常量编码的根:**换它等于换一套密文**,`SecretConstants.java` 必须重新生成,
否则运行时全部解不出来(hook 找不到类)。要求与步骤:

1. **要求**:恰好 32 字节(256 bit),写成 64 个 hex 字符或标准 Base64 都行,两边规则一致
   (`encode_secrets.py` 的 `parse_master_key()` / Gradle 的校验;Gradle 先解码成 32 个字节,
   再用 `-DWXH_MASTER_KEY_BYTES` 编进 so,不做运行期字符串解析)。
   生成:`python -c "import os;print(os.urandom(32).hex())"`。
2. **设一个变量**:`WXH_MASTER_KEY=<32 字节>`(写进仓库根 `.env` 再加载,或直接设环境
   变量;公开仓 CI 不需要这个变量,它只构建)。没设就用内置默认值;**发布路径必须设**,
   `publish_public.py` 会在缺失时直接失败。
3. **一条命令重新构建**:`./gradlew assembleLegacyRelease assembleModernRelease` ——
   `buildNativeSecret` 与 `encodeSecrets` 都会读到同一个值,自动重编 so 并重新生成密文,
   两边不会错配。想只想重生成密文:`python -X utf8 scripts/encode_secrets.py --master-key <同一个值>`。
4. **自检**:设着 `WXH_MASTER_KEY` 跑
   `python -X utf8 tests/secret-encoding/run.py --jdk <JDK17> --clang <clang>` ——
   它会给 C 侧同一个 `-DWXH_MASTER_KEY_BYTES`,逐项比对 HKDF 派生,不一致就 FAIL。
   再用 `./gradlew verifyNativeSecret` 校验工作区里的 so 与源码、当前主密钥现编的逐字节一致
   (干净 clone 还没建过 so 时先跑 `buildNativeSecret`,任务会提示缺哪个 ABI)。
5. **换完必须重编 so 并重装**:主密钥在 so 里,老 so 配新密文解不出来。密文与 so 必须成对,
   不要把新 `SecretConstants.java` 配老 `libwexhook.so` 发布。
6. **同步到公开仓**:`python -X utf8 scripts/publish_public.py --to <公开仓> --check` 预演,
   再正式同步;脚本会先校验密钥配套、确认构建必需文件齐全,然后才复制
   `SecretConstants.java` 和两个 ABI 的 so。
7. **公开仓提交后看 CI**:只需要确认两个 APK 构建通过。CI 不做密钥校验,也不需要
   GitHub Secret `WXH_MASTER_KEY`;同步前本地脚本已经把关。

## 授权数据库(FKZ_WX_DATA)

微X把授权状态存在 `databases/FKZ_WX_DATA`,三层加密(AES-256-CBC → RSA-2048 → 明文字段)。
`scripts/decode_fkz_db.py` 可解密查看;`scripts/generate_min_db.py` 可为任意 wxid
生成一份最小可启动库。

同一套生成逻辑已搬进模块(`app/.../hook/license/`):启动时按当前账号自动写好这份库
(账号先读微信 prefs 的 `login_weixin_username`,微X 校验时再补一次),
不需要设备上的 shell 脚本,也不需要进菜单点一下。
Java 实现与脚本的一致性由 `tests/license-data/run.py` 逐行校验,
「库/账号已存在」的各种场景由 `tests/license-data/run-device.py` 在真机上验证。

```powershell
# 解密查看
python -X utf8 scripts/decode_fkz_db.py <FKZ_WX_DATA 路径>

# 生成最小库(单个或多账号,多账号写进同一个库)
python -X utf8 scripts/generate_min_db.py wxid_1234567890 out.db
python -X utf8 scripts/generate_min_db.py wxid_a,wxid_b,wxid_c merged.db
```

要点(详见 `docs/reverse-engineering.md`):

- `ACCOUNT` 列必须等于当前登录 wxid,否则整表读不到;同一设备多账号共用一份库。
- `LIC` 三段结构 `"<blob>#<flag>#<seg3>"`,**段 3 的 key 是 `SHA-256(当前 wxid)`**
  (AES/CBC/PKCS7,零 IV),必须按账号现算。照抄别的账号的段 3 会解出乱码 →
  微X 判定未授权 → 不显示 `[VIP][专业]`、菜单为空,**并删掉 `wx6_2.44` 里的三个功能包**。
  生成脚本自带自检(解回去必须等于 `[1]`)。
- `PRAGMA user_version` 必须为 1,否则微X 建表报 `table DATA already exists` 启动失败。

## 脚本

| 脚本 | 用途 |
|---|---|
| `scripts/encode_secrets.py` | 把敏感常量编码成 `SecretConstants.java`(含默认主密钥,**只在内部仓**) |
| `scripts/secrets_table.py` | 敏感常量的明文表(只在内部仓提交,公开仓被排除) |
| `scripts/publish_public.py` | 按白名单把内部仓里该公开的部分同步到公开仓工作区 |
| `scripts/decode_fkz_db.py` | 解密 `FKZ_WX_DATA` 的 AES / RSA 两层 |
| `scripts/generate_min_db.py` | 生成最小可启动授权库(单/多账号,带自检) |
| `scripts/decode_microx_strings.py` | 复刻微X的字符串混淆解码器 |

`docs/StringPools.java` 是字符串池留档,在 app 的 sourceSet 之外,**不参与编译、不打进 APK**。
可直接运行复核:

```powershell
java docs/StringPools.java
```

## 行为回归测试

`tests/hook-regression/` 用独立 `app_process` 进程执行参考实现与本模块源码,
比较 Hook 注册目标、参数、回调模式、反射调用顺序及返回值(Xposed API 用记录调用的替身,
不注册真实 Hook、不安装 APK、不访问微信数据)。共 74 项检查,全部与参考实现逐条对照。
启动自检与内置载荷不在这套回归里(它们要真的读微信目录),由真机验证覆盖。

```powershell
python -X utf8 tests/hook-regression/run.py --sdk <Android SDK> --jdk <JDK17>
```

`tests/secret-encoding/` 把 `SecretConstants` 里的密文逐个解回来,和
`scripts/secrets_table.py` 的明文表逐项对照(桌面校验编码链,真机校验 native 解码):

```powershell
python -X utf8 tests/secret-encoding/run.py --jdk <JDK17>
python -X utf8 tests/secret-encoding/run-device.py --sdk <SDK> --jdk <JDK17> --serial <adb>
```

## 免责声明

仅供个人学习与研究逆向工程使用。请勿用于商业用途或违反相关服务条款的场景。
