# WeXposedHook

针对 WeXposed(微X模块)2.44 的 Xposed 模块。挂住微X把功能 dex 解密进内存的时机,
接管它的授权校验入口,并对功能包文件、授权数据库做逆向与验证。

本仓库同时包含**可编译的模块源码**与**完整逆向分析资料**。

## 仓库结构

```
WeXposedHook/
├── .github/workflows/        CI:构建 legacy + modern 两个 APK
├── app/                      Android 模块源码(Gradle 工程)
│   ├── src/main/jni/         native 源码(敏感常量解码 + 授权加密;只在内部仓)
│   └── 代码结构说明.md        源码组织 / 命名约定 / 字符串池对照
├── README.public.md          公开仓的 README(同步时改名为 README.md)
├── scripts/                  逆向与生成脚本(Python)
├── docs/                     逆向分析文档
│   ├── reverse-engineering.md   主报告:dex 反汇编、授权链路、设置键
│   ├── fkz-wx-data-crypto.md    授权库三层加密链路分析
│   └── StringPools.java          字符串池留档(不参与编译)
├── tests/hook-regression/    对照参考实现的行为回归(79 项检查)
├── tests/license-data/      授权库生成的 Java/Python 对照
├── tests/dex-probe/          类名常量能否从真 dex 解析出来(点号 vs 斜杠)
├── tests/dex-strings/        dex 常量池解析器与 Python 参考实现逐行对照
├── tests/file-restore/       功能包 30 个文件的补齐逻辑(设备上跑真代码)
├── tests/license-crypto/     授权加密链路(同一份 .inc 与 Python 参考实现对照)
├── tests/secret-encoding/    敏感常量密文与脚本明文逐项对照
├── data/                     分析样本:APK / tar / 部署脚本 / 授权库(不入库)
└── README.md
```

## 编译

需要 JDK 17 与 Android SDK 37(AGP 9.4.1 要求 Gradle 9.6+;wrapper 已锁定版本):

```powershell
./gradlew assembleLegacyRelease assembleModernRelease
```

产物是两个包(两种 Xposed API 各一个,功能相同,按框架版本二选一安装):

| 包 | 适用框架 | 入口描述符 |
|---|---|---|
| `app/build/outputs/apk/legacy/release/app-legacy-release.apk` | 经典 Xposed / 旧 LSPosed / EdXposed(API < 102) | `assets/xposed_init` |
| `app/build/outputs/apk/modern/release/app-modern-release.apk` | 现代 LibXposed,LSPosed **API ≥ 102** | `META-INF/xposed/*` |

两个包都只含自己那份 so,且每个 so 同时带 `arm64-v8a` 与 `armeabi-v7a` 两种 ABI
(微信 8.0.49 的 64 位版本跑 arm64-v8a,32 位版本跑 armeabi-v7a,同一个 APK 都能覆盖)。
现代包若提示「该模块需要更新的 Xposed 版本 102」,改用 legacy 包。

> 内置载荷(功能包目录的 30 个文件,见「模块做的事」第 4 条)就在仓库里:
> `app/src/main/assets/wx6_2.44.zip`,构建时原样打进 assets,单包约 3.0 MB。

> 本机默认 JDK 25 的 class 文件版本(69)不被当前 Gradle 支持,需显式指定 JDK 17:
> `JAVA_HOME=<JDK17 路径> ./gradlew assembleLegacyRelease assembleModernRelease`

> native(敏感常量与授权加密)在 `preBuild` 前用 NDK 的 clang 现编成
> `app/src/main/jniLibs/<abi>/libwexhook.so`。**内部仓**有 `app/src/main/jni/` 源码,
> 每次构建现编;**公开仓**没有源码,直接用随仓提交的 so。两者都没有会在配置阶段报错。

### 两个仓

同一个应用分两个仓,公开仓是内部仓裁掉敏感部分 + 补上编译产物的结果:

| | 内部仓(阿里云效) | 公开仓(GitHub) |
|---|---|---|
| 角色 | 完整开发仓 | 只放 app 与编译好的 so |
| `app/src/main/jni/` native 源码 | 提交 | **没有** |
| `app/src/main/jniLibs/<abi>/libwexhook.so` | gitignore(构建时现编) | **提交**(由内部仓同步) |
| `scripts/` 全部脚本 | 有 | **一个都没有** |
| `docs/` 逆向文档、`tests/` | 有 | **没有** |
| `app/代码结构说明.md` | 有 | **没有** |
| `app/build.gradle` | 完整版(含 native 与密钥任务) | 由 `app/build.gradle.public` 同步改名 |
| 构建 | 本地(阿里云效仓) | GitHub Actions,打两个 APK |

公开仓不需要 native 工具链:CI 直接拿提交的 so 打包,不装 NDK、不跑 clang。

公开仓**不含任何脚本**,这是有意的:`scripts/encode_secrets.py` 里有默认主密钥与完整
编码算法,`scripts/secrets_table.py` 是明文表,两者公开等于把加密作废。密文表
`SecretConstants.java` 在内部仓生成好后随源码同步过去,公开仓构建时直接用
(`encodeSecrets` 任务自动跳过)。所以公开仓 CI **不需要** `WXH_SECRETS_B64`。

公开仓构建**不需要**设 `WXH_MASTER_KEY`:没有 native 源码,构建不消费主密钥,密文表与
so 都是内部仓同步过来的现成产物。**CI 只负责构建**,不做任何密钥 / 文件检测。

密钥是否与密文配套,由内部仓本地的 `scripts/publish_public.py` 在同步前校验:它用
`WXH_MASTER_KEY` 把明文表重新编码一遍,逐项比对工作区的 `SecretConstants.java`,
任何一项不一致都会中止;两个 ABI 的 so、AndroidManifest、gradle wrapper 等构建必需
文件也在这里一次性检查。

同步由 `scripts/publish_public.py` 做(白名单复制,默认拒绝):

```powershell
# 先在内部仓用发布密钥构建出两个 ABI 的 so(不设密钥时脚本会直接拒绝同步)
$env:WXH_MASTER_KEY = "<32 字节 hex 或 Base64>"
./gradlew buildNativeSecret encodeSecrets
# 预演:只比对不写,列出会改哪些 / 公开仓里哪些多余(含空目录、敏感内容)
python -X utf8 scripts/publish_public.py --to <公开仓路径> --check
# 同步(只改文件,不提交不推送)
python -X utf8 scripts/publish_public.py --to <公开仓路径>
```

同步脚本在本地做完全部前置检测,CI 只构建:

- **密钥必填 + 配套**:没设 `WXH_MASTER_KEY` 直接退出(防默认密钥);设了就用它把
  明文表重新编码、逐项比对 `SecretConstants.java`,不一致中止。本机调试确实要用
  默认密钥时显式加 `--allow-default-key`。
- **构建必需文件**:同步清单里必须有 AndroidManifest、两个 ABI 的 so、
  `SecretConstants.java`、gradle wrapper 等,缺一个直接中止。
- **内容扫描**:白名单是目录粒度(`app/src` 整棵树),复制前会扫内置默认主密钥的
  原始值 / hex / Base64、私钥头、常见 token,命中即中止;确认无害再加
  `--allow-sensitive`。
- **清空目录**:删掉白名单外的多余文件,并把因此变空的目录一并删掉,保证公开仓里没有
  `docs/`、`tests/`、`jni/` 之类残留。

公开仓里 `git status` 确认后自行提交、推送。换密钥、改 native、改业务代码都走同一条路:
内部仓构建 → 同步 → 公开仓提交。

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
   - `FeaturePackRestorer` 按清单检查 `files/wx6_2.44` 里的 30 个文件(文件名是内容指纹,
     大小对不上也算缺失),缺哪个就从 APK 的内置载荷(`assets/wx6_2.44.zip`)补写——
     微X 判定未授权时会自己删掉其中一部分;
   - `LicenseInstaller` 按账号补齐 `databases/FKZ_WX_DATA`:10 行内容、表结构与 SQL 都由
     `libwexhook.so` 生成/提供,Java 只负责调度,不再依赖设备上的 shell 脚本。账号先读微信 prefs 里的
    `login_weixin_username`,微X 校验时再把权威账号交过来补一次。
   库或账号已存在时只补缺:已经是该账号的 LIC/verifier6 原样保留,其余设置键一动不动。
   启动自检跑在微X 读文件之前,所以这两步在这次启动里就生效(实测补齐后同一进程直接
   `feature loaded: base 525 / donation 71 / themes 113`);只有库是由微X 校验回调触发补写时,
   微X 已经读过库,才需要再重启一次。
5. `HostVersionSpoof` 在微信主进程与小程序进程(`:appbrand0` / `:appbrand1`)里伪装宿主版本:
   把启动小程序的 CGI 请求里的 `libVersion` 报成 9999,并把官方升级页的跳转 URL 清空,
   让检测宿主版本的小程序不再要求升级。微信的类名是混淆的,所以不写死类名,
   而是用自写的 dex 解析器(`DexStrings`,零第三方依赖)按字符串常量反查目标类。

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

`tests/dex-strings/` 在桌面 JVM 上直接跑 `DexStrings`,和一份独立的 Python 参考实现
对照同一批 dex 的字符串反查结果。需要先从微信 base.apk 解出 dex(不入库):

```powershell
python -X utf8 tests/dex-strings/run.py --jdk <JDK17> --dex-dir <dex 目录>
```

`tests/secret-encoding/` 把 `SecretConstants` 里的密文逐个解回来,和
`scripts/secrets_table.py` 的明文表逐项对照(桌面校验编码链,真机校验 native 解码):

```powershell
python -X utf8 tests/secret-encoding/run.py --jdk <JDK17>
python -X utf8 tests/secret-encoding/run-device.py --sdk <SDK> --jdk <JDK17> --serial <adb>
```

## 免责声明

仅供个人学习与研究逆向工程使用。请勿用于商业用途或违反相关服务条款的场景。
