# WeXposedHook

针对 WeXposed(微X模块)2.44 的 Xposed 模块。挂住微X把功能 dex 解密进内存的时机,
接管它的授权校验入口,并对功能包文件、授权数据库做逆向与验证。

本仓库同时包含**可编译的模块源码**与**完整逆向分析资料**。

## 仓库结构

```
WeXposedHook/
├── app/                      Android 模块源码(Gradle 工程)
│   └── 代码结构说明.md        源码组织 / 命名约定 / 字符串池对照
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
├── data/                     分析样本:APK / tar / 部署脚本 / 授权库(不入库)
└── README.md
```

## 编译

需要 JDK 17 与 Android SDK 37(AGP 9.4.1 要求 Gradle 9.6+;wrapper 已锁定版本):

```powershell
./gradlew assembleRelease
```

产物:`app/build/outputs/apk/release/app-release.apk`

> 内置载荷(功能包目录的 30 个文件,见「模块做的事」第 4 条)就在仓库里:
> `app/src/main/assets/wx6_2.44.zip`,构建时原样打进 assets,产物约 3.0 MB。

> 本机默认 JDK 25 的 class 文件版本(69)不被当前 Gradle 支持,需显式指定 JDK 17:
> `JAVA_HOME=<JDK17 路径> ./gradlew assembleRelease`

### 签名

发行签名只从环境变量读取,不落库;四个变量任缺一个即回退 debug 签名:

| 环境变量 | 内容 |
|---|---|
| `WXH_KEYSTORE_PATH` | 密钥库文件路径 |
| `WXH_STORE_PASSWORD` | 密钥库口令 |
| `WXH_KEY_ALIAS` | 私钥条目 alias |
| `WXH_KEY_PASSWORD` | 私钥条目口令 |

- **本地(IDE)**:Run/Debug 之外的打包走 *Build → Generate Signed App Bundle / APK*,
  直接选发行密钥库即可,不需要设环境变量。
- **CI**:四个变量用 Secrets 注入,工作流在密钥库存在时落盘并写入 `GITHUB_ENV`。
- 密钥库与口令须异地备份,不入源码、CI 日志或发行附件;正式发布后不要更换证书身份,
  否则模块签名变更会导致覆盖安装失败(需先卸载旧版)。

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
   - `LicenseInstaller` 按账号现算并写入 `databases/FKZ_WX_DATA`(`LicenseData` 生成 10 行,
    `LicenseDatabase` 写入),不再依赖设备上的 shell 脚本。账号先读微信 prefs 里的
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

## 免责声明

仅供个人学习与研究逆向工程使用。请勿用于商业用途或违反相关服务条款的场景。
