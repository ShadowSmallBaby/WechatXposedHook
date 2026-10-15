# WxModuleHook

针对 WeXposed(微X模块)2.44 的 Xposed 模块。挂住微X把功能 dex 解密进内存的时机,
接管它的授权校验入口,并对功能包文件、授权数据库做逆向与验证。

本仓库同时包含**可编译的模块源码**与**完整逆向分析资料**。

## 仓库结构

```
WxModuleHook/
├── app/                      Android 模块源码(Gradle 工程)
│   └── 代码结构说明.md        源码组织 / 命名约定 / 字符串池对照
├── scripts/                  逆向与生成脚本(Python)
├── docs/                     逆向分析文档
│   ├── reverse-engineering.md   主报告:dex 反汇编、授权链路、设置键
│   ├── fkz-wx-data-crypto.md    授权库三层加密链路分析
│   └── StringPools.java          字符串池留档(不参与编译)
├── tests/hook-regression/    对照参考实现的行为回归(74 项检查)
├── data/                     分析样本:APK / tar / 部署脚本 / 授权库(不入库)
└── README.md
```

## 编译

需要 JDK 17 与 Android SDK 37(AGP 9.4.1 要求 Gradle 9.6+;wrapper 已锁定版本):

```powershell
./gradlew assembleRelease
```

产物:`app/build/outputs/apk/release/app-release.apk`

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

包名说明:混淆包 `a`/`b`/`c` 的类名互相遮蔽,无法直接编译,
故整体语义化为 `rebuild.annotation` / `rebuild.loader` / `rebuild.support`,
详见 `app/代码结构说明.md`。

## 授权数据库(FKZ_WX_DATA)

微X把授权状态存在 `databases/FKZ_WX_DATA`,三层加密(AES-256-CBC → RSA-2048 → 明文字段)。
`scripts/decode_fkz_db.py` 可解密查看;`scripts/generate_min_db.py` 可为任意 wxid
生成一份最小可启动库。

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
不注册真实 Hook、不安装 APK、不访问微信数据)。

```powershell
python -X utf8 tests/hook-regression/run.py --sdk <Android SDK> --jdk <JDK17>
```

## 免责声明

仅供个人学习与研究逆向工程使用。请勿用于商业用途或违反相关服务条款的场景。
