# AGENTS.md

本文件面向在本仓库中工作的 AI 代理与开发者，记录项目结构、构建方式、运行时链路和不可随意改动的约束。

## 项目概览

微信 Xposed 模块集合，宿主包名固定为 `com.tencent.mm`，同一仓库产出两个可独立安装的应用：

| 模块 | 应用名 | 作用 |
|---|---|---|
| `:app` | WeXposedHook（WXH） | 接管微X模块的授权校验、自动补齐功能包、写入授权库、屏蔽更新提示 |
| `:tool` | WeXposedTool（WXT） | 对登录、小程序、通话、平板做低版本伪装 |

`shared` 是两者共用的 Hook 抽象层。目标微X模块有两个分支：微X 2.44（`wx244`）与 X 3.0（`wx30`），WXH 按 flavor 分别产出 APK。

- 基线微信版本：8.0.49（非 8.0.49 走在线适配）
- Android：minSdk 26（README 宣称支持 8.0+），compileSdk / targetSdk 37
- 当前版本：WXH `2.0`（versionCode 15），WXT `1.1`（versionCode 6）

## 技术栈

| 项 | 版本 |
|---|---|
| Gradle wrapper | 9.8.0 |
| Android Gradle Plugin | 9.4.1 |
| Kotlin（仅 tool） | 2.4.21 |
| Java 源/目标 | 17 |
| CI JDK | 21 |
| Xposed API | `de.robv.android.xposed:api:82`（compileOnly） |
| LibXposed API | `io.github.libxposed:api:102.0.0`；tool 另有 `101.0.1` 变体 |

仓库没有单元测试、没有 lint 门禁（`abortOnError false`）。验证方式是编译 + 检查 APK 内容 + 真机日志。

## 目录地图

```
app/
├── build.gradle                 # 4 个变体、载荷解包任务、签名字段
├── src/main/java/.../hook/
│   ├── framework/               # HookBootstrap、PlatformHooks
│   ├── loader/                  # SecretConstants、dex 加载拦截（按 flavor）
│   ├── deploy/                  # ModuleApk、StartupCheck、FeaturePackRestorer
│   ├── license/                 # 账号探测与授权库写入
│   ├── support/                 # guard / pack / shell / identity
│   └── ui/                      # 模块设置页
├── src/main/jniLibs/            # arm64-v8a + armeabi-v7a 的 libwexhook.so
├── src/legacy/                  # 经典 Xposed 入口 XposedInit
├── src/modern/                  # LibXposed 入口 ModernEntry + 兼容桩
├── src/wx244/                   # 微X 2.44 专属 hook、pack/wx6_2.44.zip、assets/shell.apk
└── src/wx30/                    # X 3.0 专属 hook、pack/x7_3.0.zip、assets/shell.apk、PKCS#7 签名
tool/
├── src/main/java/.../tool/
│   ├── hook/feature/            # call / miniprogram / tablet
│   ├── hook/version/            # VersionWindow、VersionTables、各类伪装入口
│   ├── hook/spoof/              # 规则模型、证书校验、成员契约
│   ├── hook/guard/              # ChatMvvmGuard、WalletVersionGuard
│   ├── config/                  # 设置模型与快照发布
│   └── ui/                      # Compose + miuix 设置界面
├── src/main/assets/             # 5 个哈希命名的规则资产
├── src/legacy/                  # 经典入口 + ContentProvider 设置通道
└── src/modern/                  # LibXposed 入口 + remote preferences 通道
shared/src/main/java/.../shared/hook/   # HookFramework / HookCallback / HookParam
xmetadata/                        # 离线分析数据（wx6 / wx7 / wxt），不参与构建
```

## 构建

### 前置

1. JDK 17 或更高，Android SDK 37。
2. `local.properties` 指向本机 SDK。
3. 真机或发布构建前导入 `.env`（内含 keystore 与自签证书）：

```bash
set -a; . ./.env; set +a
```

`app/build.gradle` 在构建时读取 `WXH_KEYSTORE_BASE64`、`WXH_STORE_PASSWORD`、`WXH_KEY_ALIAS`、`WXH_KEY_PASSWORD`，并把证书公钥编码进 `BuildConfig.MODULE_CERT_B64`。未导入时回退到 `~/.android/debug.keystore`，产物签名不一致，覆盖安装会失败，运行时身份/机器码也会漂移。

### 命令

```bash
./gradlew :app:assembleRelease    # WeXposedHook-modern-wx2.44|wx3.0-v2.0.apk
                                  # WeXposedHook-legacy-wx2.44|wx3.0-v2.0.apk（共 4 个）
./gradlew :tool:assembleRelease   # WeXposedTool-v1.1-{modern,modern101,legacy}.apk（共 3 个）
./gradlew :tool:assembleModernApisRelease   # 一次构建 modern + modern101
```

- WXT 的 release 目前固定使用 debug 签名（三个变体必须同签名才能覆盖安装），不要"顺手"改成 `.env` 签名，除非同时确认升级路径。
- 依赖仓库统一在 `settings.gradle` 配置（`FAIL_ON_PROJECT_REPOS`）。不要往模块 `build.gradle` 里加 `repositories`。

### 变体与产物命名

WXH：`framework` × `wx` 两个维度。产物名由 `androidComponents.onVariants` 生成。
`BuildConfig.WX_PACK` 是 `"wx6_2.44"` 或 `"x7_3.0"`，运行时决定功能包目录 `files/<WX_PACK>`、壳目录 `files/wxh_shell/<WX_PACK>`。

WXT：`legacy`（API 82）、`modern101`（API 101）、`modern`（API 102）。三者同包名 `io.github.shadowbaby.wechatxposed.tool`、同签名，覆盖安装切换。

### CI

- `.github/workflows/app-build.yml`：tag `v*` 触发，构建 `:app:assembleRelease`。
- `.github/workflows/tool-build.yml`：tag `WXH-v*` 触发，构建 `:tool:assembleRelease`。
- 发布说明按 `CHANGELOG.md` 的 `## vX.Y` / `## WXT-vX.Y` 段落提取。
- CI 会校验载荷条目数（两个 zip 各 15 条）与 APK 内资产名，改载荷前先看 workflow。

## 运行时链路

### WXH（`:app`）

1. 入口（`XposedInit` / `ModernEntry`）调用 `HookBootstrap.remember(modulePath)`。
2. 微信主进程（`com.tencent.mm` 或 usap/zygote 类进程）进入 `processReady`：
   `Activation.install` → `installEarly` → `StartupCheck.run` → `installZygote` → `installPackGuards` → 5 秒后启动账号探针（最多 6 轮、间隔 3 秒）。
3. `StartupCheck`：
   - `FeaturePackRestorer.ensureOnce` 把 APK 内 assets 恢复/修剪到 `files/<WX_PACK>`，并写版本标记 `wxh_pack_version`（内容为 versionCode）。
   - 账号存在时 `LicenseInstaller.ensure` 写授权库。
4. `installZygote` 挂 `InMemoryDexClassLoader` 构造，并补挂 `DexClassLoader` / `PathClassLoader`。命中微X/X 的组件入口后再安装 `CallMethodBypassHook`、`X3CallMethodHook` 等。
5. 守卫：`PackGuard` 拦截对功能包目录里文件的 `File.delete`（`.zip` 例外）；`NoticeSuppressor` 过滤特定更新提示文本。
6. `HookBootstrap.processReady` 对 appbrand 进程直接返回：载荷恢复与壳解包只发生在主进程，zygote 阶段的 dex 加载挂点对所有进程生效。

### WXT（`:tool`）

1. 入口把宿主 ClassLoader、模块 APK 路径、设置来源交给 `HostRuntime.start`。
2. 后台线程等待宿主 `Application`，读取设置快照：
   - modern/101：LibXposed remote preferences（group `settings`，key `snapshot`）
   - legacy：只读 `ContentProvider`（UID 校验在 `SettingsReadAccess`）
3. `SpoofProfiles.configureWithRetry`：
   - 从模块 APK 读证书资产，校验固定 SHA-256（`SpoofTrust.CERT_SHA256`）
   - 读 `SPOOF_HOOKS_ASSET` 与版本对应的 profile 资产，解码成规则
   - 失败时不安装任何伪装。
4. 主进程装 `VersionSpoofInstaller.installMain`（MVVM guard、版本窗口、钱包 guard、平板、网络、通话、小程序）；
   appbrand 进程只装 `installAppBrand`。
5. 设置热更新：监听 + 30 秒轮询差异，必要时重新打开/关闭全局版本窗口。

## 不可随意改动的约束

### 载荷与资产

- `app/src/wx244/pack/wx6_2.44.zip`、`app/src/wx30/pack/x7_3.0.zip` 会在构建时解包到 APK 的 `assets/` 根目录，条目名是哈希（如 `14e777717682cce8a53cfcb34a22d65`），运行时按名逐字节恢复。**不要重命名条目**，否则 `FeaturePackRestorer` 与 CI 校验都会失配。
- `FeaturePackRestorer.skipAsset` 明确跳过 `shell.apk`、`xposed_init`、`x3-*`、`8af2692b...`，这些是壳/签名资产，不是功能包文件。
- `shell.apk` 由 `ShellBundle` 解到 `files/wxh_shell/<WX_PACK>/shell.apk`，并用 `VERSION_CODE:WX_PACK` 作为 stamp。修改壳或 bump 版本后才会重新解包。
- 功能包版本标记与 `BuildConfig.VERSION_CODE` 绑定：不发版本号就只补缺失文件，不会覆盖已有文件。
- `wx244` 与 `wx30` 目录下有同名类（如 `InMemoryDexLoadHook`），实现按微X版本各自演进。不要把一个 flavor 的源码放到 `src/main`，会与另一个 flavor 的实现混淆或编译重复。

### WXT 规则

- 规则资产文件名（`15fdaf...` hooks、`534a...` 证书、`7b52...` profile、`13ec...` 8.0.48-play profile）被代码和 CI 同时引用，改名需同步全部引用。
- 规则里的类名、方法名、参数签名不是明文，统一通过 `HostFingerprint.fp*` / `MemberRules` 从 profile 取。新增键时 profile JSON 与代码必须成对更新，否则运行时抛 `Missing host string/signature`。
- `SpoofTrust.CERT_SHA256` 是证书指纹硬编码。换签名证书时三处一起改：证书资产、SHA-256 常量、`BuildConfig.SPOOF_CERT_ASSET`。
- `VersionTables` 是白名单匹配：`CALL` 的 `getonlineinfo`/`voipilink`、`LOGIN` 的 `manualauth` 等。不要把匹配放宽到整个 URI 前缀。
- 钱包一律走真实版本：`WalletVersionGuard` 在钱包相关 Activity 的 `onCreate/onDestroy` 之间让 `VersionWindow` 恢复真实版本。
- `ChatMvvmGuard` 只把 `...LoadDataUseMvvm` 配置改为 0，`...ListUseMvvm` 必须放行。拦截 List 会让会话列表退回主线程数据库查询，造成 ANR。

### 设置通道

修改设置模型时四个位置保持同步：

1. `tool/.../config/HookSettings.kt`（UI 侧模型）
2. `tool/.../hook/config/ToolSettings.java`（宿主进程侧解析）
3. `tool/.../config/PreferenceKeys.kt`
4. 发布通道：`ModernSettingsPublisher`（remote prefs）与 `LegacySettingsProvider`（ContentProvider）

`HookSettings.SNAPSHOT = "snapshot"`、`GROUP = "settings"` 是跨进程契约，不要改字面量。新增设置项要给 `ToolSettings.parse` 提供缺省值，老快照必须能继续解析。

### 签名与入口

- `app` 的 debug 与 release 都设置 `debuggable false`，不要打开。
- `proguard-rules.pro` 里 keep 的入口类（`XposedInit`、`ModernEntry`、`Wx244Hooks`、`Wx30Hooks`、`ModernSettingsPublisher`）是反射/框架查找的目标，新增入口要补 keep 规则。
- `Secret.of` 当前是直通实现；新增宿主类名/方法名常量放 `SecretConstants`，不要在业务代码里散落字面量。

## 编码约定

- 运行时代码必须防御式：每个 hook 安装点包 `try/catch` 并写日志，异常绝不能冒泡到微信。
- 日志走 `ModuleLogger` / `ToolLogger`，不要 `System.out` 或直接 `android.util.Log`（tool 的 UI 侧除外）。
- Java 侧允许 Java 17 语法（record、switch 表达式、`var`）。Kotlin 仅用于 tool 的设置 UI、入口与 `SettingsStore`。
- 注释、日志前缀、UI 文案使用中文；不要引入英文注释的混合风格。
- `app` 不引入第三方运行时依赖（Xposed API 与 LibXposed service 均为 compileOnly/框架提供）。`tool` 的 UI 依赖 Compose BOM 与 miuix-kmp。
- 能复用 `shared` 的抽象就复用，不要在 `app` 与 `tool` 各写一套 Hook 包装。

## 常见改动流程

### 新增 WXH 的 hook

1. 判断归属 flavor：微X 2.44 → `app/src/wx244/java/...`，X 3.0 → `app/src/wx30/java/...`。
2. 在对应 `Wx244Hooks` / `Wx30Hooks` 的 `installZygote`、`installEarly` 或 `installPackGuards` 中注册。
3. 类名/方法名常量加进 `SecretConstants`。
4. 确认运行进程（主进程 / appbrand），不要在 appbrand 装 UI 相关 hook。

### 新增 WXT 伪装特性

1. 在 `tool/src/main/java/.../hook/feature/<域>/` 新建类，通过 `HookFramework` + `HostFingerprint` 定位宿主成员。
2. 在 `VersionSpoofInstaller.installMain` / `installAppBrand` 注册。
3. 需要新的宿主指纹时，同时更新 `tool/src/main/assets/` 下对应 profile 资产。
4. 若受设置控制，按上面"设置通道"四处同步。

### 升级内置功能包

1. 替换 `app/src/<flavor>/pack/*.zip`（保持文件名与条目名）。
2. 需要强制覆盖时 bump `versionCode`（版本标记据此判断）。
3. 跑一次 `:app:assembleRelease`，用 `unzip -Z1` 确认 assets 数量与 CI 期望一致。

### 适配新的微信版本（WXT）

`SpoofProfiles.profileAsset` 目前区分 `8.0.48`（play 资产）与其他版本（通用资产）。新增版本适配 = 更新 profile 资产里的 `wxvers.<versionName>` 条目，并确认 `fingerprints` 覆盖旧模板的全部键（`SpoofProfile.covers` 会校验）。

## 验证清单

```bash
./gradlew :app:assembleRelease :tool:assembleRelease
unzip -Z1 app/build/outputs/apk/modernWx30/release/WeXposedHook-modern-wx3.0-v2.0.apk | grep '^assets/'
unzip -Z1 tool/build/outputs/apk/modern/release/WeXposedTool-v1.1-modern.apk | grep '^assets/'
```

真机：

1. 作用域勾选「微信」，强制停止微信后重开。
2. LSPosed 日志确认：
   - WXH：`module 2.0 (15)`、`feature packs: restored ...`、`login account=...`
   - WXT：`settings initial: ...`、`spoof rules: 8.0.x (built-in|imported)`、`chat mvvm guard: hooked`
3. WXT "未激活/不生效"时先搜 `spoof rules:` 行：证书校验失败、资产缺失、宿主版本不在规则里都会在这里给出原因，而不是 UI 状态。

## 排障提示

- WXH 菜单为空：先看账号探测（`login account=`）。账号可能在启动后 3–4 秒才可用，壳侧过早读取会跳过协议。
- 小程序白屏：优先检查功能包是否完整、`files/wxh_shell/<WX_PACK>/shell.apk` 的 stamp 是否与版本一致。
- 会话列表卡顿/ANR：确认没有误拦 `...ListUseMvvm`。
- 钱包页异常：确认 `WalletVersionGuard` 已 hook 到对应 Activity，版本窗口在钱包内应处于真实值。

## 发布约定

- 不要擅自执行 `git commit` / `git push` / 打 tag，除非用户明确要求。
- WXH 发布 tag 形如 `v2.0`；WXT 发布 tag 形如 `WXH-v1.1`（workflow 再映射到 `CHANGELOG.md` 的 `WXT-v1.1` 段落）。
- 发布前同步 `README.md` 与 `CHANGELOG.md`，并确认 `versionName` / `versionCode` 已递增。
