# WeXposedHook / WeXposedTool

微信上的模块集合，包含两个独立安装的组件：

| 组件 | 作用 |
|---|---|
| WeXposedHook（WXH） | 主模块，让微X模块与 X 的功能在启动后直接可用 |
| WeXposedTool（WXT） | 版本伪装工具，对微信的登录、小程序、通话与平板做低版本伪装 |

两个组件互不影响，可以同时安装，也可以只用其中一个。

## 一、WeXposedHook（WXH）

### 特性

- 启动时接管微X的授权校验，功能菜单直接可用
- 内置功能包：检测到功能文件缺失时自动补齐
- 自动写入授权数据库，换账号也能用
- 屏蔽小程序与通话中的宿主版本检测，避免反复提示升级（1.3.9 起由 WXT 搭配负责）
- 同时支持经典 Xposed 与现代 LibXposed 两种入口
- 同时支持微X模块 2.44 与 X 3.0（1.3.9 起理论适配微X 2.26–2.44）
- 一个 APK 同时包含 `arm64-v8a` 与 `armeabi-v7a`，64 位 / 32 位微信都能用
- 在线适配（1.3.9+，理论支持停更前的所有微信版本）

1.3.9 是 WXH 1.x 的终版，已移除内置版本伪装代码，版本伪装相关功能统一由
WeXposedTool（WXT）负责。

### 版本选择指南

发布包按「微X版本 × 框架类型」拆分，共 4 个 APK。

#### 第一步：确认微X模块版本

| 已安装的微X | 下载文件名包含 |
|---|---|
| 微X模块 2.44 | `wx2.44` |
| X 3.0 | `wx3.0` |

#### 第二步：确认框架

| 你的框架 | 下载文件名包含 |
|---|---|
| 新版 LSPosed（模块页面 API ≥ 102） | `modern` |
| 旧版 LSPosed / EdXposed / 其他经典 Xposed | `legacy` |

两者功能完全一致，只是入口 API 不同。不确定时先装 modern；如果框架提示
「该模块需要更新的 Xposed 版本 102」，改用 legacy。

#### 第三步：下载对应组合

例如：

```
WeXposedHook-modern-wx6-v1.3.9.apk
WeXposedHook-legacy-wx6-v1.3.9.apk
WeXposedHook-modern-wx7-v1.3.9.apk
WeXposedHook-legacy-wx7-v1.3.9.apk
```

#### 环境要求

| 项目 | 要求 |
|---|---|
| Android | 8.0 及以上 |
| 微信 | 停更前的所有版本（截至 8.0.49），非 8.0.49 需要在线适配 |
| 微X模块 | 2.26–2.44 或 X 3.0 |

### 使用指南

1. 安装并启用「微X模块 2.44」或「X 3.0」。
2. 安装与微X版本、本机框架匹配的 WeXposedHook APK。
3. 在 LSPosed / EdXposed 中启用本模块，作用域勾选「微信」。
4. 强制停止微信后重新打开（必要时重启手机）。
5. 首次启动会自动补齐功能包并写入授权数据；若功能菜单仍为空，再重启一次微信。

### 在线适配（非 8.0.49）

1. 安装并启用 WXH 1.3.9 与对应的微X / X 模块。
2. 正常打开微信，进入模块菜单，等待在线适配完成。
3. 适配完成后重启微信。

8.0.49 已内置，不需要等待适配。

## 二、WeXposedTool（WXT）

独立的 Xposed 模块，把微信伪装成较低版本，解锁受宿主版本限制的功能：

- 登录低版本伪装
- 小程序低版本伪装
- 解锁鸿蒙通话
- 解锁平板模式与平板登录

### 版本选择

发布包按框架能力拆成 3 个 APK（同包名、同签名，三选一覆盖安装）：

| 框架 | 文件名 |
|---|---|
| 新版 LSPosed（模块页面 API ≥ 102） | `WeXposedTool-v1.1-modern.apk` |
| 仅支持 API 101 的 LibXposed 框架 | `WeXposedTool-v1.1-modern101.apk` |
| 旧版 LSPosed / EdXposed / 经典 Xposed | `WeXposedTool-v1.1-legacy.apk` |

切换变体请**覆盖安装，不要先卸载**，否则设置会被清空。

### 使用指南

1. 安装与本机框架匹配的 APK。
2. 在 LSPosed / EdXposed 中启用模块，作用域勾选「微信」。
3. 强制停止微信后重新打开。

## 三、源码结构与构建

### 工程结构

```
WeXposedHook/
├── build.gradle                  # 根构建脚本
├── settings.gradle               # 阿里云镜像 + google() + mavenCentral()
├── gradle/wrapper/               # Gradle wrapper
├── xmetadata/
├── tool/                         # WeXposedTool（独立模块）
├── shared/                       # app 与 tool 共用的 Hook 抽象
└── app/
    ├── build.gradle              # compileSdk 37、minSdk 26
    ├── proguard-rules.pro        # R8 保留规则
    └── src/
        ├── main/
        │   ├── AndroidManifest.xml
        │   ├── java/io/github/shadowbaby/wechatxposed/hook/
        │   │   ├── framework/    # Hook 框架抽象与启动引导
        │   │   ├── loader/       # dex 加载拦截、组件识别、常量表
        │   │   ├── deploy/       # 内置载荷、启动自检
        │   │   ├── license/      # 授权库生成与写入
        │   │   └── support/      # 目标 dex 的 hook 实现
        │   ├── jniLibs/          # arm64-v8a / armeabi-v7a 的 libwexhook.so
        │   └── res/              # mipmap/logo.png + values/
        ├── wx244/                # 2.44 功能包（assets/wx6_2.44.zip）
        ├── wx30/                 # 3.0 功能包（assets/x7_3.0.zip）
        ├── legacy/               # 经典 Xposed 入口（XposedInit）
        └── modern/               # LibXposed 入口（ModernEntry）
```

`wx244` 与 `wx30` 内置的 `8.0.49` 功能包, 可编译时替换, 或者直接覆盖运行时
`legacy` 与 `modern` 共用 `main` 里的全部逻辑，只在入口处分别适配
`de.robv.android.xposed` 与 `io.github.libxposed.api`。

### 运行时流程

1. 入口记录模块 APK 路径，挂住 `dalvik.system.InMemoryDexClassLoader` 的构造函数，
   并补挂 `DexClassLoader` / `PathClassLoader` 的构造函数。
2. 有 dex 加载时，`loader` 包探测组件入口与关键类：命中 X 3.0 的授权 / 更新 / 设置 /
   组件入口则安装对应 hook；命中微X的组件入口（Base / Core / Themes / Donation）
   则注入并移出待办列表。
3. Core 组件里，`CallMethodBypassHook` 按消息号 130 / 132 / 150 处理校验结果与功能列表，
   `VerifierMethodReplacement` 处理轮询校验、接口请求与更新提示。
4. Base / Themes / Donation 只挂入口方法做握手，命中 `disable`、`updateLicense`、
   `delayed_check` 等方法名时返回 `null`。
5. 微信主进程启动时，`StartupCheck` 先按 APK 版本检查运行时目录
   （`files/wx6_2.44` 或 `files/x7_3.0`）里 27 个功能包文件是否齐全，缺哪个就从
   APK 内置载荷补写；`LicenseInstaller` 再按登录账号补一次授权库。
6. 随后安装 `PackIntegrity`、`PackGuard`、`NoticeSuppressor`，
   防止核心删除功能包或弹出更新提示。
7. 小程序进程（`appbrand0` / `appbrand1`）只安装 `PackIntegrity`。

### 构建

需要 JDK 17 与 Android SDK 37

```powershell
JAVA_HOME=<JDK17> ./gradlew :app:assembleRelease   # 主模块，4 个 APK
JAVA_HOME=<JDK17> ./gradlew :tool:assembleRelease  # 版本伪装工具，3 个 APK
```

## 四、通用说明

### 兼容性

- Android 8.0 及以上
- LSPosed / EdXposed 等支持 Xposed API 的框架

### 说明

- 模块不收集、不上传任何数据；仅在线适配或缺少对应版本规则时下载必要配置。
- 主模块依赖微X模块本身，请先确保对应版本的微X已正确安装并启用。
- 模块会修改微信进程内的运行逻辑，升级微信或微X后若出现异常，请先确认版本兼容性。

### 免责声明

仅供个人学习与研究使用，请勿用于商业用途或违反相关服务条款的场景。