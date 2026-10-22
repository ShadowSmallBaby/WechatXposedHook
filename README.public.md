# WeXposedHook

微信上的 Xposed 模块，让 X 3.0 的功能在启动后直接可用；也可直接作为 X 3.0 单 APK 壳使用。

## 特性

- 启动时接管微X的授权校验，功能菜单直接可用
- 内置功能包：检测到功能文件缺失时自动补齐
- 自动写入授权数据库，换账号也能用
- 屏蔽小程序与通话中的宿主版本检测，避免反复提示升级
- 同时支持经典 Xposed 与现代 LibXposed 两种入口（发布包当前为 legacy 单 APK）
- 只保留 X 3.0，源码更精简
- 一个 APK 同时包含 `arm64-v8a` 与 `armeabi-v7a`，64 位 / 32 位微信都能用

## 版本选择指南

发布包按「公开/完整」拆分，共 2 个 legacy 单 APK。modern 入口仍可单独
构建用于测试，但需要另外安装原版 `cn.android.x` 作为壳，暂不作为单 APK 发布。

### 第一步：确认版本

| 需求 | 下载文件名 |
|---|---|
| 只用基础功能 | `WeXposedHook-legacy-v2.0-beta.apk` |
| 需要 sf/mf/af 扩展包 | `WeXposedHook-legacy-v2.0-beta-full.apk` |

不确定时先装公开版；需要扩展功能再换完整版。

### 第二步：下载对应组合

```
WeXposedHook-legacy-v2.0-beta.apk
WeXposedHook-legacy-v2.0-beta-full.apk
```

公开版只带基础包，`-full` 额外带 sf/mf/af 扩展包。当前正式产物只发布
legacy 单 APK；modern 入口仍可单独构建用于测试，不作为单 APK 发布。

### 环境要求

| 项目 | 要求 |
|---|---|
| Android | 8.0 及以上 |
| 微信 | 8.0.49 |
| X 3.0 | 117 |

## 使用指南

1. 安装并启用「X 3.0」。
2. 安装与本机框架匹配的 WeXposedHook APK。
3. 在 LSPosed / EdXposed 中启用本模块，作用域勾选「微信」。
4. 强制停止微信后重新打开（必要时重启手机）。
5. 首次启动会自动补齐功能包并写入授权数据；若功能菜单仍为空，再重启一次微信。

## 手动修改版本伪装

模块首次启动时会在微信数据目录生成版本伪装文件，默认值为 `8.0.79`：

| 模块 | 文件路径 |
|---|---|
| X 3.0 | `/data/data/com.tencent.mm/files/X/wxh_client_version` |

文件内容是一行版本号，例如：

```text
8.0.79
```

需要手动调整时：

1. 先启动一次微信，让模块生成该文件。
2. 使用 root 文件管理器或 adb 修改文件内容；建议保持与微信 `files` 目录相同的属主，权限为 `644`。
3. 强制停止微信，再重新打开。

adb 示例：

```bash
adb shell su -c 'echo 8.0.79 > /data/data/com.tencent.mm/files/X/wxh_client_version'
adb shell su -c 'chmod 644 /data/data/com.tencent.mm/files/X/wxh_client_version'
```

注意：

- 建议只写 `8.0.x` 形式的版本号，不要加入其它说明文字。
- 删除该文件后，下次启动会自动恢复默认值 `8.0.79`。
- 修改后必须强停微信；仅返回桌面或切换账号不一定重新读取。

## 兼容性

- Android 8.0 及以上
- 微信 8.0.49
- X 3.0（117）
- LSPosed / EdXposed 等支持 Xposed API 的框架

## 说明

- 模块不收集、不上传任何数据，也不发起网络请求。
- 功能依赖 X 3.0；单 APK 壳模式已内置原版壳，无需额外安装 X 3.0。
- 模块会修改微信进程内的运行逻辑，升级微信或微X后若出现异常，请先确认版本兼容性。

## 免责声明

仅供个人学习与研究使用，请勿用于商业用途或违反相关服务条款的场景。
