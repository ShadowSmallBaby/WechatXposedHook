# WeXposedHook

微信上的 Xposed 模块,让「微X模块 2.44」的功能在启动后直接可用。

## 特性

- 启动时接管微X的授权校验,功能菜单直接可用
- 内置功能包:检测到功能文件缺失时自动补齐
- 自动写入授权数据库,换账号也能用
- 屏蔽小程序对宿主版本的检测,避免反复提示升级
- 同时支持经典 Xposed 与现代 LibXposed 两种入口
- 一个 APK 同时包含 `arm64-v8a` 与 `armeabi-v7a`,64 位 / 32 位微信都能用

## 下载与版本选择

从 [Releases](../../releases/latest) 下载最新版本:

| 文件 | 适用框架 | 选择建议 |
|---|---|---|
| `WeXposedHook-modern.apk` | 现代 LibXposed(LSPosed API ≥ 102) | 新版 LSPosed 优先选它 |
| `WeXposedHook-legacy.apk` | 经典 Xposed API(API < 102) | 旧 LSPosed / EdXposed |

两个包功能完全一致,只是入口 API 不同。不确定时先装 modern;如果框架提示
「该模块需要更新的 Xposed 版本 102」,改用 legacy。

## 使用指南

1. 安装并启用「微X模块 2.44」。
2. 安装与本机框架匹配的 WeXposedHook APK。
3. 在 LSPosed / EdXposed 中启用本模块,作用域勾选「微信」。
4. 强制停止微信后重新打开(必要时重启手机)。
5. 首次启动会自动补齐功能包并写入授权数据;若功能菜单仍为空,再重启一次微信。

## 兼容性

- Android 8.0 及以上
- 微信 8.0.49
- 微X模块 2.44
- LSPosed / EdXposed 等支持 Xposed API 的框架

## 说明

- 模块不收集、不上传任何数据,也不发起网络请求。
- 功能依赖微X模块本身,请先确保微X已正确安装并启用。
- 模块会修改微信进程内的运行逻辑,升级微信后若出现异常,请先确认版本兼容性。

## 免责声明

仅供个人学习与研究使用,请勿用于商业用途或违反相关服务条款的场景。
