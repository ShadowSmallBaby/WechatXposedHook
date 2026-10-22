# 公众号卡顿 / 通话低版本：版本伪装最小化改造（2026-10-20）

状态：**已修复，真机验证通过**。公众号、小程序、通话三个场景同时正常；通话期间打开公众号也不受影响。

> 2026-10-22 更新：该方案在 8.0.49 上复测时，通话仍返回 `sub=235`（“对方不支持”）。
> 参数级 ilink `setAppVersion` 已不足以通过服务端校验；最终可用方案与失败矩阵见
> `docs/voip-version-chain-2026-10-22.md` 第 7 节。

## 现象

- 开启模块后，打开公众号文章明显变慢，页面底部偶尔出现“网络问题”提示
- 关闭全局版本伪装后恢复正常，但小程序（如泡泡玛特）和语音/视频通话会提示低版本

## 根因

模块此前把微信全局 `ClientVersion` 从 8.0.49 改成 8.0.79（`HostVersionSpoof.applyClientVersion`），
用来绕过小程序/通话的低版本提示。但公众号文章页（`TmplWebViewMMUI`，主进程）的 JS-SDK
会按 UA/客户端版本做特性探测：

```text
WebViewStubProxyUI 反复拉起（30～1000 次）
action=1 function=handleMPPageAction
actions: getBiz / checkCanCreatePhotoAccount / getClientLanguage / reportXiaoweiCustomEvent ...
```

窗口内捕获到的页面宿主与活动：

```text
com.tencent.mm.plugin.brandservice.ui.timeline.preload.ui.TmplWebViewMMUI
```

全局版本在**进程启动阶段**就参与 UA/配置构建，页面级或 Activity 级临时还原来不及，
所以只有“启动时使用真实版本”才能让公众号恢复正常。

## 失败过的局部方案

| 方案 | 结果 |
|---|---|
| 页面 onCreate/onDestroy、onResume/onPause 临时还原 | 触发太晚，代理页循环仍在 |
| hook `WebSettings.setUserAgentString` 改 UA | 抽象方法不可 hook；UA 在更低层构建 |
| mars `req2Buf` / `getClientVersion` 请求线程作用域 | 通话检查不走 Java 请求回调 |
| `c1.J` / 云通话 `b0.a` / ilink `g0.b` 配置构造 | 未被调用 |
| Flutter `ILinkVoIPDeviceInfoApi.getDeviceInfo` / `ownerVersion` | 未被调用 |
| 全局伪装 + WebView 初始化/页面守卫 | 公众号仍卡 |
| 启动 query 里的 `version=` 参数替换 | hash 与版本一起签名，单独改版本会让 hash 失配 |
| 启动参数 `libVersion` 抬到 9999 | 低版本提示消失，但抽盒机等页面白屏（引擎特性对不上） |

## 最终方案

### 1. 全局版本保持真实

不再修改 `c64.xe.g`。公众号、钱包、网页认证、WebView UA 全部使用 8.0.49。

### 2. 小程序：启动场景短窗口

小程序启动 CGI 场景 `wx0.d`（WeChat 8.0.49）构造时，临时把全局版本改成高版本，
并采用自适应窗口：

- 构造时打开窗口，兜底上限 10 秒
- 启动 CGI 回调 `wx0.d.f(...)` 返回后，只再保留 **1.5 秒** 收尾
- watchdog 每秒检查，到点立即还原

```text
version window open(launch)
version window grace(1500ms)
version window close(watchdog)
```

这样正常启动会在回调后约 1.5 秒恢复，慢启动也不会被截断；窗口外公众号/钱包完全不受影响。

### 3. 通话：ilink 启动配置参数级替换

ilink SDK 初始化时会把 `c64.xe.g` 写进启动配置上报服务端：

```smali
sget v5, Lc64/xe;.g:I
invoke-virtual {v2, v5}, Lcom/tencent/ilink/network/Proto$IlinkStartConfig$Builder;.setAppVersion:(I)...
```

模块 hook `setAppVersion(int)`，仅当参数等于真实版本时，递归调用自身换成 8.0.79：

```text
version window: ilink appVersion -> 0x28004f3d
```

全局字段、UA、公众号链路完全不动；通话检查看到的是 ilink 配置里的高版本。

## 验证

| 场景 | 结果 |
|---|---|
| 公众号文章 | 正常，不再触发代理页循环 |
| 泡泡玛特小程序 | 正常打开，资源下载不转圈 |
| 给 Jin 发起语音/视频通话 | 正常，不再提示对方版本较高/不支持 |
| 通话期间打开公众号 | 流畅（全局字段始终是真值） |

## 限制

- 小程序启动后的 10 秒窗口内，全局字段是高版本；若在这段时间内同时打开公众号，
  网页仍会做特性探测。正常使用（启动小程序后不会立刻开文章）不会触发。
- `wx0.d`、`Proto$IlinkStartConfig$Builder` 是 WeChat 8.0.49 的混淆名；
  换微信版本时需要重新确认。
