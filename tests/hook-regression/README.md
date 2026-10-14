# 原版 DEX 行为回归

在已连接的 Android 设备上，通过独立 `app_process` 进程执行原版 DEX 和当前源码，比较 Hook 注册目标、参数、回调模式、反射调用顺序及返回值。Xposed API 使用记录调用的替身，不注册真实 Hook、不安装 APK、不访问微信数据。

运行需要 Python、JDK 17、Android SDK 36 / Build Tools 36.0.0，以及本地原版 `data/refs/WxModuleHook-1.2.apk`：

```powershell
python -X utf8 tests/hook-regression/run.py --sdk C:/Software/DevTools/Android/SDK --jdk C:/Users/Smallbaby/.jdks/liberica-17.0.20.1
```

可以用 `--original` 指定原版 APK，用 `--serial` 选择设备。构建输出在 `build/hook-regression/`，设备上的测试文件是 `/data/local/tmp/wxmodulehook-regression.jar`。

覆盖四个组件的注册、各模式方法拦截、功能列表查询、匹配和不匹配的用户标识、空授权及异常回调。测试数据由固定字符串 `fixture:test-user` 生成，不包含实际账号或授权信息。

修复前，对照原版的 74 项检查有 17 项出现差异。其中功能列表查询在原版返回完整列表，重建版错误比较了编码授权段与用户标识，返回空字符串。其他差异涉及 Core 更新提示 Hook 的目标类、动态组件拦截、授权校验分支和异常清理调用。

这些检查验证上述逻辑与原版的一致性；微信内部页面显示、真实类加载及 LSPosed 配置仍需在应用内复测。
