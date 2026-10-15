# DEX 行为回归

> 需要一个参考实现的 APK 作为对照基线,该文件不入库(在 `data/` 下,已被 .gitignore 忽略)。
> 默认路径 `data/refs/WxModuleHook-1.2.apk`,可用 `--original` 指定。

在已连接的 Android 设备上，通过独立 `app_process` 进程执行参考 DEX 和当前源码，比较 Hook 注册目标、参数、回调模式、反射调用顺序及返回值。Xposed API 使用记录调用的替身，不注册真实 Hook、不安装 APK、不访问微信数据。

运行需要 Python、JDK 17、Android SDK 37 / Build Tools 37.0.0,以及本地参考 `data/refs/WxModuleHook-1.2.apk`:

```powershell
python -X utf8 tests/hook-regression/run.py --sdk C:/Software/DevTools/Android/SDK --jdk C:/Users/Smallbaby/.jdks/liberica-17.0.20.1
```

可以用 `--original` 指定参考 APK，用 `--serial` 选择设备。构建输出在 `build/hook-regression/`，设备上的测试文件是 `/data/local/tmp/wxmodulehook-regression.jar`。

覆盖四个组件的注册、各模式方法拦截、功能列表查询、匹配和不匹配的用户标识、空授权及异常回调。测试数据由固定字符串 `fixture:test-user` 生成，不包含实际账号或授权信息。

对照参考实现的 74 项检查曾出现 17 项差异：功能列表查询在参考实现返回完整列表，而当时本模块错误地比较了编码授权段与用户标识，返回空字符串。其他差异涉及 Core 更新提示 Hook 的目标类、动态组件拦截、授权校验分支和异常清理调用。

这些检查验证上述逻辑与参考实现的一致性;微信内部页面显示、真实类加载及 LSPosed 配置仍需在应用内复测。
