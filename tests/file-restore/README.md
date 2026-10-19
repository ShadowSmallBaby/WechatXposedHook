# 功能包目录自检与补齐

`FeaturePackRestorer` 按清单检查微信 `files/wx6_2.44` 里的 24 个文件
(文件名即内容指纹 + 字节数),缺哪个就从模块 APK 的 `assets/wx6_2.44.zip` 补哪个。
载荷由构建脚本生成,2.44 APK 只携带 24 个文件;3.0 的清单为 26 个。
这里在设备上跑**真正的 App 代码**(`FeaturePackRestorer` + `ModuleApk`),
场景都铺在 `/data/local/tmp` 下的临时目录里,不碰微信真实目录。

需要 JDK17、Android SDK、adb,以及一份已构建的 release APK。

```powershell
python -X utf8 tests/file-restore/run.py --sdk <Android SDK> --jdk <JDK17> --serial <adb serial>
python -X utf8 tests/file-restore/run.py --sdk <SDK> --jdk <JDK17> --serial <serial> --apk <APK 路径>
```

| 场景 | 期望 |
|---|---|
| 目录不存在 | 建目录并铺满 24 个 |
| 目录为空 | 铺满 24 个 |
| 缺 7 个 | 只补缺的,已有的文件一个字节不动 |
| 文件大小不符 | 按缺失重写(大小是粗筛) |
| 大小相同但内容不同 | 不重写——名字即指纹,同名不同内容是"另一批版本",不属于本套清单 |
| 多出清单外的文件 | 保留不动,只补清单内的 |
| 全部齐全 | 一个字节都不改 |
| 补齐内容 | 与内置载荷逐字节一致(md5 比对) |
| 重复调用 | 幂等(`ensureOnce` 一个进程只查一次) |

## 为什么只按"在不在 + 大小"判

微X 删文件、改动文件都不报错,事后追它的失败事件太晚;而「文件在不在、大小对不对」是幂等的,
任何一次启动都能把状态拉回来。代价是"同尺寸但内容不同"判不出来——真机上这种情况是 microX
按数据库版本行下载的**另一批版本**(实测 4 个同名文件内容不同、`d61f837c…` 那组连名字都换成了
内容指纹 `9816b5df…`),不属于本套清单,不重写是对的。

探针 `src/FileRestoreCheck.java` 里带一个 `XposedBridge` 替身:app_process 里没有 Xposed 框架,
`ModuleLogger` 的日志改成打到 stdout(真机上走 `XposedBridge.log`)。
