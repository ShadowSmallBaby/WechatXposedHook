# 现代 LibXposed（API 102+）兼容桥方案

> 2026-10-22。适用场景：单 APK 仍是 legacy 壳（`de.robv.android.xposed.*`），
> 但目标框架只提供 libxposed API 102+，不再加载 legacy 入口。

## 1. 现状与结论

- 单 APK 的壳 `classes.dex`、`X30Compat`、hook 载荷全部依赖 legacy API。
- LSPosed 2.2.1 仍支持 legacy，所以目前不需要桥；本方案用于“legacy 被移除”的框架。
- 桥不是改壳，而是在 libxposed 之上**实现一套 legacy API 门面**，让壳以为自己在
  legacy 环境里运行。

## 2. 壳实际用到的 legacy API（静态扫描 `app/x30.zip`）

类型：

```
IXposedHookZygoteInit / StartupParam
IXposedHookLoadPackage
callbacks/XC_LoadPackage$LoadPackageParam
XC_MethodHook / MethodHookParam / Unhook
XposedBridge
XposedHelpers
XSharedPreferences
```

方法/字段（字符串扫描，非完整）：

```
XposedBridge.log
XposedBridge.hookAllMethods / hookMethod / invokeOriginalMethod
XposedHelpers.findClass / findClassIfExists
XposedHelpers.callMethod / callStaticMethod
XposedHelpers.getObjectField / setObjectField
XposedHelpers.getStaticObjectField
XposedHelpers.newInstance
XposedHelpers.setAdditionalInstanceField / getAdditionalInstanceField
```

## 3. 桥的结构

```
libxposed 入口（API 102）
  └─ ModernBridgeModule implements io.github.libxposed.api.XposedModule
       └─ 初始化 LegacyShim（把 de.robv.* 类装入宿主 classloader）
            └─ 反射调用 com.android.x.XposedInit.initZygote(StartupParam)
            └─ 在 onPackageLoaded 时调用 handleLoadPackage(LoadPackageParam)
```

`LegacyShim` 需要提供：

| legacy 类型 | 实现要点 |
|---|---|
| `IXposedHookZygoteInit` + `StartupParam` | 普通接口/数据类；`modulePath` 指向 identity.apk |
| `IXposedHookLoadPackage` + `LoadPackageParam` | 字段：`packageName`、`processName`、`classLoader`、`appInfo`、`isFirstApplication` |
| `XC_MethodHook` / `MethodHookParam` | before/after 回调；`args`、`thisObject`、`getResult/setResult`、`setObjectExtra/getObjectExtra`、`hasThrowable` |
| `XposedBridge` | `log`、`hookMethod`、`hookAllMethods`、`hookAllConstructors`、`invokeOriginalMethod`、`getXposedVersion`（返回 82 或 102 的映射值） |
| `XposedHelpers` | 反射工具：`findClass(IfExists)`、`callMethod`、`callStaticMethod`、字段读写、`newInstance`、additional fields |
| `XSharedPreferences` | 用 `SharedPreferences` 实现只读包装 |
| `XC_MethodHook.Unhook` | `unhook()` 直接调用 libxposed 的 `HookHandle.unhook()` |

## 4. 关键映射

| legacy | libxposed API 102 |
|---|---|
| `XposedBridge.hookMethod(member, callback)` | `xposed.hook(member).setPriority(...).intercept(chain -> ...)` |
| before 回调 | `intercept` 中先执行 before，再 `chain.proceed(args)`，再 after |
| `param.setResult(v)` | 直接 `return v`（不再调用 proceed） |
| `param.args[i] = v` | 修改 `chain.getArgs()` 的副本后 `proceed(changed)`（API 102 的 List 不可变） |
| `invokeOriginalMethod` | `chain.proceed(chain.getArgs())`（需要保存 chain 引用） |
| `getXposedVersion` | 返回 82（legacy 语义）+ 额外标记 |

## 5. 难点与风险

1. **类加载**：壳在 `classes.dex`，桥在 `classesN.dex`；必须保证宿主 classloader
   能解析 `de.robv.*`。单 APK 内所有 dex 同一 classloader，通常没问题。
2. **入口顺序**：libxposed 只回调 `ModernBridgeModule`；壳的 `XposedInit` 必须由桥
   主动反射调用，`StartupParam.modulePath` 用 `files/x30/identity.apk`。
3. **回调优先级**：legacy 的 priority 语义与 libxposed 不同，桥需要映射。
4. **资源/Provider**：壳的 Activity/Provider 在模块进程启动时不能做包名伪装
   （已由 `X30Compat.isModuleProcess()` 处理）。
5. **性能**：每次 hook 都经过 `intercept` 闭包，热路径要注意对象分配。

## 6. 分阶段实施

1. 只实现 `XposedBridge.log` + `hookMethod` + `findClass/callMethod`，跑通壳的
   `initZygote` 与 `handleLoadPackage`。
2. 补 `hookAllMethods`、`invokeOriginalMethod`、字段工具、`XSharedPreferences`。
3. 在 A16 + 纯 libxposed 环境（关闭 legacy 兼容）实测菜单与扩展包加载。
4. 保留 legacy 构建作为回退，桥只在新框架启用。

## 7. 备选

- 继续使用 LSPosed legacy 模式（当前方案），不实现桥。
- 直接把壳的 Java 层重写为 libxposed API（工作量大，见 `docs/x30-replica.md` 的讨论）。
