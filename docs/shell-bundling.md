# 单 APK 全量壳方案讨论

> 目标：让 WeXposedHook 一个 APK 同时充当「壳 + 授权绕过 + 功能包」，用户不再额外安装
> 微X 2.44 或 X 3.0。功能包仍使用原版 `wx6_2.44` / `x7_3.0`。
>
> 本文只讨论方案与现状，不改变当前「需要先安装微X」的发布形态。

---

## 1. 现状

```
WeChat 进程
├── 微X 2.44 / X 3.0（壳，Xposed 模块）
│   ├── classes.dex        入口、native 桥、设置 UI、授权/params、更新检查
│   ├── native loader      libwxcoreloader（ELF，实际来自功能包 dc7be70f）
│   └── 功能包              wx6_2.44（基础 26 + 扩展 3）/ x7_3.0（基础 26 + 扩展 3）
│                          加密 dex + _c 校验块 + _s RSA 签名 + ELF/资源
└── WeXposedHook（本模块）
    ├── 还原功能包目录
    ├── 写 FKZ_WX_DATA 授权库
    ├── hook native 桥 / verifier / 功能包验签
    └── 2.44 / 3.0 双 profile
```

壳负责但本模块目前不做的事：

| 能力 | 说明 |
|---|---|
| 解密功能 dex | 容器 `97 c4 01 30 c4 05` + 5 位数字，PBEWithMD5AndDES + 校验 |
| 加载功能 dex | 解密后交给 `InMemoryDexClassLoader`，再调用 `Wrapper.HookWrapper` |
| 包装层 | 功能 dex 依赖 `Wrapper/FPB/XpMethodHook/WxJniCoreBridge` 等壳类 |
| 设置 UI | 壳在微信设置页注入菜单、读写设置 |
| 授权 / params | `FKZ_WX_DATA`、`LIC`、`verifier6`、`params_S6`、适配文件 |
| 在线更新 | 已下线（`Domain Not Configured`），镜像只剩 GitHub 备用 |

本模块已经具备的：

- 两套功能包的完整还原（2.44 基础 26 + 扩展 3 / 3.0 基础 26 + 扩展 3）
- 两套 native 桥 hook、LIC/verifier 绕过、`SHA1withRSA` 验签绕过
- 2.44 授权库写入与功能清单覆盖
- 3.0 的入口识别、桥消息、LIC/guard/settings hook

---

## 2. 为什么可以只装一个

壳本身也是一个 Xposed 模块：`classes.dex` + `assets` + 功能包 + native loader。
功能 dex 的入口类（2.44 的 `com.fkzhang.*Wrapper.*`、3.0 的
`com.android.xc.Wrapper.HookWrapper`）和 native 桥都在壳里，功能 dex 本身不包含
这些包装类。

因此只要把「壳的 dex + native loader + 功能包」都放进本模块，并在微信进程里：

1. 用独立 ClassLoader 加载壳的 `classes.dex`；
2. 反射调用壳的入口（`XposedInit.handleLoadPackage` / `WxCoreLoader` / `HookWrapper`）；
3. 提供给壳正确的 modulePath、filesDir、Context、版本号；
4. 保留本模块已有的授权/验签绕过；

就可以让壳和功能 dex 在本模块内跑起来，用户只装一个 APK。功能包仍是原版。

---

## 3. 需要“套用”的 dex / so 清单

| 版本 | 壳 dex | native loader | 功能包 | 备注 |
|---|---|---|---|---|
| 2.44 | `微X模块_2.44.apk!/classes.dex`（约 2.4 MB） | 功能包 `dc7be70f…`（ELF，461560 B） | `wx6_2.44` 基础 26 + 扩展 3 | 壳入口 `com.fkzhang.wechatxposed.XposedInit` |
| 3.0 | `X_3.0.apk!/classes.dex`（约 1.74 MB） | 功能包 `dc7be70f…`（ELF，533080 B） | `x7_3.0` 基础 26 + 扩展 3 | 壳入口 `com.android.x.XposedInit` |

另外需要：

- 壳 APK 的 `assets/` 资源（2.44 的 8 个 blob、3.0 的 11 个 blob）——部分资源只在
  APK assets 里，不在功能包目录；
- 壳的 `xposed_init`/`META-INF/xposed/*` 描述符（如果直接加载壳 dex，可只保留入口类）；
- 授权库 `FKZ_WX_DATA` 或本模块的绕过；
- 3.0 的 params/适配文件（禁用码 `00322` 的来源）。

---

## 4. 策略 A：打包壳 dex + so + 功能包（推荐的单 APK 路线）

### 4.1 APK 内布局

```
assets/
├── shell/2.44/classes.dex
├── shell/3.0/classes.dex
├── packs/wx6_2.44.zip          # 基础包 26 文件
├── packs/wx6_2.44_ext.zip      # 扩展包 3 文件（仅 full）
├── packs/x7_3.0.zip            # 基础包 26 文件
├── packs/x7_3.0_ext.zip        # 扩展包 3 文件（仅 full）
└── native/<abi>/libwxcoreloader.so   # 从功能包 dc7be70f 提取
```

### 4.2 启动流程

```
HookBootstrap.onProcessReady(main)
├── 解压功能包到 files/wx6_2.44 或 files/x7_3.0
├── 解压壳 dex 到 files/shell/<version>/classes.dex
├── System.load(files/shell/<version>/libwxcoreloader.so)
├── InMemoryDexClassLoader / DexClassLoader 加载壳 dex
├── 反射调用壳入口
│   ├── 2.44: com.fkzhang.wechatxposed.XposedInit.handleLoadPackage(lpparam)
│   └── 3.0:  com.android.x.xposed.hook.WxCoreLoader / com.android.xc.Wrapper.HookWrapper
├── 安装本模块的桥/授权/验签绕过
└── 壳自行解密并加载功能 dex
```

### 4.3 关键实现点

1. **ClassLoader**：壳 dex 必须用独立 ClassLoader（父加载器为微信/框架加载器），
   避免与微信类冲突；壳的 `XposedBridge` 调用使用进程内已有的 Xposed API。
2. **入口参数**：2.44 的 `handleLoadPackage` 需要
   `de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam`；
   3.0 的 `WxCoreLoader` 需要 `Context`、包名、版本号、filesDir、modulePath、
   arch、apkPath（见 3.0 桥 `msg=0` 的参数）。
3. **modulePath**：壳会用它读自己的 assets/so；需要指向本模块 APK 或解压后的路径。
4. **native loader**：`dc7be70f` 是 ELF，没有 `.so` 后缀；复制为
   `libwxcoreloader.so` 后 `System.load`，或按壳的 `libwxcoreloader*` 命名加载。
5. **功能包解密**：壳的 loader 会用 PBEWithMD5AndDES + 5 位数字头解密；本模块不需要
   自己解密，只要把功能包放到壳期望的目录。
6. **授权/params**：继续使用本模块的桥 hook、LIC hook、验签绕过；3.0 的
   params/授权库层由 `X3CallMethodHook` 与 `X3SettingsBypass` 处理。
7. **ABI**：功能包里的 `dc7be70f` 是 arm64 版；32 位微信需要 `36a76b97` 等 32 位
   loader，需按进程 ABI 选择。
8. **更新/UI**：壳的设置 UI、更新检查会照常运行；在线域名已下线，需要接受
   `Domain Not Configured` 或继续 hook 更新流程。

### 4.4 优点 / 风险

| 优点 | 风险 |
|---|---|
| 用户只装一个 APK | 需分发微X壳 dex/so，涉及作者版权声明（readme 明确“不要盗版/转卖”） |
| 功能包仍是原版，升级只换 pack | APK 体积增加 ~6–12 MB（两套壳+两套包） |
| 本模块已有授权/验签绕过可复用 | 壳的入口/参数/native 依赖复杂，加载失败会影响微信启动 |
| 不依赖设备上已安装微X | 壳的 UI/更新/params 仍需维护，3.0 尚未完全跑通 |

---

## 5. 策略 B：干净重写 loader（不打包壳）

自己实现：

- 容器解密（PBEWithMD5AndDES、5 位数字头、CRC/SHA 校验）
- 功能 dex 解密与 `InMemoryDexClassLoader` 加载
- Wrapper/FPB/XpMethodHook/WxJniCoreBridge 兼容层
- 设置 UI、授权、params、更新

优点：不分发壳代码。缺点：工作量远大于当前模块，功能 dex 的类依赖很多，等于重写
半个微X；不建议在现阶段做。

---

## 6. 策略 C：保持现状（推荐短期）

- 用户安装微X 2.44 或 X 3.0 + 本模块；
- 本模块负责功能包、授权、验签、双版本适配；
- 风险最小，升级/回滚容易。

---

## 7. 建议

1. **短期**：保持策略 C；3.0 的 params/设置绕过已由 `X3CallMethodHook` / `X3SettingsBypass` 覆盖。
2. **如果确实需要单 APK**：采用策略 A，但：
   - 明确版权/分发边界；
   - 先只做 2.44 单版本验证，再扩 3.0；
   - 保留“套用壳 dex/so”的开关，出问题可回退到安装微X。
3. **不做策略 B**，除非要长期维护一套完全独立的实现。

---

## 8. 3.0 禁用码（00322）

- 功能包已按版本补齐（2.44 24 / 3.0 26，含 `P_8045/P_8048/P_8049/P_80422428p/P_80482588p` 对应参数）；
- 双 native 桥已 hook，LIC 类方法已 hook，params/verifier guard 已装；
- 禁用码由设置读取层落地，`X3SettingsBypass` hook 设置 helper 的读取方法
  （禁用码返回 0/false，valid 类返回 true），`X3CallMethodHook` 负责 params 版本回写；

---

## 9. 实施 checklist（策略 A）

- [ ] 提取并校验 2.44/3.0 壳 `classes.dex` 的哈希与版本
- [ ] 提取 `dc7be70f` 为 `libwxcoreloader.so`（arm64/arm）
- [ ] 把两套功能包和壳 dex 放进 assets，启动时解压
- [ ] 独立 ClassLoader 加载壳 dex，反射调用入口
- [ ] 传入 modulePath/filesDir/Context/版本号
- [ ] 复用本模块的桥/授权/验签绕过
- [ ] 2.44 先跑通，再扩 3.0
- [ ] 复用 3.0 的 params/设置绕过（00322）
- [ ] 体积/启动耗时/回退方案评估
- [ ] 版权与分发边界确认
