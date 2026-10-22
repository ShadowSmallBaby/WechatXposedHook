# 反逆向与完整性方案

> 2026-10-22。目标：提高静态分析、重打包、注入篡改的成本，同时不牺牲
> 真机稳定性。没有“绝对防逆向”，只有成本与可维护性的平衡。

## 1. 现状

已经具备：

- `release` / `x30` 构建启用 R8（`minifyEnabled true`），类名与包名被混淆/重打包。
- 敏感字符串走 `SecretConstants` 密文 + `libwexhook.so` 解密（`Secret.nativeOf`）。
- PBE salt/password、扩展包计划、项目自签公钥已迁到 native。
- 功能包 `_s` 项目自签 + 启动本地验签；非项目签名直接删除。
- `_s` 验签已迁 native（RSA PKCS#1 v1.5 + SHA-1），Java 不再持有
  `PublicKey` / `Signature`。
- APK 证书自检已落地：直接解析 APK Signing Block（v2/v3）取证书 SHA-256，
  绕开 `PackageManager` / `JarEntry`（壳的 X30Compat 会把这些查询替换成
  原版证书）。
- 功能包 DB 名/AES key/默认 fp、运行目录与签名包清单、恢复清单、PBE salt
  -> password 映射已下沉 native 表。
- `FeatureDexDecoder` 的容器结构、magic、permutation、PBE/AES 已迁 native；
  Java 只保留文件读取与标准 zip 取 `classes.dex`。
- dex 段完整性：构建时把最终 `classes*.dex` 的 SHA-256 写入
  `assets/wxh_integrity`，启动时重算；同签名篡改 dex 会关闭扩展注入。
- 运行时防护：`RuntimeGuard` 检查 `TracerPid` 与 frida/substrate 映射，
  命中时只降级扩展功能。
- 版本标记强制刷新运行目录，避免旧包残留。

仍暴露：

- 壳的 `classes.dex`、`res/`、`assets/<hash>` 是原版文件，可被替换后重打包。
- 激活验签在 native，但“是否允许注入”的 Java 分支仍可被 patch；当前靠
  R8 + 证书固定 + dex 完整性提高成本。
- `PackGuard` 仍依赖 `FeaturePackRestorer.packDirName()`，目录名本身在 native。

## 2. 分层加固

### 2.1 构建期

1. 保持 R8 全量混淆 + `-repackageclasses`；禁止 `-dontobfuscate`。
2. `proguard-rules.pro` 只保留入口和 Xposed 回调所需的成员，其余尽量收缩。
3. 移除 `BuildConfig.DEBUG` 相关日志与调试分支（`DexDumper` 已被 R8 裁掉）。
4. 签名使用 release keystore；不要把 debug 证书带进发布包。

### 2.2 JNI

1. **已完成**：`JNI_OnLoad` 动态注册 `Secret` 与 `LicenseCrypto`，`nm -D` 只剩 `JNI_OnLoad`。
2. 编译参数保持 `-fvisibility=hidden -Wl,--gc-sections -Wl,-s`，并 strip。
3. 敏感函数拆成多个小函数，避免单一入口被定位。
4. 校验调用方：native 侧检查 `BuildConfig` 版本/包名/证书摘要，异常时返回空。

### 2.3 关键逻辑 native 化

优先级：

| 逻辑 | 迁 native | 收益 |
|---|---|---|
| 功能包 `_s` RSA 验签 | 已完成 | 公钥/算法不进 Java 堆 |
| 激活码 Ed25519/RSA 验签 | 高 | 授权分支难 patch |
| 功能包容器解密（msgpack/PBE/AES） | 已完成 | 结构/算法不进 Java 堆 |
| PBE salt/password/组件判定 | 已完成 | Java 只拿 native 返回的 remap 计划 |
| 功能包 DB key/默认 fp、签名包清单 | 已完成 | Java 无明文 key/文件名表 |
| 运行时恢复清单（基础/扩展/别名） | 已完成 | `Secret.restorePlan()` |
| 运行目录文件名/尺寸表 | 低 | 减少明文字面量 |
| 版本伪装 URI 白名单 / 目标版本 | 已完成 | `spoof_tables.inc` + `Secret.hintMatch/spoofVersion` |
| 证书 hook 类/方法名、扩展 dex 路径、PBE/AES 算法名 | 已完成 | `SecretConstants` 加密常量（native 解密） |
| JNI 符号收敛 | 已完成 | `RegisterNatives`，无 `Java_*` 导出 |

### 2.4 完整性

1. **APK 证书自检（已完成）**：构建时从签名密钥库算证书 SHA-256 写入
   `SecretConstants.MODULE_CERT_SHA256`；启动时解析 APK Signing Block 的
   v3/v2 证书比对。不要用 `getPackageArchiveInfo` / `JarEntry`：壳的
   X30Compat 会返回原版 X 3.0 证书。不一致时保留基础包与 PBE 解密钩子，
   只把 `fp` 收窄到 `themes` 并停止扩展 dex 注入；**不能**跳过
   `FeaturePackUnlock` 或 `PbePasswordHook`，否则 3.0 native 在
   `attachBaseContext` 会因 null 对象触发 JNI abort。
2. **dex 完整性（已完成）**：`build_x30_replica.py` 在合并后计算
   `classes.dex` / `classes2.dex` / `classes3..N.dex` 的 SHA-256，写入
   `assets/wxh_integrity`；`DexIntegrity` 启动时重算。证书固定挡住换签名，
   dex 完整性挡住同签名篡改；失败只关闭扩展注入。
3. **资源完整性**：功能包 body 已有 `_s` 项目签名，覆盖了资源层。
4. **运行目录**：`wxh_pack_version` + 本地签名校验，防止替换。

### 2.5 反调试/反注入（谨慎）

- **已完成**：`RuntimeGuard` 检查 `/proc/self/status` 的 `TracerPid`，以及
  `/proc/self/maps` 里的 frida/gum/substrate；release 构建命中时只关闭扩展
  dex 注入，不崩溃。
- 不要做激进的反 root/反 LSPosed：模块本身运行在 LSPosed 环境，误判会直接失效。
- `BuildConfig.DEBUG` 下跳过检测，避免影响本地调试。

### 2.6 响应策略

- 检测失败时**降级而不是崩溃**：关闭扩展注入、保留基础功能，避免用户侧闪退。
- 关键失败写入本地日志（不含密钥），方便排查。

## 3. 不推荐

- 加壳/加固服务（360、梆梆等）：会与 Xposed/壳的资源加载冲突，风险高。
- 动态加载未签名 dex：Android 14+ 限制严格，且会触发安全扫描。
- 过度反调试导致系统/厂商工具误判：A13/A16 上都可能直接闪退。

## 4. 落地顺序

1. ~~`RegisterNatives` + strip~~（已完成）。
2. ~~APK 证书自检（native 内置 SHA-256）~~（已完成）。
3. ~~`_s` 验签迁 native~~（已完成）。
4. ~~激活码验签迁 native~~（已完成，RSA-SHA256 + 机器码/wxid 绑定）。
5. ~~dex 段完整性~~（已完成，assets/wxh_integrity + DexIntegrity）。
6. ~~`FeaturePackRestorer` / `PackGuard` 的包名表并入 native~~（已完成）。
7. ~~`FeatureDexDecoder` 容器解密 native 化~~（已完成）。
8. ~~TracerPid / frida 轻量检测~~（已完成，RuntimeGuard）。
