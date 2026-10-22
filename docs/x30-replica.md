# X 3.0 壳复刻（单 APK，阶段一）

> 2026-10-22。目标：把原版 `X_3.0.apk`（`cn.android.x` 117）与本项目**从源码构建**的
> wx30 full hook 合进一个 APK，只安装本项目插件 + 内置项目包即可运行；原版 X 3.0 /
> microX 2.44 均不安装。阶段二已移除 app/构建中的 2.44。

## 1. 结果

输出：

```
app/build/outputs/apk/release/WeXposedHook-legacy-v2.0-beta-full.apk
app/build/outputs/apk/release/WeXposedHook-legacy-v2.0-beta.apk
package = github.shadowbaby.wechatxposed.hook
versionCode = 8 / versionName = 2.0-beta / minSdk = 26
签名 = v2 + v3（不再生成 v1）

full   : size = 5,616,600 B
         sha256 = 5aefefd27614cd482736235f3ebb97c094600ee7d03df24a951509c721fa9c0f
public : size = 5,194,460 B
         sha256 = 49f8f9ede5f27a426ffa3e02b8556306533fa822ff6247998c7b94a1d76f0054
```

> 壳身份仍按 `cn.android.x` 117 处理：`assets/x30/identity.apk` 的
> manifest/versionCode 保持 117，模块 APK 自身用项目版本号。

设备实测（微信 8.0.49），原版 `cn.android.x` 已卸载、microX 2.44 未启用：

- Android 13（Redmi K20 Pro，KernelSU + LSPosed）
- Android 16（Xiaomi 23127PN0CC，Magisk + LSPosed 2.2.1）


```
X: feature loaded: base 519
X: feature loaded: themes 116
X: feature loaded: vidurlparser 31
X: feature loaded: af 175 / donation 72 / sf 76 / mf 132
X: Module loaded successfully!
```

证据：`build/analysis/af13/x30-20261022/`。

### 1.1 干净环境实测（2026-10-22，Android 16 / 微信 8.0.49）

测试前把 `files/x7_3.0`、`files/x30`、`databases/FKZ_WX_DATA` 全部改名清空：

- 公开版（无扩展包）
  - `feature packs[x30]: restored 26 file(s) from payload`
  - 自动创建 `FKZ_WX_DATA`（`DATA` 表 20 行，含 `FPVersions`/`fp`/`LIC`）
  - 菜单完整：`3.0_5.42 (b62)[VIP][专业]`
  - 无 `publish blocked`、无 native SIGSEGV
- 完整版（含 sf/mf/af）
  - `feature packs[x30-ext]: restored 3 file(s) from payload`
  - `feature dex: decoded/inject x30-af / x30-sf / x30-mf`
  - 无 native SIGSEGV

### 1.2 已知问题：系统设置/桌面仍显示默认绿色图标

- APK 内 `res/{CD,lP,ku,pt,9e,6Y}.png` 已全部换成项目 logo（RGBA），
  `aapt2 dump badging` 指向该资源，设备上的文件也能正常解码。
- HyperOS 仍显示绿色渐变默认图标；换成自适应图标、位图 drawable、
  甚至故意写成无效资源 ID，显示结果都一样，疑似系统级图标定制/缓存。
- 处理暂缓。

### 1.3 模块自身进程

`X30Compat.initZygote` 执行时进程名仍是 `usap64`，无法提前判断模块自身进程；
因此包名/签名/路径 hook 里用 `currentProcessName()` 运行时判断，命中
`github.shadowbaby.wechatxposed.hook` 时直接跳过伪装。否则启动
`com.android.x.MainActivity` 时，`androidx.startup.InitializationProvider`
会按 `cn.android.x/...` 查找并抛 `NameNotFoundException`。

已验证 A13/A16：设置界面可正常打开。

### 功能包默认值修复

`FeaturePackUnlock` 不再覆盖已有值：

- `fp` / `fp_async` 只追加默认值中缺失的项，保留已有项与顺序；
- `FPVersions` / `FPVersions_v7` 只补缺失 key，不覆盖已有版本号；
- 公开版不再强制把 `fp` 改成 `themes`。

A13 实测：`fp themes -> themes,af,sf,mf`；已有额外项时为
`fp keep themes,af,sf,mf,df`。

## 2. 输入

| 角色 | 路径 |
|---|---|
| 壳基座 | `app/x30.zip`（从 `data/refs/X_3.0.apk` 抽取的必要条目，SHA-256 `671a9a8b…f93fdd5`） |
| hook 载荷 | `app/build/outputs/apk/legacyFullEdition/release/WeXposedHook-legacy-v2.0-beta-full.apk`（源码构建，R8 混淆） |

hook 载荷由 `:app:assembleLegacyWx30FullEditionX30` 生成，必须含：
`FeatureDexInjector` / `FeaturePackUnlock`、`assets/featuredex/x30_{sf,mf,af}.dex`、
`assets/x7_3.0*.zip`、两个 ABI 的 `libwexhook.so`。

`assets/featuredex` 不再从 `data/refs` 读取：`extractFeatureDex` 在构建时从
`xmetadata/wx7/r/fp/{sf,mf,af}` 的容器解出，输出与旧的离线 dex 逐字节一致。

壳基座已抽取到 `app/x30.zip`（manifest、`resources.arsc`、`classes.dex`、
`res/`、Kotlin builtins、`assets/xposed_init`、壳独有的 32 位 loader、原版
`CERT.RSA`），构建时由 `pack_shell_dir` 打成临时壳 APK；`resources.arsc`
保持 STORED。CI 不再需要外部壳 APK。

重新抽取（本地 `data/refs/X_3.0.apk` 存在时）：

```bash
python -X utf8 scripts/extract_shell_entries.py
```

`app/x30.zip` 内的 `SOURCE.txt` 记录了来源 APK 的 SHA-256。

## 3. 产物结构

```
classes.dex                    原版 X_3.0 classes.dex（逐字节不变）
classes2.dex                   X30Compat（包名/签名/路径兼容）
classes2..N.dex                compat + 源码构建的 hook dex
lib/arm64-v8a/libwexhook.so
lib/armeabi-v7a/libwexhook.so
assets/x30/identity.apk    仅含壳 manifest + resources.arsc 的身份 APK（176,474 B；
                               LSPosed 1.9.x 需改用完整原版 APK，见 8.2）
assets/x30/original_cert.rsa 原版 CERT.RSA（native 读证书时映射到它）
assets/<hash>                 18 个平铺资产（15 个基础/壳资源 + 3 个扩展包）
                              其中带 _c/_s 的条目在构建时合并为 WXH1，运行时拆开
                              写到 files/x7_3.0/；扩展包另一套命名的 3 个别名由
                              FeaturePackRestorer 运行时代拷
assets/74fab57f…               壳内置 32 位 native loader（项目包没有）
assets/dc7be70f…               64 位 native loader（从 x7_3.0 包取）
assets/534a9729…               证书资源（从 x7_3.0 包取）
assets/xposed_init             3 行：compat / 本项目 hook / com.android.x.XposedInit
AndroidManifest.xml            包名 + 项目名称/版本
resources.arsc / res/*         项目 logo / 自适应图标
```

不包含 `wx6_2.44*`、`featuredex/{sf,mf,af}.dex`、`featuredex/core202.bin`。

### 3.1 壳 assets 与项目包的关系

壳 APK 原带 10 个 blob，但只有 3 个是真正需要的：

| 壳资源 | 处理 |
|---|---|
| `dc7be70f…`（64 位 loader） | 与 `x7_3.0.zip/LD64` 逐字节一致，从项目包取 |
| `534a9729…`（证书） | 与 `x7_3.0.zip` 同名文件一致，从项目包取 |
| `74fab57f…`（32 位 loader） | 项目包没有，保留壳原文件 |
| 其余 7 个（`36a76b97`/`44c29`/`5dbc98`/`69691c`/`c1d9f5f`/`d2caec3b`/`d61f`） | 旧版 fallback 容器，项目包已提供当前版本，构建时丢弃 |

其余 7 个不是 `x7_3.0.zip` 的同格式资源（壳内是 `92c50100` fallback 容器），
不能直接由项目包“生成”；实测丢弃后 `files/x7_3.0` 的项目包恢复即可正常加载。
构建器默认 `--shell-assets minimal`，可用 `--shell-assets all` 回退为全量拷贝。

### 3.1.1 功能包平铺、c/s 合一与运行时解密

- `assets/<hash>` 下是 **18 个 hash 资产**（直接在 assets 根，不再有 x7_3.0 目录），不再使用 zip：
  - 15 个基础/壳资源单文件直接复制；
  - 6 个带 `_c`/`_s` 的条目在构建时合并为 `WXH1` 容器
    （magic + body/c/s 三个长度 + 三段内容），运行时拆回
    `body`、`body_c`、`body_s` 三个文件；
  - 扩展包只内置 sf/mf/af 的主命名 3 份，另一套 3 个别名由
    `FeaturePackRestorer` 在运行时从主文件拷贝，避免重复载荷。
- `FeaturePackRestorer` 优先从 `assets/<name>` 复制/拆分到
  `files/x7_3.0/`，旧 APK 仍保留 zip 回退路径。
- 扩展包 6 个文件（sf/mf/af 各两种命名）是**加密后的功能 APK 容器**；
  不再随包携带明文 `featuredex`。`FeatureDexDecoder` 在运行时完成：
  外层 PBE → AES payload → `[签名, _c, 内层容器]` → 内层 PBE → 功能 APK
  → 取 `classes.dex`，然后注入 0 字节 buffer。
- `_c` 保留厂商原样；`_s` 的签名策略：
  - base/themes/donation/vidurlparser 用**项目私钥**重签
    （`scripts/sign_sidecars.py`，签名对象是去掉 32B 前缀的 runtime body）；
  - C（核心）与 L64（native loader）必须保留厂商签名：C 会被宿主二次
    校验（会出现 2 倍 body 的缓冲），L64 在 native 侧验签，Java hook 拦不到。
- `PackSignatureGuard.verifyInstalled` 在启动时用 native 内置的项目公钥
  校验 4 个功能包；非项目签名会记录 `local rejected` 并删除 body/_s。
  负向测试已确认。
- `FeaturePackRestorer` 在 `x7_3.0/wxh_pack_version` 写入 versionCode；
  APK 版本变化时强制重写全部功能包（含 `_c`/`_s`），避免旧签名残留。

- 运行时日志：

  ```
  feature packs[x30]: restored 26 file(s) from payload
  feature packs[x30-ext]: restored 3 file(s) from payload
  feature dex: decoded x30-af 478884B / x30-sf 223752B / x30-mf 400392B
  feature dex: inject x30-af / x30-sf / x30-mf
  X: Module loaded successfully!
  ```

### 3.2 插件身份

构建器还会把壳的 Android 身份替换成本项目的：

- `android:label` → `WeXposedHook`（manifest 属性直接写字符串）
- `xposeddescription` → 项目 `strings.xml` 的 `xp_desc`（默认 `WeXposedHook 微信增强模块`）
- `versionName` → `2.0-beta`、`versionCode` → `8`；壳身份仍为 117
- 启动图标/自适应图标 → `app/src/main/res/mipmap/logo.png`
  （替换密度 `res/*.webp`；`res/BW.xml`/`0K.xml` 的 foreground 指到
  background 资源 `0x7f08008b`，并把该资源各密度的 `CD/lP/ku/pt/9e/6Y.png`
  全部替换为项目 logo）
- `resources.arsc` 中 `res/Yk.xml` → `res/lP.png`（等长替换）

壳的 `classes.dex`、包名兼容、证书/modulePath 逻辑不变。

## 4. 为什么不能只改包名

壳会从 `modulePath` 指向的 APK 里读两类信息：

1. **模块身份**：manifest 的包名/版本。只有 `cn.android.x 3.0 (117)` 才会进入
   `Lsposed (integrated)` 模式并加载功能包。
2. **证书派生值**：
   - `md5_nopad = MD5(证书 DER)` 的每个字节按 `%x` 输出（不补零）；
   - params key = `SHA-256( MD5(md5_nopad + "9n4hZkF_2019").hexdigest() )`，
     用于 `AES/CBC/PKCS7`、零 IV 解 `files/x7_3.0/739440…`；
   - 功能包外层 PBE password = `MD5(md5_nopad + "9n4hZkF").hexdigest()`，
     与每个文件自己的 salt/1000 次迭代一起交给 `PBEWithMD5AndDES`。

如果 `modulePath` 直接指向本项目 APK，包名不是 `cn.android.x`，壳只加载
wxcore、不加载功能包；同时外层 PBE 密码随证书变化，会 `BadPaddingException`。

现在的做法：

| 修复 | 做法 |
|---|---|
| 包名/版本 | 构建时从壳 APK 的 `AndroidManifest.xml` + `resources.arsc` 生成
  176 KB 的 `assets/x30/identity.apk`，运行时解到
  `files/x30/identity.apk`，作为壳的 `modulePath` |
| 外层 PBE | `PbePasswordHook` 按 `PBEParameterSpec` 的 salt 把
  “本项目证书派生出的密码”换回原版 X 3.0 的密码（salt 每个文件固定） |
| 证书视图 | `ZipFile/JarFile.getEntry("META-INF/*.RSA")` 映射到
  `assets/x30/original_cert.rsa`；`JarEntry/JarFile.getCertificates`、
  `Signature.toByteArray`、`Certificate.getEncoded` 内容比对后换回原版证书 |
| 旧路径 | `JarFile/ZipFile` 构造时把 `/data/app/...` 下本包的旧 `base.apk`
  路径改回当前 `modulePath` |

params key 与模块证书无关（两侧实测值相同），因此不需要为 params 重新加密；
需要处理的只是外层 PBE 密码。这样就不再需要把完整原版 APK 打进产物，
APK 从 9.88 MB 降到 6.70 MB。

## 5. 构建

```bash
# 直接脚本（推荐先跑一次）
python -X utf8 scripts/build_x30_replica.py \
  --shell data/refs/X_3.0.apk \
  --hook-apk app/build/outputs/apk/legacyFullEdition/release/WeXposedHook-legacy-v2.0-beta-full.apk \
  --package github.shadowbaby.wechatxposed.hook \
  --output app/build/outputs/apk/release/WeXposedHook-legacy-v2.0-beta-full.apk

JAVA_HOME=<JDK17> ./gradlew :app:assembleX30Replica
```

脚本会：

- 用 `cryptography` 从壳 APK 的 v1 签名块取原版证书，从签名密钥库（默认
  `~/.android/debug.keystore`）取模块证书，注入 compat dex；
- 只改 `AndroidManifest.xml` 的 UTF-16 string pool 中 3 个包名相关字符串；
- 壳 `classes.dex` 原样；仅在 `--shell-assets all` 时全量拷贝壳 assets；res 只替换项目图标相关文件；保留非 UTF-8 的 `META-INF/services` 文件名；
- 追加 hook dex/so/资产；
- 把 `x7_3.0.zip` / `x7_3.0_ext.zip` 摊平成 `assets/<hash>`，
  带 `_c`/`_s` 的条目合并为 `WXH1` 容器；
- 不再携带 `assets/featuredex/x30_*.dex`，由 `FeatureDexDecoder`
  在运行时从扩展包容器解出；
- 从壳的 manifest/arsc 生成 176 KB 的 `assets/x30/identity.apk`，
  不再打包完整原版 APK；
- `zipalign -p 4` + `apksigner`（v1/v2/v3）。

## 6. 安装

```bash
adb install -r -d app/build/outputs/apk/release/WeXposedHook-legacy-v2.0-beta-full.apk
```

- 与设备上现有 `github.shadowbaby.wechatxposed.hook` 同 debug 证书，可原地升级；
- LSPosed 中确认本项目模块启用、作用域含微信；
- **不需要**安装/启用原版 `cn.android.x`；
- 首次运行建议触发干净环境（debug 构建）：

```bash
adb shell su -c "touch /data/user/0/com.tencent.mm/files/wxh_clean_env"
adb shell am force-stop com.tencent.mm
```

## 7. 验收

```bash
adb logcat -c
adb shell monkey -p com.tencent.mm -c android.intent.category.LAUNCHER 1
adb logcat -d -v time > x30.log
```

关键行：

```
x30 modulePath -> /data/user/0/com.tencent.mm/files/x30/identity.apk
pbe remap: d633214bb4d850dd
feature packs[x30]: restored 26 file(s) from payload
feature packs[x30-ext]: restored 6 file(s) from payload
feature dex: inject x30-af / x30-sf / x30-mf
X: feature loaded: base 519 ... mf 132
X: Module loaded successfully!
```

离线：

```bash
aapt2 dump badging <apk> | head -3     # package=github...hook, versionCode=8
apksigner verify -v <apk>              # v1/v2/v3 true
unzip -p <apk> assets/xposed_init      # 3 行
```

## 8. 已知限制（阶段二）

- 使用 `x30` build type：`debuggable=false`、无 R8 minify，注入/解锁常开；
  release minify 留到后续阶段。
- 输出 APK 内嵌 176 KB 的 `assets/x30/identity.apk`，当前 minimal 资产版
  总计约 6.70 MB（不再包含完整原版 APK）。
- 壳内日志前缀、DB 里记录的模块包名仍是 `cn.android.x`（这是有意保留）。
- 单 APK 只能使用 **legacy Xposed API**，原因见 8.1。

### 8.1 为什么单 APK 只能是 legacy API

- X 3.0 壳的入口固定在 `assets/xposed_init` → `com.android.x.XposedInit`，
  内部全程依赖 `XposedBridge/XposedHelpers`，native 侧也按 legacy 的
  modulePath / 证书派生密钥。
- modern API 模块由 `META-INF/xposed/java_init.list` 加载；APK 一旦声明
  modern 入口，LSPosed 不再读取 `assets/xposed_init`，壳不会启动。
- 因此“壳 + 本项目 hook”的单 APK 必须保持 legacy；Android 13 与 Android 16
  （LSPosed 2.2.1）均已实测通过。菜单入口与 modulePath 的关系见 8.3。
- 项目自身的 hook 业务代码已由 `HookFramework` / `HookParam` / `HookCallback`
  统一抽象，`LegacyFramework` 与 `ModernFramework` 只是两种实现；
  modern 形态需要额外安装原版 `cn.android.x` 作为壳，不是单 APK。

### 8.2 LSPosed 1.9.2 的限制（A13 实测）

最小 `identity.apk` 在 **LSPosed 2.2.1（Android 16）** 上功能包加载正常；
但在 **LSPosed 1.9.2-it（Android 13）** 上，壳只加载 wxcore，
`(s16,a24,m18)` 不出现、功能包不加载。已排除：

- 身份 APK 的包名/版本（日志显示 `cn.android.x 3.0 (117) ... (integrated)`）；
- 壳 assets（把 10 个 blob 全放进身份 APK 仍不加载）；
- `classes.dex`（把原版 classes.dex 放进身份 APK 仍不加载）；
- 授权库（清空/重建 DB 后仍不加载）。

同一台 A13 换成**完整原版 APK** 作为 `modulePath` 后功能包立即加载，
说明 1.9.2 的壳/native 还会校验 `modulePath` APK 的原始签名，而 2.2.1 不会。
因此目前按 LSPosed 版本分两种产物：

```bash
# LSPosed 2.x（A16）：6.29 MB，最小 identity.apk
python -X utf8 scripts/build_x30_replica.py ... 

# LSPosed 1.9.x（A13）：9.50 MB，完整原版 APK 作为 modulePath
python -X utf8 scripts/build_x30_replica.py ... \
  --identity-apk data/refs/X_3.0.apk \
  --output build/x30_full_donor.apk
```

后续若把 A13 的 LSPosed 升级到 2.x，可直接使用最小版本。

### 8.3 菜单入口与身份 APK

Android 16 + LSPosed 2.2.1 实测：

| modulePath | 功能包 | X 菜单入口 |
|---|---|---|
| 完整原版 `X_3.0.apk` | 加载 | **显示** |
| 176 KB `identity.apk` | 加载 | 不显示 |

功能加载与菜单入口是两条独立链路；菜单注入由壳/功能包内部完成，
并且会读取 modulePath APK 的原始身份。当前 `X30Compat` 的 Java 映射
（包名、`META-INF/*.RSA`、`getPackageInfo` 签名）覆盖不到这条 native 检查，
所以“最小身份 APK + 菜单”暂时无法兼得：需要菜单时用完整原版 APK 作为
`modulePath`（`--identity-apk data/refs/X_3.0.apk`）。

进一步定位（2026-10-22，A16）：
- 壳/功能包会查询隐藏包名 `"!#!%" + Base64("cn.android.x")`；
  已加 `isShellPackage()` 映射并伪造 `PackageInfo`，但查询通过后仍然出现
  `feature publish blocked: disable -> themes.Wrapper.Init`。
- 触发栈里出现 `android.os.<随机类名>.ⁱʽ`（每次运行类名不同），
  且 `ClassLoader.loadClass` 探针只看到真实的 `android.os.*` 类，
  说明这是壳的**动态反篡改/栈伪装检查**，不是 LSPosed API 差异。
- 结论：Java 层的包名/签名映射无法覆盖该检查；要彻底去掉原版 APK
  需要继续逆向 base dex 的检查分支或 native patch。

### 8.4 反篡改检查的根因与绕过（2026-10-22）

解密 `14e777…`（base）和 `d61f…`（core）后定位到：

```
sigs = config("sigs")                       // params 里预置的证书 MD5 列表
needle = MD5_nopad(cert(classes.dex of modulePath))
if (!sigs.contains(needle)) {
    publish("disable", ...)                 // themes/donation/base
    setDisabledCode(0x321)
}
```

- core 侧读取证书的方法：`c.ˏᵎ.ﾞˏ.ʾʻ(String)[B`
- base 侧读取证书的方法：`b.ʾᵢ.ˊˏ.ᵔʾ()String`
- 两者都用 `JarFile("classes.dex").getCertificates()[0].getEncoded()`，
  再按每字节 `%x`（不补零）取 MD5。

`CoreCertHook` 在对应 classloader 里 hook 这两个方法：
- core 返回原版证书 DER；
- base 直接返回原版证书的 MD5_nopad。

A16 实测：`core cert hook installed` / `core cert loaded 823B` 后，
`feature publish blocked: disable` **消失**，功能包与 `(s16,a24,m18)` 正常；
base 侧 hook 的菜单效果待设备重连后复测。
因此不再需要把完整原版 APK 作为 `modulePath`，只需一个含 `classes.dex`
条目的最小 donor；证书内容由 hook 替换。

## 9. 后续

- 二开工程的逐版本适配路线（微信 8.0.50–8.0.79）见
  `docs/version-adaptation-plan.md`；本文的壳结构是路线 A/B 的实现基础。
- 已完成：注入/解锁源码恢复、2.44 移除、wx30-only 构建。
- 已完成：`x7_3.0.zip`/`x7_3.0_ext.zip` 摊平为 `assets/<hash>`，
  `_c`/`_s` 合并为 `WXH1` 容器，运行时拆开。
- 已完成：删除 `assets/featuredex/x30_*.dex`，`FeatureDexDecoder`
  运行时从扩展包容器解出 dex 后注入（A13 实测 `decoded x30-af/sf/mf`）。
- 待办：定位 Android 16 最小 `identity.apk` 下菜单不显示的 native 检查。
  已准备三个测试 donor：
  - `build/donor_all_assets.apk`（manifest+arsc+10 个壳 assets）
  - `build/donor_assets_dex.apk`（再加原版 classes.dex）
  - `data/refs/X_3.0.apk`（完整原版，已知菜单正常）
- `_c`/`_s` 自签已放弃：改载荷会触发 native SIGSEGV，旁车必须原样保留。
