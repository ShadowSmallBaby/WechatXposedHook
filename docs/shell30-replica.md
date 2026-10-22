# X 3.0 壳复刻（单 APK，阶段一）

> 2026-10-22。目标：把原版 `X_3.0.apk`（`cn.android.x` 117）与本项目 wx30 debug hook
> 合进一个 APK，只安装本项目插件 + 内置项目包即可运行；原版 X 3.0 / microX 2.44 均不安装。

## 1. 结果

输出：

```
build/generated/shell30/WeXposedHook-shell30-v117.apk
package = github.shadowbaby.wechatxposed.hook
versionCode = 117 / versionName = 3.0
sha256 = 13819e25fd98dca09b05918f4f7b002f5d6febae5863b0a37b4652e221a3d54f
size = 11,691,252 B
```

设备（Android 13，微信 8.0.49）实测，原版 `cn.android.x` 已卸载、microX 2.44 未启用：

```
X: feature loaded: base 519
X: feature loaded: themes 116
X: feature loaded: vidurlparser 31
X: feature loaded: af 175 / donation 72 / sf 76 / mf 132
X: Module loaded successfully!
```

证据：`build/analysis/af13/shell30-20261022/`。

## 2. 输入

| 角色 | 路径 |
|---|---|
| 壳基座 | `data/refs/X_3.0.apk`（SHA-256 `671a9a8b…f93fdd5`） |
| hook 载荷 | `data/refs/wxh-wx30-full-debug-20261022.apk`（2026-10-22 已验证的 legacy wx30 full debug 构建） |

hook 载荷必须含：
`FeatureDexInjector` / `FeaturePackUnlock`、`assets/featuredex/x30_{sf,mf,af}.dex`、
`assets/x7_3.0*.zip`、两个 ABI 的 `libwexhook.so`。

## 3. 产物结构

```
classes.dex                    原版 X_3.0 classes.dex（逐字节不变）
classes2.dex                   Shell30Compat（包名/签名/路径兼容）
classes3..10.dex               hook 载荷 classes.dex..classes8.dex
lib/arm64-v8a/libwexhook.so
lib/armeabi-v7a/libwexhook.so
assets/shell30/original.apk    原版 X_3.0 APK（证书/壳自身资源捐献者）
assets/shell30/original_cert.rsa 原版 CERT.RSA（native 读证书时映射到它）
assets/x7_3.0.zip              项目包 26 文件
assets/x7_3.0_ext.zip          项目包扩展 6 文件
assets/featuredex/x30_*.dex    仅 3.0 注入 dex
assets/xposed_init             3 行：compat / 本项目 hook / com.android.x.XposedInit
AndroidManifest.xml            仅包名相关字符串改成本项目包名
```

不包含 `wx6_2.44*`、`featuredex/{sf,mf,af}.dex`、`featuredex/core202.bin`。

## 4. 为什么不能只改包名

壳不是“只认包名”这么简单，它把自身模块信息绑进了密钥：

1. `x.ⁱᵢ.ᐧﹶ.ʽʿ()` 打开模块 APK 的 `classes.dex`，取 v1 证书；
2. `MD5(证书 DER)` + 固定盐 `9n4hZkF_2019`，再 `SHA-256` 成 AES-256 key；
3. 用 `AES/CBC/PKCS7`、零 IV 解 `files/x7_3.0/739440…`（params，Base64）——文件名是 `MD5("xmd")`；
4. 壳的 `initZygote` 把 LSPosed 给的 `modulePath` 存进实例字段，native 侧也参与派生。

所以换签名/换 APK 路径后，params 会 `BadPaddingException`，随后 native `CallMethod`
在 `__strlen(NULL)` 上 SIGSEGV。`Shell30Compat` 的最小修复：

| 修复 | 做法 |
|---|---|
| 包名 | 模块 Context 的 `getPackageName()` 返回 `cn.android.x`；`createPackageContext("cn.android.x")` 映射到本包 |
| 证书 | `ZipFile/JarFile.getEntry("META-INF/*.RSA")`（非 COM_TENC）映射到 `assets/shell30/original_cert.rsa`；`JarEntry/JarFile.getCertificates`、`Signature.toByteArray`、`Certificate.getEncoded` 内容比对后换回原版证书 |
| modulePath | hook 壳 `XposedInit.handleLoadPackage` before：把实例字段 `ʽʿ` 改成原版 X 3.0 APK 路径；原版未安装时从 `assets/shell30/original.apk` 解到 `files/shell30/original.apk` |
| 旧路径 | `JarFile/ZipFile` 构造时把 `/data/app/...` 下本包的旧 `base.apk` 路径改回当前 `modulePath` |

这样壳/native 仍看到“原版包名 + 原版证书 + 原版 modulePath”，项目包不需要改。

## 5. 构建

```bash
# 直接脚本（推荐先跑一次）
python -X utf8 scripts/build_shell30_replica.py \
  --shell data/refs/X_3.0.apk \
  --hook-apk data/refs/wxh-wx30-full-debug-20261022.apk \
  --package github.shadowbaby.wechatxposed.hook \
  --output build/generated/shell30/WeXposedHook-shell30-v117.apk

# 或 Gradle（输出在 app/build/generated/shell30/）
JAVA_HOME=<JDK17> ./gradlew :app:assembleShell30Replica
```

脚本会：

- 用 `cryptography` 从壳 APK 的 v1 签名块取原版证书，从签名密钥库（默认
  `~/.android/debug.keystore`）取模块证书，注入 compat dex；
- 只改 `AndroidManifest.xml` 的 UTF-16 string pool 中 3 个包名相关字符串；
- 原样拷贝壳的 dex/assets/res，保留非 UTF-8 的 `META-INF/services` 文件名；
- 追加 hook dex/so/资产与原版 APK 证书捐献资产；
- `zipalign -p 4` + `apksigner`（v1/v2/v3）。

## 6. 安装

```bash
adb install -r -d build/generated/shell30/WeXposedHook-shell30-v117.apk
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
adb logcat -d -v time > shell30.log
```

关键行：

```
shell30 modulePath -> /data/user/0/com.tencent.mm/files/shell30/original.apk
feature packs[x30]: restored 26 file(s) from payload
feature packs[x30-ext]: restored 6 file(s) from payload
feature dex: inject x30-af / x30-sf / x30-mf
X: feature loaded: base 519 ... mf 132
X: Module loaded successfully!
```

离线：

```bash
aapt2 dump badging <apk> | head -3     # package=github...hook, versionCode=117
apksigner verify -v <apk>              # v1/v2/v3 true
unzip -p <apk> assets/xposed_init      # 3 行
```

## 8. 已知限制（阶段一）

- 复用 debug hook 载荷，`BuildConfig.DEBUG=true`，会带探针与较多日志；注入/解锁也只在 DEBUG 生效。
- 输出 APK 内嵌 `assets/shell30/original.apk`，体积增加约 4.1 MB（总计约 11.7 MB）。
- 壳内日志前缀、DB 里记录的模块包名仍是 `cn.android.x`（这是有意保留）。
- 源码中的 2.44 分支尚未删除，只是产物不含 2.44 资产。

## 9. 阶段二

- 恢复 `stash@{0}` 中的注入/解锁源码，做 wx30-only release 构建，去掉 debug 探针。
- 删除 2.44 flavor、`xmetadata/wx6`、2.44 hook 与相关文档。
- 评估把 `assets/shell30/original.apk` 压缩为只含证书/壳资源的最小 APK，减小体积。
- 之后再考虑 `_c`/`_s` 自签与包尾 RSA 记录替换。
