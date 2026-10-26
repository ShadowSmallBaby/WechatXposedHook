# 离线激活方案（机器码 + wxid）

> 2026-10-23 已实现核心与 UI。目标：一个 APK，扩展功能必须凭离线激活码启用；
> 不依赖服务器，激活码由发行方私钥签发，客户端用内置公钥校验。

## 1. 设计原则

- **一个 APK**：扩展包（sf/mf/af）只在激活后解密/注入。
- **离线**：激活码是“签名过的数据”，客户端本地验签，不需要联网。
- **双绑定**：机器码 + 微信 wxid；换设备或换账号都失效。
- **不破坏基础功能**：未激活仍可使用基础包（themes/base 等），只是没有扩展功能。

## 2. 机器码（已实现）

```
mid = Base32( SHA-256(
        Build.FINGERPRINT
      + "|" + Build.DEVICE
      + "|" + 模块签名证书 SHA-256
      + "|" + wxid
      )[:10] )
```

- **不使用 ANDROID_ID**：`handleLoadPackage` 阶段 Application/Context 还没创建，
  `Settings.Secure` 取不到；改用 FINGERPRINT + DEVICE，保证启动期可算且稳定。
- 加入模块证书 SHA-256，防止别人换签名重打包后复用激活码。
- wxid 从 `StartupCheck.readLoginAccount()` 读取；未登录时显示“请先登录微信”。
- 显示为 `XXXX-XXXX-XXXX-XXXX`。

## 3. 激活码格式（已实现）

Ed25519 私钥（`WXH_ACTIVATION_ED25519_KEY_BASE64`，32 字节），签名后按大写
十六进制拼成固定 144 字符的码：

```
payload = [版本 1B][功能位 1B][not_after 4B 大端][保留 2B]   // 共 8 字节
message = "WXH1|" + mid + "|" + wxid + "|" + payload
code    = hex(payload + Ed25519_signature(64B))
```

功能位：`0x01` 基础，`sf=0x02`、`mf=0x04`、`af=0x08`，`all` 为 `0x0f`。
`not_after` 为 Unix 秒，`0` 表示永久。

签名工具（推荐直接运行，弹出图形界面）：

```bash
python -X utf8 scripts/make_activation.py
```

Windows 下也可以直接用打包好的 exe（见下文，双击即可，无控制台窗口）。窗口分「签发」
「校验」两页，机器码与 wxid 在顶部共用。签发页填写功能与天数后点“生成授权码”，码会
自动进剪贴板，同时追加一行签发记录到 `data/activation_log.csv`（该目录已在
`.gitignore` 内）。

校验页把授权码粘进去（可带换行，也可以直接粘 `activation.dat` 的内容），点“校验”
即可看到是否有效、功能位和到期时间。校验只用客户端内置公钥，不需要私钥，判定规则与
`activation.c` 一致。

批量/脚本场景仍走命令行，签发参数与输出格式不变：

```bash
python -X utf8 scripts/make_activation.py \
  --mid XXXX-XXXX-XXXX-XXXX --wxid wxid_xxx \
  --features all --days 365 --out activation.dat
```

命令行校验（退出码 0 有效、1 无效）：

```bash
python -X utf8 scripts/make_activation.py \
  --verify <144位授权码> --mid XXXX-XXXX-XXXX-XXXX --wxid wxid_xxx

python -X utf8 scripts/make_activation.py \
  --verify-file activation.dat --mid XXXX-XXXX-XXXX-XXXX --wxid wxid_xxx
```

### 打包成 exe

```bash
python -X utf8 scripts/build_activation_exe.py
# 产物：build/activation/WeXposedActivation.exe（约 15 MB，单文件）
```

exe 是无控制台程序：双击直接出 GUI，带参数运行时自动挂回父控制台，CLI 与 `--verify`
照常可用。私钥**不打包进去**——exe 会在自己所在目录及向上三层父目录里找 `.env`，或读
环境变量 `WXH_ACTIVATION_ED25519_KEY_BASE64`，所以把它和 `.env` 放在一起即可。

打包需要 `pyinstaller`（图标转换额外需要 `pillow`）。用独立 venv 打包可以避免把
本机全局 Python 的无关包带进去：

```bash
python -m venv build/pack-venv
build/pack-venv/Scripts/python.exe -m pip install pyinstaller cryptography pillow
build/pack-venv/Scripts/python.exe -X utf8 scripts/build_activation_exe.py
```

`build/` 已在 `.gitignore` 内，venv 和 exe 都不会进版本库。

## 4. 客户端校验（已实现）

1. `Activation.readLevel()` 读 `files/activation.dat`：JSON 取 `code` 字段，纯文本直接当码。
2. `Activation.verifyCode()` 调 `Secret.activationLevel(code, fingerprint, device,
   certSha256, wxid, now)`，机器码、公开码比对、Ed25519 验签、`mid`/`wxid`/有效期
   全部在 native（`app/src/main/jni/activation.c`），Java 只拿回等级。
3. native 先比对公开码（不依赖 wxid，命中即 `LEVEL_BASE`）；否则用 `fingerprint`、
   `device`、证书 SHA-256、wxid 现算机器码，走 Ed25519 验签。
4. 签名通过且 `features & 0x0e != 0` 为 `LEVEL_EXT`，否则 `LEVEL_BASE`；过期或验签
   失败为 `LEVEL_NONE`。
5. 只有 `LEVEL_EXT` 才允许 `FeatureDexInjector.onFeature` 注入 sf/mf/af，否则只保留
   基础包。

功能包 `_s` 走的是另一套：`pack_verify.c` 里的 RSA PKCS#1 v1.5 + SHA-1，别和激活码
的 Ed25519 混淆。

## 5. 接入点（已实现）

- `Activation.isExtensionAllowed()`：`HookBootstrap` 启动时判定。
- `FeaturePackUnlock.run(data, extensions)`：未激活时把 `fp` 收窄为 `themes`。
- `FeatureDexInjector.onFeature`：注入前再检查激活/证书/dex 完整性/运行时防护。
- `EditionFeatures.isUnavailableExt`：full 版未激活时扩展 key 返回不可用
  （`EditionFeatures.java:20` 直接判 `Activation.isExtensionAllowed()`）。
- `ActivationDialog`：未激活时在主界面 `MMActivity`/`LauncherUI` 弹出机器码和
  激活码输入框；激活成功提示重启微信。

## 6. 安全边界

- 离线码无法防“客户端被改”：必须配合 native 验签、R8、完整性校验（见
  `docs/anti-reverse.md`）。
- 激活码可以按 wxid 绑定；发现泄露时发行方停止为该 wxid 签发新码。
- 可选在线复核：首次激活后缓存结果，联网时静默刷新吊销列表（不强制）。
- 不要把私钥、签发脚本放进 APK；`make_activation.py` 只在发行方机器上运行。

## 7. 迁移步骤

1. 新增 `support/license/Activation.java` + native `nativeVerifyActivation`。
2. 合并 public/full 构建：删除 `FULL_EDITION` 分支，扩展包随 APK 携带但默认不注入。（已完成）
3. 菜单加激活页；写 `files/activation.dat`。
4. 用测试码在 A13/A16 验证：未激活无扩展、激活后菜单出现 sf/mf/af。
5. 最后再决定是否移除 `publicEdition` flavor 与双 APK 发布流程。（已移除，只保留 legacy/modern）
