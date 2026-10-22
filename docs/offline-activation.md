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

使用项目自签 RSA-2048 私钥（`WXH_SELF_SIGN_KEY_BASE64`），RSA PKCS#1 v1.5 +
SHA-256：

```
payload = {
  "v": 1,
  "mid": "XXXX-XXXX-XXXX-XXXX",
  "wxid": "wxid_xxx",
  "features": ["all"],       // 或 ["sf","mf","af"]
  "not_after": 0             // 0=永久
}
code = Base64Url(payload_json) + "." + Base64Url(signature)
```

生成工具：

```bash
python -X utf8 scripts/make_activation.py \
  --mid XXXX-XXXX-XXXX-XXXX --wxid wxid_xxx \
  --features all --days 365 --out activation.dat
```

## 4. 客户端校验（已实现）

1. 读取 `files/activation.dat`。
2. `Secret.verifyActivation(payload, signature)` 在 native 做 RSA-SHA256 验签；
   公钥/摘要算法不在 Java。
3. 校验 `mid`、`wxid`、`not_after`、`features`。
4. 全部通过后允许 `FeatureDexInjector.onFeature` 注入 sf/mf/af；否则只保留基础包。

## 5. 接入点（已实现）

- `Activation.isExtensionAllowed()`：`HookBootstrap` 启动时判定。
- `FeaturePackUnlock.run(data, extensions)`：未激活时把 `fp` 收窄为 `themes`。
- `FeatureDexInjector.onFeature`：注入前再检查激活/证书/dex 完整性/运行时防护。
- `EditionFeatures.isUnavailableExt`：full 版未激活时扩展 key 返回不可用。
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
2. 合并 public/full 构建：删除 `FULL_EDITION` 分支，扩展包随 APK 携带但默认不注入。
3. 菜单加激活页；写 `files/activation.dat`。
4. 用测试码在 A13/A16 验证：未激活无扩展、激活后菜单出现 sf/mf/af。
5. 最后再决定是否移除 `publicEdition` flavor 与双 APK 发布流程。
