# 转账详情一直加载：定位与修复（2026-10-20）

状态：**已修复，四个公开版单独干净测试通过**。版本目标 v1.3。

## 结论

根因是 `HostVersionSpoof` 把微信全局 `ClientVersion` 从 8.0.49 改成 8.0.79：

```text
host spoof: client version: 671101245 -> 671108925
```

微信「收到的转账」详情页会读取这个版本号去请求钱包 CGI。版本与服务端/本地钱包插件
不匹配时请求不返回，界面停在“正在加载”，约 60 秒后弹“网络通信出现问题”。

## 修复方案

全局伪装保留（小程序/通话的低版本提示仍需要），只在**微信钱包页面存活期间**
临时把 `ClientVersion` 还原成真实值，退出后恢复伪装。

需要还原的页面放在白名单里：

```java
private static final String[] WALLET_VERSION_CLASSES = {
        "com.tencent.mm.wallet_core.ui.WalletBaseUI",
        "com.tencent.mm.plugin.remittance.ui.RemittanceDetailUI",
        "com.tencent.mm.plugin.remittance.ui.RemittanceUI",
        "com.tencent.mm.plugin.remittance.ui.RemittanceResultUI",
};
```

`WalletBaseUI` 覆盖所有钱包页子类；以后遇到新的非 WalletBaseUI 支付页面，
只需要把类名追加到数组，不用改 hook 逻辑。

生命周期：

```text
onCreate(Bundle)  -> depth+1；第一次进入时写入原始版本
onDestroy()       -> depth-1；归零时写回伪装版本
```

`applyClientVersion` 在 `WALLET_DEPTH > 0` 时不会覆盖原始值，避免
`LauncherUI.onResume` 或升级页刷新把伪装又写回去。

实机日志：

```text
host spoof: wallet version guard: com.tencent.mm.wallet_core.ui.WalletBaseUI (2 method(s))
host spoof: wallet version guard: com.tencent.mm.plugin.remittance.ui.RemittanceDetailUI (2 method(s))
host spoof: client version: 671101245 -> 671108925
host spoof: wallet original version: 8.0.49     # 进入转账详情
host spoof: wallet spoof restored: 8.0.79       # 退出后恢复
```

## 发行版差异

`sf/mf/af` 三个扩展包只在完整版内置：

```text
公开版：
  LICENSE_FEATURE_SET = [1]
  mf_unlocked / af_unlocked / sf_unlocked -> 保持原值 false
  DonationFeatureUnlock 不安装

完整版：
  LICENSE_FEATURE_SET = [0,1,4]
  三个 *_unlocked -> true
  DonationFeatureUnlock 放行 requires_fp_donation
```

`license_crypto.inc` 同时接受 `[1]` 和 `[0,1,4]`，两种 edition 共用一个 so。
公开版 LIC 与解锁位保持一致，避免微X 写入禁用代码 `0x329`。

## 2.44 通用修复

- `WxComponentHooks` 适配新版核心 `c.ʻʻ.ـˋ` 的禁用码 setter/getter/status
- `DisableCodeLog` / `DisableCodeClear` / `StatusCheckSkip` 拦截 `0x325/0x329/0x334`
- `FP_VERSIONS` / `FP_ASYNC` 补上 `vidurlparser`

## X 3.0 修复

- `FeatureCloseGuard`：`Wrapper.Init.init` 的 `objArr[2]` Context 兜底；
  放行初始化门禁，避免设置页构建时 `Context.getResources()` 空指针
- `X3GuardBypass`：核心 init 改为只观察不阻断；设置菜单条件按需置真
- `X3LicenseBypass`：不再清空授权类里的 ArrayList（列表方法参与功能数据分发）

## 四个公开版验证

每个版本都清空 `FKZ_WX_DATA`、`wx6_2.44`、`x7_3.0` 和版本缓存后，
点击虎子聊天里的 **¥0.01 已收款** 转账卡片：

| 变体 | 结果 |
|---|---|
| legacy wx2.44 公开版 | 通过 |
| modern wx2.44 公开版 | 通过 |
| legacy wx3.0 公开版 | 通过 |
| modern wx3.0 公开版 | 通过 |

判定方式：详情页出现「转账时间/收款时间」，且没有「正在加载」。

说明：四个版本**连续快速**跑时，微信钱包后端/页面恢复会导致后几次失败；
单独干净测试稳定通过。发布前建议每版间隔一段时间或重启微信再验。

## 改动文件

```text
app/src/main/java/.../support/HostVersionSpoof.java     转账修复 + 页面白名单
app/src/main/java/.../support/WxComponentHooks.java     新核心禁用码 + full-only donation
app/src/main/java/.../support/CallMethodBypassHook.java edition 解锁门控
app/src/main/java/.../support/X3CallMethodHook.java     edition 解锁门控
app/src/main/java/.../support/FeatureCloseGuard.java    X3 初始化修复
app/src/main/java/.../support/X3GuardBypass.java        X3 菜单/初始化修复
app/src/main/java/.../support/X3LicenseBypass.java      X3 授权列表修复
app/src/main/java/.../support/DisableCodeLog.java       (新增)
app/src/main/java/.../support/DisableCodeClear.java     (新增)
app/src/main/java/.../support/StatusCheckSkip.java      (新增)
app/src/main/java/.../support/DonationFeatureUnlock.java (新增，full-only)
app/src/main/java/.../support/EditionFeatures.java      (新增，edition 判断)
app/src/main/jni/license_crypto.inc                     接受 [1]/[0,1,4]
scripts/encode_secrets.py                               公开版 LIC [1]
scripts/secrets_table.py                                完整版 LIC [0,1,4]
scripts/generate_min_db.py                              vidurlparser 默认值
docs/reverse-engineering.md                             edition LIC 说明
app/build.gradle                                        1.2 -> 1.3
CHANGELOG.md                                            v1.3
```

不包含 `docs/ext-pack-investigation-2026-10-20.md`（已存于
`build/backup/2026-10-20-auth/`，不随本次发版）。
