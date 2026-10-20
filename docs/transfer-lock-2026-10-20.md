# 转账详情 ANR / 网络通信出现问题：定位与修复（2026-10-20）

状态：**已修复，真机验证通过**。随 v1.3.2 发布。

## 现象

- 进入「收到的转账」详情页卡死，约 5 秒后系统弹 ANR
- 重启设备后 ANR 消失，但页面仍提示「网络通信出现问题」

## 关键证据

1. **v1.3 原包同样复现**：从设备 16:22 原样 pull 的 v1.3（versionCode 4、
   Debug 签名、不含 `OrderHandlerUI`）在同样环境下也卡死，排除 1.3.2 代码改动。
2. **版本还原正常**：卡死时日志为 `wallet original version: 8.0.49`。
3. **ANR 主线程堆栈**：

```text
WalletBaseUI.onSceneEnd                 <- 钱包 CGI 回调（主线程）
  -> x.ʽﹶ.ʽʿ.beforeHookedMethod        <- 微X 的 hook
  -> c.ˉˆ.ˉᵎ$ⁱˋ.beforeHookedMethod     <- 微X 功能回调
  -> com.android.xf.base.Wrapper.Init.publish
  -> b.ʾᵢ.ʾᵢ.ˈˈ
  -> SQLiteCursor.moveToFirst
  -> sqlite3_step / pread               <- 卡在 WCDB 读
```

微X 的解码方法表里有 `on_RemittanceDetailUI_onSceneEnd`，与
`on_MallIndexUI_fakeAmountMethod1` 等并列，属于「伪造转账金额」功能。

4. **授权库开关**：解码 `FKZ_WX_DATA` 得到
   `set_fake_transfer_amount_enable = true`。
5. **关闭该功能后转账恢复**。

## 根因

两个环节叠加：

```text
模块每次进程启动：
  LicenseInstaller.ensure
    -> backup(FKZ_WX_DATA)              <- 写备份
    -> openOrCreateDatabase             <- 打开写连接
    -> CREATE TABLE / ensureLocale      <- 写事务
    -> setVersion                       <- 写 PRAGMA

微X「伪造转账金额」开启时：
  RemittanceDetailUI.onSceneEnd
    -> Wrapper.Init.publish
      -> 同步读 FKZ_WX_DATA             <- 主线程读
```

即使 `ensure` 日志显示 `license db: ... ready`（`inserted=0, refreshed=0`），
备份与写事务已经发生。主线程读与启动写在同一数据库上竞争，读侧等待超过 5 秒，
触发输入 ANR；即使锁缓解，hook 对 CGI 回调的改写仍会让页面报网络错误。

三方支付正常是因为它走 `OrderHandlerUI` 链路，不经过
`RemittanceDetailUI.onSceneEnd`。

## 修复

`LicenseDatabase.ensure` 增加纯只读快路径：

- 只读打开数据库（`OPEN_READONLY`）
- 检查 `LicenseData.rows(account)` 的每一行都存在，关键行 LIC/verifier6 可用
- 全部满足时直接返回 `ready`：**不备份、不建表、不 setVersion**
- 缺失或损坏时仍走原有写路径

这样库完整时模块启动对 `FKZ_WX_DATA` 零写入，消除与微X 主线程读取的锁竞争。

## 验证

修复后转账日志（17:23）：

```text
host spoof: wallet original version: 8.0.49    # 进入详情
host spoof: wallet spoof restored: 8.0.79      # 正常退出
```

页面正常显示，无 ANR；生命周期深度计数闭环（此前 `spoof restored` 从未触发，
因为 `WXPayEntryActivity` 没有声明 `onDestroy`，v1.3.2 已改为只挂成对方法）。

## 用户侧注意事项

- 「伪造转账金额」功能本身会改写转账详情显示，与真实转账详情天然冲突；
  若仍开启，数据库锁竞争缓解后仍可能出现页面异常，建议按需关闭。
- 原库备份：`/sdcard/Download/wxh-backup-20261020/FKZ_WX_DATA.tgz`
