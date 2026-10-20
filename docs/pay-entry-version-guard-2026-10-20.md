# 三方支付页面一直加载：定位与修复（2026-10-20）

状态：**已修复，真机验证通过**。目标版本 v1.3.2。

## 结论

美团等三方 App 调起微信支付时，微信侧页面链路是：

```text
com.sankuai.meituan/com.meituan.android.hybridcashier.HybridCashierActivity
  -> com.tencent.mm.plugin.base.stub.WXPayEntryActivity   (父类 AutoLoginActivity)
  -> com.tencent.mm.plugin.wallet_index.ui.OrderHandlerUI (父类 MMActivity)
  -> (正常时再进 WalletPayUI)
```

`WXPayEntryActivity` 与 `OrderHandlerUI` 都**不继承** `WalletBaseUI`，不在原有
`WALLET_VERSION_CLASSES` 白名单里。因此全局伪装的 `ClientVersion`（8.0.49 -> 8.0.79）
在支付链路中一直生效，支付页面请求不返回，界面停在加载态。

## 日志证据

冷启动后钱包守卫本身安装正常：

```text
host spoof: wallet version guard: com.tencent.mm.wallet_core.ui.WalletBaseUI (2 method(s))
host spoof: wallet version guard: com.tencent.mm.plugin.remittance.ui.RemittanceDetailUI (2 method(s))
host spoof: wallet version guard: com.tencent.mm.plugin.remittance.ui.RemittanceUI (2 method(s))
host spoof: wallet version guard: com.tencent.mm.plugin.remittance.ui.RemittanceResultUI (2 method(s))
host spoof: client version: 671101245 -> 671108925
```

修复前支付期间守卫**一次都没有触发**：

```text
wallet original version 命中次数: 0
wallet spoof restored 命中次数: 0
```

系统侧 Activity 时间线：

```text
16:20:43.208 START com.tencent.mm/.plugin.base.stub.WXPayEntryActivity
             callingPackage com.sankuai.meituan
16:20:43.293 START com.tencent.mm.plugin.wallet_index.ui.OrderHandlerUI
             callingPackage com.tencent.mm
16:20:43.408 Displayed OrderHandlerUI +102ms
16:20:50.471 OrderHandlerUI visibilityChanged false   # 用户返回
```

全程没有 `WalletPayUI` 的启动记录，说明页面卡在 `OrderHandlerUI`，还没走到收银台。

## 修复

`HostVersionSpoof.WALLET_VERSION_CLASSES` 增加真正显示订单的页面：

```java
"com.tencent.mm.plugin.wallet_index.ui.OrderHandlerUI",
```

**不挂 `WXPayEntryActivity`**：该 Activity 没有声明 `onDestroy`，只有 `onCreate`
被 hook 时生命周期计数只增不减，首次三方支付后 `WALLET_DEPTH` 永远大于 0，
全局伪装再也写不回去。实测日志印证：

```text
host spoof: wallet version guard: ...WXPayEntryActivity (1 method(s))
wallet spoof restored 命中次数: 0
```

为防止以后新增白名单类再踩同样的坑，`hookWalletVersion` 改为要求
`onCreate` / `onDestroy` **成对存在**才安装：

```text
host spoof: wallet version guard: <class> (2 method(s))
host spoof: wallet version guard skipped: <class> (onCreate=true, onDestroy=false)
```

生命周期仍沿用已有的深度计数：`onCreate` 时 depth+1 并还原真实版本，
`onDestroy` 时 depth-1、归零后写回伪装版本。`WalletPayUI` 正常情况下继承
`WalletBaseUI`，已有守卫自动生效，嵌套时 depth 不会提前归零。

另外，冷启动直接进支付页时 `LauncherUI.onResume` 尚未执行，
`originalClientVersion` 仍为 0，此时不会改写字段（日志输出 `untouched`），
字段保持微信自己的真实版本。

## 验证方法

冷启动微信后从美团拉起微信支付，修复后日志：

```text
host spoof: wallet version guard: ...OrderHandlerUI (2 method(s))
host spoof: wallet original version: untouched     # 冷启动直进支付页
host spoof: wallet spoof restored: 8.0.79          # 退出支付页面
```

判定标准：支付页面正常显示订单金额与支付方式，不再停在加载中；
退出后全局伪装恢复，小程序版本提示行为不受影响。

若仍失败，需要在卡住时 `dumpsys activity activities` 确认最终停留的 Activity
类名，再决定是否继续补白名单。
