# 转账详情卡死 / 网络通信出现问题：定位与修复（2026-10-20）

状态：**已修复（1.3.x）**。转账详情页可正常打开；聊天卡片的金额伪装不受影响。

## 现象

- 微X「伪造转账金额」开启时，进入「收到的转账」详情页卡死，约 5 秒后 ANR
- 关闭该功能后恢复正常
- 与模块的版本伪装、只是启动写库无关（对照实验确认）

## 根因

微X 的伪造金额功能在 `RemittanceDetailUI.onSceneEnd` 上挂了一个 handler。
转账详情页的 CGI 回调触发时，该 handler 会：

1. 从 `Activity.getIntent()` 读取转账参数
2. 在**主线程**循环执行大量聊天库查询：

```sql
SELECT * FROM message WHERE talker = ? AND isSend = 0 ORDER BY msgId DESC LIMIT 1
SELECT * FROM message WHERE talker in ('...60+ 个会话...') ORDER BY msgId DESC LIMIT 1
```

3. 通过反射修改详情对象的金额字段

几十条会话查询叠加，主线程超过 5 秒没有处理输入事件，触发 ANR。
ANR 堆栈：`WalletBaseUI.onSceneEnd -> 微X hook -> Wrapper.Init.publish ->
SQLiteCursor.getCount -> sqlite3_step`。

聊天卡片走的是另一条链路（消息渲染 hook + `msg.appmsg.wcpayinfo.feedesc`），
不经过这个 handler，所以卡片伪装一直正常。

## 尝试过但不可行的方案

- **后台线程执行 publish**：DB 查询成功，但 handler 随后更新 UI，
  触发 `CalledFromWrongThreadException`，详情页金额不生效
- **SQL 缓存 / 预热**：首次打开仍需执行几十条查询，收益有限，版本耦合高
- **关闭「伪造转账金额」**：可行，但会失去卡片伪装

## 最终方案

在 `FeatureCloseGuard.PublishGuard` 中拦截该命令（精确匹配，只作用于详情页）：

```java
private static final String TRANSFER_SCENE_COMMAND = "on_RemittanceDetailUI_onSceneEnd";

if (TRANSFER_SCENE_COMMAND.equals(command)) {
    param.setResult(null);
    return;
}
```

拦截范围仅限转账详情页的 scene-end 广播：详情页显示真实金额、不触发 WCDB 查询；
聊天卡片的金额伪装走另一条消息渲染链路，不受影响。

效果：

| 场景 | 行为 |
|---|---|
| 转账详情页 | 可正常打开，金额显示真实值（不再执行微X 的批量查询） |
| 聊天转账卡片 | 金额伪装保持正常，可正常修改 |
| 其它微X 功能 | 不受影响 |

日志：

```text
feature publish blocked: on_RemittanceDetailUI_onSceneEnd -> com.android.xf.base.Wrapper.Init
```

## 相关记录

- `docs/pay-entry-version-guard-2026-10-20.md`：三方支付入口的版本守卫修复（1.3.2）
- 原授权库备份：`/sdcard/Download/wxh-backup-20261020/FKZ_WX_DATA.tgz`
