# 微信 8.0.49 通话版本传递链路

> 2026-10-22。基于 APK `base.apk`（versionCode 2600 / 8.0.49）的 dex 反汇编，
> 用于替代此前“ilink 启动配置”的猜测。

## 1. 结论

微信 1:1 语音/视频通话有两条版本链路：

| 阶段 | 链路 | 版本来源 |
|---|---|---|
| 发起邀请 | `modelbase.i1.fillBaseReq(c64.bg, req)` → `c64.bg.setClientVersion(...)` | 全局 `c64.xe.g` |
| 通话建立 | `c1.J()` → `v2protocal.setAppCmd(505, 4B LE, 4)` → `SendRUDP` | 全局 `c64.xe.g` |

“对方微信版本较高，暂时无法发起通话”发生在**邀请阶段**，服务端读取的
是 `voipinvite` 请求公共头里的 `clientVersion`（cmdId = 170）。

## 2. 邀请链路证据

`classes8.dex`：

```text
Lcom/tencent/mm/modelbase/i1;->fillBaseReq(Lc64/bg; Lcom/tencent/mm/modelbase/i1;)V

  sget v0, Lc64/xe;->g I
  invoke-virtual {v9, v0}, Lc64/bg;->setClientVersion(I)V
```

`classes11.dex`：

```text
Ltt3/q;-><init>(Ljava/util/List; [B [B I I I I Ljava/util/LinkedList; J J)V
  const/16 v2, 170
  iput v2, v1, Lcom/tencent/mm/modelbase/j;->d I
  const-string v2, "/cgi-bin/micromsg-bin/voipinvite"
```

`Lcom/tencent/mm/plugin/voip/model/a3;->a(Ljava/lang/String; I I)I`
构造 `Ltt3/q` 并发起邀请。请求体只有 peerId、capInfo、room 参数和时间戳，
不含独立的版本字段，因此公共请求头就是服务端判断版本的输入。

## 3. 通话建立链路证据

`classes11.dex`，`Lcom/tencent/mm/plugin/voip/model/c1;->J()V`：

```text
const-string "anlin: ClientVersion: "
sget v2, Lc64/xe;->g I
...
const/4 v2, 4
invoke-static {v2}, Ljava/nio/ByteBuffer;->allocate(I)Ljava/nio/ByteBuffer;
sget-object v4, Ljava/nio/ByteOrder;->LITTLE_ENDIAN
invoke-virtual {v0, v4}, Ljava/nio/ByteBuffer;->order(Ljava/nio/ByteOrder;)...
sget v6, Lc64/xe;->g I
invoke-virtual {v4, v6}, Ljava/nio/ByteBuffer;->putInt(I)...
const/16 v6, 505
invoke-virtual {v4, v6, v0, v2}, Lcom/tencent/mm/plugin/voip/model/v2protocal;->setAppCmd(I [B I)I
```

之后包装成 `f64.gx5`（`d = 8`）并 `SendRUDP`。

`c1.J()` 的调用点：

- `Lcom/tencent/mm/plugin/voip/model/b3;->run()V`
- `Ltt3/d;->run()V`
- `Lcom/tencent/mm/plugin/voip/model/r0;->handleMessage(Message)V`

`b3` 由 `f3.c(f64.x36, int)` 在收到 **ACCEPT** 同步状态后提交，
因此 505 是通话接通后的媒体通道版本交换，不负责发起阶段的校验。

## 4. 模块实现

`support/feature/version/CallVersionSpoof.java`：

1. `fillBaseReq` after hook
   - `getCmdId() == 170` 时，把 `BaseRequest.clientVersion` 改成
     `VersionWindow.spoofed()`；
   - 其他 CGI 不动。
2. `v2protocal.setAppCmd` before hook
   - 命令为 505 且参数是 4 字节时，按小端写回 `VersionWindow.spoofed()`。

两条都只改参数，不改全局 `c64.xe.g`，避免 WebView UA / 公众号受到高版本影响。

## 5. 版本常量

```text
real     = 0x2800313d   // 8.0.49 build 61
spoofed  = 0x28004f3d   // 8.0.79 build 61（高 24 位替换，低字节保留）
```

## 6. 注意

- `c64.xe.<clinit>` 依赖微信 Application Context；在 `handleLoadPackage`
  阶段读取会触发 `sk.q0` 的 NPE，必须等 `ActivityThread.currentApplication()`
  非空后再读。
- 混淆名随微信版本变化：`c64.xe`、`modelbase.i1`、`v2protocal`、`tt3.q`
  都已在 `scripts/secrets_table.py` 中集中维护。

## 7. 最终真机结论（2026-10-22）

在 A16 / 微信 8.0.49(2600) / LSPosed 2.2.1 上逐项验证：

| 方案 | 结果 |
|---|---|
| `fillBaseReq` / mars / `MMProtocalJni` / wlogin / ilink / `setAppCmd(505)` 参数级 | 通话仍返回 235 |
| 通话发起时打开全局窗口（`z.c0` / `a3.a`） | 仍 235 |
| 启动期全局窗口（Application 就绪后 5 秒） | 聊天 MVVM 闪退 |
| `LauncherUI.onResume` 后全局窗口 10 秒再还原 | 仍 235 |
| `LauncherUI.onResume` 后全局改高并**一直保持** | **通话正常** |

结论：

1. 服务端没有持久化“登录时上报的版本”；重新登录（wlogin 已替换为 8.0.79）后恢复正常窗口仍会失败。
2. 真正消费点是**本地链路**，且读取时间早于 `a3.a` 发起邀请，可能是打开聊天 / VoIP 预连接 /
   引擎初始化阶段读取并缓存了 `c64.xe.g`。
3. 因此当前可用方案必须是「LauncherUI.onResume 后全局高版本并持续」。

已知代价：

- 公众号 JS-SDK 会因高版本做特性探测而卡顿；
- 转账详情等钱包 CGI 使用高版本会卡死，`WalletVersionGuard` 在当前时机下未能完全覆盖；
- 8.0.49 的 MVVM 聊天缺陷由 `ChatMvvmGuard` 强制关闭配置兜底。

重构目标：找到“聊天打开 → 通话建立”之间缓存版本的具体字段/方法，只 spoof 那一处，
让公众号/钱包恢复真实版本。

## 8. 最终方案（2026-10-22 真机验证）

在 A16 / 微信 8.0.49(2600) 上最终采用：

```text
启动后 20 秒：所有非钱包 CGI 的 BaseRequest.clientVersion = 0x28004f3d
20 秒后：恢复真实 8.0.49
拨号命中 voipilinkgetsdkmode / voipilinkinvite：重新开启
保持到 VideoActivity.onDestroy / voipshutdown：关闭
钱包/转账/红包页面：网络层整体保持真实
```

实现：`NetworkVersionSpoof` + `WalletVersionGuard` + `ChatMvvmGuard` + `VersionWindow`。

验证结果：

- 连续多通语音/视频通话正常；
- 公众号、小程序、转账、红包、三方支付正常；
- 启动窗口单独使用 → 通话失败；
- 通话作用域单独使用（启动期真实）→ 通话失败；
- 启动窗口 + 通话作用域 → 通话正常；
- 通话中途停止伪装 → 通话立刻失效。

关键结论：

1. 服务端需要**启动期的 CGI 版本**来注册在线状态，也需要**通话链路的 CGI 版本**持续通过校验；
2. 8.0.49 的实际通话链路是 `voipilinkgetsdkmode` → `voipilinkinvite` →
   `getfriendringback` → `voipilinksync`，不是旧 `voipinvite`；
3. `ChatMvvmGuard` 仍然必需：服务端会因高版本下发 MVVM 配置（raw=1），
   8.0.49 的 `rb4.q0` 缺失会导致聊天闪退；
4. 钱包/红包流程必须整体真实，只跳过 `mmpay` 请求不够，`secautoauth`/`newsync`
   等同一流程请求也必须真实。

## 9. 最终最小作用域（2026-10-22 再收窄）

启动阶段只伪装 **`getonlineinfo`**（cmdId 526），首次命中后 2 秒关闭：

```text
URI: /cgi-bin/micromsg-bin/getonlineinfo
请求 f64.xr2: 只有 d = language（版本在 BaseRequest 头里）
响应 f64.yr2: d 状态 / e 在线设备列表(f64.c64) / f summary XML / g,h 标志
```

服务端处理该请求时，会用公共请求头里的 clientVersion 登记当前在线会话；
后续 VoIP 兼容性检查使用的就是这个“在线设备版本”。因此只需要这一条 CGI
在启动时是 8.0.79，其它启动 CGI 全部可以真实。

通话阶段只伪装：

```text
voipilinkgetsdkmode
voipilinkinvite
getfriendringback
voipilinksync
voipilinkcancel
mmilinktransfer
voipspeedtest
```

其它请求全部真实；钱包/转账/红包页面仍然整体真实。

真机结果：通话正常（用户主动挂断）、转账、红包、公众号、小程序均正常。

注意：即使启动期只伪装 `getonlineinfo`，服务端仍会把 MVVM 配置置为 1
（`raw=1 -> 0`），`ChatMvvmGuard` 必须保留，否则 8.0.49 点聊天会 NPE。

实现（细节已下沉 native）：

```text
scripts/gen_spoof_tables.py
  -> app/src/main/jni/spoof_tables.inc   (URI 白名单 + 目标版本, XOR 混淆)
app/src/main/jni/spoof_tables.c
  -> Java_..._Secret_nativeHintMatch
  -> Java_..._Secret_nativeSpoofVersion
Java:
  Secret.hintMatch(kind, value)
  Secret.spoofVersion(real)
```

Java 侧不再保留 `getonlineinfo` / `voipilink` / `launchwxaapp` / 钱包关键字
的明文字面量，也不再有 `0x28004F00` 常量。修改白名单后执行：

```bash
python scripts/gen_spoof_tables.py
./gradlew buildNativeSecret
```


小程序：必须保留 `MiniProgramVersionSpoof` 的 `wx0.d` 启动场景窗口。
只伪装 `launchwxaapp` 请求头会让“请求头高、请求体低”，服务端按高版本返回资源，
8.0.49 客户端按低版本解析，表现为卡在下载；启动窗口让全局字段和请求体一起变高，
实测小程序正常。



