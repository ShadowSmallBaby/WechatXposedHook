# 功能包分析经验指南（微X 2.44 / X 3.0）

> 基于 2026-10-21/22 对微X 2.44 与 X 3.0 扩展包的分析。这里记录**方法论**，
> 具体密钥表/结论见 `docs/extension-pack-chain.md`。

## 0. 总体流程

```
包体/仓库盘点
  -> 离线容器解析（外壳、内层、_c、尾记录）
  -> 密码/后缀还原（PBE + 排列爆破）
  -> 版本与核心匹配（旧/新仓、core 版本尾）
  -> 动态探针（PBE/摘要/签名/文件/native 调用）
  -> 运行时验证（注入/加载/菜单）
  -> 干净环境复现（自动恢复/建库）
  -> 归档证据与更新文档
```

原则：**先离线、后动态；先小后大；单变量对照；所有设备操作可逆**。

## 1. 环境与工具

- 设备：Android 13（Xposed API 82）与 Android 16（modern API）各一台；
  LSPosed 1.9.2；微信 8.0.49；X 3.0 `cn.android.x` 117；microX 2.44 (111)。
- 日志：

  ```bash
  adb -s <serial> logcat -c
  adb -s <serial> logcat -d -v time > build/analysis/....log
  ```

- 离线脚本（当前若在 `stash@{0}` 里，先 `git stash pop` 或
  `git show 'stash@{0}^3:scripts/xxx.py'` 取出）：

  | 脚本 | 用途 |
  |---|---|
  | `scripts/decrypt_wx244.py` | 容器解析、外层/内层/`_c` 解密、RSA 尾记录 |
  | `scripts/build_x30_min.py` | 从项目仓生成 X30 最小运行目录/资产 zip |
  | `scripts/runtime_names.py` | 运行时文件名规则 |
  | `scripts/build_release_packs.py` | Gradle 用的功能包 zip 构建 |

- native 分析：NDK 的 `llvm-objdump.exe` 反汇编桥 `36a76b97`。

## 2. 包体盘点

1. 对每个来源（高级包、tar、`data/xmetadata`、项目 `xmetadata`、
   X 3.0 配置包）列出 **文件名、body 大小、SHA-256/MD5**。
2. 区分“容器文件”和“普通文件”：容器通常含 magic `97c40130`，
   前 32B 可能是 `SHA-256(body)` 前缀。
3. 先比较 **body**（去前缀后）而不是文件大小；20B/32B 头差异会造成误判。
4. 运行名不是随机：

   ```text
   trim(MD5("FP_<role>")) / trim(MD5("<role>"))；core = MD5("C")
   trim = 逐字节去掉 hex 前导 0
   ```

   扩展包两套命名都要放；`D/Xmd/P_8049/LD64/bridge` 等是固定 ID。
5. 记录每个来源的核心版本尾：`<7/9位后缀>,<hash>,0`；
   X 3.0 项目仓 core `370042`（尾 `0021125`）与远程仓 `371498`
   （尾 `0021139`）就是兼容/不兼容的分界。

## 3. 容器与密码

### 3.1 结构识别

- 7 元组 `[version, 5位位置置换, f1..f5]`；按置换取
  `f1=payload(前16B IV)`、`f3=salt(8B)`、`f4=seed(24B)`、`f2/f5=256B 签名`。
- 字段可能以不同顺序落盘，**先按置换展开再按大小/类型校验**。
- 256B 槽位不一定是哈希：可能是 `PKCS#1 v1.5` 的 RSA 记录。

### 3.2 PBE/AES 实现细节

```text
dk = PBKDF1-MD5(password, salt, 1000, 16)
DES-CBC(key=dk[:8], IV=dk[8:16]) 解 f4(24B)
去 PKCS#5 padding -> 16B AES key
AES-CBC(IV=f1[:16]) 解 f1[16:]
```

- 常见错误：把 DES IV 当成 salt、PBKDF1 输出长度取 8、忘记去除 seed 的
  PKCS#5 padding。
- 明文校验：zip `PK`、dex `dex\n`、容器 magic、msgpack `fixstr`、
  PKCS#5/7 尾部一致。

### 3.3 后缀与 password

- 2.44：9 位后缀 + **含包名 P**；X 3.0：7 位后缀 + **不含 P**。
- 后缀来源：外层/内层/`_c` 的 256B RSA 尾记录，用厂商公钥做公钥还原：
  `m = block^e mod n`，去掉 `00 01 FF..FF 00`。
- password = `trim(MD5(常量排列 + 后缀))`；常量 `C/K/P/S1..S5`。
- 爆破策略：先 3–4 个 token 的全排列，再 2/5 个；先带 P 再不带 P。
  用“解密后明文类型”做校验，避免随机 padding 误报。
- `_c` 是对称 payload + 非对称记录：32B f1 解出 msgpack 字符串，
  256B 槽位给后缀；password 同样由后缀推导。

## 4. 动态探针

- `CryptoProbe`：记录 `PBEKeySpec`、`generateSecret`、`Cipher.init`、
  `doFinal`。靠 **password+salt+seed+IV+AES key** 关联一次解密。
- `DigestProbe`：记录 `MessageDigest` 的 preimage，可直接看出
  `C/P/K/S + 后缀` 的拼接顺序。
- `SignatureProbe`（历史）：确认 `_s` 走 SHA1withRSA；自签放行已移除
  Java 验签；bypass 后任意 256B 可通过。
- `FileReadProbe`：看宿主读取了哪个包、读了多少字节、是否失败。
- `NativeCallProbe`：记录 `CallMethod(id,args)`；`133` 是扩展准备，
  `102` 是内层加载。
- 关键日志序列：

  ```text
  id=133 "sf" -> "0"
  digest FP_sf / sf
  id=102 <path> ... Wrapper.Init
  pbe-spec pw=... salt=...
  doFinal seed -> AES key -> iv
  dex buffer: N B / 0 B
  ```

- 0B dex 是“内层解包返回空”的信号；后面常跟
  `Bad range`，Android 13 再触发 JNI stale-local abort。

## 5. Native 排查

- 崩溃栈里的 `36a76b97` 偏移比函数名更有用：
  - `0x55d68` 功能包加载；
  - `0x55f40/0x55fc4` 解析包装；
  - `0x56030` 失败后解引用无效输出（fault `0x9`）；
  - `0x3fec4/0x4023c` 容器解析（insufficient bytes）。
- `SIGABRT + "attempt to remove stale Local"` 是 ART JNI local-ref
  记账问题，不是解密失败；补上真实 dex 往往能绕过这条路径。
- Android 16 上同一路径可能表现为 `negative array length` 或
  更早的 SIGSEGV（字符指针 `6tencent`），优先在 Android 13 复现。

## 6. 运行时注入

- 思路：宿主内层解包失败时会用 **0 字节 buffer** 构造
  `InMemoryDexClassLoader`。在构造函数 before 阶段替换成离线解出的真实
  `classes.dex`。
- 触发方式：
  - `CallMethod(102, path, 2, entry, ...)` 直接设置 pending；
  - 或在 `CryptoProbe` 看到外层 PBE password 时按密码映射
    `x30-sf/mf/af`（更通用）。
- pending 要设 TTL（如 10s）并在注入成功后清除，避免污染后续 loader。
- 资产按 `featuredex/<name>.dex` 放；X30 用 `x30_sf/mf/af.dex`。
- 成功标志：`com.android.xf.<feature>.Wrapper.Init` 全部初始化，
  `X: Module loaded successfully!`。

## 7. 干净环境与自动建库

- 项目本身会：
  - `FeaturePackRestorer` 从 assets 的 `x7_3.0.zip` / `x7_3.0_ext.zip`
    恢复 `files/x7_3.0/`（实测 26+6）；
  - `LicenseInstaller.ensure()` 在 DB 缺失时创建 `FKZ_WX_DATA` 并插入
    10 行（LIC/verifier6/fp/fp_async/FPVersions/LatestVersions）；
  - `FeaturePackUnlock` 补 `FPVersions` 的 sf/mf/af 和 `FPVersions_v7`。
- root shell 在 Android 13 的 app 数据目录常被 SELinux 挡住 `mv/rm`；
  把清理逻辑放到**微信进程内**（`CleanEnvironment`）执行。
- 触发：`touch /data/data/com.tencent.mm/files/wxh_clean_env`，
  重启微信；旧目录/DB 会被重命名为 `.cleanbak_*`（可恢复）。
- 验证日志：

  ```text
  clean env: ... moved
  feature packs[x30]: restored 26 file(s)
  feature packs[x30-ext]: restored 6 file(s)
  license db: ... (created, inserted 10, ...)
  X: Module loaded successfully!
  ```

## 8. 仓库与构建

- 项目仓 `xmetadata/wx7` = **32B SHA-256 前缀 + 旧版 body**；
  远程仓 `data/xmetadata/wx7` 的 core/base 更新，117 不认。
- 最小集：`3.0/r/C`、`r/L`、`r/fp/{base,themes,donation,vidurlparser,sf,mf,af}`、
  固定工具（`D/H_p/M/S/Xmd/pr/P/pr/P_8049/LD64`）、`cfg/*.{c,s}`→原样复制 `_c`/`_s`。
- 生成：

  ```bash
  python -X utf8 scripts/build_x30_min.py --source xmetadata/wx7 \
      -o build/generated/x30_min --assets app/build/generated/featurepacks/wx30
  ./gradlew :app:assembleLegacyWx30FullEditionDebug
  ```

- Gradle 的 `generateFeaturePacks` 会调用 `build_release_packs.py`：
  X30 源用项目仓、X30 ext 去 32B 前缀；`_c`/`_s` 从 `cfg/` 原样复制。
- 资产注意：`x7_3.0.zip` 放 `wx30/`，`x7_3.0_ext.zip` 放 `wx30-ext/`，
  否则 asset merge 会报 duplicate。
- 上游停止更新后的逐版本适配（8.0.50–8.0.79）见
  `docs/version-adaptation-plan.md`。

## 9. 自签经验

- 本模块存在时：`_s` 任意 256B（bypass）；`_c` 可用已知 password 重加密
  payload（保留原 256B RSA 记录）；外层/内层用已知 password 重打包。
- 包尾 256B RSA 记录由 native 用厂商公钥解析，**保留原值**；要换自己的
  RSA 必须同时替换宿主公钥/验证路径（Java + native）。
- 不要仅替换包里的 RSA 字节：未打补丁的宿主仍用厂商公钥，验签/解析会失败。
- X 3.0 实测：`_c` 的 256B 签名覆盖容器载荷，native loader 会对两个 256B 槽位做
  RSA 公钥运算；即使保留原签名块、只换 salt/IV 重新加密，也会在 `strlen(NULL)`
  处 SIGSEGV。`_s` 同理。结论：旁车必须原样保留，不能构建时重生成。

## 10. 排错清单

| 现象 | 优先检查 | 处理 |
|---|---|---|
| `133` 后 SIGSEGV fault `0x9` | 核心版本/包 body/32B 前缀 | 换 202 核 + 项目仓 body；X30 换 370042 |
| `dex buffer: 0 B` → `Bad range` | 内层 password/注入是否触发 | 检查 pending、PBE 密码映射、assets |
| `Module load error` | 核心版本是否 117 支持 | 项目仓 370042/尾 0021125；不要用 371498 |
| 菜单 `Disabled error code: 00322` | DB LIC/verifier/params | 用项目自动建库或导入完整 DB |
| 包大小/内容对不上 | 是否用了远程仓新版 | 用项目仓 body 与 32B 前缀规则 |
| LSPosed 开关改不动 | DB 在 WAL/被占用/root 写不进 | 拉 db+wal+shm 看；用管理器 UI |
| root 无法改 app 数据 | SELinux | 在微信进程内做（模块代码），或换现有文件覆盖 |
| 点击/截图无效 | 屏幕 AOD/锁屏 | `input keyevent WAKEUP`、`svc power stayon true` |
| asset duplicate | 同名 zip 同时在 `wx30/` 与 `wx30-ext/` | 只保留 `wx30-ext/` 那份 |
| 脚本 import 失败 | `python -I` 去掉脚本目录 | 显式 `sys.path.insert(0, script_dir)` |

## 11. 复现与证据

- 结论/密钥表：`docs/extension-pack-chain.md`。
- 本次证据：`build/analysis/af13/x30-20261022/`（README 有索引）。
- 最小集：`build/generated/x30_min/x7_3.0/`（32 文件）。
- 归档：`build/archive/`（可删除回收空间）。

## 12. 经验原则

1. **先离线**：能在 PC 上解的，不要先上设备。
2. **单变量**：一次只换包/核心/DB 中的一项，记录对照。
3. **可逆**：清理用重命名/stash/archive，不直接删除。
4. **证据化**：每个结论都留日志、哈希、DB 快照和截图。
5. **规则化**：能由命名/哈希推导的，不要手写常量。
6. **边界清晰**：本模块存在与否，决定自签能做到哪一步。
