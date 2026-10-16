# 授权库生成对照

模块里的 `LicenseData`(纯 Java)与 `scripts/generate_min_db.py` 是同一套算法的两份实现,
这里用同一批账号分别跑一遍,逐行比对 FKZ_WX_DATA 的 TAG/TYPE/VALUE。
参考实现已与设备上被微X 接受的 `data/FKZ_WX_DATA` 逐字节一致。

```powershell
python -X utf8 tests/license-data/run.py --jdk <JDK17>
```

纯 JVM,不需要设备、Android SDK 或微信。编译产物在 `build/license-data/`。

## 真机场景(run-device.py)

库已存在、账号已存在时不能重建:这里把 FKZ_WX_DATA 副本推到 `/data/local/tmp`,
用 `app_process` 跑真正的 `LicenseDatabase.ensure`(`android.database.sqlite`),逐项比对十一种情形与幂等性。
设备上真实的那份库不会被改动;`--source` 默认取 `data/FKZ_WX_DATA`,也可以直接给设备实库的副本。

```powershell
python -X utf8 tests/license-data/run-device.py --sdk <Android SDK> --jdk <JDK17> --serial <adb serial>
python -X utf8 tests/license-data/run-device.py --sdk <SDK> --jdk <JDK17> --serial <serial> --source <FKZ_WX_DATA 样本>
```

| 场景 | 期望 |
|---|---|
| 库不存在 | 新建 + 10 行,`user_version = 1` |
| 账号已存在且完整 | 一行不动,LIC/verifier6 原值保留(kept=2) |
| 库已存在但账号不在 | 只插这个账号的 10 行 |
| 账号已存在但 LIC 是别人的 | 只重算 LIC/verifier6(refreshed=2) |
| 库已存在但 `user_version` 不是 1 | 改回 1,数据行不动 |
| 账号已存在但 verifier6 缺失 | 只补 verifier6(inserted=1, kept=1) |
| 账号已存在但 verifier6 是别人的 | 只重算 verifier6(refreshed=1, kept=1) |
| 库被微X 占用(第二条连接开着) | 照常写入 |
| 微X 占着写事务 | `SQLiteDatabaseLockedException`,只记日志,不影响微X |
| 库文件存在但 0 字节 | 当成空库,建表 + 写 10 行 |
| 库文件损坏(不是 SQLite) | Android 的 `SQLiteDatabase` 删掉坏文件重建,照常写 10 行 |
| 重复执行 | 幂等(inserted=0, refreshed=0, kept=2) |

不会碰设备上真实的 `/data/data/com.tencent.mm/databases/FKZ_WX_DATA`。
