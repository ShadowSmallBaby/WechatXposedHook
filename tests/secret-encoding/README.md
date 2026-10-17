# 敏感常量编码对照

源码里的敏感常量(微X 混淆类名、校验方法名、58 项功能列表、AES 密钥、锚点串、
功能包清单)不以明文出现,而是由 `scripts/encode_secrets.py` 编码成密文写进
`app/.../hook/loader/SecretConstants.java`,运行时用 `Secret.of` 还原。

明文表在 `scripts/secrets_table.py`(只在内部仓),`encode_secrets.py` 只有逻辑与
常量名清单 `NAMES`。密文里带常量名前缀(`"<常量名>:<Base64>"`),so 用它当 HKDF 的 salt
派生该常量专属的子密钥。明文解码在 `libwexhook.so` 里,所以分两个测试:

- `run.py`(桌面,纯 JVM + 主机 clang):校验密文 = 明文表编码结果,以及
  `secret_crypto.inc` 的 HKDF 派生与 Python 的 `derive_subkey` 逐字节一致;
- `run-device.py`(真机):把 so 推到设备,校验 native 解出的明文与明文表逐项一致。

```powershell
python -X utf8 tests/secret-encoding/run.py --jdk <JDK17> --clang <NDK clang>
python -X utf8 tests/secret-encoding/run-device.py --sdk <SDK> --jdk <JDK17> --serial <adb>
```

## 为什么要有这个测试

编码是「常量名派生 HKDF 子密钥 + 逐字节 XOR + 位置混合」,Python 侧和 C 侧各写一遍。
两边最容易踩的坑有三个:

1. **子密钥派生必须一致**:HKDF-SHA256(主密钥 + 常量名当 salt)在 Python 与 C 里各实现一遍,
   任一处(信息串、计数器、位数)不同就全解错;`run.py` 编真源码逐项比对 C 与 Python 的派生值;
2. **常量名必须随密文传**:salt 是常量名,密文前缀带上它,so 才能派生出同一把子密钥;
3. **UTF-8 不能按字节当字符**:微X 的混淆类名全是多字节 UTF-8,早期 C 实现一个字节
   当一个 UTF-16 字符,ASCII 常量正常、多字节常量全变乱码(71 项里错 24 项)。

这些都不会报错,只会静默产出乱码——真机上表现为 hook 全部找不到类。

## 检查项

| 检查 | 期望 |
|---|---|
| 生成文件编译通过 | `javac` 退出码 0 |
| 每个密文与脚本编码结果一致 | 逐项相同 |
| 明文表的常量名与 `NAMES` 一致 | 无缺项、无多余项 |
| `secret_crypto.inc` 的 HKDF 派生与 Python 一致 | 70/70 |
| 真机上 so 能加载 | 输出 `native=available` |
| native 解出的明文与明文表一致 | 70/70 |

设了 `WXH_MASTER_KEY` 时,`run.py` 会给 C 侧同一个 `-DWXH_MASTER_KEY_BYTES`,
并打印 `主密钥来自 WXH_MASTER_KEY`,用于验证覆盖后的 C / Python 仍然一致。
