# dex 常量池解析回归

`HostVersionSpoof` 靠一个自写的 dex 解析器(`DexStrings`)按字符串常量反查混淆类,
不依赖 DexKit。这个测试在桌面 JVM 上直接跑那个解析器,把「每个 dex 里命中某字符串的类数」
和一份独立的 Python 参考实现逐行对照,证明两边结果一致。

```powershell
python -X utf8 tests/dex-strings/run.py --jdk C:/Users/Smallbaby/.jdks/liberica-17.0.20.1 --dex-dir data/tmp/edit/dex
```

`--dex-dir` 指向微信 base.apk 解出来的 dex 目录(不入库,自己从设备上拉)。
没有 dex 时脚本会跳过并说明,不算失败。

## 为什么要有这个测试

dex 格式的坑很密:方法索引在 direct / virtual 两段各自从 0 累加;proto 的参数表是
「u32 个数 + 若干 u16」而不是以 0 结尾;const-string 与 const-string/jumbo 的索引宽度不同。
任何一处读错,反查结果就会静默偏差——类还是能找到,只是找错或找不到。
桌面 JVM 跑得快,拿 15 个真 dex 和 Python 参考实现全量对照,比在设备上试错省时间。

## 检查项

| 检查 | 期望 |
|---|---|
| Java 解析器编译通过 | `javac` 退出码 0 |
| 每个 dex 的命中类数与 Python 参考一致 | 逐行相同 |
| 启动构造器锚点唯一命中 | `classes5.dex` 命中 1 个类 |
| private_openUrl 锚点唯一命中 | `classes.dex` 命中 1 个类 |
