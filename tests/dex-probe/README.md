# 类名常量探针

App 里那些混淆后的类名常量(点号分隔的二进制名)必须能从真的 dex 里解析出来,
否则 `findAndHookMethod` 只会抛 `ClassNotFoundException`。这里就是验证这一步:
把 App源码里的常量抽出来,在设备上用 `InMemoryDexClassLoader` 装一份真的微X dex,
对每个名字分别用**点号**形式和**斜杠**形式调一次 `Class.forName`。

```powershell
python -X utf8 tests/dex-probe/run.py --sdk <Android SDK> --jdk <JDK17> --serial <adb serial>
```

默认拿 `data/refs/device_dump/BaseDex.dex`(运行时从 `InMemoryDexClassLoader` 里落盘的
微X Base 组件明文 dex,见 `docs/reverse-engineering.md` 1.5),可用 `--dex` 指定别的。

## 这个测试挡的是什么

dex 描述符写成 `Lʾⁱ/ⁱʽ;`,常量就得写成 `ʾⁱ.ⁱʽ`——**点号**。
实测把斜杠形式 `ʾⁱ/ⁱʽ` 交给 `Class.forName` 会抛 `ClassNotFoundException`,
而类其实就在同一个 dex 里(探针会把这一点一起打出来)。类名写错一个字符,
`findAndHookMethod` 就只会抛 `ClassNotFoundException`,和「这个 dex 里没有它」表现一样难区分。

检查项:

| 检查 | 期望 |
|---|---|
| 每个常量点号形式能解析 | `ok` |
| 每个常量斜杠形式解析不了 | `ClassNotFoundException`(反例,证明上面那条不是废话) |
