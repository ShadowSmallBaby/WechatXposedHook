# 版本适配 SOP 明细（微信 8.0.50–8.0.79）

> 配套 `docs/version-adaptation-plan.md`。本文把单版本适配拆到**可执行命令与产物**级别，
> 一个版本从头到尾照着做即可。
>
> 约定：`<ver>` = 微信版本去点（如 `8050`）；`<verDotted>` = `8.0.50`；
> 证据目录 `build/analysis/$VER/`。

## 0. 前置条件

| 项 | 要求 |
|---|---|
| 基线 | 微信 8.0.49 + X 3.0 117 + x30，`P_8049` 可解密 |
| 工具 | Python 3.11+、pycryptodome、Android SDK build-tools（`aapt2`/`apksigner`/`dexdump`） |
| 设备 | A13 + A16 各一台，LSPosed，可无线 ADB |
| 仓库 | 工作区干净；`xmetadata/wx7/pr/P_8049`、`scripts/` 可读 |

```bash
# 每个新版本只改这三行，后续命令可直接复制
export VER=8050            # 微信版本去点
export VER_DOTTED=8.0.50   # 微信版本
export SERIAL=<设备序列号>  # adb devices 里的 serial

mkdir -p build/analysis/$VER
```

> 正文表格里的 `P_<ver>` 是命名约定；代码块里统一用 `$VER` / `$VER_DOTTED`。

## 1. 目录与产物约定

```text
build/analysis/$VER/
├── apk-meta.json            # 包名/versionCode/versionName/签名/ABI
├── classes.dex  …           # 导出的原始 dex
├── dex-stats.txt            # 类/方法/字符串规模
├── dex-diff.txt             # 与 8.0.49 的类清单差异
├── map-base.json            # 解密后的 P_8049 映射
├── map-<ver>.json           # 迁移结果
├── map-<ver>.report.json    # 置信度/未匹配/冲突
└── verify.log               # 离线、构建、实机验证输出

xmetadata/wx7/pr/P_$VER     # 最终源文件（32B 前缀 + body）
```

## 2. Step 0 采集 APK

```bash
APK=data/wechat/wechat-$VER_DOTTED.apk

aapt2 dump badging "$APK" > build/analysis/$VER/apk-meta.txt
apksigner verify --print-certs "$APK" > build/analysis/$VER/apk-certs.txt
unzip -l "$APK" | grep -E 'classes[0-9]*\.dex|lib/' > build/analysis/$VER/apk-list.txt
unzip -o "$APK" 'classes*.dex' -d build/analysis/$VER/
```

`apk-meta.json` 手工记录（后续可脚本化）：

```json
{
  "version": "8.0.50",
  "version_code": "<从 badging 读取>",
  "channel": "cn",
  "signer_sha256": "<从 apksigner 读取>",
  "abis": ["arm64-v8a", "armeabi-v7a"],
  "dex_count": 0
}
```

检查点：

- [ ] `versionName` 与目标一致；`versionCode` 已记录
- [ ] 签名哈希与 8.0.49 相同（不同则单列为渠道变体）
- [ ] 至少一个 `classes*.dex` 正常解出

## 3. Step 1 基线对齐

```bash
# 规模统计（支持直接喂 APK，自动展开 classes*.dex）
python -X utf8 scripts/dex_inspect.py stats \
    data/wechat/wechat-8.0.49.apk data/wechat/wechat-$VER_DOTTED.apk \
    > build/analysis/$VER/dex-stats.txt

# 类清单差异
python -X utf8 scripts/dex_inspect.py diff \
    data/wechat/wechat-8.0.49.apk data/wechat/wechat-$VER_DOTTED.apk \
    > build/analysis/$VER/dex-diff.txt
```

```bash
# 需要 dexdump 文本时（定位锚点类用）
python -X utf8 scripts/dex_inspect.py dump \
    build/analysis/$VER/classes.dex -o build/analysis/$VER/classes.smali.txt

python -X utf8 scripts/dex_inspect.py class \
    build/analysis/$VER/classes.smali.txt 'L<混淆类名>;' --inner
```

检查点：

- [ ] 类总数变化在合理范围，未出现 dex 分批规则变化
- [ ] 无新增/删除顶层包导致入口类整体迁移

## 4. Step 2 映射迁移（核心）

### 4.1 准备基线映射

```bash
python -X utf8 scripts/decrypt_wx244.py \
    xmetadata/wx7/pr/P_8049 -o build/scratch/p8049
```

`build/scratch/p8049/P_8049.msgpack` 是 `{语义键: 混淆类名}` 的 msgpack **map16**
（基线 1410 条）。项目脚本没有引入 msgpack 依赖，用下面这个最小解析片段即可
（已对 `P_8049` 验证：1410 条，恰好读到文件末尾）：

```bash
python -X utf8 - <<EOF
import json, pathlib

def parse_map16(raw):
    assert raw[0] == 0xDE                       # map16
    count = int.from_bytes(raw[1:3], 'big')
    pos = 3
    def read(p):
        tag = raw[p]
        if 0xA0 <= tag <= 0xBF:                 # fixstr
            n = tag & 0x1F
            return raw[p + 1:p + 1 + n].decode(), p + 1 + n
        if tag == 0xC0:                         # nil
            return None, p + 1
        if tag == 0xD9:                         # str8
            n = raw[p + 1]
            return raw[p + 2:p + 2 + n].decode(), p + 2 + n
        if tag == 0xDA:                         # str16
            n = int.from_bytes(raw[p + 1:p + 3], 'big')
            return raw[p + 3:p + 3 + n].decode(), p + 3 + n
        if tag == 0xDB:                         # str32
            n = int.from_bytes(raw[p + 1:p + 5], 'big')
            return raw[p + 5:p + 5 + n].decode(), p + 5 + n
        raise ValueError(f"unsupported tag {tag:#x} at {p}")
    out = {}
    for _ in range(count):
        key, pos = read(pos)
        value, pos = read(pos)
        out[key] = value
    return out, pos

raw = pathlib.Path('build/scratch/p8049/P_8049.msgpack').read_bytes()
mapping, end = parse_map16(raw)
assert end == len(raw), f"trailing bytes: {len(raw) - end}"
pathlib.Path('build/analysis/$VER/map-base.json').write_text(
    json.dumps(mapping, ensure_ascii=False, indent=1), encoding='utf-8')
print(len(mapping))
EOF
```

> 输出 `1410` 即正常。映射值的 `#` 前缀是原格式的一部分，迁移时原样保留。

### 4.2 锚点优先级

先锚定下列高价值键（其余靠传播），每类至少确认一个：

| 组 | 键示例 | 用途 |
|---|---|---|
| 入口 | `LauncherUI`、`MMActivity` | 启动链 |
| 会话 | `ChattingUI`、`SingleChatInfoUI` | 消息主功能 |
| 设置 | `SettingsUI` 等设置入口 | 菜单注入 |
| 朋友圈 | `SnsTimeLineUI`、`SnsCommentDetailUI` | 扩展功能 |
| 支付 | `LuckyMoney*`、钱包相关 | 只读检查 |
| 类加载 | `TinkerPatchService`、`WebView` | 壳兼容 |

定位方法（按顺序）：

1. **字符串/资源唯一命中**：在 `classes.smali.txt` 搜类内独有字符串。
   ```bash
   python -X utf8 scripts/dex_inspect.py summary \
       build/analysis/$VER/classes.smali.txt <包前缀>
   ```
2. **父类/接口 + 方法形状**：类描述符、父类、方法数与参数签名。
3. **调用边传播**：已锚定类的方法参数/返回值类型，推导相邻类。

### 4.3 结构指纹字段

对每个候选类记录（用于自动匹配）：

```json
{
  "descriptor": "Lx/y/z;",
  "super": "Lx/a/b;",
  "interfaces": ["L...;"],
  "methods": ["name(sig)ret", "..."],
  "fields": ["type name", "..."],
  "strings": ["sha1(const-string)", "..."],
  "reflect": ["class/field/method 反射字面量"],
  "callers": ["L...;->m(...)"],
  "callees": ["L...;->m(...)"]
}
```

匹配优先级：

```text
1. 类内独有字符串 / 资源名完全一致（置信度 高）
2. super + interfaces + 方法签名集合一致（高）
3. 方法名集合 + 字段类型集合 + 字符串集合 Jaccard ≥ 0.8（中）
4. 调用图上邻居已锚定 ≥ 2 个（中）
5. 仅语义名相似（低，必须人工复核）
```

### 4.4 输出与复核

```text
map-<ver>.json          # 最终映射，键集合必须与 map-base.json 一致
map-<ver>.report.json   # {key: {class, confidence, evidence, conflicts}}
```

- 键集合必须与基线一致；缺失键显式标 `null`，禁止静默删除。
- 置信度 `低` 的键逐条人工复核，至少抽查 10 个高价值键与目标 dex 对照。
- 相邻版本先试“继承”：`8.0.51` 以 `8.0.50` 的映射为种子，只重算差异类。

## 5. Step 3 生成参数容器

### 5.1 字节布局

```text
源文件 = SHA-256(body)[32B] + body
body   = msgpack fixarray(7)              # 前 4 字节即 97 c4 01 30
         [0] b"0"                          # 97=fixarray(7), c4 01 30=bin8 "0"
         [1] b"23541"                      # 5 位置换：第 i 位表示槽位 i 存放的字段
         [2] 字段2 = 256B 签名槽            # 以下槽位顺序由置换决定，不是 f1..f5 顺序
         [3] 字段3 = 8B salt
         [4] 字段5 = 256B 签名槽
         [5] 字段4 = 24B PBE 加密的 16B AES key
         [6] 字段1 = IV(16B) + AES-128-CBC 密文
```

> 基线置换是 `23541`：槽位 0..4 分别存放字段 `2,3,5,4,1`。
> 生成时**原样沿用这组置换与槽位排布**，只替换字段 1 的内容和重新生成字段 3/4。

### 5.2 加密流程

```text
key       = 16 随机字节
iv        = 16 随机字节
plain     = PKCS7(msgpack(map), block=16)
f1        = iv + AES-128-CBC(key, iv, plain)

salt      = 8 随机字节
digest    = MD5(password + salt)，再迭代 MD5 999 次（共 1000 轮）
seed_plain= key + PKCS5(8)               # 16B -> 24B
f4        = DES-CBC(key=digest[:8], iv=digest[8:16], seed_plain)

password  = trim(MD5(常量排列 + 7 位后缀))
             trim = 逐字节去掉 hex 前导 0
基线      = 排列 C S1 K / 后缀 0002318
           password ac282e135a29e137cf97b7677676c520
```

### 5.3 槽位策略（二开默认）

- `f2` / `f5` **直接复制 P_8049 的 256B 槽位**，`f3`、`f4` 按新 key 重新生成，`f1` 换新映射。
- 若核心校验签名槽导致加载失败：先启用本模块 `自签放行（已移除）` 验证；
  仍失败再用 `PbePasswordHook` / `DigestProbe` 抓取核心实际使用的 preimage。
- 密码公式先用基线后缀；核心拒绝时，抓取真实 password 后回填本文与
  `docs/extension-pack-chain.md`。

### 5.4 离线自检

```bash
python -X utf8 scripts/decrypt_wx244.py \
    xmetadata/wx7/pr/P_$VER -o build/scratch/p$VER
# 输出应是 msgpack；条目数应与 map-$VER.json 一致
```

检查点：

- [ ] 32B 前缀 == SHA-256(body)
- [ ] 解密回读的 map 与 `map-<ver>.json` 逐键一致
- [ ] 条目数与基线差异有解释

### 5.5 去重

对 `map-<ver>.json` 的规范化 JSON 取 SHA-256：

- 哈希与已有版本相同 → 矩阵标注“复用 `P_80xx`”，不新建容器；
- 不同 → 正常生成。

## 6. Step 4 登记与打包

### 6.1 文件级改动

| 文件 | 位置 | 改动 |
|---|---|---|
| `scripts/runtime_names.py` | `UTILITY` | 新增 `"pr/P_<ver>"`；路线 A 值填基线运行名 `6d6586c9c5458ecfc98981b52ee662de` |
| `scripts/build_x30_min.py` | `BASE_PACKS` | `("pr/P_<ver>", UTILITY["pr/P_<ver>"])` |
| `scripts/build_release_packs.py` | `COMMON` | 同步该行 |
| `scripts/reverse_pack_to_xmetadata.py` | `LAYOUT` | 运行名 -> `pr/P_<ver>` |
| `app/.../deploy/FeaturePackRestorer.java` | `X30_BASE_NAMES` / `X30_BASE_SIZES` | 运行名不变；**尺寸改成新文件字节数** |
| `docs/extension-pack-chain.md` | 参数表 | 新增后缀/排列/salt/password/尺寸 |

> 运行名不变时，`X30_BASE_NAMES` 不用动，但 `X30_BASE_SIZES` 必须改；
> 尺寸不匹配会导致补齐逻辑跳过该文件，且日志不报错。

### 6.2 生成与构建

```bash
python -X utf8 scripts/build_x30_min.py --source xmetadata/wx7 \
    -o build/generated/x30_min --assets app/build/generated/featurepacks/wx30
./gradlew :app:assembleLegacyWx30FullEditionDebug
```

> `scripts/verify_featurepack.py` 里的 `EXPECTED_NAMES` 是 **2.44 的 30 个文件**，
> 不要用它校验 `x7_3.0`。X30 用下面片段直接从 `FeaturePackRestorer.java`
> 读清单并逐文件比对（对当前仓库已验证：26 基础 + 6 扩展全部命中、尺寸一致）：

```bash
python -X utf8 - <<'EOF'
import re, pathlib, sys

src = pathlib.Path('app/src/main/java/github/shadowbaby/'
                   'wechatxposed/hook/deploy/FeaturePackRestorer.java').read_text('utf-8')

def names(field):
    block = re.search(field + r'\s*=\s*\{(.*?)\};', src, re.S).group(1)
    return re.findall(r'"([^"]+)"', block)

def sizes(field):
    block = re.search(field + r'\s*=\s*\{(.*?)\};', src, re.S).group(1)
    return [int(x) for x in re.findall(r'(\d+)L', block)]

root = pathlib.Path('build/generated/x30_min/x7_3.0')
actual = {p.name: p.stat().st_size for p in root.iterdir() if p.is_file()}
bad = 0
for label, nfield, sfield in (("base", "X30_BASE_NAMES", "X30_BASE_SIZES"),
                              ("ext", "X30_EXT_NAMES", "X30_EXT_SIZES")):
    expected_names, expected_sizes = names(nfield), sizes(sfield)
    missing = [n for n in expected_names if n not in actual]
    mismatch = [(n, actual[n], s) for n, s in zip(expected_names, expected_sizes)
                if n in actual and actual[n] != s]
    print(f"{label}: {len(expected_names)} expected, missing={missing}, size_bad={mismatch}")
    bad += len(missing) + len(mismatch)
sys.exit(1 if bad else 0)
EOF
```

## 7. Step 5 验证

### 7.1 离线 / 构建

```bash
# 运行目录文件数与尺寸
ls build/generated/x30_min/x7_3.0 | wc -l
python -X utf8 scripts/scan_xmetadata_manifest.py \
    --root xmetadata/wx7 --out build/analysis/$VER/manifest.json
```

- [ ] 26 + 6 个文件齐全
- [ ] `P_<ver>` 尺寸与 `FeaturePackRestorer` 中登记值一致
- [ ] 构建产物 assets 内文件名/尺寸与 Java 清单一致

### 7.2 实机

```bash
adb -s $SERIAL shell am force-stop com.tencent.mm
adb -s $SERIAL logcat -c
adb -s $SERIAL shell am start -n com.tencent.mm/.ui.LauncherUI
sleep 8
adb -s $SERIAL logcat -d -v time > build/analysis/$VER/logcat-1.log
# 二次启动用于确认参数文件已被读取
adb -s $SERIAL shell am force-stop com.tencent.mm
adb -s $SERIAL shell am start -n com.tencent.mm/.ui.LauncherUI
sleep 8
adb -s $SERIAL logcat -d -v time > build/analysis/$VER/logcat-2.log
```

日志判定：

| 现象 | 判定 |
|---|---|
| `feature packs[x30]: restored 26 file(s)` | 包完整 |
| `X: Module loaded successfully!` | 加载通过 |
| `SIGSEGV` / `fault addr` | 核心不兼容 → 路线 B 或换核心 |
| `dex buffer: 0 B` / `Bad range` | 扩展包解密/注入问题，非 P 文件 |
| `Module load error` | 核心与参数不匹配 |
| 菜单不出现且无崩溃 | 先查身份/`modulePath`，再查映射高价值键 |

### 7.3 功能矩阵

每个版本至少回归：

- [ ] 微信设置页菜单可见、可开关
- [ ] 会话列表 / 聊天页正常进入
- [ ] 消息类功能（撤回/提示等）生效
- [ ] 朋友圈入口正常
- [ ] 支付/转账页面只读检查（不触发写操作）
- [ ] 扩展包 sf / mf / af 初始化计数正常
- [ ] 异常退出率为 0（连续使用 10 分钟）

## 8. Step 6 发布与回滚

```text
1. 矩阵状态 -> ✔，填写 versionCode / 渠道 / 证据目录
2. 保留上一版本源文件与缓存产物：
   xmetadata/wx7/pr/P_8049（基线）
   build/generated/x30_min-<ver>/
3. 回滚顺序：参数文件 -> 资产 zip -> APK；不先动核心
4. 提交信息：
   feat(adapt): 微信 <verDotted> 参数适配
   versionCode=<...> map=<sha256 前 12 位> evidence=build/analysis/$VER/
```

## 9. 单版本 checklist（可复制）

```markdown
- [ ] Step 0 采集：版本号/versionCode/签名/ABI 记录
- [ ] Step 1 基线：dex stats + diff 已生成
- [ ] Step 2 映射：键集合与基线一致；低置信度已复核
- [ ] Step 3 容器：离线解密回读一致；哈希去重已判断
- [ ] Step 4 登记：runtime_names / 两个构建脚本 / 逆推表 / 尺寸
- [ ] Step 5 离线：26+6 文件、尺寸一致
- [ ] Step 5 实机：A13/A16 日志通过
- [ ] Step 5 功能：菜单/会话/消息/朋友圈/支付/扩展包
- [ ] Step 6 发布：矩阵 ✔、证据归档、提交信息完整
```

## 10. 待实现脚本（SOP 的自动化落点）

| 脚本 | 输入 -> 输出 | 替换本文的哪一步 |
|---|---|---|
| `import_wechat_apk.py` | APK -> `apk-meta.json` + dex | Step 0 |
| `migrate_param_map.py` | 基线 map + 目标 APK -> `map-<ver>.json` + report | Step 2 |
| `build_param_container.py` | map JSON -> `P_<ver>` + 自检 | Step 3 |
| `version_matrix.py` | 仓库状态 -> 矩阵校验 | Step 4/5 |

在脚本落地前，Step 2 以“锚点 + 人工复核”为主，Step 3 按 §5 的字节布局手工实现一次，
之后再固化成脚本。
