package github.shadowbaby.wechatxposed.hook.rebuild.support;

import android.content.Context;
import github.shadowbaby.wechatxposed.hook.rebuild.loader.InMemoryDexLoadHook;

/**
 * 重建源码：c.a —— 单个微X组件 dex 的 hook 注入器（原始 c 包的混淆类，原类名 c.a，原字段 f2/f10a）。
 *
 * 原始实现是状态机（while(true) switch(state)，state = hashCode(三字混淆字符串)）。
 * 本类按原始状态编号（原 0xNNN）逐状态还原：每个 case 对应原始一个状态块，
 * 状态值即原始 sparse-switch 的字符串 hashCode；寄存器轮转（v0..v37）以语义局部变量承载。
 * 死/诱饵分支（unusedFlag/truthyFlag/zero/alwaysTrue 装饰出的等价分支）折叠但保留状态号注释。
 *
 * 字符串池 HOOK_POOL（原 f2，130 项），XOR key=52313。已解出的明文段：
 *   1/8    "ﹶˆ.ˉˑ$ʿᵔ"                            —— Base 组件内混淆类（findClass 目标）
 *   9/5    "ﹶˆ.ʼי"                                —— Base 组件内混淆类（findAndHookMethod 目标）
 *   14/2   "ⁱʼ"                                    —— 上面两个类的方法名
 *   16/45  "com.fkzhang.wechatxposedhooks.WxJniCoreBridge"
 *   61/10  "CallMethod"
 *   71/7   "c.ﹶˉ.ᵔˉ"
 *   78/2   "ٴʼ"      80/1 "ᵢ"   81/6 "c.ˋ.ᵢˑ"   87/2 "ˋᵎ"   89/2 "ˎˈ"
 *   91/7   "c.ﹶˉ.ـˋ"   98/2 "ـˋ"
 *   100/8  "ᵔˏ.ⁱי$ʿٴ"                               —— Themes 组件内混淆类（findClass 目标）
 *   108/5  "ᵔˏ.ᐧי"   113/2 "ˏˊ"
 *   115/8  "ﹶˎ.ʻˎ$ﾞˏ"                              —— Donation 组件内混淆类（findClass 目标）
 *   123/5  "ﹶˎ.ـˆ"   128/2 "ʽʾ"
 *
 * 入口（原 0x440）：v24 = HOOK_POOL[0] = 4477；v16 = (v24+1)^2 = 20052484；
 *   0x420 做一次循环上界判断，0x40b 把 XOR key 固定为 52313，0x3d9 按 componentId 分派：
 *     componentId 0 → 0x38f（Base）  1 → 0x5c（Core）
 *     componentId 2 → 0x124（Themes） 其它 → 0xda（Donation）
 *
 * 各 componentId 的真实 hook 序列（执行顺序，已用 smali 解释器逐指令核对）：
 *
 *   componentId = 0（Base，原 0x38f → 0x36f → 0x35e）：
 *     findAndHookMethod("ﹶˆ.ʼי", cl, "ⁱʼ",
 *         {String.class, findClass("ﹶˆ.ˉˑ$ʿᵔ", cl), new InMemoryDexLoadHook(1)})
 *
 *   componentId = 1（Core，原 0x5c → 0x314 → 0x2cd → 0x2a8 → 0x268 → 0x23d → 0x21a
 *                     → 0x1f1 → 0x1d8 → 0x1b2 → 0x19d → 0x174 → 0x15e）：
 *     1) findAndHookMethod("com.fkzhang.wechatxposedhooks.WxJniCoreBridge", cl, "CallMethod",
 *         {Integer.TYPE, Object[].class, new CallMethodBypassHook(cl, 0)})
 *     2) findAndHookMethod("c.ﹶˉ.ᵔˉ", cl, "ٴʼ",
 *         {Context.class, new CallMethodBypassHook(cl, 1)})
 *     3) findAndHookMethod("c.ﹶˉ.ᵔˉ", cl, "ᵢ",
 *         {Boolean.TYPE, String.class, new VerifierMethodReplacement(1)})
 *     4) findAndHookMethod("c.ˋ.ᵢˑ", cl, "ˋᵎ",
 *         {new VerifierMethodReplacement(0)})
 *     5) findAndHookMethod("c.ﹶˉ.ᵔˉ", cl, "ˎˈ",
 *         {new VerifierMethodReplacement(2)})
 *     6) findAndHookMethod("c.ﹶˉ.ـˋ", cl, "ـˋ",
 *         {String.class, String.class, new CallMethodBypassHook(cl, 2)})
 *
 *   componentId = 2（Themes，原 0x124 → 0x10e）：
 *     findAndHookMethod("ᵔˏ.ᐧי", cl, "ˏˊ",
 *         {String.class, findClass("ᵔˏ.ⁱי$ʿٴ", cl), new InMemoryDexLoadHook(2)})
 *
 *   componentId = 3（Donation，原 0xda → 0xc4）：
 *     findAndHookMethod("ﹶˎ.ـˆ", cl, "ʽʾ",
 *         {String.class, findClass("ﹶˎ.ʻˎ$ﾞˏ", cl), new InMemoryDexLoadHook(3)})
 *
 * 注：Base/Themes/Donation 用的 hook 是 b.c（InMemoryDexLoadHook，afterHookedMethod/beforeHookedMethod
 *     按 mode 1/2/3 做校验屏蔽），不是 c.c（VerifierMethodReplacement）；
 *     Core 的 3/4/5 用的是 c.c（VerifierMethodReplacement）。
 */
public final class WxComponentHooks {

    /** 原 f2：字符串池（130 项），XOR key=52313 */
    private static final short[] HOOK_POOL = {
            4477, 12847, -12641, -13193, -12656, -12664, -13187, -12570,
            -12019, 12847, -12641, -13193, -12571, -13952, -5080, -12571,
            -13254, -13258, -13260, -13193, -13249, -13262, -13277, -13263,
            -13256, -13257, -13250, -13193, -13266, -13252, -13254, -13263,
            -13256, -13267, -13279, -13271, -13258, -13270, -13252, -13251,
            -13263, -13258, -13258, -13262, -13270, -13193, -13298, -13279,
            -13293, -13257, -13264, -13286, -13258, -13269, -13252, -13285,
            -13269, -13264, -13251, -13250, -13252, -13286, -13256, -13259,
            -13259, -13292, -13252, -13267, -13263, -13258, -13251, -13254,
            -13193, 12847, -12656, -13193, -12019, -12656, -13779, -12571,
            -11973, -13254, -13193, -12654, -13193, -11973, -12664, -12654,
            -12009, -12649, -12655, -13254, -13193, 12847, -12656, -13193,
            -13799, -12654, -13799, -12654, -12019, -12650, -13193, -5080,
            -13952, -13187, -12570, -13779, -12019, -12650, -13193, -10114,
            -13952, -12650, -12653, 12847, -12649, -13193, -12574, -12649,
            -13187, 13255, -12650, 12847, -12649, -13193, -13799, -12641,
            -12572, -12569};

    /** 原 f10a：微X组件序号（0=Base、1=Core、2=Themes、3=Donation） */
    public final int componentId;

    public WxComponentHooks(int i) {
        this.componentId = i;
    }

    /** 原 m16/m100：sArr[i + j] ^ key（key 由状态机固定为 52313） */
    private static String decode(int off, int len) {
        return ReflectBridgeA.decodeXor(HOOK_POOL, off, len, 52313);
    }

    /**
     * 原 m33：单个微X dex 加载后的 hook 注入。
     * 原始为 1262 条指令的状态机（原方法 c.a.a，39 寄存器），下面按原始状态编号还原。
     */
    public final void inject(ClassLoader classLoader) {
        // 原 0x0000-0x0021：v0..v24 清零；v0 = classLoader
        final ClassLoader cl = classLoader;
        // 原寄存器轮转（v0..v37）以语义变量承载：
        Object cls = null;           // 待 hook 的类名 / Class（原 v1/v3/v10/v18/v19 轮转）
        Object coreVerifierClass = null; // 原 v10；轮询类（v3）不能覆盖此目标
        Object hook = null;          // 待安装的 hook 实例（原 v7/v8/v9/v13 轮转）
        Object[] args = null;        // 待用的参数数组（原 filled-new-array 结果）
        int v4 = 0;                  // 原 v4：XOR key
        int v16 = 0;                 // 原 v16：(pool[0]+1)^2，循环上界
        int v24 = 0;                 // 原 v24：pool[0]

        // 原 0x0023-0x0028：state = hashCode("ۚۖۜ") = 1741600
        int state = ReflectBridgeA.hashCode("\u06da\u06d6\u06dc");

        // 原 0x0059：sparse-switch(v25) 按字符串 hashCode 派发
        while (true) {
            switch (state) {
                // ===== 原 0x440：入口，算循环上界 =====
                case 1741600: {                       // hash("ۚۖۜ")
                    v24 = HOOK_POOL[0];               // 原 0x0451 aget-short：4477
                    v16 = (v24 + 1) * (v24 + 1);      // 原 0x0453-0x0455：20052484
                    state = 1739023;                  // 原 0x0457-0x045c → 0x420
                    break;
                }
                // ===== 原 0x420：循环上界判断 =====
                case 1739023: {                       // 原 0x420
                    int v2 = v24 * 2 + 1;             // 原 0x042e-0x0430
                    v2 = v16 - v2;                    // 原 0x0432
                    if (v2 < 0) {                     // 原 0x0434 if-ltz → 0x43d
                        state = 1755183;              // 原 0x043d → 0x3f8
                    } else {
                        state = 1742691;              // 原 0x0436 → 0x40b
                    }
                    break;
                }
                // ===== 原 0x40b：XOR key = 52313 =====
                case 1742691: {                       // 原 0x40b
                    v4 = 52313;                       // 原 0x0419 const #0xcc59
                    state = 1758501;                  // 原 0x041d-0x045c → 0x3d9
                    break;
                }
                // ===== 原 0x3f8：诱饵 key（运行时不可达） =====
                case 1755183: {                       // 原 0x3f8
                    v4 = 0xd08e;                      // 原 0x0406 const #0xd08e（诱饵）
                    state = 1758501;                  // 原 0x041d-0x045c → 0x3d9
                    break;
                }
                // ===== 原 0x3d9：按 componentId 分派 =====
                case 1758501: {                       // 原 0x3d9
                    switch (componentId) {            // 原 0x03e9 packed-switch
                        case 0:  state = 1758077; break;  // 原 0x3f5 → 0x38f
                        case 1:  state = 1747804; break;  // 原 0x3f2 → 0x5c（default）
                        case 2:  state = 1749656; break;  // 原 0x3ef → 0x124
                        default: state = 1749564; break;  // 原 0x3ec → 0xda
                    }
                    break;
                }

                // ================= Base（componentId=0）=================
                // 原 0x38f：findClass("ﹶˆ.ˉˑ$ʿᵔ") + new InMemoryDexLoadHook(1)
                case 1758077: {                       // 原 0x38f
                    cls = ReflectBridgeB.findClass(decode(1, 8), cl);            // 原 0x3a2-0x3a6
                    hook = new InMemoryDexLoadHook(1);                           // 原 0x3aa-0x3ad
                    args = new Object[]{String.class, cls, hook};                // 原 0x3b0-0x3b5
                    state = 1748060;                  // 原 0x3c3 → 0x36f
                    break;
                }
                // 原 0x36f：decodeXor(9,5) = "ﹶˆ.ʼי"
                case 1748060: {                       // 原 0x36f
                    cls = decode(9, 5);               // 原 0x382
                    state = 1748322;                  // 原 0x38a → 0x35e
                    break;
                }
                // 原 0x35e：findAndHookMethod("ﹶˆ.ʼי", cl, "ⁱʼ", args)
                case 1748322: {                       // 原 0x35e
                    ReflectBridgeA.findAndHookMethod(cls, cl, decode(14, 2), args);  // 原 0x363-0x36b
                    return;                            // 原 0x36e
                }

                // ================= Core（componentId=1）=================
                // 原 0x5c：new CallMethodBypassHook(cl, 0) + args {Integer.TYPE, Object[].class, hook}
                case 1747804: {                       // 原 0x5c（default）
                    hook = new CallMethodBypassHook(cl, 0);                      // 原 0x66-0x69
                    args = new Object[]{Integer.TYPE, Object[].class, hook};     // 原 0x6c-0x73
                    state = 1740127;                  // 原 0x34a → 0x314
                    break;
                }
                // 原 0x314：decodeXor(16,45) = "com.fkzhang.wechatxposedhooks.WxJniCoreBridge"
                case 1740127: {                       // 原 0x314
                    cls = decode(16, 45);             // 原 0x326
                    state = 1751591;                  // 原 0x336 → 0x2cd
                    break;
                }
                // 原 0x2cd：findAndHookMethod(cls, cl, "CallMethod", args)
                //           + new CallMethodBypassHook(cl, 1) + args {Context.class, hook}
                case 1751591: {                       // 原 0x2cd
                    ReflectBridgeA.findAndHookMethod(cls, cl, decode(61, 10), args);  // 原 0x2db-0x2e5
                    hook = new CallMethodBypassHook(cl, 1);                      // 原 0x2e8-0x2eb
                    args = new Object[]{Context.class, hook};                    // 原 0x2ee-0x2f3
                    state = 1737843;                  // 原 0x308 → 0x2a8
                    break;
                }
                // 原 0x2a8：decodeXor(71,7) = "c.ﹶˉ.ᵔˉ"
                case 1737843: {                       // 原 0x2a8
                    cls = decode(71, 7);              // 原 0x2b3
                    coreVerifierClass = cls;
                    state = 1740200;                  // 原 0x2bd → 0x268
                    break;
                }
                // 原 0x268：findAndHookMethod(cls, cl, "ٴʼ", args)
                //           + new VerifierMethodReplacement(1) + args {Boolean.TYPE, String.class, hook}
                case 1740200: {                       // 原 0x268
                    ReflectBridgeA.findAndHookMethod(cls, cl, decode(78, 2), args);   // 原 0x26f-0x277
                    hook = new VerifierMethodReplacement(1);                     // 原 0x27a-0x288
                    args = new Object[]{Boolean.TYPE, String.class, hook};       // 原 0x28b-0x292
                    state = 1742906;                  // 原 0x295 → 0x23d
                    break;
                }
                // 原 0x23d：预置 decodeXor 参数 (pool,80,1) = "ᵢ"
                case 1742906: {                       // 原 0x23d
                    // 原 0x243-0x263：v15=pool, v6=1, v2=80（供下一状态解码 "ᵢ"）
                    state = 1743656;                  // 原 0x257 → 0x21a
                    break;
                }
                // 原 0x21a：findAndHookMethod(cls, cl, "ᵢ", args)
                //           + new VerifierMethodReplacement(0) + args {hook}
                case 1743656: {                       // 原 0x21a
                    ReflectBridgeA.findAndHookMethod(cls, cl, decode(80, 1), args);   // 原 0x220-0x224
                    hook = new VerifierMethodReplacement(0);                     // 原 0x227-0x22a
                    args = new Object[]{hook};                                   // 原 0x22d
                    state = 1742728;                  // 原 0x233 → 0x1f1
                    break;
                }
                // 原 0x1f1：decodeXor(81,6) = "c.ˋ.ᵢˑ"
                case 1742728: {                       // 原 0x1f1
                    cls = decode(81, 6);              // 原 0x1fc-0x217
                    state = 1748989;                  // 原 0x20b → 0x1d8
                    break;
                }
                // 原 0x1d8：findAndHookMethod(cls, cl, "ˋᵎ", args)
                case 1748989: {                       // 原 0x1d8
                    ReflectBridgeA.findAndHookMethod(cls, cl, decode(87, 2), args);   // 原 0x1e3-0x1e7
                    state = 1753817;                  // 原 0x1ec → 0x1b2
                    break;
                }
                // 原 0x1b2：new VerifierMethodReplacement(2) + args {hook}
                case 1753817: {                       // 原 0x1b2
                    hook = new VerifierMethodReplacement(2);                     // 原 0x1b8-0x1bb
                    args = new Object[]{hook};                                   // 原 0x1be
                    state = 1747735;                  // 原 0x1c9 → 0x19d
                    break;
                }
                // 原 0x19d：findAndHookMethod(cls, cl, "ˎˈ", args)
                case 1747735: {                       // 原 0x19d
                    ReflectBridgeA.findAndHookMethod(coreVerifierClass, cl, decode(89, 2), args); // 原 v10，非 v3
                    state = 1749794;                  // 原 0x1ec → 0x174
                    break;
                }
                // 原 0x174：new CallMethodBypassHook(cl, 2) + args {String.class, String.class, hook}
                case 1749794: {                       // 原 0x174
                    hook = new CallMethodBypassHook(cl, 2);                      // 原 0x17a-0x17d
                    args = new Object[]{String.class, String.class, hook};       // 原 0x180
                    state = 1758367;                  // 原 0x18e → 0x15e
                    break;
                }
                // 原 0x15e：findAndHookMethod("c.ﹶˉ.ـˋ", cl, "ـˋ", args)
                case 1758367: {                       // 原 0x15e
                    ReflectBridgeA.findAndHookMethod(
                            decode(91, 7), cl, decode(98, 2), args);             // 原 0x163-0x170
                    return;                            // 原 0x173
                }

                // ================= Themes（componentId=2）=================
                // 原 0x124：findClass("ᵔˏ.ⁱי$ʿٴ") + new InMemoryDexLoadHook(2)
                case 1749656: {                       // 原 0x124
                    cls = ReflectBridgeB.findClass(decode(100, 8), cl);          // 原 0x130-0x134
                    hook = new InMemoryDexLoadHook(2);                           // 原 0x138-0x13b
                    args = new Object[]{String.class, cls, hook};                // 原 0x13e-0x143
                    state = 1738732;                  // 原 0x14d → 0x10e
                    break;
                }
                // 原 0x10e：findAndHookMethod("ᵔˏ.ᐧי", cl, "ˏˊ", args)
                case 1738732: {                       // 原 0x10e
                    ReflectBridgeA.findAndHookMethod(
                            decode(108, 5), cl, decode(113, 2), args);           // 原 0x113-0x120
                    return;                            // 原 0x123
                }

                // ================= Donation（componentId=3）=================
                // 原 0xda：findClass("ﹶˎ.ʻˎ$ﾞˏ") + new InMemoryDexLoadHook(3)
                case 1749564: {                       // 原 0xda（default）
                    cls = ReflectBridgeB.findClass(decode(115, 8), cl);          // 原 0xe6-0xea
                    hook = new InMemoryDexLoadHook(3);                           // 原 0xee-0xf1
                    args = new Object[]{String.class, cls, hook};                // 原 0xf4-0xf9
                    state = 1740334;                  // 原 0x104 → 0xc4
                    break;
                }
                // 原 0xc4：findAndHookMethod("ﹶˎ.ـˆ", cl, "ʽʾ", args)
                case 1740334: {                       // 原 0xc4
                    ReflectBridgeA.findAndHookMethod(
                            decode(123, 5), cl, decode(128, 2), args);           // 原 0xc9-0xd6
                    return;                            // 原 0xd9
                }

                default:
                    throw new IllegalStateException("unexpected state " + state);
            }
        }
    }
}
