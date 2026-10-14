package github.shadowbaby.wechatxposed.hook;

import github.shadowbaby.wechatxposed.hook.rebuild.loader.InMemoryDexLoadHook;
import github.shadowbaby.wechatxposed.hook.rebuild.loader.ModuleLogger;
import github.shadowbaby.wechatxposed.hook.rebuild.support.ReflectBridgeA;
import github.shadowbaby.wechatxposed.hook.rebuild.support.ReflectBridgeB;
import de.robv.android.xposed.IXposedHookZygoteInit;

/**
 * WxModuleHook 1.2 入口（github.shadowbaby.wechatxposed.hook.XposedInit）。
 * assets/xposed_init 指向本类；原始 apk 的 classes.dex 只有这一个入口类 + 混淆包 a/b/c。
 *
 * initZygote 原始为 360 条指令的状态机（code_off=0xda74，18 寄存器），
 * 用字符串 hashCode 做 sparse-switch 派发 + 寄存器轮转（v0..v15 循环搬移）。
 * 下面按原始状态编号（原 0xNNN）还原控制流，寄存器轮转以局部变量表达；
 * 死分支（诱饵 key 13296 路径）在运行期不可达，保留其结构但不展开。
 */
public class XposedInit implements IXposedHookZygoteInit {

    /** XOR 加密的字符串池：ReflectBridgeA.decodeXor(DEX_LOADER_TARGET_POOL, 1, 36, 38961) = "dalvik.system.InMemoryDexClassLoader" */
    private static final short[] DEX_LOADER_TARGET_POOL = {4960, -26539, -26544, -26531, -26553, -26536, -26534,
            -26593, -26558, -26552, -26558, -26555, -26540, -26532, -26593, -26504, -26529,
            -26500, -26540, -26532, -26530, -26557, -26552, -26507, -26540, -26551, -26510,
            -26531, -26544, -26558, -26558, -26499, -26530, -26544, -26539, -26540, -26557};

    @Override
    public void initZygote(StartupParam startupParam) {
        // 原 0x0000-0x000b：v0..v11 = 0（寄存器清零）
        int v0 = 0, v1 = 0, v2 = 0, v3 = 0, v4 = 0, v5 = 0;
        int v6 = 0, v7 = 0, v8 = 0, v9 = 0, v10 = 0, v11 = 0;
        Object v12 = null;

        // 状态机主循环：sparse-switch 按 v12（字符串 hashCode）派发（原 0x0012）
        // 原始为 17 路 switch，下面按实际可达路径展开，保留原始状态号。
        int state = ReflectBridgeB.hashCode("\u06dc\u06e5\u06e0");  // 原 0x000c-0x0011：hash("ۜۥ۠")=1743991

        // 原 0x0111 -> 0x0113 -> 0x0119：if (ReflectBridgeA.unusedFlag == 0) 取 0x0119
        if (ReflectBridgeA.unusedFlag != 0) {
            v12 = "\u06d8\u06da\u06db";  // 原 0x0115：hash("ۘۚۛ")=1739801（诱饵分支，运行期不可达）
        } else {
            v12 = "\u06d8\u06db\u06dc";  // 原 0x0119：hash("ۘۛۜ")=1739833
        }
        state = ReflectBridgeB.hashCode(v12);  // 原 0x011b-0x011f

        // 原 0x00fd：v12 = DEX_LOADER_TARGET_POOL；if (ReflectBridgeA.unusedFlag == 0) 取 0x0106
        Object pool = DEX_LOADER_TARGET_POOL;  // 原 0x00fd sget-object XposedInit.۠ۚۦ
        if (ReflectBridgeA.unusedFlag != 0) {
            v12 = "\u06d6\u06e7\u06e5";  // 原 0x0103：hash("ۖۧۥ")=1738292（诱饵分支）
            state = ReflectBridgeB.hashCode(v12);  // 原 0x011b
        } else {
            v12 = "\u06d9\u06e0\u06d9";  // 原 0x0106：hash("ۙ۠ۙ")=1740946
            state = ReflectBridgeB.hashCode(v12);  // 原 0x0108-0x010f
        }

        // 原 0x00ec：v12 = 0；if (ReflectBridgeB.truthyFlag > 0) 取 0x00f2
        if (ReflectBridgeB.truthyFlag <= 0) {
            v12 = "\u06d8\u06da\u06db";  // 原 0x0115（诱饵分支）
            state = ReflectBridgeB.hashCode(v12);
        } else {
            v12 = "\u06e4\u06e0\u06d6";  // 原 0x00f2：hash("ۤ۠ۖ")=1751514
            state = ReflectBridgeB.hashCode(v12);  // 原 0x00f4-0x00fb
        }

        // 原 0x00d7：v12 = pool[0]（aget-short）；v13 = v12*v12
        int s = ((short[]) pool)[0];  // 4960
        int s2 = s * s;               // 24601600
        if (ReflectBridgeA.unusedFlag != 0) {
            v12 = "\u06d8\u06da\u06db";  // 原 0x0115（诱饵分支）
            state = ReflectBridgeB.hashCode(v12);
        } else {
            v12 = "\u06d6\u06e2\u06e4";  // 原 0x00e0：hash("ۖۢۤ")=1738136
            state = ReflectBridgeB.hashCode(v12);  // 原 0x00e2-0x00ea
        }

        // 原 0x00c1：v12 = 4020025；v12 += v6(24601600) → 28621625
        int acc = 4020025 + s2;  // 28621625
        if (!ReflectBridgeA.alwaysTrue()) {  // 原 0x00c5-0x00c9：恒真
            v12 = "\u06d8\u06da\u06db";  // 原 0x0115（死分支）
            state = ReflectBridgeB.hashCode(v12);
        } else {
            v12 = "\u06e5\u06db\u06e7";  // 原 0x00cc：hash("ۥۛۧ")=1752337
            state = ReflectBridgeB.hashCode(v12);  // 原 0x00ce-0x00d5
        }

        // 原 0x00ac：v12 = 4010；if (ReflectBridgeB.zero() == 0) 取 0x00b6
        int k = 4010;
        if (ReflectBridgeB.zero() != 0) {
            v12 = "\u06d8\u06da\u06db";  // 原 0x0115（死分支）
            state = ReflectBridgeB.hashCode(v12);
        } else {
            v12 = "\u06db\u06e5\u06d9";  // 原 0x00b6：hash("ۛۥۙ")=1743023
            state = ReflectBridgeB.hashCode(v12);  // 原 0x00b8-0x00bf
        }

        // 原 0x0015：v12 = v5*v8 = s*k；v12 = v7 - v12 = acc - s*k
        int delta = acc - s * k;  // 8732025
        // 原 0x0019：if-gez v12 → 0x00a8（>=0 时走真实 key 分支）
        if (delta >= 0) {
            // 原 0x00a8：v12 = "ۦ۟۠"(1753415)
            state = ReflectBridgeB.hashCode("\u06e6\u06df\u06e0");  // 原 0x00aa-0x00a6 -> 0x00a1
            // 原 0x00a1：v9 = 38961（真实 XOR key）
            v9 = 38961;
        } else {
            // 原 0x001b-0x001d -> 0x009e：v9 = 13296（诱饵 key，运行期不可达）
            v9 = 13296;
        }

        // 原 0x00a4：v12 = "ۚۙۡ"(1741698) -> 0x007d
        state = ReflectBridgeB.hashCode("\u06da\u06d9\u06e1");

        // 原 0x007d：v12 = new b/c（InMemoryDexLoadHook）；v13 = 0
        Object hook = new InMemoryDexLoadHook(0);  // 原 0x007d-0x0088
        if (ReflectBridgeA.unusedFlag != 0) {
            v12 = "\u06d8\u06da\u06db";  // 原 0x0115（死分支）
            state = ReflectBridgeB.hashCode(v12);
        } else {
            v12 = "\u06e5\u06d7\u06e6";  // 原 0x0093：hash("ۥۗۦ")=1752212
            state = ReflectBridgeB.hashCode(v12);  // 原 0x0095-0x009c
        }

        // 原 0x0068：v12 = pool；v13 = 1；if (ReflectBridgeA.unusedFlag == 0) 取 0x0072
        if (ReflectBridgeA.unusedFlag != 0) {
            v12 = "\u06eb\u06e2\u06d9";  // 原 0x006f：hash("۫ۢۙ")=1758306（诱饵分支）
            state = ReflectBridgeB.hashCode(v12);
        } else {
            v12 = "\u06dc\u06eb\u06d8";  // 原 0x0072：hash("ۜ۫ۘ")=1744169
            state = ReflectBridgeB.hashCode(v12);  // 原 0x0074-0x007c
        }

        // 原 0x004d：v12 = 36；v12 = decodeXor(pool, 1, 36, v9)
        String target = ReflectBridgeA.decodeXor((short[]) pool, 1, 36, v9);  // "dalvik.system.InMemoryDexClassLoader"
        // 原 0x0053-0x0058：if (ReflectBridgeA.alwaysTrue()) 取 0x005d
        if (!ReflectBridgeA.alwaysTrue()) {
            v12 = "\u06e6\u06d7\u06eb";  // 原 0x005a：hash("ۦۗ۫")=1748772（死分支）
            state = ReflectBridgeB.hashCode(v12);
        } else {
            v12 = "\u06dc\u06df\u06e6";  // 原 0x005d：hash("ۜ۟ۦ")=1743811
            state = ReflectBridgeB.hashCode(v12);  // 原 0x005f-0x0067
        }

        // 原 0x0045-0x004c：findClass(target, null) -> hookAllConstructors(class, hook)
        Object clazz = ReflectBridgeB.findClass(target, null);        // 原 0x0045 method@0061
        ReflectBridgeB.hookAllConstructors(clazz, hook);              // 原 0x0049 method@0066
        // 原 0x004c：return-void
        ModuleLogger.log("WxModuleHook-> init done");  // 日志（ModuleLogger 内部拼前缀）
    }
}
