package github.shadowbaby.wechatxposed.hook.rebuild.loader;

import java.io.File;
import java.io.Serializable;
import github.shadowbaby.wechatxposed.hook.rebuild.support.ReflectBridgeA;
import github.shadowbaby.wechatxposed.hook.rebuild.support.ReflectBridgeB;

/**
 * 重建源码：b.b —— 日志工具
 *
 * 原始结构（由 dexdump b.b.a / b.b.<clinit> 逐指令还原）：
 *
 *   <clinit>：
 *     1. 构造字符串池 ۬ۦۛ（129 个 short，本类 LOG_POOL）
 *     2. 控制流平坦化状态机（m33() 恒真 / m82() 恒 0 的诱饵分支），
 *        实际执行一段 best-effort 环境探测，整体被 try/catch 包裹：
 *          Class at = findClass("android.app.ActivityThread", null)
 *          Object thread = callStaticMethod(at, "currentActivityThread", {})
 *          Object sysCtx = callMethod(thread, "getSystemContext", {})
 *          Context pkg  = createPackageContext(sysCtx, "com.tencent.mm", 0)   // catch NameNotFound
 *          File dir     = getFilesDir(pkg)                                    // catch NameNotFound
 *          File probe   = new File(dir, decodeXor(LOG_POOL, 62, 4, 48914))    // "_wx_"
 *        探测结果未被保存，仅用于（在微信进程内）校验环境可达性；失败时静默忽略。
 *
 *   a(Serializable) —— 唯一对外行为：
 *          if (msg instanceof Throwable)
 *              XposedBridge.log((Throwable) msg);                 // ReflectBridgeA.logThrowable
 *          else
 *              XposedBridge.log("WxModuleHook-> " + msg);          // ReflectBridgeA.logString
 *        其中前缀 = decodeXor(LOG_POOL, 114, 15, 17712) = "WxModuleHook-> "
 *
 * 池中关键片段（key=48914 文件定位段 / key=17712 日志前缀段）：
 *   1..26   "android.app.ActivityThread"
 *   27..47  "currentActivityThread"
 *   48..61  "com.tencent.mm"
 *   62..65  "_wx_"
 *   97..112 "getSystemContext"
 *   114..128 "WxModuleHook-> "
 */
public abstract class ModuleLogger {

    /** 原 ۬ۦۛ: [S —— 129 项字符串池 */
    private static final short[] LOG_POOL = {
            3114, -16525, -16516, -16522, -16544, -16515, -16517, -16522, -16580, -16525, -16542, -16542,
            -16580, -16557, -16527, -16538, -16517, -16540, -16517, -16538, -16533, -16570, -16518, -16544,
            -16521, -16525, -16522, -16527, -16537, -16544, -16544, -16521, -16516, -16538, -16557, -16527,
            -16538, -16517, -16540, -16517, -16538, -16533, -16570, -16518, -16544, -16521, -16525, -16522,
            -16527, -16515, -16513, -16580, -16538, -16521, -16516, -16527, -16521, -16516, -16538, -16580,
            -16513, -16513, -16563, -16539, -16534, -16563, -16579, -16522, -16525, -16538, -16525, -16579,
            -16522, -16525, -16538, -16525, -16579, -16527, -16515, -16513, -16580, -16538, -16521, -16516,
            -16527, -16521, -16516, -16538, -16580, -16513, -16513, -16579, -16524, -16517, -16514, -16521,
            -16543, -16523, -16521, -16538, -16575, -16533, -16543, -16538, -16521, -16513, -16559, -16515,
            -16516, -16538, -16521, -16534, -16538, 8283, 17767, 17736, 17789, 17759, 17748, 17733,
            17756, 17749, 17784, 17759, 17759, 17755, 17693, 17678, 17680
    };

    static {
        // 原 <clinit> 的 best-effort 环境探测（整体 try/catch，失败静默）
        try {
            Class<?> at = ReflectBridgeB.findClass("android.app.ActivityThread", null);
            Object thread = ReflectBridgeB.callStaticMethod(at, "currentActivityThread", new Object[0]);
            Object sysCtx = ReflectBridgeB.callMethod(thread, "getSystemContext", new Object[0]);
            try {
                Object pkg = ReflectBridgeB.createPackageContext(sysCtx, "com.tencent.mm", 0);
                File dir = ReflectBridgeB.getFilesDir(pkg);
                File probe = new File(dir, ReflectBridgeB.decodeXor(LOG_POOL, 62, 4, 48914));
            } catch (android.content.pm.PackageManager.NameNotFoundException ignored) {
            }
        } catch (Throwable ignored) {
        }
    }

    /** 原 b.b.a(Serializable) */
    public static void log(Serializable msg) {
        if (msg instanceof Throwable) {
            ReflectBridgeA.logThrowable(msg);
            return;
        }
        StringBuilder sb = new StringBuilder(ReflectBridgeB.decodeXor(LOG_POOL, 114, 15, 17712));
        ReflectBridgeB.appendObject(sb, msg);
        ReflectBridgeA.logString(ReflectBridgeB.toString(sb));
    }
}
