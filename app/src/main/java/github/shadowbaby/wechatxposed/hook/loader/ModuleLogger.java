package github.shadowbaby.wechatxposed.hook.loader;

import de.robv.android.xposed.XposedBridge;
import java.io.Serializable;

/**
 * 模块日志。
 *
 * 日志正文一律用英文、尽量短:日志是给排查问题看的,不是给用户看的。
 *
 * 字符串池对照见 docs/StringPools.java。
 */
public abstract class ModuleLogger {

    private static final String LOG_PREFIX = "WeXposedHook-> ";

    /** 输出一条日志;Throwable 直接交给 XposedBridge,其余加前缀。 */
    public static void log(Serializable message) {
        if (message instanceof Throwable) {
            XposedBridge.log((Throwable) message);
        } else {
            XposedBridge.log(LOG_PREFIX + message);
        }
    }

}
