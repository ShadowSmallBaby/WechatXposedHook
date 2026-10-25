package github.shadowbaby.wechatxposed.hook.loader.util;

import github.shadowbaby.wechatxposed.hook.BuildConfig;
import github.shadowbaby.wechatxposed.hook.framework.HookFramework;
import java.io.Serializable;

public abstract class ModuleLogger {

    private static final String LOG_PREFIX = "WeXposedHook-> ";

    public static final String HOST_SPOOF_PREFIX = "host spoof: ";

    private static volatile HookFramework framework;

    public static void attach(HookFramework target) {
        framework = target;
    }

    public static void log(Serializable message) {
        HookFramework target = framework;
        if (target == null) {
            return;
        }
        if (message instanceof Throwable) {
            target.log((Throwable) message);
        } else {
            target.log(LOG_PREFIX + message);
        }
    }

    /**
     * 过程日志。开关跟 debuggable 解耦：debug 变体为了通过壳的检查把 debuggable
     * 关掉了，那会连带让 BuildConfig.DEBUG 变 false，所以单独用 VERBOSE_LOG。
     */
    public static void debug(Serializable message) {
        if (!BuildConfig.VERBOSE_LOG) {
            return;
        }
        log(message);
    }

}
