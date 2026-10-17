package github.shadowbaby.wechatxposed.hook.loader;

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

}
