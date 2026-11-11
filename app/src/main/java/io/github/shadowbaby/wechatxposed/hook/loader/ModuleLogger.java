package io.github.shadowbaby.wechatxposed.hook.loader;

import io.github.shadowbaby.wechatxposed.shared.hook.HookFramework;
import java.io.Serializable;

public abstract class ModuleLogger {

    private static final String LOG_PREFIX = "WeXposedHook-> ";

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
