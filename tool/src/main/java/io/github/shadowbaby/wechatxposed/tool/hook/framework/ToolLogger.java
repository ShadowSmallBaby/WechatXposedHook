package io.github.shadowbaby.wechatxposed.tool.hook.framework;
import io.github.shadowbaby.wechatxposed.shared.hook.HookFramework;

import io.github.shadowbaby.wechatxposed.tool.BuildConfig;
import java.io.Serializable;


public abstract class ToolLogger {

    private static final String PREFIX = "WeXposedTool-> ";

    private static volatile HookFramework framework;

    private static volatile boolean verbose = BuildConfig.VERBOSE_LOG;

    public static void attach(HookFramework target) {
        framework = target;
    }

    public static void setVerbose(boolean enabled) {
        verbose = BuildConfig.VERBOSE_LOG || enabled;
    }

    public static void log(Serializable message) {
        HookFramework target = framework;
        if (target == null) {
            return;
        }
        if (message instanceof Throwable) {
            target.log((Throwable) message);
        } else {
            target.log(PREFIX + message);
        }
    }

    public static void debug(Serializable message) {
        if (!verbose) {
            return;
        }
        log(message);
    }
}
