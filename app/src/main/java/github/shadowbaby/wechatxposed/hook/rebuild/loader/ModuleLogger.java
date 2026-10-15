package github.shadowbaby.wechatxposed.hook.rebuild.loader;

import android.content.Context;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import java.io.File;
import java.io.Serializable;

/**
 * 模块日志。
 *
 * 类加载时做两件事:
 *   1. 反射 ActivityThread 取系统 Context,再 createPackageContext("com.tencent.mm"),
 *      在 /data/data/com.tencent.mm/files 下定位 "_wx_" 探针。探测结果不参与任何逻辑,
 *      只为确认模块跑在微信进程里;任何失败都静默忽略。
 *   2. 字符串池对照见 docs/StringPools.java。
 */
public abstract class ModuleLogger {

    private static final String ACTIVITY_THREAD_CLASS = "android.app.ActivityThread";
    private static final String CURRENT_ACTIVITY_THREAD = "currentActivityThread";
    private static final String WECHAT_PACKAGE = "com.tencent.mm";
    private static final String PROBE_FILE_NAME = "_wx_";
    private static final String GET_SYSTEM_CONTEXT = "getSystemContext";
    private static final String LOG_PREFIX = "WxModuleHook-> ";

    static {
        probeWeChatEnvironment();
    }

    /** 环境探测;不在微信进程内或隐藏 API 不可用时静默跳过。 */
    private static void probeWeChatEnvironment() {
        try {
            Class<?> activityThread = XposedHelpers.findClass(ACTIVITY_THREAD_CLASS, null);
            Object thread = XposedHelpers.callStaticMethod(activityThread, CURRENT_ACTIVITY_THREAD);
            Context systemContext = (Context) XposedHelpers.callMethod(thread, GET_SYSTEM_CONTEXT);
            Context weChat = systemContext.createPackageContext(WECHAT_PACKAGE, 0);
            new File(weChat.getFilesDir(), PROBE_FILE_NAME);
        } catch (Throwable ignored) {
            // 探测结果不参与任何逻辑,失败即跳过。
        }
    }

    /** 输出一条日志;Throwable 直接交给 XposedBridge,其余加前缀。 */
    public static void log(Serializable message) {
        if (message instanceof Throwable) {
            XposedBridge.log((Throwable) message);
        } else {
            XposedBridge.log(LOG_PREFIX + message);
        }
    }

}