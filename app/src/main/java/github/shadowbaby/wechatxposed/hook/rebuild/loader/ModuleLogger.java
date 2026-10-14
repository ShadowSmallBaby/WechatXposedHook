package github.shadowbaby.wechatxposed.hook.rebuild.loader;

import android.content.Context;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import java.io.File;
import java.io.Serializable;
import github.shadowbaby.wechatxposed.hook.rebuild.XorStrings;

/**
 * 模块日志(原混淆类 b.b)。
 *
 * 原始 <clinit> 做两件事:
 *   1. 反射 ActivityThread 取系统 Context,再 createPackageContext("com.tencent.mm"),
 *      定位 /data/data/com.tencent.mm/files 下的 "_wx_" 探针。探测结果从未被使用,
 *      目的只是确认模块跑在微信进程里;任何失败都静默忽略。
 *   2. 构造下方字符串池,日志前缀由 LOG_POOL[114..129) ^ 17712 还原。
 */
public abstract class ModuleLogger {

    /** 原 b.b.<clinit> 的字符池:偏移 1..113 用 key=48914(环境探测),114..129 用 key=17712(日志前缀)。 */
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

    private static final int ENVIRONMENT_KEY = 48914;
    private static final int PREFIX_KEY = 17712;

    private static final String ACTIVITY_THREAD_CLASS = decode(1, 26, ENVIRONMENT_KEY);
    private static final String CURRENT_ACTIVITY_THREAD = decode(27, 21, ENVIRONMENT_KEY);
    private static final String WECHAT_PACKAGE = decode(48, 14, ENVIRONMENT_KEY);
    private static final String PROBE_FILE_NAME = decode(62, 4, ENVIRONMENT_KEY);
    private static final String GET_SYSTEM_CONTEXT = decode(97, 16, ENVIRONMENT_KEY);
    private static final String LOG_PREFIX = decode(114, 15, PREFIX_KEY);

    static {
        probeWeChatEnvironment();
    }

    /** 原 <clinit> 的环境探测;不在微信进程内或隐藏 API 不可用时静默跳过。 */
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

    /** 原 b.b.a(Serializable)。 */
    public static void log(Serializable message) {
        if (message instanceof Throwable) {
            XposedBridge.log((Throwable) message);
        } else {
            XposedBridge.log(LOG_PREFIX + message);
        }
    }

    private static String decode(int offset, int length, int key) {
        return XorStrings.decode(LOG_POOL, offset, length, key);
    }
}