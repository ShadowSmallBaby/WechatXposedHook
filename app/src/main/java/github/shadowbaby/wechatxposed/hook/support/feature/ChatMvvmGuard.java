package github.shadowbaby.wechatxposed.hook.support.feature;

import github.shadowbaby.wechatxposed.hook.framework.HookCallback;
import github.shadowbaby.wechatxposed.hook.framework.HookFramework;
import github.shadowbaby.wechatxposed.hook.framework.HookParam;
import github.shadowbaby.wechatxposed.hook.loader.SecretConstants;
import github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import github.shadowbaby.wechatxposed.hook.loader.util.Secret;
import java.lang.reflect.Method;

/**
 * 8.0.49 聊天 MVVM 兼容守卫。
 *
 * 服务端可能因为客户端版本被抬高而下发
 * `RepairerConfigChatLoadDataUseMvvm`，但 8.0.49 并没有注册 `rb4.q0` 组件，
 * 进入 `MvvmChatDataController.onLoad` 会直接 NPE（微信侧缺陷）。
 * 这里只对这一项返回 0，保留旧聊天加载路径。
 *
 * 注意：`RepairerConfigChatListUseMvvm` 必须放行。它控制的是会话列表数据层，
 * 8.0.49 原生支持；压回 0 会让会话列表退回旧的同步 DB 路径
 * （主线程 SQLiteCursor.getCount → fillWindow 全窗加载），
 * 在大库设备上引发 LauncherUI 输入超时 ANR，且并不能规避上面的聊天界面崩溃。
 */
public final class ChatMvvmGuard {

    /** 只有聊天数据加载的 MVVM 开关会导致 `rb4.q0` NPE，按类名尾缀精确匹配。 */
    private static final String LOAD_DATA_CONFIG = "RepairerConfigChatLoadDataUseMvvm";

    /** 会话列表 MVVM 开关，放行。 */
    private static final String LIST_CONFIG = "RepairerConfigChatListUseMvvm";

    private static final String CONFIG_HUB =
            Secret.of(SecretConstants.CHAT_CONFIG_HUB_CLASS);
    private static final String CONFIG_GET =
            Secret.of(SecretConstants.CHAT_CONFIG_GET_METHOD);

    private ChatMvvmGuard() {
    }

    private static boolean installed;

    /** 放行日志只打前几条，避免高频配置读取刷屏。 */
    private static final java.util.concurrent.atomic.AtomicInteger PASS_LOGS =
            new java.util.concurrent.atomic.AtomicInteger();

    public static synchronized void install(HookFramework framework, ClassLoader classLoader) {
        if (installed) {
            return;
        }
        try {
            Class<?> hub = framework.findClassIfExists(CONFIG_HUB, classLoader);
            if (hub == null) {
                ModuleLogger.log("chat mvvm guard: hub missing");
                return;
            }
            for (Method method : hub.getDeclaredMethods()) {
                if (CONFIG_GET.equals(method.getName())
                        && method.getParameterCount() == 1
                        && method.getReturnType() == Integer.TYPE) {
                    framework.hookMethod(method, new HookCallback() {
                        @Override
                        public void after(HookParam param) {
                            Object config = param.arg(0);
                            if (config == null) {
                                return;
                            }
                            String name = config.getClass().getName();
                            if (name.endsWith(LOAD_DATA_CONFIG)) {
                                Object raw = param.result();
                                param.setResult(0);
                                if (!(raw instanceof Integer) || (Integer) raw != 0) {
                                    ModuleLogger.log("chat mvvm guard: raw=" + raw
                                            + " -> 0, " + name);
                                }
                            } else if (name.endsWith(LIST_CONFIG)
                                    && PASS_LOGS.incrementAndGet() <= 3) {
                                ModuleLogger.log("chat mvvm guard: pass " + name
                                        + " raw=" + param.result());
                            }
                        }
                    });
                    ModuleLogger.log("chat mvvm guard: hooked");
                    installed = true;
                }
            }
        } catch (Throwable error) {
            ModuleLogger.log(error);
        }
    }
}
