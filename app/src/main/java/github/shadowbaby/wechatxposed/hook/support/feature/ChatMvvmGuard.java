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
 * `RepairerConfigChatListUseMvvm` / `RepairerConfigChatLoadDataUseMvvm`。
 * 但 8.0.49 并没有注册 `rb4.q0` 组件，进入
 * `MvvmChatDataController.onLoad` 会直接 NPE（微信侧缺陷）。
 *
 * 这里只对这两个 MVVM 配置返回 0，强制走旧聊天路径；
 * 不影响其他 repairer 配置，也不改版本字段。
 */
public final class ChatMvvmGuard {

    private static final String CONFIG_HUB =
            Secret.of(SecretConstants.CHAT_CONFIG_HUB_CLASS);
    private static final String CONFIG_GET =
            Secret.of(SecretConstants.CHAT_CONFIG_GET_METHOD);

    private ChatMvvmGuard() {
    }

    private static boolean installed;

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
                            if (name.contains("RepairerConfigChat")
                                    && name.contains("Mvvm")) {
                                Object raw = param.result();
                                param.setResult(0);
                                if (!(raw instanceof Integer) || (Integer) raw != 0) {
                                    ModuleLogger.log("chat mvvm guard: raw=" + raw
                                            + " -> 0, " + name);
                                }
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
