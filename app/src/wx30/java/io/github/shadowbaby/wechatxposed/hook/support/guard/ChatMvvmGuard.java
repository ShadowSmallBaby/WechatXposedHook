package io.github.shadowbaby.wechatxposed.hook.support.guard;

import io.github.shadowbaby.wechatxposed.shared.hook.HookCallback;
import io.github.shadowbaby.wechatxposed.shared.hook.HookFramework;
import io.github.shadowbaby.wechatxposed.shared.hook.HookParam;
import io.github.shadowbaby.wechatxposed.hook.loader.SecretConstants;
import io.github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import io.github.shadowbaby.wechatxposed.hook.loader.util.Secret;
import java.lang.reflect.Method;

public final class ChatMvvmGuard {

    private static final String LOAD_DATA_CONFIG = "RepairerConfigChatLoadDataUseMvvm";

    private static final String LIST_CONFIG = "RepairerConfigChatListUseMvvm";

    private static final String CONFIG_HUB =
            Secret.of(SecretConstants.CHAT_CONFIG_HUB_CLASS);
    private static final String CONFIG_GET =
            Secret.of(SecretConstants.CHAT_CONFIG_GET_METHOD);

    private ChatMvvmGuard() {
    }

    private static boolean installed;

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
