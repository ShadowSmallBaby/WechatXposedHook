package io.github.shadowbaby.wechatxposed.tool.hook.guard;

import io.github.shadowbaby.wechatxposed.shared.hook.HookCallback;
import io.github.shadowbaby.wechatxposed.shared.hook.HookFramework;
import io.github.shadowbaby.wechatxposed.shared.hook.HookParam;
import io.github.shadowbaby.wechatxposed.tool.hook.framework.ToolLogger;
import io.github.shadowbaby.wechatxposed.tool.hook.spoof.SpoofProfile;
import io.github.shadowbaby.wechatxposed.tool.hook.spoof.SpoofProfiles;

import java.lang.reflect.Method;

import static io.github.shadowbaby.wechatxposed.tool.hook.spoof.HostFingerprint.fp;
import static io.github.shadowbaby.wechatxposed.tool.hook.spoof.HostFingerprint.fpInt;


public final class ChatMvvmGuard {

    private static final String LOAD_DATA_CONFIG = fp("guard.chat.mvvm.loadDataConfig.repairerConfigChatLoadDataUseMvvm");
    private static final String LIST_CONFIG = fp("guard.chat.mvvm.listConfig.repairerConfigChatListUseMvvm");

    private static boolean installed;

    private static final java.util.concurrent.atomic.AtomicInteger PASS_LOGS =
            new java.util.concurrent.atomic.AtomicInteger();

    private ChatMvvmGuard() {
    }

    public static synchronized void install(HookFramework framework, ClassLoader classLoader) {
        if (installed) {
            return;
        }
        try {
            SpoofProfile profile = SpoofProfiles.current();
            Class<?> hub = framework.findClassIfExists(profile.chatConfigHub, classLoader);
            if (hub == null) {
                ToolLogger.log("chat mvvm guard: hub missing " + profile.chatConfigHub);
                return;
            }
            for (Method method : hub.getDeclaredMethods()) {
                if (profile.chatConfigGet.equals(method.getName())
                        && method.getParameterCount() == fpInt("guard.chat.mvvm.install.first")
                        && method.getReturnType() == Integer.TYPE) {
                    framework.hookMethod(method, new HookCallback() {
                        @Override
                        public void after(HookParam param) {
                            Object config = param.arg(fpInt("guard.chat.mvvm.config.zero"));
                            if (config == null) {
                                return;
                            }
                            String name = config.getClass().getName();
                            if (name.endsWith(LOAD_DATA_CONFIG)) {
                                Object raw = param.result();
                                param.setResult(0);
                                if (!(raw instanceof Integer) || (Integer) raw != 0) {
                                    ToolLogger.log("chat mvvm guard: raw=" + raw
                                            + " -> 0, " + name);
                                }
                            } else if (name.endsWith(LIST_CONFIG)
                                    && PASS_LOGS.incrementAndGet() <= 3) {
                                ToolLogger.debug("chat mvvm guard: pass " + name
                                        + " raw=" + param.result());
                            }
                        }
                    });
                    ToolLogger.log("chat mvvm guard: hooked");
                    installed = true;
                }
            }
        } catch (Throwable error) {
            ToolLogger.log(error);
        }
    }
}
