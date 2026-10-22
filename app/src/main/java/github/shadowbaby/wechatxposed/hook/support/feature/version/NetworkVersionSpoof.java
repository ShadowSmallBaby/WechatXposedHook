package github.shadowbaby.wechatxposed.hook.support.feature.version;

import github.shadowbaby.wechatxposed.hook.framework.HookCallback;
import github.shadowbaby.wechatxposed.hook.framework.HookFramework;
import github.shadowbaby.wechatxposed.hook.framework.HookParam;
import github.shadowbaby.wechatxposed.hook.loader.SecretConstants;
import github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import github.shadowbaby.wechatxposed.hook.loader.util.Secret;
import java.lang.reflect.Method;

/**
 * 网络层版本伪装（最终最小作用域）。
 *
 * - 启动期只伪装 getonlineinfo，命中后 2 秒关闭；
 * - 通话期只伪装 voipilink 链路；
 * - 小程序只伪装 launchwxaapp；
 * - 钱包/转账/红包整体保持真实。
 *
 * URI 白名单与目标版本都在 native（spoof_tables.inc），Java 只负责时机。
 */
public final class NetworkVersionSpoof {

    private static final String BASE_REQUEST_FILLER =
            Secret.of(SecretConstants.BASE_REQUEST_FILLER_CLASS);
    private static final String BASE_REQUEST_FILL =
            Secret.of(SecretConstants.BASE_REQUEST_FILL_METHOD);
    private static final String BASE_REQUEST_SET_VERSION =
            Secret.of(SecretConstants.BASE_REQUEST_SET_VERSION_METHOD);

    private static final long STARTUP_WINDOW_MS = 20_000L;
    private static final long STARTUP_AFTER_HIT_MS = 2_000L;
    private static volatile long startupUntil;
    private static volatile boolean callActive;

    private NetworkVersionSpoof() {
    }

    public static void install(HookFramework framework, ClassLoader classLoader) {
        startupUntil = System.currentTimeMillis() + STARTUP_WINDOW_MS;
        hookBaseRequest(framework, classLoader);
        hookCallUi(framework, classLoader,
                "com.tencent.mm.plugin.voip.ui.VideoActivity");
        hookCallUi(framework, classLoader,
                "com.tencent.mm.plugin.voip.ui.VoiceActivity");
    }

    private static void hookBaseRequest(HookFramework framework,
            ClassLoader classLoader) {
        try {
            Class<?> target = framework.findClassIfExists(BASE_REQUEST_FILLER, classLoader);
            if (target == null) {
                ModuleLogger.log("network version: base filler missing");
                return;
            }
            for (Method method : target.getDeclaredMethods()) {
                if (!BASE_REQUEST_FILL.equals(method.getName())
                        || method.getParameterCount() != 2) {
                    continue;
                }
                framework.hookMethod(method, new HookCallback() {
                    @Override
                    public void after(HookParam param) {
                        spoofRequest(framework, classLoader, param);
                    }
                });
                ModuleLogger.log("network version: base request hooked");
            }
        } catch (Throwable error) {
            ModuleLogger.log(error);
        }
    }

    private static void hookCallUi(HookFramework framework, ClassLoader classLoader,
            String className) {
        try {
            Class<?> target = framework.findClassIfExists(className, classLoader);
            if (target == null) {
                return;
            }
            framework.hookMethod(target, "onCreate",
                    new Class<?>[]{android.os.Bundle.class}, new HookCallback() {
                        @Override
                        public void before(HookParam param) {
                            callActive = true;
                        }
                    });
            framework.hookMethod(target, "onDestroy", new Class<?>[]{},
                    new HookCallback() {
                        @Override
                        public void after(HookParam param) {
                            callActive = false;
                            ModuleLogger.log("call context: off (ui)");
                        }
                    });
            ModuleLogger.log("network version: call ui hooked " + className);
        } catch (Throwable error) {
            ModuleLogger.log(error);
        }
    }

    private static void spoofRequest(HookFramework framework, ClassLoader classLoader,
            HookParam param) {
        Object request = param.arg(0);
        if (request == null) {
            return;
        }
        Object scene = param.arg(1);
        String uri = uriOf(framework, scene);
        String className = scene == null ? "" : scene.getClass().getName();
        boolean startup = System.currentTimeMillis() <= startupUntil;
        boolean miniProgram = Secret.hintMatch(Secret.HINT_MINI_PROGRAM, uri);
        boolean callStart = Secret.hintMatch(Secret.HINT_CALL_START, uri);

        if (callStart && !callActive) {
            callActive = true;
            ModuleLogger.log("call context: on " + uri);
        }
        if (startup) {
            if (!callActive && !miniProgram
                    && !Secret.hintMatch(Secret.HINT_STARTUP, uri)) {
                return;
            }
            if (Secret.hintMatch(Secret.HINT_STARTUP, uri)) {
                long shortened = System.currentTimeMillis() + STARTUP_AFTER_HIT_MS;
                if (shortened < startupUntil) {
                    startupUntil = shortened;
                    ModuleLogger.log("startup window: hit " + uri
                            + ", close in " + STARTUP_AFTER_HIT_MS + "ms");
                }
            }
        } else if (!callActive && !miniProgram) {
            return;
        }

        if (!startup && callActive
                && !Secret.hintMatch(Secret.HINT_CALL, uri) && !miniProgram) {
            return;
        }
        if (!VersionWindow.ensure(framework, classLoader)) {
            return;
        }
        if (VersionWindow.isWalletActive()
                || Secret.hintMatch(Secret.HINT_WALLET_URI, uri)
                || Secret.hintMatch(Secret.HINT_WALLET_CLASS, className)) {
            return;
        }
        try {
            framework.callMethod(request, BASE_REQUEST_SET_VERSION,
                    VersionWindow.spoofed());
            if (Secret.hintMatch(Secret.HINT_CALL_SHUTDOWN, uri)) {
                callActive = false;
                ModuleLogger.log("call context: off (shutdown)");
            }
        } catch (Throwable error) {
            ModuleLogger.log(error);
        }
    }

    private static String uriOf(HookFramework framework, Object scene) {
        if (scene == null) {
            return "";
        }
        try {
            Object uri = framework.callMethod(scene, "getUri");
            return uri instanceof String ? (String) uri : "";
        } catch (Throwable ignored) {
            return "";
        }
    }
}
