package github.shadowbaby.wechatxposed.hook.support.feature.version;

import github.shadowbaby.wechatxposed.hook.framework.HookCallback;
import github.shadowbaby.wechatxposed.hook.framework.HookFramework;
import github.shadowbaby.wechatxposed.hook.framework.HookParam;
import github.shadowbaby.wechatxposed.hook.loader.SecretConstants;
import github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import github.shadowbaby.wechatxposed.hook.loader.util.Secret;
import java.lang.reflect.Method;

/**
 * 网络层版本伪装（最小作用域）。
 *
 * - 启动期只伪装 getonlineinfo，命中后 2 秒关闭；
 * - 通话期只伪装 voipilink 链路；
 * - 小程序只伪装 launchwxaapp；
 * - 登录 CGI（manualauth / autoauth / h5auth / disasterauth）单独伪装：
 *   这些请求是标准协议，BaseRequest.clientVersion 明文可写，
 *   不伪装会弹「当前客户端版本过低」。
 * - 钱包/转账/红包整体保持真实。
 *
 * URI 白名单与目标版本都在 native（spoof_tables.inc），Java 只负责时机。
 */
public final class NetworkVersionSpoof {

    private static final String BASE_REQUEST_FILLER =
            Secret.of(SecretConstants.BASE_REQUEST_FILLER_CLASS);
    /** 8.0.79 起 BASE_REQUEST_FILLER 的混淆名变成 l1。 */
    private static final String BASE_REQUEST_FILLER_79 = "com.tencent.mm.modelbase.l1";
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
        for (String name : new String[]{BASE_REQUEST_FILLER, BASE_REQUEST_FILLER_79}) {
            try {
                Class<?> target = framework.findClassIfExists(name, classLoader);
                if (target == null) {
                    ModuleLogger.log("network version: base filler missing " + name);
                    continue;
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
                    ModuleLogger.log("network version: base request hooked " + name);
                }
            } catch (Throwable error) {
                ModuleLogger.log(error);
            }
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
        // 登录链路独立处理：服务端对低版本直接拒绝登录，
        // 且登录通常发生在启动窗口之后，走不到下面的通用分支。
        if (Secret.hintMatch(Secret.HINT_LOGIN, uri)) {
            spoofLogin(framework, classLoader, request, uri);
            return;
        }
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

    /**
     * 登录链路伪装。
     *
     * 直接读请求对象里的真实版本再改成目标版本，不依赖 VersionWindow：
     * 自动登录（secautoauth）早于 Application 就绪，ensure 必然失败。
     */
    private static void spoofLogin(HookFramework framework, ClassLoader classLoader,
            Object request, String uri) {
        int before = readClientVersion(request);
        int real = before;
        int spoofed;
        if (real != 0) {
            spoofed = Secret.spoofVersion(real);
        } else if (VersionWindow.ensure(framework, classLoader)) {
            real = VersionWindow.real();
            spoofed = VersionWindow.spoofed();
        } else {
            ModuleLogger.log("login spoof: no version for " + uri);
            return;
        }
        if (spoofed == 0) {
            ModuleLogger.log("login spoof: spoofVersion failed for " + uri);
            return;
        }
        try {
            framework.callMethod(request, BASE_REQUEST_SET_VERSION, spoofed);
            int after = readClientVersion(request);
            ModuleLogger.log("login spoof: " + uri + " cv 0x"
                    + Integer.toHexString(before) + " -> 0x"
                    + Integer.toHexString(after));
        } catch (Throwable error) {
            ModuleLogger.log(error);
        }
    }

    /** 读 BaseRequest 子类里的 iClientVersion 字段（8.0.49/8.0.79 都叫这个名）。 */
    private static int readClientVersion(Object request) {
        if (request == null) {
            return 0;
        }
        for (Class<?> type = request.getClass(); type != null && type != Object.class;
                type = type.getSuperclass()) {
            try {
                java.lang.reflect.Field field = type.getDeclaredField("iClientVersion");
                field.setAccessible(true);
                return field.getInt(request);
            } catch (NoSuchFieldException missing) {
                continue;
            } catch (Throwable ignored) {
                return 0;
            }
        }
        return 0;
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
