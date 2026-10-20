package github.shadowbaby.wechatxposed.hook.support;

import github.shadowbaby.wechatxposed.hook.framework.HookCallback;
import github.shadowbaby.wechatxposed.hook.framework.HookFramework;
import github.shadowbaby.wechatxposed.hook.framework.HookParam;
import github.shadowbaby.wechatxposed.hook.loader.ModuleLogger;
import github.shadowbaby.wechatxposed.hook.loader.Secret;
import github.shadowbaby.wechatxposed.hook.loader.SecretConstants;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 宿主版本伪装（最小窗口 + 参数级）。
 *
 * 1. 小程序：启动 CGI 和随后的资源准备请求都在发送时读取全局 ClientVersion，
 *    Java 层没有可参数级替换的入口，所以只在启动后的 5 秒窗口内临时改高，
 *    watchdog 兜底还原。窗口外不影响公众号/钱包。
 * 2. 通话：ilink SDK 启动配置的 appVersion 是参数级的，只替换该参数，
 *    全局字段完全不动。
 */
public final class HostVersionSpoof {

    /** 小程序启动 CGI 场景（WeChat 8.0.49）。 */
    private static final String LAUNCH_SCENE_CLASS = "wx0.d";

    /** ilink SDK 启动配置：appVersion 在建链时上报给服务端。 */
    private static final String ILINK_START_CONFIG =
            "com.tencent.ilink.network.Proto$IlinkStartConfig$Builder";
    private static final String ILINK_SET_APP_VERSION = "setAppVersion";

    private static final int CLIENT_VERSION_HIGH_MASK = 0xFFFFFF00;
    private static final int CLIENT_VERSION_LOW_MASK = 0x000000FF;
    private static final int SPOOF_CLIENT_VERSION_HIGH = 0x28004F00;

    /** 启动请求的兜底上限。 */
    private static final long LAUNCH_WINDOW_MS = 10000L;

    /** 启动 CGI 回调后再保留的收尾时间。 */
    private static final long LAUNCH_GRACE_MS = 1500L;

    private static final String CLIENT_VERSION_CLASS =
            Secret.of(SecretConstants.CLIENT_VERSION_CLASS);
    private static final String CLIENT_VERSION_FIELD =
            Secret.of(SecretConstants.CLIENT_VERSION_FIELD);

    private static final ThreadLocal<Boolean> INTERNAL =
            ThreadLocal.withInitial(() -> Boolean.FALSE);
    private static final AtomicInteger LOGS = new AtomicInteger();

    private static volatile boolean installed;
    private static volatile int realClientVersion;
    private static volatile int spoofedClientVersion;
    private static volatile boolean spoofing;
    private static volatile long spoofUntil;

    private HostVersionSpoof() {
    }

    public static synchronized void install(HookFramework framework, ClassLoader classLoader,
            String dataDir, boolean mainProcess) {
        if (installed || !mainProcess) {
            return;
        }
        installed = true;
        startWatchdog(framework, classLoader);
        hookLaunchScene(framework, classLoader);
        hookIlinkStartConfig(framework, classLoader);
    }

    private static void hookLaunchScene(HookFramework framework, ClassLoader classLoader) {
        try {
            Class<?> target = framework.findClassIfExists(LAUNCH_SCENE_CLASS, classLoader);
            if (target == null) {
                ModuleLogger.debug("version window: launch scene not found");
                return;
            }
            for (Constructor<?> constructor : target.getDeclaredConstructors()) {
                framework.hookMethod(constructor, new HookCallback() {
                    @Override
                    public void before(HookParam param) {
                        openWindow(framework, classLoader);
                    }
                });
            }
            for (Method method : target.getDeclaredMethods()) {
                if ("f".equals(method.getName()) && method.getParameterCount() == 5) {
                    framework.hookMethod(method, new HookCallback() {
                        @Override
                        public void after(HookParam param) {
                            shortenWindow();
                        }
                    });
                }
            }
            ModuleLogger.debug("version window: launch scene hooked");
        } catch (Throwable error) {
            ModuleLogger.log(error);
        }
    }

    private static void hookIlinkStartConfig(HookFramework framework, ClassLoader classLoader) {
        try {
            Class<?> target = framework.findClassIfExists(ILINK_START_CONFIG, classLoader);
            if (target == null) {
                ModuleLogger.debug("version window: ilink config not found");
                return;
            }
            for (Method method : target.getDeclaredMethods()) {
                if (ILINK_SET_APP_VERSION.equals(method.getName())
                        && method.getParameterCount() == 1
                        && method.getParameterTypes()[0] == Integer.TYPE) {
                    framework.hookMethod(method, new AppVersion(framework, classLoader));
                    ModuleLogger.debug("version window: ilink appVersion hooked");
                }
            }
        } catch (Throwable error) {
            ModuleLogger.log(error);
        }
    }

    private static void startWatchdog(HookFramework framework, ClassLoader classLoader) {
        Thread thread = new Thread(() -> {
            while (true) {
                try {
                    Thread.sleep(1000L);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    return;
                }
                if (spoofing && System.currentTimeMillis() > spoofUntil) {
                    closeWindow(framework, classLoader, "watchdog");
                }
            }
        }, "wxh-version-window");
        thread.setDaemon(true);
        thread.start();
    }

    private static synchronized void openWindow(HookFramework framework, ClassLoader classLoader) {
        if (!ensureVersions(framework, classLoader)) {
            return;
        }
        long until = System.currentTimeMillis() + LAUNCH_WINDOW_MS;
        if (until > spoofUntil) {
            spoofUntil = until;
        }
        if (!spoofing) {
            spoofing = true;
            writeClientVersion(framework, classLoader, spoofedClientVersion);
            ModuleLogger.debug("version window open(launch)");
        }
    }

    /** 启动 CGI 回调后只保留收尾时间，避免固定等满上限。 */
    private static synchronized void shortenWindow() {
        if (!spoofing) {
            return;
        }
        long grace = System.currentTimeMillis() + LAUNCH_GRACE_MS;
        if (grace < spoofUntil) {
            spoofUntil = grace;
            ModuleLogger.debug("version window grace(" + LAUNCH_GRACE_MS + "ms)");
        }
    }

    private static synchronized void closeWindow(HookFramework framework, ClassLoader classLoader,
            String reason) {
        if (!spoofing) {
            return;
        }
        spoofing = false;
        writeClientVersion(framework, classLoader, realClientVersion);
        ModuleLogger.debug("version window close(" + reason + ")");
    }

    private static synchronized boolean ensureVersions(HookFramework framework,
            ClassLoader classLoader) {
        if (realClientVersion != 0) {
            return true;
        }
        int real = readClientVersion(framework, classLoader);
        if (real == 0) {
            return false;
        }
        realClientVersion = real;
        spoofedClientVersion = (SPOOF_CLIENT_VERSION_HIGH & CLIENT_VERSION_HIGH_MASK)
                | (real & CLIENT_VERSION_LOW_MASK);
        return true;
    }

    private static int readClientVersion(HookFramework framework, ClassLoader classLoader) {
        try {
            Class<?> target = framework.findClassIfExists(CLIENT_VERSION_CLASS, classLoader);
            if (target == null) {
                return 0;
            }
            Field field = target.getDeclaredField(CLIENT_VERSION_FIELD);
            field.setAccessible(true);
            return field.getInt(null);
        } catch (Throwable error) {
            ModuleLogger.log(error);
            return 0;
        }
    }

    private static void writeClientVersion(HookFramework framework, ClassLoader classLoader,
            int value) {
        if (value == 0) {
            return;
        }
        try {
            Class<?> target = framework.findClassIfExists(CLIENT_VERSION_CLASS, classLoader);
            if (target == null) {
                return;
            }
            Field field = target.getDeclaredField(CLIENT_VERSION_FIELD);
            field.setAccessible(true);
            field.setInt(null, value);
        } catch (Throwable error) {
            ModuleLogger.log(error);
        }
    }

    /** 只替换 ilink 启动配置里的 appVersion 参数。 */
    private static final class AppVersion implements HookCallback {

        private final HookFramework framework;
        private final ClassLoader classLoader;

        AppVersion(HookFramework framework, ClassLoader classLoader) {
            this.framework = framework;
            this.classLoader = classLoader;
        }

        @Override
        public void before(HookParam param) {
            if (Boolean.TRUE.equals(INTERNAL.get())) {
                return;
            }
            if (!ensureVersions(framework, classLoader)) {
                return;
            }
            Object value = param.arg(0);
            if (!(value instanceof Integer version) || version != realClientVersion) {
                return;
            }
            try {
                INTERNAL.set(Boolean.TRUE);
                Object result = framework.callMethod(param.thisObject(),
                        ILINK_SET_APP_VERSION, spoofedClientVersion);
                param.setResult(result);
                if (LOGS.incrementAndGet() <= 3) {
                    ModuleLogger.log("version window: ilink appVersion -> 0x"
                            + Integer.toHexString(spoofedClientVersion));
                }
            } catch (Throwable error) {
                ModuleLogger.log(error);
            } finally {
                INTERNAL.set(Boolean.FALSE);
            }
        }
    }
}
