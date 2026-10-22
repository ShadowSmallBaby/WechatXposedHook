package github.shadowbaby.wechatxposed.hook.support.feature.version;

import github.shadowbaby.wechatxposed.hook.framework.HookFramework;
import github.shadowbaby.wechatxposed.hook.loader.SecretConstants;
import github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import github.shadowbaby.wechatxposed.hook.loader.util.Secret;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 全局 ClientVersion 的共享窗口。
 *
 * 目标版本与低字节沿用规则在 native（{@link Secret#spoofVersion(int)}）。
 * 当前只有小程序启动场景会临时改全局字段；通话/网络层只读取 real/spoofed。
 */
public final class VersionWindow {

    private static final String CLIENT_VERSION_CLASS =
            Secret.of(SecretConstants.CLIENT_VERSION_CLASS);
    private static final String CLIENT_VERSION_FIELD =
            Secret.of(SecretConstants.CLIENT_VERSION_FIELD);

    private static final AtomicInteger WALLET_DEPTH = new AtomicInteger();

    private static volatile boolean watchdogStarted;
    private static volatile int realClientVersion;
    private static volatile int spoofedClientVersion;
    private static volatile boolean spoofing;
    private static volatile long spoofUntil;

    private VersionWindow() {
    }

    /**
     * 只启动 watchdog，不在这里读取 ClientVersion。
     *
     * install 发生在 handleLoadPackage 阶段，此时微信的 Application Context
     * 还没初始化；提前触发 c64.xe.<clinit> 会因为 sk.q0 拿到 null Context
     * 而抛 ExceptionInInitializerError，直接把宿主带崩。
     * 版本读取推迟到真正需要打开的窗口/请求参数上。
     */
    public static void install(HookFramework framework, ClassLoader classLoader) {
        startWatchdog(framework, classLoader);
    }

    public static int real() {
        return realClientVersion;
    }

    /** 供网络层 hook 使用的公开入口。 */
    public static boolean ensure(HookFramework framework, ClassLoader classLoader) {
        return ensureVersions(framework, classLoader);
    }

    public static int spoofed() {
        return spoofedClientVersion;
    }

    static synchronized boolean ensureVersions(HookFramework framework,
            ClassLoader classLoader) {
        if (realClientVersion != 0) {
            return true;
        }
        // c64.xe 的静态初始化依赖微信 Application Context；
        // 在 handleLoadPackage 阶段读取会把宿主带崩，必须先等 Application 就绪。
        if (!isHostReady()) {
            return false;
        }
        int real = readClientVersion(framework, classLoader);
        if (real == 0) {
            return false;
        }
        realClientVersion = real;
        spoofedClientVersion = Secret.spoofVersion(real);
        if (spoofedClientVersion == 0) {
            ModuleLogger.log("version window: native spoof version unavailable");
            realClientVersion = 0;
            return false;
        }
        ModuleLogger.log("version window: real=0x" + Integer.toHexString(real)
                + " spoofed=0x" + Integer.toHexString(spoofedClientVersion));
        return true;
    }

    public static synchronized boolean open(HookFramework framework, ClassLoader classLoader,
            long durationMs, String kind) {
        if (!ensureVersions(framework, classLoader)) {
            return false;
        }
        long until = System.currentTimeMillis() + durationMs;
        if (until > spoofUntil) {
            spoofUntil = until;
        }
        if (!spoofing) {
            spoofing = true;
            if (WALLET_DEPTH.get() == 0) {
                writeClientVersion(framework, classLoader, spoofedClientVersion);
                ModuleLogger.log("version window open(" + kind + ") clientVersion=0x"
                        + Integer.toHexString(spoofedClientVersion));
            } else {
                ModuleLogger.log("version window open(" + kind + ") deferred in wallet");
            }
        }
        return true;
    }

    /** 钱包/转账页面存活期间恢复真实版本，避免 CGI 使用高版本。 */
    public static boolean isWalletActive() {
        return WALLET_DEPTH.get() > 0;
    }

    public static synchronized void enterWallet(HookFramework framework,
            ClassLoader classLoader) {
        WALLET_DEPTH.incrementAndGet();
        if (realClientVersion != 0) {
            writeClientVersion(framework, classLoader, realClientVersion);
            ModuleLogger.log("version window: wallet enter, real version");
        }
    }

    public static synchronized void exitWallet(HookFramework framework,
            ClassLoader classLoader) {
        if (WALLET_DEPTH.decrementAndGet() > 0) {
            return;
        }
        WALLET_DEPTH.set(0);
        if (spoofing) {
            writeClientVersion(framework, classLoader, spoofedClientVersion);
            ModuleLogger.log("version window: wallet exit, spoofed version");
        }
    }

    /** 缩短当前窗口，只保留收尾时间。 */
    public static synchronized void shorten(long graceMs) {
        if (!spoofing) {
            return;
        }
        long grace = System.currentTimeMillis() + graceMs;
        if (grace < spoofUntil) {
            spoofUntil = grace;
            ModuleLogger.debug("version window grace(" + graceMs + "ms)");
        }
    }

    public static synchronized void close(HookFramework framework, ClassLoader classLoader,
            String reason) {
        if (!spoofing) {
            return;
        }
        spoofing = false;
        writeClientVersion(framework, classLoader, realClientVersion);
        ModuleLogger.log("version window close(" + reason + ") clientVersion=0x"
                + Integer.toHexString(realClientVersion));
    }

    private static void startWatchdog(HookFramework framework, ClassLoader classLoader) {
        if (watchdogStarted) {
            return;
        }
        watchdogStarted = true;
        Thread thread = new Thread(() -> {
            while (true) {
                try {
                    Thread.sleep(1000L);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    return;
                }
                if (spoofing && System.currentTimeMillis() > spoofUntil) {
                    close(framework, classLoader, "watchdog");
                }
            }
        }, "wxh-version-window");
        thread.setDaemon(true);
        thread.start();
    }

    private static boolean isHostReady() {
        try {
            Class<?> activityThread = Class.forName("android.app.ActivityThread");
            Method current = activityThread.getDeclaredMethod("currentApplication");
            return current.invoke(null) != null;
        } catch (Throwable ignored) {
            // API 不可用时不要阻塞：后续路径本身发生在进程启动之后。
            return true;
        }
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
}
