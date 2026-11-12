package io.github.shadowbaby.wechatxposed.hook.framework;

import io.github.shadowbaby.wechatxposed.hook.BuildConfig;
import io.github.shadowbaby.wechatxposed.hook.deploy.ModuleApk;
import io.github.shadowbaby.wechatxposed.hook.deploy.StartupCheck;
import io.github.shadowbaby.wechatxposed.hook.license.Activation;
import io.github.shadowbaby.wechatxposed.hook.loader.SecretConstants;
import io.github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import io.github.shadowbaby.wechatxposed.hook.loader.util.Secret;
import io.github.shadowbaby.wechatxposed.shared.hook.HookFramework;
import java.io.File;

public final class HookBootstrap {

    private static final String WECHAT_PACKAGE = Secret.of(SecretConstants.WECHAT_PACKAGE);

    private static final String[] WECHAT_APPBRAND_PROCESSES = {
            Secret.of(SecretConstants.APPBRAND_0), Secret.of(SecretConstants.APPBRAND_1)};

    private static final PlatformHooks PLATFORM = loadPlatform();

    private static volatile boolean zygoteHooked;

    private static int readyPid = -1;

    private HookBootstrap() {
    }

    private static PlatformHooks loadPlatform() {
        try {
            return (PlatformHooks) Class.forName(BuildConfig.WX_PACK.startsWith("wx6")
                            ? "io.github.shadowbaby.wechatxposed.hook.framework.Wx244Hooks"
                            : "io.github.shadowbaby.wechatxposed.hook.framework.Wx30Hooks")
                    .getDeclaredConstructor().newInstance();
        } catch (Throwable error) {
            throw new IllegalStateException("platform hooks unavailable", error);
        }
    }

    public static void remember(String modulePath) {
        ModuleApk.remember(modulePath);
    }

    public static String prepareShell(HookFramework framework,
            android.content.pm.ApplicationInfo appInfo, String modulePath) {
        return PLATFORM.prepareShell(framework, appInfo, modulePath);
    }

    public static ClassLoader prepareShellLoader(HookFramework framework,
            android.content.pm.ApplicationInfo appInfo, String modulePath) {
        return PLATFORM.prepareShellLoader(framework, appInfo, modulePath);
    }

    public static String shellEntryClass() {
        return PLATFORM.shellEntryClass();
    }

    public static String shellPackage() {
        return PLATFORM.shellPackage();
    }

    public static String settingsHint() {
        return PLATFORM.settingsHint();
    }

    public static synchronized void installZygote(HookFramework framework, String modulePath) {
        ModuleApk.remember(modulePath);
        if (zygoteHooked) {
            return;
        }
        zygoteHooked = true;
        PLATFORM.installZygote(framework, modulePath);
    }

    public static void onProcessReady(HookFramework framework, String packageName,
            String processName, ClassLoader classLoader, String dataDir, String sourceDir) {
        try {
            processReady(framework, packageName, processName,
                    classLoader, dataDir, sourceDir);
        } catch (Throwable error) {
            ModuleLogger.log("bootstrap: " + error);
        }
    }

    private static void processReady(HookFramework framework, String packageName,
            String processName, ClassLoader classLoader, String dataDir, String sourceDir) {
        if (!WECHAT_PACKAGE.equals(packageName)) {
            return;
        }
        synchronized (HookBootstrap.class) {
            int pid = android.os.Process.myPid();
            if (pid == readyPid) {
                return;
            }
            readyPid = pid;
        }
        if (isAppBrandProcess(processName)) {
            return;
        }
        if (WECHAT_PACKAGE.equals(processName) || isUsapLikeProcess(processName)) {
            File data = new File(dataDir);
            Activation.install(data);
            Activation.setHostLoader(classLoader);
            ModuleLogger.log("module " + BuildConfig.VERSION_NAME
                    + " (" + BuildConfig.VERSION_CODE + ")");
            PLATFORM.installEarly(framework, classLoader);
            StartupCheck.run(data, StartupCheck.readLoginAccount(data));
            installZygote(framework, ModuleApk.modulePath());
            PLATFORM.installPackGuards(framework);
            scheduleProbe(5000L);
        }
    }

    private static final java.util.concurrent.atomic.AtomicInteger PROBE_ROUNDS =
            new java.util.concurrent.atomic.AtomicInteger();

    private static final int PROBE_MAX_ROUNDS = 6;

    private static final long PROBE_INTERVAL_MS = 3000L;

    private static void scheduleProbe(long delayMs) {
        if (PROBE_ROUNDS.incrementAndGet() > PROBE_MAX_ROUNDS) {
            return;
        }
        try {
            new android.os.Handler(android.os.Looper.getMainLooper()).postDelayed(
                    () -> new Thread(HookBootstrap::probeAccount, "wxh-probe").start(),
                    delayMs);
        } catch (Throwable error) {
            ModuleLogger.log(error);
        }
    }

    private static void probeAccount() {
        try {
            String account = Activation.probeWeChat();
            if (account == null) {
                account = Activation.probeShell();
            }
            if (account != null) {
                Activation.setRuntimeWxid(account);
                return;
            }
            scheduleProbe(PROBE_INTERVAL_MS);
        } catch (Throwable error) {
            ModuleLogger.log(error);
        }
    }

    private static boolean isUsapLikeProcess(String processName) {
        return processName != null
                && (processName.endsWith("zygote64") || processName.endsWith("zygote")
                    || processName.endsWith("usap64") || processName.endsWith("usap32"));
    }

    private static boolean isAppBrandProcess(String processName) {
        for (String name : WECHAT_APPBRAND_PROCESSES) {
            if (name.equals(processName)) {
                return true;
            }
        }
        return false;
    }
}
