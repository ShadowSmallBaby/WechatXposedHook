package github.shadowbaby.wechatxposed.hook.framework;

import github.shadowbaby.wechatxposed.hook.BuildConfig;
import github.shadowbaby.wechatxposed.hook.deploy.ModuleApk;
import github.shadowbaby.wechatxposed.hook.deploy.StartupCheck;
import github.shadowbaby.wechatxposed.hook.loader.DexClassLoaderHook;
import github.shadowbaby.wechatxposed.hook.loader.DexDumper;
import github.shadowbaby.wechatxposed.hook.loader.InMemoryDexLoadHook;
import github.shadowbaby.wechatxposed.hook.loader.ModuleLogger;
import github.shadowbaby.wechatxposed.hook.loader.Secret;
import github.shadowbaby.wechatxposed.hook.loader.SecretConstants;
import github.shadowbaby.wechatxposed.hook.support.HostVersionSpoof;
import github.shadowbaby.wechatxposed.hook.support.NoticeSuppressor;
import github.shadowbaby.wechatxposed.hook.support.PackGuard;
import github.shadowbaby.wechatxposed.hook.support.PackIntegrity;
import github.shadowbaby.wechatxposed.hook.support.SignatureVerifyBypass;
import java.io.File;

public final class HookBootstrap {

    private static final String WECHAT_PACKAGE = Secret.of(SecretConstants.WECHAT_PACKAGE);

    private static final String[] WECHAT_APPBRAND_PROCESSES = {
            Secret.of(SecretConstants.APPBRAND_0), Secret.of(SecretConstants.APPBRAND_1)};

    private HookBootstrap() {
    }

    public static void installZygote(HookFramework framework, String modulePath) {
        ModuleApk.remember(modulePath);
        String className = Secret.of(SecretConstants.IN_MEMORY_DEX_LOADER);
        Class<?> inMemoryDexClassLoader = framework.findClass(className, null);
        framework.hookConstructors(inMemoryDexClassLoader, new InMemoryDexLoadHook(framework, 0));
        installDexClassLoaderHooks(framework);
    }

    private static void installDexClassLoaderHooks(HookFramework framework) {
        DexClassLoaderHook hook = new DexClassLoaderHook(framework);
        for (String name : new String[]{"dalvik.system.DexClassLoader",
                "dalvik.system.PathClassLoader"}) {
            try {
                Class<?> loader = framework.findClassIfExists(name, null);
                if (loader != null) {
                    framework.hookConstructors(loader, hook);
                    ModuleLogger.debug("dex loader hooked: " + name);
                }
            } catch (Throwable error) {
                framework.log(error);
            }
        }
    }

    public static void onProcessReady(HookFramework framework, String packageName,
            String processName, ClassLoader classLoader, String dataDir, String sourceDir) {
        if (!WECHAT_PACKAGE.equals(packageName)) {
            return;
        }
        if (isAppBrandProcess(processName)) {
            installPackIntegrity(framework, new File(dataDir));
            installHostVersionSpoof(framework, classLoader, dataDir, false);
            return;
        }
        if (WECHAT_PACKAGE.equals(processName)) {
            File data = new File(dataDir);
            long t0 = android.os.SystemClock.elapsedRealtime();
            if (BuildConfig.DEBUG) {
                File dumpMarker = new File(data, "files/" + DexDumper.MARKER);
                if (dumpMarker.exists()) {
                    DexDumper.setDirectory(new File(data, "files/" + DexDumper.DIR));
                }
            }
            StartupCheck.run(data, StartupCheck.readLoginAccount(data));
            long t1 = android.os.SystemClock.elapsedRealtime();
            installPackIntegrity(framework, data);
            long t2 = android.os.SystemClock.elapsedRealtime();
            SignatureVerifyBypass.install(framework);
            long t3 = android.os.SystemClock.elapsedRealtime();
            PackGuard.install(framework);
            NoticeSuppressor.install(framework);
            long t4 = android.os.SystemClock.elapsedRealtime();
            installHostVersionSpoof(framework, classLoader, dataDir, true);
            long t5 = android.os.SystemClock.elapsedRealtime();
            ModuleLogger.debug("perf: startup=" + (t1 - t0) + "ms, integrity=" + (t2 - t1)
                    + "ms, signature=" + (t3 - t2) + "ms, guard=" + (t4 - t3)
                    + "ms, spoof=" + (t5 - t4) + "ms, total=" + (t5 - t0) + "ms");
        }
    }

    private static void installPackIntegrity(HookFramework framework, File dataDir) {
        try {
            PackIntegrity.install(framework, dataDir);
        } catch (Throwable error) {
            framework.log(error);
        }
    }

    private static void installHostVersionSpoof(HookFramework framework, ClassLoader classLoader,
            String dataDir, boolean mainProcess) {
        try {
            HostVersionSpoof.install(framework, classLoader, dataDir, mainProcess);
        } catch (Throwable error) {
            framework.log(error);
        }
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
