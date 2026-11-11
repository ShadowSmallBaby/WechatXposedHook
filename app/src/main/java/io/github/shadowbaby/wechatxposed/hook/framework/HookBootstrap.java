package io.github.shadowbaby.wechatxposed.hook.framework;

import io.github.shadowbaby.wechatxposed.hook.deploy.ModuleApk;
import io.github.shadowbaby.wechatxposed.hook.deploy.StartupCheck;
import io.github.shadowbaby.wechatxposed.hook.loader.DexClassLoaderHook;
import io.github.shadowbaby.wechatxposed.hook.loader.InMemoryDexLoadHook;
import io.github.shadowbaby.wechatxposed.hook.loader.ModuleLogger;
import io.github.shadowbaby.wechatxposed.hook.loader.Secret;
import io.github.shadowbaby.wechatxposed.hook.loader.SecretConstants;
import io.github.shadowbaby.wechatxposed.hook.support.NoticeSuppressor;
import io.github.shadowbaby.wechatxposed.hook.support.PackGuard;
import io.github.shadowbaby.wechatxposed.hook.support.PackIntegrity;
import java.io.File;
import io.github.shadowbaby.wechatxposed.shared.hook.HookFramework;

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
            return;
        }
        if (WECHAT_PACKAGE.equals(processName)) {
            File data = new File(dataDir);
            long t0 = android.os.SystemClock.elapsedRealtime();
            StartupCheck.run(data, StartupCheck.readLoginAccount(data));
            long t1 = android.os.SystemClock.elapsedRealtime();
            installPackIntegrity(framework, data);
            long t2 = android.os.SystemClock.elapsedRealtime();
            PackGuard.install(framework);
            NoticeSuppressor.install(framework);
            long t3 = android.os.SystemClock.elapsedRealtime();
        }
    }

    private static void installPackIntegrity(HookFramework framework, File dataDir) {
        try {
            PackIntegrity.install(framework, dataDir);
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
