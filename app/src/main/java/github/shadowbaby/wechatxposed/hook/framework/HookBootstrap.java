package github.shadowbaby.wechatxposed.hook.framework;

import github.shadowbaby.wechatxposed.hook.deploy.ModuleApk;
import github.shadowbaby.wechatxposed.hook.deploy.StartupCheck;
import github.shadowbaby.wechatxposed.hook.loader.InMemoryDexLoadHook;
import github.shadowbaby.wechatxposed.hook.loader.Secret;
import github.shadowbaby.wechatxposed.hook.loader.SecretConstants;
import github.shadowbaby.wechatxposed.hook.support.HostVersionSpoof;
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
    }

    public static void onProcessReady(HookFramework framework, String packageName,
            String processName, ClassLoader classLoader, String dataDir, String sourceDir) {
        if (!WECHAT_PACKAGE.equals(packageName)) {
            return;
        }
        if (isAppBrandProcess(processName)) {
            installHostVersionSpoof(framework, classLoader, sourceDir);
            return;
        }
        if (WECHAT_PACKAGE.equals(processName)) {
            File data = new File(dataDir);
            StartupCheck.run(data, StartupCheck.readLoginAccount(data));
            installHostVersionSpoof(framework, classLoader, sourceDir);
        }
    }

    private static void installHostVersionSpoof(HookFramework framework, ClassLoader classLoader,
            String sourceDir) {
        try {
            HostVersionSpoof.install(framework, classLoader, sourceDir);
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
