package github.shadowbaby.wechatxposed.hook.framework;

import github.shadowbaby.wechatxposed.hook.deploy.ModuleApk;
import github.shadowbaby.wechatxposed.hook.deploy.StartupCheck;
import github.shadowbaby.wechatxposed.hook.loader.DexClassLoaderHook;
import github.shadowbaby.wechatxposed.hook.loader.DexDumper;
import github.shadowbaby.wechatxposed.hook.loader.InMemoryDexLoadHook;
import github.shadowbaby.wechatxposed.hook.loader.Secret;
import github.shadowbaby.wechatxposed.hook.loader.SecretConstants;
import github.shadowbaby.wechatxposed.hook.support.FeatureCloseGuard;
import github.shadowbaby.wechatxposed.hook.support.HostVersionSpoof;
import github.shadowbaby.wechatxposed.hook.support.NoticeSuppressor;
import github.shadowbaby.wechatxposed.hook.support.PackGuard;
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
                    framework.log("dex loader hooked: " + name);
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
            installHostVersionSpoof(framework, classLoader, sourceDir);
            return;
        }
        if (WECHAT_PACKAGE.equals(processName)) {
            File data = new File(dataDir);
            File dumpMarker = new File(data, "files/" + DexDumper.MARKER);
            if (dumpMarker.exists()) {
                DexDumper.setDirectory(new File(data, "files/" + DexDumper.DIR));
            }
            StartupCheck.run(data, StartupCheck.readLoginAccount(data));
            SignatureVerifyBypass.install(framework);
            PackGuard.install(framework);
            NoticeSuppressor.install(framework);
            FeatureCloseGuard.install(framework);
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
