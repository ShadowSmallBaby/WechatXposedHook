package github.shadowbaby.wechatxposed.hook.framework;

import github.shadowbaby.wechatxposed.hook.BuildConfig;
import github.shadowbaby.wechatxposed.hook.deploy.DexIntegrity;
import github.shadowbaby.wechatxposed.hook.deploy.ModuleApk;
import github.shadowbaby.wechatxposed.hook.deploy.ModuleCertCheck;
import github.shadowbaby.wechatxposed.hook.deploy.StartupCheck;
import github.shadowbaby.wechatxposed.hook.license.Activation;
import github.shadowbaby.wechatxposed.hook.license.ActivationDialog;
import github.shadowbaby.wechatxposed.hook.loader.dex.DexClassLoaderHook;
import github.shadowbaby.wechatxposed.hook.loader.dex.DexDumper;
import github.shadowbaby.wechatxposed.hook.loader.dex.InMemoryDexLoadHook;
import github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import github.shadowbaby.wechatxposed.hook.loader.util.Secret;
import github.shadowbaby.wechatxposed.hook.loader.SecretConstants;
import github.shadowbaby.wechatxposed.hook.support.pack.FeatureDexInjector;
import github.shadowbaby.wechatxposed.hook.support.pack.FeaturePackUnlock;
import github.shadowbaby.wechatxposed.hook.support.feature.AppBrandCacheRepair;
import github.shadowbaby.wechatxposed.hook.support.feature.ChatMvvmGuard;
import github.shadowbaby.wechatxposed.hook.support.feature.HostVersionSpoof;
import github.shadowbaby.wechatxposed.hook.support.guard.NoticeSuppressor;
import github.shadowbaby.wechatxposed.hook.support.guard.RuntimeGuard;
import github.shadowbaby.wechatxposed.hook.support.pack.PackGuard;
import github.shadowbaby.wechatxposed.hook.support.pack.PackSignatureGuard;
import github.shadowbaby.wechatxposed.hook.support.pack.PbePasswordHook;
import java.io.File;

public final class HookBootstrap {

    private static final String WECHAT_PACKAGE = Secret.of(SecretConstants.WECHAT_PACKAGE);

    private static final String[] WECHAT_APPBRAND_PROCESSES = {
            Secret.of(SecretConstants.APPBRAND_0), Secret.of(SecretConstants.APPBRAND_1)};

    private static volatile boolean zygoteHooked;

    private HookBootstrap() {
    }

    /** 只记录模块路径，不安装任何 hook；授权通过后再 installZygote。 */
    public static void remember(String modulePath) {
        ModuleApk.remember(modulePath);
    }

    public static synchronized void installZygote(HookFramework framework, String modulePath) {
        ModuleApk.remember(modulePath);
        if (zygoteHooked) {
            return;
        }
        zygoteHooked = true;
        String className = Secret.of(SecretConstants.IN_MEMORY_DEX_LOADER);
        Class<?> inMemoryDexClassLoader = framework.findClass(className, null);
        framework.hookConstructors(inMemoryDexClassLoader, new InMemoryDexLoadHook(framework));
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
        AppBrandCacheRepair.install();
        if (isAppBrandProcess(processName)) {
            Activation.install(new File(dataDir));
            if (!Activation.isBaseAllowed()) {
                return;
            }
            installZygote(framework, ModuleApk.modulePath());
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
            FeatureDexInjector.setFilesDir(new File(data, "files"));
            Activation.install(data);
            ActivationDialog.install(framework, classLoader);
            // MVVM 守卫只修正服务端下发的聊天配置，属于稳定性 hook；
            // 未授权也必须装，否则微信恢复到聊天页会直接 NPE。
            ChatMvvmGuard.install(framework, classLoader);
            ModuleLogger.log("activation: machine=" + Activation.machineCode());
            boolean base = Activation.isBaseAllowed();
            if (!base) {
                ModuleLogger.log("activation: base not authorized");
                return;
            }
            installZygote(framework, ModuleApk.modulePath());
            StartupCheck.run(data, StartupCheck.readLoginAccount(data));
            PackSignatureGuard.verifyInstalled(new File(data, "files"));
            boolean trusted = ModuleCertCheck.verify(ModuleApk.modulePath())
                    && DexIntegrity.verify(ModuleApk.modulePath())
                    && RuntimeGuard.verify();
            boolean extensions = trusted && Activation.isExtensionAllowed();
            if (!extensions) {
                ModuleLogger.log("module cert: extension dex disabled");
            }
            FeaturePackUnlock.run(data, extensions);
            PbePasswordHook.install(framework);
            PackGuard.install(framework);
            NoticeSuppressor.install(framework);
            if (base) {
                installHostVersionSpoof(framework, classLoader, dataDir, true);
            }
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
