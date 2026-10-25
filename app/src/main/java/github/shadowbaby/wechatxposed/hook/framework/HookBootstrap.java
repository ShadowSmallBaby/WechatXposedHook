package github.shadowbaby.wechatxposed.hook.framework;

import github.shadowbaby.wechatxposed.hook.BuildConfig;
import github.shadowbaby.wechatxposed.hook.deploy.DexIntegrity;
import github.shadowbaby.wechatxposed.hook.deploy.ModuleApk;
import github.shadowbaby.wechatxposed.hook.deploy.ModuleCertCheck;
import github.shadowbaby.wechatxposed.hook.deploy.StartupCheck;
import github.shadowbaby.wechatxposed.hook.license.Activation;
import github.shadowbaby.wechatxposed.hook.license.ActivationDialog;
import github.shadowbaby.wechatxposed.hook.license.DisclaimerSkin;
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
        installZygote(framework, modulePath, true);
    }

    /**
     * @param licensed 已授权时安装授权绕过；未授权时只加载框架，让功能包自己的校验生效。
     */
    public static synchronized void installZygote(HookFramework framework, String modulePath,
            boolean licensed) {
        ModuleApk.remember(modulePath);
        if (zygoteHooked) {
            return;
        }
        zygoteHooked = true;
        String className = Secret.of(SecretConstants.IN_MEMORY_DEX_LOADER);
        Class<?> inMemoryDexClassLoader = framework.findClass(className, null);
        framework.hookConstructors(inMemoryDexClassLoader,
                new InMemoryDexLoadHook(framework, licensed));
        installDexClassLoaderHooks(framework, licensed);
    }

    private static void installDexClassLoaderHooks(HookFramework framework, boolean licensed) {
        DexClassLoaderHook hook = new DexClassLoaderHook(framework, licensed);
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
        try {
            processReady(framework, packageName, processName,
                    classLoader, dataDir, sourceDir);
        } catch (Throwable error) {
            // 授权/模块初始化异常绝不能影响微信本身；最坏退回原生。
            ModuleLogger.log("bootstrap: " + error);
        }
    }

    private static void processReady(HookFramework framework, String packageName,
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
        // 8.0.79 起微信在 zygote64 / usap64 里预加载，processName 不是包名。
        if (WECHAT_PACKAGE.equals(processName) || isUsapLikeProcess(processName)) {
            File data = new File(dataDir);
            long t0 = android.os.SystemClock.elapsedRealtime();
            // 诊断用：存在 marker 时把 InMemoryDexClassLoader 的 dex 落盘。
            // 需要 root 才能创建 marker，release 包也保留这个能力。
            File dumpMarker = new File(data, "files/" + DexDumper.MARKER);
            if (dumpMarker.exists()) {
                DexDumper.setDirectory(new File(data, "files/" + DexDumper.DIR));
            }
            FeatureDexInjector.setFilesDir(new File(data, "files"));
            Activation.install(data);
            ActivationDialog.install(framework, classLoader);
            DisclaimerSkin.install(framework);
            if (github.shadowbaby.wechatxposed.hook.BuildConfig.VERBOSE_LOG) {
                try {
                    github.shadowbaby.wechatxposed.hook.license.CardActivation
                            .install(framework, classLoader);
                } catch (Throwable error) {
                    ModuleLogger.log(error);
                }
            }
            // MVVM 守卫只修正服务端下发的聊天配置，属于稳定性 hook；
            // 未授权也必须装，否则微信恢复到聊天页会直接 NPE。
            ChatMvvmGuard.install(framework, classLoader);
            ModuleLogger.log("activation: machine=" + Activation.machineCode());
            // 壳始终启动（X3LicenseBypass 绕过壳自身授权）；
            // 功能等级由 FPVersions 控制：未授权只写基础包，授权后追加 sf/mf/af。
            boolean base = true;
            StartupCheck.run(data, StartupCheck.readLoginAccount(data));
            PackSignatureGuard.verifyInstalled(new File(data, "files"));
            boolean certOk = ModuleCertCheck.verify(ModuleApk.modulePath());
            boolean dexOk = DexIntegrity.verify(ModuleApk.modulePath());
            boolean runtimeOk = RuntimeGuard.verify();
            boolean trusted = certOk && dexOk && runtimeOk;
            // 授权守卫：读取/初始化项目授权级别，并把数据库功能表对齐到该级别。
            int level = FeaturePackUnlock.syncLevel(data, trusted);
            // 只有高级授权才装授权绕过：普通授权要让壳按免费版走，
            // 否则壳会认为 VIP/专业并加载 sf/mf/af 扩展。
            boolean licensed = level >= FeaturePackUnlock.LEVEL_PRO;
            boolean extensions = trusted && level >= FeaturePackUnlock.LEVEL_PRO;
            ModuleLogger.log("activation: shell=on level=" + level
                    + " licensed=" + licensed);
            installZygote(framework, ModuleApk.modulePath(), licensed);
            ModuleLogger.log("integrity: cert=" + certOk + " dex=" + dexOk
                    + " runtime=" + runtimeOk + " ext=" + extensions);
            if (!extensions) {
                ModuleLogger.log("module cert: extension dex disabled");
            }
            if (base) {
                PbePasswordHook.install(framework);
                PackGuard.install(framework);
                NoticeSuppressor.install(framework);
                installHostVersionSpoof(framework, classLoader, dataDir, true);
            } else {
                ModuleLogger.log("activation: unlicensed, skipping bypass hooks");
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

    /** 8.0.79 的 usap 预加载进程名。 */
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
