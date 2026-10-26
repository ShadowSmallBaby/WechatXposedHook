package github.shadowbaby.wechatxposed.hook.framework;

import github.shadowbaby.wechatxposed.hook.BuildConfig;
import github.shadowbaby.wechatxposed.hook.deploy.ModuleApk;
import github.shadowbaby.wechatxposed.hook.deploy.ModuleCertCheck;
import github.shadowbaby.wechatxposed.hook.deploy.StartupCheck;
import github.shadowbaby.wechatxposed.hook.license.Activation;
import github.shadowbaby.wechatxposed.hook.license.DisclaimerSkin;
import github.shadowbaby.wechatxposed.hook.license.QuickCopy;
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
import github.shadowbaby.wechatxposed.hook.support.guard.ShellHostProbe;
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
            // 小程序运行时也要版本窗口，否则启动场景和 getSystemInfo 仍是真版本。
            // PackageInfo 伪装只放在 appbrand，主进程的转账/钱包保持真实版本。
            try {
                HostVersionSpoof.installAppBrand(framework, classLoader);
                github.shadowbaby.wechatxposed.hook.support.feature.version.PackageVersionSpoof
                        .install(framework, classLoader);
            } catch (Throwable error) {
                ModuleLogger.log(error);
            }
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
            ModuleLogger.log("module " + BuildConfig.VERSION_NAME
                    + " (" + BuildConfig.VERSION_CODE + ")");
            DisclaimerSkin.install(framework, classLoader);
            QuickCopy.install(framework);
            // Toast 过滤（卡密提示 + 壳更新失败提示）与调试开关无关，正式包也要生效。
            try {
                github.shadowbaby.wechatxposed.hook.license.CardActivation
                        .hookShellToast(framework);
            } catch (Throwable error) {
                ModuleLogger.log(error);
            }
            // 卡密激活：正式包（VERBOSE_LOG=false）也必须可用。
            try {
                github.shadowbaby.wechatxposed.hook.license.CardActivation
                        .install(framework, classLoader);
            } catch (Throwable error) {
                ModuleLogger.log(error);
            }
            // MVVM 守卫只修正服务端下发的聊天配置，属于稳定性 hook；
            // 未授权也必须装，否则微信恢复到聊天页会直接 NPE。
            ChatMvvmGuard.install(framework, classLoader);
            ModuleLogger.log("activation: machine=" + Activation.machineCode());
            // 壳始终启动；功能等级由 FPVersions 控制：
            StartupCheck.run(data, StartupCheck.readLoginAccount(data));
            PackSignatureGuard.verifyInstalled(new File(data, "files"));
            boolean certOk = ModuleCertCheck.verify(ModuleApk.modulePath());
            boolean runtimeOk = RuntimeGuard.verify();
            boolean trusted = certOk && runtimeOk;
            // 授权守卫：读取/初始化项目授权级别，并把数据库功能表对齐到该级别。
            int level = FeaturePackUnlock.syncLevel(data, trusted);
            if (level < FeaturePackUnlock.LEVEL_BASE) {
                // 账号还没解析出来时 syncLevel 会直接早退，但只读查询能读到库里
                // 已有的账号行。漏了这步，授权 hook 会按未授权装死，
                // 壳随后把 themes/base/donation/vidurlparser 全部关掉。
                level = Math.max(level, FeaturePackUnlock.readLevel(data));
            }
            // 普通授权也要装授权守卫：不装的话壳按未授权处理，
            // 运行中会把 themes/base/donation/vidurlparser 逐个 closed。
            // VIP/专业 与 sf/mf/af 扩展另由 msg 150 的标签查询和功能表分级控制。
            boolean licensed = level >= FeaturePackUnlock.LEVEL_BASE;
            boolean extensions = trusted && level >= FeaturePackUnlock.LEVEL_PRO;
            if (BuildConfig.VERBOSE_LOG) {
                // 壳的更新/公告域名解析失败时只能看到一行日志，先抓调用栈定位。
                ShellHostProbe.install(framework);
            }
            ModuleLogger.log("activation: shell=on level=" + level
                    + " licensed=" + licensed);
            installZygote(framework, ModuleApk.modulePath(), licensed);
            ModuleLogger.log("integrity: cert=" + certOk
                    + " runtime=" + runtimeOk + " ext=" + extensions);
            if (!extensions) {
                ModuleLogger.log("module cert: extension dex disabled");
            }
            PbePasswordHook.install(framework);
            PackGuard.install(framework);
            NoticeSuppressor.install(framework);
            installHostVersionSpoof(framework, classLoader, dataDir, true);
            // MMKV 在启动早期可能还没初始化；延迟再探一次，文件层读不到时补上账号。
            // 探测会反射/读若干文件，放到子线程，别压主线程。
            try {
                new android.os.Handler(android.os.Looper.getMainLooper()).postDelayed(
                        () -> new Thread(HookBootstrap::probeAccount, "wxh-probe").start(),
                        5000);
            } catch (Throwable error) {
                ModuleLogger.log(error);
            }
        }
    }

    /** 壳加载完成后补问一次账号：成功就落盘并触发授权重算。 */
    private static void probeAccount() {
        try {
            String account = Activation.probeShell();
            if (account != null) {
                Activation.setRuntimeWxid(account);
                return;
            }
            if (Activation.wxid() == null) {
                File dataDir = Activation.dataDir();
                if (dataDir != null) {
                    ModuleLogger.log("login diag: " + StartupCheck.diagnose(dataDir));
                }
            }
        } catch (Throwable error) {
            ModuleLogger.log(error);
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
