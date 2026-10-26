package github.shadowbaby.wechatxposed.hook.loader.dex;

import github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import github.shadowbaby.wechatxposed.hook.loader.dex.DexDumper;
import github.shadowbaby.wechatxposed.hook.framework.HookCallback;
import github.shadowbaby.wechatxposed.hook.framework.HookFramework;
import github.shadowbaby.wechatxposed.hook.framework.HookParam;
import github.shadowbaby.wechatxposed.hook.license.Activation;
import github.shadowbaby.wechatxposed.hook.support.pack.DonationFeatureUnlock;
import github.shadowbaby.wechatxposed.hook.support.guard.FeatureCloseGuard;
import github.shadowbaby.wechatxposed.hook.support.guard.CoreCertHook;
import github.shadowbaby.wechatxposed.hook.support.pack.FeatureDexInjector;
import github.shadowbaby.wechatxposed.hook.support.guard.X3ComponentHooks;
import github.shadowbaby.wechatxposed.hook.support.guard.X3GuardBypass;
import github.shadowbaby.wechatxposed.hook.support.guard.X3SettingsBypass;

/**
 * 拦截宿主把功能 dex 解密进内存的构造。
 *
 * 3.0 扩展包的内层解包会返回 0 字节 buffer，导致 Bad range/native abort；
 * 这里在构造前把 pending 组件的离线 dex 替换进去。
 */
public final class InMemoryDexLoadHook implements HookCallback {

    private final HookFramework framework;
    /** 构造时的授权状态。启动早期账号未就绪，级别可能稍后才涨上来。 */
    private final boolean licensedInitial;

    /** 壳的 ClassLoader，账号晚到时靠它补装授权绕过。 */
    private static volatile HookFramework frameworkRef;
    private static volatile ClassLoader loaderRef;
    private static volatile boolean replayed;

    public InMemoryDexLoadHook(HookFramework framework) {
        this(framework, true);
    }

    public InMemoryDexLoadHook(HookFramework framework, boolean licensed) {
        this.framework = framework;
        this.licensedInitial = licensed;
    }

    /**
     * 未授权时不装任何授权/设置绕过，让功能包自己的校验（含协议弹窗）生效。
     *
     * 每次都要重新问授权守卫：账户晚一步到达时，构造阶段还是 0 级，
     * 钉死这个值会让壳在运行中按未授权把自己关掉。
     */
    private boolean licensed() {
        return licensedInitial || Activation.isBaseAllowed();
    }

    /** 两个 hook 各自带幂等标记（FeatureCloseGuard 用 DONE 集合），重复调用安全。 */
    private static void installLicensed(HookFramework framework, ClassLoader loader) {
        FeatureCloseGuard.probe(framework, loader);
        DonationFeatureUnlock.installIfPresent(framework, loader);
    }

    /**
     * 账号就绪后补装授权绕过。
     *
     * core dex 的加载一定早于壳通过 CallMethod 传账号，第一次 after() 只能按
     * 探到的级别决定；等账号真正到了，这里按最新授权状态再补一次，
     * 这样不用在 after() 里阻塞（阻塞会让壳初始化不完，账号反而永远不来）。
     */
    public static void retryLicensed() {
        HookFramework framework = frameworkRef;
        ClassLoader loader = loaderRef;
        if (framework == null || loader == null || replayed) {
            return;
        }
        if (!Activation.isBaseAllowed()) {
            return;
        }
        replayed = true;
        try {
            installLicensed(framework, loader);
            ModuleLogger.log("licensed hooks: replayed after account ready");
        } catch (Throwable error) {
            ModuleLogger.log(error);
        }
    }

    @Override
    public void after(HookParam param) {
        if (!(param.thisObject() instanceof ClassLoader hostClassLoader)) {
            return;
        }
        // 记住壳的 ClassLoader：账号会比 core dex 晚一步到达，那时要靠它补装。
        frameworkRef = framework;
        loaderRef = hostClassLoader;
        boolean licensed = licensed();

        DexDumper.maybeDump(param);
        CoreCertHook.install(framework, hostClassLoader);
        if (licensed) {
            installLicensed(framework, hostClassLoader);
        }

        boolean x3Class = X3ComponentHooks.matches(framework, hostClassLoader);
        boolean x3Dex = X3ComponentHooks.matchesDex(param);
        boolean guardDex = licensed && X3GuardBypass.matchesDex(param);
        boolean settingsDex = licensed && X3SettingsBypass.matchesDex(param);
        ModuleLogger.debug("dex probe: x3class=" + x3Class + " x3dex=" + x3Dex
                + " guarddex=" + guardDex
                + " settingsdex=" + settingsDex);
        if (guardDex) {
            X3GuardBypass.install(framework, hostClassLoader);
        }
        if (settingsDex) {
            X3SettingsBypass.install(framework, hostClassLoader);
        }
        if (x3Class || x3Dex) {
            X3ComponentHooks.inject(framework, hostClassLoader, licensed);
            github.shadowbaby.wechatxposed.hook.license.DisclaimerSkin
                    .hookMorePage(framework, hostClassLoader);
        }
    }

    @Override
    public void before(HookParam param) {
        String feature = FeatureDexInjector.pending();
        if (feature == null) {
            return;
        }
        try {
            Object value = param.arg(0);
            if (value instanceof java.nio.ByteBuffer buffer) {
                if (buffer.remaining() > 0) {
                    return;
                }
                byte[] dex = FeatureDexInjector.dex(feature);
                if (dex == null) {
                    return;
                }
                param.setArg(0, FeatureDexInjector.buffer(dex));
                ModuleLogger.log("feature dex: inject " + feature + " " + dex.length + "B");
                FeatureDexInjector.end();
                return;
            }
            if (value instanceof java.nio.ByteBuffer[] buffers) {
                for (java.nio.ByteBuffer buffer : buffers) {
                    if (buffer != null && buffer.remaining() > 0) {
                        return;
                    }
                }
                byte[] dex = FeatureDexInjector.dex(feature);
                if (dex == null) {
                    return;
                }
                param.setArg(0, new java.nio.ByteBuffer[]{FeatureDexInjector.buffer(dex)});
                ModuleLogger.log("feature dex: inject " + feature + " " + dex.length
                        + "B (array)");
                FeatureDexInjector.end();
            }
        } catch (Throwable error) {
            ModuleLogger.log(error);
        }
    }
}
