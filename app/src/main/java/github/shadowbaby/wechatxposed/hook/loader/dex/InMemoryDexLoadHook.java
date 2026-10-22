package github.shadowbaby.wechatxposed.hook.loader.dex;

import github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import github.shadowbaby.wechatxposed.hook.framework.HookCallback;
import github.shadowbaby.wechatxposed.hook.framework.HookFramework;
import github.shadowbaby.wechatxposed.hook.framework.HookParam;
import github.shadowbaby.wechatxposed.hook.support.pack.DonationFeatureUnlock;
import github.shadowbaby.wechatxposed.hook.support.guard.FeatureCloseGuard;
import github.shadowbaby.wechatxposed.hook.support.guard.CoreCertHook;
import github.shadowbaby.wechatxposed.hook.support.pack.FeatureDexInjector;
import github.shadowbaby.wechatxposed.hook.support.guard.X3ComponentHooks;
import github.shadowbaby.wechatxposed.hook.support.guard.X3GuardBypass;
import github.shadowbaby.wechatxposed.hook.support.guard.X3LicenseBypass;
import github.shadowbaby.wechatxposed.hook.support.guard.X3SettingsBypass;

/**
 * 拦截宿主把功能 dex 解密进内存的构造。
 *
 * 3.0 扩展包的内层解包会返回 0 字节 buffer，导致 Bad range/native abort；
 * 这里在构造前把 pending 组件的离线 dex 替换进去。
 */
public final class InMemoryDexLoadHook implements HookCallback {

    private final HookFramework framework;

    public InMemoryDexLoadHook(HookFramework framework) {
        this.framework = framework;
    }

    @Override
    public void after(HookParam param) {
        if (!(param.thisObject() instanceof ClassLoader hostClassLoader)) {
            return;
        }

        FeatureCloseGuard.probe(framework, hostClassLoader);
        CoreCertHook.install(framework, hostClassLoader);
        DonationFeatureUnlock.installIfPresent(framework, hostClassLoader);

        boolean x3Class = X3ComponentHooks.matches(framework, hostClassLoader);
        boolean x3Dex = X3ComponentHooks.matchesDex(param);
        boolean licDex = X3LicenseBypass.matchesDex(param);
        boolean guardDex = X3GuardBypass.matchesDex(param);
        boolean settingsDex = X3SettingsBypass.matchesDex(param);
        ModuleLogger.debug("dex probe: x3class=" + x3Class + " x3dex=" + x3Dex
                + " licdex=" + licDex + " guarddex=" + guardDex
                + " settingsdex=" + settingsDex);
        if (licDex) {
            X3LicenseBypass.install(framework, hostClassLoader);
        }
        if (guardDex) {
            X3GuardBypass.install(framework, hostClassLoader);
        }
        if (settingsDex) {
            X3SettingsBypass.install(framework, hostClassLoader);
        }
        if (x3Class || x3Dex) {
            X3ComponentHooks.inject(framework, hostClassLoader);
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
