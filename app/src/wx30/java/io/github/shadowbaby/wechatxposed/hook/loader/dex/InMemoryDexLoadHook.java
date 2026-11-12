package io.github.shadowbaby.wechatxposed.hook.loader.dex;

import io.github.shadowbaby.wechatxposed.hook.BuildConfig;
import io.github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import io.github.shadowbaby.wechatxposed.shared.hook.HookCallback;
import io.github.shadowbaby.wechatxposed.shared.hook.HookFramework;
import io.github.shadowbaby.wechatxposed.shared.hook.HookParam;
import io.github.shadowbaby.wechatxposed.hook.support.guard.FeatureCloseGuard;
import io.github.shadowbaby.wechatxposed.hook.support.guard.X3ComponentHooks;
import io.github.shadowbaby.wechatxposed.hook.support.guard.X3GuardBypass;
import io.github.shadowbaby.wechatxposed.hook.support.guard.X3SettingsBypass;

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
        try {
            if (BuildConfig.WX_PACK.startsWith("wx6")) {
                installMicrox(hostClassLoader);
                return;
            }
            FeatureCloseGuard.probe(framework, hostClassLoader);
            boolean x3Class = X3ComponentHooks.matches(framework, hostClassLoader);
            boolean x3Dex = X3ComponentHooks.matchesDex(param);
            boolean guardDex = X3GuardBypass.matchesDex(param);
            boolean settingsDex = X3SettingsBypass.matchesDex(param);
            ModuleLogger.debug("dex probe: x3class=" + x3Class + " x3dex=" + x3Dex
                    + " guarddex=" + guardDex + " settingsdex=" + settingsDex);
            if (guardDex) {
                X3GuardBypass.install(framework, hostClassLoader);
            }
            if (settingsDex) {
                X3SettingsBypass.install(framework, hostClassLoader);
            }
            if (x3Class || x3Dex) {
                X3ComponentHooks.inject(framework, hostClassLoader);
            }
        } catch (Throwable error) {
            ModuleLogger.log(error);
        }
    }

    private void installMicrox(ClassLoader hostClassLoader) {
    }
}
