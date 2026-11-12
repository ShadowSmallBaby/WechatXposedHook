package io.github.shadowbaby.wechatxposed.hook.loader.dex;

import io.github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import io.github.shadowbaby.wechatxposed.shared.hook.HookCallback;
import io.github.shadowbaby.wechatxposed.shared.hook.HookFramework;
import io.github.shadowbaby.wechatxposed.shared.hook.HookParam;
import io.github.shadowbaby.wechatxposed.hook.support.guard.FeatureCloseGuard;
import io.github.shadowbaby.wechatxposed.hook.support.guard.X3ComponentHooks;
import io.github.shadowbaby.wechatxposed.hook.support.guard.X3GuardBypass;
import io.github.shadowbaby.wechatxposed.hook.support.guard.X3SettingsBypass;

public final class DexClassLoaderHook implements HookCallback {

    private final HookFramework framework;

    public DexClassLoaderHook(HookFramework framework) {
        this.framework = framework;
    }

    @Override
    public void after(HookParam param) {
        if (!(param.thisObject() instanceof ClassLoader loader)) {
            return;
        }
        try {
            String path = String.valueOf(param.arg(0));
            FeatureCloseGuard.probe(framework, loader);
            boolean guard = X3GuardBypass.matchesClass(framework, loader);
            boolean settings = X3SettingsBypass.matchesClass(framework, loader);
            boolean component = X3ComponentHooks.matches(framework, loader);
            ModuleLogger.debug("dex loader: " + path + " guard=" + guard
                    + " settings=" + settings + " component=" + component);
            if (component) {
                X3ComponentHooks.inject(framework, loader);
            }
            if (guard) {
                X3GuardBypass.install(framework, loader);
            }
            if (settings) {
                X3SettingsBypass.install(framework, loader);
            }
        } catch (Throwable error) {
            ModuleLogger.log(error);
        }
    }
}
