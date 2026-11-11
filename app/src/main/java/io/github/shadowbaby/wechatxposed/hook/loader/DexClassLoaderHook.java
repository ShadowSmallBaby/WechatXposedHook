package io.github.shadowbaby.wechatxposed.hook.loader;

import io.github.shadowbaby.wechatxposed.shared.hook.HookCallback;
import io.github.shadowbaby.wechatxposed.shared.hook.HookFramework;
import io.github.shadowbaby.wechatxposed.shared.hook.HookParam;
import io.github.shadowbaby.wechatxposed.hook.support.FeatureCloseGuard;
import io.github.shadowbaby.wechatxposed.hook.support.X3ComponentHooks;
import io.github.shadowbaby.wechatxposed.hook.support.X3GuardBypass;
import io.github.shadowbaby.wechatxposed.hook.support.X3SettingsBypass;


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
