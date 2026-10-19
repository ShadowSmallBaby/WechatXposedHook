package github.shadowbaby.wechatxposed.hook.loader;

import github.shadowbaby.wechatxposed.hook.framework.HookCallback;
import github.shadowbaby.wechatxposed.hook.framework.HookFramework;
import github.shadowbaby.wechatxposed.hook.framework.HookParam;
import github.shadowbaby.wechatxposed.hook.support.FeatureCloseGuard;
import github.shadowbaby.wechatxposed.hook.support.X3ComponentHooks;
import github.shadowbaby.wechatxposed.hook.support.X3GuardBypass;
import github.shadowbaby.wechatxposed.hook.support.X3LicenseBypass;
import github.shadowbaby.wechatxposed.hook.support.X3SettingsBypass;

/**
 * 补抓 {@code DexClassLoader} / {@code PathClassLoader} 加载的 3.0 dex。
 *
 * 3.0 的 core dex 走 InMemoryDexClassLoader，但 base dex（含 LIC/设置类）有时走
 * DexClassLoader。这里在构造后按 ClassLoader 探测 3.0 的关键类，命中就安装对应
 * 的绕过 hook。
 */
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
            boolean license = X3LicenseBypass.matchesClass(framework, loader);
            boolean guard = X3GuardBypass.matchesClass(framework, loader);
            boolean settings = X3SettingsBypass.matchesClass(framework, loader);
            boolean component = X3ComponentHooks.matches(framework, loader);
            ModuleLogger.log("dex loader: " + path
                    + " lic=" + license + " guard=" + guard
                    + " settings=" + settings + " component=" + component);
            if (component) {
                X3ComponentHooks.inject(framework, loader);
            }
            if (license) {
                X3LicenseBypass.install(framework, loader);
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
