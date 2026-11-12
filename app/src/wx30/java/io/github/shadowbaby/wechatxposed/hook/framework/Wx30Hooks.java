package io.github.shadowbaby.wechatxposed.hook.framework;

import io.github.shadowbaby.wechatxposed.hook.deploy.ModuleApk;
import io.github.shadowbaby.wechatxposed.hook.loader.SecretConstants;
import io.github.shadowbaby.wechatxposed.hook.loader.dex.DexClassLoaderHook;
import io.github.shadowbaby.wechatxposed.hook.loader.dex.InMemoryDexLoadHook;
import io.github.shadowbaby.wechatxposed.hook.loader.util.Secret;
import io.github.shadowbaby.wechatxposed.hook.support.guard.ChatMvvmGuard;
import io.github.shadowbaby.wechatxposed.hook.support.guard.NoticeSuppressor;
import io.github.shadowbaby.wechatxposed.hook.support.identity.X30Compat;
import io.github.shadowbaby.wechatxposed.hook.support.pack.PackGuard;
import io.github.shadowbaby.wechatxposed.hook.support.shell.ShellBundle;
import io.github.shadowbaby.wechatxposed.shared.hook.HookFramework;

public final class Wx30Hooks implements PlatformHooks {

    @Override
    public void installZygote(HookFramework framework, String modulePath) {
        ModuleApk.remember(modulePath);
        X30Compat.install(modulePath);
        String className = Secret.of(SecretConstants.IN_MEMORY_DEX_LOADER);
        Class<?> inMemoryDexClassLoader = framework.findClass(className, null);
        framework.hookConstructors(inMemoryDexClassLoader, new InMemoryDexLoadHook(framework));
        DexClassLoaderHook hook = new DexClassLoaderHook(framework);
        for (String name : new String[]{"dalvik.system.DexClassLoader",
                "dalvik.system.PathClassLoader"}) {
            try {
                Class<?> loader = framework.findClassIfExists(name, null);
                if (loader != null) {
                    framework.hookConstructors(loader, hook);
                }
            } catch (Throwable error) {
                framework.log(error);
            }
        }
    }

    @Override
    public void installEarly(HookFramework framework, ClassLoader classLoader) {
        try {
            ChatMvvmGuard.install(framework, classLoader);
        } catch (Throwable error) {
            framework.log(error);
        }
    }

    @Override
    public void installPackGuards(HookFramework framework) {
        PackGuard.install(framework);
        NoticeSuppressor.install(framework);
    }

    @Override
    public String prepareShell(HookFramework framework,
            android.content.pm.ApplicationInfo appInfo, String modulePath) {
        String shell = ShellBundle.ensure(appInfo);
        return shell != null ? shell : modulePath;
    }

    @Override
    public ClassLoader prepareShellLoader(HookFramework framework,
            android.content.pm.ApplicationInfo appInfo, String modulePath) {
        String shell = ShellBundle.ensure(appInfo);
        if (shell == null) {
            return null;
        }
        ClassLoader loader = ShellBundle.loader(shell, new java.io.File(appInfo.dataDir));
        if (loader != null) {
            io.github.shadowbaby.wechatxposed.hook.support.identity.X30Compat.attach(loader);
        }
        return loader;
    }

    @Override
    public String shellEntryClass() {
        return Secret.of(SecretConstants.SHELL_ENTRY);
    }

    @Override
    public String shellPackage() {
        return "cn.android.x";
    }

    @Override
    public String settingsHint() {
        return "请在微信「我 → 设置 → 更多」中打开 X 3.0";
    }
}
