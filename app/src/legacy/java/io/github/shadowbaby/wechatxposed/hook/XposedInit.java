package io.github.shadowbaby.wechatxposed.hook;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.IXposedHookZygoteInit;
import de.robv.android.xposed.callbacks.XC_LoadPackage;
import io.github.shadowbaby.wechatxposed.hook.framework.HookBootstrap;
import io.github.shadowbaby.wechatxposed.hook.framework.LegacyFramework;
import io.github.shadowbaby.wechatxposed.hook.license.Activation;
import io.github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;

public class XposedInit implements IXposedHookZygoteInit, IXposedHookLoadPackage {

    private final LegacyFramework framework = new LegacyFramework();

    private Object shellEntry;

    private String modulePath;

    private IXposedHookZygoteInit.StartupParam startup;

    @Override
    public void initZygote(StartupParam startupParam) {
        Activation.captureBuildIdentity();
        ModuleLogger.attach(framework);

        startup = startupParam;
        modulePath = startupParam.modulePath;
        HookBootstrap.installZygote(framework, modulePath);
    }

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam param) {
        ModuleLogger.log("bootstrap: package=" + param.packageName
                + " process=" + param.processName
                + " appInfo=" + (param.appInfo != null));
        if (param.appInfo == null) {
            return;
        }
        if (shellEntry == null) {
            try {
                String shellPath = HookBootstrap.prepareShell(
                        framework, param.appInfo, modulePath);
                ClassLoader shellLoader = HookBootstrap.prepareShellLoader(
                        framework, param.appInfo, modulePath);
                shellEntry = initLegacy(HookBootstrap.shellEntryClass(),
                        shellPath, shellLoader);
            } catch (Throwable error) {
                ModuleLogger.log(error);
            }
        }
        try {
            HookBootstrap.onProcessReady(framework, param.packageName, param.processName,
                    param.classLoader, param.appInfo.dataDir, param.appInfo.sourceDir);
        } catch (Throwable error) {

            ModuleLogger.log(error);
        }
        if (shellEntry instanceof IXposedHookLoadPackage shell) {
            try {
                shell.handleLoadPackage(param);
            } catch (Throwable error) {
                ModuleLogger.log(error);
            }
        }
    }

    private Object initLegacy(String name, String path, ClassLoader shellLoader) {
        try {
            ClassLoader loader = shellLoader != null
                    ? shellLoader : XposedInit.class.getClassLoader();
            Class<?> type = Class.forName(name, true, loader);
            Object instance = type.getDeclaredConstructor().newInstance();
            if (!(instance instanceof IXposedHookZygoteInit entry) || startup == null) {
                return instance;
            }
            String original = startup.modulePath;
            startup.modulePath = path;
            try {
                entry.initZygote(startup);
            } finally {
                startup.modulePath = original;
            }
            return instance;
        } catch (Throwable error) {
            ModuleLogger.log(error);
            return null;
        }
    }
}
