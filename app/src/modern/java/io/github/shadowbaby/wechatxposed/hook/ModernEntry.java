package io.github.shadowbaby.wechatxposed.hook;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.os.Process;
import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.IXposedHookZygoteInit;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.callbacks.XC_LoadPackage;
import io.github.shadowbaby.wechatxposed.hook.framework.HookBootstrap;
import io.github.shadowbaby.wechatxposed.hook.framework.ModernFramework;
import io.github.shadowbaby.wechatxposed.hook.license.Activation;
import io.github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import io.github.shadowbaby.wechatxposed.hook.loader.SecretConstants;
import io.github.shadowbaby.wechatxposed.hook.loader.util.Secret;
import io.github.libxposed.api.XposedModule;
import io.github.libxposed.api.XposedModuleInterface.ModuleLoadedParam;
import io.github.libxposed.api.XposedModuleInterface.PackageReadyParam;
import java.lang.reflect.Method;

public class ModernEntry extends XposedModule {

    private static final String WECHAT_PACKAGE = Secret.of(SecretConstants.WECHAT_PACKAGE);

    private final ModernFramework framework = new ModernFramework(this);

    private Object shellEntry;

    private String modulePath;

    @Override
    public void onModuleLoaded(ModuleLoadedParam param) {
        Activation.captureBuildIdentity();
        ModuleLogger.attach(framework);
        XposedBridge.init(framework);
        modulePath = getModuleApplicationInfo().sourceDir;
        HookBootstrap.installZygote(framework, modulePath);
    }

    @Override
    public void onPackageReady(PackageReadyParam param) {
        try {
            handlePackage(param);
        } catch (Throwable error) {

            framework.log(error);
        }
    }

    private void handlePackage(PackageReadyParam param) {
        if (!WECHAT_PACKAGE.equals(param.getPackageName())) {
            return;
        }
        String processName = currentProcessName();
        ApplicationInfo info = targetInfo(param);
        ModuleLogger.debug("modern: process=" + processName + " data=" + info.dataDir);
        Activation.install(new java.io.File(info.dataDir));
        if (shellEntry == null) {
            String shellPath = HookBootstrap.prepareShell(framework, info, modulePath);
            ClassLoader shellLoader = HookBootstrap.prepareShellLoader(
                    framework, info, modulePath);
            shellEntry = initLegacy(HookBootstrap.shellEntryClass(),
                    shellPath, shellLoader);
        }
        HookBootstrap.onProcessReady(framework, param.getPackageName(), processName,
                param.getClassLoader(), info.dataDir, info.sourceDir);
        if (shellEntry instanceof IXposedHookLoadPackage shell) {
            try {
                XC_LoadPackage.LoadPackageParam load = new XC_LoadPackage.LoadPackageParam();
                load.packageName = param.getPackageName();
                load.processName = processName;
                load.classLoader = param.getClassLoader();
                load.appInfo = info;
                load.isFirstApplication = true;
                shell.handleLoadPackage(load);
            } catch (Throwable error) {
                framework.log(error);
            }
        }
    }

    private ApplicationInfo targetInfo(PackageReadyParam param) {
        ApplicationInfo info = param.getApplicationInfo();
        String packageName = param.getPackageName();

        int userId = Process.myUid() / 100000;
        java.io.File local = new java.io.File("/data/user/" + userId, packageName);
        if (local.isDirectory()) {
            info.dataDir = local.getAbsolutePath();
            return info;
        }
        try {
            Class<?> threadClass = Class.forName("android.app.ActivityThread");
            Object thread = threadClass.getMethod("currentActivityThread").invoke(null);
            Context context = (Context) threadClass.getMethod("getSystemContext")
                    .invoke(thread);
            return context.getPackageManager()
                    .getApplicationInfo(packageName, 0);
        } catch (Throwable error) {
            framework.log(error);
            return info;
        }
    }

    private Object initLegacy(String name, String modulePath, ClassLoader shellLoader) {
        try {
            ClassLoader loader = shellLoader != null
                    ? shellLoader : ModernEntry.class.getClassLoader();
            Class<?> type = Class.forName(name, true, loader);
            Object instance = type.getDeclaredConstructor().newInstance();
            if (!(instance instanceof IXposedHookZygoteInit entry)) {
                return instance;
            }
            IXposedHookZygoteInit.StartupParam startup =
                    new IXposedHookZygoteInit.StartupParam();
            startup.modulePath = modulePath;
            startup.startsSystemServer = false;
            entry.initZygote(startup);
            return instance;
        } catch (Throwable error) {
            framework.log(error);
            return null;
        }
    }

    private static String currentProcessName() {

        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
            try {
                String name = android.app.Application.getProcessName();
                if (name != null && !name.isEmpty()) {
                    return name;
                }
            } catch (Throwable ignored) {
            }
        }
        try {
            Class<?> activityThread = Class.forName("android.app.ActivityThread");
            Method method = activityThread.getDeclaredMethod("currentProcessName");
            method.setAccessible(true);
            Object name = method.invoke(null);
            return name instanceof String ? (String) name : null;
        } catch (Throwable error) {
            return null;
        }
    }
}
