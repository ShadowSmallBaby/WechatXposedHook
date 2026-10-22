package github.shadowbaby.wechatxposed.hook;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.IXposedHookZygoteInit;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.callbacks.XC_LoadPackage;
import github.shadowbaby.wechatxposed.hook.framework.HookBootstrap;
import github.shadowbaby.wechatxposed.hook.framework.ModernFramework;
import github.shadowbaby.wechatxposed.hook.license.Activation;
import github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import io.github.libxposed.api.XposedModule;
import io.github.libxposed.api.XposedModuleInterface.ModuleLoadedParam;
import io.github.libxposed.api.XposedModuleInterface.PackageReadyParam;
import java.lang.reflect.Method;

public class ModernEntry extends XposedModule {

    private final ModernFramework framework = new ModernFramework(this);

    private Object shellEntry;

    private String modulePath;

    @Override
    public void onModuleLoaded(ModuleLoadedParam param) {
        Activation.captureBuildIdentity();
        ModuleLogger.attach(framework);
        XposedBridge.init(framework);
        modulePath = getModuleApplicationInfo().sourceDir;
        initLegacy("github.shadowbaby.wechatxposed.x30.X30Compat", modulePath);
        HookBootstrap.remember(modulePath);
    }

    @Override
    public void onPackageReady(PackageReadyParam param) {
        String processName = currentProcessName();
        Activation.install(new java.io.File(param.getApplicationInfo().dataDir));
        if (Activation.isBaseAllowed() && shellEntry == null) {
            shellEntry = initLegacy("com.android.x.XposedInit", modulePath);
        }
        HookBootstrap.onProcessReady(framework, param.getPackageName(), processName,
                param.getClassLoader(), param.getApplicationInfo().dataDir,
                param.getApplicationInfo().sourceDir);
        if (!Activation.isBaseAllowed()) {
            return;
        }
        if (shellEntry instanceof IXposedHookLoadPackage shell) {
            try {
                XC_LoadPackage.LoadPackageParam load = new XC_LoadPackage.LoadPackageParam();
                load.packageName = param.getPackageName();
                load.processName = processName;
                load.classLoader = param.getClassLoader();
                load.appInfo = param.getApplicationInfo();
                load.isFirstApplication = true;
                shell.handleLoadPackage(load);
            } catch (Throwable error) {
                framework.log(error);
            }
        }
    }

    private Object initLegacy(String name, String modulePath) {
        try {
            Class<?> type = Class.forName(name, true, ModernEntry.class.getClassLoader());
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
