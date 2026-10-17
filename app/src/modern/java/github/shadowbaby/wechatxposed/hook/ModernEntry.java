package github.shadowbaby.wechatxposed.hook;

import github.shadowbaby.wechatxposed.hook.framework.HookBootstrap;
import github.shadowbaby.wechatxposed.hook.framework.ModernFramework;
import github.shadowbaby.wechatxposed.hook.loader.ModuleLogger;
import io.github.libxposed.api.XposedModule;
import io.github.libxposed.api.XposedModuleInterface.ModuleLoadedParam;
import io.github.libxposed.api.XposedModuleInterface.PackageReadyParam;
import java.lang.reflect.Method;

public class ModernEntry extends XposedModule {

    private final ModernFramework framework = new ModernFramework(this);

    @Override
    public void onModuleLoaded(ModuleLoadedParam param) {
        ModuleLogger.attach(framework);
        HookBootstrap.installZygote(framework, getModuleApplicationInfo().sourceDir);
    }

    @Override
    public void onPackageReady(PackageReadyParam param) {
        HookBootstrap.onProcessReady(framework, param.getPackageName(), currentProcessName(),
                param.getClassLoader(), param.getApplicationInfo().dataDir,
                param.getApplicationInfo().sourceDir);
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
