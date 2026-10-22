package github.shadowbaby.wechatxposed.hook;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.IXposedHookZygoteInit;
import de.robv.android.xposed.callbacks.XC_LoadPackage;
import github.shadowbaby.wechatxposed.hook.framework.HookBootstrap;
import github.shadowbaby.wechatxposed.hook.framework.LegacyFramework;
import github.shadowbaby.wechatxposed.hook.license.Activation;
import github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;

public class XposedInit implements IXposedHookZygoteInit, IXposedHookLoadPackage {

    private final LegacyFramework framework = new LegacyFramework();

    @Override
    public void initZygote(StartupParam startupParam) {
        Activation.captureBuildIdentity();
        ModuleLogger.attach(framework);
        // 授权前不安装任何功能 hook，只记录模块路径。
        HookBootstrap.remember(startupParam.modulePath);
    }

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam param) {
        if (param.appInfo == null) {
            return;
        }
        HookBootstrap.onProcessReady(framework, param.packageName, param.processName,
                param.classLoader, param.appInfo.dataDir, param.appInfo.sourceDir);
    }
}
