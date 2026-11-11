package io.github.shadowbaby.wechatxposed.tool.module;

import android.app.Application;
import android.content.Context;
import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.IXposedHookZygoteInit;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.callbacks.XC_LoadPackage;
import io.github.shadowbaby.wechatxposed.tool.hook.framework.LegacyFramework;
import java.util.concurrent.atomic.AtomicBoolean;


public final class LegacyEntry implements IXposedHookLoadPackage, IXposedHookZygoteInit {
    private static volatile String modulePath;
    private static final AtomicBoolean STARTED = new AtomicBoolean();

    @Override public void initZygote(StartupParam param) { modulePath = param.modulePath; }

    @Override public void handleLoadPackage(XC_LoadPackage.LoadPackageParam param) throws Throwable {
        if (!"com.tencent.mm".equals(param.packageName)) return;
        String process = param.processName;
        if (!"com.tencent.mm".equals(process) && !"com.tencent.mm:appbrand0".equals(process)
                && !"com.tencent.mm:appbrand1".equals(process)) return;
        XposedBridge.hookMethod(Application.class.getDeclaredMethod("attach", Context.class), new XC_MethodHook() {
            @Override protected void afterHookedMethod(MethodHookParam attached) {
                if (attached.hasThrowable() || !STARTED.compareAndSet(false, true)) return;
                Context context = (Context) attached.args[0];
                if (modulePath == null) {
                    XposedBridge.log("WeXposedTool-> legacy entry: module path unavailable");
                    return;
                }
                HostRuntime.start(new LegacyFramework(), context.getClassLoader(),
                        new LegacySettingsSource(context), modulePath, param.packageName);
            }
        });
    }
}
