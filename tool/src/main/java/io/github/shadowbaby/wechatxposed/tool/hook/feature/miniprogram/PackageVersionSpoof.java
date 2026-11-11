package io.github.shadowbaby.wechatxposed.tool.hook.feature.miniprogram;

import static io.github.shadowbaby.wechatxposed.tool.hook.spoof.HostFingerprint.*;

import io.github.shadowbaby.wechatxposed.shared.hook.HookCallback;
import io.github.shadowbaby.wechatxposed.shared.hook.HookFramework;
import io.github.shadowbaby.wechatxposed.shared.hook.HookParam;
import io.github.shadowbaby.wechatxposed.tool.hook.config.RuntimeSettings;
import io.github.shadowbaby.wechatxposed.tool.hook.config.ToolSettings;
import io.github.shadowbaby.wechatxposed.tool.hook.framework.ToolLogger;

import android.content.pm.PackageInfo;
import android.os.Parcel;
import java.lang.reflect.Method;


public final class PackageVersionSpoof {

    private static final String HOST_PACKAGE = fp("host.package.hostPackage.mmClass");


    private static final int CODE_BASE = fpInt("host.package.codeBase.versionCodeBase");
    private static final int CODE_STEP = fpInt("host.package.codeStep.versionCodeStep");

    private static boolean installed;

    private PackageVersionSpoof() {
    }

    public static synchronized void install(HookFramework framework, ClassLoader classLoader) {
        if (installed) {
            return;
        }

        installed = true;
        try {
            Class<?> manager = framework.findClassIfExists(
                    fp("host.package.manager.applicationPackageManagerClass"), null);
            if (manager == null) {
                installed = false;
                return;
            }
            Callback callback = new Callback();
            int count = 0;
            for (Method method : manager.getDeclaredMethods()) {
                if (!fp("host.package.install.getPackageInfo").equals(method.getName())) {
                    continue;
                }
                Class<?>[] types = method.getParameterTypes();
                if (types.length < 2 || types[0] != String.class) {
                    continue;
                }
                framework.hookMethod(method, callback);
                count++;
            }
            ToolLogger.log("package version spoof: " + count + " method(s)");
        } catch (Throwable error) {
            ToolLogger.log(error);
        }
    }


    private static int targetMinor(ToolSettings settings) {
        if (!settings.enabled || settings.miniProgramMode != ToolSettings.MINI_JSAPI) {
            return 0;
        }
        int spoofed = settings.targetVersion;
        return spoofed == 0 ? 0 : (spoofed >>> 8) & 0xFF;
    }

    private static final class Callback implements HookCallback {

        @Override
        public void after(HookParam param) {
            Object name = param.arg(fpInt("host.package.name.zero"));
            if (!(name instanceof String pkg) || !HOST_PACKAGE.equals(pkg)) {
                return;
            }
            if (param.hasThrowable() || !(param.result() instanceof PackageInfo info)) {
                return;
            }
            ToolSettings settings = RuntimeSettings.get();
            int minor = targetMinor(settings);
            if (minor == 0) {
                return;
            }
            try {
                PackageInfo copy = copyOf(info);
                if (copy == null) {
                    return;
                }
                copy.versionName = settings.targetVersionName;
                copy.versionCode = CODE_BASE + minor * CODE_STEP;
                param.setResult(copy);
            } catch (Throwable error) {
                ToolLogger.log(error);
            }
        }
    }

    private static PackageInfo copyOf(PackageInfo info) {
        Parcel parcel = Parcel.obtain();
        try {
            info.writeToParcel(parcel, 0);
            parcel.setDataPosition(0);
            return PackageInfo.CREATOR.createFromParcel(parcel);
        } finally {
            parcel.recycle();
        }
    }
}
