package github.shadowbaby.wechatxposed.hook.support.feature.version;

import android.content.pm.PackageInfo;
import android.os.Parcel;
import github.shadowbaby.wechatxposed.hook.framework.HookCallback;
import github.shadowbaby.wechatxposed.hook.framework.HookFramework;
import github.shadowbaby.wechatxposed.hook.framework.HookParam;
import github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import java.lang.reflect.Method;

/**
 * 小程序读的 versionName / versionCode 来自宿主 PackageInfo。
 *
 * 只改协议层 ClientVersion 覆盖不到 getSystemInfo，这里把 PackageManager
 * 返回的 PackageInfo 也替换成伪装版本。目标值不写死：从
 * {@link VersionWindow} 的 spoofed ClientVersion 里取 minor，和网络层保持一致。
 * 只处理 com.tencent.mm 自己，返回前先做 Parcel 复制，避免污染系统缓存。
 */
public final class PackageVersionSpoof {

    private static final String HOST_PACKAGE = "com.tencent.mm";

    /** 微信 major.minor 的固定前缀；minor 从 spoofed ClientVersion 取。 */
    private static final String NAME_PREFIX = "8.0.";

    /** 已知锚点：8.0.49 -> 2600，8.0.79 -> 3200，每 minor 20。 */
    private static final int CODE_BASE = 1620;

    private static final int CODE_STEP = 20;

    private static volatile HookFramework frameworkRef;

    private static volatile ClassLoader loaderRef;

    private static boolean installed;

    private PackageVersionSpoof() {
    }

    public static synchronized void install(HookFramework framework, ClassLoader classLoader) {
        if (installed) {
            return;
        }
        // 先占位，异常重试时不再重复挂已经成功的重载；类缺失则放回去允许重试。
        installed = true;
        try {
            Class<?> manager = framework.findClassIfExists(
                    "android.app.ApplicationPackageManager", null);
            if (manager == null) {
                installed = false;
                return;
            }
            frameworkRef = framework;
            loaderRef = classLoader;
            Callback callback = new Callback();
            int count = 0;
            for (Method method : manager.getDeclaredMethods()) {
                if (!"getPackageInfo".equals(method.getName())) {
                    continue;
                }
                Class<?>[] types = method.getParameterTypes();
                if (types.length < 2 || types[0] != String.class) {
                    continue;
                }
                framework.hookMethod(method, callback);
                count++;
            }
            ModuleLogger.log("package version spoof: " + count + " method(s)");
        } catch (Throwable error) {
            ModuleLogger.log(error);
        }
    }

    /** 当前伪装目标的 minor；拿不到返回 0，表示不改 PackageInfo。 */
    private static int targetMinor() {
        int spoofed = VersionWindow.spoofed();
        if (spoofed == 0) {
            HookFramework framework = frameworkRef;
            ClassLoader loader = loaderRef;
            if (framework == null || loader == null) {
                return 0;
            }
            VersionWindow.ensure(framework, loader);
            spoofed = VersionWindow.spoofed();
        }
        return spoofed == 0 ? 0 : (spoofed >>> 8) & 0xFF;
    }

    private static final class Callback implements HookCallback {

        @Override
        public void after(HookParam param) {
            Object name = param.arg(0);
            if (!(name instanceof String pkg) || !HOST_PACKAGE.equals(pkg)) {
                return;
            }
            if (!(param.result() instanceof PackageInfo info)) {
                return;
            }
            int minor = targetMinor();
            if (minor == 0) {
                return;
            }
            try {
                PackageInfo copy = copyOf(info);
                if (copy == null) {
                    return;
                }
                copy.versionName = NAME_PREFIX + minor;
                copy.versionCode = CODE_BASE + minor * CODE_STEP;
                param.setResult(copy);
            } catch (Throwable error) {
                ModuleLogger.log(error);
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
