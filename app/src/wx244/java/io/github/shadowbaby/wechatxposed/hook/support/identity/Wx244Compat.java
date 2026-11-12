package io.github.shadowbaby.wechatxposed.hook.support.identity;

import android.content.Context;
import android.content.ContextWrapper;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.Signature;
import android.content.res.AssetManager;
import android.util.Base64;
import io.github.shadowbaby.wechatxposed.hook.deploy.ModuleApk;
import io.github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import io.github.shadowbaby.wechatxposed.shared.hook.HookCallback;
import io.github.shadowbaby.wechatxposed.shared.hook.HookFramework;
import io.github.shadowbaby.wechatxposed.shared.hook.HookParam;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public final class Wx244Compat {

    private static final String SHELL_PACKAGE = "com.fkzhang.wechatxposed";

    private static final String SHELL_VERSION_NAME = "2.44";

    private static final int SHELL_VERSION_CODE = 111;

    private static volatile boolean installed;

    private static volatile boolean attached;

    private static volatile String shellPath;

    private static volatile byte[] certificate;

    private static volatile PackageInfo packageInfo;

    private Wx244Compat() {
    }

    public static synchronized void install(HookFramework framework) {
        if (installed) {
            return;
        }
        installed = true;
        try {
            Class<?> manager = framework.findClassIfExists(
                    "android.app.ApplicationPackageManager", null);
            if (manager != null) {
                hookPackageManager(framework, manager);
            }
            Class<?> base = framework.findClassIfExists("android.content.pm.PackageManager", null);
            if (base != null) {
                hookArchivePackageInfo(framework, base);
            }
            hookPackageContext(framework);
        } catch (Throwable error) {
            framework.log(error);
        }
    }

    public static synchronized void attach(String path) {
        if (path == null) {
            return;
        }
        shellPath = path;
        attached = true;
        certificate = certificate(path);
        packageInfo = null;
    }

    private static void hookPackageManager(HookFramework framework, Class<?> manager) {
        try {
            framework.hookMethod(manager, "getPackageInfo",
                    new Class<?>[]{String.class, int.class}, new HookCallback() {
                        @Override
                        public void before(HookParam param) {
                            if (matches(param.arg(0))) {
                                param.setResult(packageInfo());
                            }
                        }
                    });
            framework.hookMethod(manager, "getApplicationInfo",
                    new Class<?>[]{String.class, int.class}, new HookCallback() {
                        @Override
                        public void before(HookParam param) {
                            if (matches(param.arg(0))) {
                                param.setResult(packageInfo().applicationInfo);
                            }
                        }
                    });
            framework.hookMethod(manager, "getLaunchIntentForPackage",
                    new Class<?>[]{String.class}, new HookCallback() {
                        @Override
                        public void before(HookParam param) {
                            if (matches(param.arg(0))) {
                                param.setResult(null);
                            }
                        }
                    });
            if (!hasMethod(manager, "getPackageArchiveInfo",
                    String.class, int.class)) {
                return;
            }
            framework.hookMethod(manager, "getPackageArchiveInfo",
                    new Class<?>[]{String.class, int.class}, new HookCallback() {
                        @Override
                        public void after(HookParam param) {
                            if (param.result() instanceof PackageInfo info
                                    && matchesPath(param.arg(0))) {
                                disguise(info);
                            }
                        }
                    });
        } catch (Throwable error) {
            ModuleLogger.log("wx244 compat: " + error);
            framework.log(error);
        }
    }

    private static void hookArchivePackageInfo(HookFramework framework, Class<?> type) {
        for (Class<?>[] types : new Class<?>[][]{
                {String.class, int.class},
                {String.class, android.content.pm.PackageManager.PackageInfoFlags.class}}) {
            try {
                framework.hookMethod(type, "getPackageArchiveInfo", types, new HookCallback() {
                    @Override
                    public void after(HookParam param) {
                        if (!matchesPath(param.arg(0))) {
                            return;
                        }
                        PackageInfo info = param.result() instanceof PackageInfo value
                                ? value : packageInfo();
                        disguise(info);
                        param.setResult(info);
                        ModuleLogger.log("wx244 archive: " + param.arg(0));
                    }
                });
            } catch (Throwable error) {
                ModuleLogger.log("wx244 archive hook: " + error);
            }
        }
    }

    private static boolean hasMethod(Class<?> type, String name, Class<?>... types) {
        try {
            type.getDeclaredMethod(name, types);
            return true;
        } catch (Throwable error) {
            return false;
        }
    }

    private static void hookPackageContext(HookFramework framework) {
        for (String name : new String[]{"android.app.ContextImpl",
                "android.content.ContextWrapper"}) {
            Class<?> target = framework.findClassIfExists(name, null);
            if (target == null) {
                continue;
            }
            try {
                framework.hookMethod(target, "createPackageContext",
                        new Class<?>[]{String.class, int.class}, new HookCallback() {
                            @Override
                            public void before(HookParam param) {
                                Object value = param.arg(0);
                                if (!matches(value)) {
                                    return;
                                }
                                Context context = assetsContext(
                                        param.thisObject(), (String) value);
                                if (context != null) {
                                    param.setResult(context);
                                }
                            }
                        });
            } catch (Throwable error) {
                framework.log(error);
            }
        }
    }

    private static boolean matches(Object value) {
        if (!(value instanceof String name)) {
            return false;
        }
        if (SHELL_PACKAGE.equals(name)) {
            return true;
        }
        return hiddenPackage().equals(name) || isEncoded(name);
    }

    private static boolean matchesPath(Object value) {
        if (!(value instanceof String path)) {
            return false;
        }
        return (shellPath != null && shellPath.equals(path))
                || (ModuleApk.modulePath() != null && ModuleApk.modulePath().equals(path));
    }

    private static String hiddenPackage() {
        return "!#!%" + Base64.encodeToString(
                SHELL_PACKAGE.getBytes(StandardCharsets.UTF_8), Base64.NO_WRAP);
    }

    private static boolean isEncoded(String text) {
        for (int index = 0; index < text.length(); index++) {
            char current = text.charAt(index);
            if (current == '!' || current == '#' || current == '%'
                    || current == '$' || current == '&' || current == '@') {
                continue;
            }
            try {
                byte[] decoded = Base64.decode(text.substring(index), Base64.DEFAULT);
                return SHELL_PACKAGE.equals(new String(decoded, StandardCharsets.UTF_8));
            } catch (Throwable ignored) {
                return false;
            }
        }
        return false;
    }

    private static synchronized PackageInfo packageInfo() {
        if (packageInfo != null) {
            return packageInfo;
        }
        PackageInfo info = new PackageInfo();
        info.packageName = SHELL_PACKAGE;
        info.versionName = SHELL_VERSION_NAME;
        info.versionCode = SHELL_VERSION_CODE;
        info.applicationInfo = new ApplicationInfo();
        ApplicationInfo app = info.applicationInfo;
        app.packageName = SHELL_PACKAGE;
        String source = shellPath != null ? shellPath : ModuleApk.modulePath();
        app.sourceDir = source;
        app.publicSourceDir = source;
        app.dataDir = dataDir();
        app.nativeLibraryDir = app.dataDir + "/lib";
        app.processName = SHELL_PACKAGE;
        app.className = SHELL_PACKAGE + ".MainActivity";
        app.uid = android.os.Process.myUid();
        app.enabled = true;
        app.flags = ApplicationInfo.FLAG_HAS_CODE | ApplicationInfo.FLAG_INSTALLED;
        if (certificate != null) {
            info.signatures = new Signature[]{new Signature(certificate)};
        }
        packageInfo = info;
        return info;
    }

    private static void disguise(PackageInfo info) {
        info.packageName = SHELL_PACKAGE;
        info.versionName = SHELL_VERSION_NAME;
        info.versionCode = SHELL_VERSION_CODE;
        if (info.applicationInfo != null) {
            info.applicationInfo.packageName = SHELL_PACKAGE;
        }
        if (certificate != null) {
            info.signatures = new Signature[]{new Signature(certificate)};
        }
    }

    private static Context assetsContext(Object base, String name) {
        Context host = base instanceof Context ? (Context) base : currentApplication();
        if (host == null) {
            return null;
        }
        AssetManager manager = assets();
        return manager == null ? null : new AssetContext(host, manager, SHELL_PACKAGE);
    }

    private static AssetManager assets() {
        String path = ModuleApk.modulePath();
        if (path == null) {
            return null;
        }
        try {
            AssetManager manager = AssetManager.class.getDeclaredConstructor().newInstance();
            Method addAssetPath = AssetManager.class.getDeclaredMethod(
                    "addAssetPath", String.class);
            Object cookie = addAssetPath.invoke(manager, path);
            return cookie instanceof Integer && (Integer) cookie != 0 ? manager : null;
        } catch (Throwable error) {
            ModuleLogger.log("wx244 compat assets: " + error);
            return null;
        }
    }

    private static byte[] certificate(String path) {
        try (java.util.zip.ZipFile apk = new java.util.zip.ZipFile(path)) {
            java.util.zip.ZipEntry entry = apk.getEntry("META-INF/CERT.RSA");
            if (entry == null) {
                entry = apk.getEntry("META-INF/CERT.DSA");
            }
            if (entry == null) {
                return null;
            }
            try (InputStream input = apk.getInputStream(entry)) {
                CertificateFactory factory = CertificateFactory.getInstance("X.509");
                X509Certificate cert = (X509Certificate) factory.generateCertificate(input);
                return cert.getEncoded();
            }
        } catch (Throwable error) {
            ModuleLogger.log("wx244 compat certificate: " + error);
            return null;
        }
    }

    private static String dataDir() {
        Context context = currentApplication();
        return context == null ? "/data/user/0/" + SHELL_PACKAGE
                : context.getDataDir().getAbsolutePath();
    }

    private static Context currentApplication() {
        try {
            Class<?> activityThread = Class.forName("android.app.ActivityThread");
            Method method = activityThread.getDeclaredMethod("currentApplication");
            method.setAccessible(true);
            Object value = method.invoke(null);
            return value instanceof Context ? (Context) value : null;
        } catch (Throwable ignored) {
            return null;
        }
    }

    static final class AssetContext extends ContextWrapper {

        private final AssetManager assets;

        private final String packageName;

        AssetContext(Context base, AssetManager assets, String packageName) {
            super(base);
            this.assets = assets;
            this.packageName = packageName;
        }

        @Override
        public AssetManager getAssets() {
            return assets;
        }

        @Override
        public String getPackageName() {
            return packageName;
        }
    }
}