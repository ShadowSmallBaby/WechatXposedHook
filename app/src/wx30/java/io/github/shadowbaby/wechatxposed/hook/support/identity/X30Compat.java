package io.github.shadowbaby.wechatxposed.hook.support.identity;

import android.content.ComponentName;
import android.content.pm.PackageInfo;
import android.content.pm.Signature;
import android.util.Base64;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import io.github.shadowbaby.wechatxposed.hook.BuildConfig;
import io.github.shadowbaby.wechatxposed.hook.loader.SecretConstants;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public final class X30Compat {

    private static final String SHELL_PACKAGE = "cn.android.x";

    private static final String MODULE_PACKAGE = SecretConstants.MODULE_PACKAGE;

    private static final String ORIGINAL_CERT_B64 = "MIIE6AYJKoZIhvcNAQcCoIIE2TCCBNUCAQExCzAJBgUrDgMCGgUAMAsGCSqGSIb3DQEHAaCCAzcwggMzMIICG6ADAgECAgRGfFhrMA0GCSqGSIb3DQEBCwUAMEoxCzAJBgNVBAYTAk5MMRMwEQYDVQQIEwpHZWxkZXJsYW5kMQ8wDQYDVQQHEwZBcm5oZW0xFTATBgNVBAMTDEZhbmthaSBaaGFuZzAeFw0xNTExMjAxNzI5MzlaFw00MDExMTMxNzI5MzlaMEoxCzAJBgNVBAYTAk5MMRMwEQYDVQQIEwpHZWxkZXJsYW5kMQ8wDQYDVQQHEwZBcm5oZW0xFTATBgNVBAMTDEZhbmthaSBaaGFuZzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJvHN88d5rBMxfSMvXRTiMF3lTisjhF3qb6IDhuBbVEMLb6hB57JatkLp9QxbUIc4nGM9LRib++WWm2q3Nr2qYrCtqwYCqoZy35HIfWxx+AbzPSK3lYJU0FBAokelbWBMGF28Iyc2IFN1B/WbTsqeeuhll3pggBXKknmWM76utDBKDR494r/7EgpfkHQU6MmvSVjc8WfuNWBdQPprbn/fIxlLaKoH3mL8f9V/SSjKYP1sf8oRK2gBpiwlOcUx0jA/AHhVDr8kOf99kkYWXcM+200j0/+3Yr16Fjo8d+c8T52rHZrVpn1fR8iT5BvM7N25Xh/hOIUGnUkXzSYPxXrdp0CAwEAAaMhMB8wHQYDVR0OBBYEFPjNRzmSD1bnrpFnuV4+YGLTH8rnMA0GCSqGSIb3DQEBCwUAA4IBAQAqpUD47S9uJ5u65gLk1ZzrXHwUxUJXHUR+LrQgtyhANF5r2LW14MXMiHAc6DbJNYYrafI1MHu0fWkNwr0LVsQh5R5HERV1H5KJ5ZCVpsFNDMNEHqhKYOgSqjkmnA+1fIVvUZKkxJRt0bBkd0KluOdO+chLKPtrhyzZF/E4YaYGxUbjZPOmbk3Cre9DhrjdKP/PqA4HCcTm4S9SgZBn1fJNqCnTn2H86JIs5zngrsUItoGRvwsLA7DhBOwI3QgA9+o6w4+PjTO4lJjsXSIWT/aywaWXkHIudkI6yzYpxxz81sLyYqf/t6Zm7qMX2HcStwSYZm4/QsKu9lwioqc1q7PpMYIBeTCCAXUCAQEwUjBKMQswCQYDVQQGEwJOTDETMBEGA1UECBMKR2VsZGVybGFuZDEPMA0GA1UEBxMGQXJuaGVtMRUwEwYDVQQDEwxGYW5rYWkgWmhhbmcCBEZ8WGswCQYFKw4DAhoFADANBgkqhkiG9w0BAQEFAASCAQAbJVDLy9xdW8dmpKbUX3rr8HS9S5mFO/VQIK1Kxt3PehFrmYzlnmVp3tRG0mqaleeUbx7UlSMPOpnGMHNvIt/hmZaYXrIHbEmZuKxsCkXnIlmkgdGb4HAhbfuv8HeqG7HYcFc5JF3w247v1+ITsus+l6buKZ+gCo5FE411S+aeeI+moYUb4CM7AsYO0kq+uEolXTUYEhDpd3bKPYDIOqpfVF7ADw+302zNDnGYJx5xKfuDDmhzKe1iTIyNV7tUhpayWdmxzQ38V8C5HX5ofPUuA+EjQGZZi83GmzVQonXqCHP50eaX/BkiFiv09XraqYKJN9joZLQzXDZN0UoXNSy8";

    private static final String ORIGINAL_CERT_ASSET =
            "assets/8af2692bdcb8661da163b4204b5f5d5e";

    private static final String[] PACKAGE_LOOKUPS = {
            "getPackageInfo", "getApplicationInfo", "getLaunchIntentForPackage"};

    private static volatile Certificate originalCertificate;

    private static volatile byte[] originalCertificateDer;

    private static volatile byte[] moduleCertificateDer;

    private static volatile String moduleApkPath;

    private static volatile ClassLoader shellLoader;

    private static final ThreadLocal<Boolean> RAW_LOOKUP =
            ThreadLocal.withInitial(() -> Boolean.FALSE);

    private static final java.util.concurrent.atomic.AtomicBoolean INITIALIZED =
            new java.util.concurrent.atomic.AtomicBoolean();

    public static void install(String modulePath) {
        try {
            String process = currentProcessName();
            XposedBridge.log("WeXposedHook-> x30 process: " + process);
            if (MODULE_PACKAGE.equals(process)) {

                XposedBridge.log("WeXposedHook-> x30 compat skip: module process");
                return;
            }
            if (!INITIALIZED.compareAndSet(false, true)) {

                XposedBridge.log("WeXposedHook-> x30 compat already initialized");
                return;
            }
            moduleApkPath = modulePath;
            captureModuleCert(moduleApkPath);
            hookPackageContext("android.content.ContextWrapper");
            hookPackageContext("android.app.ContextImpl");
            hookPackageManager("android.app.ApplicationPackageManager");
            hookIntent("android.content.Intent");
            hookPackageName();
            hookArchivePaths();
            hookZipLookups();
            hookShellCertHelper();
            hookCertificates();
            hookPackageInfoSignatures();
            hookArchiveInfo();

            XposedBridge.log("WeXposedHook-> x30 compat installed: " + MODULE_PACKAGE);
        } catch (Throwable error) {
            XposedBridge.log(error);
        }
    }

    private static volatile String processNameCache;

    private static boolean isPlaceholderProcessName(String name) {
        return name == null || name.isEmpty()
                || "zygote".equals(name) || "zygote64".equals(name)
                || "usap64".equals(name)

                || name.startsWith("<");
    }

    private static String currentProcessName() {
        String cached = processNameCache;
        if (!isPlaceholderProcessName(cached)) {
            return cached;
        }

        if (android.os.Build.VERSION.SDK_INT >= 28) {
            try {
                String name = android.app.Application.getProcessName();
                if (!isPlaceholderProcessName(name)) {
                    processNameCache = name;
                    return name;
                }
            } catch (Throwable ignored) {

            }
        }
        try (java.io.FileInputStream input =
                     new java.io.FileInputStream("/proc/self/cmdline")) {
            byte[] data = new byte[128];
            int read = input.read(data);
            if (read > 0) {
                int end = 0;
                while (end < read && data[end] != 0) {
                    end++;
                }
                String name = new String(data, 0, end, StandardCharsets.UTF_8);

                if (!isPlaceholderProcessName(name)) {
                    processNameCache = name;
                }
                return name;
            }
        } catch (Throwable ignored) {

        }
        return "";
    }

    private static boolean isModuleProcessRuntime() {
        String name = currentProcessName();
        return MODULE_PACKAGE.equals(name) || name.startsWith(MODULE_PACKAGE + ":");
    }

    private static void hookPackageName() {
        for (String name : new String[]{
                "android.content.ContextWrapper", "android.app.ContextImpl"}) {
            Class<?> target = XposedHelpers.findClassIfExists(name, null);
            if (target == null) {
                continue;
            }
            XposedBridge.hookAllMethods(target, "getPackageName", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    if (isModuleProcessRuntime()) {
                        return;
                    }
                    if (MODULE_PACKAGE.equals(param.getResult())) {
                        param.setResult(SHELL_PACKAGE);
                    }
                }
            });
        }
    }

    private static void hookArchivePaths() {
        Class<?> jar = XposedHelpers.findClassIfExists("java.util.jar.JarFile", null);
        if (jar != null) {
            XposedBridge.hookAllConstructors(jar, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    replaceArchivePath(param);
                }
            });
        }
        Class<?> zip = XposedHelpers.findClassIfExists("java.util.zip.ZipFile", null);
        if (zip != null) {
            XposedBridge.hookAllConstructors(zip, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    replaceArchivePath(param);
                }
            });
        }
    }

    private static void replaceArchivePath(XC_MethodHook.MethodHookParam param) {
        if (isModuleProcessRuntime()) {
            return;
        }
        String current = moduleApkPath;
        if (current == null || param.args.length == 0) {
            return;
        }
        Object first = param.args[0];
        if (first instanceof String path) {
            if (isStaleModulePath(path, current)) {
                param.args[0] = current;
            }
        } else if (first instanceof java.io.File) {
            String path = ((java.io.File) first).getAbsolutePath();
            if (isStaleModulePath(path, current)) {
                param.args[0] = new java.io.File(current);
            }
        }
    }

    private static void hookZipLookups() {
        Class<?> zip = XposedHelpers.findClassIfExists("java.util.zip.ZipFile", null);
        if (zip != null) {
            XposedBridge.hookAllMethods(zip, "getEntry", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    mapSignatureEntry(param);
                }
            });
        }
        Class<?> jar = XposedHelpers.findClassIfExists("java.util.jar.JarFile", null);
        if (jar != null) {
            XposedBridge.hookAllMethods(jar, "getJarEntry", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    mapSignatureEntry(param);
                }
            });
        }
    }

    private static void mapSignatureEntry(XC_MethodHook.MethodHookParam param) {
        if (isModuleProcessRuntime()) {
            return;
        }
        if (param.args.length == 0 || !(param.args[0] instanceof String name)) {
            return;
        }
        String upper = name.toUpperCase();
        if (!upper.startsWith("META-INF/") || !upper.endsWith(".RSA")
                || upper.contains("COM_TENC")) {
            return;
        }
        if (isModuleOwner(param.thisObject)) {
            param.args[0] = ORIGINAL_CERT_ASSET;
        }
    }

    private static boolean isStaleModulePath(String path, String current) {
        return path != null
                && path.contains(MODULE_PACKAGE)
                && path.endsWith(".apk")
                && !path.equals(current);
    }

    private static void captureModuleCert(String modulePath) {
        if (modulePath == null || modulePath.isEmpty()) {
            XposedBridge.log("WeXposedHook-> x30 module path empty");
            return;
        }
        try {
            try (java.util.jar.JarFile jar = new java.util.jar.JarFile(modulePath)) {
                java.util.jar.JarEntry entry = jar.getJarEntry("AndroidManifest.xml");
                Certificate[] certificates = entry == null ? null : entry.getCertificates();
                if (certificates != null && certificates.length > 0) {
                    moduleCertificateDer = certificates[0].getEncoded();
                }
            }
            if (moduleCertificateDer == null) {
                moduleCertificateDer = decodeModuleCert();
            }
            XposedBridge.log("WeXposedHook-> x30 module cert len="
                    + (moduleCertificateDer == null ? -1 : moduleCertificateDer.length)
                    + " path=" + modulePath);
        } catch (Throwable error) {
            moduleCertificateDer = decodeModuleCert();
            XposedBridge.log("WeXposedHook-> x30 module cert unavailable: " + modulePath);
            XposedBridge.log(error);
        }
    }

    private static byte[] decodeModuleCert() {
        try {
            return Base64.decode(BuildConfig.MODULE_CERT_B64, Base64.DEFAULT);
        } catch (Throwable ignored) {
        }
        String path = moduleApkPath;
        if (path == null) {
            return null;
        }
        try (ZipFile apk = new ZipFile(path)) {
            ZipEntry entry = apk.getEntry("META-INF/CERT.RSA");
            if (entry == null) {
                entry = apk.getEntry("META-INF/CERT.DSA");
            }
            if (entry == null) {
                entry = apk.getEntry("META-INF/CERT.EC");
            }
            if (entry == null) {
                return null;
            }
            try (java.io.InputStream input = apk.getInputStream(entry)) {
                CertificateFactory factory = CertificateFactory.getInstance("X.509");
                Certificate certificate = factory.generateCertificate(input);
                return certificate.getEncoded();
            }
        } catch (Throwable ignored) {
            return null;
        }
    }

    public static void attach(ClassLoader loader) {
        shellLoader = loader;
        hookShellCertHelper();
    }

    private static void hookShellCertHelper() {
        ClassLoader loader = shellLoader != null
                ? shellLoader : X30Compat.class.getClassLoader();
        Class<?> helper = XposedHelpers.findClassIfExists(
                "x.ⁱᵢ.ᐧʿ", loader);
        if (helper == null) {
            XposedBridge.log("WeXposedHook-> x30 cert helper not found");
            return;
        }
        try {
            XposedBridge.hookAllMethods(helper, "ˎٴ", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    if (param.args.length > 0 && param.args[0] instanceof String) {
                        param.setResult(originalCertificateDer());
                    }
                }
            });
            XposedBridge.log("WeXposedHook-> x30 cert helper hooked");
        } catch (Throwable error) {
            XposedBridge.log(error);
        }
    }

    private static void hookPackageContext(String className) {
        Class<?> target = XposedHelpers.findClassIfExists(className, null);
        if (target == null) {
            return;
        }
        XposedBridge.hookAllMethods(target, "createPackageContext", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) {
                replace(param, 0);
            }
        });
    }

    private static void hookPackageManager(String className) {
        Class<?> target = XposedHelpers.findClassIfExists(className, null);
        if (target == null) {
            return;
        }
        for (String name : PACKAGE_LOOKUPS) {
            XposedBridge.hookAllMethods(target, name, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    replace(param, 0);
                }
            });
        }
    }

    private static void hookIntent(String className) {
        Class<?> target = XposedHelpers.findClassIfExists(className, null);
        if (target == null) {
            return;
        }
        XposedBridge.hookAllMethods(target, "setClassName", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) {
                replace(param, 0);
            }
        });
        XposedBridge.hookAllMethods(target, "setComponent", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) {
                if (param.args.length == 0 || !(param.args[0] instanceof ComponentName component)) {
                    return;
                }
                if (SHELL_PACKAGE.equals(component.getPackageName())) {
                    param.args[0] = new ComponentName(MODULE_PACKAGE, component.getClassName());
                }
            }
        });
    }

    private static void hookCertificates() {
        Class<?> entry = XposedHelpers.findClassIfExists("java.util.jar.JarEntry", null);
        if (entry != null) {
            XposedBridge.hookAllMethods(entry, "getCertificates", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    replaceCertificates(param);
                }
            });
        }
        Class<?> jar = XposedHelpers.findClassIfExists("java.util.jar.JarFile", null);
        if (jar != null) {
            XposedBridge.hookAllMethods(jar, "getCertificates", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    replaceCertificates(param);
                }
            });
        }
        Class<?> signature = XposedHelpers.findClassIfExists(
                "android.content.pm.Signature", null);
        if (signature != null) {
            XposedBridge.hookAllMethods(signature, "toByteArray", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    Object result = param.getResult();
                    if (result instanceof byte[] && isModuleCert((byte[]) result)) {
                        param.setResult(originalCertificateDer());
                    }
                }
            });
        }
        for (String name : new String[]{
                "java.security.cert.Certificate",
                "java.security.cert.X509Certificate",
                "com.android.org.conscrypt.OpenSSLX509Certificate"}) {
            Class<?> certificate = XposedHelpers.findClassIfExists(name, null);
            if (certificate == null) {
                continue;
            }
            try {
                XposedBridge.hookAllMethods(certificate, "getEncoded", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        Object result = param.getResult();
                        if (result instanceof byte[] && isModuleCert((byte[]) result)) {
                            param.setResult(originalCertificateDer());
                        }
                    }
                });
            } catch (Throwable ignored) {

            }
        }
    }

    private static void replaceCertificates(XC_MethodHook.MethodHookParam param) {
        if (isModuleProcessRuntime()) {
            return;
        }
        Object result = param.getResult();
        if (result instanceof Certificate[] certificates) {
            for (Certificate certificate : certificates) {
                if (isModuleCertificate(certificate)) {
                    Certificate original = originalCertificate();
                    if (original != null) {
                        param.setResult(new Certificate[]{original});
                    }
                    return;
                }
            }
            return;
        }
        if (result == null && isModuleOwner(param.thisObject)) {
            Certificate original = originalCertificate();
            if (original != null) {
                param.setResult(new Certificate[]{original});
            }
        }
    }

    private static boolean isModuleOwner(Object owner) {
        if (owner == null) {
            return false;
        }
        if (owner instanceof java.util.zip.ZipFile) {
            return isModuleJar(owner);
        }
        if (owner instanceof java.util.jar.JarEntry) {
            try {
                java.lang.reflect.Field field = owner.getClass().getDeclaredField("parent");
                field.setAccessible(true);
                return isModuleJar(field.get(owner));
            } catch (Throwable ignored) {
                return false;
            }
        }
        return false;
    }

    private static boolean isModuleJar(Object jar) {
        if (!(jar instanceof java.util.zip.ZipFile)) {
            return false;
        }
        try {
            String name = ((java.util.zip.ZipFile) jar).getName();
            if (name == null) {
                return false;
            }

            return name.contains(MODULE_PACKAGE);
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static boolean isModuleCertificate(Certificate certificate) {
        try {
            return isModuleCert(certificate.getEncoded());
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static boolean isModuleCert(byte[] der) {
        byte[] module = moduleCertificateDer;
        if (module == null) {
            module = decodeModuleCert();
            moduleCertificateDer = module;
        }
        if (module == null || der == null || der.length != module.length) {
            return false;
        }
        for (int index = 0; index < der.length; index++) {
            if (der[index] != module[index]) {
                return false;
            }
        }
        return true;
    }

    private static void hookPackageInfoSignatures() {
        Class<?> manager = XposedHelpers.findClassIfExists(
                "android.app.ApplicationPackageManager", null);
        if (manager == null) {
            XposedBridge.log("WeXposedHook-> x30 package manager not found");
            return;
        }
        try {
            XposedBridge.hookAllMethods(manager, "getPackageInfo", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    if (isModuleProcessRuntime()) {
                        return;
                    }
                    if (param.args.length == 0 || Boolean.TRUE.equals(RAW_LOOKUP.get())) {
                        return;
                    }
                    Object requested = param.args[0];
                    if (!MODULE_PACKAGE.equals(requested) && !isShellPackage(requested)) {
                        return;
                    }
                    if (!(param.getResult() instanceof PackageInfo info)) {
                        return;
                    }

                    disguiseAsShell(info);
                }
            });
            XposedBridge.log("WeXposedHook-> x30 package info hooked");
        } catch (Throwable error) {
            XposedBridge.log(error);
        }
    }

    private static void hookArchiveInfo() {
        Class<?> manager = XposedHelpers.findClassIfExists(
                "android.app.ApplicationPackageManager", null);
        if (manager == null) {
            return;
        }
        for (String name : new String[]{"getPackageArchiveInfo", "getPackageArchiveInfoAsUser"}) {
            try {
                XposedBridge.hookAllMethods(manager, name, new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        if (isModuleProcessRuntime()) {
                            return;
                        }
                        if (param.args.length == 0
                                || !(param.args[0] instanceof String path)) {
                            return;
                        }
                        if (!path.contains(MODULE_PACKAGE) && !path.contains(SHELL_PACKAGE)) {
                            return;
                        }
                        if (!(param.getResult() instanceof PackageInfo info)) {
                            return;
                        }
                        disguiseAsShell(info);
                        XposedBridge.log("WeXposedHook-> x30 archive info mapped: " + path);
                    }
                });
            } catch (Throwable ignored) {

            }
        }
    }

    @SuppressWarnings("deprecation")
    private static void disguiseAsShell(PackageInfo info) {
        info.packageName = SHELL_PACKAGE;
        info.signatures = new Signature[]{new Signature(originalCertificateDer())};
    }

    private static Certificate originalCertificate() {
        Certificate cached = originalCertificate;
        if (cached != null) {
            return cached;
        }
        synchronized (X30Compat.class) {
            if (originalCertificate == null) {
                try {
                    CertificateFactory factory = CertificateFactory.getInstance("X.509");
                    originalCertificate = factory.generateCertificate(
                            new ByteArrayInputStream(originalCertificateDer()));
                } catch (Throwable error) {
                    XposedBridge.log(error);
                }
            }
            return originalCertificate;
        }
    }

    private static byte[] originalCertificateDer() {
        byte[] cached = originalCertificateDer;
        if (cached != null) {
            return cached;
        }
        synchronized (X30Compat.class) {
            if (originalCertificateDer == null) {
                originalCertificateDer = Base64.decode(ORIGINAL_CERT_B64, Base64.DEFAULT);
            }
            return originalCertificateDer;
        }
    }

    private static boolean isShellPackage(Object value) {
        if (!(value instanceof String text)) {
            return false;
        }
        if (SHELL_PACKAGE.equals(text)) {
            return true;
        }
        for (int index = 0; index < text.length(); index++) {
            char current = text.charAt(index);
            if (current == '!' || current == '#' || current == '%'
                    || current == '$' || current == '&' || current == '@') {
                continue;
            }
            try {
                byte[] decoded = Base64.decode(text.substring(index), Base64.DEFAULT);
                if (SHELL_PACKAGE.equals(new String(decoded,
                        java.nio.charset.StandardCharsets.UTF_8))) {
                    return true;
                }
            } catch (Throwable ignored) {

            }
            break;
        }
        return false;
    }

    private static void replace(XC_MethodHook.MethodHookParam param, int index) {
        if (Boolean.TRUE.equals(RAW_LOOKUP.get())) {
            return;
        }
        if (param.args.length <= index || !isShellPackage(param.args[index])) {
            return;
        }
        param.args[index] = MODULE_PACKAGE;
    }
}
