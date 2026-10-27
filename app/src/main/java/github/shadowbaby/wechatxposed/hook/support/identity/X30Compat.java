package github.shadowbaby.wechatxposed.hook.support.identity;

import android.content.ComponentName;
import android.content.pm.PackageInfo;
import android.content.pm.Signature;
import android.util.Base64;
import de.robv.android.xposed.IXposedHookZygoteInit;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import github.shadowbaby.wechatxposed.hook.loader.SecretConstants;
import github.shadowbaby.wechatxposed.hook.loader.util.Secret;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

/**
 * X 3.0 壳的包名/签名兼容层。
 *
 * 壳内部用常量 "cn.android.x" 取自身 Context / PackageInfo，并用模块 APK 的签名证书
 * 派生 params（xmd/739440...）的解密密钥。复刻 APK 改了包名和签名，这里：
 *   1. 把 "cn.android.x" 的 Context/PackageInfo 查询重定向到本包；
 *   2. 对来自本 APK 的 JarEntry/PackageInfo 返回原版 X 3.0 的签名证书，
 *      让壳继续用原版密钥解密项目包。
 *
 * 包名与证书由 scripts/build_x30_replica.py 在编译前替换。
 */
public final class X30Compat implements IXposedHookZygoteInit {

    private static final String SHELL_PACKAGE = Secret.of(SecretConstants.SHELL_PACKAGE);

    private static final String SHELL_ENTRY = Secret.of(SecretConstants.SHELL_ENTRY);

    private static final String MODULE_PACKAGE = Secret.of(SecretConstants.MODULE_PACKAGE);

    private static final String ORIGINAL_CERT_B64 = "MIIE6AYJKoZIhvcNAQcCoIIE2TCCBNUCAQExCzAJBgUrDgMCGgUAMAsGCSqGSIb3DQEHAaCCAzcwggMzMIICG6ADAgECAgRGfFhrMA0GCSqGSIb3DQEBCwUAMEoxCzAJBgNVBAYTAk5MMRMwEQYDVQQIEwpHZWxkZXJsYW5kMQ8wDQYDVQQHEwZBcm5oZW0xFTATBgNVBAMTDEZhbmthaSBaaGFuZzAeFw0xNTExMjAxNzI5MzlaFw00MDExMTMxNzI5MzlaMEoxCzAJBgNVBAYTAk5MMRMwEQYDVQQIEwpHZWxkZXJsYW5kMQ8wDQYDVQQHEwZBcm5oZW0xFTATBgNVBAMTDEZhbmthaSBaaGFuZzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJvHN88d5rBMxfSMvXRTiMF3lTisjhF3qb6IDhuBbVEMLb6hB57JatkLp9QxbUIc4nGM9LRib++WWm2q3Nr2qYrCtqwYCqoZy35HIfWxx+AbzPSK3lYJU0FBAokelbWBMGF28Iyc2IFN1B/WbTsqeeuhll3pggBXKknmWM76utDBKDR494r/7EgpfkHQU6MmvSVjc8WfuNWBdQPprbn/fIxlLaKoH3mL8f9V/SSjKYP1sf8oRK2gBpiwlOcUx0jA/AHhVDr8kOf99kkYWXcM+200j0/+3Yr16Fjo8d+c8T52rHZrVpn1fR8iT5BvM7N25Xh/hOIUGnUkXzSYPxXrdp0CAwEAAaMhMB8wHQYDVR0OBBYEFPjNRzmSD1bnrpFnuV4+YGLTH8rnMA0GCSqGSIb3DQEBCwUAA4IBAQAqpUD47S9uJ5u65gLk1ZzrXHwUxUJXHUR+LrQgtyhANF5r2LW14MXMiHAc6DbJNYYrafI1MHu0fWkNwr0LVsQh5R5HERV1H5KJ5ZCVpsFNDMNEHqhKYOgSqjkmnA+1fIVvUZKkxJRt0bBkd0KluOdO+chLKPtrhyzZF/E4YaYGxUbjZPOmbk3Cre9DhrjdKP/PqA4HCcTm4S9SgZBn1fJNqCnTn2H86JIs5zngrsUItoGRvwsLA7DhBOwI3QgA9+o6w4+PjTO4lJjsXSIWT/aywaWXkHIudkI6yzYpxxz81sLyYqf/t6Zm7qMX2HcStwSYZm4/QsKu9lwioqc1q7PpMYIBeTCCAXUCAQEwUjBKMQswCQYDVQQGEwJOTDETMBEGA1UECBMKR2VsZGVybGFuZDEPMA0GA1UEBxMGQXJuaGVtMRUwEwYDVQQDEwxGYW5rYWkgWmhhbmcCBEZ8WGswCQYFKw4DAhoFADANBgkqhkiG9w0BAQEFAASCAQAbJVDLy9xdW8dmpKbUX3rr8HS9S5mFO/VQIK1Kxt3PehFrmYzlnmVp3tRG0mqaleeUbx7UlSMPOpnGMHNvIt/hmZaYXrIHbEmZuKxsCkXnIlmkgdGb4HAhbfuv8HeqG7HYcFc5JF3w247v1+ITsus+l6buKZ+gCo5FE411S+aeeI+moYUb4CM7AsYO0kq+uEolXTUYEhDpd3bKPYDIOqpfVF7ADw+302zNDnGYJx5xKfuDDmhzKe1iTIyNV7tUhpayWdmxzQ38V8C5HX5ofPUuA+EjQGZZi83GmzVQonXqCHP50eaX/BkiFiv09XraqYKJN9joZLQzXDZN0UoXNSy8";

    private static final String MODULE_CERT_B64 = "MIIEhDCCAuygAwIBAgIJANqI/MnszZ5kMA0GCSqGSIb3DQEBDAUAMG8xCzAJBgNVBAYTAkNOMREwDwYDVQQIEwhaaGVKaWFuZzEPMA0GA1UEBxMGTmluZ0JvMRMwEQYDVQQKEwpCYWJ5IEdyb3VwMRMwEQYDVQQLEwpCYWJ5IEdyb3VwMRIwEAYDVQQDEwlTbWFsbGJhYnkwIBcNMjYxMDE1MDYxNDU5WhgPMjA1NDAzMDIwNjE0NTlaMG8xCzAJBgNVBAYTAkNOMREwDwYDVQQIEwhaaGVKaWFuZzEPMA0GA1UEBxMGTmluZ0JvMRMwEQYDVQQKEwpCYWJ5IEdyb3VwMRMwEQYDVQQLEwpCYWJ5IEdyb3VwMRIwEAYDVQQDEwlTbWFsbGJhYnkwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQC3auBn3WsFSYW5rZup64FY6Ic/4zDt9BP1oIRFA9RuA3+InPojokwZNHMSZdTICw4Tlc9QnCjR4SrsjkLlLSGk4vlhME3NtW5RarIRQ3FNPpgLnlU6xePTHrpy8+/S73N2hVO29B6IROLNGCFx0jGCSHdlt1LaevsBeNnOhOesXsUiUhyAPsqdzT3Q/hM+0c/exOMFJ/yZ7hLTlAy8Wn5v6oKOZCKMQoanQaIBTuwvI1cpgP6rcoifdJ5ksdYddvtE2lDvIq4dnoOJrmnub3/jLwymqVNc9HkiYPdXuXhijaOI9KCWbnksHHoHOWx7G9tkXaQMkzB+0OrDoYqVHBt8ST/3uZdfjGTLmigY+OdIjbJtAS+JITjTA4Oz6kVQgeIJlb93FsveEcpA9tr/kAvk3wj/lCu2tUxjyM8zBSX/svF+T2nX3CleKSzrepmWE/ZOEW8bAaceujqE7rxN8uMC4DyVFUjxhLuziC5xg/k+OKlXZGW7EPOgG5sTgWtWizMCAwEAAaMhMB8wHQYDVR0OBBYEFBnnMlUW0/h5rR5AWjB8abgifvPeMA0GCSqGSIb3DQEBDAUAA4IBgQChQ5pKOUV8ts+1ZNiQQ8rk/Ce+elwSJv8oPUJQytisnI/U8CN+kbgi16PTsJWL78VgOMRJavNDX+kOiNvFEGdkB+vhnDVhwYCGyjiImKS27P5aB1TNWFNCbTdyfBEM2gDuKOnaILIrk/8bLutQNG9Xsew66fNds+u18JTThpjFp+CC4RK7idX+e9QpMwkWmmucyHSEOoDOdYPkeEyIX23tW7m06L9p1PybyU4sC9SNg1v/BJsdBIDAO1zSZBHvEZLVAUOzuNYDJCNlwtQhlRoTn9sTid6GMJht8OlFxn2QrIDDk/EBPT8Qatf38jienvWxLYAamXAeVA7h07FHCXI1i5dpoBEg13CXmJ2SzcPclN2ELfsqPAxpqiX+uwuFsAgavVwCwJP1uYQKB2aEzosgoVnqZRm6jmBYkTQQExcQCE5UhcMBcdyquuMgzRVjlAZZpHF0KhbxIW3ARIx14vyUkhrpmx6w0Fjtuh4RAm7SIN03rWa0akflpjgsK8j2t5A=";

    private static final String ORIGINAL_CERT_ASSET =
            Secret.of(SecretConstants.SHELL_CERT_PREFIX);

    private static final String[] PACKAGE_LOOKUPS = {
            "getPackageInfo", "getApplicationInfo", "getLaunchIntentForPackage"};

    private static volatile Certificate originalCertificate;

    private static volatile byte[] originalCertificateDer;

    private static volatile byte[] moduleCertificateDer;

    private static volatile String moduleApkPath;

    private static final ThreadLocal<Boolean> RAW_LOOKUP =
            ThreadLocal.withInitial(() -> Boolean.FALSE);

    /** initZygote 每个 zygote 进程只安装一次，避免 13 组系统 API 被重复包装。 */
    private static final java.util.concurrent.atomic.AtomicBoolean INITIALIZED =
            new java.util.concurrent.atomic.AtomicBoolean();

    @Override
    public void initZygote(StartupParam startupParam) {
        try {
            String process = currentProcessName();
            XposedBridge.log("WeXposedHook-> x30 process: " + process);
            if (MODULE_PACKAGE.equals(process)) {
                // 模块自己的 MainActivity/Provider 进程：不需要冒充壳的身份，
                // 否则 PackageInfo.packageName 被改成 cn.android.x，系统安装
                // androidx.startup.InitializationProvider 时会 NameNotFound 崩溃。
                XposedBridge.log("WeXposedHook-> x30 compat skip: module process");
                return;
            }
            if (!INITIALIZED.compareAndSet(false, true)) {
                // 热重载/双开/重复初始化时不要再次包装系统 API。
                XposedBridge.log("WeXposedHook-> x30 compat already initialized");
                return;
            }
            moduleApkPath = startupParam == null ? null : startupParam.modulePath;
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
            // 壳已合并进本 APK：modulePath 必须指向真实 APK，否则壳取不到自己的
            // assets（loader / xposed_init）。包名与证书仍由上面的 hooks 伪装。
            XposedBridge.log("WeXposedHook-> x30 compat installed: " + MODULE_PACKAGE);
        } catch (Throwable error) {
            XposedBridge.log(error);
        }
    }

    private static volatile String processNameCache;

    /**
     * zygote/usap 预加载阶段的名字会被 fork 后的进程继承。
     * 一旦缓存了它们，isModuleProcessRuntime() 在真实进程里永远为 false，
     * 包名伪装就会波及模块自己的进程（MainActivity 里的 ComponentName 会变成
     * cn.android.x/...，系统直接抛 Unknown component）。
     */
    private static boolean isPlaceholderProcessName(String name) {
        return name == null || name.isEmpty()
                || "zygote".equals(name) || "zygote64".equals(name)
                || "usap64".equals(name)
                // 框架预初始化阶段会给 "<pre-initialized>" 之类的占位值
                || name.startsWith("<");
    }

    private static String currentProcessName() {
        String cached = processNameCache;
        if (!isPlaceholderProcessName(cached)) {
            return cached;
        }
        // API 28 起是公开接口，不再反射 ActivityThread。
        if (android.os.Build.VERSION.SDK_INT >= 28) {
            try {
                String name = android.app.Application.getProcessName();
                if (!isPlaceholderProcessName(name)) {
                    processNameCache = name;
                    return name;
                }
            } catch (Throwable ignored) {
                // 落到 /proc 兜底
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
                // fork 后 cmdline 一定是真实进程名，这里才值得写缓存。
                if (!isPlaceholderProcessName(name)) {
                    processNameCache = name;
                }
                return name;
            }
        } catch (Throwable ignored) {
            // 忽略
        }
        return "";
    }

    /** 运行时判断：模块自身进程不能做任何包名/签名伪装。 */
    private static boolean isModuleProcessRuntime() {
        String name = currentProcessName();
        return MODULE_PACKAGE.equals(name) || name.startsWith(MODULE_PACKAGE + ":");
    }

    /**
     * 壳会把模块 APK 的绝对路径缓存在 params 里；重装后 /data/app 的哈希目录会变，
     * 旧路径会让 JarFile 打开失败并导致证书/密钥为空。这里统一改回当前 modulePath。
     */
    /** 让壳的模块 Context 继续看到原包名，native 派生密钥时保持与厂商包一致。 */
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

    /**
     * 先记住复刻 APK 自己的调试证书；之后所有返回这张证书的入口都换成原版证书。
     */
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
            return Base64.decode(MODULE_CERT_B64, Base64.DEFAULT);
        } catch (Throwable ignored) {
            return null;
        }
    }

    /**
     * 壳用 x.ⁱᵢ.ᐧʿ.ˎٴ(String) 读模块 APK 证书；直接把这个方法的返回值
     * 换成原版证书 DER，绕开 JarEntry 反射在不同 ROM 上的差异。
     */
    private static void hookShellCertHelper() {
        ClassLoader loader = X30Compat.class.getClassLoader();
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

    /**
     * 壳/native 可能从 JarEntry、JarFile、PackageInfo 或 Certificate.getEncoded()
     * 取自身证书。只要拿到的证书是复刻 APK 的调试证书，就换成原版证书。
     */
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
                // 抽象方法不能 hook，具体实现由 JarEntry/Signature 钩子覆盖。
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
            // 只认本模块自己的 APK；壳用的就是它的路径。
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

    /** 壳也可能通过 PackageManager 取 signatures；同样换回原版。 */
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
                    // 壳用隐藏包名查询后还会比对 PackageInfo.packageName。
                    disguiseAsShell(info);
                }
            });
            XposedBridge.log("WeXposedHook-> x30 package info hooked");
        } catch (Throwable error) {
            XposedBridge.log(error);
        }
    }

    /**
     * 壳可能用 {@code getPackageArchiveInfo(modulePath)} 直接读 APK 的证书；
     * 这种情况下 JarFile/PackageInfo hook 都覆盖不到，需要单独换掉签名。
     */
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
                // 该方法在这个系统版本不存在
            }
        }
    }

    /**
     * 把查询结果伪装成壳：包名 + 原版证书。
     * {@code signatures} 虽被标记弃用，但 {@code signingInfo} 是只读对象，
     * 运行期只能改这个字段。
     */
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

    /** 把第一个字符串参数里的壳包名换成本项目包名。 */
    /** 壳可能用 "!#!%" + Base64("cn.android.x") 之类的隐藏形式查询包名。 */
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
                // 不是 Base64 编码的包名
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

