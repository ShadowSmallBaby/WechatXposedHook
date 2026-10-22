package github.shadowbaby.wechatxposed.x30;

import android.content.ComponentName;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.Signature;
import android.util.Base64;
import de.robv.android.xposed.IXposedHookZygoteInit;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
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

    private static final String SHELL_PACKAGE = "cn.android.x";

    private static final String MODULE_PACKAGE = "__MODULE_PACKAGE__";

    private static final String ORIGINAL_CERT_B64 = "__ORIGINAL_CERT_B64__";

    private static final String MODULE_CERT_B64 = "__MODULE_CERT_B64__";

    private static final String ORIGINAL_CERT_ASSET = "assets/x30/original_cert.rsa";

    private static final String[] PACKAGE_LOOKUPS = {
            "getPackageInfo", "getApplicationInfo", "getLaunchIntentForPackage"};

    private static volatile Certificate originalCertificate;

    private static volatile byte[] originalCertificateDer;

    private static volatile byte[] moduleCertificateDer;

    private static volatile String moduleApkPath;

    private static final ThreadLocal<Boolean> RAW_LOOKUP =
            ThreadLocal.withInitial(() -> Boolean.FALSE);

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
            moduleApkPath = startupParam == null ? null : startupParam.modulePath;
            if (!baseAllowed()) {
                // 未授权：只安装阻止壳初始化的最小门禁，不注册任何功能 hook。
                hookShellModulePath();
                hookShellInitGate();
                XposedBridge.log("WeXposedHook-> x30 compat deferred: not authorized");
                return;
            }
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
            hookShellModulePath();
            hookShellInitGate();
            XposedBridge.log("WeXposedHook-> x30 compat installed: " + MODULE_PACKAGE);
        } catch (Throwable error) {
            XposedBridge.log(error);
        }
    }

    private static volatile String processNameCache;

    private static String currentProcessName() {
        String cached = processNameCache;
        if (cached != null) {
            return cached;
        }
        try {
            Class<?> thread = Class.forName("android.app.ActivityThread");
            Object name = thread.getMethod("currentProcessName").invoke(null);
            if (name instanceof String && !((String) name).isEmpty()
                    && !"usap64".equals(name)) {
                processNameCache = (String) name;
                return processNameCache;
            }
        } catch (Throwable ignored) {
            // 低版本没有 currentProcessName
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
                String name = new String(data, 0, end, "UTF-8");
                if (!name.isEmpty() && !"usap64".equals(name)) {
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
        if (first instanceof String) {
            String path = (String) first;
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
        if (param.args.length == 0 || !(param.args[0] instanceof String)) {
            return;
        }
        String name = (String) param.args[0];
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
            java.util.jar.JarFile jar = new java.util.jar.JarFile(modulePath);
            try {
                java.util.jar.JarEntry entry = jar.getJarEntry("AndroidManifest.xml");
                Certificate[] certificates = entry == null ? null : entry.getCertificates();
                if (certificates != null && certificates.length > 0) {
                    moduleCertificateDer = certificates[0].getEncoded();
                }
            } finally {
                jar.close();
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
                if (param.args.length == 0 || !(param.args[0] instanceof ComponentName)) {
                    return;
                }
                ComponentName component = (ComponentName) param.args[0];
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
        if (result instanceof Certificate[]) {
            Certificate[] certificates = (Certificate[]) result;
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
            // 壳会读取 modulePath（files/x30/identity.apk）里 classes.dex 的证书；
            // 这个文件不含本模块包名，也要走证书替换。
            return name.contains(MODULE_PACKAGE)
                    || name.endsWith("x30/identity.apk")
                    || name.endsWith("x30\\identity.apk");
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

    /** 未授权时直接跳过壳的 initZygote，避免 3.0 native 初始化后绕过授权。 */
    private static void hookShellInitGate() {
        Class<?> shell = XposedHelpers.findClassIfExists(
                "com.android.x.XposedInit", X30Compat.class.getClassLoader());
        if (shell == null) {
            return;
        }
        try {
            java.util.Set<?> hooks = XposedBridge.hookAllMethods(
                    shell, "initZygote", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    if (!baseAllowed()) {
                        param.setResult(null);
                    }
                }
            });
            XposedBridge.log("WeXposedHook-> x30 init gate hooks=" + hooks.size());
        } catch (Throwable error) {
            XposedBridge.log(error);
        }
    }

    /** 未授权时不让 3.0 壳的 handleLoadPackage 继续，避免绕过授权。 */
    private static boolean baseAllowed() {
        // 先做无反射的硬门禁：没有授权文件时壳完全不启动。
        if (!new java.io.File("/data/data/com.tencent.mm/files/activation.dat").isFile()) {
            return false;
        }
        try {
            Class<?> activation = Class.forName(
                    "github.shadowbaby.wechatxposed.hook.license.Activation",
                    false, X30Compat.class.getClassLoader());
            try {
                activation.getMethod("install", java.io.File.class)
                        .invoke(null, new java.io.File("/data/data/com.tencent.mm"));
            } catch (Throwable ignored) {
            }
            Object value = activation.getMethod("isBaseAllowed").invoke(null);
            return !(value instanceof Boolean) || (Boolean) value;
        } catch (Throwable ignored) {
            return true;
        }
    }

    /**
     * 壳把 initZygote 里的 modulePath 存成实例字段；native 可能用该路径派生密钥。
     * 在壳的 handleLoadPackage 执行前，把它换成原版 X 3.0 的已安装 APK 路径。
     */
    private static void hookShellModulePath() {
        ClassLoader loader = X30Compat.class.getClassLoader();
        Class<?> shell = XposedHelpers.findClassIfExists("com.android.x.XposedInit", loader);
        if (shell == null) {
            XposedBridge.log("WeXposedHook-> x30 XposedInit not found");
            return;
        }
        try {
            XposedBridge.hookAllMethods(shell, "handleLoadPackage", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    try {
                        if (!baseAllowed()) {
                            param.setResult(null);
                            return;
                        }
                        String path = originalShellApk(param.args.length > 0 ? param.args[0] : null);
                        if (path == null || param.thisObject == null) {
                            return;
                        }
                        java.lang.reflect.Field field = param.thisObject.getClass()
                                .getField("ʽʿ");
                        field.set(param.thisObject, path);
                        XposedBridge.log("WeXposedHook-> x30 modulePath -> " + path);
                    } catch (Throwable error) {
                        XposedBridge.log(error);
                    }
                }
            });
        } catch (Throwable error) {
            XposedBridge.log(error);
        }
    }

    private static String originalShellApk(Object loadParam) {
        // 优先用内置 identity.apk，避免设备上装了原版 X 时误用它。
        // 原版未安装时，从本 APK 的 assets/x30/identity.apk 解出，作为壳的 modulePath。
        try {
            Object appInfo = loadParam == null ? null
                    : XposedHelpers.getObjectField(loadParam, "appInfo");
            Object dataDir = appInfo == null ? null
                    : XposedHelpers.getObjectField(appInfo, "dataDir");
            if (dataDir instanceof String && moduleApkPath != null) {
                File target = new File((String) dataDir, "files/x30/identity.apk");
                File parent = target.getParentFile();
                if (parent != null && (parent.isDirectory() || parent.mkdirs())) {
                    java.util.zip.ZipFile zip = new java.util.zip.ZipFile(moduleApkPath);
                    try {
                        java.util.zip.ZipEntry entry =
                                zip.getEntry("assets/x30/identity.apk");
                        if (entry != null
                                && (!target.isFile() || target.length() != entry.getSize())) {
                            File temp = new File(parent, "identity.apk.tmp");
                            try (InputStream input = zip.getInputStream(entry);
                                    OutputStream output = new FileOutputStream(temp)) {
                                byte[] buffer = new byte[64 * 1024];
                                int read;
                                while ((read = input.read(buffer)) > 0) {
                                    output.write(buffer, 0, read);
                                }
                            }
                            if (!temp.renameTo(target)) {
                                if (target.delete()) {
                                    temp.renameTo(target);
                                }
                            }
                        }
                    } finally {
                        zip.close();
                    }
                }
                if (target.isFile() && target.length() > 1_000L) {
                    return target.getAbsolutePath();
                }
            }
        } catch (Throwable error) {
            XposedBridge.log(error);
        }
        // 最后才回退到设备上安装的原版 X 3.0。
        File[] entries = new File("/data/app").listFiles();
        if (entries != null) {
            for (File entry : entries) {
                if (entry.getName().contains(SHELL_PACKAGE)) {
                    File base = new File(entry, "base.apk");
                    if (base.isFile()) {
                        return base.getAbsolutePath();
                    }
                }
            }
        }
        try {
            android.app.Application app = android.app.AndroidAppHelper.currentApplication();
            if (app != null) {
                RAW_LOOKUP.set(Boolean.TRUE);
                try {
                    return app.getPackageManager()
                            .getPackageInfo(SHELL_PACKAGE, 0).applicationInfo.sourceDir;
                } finally {
                    RAW_LOOKUP.set(Boolean.FALSE);
                }
            }
        } catch (Throwable ignored) {
            // 继续用 ActivityThread 反射
        }
        try {
            Class<?> threadClass = XposedHelpers.findClass("android.app.ActivityThread", null);
            Object thread = XposedHelpers.callStaticMethod(threadClass, "currentActivityThread");
            Object systemContext = XposedHelpers.callMethod(thread, "getSystemContext");
            Object manager = XposedHelpers.callMethod(systemContext, "getPackageManager");
            RAW_LOOKUP.set(Boolean.TRUE);
            try {
                Object info = XposedHelpers.callMethod(manager, "getPackageInfo", SHELL_PACKAGE, 0);
                Object applicationInfo = XposedHelpers.getObjectField(info, "applicationInfo");
                Object source = XposedHelpers.getObjectField(applicationInfo, "sourceDir");
                if (source instanceof String) {
                    return (String) source;
                }
            } finally {
                RAW_LOOKUP.set(Boolean.FALSE);
            }
        } catch (Throwable error) {
            XposedBridge.log(error);
        }
        return null;
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
                    if (!(param.getResult() instanceof PackageInfo)) {
                        return;
                    }
                    PackageInfo info = (PackageInfo) param.getResult();
                    // 壳用隐藏包名查询后还会比对 PackageInfo.packageName。
                    info.packageName = SHELL_PACKAGE;
                    info.signatures = new Signature[]{new Signature(originalCertificateDer())};
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
                                || !(param.args[0] instanceof String)) {
                            return;
                        }
                        String path = (String) param.args[0];
                        if (!path.contains(MODULE_PACKAGE) && !path.contains(SHELL_PACKAGE)) {
                            return;
                        }
                        if (!(param.getResult() instanceof PackageInfo)) {
                            return;
                        }
                        PackageInfo info = (PackageInfo) param.getResult();
                        info.packageName = SHELL_PACKAGE;
                        info.signatures = new Signature[]{new Signature(originalCertificateDer())};
                        XposedBridge.log("WeXposedHook-> x30 archive info mapped: " + path);
                    }
                });
            } catch (Throwable ignored) {
                // 该方法在这个系统版本不存在
            }
        }
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
        if (!(value instanceof String)) {
            return false;
        }
        String text = (String) value;
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

