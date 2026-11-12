package io.github.shadowbaby.wechatxposed.hook.license;

import io.github.shadowbaby.wechatxposed.hook.deploy.StartupCheck;
import io.github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;

public final class Activation {

    public static final String ACCOUNT_CACHE = "wxh_account";

    private static volatile File dataDir;

    private static volatile String runtimeWxid;

    private static volatile String probedWxid;

    private static volatile boolean manualAccountEnabled = true;

    private static volatile ClassLoader shellLoader;

    private static volatile ClassLoader hostLoader;

    private Activation() {
    }

    public static void setManualAccountEnabled(boolean enabled) {
        manualAccountEnabled = enabled;
    }

    public static boolean isManualAccountEnabled() {
        return manualAccountEnabled;
    }

    public static void setShellLoader(ClassLoader loader) {
        if (loader != null) {
            shellLoader = loader;
        }
    }

    public static void setHostLoader(ClassLoader loader) {
        if (loader == null) {
            return;
        }
        hostLoader = loader;
        WeChatAccount.armAfter(3000L);
    }

    public static String probeWeChat() {
        String value = WeChatAccount.read(dataDir, hostLoader);
        if (value == null) {
            return null;
        }
        if (!value.equals(probedWxid)) {
            probedWxid = value;
            StartupCheck.invalidate();
            cacheAccount(value);
            ModuleLogger.log("account: from wechat api");
        }
        return value;
    }

    public static String probeShell() {
        ClassLoader loader = shellLoader;
        if (loader == null) {
            return null;
        }
        try {
            Class<?> clazz = Class.forName("c.ˊﹶ.ˉˎ", false, loader);
            Object value = clazz.getDeclaredMethod("יⁱ").invoke(null);
            if (value instanceof String text && Wxid.isReal(text)) {
                probedWxid = text;
                StartupCheck.invalidate();
                cacheAccount(text);
                ModuleLogger.log("account: from shell api");
                return text;
            }
        } catch (Throwable ignored) {
        }
        return null;
    }

    public static String runtimeWxid() {
        return runtimeWxid;
    }

    public static void setRuntimeWxid(String value) {
        if (value == null) {
            return;
        }
        String account = value.trim();
        if (!Wxid.isReal(account) || account.equals(runtimeWxid)) {
            return;
        }
        runtimeWxid = account;
        StartupCheck.invalidate();
        ModuleLogger.log("account: runtime=" + Wxid.mask(account));
        try {
            cacheAccount(account);
            if (dataDir != null) {
                StartupCheck.run(dataDir, account);
            }
        } catch (Throwable error) {
            ModuleLogger.log("account: runtime retry " + error);
        }
    }

    public static void install(File directory) {
        dataDir = directory;
    }

    public static void captureBuildIdentity() {
    }

    private static volatile String lastCached;

    private static void cacheAccount(String account) {
        File directory = dataDir;
        if (directory == null || account.equals(lastCached)) {
            return;
        }
        try {
            File file = new File(directory, "files/" + ACCOUNT_CACHE);
            byte[] bytes = account.getBytes(StandardCharsets.UTF_8);
            if (sameContent(file, bytes)) {
                lastCached = account;
                return;
            }
            File parent = file.getParentFile();
            if (parent != null && !parent.isDirectory() && !parent.mkdirs()) {
                return;
            }
            try (FileOutputStream output = new FileOutputStream(file, false)) {
                output.write(bytes);
            }
            lastCached = account;
            ModuleLogger.log("account: cached");
        } catch (Throwable error) {
            ModuleLogger.log("account: cache " + error);
        }
    }

    private static boolean sameContent(File file, byte[] bytes) {
        if (!file.isFile() || file.length() != bytes.length) {
            return false;
        }
        try (FileInputStream input = new FileInputStream(file)) {
            byte[] buffer = new byte[bytes.length];
            if (input.read(buffer) != bytes.length) {
                return false;
            }
            return java.util.Arrays.equals(buffer, bytes);
        } catch (Throwable ignored) {
            return false;
        }
    }

    public static File dataDir() {
        return dataDir;
    }

    public static String wxid() {
        if (dataDir == null) {
            return runtimeWxid;
        }
        return StartupCheck.readLoginAccount(dataDir);
    }
}
