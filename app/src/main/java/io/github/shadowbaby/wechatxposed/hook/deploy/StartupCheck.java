package io.github.shadowbaby.wechatxposed.hook.deploy;

import io.github.shadowbaby.wechatxposed.hook.license.Activation;
import io.github.shadowbaby.wechatxposed.hook.license.LicenseDatabase;
import io.github.shadowbaby.wechatxposed.hook.license.LicenseInstaller;
import io.github.shadowbaby.wechatxposed.hook.license.Wxid;
import io.github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

public abstract class StartupCheck {

    private static final String FILES_DIR = "files";

    private static final String DATABASE_PATH = "databases/" + LicenseDatabase.DB_FILE_NAME;

    private static final int BUFFER_SIZE = 256;

    private static final long SCAN_TTL_MS = 2000;

    private static volatile long lastScanAt = -SCAN_TTL_MS;

    private static volatile String lastScanResult;

    private static volatile File weChatData;

    public static void run(File dataDir, String account) {
        weChatData = dataDir;
        long start = android.os.SystemClock.elapsedRealtime();
        FeaturePackRestorer.ensureOnce(new File(dataDir, FILES_DIR), false);
        long packs = android.os.SystemClock.elapsedRealtime();
        ensureLicense(account);
        long license = android.os.SystemClock.elapsedRealtime();
        ModuleLogger.debug(
                "perf: packs=" + (packs - start) + "ms, license=" + (license - packs) + "ms");
    }

    public static void ensureLicense(String account) {
        File dataDir = weChatData;
        if (dataDir == null || account == null || account.isEmpty()) {
            return;
        }
        LicenseInstaller.ensure(new File(dataDir, DATABASE_PATH), account);
    }

    public static String readLoginAccount(File dataDir) {
        long now = android.os.SystemClock.elapsedRealtime();
        if (now - lastScanAt < SCAN_TTL_MS) {
            return lastScanResult;
        }
        String account = Activation.probeWeChat();
        if (account == null) {
            account = Activation.probeShell();
        }
        if (account == null) {
            account = Activation.runtimeWxid();
        }
        if (account == null) {
            account = readManualAccount(dataDir);
        }
        ModuleLogger.log("login account=" + Wxid.mask(account));
        lastScanAt = android.os.SystemClock.elapsedRealtime();
        lastScanResult = account;
        return account;
    }

    public static void invalidate() {
        lastScanAt = -SCAN_TTL_MS;
        lastScanResult = null;
    }

    private static String readManualAccount(File dataDir) {
        if (!Activation.isManualAccountEnabled()) {
            return null;
        }
        try (InputStream input = new FileInputStream(
                new File(dataDir, "files/" + Activation.ACCOUNT_CACHE))) {
            byte[] buffer = new byte[BUFFER_SIZE];
            int read = input.read(buffer);
            if (read <= 0) {
                return null;
            }
            String value = new String(buffer, 0, read, StandardCharsets.UTF_8).trim();
            if (Wxid.isReal(value)) {
                ModuleLogger.log("login manual account");
                return value;
            }
        } catch (Throwable ignored) {

        }
        return null;
    }

    public static String diagnose(File dataDir) {
        return "shell=" + (Activation.runtimeWxid() != null)
                + " manual=" + new File(dataDir, "files/" + Activation.ACCOUNT_CACHE).isFile();
    }
}
