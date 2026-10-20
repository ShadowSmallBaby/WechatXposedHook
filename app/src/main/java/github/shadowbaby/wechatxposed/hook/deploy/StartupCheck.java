package github.shadowbaby.wechatxposed.hook.deploy;

import github.shadowbaby.wechatxposed.hook.license.LicenseDatabase;
import github.shadowbaby.wechatxposed.hook.license.LicenseInstaller;
import github.shadowbaby.wechatxposed.hook.loader.Secret;
import github.shadowbaby.wechatxposed.hook.loader.SecretConstants;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

public abstract class StartupCheck {

    private static final String FILES_DIR = "files";

    private static final String DATABASE_PATH = "databases/" + LicenseDatabase.DB_FILE_NAME;

    private static final String PREFS_PATH = Secret.of(SecretConstants.PREFS_PATH);

    private static final String ACCOUNT_KEY = Secret.of(SecretConstants.ACCOUNT_KEY);

    private static final String WXID_PREFIX = "wxid_";

    private static final int BUFFER_SIZE = 8 * 1024;

    private static volatile File weChatData;

    public static void run(File dataDir, String account) {
        weChatData = dataDir;
        long start = android.os.SystemClock.elapsedRealtime();
        FeaturePackRestorer.ensureOnce(new File(dataDir, FILES_DIR));
        long packs = android.os.SystemClock.elapsedRealtime();
        ensureLicense(account);
        long license = android.os.SystemClock.elapsedRealtime();
        github.shadowbaby.wechatxposed.hook.loader.ModuleLogger.log(
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
        try {
            String xml = readText(new File(dataDir, PREFS_PATH));
            if (xml == null) {
                return null;
            }
            String marker = "name=\"" + ACCOUNT_KEY + "\"";
            int key = xml.indexOf(marker);
            int start = key < 0 ? -1 : xml.indexOf('>', key + marker.length());
            int end = start < 0 ? -1 : xml.indexOf('<', start);
            if (end <= start + 1) {
                return null;
            }
            String account = xml.substring(start + 1, end).trim();
            return account.startsWith(WXID_PREFIX) ? account : null;
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static String readText(File file) throws IOException {
        if (!file.isFile()) {
            return null;
        }
        try (InputStream input = new FileInputStream(file)) {
            StringBuilder text = new StringBuilder();
            byte[] buffer = new byte[BUFFER_SIZE];
            int read;
            while ((read = input.read(buffer)) > 0) {
                text.append(new String(buffer, 0, read, StandardCharsets.UTF_8));
            }
            return text.toString();
        }
    }

}
