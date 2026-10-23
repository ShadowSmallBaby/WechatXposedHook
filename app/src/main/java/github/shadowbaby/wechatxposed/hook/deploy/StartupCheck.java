package github.shadowbaby.wechatxposed.hook.deploy;

import github.shadowbaby.wechatxposed.hook.license.LicenseDatabase;
import github.shadowbaby.wechatxposed.hook.license.LicenseInstaller;
import github.shadowbaby.wechatxposed.hook.loader.util.Secret;
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
        github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger.debug(
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
        String account = scanLoginAccount(dataDir);
        if (account != null) {
            return account;
        }
        // 部分机型把登录账号写在设备加密目录。
        String path = dataDir.getAbsolutePath();
        String decrypted = path.replace("/data/user/", "/data/user_de/");
        if (!decrypted.equals(path)) {
            File deviceDir = new File(decrypted);
            if (deviceDir.isDirectory()) {
                return scanLoginAccount(deviceDir);
            }
        }
        return null;
    }

    private static String scanLoginAccount(File dataDir) {
        String account = readAccount(new File(dataDir, PREFS_PATH));
        if (account != null) {
            return account;
        }
        // 部分微信版本把 login_weixin_username 写到其他 shared_prefs 文件。
        File prefs = new File(dataDir, "shared_prefs");
        File[] files = prefs.listFiles();
        if (files == null) {
            return null;
        }
        for (File file : files) {
            if (!file.isFile() || !file.getName().endsWith(".xml")) {
                continue;
            }
            account = readAccount(file);
            if (account != null) {
                return account;
            }
        }
        return null;
    }

    private static String readAccount(File file) {
        try {
            String xml = readText(file);
            if (xml == null) {
                return null;
            }
            String account = extractAccount(xml, ACCOUNT_KEY);
            if (account == null) {
                account = extractAccount(xml, "last_login_weixin_username");
            }
            return account;
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static String extractAccount(String xml, String key) {
        String marker = "name=\"" + key + "\"";
        int position = xml.indexOf(marker);
        int start = position < 0 ? -1 : xml.indexOf('>', position + marker.length());
        int end = start < 0 ? -1 : xml.indexOf('<', start);
        if (end <= start + 1) {
            return null;
        }
        String account = xml.substring(start + 1, end).trim();
        return account.startsWith(WXID_PREFIX) ? account : null;
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
