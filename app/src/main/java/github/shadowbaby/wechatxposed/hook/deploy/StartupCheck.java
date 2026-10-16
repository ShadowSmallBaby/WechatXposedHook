package github.shadowbaby.wechatxposed.hook.deploy;

import github.shadowbaby.wechatxposed.hook.license.LicenseDatabase;
import github.shadowbaby.wechatxposed.hook.license.LicenseInstaller;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/**
 * 启动自检。
 *
 * 由 handleLoadPackage 在微信主进程启动时调用:先补齐三个功能包,再补齐授权库。
 * 这样装好 APK 就不用再跑设备上的部署脚本,也不用进菜单点一下——微X 自己把功能包删了、
 * 或者本账号还没写过库,下一次启动就被拉回来。
 *
 * 账号有两处来源:启动阶段微X 还没开始校验,只能读微信自己 prefs 里的登录 wxid;
 * 之后微X 校验时会把权威账号交过来(见 CurrentAccount),那时再补写一次。
 * 两处都走同一个幂等写库动作,所以最多也就写两次。
 */
public abstract class StartupCheck {

    /** 微信 files 目录,相对 data 目录。 */
    private static final String FILES_DIR = "files";

    /** 授权库,相对 data 目录。 */
    private static final String DATABASE_PATH = "databases/" + LicenseDatabase.DB_FILE_NAME;

    /** 登录账号所在的 prefs 文件;里面记的就是当前登录的 wxid。 */
    private static final String PREFS_PATH = "shared_prefs/com.tencent.mm_preferences.xml";

    /** 账号键名,取 prefs 的 XML 原文比读 SharedPreferences 更早、也不需要 Context。 */
    private static final String ACCOUNT_KEY = "login_weixin_username";

    /** 账号一律是 wxid 开头,别的值当没读到。 */
    private static final String WXID_PREFIX = "wxid_";

    private static final int BUFFER_SIZE = 8 * 1024;

    /** 微信 data 目录;handleLoadPackage 记下,之后只读。 */
    private static volatile File weChatData;

    /** 微信主进程启动时调用:补齐功能包 + 按 prefs 里的账号补一次授权库。 */
    public static void run(File dataDir, String account) {
        weChatData = dataDir;
        FeaturePackRestorer.ensureOnce(new File(dataDir, FILES_DIR));
        ensureLicense(account);
    }

    /** 拿到权威账号(微X 校验里传来的)后补一次授权库。 */
    public static void ensureLicense(String account) {
        File dataDir = weChatData;
        if (dataDir == null || account == null || account.isEmpty()) {
            return;
        }
        LicenseInstaller.ensure(new File(dataDir, DATABASE_PATH), account);
    }

    /** 从微信 prefs 原文里读出当前登录账号;读不到返回 null。 */
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

    /** 小文件一次读完;不存在返回 null。 */
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
