package github.shadowbaby.wechatxposed.hook.deploy;

import github.shadowbaby.wechatxposed.hook.license.Activation;
import github.shadowbaby.wechatxposed.hook.license.LicenseDatabase;
import github.shadowbaby.wechatxposed.hook.license.LicenseInstaller;
import github.shadowbaby.wechatxposed.hook.license.Wxid;
import github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/**
 * 账号优先向壳要：先调壳自己的账号查询，再退回壳 CallMethod 传下来的值。
 *
 * 手动文件只是兜底：模块只读不写，内容由用户自己填写。
 * 不扫描微信的 XML prefs，也不读 MMKV 库文件。
 */
public abstract class StartupCheck {

    private static final String FILES_DIR = "files";

    private static final String DATABASE_PATH = "databases/" + LicenseDatabase.DB_FILE_NAME;

    private static final int BUFFER_SIZE = 256;

    /** 查询结果在这个窗口内复用，避免 UI 线程反复反射。 */
    private static final long SCAN_TTL_MS = 2000;

    private static volatile long lastScanAt = -SCAN_TTL_MS;

    private static volatile String lastScanResult;

    private static volatile File weChatData;

    public static void run(File dataDir, String account) {
        weChatData = dataDir;
        long start = android.os.SystemClock.elapsedRealtime();
        // 先只读授权级别：普通/未授权时自解不恢复扩展包，壳就不会加载 sf/mf/af。
        int level = github.shadowbaby.wechatxposed.hook.support.pack.FeaturePackUnlock
                .readLevel(dataDir);
        FeaturePackRestorer.ensureOnce(new File(dataDir, FILES_DIR),
                level >= github.shadowbaby.wechatxposed.hook.support.pack.FeaturePackUnlock
                        .LEVEL_PRO);
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
        String account = Activation.probeShell();
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

    /**
     * 用户手动填写的兜底账号。模块只读，不会覆盖或删除这个文件。
     * 路径：{@code /data/user/<uid>/com.tencent.mm/files/wxh_account}
     */
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
            // 文件不存在或不可读时按未登录处理
        }
        return null;
    }

    /** 账号仍然为空时输出一条摘要，便于定位（不含账号本身）。 */
    public static String diagnose(File dataDir) {
        return "shell=" + (Activation.runtimeWxid() != null)
                + " manual=" + new File(dataDir, "files/" + Activation.ACCOUNT_CACHE).isFile();
    }
}
