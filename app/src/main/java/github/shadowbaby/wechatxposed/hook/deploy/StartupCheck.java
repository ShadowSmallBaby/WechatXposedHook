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
 * 账号解析按可靠性排序：微信自己的存储 → 壳接口 → 运行时回调 → 落盘缓存。
 *
 * 微信存储与壳接口的就绪时间接近，但前者不经过壳的 core dex，壳换版本时
 * 账号解析不会连带失效。落盘缓存由 {@link Activation} 在账号到手后写入，
 * 是下一次启动最早可用的来源。
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

    /**
     * 账号来源刚发生变化（壳查询成功 / CallMethod 传下来）时强制下次重新解析。
     *
     * 启动时壳还没加载完，第一次查询必然是 null；结果被 TTL 缓存住以后，
     * 紧接着到达的账号会命中这条 null，授权重算直接早退，级别停在 0。
     */
    public static void invalidate() {
        lastScanAt = -SCAN_TTL_MS;
        lastScanResult = null;
    }

    /**
     * 账号落盘缓存：{@code files/wxh_account}。
     *
     * 由 {@link Activation} 在任一来源解析到账号后写入，下次启动最先读它；
     * 用户也可以手动填这个文件，内容一致时模块不会去动它。
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
