package github.shadowbaby.wechatxposed.hook.license;

import android.os.Build;
import github.shadowbaby.wechatxposed.hook.deploy.StartupCheck;
import github.shadowbaby.wechatxposed.hook.support.pack.FeaturePackUnlock;
import github.shadowbaby.wechatxposed.hook.loader.SecretConstants;
import github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import github.shadowbaby.wechatxposed.hook.loader.util.Secret;
import java.io.File;

/**
 * 离线授权：免责声明页写普通授权，机器码绑定的卡密写 sf/mf/af。
 *
 * 机器码、Ed25519 验签、mid/wxid/有效期全部在 native；
 * Java 只负责读取授权文件、保存用户承诺和展示状态。
 */
public final class Activation {

    public static final int LEVEL_NONE = 0;
    public static final int LEVEL_BASE = 1;
    public static final int LEVEL_EXT = 2;

    /** 文件层读不到账号时的落盘缓存（位于微信 files 目录）。 */
    public static final String ACCOUNT_CACHE = "wxh_account";

    private static volatile String group;

    /** 群号由 native 解密，避免明文常量留在 dex。 */
    public static String group() {
        String value = group;
        if (value == null || value.isEmpty()) {
            value = Secret.of(SecretConstants.ACTIVATION_GROUP);
            if (!value.isEmpty()) {
                group = value;
            }
        }
        return value;
    }

    private static volatile File dataDir;

    private static volatile int level = -1;


    private static volatile String runtimeWxid;

    private static volatile String probedWxid;

    /** 是否读取用户手动填写的账号兜底文件；模块只读不写，默认开启。 */
    private static volatile boolean manualAccountEnabled = true;

    public static void setManualAccountEnabled(boolean enabled) {
        manualAccountEnabled = enabled;
    }

    public static boolean isManualAccountEnabled() {
        return manualAccountEnabled;
    }

    /** 壳（功能 dex）的 ClassLoader，用来调用壳自己的账号查询。 */
    private static volatile ClassLoader shellLoader;

    public static void setShellLoader(ClassLoader loader) {
        if (loader != null) {
            shellLoader = loader;
        }
    }

    /**
     * 壳的 c.ˊﹶ.ˉˎ.יⁱ() 会依次尝试反射微信的账号 API，不依赖 prefs/MMKV。
     * 这里直接复用壳的实现，作为最稳的账号来源。
     */
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
                // 之前缓存的多半是启动早期的 null，必须让它重新解析。
                StartupCheck.invalidate();
                ModuleLogger.log("activation: account from shell api");
                return text;
            }
        } catch (Throwable ignored) {
        }
        return null;
    }

    private Activation() {
    }

    public static String runtimeWxid() {
        return runtimeWxid;
    }

    /**
     * X 3.0 core 在 msgId 132/150 里传入的 userId 是权威账号，
     * 比 prefs 更可靠（双开、prefs 未就绪时尤其明显）。
     */
    public static void setRuntimeWxid(String value) {
        if (value == null) {
            return;
        }
        String account = value.trim();
        // 账号可能是自定义微信号，不再只认 wxid_ 前缀。
        if (!Wxid.isReal(account) || account.equals(runtimeWxid)) {
            return;
        }
        runtimeWxid = account;
        level = -1;
        // 必须先失效缓存：启动时的那次查询大概率是 null，
        // 它在 TTL 内会把授权重算挡回去，级别一直停在 0。
        StartupCheck.invalidate();
        ModuleLogger.log("activation: runtime account=" + Wxid.mask(account));
        try {
            if (dataDir != null) {
                StartupCheck.run(dataDir, account);
            }
            FeaturePackUnlock.retry();
            // 启动早期壳加载 core dex 时账号还没到，授权绕过可能被跳过；
            // 现在账号确定了，按最新级别补装一次。
            github.shadowbaby.wechatxposed.hook.loader.dex.InMemoryDexLoadHook
                    .retryLicensed();
        } catch (Throwable error) {
            ModuleLogger.log("activation: runtime retry " + error);
        }
    }

    public static void install(File directory) {
        dataDir = directory;
        level = -1;
    }

    /** 宿主数据目录，供授权守卫同步功能包数据库。 */
    public static File dataDir() {
        return dataDir;
    }

    /** 授权级别统一来自数据库（WXH_LEVEL）；本进程未同步时只读查询兜底。 */
    public static synchronized int level() {
        int current = FeaturePackUnlock.currentLevel();
        if (current > FeaturePackUnlock.LEVEL_NONE) {
            return current;
        }
        int cached = level;
        if (cached >= 0) {
            return cached;
        }
        int result = dataDir == null
                ? LEVEL_NONE : FeaturePackUnlock.readLevel(dataDir);
        level = result;
        return result;
    }

    public static boolean isBaseAllowed() {
        return level() >= LEVEL_BASE;
    }

    public static boolean isExtensionAllowed() {
        return level() >= LEVEL_EXT;
    }

    /** 统一走 StartupCheck 的顺序：壳查询 → 壳 CallMethod → 手动兜底。 */
    public static String wxid() {
        if (dataDir == null) {
            return runtimeWxid;
        }
        return StartupCheck.readLoginAccount(dataDir);
    }

    private static volatile String bindingFingerprint;

    private static volatile String bindingDevice;

    /**
     * 在任何版本/机型伪装 hook 安装前捕获真实 Build 标识。
     * 机器码必须绑定真机，不能用被模块改过的 Build.FINGERPRINT。
     */
    public static void captureBuildIdentity() {
        if (bindingFingerprint == null) {
            bindingFingerprint = Build.FINGERPRINT;
            bindingDevice = Build.DEVICE;
        }
    }

    private static String bindingFingerprint() {
        String value = bindingFingerprint;
        return value != null ? value : Build.FINGERPRINT;
    }

    private static String bindingDevice() {
        String value = bindingDevice;
        return value != null ? value : Build.DEVICE;
    }

    public static String machineCode() {
        return machineCode(wxid());
    }

    /** 用指定账号算机器码；授权守卫已经有账号，走这里可以避免重复反射。 */
    public static String machineCode(String account) {
        try {
            if (account == null || account.isEmpty()) {
                return null;
            }
            String certificate = Secret.of(SecretConstants.MODULE_CERT_SHA256);
            return Secret.machineCode(bindingFingerprint(), bindingDevice(),
                    certificate, account);
        } catch (Throwable error) {
            ModuleLogger.log("activation: machineCode " + error);
            return null;
        }
    }

    /** 校验授权码，返回 LEVEL_NONE / LEVEL_BASE / LEVEL_EXT（全部在 native）。 */
    public static int verifyCode(String code) {
        return verifyCode(code, wxid());
    }

    /**
     * 用指定账号复核授权码。
     *
     * 启动守卫手里已经有解析好的账号，走这个入口可以避免再次反射壳接口。
     */
    public static int verifyCode(String code, String account) {
        try {
            if (code == null || code.trim().isEmpty()) {
                return LEVEL_NONE;
            }
            // 卡密与机器码、wxid 绑定；账号为空时 mid 对不上，验签必然失败。
            return Secret.activationLevel(code.trim(), bindingFingerprint(), bindingDevice(),
                    Secret.of(SecretConstants.MODULE_CERT_SHA256),
                    account == null ? "" : account,
                    System.currentTimeMillis() / 1000L);
        } catch (Throwable error) {
            ModuleLogger.log("activation: verify " + error);
            return LEVEL_NONE;
        }
    }
}

