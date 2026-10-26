package github.shadowbaby.wechatxposed.hook.license;

import android.os.Build;
import github.shadowbaby.wechatxposed.hook.deploy.StartupCheck;
import github.shadowbaby.wechatxposed.hook.support.pack.FeaturePackUnlock;
import github.shadowbaby.wechatxposed.hook.loader.SecretConstants;
import github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import github.shadowbaby.wechatxposed.hook.loader.util.Secret;
import java.io.File;

/**
 * 离线授权：公开码启用基础功能，机器码短令牌启用 sf/mf/af。
 *
 * 机器码、公开码比对、短令牌 HMAC、mid/wxid/有效期全部在 native；
 * Java 只负责读取授权文件、保存用户承诺和展示状态。
 */
public final class Activation {

    public static final int LEVEL_NONE = 0;
    public static final int LEVEL_BASE = 1;
    public static final int LEVEL_EXT = 2;

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

    private static volatile String cachedWxid;

    private static volatile String runtimeWxid;

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
        if (!account.startsWith("wxid_")
                || account.equals(runtimeWxid)) {
            return;
        }
        runtimeWxid = account;
        cachedWxid = account;
        level = -1;
        ModuleLogger.log("activation: runtime account=" + account);
        try {
            if (dataDir != null) {
                StartupCheck.run(dataDir, account);
            }
            FeaturePackUnlock.retry();
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

    public static String wxid() {
        String runtime = runtimeWxid;
        if (runtime != null) {
            return runtime;
        }
        String cached = cachedWxid;
        if (cached != null) {
            return cached;
        }
        String account = dataDir == null ? null
                : StartupCheck.readLoginAccount(dataDir);
        if (account != null && !account.isEmpty()) {
            cachedWxid = account;
        }
        return account;
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
        try {
            String account = wxid();
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
        try {
            if (code == null || code.trim().isEmpty()) {
                return LEVEL_NONE;
            }
            String account = wxid();
            // 公开码不依赖 wxid；机器码在 native 里用空 wxid 会自然校验失败。
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

