package github.shadowbaby.wechatxposed.hook.license;

import android.os.Build;
import github.shadowbaby.wechatxposed.hook.BuildConfig;
import github.shadowbaby.wechatxposed.hook.deploy.StartupCheck;
import github.shadowbaby.wechatxposed.hook.loader.SecretConstants;
import github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import github.shadowbaby.wechatxposed.hook.loader.util.Secret;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import org.json.JSONObject;

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
    private static final int LEVEL_UNKNOWN = -1;

    private static volatile String group;

    private static volatile String promise;

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

    /** 承诺文案由 native 解密，避免明文常量留在 dex。 */
    public static String promise() {
        String value = promise;
        if (value == null || value.isEmpty()) {
            value = Secret.of(SecretConstants.ACTIVATION_PROMISE);
            if (!value.isEmpty()) {
                promise = value;
            }
        }
        return value;
    }

    private static final String FILE_NAME = "files/activation.dat";

    private static volatile File dataDir;

    private static volatile int level = -1;

    private static volatile String cachedWxid;

    private Activation() {
    }

    public static void install(File directory) {
        dataDir = directory;
        level = -1;
    }

    public static synchronized int level() {
        if (!BuildConfig.FULL_EDITION) {
            // 公开版只含基础包，免费使用，不要求授权。
            return LEVEL_BASE;
        }
        if (BuildConfig.DEBUG) {
            return LEVEL_EXT;
        }
        int cached = level;
        if (cached >= 0) {
            return cached;
        }
        try {
            int result = readLevel();
            if (result >= 0) {
                level = result;
            }
            return result;
        } catch (Throwable error) {
            ModuleLogger.log("activation: level " + error);
            return LEVEL_NONE;
        }
    }

    public static boolean isBaseAllowed() {
        return level() >= LEVEL_BASE;
    }

    public static boolean isExtensionAllowed() {
        return BuildConfig.FULL_EDITION && level() >= LEVEL_EXT;
    }

    public static boolean hasAuthorization() {
        try {
            int current = level();
            if (current > LEVEL_NONE) {
                return true;
            }
            // 账号/prefs 尚未就绪时不误弹；下次检查再判定。
            return current == LEVEL_UNKNOWN && hasCodeFile();
        } catch (Throwable error) {
            ModuleLogger.log("activation: hasAuthorization " + error);
            return false;
        }
    }

    public static boolean hasCodeFile() {
        return dataDir != null && new File(dataDir, FILE_NAME).isFile();
    }

    public static String wxid() {
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

    private static int readLevel() {
        if (dataDir == null) {
            return LEVEL_UNKNOWN;
        }
        String code = readCode();
        if (code.isEmpty()) {
            ModuleLogger.log("activation: no code machine=" + machineCode());
            return LEVEL_NONE;
        }
        int result = verifyCode(code);
        if (result > LEVEL_NONE) {
            return result;
        }
        // 机器码在 wxid 尚未就绪时先不缓存失败；公开码不依赖 wxid。
        String publicCode = Secret.packValue(Secret.PACK_PUBLIC_CODE);
        int publicLength = publicCode == null || publicCode.isEmpty()
                ? 10 : publicCode.length();
        if (wxid() == null && code.length() != publicLength) {
            return LEVEL_UNKNOWN;
        }
        ModuleLogger.debug("activation: level=" + result);
        return result;
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

    /** 校验承诺与授权码并写入文件；成功返回 true。 */
    public static boolean activate(String promise, String code) {
        String expected = promise();
        if (dataDir == null || promise == null
                || !expected.equals(promise.trim())) {
            ModuleLogger.log("activation: promise mismatch exp=" + expected.length()
                    + " in=" + (promise == null ? -1 : promise.trim().length()));
            return false;
        }
        int newLevel = verifyCode(code);
        if (newLevel <= LEVEL_NONE) {
            ModuleLogger.log("activation: verify failed len="
                    + (code == null ? -1 : code.trim().length()));
            return false;
        }
        try {
            JSONObject json = new JSONObject();
            json.put("promise", expected);
            json.put("code", code == null ? "" : code.trim());
            File file = new File(dataDir, FILE_NAME);
            File parent = file.getParentFile();
            if (parent != null && !parent.isDirectory() && !parent.mkdirs()) {
                ModuleLogger.log("activation: parent " + parent);
                return false;
            }
            try (java.io.FileOutputStream output = new java.io.FileOutputStream(file)) {
                output.write(json.toString().getBytes(StandardCharsets.UTF_8));
            }
            file.setReadable(true, false);
            level = newLevel;
            return true;
        } catch (Throwable error) {
            File probe = new File(dataDir, FILE_NAME);
            ModuleLogger.log("activation: write " + error + " r=" + probe.canRead()
                    + " w=" + probe.canWrite() + " len=" + probe.length());
            return false;
        }
    }

    private static String readCode() {
        if (dataDir == null) {
            return "";
        }
        File file = new File(dataDir, FILE_NAME);
        if (!file.isFile()) {
            return "";
        }
        try {
            String text = readText(file).trim();
            if (text.startsWith("{")) {
                return new JSONObject(text).optString("code").trim();
            }
            return text;
        } catch (Throwable error) {
            ModuleLogger.log("activation: " + error);
            return "";
        }
    }

    private static String readText(File file) throws Exception {
        try (InputStream input = new FileInputStream(file);
                ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[4096];
            int read;
            while ((read = input.read(buffer)) > 0) {
                output.write(buffer, 0, read);
            }
            return output.toString("UTF-8");
        }
    }
}
