package github.shadowbaby.wechatxposed.hook.loader.util;

public final class Secret {

    private static Boolean nativeAvailable;

    private Secret() {
    }

    public static String of(String encoded) {
        if (nativeAvailable == null) {
            nativeAvailable = loadNative();
        }
        if (!nativeAvailable) {
            return "";
        }
        try {
            String plain = nativeOf(encoded);
            return plain == null ? "" : plain;
        } catch (Throwable error) {
            return "";
        }
    }

    /** 功能包 DB 参数索引；具体值在 native。 */
    public static final int PACK_DB_NAME = 0;
    public static final int PACK_DB_KEY = 1;
    public static final int PACK_DEFAULT_FP = 2;
    public static final int PACK_DEFAULT_FP_ASYNC = 3;
    public static final int PACK_DEFAULT_VERSIONS = 4;
    public static final int PACK_DEFAULT_VERSIONS_V7 = 5;

    public static String packValue(int index) {
        if (!isNativeAvailable()) {
            return null;
        }
        try {
            return nativePackValue(index);
        } catch (Throwable error) {
            return null;
        }
    }

    private static native String nativePackValue(int index);

    /** "dir|name|len|name|len|..."；用于功能包 `_s` 校验。 */
    public static String packGuardPlan() {
        if (!isNativeAvailable()) {
            return null;
        }
        try {
            return nativePackGuardPlan();
        } catch (Throwable error) {
            return null;
        }
    }

    private static native String nativePackGuardPlan();

    /** 运行时恢复清单；full 时包含扩展包与别名。 */
    public static String restorePlan(boolean full) {
        if (!isNativeAvailable()) {
            return null;
        }
        try {
            return nativeRestorePlan(full);
        } catch (Throwable error) {
            return null;
        }
    }

    private static native String nativeRestorePlan(boolean full);

    /** salt -> "原版 password|组件名"；未命中返回 null。 */
    public static String pbePlan(String salt) {
        if (salt == null || !isNativeAvailable()) {
            return null;
        }
        try {
            return nativePbePlan(salt);
        } catch (Throwable error) {
            return null;
        }
    }

    private static native String nativePbePlan(String salt);

    /** 返回 {外层 password, 内层 password, 容器文件...}；未命中返回 null。 */
    public static String[] packPlan(String role) {
        if (role == null || !isNativeAvailable()) {
            return null;
        }
        try {
            String plan = nativePackPlan(role);
            return plan == null ? null : plan.split("\\|");
        } catch (Throwable error) {
            return null;
        }
    }

    private static native String nativeOf(String encoded);

    private static native String nativePackPlan(String role);

    /** 功能包 `_s` 验签；公钥与 RSA/SHA-1 都在 native。 */
    public static boolean verifyPack(byte[] data, byte[] signature) {
        if (data == null || signature == null || !isNativeAvailable()) {
            return false;
        }
        try {
            return nativeVerifyPack(data, signature);
        } catch (Throwable error) {
            return false;
        }
    }

    private static native boolean nativeVerifyPack(byte[] data, byte[] signature);

    /** 机器码由 native 计算，避免 Java 侧改算法。 */
    public static String machineCode(String fingerprint, String device,
            String certificate, String wxid) {
        if (!isNativeAvailable()) {
            return null;
        }
        try {
            return nativeMachineCode(fingerprint, device, certificate, wxid);
        } catch (Throwable error) {
            return null;
        }
    }

    private static native String nativeMachineCode(String fingerprint, String device,
            String certificate, String wxid);

    /** 卡密判定：0 未授权、1 基础、2 扩展。 */
    public static int activationLevel(String code, String fingerprint, String device,
            String certificate, String wxid, long now) {
        if (!isNativeAvailable()) {
            return 0;
        }
        try {
            return nativeActivationLevel(code, fingerprint, device, certificate, wxid, now);
        } catch (Throwable error) {
            return 0;
        }
    }

    private static native int nativeActivationLevel(String code, String fingerprint,
            String device, String certificate, String wxid, long now);

    /** 解扩展包容器，返回内层功能 APK；容器格式与算法在 native。 */
    public static byte[] decodeContainer(byte[] container, String outerPassword,
            String innerPassword) {
        if (container == null || outerPassword == null || innerPassword == null
                || !isNativeAvailable()) {
            return null;
        }
        try {
            return nativeDecodeContainer(container, outerPassword, innerPassword);
        } catch (Throwable error) {
            return null;
        }
    }

    private static native byte[] nativeDecodeContainer(byte[] container,
            String outerPassword, String innerPassword);

    /**
     * 单层容器解密；基础包（BaseDex）没有内层 MsgPack。
     * 明文是一份 APK，`classes.dex` 即壳的功能 dex。
     */
    public static byte[] decodeLayer(byte[] container, String password) {
        if (container == null || password == null || password.isEmpty()
                || !isNativeAvailable()) {
            return null;
        }
        try {
            return nativeDecodeLayer(container, password);
        } catch (Throwable error) {
            return null;
        }
    }

    private static native byte[] nativeDecodeLayer(byte[] container, String password);

    // 版本伪装细节表（native）
    public static final int HINT_STARTUP = 0;
    public static final int HINT_CALL_START = 1;
    public static final int HINT_CALL = 2;
    public static final int HINT_MINI_PROGRAM = 3;
    public static final int HINT_WALLET_URI = 4;
    public static final int HINT_WALLET_CLASS = 5;
    public static final int HINT_CALL_SHUTDOWN = 6;
    public static final int HINT_EXT_UNAVAILABLE = 7;
    /** 登录链路：服务端对低版本直接拒绝登录。 */
    public static final int HINT_LOGIN = 8;

    public static boolean hintMatch(int kind, String value) {
        if (value == null || !isNativeAvailable()) {
            return false;
        }
        try {
            return nativeHintMatch(kind, value);
        } catch (Throwable error) {
            return false;
        }
    }

    /** 由 native 计算伪装版本；native 不可用时返回 0。 */
    public static int spoofVersion(int realVersion) {
        if (!isNativeAvailable()) {
            return 0;
        }
        try {
            return nativeSpoofVersion(realVersion);
        } catch (Throwable error) {
            return 0;
        }
    }

    private static native boolean nativeHintMatch(int kind, String value);

    private static native int nativeSpoofVersion(int realVersion);

    public static boolean isNativeAvailable() {
        if (nativeAvailable == null) {
            nativeAvailable = loadNative();
        }
        return nativeAvailable;
    }

    private static boolean loadNative() {
        return NativeLibrary.load();
    }
}
