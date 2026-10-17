package github.shadowbaby.wechatxposed.hook.loader;

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

    private static native String nativeOf(String encoded);

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
