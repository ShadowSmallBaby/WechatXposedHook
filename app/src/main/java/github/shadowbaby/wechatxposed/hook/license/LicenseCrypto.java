package github.shadowbaby.wechatxposed.hook.license;

import github.shadowbaby.wechatxposed.hook.loader.NativeLibrary;

public final class LicenseCrypto {

    private static Boolean nativeAvailable;

    private static String[] structure;

    public static final int TAG_LICENSE = 0;

    public static final int TAG_VERIFIER6 = 1;

    private LicenseCrypto() {
    }

    public static boolean isUsable(String stored, String account, int tag) {
        return nativeAvailable() && nativeIsUsable(stored, account, tag);
    }

    public static synchronized String[] structure() {
        if (structure == null) {
            structure = nativeAvailable() ? nativeStructure() : new String[0];
        }
        return structure;
    }

    public static String dbFileName() {
        String[] items = structure();
        return items.length > 0 ? items[0] : "";
    }

    public static String[] rows(String account, String latestVersions, String fpVersions,
                                String fp, String fpAsync) {
        return nativeAvailable()
                ? nativeRows(account, latestVersions, fpVersions, fp, fpAsync)
                : null;
    }

    private static boolean nativeAvailable() {
        if (nativeAvailable == null) {
            nativeAvailable = loadNative();
        }
        return nativeAvailable;
    }

    private static boolean loadNative() {
        return NativeLibrary.load();
    }

    private static native boolean nativeIsUsable(String stored, String account, int tag);

    private static native String[] nativeStructure();

    private static native String[] nativeRows(String account, String latestVersions,
                                               String fpVersions, String fp, String fpAsync);
}
