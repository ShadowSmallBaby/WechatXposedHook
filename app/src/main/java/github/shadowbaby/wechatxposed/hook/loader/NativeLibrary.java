package github.shadowbaby.wechatxposed.hook.loader;

public final class NativeLibrary {

    public static final String NAME = "wexhook";

    private NativeLibrary() {
    }

    public static boolean load() {
        try {
            System.loadLibrary(NAME);
            return true;
        } catch (Throwable error) {
            return false;
        }
    }
}
