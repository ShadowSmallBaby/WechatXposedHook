package io.github.shadowbaby.wechatxposed.tool.hook.feature.tablet;


public final class PadSpoofState {

    private static final ThreadLocal<Boolean> ACTIVE = new ThreadLocal<>();

    private PadSpoofState() {
    }

    public static void enter() {
        ACTIVE.set(Boolean.TRUE);
    }

    public static void exit() {
        ACTIVE.remove();
    }

    public static boolean active() {
        return Boolean.TRUE.equals(ACTIVE.get());
    }
}
