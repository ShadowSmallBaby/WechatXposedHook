package io.github.shadowbaby.wechatxposed.tool.hook.config;


public final class RuntimeSettings {

    private static volatile ToolSettings current = ToolSettings.defaults();

    private RuntimeSettings() {
    }

    public static ToolSettings get() {
        return current;
    }

    public static synchronized void update(ToolSettings settings) {
        if (settings != null) {
            current = settings;
        }
    }


    public static synchronized boolean runIfCurrent(ToolSettings expected, Runnable action) {
        if (current != expected) return false;
        action.run();
        return true;
    }
}
