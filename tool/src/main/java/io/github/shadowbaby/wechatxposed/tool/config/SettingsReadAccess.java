package io.github.shadowbaby.wechatxposed.tool.config;


public final class SettingsReadAccess {
    private SettingsReadAccess() {}

    public static boolean allowed(int callerUid, int moduleUid, String[] packages) {
        if (callerUid == moduleUid) return true;
        if (packages == null) return false;
        for (String name : packages) {
            if ("com.tencent.mm".equals(name)) return true;
        }
        return false;
    }
}
