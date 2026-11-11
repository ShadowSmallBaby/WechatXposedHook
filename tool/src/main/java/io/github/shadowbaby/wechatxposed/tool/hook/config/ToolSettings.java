package io.github.shadowbaby.wechatxposed.tool.hook.config;

import org.json.JSONObject;


public final class ToolSettings {

    public static final int MINI_OFF = 0;
    public static final int MINI_LIB = 1;
    public static final int MINI_CGI = 2;
    public static final int MINI_JSAPI = 3;


    public static final int DEFAULT_TARGET_VERSION = 0x28004F30;

    public final boolean enabled;
    public final boolean login;
    public final boolean call;
    public final boolean global;
    public final boolean tablet;
    public final boolean log;
    public final int miniProgramMode;
    public final int miniLibraryResetEpoch;
    public final int targetVersion;
    public final String targetVersionName;
    public final String spoofRules;

    private ToolSettings(boolean enabled, boolean login, boolean call, boolean global,
            boolean tablet, boolean log, int miniProgramMode, int targetVersion,
            String targetVersionName, String spoofRules) {
        this(enabled, login, call, global, tablet, log, miniProgramMode, targetVersion,
                targetVersionName, spoofRules, 0);
    }

    private ToolSettings(boolean enabled, boolean login, boolean call, boolean global,
            boolean tablet, boolean log, int miniProgramMode, int targetVersion,
            String targetVersionName, String spoofRules, int miniLibraryResetEpoch) {
        this.enabled = enabled;
        this.login = login;
        this.call = call;
        this.global = global;
        this.tablet = tablet;
        this.log = log;
        this.miniProgramMode = miniProgramMode;
        this.miniLibraryResetEpoch = Math.max(0, miniLibraryResetEpoch);
        this.targetVersion = targetVersion;
        this.targetVersionName = targetVersionName;
        this.spoofRules = spoofRules;
    }

    public static ToolSettings defaults() {
        return new ToolSettings(true, true, true, false, false, false, MINI_LIB,
                DEFAULT_TARGET_VERSION, "8.0.79", "");
    }

    public static ToolSettings disabled() {
        return new ToolSettings(false, false, false, false, false, false, MINI_OFF,
                DEFAULT_TARGET_VERSION, "8.0.79", "");
    }

    public static ToolSettings parse(String json) {
        if (json == null || json.isEmpty()) {
            return defaults();
        }
        try {
            JSONObject root = new JSONObject(json);
            int mode = root.optInt("miniProgramMode", MINI_LIB);
            if (mode < MINI_OFF || mode > MINI_JSAPI) {
                mode = MINI_OFF;
            }
            int target = root.optInt("targetVersion", DEFAULT_TARGET_VERSION);
            if ((target & 0xFFFFFF00) == 0) {
                target = DEFAULT_TARGET_VERSION;
            } else if (target == 0x28004F00) {

                target = 0x28004F30;
            }
            return new ToolSettings(
                    root.optBoolean("enabled", true),
                    root.optBoolean("login", true),
                    root.optBoolean("call", true),
                    root.optBoolean("global", false),
                    root.optBoolean("tablet", false),
                    root.optBoolean("log", false),
                    mode,
                    target,
                    root.optString("targetVersionName", "8.0." + ((target >>> 8) & 255)),
                    root.optString("spoofRules", ""),
                    root.optInt("miniLibraryResetEpoch", 0));
        } catch (Throwable error) {
            return defaults();
        }
    }
}
