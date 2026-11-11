package io.github.shadowbaby.wechatxposed.tool.hook.spoof;

import io.github.shadowbaby.wechatxposed.tool.BuildConfig;
import io.github.shadowbaby.wechatxposed.tool.hook.framework.ToolLogger;


public final class SpoofProfiles {

    private static final String PROFILE_ASSETS = "7b52d971be46223af131dcdbf0ec26";

    private static final String PLAY_PROFILE_ASSETS = "13ecc51414db3b4612c5518ea4158a4";

    private static volatile SpoofProfile current;
    private SpoofProfiles() {}
    public static SpoofProfile current() { return current; }

    public static boolean configure(String overridePair, String versionName, int versionCode, String moduleApkPath) {
        return configure(overridePair, versionName, versionCode, moduleApkPath, 1);
    }


    public static boolean configureWithRetry(String overridePair, String versionName, int versionCode, String moduleApkPath) {
        return configure(overridePair, versionName, versionCode, moduleApkPath, 3);
    }

    private static boolean configure(String overridePair, String versionName, int versionCode, String moduleApkPath, int attempts) {
        current = null;
        for (int attempt = 1; attempt <= attempts; attempt++) {
            try {
                SpoofTrust.loadFromApk(moduleApkPath);
                break;
            } catch (SpoofTrust.LoadFailure error) {
                Throwable cause = error.getCause();
                ToolLogger.log("spoof rules: trust load failed reason=" + error.reason
                        + " retryable=" + error.retryable + " attempt=" + attempt + "/" + attempts
                        + (cause == null ? "" : " cause=" + cause.getClass().getSimpleName()));
                if (!error.retryable || attempt == attempts) return false;
                try { Thread.sleep(500L * attempt); }
                catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    return false;
                }
            }
        }
        String builtInText = readBuiltInFromApk(moduleApkPath, versionName);
        SpoofProfile contract = SpoofProfile.contractTemplate(builtInText);
        SpoofProfile parsed = accepted(builtInText, versionName, versionCode, contract);
        boolean imported = false;
        if (overridePair != null && !overridePair.isEmpty()) {
            SpoofProfile candidate = accepted(overridePair, versionName, versionCode, contract);
            if (candidate != null) { parsed = candidate; imported = true; }
            else ToolLogger.log("spoof rules: imported pair incomplete/invalid/wrong host");
        }
        if (parsed == null) {
            ToolLogger.log("spoof rules: no complete profile for host " + versionName + "/" + versionCode);
            return false;
        }
        current = parsed;
        ToolLogger.log("spoof rules: " + parsed.versionName + (imported ? " (imported)" : " (built-in)"));
        return true;
    }

    private static SpoofProfile accepted(String pair, String name, int code, SpoofProfile contract) {
        try {
            SpoofRulePair rules = validatedPair(pair, name, code, contract);
            return SpoofProfile.parse(rules.normalized, name);
        } catch (IllegalArgumentException ignored) { return null; }
    }

    public static SpoofRulePair validatedPair(String encoded, String builtIn, String name, int code) {
        return validatedPair(encoded, name, code, SpoofProfile.contractTemplate(builtIn));
    }

    private static SpoofRulePair validatedPair(String encoded, String name, int code, SpoofProfile contract) {
        SpoofRulePair pair = SpoofRulePair.decode(encoded);
        SpoofProfile profile = SpoofProfile.parse(pair.normalized, name);
        if (!pair.matches(name, code) || profile == null || !profile.covers(contract)) throw new IllegalArgumentException("Incomplete/wrong-host H/S pair");
        return pair;
    }


    public static String profileAsset(String versionName) {
        return "8.0.48".equals(versionName) ? PLAY_PROFILE_ASSETS : PROFILE_ASSETS;
    }

    private static String readBuiltInFromApk(String path, String versionName) {
        if (path == null || path.isEmpty()) return null;
        try (java.util.zip.ZipFile zip = new java.util.zip.ZipFile(path)) {
            return SpoofRulePair.pack(read(zip, BuildConfig.SPOOF_HOOKS_ASSET), read(zip, profileAsset(versionName)));
        } catch (Exception error) { return null; }
    }

    private static String read(java.util.zip.ZipFile zip, String asset) throws java.io.IOException {
        java.util.zip.ZipEntry entry = zip.getEntry("assets/" + asset);
        if (entry == null) throw new java.io.IOException("Missing rule asset");
        try (java.io.InputStream input = zip.getInputStream(entry)) {
            var output = new java.io.ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int count;
            while ((count = input.read(buffer)) != -1) {
                if (output.size() + count > SpoofCodec.MAX_ENCODED) throw new java.io.IOException("Rule asset bounds");
                output.write(buffer, 0, count);
            }
            return SpoofCodec.text(output.toByteArray());
        }
    }
}
