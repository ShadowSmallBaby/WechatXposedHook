package github.shadowbaby.wechatxposed.hook.support.pack;

import android.content.ContentValues;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import github.shadowbaby.wechatxposed.hook.BuildConfig;
import github.shadowbaby.wechatxposed.hook.deploy.StartupCheck;
import github.shadowbaby.wechatxposed.hook.license.Activation;
import github.shadowbaby.wechatxposed.hook.loader.SecretConstants;
import github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import github.shadowbaby.wechatxposed.hook.loader.util.Secret;
import java.io.File;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.json.JSONObject;

/**
 * 在宿主进程内准备 X 3.0 扩展功能加载条件。
 *
 * 补齐宿主功能表的 fp/版本字段，宿主在 hook 安装前就会读取该表。
 * 表名、AES key 与默认值都在 native，Java 只保留 SQLite 读写。
 * 以宿主自身的 uid/域运行，避免 root shell 被 SELinux/CE 拦截。
 */
public final class FeaturePackUnlock {

    private static final String DB_NAME = packValue(Secret.PACK_DB_NAME);

    private static final String DB_KEY = packValue(Secret.PACK_DB_KEY);

    private static final String DEFAULT_FP_VERSIONS =
            packValue(Secret.PACK_DEFAULT_VERSIONS);

    private static final String DEFAULT_FP = packValue(Secret.PACK_DEFAULT_FP);

    private static final String DEFAULT_FP_ASYNC =
            packValue(Secret.PACK_DEFAULT_FP_ASYNC);

    private static final String DEFAULT_FP_VERSIONS_V7 =
            packValue(Secret.PACK_DEFAULT_VERSIONS_V7);

    private static final String AES_MODE = Secret.of(SecretConstants.AES_ALGORITHM);

    private static final String AES_KEY = Secret.of(SecretConstants.AES_KEY_ALGORITHM);

    private static final String[] EXTENSION_FEATURES = {"af", "sf", "mf"};

    private static final String DB_DIR = "databases/";

    private static volatile boolean done;

    private static volatile File lastDataDir;

    private static volatile boolean lastAllowExtensions;

    private FeaturePackUnlock() {
    }

    public static synchronized void run(File dataDir, boolean allowExtensions) {
        lastDataDir = dataDir;
        lastAllowExtensions = allowExtensions;
        if (done) {
            return;
        }
        done = true;
        try {
            if (!enableFeature(dataDir, allowExtensions)) {
                // 账号/DB 还没就绪时允许运行时账号到达后重试。
                done = false;
            }
        } catch (Throwable error) {
            done = false;
            ModuleLogger.log(error);
        }
    }

    /** X 3.0 运行时传入权威 userId 后重跑一次。 */
    public static synchronized void retry() {
        File dataDir = lastDataDir;
        if (dataDir != null) {
            // 首次往往是公开码 + 无 wxid，allowExtensions 为 false；
            // 拿到 wxid 升级成机器码授权后必须按当前等级重算，否则扩展永远不会写入。
            lastAllowExtensions = BuildConfig.FULL_EDITION && Activation.isExtensionAllowed();
            run(dataDir, lastAllowExtensions);
        }
    }

    private static boolean enableFeature(File dataDir, boolean allowExtensions)
            throws Exception {
        boolean extensions = allowExtensions && BuildConfig.FULL_EDITION;
        if (DB_NAME.isEmpty() || DB_KEY.isEmpty()
                || DEFAULT_FP_VERSIONS.isEmpty() || DEFAULT_FP_VERSIONS_V7.isEmpty()
                || AES_MODE.isEmpty() || AES_KEY.isEmpty()) {
            ModuleLogger.log("feature unlock: native table unavailable");
            return false;
        }
        String account = StartupCheck.readLoginAccount(dataDir);
        if (account == null || account.isEmpty()) {
            ModuleLogger.log("feature unlock: no account");
            return false;
        }
        File file = new File(dataDir, DB_DIR + DB_NAME);
        if (!file.isFile()) {
            ModuleLogger.log("feature unlock: no db");
            return false;
        }
        SQLiteDatabase database = SQLiteDatabase.openDatabase(file.getPath(), null,
                SQLiteDatabase.OPEN_READWRITE);
        try {
            clearSafeMode(database, account);
            ensureVersions(database, account, extensions);
            String value = null;
            try (Cursor cursor = database.rawQuery(
                    "select VALUE from DATA where ACCOUNT=? and TAG='fp'",
                    new String[]{account})) {
                if (cursor.moveToFirst()) {
                    value = cursor.getString(0);
                }
            }
            String current = value == null ? "" : decrypt(value);
            if (current == null) {
                ModuleLogger.log("feature unlock: fp decrypt failed");
                return false;
            }
            // 只补默认值里缺的项，保留数据库里已有的项和顺序；
            // 公开版即使带上内部分量也不影响（没有扩展包就加载不出来）。
            String merged = extensions
                    ? mergeList(current, DEFAULT_FP)
                    : restrictFeatures(current);
            if (!merged.equals(current)) {
                setValue(database, account, "fp", "STRING", encrypt(merged));
                ModuleLogger.log("feature unlock: fp " + current + " -> " + merged);
            } else {
                ModuleLogger.log("feature unlock: fp keep " + current);
            }
            String async = null;
            try (Cursor cursor = database.rawQuery(
                    "select VALUE from DATA where ACCOUNT=? and TAG='fp_async'",
                    new String[]{account})) {
                if (cursor.moveToFirst()) {
                    async = decrypt(cursor.getString(0));
                }
            }
            String mergedAsync = mergeList(async == null ? "" : async,
                    DEFAULT_FP_ASYNC);
            if (async == null || !mergedAsync.equals(async)) {
                setValue(database, account, "fp_async", "STRING",
                        encrypt(mergedAsync));
                ModuleLogger.log("feature unlock: fp_async -> " + mergedAsync);
            }
        } finally {
            database.close();
        }
        return true;
    }

    private static void ensureVersions(SQLiteDatabase database, String account,
            boolean allowExtensions) throws Exception {
        String value = null;
        try (Cursor cursor = database.rawQuery(
                "select VALUE from DATA where ACCOUNT=? and TAG='FPVersions'",
                new String[]{account})) {
            if (cursor.moveToFirst()) {
                value = cursor.getString(0);
            }
        }
        if (value == null) {
            setValue(database, account, "FPVersions", "JSON",
                    encrypt(DEFAULT_FP_VERSIONS));
            ModuleLogger.log("feature unlock: FPVersions created");
        } else {
            String text = decrypt(value);
            if (text != null) {
                JSONObject json = new JSONObject(text);
                boolean changed = false;
                if (allowExtensions) {
                    changed |= putVersionIfAbsent(json, "sf", 75);
                    changed |= putVersionIfAbsent(json, "mf", 137);
                    changed |= putVersionIfAbsent(json, "af", 171);
                }
                if (changed) {
                    setValue(database, account, "FPVersions", "JSON",
                            encrypt(json.toString()));
                    ModuleLogger.log("feature unlock: FPVersions -> " + json);
                }
            }
        }
        ensureVersionRow(database, account, "FPVersions_v7", DEFAULT_FP_VERSIONS_V7);
    }

    private static void ensureVersionRow(SQLiteDatabase database, String account,
            String tag, String value) throws Exception {
        String stored = null;
        try (Cursor cursor = database.rawQuery(
                "select VALUE from DATA where ACCOUNT=? and TAG=?",
                new String[]{account, tag})) {
            if (cursor.moveToFirst()) {
                stored = cursor.getString(0);
            }
        }
        if (stored == null) {
            setValue(database, account, tag, "JSON", encrypt(value));
            ModuleLogger.log("feature unlock: " + tag + " created");
            return;
        }
        String text = decrypt(stored);
        if (text == null) {
            return;
        }
        JSONObject defaults = new JSONObject(value);
        JSONObject json = new JSONObject(text);
        boolean changed = false;
        java.util.Iterator<String> keys = defaults.keys();
        while (keys.hasNext()) {
            String key = keys.next();
            if (!json.has(key)) {
                json.put(key, defaults.get(key));
                changed = true;
            }
        }
        if (changed) {
            setValue(database, account, tag, "JSON", encrypt(json.toString()));
            ModuleLogger.log("feature unlock: " + tag + " -> " + json);
        }
    }

    private static boolean putVersionIfAbsent(JSONObject json, String key, int value) {
        if (json.has(key)) {
            return false;
        }
        try {
            json.put(key, value);
            return true;
        } catch (Exception error) {
            return false;
        }
    }

    /** 把 defaults 中缺失的项追加到 current，保留 current 原有项与顺序。 */
    private static String mergeList(String current, String defaults) {
        StringBuilder text = new StringBuilder();
        java.util.List<String> items = new java.util.ArrayList<>();
        for (String item : current.split(",")) {
            String value = item.trim();
            if (!value.isEmpty() && !items.contains(value)) {
                items.add(value);
            }
        }
        for (String item : defaults.split(",")) {
            String value = item.trim();
            if (!value.isEmpty() && !items.contains(value)) {
                items.add(value);
            }
        }
        for (String item : items) {
            if (text.length() > 0) {
                text.append(',');
            }
            text.append(item);
        }
        return text.toString();
    }

    /** 证书不可信时只保留基础功能，移除 af/sf/mf，避免宿主加载空扩展 dex。 */
    private static String restrictFeatures(String current) {
        java.util.List<String> items = new java.util.ArrayList<>();
        for (String item : current.split(",")) {
            String value = item.trim();
            if (value.isEmpty() || isExtensionFeature(value)) {
                continue;
            }
            if (!items.contains(value)) {
                items.add(value);
            }
        }
        if (items.isEmpty()) {
            items.add("themes");
        }
        StringBuilder text = new StringBuilder();
        for (String item : items) {
            if (text.length() > 0) {
                text.append(',');
            }
            text.append(item);
        }
        return text.toString();
    }

    private static boolean isExtensionFeature(String value) {
        for (String feature : EXTENSION_FEATURES) {
            if (feature.equals(value)) {
                return true;
            }
        }
        return false;
    }

    private static void clearSafeMode(SQLiteDatabase database, String account)
            throws Exception {
        setValue(database, account, "safe_mode", "STRING", encrypt(""));
        setValue(database, account, "safe_mode_cnt", "INT", encrypt("0"));
        setValue(database, account, "disable_safemode", "BOOLEAN", encrypt("true"));
    }

    private static void setValue(SQLiteDatabase database, String account, String tag,
            String type, String value) {
        ContentValues update = new ContentValues();
        update.put("VALUE", value);
        int count = database.update("DATA", update, "ACCOUNT=? and TAG=?",
                new String[]{account, tag});
        if (count == 0) {
            ContentValues insert = new ContentValues();
            insert.put("ACCOUNT", account);
            insert.put("TAG", tag);
            insert.put("TYPE", type);
            insert.put("VALUE", value);
            database.insert("DATA", null, insert);
        }
    }

    private static String packValue(int index) {
        String value = Secret.packValue(index);
        return value == null ? "" : value;
    }

    private static String decrypt(String value) {
        try {
            byte[] key = hex(DB_KEY);
            Cipher cipher = Cipher.getInstance(AES_MODE);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, AES_KEY),
                    new IvParameterSpec(new byte[16]));
            return new String(cipher.doFinal(android.util.Base64.decode(value,
                    android.util.Base64.DEFAULT)), "UTF-8");
        } catch (Throwable error) {
            return null;
        }
    }

    private static String encrypt(String value) throws Exception {
        byte[] key = hex(DB_KEY);
        Cipher cipher = Cipher.getInstance(AES_MODE);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, AES_KEY),
                new IvParameterSpec(new byte[16]));
        byte[] data = cipher.doFinal(value.getBytes("UTF-8"));
        return android.util.Base64.encodeToString(data, android.util.Base64.NO_WRAP);
    }

    private static byte[] hex(String text) {
        byte[] data = new byte[text.length() / 2];
        for (int index = 0; index < data.length; index++) {
            data[index] = (byte) Integer.parseInt(
                    text.substring(index * 2, index * 2 + 2), 16);
        }
        return data;
    }

}
