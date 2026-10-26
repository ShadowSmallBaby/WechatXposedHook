package github.shadowbaby.wechatxposed.hook.support.pack;

import android.content.ContentValues;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import github.shadowbaby.wechatxposed.hook.deploy.StartupCheck;
import github.shadowbaby.wechatxposed.hook.license.Activation;
import github.shadowbaby.wechatxposed.hook.loader.SecretConstants;
import github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import github.shadowbaby.wechatxposed.hook.loader.util.Secret;
import java.io.File;
import java.nio.charset.StandardCharsets;
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

    /** 宿主 DATA 表的字段名（壳用它读功能表/授权状态）。 */
    private static final String TAG_FP = Secret.of(SecretConstants.X30_TAG_FP);
    private static final String TAG_FP_ASYNC = Secret.of(SecretConstants.X30_TAG_FP_ASYNC);
    private static final String TAG_FP_VERSIONS =
            Secret.of(SecretConstants.X30_TAG_FP_VERSIONS);
    private static final String TAG_FP_VERSIONS_V7 =
            Secret.of(SecretConstants.X30_TAG_FP_VERSIONS_V7);
    private static final String TAG_LATEST_VERSIONS =
            Secret.of(SecretConstants.X30_TAG_LATEST_VERSIONS);
    private static final String TAG_VALID = Secret.of(SecretConstants.X30_TAG_VALID);
    private static final String TAG_NEW_USER = Secret.of(SecretConstants.X30_TAG_NEW_USER);
    private static final String TAG_DISCLAIMER =
            Secret.of(SecretConstants.X30_TAG_DISCLAIMER);
    private static final String TAG_HOOK_FAIL = Secret.of(SecretConstants.X30_TAG_HOOK_FAIL);
    private static final String TAG_SAFE_MODE = Secret.of(SecretConstants.X30_TAG_SAFE_MODE);
    private static final String TAG_SAFE_MODE_CNT =
            Secret.of(SecretConstants.X30_TAG_SAFE_MODE_CNT);
    private static final String TAG_DISABLE_SAFEMODE =
            Secret.of(SecretConstants.X30_TAG_DISABLE_SAFEMODE);

    private static final String[] EXTENSION_FEATURES = {"af", "sf", "mf"};

    private static final String DB_DIR = "databases/";

    private static volatile boolean done;

    private static volatile File lastDataDir;

    private static volatile boolean lastAllowExtensions;

    /** 最近一次守卫得到的级别；功能查询要按它决定 VIP/专业标签。默认 0 = 未授权。 */
    private static volatile int currentLevel;

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

    public static final int LEVEL_NONE = 0;
    public static final int LEVEL_BASE = 1;
    public static final int LEVEL_PRO = 2;

    private static final String LEVEL_TAG = "WXH_LEVEL";

    /** 项目授权标记：wxid,机器码,群号（普通）或 wxid,机器码,卡密（高级）。 */
    private static final String LIC_TAG = "WXH_LIC";

    private static final String EXTENSIONS = "sf,mf,af";

    /**
     * 项目授权守卫：读数据库里的 {@code WXH_LEVEL}，并让数据库与级别保持一致。
     *
     * 数据库里没有项目字段（全新库或原版库）时按原版免费版初始化：
     * 四个基础功能 + 协议待确认。返回当前级别，调用方据此决定装不装授权绕过。
     */
    /**
     * 只读授权级别，不写库；供自解决定是否恢复扩展包。
     * 数据库还没建立或字段缺失时按未授权处理。
     * 账号未知时按普通授权兜底，只适合展示与包恢复。
     */
    public static synchronized int readLevel(File dataDir) {
        return readLevel(dataDir, true);
    }

    /**
     * @param fallbackBase 账号未知时是否按普通授权兜底。
     *                     授权判定必须传 false：兜底值会让未解析出账号的进程
     *                     被当成已授权，壳跳过免责声明，授权绕过也照装。
     */
    public static synchronized int readLevel(File dataDir, boolean fallbackBase) {
        try {
            if (DB_NAME.isEmpty() || DB_KEY.isEmpty()
                    || AES_MODE.isEmpty() || AES_KEY.isEmpty()) {
                return LEVEL_NONE;
            }
            File file = new File(dataDir, DB_DIR + DB_NAME);
            if (!file.isFile()) {
                return LEVEL_NONE;
            }
            String account = StartupCheck.readLoginAccount(dataDir);
            if (account == null || account.isEmpty()) {
                // 启动早期壳还没加载完，账号必然解析不出来。展示路径按普通授权
                // 兜底（普通授权只是点一下协议，代价最低）；授权判定路径必须返回 0，
                // 否则等于替用户签了协议、还把授权绕过装给未授权进程。
                // 账号到达后 setRuntimeWxid 会重算，并把账号落盘供下次启动使用。
                return fallbackBase ? LEVEL_BASE : LEVEL_NONE;
            }
            SQLiteDatabase database = SQLiteDatabase.openDatabase(file.getPath(), null,
                    SQLiteDatabase.OPEN_READONLY);
            try {
                String stored = readTag(database, account, LEVEL_TAG);
                if (stored == null) {
                    return LEVEL_NONE;
                }
                int level = parseInt(stored, LEVEL_NONE);
                return level < LEVEL_NONE || level > LEVEL_PRO ? LEVEL_NONE : level;
            } finally {
                database.close();
            }
        } catch (Throwable error) {
            return LEVEL_NONE;
        }
    }

    public static synchronized int syncLevel(File dataDir, boolean trusted) {
        return guard(dataDir, -1, trusted);
    }

    /** 当前授权级别；功能查询（msg 150）按它决定标签与扩展。 */
    public static int currentLevel() {
        return currentLevel;
    }

    /**
     * 用户同意协议（普通授权）时写入级别；卡密授权带卡密写高级。
     *
     * @return 实际落库的级别。账号还没解析出来时返回 0 且不写库，
     *         调用方必须据此判断是否真的激活成功，不能只看输入是否合法。
     */
    public static synchronized int grant(File dataDir, int level) {
        return guard(dataDir, level, true, null);
    }

    public static synchronized int grant(File dataDir, int level, String card) {
        return guard(dataDir, level, true, card);
    }

    private static int guard(File dataDir, int target, boolean trusted) {
        return guard(dataDir, target, trusted, null);
    }

    private static int guard(File dataDir, int target, boolean trusted, String card) {
        try {
            if (DB_NAME.isEmpty() || DB_KEY.isEmpty()
                    || AES_MODE.isEmpty() || AES_KEY.isEmpty()) {
                return LEVEL_NONE;
            }
            String account = StartupCheck.readLoginAccount(dataDir);
            if (account == null || account.isEmpty()) {
                return LEVEL_NONE;
            }
            File file = new File(dataDir, DB_DIR + DB_NAME);
            if (!file.isFile()) {
                // 壳还没建库时由守卫先建，保证授权内容可控；壳自己打开后会按需迁移。
                createDatabase(file);
            }
            if (!file.isFile()) {
                return LEVEL_NONE;
            }
            try (SQLiteDatabase database = SQLiteDatabase.openDatabase(file.getPath(), null,
                    SQLiteDatabase.OPEN_READWRITE)) {
                String stored = readTag(database, account, LEVEL_TAG);
                int level;
                if (stored == null) {
                    level = LEVEL_NONE;
                    setValue(database, account, LEVEL_TAG, "INT", encrypt("0"));
                    setValue(database, account, TAG_FP, "STRING", encrypt(""));
                    setValue(database, account, TAG_FP_ASYNC, "STRING", encrypt(""));
                    setValue(database, account, TAG_FP_VERSIONS, "JSON",
                            encrypt(DEFAULT_FP_VERSIONS));
                    setValue(database, account, TAG_VALID, "BOOLEAN", encrypt("false"));
                    setValue(database, account, TAG_NEW_USER, "INT", encrypt("1"));
                    setValue(database, account, TAG_DISCLAIMER, "BOOLEAN",
                            encrypt("false"));
                    ModuleLogger.log("license guard: init level=0");
                } else {
                    level = parseInt(stored, LEVEL_NONE);
                    if (level < LEVEL_NONE || level > LEVEL_PRO) {
                        // 字段被外部写坏时按未授权处理，避免误开高级功能。
                        level = LEVEL_NONE;
                    }
                    // 显式授予（target >= 0）刚刚验过签，只有启动路径需要复核。
                    if (target < 0 && level >= LEVEL_PRO) {
                        level = recheckCard(database, account, level);
                    }
                }
                if (target >= 0 && target != level) {
                    level = target;
                    setValue(database, account, LEVEL_TAG, "INT",
                            encrypt(String.valueOf(level)));
                    ModuleLogger.log("license guard: level -> " + level);
                }
                applyLevel(database, account, level, trusted && level >= LEVEL_PRO, card);
                currentLevel = level;
                return level;
            }
        } catch (Throwable error) {
            ModuleLogger.log(error);
            return LEVEL_NONE;
        }
    }

    /** 让功能表/版本表/valid 与级别一致；值没变就不写，避免触发壳的重启检测。 */
    private static void applyLevel(SQLiteDatabase database, String account, int level,
            boolean extensions, String card) throws Exception {
        boolean pro = level >= LEVEL_PRO;
        boolean authorized = level >= LEVEL_BASE;
        writeLic(database, account, level, card);
        // 未授权时 valid=false + is_new_user=1 才会走壳的免责声明分支；
        // 授权后把这些标记补回正常值。
        setIfChanged(database, account, TAG_VALID, "BOOLEAN",
                Boolean.toString(authorized));
        if (!authorized) {
            setIfChanged(database, account, TAG_NEW_USER, "INT", "1");
        }
        setIfChanged(database, account, TAG_HOOK_FAIL, "BOOLEAN", "false");
        clearSafeMode(database, account);
        ensureVersions(database, account, pro);

        // LatestVersions 里的 fp_sf/fp_mf/fp_af 才是壳加载扩展包的依据，
        // 非高级授权时必须删掉，否则 FPVersions 清了也会照常加载。
        if (!pro) {
            dropVersions(database, account, TAG_LATEST_VERSIONS, "fp_");
        }

        // 未授权保持「待确认协议」；授权后标记为已确认，壳不再弹声明。
        setIfChanged(database, account, TAG_DISCLAIMER, "BOOLEAN",
                Boolean.toString(authorized));

        // LIC 交给 LicenseInstaller 维护：它会在缺失时写入「免费版」凭证（#f#）。
        // 这里清空会让壳运行中 license failed，普通版也不该动它。

        // FP_cls_* 保留原值：打赏页/功能列表要靠它列出功能，
        // 清掉会让列表变空；扩展实体已被目录清理挡住，不会真的加载。

        String current = readTag(database, account, TAG_FP);
        String want;
        if (!authorized) {
            // 未授权不加载任何功能包，只保留壳的核心界面。
            want = "";
        } else if (extensions) {
            want = mergeList(current == null ? "" : current,
                    mergeList(DEFAULT_FP, EXTENSIONS));
        } else {
            // DEFAULT_FP 自带 af/sf/mf；普通授权只保留基础包，扩展目录也已清理。
            want = restrictFeatures(mergeList(current == null ? "" : current, DEFAULT_FP));
        }
        if (!want.equals(current)) {
            setValue(database, account, TAG_FP, "STRING", encrypt(want));
            ModuleLogger.log("license guard: fp " + current + " -> " + want);
        }
        String async = readTag(database, account, TAG_FP_ASYNC);
        String wantAsync = authorized
                ? mergeList(async == null ? "" : async, DEFAULT_FP_ASYNC) : "";
        if (!wantAsync.equals(async)) {
            setValue(database, account, TAG_FP_ASYNC, "STRING", encrypt(wantAsync));
            ModuleLogger.log("license guard: fp_async -> " + wantAsync);
        }
    }

    /**
     * 启动时复核高级授权。
     *
     * 数据库里的 WXH_LEVEL 只是个整数：改库、整目录迁移到新设备、卡密到期
     * 都不会被发现。这里用 WXH_LIC 第三段的卡密重新验一次签，验不过就落回
     * 普通授权；公开码时代遗留的「群号当卡密」也会在这里自然失效。
     */
    private static int recheckCard(SQLiteDatabase database, String account, int level)
            throws Exception {
        String lic = readTag(database, account, LIC_TAG);
        String card = licPart(lic, 2);
        if (Activation.verifyCode(card, account) >= LEVEL_PRO) {
            return level;
        }
        // 机器码变了说明换了设备，或构建时证书固定值丢了（机器码哈希少一段）。
        // 后者属于发布事故，日志里单独标出来便于定位。
        String now = Activation.machineCode(account);
        String recorded = licPart(lic, 1);
        ModuleLogger.log("license guard: card recheck failed"
                + " card=" + (card == null ? "none" : card.length() + " chars")
                + " machine=" + (now != null && now.equals(recorded) ? "same" : "changed")
                + ", drop to base");
        setValue(database, account, LEVEL_TAG, "INT", encrypt(String.valueOf(LEVEL_BASE)));
        return LEVEL_BASE;
    }

    /** 从 WXH_LIC「wxid,机器码,卡密」里取第 index 段（0 起）。 */
    private static String licPart(String lic, int index) {
        if (lic == null || lic.isEmpty()) {
            return null;
        }
        String[] parts = lic.split(",", 3);
        if (parts.length <= index) {
            return null;
        }
        String value = parts[index].trim();
        return value.isEmpty() ? null : value;
    }

    /**
     * 项目授权标记：普通授权写「wxid,机器码,群号」，高级授权写「wxid,机器码,卡密」。
     * 未授权时留空；已写入的值在启动时不重复覆盖。
     */
    private static void writeLic(SQLiteDatabase database, String account, int level,
            String card) throws Exception {
        String current = readTag(database, account, LIC_TAG);
        if (level < LEVEL_BASE) {
            if (!"".equals(current)) {
                setIfChanged(database, account, LIC_TAG, "STRING", "");
                ModuleLogger.log("license guard: WXH_LIC cleared");
            }
            return;
        }
        boolean hasCard = card != null && !card.isEmpty();
        if (!hasCard && current != null && !current.isEmpty()) {
            // 普通授权已写过，或启动时没有新卡密：保留已有记录。
            return;
        }
        String wxid = Activation.wxid();
        String machine = Activation.machineCode();
        String tail = level >= LEVEL_PRO ? card : Activation.group();
        String value = (wxid == null ? "" : wxid) + ","
                + (machine == null ? "" : machine) + ","
                + (tail == null ? "" : tail);
        if (!value.equals(current)) {
            setValue(database, account, LIC_TAG, "STRING", encrypt(value));
            ModuleLogger.log("license guard: WXH_LIC=" + value);
        }
    }

    /** 壳还没建库时按壳的 schema 建一份空库，避免守卫无从对齐。 */
    private static void createDatabase(File file) {
        try {
            File parent = file.getParentFile();
            if (parent != null && !parent.isDirectory() && !parent.mkdirs()) {
                ModuleLogger.log("license guard: cannot create db dir");
                return;
            }
            try (SQLiteDatabase database = SQLiteDatabase.openOrCreateDatabase(file, null)) {
                database.execSQL("CREATE TABLE IF NOT EXISTS android_metadata (locale TEXT)");
                database.execSQL("CREATE TABLE IF NOT EXISTS DATA(_ID INTEGER PRIMARY KEY NOT NULL,"
                        + " ACCOUNT TEXT, TAG TEXT, TYPE TEXT, VALUE TEXT, DATA BLOB)");
                database.setVersion(1);
            }
            if (file.isFile()) {
                ModuleLogger.log("license guard: database created");
            }
        } catch (Throwable error) {
            ModuleLogger.log(error);
        }
    }

    private static int parseInt(String text, int fallback) {
        try {
            return Integer.parseInt(text.trim());
        } catch (Throwable error) {
            return fallback;
        }
    }

    /** 授权级别变化后重新对齐数据库（卡密成功后调用）。 */
    public static synchronized void retry() {
        File dataDir = Activation.dataDir();
        if (dataDir != null) {
            syncLevel(dataDir, true);
        }
    }

    private static boolean enableFeature(File dataDir, boolean allowExtensions)
            throws Exception {
        boolean extensions = allowExtensions;
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
        try (SQLiteDatabase database = SQLiteDatabase.openDatabase(file.getPath(), null,
                SQLiteDatabase.OPEN_READWRITE)) {
            clearSafeMode(database, account);
            ensureVersions(database, account, extensions);
            String current = readTag(database, account, TAG_FP);
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
                setValue(database, account, TAG_FP, "STRING", encrypt(merged));
                ModuleLogger.log("feature unlock: fp " + current + " -> " + merged);
            } else {
                ModuleLogger.log("feature unlock: fp keep " + current);
            }
            String async = readTag(database, account, TAG_FP_ASYNC);
            String mergedAsync = mergeList(async == null ? "" : async,
                    DEFAULT_FP_ASYNC);
            if (!mergedAsync.equals(async)) {
                setValue(database, account, TAG_FP_ASYNC, "STRING",
                        encrypt(mergedAsync));
                ModuleLogger.log("feature unlock: fp_async -> " + mergedAsync);
            }
        }
        return true;
    }

    private static void ensureVersions(SQLiteDatabase database, String account,
            boolean allowExtensions) throws Exception {
        String text = readTag(database, account, TAG_FP_VERSIONS);
        if (text == null) {
            setValue(database, account, TAG_FP_VERSIONS, "JSON",
                    encrypt(DEFAULT_FP_VERSIONS));
            ModuleLogger.log("feature unlock: fp versions created");
        } else {
            JSONObject json = new JSONObject(text);
            boolean changed = false;
            if (allowExtensions) {
                changed |= putVersionIfAbsent(json, "sf", 75);
                changed |= putVersionIfAbsent(json, "mf", 137);
                changed |= putVersionIfAbsent(json, "af", 171);
            } else {
                for (String feature : EXTENSION_FEATURES) {
                    changed |= json.remove(feature) != null;
                }
            }
            if (changed) {
                setValue(database, account, TAG_FP_VERSIONS, "JSON",
                        encrypt(json.toString()));
                ModuleLogger.log("feature unlock: fp versions -> " + json);
            }
        }
        ensureVersionRow(database, account, TAG_FP_VERSIONS_V7, DEFAULT_FP_VERSIONS_V7,
                allowExtensions);
        // 用实际加载的版本号回填 FPVersions，否则壳会认为功能包有更新，
        // 联网失败后把功能全部 closed。
        syncActualVersions(database, account, allowExtensions);
    }

    /** 把 FPVersions_v7 里的实际版本同步到 FPVersions 和 LatestVersions。 */
    private static void syncActualVersions(SQLiteDatabase database, String account,
            boolean allowExtensions) throws Exception {
        String v7Text = readTag(database, account, TAG_FP_VERSIONS_V7);
        if (v7Text == null || v7Text.isEmpty()) {
            return;
        }
        JSONObject actual = new JSONObject(v7Text);
        // FPVersions 的 key 列表是打赏页/功能页的展示来源，不能删；
        // 只把已有 key 的版本号改成实际值。
        String versionsText = readTag(database, account, TAG_FP_VERSIONS);
        if (versionsText != null && !versionsText.isEmpty()) {
            JSONObject versions = new JSONObject(versionsText);
            boolean changed = false;
            java.util.Iterator<String> keys = actual.keys();
            while (keys.hasNext()) {
                String key = keys.next();
                // 普通授权只维护基础包，扩展 key 不补，保持 4 个基础项。
                if (!allowExtensions && isExtensionFeature(key)) {
                    if (versions.has(key)) {
                        versions.remove(key);
                        changed = true;
                    }
                    continue;
                }
                if (!versions.has(key)) {
                    versions.put(key, actual.optInt(key));
                    changed = true;
                } else if (versions.optInt(key) != actual.optInt(key)) {
                    versions.put(key, actual.optInt(key));
                    changed = true;
                }
            }
            if (changed) {
                setValue(database, account, TAG_FP_VERSIONS, "JSON",
                        encrypt(versions.toString()));
                ModuleLogger.log("license guard: fp versions synced -> " + versions);
            }
        }
    }

    private static void ensureVersionRow(SQLiteDatabase database, String account,
            String tag, String value, boolean allowExtensions) throws Exception {
        String text = readTag(database, account, tag);
        if (text == null) {
            JSONObject fresh = new JSONObject(value);
            if (!allowExtensions) {
                for (String feature : EXTENSION_FEATURES) {
                    fresh.remove(feature);
                }
            }
            setValue(database, account, tag, "JSON", encrypt(fresh.toString()));
            ModuleLogger.log("feature unlock: " + tag + " created");
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
        if (!allowExtensions) {
            for (String feature : EXTENSION_FEATURES) {
                changed |= json.remove(feature) != null;
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
        java.util.List<String> items = parseList(current);
        for (String value : parseList(defaults)) {
            if (!items.contains(value)) {
                items.add(value);
            }
        }
        return join(items);
    }

    /** 证书不可信时只保留基础功能，移除 af/sf/mf，避免宿主加载空扩展 dex。 */
    private static String restrictFeatures(String current) {
        java.util.List<String> items = new java.util.ArrayList<>();
        for (String value : parseList(current)) {
            if (!isExtensionFeature(value)) {
                items.add(value);
            }
        }
        if (items.isEmpty()) {
            items.add("themes");
        }
        return join(items);
    }

    /** 拆分逗号列表：去空、去重并保留顺序。 */
    private static java.util.List<String> parseList(String text) {
        java.util.List<String> items = new java.util.ArrayList<>();
        for (String item : text.split(",")) {
            String value = item.trim();
            if (!value.isEmpty() && !items.contains(value)) {
                items.add(value);
            }
        }
        return items;
    }

    private static String join(java.util.List<String> items) {
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
        setIfChanged(database, account, TAG_SAFE_MODE, "STRING", "");
        setIfChanged(database, account, TAG_SAFE_MODE_CNT, "INT", "0");
        setIfChanged(database, account, TAG_DISABLE_SAFEMODE, "BOOLEAN", "true");
    }

    /** 读取并解密单个 TAG，读不到返回 null。 */
    private static String readTag(SQLiteDatabase database, String account, String tag) {
        try (Cursor cursor = database.rawQuery(
                "select VALUE from DATA where ACCOUNT=? and TAG=?",
                new String[]{account, tag})) {
            if (!cursor.moveToFirst()) {
                return null;
            }
            return decrypt(cursor.getString(0));
        } catch (Throwable error) {
            return null;
        }
    }

    /** 值没变就不写，避免触发壳的重启检测。 */
    private static void setIfChanged(SQLiteDatabase database, String account,
            String tag, String type, String plain) throws Exception {
        if (plain.equals(readTag(database, account, tag))) {
            return;
        }
        setValue(database, account, tag, type, encrypt(plain));
    }

    /** 从版本 JSON 里去掉扩展包 key；LatestVersions 用 "fp_" 前缀。 */
    private static void dropVersions(SQLiteDatabase database, String account,
            String tag, String prefix) throws Exception {
        String text = readTag(database, account, tag);
        if (text == null) {
            return;
        }
        JSONObject json = new JSONObject(text);
        boolean changed = false;
        for (String feature : EXTENSION_FEATURES) {
            changed |= json.remove(prefix + feature) != null;
        }
        if (changed) {
            setValue(database, account, tag, "JSON", encrypt(json.toString()));
            ModuleLogger.log("license guard: " + tag + " -> " + json);
        }
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
                    android.util.Base64.DEFAULT)), StandardCharsets.UTF_8);
        } catch (Throwable error) {
            return null;
        }
    }

    private static String encrypt(String value) throws Exception {
        byte[] key = hex(DB_KEY);
        Cipher cipher = Cipher.getInstance(AES_MODE);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, AES_KEY),
                new IvParameterSpec(new byte[16]));
        byte[] data = cipher.doFinal(value.getBytes(StandardCharsets.UTF_8));
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
