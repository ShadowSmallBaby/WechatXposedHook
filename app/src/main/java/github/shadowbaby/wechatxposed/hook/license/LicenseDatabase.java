package github.shadowbaby.wechatxposed.hook.license;

import android.content.ContentValues;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;

/**
 * 把 LicenseData 生成的 10 行写进微信目录下的 FKZ_WX_DATA。
 *
 * 微X 用 SQLiteOpenHelper 打开这个库,版本号是 1;user_version 不是 1 时它会重新建表
 * (CREATE TABLE 没有 IF NOT EXISTS) → "table DATA already exists" → 微X 启动失败。
 *
 * 写入策略(库里可能已经有这个账号,甚至已经被授权):
 *   - 其余 8 行只在缺失时补齐,不动微X 已经写好的状态;
 *   - LIC / verifier6 是授权判定本身:已经是这个账号的(blob 解得出该账号、段 3 能用自己的
 *     key 解开)就原样保留——设备上厂商发的值与本模块生成的等价,覆盖没有收益;
 *     缺失或者是别的账号的(照抄库)才写入/重算。
 * 写入前先备份一份 .bak。
 */
public final class LicenseDatabase {

    /** 微X 授权库文件名。 */
    public static final String DB_FILE_NAME = "FKZ_WX_DATA";

    private static final String TABLE_DATA = "DATA";
    private static final String TABLE_METADATA = "android_metadata";
    private static final String COLUMN_ID = "_ID";
    private static final String COLUMN_ACCOUNT = "ACCOUNT";
    private static final String COLUMN_TAG = "TAG";
    private static final String COLUMN_TYPE = "TYPE";
    private static final String COLUMN_VALUE = "VALUE";
    private static final String ACCOUNT_TAG_SELECTION =
            COLUMN_ACCOUNT + "=? AND " + COLUMN_TAG + "=?";

    private static final String CREATE_METADATA =
            "CREATE TABLE IF NOT EXISTS " + TABLE_METADATA + " (locale TEXT)";
    private static final String CREATE_DATA =
            "CREATE TABLE IF NOT EXISTS " + TABLE_DATA + "("
          + COLUMN_ID + " INTEGER PRIMARY KEY NOT NULL, "
          + COLUMN_ACCOUNT + " TEXT, " + COLUMN_TAG + " TEXT, "
          + COLUMN_TYPE + " TEXT, " + COLUMN_VALUE + " TEXT, DATA BLOB)";

    /** 微X 自己的 SQLiteOpenHelper 版本号,必须一致。 */
    private static final int USER_VERSION = 1;

    /** 设备上可用库的第一条数据行号,空表时从这里开始。 */
    private static final int FIRST_ROW_ID = 2;

    /** 微X 的语言环境标记。 */
    private static final String LOCALE = "zh_CN";

    /** 授权判定本身,要判断库里已有的值是不是这个账号的。 */
    private static final String TAG_LICENSE = "LIC";
    private static final String TAG_VERIFIER6 = "verifier6";

    private static final String BACKUP_SUFFIX = ".bak";

    private LicenseDatabase() {
    }

    /** 一次写入的结果,用于日志。 */
    public static final class Result {

        public final boolean created;
        public final int inserted;
        public final int refreshed;
        public final int kept;

        Result(boolean created, int inserted, int refreshed, int kept) {
            this.created = created;
            this.inserted = inserted;
            this.refreshed = refreshed;
            this.kept = kept;
        }
    }

    /** 保证 databaseFile 里有 account 的那 10 行;库不存在则新建,已存在则先备份。 */
    public static Result ensure(File databaseFile, String account) throws IOException {
        boolean created = !databaseFile.exists();
        if (!created) {
            backup(databaseFile);
        }

        SQLiteDatabase database = SQLiteDatabase.openOrCreateDatabase(databaseFile, null);
        try {
            database.execSQL(CREATE_METADATA);
            database.execSQL(CREATE_DATA);
            ensureLocale(database);
            database.setVersion(USER_VERSION);

            int inserted = 0;
            int refreshed = 0;
            int kept = 0;
            for (LicenseData.Row row : LicenseData.rows(account)) {
                String stored = storedValue(database, account, row.tag);
                if (isCritical(row.tag)) {
                    if (stored != null && isUsable(row.tag, stored, account)) {
                        kept++;
                        continue;
                    }
                    if (stored != null) {
                        database.update(TABLE_DATA, values(account, row), ACCOUNT_TAG_SELECTION,
                                new String[]{account, row.tag});
                        refreshed++;
                        continue;
                    }
                    insert(database, values(account, row));
                    inserted++;
                    continue;
                }
                if (stored != null) {
                    continue;
                }
                insert(database, values(account, row));
                inserted++;
            }
            return new Result(created, inserted, refreshed, kept);
        } finally {
            database.close();
        }
    }

    private static void insert(SQLiteDatabase database, ContentValues values) {
        values.put(COLUMN_ID, nextRowId(database));
        database.insertOrThrow(TABLE_DATA, null, values);
    }

    private static ContentValues values(String account, LicenseData.Row row) {
        ContentValues values = new ContentValues();
        values.put(COLUMN_ACCOUNT, account);
        values.put(COLUMN_TAG, row.tag);
        values.put(COLUMN_TYPE, row.type);
        values.put(COLUMN_VALUE, row.value);
        return values;
    }

    private static boolean isCritical(String tag) {
        return TAG_LICENSE.equals(tag) || TAG_VERIFIER6.equals(tag);
    }

    private static boolean isUsable(String tag, String stored, String account) {
        return TAG_LICENSE.equals(tag)
                ? LicenseData.isUsableLicense(stored, account)
                : LicenseData.isUsableVerifier6(stored, account);
    }

    /** 该账号该 tag 已有的值;没有这一行返回 null。 */
    private static String storedValue(SQLiteDatabase database, String account, String tag) {
        try (Cursor cursor = database.query(TABLE_DATA, new String[]{COLUMN_VALUE},
                ACCOUNT_TAG_SELECTION, new String[]{account, tag}, null, null, null)) {
            return cursor.moveToFirst() ? cursor.getString(0) : null;
        }
    }

    private static int nextRowId(SQLiteDatabase database) {
        try (Cursor cursor = database.rawQuery(
                "SELECT MAX(" + COLUMN_ID + ") FROM " + TABLE_DATA, null)) {
            if (cursor.moveToFirst() && !cursor.isNull(0)) {
                return Math.max(cursor.getInt(0) + 1, FIRST_ROW_ID);
            }
        }
        return FIRST_ROW_ID;
    }

    private static void ensureLocale(SQLiteDatabase database) {
        try (Cursor cursor = database.rawQuery("SELECT COUNT(*) FROM " + TABLE_METADATA, null)) {
            if (cursor.moveToFirst() && cursor.getInt(0) > 0) {
                return;
            }
        }
        database.execSQL("INSERT INTO " + TABLE_METADATA + " VALUES (?)", new Object[]{LOCALE});
    }

    /** 覆盖前留一份同名 .bak,出问题可以手工还原。 */
    private static void backup(File databaseFile) throws IOException {
        File backup = new File(databaseFile.getPath() + BACKUP_SUFFIX);
        try (InputStream input = new FileInputStream(databaseFile);
                OutputStream output = new FileOutputStream(backup)) {
            byte[] buffer = new byte[8 * 1024];
            int read;
            while ((read = input.read(buffer)) > 0) {
                output.write(buffer, 0, read);
            }
        }
    }
}
