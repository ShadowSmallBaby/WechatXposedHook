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

public final class LicenseDatabase {

    public static final String DB_FILE_NAME = LicenseCrypto.dbFileName();

    private static final int STRUCTURE_SIZE = 20;

    private LicenseDatabase() {
    }

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

    private static final class Structure {

        final String tableData;
        final String tableMetadata;
        final String columnId;
        final String columnAccount;
        final String columnTag;
        final String columnType;
        final String columnValue;
        final String selection;
        final String createMetadata;
        final String createData;
        final String locale;
        final int userVersion;
        final int firstRowId;
        final String backupSuffix;
        final String selectMaxId;
        final String insertMetadata;
        final String licenseTag;
        final String verifierTag;
        final String countMetadata;

        Structure(String[] raw) {
            tableData = raw[1];
            tableMetadata = raw[2];
            columnId = raw[3];
            columnAccount = raw[4];
            columnTag = raw[5];
            columnType = raw[6];
            columnValue = raw[7];
            selection = raw[8];
            createMetadata = raw[9];
            createData = raw[10];
            locale = raw[11];
            userVersion = Integer.parseInt(raw[12]);
            firstRowId = Integer.parseInt(raw[13]);
            backupSuffix = raw[14];
            selectMaxId = raw[15];
            insertMetadata = raw[16];
            licenseTag = raw[17];
            verifierTag = raw[18];
            countMetadata = raw[19];
        }
    }

    private static Structure structure() {
        String[] raw = LicenseCrypto.structure();
        if (raw.length < STRUCTURE_SIZE) {
            throw new IllegalStateException("license structure unavailable");
        }
        return new Structure(raw);
    }

    public static Result ensure(File databaseFile, String account) throws IOException {
        Structure structure = structure();
        boolean created = !databaseFile.exists();
        if (!created) {
            backup(databaseFile, structure.backupSuffix);
        }

        try (SQLiteDatabase database = SQLiteDatabase.openOrCreateDatabase(databaseFile, null)) {
            database.execSQL(structure.createMetadata);
            database.execSQL(structure.createData);
            ensureLocale(database, structure);
            database.setVersion(structure.userVersion);

            int inserted = 0;
            int refreshed = 0;
            int kept = 0;
            for (LicenseData.Row row : LicenseData.rows(account)) {
                String stored = storedValue(database, account, row.tag, structure);
                if (isCritical(structure, row.tag)) {
                    if (stored != null && isUsable(row.tag, stored, account, structure)) {
                        kept++;
                        continue;
                    }
                    if (stored != null) {
                        database.update(structure.tableData, values(account, row, structure),
                                structure.selection, new String[]{account, row.tag});
                        refreshed++;
                        continue;
                    }
                    insert(database, values(account, row, structure), structure);
                    inserted++;
                    continue;
                }
                if (stored != null) {
                    continue;
                }
                insert(database, values(account, row, structure), structure);
                inserted++;
            }
            return new Result(created, inserted, refreshed, kept);
        }
    }

    private static void insert(SQLiteDatabase database, ContentValues values, Structure structure) {
        values.put(structure.columnId, nextRowId(database, structure));
        database.insertOrThrow(structure.tableData, null, values);
    }

    private static ContentValues values(String account, LicenseData.Row row, Structure structure) {
        ContentValues values = new ContentValues();
        values.put(structure.columnAccount, account);
        values.put(structure.columnTag, row.tag);
        values.put(structure.columnType, row.type);
        values.put(structure.columnValue, row.value);
        return values;
    }

    private static boolean isCritical(Structure structure, String tag) {
        return structure.licenseTag.equals(tag) || structure.verifierTag.equals(tag);
    }

    private static boolean isUsable(String tag, String stored, String account,
                                    Structure structure) {
        return structure.licenseTag.equals(tag)
                ? LicenseData.isUsableLicense(stored, account)
                : LicenseData.isUsableVerifier6(stored, account);
    }

    private static String storedValue(SQLiteDatabase database, String account, String tag,
                                      Structure structure) {
        try (Cursor cursor = database.query(structure.tableData,
                new String[]{structure.columnValue}, structure.selection,
                new String[]{account, tag}, null, null, null)) {
            return cursor.moveToFirst() ? cursor.getString(0) : null;
        }
    }

    private static int nextRowId(SQLiteDatabase database, Structure structure) {
        try (Cursor cursor = database.rawQuery(structure.selectMaxId, null)) {
            if (cursor.moveToFirst() && !cursor.isNull(0)) {
                return Math.max(cursor.getInt(0) + 1, structure.firstRowId);
            }
        }
        return structure.firstRowId;
    }

    private static void ensureLocale(SQLiteDatabase database, Structure structure) {
        try (Cursor cursor = database.rawQuery(structure.countMetadata, null)) {
            if (cursor.moveToFirst() && cursor.getInt(0) > 0) {
                return;
            }
        }
        database.execSQL(structure.insertMetadata, new Object[]{structure.locale});
    }

    private static void backup(File databaseFile, String suffix) throws IOException {
        File backup = new File(databaseFile.getPath() + suffix);
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
