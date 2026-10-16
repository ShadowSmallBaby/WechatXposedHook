import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import github.shadowbaby.wechatxposed.hook.license.LicenseDatabase;
import java.io.File;

/** 在设备上跑真正的 LicenseDatabase.ensure(android.database.sqlite),run-device.py 负责比对结果。 */
public final class LicenseDatabaseCheck {

    private static final String ACCOUNT_COUNT = "SELECT COUNT(*) FROM DATA WHERE ACCOUNT=?";
    private static final String ACCOUNT_COUNT_ALL = "SELECT COUNT(DISTINCT ACCOUNT) FROM DATA";
    private static final String VALUE_BY_TAG = "SELECT VALUE FROM DATA WHERE ACCOUNT=? AND TAG=?";

    public static void main(String[] args) throws Exception {
        File database = new File(args[0]);
        String account = args[1];
        String mode = args.length > 2 ? args[2] : "";
        System.out.println("account=" + account);
        System.out.println("mode=" + (mode.isEmpty() ? "none" : mode));
        SQLiteDatabase holder = hold(database, mode);
        try {
            report("ensure1", database, account);
            report("ensure2", database, account);
        } finally {
            if (holder != null) {
                holder.close();
            }
        }

        SQLiteDatabase db = SQLiteDatabase.openDatabase(database.getPath(), null,
                SQLiteDatabase.OPEN_READONLY);
        try {
            System.out.println("version=" + db.getVersion());
            System.out.println("rows=" + scalar(db, ACCOUNT_COUNT, new String[]{account})
                    + " accounts=" + scalar(db, ACCOUNT_COUNT_ALL, null));
            System.out.println("lic=" + text(db, account, "LIC"));
            System.out.println("verifier6=" + text(db, account, "verifier6"));
        } finally {
            db.close();
        }
    }

    /** 模拟微X 自己那条连接:hold=只读打开,hold-txn=打开并占住一个写事务。 */
    private static SQLiteDatabase hold(File database, String mode) {
        if (!"hold".equals(mode) && !"hold-txn".equals(mode)) {
            return null;
        }
        SQLiteDatabase holder = SQLiteDatabase.openDatabase(database.getPath(), null,
                SQLiteDatabase.OPEN_READWRITE);
        if ("hold-txn".equals(mode)) {
            holder.beginTransaction();
        }
        return holder;
    }

    private static void report(String label, File database, String account) {
        try {
            LicenseDatabase.Result result = LicenseDatabase.ensure(database, account);
            System.out.println(label + " created=" + result.created + " inserted=" + result.inserted
                    + " refreshed=" + result.refreshed + " kept=" + result.kept);
        } catch (Throwable error) {
            System.out.println(label + " error=" + error.getClass().getSimpleName());
        }
    }

    private static int scalar(SQLiteDatabase db, String query, String[] arguments) {
        try (Cursor cursor = db.rawQuery(query, arguments)) {
            return cursor.moveToFirst() ? cursor.getInt(0) : 0;
        }
    }

    private static String text(SQLiteDatabase db, String account, String tag) {
        try (Cursor cursor = db.rawQuery(VALUE_BY_TAG, new String[]{account, tag})) {
            return cursor.moveToFirst() ? cursor.getString(0) : "";
        }
    }
}
