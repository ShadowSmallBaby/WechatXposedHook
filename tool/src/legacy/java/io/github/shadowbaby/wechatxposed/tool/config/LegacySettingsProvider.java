package io.github.shadowbaby.wechatxposed.tool.config;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.Binder;


public final class LegacySettingsProvider extends ContentProvider {
    public static final Uri URI = SettingsContract.legacySnapshotUri();

    @Override public boolean onCreate() { return true; }

    @Override public Cursor query(Uri uri, String[] projection, String selection,
            String[] selectionArgs, String sortOrder) {
        if (!URI.equals(uri) || selection != null || selectionArgs != null || sortOrder != null)
            throw new IllegalArgumentException("Only the settings snapshot is available");
        int uid = Binder.getCallingUid();
        var context = getContext();
        if (context == null || !SettingsReadAccess.allowed(uid, context.getApplicationInfo().uid,
                context.getPackageManager().getPackagesForUid(uid)))
            throw new SecurityException("Settings reader is not in the module scope");
        String snapshot = SettingsStore.INSTANCE.snapshot().encode();
        MatrixCursor cursor = new MatrixCursor(new String[]{"snapshot"}, 1);
        cursor.addRow(new Object[]{snapshot});
        if (uid != context.getApplicationInfo().uid) SettingsStore.INSTANCE.noteLegacyReader();
        return cursor;
    }

    @Override public String getType(Uri uri) { return "vnd.android.cursor.item/vnd.wextool.settings"; }
    @Override public Uri insert(Uri uri, ContentValues values) { throw new SecurityException("Read-only settings"); }
    @Override public int update(Uri uri, ContentValues values, String selection, String[] args) { throw new SecurityException("Read-only settings"); }
    @Override public int delete(Uri uri, String selection, String[] args) { throw new SecurityException("Read-only settings"); }
}
