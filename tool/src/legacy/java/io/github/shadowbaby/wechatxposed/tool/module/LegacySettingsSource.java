package io.github.shadowbaby.wechatxposed.tool.module;

import android.content.Context;
import android.database.ContentObserver;
import android.database.Cursor;
import android.net.Uri;
import android.os.Handler;
import android.os.HandlerThread;
import io.github.shadowbaby.wechatxposed.tool.config.LegacySettingsProvider;
import io.github.shadowbaby.wechatxposed.tool.hook.framework.ToolLogger;


public final class LegacySettingsSource implements SettingsSource {
    private final Context context;
    private HandlerThread thread;
    private ContentObserver observer;

    public LegacySettingsSource(Context context) { this.context = context.getApplicationContext() != null ? context.getApplicationContext() : context; }

    @Override public String readSnapshot() {
        try (Cursor cursor = context.getContentResolver().query(LegacySettingsProvider.URI,
                null, null, null, null)) {
            return cursor != null && cursor.moveToFirst() ? cursor.getString(0) : null;
        } catch (Throwable error) {
            ToolLogger.debug("legacy settings: snapshot unavailable");
            return null;
        }
    }

    @Override public void watch(Runnable refresh) {
        thread = new HandlerThread("wextool-legacy-settings");
        thread.start();
        observer = new ContentObserver(new Handler(thread.getLooper())) {
            @Override public void onChange(boolean selfChange, Uri uri) { refresh.run(); }
            @Override public void onChange(boolean selfChange) { refresh.run(); }
        };
        context.getContentResolver().registerContentObserver(LegacySettingsProvider.URI, false, observer);
    }
}
