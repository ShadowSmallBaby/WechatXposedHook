package io.github.shadowbaby.wechatxposed.tool.config;

import android.net.Uri;
import io.github.shadowbaby.wechatxposed.tool.BuildConfig;


public final class SettingsContract {
    private SettingsContract() {}

    public static Uri legacySnapshotUri() {
        return Uri.parse("content://" + BuildConfig.APPLICATION_ID + ".LegacySettings/snapshot");
    }
}
