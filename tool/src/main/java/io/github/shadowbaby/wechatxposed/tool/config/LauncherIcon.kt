package io.github.shadowbaby.wechatxposed.tool.config

import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager


object LauncherIcon {
    fun setVisible(context: Context, visible: Boolean) {
        context.packageManager.setComponentEnabledSetting(
            ComponentName(context.packageName, "${context.packageName}.Launcher"),
            if (visible) PackageManager.COMPONENT_ENABLED_STATE_ENABLED
            else PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
            PackageManager.DONT_KILL_APP
        )
        SettingsStore.putBoolean(PreferenceKeys.SHOW_LAUNCHER_ICON, visible)
    }
}
