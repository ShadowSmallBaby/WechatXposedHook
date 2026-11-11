package io.github.shadowbaby.wechatxposed.tool.module

import android.content.SharedPreferences

internal class RemoteSettingsSource(private val prefs: SharedPreferences) : SettingsSource {
    private var listener: SharedPreferences.OnSharedPreferenceChangeListener? = null

    override fun readSnapshot(): String? = try {
        prefs.getString("snapshot", null)
    } catch (_: Throwable) {
        null
    }

    override fun watch(refresh: Runnable) {
        listener = SharedPreferences.OnSharedPreferenceChangeListener { _, key ->
            if (key == null || key == "snapshot") refresh.run()
        }
        prefs.registerOnSharedPreferenceChangeListener(listener)
    }
}
