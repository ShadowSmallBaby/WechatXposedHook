package io.github.shadowbaby.wechatxposed.tool.config

import android.app.Application
import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import androidx.core.content.edit
import io.github.shadowbaby.wechatxposed.tool.BuildConfig


object SettingsStore {

    private const val PREFS_NAME = "settings"

    private lateinit var prefs: SharedPreferences


    private val publisher: SettingsPublisher? by lazy {
        if (BuildConfig.FRAMEWORK_API < 101) null else try {
            Class.forName("io.github.shadowbaby.wechatxposed.tool.config.ModernSettingsPublisher")
                .getDeclaredConstructor().newInstance() as SettingsPublisher
        } catch (error: Throwable) {
            Log.e("WeXposedTool", "Modern settings publisher initialization failed; local settings retained", error)
            null
        }
    }
    private lateinit var applicationContext: Context
    @Volatile
    private var legacySeenAt = 0L
    private val legacySeenKey = "legacy_hook_seen_at"
    private val legacySeenWindowMs = 24 * 60 * 60 * 1000L


    private val preferencePublisher = SharedPreferences.OnSharedPreferenceChangeListener { _, _ ->
        publisher?.publish()
        if (BuildConfig.FRAMEWORK_API == 82) try {
            applicationContext.contentResolver.notifyChange(SettingsContract.legacySnapshotUri(), null)
        } catch (_: Throwable) {  
        }
    }

    val active: Boolean
        get() = publisher?.active == true || (legacySeenAt > 0L &&
                System.currentTimeMillis() - legacySeenAt < legacySeenWindowMs)

    fun install(application: Application) {
        applicationContext = application
        prefs = application.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        legacySeenAt = prefs.getLong(legacySeenKey, 0L)
        applyVersionWrites(VersionSelection.migration(prefs.all))

        if (prefs.getInt(PreferenceKeys.MINI_MODE_SCHEMA, 0) < 1) {
            val oldMode = prefs.all[PreferenceKeys.MINI_PROGRAM_MODE] as? Int
            prefs.edit {
                putInt(PreferenceKeys.MINI_MODE_SCHEMA, 1).apply {
                    if (oldMode != null) putInt(
                        PreferenceKeys.MINI_PROGRAM_MODE,
                        if (oldMode == 0) HookSettings.MINI_OFF else HookSettings.MINI_CGI
                    )
                }
            }
        }
        try {
            publisher?.bind(application)
        } catch (error: Throwable) {
            Log.w("WeXposedTool", "Modern settings service binding failed; local settings retained", error)
        }
        prefs.registerOnSharedPreferenceChangeListener(preferencePublisher)
    }

    fun getBoolean(key: String, fallback: Boolean = false): Boolean =
        prefs.getBoolean(key, fallback)

    fun getInt(key: String, fallback: Int = 0): Int = prefs.getInt(key, fallback)

    fun getString(key: String, fallback: String = ""): String =
        prefs.getString(key, fallback) ?: fallback

    fun putString(key: String, value: String) {
        prefs.edit { putString(key, value) }
    }

    fun putBoolean(key: String, value: Boolean) {
        prefs.edit { putBoolean(key, value) }
    }

    @Synchronized
    fun putInt(key: String, value: Int) {

        prefs.edit {
            if (key == PreferenceKeys.MINI_PROGRAM_MODE) {
                putInt(
                    PreferenceKeys.MINI_LIBRARY_RESET_EPOCH, MiniLibraryResetPolicy.nextEpoch(
                        prefs.getInt(key, HookSettings.MINI_LIB), value,
                        prefs.getInt(PreferenceKeys.MINI_LIBRARY_RESET_EPOCH, 0)
                    )
                )
            }
            putInt(key, value)
        }
    }

    fun versionSelection(): VersionSelection = VersionSelection.read(prefs.all)

    fun selectPresetVersion(name: String, code: Int) {
        applyVersionWrites(VersionSelection.selectPreset(name, code))
    }

    fun selectSavedCustomVersion(): Boolean {
        val writes = VersionSelection.selectCustom(prefs.all) ?: return false
        applyVersionWrites(writes)
        return true
    }

    fun saveCustomVersion(name: String, code: Int, selectAfterSave: Boolean) {
        applyVersionWrites(VersionSelection.saveCustom(prefs.all, name, code, selectAfterSave))
    }


    private fun applyVersionWrites(writes: Map<String, Any>) {
        if (writes.isEmpty()) return
        prefs.edit {
            writes.forEach { (key, value) ->
                when (value) {
                    is String -> putString(key, value)
                    is Int -> putInt(key, value)
                    is Boolean -> putBoolean(key, value)
                    else -> error("Unsupported version preference")
                }
            }
        }
    }

    fun addListener(listener: SharedPreferences.OnSharedPreferenceChangeListener) {
        prefs.registerOnSharedPreferenceChangeListener(listener)
    }

    fun removeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener) {
        prefs.unregisterOnSharedPreferenceChangeListener(listener)
    }

    fun snapshot(): HookSettings = HookSettings.read { key -> prefs.all[key] }

    fun noteLegacyReader() {
        val now = System.currentTimeMillis()
        legacySeenAt = now
        if (::prefs.isInitialized) prefs.edit { putLong(legacySeenKey, now) }
    }
}
