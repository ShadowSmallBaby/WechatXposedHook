package io.github.shadowbaby.wechatxposed.tool.config

import org.json.JSONObject


data class HookSettings(
    val enabled: Boolean = true,
    val login: Boolean = true,
    val call: Boolean = true,
    val global: Boolean = false,
    val tablet: Boolean = false,
    val log: Boolean = false,
    val miniProgramMode: Int = MINI_LIB,
    val targetVersion: Int = DEFAULT_TARGET_VERSION,
    val targetVersionName: String = DEFAULT_TARGET_NAME,
    val spoofRules: String? = null,
    val miniLibraryResetEpoch: Int = 0
) {
    fun encode(): String = JSONObject().apply {
        put(PreferenceKeys.ENABLED, enabled)
        put(PreferenceKeys.LOGIN, login)
        put(PreferenceKeys.CALL, call)
        put(PreferenceKeys.GLOBAL, global)
        put(PreferenceKeys.TABLET, tablet)
        put(PreferenceKeys.LOG, log)
        put(PreferenceKeys.MINI_PROGRAM_MODE, miniProgramMode)
        put(PreferenceKeys.MINI_LIBRARY_RESET_EPOCH, miniLibraryResetEpoch)
        put(PreferenceKeys.TARGET_VERSION, targetVersion)
        put(PreferenceKeys.TARGET_VERSION_NAME, targetVersionName)
        put(PreferenceKeys.SPOOF_RULES, spoofRules ?: "")
    }.toString()

    companion object {
        const val MINI_OFF = 0
        const val MINI_LIB = 1
        const val MINI_CGI = 2
        const val MINI_JSAPI = 3


        const val DEFAULT_TARGET_VERSION = 0x28004F30
        const val DEFAULT_TARGET_NAME = "8.0.79"

        const val GROUP = "settings"
        const val SNAPSHOT = "snapshot"

        fun read(values: (String) -> Any?): HookSettings = HookSettings(
            enabled = boolean(values, PreferenceKeys.ENABLED, true),
            login = boolean(values, PreferenceKeys.LOGIN, true),
            call = boolean(values, PreferenceKeys.CALL, true),
            global = boolean(values, PreferenceKeys.GLOBAL, false),
            tablet = boolean(values, PreferenceKeys.TABLET, false),
            log = boolean(values, PreferenceKeys.LOG, false),
            miniProgramMode = int(values, PreferenceKeys.MINI_PROGRAM_MODE, MINI_LIB).coerceIn(MINI_OFF, MINI_JSAPI),
            targetVersion = migrateTarget(
                int(values, PreferenceKeys.TARGET_VERSION, DEFAULT_TARGET_VERSION)
            ),
            targetVersionName = (values(PreferenceKeys.TARGET_VERSION_NAME) as? String)
                ?.takeIf { it.isNotBlank() } ?: DEFAULT_TARGET_NAME,
            spoofRules = (values(PreferenceKeys.SPOOF_RULES) as? String)
                ?.takeIf { it.isNotBlank() },
            miniLibraryResetEpoch = int(values, PreferenceKeys.MINI_LIBRARY_RESET_EPOCH, 0)
                .coerceAtLeast(0)
        )

        private fun boolean(values: (String) -> Any?, key: String, fallback: Boolean): Boolean =
            when (val value = values(key)) {
                is Boolean -> value
                is String -> value.toBooleanStrictOrNull() ?: fallback
                else -> fallback
            }


        private fun migrateTarget(value: Int): Int =
            if (value == 0x28004F00) 0x28004F30 else value

        private fun int(values: (String) -> Any?, key: String, fallback: Int): Int =
            when (val value = values(key)) {
                is Number -> value.toInt()
                is String -> value.toIntOrNull() ?: fallback
                else -> fallback
            }
    }
}
