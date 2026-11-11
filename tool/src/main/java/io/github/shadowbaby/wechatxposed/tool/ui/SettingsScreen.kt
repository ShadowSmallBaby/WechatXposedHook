package io.github.shadowbaby.wechatxposed.tool.ui

import android.app.AlertDialog
import android.content.Context
import android.content.Intent
import android.text.InputType
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.Toast
import androidx.compose.foundation.layout.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.net.toUri
import io.github.shadowbaby.wechatxposed.tool.BuildConfig
import io.github.shadowbaby.wechatxposed.tool.R
import io.github.shadowbaby.wechatxposed.tool.config.*
import top.yukonga.miuix.kmp.basic.*
import top.yukonga.miuix.kmp.preference.ArrowPreference
import top.yukonga.miuix.kmp.preference.OverlaySpinnerPreference
import top.yukonga.miuix.kmp.preference.SwitchPreference
import top.yukonga.miuix.kmp.theme.MiuixTheme
import io.github.shadowbaby.wechatxposed.tool.config.PreferenceKeys as Keys


@Composable
fun SettingsScreen(active: Boolean) {
    Scaffold(
        topBar = {
            Column(
                Modifier
                    .statusBarsPadding()
                    .padding(horizontal = 24.dp, vertical = 12.dp)
            ) {
                Text(stringResource(R.string.app_name), fontSize = 28.sp)
                Text(
                    stringResource(
                        if (active) R.string.status_active else R.string.status_inactive
                    ),
                    fontSize = 13.sp,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary
                )
            }
        }
    ) { padding ->
        Box(Modifier.padding(padding)) {
            Page {
                SmallTitle(stringResource(R.string.section_scope))
                Card(Modifier.fillMaxWidth()) {
                    TargetVersionPreference()

                    val enabled = preference(Keys.ENABLED) {
                        SettingsStore.getBoolean(Keys.ENABLED, true)
                    }
                    SwitchPreference(
                        title = stringResource(R.string.master_switch),
                        summary = stringResource(R.string.master_switch_summary),
                        checked = enabled,
                        onCheckedChange = { SettingsStore.putBoolean(Keys.ENABLED, it) }
                    )

                    val login = preference(Keys.LOGIN) {
                        SettingsStore.getBoolean(Keys.LOGIN, true)
                    }
                    SwitchPreference(
                        title = stringResource(R.string.login_spoof),
                        summary = stringResource(R.string.login_spoof_summary),
                        checked = login,
                        onCheckedChange = { SettingsStore.putBoolean(Keys.LOGIN, it) }
                    )

                    val tablet = preference(Keys.TABLET) {
                        SettingsStore.getBoolean(Keys.TABLET, false)
                    }
                    SwitchPreference(
                        title = stringResource(R.string.tablet_mode),
                        summary = stringResource(R.string.tablet_mode_summary),
                        checked = tablet,
                        onCheckedChange = { SettingsStore.putBoolean(Keys.TABLET, it) }
                    )

                    val call = preference(Keys.CALL) {
                        SettingsStore.getBoolean(Keys.CALL, true)
                    }
                    SwitchPreference(
                        title = stringResource(R.string.call_spoof),
                        summary = stringResource(R.string.call_spoof_summary),
                        checked = call,
                        onCheckedChange = { SettingsStore.putBoolean(Keys.CALL, it) }
                    )

                    MiniProgramModePreference()

                    val global = preference(Keys.GLOBAL) {
                        SettingsStore.getBoolean(Keys.GLOBAL, false)
                    }
                    SwitchPreference(
                        title = stringResource(R.string.global_spoof),
                        summary = stringResource(R.string.global_spoof_summary),
                        checked = global,
                        onCheckedChange = { SettingsStore.putBoolean(Keys.GLOBAL, it) }
                    )
                }

                SmallTitle(stringResource(R.string.section_about))
                Card(Modifier.fillMaxWidth()) {
                    val context = LocalContext.current
                    Row(
                        Modifier.padding(16.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        AndroidView(
                            factory = { ctx ->
                                android.widget.ImageView(ctx).apply {
                                    setImageResource(R.mipmap.ic_launcher)
                                }
                            },
                            modifier = Modifier.size(52.dp)
                        )
                        Column(Modifier.padding(start = 16.dp)) {
                            Text(
                                stringResource(R.string.app_name),
                                fontSize = 20.sp,
                                fontWeight = FontWeight.SemiBold
                            )
                            Text(
                                stringResource(R.string.about_version, BuildConfig.VERSION_NAME),
                                fontSize = 14.sp,
                                color = MiuixTheme.colorScheme.onSurfaceVariantSummary
                            )
                        }
                    }
                    Text(
                        stringResource(R.string.description),
                        modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
                        fontSize = 13.sp,
                        color = MiuixTheme.colorScheme.onSurfaceVariantSummary
                    )

                    val log = preference(Keys.LOG) {
                        SettingsStore.getBoolean(Keys.LOG, false)
                    }
                    SwitchPreference(
                        title = stringResource(R.string.hook_log),
                        summary = stringResource(R.string.hook_log_summary),
                        checked = log,
                        onCheckedChange = { SettingsStore.putBoolean(Keys.LOG, it) }
                    )

                    val showIcon = preference(Keys.SHOW_LAUNCHER_ICON) {
                        SettingsStore.getBoolean(Keys.SHOW_LAUNCHER_ICON, true)
                    }
                    SwitchPreference(
                        title = stringResource(R.string.show_launcher_icon),
                        summary = stringResource(R.string.show_launcher_icon_summary),
                        checked = showIcon,
                        onCheckedChange = { visible ->
                            runCatching { LauncherIcon.setVisible(context, visible) }
                                .onFailure {
                                    Toast.makeText(context, R.string.launcher_icon_failed, Toast.LENGTH_SHORT).show()
                                }
                        }
                    )


                    ArrowPreference(
                        title = stringResource(R.string.about_source),
                        summary = stringResource(R.string.about_source_summary),
                        onClick = {
                            runCatching {
                                context.startActivity(
                                    Intent(Intent.ACTION_VIEW, GITHUB_URL.toUri())
                                )
                            }
                        }
                    )
                }
            }
        }
    }
}

@Composable
private fun TargetVersionPreference() {
    val context = LocalContext.current
    val selection = preferences(listOf(Keys.TARGET_VERSION, Keys.TARGET_VERSION_NAME,
        Keys.TARGET_VERSION_CUSTOM, Keys.CUSTOM_VERSION_CODE, Keys.CUSTOM_VERSION_NAME)) {
        SettingsStore.versionSelection()
    }
    val saved = selection.saved()
    val presetIndex = TARGET_VERSIONS.indexOfFirst { it.code == selection.code() }
    val isCustom = selection.custom() || presetIndex < 0
    val items = TARGET_VERSIONS.map { DropdownItem(it.label) } +
        DropdownItem(stringResource(R.string.version_custom))
    OverlaySpinnerPreference(
        items = items,
        selectedIndex = if (isCustom) TARGET_VERSIONS.size else presetIndex,
        title = stringResource(R.string.target_version),
        onSelectedIndexChange = { index ->
            if (index < TARGET_VERSIONS.size) {
                val preset = TARGET_VERSIONS[index]
                SettingsStore.selectPresetVersion(preset.label, preset.code)
            } else {
                if (!SettingsStore.selectSavedCustomVersion()) {
                    showCustomVersionDialog(context, selection.code(), selection.name(), true)
                }
            }
        }
    )
    if (saved != null) {
        ArrowPreference(
            title = stringResource(R.string.version_custom_content),
            endActions = {
                Text(saved.name(), fontSize = 14.sp,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary)
            },
            onClick = { showCustomVersionDialog(context, saved.code(), saved.name(), false) }
        )
    }
}


private fun showCustomVersionDialog(context: Context, currentCode: Int, currentName: String,
        selectAfterSave: Boolean) {
    val density = context.resources.displayMetrics.density
    val padding = (20 * density).toInt()
    val layout = LinearLayout(context).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(padding, padding / 2, padding, 0)
    }
    val nameInput = EditText(context).apply {
        hint = context.getString(R.string.version_name_hint)
        setText(currentName)
        inputType = InputType.TYPE_CLASS_TEXT
    }
    val codeInput = EditText(context).apply {
        hint = context.getString(R.string.version_code_hint)
        setText("0x" + Integer.toHexString(currentCode).uppercase())
        inputType = InputType.TYPE_CLASS_TEXT
    }
    layout.addView(nameInput)
    layout.addView(codeInput)
    val dialog = AlertDialog.Builder(context)
        .setTitle(R.string.version_custom_title)
        .setView(layout)
        .setPositiveButton(R.string.confirm, null)
        .setNegativeButton(R.string.cancel, null)
        .create()
    dialog.setOnShowListener {
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
            val name = nameInput.text.toString().trim()
            val code = VersionInput.parse(codeInput.text.toString())
            nameInput.error = if (name.isBlank()) context.getString(R.string.version_name_invalid) else null
            codeInput.error = if (code == null) context.getString(R.string.version_code_invalid) else null
            if (name.isNotBlank() && code != null) {
                SettingsStore.saveCustomVersion(name, code, selectAfterSave)
                dialog.dismiss()
            }
        }
    }
    dialog.show()
}

@Composable
private fun MiniProgramModePreference() {
    val mode = preference(Keys.MINI_PROGRAM_MODE) {
        SettingsStore.getInt(Keys.MINI_PROGRAM_MODE, HookSettings.MINI_LIB)
    }
    val items = listOf(
        R.string.mini_program_lib,
        R.string.mini_program_cgi,
        R.string.mini_program_jsapi,
        R.string.mini_program_off
    ).map { DropdownItem(stringResource(it)) }
    OverlaySpinnerPreference(
        items = items,
        selectedIndex = if (mode in HookSettings.MINI_LIB..HookSettings.MINI_JSAPI) mode - 1 else 3,
        title = stringResource(R.string.mini_program_spoof),
        summary = stringResource(when (mode) {
            HookSettings.MINI_LIB -> R.string.mini_program_lib_summary
            HookSettings.MINI_CGI -> R.string.mini_program_cgi_summary
            HookSettings.MINI_JSAPI -> R.string.mini_program_jsapi_summary
            else -> R.string.mini_program_off_summary
        }),
        onSelectedIndexChange = {
            SettingsStore.putInt(Keys.MINI_PROGRAM_MODE, if (it == 3) HookSettings.MINI_OFF else it + 1)
        }
    )
}

data class TargetVersion(val label: String, val code: Int)

val TARGET_VERSIONS = listOf(
    TargetVersion("8.0.79", 0x28004F30),
    TargetVersion("8.0.80", 0x28005032)
)

private const val GITHUB_URL = "https://github.com/ShadowSmallBaby/WechatXposedHook"
