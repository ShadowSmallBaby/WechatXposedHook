package io.github.shadowbaby.wechatxposed.tool.ui

import android.content.SharedPreferences
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import io.github.shadowbaby.wechatxposed.tool.config.SettingsStore


@Composable
fun <T> preference(key: String, read: () -> T): T {
    return preferences(listOf(key), read)
}


@Composable
fun <T> preferences(keys: List<String>, read: () -> T): T {
    var value by remember(keys) { mutableStateOf(read()) }
    val currentRead by rememberUpdatedState(read)
    DisposableEffect(keys) {
        val listener = SharedPreferences.OnSharedPreferenceChangeListener { _, changed ->
            if (changed == null || changed in keys) {
                value = currentRead()
            }
        }
        SettingsStore.addListener(listener)
        value = currentRead()
        onDispose { SettingsStore.removeListener(listener) }
    }
    return value
}
