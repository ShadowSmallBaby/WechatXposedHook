package io.github.shadowbaby.wechatxposed.tool.ui

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.lifecycle.compose.LifecycleResumeEffect
import io.github.shadowbaby.wechatxposed.tool.config.SettingsStore
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.theme.darkColorScheme
import top.yukonga.miuix.kmp.theme.lightColorScheme

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent { ToolApp() }
    }
}

@Composable
private fun ToolApp() {
    val dark = isSystemInDarkTheme()
    MiuixTheme(colors = if (dark) darkColorScheme() else lightColorScheme()) {
        var active by remember { mutableStateOf(SettingsStore.active) }
        val scope = rememberCoroutineScope()
        LifecycleResumeEffect(Unit) {


            active = SettingsStore.active
            val job = scope.launch {
                while (isActive) {
                    delay(1_000L)
                    active = SettingsStore.active
                }
            }
            onPauseOrDispose { job.cancel() }
        }
        SettingsScreen(active = active)
    }
}
