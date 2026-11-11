package io.github.shadowbaby.wechatxposed.tool

import android.app.Application
import io.github.shadowbaby.wechatxposed.tool.config.SettingsStore

class App : Application() {

    override fun onCreate() {
        super.onCreate()
        SettingsStore.install(this)
    }
}
