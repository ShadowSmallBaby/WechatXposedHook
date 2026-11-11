package io.github.shadowbaby.wechatxposed.tool.config

import android.app.Application


interface SettingsPublisher {
    val active: Boolean

    fun bind(application: Application)

    fun publish()
}
