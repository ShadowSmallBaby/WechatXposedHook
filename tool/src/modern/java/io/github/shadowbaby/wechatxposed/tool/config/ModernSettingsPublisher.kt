package io.github.shadowbaby.wechatxposed.tool.config

import android.app.Application
import androidx.core.content.edit
import io.github.libxposed.service.XposedService
import io.github.libxposed.service.XposedServiceHelper


class ModernSettingsPublisher : SettingsPublisher {

    @Volatile
    private var service: XposedService? = null

    override val active: Boolean
        get() = service != null

    override fun bind(application: Application) {
        XposedServiceHelper.registerListener(object : XposedServiceHelper.OnServiceListener {
            override fun onServiceBind(bound: XposedService) {
                service = bound
                publish()
            }

            override fun onServiceDied(died: XposedService) {
                service = null
            }
        })
    }

    override fun publish() {
        val bound = service ?: return
        try {
            bound.getRemotePreferences(HookSettings.GROUP).edit {
                putString(HookSettings.SNAPSHOT, SettingsStore.snapshot().encode())
            }
        } catch (_: Throwable) {

        }
    }
}
