package io.github.shadowbaby.wechatxposed.tool.module

import io.github.libxposed.api.XposedModule
import io.github.libxposed.api.XposedModuleInterface.PackageReadyParam
import io.github.shadowbaby.wechatxposed.tool.hook.framework.ModernFramework


class ModernEntry : XposedModule() {
    override fun onPackageReady(param: PackageReadyParam) {
        if (param.packageName != "com.tencent.mm") return
        HostRuntime.start(
            ModernFramework(this), param.classLoader,
            RemoteSettingsSource(getRemotePreferences("settings")),
            getModuleApplicationInfo().sourceDir, param.packageName
        )
    }
}
