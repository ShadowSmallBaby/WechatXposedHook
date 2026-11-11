package io.github.shadowbaby.wechatxposed.tool.module

import android.app.Application
import io.github.shadowbaby.wechatxposed.tool.hook.config.RuntimeSettings
import io.github.shadowbaby.wechatxposed.tool.hook.config.ToolSettings
import io.github.shadowbaby.wechatxposed.tool.hook.feature.call.CallSdkModeSpoof
import io.github.shadowbaby.wechatxposed.tool.hook.feature.miniprogram.MiniProgramLibraryCleanup
import io.github.shadowbaby.wechatxposed.tool.hook.feature.tablet.TabletMode
import io.github.shadowbaby.wechatxposed.shared.hook.HookFramework
import io.github.shadowbaby.wechatxposed.tool.hook.framework.RuleFramework
import io.github.shadowbaby.wechatxposed.tool.hook.framework.ToolLogger
import io.github.shadowbaby.wechatxposed.tool.hook.spoof.SpoofProfiles
import io.github.shadowbaby.wechatxposed.tool.hook.version.VersionSpoofInstaller
import io.github.shadowbaby.wechatxposed.tool.hook.version.VersionWindow
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong


object HostRuntime {
    @JvmStatic
    fun start(adapter: HookFramework, fallback: ClassLoader, source: SettingsSource,
              modulePath: String?, packageName: String) {
        if (packageName != HOST_PACKAGE) return
        val framework = RuleFramework(adapter)
        val process = ProcessName.current()
        if (!isTargetProcess(process) || !INSTALLED.add(process)) return
        Thread({
            ToolLogger.attach(framework)
            try {
                val loader = waitForHostLoader(fallback)
                val initialSnapshot = source.readSnapshot()?.takeIf { it.isNotBlank() }
                val settings = if (initialSnapshot == null) ToolSettings.disabled()
                    else ToolSettings.parse(initialSnapshot)
                ToolLogger.setVerbose(settings.log)
                RuntimeSettings.update(settings)

                ToolLogger.log("settings initial: process=" + process
                        + " enabled=" + settings.enabled + " login=" + settings.login
                        + " call=" + settings.call + " mini=" + settings.miniProgramMode
                        + " global=" + settings.global + " tablet=" + settings.tablet
                        + " log=" + settings.log
                        + " target=0x" + Integer.toHexString(settings.targetVersion)
                        + " imported=" + (if (settings.spoofRules.isNullOrBlank()) "none"
                        else settings.spoofRules.length.toString()))
                val host = hostPackageInfo() ?: return@Thread

                if (!SpoofProfiles.configureWithRetry(
                        settings.spoofRules, host.versionName, host.versionCode, modulePath)) {
                    ToolLogger.log("spoof rules: no bundled profile for " + host.versionName)
                    return@Thread
                }
                when {
                    process == APPBRAND_0 || process == APPBRAND_1 ->
                        VersionSpoofInstaller.installAppBrand(framework, loader, settings)
                    else -> VersionSpoofInstaller.installMain(framework, loader, settings)
                }
                if (ProcessName.current() == HOST_PACKAGE) {
                    MiniProgramLibraryCleanup.installMain(framework, loader, currentApplication())
                }
                watchSettings(framework, loader, source, initialSnapshot)
            } catch (error: Throwable) {
                framework.log(error)
            }
        }, "wextool-entry").apply { isDaemon = true }.start()
    }

    private fun isTargetProcess(process: String): Boolean =
        process == HOST_PACKAGE || process == APPBRAND_0 || process == APPBRAND_1 ||
            isUsapLike(process)

    private fun isUsapLike(process: String): Boolean =
        process.endsWith("zygote64") || process.endsWith("zygote") ||
            process.endsWith("usap64") || process.endsWith("usap32")


    private fun waitForHostLoader(fallback: ClassLoader): ClassLoader {
        repeat(40) {
            val application = currentApplication()
            if (application != null) {
                val loader = application.javaClass.classLoader
                if (loader != null) {
                    return loader
                }
            }
            try {
                Thread.sleep(250L)
            } catch (_: InterruptedException) {
                return fallback
            }
        }
        ToolLogger.log("entry: host loader unavailable, using package loader")
        return fallback
    }

    private fun currentApplication(): Application? = try {
        Class.forName("android.app.ActivityThread")
            .getDeclaredMethod("currentApplication")
            .invoke(null) as? Application
    } catch (_: Throwable) {
        null
    }


    private fun hostPackageInfo(): android.content.pm.PackageInfo? = try {
        currentApplication()?.packageManager
            ?.getPackageInfo(HOST_PACKAGE, 0)
    } catch (_: Throwable) {
        null
    }

    private fun watchSettings(framework: HookFramework, loader: ClassLoader, source: SettingsSource,
            initialSnapshot: String?) {
        val settingsLock = Any()
        var lastApplied = initialSnapshot
        fun refresh() = synchronized(settingsLock) {
            val now = source.readSnapshot()?.takeIf { it.isNotBlank() } ?: return@synchronized
            if (now != lastApplied) {
                applySettings(ToolSettings.parse(now), framework, loader)
                lastApplied = now
            }
        }
        try {
            source.watch { refresh() }
            ToolLogger.log("settings listener: on")
        } catch (error: Throwable) {
            ToolLogger.log("settings listener unavailable: $error")
        }

        refresh()
        Thread({
            while (true) {
                try {
                    Thread.sleep(30_000L)
                } catch (_: InterruptedException) {
                    return@Thread
                }
                refresh()
            }
        }, "wextool-settings").apply { isDaemon = true }.start()
    }

    private fun applySettings(settings: ToolSettings, framework: HookFramework,
            loader: ClassLoader) {
        RuntimeSettings.update(settings)
        ToolLogger.setVerbose(settings.log)
        CallSdkModeSpoof.onSettingsChanged(settings)
        TabletMode.refreshAuthIdentity(framework, loader)
        val globalEnabled = settings.enabled && settings.global
        if (!globalEnabled) VersionWindow.close(framework, loader, "settings")
        VersionWindow.configure(settings.targetVersion)
        if (globalEnabled) {
            VersionWindow.openGlobal(framework, loader)
        }
        MiniProgramLibraryCleanup.onSettingsChanged()
        ToolLogger.log("settings updated: enabled=" + settings.enabled
                + " login=" + settings.login + " call=" + settings.call
                + " mini=" + settings.miniProgramMode
                + " global=" + settings.global + " tablet=" + settings.tablet
                + " target=0x" + Integer.toHexString(settings.targetVersion)
                + " miniReset=" + settings.miniLibraryResetEpoch
                + " revision=" + settingsSequence.incrementAndGet())
    }

    private const val HOST_PACKAGE = "com.tencent.mm"
    private const val APPBRAND_0 = "com.tencent.mm:appbrand0"
    private const val APPBRAND_1 = "com.tencent.mm:appbrand1"

    private val INSTALLED = ConcurrentHashMap.newKeySet<String>()
    private val settingsSequence = AtomicLong()
}



internal object ProcessName {
    fun current(): String = try {
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
            Application.getProcessName() ?: ""
        } else {
            Class.forName("android.app.ActivityThread")
                .getDeclaredMethod("currentProcessName")
                .invoke(null) as? String ?: ""
        }
    } catch (_: Throwable) {
        ""
    }
}
