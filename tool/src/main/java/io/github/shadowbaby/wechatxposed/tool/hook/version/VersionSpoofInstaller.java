package io.github.shadowbaby.wechatxposed.tool.hook.version;

import io.github.shadowbaby.wechatxposed.tool.hook.feature.miniprogram.MiniProgramSpoof;
import io.github.shadowbaby.wechatxposed.tool.hook.feature.miniprogram.MiniProgramLibrarySpoof;
import io.github.shadowbaby.wechatxposed.tool.hook.feature.miniprogram.MiniProgramVersionGate;
import io.github.shadowbaby.wechatxposed.tool.hook.config.RuntimeSettings;
import io.github.shadowbaby.wechatxposed.tool.hook.config.ToolSettings;
import io.github.shadowbaby.wechatxposed.tool.hook.feature.tablet.TabletMode;
import io.github.shadowbaby.wechatxposed.tool.hook.feature.call.CallVersionSpoof;
import io.github.shadowbaby.wechatxposed.shared.hook.HookFramework;
import io.github.shadowbaby.wechatxposed.tool.hook.guard.ChatMvvmGuard;
import io.github.shadowbaby.wechatxposed.tool.hook.guard.WalletVersionGuard;


public final class VersionSpoofInstaller {
    private VersionSpoofInstaller() {}

    public static void installMain(HookFramework framework, ClassLoader loader, ToolSettings settings) {
        RuntimeSettings.update(settings);
        VersionWindow.configure(settings.targetVersion);
        ChatMvvmGuard.install(framework, loader);
        VersionWindow.install(framework, loader);
        WalletVersionGuard.install(framework, loader);
        TabletMode.install(framework, loader);
        NetworkVersionSpoof.install(framework, loader, settings);
        CallVersionSpoof.install(framework, loader);
        MiniProgramLibrarySpoof.install(framework, loader);
        MiniProgramVersionGate.install(framework, loader);
    }

    public static void installAppBrand(HookFramework framework, ClassLoader loader, ToolSettings settings) {
        RuntimeSettings.update(settings);
        VersionWindow.configure(settings.targetVersion);
        VersionWindow.install(framework, loader);
        MiniProgramSpoof.installAppBrand(framework, loader);
        if (settings.enabled && settings.global) VersionWindow.openGlobal(framework, loader);
    }
}
