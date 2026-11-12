package io.github.shadowbaby.wechatxposed.hook.framework;

import io.github.shadowbaby.wechatxposed.shared.hook.HookFramework;

public interface PlatformHooks {

    void installZygote(HookFramework framework, String modulePath);

    void installEarly(HookFramework framework, ClassLoader classLoader);

    void installPackGuards(HookFramework framework);

    String prepareShell(HookFramework framework, android.content.pm.ApplicationInfo appInfo,
            String modulePath);

    ClassLoader prepareShellLoader(HookFramework framework,
            android.content.pm.ApplicationInfo appInfo, String modulePath);

    String shellEntryClass();

    String shellPackage();

    String settingsHint();
}
