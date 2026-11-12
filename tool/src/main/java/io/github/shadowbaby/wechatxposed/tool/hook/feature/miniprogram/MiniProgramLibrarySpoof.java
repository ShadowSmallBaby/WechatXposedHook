package io.github.shadowbaby.wechatxposed.tool.hook.feature.miniprogram;

import io.github.shadowbaby.wechatxposed.tool.hook.config.RuntimeSettings;
import io.github.shadowbaby.wechatxposed.tool.hook.config.ToolSettings;
import io.github.shadowbaby.wechatxposed.shared.hook.HookCallback;
import io.github.shadowbaby.wechatxposed.shared.hook.HookFramework;
import io.github.shadowbaby.wechatxposed.shared.hook.HookParam;
import io.github.shadowbaby.wechatxposed.tool.hook.framework.ToolLogger;
import java.lang.reflect.Constructor;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import static io.github.shadowbaby.wechatxposed.tool.hook.spoof.HostFingerprint.*;


public final class MiniProgramLibrarySpoof {
    static final int ADVERTISED_BUILD = fpInt("mini.library.advertise.request.advertisedBuild");
    private static final Set<Constructor<?>> HOOKED = ConcurrentHashMap.newKeySet();
    private MiniProgramLibrarySpoof() {}

    public static void install(HookFramework framework, ClassLoader loader) {
        try {
            Class<?> type = framework.findClassIfExists(fp("mini.library.advertise.launch.libraryRequest.class"), loader);
            if (type == null) return;

            Constructor<?> ctor = fpConstructor(type, "mini.library.advertise.install.constructor.signature");
            if (!HOOKED.add(ctor)) return;
            try {
                framework.hookMethod(ctor, new HookCallback() {
                    @Override public void before(HookParam param) {
                        ToolSettings settings = RuntimeSettings.get();
                        if (settings.enabled && settings.miniProgramMode == ToolSettings.MINI_LIB) {
                            param.setArg(fpInt("mini.library.advertise.constructor.spoofBuildArg"), ADVERTISED_BUILD);
                        }
                    }
                });
            } catch (Throwable error) { HOOKED.remove(ctor); throw error; }
        } catch (Throwable error) { ToolLogger.debug("mini LIB: launch constructor unavailable"); }
    }
}
