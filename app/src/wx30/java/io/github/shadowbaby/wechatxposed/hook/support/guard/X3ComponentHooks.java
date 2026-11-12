package io.github.shadowbaby.wechatxposed.hook.support.guard;

import io.github.shadowbaby.wechatxposed.hook.BuildConfig;
import io.github.shadowbaby.wechatxposed.shared.hook.HookFramework;
import io.github.shadowbaby.wechatxposed.shared.hook.HookParam;
import io.github.shadowbaby.wechatxposed.hook.loader.util.ByteSearch;
import io.github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import io.github.shadowbaby.wechatxposed.hook.loader.util.Secret;
import io.github.shadowbaby.wechatxposed.hook.loader.SecretConstants;
import java.nio.ByteBuffer;

public final class X3ComponentHooks {

    private static final String ENTRY_CLASS = Secret.of(SecretConstants.COMPONENT_X30);
    private static final String BRIDGE_CLASS = Secret.of(SecretConstants.X30_BRIDGE_CLASS);
    private static final String LOADER_CLASS = Secret.of(SecretConstants.X30_LOADER_CLASS);
    private static final String CALL_METHOD = Secret.of(SecretConstants.X30_CALL_METHOD);

    private static final String LOG_HOOKED = "X3 hooked: ";
    private static final String LOG_NOT_FOUND = "X3 bridge not found: ";
    private static final String LOG_FAILED = "X3 hook failed";

    private static final java.util.Set<String> BRIDGED =
            java.util.concurrent.ConcurrentHashMap.newKeySet();

    private X3ComponentHooks() {
    }

    public static boolean matches(HookFramework framework, ClassLoader classLoader) {
        try {
            return framework.findClassIfExists(ENTRY_CLASS, classLoader) != null;
        } catch (Throwable error) {
            return false;
        }
    }

    public static boolean matchesDex(HookParam param) {
        byte[] needle = ENTRY_CLASS.replace('.', '/').getBytes();
        Object first = param.arg(0);
        if (first instanceof ByteBuffer buffer) {
            return ByteSearch.contains(buffer, needle);
        }
        if (first instanceof ByteBuffer[] buffers) {
            for (ByteBuffer buffer : buffers) {
                if (ByteSearch.contains(buffer, needle)) {
                    return true;
                }
            }
        }
        return false;
    }

    public static synchronized void inject(HookFramework framework, ClassLoader classLoader) {
        try {

            io.github.shadowbaby.wechatxposed.hook.license.Activation.setShellLoader(classLoader);
            hookBridge(framework, classLoader, BRIDGE_CLASS);
            hookBridge(framework, classLoader, LOADER_CLASS);
            if (!BuildConfig.WX_PACK.startsWith("wx6")) {
                X3GuardBypass.install(framework, classLoader);
                X3SettingsBypass.install(framework, classLoader);
            }
        } catch (Throwable error) {
            ModuleLogger.debug(LOG_FAILED);
            ModuleLogger.log(error);
        }
    }

    private static void hookBridge(HookFramework framework, ClassLoader classLoader, String className) {
        String key = className + "@" + System.identityHashCode(classLoader);
        if (!BRIDGED.add(key)) {
            return;
        }
        try {
            Class<?> bridge = framework.findClassIfExists(className, classLoader);
            if (bridge == null) {
                BRIDGED.remove(key);
                ModuleLogger.debug(LOG_NOT_FOUND + className);
                return;
            }
            framework.hookMethod(
                    bridge,
                    CALL_METHOD,
                    new Class<?>[]{Integer.TYPE, Object[].class},
                    new X3CallMethodHook());
            ModuleLogger.debug(LOG_HOOKED + className + "." + CALL_METHOD);
        } catch (Throwable error) {
            BRIDGED.remove(key);
            ModuleLogger.debug(LOG_FAILED + ": " + className);
            ModuleLogger.log(error);
        }
    }
}
