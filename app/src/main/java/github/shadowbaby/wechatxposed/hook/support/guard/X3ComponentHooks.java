package github.shadowbaby.wechatxposed.hook.support.guard;

import github.shadowbaby.wechatxposed.hook.framework.HookFramework;
import github.shadowbaby.wechatxposed.hook.framework.HookParam;
import github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import github.shadowbaby.wechatxposed.hook.loader.util.Secret;
import github.shadowbaby.wechatxposed.hook.loader.SecretConstants;
import java.nio.ByteBuffer;

/**
 * X 3.0 的组件注入。
 *
 * 在 InMemoryDexClassLoader 加载到含入口类的 dex 时注入桥与授权 hook。
 */
public final class X3ComponentHooks {

    private static final String ENTRY_CLASS = Secret.of(SecretConstants.COMPONENT_X30);
    private static final String BRIDGE_CLASS = Secret.of(SecretConstants.X30_BRIDGE_CLASS);
    private static final String LOADER_CLASS = Secret.of(SecretConstants.X30_LOADER_CLASS);
    private static final String CALL_METHOD = Secret.of(SecretConstants.X30_CALL_METHOD);

    private static final String LOG_HOOKED = "X3 hooked: ";
    private static final String LOG_NOT_FOUND = "X3 bridge not found: ";
    private static final String LOG_FAILED = "X3 hook failed";

    private static boolean injected;

    private X3ComponentHooks() {
    }

    public static boolean matches(HookFramework framework, ClassLoader classLoader) {
        try {
            return framework.findClassIfExists(ENTRY_CLASS, classLoader) != null;
        } catch (Throwable error) {
            return false;
        }
    }

    /** Class.forName 偶尔看不到刚加载的 dex 里的类，直接扫 dex 字节更稳。 */
    public static boolean matchesDex(HookParam param) {
        byte[] needle = ENTRY_CLASS.replace('.', '/').getBytes();
        Object first = param.arg(0);
        if (first instanceof ByteBuffer buffer) {
            return contains(buffer, needle);
        }
        if (first instanceof ByteBuffer[] buffers) {
            for (ByteBuffer buffer : buffers) {
                if (contains(buffer, needle)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean contains(ByteBuffer source, byte[] needle) {
        try {
            ByteBuffer buffer = source.duplicate();
            buffer.rewind();
            byte[] data = new byte[buffer.remaining()];
            buffer.get(data);
            outer:
            for (int index = 0; index <= data.length - needle.length; index++) {
                for (int offset = 0; offset < needle.length; offset++) {
                    if (data[index + offset] != needle[offset]) {
                        continue outer;
                    }
                }
                return true;
            }
        } catch (Throwable ignored) {
            // 忽略，按未命中处理
        }
        return false;
    }

    public static synchronized void inject(HookFramework framework, ClassLoader classLoader) {
        if (injected) {
            return;
        }
        injected = true;
        try {
            hookBridge(framework, classLoader, BRIDGE_CLASS);
            hookBridge(framework, classLoader, LOADER_CLASS);
            X3LicenseBypass.install(framework, classLoader);
            X3GuardBypass.install(framework, classLoader);
            X3SettingsBypass.install(framework, classLoader);
        } catch (Throwable error) {
            ModuleLogger.debug(LOG_FAILED);
            ModuleLogger.log(error);
        }
    }

    private static void hookBridge(HookFramework framework, ClassLoader classLoader, String className) {
        try {
            Class<?> bridge = framework.findClassIfExists(className, classLoader);
            if (bridge == null) {
                ModuleLogger.debug(LOG_NOT_FOUND + className);
                return;
            }
            framework.hookMethod(
                    bridge,
                    CALL_METHOD,
                    new Class<?>[]{Integer.TYPE, Object[].class},
                    new X3CallMethodHook());
            ModuleLogger.log(LOG_HOOKED + className + "." + CALL_METHOD);
        } catch (Throwable error) {
            ModuleLogger.debug(LOG_FAILED + ": " + className);
            ModuleLogger.log(error);
        }
    }
}
