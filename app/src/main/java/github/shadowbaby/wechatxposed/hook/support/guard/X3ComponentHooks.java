package github.shadowbaby.wechatxposed.hook.support.guard;

import github.shadowbaby.wechatxposed.hook.framework.HookFramework;
import github.shadowbaby.wechatxposed.hook.framework.HookParam;
import github.shadowbaby.wechatxposed.hook.loader.util.ByteSearch;
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

    /** Class.forName 偶尔看不到刚加载的 dex 里的类，直接扫 dex 字节更稳。 */
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

    /**
     * 每次功能 dex 加载后都会调用一次；桥只挂一次，各 Bypass 自己按类幂等，
     * 找不到目标类时保留重试机会（功能 dex 里有些类要等它自己的 init 才可见）。
     */
    public static synchronized void inject(HookFramework framework, ClassLoader classLoader) {
        inject(framework, classLoader, true);
    }

    /**
     * @param licensed 未授权时只挂组件桥，不装任何授权/设置绕过，
     *                 否则壳会以为已授权而跳过自己的用户协议。
     */
    public static synchronized void inject(HookFramework framework, ClassLoader classLoader,
            boolean licensed) {
        try {
            // 壳的 ClassLoader 能加载 c.**，后面直接问壳要账号。
            github.shadowbaby.wechatxposed.hook.license.Activation.setShellLoader(classLoader);
            hookBridge(framework, classLoader, BRIDGE_CLASS);
            hookBridge(framework, classLoader, LOADER_CLASS);
            if (licensed) {
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
