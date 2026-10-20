package github.shadowbaby.wechatxposed.hook.support;

import github.shadowbaby.wechatxposed.hook.framework.HookCallback;
import github.shadowbaby.wechatxposed.hook.framework.HookFramework;
import github.shadowbaby.wechatxposed.hook.framework.HookParam;
import github.shadowbaby.wechatxposed.hook.loader.ModuleLogger;
import github.shadowbaby.wechatxposed.hook.loader.Secret;
import github.shadowbaby.wechatxposed.hook.loader.SecretConstants;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.util.ArrayList;

/**
 * X 3.0 的授权门禁处理。
 *
 * 将 LIC 类的布尔方法置真，并清空授权列表返回值。
 */
public final class X3LicenseBypass {

    private static final String LICENSE_CLASS = Secret.of(SecretConstants.X30_LICENSE_CLASS);
    private static final String LICENSE_CLASS_V207 =
            Secret.of(SecretConstants.X30_LICENSE_CLASS_V207);
    private static final String[] LICENSE_CLASSES = {LICENSE_CLASS, LICENSE_CLASS_V207};

    private static final String LOG_HOOKED = "X3 license hooked: ";
    private static final String LOG_NOT_FOUND = "X3 license class not found";
    private static final String LOG_FAILED = "X3 license hook failed";

    private static final java.util.Set<String> DONE =
            java.util.concurrent.ConcurrentHashMap.newKeySet();

    private X3LicenseBypass() {
    }

    public static boolean matchesClass(HookFramework framework, ClassLoader classLoader) {
        for (String name : LICENSE_CLASSES) {
            try {
                if (framework.findClassIfExists(name, classLoader) != null) {
                    return true;
                }
            } catch (Throwable ignored) {
                // 继续看下一个名字
            }
        }
        return false;
    }

    public static synchronized void install(HookFramework framework, ClassLoader classLoader) {
        for (String className : LICENSE_CLASSES) {
            String key = className + "@" + System.identityHashCode(classLoader);
            if (!DONE.add(key)) {
                continue;
            }
            try {
                Class<?> target;
                try {
                    target = Class.forName(className, false, classLoader);
                } catch (Throwable error) {
                    ModuleLogger.log("X3 license load failed: " + className + " / " + error);
                    continue;
                }
                int count = 0;
                for (Method method : target.getDeclaredMethods()) {
                    Class<?> result = method.getReturnType();
                    if (result == Boolean.TYPE || result == Boolean.class) {
                        framework.hookMethod(method, new BooleanCallback());
                        count++;
                    }
                    // 不再清空 ArrayList 返回值：授权类里的列表方法也参与
                    // 功能数据分发，置空会让设置菜单拿不到任何条目。
                }
                ModuleLogger.log(LOG_HOOKED + className + " (" + count + " method(s))");
                if (LICENSE_CLASS.equals(className)) {
                    PackIntegrity.onOldCoreDetected("license " + className);
                }
            } catch (Throwable error) {
                ModuleLogger.log(LOG_FAILED + ": " + className);
                ModuleLogger.log(error);
                PackIntegrity.onHookError("license " + className);
            }
        }
    }

    /** 扫描 dex 字节，判断当前加载的是否是含 LIC 类的 dex。 */
    public static boolean matchesDex(HookParam param) {
        byte[] needle = LICENSE_CLASS.replace('.', '/').getBytes();
        byte[] needleV207 = LICENSE_CLASS_V207.replace('.', '/').getBytes();
        Object first = param.arg(0);
        if (first instanceof ByteBuffer buffer) {
            return contains(buffer, needle) || contains(buffer, needleV207);
        }
        if (first instanceof ByteBuffer[] buffers) {
            for (ByteBuffer buffer : buffers) {
                if (contains(buffer, needle) || contains(buffer, needleV207)) {
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
            // 按未命中处理
        }
        return false;
    }

    private static final class BooleanCallback implements HookCallback {

        @Override
        public void before(HookParam param) {
            param.setResult(Boolean.TRUE);
        }
    }

    private static final class EmptyListCallback implements HookCallback {

        @Override
        public void before(HookParam param) {
            param.setResult(new ArrayList<>());
        }
    }
}
