package github.shadowbaby.wechatxposed.hook.support.guard;

import github.shadowbaby.wechatxposed.hook.framework.HookCallback;
import github.shadowbaby.wechatxposed.hook.framework.HookFramework;
import github.shadowbaby.wechatxposed.hook.framework.HookParam;
import github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import github.shadowbaby.wechatxposed.hook.loader.util.Secret;
import github.shadowbaby.wechatxposed.hook.loader.SecretConstants;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.util.Set;

/**
 * X 3.0 的设置/数据库读取层处理。
 *
 * 禁用码返回 0/false，valid 类返回 true。
 */
public final class X3SettingsBypass {

    private static final String SETTINGS_CLASS = Secret.of(SecretConstants.X30_SETTINGS_CLASS);
    private static final String SETTINGS_CLASS_V207 =
            Secret.of(SecretConstants.X30_SETTINGS_CLASS_V207);
    private static final String[] SETTINGS_CLASSES = {SETTINGS_CLASS, SETTINGS_CLASS_V207};

    private static final String LOG_HOOKED = "X3 settings hooked: ";
    private static final String LOG_FAILED = "X3 settings hook failed: ";

    private static final Set<String> DONE = java.util.concurrent.ConcurrentHashMap.newKeySet();

    private X3SettingsBypass() {
    }

    public static boolean matchesClass(HookFramework framework, ClassLoader classLoader) {
        for (String name : SETTINGS_CLASSES) {
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
        for (String className : SETTINGS_CLASSES) {
            String key = className + "@" + System.identityHashCode(classLoader);
            if (!DONE.add(key)) {
                continue;
            }
            try {
                Class<?> target = Class.forName(className, false, classLoader);
                int count = 0;
                for (Method method : target.getDeclaredMethods()) {
                    Class<?>[] params = method.getParameterTypes();
                    if (params.length == 0 || params[0] != String.class) {
                        continue;
                    }
                    framework.hookMethod(method, new Callback(method.getReturnType()));
                    count++;
                }
                ModuleLogger.debug(LOG_HOOKED + className + " (" + count + " method(s))");
            } catch (Throwable error) {
                ModuleLogger.log(LOG_FAILED + className + " " + error);
            }
        }
    }

    public static boolean matchesDex(HookParam param) {
        byte[] needle = SETTINGS_CLASS.replace('.', '/').getBytes();
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
            // 按未命中处理
        }
        return false;
    }

    private static final class Callback implements HookCallback {

        private final Class<?> returnType;

        Callback(Class<?> returnType) {
            this.returnType = returnType;
        }

        @Override
        public void before(HookParam param) {
            try {
                String key = String.valueOf(param.arg(0));
                String lower = key.toLowerCase();
                // disclaimer_disable 的语义是「已关闭免责声明」，必须给 true，
                // 否则每次打开设置页都会重新弹倒计时。
                if ("disclaimer_disable".equals(key)) {
                    if (returnType == Boolean.TYPE || returnType == Boolean.class) {
                        param.setResult(Boolean.TRUE);
                    }
                    return;
                }
                if (lower.contains("disable")) {
                    if (returnType == Boolean.TYPE || returnType == Boolean.class) {
                        param.setResult(Boolean.FALSE);
                    } else if (returnType == Integer.TYPE || returnType == Integer.class) {
                        param.setResult(0);
                    } else if (returnType == Long.TYPE || returnType == Long.class) {
                        param.setResult(0L);
                    } else if (returnType == String.class) {
                        param.setResult("");
                    }
                    ModuleLogger.debug("X3 setting bypass: " + key);
                } else if ("valid".equals(key) || "s_valid".equals(key)) {
                    if (returnType == Boolean.TYPE || returnType == Boolean.class) {
                        param.setResult(Boolean.TRUE);
                    }
                }
            } catch (Throwable ignored) {
                // 保持原读取
            }
        }
    }
}
