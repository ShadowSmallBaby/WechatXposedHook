package io.github.shadowbaby.wechatxposed.hook.support;

import io.github.shadowbaby.wechatxposed.shared.hook.HookCallback;
import io.github.shadowbaby.wechatxposed.shared.hook.HookFramework;
import io.github.shadowbaby.wechatxposed.shared.hook.HookParam;
import io.github.shadowbaby.wechatxposed.hook.loader.ModuleLogger;
import io.github.shadowbaby.wechatxposed.hook.loader.Secret;
import io.github.shadowbaby.wechatxposed.hook.loader.SecretConstants;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.util.Set;


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
                if (SETTINGS_CLASS.equals(className)) {
                    PackIntegrity.onOldCoreDetected("settings " + className);
                }
            } catch (Throwable error) {
                ModuleLogger.log(LOG_FAILED + className + " " + error);
                PackIntegrity.onHookError("settings " + className);
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
                } else if ("valid".equals(key) || "s_valid".equals(key)) {
                    if (returnType == Boolean.TYPE || returnType == Boolean.class) {
                        param.setResult(Boolean.TRUE);
                    }
                }
            } catch (Throwable ignored) {

            }
        }
    }
}
