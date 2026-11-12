package io.github.shadowbaby.wechatxposed.hook.support.guard;

import io.github.shadowbaby.wechatxposed.shared.hook.HookCallback;
import io.github.shadowbaby.wechatxposed.shared.hook.HookFramework;
import io.github.shadowbaby.wechatxposed.shared.hook.HookParam;
import io.github.shadowbaby.wechatxposed.hook.loader.util.ByteSearch;
import io.github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import io.github.shadowbaby.wechatxposed.hook.loader.util.Secret;
import io.github.shadowbaby.wechatxposed.hook.loader.SecretConstants;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.util.Set;

public final class X3SettingsBypass {

    private static final String SETTINGS_CLASS =
            Secret.of(SecretConstants.X30_SETTINGS_CLASS);
    private static final String[] SETTINGS_CLASSES = {SETTINGS_CLASS};

    private static final String LOG_HOOKED = "X3 settings hooked: ";
    private static final String LOG_FAILED = "X3 settings hook failed: ";

    private static final Set<String> DONE = java.util.concurrent.ConcurrentHashMap.newKeySet();

    private static final String TAG_DISCLAIMER =
            Secret.of(SecretConstants.X30_TAG_DISCLAIMER);
    private static final String TAG_VALID = Secret.of(SecretConstants.X30_TAG_VALID);
    private static final String TAG_S_VALID = Secret.of(SecretConstants.X30_TAG_S_VALID);

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
                ModuleLogger.debug(LOG_HOOKED + className + " (" + count + " method(s))");
            } catch (Throwable error) {

                DONE.remove(key);
                ModuleLogger.debug(LOG_FAILED + className + " " + error);
            }
        }
    }

    public static boolean matchesDex(HookParam param) {
        byte[] needle = SETTINGS_CLASS.replace('.', '/').getBytes();
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

                if (TAG_DISCLAIMER.equals(key)) {
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
                } else if (TAG_VALID.equals(key) || TAG_S_VALID.equals(key)) {
                    if (returnType == Boolean.TYPE || returnType == Boolean.class) {
                        param.setResult(Boolean.TRUE);
                    }
                }
            } catch (Throwable ignored) {

            }
        }
    }
}
