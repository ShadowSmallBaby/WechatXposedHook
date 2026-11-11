package io.github.shadowbaby.wechatxposed.hook.support;

import io.github.shadowbaby.wechatxposed.shared.hook.HookCallback;
import io.github.shadowbaby.wechatxposed.shared.hook.HookFramework;
import io.github.shadowbaby.wechatxposed.shared.hook.HookParam;
import io.github.shadowbaby.wechatxposed.hook.loader.ModuleLogger;
import io.github.shadowbaby.wechatxposed.hook.loader.Secret;
import io.github.shadowbaby.wechatxposed.hook.loader.SecretConstants;
import java.lang.reflect.Method;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;


public final class FeatureCloseGuard {

    private static final String[] ENTRY_CLASSES = {
            Secret.of(SecretConstants.X30_ENTRY_BASE),
            Secret.of(SecretConstants.X30_ENTRY_DONATION),
            Secret.of(SecretConstants.X30_ENTRY_THEMES)};


    private static final String BASE_SETTINGS = Secret.of(SecretConstants.X30_BASE_SETTINGS);


    private static final String BASE_REGISTRY = Secret.of(SecretConstants.X30_BASE_REGISTRY);


    private static final String INIT_GATE_CLASS = Secret.of(SecretConstants.X30_INIT_GATE_CLASS);

    private static final String INIT_GATE_METHOD = Secret.of(SecretConstants.X30_INIT_GATE_METHOD);

    private static final String FINISH = "finish";

    private static final String INIT = "init";


    private static final String PUBLISH_PREFIX = "publish";

    private static final String REGISTRY_REMOVE =
            Secret.of(SecretConstants.X30_REGISTRY_REMOVE);
    private static final String REGISTRY_PUBLISH =
            Secret.of(SecretConstants.X30_REGISTRY_PUBLISH);
    private static final String BASE_DISABLE_GETTER =
            Secret.of(SecretConstants.X30_BASE_DISABLE_GETTER);

    private static final String[] BLOCKED_COMMANDS = {
            Secret.of(SecretConstants.METHOD_DISABLE),
            Secret.of(SecretConstants.METHOD_ON_UPDATE_CHECK),
            Secret.of(SecretConstants.METHOD_PROCESS_METADATA),
            Secret.of(SecretConstants.METHOD_UPDATE_LICENSE),
            Secret.of(SecretConstants.METHOD_DELAYED_CHECK)};

    private static final String LOG_HOOKED = "feature close guard: ";
    private static final String LOG_BLOCKED = "feature close blocked: ";
    private static final String LOG_DISABLE_GET = "feature disable getter blocked: ";
    private static final String LOG_PUBLISH_BLOCKED = "feature publish blocked: ";
    private static final String LOG_REGISTRY_REMOVE = "feature registry remove: ";

    private static final int LOG_LIMIT = 12;

    private static final Set<String> DONE = ConcurrentHashMap.newKeySet();

    private static final AtomicInteger PUBLISH_LOGS = new AtomicInteger();

    private FeatureCloseGuard() {
    }

    public static void probe(HookFramework framework, ClassLoader classLoader) {
        if (classLoader == null) {
            return;
        }
        for (String name : ENTRY_CLASSES) {
            String key = name + "@" + System.identityHashCode(classLoader);
            if (!DONE.add(key)) {
                continue;
            }
            try {
                Class<?> target = framework.findClassIfExists(name, classLoader);
                if (target == null) {
                    continue;
                }
                int count = 0;
                for (Method method : target.getDeclaredMethods()) {
                    String methodName = method.getName();
                    if (FINISH.equals(methodName)) {
                        framework.hookMethod(method, new Noop(LOG_BLOCKED + name, null));
                        count++;
                    } else if (methodName.startsWith(PUBLISH_PREFIX)) {
                        framework.hookMethod(method, new PublishGuard(name));
                        count++;
                    } else if (INIT.equals(methodName)
                            && method.getParameterCount() == 2
                            && method.getParameterTypes()[0] == android.content.Context.class
                            && method.getParameterTypes()[1] == Object[].class) {
                        framework.hookMethod(method, new InitContextGuard(name));
                        count++;
                    }
                }
                hookBaseSettings(framework, classLoader);
                hookBaseRegistry(framework, classLoader);
                hookInitGate(framework, classLoader);
            } catch (Throwable ignored) {

            }
        }
    }

    private static void hookBaseRegistry(HookFramework framework, ClassLoader classLoader) {
        String key = BASE_REGISTRY + "@" + System.identityHashCode(classLoader);
        if (!DONE.add(key)) {
            return;
        }
        try {
            Class<?> target = framework.findClassIfExists(BASE_REGISTRY, classLoader);
            if (target == null) {
                return;
            }
            int count = 0;
            for (Method method : target.getDeclaredMethods()) {
                String methodName = method.getName();
                Class<?>[] types = method.getParameterTypes();
                if (REGISTRY_REMOVE.equals(methodName) && types.length == 1
                        && types[0] == String.class) {
                    framework.hookMethod(method, new LogString(LOG_REGISTRY_REMOVE));
                    count++;
                } else if (REGISTRY_PUBLISH.equals(methodName) && types.length == 2
                        && types[0] == String.class) {
                    framework.hookMethod(method, new PublishGuard(BASE_REGISTRY));
                    count++;
                }
            }
        } catch (Throwable ignored) {

        }
    }


    private static void hookInitGate(HookFramework framework, ClassLoader classLoader) {
        String key = INIT_GATE_CLASS + "#" + INIT_GATE_METHOD + "@"
                + System.identityHashCode(classLoader);
        if (!DONE.add(key)) {
            return;
        }
        try {
            Class<?> target = framework.findClassIfExists(INIT_GATE_CLASS, classLoader);
            if (target == null) {
                return;
            }
            for (Method method : target.getDeclaredMethods()) {
                if (INIT_GATE_METHOD.equals(method.getName())
                        && method.getParameterCount() == 0
                        && method.getReturnType() == Boolean.TYPE) {
                    framework.hookMethod(method, new InitGate());
                }
            }
        } catch (Throwable ignored) {

        }
    }

    private static void hookBaseSettings(HookFramework framework, ClassLoader classLoader) {
        String key = BASE_SETTINGS + "@" + System.identityHashCode(classLoader);
        if (!DONE.add(key)) {
            return;
        }
        try {
            Class<?> target = framework.findClassIfExists(BASE_SETTINGS, classLoader);
            if (target == null) {
                return;
            }
            for (Method method : target.getDeclaredMethods()) {
                if (BASE_DISABLE_GETTER.equals(method.getName())
                        && method.getParameterCount() == 1
                        && method.getParameterTypes()[0] == String.class
                        && (method.getReturnType() == Boolean.TYPE
                                || method.getReturnType() == Boolean.class)) {
                    framework.hookMethod(method, new Noop(LOG_DISABLE_GET, Boolean.FALSE, true));
                }
            }
        } catch (Throwable ignored) {

        }
    }

    private static boolean blocked(String command) {

        for (String blocked : BLOCKED_COMMANDS) {
            if (blocked.equals(command)) {
                return true;
            }
        }
        return false;
    }


    private static final class InitContextGuard implements HookCallback {

        private static final Set<String> LOGGED = ConcurrentHashMap.newKeySet();

        private final String className;

        InitContextGuard(String className) {
            this.className = className;
        }

        @Override
        public void before(HookParam param) {
            Object[] args = param.args();
            if (args == null || args.length < 2 || !(args[1] instanceof Object[] values)) {
                return;
            }
            if (values.length <= 2) {
                return;
            }
            if (values[2] != null) {
                if (LOGGED.add(className + ":ok")) {
                }
                return;
            }
            Object context = args[0];
            if (context == null) {
                if (LOGGED.add(className + ":null")) {
                }
                return;
            }
            values[2] = context;
            if (LOGGED.add(className)) {
            }
        }
    }


    private static final class InitGate implements HookCallback {

        private static final AtomicInteger CALLS = new AtomicInteger();

        @Override
        public void before(HookParam param) {
            if (CALLS.incrementAndGet() <= 3) {
            }
            param.setResult(Boolean.FALSE);
        }
    }

    private static final class Noop implements HookCallback {

        private final String message;
        private final Object result;
        private final boolean debugOnly;

        Noop(String message, Object result) {
            this(message, result, false);
        }

        Noop(String message, Object result, boolean debugOnly) {
            this.message = message;
            this.result = result;
            this.debugOnly = debugOnly;
        }

        @Override
        public void before(HookParam param) {
            if (debugOnly) {
            } else {
                ModuleLogger.log(message);
            }
            param.setResult(result);
        }
    }

    private static final class LogString implements HookCallback {

        private final String prefix;

        LogString(String prefix) {
            this.prefix = prefix;
        }

        @Override
        public void before(HookParam param) {
            String value = String.valueOf(param.arg(0));
            if (value.length() > 160) {
                value = value.substring(0, 160);
            }
        }
    }

    private static final class InitLogger implements HookCallback {

        private final String className;

        InitLogger(String className) {
            this.className = className;
        }

        @Override
        public void before(HookParam param) {
        }

        @Override
        public void after(HookParam param) {
        }
    }

    private static final class PublishGuard implements HookCallback {


        private static final String TRANSFER_SCENE_COMMAND = "on_RemittanceDetailUI_onSceneEnd";

        private final String className;

        PublishGuard(String className) {
            this.className = className;
        }

        @Override
        public void before(HookParam param) {
            String command = String.valueOf(param.arg(0));

            if (TRANSFER_SCENE_COMMAND.equals(command)) {
                ModuleLogger.log(LOG_PUBLISH_BLOCKED + command + " -> " + className);
                param.setResult(null);
                return;
            }
            if (blocked(command)) {
                ModuleLogger.log(LOG_PUBLISH_BLOCKED + command + " -> " + className);
                param.setResult(null);
                return;
            }
            String lower = command.toLowerCase();
            boolean interesting = lower.contains("disable") || lower.contains("update")
                    || lower.contains("close") || lower.contains("stop")
                    || lower.contains("unload");
            if (interesting || PUBLISH_LOGS.incrementAndGet() <= LOG_LIMIT) {
            }
        }
    }
}
