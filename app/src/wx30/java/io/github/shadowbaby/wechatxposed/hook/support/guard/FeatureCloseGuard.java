package io.github.shadowbaby.wechatxposed.hook.support.guard;

import android.os.SystemClock;
import io.github.shadowbaby.wechatxposed.shared.hook.HookCallback;
import io.github.shadowbaby.wechatxposed.shared.hook.HookFramework;
import io.github.shadowbaby.wechatxposed.shared.hook.HookParam;
import io.github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import io.github.shadowbaby.wechatxposed.hook.loader.util.Secret;
import io.github.shadowbaby.wechatxposed.hook.loader.SecretConstants;
import java.lang.reflect.Method;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

public final class FeatureCloseGuard {

    private static final String[] ENTRY_CLASSES = {
            Secret.of(SecretConstants.X30_ENTRY_BASE),
            Secret.of(SecretConstants.X30_ENTRY_DONATION),
            Secret.of(SecretConstants.X30_ENTRY_THEMES)};

    private static final String BASE_SETTINGS = Secret.of(SecretConstants.X30_BASE_SETTINGS);

    private static final String BASE_REGISTRY = Secret.of(SecretConstants.X30_BASE_REGISTRY);

    private static final String BASE_REFRESH_CLASS =
            Secret.of(SecretConstants.X30_BASE_FILE_REFRESH_CLASS);
    private static final String BASE_REFRESH_METHOD =
            Secret.of(SecretConstants.X30_BASE_FILE_REFRESH_METHOD);

    private static final String BASE_DATA_GET_METHOD =
            Secret.of(SecretConstants.X30_BASE_DATA_GET_METHOD);

    private static final ThreadLocal<Boolean> BASE_REFRESHING = new ThreadLocal<>();

    private static final String LOG_SKIP_REFRESH = "base file refresh: null data -> empty";

    private static final String INIT_GATE_CLASS = Secret.of(SecretConstants.X30_INIT_GATE_CLASS);

    private static final String INIT_GATE_METHOD = Secret.of(SecretConstants.X30_INIT_GATE_METHOD);

    private static final String LOG_INIT_GATE = "feature init gate: ";

    private static final String FINISH = Secret.of(SecretConstants.X30_ENTRY_FINISH);

    private static final String INIT = Secret.of(SecretConstants.X30_ENTRY_INIT);

    private static final String LOG_INIT_CONTEXT = "feature init context: ";

    private static final String PUBLISH_PREFIX = Secret.of(SecretConstants.X30_ENTRY_PUBLISH);

    private static final String GET_DATA = Secret.of(SecretConstants.X30_ENTRY_GET_DATA);

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
            Secret.of(SecretConstants.METHOD_UPDATE_LICENSE)};

    private static final String LOG_HOOKED = "feature close guard: ";
    private static final String LOG_BLOCKED = "feature close blocked: ";
    private static final String LOG_DISABLE_GET = "feature disable getter blocked: ";
    private static final String LOG_PUBLISH_BLOCKED = "feature publish blocked: ";
    private static final String LOG_PUBLISH = "feature publish: ";
    private static final String LOG_PUBLISH_SLOW = "feature publish slow: ";
    private static final String LOG_EVENT = "feature event: ";
    private static final String LOG_REGISTRY_REMOVE = "feature registry remove: ";

    private static final int LOG_LIMIT = 12;

    private static final int SLOW_MS = 200;

    private static final Set<String> DONE = ConcurrentHashMap.newKeySet();

    private static final Set<String> EVENTS = ConcurrentHashMap.newKeySet();

    private static final ThreadLocal<String> PUBLISH_CMD = new ThreadLocal<>();

    private static final ThreadLocal<Long> PUBLISH_AT = new ThreadLocal<>();

    private static final java.util.concurrent.atomic.AtomicBoolean CHANNELS_LOGGED =
            new java.util.concurrent.atomic.AtomicBoolean();

    private static final String LOG_CHANNELS = "feature channels: ";

    private static final int CHANNEL_LIMIT = 40;

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

                    DONE.remove(key);
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
                    } else if (GET_DATA.equals(methodName)) {
                        framework.hookMethod(method, new GetDataLogger());
                        count++;
                    } else if (INIT.equals(methodName)
                            && method.getParameterCount() == 2
                            && method.getParameterTypes()[0] == android.content.Context.class
                            && method.getParameterTypes()[1] == Object[].class) {
                        framework.hookMethod(method, new InitContextGuard(name));
                        count++;
                    }
                }
                ModuleLogger.debug(LOG_HOOKED + name + " (" + count + " method(s))");
                hookBaseSettings(framework, classLoader);
                hookBaseRegistry(framework, classLoader);
                hookBaseFileRefresh(framework, classLoader);
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
            ModuleLogger.debug(LOG_HOOKED + BASE_REGISTRY + " (" + count + " method(s))");
        } catch (Throwable ignored) {

        }
    }

    private static void hookBaseFileRefresh(HookFramework framework, ClassLoader classLoader) {
        String key = "base-refresh@" + System.identityHashCode(classLoader);
        if (!DONE.add(key)) {
            return;
        }
        try {
            Class<?> refresh = framework.findClassIfExists(BASE_REFRESH_CLASS, classLoader);
            Class<?> hub = framework.findClassIfExists(BASE_REGISTRY, classLoader);
            if (refresh == null || hub == null) {
                DONE.remove(key);
                return;
            }
            framework.hookMethod(refresh, BASE_REFRESH_METHOD, new Class<?>[]{},
                    new FileRefreshGuard());
            for (Method method : hub.getDeclaredMethods()) {
                Class<?>[] types = method.getParameterTypes();
                if (BASE_DATA_GET_METHOD.equals(method.getName()) && types.length == 3
                        && types[0] == String.class && types[1] == String.class) {
                    framework.hookMethod(method, new BaseDataGuard());
                }
            }
            ModuleLogger.debug(LOG_HOOKED + BASE_REFRESH_CLASS + "." + BASE_REFRESH_METHOD);
        } catch (Throwable error) {
            DONE.remove(key);
            ModuleLogger.debug("base file refresh hook failed: " + error);
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
                    ModuleLogger.debug(LOG_INIT_GATE + "hooked");
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

    private static void logChannels(HookParam param) {
        if (!CHANNELS_LOGGED.compareAndSet(false, true)) {
            return;
        }
        Object instance = param.thisObject();
        if (instance == null) {
            return;
        }
        dumpChannels(instance, "getEventChannels");
        dumpChannels(instance, "getIdEventChannels");
    }

    private static void dumpChannels(Object instance, String name) {
        try {
            java.lang.reflect.Method method = instance.getClass().getMethod(name);
            Object value = method.invoke(instance);
            ModuleLogger.debug(LOG_CHANNELS + name + " count=" + channelSize(value));
            if (value instanceof java.util.Collection<?> collection) {

                java.util.List<String> items = new java.util.ArrayList<>();
                for (Object item : collection) {
                    items.add(String.valueOf(item));
                }
                for (int start = 0; start < items.size(); start += CHANNEL_LIMIT) {
                    int end = Math.min(items.size(), start + CHANNEL_LIMIT);
                    ModuleLogger.debug(LOG_CHANNELS + name + " [" + start + "-" + (end - 1)
                            + "] " + String.join(", ", items.subList(start, end)));
                }
                return;
            }
            ModuleLogger.debug(LOG_CHANNELS + name + " " + channelBrief(value));
        } catch (Throwable error) {
            ModuleLogger.debug(LOG_CHANNELS + name + " failed: " + error);
        }
    }

    private static int channelSize(Object value) {
        if (value instanceof java.util.Collection<?> collection) {
            return collection.size();
        }
        if (value instanceof java.util.Map<?, ?> map) {
            return map.size();
        }
        return value == null ? 0 : 1;
    }

    private static String channelBrief(Object value) {
        try {
            if (value instanceof java.util.Collection<?> collection) {
                java.util.StringJoiner joiner = new java.util.StringJoiner(", ");
                int count = 0;
                for (Object item : collection) {
                    if (count++ >= CHANNEL_LIMIT) {
                        joiner.add("...");
                        break;
                    }
                    joiner.add(String.valueOf(item));
                }
                return joiner.toString();
            }
            if (value instanceof java.util.Map<?, ?> map) {
                java.util.StringJoiner joiner = new java.util.StringJoiner(", ");
                int count = 0;
                for (java.util.Map.Entry<?, ?> entry : map.entrySet()) {
                    if (count++ >= CHANNEL_LIMIT) {
                        joiner.add("...");
                        break;
                    }
                    joiner.add(entry.getKey() + "=" + entry.getValue());
                }
                return joiner.toString();
            }
            return String.valueOf(value);
        } catch (Throwable error) {
            return "<" + error + ">";
        }
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
                    ModuleLogger.debug(LOG_INIT_CONTEXT + "ok, " + className);
                }
                return;
            }
            Object context = args[0];
            if (context == null) {
                if (LOGGED.add(className + ":null")) {
                    ModuleLogger.debug(LOG_INIT_CONTEXT + "missing, " + className);
                }
                return;
            }
            values[2] = context;
            if (LOGGED.add(className)) {
                ModuleLogger.debug(LOG_INIT_CONTEXT + "fixed, " + className);
            }
        }
    }

    private static final class InitGate implements HookCallback {

        private static final AtomicInteger CALLS = new AtomicInteger();

        @Override
        public void before(HookParam param) {
            if (CALLS.incrementAndGet() <= 3) {
                ModuleLogger.debug(LOG_INIT_GATE + "forced false");
            }
            param.setResult(Boolean.FALSE);
        }
    }

    private static final class FileRefreshGuard implements HookCallback {

        @Override
        public void before(HookParam param) {
            BASE_REFRESHING.remove();
            BASE_REFRESHING.set(Boolean.TRUE);
        }

        @Override
        public void after(HookParam param) {
            BASE_REFRESHING.remove();
        }
    }

    private static final class BaseDataGuard implements HookCallback {

        private static final AtomicBoolean LOGGED = new AtomicBoolean();

        @Override
        public void after(HookParam param) {
            if (!Boolean.TRUE.equals(BASE_REFRESHING.get())) {
                return;
            }
            BASE_REFRESHING.remove();
            if (param.result() != null) {
                return;
            }
            if (LOGGED.compareAndSet(false, true)) {
                ModuleLogger.debug(LOG_SKIP_REFRESH);
            }
            param.setResult(new java.util.ArrayList<>());
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
                ModuleLogger.debug(message);
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
            ModuleLogger.debug(prefix + value);
        }
    }

    private static final class GetDataLogger implements HookCallback {

        private static final AtomicInteger CALLS = new AtomicInteger();
        private static final int LIMIT = 40;

        private static boolean interesting(HookParam param) {
            return String.valueOf(param.arg(0)).toLowerCase().contains("settings");
        }

        @Override
        public void before(HookParam param) {
            if (!interesting(param) && CALLS.incrementAndGet() > LIMIT) {
                return;
            }
            ModuleLogger.debug("feature getData: " + param.arg(0));
        }

        @Override
        public void after(HookParam param) {
            String channel = String.valueOf(param.arg(0));
            Object result = param.result();
            if (!interesting(param) && CALLS.get() > LIMIT) {
                return;
            }
            int size = result instanceof java.util.Collection<?> values ? values.size() : -1;
            String first = "";
            if (result instanceof java.util.Collection<?> values && !values.isEmpty()) {
                Object value = values.iterator().next();
                first = String.valueOf(value);
                if (first.length() > 120) {
                    first = first.substring(0, 120);
                }
            }
            ModuleLogger.debug("feature getData result: " + channel
                    + " size=" + size + " first=" + first);
        }
    }

    private record PublishGuard(String className) implements HookCallback {

        private static final String TRANSFER_SCENE_COMMAND =
                Secret.of(SecretConstants.X30_ENTRY_REMITTANCE_SCENE);

        @Override
        public void before(HookParam param) {
            String command = String.valueOf(param.arg(0));
            logChannels(param);
            PUBLISH_CMD.set(command);
            PUBLISH_AT.set(SystemClock.elapsedRealtime());
            if (EVENTS.add(command)) {
                ModuleLogger.debug(LOG_EVENT + command + " -> " + className);
            }

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
                ModuleLogger.debug(LOG_PUBLISH + command + " -> " + className);
            }
        }

        @Override
        public void after(HookParam param) {
            String command = PUBLISH_CMD.get();
            Long at = PUBLISH_AT.get();
            PUBLISH_CMD.remove();
            PUBLISH_AT.remove();
            if (command == null || at == null) {
                return;
            }
            long cost = SystemClock.elapsedRealtime() - at;
            if (cost >= SLOW_MS) {
                ModuleLogger.log(LOG_PUBLISH_SLOW + command + " " + cost + "ms -> " + className);
            }
        }
    }
}
