package github.shadowbaby.wechatxposed.hook.support.guard;

import github.shadowbaby.wechatxposed.hook.BuildConfig;
import github.shadowbaby.wechatxposed.hook.framework.HookCallback;
import github.shadowbaby.wechatxposed.hook.framework.HookFramework;
import github.shadowbaby.wechatxposed.hook.framework.HookParam;
import github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import github.shadowbaby.wechatxposed.hook.loader.util.Secret;
import github.shadowbaby.wechatxposed.hook.loader.SecretConstants;
import java.lang.reflect.Method;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 阻止 X 3.0 在更新或校验失败后关闭功能组件。
 *
 * 组件入口的 finish() 会反注册 hook，禁用事件会把设置项/功能项移出注册表；
 * 这里同时拦截两条路径，并固定 base 组件的 disable_feature_ 开关。
 */
public final class FeatureCloseGuard {

    private static final String[] ENTRY_CLASSES = {
            Secret.of(SecretConstants.X30_ENTRY_BASE),
            Secret.of(SecretConstants.X30_ENTRY_DONATION),
            Secret.of(SecretConstants.X30_ENTRY_THEMES)};

    /** base 功能包的设置包装类。 */
    private static final String BASE_SETTINGS = Secret.of(SecretConstants.X30_BASE_SETTINGS);

    /** base 功能包的注册表/事件总线。 */
    private static final String BASE_REGISTRY = Secret.of(SecretConstants.X30_BASE_REGISTRY);

    /** Wrapper.Init.init 的门禁：返回 true 会直接跳过 Context 保存。 */
    private static final String INIT_GATE_CLASS = Secret.of(SecretConstants.X30_INIT_GATE_CLASS);

    private static final String INIT_GATE_METHOD = Secret.of(SecretConstants.X30_INIT_GATE_METHOD);

    private static final String LOG_INIT_GATE = "feature init gate: ";

    private static final String FINISH = "finish";

    private static final String INIT = "init";

    /** 微X 的 Wrapper.Init 从 objArr[2] 取 Context；为空时菜单构建会 NPE。 */
    private static final String LOG_INIT_CONTEXT = "feature init context: ";

    private static final String PUBLISH_PREFIX = "publish";

    private static final String REGISTRY_REMOVE =
            Secret.of(SecretConstants.X30_REGISTRY_REMOVE);
    private static final String REGISTRY_PUBLISH =
            Secret.of(SecretConstants.X30_REGISTRY_PUBLISH);
    private static final String REGISTRY_GET_DATA =
            Secret.of(SecretConstants.X30_REGISTRY_GET_DATA);

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

    /** 超过这个耗时的 publish 就打一条 log，用来定位主线程卡顿的事件源。 */
    private static final int SLOW_MS = 200;

    private static final Set<String> DONE = ConcurrentHashMap.newKeySet();

    /** 每种事件只打印一次，保证日志量可控又能看到全集。 */
    private static final Set<String> EVENTS = ConcurrentHashMap.newKeySet();

    private static final ThreadLocal<String> PUBLISH_CMD = new ThreadLocal<>();

    private static final ThreadLocal<Long> PUBLISH_AT = new ThreadLocal<>();

    /** 事件频道表只在第一次 publish 时打印一次。 */
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
                    } else if ("getData".equals(methodName)) {
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
                hookInitGate(framework, classLoader);
            } catch (Throwable ignored) {
                // 该类不在这个 loader 里，下一个 loader 再试
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
                } else if (REGISTRY_GET_DATA.equals(methodName) && types.length == 2
                        && types[0] == String.class && BuildConfig.DEBUG) {
                    framework.hookMethod(method, new GetDataLogger());
                    count++;
                }
            }
            ModuleLogger.debug(LOG_HOOKED + BASE_REGISTRY + " (" + count + " method(s))");
        } catch (Throwable ignored) {
            // 忽略，事件仍会从 entry.publish 走
        }
    }

    /** 放行 Wrapper.Init.init：门禁返回 false 才会保存 Context。 */
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
            // 版本不同就算了
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
            // 版本不同就算了，publish 拦截仍然生效
        }
    }

    private static boolean blocked(String command) {
        // 只拦精确的禁用事件，避免误伤正常命令。
        for (String blocked : BLOCKED_COMMANDS) {
            if (blocked.equals(command)) {
                return true;
            }
        }
        return false;
    }

    /**
     * X3 的 Wrapper 暴露了事件频道表；第一次 publish 时把全集打出来，
     * 用来把慢事件名对应到具体功能。只执行一次。
     */
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
            ModuleLogger.log(LOG_CHANNELS + name + " count=" + channelSize(value));
            if (value instanceof java.util.Collection<?> collection) {
                // 逐批打印，单条日志保持在 logcat 的 4KB 限制以内。
                java.util.List<String> items = new java.util.ArrayList<>();
                for (Object item : collection) {
                    items.add(String.valueOf(item));
                }
                for (int start = 0; start < items.size(); start += CHANNEL_LIMIT) {
                    int end = Math.min(items.size(), start + CHANNEL_LIMIT);
                    ModuleLogger.log(LOG_CHANNELS + name + " [" + start + "-" + (end - 1)
                            + "] " + String.join(", ", items.subList(start, end)));
                }
                return;
            }
            ModuleLogger.log(LOG_CHANNELS + name + " " + channelBrief(value));
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

    /**
     * 微X 的 {@code Wrapper.Init.init(Context, Object[])} 把 {@code objArr[2]}
     * 存进静态 Context；首次启动该槽位可能为 null，导致设置菜单构建时
     * {@code Context.getResources()} 空指针。这里用 init 的第一个参数兜底。
     */
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

    /** 门禁为 true 时 Wrapper.Init.init 会在保存 Context 前返回。 */
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
            if (!interesting(param) && CALLS.get() > LIMIT) {
                return;
            }
            Object result = param.result();
            int size = result instanceof java.util.Collection<?> values ? values.size() : -1;
            String first = "";
            if (result instanceof java.util.Collection<?> values && !values.isEmpty()) {
                Object value = values.iterator().next();
                first = String.valueOf(value);
                if (first.length() > 120) {
                    first = first.substring(0, 120);
                }
            }
            ModuleLogger.debug("feature getData result: " + param.arg(0)
                    + " size=" + size + " first=" + first);
        }
    }

    private static final class PublishGuard implements HookCallback {

        /** 伪造转账金额的 hook 命令：回调里会同步读 WCDB，转账详情页会卡住主线程。 */
        private static final String TRANSFER_SCENE_COMMAND = "on_RemittanceDetailUI_onSceneEnd";

        private final String className;

        PublishGuard(String className) {
            this.className = className;
        }

        @Override
        public void before(HookParam param) {
            String command = String.valueOf(param.arg(0));
            logChannels(param);
            PUBLISH_CMD.set(command);
            PUBLISH_AT.set(android.os.SystemClock.elapsedRealtime());
            if (EVENTS.add(command)) {
                ModuleLogger.log(LOG_EVENT + command + " -> " + className);
            }
            // 只拦详情页这一个场景；聊天卡片的金额伪装走消息渲染链路，不受影响。
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
            long cost = android.os.SystemClock.elapsedRealtime() - at;
            if (cost >= SLOW_MS) {
                ModuleLogger.log(LOG_PUBLISH_SLOW + command + " " + cost + "ms -> " + className);
            }
        }
    }
}
