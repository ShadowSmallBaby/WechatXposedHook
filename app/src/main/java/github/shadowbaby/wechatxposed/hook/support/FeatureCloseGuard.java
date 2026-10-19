package github.shadowbaby.wechatxposed.hook.support;

import github.shadowbaby.wechatxposed.hook.BuildConfig;
import github.shadowbaby.wechatxposed.hook.framework.HookCallback;
import github.shadowbaby.wechatxposed.hook.framework.HookFramework;
import github.shadowbaby.wechatxposed.hook.framework.HookParam;
import github.shadowbaby.wechatxposed.hook.loader.ModuleLogger;
import github.shadowbaby.wechatxposed.hook.loader.Secret;
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

    private static final String FINISH = "finish";

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
            Secret.of(SecretConstants.METHOD_UPDATE_LICENSE),
            Secret.of(SecretConstants.METHOD_DELAYED_CHECK)};

    private static final String LOG_HOOKED = "feature close guard: ";
    private static final String LOG_BLOCKED = "feature close blocked: ";
    private static final String LOG_DISABLE_GET = "feature disable getter blocked: ";
    private static final String LOG_PUBLISH_BLOCKED = "feature publish blocked: ";
    private static final String LOG_PUBLISH = "feature publish: ";
    private static final String LOG_REGISTRY_REMOVE = "feature registry remove: ";

    private static final int LOG_LIMIT = 12;

    private static final Set<String> DONE = ConcurrentHashMap.newKeySet();

    /** settings.options 返回给 UI 的列表对象。 */
    private static final Set<Integer> MENU_LISTS = ConcurrentHashMap.newKeySet();

    private static final AtomicInteger PUBLISH_LOGS = new AtomicInteger();

    private static boolean clearGuardInstalled;

    private FeatureCloseGuard() {
    }

    /** 安装一次性的全局防护（ArrayList.clear）。 */
    public static synchronized void install(HookFramework framework) {
        if (clearGuardInstalled) {
            return;
        }
        try {
            Class<?> arrayList = framework.findClassIfExists("java.util.ArrayList", null);
            if (arrayList == null) {
                return;
            }
            framework.hookMethod(arrayList, "clear", new Class<?>[]{}, new MenuClearGuard());
            clearGuardInstalled = true;
            ModuleLogger.log("menu clear guard installed");
            if (BuildConfig.DEBUG) {
                Class<?> url = framework.findClassIfExists("java.net.URL", null);
                if (url != null) {
                    framework.hookMethod(url, "openConnection", new Class<?>[]{}, new UrlLogger());
                    ModuleLogger.log("url probe installed");
                }
            }
        } catch (Throwable error) {
            framework.log(error);
        }
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
                    } else if ("getData".equals(methodName) && BuildConfig.DEBUG) {
                        framework.hookMethod(method, new GetDataLogger());
                        count++;
                    } else if ("init".equals(methodName) && BuildConfig.DEBUG) {
                        framework.hookMethod(method, new InitLogger(name));
                        count++;
                    }
                }
                ModuleLogger.log(LOG_HOOKED + name + " (" + count + " method(s))");
                hookBaseSettings(framework, classLoader);
                hookBaseRegistry(framework, classLoader);
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
            ModuleLogger.log(LOG_HOOKED + BASE_REGISTRY + " (" + count + " method(s))");
        } catch (Throwable ignored) {
            // 忽略，事件仍会从 entry.publish 走
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
                    framework.hookMethod(method, new Noop(LOG_DISABLE_GET, Boolean.FALSE));
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

    private static final class Noop implements HookCallback {

        private final String message;
        private final Object result;

        Noop(String message, Object result) {
            this.message = message;
            this.result = result;
        }

        @Override
        public void before(HookParam param) {
            ModuleLogger.log(message);
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
            ModuleLogger.log(prefix + value);
        }
    }

    private static final class MenuClearGuard implements HookCallback {

        @Override
        public void before(HookParam param) {
            Object self = param.thisObject();
            if (!(self instanceof java.util.List<?> list)) {
                return;
            }
            boolean menu = MENU_LISTS.contains(System.identityHashCode(list));
            if (!menu && list.size() >= 8) {
                String first = String.valueOf(list.get(0));
                menu = first.startsWith("Pair{")
                        && (first.contains("自动回复") || first.contains("打赏")
                        || first.contains("主题") || first.contains("转发")
                        || first.contains("朋友圈") || first.contains("红包"));
            }
            if (!menu) {
                return;
            }
            ModuleLogger.log("menu list clear blocked: size=" + list.size());
            param.setResult(null);
        }
    }

    private static final class UrlLogger implements HookCallback {

        private static final AtomicInteger CALLS = new AtomicInteger();

        @Override
        public void before(HookParam param) {
            String url = String.valueOf(param.thisObject());
            if (url.contains("check.php") || CALLS.incrementAndGet() <= 12) {
                ModuleLogger.log("core url: " + url);
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
            ModuleLogger.log("feature init: " + className);
        }

        @Override
        public void after(HookParam param) {
            ModuleLogger.log("feature init result: " + className + " -> " + param.result());
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
            ModuleLogger.log("feature getData: " + param.arg(0));
        }

        @Override
        public void after(HookParam param) {
            if (!interesting(param) && CALLS.get() > LIMIT) {
                return;
            }
            Object result = param.result();
            int size = result instanceof java.util.Collection<?> values ? values.size() : -1;
            if (result != null && "settings.options".equals(String.valueOf(param.arg(0)))) {
                MENU_LISTS.add(System.identityHashCode(result));
            }
            String first = "";
            if (result instanceof java.util.Collection<?> values && !values.isEmpty()) {
                Object value = values.iterator().next();
                first = String.valueOf(value);
                if (first.length() > 120) {
                    first = first.substring(0, 120);
                }
            }
            ModuleLogger.log("feature getData result: " + param.arg(0)
                    + " size=" + size + " first=" + first);
        }
    }

    private static final class PublishGuard implements HookCallback {

        private final String className;

        PublishGuard(String className) {
            this.className = className;
        }

        @Override
        public void before(HookParam param) {
            String command = String.valueOf(param.arg(0));
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
                ModuleLogger.log(LOG_PUBLISH + command + " -> " + className);
            }
        }
    }
}
