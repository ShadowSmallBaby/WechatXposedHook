package io.github.shadowbaby.wechatxposed.hook.support.guard;

import io.github.shadowbaby.wechatxposed.shared.hook.HookCallback;
import io.github.shadowbaby.wechatxposed.shared.hook.HookFramework;
import io.github.shadowbaby.wechatxposed.shared.hook.HookParam;
import io.github.shadowbaby.wechatxposed.hook.loader.util.ByteSearch;
import io.github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import io.github.shadowbaby.wechatxposed.hook.loader.util.Secret;
import io.github.shadowbaby.wechatxposed.hook.loader.SecretConstants;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

public final class X3GuardBypass implements HookCallback {

    private static final String UPDATE_CLASS = Secret.of(SecretConstants.X30_UPDATE_CLASS);
    private static final String[] UPDATE_CLASSES = {UPDATE_CLASS};

    private static final String[] PARAMS_APPLY = {
            Secret.of(SecretConstants.X30_PARAMS_APPLY)};
    private static final String[] PARAMS_VERIFY = {
            Secret.of(SecretConstants.X30_PARAMS_VERIFY)};
    private static final String[] VERIFIER_EXPIRED = {
            Secret.of(SecretConstants.X30_VERIFIER_EXPIRED)};
    private static final String[] DOWNLOAD_PARAMS = {
            Secret.of(SecretConstants.X30_DOWNLOAD_PARAMS)};
    private static final String[] DOWNLOAD_CORE = {
            Secret.of(SecretConstants.X30_DOWNLOAD_CORE)};

    private static final String[] SET_DISABLE = {
            Secret.of(SecretConstants.X30_SET_DISABLE)};

    private static final String[] DISABLE_FEATURES = {
            Secret.of(SecretConstants.X30_DISABLE_FEATURES),
            Secret.of(SecretConstants.X30_GUARD_DISABLE_EXTRA)};

    private static final String UI_CLASS = Secret.of(SecretConstants.X30_UI_CLASS);
    private static final String UI_OPTIONS = Secret.of(SecretConstants.X30_UI_OPTIONS);
    private static final String UI_KEYWORDS = Secret.of(SecretConstants.X30_UI_KEYWORDS);
    private static final String UI_GATE = Secret.of(SecretConstants.X30_UI_GATE);
    private static final String UI_ADAPTER = Secret.of(SecretConstants.X30_UI_ADAPTER);
    private static final String ADAPTER_GROUPS = Secret.of(SecretConstants.X30_ADAPTER_GROUPS);
    private static final String ADAPTER_ITEMS = Secret.of(SecretConstants.X30_ADAPTER_ITEMS);
    private static final String LOG_UI = "X3 settings menu forced: ";
    private static final String LOG_EMPTY = "menu empty update blocked: ";
    private static final String LOG_REBUILD = "menu rebuild triggered: ";
    private static final String FEATURE_MANAGER = Secret.of(SecretConstants.X30_FEATURE_MANAGER);
    private static final String FEATURE_UNLOAD = Secret.of(SecretConstants.X30_FEATURE_UNLOAD);

    private static final String FEATURE_UNLOAD_ONE =
            Secret.of(SecretConstants.X30_FEATURE_UNLOAD_ONE);
    private static final String UNLOAD_HANDLER = Secret.of(SecretConstants.X30_UNLOAD_HANDLER);
    private static final String UNLOAD_HANDLER_CALL =
            Secret.of(SecretConstants.X30_UNLOAD_HANDLER_CALL);
    private static final String SETTINGS_WRAPPER =
            Secret.of(SecretConstants.X30_SETTINGS_WRAPPER);
    private static final String SETTINGS_BOOL = Secret.of(SecretConstants.X30_SETTINGS_BOOL);
    private static final String REGISTRATION = Secret.of(SecretConstants.X30_REGISTRATION);
    private static final String LOG_REGISTRATION = "registration forced";
    private static final String LOG_UNLOAD = "feature unload blocked";
    private static final ThreadLocal<Boolean> MENU_BUILDING =
            ThreadLocal.withInitial(() -> Boolean.FALSE);
    private static final String LOG_UNLOAD_CMD = "unloadFeature command blocked";
    private static volatile java.lang.ref.WeakReference<Object> UI_INSTANCE;

    private static final String WRAPPER = Secret.of(SecretConstants.X30_BRIDGE_WRAPPER);
    private static final String WRAPPER_CALL = Secret.of(SecretConstants.X30_BRIDGE_CALL);

    private static final int MSG_PARAM = 130;

    private static final String ACTION_PARAM = Secret.of(SecretConstants.ACTION_PARAM);
    private static final String MIN_SUPPORTED_VERSION =
            Secret.of(SecretConstants.MIN_SUPPORTED_VERSION);

    private static final String DANGEROUS_KEYS =
            Secret.of(SecretConstants.X30_DANGEROUS_KEYS);

    private static final String LOG_HOOKED = "X3 guard hooked: ";
    private static final String LOG_SKIPPED = "X3 params apply skipped: ";
    private static final String LOG_PARAMS = "X3 params: ";
    private static final String BASE_UPDATE_TASK =
            Secret.of(SecretConstants.X30_BASE_UPDATE_TASK);
    private static final String BASE_UPDATE_DONE = Secret.of(SecretConstants.X30_UPDATE_POST);

    private static final String BASE_UPDATE_WORK = Secret.of(SecretConstants.X30_UPDATE_WORK);
    private static final String MENU_HIDDEN_METHOD =
            Secret.of(SecretConstants.X30_MENU_HIDDEN_METHOD);
    private static final String MENU_VISIBLE_METHOD =
            Secret.of(SecretConstants.X30_MENU_VISIBLE_METHOD);

    private static final int LOG_LIMIT = 600;

    private static final Set<String> DONE = ConcurrentHashMap.newKeySet();

    private static final AtomicBoolean LOGGED_PARAMS = new AtomicBoolean();

    private X3GuardBypass() {
    }

    public static boolean matchesClass(HookFramework framework, ClassLoader classLoader) {
        for (String name : UPDATE_CLASSES) {
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
        for (String className : UPDATE_CLASSES) {
            String key = className + "@" + System.identityHashCode(classLoader);
            if (!DONE.add(key)) {
                continue;
            }
            try {
                Class<?> target = Class.forName(className, false, classLoader);
                int count = hookAll(framework, target);
                ModuleLogger.debug(LOG_HOOKED + className + " (" + count + " method(s))");
            } catch (Throwable error) {

                DONE.remove(key);
                ModuleLogger.debug("X3 guard hook failed: " + className + " " + error);
            }
        }
        hookWrapper(framework, classLoader, WRAPPER, WRAPPER_CALL);
        hookBaseUpdateTask(framework, classLoader);
        hookUi(framework, classLoader);

        hookFeatureManager(framework, classLoader);
        hookSettingsWrapper(framework, classLoader);
        hookMenuTrue(framework, classLoader,
                Secret.of(SecretConstants.X30_MENU_CLASS_1),
                Secret.of(SecretConstants.X30_MENU_METHOD_1));
        hookMenuTrue(framework, classLoader,
                Secret.of(SecretConstants.X30_MENU_CLASS_2),
                Secret.of(SecretConstants.X30_MENU_METHOD_2));
        hookMenuTrue(framework, classLoader,
                Secret.of(SecretConstants.X30_MENU_CLASS_3),
                Secret.of(SecretConstants.X30_MENU_METHOD_3));

    }

    private static void hookMenuTrue(HookFramework framework, ClassLoader classLoader,
            String className, String methodName) {
        String key = className + "#" + methodName + "@" + System.identityHashCode(classLoader);
        if (!DONE.add(key)) {
            return;
        }
        try {
            Class<?> target = framework.findClassIfExists(className, classLoader);
            if (target == null) {
                return;
            }
            for (Method method : target.getDeclaredMethods()) {
                if (methodName.equals(method.getName()) && method.getParameterCount() == 0
                        && isBoolean(method.getReturnType())) {
                    framework.hookMethod(method, new MenuBuildTrue());
                    ModuleLogger.debug("menu condition hooked: " + className + "." + methodName);
                }
            }
        } catch (Throwable ignored) {

        }
    }

    private static void hookSettingsWrapper(HookFramework framework, ClassLoader classLoader) {
        String key = SETTINGS_WRAPPER + "@" + System.identityHashCode(classLoader);
        if (!DONE.add(key)) {
            return;
        }
        try {
            Class<?> target = framework.findClassIfExists(SETTINGS_WRAPPER, classLoader);
            if (target == null) {
                return;
            }
            for (Method method : target.getDeclaredMethods()) {
                Class<?>[] types = method.getParameterTypes();
                if (SETTINGS_BOOL.equals(method.getName()) && types.length == 1
                        && types[0] == String.class
                        && isBoolean(method.getReturnType())) {
                    framework.hookMethod(method, new RegistrationGuard());
                    ModuleLogger.debug("settings wrapper hooked: "
                            + SETTINGS_WRAPPER + "." + SETTINGS_BOOL);
                }
            }
        } catch (Throwable ignored) {

        }
    }

    private static void hookFeatureManager(HookFramework framework, ClassLoader classLoader) {
        String key = FEATURE_MANAGER + "@" + System.identityHashCode(classLoader);
        if (!DONE.add(key)) {
            return;
        }
        try {
            Class<?> target = framework.findClassIfExists(FEATURE_MANAGER, classLoader);
            if (target == null) {
                return;
            }
            for (Method method : target.getDeclaredMethods()) {
                String methodName = method.getName();
                Class<?>[] types = method.getParameterTypes();
                if (FEATURE_UNLOAD.equals(methodName) && types.length == 0) {
                    framework.hookMethod(method, new UnloadGuard());
                    ModuleLogger.debug("feature manager hooked: "
                            + FEATURE_MANAGER + "." + FEATURE_UNLOAD);
                } else if (FEATURE_UNLOAD_ONE.equals(methodName) && types.length == 2
                        && types[0] == String.class && types[1] == String.class) {
                    framework.hookMethod(method, new NamedUnloadGuard());
                    ModuleLogger.debug("feature manager hooked: "
                            + FEATURE_MANAGER + "." + FEATURE_UNLOAD_ONE);
                }
            }
            Class<?> handler = framework.findClassIfExists(UNLOAD_HANDLER, classLoader);
            if (handler != null) {
                for (Method method : handler.getDeclaredMethods()) {
                    Class<?>[] types = method.getParameterTypes();
                    if (UNLOAD_HANDLER_CALL.equals(method.getName()) && types.length == 1
                            && types[0] == Object[].class) {
                        framework.hookMethod(method, new UnloadCommandGuard());
                        ModuleLogger.debug("unloadFeature handler hooked: " + UNLOAD_HANDLER);
                    }
                }
            }

        } catch (Throwable ignored) {

        }
    }

    private static void scheduleMenuRebuild(Class<?> uiClass) {
        try {
            Thread thread = new Thread(() -> {
                long[] waits = {12000L};
                for (long wait : waits) {
                    try {
                        Thread.sleep(wait);
                    } catch (InterruptedException interrupted) {
                        return;
                    }
                    try {
                        java.lang.ref.WeakReference<Object> reference = UI_INSTANCE;
                        Object instance = reference == null ? null : reference.get();
                        if (instance == null) {
                            continue;
                        }
                        java.lang.reflect.Method keywords =
                                uiClass.getDeclaredMethod(UI_KEYWORDS);
                        java.lang.reflect.Method options =
                                uiClass.getDeclaredMethod(UI_OPTIONS);
                        keywords.setAccessible(true);
                        options.setAccessible(true);
                        new android.os.Handler(android.os.Looper.getMainLooper()).post(() -> {
                            try {
                                keywords.invoke(instance);
                                options.invoke(instance);
                                ModuleLogger.debug(LOG_REBUILD + "settings");
                            } catch (Throwable error) {
                                ModuleLogger.log(error);
                            }
                        });
                    } catch (Throwable error) {
                        ModuleLogger.log(error);
                    }
                }
            }, "wxh-menu-rebuild");
            thread.setDaemon(true);
            thread.start();
        } catch (Throwable ignored) {

        }
    }

    private static void hookUi(HookFramework framework, ClassLoader classLoader) {
        String key = UI_CLASS + "@" + System.identityHashCode(classLoader);
        if (!DONE.add(key)) {
            return;
        }
        try {
            Class<?> target = framework.findClassIfExists(UI_CLASS, classLoader);
            if (target == null) {
                return;
            }
            int count = 0;
            for (Method method : target.getDeclaredMethods()) {
                String name = method.getName();
                if ((UI_OPTIONS.equals(name) || UI_KEYWORDS.equals(name))
                        && method.getParameterCount() == 0) {
                    framework.hookMethod(method, new UiGate(name));
                    count++;
                }
            }
            Class<?> adapter = framework.findClassIfExists(UI_ADAPTER, classLoader);
            if (adapter != null) {
                for (Method method : adapter.getDeclaredMethods()) {
                    String name = method.getName();
                    if ((ADAPTER_GROUPS.equals(name) || ADAPTER_ITEMS.equals(name))
                            && method.getParameterCount() == 1) {
                        framework.hookMethod(method, new AdapterGuard(name));
                        count++;
                    }
                }
            }
            if (count > 0) {
                ModuleLogger.debug(LOG_UI + UI_CLASS + " (" + count + " method(s))");
                scheduleMenuRebuild(target);
            }
        } catch (Throwable ignored) {

        }
    }

    private static void hookWrapper(HookFramework framework, ClassLoader classLoader,
            String className, String methodName) {
        String key = className + "#" + methodName + "@" + System.identityHashCode(classLoader);
        if (!DONE.add(key)) {
            return;
        }
        try {
            Class<?> target = framework.findClassIfExists(className, classLoader);
            if (target == null) {
                return;
            }
            framework.hookMethod(target, methodName,
                    new Class<?>[]{Integer.TYPE, Object[].class}, new Handshake());
            ModuleLogger.debug("X3 handshake hooked: " + className + "." + methodName);
        } catch (Throwable error) {
            ModuleLogger.log("X3 handshake hook failed: " + className + " " + error);
        }
    }

    private static void hookBaseUpdateTask(HookFramework framework, ClassLoader classLoader) {
        try {
            Class<?> task = framework.findClassIfExists(BASE_UPDATE_TASK, classLoader);
            if (task == null) {
                return;
            }
            for (Method method : task.getDeclaredMethods()) {
                String name = method.getName();
                if (BASE_UPDATE_DONE.equals(name)
                        && method.getParameterCount() == 1) {
                    String key = BASE_UPDATE_TASK + "#" + name
                            + "@" + System.identityHashCode(classLoader);
                    if (!DONE.add(key)) {
                        continue;
                    }
                    framework.hookMethod(method, new NoOp("base update done"));
                    ModuleLogger.debug("base update callback hooked");
                } else if (BASE_UPDATE_WORK.equals(name)
                        && method.getParameterCount() == 1) {

                    String key = BASE_UPDATE_TASK + "#" + name
                            + "@" + System.identityHashCode(classLoader);
                    if (!DONE.add(key)) {
                        continue;
                    }
                    framework.hookMethod(method, new NoOp("base update skipped"));
                    ModuleLogger.debug("base update request skipped");
                }
            }
        } catch (Throwable ignored) {

        }
    }

    private static int hookAll(HookFramework framework, Class<?> target) {
        int count = 0;
        for (Method method : target.getDeclaredMethods()) {
            String name = method.getName();
            if (contains(PARAMS_APPLY, name)) {
                framework.hookMethod(method, new ParamsApply());
                count++;
            } else if (contains(SET_DISABLE, name)) {
                framework.hookMethod(method, new SetDisable());
                count++;
            } else if (Secret.of(SecretConstants.X30_UPDATE_INIT_METHOD).equals(name)
                    && method.getParameterCount() == 1
                    && method.getParameterTypes()[0] == android.content.Context.class) {

                framework.hookMethod(method, new UpdateInitProbe(name));
                count++;
            } else if (contains(PARAMS_VERIFY, name)) {
                framework.hookMethod(method, new ParamsVerify());
                count++;
            } else if (contains(VERIFIER_EXPIRED, name)
                    || contains(DOWNLOAD_PARAMS, name) || contains(DOWNLOAD_CORE, name)
                    || contains(DISABLE_FEATURES, name)) {
                framework.hookMethod(method, new NoOp(name));
                count++;
            } else if (MENU_HIDDEN_METHOD.equals(name)
                    && method.getParameterCount() == 0
                    && method.getReturnType() == Boolean.TYPE) {
                framework.hookMethod(method, new ForcedBool(name, Boolean.FALSE));
                count++;
            } else if (MENU_VISIBLE_METHOD.equals(name)
                    && method.getParameterCount() == 0
                    && method.getReturnType() == Boolean.TYPE) {
                framework.hookMethod(method, new ForcedBool(name, Boolean.TRUE));
                count++;
            }
        }
        return count;
    }

    private static boolean contains(String[] values, String name) {
        for (String value : values) {
            if (value.equals(name)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isBoolean(Class<?> type) {
        return type == Boolean.TYPE || type == Boolean.class;
    }

    private static void setField(Class<?> type, Object target, String name, Object value) {
        for (Class<?> current = type; current != null && current != Object.class;
                current = current.getSuperclass()) {
            try {
                java.lang.reflect.Field field = current.getDeclaredField(name);
                field.setAccessible(true);
                field.set(target, value);
                return;
            } catch (NoSuchFieldException ignored) {

            } catch (Throwable ignored) {
                return;
            }
        }
    }

    public static boolean matchesDex(HookParam param) {
        byte[] needle = UPDATE_CLASS.replace('.', '/').getBytes();
        Object first = param.arg(0);
        if (first instanceof java.nio.ByteBuffer buffer) {
            return ByteSearch.contains(buffer, needle);
        }
        if (first instanceof java.nio.ByteBuffer[] buffers) {
            for (java.nio.ByteBuffer buffer : buffers) {
                if (ByteSearch.contains(buffer, needle)) {
                    return true;
                }
            }
        }
        return false;
    }

    @Override
    public void before(HookParam param) {

    }

    private static final class AdapterGuard implements HookCallback {

        private static final Set<String> LOGGED = ConcurrentHashMap.newKeySet();

        private final String methodName;

        AdapterGuard(String methodName) {
            this.methodName = methodName;
        }

        @Override
        public void before(HookParam param) {
            Object value = param.arg(0);
            boolean empty = value == null
                    || (value instanceof java.util.Collection<?> values && values.isEmpty());
            if (!empty) {
                return;
            }
            if (LOGGED.add(methodName)) {
                ModuleLogger.log(LOG_EMPTY + methodName);
            }
            param.setResult(null);
        }
    }

    private static final class UiGate implements HookCallback {

        private static final Set<String> LOGGED = ConcurrentHashMap.newKeySet();

        private final String methodName;

        UiGate(String methodName) {
            this.methodName = methodName;
        }

        @Override
        public void before(HookParam param) {
            MENU_BUILDING.set(Boolean.TRUE);
            Object self = param.thisObject();
            if (self != null) {
                UI_INSTANCE = new java.lang.ref.WeakReference<>(self);
                setField(self.getClass(), self, UI_GATE, Boolean.TRUE);
            }
            if (LOGGED.add(methodName)) {
                ModuleLogger.debug(LOG_UI + methodName);
            }
        }

        @Override
        public void after(HookParam param) {
            MENU_BUILDING.remove();
        }
    }

    private static final class UnloadGuard implements HookCallback {

        private static final AtomicBoolean LOGGED = new AtomicBoolean();

        @Override
        public void before(HookParam param) {
            if (LOGGED.compareAndSet(false, true)) {
                ModuleLogger.log(LOG_UNLOAD + " from" + stack(new Throwable()));
            }
            param.setResult(null);
        }
    }

    private static String stack(Throwable error) {
        StringBuilder builder = new StringBuilder();
        StackTraceElement[] frames = error.getStackTrace();
        int appended = 0;
        for (StackTraceElement frame : frames) {
            String text = frame.toString();
            if (text.contains("libxposed") || text.contains("LSPosed")
                    || text.contains("XposedBridge") || text.contains("WeXposedHook")) {
                continue;
            }
            builder.append(" <- ").append(text);
            if (++appended >= 10) {
                break;
            }
        }
        return builder.toString();
    }

    private static final class NamedUnloadGuard implements HookCallback {

        private static final Set<String> LOGGED = ConcurrentHashMap.newKeySet();

        @Override
        public void before(HookParam param) {
            String name = String.valueOf(param.arg(0));

            if (!"base".equals(name) && !"donation".equals(name) && !"themes".equals(name)) {
                return;
            }
            if (LOGGED.add(name)) {
                ModuleLogger.debug("feature unload blocked: " + name);
            }
            param.setResult(null);
        }
    }

    private static final class MenuBuildTrue implements HookCallback {

        private static final AtomicBoolean LOGGED = new AtomicBoolean();

        @Override
        public void before(HookParam param) {
            if (!Boolean.TRUE.equals(MENU_BUILDING.get())) {
                return;
            }
            if (LOGGED.compareAndSet(false, true)) {
                ModuleLogger.debug("menu build condition forced");
            }
            param.setResult(Boolean.TRUE);
        }
    }

    private static final class ForcedTrue implements HookCallback {

        private static final Set<String> LOGGED = ConcurrentHashMap.newKeySet();

        private final String name;

        ForcedTrue(String name) {
            this.name = name;
        }

        @Override
        public void before(HookParam param) {
            if (LOGGED.add(name)) {
                ModuleLogger.debug("forced true: " + name);
            }
            param.setResult(Boolean.TRUE);
        }
    }

    private static final class RegistrationGuard implements HookCallback {

        private static final AtomicBoolean LOGGED = new AtomicBoolean();

        @Override
        public void before(HookParam param) {
            if (!REGISTRATION.equals(String.valueOf(param.arg(0)))) {
                return;
            }
            if (LOGGED.compareAndSet(false, true)) {
                ModuleLogger.debug(LOG_REGISTRATION);
            }
            param.setResult(Boolean.TRUE);
        }
    }

    private static final class UnloadCommandGuard implements HookCallback {

        private static final AtomicBoolean LOGGED = new AtomicBoolean();

        @Override
        public void before(HookParam param) {
            if (LOGGED.compareAndSet(false, true)) {
                ModuleLogger.debug(LOG_UNLOAD_CMD);
            }
            param.setResult(null);
        }
    }

    private static final class ParamsVerify implements HookCallback {

        private static final AtomicBoolean LOGGED = new AtomicBoolean();

        @Override
        public void before(HookParam param) {
            if (LOGGED.compareAndSet(false, true)) {
                ModuleLogger.debug("params verify path entered");
            }
        }
    }

    private static final class SetDisable implements HookCallback {

        private static final AtomicBoolean LOGGED = new AtomicBoolean();

        @Override
        public void before(HookParam param) {
            if (LOGGED.compareAndSet(false, true)) {
                ModuleLogger.debug("X3 disable code ignored: " + param.arg(0)
                        + " from" + stack(new Throwable()));
            }
            param.setResult(null);
        }
    }

    private static final class UpdateInitProbe implements HookCallback {

        private static final AtomicBoolean LOGGED = new AtomicBoolean();

        private final String methodName;

        UpdateInitProbe(String methodName) {
            this.methodName = methodName;
        }

        @Override
        public void before(HookParam param) {
            if (LOGGED.compareAndSet(false, true)) {
                ModuleLogger.debug("X3 update init allowed: " + methodName);
            }
        }
    }

    private static final class ForcedBool implements HookCallback {

        private static final Set<String> LOGGED = ConcurrentHashMap.newKeySet();

        private final String methodName;
        private final Boolean value;

        ForcedBool(String methodName, Boolean value) {
            this.methodName = methodName;
            this.value = value;
        }

        @Override
        public void before(HookParam param) {
            if (LOGGED.add(methodName + value)) {
                ModuleLogger.debug("X3 bool forced " + value + ": " + methodName);
            }
            param.setResult(value);
        }
    }

    private static final class NoOp implements HookCallback {

        private final String methodName;

        NoOp(String methodName) {
            this.methodName = methodName;
        }

        @Override
        public void before(HookParam param) {
            ModuleLogger.debug("X3 update blocked: " + methodName);
            param.setResult(null);
        }
    }

    private static final class Handshake implements HookCallback {

        private static final java.util.concurrent.atomic.AtomicInteger CALLS =
                new java.util.concurrent.atomic.AtomicInteger();

        @Override
        public void before(HookParam param) {
            try {
                Object msg = param.arg(0);
                Object[] args = param.arg(1) instanceof Object[] values ? values : null;
                int call = CALLS.incrementAndGet();
                if (call <= 5) {
                    ModuleLogger.debug("X3 wrapper call #" + call + " msg=" + msg
                            + " args=" + java.util.Arrays.toString(args));
                }
                if (!Integer.valueOf(MSG_PARAM).equals(msg) || args == null || args.length == 0) {
                    return;
                }
                if (ACTION_PARAM.equals(String.valueOf(args[0]))) {
                    ModuleLogger.debug("X3 handshake 130 -> " + MIN_SUPPORTED_VERSION
                            + " args=" + java.util.Arrays.toString(args));
                    param.setResult(MIN_SUPPORTED_VERSION);
                }
            } catch (Throwable error) {
                ModuleLogger.log(error);
            }
        }
    }

    private static final class ParamsApply implements HookCallback {

        private static final AtomicBoolean LOGGED_FAILURE = new AtomicBoolean();

        @Override
        public void before(HookParam param) {
            try {
                Object flag = param.arg(0);
                if (!Boolean.TRUE.equals(flag)) {

                    if (LOGGED_FAILURE.compareAndSet(false, true)) {
                        ModuleLogger.debug("X3 params failure skipped");
                    }
                    param.setResult(null);
                    return;
                }
                Object params = param.arg(1);
                byte[] blob = blobOf(params);
                if (LOGGED_PARAMS.compareAndSet(false, true)) {
                    ModuleLogger.debug(LOG_PARAMS + "flag=" + param.arg(0)
                            + " blob=" + (blob == null ? "null" : blob.length));
                }
                if (blob == null) {
                    return;
                }
                String text = new String(blob, StandardCharsets.UTF_8);
                if (LOGGED_PARAMS.compareAndSet(false, true)) {
                    ModuleLogger.debug(LOG_PARAMS + abbreviate(text));
                }
                String danger = dangerousKey(text);
                if (danger != null) {
                    ModuleLogger.debug(LOG_SKIPPED + danger);
                    param.setResult(null);
                }
            } catch (Throwable error) {
                ModuleLogger.log(error);
            }
        }
    }

    private static byte[] blobOf(Object params) {
        if (params == null) {
            return null;
        }
        for (Class<?> type = params.getClass(); type != null && type != Object.class;
                type = type.getSuperclass()) {
            for (Field field : type.getDeclaredFields()) {
                if (field.getType() != byte[].class) {
                    continue;
                }
                try {
                    field.setAccessible(true);
                    Object value = field.get(params);
                    if (value instanceof byte[] bytes) {
                        return bytes;
                    }
                } catch (Throwable ignored) {

                }
            }
        }
        return null;
    }

    private static String dangerousKey(String text) {
        for (String key : DANGEROUS_KEYS.split(",")) {
            if (text.contains("\"" + key + "\"")) {
                return key;
            }
        }
        return null;
    }

    private static String abbreviate(String text) {
        String single = text.replace('\n', ' ').replace('\r', ' ');
        return single.length() <= LOG_LIMIT ? single : single.substring(0, LOG_LIMIT) + "...";
    }
}
