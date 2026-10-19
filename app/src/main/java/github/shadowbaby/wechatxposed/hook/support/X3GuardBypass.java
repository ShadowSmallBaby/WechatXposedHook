package github.shadowbaby.wechatxposed.hook.support;

import github.shadowbaby.wechatxposed.hook.framework.HookCallback;
import github.shadowbaby.wechatxposed.hook.framework.HookFramework;
import github.shadowbaby.wechatxposed.hook.framework.HookParam;
import github.shadowbaby.wechatxposed.hook.loader.ModuleLogger;
import github.shadowbaby.wechatxposed.hook.loader.Secret;
import github.shadowbaby.wechatxposed.hook.loader.SecretConstants;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * X 3.0 的 params / 更新链路防护。
 *
 * 拦截会删除功能包、关闭组件或写入禁用码的 params/更新调用，
 * 并在设置页构建菜单期间维持可用状态。
 */
public final class X3GuardBypass implements HookCallback {

    private static final String UPDATE_CLASS = Secret.of(SecretConstants.X30_UPDATE_CLASS);
    private static final String UPDATE_CLASS_V207 =
            Secret.of(SecretConstants.X30_UPDATE_CLASS_V207);
    private static final String[] UPDATE_CLASSES = {UPDATE_CLASS, UPDATE_CLASS_V207};

    private static final String[] PARAMS_APPLY = {
            Secret.of(SecretConstants.X30_PARAMS_APPLY),
            Secret.of(SecretConstants.X30_PARAMS_APPLY_V207)};
    private static final String[] PARAMS_VERIFY = {
            Secret.of(SecretConstants.X30_PARAMS_VERIFY),
            Secret.of(SecretConstants.X30_PARAMS_VERIFY_V207)};
    private static final String[] VERIFIER_EXPIRED = {
            Secret.of(SecretConstants.X30_VERIFIER_EXPIRED),
            Secret.of(SecretConstants.X30_VERIFIER_EXPIRED_V207)};
    private static final String[] DOWNLOAD_PARAMS = {
            Secret.of(SecretConstants.X30_DOWNLOAD_PARAMS),
            Secret.of(SecretConstants.X30_DOWNLOAD_PARAMS_V207)};
    private static final String[] DOWNLOAD_CORE = {
            Secret.of(SecretConstants.X30_DOWNLOAD_CORE),
            Secret.of(SecretConstants.X30_DOWNLOAD_CORE_V207)};

    private static final String[] SET_DISABLE = {
            Secret.of(SecretConstants.X30_SET_DISABLE),
            Secret.of(SecretConstants.X30_SET_DISABLE_V207)};

    private static final String[] DISABLE_FEATURES = {
            Secret.of(SecretConstants.X30_DISABLE_FEATURES),
            Secret.of(SecretConstants.X30_DISABLE_FEATURES_V207),
            "ʿᴵ"};

    /** 授权/有效期判定的布尔方法。 */
    private static final String[] TRUE_METHODS = {
            "ﾞˈ", "ʻᴵ", "ʻﹳ", "ᵢˎ", "ⁱʻ", "ʼˏ"};

    private static final String LOG_TRUE = "X3 validity forced: ";

    /** 核心设置页的菜单构建入口。 */
    private static final String UI_CLASS = "c.ˏᴵ.ʻᵔ";
    private static final String UI_OPTIONS = "ٴˋ";
    private static final String UI_KEYWORDS = "ᵔˑ";
    private static final String UI_GATE = "ﾞʿ";
    private static final String UI_ADAPTER = "c.ˆﾞ.ˋʼ";
    private static final String ADAPTER_GROUPS = "ﾞʿ";
    private static final String ADAPTER_ITEMS = "ˋʼ";
    private static final String LOG_UI = "X3 settings menu forced: ";
    private static final String LOG_EMPTY = "menu empty update blocked: ";
    private static final String CORE_DATA = "c.ˏᵎ.ٴˑ";
    private static final String CORE_DATA_GET = "ˋʼ";
    private static final String LOG_CORE_DATA = "core getData: ";
    private static final String LOG_REBUILD = "menu rebuild triggered: ";
    private static final String FEATURE_MANAGER = "c.ˎﹳ.ʾᐧ";
    private static final String FEATURE_UNLOAD = "ⁱʽ";
    /** 单个功能卸载入口。 */
    private static final String FEATURE_UNLOAD_ONE = "ʼˋ";
    private static final String FEATURE_LOAD_ONE = "ˏـ";
    private static final String FEATURE_LOAD_CLASS = "ᴵʻ";
    private static final String FEATURE_LOAD_DEX = "ᵎי";
    private static final String UNLOAD_HANDLER = "c.ˎﹳ.ⁱˋ";
    private static final String UNLOAD_HANDLER_CALL = "ⁱˋ";
    private static final String SETTINGS_WRAPPER = "c.ˏᵎ.ʾʻ";
    private static final String SETTINGS_BOOL = "ᐧᵎ";
    private static final String REGISTRATION = "registration";
    private static final String LOG_REGISTRATION = "registration forced";
    private static final String LOG_UNLOAD = "feature unload blocked";
    private static final ThreadLocal<Boolean> MENU_BUILDING =
            ThreadLocal.withInitial(() -> Boolean.FALSE);
    private static final String LOG_UNLOAD_CMD = "unloadFeature command blocked";
    private static volatile java.lang.ref.WeakReference<Object> UI_INSTANCE;
    private static final String PARAMS_FILE_METHOD = "ᵔˋ";
    private static final String LOG_PARAMS_FILE = "params file path: ";

    private static final String WRAPPER = Secret.of(SecretConstants.X30_BRIDGE_WRAPPER);
    private static final String WRAPPER_V207 =
            Secret.of(SecretConstants.X30_BRIDGE_WRAPPER_V207);
    private static final String WRAPPER_CALL = Secret.of(SecretConstants.X30_BRIDGE_CALL);
    private static final String WRAPPER_CALL_V207 =
            Secret.of(SecretConstants.X30_BRIDGE_CALL_V207);

    private static final int MSG_PARAM = 130;

    private static final String ACTION_PARAM = Secret.of(SecretConstants.ACTION_PARAM);
    private static final String MIN_SUPPORTED_VERSION =
            Secret.of(SecretConstants.MIN_SUPPORTED_VERSION);

    private static final String[] DANGEROUS_KEYS = {
            "del_fp", "del_param", "disable_code", "disable_features",
            "disable_settings", "disable_xm", "eject", "force_restart"};

    private static final String LOG_HOOKED = "X3 guard hooked: ";
    private static final String LOG_SKIPPED = "X3 params apply skipped: ";
    private static final String LOG_PARAMS = "X3 params: ";

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
                // 继续看下一个名字
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
                ModuleLogger.log(LOG_HOOKED + className + " (" + count + " method(s))");
            } catch (Throwable error) {
                ModuleLogger.log("X3 guard hook failed: " + className + " " + error);
            }
        }
        hookWrapper(framework, classLoader, WRAPPER, WRAPPER_CALL);
        hookWrapper(framework, classLoader, WRAPPER_V207, WRAPPER_CALL_V207);
        hookUi(framework, classLoader);
        hookCoreData(framework, classLoader);
        hookFeatureManager(framework, classLoader);
        hookSettingsWrapper(framework, classLoader);
        hookMenuTrue(framework, classLoader, "c.ˏᵎ.ˑᵎ", "ᴵـ");
        hookMenuTrue(framework, classLoader, "c.ˏᵎ.ʾﹳ", "יʾ");
        hookMenuTrue(framework, classLoader, "c.ˏᵎ.ˎ", "ʾʽ");
        hookMenuResource(framework, classLoader);
        hookManagerProbe(framework, classLoader);
    }

    /** 记录管理器布尔查询的返回值。 */
    private static void hookManagerProbe(HookFramework framework, ClassLoader classLoader) {
        String key = "manager-probe@" + System.identityHashCode(classLoader);
        if (!DONE.add(key)) {
            return;
        }
        try {
            Class<?> target = framework.findClassIfExists(FEATURE_MANAGER, classLoader);
            if (target == null) {
                return;
            }
            int count = 0;
            for (Method method : target.getDeclaredMethods()) {
                Class<?>[] types = method.getParameterTypes();
                if (types.length >= 1 && types.length <= 2 && types[0] == String.class
                        && isBoolean(method.getReturnType())) {
                    try {
                        framework.hookMethod(method, new ManagerProbe(method.getName()));
                        count++;
                    } catch (Throwable error) {
                        ModuleLogger.log(error);
                    }
                }
            }
            ModuleLogger.log("manager probe hooked: " + count + " method(s)");
        } catch (Throwable ignored) {
            // 忽略
        }
    }

    /** 为菜单资源提供默认文案。 */
    private static void hookMenuResource(HookFramework framework, ClassLoader classLoader) {
        String key = "resource@" + System.identityHashCode(classLoader);
        if (!DONE.add(key)) {
            return;
        }
        try {
            Class<?> target = framework.findClassIfExists("c.ˊﹶ.ˉˎ", classLoader);
            if (target == null) {
                return;
            }
            for (Method method : target.getDeclaredMethods()) {
                Class<?>[] types = method.getParameterTypes();
                if ("יʾ".equals(method.getName()) && types.length == 1
                        && types[0] == String.class && method.getReturnType() == String.class) {
                    framework.hookMethod(method, new MenuResourceGuard());
                    ModuleLogger.log("menu resource hooked");
                }
            }
        } catch (Throwable ignored) {
            // 忽略
        }
    }

    /** 只在设置页构建菜单期间将条件置真。 */
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
                    ModuleLogger.log("menu condition hooked: " + className + "." + methodName);
                }
            }
        } catch (Throwable ignored) {
            // 忽略
        }
    }

    private static void hookForceTrue(HookFramework framework, ClassLoader classLoader,
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
                    framework.hookMethod(method, new ForcedTrue(methodName));
                }
            }
        } catch (Throwable ignored) {
            // 忽略
        }
    }

    private static void hookBoolProbe(HookFramework framework, ClassLoader classLoader,
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
                    framework.hookMethod(method, new BoolProbe(methodName));
                }
            }
        } catch (Throwable ignored) {
            // 忽略
        }
    }

    /** 固定 registration 标志。 */
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
                    ModuleLogger.log("settings wrapper hooked: "
                            + SETTINGS_WRAPPER + "." + SETTINGS_BOOL);
                }
            }
        } catch (Throwable ignored) {
            // 版本不同时跳过
        }
    }

    /** 保护功能注册表，避免停用流程清空菜单数据。 */
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
                    ModuleLogger.log("feature manager hooked: "
                            + FEATURE_MANAGER + "." + FEATURE_UNLOAD);
                } else if (FEATURE_UNLOAD_ONE.equals(methodName) && types.length == 2
                        && types[0] == String.class && types[1] == String.class) {
                    // 拦截单功能卸载，避免捐赠/基础组件被移出注册表。
                    framework.hookMethod(method, new NamedUnloadGuard());
                    ModuleLogger.log("feature manager hooked: "
                            + FEATURE_MANAGER + "." + FEATURE_UNLOAD_ONE);
                } else if (FEATURE_LOAD_ONE.equals(methodName) && types.length == 1
                        && types[0] == String.class) {
                    framework.hookMethod(method, new LoadProbe("load"));
                } else if (FEATURE_LOAD_CLASS.equals(methodName) && types.length == 1
                        && types[0] == String.class) {
                    framework.hookMethod(method, new LoadProbe("class"));
                } else if (FEATURE_LOAD_DEX.equals(methodName) && types.length == 2
                        && types[0] == java.io.File.class && types[1] == String.class) {
                    framework.hookMethod(method, new LoadProbe("dex"));
                }
            }
            Class<?> handler = framework.findClassIfExists(UNLOAD_HANDLER, classLoader);
            if (handler != null) {
                for (Method method : handler.getDeclaredMethods()) {
                    Class<?>[] types = method.getParameterTypes();
                    if (UNLOAD_HANDLER_CALL.equals(method.getName()) && types.length == 1
                            && types[0] == Object[].class) {
                        framework.hookMethod(method, new UnloadCommandGuard());
                        ModuleLogger.log("unloadFeature handler hooked: " + UNLOAD_HANDLER);
                    }
                }
            }
            // 观察组件自身的卸载入口。
            Class<?> feature = framework.findClassIfExists("c.ˎﹳ.ᵢʼ", classLoader);
            if (feature != null) {
                for (Method method : feature.getDeclaredMethods()) {
                    if (UNLOAD_HANDLER_CALL.equals(method.getName())
                            && method.getParameterCount() == 0) {
                        framework.hookMethod(method, new ComponentUnloadProbe());
                    }
                }
            }
        } catch (Throwable ignored) {
            // 类名随版本变化时跳过
        }
    }

    /**
     * 组件加载完成后主动重建一次菜单。
     */
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
                                uiClass.getDeclaredMethod("ᵔˑ");
                        java.lang.reflect.Method options =
                                uiClass.getDeclaredMethod("ٴˋ");
                        keywords.setAccessible(true);
                        options.setAccessible(true);
                        new android.os.Handler(android.os.Looper.getMainLooper()).post(() -> {
                            try {
                                keywords.invoke(instance);
                                options.invoke(instance);
                                ModuleLogger.log(LOG_REBUILD + "settings");
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
            // 重建失败不影响主流程
        }
    }

    private static void scheduleDataProbe(Class<?> target) {
        try {
            Thread thread = new Thread(() -> {
                try {
                    Thread.sleep(12000);
                    Object instance = target.getDeclaredMethod("ˊﹶ").invoke(null);
                    java.lang.reflect.Method get =
                            target.getDeclaredMethod("ˋʼ", String.class, Object[].class);
                    get.setAccessible(true);
                    for (String channel : new String[]{"settings.options", "settings.keywords"}) {
                        Object result = get.invoke(instance, channel, new Object[0]);
                        int size = result instanceof java.util.Collection<?> values
                                ? values.size() : -1;
                        ModuleLogger.log("core data probe: " + channel + " size=" + size);
                    }
                } catch (Throwable error) {
                    ModuleLogger.log(error);
                }
            }, "wxh-data-probe");
            thread.setDaemon(true);
            thread.start();
        } catch (Throwable ignored) {
            // 探测失败不影响主流程
        }
    }

    private static void hookCoreData(HookFramework framework, ClassLoader classLoader) {
        String key = CORE_DATA + "@" + System.identityHashCode(classLoader);
        if (!DONE.add(key)) {
            return;
        }
        try {
            Class<?> target = framework.findClassIfExists(CORE_DATA, classLoader);
            if (target == null) {
                return;
            }
            for (Method method : target.getDeclaredMethods()) {
                Class<?>[] types = method.getParameterTypes();
                if (CORE_DATA_GET.equals(method.getName()) && types.length == 2
                        && types[0] == String.class) {
                    framework.hookMethod(method, new CoreDataLogger());
                    ModuleLogger.log(LOG_CORE_DATA + "hook installed");
                    scheduleDataProbe(target);
                    return;
                }
            }
        } catch (Throwable ignored) {
            // 忽略
        }
    }

    /** 维持设置页的菜单构建开关。 */
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
                ModuleLogger.log(LOG_UI + UI_CLASS + " (" + count + " method(s))");
                scheduleMenuRebuild(target);
            }
        } catch (Throwable ignored) {
            // 类名随版本变化时跳过
        }
    }

    /**
     * 在包装层应答 130 握手。
     */
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
            ModuleLogger.log("X3 handshake hooked: " + className + "." + methodName);
        } catch (Throwable error) {
            ModuleLogger.log("X3 handshake hook failed: " + className + " " + error);
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
            } else if ("יˑ".equals(name) && method.getParameterCount() == 1
                    && method.getParameterTypes()[0] == android.content.Context.class) {
                framework.hookMethod(method, new NoOp(name));
                count++;
            } else if (PARAMS_FILE_METHOD.equals(name)
                    && method.getParameterCount() == 0
                    && method.getReturnType() == java.io.File.class) {
                framework.hookMethod(method, new ParamsFileLogger());
                count++;
            } else if (contains(PARAMS_VERIFY, name)) {
                framework.hookMethod(method, new ParamsVerify());
                count++;
            } else if (contains(VERIFIER_EXPIRED, name)
                    || contains(DOWNLOAD_PARAMS, name) || contains(DOWNLOAD_CORE, name)
                    || contains(DISABLE_FEATURES, name)) {
                framework.hookMethod(method, new NoOp(name));
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

    /** 写入成功标志位与禁用码。 */
    private static void forceFlags(Object target) {
        if (target == null) {
            return;
        }
        Class<?> type = target.getClass();
        setField(type, target, "ᵢʼ", Boolean.TRUE);
        setField(type, target, "ⁱי", Boolean.TRUE);
        setField(type, target, "ʿᵢ", Boolean.TRUE);
        setField(type, target, "ˏـ", Boolean.TRUE);
        setField(type, target, "ˉˆ", 0);
        setField(type, target, "ᵎי", 0);
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
                // 继续向父类找
            } catch (Throwable ignored) {
                return;
            }
        }
    }

    public static boolean matchesDex(HookParam param) {
        byte[] needle = UPDATE_CLASS.replace('.', '/').getBytes();
        Object first = param.arg(0);
        if (first instanceof java.nio.ByteBuffer buffer) {
            return contains(buffer, needle) || contains(buffer, UPDATE_CLASS_V207.getBytes());
        }
        if (first instanceof java.nio.ByteBuffer[] buffers) {
            for (java.nio.ByteBuffer buffer : buffers) {
                if (contains(buffer, needle) || contains(buffer, UPDATE_CLASS_V207.getBytes())) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean contains(java.nio.ByteBuffer source, byte[] needle) {
        try {
            java.nio.ByteBuffer buffer = source.duplicate();
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

    @Override
    public void before(HookParam param) {
        // 仅作为占位，真正的回调在下面两个内部类
    }

    private static final class ParamsFileLogger implements HookCallback {

        private static final AtomicBoolean LOGGED = new AtomicBoolean();

        @Override
        public void before(HookParam param) {
            // 只在 after 读返回值
        }

        @Override
        public void after(HookParam param) {
            if (!LOGGED.compareAndSet(false, true)) {
                return;
            }
            Object result = param.result();
            if (result instanceof java.io.File file) {
                ModuleLogger.log(LOG_PARAMS_FILE + file.getAbsolutePath()
                        + " exists=" + file.exists() + " len=" + file.length());
            } else {
                ModuleLogger.log(LOG_PARAMS_FILE + String.valueOf(result));
            }
        }
    }

    private static final class CoreDataLogger implements HookCallback {

        private static final java.util.concurrent.atomic.AtomicInteger CALLS =
                new java.util.concurrent.atomic.AtomicInteger();

        @Override
        public void before(HookParam param) {
            String channel = String.valueOf(param.arg(0));
            if (channel.contains("settings") || CALLS.incrementAndGet() <= 20) {
                ModuleLogger.log(LOG_CORE_DATA + channel);
            }
        }

        @Override
        public void after(HookParam param) {
            String channel = String.valueOf(param.arg(0));
            if (!channel.contains("settings") && CALLS.get() > 20) {
                return;
            }
            Object result = param.result();
            int size = result instanceof java.util.Collection<?> values ? values.size() : -1;
            ModuleLogger.log(LOG_CORE_DATA + "result: " + channel + " size=" + size);
        }
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
                ModuleLogger.log(LOG_UI + methodName);
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

    /** 拼一段调用栈用于日志。 */
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

    /** 拦截按名字卸载单个功能。 */
    private static final class NamedUnloadGuard implements HookCallback {

        private static final Set<String> LOGGED = ConcurrentHashMap.newKeySet();

        @Override
        public void before(HookParam param) {
            String name = String.valueOf(param.arg(0));
            // 只保护三个内置功能包；其它功能（比如用户自己关掉的）照常卸载。
            if (!"base".equals(name) && !"donation".equals(name) && !"themes".equals(name)) {
                return;
            }
            if (LOGGED.add(name)) {
                ModuleLogger.log("feature unload blocked: " + name);
            }
            param.setResult(null);
        }
    }

    /** 观察组件自身的卸载调用。 */
    private static final class ComponentUnloadProbe implements HookCallback {

        private static final Set<Integer> LOGGED = ConcurrentHashMap.newKeySet();

        @Override
        public void before(HookParam param) {
            Object self = param.thisObject();
            int key = self == null ? 0 : System.identityHashCode(self);
            if (!LOGGED.add(key)) {
                return;
            }
            String name = "?";
            if (self != null) {
                try {
                    Method method = self.getClass().getDeclaredMethod("ﾞʿ");
                    method.setAccessible(true);
                    name = String.valueOf(method.invoke(self));
                } catch (Throwable ignored) {
                    // 名字取不到就只记栈
                }
            }
            ModuleLogger.log("component unload: " + name + " from" + stack(new Throwable()));
        }
    }

    /** 记录功能加载链路的名字与结果。 */
    private static final class LoadProbe implements HookCallback {

        private final String tag;
        private final ThreadLocal<String> subject = new ThreadLocal<>();

        LoadProbe(String tag) {
            this.tag = tag;
        }

        @Override
        public void before(HookParam param) {
            subject.set("dex".equals(tag)
                    ? String.valueOf(param.arg(1))
                    : String.valueOf(param.arg(0)));
        }

        @Override
        public void after(HookParam param) {
            String name = subject.get();
            subject.remove();
            if (name == null) {
                return;
            }
            if ("load".equals(tag)) {
                ModuleLogger.log("feature load: " + name);
                return;
            }
            Object result = param.result();
            String value;
            if (result == null) {
                value = "null";
            } else if (result instanceof Class<?> type) {
                value = type.getName();
            } else {
                value = result.getClass().getName();
            }
            ModuleLogger.log("feature " + tag + ": " + name + " -> " + value);
        }
    }

    private static final class ManagerProbe implements HookCallback {

        private static final java.util.concurrent.ConcurrentHashMap<String,
                java.util.concurrent.atomic.AtomicInteger> COUNTS =
                new java.util.concurrent.ConcurrentHashMap<>();

        private final String name;

        ManagerProbe(String name) {
            this.name = name;
        }

        @Override
        public void before(HookParam param) {
            // 只看 after
        }

        @Override
        public void after(HookParam param) {
            java.util.concurrent.atomic.AtomicInteger counter =
                    COUNTS.computeIfAbsent(name,
                            ignored -> new java.util.concurrent.atomic.AtomicInteger());
            if (counter.incrementAndGet() > 8) {
                return;
            }
            String args = java.util.Arrays.toString(param.args());
            if (args.length() > 120) {
                args = args.substring(0, 120);
            }
            ModuleLogger.log("manager probe: " + name + args + " = " + param.result());
        }
    }

    private static final class MenuResourceGuard implements HookCallback {

        private static final AtomicBoolean LOGGED = new AtomicBoolean();

        @Override
        public void before(HookParam param) {
            if (!Boolean.TRUE.equals(MENU_BUILDING.get())) {
                return;
            }
            String key = String.valueOf(param.arg(0));
            String value = null;
            if ("appname".equals(key)) {
                value = "微X模块";
            } else if ("donate_desc".equals(key)) {
                value = "打赏";
            } else if ("donate_desc_pay".equals(key)) {
                value = "支持开发";
            } else if ("donate_desc2".equals(key)) {
                value = "感谢支持";
            }
            if (value == null) {
                return;
            }
            if (LOGGED.compareAndSet(false, true)) {
                ModuleLogger.log("menu resource default: " + key);
            }
            param.setResult(value);
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
                ModuleLogger.log("menu build condition forced");
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
                ModuleLogger.log("forced true: " + name);
            }
            param.setResult(Boolean.TRUE);
        }
    }

    private static final class BoolProbe implements HookCallback {

        private static final Set<String> LOGGED = ConcurrentHashMap.newKeySet();

        private final String name;

        BoolProbe(String name) {
            this.name = name;
        }

        @Override
        public void before(HookParam param) {
            // 只看 after 的返回值
        }

        @Override
        public void after(HookParam param) {
            if (LOGGED.add(name)) {
                ModuleLogger.log("bool probe: " + name + " = " + param.result());
            }
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
                ModuleLogger.log(LOG_REGISTRATION);
            }
            param.setResult(Boolean.TRUE);
        }
    }

    private static final class UnloadCommandGuard implements HookCallback {

        private static final AtomicBoolean LOGGED = new AtomicBoolean();

        @Override
        public void before(HookParam param) {
            if (LOGGED.compareAndSet(false, true)) {
                ModuleLogger.log(LOG_UNLOAD_CMD);
            }
            param.setResult(null);
        }
    }

    private static final class ParamsVerify implements HookCallback {

        private static final AtomicBoolean LOGGED = new AtomicBoolean();

        @Override
        public void before(HookParam param) {
            if (LOGGED.compareAndSet(false, true)) {
                ModuleLogger.log("params verify path entered");
            }
        }
    }

    private static final class SetValid implements HookCallback {

        private static final AtomicBoolean LOGGED = new AtomicBoolean();

        @Override
        public void before(HookParam param) {
            if (!Boolean.FALSE.equals(param.arg(0))) {
                return;
            }
            Object self = param.thisObject();
            forceFlags(self);
            if (self != null) {
                setField(self.getClass(), self, "ˏـ", Boolean.TRUE);
            }
            if (LOGGED.compareAndSet(false, true)) {
                ModuleLogger.log("X3 invalid state forced valid");
            }
            param.setResult(null);
        }
    }

    private static final class ForceFlags implements HookCallback {

        private static final AtomicBoolean LOGGED = new AtomicBoolean();

        @Override
        public void before(HookParam param) {
            if (LOGGED.compareAndSet(false, true)) {
                ModuleLogger.log("X3 success flags forced");
            }
            param.setResult(null);
        }
    }

    private static final class TrueValue implements HookCallback {

        private static final Set<String> LOGGED = ConcurrentHashMap.newKeySet();

        private final String methodName;

        TrueValue(String methodName) {
            this.methodName = methodName;
        }

        @Override
        public void before(HookParam param) {
            if (LOGGED.add(methodName)) {
                ModuleLogger.log(LOG_TRUE + methodName);
            }
            param.setResult(Boolean.TRUE);
        }
    }

    private static final class SetDisable implements HookCallback {

        private static final AtomicBoolean LOGGED = new AtomicBoolean();

        @Override
        public void before(HookParam param) {
            if (LOGGED.compareAndSet(false, true)) {
                ModuleLogger.log("X3 disable code ignored: " + param.arg(0)
                        + " from" + stack(new Throwable()));
            }
            param.setResult(null);
        }
    }

    private static final class NoOp implements HookCallback {

        private final String methodName;

        NoOp(String methodName) {
            this.methodName = methodName;
        }

        @Override
        public void before(HookParam param) {
            ModuleLogger.log("X3 update blocked: " + methodName);
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
                    ModuleLogger.log("X3 wrapper call #" + call + " msg=" + msg
                            + " args=" + java.util.Arrays.toString(args));
                }
                if (!Integer.valueOf(MSG_PARAM).equals(msg) || args == null || args.length == 0) {
                    return;
                }
                if (ACTION_PARAM.equals(String.valueOf(args[0]))) {
                    ModuleLogger.log("X3 handshake 130 -> " + MIN_SUPPORTED_VERSION
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
                    // params 失败回调：跳过禁用功能/关闭组件的逻辑。
                    if (LOGGED_FAILURE.compareAndSet(false, true)) {
                        ModuleLogger.log("X3 params failure skipped");
                    }
                    param.setResult(null);
                    return;
                }
                Object params = param.arg(1);
                byte[] blob = blobOf(params);
                if (LOGGED_PARAMS.compareAndSet(false, true)) {
                    ModuleLogger.log(LOG_PARAMS + "flag=" + param.arg(0)
                            + " blob=" + (blob == null ? "null" : blob.length));
                }
                if (blob == null) {
                    return;
                }
                String text = new String(blob, StandardCharsets.UTF_8);
                if (LOGGED_PARAMS.compareAndSet(false, true)) {
                    ModuleLogger.log(LOG_PARAMS + abbreviate(text));
                }
                String danger = dangerousKey(text);
                if (danger != null) {
                    ModuleLogger.log(LOG_SKIPPED + danger);
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
                    // 继续找下一个字段
                }
            }
        }
        return null;
    }

    private static String dangerousKey(String text) {
        for (String key : DANGEROUS_KEYS) {
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
