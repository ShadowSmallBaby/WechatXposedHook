import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.XC_MethodHook.MethodHookParam;
import github.shadowbaby.wechatxposed.hook.framework.HookParam;
import github.shadowbaby.wechatxposed.hook.framework.RecordingFramework;
import java.nio.charset.StandardCharsets;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.List;

/**
 * 在同一台 Android 运行时上跑参考 DEX 与本模块源码,用记录调用的替身比较行为。
 *
 * 参考实现是改名前的 APK(直接调 XposedHelpers);本模块现在多了一层
 * framework.HookFramework 适配层(为的是同时支持经典 Xposed 与 LibXposed),
 * 所以两边构造 hook 对象的方式不同,但**注册的目标、回调逻辑与返回值必须一致**。
 * 这里用 RecordingFramework 把适配层的调用转回同一组替身,让记录序列可比。
 */
public final class HookRegression {
    private static final String REBUILT = "github.shadowbaby.wechatxposed.hook.";
    private static int failures;
    private static int checks;

    private static List<String> trace(String type, String method, int component) throws Exception {
        XposedHelpers.calls.clear();
        Class<?> cls = Class.forName(type);
        Object instance = cls.getConstructor(int.class).newInstance(component);
        cls.getMethod(method, ClassLoader.class).invoke(instance, HookRegression.class.getClassLoader());
        return new ArrayList<>(XposedHelpers.calls);
    }

    /** 本模块版本:inject 现在多一个 HookFramework 参数。 */
    private static List<String> traceRebuilt(int component) throws Exception {
        XposedHelpers.calls.clear();
        Class<?> cls = Class.forName(REBUILT + "support.WxComponentHooks");
        Object instance = cls.getConstructor(int.class).newInstance(component);
        cls.getMethod("inject", Class.forName(REBUILT + "framework.HookFramework"), ClassLoader.class)
                .invoke(instance, new RecordingFramework(), HookRegression.class.getClassLoader());
        return new ArrayList<>(XposedHelpers.calls);
    }

    private static String encode(String value) {
        StringBuilder numbers = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            String number = Integer.toString(((value.charAt(i) << 2) - (i << 2) - value.length()) ^ (i * i));
            numbers.append(number.length()).append(number);
        }
        return android.util.Base64.encodeToString(numbers.toString().getBytes(StandardCharsets.UTF_8), 2);
    }

    private static List<String> callback(String type, int mode, Object[] args, String phase,
                                         boolean loader, Throwable error) throws Exception {
        Class<?> cls = Class.forName(type);
        Object instance = loader ? cls.getConstructor(int.class).newInstance(mode)
                : cls.getConstructor(ClassLoader.class, int.class).newInstance(HookRegression.class.getClassLoader(), mode);
        MethodHookParam param = new MethodHookParam();
        param.args = args;
        param.thisObject = "host";
        if (error != null) param.setThrowable(error);
        XposedHelpers.calls.clear();
        try {
            cls.getMethod(phase + "HookedMethod", MethodHookParam.class).invoke(instance, param);
        } catch (InvocationTargetException e) {
            XposedHelpers.calls.add("thrown " + e.getCause().getClass().getName());
        }
        Object result = param.getResult();
        XposedHelpers.calls.add("result " + param.returnEarly + " "
                + (result == null ? "null" : result.getClass().getName() + ":" + result));
        return new ArrayList<>(XposedHelpers.calls);
    }

    /** 本模块版本:回调类现在实现 HookCallback,方法名是 before / after。 */
    private static List<String> callbackRebuilt(String type, int mode, Object[] args, String phase,
                                                boolean loader, Throwable error) throws Exception {
        Class<?> cls = Class.forName(type);
        Object instance = loader
                ? cls.getConstructor(Class.forName(REBUILT + "framework.HookFramework"), int.class)
                        .newInstance(new RecordingFramework(), mode)
                : cls.getConstructor(Class.forName(REBUILT + "framework.HookFramework"),
                        ClassLoader.class, int.class)
                        .newInstance(new RecordingFramework(), HookRegression.class.getClassLoader(), mode);
        RecordingParam param = new RecordingParam();
        param.args = args;
        param.thisObject = "host";
        param.throwable = error;
        XposedHelpers.calls.clear();
        try {
            cls.getMethod(phase, Class.forName(REBUILT + "framework.HookParam")).invoke(instance, param);
        } catch (InvocationTargetException e) {
            XposedHelpers.calls.add("thrown " + e.getCause().getClass().getName());
        }
        XposedHelpers.calls.add("result " + (param.replaced || param.throwable != null) + " "
                + (param.replacement == null ? "null"
                        : param.replacement.getClass().getName() + ":" + param.replacement));
        return new ArrayList<>(XposedHelpers.calls);
    }

    /** 记录 setResult 的 HookParam 替身。 */
    private static final class RecordingParam implements HookParam {
        private Object[] args;
        private Object thisObject;
        private Throwable throwable;
        private boolean replaced;
        private Object replacement;

        @Override public Object[] args() { return args; }
        @Override public Object arg(int index) { return args[index]; }
        @Override public Object thisObject() { return thisObject; }
        @Override public void setResult(Object result) { replaced = true; replacement = result; }
        @Override public boolean hasThrowable() { return throwable != null; }
    }

    private static void check(String label, List<String> original, List<String> rebuilt) {
        checks++;
        if (!original.equals(rebuilt)) {
            failures++;
            System.out.println("DIFF " + label);
            for (String call : original) System.out.println("  ORIGINAL " + call);
            for (String call : rebuilt) System.out.println("  REBUILT  " + call);
        }
    }

    private static void checkCall(String label, int mode, Object... args) throws Exception {
        check(label, callback("c.b", mode, args, "before", false, null),
                callbackRebuilt(REBUILT + "support.CallMethodBypassHook", mode, args, "before", false, null));
    }

    /** 参考实现:整体替换走 replaceHookedMethod。 */
    private static List<String> replacement(String type, int mode) throws Exception {
        XposedHelpers.calls.clear();
        Class<?> cls = Class.forName(type);
        Object instance = cls.getConstructor(int.class).newInstance(mode);
        Object result = cls.getMethod("replaceHookedMethod", MethodHookParam.class)
                .invoke(instance, new MethodHookParam());
        List<String> trace = new ArrayList<>(XposedHelpers.calls);
        trace.add("return " + (result == null ? "null" : result.getClass().getName() + ":" + result));
        return trace;
    }

    /** 本模块版本:整体替换改成 before + setResult。 */
    private static List<String> replacementRebuilt(String type, int mode) throws Exception {
        XposedHelpers.calls.clear();
        Class<?> cls = Class.forName(type);
        Object instance = cls.getConstructor(int.class).newInstance(mode);
        RecordingParam param = new RecordingParam();
        param.args = new Object[0];
        cls.getMethod("before", Class.forName(REBUILT + "framework.HookParam")).invoke(instance, param);
        List<String> trace = new ArrayList<>(XposedHelpers.calls);
        trace.add("return " + (param.replacement == null ? "null"
                : param.replacement.getClass().getName() + ":" + param.replacement));
        return trace;
    }

    private static List<String> startup(String type) throws Exception {
        XposedHelpers.calls.clear();
        de.robv.android.xposed.IXposedHookZygoteInit instance =
                (de.robv.android.xposed.IXposedHookZygoteInit) Class.forName(type).getConstructor().newInstance();
        try {
            instance.initZygote(new de.robv.android.xposed.IXposedHookZygoteInit.StartupParam());
        } catch (Throwable error) { throw new AssertionError(error); }
        return new ArrayList<>(XposedHelpers.calls);
    }

    private static List<String> discovery(boolean original) throws Exception {
        Class<?> registry = Class.forName(original ? "b.a" : REBUILT + "loader.WxComponentRegistry");
        java.lang.reflect.Field field = java.util.Arrays.stream(registry.getDeclaredFields())
                .filter(f -> f.getType() == ArrayList.class).findFirst().get();
        field.setAccessible(true);
        ArrayList entries = (ArrayList) field.get(null);
        entries.clear();
        Class<?> entryType = Class.forName(original ? "c.a" : REBUILT + "support.WxComponentHooks");
        for (int component : new int[]{1, 0, 3, 2}) entries.add(entryType.getConstructor(int.class).newInstance(component));
        Class<?> hookType = Class.forName(original ? "b.c" : REBUILT + "loader.InMemoryDexLoadHook");
        Object hook = original ? hookType.getConstructor(int.class).newInstance(0)
                : hookType.getConstructor(Class.forName(REBUILT + "framework.HookFramework"), int.class)
                        .newInstance(new RecordingFramework(), 0);
        XposedHelpers.calls.clear();
        if (original) {
            MethodHookParam param = new MethodHookParam();
            param.thisObject = HookRegression.class.getClassLoader();
            hookType.getMethod("afterHookedMethod", MethodHookParam.class).invoke(hook, param);
            XposedHelpers.calls.add("remaining " + entries.size());
            // Repeat the notification to verify already registered entries are not hooked twice.
            hookType.getMethod("afterHookedMethod", MethodHookParam.class).invoke(hook, param);
        } else {
            RecordingParam param = new RecordingParam();
            param.args = new Object[0];
            param.thisObject = HookRegression.class.getClassLoader();
            java.lang.reflect.Method after =
                    hookType.getMethod("after", Class.forName(REBUILT + "framework.HookParam"));
            after.invoke(hook, param);
            XposedHelpers.calls.add("remaining " + entries.size());
            after.invoke(hook, param);
        }
        return new ArrayList<>(XposedHelpers.calls);
    }

    public static void main(String[] args) throws Exception {
        Thread.setDefaultUncaughtExceptionHandler((thread, error) -> {
            error.printStackTrace(System.out);
            System.exit(1);
        });
        // Initialize loggers before collecting traces.
        Class.forName("b.b").getMethod("a", java.io.Serializable.class).invoke(null, "warmup");
        Class.forName(REBUILT + "loader.ModuleLogger").getMethod("log", java.io.Serializable.class).invoke(null, "warmup");
        check("startup", startup("wx.module.hook.XposedInit"),
                startup("github.shadowbaby.wechatxposed.hook.XposedInit"));
        check("unrelated loader", discovery(true), discovery(false));
        for (String name : new String[]{"com.fkzhang.wechatxposedhooks.Wrapper.HookWrapper",
                "com.fkzhang.wxfeatures.base.Wrapper.Init", "com.fkzhang.wxfeatures.themes.Wrapper.Init",
                "com.fkzhang.wxfeatures.donation.Wrapper.Init"}) {
            XposedHelpers.availableClasses.add(name);
            check("discovery " + name, discovery(true), discovery(false));
        }
        XposedHelpers.availableClasses.clear();
        for (int component = 0; component < 4; component++) {
            check("component " + component, trace("c.a", "a", component), traceRebuilt(component));
            check("replacement " + component, replacement("c.c", component),
                    replacementRebuilt(REBUILT + "support.VerifierMethodReplacement", component));
        }
        for (int mode = 0; mode < 4; mode++) {
            for (String name : new String[]{"disable", "on_update_check", "process_metadata",
                                           "updateLicense", "delayed_check", "other", ""}) {
                Object[] callArgs = {name};
                check("loader " + mode + " " + name,
                        callback("b.c", mode, callArgs, "before", true, null),
                        callbackRebuilt(REBUILT + "loader.InMemoryDexLoadHook", mode, callArgs, "before", true, null));
            }
        }
        String encoded = encode("fixture:test-user");
        for (int id : new int[]{129, 130, 131, 132, 150, 999}) {
            checkCall("message " + id, 0, id, new Object[]{"verifier6", encoded, "test-user"});
        }
        for (Object lic : new Object[]{null, "", "   ", encoded + "#metadata", 7}) {
            XposedHelpers.license = lic;
            checkCall("context license " + lic, 1, (Object) null);
            checkCall("features license " + lic, 0, 150, new Object[]{6, "test-user"});
        }
        XposedHelpers.license = encoded + "#metadata";
        for (int action : new int[]{0, 2, 4, 6, 8}) {
            for (String user : new String[]{"test-user", "mismatch"}) {
                checkCall("action " + action + " " + user, 0, 150, new Object[]{action, user, encoded});
            }
        }
        checkCall("remote command", 0, 150, new Object[]{2, "test-user", "remote_rp_cmd"});
        checkCall("passthrough", 2, "key", "value");
        for (boolean thrown : new boolean[]{false, true}) {
            for (String key : new String[]{"wxid_fixture", "other"}) {
                Object[] callArgs = {key, "value"};
                Throwable error = thrown ? new IllegalStateException("fixture") : null;
                check("after " + thrown + " " + key,
                        callback("c.b", 2, callArgs, "after", false, error),
                        callbackRebuilt(REBUILT + "support.CallMethodBypassHook", 2, callArgs, "after", false, error));
            }
        }
        System.out.println((failures == 0 ? "PASS: " : "FAIL: ") + checks + " checks, " + failures + " differences");
        if (failures != 0) System.exit(1);
    }
}