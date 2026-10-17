package de.robv.android.xposed;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.List;

/** Records registrations without touching any installed app or installing real hooks. */
public final class XposedHelpers {
    public static final List<String> calls = new ArrayList<>();
    public static Object license;
    public static final java.util.Set<String> availableClasses = new java.util.HashSet<>();

    /**
     * 最近一次 findClass 解析出的名字。
     *
     * 替身把每个类都返回 Object.class,所以 findMethodExact / hookMethod 拿不到真实类名;
     * 业务代码总是「先 findClass 再 findMethodExact」,这里记下名字供它们使用,
     * 让记录出来的 hook 目标与参考实现(直接调 findAndHookMethod)可比。
     */
    public static String lastResolved;

    /** 最近一次 findMethodExact 的参数类型名,供 hookMethod 拼出与参考实现一致的签名。 */
    static String lastParameters;

    public static Class<?> findClass(String name, ClassLoader loader) {
        calls.add("find " + name);
        lastResolved = name;
        if (name.equals("java.util.Objects")) return java.util.Objects.class;
        return Object.class;
    }
    public static Class<?> findClassIfExists(String name, ClassLoader loader) {
        calls.add("findIfExists " + name);
        lastResolved = name;
        return availableClasses.contains(name) ? Object.class : null;
    }
    /** 只记下签名,真正的记录由随后的 hookMethod 完成(与 findAndHookMethod 的输出对齐)。 */
    public static Method findMethodExact(Class<?> type, String name, Class<?>... parameterTypes) {
        StringBuilder signature = new StringBuilder();
        for (int i = 0; i < parameterTypes.length; i++) {
            if (i > 0) signature.append(',');
            signature.append(parameterTypes[i].getName());
        }
        lastParameters = signature.toString();
        try {
            return Object.class.getDeclaredMethod("toString");
        } catch (NoSuchMethodException e) {
            throw new AssertionError(e);
        }
    }
    public static XC_MethodHook.Unhook findAndHookMethod(String name, ClassLoader loader,
                                                        String method, Object... args) {
        StringBuilder call = new StringBuilder("hook " + name + "#" + method + "(");
        for (int i = 0; i < args.length - 1; i++) {
            if (i > 0) call.append(',');
            call.append(((Class<?>) args[i]).getName());
        }
        Object callback = args[args.length - 1];
        String family = callback.getClass().getSimpleName();
        if (callback instanceof XC_MethodReplacement) family = "replacement";
        else if (family.equals("c") || family.equals("InMemoryDexLoadHook")) family = "loader";
        else family = "call";
        call.append(") ").append(family).append(':');
        try {
            for (Field field : callback.getClass().getDeclaredFields()) {
                if (field.getType() == int.class && !Modifier.isStatic(field.getModifiers())) {
                    field.setAccessible(true);
                    call.append(field.getInt(callback));
                }
            }
        } catch (ReflectiveOperationException e) { throw new AssertionError(e); }
        calls.add(call.toString());
        return null;
    }
    public static Object callStaticMethod(Class<?> type, String method, Object... args) {
        calls.add("static " + method + " " + java.util.Arrays.toString(args));
        if (type == java.util.Objects.class) return java.util.Objects.equals(args[0], args[1]);
        return "service";
    }
    public static Object callMethod(Object target, String method, Object... args) {
        calls.add("method " + method + " " + java.util.Arrays.toString(args));
        if (args.length == 2 && "LIC".equals(args[0])) return license;
        return null;
    }
}