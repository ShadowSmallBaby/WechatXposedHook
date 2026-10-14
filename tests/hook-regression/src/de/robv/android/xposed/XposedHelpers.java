package de.robv.android.xposed;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.List;

/** Records registrations without touching any installed app or installing real hooks. */
public final class XposedHelpers {
    public static final List<String> calls = new ArrayList<>();
    public static Object license;
    public static final java.util.Set<String> availableClasses = new java.util.HashSet<>();
    public static Class<?> findClass(String name, ClassLoader loader) {
        calls.add("find " + name);
        if (name.equals("java.util.Objects")) return java.util.Objects.class;
        return Object.class;
    }
    public static Class<?> findClassIfExists(String name, ClassLoader loader) {
        calls.add("findIfExists " + name);
        return availableClasses.contains(name) ? Object.class : null;
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
