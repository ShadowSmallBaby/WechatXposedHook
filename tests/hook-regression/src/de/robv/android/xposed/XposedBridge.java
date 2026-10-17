package de.robv.android.xposed;

import java.lang.reflect.Constructor;
import java.lang.reflect.Executable;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Collections;
import java.util.Set;

public final class XposedBridge {
    public static void log(String message) {}
    public static void log(Throwable error) {}
    public static Set<XC_MethodHook.Unhook> hookAllConstructors(Class<?> type, XC_MethodHook hook) {
        XposedHelpers.calls.add("constructors " + type.getName());
        return Collections.emptySet();
    }
    public static XC_MethodHook.Unhook hookMethod(Method method, XC_MethodHook hook) {
        XposedHelpers.calls.add("hook " + XposedHelpers.lastResolved + "#" + method.getName()
                + "() " + family(hook) + ":" + mode(hook));
        return null;
    }
    public static XC_MethodHook.Unhook hookMethod(Constructor<?> constructor, XC_MethodHook hook) {
        XposedHelpers.calls.add("hook " + XposedHelpers.lastResolved + "#<init>"
                + "() " + family(hook) + ":" + mode(hook));
        return null;
    }
    public static XC_MethodHook.Unhook hookMethod(Executable target, XC_MethodHook hook) {
        if (target instanceof Method) {
            return hookMethod((Method) target, hook);
        }
        return hookMethod((Constructor<?>) target, hook);
    }
    private static String family(XC_MethodHook hook) {
        if (hook instanceof XC_MethodReplacement) {
            return "replacement";
        }
        return "call";
    }
    /** 回调类上的实例 int 字段(就是各 hook 的 mode)。 */
    private static int mode(XC_MethodHook hook) {
        try {
            for (Field field : hook.getClass().getDeclaredFields()) {
                if (field.getType() == int.class && !Modifier.isStatic(field.getModifiers())) {
                    field.setAccessible(true);
                    return field.getInt(hook);
                }
            }
        } catch (ReflectiveOperationException e) {
            throw new AssertionError(e);
        }
        return -1;
    }
}