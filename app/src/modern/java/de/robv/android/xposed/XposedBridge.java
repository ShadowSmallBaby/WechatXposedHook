package de.robv.android.xposed;

import github.shadowbaby.wechatxposed.hook.framework.HookFramework;
import java.lang.reflect.Constructor;
import java.lang.reflect.Executable;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Member;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.LinkedHashSet;
import java.util.Set;

/** Legacy XposedBridge 的现代实现。 */
public final class XposedBridge {

    private static volatile HookFramework framework;

    private XposedBridge() {
    }

    public static void init(HookFramework hookFramework) {
        framework = hookFramework;
    }

    static HookFramework framework() {
        HookFramework current = framework;
        if (current == null) {
            throw new IllegalStateException("XposedBridge 未初始化");
        }
        return current;
    }

    public static void log(String message) {
        HookFramework current = framework;
        if (current != null) {
            current.log(message == null ? "null" : message);
        } else {
            android.util.Log.i("WeXposedHook", String.valueOf(message));
        }
    }

    public static void log(Throwable error) {
        HookFramework current = framework;
        if (current != null) {
            current.log(error);
        } else {
            android.util.Log.e("WeXposedHook", String.valueOf(error), error);
        }
    }

    public static Set<XC_MethodHook.Unhook> hookAllMethods(
            Class<?> target, String methodName, XC_MethodHook callback) {
        Set<XC_MethodHook.Unhook> result = new LinkedHashSet<>();
        for (Class<?> type = target; type != null && type != Object.class;
                type = type.getSuperclass()) {
            for (Method method : type.getDeclaredMethods()) {
                if (!method.getName().equals(methodName)
                        || Modifier.isAbstract(method.getModifiers())) {
                    continue;
                }
                result.add(hookMethod(method, callback));
            }
        }
        return result;
    }

    public static Set<XC_MethodHook.Unhook> hookAllConstructors(
            Class<?> target, XC_MethodHook callback) {
        Set<XC_MethodHook.Unhook> result = new LinkedHashSet<>();
        for (Constructor<?> constructor : target.getDeclaredConstructors()) {
            if (!Modifier.isAbstract(constructor.getModifiers())) {
                result.add(hookMethod(constructor, callback));
            }
        }
        return result;
    }

    public static XC_MethodHook.Unhook hookMethod(
            Member method, XC_MethodHook callback) {
        if (!(method instanceof Executable)) {
            throw new IllegalArgumentException("不是可 hook 的成员: " + method);
        }
        XC_MethodHook.Adapter adapter = new XC_MethodHook.Adapter(callback,
                (Executable) method);
        framework().hookMethod((Executable) method, adapter);
        return callback.new Unhook(adapter);
    }

    public static Object invokeOriginalMethod(Member method, Object thisObject,
            Object[] arguments) throws Throwable {
        try {
            ((java.lang.reflect.AccessibleObject) method).setAccessible(true);
            if (method instanceof Method) {
                return ((Method) method).invoke(thisObject, arguments);
            }
            if (method instanceof Constructor) {
                return ((Constructor<?>) method).newInstance(arguments);
            }
            throw new IllegalArgumentException("不支持的成员: " + method);
        } catch (InvocationTargetException error) {
            throw error.getCause();
        }
    }
}
