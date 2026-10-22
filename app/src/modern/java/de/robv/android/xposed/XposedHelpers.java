package de.robv.android.xposed;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Collections;
import java.util.Map;
import java.util.WeakHashMap;

/** Legacy XposedHelpers 的最小现代实现。 */
public final class XposedHelpers {

    private static final Map<Object, Map<String, Object>> EXTRA =
            Collections.synchronizedMap(new WeakHashMap<>());

    private XposedHelpers() {
    }

    public static Class<?> findClass(String name, ClassLoader loader) {
        try {
            return Class.forName(name, false, loader);
        } catch (Throwable error) {
            throw new NoClassDefFoundError(name);
        }
    }

    public static Class<?> findClassIfExists(String name, ClassLoader loader) {
        try {
            return Class.forName(name, false, loader);
        } catch (Throwable error) {
            return null;
        }
    }

    public static Object callMethod(Object target, String name, Object... args) {
        if (target == null) {
            throw new NullPointerException("target == null: " + name);
        }
        Method method = findMethodBestMatch(target.getClass(), name, types(args));
        return invoke(method, target, args);
    }

    public static Object callStaticMethod(Class<?> target, String name, Object... args) {
        Method method = findMethodBestMatch(target, name, types(args));
        return invoke(method, null, args);
    }

    public static Method findMethodBestMatch(Class<?> target, String name,
            Class<?>... parameterTypes) {
        Method method = findMethod(target, name, parameterTypes);
        if (method != null) {
            method.setAccessible(true);
            return method;
        }
        throw new NoSuchMethodError(target.getName() + "." + name);
    }

    private static Method findMethod(Class<?> target, String name,
            Class<?>... parameterTypes) {
        for (Class<?> type = target; type != null; type = type.getSuperclass()) {
            for (Method method : type.getDeclaredMethods()) {
                if (!method.getName().equals(name)
                        || !matches(method.getParameterTypes(), parameterTypes)) {
                    continue;
                }
                return method;
            }
            for (Class<?> iface : type.getInterfaces()) {
                Method method = findMethod(iface, name, parameterTypes);
                if (method != null) {
                    return method;
                }
            }
        }
        return null;
    }

    public static Constructor<?> findConstructorBestMatch(Class<?> target,
            Class<?>... parameterTypes) {
        for (Constructor<?> constructor : target.getDeclaredConstructors()) {
            if (matches(constructor.getParameterTypes(), parameterTypes)) {
                constructor.setAccessible(true);
                return constructor;
            }
        }
        throw new NoSuchMethodError(target.getName() + ".<init>");
    }

    public static Object newInstance(Class<?> target, Object... args) {
        Constructor<?> constructor = findConstructorBestMatch(target, types(args));
        try {
            return constructor.newInstance(args);
        } catch (InvocationTargetException error) {
            throw new IllegalStateException(error.getCause());
        } catch (Throwable error) {
            throw new IllegalStateException(error);
        }
    }

    public static Object getObjectField(Object target, String name) {
        try {
            return getField(target.getClass(), name).get(target);
        } catch (IllegalAccessException error) {
            throw new IllegalStateException(error);
        }
    }

    public static Object getStaticObjectField(Class<?> target, String name) {
        try {
            return getField(target, name).get(null);
        } catch (IllegalAccessException error) {
            throw new IllegalStateException(error);
        }
    }

    public static void setObjectField(Object target, String name, Object value) {
        try {
            getField(target.getClass(), name).set(target, value);
        } catch (IllegalAccessException error) {
            throw new IllegalStateException(error);
        }
    }

    public static Object getAdditionalInstanceField(Object target, String key) {
        Map<String, Object> fields = EXTRA.get(target);
        return fields == null ? null : fields.get(key);
    }

    public static Object setAdditionalInstanceField(Object target, String key,
            Object value) {
        Map<String, Object> fields = EXTRA.get(target);
        if (fields == null) {
            fields = new WeakHashMap<>();
            EXTRA.put(target, fields);
        }
        return fields.put(key, value);
    }

    public static XC_MethodHook.Unhook findAndHookMethod(Class<?> target,
            String name, Object... extras) {
        Object[] parsed = parseHookExtras(extras);
        Class<?>[] parameterTypes = (Class<?>[]) parsed[0];
        XC_MethodHook callback = (XC_MethodHook) parsed[1];
        Method method = findMethodBestMatch(target, name, parameterTypes);
        return XposedBridge.hookMethod(method, callback);
    }

    public static XC_MethodHook.Unhook findAndHookMethod(String className,
            ClassLoader loader, String name, Object... extras) {
        return findAndHookMethod(findClass(className, loader), name, extras);
    }

    private static Object[] parseHookExtras(Object[] extras) {
        if (extras == null || extras.length == 0
                || !(extras[extras.length - 1] instanceof XC_MethodHook)) {
            throw new IllegalArgumentException("findAndHookMethod 缺少 XC_MethodHook");
        }
        Class<?>[] parameterTypes = new Class<?>[extras.length - 1];
        for (int index = 0; index < parameterTypes.length; index++) {
            if (!(extras[index] instanceof Class<?>)) {
                throw new IllegalArgumentException("参数类型不是 Class: " + extras[index]);
            }
            parameterTypes[index] = (Class<?>) extras[index];
        }
        return new Object[]{parameterTypes, extras[extras.length - 1]};
    }

    private static Field getField(Class<?> target, String name) {
        for (Class<?> type = target; type != null; type = type.getSuperclass()) {
            try {
                Field field = type.getDeclaredField(name);
                field.setAccessible(true);
                return field;
            } catch (NoSuchFieldException ignored) {
            }
        }
        throw new NoSuchFieldError(target.getName() + "." + name);
    }

    private static boolean matches(Class<?>[] declared, Class<?>[] requested) {
        if (declared.length != requested.length) {
            return false;
        }
        for (int index = 0; index < declared.length; index++) {
            Class<?> expected = requested[index];
            if (expected == null) {
                continue;
            }
            Class<?> actual = declared[index];
            if (actual.isPrimitive()) {
                if (boxed(actual) != boxed(expected)) {
                    return false;
                }
            } else if (expected.isPrimitive()) {
                if (!actual.isAssignableFrom(boxed(expected))) {
                    return false;
                }
            } else if (!actual.isAssignableFrom(expected)) {
                return false;
            }
        }
        return true;
    }

    private static Class<?> boxed(Class<?> type) {
        if (type == Integer.TYPE) return Integer.class;
        if (type == Long.TYPE) return Long.class;
        if (type == Boolean.TYPE) return Boolean.class;
        if (type == Byte.TYPE) return Byte.class;
        if (type == Character.TYPE) return Character.class;
        if (type == Short.TYPE) return Short.class;
        if (type == Float.TYPE) return Float.class;
        if (type == Double.TYPE) return Double.class;
        return type;
    }

    private static Class<?>[] types(Object[] args) {
        if (args == null) {
            return new Class<?>[0];
        }
        Class<?>[] types = new Class<?>[args.length];
        for (int index = 0; index < args.length; index++) {
            types[index] = args[index] == null ? null : args[index].getClass();
        }
        return types;
    }

    private static Object invoke(Method method, Object target, Object[] args) {
        try {
            return method.invoke(target, args);
        } catch (InvocationTargetException error) {
            throw new IllegalStateException(error.getCause());
        } catch (Throwable error) {
            throw new IllegalStateException(error);
        }
    }
}
