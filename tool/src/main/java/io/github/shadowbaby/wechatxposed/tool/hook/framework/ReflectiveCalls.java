package io.github.shadowbaby.wechatxposed.tool.hook.framework;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;


public final class ReflectiveCalls {
    private ReflectiveCalls() {}

    public static Object call(Class<?> owner, Object receiver, String name, Object[] args) {
        Method best = null;
        int bestScore = Integer.MAX_VALUE;
        boolean ambiguous = false;
        for (Class<?> type = owner; type != null; type = type.getSuperclass()) {
            for (Method method : type.getDeclaredMethods()) {
                if (!method.getName().equals(name) || method.isBridge()
                        || Modifier.isStatic(method.getModifiers()) != (receiver == null)) continue;
                Class<?>[] parameters = method.getParameterTypes();
                if (parameters.length != args.length) continue;
                int score = 0;
                for (int i = 0; i < args.length; i++) {
                    Class<?> boxed = box(parameters[i]);
                    if (args[i] == null) { if (parameters[i].isPrimitive()) { score = -1; break; } score += 2; }
                    else if (!boxed.isInstance(args[i])) { score = -1; break; }
                    else if (boxed != args[i].getClass()) score++;
                }
                if (score < 0) continue;
                if (score < bestScore) { best = method; bestScore = score; ambiguous = false; }
                else if (score == bestScore && best != null
                        && !java.util.Arrays.equals(best.getParameterTypes(), parameters)) ambiguous = true;
            }
        }
        if (best == null || ambiguous) throw new NoSuchMethodError(owner.getName() + "." + name + " (missing/ambiguous)");
        return invoke(best, receiver, args);
    }

    public static Object invoke(Method method, Object receiver, Object[] args) {
        try { method.setAccessible(true); return method.invoke(receiver, args); }
        catch (InvocationTargetException error) { throw new IllegalStateException(method.getName(), error.getCause()); }
        catch (IllegalAccessException error) { throw new IllegalStateException(method.getName(), error); }
    }

    private static Class<?> box(Class<?> type) {
        if (type == int.class) return Integer.class;
        if (type == boolean.class) return Boolean.class;
        if (type == long.class) return Long.class;
        if (type == byte.class) return Byte.class;
        if (type == short.class) return Short.class;
        if (type == float.class) return Float.class;
        if (type == double.class) return Double.class;
        if (type == char.class) return Character.class;
        return type;
    }
}
