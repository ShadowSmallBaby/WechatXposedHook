package github.shadowbaby.wechatxposed.hook.framework;

import java.lang.reflect.Executable;

public interface HookFramework {

    Class<?> findClass(String name, ClassLoader loader);

    Class<?> findClassIfExists(String name, ClassLoader loader);

    void hookConstructors(Class<?> target, HookCallback callback);

    void hookMethod(Executable target, HookCallback callback);

    Object callStaticMethod(Class<?> target, String name, Object... arguments);

    Object callMethod(Object target, String name, Object... arguments);

    void hookMethod(Class<?> target, String name, Class<?>[] parameterTypes, HookCallback callback);

    void log(String message);

    void log(Throwable error);
}
