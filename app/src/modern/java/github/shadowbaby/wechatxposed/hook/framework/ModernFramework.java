package github.shadowbaby.wechatxposed.hook.framework;

import android.util.Log;
import io.github.libxposed.api.XposedInterface;
import io.github.libxposed.api.XposedModule;
import java.lang.reflect.Executable;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public final class ModernFramework implements HookFramework {

    private static final String TAG = "WeXposedHook";

    private final XposedModule module;

    public ModernFramework(XposedModule module) {
        this.module = module;
    }

    @Override
    public Class<?> findClass(String name, ClassLoader loader) {
        try {
            return Class.forName(name, false, loader);
        } catch (ClassNotFoundException error) {
            throw new NoClassDefFoundError(name);
        }
    }

    @Override
    public Class<?> findClassIfExists(String name, ClassLoader loader) {
        try {
            return Class.forName(name, false, loader);
        } catch (Throwable error) {
            return null;
        }
    }

    @Override
    public void hookConstructors(Class<?> target, HookCallback callback) {
        for (java.lang.reflect.Constructor<?> constructor : target.getDeclaredConstructors()) {
            hookMethod(constructor, callback);
        }
    }

    @Override
    public void hookMethod(Executable target, HookCallback callback) {
        module.hook(target).intercept(chain -> invoke(callback, chain));
    }

    @Override
    public void hookMethod(Class<?> target, String name, Class<?>[] parameterTypes,
            HookCallback callback) {
        try {
            Method method = target.getDeclaredMethod(name, parameterTypes);
            hookMethod(method, callback);
        } catch (NoSuchMethodException error) {
            throw new NoSuchMethodError(target.getName() + "." + name);
        }
    }

    @Override
    public Object callStaticMethod(Class<?> target, String name, Object... arguments) {
        return invokeMethod(target, null, name, arguments);
    }

    @Override
    public Object callMethod(Object target, String name, Object... arguments) {
        return invokeMethod(target.getClass(), target, name, arguments);
    }

    @Override
    public void log(String message) {
        module.log(Log.INFO, TAG, message);
    }

    @Override
    public void log(Throwable error) {
        module.log(Log.ERROR, TAG, String.valueOf(error), error);
    }

    private static Object invokeMethod(Class<?> owner, Object target, String name,
            Object[] arguments) {
        for (Class<?> type = owner; type != null; type = type.getSuperclass()) {
            for (Method method : type.getDeclaredMethods()) {
                if (!method.getName().equals(name)
                        || method.getParameterCount() != arguments.length) {
                    continue;
                }
                try {
                    method.setAccessible(true);
                    return method.invoke(target, arguments);
                } catch (IllegalAccessException | InvocationTargetException error) {
                    throw new IllegalStateException(name, error);
                }
            }
        }
        throw new NoSuchMethodError(owner.getName() + "." + name);
    }

    private static Object invoke(HookCallback callback, XposedInterface.Chain chain)
            throws Throwable {
        Param param = new Param(chain);
        callback.before(param);
        if (param.replaced) {
            return param.replacement;
        }
        try {
            Object result = chain.proceed();
            param.result = result;
        } catch (Throwable error) {
            param.throwable = error;
            callback.after(param);
            throw error;
        }
        callback.after(param);
        return param.result;
    }

    private static final class Param implements HookParam {

        private final XposedInterface.Chain chain;
        private final Object[] arguments;

        private boolean replaced;
        private Object replacement;
        private Object result;
        private Throwable throwable;

        Param(XposedInterface.Chain chain) {
            this.chain = chain;
            this.arguments = chain.getArgs().toArray();
        }

        @Override
        public Object[] args() {
            return arguments;
        }

        @Override
        public Object arg(int index) {
            return arguments[index];
        }

        @Override
        public Object thisObject() {
            return chain.getThisObject();
        }

        @Override
        public void setResult(Object value) {
            replaced = true;
            replacement = value;
        }

        @Override
        public Object result() {
            return replaced ? replacement : result;
        }

        @Override
        public boolean hasThrowable() {
            return throwable != null;
        }
    }
}
