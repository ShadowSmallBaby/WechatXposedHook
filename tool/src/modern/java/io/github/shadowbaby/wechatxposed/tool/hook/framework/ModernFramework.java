package io.github.shadowbaby.wechatxposed.tool.hook.framework;

import android.util.Log;
import io.github.libxposed.api.XposedInterface;
import io.github.libxposed.api.XposedModule;

import java.lang.reflect.Executable;
import java.lang.reflect.Method;
import io.github.shadowbaby.wechatxposed.shared.hook.HookCallback;
import io.github.shadowbaby.wechatxposed.shared.hook.HookFramework;
import io.github.shadowbaby.wechatxposed.shared.hook.HookParam;


public final class ModernFramework implements HookFramework {

    private static final String TAG = "WeXposedTool";

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
        return ReflectiveCalls.call(target, null, name, arguments);
    }

    @Override
    public Object callMethod(Object target, String name, Object... arguments) {
        return ReflectiveCalls.call(target.getClass(), target, name, arguments);
    }

    @Override
    public void log(String message) {
        module.log(Log.INFO, TAG, message);
    }

    @Override
    public void log(Throwable error) {
        module.log(Log.ERROR, TAG, String.valueOf(error), error);
    }

    private static Object invoke(HookCallback callback, XposedInterface.Chain chain)
            throws Throwable {
        Param param = new Param(chain);
        callback.before(param);
        if (param.replaced) {
            return param.replacement;
        }
        try {
            Object result = param.changedArgs == null
                    ? chain.proceed()
                    : chain.proceed(param.changedArgs);
            param.result = result;
        } catch (Throwable error) {
            param.throwable = error;
            callback.after(param);
            throw error;
        }
        callback.after(param);
        return param.result();
    }

    private static final class Param implements HookParam {

        private final XposedInterface.Chain chain;
        private final java.util.List<Object> arguments;


        private Object[] changedArgs;

        private boolean replaced;
        private Object replacement;
        private Object result;
        private Throwable throwable;

        Param(XposedInterface.Chain chain) {
            this.chain = chain;
            this.arguments = chain.getArgs();
        }

        @Override
        public Object[] args() {
            return changedArgs != null ? changedArgs.clone() : arguments.toArray();
        }

        @Override
        public Object arg(int index) {
            return changedArgs != null ? changedArgs[index] : arguments.get(index);
        }

        @Override
        public void setArg(int index, Object value) {
            if (changedArgs == null) {
                changedArgs = arguments.toArray();
            }
            changedArgs[index] = value;
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
