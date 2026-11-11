package io.github.shadowbaby.wechatxposed.tool.hook.framework;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;

import java.lang.reflect.Executable;
import io.github.shadowbaby.wechatxposed.shared.hook.HookCallback;
import io.github.shadowbaby.wechatxposed.shared.hook.HookFramework;
import io.github.shadowbaby.wechatxposed.shared.hook.HookParam;


public final class LegacyFramework implements HookFramework {
    @Override public Class<?> findClass(String name, ClassLoader loader) {
        try { return Class.forName(name, false, loader); }
        catch (ClassNotFoundException error) { throw new NoClassDefFoundError(name); }
    }

    @Override public Class<?> findClassIfExists(String name, ClassLoader loader) {
        try { return Class.forName(name, false, loader); }
        catch (Throwable error) { return null; }
    }

    @Override public void hookConstructors(Class<?> target, HookCallback callback) {
        for (var constructor : target.getDeclaredConstructors()) hookMethod(constructor, callback);
    }

    @Override public void hookMethod(Executable target, HookCallback callback) {
        XposedBridge.hookMethod(target, new XC_MethodHook() {
            @Override protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                callback.before(new LegacyFramework.Param(param));
            }
            @Override protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                Throwable original = param.getThrowable();
                try { callback.after(new LegacyFramework.Param(param)); }
                finally { if (original != null) param.setThrowable(original); }
            }
        });
    }

    @Override public void hookMethod(Class<?> target, String name, Class<?>[] types, HookCallback callback) {
        try { hookMethod(target.getDeclaredMethod(name, types), callback); }
        catch (NoSuchMethodException error) { throw new NoSuchMethodError(target.getName() + "." + name); }
    }

    @Override public Object callStaticMethod(Class<?> target, String name, Object... args) {
        return ReflectiveCalls.call(target, null, name, args);
    }
    @Override public Object callMethod(Object target, String name, Object... args) {
        return ReflectiveCalls.call(target.getClass(), target, name, args);
    }
    @Override public void log(String message) { XposedBridge.log("WeXposedTool-> " + message); }
    @Override public void log(Throwable error) { XposedBridge.log(error); }

    private static final class Param implements HookParam {
        private final XC_MethodHook.MethodHookParam param;
        Param(XC_MethodHook.MethodHookParam param) { this.param = param; }
        @Override public Object[] args() { return param.args.clone(); }
        @Override public Object arg(int index) { return param.args[index]; }
        @Override public void setArg(int index, Object value) { param.args[index] = value; }
        @Override public Object thisObject() { return param.thisObject; }
        @Override public void setResult(Object result) { param.setResult(result); }
        @Override public Object result() { return param.getResult(); }
        @Override public boolean hasThrowable() { return param.hasThrowable(); }
    }
}
