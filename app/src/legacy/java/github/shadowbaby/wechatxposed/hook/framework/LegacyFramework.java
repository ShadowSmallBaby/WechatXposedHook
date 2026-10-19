package github.shadowbaby.wechatxposed.hook.framework;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import java.lang.reflect.Executable;
import java.lang.reflect.Method;

public final class LegacyFramework implements HookFramework {

    @Override
    public Class<?> findClass(String name, ClassLoader loader) {
        return XposedHelpers.findClass(name, loader);
    }

    @Override
    public Class<?> findClassIfExists(String name, ClassLoader loader) {
        return XposedHelpers.findClassIfExists(name, loader);
    }

    @Override
    public void hookConstructors(Class<?> target, HookCallback callback) {
        XposedBridge.hookAllConstructors(target, bridge(callback));
    }

    @Override
    public void hookMethod(Executable target, HookCallback callback) {
        XposedBridge.hookMethod(target, bridge(callback));
    }

    @Override
    public void hookMethod(Class<?> target, String name, Class<?>[] parameterTypes,
            HookCallback callback) {
        Method method = XposedHelpers.findMethodExact(target, name, parameterTypes);
        XposedBridge.hookMethod(method, bridge(callback));
    }

    @Override
    public Object callStaticMethod(Class<?> target, String name, Object... arguments) {
        return XposedHelpers.callStaticMethod(target, name, arguments);
    }

    @Override
    public Object callMethod(Object target, String name, Object... arguments) {
        return XposedHelpers.callMethod(target, name, arguments);
    }

    @Override
    public void log(String message) {
        XposedBridge.log(message);
    }

    @Override
    public void log(Throwable error) {
        XposedBridge.log(error);
    }

    private static XC_MethodHook bridge(HookCallback callback) {
        return new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                callback.before(new LegacyParam(param));
            }

            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                callback.after(new LegacyParam(param));
            }
        };
    }

    private static final class LegacyParam implements HookParam {

        private final XC_MethodHook.MethodHookParam param;

        LegacyParam(XC_MethodHook.MethodHookParam param) {
            this.param = param;
        }

        @Override
        public Object[] args() {
            return param.args;
        }

        @Override
        public Object arg(int index) {
            return param.args[index];
        }

        @Override
        public Object thisObject() {
            return param.thisObject;
        }

        @Override
        public void setResult(Object result) {
            param.setResult(result);
        }

        @Override
        public Object result() {
            return param.getResult();
        }

        @Override
        public boolean hasThrowable() {
            return param.hasThrowable();
        }
    }
}
