package github.shadowbaby.wechatxposed.hook.framework;

import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import java.lang.reflect.Executable;

/**
 * 回归测试用的框架适配层替身。
 *
 * 业务代码现在只依赖 HookFramework,不在测试里注入一个实现就没法跑。
 * 这里把调用转给 XposedHelpers / XposedBridge 的记录替身,让记录出来的
 * 调用序列与参考实现(直接调 XposedHelpers)可比。
 */
public final class RecordingFramework implements HookFramework {

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
        XposedBridge.hookAllConstructors(target, new Bridge(callback));
    }

    @Override
    public void hookMethod(Executable target, HookCallback callback) {
        XposedBridge.hookMethod(target, new Bridge(callback));
    }

    @Override
    public void hookMethod(Class<?> target, String name, Class<?>[] parameterTypes,
            HookCallback callback) {
        XposedBridge.hookMethod(XposedHelpers.findMethodExact(target, name, parameterTypes),
                new Bridge(callback));
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

    /** 把 HookCallback 包成 XC_MethodHook,与 LegacyFramework 的做法一致。 */
    private static final class Bridge extends de.robv.android.xposed.XC_MethodHook {

        private final HookCallback callback;

        Bridge(HookCallback callback) {
            this.callback = callback;
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            callback.before(new Param(param));
        }

        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            callback.after(new Param(param));
        }
    }

    /** 把 MethodHookParam 包成 HookParam。 */
    private static final class Param implements HookParam {

        private final de.robv.android.xposed.XC_MethodHook.MethodHookParam param;

        Param(de.robv.android.xposed.XC_MethodHook.MethodHookParam param) {
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
        public boolean hasThrowable() {
            return param.hasThrowable();
        }
    }
}