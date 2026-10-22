package de.robv.android.xposed;

import github.shadowbaby.wechatxposed.hook.framework.HookCallback;
import github.shadowbaby.wechatxposed.hook.framework.HookFramework;
import github.shadowbaby.wechatxposed.hook.framework.HookParam;
import java.lang.reflect.Executable;
import java.lang.reflect.Member;
import java.util.HashMap;
import java.util.Map;

/** Legacy XC_MethodHook 适配到 LibXposed HookFramework。 */
public abstract class XC_MethodHook {

    protected XC_MethodHook() {
    }

    protected XC_MethodHook(int priority) {
    }

    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
    }

    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
    }

    public class Unhook {

        private final Adapter adapter;

        Unhook(Adapter adapter) {
            this.adapter = adapter;
        }

        public void unhook() {
            adapter.unhooked = true;
        }
    }

    public static final class MethodHookParam {
        public Object[] args;
        public Member method;
        public Object thisObject;
        public Object result;
        public Throwable throwable;
        public boolean resultSet;
        private final Map<String, Object> extras = new HashMap<>();

        public Object getResult() {
            return result;
        }

        public void setResult(Object value) {
            result = value;
            resultSet = true;
        }

        public Throwable getThrowable() {
            return throwable;
        }

        public void setThrowable(Throwable error) {
            throwable = error;
        }

        public boolean hasThrowable() {
            return throwable != null;
        }

        public Object getObjectExtra(String key) {
            return extras.get(key);
        }

        public void setObjectExtra(String key, Object value) {
            extras.put(key, value);
        }
    }

    static final class Adapter implements HookCallback {

        private final XC_MethodHook hook;
        private final Executable method;
        volatile boolean unhooked;

        Adapter(XC_MethodHook hook, Executable method) {
            this.hook = hook;
            this.method = method;
        }

        @Override
        public void before(HookParam param) {
            if (unhooked) {
                return;
            }
            MethodHookParam legacy = new MethodHookParam();
            legacy.args = param.args();
            legacy.thisObject = param.thisObject();
            legacy.method = method;
            try {
                hook.beforeHookedMethod(legacy);
            } catch (Throwable error) {
                XposedBridge.log(error);
            }
            Object[] original = param.args();
            if (legacy.args != null) {
                for (int index = 0; index < legacy.args.length
                        && index < original.length; index++) {
                    if (legacy.args[index] != original[index]) {
                        param.setArg(index, legacy.args[index]);
                    }
                }
            }
            if (legacy.resultSet) {
                param.setResult(legacy.result);
            }
        }

        @Override
        public void after(HookParam param) {
            if (unhooked) {
                return;
            }
            MethodHookParam legacy = new MethodHookParam();
            legacy.args = param.args();
            legacy.thisObject = param.thisObject();
            legacy.method = method;
            legacy.result = param.result();
            try {
                hook.afterHookedMethod(legacy);
            } catch (Throwable error) {
                XposedBridge.log(error);
            }
            if (legacy.resultSet) {
                param.setResult(legacy.result);
            }
        }
    }

    static HookFramework framework() {
        return XposedBridge.framework();
    }
}
