package de.robv.android.xposed;

public abstract class XC_MethodHook {
    public XC_MethodHook() {}
    public XC_MethodHook(int priority) {}
    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {}
    protected void afterHookedMethod(MethodHookParam param) throws Throwable {}
    public final class Unhook {}

    public static final class MethodHookParam {
        public Object thisObject;
        public Object[] args;
        private Object result;
        private Throwable throwable;
        public boolean returnEarly;
        public Object getResult() { return result; }
        public void setResult(Object value) { result = value; throwable = null; returnEarly = true; }
        public Throwable getThrowable() { return throwable; }
        public boolean hasThrowable() { return throwable != null; }
        public void setThrowable(Throwable value) { throwable = value; returnEarly = true; }
    }
}
