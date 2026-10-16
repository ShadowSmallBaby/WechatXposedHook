package de.robv.android.xposed;

import java.lang.reflect.Member;
import java.util.Set;

/** 测试替身:app_process 里没有 Xposed 框架,日志打到 stdout,hook 调用空实现。 */
public final class XposedBridge {

    private XposedBridge() {
    }

    public static void log(String text) {
        System.out.println("log " + text);
    }

    public static void log(Throwable throwable) {
        System.out.println("log " + throwable.getClass().getSimpleName() + ": " + throwable.getMessage());
    }

    public static Set<XC_MethodHook.Unhook> hookAllConstructors(Class<?> clazz, XC_MethodHook callback) {
        return new java.util.HashSet<>();
    }

    public static XC_MethodHook.Unhook hookMethod(Member method, XC_MethodHook callback) {
        return null;
    }
}
