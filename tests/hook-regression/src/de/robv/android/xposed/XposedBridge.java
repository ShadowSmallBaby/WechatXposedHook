package de.robv.android.xposed;

import java.util.Collections;
import java.util.Set;

public final class XposedBridge {
    public static void log(String message) {}
    public static void log(Throwable error) {}
    public static Set<XC_MethodHook.Unhook> hookAllConstructors(Class<?> type, XC_MethodHook hook) {
        XposedHelpers.calls.add("constructors " + type.getName());
        return Collections.emptySet();
    }
}
