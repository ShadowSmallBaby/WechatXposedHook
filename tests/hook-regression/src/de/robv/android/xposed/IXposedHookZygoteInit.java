package de.robv.android.xposed;

public interface IXposedHookZygoteInit {
    void initZygote(StartupParam param) throws Throwable;
    final class StartupParam { public String modulePath; public boolean startsSystemServer; }
}
