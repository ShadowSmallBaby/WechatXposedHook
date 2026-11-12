package de.robv.android.xposed;

public interface IXposedHookZygoteInit {

    final class StartupParam {
        public String modulePath;
        public boolean startsSystemServer;
    }

    void initZygote(StartupParam startupParam) throws Throwable;
}
