package de.robv.android.xposed;

/** Legacy Xposed 入口接口；现代 APK 由 ModernEntry 手动调用。 */
public interface IXposedHookZygoteInit {

    final class StartupParam {
        public String modulePath;
        public boolean startsSystemServer;
    }

    void initZygote(StartupParam startupParam) throws Throwable;
}
