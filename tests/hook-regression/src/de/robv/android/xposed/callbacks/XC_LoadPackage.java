package de.robv.android.xposed.callbacks;

/** 真机上是 XCallback.Param 的子类;这里只留本模块读的那几个字段。 */
public final class XC_LoadPackage {

    public static final class LoadPackageParam {
        public String packageName;
        public String processName;
        public ClassLoader classLoader;
        public android.content.pm.ApplicationInfo appInfo;
        public boolean isFirstApplication;
    }
}
