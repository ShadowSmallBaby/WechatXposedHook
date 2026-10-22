package de.robv.android.xposed.callbacks;

import android.content.pm.ApplicationInfo;

/** Legacy handleLoadPackage 参数。 */
public final class XC_LoadPackage {

    private XC_LoadPackage() {
    }

    public static final class LoadPackageParam {
        public String packageName;
        public String processName;
        public ClassLoader classLoader;
        public ApplicationInfo appInfo;
        public boolean isFirstApplication;
    }
}
