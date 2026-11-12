package de.robv.android.xposed;

import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;

public interface IXposedHookLoadPackage {

    void handleLoadPackage(LoadPackageParam loadPackageParam) throws Throwable;
}
