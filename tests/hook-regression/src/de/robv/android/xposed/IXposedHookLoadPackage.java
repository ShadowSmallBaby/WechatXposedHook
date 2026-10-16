package de.robv.android.xposed;

/** 只留下本模块用到的签名;真实 API 还会继承 IXposedMod。 */
public interface IXposedHookLoadPackage {
    void handleLoadPackage(de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam param)
            throws Throwable;
}
