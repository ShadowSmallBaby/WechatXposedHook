package com.android.x;

import android.content.pm.ApplicationInfo;
import android.os.Build;
import android.os.Bundle;
import android.text.TextUtils;
import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.IXposedHookZygoteInit;
import de.robv.android.xposed.callbacks.XC_LoadPackage;
import x.ˈˋ.ˎٴ;
import x.ᵢˋ.ˈﹶ;
import x.ⁱᵢ.ᵎᵔ;
import x.ﹳˉ.ʽʿ;

public class XposedInit implements IXposedHookLoadPackage, IXposedHookZygoteInit {
    public String wxhModulePath;

    /**
     * 判断是否跳过壳初始化：非微信包、被排除的包名、调试包、
     * 以及声明了特定 metaData 的包都直接放行（返回 true）。
     */
    public static boolean ʽʿ(XC_LoadPackage.LoadPackageParam loadPackageParam, String packageName) {
        if (loadPackageParam == null || loadPackageParam.appInfo == null
                || TextUtils.isEmpty(packageName)) {
            return true;
        }
        // 必须先命中微信包名，否则不是目标宿主。
        if (!packageName.contains(ʽʿ.ʽʿ(-78198949567827L))) {
            return true;
        }
        String processName = loadPackageParam.processName;
        String manufacturer = Build.MANUFACTURER;
        if (packageName.contains(ʽʿ.ʽʿ(-78190359633235L))
                || packageName.contains(ʽʿ.ʽʿ(-78155999894867L))
                || packageName.contains(ʽʿ.ʽʿ(-78125935123795L))
                || packageName.contains(ʽʿ.ʽʿ(-78091575385427L))
                || packageName.contains(ʽʿ.ʽʿ(-78070100548947L))
                || packageName.contains(ʽʿ.ʽʿ(-78314913684819L))
                || packageName.contains(ʽʿ.ʽʿ(-78293438848339L))
                || packageName.contains(ʽʿ.ʽʿ(-78259079109971L))
                || (manufacturer != null && packageName.contains(manufacturer.toLowerCase()))
                || packageName.contains(ʽʿ.ʽʿ(-78229014338899L))
                || (processName != null
                        && processName.contains(ʽʿ.ʽʿ(-78448057670995L)))) {
            return true;
        }
        ApplicationInfo appInfo = loadPackageParam.appInfo;
        try {
            // FLAG_DEBUGGABLE
            if ((appInfo.flags & 1) != 0) {
                return true;
            }
        } catch (Throwable error) {
            ᵎᵔ.ᵢﹳ(error);
        }
        Bundle metaData = appInfo.metaData;
        return metaData != null
                && metaData.containsKey(ʽʿ.ʽʿ(-77425855454547L))
                && metaData.getBoolean(ʽʿ.ʽʿ(-77644898786643L), false);
    }

    public final void handleLoadPackage(XC_LoadPackage.LoadPackageParam loadPackageParam) {
        try {
            String packageName = loadPackageParam.packageName;
            ˎٴ.ˏﾞ(loadPackageParam);
            if (ʽʿ(loadPackageParam, packageName)) {
                return;
            }
            // 壳自己的初始化会加载 native、解密功能 dex 并安装全部微信 hook，
            // 不能跳过——跳过会导致功能包的事件通道全部失效（首页三点、设置菜单都不出现）。
            new ˈﹶ().ˎٴ(loadPackageParam, packageName, this.wxhModulePath);
            if (ˎٴ.ʽʿ) {
                return;
            }
            ˎٴ.ʽʿ = true;
            if (packageName.contains(ʽʿ.ʽʿ(-101009520876883L))
                    || packageName.contains(ʽʿ.ʽʿ(-100979456105811L))
                    || packageName.contains(ʽʿ.ʽʿ(-100957981269331L))
                    || packageName.contains(ʽʿ.ʽʿ(-100927916498259L))) {
                ˎٴ.ﹶﾞ(loadPackageParam.classLoader);
            }
        } catch (Throwable th) {
            ᵎᵔ.ᵢﹳ(th);
        }
    }

    public final void initZygote(IXposedHookZygoteInit.StartupParam startupParam) {
        this.wxhModulePath = startupParam.modulePath;
    }
}
