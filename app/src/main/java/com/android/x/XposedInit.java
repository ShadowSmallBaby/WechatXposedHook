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
/* loaded from: classes.dex */
public class XposedInit implements IXposedHookLoadPackage, IXposedHookZygoteInit {
    public String wxhModulePath;

    public static boolean ʽʿ(XC_LoadPackage.LoadPackageParam loadPackageParam, String str) {
        Bundle bundle;
        if (loadPackageParam == null || loadPackageParam.appInfo == null || TextUtils.isEmpty(str) || !str.contains(ʽʿ.ʽʿ(-78198949567827L)) || str.contains(ʽʿ.ʽʿ(-78190359633235L)) || str.contains(ʽʿ.ʽʿ(-78155999894867L)) || str.contains(ʽʿ.ʽʿ(-78125935123795L)) || str.contains(ʽʿ.ʽʿ(-78091575385427L)) || str.contains(ʽʿ.ʽʿ(-78070100548947L)) || str.contains(ʽʿ.ʽʿ(-78314913684819L)) || str.contains(ʽʿ.ʽʿ(-78293438848339L)) || str.contains(ʽʿ.ʽʿ(-78259079109971L)) || str.contains(Build.MANUFACTURER.toLowerCase()) || str.contains(ʽʿ.ʽʿ(-78229014338899L)) || loadPackageParam.processName.contains(ʽʿ.ʽʿ(-78448057670995L))) {
            return true;
        }
        ApplicationInfo applicationInfo = loadPackageParam.appInfo;
        if (applicationInfo != null) {
            try {
                if ((applicationInfo.flags & 1) != 0) {
                    return true;
                }
            } catch (Throwable th) {
                ᵎᵔ.ᵢﹳ(th);
            }
        }
        ApplicationInfo applicationInfo2 = loadPackageParam.appInfo;
        if (applicationInfo2 != null && (bundle = applicationInfo2.metaData) != null && bundle.containsKey(ʽʿ.ʽʿ(-77425855454547L)) && bundle.getBoolean(ʽʿ.ʽʿ(-77644898786643L), false)) {
            return true;
        }
        return false;
    }

    public final void handleLoadPackage(XC_LoadPackage.LoadPackageParam loadPackageParam) {
        try {
            String str = loadPackageParam.packageName;
            ˎٴ.ˏﾞ(loadPackageParam);
            if (ʽʿ(loadPackageParam, str)) {
                return;
            }
            // 壳自己的初始化会加载 native、解密功能 dex 并安装全部微信 hook，
            // 不能跳过——跳过会导致功能包的事件通道全部失效（首页三点、设置菜单都不出现）。
            new ˈﹶ().ˎٴ(loadPackageParam, str, this.wxhModulePath);
            if (!ˎٴ.ʽʿ) {
                ˎٴ.ʽʿ = true;
                String str2 = loadPackageParam.packageName;
                if (str2.contains(ʽʿ.ʽʿ(-101009520876883L)) || str2.contains(ʽʿ.ʽʿ(-100979456105811L)) || str2.contains(ʽʿ.ʽʿ(-100957981269331L)) || str2.contains(ʽʿ.ʽʿ(-100927916498259L))) {
                    ˎٴ.ﹶﾞ(loadPackageParam.classLoader);
                }
            }
        } catch (Throwable th) {
            ᵎᵔ.ᵢﹳ(th);
        }
    }

    public final void initZygote(IXposedHookZygoteInit.StartupParam startupParam) {
        this.wxhModulePath = startupParam.modulePath;
    }
}
