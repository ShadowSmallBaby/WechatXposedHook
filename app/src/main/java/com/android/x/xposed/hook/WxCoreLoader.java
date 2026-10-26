package com.android.x.xposed.hook;

public abstract class WxCoreLoader {
    public static native synchronized Object CallMethod(int i, Object[] objArr);
}
