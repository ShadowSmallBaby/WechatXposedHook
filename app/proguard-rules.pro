-keep class github.shadowbaby.wechatxposed.hook.XposedInit { *; }
-keep class github.shadowbaby.wechatxposed.hook.ModernEntry { *; }

-keepclassmembers class * extends de.robv.android.xposed.XC_MethodHook {
    protected void beforeHookedMethod(de.robv.android.xposed.XC_MethodHook$MethodHookParam);
    protected void afterHookedMethod(de.robv.android.xposed.XC_MethodHook$MethodHookParam);
}

-renamesourcefileattribute SourceFile

-repackageclasses

-allowaccessmodification

-overloadaggressively

-dontwarn de.robv.android.xposed.**
-dontwarn io.github.libxposed.**
