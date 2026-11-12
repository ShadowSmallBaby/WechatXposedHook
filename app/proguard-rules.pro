-keep class io.github.shadowbaby.wechatxposed.hook.XposedInit { *; }
-keep class io.github.shadowbaby.wechatxposed.hook.ModernEntry { *; }

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

-keep class de.robv.android.xposed.** { *; }

-keepattributes *Annotation*,Signature,InnerClasses,EnclosingMethod
-dontwarn x.**
-dontwarn kotlin.reflect.**
-keep class io.github.shadowbaby.wechatxposed.hook.framework.Wx244Hooks { *; }
-keep class io.github.shadowbaby.wechatxposed.hook.framework.Wx30Hooks { *; }
-keepclasseswithmembernames class * { native <methods>; }
