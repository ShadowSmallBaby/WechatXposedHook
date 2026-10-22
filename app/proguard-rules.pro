-keep class github.shadowbaby.wechatxposed.hook.XposedInit { *; }
-keep class github.shadowbaby.wechatxposed.hook.ModernEntry { *; }
## 现代 APK 的 legacy shim 必须保持原类名：X30Compat/壳 dex 是运行时合并的，
## 按 de.robv.android.xposed.* 的名字链接，不能被 R8 重命名或裁掉。
-keep class de.robv.android.xposed.** { *; }
-keep class github.shadowbaby.wechatxposed.x30.** { *; }
-keep class com.android.x.** { *; }
# 构建脚本用类名做载荷标记，保留原名便于校验与现场排查。
-keep class github.shadowbaby.wechatxposed.hook.support.pack.FeatureDexInjector { *; }
-keep class github.shadowbaby.wechatxposed.hook.support.pack.FeaturePackUnlock { *; }

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
