-keep class github.shadowbaby.wechatxposed.hook.XposedInit { *; }
-keep class github.shadowbaby.wechatxposed.hook.ModernEntry { *; }
## X30Compat 由 assets/xposed_init 与 ModernEntry.initLegacy 按类名加载，
## 重命名或裁掉会导致壳的身份伪装完全不生效。
-keep class github.shadowbaby.wechatxposed.hook.support.identity.X30Compat { *; }
## 现代 APK 的 legacy shim 必须保持原类名：X30Compat/壳 dex 是运行时合并的，
## 按 de.robv.android.xposed.* 的名字链接，不能被 R8 重命名或裁掉。
-keep class de.robv.android.xposed.** { *; }
-keep class com.android.x.** { *; }
## 壳的运行时按类名/方法名做 native 查表，一旦被 R8 重命名会直接 SIGSEGV。
-keep class x.** { *; }
-keep class com.android.xf.** { *; }
## XposedProvider 由系统按 manifest 里的类名实例化，重命名或裁掉会让模块进程启动即崩。
-keep class io.github.libxposed.service.** { *; }
## JNI 用 RegisterNatives 按类名注册，类被重命名会让常量解密全部返回空。
-keep class github.shadowbaby.wechatxposed.hook.loader.util.Secret { *; }
-keep class github.shadowbaby.wechatxposed.hook.license.LicenseCrypto { *; }
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
## 壳内有对可选依赖的引用（项目未打包这些库）。
-dontwarn com.google.android.material.appbar.MaterialToolbar
-dontwarn kotlin.reflect.KVisibility
