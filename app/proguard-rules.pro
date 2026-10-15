# Xposed 模块入口由 assets/xposed_init 按名字加载,必须保留类名与方法。
-keep class github.shadowbaby.wechatxposed.hook.XposedInit { *; }

# 回调类由 XposedBridge 反射调用其 before/afterHookedMethod,保留成员名。
-keepclassmembers class * extends de.robv.android.xposed.XC_MethodHook {
    protected void beforeHookedMethod(de.robv.android.xposed.XC_MethodHook$MethodHookParam);
    protected void afterHookedMethod(de.robv.android.xposed.XC_MethodHook$MethodHookParam);
}

# 异常栈里保留源文件名与行号,便于真机排错。
-keepattributes SourceFile,LineNumberTable

# 微X 的类名以字符串形式传给 findClass,不参与压缩与重命名判断。
-dontwarn de.robv.android.xposed.**