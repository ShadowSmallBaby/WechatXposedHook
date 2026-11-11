

-keep class io.github.shadowbaby.wechatxposed.tool.module.ModernEntry { *; }
-keep class io.github.shadowbaby.wechatxposed.tool.module.LegacyEntry { *; }
-keep class io.github.shadowbaby.wechatxposed.tool.config.ModernSettingsPublisher { *; }

-keep,allowobfuscation class io.github.shadowbaby.wechatxposed.tool.hook.framework.ModernFramework** { *; }
-keep,allowobfuscation class io.github.shadowbaby.wechatxposed.tool.hook.framework.LegacyFramework** { *; }
-keepattributes Signature,InnerClasses,EnclosingMethod
-dontwarn io.github.libxposed.**
-dontwarn de.robv.android.xposed.**
