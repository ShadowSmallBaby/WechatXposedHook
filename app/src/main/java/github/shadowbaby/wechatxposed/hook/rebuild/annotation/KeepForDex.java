package github.shadowbaby.wechatxposed.hook.rebuild.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 重建源码：a.a —— 编译期注解（原 apk classes.dex 中的辅助注解）
 *
 * @Target 覆盖 PACKAGE/TYPE/ANNOTATION_TYPE/CONSTRUCTOR/METHOD/FIELD
 * @Retention CLASS（不进运行时反射）
 *
 * 该注解在运行时逻辑中未被引用，仅为 dex 完整性保留。
 */
@Target({ElementType.PACKAGE, ElementType.TYPE, ElementType.ANNOTATION_TYPE,
        ElementType.CONSTRUCTOR, ElementType.METHOD, ElementType.FIELD})
@Retention(RetentionPolicy.CLASS)
public @interface KeepForDex {
}
