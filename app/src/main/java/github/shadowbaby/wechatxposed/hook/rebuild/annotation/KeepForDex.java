package github.shadowbaby.wechatxposed.hook.rebuild.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 编译期注解,可标注 PACKAGE / TYPE / ANNOTATION_TYPE / CONSTRUCTOR / METHOD / FIELD。
 *
 * @Retention CLASS:只留在 class 文件里,不进运行时反射。
 * 当前代码未引用,保留仅为与 dex 结构一致。
 */
@Target({ElementType.PACKAGE, ElementType.TYPE, ElementType.ANNOTATION_TYPE,
        ElementType.CONSTRUCTOR, ElementType.METHOD, ElementType.FIELD})
@Retention(RetentionPolicy.CLASS)
public @interface KeepForDex {
}
