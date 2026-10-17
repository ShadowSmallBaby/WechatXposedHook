package github.shadowbaby.wechatxposed.hook.loader;

import java.io.PrintStream;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;

/**
 * 在设备上跑 native 解码路径,把每个常量按 {@code 名字=明文} 打印。
 *
 * 与 SecretCheck 的区别:这里先确认 libwexhook.so 能加载,加载失败直接报错,
 * 避免「悄悄走了 Java 回退路径」被当成 native 通过。
 */
public final class SecretNativeCheck {

    public static void main(String[] args) throws Exception {
        PrintStream out = new PrintStream(System.out, true, StandardCharsets.UTF_8);
        if (!Secret.isNativeAvailable()) {
            out.println("native=unavailable");
            return;
        }
        out.println("native=available");
        for (Field field : SecretConstants.class.getDeclaredFields()) {
            if (field.getType() != String.class) {
                continue;
            }
            field.setAccessible(true);
            out.println(field.getName() + "=" + Secret.of((String) field.get(null)));
        }
    }

    private SecretNativeCheck() {
    }
}
