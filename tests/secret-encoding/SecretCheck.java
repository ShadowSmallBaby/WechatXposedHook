package github.shadowbaby.wechatxposed.hook.loader;

import java.io.PrintStream;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;

/**
 * 把 SecretConstants 里每个密文按 {@code 名字=密文} 打印,供 run.py 与
 * scripts/encode_secrets.py 的编码结果逐项对照。
 *
 * 这里不调 Secret.of:明文解码在 so 里,桌面 JVM 没有 so(见 run-device.py)。
 * 桌面只校验「密文 = 明文表经常量名派生 HKDF 子密钥编码」这条链。
 */
public final class SecretCheck {

    public static void main(String[] args) throws Exception {
        PrintStream out = new PrintStream(System.out, true, StandardCharsets.UTF_8);
        for (Field field : SecretConstants.class.getDeclaredFields()) {
            if (field.getType() != String.class) {
                continue;
            }
            field.setAccessible(true);
            out.println(field.getName() + "=" + field.get(null));
        }
    }

    private SecretCheck() {
    }
}
