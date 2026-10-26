package github.shadowbaby.wechatxposed.hook.loader.util;

import java.nio.ByteBuffer;

/** dex 字节里查找类名，用于判断当前加载的是哪个组件。 */
public final class ByteSearch {

    private ByteSearch() {
    }

    public static boolean contains(ByteBuffer source, byte[] needle) {
        try {
            ByteBuffer buffer = source.duplicate();
            buffer.rewind();
            byte[] data = new byte[buffer.remaining()];
            buffer.get(data);
            outer:
            for (int index = 0; index <= data.length - needle.length; index++) {
                for (int offset = 0; offset < needle.length; offset++) {
                    if (data[index + offset] != needle[offset]) {
                        continue outer;
                    }
                }
                return true;
            }
        } catch (Throwable ignored) {
            // 按未命中处理
        }
        return false;
    }
}
