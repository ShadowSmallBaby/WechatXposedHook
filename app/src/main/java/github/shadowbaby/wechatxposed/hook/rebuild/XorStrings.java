package github.shadowbaby.wechatxposed.hook.rebuild;

/**
 * 原混淆代码的字符串保护:明文按字符与一个整数 key 异或后存进 short[] 池,运行时还原。
 *
 * 重建后各类把解密结果提升为具名常量(类加载时解一次),调用点读到的是普通字符串。
 * 每个常量旁标注【池名, 偏移, 长度, key】,可与 data/decompiled 下的 smali 逐条对照。
 */
public final class XorStrings {

    private XorStrings() {
    }

    /** 还原 pool[offset, offset + length) 与 key 异或后的明文。 */
    public static String decode(short[] pool, int offset, int length, int key) {
        char[] chars = new char[length];
        for (int i = 0; i < length; i++) {
            chars[i] = (char) (pool[offset + i] ^ key);
        }
        return new String(chars);
    }
}