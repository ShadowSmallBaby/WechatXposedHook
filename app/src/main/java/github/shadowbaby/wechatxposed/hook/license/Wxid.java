package github.shadowbaby.wechatxposed.hook.license;

/**
 * 微信内部账号（wxid）的识别与提取。
 *
 * 微信 8.0.49 把登录账号从 XML prefs 迁到了 MMKV，两处都可能出现
 * {@code wxid_friend_req} 这类内部占位符，真实 wxid 的尾部是字母数字。
 */
public final class Wxid {

    private static final String PREFIX = "wxid_";

    private static final int MIN_LENGTH = 6;

    private static final int MAX_LENGTH = 32;

    /** 壳和微信内部会把这些字符串当 userId 传，不能当成真账号。 */
    private static final java.util.Set<String> PLACEHOLDERS = java.util.Set.of(
            "wxid_missing", "wxid_invalid", "wxid_friend_req", "wxid_not_found",
            "wxid_unknown", "wxid_null", "wxid_empty", "wxid_none");

    private Wxid() {
    }

    /**
     * 账号不一定是 wxid_ 开头：自定义微信号（如 Dead_MDD）同样是合法 userId。
     * 这里只排除明显不是账号的值（短串、占位符、带非法字符）。
     */
    public static boolean isReal(String text) {
        if (text == null) {
            return false;
        }
        String value = text.trim();
        int length = value.length();
        if (length < MIN_LENGTH || length > MAX_LENGTH) {
            return false;
        }
        // 自定义微信号至少字母开头，借此排除 p / C / zh / true 这类参数值。
        if (!isLetter(value.charAt(0))) {
            return false;
        }
        for (int index = 0; index < length; index++) {
            char c = value.charAt(index);
            if (!isBody(c) && c != '_' && c != '-') {
                return false;
            }
        }
        // 壳和微信内部的占位符：wxid_friend_req / wxid_missing / wxid_invalid
        if (PLACEHOLDERS.contains(value)) {
            return false;
        }
        return !(value.startsWith(PREFIX)
                && value.indexOf('_', PREFIX.length()) > 0);
    }

    private static boolean isLetter(char value) {
        return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z');
    }

    /** 从任意文本（含 MMKV 二进制）里取第一个真实 wxid。 */
    public static String first(String text) {
        if (text == null) {
            return null;
        }
        int index = 0;
        while (true) {
            int start = text.indexOf(PREFIX, index);
            if (start < 0) {
                return null;
            }
            int end = start + PREFIX.length();
            while (end < text.length() && isBody(text.charAt(end))) {
                end++;
            }
            String value = text.substring(start, end);
            if (isReal(value)) {
                return value;
            }
            index = start + PREFIX.length();
        }
    }

    private static boolean isBody(char value) {
        return (value >= '0' && value <= '9')
                || (value >= 'a' && value <= 'z')
                || (value >= 'A' && value <= 'Z');
    }

    /** 日志里只露前几位，避免把完整账号写进 logcat。 */
    public static String mask(String value) {
        if (value == null || value.isEmpty()) {
            return "null";
        }
        int keep = Math.min(6, value.length());
        return value.substring(0, keep) + "…(" + value.length() + ")";
    }
}
