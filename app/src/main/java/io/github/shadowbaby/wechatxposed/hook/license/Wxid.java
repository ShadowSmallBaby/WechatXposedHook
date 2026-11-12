package io.github.shadowbaby.wechatxposed.hook.license;

public final class Wxid {

    private static final String PREFIX = "wxid_";

    private static final int MIN_LENGTH = 6;

    private static final int MAX_LENGTH = 32;

    private static final java.util.Set<String> PLACEHOLDERS = java.util.Set.of(
            "wxid_missing", "wxid_invalid", "wxid_friend_req", "wxid_not_found",
            "wxid_unknown", "wxid_null", "wxid_empty", "wxid_none");

    private Wxid() {
    }

    public static boolean isReal(String text) {
        if (text == null) {
            return false;
        }
        String value = text.trim();
        int length = value.length();
        if (length < MIN_LENGTH || length > MAX_LENGTH) {
            return false;
        }

        if (!isLetter(value.charAt(0))) {
            return false;
        }
        for (int index = 0; index < length; index++) {
            char c = value.charAt(index);
            if (!isBody(c) && c != '_' && c != '-') {
                return false;
            }
        }

        if (PLACEHOLDERS.contains(value)) {
            return false;
        }
        return !(value.startsWith(PREFIX)
                && value.indexOf('_', PREFIX.length()) > 0);
    }

    private static boolean isLetter(char value) {
        return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z');
    }

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

    public static String mask(String value) {
        if (value == null || value.isEmpty()) {
            return "null";
        }
        int keep = Math.min(6, value.length());
        return value.substring(0, keep) + "…(" + value.length() + ")";
    }
}
