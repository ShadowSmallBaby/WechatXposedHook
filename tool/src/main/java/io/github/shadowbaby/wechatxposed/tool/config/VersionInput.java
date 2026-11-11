package io.github.shadowbaby.wechatxposed.tool.config;


public final class VersionInput {
    private VersionInput() {}

    public static Integer parse(String input) {
        if (input == null) return null;
        String value = input.trim().replaceFirst("^0[xX]", "");
        if (!value.matches("[0-9a-fA-F]{1,8}")) return null;
        long parsed = Long.parseLong(value, 16);
        return parsed > 0 && parsed <= Integer.MAX_VALUE && (parsed & 0xffffff00L) != 0
                ? (int) parsed : null;
    }
}
