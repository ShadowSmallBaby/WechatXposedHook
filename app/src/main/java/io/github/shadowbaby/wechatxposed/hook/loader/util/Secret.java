package io.github.shadowbaby.wechatxposed.hook.loader.util;

public final class Secret {

    private Secret() {
    }

    public static String of(String value) {
        return value == null ? "" : value;
    }
}
