package io.github.shadowbaby.wechatxposed.shared.hook;

public interface HookCallback {

    default void before(HookParam param) throws Throwable {
    }

    default void after(HookParam param) throws Throwable {
    }
}