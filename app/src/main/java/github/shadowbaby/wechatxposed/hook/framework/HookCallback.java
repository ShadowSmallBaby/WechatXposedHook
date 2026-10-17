package github.shadowbaby.wechatxposed.hook.framework;

public interface HookCallback {

    default void before(HookParam param) throws Throwable {
    }

    default void after(HookParam param) throws Throwable {
    }
}
