package io.github.shadowbaby.wechatxposed.tool.module;


public interface SettingsSource {
    String readSnapshot();
    void watch(Runnable refresh);
}
