package io.github.shadowbaby.wechatxposed.hook.support;

import io.github.shadowbaby.wechatxposed.shared.hook.HookCallback;
import io.github.shadowbaby.wechatxposed.shared.hook.HookParam;


public final class StatusCheckSkip implements HookCallback {

    @Override
    public void before(HookParam param) {
        param.setResult(null);
    }
}
