package github.shadowbaby.wechatxposed.hook.support;

import github.shadowbaby.wechatxposed.hook.framework.HookCallback;
import github.shadowbaby.wechatxposed.hook.framework.HookParam;

/**
 * 跳过 CoreDex 的时间戳一致性检查，避免写入 0x334。
 */
public final class StatusCheckSkip implements HookCallback {

    @Override
    public void before(HookParam param) {
        param.setResult(null);
    }
}
