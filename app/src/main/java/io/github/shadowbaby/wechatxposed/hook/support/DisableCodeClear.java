package io.github.shadowbaby.wechatxposed.hook.support;

import io.github.shadowbaby.wechatxposed.shared.hook.HookCallback;
import io.github.shadowbaby.wechatxposed.shared.hook.HookParam;
import io.github.shadowbaby.wechatxposed.hook.loader.ModuleLogger;


public final class DisableCodeClear implements HookCallback {

    private static final int DISABLED_UNLOCKED_MISMATCH = 0x329;

    private static final int DISABLED_TIME_CHECK = 0x334;

    private static final int DISABLED_INVALID_LICENSE = 0x325;

    @Override
    public void after(HookParam param) {
        Object result = param.result();
        if (!(result instanceof Integer code)) {
            return;
        }
        if (code == DISABLED_UNLOCKED_MISMATCH || code == DISABLED_TIME_CHECK
                || code == DISABLED_INVALID_LICENSE) {
            param.setResult(0);
            ModuleLogger.log(String.format("disable code cleared: %05X", code));
        }
    }
}
