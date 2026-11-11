package io.github.shadowbaby.wechatxposed.hook.support;

import io.github.shadowbaby.wechatxposed.shared.hook.HookCallback;
import io.github.shadowbaby.wechatxposed.shared.hook.HookParam;
import io.github.shadowbaby.wechatxposed.hook.loader.ModuleLogger;


public final class DisableCodeLog implements HookCallback {

    private static final int DISABLED_UNLOCKED_MISMATCH = 0x329;

    private static final int DISABLED_TIME_CHECK = 0x334;

    private static final int DISABLED_INVALID_LICENSE = 0x325;

    @Override
    public void before(HookParam param) {
        Object[] args = param.args();
        if (args == null || args.length == 0 || !(args[0] instanceof Integer code)) {
            return;
        }
        ModuleLogger.log(String.format("disable code set: %05X", code));
        if (code == DISABLED_UNLOCKED_MISMATCH || code == DISABLED_TIME_CHECK
                || code == DISABLED_INVALID_LICENSE) {
            param.setResult(null);
        }
    }
}
