package github.shadowbaby.wechatxposed.hook.support;

import github.shadowbaby.wechatxposed.hook.framework.HookCallback;
import github.shadowbaby.wechatxposed.hook.framework.HookParam;
import github.shadowbaby.wechatxposed.hook.loader.ModuleLogger;

/**
 * 清理 0x329 / 0x334 这类一致性检查产生的禁用代码。
 */
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
