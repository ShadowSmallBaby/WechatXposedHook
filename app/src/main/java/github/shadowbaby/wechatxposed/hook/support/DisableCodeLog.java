package github.shadowbaby.wechatxposed.hook.support;

import github.shadowbaby.wechatxposed.hook.framework.HookCallback;
import github.shadowbaby.wechatxposed.hook.framework.HookParam;
import github.shadowbaby.wechatxposed.hook.loader.ModuleLogger;

/**
 * 记录并拦截一致性检查产生的禁用代码。
 */
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
