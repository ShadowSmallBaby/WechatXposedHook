package io.github.shadowbaby.wechatxposed.hook.support;

import io.github.shadowbaby.wechatxposed.shared.hook.HookCallback;
import io.github.shadowbaby.wechatxposed.shared.hook.HookParam;
import io.github.shadowbaby.wechatxposed.hook.loader.ModuleLogger;

public final class VerifierMethodReplacement implements HookCallback {

    public static final int POLLING_VERIFIER = 0;

    public static final int CHECK_API_REQUEST = 1;

    public static final int UPDATED_TIPS = 2;

    private final int replacementMode;

    public VerifierMethodReplacement(int mode) {
        this.replacementMode = mode;
    }

    @Override
    public void before(HookParam param) {
        switch (replacementMode) {
            case POLLING_VERIFIER -> {
                param.setResult(null);
            }
            case CHECK_API_REQUEST -> {
                param.setResult(null);
            }
            default -> {
                param.setResult(Boolean.FALSE);
            }
        }
    }

}
