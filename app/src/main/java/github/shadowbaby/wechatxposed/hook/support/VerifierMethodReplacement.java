package github.shadowbaby.wechatxposed.hook.support;

import github.shadowbaby.wechatxposed.hook.framework.HookCallback;
import github.shadowbaby.wechatxposed.hook.framework.HookParam;
import github.shadowbaby.wechatxposed.hook.loader.ModuleLogger;

public final class VerifierMethodReplacement implements HookCallback {

    public static final int POLLING_VERIFIER = 0;

    public static final int CHECK_API_REQUEST = 1;

    public static final int UPDATED_TIPS = 2;

    private static final String POLLING_VERIFIER_MESSAGE = "blocked polling verifier";
    private static final String CHECK_API_REQUEST_MESSAGE = "blocked check api";
    private static final String UPDATED_TIPS_MESSAGE = "blocked update tips";

    private final int replacementMode;

    public VerifierMethodReplacement(int mode) {
        this.replacementMode = mode;
    }

    @Override
    public void before(HookParam param) {
        switch (replacementMode) {
            case POLLING_VERIFIER -> {
                ModuleLogger.log(POLLING_VERIFIER_MESSAGE);
                param.setResult(null);
            }
            case CHECK_API_REQUEST -> {
                ModuleLogger.log(CHECK_API_REQUEST_MESSAGE);
                param.setResult(null);
            }
            default -> {
                ModuleLogger.log(UPDATED_TIPS_MESSAGE);
                param.setResult(Boolean.FALSE);
            }
        }
    }

}
