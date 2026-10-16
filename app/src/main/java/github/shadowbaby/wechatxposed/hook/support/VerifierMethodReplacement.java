package github.shadowbaby.wechatxposed.hook.support;

import de.robv.android.xposed.XC_MethodReplacement;
import github.shadowbaby.wechatxposed.hook.loader.ModuleLogger;

/**
 * 把一个方法整体替换为固定返回值。
 *
 * 用于堵掉微X的轮询校验、接口请求和更新提示三个入口:
 *   mode 0 → 记日志后返回 null
 *   mode 1 → 记日志后返回 null
 *   其它   → 记日志后返回 false
 */
public final class VerifierMethodReplacement extends XC_MethodReplacement {

    /** 轮询校验。 */
    public static final int POLLING_VERIFIER = 0;

    /** 校验接口请求。 */
    public static final int CHECK_API_REQUEST = 1;

    /** 更新提示。 */
    public static final int UPDATED_TIPS = 2;

    private static final String POLLING_VERIFIER_MESSAGE = "blocked polling verifier";
    private static final String CHECK_API_REQUEST_MESSAGE = "blocked check api";
    private static final String UPDATED_TIPS_MESSAGE = "blocked update tips";

    private final int replacementMode;

    public VerifierMethodReplacement(int mode) {
        this.replacementMode = mode;
    }

    @Override
    public Object replaceHookedMethod(MethodHookParam param) {
        return switch (replacementMode) {
            case POLLING_VERIFIER -> {
                ModuleLogger.log(POLLING_VERIFIER_MESSAGE);
                yield null;
            }
            case CHECK_API_REQUEST -> {
                ModuleLogger.log(CHECK_API_REQUEST_MESSAGE);
                yield null;
            }
            default -> {
                ModuleLogger.log(UPDATED_TIPS_MESSAGE);
                yield Boolean.FALSE;
            }
        };
    }

}
