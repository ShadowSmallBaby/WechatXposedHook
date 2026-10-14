package github.shadowbaby.wechatxposed.hook.rebuild.support;

import de.robv.android.xposed.XC_MethodReplacement;
import github.shadowbaby.wechatxposed.hook.rebuild.XorStrings;
import github.shadowbaby.wechatxposed.hook.rebuild.loader.ModuleLogger;

/**
 * 把一个方法整体替换为固定返回值(原混淆类 c.c)。
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

    /** 原 c.c.<clinit> 的字符池,key=55271。 */
    private static final short[] REPLACEMENT_POOL = {
            5044, -10363, -10362, -10359, -10359, -10366, -10365, -10297,
            -10345, -10360, -10357, -10357, -10354, -10359, -10368, -10297,
            -10351, -10366, -10347, -10354, -10367, -10354, -10366, -10347,
            -10363, -10362, -10359, -10359, -10366, -10365, -10297, -10364,
            -10353, -10366, -10364, -10356, -10297, -10362, -10345, -10354,
            -10297, -10347, -10366, -10346, -10350, -10366, -10348, -10349,
            -10363, -10362, -10359, -10359, -10366, -10365, -10297, -10350,
            -10345, -10365, -10362, -10349, -10366, -10365, -10297, -10349,
            -10354, -10345, -10348};

    private static final int POOL_KEY = 55271;

    private static final String POLLING_VERIFIER_MESSAGE = decode(1, 23);
    private static final String CHECK_API_REQUEST_MESSAGE = decode(24, 24);
    private static final String UPDATED_TIPS_MESSAGE = decode(48, 19);

    private final int replacementMode;

    public VerifierMethodReplacement(int mode) {
        this.replacementMode = mode;
    }

    @Override
    public Object replaceHookedMethod(MethodHookParam param) {
        switch (replacementMode) {
            case POLLING_VERIFIER:
                ModuleLogger.log(POLLING_VERIFIER_MESSAGE);
                return null;
            case CHECK_API_REQUEST:
                ModuleLogger.log(CHECK_API_REQUEST_MESSAGE);
                return null;
            default:
                ModuleLogger.log(UPDATED_TIPS_MESSAGE);
                return Boolean.FALSE;
        }
    }

    private static String decode(int offset, int length) {
        return XorStrings.decode(REPLACEMENT_POOL, offset, length, POOL_KEY);
    }
}