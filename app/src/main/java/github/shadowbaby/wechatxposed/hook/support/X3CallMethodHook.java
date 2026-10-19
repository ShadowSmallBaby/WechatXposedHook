package github.shadowbaby.wechatxposed.hook.support;

import github.shadowbaby.wechatxposed.hook.framework.HookCallback;
import github.shadowbaby.wechatxposed.hook.framework.HookParam;
import github.shadowbaby.wechatxposed.hook.loader.ModuleLogger;
import github.shadowbaby.wechatxposed.hook.loader.Secret;
import github.shadowbaby.wechatxposed.hook.loader.SecretConstants;

/**
 * X 3.0 的 native 桥 {@code com.android.xc.WxJniCoreBridge.CallMethod(I,Object[])Object}
 * 的授权应答替换。
 *
 * 3.0 的 verifier/服务类名与 2.44 不同，所以这里不复用 2.44 的
 * {@link CallMethodBypassHook}（它会去找 2.44 的 verifier 类），而是按消息号直接
 * 返回成功/功能列表。
 */
public final class X3CallMethodHook implements HookCallback {

    private static final int MSG_VERIFY_RESULT = 130;
    private static final int MSG_LICENSE_BLOB = 132;
    private static final int MSG_FEATURE_QUERY = 150;    private static final String ACTION_PARAM = Secret.of(SecretConstants.ACTION_PARAM);
    private static final String VERIFIER_SERVICE = Secret.of(SecretConstants.VERIFIER_SERVICE);
    private static final String MIN_SUPPORTED_VERSION =
            Secret.of(SecretConstants.MIN_SUPPORTED_VERSION);
    private static final String UNLIMITED = Secret.of(SecretConstants.UNLIMITED);
    private static final String REMOTE_COMMAND = Secret.of(SecretConstants.REMOTE_COMMAND);
    private static final String FEATURES = Secret.of(SecretConstants.FEATURES);

    private static final String TRUE_TEXT = "true";

    private static final java.util.concurrent.atomic.AtomicInteger CALLS =
            new java.util.concurrent.atomic.AtomicInteger();
    private static final java.util.Set<Integer> SEEN =
            java.util.concurrent.ConcurrentHashMap.newKeySet();

    public X3CallMethodHook() {
    }

    @Override
    public void before(HookParam param) {
        try {
            int msgId = (Integer) param.arg(0);
            int call = CALLS.incrementAndGet();
            Object[] params = (Object[]) param.arg(1);
            if (SEEN.add(msgId)) {
                ModuleLogger.log("X3 msg new: " + msgId
                        + " args=" + java.util.Arrays.toString(params));
            } else if (call <= 3) {
                ModuleLogger.log("X3 call #" + call + " msg=" + msgId);
            }

            // 130 的 param 是版本握手：核心拿返回值跟本机微信版本比较，
            // 不一致就删 params 文件并落到 Disabled error code。这里回本机版本，
            // 与 2.44 的 CallMethodBypassHook 保持一致。
            if (msgId == MSG_VERIFY_RESULT) {
                if (ACTION_PARAM.equals(String.valueOf(params[0]))) {
                    ModuleLogger.log("X3 130 param -> " + MIN_SUPPORTED_VERSION
                            + " args=" + java.util.Arrays.toString(params));
                    param.setResult(MIN_SUPPORTED_VERSION);
                } else if (VERIFIER_SERVICE.equals(String.valueOf(params[0]))) {
                    param.setResult(TRUE_TEXT);
                }
                return;
            }

            if (msgId == MSG_LICENSE_BLOB) {
                if (VERIFIER_SERVICE.equals(String.valueOf(params[0]))) {
                    param.setResult(Boolean.TRUE);
                }
                return;
            }

            if (msgId == MSG_FEATURE_QUERY) {
                Object queryType = params[0];
                if (Integer.valueOf(0).equals(queryType) || Integer.valueOf(2).equals(queryType)) {
                    if (Integer.valueOf(2).equals(queryType)
                            && REMOTE_COMMAND.equals(String.valueOf(params[2]))) {
                        return;
                    }
                    param.setResult(Boolean.TRUE);
                } else if (Integer.valueOf(4).equals(queryType)) {
                    param.setResult(UNLIMITED);
                } else if (Integer.valueOf(6).equals(queryType)) {
                    param.setResult(FEATURES);
                }
            }
        } catch (Throwable error) {
            ModuleLogger.log(error);
        }
    }
}
