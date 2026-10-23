package github.shadowbaby.wechatxposed.hook.support.guard;

import github.shadowbaby.wechatxposed.hook.license.Activation;
import github.shadowbaby.wechatxposed.hook.support.feature.EditionFeatures;
import github.shadowbaby.wechatxposed.hook.framework.HookCallback;
import github.shadowbaby.wechatxposed.hook.framework.HookParam;
import github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import github.shadowbaby.wechatxposed.hook.loader.util.Secret;
import github.shadowbaby.wechatxposed.hook.loader.SecretConstants;

/**
 * X 3.0 native 桥 {@code com.android.xc.WxJniCoreBridge.CallMethod(I,Object[])Object}
 * 的应答替换。
 *
 * 按消息号返回授权结果与功能列表。
 */
public final class X3CallMethodHook implements HookCallback {

    private static final int MSG_VERIFY_RESULT = 130;
    private static final int MSG_LICENSE_BLOB = 132;
    private static final int MSG_FEATURE_QUERY = 150;
    private static final String ACTION_PARAM = Secret.of(SecretConstants.ACTION_PARAM);
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
            if (msgId == MSG_LICENSE_BLOB || msgId == MSG_FEATURE_QUERY) {
                ModuleLogger.debug("X3 msg " + msgId + " params="
                        + java.util.Arrays.deepToString(params));
            }
            // 132/150 只在首次授权时出现，重启后 X3 不再发，wxid 会永远拿不到。
            // 任何一次 CallMethod 都顺手捞一遍，机器码授权才能算出来。
            captureAccount(params);
            if (SEEN.add(msgId)) {
                ModuleLogger.debug("X3 msg new: " + msgId
                        + " args=" + java.util.Arrays.toString(params));
            } else if (call <= 3) {
                ModuleLogger.debug("X3 call #" + call + " msg=" + msgId);
            }

            // 130 的 param 是版本握手，返回本机支持的版本。
            if (msgId == MSG_VERIFY_RESULT) {
                if (ACTION_PARAM.equals(String.valueOf(params[0]))) {
                    ModuleLogger.debug("X3 130 param -> " + MIN_SUPPORTED_VERSION
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
                    if (Integer.valueOf(2).equals(queryType)) {
                        String key = String.valueOf(params[2]);
                        if (REMOTE_COMMAND.equals(key)
                                || EditionFeatures.isUnavailableExt(key)) {
                            return;
                        }
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

    /** 从 X 3.0 传入的参数里捞出当前登录 wxid，作为授权账号的权威来源。 */
    private static void captureAccount(Object[] params) {
        java.util.Set<String> found = new java.util.LinkedHashSet<>();
        collectWxid(params, found);
        if (found.isEmpty()) {
            return;
        }
        String preferred = Activation.wxid();
        if (preferred != null && found.contains(preferred)) {
            Activation.setRuntimeWxid(preferred);
            return;
        }
        Activation.setRuntimeWxid(found.iterator().next());
    }

    private static void collectWxid(Object value, java.util.Set<String> out) {
        if (value instanceof String text) {
            if (text.startsWith("wxid_")) {
                out.add(text);
            }
        } else if (value instanceof Object[] array) {
            for (Object item : array) {
                collectWxid(item, out);
            }
        }
    }
}
