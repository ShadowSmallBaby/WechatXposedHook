package io.github.shadowbaby.wechatxposed.hook.support;

import io.github.shadowbaby.wechatxposed.shared.hook.HookCallback;
import io.github.shadowbaby.wechatxposed.shared.hook.HookParam;
import io.github.shadowbaby.wechatxposed.hook.loader.ModuleLogger;
import io.github.shadowbaby.wechatxposed.hook.loader.Secret;
import io.github.shadowbaby.wechatxposed.hook.loader.SecretConstants;


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
            if (SEEN.add(msgId)) {
            } else if (call <= 3) {
            }


            if (msgId == MSG_VERIFY_RESULT) {
                if (ACTION_PARAM.equals(String.valueOf(params[0]))) {
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
                        if (REMOTE_COMMAND.equals(key)) {
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
}
