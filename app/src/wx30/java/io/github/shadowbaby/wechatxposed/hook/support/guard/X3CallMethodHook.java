package io.github.shadowbaby.wechatxposed.hook.support.guard;

import io.github.shadowbaby.wechatxposed.hook.license.Activation;
import io.github.shadowbaby.wechatxposed.shared.hook.HookCallback;
import io.github.shadowbaby.wechatxposed.shared.hook.HookParam;
import io.github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import io.github.shadowbaby.wechatxposed.hook.loader.util.Secret;
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

    private static final String TAG_VIP = Secret.of(SecretConstants.X30_TAG_VIP);

    private static final String TAG_PRO = Secret.of(SecretConstants.X30_TAG_PRO);

    private static final java.util.Set<String> ADVANCED_FEATURES = java.util.Set.of(
            "multichat_autoforward",
            "moments_auto_forward",
            "secret_friend",
            "auto_accept_chatroom_invite",
            "integrated_mode");

    private static final String TRUE_TEXT = "true";

    private static final java.util.concurrent.atomic.AtomicInteger CALLS =
            new java.util.concurrent.atomic.AtomicInteger();
    private static final java.util.Set<Integer> SEEN =
            java.util.concurrent.ConcurrentHashMap.newKeySet();

    private static final java.util.Set<Integer> RESULTS =
            java.util.concurrent.ConcurrentHashMap.newKeySet();

    private static final int ENTRY_LOG_LIMIT = 30;

    public X3CallMethodHook() {
    }

    @Override
    public void before(HookParam param) {
        try {
            int msgId = (Integer) param.arg(0);
            int call = CALLS.incrementAndGet();
            Object[] params = (Object[]) param.arg(1);

            if (call <= ENTRY_LOG_LIMIT) {
                ModuleLogger.debug("X3 call #" + call + " msg=" + msgId
                        + " args=" + briefArgs(params));
            }

            captureAccount(msgId, params);
            if (SEEN.add(msgId)) {
                ModuleLogger.debug("X3 msg new: " + msgId);
            }

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

                if (Integer.valueOf(0).equals(queryType)
                        || Integer.valueOf(1).equals(queryType)
                        || Integer.valueOf(2).equals(queryType)) {
                    if (Integer.valueOf(2).equals(queryType)) {
                        String key = String.valueOf(params[2]);
                        if (REMOTE_COMMAND.equals(key)) {
                            return;
                        }

                        if (TAG_VIP.equals(key) || TAG_PRO.equals(key)) {
                            param.setResult(Boolean.FALSE);
                            return;
                        }

                        if (ADVANCED_FEATURES.contains(key)) {
                            param.setResult(Boolean.FALSE);
                            return;
                        }
                    }
                    param.setResult(Boolean.TRUE);
                } else if (Integer.valueOf(4).equals(queryType)) {
                    param.setResult(UNLIMITED);
                } else if (Integer.valueOf(6).equals(queryType)) {
                    param.setResult(features());
                }
            }
        } catch (Throwable error) {
            ModuleLogger.log(error);
        }
    }

    @Override
    public void after(HookParam param) {
        try {
            int msgId = (Integer) param.arg(0);
            if (!RESULTS.add(msgId)) {
                return;
            }
            ModuleLogger.debug("X3 result " + msgId + " = " + brief(param.result()));
        } catch (Throwable error) {
            ModuleLogger.log(error);
        }
    }

    private static String brief(Object value) {
        if (value == null) {
            return "null";
        }
        if (value instanceof byte[] bytes) {
            return "byte[" + bytes.length + "]";
        }
        if (value instanceof Object[] array) {
            return briefArgs(array);
        }
        String text = String.valueOf(value);
        return text.length() > 200 ? text.substring(0, 200) + "..." : text;
    }

    private static String briefArgs(Object[] args) {
        if (args == null) {
            return "null";
        }
        StringBuilder text = new StringBuilder("[");
        for (int i = 0; i < args.length; i++) {
            if (i > 0) {
                text.append(", ");
            }
            Object value = args[i];
            if (value instanceof byte[] bytes) {
                text.append("byte[").append(bytes.length).append(']');
            } else if (value instanceof Object[] nested) {
                text.append(briefArgs(nested));
            } else {
                String item = String.valueOf(value);
                text.append(item.length() > 120 ? item.substring(0, 120) + "..." : item);
            }
        }
        return text.append(']').toString();
    }

    private static String features() {
        StringBuilder text = new StringBuilder();
        for (String item : FEATURES.split(",")) {
            String value = item.trim();
            if (value.isEmpty() || ADVANCED_FEATURES.contains(value)) {
                continue;
            }
            if (text.length() > 0) {
                text.append(',');
            }
            text.append(value);
        }
        return text.toString();
    }

    private static void captureAccount(int msgId, Object[] params) {
        if (params == null) {
            return;
        }
        String account = null;
        if (msgId == MSG_FEATURE_QUERY && params.length > 1) {
            account = asAccount(params[1]);
        } else if (msgId == MSG_LICENSE_BLOB && params.length > 2) {
            account = asAccount(params[2]);
        }
        if (account != null) {
            Activation.setRuntimeWxid(account);
        }
    }

    private static String asAccount(Object value) {
        if (!(value instanceof String text)) {
            return null;
        }
        String trimmed = text.trim();
        return io.github.shadowbaby.wechatxposed.hook.license.Wxid.isReal(trimmed)
                ? trimmed : null;
    }
}
