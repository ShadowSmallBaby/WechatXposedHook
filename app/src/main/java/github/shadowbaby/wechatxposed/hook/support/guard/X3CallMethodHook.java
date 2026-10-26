package github.shadowbaby.wechatxposed.hook.support.guard;

import github.shadowbaby.wechatxposed.hook.license.Activation;
import github.shadowbaby.wechatxposed.hook.support.feature.EditionFeatures;
import github.shadowbaby.wechatxposed.hook.support.pack.FeaturePackUnlock;
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

    /** 头部两个授权标签的查询 key；只有高级授权才为真。 */
    private static final String TAG_VIP = Secret.of(SecretConstants.X30_TAG_VIP);

    private static final String TAG_PRO = Secret.of(SecretConstants.X30_TAG_PRO);

    /** 只有高级授权才「已注册」的特性；普通授权要从 FEATURES 里剔掉。 */
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

    /** 每个消息号只记一次原始返回值，账号有可能从这里下来。 */
    private static final java.util.Set<Integer> RESULTS =
            java.util.concurrent.ConcurrentHashMap.newKeySet();

    /** 启动阶段记录前这么多次 CallMethod，确认账号到底有没有随参数下来。 */
    private static final int ENTRY_LOG_LIMIT = 30;

    public X3CallMethodHook() {
    }

    @Override
    public void before(HookParam param) {
        try {
            int msgId = (Integer) param.arg(0);
            int call = CALLS.incrementAndGet();
            Object[] params = (Object[]) param.arg(1);
            // 排查用：启动阶段记录前若干次调用，确认 132/150 有没有把账号带过来。
            if (call <= ENTRY_LOG_LIMIT) {
                ModuleLogger.debug("X3 call #" + call + " msg=" + msgId
                        + " args=" + briefArgs(params));
            }
            // 132/150 只在首次授权时出现，重启后 X3 不再发，wxid 会永远拿不到。
            // 任何一次 CallMethod 都顺手捞一遍，机器码授权才能算出来。
            captureAccount(msgId, params);
            if (SEEN.add(msgId)) {
                ModuleLogger.debug("X3 msg new: " + msgId);
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
                // 1 是「单个功能是否启用」，壳运行中定期复查，不返回 true 会逐个 closed。
                if (Integer.valueOf(0).equals(queryType)
                        || Integer.valueOf(1).equals(queryType)
                        || Integer.valueOf(2).equals(queryType)) {
                    if (Integer.valueOf(2).equals(queryType)) {
                        String key = String.valueOf(params[2]);
                        if (REMOTE_COMMAND.equals(key)
                                || EditionFeatures.isUnavailableExt(key)) {
                            return;
                        }
                        // 头部的 [VIP][专业] 就是这两个标签查询换来的；
                        // 普通授权不能置真，否则会冒充高级授权。
                        if (TAG_VIP.equals(key) || TAG_PRO.equals(key)) {
                            if (FeaturePackUnlock.currentLevel()
                                    < FeaturePackUnlock.LEVEL_PRO) {
                                param.setResult(Boolean.FALSE);
                                return;
                            }
                        }
                        // 关于页的「(已注册)」按功能名逐个查询，高级项普通授权返回 false。
                        if (ADVANCED_FEATURES.contains(key)
                                && FeaturePackUnlock.currentLevel()
                                < FeaturePackUnlock.LEVEL_PRO) {
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

    /** 记录壳自己返回的内容：账号可能是在返回值里传下来的。 */
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

    /** 普通授权只返回基础特性；高级项要等卡密授权后才「已注册」。 */
    private static String features() {
        if (FeaturePackUnlock.currentLevel() >= FeaturePackUnlock.LEVEL_PRO) {
            return FEATURES;
        }
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

    /**
     * 150 的 args[1]、132 的 args[2] 是当前账号。
     * 只从这两个固定位置取，避免把参数里的功能名/配置项当成账号。
     */
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
        return github.shadowbaby.wechatxposed.hook.license.Wxid.isReal(trimmed)
                ? trimmed : null;
    }
}
