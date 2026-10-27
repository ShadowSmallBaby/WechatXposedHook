package github.shadowbaby.wechatxposed.hook.support.pack;

import github.shadowbaby.wechatxposed.hook.framework.HookCallback;
import github.shadowbaby.wechatxposed.hook.framework.HookFramework;
import github.shadowbaby.wechatxposed.hook.framework.HookParam;
import github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import github.shadowbaby.wechatxposed.hook.loader.util.Secret;

/**
 * 捕获宿主解密功能包外层时使用的 PBE password。
 *
 * 只观察 {@link javax.crypto.spec.PBEKeySpec} 的 char[] 构造；salt 与
 * password 的映射、组件判定都在 native（Secret.pbePlan），Java 只负责
 * 替换 password 并通知 FeatureDexInjector 注入离线解出的 classes.dex。
 */
public final class PbePasswordHook implements HookCallback {

    private static boolean installed;

    private PbePasswordHook() {
    }

    public static synchronized void install(HookFramework framework) {
        if (installed) {
            return;
        }
        // 先占位，异常重试时不再重复挂构造器；PBEKeySpec 缺失则放回去允许重试。
        installed = true;
        try {
            Class<?> spec = framework.findClassIfExists(
                    "javax.crypto.spec.PBEKeySpec", null);
            if (spec == null) {
                installed = false;
                return;
            }
            framework.hookConstructors(spec, new PbePasswordHook());
            ModuleLogger.debug("pbe password hook installed");
        } catch (Throwable error) {
            framework.log(error);
        }
    }

    @Override
    public void before(HookParam param) {
        Object[] args = param.args();
        if (args == null || args.length == 0 || !(args[0] instanceof char[] password)) {
            return;
        }
        if (args.length <= 1 || !(args[1] instanceof byte[] saltBytes)) {
            return;
        }
        String plan = Secret.pbePlan(hex(saltBytes));
        if (plan == null) {
            return;
        }
        int separator = plan.indexOf('|');
        if (separator < 0) {
            return;
        }
        String original = plan.substring(0, separator);
        if (!original.isEmpty() && !original.equals(new String((char[]) password))) {
            param.setArg(0, original.toCharArray());
        }
        String feature = plan.substring(separator + 1);
        if (!feature.isEmpty()) {
            FeatureDexInjector.onFeature(feature);
        }
    }

    private static String hex(byte[] data) {
        StringBuilder text = new StringBuilder(data.length * 2);
        for (byte value : data) {
            text.append(String.format("%02x", value));
        }
        return text.toString();
    }
}
