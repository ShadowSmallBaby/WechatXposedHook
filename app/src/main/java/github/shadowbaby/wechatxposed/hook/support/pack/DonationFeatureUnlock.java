package github.shadowbaby.wechatxposed.hook.support.pack;

import github.shadowbaby.wechatxposed.hook.framework.HookCallback;
import github.shadowbaby.wechatxposed.hook.framework.HookFramework;
import github.shadowbaby.wechatxposed.hook.framework.HookParam;
import github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import github.shadowbaby.wechatxposed.hook.loader.util.Secret;
import github.shadowbaby.wechatxposed.hook.loader.SecretConstants;

/**
 * 放行捐赠 keycard 功能包。
 *
 * DonationDex 的 {@code Lᵔˏ/ᐧי;->ʿٴ(String, Object[])Z} 是功能查询分发器：
 * 已注册的 key 走本地表，否则回落到宿主 native 判定。
 *
 * 关键点：{@code Lᵔˏ/ˎʿ;->run()} 会查询 {@code requires_fp_donation}，
 * 返回真时会调用 {@code unloadFeature("core")} 并清空三张功能注册表，
 * 因此这里必须压成 false，否则 sf/mf/af 的功能会被整表清掉。
 */
public final class DonationFeatureUnlock implements HookCallback {

    private static final String PREFIX = "fp_";

    /** 捐赠要求查询：true 会触发卸载并清空功能表。 */
    private static final String REQUIRES_DONATION = "requires_fp_donation";

    private static final String LOG_PREFIX = "donation unlock: ";

    private static final String REQUIRES_CLASS =
            Secret.of(SecretConstants.DONATION_REQUIRES_CLASS_V30);
    private static final String REQUIRES_METHOD =
            Secret.of(SecretConstants.DONATION_REQUIRES_METHOD_V30);

    private static boolean installed;

    /** 在 X 3.0 donation 组件的 ClassLoader 上安装判定 hook。 */
    public static synchronized void installIfPresent(HookFramework framework,
            ClassLoader classLoader) {
        if (installed || classLoader == null) {
            return;
        }
        try {
            Class<?> target = framework.findClassIfExists(REQUIRES_CLASS, classLoader);
            if (target == null) {
                return;
            }
            framework.hookMethod(target, REQUIRES_METHOD,
                    new Class<?>[]{String.class, Object[].class},
                    new DonationFeatureUnlock());
            installed = true;
            ModuleLogger.log("donation requires hooked: " + REQUIRES_CLASS + "." + REQUIRES_METHOD);
        } catch (Throwable error) {
            framework.log(error);
        }
    }

    @Override
    public void before(HookParam param) {
        Object[] args = param.args();
        if (args == null || args.length == 0) {
            return;
        }
        Object value = args[0];
        if (!(value instanceof String name)) {
            return;
        }
        String key = name.trim();
        String bare = key.startsWith(PREFIX) ? key.substring(PREFIX.length()) : key;
        ModuleLogger.debug(LOG_PREFIX + key);
        if (REQUIRES_DONATION.equals(bare)) {
            param.setResult(Boolean.TRUE);
            ModuleLogger.debug(LOG_PREFIX + key + " -> true");
            return;
        }
        if ("sf".equals(bare) || "mf".equals(bare) || "af".equals(bare)) {
            param.setResult(Boolean.TRUE);
        }
    }
}
