package github.shadowbaby.wechatxposed.hook.support;

import github.shadowbaby.wechatxposed.hook.framework.HookCallback;
import github.shadowbaby.wechatxposed.hook.framework.HookParam;
import github.shadowbaby.wechatxposed.hook.loader.ModuleLogger;

/**
 * 放行捐赠 keycard 功能包。
 *
 * DonationDex 的 {@code Lᵔˏ/ᐧי;->ʿٴ(String, Object[])Z}（requires_fp_donation）
 * 会判断 fp_sf / fp_mf / fp_af 是否受当前捐赠档位限制。这里只对这三个包返回
 * true，其它查询保持原逻辑。
 */
public final class DonationFeatureUnlock implements HookCallback {

    private static final String PREFIX = "fp_";

    private static final String LOG_PREFIX = "donation unlock: ";

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
        if (key.startsWith(PREFIX)) {
            key = key.substring(PREFIX.length());
        }
        if ("sf".equals(key) || "mf".equals(key) || "af".equals(key)) {
            param.setResult(Boolean.TRUE);
            ModuleLogger.debug(LOG_PREFIX + name);
        }
    }
}
