package github.shadowbaby.wechatxposed.hook.support;

import github.shadowbaby.wechatxposed.hook.BuildConfig;

/**
 * 按发行版区分功能包是否内置。
 *
 * 公开版不带 sf/mf/af 三个扩展包，对应的 *_unlocked 查询必须保持 false，
 * 否则 LIC 与实际解锁位不一致，微X 会写禁用代码 0x329。
 */
final class EditionFeatures {

    private EditionFeatures() {
    }

    static boolean isUnavailableExt(String key) {
        if (BuildConfig.FULL_EDITION) {
            return false;
        }
        return key.endsWith("mf_unlocked") || key.endsWith("af_unlocked")
                || key.endsWith("sf_unlocked");
    }
}
