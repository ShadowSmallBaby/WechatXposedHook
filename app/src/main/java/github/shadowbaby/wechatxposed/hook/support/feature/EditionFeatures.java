package github.shadowbaby.wechatxposed.hook.support.feature;

import github.shadowbaby.wechatxposed.hook.BuildConfig;
import github.shadowbaby.wechatxposed.hook.license.Activation;
import github.shadowbaby.wechatxposed.hook.loader.util.Secret;

/**
 * 按发行版区分功能包是否内置。
 *
 * 公开版不带 sf/mf/af 三个扩展包，对应的 *_unlocked 查询必须保持 false，
 * 否则 LIC 与实际解锁位不一致，微X 会写禁用代码 0x329。
 * 后缀表在 native，Java 只保留发行版判断。
 */
public final class EditionFeatures {

    private EditionFeatures() {
    }

    public static boolean isUnavailableExt(String key) {
        if (BuildConfig.FULL_EDITION && Activation.isExtensionAllowed()) {
            return false;
        }
        return Secret.hintMatch(Secret.HINT_EXT_UNAVAILABLE, key);
    }
}
