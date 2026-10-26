package github.shadowbaby.wechatxposed.hook.support.feature;

import github.shadowbaby.wechatxposed.hook.license.Activation;
import github.shadowbaby.wechatxposed.hook.loader.util.Secret;

/**
 * sf/mf/af 三个扩展包的解锁位。
 *
 * 未解锁时对应的 *_unlocked 查询必须保持 false，否则 LIC 与实际解锁位不一致，
 * 微X 会写禁用代码 0x329。后缀表在 native，Java 只保留授权判断。
 */
public final class EditionFeatures {

    private EditionFeatures() {
    }

    public static boolean isUnavailableExt(String key) {
        if (Activation.isExtensionAllowed()) {
            return false;
        }
        return Secret.hintMatch(Secret.HINT_EXT_UNAVAILABLE, key);
    }
}
