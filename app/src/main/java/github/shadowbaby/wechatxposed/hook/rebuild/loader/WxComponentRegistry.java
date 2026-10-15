package github.shadowbaby.wechatxposed.hook.rebuild.loader;

import github.shadowbaby.wechatxposed.hook.rebuild.support.WxComponentHooks;
import java.util.ArrayList;
import java.util.List;

/**
 * 微X模块组件的待挂钩列表。
 *
 * 静态块按 Core → Base → Themes → Donation 的顺序登记四个组件,建好后不再改动,
 * InMemoryDexLoadHook 每发现一个微X dex 就摘掉对应的一项。
 */
public abstract class WxComponentRegistry {

    /** 待挂钩的组件,CORE_DEX / BASE_DEX / THEMES_DEX / DONATION_DEX。 */
    public static final ArrayList<WxComponentHooks> WX_COMPONENTS = new ArrayList<>(
            List.of(new WxComponentHooks(WxComponentHooks.CORE_DEX),
                    new WxComponentHooks(WxComponentHooks.BASE_DEX),
                    new WxComponentHooks(WxComponentHooks.THEMES_DEX),
                    new WxComponentHooks(WxComponentHooks.DONATION_DEX)));
}