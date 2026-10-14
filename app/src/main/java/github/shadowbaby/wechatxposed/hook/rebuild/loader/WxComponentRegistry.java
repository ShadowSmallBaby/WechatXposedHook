package github.shadowbaby.wechatxposed.hook.rebuild.loader;

import github.shadowbaby.wechatxposed.hook.rebuild.support.WxComponentHooks;
import java.util.ArrayList;
import java.util.List;

/**
 * 微X模块的描述列表(原混淆类 b.a)。
 *
 * 静态块按 Core → Base → Themes → Donation 的顺序登记四个组件,建好后不再改动,
 * InMemoryDexLoadHook 每发现一个微X dex 就摘掉对应的一项。
 */
public abstract class WxComponentRegistry {

    /** 待挂钩的组件,COREDEX / BASEDEX / THEMESDEX / DONATIONDEX。 */
    public static final ArrayList<WxComponentHooks> WX_COMPONENTS = new ArrayList<>(
            List.of(new WxComponentHooks(WxComponentHooks.COREDEX),
                    new WxComponentHooks(WxComponentHooks.BASEDEX),
                    new WxComponentHooks(WxComponentHooks.THEMESDEX),
                    new WxComponentHooks(WxComponentHooks.DONATIONDEX)));
}