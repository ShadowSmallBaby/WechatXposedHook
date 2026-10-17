package github.shadowbaby.wechatxposed.hook.loader;

import github.shadowbaby.wechatxposed.hook.support.WxComponentHooks;
import java.util.ArrayList;
import java.util.List;

public abstract class WxComponentRegistry {

    public static final ArrayList<WxComponentHooks> WX_COMPONENTS = new ArrayList<>(
            List.of(new WxComponentHooks(WxComponentHooks.CORE_DEX),
                    new WxComponentHooks(WxComponentHooks.BASE_DEX),
                    new WxComponentHooks(WxComponentHooks.THEMES_DEX),
                    new WxComponentHooks(WxComponentHooks.DONATION_DEX)));
}
