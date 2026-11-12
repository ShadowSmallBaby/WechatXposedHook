package io.github.shadowbaby.wechatxposed.hook.support.guard;

import java.util.ArrayList;
import java.util.List;

public abstract class WxComponentRegistry {

    public static final ArrayList<WxComponentHooks> WX_COMPONENTS = new ArrayList<>(
            List.of(new WxComponentHooks(WxComponentHooks.CORE_DEX),
                    new WxComponentHooks(WxComponentHooks.BASE_DEX),
                    new WxComponentHooks(WxComponentHooks.THEMES_DEX),
                    new WxComponentHooks(WxComponentHooks.DONATION_DEX)));
}
