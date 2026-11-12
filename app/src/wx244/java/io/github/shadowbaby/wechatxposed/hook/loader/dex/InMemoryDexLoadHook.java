package io.github.shadowbaby.wechatxposed.hook.loader.dex;

import io.github.shadowbaby.wechatxposed.hook.support.guard.WxComponentRegistry;
import io.github.shadowbaby.wechatxposed.hook.support.guard.WxComponentHooks;
import io.github.shadowbaby.wechatxposed.hook.loader.SecretConstants;
import io.github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import io.github.shadowbaby.wechatxposed.hook.loader.util.Secret;
import io.github.shadowbaby.wechatxposed.shared.hook.HookCallback;
import io.github.shadowbaby.wechatxposed.shared.hook.HookFramework;
import io.github.shadowbaby.wechatxposed.shared.hook.HookParam;
import java.util.ArrayList;
import java.util.Iterator;

public final class InMemoryDexLoadHook implements HookCallback {

    public static final int DEX_LOADER = 0;

    public static final int BASE_HANDSHAKE = 1;

    public static final int THEMES_HANDSHAKE = 2;

    public static final int DONATION_HANDSHAKE = 3;

    private static final String[] COMPONENT_ENTRY_CLASSES = {
            Secret.of(SecretConstants.COMPONENT_BASE),
            Secret.of(SecretConstants.COMPONENT_CORE),
            Secret.of(SecretConstants.COMPONENT_THEMES),
            Secret.of(SecretConstants.COMPONENT_DONATION)};

    private static final String ON_UPDATE_CHECK = Secret.of(SecretConstants.METHOD_ON_UPDATE_CHECK);
    private static final String DISABLE = Secret.of(SecretConstants.METHOD_DISABLE);
    private static final String PROCESS_METADATA = Secret.of(SecretConstants.METHOD_PROCESS_METADATA);
    private static final String UPDATE_LICENSE = Secret.of(SecretConstants.METHOD_UPDATE_LICENSE);
    private static final String DELAYED_CHECK = Secret.of(SecretConstants.METHOD_DELAYED_CHECK);

    private final HookFramework framework;
    private final int mode;

    public InMemoryDexLoadHook(HookFramework framework, int mode) {
        this.framework = framework;
        this.mode = mode;
    }

    @Override
    public void after(HookParam param) {
        if (mode != DEX_LOADER || !(param.thisObject() instanceof ClassLoader hostClassLoader)) {
            return;
        }
        try {
            synchronized (WxComponentHooks.class) {
                ArrayList<WxComponentHooks> pending = WxComponentRegistry.WX_COMPONENTS;
                if (pending.isEmpty()) {
                    return;
                }
                Iterator<WxComponentHooks> iterator = pending.iterator();
                while (iterator.hasNext()) {
                    WxComponentHooks component = iterator.next();
                    if (framework.findClassIfExists(
                            COMPONENT_ENTRY_CLASSES[component.componentId],
                            hostClassLoader) == null) {
                        continue;
                    }
                    component.inject(framework, hostClassLoader);
                    iterator.remove();
                }
            }
        } catch (Throwable error) {
            ModuleLogger.log(error);
        }
    }

    @Override
    public void before(HookParam param) {
        if (mode == DEX_LOADER) {
            return;
        }
        String methodName = String.valueOf(param.arg(0));
        boolean block = ON_UPDATE_CHECK.equals(methodName);
        if (mode == BASE_HANDSHAKE) {
            block |= DISABLE.equals(methodName) || PROCESS_METADATA.equals(methodName);
        } else if (mode == DONATION_HANDSHAKE) {
            block |= DISABLE.equals(methodName) || UPDATE_LICENSE.equals(methodName)
                    || DELAYED_CHECK.equals(methodName);
        }
        if (block) {
            param.setResult(null);
        }
    }
}
