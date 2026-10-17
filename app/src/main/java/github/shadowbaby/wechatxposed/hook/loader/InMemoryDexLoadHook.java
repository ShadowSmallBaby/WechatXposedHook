package github.shadowbaby.wechatxposed.hook.loader;

import github.shadowbaby.wechatxposed.hook.framework.HookCallback;
import github.shadowbaby.wechatxposed.hook.framework.HookFramework;
import github.shadowbaby.wechatxposed.hook.framework.HookParam;
import github.shadowbaby.wechatxposed.hook.support.WxComponentHooks;
import java.util.ArrayList;
import java.util.Iterator;

public final class InMemoryDexLoadHook implements HookCallback {

    public static final int DEX_LOADER = 0;

    public static final int BASE_HANDSHAKE = 1;

    public static final int THEMES_HANDSHAKE = 2;

    public static final int DONATION_HANDSHAKE = 3;

    private static final String ALL_DEX_HOOKED = "all dex already hooked";
    private static final String IGNORED_NON_MODULE_DEX = "ignored non-module dex";
    private static final String LOG_FOUND = "found ";
    private static final String LOG_ENABLE_SUFFIX = ", enable: ";
    private static final String LOG_HOOK_SUCCEEDED_SUFFIX = " hooked";

    private static final String[] COMPONENT_ENTRY_CLASSES = {
            Secret.of(SecretConstants.COMPONENT_BASE),
            Secret.of(SecretConstants.COMPONENT_CORE),
            Secret.of(SecretConstants.COMPONENT_DONATION),
            Secret.of(SecretConstants.COMPONENT_THEMES)};

    private static final String[] COMPONENT_NAMES = {
            Secret.of(SecretConstants.COMPONENT_NAME_BASE),
            Secret.of(SecretConstants.COMPONENT_NAME_CORE),
            Secret.of(SecretConstants.COMPONENT_NAME_DONATION),
            Secret.of(SecretConstants.COMPONENT_NAME_THEMES)};

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

        synchronized (WxComponentHooks.class) {
            ArrayList<WxComponentHooks> pending = WxComponentRegistry.WX_COMPONENTS;
            if (pending.isEmpty()) {
                framework.log(ALL_DEX_HOOKED);
                return;
            }
            Iterator<WxComponentHooks> iterator = pending.iterator();
            while (iterator.hasNext()) {
                WxComponentHooks component = iterator.next();
                if (framework.findClassIfExists(
                        COMPONENT_ENTRY_CLASSES[component.componentId], hostClassLoader) == null) {
                    framework.log(IGNORED_NON_MODULE_DEX);
                    continue;
                }
                framework.log(LOG_FOUND + COMPONENT_NAMES[component.componentId]
                        + LOG_ENABLE_SUFFIX + Boolean.TRUE);
                component.inject(framework, hostClassLoader);
                framework.log(COMPONENT_NAMES[component.componentId] + LOG_HOOK_SUCCEEDED_SUFFIX);
                iterator.remove();
            }
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
