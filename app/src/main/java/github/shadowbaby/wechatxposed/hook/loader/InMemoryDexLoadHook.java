package github.shadowbaby.wechatxposed.hook.loader;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;
import java.util.ArrayList;
import java.util.Iterator;
import github.shadowbaby.wechatxposed.hook.support.WxComponentHooks;

/**
 * InMemoryDexClassLoader 构造函数 hook。
 *
 * 一个类承担两种角色,由构造参数 mode 选择:
 *   mode 0 —— 挂在 InMemoryDexClassLoader 构造函数上。afterHookedMethod 里检查刚加载的
 *             dex 是不是微X的四个组件之一,是就给它的 ClassLoader 装 hook 并从待办列表移除。
 *   mode 1/2/3 —— 作为回调挂在微X自身的入口方法上,beforeHookedMethod 里把在线校验调用
 *             (disable / on_update_check / process_metadata / updateLicense / delayed_check)
 *             直接返回 null 屏蔽掉。
 */
public final class InMemoryDexLoadHook extends XC_MethodHook {

    /** 挂载 InMemoryDexClassLoader 构造函数的实例。 */
    public static final int DEX_LOADER = 0;

    /** 握手回调,挂在微X的 BaseDex 入口上。 */
    public static final int BASE_HANDSHAKE = 1;

    /** 握手回调,挂在微X的 ThemesDex 入口上。 */
    public static final int THEMES_HANDSHAKE = 2;

    /** 握手回调,挂在微X的 DonationDex 入口上。 */
    public static final int DONATION_HANDSHAKE = 3;

    private static final String ALL_DEX_HOOKED = "all dex already hooked";
    private static final String IGNORED_NON_MODULE_DEX = "ignored non-module dex";
    private static final String LOG_FOUND = "found ";
    private static final String LOG_ENABLE_SUFFIX = ", enable: ";
    private static final String LOG_HOOK_SUCCEEDED_SUFFIX = " hooked";

    /** 四个微X组件的入口类名,下标即 componentId。 */
    private static final String[] COMPONENT_ENTRY_CLASSES = {
            "com.fkzhang.wxfeatures.base.Wrapper.Init",           // 0 BaseDex
            "com.fkzhang.wechatxposedhooks.Wrapper.HookWrapper",  // 1 CoreDex
            "com.fkzhang.wxfeatures.donation.Wrapper.Init",        // 2 DonationDex
            "com.fkzhang.wxfeatures.themes.Wrapper.Init"};         // 3 ThemesDex

    /** 备忘日志里的组件短名,下标即 componentId。 */
    private static final String[] COMPONENT_NAMES = {
            "BaseDex",
            "CoreDex",
            "DonationDex",
            "ThemesDex"};

    /** 被屏蔽的在线校验入口方法名。 */
    private static final String ON_UPDATE_CHECK = "on_update_check";
    private static final String DISABLE = "disable";
    private static final String PROCESS_METADATA = "process_metadata";
    private static final String UPDATE_LICENSE = "updateLicense";
    private static final String DELAYED_CHECK = "delayed_check";

    private final int mode;

    public InMemoryDexLoadHook(int mode) {
        this.mode = mode;
    }

    @Override
    public void afterHookedMethod(MethodHookParam param) throws Throwable {
        super.afterHookedMethod(param);
        if (mode != DEX_LOADER || !(param.thisObject instanceof ClassLoader hostClassLoader)) {
            return;
        }

        synchronized (WxComponentHooks.class) {
            ArrayList<WxComponentHooks> pending = WxComponentRegistry.WX_COMPONENTS;
            if (pending.isEmpty()) {
                ModuleLogger.log(ALL_DEX_HOOKED);
                return;
            }
            Iterator<WxComponentHooks> iterator = pending.iterator();
            while (iterator.hasNext()) {
                WxComponentHooks component = iterator.next();
                if (XposedHelpers.findClassIfExists(COMPONENT_ENTRY_CLASSES[component.componentId], hostClassLoader) == null) {
                    ModuleLogger.log(IGNORED_NON_MODULE_DEX);
                    continue;
                }
                ModuleLogger.log(LOG_FOUND + COMPONENT_NAMES[component.componentId]
                        + LOG_ENABLE_SUFFIX + Boolean.TRUE);
                component.inject(hostClassLoader);
                ModuleLogger.log(COMPONENT_NAMES[component.componentId] + LOG_HOOK_SUCCEEDED_SUFFIX);
                iterator.remove();
            }
        }
    }

    @Override
    public void beforeHookedMethod(MethodHookParam param) throws Throwable {
        super.beforeHookedMethod(param);
        if (mode == DEX_LOADER) {
            return;
        }
        String methodName = String.valueOf(param.args[0]);
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
