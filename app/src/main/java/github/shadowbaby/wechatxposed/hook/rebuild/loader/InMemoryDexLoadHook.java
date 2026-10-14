package github.shadowbaby.wechatxposed.hook.rebuild.loader;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;
import java.util.ArrayList;
import java.util.Iterator;
import github.shadowbaby.wechatxposed.hook.rebuild.XorStrings;
import github.shadowbaby.wechatxposed.hook.rebuild.support.WxComponentHooks;

/**
 * InMemoryDexClassLoader 构造函数 hook(原混淆类 b.c)。
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

    /**
     * 原 b.c.<clinit> 的字符池。
     * 1..298 用 key=7403(组件类名与日志文案),299..364 用 key=17407(校验方法名)。
     */
    private static final short[] LOADER_POOL = {
            1657, 7338, 7303, 7303, 7371, 7311, 7310, 7315, 7371, 7306, 7303, 7321,
            7310, 7306, 7311, 7314, 7371, 7299, 7300, 7300, 7296, 7310, 7311, 7365,
            7304, 7300, 7302, 7365, 7309, 7296, 7313, 7299, 7306, 7301, 7308, 7365,
            7324, 7315, 7309, 7310, 7306, 7327, 7326, 7321, 7310, 7320, 7365, 7305,
            7306, 7320, 7310, 7365, 7356, 7321, 7306, 7323, 7323, 7310, 7321, 7365,
            7330, 7301, 7298, 7327, 7304, 7300, 7302, 7365, 7309, 7296, 7313, 7299,
            7306, 7301, 7308, 7365, 7324, 7310, 7304, 7299, 7306, 7327, 7315, 7323,
            7300, 7320, 7310, 7311, 7299, 7300, 7300, 7296, 7320, 7365, 7356, 7321,
            7306, 7323, 7323, 7310, 7321, 7365, 7331, 7300, 7300, 7296, 7356, 7321,
            7306, 7323, 7323, 7310, 7321, 7304, 7300, 7302, 7365, 7309, 7296, 7313,
            7299, 7306, 7301, 7308, 7365, 7324, 7315, 7309, 7310, 7306, 7327, 7326,
            7321, 7310, 7320, 7365, 7311, 7300, 7301, 7306, 7327, 7298, 7300, 7301,
            7365, 7356, 7321, 7306, 7323, 7323, 7310, 7321, 7365, 7330, 7301, 7298,
            7327, 7304, 7300, 7302, 7365, 7309, 7296, 7313, 7299, 7306, 7301, 7308,
            7365, 7324, 7315, 7309, 7310, 7306, 7327, 7326, 7321, 7310, 7320, 7365,
            7327, 7299, 7310, 7302, 7310, 7320, 7365, 7356, 7321, 7306, 7323, 7323,
            7310, 7321, 7365, 7330, 7301, 7298, 7327, 7330, 7308, 7301, 7300, 7321,
            7310, 7311, 7371, 7301, 7300, 7301, 7371, 7324, 7315, 7371, 7302, 7300,
            7311, 7326, 7303, 7310, 7371, 7311, 7310, 7315, 7365, 7337, 7306, 7320,
            7310, 7343, 7310, 7315, 7336, 7300, 7321, 7310, 7343, 7310, 7315, 7343,
            7300, 7301, 7306, 7327, 7298, 7300, 7301, 7343, 7310, 7315, 7359, 7299,
            7310, 7302, 7310, 7320, 7343, 7310, 7315, 7341, 7300, 7326, 7301, 7311,
            7371, 7367, 7371, 7310, 7301, 7306, 7305, 7303, 7310, 7377, 7371, 7371,
            7299, 7300, 7300, 7296, 7371, 7320, 7326, 7304, 7365, 7342, 7321, 7321,
            7300, 7321, 7371, 7327, 7300, 7371, 7299, 7300, 7300, 7296, 7371, 2299,
            17307, 17302, 17292, 17310, 17309, 17299, 17306, 17296, 17297, 17312, 17290, 17295,
            17307, 17310, 17291, 17306, 17312, 17308, 17303, 17306, 17308, 17300, 17295, 17293,
            17296, 17308, 17306, 17292, 17292, 17312, 17298, 17306, 17291, 17310, 17307, 17310,
            17291, 17310, 17290, 17295, 17307, 17310, 17291, 17306, 17331, 17302, 17308, 17306,
            17297, 17292, 17306, 17307, 17306, 17299, 17310, 17286, 17306, 17307, 17312, 17308,
            17303, 17306, 17308, 17300};

    private static final int TEXT_KEY = 7403;
    private static final int VERIFIER_KEY = 17407;

    private static final String ALL_DEX_HOOKED = decode(1, 23, TEXT_KEY);
    private static final String IGNORED_NON_MODULE_DEX = decode(199, 26, TEXT_KEY);
    private static final String LOG_FOUND = decode(259, 6, TEXT_KEY);
    private static final String LOG_ENABLE_SUFFIX = decode(265, 10, TEXT_KEY);
    private static final String LOG_HOOK_SUCCEEDED_SUFFIX = decode(275, 10, TEXT_KEY);

    /** 四个微X组件的入口类名,下标即 componentId。 */
    private static final String[] COMPONENT_ENTRY_CLASSES = {
            decode(24, 40, TEXT_KEY),   // 0 BaseDex
            decode(64, 49, TEXT_KEY),   // 1 CoreDex
            decode(113, 44, TEXT_KEY),  // 2 DonationDex
            decode(157, 42, TEXT_KEY)}; // 3 ThemesDex

    /** 备忘日志里的组件短名,下标即 componentId。 */
    private static final String[] COMPONENT_NAMES = {
            decode(225, 7, TEXT_KEY),   // "BaseDex"
            decode(232, 7, TEXT_KEY),   // "CoreDex"
            decode(239, 11, TEXT_KEY),  // "DonationDex"
            decode(250, 9, TEXT_KEY)};  // "ThemesDex"

    /** 被屏蔽的在线校验入口方法名。 */
    private static final String ON_UPDATE_CHECK = decode(307, 15, VERIFIER_KEY);
    private static final String DISABLE = decode(300, 7, VERIFIER_KEY);
    private static final String PROCESS_METADATA = decode(322, 16, VERIFIER_KEY);
    private static final String UPDATE_LICENSE = decode(338, 13, VERIFIER_KEY);
    private static final String DELAYED_CHECK = decode(351, 13, VERIFIER_KEY);

    private final int mode;

    public InMemoryDexLoadHook(int mode) {
        this.mode = mode;
    }

    @Override
    public void afterHookedMethod(MethodHookParam param) throws Throwable {
        super.afterHookedMethod(param);
        if (mode != DEX_LOADER || !(param.thisObject instanceof ClassLoader)) {
            return;
        }
        ClassLoader hostClassLoader = (ClassLoader) param.thisObject;

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

    private static String decode(int offset, int length, int key) {
        return XorStrings.decode(LOADER_POOL, offset, length, key);
    }
}