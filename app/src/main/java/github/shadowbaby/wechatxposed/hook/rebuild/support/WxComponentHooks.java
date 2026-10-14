package github.shadowbaby.wechatxposed.hook.rebuild.support;

import android.content.Context;
import de.robv.android.xposed.XposedHelpers;
import github.shadowbaby.wechatxposed.hook.rebuild.XorStrings;
import github.shadowbaby.wechatxposed.hook.rebuild.loader.InMemoryDexLoadHook;

/**
 * 给一个已加载的微X组件 dex 装 hook(原混淆类 c.a)。
 *
 * 微X把功能拆成四个 dex,每个 dex 里的类名不同,钩法也不同:
 *   Base     —— 只做握手,让模块知道这个 dex 已经进来了
 *   Core     —— 六个 hook,是全部功能的核心:伪造 CallMethod 的授权返回、堵掉三处校验
 *   Themes   —— 只做握手
 *   Donation —— 只做握手
 *
 * 类名分两类:一类能直接写出来(WxJniCoreBridge),一类是微X自己混淆过的
 * (c. َˉ.ᴖˉ 之类),必须等 dex 加载完、拿到它的 ClassLoader 才能解析,
 * 所以这里把混淆名当普通字符串传给 findAndHookMethod。
 */
public final class WxComponentHooks {

    /** 微X的 Base 组件(com.fkzhang.wxfeatures.base)。 */
    public static final int BASEDEX = 0;

    /** 微X的 Core 组件(com.fkzhang.wechatxposedhooks),授权逻辑都在这里。 */
    public static final int COREDEX = 1;

    /** 微X的 Themes 组件(com.fkzhang.wxfeatures.themes)。 */
    public static final int THEMESDEX = 2;

    /** 微X的 Donation 组件(com.fkzhang.wxfeatures.donation)。 */
    public static final int DONATIONDEX = 3;

    /** 原 c.a.<clinit> 的字符池,key=52313。 */
    private static final short[] HOOK_POOL = {
            4477, 12847, -12641, -13193, -12656, -12664, -13187, -12570,
            -12019, 12847, -12641, -13193, -12571, -13952, -5080, -12571,
            -13254, -13258, -13260, -13193, -13249, -13262, -13277, -13263,
            -13256, -13257, -13250, -13193, -13266, -13252, -13254, -13263,
            -13256, -13267, -13279, -13271, -13258, -13270, -13252, -13251,
            -13263, -13258, -13258, -13262, -13270, -13193, -13298, -13279,
            -13293, -13257, -13264, -13286, -13258, -13269, -13252, -13285,
            -13269, -13264, -13251, -13250, -13252, -13286, -13256, -13259,
            -13259, -13292, -13252, -13267, -13263, -13258, -13251, -13254,
            -13193, 12847, -12656, -13193, -12019, -12656, -13779, -12571,
            -11973, -13254, -13193, -12654, -13193, -11973, -12664, -12654,
            -12009, -12649, -12655, -13254, -13193, 12847, -12656, -13193,
            -13799, -12654, -13799, -12654, -12019, -12650, -13193, -5080,
            -13952, -13187, -12570, -13779, -12019, -12650, -13193, -10114,
            -13952, -12650, -12653, 12847, -12649, -13193, -12574, -12649,
            -13187, 13255, -12650, 12847, -12649, -13193, -13799, -12641,
            -12572, -12569};

    private static final int POOL_KEY = 52313;

    // ---- Base 组件:入口类与方法 ----
    private static final String BASE_ENTRY_CLASS = decode(9, 5);
    private static final String BASE_ENTRY_METHOD = decode(14, 2);
    private static final String BASE_HOOK_ARGUMENT_CLASS = decode(1, 8);

    // ---- Core 组件:CallMethod 及其两个重载 ----
    private static final String WX_JNI_CORE_BRIDGE = decode(16, 45);
    private static final String CALL_METHOD = decode(61, 10);

    /** Core 里的授权校验类,挂三个方法。 */
    private static final String CORE_VERIFIER_CLASS = decode(71, 7);
    private static final String CORE_VERIFY_SIGNATURE_METHOD = decode(78, 2);
    private static final String CORE_VERIFY_BOOLEAN_STRING_METHOD = decode(80, 1);
    private static final String CORE_VERIFY_UPDATED_TIPS_METHOD = decode(89, 2);

    /** Core 里的轮询校验类。 */
    private static final String CORE_POLLING_CLASS = decode(81, 6);
    private static final String CORE_POLLING_METHOD = decode(87, 2);

    /** Core 里的授权查询类。 */
    private static final String CORE_LICENSE_CLASS = decode(91, 7);
    private static final String CORE_LICENSE_METHOD = decode(98, 2);

    // ---- Themes 组件:入口类与方法 ----
    private static final String THEMES_ENTRY_CLASS = decode(108, 5);
    private static final String THEMES_ENTRY_METHOD = decode(113, 2);
    private static final String THEMES_HOOK_ARGUMENT_CLASS = decode(100, 8);

    // ---- Donation 组件:入口类与方法 ----
    private static final String DONATION_ENTRY_CLASS = decode(123, 5);
    private static final String DONATION_ENTRY_METHOD = decode(128, 2);
    private static final String DONATION_HOOK_ARGUMENT_CLASS = decode(115, 8);

    /** 0=Base、1=Core、2=Themes、3=Donation。 */
    public final int componentId;

    public WxComponentHooks(int componentId) {
        this.componentId = componentId;
    }

    /** 给已加载的组件 dex 装 hook。 */
    public void inject(ClassLoader classLoader) {
        switch (componentId) {
            case BASEDEX:
                hookBase(classLoader);
                break;
            case COREDEX:
                hookCore(classLoader);
                break;
            case THEMESDEX:
                hookThemes(classLoader);
                break;
            default:
                hookDonation(classLoader);
                break;
        }
    }

    /** BaseDex:只挂入口方法做握手,不拦截任何行为。 */
    private void hookBase(ClassLoader classLoader) {
        Class<?> hookArgument = XposedHelpers.findClass(BASE_HOOK_ARGUMENT_CLASS, classLoader);
        XposedHelpers.findAndHookMethod(BASE_ENTRY_CLASS, classLoader, BASE_ENTRY_METHOD,
                String.class,
                hookArgument,
                new InMemoryDexLoadHook(InMemoryDexLoadHook.BASE_HANDSHAKE));
    }

    /** ThemesDex:只挂入口方法做握手。 */
    private void hookThemes(ClassLoader classLoader) {
        Class<?> hookArgument = XposedHelpers.findClass(THEMES_HOOK_ARGUMENT_CLASS, classLoader);
        XposedHelpers.findAndHookMethod(THEMES_ENTRY_CLASS, classLoader, THEMES_ENTRY_METHOD,
                String.class,
                hookArgument,
                new InMemoryDexLoadHook(InMemoryDexLoadHook.THEMES_HANDSHAKE));
    }

    /** DonationDex:只挂入口方法做握手。 */
    private void hookDonation(ClassLoader classLoader) {
        Class<?> hookArgument = XposedHelpers.findClass(DONATION_HOOK_ARGUMENT_CLASS, classLoader);
        XposedHelpers.findAndHookMethod(DONATION_ENTRY_CLASS, classLoader, DONATION_ENTRY_METHOD,
                String.class,
                hookArgument,
                new InMemoryDexLoadHook(InMemoryDexLoadHook.DONATION_HANDSHAKE));
    }

    /** CoreDex:六个 hook,决定授权校验是否被绕过。 */
    private void hookCore(ClassLoader classLoader) {
        // 1. CallMethod(int, Object[]):微X所有功能的总入口,按调用内容伪造返回值。
        XposedHelpers.findAndHookMethod(WX_JNI_CORE_BRIDGE, classLoader, CALL_METHOD,
                Integer.TYPE,
                Object[].class,
                new CallMethodBypassHook(classLoader, CallMethodBypassHook.VERIFIER_MESSAGE));

        // 2. CallMethod(Context):按授权上下文伪造返回值。
        XposedHelpers.findAndHookMethod(CORE_VERIFIER_CLASS, classLoader, CORE_VERIFY_SIGNATURE_METHOD,
                Context.class,
                new CallMethodBypassHook(classLoader, CallMethodBypassHook.LICENSE_CONTEXT));

        // 3. 校验接口请求:整体替换为固定返回值,不再发起请求。
        XposedHelpers.findAndHookMethod(CORE_VERIFIER_CLASS, classLoader, CORE_VERIFY_BOOLEAN_STRING_METHOD,
                Boolean.TYPE,
                String.class,
                new VerifierMethodReplacement(VerifierMethodReplacement.CHECK_API_REQUEST));

        // 4. 轮询校验:整体替换,不再轮询。
        XposedHelpers.findAndHookMethod(CORE_POLLING_CLASS, classLoader, CORE_POLLING_METHOD,
                new VerifierMethodReplacement(VerifierMethodReplacement.POLLING_VERIFIER));

        // 5. 更新提示:整体替换,不再弹提示。注意仍挂在 CORE_VERIFIER_CLASS 上。
        XposedHelpers.findAndHookMethod(CORE_VERIFIER_CLASS, classLoader, CORE_VERIFY_UPDATED_TIPS_METHOD,
                new VerifierMethodReplacement(VerifierMethodReplacement.UPDATED_TIPS));

        // 6. 授权查询:透传给原方法,只在结果上做修补。
        XposedHelpers.findAndHookMethod(CORE_LICENSE_CLASS, classLoader, CORE_LICENSE_METHOD,
                String.class,
                String.class,
                new CallMethodBypassHook(classLoader, CallMethodBypassHook.PASSTHROUGH));
    }

    private static String decode(int offset, int length) {
        return XorStrings.decode(HOOK_POOL, offset, length, POOL_KEY);
    }
}