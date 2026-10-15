package github.shadowbaby.wechatxposed.hook.rebuild.support;

import android.content.Context;
import de.robv.android.xposed.XposedHelpers;
import github.shadowbaby.wechatxposed.hook.rebuild.loader.InMemoryDexLoadHook;

/**
 * 给一个已加载的微X组件 dex 装 hook。
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
    public static final int BASE_DEX = 0;

    /** 微X的 Core 组件(com.fkzhang.wechatxposedhooks),授权逻辑都在这里。 */
    public static final int CORE_DEX = 1;

    /** 微X的 Themes 组件(com.fkzhang.wxfeatures.themes)。 */
    public static final int THEMES_DEX = 2;

    /** 微X的 Donation 组件(com.fkzhang.wxfeatures.donation)。 */
    public static final int DONATION_DEX = 3;

    // ---- Base 组件:入口类与方法 ----
    private static final String BASE_ENTRY_CLASS = "\uFE76\u02C6.\u02BC\u05D9";
    private static final String BASE_ENTRY_METHOD = "\u2071\u02BC";
    private static final String BASE_HOOK_ARGUMENT_CLASS = "\uFE76\u02C6.\u02C9\u02D1$\u02BF\u1D54";

    // ---- Core 组件:CallMethod 及其两个重载 ----
    private static final String WX_JNI_CORE_BRIDGE = "com.fkzhang.wechatxposedhooks.WxJniCoreBridge";
    private static final String CALL_METHOD = "CallMethod";

    /** Core 里的授权校验类,挂三个方法。 */
    private static final String CORE_VERIFIER_CLASS = "c.\uFE76\u02C9.\u1D54\u02C9";
    private static final String CORE_VERIFY_SIGNATURE_METHOD = "\u0674\u02BC";
    private static final String CORE_VERIFY_BOOLEAN_STRING_METHOD = "\u1D62";
    private static final String CORE_VERIFY_UPDATED_TIPS_METHOD = "\u02CE\u02C8";

    /** Core 里的轮询校验类。 */
    private static final String CORE_POLLING_CLASS = "c.\u02CB.\u1D62\u02D1";
    private static final String CORE_POLLING_METHOD = "\u02CB\u1D4E";

    /** Core 里的授权查询类。 */
    private static final String CORE_LICENSE_CLASS = "c.\uFE76\u02C9.\u0640\u02CB";
    private static final String CORE_LICENSE_METHOD = "\u0640\u02CB";

    // ---- Themes 组件:入口类与方法 ----
    private static final String THEMES_ENTRY_CLASS = "\u1D54\u02CF.\u1427\u05D9";
    private static final String THEMES_ENTRY_METHOD = "\u02CF\u02CA";
    private static final String THEMES_HOOK_ARGUMENT_CLASS = "\u1D54\u02CF.\u2071\u05D9$\u02BF\u0674";

    // ---- Donation 组件:入口类与方法 ----
    private static final String DONATION_ENTRY_CLASS = "\uFE76\u02CE.\u0640\u02C6";
    private static final String DONATION_ENTRY_METHOD = "\u02BD\u02BE";
    private static final String DONATION_HOOK_ARGUMENT_CLASS = "\uFE76\u02CE.\u02BB\u02CE$\uFF9E\u02CF";

    /** 0=Base、1=Core、2=Themes、3=Donation。 */
    public final int componentId;

    public WxComponentHooks(int componentId) {
        this.componentId = componentId;
    }

    /** 给已加载的组件 dex 装 hook。 */
    public void inject(ClassLoader classLoader) {
        switch (componentId) {
            case BASE_DEX:
                hookBase(classLoader);
                break;
            case CORE_DEX:
                hookCore(classLoader);
                break;
            case THEMES_DEX:
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

        // 6. 授权查询:不干预调用本身,只在结果上做修补。
        XposedHelpers.findAndHookMethod(CORE_LICENSE_CLASS, classLoader, CORE_LICENSE_METHOD,
                String.class,
                String.class,
                new CallMethodBypassHook(classLoader, CallMethodBypassHook.PASSTHROUGH));
    }

}