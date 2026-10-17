package github.shadowbaby.wechatxposed.hook.support;

import android.content.Context;
import github.shadowbaby.wechatxposed.hook.framework.HookFramework;
import github.shadowbaby.wechatxposed.hook.loader.InMemoryDexLoadHook;
import github.shadowbaby.wechatxposed.hook.loader.Secret;
import github.shadowbaby.wechatxposed.hook.loader.SecretConstants;

public final class WxComponentHooks {

    public static final int BASE_DEX = 0;

    public static final int CORE_DEX = 1;

    public static final int THEMES_DEX = 2;

    public static final int DONATION_DEX = 3;

    private static final String BASE_ENTRY_CLASS = Secret.of(SecretConstants.BASE_ENTRY_CLASS);
    private static final String BASE_ENTRY_METHOD = Secret.of(SecretConstants.BASE_ENTRY_METHOD);
    private static final String BASE_HOOK_ARGUMENT_CLASS =
            Secret.of(SecretConstants.BASE_HOOK_ARGUMENT_CLASS);

    private static final String WX_JNI_CORE_BRIDGE = Secret.of(SecretConstants.WX_JNI_CORE_BRIDGE);
    private static final String CALL_METHOD = Secret.of(SecretConstants.CALL_METHOD);

    private static final String CORE_VERIFIER_CLASS = Secret.of(SecretConstants.CORE_VERIFIER_CLASS);
    private static final String CORE_VERIFY_SIGNATURE_METHOD =
            Secret.of(SecretConstants.CORE_VERIFY_SIGNATURE_METHOD);
    private static final String CORE_VERIFY_BOOLEAN_STRING_METHOD =
            Secret.of(SecretConstants.CORE_VERIFY_BOOLEAN_STRING_METHOD);
    private static final String CORE_VERIFY_UPDATED_TIPS_METHOD =
            Secret.of(SecretConstants.CORE_VERIFY_UPDATED_TIPS_METHOD);

    private static final String CORE_POLLING_CLASS = Secret.of(SecretConstants.CORE_POLLING_CLASS);
    private static final String CORE_POLLING_METHOD = Secret.of(SecretConstants.CORE_POLLING_METHOD);

    private static final String CORE_LICENSE_CLASS = Secret.of(SecretConstants.CORE_LICENSE_CLASS);
    private static final String CORE_LICENSE_METHOD = Secret.of(SecretConstants.CORE_LICENSE_METHOD);

    private static final String THEMES_ENTRY_CLASS = Secret.of(SecretConstants.THEMES_ENTRY_CLASS);
    private static final String THEMES_ENTRY_METHOD = Secret.of(SecretConstants.THEMES_ENTRY_METHOD);
    private static final String THEMES_HOOK_ARGUMENT_CLASS =
            Secret.of(SecretConstants.THEMES_HOOK_ARGUMENT_CLASS);

    private static final String DONATION_ENTRY_CLASS = Secret.of(SecretConstants.DONATION_ENTRY_CLASS);
    private static final String DONATION_ENTRY_METHOD = Secret.of(SecretConstants.DONATION_ENTRY_METHOD);
    private static final String DONATION_HOOK_ARGUMENT_CLASS =
            Secret.of(SecretConstants.DONATION_HOOK_ARGUMENT_CLASS);

    public final int componentId;

    public WxComponentHooks(int componentId) {
        this.componentId = componentId;
    }

    public void inject(HookFramework framework, ClassLoader classLoader) {
        switch (componentId) {
            case BASE_DEX:
                hookBase(framework, classLoader);
                break;
            case CORE_DEX:
                hookCore(framework, classLoader);
                break;
            case THEMES_DEX:
                hookThemes(framework, classLoader);
                break;
            default:
                hookDonation(framework, classLoader);
                break;
        }
    }

    private void hookBase(HookFramework framework, ClassLoader classLoader) {
        Class<?> hookArgument = framework.findClass(BASE_HOOK_ARGUMENT_CLASS, classLoader);
        framework.hookMethod(framework.findClass(BASE_ENTRY_CLASS, classLoader), BASE_ENTRY_METHOD,
                new Class<?>[]{String.class, hookArgument},
                new InMemoryDexLoadHook(framework, InMemoryDexLoadHook.BASE_HANDSHAKE));
    }

    private void hookThemes(HookFramework framework, ClassLoader classLoader) {
        Class<?> hookArgument = framework.findClass(THEMES_HOOK_ARGUMENT_CLASS, classLoader);
        framework.hookMethod(framework.findClass(THEMES_ENTRY_CLASS, classLoader), THEMES_ENTRY_METHOD,
                new Class<?>[]{String.class, hookArgument},
                new InMemoryDexLoadHook(framework, InMemoryDexLoadHook.THEMES_HANDSHAKE));
    }

    private void hookDonation(HookFramework framework, ClassLoader classLoader) {
        Class<?> hookArgument = framework.findClass(DONATION_HOOK_ARGUMENT_CLASS, classLoader);
        framework.hookMethod(framework.findClass(DONATION_ENTRY_CLASS, classLoader),
                DONATION_ENTRY_METHOD,
                new Class<?>[]{String.class, hookArgument},
                new InMemoryDexLoadHook(framework, InMemoryDexLoadHook.DONATION_HANDSHAKE));
    }

    private void hookCore(HookFramework framework, ClassLoader classLoader) {

        framework.hookMethod(framework.findClass(WX_JNI_CORE_BRIDGE, classLoader), CALL_METHOD,
                new Class<?>[]{Integer.TYPE, Object[].class},
                new CallMethodBypassHook(framework, classLoader, CallMethodBypassHook.VERIFIER_MESSAGE));

        framework.hookMethod(framework.findClass(CORE_VERIFIER_CLASS, classLoader),
                CORE_VERIFY_SIGNATURE_METHOD,
                new Class<?>[]{Context.class},
                new CallMethodBypassHook(framework, classLoader, CallMethodBypassHook.LICENSE_CONTEXT));

        framework.hookMethod(framework.findClass(CORE_VERIFIER_CLASS, classLoader),
                CORE_VERIFY_BOOLEAN_STRING_METHOD,
                new Class<?>[]{Boolean.TYPE, String.class},
                new VerifierMethodReplacement(VerifierMethodReplacement.CHECK_API_REQUEST));

        framework.hookMethod(framework.findClass(CORE_POLLING_CLASS, classLoader),
                CORE_POLLING_METHOD,
                new Class<?>[]{},
                new VerifierMethodReplacement(VerifierMethodReplacement.POLLING_VERIFIER));

        framework.hookMethod(framework.findClass(CORE_VERIFIER_CLASS, classLoader),
                CORE_VERIFY_UPDATED_TIPS_METHOD,
                new Class<?>[]{},
                new VerifierMethodReplacement(VerifierMethodReplacement.UPDATED_TIPS));

        framework.hookMethod(framework.findClass(CORE_LICENSE_CLASS, classLoader),
                CORE_LICENSE_METHOD,
                new Class<?>[]{String.class, String.class},
                new CallMethodBypassHook(framework, classLoader, CallMethodBypassHook.PASSTHROUGH));
    }

}
