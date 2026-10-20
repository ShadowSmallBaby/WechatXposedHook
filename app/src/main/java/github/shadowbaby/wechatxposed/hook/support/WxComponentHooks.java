package github.shadowbaby.wechatxposed.hook.support;

import android.content.Context;
import github.shadowbaby.wechatxposed.hook.BuildConfig;
import github.shadowbaby.wechatxposed.hook.framework.HookFramework;
import github.shadowbaby.wechatxposed.hook.loader.InMemoryDexLoadHook;
import github.shadowbaby.wechatxposed.hook.loader.Secret;
import github.shadowbaby.wechatxposed.hook.loader.SecretConstants;
import java.lang.reflect.Field;

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
    private static final String CORE_DISABLE_SETTER =
            Secret.of(SecretConstants.CORE_DISABLE_SETTER);
    private static final String CORE_DISABLE_GETTER =
            Secret.of(SecretConstants.CORE_DISABLE_GETTER);
    private static final String CORE_STATUS_CHECK =
            Secret.of(SecretConstants.CORE_STATUS_CHECK);
    private static final String CORE_VERIFIER_FACTORY =
            Secret.of(SecretConstants.CORE_VERIFIER_FACTORY);
    private static final String CORE_VERIFIER_CLASS_V2 =
            Secret.of(SecretConstants.CORE_VERIFIER_CLASS_V2);
    private static final String CORE_DISABLE_SETTER_V2 =
            Secret.of(SecretConstants.CORE_DISABLE_SETTER_V2);
    private static final String CORE_DISABLE_GETTER_V2 =
            Secret.of(SecretConstants.CORE_DISABLE_GETTER_V2);
    private static final String CORE_STATUS_CHECK_V2 =
            Secret.of(SecretConstants.CORE_STATUS_CHECK_V2);
    private static final String CORE_VERIFIER_INSTANCE_V2 =
            Secret.of(SecretConstants.CORE_VERIFIER_INSTANCE_V2);

    private static final HookSpec[] DISABLE_SPECS = {
            new HookSpec(CORE_VERIFIER_CLASS, CORE_DISABLE_SETTER, CORE_DISABLE_GETTER,
                    CORE_STATUS_CHECK, CORE_VERIFIER_FACTORY, null),
            new HookSpec(CORE_VERIFIER_CLASS_V2, CORE_DISABLE_SETTER_V2, CORE_DISABLE_GETTER_V2,
                    CORE_STATUS_CHECK_V2, null, CORE_VERIFIER_INSTANCE_V2)};

    private static boolean disableHooksInstalled;

    private static final String THEMES_ENTRY_CLASS = Secret.of(SecretConstants.THEMES_ENTRY_CLASS);
    private static final String THEMES_ENTRY_METHOD = Secret.of(SecretConstants.THEMES_ENTRY_METHOD);
    private static final String THEMES_HOOK_ARGUMENT_CLASS =
            Secret.of(SecretConstants.THEMES_HOOK_ARGUMENT_CLASS);

    private static final String DONATION_ENTRY_CLASS = Secret.of(SecretConstants.DONATION_ENTRY_CLASS);
    private static final String DONATION_ENTRY_METHOD = Secret.of(SecretConstants.DONATION_ENTRY_METHOD);
    private static final String DONATION_HOOK_ARGUMENT_CLASS =
            Secret.of(SecretConstants.DONATION_HOOK_ARGUMENT_CLASS);

    /** sf/mf/af 仅在完整版内置，公开版不装这个放行。 */
    private static final String DONATION_REQUIRES_CLASS =
            Secret.of(SecretConstants.DONATION_REQUIRES_CLASS);
    private static final String DONATION_REQUIRES_METHOD =
            Secret.of(SecretConstants.DONATION_REQUIRES_METHOD);

    private static boolean donationRequiresHooked;

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
        installDonationRequires(framework, classLoader);
    }

    /**
     * donation loader 里安装 sf/mf/af 的放行。
     *
     * 只有完整版才内置这三个扩展包，公开版跳过。
     */
    private void installDonationRequires(HookFramework framework, ClassLoader classLoader) {
        if (!BuildConfig.FULL_EDITION) {
            return;
        }
        synchronized (WxComponentHooks.class) {
            if (donationRequiresHooked) {
                return;
            }
            try {
                Class<?> requires = framework.findClassIfExists(
                        DONATION_REQUIRES_CLASS, classLoader);
                if (requires == null) {
                    return;
                }
                framework.hookMethod(requires, DONATION_REQUIRES_METHOD,
                        new Class<?>[]{String.class, Object[].class},
                        new DonationFeatureUnlock());
                donationRequiresHooked = true;
                framework.log("donation requires hooked: " + DONATION_REQUIRES_CLASS
                        + "." + DONATION_REQUIRES_METHOD);
            } catch (Throwable error) {
                framework.log(error);
            }
        }
    }

    private void hookCore(HookFramework framework, ClassLoader classLoader) {
        startDisableHookInstaller(framework, classLoader);

        framework.hookMethod(framework.findClass(WX_JNI_CORE_BRIDGE, classLoader), CALL_METHOD,
                new Class<?>[]{Integer.TYPE, Object[].class},
                new CallMethodBypassHook(framework, classLoader, CallMethodBypassHook.VERIFIER_MESSAGE));

        framework.hookMethod(framework.findClass(CORE_VERIFIER_CLASS, classLoader),
                CORE_VERIFY_SIGNATURE_METHOD,
                new Class<?>[]{Context.class},
                new CallMethodBypassHook(framework, classLoader, CallMethodBypassHook.LICENSE_CONTEXT));

        try {
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
                    new CallMethodBypassHook(framework, classLoader,
                            CallMethodBypassHook.PASSTHROUGH));
        } catch (Throwable error) {
            framework.log(error);
        }
    }

    private void startDisableHookInstaller(HookFramework framework, ClassLoader classLoader) {
        synchronized (WxComponentHooks.class) {
            if (disableHooksInstalled) {
                return;
            }
        }
        Thread thread = new Thread(new DisableHookInstaller(framework, classLoader),
                "wxh-disable-hooks");
        thread.setDaemon(true);
        thread.start();
    }

    private static final class HookSpec {

        final String className;
        final String setter;
        final String getter;
        final String status;
        final String factory;
        final String instanceField;

        HookSpec(String className, String setter, String getter, String status,
                 String factory, String instanceField) {
            this.className = className;
            this.setter = setter;
            this.getter = getter;
            this.status = status;
            this.factory = factory;
            this.instanceField = instanceField;
        }
    }

    private static final class DisableHookInstaller implements Runnable {

        private final HookFramework framework;

        private final ClassLoader classLoader;

        DisableHookInstaller(HookFramework framework, ClassLoader classLoader) {
            this.framework = framework;
            this.classLoader = classLoader;
        }

        @Override
        public void run() {
            boolean[] installed = new boolean[DISABLE_SPECS.length];
            for (int attempt = 0; attempt < 40; attempt++) {
                boolean all = true;
                for (int index = 0; index < DISABLE_SPECS.length; index++) {
                    if (installed[index]) {
                        continue;
                    }
                    all = false;
                    HookSpec spec = DISABLE_SPECS[index];
                    try {
                        Class<?> core = framework.findClassIfExists(
                                spec.className, classLoader);
                        if (core == null) {
                            continue;
                        }
                        framework.hookMethod(core, spec.setter,
                                new Class<?>[]{Integer.TYPE}, new DisableCodeLog());
                        framework.hookMethod(core, spec.getter,
                                new Class<?>[]{}, new DisableCodeClear());
                        framework.hookMethod(core, spec.status,
                                new Class<?>[]{}, new StatusCheckSkip());
                        installed[index] = true;
                        framework.log("disable hooks installed: " + spec.className);
                        clearDisableCode(core, spec);
                    } catch (Throwable error) {
                        framework.log(error);
                    }
                }
                if (all) {
                    synchronized (WxComponentHooks.class) {
                        disableHooksInstalled = true;
                    }
                    return;
                }
                try {
                    Thread.sleep(500L);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
            framework.log("disable hooks not installed");
        }

        private void clearDisableCode(Class<?> core, HookSpec spec) {
            try {
                Object instance = null;
                if (spec.instanceField != null) {
                    Field field = core.getDeclaredField(spec.instanceField);
                    field.setAccessible(true);
                    instance = field.get(null);
                } else if (spec.factory != null) {
                    instance = framework.callStaticMethod(core, spec.factory);
                }
                if (instance != null) {
                    framework.callMethod(instance, spec.setter, 0);
                }
            } catch (Throwable error) {
                framework.log(error);
            }
        }
    }

}
