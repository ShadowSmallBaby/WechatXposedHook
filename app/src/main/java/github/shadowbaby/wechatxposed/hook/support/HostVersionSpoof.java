package github.shadowbaby.wechatxposed.hook.support;

import github.shadowbaby.wechatxposed.hook.framework.HookCallback;
import github.shadowbaby.wechatxposed.hook.framework.HookFramework;
import github.shadowbaby.wechatxposed.hook.framework.HookParam;
import github.shadowbaby.wechatxposed.hook.loader.ModuleLogger;
import github.shadowbaby.wechatxposed.hook.loader.Secret;
import github.shadowbaby.wechatxposed.hook.loader.SecretConstants;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.List;
import org.json.JSONObject;

public final class HostVersionSpoof {

    private static final int FAKE_LIB_VERSION = 9999;

    private static final String[] LAUNCH_ANCHORS = {
            Secret.of(SecretConstants.LAUNCH_ANCHOR_CGI),
            Secret.of(SecretConstants.LAUNCH_ANCHOR_CTOR)};

    private static final String[] OPEN_URL_ANCHORS = {
            Secret.of(SecretConstants.OPEN_URL_ANCHOR_MAIN),
            Secret.of(SecretConstants.OPEN_URL_ANCHOR_APPID),
            Secret.of(SecretConstants.OPEN_URL_ANCHOR_STYLE)};

    private static final String[] UPGRADE_URLS = {
            Secret.of(SecretConstants.UPGRADE_URL_1),
            Secret.of(SecretConstants.UPGRADE_URL_2)};

    private static final int LIB_VERSION_INDEX = 6;

    private static boolean installed;

    private static final String LOG = ModuleLogger.HOST_SPOOF_PREFIX;
    private static final String LOG_NO_DEX = LOG + "no dex, skipped";
    private static final String KEY_URL = "url";

    private HostVersionSpoof() {
    }

    public static synchronized void install(HookFramework framework, ClassLoader classLoader,
            String sourceDir) {
        if (installed) {
            return;
        }
        installed = true;
        try {
            List<byte[]> dexBytes = DexPaths.of(sourceDir);
            if (dexBytes.isEmpty()) {
                ModuleLogger.log(LOG_NO_DEX);
                return;
            }
            int constructors = 0;
            int methods = 0;
            for (byte[] bytes : dexBytes) {
                DexStrings dex = DexStrings.open(bytes);
                if (dex == null) {
                    continue;
                }
                constructors += hookLaunchConstructors(
                        framework, classLoader, dex.classesContaining(LAUNCH_ANCHORS));
                methods += hookOpenUrl(framework, classLoader, dex.classesContaining(OPEN_URL_ANCHORS));
            }
            ModuleLogger.log(LOG + constructors + " ctor, " + methods + " openUrl hooked");
        } catch (Throwable error) {
            ModuleLogger.log(error);
        }
    }

    private static int hookLaunchConstructors(HookFramework framework, ClassLoader classLoader,
            List<String> classes) {
        int count = 0;
        for (String name : classes) {
            Class<?> target = framework.findClassIfExists(name, classLoader);
            if (target == null) {
                continue;
            }
            for (Constructor<?> constructor : target.getDeclaredConstructors()) {
                Class<?>[] parameters = constructor.getParameterTypes();
                if (parameters.length <= LIB_VERSION_INDEX
                        || parameters[LIB_VERSION_INDEX] != Integer.TYPE) {
                    continue;
                }
                framework.hookMethod(constructor, new HookCallback() {
                    @Override
                    public void before(HookParam param) {
                        param.args()[LIB_VERSION_INDEX] = FAKE_LIB_VERSION;
                    }
                });
                count++;
            }
        }
        return count;
    }

    private static int hookOpenUrl(HookFramework framework, ClassLoader classLoader,
            List<String> classes) {
        int count = 0;
        for (String name : classes) {
            Class<?> target = framework.findClassIfExists(name, classLoader);
            if (target == null) {
                continue;
            }
            for (Method method : target.getDeclaredMethods()) {
                if (!isOpenUrlSignature(method)) {
                    continue;
                }
                framework.hookMethod(method, new HookCallback() {
                    @Override
                    public void before(HookParam param) {
                        clearUpgradeUrl(param);
                    }
                });
                count++;
            }
        }
        return count;
    }

    private static boolean isOpenUrlSignature(Method method) {
        Class<?>[] parameters = method.getParameterTypes();
        return parameters.length == 3
                && "org.json.JSONObject".equals(parameters[1].getName())
                && parameters[2] == Integer.TYPE
                && method.getReturnType() == Void.TYPE;
    }

    private static void clearUpgradeUrl(HookParam param) {
        if (!(param.arg(1) instanceof JSONObject json)) {
            return;
        }
        String url = json.optString(KEY_URL);
        if (url.isEmpty()) {
            return;
        }
        for (String upgrade : UPGRADE_URLS) {
            if (url.equals(upgrade) || url.startsWith(upgrade + "/")
                    || url.startsWith(upgrade + "?") || url.startsWith(upgrade + "#")) {
                try {
                    json.put(KEY_URL, "");
                } catch (Throwable ignored) {

                }
                return;
            }
        }
    }
}
