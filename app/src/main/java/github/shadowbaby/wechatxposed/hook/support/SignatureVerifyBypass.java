package github.shadowbaby.wechatxposed.hook.support;

import github.shadowbaby.wechatxposed.hook.framework.HookCallback;
import github.shadowbaby.wechatxposed.hook.framework.HookFramework;
import github.shadowbaby.wechatxposed.hook.framework.HookParam;
import github.shadowbaby.wechatxposed.hook.loader.ModuleLogger;

/**
 * 跳过对功能包的 SHA1withRSA 验签。
 *
 * 功能包由项目自签，不使用原始签名，因此在
 * {@code java.security.Signature.verify} 层对 SHA1withRSA 返回 true。
 *
 * 注意：同一进程内其它 SHA1withRSA 校验也会一并放行。
 */
public final class SignatureVerifyBypass implements HookCallback {

    private static final String ALGORITHM = "SHA1withRSA";
    private static final String LOG_BYPASS = "signature bypass: " + ALGORITHM;
    private static final String LOG_INSTALLED = "signature verifier hooked";

    private static boolean installed;

    private final HookFramework framework;

    private SignatureVerifyBypass(HookFramework framework) {
        this.framework = framework;
    }

    public static synchronized void install(HookFramework framework) {
        if (installed) {
            return;
        }
        try {
            Class<?> signature = framework.findClass("java.security.Signature", null);
            SignatureVerifyBypass bypass = new SignatureVerifyBypass(framework);
            framework.hookMethod(signature, "verify", new Class<?>[]{byte[].class}, bypass);
            framework.hookMethod(signature, "verify",
                    new Class<?>[]{byte[].class, Integer.TYPE, Integer.TYPE}, bypass);
            installed = true;
            ModuleLogger.log(LOG_INSTALLED);
        } catch (Throwable error) {
            ModuleLogger.log(error);
        }
    }

    @Override
    public void before(HookParam param) {
        try {
            Object algorithm = framework.callMethod(param.thisObject(), "getAlgorithm");
            if (ALGORITHM.equals(String.valueOf(algorithm))) {
                param.setResult(Boolean.TRUE);
                ModuleLogger.log(LOG_BYPASS);
            }
        } catch (Throwable ignored) {
            // 取不到算法就保持原行为
        }
    }
}
