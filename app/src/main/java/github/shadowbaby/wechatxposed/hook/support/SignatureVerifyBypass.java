package github.shadowbaby.wechatxposed.hook.support;

import github.shadowbaby.wechatxposed.hook.framework.HookCallback;
import github.shadowbaby.wechatxposed.hook.framework.HookFramework;
import github.shadowbaby.wechatxposed.hook.framework.HookParam;
import github.shadowbaby.wechatxposed.hook.loader.ModuleLogger;

/**
 * 跳过微X 对功能包的 SHA1withRSA 验签。
 *
 * 微X 2.44 在 BaseDex 的 {@code Lﹶˆ/ٴʻ;.ᵎᵔ(File)Z} 里读取 {@code <body>_s} 并调用
 * {@code Signature.getInstance("SHA1withRSA")} 验签；3.0 的验签器在运行时 dex 里，
 * 类名不同，但最终都走 {@code java.security.Signature.verify}。
 *
 * 因此这里直接 hook 系统类，只对算法名为 SHA1withRSA 的验签返回 true。这样用
 * source 装配出来、没有作者私钥签名的 body 也能被加载。副作用是会同时放过微X
 * 其它 SHA1withRSA 校验（例如授权块），本模块本来就已经在绕过授权，影响可控；
 * 但微信进程里若还有其它 SHA1withRSA 校验也会被放过，需要注意。
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
