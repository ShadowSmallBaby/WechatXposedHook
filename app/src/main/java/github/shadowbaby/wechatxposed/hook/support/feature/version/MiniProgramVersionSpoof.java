package github.shadowbaby.wechatxposed.hook.support.feature.version;

import github.shadowbaby.wechatxposed.hook.framework.HookCallback;
import github.shadowbaby.wechatxposed.hook.framework.HookFramework;
import github.shadowbaby.wechatxposed.hook.framework.HookParam;
import github.shadowbaby.wechatxposed.hook.loader.SecretConstants;
import github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import github.shadowbaby.wechatxposed.hook.loader.util.Secret;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;

/**
 * 小程序版本伪装。
 *
 * 小程序启动 CGI 和随后的资源准备请求都在发送时读取全局 ClientVersion，
 * Java 层没有可参数级替换的入口，所以只在启动窗口内临时改高，
 * 启动回调后缩短、watchdog 兜底还原。窗口外不影响公众号/钱包。
 */
public final class MiniProgramVersionSpoof {

    /** 小程序启动 CGI 场景（WeChat 8.0.49）。 */
    private static final String LAUNCH_SCENE_CLASS =
            Secret.of(SecretConstants.LAUNCH_SCENE_CLASS);

    /** 启动 CGI 的场景回调方法（onGYNetEnd）。 */
    private static final String LAUNCH_SCENE_CALLBACK =
            Secret.of(SecretConstants.LAUNCH_SCENE_CALLBACK);

    /** 启动请求的兜底上限。 */
    private static final long LAUNCH_WINDOW_MS = 10_000L;

    /** 启动 CGI 回调后再保留的收尾时间。 */
    private static final long LAUNCH_GRACE_MS = 1_500L;

    private MiniProgramVersionSpoof() {
    }

    public static void install(HookFramework framework, ClassLoader classLoader) {
        try {
            Class<?> target = framework.findClassIfExists(LAUNCH_SCENE_CLASS, classLoader);
            if (target == null) {
                ModuleLogger.log("mini program: launch class missing " + LAUNCH_SCENE_CLASS);
                return;
            }
            int constructors = 0;
            for (Constructor<?> constructor : target.getDeclaredConstructors()) {
                framework.hookMethod(constructor, new HookCallback() {
                    @Override
                    public void before(HookParam param) {
                        if (!VersionWindow.open(framework, classLoader,
                                LAUNCH_WINDOW_MS, "launch")) {
                            ModuleLogger.log("mini program: launch window not ready");
                        }
                    }
                });
                constructors++;
            }
            int callbacks = 0;
            for (Method method : target.getDeclaredMethods()) {
                if (LAUNCH_SCENE_CALLBACK.equals(method.getName())
                        && method.getParameterCount() == 5) {
                    framework.hookMethod(method, new HookCallback() {
                        @Override
                        public void after(HookParam param) {
                            VersionWindow.shorten(LAUNCH_GRACE_MS);
                        }
                    });
                    callbacks++;
                }
            }
            ModuleLogger.log("mini program: launch hooked " + constructors
                    + " constructor(s), " + callbacks + " callback(s)");
        } catch (Throwable error) {
            ModuleLogger.log(error);
        }
    }
}
