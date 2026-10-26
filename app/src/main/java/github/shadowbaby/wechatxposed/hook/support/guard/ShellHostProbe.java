package github.shadowbaby.wechatxposed.hook.support.guard;

import github.shadowbaby.wechatxposed.hook.framework.HookCallback;
import github.shadowbaby.wechatxposed.hook.framework.HookFramework;
import github.shadowbaby.wechatxposed.hook.framework.HookParam;
import github.shadowbaby.wechatxposed.hook.loader.SecretConstants;
import github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import github.shadowbaby.wechatxposed.hook.loader.util.Secret;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 壳自带的更新/公告请求解析失败时只打一行 {@code X: Unable to resolve host}，
 * 看不出是谁发起的。这里对已知的壳域名打印一次调用栈，
 * 用来决定后续在哪一层拦截（更新任务、还是授权校验）。
 *
 * 只在 debug 包（VERBOSE_LOG）里安装；每次命中域名只打印一次。
 */
public final class ShellHostProbe implements HookCallback {

    private static final String[] HOSTS = {
            Secret.of(SecretConstants.SHELL_API_HOST),
            Secret.of(SecretConstants.SHELL_UPDATE_HOST)};

    private static final Set<String> LOGGED = ConcurrentHashMap.newKeySet();

    private ShellHostProbe() {
    }

    public static void install(HookFramework framework) {
        try {
            Class<?> target = framework.findClassIfExists("java.net.InetAddress", null);
            if (target == null) {
                return;
            }
            framework.hookMethod(target, "getAllByName",
                    new Class<?>[]{String.class}, new ShellHostProbe());
            ModuleLogger.debug("shell host probe: hooked");
        } catch (Throwable error) {
            ModuleLogger.log(error);
        }
    }

    @Override
    public void before(HookParam param) {
        String host = String.valueOf(param.arg(0));
        for (String name : HOSTS) {
            if (host.contains(name) && LOGGED.add(name)) {
                ModuleLogger.log("shell host: " + host + " from" + stack());
            }
        }
    }

    /** 拼一段调用栈，跳过 Xposed 与 okhttp 自身的帧，只留业务调用方。 */
    private static String stack() {
        StringBuilder builder = new StringBuilder();
        int appended = 0;
        for (StackTraceElement frame : new Throwable().getStackTrace()) {
            String text = frame.toString();
            if (text.contains("libxposed") || text.contains("LSPosed")
                    || text.contains("XposedBridge") || text.contains("WeXposedHook")
                    || text.contains("ShellHostProbe") || text.contains("XC_MethodHook")
                    || text.contains("LSPHooker_") || text.contains("j0.callback")
                    || text.contains("com.android.okhttp") || text.contains("java.net")
                    || text.startsWith("vT.")) {
                continue;
            }
            builder.append(" <- ").append(text);
            if (++appended >= 24) {
                break;
            }
        }
        return builder.toString();
    }
}
