package io.github.shadowbaby.wechatxposed.tool.hook.feature.miniprogram;

import io.github.shadowbaby.wechatxposed.tool.hook.config.RuntimeSettings;
import io.github.shadowbaby.wechatxposed.tool.hook.config.ToolSettings;
import io.github.shadowbaby.wechatxposed.shared.hook.HookCallback;
import io.github.shadowbaby.wechatxposed.shared.hook.HookFramework;
import io.github.shadowbaby.wechatxposed.shared.hook.HookParam;
import io.github.shadowbaby.wechatxposed.tool.hook.framework.ToolLogger;
import java.lang.reflect.Method;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import org.json.JSONObject;
import static io.github.shadowbaby.wechatxposed.tool.hook.spoof.HostFingerprint.*;


public final class MiniProgramVersionGate {
    private static final Set<Method> HOOKED = ConcurrentHashMap.newKeySet();
    private static final AtomicLong SEQUENCE = new AtomicLong();
    private MiniProgramVersionGate() {}

    public static void install(HookFramework framework, ClassLoader loader) {
        installPrivateOpenUrl(framework, loader);
        try {
            Class<?> creator = framework.findClassIfExists(fp("mini.versionGate.launch.actionFactory.class"), loader);
            if (creator == null) return;
            Method method = fpMethod(creator, fp("mini.versionGate.launch.actionFactory.create.method"), "mini.versionGate.launch.actionFactory.create.signature");
            if (!HOOKED.add(method)) return;
            try {
                framework.hookMethod(method, new HookCallback() {
                    @Override public void before(HookParam param) {
                        ToolSettings settings = RuntimeSettings.get();
                        if (!settings.enabled || settings.miniProgramMode == ToolSettings.MINI_OFF
                                || param.hasThrowable()) return;
                        Object action = fpRead(param.arg(fpInt("mini.versionGate.launch.actionFactory.recordArg")), "mini.versionGate.launch.record.action");
                        String reason = MiniProgramVersionPolicy.reason(fpRead(action, "mini.versionGate.launch.action.code"),
                                fpRead(action, "mini.versionGate.launch.action.page"), fpRead(action, "mini.versionGate.launch.action.message"));
                        if (reason == null) return;

                        param.setResult(null);
                        if (settings.log) ToolLogger.log("mini version gate #" + SEQUENCE.incrementAndGet()
                                + " mode=" + settings.miniProgramMode + " blocked=" + reason);
                    }
                });
            } catch (Throwable error) { HOOKED.remove(method); throw error; }
        } catch (Throwable error) { ToolLogger.debug("mini version gate: action factory unavailable"); }
    }

    private static void installPrivateOpenUrl(HookFramework framework, ClassLoader loader) {
        try {
            Class<?> owner = framework.findClassIfExists(fp("mini.versionGate.privateApi.openUrl.class"), loader);
            if (owner == null) return;
            Method method = fpMethod(owner, fp("mini.versionGate.privateApi.openUrl.invoke.method"), "mini.versionGate.privateApi.openUrl.invoke.signature");
            if (!HOOKED.add(method)) return;
            try {
                framework.hookMethod(method, new HookCallback() {
                    @Override public void before(HookParam param) {
                        ToolSettings settings = RuntimeSettings.get();
                        if (!settings.enabled || settings.miniProgramMode == ToolSettings.MINI_OFF
                                || param.hasThrowable() || !(param.arg(fpInt("mini.versionGate.privateApi.openUrl.jsonArg")) instanceof JSONObject data)
                                || !MiniProgramVersionPolicy.updateUrl(data.optString(fp("mini.versionGate.before.url")))) return;
                        try {

                            JSONObject copy = new JSONObject();
                            var keys = data.keys();
                            while (keys.hasNext()) { String key = keys.next(); copy.put(key, data.get(key)); }
                            copy.put(fp("mini.versionGate.before.url"), "");
                            param.setArg(fpInt("mini.versionGate.privateApi.openUrl.jsonArg"), copy);
                            if (settings.log) ToolLogger.log("mini version gate #" + SEQUENCE.incrementAndGet()
                                    + " mode=" + settings.miniProgramMode + " blocked=private-update-url callback=fail");
                        } catch (Throwable error) { ToolLogger.debug("mini version gate: URL parameter copy failed"); }
                    }
                });
            } catch (Throwable error) { HOOKED.remove(method); throw error; }
        } catch (Throwable error) { ToolLogger.debug("mini version gate: private URL target unavailable"); }
    }

}
