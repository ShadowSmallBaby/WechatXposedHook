package io.github.shadowbaby.wechatxposed.tool.hook.feature.miniprogram;

import static io.github.shadowbaby.wechatxposed.tool.hook.spoof.HostFingerprint.*;

import io.github.shadowbaby.wechatxposed.tool.hook.config.RuntimeSettings;
import io.github.shadowbaby.wechatxposed.tool.hook.config.ToolSettings;
import io.github.shadowbaby.wechatxposed.shared.hook.HookCallback;
import io.github.shadowbaby.wechatxposed.shared.hook.HookFramework;
import io.github.shadowbaby.wechatxposed.shared.hook.HookParam;
import io.github.shadowbaby.wechatxposed.tool.hook.framework.ToolLogger;
import io.github.shadowbaby.wechatxposed.tool.hook.version.NetworkVersionSpoof;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import org.json.JSONObject;


public final class MiniProgramSpoof {
    private static boolean appBrandInstalled;
    private MiniProgramSpoof() {}

    public static synchronized void installAppBrand(HookFramework framework, ClassLoader loader) {
        if (appBrandInstalled) return;
        appBrandInstalled = true;
        MiniProgramLibrarySpoof.install(framework, loader);
        hookJsApi(framework, loader, fp("mini.environment.legacy.systemInfo.class"), fp("mini.environment.legacy.systemInfo.read.method"), "mini.environment.legacy.systemInfo.read.signature");
        hookJsApi(framework, loader, fp("mini.environment.legacy.deviceInfo.class"), fp("mini.environment.legacy.deviceInfo.read.method"), "mini.environment.legacy.deviceInfo.read.signature");
        hookJsApi(framework, loader, fp("mini.environment.api.systemInfo.class"), fp("mini.environment.api.systemInfo.read.method"),
                "mini.environment.api.systemInfo.read.signature");
        hookEnvironment(framework, loader);
        hookDirectEnvironment(framework, loader, fp("mini.environment.runtime.service.class"));
        hookDirectEnvironment(framework, loader, fp("mini.environment.runtime.gameService.class"));
        PackageVersionSpoof.install(framework, loader);
        NetworkVersionSpoof.installRequests(framework, loader);
        MiniProgramVersionGate.install(framework, loader);
    }

    private static boolean jsApiEnabled(ToolSettings settings) {
        return settings.enabled && settings.miniProgramMode == ToolSettings.MINI_JSAPI;
    }


    private static void hookEnvironment(HookFramework framework, ClassLoader loader) {
        try {
            Class<?> type = framework.findClassIfExists(fp("mini.environment.environment.builder.class"), loader);
            if (type == null) return;
            framework.hookMethod(fpMethod(type, fp("mini.environment.environment.assemble.method"), "mini.environment.environment.assemble.signature"),
                    new HookCallback() {
                        @Override public void before(HookParam param) {
                            ToolSettings settings = RuntimeSettings.get();
                            if (!jsApiEnabled(settings)) return;
                            if (fp("mini.environment.before.clientVersion").equals(param.arg(fpInt("mini.environment.environment.valuesArg"))) && param.arg(fpInt("mini.environment.environment.keyArg")) instanceof Number) {
                                param.setArg(fpInt("mini.environment.environment.keyArg"), settings.targetVersion);
                            } else if (fp("mini.environment.before.host").equals(param.arg(fpInt("mini.environment.environment.valuesArg"))) && param.arg(fpInt("mini.environment.environment.keyArg")) instanceof JSONObject host
                                    && fp("mini.environment.before.weChat").equals(host.optString(fp("mini.environment.before.env"))) && host.opt(fp("mini.environment.before.version")) instanceof Number) {
                                try {
                                    JSONObject copy = new JSONObject();
                                    Iterator<String> keys = host.keys();
                                    while (keys.hasNext()) {
                                        String key = keys.next();
                                        copy.put(key, host.get(key));
                                    }
                                    copy.put(fp("mini.environment.before.version"), settings.targetVersion);
                                    param.setArg(fpInt("mini.environment.environment.keyArg"), copy);
                                } catch (Throwable error) { ToolLogger.debug("mini JSAPI: host copy failed"); }
                            }
                        }
                    });
        } catch (Throwable error) { ToolLogger.debug("mini JSAPI: environment writer unavailable"); }
    }


    private static void hookDirectEnvironment(HookFramework framework, ClassLoader loader, String owner) {
        try {
            Class<?> type = framework.findClassIfExists(owner, loader);
            if (type == null) return;
            framework.hookMethod(fpMethod(type, fp("mini.environment.environment.read.method"), "mini.environment.environment.read.signature"), new HookCallback() {
                @Override public void after(HookParam param) {
                    ToolSettings settings = RuntimeSettings.get();
                    if (jsApiEnabled(settings) && !param.hasThrowable() && param.arg(fpInt("mini.environment.deviceInfo.contextArg")) instanceof JSONObject json
                            && json.opt(fp("mini.environment.after.clientVersion")) instanceof Number) {
                        try { json.put(fp("mini.environment.after.clientVersion"), settings.targetVersion); }
                        catch (Throwable error) { ToolLogger.debug("mini JSAPI: environment update failed"); }
                    }
                }
            });
        } catch (Throwable error) { ToolLogger.debug("mini JSAPI: adapter unavailable " + owner); }
    }


    private static void hookJsApi(HookFramework framework, ClassLoader loader,
            String owner, String name, String signatureKey) {
        try {
            Class<?> type = framework.findClassIfExists(owner, loader);
            if (type == null) return;
            Method method = fpMethod(type, name, signatureKey);
            if (!Map.class.isAssignableFrom(method.getReturnType())) return;
            framework.hookMethod(method, new HookCallback() {
                @Override public void after(HookParam param) {
                    ToolSettings settings = RuntimeSettings.get();
                    if (!jsApiEnabled(settings) || param.hasThrowable() || !(param.result() instanceof Map<?, ?> original)) return;
                    boolean nameVersion = original.get(fp("mini.environment.nameVersion.version")) instanceof String;
                    boolean clientVersion = original.get(fp("mini.environment.clientVersion.clientVersion")) instanceof Number;
                    if (!nameVersion && !clientVersion) return;
                    Map<Object, Object> copy = new HashMap<>(original);
                    if (nameVersion) copy.put(fp("mini.environment.after.version"), settings.targetVersionName);
                    if (clientVersion) copy.put(fp("mini.environment.after.clientVersion"), settings.targetVersion);
                    param.setResult(copy);
                }
            });
        } catch (Throwable error) { ToolLogger.debug("mini JSAPI: target unavailable " + owner + "#" + name); }
    }
}
