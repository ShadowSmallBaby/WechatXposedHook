package io.github.shadowbaby.wechatxposed.tool.hook.feature.call;

import io.github.shadowbaby.wechatxposed.tool.hook.config.RuntimeSettings;
import io.github.shadowbaby.wechatxposed.tool.hook.config.ToolSettings;
import io.github.shadowbaby.wechatxposed.shared.hook.HookCallback;
import io.github.shadowbaby.wechatxposed.shared.hook.HookFramework;
import io.github.shadowbaby.wechatxposed.shared.hook.HookParam;
import io.github.shadowbaby.wechatxposed.tool.hook.framework.ToolLogger;
import java.lang.reflect.Method;
import java.util.Collections;
import java.util.Set;
import java.util.WeakHashMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import static io.github.shadowbaby.wechatxposed.tool.hook.spoof.HostFingerprint.*;


public final class CallSdkModeSpoof {
    private static final Set<Method> HOOKED = ConcurrentHashMap.newKeySet();
    private static final Set<Object> HELPERS = Collections.newSetFromMap(new WeakHashMap<>());
    private static final AtomicLong SEQUENCE = new AtomicLong();
    private static boolean gateInitialized, lastGate;
    private CallSdkModeSpoof() {}

    public static void install(HookFramework framework, ClassLoader loader) {
        onSettingsChanged(RuntimeSettings.get());

        trackHelper(framework, loader, fp("call.sdk.helper.primary.class"));
        trackHelper(framework, loader, fp("call.sdk.helper.alternate.class"));
        try {
            Class<?> responseType = framework.findClass(fp("call.sdk.response.class"), loader);
            fpValidate(responseType, "call.sdk.response.mode", false, true);
            Class<?> wrapper = framework.findClass(fp("call.sdk.wrapper.class"), loader);
            Method parser = fpMethod(wrapper, fp("call.sdk.response.parse.method"), "call.sdk.install.fromProtoBuf.signature");
            if (!HOOKED.add(parser)) return;
            try {
                framework.hookMethod(parser, new HookCallback() {
                    @Override public void after(HookParam param) {
                        ToolSettings settings = RuntimeSettings.get();
                        if (!settings.enabled || !settings.call || param.hasThrowable()
                                || !Integer.valueOf(0).equals(param.result())) return;
                        Object response = fpRead(param.thisObject(), "call.sdk.wrapper.payload");
                        if (response == null || response.getClass() != responseType) return;
                        try {

                            Object base = fpCall(framework, response, "call.sdk.response.baseResponse.read");
                            if (!Integer.valueOf(0).equals(fpRead(base, "call.sdk.baseResponse.ret"))) return;
                            int serverMode = (Integer) fpRequire(response, "call.sdk.response.mode");

                            if (serverMode == fpInt("call.sdk.mode.legacy")) fpWrite(response, "call.sdk.response.mode", fpInt("call.sdk.mode.modern"));
                            ToolLogger.debug("call sdk mode #" + SEQUENCE.incrementAndGet()
                                    + " server=" + serverMode + " effective=" + fpRequire(response, "call.sdk.response.mode")
                                    + " Ret=0 cacheSeconds=" + fpRead(response, "call.sdk.response.cacheSeconds") + " global=" + settings.global);
                        } catch (Throwable error) { ToolLogger.debug("call sdk mode: response contract unavailable"); }
                    }
                });
                ToolLogger.debug("call sdk mode: parser hooked " + wrapper.getName());
            } catch (Throwable error) { HOOKED.remove(parser); throw error; }
        } catch (Throwable error) { ToolLogger.debug("call sdk mode: parser unavailable"); }
    }

    private static void trackHelper(HookFramework framework, ClassLoader loader, String name) {
        try {
            Class<?> owner = framework.findClass(name, loader);
            Method loaderMethod = fpMethod(owner, fp("call.sdk.helper.cacheLoad.method"), "call.sdk.helper.cacheLoad.signature");
            if (!HOOKED.add(loaderMethod)) return;
            try {
                framework.hookMethod(loaderMethod, new HookCallback() {
                    @Override public void before(HookParam param) {

                        Object helper = param.arg(fpInt("call.sdk.helper.cacheLoad.helperArg"));
                        if (helper != null && helper.getClass() == owner) synchronized (CallSdkModeSpoof.class) {
                            HELPERS.add(helper);
                        }
                    }
                });
                ToolLogger.debug("call sdk mode: cache tracker hooked " + owner.getName());
            } catch (Throwable error) { HOOKED.remove(loaderMethod); throw error; }
        } catch (Throwable error) { ToolLogger.debug("call sdk mode: cache tracker unavailable " + name); }
    }

    public static synchronized void onSettingsChanged(ToolSettings settings) {
        boolean gate = settings.enabled && settings.call;
        if (gateInitialized && gate != lastGate) {
            int cleared = 0;
            for (Object helper : HELPERS) {
                Object cache = fpRead(helper, "call.sdk.helper.decisionCache");
                if (cache instanceof ConcurrentHashMap<?, ?> map && !map.isEmpty()) {
                    map.clear();
                    cleared++;
                }
            }
            if (cleared != 0) ToolLogger.debug("call sdk mode: decision caches reset=" + cleared);
        }
        lastGate = gate;
        gateInitialized = true;
    }
}
