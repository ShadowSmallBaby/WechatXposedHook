package io.github.shadowbaby.wechatxposed.tool.hook.feature.call;

import io.github.shadowbaby.wechatxposed.tool.hook.config.RuntimeSettings;
import io.github.shadowbaby.wechatxposed.tool.hook.config.ToolSettings;
import io.github.shadowbaby.wechatxposed.shared.hook.HookCallback;
import io.github.shadowbaby.wechatxposed.shared.hook.HookFramework;
import io.github.shadowbaby.wechatxposed.shared.hook.HookParam;
import io.github.shadowbaby.wechatxposed.tool.hook.framework.ToolLogger;
import io.github.shadowbaby.wechatxposed.tool.hook.version.VersionWindow;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import static io.github.shadowbaby.wechatxposed.tool.hook.spoof.HostFingerprint.*;


public final class CallVersionSpoof {
    private static final Set<Method> HOOKED = ConcurrentHashMap.newKeySet();
    private static final AtomicInteger MEDIA_PROBE = new AtomicInteger();
    private CallVersionSpoof() {}

    public static void install(HookFramework framework, ClassLoader loader) {
        CallSdkModeSpoof.install(framework, loader);
        CallMpVersionSpoof.install(framework, loader);
        CallPacketVersionSpoof.install(framework, loader);
        try {
            Class<?> type = framework.findClassIfExists(fp("call.media.type.v2protocalClass"), loader);
            if (type == null) return;
            Method method = fpMethod(type, fp("call.media.method.setAppCmd"), "call.media.install.setAppCmd.signature");
            if (!HOOKED.add(method)) return;
            try {
                framework.hookMethod(method, new HookCallback() {
                    @Override public void before(HookParam param) {
                        if (MEDIA_PROBE.incrementAndGet() <= 80) {
                            Object payload = param.arg(fpInt("call.media.before.first"));
                            ToolLogger.debug("call media probe: cmd="
                                    + param.arg(fpInt("call.media.before.zero"))
                                    + " payloadLen=" + (payload instanceof byte[] data ? data.length : "n/a")
                                    + " mode=" + param.arg(fpInt("call.media.before.second")));
                        }
                        ToolSettings settings = RuntimeSettings.get();
                        if (!settings.enabled || !settings.call || VersionWindow.isWalletActive()
                                || !Integer.valueOf(fpInt("call.media.before.setVersionCommand")).equals(param.arg(fpInt("call.media.before.zero")))
                                || !Integer.valueOf(4).equals(param.arg(fpInt("call.media.before.second")))
                                || !(param.arg(fpInt("call.media.before.first")) instanceof byte[] data) || data.length != 4) return;
                        byte[] copy = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN)
                                .putInt(settings.targetVersion).array();
                        param.setArg(fpInt("call.media.before.first"), copy);
                        ToolLogger.debug("call media version: cmd=505 ClientVersion=0x"
                                + Integer.toHexString(settings.targetVersion));
                    }
                });
                ToolLogger.debug("call media: 505 hooked " + type.getName());
            } catch (Throwable error) { HOOKED.remove(method); throw error; }
        } catch (Throwable error) { ToolLogger.debug("call media: 505 target unavailable"); }
    }
}
