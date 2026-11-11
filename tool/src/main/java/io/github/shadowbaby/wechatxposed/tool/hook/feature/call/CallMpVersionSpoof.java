package io.github.shadowbaby.wechatxposed.tool.hook.feature.call;

import static io.github.shadowbaby.wechatxposed.tool.hook.spoof.HostFingerprint.*;

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
import java.util.concurrent.atomic.AtomicLong;


public final class CallMpVersionSpoof {
    private static final Set<Method> HOOKED = ConcurrentHashMap.newKeySet();
    private static final AtomicLong SEQUENCE = new AtomicLong();
    private CallMpVersionSpoof() {}

    private static boolean active(ToolSettings settings) {

        return settings.enabled && settings.call && !settings.global && settings.targetVersion > 0
                && !VersionWindow.isWalletActive();
    }

    public static void install(HookFramework framework, ClassLoader loader) {
        hook(framework, loader, fp("call.mp.deviceInfo.provider.class"), fp("call.mp.deviceInfo.read.method"), new HookCallback() {
            @Override public void after(HookParam param) {
                var settings = RuntimeSettings.get();
                if (!active(settings) || param.hasThrowable() || param.result() == null) return;
                Object original = param.result();
                String owner = fp("call.mp.deviceInfo.class");
                if (!owner.equals(original.getClass().getName())) return;
                try {
                    Object value = fpCall(framework, original, "call.mp.ownerVersion.read");
                    if (!(value instanceof String version) || !version.matches(fp("call.mp.ownerVersion.format"))) return;
                    String target = "0x" + Integer.toHexString(settings.targetVersion);
                    if (Long.parseLong(version.substring(2), 16) == (settings.targetVersion & 0xffffffffL)) return;

                    Object builder = fpCall(framework, original.getClass(), "call.mp.deviceInfo.copyBuilder", original);
                    fpCall(framework, builder, "call.mp.ownerVersion.write", target);
                    Object replacement = fpCall(framework, builder, "call.mp.deviceInfo.build");
                    if (replacement != null && replacement.getClass() == original.getClass()
                            && param.result() == original && RuntimeSettings.get() == settings && active(settings)) {
                        param.setResult(replacement);
                        ToolLogger.debug("call MP #" + SEQUENCE.incrementAndGet() + " ownerVersion=" + version + "->" + target);
                    }
                } catch (Throwable error) { ToolLogger.debug("call MP: DeviceInfo contract unavailable"); }
            }
        }, "call.mp.deviceInfo.read.signature");
        try {
            Class<?> bytes = framework.findClass(fp("call.mp.byteString.class"), loader);
            hook(framework, loader,
                    fp("call.mp.rudp.builder.class"),
                    fp("call.mp.rudp.buffer.write.method"), new HookCallback() {
                        @Override public void before(HookParam param) {
                            var settings = RuntimeSettings.get();
                            if (!active(settings) || param.hasThrowable() || param.arg(fpInt("call.mp.rudp.buffer.arg")) == null) return;
                            try {


                                if (!Integer.valueOf(fpInt("call.mp.rudp.versionCommand")).equals(fpCall(framework, param.thisObject(), "call.mp.rudp.command.read"))) return;
                                Object buffer = param.arg(fpInt("call.mp.rudp.versionOffset"));
                                if (!Integer.valueOf(4).equals(fpCall(framework, buffer, "call.mp.byteString.size"))) return;
                                Object data = fpCall(framework, buffer, "call.mp.byteString.bytes");
                                if (!(data instanceof byte[] input) || input.length != 4) return;
                                int target = settings.targetVersion;
                                if (ByteBuffer.wrap(input).order(ByteOrder.LITTLE_ENDIAN).getInt() == target) return;
                                byte[] copy = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(target).array();
                                Object replacement = fpCall(framework, bytes, "call.mp.byteString.fromBytes", copy);
                                if (!bytes.isInstance(replacement) || param.arg(fpInt("call.mp.rudp.buffer.arg")) != buffer
                                        || RuntimeSettings.get() != settings || !active(settings)) return;
                                param.setArg(fpInt("call.mp.rudp.buffer.arg"), replacement);
                                ToolLogger.debug("call MP #" + SEQUENCE.incrementAndGet()
                                        + " RUDP cmd=8 ClientVersion=0x" + Integer.toHexString(target));
                            } catch (Throwable error) { ToolLogger.debug("call MP: RUDP contract unavailable"); }
                        }
                    }, "call.mp.rudp.buffer.write.signature");
        } catch (Throwable error) { ToolLogger.debug("call MP: ByteString unavailable"); }
    }

    private static void hook(HookFramework framework, ClassLoader loader, String owner, String name,
            HookCallback callback, String signatureKey) {
        try {
            Method method = fpMethod(framework.findClass(owner, loader), name, signatureKey);
            if (!HOOKED.add(method)) return;
            try { framework.hookMethod(method, callback); }
            catch (Throwable error) { HOOKED.remove(method); throw error; }
            ToolLogger.debug("call MP: hooked " + owner + "#" + name);
        } catch (Throwable error) { ToolLogger.debug("call MP: target unavailable " + owner + "#" + name); }
    }
}
