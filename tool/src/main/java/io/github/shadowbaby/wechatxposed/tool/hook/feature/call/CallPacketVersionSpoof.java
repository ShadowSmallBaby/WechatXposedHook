package io.github.shadowbaby.wechatxposed.tool.hook.feature.call;

import static io.github.shadowbaby.wechatxposed.tool.hook.spoof.HostFingerprint.*;

import io.github.shadowbaby.wechatxposed.tool.hook.config.RuntimeSettings;
import io.github.shadowbaby.wechatxposed.shared.hook.HookCallback;
import io.github.shadowbaby.wechatxposed.shared.hook.HookFramework;
import io.github.shadowbaby.wechatxposed.shared.hook.HookParam;
import io.github.shadowbaby.wechatxposed.tool.hook.framework.ToolLogger;
import io.github.shadowbaby.wechatxposed.tool.hook.version.VersionWindow;
import java.lang.reflect.Method;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;


public final class CallPacketVersionSpoof {
    private static final int PROFILE_VERSION = fpInt("call.packet.hostClientVersion");
    private static final int SDK_MODE_CGI = fpInt("call.packet.routes.sdkMode.command");

    private static final int MP_INVITE_CGI = fpInt("call.packet.routes.mpInvite.command");
    private static final Set<Method> HOOKED = ConcurrentHashMap.newKeySet();
    private static final AtomicLong SEQUENCE = new AtomicLong();
    private static final ThreadLocal<Deque<RequestScope>> REQUESTS = new ThreadLocal<>();

    private CallPacketVersionSpoof() {}

    public static void install(HookFramework framework, ClassLoader loader) {
        installRequestBinding(framework, loader);
        try {
            Class<?> owner = framework.findClass(fp("call.packet.native.protocol.class"), loader);
            Class<?> output = framework.findClass(fp("call.packet.native.output.class"), loader);
            fpValidate(output, "call.packet.native.output.bytes", false, true);

            Method method = fpMethod(owner, fp("call.packet.native.pack.method"), "call.packet.install.pack.signature");
            if (!HOOKED.add(method)) return;
            try {
                framework.hookMethod(method, new HookCallback() {
                    @Override public void after(HookParam param) {
                        var settings = RuntimeSettings.get();
                        if (!settings.enabled || !settings.call || settings.global || settings.targetVersion <= 0
                                || VersionWindow.isWalletActive() || param.hasThrowable()
                                || !Boolean.TRUE.equals(param.result())
                                || !(param.arg(fpInt("call.packet.after.seventh")) instanceof Integer func) || !supportedCgi(func)
                                || param.arg(fpInt("call.packet.after.first")) == null || !(param.arg(fpInt("call.packet.after.zero")) instanceof byte[] body)) return;
                        try {
                            byte[] original = (byte[]) fpRequire(param.arg(fpInt("call.packet.original.first")), "call.packet.native.output.bytes");
                            RequestScope scope = currentScope();
                            boolean sealed = Integer.valueOf(fpInt("call.packet.sealed.aesGcmEncryption")).equals(param.arg(fpInt("call.packet.sealed.third")));


                            boolean bound = sealed && scope != null && scope.func == func
                                    && scope.target == settings.targetVersion
                                    && scope.sealed == body;
                            boolean plain = !sealed && !Integer.valueOf(fpInt("call.packet.plain.compressedEncryption")).equals(param.arg(fpInt("call.packet.plain.third")))
                                    && bodyHasVersion(body, settings.targetVersion);
                            if (!bound && !plain) {
                                event(func, sealed ? "unchanged=encrypted-body-unbound" + bindingState(scope, func, settings.targetVersion, body)
                                        : "unchanged=body-version");
                                return;
                            }
                            int offset = versionOffset(original, func);
                            if (offset < fpInt("call.packet.after.zero")) {
                                event(func, "unchanged=unknown-header");
                                return;
                            }
                            int encryption = headerEncryption(original, offset);
                            if ((bound && encryption != fpInt("call.packet.after.aesGcmEncryption")) || (plain && encryption != fpInt("call.packet.after.first") && encryption != fpInt("call.packet.after.fifth"))) {
                                event(func, "unchanged=encryption-contract");
                                return;
                            }
                            int previous = readInt(original, offset);
                            if (previous == settings.targetVersion) {
                                event(func, "unchanged=already-target packetVersion=0x" + Integer.toHexString(previous));
                                return;
                            }




                            byte[] copy = original.clone();
                            int target = settings.targetVersion;
                            copy[offset] = (byte) (target >>> fpInt("call.packet.after.framePrefixBytes"));
                            copy[offset + fpInt("call.packet.after.first")] = (byte) (target >>> fpInt("call.packet.after.gcmTagBytes"));
                            copy[offset + fpInt("call.packet.after.second")] = (byte) (target >>> fpInt("call.packet.after.eighth"));
                            copy[offset + fpInt("call.packet.after.third")] = (byte) target;

                            if (RuntimeSettings.get() != settings || VersionWindow.isWalletActive()
                                    || fpRequire(param.arg(fpInt("call.packet.after.first")), "call.packet.native.output.bytes") != original) return;
                            fpWrite(param.arg(fpInt("call.packet.after.first")), "call.packet.native.output.bytes", copy);
                            event(func, "packetVersion=0x" + Integer.toHexString(previous)
                                    + "->0x" + Integer.toHexString(target) + " requestOnly=true"
                                    + " profile=0x" + Integer.toHexString(PROFILE_VERSION)
                                    + " bodySource=" + (bound ? "remote-req-aes13" : "jni-plain"));
                        } catch (Throwable error) { event(func, "unchanged=output-contract"); }
                    }
                });
            } catch (Throwable error) { HOOKED.remove(method); throw error; }
            ToolLogger.debug("call packet: ordinary pack hooked");
        } catch (Throwable error) { ToolLogger.debug("call packet: ordinary pack contract unavailable"); }
    }


    private static String bindingState(RequestScope scope, int func, int target, byte[] body) {
        if (scope == null) return " scope=none";
        return " scope=present commandMatch=" + (scope.func == func)
                + " serializer=" + scope.serializerObserved + " plain=" + (scope.plain != null)
                + " targetMatch=" + (scope.target == target)
                + " encryptor=" + scope.encryptorObserved + " inputMatch=" + scope.encryptionInputMatched
                + " sealed=" + (scope.sealed != null) + " cipherMatch=" + (scope.sealed == body)
                + " bodyCheck=" + scope.bodyCheck
                + " requestVersion=" + versionState(scope.requestVersion)
                + " serializedVersion=" + versionState(scope.serializedVersion);
    }

    private static String versionState(Integer version) {
        return version == null ? "unobserved" : "0x" + Integer.toHexString(version);
    }


    private static void installRequestBinding(HookFramework framework, ClassLoader loader) {
        try {
            Class<?> remote = framework.findClass(fp("call.packet.request.binding.class"), loader);
            fpValidate(remote, "call.packet.request.binding.payload", false, false);
            fpValidate(remote, "call.packet.request.binding.command", false, false);
            hook(framework, fpMethod(remote, fp("call.packet.request.binding.serialize.method"), "call.packet.request.binding.serialize.signature"), new HookCallback() {
                @Override public void before(HookParam param) {
                    Object original = null;
                    int func = fpInt("call.packet.func.zero");

                    try {
                        original = fpRequire(param.thisObject(), "call.packet.request.binding.payload");
                        func = (Integer) fpRequire(param.thisObject(), "call.packet.request.binding.command");
                    } catch (Throwable ignored) { }
                    Deque<RequestScope> stack = REQUESTS.get();
                    if (stack == null) { stack = new ArrayDeque<>(); REQUESTS.set(stack); }

                    stack.push(new RequestScope(original, func));
                }
                @Override public void after(HookParam param) {
                    Deque<RequestScope> stack = REQUESTS.get();
                    if (stack == null) return;
                    stack.poll();
                    if (stack.isEmpty()) REQUESTS.remove();
                }
            });
            hook(framework, fpMethod(framework.findClass(fp("call.packet.request.wrapper.class"), loader), fp("call.packet.request.serialize.method"), "call.packet.request.serialize.signature"), new HookCallback() {
                @Override public void before(HookParam param) {
                    RequestScope scope = currentScope();
                    var settings = RuntimeSettings.get();

                    if (scope == null || !supportedCgi(scope.func) || scope.request != param.thisObject()
                            || !settings.enabled || !settings.call || settings.global || settings.targetVersion <= 0
                            || VersionWindow.isWalletActive()) return;
                    try {
                        int previous = (Integer) fpRequire(scope.request, "version.request.baseRequest.clientVersion");
                        if (previous == settings.targetVersion || RuntimeSettings.get() != settings
                                || VersionWindow.isWalletActive()) return;
                        fpWrite(scope.request, "version.request.baseRequest.clientVersion", settings.targetVersion);
                        event(scope.func, "baseVersion=0x" + Integer.toHexString(previous)
                                + "->0x" + Integer.toHexString(settings.targetVersion) + " requestOnly=true");
                    } catch (Throwable error) { event(scope.func, "unchanged=base-conversion-contract"); }
                }
                @Override public void after(HookParam param) {
                    RequestScope scope = currentScope();
                    if (scope == null || !supportedCgi(scope.func) || scope.request != param.thisObject()) return;
                    scope.serializerObserved = true;
                    scope.plain = null; scope.sealed = null; scope.target = fpInt("call.packet.after.zero");
                    scope.requestVersion = null; scope.serializedVersion = null;
                    var settings = RuntimeSettings.get();
                    if (!settings.enabled || !settings.call) { scope.bodyCheck = "disabled"; return; }
                    if (settings.global) { scope.bodyCheck = "global"; return; }
                    if (VersionWindow.isWalletActive()) { scope.bodyCheck = "wallet"; return; }
                    if (param.hasThrowable()) { scope.bodyCheck = "serializer-exception"; return; }
                    if (!(param.result() instanceof byte[] data)) { scope.bodyCheck = "serializer-not-bytes"; return; }
                    try {
                        Object version = fpRequire(scope.request, "version.request.baseRequest.clientVersion");
                        if (version instanceof Integer value) scope.requestVersion = value;
                    } catch (IllegalArgumentException ignored) { }
                    if (!bodyHasVersion(data, settings.targetVersion, scope)) return;

                    scope.plain = data; scope.target = settings.targetVersion;
                }
            });
            hook(framework, fpMethod(framework.findClass(fp("call.packet.encryption.bridge.class"), loader), fp("call.packet.encryption.seal.method"), "call.packet.encryption.seal.signature"), new HookCallback() {
                @Override public void after(HookParam param) {
                    RequestScope scope = currentScope();

                    if (scope == null) return;
                    scope.encryptorObserved = true;
                    scope.encryptionInputMatched = scope.plain != null && scope.plain == param.arg(fpInt("call.packet.after.first"));
                    if (!scope.encryptionInputMatched) return;
                    scope.sealed = !param.hasThrowable() && param.result() instanceof byte[] data
                            && data.length > fpInt("call.packet.after.zero") ? data : null;
                }
            });
            ToolLogger.debug("call packet: request binding hooked");
        } catch (Throwable error) { ToolLogger.debug("call packet: AES13 request binding unavailable"); }
    }

    private static void hook(HookFramework framework, Method method, HookCallback callback) throws Throwable {
        if (!HOOKED.add(method)) return;
        try { framework.hookMethod(method, callback); }
        catch (Throwable error) { HOOKED.remove(method); throw error; }
    }

    private static RequestScope currentScope() {
        Deque<RequestScope> stack = REQUESTS.get();
        return stack == null ? null : stack.peek();
    }

    private static final class RequestScope {
        final Object request;
        final int func;
        byte[] plain, sealed;
        int target;
        boolean serializerObserved, encryptorObserved, encryptionInputMatched;
        String bodyCheck = "unobserved";
        Integer requestVersion, serializedVersion;
        RequestScope(Object request, int func) { this.request = request; this.func = func; }
    }

    private static int headerEncryption(byte[] packet, int offset) {
        int prefix = offset - fpInt("call.packet.prefix.second");
        return ((packet[prefix] & fpInt("call.packet.headerEncryption.byteMask")) | (packet[prefix + fpInt("call.packet.headerEncryption.first")] & fpInt("call.packet.headerEncryption.byteMask")) << fpInt("call.packet.headerEncryption.eighth")) >>> fpInt("call.packet.headerEncryption.hybridEncryption");
    }

    private static boolean supportedCgi(int func) {
        return func == SDK_MODE_CGI || func == MP_INVITE_CGI;
    }

    private static void event(int func, String message) {
        ToolLogger.debug("call packet #" + SEQUENCE.incrementAndGet() + " func=" + func + " " + message);
    }


    static int versionOffset(byte[] packet, int expectedFunc) {
        if (!supportedCgi(expectedFunc)) return -fpInt("call.packet.versionOffset.first");
        if (packet == null || packet.length < fpInt("call.packet.versionOffset.nibbleMask")) return -fpInt("call.packet.versionOffset.first");
        int prefix = (packet[fpInt("call.packet.prefix.zero")] & fpInt("call.packet.prefix.byteMask")) == fpInt("call.packet.prefix.packetMarker") ? fpInt("call.packet.prefix.first") : fpInt("call.packet.prefix.zero");
        int flags = (packet[prefix] & fpInt("call.packet.flags.byteMask")) | (packet[prefix + fpInt("call.packet.flags.first")] & fpInt("call.packet.flags.byteMask")) << fpInt("call.packet.flags.eighth");
        int end = flags >>> fpInt("call.packet.end.second") & fpInt("call.packet.end.headerSizeMask"), cookie = flags >>> fpInt("call.packet.cookie.eighth") & fpInt("call.packet.cookie.nibbleMask");
        int encryption = flags >>> fpInt("call.packet.encryption.hybridEncryption");


        if ((encryption != fpInt("call.packet.versionOffset.first") && encryption != fpInt("call.packet.versionOffset.fifth") && encryption != fpInt("call.packet.versionOffset.aesGcmEncryption") && encryption != fpInt("call.packet.versionOffset.compressedEncryption"))
                || end < prefix + fpInt("call.packet.versionOffset.nibbleMask") + cookie || end >= packet.length || (prefix == fpInt("call.packet.versionOffset.zero") && end > fpInt("call.packet.versionOffset.extendedEncryption"))) return -fpInt("call.packet.versionOffset.first");
        try {
            Cursor cursor = new Cursor(packet, prefix + fpInt("call.packet.cursor.tagBytes") + cookie, end);
            if (cursor.varint(fpInt("call.packet.versionOffset.maximumCommand")) != expectedFunc) return -fpInt("call.packet.versionOffset.first");
            if (cursor.varint(0xffffffffL) != packet.length - end) return -fpInt("call.packet.versionOffset.first");
            cursor.varint(0xffffffffL);
            cursor.varint(fpInt("call.packet.versionOffset.maximumCommand"));
            cursor.varint(fpInt("call.packet.versionOffset.maximumCommand"));
            if (prefix != fpInt("call.packet.versionOffset.zero")) {
                cursor.varint(0xffffffffL);
                cursor.skip(fpInt("call.packet.versionOffset.first"));
                cursor.varint(0xffffffffL);
                cursor.skip(fpInt("call.packet.versionOffset.second"));
                cursor.varint(fpInt("call.packet.versionOffset.maximumCommand"));
                cursor.skip(fpInt("call.packet.versionOffset.second"));
            }
            return cursor.position == end ? prefix + fpInt("call.packet.versionOffset.second") : -fpInt("call.packet.versionOffset.first");
        } catch (IllegalArgumentException ignored) { return -fpInt("call.packet.versionOffset.first"); }
    }

    static boolean bodyHasVersion(byte[] data, int expected) {
        return bodyHasVersion(data, expected, null);
    }

    private static boolean bodyFailure(RequestScope scope, String reason) {
        if (scope != null) scope.bodyCheck = reason;
        return false;
    }

    private static boolean bodyHasVersion(byte[] data, int expected, RequestScope scope) {
        if (data == null || data.length < fpInt("call.packet.bodyHasVersion.second") || expected <= fpInt("call.packet.bodyHasVersion.zero"))
            return bodyFailure(scope, "invalid-input");
        try {

            Cursor outer = new Cursor(data, fpInt("call.packet.outer.zero"), data.length);
            if (outer.varint(0xffffffffL) != fpInt("call.packet.bodyHasVersion.tagBytes")) return bodyFailure(scope, "base-tag");
            int size = (int) outer.varint(fpInt("call.packet.size.maximumMessageBytes"));
            if (size > data.length - outer.position) return bodyFailure(scope, "base-length");
            Cursor base = new Cursor(data, outer.position, outer.position + size);
            boolean found = false;
            for (int fields = fpInt("call.packet.fields.zero"); base.position < base.end && fields < fpInt("call.packet.bodyHasVersion.maximumFields"); fields++) {
                long tag = base.varint(0xffffffffL);
                if (tag >>> fpInt("call.packet.bodyHasVersion.third") == fpInt("call.packet.bodyHasVersion.zero")) return bodyFailure(scope, "zero-field");
                int wire = (int) tag & fpInt("call.packet.wire.seventh");
                if (tag >>> fpInt("call.packet.bodyHasVersion.third") == fpInt("call.packet.bodyHasVersion.fourth")) {
                    if (wire != fpInt("call.packet.bodyHasVersion.zero")) return bodyFailure(scope, "version-wire");
                    if (found) return bodyFailure(scope, "duplicate-version");
                    long version = base.varint(0xffffffffL);
                    if (scope != null) scope.serializedVersion = (int) version;
                    if (version != (expected & 0xffffffffL)) return bodyFailure(scope, "version-mismatch");
                    found = true;
                } else if (wire == fpInt("call.packet.bodyHasVersion.zero")) base.varint(-fpInt("call.packet.bodyHasVersion.first"));
                else if (wire == fpInt("call.packet.bodyHasVersion.first")) base.skip(fpInt("call.packet.bodyHasVersion.eighth"));
                else if (wire == fpInt("call.packet.bodyHasVersion.second")) base.skip((int) base.varint(fpInt("call.packet.bodyHasVersion.maximumMessageBytes")));
                else if (wire == fpInt("call.packet.bodyHasVersion.fifth")) base.skip(fpInt("call.packet.bodyHasVersion.fourth"));
                else return bodyFailure(scope, "unsupported-wire");
            }
            if (!found) return bodyFailure(scope, "missing-version");
            if (base.position != base.end) return bodyFailure(scope, "field-limit");
            if (scope != null) scope.bodyCheck = "verified";
            return true;
        } catch (IllegalArgumentException ignored) { return bodyFailure(scope, "malformed-varint-or-length"); }
    }

    private static int readInt(byte[] data, int offset) {
        return (data[offset] & 255) << 24 | (data[offset + 1] & 255) << 16
                | (data[offset + 2] & 255) << 8 | data[offset + 3] & 255;
    }

    private static final class Cursor {
        final byte[] data;
        final int end;
        int position;
        Cursor(byte[] data, int position, int end) { this.data = data; this.position = position; this.end = end; }
        void skip(int size) {
            if (size < 0 || size > end - position) throw new IllegalArgumentException();
            position += size;
        }
        long varint(long maximum) {
            long result = fpInt("call.packet.result.zero");
            for (int i = fpInt("call.packet.version.byteIndex.initial"); i < 10; i++) {
                if (position >= end) throw new IllegalArgumentException();
                int value = data[position++] & fpInt("call.packet.value.byteMask");
                if (i == 9 && (value & 254) != 0) throw new IllegalArgumentException();
                result |= (long) (value & 127) << (i * 7);
                if ((value & 128) == 0) {
                    if ((i > 0 && (value & 127) == 0) || Long.compareUnsigned(result, maximum) > 0)
                        throw new IllegalArgumentException();
                    return result;
                }
            }
            throw new IllegalArgumentException();
        }
    }
}
