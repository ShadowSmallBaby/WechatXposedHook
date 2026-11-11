package io.github.shadowbaby.wechatxposed.tool.hook.version;

import io.github.shadowbaby.wechatxposed.tool.hook.config.RuntimeSettings;
import io.github.shadowbaby.wechatxposed.shared.hook.HookCallback;
import io.github.shadowbaby.wechatxposed.shared.hook.HookFramework;
import io.github.shadowbaby.wechatxposed.shared.hook.HookParam;
import io.github.shadowbaby.wechatxposed.tool.hook.framework.ToolLogger;
import io.github.shadowbaby.wechatxposed.tool.hook.spoof.SpoofProfiles;

import java.lang.reflect.Method;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import static io.github.shadowbaby.wechatxposed.tool.hook.spoof.HostFingerprint.*;


final class GlobalVersionSpoof {
    private static final Set<Method> HOOKED = ConcurrentHashMap.newKeySet();
    private static final Set<ClassLoader> INSTALLED = ConcurrentHashMap.newKeySet();
    private static final ThreadLocal<Boolean> INTERNAL_NATIVE = new ThreadLocal<>();
    private static final ThreadLocal<Boolean> FORCED_NATIVE = new ThreadLocal<>();
    private static volatile Method nativeSetter;
    private static volatile boolean nativeReady;
    private static volatile boolean nativeOwned;
    private static volatile int lastNativeVersion;

    private GlobalVersionSpoof() {
    }

    static void install(HookFramework framework, ClassLoader loader) {
        if (!INSTALLED.add(loader)) return;
        HookCallback reassert = new HookCallback() {
            @Override
            public void after(HookParam param) {
                if (!param.hasThrowable() && active()) VersionWindow.openGlobal(framework, loader);
            }
        };

        hook(framework, loader, SpoofProfiles.current().clientVersionClass, fp("version.global.hostIdentity.initialize.method"), reassert, "version.global.hostIdentity.initialize.signature");
        hook(framework, loader, fp("version.global.install.launcherUIClass"), fp("version.global.install.onResume"), reassert, "version.global.install.onResume.signature");
        hook(framework, loader, fp("version.global.install.protoIlinkStartConfigBuilderClass"),
                fp("version.global.install.setAppVersion"), new HookCallback() {
                    @Override
                    public void before(HookParam param) {
                        if (!active() || VersionWindow.isWalletActive()) return;
                        VersionWindow.openGlobal(framework, loader);
                        if (VersionWindow.spoofed() == 0) return;
                        int previous = (Integer) param.arg(fpInt("version.global.previous.zero"));
                        param.setArg(fpInt("version.global.before.zero"), VersionWindow.spoofed());
                        ToolLogger.debug("global version: ilink config 0x" + Integer.toHexString(previous)
                                + "->0x" + Integer.toHexString(VersionWindow.spoofed()));
                    }
                }, "version.global.install.setAppVersion.signature");
        installNative(framework, loader);
    }

    private static boolean active() {
        var settings = RuntimeSettings.get();
        return settings.enabled && settings.global;
    }

    private static void installNative(HookFramework framework, ClassLoader loader) {
        String owner = fp("version.global.owner.mMProtocalJniClass");
        nativeSetter = hook(framework, loader, owner, fp("version.global.installNative.setClientPackVersion"), new HookCallback() {
            @Override
            public void before(HookParam param) {
                if (Boolean.TRUE.equals(INTERNAL_NATIVE.get())) return;
                FORCED_NATIVE.remove();
                if (!active()) return;
                if (!VersionWindow.ensure(framework, loader)) return;
                int previous = (Integer) param.arg(fpInt("version.global.previous.zero"));

                if (previous <= 0) return;
                int effective = VersionWindow.isWalletActive() ? VersionWindow.real() : VersionWindow.spoofed();
                param.setArg(fpInt("version.global.before.zero"), effective);
                FORCED_NATIVE.set(true);
                ToolLogger.debug("global version: native setter 0x" + Integer.toHexString(previous)
                        + "->0x" + Integer.toHexString(effective));
            }

            @Override
            public void after(HookParam param) {
                if (Boolean.TRUE.equals(INTERNAL_NATIVE.get())) return;
                try {
                    if (param.hasThrowable() || !Boolean.TRUE.equals(param.result())) return;
                    boolean forced = Boolean.TRUE.equals(FORCED_NATIVE.get());
                    nativeReady = true;
                    lastNativeVersion = (Integer) param.arg(fpInt("version.global.after.zero"));
                    nativeOwned = forced && lastNativeVersion != VersionWindow.real();


                    if (forced) applyNative(active() && !VersionWindow.isWalletActive()
                            ? VersionWindow.spoofed() : VersionWindow.real());
                } finally {
                    FORCED_NATIVE.remove();
                }
            }
        }, "version.global.installNative.setClientPackVersion.signature");
        if (nativeSetter == null) return;
        HookCallback pack = new HookCallback() {
            @Override
            public void before(HookParam param) {
                if (active()) {
                    VersionWindow.openGlobal(framework, loader);
                    int effective = VersionWindow.isWalletActive() ? VersionWindow.real() : VersionWindow.spoofed();


                    applyNative(effective, true);
                } else if (nativeOwned) applyNative(VersionWindow.real());
            }
        };
        try {
            hook(framework, loader, owner, fp("version.global.native.packetPack.method"), pack, "version.global.native.packetPack.signature");
            hook(framework, loader, owner, fp("version.global.installNative.packHybridEcdh"), pack, "version.global.installNative.packHybridEcdh.signature");
        } catch (Throwable error) {
            ToolLogger.debug("global version: pack boundary unavailable");
        }
    }

    static void applyNative(int value) {
        applyNative(value, false);
    }

    private static synchronized void applyNative(int value, boolean atPack) {
        if (value <= 0 || nativeSetter == null || (!nativeReady && !atPack)
                || (nativeReady && lastNativeVersion == value)
                || (!active() && !nativeOwned)) return;
        INTERNAL_NATIVE.set(true);
        try {
            if (Boolean.TRUE.equals(nativeSetter.invoke(null, value))) {
                nativeReady = true;
                lastNativeVersion = value;
                nativeOwned = active() && value != VersionWindow.real();
                ToolLogger.debug("global version: native applied=0x" + Integer.toHexString(value)
                        + " owned=" + nativeOwned);
            } else ToolLogger.debug("global version: native setter rejected");
        } catch (Throwable error) {

            ToolLogger.debug("global version: native sync unavailable");
        } finally {
            INTERNAL_NATIVE.remove();
        }
    }

    private static Method hook(HookFramework framework, ClassLoader loader, String owner,
                               String name, HookCallback callback, String signatureKey) {
        try {
            Method method = fpMethod(framework.findClass(owner, loader), name, signatureKey);
            if (!HOOKED.add(method)) return method;
            try {
                framework.hookMethod(method, callback);
            } catch (Throwable error) {
                HOOKED.remove(method);
                throw error;
            }
            return method;
        } catch (Throwable error) {
            INSTALLED.remove(loader);
            ToolLogger.debug("global version: target unavailable " + owner + "#" + name);
            return null;
        }
    }
}
