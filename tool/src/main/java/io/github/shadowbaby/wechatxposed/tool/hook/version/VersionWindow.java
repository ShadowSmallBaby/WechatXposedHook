package io.github.shadowbaby.wechatxposed.tool.hook.version;

import io.github.shadowbaby.wechatxposed.shared.hook.HookFramework;
import io.github.shadowbaby.wechatxposed.tool.hook.framework.ToolLogger;
import io.github.shadowbaby.wechatxposed.tool.hook.spoof.SpoofProfile;
import io.github.shadowbaby.wechatxposed.tool.hook.spoof.SpoofProfiles;

import java.lang.reflect.Method;
import java.util.concurrent.atomic.AtomicInteger;

import static io.github.shadowbaby.wechatxposed.tool.hook.spoof.HostFingerprint.*;


public final class VersionWindow {

    private static final AtomicInteger WALLET_DEPTH = new AtomicInteger();

    private static volatile int realClientVersion;
    private static volatile int spoofedClientVersion;
    private static volatile boolean globalPinned;
    private static volatile int targetVersion = VersionTables.TARGET_VERSION;
    private static volatile HookFramework frameworkRef;
    private static volatile ClassLoader loaderRef;

    private VersionWindow() {
    }


    public static synchronized void configure(int configuredTarget) {
        if ((configuredTarget & 0xFFFFFF00) == 0 || configuredTarget == targetVersion) {
            return;
        }
        targetVersion = configuredTarget;
        if (realClientVersion != 0) {
            spoofedClientVersion = targetVersion;
            HookFramework framework = frameworkRef;
            ClassLoader loader = loaderRef;
            if (globalPinned && framework != null && loader != null && !isWalletActive()) {
                writeClientVersion(framework, loader, spoofedClientVersion);
                ToolLogger.log("global version: target 0x"
                        + Integer.toHexString(targetVersion) + " applied");
            }
        }
    }


    public static void install(HookFramework framework, ClassLoader classLoader) {
        frameworkRef = framework;
        loaderRef = classLoader;
    }

    public static int real() {
        return realClientVersion;
    }

    public static int spoofed() {
        return spoofedClientVersion;
    }

    public static boolean ensure(HookFramework framework, ClassLoader classLoader) {
        return ensureVersions(framework, classLoader);
    }


    public static synchronized void openGlobal(HookFramework framework, ClassLoader loader) {
        GlobalVersionSpoof.install(framework, loader);
        globalPinned = true;
        applyCurrent(framework, loader);
    }

    private static void applyCurrent(HookFramework framework, ClassLoader loader) {
        if (ensureVersions(framework, loader)) {
            writeClientVersion(framework, loader,
                    !isWalletActive() && globalPinned
                            ? spoofedClientVersion : realClientVersion);
        }
    }

    static synchronized boolean ensureVersions(HookFramework framework,
                                               ClassLoader classLoader) {
        if (realClientVersion != 0) {
            return true;
        }

        if (!isHostReady()) {
            return false;
        }
        int real = readClientVersion(framework, classLoader);
        if (real == 0) {
            return false;
        }
        realClientVersion = real;
        spoofedClientVersion = targetVersion;
        ToolLogger.log("version values: real=0x" + Integer.toHexString(real)
                + " target=0x" + Integer.toHexString(spoofedClientVersion));
        return true;
    }

    public static boolean isWalletActive() {
        return WALLET_DEPTH.get() > 0;
    }

    public static synchronized void enterWallet(HookFramework framework,
                                                ClassLoader classLoader) {
        WALLET_DEPTH.incrementAndGet();
        if (globalPinned && realClientVersion != 0) {
            writeClientVersion(framework, classLoader, realClientVersion);
            ToolLogger.log("global version: wallet enter, real version");
        }
    }

    public static synchronized void exitWallet(HookFramework framework,
                                               ClassLoader classLoader) {
        if (WALLET_DEPTH.decrementAndGet() > 0) {
            return;
        }
        WALLET_DEPTH.set(0);
        if (globalPinned) applyCurrent(framework, classLoader);
    }


    public static synchronized void close(HookFramework framework, ClassLoader loader,
                                          String reason) {
        if (!globalPinned) return;
        globalPinned = false;
        applyCurrent(framework, loader);
        ToolLogger.debug("global version: off (" + reason + ")");
    }

    private static boolean isHostReady() {
        try {
            Class<?> activityThread = Class.forName(fp("version.global.runtime.activityThread.activityThreadClass"));
            Method current = fpMethod(activityThread, fp("version.global.runtime.current.currentApplication"), "version.global.runtime.isHostReady.currentApplication.signature");
            return current.invoke(null) != null;
        } catch (Throwable ignored) {

            return true;
        }
    }

    private static int readClientVersion(HookFramework framework, ClassLoader classLoader) {
        try {
            SpoofProfile profile = SpoofProfiles.current();
            Class<?> target = framework.findClassIfExists(
                    profile.clientVersionClass, classLoader);
            if (target == null) {
                return 0;
            }
            return (Integer) fpRequire(target, "version.global.clientVersion");
        } catch (Throwable error) {
            ToolLogger.log(error);
            return 0;
        }
    }

    private static void writeClientVersion(HookFramework framework, ClassLoader classLoader,
                                           int value) {
        if (value == 0) {
            return;
        }
        try {
            SpoofProfile profile = SpoofProfiles.current();
            Class<?> target = framework.findClassIfExists(
                    profile.clientVersionClass, classLoader);
            if (target == null) {
                return;
            }
            int previous = (Integer) fpRequire(target, "version.global.clientVersion");
            fpWrite(target, "version.global.clientVersion", value);
            if (previous != value) ToolLogger.debug("global version: java 0x"
                    + Integer.toHexString(previous) + "->0x" + Integer.toHexString(value)
                    + " pinned=" + globalPinned + " wallet=" + isWalletActive());
            GlobalVersionSpoof.applyNative(value);
        } catch (Throwable error) {
            ToolLogger.log(error);
        }
    }
}
