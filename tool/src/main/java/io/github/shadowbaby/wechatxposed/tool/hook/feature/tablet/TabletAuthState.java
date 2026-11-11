package io.github.shadowbaby.wechatxposed.tool.hook.feature.tablet;

import io.github.shadowbaby.wechatxposed.shared.hook.HookFramework;

import java.lang.reflect.Method;

import static io.github.shadowbaby.wechatxposed.tool.hook.spoof.HostFingerprint.*;


public final class TabletAuthState {
    private TabletAuthState() {
    }

    public static boolean isPad(HookFramework framework, ClassLoader loader) {
        return deviceFlag(framework, loader) == 0;
    }

    public static int deviceFlag(HookFramework framework, ClassLoader loader) {
        try {
            Class<?> kernel = framework.findClass(fp("tablet.account.kernel.class"), loader);
            Object account = fpCall(framework, kernel, "tablet.account.kernel.account.read");
            Object storage = fpCall(framework, account, "tablet.account.account.storage.read");
            Class<?> keys = framework.findClass(fp("tablet.account.storage.key.class"), loader);
            Object key = fpCall(framework, keys, "tablet.account.storage.key.resolve", fp("tablet.account.deviceFlag.storageKey"));

            Method read = fpMethod(framework.findClass(fp("tablet.account.storage.class"), loader), fp("tablet.account.deviceFlag.read.method"), "tablet.account.deviceFlag.read.signature");
            read.setAccessible(true);
            Object flag = read.invoke(storage, key, -1);

            return flag instanceof Number n && n.intValue() >= 0 ? ((n.intValue() & fpInt("tablet.account.deviceFlag.padMask")) != fpInt("tablet.account.deviceFlag.default") ? fpInt("tablet.account.deviceFlag.default") : fpInt("tablet.account.deviceFlag.padMask")) : -1;
        } catch (Throwable ignored) {
            return -1;
        }
    }

}
