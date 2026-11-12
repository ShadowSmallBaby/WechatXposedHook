package io.github.shadowbaby.wechatxposed.tool.hook.feature.tablet;

import io.github.shadowbaby.wechatxposed.tool.hook.config.RuntimeSettings;
import io.github.shadowbaby.wechatxposed.shared.hook.HookCallback;
import io.github.shadowbaby.wechatxposed.shared.hook.HookFramework;
import io.github.shadowbaby.wechatxposed.shared.hook.HookParam;
import io.github.shadowbaby.wechatxposed.tool.hook.framework.ToolLogger;
import io.github.shadowbaby.wechatxposed.tool.hook.spoof.SpoofProfile;
import io.github.shadowbaby.wechatxposed.tool.hook.spoof.SpoofProfiles;
import io.github.shadowbaby.wechatxposed.tool.hook.version.VersionTables;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.concurrent.atomic.AtomicLong;

import static io.github.shadowbaby.wechatxposed.tool.hook.spoof.HostFingerprint.*;


public final class TabletMode {

    private static final String LOGIN_SCREEN = fp("tablet.mode.loginScreen.loginAsExDeviceUI");
    private static final String LOGIN_HISTORY = fp("tablet.mode.loginHistory.loginHistoryUI");
    private static final String LOGIN_PACKAGE = fp("tablet.mode.loginPackage.uiClass");
    private static final String LOGIN_COMPOSE = fp("tablet.mode.login.compose.class");
    private static final String CHAT_PACKAGE = fp("tablet.mode.chatPackage.chatClass");
    private static final String CHAT_FOOTER = fp("tablet.mode.chatFooter.chatFooter");
    private static final String FINDER_LIVE = fp("tablet.mode.finderLive.finderLiveFindPageUI");

    private static boolean installed;
    private static volatile boolean deviceInitHooked;
    private static volatile boolean identityForced;
    private static final ThreadLocal<Integer> DEVICE_INIT_DEPTH = new ThreadLocal<>();
    private static final AtomicLong AUTH_SEQUENCE = new AtomicLong();

    private TabletMode() {
    }

    public static synchronized void install(HookFramework framework, ClassLoader classLoader) {
        if (installed) {
            return;
        }
        installed = true;
        int hooked = 0;
        for (SpoofProfile.TabletEntry entry : SpoofProfiles.current().tablet) {
            try {
                Class<?> owner = framework.findClassIfExists(entry.owner, classLoader);
                if (owner == null || owner.isInterface()) {
                    continue;
                }
                Method target = fpMethod(owner, entry.method, entry.signature);
                if (Modifier.isAbstract(target.getModifiers())
                        || (target.getReturnType() != Boolean.TYPE
                        && target.getReturnType() != Boolean.class)) {
                    continue;
                }
                String visibleMethod = entry.exclude;
                String forced = entry.force;
                framework.hookMethod(target, new HookCallback() {
                    @Override
                    public void before(HookParam param) {
                        if (!RuntimeSettings.get().enabled
                                || !RuntimeSettings.get().tablet) {
                            return;
                        }
                        if (!inLoginFlow(framework, classLoader)) {
                            return;
                        }
                        boolean value;
                        if ("true".equals(forced)) {
                            value = true;
                        } else if ("false".equals(forced)) {
                            value = false;
                        } else {
                            value = shouldForce(visibleMethod);
                        }
                        param.setResult(value);
                    }
                });
                hooked++;
                ToolLogger.debug("tablet mode: hooked " + entry.owner + "#" + entry.method);
            } catch (Throwable error) {
                ToolLogger.debug("tablet mode: skip " + entry.owner + "#" + entry.method);
            }
        }
        hookDeviceInitialization(framework, classLoader);
        ToolLogger.log("tablet mode: " + hooked + " target(s)");
    }

    private static void hookDeviceInitialization(HookFramework framework, ClassLoader loader) {
        try {
            Class<?> owner = framework.findClassIfExists(fp("tablet.mode.deviceIdentity.class"), loader);
            if (owner == null) return;
            Method method = fpMethod(owner, fp("tablet.mode.deviceIdentity.initialize.method"), "tablet.mode.deviceIdentity.initialize.signature");
            if (!Modifier.isStatic(method.getModifiers()) || method.getReturnType() != Void.TYPE) return;
            framework.hookMethod(method, new HookCallback() {
                @Override
                public void before(HookParam param) {
                    Integer depth = DEVICE_INIT_DEPTH.get();
                    DEVICE_INIT_DEPTH.set(depth == null ? 1 : depth + 1);
                }

                @Override
                public void after(HookParam param) {
                    try {
                        if (!param.hasThrowable()) {
                            identityForced = padIdentityRequired(framework, loader);
                            if (identityForced) {
                                ToolLogger.debug("tablet auth identity: pad via=a7.b input=" + param.arg(fpInt("tablet.mode.deviceIdentity.deviceTypeArg")));
                            }
                        }
                    } finally {
                        Integer depth = DEVICE_INIT_DEPTH.get();
                        if (depth == null || depth <= 1) DEVICE_INIT_DEPTH.remove();
                        else DEVICE_INIT_DEPTH.set(depth - 1);
                    }
                }
            });
            deviceInitHooked = true;
            ToolLogger.debug("tablet auth identity: hooked com.tencent.mm.app.a7#b(int)");
        } catch (Throwable error) {
            ToolLogger.log("tablet auth identity: initializer unavailable");
        }
    }

    private static boolean padSpoofEnabled() {
        var settings = RuntimeSettings.get();
        return settings.enabled && settings.login;
    }

    private static boolean padIdentityEnabled() {
        return padSpoofEnabled() && RuntimeSettings.get().tablet;
    }

    private static boolean padIdentityRequired(HookFramework framework, ClassLoader loader) {
        return padIdentityEnabled() && (inExplicitPadLogin() || TabletAuthState.isPad(framework, loader));
    }

    public static boolean shouldSpoofPadRequest(HookFramework framework, ClassLoader loader, String uri) {
        if (!padSpoofEnabled() || !VersionTables.match(VersionTables.LOGIN_PAD, uri)) return false;
        return (!uri.endsWith(fp("tablet.mode.shouldSpoofPadRequest.secautoauth")) && !uri.endsWith(fp("tablet.mode.shouldSpoofPadRequest.autoauth")))
                || padIdentityRequired(framework, loader);
    }

    public static void prepareAutoAuth(HookFramework framework, ClassLoader loader, String uri) {
        if (!deviceInitHooked || !fp("tablet.mode.prepareAutoAuth.cgiBinMicromsgBinSecautoauth").equals(uri)) return;
        boolean required = padIdentityRequired(framework, loader);
        boolean wasForced = identityForced;
        boolean reinitialize = wasForced || required;
        if (reinitialize) {
            reinitializeIdentity(framework, loader);
        }
        ToolLogger.debug("tablet auth #" + AUTH_SEQUENCE.incrementAndGet()
                + " requiredPad=" + required + " wasForcedPad=" + wasForced
                + " nowForcedPad=" + identityForced + " reinit=" + reinitialize);
    }

    public static void refreshAuthIdentity(HookFramework framework, ClassLoader loader) {
        if (deviceInitHooked && identityForced != padIdentityRequired(framework, loader)) {
            reinitializeIdentity(framework, loader);
        }
    }

    private static void reinitializeIdentity(HookFramework framework, ClassLoader loader) {
        try {
            Class<?> owner = framework.findClassIfExists(fp("tablet.mode.deviceIdentity.class"), loader);
            if (owner != null) fpCall(framework, owner, "tablet.mode.deviceIdentity.initialize", -1);
        } catch (Throwable error) {
            ToolLogger.log("tablet auth identity: original initialization failed");
        }
    }

    private static boolean inLoginFlow(HookFramework framework, ClassLoader loader) {
        Integer depth = DEVICE_INIT_DEPTH.get();
        if (depth != null && depth > 0) {

            return padIdentityRequired(framework, loader);
        }
        StackTraceElement[] stack = Thread.currentThread().getStackTrace();
        if (stack.length == 0 || stack.length > 128) {
            return false;
        }
        for (StackTraceElement frame : stack) {
            if (frame == null) {
                return false;
            }
            String text = frame.toString();
            if (text.length() > 2048) {
                return false;
            }
            if (text.contains(LOGIN_SCREEN) || text.contains(LOGIN_HISTORY)
                    || text.contains(LOGIN_PACKAGE) || text.contains(LOGIN_COMPOSE)) {
                return true;
            }
        }
        return false;
    }

    private static boolean inExplicitPadLogin() {
        for (StackTraceElement frame : Thread.currentThread().getStackTrace()) {
            if (frame.getClassName().startsWith(fp("tablet.mode.inExplicitPadLogin.separatorClass")))
                return true;
        }
        return false;
    }

    private static boolean shouldForce(String visibleMethod) {
        StackTraceElement[] stack = Thread.currentThread().getStackTrace();
        if (stack.length == 0 || stack.length > 128) {
            return false;
        }
        boolean login = false;
        boolean chat = false;
        boolean excluded = false;
        for (StackTraceElement frame : stack) {
            if (frame == null) {
                return false;
            }
            String text = frame.toString();
            if (text.length() > 2048) {
                return false;
            }
            login |= text.contains(LOGIN_SCREEN);
            chat |= text.contains(CHAT_PACKAGE);
            excluded |= text.contains(CHAT_FOOTER)
                    || text.contains(FINDER_LIVE)
                    || (!visibleMethod.isEmpty() && text.contains(visibleMethod));
        }

        return login || (!chat && !excluded);
    }
}
