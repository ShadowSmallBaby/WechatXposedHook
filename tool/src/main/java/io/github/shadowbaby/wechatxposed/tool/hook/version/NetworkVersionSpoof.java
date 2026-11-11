package io.github.shadowbaby.wechatxposed.tool.hook.version;

import io.github.shadowbaby.wechatxposed.tool.hook.config.RuntimeSettings;
import io.github.shadowbaby.wechatxposed.tool.hook.config.ToolSettings;
import io.github.shadowbaby.wechatxposed.tool.hook.feature.tablet.PadSpoofState;
import io.github.shadowbaby.wechatxposed.tool.hook.feature.tablet.TabletMode;
import io.github.shadowbaby.wechatxposed.shared.hook.HookCallback;
import io.github.shadowbaby.wechatxposed.shared.hook.HookFramework;
import io.github.shadowbaby.wechatxposed.shared.hook.HookParam;
import io.github.shadowbaby.wechatxposed.tool.hook.framework.ToolLogger;
import io.github.shadowbaby.wechatxposed.tool.hook.spoof.SpoofProfile;
import io.github.shadowbaby.wechatxposed.tool.hook.spoof.SpoofProfiles;

import java.lang.reflect.Method;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import static io.github.shadowbaby.wechatxposed.tool.hook.spoof.HostFingerprint.*;


public final class NetworkVersionSpoof {
    private static final Set<Method> HOOKED = ConcurrentHashMap.newKeySet();

    private NetworkVersionSpoof() {
    }

    public static void install(HookFramework framework, ClassLoader loader, ToolSettings settings) {
        RuntimeSettings.update(settings);
        installRequests(framework, loader);
        if (settings.enabled && settings.global) VersionWindow.openGlobal(framework, loader);
    }

    public static void installRequests(HookFramework framework, ClassLoader loader) {
        SpoofProfile profile = SpoofProfiles.current();
        try {
            Class<?> filler = framework.findClassIfExists(profile.baseRequestFiller, loader);
            if (filler != null) {
                {
                    Method method = fpMethod(filler, profile.baseRequestFill, "version.request.baseRequest.fill.signature");
                    hookOnce(framework, method, new HookCallback() {
                        @Override
                        public void before(HookParam param) {
                            String uri = uriOf(framework, param.arg(fpInt("version.request.uri.first")));
                            TabletMode.prepareAutoAuth(framework, loader, uri);
                            ToolSettings current = RuntimeSettings.get();
                            if (!current.enabled) return;
                            if (current.global) VersionWindow.openGlobal(framework, loader);
                            else if (TabletMode.shouldSpoofPadRequest(framework, loader, uri))
                                PadSpoofState.enter();
                        }

                        @Override
                        public void after(HookParam param) {
                            try {
                                if (!param.hasThrowable()) {
                                    spoofRequest(framework, loader, param);
                                }
                            } finally {
                                PadSpoofState.exit();
                            }
                        }
                    });
                }
            }
            Class<?> base = framework.findClassIfExists(fp("version.request.baseRequest.class"), loader);
            if (base != null) {
                hookOnce(framework, fpMethod(base, fp("version.request.installRequests.setClientVersion"), "version.request.installRequests.setClientVersion.signature"), new HookCallback() {
                    @Override
                    public void before(HookParam param) {
                        ToolSettings current = RuntimeSettings.get();

                        if (current.enabled && current.login && PadSpoofState.active())
                            param.setArg(fpInt("version.request.before.zero"), current.targetVersion);
                    }
                });
            }
        } catch (Throwable error) {
            ToolLogger.log(error);
        }
    }

    private static void hookOnce(HookFramework framework, Method method, HookCallback callback) throws Throwable {
        if (!HOOKED.add(method)) return;
        try {
            framework.hookMethod(method, callback);
        } catch (Throwable error) {
            HOOKED.remove(method);
            throw error;
        }
    }

    private static void spoofRequest(HookFramework framework, ClassLoader loader, HookParam param) {
        ToolSettings settings = RuntimeSettings.get();
        Object request = param.arg(fpInt("version.request.request.zero"));
        if (!settings.enabled || request == null) return;
        String uri = uriOf(framework, param.arg(fpInt("version.request.uri.first")));
        String scene = param.arg(fpInt("version.request.scene.first")) == null ? "" : param.arg(fpInt("version.request.scene.first")).getClass().getName();
        boolean wallet = VersionWindow.isWalletActive()
                || VersionTables.match(VersionTables.WALLET_URI, uri)
                || VersionTables.match(VersionTables.WALLET_CLASS, scene);
        if (settings.global) {
            if (wallet) {
                if (VersionWindow.ensure(framework, loader)) setVersion(framework, request, VersionWindow.real());
            } else setVersion(framework, request, settings.targetVersion);
            return;
        }
        if (wallet) return;
        boolean login = settings.login && VersionTables.match(VersionTables.LOGIN, uri);
        boolean pad = TabletMode.shouldSpoofPadRequest(framework, loader, uri);
        boolean mini = settings.miniProgramMode == ToolSettings.MINI_CGI
                && VersionTables.match(VersionTables.MINI_PROGRAM, uri);
        boolean call = settings.call && VersionTables.match(VersionTables.CALL, uri);
        if (login || pad || mini || call) {
            setVersion(framework, request, settings.targetVersion);
            ToolLogger.debug("request spoof: " + uri + " ClientVersion=0x"
                    + Integer.toHexString(settings.targetVersion));
        }
    }

    private static void setVersion(HookFramework framework, Object request, int version) {
        if (version == 0) return;
        try {
            fpWrite(request, "version.request.baseRequest.clientVersion", version);
            return;
        } catch (IllegalArgumentException unavailable) { }
        try {
            fpCall(framework, request, "version.request.baseRequest.clientVersion.write", version);
        } catch (Throwable error) {
            ToolLogger.log(error);
        }
    }

    private static String uriOf(HookFramework framework, Object scene) {
        if (scene == null) return "";
        try {
            Object uri = fpCall(framework, scene, "version.request.scene.uri.read");
            return uri instanceof String ? (String) uri : "";
        } catch (Throwable error) {
            return "";
        }
    }
}
