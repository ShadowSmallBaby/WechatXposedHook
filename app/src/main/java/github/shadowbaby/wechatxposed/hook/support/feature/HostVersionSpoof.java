package github.shadowbaby.wechatxposed.hook.support.feature;

import github.shadowbaby.wechatxposed.hook.framework.HookFramework;
import github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import github.shadowbaby.wechatxposed.hook.support.feature.version.MiniProgramVersionSpoof;
import github.shadowbaby.wechatxposed.hook.support.feature.version.NetworkVersionSpoof;
import github.shadowbaby.wechatxposed.hook.support.feature.version.VersionWindow;

/**
 * 宿主版本伪装入口（最终最小方案）。
 *
 * - {@link NetworkVersionSpoof}：只伪装 getonlineinfo、voipilink 链路、launchwxaapp；
 * - {@link MiniProgramVersionSpoof}：小程序启动场景临时抬全局版本，保证头体一致；
 * - {@link WalletVersionGuard}：钱包/转账/红包页面整体保持真实；
 * - {@link ChatMvvmGuard}：服务端仍会下发 MVVM 开关，强制关闭避免 8.0.49 闪退。
 *
 * 真机验证：通话、公众号、小程序、转账、红包均正常。
 */
public final class HostVersionSpoof {

    private static volatile boolean installed;

    private HostVersionSpoof() {
    }

    public static synchronized void install(HookFramework framework, ClassLoader classLoader,
            String dataDir, boolean mainProcess) {
        if (installed || !mainProcess) {
            return;
        }
        installed = true;
        ChatMvvmGuard.install(framework, classLoader);
        VersionWindow.install(framework, classLoader);
        WalletVersionGuard.install(framework, classLoader);
        MiniProgramVersionSpoof.install(framework, classLoader);
        NetworkVersionSpoof.install(framework, classLoader);
        ModuleLogger.log("version spoof: installed (network-only)");
    }
}
