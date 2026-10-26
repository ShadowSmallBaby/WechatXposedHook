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
        // 小程序启动窗口只在 appbrand 装：主进程的 launch 场景会被转账/支付误触发，
        // 把 CGI 版本抬到 8.0.79 后服务端直接判系统繁忙。
        NetworkVersionSpoof.install(framework, classLoader);
        ModuleLogger.log("version spoof: installed (network-only)");
    }

    /**
     * 小程序运行时（appbrand 进程）只装版本窗口。
     *
     * 小程序的启动场景和 getSystemInfo 都在这个进程里，主进程的窗口覆盖不到；
     * 钱包/网络链路仍保持真版本，不在这里装。
     */
    public static synchronized void installAppBrand(HookFramework framework,
            ClassLoader classLoader) {
        if (installed) {
            return;
        }
        installed = true;
        VersionWindow.install(framework, classLoader);
        MiniProgramVersionSpoof.install(framework, classLoader);
        ModuleLogger.log("version spoof: appbrand window installed");
    }
}
