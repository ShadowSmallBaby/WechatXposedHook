package github.shadowbaby.wechatxposed.hook.support.feature;

import github.shadowbaby.wechatxposed.hook.framework.HookCallback;
import github.shadowbaby.wechatxposed.hook.framework.HookFramework;
import github.shadowbaby.wechatxposed.hook.framework.HookParam;
import github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import github.shadowbaby.wechatxposed.hook.support.feature.version.VersionWindow;

/**
 * 钱包/转账页面的版本恢复。
 *
 * 全局 8.0.79 会让钱包相关 CGI 一直加载，v1.3 的做法是在这些页面
 * onCreate ~ onDestroy 之间恢复真实版本。这里原样保留。
 */
public final class WalletVersionGuard {

    private static final String[] WALLET_CLASSES = {
            "com.tencent.mm.wallet_core.ui.WalletBaseUI",
            "com.tencent.mm.plugin.remittance.ui.RemittanceDetailUI",
            "com.tencent.mm.plugin.remittance.ui.RemittanceUI",
            "com.tencent.mm.plugin.remittance.ui.RemittanceResultUI",
            "com.tencent.mm.plugin.luckymoney.ui.LuckyMoneyReceiveUI",
            "com.tencent.mm.plugin.luckymoney.ui.LuckyMoneyNewReceiveUI",
            "com.tencent.mm.plugin.luckymoney.ui.LuckyMoneyDetailUI",
            "com.tencent.mm.plugin.luckymoney.ui.LuckyMoneyMyRecordUI",
            "com.tencent.mm.plugin.luckymoney.ui.LuckyMoneyPrepareUI",
    };

    private WalletVersionGuard() {
    }

    public static void install(HookFramework framework, ClassLoader classLoader) {
        for (String name : WALLET_CLASSES) {
            try {
                Class<?> target = framework.findClassIfExists(name, classLoader);
                if (target == null) {
                    ModuleLogger.debug("wallet version: missing " + name);
                    continue;
                }
                framework.hookMethod(target, "onCreate",
                        new Class<?>[]{android.os.Bundle.class}, new HookCallback() {
                            @Override
                            public void before(HookParam param) {
                                VersionWindow.enterWallet(framework, classLoader);
                            }
                        });
                framework.hookMethod(target, "onDestroy", new Class<?>[]{},
                        new HookCallback() {
                            @Override
                            public void after(HookParam param) {
                                VersionWindow.exitWallet(framework, classLoader);
                            }
                        });
                ModuleLogger.log("wallet version: hooked " + name);
            } catch (Throwable error) {
                ModuleLogger.debug("wallet version: failed " + name);
            }
        }
    }
}
