package io.github.shadowbaby.wechatxposed.tool.hook.guard;

import io.github.shadowbaby.wechatxposed.shared.hook.HookCallback;
import io.github.shadowbaby.wechatxposed.shared.hook.HookFramework;
import io.github.shadowbaby.wechatxposed.shared.hook.HookParam;
import io.github.shadowbaby.wechatxposed.tool.hook.framework.ToolLogger;
import io.github.shadowbaby.wechatxposed.tool.hook.version.VersionWindow;

import java.lang.reflect.Method;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import static io.github.shadowbaby.wechatxposed.tool.hook.spoof.HostFingerprint.fp;
import static io.github.shadowbaby.wechatxposed.tool.hook.spoof.HostFingerprint.fpMethod;


public final class WalletVersionGuard {

    private static final String[] WALLET_CLASSES = {
            fp("guard.wallet.walletClasses.walletBaseUIClass"),
            fp("guard.wallet.walletClasses.remittanceDetailUIClass"),
            fp("guard.wallet.walletClasses.remittanceUIClass"),
            fp("guard.wallet.walletClasses.remittanceResultUIClass"),
            fp("guard.wallet.walletClasses.luckyMoneyReceiveUIClass"),
            fp("guard.wallet.walletClasses.luckyMoneyNewReceiveUIClass"),
            fp("guard.wallet.walletClasses.luckyMoneyDetailUIClass"),
            fp("guard.wallet.walletClasses.luckyMoneyPrepareUIClass"),
    };

    private static final Set<String> DONE = ConcurrentHashMap.newKeySet();

    private WalletVersionGuard() {
    }

    public static synchronized void install(HookFramework framework, ClassLoader classLoader) {
        for (String name : WALLET_CLASSES) {
            String key = name + "@" + System.identityHashCode(classLoader);
            if (!DONE.add(key)) {
                continue;
            }
            try {
                Class<?> target = framework.findClassIfExists(name, classLoader);
                if (target == null) {
                    DONE.remove(key);
                    ToolLogger.debug("wallet version: missing " + name);
                    continue;
                }

                Method create = fpMethod(target, fp("guard.wallet.create.onCreate"), "guard.wallet.install.onCreate.signature");
                Method destroy = fpMethod(target, fp("guard.wallet.destroy.onDestroy"), "guard.wallet.install.onDestroy.signature");
                framework.hookMethod(create, new HookCallback() {
                    @Override
                    public void before(HookParam param) {
                        VersionWindow.enterWallet(framework, classLoader);
                    }
                });
                framework.hookMethod(destroy, new HookCallback() {
                    @Override
                    public void after(HookParam param) {
                        VersionWindow.exitWallet(framework, classLoader);
                    }
                });
                ToolLogger.debug("wallet version: hooked " + name);
            } catch (Throwable error) {
                DONE.remove(key);
                ToolLogger.debug("wallet version: failed " + name);
            }
        }
    }
}
