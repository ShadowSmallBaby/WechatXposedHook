package github.shadowbaby.wechatxposed.hook;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.IXposedHookZygoteInit;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;
import github.shadowbaby.wechatxposed.hook.deploy.ModuleApk;
import github.shadowbaby.wechatxposed.hook.deploy.StartupCheck;
import github.shadowbaby.wechatxposed.hook.loader.InMemoryDexLoadHook;
import github.shadowbaby.wechatxposed.hook.support.HostVersionSpoof;
import java.io.File;

/**
 * 模块入口(assets/xposed_init 指向本类)。
 *
 * 主功能(微X 授权接管)与辅助功能(小程序宿主版本伪装)分开:
 *   1. initZygote 挂住 dalvik.system.InMemoryDexClassLoader 的构造函数,等微X模块把功能 dex
 *      解密进内存时交给 InMemoryDexLoadHook 继续处理,并记下模块自己的 APK 路径(内置载荷在那里面);
 *   2. handleLoadPackage 在微信主进程启动时跑一次启动自检,补齐功能包与授权库。
 *   3. handleLoadPackage 在微信主进程与小程序进程(:appbrand0 / :appbrand1)里挂宿主版本伪装。
 *
 * 第 3 条是辅助功能,失败不影响前两条:它自己吞掉所有异常,而且跑在启动自检之后。
 *
 * 字符串池对照见 docs/StringPools.java。
 */
public class XposedInit implements IXposedHookZygoteInit, IXposedHookLoadPackage {

    /** 微信包名;主进程名与包名相同。 */
    private static final String WECHAT_PACKAGE = "com.tencent.mm";

    /** 小程序进程,宿主版本伪装要挂在这里。 */
    private static final String[] WECHAT_APPBRAND_PROCESSES = {
            "com.tencent.mm:appbrand0", "com.tencent.mm:appbrand1"};

    @Override
    public void initZygote(StartupParam startupParam) {
        ModuleApk.remember(startupParam.modulePath);
        String className = "dalvik.system.InMemoryDexClassLoader";
        Class<?> inMemoryDexClassLoader = XposedHelpers.findClass(className, null);
        XposedBridge.hookAllConstructors(inMemoryDexClassLoader, new InMemoryDexLoadHook(0));
    }

    /**
     * 微信进程启动时挂伪装;主进程额外跑一次启动自检。
     *
     * 启动自检只看主进程:微X 的功能 dex 也在主进程里加载,:push / :tools 之类的子进程不需要动。
     */
    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam param) {
        if (!WECHAT_PACKAGE.equals(param.packageName) || param.appInfo == null) {
            return;
        }
        if (isAppBrandProcess(param.processName)) {
            installHostVersionSpoof(param);
            return;
        }
        if (WECHAT_PACKAGE.equals(param.processName)) {
            File dataDir = new File(param.appInfo.dataDir);
            StartupCheck.run(dataDir, StartupCheck.readLoginAccount(dataDir));
            installHostVersionSpoof(param);
        }
    }

    /**
     * 挂宿主版本伪装(辅助功能)。
     *
     * 单独包一层 try/catch:辅助功能出任何问题都不该影响主功能,
     * 所以这里再兜一次,连 {@code install} 自己的兜底都不依赖。
     */
    private static void installHostVersionSpoof(XC_LoadPackage.LoadPackageParam param) {
        try {
            HostVersionSpoof.install(param.classLoader, param.appInfo.sourceDir);
        } catch (Throwable error) {
            XposedBridge.log(error);
        }
    }

    /** 是不是小程序进程。 */
    private static boolean isAppBrandProcess(String processName) {
        for (String name : WECHAT_APPBRAND_PROCESSES) {
            if (name.equals(processName)) {
                return true;
            }
        }
        return false;
    }
}
