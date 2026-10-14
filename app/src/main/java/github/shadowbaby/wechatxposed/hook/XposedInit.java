package github.shadowbaby.wechatxposed.hook;

import de.robv.android.xposed.IXposedHookZygoteInit;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import github.shadowbaby.wechatxposed.hook.rebuild.loader.InMemoryDexLoadHook;

/**
 * 模块入口(assets/xposed_init 指向本类)。
 *
 * 只做一件事:挂住 dalvik.system.InMemoryDexClassLoader 的构造函数,
 * 等微X模块把功能 dex 解密进内存时,交给 InMemoryDexLoadHook 继续处理。
 *
 * 目标类名原以 XOR 池存放,现已内联为明文;池原文与解码对照见 docs/StringPools.java。
 */
public class XposedInit implements IXposedHookZygoteInit {

    @Override
    public void initZygote(StartupParam startupParam) {
        String className = "dalvik.system.InMemoryDexClassLoader";
        Class<?> inMemoryDexClassLoader = XposedHelpers.findClass(className, null);
        XposedBridge.hookAllConstructors(inMemoryDexClassLoader, new InMemoryDexLoadHook(0));
    }
}