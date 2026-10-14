package github.shadowbaby.wechatxposed.hook;

import de.robv.android.xposed.IXposedHookZygoteInit;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import github.shadowbaby.wechatxposed.hook.rebuild.loader.InMemoryDexLoadHook;
import github.shadowbaby.wechatxposed.hook.rebuild.XorStrings;

/**
 * 模块入口(assets/xposed_init 指向本类)。
 *
 * 只做一件事:挂住 dalvik.system.InMemoryDexClassLoader 的构造函数,
 * 等微X模块把功能 dex 解密进内存时,交给 InMemoryDexLoadHook 继续处理。
 *
 * 明文目标类名由 DEX_LOADER_TARGET_POOL[1..37) ^ 38961 还原,key 在原始字节码里
 * 由 pool[0] 的算术式 (4960^2 + 4020025) - 4960 * 4010 推出。
 */
public class XposedInit implements IXposedHookZygoteInit {

    /** 原 XposedInit.<clinit> 的字符池,仅 1..36 用于目标类名。 */
    private static final short[] DEX_LOADER_TARGET_POOL = {
            4960, -26539, -26544, -26531, -26553, -26536, -26534,
            -26593, -26558, -26552, -26558, -26555, -26540, -26532, -26593, -26504, -26529,
            -26500, -26540, -26532, -26530, -26557, -26552, -26507, -26540, -26551, -26510,
            -26531, -26544, -26558, -26558, -26499, -26530, -26544, -26539, -26540, -26557};

    /** 池中目标类名所在的位置与异或 key。 */
    private static final int TARGET_OFFSET = 1;
    private static final int TARGET_LENGTH = 36;
    private static final int TARGET_KEY = 38961;

    @Override
    public void initZygote(StartupParam startupParam) {
        String className = XorStrings.decode(DEX_LOADER_TARGET_POOL, TARGET_OFFSET, TARGET_LENGTH, TARGET_KEY);
        Class<?> inMemoryDexClassLoader = XposedHelpers.findClass(className, null);
        XposedBridge.hookAllConstructors(inMemoryDexClassLoader, new InMemoryDexLoadHook(0));
    }
}