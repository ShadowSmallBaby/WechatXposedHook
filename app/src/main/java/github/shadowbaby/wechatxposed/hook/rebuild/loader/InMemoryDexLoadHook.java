package github.shadowbaby.wechatxposed.hook.rebuild.loader;

import github.shadowbaby.wechatxposed.hook.rebuild.support.ReflectBridgeA;
import github.shadowbaby.wechatxposed.hook.rebuild.support.ReflectBridgeB;
import github.shadowbaby.wechatxposed.hook.rebuild.support.WxComponentHooks;
import de.robv.android.xposed.XC_MethodHook;
import java.util.ArrayList;
import java.util.Iterator;

/**
 * 重建源码：b.c —— InMemoryDexClassLoader 构造函数 hook（原始 b 包的混淆类，原类名 b.c，原字段 f1/f9a）。
 *
 * 池 LOADER_POOL（原 f1，364 项）。两套 XOR key：
 *   key=7403  —— 组件类名 / 日志文案（由 s*s 公式选出，s=LOADER_POOL[0]=1657）
 *   key=17407 —— 微X校验方法名（"disable" 段 300..363）
 *
 * 【afterHookedMethod】（原方法体，仅 f9a==0 即构造函数 hook 生效）
 *   - key 选择：i = ((s*s) + 7980625) - (s*5650)，s=1657 → 7403
 *   - thisObject 必须是 ClassLoader，否则直接返回
 *   - 同步块锁定 b.a 类，遍历 WX_COMPONENTS（b.a 静态块构造，顺序 componentId=1,0,3,2）：
 *       - 列表空 → 日志 "All dex already hooked."（1/23）并返回
 *       - 每项按 componentId 取类名 findClassIfExists：
 *           0 → 24/40  "com.fkzhang.wxfeatures.base.Wrapper.Init"
 *           1 → 64/49  "com.fkzhang.wechatxposedhooks.Wrapper.HookWrapper"
 *           2 → 113/44 "com.fkzhang.wxfeatures.donation.Wrapper.Init"
 *           其它 → 157/42 "com.fkzhang.wxfeatures.themes.Wrapper.Init"
 *       - 命中则：日志 "Found " + dexName + ", enable: " + TRUE（dexName 225/7 BaseDex、
 *         232/7 CoreDex、239/11 DonationDex、250/9 ThemesDex）；调用 entry.inject(cl)（c.a.a）；
 *         日志 dexName + " hook suc."（275/10）；it.remove()
 *       - 未命中：日志 "Ignored non wx module dex."（199/26）
 *
 * 【beforeHookedMethod】（原方法体，f9a==1/2/3 三条分支；f9a==0 时先 super 后直接返回）
 *   公共前置（所有 f9a）：先算出 str11/str12 两个基准串
 *     s3 = LOADER_POOL[299] = 2299；s = 5107；s2 = 20428；i3 = (s3+s)^2
 *     (s3*s2) - i3 <= 0 → i4 = 17407（key）；否则 i4 = 60664（诱饵，运行时永不取）
 *     str11 = decodeXor(f1, 300, 7, 17407)  = "disable"
 *     str12 = decodeXor(f1, 307, 15, 17407) = "on_update_check"
 *   然后按 f9a 分流：
 *     f9a==1：super；obj4=args[0]；switch(hashCode(String.valueOf(obj4)))
 *         "on_update_check"(1636443250) → 若 equals(str12) → setResult(null)
 *         "disable"        (1671308008) → 若 equals(str11) → setResult(null)
 *         "process_metadata"(1925143295) → 若 equals(decodeXor(f1,322,16,17407)) → setResult(null)
 *         其它 → 透传（不 setResult）
 *     f9a==2：super；若 String.valueOf(args[0]).equals(str12="on_update_check") → setResult(null)
 *     f9a==3：super；switch(hashCode(String.valueOf(args[0])))
 *         "on_update_check"(1636443250) → 若 equals(str12) → setResult(null)
 *         "disable"        (1671308008) → 若 equals(str11) → setResult(null)
 *         -1329193160 → 若 equals(decodeXor(f1,338,13,17407)="updateLicense") → setResult(null)
 *         -160258069 → 若 equals(decodeXor(f1,351,13,17407)="delayed_check") → setResult(null)
 *         其它 → 透传
 *   即：屏蔽微X在线校验入口（on_update_check / disable / process_metadata / updateLicense / delayed_check），
 *   命中即 setResult(null) 使被 hook 方法直接返回 null。
 */
public final class InMemoryDexLoadHook extends XC_MethodHook {

    private static final short[] LOADER_POOL = {
            1657, 7338, 7303, 7303, 7371, 7311, 7310, 7315, 7371, 7306, 7303, 7321,
            7310, 7306, 7311, 7314, 7371, 7299, 7300, 7300, 7296, 7310, 7311, 7365,
            7304, 7300, 7302, 7365, 7309, 7296, 7313, 7299, 7306, 7301, 7308, 7365,
            7324, 7315, 7309, 7310, 7306, 7327, 7326, 7321, 7310, 7320, 7365, 7305,
            7306, 7320, 7310, 7365, 7356, 7321, 7306, 7323, 7323, 7310, 7321, 7365,
            7330, 7301, 7298, 7327, 7304, 7300, 7302, 7365, 7309, 7296, 7313, 7299,
            7306, 7301, 7308, 7365, 7324, 7310, 7304, 7299, 7306, 7327, 7315, 7323,
            7300, 7320, 7310, 7311, 7299, 7300, 7300, 7296, 7320, 7365, 7356, 7321,
            7306, 7323, 7323, 7310, 7321, 7365, 7331, 7300, 7300, 7296, 7356, 7321,
            7306, 7323, 7323, 7310, 7321, 7304, 7300, 7302, 7365, 7309, 7296, 7313,
            7299, 7306, 7301, 7308, 7365, 7324, 7315, 7309, 7310, 7306, 7327, 7326,
            7321, 7310, 7320, 7365, 7311, 7300, 7301, 7306, 7327, 7298, 7300, 7301,
            7365, 7356, 7321, 7306, 7323, 7323, 7310, 7321, 7365, 7330, 7301, 7298,
            7327, 7304, 7300, 7302, 7365, 7309, 7296, 7313, 7299, 7306, 7301, 7308,
            7365, 7324, 7315, 7309, 7310, 7306, 7327, 7326, 7321, 7310, 7320, 7365,
            7327, 7299, 7310, 7302, 7310, 7320, 7365, 7356, 7321, 7306, 7323, 7323,
            7310, 7321, 7365, 7330, 7301, 7298, 7327, 7330, 7308, 7301, 7300, 7321,
            7310, 7311, 7371, 7301, 7300, 7301, 7371, 7324, 7315, 7371, 7302, 7300,
            7311, 7326, 7303, 7310, 7371, 7311, 7310, 7315, 7365, 7337, 7306, 7320,
            7310, 7343, 7310, 7315, 7336, 7300, 7321, 7310, 7343, 7310, 7315, 7343,
            7300, 7301, 7306, 7327, 7298, 7300, 7301, 7343, 7310, 7315, 7359, 7299,
            7310, 7302, 7310, 7320, 7343, 7310, 7315, 7341, 7300, 7326, 7301, 7311,
            7371, 7367, 7371, 7310, 7301, 7306, 7305, 7303, 7310, 7377, 7371, 7371,
            7299, 7300, 7300, 7296, 7371, 7320, 7326, 7304, 7365, 7342, 7321, 7321,
            7300, 7321, 7371, 7327, 7300, 7371, 7299, 7300, 7300, 7296, 7371, 2299,
            17307, 17302, 17292, 17310, 17309, 17299, 17306, 17296, 17297, 17312, 17290, 17295,
            17307, 17310, 17291, 17306, 17312, 17308, 17303, 17306, 17308, 17300, 17295, 17293,
            17296, 17308, 17306, 17292, 17292, 17312, 17298, 17306, 17291, 17310, 17307, 17310,
            17291, 17310, 17290, 17295, 17307, 17310, 17291, 17306, 17331, 17302, 17308, 17306,
            17297, 17292, 17306, 17307, 17306, 17299, 17310, 17286, 17306, 17307, 17312, 17308,
            17303, 17306, 17308, 17300};

    /** 原 f9a：0=构造 hook；1/2/3 = 各 dex 内方法的 beforeHookedMethod 回调 */
    public final int mode;

    public InMemoryDexLoadHook(int i) { this.mode = i; }

    @Override
    public void afterHookedMethod(MethodHookParam param) throws Throwable {
        // 原 key 选择：i = ((s*s) + 7980625) - (s*5650)，s = LOADER_POOL[0] = 1657 → 7403
        int key = 7403;
        super.afterHookedMethod(param);
        if (this.mode != 0) return;
        Object obj = param.thisObject;
        if (!(obj instanceof ClassLoader)) return;
        ClassLoader cl = (ClassLoader) obj;

        ArrayList<WxComponentHooks> list = WxComponentRegistry.WX_COMPONENTS;
        synchronized (WxComponentHooks.class) {
            if (ReflectBridgeB.listIsEmpty(list)) {                          // list.isEmpty()
                ReflectBridgeA.logMessage(ReflectBridgeA.decodeXor(LOADER_POOL, 1, 23, key));       // "All dex already hooked."
                return;
            }
            Iterator<WxComponentHooks> it = ReflectBridgeA.listIterator(list);
            while (ReflectBridgeB.iteratorHasNext(it)) {                          // it.hasNext()
                WxComponentHooks entry = (WxComponentHooks) ReflectBridgeB.iteratorNext(it);
                String name;   // 微X组件类名
                switch (entry.componentId) {
                    case 0:  name = ReflectBridgeB.decodeXor(LOADER_POOL, 24, 40, key);  break;   // base.Wrapper.Init
                    case 1:  name = ReflectBridgeB.decodeXor(LOADER_POOL, 64, 49, key);  break;   // HookWrapper
                    case 2:  name = ReflectBridgeB.decodeXor(LOADER_POOL, 113, 44, key); break;   // donation.Wrapper.Init
                    default: name = ReflectBridgeA.decodeXor(LOADER_POOL, 157, 42, key);  break;   // themes.Wrapper.Init
                }
                if (ReflectBridgeA.findClassIfExists(name, cl) != null) {           // findClassIfExists
                    String dexName;
                    switch (entry.componentId) {
                        case 0:  dexName = ReflectBridgeB.decodeXor(LOADER_POOL, 225, 7, key);  break;  // "BaseDex"
                        case 1:  dexName = ReflectBridgeB.decodeXor(LOADER_POOL, 232, 7, key);  break;  // "CoreDex"
                        case 2:  dexName = ReflectBridgeA.decodeXor(LOADER_POOL, 239, 11, key);  break;  // "DonationDex"
                        default: dexName = ReflectBridgeB.decodeXor(LOADER_POOL, 250, 9, key);  break;  // "ThemesDex"
                    }
                    StringBuilder sb = new StringBuilder();
                    ReflectBridgeB.appendString(sb, ReflectBridgeA.decodeXor(LOADER_POOL, 259, 6, key));   // "Found "
                    ReflectBridgeA.appendString(sb, dexName);
                    ReflectBridgeA.appendString(sb, ReflectBridgeA.decodeXor(LOADER_POOL, 265, 10, key));  // ", enable: "
                    ReflectBridgeB.appendObject(sb, Boolean.TRUE);
                    ReflectBridgeB.logMessage(ReflectBridgeA.toString(sb));                    // b.b.a 日志
                    ReflectBridgeB.invokeComponentHook(entry, cl);                        // entry.a(cl) → c.a.a(cl)
                    StringBuilder sb2 = new StringBuilder();
                    ReflectBridgeB.appendString(sb2, dexName);
                    ReflectBridgeA.appendString(sb2, ReflectBridgeB.decodeXor(LOADER_POOL, 275, 10, key)); // " hook suc."
                    ReflectBridgeA.logMessage(ReflectBridgeA.toString(sb2));
                    ReflectBridgeB.iteratorRemove(it);                               // it.remove()
                } else {
                    ReflectBridgeA.logMessage(ReflectBridgeA.decodeXor(LOADER_POOL, 199, 26, key));      // "Ignored non wx module dex."
                }
            }
        }
    }

    @Override
    public void beforeHookedMethod(MethodHookParam param) throws Throwable {
        super.beforeHookedMethod(param);
        if (mode == 0 || mode < 1 || mode > 3) return;

        String method = String.valueOf(param.args[0]);
        boolean block = "on_update_check".equals(method);
        if (mode == 1) {
            block |= "disable".equals(method) || "process_metadata".equals(method);
        } else if (mode == 3) {
            block |= "disable".equals(method) || "updateLicense".equals(method)
                    || "delayed_check".equals(method);
        }
        if (block) param.setResult(null);
    }
}
