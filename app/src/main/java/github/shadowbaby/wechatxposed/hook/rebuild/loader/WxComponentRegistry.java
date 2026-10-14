package github.shadowbaby.wechatxposed.hook.rebuild.loader;

import github.shadowbaby.wechatxposed.hook.rebuild.support.ReflectBridgeB;
import github.shadowbaby.wechatxposed.hook.rebuild.support.WxComponentHooks;
import java.util.ArrayList;
import java.util.List;

/**
 * 重建源码：b.a —— 微X模块描述列表容器（原始 b 包的混淆抽象类）
 *
 * 原始逻辑（由 dexdump b.a.<clinit> 逐指令还原，insns 210）：
 *   静态块构造 4 个 c.a 项（componentId 顺序 1=Core、0=Base、3=Themes、2=Donation），
 *   逐项 requireNonNull 后 add 进 ArrayList(4)，再用 Collections.unmodifiableList 包装，
 *   最后 new ArrayList(unmodifiableList) 赋给 WX_COMPONENTS。
 *
 * 原始指令（case 1758073 主构造分支，0x3b..0xba）：
 *   0x3b  v0 = new ArrayList()
 *   0x4c  v1 = new WxComponentHooks(1)      // CoreDex
 *   0x57  v2 = new WxComponentHooks(0)      // BaseDex
 *   0x6e  v3 = new WxComponentHooks(3)      // ThemesDex
 *   0x82  v4 = new WxComponentHooks(2)      // DonationDex
 *   0x85  Object[] v1 = { v1, v2, v3, v4 }
 *   0x91  v2 = new ArrayList(4)
 *   0x98  for (v4 = 0; v4 < 4; v4++) { Objects.requireNonNull(v1[v4]); v2.add(v1[v4]); }
 *   0xb1  List v1 = Collections.unmodifiableList(v2)     // ReflectBridgeB.unmodifiableList
 *   0xb5  v0.<init>(v1)                                   // new ArrayList(unmodifiableList)
 *   0xb8  WX_COMPONENTS = v0
 *
 * 注：c.ReflectBridgeB.truthyFlag = 1730 恒大于 0，c.ReflectBridgeA.unusedFlag 恒为 0（未赋值），
 *     zero() 恒返回 0、alwaysTrue() 恒返回 true——这些是控制流混淆的装饰常量，
 *     真实路径只有一条（主构造分支），其余分支全是诱饵。
 */
public abstract class WxComponentRegistry {

    /** 原 b.a.f8a：微X模块描述列表（4 项，静态块初始化） */
    public static final ArrayList<WxComponentHooks> WX_COMPONENTS;

    static {
        // 原始为状态机混淆（case 1739861/1742139/1744077/1753699/1758073），真实路径只有主构造分支。
        Object[] arr = new Object[]{
                new WxComponentHooks(1),   // 原 0x4c CoreDex   (com.fkzhang.wechatxposedhooks)
                new WxComponentHooks(0),   // 原 0x57 BaseDex   (com.fkzhang.wxfeatures.base)
                new WxComponentHooks(3),   // 原 0x6e ThemesDex (com.fkzhang.wxfeatures.themes)
                new WxComponentHooks(2),   // 原 0x82 DonationDex (com.fkzhang.wxfeatures.donation)
        };
        ArrayList<WxComponentHooks> list = new ArrayList<>(4);   // 原 0x91
        for (int i = 0; i < 4; i++) {                            // 原 0x98..0xb0
            ReflectBridgeB.requireNonNull(arr[i]);               // 原 0x9c m68
            list.add((WxComponentHooks) arr[i]);                 // 原 0x9f m55
        }
        List<WxComponentHooks> unmod = ReflectBridgeB.unmodifiableList(list);   // 原 0xb1 m83
        WX_COMPONENTS = new ArrayList<>(unmod);                  // 原 0xb5
    }
}
