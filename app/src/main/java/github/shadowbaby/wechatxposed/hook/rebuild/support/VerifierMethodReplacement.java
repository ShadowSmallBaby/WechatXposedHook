package github.shadowbaby.wechatxposed.hook.rebuild.support;

import de.robv.android.xposed.XC_MethodReplacement;

/**
 * 重建源码：c.c —— XC_MethodReplacement（原始 c 包的混淆类，原类名 c.c，原字段 f4/f13a）。
 *
 * 池 REPLACEMENT_POOL（原 f4，67 项），key=55271 段明文：
 *   1/23   "banned polling verifier"
 *   24/24  "banned check api request"
 *   48/19  "banned updated tips"
 * （key=18251 为诱饵分支，解出的是不可读字符，运行时永不采用。）
 *
 * 原始状态机（decompiled_bad/sources/c/c.java，入口 state=hashCode("\u06e7\u06e5\u06df")=1754561）：
 *   1754561 →(m33()==true) 1740735 →(m82()==0) 1758438 →(f6>0) 1752175
 *   →(f6>0) 1740798 →(f5==0) 1752183 →(f6>0) 1739198 →(f6>0) 1737858
 *   → 三元 i4-(i12*i12)>0 ? 1739271 : 1739396  —— 实算 i3=f4[0]*2=10088, i4=10089,
 *     i12=f4[0]+1=5045, i12*i12=25452025, 10089-25452025<0 → 取 1739396 → i5=55271
 *   → 1751245：switch(this.f13a)
 *       case 0  → 1755398（i6=1,i7=23）→ 1753478：log(decodeXor(f4,1,23,55271)); return null
 *       case 1  → 1747424（外层 default：i8=24,i9=24）→ 1737885：log(decodeXor(f4,24,24,55271)); return null
 *       default → 1741072（i10=48,i11=19）→ 1748352：log(decodeXor(f4,48,19,55271)); return Boolean.FALSE
 *
 * 结论（注意与旧版重建相反）：
 *   replacementMode=0 → 日志 "banned polling verifier"，返回 null
 *   replacementMode=1 → 日志 "banned check api request"，返回 null
 *   replacementMode=其它 → 日志 "banned updated tips"，返回 Boolean.FALSE
 * 即 c.c 把被 hook 的方法整体替换为固定返回值（null / false），并打一条微X内部自述日志。
 * replacementMode 由 c.a 在 findAndHookMethod(..., MethodReplacement) 时指定。
 */
public final class VerifierMethodReplacement extends XC_MethodReplacement {

    private static final short[] REPLACEMENT_POOL = {
            5044, -10363, -10362, -10359, -10359, -10366, -10365, -10297,
            -10345, -10360, -10357, -10357, -10354, -10359, -10368, -10297,
            -10351, -10366, -10347, -10354, -10367, -10354, -10366, -10347,
            -10363, -10362, -10359, -10359, -10366, -10365, -10297, -10364,
            -10353, -10366, -10364, -10356, -10297, -10362, -10345, -10354,
            -10297, -10347, -10366, -10346, -10350, -10366, -10348, -10349,
            -10363, -10362, -10359, -10359, -10366, -10365, -10297, -10350,
            -10345, -10365, -10362, -10349, -10366, -10365, -10297, -10349,
            -10354, -10345, -10348};

    /** 原 f13a：0=轮询校验；1=API 请求；其它=更新提示 */
    public final int replacementMode;

    public VerifierMethodReplacement(int i) { this.replacementMode = i; }

    @Override
    public Object replaceHookedMethod(MethodHookParam param) throws Throwable {
        // 原 1751245：switch(this.f13a)，i5 已由 1739396 固定为 55271
        switch (this.replacementMode) {
            case 0:
                ReflectBridgeB.logMessage(ReflectBridgeB.decodeXor(REPLACEMENT_POOL, 1, 23, 55271));   // "banned polling verifier"
                return null;                                                                             // 原 1753478
            case 1:
                ReflectBridgeB.logMessage(ReflectBridgeB.decodeXor(REPLACEMENT_POOL, 24, 24, 55271));  // "banned check api request"
                return null;                                                                             // 原 1737885
            default:
                ReflectBridgeB.logMessage(ReflectBridgeB.decodeXor(REPLACEMENT_POOL, 48, 19, 55271));  // "banned updated tips"
                return Boolean.FALSE;                                                                    // 原 1748352
        }
    }
}
