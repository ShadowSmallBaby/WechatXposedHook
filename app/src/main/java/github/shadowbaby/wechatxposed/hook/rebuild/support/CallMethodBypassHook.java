package github.shadowbaby.wechatxposed.hook.rebuild.support;

import android.text.TextUtils;
import de.robv.android.xposed.XC_MethodHook;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import github.shadowbaby.wechatxposed.hook.rebuild.loader.ModuleLogger;

/**
 * 重建源码：原 c.b —— WxJniCoreBridge.CallMethod hook（整个补丁的核心）。
 *
 * 拦截微X的授权校验与在线验证调用，伪造授权返回。
 *
 * 原始实现是 13265 行的状态机（while(true) switch(state)，state = hashCode(三字字符串)）。
 * 本类按状态转移逐 case 还原为可读的结构化 Java，保留全部可观测行为：
 *   - 所有 setResult 取值与分支条件（msgId==130/132/150 等）
 *   - 所有反射调用（callStaticMethod / callMethod / findClass）
 *   - 运行时字符串构造循环（Base64 解码 + 逐字符 XOR + split）
 *   - try/catch 兜底链
 * 原状态机 case 号以注释保留（如 "原 1746836"），便于与 data/decompiled 对照。
 *
 * 字符串池 BYPASS_POOL（原 f3，1251 项），XOR key=5559。已解出明文段：
 *   18/9   "verifier6"        27/7   "c.ˉˉ.ٴʻ"       34/2  "ⁱˏ"
 *   36/5   "param"            41/4   "null"            45/1  ":"
 *   46/6   "equals"           52/17  "java.util.Objects"
 *   69/2   "ʽᵔ"               71/2   "ᐧٴ"              73/7  "c.ﹳﹶ.ʽᵔ"
 *   80/3   "LIC"              83/2   "ﹳˏ"              85/6  "8.0.49"
 *   91/7   "c.ﹳﹶ.ʽᵔ"         98/2   "ᐧٴ"              100/2 "ʽᵔ"
 *   102/2  "ˑᵎ"              104/4  "true"            108/13 "remote_rp_cmd"
 *   121/9  "unlimited"        130/7  "c.ˉˉ.ٴʻ"        137/2 "ⁱˏ"
 *   139/3  "LIC"              142/2  "ﹳˏ"              144/1 "#"
 *   145/1106 付费功能列表（58 项）
 *
 * 注意：本类所有 sparse-switch 载荷均为非标准布局——
 *   [u2 ident=0x200][u2 size][size × s4 key][size × s4 target]，
 * 即「先全部 key 再全部 target」（标准 Dalvik 是交替排列），
 * 且 target 是相对 switch 指令 pc 的偏移。按标准布局解析会得到乱码目标。
 *
 * 三个分支（原 switch(this.f11a) = hashCode("۟ۤۙ"/"ۖۤۤ"/default)）：
 *   bypassMode=0（校验拦截） bypassMode=1（License 拦截） bypassMode=2（透传）
 */
public final class CallMethodBypassHook extends XC_MethodHook {
    private static final java.util.concurrent.atomic.AtomicInteger TRACE_COUNT = new java.util.concurrent.atomic.AtomicInteger();

    private void traceCall(String phase, MethodHookParam param) {
        if (bypassMode != 0 || TRACE_COUNT.incrementAndGet() > 160) return;
        try {
            Object[] arguments = (Object[]) param.args[1];
            Object action = arguments.length == 0 ? null : arguments[0];
            String actionLabel = action instanceof Number ? action.toString()
                    : ("param".equals(action) || "verifier6".equals(action) ? (String) action : "other");
            Object result = param.getResult();
            String resultLabel = result instanceof String ? "String[len=" + ((String) result).length() + "]"
                    : result instanceof Boolean ? result.toString()
                    : result == null ? "null" : result.getClass().getSimpleName();
            ModuleLogger.log("TRACE " + phase + " id=" + param.args[0] + " action=" + actionLabel
                    + " argc=" + arguments.length + " result=" + resultLabel + " error=" + param.hasThrowable());
        } catch (Throwable ignored) {}
    }

    private static final short[] BYPASS_POOL = {
            7685, -10032, -10017, -10034, -10045, -9992, -10044, -10103,
            9940, 9937, -10103, -9702, -14861, -13184, -8493, -9702,
            -14861, 3981, 5569, 5586, 5573, 5598, 5585, 5598,
            5586, 5573, 5505, 5588, 5529, 6014, 6014, 5529,
            5059, 5900, 13766, 6008, 5575, 5590, 5573, 5590,
            5594, 5593, 5570, 5595, 5595, 5517, 5586, 5574,
            5570, 5590, 5595, 5572, 5597, 5590, 5569, 5590,
            5529, 5570, 5571, 5598, 5595, 5529, 5624, 5589,
            5597, 5586, 5588, 5571, 5572, 5898, 2275, 400,
            5059, 5588, 5529, -5180, -5183, 5529, 5898, 2275,
            5627, 5630, 5620, -5180, 6008, 5519, 5529, 5511,
            5529, 5507, 5518, 5588, 5529, -5180, -5183, 5529,
            5898, 2275, 400, 5059, 5898, 2275, 5990, 2297,
            5571, 5573, 5570, 5586, 5573, 5586, 5594, 5592,
            5571, 5586, 5608, 5573, 5575, 5608, 5588, 5594,
            5587, 5570, 5593, 5595, 5598, 5594, 5598, 5571,
            5586, 5587, 5588, 5529, 6014, 6014, 5529, 5059,
            5900, 13766, 6008, 5627, 5630, 5620, -5180, 6008,
            5524, 5573, 5586, 5594, 5592, 5569, 5586, 5608,
            5593, 5592, 5571, 5598, 5588, 5586, 5531, 5575,
            5573, 5598, 5592, 5573, 5598, 5571, 5582, 5608,
            5570, 5575, 5587, 5590, 5571, 5586, 5531, 5586,
            5583, 5571, 5573, 5590, 5608, 5587, 5585, 5531,
            5572, 5586, 5593, 5587, 5608, 5573, 5590, 5568,
            5608, 5598, 5594, 5590, 5584, 5586, 5531, 5590,
            5570, 5571, 5592, 5608, 5588, 5592, 5594, 5594,
            5586, 5593, 5571, 5608, 5573, 5592, 5589, 5592,
            5571, 5531, 5571, 5586, 5583, 5571, 5608, 5573,
            5586, 5575, 5608, 5593, 5598, 5588, 5596, 5593,
            5590, 5594, 5586, 5531, 5572, 5592, 5573, 5571,
            5608, 5588, 5592, 5593, 5571, 5590, 5588, 5571,
            5572, 5531, 5588, 5592, 5593, 5571, 5590, 5588,
            5571, 5572, 5608, 5572, 5586, 5595, 5586, 5588,
            5571, 5608, 5572, 5586, 5583, 5531, 5588, 5592,
            5593, 5571, 5590, 5588, 5571, 5572, 5608, 5572,
            5586, 5595, 5586, 5588, 5571, 5608, 5595, 5592,
            5588, 5590, 5571, 5598, 5592, 5593, 5531, 5594,
            5592, 5587, 5598, 5585, 5582, 5608, 5572, 5571,
            5586, 5575, 5572, 5531, 5571, 5599, 5586, 5594,
            5586, 5572, 5531, 5585, 5590, 5596, 5586, 5608,
            5584, 5575, 5572, 5531, 5585, 5608, 5590, 5570,
            5571, 5592, 5573, 5586, 5575, 5595, 5582, 5608,
            5586, 5583, 5575, 5592, 5573, 5571, 5531, 5590,
            5570, 5571, 5592, 5608, 5588, 5592, 5593, 5571,
            5590, 5598, 5593, 5608, 5593, 5586, 5568, 5608,
            5588, 5592, 5593, 5571, 5590, 5588, 5571, 5531,
            5588, 5599, 5590, 5571, 5573, 5592, 5592, 5594,
            5608, 5572, 5586, 5593, 5587, 5608, 5594, 5570,
            5595, 5571, 5598, 5608, 5598, 5593, 5569, 5598,
            5571, 5586, 5572, 5531, 5581, 5592, 5594, 5589,
            5598, 5586, 5608, 5590, 5570, 5571, 5592, 5608,
            5587, 5586, 5595, 5586, 5571, 5586, 5531, 5571,
            5590, 5598, 5595, 5608, 5594, 5592, 5587, 5586,
            5531, 5573, 5586, 5587, 5575, 5590, 5588, 5596,
            5586, 5571, 5608, 5590, 5594, 5592, 5570, 5593,
            5571, 5608, 5590, 5588, 5588, 5570, 5594, 5570,
            5595, 5590, 5571, 5586, 5531, 5598, 5593, 5571,
            5586, 5584, 5573, 5590, 5571, 5586, 5587, 5608,
            5590, 5595, 5595, 5592, 5568, 5586, 5587, 5531,
            5572, 5586, 5593, 5587, 5608, 5594, 5570, 5595,
            5571, 5575, 5595, 5586, 5608, 5585, 5573, 5598,
            5586, 5593, 5587, 5588, 5590, 5573, 5587, 5531,
            5572, 5588, 5590, 5593, 5608, 5584, 5590, 5595,
            5595, 5586, 5573, 5582, 5608, 5571, 5592, 5608,
            5588, 5590, 5594, 5586, 5573, 5590, 5531, 5569,
            5598, 5587, 5586, 5592, 5588, 5590, 5595, 5595,
            5608, 5573, 5598, 5593, 5584, 5571, 5592, 5593,
            5586, 5608, 5590, 5587, 5569, 5590, 5593, 5588,
            5586, 5587, 5531, 5568, 5583, 5598, 5587, 5608,
            5585, 5573, 5598, 5586, 5593, 5587, 5608, 5573,
            5586, 5574, 5531, 5586, 5583, 5575, 5592, 5573,
            5571, 5608, 5588, 5599, 5590, 5571, 5573, 5592,
            5592, 5594, 5608, 5594, 5586, 5594, 5589, 5586,
            5573, 5572, 5531, 5590, 5570, 5571, 5592, 5608,
            5587, 5592, 5568, 5593, 5595, 5592, 5590, 5587,
            5608, 5588, 5599, 5590, 5571, 5608, 5594, 5586,
            5587, 5598, 5590, 5531, 5568, 5586, 5573, 5570,
            5593, 5608, 5595, 5598, 5596, 5586, 5608, 5590,
            5595, 5595, 5531, 5594, 5592, 5594, 5586, 5593,
            5571, 5608, 5592, 5573, 5598, 5584, 5598, 5593,
            5590, 5595, 5608, 5598, 5594, 5590, 5584, 5586,
            5531, 5585, 5590, 5596, 5586, 5608, 5594, 5592,
            5594, 5586, 5593, 5571, 5608, 5585, 5592, 5573,
            5568, 5590, 5573, 5587, 5531, 5581, 5592, 5594,
            5589, 5598, 5586, 5608, 5572, 5598, 5595, 5586,
            5593, 5571, 5608, 5572, 5586, 5590, 5573, 5588,
            5599, 5531, 5581, 5592, 5594, 5589, 5598, 5586,
            5608, 5571, 5573, 5590, 5593, 5572, 5585, 5586,
            5573, 5608, 5572, 5586, 5590, 5573, 5588, 5599,
            5531, 5572, 5599, 5592, 5568, 5608, 5573, 5586,
            5590, 5595, 5593, 5590, 5594, 5586, 5531, 5590,
            5570, 5571, 5592, 5608, 5590, 5588, 5588, 5586,
            5575, 5571, 5608, 5593, 5586, 5598, 5584, 5599,
            5589, 5592, 5573, 5608, 5573, 5586, 5574, 5531,
            5585, 5590, 5572, 5571, 5608, 5572, 5586, 5593,
            5587, 5531, 5571, 5590, 5584, 5608, 5585, 5592,
            5573, 5568, 5590, 5573, 5587, 5531, 5596, 5586,
            5582, 5568, 5592, 5573, 5587, 5608, 5593, 5592,
            5571, 5598, 5585, 5598, 5588, 5590, 5571, 5598,
            5592, 5593, 5531, 5585, 5590, 5596, 5586, 5608,
            5571, 5573, 5590, 5593, 5572, 5585, 5586, 5573,
            5608, 5590, 5594, 5592, 5570, 5593, 5571, 5531,
            5590, 5588, 5588, 5586, 5575, 5571, 5608, 5593,
            5586, 5598, 5584, 5599, 5589, 5592, 5573, 5608,
            5585, 5573, 5598, 5586, 5593, 5587, 5573, 5586,
            5574, 5531, 5590, 5570, 5571, 5592, 5608, 5585,
            5573, 5598, 5586, 5593, 5587, 5573, 5586, 5574,
            5531, 5593, 5586, 5568, 5608, 5588, 5599, 5590,
            5571, 5573, 5592, 5592, 5594, 5608, 5588, 5599,
            5590, 5571, 5608, 5589, 5595, 5590, 5588, 5596,
            5595, 5598, 5572, 5571, 5531, 5590, 5570, 5571,
            5592, 5608, 5595, 5590, 5589, 5586, 5595, 5608,
            5593, 5586, 5568, 5608, 5588, 5592, 5593, 5571,
            5590, 5588, 5571, 5531, 5573, 5586, 5588, 5592,
            5573, 5587, 5608, 5572, 5599, 5592, 5568, 5598,
            5587, 5531, 5570, 5593, 5595, 5598, 5594, 5598,
            5571, 5586, 5587, 5608, 5569, 5592, 5598, 5588,
            5586, 5608, 5572, 5586, 5595, 5531, 5586, 5583,
            5571, 5573, 5590, 5588, 5571, 5608, 5569, 5598,
            5587, 5608, 5590, 5570, 5587, 5598, 5592, 5531,
            5590, 5570, 5571, 5592, 5608, 5573, 5586, 5594,
            5590, 5573, 5596, 5608, 5593, 5586, 5568, 5608,
            5588, 5592, 5593, 5571, 5590, 5588, 5571, 5531,
            5585, 5590, 5569, 5608, 5568, 5586, 5593, 5592,
            5571, 5586, 5531, 5594, 5570, 5595, 5571, 5598,
            5608, 5573, 5586, 5572, 5575, 5592, 5593, 5572,
            5586, 5531, 5573, 5575, 5608, 5596, 5586, 5582,
            5568, 5592, 5573, 5587, 5531, 5588, 5599, 5590,
            5571, 5573, 5592, 5592, 5594, 5608, 5588, 5592,
            5593, 5571, 5590, 5598, 5593, 5586, 5573, 5608,
            5571, 5590, 5584, 5572, 5531, 5594, 5592, 5594,
            5586, 5593, 5571, 5572, 5608, 5588, 5592, 5593,
            5571, 5590, 5598, 5593, 5586, 5573, 5608, 5586,
            5593, 5590, 5589, 5595, 5586, 5531, 5572, 5593,
            5572, 5608, 5586, 5583, 5575, 5592, 5573, 5571,
            5531, 5572, 5593, 5572, 5608, 5596, 5586, 5582,
            5568, 5592, 5573, 5587, 5608, 5593, 5592, 5571,
            5598, 5585, 5598, 5588, 5590, 5571, 5598, 5592,
            5593, 5531, 5594, 5590, 5572, 5572, 5608, 5572,
            5593, 5572, 5608, 5595, 5598, 5596, 5586, 5531,
            5586, 5583, 5575, 5592, 5573, 5571, 5608, 5588,
            5592, 5593, 5571, 5590, 5588, 5571, 5572, 5531,
            5585, 5573, 5598, 5586, 5593, 5587, 5608, 5573,
            5586, 5574, 5570, 5586, 5572, 5571, 5608, 5598,
            5594, 5575, 5592, 5573, 5571, 5531, 5572, 5588,
            5599, 5586, 5587, 5570, 5595, 5586, 5587, 5608,
            5571, 5590, 5572, 5596, 5531, 5571, 5590, 5572,
            5596, 5608, 5588, 5599, 5590, 5571, 5573, 5592,
            5592, 5594, 5608, 5598, 5593, 5569, 5598, 5571,
            5586, 5608, 5590, 5595, 5595, 5592, 5568, 5608,
            5589, 5582, 5608, 5598, 5587, 5586, 5593, 5571,
            5598, 5571, 5582, 5531, 5588, 5599, 5590, 5571,
            5608, 5572, 5588, 5599, 5586, 5587, 5570, 5595,
            5586, 5608, 5585, 5592, 5573, 5568, 5590, 5573,
            5587, 5531, 5590, 5570, 5571, 5592, 5608, 5588,
            5595, 5586, 5590, 5593, 5608, 5594, 5592, 5594,
            5586, 5593, 5571,
    };

    /** 0=校验拦截；1=License 拦截；2=透传 */
    public final int bypassMode;

    /** 宿主（微X模块 dex）的 ClassLoader，用于 findClass 白名单类 */
    public final ClassLoader hostClassLoader;

    public CallMethodBypassHook(ClassLoader cl, int mode) {
        this.hostClassLoader = cl;
        this.bypassMode = mode;
    }

    /** 伪造的付费功能列表（key=5559 段 145/1106，共 58 项） */
    static final String FEATURES =
        "remove_notice,priority_update,extra_df,send_raw_image,auto_comment_robot,"
      + "text_rep_nickname,sort_contacts,contacts_select_sex,contacts_select_location,"
      + "modify_steps,themes,fake_gps,f_autoreply_export,auto_contain_new_contact,"
      + "chatroom_send_multi_invites,zombie_auto_delete,tail_mode,"
      + "redpacket_amount_accumulate,integrated_allowed,send_multple_friendcard,"
      + "scan_gallery_to_camera,videocall_ringtone_advanced,wxid_friend_req,"
      + "export_chatroom_members,auto_download_chat_media,werun_like_all,"
      + "moment_original_image,fake_moment_forward,zombie_silent_search,"
      + "zombie_transfer_search,show_realname,auto_accept_neighbor_req,fast_send,"
      + "tag_forward,keyword_notification,fake_transfer_amount,accept_neighbor_friendreq,"
      + "auto_friendreq,new_chatroom_chat_blacklist,auto_label_new_contact,"
      + "record_showid,unlimited_voice_sel,extract_vid_audio,auto_remark_new_contact,"
      + "fav_wenote,multi_response,rp_keyword,chatroom_container_tags,"
      + "moments_container_enable,sns_export,sns_keyword_notification,mass_sns_like,"
      + "export_contacts,friend_request_import,scheduled_task,"
      + "task_chatroom_invite_allow_by_identity,chat_schedule_forward,auto_clean_moment";

    @Override
    public void beforeHookedMethod(MethodHookParam param) throws Throwable {
        switch (this.bypassMode) {
            case 0:
                hookVerifier(param);
                break;
            case 1:
                hookLicense(param);
                break;
            default:
                super.beforeHookedMethod(param);
                break;
        }
        traceCall("before", param);
    }

    @Override
    public void afterHookedMethod(MethodHookParam param) throws Throwable {
        traceCall("after", param);
        // 原 c.b.afterHookedMethod（874 指令状态机，入口状态 hash("۟۠ۗ")=1746710）。
        // 状态转移表（sparse-switch 载荷为「先全部 key 再全部 target」的非标准布局，
        // 且 target 相对 switch 指令 pc=0x5f）：
        //   1746710 -> 0x2d8   1754563 -> 0x245   1753602 -> 0x219   1754165 -> 0x1f1
        //   1753222 -> 0x1e0   1740048 -> 0x1be   1755214 -> 0x19f   1755246 -> 0xf4
        //   1743217 -> 0x56    1739240 -> 0xba    1758914 -> 0x9a    1749758 -> 0x77
        //   1743527 -> 0x56    1752552 -> 0x5d    1741195 -> 0x170   1738805 -> 0x19e
        //   1753298 -> 0x1a5   1758107 -> 0x11e   1754615 -> 0x147
        // 大量 case 为死代码（ۢۨۨ() 恒 0、ۥۨۢ() 恒 1 使分支恒定）。
        super.afterHookedMethod(param);                 // 原 0x200 / 0x20e
        if (this.bypassMode != 2) {                     // 原 packed-switch(this.f11a) @0x229；default -> 0x22c
            return;                                     // 原 0x1fe return-void
        }
        if (!ReflectBridgeA.hasThrowable(param)) {      // 原 0x211 hasThrowable
            return;                                     // 原 0x21a -> 0x1fd return-void
        }
        Object arg0 = param.args[0];                    // 原 0x1d9 aget-object
        String s = String.valueOf(arg0);                // 原 0x1ad String.valueOf（۠۠۟）
        if (!s.startsWith(xorDecode(1, 5, 55463))) {    // 原 0x18d startsWith("wxid_")
            return;                                     // 原 0x1a0 -> 0x21a -> 0x1fd
        }
        // 原 0x62 / 0x119 / 0xf9：findClass + callStaticMethod
        Object verifier = ReflectBridgeA.callStaticMethod( // 原 0x103 callStaticMethod（۫ۖۙ）
                ReflectBridgeA.findClass(xorDecode(6, 7, 55463), this.hostClassLoader), // "c.ﹳﹶ.ʽᵔ"
                xorDecode(13, 2, 55463),                // "ᐧٴ"
                new Object[0]);
        ReflectBridgeA.callMethod(verifier, xorDecode(15, 2, 55463), new Object[0]);
    }

    /** bypassMode=0：拦截 verifier6 校验调用，伪造返回（原状态机 1746836 起） */
    private void hookVerifier(MethodHookParam param) {
        try {
            // 原 1746836：int msgId = ((Integer) args[0]).intValue(); Object[] params = (Object[]) args[1];
            int msgId = ReflectBridgeA.intValue(param.args[0]);
            Object[] params = (Object[]) param.args[1];
            String verifier = xorDecode(18, 9);              // "verifier6"

            if (msgId == 130) {
                // 原 1746772：m292 = "param".equals(params[0]) ? 1747525 : 1747828
                if (xorDecode(36, 5).equals(params[0])) {    // "param"
                    // 原 1747525 → 1741146(return)：setResult("8.0.49")
                    param.setResult(xorDecode(85, 6));
                    return;
                }
                // 原 1747828：if ("verifier6".equals(params[0])) → 1753607
                if (verifier.equals(params[0])) {
                    // 原 1753607 → 1741146(return)：setResult("true")
                    param.setResult(xorDecode(104, 4));
                }
                return;                                      // 原 1741146
            }

            // 原 1752217：批量解码常量；classLoader = this.f12b
            String sNull = xorDecode(41, 4);                 // "null"
            String sColon = xorDecode(45, 1);                // ":"
            String sEquals = xorDecode(46, 6);               // "equals"          (str130)
            String sObjects = xorDecode(52, 17);             // "java.util.Objects" (str118)
            String s69 = xorDecode(69, 2);                   // "ʽᵔ"              (str120)
            String s71 = xorDecode(71, 2);                   // "ᐧٴ"              (str134)
            String s73 = xorDecode(73, 7);                   // "c.ﹳﹶ.ʽᵔ"        (str135)
            ClassLoader cl = this.hostClassLoader;

            if (msgId == 132) {
                // 原 1738423：if (!"verifier6".equals(params[0])) return;
                if (!verifier.equals(params[0])) {
                    return;                                  // 原 1741146
                }
                // 原 1755082：str122 = String.valueOf(params[2]); log(Base64(params[2]))
                String p2 = String.valueOf(params[2]);
                ModuleLogger.log(ReflectBridgeA.base64Encode(ReflectBridgeA.getBytes(p2), 2));
                // 原 1755082：str123 = String.valueOf(params[1])
                String p1 = String.valueOf(params[1]);
                if (TextUtils.isEmpty(p1)) {
                    // 原 1752692 → 1740240：清理调用后 return
                    verifierCleanupCall(cl, s73, s71, s69);
                    return;                                  // 原 1741146
                }
                if (p1.equals(sNull)) {                      // 原 1742850 → 1752692
                    verifierCleanupCall(cl, s73, s71, s69);  // → 1740240
                    return;                                  // 原 1741146
                }
                // 原 1742937：白名单校验链
                runWhitelistChain(param, p1, p2, cl, sColon, sEquals, sObjects, s73, s71, s69);
                return;
            }

            if (msgId == 150) {
                // 原 1743549：if (msgId != 150) return; else → 1753706
                // 原 1753706：params[0] 依次与 Integer.valueOf(0/2/4/6) 比较（嵌套 if）。
                if (Integer.valueOf(0).equals(params[0])) {
                    // 原 1752444：str124 = String.valueOf(params[1]); str125 = String.valueOf(params[2]);
                    String userId = String.valueOf(params[1]);
                    String str125 = String.valueOf(params[2]);
                    if (TextUtils.isEmpty(str125)) {
                        return;                              // 原 1741146
                    }
                    // 原 1738887：if (str125.equals("null")) return; else → 1748336
                    if (str125.equals(sNull)) {
                        return;                              // 原 1741146
                    }
                    // 原 1748336 → … → 1754223 → 1739270 → 1740110/1743801
                    runLicenseCheckChain(param, userId, str125, cl, sColon, sEquals, sObjects, s73, s71, s69);
                    return;
                }
                // 原 1741070：if (Integer.valueOf(2).equals(params[0])) → 1748022 else 1740062
                if (Integer.valueOf(2).equals(params[0])) {
                    // 原 1748022：if (decode(108,13).equals(params[2])) return; else → 1741129
                    if (xorDecode(108, 13).equals(params[2])) {   // "remote_rp_cmd"
                        return;                                   // 原 1741146
                    }
                    // 原 1741129：setResult(Boolean.TRUE)
                    param.setResult(Boolean.TRUE);
                    return;
                }
                // 原 1740062：if (Integer.valueOf(4).equals(params[0])) → 1741099 else 1741764
                if (Integer.valueOf(4).equals(params[0])) {
                    // 原 1741099：setResult(decode(121,9)) = "unlimited"
                    param.setResult(xorDecode(121, 9));
                    return;
                }
                // 原 1741764：if (Integer.valueOf(6).equals(params[0])) → 1743673 else 1741146(return)
                if (Integer.valueOf(6).equals(params[0])) {
                    // 原 1743673：obj = callStaticMethod(findClass("c.ˉˉ.ٴʻ", cl), "ⁱˏ")
                    // 原 1743986：m = callMethod(obj, "ﹳˏ", {"LIC", ""})
                    //   obj == null → 1751282：setResult("")
                    //   !(m instanceof String) → 1747799：setResult("") → 1751282：setResult("")
                    //   m instanceof String → 1753631（见 runLicenseProbeChain）
                    Object probe = ReflectBridgeA.callStaticMethod(
                            ReflectBridgeA.findClass(xorDecode(130, 7), cl),    // "c.ˉˉ.ٴʻ"
                            xorDecode(137, 2), new Object[0]);                  // "ⁱˏ"
                    if (probe != null) {
                        Object m = ReflectBridgeA.callMethod(probe, xorDecode(142, 2),
                                new Object[]{xorDecode(139, 3), ""});           // "ﹳˏ" / "LIC"
                        if (m instanceof String) {
                            runLicenseProbeChain(param, params[1], (String) m, cl, sColon, sEquals, sObjects, s73, s71, s69);
                            return;                                             // 原 1753631
                        }
                        param.setResult("");                                    // 原 1747799
                    }
                    param.setResult("");                                        // 原 1751282
                    return;
                }
                // 原 1741764 的 else → 1741146：直接 return
                return;
            }
            // 其余 msgId：原 1743549 的 if(msgId!=150) return
        } catch (Exception unused) {
            licenseCleanupCall();                            // 原 1739365 兜底
        }
    }

    /**
     * 原 1740240（msgId==132 的“空 / "null"”分支）：
     *   callMethod(callStaticMethod(findClass("c.ﹳﹶ.ʽᵔ", cl), "ᐧٴ"), "ʽᵔ")
     */
    private static void verifierCleanupCall(ClassLoader cl, String s73, String s71, String s69) {
        ReflectBridgeA.callMethod(
                ReflectBridgeA.callStaticMethod(ReflectBridgeA.findClass(s73, cl), s71, new Object[0]),
                s69, new Object[0]);
    }

    /**
     * 原 1753631（msgId==150、params[0]==6、License 探测返回 String）：
     *   原 1747746：String[] parts = probe.split("#")；str = parts[0]
     *   原 1741728：若 isEmpty(str) 先 setResult("")
     *   原 1740732：str137 = new String(Base64.decode(str, 2), UTF_8)；ArrayList arrayList24 = new ArrayList()
     *   原 1752269/1746967/1742658/1759018/1738841/1747051/1739062/1748350：
     *     扫描 str137，把「长度前缀 + 数字段」解析为 int 收集进 arrayList24
     *   原 1754536/1740803/1754161/1743096：由 arrayList24 逐位 XOR 还原候选串（同 runWhitelistChain）
     *   原 1743559：Objects.equals(params[1], sb.toString().split(":")[1])
     *   原 1741597：true → 1737906 setResult(FEATURES)；false → 1754195 清理调用 + setResult("")
     */
    private void runLicenseProbeChain(MethodHookParam param, Object userId, String probe, ClassLoader cl,
                                      String sColon, String sEquals, String sObjects,
                                      String s73, String s71, String s69) {
        try {
            if (TextUtils.isEmpty(probe)) {
                param.setResult("");
                return;
            }
            // 原 1747746：按 "#" 拆分，取第 0 段
            String[] parts = probe.split(xorDecode(144, 1));                 // "#"
            String first = parts[0];
            // 原 1741728：空串先 setResult("")
            if (TextUtils.isEmpty(first)) {
                param.setResult("");
                return;
            }
            // 原 1740732
            String str137 = new String(ReflectBridgeA.base64Decode(first, 2), StandardCharsets.UTF_8);
            ArrayList arrayList24 = new ArrayList();

            // 原 1752269/1746967/1742658/1759018/1738841/1747051/1739062/1748350
            int i188 = str137.length();                                      // 原 1746967
            int i180 = 0;                                                    // 原 1752269
            while (i180 < i188) {                                            // 原 1742658
                int i156 = Character.getNumericValue(str137.charAt(i180));   // 原 1759018
                if (i156 > 0) {                                              // 原 1738841
                    int i181 = i180 + 1;                                     // 原 1747051
                    int i182 = i181 + i156;
                    if (i182 <= i188) {                                      // 原 1747748
                        // 原 1739062
                        arrayList24.add(Integer.valueOf(Integer.parseInt(str137.substring(i181, i182))));
                    }
                }
                i180 += i156 + 1;                                            // 原 1748350
            }

            // 原 1754536/1740803/1754161/1743096：XOR 还原
            int i38 = arrayList24.size();                                    // 原 1754536
            StringBuilder sb15 = new StringBuilder();
            for (int i183 = 0; i183 < i38; i183++) {                         // 原 1740803/1754161
                // 原 1743096
                sb15.append((char) ((((i183 << 2) + i38)
                        + (ReflectBridgeA.intValue(arrayList24.get(i183)) ^ (i183 * i183))) >> 2));
            }

            // 原 1743559：obj18 是调用方传入的用户标识，不是 Base64 授权段。
            Class<?> m92 = ReflectBridgeA.findClass(sObjects, null);
            String[] parts2 = sb15.toString().split(sColon);
            boolean z3 = ReflectBridgeA.boolValue(
                    ReflectBridgeA.callStaticMethod(m92, sEquals, new Object[]{userId, parts2[1]}));
            // 原 1741597：z3 ? 1737906 : 1754195
            if (z3) {
                // 原 1737906：setResult(decode(145,1106)) = 付费功能列表
                param.setResult(FEATURES);
            } else {
                // 原 1754195：清理调用 + setResult("")
                verifierCleanupCall(cl, s73, s71, s69);
                param.setResult("");
            }
        } catch (Exception unused) {
            licenseCleanupCall();                                        // 原 1739365 兜底
            param.setResult("");
        }
    }

    /**
     * 白名单校验链（原 1742937 → 1755597 → 1749406 → 1739104 → 1738899 → 1746937
     *   → 1743067/1753658 → 1758412 → 1758293 → 1747424 → 1737874 → 1743905
     *   →（default）→ 1739410 → 1758369 → 1742102 → 1749317/1743024）：
     *
     *   1. str126 = new String(Base64.decode(value, 2), UTF_8)          // 1742937
     *   2. 扫描 str126，把「长度前缀 + 数字段」解析为 int 收集进 arrayList22 // 1749406..1743067
     *   3. sb13 = 由 arrayList22 逐位 XOR 还原的候选串                    // 1743905..1739410
     *   4. Objects.equals(str257=value2, sb13.split(":")[1])            // 1758369
     *   5. true → setResult(Boolean.TRUE)；false → 清理调用 + setResult("") // 1742102
     */
    private void runWhitelistChain(MethodHookParam param, String value, String value2, ClassLoader cl,
                                   String sColon, String sEquals, String sObjects,
                                   String s73, String s71, String s69) {
        try {
            // 原 1742937
            String str126 = new String(ReflectBridgeA.base64Decode(value, 2), StandardCharsets.UTF_8);
            ArrayList arrayList22 = new ArrayList();

            // 原 1749406/1739104：i165 = str126.length(); while (i166 < i165)
            int i165 = str126.length();
            int i166 = 0;                                        // 原 1755597
            while (i166 < i165) {
                // 原 1738899：i158 = Character.getNumericValue(str126.charAt(i166))
                int i158 = Character.getNumericValue(str126.charAt(i166));
                // 原 1746937：if (i158 > 0) → 1753658
                if (i158 > 0) {
                    // 原 1753658：i171 = i166 + 1; i172 = i171 + i158
                    int i171 = i166 + 1;
                    int i172 = i171 + i158;
                    // 原 1758412：if (i172 <= i165) → 1758293
                    if (i172 <= i165) {
                        // 原 1758293：arrayList22.add(Integer.valueOf(str126.substring(i171, i172)))
                        arrayList22.add(Integer.valueOf(str126.substring(i171, i172)));
                    }
                }
                // 原 1743067：i166 += i158 + 1
                i166 += i158 + 1;
            }

            // 原 1747424：i168 = arrayList22.size(); sb13 = new StringBuilder()
            int i168 = arrayList22.size();
            StringBuilder sb13 = new StringBuilder();
            // 原 1743905：while (i174 < i168) → default(1743096 同构块)
            for (int i174 = 0; i174 < i168; i174++) {
                // 原 default(0xe14)：sb13.append((char)(((i<<2)+i168+(intValue(arrayList22.get(i))^(i*i)))>>2))
                sb13.append((char) ((((i174 << 2) + i168)
                        + (ReflectBridgeA.intValue(arrayList22.get(i174)) ^ (i174 * i174))) >> 2));
                // 原 1739410：i174++
            }

            // 原 1758369：z = ((Boolean) callStaticMethod(findClass("java.util.Objects", null), "equals",
            //           {value2, sb13.toString().split(":")[1]})).booleanValue()
            Class<?> m9 = ReflectBridgeA.findClass(sObjects, null);
            String[] parts = sb13.toString().split(sColon);
            boolean z = ReflectBridgeA.boolValue(
                    ReflectBridgeA.callStaticMethod(m9, sEquals, new Object[]{value2, parts[1]}));
            // 原 1742102：z ? 1749317 : 1743024
            if (z) {
                // 原 1749317：setResult(Boolean.TRUE) → 1741146
                param.setResult(Boolean.TRUE);
            } else {
                // 原 1743024：callMethod(callStaticMethod(findClass("c.ﹳﹶ.ʽᵔ", cl), "ᐧٴ"), "ʽᵔ")
                //            setResult(str131="") → 1741146
                verifierCleanupCall(cl, s73, s71, s69);
                param.setResult("");
            }
        } catch (Exception unused) {
            licenseCleanupCall();                                // 原 1739365 兜底
        }
    }

    /**
     * msgId==150 的 License 校验链（原 1748336 → 1755711 → 1755359 → 1746563
     *   → 1758277 → 1751369 → 1754134 → 1754223 → 1739270 → 1740110/1743801）：
     *   1. str127 = new String(Base64.decode(str30, 2), UTF_8)          // 1748336
     *   2. 扫描 str127，把「长度前缀 + 数字段」解析为 int 收集进 arrayList14 // 1755711..1751369
     *   3. sb14 = 由 arrayList14 逐位 XOR 还原的候选串                    // 1758277..1754134
     *   4. Objects.equals(str124, sb14.split(":")[1])                   // 1754223
     *   5. 匹配 → setResult(TRUE)；不匹配 → 清理调用 + setResult(FALSE)
     */
    private void runLicenseCheckChain(MethodHookParam param, String userId, String str30, ClassLoader cl,
                                      String sColon, String sEquals, String sObjects,
                                      String s73, String s71, String s69) {
        try {
            // 原 1748336
            String str127 = new String(ReflectBridgeA.base64Decode(str30, 2), StandardCharsets.UTF_8);
            ArrayList arrayList14 = new ArrayList();

            // 原 1755711：i167 = str127.length()
            int i167 = str127.length();
            int i178 = 0;
            while (i178 < i167) {                                // 原 1755359
                // 原 1747376：i159 = Character.getNumericValue(str127.charAt(i178))
                int i159 = Character.getNumericValue(str127.charAt(i178));
                // 原 1754533：if (i159 > 0) → 1751368
                if (i159 > 0) {
                    // 原 1751368：i175 = i178 + 1; i176 = i175 + i159
                    int i175 = i178 + 1;
                    int i176 = i175 + i159;
                    // 原 1749666：arrayList14.add(Integer.valueOf(str127.substring(i175, i176)))
                    if (i176 <= i167) {
                        arrayList14.add(Integer.valueOf(str127.substring(i175, i176)));
                    }
                }
                // 原 1747465/1751368：i178 += i159 + 1（同白名单链）
                i178 += i159 + 1;
            }

            // 原 1746563：i170 = arrayList14.size(); sb14 = new StringBuilder()
            int i170 = arrayList14.size();
            StringBuilder sb14 = new StringBuilder();
            // 原 1758277：while (i178 < i170) → 1751369（同构 XOR 还原块）
            for (int i = 0; i < i170; i++) {
                sb14.append((char) ((((i << 2) + i170)
                        + (ReflectBridgeA.intValue(arrayList14.get(i)) ^ (i * i))) >> 2));
            }

            // 原 1754223：z2 = ((Boolean) callStaticMethod(findClass("java.util.Objects", null), "equals",
            //           {str124, sb14.toString().split(":")[1]})).booleanValue()
            Class<?> m75 = ReflectBridgeA.findClass(sObjects, null);
            String[] parts = sb14.toString().split(sColon);
            boolean z2 = ReflectBridgeA.boolValue(
                    ReflectBridgeA.callStaticMethod(m75, sEquals, new Object[]{userId, parts[1]}));
            // 原 1739270：不匹配时清理授权；匹配时返回 true。
            if (!z2) {
                // 原 1740110：callMethod(callStaticMethod(findClass("c.ﹳﹶ.ʽᵔ", cl), "ᐧٴ"), "ʽᵔ")
                //            setResult(Boolean.FALSE)
                verifierCleanupCall(cl, s73, s71, s69);
                param.setResult(Boolean.FALSE);
            } else {
                // 原 1743801：setResult(Boolean.TRUE)
                param.setResult(Boolean.TRUE);
            }
        } catch (Exception unused) {
            licenseCleanupCall();                                // 原 1739365 兜底
        }
    }

    /** bypassMode=1：拦截 License 校验调用，伪造会员返回（原状态机 1738198 起） */
    private void hookLicense(MethodHookParam param) throws Throwable {
        super.beforeHookedMethod(param);                 // 原 1738198
        try {
            // 原 1738198：m43 = callStaticMethod(findClass("c.ˉˉ.ٴʻ", cl), "ⁱˏ")
            Object m43 = ReflectBridgeA.callStaticMethod(
                    ReflectBridgeA.findClass(xorDecode(27, 7), this.hostClassLoader),
                    xorDecode(34, 2), new Object[0]);
            if (m43 == null) {
                // 原 1738198 的 else → 1755400
                licenseFallback(param);
                return;
            }
            // 原 1752329：m732 = callMethod(m43, "ﹳˏ", {"LIC", ""})
            Object m732 = ReflectBridgeA.callMethod(m43, xorDecode(83, 2),
                    new Object[]{xorDecode(80, 3), ""});
            if (m732 == null) {
                // 原 1752329 的 else → 1755400
                licenseFallback(param);
                return;
            }
            // 原 1739179：str121 = String.valueOf(m732); i160 = str121.length()
            String str121 = String.valueOf(m732);
            int len = str121.length();
            // 原 1739043：while (i6 < len) → 1741734；退出 → 1755400
            int i6 = 0;
            while (i6 < len) {
                // 原 1741734：cp = str121.codePointAt(i6); if (!Character.isWhitespace(cp)) → 1748027
                int cp = str121.codePointAt(i6);
                if (!Character.isWhitespace(cp)) {
                    // 原 1748027：setResult(null) → 1747701(return)
                    param.setResult(null);
                    return;
                }
                // 原 1747051：i6 += Character.charCount(cp) → 1739043
                i6 += Character.charCount(cp);
            }
            // 原 1755400
            licenseFallback(param);
        } catch (Exception unused) {
            // 原 1739365：callMethod(callStaticMethod(findClass("c.ﹳﹶ.ʽᵔ", cl), "ᐧٴ"), "ʽᵔ") → return
            licenseCleanupCall();
        }
    }

    /**
     * 原 1755400：
     *   callMethod(callStaticMethod(findClass("c.ﹳﹶ.ʽᵔ", cl), "ᐧٴ"), "ʽᵔ")
     *   callMethod(thisObject, "ˑᵎ", {805})
     * 随后 → 1747701（直接 return，不 setResult）。
     */
    private void licenseFallback(MethodHookParam param) {
        try {
            licenseCleanupCall();                        // 原 1755400 第一句
            ReflectBridgeA.callMethod(param.thisObject, xorDecode(102, 2),
                    new Object[]{Integer.valueOf(805)}); // 原 1755400 第二句
            // 原 1747701：return（无 setResult）
        } catch (Exception unused) {
            // 原 1739365
        }
    }

    /** 原 1739365：callMethod(callStaticMethod(findClass("c.ﹳﹶ.ʽᵔ", cl), "ᐧٴ"), "ʽᵔ") */
    private void licenseCleanupCall() {
        ReflectBridgeA.callMethod(
                ReflectBridgeA.callStaticMethod(
                        ReflectBridgeA.findClass(xorDecode(73, 7), this.hostClassLoader),
                        xorDecode(71, 2), new Object[0]),
                xorDecode(69, 2), new Object[0]);
    }

    /** XOR 字符串池解码（原 m16/m100：sArr[i+j] ^ key） */
    private static String xorDecode(int off, int len) {
        return ReflectBridgeA.decodeXor(BYPASS_POOL, off, len, 5559);
    }

    /** afterHookedMethod 用的第二套 key（原 key=55463） */
    private static String xorDecode(int off, int len, int key) {
        return ReflectBridgeA.decodeXor(BYPASS_POOL, off, len, key);
    }

}
