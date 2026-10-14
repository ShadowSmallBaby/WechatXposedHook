package github.shadowbaby.wechatxposed.hook.rebuild.support;

import android.text.TextUtils;
import android.util.Base64;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import github.shadowbaby.wechatxposed.hook.rebuild.XorStrings;
import github.shadowbaby.wechatxposed.hook.rebuild.loader.ModuleLogger;

/**
 * 核心 hook:伪造微X的授权返回(原混淆类 c.b)。
 *
 * 微X把授权判断和功能调用都收敛到少数几个入口里,这个方法按入口类型做三件事之一:
 *   VERIFIER_MESSAGE —— CallMethod(int, Object[]):微X的主要入口。按 msgId 分发,
 *                       把校验结果、版本号、功能列表换成模块想要的返回值。
 *   LICENSE_CONTEXT  —— CallMethod(Context):授权上下文。拿到授权串后判断是否为空白,
 *                       空白即放行(返回 null),否则交给内部版本号兜底。
 *   PASSTHROUGH      —— 授权查询:不干预调用本身,只在原方法抛异常且参数是 wxid_ 时
 *                       额外清理一次授权缓存。
 *
 * 授权串的编码:Base64 包住一串「长度前缀 + 数字段」,再按位异或还原成
 * "用户标识:授权内容",最后用 java.util.Objects.equals 和调用方的用户标识比对。
 */
public final class CallMethodBypassHook extends XC_MethodHook {

    /** 处理 CallMethod(int, Object[]),按 msgId 伪造授权校验结果。 */
    public static final int VERIFIER_MESSAGE = 0;

    /** 处理 CallMethod(Context),按授权上下文决定放行。 */
    public static final int LICENSE_CONTEXT = 1;

    /** 原样放行,只在异常时做清理。 */
    public static final int PASSTHROUGH = 2;

    /** 请求授权校验结果。 */
    private static final int MSG_VERIFY_RESULT = 130;

    /** 上报授权数据块。 */
    private static final int MSG_LICENSE_BLOB = 132;

    /** 查询功能。 */
    private static final int MSG_FEATURE_QUERY = 150;

    /**
     * 原 c.b.<clinit> 的字符池。主 key=5559;
     * afterHookedMethod 用的 wxid_ 前缀段是另一套 key=55463。
     */
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

    private static final int POOL_KEY = 5559;
    private static final int AFTER_KEY = 55463;

    /** 微X请求校验结果时用的服务名。 */
    private static final String VERIFIER_SERVICE = decode(18, 9, POOL_KEY);

    /** msgId 130 请求里,表示「这次调用是查参数」的标记。 */
    private static final String ACTION_PARAM = decode(36, 5, POOL_KEY);

    /** 授权数据块里字段之间的分隔符。 */
    private static final String FIELD_SEPARATOR = decode(45, 1, POOL_KEY);

    /** 用来比对的字符串字面量 "null"。 */
    private static final String NULL_TEXT = decode(41, 4, POOL_KEY);

    /** 用来比对的字符串字面量 "true"。 */
    private static final String TRUE_TEXT = decode(104, 4, POOL_KEY);

    /** 微X要求的最低版本号,低于它功能会被禁用。 */
    private static final String MIN_SUPPORTED_VERSION = decode(85, 6, POOL_KEY);

    /** 会员授权标记。 */
    private static final String UNLIMITED = decode(121, 9, POOL_KEY);

    /** 查询功能时表示「远端指令」的标记,命中则不下发功能列表。 */
    private static final String REMOTE_COMMAND = decode(108, 13, POOL_KEY);

    /** 授权串里用户标识与授权内容的分隔符。 */
    private static final String PAYLOAD_SEPARATOR = decode(144, 1, POOL_KEY);

    /** 授权比对用的 JDK 工具类。 */
    private static final String OBJECTS_CLASS = decode(52, 17, POOL_KEY);
    private static final String OBJECTS_EQUALS_METHOD = decode(46, 6, POOL_KEY);

    /** 微X内部的授权服务类与工厂方法。 */
    private static final String VERIFIER_SERVICE_CLASS = decode(27, 7, POOL_KEY);
    private static final String VERIFIER_SERVICE_FACTORY = decode(34, 2, POOL_KEY);

    /** 读出授权对象的字段。 */
    private static final String LICENSE_FIELD = decode(80, 3, POOL_KEY);
    private static final String LICENSE_GETTER_METHOD = decode(83, 2, POOL_KEY);

    /** 清掉当前授权的方法。 */
    private static final String RELEASE_LICENSE_METHOD = decode(69, 2, POOL_KEY);

    /** 清授权前先取小工具对象的类、工厂方法(与方法名共用 RELEASE_LICENSE_METHOD)。 */
    private static final String CLEANUP_CLASS = decode(73, 7, POOL_KEY);
    private static final String CLEANUP_FACTORY_METHOD = decode(71, 2, POOL_KEY);

    /** 把内部版本号顶上去的方法。 */
    private static final String SET_INTERNAL_VERSION_METHOD = decode(102, 2, POOL_KEY);

    /** 顶上去的版本号。 */
    private static final int INTERNAL_VERSION = 805;

    /** 仅当调用方抛异常且参数是这个前缀的微信号时,才额外清理授权缓存。 */
    private static final String WXID_PREFIX = decode(1, 5, AFTER_KEY);

    /** 解锁后开放的功能列表(池 145/1106)。 */
    private static final String FEATURES =
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

    /** VERIFIER_MESSAGE / LICENSE_CONTEXT / PASSTHROUGH。 */
    public final int bypassMode;

    /** 微X组件 dex 的 ClassLoader,用来解析它自己的混淆类。 */
    public final ClassLoader hostClassLoader;

    public CallMethodBypassHook(ClassLoader hostClassLoader, int bypassMode) {
        this.hostClassLoader = hostClassLoader;
        this.bypassMode = bypassMode;
    }

    @Override
    public void beforeHookedMethod(MethodHookParam param) throws Throwable {
        switch (bypassMode) {
            case VERIFIER_MESSAGE:
                handleVerifierCall(param);
                break;
            case LICENSE_CONTEXT:
                handleLicenseContext(param);
                break;
            default:
                super.beforeHookedMethod(param);
                break;
        }
    }

    @Override
    public void afterHookedMethod(MethodHookParam param) throws Throwable {
        super.afterHookedMethod(param);
        if (bypassMode != PASSTHROUGH || !param.hasThrowable()) {
            return;
        }
        String account = String.valueOf(param.args[0]);
        if (!account.startsWith(WXID_PREFIX)) {
            return;
        }
        releaseLicense();
    }

    /**
     * CallMethod(int msgId, Object[] params)。
     *
     * msgId 130 —— 直接给出校验结果:问参数就回最低版本号,问服务就回 "true"。
     * msgId 132 —— 日志留一份授权数据,然后按白名单比对用户标识。
     * msgId 150 —— 查功能:分 0/2/4/6 四种查询,分别走授权校验、远端指令判断、
     *              直接给 "unlimited"、以及读授权对象再比对。
     */
    private void handleVerifierCall(MethodHookParam param) {
        try {
            int msgId = (Integer) param.args[0];
            Object[] params = (Object[]) param.args[1];

            if (msgId == MSG_VERIFY_RESULT) {
                if (ACTION_PARAM.equals(params[0])) {
                    param.setResult(MIN_SUPPORTED_VERSION);
                } else if (VERIFIER_SERVICE.equals(params[0])) {
                    param.setResult(TRUE_TEXT);
                }
                return;
            }

            if (msgId == MSG_LICENSE_BLOB) {
                if (!VERIFIER_SERVICE.equals(params[0])) {
                    return;
                }
                String encodedLicense = String.valueOf(params[1]);
                String expectedUser = String.valueOf(params[2]);
                ModuleLogger.log(Base64.encodeToString(expectedUser.getBytes(), Base64.NO_WRAP));
                if (TextUtils.isEmpty(encodedLicense) || NULL_TEXT.equals(encodedLicense)) {
                    releaseLicense();
                    return;
                }
                verifyAgainstWhitelist(param, encodedLicense, expectedUser);
                return;
            }

            if (msgId == MSG_FEATURE_QUERY) {
                handleFeatureQuery(param, params);
            }
        } catch (Exception e) {
            releaseLicense();
        }
    }

    /** msgId 150:params[0] 是查询类型。 */
    private void handleFeatureQuery(MethodHookParam param, Object[] params) {
        Object queryType = params[0];

        if (Integer.valueOf(0).equals(queryType)) {
            String userId = String.valueOf(params[1]);
            String encodedLicense = String.valueOf(params[2]);
            if (TextUtils.isEmpty(encodedLicense) || NULL_TEXT.equals(encodedLicense)) {
                return;
            }
            verifyLicense(param, userId, encodedLicense);
            return;
        }

        if (Integer.valueOf(2).equals(queryType)) {
            // 远端指令不下发功能列表,其余一律回 true。
            if (!REMOTE_COMMAND.equals(params[2])) {
                param.setResult(Boolean.TRUE);
            }
            return;
        }

        if (Integer.valueOf(4).equals(queryType)) {
            param.setResult(UNLIMITED);
            return;
        }

        if (Integer.valueOf(6).equals(queryType)) {
            // 先从授权服务取出授权对象,再拿它比对;取不到就回空串。
            Object service = XposedHelpers.callStaticMethod(
                    XposedHelpers.findClass(VERIFIER_SERVICE_CLASS, hostClassLoader),
                    VERIFIER_SERVICE_FACTORY);
            if (service == null) {
                param.setResult("");
                return;
            }
            Object license = XposedHelpers.callMethod(service, LICENSE_GETTER_METHOD, LICENSE_FIELD, "");
            if (!(license instanceof String)) {
                param.setResult("");
                return;
            }
            verifyLicenseFromService(param, String.valueOf(params[1]), (String) license);
        }
    }

    /**
     * 白名单校验(msgId 132 路径):把调用方给的授权数据解出来,取 ":" 后半段的用户标识
     * 与实际用户标识比对,一致即放行。
     */
    private void verifyAgainstWhitelist(MethodHookParam param, String encodedLicense, String expectedUser) {
        try {
            String decoded = decodeLicenseBlob(encodedLicense);
            Class<?> objects = objectsClass();
            String licenseUser = decoded.split(FIELD_SEPARATOR)[1];
            if (objectsEqual(objects, expectedUser, licenseUser)) {
                param.setResult(Boolean.TRUE);
            } else {
                releaseLicense();
                param.setResult("");
            }
        } catch (Exception e) {
            releaseLicense();
        }
    }

    /**
     * 授权校验(msgId 150 / 查询类型 0):同样的比对,但比对对象是调用方给的用户标识,
     * 结果回 true / false。
     */
    private void verifyLicense(MethodHookParam param, String userId, String encodedLicense) {
        try {
            String decoded = decodeLicenseBlob(encodedLicense);
            Class<?> objects = objectsClass();
            String licenseUser = decoded.split(FIELD_SEPARATOR)[1];
            if (objectsEqual(objects, userId, licenseUser)) {
                param.setResult(Boolean.TRUE);
            } else {
                releaseLicense();
                param.setResult(Boolean.FALSE);
            }
        } catch (Exception e) {
            releaseLicense();
        }
    }

    /**
     * 从授权对象里读出的授权串再比对(查询类型 6):比对通过就下发完整功能列表,
     * 否则清掉授权并回空串。
     */
    private void verifyLicenseFromService(MethodHookParam param, String userId, String license) {
        try {
            if (TextUtils.isEmpty(license)) {
                param.setResult("");
                return;
            }
            String encodedLicense = license.split(PAYLOAD_SEPARATOR)[0];
            if (TextUtils.isEmpty(encodedLicense)) {
                param.setResult("");
                return;
            }
            String decoded = decodeLicenseBlob(encodedLicense);
            Class<?> objects = objectsClass();
            String licenseUser = decoded.split(FIELD_SEPARATOR)[1];
            if (objectsEqual(objects, userId, licenseUser)) {
                param.setResult(FEATURES);
            } else {
                releaseLicense();
                param.setResult("");
            }
        } catch (Exception e) {
            releaseLicense();
            param.setResult("");
        }
    }

    /**
     * CallMethod(Context):从授权服务取一次授权,只要拿到的不是一串空白就放行(返回 null);
     * 拿不到或全是空白,就把微X内部版本号顶到 805,让它走自己的兜底逻辑。
     */
    private void handleLicenseContext(MethodHookParam param) throws Throwable {
        super.beforeHookedMethod(param);
        try {
            Object service = XposedHelpers.callStaticMethod(
                    XposedHelpers.findClass(VERIFIER_SERVICE_CLASS, hostClassLoader),
                    VERIFIER_SERVICE_FACTORY);
            if (service == null) {
                raiseInternalVersion(param);
                return;
            }
            Object license = XposedHelpers.callMethod(service, LICENSE_GETTER_METHOD, LICENSE_FIELD, "");
            if (license == null) {
                raiseInternalVersion(param);
                return;
            }
            String text = String.valueOf(license);
            for (int index = 0; index < text.length(); ) {
                int codePoint = text.codePointAt(index);
                if (!Character.isWhitespace(codePoint)) {
                    param.setResult(null);
                    return;
                }
                index += Character.charCount(codePoint);
            }
            raiseInternalVersion(param);
        } catch (Exception e) {
            releaseLicense();
        }
    }

    /** 清掉授权缓存,再把内部版本号顶上去;任何一步失败都静默跳过。 */
    private void raiseInternalVersion(MethodHookParam param) {
        try {
            releaseLicense();
            XposedHelpers.callMethod(param.thisObject, SET_INTERNAL_VERSION_METHOD, INTERNAL_VERSION);
        } catch (Exception ignored) {
            // 兜底路径,失败不影响原方法执行。
        }
    }

    /** 找到微X的授权小工具并让它清掉当前授权。 */
    private void releaseLicense() {
        Object utility = XposedHelpers.callStaticMethod(
                XposedHelpers.findClass(CLEANUP_CLASS, hostClassLoader), CLEANUP_FACTORY_METHOD);
        XposedHelpers.callMethod(utility, RELEASE_LICENSE_METHOD);
    }

    /** 原实现经反射调用 java.util.Objects.equals,保持同一调用形态。 */
    private static Class<?> objectsClass() {
        return XposedHelpers.findClass(OBJECTS_CLASS, null);
    }

    private static boolean objectsEqual(Class<?> objects, String left, String right) {
        return (Boolean) XposedHelpers.callStaticMethod(objects, OBJECTS_EQUALS_METHOD, left, right);
    }

    /**
     * 还原授权串:Base64 → 文本 → 一串「长度前缀 + 数字段」→ 按位异或回 "用户标识:授权内容"。
     *
     * 例如 "fixture:test-user" 会被编码成一串数字,每段前带一个数字表示该段长度。
     */
    private static String decodeLicenseBlob(String encoded) {
        String packed = new String(Base64.decode(encoded, Base64.NO_WRAP), StandardCharsets.UTF_8);
        int[] numbers = unpackSegments(packed);
        StringBuilder decoded = new StringBuilder(numbers.length);
        for (int i = 0; i < numbers.length; i++) {
            decoded.append((char) ((((i << 2) + numbers.length) + (numbers[i] ^ (i * i))) >> 2));
        }
        return decoded.toString();
    }

    /** 读出 packed 里每个「长度前缀 + 数字段」表示的数字,越界或前缀为 0 即跳过。 */
    private static int[] unpackSegments(String packed) {
        int[] segments = new int[packed.length()];
        int count = 0;
        int index = 0;
        while (index < packed.length()) {
            int digits = Character.getNumericValue(packed.charAt(index));
            if (digits > 0) {
                int start = index + 1;
                int end = start + digits;
                if (end <= packed.length()) {
                    segments[count++] = Integer.parseInt(packed.substring(start, end));
                }
            }
            index += digits + 1;
        }
        return Arrays.copyOf(segments, count);
    }

    private static String decode(int offset, int length, int key) {
        return XorStrings.decode(BYPASS_POOL, offset, length, key);
    }
}