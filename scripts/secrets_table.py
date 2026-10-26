"""敏感常量的明文表(**只在内部仓提交,绝不进公开仓**)。

常量名 -> 明文。名字与源码里 Secret.of(SecretConstants.XXX) 的引用一一对应。
改这里之后跑 scripts/encode_secrets.py 重新生成密文。

公开仓没有本文件,构建时直接用同步过去的 SecretConstants.java(密文)。
若某个内部 CI 也不想落明文,可改用环境变量 WXH_SECRETS_B64(见 encode_secrets.py)。
scripts/publish_public.py 的 DENY 列表里有本文件,同步时不会过去。

直接运行本脚本可导出 CI Secrets 用的两份文件(默认写到 data/secrets/):

    python -X utf8 scripts/secrets_table.py [--output-dir DIR] [--name PREFIX]

    secrets.json  可读的明文 JSON
    secrets.b64   WXH_SECRETS_B64 的值(明文 JSON 的 Base64)
"""
import argparse
import base64
import json
from pathlib import Path

SECRETS = {
    # XposedInit
    "WECHAT_PACKAGE": "com.tencent.mm",
    "WECHAT_LAUNCHER_CLASS": "com.tencent.mm.ui.LauncherUI",
    "APPBRAND_0": "com.tencent.mm:appbrand0",
    "APPBRAND_1": "com.tencent.mm:appbrand1",
    "IN_MEMORY_DEX_LOADER": "dalvik.system.InMemoryDexClassLoader",
    # 壳身份与入口
    "SHELL_PACKAGE": "cn.android.x",
    "SHELL_ENTRY": "com.android.x.XposedInit",
    "SHELL_CERT_PREFIX": "assets/8af2692bdcb8661da163b4204b5f5d5e",
    "SHELL_GOTO_SETTINGS": "gotosettings",
    "SHELL_UPDATE_HOST": "v.weixiaov.wang",
    "SHELL_API_HOST": "wxp2022.vip",

    # InMemoryDexLoadHook
    # X 3.0（cn.android.x）
    "COMPONENT_X30": "com.android.xc.Wrapper.HookWrapper",
    "X30_BRIDGE_CLASS": "com.android.xc.WxJniCoreBridge",
    "X30_LOADER_CLASS": "com.android.x.xposed.hook.WxCoreLoader",
    # 核心已内置为 wxcore 212，类名/方法名只保留这一套（旧核心 202 已不再加载）
    "X30_UPDATE_CLASS": "c.ˏᵎ.ˎ",
    "X30_SETTINGS_CLASS": "c.ˉˆ.ʼˊ",
    # 更新类里的关键方法
    "X30_PARAMS_APPLY": "ˋˉ",
    "X30_PARAMS_VERIFY": "ˑˏ",
    "X30_VERIFIER_EXPIRED": "ᵎᐧ",
    "X30_DOWNLOAD_PARAMS": "ⁱᵔ",
    "X30_DOWNLOAD_CORE": "ˈʽ",
    # 核心调用 native 桥的统一包装类
    "X30_BRIDGE_WRAPPER": "c.ˊﹶ.ˉˎ",
    "X30_BRIDGE_CALL": "ﾞⁱ",
    "X30_SET_DISABLE": "ﹳᵎ",
    "X30_DISABLE_FEATURES": "ᴵˎ",
    "X30_CALL_METHOD": "CallMethod",
    # X 3.0 guard / UI / feature registry
    "X30_GUARD_DISABLE_EXTRA": "ʿᴵ",
    "X30_UI_CLASS": "c.ˏᴵ.ʻᵔ",
    "X30_UI_OPTIONS": "ٴˋ",
    "X30_UI_KEYWORDS": "ᵔˑ",
    "X30_UI_GATE": "ﾞʿ",
    "X30_UI_ADAPTER": "c.ˆﾞ.ˋʼ",
    "X30_ADAPTER_GROUPS": "ﾞʿ",
    "X30_ADAPTER_ITEMS": "ˋʼ",
    "X30_CORE_DATA_CLASS": "c.ˏᵎ.ٴˑ",
    "X30_CORE_DATA_GET": "ˋʼ",
    # 更多页入口方法（类名复用 X30_UI_CLASS）
    "X30_MORE_METHOD": "ʻᵔ",
    # 功能包入口方法
    "X30_ENTRY_FINISH": "finish",
    "X30_ENTRY_INIT": "init",
    "X30_ENTRY_PUBLISH": "publish",
    "X30_ENTRY_GET_DATA": "getData",
    "X30_ENTRY_REMITTANCE_SCENE": "on_RemittanceDetailUI_onSceneEnd",
    # 更新任务
    "X30_UPDATE_POST": "onPostExecute",
    "X30_UPDATE_WORK": "doInBackground",
    # 授权标签
    "X30_TAG_VIP": "tag_vip",
    "X30_TAG_PRO": "tag_pro",
    # params 危险键（逗号分隔）
    "X30_DANGEROUS_KEYS": "del_fp,del_param,disable_code,disable_features,"
                          "disable_settings,disable_xm,eject,force_restart",
    # DATA 表字段
    "X30_TAG_FP": "fp",
    "X30_TAG_FP_ASYNC": "fp_async",
    "X30_TAG_FP_VERSIONS": "FPVersions",
    "X30_TAG_FP_VERSIONS_V7": "FPVersions_v7",
    "X30_TAG_LATEST_VERSIONS": "LatestVersions",
    "X30_TAG_VALID": "valid",
    "X30_TAG_S_VALID": "s_valid",
    "X30_TAG_NEW_USER": "is_new_user",
    "X30_TAG_DISCLAIMER": "disclaimer_disable",
    "X30_TAG_HOOK_FAIL": "hookFail",
    "X30_TAG_SAFE_MODE": "safe_mode",
    "X30_TAG_SAFE_MODE_CNT": "safe_mode_cnt",
    "X30_TAG_DISABLE_SAFEMODE": "disable_safemode",
    "X30_FEATURE_MANAGER": "c.ˎﹳ.ʾᐧ",
    "X30_FEATURE_UNLOAD": "ⁱʽ",
    "X30_FEATURE_UNLOAD_ONE": "ʼˋ",
    "X30_FEATURE_LOAD_ONE": "ˏـ",
    "X30_FEATURE_LOAD_CLASS": "ᴵʻ",
    "X30_FEATURE_LOAD_DEX": "ᵎי",
    "X30_UNLOAD_HANDLER": "c.ˎﹳ.ⁱˋ",
    "X30_UNLOAD_HANDLER_CALL": "ⁱˋ",
    "X30_SETTINGS_WRAPPER": "c.ˏᵎ.ʾʻ",
    "X30_SETTINGS_BOOL": "ᐧᵎ",
    "X30_REGISTRATION": "registration",
    "X30_PARAMS_FILE_METHOD": "ᵔˋ",
    "X30_MENU_CLASS_1": "c.ˏᵎ.ˑᵎ",
    "X30_MENU_METHOD_1": "ᴵـ",
    "X30_MENU_CLASS_2": "c.ˏᵎ.ʾﹳ",
    "X30_MENU_METHOD_2": "יʾ",
    "X30_MENU_CLASS_3": "c.ˏᵎ.ˎ",
    "X30_MENU_METHOD_3": "ʾʽ",
    "X30_COMPONENT_UNLOAD_CLASS": "c.ˎﹳ.ᵢʼ",
    "X30_CORE_DATA_INSTANCE_METHOD": "ˊﹶ",
    "X30_UPDATE_INIT_METHOD": "יˑ",
    "X30_BASE_UPDATE_TASK": "c.ˏᵎ.ᵢᵔ$ʾʻ",
    "X30_COMPONENT_NAME_METHOD": "ﾞʿ",
    "X30_ENTRY_BASE": "com.android.xf.base.Wrapper.Init",
    "X30_ENTRY_DONATION": "com.android.xf.donation.Wrapper.Init",
    "X30_ENTRY_THEMES": "com.android.xf.themes.Wrapper.Init",
    "X30_BASE_SETTINGS": "b.ⁱᵔ.ˈˈ",
    "X30_BASE_REGISTRY": "b.ʾᵢ.ʾᵢ",
    # base 包的文件列表刷新：宿主数据源返回 null 时内部会 addAll(null) 抛 NPE
    "X30_BASE_FILE_REFRESH_CLASS": "b.ʾᵢ.ˉᐧ$ˆٴ",
    "X30_BASE_FILE_REFRESH_METHOD": "ﾞᐧ",
    "X30_BASE_DATA_GET_METHOD": "ˆʿ",
    "X30_INIT_GATE_CLASS": "b.ⁱᵔ.ˉˏ",
    "X30_INIT_GATE_METHOD": "ˑٴ",
    "X30_MENU_HIDDEN_METHOD": "ᵎˆ",
    "X30_MENU_VISIBLE_METHOD": "ᵢˎ",
    "X30_REGISTRY_REMOVE": "ʽי",
    "X30_REGISTRY_PUBLISH": "ˈˈ",
    "X30_REGISTRY_GET_DATA": "ʻˑ",
    "X30_BASE_DISABLE_GETTER": "ⁱʾ",
    "METHOD_ON_UPDATE_CHECK": "on_update_check",
    "METHOD_DISABLE": "disable",
    "METHOD_PROCESS_METADATA": "process_metadata",
    "METHOD_UPDATE_LICENSE": "updateLicense",

    # WxComponentHooks
    # 2.44_5.41 \u65b0\u6838\u5fc3\uff08352186\uff09\u7684\u540c\u4e00\u7ec4\u65b9\u6cd5
    # \u6350\u8d60 keycard \u5305\u662f\u5426\u53ef\u7528\u7684\u5224\u5b9a\uff1aL\u1d54\u02cf/\u1427\u05d9;->\u02bf\u0674(String,Object[])Z
    # X 3.0 donation \u5305\u540c\u4e00\u65b9\u6cd5\uff0c\u6df7\u6dc6\u6210 d.* \u547d\u540d\u7a7a\u95f4
    "DONATION_REQUIRES_CLASS_V30": "d.\u05d9\u02bb.\u02ce\u02cf",
    "DONATION_REQUIRES_METHOD_V30": "\u1427\u05d9",

    # CallMethodBypassHook
    "VERIFIER_SERVICE": "verifier6",
    "ACTION_PARAM": "param",
    "MIN_SUPPORTED_VERSION": "8.0.49",
    "UNLIMITED": "unlimited",
    "REMOTE_COMMAND": "remote_rp_cmd",
    "FEATURES": (
        "remove_notice,priority_update,extra_df,send_raw_image,auto_comment_robot,"
        "text_rep_nickname,sort_contacts,contacts_select_sex,contacts_select_location,"
        "modify_steps,themes,fake_gps,f_autoreply_export,auto_contain_new_contact,"
        "chatroom_send_multi_invites,zombie_auto_delete,tail_mode,"
        "redpacket_amount_accumulate,integrated_allowed,send_multple_friendcard,"
        "scan_gallery_to_camera,videocall_ringtone_advanced,wxid_friend_req,"
        "export_chatroom_members,auto_download_chat_media,werun_like_all,"
        "moment_original_image,fake_moment_forward,zombie_silent_search,"
        "zombie_transfer_search,show_realname,auto_accept_neighbor_req,fast_send,"
        "tag_forward,keyword_notification,fake_transfer_amount,accept_neighbor_friendreq,"
        "auto_friendreq,new_chatroom_chat_blacklist,auto_label_new_contact,"
        "record_showid,unlimited_voice_sel,extract_vid_audio,auto_remark_new_contact,"
        "fav_wenote,multi_response,rp_keyword,chatroom_container_tags,"
        "moments_container_enable,sns_export,sns_keyword_notification,mass_sns_like,"
        "export_contacts,friend_request_import,scheduled_task,modify_message,"
        "task_chatroom_invite_allow_by_identity,chat_schedule_forward,auto_clean_moment,"
        # 关于 -> 自助获取高级功能：四项独立于打赏功能集
        "multichat_autoforward,moments_auto_forward,secret_friend,auto_accept_chatroom_invite,"
        # 关于 -> 自助获取高级功能：内置模式
        "integrated_mode"),

    # LicenseData

    "LATEST_VERSIONS": (
        "{\"fp_themes\":\"71\",\"fp_sf\":\"4b\",\"fp_af\":\"ab\",\"fp_vidurlparser\":\"1e\","
        "\"fp_mf\":\"89\",\"fp_donation\":\"47\",\"fp_xv\":\"1f2\",\"fp_base\":\"20d\","
        "\"meta\":\"1902dffe702\",\"string\":\"18fe3f447ec\",\"h_p\":\"18eec2d7db3\","
        "\"lib\":\"9\",\"core\":\"cf\",\"apk\":\"42,2.2,821452f9\"}"),
    "FP_VERSIONS": "{\"themes\":113,\"donation\":71,\"base\":525,\"vidurlparser\":30}",
    "FP": "themes,af,sf,mf",
    "FP_ASYNC": "base,vidurlparser,donation",

    # StartupCheck / ModuleApk
    "PREFS_PATH": "shared_prefs/com.tencent.mm_preferences.xml",
    "ACCOUNT_KEY": "login_weixin_username",
    "MODULE_PACKAGE": "github.shadowbaby.wechatxposed.hook",
    # 构建时由 encodeSecrets 从签名密钥库写入；为空表示不做证书固定。
    "MODULE_CERT_SHA256": "",
    # 授权弹窗文案（明文只存在于本表，运行时由 native 解密）
    "ACTIVATION_GROUP": "1065821554",

    # HostVersionSpoof / DexPaths
    "CLIENT_VERSION_CLASS": "c64.xe",
    "CLIENT_VERSION_FIELD": "g",
    "LAUNCH_SCENE_CLASS": "wx0.d",
    "LAUNCH_SCENE_CALLBACK": "f",
    # 1:1 通话：版本号通过 RUDP 命令 505 上报（4 字节小端）
    # 所有 CGI 的公共请求头：ClientVersion 在这里写入 BaseRequest
    "BASE_REQUEST_FILLER_CLASS": "com.tencent.mm.modelbase.i1",
    "BASE_REQUEST_FILL_METHOD": "fillBaseReq",
    "BASE_REQUEST_SET_VERSION_METHOD": "setClientVersion",
    # 8.0.49 聊天 MVVM 兼容守卫：服务端开关打开时本地强制走旧路径
    "CHAT_CONFIG_HUB_CLASS": "kl1.d",
    "CHAT_CONFIG_GET_METHOD": "b",
    # 证书 hook / 扩展 dex：细节字符串走 native 解密
    "CORE_CERT_CLASS": "c.ˏᵎ.ﾞˏ",
    "CORE_CERT_METHOD": "ʾʻ",
    "CORE_MD5_CLASS": "b.ʾᵢ.ˊˏ",
    "CORE_MD5_METHOD": "ᵔʾ",
    "CORE_CERT_ASSET": "8af2692bdcb8661da163b4204b5f5d5e",
    "FEATURE_PACK_DIR": "x7_3.0",
    "FEATURE_PACK_ASSET_DIR": "x7_3.0/",
    "AES_ALGORITHM": "AES/CBC/PKCS5Padding",
    "AES_KEY_ALGORITHM": "AES",
}


def main():
    """导出明文表:JSON 给人看,Base64 直接填进 WXH_SECRETS_B64。"""
    parser = argparse.ArgumentParser(description="导出明文常量表(仅供内部使用)")
    parser.add_argument("--output-dir", type=Path,
                        default=Path(__file__).resolve().parents[1] / "data" / "secrets",
                        help="输出目录(默认 data/secrets,已在 .gitignore 里)")
    parser.add_argument("--name", default="secrets",
                        help="输出文件名前缀(默认 secrets)")
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    json_path = args.output_dir / (args.name + ".json")
    b64_path = args.output_dir / (args.name + ".b64")
    json_path.write_text(
        json.dumps(SECRETS, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    compact = json.dumps(SECRETS, ensure_ascii=False, separators=(",", ":"))
    b64_path.write_text(
        base64.b64encode(compact.encode("utf-8")).decode("ascii"), encoding="ascii")
    print("已导出 %d 个常量(明文,勿提交):" % len(SECRETS))
    print("  JSON  : " + str(json_path))
    print("  Base64: " + str(b64_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
