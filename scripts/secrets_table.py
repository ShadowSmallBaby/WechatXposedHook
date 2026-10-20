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
    "APPBRAND_0": "com.tencent.mm:appbrand0",
    "APPBRAND_1": "com.tencent.mm:appbrand1",
    "IN_MEMORY_DEX_LOADER": "dalvik.system.InMemoryDexClassLoader",

    # InMemoryDexLoadHook
    "COMPONENT_BASE": "com.fkzhang.wxfeatures.base.Wrapper.Init",
    "COMPONENT_CORE": "com.fkzhang.wechatxposedhooks.Wrapper.HookWrapper",
    "COMPONENT_DONATION": "com.fkzhang.wxfeatures.donation.Wrapper.Init",
    "COMPONENT_THEMES": "com.fkzhang.wxfeatures.themes.Wrapper.Init",
    # X 3.0（cn.android.x）
    "COMPONENT_X30": "com.android.xc.Wrapper.HookWrapper",
    "X30_BRIDGE_CLASS": "com.android.xc.WxJniCoreBridge",
    "X30_LOADER_CLASS": "com.android.x.xposed.hook.WxCoreLoader",
    "X30_LICENSE_CLASS": "c.ـˉ.ˈʽ",
    "X30_UPDATE_CLASS": "c.ـˉ.ⁱⁱ",
    "X30_SETTINGS_CLASS": "c.יᴵ.ٴʻ",
    # core v207 重新混淆后的名字（2.44 CoreDex 与 v206 一一对应的类）
    "X30_LICENSE_CLASS_V207": "c.ˏᵎ.ـʼ",
    "X30_UPDATE_CLASS_V207": "c.ˏᵎ.ˎ",
    "X30_SETTINGS_CLASS_V207": "c.ˉˆ.ʼˊ",
    # 更新类里的关键方法（旧名 / v207 名）
    "X30_PARAMS_APPLY": "ʿʽ",
    "X30_PARAMS_APPLY_V207": "ˋˉ",
    "X30_PARAMS_VERIFY": "ʼﾞ",
    "X30_PARAMS_VERIFY_V207": "ˑˏ",
    "X30_VERIFIER_EXPIRED": "ﹶٴ",
    "X30_VERIFIER_EXPIRED_V207": "ᵎᐧ",
    "X30_DOWNLOAD_PARAMS": "ˊᵔ",
    "X30_DOWNLOAD_PARAMS_V207": "ⁱᵔ",
    "X30_DOWNLOAD_CORE": "ﹶˆ",
    "X30_DOWNLOAD_CORE_V207": "ˈʽ",
    # 核心调用 native 桥的统一包装类（v206 是 c.ˈⁱ.ᵔﹶ，v207 重命名）
    "X30_BRIDGE_WRAPPER": "c.ˈⁱ.ᵔﹶ",
    "X30_BRIDGE_WRAPPER_V207": "c.ˊﹶ.ˉˎ",
    "X30_BRIDGE_CALL": "ʻᵢ",
    "X30_BRIDGE_CALL_V207": "ﾞⁱ",
    "X30_SET_DISABLE": "ـˑ",
    "X30_SET_DISABLE_V207": "ﹳᵎ",
    "X30_DISABLE_FEATURES": "ᵔʿ",
    "X30_DISABLE_FEATURES_V207": "ᴵˎ",
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
    "X30_FORCE_FLAG_1": "ᵢʼ",
    "X30_FORCE_FLAG_2": "ⁱי",
    "X30_FORCE_FLAG_3": "ʿᵢ",
    "X30_FORCE_FLAG_4": "ˏـ",
    "X30_FORCE_FLAG_5": "ˉˆ",
    "X30_FORCE_FLAG_6": "ᵎי",
    "X30_ENTRY_BASE": "com.android.xf.base.Wrapper.Init",
    "X30_ENTRY_DONATION": "com.android.xf.donation.Wrapper.Init",
    "X30_ENTRY_THEMES": "com.android.xf.themes.Wrapper.Init",
    "X30_BASE_SETTINGS": "b.ⁱᵔ.ˈˈ",
    "X30_BASE_REGISTRY": "b.ʾᵢ.ʾᵢ",
    "X30_INIT_GATE_CLASS": "b.ⁱᵔ.ˉˏ",
    "X30_INIT_GATE_METHOD": "ˑٴ",
    "X30_MENU_HIDDEN_METHOD": "ᵎˆ",
    "X30_MENU_VISIBLE_METHOD": "ᵢˎ",
    "X30_REGISTRY_REMOVE": "ʽי",
    "X30_REGISTRY_PUBLISH": "ˈˈ",
    "X30_REGISTRY_GET_DATA": "ʻˑ",
    "X30_BASE_DISABLE_GETTER": "ⁱʾ",
    "COMPONENT_NAME_BASE": "BaseDex",
    "COMPONENT_NAME_CORE": "CoreDex",
    "COMPONENT_NAME_DONATION": "DonationDex",
    "COMPONENT_NAME_THEMES": "ThemesDex",
    "METHOD_ON_UPDATE_CHECK": "on_update_check",
    "METHOD_DISABLE": "disable",
    "METHOD_PROCESS_METADATA": "process_metadata",
    "METHOD_UPDATE_LICENSE": "updateLicense",
    "METHOD_DELAYED_CHECK": "delayed_check",

    # WxComponentHooks
    "BASE_ENTRY_CLASS": "\ufe76\u02c6.\u02bc\u05d9",
    "BASE_ENTRY_METHOD": "\u2071\u02bc",
    "BASE_HOOK_ARGUMENT_CLASS": "\ufe76\u02c6.\u02c9\u02d1$\u02bf\u1d54",
    "WX_JNI_CORE_BRIDGE": "com.fkzhang.wechatxposedhooks.WxJniCoreBridge",
    "CALL_METHOD": "CallMethod",
    "CORE_VERIFIER_CLASS": "c.\ufe76\u02c9.\u1d54\u02c9",
    "CORE_VERIFY_SIGNATURE_METHOD": "\u0674\u02bc",
    "CORE_VERIFY_BOOLEAN_STRING_METHOD": "\u1d62",
    "CORE_VERIFY_UPDATED_TIPS_METHOD": "\u02ce\u02c8",
    "CORE_POLLING_CLASS": "c.\u02cb.\u1d62\u02d1",
    "CORE_POLLING_METHOD": "\u02cb\u1d4e",
    "CORE_LICENSE_CLASS": "c.\ufe76\u02c9.\u0640\u02cb",
    "CORE_LICENSE_METHOD": "\u0640\u02cb",
    "CORE_DISABLE_SETTER": "\u02d1\u1d4e",
    "CORE_DISABLE_GETTER": "\u02bb\u02d1",
    "CORE_STATUS_CHECK": "\u2071\u1d62",
    "CORE_VERIFIER_FACTORY": "\u1d4e\u0640",
    # 2.44_5.41 \u65b0\u6838\u5fc3\uff08352186\uff09\u7684\u540c\u4e00\u7ec4\u65b9\u6cd5
    "CORE_VERIFIER_CLASS_V2": "c.\u02bb\u02bb.\u0640\u02cb",
    "CORE_DISABLE_SETTER_V2": "\u02c9\ufe76",
    "CORE_DISABLE_GETTER_V2": "\u2071\u05d9",
    "CORE_STATUS_CHECK_V2": "\u02bd\u02bd",
    "CORE_VERIFIER_INSTANCE_V2": "\u02c9\u0674",
    "THEMES_ENTRY_CLASS": "\ufe76\u02ce.\u0640\u02c6",
    "THEMES_ENTRY_METHOD": "\u02bd\u02be",
    "THEMES_HOOK_ARGUMENT_CLASS": "\ufe76\u02ce.\u02bb\u02ce$\uff9e\u02cf",
    "DONATION_ENTRY_CLASS": "\u1d54\u02cf.\u1427\u05d9",
    "DONATION_ENTRY_METHOD": "\u02cf\u02ca",
    "DONATION_HOOK_ARGUMENT_CLASS": "\u1d54\u02cf.\u2071\u05d9$\u02bf\u0674",
    # \u6350\u8d60 keycard \u5305\u662f\u5426\u53ef\u7528\u7684\u5224\u5b9a\uff1aL\u1d54\u02cf/\u1427\u05d9;->\u02bf\u0674(String,Object[])Z
    "DONATION_REQUIRES_CLASS": "\u1d54\u02cf.\u1427\u05d9",
    "DONATION_REQUIRES_METHOD": "\u02bf\u0674",

    # CallMethodBypassHook
    "VERIFIER_SERVICE": "verifier6",
    "ACTION_PARAM": "param",
    "MIN_SUPPORTED_VERSION": "8.0.49",
    "UNLIMITED": "unlimited",
    "REMOTE_COMMAND": "remote_rp_cmd",
    "OBJECTS_CLASS": "java.util.Objects",
    "OBJECTS_EQUALS_METHOD": "equals",
    "VERIFIER_SERVICE_CLASS": "c.\u02c9\u02c9.\u0674\u02bb",
    "VERIFIER_SERVICE_FACTORY": "\u2071\u02cf",
    "LICENSE_FIELD": "LIC",
    "LICENSE_GETTER_METHOD": "\ufe73\u02cf",
    "RELEASE_LICENSE_METHOD": "\u02bd\u1d54",
    "CLEANUP_CLASS": "c.\ufe73\ufe76.\u02bd\u1d54",
    "CLEANUP_FACTORY_METHOD": "\u1427\u0674",
    "SET_INTERNAL_VERSION_METHOD": "\u02d1\u1d4e",
    "WXID_PREFIX": "wxid_",
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
    "FP": "themes",
    "FP_ASYNC": "base,vidurlparser,donation",
    "LICENSE_FEATURE_SET": "[0,1,4]",
    "LICENSE_TAG": "LIC",
    "VERIFIER6_TAG": "verifier6",

    # StartupCheck / ModuleApk
    "PREFS_PATH": "shared_prefs/com.tencent.mm_preferences.xml",
    "ACCOUNT_KEY": "login_weixin_username",
    "MODULE_PACKAGE": "github.shadowbaby.wechatxposed.hook",

    # FeaturePackRestorer
    "FEATURE_DIR": "wx6_2.44",
    "FEATURE_PAYLOAD": "wx6_2.44.zip",
    "SELF_SIGN_PUBLIC_KEY": (
        "-----BEGIN PUBLIC KEY-----\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlqFTDs271XTnRh5sHUwU\n"
        "OH5kfFdc1ndpMcN4JS2esQn8z5OqQ+h13Y/bvrgXG7IFB+3kSO3uBdAQj9vkjuDj\n"
        "oyMcvcXpmZqFV3LPB8bKjAWAcQ5giahOxzt74rBBYXhpf9UD4TeezosiDqlD4p0J\n"
        "nb0IIQbhCg+6diSn8QA+6YfkkhjuPq90O2U7I4a/zZhQrhn5Y2audGwOp4D2idfR\n"
        "a6mxI0wwyQdlVzUKjnXvtxoe+CrtUlJFyntHscJxSfymJoHecMqPt6Dgjo+aJKVS\n"
        "LJ2lxKl0LS0aRTXa4ANUzf4719KeWdmH0zGm7j3oV7PE76LONmIBUzUMLQn1EJBV\n"
        "swIDAQAB\n"
        "-----END PUBLIC KEY-----\n"),

    # HostVersionSpoof / DexPaths
    "CLIENT_VERSION_CLASS": "c64.xe",
    "CLIENT_VERSION_FIELD": "g",
    "LAUNCH_SCENE_CLASS": "wx0.d",
    "LAUNCH_SCENE_CALLBACK": "f",
    "ILINK_START_CONFIG_CLASS": "com.tencent.ilink.network.Proto$IlinkStartConfig$Builder",
    "ILINK_SET_APP_VERSION_METHOD": "setAppVersion",
    "UPGRADE_URL_1": "https://support.weixin.qq.com/update",
    "DEX_SUFFIX": ".dex",
    "DEX_PREFIX": "classes",
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
