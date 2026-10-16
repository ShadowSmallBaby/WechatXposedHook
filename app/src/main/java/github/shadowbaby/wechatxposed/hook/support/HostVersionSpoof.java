package github.shadowbaby.wechatxposed.hook.support;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import github.shadowbaby.wechatxposed.hook.loader.ModuleLogger;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.List;
import org.json.JSONObject;

/**
 * 小程序宿主版本伪装。
 *
 * 有些小程序会检查微信宿主版本(基础库版本),版本低就要求升级、不给用。这里做两件事:
 *   1. 把启动小程序的 CGI 请求里的 libVersion 报成一个很大的值;
 *   2. 把官方升级页的跳转 URL 清空(空 URL 会走宿主自己的失败回调,不影响小程序 JS 回调)。
 *
 * 微信的类名是混淆的、且随版本变化,所以不写死类名,改成按 dex 常量池里的字符串反查:
 *   - 构造器所在类:方法里同时引用 "MicroMsg.AppBrand.CgiLaunchWxaApp|func:1122" 与
 *     "&lt;init&gt; cgiHash[%d], ... libVersion[%d], ..."(实测 wx0.d,在 base.apk 的 classes5.dex);
 *   - private_openUrl 方法:方法里同时引用 "private_openUrl"、"geta8key_open_webview_appid"、
 *     "open_custom_style_url"(实测 com.tencent.mm.plugin.appbrand.jsapi.oa.u,在 classes.dex)。
 *     这一版微信里该方法引用的是 "url" 而不是 "rawUrl",而 "url" 太泛(全 dex 有 65 个类命中),
 *     所以第三个锚点用只属于这个方法的 "open_custom_style_url"。
 *
 * 目标进程是微信主进程与 :appbrand0 / :appbrand1(小程序跑在后者)。
 */
public final class HostVersionSpoof {

    /** 伪造出来的宿主版本号(越大越"新")。 */
    private static final int FAKE_LIB_VERSION = 9999;

    /** 构造器所在类的锚点。 */
    private static final String[] LAUNCH_ANCHORS = {
            "MicroMsg.AppBrand.CgiLaunchWxaApp|func:1122",
            "<init> cgiHash[%d], username[%s] appId[%s] sync[%b] sessionId[%s] instanceId[%s] "
                    + "libVersion[%d], source:%s, launchMode:%d, migrate:%b, fallback:%b"};

    /** private_openUrl 所在类的锚点。 */
    private static final String[] OPEN_URL_ANCHORS = {
            "private_openUrl", "geta8key_open_webview_appid", "open_custom_style_url"};

    /** 官方升级页;命中就清空 URL。 */
    private static final String[] UPGRADE_URLS = {
            "https://support.weixin.qq.com/update",
            "https://szsupport.weixin.qq.com/update"};

    /** libVersion 在构造器参数里的下标(0 起)。 */
    private static final int LIB_VERSION_INDEX = 6;

    /** 一个进程只挂一次。 */
    private static boolean installed;

    private static final String LOG = "host spoof: ";
    private static final String LOG_NO_DEX = LOG + "no dex, skipped";

    private HostVersionSpoof() {
    }

    /**
     * 在微信进程里挂上伪装。
     *
     * @param classLoader 微信的类加载器
     * @param sourceDir   微信 base.apk 路径(从 ApplicationInfo.sourceDir 拿),dex 从这里读
     */
    public static synchronized void install(ClassLoader classLoader, String sourceDir) {
        if (installed) {
            return;
        }
        installed = true;
        try {
            List<byte[]> dexBytes = DexPaths.of(sourceDir);
            if (dexBytes.isEmpty()) {
                ModuleLogger.log(LOG_NO_DEX);
                return;
            }
            int constructors = 0;
            int methods = 0;
            for (byte[] bytes : dexBytes) {
                DexStrings dex = DexStrings.open(bytes);
                if (dex == null) {
                    continue;
                }
                constructors += hookLaunchConstructors(
                        classLoader, dex.classesContaining(LAUNCH_ANCHORS));
                methods += hookOpenUrl(classLoader, dex.classesContaining(OPEN_URL_ANCHORS));
            }
            ModuleLogger.log(LOG + constructors + " ctor, " + methods + " openUrl hooked");
        } catch (Throwable error) {
            ModuleLogger.log(error);
        }
    }

    /** 挂 CgiLaunchWxaApp 的构造器,把 libVersion 参数改大。 */
    private static int hookLaunchConstructors(ClassLoader classLoader, List<String> classes) {
        int count = 0;
        for (String name : classes) {
            Class<?> target = XposedHelpers.findClassIfExists(name, classLoader);
            if (target == null) {
                continue;
            }
            for (Constructor<?> constructor : target.getDeclaredConstructors()) {
                Class<?>[] parameters = constructor.getParameterTypes();
                if (parameters.length <= LIB_VERSION_INDEX
                        || parameters[LIB_VERSION_INDEX] != Integer.TYPE) {
                    continue;
                }
                XposedBridge.hookMethod(constructor, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        param.args[LIB_VERSION_INDEX] = FAKE_LIB_VERSION;
                    }
                });
                count++;
            }
        }
        return count;
    }

    /** 挂 private_openUrl,把官方升级页的 URL 清空。 */
    private static int hookOpenUrl(ClassLoader classLoader, List<String> classes) {
        int count = 0;
        for (String name : classes) {
            Class<?> target = XposedHelpers.findClassIfExists(name, classLoader);
            if (target == null) {
                continue;
            }
            for (Method method : target.getDeclaredMethods()) {
                if (!isOpenUrlSignature(method)) {
                    continue;
                }
                XposedBridge.hookMethod(method, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        clearUpgradeUrl(param);
                    }
                });
                count++;
            }
        }
        return count;
    }

    /** (任意, JSONObject, int) -> void,第二个参数是 JSONObject。 */
    private static boolean isOpenUrlSignature(Method method) {
        Class<?>[] parameters = method.getParameterTypes();
        return parameters.length == 3
                && "org.json.JSONObject".equals(parameters[1].getName())
                && parameters[2] == Integer.TYPE
                && method.getReturnType() == Void.TYPE;
    }

    /** 第二个参数是 JSONObject,里面的 url 指向官方升级页就清空。 */
    private static void clearUpgradeUrl(XC_MethodHook.MethodHookParam param) {
        Object data = param.args[1];
        if (!(data instanceof JSONObject)) {
            return;
        }
        JSONObject json = (JSONObject) data;
        String url = json.optString("url");
        if (url == null || url.isEmpty()) {
            return;
        }
        for (String upgrade : UPGRADE_URLS) {
            if (url.equals(upgrade) || url.startsWith(upgrade + "/")
                    || url.startsWith(upgrade + "?") || url.startsWith(upgrade + "#")) {
                try {
                    json.put("url", "");
                } catch (Throwable ignored) {
                    // put 只在 key 为 null 时抛,这里 key 是常量,不会走到
                }
                return;
            }
        }
    }
}
