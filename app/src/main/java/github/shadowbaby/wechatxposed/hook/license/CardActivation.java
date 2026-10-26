package github.shadowbaby.wechatxposed.hook.license;

import github.shadowbaby.wechatxposed.hook.framework.HookCallback;
import github.shadowbaby.wechatxposed.hook.framework.HookFramework;
import github.shadowbaby.wechatxposed.hook.framework.HookParam;
import github.shadowbaby.wechatxposed.hook.loader.util.Contexts;
import github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;

/**
 * 用功能包「关于 → 自助获取高级功能 → 输入卡密」的窗口做本模块授权。
 *
 * 用户在功能包的卡密窗口输入授权码，点「确定」时拦截，交给 native 校验；
 * 通过后写数据库授权级别（WXH_LEVEL），功能包自己的卡密校验照常跑。
 */
public final class CardActivation {

    private static volatile boolean installed;
    private static volatile boolean toastHooked;

    private CardActivation() {
    }

    public static synchronized void install(HookFramework framework, ClassLoader classLoader) {
        if (installed) {
            return;
        }
        installed = true;
        try {
            Class<?> view = framework.findClassIfExists("android.view.View", null);
            if (view == null) {
                ModuleLogger.log("card activation: View missing");
                return;
            }
            framework.hookMethod(view, "performClick", new Class<?>[]{}, new HookCallback() {
                @Override
                public void before(HookParam param) {
                    Object self = param.thisObject();
                    if (!(self instanceof android.widget.TextView textView)) {
                        return;
                    }
                    CharSequence label = textView.getText();
                    if (label == null || !"确定".equals(label.toString().trim())) {
                        return;
                    }
                    String code = findCode(self);
                    if (code == null || code.isEmpty()) {
                        return;
                    }
                    int granted = Activation.verifyCode(code);
                    boolean ok = granted > Activation.LEVEL_NONE;
                    ModuleLogger.log("card activation: " + (ok ? "success" : "failed")
                            + " level=" + granted
                            + " len=" + code.length()
                            + " wxid=" + Activation.wxid());
                    android.content.Context context = textView.getContext();
                    if (ok) {
                        // 卡片只认卡密：payload 的 features 位决定普通还是高级。
                        // 按真实级别写库，别把基础码写成高级。
                        boolean extended = granted >= Activation.LEVEL_EXT;
                        toast(context, extended
                                ? "高级功能已激活，即将重启微信"
                                : "基础功能已激活，即将重启微信");
                        try {
                            int wanted = extended
                                    ? github.shadowbaby.wechatxposed.hook.support.pack
                                            .FeaturePackUnlock.LEVEL_PRO
                                    : github.shadowbaby.wechatxposed.hook.support.pack
                                            .FeaturePackUnlock.LEVEL_BASE;
                            // 只升不降：已付费用户误输低级卡不该丢掉扩展。
                            int target = Math.max(Activation.level(), wanted);
                            github.shadowbaby.wechatxposed.hook.support.pack.FeaturePackUnlock
                                    .grant(Activation.dataDir(), target,
                                            extended ? code : null);
                        } catch (Throwable error) {
                            ModuleLogger.log(error);
                        }
                        android.app.Activity activity = Contexts.activityOf(context);
                        if (activity != null) {
                            new android.os.Handler(android.os.Looper.getMainLooper())
                                    .postDelayed(() ->
                                            WeChatRestart.restart(activity), 1200);
                        }
                    } else {
                        toast(context, "授权码无效");
                    }
                }
            });
            hookShellToast(framework);
            ModuleLogger.log("card activation: installed");
        } catch (Throwable error) {
            ModuleLogger.log(error);
        }
    }

    private static void toast(android.content.Context context, String text) {
        if (context == null) {
            return;
        }
        try {
            final android.content.Context app = context.getApplicationContext();
            new android.os.Handler(android.os.Looper.getMainLooper()).post(() -> {
                try {
                    android.widget.Toast.makeText(app, text,
                            android.widget.Toast.LENGTH_LONG).show();
                } catch (Throwable ignored) {
                    // 忽略
                }
            });
        } catch (Throwable ignored) {
            // 忽略
        }
    }

    /** 屏蔽功能包自己的卡密提示（含「卡密」「复制不完整」的 Toast）。 */
    public static void hookShellToast(HookFramework framework) {
        if (toastHooked) {
            return;
        }
        toastHooked = true;
        try {
            Class<?> toast = framework.findClassIfExists("android.widget.Toast", null);
            if (toast == null) {
                return;
            }
            framework.hookMethod(toast, "show", new Class<?>[]{}, new HookCallback() {
                @Override
                public void before(HookParam param) {
                    Object self = param.thisObject();
                    if (self == null) {
                        return;
                    }
                    try {
                        java.lang.reflect.Field field = self.getClass()
                                .getDeclaredField("mText");
                        field.setAccessible(true);
                        Object text = field.get(self);
                        if (text instanceof CharSequence) {
                            String value = text.toString();
                            // 卡密提示 + 壳联网更新失败的提示（服务器已下线）。
                            if (value.contains("卡密")
                                    || value.contains("复制不完整")
                                    || value.contains("无法写入")
                                    || value.contains("更新失败")) {
                                ModuleLogger.log("shell toast blocked: " + value);
                                param.setResult(null);
                            }
                        }
                    } catch (Throwable ignored) {
                        // 字段不可读
                    }
                }
            });
            ModuleLogger.log("card activation: shell toast hooked");
        } catch (Throwable error) {
            ModuleLogger.log(error);
        }
    }

    /** 从当前窗口里找有内容的 EditText。 */
    private static String findCode(Object view) {
        try {
            android.view.View root = ((android.view.View) view).getRootView();
            java.util.ArrayDeque<android.view.View> queue = new java.util.ArrayDeque<>();
            queue.add(root);
            int guard = 0;
            while (!queue.isEmpty() && guard++ < 800) {
                android.view.View current = queue.poll();
                if (current instanceof android.widget.EditText edit) {
                    CharSequence text = edit.getText();
                    if (text != null && text.length() > 0) {
                        return text.toString().trim();
                    }
                }
                if (current instanceof android.view.ViewGroup group) {
                    for (int index = 0; index < group.getChildCount(); index++) {
                        queue.add(group.getChildAt(index));
                    }
                }
            }
        } catch (Throwable ignored) {
            // 忽略
        }
        return null;
    }
}
