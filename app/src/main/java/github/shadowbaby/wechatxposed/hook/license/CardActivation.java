package github.shadowbaby.wechatxposed.hook.license;

import github.shadowbaby.wechatxposed.hook.framework.HookCallback;
import github.shadowbaby.wechatxposed.hook.framework.HookFramework;
import github.shadowbaby.wechatxposed.hook.framework.HookParam;
import github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;

/**
 * 用功能包「关于 → 自助获取高级功能 → 输入卡密」的窗口做本模块授权。
 *
 * 用户在功能包的卡密窗口输入本模块的授权码，点「确定」时拦截，
 * 走 {@link Activation#activate(String, String)} 验证；通过即写 activation.dat。
 * 功能包自己的卡密校验照常跑（会失败，不影响）。
 */
public final class CardActivation {

    private static volatile boolean installed;

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
                    boolean ok = Activation.activate(Activation.promise(), code);
                    ModuleLogger.log("card activation: " + (ok ? "success" : "failed")
                            + " len=" + code.length()
                            + " level=" + Activation.level()
                            + " ext=" + Activation.isExtensionAllowed()
                            + " wxid=" + Activation.wxid());
                    android.content.Context context = textView.getContext();
                    if (ok) {
                        toast(context, "高级功能已激活，即将重启微信");
                        try {
                            // 高级激活：写项目授权级别，功能表随之下发 sf/mf/af。
                            github.shadowbaby.wechatxposed.hook.support.pack.FeaturePackUnlock
                                    .grant(Activation.dataDir(),
                                            github.shadowbaby.wechatxposed.hook.support.pack
                                                    .FeaturePackUnlock.LEVEL_PRO, code);
                        } catch (Throwable error) {
                            ModuleLogger.log(error);
                        }
                        android.app.Activity activity = activityOf(context);
                        if (activity != null) {
                            new android.os.Handler(android.os.Looper.getMainLooper())
                                    .postDelayed(() ->
                                            ActivationDialog.restartWechat(activity), 1200);
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

    /** 从 Context 向上找 Activity，用于授权后重启微信。 */
    private static android.app.Activity activityOf(android.content.Context context) {
        android.content.Context current = context;
        while (current instanceof android.content.ContextWrapper wrapper) {
            if (current instanceof android.app.Activity activity) {
                return activity;
            }
            current = wrapper.getBaseContext();
        }
        return null;
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
                        if (text instanceof CharSequence
                                && (text.toString().contains("卡密")
                                    || text.toString().contains("复制不完整"))) {
                            ModuleLogger.log("card toast blocked: " + text);
                            param.setResult(null);
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
