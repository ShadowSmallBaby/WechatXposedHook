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

    /** 已经被接管过「确定」的窗口按钮，避免重复设置监听。 */
    private static final java.util.WeakHashMap<android.view.View, Boolean> BOUND =
            new java.util.WeakHashMap<>();

    /** 同一次点击被两条路径命中时只处理一次。 */
    private static final long DEDUPE_MS = 1500L;
    private static volatile String lastCode;
    private static volatile long lastAt;

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
                    // performClick 是全局 hook：微信里带输入框的对话框（改备注、建群、
                    // 加标签…）都有「确定」+ EditText，不限定窗口会把普通操作当成卡密输入。
                    if (!isCardWindow((android.view.View) self)) {
                        return;
                    }
                    // 对话框接管已经替换过监听，这里再校验一次会重复重启微信。
                    if (BOUND.containsKey(self)) {
                        return;
                    }
                    String code = findCode((android.view.View) self);
                    if (code == null || code.isEmpty()) {
                        return;
                    }
                    confirm(textView, code);
                }
            });
            hookCardDialog(framework);
            hookShellToast(framework);
            ModuleLogger.log("card activation: installed");
        } catch (Throwable error) {
            ModuleLogger.log(error);
        }
    }

    /**
     * 卡密窗口出现时接管「确定」。
     *
     * 和协议弹窗同一套路：壳的输入窗口是 AlertDialog，挂在 {@code Dialog.show} 上
     * 就能在窗口本体现身时拿到它，不必靠全局点击去猜。接管后壳自己的卡密校验
     * （服务器早已下线，必然失败）不会再跑到我们的提示之后。
     */
    private static void hookCardDialog(HookFramework framework) {
        try {
            Class<?> dialog = framework.findClassIfExists("android.app.Dialog", null);
            if (dialog == null) {
                ModuleLogger.log("card activation: Dialog missing");
                return;
            }
            framework.hookMethod(dialog, "show", new Class<?>[]{}, new HookCallback() {
                @Override
                public void after(HookParam param) {
                    Object self = param.thisObject();
                    if (!(self instanceof android.app.Dialog instance)) {
                        return;
                    }
                    android.view.Window window = instance.getWindow();
                    android.view.View decor = window == null ? null : window.getDecorView();
                    if (decor == null || !isCardWindow(decor)) {
                        return;
                    }
                    android.widget.TextView confirmButton = findConfirm(decor);
                    if (confirmButton == null) {
                        return;
                    }
                    if (BOUND.put(confirmButton, Boolean.TRUE) != null) {
                        return;
                    }
                    // 直接替换监听：壳自己的校验/长度限制不再参与这次点击。
                    confirmButton.setOnClickListener(view -> {
                        if (!(view instanceof android.widget.TextView textView)) {
                            return;
                        }
                        String code = findCode(textView);
                        if (code == null || code.isEmpty()) {
                            toast(textView.getContext(), "请先输入授权码");
                            return;
                        }
                        confirm(textView, code);
                    });
                    ModuleLogger.log("card activation: dialog bound");
                }
            });
            ModuleLogger.log("card activation: dialog hooked");
        } catch (Throwable error) {
            ModuleLogger.log(error);
        }
    }

    /** 校验并落库；点击 hook 与对话框接管共用。 */
    private static void confirm(android.widget.TextView textView, String code) {
        // 两条路径可能都命中同一次点击（壳重设过监听时），必须去重，
        // 否则会验两次、重启两次。
        long now = android.os.SystemClock.elapsedRealtime();
        if (code.equals(lastCode) && now - lastAt < DEDUPE_MS) {
            return;
        }
        lastCode = code;
        lastAt = now;
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
            int wanted = extended
                    ? github.shadowbaby.wechatxposed.hook.support.pack
                            .FeaturePackUnlock.LEVEL_PRO
                    : github.shadowbaby.wechatxposed.hook.support.pack
                            .FeaturePackUnlock.LEVEL_BASE;
            int stored = Activation.LEVEL_NONE;
            try {
                // 只升不降：已付费用户误输低级卡不该丢掉扩展。
                int target = Math.max(Activation.level(), wanted);
                stored = github.shadowbaby.wechatxposed.hook.support.pack
                        .FeaturePackUnlock.grant(Activation.dataDir(), target,
                                extended ? code : null);
            } catch (Throwable error) {
                ModuleLogger.log(error);
            }
            if (stored < wanted) {
                // 账号还没解析出来时 guard 早退，库里什么都没写。
                // 这时候提示成功会让用户重启后看到空菜单。
                ModuleLogger.log("card activation: grant deferred, account not ready");
                toast(context, "账号还没准备好，请重启微信后再试");
                return;
            }
            toast(context, extended
                    ? "高级功能已激活，即将重启微信"
                    : "基础功能已激活，即将重启微信");
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
                            // 壳自己的卡密校验永远过不了，输错/输长都会弹一句；
                            // 兼容码时代还要连「授权/激活」这类文案一起压掉。
                            if (value.contains("卡密")
                                    || value.contains("授权码")
                                    || value.contains("激活码")
                                    || value.contains("复制不完整")
                                    || value.contains("无法写入")
                                    || value.contains("更新失败")
                                    || (value.startsWith("[X]") && (value.contains("授权")
                                            || value.contains("激活")
                                            || value.contains("验证失败")))) {
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

    /** 只有卡密窗口才做本模块校验：窗口内必须有「卡密/授权码/激活码」字样。 */
    private static boolean isCardWindow(android.view.View view) {
        try {
            android.view.View root = view.getRootView();
            java.util.ArrayDeque<android.view.View> queue = new java.util.ArrayDeque<>();
            queue.add(root);
            int guard = 0;
            while (!queue.isEmpty() && guard++ < 1000) {
                android.view.View current = queue.poll();
                if (current instanceof android.widget.TextView textView) {
                    // 壳的卡密窗口标题、「自助获取高级功能」入口和输入框 hint 都带这个词。
                    if (hasCardWord(textView.getText()) || hasCardWord(textView.getHint())) {
                        return true;
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
        return false;
    }

    private static boolean hasCardWord(CharSequence text) {
        if (text == null) {
            return false;
        }
        String value = text.toString();
        return value.contains("卡密")
                || value.contains("授权码")
                || value.contains("激活码");
    }

    /** 找窗口里的「确定」按钮。 */
    private static android.widget.TextView findConfirm(android.view.View view) {
        if (view instanceof android.widget.TextView textView) {
            CharSequence text = textView.getText();
            if (text != null && "确定".equals(text.toString().trim())
                    && textView.isClickable()) {
                return textView;
            }
        }
        if (view instanceof android.view.ViewGroup group) {
            for (int index = 0; index < group.getChildCount(); index++) {
                android.widget.TextView hit = findConfirm(group.getChildAt(index));
                if (hit != null) {
                    return hit;
                }
            }
        }
        return null;
    }

    /**
     * 从按钮向上找最近的、带 EditText 的容器，再取其中有内容的输入框。
     *
     * 不用 rootView：整个窗口里第一个非空 EditText 可能是别处的搜索框/聊天输入框，
     * 会把无关内容当成卡密。向上最多几层，避免一路走到 DecorView。
     */
    private static String findCode(android.view.View view) {
        try {
            android.view.View current = view;
            for (int depth = 0; current != null && depth < 8; depth++) {
                if (current instanceof android.view.ViewGroup group) {
                    String code = firstCode(group);
                    if (code != null) {
                        return code;
                    }
                }
                android.view.ViewParent parent = current.getParent();
                if (!(parent instanceof android.view.View parentView)) {
                    break;
                }
                current = parentView;
            }
        } catch (Throwable ignored) {
            // 忽略
        }
        return null;
    }

    /** 在给定容器内找有内容的 EditText。 */
    private static String firstCode(android.view.ViewGroup container) {
        java.util.ArrayDeque<android.view.View> queue = new java.util.ArrayDeque<>();
        queue.add(container);
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
        return null;
    }
}
