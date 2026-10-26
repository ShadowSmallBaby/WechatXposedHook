package github.shadowbaby.wechatxposed.hook.license;

import android.app.AlertDialog;
import android.content.Context;
import android.graphics.drawable.GradientDrawable;
import android.os.Handler;
import android.os.Looper;
import android.text.InputType;
import android.text.SpannableString;
import android.text.Spanned;
import android.text.style.AlignmentSpan;
import android.text.style.ForegroundColorSpan;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;
import github.shadowbaby.wechatxposed.hook.framework.HookCallback;
import github.shadowbaby.wechatxposed.hook.framework.HookFramework;
import github.shadowbaby.wechatxposed.hook.framework.HookParam;
import github.shadowbaby.wechatxposed.hook.loader.SecretConstants;
import github.shadowbaby.wechatxposed.hook.loader.util.Contexts;
import github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import github.shadowbaby.wechatxposed.hook.loader.util.Secret;
import java.util.WeakHashMap;

/**
 * 功能包免责声明弹窗的外观与交互控制。
 *
 * 弹窗由 core dex 里的 {@code c.ˏᵎ.C0232} 构建，内容区是 RelativeLayout，
 * 往里插 View 会层叠，所以这里只改文案；倒计时结束后自动弹二次输入框，
 * 承诺输入正确才放行「同意」，放行时写入普通授权。
 */
public final class DisclaimerSkin implements HookCallback {

    private static final String MARK = "免责声明";

    private static final String ORIGINAL_BODY = "此模块是免费软件";

    private static final String ORIGINAL_TIP = "接受并关闭声明";

    private static final String TITLE = "WXH用户协议";

    /** 倒计时结束后需要手动输入的承诺。 */
    private static final String PROMISE = "我已知晓并同意";

    /** 已经通过承诺校验的按钮，再次点击直接放行。 */
    private static final WeakHashMap<View, Boolean> APPROVED = new WeakHashMap<>();

    private static volatile boolean promptOpen;

    /** 倒计时是否已经走完；未走完前不允许弹出签署窗口。 */
    private static volatile boolean countdownDone;

    /** 当前正在展示的协议弹窗；只有「同意」或「退出」能关闭它。 */
    private static volatile AlertDialog activeDialog;

    private static volatile boolean allowDismiss;

    private static volatile HookFramework frameworkRef;

    private static volatile boolean moreHooked;

    /** 限定尝试次数：类没加载时每次失败重试都会触发类加载，次数多了会 OOM。 */
    private static volatile int moreAttempts;

    private static final int MORE_MAX_ATTEMPTS = 3;

    private static volatile boolean installed;

    /** 更多页类由 core dex 加载，类名复用 UI 入口常量。 */
    private static final String MORE_CLASS = Secret.of(SecretConstants.X30_UI_CLASS);

    private static final String MORE_METHOD = Secret.of(SecretConstants.X30_MORE_METHOD);

    private DisclaimerSkin() {
    }

    public static synchronized void install(HookFramework framework,
            ClassLoader classLoader) {
        if (installed) {
            return;
        }
        try {
            // show() 声明在 Dialog 上，AlertDialog 只继承不重写。
            Class<?> dialog = framework.findClassIfExists("android.app.Dialog", null);
            if (dialog == null) {
                ModuleLogger.log("disclaimer: Dialog missing");
                return;
            }
            framework.hookMethod(dialog, "show", new Class<?>[]{}, new DisclaimerSkin());
            // 协议只能靠「同意/退出」关闭；否则壳点一下就把窗口关掉，用户没有可操作入口。
            framework.hookMethod(dialog, "dismiss", new Class<?>[]{}, new HookCallback() {
                @Override
                public void before(HookParam param) {
                    if (param.thisObject() == activeDialog && !allowDismiss) {
                        param.setResult(null);
                    }
                }
            });
            // 点「接受声明」那片区域时壳会走 mo876 -> C0150.m860 打开更多页，
            // 协议没签成之前把这一跳拦掉。core dex 加载较晚，这里先记下 framework，
            // 等弹窗真的出现（此时 core 已就绪）再挂。
            frameworkRef = framework;
            installed = true;
            ModuleLogger.log("disclaimer: hooked");
        } catch (Throwable error) {
            ModuleLogger.log(error);
        }
    }

    @Override
    public void after(HookParam param) {
        Object self = param.thisObject();
        if (!(self instanceof AlertDialog dialog)) {
            return;
        }
        try {
            android.view.Window window = dialog.getWindow();
            if (window == null) {
                return;
            }
            View decor = window.getDecorView();
            TextView title = find(decor, MARK);
            TextView body = find(decor, ORIGINAL_BODY);
            if (title == null || body == null) {
                return;
            }
            Context context = dialog.getContext();
            title.setText(TITLE);
            body.setText(styleCopyRow(buildBody()));
            // 壳给内容区挂了关闭监听；这里在触摸层直接消费，避免点击被它吃掉。
            body.setOnTouchListener((view, event) -> {
                if (event.getAction() == android.view.MotionEvent.ACTION_UP) {
                    IdentityClipboard.copy(context);
                }
                return true;
            });

            TextView tip = find(decor, ORIGINAL_TIP);
            if (tip != null) {
                tip.setText("接受声明并点击签署承诺");
            }
            countdownDone = false;
            Button positive = dialog.getButton(AlertDialog.BUTTON_POSITIVE);
            if (positive != null) {
                bindSignClicks(decor, context, positive);
            }
            Button negative = dialog.getButton(AlertDialog.BUTTON_NEGATIVE);
            if (positive != null) {
                positive.setText("同意");
                // 接管点击：承诺没通过就不关闭，壳自己的 listener 不再执行。
                positive.setOnClickListener(view ->
                        handlePositive(dialog, context, view));
                // 倒计时归零后自动弹输入框，不用先去点「同意」。
                autoPromptAfterCountdown(dialog, decor, context, positive);
            }
            if (negative != null) {
                negative.setText("退出");
                negative.setOnClickListener(view -> {
                    allowDismiss = true;
                    dialog.dismiss();
                });
            }
            ModuleLogger.log("disclaimer: skinned");
            activeDialog = dialog;
            allowDismiss = false;
        } catch (Throwable error) {
            ModuleLogger.log(error);
        }
    }

    private static final String COPY_ROW = "点击复制 机器码/WXID";

    /** 第二块开头，同时用于分段对齐。 */
    private static final String DECLARATION = "此软件是捐赠软件";

    private static final java.util.regex.Pattern COUNTDOWN =
            java.util.regex.Pattern.compile("\\d{1,2}");

    private static CharSequence buildBody() {
        String group = Activation.group();
        return "欢迎使用WXH模块, 交流群: "
                + (group == null || group.isEmpty() ? "未配置" : group) + "\n\n"
                + DECLARATION + "，可以免费使用。\n"
                + "任何形式或渠道包括预装手机售卖此软件\n"
                + "都是非法贩卖，别上当受骗！\n"
                + "使用本模块存在账号风险，请谨慎使用、后果自负。\n\n"
                + "如果不能接受请马上卸载停止使用！\n\n"
                + COPY_ROW;
    }

    /** 第一块左对齐、第二块居中、复制行标红可点。 */
    private static CharSequence styleCopyRow(CharSequence source) {
        String text = source.toString();
        int copyStart = text.indexOf(COPY_ROW);
        if (copyStart < 0) {
            return source;
        }
        SpannableString span = new SpannableString(text);
        int copyEnd = text.length();
        int centerStart = text.indexOf(DECLARATION);
        if (centerStart >= 0 && copyStart > centerStart) {
            // 三段都居中，和第二块保持一致的版式。
            span.setSpan(new AlignmentSpan.Standard(
                            android.text.Layout.Alignment.ALIGN_CENTER),
                    0, centerStart, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
            span.setSpan(new AlignmentSpan.Standard(
                            android.text.Layout.Alignment.ALIGN_CENTER),
                    centerStart, copyStart, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        }
        span.setSpan(new ForegroundColorSpan(0xFFFF5555), copyStart, copyEnd,
                Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        return span;
    }

    /** 倒计时归零后自动弹一次承诺输入框。 */
    private static void autoPromptAfterCountdown(AlertDialog dialog, View decor,
            Context context, Button positive) {
        Handler handler = new Handler(Looper.getMainLooper());
        Runnable task = new Runnable() {
            private int ticks;

            @Override
            public void run() {
                if (!dialog.isShowing() || ticks++ > 120) {
                    return;
                }
                // 壳在倒计时刷新时会重设这一行的点击，每轮都补挂一次。
                bindSignClicks(decor, context, positive);
                TextView countdown = findNumber(decor);
                if (countdown == null || "0".equals(countdown.getText().toString().trim())) {
                    countdownDone = true;
                    if (countdown != null) {
                        // 归零后固定显示 0，文案保持不变。
                        countdown.setText("0");
                    }
                    if (!APPROVED.containsKey(positive)) {
                        showPromisePrompt(context, positive);
                    }
                    return;
                }
                handler.postDelayed(this, 500);
            }
        };
        handler.postDelayed(task, 500);
    }

    /** core dex 里的更多页类由独立 ClassLoader 加载，需要调用方传入那个 loader。 */
    public static synchronized void hookMorePage(HookFramework framework,
            ClassLoader classLoader) {
        if (moreHooked || moreAttempts >= MORE_MAX_ATTEMPTS) {
            return;
        }
        moreAttempts++;
        try {
            Class<?> more = framework.findClassIfExists(MORE_CLASS, classLoader);
            if (more == null) {
                ModuleLogger.debug("disclaimer: more class not found: "
                        + (classLoader == null ? "null" : classLoader.getClass().getName()));
                return;
            }
            moreHooked = true;
            framework.hookMethod(more, MORE_METHOD,
                    new Class<?>[]{android.app.Activity.class}, new HookCallback() {
                        @Override
                        public void before(HookParam param) {
                            if (activeDialog != null && !allowDismiss) {
                                param.setResult(null);
                                ModuleLogger.log("disclaimer: more page blocked");
                            }
                        }
                    });
            ModuleLogger.log("disclaimer: more page hook installed");
        } catch (Throwable error) {
            ModuleLogger.log(error);
        }
    }

    /** 「接受声明并点击签署承诺」与倒计时数字共用同一个点击逻辑。 */
    private static void bindSignClicks(View decor, Context context, Button positive) {
        View.OnClickListener listener = view -> {
            if (!countdownDone) {
                Toast.makeText(context, "倒计时结束后才能签署承诺",
                        Toast.LENGTH_SHORT).show();
                return;
            }
            showPromisePrompt(context, positive);
        };
        TextView hint = find(decor, "接受声明并点击签署承诺");
        if (hint != null) {
            hint.setOnClickListener(listener);
            hint.setOnLongClickListener(view -> true);
            // 这一整行（含倒计时数字）的父容器也挂着壳的关闭逻辑，一并接管。
            if (hint.getParent() instanceof View parent) {
                parent.setClickable(true);
                parent.setOnClickListener(listener);
                parent.setOnLongClickListener(view -> true);
            }
        }
        TextView countdown = findNumber(decor);
        if (countdown != null) {
            countdown.setOnClickListener(listener);
            countdown.setOnLongClickListener(view -> true);
        }
    }

    private static void showPromisePrompt(Context context, View positive) {
        if (promptOpen || APPROVED.containsKey(positive) || !countdownDone) {
            return;
        }
        promptOpen = true;
        EditText input = new EditText(context);
        input.setHint(PROMISE);
        input.setSingleLine(true);
        input.setGravity(Gravity.CENTER);
        input.setTextSize(14);
        input.setInputType(InputType.TYPE_CLASS_TEXT
                | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        GradientDrawable background = new GradientDrawable();
        background.setColor(0x22888888);
        background.setCornerRadius(12);
        input.setBackground(background);
        int pad = (int) (16 * context.getResources().getDisplayMetrics().density);
        input.setPadding(pad, pad / 2, pad, pad / 2);

        AlertDialog prompt = new AlertDialog.Builder(context)
                .setTitle("签署承诺")
                .setMessage("我承诺: " + PROMISE)
                .setView(input)
                .setPositiveButton("签署", null)
                .setNegativeButton("取消", null)
                .create();
        // 点外部不关闭，避免误触后退回协议页。
        prompt.setCanceledOnTouchOutside(false);
        boolean night = (context.getResources().getConfiguration().uiMode
                & android.content.res.Configuration.UI_MODE_NIGHT_MASK)
                == android.content.res.Configuration.UI_MODE_NIGHT_YES;
        int buttonColor = night ? 0xFFFFFFFF : 0xFF111111;
        // 用 OnShowListener 接管按钮：校验不过时对话框不关闭，可以继续改。
        prompt.setOnShowListener(shown -> {
            Button cancel = prompt.getButton(AlertDialog.BUTTON_NEGATIVE);
            if (cancel != null) {
                cancel.setTextColor(buttonColor);
            }
            Button confirm = prompt.getButton(AlertDialog.BUTTON_POSITIVE);
            if (confirm == null) {
                return;
            }
            confirm.setTextColor(buttonColor);
            confirm.setOnClickListener(v -> {
                CharSequence text = input.getText();
                if (text == null || !PROMISE.equals(text.toString().trim())) {
                    Toast.makeText(context, "承诺内容不正确", Toast.LENGTH_SHORT).show();
                    return;
                }
                APPROVED.put(positive, Boolean.TRUE);
                Toast.makeText(context, "承诺正确，请点「同意」", Toast.LENGTH_SHORT).show();
                prompt.dismiss();
            });
        });
        prompt.setOnDismissListener(dialog -> promptOpen = false);
        prompt.show();
    }

    /** 「同意」：倒计时结束 + 承诺通过才写授权并关闭弹窗。 */
    private static void handlePositive(AlertDialog dialog, Context context, View view) {
        if (!countdownDone) {
            Toast.makeText(context, "倒计时结束后才能签署承诺",
                    Toast.LENGTH_SHORT).show();
            return;
        }
        if (!APPROVED.containsKey(view)) {
            showPromisePrompt(context, view);
            return;
        }
        grantBase(view);
        allowDismiss = true;
        dialog.dismiss();
    }

    /** 同意协议 -> 普通授权（基础功能），随后自动重启微信让功能表生效。 */
    private static void grantBase(View source) {
        java.io.File dataDir = Activation.dataDir();
        if (dataDir == null) {
            return;
        }
        int granted =
                github.shadowbaby.wechatxposed.hook.support.pack.FeaturePackUnlock
                        .grant(dataDir,
                                github.shadowbaby.wechatxposed.hook.support.pack
                                        .FeaturePackUnlock.LEVEL_BASE);
        Context context = source.getContext();
        if (granted < github.shadowbaby.wechatxposed.hook.support.pack.FeaturePackUnlock
                .LEVEL_BASE) {
            // 账号还没解析出来时 guard 会早退，这里不能报成功：
            // 否则用户签完协议重启，功能表仍是空的。
            ModuleLogger.log("disclaimer: base grant deferred, account not ready");
            Toast.makeText(context, "账号还没准备好，请稍后再点一次",
                    Toast.LENGTH_LONG).show();
            return;
        }
        ModuleLogger.log("disclaimer: base granted");
        Toast.makeText(context, "基础功能已激活，即将重启微信",
                Toast.LENGTH_SHORT).show();
        android.app.Activity activity = Contexts.activityOf(context);
        if (activity != null) {
            new Handler(Looper.getMainLooper())
                    .postDelayed(() -> WeChatRestart.restart(activity), 1200);
        }
    }

    /** 找倒计时数字（1~2 位纯数字的 TextView）。 */
    private static TextView findNumber(View view) {
        if (view instanceof TextView label) {
            CharSequence text = label.getText();
            if (text != null && COUNTDOWN.matcher(text).matches()) {
                return label;
            }
        }
        if (view instanceof ViewGroup group) {
            for (int index = 0; index < group.getChildCount(); index++) {
                TextView hit = findNumber(group.getChildAt(index));
                if (hit != null) {
                    return hit;
                }
            }
        }
        return null;
    }

    /** 遍历 View 树找第一个包含指定文案的 TextView。 */
    private static TextView find(View view, String needle) {
        if (view instanceof TextView label) {
            CharSequence text = label.getText();
            if (text != null && text.toString().contains(needle)) {
                return label;
            }
        }
        if (view instanceof ViewGroup group) {
            for (int index = 0; index < group.getChildCount(); index++) {
                TextView hit = find(group.getChildAt(index), needle);
                if (hit != null) {
                    return hit;
                }
            }
        }
        return null;
    }
}
