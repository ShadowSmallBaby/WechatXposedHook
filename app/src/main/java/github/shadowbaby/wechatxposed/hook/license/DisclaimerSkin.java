package github.shadowbaby.wechatxposed.hook.license;

import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.graphics.drawable.GradientDrawable;
import android.os.Handler;
import android.os.Looper;
import android.text.InputType;
import android.text.SpannableString;
import android.text.Spanned;
import android.text.TextPaint;
import android.text.method.LinkMovementMethod;
import android.text.style.AlignmentSpan;
import android.text.style.ClickableSpan;
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
import github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
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

    private static volatile boolean installed;

    private DisclaimerSkin() {
    }

    public static synchronized void install(HookFramework framework) {
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
            // 协议只能由「同意」关闭，点外部/返回键都不允许。
            dialog.setCancelable(false);
            dialog.setCanceledOnTouchOutside(false);
            title.setText(TITLE);
            body.setText(styleCopyRow(context, buildBody()));
            body.setMovementMethod(LinkMovementMethod.getInstance());
            body.setHighlightColor(0x00000000);

            TextView tip = find(decor, ORIGINAL_TIP);
            if (tip != null) {
                tip.setText("接受声明并点击签署承诺");
            }
            countdownDone = false;
            Button positive = dialog.getButton(AlertDialog.BUTTON_POSITIVE);
            if (tip != null && positive != null) {
                tip.setOnClickListener(view -> {
                    if (!countdownDone) {
                        Toast.makeText(context, "倒计时结束后才能签署承诺",
                                Toast.LENGTH_SHORT).show();
                        return;
                    }
                    showPromisePrompt(context, positive);
                });
            }
            Button negative = dialog.getButton(AlertDialog.BUTTON_NEGATIVE);
            TextView countdown = findNumber(decor);
            if (countdown != null) {
                // 壳给倒计时数字挂了点击（点了会关协议），这里直接摘掉。
                countdown.setClickable(false);
                countdown.setOnClickListener(null);
            }
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
                negative.setOnClickListener(view -> dialog.dismiss());
            }
            ModuleLogger.log("disclaimer: skinned");
        } catch (Throwable error) {
            ModuleLogger.log(error);
        }
    }

    private static final String COPY_ROW = "点击复制 机器码/WXID";

    private static CharSequence buildBody() {
        String group = Activation.group();
        return "欢迎使用WXH模块, 交流群: "
                + (group == null || group.isEmpty() ? "未配置" : group) + "\n\n"
                + "此软件是捐赠软件，可以免费使用。\n"
                + "任何形式或渠道包括预装手机售卖此软件\n"
                + "都是非法贩卖，别上当受骗！\n"
                + "使用本模块存在账号风险，请谨慎使用、后果自负。\n\n"
                + "如果不能接受请马上卸载停止使用！\n\n"
                + COPY_ROW;
    }

    /** 第一块左对齐、第二块居中、复制行标红可点。 */
    private static CharSequence styleCopyRow(Context context, CharSequence source) {
        String text = source.toString();
        int copyStart = text.indexOf(COPY_ROW);
        if (copyStart < 0) {
            return source;
        }
        SpannableString span = new SpannableString(text);
        int copyEnd = text.length();
        int centerStart = text.indexOf("此软件是捐赠软件");
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
        span.setSpan(new ClickableSpan() {
            @Override
            public void onClick(View widget) {
                copy(context);
            }

            @Override
            public void updateDrawState(TextPaint ds) {
                ds.setColor(0xFFFF5555);
                ds.setUnderlineText(false);
            }
        }, copyStart, copyEnd, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
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
                TextView countdown = findNumber(decor);
                if (countdown == null || "0".equals(countdown.getText().toString().trim())) {
                    countdownDone = true;
                    if (countdown != null) {
                        // 归零后固定显示 0，并去掉壳在这个区域上的点击（点了会关协议）。
                        countdown.setText("0");
                        countdown.setClickable(false);
                        countdown.setOnClickListener(null);
                    }
                    TextView hint = find(decor, "接受声明并点击签署承诺");
                    if (hint == null) {
                        hint = find(decor, "你可以点击签署承诺了");
                    }
                    if (hint != null) {
                        hint.setText("你可以点击签署承诺了");
                        hint.setClickable(true);
                        hint.setOnClickListener(v -> showPromisePrompt(context, positive));
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
        dialog.dismiss();
    }

    /** 同意协议 -> 普通授权（基础功能），随后自动重启微信让功能表生效。 */
    private static void grantBase(View source) {
        java.io.File dataDir = Activation.dataDir();
        if (dataDir == null) {
            return;
        }
        github.shadowbaby.wechatxposed.hook.support.pack.FeaturePackUnlock
                .grant(dataDir,
                        github.shadowbaby.wechatxposed.hook.support.pack.FeaturePackUnlock
                                .LEVEL_BASE);
        ModuleLogger.log("disclaimer: base granted");
        Context context = source.getContext();
        Toast.makeText(context, "基础功能已激活，即将重启微信",
                Toast.LENGTH_SHORT).show();
        android.app.Activity activity = activityOf(context);
        if (activity != null) {
            new Handler(Looper.getMainLooper())
                    .postDelayed(() -> ActivationDialog.restartWechat(activity), 1200);
        }
    }

    /** 从 Context 向上找 Activity。 */
    private static android.app.Activity activityOf(Context context) {
        Context current = context;
        while (current instanceof android.content.ContextWrapper wrapper) {
            if (current instanceof android.app.Activity activity) {
                return activity;
            }
            current = wrapper.getBaseContext();
        }
        return null;
    }

    private static void copy(Context context) {
        String machine = Activation.machineCode();
        String wxid = Activation.wxid();
        String value = "机器码: " + (machine == null ? "" : machine)
                + "\nWXID: " + (wxid == null ? "" : wxid);
        try {
            ClipboardManager manager =
                    (ClipboardManager) context.getSystemService(Context.CLIPBOARD_SERVICE);
            if (manager == null) {
                return;
            }
            manager.setPrimaryClip(ClipData.newPlainText("机器码", value));
            Toast.makeText(context, "已复制机器码与 WXID", Toast.LENGTH_SHORT).show();
        } catch (Throwable error) {
            ModuleLogger.log(error);
        }
    }

    /** 找倒计时数字（1~2 位纯数字的 TextView）。 */
    private static TextView findNumber(View view) {
        if (view instanceof TextView label) {
            CharSequence text = label.getText();
            if (text != null && text.toString().matches("\\d{1,2}")) {
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
