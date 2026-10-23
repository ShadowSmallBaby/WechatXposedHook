package github.shadowbaby.wechatxposed.hook.license;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.os.Bundle;
import android.os.SystemClock;
import android.text.InputType;
import android.view.MotionEvent;
import android.view.ViewConfiguration;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;
import github.shadowbaby.wechatxposed.hook.BuildConfig;
import github.shadowbaby.wechatxposed.hook.framework.HookCallback;
import github.shadowbaby.wechatxposed.hook.framework.HookFramework;
import github.shadowbaby.wechatxposed.hook.framework.HookParam;
import github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;

/**
 * 首次安装授权弹窗。
 *
 * 公开码启用基础功能；机器码启用 sf/mf/af。用户必须手动输入承诺，
 * 承诺框禁用粘贴；授权文件存在后不再弹出。
 */
public final class ActivationDialog implements HookCallback {

    private static boolean installed;

    private static boolean shown;

    private ActivationDialog() {
    }

    public static synchronized void install(HookFramework framework,
            ClassLoader classLoader) {
        if (installed || !BuildConfig.FULL_EDITION || BuildConfig.DEBUG) {
            return;
        }
        boolean hooked = false;
        for (String name : new String[]{
                "com.tencent.mm.ui.MMActivity", "com.tencent.mm.ui.LauncherUI"}) {
            try {
                Class<?> target = framework.findClassIfExists(name, classLoader);
                if (target == null) {
                    continue;
                }
                framework.hookMethod(target, "onCreate",
                        new Class<?>[]{Bundle.class}, new ActivationDialog());
                hooked = true;
                ModuleLogger.debug("activation dialog hooked: " + name);
            } catch (Throwable error) {
                framework.log(error);
            }
        }
        installed = hooked;
        if (hooked) {
            try {
                Class<?> activityClass = framework.findClass("android.app.Activity", null);
                framework.hookMethod(activityClass, "dispatchTouchEvent",
                        new Class<?>[]{MotionEvent.class}, new ReopenTouch());
                ModuleLogger.log("activation dialog: double-tap reopen installed");
            } catch (Throwable error) {
                framework.log(error);
            }
        }
        if (!hooked) {
            ModuleLogger.debug("activation dialog: activity not found");
        } else {
            ModuleLogger.debug("activation dialog: installed");
        }
    }

    @Override
    public void after(HookParam param) {
        try {
            if (shown || Activation.hasAuthorization()) {
                return;
            }
            Object target = param.thisObject();
            if (!(target instanceof Activity activity) || activity.isFinishing()) {
                return;
            }
            tryShow(activity, 0);
        } catch (Throwable error) {
            // 授权弹窗异常不能影响微信。
            ModuleLogger.log("activation dialog: " + error);
        }
    }

    private static void tryShow(Activity activity, int attempt) {
        tryShow(activity, attempt, false);
    }

    private static void tryShow(Activity activity, int attempt, boolean force) {
        if (shown || (!force && Activation.hasAuthorization())
                || activity.isFinishing()) {
            return;
        }
        shown = true;
        try {
            show(activity);
        } catch (Throwable error) {
            ModuleLogger.log("activation dialog: " + error);
        }
    }

    private static void show(Activity activity) {
        String machine = Activation.machineCode();
        String wxid = Activation.wxid();
        int padding = (int) (18 * activity.getResources().getDisplayMetrics().density);
        int gap = (int) (10 * activity.getResources().getDisplayMetrics().density);
        boolean night = (activity.getResources().getConfiguration().uiMode
                & android.content.res.Configuration.UI_MODE_NIGHT_MASK)
                == android.content.res.Configuration.UI_MODE_NIGHT_YES;
        int textColor = night ? 0xFFFFFFFF : 0xFF111111;
        int hintColor = night ? 0x99FFFFFF : 0x99000000;

        LinearLayout content = new LinearLayout(activity);
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(padding, gap, padding, 0);

        TextView header = new TextView(activity);
        header.setText("WXH交流群：" + Activation.group()
                + "\n本模块免费使用，如付费购买请联系卖家退款。"
                + "\n关闭后可在首页双击顶部“微信”重新打开。");
        header.setTextSize(13);
        header.setTextColor(textColor);
        header.setLineSpacing(0, 1.15f);
        header.setPadding(0, 0, 0, gap);
        content.addView(header);

        LinearLayout card = new LinearLayout(activity);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setPadding(gap, gap, gap, gap);
        android.graphics.drawable.GradientDrawable background =
                new android.graphics.drawable.GradientDrawable();
        background.setColor(0x22888888);
        background.setCornerRadius(8 * activity.getResources().getDisplayMetrics().density);
        card.setBackground(background);
        card.addView(line(activity, "机器码：", machine == null ? "请先登录微信" : machine, true, textColor));
        card.addView(line(activity, "wxid：", wxid == null ? "请先登录微信" : wxid, true, textColor));
        card.addView(line(activity, "承诺：", Activation.promise(), false, textColor));
        content.addView(card);

        EditText promise = new NoPasteEditText(activity);
        promise.setHint("请填写承诺：在此手动输入上面的承诺内容");
        promise.setInputType(InputType.TYPE_CLASS_TEXT
                | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
                | InputType.TYPE_TEXT_FLAG_MULTI_LINE);
        promise.setGravity(android.view.Gravity.TOP | android.view.Gravity.START);
        promise.setTextSize(14);
        promise.setTextColor(textColor);
        promise.setHintTextColor(hintColor);
        promise.setSingleLine(false);
        promise.setMinLines(3);
        promise.setPadding(gap, gap / 2, gap, gap / 2);
        promise.setBackground(box(activity, gap));
        LinearLayout.LayoutParams promiseParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        promiseParams.setMargins(0, gap, 0, 0);
        promise.setLayoutParams(promiseParams);
        content.addView(promise);

        EditText code = new EditText(activity);
        code.setHint("请输入授权码（必填）");
        code.setInputType(InputType.TYPE_CLASS_TEXT
                | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
                | InputType.TYPE_TEXT_FLAG_MULTI_LINE);
        code.setGravity(android.view.Gravity.TOP | android.view.Gravity.START);
        code.setTextSize(14);
        code.setTextColor(textColor);
        code.setHintTextColor(hintColor);
        code.setMinLines(2);
        code.setPadding(gap, gap / 2, gap, gap / 2);
        code.setBackground(box(activity, gap));
        LinearLayout.LayoutParams codeParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        codeParams.setMargins(0, gap, 0, gap);
        code.setLayoutParams(codeParams);
        content.addView(code);

        android.widget.ScrollView scroll = new android.widget.ScrollView(activity);
        scroll.addView(content);

        TextView title = new TextView(activity);
        title.setText("WXH 免费授权");
        title.setGravity(android.view.Gravity.CENTER);
        title.setTextSize(18);
        title.setTextColor(textColor);
        title.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        title.setPadding(0, gap, 0, gap);

        AlertDialog dialog = new AlertDialog.Builder(activity)
                .setCustomTitle(title)
                .setView(scroll)
                .setPositiveButton("授权", null)
                .setNegativeButton("稍后", null)
                .create();
        dialog.setOnShowListener(ignored -> {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setTextColor(textColor);
            dialog.getButton(AlertDialog.BUTTON_NEGATIVE).setTextColor(textColor);
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(view -> {
            String promiseText = promise.getText().toString().trim();
            String codeText = code.getText().toString().trim();
            if (promiseText.isEmpty() || codeText.isEmpty()) {
                Toast.makeText(activity, "承诺和授权码都必须填写",
                        Toast.LENGTH_SHORT).show();
                return;
            }
            boolean ok = Activation.activate(promiseText, codeText);
            Toast.makeText(activity,
                    ok ? "授权成功，请重启微信"
                            : "承诺内容或授权码不正确",
                    Toast.LENGTH_LONG).show();
            if (ok) {
                dialog.dismiss();
            }
            });
        });
        dialog.setOnDismissListener(d -> shown = false);
        dialog.show();
    }

    private static android.graphics.drawable.GradientDrawable box(
            Activity activity, int radius) {
        android.graphics.drawable.GradientDrawable box =
                new android.graphics.drawable.GradientDrawable();
        box.setColor(0x11888888);
        box.setStroke(1, 0x33888888);
        box.setCornerRadius(radius);
        return box;
    }

    private static TextView line(Activity activity, String label, String value,
            boolean monospace, int color) {
        TextView view = new TextView(activity);
        view.setText(label + value);
        view.setTextSize(14);
        view.setTextColor(color);
        view.setTextIsSelectable(true);
        view.setSingleLine(monospace);
        if (monospace) {
            view.setTypeface(android.graphics.Typeface.MONOSPACE);
        }
        view.setPadding(0, 2, 0, 2);
        return view;
    }

    /** 承诺框禁用长按粘贴/剪切。 */
    private static final class NoPasteEditText extends EditText {

        NoPasteEditText(Context context) {
            super(context);
            setLongClickable(false);
            setTextIsSelectable(false);
        }

        @Override
        public boolean onTextContextMenuItem(int id) {
            if (id == android.R.id.paste
                    || id == android.R.id.pasteAsPlainText
                    || id == android.R.id.cut) {
                return false;
            }
            return super.onTextContextMenuItem(id);
        }

        @Override
        public boolean isSuggestionsEnabled() {
            return false;
        }
    }

    /**
     * 未授权时，在微信首页标题区域双击可重新打开授权窗。
     * 只观察事件，不消费，不影响微信原有手势。
     */
    private static final class ReopenTouch implements HookCallback {

        private static final String LAUNCHER = "com.tencent.mm.ui.LauncherUI";

        private static long downTime;
        private static long lastTapTime;
        private static float downX;
        private static float downY;
        private static float lastTapY;

        @Override
        public void before(HookParam param) {
            Object target = param.thisObject();
            if (!(target instanceof Activity activity)
                    || !LAUNCHER.equals(activity.getClass().getName())
                    || shown) {
                return;
            }
            Object argument = param.arg(0);
            if (!(argument instanceof MotionEvent event)
                    || event.getPointerCount() != 1) {
                return;
            }
            long now = SystemClock.uptimeMillis();
            int action = event.getActionMasked();
            if (action == MotionEvent.ACTION_DOWN) {
                downTime = now;
                downX = event.getX();
                downY = event.getY();
                return;
            }
            if (action != MotionEvent.ACTION_UP) {
                return;
            }
            float limit = topLimit(activity);
            float deltaX = event.getX() - downX;
            float deltaY = event.getY() - downY;
            float slop = ViewConfiguration.get(activity).getScaledTouchSlop() * 2f;
            if (event.getY() > limit || downY > limit
                    || deltaX * deltaX + deltaY * deltaY > slop * slop
                    || now - downTime > 350) {
                lastTapTime = 0;
                return;
            }
            if (lastTapTime != 0 && now - lastTapTime <= 450
                    && lastTapY <= limit) {
                lastTapTime = 0;
                activity.runOnUiThread(() -> tryShow(activity, 0, true));
            } else {
                lastTapTime = now;
                lastTapY = event.getY();
            }
        }

        private static float topLimit(Activity activity) {
            int id = activity.getResources().getIdentifier(
                    "status_bar_height", "dimen", "android");
            int status = id > 0
                    ? activity.getResources().getDimensionPixelSize(id) : 0;
            return status + 64f * activity.getResources().getDisplayMetrics().density;
        }
    }
}
