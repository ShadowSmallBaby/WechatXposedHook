package github.shadowbaby.wechatxposed.hook.license;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.ContextWrapper;
import android.os.Handler;
import android.os.Looper;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import github.shadowbaby.wechatxposed.hook.framework.HookCallback;
import github.shadowbaby.wechatxposed.hook.framework.HookFramework;
import github.shadowbaby.wechatxposed.hook.framework.HookParam;
import github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;

/**
 * 未授权时的用户协议弹窗。
 *
 * 原版功能包的免责声明只在点开「更多」时出现；功能包在未授权时不会加载，
 * 这里改为监听设置页「更多」这一项的点击，在页面打开后弹出等价内容。
 */
public final class AgreementDialog implements HookCallback {

    private static final String TITLE = "用户协议";

    private static final String BODY =
            "欢迎使用 X 模块。\n\n"
            + "声明：此软件是捐赠软件，可以免费使用。如果喜欢请打赏支持维护和开发！\n"
            + "任何形式或渠道包括预装手机售卖此软件都是非法贩卖，别上当受骗！"
            + "欢迎举报贩卖者！请慎用，不要宣传！\n\n"
            + "点击「接受并关闭」表示你已阅读并同意上述声明。";

    /** 更多页独有的菜单项，用来判断页面已经显示。 */
    private static final String MORE_MARKER = "设置模块文件夹";

    private static volatile boolean installed;

    private static volatile boolean shown;

    private AgreementDialog() {
    }

    public static synchronized void install(HookFramework framework,
            ClassLoader classLoader) {
        if (installed) {
            return;
        }
        try {
            Class<?> view = framework.findClassIfExists("android.view.View", null);
            if (view == null) {
                ModuleLogger.log("agreement dialog: View missing");
                return;
            }
            framework.hookMethod(view, "onAttachedToWindow", new Class<?>[]{},
                    new AgreementDialog());
            installed = true;
            ModuleLogger.log("agreement dialog: installed");
        } catch (Throwable error) {
            framework.log(error);
        }
    }

    @Override
    public void after(HookParam param) {
        if (shown || Activation.isBaseAllowed()) {
            return;
        }
        Object self = param.thisObject();
        if (!(self instanceof TextView label)) {
            return;
        }
        CharSequence value = label.getText();
        if (value == null || !value.toString().contains(MORE_MARKER)) {
            return;
        }
        Activity activity = activityOf(label.getContext());
        if (activity == null || activity.isFinishing()) {
            return;
        }
        shown = true;
        // 等更多页完成布局后再压上协议窗口。
        new Handler(Looper.getMainLooper()).postDelayed(() -> {
            try {
                show(activity);
            } catch (Throwable error) {
                ModuleLogger.log("agreement dialog: " + error);
            }
        }, 300);
    }

    private static Activity activityOf(Context context) {
        Context current = context;
        while (current instanceof ContextWrapper wrapper) {
            if (current instanceof Activity activity) {
                return activity;
            }
            current = wrapper.getBaseContext();
        }
        return null;
    }

    private static void show(Activity activity) {
        if (activity.isFinishing()) {
            return;
        }
        float density = activity.getResources().getDisplayMetrics().density;
        int padding = (int) (18 * density);
        int gap = (int) (10 * density);
        boolean night = (activity.getResources().getConfiguration().uiMode
                & android.content.res.Configuration.UI_MODE_NIGHT_MASK)
                == android.content.res.Configuration.UI_MODE_NIGHT_YES;
        int textColor = night ? 0xFFFFFFFF : 0xFF111111;

        LinearLayout content = new LinearLayout(activity);
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(padding, gap, padding, 0);

        TextView body = new TextView(activity);
        body.setText(BODY);
        body.setTextSize(14);
        body.setTextColor(textColor);
        body.setLineSpacing(0, 1.2f);
        content.addView(body);

        String machine = Activation.machineCode();
        TextView code = new TextView(activity);
        code.setText("\n机器码：" + (machine == null ? "请先登录微信" : machine));
        code.setTextSize(13);
        code.setTextColor(textColor);
        code.setTextIsSelectable(true);
        code.setTypeface(android.graphics.Typeface.MONOSPACE);
        content.addView(code);

        ScrollView scroll = new ScrollView(activity);
        scroll.addView(content);
        scroll.setLayoutParams(new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        TextView title = new TextView(activity);
        title.setText(TITLE);
        title.setGravity(android.view.Gravity.CENTER);
        title.setTextSize(18);
        title.setTextColor(textColor);
        title.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        title.setPadding(0, gap, 0, gap);

        AlertDialog dialog = new AlertDialog.Builder(activity)
                .setCustomTitle(title)
                .setView(scroll)
                .setPositiveButton("接受并关闭", null)
                .setCancelable(false)
                .create();
        dialog.setOnShowListener(ignored ->
                dialog.getButton(AlertDialog.BUTTON_POSITIVE).setTextColor(textColor));
        dialog.show();
        ModuleLogger.log("agreement dialog: shown");
    }
}
