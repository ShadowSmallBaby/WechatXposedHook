package github.shadowbaby.wechatxposed.hook.license;

import android.app.Activity;
import android.os.SystemClock;
import android.view.MotionEvent;
import android.view.ViewConfiguration;
import github.shadowbaby.wechatxposed.hook.framework.HookCallback;
import github.shadowbaby.wechatxposed.hook.framework.HookFramework;
import github.shadowbaby.wechatxposed.hook.framework.HookParam;
import github.shadowbaby.wechatxposed.hook.loader.SecretConstants;
import github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import github.shadowbaby.wechatxposed.hook.loader.util.Secret;

/**
 * 微信首页双击顶部标题复制机器码与 WXID。
 *
 * 协议弹窗关闭后就没有复制入口了；这里只观察触摸事件，不消费，不影响原有手势。
 */
public final class QuickCopy implements HookCallback {

    private static final String LAUNCHER = Secret.of(SecretConstants.WECHAT_LAUNCHER_CLASS);

    private static volatile boolean installed;

    private static long downTime;

    private static long lastTapTime;

    private static float downX;

    private static float downY;

    private static float lastTapY;

    private QuickCopy() {
    }

    public static synchronized void install(HookFramework framework) {
        if (installed) {
            return;
        }
        try {
            Class<?> activity = framework.findClassIfExists("android.app.Activity", null);
            if (activity == null) {
                return;
            }
            framework.hookMethod(activity, "dispatchTouchEvent",
                    new Class<?>[]{MotionEvent.class}, new QuickCopy());
            installed = true;
            ModuleLogger.debug("quick copy: installed");
        } catch (Throwable error) {
            ModuleLogger.log(error);
        }
    }

    @Override
    public void before(HookParam param) {
        Object target = param.thisObject();
        if (!(target instanceof Activity activity)
                || !LAUNCHER.equals(activity.getClass().getName())) {
            return;
        }
        Object argument = param.arg(0);
        if (!(argument instanceof MotionEvent event) || event.getPointerCount() != 1) {
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
        if (lastTapTime != 0 && now - lastTapTime <= 450 && lastTapY <= limit) {
            lastTapTime = 0;
            activity.runOnUiThread(() -> IdentityClipboard.copy(activity));
        } else {
            lastTapTime = now;
            lastTapY = event.getY();
        }
    }

    /** 状态栏高度 + 64dp，覆盖首页标题栏区域。 */
    private static float topLimit(Activity activity) {
        int id = activity.getResources().getIdentifier(
                "status_bar_height", "dimen", "android");
        int status = id > 0
                ? activity.getResources().getDimensionPixelSize(id) : 0;
        return status + 64f * activity.getResources().getDisplayMetrics().density;
    }
}
