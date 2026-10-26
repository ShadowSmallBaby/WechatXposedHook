package github.shadowbaby.wechatxposed.hook.license;

import android.app.Activity;
import android.app.AlarmManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.os.Handler;
import android.os.Looper;
import android.os.Process;
import android.os.SystemClock;
import android.widget.Toast;
import github.shadowbaby.wechatxposed.hook.loader.SecretConstants;
import github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import github.shadowbaby.wechatxposed.hook.loader.util.Secret;

/** 授权级别变化后重启微信，让功能表与授权状态立即生效。 */
public final class WeChatRestart {

    private static final String WECHAT = Secret.of(SecretConstants.WECHAT_PACKAGE);

    private static final String LAUNCHER = Secret.of(SecretConstants.WECHAT_LAUNCHER_CLASS);

    private WeChatRestart() {
    }

    /**
     * 先起一个定时拉起微信的 PendingIntent，再结束当前进程；
     * 拉起失败时退化为提示手动重启。
     */
    public static void restart(Activity activity) {
        try {
            Intent intent = new Intent(Intent.ACTION_MAIN);
            intent.setClassName(WECHAT, LAUNCHER);
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK
                    | Intent.FLAG_ACTIVITY_CLEAR_TASK);
            PendingIntent launch = PendingIntent.getActivity(activity, 0x5758, intent,
                    PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
            AlarmManager alarms = activity.getSystemService(AlarmManager.class);
            if (alarms == null) {
                Toast.makeText(activity, "授权成功，请手动重启微信",
                        Toast.LENGTH_LONG).show();
                return;
            }
            long when = SystemClock.elapsedRealtime() + 900;
            try {
                alarms.setExactAndAllowWhileIdle(
                        AlarmManager.ELAPSED_REALTIME_WAKEUP, when, launch);
            } catch (Throwable error) {
                alarms.set(AlarmManager.ELAPSED_REALTIME_WAKEUP, when, launch);
            }
            Toast.makeText(activity, "授权成功，正在重启微信…",
                    Toast.LENGTH_SHORT).show();
            new Handler(Looper.getMainLooper()).postDelayed(() -> {
                activity.finishAffinity();
                Process.killProcess(Process.myPid());
            }, 500);
        } catch (Throwable error) {
            ModuleLogger.log("activation restart: " + error);
            Toast.makeText(activity, "授权成功，请手动重启微信",
                    Toast.LENGTH_LONG).show();
        }
    }
}
