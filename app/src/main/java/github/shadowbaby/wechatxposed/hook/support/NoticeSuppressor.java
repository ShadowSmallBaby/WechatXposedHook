package github.shadowbaby.wechatxposed.hook.support;

import android.widget.TextView;
import github.shadowbaby.wechatxposed.hook.framework.HookCallback;
import github.shadowbaby.wechatxposed.hook.framework.HookFramework;
import github.shadowbaby.wechatxposed.hook.framework.HookParam;
import github.shadowbaby.wechatxposed.hook.loader.ModuleLogger;

/**
 * 屏蔽 X 3.0 菜单顶部的更新失败提示。
 *
 * 更新链路被拦截后，宿主仍可能把失败文案设置到 TextView 上。
 * 这里在 TextView.setText 层过滤提示语，其余文本不受影响。
 */
public final class NoticeSuppressor {

    private static final String[] BLOCKED = {
            "无法连接服务器", "下载更新文件", "不影响使用"};

    private static final String LOG_BLOCKED = "update notice hidden";

    private static boolean installed;

    private NoticeSuppressor() {
    }

    public static synchronized void install(HookFramework framework) {
        if (installed) {
            return;
        }
        try {
            Class<?> textView = framework.findClassIfExists("android.widget.TextView", null);
            if (textView == null) {
                return;
            }
            Callback callback = new Callback();
            framework.hookMethod(textView, "setText", new Class<?>[]{CharSequence.class}, callback);
            framework.hookMethod(textView, "setText",
                    new Class<?>[]{CharSequence.class, TextView.BufferType.class}, callback);
            installed = true;
            ModuleLogger.log("notice suppressor installed");
        } catch (Throwable error) {
            framework.log(error);
        }
    }

    private static final class Callback implements HookCallback {

        @Override
        public void before(HookParam param) {
            Object value = param.arg(0);
            if (!(value instanceof CharSequence text)) {
                return;
            }
            String message = text.toString();
            for (String blocked : BLOCKED) {
                if (message.contains(blocked)) {
                    ModuleLogger.log(LOG_BLOCKED);
                    param.setResult(null);
                    return;
                }
            }
        }
    }
}
