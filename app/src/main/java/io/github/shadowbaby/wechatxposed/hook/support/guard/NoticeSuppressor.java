package io.github.shadowbaby.wechatxposed.hook.support.guard;

import android.widget.TextView;
import io.github.shadowbaby.wechatxposed.shared.hook.HookCallback;
import io.github.shadowbaby.wechatxposed.shared.hook.HookFramework;
import io.github.shadowbaby.wechatxposed.shared.hook.HookParam;
import io.github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;

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

        installed = true;
        try {
            Class<?> textView = framework.findClassIfExists("android.widget.TextView", null);
            if (textView == null) {
                installed = false;
                return;
            }
            Callback callback = new Callback();
            framework.hookMethod(textView, "setText", new Class<?>[]{CharSequence.class}, callback);
            framework.hookMethod(textView, "setText",
                    new Class<?>[]{CharSequence.class, TextView.BufferType.class}, callback);
            ModuleLogger.debug("notice suppressor installed");
        } catch (Throwable error) {
            framework.log(error);
        }
    }

    private static final class Callback implements HookCallback {

        private static final String REGISTERED = "(已注册)";

        @Override
        public void before(HookParam param) {
            Object value = param.arg(0);
            if (!(value instanceof CharSequence text)) {
                return;
            }
            String message = text.toString();
            for (String blocked : BLOCKED) {
                if (message.contains(blocked)) {
                    ModuleLogger.debug(LOG_BLOCKED);
                    param.setResult(null);
                    return;
                }
            }
            if (!message.contains(REGISTERED)) {
                return;
            }
            param.setArg(0, "");
        }

    }
}
