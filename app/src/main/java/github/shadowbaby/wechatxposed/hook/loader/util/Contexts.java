package github.shadowbaby.wechatxposed.hook.loader.util;

import android.app.Activity;
import android.content.Context;
import android.content.ContextWrapper;

/** 从任意 Context 向上找 Activity。 */
public final class Contexts {

    private Contexts() {
    }

    public static Activity activityOf(Context context) {
        Context current = context;
        while (current instanceof ContextWrapper wrapper) {
            if (current instanceof Activity activity) {
                return activity;
            }
            current = wrapper.getBaseContext();
        }
        return null;
    }
}
