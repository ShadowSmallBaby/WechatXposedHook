package github.shadowbaby.wechatxposed.hook.license;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.widget.Toast;
import github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;

/** 把机器码与 WXID 复制到剪贴板。 */
public final class IdentityClipboard {

    private IdentityClipboard() {
    }

    public static void copy(Context context) {
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
}
