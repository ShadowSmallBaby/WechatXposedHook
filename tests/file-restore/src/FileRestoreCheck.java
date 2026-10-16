import github.shadowbaby.wechatxposed.hook.deploy.FeaturePackRestorer;
import github.shadowbaby.wechatxposed.hook.deploy.ModuleApk;
import java.io.File;
import java.util.List;

/**
 * 在设备上跑真正的 FeaturePackRestorer(读模块 APK 的 assets/wx6_2.44.zip)。
 *
 * 参数: <微信 files 目录> [mode] [模块 APK 路径]
 * ensureOnce 收的是微信 files 目录,它自己会拼 wx6_2.44 子目录,所以探针也按这个语义走。
 */
public final class FileRestoreCheck {

    private static final String DIR_NAME = "wx6_2.44";

    public static void main(String[] args) throws Exception {
        File filesDir = new File(args[0]);
        String mode = args.length > 1 ? args[1] : "";
        if (args.length > 2) {
            ModuleApk.rememberForTest(args[2]);
        }
        File directory = new File(filesDir, DIR_NAME);
        System.out.println("mode=" + (mode.isEmpty() ? "none" : mode));
        List<String> before = FeaturePackRestorer.missingFiles(directory);
        System.out.println("missingBefore=" + before.size());
        try {
            FeaturePackRestorer.ensureOnce(filesDir);
        } catch (Throwable error) {
            System.out.println("ensureError=" + error.getClass().getSimpleName());
        }
        List<String> after = FeaturePackRestorer.missingFiles(directory);
        System.out.println("missingAfter=" + after.size());
        System.out.println("files=" + count(directory));
    }

    private static int count(File directory) {
        File[] entries = directory.listFiles();
        if (entries == null) {
            return 0;
        }
        int files = 0;
        for (File entry : entries) {
            if (entry.isFile()) {
                files++;
            }
        }
        return files;
    }
}
