package github.shadowbaby.wechatxposed.hook.deploy;

import github.shadowbaby.wechatxposed.hook.loader.util.Secret;
import github.shadowbaby.wechatxposed.hook.loader.SecretConstants;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public abstract class ModuleApk {

    private static final String ASSETS_PREFIX = "assets/";

    private static final String PACKAGE = Secret.of(SecretConstants.MODULE_PACKAGE);

    private static final String[] APP_DIRS = {"/data/app", "/data/app-private"};

    private static volatile String path;

    public static void remember(String modulePath) {
        path = modulePath;
    }

    public static void rememberForTest(String modulePath) {
        remember(modulePath);
    }

    /** 当前模块 APK 路径；证书自检使用。 */
    public static String modulePath() {
        String current = usablePath(path);
        return current != null ? current : usablePath(findInstalledApk());
    }

    public static boolean extractPayload(String assetName, File target) throws IOException {
        return copyAsset(assetName, target);
    }

    /** 从模块 APK 的 assets/ 下复制单个文件（平铺功能包用）。 */
    public static boolean copyAsset(String assetPath, File target) throws IOException {
        String modulePath = usablePath(path);
        if (modulePath == null) {
            modulePath = usablePath(findInstalledApk());
        }
        if (modulePath == null) {
            return false;
        }
        try (ZipFile apk = new ZipFile(modulePath)) {
            ZipEntry entry = apk.getEntry(ASSETS_PREFIX + assetPath);
            if (entry == null) {
                return false;
            }
            try (InputStream input = apk.getInputStream(entry);
                    OutputStream output = new FileOutputStream(target)) {
                byte[] buffer = new byte[16 * 1024];
                int read;
                while ((read = input.read(buffer)) > 0) {
                    output.write(buffer, 0, read);
                }
            }
        }
        return true;
    }

    /** 读取模块 APK 的单个 asset，失败返回 null。 */
    public static byte[] readAsset(String assetPath) {
        String modulePath = usablePath(path);
        if (modulePath == null) {
            modulePath = usablePath(findInstalledApk());
        }
        if (modulePath == null) {
            return null;
        }
        try (ZipFile apk = new ZipFile(modulePath)) {
            ZipEntry entry = apk.getEntry(ASSETS_PREFIX + assetPath);
            if (entry == null) {
                return null;
            }
            try (InputStream input = apk.getInputStream(entry);
                    java.io.ByteArrayOutputStream output =
                            new java.io.ByteArrayOutputStream()) {
                byte[] buffer = new byte[16 * 1024];
                int read;
                while ((read = input.read(buffer)) > 0) {
                    output.write(buffer, 0, read);
                }
                return output.toByteArray();
            }
        } catch (IOException error) {
            return null;
        }
    }

    private static String usablePath(String candidate) {
        return candidate != null && new File(candidate).isFile() ? candidate : null;
    }

    private static String findInstalledApk() {
        for (String dir : APP_DIRS) {
            File root = new File(dir);
            File[] entries = root.listFiles();
            if (entries == null) {
                continue;
            }
            for (File entry : entries) {
                if (!entry.isDirectory() || !entry.getName().contains(PACKAGE)) {
                    continue;
                }
                File base = new File(entry, "base.apk");
                if (base.isFile()) {
                    return base.getAbsolutePath();
                }
            }
        }
        return null;
    }
}
