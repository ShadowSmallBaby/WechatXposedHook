package github.shadowbaby.wechatxposed.hook.deploy;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * 模块自己的 APK。
 *
 * 内置载荷(微X 的加密功能包,见 FeaturePackRestorer)放在模块 APK 的 assets 里,而模块 APK 是
 * LSPosed 按路径加载的独立 APK,不是微信的 APK,所以这份 assets 只能自己按路径读:
 * 路径来自 initZygote 的 StartupParam.modulePath。
 *
 * 这个路径是 LSPosed 上次扫描时记下的,重装 APK 后安装目录会变、它要到下次重启框架才刷新,
 * 所以路径指向的文件不存在时按包名在 /data/app 下重新找一次。
 */
public abstract class ModuleApk {

    private static final String ASSETS_PREFIX = "assets/";

    /** 模块包名;initZygote 拿不到有效路径时按它找当前安装的 APK。 */
    private static final String PACKAGE = "github.shadowbaby.wechatxposed.hook";

    /** 按包名找 APK 时先试这些目录。 */
    private static final String[] APP_DIRS = {"/data/app", "/data/app-private"};

    /** 模块 APK 路径;initZygote 写入一次,之后只读。 */
    private static volatile String path;

    /** initZygote 记下模块 APK 路径。 */
    public static void remember(String modulePath) {
        path = modulePath;
    }

    /** 测试用:直接指定模块 APK 路径(真机上由 initZygote 调 remember)。 */
    public static void rememberForTest(String modulePath) {
        remember(modulePath);
    }

    /**
     * 把内置载荷(assets 里的 zip)解到 target;模块里没有这个条目时返回 false。
     *
     * 载荷在模块 APK 里是压缩存储的一个条目,不能直接当 zip 打开,先解出来再读。
     */
    public static boolean extractPayload(String assetName, File target) throws IOException {
        String modulePath = usablePath(path);
        if (modulePath == null) {
            modulePath = usablePath(findInstalledApk());
        }
        if (modulePath == null) {
            return false;
        }
        try (ZipFile apk = new ZipFile(modulePath)) {
            ZipEntry entry = apk.getEntry(ASSETS_PREFIX + assetName);
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

    /**
     * 路径可用才返回它。
     *
     * LSPosed 记的模块路径是它上次扫描时的安装位置,重装 APK 后目录名会变,
     * 而它要到下次重启框架才刷新;这时拿到的路径指向一个已不存在的文件。
     */
    private static String usablePath(String candidate) {
        return candidate != null && new File(candidate).isFile() ? candidate : null;
    }

    /** 按包名在 /data/app 下找当前安装的 base.apk;找不到返回 null。 */
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
