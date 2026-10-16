package github.shadowbaby.wechatxposed.hook.support;

import github.shadowbaby.wechatxposed.hook.loader.ModuleLogger;
import java.io.File;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * 从 APK 里取出 dex 条目。
 *
 * 微信的 dex 都在 base.apk 里(classes.dex、classes2.dex …),直接按 zip 条目读,
 * 不走 {@code dalvik.system.DexFile}:后者只能列类名,拿不到字节,而我们要自己解析常量池。
 * 读出来的 dex 字节直接交给 {@link DexStrings},不落盘。
 */
final class DexPaths {

    private static final String LOG = "host spoof: ";

    private DexPaths() {
    }

    /** APK 里各 dex 的字节,按 classes.dex / classes2.dex … 的顺序。 */
    static List<byte[]> of(String apkPath) {
        if (apkPath == null || apkPath.isEmpty()) {
            ModuleLogger.log(LOG + "sourceDir empty");
            return Collections.emptyList();
        }
        File apk = new File(apkPath);
        if (!apk.isFile()) {
            ModuleLogger.log(LOG + "apk missing " + apkPath);
            return Collections.emptyList();
        }
        List<byte[]> result = new ArrayList<>();
        try (ZipFile zip = new ZipFile(apk)) {
            List<String> names = new ArrayList<>();
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String name = entry.getName();
                if (name.startsWith("classes") && name.endsWith(".dex") && !entry.isDirectory()) {
                    names.add(name);
                }
            }
            Collections.sort(names);
            for (String name : names) {
                try (InputStream in = zip.getInputStream(zip.getEntry(name))) {
                    ByteArrayOutputStream out = new ByteArrayOutputStream();
                    byte[] buffer = new byte[64 * 1024];
                    int read;
                    while ((read = in.read(buffer)) > 0) {
                        out.write(buffer, 0, read);
                    }
                    result.add(out.toByteArray());
                } catch (IOException error) {
                    ModuleLogger.log(LOG + "read " + name + " failed: " + error);
                }
            }
        } catch (IOException error) {
            ModuleLogger.log(LOG + "open apk failed: " + error);
            return result;
        }
        return result;
    }
}
