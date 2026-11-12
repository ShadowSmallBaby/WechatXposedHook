package io.github.shadowbaby.wechatxposed.hook.support.shell;

import android.content.pm.ApplicationInfo;
import io.github.shadowbaby.wechatxposed.hook.BuildConfig;
import io.github.shadowbaby.wechatxposed.hook.deploy.ModuleApk;
import io.github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

public final class ShellBundle {

    private static final String LOG = "shell bundle: ";

    private static final String ASSET = "shell.apk";

    private static final String STAMP = "shell.apk.stamp";

    private static volatile String path;

    private static volatile ClassLoader loader;

    private ShellBundle() {
    }

    public static synchronized String ensure(ApplicationInfo appInfo) {
        if (path != null) {
            return path;
        }
        if (appInfo == null || appInfo.dataDir == null) {
            return null;
        }
        File directory = new File(appInfo.dataDir,
                "files/wxh_shell/" + BuildConfig.WX_PACK);
        if (!directory.isDirectory() && !directory.mkdirs()) {
            ModuleLogger.log(LOG + "cannot create " + directory);
            return null;
        }
        File target = new File(directory, ASSET);
        String stamp = BuildConfig.VERSION_CODE + ":" + BuildConfig.WX_PACK;
        if (!isCurrent(target, directory, stamp) && !extract(target)) {
            return null;
        }
        write(new File(directory, STAMP), stamp.getBytes(StandardCharsets.UTF_8));
        path = target.getAbsolutePath();
        return path;
    }

    public static String shellApkPath() {
        return path;
    }

    public static synchronized ClassLoader loader(String shellApkPath, File dataDir) {
        if (loader != null) {
            return loader;
        }
        if (shellApkPath == null || dataDir == null) {
            return null;
        }
        File dexOut = new File(dataDir,
                "files/wxh_shell/" + BuildConfig.WX_PACK + "/dexout");
        if (!dexOut.isDirectory() && !dexOut.mkdirs()) {
            ModuleLogger.log(LOG + "cannot create " + dexOut);
            return null;
        }
        try {
            loader = new dalvik.system.DexClassLoader(shellApkPath,
                    dexOut.getAbsolutePath(), null, ShellBundle.class.getClassLoader());
            return loader;
        } catch (Throwable error) {
            ModuleLogger.log(LOG + "loader failed: " + error);
            return null;
        }
    }

    private static boolean isCurrent(File target, File directory, String stamp) {
        if (!target.isFile() || target.length() == 0 || target.canWrite()) {
            return false;
        }
        File file = new File(directory, STAMP);
        if (!file.isFile()) {
            return false;
        }
        try (InputStream input = new java.io.FileInputStream(file)) {
            byte[] buffer = new byte[32];
            int read = input.read(buffer);
            return read > 0
                    && stamp.equals(new String(buffer, 0, read, StandardCharsets.UTF_8).trim());
        } catch (Throwable error) {
            return false;
        }
    }

    private static boolean extract(File target) {
        File temp = new File(target.getParentFile(), ASSET + ".tmp");
        try (InputStream input = ModuleApk.openAsset(ASSET);
                FileOutputStream output = new FileOutputStream(temp)) {
            if (input == null) {
                ModuleLogger.log(LOG + "asset missing " + ASSET);
                return false;
            }
            byte[] buffer = new byte[16 * 1024];
            int read;
            while ((read = input.read(buffer)) > 0) {
                output.write(buffer, 0, read);
            }
            output.flush();
            output.getFD().sync();
        } catch (Throwable error) {
            ModuleLogger.log(LOG + "extract: " + error);
            temp.delete();
            return false;
        }
        if (!temp.renameTo(target)) {
            if (target.delete() && temp.renameTo(target)) {
                target.setReadable(true, false);
                return true;
            }
            temp.delete();
            ModuleLogger.log(LOG + "cannot replace " + target);
            return false;
        }
        target.setReadable(true, false);
        target.setWritable(false, false);
        return true;
    }

    private static void write(File file, byte[] data) {
        try (FileOutputStream output = new FileOutputStream(file)) {
            output.write(data);
        } catch (Throwable error) {
            ModuleLogger.log(LOG + "stamp: " + error);
        }
    }
}
