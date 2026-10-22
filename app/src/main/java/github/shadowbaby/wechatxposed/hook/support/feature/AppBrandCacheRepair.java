package github.shadowbaby.wechatxposed.hook.support.feature;

import github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;

/**
 * 小程序 Flutter 缓存自愈。
 *
 * 微信小程序进程（appbrand0/1/...）的 Flutter/XML 缓存损坏或被写成 0 字节时，
 * Flutter 引擎会报 `fontXmlName ... no element found`，表现为小程序白屏。
 * 这里在进程启动早期扫描 code_cache，按规则删除无效缓存，让 Flutter 重新生成。
 *
 * 只清理 code_cache 内的 flutter_* 和 *.xml，不触碰聊天数据。
 */
public final class AppBrandCacheRepair {

    private static volatile boolean started;

    private AppBrandCacheRepair() {
    }

    public static void install() {
        if (started) {
            return;
        }
        started = true;
        Thread thread = new Thread(() -> {
            for (int attempt = 0; attempt < 40; attempt++) {
                try {
                    if (repairOnce()) {
                        // Flutter 可能在启动后才写出缓存；延迟复扫几次。
                        for (int delayed = 0; delayed < 3; delayed++) {
                            Thread.sleep(3_000L);
                            repairOnce();
                        }
                        return;
                    }
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    return;
                } catch (Throwable error) {
                    ModuleLogger.debug("appbrand cache: " + error);
                }
                try {
                    Thread.sleep(50L);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
        }, "wxh-appbrand-cache");
        thread.setDaemon(true);
        thread.start();
    }

    private static boolean repairOnce() throws Exception {
        Class<?> activityThread = Class.forName("android.app.ActivityThread");
        Object application = activityThread
                .getDeclaredMethod("currentApplication").invoke(null);
        if (!(application instanceof android.content.Context)) {
            return false;
        }
        File codeCache = ((android.content.Context) application).getCodeCacheDir();
        if (codeCache == null || !codeCache.isDirectory()) {
            return false;
        }
        repairTree(codeCache, 0);
        return true;
    }

    /** 只清理 code_cache 内与 Flutter/XML 相关的缓存，最多 3 层。 */
    private static void repairTree(File directory, int depth) {
        if (depth > 3 || directory == null || !directory.isDirectory()) {
            return;
        }
        File[] children = directory.listFiles();
        if (children == null) {
            return;
        }
        for (File child : children) {
            if (child.isDirectory()) {
                repairTree(child, depth + 1);
            } else {
                repairFile(child);
            }
        }
    }

    private static void repairFile(File file) {
        String name = file.getName();
        boolean flutter = name.startsWith("flutter");
        boolean xml = name.endsWith(".xml");
        if (!flutter && !xml) {
            return;
        }
        // Flutter 缓存只删 0 字节；XML 额外校验是否以 '<' 开头。
        if (file.length() > 0 && (!xml || validXml(file))) {
            return;
        }
        if (file.delete()) {
            ModuleLogger.log("appbrand cache: removed invalid " + file.getAbsolutePath());
        }
    }

    private static boolean validXml(File file) {
        if (file.length() <= 0) {
            return false;
        }
        try (InputStream input = new FileInputStream(file)) {
            int value;
            while ((value = input.read()) != -1) {
                if (!Character.isWhitespace(value)) {
                    return value == '<';
                }
            }
        } catch (Throwable ignored) {
            return false;
        }
        return false;
    }
}
