package github.shadowbaby.wechatxposed.hook.support.feature;

import android.content.Context;
import github.shadowbaby.wechatxposed.hook.framework.HookCallback;
import github.shadowbaby.wechatxposed.hook.framework.HookFramework;
import github.shadowbaby.wechatxposed.hook.framework.HookParam;
import github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * 小程序 Flutter 缓存自愈。
 *
 * 微信小程序进程（appbrand0/1/...）的 XML 缓存损坏时，Flutter 解析会失败。
 * 注意：`flutter_custom_fonts2.xml` 每次启动都会被 Flutter 写成 0 字节，
 * 表示「没有自定义字体」，属于正常输出，不能当成坏缓存删除。
 * 这里只清理「有内容但不是合法 XML」的缓存，让 Flutter 重新生成。
 *
 * 只清理 code_cache 内的 *.xml，不触碰聊天数据。
 */
public final class AppBrandCacheRepair {

    /** 微信 Application 固定类名；日志栈里它覆写了 attachBaseContext。 */
    private static final String HOST_APPLICATION = "com.tencent.mm.app.Application";

    private static volatile boolean started;

    private static final AtomicBoolean SCANNING = new AtomicBoolean();

    private AppBrandCacheRepair() {
    }

    public static void install(HookFramework framework, ClassLoader classLoader) {
        if (started) {
            return;
        }
        started = true;
        hookAttachBaseContext(framework, classLoader);
        startFallbackWait();
    }

    /**
     * attachBaseContext 之后 Context 已经可用，直接拿它扫描，不再依赖轮询
     * currentApplication。预初始化进程可能赶不上这次 hook，另有轮询兜底。
     */
    private static void hookAttachBaseContext(HookFramework framework,
            ClassLoader classLoader) {
        try {
            Class<?> target = framework.findClassIfExists(HOST_APPLICATION, classLoader);
            if (target == null) {
                ModuleLogger.log("appbrand cache: application class missing");
                return;
            }
            framework.hookMethod(target, "attachBaseContext",
                    new Class<?>[]{Context.class}, new HookCallback() {
                        @Override
                        public void after(HookParam param) {
                            Object context = param.arg(0);
                            if (context instanceof Context value) {
                                startScan(value);
                            }
                        }
                    });
            ModuleLogger.log("appbrand cache: context hooked");
        } catch (Throwable error) {
            ModuleLogger.log(error);
        }
    }

    /** 兜底：预初始化进程可能在 hook 安装前就完成 attach，轮询 30 秒。 */
    private static void startFallbackWait() {
        Thread thread = new Thread(() -> {
            long deadline = System.currentTimeMillis() + 30_000L;
            while (System.currentTimeMillis() < deadline && !SCANNING.get()) {
                try {
                    Class<?> activityThread = Class.forName("android.app.ActivityThread");
                    Object application = activityThread
                            .getDeclaredMethod("currentApplication").invoke(null);
                    if (application instanceof Context context) {
                        startScan(context);
                        return;
                    }
                    Thread.sleep(250L);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    return;
                } catch (Throwable error) {
                    ModuleLogger.debug("appbrand cache: " + error);
                    try {
                        Thread.sleep(250L);
                    } catch (InterruptedException interrupted) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                }
            }
        }, "wxh-appbrand-cache-wait");
        thread.setDaemon(true);
        thread.start();
    }

    /**
     * Flutter 可能在进程启动后才写出缓存，所以间隔复扫：
     * 首次立即扫，之后每 3 秒一次，共 10 次覆盖 30 秒。
     */
    private static void startScan(Context context) {
        if (!SCANNING.compareAndSet(false, true)) {
            return;
        }
        Thread thread = new Thread(() -> {
            for (int attempt = 0; attempt < 10; attempt++) {
                try {
                    if (attempt > 0) {
                        Thread.sleep(3_000L);
                    }
                    repair(context);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    return;
                } catch (Throwable error) {
                    ModuleLogger.debug("appbrand cache: " + error);
                }
            }
        }, "wxh-appbrand-cache");
        thread.setDaemon(true);
        thread.start();
    }

    private static void repair(Context context) {
        File codeCache = context.getCodeCacheDir();
        if (codeCache == null || !codeCache.isDirectory()) {
            return;
        }
        repairTree(codeCache, 0);
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
        if (!name.endsWith(".xml")) {
            return;
        }
        // flutter_custom_fonts2.xml 每次启动都会被 Flutter 写成 0 字节，
        // 表示「没有自定义字体」，属于正常输出；删了只会被重新写回。
        // 只清理有内容但 XML 无效的文件。
        if (file.length() == 0 || validXml(file)) {
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
