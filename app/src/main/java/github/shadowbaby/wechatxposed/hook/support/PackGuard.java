package github.shadowbaby.wechatxposed.hook.support;

import github.shadowbaby.wechatxposed.hook.framework.HookCallback;
import github.shadowbaby.wechatxposed.hook.framework.HookFramework;
import github.shadowbaby.wechatxposed.hook.framework.HookParam;
import github.shadowbaby.wechatxposed.hook.loader.ModuleLogger;
import java.io.File;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 阻止微X核心在「参数校验失败 / 更新失败」时删除本地功能包。
 *
 * 微X核心的 params 响应里带 {@code del_fp} / {@code del_param} 指令，
 * 校验不通过时会直接删掉 files/wx6_2.44、files/x7_3.0 下的文件，
 * 下一次启动就加载不到功能包，界面落到「Disabled error code: 00329」。
 *
 * 这里只拦这两个目录下的普通文件；FeaturePackRestorer 自己解压用的
 * {@code *.zip} 临时包放行，避免影响启动补齐。
 */
public final class PackGuard {

    private static final String[] PACK_DIRS = {
            "/files/wx6_2.44/", "/files/x7_3.0/"};

    private static final String ZIP_SUFFIX = ".zip";

    private static final String LOG_BLOCKED = "pack delete blocked: ";

    private static boolean installed;

    private static final Set<String> LOGGED = ConcurrentHashMap.newKeySet();

    private PackGuard() {
    }

    public static synchronized void install(HookFramework framework) {
        if (installed) {
            return;
        }
        try {
            Class<?> fileClass = framework.findClassIfExists("java.io.File", null);
            if (fileClass == null) {
                return;
            }
            framework.hookMethod(fileClass, "delete", new Class<?>[]{}, new Callback());
            installed = true;
            ModuleLogger.log("pack guard installed: File.delete");
        } catch (Throwable error) {
            framework.log(error);
        }
    }

    private static final class Callback implements HookCallback {

        @Override
        public void before(HookParam param) {
            Object target = param.thisObject();
            if (!(target instanceof File file)) {
                return;
            }
            String path = file.getAbsolutePath().replace('\\', '/');
            if (path.endsWith(ZIP_SUFFIX)) {
                return;
            }
            for (String dir : PACK_DIRS) {
                if (path.contains(dir)) {
                    if (LOGGED.add(path)) {
                        ModuleLogger.log(LOG_BLOCKED + path);
                    }
                    param.setResult(Boolean.FALSE);
                    return;
                }
            }
        }
    }
}
