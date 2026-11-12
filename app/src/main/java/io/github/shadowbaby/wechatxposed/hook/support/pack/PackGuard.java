package io.github.shadowbaby.wechatxposed.hook.support.pack;

import io.github.shadowbaby.wechatxposed.hook.BuildConfig;
import io.github.shadowbaby.wechatxposed.shared.hook.HookCallback;
import io.github.shadowbaby.wechatxposed.shared.hook.HookFramework;
import io.github.shadowbaby.wechatxposed.shared.hook.HookParam;
import io.github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import java.io.File;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public final class PackGuard {

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

        installed = true;
        try {
            Class<?> fileClass = framework.findClassIfExists("java.io.File", null);
            if (fileClass == null) {
                installed = false;
                return;
            }
            framework.hookMethod(fileClass, "delete", new Class<?>[]{}, new Callback());
            ModuleLogger.debug("pack guard installed: File.delete");
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
            String dir = BuildConfig.WX_PACK;
            if (dir.isEmpty() || !path.contains("/files/" + dir + "/")) {
                return;
            }
            if (LOGGED.add(path)) {
                ModuleLogger.log(LOG_BLOCKED + path);
            }
            param.setResult(Boolean.FALSE);
        }
    }
}
