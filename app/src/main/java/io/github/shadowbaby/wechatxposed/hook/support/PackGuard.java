package io.github.shadowbaby.wechatxposed.hook.support;

import io.github.shadowbaby.wechatxposed.shared.hook.HookCallback;
import io.github.shadowbaby.wechatxposed.shared.hook.HookFramework;
import io.github.shadowbaby.wechatxposed.shared.hook.HookParam;
import io.github.shadowbaby.wechatxposed.hook.loader.ModuleLogger;
import java.io.File;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;


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
        } catch (Throwable error) {
            framework.log(error);
        }
    }

    private static final class Callback implements HookCallback {

        @Override
        public void before(HookParam param) {
            if (PackIntegrity.isRepairing()) {
                return;
            }
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
