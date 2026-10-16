package github.shadowbaby.wechatxposed.hook.license;

import java.io.File;
import github.shadowbaby.wechatxposed.hook.loader.ModuleLogger;

/**
 * 授权库的补齐动作:按账号写入/修复 databases/FKZ_WX_DATA。
 *
 * 目标是不再依赖设备上的 shell 脚本,也不需要菜单入口——启动自检拿到账号就直接写
 * (见 deploy.StartupCheck)。写入在微信进程内完成,微X 在本次启动里已经把旧内容读进内存,
 * 所以写完要重启微X(或微信)才生效。
 */
public final class LicenseInstaller {

    private static final String LABEL_CREATED = "created";
    private static final String LABEL_EXISTING = "existing";
    private static final String LOG_PREFIX = "license db: ";
    private static final String LOG_SUFFIX = ", restart microX to apply";

    /** 账号已经在库里、这次一行都不用改时的日志。 */
    private static final String LOG_READY = " ready";

    /** 已经成功写过库的账号;同一个账号不重复写。 */
    private static String installedAccount;

    private LicenseInstaller() {
    }

    /** 为账号写入/修复授权库;同一个账号只写一次,失败不记,下次再试。 */
    public static synchronized void ensure(File database, String account) {
        if (account.equals(installedAccount)) {
            return;
        }
        try {
            LicenseDatabase.Result result = LicenseDatabase.ensure(database, account);
            installedAccount = account;
            ModuleLogger.log(describe(account, database, result));
        } catch (Throwable error) {
            ModuleLogger.log(error);
        }
    }

    private static String describe(String account, File database, LicenseDatabase.Result result) {
        if (result.inserted == 0 && result.refreshed == 0) {
            return LOG_PREFIX + account + LOG_READY;
        }
        return LOG_PREFIX + account + " -> " + database.getAbsolutePath()
                + " (" + (result.created ? LABEL_CREATED : LABEL_EXISTING)
                + ", inserted " + result.inserted + ", refreshed " + result.refreshed
                + ", kept " + result.kept + ")"
                + LOG_SUFFIX;
    }
}
