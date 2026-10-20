package github.shadowbaby.wechatxposed.hook.license;

import java.io.File;
import github.shadowbaby.wechatxposed.hook.loader.ModuleLogger;

public final class LicenseInstaller {

    private static final String LABEL_CREATED = "created";
    private static final String LABEL_EXISTING = "existing";
    private static final String LOG_PREFIX = "license db: ";
    private static final String LOG_SUFFIX = ", restart microX to apply";

    private static final String LOG_READY = " ready";

    private static String installedAccount;

    private LicenseInstaller() {
    }

    public static synchronized void ensure(File database, String account) {
        if (account.equals(installedAccount)) {
            return;
        }
        try {
            LicenseDatabase.Result result = LicenseDatabase.ensure(database, account);
            installedAccount = account;
            ModuleLogger.debug(describe(account, database, result));
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
