package github.shadowbaby.wechatxposed.hook.loader;

import github.shadowbaby.wechatxposed.hook.deploy.StartupCheck;

public abstract class CurrentAccount {

    private static final String NULL_TEXT = "null";

    public static void remember(String value) {
        if (value != null && !value.isEmpty() && !NULL_TEXT.equals(value)) {
            StartupCheck.ensureLicense(value);
        }
    }

}
