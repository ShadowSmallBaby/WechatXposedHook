package github.shadowbaby.wechatxposed.hook.loader;

import github.shadowbaby.wechatxposed.hook.deploy.StartupCheck;

/**
 * 微X 传来的登录账号。
 *
 * 微X 每次校验授权都会把登录账号交给 hook(msgId 132 的 expectedUser、功能查询的 userId),
 * 这里转给启动自检,按这个账号补一次授权库——写库必须在微信进程里用真实账号,
 * 猜一个 wxid 写出来的库,微X 的 "SELECT * FROM DATA WHERE ACCOUNT=?" 读不到。
 */
public abstract class CurrentAccount {

    /** String.valueOf(null) 的结果,用它挡掉还没拿到账号时的占位值。 */
    private static final String NULL_TEXT = "null";

    /** 微X 交来账号时补一次授权库;空值忽略。 */
    public static void remember(String value) {
        if (value != null && !value.isEmpty() && !NULL_TEXT.equals(value)) {
            StartupCheck.ensureLicense(value);
        }
    }

}
