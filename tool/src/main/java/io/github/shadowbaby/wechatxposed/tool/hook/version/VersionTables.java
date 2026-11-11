package io.github.shadowbaby.wechatxposed.tool.hook.version;

import static io.github.shadowbaby.wechatxposed.tool.hook.spoof.HostFingerprint.fp;


public final class VersionTables {

    public static final int CALL = 2;
    public static final int MINI_PROGRAM = 3;
    public static final int WALLET_URI = 4;
    public static final int WALLET_CLASS = 5;
    public static final int LOGIN = 7;
    public static final int LOGIN_PAD = 8;


    public static final int TARGET_VERSION = 0x28004F30;

    private static final String[] CALL_TABLE = {

            fp("version.routes.callTable.getonlineinfo"),
            fp("version.routes.callTable.voipilink"), fp("version.routes.callTable.voipinvite"), fp("version.routes.callTable.getfriendringback"),
            fp("version.routes.callTable.mmilinktransfer"), fp("version.routes.callTable.voipspeedtest"), fp("version.routes.callTable.voipshutdown"),
    };


    private static final String[] MINI_PROGRAM_TABLE = {
            fp("version.routes.miniProgramTable.cgiBinMmbizBinWxaattrLaunchwxaapp"),

            fp("version.routes.miniProgramTable.cgiBinMmbizBinWxaattrWxajsapiinfo"),
    };

    private static final String[] WALLET_URI_TABLE = {
            fp("version.routes.walletUriTable.mmpay"), fp("version.routes.walletUriTable.tenpay"), fp("version.routes.walletUriTable.wallet"), fp("version.routes.walletUriTable.remit"), fp("version.routes.walletUriTable.transfer"),
            fp("version.routes.walletUriTable.redpacket"), fp("version.routes.walletUriTable.lucky"), fp("version.routes.walletUriTable.hongbao"),
    };

    private static final String[] WALLET_CLASS_TABLE = {
            fp("version.routes.walletClassTable.wallet"), fp("version.routes.walletClassTable.mmpay"), fp("version.routes.walletClassTable.tenpay"), fp("version.routes.walletClassTable.remit"), fp("version.routes.walletClassTable.kinda"),
            fp("version.routes.walletClassTable.redpacket"), fp("version.routes.walletClassTable.hongbao"), fp("version.routes.walletClassTable.lucky"), fp("version.routes.walletClassTable.pluginPay"), fp("version.routes.walletClassTable.pluginHb"),
    };

    private static final String[] LOGIN_TABLE = {
            fp("version.routes.loginTable.manualauth"),
    };


    private static final String[] LOGIN_PAD_TABLE = {
            fp("version.routes.loginPadTable.checkloginaspad"),
            fp("version.routes.loginPadTable.getloginqrcode"),
            fp("version.routes.loginPadTable.checkloginqrcode"),

            fp("version.routes.loginPadTable.autoauth"),
    };

    private VersionTables() {
    }

    public static boolean match(int kind, String value) {
        if (value == null || value.isEmpty()) {
            return false;
        }
        String[] table = tableFor(kind);
        if (table == null) {
            return false;
        }
        for (String needle : table) {
            if (kind == MINI_PROGRAM ? value.equalsIgnoreCase(needle) : containsIgnoreCase(value, needle)) {
                return true;
            }
        }
        return false;
    }

    private static String[] tableFor(int kind) {
        return switch (kind) {
            case CALL -> CALL_TABLE;
            case MINI_PROGRAM -> MINI_PROGRAM_TABLE;
            case WALLET_URI -> WALLET_URI_TABLE;
            case WALLET_CLASS -> WALLET_CLASS_TABLE;
            case LOGIN -> LOGIN_TABLE;
            case LOGIN_PAD -> LOGIN_PAD_TABLE;
            default -> null;
        };
    }

    private static boolean containsIgnoreCase(String haystack, String needle) {
        int needleLength = needle.length();
        int limit = haystack.length() - needleLength;
        for (int start = 0; start <= limit; start++) {
            if (haystack.regionMatches(true, start, needle, 0, needleLength)) {
                return true;
            }
        }
        return false;
    }
}
