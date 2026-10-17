package github.shadowbaby.wechatxposed.hook.license;

import java.util.ArrayList;
import java.util.List;
import github.shadowbaby.wechatxposed.hook.loader.Secret;
import github.shadowbaby.wechatxposed.hook.loader.SecretConstants;

public final class LicenseData {

    private static final String LATEST_VERSIONS = Secret.of(SecretConstants.LATEST_VERSIONS);

    private static final String FP_VERSIONS = Secret.of(SecretConstants.FP_VERSIONS);

    private static final String FP = Secret.of(SecretConstants.FP);

    private static final String FP_ASYNC = Secret.of(SecretConstants.FP_ASYNC);

    private LicenseData() {
    }

    public static final class Row {

        public final String tag;
        public final String type;
        public final String value;

        Row(String tag, String type, String value) {
            this.tag = tag;
            this.type = type;
            this.value = value;
        }
    }

    public static List<Row> rows(String account) {
        String[] raw = LicenseCrypto.rows(account, LATEST_VERSIONS, FP_VERSIONS, FP, FP_ASYNC);
        if (raw == null) {
            throw new IllegalStateException("license rows unavailable: " + account);
        }
        List<Row> rows = new ArrayList<>(raw.length);
        for (String item : raw) {
            String[] parts = item.split("\n", 3);
            rows.add(new Row(parts[0], parts[1], parts[2]));
        }
        return rows;
    }

    static boolean isUsableLicense(String stored, String account) {
        return LicenseCrypto.isUsable(stored, account, LicenseCrypto.TAG_LICENSE);
    }

    static boolean isUsableVerifier6(String stored, String account) {
        return LicenseCrypto.isUsable(stored, account, LicenseCrypto.TAG_VERIFIER6);
    }
}
