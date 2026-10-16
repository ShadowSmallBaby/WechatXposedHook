package github.shadowbaby.wechatxposed.hook.license;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * 微X 授权库(FKZ_WX_DATA)里每个账号要写的 10 行数据。
 *
 * 取值依据(见 docs/reverse-engineering.md 第二节、docs/fkz-wx-data-crypto.md):
 *   - ACCOUNT 必须等于登录账号,否则微X 那条 "SELECT * FROM DATA WHERE ACCOUNT=? AND TAG=?"
 *     整表读不到 → 设置界面能开、功能菜单为空;
 *   - LIC 必须正好 3 段 `blob#f#seg3`:blob 解出 "LIC:<账号>" 供 hook 比对,
 *     seg3 的 key 是 SHA-256(该账号),必须按账号现算——照抄别的账号的段 3 会解出乱码;
 *   - verifier6 同理,blob 编码 "verifier6#D:<账号>";
 *   - 所有值先用微X 的第一层 AES-256-CBC(零 IV、PKCS7)加密,再 Base64。
 *
 * 其余 8 行是让微X 正常启动并显示 [VIP][专业] 的最小集合,与设备上已被接受的库逐字节一致。
 */
public final class LicenseData {

    /** 第一层 AES-256 密钥。 */
    private static final String AES_KEY_HEX =
            "31d019ea56d574133508b10d944b413c4fb9eb58a90e1a015c62729f7459c66d";

    /** 第一层固定零 IV。 */
    private static final byte[] ZERO_IV = new byte[16];

    private static final String AES_TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final String AES_ALGORITHM = "AES";
    private static final String SHA_256 = "SHA-256";

    private static final String TYPE_BOOLEAN = "BOOLEAN";
    private static final String TYPE_INT = "INT";
    private static final String TYPE_JSON = "JSON";
    private static final String TYPE_STRING = "STRING";

    private static final String FALSE_TEXT = "false";
    private static final String TRUE_TEXT = "true";

    /** 版本号基线,与设备上可用库一致;微X 用它判断功能包是否需要更新。 */
    private static final String LATEST_VERSIONS =
            "{\"fp_themes\":\"71\",\"fp_sf\":\"4b\",\"fp_af\":\"ab\",\"fp_vidurlparser\":\"1e\","
          + "\"fp_mf\":\"89\",\"fp_donation\":\"47\",\"fp_xv\":\"1f2\",\"fp_base\":\"20d\","
          + "\"meta\":\"1902dffe702\",\"string\":\"18fe3f447ec\",\"h_p\":\"18eec2d7db3\","
          + "\"lib\":\"9\",\"core\":\"cf\",\"apk\":\"42,2.2,821452f9\"}";

    /** 各功能包版本号。 */
    private static final String FP_VERSIONS = "{\"themes\":113,\"donation\":71,\"base\":525}";

    /** 当前生效的功能包。 */
    private static final String FP = "themes";

    /** 后台异步更新的功能包。 */
    private static final String FP_ASYNC = "base,donation";

    /** LIC 段 3 解密后的明文:授权档位。 */
    private static final String LICENSE_FEATURE_SET = "[1]";

    private static final String FIELD_SEPARATOR = "#";
    private static final String USER_SEPARATOR = ":";
    private static final String LICENSE_SEGMENT_FLAG = "f";
    private static final String LICENSE_TAG = "LIC";
    private static final String VERIFIER6_TAG = "verifier6";
    private static final String VERIFIER6_FLAG = "D";

    /** LIC 段数必须正好 3,微X 的 getLicData 按 "#" 切分后取第 3 段。 */
    private static final int LICENSE_SEGMENTS = 3;

    private LicenseData() {
    }

    /** 一个账号要写进 DATA 表的 10 行。 */
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

    /**
     * 生成账号对应的 10 行。
     *
     * 生成 LIC 段 3 后立刻按微X 的解密路径复算一次,算不回去说明段 3 与账号不匹配,
     * 直接抛异常而不是写出一份会让微X 判定未授权的库。
     */
    public static List<Row> rows(String account) {
        String segment3 = licenseSegment3(account);
        if (!LICENSE_FEATURE_SET.equals(decodeSegment3(segment3, account))) {
            throw new IllegalStateException("LIC 第 3 段自检失败: " + account);
        }

        String license = encryptValue(encodeBlob(LICENSE_TAG + USER_SEPARATOR + account)
                + FIELD_SEPARATOR + LICENSE_SEGMENT_FLAG + FIELD_SEPARATOR + segment3);
        String verifier6 = encryptValue(encodeBlob(verifier6Payload(account)));

        List<Row> rows = new ArrayList<>(10);
        rows.add(new Row("hookFail", TYPE_BOOLEAN, encryptValue(FALSE_TEXT)));
        rows.add(new Row("disclaimer_disable", TYPE_BOOLEAN, encryptValue(TRUE_TEXT)));
        rows.add(new Row("is_new_user", TYPE_INT, encryptValue("10")));
        rows.add(new Row("LatestVersions", TYPE_JSON, encryptValue(LATEST_VERSIONS)));
        rows.add(new Row("FPVersions", TYPE_JSON, encryptValue(FP_VERSIONS)));
        rows.add(new Row("valid", TYPE_BOOLEAN, encryptValue(TRUE_TEXT)));
        rows.add(new Row("fp", TYPE_STRING, encryptValue(FP)));
        rows.add(new Row("fp_async", TYPE_STRING, encryptValue(FP_ASYNC)));
        rows.add(new Row(LICENSE_TAG, TYPE_STRING, license));
        rows.add(new Row(VERIFIER6_TAG, TYPE_STRING, verifier6));
        return rows;
    }

    /**
     * 库里已有的 LIC 是不是这个账号的:blob 解出 "LIC:<账号>",正好 3 段,
     * 且第 3 段能用该账号的 key 解开。都满足就不要动它——设备上厂商发的 LIC
     * 与本模块生成的等价,覆盖没有收益。
     */
    static boolean isUsableLicense(String stored, String account) {
        try {
            String[] segments = decryptValue(stored).split(FIELD_SEPARATOR, -1);
            return segments.length == LICENSE_SEGMENTS
                    && (LICENSE_TAG + USER_SEPARATOR + account).equals(decodeBlob(segments[0]))
                    && LICENSE_FEATURE_SET.equals(decodeSegment3(segments[2], account));
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** 库里已有的 verifier6 是不是这个账号的;标记位按微X 自己的取值(实测有 D 与 A),不限定。 */
    static boolean isUsableVerifier6(String stored, String account) {
        try {
            String decoded = decodeBlob(decryptValue(stored));
            return decoded.startsWith(VERIFIER6_TAG + FIELD_SEPARATOR)
                    && decoded.endsWith(USER_SEPARATOR + account);
        } catch (RuntimeException e) {
            return false;
        }
    }

    private static String verifier6Payload(String account) {
        return VERIFIER6_TAG + FIELD_SEPARATOR + VERIFIER6_FLAG + USER_SEPARATOR + account;
    }

    /** LIC 第三段:key = SHA-256(账号) 原文摘要,AES/CBC/PKCS7、零 IV,再 Base64。 */
    static String licenseSegment3(String account) {
        byte[] key = sha256(account);
        return Base64.getEncoder().encodeToString(
                aes(Cipher.ENCRYPT_MODE, key, LICENSE_FEATURE_SET.getBytes(StandardCharsets.UTF_8)));
    }

    /** licenseSegment3 的逆运算,只用于自检。 */
    static String decodeSegment3(String segment3, String account) {
        byte[] key = sha256(account);
        byte[] plain = aes(Cipher.DECRYPT_MODE, key, Base64.getDecoder().decode(segment3));
        return new String(plain, StandardCharsets.UTF_8);
    }

    /** 第一层加密:AES-256-CBC、零 IV、PKCS7,再 Base64。 */
    static String encryptValue(String plain) {
        byte[] key = hexToBytes(AES_KEY_HEX);
        return Base64.getEncoder().encodeToString(
                aes(Cipher.ENCRYPT_MODE, key, plain.getBytes(StandardCharsets.UTF_8)));
    }

    /** 第一层解密,只用于判断库里已有的值能不能用。 */
    static String decryptValue(String encrypted) {
        byte[] key = hexToBytes(AES_KEY_HEX);
        byte[] plain = aes(Cipher.DECRYPT_MODE, key, Base64.getDecoder().decode(encrypted));
        return new String(plain, StandardCharsets.UTF_8);
    }

    /**
     * 把 "LIC:<账号>" 编成数字串(每段「一位长度前缀 + 数字」),
     * 与 CallMethodBypassHook.decodeLicenseBlob 的解码相反。
     */
    static String encodeBlob(String plain) {
        int length = plain.length();
        StringBuilder packed = new StringBuilder();
        for (int index = 0; index < length; index++) {
            int base = (plain.charAt(index) << 2) - ((index << 2) + length);
            int shifted = -1;
            for (int delta = 0; delta < 4; delta++) {
                if (base + delta >= 0) {
                    shifted = (base + delta) ^ (index * index);
                    break;
                }
            }
            if (shifted < 0) {
                throw new IllegalArgumentException("字符超出可编码范围: " + plain);
            }
            String digits = Integer.toString(shifted);
            packed.append(digits.length()).append(digits);
        }
        return Base64.getEncoder().encodeToString(packed.toString().getBytes(StandardCharsets.UTF_8));
    }

    /** encodeBlob 的逆运算,与 CallMethodBypassHook.decodeLicenseBlob 一致。 */
    static String decodeBlob(String encoded) {
        String packed = new String(Base64.getDecoder().decode(encoded), StandardCharsets.UTF_8);
        List<Integer> numbers = new ArrayList<>();
        int index = 0;
        while (index < packed.length()) {
            int digits = Character.getNumericValue(packed.charAt(index));
            int start = index + 1;
            int end = start + digits;
            if (digits > 0 && end <= packed.length()) {
                numbers.add(Integer.parseInt(packed.substring(start, end)));
            }
            index += digits > 0 ? digits + 1 : 1;
        }
        StringBuilder decoded = new StringBuilder(numbers.size());
        for (int i = 0; i < numbers.size(); i++) {
            decoded.append((char) ((((i << 2) + numbers.size()) + (numbers.get(i) ^ (i * i))) >> 2));
        }
        return decoded.toString();
    }

    private static byte[] aes(int mode, byte[] key, byte[] input) {
        try {
            Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
            cipher.init(mode, new SecretKeySpec(key, AES_ALGORITHM), new IvParameterSpec(ZERO_IV));
            return cipher.doFinal(input);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES 失败", e);
        }
    }

    private static byte[] sha256(String text) {
        try {
            return MessageDigest.getInstance(SHA_256).digest(text.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA-256 不可用", e);
        }
    }

    private static byte[] hexToBytes(String hex) {
        byte[] bytes = new byte[hex.length() / 2];
        for (int index = 0; index < bytes.length; index++) {
            bytes[index] = (byte) Integer.parseInt(hex.substring(index * 2, index * 2 + 2), 16);
        }
        return bytes;
    }
}
