package github.shadowbaby.wechatxposed.hook.deploy;

import github.shadowbaby.wechatxposed.hook.BuildConfig;
import github.shadowbaby.wechatxposed.hook.loader.ModuleLogger;
import github.shadowbaby.wechatxposed.hook.loader.Secret;
import github.shadowbaby.wechatxposed.hook.loader.SecretConstants;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * 按清单补齐功能包。
 *
 * 每个 APK 只处理对应版本的运行时目录:
 *   - 微X 2.44: files/wx6_2.44, 基础包 26 / 扩展包 3
 *   - X 3.0: files/x7_3.0, 基础包 26 / 扩展包 3
 */
public abstract class FeaturePackRestorer {

    private static final int BUFFER_SIZE = 16 * 1024;

    /**
     * 存在该标记时跳过补齐，避免覆盖运行时目录里的新包。
     */
    private static final String SKIP_MARKER = "wxh_skip_restore";

    private static final String LOG_SKIPPED = "feature packs: restore skipped by marker";

    private static final String LOG_NO_DIR = "feature packs: cannot create dir ";
    private static final String LOG_NO_PAYLOAD = "feature packs: payload missing, skipped";
    private static final String LOG_BAD_PAYLOAD_PREFIX = "feature packs: payload lacks ";
    private static final String LOG_NOT_READABLE = "feature packs: cannot chmod ";
    private static final String LOG_NOT_DELETED = "feature packs: cannot delete temp payload ";

    private static final String[] V24_BASE_NAMES = {
            "14e777717682cce8a53cfcb34a22d65", "14e777717682cce8a53cfcb34a22d65_c",
            "14e777717682cce8a53cfcb34a22d65_s",
            "36a76b97b96b5d46742bb4bcd2ff24d", "36a76b97b96b5d46742bb4bcd2ff24d_c",
            "36a76b97b96b5d46742bb4bcd2ff24d_s", "44c29edb103a2872f519adc9afdaaa",
            "534a9729a0c461cbd7a4379978fb742",
            "5dbc98dcc983a7728bd82d1a47546e", "62a4e566b714ea1c4349923c9ea6c35",
            "69691c7bdcc3ce6d5d8a1361f22d4ac", "6d6586c9c5458ecfc98981b52ee662de",
            "739440c5d87b2b8095b99f9d2a1bbf9",
            "802766a4a4bd401c145a57463274d4dd", "802766a4a4bd401c145a57463274d4dd_c",
            "802766a4a4bd401c145a57463274d4dd_s",
            "a89eaf67dc796cb3af54d94fac0198b", "a89eaf67dc796cb3af54d94fac0198b_c",
            "a89eaf67dc796cb3af54d94fac0198b_s",
            "d61f837cad1d412f80b84d143e1257", "d61f837cad1d412f80b84d143e1257_c",
            "d61f837cad1d412f80b84d143e1257_s",
            "dc7be70f1898d3a58965a919740f97",
            "df4e6fd144fab2389ece8cb79eaa8f", "df4e6fd144fab2389ece8cb79eaa8f_c",
            "df4e6fd144fab2389ece8cb79eaa8f_s"};

    private static final long[] V24_BASE_SIZES = {
            1035962L, 599L, 256L,
            528976L, 599L, 256L, 4568L, 1159L,
            259018L, 48008L, 41352L, 43336L, 98264L,
            200890L, 599L, 256L,
            121466L, 599L, 256L,
            347578L, 599L, 256L,
            461560L,
            131050L, 599L, 256L};

    private static final String[] V24_EXT_NAMES = {
            "257f23e0175be13dec231373679bedc",
            "ec38a2b5b262d9c72f75edacb8875cfe",
            "ee06cd8f9beaf915a27b8bad9e8c2f"};

    private static final long[] V24_EXT_SIZES = {
            88670L, 151710L, 178558L};

    private static final String[] X30_BASE_NAMES = {
            "14e777717682cce8a53cfcb34a22d65", "14e777717682cce8a53cfcb34a22d65_c",
            "14e777717682cce8a53cfcb34a22d65_s",
            "36a76b97b96b5d46742bb4bcd2ff24d", "36a76b97b96b5d46742bb4bcd2ff24d_c",
            "36a76b97b96b5d46742bb4bcd2ff24d_s", "44c29edb103a2872f519adc9afdaaa",
            "534a9729a0c461cbd7a4379978fb742",
            "5dbc98dcc983a7728bd82d1a47546e", "62a4e566b714ea1c4349923c9ea6c35",
            "69691c7bdcc3ce6d5d8a1361f22d4ac",
            "6d6586c9c5458ecfc98981b52ee662de",
            "739440c5d87b2b8095b99f9d2a1bbf9",
            "802766a4a4bd401c145a57463274d4dd", "802766a4a4bd401c145a57463274d4dd_c",
            "802766a4a4bd401c145a57463274d4dd_s",
            "a89eaf67dc796cb3af54d94fac0198b", "a89eaf67dc796cb3af54d94fac0198b_c",
            "a89eaf67dc796cb3af54d94fac0198b_s",
            "d61f837cad1d412f80b84d143e1257", "d61f837cad1d412f80b84d143e1257_c",
            "d61f837cad1d412f80b84d143e1257_s",
            "df4e6fd144fab2389ece8cb79eaa8f",
            "df4e6fd144fab2389ece8cb79eaa8f_c",
            "df4e6fd144fab2389ece8cb79eaa8f_s",
            "dc7be70f1898d3a58965a919740f97"};

    private static final long[] X30_BASE_SIZES = {
            994250L, 599L, 256L,
            597288L, 599L, 256L, 4568L, 1159L,
            258922L, 48008L, 41464L,
            43336L, 98264L,
            200554L, 599L, 256L,
            121962L, 599L, 256L,
            370042L, 599L, 256L,
            129498L, 599L, 256L,
            533080L};

    private static final String[] X30_EXT_NAMES = {
            "257f23e0175be13dec231373679bedc",
            "ec38a2b5b262d9c72f75edacb8875cfe",
            "ee06cd8f9beaf915a27b8bad9e8c2f"};

    private static final long[] X30_EXT_SIZES = {
            91594L, 148186L, 182538L};

    private static final String V24_EXT_PAYLOAD = "wx6_2.44_ext.zip";
    private static final String X30_EXT_PAYLOAD = "x7_3.0_ext.zip";

    private static final Pack V24_BASE = new Pack("v24",
            Secret.of(SecretConstants.FEATURE_DIR),
            Secret.of(SecretConstants.FEATURE_PAYLOAD),
            V24_BASE_NAMES, V24_BASE_SIZES);

    private static final Pack V24_EXT = new Pack("v24-ext",
            Secret.of(SecretConstants.FEATURE_DIR),
            V24_EXT_PAYLOAD, V24_EXT_NAMES, V24_EXT_SIZES);

    private static final Pack X30_BASE = new Pack("x30",
            "x7_3.0", "x7_3.0.zip", X30_BASE_NAMES, X30_BASE_SIZES);

    private static final Pack X30_EXT = new Pack("x30-ext",
            "x7_3.0", X30_EXT_PAYLOAD, X30_EXT_NAMES, X30_EXT_SIZES);

    /** 公开版只有基础包；full 额外补齐扩展包。 */
    private static final Pack[] PACKS = BuildConfig.WX_PACK.startsWith("wx6")
            ? (BuildConfig.FULL_EDITION
                    ? new Pack[]{V24_BASE, V24_EXT} : new Pack[]{V24_BASE})
            : (BuildConfig.FULL_EDITION
                    ? new Pack[]{X30_BASE, X30_EXT} : new Pack[]{X30_BASE});

    private static boolean checked;

    public static synchronized void ensureOnce(File filesDir) {
        if (checked) {
            return;
        }
        checked = true;
        if (new File(filesDir, SKIP_MARKER).isFile()) {
            ModuleLogger.log(LOG_SKIPPED);
            return;
        }
        for (Pack pack : PACKS) {
            ensure(filesDir, pack);
        }
    }

    public static List<String> missingFiles(File directory) {
        return missingFiles(directory, BuildConfig.WX_PACK.startsWith("wx6")
                ? V24_BASE : X30_BASE);
    }

    /** 当前 APK 对应的运行时目录名。 */
    public static String packDirName() {
        return BuildConfig.WX_PACK.startsWith("wx6")
                ? Secret.of(SecretConstants.FEATURE_DIR) : "x7_3.0";
    }

    /** 当前 APK 内置载荷的 zip 名。 */
    public static String payloadName() {
        return BuildConfig.WX_PACK.startsWith("wx6")
                ? Secret.of(SecretConstants.FEATURE_PAYLOAD) : "x7_3.0.zip";
    }

    /** full 版额外内置的扩展包 zip 名。 */
    public static String extPayloadName() {
        return BuildConfig.WX_PACK.startsWith("wx6")
                ? V24_EXT_PAYLOAD : X30_EXT_PAYLOAD;
    }

    private static void ensure(File filesDir, Pack pack) {
        try {
            File directory = new File(filesDir, pack.dirName);
            if (!directory.isDirectory() && !directory.mkdirs()) {
                ModuleLogger.log(LOG_NO_DIR + directory.getAbsolutePath());
                return;
            }
            List<String> missing = missingFiles(directory, pack);
            if (missing.isEmpty()) {
                ModuleLogger.log("feature packs[" + pack.name + "]: all "
                        + pack.names.length + " intact");
                return;
            }
            int restored = restore(directory, pack, missing);
            if (restored > 0) {
                ModuleLogger.log("feature packs[" + pack.name + "]: restored " + restored
                        + " file(s) from payload");
            }
        } catch (Throwable error) {
            ModuleLogger.log(error);
        }
    }

    private static List<String> missingFiles(File directory, Pack pack) {
        List<String> missing = new ArrayList<>(pack.names.length);
        for (int index = 0; index < pack.names.length; index++) {
            File file = new File(directory, pack.names[index]);
            if (!file.isFile() || file.length() != pack.sizes[index]) {
                missing.add(pack.names[index]);
            }
        }
        return missing;
    }

    private static int restore(File directory, Pack pack, List<String> missing)
            throws IOException {
        File archive = new File(directory, pack.payload);
        if (!ModuleApk.extractPayload(pack.payload, archive)) {
            ModuleLogger.log(LOG_NO_PAYLOAD + " [" + pack.name + "]");
            return 0;
        }
        int restored = 0;
        try (ZipFile payload = new ZipFile(archive)) {
            for (String name : missing) {
                ZipEntry entry = payload.getEntry(name);
                if (entry == null) {
                    ModuleLogger.log(LOG_BAD_PAYLOAD_PREFIX + name);
                    continue;
                }
                File target = new File(directory, name);
                try (InputStream input = payload.getInputStream(entry);
                        OutputStream output = new FileOutputStream(target)) {
                    byte[] buffer = new byte[BUFFER_SIZE];
                    int read;
                    while ((read = input.read(buffer)) > 0) {
                        output.write(buffer, 0, read);
                    }
                }
                if (!target.setReadable(true, false)) {
                    ModuleLogger.log(LOG_NOT_READABLE + name);
                }
                restored++;
            }
        } finally {
            if (!archive.delete()) {
                ModuleLogger.log(LOG_NOT_DELETED + archive.getName());
            }
        }
        return restored;
    }

    private static final class Pack {

        final String name;
        final String dirName;
        final String payload;
        final String[] names;
        final long[] sizes;

        Pack(String name, String dirName, String payload, String[] names, long[] sizes) {
            this.name = name;
            this.dirName = dirName;
            this.payload = payload;
            this.names = names;
            this.sizes = sizes;
        }
    }
}
