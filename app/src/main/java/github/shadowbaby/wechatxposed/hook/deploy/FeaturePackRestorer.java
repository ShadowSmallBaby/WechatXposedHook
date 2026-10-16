package github.shadowbaby.wechatxposed.hook.deploy;

import github.shadowbaby.wechatxposed.hook.loader.ModuleLogger;
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
 * 功能包目录(wx6_2.44)的自检与补齐。
 *
 * 微X 把功能包放在微信的 files/wx6_2.44 下,文件名就是内容指纹。授权判定失败时微X 会自己
 * 删掉其中一部分(实测会删掉 Base / Donation / Themes 三个包,只留 _c / _s 边车文件),
 * 之后功能菜单就是空的;而恢复必须拿回原样的加密文件,自己重新生成没用——
 * 微X 会用 _c 校验块与 _s 签名块验它们。
 *
 * 所以整套 30 个文件(含三组 _c / _s)内置在模块 APK 的 assets/wx6_2.44.zip 里,
 * 启动时按清单检查缺哪个补哪个。清单就是这一套文件的名字与字节数:
 * 文件名是内容指纹,大小对不上说明文件被换过,同样按缺失处理。
 *
 * 选文件级检测而不是追微X 的失败事件:清理发生在微X 自己的代码里,等它报错或删完再反应就晚了,
 * 而「文件在不在、大小对不对」是幂等的,任何一次启动都能把状态拉回来。
 */
public abstract class FeaturePackRestorer {

    /** 功能包目录,相对微信 files 目录。 */
    private static final String DIR_NAME = "wx6_2.44";

    /** 内置载荷:模块 APK 的 assets/wx6_2.44.zip,里面是下面这份清单的全部文件。 */
    private static final String PAYLOAD = "wx6_2.44.zip";

    /** 清单:文件名 -> 字节数(文件名即内容指纹)。 */
    private static final String[] NAMES = {
            "14e777717682cce8a53cfcb34a22d65", "14e777717682cce8a53cfcb34a22d65_c",
            "14e777717682cce8a53cfcb34a22d65_s", "24ce1c66be23f9c731fb2db3a76954",
            "36a76b97b96b5d46742bb4bcd2ff24d", "36a76b97b96b5d46742bb4bcd2ff24d_c",
            "36a76b97b96b5d46742bb4bcd2ff24d_s", "44c29edb103a2872f519adc9afdaaa",
            "534a9729a0c461cbd7a4379978fb742", "55bcfe849748f60697e2b1e191321b3",
            "5dbc98dcc983a7728bd82d1a47546e", "62a4e566b714ea1c4349923c9ea6c35",
            "69691c7bdcc3ce6d5d8a1361f22d4ac", "6d6586c9c5458ecfc98981b52ee662de",
            "739440c5d87b2b8095b99f9d2a1bbf9", "7e72d95130d766517ea69c215f38ddd",
            "802766a4a4bd401c145a57463274d4dd", "802766a4a4bd401c145a57463274d4dd_c",
            "802766a4a4bd401c145a57463274d4dd_s", "89d9d67db0a14fc9b040cf25a28ef71",
            "9816b5dfd637d3ce1473a9951b9e05", "a89eaf67dc796cb3af54d94fac0198b",
            "a89eaf67dc796cb3af54d94fac0198b_c", "a89eaf67dc796cb3af54d94fac0198b_s",
            "d61f837cad1d412f80b84d143e1257", "d61f837cad1d412f80b84d143e1257_backup_c",
            "d61f837cad1d412f80b84d143e1257_backup_s", "d61f837cad1d412f80b84d143e1257_c",
            "d61f837cad1d412f80b84d143e1257_s", "dc7be70f1898d3a58965a919740f97"};

    private static final long[] SIZES = {
            1035962L, 599L, 256L, 43048L, 528976L, 599L, 256L, 4568L, 1159L, 43240L,
            259018L, 48008L, 41352L, 43336L, 98264L, 42808L, 200890L, 599L, 256L, 42440L,
            352186L, 121466L, 599L, 256L, 347578L, 599L, 256L, 599L, 256L, 461560L};

    private static final int BUFFER_SIZE = 16 * 1024;

    private static final String LOG_INTACT = "feature packs: all " + NAMES.length + " intact";
    private static final String LOG_RESTORED_PREFIX = "feature packs: restored ";
    private static final String LOG_RESTORED_SUFFIX = " file(s) from payload";
    private static final String LOG_NO_DIR = "feature packs: cannot create dir ";
    private static final String LOG_NO_PAYLOAD = "feature packs: payload missing, skipped";
    private static final String LOG_BAD_PAYLOAD_PREFIX = "feature packs: payload lacks ";
    private static final String LOG_NOT_READABLE = "feature packs: cannot chmod ";
    private static final String LOG_NOT_DELETED = "feature packs: cannot delete temp payload ";

    /** 一个进程只查一次。 */
    private static boolean checked;

    /** 启动自检:清单里缺哪个补哪个;任何失败只记日志,不影响微X。 */
    public static synchronized void ensureOnce(File filesDir) {
        if (checked) {
            return;
        }
        checked = true;
        try {
            File directory = new File(filesDir, DIR_NAME);
            if (!directory.isDirectory() && !directory.mkdirs()) {
                ModuleLogger.log(LOG_NO_DIR + directory.getAbsolutePath());
                return;
            }
            List<String> missing = missingFiles(directory);
            if (missing.isEmpty()) {
                ModuleLogger.log(LOG_INTACT);
                return;
            }
            int restored = restore(directory, missing);
            if (restored > 0) {
                ModuleLogger.log(LOG_RESTORED_PREFIX + restored + LOG_RESTORED_SUFFIX);
            }
        } catch (Throwable error) {
            ModuleLogger.log(error);
        }
    }

    /** 清单里缺失或大小不符的文件名;空表示整套齐全。 */
    public static List<String> missingFiles(File directory) {
        List<String> missing = new ArrayList<>(NAMES.length);
        for (int index = 0; index < NAMES.length; index++) {
            File file = new File(directory, NAMES[index]);
            if (!file.isFile() || file.length() != SIZES[index]) {
                missing.add(NAMES[index]);
            }
        }
        return missing;
    }

    /** 从内置载荷里逐个取出缺失的文件;返回实际补写的数量。 */
    private static int restore(File directory, List<String> missing) throws IOException {
        File archive = new File(directory, PAYLOAD);
        if (!ModuleApk.extractPayload(PAYLOAD, archive)) {
            ModuleLogger.log(LOG_NO_PAYLOAD);
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
                // 与原来由脚本写进去的文件一样,同 uid 之外的进程也能读;失败不影响微X。
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
}
