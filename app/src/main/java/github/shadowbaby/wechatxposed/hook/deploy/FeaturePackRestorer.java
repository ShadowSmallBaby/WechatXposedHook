package github.shadowbaby.wechatxposed.hook.deploy;

import github.shadowbaby.wechatxposed.hook.BuildConfig;
import github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import github.shadowbaby.wechatxposed.hook.loader.util.Secret;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * 按 native 清单补齐功能包。
 *
 * 运行目录、基础包与扩展包的文件名/长度、扩展包别名都由
 * `Secret.restorePlan()` 提供，Java 不保留明文清单。
 */
public abstract class FeaturePackRestorer {

    private static final int BUFFER_SIZE = 16 * 1024;

    /**
     * 存在该标记时跳过补齐，避免覆盖运行时目录里的新包。
     */
    private static final String SKIP_MARKER = "wxh_skip_restore";

    /** APK versionCode 写在这里；版本变化时强制重写全部功能包（含 _c/_s）。 */
    private static final String VERSION_MARKER = "wxh_pack_version";

    private static final String LOG_SKIPPED = "feature packs: restore skipped by marker";

    private static final String LOG_NO_DIR = "feature packs: cannot create dir ";
    private static final String LOG_NOT_READABLE = "feature packs: cannot chmod ";

    /** 包清单由 native 生成：role|dir|name|size|...;alias|from|to|...。 */
    private static final String RESTORE_PLAN =
            Secret.restorePlan(BuildConfig.FULL_EDITION);

    private static final Pack[] PACKS = parsePacks(RESTORE_PLAN);

    private static final String[][] ALIASES = parseAliases(RESTORE_PLAN);

    private static final Pack BASE_PACK = PACKS.length == 0 ? null : PACKS[0];

    private static boolean checked;

    public static synchronized void ensureOnce(File filesDir) {
        if (checked) {
            return;
        }
        checked = true;
        if (PACKS.length == 0) {
            ModuleLogger.log("feature packs: native plan unavailable");
            return;
        }
        if (new File(filesDir, SKIP_MARKER).isFile()) {
            ModuleLogger.debug(LOG_SKIPPED);
            return;
        }
        boolean force = !matchesVersion(filesDir);
        for (Pack pack : PACKS) {
            ensure(filesDir, pack, force);
        }
        if (force) {
            writeVersion(filesDir);
        }
    }

    private static boolean matchesVersion(File filesDir) {
        if (BASE_PACK == null) {
            return false;
        }
        File marker = new File(new File(filesDir, BASE_PACK.dirName), VERSION_MARKER);
        if (!marker.isFile()) {
            return false;
        }
        try (InputStream input = new FileInputStream(marker)) {
            byte[] buffer = new byte[32];
            int read = input.read(buffer);
            if (read <= 0) {
                return false;
            }
            String value = new String(buffer, 0, read, java.nio.charset.StandardCharsets.UTF_8);
            return String.valueOf(BuildConfig.VERSION_CODE).equals(value.trim());
        } catch (Throwable error) {
            return false;
        }
    }

    private static void writeVersion(File filesDir) {
        if (BASE_PACK == null) {
            return;
        }
        File directory = new File(filesDir, BASE_PACK.dirName);
        if (!directory.isDirectory() && !directory.mkdirs()) {
            return;
        }
        try (OutputStream output = new FileOutputStream(new File(directory, VERSION_MARKER))) {
            output.write(String.valueOf(BuildConfig.VERSION_CODE)
                    .getBytes(java.nio.charset.StandardCharsets.UTF_8));
        } catch (Throwable error) {
            ModuleLogger.log(error);
        }
    }

    public static List<String> missingFiles(File directory) {
        if (BASE_PACK == null) {
            return new ArrayList<>();
        }
        return missingFiles(directory, BASE_PACK);
    }

    /** 当前 APK 对应的运行时目录名。 */
    public static String packDirName() {
        return BASE_PACK == null ? "" : BASE_PACK.dirName;
    }

    private static void ensure(File filesDir, Pack pack, boolean force) {
        try {
            File directory = new File(filesDir, pack.dirName);
            if (!directory.isDirectory() && !directory.mkdirs()) {
                ModuleLogger.log(LOG_NO_DIR + directory.getAbsolutePath());
                return;
            }
            List<String> missing = force
                    ? new ArrayList<>(Arrays.asList(pack.names))
                    : missingFiles(directory, pack);
            if (missing.isEmpty()) {
                ModuleLogger.debug("feature packs[" + pack.name + "]: all "
                        + pack.names.length + " intact");
            } else {
                int restored = restore(directory, pack, missing);
                if (restored > 0) {
                    ModuleLogger.log("feature packs[" + pack.name + "]: restored " + restored
                            + " file(s) from assets");
                }
            }
            if (pack != BASE_PACK) {
                ensureAliases(directory);
            }
        } catch (Throwable error) {
            ModuleLogger.log(error);
        }
    }

    /** 第二套命名与主文件内容一致；主文件在时直接拷贝一份。 */
    private static void ensureAliases(File directory) {
        for (String[] pair : ALIASES) {
            if (pair == null || pair.length < 2) {
                continue;
            }
            File source = new File(directory, pair[0]);
            File alias = new File(directory, pair[1]);
            if (!source.isFile() || alias.length() == source.length()) {
                continue;
            }
            try (InputStream input = new FileInputStream(source);
                    OutputStream output = new FileOutputStream(alias)) {
                byte[] buffer = new byte[BUFFER_SIZE];
                int read;
                while ((read = input.read(buffer)) > 0) {
                    output.write(buffer, 0, read);
                }
                alias.setReadable(true, false);
            } catch (Throwable error) {
                ModuleLogger.log(error);
            }
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
        int restored = 0;
        for (String name : missing) {
            if (restoreMerged(directory, pack.dirName, name)) {
                restored++;
                continue;
            }
            File target = new File(directory, name);
            if (ModuleApk.copyAsset(name, target)
                    || ModuleApk.copyAsset(pack.dirName + "/" + name, target)) {
                if (!target.setReadable(true, false)) {
                    ModuleLogger.log(LOG_NOT_READABLE + name);
                }
                restored++;
            } else {
                ModuleLogger.log("feature packs: asset missing " + name);
            }
        }
        return restored;
    }

    /** 平铺资产里的 WXH1 容器：body + _c + _s 合一，运行时拆开写盘。 */
    private static boolean restoreMerged(File directory, String dirName, String name) {
        String base = name;
        if (name.endsWith("_c") || name.endsWith("_s")) {
            base = name.substring(0, name.length() - 2);
        }
        byte[] data = ModuleApk.readAsset(base);
        if (data == null) {
            data = ModuleApk.readAsset(dirName + "/" + base);
        }
        if (data == null || data.length < 16
                || data[0] != 'W' || data[1] != 'X'
                || data[2] != 'H' || data[3] != '1') {
            return false;
        }
        int bodySize = readInt(data, 4);
        int sidecarSize = readInt(data, 8);
        int signatureSize = readInt(data, 12);
        if (bodySize < 0 || sidecarSize < 0 || signatureSize < 0
                || 16L + bodySize + sidecarSize + signatureSize != data.length) {
            return false;
        }
        try {
            int offset = 16;
            writePart(directory, base, data, offset, bodySize);
            offset += bodySize;
            if (sidecarSize > 0) {
                writePart(directory, base + "_c", data, offset, sidecarSize);
                offset += sidecarSize;
            }
            if (signatureSize > 0) {
                writePart(directory, base + "_s", data, offset, signatureSize);
            }
            return true;
        } catch (IOException error) {
            ModuleLogger.log(error);
            return false;
        }
    }

    private static void writePart(File directory, String name, byte[] data,
            int offset, int length) throws IOException {
        File target = new File(directory, name);
        try (OutputStream output = new FileOutputStream(target)) {
            output.write(data, offset, length);
        }
        if (!target.setReadable(true, false)) {
            ModuleLogger.log(LOG_NOT_READABLE + name);
        }
    }

    private static int readInt(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 24)
                | ((data[offset + 1] & 0xFF) << 16)
                | ((data[offset + 2] & 0xFF) << 8)
                | (data[offset + 3] & 0xFF);
    }

    private static Pack[] parsePacks(String plan) {
        if (plan == null || plan.isEmpty()) {
            return new Pack[0];
        }
        List<Pack> packs = new ArrayList<>();
        for (String section : plan.split(";")) {
            String[] parts = section.split("\\|");
            if (parts.length < 4 || "alias".equals(parts[0])) {
                continue;
            }
            int count = (parts.length - 2) / 2;
            String[] names = new String[count];
            long[] sizes = new long[count];
            try {
                for (int index = 0; index < count; index++) {
                    names[index] = parts[2 + index * 2];
                    sizes[index] = Long.parseLong(parts[3 + index * 2]);
                }
            } catch (NumberFormatException error) {
                continue;
            }
            packs.add(new Pack(parts[0], parts[1], names, sizes));
        }
        return packs.toArray(new Pack[0]);
    }

    private static String[][] parseAliases(String plan) {
        if (plan == null || plan.isEmpty()) {
            return new String[0][];
        }
        for (String section : plan.split(";")) {
            String[] parts = section.split("\\|");
            if (parts.length < 3 || !"alias".equals(parts[0])) {
                continue;
            }
            int count = (parts.length - 1) / 2;
            String[][] aliases = new String[count][2];
            for (int index = 0; index < count; index++) {
                aliases[index][0] = parts[1 + index * 2];
                aliases[index][1] = parts[2 + index * 2];
            }
            return aliases;
        }
        return new String[0][];
    }

    private static final class Pack {

        final String name;
        final String dirName;
        final String[] names;
        final long[] sizes;

        Pack(String name, String dirName, String[] names, long[] sizes) {
            this.name = name;
            this.dirName = dirName;
            this.names = names;
            this.sizes = sizes;
        }
    }
}
