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
import java.security.MessageDigest;
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
    private static final String RESTORE_PLAN = Secret.restorePlan(true);

    private static final Pack[] PACKS = parsePacks(RESTORE_PLAN);

    private static final String[][] ALIASES = parseAliases(RESTORE_PLAN);

    private static final Pack BASE_PACK = PACKS.length == 0 ? null : PACKS[0];

    private static boolean checked;

    /** 上次跑的时候是否恢复了扩展包。账号晚到时先按未授权跑，之后要能补回来。 */
    private static boolean extensionsReady;

    public static synchronized void ensureOnce(File filesDir) {
        ensureOnce(filesDir, true);
    }

    /**
     * @param allowExtensions 普通/未授权时跳过并清掉扩展包（x30-ext），
     *                        否则壳扫描目录会加载 sf/mf/af。
     */
    public static synchronized void ensureOnce(File filesDir, boolean allowExtensions) {
        // 授权级别在启动早期可能还读不出来，先按未授权跑过一次之后，
        // 级别涨上来必须允许补恢复扩展包；否则壳扫目录时看不到 sf/mf/af。
        if (checked && (extensionsReady || !allowExtensions)) {
            return;
        }
        checked = true;
        extensionsReady = allowExtensions;
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
            if (!allowExtensions && pack.name.endsWith("-ext")) {
                purge(filesDir, pack);
                continue;
            }
            ensure(filesDir, pack, force);
        }
        if (force) {
            writeVersion(filesDir);
        }
    }

    /** 删除扩展包文件，避免壳扫描目录时继续加载。 */
    private static void purge(File filesDir, Pack pack) {
        File directory = new File(filesDir, pack.dirName);
        for (String name : pack.names) {
            File file = new File(directory, name);
            if (file.isFile()) {
                file.delete();
            }
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
            pruneSidecars(directory, pack);
        } catch (Throwable error) {
            ModuleLogger.log(error);
        }
    }

    /**
     * 新版容器不再带 _c/_s，但旧版留下的签名文件不会被上面的恢复覆盖；
     * 壳扫到「主文件 + 旧签名」会判定该包损坏，整批 fp 都不加载。
     */
    private static void pruneSidecars(File directory, Pack pack) {
        java.util.Set<String> bases = new java.util.LinkedHashSet<>();
        for (String name : pack.names) {
            bases.add(hasSuffix(name) ? name.substring(0, name.length() - 2) : name);
        }
        for (String base : bases) {
            if (!contains(pack.names, base + "_c")) {
                prune(directory, base + "_c");
            }
            if (!contains(pack.names, base + "_s")) {
                prune(directory, base + "_s");
            }
        }
    }

    private static boolean hasSuffix(String name) {
        return name.endsWith("_c") || name.endsWith("_s");
    }

    private static boolean contains(String[] names, String target) {
        for (String name : names) {
            if (name.equals(target)) {
                return true;
            }
        }
        return false;
    }

    private static void prune(File directory, String name) {
        File file = new File(directory, name);
        if (file.isFile() && file.delete()) {
            ModuleLogger.debug("feature packs: pruned stale " + name);
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
                continue;
            }
            if (verifyContent(pack.names[index])
                    && !hashMatches(file, pack.hashes[index])) {
                ModuleLogger.log("feature packs: hash mismatch " + pack.names[index]);
                missing.add(pack.names[index]);
            }
        }
        return missing;
    }

    /**
     * 暂时只对 _s 签名侧车做内容哈希：每个只有 256 字节，启动开销可忽略。
     * body/_c 先维持长度校验，观察稳定后再扩大；清单里仍保留全部哈希。
     */
    private static boolean verifyContent(String name) {
        return name.endsWith("_s");
    }

    /**
     * 空哈希表示旧版清单，只校验长度；新版清单必须逐字节对 SHA-256，
     * 避免「大小相同但内容被替换」的包被壳当成完整包加载。
     */
    private static boolean hashMatches(File file, String expected) {
        if (!isSha256(expected)) {
            return true;
        }
        try (InputStream input = new FileInputStream(file)) {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] buffer = new byte[BUFFER_SIZE];
            int read;
            while ((read = input.read(buffer)) > 0) {
                digest.update(buffer, 0, read);
            }
            return expected.equalsIgnoreCase(hex(digest.digest()));
        } catch (Throwable error) {
            return false;
        }
    }

    private static boolean isSha256(String value) {
        if (value == null || value.length() != 64) {
            return false;
        }
        for (int index = 0; index < 64; index++) {
            char ch = value.charAt(index);
            boolean hex = (ch >= '0' && ch <= '9')
                    || (ch >= 'a' && ch <= 'f')
                    || (ch >= 'A' && ch <= 'F');
            if (!hex) {
                return false;
            }
        }
        return true;
    }

    private static String hex(byte[] data) {
        char[] digits = "0123456789abcdef".toCharArray();
        char[] out = new char[data.length * 2];
        for (int index = 0; index < data.length; index++) {
            int value = data[index] & 0xFF;
            out[index * 2] = digits[value >>> 4];
            out[index * 2 + 1] = digits[value & 0x0F];
        }
        return new String(out);
    }

    private static int restore(File directory, Pack pack, List<String> missing)
            throws IOException {
        int restored = 0;
        for (String name : missing) {
            if (restoreMerged(directory, pack, name)) {
                restored++;
                continue;
            }
            File target = new File(directory, name);
            if (ModuleApk.copyAsset(name, target)
                    || ModuleApk.copyAsset(pack.dirName + "/" + name, target)) {
                if (!verify(target, pack, name)) {
                    target.delete();
                    ModuleLogger.log("feature packs: hash mismatch after restore " + name);
                    continue;
                }
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

    private static boolean verify(File file, Pack pack, String name) {
        int index = pack.indexOf(name);
        if (index < 0) {
            return false;
        }
        return file.isFile()
                && file.length() == pack.sizes[index]
                && (!verifyContent(name) || hashMatches(file, pack.hashes[index]));
    }

    /** 平铺资产里的 WXH1 容器：body + _c + _s 合一，运行时拆开写盘。 */
    private static boolean restoreMerged(File directory, Pack pack, String name) {
        String base = name;
        if (name.endsWith("_c") || name.endsWith("_s")) {
            base = name.substring(0, name.length() - 2);
        }
        byte[] data = ModuleApk.readAsset(base);
        if (data == null) {
            data = ModuleApk.readAsset(pack.dirName + "/" + base);
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
            writePart(directory, base, data, offset, bodySize, pack.hashOf(base));
            offset += bodySize;
            if (sidecarSize > 0) {
                String sidecar = base + "_c";
                writePart(directory, sidecar, data, offset, sidecarSize, pack.hashOf(sidecar));
                offset += sidecarSize;
            }
            if (signatureSize > 0) {
                String signature = base + "_s";
                writePart(directory, signature, data, offset, signatureSize, pack.hashOf(signature));
            }
            return true;
        } catch (IOException error) {
            ModuleLogger.log(error);
            return false;
        }
    }

    /** 先写临时文件再 rename，避免中断留下半截文件被当成完整包。 */
    private static void writePart(File directory, String name, byte[] data,
            int offset, int length, String expectedHash) throws IOException {
        File target = new File(directory, name);
        File temp = new File(directory, name + ".tmp");
        try (java.io.FileOutputStream output = new java.io.FileOutputStream(temp)) {
            output.write(data, offset, length);
            output.flush();
            output.getFD().sync();
        }
        if (!temp.renameTo(target)) {
            if (!target.delete() || !temp.renameTo(target)) {
                throw new IOException("feature packs: rename failed " + name);
            }
        }
        if (target.length() != length) {
            throw new IOException("feature packs: size mismatch " + name);
        }
        if (verifyContent(name) && !hashMatches(target, expectedHash)) {
            throw new IOException("feature packs: hash mismatch " + name);
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
            int tail = parts.length - 2;
            // 新清单每项是 name|size|sha256；旧清单只有 name|size。
            boolean withHash = tail % 3 == 0 && parts.length > 4 && isSha256(parts[4]);
            int stride = withHash ? 3 : 2;
            if (tail <= 0 || tail % stride != 0) {
                continue;
            }
            int count = tail / stride;
            String[] names = new String[count];
            long[] sizes = new long[count];
            String[] hashes = new String[count];
            try {
                for (int index = 0; index < count; index++) {
                    int offset = 2 + index * stride;
                    names[index] = parts[offset];
                    sizes[index] = Long.parseLong(parts[offset + 1]);
                    hashes[index] = withHash ? parts[offset + 2] : "";
                }
            } catch (NumberFormatException error) {
                continue;
            }
            packs.add(new Pack(parts[0], parts[1], names, sizes, hashes));
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

    private record Pack(String name, String dirName, String[] names, long[] sizes,
            String[] hashes) {

        int indexOf(String target) {
            for (int index = 0; index < names.length; index++) {
                if (names[index].equals(target)) {
                    return index;
                }
            }
            return -1;
        }

        String hashOf(String target) {
            int index = indexOf(target);
            return index < 0 ? "" : hashes[index];
        }
    }
}
