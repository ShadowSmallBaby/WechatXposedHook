package github.shadowbaby.wechatxposed.hook.support;

import github.shadowbaby.wechatxposed.hook.BuildConfig;
import github.shadowbaby.wechatxposed.hook.deploy.FeaturePackRestorer;
import github.shadowbaby.wechatxposed.hook.deploy.ModuleApk;
import github.shadowbaby.wechatxposed.hook.framework.HookCallback;
import github.shadowbaby.wechatxposed.hook.framework.HookFramework;
import github.shadowbaby.wechatxposed.hook.framework.HookParam;
import github.shadowbaby.wechatxposed.hook.loader.ModuleLogger;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * 功能包完整性守卫。
 *
 * 以模块 APK 内置的功能包 zip 为唯一基准，校验文件名、大小和 SHA-256；
 * 主进程与 appbrand 进程都会安装。X3 尝试覆盖/重命名功能包时同步恢复，
 * 旧核心类出现时也会触发一次恢复。
 */
public final class PackIntegrity {

    private static final String LOG = "pack integrity: ";
    private static final String ZIP_SUFFIX = ".zip";
    private static final String TEMP_PREFIX = "wxh_pack_";
    private static final int BUFFER_SIZE = 16 * 1024;

    private static final Map<Object, String> STREAMS =
            Collections.synchronizedMap(new WeakHashMap<>());

    private static final Set<String> LOGGED = ConcurrentHashMap.newKeySet();

    private static final ThreadLocal<Boolean> INTERNAL =
            ThreadLocal.withInitial(() -> Boolean.FALSE);

    private static volatile boolean installed;
    private static volatile boolean repairing;
    private static volatile boolean oldCore;
    private static volatile boolean oldCorePending;
    private static volatile File filesDir;
    private static volatile File packDir;
    private static volatile String payloadName;
    private static volatile String extPayloadName;

    private PackIntegrity() {
    }

    public static synchronized void install(HookFramework framework, File dataDir) {
        if (installed || BuildConfig.WX_PACK.startsWith("wx6")) {
            return;
        }
        installed = true;
        filesDir = dataDir;
        packDir = new File(new File(dataDir, "files"), FeaturePackRestorer.packDirName());
        payloadName = FeaturePackRestorer.payloadName();
        extPayloadName = BuildConfig.FULL_EDITION
                ? FeaturePackRestorer.extPayloadName() : null;
        if (oldCorePending) {
            oldCorePending = false;
            onOldCoreDetected("pending");
        } else {
            check("startup");
        }
        hook(framework);
        ModuleLogger.debug(LOG + "installed: " + packDir);
    }

    public static boolean isRepairing() {
        return repairing;
    }

    /** X3 旧核心类出现时调用；类名本身就是版本判据。 */
    public static void onOldCoreDetected(String source) {
        if (oldCore) {
            return;
        }
        oldCore = true;
        if (filesDir == null) {
            oldCorePending = true;
            ModuleLogger.log(LOG + "old core detected before install: " + source);
            return;
        }
        ModuleLogger.log(LOG + "old core detected: " + source);
        if (repair("old-core")) {
            ModuleLogger.log(LOG + "old core files repaired; restart recommended");
        }
    }

    /** hook 报错也可作为完整性信号：只在不一致时目录级覆盖。 */
    public static void onHookError(String source) {
        if (filesDir == null) {
            ModuleLogger.log(LOG + "hook error before install: " + source);
            return;
        }
        ModuleLogger.log(LOG + "hook error signal: " + source);
        check("hook-error");
    }

    private static void hook(HookFramework framework) {
        try {
            Class<?> file = framework.findClassIfExists("java.io.File", null);
            if (file != null) {
                framework.hookMethod(file, "renameTo", new Class<?>[]{File.class},
                        new RenameGuard());
            }
        } catch (Throwable error) {
            ModuleLogger.log(error);
        }
        try {
            Class<?> output = framework.findClassIfExists("java.io.FileOutputStream", null);
            if (output != null) {
                framework.hookConstructors(output, new WriteCtor());
                framework.hookMethod(output, "write", new Class<?>[]{int.class}, new WriteGuard());
                framework.hookMethod(output, "write", new Class<?>[]{byte[].class}, new WriteGuard());
                framework.hookMethod(output, "write",
                        new Class<?>[]{byte[].class, int.class, int.class}, new WriteGuard());
            }
        } catch (Throwable error) {
            ModuleLogger.log(error);
        }
        try {
            Class<?> random = framework.findClassIfExists("java.io.RandomAccessFile", null);
            if (random != null) {
                framework.hookConstructors(random, new RandomCtor());
                framework.hookMethod(random, "write", new Class<?>[]{int.class}, new WriteGuard());
                framework.hookMethod(random, "write", new Class<?>[]{byte[].class}, new WriteGuard());
                framework.hookMethod(random, "write",
                        new Class<?>[]{byte[].class, int.class, int.class}, new WriteGuard());
            }
        } catch (Throwable error) {
            ModuleLogger.log(error);
        }
    }

    private static final class WriteCtor implements HookCallback {

        @Override
        public void after(HookParam param) {
            String path = pathOf(param.arg(0));
            if (path == null) {
                return;
            }
            Object target = param.thisObject();
            if (target != null) {
                STREAMS.put(target, path);
            }
            if (isCritical(path) && !isInternal()) {
                if (LOGGED.add(path)) {
                    ModuleLogger.log(LOG + "write open: " + path);
                }
                repair("open-write");
            }
        }
    }

    private static final class RandomCtor implements HookCallback {

        @Override
        public void after(HookParam param) {
            String path = pathOf(param.arg(0));
            Object target = param.thisObject();
            if (path == null || target == null) {
                return;
            }
            STREAMS.put(target, path);
            String mode = param.arg(1) instanceof String ? (String) param.arg(1) : "";
            if (isCritical(path) && !isInternal() && mode.contains("w")) {
                if (LOGGED.add(path)) {
                    ModuleLogger.log(LOG + "random open: " + path);
                }
                repair("random-open");
            }
        }
    }

    private static final class WriteGuard implements HookCallback {

        @Override
        public void before(HookParam param) {
            String path = STREAMS.get(param.thisObject());
            if (!isCritical(path) || isInternal()) {
                return;
            }
            if (LOGGED.add(path)) {
                ModuleLogger.log(LOG + "blocked write: " + path);
            }
            param.setResult(null);
            repair("write");
        }
    }

    private static final class RenameGuard implements HookCallback {

        @Override
        public void before(HookParam param) {
            String source = pathOf(param.thisObject());
            String target = pathOf(param.arg(0));
            if (isInternal() || (!isCritical(source) && !isCritical(target))) {
                return;
            }
            String path = isCritical(source) ? source : target;
            if (LOGGED.add(path)) {
                ModuleLogger.log(LOG + "blocked rename: " + source + " -> " + target);
            }
            param.setResult(Boolean.FALSE);
            repair("rename");
        }
    }

    private static boolean isInternal() {
        return repairing || Boolean.TRUE.equals(INTERNAL.get());
    }

    /** 只有核心/native 及插件自解包产物会触发目录级覆盖；功能包允许正常更新。 */
    private static boolean isCritical(String path) {
        if (!isPackPath(path) || path == null) {
            return false;
        }
        String name = path.substring(path.lastIndexOf('/') + 1);
        return name.startsWith("d61f837cad1d412f80b84d143e1257")
                || name.startsWith("36a76b97b96b5d46742bb4bcd2ff24d")
                || name.startsWith("dc7be70f1898d3a58965a919740f97")
                || name.startsWith("a660ee759640f14c9e51c31bc5b5392")
                || name.startsWith("a282aad6b5f0dbd0ee2dfbb2f46a3d40");
    }

    private static boolean isPackPath(String path) {
        File dir = packDir;
        if (dir == null || path == null) {
            return false;
        }
        String root = dir.getAbsolutePath().replace('\\', '/');
        return path.equals(root) || path.startsWith(root + "/");
    }

    private static String pathOf(Object value) {
        if (value instanceof File file) {
            return file.getAbsolutePath().replace('\\', '/');
        }
        if (value instanceof String text) {
            return new File(text).getAbsolutePath().replace('\\', '/');
        }
        return null;
    }

    private static synchronized void check(String reason) {
        if (repairing) {
            return;
        }
        Map<String, Entry> table = loadExpected();
        if (table == null) {
            return;
        }
        if (matchesDir(table)) {
            ModuleLogger.debug(LOG + "check " + reason + ": intact (" + table.size() + ")");
            return;
        }
        ModuleLogger.log(LOG + "check " + reason + ": mismatch, replacing directory");
        repair(reason);
    }

    private static synchronized boolean repair(String reason) {
        if (repairing) {
            return false;
        }
        File dir = packDir;
        File base = filesDir;
        String payload = payloadName;
        if (dir == null || base == null || payload == null) {
            ModuleLogger.log(LOG + "cannot repair " + reason + ": not installed");
            return false;
        }
        repairing = true;
        INTERNAL.set(Boolean.TRUE);
        File tempDir = null;
        File backup = null;
        try {
            tempDir = new File(base, TEMP_PREFIX + "dir_" + System.nanoTime());
            if (!tempDir.mkdirs()) {
                ModuleLogger.log(LOG + "cannot create " + tempDir);
                return false;
            }
            Map<String, Entry> table = new HashMap<>();
            if (!readPayload(payload, base, tempDir, table)) {
                return false;
            }
            if (extPayloadName != null
                    && !readPayload(extPayloadName, base, tempDir, table)) {
                return false;
            }
            if (table.isEmpty()) {
                ModuleLogger.log(LOG + "payload empty: " + payload);
                return false;
            }
            File parent = dir.getParentFile();
            if (parent != null && !parent.isDirectory() && !parent.mkdirs()) {
                ModuleLogger.log(LOG + "cannot create " + parent);
                return false;
            }
            if (dir.exists()) {
                backup = new File(parent, dir.getName() + ".old." + System.nanoTime());
                if (!dir.renameTo(backup)) {
                    ModuleLogger.log(LOG + "cannot move old directory: " + dir);
                    return false;
                }
            }
            if (!tempDir.renameTo(dir)) {
                ModuleLogger.log(LOG + "cannot replace directory: " + dir);
                if (backup != null && !backup.renameTo(dir)) {
                    ModuleLogger.log(LOG + "cannot restore old directory: " + backup);
                }
                return false;
            }
            if (backup != null) {
                deleteTree(backup);
            }
            int bad = 0;
            for (Map.Entry<String, Entry> item : table.entrySet()) {
                if (!matches(new File(dir, item.getKey()).getAbsolutePath().replace('\\', '/'),
                        item.getValue())) {
                    bad++;
                }
            }
            int count = countFiles(dir);
            ModuleLogger.log(LOG + "replace " + reason + ": " + count + " files, "
                    + table.size() + " expected, " + bad + " bad");
            return bad == 0 && count == table.size();
        } catch (Throwable error) {
            ModuleLogger.log(error);
            return false;
        } finally {
            if (tempDir != null && tempDir.exists()) {
                deleteTree(tempDir);
            }
            INTERNAL.set(Boolean.FALSE);
            repairing = false;
        }
    }

    private static Map<String, Entry> loadExpected() {
        File base = filesDir;
        String payload = payloadName;
        if (base == null || payload == null) {
            return null;
        }
        Map<String, Entry> table = new HashMap<>();
        if (!readPayload(payload, base, null, table)) {
            return null;
        }
        if (extPayloadName != null
                && !readPayload(extPayloadName, base, null, table)) {
            return null;
        }
        return table;
    }

    /** 读取一个内置载荷；tempDir 非空时同时落盘。 */
    private static boolean readPayload(String payload, File base, File tempDir,
            Map<String, Entry> table) {
        File archive = null;
        try {
            archive = File.createTempFile(TEMP_PREFIX, ZIP_SUFFIX, base);
            if (!ModuleApk.extractPayload(payload, archive)) {
                ModuleLogger.log(LOG + "payload missing: " + payload);
                return false;
            }
            try (ZipFile zip = new ZipFile(archive)) {
                for (ZipEntry entry : Collections.list(zip.entries())) {
                    if (entry.isDirectory()) {
                        continue;
                    }
                    String name = entry.getName();
                    if (name.contains("/") || name.contains("\\")) {
                        continue;
                    }
                    byte[] data = readAll(zip.getInputStream(entry));
                    if (tempDir != null) {
                        write(new File(tempDir, name), data);
                    }
                    table.put(name, new Entry(data.length, sha256(data)));
                }
            }
            return true;
        } catch (Throwable error) {
            ModuleLogger.log(error);
            return false;
        } finally {
            if (archive != null && !archive.delete()) {
                ModuleLogger.log(LOG + "cannot delete " + archive);
            }
        }
    }

    private static boolean matchesDir(Map<String, Entry> table) {
        File dir = packDir;
        if (dir == null || !dir.isDirectory()) {
            return false;
        }
        File[] files = dir.listFiles();
        if (files == null) {
            return false;
        }
        int count = 0;
        for (File file : files) {
            if (!file.isFile()) {
                continue;
            }
            count++;
            Entry entry = table.get(file.getName());
            if (entry == null || !matches(file.getAbsolutePath().replace('\\', '/'), entry)) {
                return false;
            }
        }
        return count == table.size();
    }

    private static int countFiles(File dir) {
        File[] files = dir.listFiles();
        if (files == null) {
            return 0;
        }
        int count = 0;
        for (File file : files) {
            if (file.isFile()) {
                count++;
            }
        }
        return count;
    }

    private static void deleteTree(File file) {
        if (file == null) {
            return;
        }
        File[] children = file.listFiles();
        if (children != null) {
            for (File child : children) {
                deleteTree(child);
            }
        }
        if (!file.delete()) {
            ModuleLogger.log(LOG + "cannot delete " + file);
        }
    }

    private static boolean matches(String path, Entry entry) {
        File file = new File(path);
        return file.isFile() && file.length() == entry.size
                && entry.hash.equals(sha256(file));
    }

    private static void write(File target, byte[] data) throws IOException {
        File parent = target.getParentFile();
        if (parent != null && !parent.isDirectory() && !parent.mkdirs()) {
            throw new IOException("cannot create " + parent);
        }
        File temp = new File(parent, target.getName() + ".tmp");
        try (FileOutputStream output = new FileOutputStream(temp)) {
            output.write(data);
        }
        if (!temp.renameTo(target)) {
            if (target.exists() && !target.delete()) {
                throw new IOException("cannot replace " + target);
            }
            if (!temp.renameTo(target)) {
                throw new IOException("cannot rename " + temp + " -> " + target);
            }
        }
        if (!target.setReadable(true, false)) {
            ModuleLogger.log(LOG + "cannot chmod " + target);
        }
    }

    private static byte[] readAll(InputStream input) throws IOException {
        try (InputStream stream = input) {
            byte[] buffer = new byte[BUFFER_SIZE];
            java.io.ByteArrayOutputStream output = new java.io.ByteArrayOutputStream();
            int read;
            while ((read = stream.read(buffer)) > 0) {
                output.write(buffer, 0, read);
            }
            return output.toByteArray();
        }
    }

    private static String sha256(byte[] data) {
        try {
            return hex(MessageDigest.getInstance("SHA-256").digest(data));
        } catch (Throwable error) {
            return "";
        }
    }

    private static String sha256(File file) {
        try (InputStream input = new FileInputStream(file)) {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] buffer = new byte[BUFFER_SIZE];
            int read;
            while ((read = input.read(buffer)) > 0) {
                digest.update(buffer, 0, read);
            }
            return hex(digest.digest());
        } catch (Throwable error) {
            return "";
        }
    }

    private static String hex(byte[] data) {
        StringBuilder text = new StringBuilder(data.length * 2);
        for (byte value : data) {
            text.append(Character.forDigit((value >> 4) & 0xF, 16));
            text.append(Character.forDigit(value & 0xF, 16));
        }
        return text.toString();
    }

    private static final class Entry {

        final long size;
        final String hash;

        Entry(long size, String hash) {
            this.size = size;
            this.hash = hash;
        }
    }
}
