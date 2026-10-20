package github.shadowbaby.wechatxposed.hook.support;

import github.shadowbaby.wechatxposed.hook.BuildConfig;
import github.shadowbaby.wechatxposed.hook.framework.HookCallback;
import github.shadowbaby.wechatxposed.hook.framework.HookFramework;
import github.shadowbaby.wechatxposed.hook.framework.HookParam;
import github.shadowbaby.wechatxposed.hook.loader.ModuleLogger;
import github.shadowbaby.wechatxposed.hook.loader.Secret;
import github.shadowbaby.wechatxposed.hook.loader.SecretConstants;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.json.JSONObject;

public final class HostVersionSpoof {

    private static final String[] OPEN_URL_ANCHORS = {
            Secret.of(SecretConstants.OPEN_URL_ANCHOR_MAIN),
            Secret.of(SecretConstants.OPEN_URL_ANCHOR_APPID),
            Secret.of(SecretConstants.OPEN_URL_ANCHOR_STYLE)};

    private static final String[] UPGRADE_URLS = {
            Secret.of(SecretConstants.UPGRADE_URL_1),
            Secret.of(SecretConstants.UPGRADE_URL_2)};

    private static final int CLIENT_VERSION_HIGH_MASK = 0xFFFFFF00;
    private static final int CLIENT_VERSION_LOW_MASK = 0x000000FF;
    private static final int CLIENT_VERSION_BASE_8 = 0x28000000;
    private static final int CLIENT_VERSION_DEFAULT_HIGH = 0x28004F00;
    private static final String CLIENT_VERSION_CLASS =
            Secret.of(SecretConstants.CLIENT_VERSION_CLASS);
    private static final String CLIENT_VERSION_FIELD =
            Secret.of(SecretConstants.CLIENT_VERSION_FIELD);

    /**
     * 需要临时还原 ClientVersion 的页面白名单。
     *
     * 以后遇到新的钱包/支付页面，只需要把类名加到这里，不用改 hook 逻辑。
     * WalletBaseUI 覆盖所有子类；下面的具体页面用于非 WalletBaseUI 的入口。
     */
    private static final String[] WALLET_VERSION_CLASSES = {
            "com.tencent.mm.wallet_core.ui.WalletBaseUI",
            "com.tencent.mm.plugin.remittance.ui.RemittanceDetailUI",
            "com.tencent.mm.plugin.remittance.ui.RemittanceUI",
            "com.tencent.mm.plugin.remittance.ui.RemittanceResultUI",
    };

    private static final AtomicInteger WALLET_DEPTH = new AtomicInteger();

    private static volatile int originalClientVersion;
    private static volatile int spoofedClientVersion;
    private static final String UPGRADE_VERSION_FILE = "wxh_client_version";
    private static final long UPGRADE_VERSION_TTL_MS = 24L * 60L * 60L * 1000L;
    private static final long UPGRADE_VERSION_DELAY_MS = 30000L;
    private static final String UPGRADE_VERSION_PAGE = "/?scene=miniprogram";
    private static final Pattern UPGRADE_VERSION_PATTERN = Pattern.compile(
            "\"andrVersion\"\\s*:\\s*\"([^\"]+)\"", Pattern.CASE_INSENSITIVE);
    private static final Pattern UPGRADE_TASK_PATTERN = Pattern.compile(
            "\"bit64\"\\s*:\\s*\"([^\"]+)\"", Pattern.CASE_INSENSITIVE);
    private static final Pattern UPGRADE_TASK_HEX_PATTERN = Pattern.compile(
            "0x([0-9a-fA-F]{8})");
    private static final String UPGRADE_ERROR_PAGE = "waerrpage";
    private static final String UPGRADE_ERROR_TYPE = "type=upgrade";
    private static final String PLUGIN_DIR_WX244 = "WechatXposed";
    private static final String PLUGIN_DIR_WX30 = "X";
    private static final String LAUNCHER_UI = "com.tencent.mm.ui.LauncherUI";
    private static final String UPGRADE_USER_AGENT =
            "Mozilla/5.0 (Linux; Android 15) AppleWebKit/537.36 (KHTML, like Gecko) "
                    + "Version/4.0 Chrome/120 Mobile Safari/537.36 MicroMessenger/8.0.49";
    private static volatile boolean clientVersionSet;
    private static volatile boolean upgradeVersionStarted;
    private static File upgradeVersionFile;
    private static volatile int cachedClientVersion;

    private static boolean installed;

    private static final String LOG = ModuleLogger.HOST_SPOOF_PREFIX;
    private static final String LOG_NO_DEX = LOG + "no dex, skipped";
    private static final String KEY_URL = "url";

    private HostVersionSpoof() {
    }

    public static synchronized void install(HookFramework framework, ClassLoader classLoader,
            String sourceDir, String dataDir, boolean mainProcess) {
        if (installed) {
            return;
        }
        installed = true;
        if (mainProcess && dataDir != null) {
            String pluginDir = BuildConfig.WX_PACK.startsWith("wx6")
                    ? PLUGIN_DIR_WX244 : PLUGIN_DIR_WX30;
            upgradeVersionFile = new File(new File(dataDir, "files"),
                    pluginDir + "/" + UPGRADE_VERSION_FILE);
            ModuleLogger.log(LOG + "version file: " + upgradeVersionFile);
            cachedClientVersion = readCachedVersion(upgradeVersionFile);
            boolean seeded = false;
            if (cachedClientVersion == 0) {
                cachedClientVersion = CLIENT_VERSION_DEFAULT_HIGH;
                writeCachedVersion(upgradeVersionFile, cachedClientVersion);
                seeded = true;
                ModuleLogger.log(LOG + "default version: " + formatVersion(cachedClientVersion));
            } else {
                ModuleLogger.log(LOG + "cached version: " + formatVersion(cachedClientVersion));
            }
            scheduleUpgradeVersion(framework, classLoader, seeded);
            hookClientVersionTrigger(framework, classLoader, LAUNCHER_UI);
            hookWalletVersion(framework, classLoader);
        }
        try {
            List<byte[]> dexBytes = DexPaths.of(sourceDir);
            if (dexBytes.isEmpty()) {
                ModuleLogger.log(LOG_NO_DEX);
                return;
            }
            int methods = 0;
            for (byte[] bytes : dexBytes) {
                DexStrings dex = DexStrings.open(bytes);
                if (dex == null) {
                    continue;
                }
                methods += hookOpenUrl(framework, classLoader, dex.classesContaining(OPEN_URL_ANCHORS));
            }
            ModuleLogger.log(LOG + methods + " openUrl hooked");
        } catch (Throwable error) {
            ModuleLogger.log(error);
        }
    }

    private static synchronized void setClientVersion(HookFramework framework,
            ClassLoader classLoader) {
        applyClientVersion(framework, classLoader, false);
    }

    private static synchronized void refreshClientVersion(HookFramework framework,
            ClassLoader classLoader) {
        applyClientVersion(framework, classLoader, true);
    }

    private static void applyClientVersion(HookFramework framework, ClassLoader classLoader,
            boolean force) {
        if (clientVersionSet && !force) {
            return;
        }
        try {
            Class<?> target = framework.findClassIfExists(CLIENT_VERSION_CLASS, classLoader);
            if (target == null) {
                return;
            }
            Field field = target.getDeclaredField(CLIENT_VERSION_FIELD);
            field.setAccessible(true);
            int old = field.getInt(null);
            if (originalClientVersion == 0) {
                originalClientVersion = old;
            }
            int low = old & CLIENT_VERSION_LOW_MASK;
            int high = cachedClientVersion != 0
                    ? cachedClientVersion & CLIENT_VERSION_HIGH_MASK
                    : CLIENT_VERSION_DEFAULT_HIGH & CLIENT_VERSION_HIGH_MASK;
            int fake = high | low;
            spoofedClientVersion = fake;
            if (WALLET_DEPTH.get() > 0) {
                // 钱包/转账页面存活期间保持原始版本。
                clientVersionSet = true;
                return;
            }
            if (force && fake <= old) {
                return;
            }
            field.setInt(null, fake);
            clientVersionSet = true;
            ModuleLogger.log(LOG + (force ? "client version refresh: " : "client version: ")
                    + old + " -> " + fake);
        } catch (Throwable error) {
            ModuleLogger.log(error);
        }
    }

    private static void triggerUpgradeVersion(HookFramework framework, ClassLoader classLoader) {
        File file = upgradeVersionFile;
        if (file != null) {
            startUpgradeFetch(framework, classLoader, file, 0L);
        }
    }

    private static void scheduleUpgradeVersion(HookFramework framework, ClassLoader classLoader,
            boolean force) {
        File file = upgradeVersionFile;
        if (file == null) {
            return;
        }
        if (!force) {
            long age = System.currentTimeMillis() - file.lastModified();
            if (age < UPGRADE_VERSION_TTL_MS
                    && (cachedClientVersion & CLIENT_VERSION_HIGH_MASK)
                    >= CLIENT_VERSION_DEFAULT_HIGH) {
                return;
            }
        }
        startUpgradeFetch(framework, classLoader, file, UPGRADE_VERSION_DELAY_MS);
    }

    private static void startUpgradeFetch(HookFramework framework, ClassLoader classLoader,
            File file, long delayMs) {
        Thread thread = new Thread(() -> {
            if (delayMs > 0) {
                try {
                    Thread.sleep(delayMs);
                } catch (InterruptedException ignored) {
                    return;
                }
            }
            if (!beginUpgradeFetch()) {
                return;
            }
            fetchUpgradeVersion(framework, classLoader, file);
        }, "wxh-upgrade");
        thread.setDaemon(true);
        thread.start();
    }

    private static synchronized boolean beginUpgradeFetch() {
        if (upgradeVersionStarted) {
            return false;
        }
        upgradeVersionStarted = true;
        return true;
    }

    private static synchronized void endUpgradeFetch() {
        upgradeVersionStarted = false;
    }

    private static void hookClientVersionTrigger(HookFramework framework, ClassLoader classLoader,
            String className) {
        try {
            Class<?> target = framework.findClassIfExists(className, classLoader);
            if (target == null) {
                return;
            }
            for (Method method : target.getDeclaredMethods()) {
                if (!"onResume".equals(method.getName())) {
                    continue;
                }
                framework.hookMethod(method, new HookCallback() {
                    @Override
                    public void before(HookParam param) {
                        setClientVersion(framework, classLoader);
                    }
                });
                String simple = className.substring(className.lastIndexOf('.') + 1);
                ModuleLogger.log(LOG + simple + " version trigger hooked");
            }
        } catch (Throwable error) {
            ModuleLogger.log(error);
        }
    }

    /**
     * 钱包/转账页面存活期间把 ClientVersion 还原成真实值。
     *
     * 全局伪装是为了小程序/通话的低版本提示；但微信钱包的转账详情会拿这个
     * 版本去请求 CGI，8.0.79 会让页面一直加载。这里只在这类 Activity 的
     * onCreate ~ onDestroy 之间临时还原。
     */
    private static void hookWalletVersion(HookFramework framework, ClassLoader classLoader) {
        for (String className : WALLET_VERSION_CLASSES) {
            try {
                Class<?> target = framework.findClassIfExists(className, classLoader);
                if (target == null) {
                    continue;
                }
                int count = 0;
                for (Method method : target.getDeclaredMethods()) {
                    if ("onCreate".equals(method.getName())
                            && method.getParameterCount() == 1
                            && method.getParameterTypes()[0] == android.os.Bundle.class) {
                        framework.hookMethod(method,
                                new WalletLifecycle(framework, classLoader, true));
                        count++;
                    } else if ("onDestroy".equals(method.getName())
                            && method.getParameterCount() == 0) {
                        framework.hookMethod(method,
                                new WalletLifecycle(framework, classLoader, false));
                        count++;
                    }
                }
                if (count > 0) {
                    ModuleLogger.log(LOG + "wallet version guard: " + className
                            + " (" + count + " method(s))");
                }
            } catch (Throwable error) {
                ModuleLogger.log(error);
            }
        }
    }

    private static void writeClientVersion(HookFramework framework, ClassLoader classLoader,
            int value) {
        if (value == 0) {
            return;
        }
        try {
            Class<?> target = framework.findClassIfExists(CLIENT_VERSION_CLASS, classLoader);
            if (target == null) {
                return;
            }
            Field field = target.getDeclaredField(CLIENT_VERSION_FIELD);
            field.setAccessible(true);
            field.setInt(null, value);
        } catch (Throwable error) {
            ModuleLogger.log(error);
        }
    }

    private static final class WalletLifecycle implements HookCallback {

        private static final AtomicInteger LOGS = new AtomicInteger();

        private final HookFramework framework;
        private final ClassLoader classLoader;
        private final boolean enter;

        WalletLifecycle(HookFramework framework, ClassLoader classLoader, boolean enter) {
            this.framework = framework;
            this.classLoader = classLoader;
            this.enter = enter;
        }

        @Override
        public void before(HookParam param) {
            if (!enter) {
                return;
            }
            if (WALLET_DEPTH.incrementAndGet() == 1) {
                writeClientVersion(framework, classLoader, originalClientVersion);
                if (LOGS.incrementAndGet() <= 3) {
                    ModuleLogger.log(LOG + "wallet original version: "
                            + formatVersion(originalClientVersion));
                }
            }
        }

        @Override
        public void after(HookParam param) {
            if (enter) {
                return;
            }
            if (WALLET_DEPTH.decrementAndGet() <= 0) {
                WALLET_DEPTH.set(0);
                writeClientVersion(framework, classLoader, spoofedClientVersion);
                if (LOGS.incrementAndGet() <= 6) {
                    ModuleLogger.log(LOG + "wallet spoof restored: "
                            + formatVersion(spoofedClientVersion));
                }
            }
        }
    }

    private static void fetchUpgradeVersion(HookFramework framework, ClassLoader classLoader,
            File file) {
        boolean success = false;
        try {
            String url = Secret.of(SecretConstants.UPGRADE_URL_1) + UPGRADE_VERSION_PAGE;
            HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(5000);
            connection.setRequestProperty("User-Agent", UPGRADE_USER_AGENT);
            connection.setRequestProperty("Accept-Encoding", "identity");
            try {
                int code = connection.getResponseCode();
                if (code != HttpURLConnection.HTTP_OK) {
                    ModuleLogger.log(LOG + "upgrade page: http " + code);
                    return;
                }
                InputStream input = connection.getInputStream();
                if ("gzip".equalsIgnoreCase(connection.getContentEncoding())) {
                    input = new java.util.zip.GZIPInputStream(input);
                }
                String body = readBody(input);
                String version = match(body, UPGRADE_VERSION_PATTERN);
                String task = match(body, UPGRADE_TASK_PATTERN);
                int high = parseUpgradeVersion(version, task);
                if (high == 0) {
                    ModuleLogger.log(LOG + "upgrade page: no version");
                    return;
                }
                ModuleLogger.log(LOG + "upgrade version: " + version + " -> " + formatVersion(high));
                if (high > (cachedClientVersion & CLIENT_VERSION_HIGH_MASK)) {
                    cachedClientVersion = high;
                    writeCachedVersion(file, high);
                    refreshClientVersion(framework, classLoader);
                }
                if (!file.setLastModified(System.currentTimeMillis())) {
                    ModuleLogger.log(LOG + "upgrade page: touch failed");
                }
                success = true;
            } finally {
                connection.disconnect();
            }
        } catch (Throwable error) {
            ModuleLogger.log(error);
        } finally {
            if (!success) {
                endUpgradeFetch();
            }
        }
    }

    private static String readBody(InputStream input) throws Exception {
        StringBuilder body = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(input, StandardCharsets.UTF_8))) {
            char[] buffer = new char[4096];
            int count;
            while ((count = reader.read(buffer)) != -1 && body.length() < 262144) {
                body.append(buffer, 0, count);
            }
        }
        return body.toString();
    }

    private static String match(String body, Pattern pattern) {
        Matcher matcher = pattern.matcher(body);
        return matcher.find() ? matcher.group(1) : null;
    }

    // 升级页版本只取 major/minor/patch 三个字节, 低字节保留当前客户端后缀; 不扩展到 255。
    private static int parseUpgradeVersion(String version, String task) {
        if (task != null) {
            Matcher matcher = UPGRADE_TASK_HEX_PATTERN.matcher(task);
            if (matcher.find()) {
                return parsePackedHigh(matcher.group(1));
            }
        }
        return parseVersionHigh(version);
    }

    private static int parsePackedHigh(String digits) {
        try {
            int high = (int) (Long.parseLong(digits, 16) & CLIENT_VERSION_HIGH_MASK);
            return isVersion8(high) ? high : 0;
        } catch (NumberFormatException ignored) {
            return 0;
        }
    }

    private static int parseVersionHigh(String version) {
        if (version == null) {
            return 0;
        }
        String[] parts = version.split("\\.");
        if (parts.length < 3) {
            return 0;
        }
        try {
            int major = Integer.parseInt(parts[0].trim());
            int minor = Integer.parseInt(parts[1].trim());
            int patch = Integer.parseInt(parts[2].trim());
            if (major == 8) {
                return CLIENT_VERSION_BASE_8 | (minor << 16) | (patch << 8);
            }
        } catch (NumberFormatException ignored) {

        }
        return 0;
    }

    private static boolean isVersion8(int high) {
        return (high & 0xFF000000) == CLIENT_VERSION_BASE_8;
    }

    private static String formatVersion(int high) {
        int minor = (high >> 16) & 0xFF;
        int patch = (high >> 8) & 0xFF;
        return "8." + minor + "." + patch;
    }

    private static int readCachedVersion(File file) {
        if (file == null || !file.exists()) {
            return 0;
        }
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8))) {
            return parseCachedVersion(reader.readLine());
        } catch (Throwable error) {
            ModuleLogger.log(error);
            return 0;
        }
    }

    private static int parseCachedVersion(String value) {
        if (value == null) {
            return 0;
        }
        String text = value.trim();
        if (text.startsWith("﻿")) {
            text = text.substring(1).trim();
        }
        if (text.isEmpty()) {
            return 0;
        }
        if (text.startsWith("0x") || text.startsWith("0X")) {
            return parsePackedHigh(text.substring(2));
        }
        return parseVersionHigh(text);
    }

    private static void writeCachedVersion(File file, int high) {
        try {
            File parent = file.getParentFile();
            if (parent != null && !parent.exists()) {
                parent.mkdirs();
            }
            File temp = parent == null
                    ? new File(file.getPath() + ".tmp")
                    : new File(parent, file.getName() + ".tmp");
            try (FileOutputStream out = new FileOutputStream(temp)) {
                out.write((formatVersion(high) + "\n").getBytes(StandardCharsets.UTF_8));
            }
            if (!temp.renameTo(file)) {
                file.delete();
                temp.renameTo(file);
            }
        } catch (Throwable error) {
            ModuleLogger.log(error);
        }
    }


    private static int hookOpenUrl(HookFramework framework, ClassLoader classLoader,
            List<String> classes) {
        int count = 0;
        for (String name : classes) {
            Class<?> target = framework.findClassIfExists(name, classLoader);
            if (target == null) {
                continue;
            }
            for (Method method : target.getDeclaredMethods()) {
                if (!isOpenUrlSignature(method)) {
                    continue;
                }
                framework.hookMethod(method, new HookCallback() {
                    @Override
                    public void before(HookParam param) {
                        if (isUpgradeError(param)) {
                            triggerUpgradeVersion(framework, classLoader);
                        }
                    }
                });
                count++;
            }
        }
        return count;
    }

    private static boolean isOpenUrlSignature(Method method) {
        Class<?>[] parameters = method.getParameterTypes();
        return parameters.length == 3
                && "org.json.JSONObject".equals(parameters[1].getName())
                && parameters[2] == Integer.TYPE
                && method.getReturnType() == Void.TYPE;
    }

    private static boolean isUpgradeError(HookParam param) {
        if (!(param.arg(1) instanceof JSONObject json)) {
            return false;
        }
        String url = json.optString(KEY_URL);
        return !url.isEmpty() && (url.contains(UPGRADE_ERROR_PAGE)
                || url.contains(UPGRADE_ERROR_TYPE) || isUpgradeUrl(url));
    }

    private static boolean isUpgradeUrl(String url) {
        for (String upgrade : UPGRADE_URLS) {
            if (url.equals(upgrade) || url.startsWith(upgrade + "/")
                    || url.startsWith(upgrade + "?") || url.startsWith(upgrade + "#")) {
                return true;
            }
        }
        return false;
    }
}
