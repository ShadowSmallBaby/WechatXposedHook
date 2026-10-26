package github.shadowbaby.wechatxposed.hook.license;

import android.os.SystemClock;
import github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;

/**
 * 进程内直接问微信要当前登录账号，不再依赖壳。
 *
 * 壳的账号接口同样靠反射微信实现，但要等 core dex 加载完，比壳判断授权、
 * 加载功能包晚 3~4 秒。这个窗口里账号为空，所有授权判定只能按兜底值走，
 * 结果就是壳跳过免责声明、功能表为空、菜单点进去没有内容。
 *
 * 来源按可用时间排序：先读微信自己的 SharedPreferences / MMKV 文件
 * （启动前就在磁盘上，毫秒级），再反射微信的配置存储，最后交给壳。
 */
public final class WeChatAccount {

    /** 微信保存登录名的 prefs，壳的第三层兜底也读这几个。 */
    private static final String[] PREFS = {
            "notify_key_pref_no_account",
            "switch_account_preferences",
            "com.tencent.mm_preferences_account_history"
    };

    private static final String[] PREFS_KEYS = {
            "login_weixin_username",
            "last_switch_account_to_wx_username"
    };

    /** 这个 prefs 的 key 本身就是账号，用来兜最后一步。 */
    private static final String PREFS_HISTORY = "com.tencent.mm_preferences_account_history";

    /** 微信里持有配置存储的门面类，8.x 的主流写法是 model.c.b()。 */
    private static final String[] FACADES = {
            "com.tencent.mm.model.c",
            "com.tencent.mm.storage.ConfigStorage",
            "com.tencent.mm.storage.au"
    };

    /** 门面上拿存储实例的静态入口，随版本改名，按顺序试。 */
    private static final String[] GETTERS = {"b", "II", "aS", "getInstance"};

    /** 存储里取登录名的方法；字段名只在方法全失败时兜底。 */
    private static final String[] USERNAME_METHODS = {"getUsername"};

    private static final String[] USERNAME_FIELDS = {"field_username", "username"};

    /** 微信 kernel 的服务定位器，第二条获取路径。 */
    private static final String KERNEL = "com.tencent.mm.kernel.g";

    /** 成功后的复用窗口；失败后短冷却，避免 UI 线程反复反射抛异常。 */
    private static final long CACHE_MS = 60_000L;

    private static final long RETRY_MS = 3_000L;

    private static volatile String cached;

    private static volatile long cachedAt;

    private static volatile long retryAt;

    /** 命中的门面与方法，只在变化时打一次日志，便于换版本时定位。 */
    private static volatile String hit;

    /** 允许开始探测的时间点；进程刚绑定时不能碰微信的存储类。 */
    private static volatile long armedAt = Long.MAX_VALUE;

    private WeChatAccount() {
    }

    /**
     * 延后多久开始探测微信存储。
     *
     * 进程刚绑定 Application 时微信的类还没初始化，主动调用 model.c.b()
     * 会触发它的静态块：一旦抛异常，类会被 JVM 标记成 Erroneous，
     * 微信自己后续再用就是 NoClassDefFoundError。等它自己走完再问，
     * 只晚几秒，换来不会把宿主拖崩。
     */
    public static void armAfter(long delayMs) {
        armedAt = SystemClock.elapsedRealtime() + delayMs;
    }

    /**
     * @param dataDir 微信的数据目录（{@code /data/user/<uid>/com.tencent.mm}）
     * @param loader  微信的 ClassLoader（能加载 {@code com.tencent.mm.**}）
     * @return 真实账号；文件层和微信存储都还没就绪时返回 null
     */
    public static String read(File dataDir, ClassLoader loader) {
        long now = SystemClock.elapsedRealtime();
        String value = cached;
        if (value != null && now - cachedAt < CACHE_MS) {
            return value;
        }
        // 文件层最早可用：微信启动前 prefs 就在磁盘上，不需要等类初始化。
        value = fromPrefs(dataDir);
        if (value != null) {
            cached = value;
            cachedAt = now;
            return value;
        }
        if (loader == null || now < armedAt || now < retryAt) {
            return null;
        }
        String account = probe(loader);
        if (account != null) {
            cached = account;
            cachedAt = now;
            return account;
        }
        // 登录信息恢复前存储还没建好，启动早期失败是常态，过几秒再试。
        retryAt = now + RETRY_MS;
        return null;
    }

    /**
     * 从微信自己的 SharedPreferences / MMKV 里取登录名。
     *
     * 这是壳第三层兜底读的那几个文件，放在这里最优先：账号在微信启动前
     * 就已经落盘，读它只需要一次 IO，不必等 core dex 或微信的存储类。
     */
    public static String fromPrefs(File dataDir) {
        if (dataDir == null) {
            return null;
        }
        String value = fromPrefsDir(new File(dataDir, "shared_prefs"));
        if (value == null) {
            value = fromMmkvDir(new File(dataDir, "files/mmkv"));
        }
        if (value != null) {
            record("prefs " + Wxid.mask(value));
        }
        return value;
    }

    private static String fromPrefsDir(File dir) {
        for (String name : PREFS) {
            String text = readText(new File(dir, name + ".xml"));
            if (text == null) {
                continue;
            }
            for (String key : PREFS_KEYS) {
                String value = xmlValue(text, key);
                if (Wxid.isReal(value)) {
                    return value;
                }
            }
            // 账号历史表的 key 就是微信号。
            if (PREFS_HISTORY.equals(name)) {
                for (String key : xmlKeys(text)) {
                    if (Wxid.isReal(key)) {
                        return key;
                    }
                }
            }
        }
        return null;
    }

    /**
     * 微信 8.x 把 prefs 迁到了 MMKV：二进制容器，但 key 与字符串值都是明文。
     * 按 key 定位后取紧随其后的可打印串，再用 {@link Wxid#isReal} 过滤误判。
     */
    private static String fromMmkvDir(File dir) {
        for (String name : PREFS) {
            byte[] data = readBytes(new File(dir, name));
            if (data == null) {
                continue;
            }
            for (String key : PREFS_KEYS) {
                String value = mmkvValue(data, key);
                if (Wxid.isReal(value)) {
                    return value;
                }
            }
        }
        return null;
    }

    private static String mmkvValue(byte[] data, String key) {
        byte[] needle = key.getBytes(StandardCharsets.UTF_8);
        for (int index = 0; index + needle.length < data.length; index++) {
            if (!matches(data, index, needle)) {
                continue;
            }
            int start = index + needle.length;
            while (start < data.length && !printable(data[start])) {
                start++;
            }
            int end = start;
            while (end < data.length && printable(data[end])) {
                end++;
            }
            if (end - start >= 6) {
                return new String(data, start, end - start, StandardCharsets.UTF_8);
            }
        }
        return null;
    }

    private static boolean matches(byte[] data, int offset, byte[] needle) {
        for (int index = 0; index < needle.length; index++) {
            if (data[offset + index] != needle[index]) {
                return false;
            }
        }
        return true;
    }

    private static boolean printable(byte value) {
        return value >= 0x20 && value < 0x7F;
    }

    private static String xmlValue(String xml, String key) {
        String head = "<string name=\"" + key + "\">";
        int start = xml.indexOf(head);
        if (start < 0) {
            return null;
        }
        start += head.length();
        int end = xml.indexOf("</string>", start);
        return end < 0 ? null : xml.substring(start, end).trim();
    }

    private static java.util.List<String> xmlKeys(String xml) {
        java.util.List<String> keys = new java.util.ArrayList<>();
        String head = "<string name=\"";
        int index = 0;
        while (true) {
            int start = xml.indexOf(head, index);
            if (start < 0) {
                break;
            }
            start += head.length();
            int end = xml.indexOf('"', start);
            if (end < 0) {
                break;
            }
            keys.add(xml.substring(start, end));
            index = end;
        }
        return keys;
    }

    private static String readText(File file) {
        byte[] data = readBytes(file);
        return data == null ? null : new String(data, StandardCharsets.UTF_8);
    }

    private static byte[] readBytes(File file) {
        if (!file.isFile()) {
            return null;
        }
        try (FileInputStream input = new FileInputStream(file)) {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            int read;
            while ((read = input.read(buffer)) > 0) {
                output.write(buffer, 0, read);
            }
            return output.toByteArray();
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static String probe(ClassLoader loader) {
        String account = fromFacade(loader);
        if (account == null) {
            account = fromKernel(loader);
        }
        return account;
    }

    /** 路径一：门面类的静态 getter 直接拿配置存储。 */
    private static String fromFacade(ClassLoader loader) {
        for (String name : FACADES) {
            Class<?> facade = load(name, loader);
            if (facade == null) {
                continue;
            }
            for (String getter : GETTERS) {
                String account = username(callStatic(facade, getter));
                if (account != null) {
                    record(name + "." + getter);
                    return account;
                }
            }
        }
        return null;
    }

    /** 路径二：kernel 按类定位账号存储，门面改名时还能走通。 */
    private static String fromKernel(ClassLoader loader) {
        Class<?> kernel = load(KERNEL, loader);
        if (kernel == null) {
            return null;
        }
        for (String name : FACADES) {
            Class<?> facade = load(name, loader);
            if (facade == null) {
                continue;
            }
            String account = username(callStatic(kernel, "b", facade));
            if (account != null) {
                record(KERNEL + ".b(" + name + ")");
                return account;
            }
        }
        return null;
    }

    private static Class<?> load(String name, ClassLoader loader) {
        try {
            // false：只加载不初始化，避免在微信自己准备好之前触发静态块。
            return Class.forName(name, false, loader);
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static Object callStatic(Class<?> type, String name) {
        try {
            Method method = type.getDeclaredMethod(name);
            method.setAccessible(true);
            return method.invoke(null);
        } catch (Throwable ignored) {
            // 方法可能声明在父类上，退回 public 查找
        }
        try {
            Method method = type.getMethod(name);
            method.setAccessible(true);
            return method.invoke(null);
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static Object callStatic(Class<?> type, String name, Class<?> argument) {
        try {
            Method method = type.getMethod(name, Class.class);
            method.setAccessible(true);
            return method.invoke(null, argument);
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static String username(Object storage) {
        if (storage == null) {
            return null;
        }
        for (String name : USERNAME_METHODS) {
            try {
                Method method = storage.getClass().getMethod(name);
                method.setAccessible(true);
                Object value = method.invoke(storage);
                // 自定义微信号同样是合法 userId，不能只认 wxid_ 前缀。
                if (value instanceof String text && Wxid.isReal(text)) {
                    return text;
                }
            } catch (Throwable ignored) {
                // 继续下一个候选
            }
        }
        for (String name : USERNAME_FIELDS) {
            try {
                java.lang.reflect.Field field = storage.getClass().getDeclaredField(name);
                field.setAccessible(true);
                Object value = field.get(storage);
                if (value instanceof String text && Wxid.isReal(text)) {
                    return text;
                }
            } catch (Throwable ignored) {
                // 继续下一个候选
            }
        }
        return null;
    }

    private static void record(String path) {
        if (!path.equals(hit)) {
            hit = path;
            ModuleLogger.log("account probe: " + path);
        }
    }
}
