package io.github.shadowbaby.wechatxposed.hook.license;

import android.os.SystemClock;
import io.github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;

public final class WeChatAccount {

    private static final String[] PREFS = {
            "notify_key_pref_no_account",
            "switch_account_preferences",
            "com.tencent.mm_preferences_account_history"
    };

    private static final String[] PREFS_KEYS = {
            "login_weixin_username",
            "last_switch_account_to_wx_username"
    };

    private static final String PREFS_HISTORY = "com.tencent.mm_preferences_account_history";

    private static final String[] FACADES = {
            "com.tencent.mm.model.c",
            "com.tencent.mm.storage.ConfigStorage",
            "com.tencent.mm.storage.au"
    };

    private static final String[] GETTERS = {"b", "II", "aS", "getInstance"};

    private static final String[] USERNAME_METHODS = {"getUsername"};

    private static final String[] USERNAME_FIELDS = {"field_username", "username"};

    private static final String KERNEL = "com.tencent.mm.kernel.g";

    private static final long CACHE_MS = 60_000L;

    private static final long RETRY_MS = 3_000L;

    private static volatile String cached;

    private static volatile long cachedAt;

    private static volatile long retryAt;

    private static volatile String hit;

    private static volatile long armedAt = Long.MAX_VALUE;

    private WeChatAccount() {
    }

    public static void armAfter(long delayMs) {
        armedAt = SystemClock.elapsedRealtime() + delayMs;
    }

    public static String read(File dataDir, ClassLoader loader) {
        long now = SystemClock.elapsedRealtime();
        String value = cached;
        if (value != null && now - cachedAt < CACHE_MS) {
            return value;
        }

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

        retryAt = now + RETRY_MS;
        return null;
    }

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

                if (value instanceof String text && Wxid.isReal(text)) {
                    return text;
                }
            } catch (Throwable ignored) {

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
