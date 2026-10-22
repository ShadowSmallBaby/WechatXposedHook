package de.robv.android.xposed;

import android.util.Xml;
import java.io.File;
import java.io.FileInputStream;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.xmlpull.v1.XmlPullParser;

/** Legacy XSharedPreferences 的最小实现（只读 XML）。 */
public final class XSharedPreferences {

    private final File file;

    private final Map<String, Object> values = new HashMap<>();

    public XSharedPreferences(String packageName, String prefFileName) {
        this(new File("/data/data/" + packageName + "/shared_prefs",
                prefFileName + ".xml"));
    }

    public XSharedPreferences(String packageName) {
        this(new File("/data/data/" + packageName + "/shared_prefs",
                packageName + "_preferences.xml"));
    }

    public XSharedPreferences(File file) {
        this.file = file;
        reload();
    }

    public void reload() {
        values.clear();
        if (file == null || !file.isFile()) {
            return;
        }
        try (FileInputStream input = new FileInputStream(file)) {
            XmlPullParser parser = Xml.newPullParser();
            parser.setInput(input, "UTF-8");
            String key = null;
            for (int event = parser.getEventType();
                    event != XmlPullParser.END_DOCUMENT;
                    event = parser.next()) {
                if (event == XmlPullParser.START_TAG) {
                    String tag = parser.getName();
                    if ("map".equals(tag)) {
                        continue;
                    }
                    key = parser.getAttributeValue(null, "name");
                    String text = parser.nextText();
                    values.put(key, convert(tag, text));
                }
            }
        } catch (Throwable ignored) {
        }
    }

    private static Object convert(String tag, String text) {
        try {
            if ("boolean".equals(tag)) {
                return Boolean.parseBoolean(text);
            }
            if ("int".equals(tag)) {
                return Integer.parseInt(text);
            }
            if ("long".equals(tag)) {
                return Long.parseLong(text);
            }
            if ("float".equals(tag)) {
                return Float.parseFloat(text);
            }
            if ("set".equals(tag)) {
                return new HashSet<>();
            }
        } catch (Throwable ignored) {
        }
        return text;
    }

    public Map<String, ?> getAll() {
        return new HashMap<>(values);
    }

    public String getString(String key, String defValue) {
        Object value = values.get(key);
        return value == null ? defValue : String.valueOf(value);
    }

    public Set<String> getStringSet(String key, Set<String> defValues) {
        Object value = values.get(key);
        if (value instanceof Set<?>) {
            @SuppressWarnings("unchecked")
            Set<String> result = (Set<String>) value;
            return result;
        }
        return defValues;
    }

    public int getInt(String key, int defValue) {
        Object value = values.get(key);
        return value instanceof Number ? ((Number) value).intValue() : defValue;
    }

    public long getLong(String key, long defValue) {
        Object value = values.get(key);
        return value instanceof Number ? ((Number) value).longValue() : defValue;
    }

    public float getFloat(String key, float defValue) {
        Object value = values.get(key);
        return value instanceof Number ? ((Number) value).floatValue() : defValue;
    }

    public boolean getBoolean(String key, boolean defValue) {
        Object value = values.get(key);
        return value instanceof Boolean ? (Boolean) value : defValue;
    }

    public boolean contains(String key) {
        return values.containsKey(key);
    }

    public boolean makeWorldReadable() {
        return file != null && file.setReadable(true, false);
    }

    public File getFile() {
        return file;
    }
}
