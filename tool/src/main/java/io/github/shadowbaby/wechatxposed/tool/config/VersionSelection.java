package io.github.shadowbaby.wechatxposed.tool.config;

import java.util.LinkedHashMap;
import java.util.Map;


public record VersionSelection(int code, String name, boolean custom, CustomVersion saved) {
    public static final String ACTIVE_CODE = "targetVersion";
    public static final String ACTIVE_NAME = "targetVersionName";
    public static final String ACTIVE_CUSTOM = "targetVersionCustom";
    public static final String SAVED_CODE = "customVersionCode";
    public static final String SAVED_NAME = "customVersionName";
    private static final int DEFAULT_CODE = 0x28004F30;
    private static final String DEFAULT_NAME = "8.0.79";

    public record CustomVersion(int code, String name) {
        public CustomVersion {
            if (!validCode(code) || name == null || name.isBlank())
                throw new IllegalArgumentException("Invalid custom version");
            name = name.trim();
        }
    }

    public static VersionSelection read(Map<String, ?> values) {
        Object rawCode = values.get(ACTIVE_CODE);
        int code = rawCode instanceof Integer ? (Integer) rawCode : DEFAULT_CODE;
        Object rawName = values.get(ACTIVE_NAME);
        String name = rawName instanceof String && !((String) rawName).isBlank()
                ? (String) rawName : DEFAULT_NAME;
        Object rawCustom = values.get(ACTIVE_CUSTOM);
        boolean custom = rawCustom instanceof Boolean ? (Boolean) rawCustom
                : code != 0x28004F30 && code != 0x28005032;
        return new VersionSelection(code, name, custom, saved(values));
    }

    private static CustomVersion saved(Map<String, ?> values) {
        Object code = values.get(SAVED_CODE), name = values.get(SAVED_NAME);
        if (!(code instanceof Integer) || !(name instanceof String)
                || !validCode((Integer) code) || ((String) name).isBlank()) return null;
        return new CustomVersion((Integer) code, (String) name);
    }


    public static Map<String, Object> migration(Map<String, ?> values) {
        if (values.containsKey(SAVED_CODE) || values.containsKey(SAVED_NAME)) return Map.of();
        VersionSelection current = read(values);
        if (!current.custom || !validCode(current.code)
                || !(values.get(ACTIVE_NAME) instanceof String name) || name.isBlank()) return Map.of();
        return savedWrites(new CustomVersion(current.code, name));
    }


    public static Map<String, Object> saveCustom(Map<String, ?> values, String name, int code,
            boolean selectAfterSave) {
        CustomVersion saved = new CustomVersion(code, name);
        Map<String, Object> writes = savedWrites(saved);
        if (selectAfterSave || read(values).custom) writes.putAll(activeWrites(saved, true));
        return writes;
    }


    public static Map<String, Object> selectCustom(Map<String, ?> values) {
        CustomVersion saved = saved(values);
        return saved == null ? null : activeWrites(saved, true);
    }

    public static Map<String, Object> selectPreset(String name, int code) {
        return activeWrites(new CustomVersion(code, name), false);
    }

    private static Map<String, Object> savedWrites(CustomVersion version) {
        Map<String, Object> writes = new LinkedHashMap<>();
        writes.put(SAVED_CODE, version.code);
        writes.put(SAVED_NAME, version.name);
        return writes;
    }

    private static Map<String, Object> activeWrites(CustomVersion version, boolean custom) {
        Map<String, Object> writes = new LinkedHashMap<>();
        writes.put(ACTIVE_CODE, version.code);
        writes.put(ACTIVE_NAME, version.name);
        writes.put(ACTIVE_CUSTOM, custom);
        return writes;
    }

    private static boolean validCode(int code) {
        return code > 0 && (code & 0xffffff00) != 0;
    }
}
