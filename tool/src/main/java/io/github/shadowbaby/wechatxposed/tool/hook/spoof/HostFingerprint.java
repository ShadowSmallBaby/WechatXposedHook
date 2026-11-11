package io.github.shadowbaby.wechatxposed.tool.hook.spoof;

import io.github.shadowbaby.wechatxposed.shared.hook.HookFramework;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;


public final class HostFingerprint {
    private HostFingerprint() {
    }

    public static String fp(String key) {
        String value = profile().fingerprintStrings.get(key);
        if (value == null) throw new IllegalArgumentException("Missing host string: " + key);
        return value;
    }

    public static int fpInt(String key) {
        Integer value = MemberRules.boundIndex(key);
        if (value == null) value = profile().fingerprintIntegers.get(key);
        if (value == null) throw new IllegalArgumentException("Missing host integer: " + key);
        return value;
    }

    public static String[] fpTypeNames(String key) {
        MemberRule value = profile().fingerprintSignatures.get(key);
        if (value == null) throw new IllegalArgumentException("Missing host signature: " + key);
        return value.parameters.toArray(new String[0]);
    }

    public static Class<?>[] fpTypes(String key, Class<?> owner) {
        return resolve(key, owner.getClassLoader(), owner);
    }

    public static Class<?>[] fpTypes(String key, ClassLoader loader) {
        return resolve(key, loader, null);
    }

    public static Method fpMethod(Class<?> owner, String name, String key) throws NoSuchMethodException {
        return MemberRules.method(owner, name, key);
    }

    public static Method fpInheritedMethod(Class<?> owner, String name, String key) throws NoSuchMethodException {
        return MemberRules.method(owner, name, key, true);
    }

    public static Constructor<?> fpConstructor(Class<?> owner, String key) throws NoSuchMethodException {
        return MemberRules.constructor(owner, key);
    }

    public static Object fpCall(HookFramework framework, Object target, String key, Object... inputs) {
        return MemberRules.call(framework, target, key, inputs);
    }

    public static Object fpRead(Object root, String key) { return PropertyRules.read(root, key); }
    public static Object fpRequire(Object root, String key) { return PropertyRules.require(root, key); }
    public static void fpWrite(Object root, String key, Object value) { PropertyRules.write(root, key, value); }
    public static void fpValidate(Class<?> owner, String key, boolean staticRoot, boolean writable) {
        PropertyRules.validate(owner, key, staticRoot, writable);
    }

    public static Class<?> resolveType(String name, ClassLoader loader, Class<?> owner) {
        try { return type(name, loader, owner); }
        catch (ClassNotFoundException error) { throw new IllegalArgumentException("Host type unavailable: " + name, error); }
    }

    private static Class<?>[] resolve(String key, ClassLoader loader, Class<?> owner) {
        String[] names = fpTypeNames(key);
        Class<?>[] types = new Class<?>[names.length];
        for (int i = 0; i < names.length; i++) {
            try {
                types[i] = type(names[i], loader, owner);
            } catch (ClassNotFoundException error) {
                throw new IllegalArgumentException("Host signature unavailable: " + key, error);
            }
        }
        return types;
    }

    private static Class<?> type(String name, ClassLoader loader, Class<?> owner) throws ClassNotFoundException {
        if (name.equals("@owner")) {
            if (owner == null) throw new ClassNotFoundException("Signature requires owner");
            return owner;
        }
        if (name.endsWith("[]")) {
            return java.lang.reflect.Array.newInstance(type(name.substring(0, name.length() - 2), loader, owner), 0).getClass();
        }
        return switch (name) {
            case "void" -> void.class;
            case "boolean" -> boolean.class;
            case "byte" -> byte.class;
            case "short" -> short.class;
            case "int" -> int.class;
            case "long" -> long.class;
            case "float" -> float.class;
            case "double" -> double.class;
            case "char" -> char.class;
            default -> Class.forName(name, false, loader);
        };
    }

    private static SpoofProfile profile() {
        SpoofProfile current = SpoofProfiles.current();
        if (current == null) throw new IllegalStateException("Host profile unavailable");
        return current;
    }
}
