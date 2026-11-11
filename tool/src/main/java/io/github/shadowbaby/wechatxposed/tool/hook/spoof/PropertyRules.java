package io.github.shadowbaby.wechatxposed.tool.hook.spoof;

import io.github.shadowbaby.wechatxposed.tool.hook.framework.ReflectiveCalls;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;


public final class PropertyRules {
    private PropertyRules() {}
    private static final class Missing extends IllegalArgumentException {
        Missing(String message) { super(message); }
    }
    private static final class NoValue extends IllegalArgumentException {
        NoValue(String message) { super(message); }
    }
    private static final class Conversion extends IllegalArgumentException {
        Conversion(String message) { super(message); }
    }
    private record Access(Object receiver, Field field, Method getter, Method setter, Class<?> nativeType, PropertyRule.Step step) {
        Object read() {
            if (field == null) return ReflectiveCalls.invoke(getter, receiver, accessorArgs(getter, step.getter(), new Object[0]));
            try { field.setAccessible(true); return field.get(receiver); }
            catch (ReflectiveOperationException error) { throw new IllegalArgumentException("Property read", error); }
        }
        void write(Object value) {
            if (field != null && Modifier.isFinal(field.getModifiers())) throw new IllegalArgumentException("Final property is read-only");
            if (field == null && setter == null) throw new IllegalArgumentException("Missing property setter");
            if (field == null) { ReflectiveCalls.invoke(setter, receiver, accessorArgs(setter, step.setter(), new Object[]{value})); return; }
            Object converted = convert(value, nativeType);
            try { field.setAccessible(true); field.set(receiver, converted); }
            catch (ReflectiveOperationException error) { throw new IllegalArgumentException("Property write", error); }
        }
    }
    private record Selected(Access access, PropertyRule rule, Class<?> rootType) {}

    public static Object read(Object root, String key) {
        if (root == null) return null;
        try { return require(root, key); }
        catch (Missing | NoValue | Conversion unavailable) { return null; }
    }
    public static Object require(Object root, String key) {
        Selected selected = select(root, key, false);
        Object raw = selected.access.read();
        return selected.rule.valueType == null ? raw : convert(raw, type(selected.rule.valueType, selected.rootType));
    }
    public static void write(Object root, String key, Object value) {
        Selected selected = select(root, key, true);
        Object logical = selected.rule.valueType == null ? value : convert(value, type(selected.rule.valueType, selected.rootType));
        selected.access.write(logical);
    }

    public static void validate(Class<?> owner, String key, boolean staticRoot, boolean writable) {
        for (PropertyRule variant : variants(rule(key))) {
            try {
                Class<?> current = owner;
                boolean staticMember = staticRoot;
                for (int i = 0; i < variant.path.size(); i++) {
                    Access access = access(current, null, staticMember, variant.path.get(i), i == variant.path.size() - 1 && writable);
                    current = access.nativeType;
                    String runtimeType = variant.path.get(i).runtimeType();
                    if (runtimeType != null) {
                        Class<?> layout = type(runtimeType, owner);
                        if (current.isPrimitive() || layout.isPrimitive() || !current.isAssignableFrom(layout)) throw new Missing("Property runtime type scope");
                        current = layout;
                    }
                    staticMember = false;
                }
                return;
            } catch (Missing ignored) {}
        }
        throw new Missing("Property layout unavailable: " + key);
    }

    private static Selected select(Object root, String key, boolean writable) {
        if (root == null) throw new Missing("Null property root");
        Class<?> rootType = root instanceof Class<?> c ? c : root.getClass();
        for (PropertyRule variant : variants(rule(key))) {
            Object current = root;
            try {
                for (int i = 0; i < variant.path.size(); i++) {
                    if (current == null) throw new NoValue("Null intermediate property: " + key);
                    boolean isStatic = current instanceof Class<?>;
                    Class<?> owner = isStatic ? (Class<?>) current : current.getClass();
                    Access access = access(owner, isStatic ? null : current, isStatic, variant.path.get(i), writable && i == variant.path.size() - 1);
                    if (i == variant.path.size() - 1) return new Selected(access, variant, rootType);
                     current = access.read();
                    String runtimeType = variant.path.get(i).runtimeType();
                    if (runtimeType != null && current != null && !type(runtimeType, owner).isInstance(current))
                        throw new Missing("Property runtime type mismatch");
                }
            } catch (Missing ignored) {}
        }
        throw new Missing("Property layout unavailable: " + key);
    }

    private static PropertyRule rule(String key) {
        SpoofProfile profile = SpoofProfiles.current();
        if (profile == null) throw new Missing("Host property profile unavailable");
        PropertyRule rule = profile.fingerprintProperties.get(key);
        if (rule == null) throw new Missing("Missing property rule: " + key);
        return rule;
    }
    private static List<PropertyRule> variants(PropertyRule rule) {
        List<PropertyRule> values = new ArrayList<>(); values.add(rule); values.addAll(rule.alternatives); return values;
    }
    private static Access access(Class<?> owner, Object receiver, boolean staticRoot, PropertyRule.Step step, boolean writable) {
        if (step.isStatic() != null && step.isStatic() != staticRoot) throw new Missing("Property static scope");
        Field field = null;
        Method getter = null, setter = null;
        Class<?> actual;
        if (step.field() != null) {
            for (Class<?> c = owner; c != null; c = step.inherited() ? c.getSuperclass() : null) {
                try { field = c.getDeclaredField(step.field()); break; }
                catch (NoSuchFieldException ignored) {}
            }
            if (field == null || Modifier.isStatic(field.getModifiers()) != staticRoot) throw new Missing("Property field unavailable");
            if (writable && Modifier.isFinal(field.getModifiers())) throw new Missing("Final property");
            actual = field.getType();
        } else {
            getter = method(owner, step.getter(), staticRoot, step.inherited());
            actual = getter.getReturnType();
            if (actual == void.class) throw new Missing("Void getter");
            if (writable) {
                if (step.setter() == null) throw new Missing("Read-only getter");
                setter = method(owner, step.setter(), staticRoot, step.inherited());
            }
        }
        if (step.type() != null && type(step.type(), owner) != actual) throw new Missing("Property declared type mismatch");
        return new Access(receiver, field, getter, setter, actual, step);
    }
    private static Object[] accessorArgs(Method method, MemberRule rule, Object[] inputs) {
        Object[] values = MemberRules.assemble(rule, inputs);
        Class<?>[] types = method.getParameterTypes();
        for (int i = 0; i < values.length; i++) values[i] = convert(values[i], types[i]);
        return values;
    }
    private static Method method(Class<?> owner, MemberRule rule, boolean staticRoot, boolean inherited) {
        if (rule.isStatic != staticRoot) throw new Missing("Accessor static scope");
        Class<?>[] parameters = new Class<?>[rule.parameters.size()];
        for (int i = 0; i < parameters.length; i++) parameters[i] = type(rule.parameters.get(i), owner);
        for (Class<?> c = owner; c != null; c = inherited ? c.getSuperclass() : null) {
            Method selected = null;
            for (Method method : c.getDeclaredMethods()) {
                if (!method.getName().equals(rule.name) || method.isBridge() || Modifier.isAbstract(method.getModifiers())
                        || Modifier.isStatic(method.getModifiers()) != staticRoot || !Arrays.equals(parameters, method.getParameterTypes())
                        || (rule.returns != null && type(rule.returns, owner) != method.getReturnType())) continue;
                if (selected != null) throw new IllegalArgumentException("Ambiguous property accessor");
                selected = method;
            }
            if (selected != null) return selected;
        }
        throw new Missing("Property accessor unavailable");
    }
    private static Class<?> type(String name, Class<?> owner) {
        try { return HostFingerprint.resolveType(name, owner.getClassLoader(), owner); }
        catch (IllegalArgumentException error) {
            if (error.getCause() instanceof ClassNotFoundException) throw new Missing("Property type unavailable");
            throw error;
        }
    }

    private static Object convert(Object value, Class<?> target) {
        if (value == null) {
            if (target.isPrimitive()) throw new Conversion("Null primitive property");
            return null;
        }
        if (!target.isPrimitive() && target.isInstance(value)) return value;
        if ((target == boolean.class || target == Boolean.class) && value instanceof Boolean) return value;
        if ((target == char.class || target == Character.class) && value instanceof Character) return value;
        if (!(value instanceof Number number)) throw new Conversion("Property value type mismatch");
        try {
            BigDecimal decimal = new BigDecimal(number.toString());
            if (target == int.class || target == Integer.class) return decimal.intValueExact();
            if (target == long.class || target == Long.class) return decimal.longValueExact();
            if (target == byte.class || target == Byte.class) {
                int n = decimal.intValueExact(); if (n < Byte.MIN_VALUE || n > Byte.MAX_VALUE) throw new ArithmeticException(); return (byte) n;
            }
            if (target == short.class || target == Short.class) {
                int n = decimal.intValueExact(); if (n < Short.MIN_VALUE || n > Short.MAX_VALUE) throw new ArithmeticException(); return (short) n;
            }
            if (target == double.class || target == Double.class) {
                double n = number.doubleValue();
                if (!Double.isFinite(n)) throw new ArithmeticException();
                if (number instanceof Double || number instanceof Float) return n;
                if (new BigDecimal(n).compareTo(decimal) != 0) throw new ArithmeticException(); return n;
            }
            if (target == float.class || target == Float.class) {
                float n = number.floatValue();
                if (!Float.isFinite(n)) throw new ArithmeticException();
                if (number instanceof Float) return n;
                BigDecimal original = number instanceof Double ? new BigDecimal(number.doubleValue()) : decimal;
                if (new BigDecimal((double) n).compareTo(original) != 0) throw new ArithmeticException(); return n;
            }
        } catch (ArithmeticException | NumberFormatException error) { throw new Conversion("Lossy property conversion"); }
        throw new Conversion("Property value type mismatch");
    }
}
