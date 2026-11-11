package io.github.shadowbaby.wechatxposed.tool.hook.spoof;

import io.github.shadowbaby.wechatxposed.shared.hook.HookCallback;
import io.github.shadowbaby.wechatxposed.shared.hook.HookFramework;
import io.github.shadowbaby.wechatxposed.shared.hook.HookParam;
import io.github.shadowbaby.wechatxposed.tool.hook.framework.ReflectiveCalls;
import java.lang.reflect.Constructor;
import java.lang.reflect.Executable;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;


public final class MemberRules {
    private static final Map<Executable, Map<String, Integer>> BINDINGS = new ConcurrentHashMap<>();
    private static final ThreadLocal<Map<String, Integer>> CURRENT = new ThreadLocal<>();
    private MemberRules() {}

    public static Integer boundIndex(String key) {
        Map<String, Integer> current = CURRENT.get();
        return current == null ? null : current.get(key);
    }

    public static Method method(Class<?> owner, String baseName, String key) throws NoSuchMethodException {
        return method(owner, baseName, key, false);
    }

    public static Method method(Class<?> owner, String baseName, String key, boolean inherited) throws NoSuchMethodException {
        MemberRule rule = rule(key);
        Method method = find(owner, baseName, rule, inherited);
        if (method != null) { BINDINGS.put(method, rule.bindings); return method; }
        for (MemberRule alternative : rule.alternatives) {
            method = find(owner, baseName, alternative, inherited);
            if (method != null) { BINDINGS.put(method, alternative.bindings); return method; }
        }
        throw new NoSuchMethodException(owner.getName() + "." + baseName + " [" + key + "]");
    }

    public static Constructor<?> constructor(Class<?> owner, String key) throws NoSuchMethodException {
        MemberRule rule = rule(key);
        for (MemberRule candidate : variants(rule)) {
            try {
                Constructor<?> constructor = owner.getDeclaredConstructor(types(candidate, owner));
                BINDINGS.put(constructor, candidate.bindings);
                return constructor;
            } catch (NoSuchMethodException ignored) {}
            catch (IllegalArgumentException error) {
                if (!(error.getCause() instanceof ClassNotFoundException)) throw error;
            }
        }
        throw new NoSuchMethodException(owner.getName() + " [" + key + "]");
    }

    private static MemberRule rule(String key) {
        MemberRule rule = SpoofProfiles.current().fingerprintSignatures.get(key);
        if (rule == null) throw new IllegalArgumentException("Missing signature: " + key);
        return rule;
    }

    private static Class<?>[] types(MemberRule rule, Class<?> owner) {
        Class<?>[] result = new Class<?>[rule.parameters.size()];
        for (int i = 0; i < result.length; i++) result[i] = HostFingerprint.resolveType(rule.parameters.get(i), owner.getClassLoader(), owner);
        return result;
    }

    private static Method find(Class<?> owner, String baseName, MemberRule rule) {
        return find(owner, baseName, rule, false);
    }

    private static Method find(Class<?> owner, String baseName, MemberRule rule, boolean inherited) {
        String name = rule.name == null ? baseName : rule.name;
        Class<?>[] params;
        Class<?> resultType;
        try {
            params = types(rule, owner);
            resultType = rule.returns == null ? null : HostFingerprint.resolveType(rule.returns, owner.getClassLoader(), owner);
        } catch (IllegalArgumentException error) {
            if (error.getCause() instanceof ClassNotFoundException) return null;
            throw error;
        }
        for (Class<?> type = owner; type != null; type = inherited ? type.getSuperclass() : null) {
            Method result = null;
            for (Method method : type.getDeclaredMethods()) {
                if (method.isBridge() || Modifier.isAbstract(method.getModifiers()) || !method.getName().equals(name)
                        || !java.util.Arrays.equals(params, method.getParameterTypes())
                        || (resultType != null && method.getReturnType() != resultType)
                        || (rule.isStatic != null && rule.isStatic != Modifier.isStatic(method.getModifiers()))) continue;
                if (result != null) throw new IllegalArgumentException("Ambiguous member contract");
                result = method;
            }
            if (result != null) return result;
        }
        return null;
    }

    public static Object call(HookFramework framework, Object target, String key, Object[] inputs) {
        MemberRule rule = SpoofProfiles.current().fingerprintCalls.get(key);
        if (rule == null) throw new IllegalArgumentException("Missing call: " + key);
        Class<?> owner = target instanceof Class<?> type ? type : target.getClass();
        for (MemberRule candidate : variants(rule)) {
            Object[] args = assemble(candidate, inputs);
            if (candidate.isStatic != (target instanceof Class<?>)) throw new IllegalArgumentException("Call receiver kind");
            if (candidate.parameters == null) {

                try {
                    if (candidate.isStatic) return framework.callStaticMethod(owner, candidate.name, args);
                    return framework.callMethod(target, candidate.name, args);
                } catch (NoSuchMethodError missing) { continue; }
            }
            Method method = find(owner, candidate.name, candidate, true);
            if (method != null) return ReflectiveCalls.invoke(method, candidate.isStatic ? null : target, args);
        }
        throw new NoSuchMethodError(owner.getName() + " [" + key + "]");
    }

    static Object[] assemble(MemberRule rule, Object[] inputs) {
        Object[] args = new Object[rule.arguments.size()];
        for (int i = 0; i < args.length; i++) {
            MemberRule.Argument arg = rule.arguments.get(i);
            if (arg.input() >= 0) {
                if (arg.input() >= inputs.length) throw new IllegalArgumentException("Missing logical call input");
                args[i] = inputs[arg.input()];
            } else if (arg.type().equals("int")) args[i] = ((Number) arg.constant()).intValue();
            else if (arg.type().equals("long")) args[i] = ((Number) arg.constant()).longValue();
            else args[i] = arg.constant();
        }
        return args;
    }

    private static Iterable<MemberRule> variants(MemberRule rule) {
        var list = new java.util.ArrayList<MemberRule>();
        list.add(rule); list.addAll(rule.alternatives); return list;
    }

    public static HookCallback bind(Executable target, HookCallback callback) {
        Map<String, Integer> values = BINDINGS.getOrDefault(target, Collections.emptyMap());
        return new HookCallback() {
            @Override public void before(HookParam param) throws Throwable { scoped(values, () -> callback.before(param)); }
            @Override public void after(HookParam param) throws Throwable { scoped(values, () -> callback.after(param)); }
        };
    }

    private interface Action { void run() throws Throwable; }
    private static void scoped(Map<String, Integer> values, Action action) throws Throwable {
        Map<String, Integer> previous = CURRENT.get();
        CURRENT.set(values);
        try { action.run(); }
        finally { if (previous == null) CURRENT.remove(); else CURRENT.set(previous); }
    }
}
