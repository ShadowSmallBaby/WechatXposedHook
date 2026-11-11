package io.github.shadowbaby.wechatxposed.tool.hook.framework;

import io.github.shadowbaby.wechatxposed.tool.hook.spoof.MemberRules;
import java.lang.reflect.Executable;
import io.github.shadowbaby.wechatxposed.shared.hook.HookCallback;
import io.github.shadowbaby.wechatxposed.shared.hook.HookFramework;


public final class RuleFramework implements HookFramework {
    private final HookFramework delegate;
    public RuleFramework(HookFramework delegate) { this.delegate = delegate; }
    @Override public Class<?> findClass(String name, ClassLoader loader) { return delegate.findClass(name, loader); }
    @Override public Class<?> findClassIfExists(String name, ClassLoader loader) { return delegate.findClassIfExists(name, loader); }
    @Override public void hookConstructors(Class<?> target, HookCallback callback) {
        for (var constructor : target.getDeclaredConstructors()) hookMethod(constructor, callback);
    }
    @Override public void hookMethod(Executable target, HookCallback callback) { delegate.hookMethod(target, MemberRules.bind(target, callback)); }
    @Override public void hookMethod(Class<?> target, String name, Class<?>[] types, HookCallback callback) {
        try { hookMethod(target.getDeclaredMethod(name, types), callback); }
        catch (NoSuchMethodException error) { throw new NoSuchMethodError(name); }
    }
    @Override public Object callMethod(Object target, String name, Object... args) { return delegate.callMethod(target, name, args); }
    @Override public Object callStaticMethod(Class<?> target, String name, Object... args) { return delegate.callStaticMethod(target, name, args); }
    @Override public void log(String message) { delegate.log(message); }
    @Override public void log(Throwable error) { delegate.log(error); }
}
