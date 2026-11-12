package io.github.shadowbaby.wechatxposed.shared.hook;

public interface HookParam {

    Object[] args();

    Object arg(int index);

    default void setArg(int index, Object value) {
        throw new UnsupportedOperationException("setArg");
    }

    Object thisObject();

    void setResult(Object result);

    Object result();

    boolean hasThrowable();
}
