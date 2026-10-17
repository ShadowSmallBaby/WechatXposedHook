package github.shadowbaby.wechatxposed.hook.framework;

public interface HookParam {

    Object[] args();

    Object arg(int index);

    Object thisObject();

    void setResult(Object result);

    boolean hasThrowable();
}
