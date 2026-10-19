package github.shadowbaby.wechatxposed.hook.framework;

public interface HookParam {

    Object[] args();

    Object arg(int index);

    Object thisObject();

    void setResult(Object result);

    /** 原方法执行后的返回值（after 回调里可读；before 阶段为 null）。 */
    Object result();

    boolean hasThrowable();
}
