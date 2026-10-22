package github.shadowbaby.wechatxposed.hook.framework;

public interface HookParam {

    Object[] args();

    Object arg(int index);

    /** 替换方法参数(before 阶段生效)。 */
    void setArg(int index, Object value);

    Object thisObject();

    void setResult(Object result);

    /** 原方法执行后的返回值（after 回调里可读；before 阶段为 null）。 */
    Object result();

    boolean hasThrowable();
}
