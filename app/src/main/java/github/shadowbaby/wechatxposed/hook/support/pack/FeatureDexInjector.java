package github.shadowbaby.wechatxposed.hook.support.pack;

import github.shadowbaby.wechatxposed.hook.deploy.ModuleApk;
import github.shadowbaby.wechatxposed.hook.deploy.ModuleCertCheck;
import github.shadowbaby.wechatxposed.hook.license.Activation;
import github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import github.shadowbaby.wechatxposed.hook.support.guard.RuntimeGuard;
import java.io.File;
import java.nio.ByteBuffer;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 宿主扩展包内层解包返回空时，补上离线解出的 classes.dex。
 *
 * 宿主在 {@code CallMethod(102, path, 2, entry, ...)} 里用
 * {@code InMemoryDexClassLoader} 加载内层 payload。3.0 扩展包的内层密码表
 * 不在当前 shell 中，宿主会传入 0 字节 buffer；这里按外层 PBE password
 * 识别组件，在构造 before 阶段把空 buffer 换成真实 dex。
 */
public final class FeatureDexInjector {

    private static final long PENDING_TTL_MS = 10_000L;

    private static final ThreadLocal<String> PENDING = new ThreadLocal<>();

    private static final ThreadLocal<Long> PENDING_AT = new ThreadLocal<>();

    private static final Map<String, byte[]> CACHE = new ConcurrentHashMap<>();

    /**
     * 注入用的 direct buffer 必须活到进程结束。
     *
     * InMemoryDexClassLoader 只借用 buffer 的 native 内存，buffer 被 GC 回收后
     * ART 后续解析该类时会读到已释放内存，破坏 LinearAlloc（Android 17 上表现为
     * Class.forName 阶段 SIGSEGV，fault addr 为 dex 里的字符串数据）。
     */
    private static final java.util.List<ByteBuffer> LIVE_BUFFERS =
            java.util.Collections.synchronizedList(new java.util.ArrayList<>());

    private static volatile File filesDir;

    private FeatureDexInjector() {
    }

    public static void setFilesDir(File directory) {
        filesDir = directory;
    }

    /** 宿主解密匹配到扩展包时调用；feature 由 native 查表得到。 */
    public static void onFeature(String feature) {
        if (feature == null || feature.isEmpty()) {
            return;
        }
        // 高级激活才注入扩展 dex。
        if (!Activation.isExtensionAllowed()
                || !ModuleCertCheck.verify(ModuleApk.modulePath())
                || !RuntimeGuard.verify()) {
            return;
        }
        setPending(feature);
    }

    private static void setPending(String feature) {
        PENDING.set(feature);
        PENDING_AT.set(android.os.SystemClock.elapsedRealtime());
        ModuleLogger.log("feature dex: pending " + feature);
    }

    public static void end() {
        PENDING.remove();
        PENDING_AT.remove();
    }

    public static String pending() {
        String feature = PENDING.get();
        Long at = PENDING_AT.get();
        if (feature == null || at == null) {
            return null;
        }
        if (android.os.SystemClock.elapsedRealtime() - at > PENDING_TTL_MS) {
            end();
            return null;
        }
        return feature;
    }

    /** 从扩展包容器运行时解出组件 dex。 */
    public static byte[] dex(String feature) {
        byte[] cached = CACHE.get(feature);
        if (cached != null) {
            return cached;
        }
        byte[] data = FeatureDexDecoder.decode(filesDir, feature);
        if (data != null) {
            CACHE.put(feature, data);
        }
        return data;
    }

    /** 生成 InMemoryDexClassLoader 需要的 direct buffer。 */
    public static ByteBuffer buffer(byte[] data) {
        ByteBuffer buffer = ByteBuffer.allocateDirect(data.length);
        buffer.put(data);
        buffer.flip();
        LIVE_BUFFERS.add(buffer);
        return buffer;
    }
}
