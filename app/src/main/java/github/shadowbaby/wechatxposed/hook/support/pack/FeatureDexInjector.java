package github.shadowbaby.wechatxposed.hook.support.pack;

import github.shadowbaby.wechatxposed.hook.BuildConfig;
import github.shadowbaby.wechatxposed.hook.deploy.DexIntegrity;
import github.shadowbaby.wechatxposed.hook.deploy.ModuleApk;
import github.shadowbaby.wechatxposed.hook.deploy.ModuleCertCheck;
import github.shadowbaby.wechatxposed.hook.license.Activation;
import github.shadowbaby.wechatxposed.hook.loader.SecretConstants;
import github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import github.shadowbaby.wechatxposed.hook.loader.util.Secret;
import github.shadowbaby.wechatxposed.hook.support.guard.RuntimeGuard;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
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

    private static final String ASSET_DIR =
            Secret.of(SecretConstants.FEATURE_DEX_DIR);

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
        if (!BuildConfig.FULL_EDITION) {
            return;
        }
        if (feature == null || feature.isEmpty()) {
            return;
        }
        // 高级激活才注入扩展 dex。
        if (!Activation.isExtensionAllowed()
                || !ModuleCertCheck.verify(ModuleApk.modulePath())
                || !DexIntegrity.verify(ModuleApk.modulePath())
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

    /** 读取组件 dex：优先从扩展包容器运行时解密，旧 APK 回退到 featuredex 资产。 */
    public static byte[] dex(String feature) {
        byte[] cached = CACHE.get(feature);
        if (cached != null) {
            return cached;
        }
        byte[] data = FeatureDexDecoder.decode(filesDir, feature);
        if (data == null) {
            data = legacyDex(feature);
        }
        if (data != null) {
            CACHE.put(feature, data);
        }
        return data;
    }

    private static byte[] legacyDex(String feature) {
        String name = assetName(feature);
        byte[] data = null;
        try {
            File directory = filesDir;
            if (directory == null) {
                return null;
            }
            File target = new File(directory, Secret.of(SecretConstants.FEATURE_DEX_INJECTED) + name);
            if (!target.isFile() || target.length() == 0) {
                File parent = target.getParentFile();
                if (parent != null) {
                    parent.mkdirs();
                }
                if (!ModuleApk.extractPayload(ASSET_DIR + name, target)) {
                    ModuleLogger.log("feature dex: asset missing " + feature);
                }
            }
            if (target.isFile() && target.length() > 0) {
                data = read(target);
            }
        } catch (Throwable error) {
            ModuleLogger.log(error);
        }
        return data;
    }

    private static String assetName(String feature) {
        return Secret.of(SecretConstants.FEATURE_DEX_PREFIX)
                + feature.substring(4) + Secret.of(SecretConstants.FEATURE_DEX_SUFFIX);
    }

    private static byte[] read(File file) throws Exception {
        try (InputStream input = new FileInputStream(file);
                ByteArrayOutputStream output = new ByteArrayOutputStream((int) file.length())) {
            byte[] buffer = new byte[16 * 1024];
            int count;
            while ((count = input.read(buffer)) > 0) {
                output.write(buffer, 0, count);
            }
            return output.toByteArray();
        }
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
