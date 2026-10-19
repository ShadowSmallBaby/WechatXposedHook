package github.shadowbaby.wechatxposed.hook.loader;

import github.shadowbaby.wechatxposed.hook.framework.HookParam;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;

/**
 * 调试用：把 {@code InMemoryDexClassLoader} 构造时传入的 dex 字节落盘。
 *
 * 仅在微信数据目录存在标记文件 {@code files/wxh_dump_dex} 时启用；用于分析
 * 新版本微X（例如 X 3.0）运行时解密的 dex。分析完删除标记即可停止。
 */
public final class DexDumper {

    public static final String MARKER = "wxh_dump_dex";
    public static final String DIR = "dex_dump";

    private static final byte[] DEX_MAGIC = {'d', 'e', 'x', '\n'};

    private static File directory;
    private static int counter;

    private DexDumper() {
    }

    public static synchronized void setDirectory(File target) {
        if (target == null) {
            return;
        }
        if (!target.isDirectory() && !target.mkdirs()) {
            ModuleLogger.log("dex dump: cannot create " + target);
            return;
        }
        directory = target;
        ModuleLogger.log("dex dump: " + target);
    }

    public static void maybeDump(HookParam param) {
        if (directory == null) {
            return;
        }
        Object first = param.arg(0);
        if (first instanceof ByteBuffer buffer) {
            dump(buffer);
        } else if (first instanceof ByteBuffer[] buffers) {
            for (ByteBuffer buffer : buffers) {
                dump(buffer);
            }
        }
    }

    private static void dump(ByteBuffer source) {
        try {
            ByteBuffer buffer = source.duplicate();
            buffer.rewind();
            if (buffer.remaining() < DEX_MAGIC.length) {
                return;
            }
            byte[] magic = new byte[DEX_MAGIC.length];
            buffer.get(magic);
            for (int index = 0; index < DEX_MAGIC.length; index++) {
                if (magic[index] != DEX_MAGIC[index]) {
                    return;
                }
            }
            buffer.rewind();
            byte[] payload = new byte[buffer.remaining()];
            buffer.get(payload);

            File target;
            synchronized (DexDumper.class) {
                target = new File(directory, "dex-" + System.currentTimeMillis()
                        + "-" + counter++ + ".dex");
            }
            try (FileOutputStream output = new FileOutputStream(target)) {
                output.write(payload);
            }
            ModuleLogger.log("dex dump: " + target.getName() + " " + payload.length + " B");
        } catch (Throwable error) {
            ModuleLogger.log(error);
        }
    }
}
