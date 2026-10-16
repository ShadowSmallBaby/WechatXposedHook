import java.io.File;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;

/**
 * 在设备上验证 App 里的类名常量能不能从真的 dex 里解析出来。
 *
 * 只做一件事:把 dex 用 InMemoryDexClassLoader 装起来,对每个类名分别用点号形式和斜杠形式
 * 调 Class.forName,把结果打出来。run.py 负责比对。
 */
public final class ClassProbe {

    public static void main(String[] args) throws Exception {
        File dex = new File(args[0]);
        List<String> names = Files.readAllLines(new File(args[1]).toPath(), StandardCharsets.UTF_8);
        ClassLoader loader = inMemory(dex);
        for (String name : names) {
            if (name.isEmpty()) {
                continue;
            }
            System.out.println("NAME " + name
                    + " dotted=" + probe(loader, name)
                    + " slashed=" + probe(loader, name.replace('.', '/')));
        }
    }

    /** 返回 "ok" 或者异常类名。 */
    private static String probe(ClassLoader loader, String name) {
        try {
            Class.forName(name, false, loader);
            return "ok";
        } catch (Throwable error) {
            return error.getClass().getSimpleName();
        }
    }

    private static ClassLoader inMemory(File dex) throws Exception {
        try (RandomAccessFile file = new RandomAccessFile(dex, "r");
                FileChannel channel = file.getChannel()) {
            ByteBuffer buffer = channel.map(FileChannel.MapMode.READ_ONLY, 0, channel.size());
            return new dalvik.system.InMemoryDexClassLoader(buffer, ClassProbe.class.getClassLoader());
        }
    }
}
