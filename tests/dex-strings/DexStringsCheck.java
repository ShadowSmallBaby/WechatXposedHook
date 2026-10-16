import java.io.File;
import java.nio.file.Files;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;

/**
 * 在桌面 JVM 上跑 App 里的 DexStrings,把每个 dex 的命中类数打出来。
 *
 * 输出格式和 Python 参考实现一致,由 run.py 逐行对照:
 *   &lt;dex 名&gt; | &lt;字符串&gt;=&lt;命中类数&gt; | ...
 */
public final class DexStringsCheck {

    /** 用来反查的字符串;前三个是 private_openUrl 的锚点,后三个是启动构造器的锚点。 */
    private static final String[] PROBES = {
            "private_openUrl", "geta8key_open_webview_appid", "open_custom_style_url",
            "MicroMsg.AppBrand.CgiLaunchWxaApp|func:1122", "rawUrl", "url"};

    public static void main(String[] args) throws Exception {
        Class<?> parser = Class.forName(
                "github.shadowbaby.wechatxposed.hook.support.DexStrings");
        Method open = parser.getDeclaredMethod("open", byte[].class);
        Method classesContaining = parser.getDeclaredMethod("classesContaining", String[].class);
        open.setAccessible(true);
        classesContaining.setAccessible(true);

        File[] dexes = new File(args[0]).listFiles();
        if (dexes == null) {
            throw new IllegalStateException("不是目录: " + args[0]);
        }
        Arrays.sort(dexes);
        for (File dex : dexes) {
            if (!dex.getName().endsWith(".dex")) {
                continue;
            }
            Object parsed = open.invoke(null, (Object) Files.readAllBytes(dex.toPath()));
            if (parsed == null) {
                continue;
            }
            StringBuilder line = new StringBuilder(dex.getName());
            for (String probe : PROBES) {
                @SuppressWarnings("unchecked")
                List<String> hits =
                        (List<String>) classesContaining.invoke(parsed, (Object) new String[] {probe});
                line.append(" | ").append(probe).append('=').append(hits.size());
            }
            System.out.println(line);
        }
    }
}
