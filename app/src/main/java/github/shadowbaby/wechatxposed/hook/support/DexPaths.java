package github.shadowbaby.wechatxposed.hook.support;

import github.shadowbaby.wechatxposed.hook.loader.ModuleLogger;
import github.shadowbaby.wechatxposed.hook.loader.Secret;
import github.shadowbaby.wechatxposed.hook.loader.SecretConstants;
import java.io.File;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

final class DexPaths {

    private static final String LOG = ModuleLogger.HOST_SPOOF_PREFIX;

    private DexPaths() {
    }

    static List<byte[]> of(String apkPath) {
        if (apkPath == null || apkPath.isEmpty()) {
            ModuleLogger.log(LOG + "sourceDir empty");
            return Collections.emptyList();
        }
        File apk = new File(apkPath);
        if (!apk.isFile()) {
            ModuleLogger.log(LOG + "apk missing " + apkPath);
            return Collections.emptyList();
        }
        List<byte[]> result = new ArrayList<>();
        try (ZipFile zip = new ZipFile(apk)) {
            List<String> names = new ArrayList<>();
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String name = entry.getName();
                if (name.startsWith(Secret.of(SecretConstants.DEX_PREFIX))
                        && name.endsWith(Secret.of(SecretConstants.DEX_SUFFIX))
                        && !entry.isDirectory()) {
                    names.add(name);
                }
            }
            Collections.sort(names);
            for (String name : names) {
                try (InputStream in = zip.getInputStream(zip.getEntry(name))) {
                    ByteArrayOutputStream out = new ByteArrayOutputStream();
                    byte[] buffer = new byte[64 * 1024];
                    int read;
                    while ((read = in.read(buffer)) > 0) {
                        out.write(buffer, 0, read);
                    }
                    result.add(out.toByteArray());
                } catch (IOException error) {
                    ModuleLogger.log(LOG + "read " + name + " failed: " + error);
                }
            }
        } catch (IOException error) {
            ModuleLogger.log(LOG + "open apk failed: " + error);
            return result;
        }
        return result;
    }
}
