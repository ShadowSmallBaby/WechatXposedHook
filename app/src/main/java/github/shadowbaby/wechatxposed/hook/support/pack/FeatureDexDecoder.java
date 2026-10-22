package github.shadowbaby.wechatxposed.hook.support.pack;

import github.shadowbaby.wechatxposed.hook.deploy.ModuleApk;
import github.shadowbaby.wechatxposed.hook.loader.SecretConstants;
import github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import github.shadowbaby.wechatxposed.hook.loader.util.Secret;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * 从扩展包容器解出 classes.dex。
 *
 * 容器格式、字段映射与 PBE/AES 都在 native（Secret.decodeContainer）；
 * Java 只负责读取容器和内层 APK 的标准 zip 条目。
 */
public final class FeatureDexDecoder {

    private static final String PACK_DIR =
            Secret.of(SecretConstants.FEATURE_PACK_ASSET_DIR);

    private FeatureDexDecoder() {
    }

    public static byte[] decode(File filesDir, String feature) {
        String[] entry = Secret.packPlan(feature);
        if (entry == null || entry.length < 4) {
            ModuleLogger.log("feature dex: no plan " + feature);
            return null;
        }
        for (int index = 2; index < entry.length; index++) {
            byte[] container = read(filesDir, entry[index]);
            if (container == null) {
                continue;
            }
            byte[] dex = decrypt(container, entry[0], entry[1]);
            if (dex != null) {
                ModuleLogger.log("feature dex: decoded " + feature + " " + dex.length + "B");
                return dex;
            }
        }
        ModuleLogger.log("feature dex: decode failed " + feature);
        return null;
    }

    private static byte[] read(File filesDir, String name) {
        try {
            if (filesDir != null) {
                File file = new File(new File(filesDir, Secret.of(SecretConstants.FEATURE_PACK_DIR)), name);
                if (file.isFile()) {
                    return readFile(file);
                }
            }
        } catch (Throwable error) {
            ModuleLogger.log(error);
        }
        byte[] data = ModuleApk.readAsset(name);
        if (data == null) {
            data = ModuleApk.readAsset(PACK_DIR + name);
        }
        return data;
    }

    private static byte[] decrypt(byte[] container, String outerPassword,
            String innerPassword) {
        try {
            byte[] apk = Secret.decodeContainer(container, outerPassword, innerPassword);
            if (apk == null || apk.length < 4 || apk[0] != 'P' || apk[1] != 'K') {
                return null;
            }
            return readDex(apk);
        } catch (Throwable error) {
            ModuleLogger.log(error);
            return null;
        }
    }

    private static byte[] readDex(byte[] apk) throws Exception {
        try (ZipInputStream input = new ZipInputStream(
                new ByteArrayInputStream(apk))) {
            ZipEntry entry;
            while ((entry = input.getNextEntry()) != null) {
                if (!"classes.dex".equals(entry.getName())) {
                    continue;
                }
                byte[] dex = readAll(input);
                if (dex.length > 8 && dex[0] == 'd' && dex[1] == 'e'
                        && dex[2] == 'x' && dex[3] == '\n') {
                    return dex;
                }
                return null;
            }
        }
        return null;
    }

    private static byte[] readAll(InputStream input) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[16 * 1024];
        int count;
        while ((count = input.read(buffer)) > 0) {
            output.write(buffer, 0, count);
        }
        return output.toByteArray();
    }

    private static byte[] readFile(File file) throws Exception {
        try (InputStream input = new FileInputStream(file)) {
            return readAll(input);
        }
    }
}
