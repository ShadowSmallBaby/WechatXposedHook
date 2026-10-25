package github.shadowbaby.wechatxposed.hook.deploy;

import github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * dex 段完整性。
 *
 * 构建时 build_x30_replica.py 把最终 classes*.dex 的 SHA-256 写入
 * assets/wxh_integrity；启动时读同一 APK 的 dex 重新计算。证书固定通过
 * 后，重打包者即使换签名也会被 ModuleCertCheck 拦住；同签名篡改 dex
 * 则由本类拦住，两者都失败只关闭扩展功能。
 */
public final class DexIntegrity {

    private static final String PLAN_ENTRY = "assets/wxh_integrity";

    private static volatile Boolean trusted;

    private DexIntegrity() {
    }

    public static synchronized boolean verify(String modulePath) {
        Boolean cached = trusted;
        if (cached != null) {
            return cached;
        }
        if (modulePath == null || !new File(modulePath).isFile()) {
            trusted = false;
            ModuleLogger.log("dex integrity: module missing");
            return false;
        }
        try (ZipFile apk = new ZipFile(modulePath)) {
            ZipEntry plan = apk.getEntry(PLAN_ENTRY);
            if (plan == null) {
                // 散包方案：功能包以 assets 散包形式存在，不在 APK 的 dex 列表里，
                // plan 自然缺失。完整性由 ModuleCertCheck + RuntimeGuard + 包签名保障。
                trusted = true;
                ModuleLogger.log("dex integrity: plan missing (skip)");
                return true;
            }
            String text = new String(readAll(apk.getInputStream(plan)),
                    java.nio.charset.StandardCharsets.US_ASCII);
            for (String line : text.split("\\n")) {
                int separator = line.indexOf(':');
                if (separator <= 0 || separator + 1 >= line.length()) {
                    continue;
                }
                String name = line.substring(0, separator).trim();
                String expected = line.substring(separator + 1).trim();
                ZipEntry dex = apk.getEntry(name);
                if (dex == null) {
                    trusted = false;
                    ModuleLogger.log("dex integrity: missing " + name);
                    return false;
                }
                String actual = sha256(apk.getInputStream(dex));
                if (!expected.equalsIgnoreCase(actual)) {
                    trusted = false;
                    ModuleLogger.log("dex integrity: mismatch " + name);
                    return false;
                }
            }
            trusted = true;
            ModuleLogger.debug("dex integrity: ok");
            return true;
        } catch (Throwable error) {
            trusted = false;
            ModuleLogger.log(error);
            return false;
        }
    }

    public static boolean isTrusted() {
        Boolean value = trusted;
        return value == null || value;
    }

    private static String sha256(InputStream input) throws Exception {
        try (InputStream stream = input) {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] buffer = new byte[64 * 1024];
            int read;
            while ((read = stream.read(buffer)) > 0) {
                digest.update(buffer, 0, read);
            }
            byte[] hash = digest.digest();
            StringBuilder text = new StringBuilder(hash.length * 2);
            for (byte value : hash) {
                text.append(String.format(Locale.US, "%02x", value));
            }
            return text.toString();
        }
    }

    private static byte[] readAll(InputStream input) throws Exception {
        try (InputStream stream = input;
                ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8 * 1024];
            int read;
            while ((read = stream.read(buffer)) > 0) {
                output.write(buffer, 0, read);
            }
            return output.toByteArray();
        }
    }
}
