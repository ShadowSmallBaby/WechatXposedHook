package github.shadowbaby.wechatxposed.hook.deploy;

import github.shadowbaby.wechatxposed.hook.loader.SecretConstants;
import github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import github.shadowbaby.wechatxposed.hook.loader.util.Secret;
import java.io.File;
import java.io.RandomAccessFile;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Locale;

/**
 * 模块 APK 证书自检。
 *
 * 构建时把签名证书 SHA-256 加密进 SecretConstants；启动时直接解析 APK
 * Signing Block（v2/v3）取证书，绕开 PackageManager / JarEntry。壳的
 * X30Compat 会把模块 APK 的签名查询替换成原版证书，因此不能用
 * getPackageArchiveInfo。
 *
 * 不一致只关闭扩展功能，不崩溃；解析失败按不可信处理。
 */
public final class ModuleCertCheck {

    private static final int EOCD_MAGIC = 0x06054b50;
    private static final int APK_SIG_BLOCK_MAGIC_LOW = 0x204b5041;
    private static final int APK_SIG_BLOCK_MAGIC_HIGH = 0x20676953;
    private static final int V2_BLOCK_ID = 0x7109871a;
    private static final int V3_BLOCK_ID = 0xf05368c0;

    private static volatile Boolean trusted;

    private ModuleCertCheck() {
    }

    public static synchronized boolean verify(String modulePath) {
        Boolean cached = trusted;
        if (cached != null) {
            return cached;
        }
        try {
            String expected = Secret.of(SecretConstants.MODULE_CERT_SHA256);
            if (expected == null || expected.isEmpty()) {
                trusted = true;
                return true;
            }
            String actual = signingCertificateSha256(modulePath);
            if (actual == null) {
                trusted = false;
                ModuleLogger.log("module cert: unreadable " + modulePath);
                return false;
            }
            boolean ok = expected.equalsIgnoreCase(actual);
            trusted = ok;
            if (ok) {
                ModuleLogger.debug("module cert: ok");
            } else {
                ModuleLogger.log("module cert: mismatch expected=" + expected
                        + " actual=" + actual);
            }
            return ok;
        } catch (Throwable error) {
            trusted = false;
            ModuleLogger.log(error);
            return false;
        }
    }

    /** 尚未得出结论时按可信处理，避免启动早期误伤基础功能。 */
    public static boolean isTrusted() {
        Boolean value = trusted;
        return value == null || value;
    }

    /** 直接从 APK Signing Block 取第一个签名证书的 SHA-256。 */
    private static String signingCertificateSha256(String path) {
        if (path == null) {
            return null;
        }
        File file = new File(path);
        if (!file.isFile()) {
            return null;
        }
        try (RandomAccessFile apk = new RandomAccessFile(file, "r")) {
            long fileLength = apk.length();
            if (fileLength < 32) {
                return null;
            }
            byte[] tail = read(apk, Math.max(0, fileLength - (22 + 0xffff)),
                    (int) Math.min(fileLength, 22 + 0xffffL));
            int eocd = lastEocd(tail);
            if (eocd < 0) {
                return null;
            }
            long centralSize = u32(tail, eocd + 12) & 0xffffffffL;
            long centralOffset = u32(tail, eocd + 16) & 0xffffffffL;
            if (centralSize == 0xffffffffL || centralOffset == 0xffffffffL
                    || centralOffset < 32 || centralOffset > fileLength) {
                return null;
            }
            byte[] footer = read(apk, centralOffset - 24, 24);
            if (u64(footer, 0) == 0
                    || u32(footer, 8) != APK_SIG_BLOCK_MAGIC_LOW
                    || u32(footer, 12) != APK_SIG_BLOCK_MAGIC_HIGH) {
                return null;
            }
            long blockSize = u64(footer, 0);
            long blockStart = centralOffset - blockSize - 8;
            if (blockStart < 0 || blockSize > Integer.MAX_VALUE - 24) {
                return null;
            }
            byte[] block = read(apk, blockStart, (int) (blockSize + 8));
            if (u64(block, 0) != blockSize) {
                return null;
            }
            byte[] v2 = null;
            byte[] v3 = null;
            int position = 8;
            int pairsEnd = block.length - 24;
            while (position + 12 <= pairsEnd) {
                long pairLength = u64(block, position);
                position += 8;
                if (pairLength < 4 || pairLength > pairsEnd - position) {
                    break;
                }
                int id = u32(block, position);
                position += 4;
                int valueLength = (int) pairLength - 4;
                if (id == V3_BLOCK_ID) {
                    v3 = Arrays.copyOfRange(block, position, position + valueLength);
                } else if (id == V2_BLOCK_ID) {
                    v2 = Arrays.copyOfRange(block, position, position + valueLength);
                }
                position += valueLength;
            }
            byte[] certificate = v3 != null ? firstCertificate(v3) : null;
            if (certificate == null && v2 != null) {
                certificate = firstCertificate(v2);
            }
            if (certificate == null) {
                return null;
            }
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(certificate);
            StringBuilder text = new StringBuilder(digest.length * 2);
            for (byte value : digest) {
                text.append(String.format(Locale.US, "%02x", value));
            }
            return text.toString();
        } catch (Throwable error) {
            return null;
        }
    }

    /** v2/v3 的 signers 序列中，第一个 signer 的 signedData.certificates[0]。 */
    private static byte[] firstCertificate(byte[] value) {
        if (value.length < 8) {
            return null;
        }
        int signersLength = u32(value, 0);
        int signersEnd = 4 + signersLength;
        if (signersLength <= 0 || signersEnd > value.length) {
            return null;
        }
        int position = 4;
        while (position + 4 <= signersEnd) {
            int signerLength = u32(value, position);
            position += 4;
            int signerEnd = position + signerLength;
            if (signerLength < 8 || signerEnd > signersEnd) {
                return null;
            }
            int signedDataLength = u32(value, position);
            position += 4;
            int signedDataEnd = position + signedDataLength;
            if (signedDataLength < 8 || signedDataEnd > signerEnd) {
                return null;
            }
            int digestsLength = u32(value, position);
            position += 4;
            if (digestsLength < 0 || position + digestsLength + 4 > signedDataEnd) {
                return null;
            }
            position += digestsLength;
            int certificatesLength = u32(value, position);
            position += 4;
            int certificatesEnd = position + certificatesLength;
            if (certificatesLength >= 4 && certificatesEnd <= signedDataEnd) {
                int certificateLength = u32(value, position);
                position += 4;
                if (certificateLength > 0 && position + certificateLength <= certificatesEnd) {
                    return Arrays.copyOfRange(value, position,
                            position + certificateLength);
                }
            }
            position = signerEnd;
        }
        return null;
    }

    private static int lastEocd(byte[] data) {
        for (int index = data.length - 22; index >= 0; index--) {
            if (u32(data, index) == EOCD_MAGIC) {
                return index;
            }
        }
        return -1;
    }

    private static byte[] read(RandomAccessFile file, long position, int length)
            throws Exception {
        byte[] data = new byte[length];
        file.seek(position);
        file.readFully(data);
        return data;
    }

    private static int u32(byte[] data, int offset) {
        return (data[offset] & 0xff)
                | ((data[offset + 1] & 0xff) << 8)
                | ((data[offset + 2] & 0xff) << 16)
                | ((data[offset + 3] & 0xff) << 24);
    }

    private static long u64(byte[] data, int offset) {
        return (u32(data, offset) & 0xffffffffL)
                | ((u32(data, offset + 4) & 0xffffffffL) << 32);
    }
}
