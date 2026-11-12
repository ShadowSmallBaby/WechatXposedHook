package io.github.shadowbaby.wechatxposed.tool.hook.spoof;

import org.json.JSONObject;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.charset.CodingErrorAction;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public final class SpoofCodec {
    public static final int MAX_ENCODED = 3 * 1024 * 1024;
    private static final int MAX_PLAIN = 2 * 1024 * 1024;
    private static final byte[] MAGIC = "WXSPF1".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] DOMAIN = "WXH-SPF-AES-GCM-v1\0".getBytes(StandardCharsets.UTF_8);
    private SpoofCodec() {}

    public static byte[] stripHash(byte[] raw) {
        if (raw == null || raw.length <= 32) return raw;
        try {
            byte[] body = Arrays.copyOfRange(raw, 32, raw.length);
            byte[] actual = MessageDigest.getInstance("SHA-256").digest(body);
            byte[] expected = Arrays.copyOf(raw, 32);
            return MessageDigest.isEqual(expected, actual) ? body : raw;
        } catch (Exception error) {
            return raw;
        }
    }

    public static String text(byte[] raw) {
        return new String(stripHash(raw), StandardCharsets.US_ASCII).trim();
    }

    public static JSONObject decode(String encoded) {
        try {
            if (encoded == null || encoded.length() > MAX_ENCODED) throw new IllegalArgumentException("SPF size");
            byte[] data = Base64.getDecoder().decode(encoded.trim());
            if (data.length < 294 || !Arrays.equals(MAGIC, Arrays.copyOf(data, 6))) throw new IllegalArgumentException("SPF header");
            int size = ByteBuffer.wrap(data, 18, 4).getInt();
            if (size <= 16 || size > MAX_PLAIN + 16 || data.length != 22L + size + 256) throw new IllegalArgumentException("SPF length");
            byte[] publicDer = SpoofTrust.publicBytes();
            Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicDer)));
            verifier.update(data, 0, 22 + size);
            if (!verifier.verify(data, 22 + size, 256)) throw new IllegalArgumentException("SPF signature");
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(DOMAIN);
            byte[] aesKey = digest.digest(publicDer);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKey, "AES"), new GCMParameterSpec(128, data, 6, 12));
            cipher.updateAAD(data, 0, 22);
            byte[] plain = cipher.doFinal(data, 22, size);
            String text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(plain)).toString();
            return new JSONObject(text);
        } catch (Exception error) {
            throw new IllegalArgumentException("Invalid signed SPF", error);
        }
    }

    public static String version(JSONObject root) {
        Object version = root.opt("VERSION");
        if (!(version instanceof String text) || !text.matches("[0-9a-f]{1,16}")) throw new IllegalArgumentException("SPF VERSION");
        return text;
    }
}
