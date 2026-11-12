package io.github.shadowbaby.wechatxposed.tool.hook.spoof;

import io.github.shadowbaby.wechatxposed.tool.BuildConfig;


public final class SpoofTrust {
    private SpoofTrust() {}
    public static final String CERT_SHA256 = "a325f9acc4b0bc154efeab4673fb35aa68f4f5e63c926f0206fa614810503713";
    public static final int MAX_CERT_BYTES = 16 * 1024;
    private static volatile byte[] publicDer;

    public static final class LoadFailure extends IllegalArgumentException {
        public final String reason;
        public final boolean retryable;

        private LoadFailure(String reason, boolean retryable, Throwable cause) {
            super("SPF trust asset: " + reason, cause);
            this.reason = reason;
            this.retryable = retryable;
        }
    }

    public static void initialize(byte[] certificate) {
        try {
            if (certificate == null || certificate.length == 0 || certificate.length > MAX_CERT_BYTES)
                throw new LoadFailure("certificate-size", false, null);
            byte[] bytes = certificate.clone();
            byte[] expected = new byte[32];
            for (int i = 0; i < expected.length; i++)
                expected[i] = (byte) Integer.parseInt(CERT_SHA256.substring(i * 2, i * 2 + 2), 16);
            if (!java.security.MessageDigest.isEqual(expected, java.security.MessageDigest.getInstance("SHA-256").digest(bytes)))
                throw new LoadFailure("certificate-identity", false, null);
            var input = new java.io.ByteArrayInputStream(bytes);
            var cert = (java.security.cert.X509Certificate) java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(input);
            if (input.available() != 0 || !(cert.getPublicKey() instanceof java.security.interfaces.RSAPublicKey key)
                    || key.getModulus().bitLength() != 2048) throw new LoadFailure("certificate-key", false, null);
            publicDer = key.getEncoded();
        } catch (LoadFailure error) { throw error; }
        catch (Exception error) { throw new LoadFailure("certificate-format", false, error); }
    }

    public static byte[] publicBytes() {
        byte[] value = publicDer;
        if (value == null) throw new IllegalArgumentException("SPF trust asset not loaded");
        return value.clone();
    }

    public static void loadFromApk(String apkPath) {
        if (apkPath == null || apkPath.isBlank()) throw new LoadFailure("apk-path-unavailable", false, null);
        try (var zip = new java.util.zip.ZipFile(apkPath)) {
            var entry = zip.getEntry("assets/" + BuildConfig.SPOOF_CERT_ASSET);
            if (entry == null) throw new LoadFailure("certificate-missing", false, null);
            try (var input = zip.getInputStream(entry)) {
                load(input);
            } catch (java.io.IOException error) {
                throw new LoadFailure("certificate-read", true, error);
            }
        } catch (LoadFailure error) { throw error; }
        catch (java.util.zip.ZipException error) { throw new LoadFailure("apk-format", false, error); }
        catch (java.io.IOException error) { throw new LoadFailure("apk-read", true, error); }
        catch (SecurityException error) { throw new LoadFailure("apk-access", true, error); }
    }

    public static void load(java.io.InputStream input) throws java.io.IOException {
        var output = new java.io.ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int count;
        while ((count = input.read(buffer)) != -1) {
            if (output.size() + count > MAX_CERT_BYTES) throw new LoadFailure("certificate-size", false, null);
            output.write(buffer, 0, count);
        }
        initialize(SpoofCodec.stripHash(output.toByteArray()));
    }
}
