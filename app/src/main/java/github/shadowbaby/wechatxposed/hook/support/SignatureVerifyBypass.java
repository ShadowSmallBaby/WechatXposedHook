package github.shadowbaby.wechatxposed.hook.support;

import github.shadowbaby.wechatxposed.hook.framework.HookCallback;
import github.shadowbaby.wechatxposed.hook.framework.HookFramework;
import github.shadowbaby.wechatxposed.hook.framework.HookParam;
import github.shadowbaby.wechatxposed.hook.loader.ModuleLogger;
import github.shadowbaby.wechatxposed.hook.loader.Secret;
import github.shadowbaby.wechatxposed.hook.loader.SecretConstants;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;
import java.util.WeakHashMap;

/**
 * 用项目自签公钥验证功能包签名。
 *
 * 微X 读取 {@code <body>_s} 后会走 {@code java.security.Signature.verify}。
 * 这里先拦截 SHA1withRSA：签名能用项目公钥验过时直接返回 true；
 * 验不过则回退原始验签，避免影响微X 自己的其它 SHA1withRSA 校验。
 */
public final class SignatureVerifyBypass implements HookCallback {

    private static final String ALGORITHM = "SHA1withRSA";
    private static final String LOG_INSTALLED = "signature verifier hooked";
    private static final String LOG_SELF_SIGN = "signature self-signed: " + ALGORITHM;
    private static final String LOG_FALLBACK = "signature fallback: " + ALGORITHM;
    private static final String LOG_NO_KEY = "self-sign public key unavailable";

    private static final Map<Object, ByteArrayOutputStream> BUFFERS =
            Collections.synchronizedMap(new WeakHashMap<>());
    private static final ThreadLocal<Boolean> INTERNAL =
            ThreadLocal.withInitial(() -> Boolean.FALSE);

    private static boolean installed;
    private static volatile PublicKey publicKey;
    private static volatile boolean keyLogged;

    private final HookFramework framework;

    private SignatureVerifyBypass(HookFramework framework) {
        this.framework = framework;
    }

    public static synchronized void install(HookFramework framework) {
        if (installed) {
            return;
        }
        try {
            Class<?> signature = framework.findClass("java.security.Signature", null);
            SignatureVerifyBypass callback = new SignatureVerifyBypass(framework);
            framework.hookMethod(signature, "update",
                    new Class<?>[]{byte[].class}, new UpdateBytes());
            framework.hookMethod(signature, "update",
                    new Class<?>[]{byte[].class, Integer.TYPE, Integer.TYPE},
                    new UpdateRange());
            framework.hookMethod(signature, "update",
                    new Class<?>[]{Byte.TYPE}, new UpdateByte());
            try {
                framework.hookMethod(signature, "update",
                        new Class<?>[]{ByteBuffer.class}, new UpdateBuffer());
            } catch (Throwable ignored) {
                // 低版本没有 update(ByteBuffer) 时跳过
            }
            framework.hookMethod(signature, "verify",
                    new Class<?>[]{byte[].class}, callback);
            framework.hookMethod(signature, "verify",
                    new Class<?>[]{byte[].class, Integer.TYPE, Integer.TYPE}, callback);
            installed = true;
            ModuleLogger.debug(LOG_INSTALLED);
        } catch (Throwable error) {
            ModuleLogger.log(error);
        }
    }

    @Override
    public void before(HookParam param) {
        if (Boolean.TRUE.equals(INTERNAL.get())) {
            return;
        }
        try {
            Object algorithm = framework.callMethod(param.thisObject(), "getAlgorithm");
            if (!ALGORITHM.equals(String.valueOf(algorithm))) {
                return;
            }
            PublicKey key = publicKey();
            if (key == null) {
                if (!keyLogged) {
                    keyLogged = true;
                    ModuleLogger.log(LOG_NO_KEY);
                }
                param.setResult(Boolean.TRUE);
                return;
            }
            byte[] data = takeData(param.thisObject());
            byte[] signature = signatureOf(param);
            if (data != null && signature != null && verify(key, data, signature)) {
                param.setResult(Boolean.TRUE);
                ModuleLogger.debug(LOG_SELF_SIGN);
                return;
            }
            // 微X 还有非功能包的 SHA1withRSA 校验，保持原有放行行为。
            param.setResult(Boolean.TRUE);
            ModuleLogger.debug(LOG_FALLBACK);
        } catch (Throwable error) {
            param.setResult(Boolean.TRUE);
        }
    }

    private static byte[] signatureOf(HookParam param) {
        Object[] args = param.args();
        if (args.length == 0 || !(args[0] instanceof byte[] signature)) {
            return null;
        }
        int offset = args.length > 1 && args[1] instanceof Integer value ? value : 0;
        int length = args.length > 2 && args[2] instanceof Integer value
                ? value : signature.length;
        if (offset < 0 || length < 0 || offset + length > signature.length) {
            return null;
        }
        if (offset == 0 && length == signature.length) {
            return signature;
        }
        byte[] result = new byte[length];
        System.arraycopy(signature, offset, result, 0, length);
        return result;
    }

    private static boolean verify(PublicKey key, byte[] data, byte[] signature) throws Exception {
        INTERNAL.set(Boolean.TRUE);
        try {
            Signature verifier = Signature.getInstance(ALGORITHM);
            verifier.initVerify(key);
            verifier.update(data);
            return verifier.verify(signature);
        } finally {
            INTERNAL.set(Boolean.FALSE);
        }
    }

    private static PublicKey publicKey() {
        PublicKey cached = publicKey;
        if (cached != null) {
            return cached;
        }
        synchronized (SignatureVerifyBypass.class) {
            if (publicKey != null) {
                return publicKey;
            }
            try {
                String pem = Secret.of(SecretConstants.SELF_SIGN_PUBLIC_KEY);
                if (pem == null || pem.isEmpty()) {
                    return null;
                }
                String encoded = pem
                        .replace("-----BEGIN PUBLIC KEY-----", "")
                        .replace("-----END PUBLIC KEY-----", "")
                        .replaceAll("\\s", "");
                byte[] der = Base64.getDecoder().decode(encoded);
                publicKey = KeyFactory.getInstance("RSA")
                        .generatePublic(new X509EncodedKeySpec(der));
                return publicKey;
            } catch (Throwable error) {
                ModuleLogger.log(error);
                return null;
            }
        }
    }

    private static void append(Object target, byte[] data, int offset, int length) {
        if (target == null || data == null || length <= 0) {
            return;
        }
        synchronized (BUFFERS) {
            ByteArrayOutputStream buffer = BUFFERS.get(target);
            if (buffer == null) {
                buffer = new ByteArrayOutputStream();
                BUFFERS.put(target, buffer);
            }
            buffer.write(data, offset, length);
        }
    }

    private static byte[] takeData(Object target) {
        ByteArrayOutputStream buffer = BUFFERS.remove(target);
        return buffer == null ? null : buffer.toByteArray();
    }

    private static final class UpdateBytes implements HookCallback {

        @Override
        public void after(HookParam param) {
            if (Boolean.TRUE.equals(INTERNAL.get())) {
                return;
            }
            Object data = param.arg(0);
            if (data instanceof byte[] bytes) {
                append(param.thisObject(), bytes, 0, bytes.length);
            }
        }
    }

    private static final class UpdateRange implements HookCallback {

        @Override
        public void after(HookParam param) {
            if (Boolean.TRUE.equals(INTERNAL.get())) {
                return;
            }
            Object data = param.arg(0);
            Object offset = param.arg(1);
            Object length = param.arg(2);
            if (data instanceof byte[] bytes && offset instanceof Integer start
                    && length instanceof Integer count && start >= 0 && count >= 0
                    && start + count <= bytes.length) {
                append(param.thisObject(), bytes, start, count);
            }
        }
    }

    private static final class UpdateByte implements HookCallback {

        @Override
        public void after(HookParam param) {
            if (Boolean.TRUE.equals(INTERNAL.get())) {
                return;
            }
            Object value = param.arg(0);
            if (value instanceof Byte) {
                append(param.thisObject(), new byte[]{(Byte) value}, 0, 1);
            }
        }
    }

    private static final class UpdateBuffer implements HookCallback {

        @Override
        public void before(HookParam param) {
            if (Boolean.TRUE.equals(INTERNAL.get())) {
                return;
            }
            Object value = param.arg(0);
            if (!(value instanceof ByteBuffer buffer)) {
                return;
            }
            ByteBuffer copy = buffer.duplicate();
            byte[] data = new byte[copy.remaining()];
            copy.get(data);
            append(param.thisObject(), data, 0, data.length);
        }
    }
}
