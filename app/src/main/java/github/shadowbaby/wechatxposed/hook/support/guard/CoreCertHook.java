package github.shadowbaby.wechatxposed.hook.support.guard;

import github.shadowbaby.wechatxposed.hook.deploy.ModuleApk;
import github.shadowbaby.wechatxposed.hook.framework.HookCallback;
import github.shadowbaby.wechatxposed.hook.framework.HookFramework;
import github.shadowbaby.wechatxposed.hook.framework.HookParam;
import github.shadowbaby.wechatxposed.hook.loader.SecretConstants;
import github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import github.shadowbaby.wechatxposed.hook.loader.util.Secret;
import java.io.ByteArrayInputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Collection;

/**
 * 壳的核心 dex 会从 modulePath 的 classes.dex 取签名证书，算 MD5 后与 params 里的
 * "sigs" 比对；不一致就 publish "disable"。这里把证书读取换成原版证书。
 */
public final class CoreCertHook {

    private static final java.util.Set<String> INSTALLED =
            java.util.Collections.synchronizedSet(new java.util.HashSet<String>());

    private static byte[] originalCert;

    private static String originalCertMd5;

    private CoreCertHook() {
    }

    public static synchronized void install(HookFramework framework, ClassLoader loader) {
        try {
            String coreKey = "core@" + System.identityHashCode(loader);
            Class<?> core = framework.findClassIfExists(Secret.of(SecretConstants.CORE_CERT_CLASS), loader);
            if (core != null && INSTALLED.add(coreKey)) {
                framework.hookMethod(core, Secret.of(SecretConstants.CORE_CERT_METHOD), new Class<?>[]{String.class},
                        new HookCallback() {
                            @Override
                            public void before(HookParam param) {
                                byte[] cert = originalCert();
                                if (cert != null) {
                                    param.setResult(cert);
                                }
                            }
                        });
                ModuleLogger.log("core cert hook installed");
            }
            String baseKey = "base@" + System.identityHashCode(loader);
            Class<?> base = framework.findClassIfExists(Secret.of(SecretConstants.CORE_MD5_CLASS), loader);
            if (base != null && INSTALLED.add(baseKey)) {
                framework.hookMethod(base, Secret.of(SecretConstants.CORE_MD5_METHOD), new Class<?>[]{},
                        new HookCallback() {
                            @Override
                            public void before(HookParam param) {
                                String value = originalCertMd5();
                                if (value != null) {
                                    param.setResult(value);
                                }
                            }
                        });
                ModuleLogger.log("base cert hook installed");
            }
        } catch (Throwable error) {
            framework.log(error);
        }
    }

    /** 原版证书 DER 的 MD5，每个字节按 %x 输出（不补零），与壳的算法一致。 */
    private static String originalCertMd5() {
        if (originalCertMd5 != null) {
            return originalCertMd5;
        }
        byte[] cert = originalCert();
        if (cert == null) {
            return null;
        }
        try {
            byte[] digest = java.security.MessageDigest.getInstance("MD5").digest(cert);
            StringBuilder text = new StringBuilder(digest.length * 2);
            for (byte value : digest) {
                text.append(Integer.toHexString(value & 0xFF));
            }
            originalCertMd5 = text.toString();
            ModuleLogger.log("base cert md5 " + originalCertMd5);
            return originalCertMd5;
        } catch (Throwable error) {
            ModuleLogger.log(error);
            return null;
        }
    }

    private static byte[] originalCert() {
        if (originalCert != null) {
            return originalCert;
        }
        try {
            byte[] pkcs7 = ModuleApk.readAsset(Secret.of(SecretConstants.CORE_CERT_ASSET));
            if (pkcs7 == null) {
                return null;
            }
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            Collection<? extends Certificate> certificates = factory.generateCertificates(
                    new ByteArrayInputStream(pkcs7));
            if (certificates.isEmpty()) {
                return null;
            }
            originalCert = certificates.iterator().next().getEncoded();
            ModuleLogger.log("core cert loaded " + originalCert.length + "B");
            return originalCert;
        } catch (Throwable error) {
            ModuleLogger.log(error);
            return null;
        }
    }
}
