package github.shadowbaby.wechatxposed.hook.support;

import android.text.TextUtils;
import android.util.Base64;
import github.shadowbaby.wechatxposed.hook.BuildConfig;
import github.shadowbaby.wechatxposed.hook.framework.HookCallback;
import github.shadowbaby.wechatxposed.hook.framework.HookFramework;
import github.shadowbaby.wechatxposed.hook.framework.HookParam;
import github.shadowbaby.wechatxposed.hook.loader.CurrentAccount;
import github.shadowbaby.wechatxposed.hook.loader.Secret;
import github.shadowbaby.wechatxposed.hook.loader.SecretConstants;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public final class CallMethodBypassHook implements HookCallback {

    public static final int VERIFIER_MESSAGE = 0;

    public static final int LICENSE_CONTEXT = 1;

    public static final int PASSTHROUGH = 2;

    private static final int MSG_VERIFY_RESULT = 130;

    private static final int MSG_LICENSE_BLOB = 132;

    private static final int MSG_FEATURE_QUERY = 150;

    private static final String VERIFIER_SERVICE = Secret.of(SecretConstants.VERIFIER_SERVICE);

    private static final String ACTION_PARAM = Secret.of(SecretConstants.ACTION_PARAM);

    private static final String FIELD_SEPARATOR = ":";

    private static final String NULL_TEXT = "null";

    private static final String TRUE_TEXT = "true";

    private static final String MIN_SUPPORTED_VERSION = Secret.of(SecretConstants.MIN_SUPPORTED_VERSION);

    private static final String UNLIMITED = Secret.of(SecretConstants.UNLIMITED);

    private static final String REMOTE_COMMAND = Secret.of(SecretConstants.REMOTE_COMMAND);

    private static final String PAYLOAD_SEPARATOR = "#";

    private static final String OBJECTS_CLASS = Secret.of(SecretConstants.OBJECTS_CLASS);
    private static final String OBJECTS_EQUALS_METHOD = Secret.of(SecretConstants.OBJECTS_EQUALS_METHOD);

    private static final String VERIFIER_SERVICE_CLASS = Secret.of(SecretConstants.VERIFIER_SERVICE_CLASS);
    private static final String VERIFIER_SERVICE_FACTORY = Secret.of(SecretConstants.VERIFIER_SERVICE_FACTORY);

    private static final String LICENSE_FIELD = Secret.of(SecretConstants.LICENSE_FIELD);
    private static final String LICENSE_GETTER_METHOD = Secret.of(SecretConstants.LICENSE_GETTER_METHOD);

    private static final String RELEASE_LICENSE_METHOD = Secret.of(SecretConstants.RELEASE_LICENSE_METHOD);

    private static final String CLEANUP_CLASS = Secret.of(SecretConstants.CLEANUP_CLASS);
    private static final String CLEANUP_FACTORY_METHOD = Secret.of(SecretConstants.CLEANUP_FACTORY_METHOD);

    private static final String SET_INTERNAL_VERSION_METHOD =
            Secret.of(SecretConstants.SET_INTERNAL_VERSION_METHOD);

    private static final int INTERNAL_VERSION = 805;

    private static final String WXID_PREFIX = Secret.of(SecretConstants.WXID_PREFIX);

    private static final String FEATURES = Secret.of(SecretConstants.FEATURES);

    public final int bypassMode;

    private final HookFramework framework;

    private final ClassLoader hostClassLoader;

    public CallMethodBypassHook(HookFramework framework, ClassLoader hostClassLoader, int bypassMode) {
        this.framework = framework;
        this.hostClassLoader = hostClassLoader;
        this.bypassMode = bypassMode;
    }

    @Override
    public void before(HookParam param) throws Throwable {
        switch (bypassMode) {
            case VERIFIER_MESSAGE:
                handleVerifierCall(param);
                break;
            case LICENSE_CONTEXT:
                handleLicenseContext(param);
                break;
            default:
                break;
        }
    }

    @Override
    public void after(HookParam param) {
        if (bypassMode != PASSTHROUGH || !param.hasThrowable()) {
            return;
        }
        String account = String.valueOf(param.arg(0));
        if (!account.startsWith(WXID_PREFIX)) {
            return;
        }
        releaseLicense();
    }

    private void handleVerifierCall(HookParam param) {
        try {
            int msgId = (Integer) param.arg(0);
            Object[] params = (Object[]) param.arg(1);

            if (msgId == MSG_VERIFY_RESULT) {
                if (ACTION_PARAM.equals(params[0])) {
                    param.setResult(MIN_SUPPORTED_VERSION);
                } else if (VERIFIER_SERVICE.equals(params[0])) {
                    param.setResult(TRUE_TEXT);
                }
                return;
            }

            if (msgId == MSG_LICENSE_BLOB) {
                if (!VERIFIER_SERVICE.equals(params[0])) {
                    return;
                }
                String encodedLicense = String.valueOf(params[1]);
                String expectedUser = String.valueOf(params[2]);
                CurrentAccount.remember(expectedUser);
                if (TextUtils.isEmpty(encodedLicense) || NULL_TEXT.equals(encodedLicense)) {
                    releaseLicense();
                    return;
                }
                verifyAgainstWhitelist(param, encodedLicense, expectedUser);
                return;
            }

            if (msgId == MSG_FEATURE_QUERY) {
                handleFeatureQuery(param, params);
            }
        } catch (Exception e) {
            releaseLicense();
        }
    }

    private void handleFeatureQuery(HookParam param, Object[] params) {
        Object queryType = params[0];

        if (Integer.valueOf(0).equals(queryType)) {
            String userId = String.valueOf(params[1]);
            String encodedLicense = String.valueOf(params[2]);
            CurrentAccount.remember(userId);
            if (TextUtils.isEmpty(encodedLicense) || NULL_TEXT.equals(encodedLicense)) {
                return;
            }
            verifyLicense(param, userId, encodedLicense);
            return;
        }

        if (Integer.valueOf(2).equals(queryType)) {

            String key = String.valueOf(params[2]);
            if (BuildConfig.DEBUG && key.endsWith("_unlocked")) {
                framework.log("unlock query: " + key);
            }
            if (!REMOTE_COMMAND.equals(params[2])
                    && !EditionFeatures.isUnavailableExt(key)) {
                param.setResult(Boolean.TRUE);
            }
            return;
        }

        if (Integer.valueOf(4).equals(queryType)) {
            param.setResult(UNLIMITED);
            return;
        }

        if (Integer.valueOf(6).equals(queryType)) {

            Object service = framework.callStaticMethod(
                    framework.findClass(VERIFIER_SERVICE_CLASS, hostClassLoader),
                    VERIFIER_SERVICE_FACTORY);
            if (service == null) {
                param.setResult("");
                return;
            }
            Object license = framework.callMethod(service, LICENSE_GETTER_METHOD, LICENSE_FIELD, "");
            if (!(license instanceof String)) {
                param.setResult("");
                return;
            }
            verifyLicenseFromService(param, String.valueOf(params[1]), (String) license);
        }
    }

    private void verifyAgainstWhitelist(HookParam param, String encodedLicense, String expectedUser) {
        try {
            String decoded = decodeLicenseBlob(encodedLicense);
            String licenseUser = decoded.split(FIELD_SEPARATOR)[1];
            if (objectsEqual(expectedUser, licenseUser)) {
                param.setResult(Boolean.TRUE);
            } else {
                releaseLicense();
                param.setResult("");
            }
        } catch (Exception e) {
            releaseLicense();
        }
    }

    private void verifyLicense(HookParam param, String userId, String encodedLicense) {
        try {
            String decoded = decodeLicenseBlob(encodedLicense);
            String licenseUser = decoded.split(FIELD_SEPARATOR)[1];
            if (objectsEqual(userId, licenseUser)) {
                param.setResult(Boolean.TRUE);
            } else {
                releaseLicense();
                param.setResult(Boolean.FALSE);
            }
        } catch (Exception e) {
            releaseLicense();
        }
    }

    private void verifyLicenseFromService(HookParam param, String userId, String license) {
        try {
            if (TextUtils.isEmpty(license)) {
                param.setResult("");
                return;
            }
            String encodedLicense = license.split(PAYLOAD_SEPARATOR)[0];
            if (TextUtils.isEmpty(encodedLicense)) {
                param.setResult("");
                return;
            }
            String decoded = decodeLicenseBlob(encodedLicense);
            String licenseUser = decoded.split(FIELD_SEPARATOR)[1];
            if (objectsEqual(userId, licenseUser)) {
                param.setResult(FEATURES);
            } else {
                releaseLicense();
                param.setResult("");
            }
        } catch (Exception e) {
            releaseLicense();
            param.setResult("");
        }
    }

    private void handleLicenseContext(HookParam param) {
        try {
            Object service = framework.callStaticMethod(
                    framework.findClass(VERIFIER_SERVICE_CLASS, hostClassLoader),
                    VERIFIER_SERVICE_FACTORY);
            if (service == null) {
                raiseInternalVersion(param);
                return;
            }
            Object license = framework.callMethod(service, LICENSE_GETTER_METHOD, LICENSE_FIELD, "");
            if (license == null) {
                raiseInternalVersion(param);
                return;
            }
            String text = String.valueOf(license);
            for (int index = 0; index < text.length(); ) {
                int codePoint = text.codePointAt(index);
                if (!Character.isWhitespace(codePoint)) {
                    param.setResult(null);
                    return;
                }
                index += Character.charCount(codePoint);
            }
            raiseInternalVersion(param);
        } catch (Exception e) {
            releaseLicense();
        }
    }

    private void raiseInternalVersion(HookParam param) {
        try {
            releaseLicense();
            framework.callMethod(param.thisObject(), SET_INTERNAL_VERSION_METHOD, INTERNAL_VERSION);
        } catch (Exception ignored) {

        }
    }

    private void releaseLicense() {
        Object utility = framework.callStaticMethod(
                framework.findClass(CLEANUP_CLASS, hostClassLoader), CLEANUP_FACTORY_METHOD);
        framework.callMethod(utility, RELEASE_LICENSE_METHOD);
    }

    private boolean objectsEqual(String left, String right) {
        return (Boolean) framework.callStaticMethod(
                framework.findClass(OBJECTS_CLASS, null), OBJECTS_EQUALS_METHOD, left, right);
    }

    private static String decodeLicenseBlob(String encoded) {
        String packed = new String(Base64.decode(encoded, Base64.NO_WRAP), StandardCharsets.UTF_8);
        int[] numbers = unpackSegments(packed);
        StringBuilder decoded = new StringBuilder(numbers.length);
        for (int i = 0; i < numbers.length; i++) {
            decoded.append((char) ((((i << 2) + numbers.length) + (numbers[i] ^ (i * i))) >> 2));
        }
        return decoded.toString();
    }

    private static int[] unpackSegments(String packed) {
        int[] segments = new int[packed.length()];
        int count = 0;
        int index = 0;
        while (index < packed.length()) {
            int digits = Character.getNumericValue(packed.charAt(index));
            if (digits > 0) {
                int start = index + 1;
                int end = start + digits;
                if (end <= packed.length()) {
                    segments[count++] = Integer.parseInt(packed.substring(start, end));
                }
            }
            index += digits + 1;
        }
        return Arrays.copyOf(segments, count);
    }

}
