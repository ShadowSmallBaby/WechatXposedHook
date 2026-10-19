/*
 * 授权库(FKZ_WX_DATA)的 JNI 入口。
 *
 * 纯算法在 license_crypto.inc;本文件只负责 JNI 绑定。
 */
#include <jni.h>
#include <stdio.h>

#include "license_crypto.inc"

/*
 * 判断库里已有的值是不是这个账号的:
 *   tag 0 —— LIC:解出 "LIC:<账号>",正好 3 段,且第 3 段能用该账号的 key 解开;
 *   tag 1 —— verifier6:解出 "verifier6:<flag>:<账号>"。
 * 返回 1/0。
 */
JNIEXPORT jint JNICALL
Java_github_shadowbaby_wechatxposed_hook_license_LicenseCrypto_nativeIsUsable(JNIEnv *env,
                                                                              jclass type,
                                                                              jstring stored,
                                                                              jstring account,
                                                                              jint tag) {
    (void) type;
    if (stored == NULL || account == NULL) {
        return 0;
    }
    const char *stored_text = (*env)->GetStringUTFChars(env, stored, NULL);
    const char *account_text = (*env)->GetStringUTFChars(env, account, NULL);
    if (stored_text == NULL || account_text == NULL) {
        if (stored_text != NULL) {
            (*env)->ReleaseStringUTFChars(env, stored, stored_text);
        }
        if (account_text != NULL) {
            (*env)->ReleaseStringUTFChars(env, account, account_text);
        }
        return 0;
    }
    size_t stored_length = (size_t) (*env)->GetStringUTFLength(env, stored);
    size_t account_length = (size_t) (*env)->GetStringUTFLength(env, account);

    int usable = 0;
    size_t raw_length = 0;
    uint8_t *raw = base64_decode(stored_text, stored_length, &raw_length);
    if (raw != NULL) {
        size_t plain_length = 0;
        uint8_t *plain = aes256_cbc_decrypt(raw, raw_length, &plain_length);
        if (plain != NULL) {
            usable = tag == 0 ? check_license((const char *) plain, account_text, account_length)
                              : check_verifier6((const char *) plain, account_text, account_length);
            free(plain);
        }
        free(raw);
    }
    (*env)->ReleaseStringUTFChars(env, stored, stored_text);
    (*env)->ReleaseStringUTFChars(env, account, account_text);
    return usable;
}

/* ---------- 授权库结构:表名、列名、SQL、行 tag 全部只留在 so 内 ---------- */

#define LICENSE_STRUCTURE_COUNT 20
#define LICENSE_ROW_COUNT 10

static const char *LICENSE_STRUCTURE[LICENSE_STRUCTURE_COUNT] = {
    "FKZ_WX_DATA",
    "DATA",
    "android_metadata",
    "_ID",
    "ACCOUNT",
    "TAG",
    "TYPE",
    "VALUE",
    "ACCOUNT=? AND TAG=?",
    "CREATE TABLE IF NOT EXISTS android_metadata (locale TEXT)",
    "CREATE TABLE IF NOT EXISTS DATA(_ID INTEGER PRIMARY KEY NOT NULL, ACCOUNT TEXT, TAG TEXT, TYPE TEXT, VALUE TEXT, DATA BLOB)",
    "zh_CN",
    "1",
    "2",
    ".bak",
    "SELECT MAX(_ID) FROM DATA",
    "INSERT INTO android_metadata VALUES (?)",
    "LIC",
    "verifier6",
    "SELECT COUNT(*) FROM android_metadata",
};

static char *encrypt_text(const char *text, size_t length) {
    size_t encrypted_length = 0;
    uint8_t *encrypted = aes256_cbc_encrypt((const uint8_t *) text, length, &encrypted_length);
    if (encrypted == NULL) {
        return NULL;
    }
    char *encoded = base64_encode(encrypted, encrypted_length);
    free(encrypted);
    return encoded;
}

static char *blob_base64(const char *text, size_t length) {
    size_t units = 0;
    uint16_t *utf16 = utf8_to_utf16(text, length, &units);
    if (utf16 == NULL) {
        return NULL;
    }
    char *packed = blob_encode(utf16, units);
    free(utf16);
    if (packed == NULL) {
        return NULL;
    }
    char *encoded = base64_encode((const uint8_t *) packed, strlen(packed));
    free(packed);
    return encoded;
}

static char *segment3_for(const char *account, size_t account_length) {
    Sha256 sha;
    sha256_init(&sha);
    sha256_update(&sha, (const uint8_t *) account, account_length);
    uint8_t key[32];
    sha256_final(&sha, key);

    size_t plain_length = strlen(LICENSE_FEATURE_SET);
    size_t padded = (plain_length / 16 + 1) * 16;
    uint8_t *output = (uint8_t *) malloc(padded);
    if (output == NULL) {
        return NULL;
    }
    uint8_t round_keys[240];
    aes256_expand(key, round_keys);
    uint8_t chain[16];
    memset(chain, 0, 16);
    for (size_t offset = 0; offset < padded; offset += 16) {
        uint8_t block[16];
        for (int index = 0; index < 16; index++) {
            size_t position = offset + (size_t) index;
            uint8_t value = position < plain_length
                    ? (uint8_t) LICENSE_FEATURE_SET[position]
                    : (uint8_t) (padded - plain_length);
            block[index] = (uint8_t) (value ^ chain[index]);
        }
        aes256_encrypt_block(round_keys, block);
        memcpy(output + offset, block, 16);
        memcpy(chain, block, 16);
    }
    char *encoded = base64_encode(output, padded);
    free(output);
    return encoded;
}

JNIEXPORT jobjectArray JNICALL
Java_github_shadowbaby_wechatxposed_hook_license_LicenseCrypto_nativeStructure(
        JNIEnv *env, jclass type) {
    (void) type;
    jclass string_class = (*env)->FindClass(env, "java/lang/String");
    if (string_class == NULL) {
        return NULL;
    }
    jobjectArray result = (*env)->NewObjectArray(env, LICENSE_STRUCTURE_COUNT,
                                                string_class, NULL);
    if (result == NULL) {
        return NULL;
    }
    for (int index = 0; index < LICENSE_STRUCTURE_COUNT; index++) {
        jstring item = (*env)->NewStringUTF(env, LICENSE_STRUCTURE[index]);
        if (item == NULL) {
            return NULL;
        }
        (*env)->SetObjectArrayElement(env, result, index, item);
        (*env)->DeleteLocalRef(env, item);
    }
    return result;
}

JNIEXPORT jobjectArray JNICALL
Java_github_shadowbaby_wechatxposed_hook_license_LicenseCrypto_nativeRows(
        JNIEnv *env, jclass type, jstring account, jstring latest_versions,
        jstring fp_versions, jstring fp, jstring fp_async) {
    (void) type;
    static const char *tags[LICENSE_ROW_COUNT] = {
        "hookFail", "disclaimer_disable", "is_new_user", "LatestVersions",
        "FPVersions", "valid", "fp", "fp_async", "LIC", "verifier6",
    };
    static const char *types[LICENSE_ROW_COUNT] = {
        "BOOLEAN", "BOOLEAN", "INT", "JSON",
        "JSON", "BOOLEAN", "STRING", "STRING", "STRING", "STRING",
    };
    if (account == NULL || latest_versions == NULL || fp_versions == NULL
            || fp == NULL || fp_async == NULL) {
        return NULL;
    }
    const char *account_text = (*env)->GetStringUTFChars(env, account, NULL);
    if (account_text == NULL) {
        return NULL;
    }
    size_t account_length = (size_t) (*env)->GetStringUTFLength(env, account);
    char *values[LICENSE_ROW_COUNT] = {0};
    char *segment3 = NULL;
    jobjectArray result = NULL;

    segment3 = segment3_for(account_text, account_length);
    if (segment3 == NULL || !check_segment3(segment3, account_text, account_length)) {
        goto cleanup;
    }

    size_t license_blob_length = 4 + account_length;
    char *license_plain = (char *) malloc(license_blob_length + 1);
    if (license_plain == NULL) {
        goto cleanup;
    }
    memcpy(license_plain, "LIC:", 4);
    memcpy(license_plain + 4, account_text, account_length);
    license_plain[license_blob_length] = '\0';
    char *license_blob = blob_base64(license_plain, license_blob_length);
    free(license_plain);
    if (license_blob == NULL) {
        goto cleanup;
    }
    size_t license_length = strlen(license_blob) + 3 + strlen(segment3) + 1;
    char *license_full = (char *) malloc(license_length);
    if (license_full == NULL) {
        free(license_blob);
        goto cleanup;
    }
    snprintf(license_full, license_length, "%s#f#%s", license_blob, segment3);
    free(license_blob);
    values[8] = encrypt_text(license_full, strlen(license_full));
    free(license_full);
    if (values[8] == NULL) {
        goto cleanup;
    }

    size_t verifier_blob_length = 12 + account_length;
    char *verifier_plain = (char *) malloc(verifier_blob_length + 1);
    if (verifier_plain == NULL) {
        goto cleanup;
    }
    memcpy(verifier_plain, "verifier6#D:", 12);
    memcpy(verifier_plain + 12, account_text, account_length);
    verifier_plain[verifier_blob_length] = '\0';
    char *verifier_blob = blob_base64(verifier_plain, verifier_blob_length);
    free(verifier_plain);
    if (verifier_blob == NULL) {
        goto cleanup;
    }
    values[9] = encrypt_text(verifier_blob, strlen(verifier_blob));
    free(verifier_blob);
    if (values[9] == NULL) {
        goto cleanup;
    }

    const char *latest = (*env)->GetStringUTFChars(env, latest_versions, NULL);
    const char *versions = (*env)->GetStringUTFChars(env, fp_versions, NULL);
    const char *fp_text = (*env)->GetStringUTFChars(env, fp, NULL);
    const char *async_text = (*env)->GetStringUTFChars(env, fp_async, NULL);
    if (latest == NULL || versions == NULL || fp_text == NULL || async_text == NULL) {
        if (latest != NULL) {
            (*env)->ReleaseStringUTFChars(env, latest_versions, latest);
        }
        if (versions != NULL) {
            (*env)->ReleaseStringUTFChars(env, fp_versions, versions);
        }
        if (fp_text != NULL) {
            (*env)->ReleaseStringUTFChars(env, fp, fp_text);
        }
        if (async_text != NULL) {
            (*env)->ReleaseStringUTFChars(env, fp_async, async_text);
        }
        goto cleanup;
    }
    values[0] = encrypt_text("false", 5);
    values[1] = encrypt_text("true", 4);
    values[2] = encrypt_text("10", 2);
    values[3] = encrypt_text(latest, strlen(latest));
    values[4] = encrypt_text(versions, strlen(versions));
    values[5] = encrypt_text("true", 4);
    values[6] = encrypt_text(fp_text, strlen(fp_text));
    values[7] = encrypt_text(async_text, strlen(async_text));
    (*env)->ReleaseStringUTFChars(env, latest_versions, latest);
    (*env)->ReleaseStringUTFChars(env, fp_versions, versions);
    (*env)->ReleaseStringUTFChars(env, fp, fp_text);
    (*env)->ReleaseStringUTFChars(env, fp_async, async_text);

    for (int index = 0; index < LICENSE_ROW_COUNT; index++) {
        if (values[index] == NULL) {
            goto cleanup;
        }
    }

    jclass string_class = (*env)->FindClass(env, "java/lang/String");
    if (string_class == NULL) {
        goto cleanup;
    }
    result = (*env)->NewObjectArray(env, LICENSE_ROW_COUNT, string_class, NULL);
    if (result == NULL) {
        goto cleanup;
    }
    for (int index = 0; index < LICENSE_ROW_COUNT; index++) {
        size_t line_length = strlen(tags[index]) + strlen(types[index])
                + strlen(values[index]) + 3;
        char *line = (char *) malloc(line_length);
        if (line == NULL) {
            result = NULL;
            goto cleanup;
        }
        snprintf(line, line_length, "%s\n%s\n%s", tags[index], types[index], values[index]);
        jstring item = (*env)->NewStringUTF(env, line);
        free(line);
        if (item == NULL) {
            result = NULL;
            goto cleanup;
        }
        (*env)->SetObjectArrayElement(env, result, index, item);
        (*env)->DeleteLocalRef(env, item);
    }

cleanup:
    free(segment3);
    for (int index = 0; index < LICENSE_ROW_COUNT; index++) {
        free(values[index]);
    }
    (*env)->ReleaseStringUTFChars(env, account, account_text);
    return result;
}
