/*
 * 敏感字符串解码的 JNI 入口。
 *
 * 纯算法(SHA-256 / HMAC / HKDF 派生 + XOR 还原)在 secret_crypto.inc;
 * 本文件只负责 JNI 绑定与 UTF-8 -> UTF-16 转换。
 *
 * 密文格式:"<常量名>:<Base64 密文>"。
 */
#include <jni.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "secret_crypto.inc"
#include "pack_tables.inc"

static jstring secret_native_of(JNIEnv *env, jclass type,
                                                               jstring encoded) {
    (void) type;
    if (encoded == NULL) {
        return NULL;
    }
    const char *text = (*env)->GetStringUTFChars(env, encoded, NULL);
    if (text == NULL) {
        return NULL;
    }
    jsize length = (*env)->GetStringUTFLength(env, encoded);

    /* 密文前缀是常量名(HKDF 的 salt),":" 之后才是 Base64。 */
    const char *separator = strchr(text, ':');
    if (separator == NULL) {
        (*env)->ReleaseStringUTFChars(env, encoded, text);
        return NULL;
    }
    size_t name_length = (size_t) (separator - text);
    const char *payload = separator + 1;
    jsize payload_length = length - (jsize) (name_length + 1);

    /* Base64 解码(标准字母表,无换行)。 */
    static const char *ALPHABET =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int8_t reverse[256];
    for (int index = 0; index < 256; index++) {
        reverse[index] = -1;
    }
    for (int index = 0; index < 64; index++) {
        reverse[(uint8_t) ALPHABET[index]] = (int8_t) index;
    }

    uint8_t *raw = (uint8_t *) malloc((size_t) payload_length + 1);
    if (raw == NULL) {
        (*env)->ReleaseStringUTFChars(env, encoded, text);
        return NULL;
    }
    int raw_length = 0;
    int accumulator = 0;
    int bits = 0;
    for (int index = 0; index < payload_length; index++) {
        int8_t value = reverse[(uint8_t) payload[index]];
        if (value < 0) {
            continue;
        }
        accumulator = (accumulator << 6) | value;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            raw[raw_length++] = (uint8_t) ((accumulator >> bits) & 0xff);
        }
    }

    /* 子密钥按常量名现派生;名字只在这里用一次,不留在内存里。 */
    uint8_t subkey[SECRET_SUBKEY_LEN];
    secret_derive_subkey(text, name_length, subkey);

    /*
     * 解出的字节是 UTF-8,不能一个字节当一个 UTF-16 字符:
     * 多字节字符会变成乱码。这里手工做 UTF-8 -> UTF-16。
     */
    jchar *plain = (jchar *) malloc(sizeof(jchar) * ((size_t) raw_length + 1));
    if (plain == NULL) {
        free(raw);
        (*env)->ReleaseStringUTFChars(env, encoded, text);
        return NULL;
    }
    int out_length = 0;
    for (int index = 0; index < raw_length; ) {
        uint8_t value = (uint8_t) (raw[index] ^ subkey[index % SECRET_SUBKEY_LEN]
                                   ^ (uint8_t) (index * 31));
        int extra = 0;
        uint32_t code_point = 0;
        if (value < 0x80) {
            code_point = value;
        } else if ((value & 0xe0) == 0xc0) {
            code_point = value & 0x1f;
            extra = 1;
        } else if ((value & 0xf0) == 0xe0) {
            code_point = value & 0x0f;
            extra = 2;
        } else if ((value & 0xf8) == 0xf0) {
            code_point = value & 0x07;
            extra = 3;
        } else {
            /* 非法首字节:按单字节处理,不中断解码。 */
            code_point = value;
        }
        for (int step = 1; step <= extra && index + step < raw_length; step++) {
            uint8_t next = (uint8_t) (raw[index + step] ^ subkey[(index + step) % SECRET_SUBKEY_LEN]
                                      ^ (uint8_t) ((index + step) * 31));
            code_point = (code_point << 6) | (next & 0x3f);
        }
        index += extra + 1;
        if (code_point >= 0x10000) {
            /* 补充平面:拆成代理对。 */
            code_point -= 0x10000;
            plain[out_length++] = (jchar) (0xd800 + (code_point >> 10));
            plain[out_length++] = (jchar) (0xdc00 + (code_point & 0x3ff));
        } else {
            plain[out_length++] = (jchar) code_point;
        }
    }
    free(raw);
    (*env)->ReleaseStringUTFChars(env, encoded, text);

    jstring result = (*env)->NewString(env, plain, (jsize) out_length);
    free(plain);
    return result;
}


/* ---------------- 功能包表(PBE salt / 扩展包计划) ---------------- */

static const uint8_t PACK_TABLE_KEY[16] = {
        0x9f, 0x2c, 0x41, 0xd8, 0xb7, 0x3e, 0xa6, 0x05,
        0x51, 0xcc, 0x7e, 0x20, 0xf4, 0xa9, 0xd3, 0x8b,
};

static size_t pack_table_decode(const PackTableEntry *entry, char *out, size_t capacity) {
    size_t length = entry->length;
    if (length + 1 > capacity) {
        length = capacity - 1;
    }
    for (size_t index = 0; index < length; index++) {
        out[index] = (char) (entry->data[index] ^ PACK_TABLE_KEY[index & 15]
                             ^ (uint8_t) ((index * 77 + 13) & 0xff));
    }
    out[length] = 0;
    return length;
}

/* 表项格式 "<key>|<payload>";返回 payload 的 jstring。 */
static jstring pack_table_lookup(JNIEnv *env, const PackTableEntry *table, size_t count,
                                 const char *key, size_t key_length) {
    char buffer[512];
    for (size_t index = 0; index < count; index++) {
        pack_table_decode(&table[index], buffer, sizeof(buffer));
        char *separator = strchr(buffer, '|');
        if (separator == NULL) {
            continue;
        }
        if ((size_t) (separator - buffer) == key_length
            && memcmp(buffer, key, key_length) == 0) {
            jstring result = (*env)->NewStringUTF(env, separator + 1);
            memset(buffer, 0, sizeof(buffer));
            return result;
        }
    }
    memset(buffer, 0, sizeof(buffer));
    return NULL;
}

static jstring secret_native_pack_plan(
        JNIEnv *env, jclass type, jstring role) {
    (void) type;
    if (role == NULL) {
        return NULL;
    }
    const char *key = (*env)->GetStringUTFChars(env, role, NULL);
    if (key == NULL) {
        return NULL;
    }
    jsize length = (*env)->GetStringUTFLength(env, role);
    jstring result = pack_table_lookup(env, PACK_PLAN_TABLE, PACK_PLAN_COUNT,
                                       key, (size_t) length);
    (*env)->ReleaseStringUTFChars(env, role, key);
    return result;
}

/* 运行目录恢复清单：基础包 / 扩展包 / 扩展包别名。 */
static jstring secret_native_restore_plan(
        JNIEnv *env, jclass type, jboolean full) {
    (void) type;
    char meta[3][64];
    for (size_t index = 0; index < 3 && index < RESTORE_META_COUNT; index++) {
        pack_table_decode(&RESTORE_META_TABLE[index], meta[index], sizeof(meta[index]));
    }
    char buffer[4096];
    size_t used = 0;
    int failed = 0;
    for (int section = 0; section < 2 && !failed; section++) {
        if (section == 1) {
            if (!full) {
                break;
            }
            const char *separator = ";";
            if (used + 1 >= sizeof(buffer)) {
                failed = 1;
                break;
            }
            buffer[used++] = *separator;
        }
        const char *role = meta[section == 0 ? 0 : 2];
        size_t role_length = strlen(role);
        size_t dir_length = strlen(meta[1]);
        if (used + role_length + dir_length + 2 >= sizeof(buffer)) {
            failed = 1;
            break;
        }
        memcpy(buffer + used, role, role_length);
        used += role_length;
        buffer[used++] = '|';
        memcpy(buffer + used, meta[1], dir_length);
        used += dir_length;
        const PackTableEntry *table = section == 0 ? RESTORE_BASE_TABLE : RESTORE_EXT_TABLE;
        size_t count = section == 0 ? RESTORE_BASE_COUNT : RESTORE_EXT_COUNT;
        for (size_t index = 0; index < count && !failed; index++) {
            char item[128];
            size_t length = pack_table_decode(&table[index], item, sizeof(item));
            if (used + length + 2 >= sizeof(buffer)) {
                failed = 1;
            } else {
                buffer[used++] = '|';
                memcpy(buffer + used, item, length);
                used += length;
            }
            memset(item, 0, sizeof(item));
        }
    }
    if (full && !failed) {
        const char *alias_tag = ";alias";
        size_t tag_length = strlen(alias_tag);
        if (used + tag_length + 1 >= sizeof(buffer)) {
            failed = 1;
        } else {
            memcpy(buffer + used, alias_tag, tag_length);
            used += tag_length;
        }
        for (size_t index = 0; index < RESTORE_ALIAS_COUNT && !failed; index++) {
            char item[128];
            size_t length = pack_table_decode(&RESTORE_ALIAS_TABLE[index],
                                              item, sizeof(item));
            if (used + length + 2 >= sizeof(buffer)) {
                failed = 1;
            } else {
                buffer[used++] = '|';
                memcpy(buffer + used, item, length);
                used += length;
            }
            memset(item, 0, sizeof(item));
        }
    }
    jstring result = NULL;
    if (!failed) {
        buffer[used] = 0;
        result = (*env)->NewStringUTF(env, buffer);
    }
    memset(buffer, 0, sizeof(buffer));
    memset(meta, 0, sizeof(meta));
    return result;
}

/* 功能包 DB 参数（DB 名、AES key、默认 fp/版本）；索引与 Secret.PACK_* 对应。 */
static jstring secret_native_pack_value(
        JNIEnv *env, jclass type, jint index) {
    (void) type;
    if (index < 0 || (size_t) index >= PACK_DB_COUNT) {
        return NULL;
    }
    char buffer[512];
    pack_table_decode(&PACK_DB_TABLE[index], buffer, sizeof(buffer));
    jstring result = (*env)->NewStringUTF(env, buffer);
    memset(buffer, 0, sizeof(buffer));
    return result;
}

/* 运行目录 + 项目签名的四个包，格式 "dir|name|len|name|len|..."。 */
static jstring secret_native_pack_guard_plan(
        JNIEnv *env, jclass type) {
    (void) type;
    char buffer[1024];
    size_t used = 0;
    for (size_t index = 0; index < PACK_GUARD_COUNT; index++) {
        char item[256];
        size_t length = pack_table_decode(&PACK_GUARD_TABLE[index],
                                          item, sizeof(item));
        if (used + length + 2 > sizeof(buffer)) {
            memset(buffer, 0, sizeof(buffer));
            return NULL;
        }
        if (used > 0) {
            buffer[used++] = '|';
        }
        memcpy(buffer + used, item, length);
        used += length;
        memset(item, 0, sizeof(item));
    }
    buffer[used] = 0;
    jstring result = (*env)->NewStringUTF(env, buffer);
    memset(buffer, 0, sizeof(buffer));
    return result;
}

/*
 * PBE salt -> 原版 password + 对应组件，格式 "password|feature"。
 * 组件为空表示只是普通解密，不需要注入 dex。
 */
static jstring secret_native_pbe_plan(
        JNIEnv *env, jclass type, jstring salt) {
    (void) type;
    if (salt == NULL) {
        return NULL;
    }
    const char *key = (*env)->GetStringUTFChars(env, salt, NULL);
    if (key == NULL) {
        return NULL;
    }
    size_t key_length = (size_t) (*env)->GetStringUTFLength(env, salt);
    char password[256];
    password[0] = 0;
    char buffer[512];
    int matched = 0;
    for (size_t index = 0; index < PACK_SALT_COUNT && !matched; index++) {
        pack_table_decode(&PACK_SALT_TABLE[index], buffer, sizeof(buffer));
        char *separator = strchr(buffer, '|');
        if (separator == NULL) {
            continue;
        }
        if ((size_t) (separator - buffer) == key_length
            && memcmp(buffer, key, key_length) == 0) {
            snprintf(password, sizeof(password), "%s", separator + 1);
            matched = 1;
        }
    }
    if (!matched) {
        memset(buffer, 0, sizeof(buffer));
        memset(password, 0, sizeof(password));
        (*env)->ReleaseStringUTFChars(env, salt, key);
        return NULL;
    }
    char feature[128];
    feature[0] = 0;
    for (size_t index = 0; index < PACK_PLAN_COUNT; index++) {
        pack_table_decode(&PACK_PLAN_TABLE[index], buffer, sizeof(buffer));
        char *role = buffer;
        char *outer = strchr(role, '|');
        if (outer == NULL) {
            continue;
        }
        *outer++ = 0;
        char *inner = strchr(outer, '|');
        if (inner == NULL) {
            continue;
        }
        *inner = 0;
        if (strcmp(outer, password) == 0) {
            snprintf(feature, sizeof(feature), "%s", role);
            break;
        }
    }
    char plan[512];
    snprintf(plan, sizeof(plan), "%s|%s", password, feature);
    jstring result = (*env)->NewStringUTF(env, plan);
    memset(buffer, 0, sizeof(buffer));
    memset(password, 0, sizeof(password));
    memset(feature, 0, sizeof(feature));
    memset(plan, 0, sizeof(plan));
    (*env)->ReleaseStringUTFChars(env, salt, key);
    return result;
}


/* 项目自签包验签；公钥解析与 RSA 在 pack_verify.c。 */
extern jboolean wxh_native_verify_pack(JNIEnv *env, jclass type,
                                       jbyteArray data, jbyteArray signature);
extern jstring wxh_native_machine_code(JNIEnv *env, jclass type,
                                       jstring fingerprint, jstring device,
                                       jstring certificate, jstring wxid);
extern jint wxh_native_activation_level(JNIEnv *env, jclass type, jstring code,
                                        jstring fingerprint, jstring device,
                                        jstring certificate, jstring wxid,
                                        jlong now);
extern jbyteArray wxh_native_decode_container(JNIEnv *env, jclass type,
                                              jbyteArray container,
                                              jstring outer_password,
                                              jstring inner_password);
extern jbyteArray wxh_native_decode_layer(JNIEnv *env, jclass type,
                                          jbyteArray container,
                                          jstring password);

/* 动态注册，避免导出 Java_... 符号。 */
extern jboolean wxh_native_hint_match(JNIEnv *env, jclass type, jint kind, jstring value);
extern jint wxh_native_spoof_version(JNIEnv *env, jclass type, jint real_version);

static const JNINativeMethod SECRET_METHODS[] = {
    {"nativeOf", "(Ljava/lang/String;)Ljava/lang/String;", (void *) secret_native_of},
    {"nativePackPlan", "(Ljava/lang/String;)Ljava/lang/String;",
     (void *) secret_native_pack_plan},
    {"nativePackValue", "(I)Ljava/lang/String;", (void *) secret_native_pack_value},
    {"nativePackGuardPlan", "()Ljava/lang/String;",
     (void *) secret_native_pack_guard_plan},
    {"nativeRestorePlan", "(Z)Ljava/lang/String;",
     (void *) secret_native_restore_plan},
    {"nativePbePlan", "(Ljava/lang/String;)Ljava/lang/String;",
     (void *) secret_native_pbe_plan},
    {"nativeVerifyPack", "([B[B)Z", (void *) wxh_native_verify_pack},
    {"nativeMachineCode", "(Ljava/lang/String;Ljava/lang/String;"
     "Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
     (void *) wxh_native_machine_code},
    {"nativeActivationLevel", "(Ljava/lang/String;Ljava/lang/String;"
     "Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;J)I",
     (void *) wxh_native_activation_level},
    {"nativeDecodeContainer", "([BLjava/lang/String;Ljava/lang/String;)[B",
     (void *) wxh_native_decode_container},
    {"nativeDecodeLayer", "([BLjava/lang/String;)[B",
     (void *) wxh_native_decode_layer},
    {"nativeHintMatch", "(ILjava/lang/String;)Z", (void *) wxh_native_hint_match},
    {"nativeSpoofVersion", "(I)I", (void *) wxh_native_spoof_version},
};

extern jint license_native_is_usable(JNIEnv *env, jclass type,
                                     jstring stored, jstring account, jint tag);
extern jobjectArray license_native_structure(JNIEnv *env, jclass type);
extern jobjectArray license_native_rows(JNIEnv *env, jclass type,
                                        jstring account, jstring latest_versions,
                                        jstring fp_versions, jstring fp, jstring fp_async);

static const JNINativeMethod LICENSE_METHODS[] = {
    {"nativeIsUsable", "(Ljava/lang/String;Ljava/lang/String;I)Z",
     (void *) license_native_is_usable},
    {"nativeStructure", "()[Ljava/lang/String;", (void *) license_native_structure},
    {"nativeRows", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;"
     "Ljava/lang/String;Ljava/lang/String;)[Ljava/lang/String;",
     (void *) license_native_rows},
};

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void) reserved;
    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void **) &env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    jclass clazz = (*env)->FindClass(env,
            "github/shadowbaby/wechatxposed/hook/loader/util/Secret");
    if (clazz == NULL) {
        return JNI_ERR;
    }
    if ((*env)->RegisterNatives(env, clazz, SECRET_METHODS,
                                (jint) (sizeof(SECRET_METHODS) / sizeof(SECRET_METHODS[0]))) != 0) {
        return JNI_ERR;
    }
    jclass license = (*env)->FindClass(env,
            "github/shadowbaby/wechatxposed/hook/license/LicenseCrypto");
    if (license == NULL) {
        return JNI_ERR;
    }
    if ((*env)->RegisterNatives(env, license, LICENSE_METHODS,
                                (jint) (sizeof(LICENSE_METHODS) / sizeof(LICENSE_METHODS[0]))) != 0) {
        return JNI_ERR;
    }
    return JNI_VERSION_1_6;
}
