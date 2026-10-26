/*
 * 授权判定：机器码绑定的 Ed25519 短令牌。
 *
 * 令牌 72B：payload(8B) + Ed25519 签名(64B)，hex 后 144 字符；
 * 签名覆盖 "WXH1|<机器码>|<wxid>|" + payload。
 * 普通授权不走这里，由免责声明页面写入。
 */
#include <jni.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "secret_crypto.inc"
#include "pack_tables.inc"
#include "tweetnacl.h"

#define ED25519_PUBLIC_KEY_BYTES 32
#define ED25519_SIGNATURE_BYTES 64
#define ED25519_CODE_BYTES (ACT_PAYLOAD_BYTES + ED25519_SIGNATURE_BYTES)

static const uint8_t ED25519_PUBLIC_KEY[ED25519_PUBLIC_KEY_BYTES] = {
        0xa3, 0x77, 0x98, 0x15, 0x63, 0xdf, 0xfc, 0x18,
        0x61, 0xdb, 0xd4, 0xac, 0x65, 0x74, 0x0f, 0x1d,
        0x32, 0x08, 0x74, 0x89, 0x85, 0x1e, 0x2c, 0xc2,
        0xb1, 0xb3, 0xd5, 0x04, 0x0a, 0x06, 0x12, 0xa2,
};

#define ACT_PAYLOAD_BYTES 8

static const uint8_t ACT_TABLE_KEY[16] = {
        0x9f, 0x2c, 0x41, 0xd8, 0xb7, 0x3e, 0xa6, 0x05,
        0x51, 0xcc, 0x7e, 0x20, 0xf4, 0xa9, 0xd3, 0x8b,
};

static void act_table_decode(const PackTableEntry *entry, char *out, size_t capacity) {
    size_t length = entry->length;
    if (length + 1 > capacity) {
        length = capacity - 1;
    }
    for (size_t index = 0; index < length; index++) {
        out[index] = (char) (entry->data[index] ^ ACT_TABLE_KEY[index & 15]
                             ^ (uint8_t) ((index * 77 + 13) & 0xff));
    }
    out[length] = 0;
}

static void base32_encode(const uint8_t *data, size_t length, char *out) {
    static const char ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    size_t position = 0;
    int buffer = 0;
    int bits = 0;
    for (size_t index = 0; index < length; index++) {
        buffer = (buffer << 8) | data[index];
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out[position++] = ALPHABET[(buffer >> bits) & 31];
        }
    }
    if (bits > 0) {
        out[position++] = ALPHABET[(buffer << (5 - bits)) & 31];
    }
    out[position] = 0;
}

static jstring machine_code(JNIEnv *env, jstring fingerprint, jstring device,
                            jstring certificate, jstring wxid) {
    if (fingerprint == NULL || device == NULL || certificate == NULL || wxid == NULL) {
        return NULL;
    }
    const char *parts[4];
    parts[0] = (*env)->GetStringUTFChars(env, fingerprint, NULL);
    parts[1] = (*env)->GetStringUTFChars(env, device, NULL);
    parts[2] = (*env)->GetStringUTFChars(env, certificate, NULL);
    parts[3] = (*env)->GetStringUTFChars(env, wxid, NULL);
    if (parts[0] == NULL || parts[1] == NULL || parts[2] == NULL || parts[3] == NULL) {
        for (int index = 0; index < 4; index++) {
            if (parts[index] != NULL) {
                (*env)->ReleaseStringUTFChars(env,
                        index == 0 ? fingerprint : index == 1 ? device
                        : index == 2 ? certificate : wxid, parts[index]);
            }
        }
        return NULL;
    }
    char message[512];
    int length = snprintf(message, sizeof(message), "%s|%s|%s|%s",
                          parts[0], parts[1], parts[2], parts[3]);
    uint8_t digest[32];
    secret_sha256((const uint8_t *) message, (size_t) length, digest);
    char encoded[32];
    base32_encode(digest, 10, encoded);
    char formatted[32];
    size_t position = 0;
    for (size_t index = 0; encoded[index] != 0; index++) {
        if (index > 0 && index % 4 == 0) {
            formatted[position++] = '-';
        }
        formatted[position++] = encoded[index];
    }
    formatted[position] = 0;
    jstring result = (*env)->NewStringUTF(env, formatted);
    memset(message, 0, sizeof(message));
    memset(digest, 0, sizeof(digest));
    (*env)->ReleaseStringUTFChars(env, fingerprint, parts[0]);
    (*env)->ReleaseStringUTFChars(env, device, parts[1]);
    (*env)->ReleaseStringUTFChars(env, certificate, parts[2]);
    (*env)->ReleaseStringUTFChars(env, wxid, parts[3]);
    return result;
}

static int hex_value(char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    return -1;
}

static int hex_decode(const char *text, size_t length, uint8_t *out, size_t capacity) {
    if (length % 2 != 0 || length / 2 > capacity) {
        return -1;
    }
    for (size_t index = 0; index < length; index += 2) {
        int high = hex_value(text[index]);
        int low = hex_value(text[index + 1]);
        if (high < 0 || low < 0) {
            return -1;
        }
        out[index / 2] = (uint8_t) ((high << 4) | low);
    }
    return (int) (length / 2);
}

static int ed25519_token_level(const char *code, size_t code_length,
                               const char *mid, const char *wxid, uint64_t now) {
    uint8_t token[ED25519_CODE_BYTES];
    int decoded = hex_decode(code, code_length, token, sizeof(token));
    if (decoded != ED25519_CODE_BYTES) {
        return 0;
    }
    uint32_t not_after = ((uint32_t) token[2] << 24)
                         | ((uint32_t) token[3] << 16)
                         | ((uint32_t) token[4] << 8) | token[5];
    if (not_after != 0 && now > not_after) {
        return 0;
    }
    char message[512];
    int length = snprintf(message, sizeof(message), "WXH1|%s|%s|",
                          mid == NULL ? "" : mid, wxid == NULL ? "" : wxid);
    if (length < 0 || (size_t) length + ACT_PAYLOAD_BYTES > sizeof(message)) {
        return 0;
    }
    memcpy(message + length, token, ACT_PAYLOAD_BYTES);
    size_t message_length = (size_t) length + ACT_PAYLOAD_BYTES;

    uint8_t *signed_message = (uint8_t *) malloc(
            ED25519_SIGNATURE_BYTES + message_length);
    /*
     * crypto_sign_open 会先把 sm 整体（64B 签名 + N 字节正文）拷进 m，
     * 所以 opened 必须按 64 + N 分配；只给 N 会溢出 64 字节，
     * 覆盖堆上相邻对象（曾表现为 ICU RegexPattern 被踩后 GC 崩溃）。
     */
    uint8_t *opened = (uint8_t *) malloc(
            ED25519_SIGNATURE_BYTES + message_length);
    if (signed_message == NULL || opened == NULL) {
        free(signed_message);
        free(opened);
        return 0;
    }
    memcpy(signed_message, token + ACT_PAYLOAD_BYTES, ED25519_SIGNATURE_BYTES);
    memcpy(signed_message + ED25519_SIGNATURE_BYTES, message, message_length);
    unsigned long long opened_length = 0;
    int verified = crypto_sign_open(opened, &opened_length, signed_message,
                                    ED25519_SIGNATURE_BYTES + message_length,
                                    ED25519_PUBLIC_KEY) == 0
                   && opened_length == message_length
                   && memcmp(opened, message, message_length) == 0;
    memset(signed_message, 0, ED25519_SIGNATURE_BYTES + message_length);
    memset(opened, 0, ED25519_SIGNATURE_BYTES + message_length);
    free(signed_message);
    free(opened);
    memset(message, 0, sizeof(message));
    if (!verified) {
        return 0;
    }
    int features = token[1];
    return (features & 0x0e) != 0 ? 2 : 1;
}

static jint activation_level(JNIEnv *env, jclass type, jstring code,
                             jstring fingerprint, jstring device,
                             jstring certificate, jstring wxid, jlong now) {
    (void) type;
    if (code == NULL) {
        return 0;
    }
    const char *text = (*env)->GetStringUTFChars(env, code, NULL);
    if (text == NULL) {
        return 0;
    }
    size_t length = (size_t) (*env)->GetStringUTFLength(env, code);
    /* 只认机器码绑定的授权令牌：普通授权走免责声明，扩展走卡密，没有公开码通道。 */
    if (wxid == NULL) {
        (*env)->ReleaseStringUTFChars(env, code, text);
        return 0;
    }
    jstring expected = machine_code(env, fingerprint, device, certificate, wxid);
    if (expected == NULL) {
        (*env)->ReleaseStringUTFChars(env, code, text);
        return 0;
    }
    const char *mid = (*env)->GetStringUTFChars(env, expected, NULL);
    const char *wxid_text = (*env)->GetStringUTFChars(env, wxid, NULL);
    int level = 0;
    if (mid != NULL && wxid_text != NULL
            && length == ED25519_CODE_BYTES * 2) {
        level = ed25519_token_level(text, length, mid, wxid_text,
                                    (uint64_t) now);
    }
    if (mid != NULL) {
        (*env)->ReleaseStringUTFChars(env, expected, mid);
    }
    if (wxid_text != NULL) {
        (*env)->ReleaseStringUTFChars(env, wxid, wxid_text);
    }
    (*env)->DeleteLocalRef(env, expected);
    (*env)->ReleaseStringUTFChars(env, code, text);
    return level;
}

jstring wxh_native_machine_code(JNIEnv *env, jclass type, jstring fingerprint,
                                jstring device, jstring certificate, jstring wxid) {
    (void) type;
    return machine_code(env, fingerprint, device, certificate, wxid);
}

jint wxh_native_activation_level(JNIEnv *env, jclass type, jstring code,
                                 jstring fingerprint, jstring device,
                                 jstring certificate, jstring wxid, jlong now) {
    return activation_level(env, type, code, fingerprint, device,
                            certificate, wxid, now);
}
