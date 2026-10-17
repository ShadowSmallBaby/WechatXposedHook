/*
 * 敏感字符串解码(阶段 4:每项独立子密钥)。
 *
 * 纯算法(SHA-256 / HMAC / HKDF 派生 + XOR 还原)在 secret_crypto.inc 里,
 * 桌面测试直接编它;本文件只负责 JNI 绑定与 UTF-8 -> UTF-16 转换。
 * 主密钥与 info 串都在 .inc 内,dex 里既没有明文也没有密钥。
 *
 * 密文格式:"<常量名>:<Base64 密文>"。常量名是 HKDF 的 salt,
 * 必须随密文一起传进来,所以 Secret.of 的签名不用改。
 *
 * 这一层不是密码学安全(so 可被反汇编),目的是把门槛从「strings 一下」
 * 抬到「逆 native 代码 + 复现 HKDF」。
 */
#include <jni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "secret_crypto.inc"

JNIEXPORT jstring JNICALL
Java_github_shadowbaby_wechatxposed_hook_loader_Secret_nativeOf(JNIEnv *env, jclass type,
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
     * 多字节字符(微X 的混淆类名全是)会变成乱码。这里手工做 UTF-8 -> UTF-16。
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