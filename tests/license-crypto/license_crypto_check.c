/*
 * 桌面校验 license.c 的加密链路。
 *
 * 直接 include app/src/main/jni/license.c,调用里面的静态函数
 * (AES-256-CBC、SHA-256、blob 编码、LIC 段 3),与 Python 参考实现逐项对照。
 * 主机是 x86_64,arm64 的 so 加载不了,所以这里编译同一份 C 源码验证算法本身;
 * 真机上 so 的加载与 JNI 绑定由 tests/license-data/run-device.py 覆盖。
 *
 * 用法:license_crypto_check <命令> <参数...>
 *   encrypt <明文>                第一层加密(输出 Base64)
 *   segment3 <账号>               LIC 第 3 段
 *   decode3 <段3> <账号>          LIC 第 3 段的逆运算
 *   encodeblob <明文>             blob 编码
 *   usable <stored> <账号> <tag>  isUsable(0=LIC,1=verifier6)
 */
#include <stdio.h>
#include <string.h>

/* 只编纯算法部分(不含 JNI),这样主机 clang 不需要 Android 的 jni.h。 */
#include "../../app/src/main/jni/license_crypto.inc"

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <command> ...\n", argv[0]);
        return 2;
    }
    const char *command = argv[1];
    if (strcmp(command, "encrypt") == 0 && argc == 3) {
        size_t length = 0;
        uint8_t *encrypted = aes256_cbc_encrypt((const uint8_t *) argv[2], strlen(argv[2]), &length);
        char *encoded = base64_encode(encrypted, length);
        printf("%s\n", encoded);
        free(encoded);
        free(encrypted);
        return 0;
    }
    if (strcmp(command, "segment3") == 0 && argc == 3) {
        Sha256 sha;
        sha256_init(&sha);
        sha256_update(&sha, (const uint8_t *) argv[2], strlen(argv[2]));
        uint8_t key[32];
        sha256_final(&sha, key);
        size_t plain_length = strlen(LICENSE_FEATURE_SET);
        size_t padded = (plain_length / 16 + 1) * 16;
        uint8_t *output = (uint8_t *) malloc(padded);
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
        printf("%s\n", encoded);
        free(encoded);
        free(output);
        return 0;
    }
    if (strcmp(command, "decode3") == 0 && argc == 4) {
        Sha256 sha;
        sha256_init(&sha);
        sha256_update(&sha, (const uint8_t *) argv[3], strlen(argv[3]));
        uint8_t key[32];
        sha256_final(&sha, key);
        size_t raw_length = 0;
        uint8_t *raw = base64_decode(argv[2], strlen(argv[2]), &raw_length);
        if (raw == NULL || raw_length != 16) {
            printf("(bad)\n");
            return 0;
        }
        uint8_t round_keys[240];
        aes256_expand(key, round_keys);
        uint8_t state[16];
        memcpy(state, raw, 16);
        uint8_t zero[16];
        memset(zero, 0, 16);
        aes256_decrypt_block(round_keys, state, zero);
        uint8_t padding = state[15];
        size_t plain_length = 16;
        if (padding >= 1 && padding <= 16) {
            plain_length = 16 - padding;
        }
        fwrite(state, 1, plain_length, stdout);
        printf("\n");
        free(raw);
        return 0;
    }
    if (strcmp(command, "encodeblob") == 0 && argc == 3) {
        size_t units = 0;
        uint16_t *utf16 = utf8_to_utf16(argv[2], strlen(argv[2]), &units);
        char *packed = blob_encode(utf16, units);
        size_t packed_length = strlen(packed);
        char *encoded = base64_encode((const uint8_t *) packed, packed_length);
        printf("%s\n", encoded);
        free(encoded);
        free(packed);
        free(utf16);
        return 0;
    }
    if (strcmp(command, "usable") == 0 && argc == 5) {
        size_t stored_length = 0;
        uint8_t *raw = base64_decode(argv[2], strlen(argv[2]), &stored_length);
        size_t plain_length = 0;
        uint8_t *plain = aes256_cbc_decrypt(raw, stored_length, &plain_length);
        int tag = atoi(argv[4]);
        int usable = tag == 0
                ? check_license((const char *) plain, argv[3], strlen(argv[3]))
                : check_verifier6((const char *) plain, argv[3], strlen(argv[3]));
        printf("%d\n", usable);
        free(plain);
        free(raw);
        return 0;
    }
    fprintf(stderr, "bad arguments\n");
    return 2;
}