/*
 * 桌面校验 secret_crypto.inc:HKDF-SHA256 派生的子密钥必须与
 * scripts/encode_secrets.py 的 derive_subkey 逐字节一致。
 *
 * 主机是 x86_64,arm64 的 so 加载不了,所以这里验证算法本身;
 * 真机上 so 的加载与 JNI 绑定由 tests/secret-encoding/run-device.py 覆盖。
 *
 * 用法:secret_crypto_check <常量名> [常量名...]  每行打印 "<名字> <子密钥 hex>"
 */
#include <stdio.h>
#include <string.h>

#include "app/src/main/jni/secret_crypto.inc"

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "用法: %s <常量名> [常量名...]\n", argv[0]);
        return 2;
    }
    for (int index = 1; index < argc; index++) {
        const char *name = argv[index];
        uint8_t subkey[SECRET_SUBKEY_LEN];
        secret_derive_subkey(name, strlen(name), subkey);
        printf("%s ", name);
        for (int byte = 0; byte < SECRET_SUBKEY_LEN; byte++) {
            printf("%02x", subkey[byte]);
        }
        printf("\n");
    }
    return 0;
}