/*
 * 敏感常量解码的纯算法部分(无 JNI)。
 *
 * 单独拆出来是为了让桌面测试能直接编译同一份源码:
 * tests/secret-encoding/secret_crypto_check.c 直接 include 本文件,
 * 用主机 clang 编出可执行文件,与 scripts/encode_secrets.py 逐项对照。
 * secret.c 也 include 它,再补上 JNI 导出。
 *
 * 结构:
 *   1. 主密钥(SECRET_DEFAULT_MASTER_KEY)只存在于本文件,编译进 so,dex 里没有;
 *      构建时设 WXH_MASTER_KEY(32 字节 hex 或 Base64)可由 Gradle 覆盖它;
 *   2. 每个常量用「常量名」当 HKDF-SHA256 的 salt,从主密钥派生一把独立的
 *      32 字节子密钥(derive_subkey);子密钥再按逐字节 XOR + 位置混合解密密文。
 *
 * 与早期版本的区别:早期全部常量共用一把会话种子,逆出一项等于逆出全部;
 * 现在每项一把子密钥(HKDF 的 salt 是常量名),单项泄露不扩散到其它常量。
 *
 * 这一层不是密码学安全(so 可被反汇编),目的是把门槛从「strings 一下」
 * 抬到「逆 native 代码 + 复现 HKDF」。
 */
#ifndef WEXPOSEDHOOK_SECRET_CRYPTO_INC
#define WEXPOSEDHOOK_SECRET_CRYPTO_INC

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/*
 * 主密钥:32 字节。默认值必须与 scripts/encode_secrets.py 的 DEFAULT_MASTER_KEY 逐字节一致。
 * 构建时设 WXH_MASTER_KEY(32 字节 hex 或标准 Base64),由 Gradle 校验格式、解码成
 * 32 个字节后以 -DWXH_MASTER_KEY_BYTES=<字节列表> 覆盖;这里不做运行期字符串解析,
 * 格式非法在 Gradle 配置阶段就报错。
 */
#ifdef WXH_MASTER_KEY_BYTES
static const uint8_t SECRET_MASTER_KEY[32] = {WXH_MASTER_KEY_BYTES};
#else
static const uint8_t SECRET_MASTER_KEY[32] = {
    0x7b, 0x1e, 0x4d, 0x92, 0x35, 0xa8, 0x0f, 0xc6,
    0x51, 0x3b, 0xe7, 0x28, 0x9d, 0x64, 0x02, 0xfa,
    0x8c, 0x17, 0xb3, 0x5e, 0xd0, 0x49, 0x26, 0x7f,
    0xa1, 0x38, 0xcb, 0x06, 0x94, 0x5d, 0xe2, 0x70,
};
#endif

#define secret_master_key() (SECRET_MASTER_KEY)

/* HKDF 的 info 串;与 scripts/encode_secrets.py 的 HKDF_INFO 一致。 */
static const char SECRET_HKDF_INFO[] = "wexhook-v2";

#define SECRET_SUBKEY_LEN 32

/* ---------------- SHA-256(精简实现,只用于 HKDF) ---------------- */

typedef struct {
    uint32_t state[8];
    uint64_t length;
    uint8_t buffer[64];
    size_t used;
} SecretSha256;

static const uint32_t SECRET_SHA256_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

#define SECRET_ROTR(value, bits) (((value) >> (bits)) | ((value) << (32 - (bits))))

static void secret_sha256_block(SecretSha256 *ctx, const uint8_t *block) {
    uint32_t w[64];
    for (int index = 0; index < 16; index++) {
        w[index] = ((uint32_t) block[index * 4] << 24) | ((uint32_t) block[index * 4 + 1] << 16)
                   | ((uint32_t) block[index * 4 + 2] << 8) | (uint32_t) block[index * 4 + 3];
    }
    for (int index = 16; index < 64; index++) {
        uint32_t s0 = SECRET_ROTR(w[index - 15], 7) ^ SECRET_ROTR(w[index - 15], 18)
                      ^ (w[index - 15] >> 3);
        uint32_t s1 = SECRET_ROTR(w[index - 2], 17) ^ SECRET_ROTR(w[index - 2], 19)
                      ^ (w[index - 2] >> 10);
        w[index] = w[index - 16] + s0 + w[index - 7] + s1;
    }
    uint32_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3];
    uint32_t e = ctx->state[4], f = ctx->state[5], g = ctx->state[6], h = ctx->state[7];
    for (int index = 0; index < 64; index++) {
        uint32_t s1 = SECRET_ROTR(e, 6) ^ SECRET_ROTR(e, 11) ^ SECRET_ROTR(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + s1 + ch + SECRET_SHA256_K[index] + w[index];
        uint32_t s0 = SECRET_ROTR(a, 2) ^ SECRET_ROTR(a, 13) ^ SECRET_ROTR(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = s0 + maj;
        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void secret_sha256_init(SecretSha256 *ctx) {
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
    ctx->length = 0;
    ctx->used = 0;
}

static void secret_sha256_update(SecretSha256 *ctx, const uint8_t *data, size_t length) {
    ctx->length += length;
    while (length > 0) {
        size_t space = 64 - ctx->used;
        size_t take = length < space ? length : space;
        memcpy(ctx->buffer + ctx->used, data, take);
        ctx->used += take;
        data += take;
        length -= take;
        if (ctx->used == 64) {
            secret_sha256_block(ctx, ctx->buffer);
            ctx->used = 0;
        }
    }
}

static void secret_sha256_final(SecretSha256 *ctx, uint8_t *out) {
    uint64_t bits = ctx->length * 8;
    uint8_t pad = 0x80;
    secret_sha256_update(ctx, &pad, 1);
    uint8_t zero = 0;
    while (ctx->used != 56) {
        secret_sha256_update(ctx, &zero, 1);
    }
    uint8_t tail[8];
    for (int index = 0; index < 8; index++) {
        tail[index] = (uint8_t) (bits >> (56 - index * 8));
    }
    secret_sha256_update(ctx, tail, 8);
    for (int index = 0; index < 8; index++) {
        out[index * 4] = (uint8_t) (ctx->state[index] >> 24);
        out[index * 4 + 1] = (uint8_t) (ctx->state[index] >> 16);
        out[index * 4 + 2] = (uint8_t) (ctx->state[index] >> 8);
        out[index * 4 + 3] = (uint8_t) ctx->state[index];
    }
}

static void secret_sha256(const uint8_t *data, size_t length, uint8_t *out) {
    SecretSha256 ctx;
    secret_sha256_init(&ctx);
    secret_sha256_update(&ctx, data, length);
    secret_sha256_final(&ctx, out);
}

/* HMAC-SHA256;key 与 message 都是任意长度。 */
static void secret_hmac_sha256(const uint8_t *key, size_t key_length,
                               const uint8_t *message, size_t message_length, uint8_t *out) {
    uint8_t block[64];
    memset(block, 0, sizeof(block));
    if (key_length > 64) {
        secret_sha256(key, key_length, block);
    } else {
        memcpy(block, key, key_length);
    }
    uint8_t inner[64];
    uint8_t outer[64];
    for (int index = 0; index < 64; index++) {
        inner[index] = (uint8_t) (block[index] ^ 0x36);
        outer[index] = (uint8_t) (block[index] ^ 0x5c);
    }
    SecretSha256 ctx;
    uint8_t digest[32];
    secret_sha256_init(&ctx);
    secret_sha256_update(&ctx, inner, sizeof(inner));
    secret_sha256_update(&ctx, message, message_length);
    secret_sha256_final(&ctx, digest);
    secret_sha256_init(&ctx);
    secret_sha256_update(&ctx, outer, sizeof(outer));
    secret_sha256_update(&ctx, digest, sizeof(digest));
    secret_sha256_final(&ctx, out);
}

/*
 * HKDF-SHA256(RFC 5869)的 extract + expand,输出 32 字节。
 * L=32 只需一轮 expand(T(1) = HMAC(PRK, info || 0x01))。
 */
static void secret_hkdf_sha256(const uint8_t *ikm, size_t ikm_length,
                               const uint8_t *salt, size_t salt_length,
                               const uint8_t *info, size_t info_length, uint8_t *out) {
    uint8_t prk[32];
    secret_hmac_sha256(salt, salt_length, ikm, ikm_length, prk);
    uint8_t message[64];
    memcpy(message, info, info_length);
    size_t used = info_length;
    message[used++] = 0x01;
    secret_hmac_sha256(prk, sizeof(prk), message, used, out);
}

/* 由主密钥 + 常量名派生该常量专属的 32 字节子密钥。 */
static void secret_derive_subkey(const char *name, size_t name_length, uint8_t *subkey) {
    secret_hkdf_sha256(secret_master_key(), 32,
                       (const uint8_t *) name, name_length,
                       (const uint8_t *) SECRET_HKDF_INFO, sizeof(SECRET_HKDF_INFO) - 1,
                       subkey);
}

#endif
