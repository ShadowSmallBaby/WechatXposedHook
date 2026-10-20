/*
 * 授权库数据加密算法(纯算法,无 JNI)。
 *
 * license.c 在包含本文件后补上 JNI 导出。
 */
#ifndef WEXPOSEDHOOK_LICENSE_CRYPTO_INC
#define WEXPOSEDHOOK_LICENSE_CRYPTO_INC

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
/*
 * 授权数据算法:
 *   - 第一层 AES-256-CBC(零 IV、PKCS7)+ Base64;
 *   - LIC 第 3 段的 key = SHA-256(账号);
 *   - "LIC:<账号>" 的 blob 编码。
 *
 * 与 Java 侧的两个约定:
 *   1. 明文按 UTF-8 取字节;
 *   2. Base64 使用标准字母表、无换行。
 */

/* 第一层 AES-256 密钥:32 字节。改动后需要重新生成授权数据。 */
static const uint8_t AES_KEY[32] = {
    0x31, 0xd0, 0x19, 0xea, 0x56, 0xd5, 0x74, 0x13,
    0x35, 0x08, 0xb1, 0x0d, 0x94, 0x4b, 0x41, 0x3c,
    0x4f, 0xb9, 0xeb, 0x58, 0xa9, 0x0e, 0x1a, 0x01,
    0x5c, 0x62, 0x72, 0x9f, 0x74, 0x59, 0xc6, 0x6d,
};

/* LIC 第 3 段解密后的明文:授权档位。 */
static const char LICENSE_FEATURE_SET[] = "[0,1,4]";
/* 公开版不带扩展包，功能集合保持 [1]；native 两种都接受。 */
static const char LICENSE_FEATURE_SET_LEGACY[] = "[1]";

/* ---------------------------------------------------------------- SHA-256 */

typedef struct {
    uint32_t state[8];
    uint64_t bits;
    uint8_t buffer[64];
    size_t used;
} Sha256;

static const uint32_t SHA256_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static uint32_t rotate_right(uint32_t value, int count) {
    return (value >> count) | (value << (32 - count));
}

static void sha256_block(Sha256 *ctx, const uint8_t *block) {
    uint32_t w[64];
    for (int index = 0; index < 16; index++) {
        w[index] = ((uint32_t) block[index * 4] << 24) | ((uint32_t) block[index * 4 + 1] << 16)
                | ((uint32_t) block[index * 4 + 2] << 8) | (uint32_t) block[index * 4 + 3];
    }
    for (int index = 16; index < 64; index++) {
        uint32_t s0 = rotate_right(w[index - 15], 7) ^ rotate_right(w[index - 15], 18)
                ^ (w[index - 15] >> 3);
        uint32_t s1 = rotate_right(w[index - 2], 17) ^ rotate_right(w[index - 2], 19)
                ^ (w[index - 2] >> 10);
        w[index] = w[index - 16] + s0 + w[index - 7] + s1;
    }
    uint32_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3];
    uint32_t e = ctx->state[4], f = ctx->state[5], g = ctx->state[6], h = ctx->state[7];
    for (int index = 0; index < 64; index++) {
        uint32_t s1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t temp1 = h + s1 + ch + SHA256_K[index] + w[index];
        uint32_t s0 = rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = s0 + maj;
        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(Sha256 *ctx) {
    static const uint32_t INIT[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    };
    memcpy(ctx->state, INIT, sizeof(INIT));
    ctx->bits = 0;
    ctx->used = 0;
}

static void sha256_update(Sha256 *ctx, const uint8_t *data, size_t length) {
    ctx->bits += (uint64_t) length * 8;
    while (length > 0) {
        size_t room = 64 - ctx->used;
        size_t take = length < room ? length : room;
        memcpy(ctx->buffer + ctx->used, data, take);
        ctx->used += take;
        data += take;
        length -= take;
        if (ctx->used == 64) {
            sha256_block(ctx, ctx->buffer);
            ctx->used = 0;
        }
    }
}

static void sha256_final(Sha256 *ctx, uint8_t out[32]) {
    uint64_t bits = ctx->bits;
    uint8_t pad = 0x80;
    sha256_update(ctx, &pad, 1);
    uint8_t zero = 0;
    while (ctx->used != 56) {
        sha256_update(ctx, &zero, 1);
    }
    uint8_t length[8];
    for (int index = 0; index < 8; index++) {
        length[index] = (uint8_t) (bits >> (56 - index * 8));
    }
    sha256_update(ctx, length, 8);
    for (int index = 0; index < 8; index++) {
        out[index * 4] = (uint8_t) (ctx->state[index] >> 24);
        out[index * 4 + 1] = (uint8_t) (ctx->state[index] >> 16);
        out[index * 4 + 2] = (uint8_t) (ctx->state[index] >> 8);
        out[index * 4 + 3] = (uint8_t) ctx->state[index];
    }
}

/* ---------------------------------------------------------------- AES-256 */

static const uint8_t AES_SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
};

static const uint8_t AES_RCON[11] = {
    0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,
};

static uint8_t multiply(uint8_t left, uint8_t right) {
    uint8_t result = 0;
    while (right != 0) {
        if (right & 1) {
            result ^= left;
        }
        uint8_t high = (uint8_t) (left & 0x80);
        left = (uint8_t) (left << 1);
        if (high) {
            left ^= 0x1b;
        }
        right >>= 1;
    }
    return result;
}

/* AES-256 轮密钥:14 轮 + 初始,共 15 组 x 16 字节。 */
static void aes256_expand(const uint8_t key[32], uint8_t round_keys[240]) {
    memcpy(round_keys, key, 32);
    int produced = 32;
    int rcon = 1;
    uint8_t temp[4];
    while (produced < 240) {
        memcpy(temp, round_keys + produced - 4, 4);
        if (produced % 32 == 0) {
            uint8_t first = temp[0];
            temp[0] = (uint8_t) (AES_SBOX[temp[1]] ^ AES_RCON[rcon++]);
            temp[1] = AES_SBOX[temp[2]];
            temp[2] = AES_SBOX[temp[3]];
            temp[3] = AES_SBOX[first];
        } else if (produced % 32 == 16) {
            for (int index = 0; index < 4; index++) {
                temp[index] = AES_SBOX[temp[index]];
            }
        }
        for (int index = 0; index < 4; index++) {
            round_keys[produced] = (uint8_t) (round_keys[produced - 32] ^ temp[index]);
            produced++;
        }
    }
}

static void add_round_key(uint8_t state[16], const uint8_t *round_key) {
    for (int index = 0; index < 16; index++) {
        state[index] ^= round_key[index];
    }
}

/* 逆 S 盒:线性查找,只用于校验路径,不追求速度。 */
static uint8_t inverse_sbox(uint8_t value) {
    for (int candidate = 0; candidate < 256; candidate++) {
        if (AES_SBOX[candidate] == value) {
            return (uint8_t) candidate;
        }
    }
    return 0;
}

/* state 按列优先存放:state[row + 4*col]。 */
static void aes256_encrypt_block(const uint8_t round_keys[240], uint8_t state[16]) {
    add_round_key(state, round_keys);
    for (int round = 1; round <= 14; round++) {
        for (int index = 0; index < 16; index++) {
            state[index] = AES_SBOX[state[index]];
        }
        uint8_t shifted[16];
        for (int row = 0; row < 4; row++) {
            for (int col = 0; col < 4; col++) {
                shifted[row + 4 * col] = state[row + 4 * ((col + row) % 4)];
            }
        }
        memcpy(state, shifted, 16);
        if (round != 14) {
            uint8_t mixed[16];
            for (int col = 0; col < 4; col++) {
                uint8_t a0 = state[4 * col], a1 = state[4 * col + 1];
                uint8_t a2 = state[4 * col + 2], a3 = state[4 * col + 3];
                mixed[4 * col] = (uint8_t) (multiply(a0, 2) ^ multiply(a1, 3) ^ a2 ^ a3);
                mixed[4 * col + 1] = (uint8_t) (a0 ^ multiply(a1, 2) ^ multiply(a2, 3) ^ a3);
                mixed[4 * col + 2] = (uint8_t) (a0 ^ a1 ^ multiply(a2, 2) ^ multiply(a3, 3));
                mixed[4 * col + 3] = (uint8_t) (multiply(a0, 3) ^ a1 ^ a2 ^ multiply(a3, 2));
            }
            memcpy(state, mixed, 16);
        }
        add_round_key(state, round_keys + round * 16);
    }
}

/* 单块解密(逆序轮密钥 + 逆变换),chain 为上一块密文(CBC 异或用)。 */
static void aes256_decrypt_block(const uint8_t round_keys[240], uint8_t state[16],
                                 const uint8_t chain[16]) {
    add_round_key(state, round_keys + 14 * 16);
    for (int round = 13; round >= 0; round--) {
        uint8_t shifted[16];
        for (int row = 0; row < 4; row++) {
            for (int col = 0; col < 4; col++) {
                shifted[row + 4 * ((col + row) % 4)] = state[row + 4 * col];
            }
        }
        memcpy(state, shifted, 16);
        for (int index = 0; index < 16; index++) {
            state[index] = inverse_sbox(state[index]);
        }
        add_round_key(state, round_keys + round * 16);
        if (round != 0) {
            uint8_t mixed[16];
            for (int col = 0; col < 4; col++) {
                uint8_t a0 = state[4 * col], a1 = state[4 * col + 1];
                uint8_t a2 = state[4 * col + 2], a3 = state[4 * col + 3];
                mixed[4 * col] = (uint8_t) (multiply(a0, 14) ^ multiply(a1, 11)
                        ^ multiply(a2, 13) ^ multiply(a3, 9));
                mixed[4 * col + 1] = (uint8_t) (multiply(a0, 9) ^ multiply(a1, 14)
                        ^ multiply(a2, 11) ^ multiply(a3, 13));
                mixed[4 * col + 2] = (uint8_t) (multiply(a0, 13) ^ multiply(a1, 9)
                        ^ multiply(a2, 14) ^ multiply(a3, 11));
                mixed[4 * col + 3] = (uint8_t) (multiply(a0, 11) ^ multiply(a1, 13)
                        ^ multiply(a2, 9) ^ multiply(a3, 14));
            }
            memcpy(state, mixed, 16);
        }
    }
    /* CBC:逆完整个 AES 后再与上一块密文异或,只做一次。 */
    for (int index = 0; index < 16; index++) {
        state[index] ^= chain[index];
    }
}

/* AES-256-CBC 加密,零 IV、PKCS7 填充;返回新分配的缓冲,长度是 16 的倍数。 */
static uint8_t *aes256_cbc_encrypt(const uint8_t *input, size_t length, size_t *out_length) {
    size_t padded = (length / 16 + 1) * 16;
    uint8_t *output = (uint8_t *) malloc(padded);
    if (output == NULL) {
        return NULL;
    }
    uint8_t round_keys[240];
    aes256_expand(AES_KEY, round_keys);
    uint8_t chain[16];
    memset(chain, 0, 16);
    for (size_t offset = 0; offset < padded; offset += 16) {
        uint8_t block[16];
        for (int index = 0; index < 16; index++) {
            size_t position = offset + (size_t) index;
            uint8_t value = position < length ? input[position] : (uint8_t) (padded - length);
            block[index] = (uint8_t) (value ^ chain[index]);
        }
        aes256_encrypt_block(round_keys, block);
        memcpy(output + offset, block, 16);
        memcpy(chain, block, 16);
    }
    *out_length = padded;
    return output;
}

/* AES-256-CBC 解密(零 IV),去掉 PKCS7 填充;返回新分配的明文缓冲。 */
static uint8_t *aes256_cbc_decrypt(const uint8_t *input, size_t length, size_t *out_length) {
    if (length == 0 || length % 16 != 0) {
        return NULL;
    }
    uint8_t *output = (uint8_t *) malloc(length + 1);
    if (output == NULL) {
        return NULL;
    }
    uint8_t round_keys[240];
    aes256_expand(AES_KEY, round_keys);
    uint8_t chain[16];
    memset(chain, 0, 16);
    for (size_t offset = 0; offset < length; offset += 16) {
        uint8_t state[16];
        memcpy(state, input + offset, 16);
        aes256_decrypt_block(round_keys, state, chain);
        memcpy(chain, input + offset, 16);
        memcpy(output + offset, state, 16);
    }
    uint8_t padding = output[length - 1];
    size_t plain_length = length;
    if (padding >= 1 && padding <= 16 && (size_t) padding <= length) {
        plain_length = length - padding;
    }
    output[plain_length] = '\0';
    *out_length = plain_length;
    return output;
}

/* ---------------------------------------------------------------- Base64 */

static const char BASE64_ALPHABET[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *base64_encode(const uint8_t *data, size_t length) {
    size_t groups = (length + 2) / 3;
    char *out = (char *) malloc(groups * 4 + 1);
    if (out == NULL) {
        return NULL;
    }
    size_t written = 0;
    for (size_t offset = 0; offset < length; offset += 3) {
        uint32_t chunk = (uint32_t) data[offset] << 16;
        size_t remaining = length - offset;
        if (remaining > 1) {
            chunk |= (uint32_t) data[offset + 1] << 8;
        }
        if (remaining > 2) {
            chunk |= data[offset + 2];
        }
        out[written++] = BASE64_ALPHABET[(chunk >> 18) & 0x3f];
        out[written++] = BASE64_ALPHABET[(chunk >> 12) & 0x3f];
        out[written++] = remaining > 1 ? BASE64_ALPHABET[(chunk >> 6) & 0x3f] : '=';
        out[written++] = remaining > 2 ? BASE64_ALPHABET[chunk & 0x3f] : '=';
    }
    out[written] = '\0';
    return out;
}

static uint8_t *base64_decode(const char *text, size_t length, size_t *out_length) {
    int8_t reverse[256];
    for (int index = 0; index < 256; index++) {
        reverse[index] = -1;
    }
    for (int index = 0; index < 64; index++) {
        reverse[(uint8_t) BASE64_ALPHABET[index]] = (int8_t) index;
    }
    uint8_t *out = (uint8_t *) malloc(length + 1);
    if (out == NULL) {
        return NULL;
    }
    size_t written = 0;
    int accumulator = 0;
    int bits = 0;
    for (size_t index = 0; index < length; index++) {
        int8_t value = reverse[(uint8_t) text[index]];
        if (value < 0) {
            continue;
        }
        accumulator = (accumulator << 6) | value;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[written++] = (uint8_t) ((accumulator >> bits) & 0xff);
        }
    }
    out[written] = '\0';
    *out_length = written;
    return out;
}

/* ------------------------------------------------------- blob 编码/解码 */

/*
 * "LIC:<账号>" 编成数字串:每个字符先算 base = (char << 2) - (index << 2) - length,
 * 取第一个非负的 base + delta(delta 0..3)与 index^2 异或,再写成「一位长度前缀 + 数字」。
 */
static char *blob_encode(const uint16_t *text, size_t length) {
    size_t capacity = length * 12 + 1;
    char *packed = (char *) malloc(capacity);
    if (packed == NULL) {
        return NULL;
    }
    size_t written = 0;
    for (size_t index = 0; index < length; index++) {
        int base = ((int) text[index] << 2) - (int) ((index << 2) + length);
        int shifted = -1;
        for (int delta = 0; delta < 4; delta++) {
            if (base + delta >= 0) {
                shifted = (base + delta) ^ (int) (index * index);
                break;
            }
        }
        if (shifted < 0) {
            free(packed);
            return NULL;
        }
        char digits[12];
        int count = 0;
        int value = shifted;
        if (value == 0) {
            digits[count++] = '0';
        }
        while (value > 0) {
            digits[count++] = (char) ('0' + value % 10);
            value /= 10;
        }
        packed[written++] = (char) ('0' + count);
        for (int step = count - 1; step >= 0; step--) {
            packed[written++] = digits[step];
        }
    }
    packed[written] = '\0';
    return packed;
}

/* blob_encode 的逆运算。 */
static uint16_t *blob_decode(const char *packed, size_t length, size_t *out_length) {
    uint16_t *numbers = (uint16_t *) malloc((length + 1) * sizeof(uint16_t));
    if (numbers == NULL) {
        return NULL;
    }
    size_t count = 0;
    size_t index = 0;
    while (index < length) {
        int digits = packed[index] - '0';
        if (digits > 0 && index + 1 + (size_t) digits <= length) {
            int value = 0;
            for (int step = 0; step < digits; step++) {
                value = value * 10 + (packed[index + 1 + (size_t) step] - '0');
            }
            numbers[count++] = (uint16_t) value;
        }
        index += (size_t) digits + 1;
    }
    uint16_t *decoded = (uint16_t *) malloc((count + 1) * sizeof(uint16_t));
    if (decoded == NULL) {
        free(numbers);
        return NULL;
    }
    for (size_t position = 0; position < count; position++) {
        int value = (int) (((position << 2) + count) + (numbers[position] ^ (position * position)));
        decoded[position] = (uint16_t) (value >> 2);
    }
    free(numbers);
    *out_length = count;
    return decoded;
}

/* --------------------------------------------------------- 校验辅助函数 */

/* 段 3 的 key = SHA-256(账号);公开版解出 "[1]"，完整版解出 "[0,1,4]"。 */
static int check_segment3(const char *segment, const char *account, size_t account_length) {
    Sha256 sha;
    sha256_init(&sha);
    sha256_update(&sha, (const uint8_t *) account, account_length);
    uint8_t key[32];
    sha256_final(&sha, key);

    size_t raw_length = 0;
    uint8_t *raw = base64_decode(segment, strlen(segment), &raw_length);
    if (raw == NULL) {
        return 0;
    }
    int matches = 0;
    if (raw_length == 16) {
        uint8_t round_keys[240];
        aes256_expand(key, round_keys);
        uint8_t state[16];
        memcpy(state, raw, 16);
        uint8_t zero[16];
        memset(zero, 0, 16);
        aes256_decrypt_block(round_keys, state, zero);
        size_t expected_length = strlen(LICENSE_FEATURE_SET);
        matches = memcmp(state, LICENSE_FEATURE_SET, expected_length) == 0
                || memcmp(state, LICENSE_FEATURE_SET_LEGACY,
                          strlen(LICENSE_FEATURE_SET_LEGACY)) == 0;
    }
    free(raw);
    return matches;
}

/*
 * 第一层解密后的明文形如 "<blob 的 Base64>#f#<段3>":
 * 先按 '#' 切 3 段,再把第 1 段 Base64 解出来做 blob 解码,得到 "LIC:<账号>";
 * 最后用账号摘要当 key 解第 3 段,必须等于 "[1]"。
 */
static int check_license(const char *plain, const char *account, size_t account_length) {
    /* 找两个 '#' 的位置。 */
    const char *first = strchr(plain, '#');
    if (first == NULL) {
        return 0;
    }
    const char *second = strchr(first + 1, '#');
    if (second == NULL) {
        return 0;
    }
    size_t blob_length = (size_t) (first - plain);
    size_t segment_length = strlen(second + 1);

    size_t packed_length = 0;
    uint8_t *packed = base64_decode(plain, blob_length, &packed_length);
    if (packed == NULL) {
        return 0;
    }
    size_t length = 0;
    uint16_t *decoded = blob_decode((const char *) packed, packed_length, &length);
    free(packed);
    if (decoded == NULL) {
        return 0;
    }
    int usable = 0;
    size_t expected = 4 + account_length;
    if (length == expected && decoded[0] == 'L' && decoded[1] == 'I' && decoded[2] == 'C'
            && decoded[3] == ':') {
        int matches = 1;
        for (size_t index = 0; index < account_length; index++) {
            if (decoded[4 + index] != (uint16_t) (uint8_t) account[index]) {
                matches = 0;
                break;
            }
        }
        if (matches) {
            char *segment = (char *) malloc(segment_length + 1);
            if (segment != NULL) {
                memcpy(segment, second + 1, segment_length);
                segment[segment_length] = '\0';
                usable = check_segment3(segment, account, account_length);
                free(segment);
            }
        }
    }
    free(decoded);
    return usable;
}

/* verifier6 解密后:blob 解出 "verifier6:<flag>:<账号>"。 */
static int check_verifier6(const char *plain, const char *account, size_t account_length) {
    size_t packed_length = 0;
    uint8_t *packed = base64_decode(plain, strlen(plain), &packed_length);
    if (packed == NULL) {
        return 0;
    }
    size_t length = 0;
    uint16_t *decoded = blob_decode((const char *) packed, packed_length, &length);
    free(packed);
    if (decoded == NULL) {
        return 0;
    }
    const char *prefix = "verifier6#";
    size_t prefix_length = strlen(prefix);
    int matches = length > prefix_length + 1 + account_length;
    if (matches) {
        for (size_t index = 0; index < prefix_length; index++) {
            if (decoded[index] != (uint16_t) (uint8_t) prefix[index]) {
                matches = 0;
                break;
            }
        }
    }
    if (matches) {
        size_t suffix = length - account_length;
        if (decoded[suffix - 1] != ':') {
            matches = 0;
        } else {
            for (size_t index = 0; index < account_length; index++) {
                if (decoded[suffix + index] != (uint16_t) (uint8_t) account[index]) {
                    matches = 0;
                    break;
                }
            }
        }
    }
    free(decoded);
    return matches;
}

/* ------------------------------------------------------------- JNI 入口 */

/* UTF-8 -> UTF-16(与 secret.c 的处理一致)。 */
static uint16_t *utf8_to_utf16(const char *text, size_t length, size_t *out_length) {
    uint16_t *out = (uint16_t *) malloc((length + 1) * sizeof(uint16_t));
    if (out == NULL) {
        return NULL;
    }
    size_t written = 0;
    for (size_t index = 0; index < length; ) {
        uint8_t value = (uint8_t) text[index];
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
            code_point = value;
        }
        for (int step = 1; step <= extra && index + (size_t) step < length; step++) {
            code_point = (code_point << 6) | ((uint8_t) text[index + (size_t) step] & 0x3f);
        }
        index += (size_t) extra + 1;
        if (code_point >= 0x10000) {
            code_point -= 0x10000;
            out[written++] = (uint16_t) (0xd800 + (code_point >> 10));
            out[written++] = (uint16_t) (0xdc00 + (code_point & 0x3ff));
        } else {
            out[written++] = (uint16_t) code_point;
        }
    }
    *out_length = written;
    return out;
}
#endif /* WEXPOSEDHOOK_LICENSE_CRYPTO_INC */