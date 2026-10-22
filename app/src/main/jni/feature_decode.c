/*
 * 功能包容器解密：MsgPack 7 元组 + PBEWithMD5AndDES + AES-CBC。
 *
 * 容器结构、magic、permutation、字段映射都在本文件；Java 只拿解密后的
 * 内层 APK，再用标准 ZipInputStream 取 classes.dex。
 */
#include <jni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ---------------- MD5 ---------------- */

typedef struct {
    uint32_t state[4];
    uint64_t bits;
    uint8_t block[64];
    size_t used;
} Md5;

static uint32_t rol32(uint32_t value, int shift) {
    return (value << shift) | (value >> (32 - shift));
}

static void md5_transform(uint32_t state[4], const uint8_t block[64]) {
    static const uint32_t K[64] = {
            0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
            0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
            0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
            0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
            0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
            0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
            0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
            0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
            0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
            0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
            0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
            0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
            0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
            0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
            0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
            0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    };
    static const uint8_t S[64] = {
            7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
            5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
            4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
            6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    };
    uint32_t words[16];
    for (int index = 0; index < 16; index++) {
        words[index] = (uint32_t) block[index * 4]
                       | ((uint32_t) block[index * 4 + 1] << 8)
                       | ((uint32_t) block[index * 4 + 2] << 16)
                       | ((uint32_t) block[index * 4 + 3] << 24);
    }
    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    for (int index = 0; index < 64; index++) {
        uint32_t f;
        int g;
        if (index < 16) {
            f = (b & c) | ((~b) & d);
            g = index;
        } else if (index < 32) {
            f = (d & b) | ((~d) & c);
            g = (5 * index + 1) & 15;
        } else if (index < 48) {
            f = b ^ c ^ d;
            g = (3 * index + 5) & 15;
        } else {
            f = c ^ (b | (~d));
            g = (7 * index) & 15;
        }
        uint32_t temp = d;
        d = c;
        c = b;
        b = b + rol32(a + f + K[index] + words[g], S[index]);
        a = temp;
    }
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

static void md5_init(Md5 *ctx) {
    ctx->state[0] = 0x67452301u;
    ctx->state[1] = 0xefcdab89u;
    ctx->state[2] = 0x98badcfeu;
    ctx->state[3] = 0x10325476u;
    ctx->bits = 0;
    ctx->used = 0;
}

static void md5_update(Md5 *ctx, const uint8_t *data, size_t length) {
    ctx->bits += (uint64_t) length * 8u;
    while (length > 0) {
        size_t room = 64 - ctx->used;
        size_t take = length < room ? length : room;
        memcpy(ctx->block + ctx->used, data, take);
        ctx->used += take;
        data += take;
        length -= take;
        if (ctx->used == 64) {
            md5_transform(ctx->state, ctx->block);
            ctx->used = 0;
        }
    }
}

static void md5_final(Md5 *ctx, uint8_t out[16]) {
    uint64_t bits = ctx->bits;
    uint8_t pad = 0x80;
    md5_update(ctx, &pad, 1);
    uint8_t zero = 0;
    while (ctx->used != 56) {
        md5_update(ctx, &zero, 1);
    }
    for (int index = 0; index < 8; index++) {
        ctx->block[56 + index] = (uint8_t) (bits >> (index * 8));
    }
    md5_transform(ctx->state, ctx->block);
    for (int index = 0; index < 16; index++) {
        out[index] = (uint8_t) (ctx->state[index / 4] >> ((index % 4) * 8));
    }
}

/* ---------------- DES ---------------- */

static const uint8_t DES_IP[64] = {
        58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
};

static const uint8_t DES_FP[64] = {
        40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
};

static const uint8_t DES_E[48] = {
        32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
};

static const uint8_t DES_P[32] = {
        16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
        2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
};

static const uint8_t DES_PC1[56] = {
        57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
};

static const uint8_t DES_PC2[48] = {
        14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
};

static const uint8_t DES_SHIFT[16] = {
        1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1,
};

static const uint8_t DES_S[8][64] = {
        {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
         0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
         4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
         15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13},
        {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
         3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
         0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
         13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9},
        {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
         13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
         13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
         1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12},
        {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
         13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
         10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
         3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14},
        {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
         14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
         4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
         11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3},
        {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
         10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
         9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
         4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13},
        {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
         13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
         1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
         6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12},
        {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
         1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
         7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
         2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11},
};

static uint64_t des_permute(uint64_t input, int input_bits,
                            const uint8_t *table, int output_bits) {
    uint64_t output = 0;
    for (int index = 0; index < output_bits; index++) {
        int position = table[index];
        output = (output << 1) | ((input >> (input_bits - position)) & 1u);
    }
    return output;
}

static uint32_t des_rotate(uint32_t value, int shift) {
    return ((value << shift) | (value >> (28 - shift))) & 0x0fffffffu;
}

static void des_schedule(uint64_t key, uint64_t subkeys[16]) {
    uint64_t permuted = des_permute(key, 64, DES_PC1, 56);
    uint32_t left = (uint32_t) (permuted >> 28) & 0x0fffffffu;
    uint32_t right = (uint32_t) permuted & 0x0fffffffu;
    for (int round = 0; round < 16; round++) {
        left = des_rotate(left, DES_SHIFT[round]);
        right = des_rotate(right, DES_SHIFT[round]);
        subkeys[round] = des_permute(((uint64_t) left << 28) | right,
                                     56, DES_PC2, 48);
    }
}

static uint64_t des_crypt(uint64_t block, const uint64_t subkeys[16], int decrypt) {
    uint64_t permuted = des_permute(block, 64, DES_IP, 64);
    uint32_t left = (uint32_t) (permuted >> 32);
    uint32_t right = (uint32_t) permuted;
    for (int round = 0; round < 16; round++) {
        uint64_t expanded = des_permute(right, 32, DES_E, 48);
        uint64_t mixed = expanded ^ subkeys[decrypt ? 15 - round : round];
        uint32_t substituted = 0;
        for (int box = 0; box < 8; box++) {
            int shift = 42 - box * 6;
            int six = (int) ((mixed >> shift) & 0x3f);
            int row = ((six & 0x20) >> 4) | (six & 1);
            int column = (six >> 1) & 0x0f;
            substituted = (substituted << 4) | DES_S[box][row * 16 + column];
        }
        uint32_t function = (uint32_t) des_permute(substituted, 32, DES_P, 32);
        uint32_t next = left ^ function;
        left = right;
        right = next;
    }
    uint64_t preoutput = ((uint64_t) right << 32) | left;
    return des_permute(preoutput, 64, DES_FP, 64);
}

/* PBEWithMD5AndDES：key = MD5(password || salt)[0..7]，IV = [8..15]。 */
static int pbe_decrypt(const uint8_t *password, size_t password_length,
                       const uint8_t salt[8], const uint8_t *input,
                       size_t input_length, uint8_t *output) {
    if (input_length == 0 || input_length % 8 != 0) {
        return 0;
    }
    Md5 ctx;
    md5_init(&ctx);
    md5_update(&ctx, password, password_length);
    md5_update(&ctx, salt, 8);
    uint8_t digest[16];
    md5_final(&ctx, digest);
    /* PBKDF1：MD5 迭代 1000 次，key/IV 取最后一轮的前 16 字节。 */
    for (int iteration = 1; iteration < 1000; iteration++) {
        md5_init(&ctx);
        md5_update(&ctx, digest, 16);
        md5_final(&ctx, digest);
    }
    uint64_t key = 0;
    for (int index = 0; index < 8; index++) {
        key = (key << 8) | digest[index];
    }
    uint64_t subkeys[16];
    des_schedule(key, subkeys);
    uint64_t previous = 0;
    for (int index = 0; index < 8; index++) {
        previous = (previous << 8) | digest[8 + index];
    }
    for (size_t offset = 0; offset < input_length; offset += 8) {
        uint64_t cipher = 0;
        for (int index = 0; index < 8; index++) {
            cipher = (cipher << 8) | input[offset + index];
        }
        uint64_t plain = des_crypt(cipher, subkeys, 1) ^ previous;
        for (int index = 0; index < 8; index++) {
            output[offset + index] = (uint8_t) (plain >> (56 - index * 8));
        }
        previous = cipher;
    }
    /* PKCS#5 去填充 */
    uint8_t padding = output[input_length - 1];
    if (padding == 0 || padding > 8 || padding > input_length) {
        return 0;
    }
    for (size_t index = 0; index < padding; index++) {
        if (output[input_length - 1 - index] != padding) {
            return 0;
        }
    }
    memset(output + input_length - padding, 0, padding);
    return (int) (input_length - padding);
}

/* ---------------- AES-128 ---------------- */

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

static const uint8_t AES_INV_SBOX[256] = {
        0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
        0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
        0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
        0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
        0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
        0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
        0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
        0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
        0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
        0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
        0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
        0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
        0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
        0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
        0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
        0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d,
};

static uint8_t aes_xtime(uint8_t value) {
    return (uint8_t) ((value << 1) ^ ((value & 0x80) ? 0x1b : 0));
}

static uint8_t aes_mul(uint8_t left, uint8_t right) {
    uint8_t result = 0;
    while (right != 0) {
        if (right & 1) {
            result ^= left;
        }
        left = aes_xtime(left);
        right >>= 1;
    }
    return result;
}

static void aes_expand(const uint8_t key[16], uint8_t round_keys[176]) {
    memcpy(round_keys, key, 16);
    static const uint8_t RCON[10] = {
            0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};
    for (int index = 16; index < 176; index += 4) {
        uint8_t temp[4] = {
                round_keys[index - 4], round_keys[index - 3],
                round_keys[index - 2], round_keys[index - 1]};
        if (index % 16 == 0) {
            uint8_t first = temp[0];
            temp[0] = (uint8_t) (AES_SBOX[temp[1]] ^ RCON[index / 16 - 1]);
            temp[1] = AES_SBOX[temp[2]];
            temp[2] = AES_SBOX[temp[3]];
            temp[3] = AES_SBOX[first];
        }
        round_keys[index] = round_keys[index - 16] ^ temp[0];
        round_keys[index + 1] = round_keys[index - 15] ^ temp[1];
        round_keys[index + 2] = round_keys[index - 14] ^ temp[2];
        round_keys[index + 3] = round_keys[index - 13] ^ temp[3];
    }
}

static void aes_add_round_key(uint8_t state[16], const uint8_t *key) {
    for (int index = 0; index < 16; index++) {
        state[index] ^= key[index];
    }
}

static void aes_inv_shift_rows(uint8_t state[16]) {
    uint8_t temp[16];
    memcpy(temp, state, 16);
    state[0] = temp[0]; state[4] = temp[4]; state[8] = temp[8]; state[12] = temp[12];
    state[1] = temp[13]; state[5] = temp[1]; state[9] = temp[5]; state[13] = temp[9];
    state[2] = temp[10]; state[6] = temp[14]; state[10] = temp[2]; state[14] = temp[6];
    state[3] = temp[7]; state[7] = temp[11]; state[11] = temp[15]; state[15] = temp[3];
}

static void aes_inv_sub_bytes(uint8_t state[16]) {
    for (int index = 0; index < 16; index++) {
        state[index] = AES_INV_SBOX[state[index]];
    }
}

static void aes_inv_mix_columns(uint8_t state[16]) {
    for (int column = 0; column < 4; column++) {
        uint8_t *value = state + column * 4;
        uint8_t a = value[0], b = value[1], c = value[2], d = value[3];
        value[0] = aes_mul(a, 14) ^ aes_mul(b, 11) ^ aes_mul(c, 13) ^ aes_mul(d, 9);
        value[1] = aes_mul(a, 9) ^ aes_mul(b, 14) ^ aes_mul(c, 11) ^ aes_mul(d, 13);
        value[2] = aes_mul(a, 13) ^ aes_mul(b, 9) ^ aes_mul(c, 14) ^ aes_mul(d, 11);
        value[3] = aes_mul(a, 11) ^ aes_mul(b, 13) ^ aes_mul(c, 9) ^ aes_mul(d, 14);
    }
}

static void aes_decrypt_block(const uint8_t input[16], const uint8_t round_keys[176],
                              uint8_t output[16]) {
    uint8_t state[16];
    memcpy(state, input, 16);
    aes_add_round_key(state, round_keys + 160);
    for (int round = 9; round >= 1; round--) {
        aes_inv_shift_rows(state);
        aes_inv_sub_bytes(state);
        aes_add_round_key(state, round_keys + round * 16);
        aes_inv_mix_columns(state);
    }
    aes_inv_shift_rows(state);
    aes_inv_sub_bytes(state);
    aes_add_round_key(state, round_keys);
    memcpy(output, state, 16);
}

static int aes_cbc_decrypt(const uint8_t key[16], const uint8_t iv[16],
                           const uint8_t *input, size_t input_length,
                           uint8_t *output) {
    if (input_length == 0 || input_length % 16 != 0) {
        return 0;
    }
    uint8_t round_keys[176];
    aes_expand(key, round_keys);
    uint8_t previous[16];
    memcpy(previous, iv, 16);
    for (size_t offset = 0; offset < input_length; offset += 16) {
        uint8_t block[16];
        aes_decrypt_block(input + offset, round_keys, block);
        for (int index = 0; index < 16; index++) {
            output[offset + index] = block[index] ^ previous[index];
        }
        memcpy(previous, input + offset, 16);
    }
    uint8_t padding = output[input_length - 1];
    if (padding == 0 || padding > 16 || padding > input_length) {
        return 0;
    }
    for (size_t index = 0; index < padding; index++) {
        if (output[input_length - 1 - index] != padding) {
            return 0;
        }
    }
    memset(output + input_length - padding, 0, padding);
    return (int) (input_length - padding);
}

/* ---------------- MsgPack ---------------- */

enum {
    MP_INTEGER = 1,
    MP_BYTES = 2,
    MP_ARRAY = 3,
    MP_NIL = 4,
    MP_BOOL = 5,
};

typedef struct MpValue {
    int type;
    uint32_t integer;
    const uint8_t *bytes;
    size_t length;
    struct MpValue *items;
    int count;
} MpValue;

typedef struct {
    const uint8_t *data;
    size_t size;
    size_t position;
} MpReader;

static int mp_read(MpReader *reader, MpValue *value, int depth);

static void mp_free(MpValue *value) {
    if (value->type == MP_ARRAY && value->items != NULL) {
        for (int index = 0; index < value->count; index++) {
            mp_free(&value->items[index]);
        }
        free(value->items);
        value->items = NULL;
    }
}

static int mp_take(MpReader *reader, size_t length, const uint8_t **out) {
    if (reader->position + length > reader->size) {
        return 0;
    }
    *out = reader->data + reader->position;
    reader->position += length;
    return 1;
}

static int mp_read(MpReader *reader, MpValue *value, int depth) {
    if (depth > 8) {
        return 0;
    }
    memset(value, 0, sizeof(*value));
    const uint8_t *cursor;
    if (!mp_take(reader, 1, &cursor)) {
        return 0;
    }
    uint8_t tag = cursor[0];
    if (tag <= 0x7f) {
        value->type = MP_INTEGER;
        value->integer = tag;
        return 1;
    }
    if (tag >= 0x90 && tag <= 0x9f) {
        int count = tag & 0x0f;
        value->type = MP_ARRAY;
        value->count = count;
        value->items = (MpValue *) calloc((size_t) count, sizeof(MpValue));
        if (value->items == NULL) {
            return 0;
        }
        for (int index = 0; index < count; index++) {
            if (!mp_read(reader, &value->items[index], depth + 1)) {
                mp_free(value);
                return 0;
            }
        }
        return 1;
    }
    if (tag >= 0xa0 && tag <= 0xbf) {
        size_t length = tag & 0x1f;
        value->type = MP_BYTES;
        value->length = length;
        return mp_take(reader, length, &value->bytes);
    }
    if (tag == 0xc0) {
        value->type = MP_NIL;
        return 1;
    }
    if (tag == 0xc2 || tag == 0xc3) {
        value->type = MP_BOOL;
        value->integer = tag == 0xc3;
        return 1;
    }
    if (tag == 0xc4 || tag == 0xc5 || tag == 0xc6
        || tag == 0xd9 || tag == 0xda || tag == 0xdb) {
        size_t length;
        if (tag == 0xc4 || tag == 0xd9) {
            if (!mp_take(reader, 1, &cursor)) {
                return 0;
            }
            length = cursor[0];
        } else if (tag == 0xc5 || tag == 0xda) {
            if (!mp_take(reader, 2, &cursor)) {
                return 0;
            }
            length = ((size_t) cursor[0] << 8) | cursor[1];
        } else {
            if (!mp_take(reader, 4, &cursor)) {
                return 0;
            }
            length = ((size_t) cursor[0] << 24) | ((size_t) cursor[1] << 16)
                     | ((size_t) cursor[2] << 8) | cursor[3];
        }
        value->type = MP_BYTES;
        value->length = length;
        return mp_take(reader, length, &value->bytes);
    }
    if (tag == 0xcc || tag == 0xcd || tag == 0xce
        || tag == 0xd0 || tag == 0xd1 || tag == 0xd2) {
        int length = tag == 0xcc || tag == 0xd0 ? 1
                     : (tag == 0xcd || tag == 0xd1 ? 2 : 4);
        if (!mp_take(reader, (size_t) length, &cursor)) {
            return 0;
        }
        uint32_t number = 0;
        for (int index = 0; index < length; index++) {
            number = (number << 8) | cursor[index];
        }
        value->type = MP_INTEGER;
        value->integer = number;
        return 1;
    }
    return 0;
}

typedef struct {
    const uint8_t *payload;
    size_t payload_length;
    const uint8_t *salt;
    const uint8_t *seed;
    size_t seed_length;
} Container;

static int container_parse(const uint8_t *data, size_t length, Container *out) {
    static const uint8_t MAGIC[4] = {0x97, 0xc4, 0x01, 0x30};
    int offset = -1;
    size_t limit = length > 64 ? 64 : length;
    for (size_t index = 0; index + 4 <= limit; index++) {
        if (memcmp(data + index, MAGIC, 4) == 0) {
            offset = (int) index;
            break;
        }
    }
    if (offset < 0) {
        return 0;
    }
    MpReader reader = {data, length, (size_t) offset};
    MpValue array;
    if (!mp_read(&reader, &array, 0) || array.type != MP_ARRAY || array.count != 7) {
        mp_free(&array);
        return 0;
    }
    MpValue *permutation = &array.items[1];
    if (permutation->type != MP_BYTES || permutation->length < 5) {
        mp_free(&array);
        return 0;
    }
    memset(out, 0, sizeof(*out));
    for (int index = 0; index < 5; index++) {
        MpValue *value = &array.items[index + 2];
        if (value->type != MP_BYTES) {
            mp_free(&array);
            return 0;
        }
        int field = permutation->bytes[index] - '0';
        if (field == 1) {
            out->payload = value->bytes;
            out->payload_length = value->length;
        } else if (field == 3 && value->length == 8) {
            out->salt = value->bytes;
        } else if (field == 4) {
            out->seed = value->bytes;
            out->seed_length = value->length;
        } else if (field < 1 || field > 5) {
            mp_free(&array);
            return 0;
        }
    }
    int valid = out->payload != NULL && out->salt != NULL && out->seed != NULL;
    mp_free(&array);
    return valid;
}

/* ---------------- 容器解密 ---------------- */

static uint8_t *decrypt_container(const uint8_t *data, size_t length,
                                  const char *password, size_t *out_length) {
    Container container;
    if (!container_parse(data, length, &container)) {
        return NULL;
    }
    if (container.seed_length == 0 || container.seed_length > 64) {
        return NULL;
    }
    uint8_t aes_key[64];
    int aes_key_length = pbe_decrypt((const uint8_t *) password, strlen(password),
                                     container.salt, container.seed,
                                     container.seed_length, aes_key);
    if (aes_key_length != 16 || container.payload_length <= 16) {
        memset(aes_key, 0, sizeof(aes_key));
        return NULL;
    }
    uint8_t *plain = (uint8_t *) malloc(container.payload_length);
    if (plain == NULL) {
        memset(aes_key, 0, sizeof(aes_key));
        return NULL;
    }
    int plain_length = aes_cbc_decrypt(aes_key, container.payload,
                                       container.payload + 16,
                                       container.payload_length - 16, plain);
    memset(aes_key, 0, sizeof(aes_key));
    if (plain_length <= 0) {
        free(plain);
        return NULL;
    }
    *out_length = (size_t) plain_length;
    return plain;
}

static uint8_t *feature_decode(const uint8_t *container, size_t length,
                               const char *outer_password,
                               const char *inner_password,
                               size_t *out_length) {
    size_t outer_length = 0;
    uint8_t *outer = decrypt_container(container, length, outer_password, &outer_length);
    if (outer == NULL) {
        return NULL;
    }
    /* 外层明文是 MsgPack 数组，第 3 个元素是内层容器。 */
    uint8_t *inner_apk = NULL;
    MpReader reader = {outer, outer_length, 0};
    MpValue array;
    if (mp_read(&reader, &array, 0) && array.type == MP_ARRAY
        && array.count >= 3 && array.items[2].type == MP_BYTES) {
        size_t inner_length = 0;
        uint8_t *inner = decrypt_container(array.items[2].bytes,
                                           array.items[2].length,
                                           inner_password, &inner_length);
        if (inner != NULL) {
            if (inner_length >= 2 && inner[0] == 'P' && inner[1] == 'K') {
                inner_apk = inner;
                *out_length = inner_length;
            } else {
                free(inner);
            }
        }
    }
    mp_free(&array);
    memset(outer, 0, outer_length);
    free(outer);
    return inner_apk;
}

jbyteArray wxh_native_decode_container(JNIEnv *env, jclass type,
                                       jbyteArray container,
                                       jstring outer_password,
                                       jstring inner_password) {
    (void) type;
    if (container == NULL || outer_password == NULL || inner_password == NULL) {
        return NULL;
    }
    jsize length = (*env)->GetArrayLength(env, container);
    if (length <= 0) {
        return NULL;
    }
    const char *outer = (*env)->GetStringUTFChars(env, outer_password, NULL);
    const char *inner = (*env)->GetStringUTFChars(env, inner_password, NULL);
    if (outer == NULL || inner == NULL) {
        if (outer != NULL) {
            (*env)->ReleaseStringUTFChars(env, outer_password, outer);
        }
        if (inner != NULL) {
            (*env)->ReleaseStringUTFChars(env, inner_password, inner);
        }
        return NULL;
    }
    uint8_t *data = (uint8_t *) malloc((size_t) length);
    if (data == NULL) {
        (*env)->ReleaseStringUTFChars(env, outer_password, outer);
        (*env)->ReleaseStringUTFChars(env, inner_password, inner);
        return NULL;
    }
    (*env)->GetByteArrayRegion(env, container, 0, length, (jbyte *) data);
    size_t output_length = 0;
    uint8_t *output = feature_decode(data, (size_t) length, outer, inner, &output_length);
    free(data);
    (*env)->ReleaseStringUTFChars(env, outer_password, outer);
    (*env)->ReleaseStringUTFChars(env, inner_password, inner);
    jbyteArray result = NULL;
    if (output != NULL && output_length > 0 && output_length <= 0x7fffffff) {
        result = (*env)->NewByteArray(env, (jsize) output_length);
        if (result != NULL) {
            (*env)->SetByteArrayRegion(env, result, 0, (jsize) output_length,
                                       (const jbyte *) output);
        }
    }
    if (output != NULL) {
        memset(output, 0, output_length);
        free(output);
    }
    return result;
}
