/*
 * 功能包 _s 验签：RSA PKCS#1 v1.5 + SHA-1。
 *
 * 公钥（X.509 SubjectPublicKeyInfo DER）在 pack_tables.inc，Java 侧不再持有
 * PublicKey / Signature。验签失败由调用方删除 body 与 _s，下次启动重新恢复。
 */
#include <jni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "pack_tables.inc"

/* ---------------- SHA-1 ---------------- */

typedef struct {
    uint32_t state[5];
    uint64_t bits;
    uint8_t block[64];
    size_t used;
} Sha1;

static uint32_t rol32(uint32_t value, int shift) {
    return (value << shift) | (value >> (32 - shift));
}

static void sha1_block(Sha1 *ctx, const uint8_t *block) {
    uint32_t words[80];
    for (int index = 0; index < 16; index++) {
        words[index] = ((uint32_t) block[index * 4] << 24)
                       | ((uint32_t) block[index * 4 + 1] << 16)
                       | ((uint32_t) block[index * 4 + 2] << 8)
                       | (uint32_t) block[index * 4 + 3];
    }
    for (int index = 16; index < 80; index++) {
        words[index] = rol32(words[index - 3] ^ words[index - 8]
                             ^ words[index - 14] ^ words[index - 16], 1);
    }
    uint32_t a = ctx->state[0];
    uint32_t b = ctx->state[1];
    uint32_t c = ctx->state[2];
    uint32_t d = ctx->state[3];
    uint32_t e = ctx->state[4];
    for (int index = 0; index < 80; index++) {
        uint32_t function;
        uint32_t constant;
        if (index < 20) {
            function = (b & c) | ((~b) & d);
            constant = 0x5a827999u;
        } else if (index < 40) {
            function = b ^ c ^ d;
            constant = 0x6ed9eba1u;
        } else if (index < 60) {
            function = (b & c) | (b & d) | (c & d);
            constant = 0x8f1bbcdcu;
        } else {
            function = b ^ c ^ d;
            constant = 0xca62c1d6u;
        }
        uint32_t temp = rol32(a, 5) + function + e + constant + words[index];
        e = d;
        d = c;
        c = rol32(b, 30);
        b = a;
        a = temp;
    }
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
}

static void sha1_init(Sha1 *ctx) {
    ctx->state[0] = 0x67452301u;
    ctx->state[1] = 0xefcdab89u;
    ctx->state[2] = 0x98badcfeu;
    ctx->state[3] = 0x10325476u;
    ctx->state[4] = 0xc3d2e1f0u;
    ctx->bits = 0;
    ctx->used = 0;
}

static void sha1_update(Sha1 *ctx, const uint8_t *data, size_t length) {
    ctx->bits += (uint64_t) length * 8u;
    while (length > 0) {
        size_t room = 64 - ctx->used;
        size_t take = length < room ? length : room;
        memcpy(ctx->block + ctx->used, data, take);
        ctx->used += take;
        data += take;
        length -= take;
        if (ctx->used == 64) {
            sha1_block(ctx, ctx->block);
            ctx->used = 0;
        }
    }
}

static void sha1_final(Sha1 *ctx, uint8_t out[20]) {
    uint64_t bits = ctx->bits;
    uint8_t pad = 0x80;
    sha1_update(ctx, &pad, 1);
    uint8_t zero = 0;
    while (ctx->used != 56) {
        sha1_update(ctx, &zero, 1);
    }
    uint8_t length[8];
    for (int index = 0; index < 8; index++) {
        length[7 - index] = (uint8_t) (bits >> (index * 8));
    }
    /* 直接写入长度，避免把 padding 计入 bits。 */
    memcpy(ctx->block + 56, length, 8);
    sha1_block(ctx, ctx->block);
    for (int index = 0; index < 5; index++) {
        out[index * 4] = (uint8_t) (ctx->state[index] >> 24);
        out[index * 4 + 1] = (uint8_t) (ctx->state[index] >> 16);
        out[index * 4 + 2] = (uint8_t) (ctx->state[index] >> 8);
        out[index * 4 + 3] = (uint8_t) ctx->state[index];
    }
}

/* ---------------- 大整数（最多 2048 位） ---------------- */

/* 多留两个 limb：模约简中的左移进位不能丢。 */
#define BN_LIMBS 66
#define BN_DOUBLE_LIMBS 132

typedef struct {
    uint32_t limb[BN_LIMBS];
    int count;
} BigNum;

static void bn_trim(BigNum *value) {
    while (value->count > 0 && value->limb[value->count - 1] == 0) {
        value->count--;
    }
}

static void bn_from_bytes(BigNum *value, const uint8_t *data, size_t length) {
    memset(value, 0, sizeof(*value));
    for (size_t index = 0; index < length; index++) {
        uint8_t byte = data[length - 1 - index];
        size_t limb = index / 4;
        int shift = (int) (index % 4) * 8;
        if (limb < BN_LIMBS) {
            value->limb[limb] |= (uint32_t) byte << shift;
        }
    }
    value->count = BN_LIMBS;
    bn_trim(value);
}

static void bn_to_bytes(const BigNum *value, uint8_t *out, size_t length) {
    memset(out, 0, length);
    for (size_t index = 0; index < length; index++) {
        size_t limb = index / 4;
        int shift = (int) (index % 4) * 8;
        uint32_t byte = limb < (size_t) value->count
                        ? (value->limb[limb] >> shift) & 0xffu : 0;
        out[length - 1 - index] = (uint8_t) byte;
    }
}

static int bn_compare(const BigNum *left, const BigNum *right) {
    if (left->count != right->count) {
        return left->count < right->count ? -1 : 1;
    }
    for (int index = left->count - 1; index >= 0; index--) {
        if (left->limb[index] != right->limb[index]) {
            return left->limb[index] < right->limb[index] ? -1 : 1;
        }
    }
    return 0;
}

/* left -= right，要求 left >= right。 */
static void bn_subtract(BigNum *left, const BigNum *right) {
    int64_t borrow = 0;
    for (int index = 0; index < left->count; index++) {
        int64_t value = (int64_t) left->limb[index] - borrow
                        - (index < right->count ? right->limb[index] : 0);
        if (value < 0) {
            value += ((int64_t) 1 << 32);
            borrow = 1;
        } else {
            borrow = 0;
        }
        left->limb[index] = (uint32_t) value;
    }
    bn_trim(left);
}

static void bn_shift_left_one(BigNum *value) {
    uint32_t carry = 0;
    for (int index = 0; index < value->count; index++) {
        uint32_t next = value->limb[index] >> 31;
        value->limb[index] = (value->limb[index] << 1) | carry;
        carry = next;
    }
    if (carry != 0 && value->count < BN_LIMBS) {
        value->limb[value->count++] = carry;
    }
}

typedef struct {
    uint32_t limb[BN_DOUBLE_LIMBS];
    int count;
} BigNum2;

static void bn2_trim(BigNum2 *value) {
    while (value->count > 0 && value->limb[value->count - 1] == 0) {
        value->count--;
    }
}

static void bn_multiply(const BigNum *left, const BigNum *right, BigNum2 *out) {
    memset(out, 0, sizeof(*out));
    for (int i = 0; i < left->count; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < right->count; j++) {
            uint64_t value = (uint64_t) left->limb[i] * right->limb[j]
                             + out->limb[i + j] + carry;
            out->limb[i + j] = (uint32_t) value;
            carry = value >> 32;
        }
        int index = i + right->count;
        while (carry != 0 && index < BN_DOUBLE_LIMBS) {
            uint64_t value = (uint64_t) out->limb[index] + carry;
            out->limb[index] = (uint32_t) value;
            carry = value >> 32;
            index++;
        }
    }
    out->count = BN_DOUBLE_LIMBS;
    bn2_trim(out);
}

/* out = value mod modulus，按位移长除法。 */
static void bn_modulo(const BigNum2 *value, const BigNum *modulus, BigNum *out) {
    memset(out, 0, sizeof(*out));
    int bits = value->count * 32;
    for (int bit = bits - 1; bit >= 0; bit--) {
        bn_shift_left_one(out);
        out->limb[0] |= (value->limb[bit / 32] >> (bit % 32)) & 1u;
        if (out->count == 0 && out->limb[0] != 0) {
            out->count = 1;
        }
        if (bn_compare(out, modulus) >= 0) {
            bn_subtract(out, modulus);
        }
    }
}

static void bn_mod_multiply(const BigNum *left, const BigNum *right,
                            const BigNum *modulus, BigNum *out) {
    BigNum2 product;
    bn_multiply(left, right, &product);
    bn_modulo(&product, modulus, out);
}

/* out = base ^ exponent mod modulus。 */
static void bn_mod_power(const BigNum *base, uint32_t exponent,
                         const BigNum *modulus, BigNum *out) {
    BigNum result;
    BigNum factor = *base;
    memset(&result, 0, sizeof(result));
    result.limb[0] = 1;
    result.count = 1;
    while (exponent != 0) {
        if ((exponent & 1u) != 0) {
            bn_mod_multiply(&result, &factor, modulus, &result);
        }
        exponent >>= 1;
        if (exponent != 0) {
            bn_mod_multiply(&factor, &factor, modulus, &factor);
        }
    }
    *out = result;
}

/* ---------------- DER ---------------- */

static int der_read(const uint8_t **cursor, const uint8_t *end,
                    uint8_t *tag, const uint8_t **value, size_t *length) {
    if (*cursor >= end) {
        return 0;
    }
    uint8_t type = *(*cursor)++;
    if (type == 0 || *cursor >= end) {
        return 0;
    }
    size_t size = *(*cursor)++;
    if ((size & 0x80u) != 0) {
        int count = (int) (size & 0x7fu);
        if (count <= 0 || count > 4 || *cursor + count > end) {
            return 0;
        }
        size = 0;
        for (int index = 0; index < count; index++) {
            size = (size << 8) | *(*cursor)++;
        }
    }
    if (*cursor + size > end) {
        return 0;
    }
    *tag = type;
    *value = *cursor;
    *length = size;
    *cursor += size;
    return 1;
}

static int rsa_public_key(const uint8_t **modulus, size_t *modulus_length,
                          uint32_t *exponent) {
    const uint8_t *cursor = PACK_SIGN_PUBLIC_KEY;
    const uint8_t *end = cursor + sizeof(PACK_SIGN_PUBLIC_KEY);
    uint8_t tag;
    const uint8_t *value;
    size_t length;

    if (!der_read(&cursor, end, &tag, &value, &length) || tag != 0x30) {
        return 0;
    }
    const uint8_t *sequence_end = value + length;
    /* 进入外层 SEQUENCE；der_read 已把 cursor 推到末尾。 */
    cursor = value;
    if (!der_read(&cursor, sequence_end, &tag, &value, &length) || tag != 0x30) {
        return 0;
    }
    if (!der_read(&cursor, sequence_end, &tag, &value, &length)
        || tag != 0x03 || length < 1 || value[0] != 0) {
        return 0;
    }
    const uint8_t *inner = value + 1;
    const uint8_t *inner_end = value + length;
    if (!der_read(&inner, inner_end, &tag, &value, &length) || tag != 0x30) {
        return 0;
    }
    const uint8_t *rsa_end = value + length;
    /* 进入 RSAPublicKey SEQUENCE。 */
    inner = value;
    if (!der_read(&inner, rsa_end, &tag, &value, &length) || tag != 0x02) {
        return 0;
    }
    const uint8_t *mod = value;
    size_t mod_length = length;
    while (mod_length > 0 && mod[0] == 0) {
        mod++;
        mod_length--;
    }
    if (!der_read(&inner, rsa_end, &tag, &value, &length) || tag != 0x02) {
        return 0;
    }
    if (length == 0 || length > 4) {
        return 0;
    }
    uint32_t exp = 0;
    for (size_t index = 0; index < length; index++) {
        exp = (exp << 8) | value[index];
    }
    if (mod_length != 256 || exp == 0) {
        return 0;
    }
    *modulus = mod;
    *modulus_length = mod_length;
    *exponent = exp;
    return 1;
}

static int rsa_verify_digest(const uint8_t *signature, size_t signature_length,
                             const uint8_t *digest_info, size_t digest_info_length,
                             const uint8_t *digest, size_t digest_length) {
    const uint8_t *modulus_bytes;
    size_t modulus_length;
    uint32_t exponent;
    if (!rsa_public_key(&modulus_bytes, &modulus_length, &exponent)) {
        return 0;
    }
    if (signature_length != modulus_length) {
        return 0;
    }
    BigNum modulus;
    BigNum signature_value;
    BigNum message;
    bn_from_bytes(&modulus, modulus_bytes, modulus_length);
    bn_from_bytes(&signature_value, signature, signature_length);
    if (bn_compare(&signature_value, &modulus) >= 0) {
        return 0;
    }
    bn_mod_power(&signature_value, exponent, &modulus, &message);

    uint8_t encoded[256];
    bn_to_bytes(&message, encoded, modulus_length);
    size_t position = 0;
    if (encoded[position++] != 0x00 || encoded[position++] != 0x01) {
        return 0;
    }
    while (position < modulus_length && encoded[position] == 0xff) {
        position++;
    }
    if (position >= modulus_length || encoded[position] != 0x00) {
        return 0;
    }
    position++;
    if (position + digest_info_length + digest_length > modulus_length) {
        return 0;
    }
    if (memcmp(encoded + position, digest_info, digest_info_length) != 0) {
        return 0;
    }
    return memcmp(encoded + position + digest_info_length,
                  digest, digest_length) == 0;
}

static int rsa_verify_sha1(const uint8_t *data, size_t data_length,
                           const uint8_t *signature, size_t signature_length) {
    static const uint8_t DIGEST_INFO[15] = {
            0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
            0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
    };
    uint8_t digest[20];
    Sha1 context;
    sha1_init(&context);
    sha1_update(&context, data, data_length);
    sha1_final(&context, digest);
    return rsa_verify_digest(signature, signature_length,
                             DIGEST_INFO, sizeof(DIGEST_INFO), digest, sizeof(digest));
}

jboolean wxh_native_verify_pack(JNIEnv *env, jclass type,
                                jbyteArray data, jbyteArray signature) {
    (void) type;
    if (data == NULL || signature == NULL) {
        return JNI_FALSE;
    }
    jsize data_length = (*env)->GetArrayLength(env, data);
    jsize signature_length = (*env)->GetArrayLength(env, signature);
    if (data_length <= 0 || signature_length != 256) {
        return JNI_FALSE;
    }
    uint8_t *data_bytes = (uint8_t *) malloc((size_t) data_length);
    uint8_t *signature_bytes = (uint8_t *) malloc((size_t) signature_length);
    if (data_bytes == NULL || signature_bytes == NULL) {
        free(data_bytes);
        free(signature_bytes);
        return JNI_FALSE;
    }
    (*env)->GetByteArrayRegion(env, data, 0, data_length, (jbyte *) data_bytes);
    (*env)->GetByteArrayRegion(env, signature, 0, signature_length,
                               (jbyte *) signature_bytes);
    int verified = rsa_verify_sha1(data_bytes, (size_t) data_length,
                                   signature_bytes, (size_t) signature_length);
    free(data_bytes);
    free(signature_bytes);
    return verified ? JNI_TRUE : JNI_FALSE;
}
