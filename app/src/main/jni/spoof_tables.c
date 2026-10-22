/*
 * 版本伪装细节表：URI 白名单、钱包判定、目标版本。
 * 表由 scripts/gen_spoof_tables.py 生成并 XOR 混淆。
 */
#include <jni.h>
#include <stdint.h>
#include <string.h>

#include "spoof_tables.inc"

static int spoof_decode(const SpoofEntry *entry, char *out, size_t capacity) {
    if (entry->length + 1 > capacity) {
        return 0;
    }
    for (size_t index = 0; index < entry->length; index++) {
        out[index] = (char) (entry->data[index]
                             ^ SPOOF_KEY[index & 15]
                             ^ (uint8_t) ((index * 77 + 13) & 0xff));
    }
    out[entry->length] = 0;
    return (int) entry->length;
}

static int contains_ci(const char *haystack, const char *needle) {
    if (haystack == NULL || needle == NULL || *needle == 0) {
        return 0;
    }
    size_t needle_length = strlen(needle);
    for (const char *cursor = haystack; *cursor != 0; cursor++) {
        size_t index = 0;
        for (; index < needle_length && cursor[index] != 0; index++) {
            char left = cursor[index];
            char right = needle[index];
            if (left >= 'A' && left <= 'Z') {
                left = (char) (left + 32);
            }
            if (right >= 'A' && right <= 'Z') {
                right = (char) (right + 32);
            }
            if (left != right) {
                break;
            }
        }
        if (index == needle_length) {
            return 1;
        }
    }
    return 0;
}

typedef struct {
    const SpoofEntry *table;
    size_t count;
} SpoofTable;

static SpoofTable spoof_table_for(jint kind) {
    SpoofTable result = {NULL, 0};
    switch (kind) {
        case 0:
            result.table = SPOOF_STARTUP_TABLE;
            result.count = SPOOF_STARTUP_COUNT;
            break;
        case 1:
            result.table = SPOOF_CALL_START_TABLE;
            result.count = SPOOF_CALL_START_COUNT;
            break;
        case 2:
            result.table = SPOOF_CALL_TABLE;
            result.count = SPOOF_CALL_COUNT;
            break;
        case 3:
            result.table = SPOOF_MINI_PROGRAM_TABLE;
            result.count = SPOOF_MINI_PROGRAM_COUNT;
            break;
        case 4:
            result.table = SPOOF_WALLET_URI_TABLE;
            result.count = SPOOF_WALLET_URI_COUNT;
            break;
        case 5:
            result.table = SPOOF_WALLET_CLASS_TABLE;
            result.count = SPOOF_WALLET_CLASS_COUNT;
            break;
        case 6:
            result.table = SPOOF_CALL_SHUTDOWN_TABLE;
            result.count = SPOOF_CALL_SHUTDOWN_COUNT;
            break;
        case 7:
            result.table = SPOOF_EXT_UNAVAILABLE_TABLE;
            result.count = SPOOF_EXT_UNAVAILABLE_COUNT;
            break;
        default:
            break;
    }
    return result;
}

jboolean wxh_native_hint_match(
        JNIEnv *env, jclass type, jint kind, jstring value) {
    (void) type;
    if (value == NULL) {
        return JNI_FALSE;
    }
    const char *text = (*env)->GetStringUTFChars(env, value, NULL);
    if (text == NULL) {
        return JNI_FALSE;
    }
    SpoofTable table = spoof_table_for(kind);
    jboolean matched = JNI_FALSE;
    char buffer[128];
    for (size_t index = 0; index < table.count && matched == JNI_FALSE; index++) {
        if (spoof_decode(&table.table[index], buffer, sizeof(buffer)) > 0
            && contains_ci(text, buffer)) {
            matched = JNI_TRUE;
        }
    }
    memset(buffer, 0, sizeof(buffer));
    (*env)->ReleaseStringUTFChars(env, value, text);
    return matched;
}

jint wxh_native_spoof_version(
        JNIEnv *env, jclass type, jint real_version) {
    (void) env;
    (void) type;
    uint32_t high = SPOOF_VERSION_HIGH_ENC ^ SPOOF_VERSION_MASK;
    return (jint) ((high & 0xFFFFFF00u) | ((uint32_t) real_version & 0xFFu));
}
