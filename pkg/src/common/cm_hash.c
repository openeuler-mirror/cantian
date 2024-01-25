/* -------------------------------------------------------------------------
 *  This file is part of the Cantian project.
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
 *
 * Cantian is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *          http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 * -------------------------------------------------------------------------
 *
 * cm_hash.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_hash.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_hash.h"
#include <math.h>

#define CM_HASH_INIT(key, len) (0x9E735650 + (len))

#define HASH_BYTE_BATCH 12
#define HASH_DIM_BATCH  3
#define HASH_WORD_SIZE  4

typedef union {
    uint8 bytes[4]; /* used for handling different endian */
    uint32 value;
} endian_t;

typedef union {
    uint8 bytes[HASH_BYTE_BATCH];
    uint32 dim[HASH_DIM_BATCH];
    endian_t e[HASH_DIM_BATCH];
} hash_helper_t;

#define HASH_RESULT(hs) ((hs)->e[2].value)

/** package a word with big endian mode */
static inline void cm_pack_big_endian(const uint8 key[HASH_WORD_SIZE], endian_t *e)
{
    e->bytes[0] = key[3];
    e->bytes[1] = key[2];
    e->bytes[2] = key[1];
    e->bytes[3] = key[0];
}

/** package a word with little endian mode */
static inline void cm_pack_little_endian(const uint8 key[HASH_WORD_SIZE], endian_t *e)
{
    e->bytes[0] = key[0];
    e->bytes[1] = key[1];
    e->bytes[2] = key[2];
    e->bytes[3] = key[3];
}

static uint32 cm_hash_big_endian(const uint8 *bytes, uint32 length, uint32 range)
{
    uint32 value = HASH_SEED;
    uint32 size = length;
    char seed[4];
    uint8 *ptr = (uint8 *)bytes;
    if (size == 0) {
        return 0;
    }

    while (size >= 4) {
        seed[0] = (char)ptr[0];
        seed[1] = (char)ptr[1];
        seed[2] = (char)ptr[2];
        seed[3] = (char)ptr[3];

        value *= HASH_PRIME;
        value ^= *(uint32 *)seed;

        ptr += 4;
        size -= 4;
    }

    if (size == 0) {
        return (range == INFINITE_HASH_RANGE) ? value : (value % range);
    }

    *(uint32 *)seed = 0;
    if (size == 1) {
        seed[0] = (char)ptr[0];
    } else if (size == 2) {
        seed[0] = (char)ptr[0];
        seed[1] = (char)ptr[1];
    } else if (size == 3) {
        seed[0] = (char)ptr[0];
        seed[1] = (char)ptr[1];
        seed[2] = (char)ptr[2];
    }

    value *= HASH_PRIME;
    value ^= *(uint32 *)seed;
    return (range == INFINITE_HASH_RANGE) ? value : (value % range);
}

static uint32 cm_hash_little_endian(const uint8 *bytes, uint32 length, uint32 range)
{
    uint32 value = HASH_SEED;
    uint32 size = length;
    char seed[4];
    uint8 *ptr;

    ptr = (uint8 *)bytes;
    if (size == 0) {
        return 0;
    }

    while (size >= 4) {
        seed[0] = (char)ptr[3];
        seed[1] = (char)ptr[2];
        seed[2] = (char)ptr[1];
        seed[3] = (char)ptr[0];

        value *= HASH_PRIME;
        value ^= *(uint32 *)seed;

        ptr += 4;
        size -= 4;
    }

    if (size == 0) {
        return (range == INFINITE_HASH_RANGE) ? value : (value % range);
    }

    *(uint32 *)seed = 0;
    if (size == 1) {
        seed[3] = (char)ptr[0];
    } else if (size == 2) {
        seed[3] = (char)ptr[0];
        seed[2] = (char)ptr[1];
    } else if (size == 3) {
        seed[3] = (char)ptr[0];
        seed[2] = (char)ptr[1];
        seed[1] = (char)ptr[2];
    }

    value *= HASH_PRIME;
    value ^= *(uint32 *)seed;
    return (range == INFINITE_HASH_RANGE) ? value : (value % range);
}

uint32 cm_hash_bytes(const uint8 *bytes, uint32 length, uint32 range)
{
    if (IS_BIG_ENDIAN) {
        return cm_hash_big_endian(bytes, length, range);
    } else {
        return cm_hash_little_endian(bytes, length, range);
    }
}

uint32 cm_hash_string(const char *str, uint32 range)
{
    return cm_hash_bytes((uint8 *)str, (uint32)strlen(str), range);
}

uint32 cm_hash_column_name(const char *str, uint32 length, uint32 range, bool32 insensitive_flag)
{
    if (insensitive_flag) {
        char column_name[CT_NAME_BUFFER_SIZE];
        text_t hash_text;
        cm_str2text((char *)str, &hash_text);
        cm_text2str_with_upper(&hash_text, column_name, CT_NAME_BUFFER_SIZE);
        return cm_hash_bytes((uint8 *)column_name, length, range);
    }
    return cm_hash_bytes((uint8 *)str, length, range);
}

uint32 cm_hash_text(const text_t *text, uint32 range)
{
    return cm_hash_bytes((uint8 *)text->str, (uint32)text->len, range);
}

uint32 cm_hash_multi_text(const text_t *text, uint32 count, uint32 range)
{
    uint32 i;
    uint32 value = 0;

    for (i = 0; i < count; i++) {
        if (i == 0) {
            value = cm_hash_bytes((uint8 *)text[i].str, (uint32)text[i].len, INFINITE_HASH_RANGE);
        } else {
            value = (value << 1) | ((value & 0x80000000) ? 1 : 0);
            value ^= cm_hash_bytes((uint8 *)text[i].str, (uint32)text[i].len, INFINITE_HASH_RANGE);
        }
    }

    return (range == INFINITE_HASH_RANGE) ? value : (value % range);
}

#define FORWARD_MAPPING(hs, i, j, k, n)                                                    \
    do {                                                                                   \
        (hs)->dim[i] = cm_crol((hs)->dim[k], ((n) + (k))) ^ ((hs)->dim[i] - (hs)->dim[k]); \
        (hs)->dim[k] += (hs)->dim[j];                                                      \
    } while (0)

static inline void cm_forward_transform(hash_helper_t *hs)
{
    FORWARD_MAPPING(hs, 0, 1, 2, 2);
    FORWARD_MAPPING(hs, 1, 2, 0, 6);
    FORWARD_MAPPING(hs, 2, 0, 1, 7);
    FORWARD_MAPPING(hs, 0, 1, 2, 14);
    FORWARD_MAPPING(hs, 1, 2, 0, 19);
    FORWARD_MAPPING(hs, 2, 0, 1, 3);
}

#define BACKWARD_MAPPING(hs, i, j, k, n) \
    (hs)->dim[i] = (((hs)->dim[i] ^ (hs)->dim[j]) - cm_crol((hs)->dim[j], ((n) + (k) - (j))))

static inline void cm_backward_transform(hash_helper_t *hs)
{
    BACKWARD_MAPPING(hs, 2, 1, 0, 15);
    BACKWARD_MAPPING(hs, 0, 2, 1, 12);
    BACKWARD_MAPPING(hs, 1, 0, 2, 23);
    BACKWARD_MAPPING(hs, 2, 1, 0, 17);
    BACKWARD_MAPPING(hs, 0, 2, 1, 5);
    BACKWARD_MAPPING(hs, 1, 0, 2, 12);
    BACKWARD_MAPPING(hs, 2, 1, 0, 25);
}

/* Hash a key whose length is less than HASH_WORD_SIZE with big endian */
static inline uint32 hash_semiword_big_endian(const uint8 *key, uint32 len)
{
    endian_t e = { .value = 0 };

    if (len == 1) {
        e.bytes[3] = key[0];
    } else if (len == 2) {
        e.bytes[2] = key[1];
        e.bytes[3] = key[0];
    } else {
        e.bytes[1] = key[2];
        e.bytes[2] = key[1];
        e.bytes[3] = key[0];
    }

    return e.value;
}

/* Hash a key whose length is less than HASH_WORD_SIZE with little endian */
static inline uint32 hash_semiword_little_endian(const uint8 *key, uint32 len)
{
    endian_t e = { .value = 0 };

    if (len == 1) {
        e.bytes[0] = key[0];
    } else if (len == 2) {
        e.bytes[0] = key[0];
        e.bytes[1] = key[1];
    } else {
        e.bytes[0] = key[0];
        e.bytes[1] = key[1];
        e.bytes[2] = key[2];
    }

    return e.value;
}

static inline uint32 cm_hash_aligned_raw(const uint8 *key, uint32 len, hash_helper_t *hs)
{
    const endian_t *e = NULL;
    uint32 len_tmp = len;
    /* assembly hash value by batch */
    while (len_tmp >= HASH_BYTE_BATCH) {
        e = (const endian_t *)key;
        hs->dim[0] += e[0].value;
        hs->dim[1] += e[1].value;
        hs->dim[2] += e[2].value;
        cm_forward_transform(hs);

        key += HASH_BYTE_BATCH;
        len_tmp -= HASH_BYTE_BATCH;
    }

    /* assembly the left word */
    uint32 i = 0;
    while (len_tmp >= HASH_WORD_SIZE) {
        e = (const endian_t *)key;
        hs->dim[i] += e->value;
        key += HASH_WORD_SIZE;
        len_tmp -= HASH_WORD_SIZE;
        i++;
    }

    /* assembly the left bytes */
    if (len_tmp != 0) {
        uint32 eval = IS_BIG_ENDIAN ? hash_semiword_big_endian(key, len_tmp)
                                    : hash_semiword_little_endian(key, len_tmp);
        if (i >= (HASH_DIM_BATCH - 1)) {
            eval <<= 8;
        }
        hs->dim[i] += eval;
    }

    cm_backward_transform(hs);
    return HASH_RESULT(hs);
}

static inline void hash_noaligned_big_endian(const uint8 *key, uint32 len, hash_helper_t *hs)
{
    endian_t e;
    uint32 len_tmp = len;
    /* assembly hash value by batch */
    while (len_tmp >= HASH_BYTE_BATCH) {
        cm_pack_big_endian(key, &e);
        hs->dim[0] += e.value;
        key += HASH_WORD_SIZE;

        cm_pack_big_endian(key, &e);
        hs->dim[1] += e.value;
        key += HASH_WORD_SIZE;

        cm_pack_big_endian(key, &e);
        hs->dim[2] += e.value;
        key += HASH_WORD_SIZE;

        cm_forward_transform(hs);
        len_tmp -= HASH_BYTE_BATCH;
    }

    uint32 i = 0;
    while (len_tmp >= HASH_WORD_SIZE) {
        cm_pack_big_endian(key, &e);
        hs->dim[i] += e.value;
        key += HASH_WORD_SIZE;
        len_tmp -= HASH_WORD_SIZE;
        i++;
    }

    CT_RETVOID_IFTRUE(len_tmp == 0);

    e.value = hash_semiword_big_endian(key, len_tmp);
    if (i >= (HASH_DIM_BATCH - 1)) {
        e.value <<= 8;
    }

    hs->dim[i] += e.value;
}

static inline void hash_noaligned_little_endian(const uint8 *key, uint32 len, hash_helper_t *hs)
{
    endian_t e;
    uint32 len_tmp = len;
    /* assembly hash value by batch */
    while (len_tmp >= HASH_BYTE_BATCH) {
        cm_pack_little_endian(key, &e);
        hs->dim[0] += e.value;
        key += 4;

        cm_pack_little_endian(key, &e);
        hs->dim[1] += e.value;
        key += 4;

        cm_pack_little_endian(key, &e);
        hs->dim[2] += e.value;
        key += 4;

        cm_forward_transform(hs);
        len_tmp -= HASH_BYTE_BATCH;
    }

    uint32 i = 0;
    while (len_tmp >= HASH_WORD_SIZE) {
        cm_pack_little_endian(key, &e);
        hs->dim[i] += e.value;
        key += HASH_WORD_SIZE;
        len_tmp -= HASH_WORD_SIZE;
        i++;
    }

    CT_RETVOID_IFTRUE(len_tmp == 0);

    e.value = hash_semiword_little_endian(key, len_tmp);

    if (i >= (HASH_DIM_BATCH - 1)) {
        e.value <<= 8;
    }

    hs->dim[i] += e.value;
}

static inline uint32 cm_hash_noaligned_raw(const uint8 *key, uint32 len, hash_helper_t *hs)
{
    if (IS_BIG_ENDIAN) {
        hash_noaligned_big_endian(key, len, hs);
    } else {
        hash_noaligned_little_endian(key, len, hs);
    }

    cm_backward_transform(hs);

    return HASH_RESULT(hs);
}

#define CM_IS_ALIGNED_KEY(key) (((uint64)(key) % 4) > 0)

static inline void cm_init_hash_helper(const uint8 *key, uint32 len, hash_helper_t *hs)
{
    uint32 init_val = CM_HASH_INIT(key, len);
    hs->dim[0] = init_val;
    hs->dim[1] = init_val;
    hs->dim[2] = init_val;
}

uint32 cm_hash_raw(const uint8 *key, uint32 len)
{
    hash_helper_t hs;

    cm_init_hash_helper(key, len, &hs);

    if (CM_IS_ALIGNED_KEY(key)) {
        return cm_hash_noaligned_raw(key, len, &hs);
    } else {
        return cm_hash_aligned_raw(key, len, &hs);
    }
}

uint32 cm_hash_uint32_shard(uint32 val)
{
    hash_helper_t hs;

    cm_init_hash_helper((uint8 *)&val, sizeof(uint32), &hs);

    hs.dim[0] += val;
    cm_backward_transform(&hs);

    return HASH_RESULT(&hs);
}

uint32 cm_hash_int64(int64 i64)
{
    uint32 u32l = (uint32)i64;
    uint32 u32h = (uint32)(i64 >> 32);

    u32l ^= (i64 >= 0) ? u32h : ~u32h;

    return cm_hash_uint32_shard(u32l);
}

uint32 cm_hash_uint64(uint64 i64)
{
    uint32 u32l = (uint32)i64;
    uint32 u32h = (uint32)(i64 >> 32);

    u32l ^= (i64 >= 0) ? u32h : ~u32h;

    return cm_hash_uint32_shard(u32l);
}

uint32 cm_hash_real(double val)
{
    if (fabs(val) < CT_REAL_PRECISION) {
        return 0;
    }

    return cm_hash_raw((unsigned char *)&val, sizeof(val));
}

uint32 cm_hash_timestamp(uint64 val)
{
    return cm_hash_int64((int64)val);
}

/* get the min prime number greater than specify value */
uint32 cm_get_prime_number(const uint32 base)
{
    uint32 prime_number = 0;
    uint32 i, limit, sqrt_val;

    if (base <= 11) {
        return 11;
    }

    limit = base;
    if (base % 2 == 0) {
        limit++;
    }

    for (prime_number = limit; 1; prime_number += 2) {
        sqrt_val = (uint32)(int32)sqrtf((float)prime_number);
        for (i = 3; i <= sqrt_val; i += 2) {
            if ((prime_number % i == 0)) {
                break; /* prime_number is not prime number */
            }
        }

        if (i > sqrt_val) {
            break; /* prime_number is prime number */
        }
    }

    return prime_number;
}

static uint32 compute_hash_basic(const variant_t *value, bool32 *is_type_ok)
{
    *is_type_ok = CT_TRUE;
    switch (value->type) {
        case CT_TYPE_UINT32:
        case CT_TYPE_INTEGER:
            return (uint32)(value->v_int);
        case CT_TYPE_UINT64:
            return (uint32)(value->v_ubigint);
        case CT_TYPE_BIGINT:
            return (uint32)(value->v_bigint);
            /*
            * number/decimal value hash will reach here.
            * 1. before calculate number/decimal value hash,
            *    we have already converted number/decimal to real for special precision and scale
            * 2. we have forbidden real as distribute datatype in create table
            * @see shd_adjust_and_convert
            */
        case CT_TYPE_REAL:
            return (uint32)(int32)(value->v_real);
        case CT_TYPE_DATE:
        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_DATETIME_MYSQL:
        case CT_TYPE_TIME_MYSQL:
        case CT_TYPE_DATE_MYSQL:
        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
        case CT_TYPE_STRING:
        default:
            *is_type_ok = CT_FALSE;
            return 0;
    }
}

uint32 hash_basic_value_combination(uint32 idx, unsigned int hashValue_input, const variant_t *value,
    bool32 *is_type_ok)
{
    unsigned int hashValue = hashValue_input;
    if (value->is_null) {
        *is_type_ok = CT_TRUE;
        return hashValue;
    }

    if (idx != 0) {
        hashValue += compute_hash_basic(value, is_type_ok);
    } else {
        hashValue = compute_hash_basic(value, is_type_ok);
    }

    return hashValue;
}
