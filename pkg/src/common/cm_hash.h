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
 * cm_hash.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_hash.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_HASH_H__
#define __CM_HASH_H__

#include "cm_defs.h"
#include "cm_text.h"
#include "var_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef union {
    uint64 u64;
    struct {
        uint32 u32p0;
        uint32 u32p1;
    };
} u64shape_t;

/** left rotate u32 by n bits */
static inline uint32 cm_crol(uint32 u32, uint32 n)
{
#ifdef WIN32
    u64shape_t shape;
    shape.u64 = ((uint64)u32) << n;
    return shape.u32p0 | shape.u32p1;
#else
    /* In GCC or Linux, this following codes can be optimized by merely
    * one instruction, i.e.: rol  eax, cl */
    return (u32 >> (UINT32_BITS - n)) | (u32 << n);
#endif
}


#define INFINITE_HASH_RANGE (uint32)0
#define HASH_PRIME          (uint32)0x01000193
#define HASH_SEED           (uint32)0x811c9dc5

static inline uint32 cm_hash_uint32(uint32 i32_input, uint32 range)
{
    uint32 i32 = i32_input;
    i32 *= HASH_SEED;

    if (range > 0) {
        return i32 % range;
    }

    return i32;
}


uint32 cm_hash_bytes(const uint8 *bytes, uint32 length, uint32 range);
uint32 cm_hash_string(const char *str, uint32 range);
uint32 cm_hash_text(const text_t *text, uint32 range);
uint32 cm_hash_multi_text(const text_t *text, uint32 count, uint32 range);
uint32 cm_hash_raw(const uint8 *key, uint32 len);
uint32 cm_hash_column_name(const char *str, uint32 length, uint32 range, bool32 insensitive_flag);

uint32 cm_hash_uint32_shard(uint32 val);
uint32 cm_hash_uint64(uint64 i64);
uint32 cm_hash_int64(int64 i64);
uint32 cm_hash_real(double val);
uint32 cm_hash_timestamp(uint64 val);
uint32 cm_get_prime_number(const uint32 base);
uint32 hash_basic_value_combination(uint32 idx, unsigned int hashValue_input, const variant_t *value,
    bool32 *is_type_ok);
#define cm_hash_func  cm_hash_raw

#define HASH_BUCKET_INSERT(bucket, item)     \
    do {                                     \
        (item)->hash_next = (bucket)->first;     \
        (item)->hash_prev = NULL;              \
        if ((bucket)->first != NULL) {         \
            (bucket)->first->hash_prev = (item); \
        }                                    \
                                             \
        (bucket)->first = (item);                \
    } while (0)

#define HASH_BUCKET_REMOVE(bucket, item)                  \
    do {                                                  \
        if ((item)->hash_prev != NULL) {                    \
            (item)->hash_prev->hash_next = (item)->hash_next; \
        }                                                 \
                                                          \
        if ((item) != NULL && (item)->hash_next != NULL) {    \
            (item)->hash_next->hash_prev = (item)->hash_prev; \
        }                                                 \
                                                          \
        if ((item) == (bucket)->first) {                      \
            (bucket)->first = (item)->hash_next;              \
        }                                                 \
    } while (0)

#ifdef __cplusplus
}
#endif

#endif
