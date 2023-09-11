/* -------------------------------------------------------------------------
 *  This file is part of the Cantian project.
 * Copyright (c) 2023 Huawei Technologies Co.,Ltd.
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
 * cm_partkey.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_partkey.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef _CM_PART_H_
#define _CM_PART_H_

#include "cm_defs.h"
#include "cm_text.h"
#include "cm_binary.h"
#include "cm_decimal.h"
#include "cm_date.h"
#include "cm_memory.h"
#include "cm_base.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
* @addtogroup partition
* @brief Support partition key managment.
* @{ */
#pragma pack(4)
/** partition key structure */
typedef struct st_part_key {
    uint16 size;
    uint16 column_count;
    uint8 bitmap[4];
} part_key_t;
#pragma pack()

typedef struct st_part_decode_key {
    uint16 count;
    uint16 *offsets;
    uint16 *lens;
    char *buf;
} part_decode_key_t;

#define PART_BITMAP_EX_SIZE(cols) (((cols) <= 8) ? 0 : (CM_ALIGN16((cols) - 8) / 2))

#define PART_KEY_BITS_NULL    (uint8)0x00
#define PART_KEY_BITS_4       (uint8)0x01
#define PART_KEY_BITS_8       (uint8)0x02
#define PART_KEY_BITS_VAR     (uint8)0x03
#define PART_KEY_BITS_MIN     (uint8)0x04
#define PART_KEY_BITS_MAX     (uint8)0x05
#define PART_KEY_BITS_DEFAULT (uint8)0x06
#define PART_KEY_BITS_UNKNOWN (uint8)0x07

#define PART_KEY_BITS_4_LEN  (uint16)0x04
#define PART_KEY_BITS_8_LEN  (uint16)0x08
#define PART_KEY_MIN_LEN     (uint16)0x0000
#define PART_KEY_UNKNOWN_LEN (uint16)0x2000
#define PART_KEY_DEFAULT_LEN (uint16)0x4000
#define PART_KEY_NULL_LEN    (uint16)0x8000
#define PART_KEY_MAX_LEN     (uint16)0xFFFF

#define PART_VALUE_MAX      "MAXVALUE"
#define PART_VALUE_DEFAULT  "DEFAULT"
#define PART_MAX_LIST_COUNT 500

#define CM_CHECK_KEY_FREE(part_key, len)                          \
    {                                                             \
        if ((part_key)->size + (len) > GS_MAX_COLUMN_SIZE) {      \
            GS_THROW_ERROR(ERR_MAX_PART_KEY, GS_MAX_COLUMN_SIZE); \
            return GS_ERROR;                                      \
        }                                                         \
    }

/** see comments in cm_row.h */
static inline void part_key_init(part_key_t *part_key, uint32 column_count)
{
    uint32 ex_maps;

    ex_maps = PART_BITMAP_EX_SIZE(column_count);
    part_key->size = (uint16)sizeof(part_key_t) + ex_maps;
    part_key->column_count = 0;
}

/**
 * col >> 1: one bitmap can fill two partkey column
 * col & 0x01: col logical position in bitmap
 *  (col & 0x01) << 2: col physical position in bitmap
 */
static inline void part_set_key_bits(part_key_t *part_key, uint8 bits)
{
    uint32 map_id = part_key->column_count >> 1;

    // erase bits
    part_key->bitmap[map_id] &= ~(0x0F << ((part_key->column_count & 0x01) << 2));

    // set bits
    part_key->bitmap[map_id] |= bits << (((uint8)(part_key->column_count & 0x01) << 2));
}

static inline uint8 part_get_key_bits(part_key_t *part_key, uint32 id)
{
    uint32 map_id = id >> 1;

    return (uint8)(part_key->bitmap[map_id] >> ((id & 0x01) << 2)) & (uint8)0x0F;
}

static inline void part_put_null(part_key_t *part_key)
{
    CM_POINTER(part_key);
    part_set_key_bits(part_key, PART_KEY_BITS_NULL);
    part_key->column_count++;
}

static inline void part_put_min(part_key_t *part_key)
{
    CM_POINTER(part_key);
    part_set_key_bits(part_key, PART_KEY_BITS_MIN);
    part_key->column_count++;
}

static inline void part_put_max(part_key_t *part_key)
{
    CM_POINTER(part_key);
    part_set_key_bits(part_key, PART_KEY_BITS_MAX);
    part_key->column_count++;
}

static inline void part_put_default(part_key_t *part_key)
{
    CM_POINTER(part_key);
    part_set_key_bits(part_key, PART_KEY_BITS_DEFAULT);
    part_key->column_count++;
}

static inline void part_put_unknown(part_key_t *part_key)
{
    CM_POINTER(part_key);
    part_set_key_bits(part_key, PART_KEY_BITS_UNKNOWN);
    part_key->column_count++;
}

static inline status_t part_put_int32(part_key_t *part_key, int32 val)
{
    CM_POINTER(part_key);
    CM_CHECK_KEY_FREE(part_key, sizeof(int32));

    *(int32 *)((char *)part_key + part_key->size) = val;
    part_key->size += (uint16)sizeof(int32);

    part_set_key_bits(part_key, PART_KEY_BITS_4);
    part_key->column_count++;

    return GS_SUCCESS;
}

static inline status_t part_put_uint32(part_key_t *part_key, uint32 val)
{
    return part_put_int32(part_key, (int32)val);
}

static inline status_t part_put_int64(part_key_t *part_key, int64 val)
{
    CM_POINTER(part_key);
    CM_CHECK_KEY_FREE(part_key, sizeof(int64));

    *(int64 *)((char *)part_key + part_key->size) = val;
    part_key->size += (uint16)sizeof(int64);

    part_set_key_bits(part_key, PART_KEY_BITS_8);
    part_key->column_count++;

    return GS_SUCCESS;
}

static inline status_t part_put_uint64(part_key_t *part_key, uint64 val)
{
    return part_put_int64(part_key, (int64)val);
}

static inline status_t part_put_real(part_key_t *part_key, double val)
{
    CM_POINTER(part_key);
    CM_CHECK_KEY_FREE(part_key, sizeof(double));

    *(double *)((char *)part_key + part_key->size) = val;
    part_key->size += (uint16)sizeof(double);

    part_set_key_bits(part_key, PART_KEY_BITS_8);
    part_key->column_count++;

    return GS_SUCCESS;
}

static inline status_t part_put_text(part_key_t *part_key, text_t *text)
{
    uint32 actual_size;

    CM_POINTER2(part_key, text);

    if (text->str == NULL) {
        part_put_null(part_key);
        return GS_SUCCESS;
    }

    actual_size = text->len + sizeof(uint16);
    actual_size = CM_ALIGN4(actual_size);
    CM_CHECK_KEY_FREE(part_key, actual_size);

    char *addr = (char *)part_key + part_key->size;
    *(uint16 *)addr = (uint16)text->len;

    addr += sizeof(uint16);
    if (text->len != 0) {
        MEMS_RETURN_IFERR(
            memcpy_sp(addr, (size_t)((char *)part_key + GS_MAX_COLUMN_SIZE - addr), text->str, text->len));
    }
    part_key->size += (uint16)actual_size;

    part_set_key_bits(part_key, PART_KEY_BITS_VAR);
    part_key->column_count++;

    return GS_SUCCESS;
}

static inline status_t part_put_str(part_key_t *part_key, char *str, uint32 str_len)
{
    text_t text;
    cm_str2text_safe(str, str_len, &text);
    return part_put_text(part_key, &text);
}

static inline status_t part_put_bin(part_key_t *part_key, binary_t *bin)
{
    uint32 actual_size;
    CM_POINTER2(part_key, bin);

    if (bin->bytes == NULL) {
        part_put_null(part_key);
        return GS_SUCCESS;
    }

    actual_size = bin->size + sizeof(uint16);
    actual_size = CM_ALIGN4(actual_size);
    CM_CHECK_KEY_FREE(part_key, actual_size);

    char *addr = (char *)part_key + part_key->size;
    *(uint16 *)addr = (uint16)bin->size;
    addr += sizeof(uint16);
    if (bin->size != 0) {
        MEMS_RETURN_IFERR(
            memcpy_sp(addr, (size_t)((char *)part_key + GS_MAX_COLUMN_SIZE - addr), bin->bytes, bin->size));
    }
    part_key->size += (uint16)actual_size;

    part_set_key_bits(part_key, PART_KEY_BITS_VAR);
    part_key->column_count++;

    return GS_SUCCESS;
}

#define part_put_date          part_put_int64
#define part_put_timestamp     part_put_int64
#define part_put_timestamp_ltz part_put_int64
#define part_put_dsinterval    part_put_int64
#define part_put_yminterval    part_put_int32

static inline status_t part_put_timestamptz(part_key_t *part_key, timestamp_tz_t *tstz)
{
    binary_t bin;
    CM_POINTER2(part_key, tstz);
    bin.bytes = (uint8 *)tstz;
    bin.size = sizeof(timestamp_tz_t);
    return part_put_bin(part_key, &bin);
}

static inline status_t part_put_dec4_core(part_key_t *part_key, dec4_t *dval)
{
    uint8  part_key_bits;
    uint32 actual_size;
    dec4_t* d4 = NULL;
    uint32 original_size = cm_dec4_stor_sz(dval);
    char *addr = (char *)part_key + part_key->size;

    if (original_size <= PART_KEY_BITS_8_LEN) {
        d4 = (dec4_t *)addr;
        if (original_size <= PART_KEY_BITS_4_LEN) {
            actual_size = sizeof(int32);
            part_key_bits = PART_KEY_BITS_4;
        } else {
            actual_size = sizeof(int64);
            part_key_bits = PART_KEY_BITS_8;
        }
    } else {
        *(uint16 *)addr = (uint16)original_size;
        d4 = (dec4_t *)(addr + sizeof(uint16));
        original_size += sizeof(uint16);
        actual_size = CM_ALIGN4(original_size);
        part_key_bits = PART_KEY_BITS_VAR;
    }

    CM_CHECK_KEY_FREE(part_key, actual_size);
    part_key->size += (uint16)actual_size;
    part_set_key_bits(part_key, part_key_bits);
    part_key->column_count++;

    /* dec4 is Four-byte alignment, if the original size is not multiplier of 4, it is need to fill 0.
     * apply  & (4 - 1) is order to raise efficiency
     */
    if (original_size & (DEC4_CELL_DIGIT - 1)) {
        d4->cells[dval->ncells] = 0;
    }
    cm_dec4_copy(d4, dval);

    return GS_SUCCESS;
}

static inline status_t part_put_dec4(part_key_t *part_key, dec8_t *d8)
{
    dec4_t d4;
    GS_RETURN_IFERR(cm_dec_8_to_4(&d4, d8));
    return part_put_dec4_core(part_key, &d4);
}

static status_t part_put_dec2_core(part_key_t *part_key, dec2_t *dval)
{
    uint8  part_key_bits;
    uint32 actual_size;
    payload_t* d2 = NULL;
    uint32 original_size = cm_dec2_stor_sz(dval);
    char *addr = (char *)part_key + part_key->size;
    
    actual_size = CM_ALIGN4(original_size + sizeof(uint16));
    *(uint16 *)addr = original_size;
    d2 = (payload_t *)(addr + sizeof(uint16));
    part_key_bits = PART_KEY_BITS_VAR;

    CM_CHECK_KEY_FREE(part_key, actual_size);
    part_key->size += (uint8)actual_size;
    part_set_key_bits(part_key, part_key_bits);
    part_key->column_count++;

    /* dec2 is two-byte alignment, if the original size is not multiplier of 2, it is need to fill 0.
     * apply  & (2 - 1) is order to raise efficiency
     */
    for (uint32 i = 0; i < actual_size - original_size; i++) {
        d2->cells[GET_CELLS_SIZE(dval) + i] = 0;
    }
    cm_dec2_copy_payload(d2, (const payload_t *)GET_PAYLOAD(dval), dval->len);
    return GS_SUCCESS;
}

static inline status_t part_put_dec2(part_key_t *part_key, dec8_t *d8)
{
    dec2_t dval;
    GS_RETURN_IFERR(cm_dec_8_to_2(&dval, d8));
    return part_put_dec2_core(part_key, &dval);
}

static inline status_t part_put_data(part_key_t *part_key, void *data, uint32 len, gs_type_t type)
{
    char *addr = NULL;
    uint32 actual_size;

    CM_POINTER2(part_key, data);

    switch (type) {
        case GS_TYPE_UINT32:
        case GS_TYPE_INTEGER:
        case GS_TYPE_INTERVAL_YM:
            actual_size = (uint16)sizeof(int32);
            addr = (char *)part_key + part_key->size;
            *(int32 *)addr = *(int32 *)data;
            part_set_key_bits(part_key, PART_KEY_BITS_4);
            break;

        case GS_TYPE_BIGINT:
        case GS_TYPE_REAL:
        case GS_TYPE_DATE:
        case GS_TYPE_TIMESTAMP:
        case GS_TYPE_TIMESTAMP_TZ_FAKE:
        case GS_TYPE_TIMESTAMP_LTZ:
        case GS_TYPE_INTERVAL_DS:
            actual_size = (uint16)sizeof(int64);
            addr = (char *)part_key + part_key->size;
            *(int64 *)addr = *(int64 *)data;
            part_set_key_bits(part_key, PART_KEY_BITS_8);
            break;
        
        case GS_TYPE_TIMESTAMP_TZ:
            actual_size = (uint16)sizeof(timestamp_tz_t);
            addr = (char *)part_key + part_key->size;
            *(timestamp_tz_t*)addr = *(timestamp_tz_t *)data;
            part_set_key_bits(part_key, PART_KEY_BITS_VAR);
            break;

        case GS_TYPE_CHAR:
        case GS_TYPE_VARCHAR:
        case GS_TYPE_STRING:
        case GS_TYPE_BINARY:
        case GS_TYPE_RAW:
        case GS_TYPE_NUMBER2:
            actual_size = len + sizeof(uint16);
            actual_size = CM_ALIGN4(actual_size);
            CM_CHECK_KEY_FREE(part_key, actual_size);

            addr = (char *)part_key + part_key->size;
            *(uint16 *)addr = (uint16)len;
            addr += sizeof(uint16);
            if (len != 0) {
                MEMS_RETURN_IFERR(memcpy_sp(addr, (size_t)((char *)part_key + GS_MAX_COLUMN_SIZE - addr), data, len));
            }
            part_set_key_bits(part_key, PART_KEY_BITS_VAR);
            break;
        case GS_TYPE_NUMBER:
        case GS_TYPE_NUMBER3:
        case GS_TYPE_DECIMAL:
            addr = (char *)part_key + part_key->size;
            if (len <= PART_KEY_BITS_4_LEN) {
                actual_size = 4;
                CM_CHECK_KEY_FREE(part_key, actual_size);
                part_set_key_bits(part_key, PART_KEY_BITS_4);
            } else if (len <= PART_KEY_BITS_8_LEN) {
                actual_size = 8;
                CM_CHECK_KEY_FREE(part_key, actual_size);
                part_set_key_bits(part_key, PART_KEY_BITS_8);
            } else {
                actual_size = len + sizeof(uint16);
                actual_size = CM_ALIGN4(actual_size);
                CM_CHECK_KEY_FREE(part_key, actual_size);
                *(uint16 *)addr = (uint16)len;
                addr += sizeof(uint16);

                uint32 zero_count = actual_size - sizeof(uint16) - len;
                if (zero_count > 0) {
                    MEMS_RETURN_IFERR(memset_s(addr + len, zero_count, 0, zero_count));
                }
                part_set_key_bits(part_key, PART_KEY_BITS_VAR);
            }

            if (len != 0) {
                MEMS_RETURN_IFERR(memcpy_sp(addr, GS_MAX_COLUMN_SIZE - part_key->size, data, len));
            }
            break;

        default:
            GS_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "invalid partition key type");
            return GS_ERROR;
    }

    part_key->size += (uint16)actual_size;
    part_key->column_count++;

    return GS_SUCCESS;
}

static inline void part_decode_key(part_key_t *part_key, part_decode_key_t *decoder)
{
    uint8 bits;
    uint16 i, pos, ex_maps;

    CM_POINTER2(part_key, decoder);
    CM_ASSERT(part_key->column_count < GS_MAX_COLUMNS);

    decoder->count = part_key->column_count;
    decoder->buf = (char *)part_key;

    ex_maps = PART_BITMAP_EX_SIZE(part_key->column_count);
    pos = sizeof(part_key_t) + ex_maps;

    for (i = 0; i < part_key->column_count; i++) {
        bits = part_get_key_bits(part_key, i);
        decoder->offsets[i] = pos;

        if (bits == PART_KEY_BITS_8) {
            decoder->lens[i] = 8;
            pos += 8;
        } else if (bits == PART_KEY_BITS_4) {
            decoder->lens[i] = 4;
            pos += 4;
        } else if (bits == PART_KEY_BITS_NULL) {
            decoder->lens[i] = PART_KEY_NULL_LEN;
        } else if (bits == PART_KEY_BITS_DEFAULT) {
            decoder->lens[i] = PART_KEY_DEFAULT_LEN;
        } else if (bits == PART_KEY_BITS_UNKNOWN) {
            decoder->lens[i] = PART_KEY_UNKNOWN_LEN;
        } else if (bits == PART_KEY_BITS_MIN) {
            decoder->lens[i] = PART_KEY_MIN_LEN;
        } else if (bits == PART_KEY_BITS_MAX) {
            decoder->lens[i] = PART_KEY_MAX_LEN;
        } else {
            decoder->lens[i] = *(uint16 *)((char *)part_key + pos);
            decoder->offsets[i] += sizeof(uint16);
            pos += CM_ALIGN4(decoder->lens[i] + sizeof(uint16));
        }
    }
}

#define NUMBER_ZERO_STORAGR_LEN 2
static inline void part_get_number_zero(gs_type_t type, char* data, int max_len, uint32* len)
{
    CM_ASSERT(max_len >= NUMBER_ZERO_STORAGR_LEN);
    if (type == GS_TYPE_NUMBER2) {
        *data = ZERO_EXPN;
        *len = sizeof(c2typ_t);
    } else if (type == GS_TYPE_NUMBER || type == GS_TYPE_DECIMAL) {
        ((dec4_t*)data)->head = 0;
        *len = sizeof(c4typ_t);
    }
}

/** @}**/
#ifdef __cplusplus
}
#endif

#endif
