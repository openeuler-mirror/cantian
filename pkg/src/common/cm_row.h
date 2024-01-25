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
 * cm_row.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_row.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_ROW_H__
#define __CM_ROW_H__
#include "cm_base.h"
#include "cm_defs.h"
#include "cm_text.h"
#include "cm_binary.h"
#include "cm_decimal.h"
#include "cm_date.h"
#include "var_inc.h"
#include "cm_row_persist.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_row_assist {
    uint16 col_id;
    uint16 max_size;
    bool32 is_csf;
    row_head_t *head;
    char *buf;
} row_assist_t;

#define CSF_SHORT_COL_DESC_LEN     1
#define CSF_LONG_COL_DESC_LEN      3
#define BMP_VARLEN_COL_DESC_LEN    2

#define CM_CHECK_ROW_FREE(row, len)                                  \
    {                                                                \
        if ((row)->head->size + (len) > (row)->max_size) {           \
            CT_THROW_ERROR(ERR_ROW_SIZE_TOO_LARGE, (row)->max_size); \
            return CT_ERROR;                                         \
        }                                                            \
    }

#define IS_SPRS_ROW(row) (SECUREC_UNLIKELY((row)->column_count == 0))
typedef status_t(*cm_put_row_column_t)(row_head_t *src_row, uint16 *src_offsets, uint16 *src_lens,
    uint16 col_id, row_assist_t *dst_ra);

static inline uint16 row_bitmap_ex_size(row_head_t *row)
{
    if (IS_SPRS_ROW(row)) {
        CM_ASSERT(row->sprs_count >= CT_SPRS_COLUMNS);
        return (uint16)(CM_ALIGN16(row->sprs_count - 4) / 4);
    } else {
        return (uint16)((row->column_count <= 12) ? 0 : (CM_ALIGN16(row->column_count - 12) / 4));
    }
}

static inline uint16 col_bitmap_ex_size(uint16 cols)
{
    if (cols >= CT_SPRS_COLUMNS) {
        return (uint16)(CM_ALIGN16(cols - 4) / 4);
    } else {
        return (uint16)((cols <= 12) ? 0 : (CM_ALIGN16(cols - 12) / 4));
    }
}

static inline uint16 col_bitmap_size(uint16 cols)
{
    if (cols >= CT_SPRS_COLUMNS) {
        return (uint16)(CM_ALIGN16(cols - 4) / 4) + 1;
    } else {
        return (uint16)((cols <= 12) ? 0 : (CM_ALIGN16(cols - 12) / 4)) + 3;
    }
}

#define ROW_BITMAP_EX_SIZE(row)  row_bitmap_ex_size(row)
#define COL_BITMAP_EX_SIZE(cols) col_bitmap_ex_size(cols)
#define COL_BITMAP_SIZE(cols) col_bitmap_size(cols)

#define CSF_ROW_HEAD_SIZE(cols) csf_row_head_size(cols)

#define CM_CURR_ROW_PTR(ra)      ((ra)->buf + (ra)->head->size)

#define ROW_COLUMN_COUNT(row) (uint16)(IS_SPRS_ROW(row) ? (row)->sprs_count : (row)->column_count)
#define ROW_ITL_ID(row)       (uint8)(IS_SPRS_ROW(row) ? (row)->sprs_itl_id : (row)->itl_id)

#define ROW_SET_COLUMN_COUNT(row, count)   \
    do {                                   \
        if (IS_SPRS_ROW(row)) {            \
            (row)->sprs_count = (count);   \
        } else {                           \
            (row)->column_count = (count); \
        }                                  \
    } while (0)

#define ROW_SET_ITL_ID(row, id)        \
    do {                               \
        if (IS_SPRS_ROW(row)) {        \
            (row)->sprs_itl_id = (id); \
        } else {                       \
            (row)->itl_id = (id);      \
        }                              \
    } while (0)

/** compacting mask using in heap compact page */
#define ROW_COMPACTING_MASK 0x8000

static inline uint16 csf_row_head_size(uint32 column_count)
{
    if (column_count >= CT_SPRS_COLUMNS) {
        return (uint16)OFFSET_OF(row_head_t, sprs_bitmap);
    } else {
        return (uint16)OFFSET_OF(row_head_t, bitmap);
    }
}

/*
normal row: format of the map in the row
0         2          4          6          8(byte)
+---------+----------+----------+----------+
| mask i  | mask i+1 | mask i+2 | mask i+3 |

mask value:     0x00     0x01     0x02    0x03
data length:    null     4-byte   8-byte  var len

CSF row:
LEN(1 Byte) [LEN >=254(2 Bytes)]  DATA

SPRS row:
COLUMN_COUNT(0)   SPRS_COUNT(columns) SPRS_BITMAP
+---------+----------------------+----------...--+
*/
static inline void csf_row_init(row_assist_t *ra, char *buf, uint32 max_size, uint32 column_count)
{
    CM_ASSERT(column_count != 0);

    ra->buf = buf;
    ra->max_size = max_size;
    ra->col_id = 0;
    ra->is_csf = CT_TRUE;
    ra->head = (row_head_t *)buf;
    ra->head->flags = 0;
    ra->head->is_csf = 1;

    if (column_count >= CT_SPRS_COLUMNS) {
        ra->head->column_count = 0;
        ra->head->sprs_count = (uint16)column_count;
        ra->head->sprs_itl_id = CT_INVALID_ID8;
        ra->head->size = (uint16)OFFSET_OF(row_head_t, sprs_bitmap);
    } else {
        ra->head->column_count = (uint16)column_count;
        ra->head->itl_id = CT_INVALID_ID8;
        ra->head->size = (uint16)OFFSET_OF(row_head_t, bitmap);
    }
}

#define CSF_NULL_FLAG (uint8)0xFF
#define CSF_VARLEN_EX (uint8)0xFE
#define CSF_ZERO_FLAG (uint8)0

static inline void csf_put_column_len(row_assist_t *ra, uint8 len)
{
    *(uint8 *)CM_CURR_ROW_PTR(ra) = len;
    ra->head->size++;
    ra->col_id++;
}

static inline status_t csf_put_null(row_assist_t *ra)
{
    CM_CHECK_ROW_FREE(ra, (uint16)1);
    csf_put_column_len(ra, CSF_NULL_FLAG);
    return CT_SUCCESS;
}

static inline status_t csf_put_zero(row_assist_t *ra)
{
    CM_CHECK_ROW_FREE(ra, (uint16)1);
    csf_put_column_len(ra, CSF_ZERO_FLAG);
    return CT_SUCCESS;
}

static inline status_t csf_put_int32(row_assist_t *ra, int32 val)
{
    CM_CHECK_ROW_FREE(ra, sizeof(int32) + 1);
    csf_put_column_len(ra, sizeof(int32));
    *(int32 *)CM_CURR_ROW_PTR(ra) = val;
    ra->head->size += sizeof(int32);
    return CT_SUCCESS;
}

static inline status_t csf_put_uint32(row_assist_t *ra, uint32 val)
{
    return csf_put_int32(ra, (int32)val);
}

static inline status_t csf_put_int64(row_assist_t *ra, int64 val)
{
    CM_CHECK_ROW_FREE(ra, sizeof(int64) + 1);
    csf_put_column_len(ra, sizeof(int64));
    *(int64 *)CM_CURR_ROW_PTR(ra) = val;
    ra->head->size += sizeof(int64);
    return CT_SUCCESS;
}

static inline status_t csf_put_real(row_assist_t *ra, double val)
{
    CM_CHECK_ROW_FREE(ra, sizeof(double) + 1);
    csf_put_column_len(ra, sizeof(double));
    *(double *)CM_CURR_ROW_PTR(ra) = val;
    ra->head->size += sizeof(double);
    return CT_SUCCESS;
}

static inline status_t csf_put_text(row_assist_t *ra, text_t *val)
{
    if (val->len < CSF_VARLEN_EX) {
        CM_CHECK_ROW_FREE(ra, val->len + CSF_SHORT_COL_DESC_LEN);
        csf_put_column_len(ra, (uint8)val->len);
    } else {
        CM_CHECK_ROW_FREE(ra, val->len + CSF_LONG_COL_DESC_LEN);
        csf_put_column_len(ra, CSF_VARLEN_EX);
        *(uint16 *)CM_CURR_ROW_PTR(ra) = (uint16)val->len;
        ra->head->size += sizeof(uint16);
    }
    if (val->len != 0) {
        MEMS_RETURN_IFERR(memcpy_sp(CM_CURR_ROW_PTR(ra), ra->max_size - ra->head->size, val->str, val->len));
    }
    ra->head->size += (uint16)val->len;
    return CT_SUCCESS;
}

static inline status_t csf_put_text_with_term(row_assist_t *ra, text_t *val)
{
    if (val->len < CSF_VARLEN_EX) {
        CM_CHECK_ROW_FREE(ra, val->len + CSF_SHORT_COL_DESC_LEN + 1);
        csf_put_column_len(ra, (uint8)val->len);
    } else {
        CM_CHECK_ROW_FREE(ra, val->len + CSF_LONG_COL_DESC_LEN + 1);
        csf_put_column_len(ra, CSF_VARLEN_EX);
        *(uint16 *)CM_CURR_ROW_PTR(ra) = (uint16)val->len;
        ra->head->size += sizeof(uint16);
    }
    if (val->len != 0) {
        MEMS_RETURN_IFERR(memcpy_sp(CM_CURR_ROW_PTR(ra), ra->max_size - ra->head->size, val->str, val->len));
    }
    ra->head->size += (uint16)val->len;
    ra->head->size++;
    return CT_SUCCESS;
}

static inline status_t csf_put_bin(row_assist_t *ra, binary_t *val)
{
    if (val->bytes == NULL) {
        return csf_put_null(ra);
    }

    if (val->size < CSF_VARLEN_EX) {
        CM_CHECK_ROW_FREE(ra, val->size + CSF_SHORT_COL_DESC_LEN);
        csf_put_column_len(ra, (uint8)val->size);
    } else {
        CM_CHECK_ROW_FREE(ra, val->size + CSF_LONG_COL_DESC_LEN);
        csf_put_column_len(ra, CSF_VARLEN_EX);
        *(uint16 *)CM_CURR_ROW_PTR(ra) = (uint16)val->size;
        ra->head->size += sizeof(uint16);
    }
    if (val->size != 0) {
        MEMS_RETURN_IFERR(memcpy_sp(CM_CURR_ROW_PTR(ra), ra->max_size - ra->head->size, val->bytes, val->size));
    }
    ra->head->size += (uint16)val->size;
    return CT_SUCCESS;
}

static inline status_t csf_put_lob(row_assist_t *ra, uint32 lob_locator_size, var_lob_t *lob)
{
    if (lob_locator_size < CSF_VARLEN_EX) {
        CM_CHECK_ROW_FREE(ra, lob_locator_size + CSF_SHORT_COL_DESC_LEN);
        csf_put_column_len(ra, (uint8)lob_locator_size);
    } else {
        CM_CHECK_ROW_FREE(ra, lob_locator_size + CSF_LONG_COL_DESC_LEN);
        csf_put_column_len(ra, CSF_VARLEN_EX);
        *(uint16 *)CM_CURR_ROW_PTR(ra) = (uint16)lob_locator_size;
        ra->head->size += sizeof(uint16);
    }

    switch (lob->type) {
        case CT_LOB_FROM_KERNEL:
            if (lob->knl_lob.size != 0) {
                MEMS_RETURN_IFERR(memcpy_sp(CM_CURR_ROW_PTR(ra), ra->max_size - ra->head->size, lob->knl_lob.bytes,
                    lob->knl_lob.size));
            }
            break;
        case CT_LOB_FROM_VMPOOL:
            MEMS_RETURN_IFERR(memcpy_sp(CM_CURR_ROW_PTR(ra), ra->max_size - ra->head->size,
                                        (char *)&lob->vm_lob, sizeof(lob->vm_lob)));
            break;
        default:
            CT_THROW_ERROR(ERR_UNKNOWN_LOB_TYPE, "do put csf");
            return CT_ERROR;
    }

    ra->head->size += (uint16)lob_locator_size;
    return CT_SUCCESS;
}

static inline status_t csf_put_column_data(row_assist_t *ra, void *data, uint32 size)
{
    if (size == CT_NULL_VALUE_LEN) {
        return csf_put_null(ra);
    } else {
        if (size < CSF_VARLEN_EX) {
            CM_CHECK_ROW_FREE(ra, size + CSF_SHORT_COL_DESC_LEN);
            csf_put_column_len(ra, (uint8)size);
        } else {
            CM_CHECK_ROW_FREE(ra, size + CSF_LONG_COL_DESC_LEN);
            csf_put_column_len(ra, CSF_VARLEN_EX);
            *(uint16 *)CM_CURR_ROW_PTR(ra) = (uint16)size;
            ra->head->size += sizeof(uint16);
        }
        if (size != 0) {
            MEMS_RETURN_IFERR(memcpy_sp(CM_CURR_ROW_PTR(ra), ra->max_size - ra->head->size, data, size));
        }
        ra->head->size += size;
    }
    return CT_SUCCESS;
}

#ifdef WIN32
extern __declspec(thread) uint8 g_row_offset[2];
#else
extern __thread uint8 g_row_offset[2];
#endif

static inline void csf_decode_row(row_assist_t *ra, uint16 *offsets, uint16 *lens, uint16 *size)
{
    uint16 i, pos;
    uint8 ind_or_len;

    pos = IS_SPRS_ROW(ra->head) ? OFFSET_OF(row_head_t, sprs_bitmap) : OFFSET_OF(row_head_t, bitmap);
    pos += g_row_offset[ra->head->is_migr];

    for (i = 0; i < ROW_COLUMN_COUNT(ra->head); i++) {
        if (pos >= ra->head->size) {
            lens[i] = (uint16)CT_NULL_VALUE_LEN;
            continue;
        }

        ind_or_len = *(uint8 *)(ra->buf + pos);

        if (ind_or_len < CSF_VARLEN_EX) {
            lens[i] = (uint16)ind_or_len;
            offsets[i] = pos + 1;
            pos += (lens[i] + 1);
        } else if (ind_or_len == CSF_NULL_FLAG) {
            lens[i] = (uint16)CT_NULL_VALUE_LEN;
            offsets[i] = pos + 1;
            pos++;
        } else {
            lens[i] = *(uint16 *)(ra->buf + pos + 1);
            offsets[i] = pos + sizeof(uint16) + 1;
            pos += (lens[i] + sizeof(uint16) + 1);
        }
    }

    if (size != NULL) {
        *size = pos;
    }
}

static inline void row_end(row_assist_t *ra)
{
    if (ra->is_csf) {
        ra->head->size = CM_ALIGN4(ra->head->size);
    }
}

static inline void row_init(row_assist_t *ra, char *buf, uint32 max_size, uint32 column_count)
{
    uint32 head_size, ex_maps;
    CM_ASSERT(column_count != 0);

    ex_maps = COL_BITMAP_EX_SIZE(column_count);
    head_size = sizeof(row_head_t) + ex_maps;

    ra->buf = buf;
    ra->max_size = max_size;
    ra->col_id = 0;
    ra->is_csf = CT_FALSE;

    ra->head = (row_head_t *)buf;
    ra->head->size = (uint16)head_size;
    ra->head->flags = 0;

    if (column_count >= CT_SPRS_COLUMNS) {
        ra->head->column_count = 0;
        ra->head->sprs_count = (uint16)column_count;
        ra->head->sprs_itl_id = CT_INVALID_ID8;
        MEMS_RETVOID_IFERR(memset_sp(ra->head->sprs_bitmap, ex_maps + 1, 0, ex_maps + 1));
    } else {
        ra->head->column_count = (uint16)column_count;
        ra->head->itl_id = CT_INVALID_ID8;
        MEMS_RETVOID_IFERR(memset_sp(ra->head->bitmap, (uint64)(ex_maps + NON_CSF_BITMAP_SIZE), 0,
                                     (uint64)(ex_maps + NON_CSF_BITMAP_SIZE)));
    }
}

static inline void cm_row_init(row_assist_t *ra, char *buf, uint32 max_size, uint32 column_count, bool32 is_csf)
{
    if (is_csf) {
        csf_row_init(ra, buf, max_size, column_count);
    } else {
        row_init(ra, buf, max_size, column_count);
    }
}

#define COL_BITS_NULL (uint8)0x00
#define COL_BITS_4    (uint8)0x01
#define COL_BITS_8    (uint8)0x02
#define COL_BITS_VAR  (uint8)0x03

static inline void row_set_column_bits(row_assist_t *ra, uint8 bits)
{
    uint32 map_id;
    uint8 *bitmap = NULL;

    map_id = ra->col_id >> 2;
    bitmap = IS_SPRS_ROW(ra->head) ? ra->head->sprs_bitmap : ra->head->bitmap;

    // erase bits
    bitmap[map_id] &= ~(0x03 << ((ra->col_id & 0x03) << 1));

    // set bits
    bitmap[map_id] |= bits << (((uint8)(ra->col_id & 0x03) << 1));
}

static inline void row_set_column_bits2(row_head_t *row, uint8 bits, uint32 col_id)
{
    uint32 map_id;
    uint8 *bitmap = NULL;

    map_id = col_id >> 2;
    bitmap = IS_SPRS_ROW(row) ? row->sprs_bitmap : row->bitmap;

    // erase bits
    bitmap[map_id] &= ~(0x03 << ((col_id & 0x03) << 1));

    // set bits
    bitmap[map_id] |= bits << (((uint8)(col_id & 0x03)) << 1);
}

static inline uint8 row_get_column_bits(row_assist_t *ra, uint32 id)
{
    uint32 map_id;
    uint8 *bitmap = NULL;

    map_id = id >> 2;
    bitmap = IS_SPRS_ROW(ra->head) ? ra->head->sprs_bitmap : ra->head->bitmap;

    return (uint8)(bitmap[map_id] >> ((id & 0x03) << 1)) & (uint8)0x03;
}

static inline uint8 row_get_column_bits2(row_head_t *row, uint32 id)
{
    uint32 map_id;
    uint8 *bitmap = NULL;

    map_id = id >> 2;
    bitmap = IS_SPRS_ROW(row) ? row->sprs_bitmap : row->bitmap;

    return (uint8)(bitmap[map_id] >> ((id & 0x03) << 1)) & (uint8)0x03;
}

static inline uint16 row_column_bits_size(uint16 col_num)
{
    if (col_num == 0) {
        return sizeof(uint32);
    }

    return (uint16)(CM_ALIGN16(col_num) >> 2);
}

static inline status_t bmp_put_null(row_assist_t *ra)
{
    row_set_column_bits(ra, COL_BITS_NULL);
    ra->col_id++;
    return CT_SUCCESS;
}

static inline status_t bmp_put_bin(row_assist_t *ra, binary_t *bin)
{
    char *addr = NULL;
    uint64 original_size;
    uint64 actual_size;
    int64 zero_count;

    if (bin->bytes == NULL) {
        return bmp_put_null(ra);
    }
    
    original_size = (uint64)bin->size + sizeof(uint16);
    actual_size = CM_ALIGN4(original_size);
    CM_CHECK_ROW_FREE(ra, actual_size);

    addr = CM_CURR_ROW_PTR(ra);

    *(uint16 *)addr = (uint16)bin->size;
    addr += sizeof(uint16);
    if (bin->size != 0) {
        MEMS_RETURN_IFERR(memcpy_s(addr, ra->max_size - ra->head->size - sizeof(uint16), bin->bytes, bin->size));
    }

    zero_count = actual_size - original_size;
    if (zero_count > 0) {
        MEMS_RETURN_IFERR(memset_s(addr + bin->size, (uint32)zero_count, 0, (uint32)zero_count));
    }

    ra->head->size += (uint16)actual_size;
    row_set_column_bits(ra, COL_BITS_VAR);
    ra->col_id++;
    return CT_SUCCESS;
}

static inline status_t bmp_put_int32(row_assist_t *ra, int32 val)
{
    CM_CHECK_ROW_FREE(ra, sizeof(int32));
    *(int32 *)CM_CURR_ROW_PTR(ra) = val;
    ra->head->size += (uint16)sizeof(int32);
    row_set_column_bits(ra, COL_BITS_4);
    ra->col_id++;
    return CT_SUCCESS;
}

static inline status_t bmp_put_int64(row_assist_t *ra, int64 val)
{
    CM_CHECK_ROW_FREE(ra, sizeof(int64));
    *(int64 *)CM_CURR_ROW_PTR(ra) = val;
    ra->head->size += (uint16)sizeof(int64);
    row_set_column_bits(ra, COL_BITS_8);
    ra->col_id++;
    return CT_SUCCESS;
}

static inline status_t row_put_int64(row_assist_t *ra, int64 val)
{
    CM_POINTER(ra);
    if (ra->is_csf) {
        return csf_put_int64(ra, val);
    } else {
        return bmp_put_int64(ra, val);
    }
}

static inline status_t bmp_put_datetime_mysql(row_assist_t *ra, int64 val, int32 precision)
{
    CM_CHECK_ROW_FREE(ra, sizeof(int64));
    cm_datetime_int_to_binary(val, ((uchar *)((ra)->buf + (ra)->head->size)), precision);
    ra->head->size += (uint16)sizeof(int64);
    row_set_column_bits(ra, COL_BITS_8);
    ra->col_id++;
    return CT_SUCCESS;
}

static inline status_t row_put_datetime_mysql(row_assist_t *ra, int64 val, int32 precision)
{
    CM_POINTER(ra);
    return bmp_put_datetime_mysql(ra, val, precision);
}

static inline status_t bmp_put_time_mysql(row_assist_t *ra, int64 val, int32 precision)
{
    CM_CHECK_ROW_FREE(ra, sizeof(int64));
    cm_time_int_to_binary(val, ((uchar *)((ra)->buf + (ra)->head->size)), precision);
    ra->head->size += (uint16)sizeof(int64);
    row_set_column_bits(ra, COL_BITS_8);
    ra->col_id++;
    return CT_SUCCESS;
}

static inline status_t row_put_time_mysql(row_assist_t *ra, int64 val, int32 precision)
{
    CM_POINTER(ra);
    return bmp_put_time_mysql(ra, val, precision);
}

static inline status_t row_put_int32(row_assist_t *ra, int32 val)
{
    CM_POINTER(ra);
    if (ra->is_csf) {
        return csf_put_int32(ra, val);
    } else {
        return bmp_put_int32(ra, val);
    }
}

static inline status_t row_put_null(row_assist_t *ra)
{
    CM_POINTER(ra);
    if (ra->is_csf) {
        return csf_put_null(ra);
    } else {
        return bmp_put_null(ra);
    }
}

static inline status_t row_put_bin(row_assist_t *ra, binary_t *bin)
{
    CM_POINTER2(ra, bin);

    if (ra->is_csf) {
        return csf_put_bin(ra, bin);
    } else {
        return bmp_put_bin(ra, bin);
    }
}

static inline status_t row_put_timestamptz(row_assist_t *ra, timestamp_tz_t *tstz)
{
    binary_t bin;
    CM_POINTER2(ra, tstz);
    tstz->unused = 0;
    bin.bytes = (uint8 *)tstz;
    bin.size = sizeof(timestamp_tz_t);
    return row_put_bin(ra, &bin);
}

static inline status_t row_set_null(row_assist_t *ra, uint32 col_id)
{
    ra->col_id = col_id;
    return row_put_null(ra);
}

static inline status_t row_set_int32(row_assist_t *ra, int32 val, uint32 col_id)
{
    ra->col_id = col_id;
    return row_put_int32(ra, val);
}

static inline status_t row_put_uint64(row_assist_t *ra, uint64 val)
{
    return row_put_int64(ra, (int64)val);
}

static inline status_t row_put_uint32(row_assist_t *ra, uint32 val)
{
    return row_put_int32(ra, (int32)val);
}

static inline status_t row_set_uint32(row_assist_t *ra, uint32 val, uint32 col_id)
{
    return row_set_int32(ra, (int32)val, col_id);
}

static inline status_t row_set_int64(row_assist_t *ra, int64 val, uint32 col_id)
{
    ra->col_id = col_id;
    return row_put_int64(ra, val);
}

static inline status_t row_put_timestamp_tz(row_assist_t *ra, timestamp_tz_t *val)
{
    return row_put_timestamptz(ra, val);
}

static inline status_t row_set_timestamp_tz(row_assist_t *ra, timestamp_tz_t *val, uint32 col_id)
{
    ra->col_id = col_id;
    return row_put_timestamp_tz(ra, val);
}

static inline status_t row_put_real(row_assist_t *ra, double val)
{
    CM_POINTER(ra);
    if (ra->is_csf) {
        return csf_put_real(ra, val);
    }

    CM_CHECK_ROW_FREE(ra, sizeof(double));
    *(double *)CM_CURR_ROW_PTR(ra) = val;
    ra->head->size += (uint16)sizeof(double);
    row_set_column_bits(ra, COL_BITS_8);
    ra->col_id++;
    return CT_SUCCESS;
}

static inline status_t row_set_real(row_assist_t *ra, double val, uint32 col_id)
{
    ra->col_id = col_id;
    return row_put_real(ra, val);
}

static inline status_t row_put_text(row_assist_t *ra, text_t *text)
{
    uint64 original_size;
    uint64 actual_size;
    uint64 zero_count;

    CM_POINTER2(ra, text);
    if (ra->is_csf) {
        return csf_put_text(ra, text);
    }

    original_size = (uint64)text->len + sizeof(uint16);
    actual_size = CM_ALIGN4(original_size);
    CM_CHECK_ROW_FREE(ra, actual_size);

    char *addr = CM_CURR_ROW_PTR(ra);
    *(uint16 *)addr = (uint16)(text->len);

    addr += sizeof(uint16);
    if (text->len != 0) {
        MEMS_RETURN_IFERR(memcpy_sp(addr, ra->max_size - ra->head->size - sizeof(uint16), text->str, text->len));
    }
    zero_count = actual_size - original_size;
    if (zero_count > 0) {
        MEMS_RETURN_IFERR(memset_sp(addr + text->len, (size_t)zero_count, 0, (size_t)zero_count));
    }

    ra->head->size += (uint16)actual_size;
    row_set_column_bits(ra, COL_BITS_VAR);
    ra->col_id++;
    return CT_SUCCESS;
}

static inline status_t row_put_vmid(row_assist_t *ra, mtrl_rowid_t *vmid)
{
    CM_POINTER2(ra, vmid);

    CM_CHECK_ROW_FREE(ra, sizeof(mtrl_rowid_t));
    *(mtrl_rowid_t *)CM_CURR_ROW_PTR(ra) = *vmid;
    ra->head->size += (uint16)sizeof(mtrl_rowid_t);
    row_set_column_bits(ra, COL_BITS_8);
    ra->col_id++;
    return CT_SUCCESS;
}

static inline status_t row_put_cursor(row_assist_t *ra, cursor_t *cursor)
{
    int64 result;
    CM_POINTER2(ra, cursor);

    result = (int64)(((uint64)cursor->stmt_id << 32) + (uint64)cursor->fetch_mode);
    return row_put_int64(ra, result);
}

static inline status_t row_set_text(row_assist_t *ra, text_t *text, uint32 col_id)
{
    ra->col_id = col_id;
    return row_put_text(ra, text);
}

static inline status_t row_put_text_with_term(row_assist_t *ra, text_t *text)
{
    uint64 actual_size;
    CM_POINTER2(ra, text);
    if (ra->is_csf) {
        return csf_put_text_with_term(ra, text);
    }

    actual_size = (uint64)text->len + sizeof(uint16);
    actual_size = CM_ALIGN4(actual_size);
    CM_CHECK_ROW_FREE(ra, actual_size);

    char *addr = CM_CURR_ROW_PTR(ra);
    *(uint16 *)addr = (uint16)(text->len);

    addr += sizeof(uint16);
    if (text->len != 0) {
        MEMS_RETURN_IFERR(memcpy_sp(addr, ra->max_size - ra->head->size - sizeof(uint16), text->str, text->len));
    }

    ra->head->size += (uint16)actual_size;
    row_set_column_bits(ra, COL_BITS_VAR);
    ra->col_id++;
    return CT_SUCCESS;
}

static inline status_t row_put_str_with_term(row_assist_t *ra, char *str, uint32 str_len)
{
    text_t text;
    cm_str2text_safe(str, str_len, &text);
    return row_put_text_with_term(ra, &text);
}

static inline status_t row_put_str(row_assist_t *ra, const char *str)
{
    text_t text;
    cm_str2text((char *)str, &text);
    return row_put_text(ra, &text);
}

static inline status_t row_put_lob(row_assist_t *ra, uint32 lob_locator_size, var_lob_t *lob)
{
    uint64 origin_size;
    uint64 actual_size;
    uint64 zero_count;
    uint32 copy_size = 0;
    CM_POINTER(ra);

    if (ra->is_csf) {
        return csf_put_lob(ra, lob_locator_size, lob);
    }

    origin_size = (uint64)lob_locator_size + sizeof(uint16);
    actual_size = CM_ALIGN4(origin_size);
    zero_count = actual_size - origin_size;
    CM_CHECK_ROW_FREE(ra, actual_size);

    char *addr = CM_CURR_ROW_PTR(ra);

    *(uint16 *)addr = (uint16)lob_locator_size;
    addr += sizeof(uint16);

    switch (lob->type) {
        case CT_LOB_FROM_KERNEL:
            if (lob->knl_lob.size != 0) {
                copy_size = lob->knl_lob.size;
                MEMS_RETURN_IFERR(memcpy_sp(addr, ra->max_size - ra->head->size - sizeof(uint16), lob->knl_lob.bytes,
                                            copy_size));
            }
            break;
        case CT_LOB_FROM_VMPOOL:
            copy_size = sizeof(lob->vm_lob);
            MEMS_RETURN_IFERR(memcpy_sp(addr, ra->max_size - ra->head->size - sizeof(uint16),
                                        (char *)&lob->vm_lob, copy_size));
            break;
        default:
            CT_THROW_ERROR(ERR_UNKNOWN_LOB_TYPE, "do row put");
            return CT_ERROR;
    }

    if (zero_count > 0) {
        MEMS_RETURN_IFERR(memset_sp(addr + copy_size,
                                    (size_t)ra->max_size - ra->head->size - sizeof(uint16) - copy_size, 0,
                                    (size_t)zero_count));
    }

    ra->head->size += (uint16)actual_size;
    row_set_column_bits(ra, COL_BITS_VAR);
    ra->col_id++;
    return CT_SUCCESS;
}

#define CURE_ADDR                            (addr + *offset)
#define CHECK_AND_PUT_VALUE(ra, type, value) \
    do {                                               \
        CM_CHECK_ROW_FREE(ra, *offset + sizeof(type)); \
        *(type *)CURE_ADDR = VALUE(type, value);       \
        *offset += sizeof(type);                       \
    } while (0)


static inline status_t row_set_bin(row_assist_t *ra, binary_t *bin, uint32 col_id)
{
    ra->col_id = col_id;
    return row_put_bin(ra, bin);
}

#define row_put_bool(ra, val) row_put_int32((ra), (int32)((val) != 0))
#define row_put_date          row_put_int64
#define row_put_timestamp     row_put_int64
#define row_put_timestamp_ltz row_put_int64
#define row_put_yminterval    row_put_int32
#define row_put_dsinterval    row_put_int64

#define row_set_bool(ra, val, col_id) row_set_int32((ra), (int32)((val) != 0), (col_id))
#define row_set_date                  row_set_int64
#define row_set_timestamp             row_set_int64
#define row_set_timestamp_ltz         row_set_int64
#define row_set_yminterval            row_set_int32
#define row_set_dsinterval            row_set_int64

static inline status_t bmp_put_column_data(row_assist_t *ra, uint8 bits, char *data, uint32 size)
{
    binary_t bin;

    if (bits == COL_BITS_8) {
        return bmp_put_int64(ra, *(int64 *)data);
    } else if (bits == COL_BITS_4) {
        return bmp_put_int32(ra, *(int32 *)data);
    } else if (bits == COL_BITS_VAR) {
        bin.size = size;
        bin.bytes = (uint8 *)data;
        return bmp_put_bin(ra, &bin);
    } else {
        return bmp_put_null(ra);
    }
}

static inline status_t csf_put_dec4_inner(row_assist_t *ra, dec4_t *dval)
{
    dec4_t *d4 = NULL;
    uint32 original_size = cm_dec4_stor_sz(dval);
    CM_CHECK_ROW_FREE(ra, original_size + 1);
    csf_put_column_len(ra, (uint8)original_size);
    d4 = (dec4_t *)CM_CURR_ROW_PTR(ra);
    cm_dec4_copy(d4, dval);
    ra->head->size += original_size;
    return CT_SUCCESS;
}

static inline status_t csf_put_dec4(row_assist_t *ra, dec4_t *dval)
{
    if (dval->ncells == 0) {
        return csf_put_zero(ra);
    }
    
    return csf_put_dec4_inner(ra, dval);
}

static inline status_t row_put_dec4_core(row_assist_t *ra, dec4_t *dval)
{
    CM_POINTER(ra);
    if (ra->is_csf) {
        return csf_put_dec4(ra, dval);
    }

    char* addr = CM_CURR_ROW_PTR(ra);
    dec4_t* d4 = NULL;
    uint32 original_size = cm_dec4_stor_sz(dval);
    uint32 actual_size;
    uint8  col_bits;

    /* Step 1. Generate the column schema data */
    if (original_size <= 8) {
        d4 = (dec4_t*)addr;
        if (original_size <= 4) {
            actual_size = sizeof(int32);
            col_bits = COL_BITS_4;
        } else {
            actual_size = sizeof(int64);
            col_bits = COL_BITS_8;
        }
        CM_CHECK_ROW_FREE(ra, actual_size);
    } else {
        actual_size = CM_ALIGN4(original_size + sizeof(uint16));
        col_bits = COL_BITS_VAR;
        CM_CHECK_ROW_FREE(ra, actual_size);
        *(uint16 *)addr = (uint16)original_size;
        d4 = (dec4_t*)(addr + sizeof(uint16));
        original_size += sizeof(uint16);
    }

    ra->head->size += actual_size;
    row_set_column_bits(ra, col_bits);
    ra->col_id++;

    /* Step 2. Copy decimal into row */
    if (original_size & 3) {
        d4->cells[dval->ncells] = 0;
    }
    cm_dec4_copy(d4, dval);
    return CT_SUCCESS;
}


static inline status_t row_put_dec4(row_assist_t *ra, dec8_t *d8)
{
    dec4_t d4;
    CT_RETURN_IFERR(cm_dec_8_to_4(&d4, d8));
    return row_put_dec4_core(ra, &d4);
}

static inline status_t csf_put_dec2_inner(row_assist_t *ra, dec2_t *dval)
{
    payload_t *d2 = NULL;
    uint8 original_size = cm_dec2_stor_sz(dval);
    
    CM_CHECK_ROW_FREE(ra, original_size + 1);
    csf_put_column_len(ra, original_size);
    d2 = (payload_t *)CM_CURR_ROW_PTR(ra);
    cm_dec2_copy_payload(d2, (const payload_t *)GET_PAYLOAD(dval), dval->len);
    ra->head->size += original_size;
    return CT_SUCCESS;
}

static inline status_t csf_put_dec2(row_assist_t *ra, dec2_t *dval)
{
    if (DECIMAL2_IS_ZERO(dval) || dval->len == 0) {
        return csf_put_zero(ra);
    }

    return csf_put_dec2_inner(ra, dval);
}

static inline status_t row_put_dec2_core(row_assist_t *ra, dec2_t *dval)
{
    CM_POINTER(ra);
    if (ra->is_csf) {
        return csf_put_dec2(ra, dval);
    }

    char *addr = CM_CURR_ROW_PTR(ra);
    payload_t *d2 = NULL;
    uint8 original_size = cm_dec2_stor_sz(dval);
    uint8 actual_size;
    uint8 col_bits;

    /* Step 1. Generate the column schema data */
    actual_size = CM_ALIGN4(original_size + sizeof(uint16));
    CM_CHECK_ROW_FREE(ra, actual_size);
    *(uint16 *)addr = original_size;
    d2 = (payload_t *)(addr + sizeof(uint16));
    col_bits = COL_BITS_VAR;

    ra->head->size += actual_size;
    row_set_column_bits(ra, col_bits);
    ra->col_id++;

    /* Step 2. Copy decimal into row */
    for (uint8 i = 0; i < actual_size - original_size; i++) {
        d2->cells[GET_CELLS_SIZE(dval) + i] = 0;
    }
    cm_dec2_copy_payload(d2, (const payload_t *)GET_PAYLOAD(dval), dval->len);
    return CT_SUCCESS;
}

static inline status_t row_put_dec2(row_assist_t *ra, dec8_t *d8)
{
    dec2_t d2;
    CT_RETURN_IFERR(cm_dec_8_to_2(&d2, d8));
    return row_put_dec2_core(ra, &d2);
}

static inline status_t row_set_dec4(row_assist_t *ra, dec8_t *dec, uint32 col_id)
{
    ra->col_id = col_id;
    return row_put_dec4(ra, dec);
}

static inline status_t row_set_dec2(row_assist_t *ra, dec8_t *dec, uint32 col_id)
{
    ra->col_id = col_id;
    return row_put_dec2(ra, dec);
}

static void inline row_put_prec_and_scale(row_assist_t *ra, uint32 datatype, int32 precision, int32 scale)
{
    switch (datatype) {
        case CT_TYPE_REAL:
        case CT_TYPE_FLOAT:
            if (precision != CT_UNSPECIFIED_REAL_PREC) {
                (void)row_put_int32(ra, precision);  // precision
                (void)row_put_int32(ra, scale);      // scale
                return;
            }
            break;

        case CT_TYPE_NUMBER:
        case CT_TYPE_DECIMAL:
        case CT_TYPE_NUMBER2:
        case CT_TYPE_NUMBER3:
            if (precision != CT_UNSPECIFIED_NUM_PREC) {
                (void)row_put_int32(ra, precision);  // precision
                (void)row_put_int32(ra, scale);      // scale
                return;
            }
            break;

        case CT_TYPE_INTERVAL_DS:
            (void)row_put_int32(ra, precision);  // precision
            (void)row_put_int32(ra, scale);      // scale
            return;

        case CT_TYPE_INTERVAL_YM:
        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
        case CT_TYPE_TIMESTAMP_TZ:
        case CT_TYPE_TIMESTAMP_LTZ:
        case CT_TYPE_DATETIME_MYSQL:
        case CT_TYPE_TIME_MYSQL:
        case CT_TYPE_INTEGER:
        case CT_TYPE_UINT32:
        case CT_TYPE_UINT64:
        case CT_TYPE_BIGINT:
            (void)row_put_int32(ra, precision);  // precision
            (void)row_put_null(ra);                    // scale
            return;

        default:
            break;
    }

    (void)row_put_null(ra);  // precision
    (void)row_put_null(ra);  // scale
}

static inline void row_put_column_data(row_assist_t *ra, uint8 bits, char *data, uint32 size)
{
    if (ra->is_csf) {
        (void)csf_put_column_data(ra, data, size);
    } else {
        (void)bmp_put_column_data(ra, bits, data, size);
    }
    return;
}

static inline void cm_attach_row(row_assist_t *ra, char *addr)
{
    ra->buf = addr;
    ra->head = (row_head_t *)addr;
    ra->col_id = 0;
    ra->max_size = 0;
    ra->is_csf = (ra->head->is_csf == 1);
}

static inline void cm_decode_row_base(row_assist_t *ra, const char *ptr, uint16 count, uint16 *offsets, uint16 *lens,
                                      uint16 *size)
{
    uint8 bits;
    uint16 i, pos, ex_maps;
    CM_POINTER3(ptr, offsets, lens);

    if (SECUREC_UNLIKELY(ra->is_csf)) {
        csf_decode_row(ra, offsets, lens, size);
        return;
    }

    ex_maps = ROW_BITMAP_EX_SIZE(ra->head);
    pos = sizeof(row_head_t) + ex_maps + g_row_offset[ra->head->is_migr];

    for (i = 0; i < count; i++) {
        bits = row_get_column_bits(ra, i);
        offsets[i] = pos;

        if (bits == COL_BITS_8) {
            lens[i] = 8;
            pos += 8;
        } else if (bits == COL_BITS_4) {
            lens[i] = 4;
            pos += 4;
        } else if (bits == COL_BITS_NULL) {
            lens[i] = CT_NULL_VALUE_LEN;
        } else {
            lens[i] = *(uint16 *)(ptr + pos);
            offsets[i] += sizeof(uint16);
            pos += CM_ALIGN4(lens[i] + sizeof(uint16));
        }
    }

    if (size != NULL) {
        *size = pos;
    }
}

static inline void cm_decode_row(char *ptr, uint16 *offsets, uint16 *lens, uint16 *size)
{
    row_assist_t ra;
    uint16 column_count;

    cm_attach_row(&ra, ptr);
    column_count = ROW_COLUMN_COUNT(ra.head);
    cm_decode_row_base(&ra, ptr, column_count, offsets, lens, size);
}

static inline uint32 cm_decode_row_imp(char *ptr, uint16 *offsets, uint16 *lens, uint16 *size)
{
    row_assist_t ra;
    uint16 column_count;

    cm_attach_row(&ra, ptr);
    column_count = ROW_COLUMN_COUNT(ra.head);
    cm_decode_row_base(&ra, ptr, column_count, offsets, lens, size);
    return column_count;
}

static inline void cm_decode_row_ex(
    char *ptr, uint16 *offsets, uint16 *lens, uint16 count, uint16 *size, uint16 *decode_count)
{
    row_assist_t ra;
    uint16 column_count;

    cm_attach_row(&ra, ptr);
    column_count = ROW_COLUMN_COUNT(ra.head);
    *decode_count = MIN(column_count, count);
    cm_decode_row_base(&ra, ptr, *decode_count, offsets, lens, size);
}

static inline uint16 cm_get_row_size(char *row)
{
    return ((row_head_t *)row)->size;
}

static inline uint16 cm_row_init_size(bool32 is_csf, uint32 column_count)
{
    if (is_csf) {
        return CSF_ROW_HEAD_SIZE(column_count);
    } else {
        return sizeof(row_head_t) + COL_BITMAP_EX_SIZE(column_count);
    }
}

static inline bool32 cm_is_null_col(row_head_t *row, uint16 *lens, int16 col)
{
    if (row->is_csf) {
        return lens[col] == CT_NULL_VALUE_LEN;
    } else {
        uint8 bits = row_get_column_bits2(row, col);
        return bits == COL_BITS_NULL;
    }
}
static inline status_t cm_put_csf_row_column(row_head_t *src_row, uint16 *src_offsets, uint16 *src_lens,
    uint16 col_id, row_assist_t *dst_ra)
{
    return csf_put_column_data(dst_ra, (char *)(src_row) + src_offsets[col_id], src_lens[col_id]);
}

static inline status_t cm_put_bmp_row_column(row_head_t *src_row, uint16 *src_offsets, uint16 *src_lens,
    uint16 col_id, row_assist_t *dst_ra)
{
    uint8 bits;

    bits = row_get_column_bits2(src_row, col_id);
    return bmp_put_column_data(dst_ra, bits, (char *)(src_row) + src_offsets[col_id], src_lens[col_id]);
}

static inline bool32 cm_row_equal(const char *lbuf, const char *rbuf)
{
    uint16 l_keysize = ((row_head_t *)lbuf)->size;
    uint16 r_keysize = ((row_head_t *)rbuf)->size;

    if (l_keysize != r_keysize) {
        return CT_FALSE;
    }

    return (memcmp(lbuf, rbuf, l_keysize) == 0);
}

#define ROW_SIZE(row)           (((row_head_t *)(row))->size)
#define IS_INVALID_ROW(row)     (((row_head_t *)(row))->size == 0)
#define CM_SET_INVALID_ROW(row) \
    {                                    \
        (((row_head_t *)(row))->size) = 0; \
    }
#ifdef __cplusplus
}
#endif

#endif
