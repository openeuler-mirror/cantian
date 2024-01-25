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
 * cm_binary.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_binary.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_BINARY_H_
#define __CM_BINARY_H_

#include "cm_defs.h"
#include "cm_text.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_binary {
    uint8  *bytes;
    uint32  size;
    bool8   is_hex_const;  // for MySQl compatible, "where a = x\010102"
    uint8   unused[3];
} binary_t;

extern const uint8 g_hex2byte_map[];
extern const char  g_hex_map[];

static inline uint8 cm_hex2int8(uchar c)
{
    return g_hex2byte_map[c];
}

static inline void cm_rtrim0_binary(binary_t *bin)
{
    while (bin->size > 0 && (bin->bytes[bin->size - 1] == 0)) {
        --bin->size;
    }
}

void     cm_bigint2hex(uint64 val, text_t *result);
status_t cm_xbytes2bigint(const binary_t *bin, int64 *result);
status_t cm_xbytes2ubigint(const binary_t *bin, uint64 *result);
status_t cm_xbytes2uint32(const binary_t *bin, uint32 *result);
status_t cm_xbytes2int32(const binary_t *bin, int32 *result);

status_t cm_verify_hex_string(const text_t *text);
status_t cm_bin2str(binary_t *bin, bool32 hex_prefix, char *str, uint32 buf_len);
status_t cm_bin2text(const binary_t *bin, bool32 hex_prefix, text_t *text);
status_t cm_str2bin(const char *str, bool32 hex_prefix, binary_t *bin, uint32 bin_max_sz);
status_t cm_text2bin(const text_t *text, bool32 hex_prefix, binary_t *bin, uint32 bin_max_sz);
status_t cm_hex2int64(const char *str, uint32 strlen, int64 *res);
int32 cm_compare_bin(const binary_t *left, const binary_t *right);
status_t cm_concat_bin(binary_t *bin, uint32 bin_len, const binary_t *part);

/**************************************************************************
 * NBO Network Byte Order, nbo32 = network byte order 32 bits integer
 ***************************************************************************/
/* uint8 * b: bytes buffer
 * n >= 0 && n <= 0xFF */
static inline void nbo32_write_1byte(uint8 *b, uint32 n)
{
    b[0] = (uint8)n;
}

/* uint8 * b: bytes buffer */
static inline uint32 nbo32_read_1byte(uint8 *b)
{
    return ((uint32)(b[0]));
}

/* uint8 * b: bytes buffer
* n >= 0 && n <= 0xFFFF */
static inline void nbo32_write_2bytes(uint8 *b, uint32 n)
{
    b[0] = (uint8)(n >> 8);
    b[1] = (uint8)n;
}

/* uint8 * b: bytes buffer */
static inline uint32 nbo32_read_2bytes(const uint8 *b) /* !< in: pointer to 2 bytes */
{
    return (((uint32)(b[0]) << 8) | (uint32)(b[1]));
}

/* uint8 * b: bytes buffer */
static inline void nbo32_write_4bytes(uint8 *b, uint32 n)
{
    b[0] = (uint8)(n >> 24);
    b[1] = (uint8)(n >> 16);
    b[2] = (uint8)(n >> 8);
    b[3] = (uint8)n;
}

/* uint8 * b: bytes buffer */
static inline  uint32 nbo32_read_4bytes(const uint8 *b)
{
    return (((uint32)(b[0]) << 24) | ((uint32)(b[1]) << 16) | ((uint32)(b[2]) << 8) | (uint32)(b[3]));
}

#ifdef __cplusplus
}
#endif

#endif
