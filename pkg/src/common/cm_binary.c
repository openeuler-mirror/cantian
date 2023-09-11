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
 * cm_binary.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_binary.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_binary.h"

#ifdef __cplusplus
extern "C" {
#endif

const char g_hex_map[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

const uint8 g_hex2byte_map[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

static const char *g_byte2hex_map[] = {
    "00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "0A", "0B", "0C", "0D", "0E", "0F",
    "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "1A", "1B", "1C", "1D", "1E", "1F",
    "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "2A", "2B", "2C", "2D", "2E", "2F",
    "30", "31", "32", "33", "34", "35", "36", "37", "38", "39", "3A", "3B", "3C", "3D", "3E", "3F",
    "40", "41", "42", "43", "44", "45", "46", "47", "48", "49", "4A", "4B", "4C", "4D", "4E", "4F",
    "50", "51", "52", "53", "54", "55", "56", "57", "58", "59", "5A", "5B", "5C", "5D", "5E", "5F",
    "60", "61", "62", "63", "64", "65", "66", "67", "68", "69", "6A", "6B", "6C", "6D", "6E", "6F",
    "70", "71", "72", "73", "74", "75", "76", "77", "78", "79", "7A", "7B", "7C", "7D", "7E", "7F",
    "80", "81", "82", "83", "84", "85", "86", "87", "88", "89", "8A", "8B", "8C", "8D", "8E", "8F",
    "90", "91", "92", "93", "94", "95", "96", "97", "98", "99", "9A", "9B", "9C", "9D", "9E", "9F",
    "A0", "A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A9", "AA", "AB", "AC", "AD", "AE", "AF",
    "B0", "B1", "B2", "B3", "B4", "B5", "B6", "B7", "B8", "B9", "BA", "BB", "BC", "BD", "BE", "BF",
    "C0", "C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "CA", "CB", "CC", "CD", "CE", "CF",
    "D0", "D1", "D2", "D3", "D4", "D5", "D6", "D7", "D8", "D9", "DA", "DB", "DC", "DD", "DE", "DF",
    "E0", "E1", "E2", "E3", "E4", "E5", "E6", "E7", "E8", "E9", "EA", "EB", "EC", "ED", "EE", "EF",
    "F0", "F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8", "F9", "FA", "FB", "FC", "FD", "FE", "FF",
};

static inline void cm_concat_byte_hex(text_t *text, uint8 byte)
{
    const char *byte_hex = g_byte2hex_map[byte];

    if (text->len > 0) {
        *(uint16 *)(text->str + text->len) = *(uint16 *)byte_hex;
        text->len += 2;
        return;
    }

    // whether text->len is equal to 0
    if (byte == 0) { // if the highest byte is 0, ignore it
        return;
    }

    if (byte < 0x10) {  // if the first char of byte_hex is "0", ignore it
        text->str[text->len] = byte_hex[1];
        text->len = 1;
    } else {
        *(uint16 *)(text->str + text->len) = *(uint16 *)byte_hex;
        text->len = 2;
    }
}

#define BIGINT_BYTE_MASK_BEGIN 0xFF00000000000000

static inline uint8 cm_get_bigint_byte(uint64 val, uint32 id)
{
    // id << 3 is equal to id * 8
    uint64 mask = BIGINT_BYTE_MASK_BEGIN >> (id << 3);
    uint32 bits = ((7 - id) << 3);

    return (uint8)((val & mask) >> bits);
}


// the buffer of result->str is ready
void cm_bigint2hex(uint64 val, text_t *result)
{
    uint8 byte;
    for (uint32 i = 0; i < sizeof(uint64); i++) {
        byte = cm_get_bigint_byte(val, i);
        cm_concat_byte_hex(result, byte);
    }

    // whether val is qual to 0
    if (result->len == 0) {
        result->str[0] = '0';
        result->len = 1;
    }
}

static inline status_t cm_xbytes_as_uint64(const binary_t *bin, uint64 *result, const char *type_name)
{
    if (bin->size > sizeof(int64)) {  // int64 for 8 * bytes
        GS_THROW_ERROR(ERR_TYPE_OVERFLOW, type_name);
        return GS_ERROR;
    }

    if (bin->size == 0) {
        *result = 0;
        return GS_SUCCESS;
    }

    uint64 u64 = bin->bytes[0];
    for (uint32 i = 1; i < bin->size; i++) {
        u64 = (u64 << 8) + bin->bytes[i];  // one byte = 8 bits
    }

    *result = u64;
    return GS_SUCCESS;
}

// XBYTES is used for compitable with MySQL(sample ...where a = X\010203...)
// XBYTES were processed as BIGINT when exec some operator(+-*/%) expressions
status_t cm_xbytes2bigint(const binary_t *bin, int64 *result)
{
    return cm_xbytes_as_uint64(bin, (uint64 *)result, "BIGINT");
}

status_t cm_xbytes2ubigint(const binary_t *bin, uint64 *result)
{
    return cm_xbytes_as_uint64(bin, (uint64 *)result, "UNSIGNED BIGINT");
}

status_t cm_xbytes2uint32(const binary_t *bin, uint32 *result)
{
    uint64 u64;
    GS_RETURN_IFERR(cm_xbytes_as_uint64(bin, &u64, "UNSIGNED INTEGER"));
    TO_UINT32_OVERFLOW_CHECK(u64, uint64);
    *result = (uint32)u64;
    return GS_SUCCESS;
}

status_t cm_xbytes2int32(const binary_t *bin, int32 *result)
{
    uint64 u64;
    GS_RETURN_IFERR(cm_xbytes_as_uint64(bin, &u64, "INTEGER"));
    TO_UINT32_OVERFLOW_CHECK(u64, uint64);
    *result = (int32)u64;
    return GS_SUCCESS;
}

status_t cm_str2bin(const char *str, bool32 hex_prefix, binary_t *bin, uint32 bin_max_sz)
{
    text_t text;
    cm_str2text((char *)str, &text);
    return cm_text2bin(&text, hex_prefix, bin, bin_max_sz);
}

status_t cm_verify_hex_string(const text_t *text)
{
    // if the prefix exists, the text->len must be >= 2
    bool32 has_prefix = (text->len >= 2) && ((text->str[0] == '\\') || (text->str[0] == '0')) &&
                        ((text->str[1] == 'x') || (text->str[1] == 'X'));
    if (has_prefix) {
        if (text->len < 3) {  // min hex string is 0x0
            GS_THROW_ERROR(ERR_TEXT_FORMAT_ERROR, "hex");
            return GS_ERROR;
        }
    }

    uint32 i = has_prefix ? 2 : 0;
    uint8 half_byte = 0;
    for (; i < text->len; i++) {
        half_byte = cm_hex2int8((uint8)text->str[i]);
        if (half_byte == 0xFF) {
            GS_THROW_ERROR(ERR_TEXT_FORMAT_ERROR, "hex");
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t cm_text2bin_check(const text_t *text, bool32 hex_prefix, binary_t *bin)
{
    if (hex_prefix) {
        if (text->len < 3) {  // min hex string is 0x0
            GS_THROW_ERROR(ERR_TEXT_FORMAT_ERROR, "hex");
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

status_t cm_text2bin(const text_t *text, bool32 hex_prefix, binary_t *bin, uint32 bin_max_sz)
{
    uint32 i, pos;
    uint8 half_byte;

    CM_POINTER2(text, bin);
    GS_RETURN_IFERR(cm_text2bin_check(text, hex_prefix, bin));
    if (text->len == 0) {
        bin->size = 0;
        return GS_SUCCESS;
    }

    // set the starting position
    i = hex_prefix ? 2 : 0;
    uint32 len = text->len;
    bool32 is_quotes = (text->str[0] == 'X') && (text->str[1] == '\'');
    if (is_quotes) {
        len = text->len - 1;
    }

    pos = 0;
    if (len % 2 == 1) {  // handle odd length hex string
        if (pos >= bin_max_sz) {
            GS_THROW_ERROR(ERR_BUFFER_OVERFLOW, pos, bin_max_sz);
            return GS_ERROR;
        }

        bin->bytes[pos] = cm_hex2int8((uint8)text->str[i]);
        if (bin->bytes[pos] == 0xFF) {
            GS_THROW_ERROR(ERR_TEXT_FORMAT_ERROR, "hex");
            return GS_ERROR;
        }
        pos++;
        i++;
    }

    for (; i < len; i += 2) {  // 1 byte needs 2 chars to express
        half_byte = cm_hex2int8((uint8)text->str[i]);
        if (half_byte == 0xFF) {
            GS_THROW_ERROR(ERR_TEXT_FORMAT_ERROR, "hex");
            return GS_ERROR;
        }

        if (pos >= bin_max_sz) {
            GS_THROW_ERROR(ERR_BUFFER_OVERFLOW, pos, bin_max_sz);
            return GS_ERROR;
        }

        bin->bytes[pos] = (uint8)(half_byte << 4);

        half_byte = cm_hex2int8((uint8)text->str[i + 1]);
        if (half_byte == 0xFF) {
            GS_THROW_ERROR(ERR_TEXT_FORMAT_ERROR, "hex");
            return GS_ERROR;
        }

        bin->bytes[pos] += half_byte;
        pos++;
    }

    bin->size = pos;

    return GS_SUCCESS;
}

status_t cm_bin2text(const binary_t *bin, bool32 hex_prefix, text_t *text)
{
    uint32 i, pos;
    uint32 buf_len;
    CM_POINTER2(bin, text);

    char *str = text->str;
    buf_len = text->len;
    if (hex_prefix) {
        if (bin->size * 2 + 2 > buf_len) {  // 1 byte needs 2 chars
            GS_THROW_ERROR(ERR_COVNERT_FORMAT_ERROR, "string");
            return GS_ERROR;
        }

        str[0] = '0';
        str[1] = 'x';

        pos = 2;  // if the prefix exists, the position must start from 2
    } else {
        if (bin->size * 2 > buf_len) { // 1 byte needs 2 chars
            GS_THROW_ERROR(ERR_COVNERT_FORMAT_ERROR, "string");
            return GS_ERROR;
        }

        pos = 0;
    }

    for (i = 0; i < bin->size; i++) {
        str[pos] = g_hex_map[(bin->bytes[i] & 0xF0) >> 4];
        pos++;
        str[pos] = g_hex_map[bin->bytes[i] & 0x0F];
        pos++;
    }

    text->len = pos;
    return GS_SUCCESS;
}

status_t cm_bin2str(binary_t *bin, bool32 hex_prefix, char *str, uint32 buf_len)
{
    text_t tmp_text = { .str = str, .len = buf_len };

    GS_RETURN_IFERR(cm_bin2text(bin, hex_prefix, &tmp_text));

    if (tmp_text.len >= buf_len) {
        GS_THROW_ERROR(ERR_BUFFER_OVERFLOW, tmp_text.len + 1, buf_len);
        return GS_ERROR;
    }
    str[tmp_text.len] = '\0';
    return GS_SUCCESS;
}

status_t cm_hex2int64(const char *str, uint32 strlen, int64 *res)
{
    int64 iret = 0;
    unsigned char *ptr = (unsigned char *)str;
    for (uint32 i = 0; i < strlen; i++) {
        if (*ptr >= '0' && *ptr <= '9') {
            iret = (iret << 4) + ((*ptr) - '0');  // one character said 4 bit for hex
        } else if (*ptr >= 'A' && *ptr <= 'F') {
            iret = (iret << 4) + (((*ptr) - 'A') + 10);
        } else if (*ptr >= 'a' && *ptr <= 'f') {
            iret = (iret << 4) + (((*ptr) - 'a') + 10);
        } else {
            return GS_ERROR;
        }
        ++ptr;
    }
    *res = iret;
    return GS_SUCCESS;
}

int32 cm_compare_bin(const binary_t *left, const binary_t *right)
{
    uint32 i, cmp_len;
    uchar c1, c2;

    cmp_len = (left->size < right->size) ? left->size : right->size;
    for (i = 0; i < cmp_len; i++) {
        c1 = (uchar)left->bytes[i];
        c2 = (uchar)right->bytes[i];

        if (c1 > c2) {
            return 1;
        } else if (c1 < c2) {
            return -1;
        }
    }

    return (left->size > right->size) ? 1 : ((left->size == right->size) ? 0 : -1);
}

status_t cm_concat_bin(binary_t *bin, uint32 bin_len, const binary_t *part)
{
    if (part->size != 0) {
        MEMS_RETURN_IFERR(
            memcpy_sp(bin->bytes + bin->size, (size_t)(bin_len - bin->size), part->bytes, (size_t)part->size));
    }
    bin->size += part->size;
    return GS_SUCCESS;
}

#ifdef __cplusplus
}
#endif
