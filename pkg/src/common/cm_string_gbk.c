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
 * cm_string_gbk.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_string_gbk.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_charset.h"
#include "cm_iconv.h"

#ifdef __cplusplus
extern "C" {
#endif

/* GBK charset */
static int32 cm_gbk_chr_bytes(uint8 c, uint32 *bytes)
{
    if (CM_IS_ASCII((int8)c)) {
        *bytes = 1;
        return CT_SUCCESS;
    } else if (IS_VALID_GBK_START_BYTE(c)) {
        *bytes = 2;
        return CT_SUCCESS;
    } else {
        *bytes = 1;
        return CT_ERROR;
    }
}

static status_t cm_gbk_str_bytes_internal(const char *str, uint32 len, uint32 *bytes)
{
    uint32 i;

    if (cm_gbk_chr_bytes((uint8)*str, bytes) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (*bytes > len) {
        *bytes = len;
        return CT_ERROR;
    }

    // verify GBK character
    for (i = 1; i < *bytes; i++) {
        if (!IS_VALID_GBK_CHAR(*(str + i))) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static inline status_t cm_gbk_str_bytes_ignore(const char *str, uint32 len, uint32 *bytes)
{
    uint32 i, check_len;

    if (cm_gbk_chr_bytes((uint8)*str, bytes) != CT_SUCCESS) {
        return CT_ERROR;
    }

    // verify GBK character
    check_len = MIN(*bytes, len);
    for (i = 1; i < check_len; i++) {
        if (!IS_VALID_GBK_CHAR(*(str + i))) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t cm_gbk_length_internal(const text_t *text, uint32 *characters)
{
    uint32 pos, temp_bytes, temp_characters;

    pos = temp_characters = 0;

    while (pos < text->len) {
        if (cm_gbk_str_bytes_internal(text->str + pos, text->len - pos, &temp_bytes) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_NLS_INTERNAL_ERROR, "GBK buffer");
            return CT_ERROR;
        }

        pos += temp_bytes;
        temp_characters++;
    }

    if (pos != text->len) {
        CT_THROW_ERROR(ERR_NLS_INTERNAL_ERROR, "GBK buffer");
        return CT_ERROR;
    }

    *characters = temp_characters;
    return CT_SUCCESS;
}

static inline void cm_gbk_special_multi_byte(text_t *src, text_t *dst, uint32 *i, uint32 *j)
{
    switch (src->str[*i]) {
        case (ASCII_HALF_BLANK_SPACE): {
            // convert half-width blank space to full-width blank space(0xA1A1)
            dst->str[*j] = 0xA1;
            dst->str[*j + 1] = 0xA1;
            dst->len += 1;
            *i += 1;
            *j += 2;
            break;
        }
        case (ASCII_HALF_DOUBLE_QUOTATION): {
            // convert half-width double quotation to full-width double quotation(0xA1B1)
            dst->str[*j] = 0xA1;
            dst->str[*j + 1] = 0xB1;
            dst->len += 1;
            *i += 1;
            *j += 2;
            break;
        }
        case (ASCII_HALF_SINGLE_QUOTATION): {
            // convert half-width single quotation to full-width single quotation(0xA1AF)
            dst->str[*j] = 0xA1;
            dst->str[*j + 1] = 0xAF;
            dst->len += 1;
            *i += 1;
            *j += 2;
            break;
        }
        case (ASCII_HALF_DOLLAR): {
            // convert half-width double quotation to full-width double quotation(0xA1E7)
            dst->str[*j] = 0xA1;
            dst->str[*j + 1] = 0xE7;
            dst->len += 1;
            *i += 1;
            *j += 2;
            break;
        }
        case (ASCII_HALF_CARET): {
            // convert half-width caret to full-width caret(0xA6E4)
            dst->str[*j] = 0xA6;
            dst->str[*j + 1] = 0xE4;
            dst->len += 1;
            *i += 1;
            *j += 2;
            break;
        }
        case (ASCII_HALF_APOSTROPHE): {
            // convert half-width apostrophe to full-width apostrophe(0xA1AE)
            dst->str[*j] = 0xA1;
            dst->str[*j + 1] = 0xAE;
            dst->len += 1;
            *i += 1;
            *j += 2;
            break;
        }
        case (ASCII_HALF_TILDE): {
            // convert half-width tilde to full-width tilde(0xA1AB)
            dst->str[*j] = 0xA1;
            dst->str[*j + 1] = 0xAB;
            dst->len += 1;
            *i += 1;
            *j += 2;
            break;
        }
        default:
            break;
    }
}

static inline void cm_gbk_common_multi_byte(text_t *src, text_t *dst, uint32 *i, uint32 *j)
{
    // convert half-width character to full-width character(other ascii character)
    dst->str[*j] = 0xA3;
    dst->str[*j + 1] = src->str[*i] + 0x80;
    dst->len += 1;
    *i += 1;
    *j += 2;
}

static inline void cm_gbk_other_character_multi_byte(text_t *src, text_t *dst, uint32 *i, uint32 *j)
{
    dst->str[*j] = src->str[*i];
    dst->str[*j + 1] = src->str[*i + 1];
    *i += 2;
    *j += 2;
}

static inline void cm_gbk_special_single_byte(text_t *src, text_t *dst, uint32 *i, uint32 *j)
{
    if (GBK_FULL_BLANK_SPACE(src->str[*i], src->str[*i + 1])) {
        // convert full-width blank space to half-width blank space(0x20)
        dst->str[*j] = 0x20;
        dst->len -= 1;
        *i += 2;
        *j += 1;
    } else if (GBK_FULL_DOUBLE_QUOTATION(src->str[*i], src->str[*i + 1])) {
        // convert full-width double quotation to half-width double quotation(0x22)
        dst->str[*j] = 0x22;
        dst->len -= 1;
        *i += 2;
        *j += 1;
    } else if (GBK_FULL_SINGLE_QUOTATION(src->str[*i], src->str[*i + 1])) {
        // convert full-width single quotation to half-width single quotation(0x27)
        dst->str[*j] = 0x27;
        dst->len -= 1;
        *i += 2;
        *j += 1;
    } else if (GBK_FULL_DOLLAR(src->str[*i], src->str[*i + 1])) {
        // convert full-width dollar to half-width dollar(0x24)
        dst->str[*j] = 0x24;
        dst->len -= 1;
        *i += 2;
        *j += 1;
    } else if (GBK_FULL_CARET(src->str[*i], src->str[*i + 1])) {
        // convert full-width caret to half-width caret(0x5E)
        dst->str[*j] = 0x5E;
        dst->len -= 1;
        *i += 2;
        *j += 1;
    } else if (GBK_FULL_APOSTROPHE(src->str[*i], src->str[*i + 1])) {
        // convert full-width apostrophe to half-width apostrophe(0x60)
        dst->str[*j] = 0x60;
        dst->len -= 1;
        *i += 2;
        *j += 1;
    } else if (GBK_FULL_TILDE(src->str[*i], src->str[*i + 1])) {
        // convert full-width tilde to half-width tilde(0x7E)
        dst->str[*j] = 0x7E;
        dst->len -= 1;
        *i += 2;
        *j += 1;
    }
}

static inline void cm_gbk_common_single_byte(text_t *src, text_t *dst, uint32 *i, uint32 *j)
{
    // convert full-width character to half-width character(other ascii character)
    dst->str[*j] = (src->str[*i + 1] - 0x80) & 0xFF;
    dst->len -= 1;
    *i += 2;
    *j += 1;
}

static inline status_t cm_gbk_other_character_single_byte(text_t *src, text_t *dst, uint32 *i, uint32 *j)
{
    uint32 char_bytes;

    CT_RETURN_IFERR(cm_gbk_chr_bytes((uint8)src->str[*i], &char_bytes));
    if (char_bytes == 1) {
        dst->str[*j] = src->str[*i];
        *i += 1;
        *j += 1;
    } else {
        dst->str[*j] = src->str[*i];
        dst->str[*j + 1] = src->str[*i + 1];
        *i += 2;
        *j += 2;
    }

    return CT_SUCCESS;
}

static status_t cm_gbk_multi_byte_internal(text_t *src, text_t *dst)
{
    uint32 i, j;
    
    i = j = 0;
    dst->len = src->len;

    while (i < src->len) {
        if (IS_GBK_SPECIAL_HALF_CHARACTER(src->str[i])) {
            // for special character
            cm_gbk_special_multi_byte(src, dst, &i, &j);
        } else if (GBK_HALF_OTHER(src->str[i])) {
            // for common ascii character
            cm_gbk_common_multi_byte(src, dst, &i, &j);
        } else {
            // for other character
            cm_gbk_other_character_multi_byte(src, dst, &i, &j);
        }
    }

    return CT_SUCCESS;
}

static status_t cm_gbk_single_byte_internal(text_t *src, text_t *dst)
{
    uint32 i, j;
    
    i = j = 0;
    dst->len = src->len;

    while (i < src->len) {
        if ((src->len - i >= 2) && IS_GBK_SPECIAL_FULL_CHARACTER(src->str[i], src->str[i + 1])) {
            // for special character
            cm_gbk_special_single_byte(src, dst, &i, &j);
        } else if ((src->len - i >= 2) && GBK_FULL_OTHER(src->str[i], src->str[i + 1])) {
            // for common ascii character
            cm_gbk_common_single_byte(src, dst, &i, &j);
        } else {
            // for other character
            CT_RETURN_IFERR(cm_gbk_other_character_single_byte(src, dst, &i, &j));
        }
    }

    return CT_SUCCESS;
}

static status_t cm_gbk_length_ignore_internal(const text_t *text, uint32 *characters, uint32 *ignore_bytes)
{
    uint32 pos, temp_bytes, temp_characters;

    pos = temp_characters = 0;

    while (pos < text->len) {
        if (cm_gbk_str_bytes_ignore(text->str + pos, text->len - pos, &temp_bytes) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_NLS_INTERNAL_ERROR, "GBK buffer");
            return CT_ERROR;
        }

        pos += temp_bytes;
        temp_characters++;
    }

    *characters = temp_characters;
    *ignore_bytes = pos - text->len;
    return CT_SUCCESS;
}

char *cm_gbk_move_char_forward(const char *str, uint32 str_len)
{
    uint32 chlen = 0;
    if (cm_gbk_str_bytes(str, str_len, &chlen) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_GENERIC_INTERNAL_ERROR, "invalid GBK buffer");
        return NULL;
    }

    return (char *)(str + chlen);
}

char *cm_gbk_move_char_backward(char *str, const char *head)
{
    char *c = str - 1;
    uint32 chnum = 0;

    if (CM_IS_ASCII(*c)) {
        return c;
    }

    if (IS_VALID_GBK_CHAR(*c) &&
        c > head &&
        IS_VALID_GBK_START_BYTE(*(c - 1))) {
        c--;
    }

    if ((cm_gbk_chr_bytes((uint8)*c, &chnum) == CT_SUCCESS) && (chnum == str - c)) {
        return c;
    }
    CT_THROW_ERROR(ERR_GENERIC_INTERNAL_ERROR, "invalid GBK buffer");
    return NULL;
}

char *cm_gbk_name(void)
{
    return "GBK";
}

bool8 cm_gbk_has_multibyte(const char *str, uint32 len)
{
    uint32 i;
    uint8 *ptr = (uint8 *)str;

    for (i = 0; i < len; i++) {
        if (IS_VALID_GBK_START_BYTE(ptr[i])) {
            return CT_TRUE;
        }
    }

    return CT_FALSE;
}

status_t cm_gbk_str_bytes(const char *str, uint32 len, uint32 *bytes)
{
    return cm_gbk_str_bytes_internal(str, len, bytes);
}

status_t cm_gbk_reverse_str_bytes(const char *str, uint32 len, uint32 *bytes)
{
    const char* cur_c = str;

    // 1 byte character
    if (CM_IS_ASCII(*cur_c)) {
        *bytes = 1;
        return CT_SUCCESS;
    }

    // 2 bytes character
    if (len < 2 || !IS_VALID_GBK_CHAR(*cur_c) || !IS_VALID_GBK_START_BYTE(*(cur_c - 1))) {
        return CT_ERROR;
    }

    *bytes = 2;
    return CT_SUCCESS;
}

bool8 cm_gbk_text_like(const text_t *text1, const text_t *text2)
{
    return (bool8)cm_text_like(text1, text2, CHARSET_GBK);
}

status_t cm_gbk_text_like_escape(char *str, const char *str_end, char *wildstr,
    const char *wildend, char escape, int32 *cmp_ret)
{
    return cm_text_like_escape(str, str_end, wildstr, wildend, escape, cmp_ret, CHARSET_GBK);
}

status_t cm_gbk_length(const text_t *text, uint32 *characters)
{
    return cm_gbk_length_internal(text, characters);
}

status_t cm_gbk_length_ignore(const text_t *text, uint32 *characters, uint32 *ignore_bytes)
{
    return cm_gbk_length_ignore_internal(text, characters, ignore_bytes);
}

status_t cm_gbk_length_ignore_truncated_bytes(text_t *text)
{
    uint32 bytes;
    uint32 chars;
    if (cm_gbk_length_ignore(text, &chars, &bytes) != CT_SUCCESS) {
        return CT_ERROR;
    }

    text->len = text->len - bytes;
    return CT_SUCCESS;
}

status_t cm_gbk_substr(text_t *src, int32 start, uint32 size, text_t *dst)
{
    return cm_substr(src, start, size, dst, CHARSET_GBK);
}

status_t cm_gbk_substr_left(text_t *src, uint32 start, uint32 size, text_t *dst)
{
    return cm_substr_left(src, start, size, dst, CHARSET_GBK);
}

status_t cm_gbk_substr_right(text_t *src, uint32 start, uint32 size, text_t *dst, bool32 overflow_allowed)
{
    return cm_substr_right(src, start, size, dst, overflow_allowed, CHARSET_GBK);
}

uint32 cm_gbk_instr(const text_t *str, const text_t *substr, int32 pos, uint32 nth, bool32 *is_char)
{
    return cm_instr(str, substr, pos, nth, is_char, CHARSET_GBK);
}

status_t cm_gbk_get_start_byte_pos(const text_t *text, uint32 char_pos, uint32 *start)
{
    return cm_get_start_byte_pos(text, char_pos, start, CHARSET_GBK);
}

status_t cm_gbk_num_instr(const text_t *str, const text_t *substr, text_t *splitchar, uint32 *num)
{
    return cm_num_instr(str, substr, splitchar, num, CHARSET_GBK);
}

uint32 cm_gbk_max_bytes_per_char(void)
{
    // 2bytes: 0x8140~0xFEFE
    return 2;
}

status_t cm_gbk_multi_byte(text_t *src, text_t *dst)
{
    return cm_gbk_multi_byte_internal(src, dst);
}

status_t cm_gbk_single_byte(text_t *src, text_t *dst)
{
    return cm_gbk_single_byte_internal(src, dst);
}

status_t cm_gbk_to_unicode(uint8 *str, uint32 *strlen)
{
    int32 iRet;
    uint16 ucs2;
    char *pGbk = (char *)str;

    if (*strlen != 2) {
        return CT_ERROR;
    }

    iRet = gbk2ucs2(pGbk, *strlen, &ucs2);
    if (iRet < 0) {
        return CT_ERROR;
    }
   
    str[0] = (ucs2 >> 8) & 0xFF;
    str[1] = ucs2 & 0xFF;

    return CT_SUCCESS;
}

#ifdef __cplusplus
}
#endif