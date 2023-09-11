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
 * cm_string_utf8.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_string_utf8.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_charset.h"

#ifdef __cplusplus
extern "C" {
#endif

/* UTF8 charset */
int32 cm_utf8_chr_bytes(uint8 c, uint32 *bytes)
{
    uint8 chr = c;
    // 1 byte character
    if (chr < 0x80) {
        *bytes = 1;
        return GS_SUCCESS;
    }

    // 2-6 bytes character
    *bytes = 0;
    while (chr & 0x80) {
        (*bytes)++;
        chr <<= 1;
    }

    // begin with 10xxxxxx is invalid
    if (*bytes >= 2 && *bytes <= 6) {
        return GS_SUCCESS;
    } else {
        *bytes = 1;
        return GS_ERROR;
    }
}

static status_t cm_utf8_str_bytes_internal(const char *str, uint32 len, uint32 *bytes)
{
    uint32 i;

    if (cm_utf8_chr_bytes((uint8)*str, bytes) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (*bytes > len) {
        *bytes = len;
        return GS_ERROR;
    }

    // verify utf8 character
    for (i = 1; i < *bytes; i++) {
        if (!IS_VALID_UTF8_CHAR((uint8)*(str + i))) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t cm_utf8_length_internal(const text_t *text, uint32 *characters)
{
    uint32 pos, temp_bytes, temp_characters;

    pos = temp_characters = 0;

    while (pos < text->len) {
        if (cm_utf8_str_bytes_internal(text->str + pos, text->len - pos, &temp_bytes) != GS_SUCCESS) {
            GS_THROW_ERROR(ERR_NLS_INTERNAL_ERROR, "utf-8 buffer");
            return GS_ERROR;
        }

        pos += temp_bytes;
        temp_characters++;
    }

    if (pos != text->len) {
        GS_THROW_ERROR(ERR_NLS_INTERNAL_ERROR, "utf-8 buffer");
        return GS_ERROR;
    }

    *characters = temp_characters;
    return GS_SUCCESS;
}

static inline void cm_utf8_special_multi_byte(text_t *src, text_t *dst, uint32 *i, uint32 *j)
{
    switch (src->str[*i]) {
        case (ASCII_HALF_BLANK_SPACE): {
            // convert half-width blank space to full-width blank space(0xE38080)
            dst->str[*j] = 0xE3;
            dst->str[*j + 1] = 0x80;
            dst->str[*j + 2] = 0x80;
            dst->len += 2;
            *i += 1;
            *j += 3;
            break;
        }
        case (ASCII_HALF_DOUBLE_QUOTATION): {
            // convert half-width double quotation to full-width double quotation(0xE2809D)
            dst->str[*j] = 0xE2;
            dst->str[*j + 1] = 0x80;
            dst->str[*j + 2] = 0x9D;
            dst->len += 2;
            *i += 1;
            *j += 3;
            break;
        }
        case (ASCII_HALF_SINGLE_QUOTATION): {
            // convert half-width single quotation to full-width single quotation(0xE28099)
            dst->str[*j] = 0xE2;
            dst->str[*j + 1] = 0x80;
            dst->str[*j + 2] = 0x99;
            dst->len += 2;
            *i += 1;
            *j += 3;
            break;
        }
        case (ASCII_HALF_CARET): {
            // convert half-width caret to full-width caret(0xEFB8BF)
            dst->str[*j] = 0xEF;
            dst->str[*j + 1] = 0xB8;
            dst->str[*j + 2] = 0xBF;
            dst->len += 2;
            *i += 1;
            *j += 3;
            break;
        }
        case (ASCII_HALF_APOSTROPHE): {
            // convert half-width apostrophe to full-width apostrophe(0xE28098)
            dst->str[*j] = 0xE2;
            dst->str[*j + 1] = 0x80;
            dst->str[*j + 2] = 0x98;
            dst->len += 2;
            *i += 1;
            *j += 3;
            break;
        }
        case (ASCII_HALF_TILDE): {
            // convert half-width tilde to full-width tilde(0xE288BC)
            dst->str[*j] = 0xE2;
            dst->str[*j + 1] = 0x88;
            dst->str[*j + 2] = 0xBC;
            dst->len += 2;
            *i += 1;
            *j += 3;
            break;
        }
        default:
            break;
    }
}

static inline void cm_utf8_common_multi_byte(text_t *src, text_t *dst, uint32 *i, uint32 *j)
{
    // convert half-width character to full-width character(other ascii character)
    dst->str[*j] = 0xE0 | ((src->str[*i] + 65248) >> 12);
    dst->str[*j + 1] = 0x80 | (0x3F & ((src->str[*i] + 65248) >> 6));
    dst->str[*j + 2] = 0x80 | (0x3F & (src->str[*i] + 65248));
    dst->len += 2;
    *i += 1;
    *j += 3;
}

static inline status_t cm_utf8_other_character_multi_byte(text_t *src, text_t *dst, uint32 *i, uint32 *j)
{
    uint32 char_bytes;

    GS_RETURN_IFERR(cm_utf8_chr_bytes((uint8)src->str[*i], &char_bytes));
    while (char_bytes) {
        dst->str[*j] = src->str[*i];
        char_bytes -= 1;
        *i += 1;
        *j += 1;
    }

    return GS_SUCCESS;
}

static inline void cm_utf8_special_single_byte(text_t *src, text_t *dst, uint32 *i, uint32 *j)
{
    if (UTF8_FULL_BLANK_SPACE(src->str[*i], src->str[*i + 1], src->str[*i + 2])) {
        // convert full-width blank space to half-width blank space(0x20)
        dst->str[*j] = 0x20;
        dst->len -= 2;
        *i += 3;
        *j += 1;
    } else if (UTF8_FULL_DOUBLE_QUOTATION(src->str[*i], src->str[*i + 1], src->str[*i + 2])) {
        // convert full-width double quotation to half-width double quotation(0x22)
        dst->str[*j] = 0x22;
        dst->len -= 2;
        *i += 3;
        *j += 1;
    } else if (UTF8_FULL_SINGLE_QUOTATION(src->str[*i], src->str[*i + 1], src->str[*i + 2])) {
        // convert full-width single quotation to half-width single quotation(0x27)
        dst->str[*j] = 0x27;
        dst->len -= 2;
        *i += 3;
        *j += 1;
    } else if (UTF8_FULL_CARET(src->str[*i], src->str[*i + 1], src->str[*i + 2])) {
        // convert full-width caret to half-width caret(0x5E)
        dst->str[*j] = 0x5E;
        dst->len -= 2;
        *i += 3;
        *j += 1;
    } else if (UTF8_FULL_APOSTROPHE(src->str[*i], src->str[*i + 1], src->str[*i + 2])) {
        // convert full-width apostrophe to half-width apostrophe(0x60)
        dst->str[*j] = 0x60;
        dst->len -= 2;
        *i += 3;
        *j += 1;
    } else if (UTF8_FULL_TILDE(src->str[*i], src->str[*i + 1], src->str[*i + 2])) {
        // convert full-width tilde to half-width tilde(0x7E)
        dst->str[*j] = 0x7E;
        dst->len -= 2;
        *i += 3;
        *j += 1;
    }
}

static inline void cm_utf8_common_single_byte(text_t *src, text_t *dst, uint32 *i, uint32 *j)
{
    // convert full-width character to half-width character(other ascii character)
    dst->str[*j] = (int8)(((uint16)(src->str[*i] & 0x0F) << 12) +
        ((uint16)(src->str[*i + 1] & 0x3F) << 6) + (uint16)(src->str[*i + 2] & 0x3F) - 65248);
    dst->len -= 2;
    *i += 3;
    *j += 1;
}

static inline status_t cm_utf8_other_character_single_byte(text_t *src, text_t *dst, uint32 *i, uint32 *j)
{
    uint32 char_bytes;

    GS_RETURN_IFERR(cm_utf8_chr_bytes((uint8)src->str[*i], &char_bytes));
    while (char_bytes) {
        dst->str[*j] = src->str[*i];
        char_bytes -= 1;
        *i += 1;
        *j += 1;
    }

    return GS_SUCCESS;
}

static status_t cm_utf8_multi_byte_internal(text_t *src, text_t *dst)
{
    uint32 i, j;

    i = j = 0;
    dst->len = src->len;

    while (i < src->len) {
        if (IS_UTF8_SPECIAL_HALF_CHARACTER(src->str[i])) {
            // for special character
            cm_utf8_special_multi_byte(src, dst, &i, &j);
        } else if (UTF8_HALF_OTHER(src->str[i])) {
            // for common ascii character
            cm_utf8_common_multi_byte(src, dst, &i, &j);
        } else {
            // for other character
            GS_RETURN_IFERR(cm_utf8_other_character_multi_byte(src, dst, &i, &j));
        }
    }

    return GS_SUCCESS;
}

static status_t cm_utf8_single_byte_internal(text_t *src, text_t *dst)
{
    uint32 i, j;

    i = j = 0;
    dst->len = src->len;

    while (i < src->len) {
        if ((src->len - i >= 3) && IS_UTF8_SPECIAL_FULL_CHARACTER(src->str[i], src->str[i + 1], src->str[i + 2])) {
            // for special character
            cm_utf8_special_single_byte(src, dst, &i, &j);
        } else if ((src->len - i >= 3) &&
            (UTF8_FULL_OTHER_1(src->str[i], src->str[i + 1], src->str[i + 2]) ||
             UTF8_FULL_OTHER_2(src->str[i], src->str[i + 1], src->str[i + 2]))) {
            // for common ascii character
            cm_utf8_common_single_byte(src, dst, &i, &j);
        } else {
            // for other character
            GS_RETURN_IFERR(cm_utf8_other_character_single_byte(src, dst, &i, &j));
        }
    }

    return GS_SUCCESS;
}

static inline status_t cm_utf8_str_bytes_ignore(const char *str, uint32 len, uint32 *bytes)
{
    uint32 i, check_len;

    if (cm_utf8_chr_bytes((uint8)*str, bytes) != GS_SUCCESS) {
        return GS_ERROR;
    }

    // verify utf8 character
    check_len = MIN(*bytes, len);
    for (i = 1; i < check_len; i++) {
        if (!IS_VALID_UTF8_CHAR((uint8)*(str + i))) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t cm_utf8_length_ignore_internal(const text_t *text, uint32 *characters, uint32 *ignore_bytes)
{
    uint32 pos, temp_bytes, temp_characters;

    pos = temp_characters = 0;

    while (pos < text->len) {
        if (cm_utf8_str_bytes_ignore(text->str + pos, text->len - pos, &temp_bytes) != GS_SUCCESS) {
            GS_THROW_ERROR(ERR_NLS_INTERNAL_ERROR, "utf-8 buffer");
            return GS_ERROR;
        }
        
        pos += temp_bytes;
        temp_characters++;
    }

    *characters = temp_characters;
    *ignore_bytes = pos - text->len;
    return GS_SUCCESS;
}

static status_t cm_utf8_length_ignore_truncated_bytes_internal(text_t *text)
{
    uint32 len = text->len;
    uint32 utf8_bytes = 0;
    uint32 ignore_bytes = 0;
    status_t ret;

    while (len > 0 && ignore_bytes <= CM_CHARSET_FUNC(CHARSET_UTF8).max_bytes_per_char()) {
        ignore_bytes++;

        ret = cm_utf8_chr_bytes((uint8)(*(text->str + len - 1)), &utf8_bytes);
        if (ret != GS_SUCCESS) {
            len--;
            continue;
        }

        if (ignore_bytes != utf8_bytes) {
            /* ignore the last invalid utf8 character */
            text->len -= ignore_bytes;
        }

        return GS_SUCCESS;
    }

    GS_THROW_ERROR(ERR_NLS_INTERNAL_ERROR, "utf8 buffer");
    return GS_ERROR;
}

char *cm_utf8_move_char_forward(const char *str, uint32 str_len)
{
    uint32 chlen = 0;
    if (cm_utf8_str_bytes(str, str_len, &chlen) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_GENERIC_INTERNAL_ERROR, "invalid utf-8 buffer");
        return NULL;
    }

    return (char *)(str + chlen);
}

char *cm_utf8_move_char_backward(char *str, const char *head)
{
    char *c = str - 1;
    uint32 chnum = 0;

    if ((uint8)(*c) < 0x80) {
        return c;
    }

    while (IS_VALID_UTF8_CHAR((uint8)(*c)) && (c > head)) {
        --c;
    }

    if ((cm_utf8_chr_bytes(*c, &chnum) == GS_SUCCESS) && (chnum == str - c)) {
        return c;
    }
    GS_THROW_ERROR(ERR_GENERIC_INTERNAL_ERROR, "invalid utf-8 buffer");
    return NULL;
}

char *cm_utf8_name(void)
{
    return "UTF-8";
}

bool8 cm_utf8_has_multibyte(const char *str, uint32 len)
{
    uint32 i;
    uint8 *ptr = (uint8 *)str;

    for (i = 0; i < len; i++) {
        if (ptr[i] & 0x80) {
            return GS_TRUE;
        }
    }

    return GS_FALSE;
}

status_t cm_utf8_str_bytes(const char *str, uint32 len, uint32 *bytes)
{
    return cm_utf8_str_bytes_internal(str, len, bytes);
}

status_t cm_utf8_reverse_str_bytes(const char *str, uint32 len, uint32 *bytes)
{
    const char* cur_c = str;

    // 1 byte character
    if (CM_IS_ASCII(*cur_c)) {
        *bytes = 1;
        return GS_SUCCESS;
    }

    // 2-6 bytes character
    *bytes = 1;
    while ((*bytes < len) && IS_VALID_UTF8_CHAR(*cur_c)) {
        (*bytes)++;
        cur_c -= 1;
    }

    return (*bytes >= 2 && *bytes <= 6 && *bytes < len) ? GS_SUCCESS : GS_ERROR;
}

bool8 cm_utf8_text_like(const text_t *text1, const text_t *text2)
{
    return (bool8)cm_text_like(text1, text2, CHARSET_UTF8);
}

status_t cm_utf8_text_like_escape(char *str, const char *str_end, char *wildstr,
    const char *wildend, char escape, int32 *cmp_ret)
{
    return cm_text_like_escape(str, str_end, wildstr, wildend, escape, cmp_ret, CHARSET_UTF8);
}

status_t cm_utf8_length(const text_t *text, uint32 *characters)
{
    return cm_utf8_length_internal(text, characters);
}

/*
  len - character num of text
  ignore_bytes - text may be incomplete, ignore last several bytes to make up a complete utf8 character
*/
status_t cm_utf8_length_ignore(const text_t *text, uint32 *characters, uint32 *ignore_bytes)
{
    return cm_utf8_length_ignore_internal(text, characters, ignore_bytes);
}

status_t cm_utf8_length_ignore_truncated_bytes(text_t *text)
{
    return cm_utf8_length_ignore_truncated_bytes_internal(text);
}

status_t cm_utf8_substr(text_t *src, int32 start, uint32 size, text_t *dst)
{
    return cm_substr(src, start, size, dst, CHARSET_UTF8);
}

status_t cm_utf8_substr_left(text_t *src, uint32 start, uint32 size, text_t *dst)
{
    return cm_substr_left(src, start, size, dst, CHARSET_UTF8);
}

status_t cm_utf8_substr_right(text_t *src, uint32 start, uint32 size, text_t *dst, bool32 overflow_allowed)
{
    return cm_substr_right(src, start, size, dst, overflow_allowed, CHARSET_UTF8);
}

uint32 cm_utf8_instr(const text_t *str, const text_t *substr, int32 pos, uint32 nth, bool32 *is_char)
{
    return cm_instr(str, substr, pos, nth, is_char, CHARSET_UTF8);
}

status_t cm_utf8_get_start_byte_pos(const text_t *text, uint32 char_pos, uint32 *start)
{
    return cm_get_start_byte_pos(text, char_pos, start, CHARSET_UTF8);
}

status_t cm_utf8_num_instr(const text_t *str, const text_t *substr, text_t *splitchar, uint32 *num)
{
    return cm_num_instr(str, substr, splitchar, num, CHARSET_UTF8);
}

uint32 cm_utf8_max_bytes_per_char(void)
{
    // 6bytes: 1111110x 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx
    return 6;
}

status_t cm_utf8_multi_byte(text_t *src, text_t *dst)
{
    return cm_utf8_multi_byte_internal(src, dst);
}

status_t cm_utf8_single_byte(text_t *src, text_t *dst)
{
    return cm_utf8_single_byte_internal(src, dst);
}

bool32 cm_utf8_str_like(const char *str1, const char *str2)
{
    text_t text1, text2;
    cm_str2text((char *)str1, &text1);
    cm_str2text((char *)str2, &text2);
    return cm_text_like(&text1, &text2, CHARSET_UTF8);
}

status_t cm_utf8_to_unicode(uint8 *str, uint32 *strlen)
{
    uint32 pos = 1;
    if (*strlen < 2 || *strlen > 6) {
        return GS_ERROR;
    }
    uint8 tmp[6];
    for (uint32 i = 0; i < *strlen; i++) {
        tmp[i] = *(str + i);
    }
    switch (*strlen) {
        // 110xxxxx 10xxxxxx
        case 2:
            str[0] = (tmp[0] & 0x1F) >> 2;
            str[1] = ((tmp[0] & 0x1F) << 6) + (tmp[1] & 0x3F);
            pos = 2;
            break;
        // 1110xxxx 10xxxxxx 10xxxxxx
        case 3:
            str[0] = ((tmp[0] & 0x0F) << 4) + ((tmp[1] & 0x3F) >> 2);
            str[1] = ((tmp[1] & 0x3F) << 6) + (tmp[2] & 0x3F);
            pos = 2;
            break;
        // 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
        case 4:
            str[0] = ((tmp[0] & 0x07) << 2) + ((tmp[1] & 0x3F) >> 4);
            str[1] = ((tmp[1] & 0x3F) << 4) + ((tmp[2] & 0x3F) >> 2);
            str[2] = ((tmp[2] & 0x3F) << 6) + (tmp[3] & 0x3F);
            pos = 3;
            break;
        // 111110xx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx
        case 5:
            str[0] = tmp[0] & 0x03;
            str[1] = ((tmp[1] & 0x3F) << 2) + ((tmp[2] & 0x3F) >> 4);
            str[2] = ((tmp[2] & 0x3F) << 4) + ((tmp[3] & 0x3F) >> 2);
            str[3] = ((tmp[3] & 0x3F) << 6) + (tmp[4] & 0x3F);
            pos = 4;
            break;
        // 1111110x 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx
        case 6:
            str[0] = ((tmp[0] & 0x03) << 6) + (tmp[1] & 0x3F);
            str[1] = ((tmp[2] & 0x3F) << 2) + ((tmp[3] & 0x3F) >> 4);
            str[2] = ((tmp[3] & 0x3F) << 4) + ((tmp[4] & 0x3F) >> 2);
            str[3] = ((tmp[4] & 0x3F) << 6) + (tmp[5] & 0x3F);
            pos = 4;
            break;
        default:
            break;
    }
    *strlen = pos;
    return GS_SUCCESS;
}

#ifdef __cplusplus
}
#endif