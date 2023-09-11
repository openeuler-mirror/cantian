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
 * cm_string_utf8.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_string_utf8.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_STRING_UTF8_H__
#define __CM_STRING_UTF8_H__

#ifdef __cplusplus
extern "C" {
#endif

/* UTF8 format
1byte : 0xxxxxxx
2bytes: 110xxxxx 10xxxxxx
3bytes: 1110xxxx 10xxxxxx 10xxxxxx
4bytes: 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
5bytes: 111110xx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx
6bytes: 1111110x 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx
*/
#define IS_VALID_UTF8_CHAR(c) (((c) & 0xC0) == 0x80)  // 10xxxxxx
#define IS_UTF8_SPECIAL_HALF_CHARACTER(a)   (((a) == 0x20) || ((a) == 0x22) || ((a) == 0x27) || \
                                             ((a) == 0x5E) || ((a) == 0x60) || ((a) == 0x7E))
#define IS_UTF8_SPECIAL_FULL_CHARACTER(a, b, c) (UTF8_FULL_BLANK_SPACE((a), (b), (c)) || \
                                               UTF8_FULL_DOUBLE_QUOTATION((a), (b), (c)) || \
                                               UTF8_FULL_SINGLE_QUOTATION((a), (b), (c)) || \
                                               UTF8_FULL_CARET((a), (b), (c)) || \
                                               UTF8_FULL_APOSTROPHE((a), (b), (c)) || UTF8_FULL_TILDE((a), (b), (c)))
#define UTF8_FULL_BLANK_SPACE(a, b, c)   (((a) & 0xFF) == 0xE3 && ((b) & 0xFF) == 0x80 && ((c) & 0xFF) == 0x80)  // 0xE38080
#define UTF8_FULL_DOUBLE_QUOTATION(a, b, c)   (((a) & 0xFF) == 0xE2 && ((b) & 0xFF) == 0x80 && ((c) & 0xFF) == 0x9D) // 0xE2809D
#define UTF8_FULL_SINGLE_QUOTATION(a, b, c)   (((a) & 0xFF) == 0xE2 && ((b) & 0xFF) == 0x80 && ((c) & 0xFF) == 0x99) // 0xE28099
#define UTF8_FULL_CARET(a, b, c)    (((a) & 0xFF) == 0xEF && ((b) & 0xFF) == 0xB8 && ((c) & 0xFF) == 0xBF)    // 0xEFB8BF
#define UTF8_FULL_APOSTROPHE(a, b, c)    (((a) & 0xFF) == 0xE2 && ((b) & 0xFF) == 0x80 && ((c) & 0xFF) == 0x98)  // 0xE28098
#define UTF8_FULL_TILDE(a, b, c)    (((a) & 0xFF) == 0xE2 && ((b) & 0xFF) == 0x88 && ((c) & 0xFF) == 0xBC)    // 0xE288BC
#define UTF8_FULL_OTHER_1(a, b, c)   ((((a) & 0xFF) == 0xEF) && (((b) & 0xFF) == 0xBC) && \
                              ((((c) & 0xFF) == 0x81) || (((c) & 0xFF) == 0xBF) || \
                               (((c) & 0xFF) >= 0x83 && ((c) & 0xFF) <= 0x86) || \
                               (((c) & 0xFF) >= 0x88 && ((c) & 0xFF) <= 0xBD)))
#define UTF8_FULL_OTHER_2(a, b, c)   ((((a) & 0xFF) == 0xEF) && (((b) & 0xFF) == 0xBD) && \
                              (((c) & 0xFF) >= 0x81 && ((c) & 0xFF) <= 0x9D))
#define UTF8_HALF_OTHER(a)    (((a) == 0x21) || ((a) >= 0x23 && (a) <= 0x26) || ((a) >= 0x28 && (a) <= 0x5D) || \
                                 ((a) == 0x5F) || ((a) >= 0x61 && (a) <= 0x7D))

/* UTF8 charset */
char *cm_utf8_move_char_forward(const char *str, uint32 str_len);
char *cm_utf8_move_char_backward(char *str, const char *head);
char *cm_utf8_name(void);
bool8 cm_utf8_has_multibyte(const char *str, uint32 len);
status_t cm_utf8_str_bytes(const char *str, uint32 len, uint32 *bytes);
status_t cm_utf8_to_unicode(uint8 *str, uint32 *strlen);
int32 cm_utf8_chr_bytes(uint8 c, uint32 *bytes);
status_t cm_utf8_reverse_str_bytes(const char *str, uint32 len, uint32 *bytes);

bool8 cm_utf8_text_like(const text_t *text1, const text_t *text2);
status_t cm_utf8_text_like_escape(char *str, const char *str_end, char *wildstr,
    const char *wildend, char escape, int32 *cmp_ret);
status_t cm_utf8_length(const text_t *text, uint32 *characters);
status_t cm_utf8_length_ignore(const text_t *text, uint32 *characters, uint32 *ignore_bytes);
status_t cm_utf8_length_ignore_truncated_bytes(text_t *text);
status_t cm_utf8_substr(text_t *src, int32 start, uint32 size, text_t *dst);
status_t cm_utf8_substr_left(text_t *src, uint32 start, uint32 size, text_t *dst);
status_t cm_utf8_substr_right(text_t *src, uint32 start, uint32 size, text_t *dst, bool32 overflow_allowed);
uint32 cm_utf8_instr(const text_t *str, const text_t *substr, int32 pos, uint32 nth, bool32 *is_char);
status_t cm_utf8_get_start_byte_pos(const text_t *text, uint32 char_pos, uint32 *start);
status_t cm_utf8_num_instr(const text_t *str, const text_t *substr, text_t *splitchar, uint32 *num);
uint32 cm_utf8_max_bytes_per_char(void);
status_t cm_utf8_multi_byte(text_t *src, text_t *dst);
status_t cm_utf8_single_byte(text_t *src, text_t *dst);

bool32 cm_utf8_str_like(const char *str1, const char *str2);

#ifdef __cplusplus
}
#endif

#endif