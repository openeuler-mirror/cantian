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
 * cm_string_gbk.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_string_gbk.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_STRING_GBK_H__
#define __CM_STRING_GBK_H__

#ifdef __cplusplus
extern "C" {
#endif

/* GBK format
1byte : 0xxxxxxx
2bytes: 0x8140~0xFEFE
*/
#define IS_VALID_GBK_START_BYTE(c) (((uint8)(c) >= 0x81) && ((uint8)(c) <= 0xFE))
#define IS_VALID_GBK_CHAR(c) (((uint8)(c) >= 0x40) && ((uint8)(c) <= 0xFE))
#define IS_GBK_SPECIAL_HALF_CHARACTER(a) (((a) == 0x20) || ((a) == 0x22) || ((a) == 0x24) || ((a) == 0x27) || \
                                          ((a) == 0x5E) || ((a) == 0x60) || ((a) == 0x7E))
#define IS_GBK_SPECIAL_FULL_CHARACTER(a, b) (GBK_FULL_BLANK_SPACE(a, b) || GBK_FULL_DOUBLE_QUOTATION(a, b) || \
                                            GBK_FULL_SINGLE_QUOTATION(a, b) || GBK_FULL_DOLLAR(a, b) || \
                                            GBK_FULL_CARET(a, b) || GBK_FULL_APOSTROPHE(a, b) || GBK_FULL_TILDE(a, b))
#define GBK_FULL_BLANK_SPACE(a, b)    (((a) & 0xFF) == 0xA1 && ((b) & 0xFF) == 0xA1)    // 0xA1A1
#define GBK_FULL_DOUBLE_QUOTATION(a, b)    (((a) & 0xFF) == 0xA1 && ((b) & 0xFF) == 0xB1)    // 0xA1B1
#define GBK_FULL_SINGLE_QUOTATION(a, b)    (((a) & 0xFF) == 0xA1 && ((b) & 0xFF) == 0xAF)    // 0xA1AF
#define GBK_FULL_DOLLAR(a, b)    (((a) & 0xFF) == 0xA1 && ((b) & 0xFF) == 0xE7)    // 0xA1E7
#define GBK_FULL_CARET(a, b)    (((a) & 0xFF) == 0xA6 && ((b) & 0xFF) == 0xE4)    // 0xA6E4
#define GBK_FULL_APOSTROPHE(a, b)    (((a) & 0xFF) == 0xA1 && ((b) & 0xFF) == 0xAE)    // 0xA1AE
#define GBK_FULL_TILDE(a, b)    (((a) & 0xFF) == 0xA1 && ((b) & 0xFF) == 0xAB)    // 0xA1AB
#define GBK_FULL_OTHER(a, b)    (((a) & 0xFF) == 0xA3 && ((((b) & 0xFF) == 0xA1) || (((b) & 0xFF) == 0xA3) || \
                                (((b) & 0xFF) >= 0xA5 && ((b) & 0xFF) <= 0xA6) || \
                                (((b) & 0xFF) >= 0xA8 && ((b) & 0xFF) <= 0xDD) || \
                                (((b) & 0xFF) == 0xDF) || (((b) & 0xFF) >= 0xE1 && ((b) & 0xFF) <= 0xFD)))
#define GBK_HALF_OTHER(a)    (((a) == 0x21) || ((a) == 0x23) || ((a) >= 0x25 && (a) <= 0x26) || \
                                ((a) >= 0x28 && (a) <= 0x5D) || ((a) == 0x5F) || ((a) >= 0x61 && (a) <= 0x7D))

/* GBK charset */
char *cm_gbk_move_char_forward(const char *str, uint32 str_len);
char *cm_gbk_move_char_backward(char *str, const char *head);
char *cm_gbk_name(void);
bool8 cm_gbk_has_multibyte(const char *str, uint32 len);
status_t cm_gbk_str_bytes(const char *str, uint32 len, uint32 *bytes);
status_t cm_gbk_to_unicode(uint8 *str, uint32 *strlen);

status_t cm_gbk_reverse_str_bytes(const char *str, uint32 len, uint32 *bytes);

bool8 cm_gbk_text_like(const text_t *text1, const text_t *text2);
status_t cm_gbk_text_like_escape(char *str, const char *str_end, char *wildstr,
    const char *wildend, char escape, int32 *cmp_ret);
status_t cm_gbk_length(const text_t *text, uint32 *characters);
status_t cm_gbk_length_ignore(const text_t *text, uint32 *characters, uint32 *ignore_bytes);
status_t cm_gbk_length_ignore_truncated_bytes(text_t *text);
status_t cm_gbk_substr(text_t *src, int32 start, uint32 size, text_t *dst);
status_t cm_gbk_substr_left(text_t *src, uint32 start, uint32 size, text_t *dst);
status_t cm_gbk_substr_right(text_t *src, uint32 start, uint32 size, text_t *dst, bool32 overflow_allowed);
uint32 cm_gbk_instr(const text_t *str, const text_t *substr, int32 pos, uint32 nth, bool32 *is_char);
status_t cm_gbk_get_start_byte_pos(const text_t *text, uint32 char_pos, uint32 *start);
status_t cm_gbk_num_instr(const text_t *str, const text_t *substr, text_t *splitchar, uint32 *num);
uint32 cm_gbk_max_bytes_per_char(void);
status_t cm_gbk_multi_byte(text_t *src, text_t *dst);
status_t cm_gbk_single_byte(text_t *src, text_t *dst);

#ifdef __cplusplus
}
#endif

#endif
