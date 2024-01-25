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
 * cm_string_common.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_string_common.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __CM_STRING_COMMON_H__
#define __CM_STRING_COMMON_H__

#ifdef __cplusplus
extern "C" {
#endif

#define isgbkhead(c) (0x81 <= (uchar)(c) && (uchar)(c) <= 0xfe)
#define isgbktail(c) ((0x40 <= (uchar)(c) && (uchar)(c) <= 0x7e) || (0x80 <= (uchar)(c) && (uchar)(c) <= 0xfe))
#define isgbkcode(c, d) (isgbkhead(c) && isgbktail(d))
#define gbkcode(c, d) ((((uint)(uchar)(c)) << 8) | (uchar)(d))
#define gbkhead(e) ((uchar)((e) >> 8))
#define gbktail(e) ((uchar)((e) & 0xff))

uint cm_ismbchar_utf8mb4(const CHARSET_COLLATION *cs, const char *b, const char *e);
uint cm_ismbchar_gbk(const CHARSET_COLLATION *cs, const char *b, const char *e);
uint cm_ismbchar_utf8(const CHARSET_COLLATION *cs, const char *b, const char *e);
size_t cm_numchars_mb(const CHARSET_COLLATION *cs, const char *b, const char *e);
size_t cm_numchars_8bit(const CHARSET_COLLATION *cs, const char *b, const char *e);
int32 cm_simple_compare_collsp(const CHARSET_COLLATION *cs, text_t *text1, text_t *text2);
int32 cm_8bit_bin_compare_collsp(const CHARSET_COLLATION *cs, text_t *text1, text_t *text2);
int32 cm_gbk_compare_collsp(const CHARSET_COLLATION *cs, text_t *text1, text_t *text2);
int32 cm_mb_bin_compare_collsp(const CHARSET_COLLATION *cs, text_t *text1, text_t *text2);
int32 cm_utf8_compare_collsp(const CHARSET_COLLATION *cs, text_t *text1, text_t *text2);

extern const uchar sort_order_latin1_general_ci[256];
extern const uchar sort_order_latin1_general_cs[256];
extern const uchar sort_order_latin1[256];
extern const uchar sort_order_ascii_general_ci[256];
extern const uchar to_lower_ascii_bin[256];
extern const uchar to_upper_ascii_bin[256];
extern const uchar sort_order_gbk[256];
extern const uint16 gbk_order[];


#ifdef __cplusplus
}
#endif

#endif