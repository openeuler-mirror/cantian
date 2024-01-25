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
 * cm_charset.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_charset.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_CHARSET_H__
#define __CM_CHARSET_H__

#include "cm_defs.h"
#include "cm_text.h"
#include "cm_iconv.h"
#include "cm_string_gbk.h"
#include "cm_string_utf8.h"
#include "cm_string_uca.h"
#include "cm_string_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define UCA_MAX_CHAR_GRP 4
#define CM_CS_COMPILED (1 << 0)
#define CM_CS_CONFIG (1 << 1)
#define CM_CS_INDEX (1 << 2)
#define CM_CS_LOADED (1 << 3)
#define CM_CS_BINSORT (1 << 4)
#define CM_CS_PRIMARY (1 << 5)
#define CM_CS_STRNXFRM (1 << 6)
#define CM_CS_UNICODE (1 << 7)
#define CM_CS_READY (1 << 8)
#define CM_CS_AVAILABLE (1 << 9)
#define CM_CS_CSSORT (1 << 10)
#define CM_CS_HIDDEN (1 << 11)
#define CM_CS_PUREASCII (1 << 12)
#define CM_CS_NONASCII (1 << 13)
#define CM_CS_UNICODE_SUPPLEMENT (1 << 14)
#define CM_CS_LOWER_SORT (1 << 15)
#define CM_CHARSET_UNDEFINED 0

#define CM_CS_UTF8MB4_UCA_FLAGS \
        (CM_CS_COMPILED | CM_CS_STRNXFRM | CM_CS_UNICODE | CM_CS_UNICODE_SUPPLEMENT)

typedef enum st_charset_type {
    CHARSET_UTF8 = 0,
    CHARSET_GBK,
    CHARSET_UTF8MB4,
    CHARSET_BINARY,
    CHARSET_LATIN1,
    CHARSET_ASCII,
    CHARSET_MAX,
} charset_type_t;

/* defines the available code page identifiers */
#define CODE_PAGE_GB2312    (uint32)936     // ANSI/OEM Simplified Chinese (PRC, Singapore); Chinese Simplified (GB2312)
#define CODE_PAGE_GB18030   (uint32)54936   // Windows XP and later: GB18030 Simplified Chinese (4 byte); Chinese Simplified (GB18030)
#define CODE_PAGE_UTF8      (uint32)65001   // Unicode (UTF-8)

typedef enum st_collation_type {
    COLLATE_UTF8_BIN = 0,
    COLLATE_UTF8_GENERAL_CI,
    COLLATE_UTF8_UNICODE_CI,
    COLLATE_GBK_BIN,
    COLLATE_GBK_CHINESE_CI,
    COLLATE_UTF8MB4_GENERAL_CI,
    COLLATE_UTF8MB4_BIN,
    COLLATE_BINARY,
    COLLATE_UTF8MB4_0900_AI_CI,
    COLLATE_UTF8MB4_0900_BIN,
    COLLATE_LATIN1_GENERAL_CI,
    COLLATE_LATIN1_GENERAL_CS,
    COLLATE_LATIN1_BIN,
    COLLATE_ASCII_GENERAL_CI,
    COLLATE_ASCII_BIN,
    COLLATE_UTF8MB3_GENERAL_CI,
    COLLATE_UTF8MB3_BIN,
    COLLATE_UTF8_TOLOWER_CI,
    COLLATE_SWEDISH_CI = 255,
    COLLATE_MAX,
} collation_type_t;

typedef enum st_ascii_half_type {
    ASCII_HALF_BLANK_SPACE = 0x20,
    ASCII_HALF_DOUBLE_QUOTATION = 0x22,
    ASCII_HALF_DOLLAR = 0x24,
    ASCII_HALF_SINGLE_QUOTATION = 0x27,
    ASCII_HALF_CARET = 0x5E,
    ASCII_HALF_APOSTROPHE = 0x60,
    ASCII_HALF_TILDE = 0x7E,
} ascii_half_type_t;

typedef ulong cm_wc_t;

typedef uint16 (*charset_find_code_proc)(uint8 *code, uint32 *len);
typedef int32 (*transcode_func_t)(const void *src, uint32 *src_len, void *dst, uint32 dst_len, bool32 *eof);

typedef struct st_charset {
    charset_type_t id;
    char name[CT_NAME_BUFFER_SIZE];
    char *codes;
    charset_find_code_proc find_code;
    uint32 max_size; // max length of multibyte
    uint32 cp_id;    // code page for convert between widechar and multibyte
} charset_t;

typedef struct st_collation {
    collation_type_t id;
    char name[CT_NAME_BUFFER_SIZE];
} collation_t;

typedef struct st_charset_coll {
    collation_type_t id;
    CHARSET_COLLATION *cs;
    bool32 is_sensitive;
} charset_coll_t;

status_t cm_get_charset(const char *name, charset_t **charset);
status_t cm_get_charset_ex(text_t *name, charset_t **charset);

uint16 cm_get_charset_id(const char *name);
uint16 cm_get_charset_id_ex(text_t *name);

uint16 cm_get_collation_id(text_t *name);
status_t cm_get_collation(text_t *name, collation_t **collation);

const char *cm_get_charset_name(charset_type_t id);
uint32 cm_get_cp_id(charset_type_t id);
uint32 cm_get_max_size(charset_type_t id);

transcode_func_t cm_get_transcode_func(uint16 src_id, uint16 dst_id);
transcode_func_t cm_get_transcode_func_ucs2(uint16 src_id);
transcode_func_t cm_from_transcode_func_ucs2(uint16 src_id);
status_t cm_get_transcode_length(const text_t *src_text, uint16 src_id, uint16 dst_id, uint32 *dst_length);
status_t cm_transcode(uint16 src_id, uint16 dst_id, void *src, uint32 *src_len, void *dst, uint32 *dst_len,
                      bool8 force);

bool32 cm_text_like(const text_t *text1, const text_t *text2, charset_type_t type);
bool32 cm_text_like_ins(const text_t *text1, const text_t *text2, charset_type_t type);
int32 cm_in_like_ins(const char *str1, uint32 len1, const char *str2, uint32 len2, uint32 *match_len1,
                     charset_type_t type);
status_t cm_text_like_escape(char *str, const char *str_end, char *wildstr, const char *wildend, char escape,
                             int32 *cmp_ret, charset_type_t type);
status_t cm_text_like_escape_ins(char *str, const char *str_end, char *wildstr, const char *wildend, char escape,
                                 int32 *cmp_ret, charset_type_t type);
status_t cm_substr_left(text_t *src, uint32 start, uint32 size, text_t *dst, charset_type_t type);
status_t cm_substr_right(text_t *src, uint32 start, uint32 size, text_t *dst, bool32 overflow_allowed,
                         charset_type_t type);
status_t cm_substr(text_t *src, int32 start_input, uint32 size, text_t *dst, charset_type_t type);
status_t cm_get_start_byte_pos(const text_t *text, uint32 char_pos, uint32 *start, charset_type_t charset);
uint32 cm_instr(const text_t *str, const text_t *substr, int32 pos, uint32 nth, bool32 *is_char, charset_type_t type);
status_t cm_num_instr(const text_t *str, const text_t *substr, text_t *splitchar, uint32 *num, charset_type_t type);

uint32 cm_instr_core(const text_t *str, const text_t *substr, int32 pos, uint32 nth, uint32 start);
CHARSET_COLLATION *cm_get_charset_coll(uint32 collate_id);
bool32 cm_is_collate_sensitive(uint32 collate_id);

typedef char* (*charset_move_char_forward)(const char *str, uint32 str_len);
typedef char* (*charset_move_char_backward)(char *str, const char *head);
typedef char* (*charset_name_t)(void);
typedef bool8(*cm_has_multibyte_t)(const char *str, uint32 len);
typedef status_t(*cm_str_bytes_t)(const char *str, uint32 len, uint32 *bytes);
typedef status_t(*cm_str_unicode_t)(uint8 *str, uint32 *strlen);
typedef status_t(*cm_reverse_str_bytes_t)(const char *str, uint32 len, uint32 *bytes);
typedef bool8(*cm_text_like_t)(const text_t *text1, const text_t *text2);
typedef status_t(*cm_text_like_escape_t)(char *str, const char *str_end, char *wildstr,
    const char *wildend, char escape, int32 *cmp_ret);
typedef status_t(*cm_length_t)(const text_t *text, uint32 *characters);
typedef status_t(*cm_length_ignore_t)(const text_t *text, uint32 *characters, uint32 *ignore_bytes);
typedef status_t (*cm_length_ignore_truncated_bytes_t)(text_t *text);
typedef status_t(*cm_substr_t)(text_t *src, int32 start, uint32 size, text_t *dst);
typedef status_t(*cm_substr_left_t)(text_t *src, uint32 start, uint32 size, text_t *dst);
typedef status_t(*cm_substr_right_t)(text_t *src, uint32 start, uint32 size, text_t *dst, bool32 overflow_allowed);
typedef uint32(*cm_instr_t)(const text_t *str, const text_t *substr, int32 pos, uint32 nth, bool32 *is_char);
typedef status_t(*cm_get_start_byte_pos_t)(const text_t *text, uint32 char_pos, uint32 *start);
typedef status_t(*cm_num_instr_t)(const text_t *str, const text_t *substr, text_t *splitchar, uint32 *num);
typedef uint32(*cm_max_bytes_per_char_t)(void);
typedef status_t(*cm_multi_byte_t)(text_t *src, text_t *dst);
typedef status_t(*cm_single_byte_t)(text_t *src, text_t *dst);

typedef struct {
    charset_move_char_forward move_char_forward;
    charset_move_char_backward move_char_backward;
    charset_name_t name;
    cm_has_multibyte_t has_multibyte;
    cm_str_bytes_t str_bytes;
    cm_str_unicode_t str_unicode;
    cm_reverse_str_bytes_t reverse_str_bytes;
    cm_text_like_t like;
    cm_text_like_escape_t escape_like;
    cm_length_t length;
    cm_length_ignore_t  length_ignore;
    cm_length_ignore_truncated_bytes_t length_ignore_truncated_bytes;
    cm_substr_t substr;
    cm_substr_left_t substr_left;
    cm_substr_right_t substr_right;
    cm_instr_t instr;
    cm_get_start_byte_pos_t get_start_byte_pos;
    cm_num_instr_t num_instr;
    cm_max_bytes_per_char_t max_bytes_per_char;
    cm_multi_byte_t     multi_byte;
    cm_single_byte_t    single_byte;
} charset_func_t;

typedef struct CM_UNI_IDX {
    uint16 from;
    uint16 to;
    const uchar *tab;
} CM_UNI_IDX;

typedef enum pad_attribute_t {
    PAD_SPACE,
    NO_PAD
} pad_attribute_t;

typedef size_t (*cm_charset_conv_case)(const CHARSET_COLLATION *, const text_t *, const text_t *);
typedef int (*cm_charset_conv_mb_wc)(const CHARSET_COLLATION *, cm_wc_t *, const uchar *, const uchar *);
typedef int (*cm_charset_conv_wc_mb)(const CHARSET_COLLATION *, cm_wc_t, uchar *, uchar *);

typedef struct cm_charset_handler_t {
    cm_charset_conv_case caseup;
    cm_charset_conv_case casedn;
    cm_charset_conv_mb_wc mb_wc;
    cm_charset_conv_wc_mb wc_mb;
} cm_charset_handler_t;

typedef enum enum_char_grp {
    CHARGRP_NONE,
    CHARGRP_CORE,
    CHARGRP_LATIN,
    CHARGRP_CYRILLIC,
    CHARGRP_ARAB,
    CHARGRP_KANA,
    CHARGRP_OTHERS
} enum_char_grp;

typedef struct weight_boundary_t {
    uint16 begin;
    uint16 end;
} weight_boundary_t;

typedef struct reorder_wt_rec_t {
    struct weight_boundary_t old_wt_bdy;
    struct weight_boundary_t new_wt_bdy;
} reorder_wt_rec_t;

typedef struct reorder_param_t {
    enum enum_char_grp reorder_grp[UCA_MAX_CHAR_GRP];
    struct reorder_wt_rec_t wt_rec[2 * UCA_MAX_CHAR_GRP];
    int wt_rec_num;
    uint16 max_weight;
} reorder_param_t;

typedef enum case_first_t {
    CASE_FIRST_OFF,
    CASE_FIRST_UPPER,
    CASE_FIRST_LOWER
} case_first_t;

typedef struct coll_param_t {
    reorder_param_t *reorder_param;
    bool32 norm_enabled;  // false = normalization off, default; true = on
    case_first_t case_first;
} coll_param_t;

typedef struct CM_UNICASE_CHARACTER {
    uint32 toupper;
    uint32 tolower;
    uint32 sort;
} CM_UNICASE_CHARACTER;

typedef struct CM_UNICASE_INFO {
    cm_wc_t maxchar;
    const CM_UNICASE_CHARACTER **page;
} CM_UNICASE_INFO;

typedef uint (*cs_ismbchar)(const CHARSET_COLLATION *, const char *, const char *);
typedef size_t (*cs_numchars)(const CHARSET_COLLATION *, const char *b, const char *e);
typedef int32 (*cmp_collsp)(const CHARSET_COLLATION *, text_t *, text_t *);
typedef int32 (*cset_mb_wc)(cm_wc_t *pwc, const uchar *s, const uchar *e);
typedef struct CHARSET_COLLATION {
    uint number;
    uint state;
    char *csname;
    char *clname;
    coll_param_t *coll_param;
    const uchar *sort_order;
    struct CM_UCA_INFO *uca;
    const CM_UNICASE_INFO *caseinfo;
    uchar levels_for_compare;
    uint mbmaxlen;
    cset_mb_wc mb_wc;
    cs_ismbchar ismbchar;
    cs_numchars numchars;
    cmp_collsp collsp;
    pad_attribute_t pad_attribute;
} CHARSET_COLLATION;

extern charset_func_t g_charset_func[];

#define CM_CHARSET_FUNC(charset) (g_charset_func[charset])

#ifdef __cplusplus
}
#endif

#endif
