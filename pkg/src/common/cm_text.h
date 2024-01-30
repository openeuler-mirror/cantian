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
 * cm_text.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_text.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_TEXT_H__
#define __CM_TEXT_H__
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include "cm_defs.h"
#include "cm_debug.h"
#include "cm_error.h"
#include "securectype.h"
#include <stdint.h>
#include "cm_log.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    CASE_SENSITIVE = 1,
    CASE_INSENSITIVE = 2,
} case_mode_t;

#pragma pack(4)
typedef struct st_text {
    char *str;
    uint32 len;
} text_t;
#pragma pack()

#ifdef Z_SHARDING
typedef struct st_long_text {
    char *text_addr;
    uint32 text_size;
    uint32 first_page_id;
    bool32 is_long_sql;
} long_text_t;
#endif

typedef struct st_cursor {
    uint32 stmt_id;
    uint32 fetch_mode; /* 0, normal fetch; 1, prepare and execute; 2 prepare and fetch */
} cursor_t;

/** A text buffer that along with a maximal length */
typedef union un_text_buf {
    text_t value;

    struct {
        char *str;
        uint32 len;
        uint32 max_size;
    };
} text_buf_t;

/* macro CM_INIT_TEXTBUF() will help make it easier to assign the buffer and length to text_buf_t */
#define CM_INIT_TEXTBUF(text_buf, buf_size, buf) \
    do {                                         \
        (text_buf)->max_size = (buf_size);       \
        (text_buf)->str = (buf);                 \
        (text_buf)->len = 0;                     \
    } while (0)

#pragma pack(4)
typedef union un_sql_text {
    text_t value;
    struct {
        char *str;
        uint32 len;
        source_location_t loc;
        bool32 implicit;
    };
} sql_text_t;
#pragma pack()

#define CT_MAX_TUPLE_SIZE 10
#define CT_MAX_INT64_SIZE 22
/* A tuple of continuous words with size */
typedef struct {
    uint32 size;
    char *words[CT_MAX_TUPLE_SIZE];
} word_tuple_t;

/* Attach each word_tuple_t with an ID */
typedef struct {
    uint32 id;
    word_tuple_t tuple;
} word_record_t;

typedef enum en_num_flag {
    NF_NONE = 0x0,
    NF_NEGATIVE_SIGN = 0x0001,                    /* `-` */
    NF_POSTIVE_SIGN = 0x0002,                     /* `+` */
    NF_SIGN = NF_NEGATIVE_SIGN | NF_POSTIVE_SIGN, /* `+` */
    NF_DOT = 0x0004,                              /* `.` */
    NF_EXPN = 0x0008,                             /* `E` or `e` */
    NF_SZ_INDICATOR = 0x0010,                     /* B, K, M, G, T, P, E */
    NF_ALL = 0xFFFF
} num_flag_t;

#define CT_MAX_NUM_PART_BUFF (CT_MAX_DEC_OUTPUT_ALL_PREC)

typedef struct st_digitext {
    char str[CT_MAX_NUM_PART_BUFF];
    uint32 len;
} digitext_t;

/* !
 * \brief An internal struct used to parse and extract the part of a
 * numeric text
 */
typedef struct st_num_part {
    bool32 is_neg;
    bool32 has_dot;
    bool32 has_expn;
    bool32 do_round;
    int32 sci_expn;
    int32 dot_offset;
    /* indicating which num flag should be excluded, it should be specified
     * before parsing. */
    uint32 excl_flag;
    digitext_t digit_text;

    /* for parse size type (unsigned integer with [K|M|G|T|P...]) */
    char sz_indicator;
} num_part_t;

#define NUMPART_IS_ZERO(np) ((np)->digit_text.len == 1 && CM_IS_ZERO((np)->digit_text.str[0]))

#define CM_ZERO_NUMPART(np)             \
    do {                                \
        (np)->digit_text.str[0] = '0';  \
        (np)->digit_text.str[1] = '\0'; \
        (np)->digit_text.len = 1;       \
    } while (0)

/* The Error codes when parsing numeric text */
typedef enum en_num_errno {
    NERR_SUCCESS = 0,  // CT_SUCCESS
    NERR_ERROR,        /* error without concrete reason */
    NERR_INVALID_LEN,
    NERR_NO_DIGIT,
    NERR_UNEXPECTED_CHAR,
    NERR_NO_EXPN_DIGIT,
    NERR_EXPN_WITH_NCHAR,
    NERR_EXPN_TOO_LONG,
    NERR_EXPN_OVERFLOW,
    NERR_OVERFLOW,
    NERR_UNALLOWED_NEG,
    NERR_UNALLOWED_DOT,
    NERR_UNALLOWED_EXPN,
    NERR_MULTIPLE_DOTS,
    NERR_EXPECTED_INTEGER,
    NERR_EXPECTED_POS_INT,
    NERR__NOT_USED__ /* for safely accessing the error information */
} num_errno_t;

extern const char *g_num_errinfos[];

#define CM_CHECK_NUM_ERRNO(err_no)  \
    if ((err_no) != NERR_SUCCESS) { \
        return (err_no);            \
    }

#define CM_NO_CHECK_NUM_ERRNO(err_no)                                       \
    if ((err_no) != NERR_SUCCESS && (err_no) != NERR_UNEXPECTED_CHAR) {     \
        return (err_no);                                                    \
    }

#define CM_TRY_THROW_NUM_ERR(err_no)                                        \
    do {                                                                    \
        if ((err_no) != NERR_SUCCESS) {                                     \
            CT_THROW_ERROR(ERR_INVALID_NUMBER, cm_get_num_errinfo(err_no)); \
            return CT_ERROR;                                                \
        }                                                                   \
    } while (0)

static inline const char *cm_get_num_errinfo(uint32 err_no)
{
    CM_ASSERT(err_no < NERR__NOT_USED__);
    CM_ASSERT(err_no != NERR_SUCCESS);
    return (g_num_errinfos[err_no] != NULL) ? g_num_errinfos[err_no] : "";
}

static inline void cm_str2text(char *str, text_t *text)
{
    text->str = str;
    text->len = (str == NULL) ? 0 : (uint32)strlen(str);
}

static inline void cm_str2text_safe(char *str, uint32 len, text_t *text)
{
    text->str = str;
    text->len = len;
}

#define MICROSECS_PER_MILLISEC  1000U
#define MICROSECS_PER_SECOND    1000000U

#define CM_TEXT_BEGIN(text)  ((text)->str[0])
#define CM_TEXT_FIRST(text)  ((text)->str[0])
#define CM_TEXT_SECOND(text) ((text)->str[1])
#define CM_TEXT_END(text)    ((text)->str[(text)->len - 1])
#define CM_TEXT_SECONDTOLAST(text)      (((text)->len >= 2) ? ((text)->str[(text)->len - 2]) : '\0')
#define CM_NULL_TERM(text)   \
    {                                    \
        (text)->str[(text)->len] = '\0'; \
    }
#define CM_IS_EMPTY(text) (((text)->str == NULL) || ((text)->len == 0))
#define CM_IS_QUOTE_CHAR(c1) ((c1)== '\'' || (c1) == '"' || (c1) == '`')
#define CM_IS_QUOTE_STRING(c1, c2) ((c1) == (c2) && CM_IS_QUOTE_CHAR(c1))

#define CM_REMOVE_FIRST(text) \
    do {                      \
        --((text)->len);      \
        ++((text)->str);      \
    } while (0)

/* n must be less than text->len */
#define CM_REMOVE_FIRST_N(text, n) \
    do {                           \
        uint32 _nn = (uint32)(n);  \
        (text)->len -= _nn;        \
        (text)->str += _nn;        \
    } while (0)

#define CM_REMOVE_LAST(text) \
    {                        \
        --((text)->len);     \
    }
#define CM_IS_EMPTY_STR(str)     (((str) == NULL) || ((str)[0] == 0))
#define CM_STR_REMOVE_FIRST(str) \
    {                            \
        (str)++;                 \
    }
#define CM_STR_REMOVE_FIRST_N(str, cnt) \
    do {                         \
        uint32 _cnt = cnt;       \
        while (_cnt > 0) {        \
            (str)++;             \
            _cnt--;              \
        }                        \
    } while (0)
#define CM_STR_GET_FIRST(str, out) \
    {                              \
        (out) = (str)[0];          \
    }
#define CM_STR_POP_FIRST(str, out)      \
    do {                                \
        CM_STR_GET_FIRST((str), (out)); \
        CM_STR_REMOVE_FIRST((str));     \
    } while (0)
#define CM_STR_BEGIN_WITH(str1, str2)     strncmp((str1), (str2), strlen(str2)) == 0
#define CM_IS_ENCLOSED_WITH_CHAR(text, c) ((text)->len >= 2 && (text)->str[0] == (c) &&  \
        (text)->str[(text)->len - 1] == (c))

/* Remove the enclosed char or the head and the tail of the text */
#define CM_REMOVE_ENCLOSED_CHAR(text) \
    do {                              \
        ++((text)->str);              \
        (text)->len -= 2;             \
    } while (0)

/* Get the tail address of a text */
#define CM_GET_TAIL(text) ((text)->str + (text)->len)

/* Get the i-th char of the text */
#define CM_GET_CHAR(text, i) ((text)->str[(i)])

/** Append a char at the end of text */
#define CM_TEXT_APPEND(text, c) (text)->str[(text)->len++] = (c)

/** Clear all characters of the text */
#define CM_TEXT_CLEAR(text) (text)->len = 0

#define UPPER(c) (((c) >= 'a' && (c) <= 'z') ? ((c) - 32) : (c))
#define LOWER(c) (((c) >= 'A' && (c) <= 'Z') ? ((c) + 32) : (c))

#define CM_IS_DIGIT(c)         ((c) >= '0' && ((c) <= '9'))
#define CM_IS_NONZERO_DIGIT(c) ((c) > '0' && ((c) <= '9'))
#define CM_IS_EXPN_CHAR(c)     ((c) == 'e' || ((c) == 'E'))
#define CM_IS_SIGN_CHAR(c)     ((c) == '-' || ((c) == '+'))

/** Hex chars are any of: 0 1 2 3 4 5 6 7 8 9 a b c d e f A B C D E F */
#define CM_IS_HEX(c)   ((bool32)isxdigit(c))
#define CM_IS_ASCII(c) ((c) >= 0)

/** An enclosed char must be an ASCII char */
#define CM_IS_VALID_ENCLOSED_CHAR(c) CM_IS_ASCII(((char)(c)))

#define CM_IS_ZERO(c)    ((c) == '0')
#define CM_IS_DOT(c)     ((c) == '.')
#define CM_IS_NONZERO(c) ((c) != '0')
#define CM_IS_COLON(c)   ((c) == ':')

/** Convert a digital char into numerical digit */
#define CM_C2D(c) ((c) - '0')

#define CM_DEFAULT_DIGIT_RADIX  10
#define CM_HEX_DIGIT_RADIX      16
#define SIGNED_LLONG_MAX  "9223372036854775807"
#define SIGNED_LLONG_MIN  "-9223372036854775808"
#define UNSIGNED_LLONG_MAX  "18446744073709551615"

#define CM_SNPRINTF_REAL(iret_snprintf, str, real_val, len)                                    \
    do {                                                                                       \
        if ((real_val) == 0) {                                                                 \
            (iret_snprintf) = snprintf_s((str), (len), (len) - 1, "0");                        \
        } else {                                                                               \
            (iret_snprintf) = snprintf_s((str), (len), (len) - 1, PRINT_FMT_REAL, (real_val)); \
        }                                                                                      \
    } while (0)

/** Copy src text to dest text */
static inline status_t cm_text_copy(text_t *dest, uint32 buf_len, text_t *src)
{
    if (src->len != 0) {
        MEMS_RETURN_IFERR(memcpy_sp((dest)->str, buf_len, (src)->str, (src)->len));
        (dest)->len = (src)->len;
    }
    return CT_SUCCESS;
}

static inline void cm_text_copy_upper(text_t *dest, const text_t *src)
{
    dest->len = src->len;
    for (uint32 i = 0; i < src->len; i++) {
        dest->str[i] = UPPER(src->str[i]);
    }
}

static inline status_t cm_text_copy_from_str(text_t *dest, const char *str, uint32 buf_len)
{
    MEMS_RETURN_IFERR(strcpy_s(dest->str, buf_len, str));
    dest->len = (uint32)strlen(str);
    return CT_SUCCESS;
}

static inline void cm_concat_text(text_t *text, uint32 max_len, const text_t *part)
{
    if (SECUREC_UNLIKELY(part->len == 0 || text->len >= max_len)) {
        return;
    }
    
    uint32 cat_len = ((text->len + part->len) <= max_len) ? part->len : (max_len - text->len);
    MEMS_RETVOID_IFERR(memcpy_s(text->str + text->len, max_len - text->len, part->str, cat_len));
    text->len += cat_len;
}

void cm_concat_fmt(text_t *text, uint32 fmt_size, const char *fmt, ...);

/**
 * concatenate a text with a given maximal buf size, if the result length
 * exceeds the maximal buf size return CT_FALSE; else return CT_TRUE
 */
static inline bool32 cm_buf_append_text(text_buf_t *dst, const text_t *part)
{
    if (dst->len + part->len >= dst->max_size) {
        return CT_FALSE;
    }

    for (uint32 i = 0; i < part->len; ++i) {
        CM_TEXT_APPEND(dst, part->str[i]);
    }

    return CT_TRUE;
}

static inline bool32 cm_buf_append_char(text_buf_t *dst, char c)
{
    if (dst->len + 1 >= dst->max_size) {
        return CT_FALSE;
    }

    CM_TEXT_APPEND(dst, c);

    return CT_TRUE;
}

static inline bool32 cm_buf_append_str(text_buf_t *dst, const char *str)
{
    size_t len = strlen(str);
    if (dst->len + len >= dst->max_size) {
        return CT_FALSE;
    }

    for (uint32 i = 0; i < len; ++i) {
        CM_TEXT_APPEND(dst, str[i]);
    }

    return CT_TRUE;
}

static inline void cm_concat_text_upper(text_t *text, const text_t *part)
{
    for (uint32 i = 0; i < part->len; ++i) {
        CM_TEXT_APPEND(text, UPPER(part->str[i]));
    }
}

static inline void cm_concat_text_with_cut(text_t *text, uint32 len, const text_t *part)
{
    uint32 real_len = (part->len <= len) ? part->len : len;
    for (uint32 i = 0; i < real_len; ++i) {
        CM_TEXT_APPEND(text, part->str[i]);
    }
}

static inline void cm_concat_text_upper_with_cut(text_t *text, uint32 len, const text_t *part)
{
    uint32 real_len = (part->len <= len) ? part->len : len;
    for (uint32 i = 0; i < real_len; ++i) {
        CM_TEXT_APPEND(text, UPPER(part->str[i]));
    }
}

bool32 cm_buf_append_fmt(text_buf_t *tbuf, const char *fmt, ...);

/**
* Append first num characters of src into dst;
* + if num<=0, do nothing;
* + if num <= src.len, the first num characters are appended
* + if num > src.len, all characters of src are copyed, and the dst.len += src.len
* @note the user must ensure sufficient space to store them
* @author Added at 2018/03/30
*/
static inline status_t cm_concat_ntext(text_t *dst, const text_t *src, int32 num)
{
    int32 number = num;
    if (number <= 0) {
        return CT_SUCCESS;
    }
    if ((uint32)number > src->len) {
        number = (int32)src->len;
    }
    if (number != 0) {
        MEMS_RETURN_IFERR(memcpy_sp(CM_GET_TAIL(dst), number, src->str, number));
    }
    dst->len += (uint32)number;
    return CT_SUCCESS;
}

static inline status_t cm_concat_string(text_t *text, uint32 maxsize, const char *part)
{
    uint32 len = (uint32)strlen(part);
    if (len != 0 && len <= (maxsize - text->len)) {
        MEMS_RETURN_IFERR(memcpy_sp(text->str + text->len, maxsize - text->len, part, len));
        text->len += len;
    }
    return CT_SUCCESS;
}

static inline status_t cm_concat_n_string(text_t *text, uint32 maxsize, const char *part, uint32 size)
{
    if (size != 0) {
        MEMS_RETURN_IFERR(memcpy_sp(text->str + text->len, maxsize - text->len, part, size));
        text->len += size;
    }
    return CT_SUCCESS;
}

static inline void cm_concat_int32(text_t *text, uint32 max_len, uint32 i32)
{
    char buf[CT_NUMBER_BUFFER_SIZE];
    
    if (snprintf_s(buf, sizeof(buf), sizeof(buf) - 1, "%u", i32) == -1) {
        return;
    }

    (void)cm_concat_string(text, max_len, buf);
}

static inline void cm_concat_int64(text_t *text, uint32 max_len, int64 i64)
{
    char buf[CT_NUMBER_BUFFER_SIZE];

    if (snprintf_s(buf, sizeof(buf), sizeof(buf) - 1, "%lld", i64) == -1) {
        return;
    }

    (void)cm_concat_string(text, max_len, buf);
}

static inline void cm_rtrim_text(text_t *text)
{
    int32 index;

    if (text->str == NULL) {
        text->len = 0;
        return;
    } else if (text->len == 0) {
        return;
    }

    index = (int32)text->len - 1;
    while (index >= 0) {
        if ((uchar)text->str[index] > (uchar)' ') {
            text->len = (uint32)(index + 1);
            return;
        }

        --index;
    }
}

static inline void cm_ltrim_text(text_t *text)
{
    if (text->str == NULL) {
        text->len = 0;
        return;
    } else if (text->len == 0) {
        return;
    }

    while (text->len > 0) {
        if ((uchar)*text->str > ' ') {
            break;
        }
        text->str++;
        text->len--;
    }
}

static inline void cm_trim_text(text_t *text)
{
    cm_ltrim_text(text);
    cm_rtrim_text(text);
}

static inline void cm_text_rtrim_zero(text_t *text)
{
    CM_POINTER(text);

    for (int32 i = (int32)text->len - 1; i > 0; --i) {
        if (CM_IS_ZERO(text->str[i]) || CM_IS_DOT(text->str[i])) {
            --text->len;
        } else {
            return;
        }
    }
}

/** skipping leading zeros, if all text are zeros, only one zero is
 ** kept. */
static inline void cm_text_ltrim_zero(text_t *text)
{
    CM_POINTER(text);

    while (text->len > 1 && CM_IS_ZERO(CM_TEXT_FIRST(text))) {
        CM_REMOVE_FIRST(text);
    }
}

static bool32 cm_is_bracket_text(const text_t *text)
{
    bool32 in_string = CT_FALSE;
    uint32 depth;

    if (text->len < 2) {
        return CT_FALSE;
    }

    bool32 flag = CM_TEXT_BEGIN(text) != '(' || CM_TEXT_END(text) != ')';
    if (flag) {
        return CT_FALSE;
    }

    depth = 1;
    for (uint32 i = 1; i < text->len; i++) {
        if (text->str[i] == '\'') {
            in_string = !in_string;
            continue;
        }

        if (in_string) {
            continue;
        } else if (text->str[i] == '(') {
            depth++;
        } else if (text->str[i] == ')') {
            depth--;
            if (depth == 0) {
                return (i == text->len - 1);
            }
        }
    }

    return CT_FALSE;
}

static inline void cm_remove_brackets(text_t *text)
{
    while (cm_is_bracket_text(text)) {
        text->str++;
        text->len -= 2;
        cm_trim_text(text);
    }
}

// case sensitive
static inline bool32 cm_text_equal(const text_t *text1, const text_t *text2)
{
    uint32 i;

    if (text1->len != text2->len) {
        return CT_FALSE;
    }

    for (i = 0; i < text1->len; i++) {
        if (text1->str[i] != text2->str[i]) {
            return CT_FALSE;
        }
    }

    return CT_TRUE;
}

// case insensitive, all text uses upper mode to compare.
static inline bool32 cm_text_equal_ins(const text_t *text1, const text_t *text2)
{
    uint32 i;

    if (text1->len != text2->len) {
        return CT_FALSE;
    }

    for (i = 0; i < text1->len; i++) {
        if (UPPER(text1->str[i]) != UPPER(text2->str[i])) {
            return CT_FALSE;
        }
    }

    return CT_TRUE;
}

// case insensitive, the secord text uses upper mode to compare.
static inline bool32 cm_text_equal_ins2(const text_t *text1, const text_t *text2)
{
    uint32 i;

    if (text1->len != text2->len) {
        return CT_FALSE;
    }

    for (i = 0; i < text1->len; i++) {
        if (text1->str[i] != UPPER(text2->str[i])) {
            return CT_FALSE;
        }
    }

    return CT_TRUE;
}

static inline bool32 cm_text_str_equal(const text_t *text, const char *str)
{
    uint32 i;

    for (i = 0; i < text->len; i++) {
        if (text->str[i] != str[i] || str[i] == '\0') {
            return CT_FALSE;
        }
    }

    return (str[text->len] == '\0');
}

static inline bool32 cm_text_str_equal_ins(const text_t *text, const char *str)
{
    uint32 i;

    for (i = 0; i < text->len; i++) {
        if (UPPER(text->str[i]) != UPPER(str[i]) || str[i] == '\0') {
            return CT_FALSE;
        }
    }

    return (str[text->len] == '\0');
}

static inline bool32 cm_text_str_less_equal_ins(const text_t *text, const char *str, const uint32 less_len)
{
    uint32 i;

    if (text->len < less_len) {
        return CT_FALSE;
    }

    for (i = 0; i < text->len; i++) {
        if (UPPER(text->str[i]) != UPPER(str[i]) || str[i] == '\0') {
            return CT_FALSE;
        }
    }

    return CT_TRUE;
}

static inline bool32 cm_text_str_contain_equal_ins(const text_t *text, const char *str, const uint32 str_len)
{
    uint32 i;

    if (text->len < str_len) {
        return CT_FALSE;
    }

    for (i = 0; i < str_len; i++) {
        if (UPPER(text->str[i]) != UPPER(str[i])) {
            return CT_FALSE;
        }
    }

    return CT_TRUE;
}

static inline uint32 cm_text_str_get_match_len(const text_t *text, const char *str)
{
    uint32 str_len = (uint32)strlen(str);
    uint32 min_len = MIN(text->len, str_len);

    for (uint32 i = 0; i < min_len; i++) {
        if (UPPER(text->str[i]) != UPPER(str[i])) {
            return i;
        }
    }
    return min_len;
}

static inline int32 cm_compare_text(const text_t *text1, const text_t *text2)
{
    uint32 i, cmp_len;
    uchar c1, c2;

    cmp_len = (text1->len < text2->len) ? text1->len : text2->len;
    for (i = 0; i < cmp_len; i++) {
        c1 = (uchar)text1->str[i];
        c2 = (uchar)text2->str[i];

        if (c1 > c2) {
            return 1;
        } else if (c1 < c2) {
            return -1;
        }
    }
    return (text1->len > text2->len) ? 1 : ((text1->len == text2->len) ? 0 : -1);
}

static inline int32 cm_compare_digitext(const digitext_t *dtext1, const digitext_t *dtext2)
{
    const text_t text1 = { (char *)dtext1->str, dtext1->len };
    const text_t text2 = { (char *)dtext2->str, dtext2->len };
    return cm_compare_text(&text1, &text2);
}

static inline int32 cm_compare_text_rtrim(const text_t *text1, const text_t *text2)
{
    text_t l_text = *text1;
    text_t r_text = *text2;

    cm_rtrim_text(&l_text);
    cm_rtrim_text(&r_text);
    return cm_compare_text(&l_text, &r_text);
}

static inline int32 cm_compare_text_ins(const text_t *text1, const text_t *text2)
{
    uint32 i, cmp_len;
    uchar c1, c2;

    cmp_len = (text1->len < text2->len) ? text1->len : text2->len;

    for (i = 0; i < cmp_len; i++) {
        c1 = (uchar)UPPER(text1->str[i]);
        c2 = (uchar)UPPER(text2->str[i]);
        if (c1 > c2) {
            return 1;
        } else if (c1 < c2) {
            return -1;
        }
    }

    return (text1->len > text2->len) ? 1 : ((text1->len == text2->len) ? 0 : -1);
}

static inline int32 cm_compare_text_str(const text_t *text, const char *str)
{
    uint32 i;
    uchar c1, c2;
    for (i = 0; i < text->len; i++) {
        c1 = (uchar)text->str[i];
        c2 = (uchar)str[i];

        if (c1 > c2) {
            return 1;
        } else if (c1 < c2) {
            return -1;
        }
    }
    return (str[i] == '\0') ? 0 : -1;
}

static inline int32 cm_compare_text_str_ins(const text_t *text, const char *str)
{
    uint32 i;
    uchar c1, c2;
    for (i = 0; i < text->len; i++) {
        c1 = (uchar)UPPER(text->str[i]);
        c2 = (uchar)UPPER(str[i]);
        if (c1 > c2) {
            return 1;
        } else if (c1 < c2) {
            return -1;
        }
    }
    return (str[i] == '\0') ? 0 : -1;
}

#ifdef WIN32
#define cm_strcmpi  _strcmpi
#define cm_strcmpni _strnicmp
#else
#define cm_strcmpi  strcasecmp
#define cm_strcmpni strncasecmp
#endif

static inline const char *cm_strstri(const char *str, const char *subStr)
{
    size_t len = strlen(subStr);
    if (len == 0) {
        return NULL;
    }

    while (*str) {
        if (cm_strcmpni(str, subStr, len) == 0) {
            return str;
        }
        ++str;
    }
    return NULL;
}

static inline const char *cm_strnstri(const char *str, uint32 len, const char *sub_str, uint32 sub_len)
{
    uint32 match_count = 0;

    if (len < sub_len) {
        return NULL;
    }

    for (uint32 i = 0; i < len; i++) {
        if (UPPER(str[i]) != UPPER(sub_str[match_count])) {
            match_count = 0;
            if (UPPER(str[i]) == UPPER(sub_str[match_count])) {
                ++match_count;
            }
            continue;
        }

        if (++match_count == sub_len) {
            return str + i + 1 - sub_len;
        }
    }
    return NULL;
}

static inline bool32 cm_char_in_text(char c, const text_t *set)
{
    return memchr((void *)set->str, c, set->len) != NULL;
}

static inline void cm_rtrim_text_func(text_t *text, const text_t *set)
{
    while (text->len > 0) {
        if (!cm_char_in_text(text->str[text->len - 1], set)) {
            break;
        }
        text->len--;
    }
}

/**
 * Append num characters c to the text; if num<=0, do nothing;
 * @note the user must ensure sufficient space to store them
 * @author Added at 2018/03/30
 */
static inline void cm_text_appendc(text_t *text, int32 num, char c)
{
    int32 number = num;
    while (number-- > 0) {
        CM_TEXT_APPEND(text, c);
    }
}

static inline uint32 cm_get_first_pos(const text_t *text, const char c)
{
    for (uint32 i = 0; i < text->len; i++) {
        if (text->str[i] == c) {
            return i;
        }
    }
    return CT_INVALID_ID32;
}

static inline uint32 cm_get_last_pos(const text_t *text, const char c)
{
    for (uint32 i = text->len; i > 0; i--) {
        if (text->str[i - 1] == c) {
            return (uint32)(i - 1);
        }
    }
    return CT_INVALID_ID32;
}

#define cm_compare_str(str1, str2)     strcmp(str1, str2)
#define cm_compare_str_ins(str1, str2) cm_strcmpi(str1, str2)
#define cm_str_equal(str1, str2)       (strcmp(str1, str2) == 0)
#define cm_str_equal_ins(str1, str2)   (cm_strcmpi(str1, str2) == 0)

extern const text_t g_null_text;
extern const char *g_visible_char_map[128];

#define CM_NULL_TEXT g_null_text
status_t cm_text2str(const text_t *text, char *buf, uint32 buf_size);
status_t cm_text2str_with_quato(const text_t *text, char *buf, uint32 buf_size);
void cm_text2str_with_upper(const text_t *text, char *buf, uint32 buf_size);
status_t cm_text2bool(const text_t *bool_text, bool32 *val);
status_t cm_text2real(const text_t *text_src, double *value);
status_t cm_text2uint16(const text_t *text_src, uint16 *value);
status_t cm_text2int(const text_t *text_src, int32 *value);
status_t cm_text2uint32(const text_t *text_src, uint32 *value);
status_t cm_text2uint64(const text_t *text_src, uint64 *value);
status_t cm_text2bigint(const text_t *text_src, int64 *value);

static inline void cm_text2digitext(const text_t *num_text, digitext_t *dig_text)
{
    (void)cm_text2str(num_text, dig_text->str, CT_MAX_NUM_PART_BUFF);
    dig_text->len = num_text->len;
}

/** Try convert a native datatype into text */
static inline void cm_int2text(int32 value, text_t *text)
{
    int iret_snprintf;

    CM_POINTER(text);

    iret_snprintf = snprintf_s(text->str, CT_MAX_INT32_STRLEN + 1, CT_MAX_INT32_STRLEN, PRINT_FMT_INTEGER, value);
    if (iret_snprintf == -1) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, (iret_snprintf));
        return;
    }
    text->len = (uint32)iret_snprintf;
}

static inline void cm_uint32_to_text(uint32 value, text_t *text)
{
    int iret_snprintf;
    CM_POINTER(text);
    iret_snprintf = snprintf_s(text->str, CT_MAX_UINT32_STRLEN + 1, CT_MAX_UINT32_STRLEN, PRINT_FMT_UINT32, value);
    if (iret_snprintf == -1) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, (iret_snprintf));
        return;
    }
    text->len = (uint32)iret_snprintf;
}

static inline void cm_bool2text(bool32 value, text_t *text)
{
    int iret_snprintf;
    CM_POINTER(text);
    iret_snprintf = snprintf_s(text->str, CT_MAX_BOOL_STRLEN + 1, CT_MAX_BOOL_STRLEN, value ? "TRUE" : "FALSE");
    if (iret_snprintf == -1) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, (iret_snprintf));
        return;
    }
    text->len = (uint32)iret_snprintf;
}

static inline void cm_bigint2text(int64 value, text_t *text)
{
    int iret_snprintf;
    CM_POINTER(text);
#ifdef WIN32
    iret_snprintf = snprintf_s(text->str, CT_MAX_INT64_STRLEN + 1, CT_MAX_INT64_STRLEN, PRINT_FMT_BIGINT, value);
#else
    iret_snprintf = snprintf_s(text->str, CT_MAX_INT64_STRLEN + 1, CT_MAX_INT64_STRLEN, PRINT_FMT_BIGINT,
                               (long long)value);
#endif
    if (iret_snprintf == -1) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, (iret_snprintf));
        return;
    }
    text->len = (uint32)iret_snprintf;
}

static inline void cm_uint64_to_text(uint64 value, text_t *text)
{
    int iret_snprintf;
    CM_POINTER(text);
#ifdef WIN32
    iret_snprintf = snprintf_s(text->str, CT_MAX_UINT64_STRLEN + 1, CT_MAX_UINT64_STRLEN, PRINT_FMT_UINT64, value);
#else
    iret_snprintf = snprintf_s(text->str, CT_MAX_UINT64_STRLEN + 1, CT_MAX_UINT64_STRLEN, PRINT_FMT_UINT64,
                               (unsigned long long)value);
#endif
    if (iret_snprintf == -1) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, (iret_snprintf));
        return;
    }
    text->len = (uint32)iret_snprintf;
}

static inline void cm_real2text(double real_val, text_t *text)
{
    int iret_snprintf;
    CM_POINTER(text);
    CM_SNPRINTF_REAL(iret_snprintf, text->str, real_val, CT_MAX_REAL_OUTPUT_STRLEN + 1);

    if (iret_snprintf == -1) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, (iret_snprintf));
        return;
    }
    text->len = (uint32)iret_snprintf;
}

/** Try convert a numeric text into a native datatype */
num_errno_t cm_text2int_ex(const text_t *text_src, int32 *value);
num_errno_t cm_text2uint32_ex(const text_t *text_src, uint32 *value);
num_errno_t cm_text2bigint_ex(const text_t *num_text, int64 *value);
num_errno_t cm_text2uint64_ex(const text_t *num_text, uint64 *value);
num_errno_t cm_text2real_ex(const text_t *text_src, double *value);
num_errno_t cm_text2real_ex_no_check_err(const text_t *text_src, double *value);
num_errno_t cm_text2int16_ex(const text_t *text, int32 *val);

/** Try convert a number parts (a struct for processed numeric text) into a navie datatype */
num_errno_t cm_numpart2int(num_part_t *np, int32 *value);
num_errno_t cm_numpart2bigint(const num_part_t *np, int64 *value);
num_errno_t cm_numpart2uint32(const num_part_t *np, uint32 *value);
num_errno_t cm_numpart2uint64(const num_part_t *np, uint64 *value);
num_errno_t cm_numpart2real(num_part_t *np, double *value);
num_errno_t cm_numpart2size(const num_part_t *np, int64 *value);

status_t cm_str2uint16(const char *str, uint16 *value);
status_t cm_str2uint32(const char *str, uint32 *value);
status_t cm_str2uint64(const char *str, uint64 *value);
status_t cm_str2int(const char *str, int32 *value);
status_t cm_str2bigint(const char *str, int64 *value);
status_t cm_str2real(const char *str, double *value);
bool32 cm_str2real_ex(const char *str, double *val);
uint32 cm_bool2str(bool32 value, char *str);
void cm_split_text(const text_t *text, char split_char, char enclose_char, text_t *left, text_t *right);
bool32 cm_split_rtext(const text_t *text, char split_char, char enclose_char, text_t *left, text_t *right);
bool32 cm_is_short(const text_t *text);
bool32 cm_is_int(const text_t *text);
bool32 cm_is_bigint(const text_t *text, num_part_t *np);

num_errno_t cm_decide_numtype(const num_part_t *np, ct_type_t *type);

num_errno_t cm_is_number(const text_t *text, ct_type_t *type);
num_errno_t cm_is_number_with_sign(const text_t *text, ct_type_t *type);
bool32 cm_is_unsigned_int(const char *num);
void cm_truncate_text(text_t *text, uint32 max_len);
void cm_trim_number(text_t *text, bool32 has_dot);
status_t cm_text2size(const text_t *text, int64 *value);
status_t cm_text2microsecond(const text_t *text, uint64 *value);
status_t cm_str2size(const char *str, int64 *value);
status_t cm_str2microsecond(const char *str, uint64 *value);
bool32 cm_fetch_text(text_t *text, char split_char, char enclose_char, text_t *sub);
bool32 cm_fetch_rtext(text_t *text, char split_char, char enclose_char, text_t *sub);
bool32 cm_is_enclosed(const text_t *text, char enclosed_char);
bool32 cm_fetch_line(text_t *text, text_t *line, bool32 eof);

void cm_str_upper(char *str);
void cm_str_lower(char *str);
void cm_text_upper(text_t *text);
void cm_text_lower(text_t *text);
void cm_text_upper_self_name(text_t *name);
void cm_str_reverse(char *dst, const char *src, uint32 dst_len);
size_t cm_str_diff_chars(const char *src, const char *dst);
uint32 cm_instrb(const text_t *str, const text_t *substr, int32 pos, uint32 nth);
status_t cm_substrb(const text_t *src, int32 start, uint32 size, text_t *dst);

char *cm_strchr(const text_t *str, const int32 c);
status_t cm_replace_regexp_spec_chars(text_t *regexp, char *ret, uint32 ret_size);
status_t cm_str2bool(const char *bool_str, bool32 *val);
int32 cm_mysql_compare(const CHARSET_COLLATION *cc, const text_t *text1, const text_t *text2);

/** Get the c-string of a char, for printing \n, \t, \r ... */
static inline const char *cm_char2visible(int32 c)
{
    return (c >= 0 && c <= 127) ? g_visible_char_map[c] : "";
}

#define C2V(c) (cm_char2visible(c))

num_errno_t cm_split_num_text(const text_t *num_text, num_part_t *np);

/** Set at most num characters of text by c */
static inline status_t cm_text_set(text_t *text, uint32 num, char c)
{
    uint32 number = num;
    if (text->len == 0 || number == 0) {
        return CT_SUCCESS;
    }

    if (text->len < number) {
        number = text->len;
    }

    MEMS_RETURN_IFERR(memset_s(text->str, number, c, number));
    return CT_SUCCESS;
}

/* Locate first occurrence of character in string
 * Returns the first position of the character in the text.
 * If the character is not found return -1
 * */
static inline int32 cm_text_chr(const text_t *text, char c)
{
    for (uint32 i = 0; i < text->len; i++) {
        if (text->str[i] == c) {
            return (int32)i;
        }
    }

    return -1;
}

/* Locate first occurrence of character in string that ignoring the character
 * enclosed by enclosed_char
 * IF c == enclosed_char
 * + if count(text, c) is odd, return the last postion of c
 * + if count(text, c) is even, return -1
 * IF c != enclosed_char return the first c that are not enclosed
* Returns the first position of the character in the text.
* If the character is not found return -1
* */
static inline int32 cm_text_enclosed_chr(const text_t *text, char c, char enclose_char)
{
    int32 last_enclosed_pos = -1;
    bool32 in_enclosed = CT_FALSE;

    for (uint32 i = 0; i < text->len; i++) {
        if (CM_IS_VALID_ENCLOSED_CHAR(enclose_char) && text->str[i] == enclose_char) {
            in_enclosed = !in_enclosed;
            last_enclosed_pos = (int32)i;
        }
        if (in_enclosed) {
            continue;
        }
        if (text->str[i] == c) {
            return (int32)i;
        }
    }

    if (CM_IS_VALID_ENCLOSED_CHAR(enclose_char) && c == enclose_char && in_enclosed) {
        return last_enclosed_pos;
    }

    return -1;
}

/**
 * Locate first occurrence of a string in another string that ignoring the character
 *
 * this method is imitated by method cm_text_enclosed_chr.
 */
static inline int32 cm_str_enclosed_chr(const text_t *text, const char *search_str, char enclose_char)
{
    int32 last_enclosed_pos = -1;
    bool32 in_enclosed = CT_FALSE;

    for (uint32 i = 0; i < text->len; i++) {
        if (CM_IS_VALID_ENCLOSED_CHAR(enclose_char) && text->str[i] == enclose_char) {
            in_enclosed = !in_enclosed;
            last_enclosed_pos = (int32)i;
        }
        if (in_enclosed) {
            continue;
        }

        bool32 flag = 1;

        if (text->str[i] == search_str[0]) {
            // text->str[i] and search_str[0] are '/0', (example SQL, fields terminated by '\0') need Special handling.
            if (strlen(search_str) == 0) {
                return (int32)i;
            }

            size_t len = strlen(search_str);

            for (uint32 j = 1; j < len; j++) {
                if (i + j < text->len && text->str[i + j] == search_str[j]) {
                    continue;
                } else {
                    flag = 0;
                    break;
                }
            }

            if (flag) {
                return (int32)i;
            }
        }
    }

    if (CM_IS_VALID_ENCLOSED_CHAR(enclose_char) && 1 == strlen(search_str) && search_str[0] == enclose_char &&
        in_enclosed) {
        return last_enclosed_pos;
    }

    return -1;
}

/* Locate last occurrence of character in string
* Returns the last position of the character in the text.
* If the character is not found return -1
* */
static inline int32 cm_text_rchr(const text_t *text, char c)
{
    for (int32 i = (int32)(text->len - 1); i >= 0; --i) {
        if (text->str[i] == c) {
            return i;
        }
    }

    return -1;
}

/* Locate last occurrence one of character in string
* Returns the last position of the character in the text.
* If the character is not found return -1
* */
static inline int32 cm_text_rchr2(const text_t *text, const char *chs)
{
    const char *p = NULL;

    for (int32 i = (int32)(text->len - 1); i >= 0; --i) {
        p = chs;
        while (*p != '\0') {
            if (text->str[i] == *p++) {
                return i;
            }
        }
    }

    return -1;
}

static inline int32 cm_text_text(const text_t *src, const text_t *sub)
{
    uint32 i, j;

    if (src->len < sub->len) {
        return -1;
    }

    for (i = 0; i < src->len; i++) {
        for (j = 0; j < sub->len; j++) {
            if (i + j >= src->len) {
                return -1;
            }
            if (src->str[i + j] != sub->str[j]) {
                break;
            }
        }
        if (j == sub->len) {
            return (int32)i;
        }
    }
    return -1;
}

status_t cm_replace_quotation(char *src, char *dest, uint32 dest_len, bool32 *exist_flag);

// for multiple sql
typedef struct st_cm_ignore_oper {
    int32 oper_no;
    uint32 expected_enclosed_char;
    uint32 expected_note_no;
    uint32 expected_label_no;
} cm_ignore_oper_t;

bool32 cm_is_multiple_sql(text_t *sql);
bool32 cm_fetch_subsql(text_t *sql, text_t *sub_sql);

/** Duplicate a text. It allocates memory from OS. Its memories must be
 ** freed when it is no need to use */
/* @author Added, 2018/10/07 */
static inline status_t cm_text_dup(const text_t *src, text_t **dst)
{
    errno_t rc_memzero;

    if (src == NULL || (CM_IS_EMPTY(src))) {
        *dst = NULL;
        return CT_SUCCESS;
    }

    text_t *dst_path = (text_t *)malloc(sizeof(text_t));
    if (dst_path == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)sizeof(text_t), "duplicate text");
        return CT_ERROR;
    }

    rc_memzero = memset_sp(dst_path, sizeof(text_t), 0, sizeof(text_t));
    if (rc_memzero != EOK) {
        CM_FREE_PTR(dst_path);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, rc_memzero);
        return CT_ERROR;
    }
    if (src->len == 0) {
        CM_FREE_PTR(dst_path);
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)(src->len + 1), "duplicate text");
        return CT_ERROR;
    }
    dst_path->str = (char *)malloc(src->len + 1);
    if (dst_path->str == NULL) {
        CM_FREE_PTR(dst_path);
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)(src->len + 1), "duplicate text");
        return CT_ERROR;
    }

    rc_memzero = memset_sp(dst_path->str, src->len + 1, 0, src->len + 1);
    if (rc_memzero != EOK) {
        CM_FREE_PTR(dst_path->str);
        CM_FREE_PTR(dst_path);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, rc_memzero);
        return CT_ERROR;
    }

    if (cm_text2str(src, dst_path->str, src->len + 1) != CT_SUCCESS) {
        CM_FREE_PTR(dst_path->str);
        CM_FREE_PTR(dst_path);
        return CT_ERROR;
    }
    dst_path->len = src->len;

    *dst = dst_path;
    return CT_SUCCESS;
}

static inline void cm_free_text(text_t *text)
{
    if (text == NULL) {
        return;
    }

    CM_FREE_PTR(text->str);
    CM_FREE_PTR(text);
}

static inline void cm_text_skip(text_t *text, uint32 step)
{
    uint32 step_t = step;
    step_t = MIN(step_t, text->len);
    text->str += step_t;
    text->len -= step_t;
}

static inline void cm_text_skip_spaces(text_t *text)
{
    while (text->len > 0 && text->str[0] == ' ') {
        text->str++;
        text->len--;
    }

    while (text->len > 0 && text->str[text->len - 1] == ' ') {
        text->len--;
    }
}

/* ignores the comment and get valid content of text */
void cm_extract_content(text_t *text, text_t *content);
void cm_delete_text_end_slash(text_t *text);

static inline status_t cm_chk_and_upper_base16(text_t *text)
{
    // make sure the length of text is odd
    if (text->len % 2 != 0) {
        return CT_ERROR;
    }

    for (uint32 i = 0; i < text->len; ++i) {
        char c = text->str[i];
        if (c >= 'a' && c <= 'f') {
            text->str[i] = c - 32;
            continue;
        }
        if ((c >= 'A' && c <= 'F') || (c >= '0' && c <= '9')) {
            continue;
        }
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

int32 cm_text_text_ins(const text_t *src, const text_t *sub);
bool32 cm_text_split(text_t *text, text_t *sub_text, text_t *left_text, text_t *right_text);
#ifdef __cplusplus
}
#endif

#endif
