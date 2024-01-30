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
 * cm_text.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_text.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_text.h"
#include "cm_decimal.h"
#include "cm_charset.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_MILLISECOND 4294967295000
const text_t g_null_text = { .str = "", .len = 0 };

const char *g_visible_char_map[128] = {
    [0] = "\\0",
    [1] = "\\x01", [2] = "\\x02", [3] = "\\x03", [4] = "\\x04", [5] = "\\x05", [6] = "\\x06", [7] = "\\a", [8] = "\\b",
    [9] = "\\t", [10] = "\\n", [11] = "\\v", [12] = "\\f", [13] = "\\r", [14] = "\\x0E", [15] = "\\x0F", [16] = "\\x10",
    [17] = "\\x11", [18] = "\\x12", [19] = "\\x13", [20] = "\\x14", [21] = "\\x15", [22] = "\\x16", [23] = "\\x17",
    [24] = "\\x18", [25] = "\\x19", [26] = "\\x1A", [27] = "\\x1B", [28] = "\\x1C", [29] = "\\x1D", [30] = "\\x1E",
    [31] = "\\x1F", [32] = " ", [33] = "!", [34] = "\"", [35] = "#", [36] = "$", [37] = "%", [38] = "&", [39] = "\\'",
    [40] = "(", [41] = ")", [42] = "*", [43] = "+", [44] = ",", [45] = "-", [46] = ".", [47] = "/", [48] = "0",
    [49] = "1", [50] = "2", [51] = "3", [52] = "4", [53] = "5", [54] = "6", [55] = "7", [56] = "8", [57] = "9",
    [58] = ":", [59] = ";", [60] = "<", [61] = "=", [62] = ">", [63] = "?", [64] = "@", [65] = "A", [66] = "B",
    [67] = "C", [68] = "D", [69] = "E", [70] = "F", [71] = "G", [72] = "H", [73] = "I", [74] = "J", [75] = "K",
    [76] = "L", [77] = "M", [78] = "N", [79] = "O", [80] = "P", [81] = "Q", [82] = "R", [83] = "S", [84] = "T",
    [85] = "U", [86] = "V", [87] = "W", [88] = "X", [89] = "Y", [90] = "Z", [91] = "[", [92] = "\\", [93] = "]",
    [94] = "^", [95] = "_", [96] = "`", [97] = "a", [98] = "b", [99] = "c", [100] = "d", [101] = "e", [102] = "f",
    [103] = "g", [104] = "h", [105] = "i", [106] = "j", [107] = "k", [108] = "l", [109] = "m", [110] = "n", [111] = "o",
    [112] = "p", [113] = "q", [114] = "r", [115] = "s", [116] = "t", [117] = "u", [118] = "v", [119] = "w", [120] = "x",
    [121] = "y", [122] = "z", [123] = "{", [124] = "|", [125] = "}", [126] = "~", [127] = "\\x7F"
};

static digitext_t g_int16_ceil = { "65535", 5 };
/* The numeric text of the max and the min integer */
static digitext_t g_pos_int32_ceil = { "2147483647", 10 };
static digitext_t g_neg_int32_ceil = { "2147483648", 10 };
static digitext_t g_uint32_ceil = { "4294967295", 10 };
/* The numeric text of the max and the min bigint */
static digitext_t g_pos_bigint_ceil = { "9223372036854775807",  19 };
static digitext_t g_neg_bigint_ceil = { "9223372036854775808",  19 };
static digitext_t g_uint64_ceil = { "18446744073709551615", 20 };

/** The text value of the maximal double 1.7976931348623158e+308, see DBL_MAX */
static digitext_t g_double_ceil = { "179769313486231", 15 };

const char *g_num_errinfos[NERR__NOT_USED__] = {
    [NERR_SUCCESS] = "",
    [NERR_ERROR] = "",
    [NERR_INVALID_LEN] = "-- text is empty or too long",
    [NERR_NO_DIGIT] = "",
    [NERR_UNEXPECTED_CHAR] = "-- unexpected character",
    [NERR_NO_EXPN_DIGIT] = "-- no digits in exponent",
    [NERR_EXPN_WITH_NCHAR] = "-- unexpected character in exponent",
    [NERR_EXPN_TOO_LONG] = "-- exponent text is too long (< 6)",
    [NERR_EXPN_OVERFLOW] = "-- exponent overflow",
    [NERR_OVERFLOW] = "-- overflow",
    [NERR_UNALLOWED_NEG] = "-- minus sign is not allowed",
    [NERR_UNALLOWED_DOT] = "-- decimal point is not allowed",
    [NERR_UNALLOWED_EXPN] = "-- exponent is not allowed",
    [NERR_MULTIPLE_DOTS] = "-- existing multiple decimal points",
    [NERR_EXPECTED_INTEGER] = "-- integer is expected",
    [NERR_EXPECTED_POS_INT] = "-- non-negative integer is expected",
};

/**
 * append at most (fmt_size - 1) characters to text,
 * @note The caller should grant sufficient spaces to accommodate them
 */
void cm_concat_fmt(text_t *text, uint32 fmt_size, const char *fmt, ...)
{
    va_list var_list;
    int32 len;

    va_start(var_list, fmt);
    len = vsnprintf_s(CM_GET_TAIL(text), fmt_size, fmt_size - 1, fmt, var_list);
    PRTS_RETVOID_IFERR(len);
    va_end(var_list);
    if (len < 0) {
        return;
    }
    text->len += (uint32)len;
}

bool32 cm_buf_append_fmt(text_buf_t *tbuf, const char *fmt, ...)
{
    va_list var_list;
    size_t sz;
    int32 len;
    if (tbuf->max_size < tbuf->len) {
        return CT_FALSE;
    }

    sz = tbuf->max_size - tbuf->len;
    va_start(var_list, fmt);
    len = vsnprintf_s(CM_GET_TAIL(tbuf), sz, sz - 1, fmt, var_list);
    if (SECUREC_UNLIKELY(len == -1)) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, len);
        return CT_FALSE;
    }
    va_end(var_list);

    if (len < 0) {
        return CT_FALSE;
    }

    tbuf->len += (uint32)len;
    return CT_TRUE;
}

status_t cm_text2str_with_quato(const text_t *text, char *buf, uint32 buf_size)
{
    uint32 copy_size;
    CM_ASSERT(buf_size > CT_QUATO_LEN + 1);
    copy_size = (text->len + CT_QUATO_LEN >= buf_size) ? buf_size - CT_QUATO_LEN - 1 : text->len;
    buf[0] = '\'';
    if (copy_size > 0) {
        MEMS_RETURN_IFERR(memcpy_sp(buf + 1, copy_size, text->str, copy_size));
    }
    buf[copy_size + 1] = '\'';
    buf[copy_size + CT_QUATO_LEN] = '\0';
    return CT_SUCCESS;
}

status_t cm_text2str(const text_t *text, char *buf, uint32 buf_size)
{
    uint32 copy_size;
    CM_ASSERT(buf_size > 1);
    copy_size = (text->len >= buf_size) ? buf_size - 1 : text->len;
    if (copy_size > 0) {
        MEMS_RETURN_IFERR(memcpy_sp(buf, copy_size, text->str, copy_size));
    }

    buf[copy_size] = '\0';
    return CT_SUCCESS;
}

void cm_text2str_with_upper(const text_t *text, char *buf, uint32 buf_size)
{
    uint32 copy_size;
    copy_size = (text->len >= buf_size) ? buf_size - 1 : text->len;
    for (uint32 i = 0; i < copy_size; i++) {
        buf[i] = UPPER(text->str[i]);
    }

    buf[copy_size] = '\0';
}

status_t cm_text2uint16(const text_t *text_src, uint16 *value)
{
    char buf[CT_MAX_NUMBER_LEN + 1] = {0};
    text_t text = *text_src;

    cm_trim_text(&text);

    if (text.len > CT_MAX_NUMBER_LEN) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR,
            "Convert uint16 failed, the length of text can't be larger than %u, text = %s",
            CT_MAX_NUMBER_LEN, T2S(&text));
        return CT_ERROR;
    }
    CT_RETURN_IFERR(cm_text2str(&text, buf, CT_MAX_NUMBER_LEN + 1));

    return cm_str2uint16(buf, value);
}

status_t cm_text2int(const text_t *text_src, int32 *value)
{
    char buf[CT_MAX_NUMBER_LEN + 1] = {0};
    text_t text = *text_src;

    cm_trim_text(&text);

    if (text.len > CT_MAX_NUMBER_LEN) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR,
            "Convert int32 failed, the length of text can't be larger than %u, text = %s",
            CT_MAX_NUMBER_LEN, T2S(&text));
        return CT_ERROR;
    }
    CT_RETURN_IFERR(cm_text2str(&text, buf, CT_MAX_NUMBER_LEN + 1));

    return cm_str2int(buf, value);
}

num_errno_t cm_numpart2int(num_part_t *np, int32 *value)
{
    if (NUMPART_IS_ZERO(np)) {
        *value = 0;
        return NERR_SUCCESS;
    }

    if (np->digit_text.len > CT_MAX_INT32_PREC ||
        np->has_dot || np->has_expn) {
        return NERR_ERROR;
    }

    if (np->digit_text.len == CT_MAX_INT32_PREC) {
        int32 cmp_ret = cm_compare_digitext(&np->digit_text,
                                            np->is_neg ? &g_neg_int32_ceil : &g_pos_int32_ceil);
        if (cmp_ret > 0) {
            return NERR_OVERFLOW;
        } else if (cmp_ret == 0) {
            *value = np->is_neg ? CT_MIN_INT32 : CT_MAX_INT32;
            return NERR_SUCCESS;
        }
    }

    CM_NULL_TERM(&np->digit_text);
    *value = atoi(np->digit_text.str);

    if (np->is_neg) {
        *value = -(*value);
    }
    return NERR_SUCCESS;
}

/**
* Try to parse an int32 from text, if the conversion is failed, FALSE
* will be returned

*/
num_errno_t cm_text2int_ex(const text_t *text_src, int32 *value)
{
    num_part_t np;
    num_errno_t err_no;

    np.excl_flag = NF_DOT | NF_EXPN;
    err_no = cm_split_num_text(text_src, &np);
    CM_CHECK_NUM_ERRNO(err_no);

    return cm_numpart2int(&np, value);
}

/**
 * Convert a text into a boolean, the following inputs are supported:
 * 1  ==> true
 * 0  ==> false
 * upper(T) ==> true
 * upper(F) ==> false
 * upper(true) ==> true
 * upper(false) ==> false
 */
status_t cm_text2bool(const text_t *bool_text, bool32 *val)
{
    text_t text;

    if (bool_text == NULL) {
        CT_THROW_ERROR(ERR_ASSERT_ERROR, "bool_text != NULL");
        return CT_ERROR;
    }

    text = *bool_text;
    cm_trim_text(&text);

    do {
        CT_BREAK_IF_TRUE(CM_IS_EMPTY(&text));  // empty text is not allowed

        if (text.len == 1) {
            if (CM_IS_ZERO(text.str[0]) || UPPER(text.str[0]) == 'F') {
                *val = CT_FALSE;
                return CT_SUCCESS;
            } else if (text.str[0] == '1' || UPPER(text.str[0]) == 'T') {
                *val = CT_TRUE;
                return CT_SUCCESS;
            }
            break;
        }

        CT_BREAK_IF_TRUE(text.len < CT_MIN_BOOL_STRLEN || text.len > CT_MAX_BOOL_STRLEN);

        if (cm_compare_text_str_ins(&text, "TRUE") == 0) {
            *val = CT_TRUE;
            return CT_SUCCESS;
        } else if (cm_compare_text_str_ins(&text, "FALSE") == 0) {
            *val = CT_FALSE;
            return CT_SUCCESS;
        }
    } while (CT_FALSE);

    CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "invalid BOOLEAN text");
    return CT_ERROR;
}

status_t cm_str2bool(const char *bool_str, bool32 *val)
{
    text_t text_bool;
    cm_str2text((char *)bool_str, &text_bool);
    return cm_text2bool(&text_bool, val);
}

status_t cm_text2uint32(const text_t *text_src, uint32 *value)
{
    char buf[CT_MAX_NUMBER_LEN + 1] = {0};  // '00000000000000000000001'
    text_t text = *text_src;

    cm_trim_text(&text);

    if (text.len > CT_MAX_NUMBER_LEN) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR,
            "Convert uint32 failed, the length of text can't be larger than %u, text = %s",
            CT_MAX_NUMBER_LEN, T2S(&text));
        return CT_ERROR;
    }
    CT_RETURN_IFERR(cm_text2str(&text, buf, CT_MAX_NUMBER_LEN + 1));

    return cm_str2uint32(buf, value);
}

status_t cm_text2uint64(const text_t *text_src, uint64 *value)
{
    char buf[CT_MAX_NUMBER_LEN + 1] = { 0 };  // '00000000000000000000001'
    text_t text = *text_src;

    cm_trim_text(&text);

    if (text.len > CT_MAX_NUMBER_LEN) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR,
            "Convert uint64 failed, the length of text can't be larger than %u, text = %s",
            CT_MAX_NUMBER_LEN, T2S(&text));
        return CT_ERROR;
    }
    CT_RETURN_IFERR(cm_text2str(&text, buf, CT_MAX_NUMBER_LEN + 1));

    return cm_str2uint64(buf, value);
}


num_errno_t cm_numpart2uint32(const num_part_t *np, uint32 *value)
{
    if (NUMPART_IS_ZERO(np)) {
        *value = 0;
        return NERR_SUCCESS;
    }

    if (np->digit_text.len > CT_MAX_UINT32_PREC ||
        np->has_dot || np->has_expn || np->is_neg) {
        return NERR_ERROR;
    }

    if (np->digit_text.len == CT_MAX_UINT32_PREC) {
        int32 cmp_ret = cm_compare_digitext(&np->digit_text, &g_uint32_ceil);
        if (cmp_ret > 0) {
            return NERR_OVERFLOW;
        } else if (cmp_ret == 0) {
            *value = CT_MAX_UINT32;
            return NERR_SUCCESS;
        }
    }

    *value = 0;
    for (uint32 i = 0; i < np->digit_text.len; ++i) {
        *value = (*value) * CM_DEFAULT_DIGIT_RADIX + CM_C2D(np->digit_text.str[i]);
    }

    return NERR_SUCCESS;
}

/**
* Try to parse an uint32 from text, if the conversion is failed, FALSE
* will be returned

*/
num_errno_t cm_text2uint32_ex(const text_t *text_src, uint32 *value)
{
    num_part_t np;
    num_errno_t err_no;

    np.excl_flag = NF_DOT | NF_EXPN | NF_NEGATIVE_SIGN;
    err_no = cm_split_num_text(text_src, &np);
    CM_CHECK_NUM_ERRNO(err_no);

    return cm_numpart2uint32(&np, value);
}

status_t cm_text2bigint(const text_t *text_src, int64 *value)
{
    char buf[CT_MAX_NUMBER_LEN + 1] = {0};  // '00000000000000000000000000000001'
    text_t text = *text_src;

    cm_trim_text(&text);

    if (text.len > CT_MAX_NUMBER_LEN) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR,
            "Convert int64 failed, the length of text can't be larger than %u, text = %s",
            CT_MAX_NUMBER_LEN, T2S(&text));
        return CT_ERROR;
    }

    CT_RETURN_IFERR(cm_text2str(&text, buf, CT_MAX_NUMBER_LEN + 1));

    return cm_str2bigint(buf, value);
}

num_errno_t cm_numpart2bigint(const num_part_t *np, int64 *value)
{
    if (NUMPART_IS_ZERO(np)) {
        *value = 0;
        return NERR_SUCCESS;
    }

    CT_RETVALUE_IFTRUE((np->digit_text.len > CT_MAX_INT64_PREC || np->has_dot || np->has_expn), NERR_ERROR);

    if (np->digit_text.len == CT_MAX_INT64_PREC) {
        int32 cmp_ret = cm_compare_digitext(&np->digit_text,
                                            np->is_neg ? &g_neg_bigint_ceil : &g_pos_bigint_ceil);
        if (cmp_ret > 0) {
            return NERR_OVERFLOW;
        } else if (cmp_ret == 0) {
            *value = np->is_neg ? CT_MIN_INT64 : CT_MAX_INT64;
            return NERR_SUCCESS;
        }
    }

    int64 val = 0;
    for (uint32 i = 0; i < np->digit_text.len; ++i) {
        if (!CM_IS_DIGIT(np->digit_text.str[i])) {
            CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "np->digit_text.str(%c) should be a digit", np->digit_text.str[i]);
            return NERR_ERROR;
        }
        val = val * CM_DEFAULT_DIGIT_RADIX + CM_C2D(np->digit_text.str[i]);
    }

    *value = np->is_neg ? -val : val;
    return NERR_SUCCESS;
}

/**
* Try to parse a BIGINT from text, if the conversion is failed, FALSE
* will be returned

*/
num_errno_t cm_text2bigint_ex(const text_t *num_text, int64 *value)
{
    num_part_t np;
    num_errno_t err_no;

    np.excl_flag = NF_DOT | NF_EXPN;
    err_no = cm_split_num_text(num_text, &np);
    CM_CHECK_NUM_ERRNO(err_no);

    return cm_numpart2bigint(&np, value);
}

num_errno_t cm_numpart2uint64(const num_part_t *np, uint64 *value)
{
    if (np->digit_text.len > CT_MAX_UINT64_PREC ||
        np->has_dot || np->is_neg || np->has_expn) {
        return NERR_ERROR;
    }

    if (np->digit_text.len == CT_MAX_UINT64_PREC) {
        int32 cmp_ret = cm_compare_digitext(&np->digit_text, &g_uint64_ceil);
        if (cmp_ret > 0) {
            return NERR_OVERFLOW;
        } else if (cmp_ret == 0) {
            *value = CT_MAX_UINT64;
            return NERR_SUCCESS;
        }
    }

    *value = 0;
    for (uint32 i = 0; i < np->digit_text.len; ++i) {
        if (!CM_IS_DIGIT(np->digit_text.str[i])) {
            CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "np->digit_text.str(%c) should be a digit", np->digit_text.str[i]);
            return NERR_ERROR;
        }
        *value = (*value) * CM_DEFAULT_DIGIT_RADIX + CM_C2D(np->digit_text.str[i]);
    }

    return NERR_SUCCESS;
}

/**
* Try to parse a UINT64 from text, if the conversion is failed, FALSE
* will be returned

*/
num_errno_t cm_text2uint64_ex(const text_t *num_text, uint64 *value)
{
    num_part_t np;
    num_errno_t err_no;

    np.excl_flag = NF_DOT | NF_EXPN | NF_NEGATIVE_SIGN;
    err_no = cm_split_num_text(num_text, &np);

    CM_CHECK_NUM_ERRNO(err_no);

    return cm_numpart2uint64(&np, value);
}

static bool32 cm_is_err(const char *err)
{
    if (err == NULL) {
        return CT_FALSE;
    }

    while (*err != '\0') {
        if (*err != ' ') {
            return CT_TRUE;
        }
        err++;
    }

    return CT_FALSE;
}

status_t cm_str2int(const char *str, int32 *value)
{
    char *err = NULL;
    int64 val_int64 = strtol(str, &err, CM_DEFAULT_DIGIT_RADIX);
    if (cm_is_err(err)) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "Convert int32 failed, text = %s", str);
        return CT_ERROR;
    }

    if (val_int64 > INT_MAX || val_int64 < INT_MIN) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR,
                          "Convert int32 failed, the number text is not in the range of int32, text = %s", str);
        return CT_ERROR;
    }

    *value = (int32)val_int64;
    return CT_SUCCESS;
}

status_t cm_str2uint16(const char *str, uint16 *value)
{
    char *err = NULL;
    int64 val_int64 = strtol(str, &err, CM_DEFAULT_DIGIT_RADIX);
    if (cm_is_err(err)) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "Convert uint16 failed, text = %s", str);
        return CT_ERROR;
    }

    if (val_int64 > USHRT_MAX || val_int64 < 0) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR,
                          "Convert uint16 failed, the number text is not in the range of uint16, text = %s", str);
        return CT_ERROR;
    }

    *value = (uint16)val_int64;
    return CT_SUCCESS;
}

status_t cm_str2uint32(const char *str, uint32 *value)
{
    char *err = NULL;
    int64 val_int64 = strtoll(str, &err, CM_DEFAULT_DIGIT_RADIX);
    if (cm_is_err(err)) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "Convert uint32 failed, text = %s", str);
        return CT_ERROR;
    }

    if (val_int64 > UINT_MAX || val_int64 < 0) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR,
                          "Convert uint32 failed, the number text is not in the range of uint32, text = %s", str);
        return CT_ERROR;
    }

    *value = (uint32)val_int64;
    return CT_SUCCESS;
}

status_t cm_str2bigint(const char *str, int64 *value)
{
    char *err = NULL;
    *value = strtoll(str, &err, CM_DEFAULT_DIGIT_RADIX);
    if (cm_is_err(err)) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "Convert int64 failed, text = %s", str);
        return CT_ERROR;
    }
    // if str = "9223372036854775808", *value will be LLONG_MAX
    if (*value == LLONG_MAX || *value == LLONG_MIN) {
        if (cm_compare_str(str, (const char *)SIGNED_LLONG_MIN) != 0 &&
            cm_compare_str(str, (const char *)SIGNED_LLONG_MAX) != 0) {
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR,
                "Convert int64 failed, the number text is not in the range of signed long long, text = %s", str);
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t cm_str2uint64(const char *str, uint64 *value)
{
    char *err = NULL;
    *value = strtoull(str, &err, CM_DEFAULT_DIGIT_RADIX);
    if (cm_is_err(err)) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "Convert uint64 failed, text = %s", str);
        return CT_ERROR;
    }

    if (*value == ULLONG_MAX) {  // if str = "18446744073709551616", *value will be ULLONG_MAX
        if (cm_compare_str(str, (const char *)UNSIGNED_LLONG_MAX) != 0) {
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR,
                "Convert int64 failed, the number text is not in the range of unsigned long long, text = %s", str);
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t cm_text2real(const text_t *text_src, double *value)
{
    char buf[CT_MAX_REAL_INPUT_STRLEN + 1] = {0};
    text_t text = *text_src;

    cm_trim_text(&text);

    if (text.len > CT_MAX_REAL_INPUT_STRLEN) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR,
                          "Convert double failed, the length(%u) of text can't be larger than %u, text = %s", text.len,
                          CT_MAX_REAL_INPUT_STRLEN, T2S(&text));
        return CT_ERROR;
    }
    CT_RETURN_IFERR(cm_text2str(&text, buf, CT_MAX_REAL_INPUT_STRLEN + 1));

    return cm_str2real(buf, value);
}

num_errno_t cm_numpart2real(num_part_t *np, double *value)
{
    int32 expn;

    if (np->sci_expn > CT_MAX_REAL_EXPN) {
        return NERR_OVERFLOW;
    }

    if (np->sci_expn == CT_MAX_REAL_EXPN) {
        if (cm_compare_digitext(&np->digit_text, &g_double_ceil) > 0) {
            return NERR_OVERFLOW;
        }
    } else if (np->sci_expn < CT_MIN_REAL_EXPN) {
        *value = 0.0;
        return NERR_SUCCESS;
    }

    expn = np->sci_expn - (int32)(np->digit_text.len) + 1 + (int32)np->do_round;

    int32 code = snprintf_s(CM_GET_TAIL(&np->digit_text), CT_MAX_NUM_PART_BUFF - np->digit_text.len,
        CT_MAX_NUM_PART_BUFF - np->digit_text.len - 1, "E%d", expn);
    if (SECUREC_UNLIKELY(code == -1)) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, code);
        return NERR_ERROR;
    }

    *value = atof(np->digit_text.str);

    if (np->is_neg) {
        *value = -(*value);
    }
    return NERR_SUCCESS;
}

num_errno_t cm_text2real_ex(const text_t *text_src, double *value)
{
    num_part_t np;
    num_errno_t err_no;

    np.excl_flag = NF_NONE;
    err_no = cm_split_num_text(text_src, &np);
    CM_CHECK_NUM_ERRNO(err_no);

    return cm_numpart2real(&np, value);
}

num_errno_t cm_text2real_ex_no_check_err(const text_t *text_src, double *value)
{
    num_part_t np;
    num_errno_t err_no;

    np.excl_flag = NF_NONE;
    err_no = cm_split_num_text(text_src, &np);
    CM_NO_CHECK_NUM_ERRNO(err_no);

    return cm_numpart2real(&np, value);
}

status_t cm_str2real(const char *str, double *value)
{
    char *err = NULL;
    *value = strtod(str, &err);
    if (cm_is_err(err)) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "Convert double failed, text = %s", str);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

/**
 * try to convert any c-string into double. If the conversion is success,
 * the return value is CT_TRUE and val is the converted value; else CT_FALSE
 * is returned.
 * @note the c-string is formed by an optional sign character (+ or -),
 * followed by a sequence of digits, optionally containing a decimal-point
 * character (.), optionally followed by an exponent part (an e or E
 * character followed by an optional sign and a sequence of digits).
 * e.g., the following c-string is allowed:
 * '123123', '0.2343', '-23542354', '   34563456.3' (leading space),
 * '+3254.34', '34532.3434E100', '4e12'
 *
 * the following is not allowed:
 * '1234erewr', '23423.123.23423', 'E3254345', '123E123.232'
 *

 */
bool32 cm_str2real_ex(const char *str, double *val)
{
    text_t text;
    cm_str2text((char *)str, &text);
    return cm_text2real_ex(&text, val) == NERR_SUCCESS;
}

/**
 * Try to parse an int16 from text
 */
num_errno_t cm_text2int16_ex(const text_t *text, int32 *val)
{
    char c;
    bool32 is_neg = CT_FALSE;
    uint32 i = 0;

    // handle the sign
    c = text->str[i];
    if (CM_IS_SIGN_CHAR(c)) {
        is_neg = (c == '-');
        c = text->str[++i];  // move to next character
    }

    /* if no digits, return error  */
    CT_RETVALUE_IFTRUE((i >= text->len), NERR_NO_DIGIT);

    *val = 0;
    // skip leading zeros
    while (CM_IS_ZERO(c)) {
        ++i;
        // all text are zeros, return 0
        if (i >= text->len) {
            return NERR_SUCCESS;
        }
        c = text->str[i];
    }

    // found the first non-zero digit
    // too many nonzero exponent digits, the number of significant digits
    // must be no less than 5
    CT_RETVALUE_IFTRUE((text->len >= (6 + i)), NERR_INVALID_LEN);

    for (;;) {
        // invalid number text with unexpected characters
        CT_RETVALUE_IFTRUE((!CM_IS_DIGIT(c)), NERR_UNEXPECTED_CHAR);
        *val = (*val) * CM_DEFAULT_DIGIT_RADIX + CM_C2D(c);

        ++i;
        CT_BREAK_IF_TRUE(i >= text->len);
        c = text->str[i];
    }
    // overflow
    CT_RETVALUE_IFTRUE((*val != (int16)(*val)), NERR_OVERFLOW);

    if (is_neg) {
        *val = -(*val);
    }
    return NERR_SUCCESS;
}

uint32 cm_bool2str(bool32 value, char *str)
{
    text_t text;
    CM_POINTER(str);

    text.str = str;
    text.len = 0;
    cm_bool2text(value, &text);
    CM_NULL_TERM(&text);
    return text.len;
}

static bool32 cm_diag_int(const text_t *text, const digitext_t *dtext, num_part_t *np)
{
    uint32 i;
    bool32 is_neg = CT_FALSE;
    text_t num_text = *text;

    cm_trim_text(&num_text);

    CT_RETVALUE_IFTRUE((num_text.len == 0), CT_FALSE);

    if (CM_IS_SIGN_CHAR(num_text.str[0])) {
        is_neg = ('-' == num_text.str[0]);
        CM_REMOVE_FIRST(&num_text);
    }

    // skipping leading zeros
    cm_text_ltrim_zero(&num_text);

    for (i = 0; i < num_text.len; i++) {
        if (i >= dtext->len || !CM_IS_DIGIT(num_text.str[i])) {
            return CT_FALSE;
        }
    }

    text_t num_dtext = { .str = (char *)dtext->str, .len = dtext->len };
    CT_RETVALUE_IFTRUE((num_text.len == dtext->len && cm_compare_text(&num_text, &num_dtext) > 0), CT_FALSE);

    if (np != NULL) {
        cm_text2digitext(&num_text, &np->digit_text);
        np->digit_text.len = num_text.len;
        np->has_dot = CT_FALSE;
        np->has_expn = CT_FALSE;
        np->is_neg = is_neg;
    }

    return CT_TRUE;
}

bool32 cm_is_short(const text_t *text)
{
    return cm_diag_int(text, &g_int16_ceil, NULL);
}

bool32 cm_is_int(const text_t *text)
{
    return cm_diag_int(text, &g_pos_int32_ceil, NULL);
}

bool32 cm_is_bigint(const text_t *text, num_part_t *np)
{
    return cm_diag_int(text, &g_pos_bigint_ceil, np);
}

/* Decide whether the num_part is REAL or DECIMAL type, if overflow,
 * return false. */
static inline num_errno_t cm_decide_decimal_type(const num_part_t *np, ct_type_t *type)
{
    if (np->sci_expn < CT_MAX_REAL_EXPN) {
        // Rule 2.1: if sci_exp > MAX_NUMERIC_EXPN, then it is a double type
        // Rule 2.2: if sci_exp < MIN_NUMERIC_EXPN, then it is a double zero
        // Rule 2.3: used as decimal type
        *type = (np->sci_expn > MAX_NUMERIC_EXPN || np->sci_expn < MIN_NUMERIC_EXPN) ? CT_TYPE_REAL : CT_TYPE_NUMBER;
        return NERR_SUCCESS;
    } else if (np->sci_expn == CT_MAX_REAL_EXPN) {
        CT_RETVALUE_IFTRUE((cm_compare_digitext(&np->digit_text, &g_double_ceil) > 0), NERR_OVERFLOW);
        // less than the maximal representable double
        *type = CT_TYPE_REAL;
        return NERR_SUCCESS;
    }

    // sci_exp > CT_MAX_REAL_EXPN
    return NERR_OVERFLOW;
}

/* Decide type of an integer num_part, if the num_part is
 * + in the range of an int32, type = CT_TYPE_INTEGER;
 * + in the range of an bigint, type = CT_TYPE_BIGINT;
 * + else, return number type */
static inline num_errno_t cm_decide_integer_type(const num_part_t *np, ct_type_t *type)
{
    const digitext_t *cmp_text = NULL;
    /* Rule 4: no dot and no expn */
    /* Rule 4.1: the precision less than the maximal length of an int32 */
    if (np->digit_text.len < CT_MAX_INT32_PREC) {
        *type = CT_TYPE_INTEGER;
        return NERR_SUCCESS;
    }
    /* Rule 4.2: the precision equal to the maximal length of an int32/ uint32 */
    if (np->digit_text.len == CT_MAX_INT32_PREC) {
        *type = CT_TYPE_INTEGER;
        if (np->is_neg) {
            if (cm_compare_digitext(&np->digit_text, &g_neg_int32_ceil) > 0) {
                *type = CT_TYPE_BIGINT;
            }
        } else {
            if (cm_compare_digitext(&np->digit_text, &g_pos_int32_ceil) > 0) {
                *type = (cm_compare_digitext(&np->digit_text, &g_uint32_ceil) <= 0) ? CT_TYPE_UINT32 : CT_TYPE_BIGINT;
            }
        }

        return NERR_SUCCESS;
    }
    /* Rule 4.3: the precision less than the maximal length of an int64 */
    if (np->digit_text.len < CT_MAX_INT64_PREC) {
        *type = CT_TYPE_BIGINT;
        return NERR_SUCCESS;
    }

    if (np->digit_text.len == CT_MAX_INT64_PREC) {
        cmp_text = np->is_neg ? &g_neg_bigint_ceil : &g_pos_bigint_ceil;
        *type = (cm_compare_digitext(&np->digit_text, cmp_text) > 0) ? CT_TYPE_NUMBER : CT_TYPE_BIGINT;
        return NERR_SUCCESS;
    }
    
    if (np->digit_text.len == CT_MAX_UINT64_PREC) {
        if (np->is_neg) {
            *type = CT_TYPE_NUMBER;
        } else {
            *type = (cm_compare_digitext(&np->digit_text, &g_uint64_ceil) > 0) ? CT_TYPE_NUMBER : CT_TYPE_UINT64;
        }
        return NERR_SUCCESS;
    }

    if (np->digit_text.len <= CT_MAX_NUM_PRECISION) {
        *type = CT_TYPE_NUMBER;
        return NERR_SUCCESS;
    }
    return NERR_ERROR;
}

num_errno_t cm_decide_numtype(const num_part_t *np, ct_type_t *type)
{
    // Decide the datatype of numeric text
    // Rule 1: if the base part is zero(s), return integer 0
    if (NUMPART_IS_ZERO(np) && !np->has_dot && !np->has_expn) {
        *type = CT_TYPE_INTEGER;
        return NERR_SUCCESS;
    }

    // Rule 2: if expn or dot exist, or the text is too long
    if (np->has_expn || np->has_dot || np->digit_text.len > CT_MAX_INT64_PREC) {
        return cm_decide_decimal_type(np, type);
    }

    return cm_decide_integer_type(np, type);
}

/**
* Scan the NUMERIC text, and identify its validation and return its datatype
* @param
* -- precision: records the precision of the num_text. The initial value
*               is -1, indicating no significant digit found. When a leading zero
*               is found, the precision is set to 0, it means the merely
*               significant digit is zero. precision > 0 represents the
*               number of significant digits in the numeric text.
* @see  cm_text2dec
* @note the maximal possible exponent of the numeric text is restricted in the
*       range of int16

*/
num_errno_t cm_is_number_with_sign(const text_t *text, ct_type_t *type)
{
    num_part_t np;
    num_errno_t err_no;

    np.excl_flag = NF_NONE;
    err_no = cm_split_num_text(text, &np);
    CM_CHECK_NUM_ERRNO(err_no);

    return cm_decide_numtype(&np, type);
}

num_errno_t cm_is_number(const text_t *text, ct_type_t *type)
{
    return cm_is_number_with_sign(text, type);
}

/** recording the significand digits into num_part */
static inline void cm_record_digit(num_part_t *np, int32 *precision,
                                   int32 *prec_offset, int32 pos, char c)
{
    if (*precision >= 0) {
        ++(*precision);
        if (*precision > (MAX_NUMERIC_BUFF + 1)) {
            // if the buff is full, ignoring the later digits
            return;
        } else if (*precision == (MAX_NUMERIC_BUFF + 1)) {
            // mark the rounding mode is needed
            np->do_round = (c >= '5');
            return;
        }
    } else {
        *precision = 1;
    }

    if (*precision == 1) {
        // if found the first significant digit, records its position
        *prec_offset = pos;
    }
    CM_TEXT_APPEND(&np->digit_text, c);
}

/** calculate expn of the significand digits, confirm the sci_expn is even **/
static inline void cm_calc_significand_expn(int32 dot_offset, int32 prec_offset, int32 precision, num_part_t *np)
{
    int offset;
    int32 dot_offset_t = dot_offset;
    // Step 3.1. compute the sci_exp
    if (dot_offset_t >= 0) { /* if a dot exists */
        /* Now, prec_offset records the distance from the first significant digit to the dot.
        * dot_offset > 0 means dot is counted, thus this means the sci_exp should subtract one.  */
        dot_offset_t -= prec_offset;
        offset = ((dot_offset_t > 0) ? dot_offset_t - 1 : dot_offset_t);
    } else {
        offset = precision - 1;
    }
    np->sci_expn += offset;
}

/** CM_MAX_EXPN must greater than the maximal exponent that DB can capacity.
 * In current system, the maximal exponent is 308 for double. Therefore, the
 * value is set to 99999999 is reasonable. */
#define CM_MAX_EXPN 99999999

/**
* Parse an exponent from the numeric text *dec_text*, i is the offset
* of exponent. When unexpected character occur or the exponent overflow,
* an error will be returned.

*/
static inline num_errno_t cm_parse_num_expn(text_t *expn_text, int32 *expn)
{
    char c;
    int32 tmp_exp;
    bool32 is_negexp = CT_FALSE;
    uint32 i = 0;

    // handle the sign of exponent
    c = expn_text->str[i];
    if (CM_IS_SIGN_CHAR(c)) {
        is_negexp = (c == '-');
        c = expn_text->str[++i];  // move to next character
    }
    if (i >= expn_text->len) { /* if no exponent digits, return error  */
        CT_RETVALUE_IFTRUE((i >= expn_text->len), NERR_NO_EXPN_DIGIT);
    }

    // skip leading zeros in the exponent
    while (CM_IS_ZERO(c)) {
        ++i;
        if (i >= expn_text->len) {
            *expn = 0;
            return NERR_SUCCESS;
        }
        c = expn_text->str[i];
    }

    // too many nonzero exponent digits
    tmp_exp = 0;
    for (;;) {
        CT_RETVALUE_IFTRUE((!CM_IS_DIGIT(c)), NERR_EXPN_WITH_NCHAR);

        if (tmp_exp < CM_MAX_EXPN) {  // to avoid int32 overflow
            tmp_exp = tmp_exp * CM_DEFAULT_DIGIT_RADIX + CM_C2D(c);
        }

        ++i;
        if (i >= expn_text->len) {
            break;
        }
        c = expn_text->str[i];
    }

    // check exponent overflow on positive integer
    CT_RETVALUE_IFTRUE((!is_negexp && tmp_exp > CM_MAX_EXPN), NERR_OVERFLOW);

    *expn = is_negexp ? -tmp_exp : tmp_exp;

    return NERR_SUCCESS;
}

num_errno_t cm_split_num_text(const text_t *num_text, num_part_t *np)
{
    int32 i;
    char c;
    text_t text;                   /** the temporary text */
    int32 dot_offset = -1;         /** '.' offset, -1 if none */
    int32 prec_offset = -1;        /** the offset of the first significant digit, -1 if none */
    int32 precision = -1;          /* see comments of the function */
    bool32 leading_flag = CT_TRUE; /** used to ignore leading zeros */

    /* When the number of significant digits exceeds the dight_buf
                                     * Then, a round happens when the MAX_NUMERIC_BUFF+1 significant
                                     * digit is equal and greater than '5' */
    CM_POINTER2(num_text, np);
    np->digit_text.len = 0;
    np->has_dot = CT_FALSE;
    np->has_expn = CT_FALSE;
    np->do_round = CT_FALSE;
    np->is_neg = CT_FALSE;
    np->sci_expn = 0;

    text = *num_text;
    cm_trim_text(&text);

    CT_RETVALUE_IFTRUE((text.len == 0 || text.len >= SIZE_M(1)), NERR_INVALID_LEN);  // text.len > 2^15

    i = 0;
    /* Step 1. fetch the sign of the decimal */
    if (text.str[i] == '-') {  // leading minus means negative
        // if negative sign is not allowed
        CT_RETVALUE_IFTRUE((np->excl_flag & NF_NEGATIVE_SIGN), NERR_UNALLOWED_NEG);
        np->is_neg = CT_TRUE;
        i++;
    } else if (text.str[i] == '+') {  // leading + allowed
        i++;
    }

    /* check again */
    CT_RETVALUE_IFTRUE((i >= (int32)text.len), NERR_NO_DIGIT);

    /* Step 2. parse the scale, exponent, precision, Significant value of the decimal */
    for (; i < (int32)text.len; ++i) {
        c = text.str[i];
        if (leading_flag) {  // ignoring leading zeros
            if (CM_IS_ZERO(c)) {
                precision = 0;
                continue;
            } else if (c != '.') {
                leading_flag = CT_FALSE;
            }
        }

        if (CM_IS_DIGIT(c)) {  // recording the significand
            cm_record_digit(np, &precision, &prec_offset, i, c);
            continue;
        }

        if (CM_IS_DOT(c)) {
            CT_RETVALUE_IFTRUE((np->excl_flag & NF_DOT), NERR_UNALLOWED_DOT);

            CT_RETVALUE_IFTRUE((dot_offset >= 0), NERR_MULTIPLE_DOTS);

            dot_offset = i;  //
            np->has_dot = CT_TRUE;
            continue;
        }

        // begin to handle and fetch exponent
        CT_RETVALUE_IFTRUE((!CM_IS_EXPN_CHAR(c)), NERR_UNEXPECTED_CHAR);

        // Exclude: 'E0012', '.E0012', '-E0012', '+.E0012', .etc
        CT_RETVALUE_IFTRUE((precision < 0), NERR_UNEXPECTED_CHAR);
        CT_RETVALUE_IFTRUE((np->excl_flag & NF_EXPN), NERR_UNALLOWED_EXPN);

        // redirect text pointing to expn part
        text.str += (i + 1);
        text.len -= (i + 1);
        num_errno_t nerr = cm_parse_num_expn(&text, &np->sci_expn);
        CT_RETVALUE_IFTRUE((nerr != NERR_SUCCESS), nerr);
        np->has_expn = CT_TRUE;
        break;
    }  // end for

    CT_RETVALUE_IFTRUE((precision < 0), NERR_NO_DIGIT);

    if (precision == 0) {
        CM_ZERO_NUMPART(np);
        return NERR_SUCCESS;
    }

    // Step 3: Calculate the scale of the total number text
    cm_calc_significand_expn(dot_offset, prec_offset, precision, np);
    
    if (np->digit_text.len > num_text->len || np->digit_text.len >= CT_MAX_NUM_PART_BUFF) {
        CT_THROW_ERROR_EX(ERR_ASSERT_ERROR,
            "np->digit_text.len(%u) <= num_text->len(%u) and np->digit_text.len(%u) < CT_MAX_NUM_PART_BUFF(%d)",
            np->digit_text.len, num_text->len, np->digit_text.len, CT_MAX_NUM_PART_BUFF);
        return NERR_ERROR;
    }
    return NERR_SUCCESS;
}

/**
 * Split a text by split_char starting from 0, if split_char is enclosed by
 * *enclose_char*, it will be skipped. Note that enclose_char = 0 means no
 * enclose_char.
 *
 * If no split_char is found, the left = text, and the right = empty_text
 * @see cm_split_rtext

 */
void cm_split_text(const text_t *text, char split_char, char enclose_char, text_t *left, text_t *right)
{
    uint32 i;
    bool32 is_enclosed = CT_FALSE;

    left->str = text->str;

    for (i = 0; i < text->len; i++) {
        if (enclose_char != 0 && text->str[i] == enclose_char) {
            is_enclosed = !is_enclosed;
            continue;
        }

        if (is_enclosed) {
            continue;
        }

        if (text->str[i] == split_char) {
            left->len = i;
            right->str = text->str + i + 1;
            right->len = text->len - (i + 1);
            return;
        }
    }
    /* if the split_char is not found */
    left->len = text->len;
    right->len = 0;
    right->str = NULL;
}

/**
 * Reversely split a text from starting from its end, if the *split_char*
 * is enclosed in *enclose_char*, then skipping it.
 * @note enclose_char = 0 means no enclose_char.
 * @note If no split_char is found, the left = text, and the right = empty_text
 * @see cm_split_text

 */
bool32 cm_split_rtext(const text_t *text, char split_char, char enclose_char, text_t *left, text_t *right)
{
    int32 i;
    bool32 is_enclosed = CT_FALSE;

    left->str = text->str;
    for (i = (int32)text->len; i-- > 0;) {
        if (enclose_char != 0 && text->str[i] == enclose_char) {
            is_enclosed = !is_enclosed;
            continue;
        }

        if (is_enclosed) {
            continue;
        }

        if (text->str[i] == split_char) {
            left->len = (uint32)i;
            right->str = text->str + i + 1;
            right->len = text->len - (i + 1);
            return CT_TRUE;
        }
    }

    /* if the split_char is not found */
    left->len = text->len;
    right->len = 0;
    right->str = NULL;
    return CT_FALSE;
}

void cm_trim_number(text_t *text, bool32 has_dot)
{
    int32 i;

    CT_RETVOID_IFTRUE(text->len <= 1);

    uint32 trim_count = 0;
    // remove leading zeros to
    for (i = 0; i < (int32)text->len - 1; i++) {
        if (text->str[i] == '0' && text->str[i + 1] != '.') {
            trim_count++;
        } else {
            break;
        }
    }

    text->len -= trim_count;
    text->str += trim_count;

    CT_RETVOID_IFTRUE(!has_dot);

    trim_count = 0;
    for (i = (int32)(text->len - 1); i > 0; i--) {
        if (text->str[i] == '0' && text->str[i - 1] != '.') {
            trim_count++;
        } else {
            break;
        }
    }

    text->len -= trim_count;
}

status_t cm_text2size(const text_t *text, int64 *value)
{
    text_t num = *text;
    uint64 unit = 1;
    double size;

    switch (CM_TEXT_END(text)) {
        case 'k':
        case 'K':
            unit <<= 10;
            break;

        case 'm':
        case 'M':
            unit <<= 20;
            break;

        case 'g':
        case 'G':
            unit <<= 30;
            break;

        case 't':
        case 'T':
            unit <<= 40;
            break;

        case 'p':
        case 'P':
            unit <<= 50;
            break;

        case 'e':
        case 'E':
            unit <<= 60;
            break;
        case 'b':
        case 'B':
            num.len--;
        // fall through
        default:
            break;
    }

    if (unit != 1) {
        num.len--;
    }

    CT_RETURN_IFERR(cm_text2real(&num, &size));

    *value = (int64)(size * unit);
    return CT_SUCCESS;
}

status_t cm_text2microsecond(const text_t *text, uint64 *value)
{
    text_t num = *text;
    uint32 second = 0;
    uint64 microsecond = 0;
    uint16 displace = 0;
    char endchar = CM_TEXT_END(text);
    if (endchar == 's' || endchar == 'S') {
        if (CM_TEXT_SECONDTOLAST(text) == 'm' || CM_TEXT_SECONDTOLAST(text) == 'M') {
            displace = 2;
        }
        if (CM_TEXT_SECONDTOLAST(text) >= '0' && CM_TEXT_SECONDTOLAST(text) <= '9') {
            displace = 1;
        }
    }

    if (displace == 1) {
        num.len--;
    }

    if (displace == 2) {
        num.len -= 2;
    }

    if (displace == 1 || displace == 0) {
        if (cm_text2uint32(&num, &second) != CT_SUCCESS) {
            return CT_ERROR;
        }
        *value = (uint64)second * MICROSECS_PER_SECOND;
    }

    if (displace == 2) {
        if (cm_text2uint64(&num, &microsecond) != CT_SUCCESS) {
            return CT_ERROR;
        }
        if (microsecond > MAX_MILLISECOND) {
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR,
                "Convert millisecond failed, the number text is not in the range, text = %llu", microsecond);
            return CT_ERROR;
        }
        *value = microsecond * MICROSECS_PER_MILLISEC;
    }
    return CT_SUCCESS;
}

status_t cm_str2size(const char *str, int64 *value)
{
    text_t text;
    cm_str2text((char *)str, &text);
    return cm_text2size(&text, value);
}

status_t cm_str2microsecond(const char *str, uint64 *value)
{
    text_t text;
    cm_str2text((char *)str, &text);
    return cm_text2microsecond(&text, value);
}

num_errno_t cm_numpart2size(const num_part_t *np, int64 *value)
{
    int64 unit;
    num_errno_t err_no = cm_numpart2bigint(np, value);
    CM_CHECK_NUM_ERRNO(err_no);

    CT_RETVALUE_IFTRUE((*value < 0), NERR_EXPECTED_POS_INT);

    unit = 0;
    switch (np->sz_indicator) {
        case 'k':
        case 'K':
            unit = 10;
            break;

        case 'm':
        case 'M':
            unit = 20;
            break;

        case 'g':
        case 'G':
            unit = 30;
            break;

        case 't':
        case 'T':
            unit = 40;
            break;

        case 'p':
        case 'P':
            unit = 50;
            break;

        case 'e':
        case 'E':
            unit = 60;
            break;

        default:
        case 'b':
        case 'B':
            break;
    }

    // overflow
    CT_RETVALUE_IFTRUE((*value > (CT_MAX_INT64 >> unit)), NERR_OVERFLOW);

    *value = *value << unit;
    return NERR_SUCCESS;
}

/* Fetch a text starting from 0, if the *split_char* is
 * enclosed in *enclose_char*, then skipping it. If the input text is
 * empty, then FALSE is returned.
 * @see cm_fetch_text, cm_split_text, cm_split_rtext
 * */
bool32 cm_fetch_text(text_t *text, char split_char, char enclose_char, text_t *sub)
{
    text_t remain;
    if (text->len == 0) {
        CM_TEXT_CLEAR(sub);
        return CT_FALSE;
    }

    cm_split_text(text, split_char, enclose_char, sub, &remain);

    text->len = remain.len;
    text->str = remain.str;
    return CT_TRUE;
}

/* Reversely fetch a text starting from its end, if the *split_char* is
 * enclosed in *enclose_char*, then skipping it. If the input text is
 * empty, then FALSE is returned.
 * @see cm_fetch_text, cm_split_text, cm_split_rtext
 * */
bool32 cm_fetch_rtext(text_t *text, char split_char, char enclose_char, text_t *sub)
{
    if (text->len == 0) {
        CM_TEXT_CLEAR(sub);
        return CT_FALSE;
    }

    return cm_split_rtext(text, split_char, enclose_char, sub, text);
}

bool32 cm_is_enclosed(const text_t *text, char enclosed_char)
{
    if (text->len < 2) {
        return CT_FALSE;
    }

    if (enclosed_char == (CM_TEXT_BEGIN(text)) && (enclosed_char == CM_TEXT_END(text))) {
        return CT_TRUE;
    }
    return CT_FALSE;
}

bool32 cm_fetch_line(text_t *text, text_t *line, bool32 eof)
{
    text_t remain;
    if (text->len == 0) {
        CM_TEXT_CLEAR(line);
        return CT_FALSE;
    }

    cm_split_text(text, '\n', '\0', line, &remain);

    if (remain.len == text->len) { /* no spilting char found */
        if (!eof) {
            CM_TEXT_CLEAR(line);
            return CT_FALSE;
        }

        line->len = remain.len;
        line->str = remain.str;
        CM_TEXT_CLEAR(text);
        return CT_TRUE;
    }

    text->len = remain.len;
    text->str = remain.str;
    return CT_TRUE;
}

uint32 cm_instrb(const text_t *str, const text_t *substr, int32 pos, uint32 nth)
{
    uint32 start = 0;

    if ((uint32)abs(pos) > str->len || pos == 0 || str->len < substr->len) {
        return 0;
    }

    // get start bytes pos
    if (pos > 0) {
        // search forward
        start = (uint32)(pos - 1);
    } else {
        // search backward
        start = (uint32)(str->len + pos);
    }

    // get result bytes pos
    return cm_instr_core(str, substr, pos, nth, start);
}

char *cm_strchr(const text_t *str, const int32 c)
{
    for (uint32 i = 0; i < str->len; ++i) {
        if (str->str[i] == c) {
            return str->str + i;
        }
    }

    return NULL;
}

void cm_str_upper(char *str)
{
    char *tmp = NULL;

    CM_POINTER(str);

    tmp = str;
    while (*tmp != '\0') {
        *tmp = UPPER(*tmp);
        tmp++;
    }

    return;
}

void cm_str_lower(char *str)
{
    char *tmp = NULL;

    CM_POINTER(str);

    tmp = str;
    while (*tmp != '\0') {
        *tmp = LOWER(*tmp);
        tmp++;
    }

    return;
}
/* calculate how many different character bits of two strings,for example:
1."abc" and "ab"  : one different character bit
2."abc" and  "accd" : two different character bits
3."abc" and "dabc" : four different character bits
*/
size_t cm_str_diff_chars(const char *src, const char *dst)
{
    size_t i, diff_chars;
    size_t src_len = strlen(src);
    size_t dst_len = strlen(dst);
    size_t min_len = MIN(src_len, dst_len);
    if (src_len >= dst_len) {
        diff_chars = src_len - dst_len;
    } else {
        diff_chars = dst_len - src_len;
    }
    for (i = 0; i < min_len; i++) {
        if (src[i] != dst[i]) {
            diff_chars++;
        }
    }
    return diff_chars;
}

void cm_str_reverse(char *dst, const char *src, uint32 dst_len)
{
    uint32 i;
    size_t len = strlen(src);
    if (len >= dst_len) {
        CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "len(%lu) < dst_len(%u)", len, dst_len);
        return;
    }

    for (i = 0; i < len; i++) {
        dst[i] = src[len - 1 - i];
    }
    dst[len] = '\0';
}

void cm_text_upper(text_t *text)
{
    uint32 i;

    for (i = 0; i < text->len; i++) {
        text->str[i] = UPPER(text->str[i]);
    }
}

void cm_text_upper_self_name(text_t *name)
{
    if (!(CM_TEXT_BEGIN(name) == '\"' || CM_TEXT_BEGIN(name) == '`')) {
        cm_text_upper(name);
    }
}

void cm_text_lower(text_t *text)
{
    uint32 i;

    for (i = 0; i < text->len; i++) {
        text->str[i] = LOWER(text->str[i]);
    }
}

bool32 cm_is_unsigned_int(const char *num)
{
    uint32 i = 0;
    size_t len = strlen(num);
    if (len > CT_MAX_INT32_STRLEN) {
        CT_THROW_ERROR_EX(ERR_GENERIC_INTERNAL_ERROR, "'%s' is too long for unsigned int", num);
        return CT_FALSE;
    }

    for (i = 0; i < len; i++) {
        if (!(num[i] >= '0' && num[i] <= '9')) {
            CT_THROW_ERROR_EX(ERR_GENERIC_INTERNAL_ERROR, "character '%c' is invalid for unsigned int", num[i]);
            return CT_FALSE;
        }
    }

    return CT_TRUE;
}

/**
 * Truncate a text from tailing to the maximal. If the text is too long
 * '...' is appended.

 */
void cm_truncate_text(text_t *text, uint32 max_len)
{
    if (text == NULL || text->str == NULL) {
        CT_THROW_ERROR(ERR_ASSERT_ERROR, "text != NULL and text->str != NULL");
        return;
    }
    if (text->len > max_len && max_len > 3) {
        text->len = max_len - 3;
        CM_TEXT_APPEND(text, '.');
        CM_TEXT_APPEND(text, '.');
        CM_TEXT_APPEND(text, '.');
    }
    CM_NULL_TERM(text);
}

status_t cm_substrb(const text_t *src, int32 start, uint32 size, text_t *dst)
{
    uint32 copy_size;
    int32 start_internal = start;
    if ((uint32)abs(start_internal) > src->len) {
        dst->len = 0;
        return CT_SUCCESS;
    }
    if (start_internal > 0) {
        start_internal--;
    } else if (start_internal < 0) {
        start_internal = (int32)src->len + start_internal;
    }

    copy_size = ((uint32)(src->len - start_internal)) > size ? size : ((uint32)(src->len - start_internal));
    if (copy_size > 0) {
        MEMS_RETURN_IFERR(memcpy_sp(dst->str, copy_size, src->str + start_internal, copy_size));
    }
    dst->len = copy_size;
    return CT_SUCCESS;
}

status_t cm_replace_quotation(char *src, char *dest, uint32 dest_len, bool32 *exist_flag)
{
    char *src_tmp = NULL;
    char *dest_tmp = NULL;
    *exist_flag = CT_FALSE;

    CM_POINTER(src);

    src_tmp = src;

    while (*src_tmp != '\0') {
        if (*src_tmp == '\'') {
            *exist_flag = CT_TRUE;
            break;
        }
        src_tmp++;
    }

    if (*exist_flag) {
        src_tmp = src;
        dest_tmp = dest;
        uint32 count = 0;
        while (*src_tmp != '\0') {
            if (count >= dest_len - 1) {
                CT_THROW_ERROR(ERR_OUT_OF_INDEX, "dest_tmp", dest_len);
                return CT_ERROR;
            }
            count++;
            *dest_tmp = *src_tmp;

            if (*src_tmp == '\'') {
                dest_tmp++;
                *dest_tmp = '\'';
            }
            src_tmp++;
            dest_tmp++;
        }

        *dest_tmp = '\0';
    }

    return CT_SUCCESS;
}

#define CM_IS_SPACE(c)         ((c) == ' ')
#define CM_IS_ENCLOSED_CHAR(c) ((c) == '\'' || (c) == '"' || (c) == '`')
#define CM_IS_NOTE(c)          ((c) == '/')
#define CM_IS_LINE(c)          ((c) == '-')
#define CM_IS_RETURN(c)        ((c) == '\n')
#define CM_IS_LABEL(c)         ((c) == '<')
#define CM_IS_SPLIT_CHAR(c)    ((c) == ';')

const char cm_note_str[4] = { '/',       '*', '*', '/' };
const char cm_label_str[4] = { '<',       '<', '>', '>' };
const text_t cm_declare_str = { "DECLARE", 7 };
const text_t cm_begin_str = { "BEGIN",   5 };
const text_t cm_create_str = { "CREATE",  6 };
const text_t cm_ddl_str[2] = {{ "OR", 2 }, { "REPLACE", 7 }};
const text_t cm_block_str[5] = {{ "PROCEDURE", 9 }, { "FUNCTION", 8 }, { "TRIGGER", 7 }, { "PACKAGE", 7 }, { "TYPE", 4 }};

static inline bool32 cm_if_sql_ignore_oper(cm_ignore_oper_t *ignore_oper, char c)
{
    switch (ignore_oper->oper_no) {
        // ignore enclosed_char, must end with enclosed_char, like ' XXX ' or " XXX "
        case 0:
            if ((uint32)c == ignore_oper->expected_enclosed_char) {
                ignore_oper->oper_no = -1;
            }
            break;

        // ignore note, must end with note, like /* XXX */
        case 1:
            if (c == cm_note_str[ignore_oper->expected_note_no]) {
                if (ignore_oper->expected_note_no == 3) {
                    ignore_oper->oper_no = -1;
                } else {
                    ignore_oper->expected_note_no++;
                }
            }
            break;

        // ignore line, must end with \n, like -- XXX \n
        case 2:
            if (CM_IS_RETURN(c)) {
                ignore_oper->oper_no = -1;
            }
            break;

        // ignore label, must end with label, like << XXX >> \n
        case 3:
        default:
            if (c == cm_label_str[ignore_oper->expected_label_no]) {
                if (ignore_oper->expected_label_no == 3) {
                    ignore_oper->oper_no = -1;
                } else {
                    ignore_oper->expected_label_no++;
                }
            } else {
                /* "<<" found, ignore next all characters until ">>" */
                if (ignore_oper->expected_label_no == 2) {
                    break;
                }
                if (CM_IS_ENCLOSED_CHAR(c)) {
                    ignore_oper->oper_no = 0;
                    ignore_oper->expected_enclosed_char = (uint32)c;
                    return CT_TRUE;
                } else if (CM_IS_NOTE(c)) {
                    ignore_oper->oper_no = 1;
                    ignore_oper->expected_note_no = 1;
                    return CT_TRUE;
                } else {
                    ignore_oper->oper_no = -1;
                    ignore_oper->expected_label_no = 0;
                }
            }
            break;
        }

    return CT_TRUE;
}

static inline bool32 cm_if_sql_ignore(text_t *sql, uint32 cur_pos, cm_ignore_oper_t *ignore_oper)
{
    char c = sql->str[cur_pos];

    // oper_no options: 0 means enclosed_char, 1 means note, 2 means line
    if (ignore_oper->oper_no == -1) {
        if (CM_IS_ENCLOSED_CHAR(c)) {
            ignore_oper->oper_no = 0;
            ignore_oper->expected_enclosed_char = (uint32)c;
            return CT_TRUE;
        } else if (CM_IS_NOTE(c)) {
            ignore_oper->oper_no = 1;
            ignore_oper->expected_note_no = 1;
            return CT_TRUE;
        } else if (CM_IS_LINE(c) && (cur_pos < sql->len - 1) && CM_IS_LINE(sql->str[cur_pos + 1])) {
            ignore_oper->oper_no = 2;
            return CT_TRUE;
        } else if (CM_IS_LABEL(c)) {
            ignore_oper->oper_no = 3;
            ignore_oper->expected_label_no = 1;
            return CT_TRUE;
        }

        return CT_FALSE;
    }

    return cm_if_sql_ignore_oper(ignore_oper, c);
}

static inline bool32 cm_if_sql_block(text_t *sql)
{
    /* block keywords:
    DECLARE
    BEGIN
    CREATE [OR REPLACE] PROCEDURE | FUNCTION | TRIGGER
    */
    uint32 i;

    // less len is 5, keyword "BEGIN"
    if (sql->len < cm_begin_str.len) {
        return CT_FALSE;
    }

    if (cm_text_str_contain_equal_ins(sql, cm_declare_str.str, cm_declare_str.len)) {
        return CT_TRUE;
    }

    if (cm_text_str_contain_equal_ins(sql, cm_begin_str.str, cm_begin_str.len)) {
        return CT_TRUE;
    }

    if (!cm_text_str_contain_equal_ins(sql, cm_create_str.str, cm_create_str.len)) {
        return CT_FALSE;
    }

    sql->str += cm_create_str.len;
    sql->len -= cm_create_str.len;

    cm_trim_text(sql);
    if (CM_IS_EMPTY(sql)) {
        return CT_FALSE;
    }

    for (i = 0; i < 2; i++) {
        if (!cm_text_str_contain_equal_ins(sql, cm_ddl_str[i].str, cm_ddl_str[i].len)) {
            break;
        }

        sql->str += cm_ddl_str[i].len;
        sql->len -= cm_ddl_str[i].len;

        cm_trim_text(sql);
        if (CM_IS_EMPTY(sql)) {
            return CT_FALSE;
        }
    }

    for (i = 0; i < cm_begin_str.len; i++) {
        if (cm_text_str_contain_equal_ins(sql, cm_block_str[i].str, cm_block_str[i].len)) {
            return CT_TRUE;
        }
    }

    return CT_FALSE;
}

bool32 cm_is_multiple_sql(text_t *sql)
{
    cm_ignore_oper_t ignore_oper = { -1, 0, 0 };
    uint32 i, pos;
    int32 pure_pos = -1;
    text_t pure_sql;
    char c;

    cm_trim_text(sql);
    if (CM_IS_EMPTY(sql)) {
        return CT_FALSE;
    }
    pos = cm_get_first_pos(sql, ';');
    if (pos == CT_INVALID_ID32 || (pos == sql->len - 1)) {
        return CT_FALSE;
    }

    for (i = 0; i < sql->len; i++) {
        c = sql->str[i];

        // ignore space, return or special char
        if (CM_IS_SPACE(c) || (CM_IS_RETURN(c) && ignore_oper.oper_no == -1) ||
            cm_if_sql_ignore(sql, i, &ignore_oper)) {
            continue;
        }

        if (pure_pos == -1) {
            pure_pos = (int32)i;
        }

        // encounter split char
        if (c == ';' && i != sql->len - 1) {
            pure_sql.str = sql->str + (uint32)pure_pos;
            pure_sql.len = sql->len - (uint32)pure_pos;
            if (cm_if_sql_block(&pure_sql)) {
                break;
            }

            return CT_TRUE;
        }
    }

    return CT_FALSE;
}

bool32 cm_fetch_subsql(text_t *sql, text_t *sub_sql)
{
    uint32 i;
    char c;
    int32 in_enclosed_char = -1;

    cm_trim_text(sql);

    if (CM_IS_EMPTY(sql)) {
        CM_TEXT_CLEAR(sub_sql);
        return CT_FALSE;
    }

    sub_sql->str = sql->str;

    for (i = 0; i < sql->len; i++) {
        c = sql->str[i];

        if (CM_IS_ENCLOSED_CHAR(c)) {
            if (in_enclosed_char < 0) {
                in_enclosed_char = c;
            } else if (in_enclosed_char == c) {
                in_enclosed_char = -1;
            }
            continue;
        }

        if (in_enclosed_char > 0) {
            continue;
        }

        // encounter split CHAR
        if (c == ';') {
            sub_sql->len = i;
            sql->str += (i + 1);
            sql->len -= (i + 1);
            return (sub_sql->len != 0);
        }
    }

    sub_sql->len = (sql->str[sql->len - 1] == ';') ? (sql->len - 1) : sql->len;
    sql->str = NULL;
    sql->len = 0;
    return (sub_sql->len != 0);
}

/* The general regular expression use "\\" to match "\",
 * but in the character class in oracle, that is the part enclosed in [], use "\" to match "\"
 * the processing here is to replace the "\" in [] with "\\"
*/
status_t cm_replace_regexp_spec_chars(text_t *regexp, char *ret, uint32 ret_size)
{
    uint32 i;
    uint32 j = 0;
    uint32 chars = 0;
    uint32 dep = 0;
    bool32 in_char_class = CT_FALSE;
    char *pre = NULL;
    bool32 is_escape = CT_FALSE;
    bool32 pre_is_escape = CT_FALSE;

    for (i = 0; i < regexp->len; i++) {
        if (j >= ret_size) {
            CT_THROW_ERROR(ERR_BUFFER_OVERFLOW, j + 1, ret_size);
            return CT_ERROR;
        }
        is_escape = CT_FALSE;
        if (regexp->str[i] == '[') {
            if (!in_char_class) {
                if (pre == NULL || !pre_is_escape) {
                    in_char_class = CT_TRUE;
                }
            } else {
                if (i + 1 < regexp->len && regexp->str[i + 1] == ':') {
                    dep++;
                }
                chars++;
            }
        } else if (regexp->str[i] == ']') {
            if (in_char_class) {
                if (dep > 0 && pre != NULL && *pre == ':') {
                    dep--;
                } else if (chars == 0) {
                    chars++;
                } else {
                    chars = 0;
                    in_char_class = CT_FALSE;
                }
            }
        } else if (regexp->str[i] == '\\') {
            is_escape = !pre_is_escape;
            if (in_char_class) {
                chars++;
                ret[j] = '\\';
                j++;
            }
        } else {
            if (in_char_class) {
                chars++;
            }
        }

        ret[j] = regexp->str[i];
        j++;
        pre = &regexp->str[i];
        pre_is_escape = is_escape;
    }
    ret[j] = '\0';

    return CT_SUCCESS;
}

void cm_extract_content(text_t *text, text_t *content)
{
    uint32 i, j;
    char in_enclosed_char = -1;

    content->len = 0;

    for (i = 0; i < text->len;) {
        if (CM_IS_ENCLOSED_CHAR(text->str[i])) {
            if (in_enclosed_char < 0) {
                in_enclosed_char = text->str[i];
            } else if (in_enclosed_char == text->str[i]) {
                in_enclosed_char = -1;
            }

            content->str[content->len++] = text->str[i];
            i++;
            continue;
        }

        if (in_enclosed_char > 0) {
            content->str[content->len++] = text->str[i];
            i++;
            continue;
        }

        if (text->str[i] == '-' && (i + 1 < text->len) && text->str[i + 1] == '-') {
            return;
        }

        if (text->str[i] == '/' && (i + 1 < text->len) && text->str[i + 1] == '*') {
            for (j = i + 2; j < text->len; j++) {
                if (text->str[j] == '*' && (j + 1 < text->len) && text->str[j + 1] == '/') {
                    i = j + 1;
                    break;
                }
            }

            i++;
            continue;
        }

        content->str[content->len++] = text->str[i];
        i++;
    }
}

int32 cm_text_text_ins(const text_t *src, const text_t *sub)
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
            if (UPPER(src->str[i + j]) != UPPER(sub->str[j])) {
                break;
            }
        }
        if (j == sub->len) {
            return (int32)i;
        }
    }
    return -1;
}

void cm_delete_text_end_slash(text_t *text)
{
    while (text->len >= 1 && text->str[text->len - 1] == SLASH) {
        text->len--;
    }
}

/* split string into two parts based on substring
 in:  text_t *text             'create procedure p1(v1 int) is begin xxx'
 in:  text_t *sub_text         'begin'
 out: text_t *left_text        'create procedure p1(v1 int) is'
 out: text_t *right_text       'begin xxx'
 return: TRUE text contains sub_text
         FALSE text does not contain sub_text
*/
bool32 cm_text_split(text_t *text, text_t *sub_text, text_t *left_text, text_t *right_text)
{
    text_t tmp_text = *text;
    text_t tmp_sub_text;

    if (CM_IS_EMPTY(text) || CM_IS_EMPTY(sub_text)) {
        return CT_FALSE;
    }

    while (tmp_text.len >= sub_text->len) {
        tmp_sub_text.str = tmp_text.str;
        tmp_sub_text.len = sub_text->len;
        if (cm_text_equal_ins(&tmp_sub_text, sub_text)) {
            *right_text = tmp_text;
            left_text->str = text->str;
            left_text->len = text->len - right_text->len;
            return CT_TRUE;
        }
        tmp_text.str++;
        tmp_text.len--;
    }

    return CT_FALSE;
}

int32 cm_mysql_compare(const CHARSET_COLLATION *cc, const text_t *text1, const text_t *text2)
{
    return (cc->collsp(cc, (text_t *)text1, (text_t *)text2));
}

#ifdef __cplusplus
}
#endif