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
 * cm_dec8.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_dec8.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_DEC8_H_
#define __CM_DEC8_H_
#include "cm_dec4.h"

/* The number of cells (an uint32) used to store the decimal type. */
#define DEC8_CELL_SIZE (uint8)9
#define DEC8_MAX_LEN (uint8)(DEC8_CELL_SIZE + 1)

/* The number of digits that an element of an int256, i.e., an uint32
can encode. This indicates each uint32 can record at most DEC_ELEM_DIGIT
digits. Its value 9 is the upper, since 10^(9+1) < 2^32 < 10^11  */
#define DEC8_CELL_DIGIT 8

#define DEC8_EXPN_UNIT 8

#define SEXP_2_D8EXP(sci_exp) (int16)((sci_exp) / DEC8_EXPN_UNIT)

#define D8EXP_2_SEXP(dexp) ((dexp) * DEC8_EXPN_UNIT)

/* The the mask used to handle each cell. It is equal to 10^DEC_CELL_DIGIT */
#define DEC8_CELL_MASK 100000000U

/* Half of DEC_CELL_MASK */
#define DEC8_HALF_MASK 50000000U

/** The format to print a cell */
#define DEC8_CELL_FMT "%08u"

/* DEC_MAX_ALLOWED_PREC = DEC_CELL_SIZE * DEC_CELL_DIGIT indicates the maximal
precision that a decimal can capture at most */
#define DEC8_MAX_ALLOWED_PREC (DEC8_CELL_SIZE * DEC8_CELL_DIGIT)

#define DEC8_MAX_EXP_OFFSET DEC8_CELL_SIZE

typedef uint32 c8typ_t;
typedef uint64 cc8typ_t;
typedef c8typ_t cell8_t[DEC8_CELL_SIZE];

#define DEC8_SIGN_PLUS (uint8)1
#define DEC8_SIGN_MINUS (uint8)0

/*
 * decimal memory encode format:
 * len[1] head[1] digit[0~7]
 * head 1bytes
 * ------------------------------------------------------------
 * A7         | A6           | A5    A4    A3    A2    A1    A0
 * ------------------------------------------------------------
 * signbit    | expn sign    | 0x000 0000 ~ 0x111 1111
 *            | bit          |          0 ~ 127
 * ------------------------------------------------------------
 *            |1:non neg     |0x1100 0001 ~ 0x1111 1111
 *            |              |[0xc1, 0xff] => [0, 62] 0xc1 is 0 expn code
 *  1:nonneg  |--------------|----------------------------------
 *            |0: neg        |0x1000 0000 ~ 0x1100 0000
 *            |              |[0x80, 0xc0] => [-65,-1]
 * ------------------------------------------------------------
 *            |1: neg        |0x0011 1111 ~ 0x0111 1111
 *            |              |[0x3f, 0x7f] => [-1, -65]
 *  0:neg     |--------------|----------------------------------
 *            |0: non neg    |0x0000 0000 ~ 0x0011 1110
 *            |              |[0x00, 0x3e] => [62,0] 0x3e is 0 expn code
 * ------------------------------------------------------------
 * 1: use one bytes to indicate len, len range 1~8
 * 2: use the 1 bytes to indicate sign and expn
 *   2.1 use a7 to indicate sign bit, 1 indicate non negative, 0 indicate negative
 *   2.2 use a6 to indicate the expn sign bit
 *      2.2.1 when number is non negative, the greater expn, the greate number.
 *            so, expn sign bit 1:non negative, 0: negative
 *      2.2.2 when number is negative, the greater expn, the lesser number.
 *            so, expn sign bit 1: negative, 0: non negative
 * 3: use bytes buffer to indicate to significant digits
 *
 * base above the encode rule, the comparison between two decimal can be converted into a memory comparison.
 *
 */
#pragma pack(1)
typedef struct st_dec8 {
    uint8 len;  // len range 1~8, is ncells + 1
    union {
        struct {
            uint8 expn : 6;      /* the exponent of the number */
            uint8 expn_sign : 1; /* exponent sign bit */
            uint8 sign : 1;      /* sign bit, 1 indicate non negative, 0 indicate negative */
        };
        uint8 head;
    };
    cell8_t cells;
} dec8_t;
#pragma pack()

// Fusing the exponential range of dec2 and dec4
#define DEC8_EXPN_LOW   ((int32)-130)
#define DEC8_EXPN_UPPER ((int32)127)
/* overflow check */
#define DEC8_OVERFLOW_CHECK_BY_SCIEXP(sciexp) \
    do {                                      \
        if ((sciexp) > DEC8_EXPN_UPPER) {     \
            CT_THROW_ERROR(ERR_NUM_OVERFLOW); \
            return CT_ERROR;                  \
        }                                     \
    } while (0)

#define DEC8_HEAD_EXPN_LOW   ((int32)-520)   // -65 * 8
#define DEC8_HEAD_EXPN_UPPER ((int32)496)    // 62 * 8
/* overflow check */
#define DEC8_HEAD_OVERFLOW_CHECK(sciexp)                                        \
    do {                                                                        \
        if ((sciexp) > DEC8_HEAD_EXPN_UPPER || (sciexp) < DEC8_HEAD_EXPN_LOW) { \
            CT_THROW_ERROR(ERR_NUM_OVERFLOW);                                   \
            return CT_ERROR;                                                    \
        }                                                                       \
    } while (0)


extern const dec8_t DEC8_MIN_INT64;
extern const dec8_t DEC8_ONE;

#define GET_CELLS8_SIZE(dec) ((uint32)((dec)->len - 1))
#define NON_NEG_ZERO_D8EXPN  ((int32)0xc1)
#define NEG_ZERO_D8EXPN      ((int32)0x3e)
#define ZERO_D8EXPN          ((int32)0x80)

#define DEC8_NON_NEG_ZERO(dec) ((dec)->len == 1 && (dec)->head == NON_NEG_ZERO_D8EXPN)
#define DEC8_NEG_ZERO(dec)     ((dec)->len == 1 && (dec)->head == NEG_ZERO_D8EXPN)

#define DECIMAL8_IS_ZERO(dec) \
    ((dec)->len == 1 && ((dec)->head == ZERO_D8EXPN || (dec)->head == NON_NEG_ZERO_D8EXPN || \
    (dec)->head == NEG_ZERO_D8EXPN))
#define IS_DEC8_NEG(dec) (!(dec)->sign)

// sci_exp is 10's integer power, result is dec->head
#define CONVERT_D8EXPN(sci_exp, is_neg) ((uint8)((is_neg) ? \
    (NEG_ZERO_D8EXPN - SEXP_2_D8EXP(sci_exp)) : (SEXP_2_D8EXP(sci_exp) + NON_NEG_ZERO_D8EXPN)))

// expn is 100000000's integer power, result is dec->head
#define CONVERT_D8EXPN2(expn, is_neg) ((uint8)((is_neg) ? \
    (NEG_ZERO_D8EXPN - (expn)) : ((expn) + NON_NEG_ZERO_D8EXPN)))

// result is 100000000's integer power
#define GET_DEC8_EXPN(dec) (IS_DEC8_NEG(dec) ? \
    (NEG_ZERO_D8EXPN - (dec)->head) : ((dec)->head - NON_NEG_ZERO_D8EXPN))

// result is 10's integer power
#define GET_DEC8_SCI_EXP(dec) D8EXP_2_SEXP(GET_DEC8_EXPN(dec))

/* Get the scientific exponent of a decimal when given its exponent and precision */
#define DEC8_GET_SEXP_BY_PREC0(sexp, prec0) ((int32)(sexp) + (int32)(prec0) - 1)
/* Get the scientific exponent of a decimal when given its exponent and cell0 */
#define DEC8_GET_SEXP_BY_CELL0(sexp, c8_0) DEC8_GET_SEXP_BY_PREC0(sexp, cm_count_u32digits(c8_0))
/* Get the scientific exponent of a decimal6 */
#define DEC8_GET_SEXP(dec) DEC8_GET_SEXP_BY_CELL0(GET_DEC8_SCI_EXP(dec), ((dec)->cells[0]))

/* overflow check */
#define DEC8_OVERFLOW_CHECK(dec) DEC8_OVERFLOW_CHECK_BY_SCIEXP(DEC8_GET_SEXP(dec))

/* Get the position of n-th digit of an dec8, when given precision
 * of cell0 (i.e., the position of the dot).
 * @note Both n and the pos begin with 0 */
#define DEC8_POS_N_BY_PREC0(n, prec0) ((n) + (int32)DEC8_CELL_DIGIT - (int32)(prec0))
#define DEC8_POS_N_BY_CELL0(n, cells) ((n) + (int32)DEC8_CELL_DIGIT - cm_count_u32digits((cells)[0]))

#define DEC8_TO_REAL_MAX_CELLS (int32)3

#ifdef __cplusplus
extern "C" {
#endif

void cm_dec8_print(const dec8_t *dec, const char *file, uint32 line, const char *func_name, const char *fmt, ...);

/* open debug mode #define  DEBUG_DEC8 */
#ifdef DEBUG_DEC8
#define DEC8_DEBUG_PRINT(dec, fmt, ...) \
    cm_dec8_print(dec, (char *)__FILE__, (uint32)__LINE__, (char *)__FUNCTION__, fmt, ##__VA_ARGS__)
#else
#define DEC8_DEBUG_PRINT(dec, fmt, ...)
#endif

status_t cm_dec8_finalise(dec8_t *dec, uint32 prec, bool32 allow_overflow);

static inline void cm_zero_dec8(dec8_t *dec)
{
    dec->len = 1;
    dec->head = ZERO_D8EXPN;
    dec->cells[0] = 0;
}

/* Copy the data a decimal */
static inline void cm_dec8_copy(dec8_t *dst, const dec8_t *src)
{
    if (SECUREC_UNLIKELY(dst == src)) {
        return;
    }
    if (SECUREC_UNLIKELY(src->len == 0)) {
        cm_zero_dec8(dst);
        return;
    }
    dst->len = src->len;
    dst->head = src->head;
    /* Another way to Copy the data of decimals is to use loops, for example:
     *    uint32 i = src->len - 1;
     *    while (i-- > 0)
     *        dst->cells[i] = src->cells[i];
     * However, this function is performance sensitive, and not too safe when
     * src's ncells is abnormal. By actural testing, using switch..case here
     * the performance can improve at least 1.5%. The testing results are
     *    WHILE LOOP  : 5.64% cm_dec8_copy
     *    SWITCH CASE : 4.14% cm_dec8_copy
     * Another advantage is that the default branch of SWITCH CASE can be used
     * to handle abnormal case, which reduces an IF statement.
     */
    switch (GET_CELLS8_SIZE(src)) {
        case 9:
            dst->cells[8] = src->cells[8];
            /* fall-through */
        case 8:
            dst->cells[7] = src->cells[7];
            /* fall-through */
        case 7:
            dst->cells[6] = src->cells[6];
            /* fall-through */
        case 6:
            dst->cells[5] = src->cells[5];
            /* fall-through */
        case 5:
            dst->cells[4] = src->cells[4];
            /* fall-through */
        case 4:
            dst->cells[3] = src->cells[3];
            /* fall-through */
        case 3:
            dst->cells[2] = src->cells[2];
            /* fall-through */
        case 2:
            dst->cells[1] = src->cells[1];
            /* fall-through */
        case 1:
            dst->cells[0] = src->cells[0];
            /* fall-through */
        case 0:
            break;
        default:
            CM_NEVER;
            break;
    }
}

static inline int32 cm_dec8_cmp_data(const dec8_t *dec1, const dec8_t *dec2)
{
    uint32 cmp_len = MIN(GET_CELLS8_SIZE(dec1), GET_CELLS8_SIZE(dec2));
    for (uint32 i = 0; i < cmp_len; i++) {
        DECIMAL_TRY_CMP(dec1->cells[i], dec2->cells[i], 1);
    }

    DECIMAL_TRY_CMP(GET_CELLS8_SIZE(dec1), GET_CELLS8_SIZE(dec2), 1);
    return 0;
}

/*
 * dec1 > dec2: return  1
 * dec1 = dec2: return  0
 * dec1 < dec2: return -1
 */
static inline int32 cm_dec8_cmp(const dec8_t *dec1, const dec8_t *dec2)
{
    if (dec1->head != dec2->head) {
        return (dec1->head > dec2->head) ? 1 : -1;
    }
    if (DECIMAL8_IS_ZERO(dec1)) {
        return 0;
    }
    int32 flag = IS_DEC8_NEG(dec1) ? -1 : 1;
    uint32 cmp_len = MIN(GET_CELLS8_SIZE(dec1), GET_CELLS8_SIZE(dec2));
    for (uint32 i = 0; i < cmp_len; i++) {
        DECIMAL_TRY_CMP(dec1->cells[i], dec2->cells[i], flag);
    }

    DECIMAL_TRY_CMP(GET_CELLS8_SIZE(dec1), GET_CELLS8_SIZE(dec2), flag);
    return 0;
}

static inline void cm_dec8_trim_zeros(dec8_t *dec)
{
    while (GET_CELLS8_SIZE(dec) > 0 && dec->cells[GET_CELLS8_SIZE(dec) - 1] == 0) {
        --dec->len;
    }
    if (dec->len == 1) {
        cm_zero_dec8(dec);
    }
}

static inline void cm_dec8_abs(dec8_t *dec)
{
    if (!IS_DEC8_NEG(dec)) {
        return;
    }

    int expn = GET_DEC8_SCI_EXP(dec);
    dec->head = CONVERT_D8EXPN(expn, CT_FALSE);
}

status_t cm_dec8_to_str(const dec8_t *dec, int max_len, char *str);
status_t cm_dec8_to_text(const dec8_t *dec, int32 max_length, text_t *text);

/*
 * Convert a decimal into a text with all precisions
 */
static inline status_t cm_dec8_to_text_all(const dec8_t *dec, text_buf_t *text)
{
    if (text->max_size <= CT_MAX_DEC_OUTPUT_ALL_PREC) {
        return CT_ERROR;
    }
    return cm_dec8_to_text(dec, CT_MAX_DEC_OUTPUT_ALL_PREC, &text->value);
}

static inline status_t cm_dec8_to_str_all(const dec8_t *dec, char *str, uint32 buffer_len)
{
    text_buf_t text_buf;
    text_buf.str = str;
    text_buf.len = 0;
    text_buf.max_size = buffer_len;

    CT_RETURN_IFERR(cm_dec8_to_text_all(dec, &text_buf));
    str[text_buf.len] = '\0';
    return CT_SUCCESS;
}

status_t cm_str_to_dec8(const char *str, dec8_t *dec);
num_errno_t cm_numpart_to_dec8(num_part_t *np, dec8_t *dec);
status_t cm_text_to_dec8(const text_t *dec_text, dec8_t *dec);
status_t cm_hext_to_dec8(const text_t *hex_text, dec8_t *dec);
void cm_uint32_to_dec8(uint32 i32, dec8_t *dec);
void cm_int32_to_dec8(int32 i_32, dec8_t *dec);
void cm_int64_to_dec8(int64 i_64, dec8_t *dec);
status_t cm_real_to_dec8(double real, dec8_t *dec);
status_t cm_real_to_dec8_prec16(double real, dec8_t *dec);
status_t cm_real_to_dec8_prec17(double real, dec8_t *dec);
double cm_dec8_to_real(const dec8_t *dec);
status_t cm_dec8_divide(const dec8_t *dec1, const dec8_t *dec2, dec8_t *result);
status_t cm_adjust_dec8(dec8_t *dec, int32 precision, int32 scale);
status_t cm_dec8_to_uint64(const dec8_t *dec, uint64 *u64, round_mode_t rnd_mode);
status_t cm_dec8_to_int64(const dec8_t *dec, int64 *val, round_mode_t rnd_mode);
int32 cm_dec8_to_int64_range(const dec8_t *dec, int64 *i64, round_mode_t rnd_mode);
status_t cm_dec8_to_uint32(const dec8_t *dec, uint32 *i32, round_mode_t rnd_mode);
status_t cm_dec8_to_int32(const dec8_t *dec, int32 *i32, round_mode_t rnd_mode);
status_t cm_dec8_floor(dec8_t *dec);
status_t cm_dec8_ceil(dec8_t *dec);
bool32 cm_dec8_is_integer(const dec8_t *dec);
void cm_uint64_to_dec8(uint64 u64, dec8_t *dec);
status_t cm_dec8_scale(dec8_t *dec, int32 scale, round_mode_t rnd_mode);
status_t cm_dec8_sqrt(const dec8_t *d, dec8_t *r);
status_t cm_dec8_sin(const dec8_t *dec, dec8_t *result);
status_t cm_dec8_cos(const dec8_t *dec, dec8_t *result);
status_t cm_dec8_tan(const dec8_t *dec, dec8_t *result);
status_t cm_dec8_radians(const dec8_t *dec, dec8_t *result);
status_t cm_dec8_pi(dec8_t *result);
status_t cm_dec8_asin_op(const dec8_t *d, dec8_t *rs);
status_t cm_dec8_acos(const dec8_t *dec, dec8_t *result);
status_t cm_dec8_atan(const dec8_t *dec, dec8_t *result);
status_t cm_dec8_atan2(const dec8_t *dec1, const dec8_t *dec2, dec8_t *result);
status_t cm_dec8_tanh(const dec8_t *dec, dec8_t *result);
status_t cm_dec8_exp(const dec8_t *dec, dec8_t *result);
status_t cm_dec8_ln(const dec8_t *dec, dec8_t *result);
status_t cm_dec8_log(const dec8_t *n2, const dec8_t *n1, dec8_t *result);
status_t cm_dec8_power(const dec8_t *x, const dec8_t *r, dec8_t *y);
status_t cm_dec8_mod(const dec8_t *n2, const dec8_t *n1, dec8_t *y);
void cm_dec8_sign(const dec8_t *dec, dec8_t *result);

/*
 * The core algorithm for addition/substruction/multiplication of two decimals,
 * without truncating the result.
 */
void cm_dec8_add_op(const dec8_t *d1, const dec8_t *d2, dec8_t *rs);
void cm_dec8_sub_op(const dec8_t *d1, const dec8_t *d2, dec8_t *rs);
void cm_dec8_mul_op(const dec8_t *d1, const dec8_t *d2, dec8_t *rs);

/*
 * Adds two decimal variables and returns a truncated result which precision can not
 * exceed MAX_NUMERIC_BUFF
 */
static inline status_t cm_dec8_add(const dec8_t *dec1, const dec8_t *dec2, dec8_t *result)
{
    cm_dec8_add_op(dec1, dec2, result);
    return cm_dec8_finalise(result, MAX_NUMERIC_BUFF, CT_FALSE);
}

/*
 * Subtraction of two decimals, dec1 - dec2 and returns a truncated result
 * which precision can not exceed MAX_NUMERIC_BUFF
 */
static inline status_t cm_dec8_subtract(const dec8_t *dec1, const dec8_t *dec2, dec8_t *result)
{
    cm_dec8_sub_op(dec1, dec2, result);
    return cm_dec8_finalise(result, MAX_NUMERIC_BUFF, CT_FALSE);
}

/*
 * multiplication of two decimal

 */
static inline status_t cm_dec8_multiply(const dec8_t *dec1, const dec8_t *dec2, dec8_t *result)
{
    cm_dec8_mul_op(dec1, dec2, result);
    return cm_dec8_finalise(result, MAX_NUMERIC_BUFF, CT_FALSE);
}

static inline status_t cm_dec8_asin(const dec8_t *d, dec8_t *rs)
{
    CT_RETURN_IFERR(cm_dec8_asin_op(d, rs));

    return cm_dec8_finalise(rs, MAX_NUMERIC_BUFF, CT_FALSE);
}

void cm_dec8_negate(dec8_t *dec);
void cm_dec8_negate2(dec8_t *dec, dec8_t *ret);
status_t cm_dec8_check_type_overflow(dec8_t *dec, int16 type);

#ifdef __cplusplus
}
#endif

#endif