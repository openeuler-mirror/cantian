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
 * cm_dec2.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_dec2.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __CM_DEC2_H_
#define __CM_DEC2_H_

#include "cm_text.h"
#include "cm_dec.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DEC2_CELL_DIGIT          2
#define DEC2_EXPN_UNIT           2
/* The the mask used to handle each cell. It is equal to 10^DEC2_CELL_DIGIT */
#define DEC2_CELL_MASK           100U
#define NON_NEG_ZERO_EXPN        ((int32)0xc1)
#define NEG_ZERO_EXPN            ((int32)0x3e)
#define DEC2_EXPN_LOW_HALF       ((int32)(-65))
#define DEC2_EXPN_UPPER_HALF     ((int32)(62))
#define DEC2_EXPN_LOW            ((int32)(-130))
#define DEC2_EXPN_UPPER          ((int32)(125))

#define ZERO_EXPN             ((uint8)0x80)
#define NON_NEG_ZERO(len, head)     ((len) == 1 && (head) == NON_NEG_ZERO_EXPN)
#define NEG_ZERO(len, head)         ((len) == 1 && (head) == NEG_ZERO_EXPN)

#define DEC2_HEAD_IS_ZERO(head) ((head) == ZERO_EXPN || (head) == NON_NEG_ZERO_EXPN || (head) == NEG_ZERO_EXPN)
#define DECIMAL2_IS_ZERO(dec) ((dec)->len == 1 && DEC2_HEAD_IS_ZERO((dec)->head))

#define IS_DEC_NEG(dec)       (!(dec)->sign)
#define DEC2_MAX_INT16_POWER  ((int8)(2)) // the maximal SHORT 32767 = 3.2767 * 100^2
#define DEC2_MAX_INT32_POWER  ((int8)(4)) // the maximal INTEGER 2147483647 = 21.47483647 * 100^4
#define DEC2_MAX_INT64_POWER  ((int8)(9)) // the maximal BIGINT is 9223372036854775807 = 9.223372036854775807 * 100^9

#define DEC2_TO_REAL_MAX_CELLS    ((int8)(9))

#define DECIMAL2_LEN(buf) cm_dec2_stor_sz((dec2_t *)(buf))

#define SEXP_2_D2EXP(sci_exp) ((sci_exp) / DEC2_EXPN_UNIT)  // result is 100's integer power
#define D2EXP_2_SEXP(dexp) ((dexp) * DEC2_EXPN_UNIT)
// sci_exp is 10's integer power, result is dec->head
#define CONVERT_EXPN(sci_exp, is_neg) \
    ((c2typ_t)((is_neg) ? (NEG_ZERO_EXPN - SEXP_2_D2EXP(sci_exp)) : (SEXP_2_D2EXP(sci_exp) + NON_NEG_ZERO_EXPN)))
// expn is 100's integer power, result is dec->head
#define CONVERT_EXPN2(expn, is_neg) \
    ((c2typ_t)((is_neg) ? (NEG_ZERO_EXPN - (expn)) : ((expn) + NON_NEG_ZERO_EXPN)))
// result is 100's integer power
#define GET_100_EXPN(dec) (IS_DEC_NEG(dec) ? (NEG_ZERO_EXPN - (dec)->head) : ((dec)->head - NON_NEG_ZERO_EXPN))
#define GET_10_EXPN(dec) D2EXP_2_SEXP(GET_100_EXPN(dec))

/* Get the scientific exponent of a decimal when given its exponent and precision */
#define DEC2_GET_SEXP_BY_PREC0(sexp, prec0) ((int32)(sexp) + (int32)(prec0) - 1)
/* Get the scientific exponent of a decimal when given its exponent and cell0 */
#define DEC2_GET_SEXP_BY_CELL0(sexp, cell0) DEC2_GET_SEXP_BY_PREC0(sexp, cm_count_u8digits(cell0))
/* Get the scientific exponent of a decimal */
#define DEC2_GET_SEXP(dec) DEC2_GET_SEXP_BY_CELL0(GET_10_EXPN(dec), ((dec)->cells[0]))

/* overflow check */
#define DEC2_OVERFLOW_CHECK_BY_SCIEXP(sciexp) \
    do {                                      \
        if ((sciexp) > DEC2_EXPN_UPPER) {     \
            GS_THROW_ERROR(ERR_NUM_OVERFLOW); \
            return GS_ERROR;                  \
        }                                     \
    } while (0)

// expn is 100's integer power
#define DEC2_OVERFLOW_CHECK_BY_EXPN(expn) \
    do {                                  \
        if (SECUREC_UNLIKELY((expn) > DEC2_EXPN_UPPER_HALF) || SECUREC_UNLIKELY((expn) < DEC2_EXPN_LOW_HALF)) {   \
            GS_THROW_ERROR(ERR_NUM_OVERFLOW);   \
            return GS_ERROR;   \
        }   \
    } while (0)

/*
 * decimal memory encode format:
 * len[1] head[1] digit[0~21]
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
 * 1: use one bytes to indicate len, len range 1~26
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
/*
Positive numbers in the range 1 x 10^-130 to 9.999999 x 10^125 with up to 38 significant
Negative numbers from -1 x 10^-130 to 9.999999 x 10^125 with up to 38 significant digits
Considering that 40-bit significant numbers, exponential adjustment and Newton iteration accuracy,
DEC2_CELL_SIZE define 22
*/
#define DEC2_CELL_SIZE (uint8)36
#define DEC2_MAX_EXP_OFFSET DEC2_CELL_SIZE
#define DEC2_MAX_LEN (uint8)(DEC2_CELL_SIZE + 1)

typedef uint8 c2typ_t;
typedef c2typ_t cell2_t[DEC2_CELL_SIZE];

#define GET_CELLS_SIZE(dec) ((uint32)((dec)->len - 1))
/* DEC2_MAX_ALLOWED_PREC = DEC_CELL_SIZE * DEC4_CELL_DIGIT indicates the maximal
precision that a decimal can capture at most */
#define DEC2_MAX_ALLOWED_PREC (DEC2_CELL_SIZE * DEC2_CELL_DIGIT)

/* Get the position of n-th digit of an int256, when given precision
 * of u0 (i.e., the position of the dot).
 * @note Both n and the pos begin with 0 */
#define DEC2_POS_N_BY_PREC0(n, prec0) ((n) + (int32)DEC2_CELL_DIGIT - (int32)(prec0))
/* Compute the (maximal) size of a decimal when specify the precision */
#define DEC2_HEAD_SIZE (OFFSET_OF(dec2_t, cells))
/* Compute the number of cells used to store the significant digits when
 * given precision. The precision must be greater than zero.
 * **NOTE THAT:** for adjusting the expn to be an integral multiple of
 * DEC2_CELL_DIGIT (for speeding addition and subtraction), You may require
 * an additional cell to store the significant digits. 1 + CEIL((P - 1) / 2)
 */
#define DEC2_NCELLS(precision) (CM_ALIGN_CEIL((precision) - 1, DEC2_CELL_DIGIT) + 1)
#define MAX_DEC2_BYTE_BY_PREC(prec) (DEC2_NCELLS(prec) * sizeof(c2typ_t) + DEC2_HEAD_SIZE)
#define MAX_DEC2_BYTE_SZ MAX_DEC2_BYTE_BY_PREC(GS_MAX_NUM_SAVING_PREC)

/*
 * expn: the exponent of the number
 * expn_sign: exponent sign bit
 * sign: sign bit, 1 indicate non negative, 0 indicate negative
 */
#pragma pack(1)
#define DEC2_PAYLOAD            \
    union {                     \
        struct {                \
            uint8 expn : 6;     \
            uint8 expn_sign : 1; \
            uint8 sign : 1;     \
        };                      \
        c2typ_t head;           \
    };                          \
    cell2_t cells;              \

typedef struct st_payload {
    DEC2_PAYLOAD
} payload_t;

typedef struct st_dec2 {
    uint8 len;  // len range 1~26
    DEC2_PAYLOAD
} dec2_t;
#pragma pack()

#define GET_PAYLOAD(dec)   (payload_t *)(&((dec)->head))

/*  Copy the data a decimal
    Another way to Copy the data of decimals is to use loops, for example:
    *    uint32 i = src->ncells;
    *    while (i-- > 0)
    *        dst->cells[i] = src->cells[i];
    * However, this function is performance sensitive, and not too safe when
    * src->ncells is abnormal. By actural testing, using switch..case here
    * the performance can improve at least 1.5%. The testing results are
    *    WHILE LOOP  : 5.64% cm_dec2_copy
    *    SWITCH CASE : 4.14% cm_dec2_copy
    * Another advantage is that the default branch of SWITCH CASE can be used
    * to handle abnormal case, which reduces an IF statement.
    */
static inline void cm_dec2_copy_payload(payload_t *dst, const payload_t *src, uint8 len)
{
    if (SECUREC_UNLIKELY(dst == src)) {
        return;
    }

    dst->head = src->head;
    int nums = len - 1; // len is greater than 1

    switch (nums) {
        case 36: /* = DEC2_CELL_SIZE */
            dst->cells[35] = src->cells[35];
            /* fall-through */
        case 35:
            dst->cells[34] = src->cells[34];
            /* fall-through */
        case 34:
            dst->cells[33] = src->cells[33];
            /* fall-through */
        case 33:
            dst->cells[32] = src->cells[32];
            /* fall-through */
        case 32:
            dst->cells[31] = src->cells[31];
            /* fall-through */
        case 31:
            dst->cells[30] = src->cells[30];
            /* fall-through */
        case 30:
            dst->cells[29] = src->cells[29];
            /* fall-through */
        case 29:
            dst->cells[28] = src->cells[28];
            /* fall-through */
        case 28:
            dst->cells[27] = src->cells[27];
            /* fall-through */
        case 27:
            dst->cells[26] = src->cells[26];
            /* fall-through */
        case 26:
            dst->cells[25] = src->cells[25];
            /* fall-through */
        case 25:
            dst->cells[24] = src->cells[24];
            /* fall-through */
        case 24:
            dst->cells[23] = src->cells[23];
            /* fall-through */
        case 23:
            dst->cells[22] = src->cells[22];
            /* fall-through */
        case 22:
            dst->cells[21] = src->cells[21];
            /* fall-through */
        case 21:
            dst->cells[20] = src->cells[20];
            /* fall-through */
        case 20:
            dst->cells[19] = src->cells[19];
            /* fall-through */
        case 19:
            dst->cells[18] = src->cells[18];
            /* fall-through */
        case 18:
            dst->cells[17] = src->cells[17];
            /* fall-through */
        case 17:
            dst->cells[16] = src->cells[16];
            /* fall-through */
        case 16:
            dst->cells[15] = src->cells[15];
            /* fall-through */
        case 15:
            dst->cells[14] = src->cells[14];
            /* fall-through */
        case 14:
            dst->cells[13] = src->cells[13];
            /* fall-through */
        case 13:
            dst->cells[12] = src->cells[12];
            /* fall-through */
        case 12:
            dst->cells[11] = src->cells[11];
            /* fall-through */
        case 11:
            dst->cells[10] = src->cells[10];
            /* fall-through */
        case 10:
            dst->cells[9] = src->cells[9];
            /* fall-through */
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

static inline void cm_zero_dec2(dec2_t *dec)
{
    dec->len = 1;
    dec->head = ZERO_EXPN;
    dec->cells[0] = 0;
}

static inline void cm_zero_payload(uint8 *len, payload_t *pay)
{
    *len = 1;
    pay->head = ZERO_EXPN;
}

static inline uint8 cm_dec2_stor_sz(const dec2_t *d2)
{
    return d2->len * sizeof(c2typ_t);
}

static inline void cm_dec2_copy(dec2_t *dst, const dec2_t *src)
{
    dst->len = src->len;
    cm_dec2_copy_payload(GET_PAYLOAD(dst), GET_PAYLOAD(src), src->len);
}

static inline void cm_dec2_copy_ex(dec2_t *dst, const payload_t *src, uint8 len)
{
    if (SECUREC_UNLIKELY(len == 0)) {
        cm_zero_dec2(dst);
        return;
    }
    dst->len = len;
    cm_dec2_copy_payload(GET_PAYLOAD(dst), src, len);
}

void cm_dec2_print(const dec2_t *dec, const char *file, uint32 line, const char *func_name, const char *fmt, ...);

/* open debug mode #define  DEBUG_DEC2 */
#ifdef DEBUG_DEC2
#define DEC2_DEBUG_PRINT(dec, fmt, ...) \
    cm_dec2_print(dec, (char *)__FILE__, (uint32)__LINE__, (char *)__FUNCTION__, fmt, ##__VA_ARGS__)
#else
#define DEC2_DEBUG_PRINT(dec, fmt, ...)
#endif

void cm_int32_to_dec2(int32 i_32, dec2_t *dec);
void cm_uint32_to_dec2(uint32 i32, dec2_t *dec);
void cm_int64_to_dec2(int64 i_64, dec2_t *dec);
status_t cm_real_to_dec2(double real, dec2_t *dec);
status_t cm_text_to_dec2(const text_t *dec_text, dec2_t *dec);
bool32 cm_dec2_is_integer(const dec2_t *dec);
double cm_dec2_to_real(const dec2_t *dec);
status_t cm_dec2_to_int16(dec2_t *dec, int16 *i16, round_mode_t rnd_mode);
status_t cm_dec2_to_int32(dec2_t *dec, int32 *i32, round_mode_t rnd_mode);
status_t cm_dec2_to_int64(dec2_t *dec, int64 *val, round_mode_t rnd_mode);
status_t cm_dec2_to_uint16(dec2_t *dec, uint16 *i16, round_mode_t rnd_mode);
status_t cm_dec2_to_uint32(dec2_t *dec, uint32 *i32, round_mode_t rnd_mode);
status_t cm_dec2_to_uint64(const dec2_t *dec, uint64 *u64, round_mode_t rnd_mode);
status_t cm_dec2_to_str(const dec2_t *dec, int max_len, char *str);
status_t cm_str_to_dec2(const char *str, dec2_t *dec);

status_t cm_dec2_finalise(dec2_t *dec, uint32 prec);
status_t cm_dec2_sin(const dec2_t *dec, dec2_t *result);

static inline void cm_dec2_trim_zeros(dec2_t *dec)
{
    while (GET_CELLS_SIZE(dec) > 0 && dec->cells[GET_CELLS_SIZE(dec) - 1] == 0) {
        --dec->len;
    }

    if (dec->len == 1) {
        cm_zero_dec2(dec);
    }
}

static inline int32 cm_dec2_cmp_cells(const payload_t *pay1, uint8 len1,
                                      const payload_t *pay2, uint8 len2)
{
    uint32 cmp_len = MIN(len1 - 1, len2 - 1);
    int32 ret = memcmp(pay1->cells, pay2->cells, cmp_len);
    if (ret > 0) {
        return 1;
    } else if (ret < 0) {
        return -1;
    }
 	 
    return (len1 > len2) ? 1 : ((len1 == len2) ? 0 : -1);
}

static inline int32 cm_dec2_cmp_payload(const payload_t *pay1, uint8 len1, const payload_t *pay2, uint8 len2)
{
    if (pay1->head != pay2->head) {
        return (pay1->head > pay2->head) ? 1 : -1;
    }

    int32 cmp = cm_dec2_cmp_cells(pay1, len1, pay2, len2);
    return IS_DEC_NEG(pay1) ? (-cmp) : cmp;
}

status_t cm_dec2_add_op(const dec2_t *d1, const dec2_t *d2, dec2_t *rs);

/*
 * Adds two decimal variables and returns a truncated result which precision can not
 * exceed MAX_NUMERIC_BUFF
 */
static inline status_t cm_dec2_add(const dec2_t *dec1, const dec2_t *dec2, dec2_t *result)
{
    if (cm_dec2_add_op(dec1, dec2, result) != GS_SUCCESS) {
        return GS_ERROR;
    }
    return cm_dec2_finalise(result, MAX_NUMERIC_BUFF);
}

status_t cm_dec2_sub_op(const dec2_t *d1, const dec2_t *d2, dec2_t *rs);
status_t cm_dec2_mul_op(const dec2_t *d1, const dec2_t *d2, dec2_t *rs);

/*
 * multiplication of two decimal
 */
static inline status_t cm_dec2_multiply(const dec2_t *dec1, const dec2_t *dec2, dec2_t *result)
{
    if (cm_dec2_mul_op(dec1, dec2, result) != GS_SUCCESS) {
        return GS_ERROR;
    }
    return cm_dec2_finalise(result, MAX_NUMERIC_BUFF);
}

status_t cm_dec2_divide(const dec2_t *dec1, const dec2_t *dec2, dec2_t *result);

status_t cm_dec2_to_text(const dec2_t *dec, int32 max_len, text_t *text);

#ifdef __cplusplus
}
#endif

#endif
