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
 * cm_decimal.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_decimal.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __CM_NUMBER_H_
#define __CM_NUMBER_H_

#include "cm_dec2.h"
#include "cm_dec8.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Decode a decimal from a void data with size

 */
static inline void cm_dec_2_to_4(const dec2_t *d2, dec4_t *d4)
{
    if (DECIMAL2_IS_ZERO(d2) || DEC2_GET_SEXP(d2) < MIN_NUMERIC_EXPN) {
        cm_zero_dec4(d4);
        return;
    }
    uint32 i4 = 0;
    uint32 i2 = 0;
    d4->sign = !d2->sign;
    int8 expn = GET_100_EXPN(d2);
    if (cm_is_even(expn)) {
        d4->expn = expn / 2;
        d4->cells[0] = d2->cells[0];
        i2 = 1;
        i4 = 1;
    } else {
        // dot move right
        d4->expn = (expn - 1) / 2;
    }

    for (; i2 < GET_CELLS_SIZE(d2); i2 += 2, i4++) {
        d4->cells[i4] = (c4typ_t)d2->cells[i2] * DEC2_CELL_MASK;
        if (i2 + 1 < GET_CELLS_SIZE(d2)) {
            d4->cells[i4] += d2->cells[i2 + 1];
        }
    }
    d4->ncells = i4;
}

static inline status_t cm_dec_4_to_2(const dec4_t *d4, const uint32 sz_byte, dec2_t *d2)
{
    if (sz_byte == 0 || DECIMAL_IS_ZERO(d4)) {
        cm_zero_dec2(d2);
        return CT_SUCCESS;
    }
    // check validation again
    if (SECUREC_UNLIKELY((uint32)(cm_dec4_stor_sz(d4)) > sz_byte)) {
        CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "cm_dec4_stor_sz(d4)(%u) <= sz_byte(%u)", (uint32)(cm_dec2_stor_sz(d2)),
                          sz_byte);
        return CT_ERROR;
    }
    if (DEC4_GET_SEXP(d4) > DEC2_EXPN_UPPER) {
        CT_THROW_ERROR(ERR_NUM_OVERFLOW);
        return CT_ERROR;
    }
    uint32 i4 = 0;
    uint32 i2 = 0;
    uint32 len = 0;

    // left move dot
    if (d4->cells[0] < DEC2_CELL_MASK) {
        d2->cells[0] = (c2typ_t)d4->cells[0];
        d2->head = CONVERT_EXPN2(d4->expn * 2, d4->sign);
        i2++;
        i4++;
        len++;
    } else {
        d2->head = CONVERT_EXPN2(d4->expn * 2 + 1, d4->sign);
    }

    for (; i4 < d4->ncells && i2 < DEC2_CELL_SIZE - 1; i4++, i2 += 2) {
        d2->cells[i2] = d4->cells[i4] / DEC2_CELL_MASK;
        len++;
        d2->cells[i2 + 1] = d4->cells[i4] % DEC2_CELL_MASK;
        len++;
    }
    d2->len = len + 1;
    cm_dec2_trim_zeros(d2);

    return CT_SUCCESS;
}

/* The arithmetic operations among DECIMAL2 */
#define cm_int32_to_dec(i32, dec) cm_int32_to_dec8((i32), (dec))
#define cm_uint32_to_dec(i32, dec) cm_uint32_to_dec8((i32), (dec))
#define cm_int64_to_dec(i64, dec) cm_int64_to_dec8((i64), (dec))
#define cm_uint64_to_dec(u64, dec) cm_uint64_to_dec8((u64), (dec))
#define cm_real_to_dec(real, result) cm_real_to_dec8((real), (result))

#define cm_dec_to_real(dec) cm_dec8_to_real((dec))
#define cm_dec_to_uint64(dec, u64, rnd_mode) cm_dec8_to_uint64((dec), (u64), (rnd_mode))
#define cm_dec_to_int64(dec, i64, rnd_mode) cm_dec8_to_int64((dec), (i64), (rnd_mode))
#define cm_dec_to_uint32(dec, u32, rnd_mode) cm_dec8_to_uint32((dec), (u32), (rnd_mode))
#define cm_dec_to_int32(dec, i32, rnd_mode) cm_dec8_to_int32((dec), (i32), (rnd_mode))

/*
 * Decode a decimal from a void data with size

 */
static inline status_t cm_dec_4_to_8(dec8_t *d8, const dec4_t *d4, uint32 sz_byte)
{
    if (sz_byte == 0) {
        cm_zero_dec8(d8);
        return CT_SUCCESS;
    }
    // check validation again
    if ((uint32)(cm_dec4_stor_sz(d4)) > sz_byte) {
        CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "cm_dec4_stor_sz(d4)(%u) <= sz_byte(%u)",
                          (uint32)(cm_dec4_stor_sz(d4)), sz_byte);
        return CT_ERROR;
    }
    if (DECIMAL_IS_ZERO(d4)) {
        cm_zero_dec8(d8);
        return CT_SUCCESS;
    }

    uint32 i4 = 0;
    uint32 i8 = 0;
    if (d4->expn < 0) {
        d8->head = CONVERT_D8EXPN2((d4->expn - 1) / 2, d4->sign);
    } else {
        d8->head = CONVERT_D8EXPN2(d4->expn / 2, d4->sign);
    }

    if (d4->expn % 2 == 0) {
        d8->cells[0] = d4->cells[0];
        i4 = 1;
        i8 = 1;
    }

    for (; i4 < d4->ncells && i4 < DEC4_CELL_SIZE - 1; i4 += 2, i8++) {
        d8->cells[i8] = (c8typ_t)d4->cells[i4] * DEC4_CELL_MASK;
        if (i4 + 1 < d4->ncells) {
            d8->cells[i8] += d4->cells[i4 + 1];
        }
    }
    d8->len = i8 + 1;
    cm_dec8_trim_zeros(d8);
    return CT_SUCCESS;
}

static inline status_t cm_dec_8_to_4(dec4_t *d4, const dec8_t *d8)
{
    if (DECIMAL8_IS_ZERO(d8)) {
        cm_zero_dec4(d4);
        return CT_SUCCESS;
    }

    int16 expn = DEC8_GET_SEXP(d8);
    if (expn > MAX_NUMERIC_EXPN) {
        CT_THROW_ERROR(ERR_NUM_OVERFLOW);
        return CT_ERROR;
    } else if (expn < MIN_NUMERIC_EXPN) {
        cm_zero_dec4(d4);
        return CT_SUCCESS;
    }

    uint32 i8 = 0;
    uint32 i4 = 0;

    d4->sign = IS_DEC8_NEG(d8);
    d4->expn = (int8)(GET_DEC8_EXPN(d8) * 2 + 1);
    if (d8->cells[0] < DEC4_CELL_MASK) {
        d4->cells[0] = (c4typ_t)d8->cells[0];
        d4->expn--;
        i4++;
        i8++;
    }

    for (; i8 < GET_CELLS8_SIZE(d8) && i4 < DEC4_CELL_SIZE - 1; i8++, i4 += 2) {
        d4->cells[i4] = d8->cells[i8] / DEC4_CELL_MASK;
        d4->cells[i4 + 1] = d8->cells[i8] % DEC4_CELL_MASK;
    }

    // remove tailing zero if exits
    if (d4->cells[i4 - 1] == 0) {
        i4--;
    }
    d4->ncells = (uint8)i4;
    return CT_SUCCESS;
}

static inline status_t cm_dec_2_to_8(dec8_t *d8, const payload_t *d2, uint32 len)
{
    if (len == 0) {
        cm_zero_dec8(d8);
        return CT_SUCCESS;
    }

    if (len == 1 && DEC2_HEAD_IS_ZERO(d2->head)) {
        cm_zero_dec8(d8);
        return CT_SUCCESS;
    }

    uint32 i2 = 0;
    uint8 i8;
    uint8 ncells = len - 1;
    // The convert satisfies:
    // expn2 = expn8 * 4 + delta.
    // Convert the first delta cells of d2 to d8->cell[0]. To make sure the dot move right, the delta must be in [0, 3].
    int8 expn2 = GET_100_EXPN(d2);
    int8 expn8, delta;

    if (expn2 < 0) {
        expn8 = (int8)floor(expn2 * 1.0 / 4);
    } else {
        expn8 = expn2 / 4;
    }
    delta = expn2 - expn8 * 4;

    d8->head = CONVERT_D8EXPN2(expn8, IS_DEC_NEG(d2));
    d8->cells[0] = d2->cells[i2++] * g_1ten_powers[delta * 2];

    for (int8 i = delta - 1; i >= 0 && i2 < ncells; i--) {
        d8->cells[0] += d2->cells[i2++] * g_1ten_powers[i * 2];
    }

    for (i8 = 1; i2 < ncells; i8++) {
        d8->cells[i8] = (c8typ_t)d2->cells[i2++] * g_1ten_powers[6];
        if (i2 < ncells) {
            d8->cells[i8] += (c8typ_t)d2->cells[i2++] * g_1ten_powers[4];
        }
        if (i2 < ncells) {
            d8->cells[i8] += (c8typ_t)d2->cells[i2++] * DEC2_CELL_MASK;
        }
        if (i2 < ncells) {
            d8->cells[i8] += d2->cells[i2++];
        }
    }
    d8->len = i8 + 1;
    return CT_SUCCESS;
}

static inline status_t cm_dec_8_to_2(dec2_t *d2, const dec8_t *d8)
{
    if (DECIMAL8_IS_ZERO(d8)) {
        cm_zero_dec2(d2);
        return CT_SUCCESS;
    }

    uint8 i2 = 0;
    int8 expn, extra_expn;
    uint32 tmp;

    if (d8->cells[0] >= g_1ten_powers[4]) {
        extra_expn = ((d8->cells[0] >= g_1ten_powers[6]) ? 3 : 2);
    } else {
        extra_expn = ((d8->cells[0] >= DEC2_CELL_MASK) ? 1 : 0);
    }
    expn = GET_DEC8_EXPN(d8) * 4 + extra_expn;
    if (expn > DEC2_EXPN_UPPER_HALF) {
        CT_THROW_ERROR(ERR_NUM_OVERFLOW);
        return CT_ERROR;
    } else if (expn < DEC2_EXPN_LOW_HALF) {
        cm_zero_dec2(d2);
        return CT_SUCCESS;
    }

    tmp = d8->cells[0];
    d2->head = CONVERT_EXPN2((expn), IS_DEC8_NEG(d8));
    for (int32 i = extra_expn * 2; i >= 0; i -= 2) {
        d2->cells[i2++] = tmp / g_1ten_powers[i];
        tmp %= g_1ten_powers[i];
    }

    for (uint8 i8 = 1; i8 < GET_CELLS8_SIZE(d8) && i2 < DEC2_CELL_SIZE; i8++) {
        d2->cells[i2++] = d8->cells[i8] / g_1ten_powers[6];
        tmp = d8->cells[i8] % g_1ten_powers[6];
        if (i2 < DEC2_CELL_SIZE) {
            d2->cells[i2++] = tmp / g_1ten_powers[4];
            tmp %= g_1ten_powers[4];
        }
        if (i2 < DEC2_CELL_SIZE) {
            d2->cells[i2++] = tmp / DEC2_CELL_MASK;
            tmp %= DEC2_CELL_MASK;
        }
        if (i2 < DEC2_CELL_SIZE) {
            d2->cells[i2++] = tmp;
        }
    }
    d2->len = i2 + 1;
    // remove tailing zero if exits
    cm_dec2_trim_zeros(d2);
    return CT_SUCCESS;
}

/* The actual bytes of a dec8 in storage */
static inline uint32 cm_dec8_stor_sz(const dec8_t *d8)
{
    dec4_t d4;
    CT_RETURN_IFERR(cm_dec_8_to_4(&d4, d8));
    return cm_dec4_stor_sz(&d4);
}

static inline uint32 cm_dec8_stor_sz2(const dec8_t *d8)
{
    dec2_t d2;
    CT_RETURN_IFERR(cm_dec_8_to_2(&d2, d8));
    return cm_dec2_stor_sz(&d2);
}

static inline status_t cm_adjust_double(double *val, int32 precision, int32 scale)
{
    if (precision == CT_UNSPECIFIED_NUM_PREC) {
        return CT_SUCCESS;
    }

    dec8_t dec;
    CT_RETURN_IFERR(cm_real_to_dec8(*val, &dec));
    CT_RETURN_IFERR(cm_adjust_dec8(&dec, precision, scale));

    *val = cm_dec8_to_real(&dec);
    return CT_SUCCESS;
}

/* The arithmetic operations among DECIMAL and BIGINT */
static inline status_t cm_dec8_add_int64(const dec8_t *dec, int64 i64, dec8_t *result)
{
    dec8_t i64_dec;
    cm_int64_to_dec8(i64, &i64_dec);
    return cm_dec8_add(dec, &i64_dec, result);
}

static inline status_t cm_dec8_add_int32(const dec8_t *dec, int32 i32, dec8_t *result)
{
    dec8_t i32_dec;
    cm_int64_to_dec8(i32, &i32_dec);
    return cm_dec8_add(dec, &i32_dec, result);
}

static inline status_t cm_int64_sub_dec8(int64 i64, const dec8_t *dec, dec8_t *result)
{
    dec8_t i64_dec;
    cm_int64_to_dec8(i64, &i64_dec);
    return cm_dec8_subtract(&i64_dec, dec, result);
}

static inline status_t cm_dec8_mul_int64(const dec8_t *dec, int64 i64, dec8_t *result)
{
    dec8_t i64_dec;
    cm_int64_to_dec8(i64, &i64_dec);
    return cm_dec8_multiply(dec, &i64_dec, result);
}

static inline status_t cm_dec8_div_int64(const dec8_t *dec, int64 i64, dec8_t *result)
{
    dec8_t i64_dec;
    cm_int64_to_dec8(i64, &i64_dec);
    return cm_dec8_divide(dec, &i64_dec, result);
}

static inline status_t cm_int64_div_dec8(int64 i64, const dec8_t *dec, dec8_t *result)
{
    dec8_t i64_dec;
    cm_int64_to_dec8(i64, &i64_dec);
    return cm_dec8_divide(&i64_dec, dec, result);
}

static inline status_t cm_dec8_add_real(const dec8_t *dec, double real, dec8_t *result)
{
    dec8_t real_dec;
    if (cm_real_to_dec8(real, &real_dec) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return cm_dec8_add(dec, &real_dec, result);
}

static inline status_t cm_real_sub_dec8(double real, const dec8_t *dec, dec8_t *result)
{
    dec8_t real_dec;
    if (cm_real_to_dec8(real, &real_dec) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return cm_dec8_subtract(&real_dec, dec, result);
}

static inline status_t cm_dec8_mul_real(const dec8_t *dec, double real, dec8_t *result)
{
    dec8_t real_dec;
    if (cm_real_to_dec8(real, &real_dec) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return cm_dec8_multiply(dec, &real_dec, result);
}

static inline status_t cm_dec8_div_real(const dec8_t *dec, double real, dec8_t *result)
{
    dec8_t real_dec;
    if (cm_real_to_dec8(real, &real_dec) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return cm_dec8_divide(dec, &real_dec, result);
}

static inline status_t cm_real_div_dec8(double real, const dec8_t *dec, dec8_t *result)
{
    dec8_t real_dec;
    if (cm_real_to_dec8(real, &real_dec) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return cm_dec8_divide(&real_dec, dec, result);
}

#define cm_int64_sub_dec(i32, dec, result) cm_int64_sub_dec8((i32), (dec), (result))
#define cm_real_mul_dec(real, dec, result) cm_dec8_mul_real((dec), (real), (result))
#define cm_int64_add_dec(i64, dec, result) cm_dec8_add_int64((dec), (i64), (result))
#define cm_real_add_dec(real, dec, result) cm_dec8_add_real((dec), (real), (result))
#define cm_real_sub_dec(real, dec, result) cm_real_sub_dec8((real), (dec), (result))
#define cm_int64_mul_dec(i64, dec, result) cm_dec8_mul_int64((dec), (i64), (result))
#define cm_int64_div_dec(i64, dec, result) cm_int64_div_dec8((i64), (dec), (result))
#define cm_real_div_dec(real, dec, result) cm_real_div_dec8((real), (dec), (result))
#define cm_dec_div_int64(dec, i64, result) cm_dec8_div_int64((dec), (i64), (result))
#define cm_dec_add_int64(dec, i64, result) cm_dec8_add_int64((dec), (i64), (result))

#define cm_dec_div_real(dec, real, result) cm_dec8_div_real((dec), (real), (result))

#define cm_dec_add(dec1, dec2, result) cm_dec8_add((dec1), (dec2), (result))
#define cm_dec_subtract(dec1, dec2, result) cm_dec8_subtract((dec1), (dec2), (result))
#define cm_dec_mul(dec1, dec2, result) cm_dec8_multiply((dec1), (dec2), (result))
#define cm_dec_divide(dec1, dec2, result) cm_dec8_divide((dec1), (dec2), (result))
#define cm_dec_scale(dec, scale, rnd_mode) cm_dec8_scale((dec), (scale), (rnd_mode))
#define cm_dec_ceil(dec) cm_dec8_ceil((dec))
#define cm_dec_floor(dec) cm_dec8_floor((dec))

#define cm_dec_copy(dst, src) cm_dec8_copy((dst), (src))
#define cm_adjust_dec(dec, precision, scale) cm_adjust_dec8((dec), (precision), (scale))
#define cm_dec_to_text(dec, max_len, text) cm_dec8_to_text((dec), (max_len), (text))
#define cm_dec_to_str(dec, max_len, str) cm_dec8_to_str((dec), (max_len), (str))

#define cm_dec_sqrt(d, r) cm_dec8_sqrt((d), (r))
#define cm_text_to_dec(dec_text, dec) cm_text_to_dec8((dec_text), (dec))
#define cm_dec_is_integer(dec) cm_dec8_is_integer((dec))
#define cm_dec_abs(decl) cm_dec8_abs((decl))
#define cm_dec_sin(dec, result) cm_dec8_sin((dec), (result))
#define cm_dec_cos(dec, result) cm_dec8_cos((dec), (result))
#define cm_dec_tan(dec, result) cm_dec8_tan((dec), (result))
#define cm_dec_radians(dec, result) cm_dec8_radians((dec), (result))
#define cm_dec_pi(result) cm_dec8_pi((result))
#define cm_dec_asin(dec, result) cm_dec8_asin((dec), (result))
#define cm_dec_acos(dec, result) cm_dec8_acos((dec), (result))
#define cm_dec_atan(dec, result) cm_dec8_atan((dec), (result))
#define cm_dec_atan2(dec1, dec2, result) cm_dec8_atan2((dec1), (dec2), (result))
#define cm_dec_tanh(dec, result) cm_dec8_tanh((dec), (result))
#define cm_dec_exp(dec, result) cm_dec8_exp((dec), (result))
#define cm_dec_ln(dec, result) cm_dec8_ln((dec), (result))
#define cm_dec_mod(n2, n1, y) cm_dec8_mod((n2), (n1), (y))
#define cm_dec_power(x, r, y) cm_dec8_power((x), (r), (y))
#define cm_dec_log(n2, n1, result) cm_dec8_log((n2), (n1), (result))
#define cm_dec_sign(dec, result) cm_dec8_sign((dec), (result))
#define cm_hext_to_dec(hex_text, dec) cm_hext_to_dec8((hex_text), (dec))
#define cm_dec_cmp(dec1, dec2) cm_dec8_cmp((dec1), (dec2))
#define cm_dec_cmp_payload(pay1, len1, pay2, len2) \
    cm_dec2_cmp_payload((const payload_t *)(pay1), (len1), (const payload_t *)(pay2), (len2))

#define cm_dec_negate(dec) cm_dec8_negate((dec))
#define cm_dec_negate2(dec, ret) cm_dec8_negate2((dec), (ret))
#define cm_zero_dec(dec) cm_zero_dec8((dec))
#define cm_dec_stor_sz(dec) cm_dec8_stor_sz((dec))
#define cm_dec_stor_sz2(dec) cm_dec8_stor_sz2((dec))
#define cm_dec_check_overflow(dec, type) cm_dec8_check_type_overflow((dec), (type))

#ifdef __cplusplus
}
#endif

#endif
