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
 * cm_dec.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_dec.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __CM_DEC_H_
#define __CM_DEC_H_

#include <math.h>
#include "cm_defs.h"
#include "cm_debug.h"
#include "cm_text.h"

#ifdef __cplusplus
extern "C" {
#endif

/*  The maximal buff size for parsing a decimal, The MAX_NUMERIC_BUFF is
 *  set to be greater than MAX_NUM_PRECISION, which can be captured
 *  more significant digits, and thus can promote high calculation accuracy.
 *  The bigger the value is, the more accuracy it can be improved, but may
 *  weaken the performance.
 */
#define MAX_NUMERIC_BUFF 65
    
/* The maximal precision for comparing two decimal. Directly compare
 * two decimals may cause failure as several digits in the last may be
 * not too much accuracy,
 * @note  MAX_NUM_CMP_PREC <= MAX_NUMERIC_BUFF, i.e., must less than
 * the number of digits in buff
 */
#define MAX_NUM_CMP_PREC CT_MAX_NUM_SAVING_PREC
    
#define CT_PI 3.14159265358979323846        // pi
#define CT_PI_2 1.57079632679489661923      // pi/2
#define CT_PI_4 0.785398163397448309616     // pi/4
#define CT_1_PI 0.318309886183790671538     // 1/pi
#define CT_2_PI 0.636619772367581343076     // 2/pi
#define CT_2_SQRTPI 1.12837916709551257390  // 2/sqrt(pi)
#define CT_180_DEGREE 180.0                 //180°
    
#define CT_LOG10_2 0.30102999566398119521374  // log10(2)
#define DEC_EXPN_BUFF_SZ 16

#define INV_FACT_START 3
#define _I(i) ((i) - INV_FACT_START)

extern const uint32 g_1ten_powers[];
extern const uint32 g_5ten_powers[];

typedef enum en_round_mode {
    ROUND_TRUNC,   /* round towards zero, @see C function *trunc*, <==> (int)dec */
    ROUND_CEILING, /* round towards positive infinity, @see C function *ceil* */
    ROUND_FLOOR,   /* round towards negative infinity, @see C function *floor* */
    /* round towards "nearest neighbor" unless both neighbors are equidistant, in which case round up. */
    ROUND_HALF_UP,
} round_mode_t;

/* Truncate tailing *prec* number of digits of an int64 into zeros.
 * e.g., cm_truncate_bigint(123123, 3) ==> 123000
 *   cm_truncate_bigint(123623, 3) ==> 124000
 * @note prec can not exceed 9  */
static inline int64 cm_truncate_bigint(int64 val_input, uint32 prec)
{
    int64 val = val_input;
    if (val >= 0) {
        val += g_5ten_powers[prec];  // for round
    } else {
        val -= g_5ten_powers[prec];  // for round
    }

    return (val / g_1ten_powers[prec]) * g_1ten_powers[prec];
}

/*
 * Count the number of 10-base digits of an uint16.
 * e.g. 451 ==> 3, 12 ==> 2, abs(-100) ==> 3, 0 ==> 1, 1 ==> 1
 */
static inline uint32 cm_count_u16digits(uint16 u16)
{
    // Binary search
    if (u16 >= 1000u) {
        return (uint32)((u16 >= 10000u) ? 5 : 4);
    }

    return (uint32)((u16 >= 100u) ? 3 : ((u16 >= 10u) ? 2 : 1));
}

/*
 * Count the number of 10-base digits of an uint8.
 * e.g. >=100 ==>3 >=10 ==>2, < 10 ==> 1
 */
static inline uint32 cm_count_u8digits(uint8 u8)
{
    return (uint32)((u8 >= 10u) ? ((u8 >= 100u) ? 3 : 2) : 1);
}

static inline uint32 cm_count_u32digits(uint32 u32)
{
    // Binary search
    if (u32 >= 100000u) {
        if (u32 >= 10000000u) {
            return (uint32)((u32 < 100000000u) ? 8 : ((u32 >= 1000000000u) ? 10 : 9));
        }
        return (uint32)((u32 >= 1000000u) ? 7 : 6);
    }

    if (u32 >= 1000u) {
        return (uint32)((u32 >= 10000u) ? 5 : 4);
    }

    return (uint32)((u32 >= 100u) ? 3 : ((u32 >= 10u) ? 2 : 1));
}

static inline double cm_round_real(double val, round_mode_t mode)
{
    switch (mode) {
        case ROUND_TRUNC:
            return trunc(val);

        case ROUND_CEILING:
            return ceil(val);

        case ROUND_FLOOR:
            return floor(val);

        case ROUND_HALF_UP:
            return round(val);
        default:
            CM_NEVER;
            return 0;
    }
}

/**
 * Convert a single cell text into uint32. A single cell text is a text of
 * digits, with the number of text is no more than 9

 */
static inline uint32 cm_celltext2uint32(const text_t *cellt)
{
    uint32 val = 0;

    for (uint32 i = 0; i < cellt->len; ++i) {
        val = val * 10 + (uint32)(uint8)CM_C2D(cellt->str[i]);
    }

    return val;
}

status_t cm_dec2uint64_check_overflow(uint64 u64h, uint64 u64l, uint64 *u64);
status_t cm_dec2int64_check_overflow(uint64 u64_val, bool8 is_neg, int64 *val);

#ifdef __cplusplus
}
#endif

#endif
