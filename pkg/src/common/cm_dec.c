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
 * cm_dec.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_dec.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_dec.h"
#ifdef __cplusplus
extern "C" {
#endif

const uint32 g_1ten_powers[10] = {
    1u,          // 10^0
    10u,         // 10^1
    100u,        // 10^2
    1000u,       // 10^3
    10000u,      // 10^4
    100000u,     // 10^5
    1000000u,    // 10^6
    10000000u,   // 10^7
    100000000u,  // 10^8
    1000000000u  // 10^9
};

// half of g_1ten_powers, used for rounding a decimal
const uint32 g_5ten_powers[10] = {
    0u,          // 0
    5u,          // 5 x 10^0
    50u,         // 5 x 10^1
    500u,        // 5 x 10^2
    5000u,       // 5 x 10^3
    50000u,      // 5 x 10^4
    500000u,     // 5 x 10^5
    5000000u,    // 5 x 10^6
    50000000u,   // 5 x 10^7
    500000000u,  // 5 x 10^8
};

status_t cm_dec2uint64_check_overflow(uint64 u64h, uint64 u64l, uint64 *u64)
{
    if (u64h == 18440000000000000000ull && u64l > 6744073709551615ull) {
        CT_THROW_ERROR(ERR_TYPE_OVERFLOW, "UINT64");
        return CT_ERROR;
    }
    *u64 = u64h + u64l;
    return CT_SUCCESS;
}

status_t cm_dec2int64_check_overflow(uint64 u64_val, bool8 is_neg, int64 *val)
{
    if (u64_val > 9223372036854775807ull) {
        if (is_neg && u64_val == 9223372036854775808ull) {
            *val = CT_MIN_INT64;
            return CT_SUCCESS;
        }

        CT_THROW_ERROR(ERR_TYPE_OVERFLOW, "BIGINT");
        return CT_ERROR;
    }

    *val = is_neg ? -(int64)u64_val : (int64)u64_val;
    return CT_SUCCESS;
}

#ifdef __cplusplus
}
#endif
