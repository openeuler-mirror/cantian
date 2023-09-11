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
 * opr_add.h
 *
 *
 * IDENTIFICATION
 * src/common/variant/opr_add.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __OPR_ADD_H__
#define __OPR_ADD_H__

#include "var_opr.h"

status_t opr_exec_add(opr_operand_set_t *op_set);
status_t opr_type_infer_add(gs_type_t left, gs_type_t right, gs_type_t *result);

/**
* addition/subtraction of two bigints, if overflow occurs, an error will be return;
*/
static inline status_t opr_bigint_add(int64 a, int64 b, int64 *res)
{
    if (SECUREC_UNLIKELY(opr_int64add_overflow(a, b, res))) {
        GS_THROW_ERROR(ERR_TYPE_OVERFLOW, "BIGINT");
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

static inline status_t opr_double_add(double a, double b, double *res)
{
    bool32 inf_is_valid = isinf(a) || isinf(b);
    *res = a + b;
    if (isinf(*res) && !inf_is_valid) {
        GS_THROW_ERROR(ERR_TYPE_OVERFLOW, "DOUBLE/REAL");
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

#endif
