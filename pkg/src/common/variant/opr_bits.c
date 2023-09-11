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
 * opr_bits.c
 *
 *
 * IDENTIFICATION
 * src/common/variant/opr_bits.c
 *
 * -------------------------------------------------------------------------
 */
#include "opr_bits.h"

#define PREPARE_BIT_OPER(op_set)                             \
    do {                                                     \
        OP_RESULT(op_set)->v_bigint = 0;                     \
        OP_RESULT(op_set)->type = GS_TYPE_BIGINT;            \
                                                             \
        if (var_as_bigint(OP_LEFT(op_set)) != GS_SUCCESS) {  \
            return GS_ERROR;                                 \
        }                                                    \
                                                             \
        if (var_as_bigint(OP_RIGHT(op_set)) != GS_SUCCESS) { \
            return GS_ERROR;                                 \
        }                                                    \
    } while (0)

status_t opr_exec_bitand(opr_operand_set_t *op_set)
{
    PREPARE_BIT_OPER(op_set);
    OP_RESULT(op_set)->v_bigint = OP_LEFT(op_set)->v_bigint & OP_RIGHT(op_set)->v_bigint;
    return GS_SUCCESS;
}


status_t opr_exec_bitor(opr_operand_set_t *op_set)
{
    PREPARE_BIT_OPER(op_set);
    OP_RESULT(op_set)->v_bigint = OP_LEFT(op_set)->v_bigint | OP_RIGHT(op_set)->v_bigint;
    return GS_SUCCESS;
}

status_t opr_exec_bitxor(opr_operand_set_t *op_set)
{
    PREPARE_BIT_OPER(op_set);
    OP_RESULT(op_set)->v_bigint = OP_LEFT(op_set)->v_bigint ^ OP_RIGHT(op_set)->v_bigint;
    return GS_SUCCESS;
}

#define PREPARE_BIT_SHIFT(op_set)                                                 \
    do {                                                                          \
        OP_RESULT(op_set)->v_bigint = 0;                                          \
        OP_RESULT(op_set)->type = GS_TYPE_BIGINT;                                 \
                                                                                  \
        if (var_as_bigint(OP_LEFT(op_set)) != GS_SUCCESS) {                       \
            return GS_ERROR;                                                      \
        }                                                                         \
                                                                                  \
        if (var_as_bigint(OP_RIGHT(op_set)) != GS_SUCCESS) {                      \
            return GS_ERROR;                                                      \
        }                                                                         \
                                                                                  \
        if (OP_RIGHT(op_set)->v_bigint >= 64 || OP_RIGHT(op_set)->v_bigint < 0) { \
            return GS_SUCCESS;                                                    \
        }                                                                         \
    } while (0)


status_t opr_exec_lshift(opr_operand_set_t *op_set)
{
    PREPARE_BIT_SHIFT(op_set);
    OP_RESULT(op_set)->v_bigint = OP_LEFT(op_set)->v_bigint << OP_RIGHT(op_set)->v_bigint;
    return GS_SUCCESS;
}

status_t opr_exec_rshift(opr_operand_set_t *op_set)
{
    PREPARE_BIT_SHIFT(op_set);
    OP_RESULT(op_set)->v_bigint = OP_LEFT(op_set)->v_bigint >> OP_RIGHT(op_set)->v_bigint;
    return GS_SUCCESS;
}
