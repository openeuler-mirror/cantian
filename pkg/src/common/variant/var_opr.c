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
 * var_opr.c
 *
 *
 * IDENTIFICATION
 * src/common/variant/var_opr.c
 *
 * -------------------------------------------------------------------------
 */
#include "var_opr.h"
#include "opr_add.h"
#include "opr_sub.h"
#include "opr_mul.h"
#include "opr_div.h"
#include "opr_mod.h"
#include "opr_cat.h"
#include "opr_bits.h"

opr_options_t g_opr_options = { CT_FALSE };

opr_exec_t g_opr_execs[OPER_TYPE_CEIL] = {
    [OPER_TYPE_ADD]    = opr_exec_add,
    [OPER_TYPE_SUB]    = opr_exec_sub,
    [OPER_TYPE_MUL]    = opr_exec_mul,
    [OPER_TYPE_DIV]    = opr_exec_div,
    [OPER_TYPE_MOD]    = opr_exec_mod,
    [OPER_TYPE_CAT]    = opr_exec_cat,
    [OPER_TYPE_BITAND] = opr_exec_bitand,
    [OPER_TYPE_BITOR]  = opr_exec_bitor,
    [OPER_TYPE_BITXOR] = opr_exec_bitxor,
    [OPER_TYPE_LSHIFT] = opr_exec_lshift,
    [OPER_TYPE_RSHIFT] = opr_exec_rshift,
};

opr_infer_t g_opr_infers[OPER_TYPE_CEIL] = {
    [OPER_TYPE_ADD] = opr_type_infer_add,
    [OPER_TYPE_SUB] = opr_type_infer_sub,
    [OPER_TYPE_MUL] = opr_type_infer_mul,
    [OPER_TYPE_DIV] = opr_type_infer_div,
    [OPER_TYPE_MOD] = opr_type_infer_mod,
};

uint32 g_opr_priority[OPER_TYPE_CEIL] = {
    [OPER_TYPE_ROOT]   = 65535,
    [OPER_TYPE_PRIOR]  = 65535,
    [OPER_TYPE_MUL]    = 3,
    [OPER_TYPE_DIV]    = 3,
    [OPER_TYPE_MOD]    = 3,
    [OPER_TYPE_ADD]    = 4,
    [OPER_TYPE_SUB]    = 4,
    [OPER_TYPE_LSHIFT] = 5,
    [OPER_TYPE_RSHIFT] = 5,
    [OPER_TYPE_BITAND] = 8,
    [OPER_TYPE_BITXOR] = 9,
    [OPER_TYPE_BITOR]  = 10,
    [OPER_TYPE_CAT]    = 4
};

status_t opr_infer_type_sum(ct_type_t sum_type, typmode_t *typmod)
{
    switch (sum_type) {
        case CT_TYPE_UINT32:
        case CT_TYPE_INTEGER:
            typmod->datatype = CT_TYPE_BIGINT;
            typmod->size = 8;
            return CT_SUCCESS;

        case CT_TYPE_BIGINT:
        case CT_TYPE_NUMBER:
        case CT_TYPE_DECIMAL:
        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
        case CT_TYPE_STRING:
        case CT_TYPE_UNKNOWN:
            typmod->datatype = CT_TYPE_NUMBER;
            typmod->size = MAX_DEC_BYTE_SZ;
            return CT_SUCCESS;
        case CT_TYPE_NUMBER2:
            typmod->datatype = CT_TYPE_NUMBER2;
            typmod->size = MAX_DEC2_BYTE_SZ;
            return CT_SUCCESS;

        case CT_TYPE_REAL:
            typmod->datatype = CT_TYPE_REAL;
            typmod->size = 8;
            return CT_SUCCESS;

        default:
            CT_THROW_ERROR(ERR_TYPE_MISMATCH, "NUMERIC", get_datatype_name_str(sum_type));
            return CT_ERROR;
    }
}

status_t opr_unary(variant_t *right, variant_t *result)
{
    switch (right->type) {
        case CT_TYPE_UINT32:
            result->v_bigint = -(int64)right->v_uint32;
            result->type = CT_TYPE_BIGINT;
            return CT_SUCCESS;

        case CT_TYPE_INTEGER:
            result->v_bigint = -(int64)right->v_int;
            result->type = CT_TYPE_BIGINT;
            return CT_SUCCESS;

        case CT_TYPE_BIGINT:
            if (right->v_bigint == CT_MIN_INT64) {
                CT_THROW_ERROR(ERR_TYPE_OVERFLOW, "BIGINT");
                return CT_ERROR;
            }
            result->type = CT_TYPE_BIGINT;
            result->v_bigint = -right->v_bigint;
            return CT_SUCCESS;

        case CT_TYPE_REAL:
            result->type = CT_TYPE_REAL;
            result->v_real = -right->v_real;
            return CT_SUCCESS;

        case CT_TYPE_NUMBER:
        case CT_TYPE_DECIMAL:
            result->type = CT_TYPE_NUMBER;
            cm_dec_negate2(&right->v_dec, &result->v_dec);
            return CT_SUCCESS;

        case CT_TYPE_NUMBER2:
            result->type = CT_TYPE_NUMBER2;
            cm_dec_negate2(&right->v_dec, &result->v_dec);
            return CT_SUCCESS;

        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
        case CT_TYPE_STRING:
        case CT_TYPE_BINARY:
        case CT_TYPE_VARBINARY: {
            CT_RETURN_IFERR(cm_text_to_dec8(VALUE_PTR(text_t, right), &result->v_dec));
            result->type = CT_TYPE_NUMBER;
            cm_dec_negate(&result->v_dec);
            return CT_SUCCESS;
        }

        case CT_TYPE_DATE:
        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_INTERVAL_DS:
        case CT_TYPE_INTERVAL_YM:
        case CT_TYPE_RAW:
        case CT_TYPE_CLOB:
        case CT_TYPE_BLOB:
        case CT_TYPE_IMAGE:
        case CT_TYPE_CURSOR:
        case CT_TYPE_COLUMN:
        case CT_TYPE_BOOLEAN:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
        case CT_TYPE_TIMESTAMP_TZ:
        case CT_TYPE_TIMESTAMP_LTZ:
        default:
            break;
    }

    CT_THROW_ERROR(ERR_UNDEFINED_OPER, "", "-", get_datatype_name_str((int32)(right->type)));
    return CT_ERROR;
}

static inline bool32 is_valid_operand_type(ct_type_t l_type, ct_type_t r_type)
{
    return (l_type > CT_TYPE_BASE && l_type < CT_TYPE__DO_NOT_USE) &&
        (r_type > CT_TYPE_BASE && r_type < CT_TYPE__DO_NOT_USE);
}

status_t opr_exec(operator_type_t oper,
    const nlsparams_t *nls, variant_t *left, variant_t *right, variant_t *result)
{
    if (SECUREC_UNLIKELY(left->is_null || right->is_null)) {
        if (oper != OPER_TYPE_CAT) {
            result->type = CT_DATATYPE_OF_NULL;
            result->is_null = CT_TRUE;
            return CT_SUCCESS;
        }

        if (left->is_null) {
            left->type = CT_DATATYPE_OF_NULL;
        }

        if (right->is_null) {
            right->type = CT_DATATYPE_OF_NULL;
        }
    }

    if (SECUREC_UNLIKELY(!is_valid_operand_type(left->type, right->type))) {
        CT_THROW_ERROR(ERR_INVALID_OPERATION, " illegal operand datatype");
        return CT_ERROR;
    }

    if (SECUREC_UNLIKELY(oper >= OPER_TYPE_CEIL || g_opr_execs[oper] == NULL)) {
        CT_THROW_ERROR(ERR_INVALID_OPERATION, " illegal operator");
        return CT_ERROR;
    }

    opr_exec_t exec = g_opr_execs[oper];
    opr_operand_set_t op_set = { (nlsparams_t *)nls, left, right, result };
    result->is_null = CT_FALSE;
    return exec(&op_set);
}


status_t opr_infer_type(operator_type_t oper, ct_type_t left, ct_type_t right, ct_type_t *result)
{
    if (SECUREC_UNLIKELY(oper >= OPER_TYPE_CEIL)) {
        CT_THROW_ERROR(ERR_INVALID_OPERATION, "illegal operator");
        return CT_ERROR;
    }

    if (CT_IS_UNKNOWN_TYPE(left) || CT_IS_UNKNOWN_TYPE(right)) {
        *result = CT_TYPE_UNKNOWN;
        return CT_SUCCESS;
    }

    if (SECUREC_UNLIKELY(!is_valid_operand_type(left, right))) {
        CT_THROW_ERROR(ERR_INVALID_OPERATION, "illegal operand datatype");
        return CT_ERROR;
    }

    opr_infer_t infer = g_opr_infers[oper];

    if (SECUREC_UNLIKELY(infer == NULL)) {
        *result = CT_TYPE_UNKNOWN;
        return CT_SUCCESS;
    }

    return infer(left, right, result);
}