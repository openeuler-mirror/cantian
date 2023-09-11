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

opr_options_t g_opr_options = { GS_FALSE };

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

status_t opr_infer_type_sum(gs_type_t sum_type, typmode_t *typmod)
{
    switch (sum_type) {
        case GS_TYPE_UINT32:
        case GS_TYPE_INTEGER:
            typmod->datatype = GS_TYPE_BIGINT;
            typmod->size = 8;
            return GS_SUCCESS;

        case GS_TYPE_BIGINT:
        case GS_TYPE_NUMBER:
        case GS_TYPE_DECIMAL:
        case GS_TYPE_CHAR:
        case GS_TYPE_VARCHAR:
        case GS_TYPE_STRING:
        case GS_TYPE_UNKNOWN:
            typmod->datatype = GS_TYPE_NUMBER;
            typmod->size = MAX_DEC_BYTE_SZ;
            return GS_SUCCESS;
        case GS_TYPE_NUMBER2:
            typmod->datatype = GS_TYPE_NUMBER2;
            typmod->size = MAX_DEC2_BYTE_SZ;
            return GS_SUCCESS;

        case GS_TYPE_REAL:
            typmod->datatype = GS_TYPE_REAL;
            typmod->size = 8;
            return GS_SUCCESS;

        default:
            GS_THROW_ERROR(ERR_TYPE_MISMATCH, "NUMERIC", get_datatype_name_str(sum_type));
            return GS_ERROR;
    }
}

status_t opr_unary(variant_t *right, variant_t *result)
{
    switch (right->type) {
        case GS_TYPE_UINT32:
            result->v_bigint = -(int64)right->v_uint32;
            result->type = GS_TYPE_BIGINT;
            return GS_SUCCESS;

        case GS_TYPE_INTEGER:
            result->v_bigint = -(int64)right->v_int;
            result->type = GS_TYPE_BIGINT;
            return GS_SUCCESS;

        case GS_TYPE_BIGINT:
            if (right->v_bigint == GS_MIN_INT64) {
                GS_THROW_ERROR(ERR_TYPE_OVERFLOW, "BIGINT");
                return GS_ERROR;
            }
            result->type = GS_TYPE_BIGINT;
            result->v_bigint = -right->v_bigint;
            return GS_SUCCESS;

        case GS_TYPE_REAL:
            result->type = GS_TYPE_REAL;
            result->v_real = -right->v_real;
            return GS_SUCCESS;

        case GS_TYPE_NUMBER:
        case GS_TYPE_DECIMAL:
            result->type = GS_TYPE_NUMBER;
            cm_dec_negate2(&right->v_dec, &result->v_dec);
            return GS_SUCCESS;

        case GS_TYPE_NUMBER2:
            result->type = GS_TYPE_NUMBER2;
            cm_dec_negate2(&right->v_dec, &result->v_dec);
            return GS_SUCCESS;

        case GS_TYPE_CHAR:
        case GS_TYPE_VARCHAR:
        case GS_TYPE_STRING:
        case GS_TYPE_BINARY:
        case GS_TYPE_VARBINARY: {
            GS_RETURN_IFERR(cm_text_to_dec8(VALUE_PTR(text_t, right), &result->v_dec));
            result->type = GS_TYPE_NUMBER;
            cm_dec_negate(&result->v_dec);
            return GS_SUCCESS;
        }

        case GS_TYPE_DATE:
        case GS_TYPE_TIMESTAMP:
        case GS_TYPE_INTERVAL_DS:
        case GS_TYPE_INTERVAL_YM:
        case GS_TYPE_RAW:
        case GS_TYPE_CLOB:
        case GS_TYPE_BLOB:
        case GS_TYPE_IMAGE:
        case GS_TYPE_CURSOR:
        case GS_TYPE_COLUMN:
        case GS_TYPE_BOOLEAN:
        case GS_TYPE_TIMESTAMP_TZ_FAKE:
        case GS_TYPE_TIMESTAMP_TZ:
        case GS_TYPE_TIMESTAMP_LTZ:
        default:
            break;
    }

    GS_THROW_ERROR(ERR_UNDEFINED_OPER, "", "-", get_datatype_name_str((int32)(right->type)));
    return GS_ERROR;
}

static inline bool32 is_valid_operand_type(gs_type_t l_type, gs_type_t r_type)
{
    return (l_type > GS_TYPE_BASE && l_type < GS_TYPE__DO_NOT_USE) &&
        (r_type > GS_TYPE_BASE && r_type < GS_TYPE__DO_NOT_USE);
}

status_t opr_exec(operator_type_t oper,
    const nlsparams_t *nls, variant_t *left, variant_t *right, variant_t *result)
{
    if (SECUREC_UNLIKELY(left->is_null || right->is_null)) {
        if (oper != OPER_TYPE_CAT) {
            result->type = GS_DATATYPE_OF_NULL;
            result->is_null = GS_TRUE;
            return GS_SUCCESS;
        }

        if (left->is_null) {
            left->type = GS_DATATYPE_OF_NULL;
        }

        if (right->is_null) {
            right->type = GS_DATATYPE_OF_NULL;
        }
    }

    if (SECUREC_UNLIKELY(!is_valid_operand_type(left->type, right->type))) {
        GS_THROW_ERROR(ERR_INVALID_OPERATION, " illegal operand datatype");
        return GS_ERROR;
    }

    if (SECUREC_UNLIKELY(oper >= OPER_TYPE_CEIL || g_opr_execs[oper] == NULL)) {
        GS_THROW_ERROR(ERR_INVALID_OPERATION, " illegal operator");
        return GS_ERROR;
    }

    opr_exec_t exec = g_opr_execs[oper];
    opr_operand_set_t op_set = { (nlsparams_t *)nls, left, right, result };
    result->is_null = GS_FALSE;
    return exec(&op_set);
}


status_t opr_infer_type(operator_type_t oper, gs_type_t left, gs_type_t right, gs_type_t *result)
{
    if (SECUREC_UNLIKELY(oper >= OPER_TYPE_CEIL)) {
        GS_THROW_ERROR(ERR_INVALID_OPERATION, "illegal operator");
        return GS_ERROR;
    }

    if (GS_IS_UNKNOWN_TYPE(left) || GS_IS_UNKNOWN_TYPE(right)) {
        *result = GS_TYPE_UNKNOWN;
        return GS_SUCCESS;
    }

    if (SECUREC_UNLIKELY(!is_valid_operand_type(left, right))) {
        GS_THROW_ERROR(ERR_INVALID_OPERATION, "illegal operand datatype");
        return GS_ERROR;
    }

    opr_infer_t infer = g_opr_infers[oper];

    if (SECUREC_UNLIKELY(infer == NULL)) {
        *result = GS_TYPE_UNKNOWN;
        return GS_SUCCESS;
    }

    return infer(left, right, result);
}