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
 * var_opr.h
 *
 *
 * IDENTIFICATION
 * src/common/variant/var_opr.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __VAR_OPR_H__
#define __VAR_OPR_H__

#include "var_defs.h"
#include "var_cast.h"

#define OPR_THROW_ERROR(oper, l_type, r_type) \
    CT_THROW_ERROR(ERR_UNDEFINED_OPER,                       \
        get_datatype_name_str((int32)(l_type)),               \
        oper,                                                \
        get_datatype_name_str((int32)(r_type)))

/** check overflow for real/double type */
#define CHECK_REAL_OVERFLOW(val, inf_is_valid, zero_is_valid) \
    do {                                                       \
        if (isinf(val) && !(inf_is_valid)) {               \
            CT_THROW_ERROR(ERR_TYPE_OVERFLOW, "DOUBLE/REAL");  \
            return CT_ERROR;                                   \
        }                                                      \
        if ((val) == 0.0 && !(zero_is_valid)) {                \
            CT_THROW_ERROR(ERR_TYPE_OVERFLOW, "DOUBLE/REAL");  \
            return CT_ERROR;                                   \
        }                                                      \
    } while (0)

typedef struct st_opr_operand_set {
    nlsparams_t *nls;
    variant_t   *left;
    variant_t   *right;
    variant_t   *result;
} opr_operand_set_t;

#define OP_LEFT(op_set)   ((op_set)->left)
#define OP_RIGHT(op_set)  ((op_set)->right)
#define OP_RESULT(op_set) ((op_set)->result)

typedef status_t (*opr_exec_t)(opr_operand_set_t *op_set);
typedef status_t (*opr_infer_t)(ct_type_t left, ct_type_t right, ct_type_t *result);

typedef struct st_opr_rule {
    opr_exec_t     exec;          // executor
    ct_type_t      lc_type;       // the type left variant converted to
    ct_type_t      rc_type;       // the type right variant converted to
    ct_type_t      rs_type;       // the type of result
}opr_rule_t;

// declare rule for operator "+"
#define OPR_DECL(name, lct, rct, rst)  \
    static opr_rule_t g_opr_##name = {.exec = (name), .lc_type = (lct), .rc_type = (rct), .rs_type = (rst)}

#define __OPR_DEF(lt, rt, name) [CT_TYPE_I((lt))][CT_TYPE_I((rt))] = &(g_opr_##name)

static inline status_t opr_text2dec(variant_t *text, variant_t *dec)
{
    CT_RETURN_IFERR(cm_text_to_dec(VALUE_PTR(text_t, text), &dec->v_dec));
    dec->ctrl = 0;
    dec->type = CT_TYPE_NUMBER2;
    return CT_SUCCESS;
}

extern opr_exec_t  g_opr_execs[];
extern opr_infer_t g_opr_infers[];
extern uint32      g_opr_priority[];

status_t opr_exec(operator_type_t oper,
    const nlsparams_t *nls, variant_t *left, variant_t *right, variant_t *result);
status_t opr_infer_type(operator_type_t oper, ct_type_t left, ct_type_t right, ct_type_t *result);
status_t opr_infer_type_sum(ct_type_t sum_type, typmode_t *typmod);

// process binary as string if the binary variant is not from const hex
// binary data converted to string directly
#define OPR_ANYTYPE_BINARY(oper, op_set) \
    do { \
        variant_t var; \
        variant_t *old_right = OP_RIGHT(op_set);       \
        if (!OP_RIGHT(op_set)->v_bin.is_hex_const) { \
            var.v_bin = OP_RIGHT(op_set)->v_bin; \
            var.type  = CT_TYPE_STRING; \
        } else { \
            CT_RETURN_IFERR(cm_xbytes2bigint(&OP_RIGHT(op_set)->v_bin, &var.v_bigint)); \
            var.type = CT_TYPE_BIGINT; \
        } \
        OP_RIGHT(op_set) = &var; \
        status_t status = opr_exec_##oper(op_set); \
        OP_RIGHT(op_set) = old_right;      \
        return status;          \
    } while (0)

// process binary as string if the binary variant is not from const hex
// binary data converted to string directly
#define OPR_BINARY_ANYTYPE(oper, op_set) \
    do { \
        variant_t var; \
        variant_t *old_left = OP_LEFT(op_set);     \
        if (!OP_LEFT(op_set)->v_bin.is_hex_const) { \
            var.v_bin = OP_LEFT(op_set)->v_bin; \
            var.type  = CT_TYPE_STRING; \
        } else { \
            CT_RETURN_IFERR(cm_xbytes2bigint(&OP_LEFT(op_set)->v_bin, &var.v_bigint)); \
            var.type = CT_TYPE_BIGINT; \
        } \
        OP_LEFT(op_set) = &var; \
        status_t status = opr_exec_##oper(op_set); \
        OP_LEFT(op_set) = old_left;          \
        return status;          \
    } while (0)


typedef struct st_opr_options {
    bool32 div0_accepted;
} opr_options_t;

extern opr_options_t g_opr_options;

static inline char *var_get_buf(variant_t *var)
{
    char *buf = NULL;
    uint32 len = 0;

    if (var->is_null) {
        return NULL;
    }

    if (CT_IS_VARLEN_TYPE(var->type)) {
        buf = var->v_text.str;
        len = var->v_text.len;
    } else if (CT_IS_LOB_TYPE(var->type)) {
        if (var->v_lob.type == CT_LOB_FROM_KERNEL) {
            buf = (char *)var->v_lob.knl_lob.bytes;
            len = var->v_lob.knl_lob.size;
        } else if (var->v_lob.type == CT_LOB_FROM_NORMAL) {
            buf = var->v_lob.normal_lob.value.str;
            len = var->v_lob.normal_lob.value.len;
        } else {
            return NULL;
        }
    } else {
        return NULL;
    }

    if (len == 0) {
        return NULL;
    }

    return buf;
}

#ifdef WIN32
// add overflow check
#define opr_int32add_overflow(a, b, res) (Int32Add((a), (b), (res)) == INTSAFE_E_ARITHMETIC_OVERFLOW)
#define opr_int64add_overflow(a, b, res) (Int64Add((a), (b), (res)) == INTSAFE_E_ARITHMETIC_OVERFLOW)
#define opr_uint32add_overflow(a, b, res) (UInt32Add((a), (b), (res)) == INTSAFE_E_ARITHMETIC_OVERFLOW)
#define opr_uint64add_overflow(a, b, res) (UInt64Add((a), (b), (res)) == INTSAFE_E_ARITHMETIC_OVERFLOW)
//  sub overflow check
#define opr_int32sub_overflow(a, b, res) (Int32Sub((a), (b), (res)) == INTSAFE_E_ARITHMETIC_OVERFLOW)
#define opr_int64sub_overflow(a, b, res) (Int64Sub((a), (b), (res)) == INTSAFE_E_ARITHMETIC_OVERFLOW)
#define opr_uint32sub_overflow(a, b, res) (UInt32Sub((a), (b), (res)) == INTSAFE_E_ARITHMETIC_OVERFLOW)
#define opr_uint64sub_overflow(a, b, res) (UInt64Sub((a), (b), (res)) == INTSAFE_E_ARITHMETIC_OVERFLOW)
// multiple overflow check
#define opr_int32mul_overflow(a, b, res) (Int32Mult((a), (b), (res)) == INTSAFE_E_ARITHMETIC_OVERFLOW)
#define opr_int64mul_overflow(a, b, res) (Int64Mult((a), (b), (res)) == INTSAFE_E_ARITHMETIC_OVERFLOW)
#define opr_uint32mul_overflow(a, b, res) (UInt32Mult((a), (b), (res)) == INTSAFE_E_ARITHMETIC_OVERFLOW)
#define opr_uint64mul_overflow(a, b, res) (UInt64Mult((a), (b), (res)) == INTSAFE_E_ARITHMETIC_OVERFLOW)

#else
// add overflow check
#define opr_int32add_overflow(a, b, res) __builtin_sadd_overflow((a), (b), (res))
#define opr_int64add_overflow(a, b, res) __builtin_saddll_overflow((a), (b), (res))
#define opr_uint32add_overflow(a, b, res) __builtin_uadd_overflow((a), (b), (res))
#define opr_uint64add_overflow(a, b, res) __builtin_uaddll_overflow((a), (b), (res))
//  sub overflow check
#define opr_int32sub_overflow(a, b, res) __builtin_ssub_overflow((a), (b), (res))
#define opr_int64sub_overflow(a, b, res) __builtin_ssubll_overflow((a), (b), (res))
#define opr_uint32sub_overflow(a, b, res) __builtin_usub_overflow((a), (b), (res))
#define opr_uint64sub_overflow(a, b, res) __builtin_usubll_overflow((a), (b), (res))
// multiple overflow check
#define opr_int32mul_overflow(a, b, res) __builtin_smul_overflow((a), (b), (res))
#define opr_int64mul_overflow(a, b, res) __builtin_smulll_overflow((a), (b), (res))
#define opr_uint32mul_overflow(a, b, res) __builtin_umul_overflow((a), (b), (res))
#define opr_uint64mul_overflow(a, b, res) __builtin_umulll_overflow((a), (b), (res))

#endif

#endif
