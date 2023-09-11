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
 * opr_mul.c
 *
 *
 * IDENTIFICATION
 * src/common/variant/opr_mul.c
 *
 * -------------------------------------------------------------------------
 */
#include "opr_mul.h"

static inline status_t mul_anytype_binary(opr_operand_set_t *op_set)
{
    OPR_ANYTYPE_BINARY(mul, op_set);
}

static inline status_t mul_binary_anytype(opr_operand_set_t *op_set)
{
    OPR_BINARY_ANYTYPE(mul, op_set);
}

static inline status_t opr_bigint_mul(int64 a, int64 b, int64 *res)
{
    if (SECUREC_UNLIKELY(opr_int64mul_overflow(a, b, res))) {
        GS_THROW_ERROR(ERR_TYPE_OVERFLOW, "BIGINT");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

/**
* multiplication of two integers, if overflow occurs, an error will be return;
*/
static inline status_t opr_int32_mul(int32 a, int32 b, int32 *res)
{
    if (SECUREC_UNLIKELY(opr_int32mul_overflow(a, b, res))) {
        GS_THROW_ERROR(ERR_TYPE_OVERFLOW, "INTEGER");
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

static inline status_t opr_double_mul(double a, double b, double *res)
{
    bool32 inf_is_valid = isinf(a) || isinf(b);
    *res = (VAR_DOUBLE_IS_ZERO(a) || VAR_DOUBLE_IS_ZERO(b)) ? 0 : (a * b);
    CHECK_REAL_OVERFLOW(*res, inf_is_valid, (VAR_DOUBLE_IS_ZERO(a) || VAR_DOUBLE_IS_ZERO(b)));
    return GS_SUCCESS;
}

static inline status_t opr_ymitvl_mul_real(interval_ym_t ymitvl, double num, interval_ym_t *res)
{
    double mul_res;
    do {
        if (ymitvl != 0 && fabs(num) > GS_MAX_YMINTERVAL) {
            break;
        }
        mul_res = ymitvl * num;
        if (fabs(mul_res) > GS_MAX_YMINTERVAL) {
            break;
        }
        *res = (interval_ym_t)mul_res;
        return GS_SUCCESS;
    } while (0);

    GS_THROW_ERROR(ERR_TYPE_OVERFLOW, "INTERVAL YEAR TO MONTH");
    return GS_ERROR;
}

static inline status_t opr_real_mul_ymitvl(double num, interval_ym_t ymitvl, interval_ym_t *res)
{
    return opr_ymitvl_mul_real(ymitvl, num, res);
}

static inline status_t opr_dsitvl_mul_real(interval_ds_t dsitvl, double num, interval_ds_t *res)
{
    double mul_res;
    do {
        if (dsitvl != 0 && fabs(num) > GS_MAX_DSINTERVAL) {
            break;
        }
        mul_res = dsitvl * num;
        if (fabs(mul_res) > GS_MAX_DSINTERVAL) {
            break;
        }
        *res = (interval_ds_t)mul_res;
        return GS_SUCCESS;
    } while (0);

    GS_THROW_ERROR(ERR_TYPE_OVERFLOW, "INTERVAL DAY TO SECOND");
    return GS_ERROR;
}

static inline status_t opr_real_mul_dsitvl(double num, interval_ds_t dsitvl, interval_ds_t *res)
{
    return opr_dsitvl_mul_real(dsitvl, num, res);
}

static inline status_t opr_dec_mul_dsitvl(const dec8_t *dec, interval_ds_t dsitvl, interval_ds_t *result)
{
    double num = cm_dec_to_real(dec);
    return opr_real_mul_dsitvl(num, dsitvl, result);
}

static inline status_t opr_dsitvl_mul_dec(interval_ds_t dsitvl, const dec8_t *dec, interval_ds_t *result)
{
    return opr_dec_mul_dsitvl(dec, dsitvl, result);
}

static inline status_t opr_dec_mul_ymitvl(const dec8_t *dec, interval_ym_t ymitvl, interval_ym_t *result)
{
    double num = cm_dec_to_real(dec);
    return opr_real_mul_ymitvl(num, ymitvl, result);
}


static inline status_t opr_ymitvl_mul_dec(interval_ym_t ymitvl, const dec8_t *dec, interval_ym_t *result)
{
    return opr_dec_mul_ymitvl(dec, ymitvl, result);
}

static inline status_t mul_uint_uint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_BIGINT;
    return opr_bigint_mul((int64)OP_LEFT(op_set)->v_uint32, (int64)OP_RIGHT(op_set)->v_uint32,
        &OP_RESULT(op_set)->v_bigint);
}

static inline status_t mul_uint_int(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_BIGINT;
    return opr_bigint_mul((int64)OP_LEFT(op_set)->v_uint32, (int64)OP_RIGHT(op_set)->v_int,
        &OP_RESULT(op_set)->v_bigint);
}

static inline status_t mul_uint_bigint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_BIGINT;
    return opr_bigint_mul((int64)OP_LEFT(op_set)->v_uint32, OP_RIGHT(op_set)->v_bigint, &OP_RESULT(op_set)->v_bigint);
}

static inline status_t mul_uint_real(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_REAL;
    return opr_double_mul((double)OP_LEFT(op_set)->v_uint32, OP_RIGHT(op_set)->v_real, &OP_RESULT(op_set)->v_real);
}

static inline status_t mul_uint_number(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_NUMBER;
    return cm_int64_mul_dec((int64)OP_LEFT(op_set)->v_uint32, &OP_RIGHT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

static inline status_t mul_uint_number2(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_NUMBER2;
    return cm_int64_mul_dec((int64)OP_LEFT(op_set)->v_uint32, &OP_RIGHT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

#define mul_uint_decimal  mul_uint_number

static inline status_t mul_anytype_string(opr_operand_set_t *op_set)
{
    variant_t var = *OP_RIGHT(op_set);
    variant_t *old_right = OP_RIGHT(op_set);
    GS_RETURN_IFERR(var_as_num(&var));
    OP_RIGHT(op_set) = &var;
    status_t status = opr_exec_mul(op_set);
    OP_RIGHT(op_set) = old_right;
    return status;
}

#define mul_uint_string     mul_anytype_string
#define mul_uint_char       mul_anytype_string
#define mul_uint_varchar    mul_anytype_string
#define mul_uint_binary     mul_anytype_binary
#define mul_uint_varbinary  mul_anytype_string

static inline status_t mul_uint_interval_ds(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_INTERVAL_DS;
    return opr_real_mul_dsitvl((double)OP_LEFT(op_set)->v_uint32, OP_RIGHT(op_set)->v_itvl_ds,
        &OP_RESULT(op_set)->v_itvl_ds);
}

static inline status_t mul_uint_interval_ym(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_INTERVAL_YM;
    return opr_real_mul_ymitvl((double)OP_LEFT(op_set)->v_uint32, OP_RIGHT(op_set)->v_itvl_ym,
        &OP_RESULT(op_set)->v_itvl_ym);
}

OPR_DECL(mul_uint_uint, GS_TYPE_BIGINT, GS_TYPE_BIGINT, GS_TYPE_BIGINT);
OPR_DECL(mul_uint_int, GS_TYPE_BIGINT, GS_TYPE_BIGINT, GS_TYPE_BIGINT);
OPR_DECL(mul_uint_bigint, GS_TYPE_BIGINT, GS_TYPE_BIGINT, GS_TYPE_BIGINT);
OPR_DECL(mul_uint_real, GS_TYPE_REAL, GS_TYPE_REAL, GS_TYPE_REAL);
OPR_DECL(mul_uint_number, GS_TYPE_NUMBER, GS_TYPE_NUMBER, GS_TYPE_NUMBER);
OPR_DECL(mul_uint_number2, GS_TYPE_NUMBER2, GS_TYPE_NUMBER2, GS_TYPE_NUMBER2);
OPR_DECL(mul_uint_decimal, GS_TYPE_DECIMAL, GS_TYPE_DECIMAL, GS_TYPE_DECIMAL);
OPR_DECL(mul_uint_char, GS_TYPE_NUMBER, GS_TYPE_NUMBER, GS_TYPE_NUMBER);
OPR_DECL(mul_uint_varchar, GS_TYPE_NUMBER, GS_TYPE_NUMBER, GS_TYPE_NUMBER);
OPR_DECL(mul_uint_string, GS_TYPE_NUMBER, GS_TYPE_NUMBER, GS_TYPE_NUMBER);
OPR_DECL(mul_uint_interval_ym, GS_TYPE_REAL, GS_TYPE_INTERVAL_YM, GS_TYPE_INTERVAL_YM);
OPR_DECL(mul_uint_interval_ds, GS_TYPE_REAL, GS_TYPE_INTERVAL_DS, GS_TYPE_INTERVAL_DS);
OPR_DECL(mul_uint_binary, GS_TYPE_NUMBER, GS_TYPE_NUMBER, GS_TYPE_NUMBER);
OPR_DECL(mul_uint_varbinary, GS_TYPE_NUMBER, GS_TYPE_NUMBER, GS_TYPE_NUMBER);

static inline status_t mul_int_uint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_BIGINT;
    return opr_bigint_mul((int64)OP_LEFT(op_set)->v_int, (int64)OP_RIGHT(op_set)->v_uint32,
        &OP_RESULT(op_set)->v_bigint);
}

static inline status_t mul_int_int(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_BIGINT;
    return opr_bigint_mul((int64)OP_LEFT(op_set)->v_int, (int64)OP_RIGHT(op_set)->v_int,
        &OP_RESULT(op_set)->v_bigint);
}

static inline status_t mul_int_bigint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_BIGINT;
    return opr_bigint_mul((int64)OP_LEFT(op_set)->v_int, OP_RIGHT(op_set)->v_bigint, &OP_RESULT(op_set)->v_bigint);
}

static inline status_t mul_int_real(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_REAL;
    return opr_double_mul((double)OP_LEFT(op_set)->v_int, OP_RIGHT(op_set)->v_real, &OP_RESULT(op_set)->v_real);
}

static inline status_t mul_int_number(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_NUMBER;
    return cm_int64_mul_dec((int64)OP_LEFT(op_set)->v_int, &OP_RIGHT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

static inline status_t mul_int_number2(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_NUMBER2;
    return cm_int64_mul_dec((int64)OP_LEFT(op_set)->v_int, &OP_RIGHT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

#define mul_int_decimal    mul_int_number

#define mul_int_string     mul_anytype_string
#define mul_int_char       mul_anytype_string
#define mul_int_varchar    mul_anytype_string
#define mul_int_binary     mul_anytype_binary
#define mul_int_varbinary  mul_anytype_string

static inline status_t mul_int_interval_ds(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_INTERVAL_DS;
    return opr_real_mul_dsitvl((double)OP_LEFT(op_set)->v_int, OP_RIGHT(op_set)->v_itvl_ds,
        &OP_RESULT(op_set)->v_itvl_ds);
}

static inline status_t mul_int_interval_ym(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_INTERVAL_YM;
    return opr_real_mul_ymitvl((double)OP_LEFT(op_set)->v_int, OP_RIGHT(op_set)->v_itvl_ym,
        &OP_RESULT(op_set)->v_itvl_ym);
}

OPR_DECL(mul_int_uint, GS_TYPE_BIGINT, GS_TYPE_BIGINT, GS_TYPE_BIGINT);
OPR_DECL(mul_int_int, GS_TYPE_BIGINT, GS_TYPE_BIGINT, GS_TYPE_BIGINT);
OPR_DECL(mul_int_bigint, GS_TYPE_BIGINT, GS_TYPE_BIGINT, GS_TYPE_BIGINT);
OPR_DECL(mul_int_real, GS_TYPE_REAL, GS_TYPE_REAL, GS_TYPE_REAL);
OPR_DECL(mul_int_number, GS_TYPE_NUMBER, GS_TYPE_NUMBER, GS_TYPE_NUMBER);
OPR_DECL(mul_int_number2, GS_TYPE_NUMBER2, GS_TYPE_NUMBER2, GS_TYPE_NUMBER2);
OPR_DECL(mul_int_decimal, GS_TYPE_DECIMAL, GS_TYPE_DECIMAL, GS_TYPE_DECIMAL);
OPR_DECL(mul_int_char, GS_TYPE_NUMBER, GS_TYPE_NUMBER, GS_TYPE_NUMBER);
OPR_DECL(mul_int_varchar, GS_TYPE_NUMBER, GS_TYPE_NUMBER, GS_TYPE_NUMBER);
OPR_DECL(mul_int_string, GS_TYPE_NUMBER, GS_TYPE_NUMBER, GS_TYPE_NUMBER);
OPR_DECL(mul_int_interval_ym, GS_TYPE_REAL, GS_TYPE_INTERVAL_YM, GS_TYPE_INTERVAL_YM);
OPR_DECL(mul_int_interval_ds, GS_TYPE_REAL, GS_TYPE_INTERVAL_DS, GS_TYPE_INTERVAL_DS);
OPR_DECL(mul_int_binary, GS_TYPE_NUMBER, GS_TYPE_NUMBER, GS_TYPE_NUMBER);
OPR_DECL(mul_int_varbinary, GS_TYPE_NUMBER, GS_TYPE_NUMBER, GS_TYPE_NUMBER);

static inline status_t mul_bigint_uint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_BIGINT;
    return opr_bigint_mul(OP_LEFT(op_set)->v_bigint, (int64)OP_RIGHT(op_set)->v_uint32, &OP_RESULT(op_set)->v_bigint);
}

static inline status_t mul_bigint_int(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_BIGINT;
    return opr_bigint_mul(OP_LEFT(op_set)->v_bigint, (int64)OP_RIGHT(op_set)->v_int, &OP_RESULT(op_set)->v_bigint);
}

static inline status_t mul_bigint_bigint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_BIGINT;
    return opr_bigint_mul(OP_LEFT(op_set)->v_bigint, OP_RIGHT(op_set)->v_bigint, &OP_RESULT(op_set)->v_bigint);
}

static inline status_t mul_bigint_real(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_REAL;
    return opr_double_mul((double)OP_LEFT(op_set)->v_bigint, OP_RIGHT(op_set)->v_real, &OP_RESULT(op_set)->v_real);
}

static inline status_t mul_bigint_number(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_NUMBER;
    return cm_int64_mul_dec(OP_LEFT(op_set)->v_bigint, &OP_RIGHT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

static inline status_t mul_bigint_number2(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_NUMBER2;
    return cm_int64_mul_dec(OP_LEFT(op_set)->v_bigint, &OP_RIGHT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

#define mul_bigint_decimal    mul_int_number

#define mul_bigint_string     mul_anytype_string
#define mul_bigint_char       mul_anytype_string
#define mul_bigint_varchar    mul_anytype_string
#define mul_bigint_binary     mul_anytype_binary
#define mul_bigint_varbinary  mul_anytype_string

static inline status_t mul_bigint_interval_ds(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_INTERVAL_DS;
    return opr_real_mul_dsitvl((double)OP_LEFT(op_set)->v_bigint, OP_RIGHT(op_set)->v_itvl_ds,
        &OP_RESULT(op_set)->v_itvl_ds);
}

static inline status_t mul_bigint_interval_ym(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_INTERVAL_YM;
    return opr_real_mul_ymitvl((double)OP_LEFT(op_set)->v_bigint, OP_RIGHT(op_set)->v_itvl_ym,
        &OP_RESULT(op_set)->v_itvl_ym);
}

OPR_DECL(mul_bigint_uint, GS_TYPE_BIGINT, GS_TYPE_BIGINT, GS_TYPE_BIGINT);
OPR_DECL(mul_bigint_int, GS_TYPE_BIGINT, GS_TYPE_BIGINT, GS_TYPE_BIGINT);
OPR_DECL(mul_bigint_bigint, GS_TYPE_BIGINT, GS_TYPE_BIGINT, GS_TYPE_BIGINT);
OPR_DECL(mul_bigint_real, GS_TYPE_REAL, GS_TYPE_REAL, GS_TYPE_REAL);
OPR_DECL(mul_bigint_number, GS_TYPE_NUMBER, GS_TYPE_NUMBER, GS_TYPE_NUMBER);
OPR_DECL(mul_bigint_number2, GS_TYPE_NUMBER2, GS_TYPE_NUMBER2, GS_TYPE_NUMBER2);
OPR_DECL(mul_bigint_decimal, GS_TYPE_DECIMAL, GS_TYPE_DECIMAL, GS_TYPE_DECIMAL);
OPR_DECL(mul_bigint_char, GS_TYPE_NUMBER, GS_TYPE_NUMBER, GS_TYPE_NUMBER);
OPR_DECL(mul_bigint_varchar, GS_TYPE_NUMBER, GS_TYPE_NUMBER, GS_TYPE_NUMBER);
OPR_DECL(mul_bigint_string, GS_TYPE_NUMBER, GS_TYPE_NUMBER, GS_TYPE_NUMBER);
OPR_DECL(mul_bigint_interval_ym, GS_TYPE_REAL, GS_TYPE_INTERVAL_YM, GS_TYPE_INTERVAL_YM);
OPR_DECL(mul_bigint_interval_ds, GS_TYPE_REAL, GS_TYPE_INTERVAL_DS, GS_TYPE_INTERVAL_DS);
OPR_DECL(mul_bigint_binary, GS_TYPE_NUMBER, GS_TYPE_NUMBER, GS_TYPE_NUMBER);
OPR_DECL(mul_bigint_varbinary, GS_TYPE_NUMBER, GS_TYPE_NUMBER, GS_TYPE_NUMBER);

static inline status_t mul_real_uint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_REAL;
    return opr_double_mul(OP_LEFT(op_set)->v_real, OP_RIGHT(op_set)->v_uint32, &OP_RESULT(op_set)->v_real);
}

static inline status_t mul_real_int(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_REAL;
    return opr_double_mul(OP_LEFT(op_set)->v_real, OP_RIGHT(op_set)->v_int, &OP_RESULT(op_set)->v_real);
}

static inline status_t mul_real_bigint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_REAL;
    return opr_double_mul(OP_LEFT(op_set)->v_real, (double)OP_RIGHT(op_set)->v_bigint, &OP_RESULT(op_set)->v_real);
}

static inline status_t mul_real_real(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_REAL;
    return opr_double_mul(OP_LEFT(op_set)->v_real, OP_RIGHT(op_set)->v_real, &OP_RESULT(op_set)->v_real);
}

static inline status_t mul_real_number(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_NUMBER;
    return cm_real_mul_dec(OP_LEFT(op_set)->v_real, &OP_RIGHT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

static inline status_t mul_real_number2(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_NUMBER2;
    return cm_real_mul_dec(OP_LEFT(op_set)->v_real, &OP_RIGHT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

#define mul_real_decimal mul_real_number

#define mul_real_string     mul_anytype_string
#define mul_real_char       mul_anytype_string
#define mul_real_varchar    mul_anytype_string
#define mul_real_binary     mul_anytype_binary
#define mul_real_varbinary  mul_anytype_string

static inline status_t mul_real_interval_ds(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_INTERVAL_DS;
    return opr_real_mul_dsitvl(OP_LEFT(op_set)->v_real, OP_RIGHT(op_set)->v_itvl_ds, &OP_RESULT(op_set)->v_itvl_ds);
}

static inline status_t mul_real_interval_ym(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_INTERVAL_YM;
    return opr_real_mul_ymitvl(OP_LEFT(op_set)->v_real, OP_RIGHT(op_set)->v_itvl_ym, &OP_RESULT(op_set)->v_itvl_ym);
}

OPR_DECL(mul_real_uint, GS_TYPE_REAL, GS_TYPE_REAL, GS_TYPE_REAL);
OPR_DECL(mul_real_int, GS_TYPE_REAL, GS_TYPE_REAL, GS_TYPE_REAL);
OPR_DECL(mul_real_bigint, GS_TYPE_REAL, GS_TYPE_REAL, GS_TYPE_REAL);
OPR_DECL(mul_real_real, GS_TYPE_REAL, GS_TYPE_REAL, GS_TYPE_REAL);
OPR_DECL(mul_real_number, GS_TYPE_NUMBER, GS_TYPE_NUMBER, GS_TYPE_NUMBER);
OPR_DECL(mul_real_number2, GS_TYPE_NUMBER2, GS_TYPE_NUMBER2, GS_TYPE_NUMBER2);
OPR_DECL(mul_real_decimal, GS_TYPE_DECIMAL, GS_TYPE_DECIMAL, GS_TYPE_DECIMAL);
OPR_DECL(mul_real_char, GS_TYPE_NUMBER, GS_TYPE_NUMBER, GS_TYPE_NUMBER);
OPR_DECL(mul_real_varchar, GS_TYPE_NUMBER, GS_TYPE_NUMBER, GS_TYPE_NUMBER);
OPR_DECL(mul_real_string, GS_TYPE_NUMBER, GS_TYPE_NUMBER, GS_TYPE_NUMBER);
OPR_DECL(mul_real_interval_ym, GS_TYPE_REAL, GS_TYPE_INTERVAL_YM, GS_TYPE_INTERVAL_YM);
OPR_DECL(mul_real_interval_ds, GS_TYPE_REAL, GS_TYPE_INTERVAL_DS, GS_TYPE_INTERVAL_DS);
OPR_DECL(mul_real_binary, GS_TYPE_NUMBER, GS_TYPE_NUMBER, GS_TYPE_NUMBER);
OPR_DECL(mul_real_varbinary, GS_TYPE_NUMBER, GS_TYPE_NUMBER, GS_TYPE_NUMBER);

static inline status_t mul_number_uint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_NUMBER;
    return cm_int64_mul_dec((int64)OP_RIGHT(op_set)->v_uint32, &OP_LEFT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

static inline status_t mul_number_int(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_NUMBER;
    return cm_int64_mul_dec((int64)OP_RIGHT(op_set)->v_int, &OP_LEFT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

static inline status_t mul_number_bigint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_NUMBER;
    return cm_int64_mul_dec(OP_RIGHT(op_set)->v_bigint, &OP_LEFT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

static inline status_t mul_number_real(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_NUMBER;
    return cm_real_mul_dec(OP_RIGHT(op_set)->v_real, &OP_LEFT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

static inline status_t mul_number_number(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_NUMBER;
    return cm_dec_mul(&OP_LEFT(op_set)->v_dec, &OP_RIGHT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

#define mul_number_decimal mul_number_number

static inline status_t mul_number_number2(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_NUMBER2;
    return cm_dec_mul(&OP_LEFT(op_set)->v_dec, &OP_RIGHT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

#define mul_number_string     mul_anytype_string
#define mul_number_char       mul_anytype_string
#define mul_number_varchar    mul_anytype_string
#define mul_number_binary     mul_anytype_binary
#define mul_number_varbinary  mul_anytype_string

static inline status_t mul_number_interval_ds(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_INTERVAL_DS;
    return opr_dec_mul_dsitvl(&OP_LEFT(op_set)->v_dec, OP_RIGHT(op_set)->v_itvl_ds, &OP_RESULT(op_set)->v_itvl_ds);
}

static inline status_t mul_number_interval_ym(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_INTERVAL_YM;
    return opr_dec_mul_ymitvl(&OP_LEFT(op_set)->v_dec, OP_RIGHT(op_set)->v_itvl_ym, &OP_RESULT(op_set)->v_itvl_ym);
}

OPR_DECL(mul_number_uint, GS_TYPE_NUMBER, GS_TYPE_NUMBER, GS_TYPE_NUMBER);
OPR_DECL(mul_number_int, GS_TYPE_NUMBER, GS_TYPE_NUMBER, GS_TYPE_NUMBER);
OPR_DECL(mul_number_bigint, GS_TYPE_NUMBER, GS_TYPE_NUMBER, GS_TYPE_NUMBER);
OPR_DECL(mul_number_real, GS_TYPE_NUMBER, GS_TYPE_NUMBER, GS_TYPE_NUMBER);
OPR_DECL(mul_number_number, GS_TYPE_NUMBER, GS_TYPE_NUMBER, GS_TYPE_NUMBER);
OPR_DECL(mul_number_number2, GS_TYPE_NUMBER, GS_TYPE_NUMBER, GS_TYPE_NUMBER2);
OPR_DECL(mul_number_decimal, GS_TYPE_DECIMAL, GS_TYPE_DECIMAL, GS_TYPE_DECIMAL);
OPR_DECL(mul_number_char, GS_TYPE_NUMBER, GS_TYPE_NUMBER, GS_TYPE_NUMBER);
OPR_DECL(mul_number_varchar, GS_TYPE_NUMBER, GS_TYPE_NUMBER, GS_TYPE_NUMBER);
OPR_DECL(mul_number_string, GS_TYPE_NUMBER, GS_TYPE_NUMBER, GS_TYPE_NUMBER);
OPR_DECL(mul_number_interval_ym, GS_TYPE_REAL, GS_TYPE_INTERVAL_YM, GS_TYPE_INTERVAL_YM);
OPR_DECL(mul_number_interval_ds, GS_TYPE_REAL, GS_TYPE_INTERVAL_DS, GS_TYPE_INTERVAL_DS);
OPR_DECL(mul_number_binary, GS_TYPE_NUMBER, GS_TYPE_NUMBER, GS_TYPE_NUMBER);
OPR_DECL(mul_number_varbinary, GS_TYPE_NUMBER, GS_TYPE_NUMBER, GS_TYPE_NUMBER);

static inline status_t mul_number2_uint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_NUMBER2;
    return cm_int64_mul_dec((int64)OP_RIGHT(op_set)->v_uint32, &OP_LEFT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

static inline status_t mul_number2_int(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_NUMBER2;
    return cm_int64_mul_dec((int64)OP_RIGHT(op_set)->v_int, &OP_LEFT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

static inline status_t mul_number2_bigint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_NUMBER2;
    return cm_int64_mul_dec(OP_RIGHT(op_set)->v_bigint, &OP_LEFT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

static inline status_t mul_number2_real(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_NUMBER2;
    return cm_real_mul_dec(OP_RIGHT(op_set)->v_real, &OP_LEFT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

static inline status_t mul_number2_number(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_NUMBER2;
    return cm_dec_mul(&OP_LEFT(op_set)->v_dec, &OP_RIGHT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

#define mul_number2_decimal mul_number2_number
#define mul_number2_number2 mul_number2_number

#define mul_number2_string     mul_anytype_string
#define mul_number2_char       mul_anytype_string
#define mul_number2_varchar    mul_anytype_string
#define mul_number2_binary     mul_anytype_binary
#define mul_number2_varbinary  mul_anytype_string

static inline status_t mul_number2_interval_ds(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_INTERVAL_DS;
    return opr_dec_mul_dsitvl(&OP_LEFT(op_set)->v_dec, OP_RIGHT(op_set)->v_itvl_ds, &OP_RESULT(op_set)->v_itvl_ds);
}

static inline status_t mul_number2_interval_ym(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_INTERVAL_YM;
    return opr_dec_mul_ymitvl(&OP_LEFT(op_set)->v_dec, OP_RIGHT(op_set)->v_itvl_ym, &OP_RESULT(op_set)->v_itvl_ym);
}

OPR_DECL(mul_number2_uint, GS_TYPE_NUMBER2, GS_TYPE_NUMBER2, GS_TYPE_NUMBER2);
OPR_DECL(mul_number2_int, GS_TYPE_NUMBER2, GS_TYPE_NUMBER2, GS_TYPE_NUMBER2);
OPR_DECL(mul_number2_bigint, GS_TYPE_NUMBER2, GS_TYPE_NUMBER2, GS_TYPE_NUMBER2);
OPR_DECL(mul_number2_real, GS_TYPE_NUMBER2, GS_TYPE_NUMBER2, GS_TYPE_NUMBER2);
OPR_DECL(mul_number2_number, GS_TYPE_NUMBER2, GS_TYPE_NUMBER2, GS_TYPE_NUMBER2);
OPR_DECL(mul_number2_number2, GS_TYPE_NUMBER2, GS_TYPE_NUMBER2, GS_TYPE_NUMBER2);
OPR_DECL(mul_number2_decimal, GS_TYPE_NUMBER2, GS_TYPE_NUMBER2, GS_TYPE_NUMBER2);
OPR_DECL(mul_number2_char, GS_TYPE_NUMBER2, GS_TYPE_NUMBER2, GS_TYPE_NUMBER2);
OPR_DECL(mul_number2_varchar, GS_TYPE_NUMBER2, GS_TYPE_NUMBER2, GS_TYPE_NUMBER2);
OPR_DECL(mul_number2_string, GS_TYPE_NUMBER2, GS_TYPE_NUMBER2, GS_TYPE_NUMBER2);
OPR_DECL(mul_number2_interval_ym, GS_TYPE_REAL, GS_TYPE_INTERVAL_YM, GS_TYPE_INTERVAL_YM);
OPR_DECL(mul_number2_interval_ds, GS_TYPE_REAL, GS_TYPE_INTERVAL_DS, GS_TYPE_INTERVAL_DS);
OPR_DECL(mul_number2_binary, GS_TYPE_NUMBER2, GS_TYPE_NUMBER2, GS_TYPE_NUMBER2);
OPR_DECL(mul_number2_varbinary, GS_TYPE_NUMBER2, GS_TYPE_NUMBER2, GS_TYPE_NUMBER2);

static inline status_t mul_string_anytype(opr_operand_set_t *op_set)
{
    variant_t var;
    variant_t *old_left = OP_LEFT(op_set);
    GS_RETURN_IFERR(opr_text2dec(OP_LEFT(op_set), &var));
    OP_LEFT(op_set) = &var;
    status_t status = opr_exec_mul(op_set);
    OP_LEFT(op_set) = old_left;
    return status;
}

#define mul_string_uint             mul_string_anytype
#define mul_string_int              mul_string_anytype
#define mul_string_bigint           mul_string_anytype
#define mul_string_real             mul_string_anytype
#define mul_string_number           mul_string_anytype
#define mul_string_number2          mul_string_anytype
#define mul_string_decimal          mul_string_anytype
#define mul_string_char             mul_string_anytype
#define mul_string_varchar          mul_string_anytype
#define mul_string_string           mul_string_anytype
#define mul_string_interval_ym      mul_string_anytype
#define mul_string_interval_ds      mul_string_anytype
#define mul_string_binary           mul_anytype_binary
#define mul_string_varbinary        mul_string_anytype

OPR_DECL(mul_string_uint, GS_TYPE_NUMBER, GS_TYPE_NUMBER, GS_TYPE_NUMBER);
OPR_DECL(mul_string_int, GS_TYPE_NUMBER, GS_TYPE_NUMBER, GS_TYPE_NUMBER);
OPR_DECL(mul_string_bigint, GS_TYPE_NUMBER, GS_TYPE_NUMBER, GS_TYPE_NUMBER);
OPR_DECL(mul_string_real, GS_TYPE_NUMBER, GS_TYPE_NUMBER, GS_TYPE_NUMBER);
OPR_DECL(mul_string_number, GS_TYPE_NUMBER, GS_TYPE_NUMBER, GS_TYPE_NUMBER);
OPR_DECL(mul_string_number2, GS_TYPE_NUMBER2, GS_TYPE_NUMBER2, GS_TYPE_NUMBER2);
OPR_DECL(mul_string_decimal, GS_TYPE_DECIMAL, GS_TYPE_DECIMAL, GS_TYPE_DECIMAL);
OPR_DECL(mul_string_char, GS_TYPE_NUMBER, GS_TYPE_NUMBER, GS_TYPE_NUMBER);
OPR_DECL(mul_string_varchar, GS_TYPE_NUMBER, GS_TYPE_NUMBER, GS_TYPE_NUMBER);
OPR_DECL(mul_string_string, GS_TYPE_NUMBER, GS_TYPE_NUMBER, GS_TYPE_NUMBER);
OPR_DECL(mul_string_interval_ym, GS_TYPE_REAL, GS_TYPE_INTERVAL_YM, GS_TYPE_INTERVAL_YM);
OPR_DECL(mul_string_interval_ds, GS_TYPE_REAL, GS_TYPE_INTERVAL_DS, GS_TYPE_INTERVAL_DS);
OPR_DECL(mul_string_binary, GS_TYPE_NUMBER, GS_TYPE_NUMBER, GS_TYPE_NUMBER);
OPR_DECL(mul_string_varbinary, GS_TYPE_NUMBER, GS_TYPE_NUMBER, GS_TYPE_NUMBER);

#define mul_binary_uint             mul_binary_anytype
#define mul_binary_int              mul_binary_anytype
#define mul_binary_bigint           mul_binary_anytype
#define mul_binary_real             mul_binary_anytype
#define mul_binary_number           mul_binary_anytype
#define mul_binary_number2          mul_binary_anytype
#define mul_binary_decimal          mul_binary_anytype
#define mul_binary_char             mul_binary_anytype
#define mul_binary_varchar          mul_binary_anytype
#define mul_binary_string           mul_binary_anytype
#define mul_binary_interval_ym      mul_binary_anytype
#define mul_binary_interval_ds      mul_binary_anytype
#define mul_binary_binary           mul_binary_anytype
#define mul_binary_varbinary        mul_binary_anytype

OPR_DECL(mul_binary_uint, GS_TYPE_NUMBER, GS_TYPE_NUMBER, GS_TYPE_NUMBER);
OPR_DECL(mul_binary_int, GS_TYPE_NUMBER, GS_TYPE_NUMBER, GS_TYPE_NUMBER);
OPR_DECL(mul_binary_bigint, GS_TYPE_NUMBER, GS_TYPE_NUMBER, GS_TYPE_NUMBER);
OPR_DECL(mul_binary_real, GS_TYPE_NUMBER, GS_TYPE_NUMBER, GS_TYPE_NUMBER);
OPR_DECL(mul_binary_number, GS_TYPE_NUMBER, GS_TYPE_NUMBER, GS_TYPE_NUMBER);
OPR_DECL(mul_binary_number2, GS_TYPE_NUMBER2, GS_TYPE_NUMBER2, GS_TYPE_NUMBER2);
OPR_DECL(mul_binary_decimal, GS_TYPE_DECIMAL, GS_TYPE_DECIMAL, GS_TYPE_DECIMAL);
OPR_DECL(mul_binary_char, GS_TYPE_NUMBER, GS_TYPE_NUMBER, GS_TYPE_NUMBER);
OPR_DECL(mul_binary_varchar, GS_TYPE_NUMBER, GS_TYPE_NUMBER, GS_TYPE_NUMBER);
OPR_DECL(mul_binary_string, GS_TYPE_NUMBER, GS_TYPE_NUMBER, GS_TYPE_NUMBER);
OPR_DECL(mul_binary_interval_ym, GS_TYPE_REAL, GS_TYPE_INTERVAL_YM, GS_TYPE_INTERVAL_YM);
OPR_DECL(mul_binary_interval_ds, GS_TYPE_REAL, GS_TYPE_INTERVAL_DS, GS_TYPE_INTERVAL_DS);
OPR_DECL(mul_binary_binary, GS_TYPE_NUMBER, GS_TYPE_NUMBER, GS_TYPE_NUMBER);
OPR_DECL(mul_binary_varbinary, GS_TYPE_NUMBER, GS_TYPE_NUMBER, GS_TYPE_NUMBER);

static inline status_t mul_interval_ds_uint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_INTERVAL_DS;
    return opr_dsitvl_mul_real(OP_LEFT(op_set)->v_itvl_ds, (double)OP_RIGHT(op_set)->v_uint32,
        &OP_RESULT(op_set)->v_itvl_ds);
}

static inline status_t mul_interval_ds_int(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_INTERVAL_DS;
    return opr_dsitvl_mul_real(OP_LEFT(op_set)->v_itvl_ds, (double)OP_RIGHT(op_set)->v_int,
        &OP_RESULT(op_set)->v_itvl_ds);
}

static inline status_t mul_interval_ds_bigint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_INTERVAL_DS;
    return opr_dsitvl_mul_real(OP_LEFT(op_set)->v_itvl_ds, (double)OP_RIGHT(op_set)->v_bigint,
        &OP_RESULT(op_set)->v_itvl_ds);
}

static inline status_t mul_interval_ds_real(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_INTERVAL_DS;
    return opr_dsitvl_mul_real(OP_LEFT(op_set)->v_itvl_ds, OP_RIGHT(op_set)->v_real, &OP_RESULT(op_set)->v_itvl_ds);
}

static inline status_t mul_interval_ds_number(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_INTERVAL_DS;
    return opr_dsitvl_mul_dec(OP_LEFT(op_set)->v_itvl_ds, &OP_RIGHT(op_set)->v_dec, &OP_RESULT(op_set)->v_itvl_ds);
}

#define mul_interval_ds_decimal      mul_interval_ds_number
#define mul_interval_ds_number2      mul_interval_ds_number
#define mul_interval_ds_string       mul_anytype_string
#define mul_interval_ds_char         mul_anytype_string
#define mul_interval_ds_varchar      mul_anytype_string
#define mul_interval_ds_binary       mul_anytype_binary
#define mul_interval_ds_varbinary    mul_anytype_string

OPR_DECL(mul_interval_ds_uint, GS_TYPE_INTERVAL_DS, GS_TYPE_REAL, GS_TYPE_INTERVAL_DS);
OPR_DECL(mul_interval_ds_int, GS_TYPE_INTERVAL_DS, GS_TYPE_REAL, GS_TYPE_INTERVAL_DS);
OPR_DECL(mul_interval_ds_bigint, GS_TYPE_INTERVAL_DS, GS_TYPE_REAL, GS_TYPE_INTERVAL_DS);
OPR_DECL(mul_interval_ds_real, GS_TYPE_INTERVAL_DS, GS_TYPE_REAL, GS_TYPE_INTERVAL_DS);
OPR_DECL(mul_interval_ds_number, GS_TYPE_INTERVAL_DS, GS_TYPE_REAL, GS_TYPE_INTERVAL_DS);
OPR_DECL(mul_interval_ds_number2, GS_TYPE_INTERVAL_DS, GS_TYPE_REAL, GS_TYPE_INTERVAL_DS);
OPR_DECL(mul_interval_ds_decimal, GS_TYPE_INTERVAL_DS, GS_TYPE_REAL, GS_TYPE_INTERVAL_DS);
OPR_DECL(mul_interval_ds_char, GS_TYPE_INTERVAL_DS, GS_TYPE_REAL, GS_TYPE_INTERVAL_DS);
OPR_DECL(mul_interval_ds_varchar, GS_TYPE_INTERVAL_DS, GS_TYPE_REAL, GS_TYPE_INTERVAL_DS);
OPR_DECL(mul_interval_ds_string, GS_TYPE_INTERVAL_DS, GS_TYPE_REAL, GS_TYPE_INTERVAL_DS);
OPR_DECL(mul_interval_ds_binary, GS_TYPE_INTERVAL_DS, GS_TYPE_REAL, GS_TYPE_INTERVAL_DS);
OPR_DECL(mul_interval_ds_varbinary, GS_TYPE_INTERVAL_DS, GS_TYPE_REAL, GS_TYPE_INTERVAL_DS);


static inline status_t mul_interval_ym_uint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_INTERVAL_YM;
    return opr_ymitvl_mul_real(OP_LEFT(op_set)->v_itvl_ym, (double)OP_RIGHT(op_set)->v_uint32,
        &OP_RESULT(op_set)->v_itvl_ym);
}

static inline status_t mul_interval_ym_int(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_INTERVAL_YM;
    return opr_ymitvl_mul_real(OP_LEFT(op_set)->v_itvl_ym, (double)OP_RIGHT(op_set)->v_int,
        &OP_RESULT(op_set)->v_itvl_ym);
}

static inline status_t mul_interval_ym_bigint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_INTERVAL_YM;
    return opr_ymitvl_mul_real(OP_LEFT(op_set)->v_itvl_ym, (double)OP_RIGHT(op_set)->v_bigint,
        &OP_RESULT(op_set)->v_itvl_ym);
}

static inline status_t mul_interval_ym_real(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_INTERVAL_YM;
    return opr_ymitvl_mul_real(OP_LEFT(op_set)->v_itvl_ym, OP_RIGHT(op_set)->v_real, &OP_RESULT(op_set)->v_itvl_ym);
}

static inline status_t mul_interval_ym_number(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = GS_TYPE_INTERVAL_YM;
    return opr_ymitvl_mul_dec(OP_LEFT(op_set)->v_itvl_ym, &OP_RIGHT(op_set)->v_dec, &OP_RESULT(op_set)->v_itvl_ym);
}

#define mul_interval_ym_decimal      mul_interval_ds_number
#define mul_interval_ym_number2      mul_interval_ds_number
#define mul_interval_ym_string       mul_anytype_string
#define mul_interval_ym_char         mul_anytype_string
#define mul_interval_ym_varchar      mul_anytype_string
#define mul_interval_ym_binary       mul_anytype_binary
#define mul_interval_ym_varbinary    mul_anytype_string

OPR_DECL(mul_interval_ym_uint, GS_TYPE_INTERVAL_YM, GS_TYPE_REAL, GS_TYPE_INTERVAL_YM);
OPR_DECL(mul_interval_ym_int, GS_TYPE_INTERVAL_YM, GS_TYPE_REAL, GS_TYPE_INTERVAL_YM);
OPR_DECL(mul_interval_ym_bigint, GS_TYPE_INTERVAL_YM, GS_TYPE_REAL, GS_TYPE_INTERVAL_YM);
OPR_DECL(mul_interval_ym_real, GS_TYPE_INTERVAL_YM, GS_TYPE_REAL, GS_TYPE_INTERVAL_YM);
OPR_DECL(mul_interval_ym_number, GS_TYPE_INTERVAL_YM, GS_TYPE_REAL, GS_TYPE_INTERVAL_YM);
OPR_DECL(mul_interval_ym_number2, GS_TYPE_INTERVAL_YM, GS_TYPE_REAL, GS_TYPE_INTERVAL_YM);
OPR_DECL(mul_interval_ym_decimal, GS_TYPE_INTERVAL_YM, GS_TYPE_REAL, GS_TYPE_INTERVAL_YM);
OPR_DECL(mul_interval_ym_char, GS_TYPE_INTERVAL_YM, GS_TYPE_REAL, GS_TYPE_INTERVAL_YM);
OPR_DECL(mul_interval_ym_varchar, GS_TYPE_INTERVAL_YM, GS_TYPE_REAL, GS_TYPE_INTERVAL_YM);
OPR_DECL(mul_interval_ym_string, GS_TYPE_INTERVAL_YM, GS_TYPE_REAL, GS_TYPE_INTERVAL_YM);
OPR_DECL(mul_interval_ym_binary, GS_TYPE_INTERVAL_YM, GS_TYPE_REAL, GS_TYPE_INTERVAL_YM);
OPR_DECL(mul_interval_ym_varbinary, GS_TYPE_INTERVAL_YM, GS_TYPE_REAL, GS_TYPE_INTERVAL_YM);

static opr_rule_t *g_mul_oprs[VAR_TYPE_ARRAY_SIZE][VAR_TYPE_ARRAY_SIZE] = {
    __OPR_DEF(GS_TYPE_UINT32, GS_TYPE_UINT32,             mul_uint_uint),
    __OPR_DEF(GS_TYPE_UINT32, GS_TYPE_INTEGER,            mul_uint_int),
    __OPR_DEF(GS_TYPE_UINT32, GS_TYPE_BIGINT,             mul_uint_bigint),
    __OPR_DEF(GS_TYPE_UINT32, GS_TYPE_REAL,               mul_uint_real),
    __OPR_DEF(GS_TYPE_UINT32, GS_TYPE_NUMBER,             mul_uint_number),
    __OPR_DEF(GS_TYPE_UINT32, GS_TYPE_NUMBER2,            mul_uint_number2),
    __OPR_DEF(GS_TYPE_UINT32, GS_TYPE_DECIMAL,            mul_uint_decimal),
    __OPR_DEF(GS_TYPE_UINT32, GS_TYPE_CHAR,               mul_uint_char),
    __OPR_DEF(GS_TYPE_UINT32, GS_TYPE_VARCHAR,            mul_uint_varchar),
    __OPR_DEF(GS_TYPE_UINT32, GS_TYPE_STRING,             mul_uint_string),
    __OPR_DEF(GS_TYPE_UINT32, GS_TYPE_INTERVAL_YM,        mul_uint_interval_ym),
    __OPR_DEF(GS_TYPE_UINT32, GS_TYPE_INTERVAL_DS,        mul_uint_interval_ds),
    __OPR_DEF(GS_TYPE_UINT32, GS_TYPE_BINARY,             mul_uint_binary),
    __OPR_DEF(GS_TYPE_UINT32, GS_TYPE_VARBINARY,          mul_uint_varbinary),

    __OPR_DEF(GS_TYPE_INTEGER, GS_TYPE_UINT32,             mul_int_uint),
    __OPR_DEF(GS_TYPE_INTEGER, GS_TYPE_INTEGER,            mul_int_int),
    __OPR_DEF(GS_TYPE_INTEGER, GS_TYPE_BIGINT,             mul_int_bigint),
    __OPR_DEF(GS_TYPE_INTEGER, GS_TYPE_REAL,               mul_int_real),
    __OPR_DEF(GS_TYPE_INTEGER, GS_TYPE_NUMBER,             mul_int_number),
    __OPR_DEF(GS_TYPE_INTEGER, GS_TYPE_NUMBER2,            mul_int_number2),
    __OPR_DEF(GS_TYPE_INTEGER, GS_TYPE_DECIMAL,            mul_int_decimal),
    __OPR_DEF(GS_TYPE_INTEGER, GS_TYPE_CHAR,               mul_int_char),
    __OPR_DEF(GS_TYPE_INTEGER, GS_TYPE_VARCHAR,            mul_int_varchar),
    __OPR_DEF(GS_TYPE_INTEGER, GS_TYPE_STRING,             mul_int_string),
    __OPR_DEF(GS_TYPE_INTEGER, GS_TYPE_INTERVAL_YM,        mul_int_interval_ym),
    __OPR_DEF(GS_TYPE_INTEGER, GS_TYPE_INTERVAL_DS,        mul_int_interval_ds),
    __OPR_DEF(GS_TYPE_INTEGER, GS_TYPE_BINARY,             mul_int_binary),
    __OPR_DEF(GS_TYPE_INTEGER, GS_TYPE_VARBINARY,          mul_int_varbinary),

    __OPR_DEF(GS_TYPE_BIGINT, GS_TYPE_UINT32,            mul_bigint_uint),
    __OPR_DEF(GS_TYPE_BIGINT, GS_TYPE_INTEGER,           mul_bigint_int),
    __OPR_DEF(GS_TYPE_BIGINT, GS_TYPE_BIGINT,            mul_bigint_bigint),
    __OPR_DEF(GS_TYPE_BIGINT, GS_TYPE_REAL,              mul_bigint_real),
    __OPR_DEF(GS_TYPE_BIGINT, GS_TYPE_NUMBER,            mul_bigint_number),
    __OPR_DEF(GS_TYPE_BIGINT, GS_TYPE_NUMBER2,           mul_bigint_number2),
    __OPR_DEF(GS_TYPE_BIGINT, GS_TYPE_DECIMAL,           mul_bigint_decimal),
    __OPR_DEF(GS_TYPE_BIGINT, GS_TYPE_CHAR,              mul_bigint_char),
    __OPR_DEF(GS_TYPE_BIGINT, GS_TYPE_VARCHAR,           mul_bigint_varchar),
    __OPR_DEF(GS_TYPE_BIGINT, GS_TYPE_STRING,            mul_bigint_string),
    __OPR_DEF(GS_TYPE_BIGINT, GS_TYPE_INTERVAL_YM,       mul_bigint_interval_ym),
    __OPR_DEF(GS_TYPE_BIGINT, GS_TYPE_INTERVAL_DS,       mul_bigint_interval_ds),
    __OPR_DEF(GS_TYPE_BIGINT, GS_TYPE_BINARY,            mul_bigint_binary),
    __OPR_DEF(GS_TYPE_BIGINT, GS_TYPE_VARBINARY,         mul_bigint_varbinary),

    __OPR_DEF(GS_TYPE_REAL, GS_TYPE_UINT32,                  mul_real_uint),
    __OPR_DEF(GS_TYPE_REAL, GS_TYPE_INTEGER,                 mul_real_int),
    __OPR_DEF(GS_TYPE_REAL, GS_TYPE_BIGINT,                  mul_real_bigint),
    __OPR_DEF(GS_TYPE_REAL, GS_TYPE_REAL,                    mul_real_real),
    __OPR_DEF(GS_TYPE_REAL, GS_TYPE_NUMBER,                  mul_real_number),
    __OPR_DEF(GS_TYPE_REAL, GS_TYPE_NUMBER2,                 mul_real_number2),
    __OPR_DEF(GS_TYPE_REAL, GS_TYPE_DECIMAL,                 mul_real_decimal),
    __OPR_DEF(GS_TYPE_REAL, GS_TYPE_CHAR,                    mul_real_char),
    __OPR_DEF(GS_TYPE_REAL, GS_TYPE_VARCHAR,                 mul_real_varchar),
    __OPR_DEF(GS_TYPE_REAL, GS_TYPE_STRING,                  mul_real_string),
    __OPR_DEF(GS_TYPE_REAL, GS_TYPE_INTERVAL_YM,             mul_real_interval_ym),
    __OPR_DEF(GS_TYPE_REAL, GS_TYPE_INTERVAL_DS,             mul_real_interval_ds),
    __OPR_DEF(GS_TYPE_REAL, GS_TYPE_BINARY,                  mul_real_binary),
    __OPR_DEF(GS_TYPE_REAL, GS_TYPE_VARBINARY,               mul_real_varbinary),

    __OPR_DEF(GS_TYPE_NUMBER, GS_TYPE_UINT32,              mul_number_uint),
    __OPR_DEF(GS_TYPE_NUMBER, GS_TYPE_INTEGER,             mul_number_int),
    __OPR_DEF(GS_TYPE_NUMBER, GS_TYPE_BIGINT,              mul_number_bigint),
    __OPR_DEF(GS_TYPE_NUMBER, GS_TYPE_REAL,                mul_number_real),
    __OPR_DEF(GS_TYPE_NUMBER, GS_TYPE_NUMBER,              mul_number_number),
    __OPR_DEF(GS_TYPE_NUMBER, GS_TYPE_NUMBER2,             mul_number_number2),
    __OPR_DEF(GS_TYPE_NUMBER, GS_TYPE_DECIMAL,             mul_number_decimal),
    __OPR_DEF(GS_TYPE_NUMBER, GS_TYPE_CHAR,                mul_number_char),
    __OPR_DEF(GS_TYPE_NUMBER, GS_TYPE_VARCHAR,             mul_number_varchar),
    __OPR_DEF(GS_TYPE_NUMBER, GS_TYPE_STRING,              mul_number_string),
    __OPR_DEF(GS_TYPE_NUMBER, GS_TYPE_INTERVAL_YM,         mul_number_interval_ym),
    __OPR_DEF(GS_TYPE_NUMBER, GS_TYPE_INTERVAL_DS,         mul_number_interval_ds),
    __OPR_DEF(GS_TYPE_NUMBER, GS_TYPE_BINARY,              mul_number_binary),
    __OPR_DEF(GS_TYPE_NUMBER, GS_TYPE_VARBINARY,           mul_number_varbinary),

    __OPR_DEF(GS_TYPE_NUMBER2, GS_TYPE_UINT32,              mul_number2_uint),
    __OPR_DEF(GS_TYPE_NUMBER2, GS_TYPE_INTEGER,             mul_number2_int),
    __OPR_DEF(GS_TYPE_NUMBER2, GS_TYPE_BIGINT,              mul_number2_bigint),
    __OPR_DEF(GS_TYPE_NUMBER2, GS_TYPE_REAL,                mul_number2_real),
    __OPR_DEF(GS_TYPE_NUMBER2, GS_TYPE_NUMBER,              mul_number2_number),
    __OPR_DEF(GS_TYPE_NUMBER2, GS_TYPE_DECIMAL,             mul_number2_decimal),
    __OPR_DEF(GS_TYPE_NUMBER2, GS_TYPE_CHAR,                mul_number2_char),
    __OPR_DEF(GS_TYPE_NUMBER2, GS_TYPE_VARCHAR,             mul_number2_varchar),
    __OPR_DEF(GS_TYPE_NUMBER2, GS_TYPE_STRING,              mul_number2_string),
    __OPR_DEF(GS_TYPE_NUMBER2, GS_TYPE_INTERVAL_YM,         mul_number2_interval_ym),
    __OPR_DEF(GS_TYPE_NUMBER2, GS_TYPE_INTERVAL_DS,         mul_number2_interval_ds),
    __OPR_DEF(GS_TYPE_NUMBER2, GS_TYPE_BINARY,              mul_number2_binary),
    __OPR_DEF(GS_TYPE_NUMBER2, GS_TYPE_VARBINARY,           mul_number2_varbinary),
    __OPR_DEF(GS_TYPE_NUMBER2, GS_TYPE_NUMBER2,             mul_number2_number2),

    __OPR_DEF(GS_TYPE_DECIMAL, GS_TYPE_UINT32,              mul_number_uint),
    __OPR_DEF(GS_TYPE_DECIMAL, GS_TYPE_INTEGER,             mul_number_int),
    __OPR_DEF(GS_TYPE_DECIMAL, GS_TYPE_BIGINT,              mul_number_bigint),
    __OPR_DEF(GS_TYPE_DECIMAL, GS_TYPE_REAL,                mul_number_real),
    __OPR_DEF(GS_TYPE_DECIMAL, GS_TYPE_NUMBER,              mul_number_number),
    __OPR_DEF(GS_TYPE_DECIMAL, GS_TYPE_NUMBER2,             mul_number_number2),
    __OPR_DEF(GS_TYPE_DECIMAL, GS_TYPE_DECIMAL,             mul_number_decimal),
    __OPR_DEF(GS_TYPE_DECIMAL, GS_TYPE_CHAR,                mul_number_char),
    __OPR_DEF(GS_TYPE_DECIMAL, GS_TYPE_VARCHAR,             mul_number_varchar),
    __OPR_DEF(GS_TYPE_DECIMAL, GS_TYPE_STRING,              mul_number_string),
    __OPR_DEF(GS_TYPE_DECIMAL, GS_TYPE_INTERVAL_YM,         mul_number_interval_ym),
    __OPR_DEF(GS_TYPE_DECIMAL, GS_TYPE_INTERVAL_DS,         mul_number_interval_ds),
    __OPR_DEF(GS_TYPE_DECIMAL, GS_TYPE_BINARY,              mul_number_binary),
    __OPR_DEF(GS_TYPE_DECIMAL, GS_TYPE_VARBINARY,           mul_number_varbinary),

    __OPR_DEF(GS_TYPE_CHAR, GS_TYPE_UINT32,            mul_string_uint),
    __OPR_DEF(GS_TYPE_CHAR, GS_TYPE_INTEGER,           mul_string_int),
    __OPR_DEF(GS_TYPE_CHAR, GS_TYPE_BIGINT,            mul_string_bigint),
    __OPR_DEF(GS_TYPE_CHAR, GS_TYPE_REAL,              mul_string_real),
    __OPR_DEF(GS_TYPE_CHAR, GS_TYPE_NUMBER,            mul_string_number),
    __OPR_DEF(GS_TYPE_CHAR, GS_TYPE_NUMBER2,           mul_string_number2),
    __OPR_DEF(GS_TYPE_CHAR, GS_TYPE_DECIMAL,           mul_string_decimal),
    __OPR_DEF(GS_TYPE_CHAR, GS_TYPE_CHAR,              mul_string_char),
    __OPR_DEF(GS_TYPE_CHAR, GS_TYPE_VARCHAR,           mul_string_varchar),
    __OPR_DEF(GS_TYPE_CHAR, GS_TYPE_STRING,            mul_string_string),
    __OPR_DEF(GS_TYPE_CHAR, GS_TYPE_INTERVAL_YM,       mul_string_interval_ym),
    __OPR_DEF(GS_TYPE_CHAR, GS_TYPE_INTERVAL_DS,       mul_string_interval_ds),
    __OPR_DEF(GS_TYPE_CHAR, GS_TYPE_BINARY,            mul_string_binary),
    __OPR_DEF(GS_TYPE_CHAR, GS_TYPE_VARBINARY,         mul_string_varbinary),

    __OPR_DEF(GS_TYPE_VARCHAR, GS_TYPE_UINT32,            mul_string_uint),
    __OPR_DEF(GS_TYPE_VARCHAR, GS_TYPE_INTEGER,           mul_string_int),
    __OPR_DEF(GS_TYPE_VARCHAR, GS_TYPE_BIGINT,            mul_string_bigint),
    __OPR_DEF(GS_TYPE_VARCHAR, GS_TYPE_REAL,              mul_string_real),
    __OPR_DEF(GS_TYPE_VARCHAR, GS_TYPE_NUMBER,            mul_string_number),
    __OPR_DEF(GS_TYPE_VARCHAR, GS_TYPE_NUMBER2,           mul_string_number2),
    __OPR_DEF(GS_TYPE_VARCHAR, GS_TYPE_DECIMAL,           mul_string_decimal),
    __OPR_DEF(GS_TYPE_VARCHAR, GS_TYPE_CHAR,              mul_string_char),
    __OPR_DEF(GS_TYPE_VARCHAR, GS_TYPE_VARCHAR,           mul_string_varchar),
    __OPR_DEF(GS_TYPE_VARCHAR, GS_TYPE_STRING,            mul_string_string),
    __OPR_DEF(GS_TYPE_VARCHAR, GS_TYPE_INTERVAL_YM,       mul_string_interval_ym),
    __OPR_DEF(GS_TYPE_VARCHAR, GS_TYPE_INTERVAL_DS,       mul_string_interval_ds),
    __OPR_DEF(GS_TYPE_VARCHAR, GS_TYPE_BINARY,            mul_string_binary),
    __OPR_DEF(GS_TYPE_VARCHAR, GS_TYPE_VARBINARY,         mul_string_varbinary),

    __OPR_DEF(GS_TYPE_STRING, GS_TYPE_UINT32,            mul_string_uint),
    __OPR_DEF(GS_TYPE_STRING, GS_TYPE_INTEGER,           mul_string_int),
    __OPR_DEF(GS_TYPE_STRING, GS_TYPE_BIGINT,            mul_string_bigint),
    __OPR_DEF(GS_TYPE_STRING, GS_TYPE_REAL,              mul_string_real),
    __OPR_DEF(GS_TYPE_STRING, GS_TYPE_NUMBER,            mul_string_number),
    __OPR_DEF(GS_TYPE_STRING, GS_TYPE_NUMBER2,           mul_string_number2),
    __OPR_DEF(GS_TYPE_STRING, GS_TYPE_DECIMAL,           mul_string_decimal),
    __OPR_DEF(GS_TYPE_STRING, GS_TYPE_CHAR,              mul_string_char),
    __OPR_DEF(GS_TYPE_STRING, GS_TYPE_VARCHAR,           mul_string_varchar),
    __OPR_DEF(GS_TYPE_STRING, GS_TYPE_STRING,            mul_string_string),
    __OPR_DEF(GS_TYPE_STRING, GS_TYPE_INTERVAL_YM,       mul_string_interval_ym),
    __OPR_DEF(GS_TYPE_STRING, GS_TYPE_INTERVAL_DS,       mul_string_interval_ds),
    __OPR_DEF(GS_TYPE_STRING, GS_TYPE_BINARY,            mul_string_binary),
    __OPR_DEF(GS_TYPE_STRING, GS_TYPE_VARBINARY,         mul_string_varbinary),

    __OPR_DEF(GS_TYPE_BINARY, GS_TYPE_UINT32,            mul_binary_uint),
    __OPR_DEF(GS_TYPE_BINARY, GS_TYPE_INTEGER,           mul_binary_int),
    __OPR_DEF(GS_TYPE_BINARY, GS_TYPE_BIGINT,            mul_binary_bigint),
    __OPR_DEF(GS_TYPE_BINARY, GS_TYPE_REAL,              mul_binary_real),
    __OPR_DEF(GS_TYPE_BINARY, GS_TYPE_NUMBER,            mul_binary_number),
    __OPR_DEF(GS_TYPE_BINARY, GS_TYPE_NUMBER2,           mul_binary_number2),
    __OPR_DEF(GS_TYPE_BINARY, GS_TYPE_DECIMAL,           mul_binary_decimal),
    __OPR_DEF(GS_TYPE_BINARY, GS_TYPE_CHAR,              mul_binary_char),
    __OPR_DEF(GS_TYPE_BINARY, GS_TYPE_VARCHAR,           mul_binary_varchar),
    __OPR_DEF(GS_TYPE_BINARY, GS_TYPE_STRING,            mul_binary_string),
    __OPR_DEF(GS_TYPE_BINARY, GS_TYPE_INTERVAL_YM,       mul_binary_interval_ym),
    __OPR_DEF(GS_TYPE_BINARY, GS_TYPE_INTERVAL_DS,       mul_binary_interval_ds),
    __OPR_DEF(GS_TYPE_BINARY, GS_TYPE_BINARY,            mul_binary_binary),
    __OPR_DEF(GS_TYPE_BINARY, GS_TYPE_VARBINARY,         mul_binary_varbinary),

    __OPR_DEF(GS_TYPE_VARBINARY, GS_TYPE_UINT32,            mul_string_uint),
    __OPR_DEF(GS_TYPE_VARBINARY, GS_TYPE_INTEGER,           mul_string_int),
    __OPR_DEF(GS_TYPE_VARBINARY, GS_TYPE_BIGINT,            mul_string_bigint),
    __OPR_DEF(GS_TYPE_VARBINARY, GS_TYPE_REAL,              mul_string_real),
    __OPR_DEF(GS_TYPE_VARBINARY, GS_TYPE_NUMBER,            mul_string_number),
    __OPR_DEF(GS_TYPE_VARBINARY, GS_TYPE_NUMBER2,           mul_string_number2),
    __OPR_DEF(GS_TYPE_VARBINARY, GS_TYPE_DECIMAL,           mul_string_decimal),
    __OPR_DEF(GS_TYPE_VARBINARY, GS_TYPE_CHAR,              mul_string_char),
    __OPR_DEF(GS_TYPE_VARBINARY, GS_TYPE_VARCHAR,           mul_string_varchar),
    __OPR_DEF(GS_TYPE_VARBINARY, GS_TYPE_STRING,            mul_string_string),
    __OPR_DEF(GS_TYPE_VARBINARY, GS_TYPE_INTERVAL_YM,       mul_string_interval_ym),
    __OPR_DEF(GS_TYPE_VARBINARY, GS_TYPE_INTERVAL_DS,       mul_string_interval_ds),
    __OPR_DEF(GS_TYPE_VARBINARY, GS_TYPE_BINARY,            mul_string_binary),
    __OPR_DEF(GS_TYPE_VARBINARY, GS_TYPE_VARBINARY,         mul_string_varbinary),

    __OPR_DEF(GS_TYPE_INTERVAL_YM, GS_TYPE_UINT32,         mul_interval_ym_uint),
    __OPR_DEF(GS_TYPE_INTERVAL_YM, GS_TYPE_INTEGER,        mul_interval_ym_int),
    __OPR_DEF(GS_TYPE_INTERVAL_YM, GS_TYPE_BIGINT,         mul_interval_ym_bigint),
    __OPR_DEF(GS_TYPE_INTERVAL_YM, GS_TYPE_REAL,           mul_interval_ym_real),
    __OPR_DEF(GS_TYPE_INTERVAL_YM, GS_TYPE_NUMBER,         mul_interval_ym_number),
    __OPR_DEF(GS_TYPE_INTERVAL_YM, GS_TYPE_NUMBER2,        mul_interval_ym_number2),
    __OPR_DEF(GS_TYPE_INTERVAL_YM, GS_TYPE_DECIMAL,        mul_interval_ym_decimal),
    __OPR_DEF(GS_TYPE_INTERVAL_YM, GS_TYPE_CHAR,           mul_interval_ym_char),
    __OPR_DEF(GS_TYPE_INTERVAL_YM, GS_TYPE_VARCHAR,        mul_interval_ym_varchar),
    __OPR_DEF(GS_TYPE_INTERVAL_YM, GS_TYPE_STRING,         mul_interval_ym_string),
    __OPR_DEF(GS_TYPE_INTERVAL_YM, GS_TYPE_BINARY,         mul_interval_ym_binary),
    __OPR_DEF(GS_TYPE_INTERVAL_YM, GS_TYPE_VARBINARY,      mul_interval_ym_varbinary),

    __OPR_DEF(GS_TYPE_INTERVAL_DS, GS_TYPE_UINT32,        mul_interval_ds_uint),
    __OPR_DEF(GS_TYPE_INTERVAL_DS, GS_TYPE_INTEGER,       mul_interval_ds_int),
    __OPR_DEF(GS_TYPE_INTERVAL_DS, GS_TYPE_BIGINT,        mul_interval_ds_bigint),
    __OPR_DEF(GS_TYPE_INTERVAL_DS, GS_TYPE_REAL,          mul_interval_ds_real),
    __OPR_DEF(GS_TYPE_INTERVAL_DS, GS_TYPE_NUMBER,        mul_interval_ds_number),
    __OPR_DEF(GS_TYPE_INTERVAL_DS, GS_TYPE_NUMBER2,       mul_interval_ds_number2),
    __OPR_DEF(GS_TYPE_INTERVAL_DS, GS_TYPE_DECIMAL,       mul_interval_ds_decimal),
    __OPR_DEF(GS_TYPE_INTERVAL_DS, GS_TYPE_CHAR,          mul_interval_ds_char),
    __OPR_DEF(GS_TYPE_INTERVAL_DS, GS_TYPE_VARCHAR,       mul_interval_ds_varchar),
    __OPR_DEF(GS_TYPE_INTERVAL_DS, GS_TYPE_STRING,        mul_interval_ds_string),
    __OPR_DEF(GS_TYPE_INTERVAL_DS, GS_TYPE_BINARY,        mul_interval_ds_binary),
    __OPR_DEF(GS_TYPE_INTERVAL_DS, GS_TYPE_VARBINARY,     mul_interval_ds_varbinary),
};  // end g_multiplication_rules

status_t opr_exec_mul(opr_operand_set_t *op_set)
{
    opr_rule_t *rule = g_mul_oprs[GS_TYPE_I(OP_LEFT(op_set)->type)][GS_TYPE_I(OP_RIGHT(op_set)->type)];

    if (SECUREC_UNLIKELY(rule == NULL)) {
        OPR_THROW_ERROR("*", OP_LEFT(op_set)->type, OP_RIGHT(op_set)->type);
        return GS_ERROR;
    }

    return rule->exec(op_set);
}

status_t opr_type_infer_mul(gs_type_t left, gs_type_t right, gs_type_t *result)
{
    opr_rule_t *rule = g_mul_oprs[GS_TYPE_I(left)][GS_TYPE_I(right)];

    if (rule != NULL) {
        *result = rule->rs_type;
        return GS_SUCCESS;
    }

    OPR_THROW_ERROR("*", left, right);
    return GS_ERROR;
}