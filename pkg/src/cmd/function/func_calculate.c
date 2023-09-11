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
 * func_calculate.c
 *
 *
 * IDENTIFICATION
 * src/cmd/function/func_calculate.c
 *
 * -------------------------------------------------------------------------
 */
#include "func_calculate.h"
#include "func_hex.h"
#include "srv_instance.h"

status_t sql_func_abs(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    CM_POINTER3(stmt, func, result);

    expr_tree_t *arg = func->argument; // the first argument
    CM_POINTER(arg);

    SQL_EXEC_FUNC_ARG_EX(arg, result, result);

    if (GS_SUCCESS != var_as_decimal(result)) {
        return GS_ERROR;
    }

    result->is_null = GS_FALSE;
    cm_dec_abs(&result->v_dec);
    result->type = GS_TYPE_NUMBER;

    return GS_SUCCESS;
}

status_t sql_verify_abs(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 1, 1, GS_INVALID_ID32) != GS_SUCCESS) {
        return GS_ERROR;
    }

    func->datatype = GS_TYPE_NUMBER;
    func->size = (uint16)GS_MAX_DEC_OUTPUT_ALL_PREC;
    return GS_SUCCESS;
}

status_t sql_func_sin(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t var;

    CM_POINTER3(stmt, func, result);

    expr_tree_t *arg = func->argument;
    CM_POINTER(arg);

    SQL_EXEC_FUNC_ARG_EX(arg, &var, result);

    LOC_RETURN_IFERR(var_as_decimal(&var), arg->loc);
    LOC_RETURN_IFERR(cm_dec_sin(&var.v_dec, &result->v_dec), arg->loc);

    result->is_null = GS_FALSE;
    result->type = GS_TYPE_NUMBER;

    return GS_SUCCESS;
}

/* trigonometric functions' verification, such as sin(x), cos(x), tan(x), asin(x) */
status_t sql_verify_trigonometric(sql_verifier_t *verifier, expr_node_t *func)
{
    CM_POINTER2(verifier, func);

    GS_RETURN_IFERR(sql_verify_func_node(verifier, func, 1, 1, GS_INVALID_ID32));

    if (!sql_match_numeric_type(TREE_DATATYPE(func->argument))) {
        GS_SRC_ERROR_REQUIRE_NUMERIC(func->argument->loc, TREE_DATATYPE(func->argument));
        return GS_ERROR;
    }

    func->datatype = GS_TYPE_NUMBER;
    func->size = GS_MAX_DEC_OUTPUT_ALL_PREC;

    return GS_SUCCESS;
}

status_t sql_func_cos(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t var;

    CM_POINTER3(stmt, func, result);

    expr_tree_t *arg = func->argument;
    CM_POINTER(arg);

    SQL_EXEC_FUNC_ARG_EX(arg, &var, result);

    LOC_RETURN_IFERR(var_as_decimal(&var), arg->loc);
    LOC_RETURN_IFERR(cm_dec_cos(&var.v_dec, &result->v_dec), arg->loc);

    result->is_null = GS_FALSE;
    result->type = GS_TYPE_NUMBER;

    return GS_SUCCESS;
}

status_t sql_func_tan(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t var;

    CM_POINTER3(stmt, func, result);

    expr_tree_t *arg = func->argument;
    CM_POINTER(arg);

    SQL_EXEC_FUNC_ARG_EX(arg, &var, result);

    LOC_RETURN_IFERR(var_as_decimal(&var), arg->loc);
    LOC_RETURN_IFERR(cm_dec_tan(&var.v_dec, &result->v_dec), arg->loc);

    result->is_null = GS_FALSE;
    result->type = GS_TYPE_NUMBER;

    return GS_SUCCESS;
}

status_t sql_func_asin(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t var;

    CM_POINTER3(stmt, func, result);

    expr_tree_t *arg = func->argument;
    CM_POINTER(arg);

    SQL_EXEC_FUNC_ARG_EX(arg, &var, result);

    LOC_RETURN_IFERR(var_as_decimal(&var), arg->loc);
    LOC_RETURN_IFERR(cm_dec_asin(&var.v_dec, &result->v_dec), arg->loc);

    result->is_null = GS_FALSE;
    result->type = GS_TYPE_NUMBER;

    return GS_SUCCESS;
}

status_t sql_func_acos(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t var;

    CM_POINTER3(stmt, func, result);

    expr_tree_t *arg = func->argument;
    CM_POINTER(arg);

    SQL_EXEC_FUNC_ARG_EX(arg, &var, result);

    LOC_RETURN_IFERR(var_as_decimal(&var), arg->loc);
    LOC_RETURN_IFERR(cm_dec_acos(&var.v_dec, &result->v_dec), arg->loc);

    result->is_null = GS_FALSE;
    result->type = GS_TYPE_NUMBER;

    return GS_SUCCESS;
}

status_t sql_func_atan(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t var;

    CM_POINTER3(stmt, func, result);

    expr_tree_t *arg = func->argument;

    CM_POINTER(arg);

    SQL_EXEC_FUNC_ARG_EX(arg, &var, result);
    LOC_RETURN_IFERR(var_as_decimal(&var), arg->loc);
    LOC_RETURN_IFERR(var_as_decimal(&var), arg->loc);
    LOC_RETURN_IFERR(cm_dec_atan(&var.v_dec, &result->v_dec), arg->loc);

    result->is_null = GS_FALSE;
    result->type = GS_TYPE_NUMBER;

    return GS_SUCCESS;
}

status_t sql_func_atan2(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    expr_tree_t *arg1 = NULL;
    expr_tree_t *arg2 = NULL;
    variant_t var1, var2;

    CM_POINTER3(stmt, func, result);

    arg1 = func->argument;

    CM_POINTER(arg1);
    SQL_EXEC_FUNC_ARG_EX(arg1, &var1, result);
    LOC_RETURN_IFERR(sql_convert_variant(stmt, &var1, GS_TYPE_NUMBER), arg1->loc);

    arg2 = arg1->next;

    CM_POINTER(arg2);
    SQL_EXEC_FUNC_ARG_EX(arg2, &var2, result);
    LOC_RETURN_IFERR(sql_convert_variant(stmt, &var2, GS_TYPE_NUMBER), arg2->loc);

    GS_RETURN_IFERR(cm_dec_atan2(&var1.v_dec, &var2.v_dec, &result->v_dec));

    result->is_null = GS_FALSE;
    result->type = GS_TYPE_NUMBER;

    return GS_SUCCESS;
}

status_t sql_verify_atan2(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    GS_RETURN_IFERR(sql_verify_func_node(verf, func, 2, 2, GS_INVALID_ID32));

    expr_tree_t *arg = func->argument;

    if (!sql_match_numeric_type(TREE_DATATYPE(arg))) {
        GS_SRC_ERROR_REQUIRE_NUMERIC(arg->loc, TREE_DATATYPE(arg));
        return GS_ERROR;
    }

    arg = arg->next;

    if (!sql_match_numeric_type(TREE_DATATYPE(arg))) {
        GS_SRC_ERROR_REQUIRE_NUMERIC(arg->loc, TREE_DATATYPE(arg));
        return GS_ERROR;
    }

    func->datatype = GS_TYPE_NUMBER;
    func->size = GS_MAX_DEC_OUTPUT_ALL_PREC;
    return GS_SUCCESS;
}

status_t sql_func_tanh(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    expr_tree_t *arg = NULL;
    variant_t var;

    CM_POINTER3(stmt, func, result);

    arg = func->argument;
    CM_POINTER(arg);

    SQL_EXEC_FUNC_ARG_EX(arg, &var, result);

    LOC_RETURN_IFERR(sql_convert_variant(stmt, &var, GS_TYPE_NUMBER), arg->loc);

    LOC_RETURN_IFERR(cm_dec_tanh(&var.v_dec, &result->v_dec), arg->loc);

    result->is_null = GS_FALSE;
    result->type = GS_TYPE_NUMBER;

    return GS_SUCCESS;
}

status_t sql_verify_tanh(sql_verifier_t *verifier, expr_node_t *func)
{
    CM_POINTER2(verifier, func);

    if (GS_SUCCESS != sql_verify_func_node(verifier, func, 1, 1, GS_INVALID_ID32)) {
        return GS_ERROR;
    }

    if (!sql_match_numeric_type(TREE_DATATYPE(func->argument))) {
        GS_SRC_ERROR_REQUIRE_NUMERIC(func->argument->loc, TREE_DATATYPE(func->argument));
        return GS_ERROR;
    }

    func->datatype = GS_TYPE_NUMBER;
    func->size = GS_MAX_DEC_OUTPUT_ALL_PREC;

    return GS_SUCCESS;
}

static status_t sql_func_bit_oper(sql_stmt_t *stmt, expr_node_t *func, bit_operation_t op, variant_t *result)
{
    variant_t l_var, r_var; // left and right variants

    CM_POINTER3(stmt, func, result);

    expr_tree_t *arg1 = func->argument;
    CM_POINTER(arg1);
    SQL_EXEC_FUNC_ARG_EX(arg1, &l_var, result);
    if (var_as_floor_bigint(&l_var) != GS_SUCCESS) {
        cm_set_error_loc(arg1->loc);
        return GS_ERROR;
    }

    expr_tree_t *arg2 = arg1->next;
    CM_POINTER(arg2);
    SQL_EXEC_FUNC_ARG_EX(arg2, &r_var, result);
    if (var_as_floor_bigint(&r_var) != GS_SUCCESS) {
        cm_set_error_loc(arg2->loc);
        return GS_ERROR;
    }

    switch (op) {
        case BIT_OPER_AND:
            result->v_bigint = (uint64)l_var.v_bigint & (uint64)r_var.v_bigint;
            break;

        case BIT_OPER_OR:
            result->v_bigint = (uint64)l_var.v_bigint | (uint64)r_var.v_bigint;
            break;

        case BIT_OPER_XOR:
            result->v_bigint = (uint64)l_var.v_bigint ^ (uint64)r_var.v_bigint;
            break;

        default:
            GS_THROW_ERROR(ERR_UNSUPPORT_OPER_TYPE, "bit operation", op);
            return GS_ERROR;
    }
    result->type = GS_TYPE_BIGINT;
    result->is_null = GS_FALSE;
    return GS_SUCCESS;
}

status_t sql_func_bit_and(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    return sql_func_bit_oper(stmt, func, BIT_OPER_AND, result);
}

status_t sql_verify_bit_func(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 2, 2, GS_INVALID_ID32) != GS_SUCCESS) {
        return GS_ERROR;
    }

    func->datatype = GS_TYPE_BIGINT;
    func->size = GS_BIGINT_SIZE;

    return GS_SUCCESS;
}

status_t sql_func_bit_or(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    return sql_func_bit_oper(stmt, func, BIT_OPER_OR, result);
}

status_t sql_func_bit_xor(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    return sql_func_bit_oper(stmt, func, BIT_OPER_XOR, result);
}

status_t sql_func_ceil(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    CM_POINTER3(stmt, func, result);

    expr_tree_t *arg = func->argument;
    CM_POINTER(arg);

    SQL_EXEC_FUNC_ARG_EX(arg, result, result);

    GS_RETURN_IFERR(var_as_decimal(result));

    result->is_null = GS_FALSE;
    result->type = GS_TYPE_NUMBER;

    return cm_dec_ceil(&result->v_dec);
}

status_t sql_verify_ceil(sql_verifier_t *verifier, expr_node_t *func)
{
    CM_POINTER2(verifier, func);

    if (GS_SUCCESS != sql_verify_func_node(verifier, func, 1, 1, GS_INVALID_ID32)) {
        return GS_ERROR;
    }

    expr_tree_t *arg1 = func->argument;
    if (!sql_match_numeric_type(TREE_DATATYPE(arg1))) {
        GS_SRC_ERROR_REQUIRE_NUMERIC(arg1->loc, TREE_DATATYPE(arg1));
        return GS_ERROR;
    }

    func->datatype = GS_TYPE_NUMBER;
    func->size = GS_MAX_DEC_OUTPUT_ALL_PREC;

    return GS_SUCCESS;
}

status_t sql_func_exp(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t e;
    CM_POINTER3(stmt, func, result);

    expr_tree_t *arg = func->argument;
    CM_POINTER(arg);

    SQL_EXEC_FUNC_ARG_EX(arg, &e, result);

    if (GS_SUCCESS != var_as_decimal(&e)) {
        cm_set_error_loc(arg->loc);
        return GS_ERROR;
    }

    result->is_null = GS_FALSE;
    if (GS_SUCCESS != cm_dec_exp(&e.v_dec, &result->v_dec)) {
        cm_set_error_loc(arg->loc);
        return GS_ERROR;
    }
    result->type = GS_TYPE_NUMBER;

    return GS_SUCCESS;
}

status_t sql_verify_exp(sql_verifier_t *verifier, expr_node_t *func)
{
    CM_POINTER2(verifier, func);

    GS_RETURN_IFERR(sql_verify_func_node(verifier, func, 1, 1, GS_INVALID_ID32));

    expr_tree_t *arg1 = func->argument;
    if (!sql_match_numeric_type(TREE_DATATYPE(arg1))) {
        GS_SRC_ERROR_REQUIRE_NUMERIC(arg1->loc, TREE_DATATYPE(arg1));
        return GS_ERROR;
    }

    func->datatype = GS_TYPE_NUMBER;
    func->size = GS_MAX_DEC_OUTPUT_ALL_PREC;

    return GS_SUCCESS;
}

status_t sql_func_floor(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    CM_POINTER3(stmt, func, result);

    expr_tree_t *arg = func->argument;
    CM_POINTER(arg);

    SQL_EXEC_FUNC_ARG_EX(arg, result, result);

    if (var_as_decimal(result) != GS_SUCCESS) {
        return GS_ERROR;
    }

    result->is_null = GS_FALSE;
    result->type = GS_TYPE_NUMBER;
    return cm_dec_floor(&result->v_dec);
}

status_t sql_verify_floor(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 1, 1, GS_INVALID_ID32) != GS_SUCCESS) {
        return GS_ERROR;
    }

    expr_tree_t *arg1 = func->argument;
    if (!sql_match_numeric_type(TREE_DATATYPE(arg1))) {
        GS_SRC_ERROR_REQUIRE_NUMERIC(arg1->loc, TREE_DATATYPE(arg1));
        return GS_ERROR;
    }

    func->datatype = GS_TYPE_NUMBER;
    func->size = GS_MAX_DEC_OUTPUT_ALL_PREC;

    return GS_SUCCESS;
}

static void sql_func_inet_ntoa_core(sql_stmt_t *stmt, variant_t *var, variant_t *result)
{
    uint32 byte1, byte2, byte3, byte4;

    byte1 = ((uint64)var->v_bigint & 0xFF000000) >> 24;
    byte2 = ((uint64)var->v_bigint & 0x00FF0000) >> 16;
    byte3 = ((uint64)var->v_bigint & 0x0000FF00) >> 8;
    byte4 = ((uint64)var->v_bigint & 0x000000FF);

    PRTS_RETVOID_IFERR(snprintf_s(result->v_text.str, GS_STRING_BUFFER_SIZE, GS_STRING_BUFFER_SIZE - 1, "%u.%u.%u.%u",
        byte1, byte2, byte3, byte4));

    result->v_text.len = (uint32)strlen(result->v_text.str);
    result->type = GS_TYPE_STRING;
    result->is_null = GS_FALSE;
}

status_t sql_func_inet_ntoa(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t arg;
    char *buf = NULL;

    CM_POINTER3(stmt, func, result);
    CM_POINTER(func->argument);

    SQL_EXEC_FUNC_ARG_EX(func->argument, &arg, result);
    if (var_as_bigint(&arg) != GS_SUCCESS) {
        cm_set_error_loc(func->loc);
        return GS_ERROR;
    }
    if (arg.is_null || arg.v_bigint < 0 || arg.v_bigint > (int64)0xFFFFFFFF) {
        SQL_SET_NULL_VAR(result);
        return GS_SUCCESS;
    }

    GS_RETURN_IFERR(sql_push(stmt, GS_STRING_BUFFER_SIZE, (void **)&buf));
    result->v_text.str = buf;
    result->v_text.len = 0;

    sql_func_inet_ntoa_core(stmt, &arg, result);
    return GS_SUCCESS;
}

status_t sql_verify_inet_ntoa(sql_verifier_t *verifier, expr_node_t *func)
{
    CM_POINTER2(verifier, func);

    GS_RETURN_IFERR(sql_verify_func_node(verifier, func, 1, 1, GS_INVALID_ID32));

    func->datatype = GS_TYPE_STRING;
    func->size = cm_get_datatype_strlen(func->argument->root->datatype, func->argument->root->size);
    return GS_SUCCESS;
}

status_t sql_func_ln(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t var;
    CM_POINTER3(stmt, func, result);

    expr_tree_t *arg = func->argument;
    CM_POINTER(arg);

    SQL_EXEC_FUNC_ARG_EX(arg, &var, result);

    if (GS_SUCCESS != var_as_decimal(&var)) {
        cm_set_error_loc(arg->loc);
        return GS_ERROR;
    }

    result->is_null = GS_FALSE;
    if (GS_SUCCESS != cm_dec_ln(&var.v_dec, &result->v_dec)) {
        cm_set_error_loc(arg->loc);
        return GS_ERROR;
    }
    result->type = GS_TYPE_NUMBER;

    return GS_SUCCESS;
}

status_t sql_verify_ln(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    GS_RETURN_IFERR(sql_verify_func_node(verf, func, 1, 1, GS_INVALID_ID32));

    expr_tree_t *arg1 = func->argument;
    if (!sql_match_numeric_type(TREE_DATATYPE(arg1))) {
        GS_SRC_ERROR_REQUIRE_NUMERIC(arg1->loc, TREE_DATATYPE(arg1));
        return GS_ERROR;
    }

    func->datatype = GS_TYPE_NUMBER;
    func->size = GS_MAX_DEC_OUTPUT_ALL_PREC;
    return GS_SUCCESS;
}

status_t sql_func_log(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    expr_tree_t *arg1 = NULL;
    expr_tree_t *arg2 = NULL;
    variant_t l_var, r_var;

    arg1 = func->argument;

    SQL_EXEC_FUNC_ARG_EX(arg1, &l_var, result);
    LOC_RETURN_IFERR(var_as_decimal(&l_var), arg1->loc);

    result->is_null = GS_FALSE;
    result->type = GS_TYPE_NUMBER;

    // 1. log(a) = ln(a), where a > 0
    arg2 = arg1->next;
    if (arg2 == NULL) {
        LOC_RETURN_IFERR(cm_dec_ln(&l_var.v_dec, &result->v_dec), arg1->loc);
        return GS_SUCCESS;
    }

    // 2. log(a, b) = ln(b) / ln(a), where a > 0 && a != 1 && b > 0
    SQL_EXEC_FUNC_ARG_EX(arg2, &r_var, result);
    LOC_RETURN_IFERR(var_as_decimal(&r_var), arg2->loc);

    LOC_RETURN_IFERR(cm_dec_log(&l_var.v_dec, &r_var.v_dec, &result->v_dec), func->loc);
    return GS_SUCCESS;
}

status_t sql_verify_log(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    GS_RETURN_IFERR(sql_verify_func_node(verf, func, 1, 2, GS_INVALID_ID32));

    func->datatype = GS_TYPE_NUMBER;
    func->size = MAX_DEC_BYTE_SZ;
    return GS_SUCCESS;
}

status_t sql_func_mod(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    expr_tree_t *arg1 = NULL;
    expr_tree_t *arg2 = NULL;
    variant_t l_var, r_var;

    CM_POINTER3(stmt, func, result);

    result->is_null = GS_FALSE;

    arg1 = func->argument;
    CM_POINTER(arg1);
    SQL_EXEC_FUNC_ARG_EX(arg1, &l_var, result);
    sql_keep_stack_variant(stmt, &l_var);

    arg2 = arg1->next;
    CM_POINTER(arg2);
    SQL_EXEC_FUNC_ARG_EX(arg2, &r_var, result);
    sql_keep_stack_variant(stmt, &r_var);

    if (l_var.type == GS_TYPE_INTEGER && r_var.type == GS_TYPE_INTEGER) {
        result->type = GS_TYPE_INTEGER;
        result->v_int = r_var.v_int == 0 ? l_var.v_int : l_var.v_int % r_var.v_int;
        GS_RETURN_IFERR(var_as_decimal(result));
        return GS_SUCCESS;
    }

    if (l_var.type == GS_TYPE_BIGINT && r_var.type == GS_TYPE_BIGINT) {
        result->type = GS_TYPE_BIGINT;
        result->v_bigint = r_var.v_bigint == 0 ? l_var.v_bigint : l_var.v_bigint % r_var.v_bigint;
        GS_RETURN_IFERR(var_as_decimal(result));
        return GS_SUCCESS;
    }

    if (l_var.type == GS_TYPE_BIGINT && r_var.type == GS_TYPE_INTEGER) {
        result->type = GS_TYPE_BIGINT;
        result->v_bigint = r_var.v_int == 0 ? l_var.v_bigint : l_var.v_bigint % r_var.v_int;
        GS_RETURN_IFERR(var_as_decimal(result));
        return GS_SUCCESS;
    }

    if (l_var.type == GS_TYPE_INTEGER && r_var.type == GS_TYPE_BIGINT) {
        result->type = GS_TYPE_BIGINT;
        result->v_bigint = r_var.v_bigint == 0 ? l_var.v_int : l_var.v_int % r_var.v_bigint;
        GS_RETURN_IFERR(var_as_decimal(result));
        return GS_SUCCESS;
    }

    GS_RETURN_IFERR(var_as_decimal(&l_var));
    GS_RETURN_IFERR(var_as_decimal(&r_var));

    result->type = GS_TYPE_NUMBER;
    return cm_dec_mod(&l_var.v_dec, &r_var.v_dec, &result->v_dec);
}

status_t sql_verify_mod(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    GS_RETURN_IFERR(sql_verify_func_node(verf, func, 2, 2, GS_INVALID_ID32));

    func->datatype = GS_TYPE_NUMBER;
    func->size = GS_MAX_DEC_OUTPUT_ALL_PREC;
    return GS_SUCCESS;
}

#define POWER_AS_SHIFT_BASE 2
#define POWER_AS_SHIFT_MIN_EXPN 0
#define POWER_AS_SHIFT_MAX_EXPN 30
static inline bool32 if_power_as_shift(variant_t *base, variant_t *expn)
{
    if (base->type == GS_TYPE_INTEGER && base->v_int == POWER_AS_SHIFT_BASE && expn->type == GS_TYPE_INTEGER &&
        expn->v_int >= POWER_AS_SHIFT_MIN_EXPN && expn->v_int <= POWER_AS_SHIFT_MAX_EXPN) {
        return GS_TRUE;
    }

    return GS_FALSE;
}

status_t sql_func_pi(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    CM_POINTER3(stmt, func, result);

    cm_dec8_pi(&result->v_dec);
    result->is_null = GS_FALSE;
    result->type = GS_TYPE_NUMBER;
    
    return GS_SUCCESS;
}

status_t sql_verify_pi(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    GS_RETURN_IFERR(sql_verify_func_node(verf, func, 0, 0, GS_INVALID_ID32));

    func->datatype = GS_TYPE_NUMBER;
    func->size = MAX_DEC_BYTE_SZ;
    return GS_SUCCESS;
}

status_t sql_func_power(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    expr_tree_t *arg1 = NULL;
    expr_tree_t *arg2 = NULL;
    variant_t base, expn;

    CM_POINTER3(stmt, func, result);

    result->is_null = GS_FALSE;
    result->type = GS_TYPE_NUMBER;

    arg1 = func->argument;
    CM_POINTER(arg1);
    SQL_EXEC_FUNC_ARG_EX(arg1, &base, result);

    arg2 = arg1->next;
    CM_POINTER(arg2);
    SQL_EXEC_FUNC_ARG_EX(arg2, &expn, result);

    if (if_power_as_shift(&base, &expn)) {
        result->v_int = 1 << expn.v_int;
        cm_int32_to_dec8(result->v_int, VALUE_PTR(dec8_t, result));
        return GS_SUCCESS;
    }

    GS_RETURN_IFERR(var_as_decimal(&base));
    GS_RETURN_IFERR(var_as_decimal(&expn));
    return cm_dec_power(&base.v_dec, &expn.v_dec, &result->v_dec);
}

status_t sql_verify_power(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    GS_RETURN_IFERR(sql_verify_func_node(verf, func, 2, 2, GS_INVALID_ID32));

    expr_tree_t *arg = func->argument;
    if (!sql_match_numeric_type(TREE_DATATYPE(arg))) {
        GS_SRC_ERROR_REQUIRE_NUMERIC(arg->loc, TREE_DATATYPE(arg));
        return GS_ERROR;
    }

    arg = arg->next;
    if (!sql_match_numeric_type(TREE_DATATYPE(arg))) {
        GS_SRC_ERROR_REQUIRE_NUMERIC(arg->loc, TREE_DATATYPE(arg));
        return GS_ERROR;
    }

    func->datatype = GS_TYPE_NUMBER;
    func->size = MAX_DEC_BYTE_SZ;
    return GS_SUCCESS;
}

status_t sql_func_radians(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t var;

    CM_POINTER3(stmt, func, result);

    expr_tree_t *arg = func->argument;
    CM_POINTER(arg);

    SQL_EXEC_FUNC_ARG_EX(arg, &var, result);

    LOC_RETURN_IFERR(var_as_decimal(&var), arg->loc);
    LOC_RETURN_IFERR(cm_dec8_radians(&var.v_dec, &result->v_dec), arg->loc);

    result->is_null = GS_FALSE;
    result->type = GS_TYPE_NUMBER;

    return GS_SUCCESS;
}

status_t sql_func_rand(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    expr_tree_t *arg = NULL;
    uint32 randvalue;
    variant_t var_seed;
    int64 seed;

    result->is_null = GS_FALSE;
    result->type = GS_TYPE_NUMBER;

    if (func->argument != NULL) {
        arg = func->argument;

        /* get the seed value */
        if (sql_exec_expr(stmt, arg, &var_seed) != GS_SUCCESS) {
            return GS_ERROR;
        }
        SQL_CHECK_COLUMN_VAR(&var_seed, result);
        if (!(var_seed.is_null == GS_FALSE && GS_IS_NUMERIC_TYPE(var_seed.type))) {
            GS_SRC_THROW_ERROR(func->argument->root->loc, ERR_INVALID_FUNC_PARAMS,
                               "the seed of rand is incorrect");
            return GS_ERROR;
        }

        /* convert to uint64 */
        GS_RETURN_IFERR(var_to_round_bigint(&var_seed, ROUND_TRUNC, &seed, NULL));
        randvalue = cm_rand_int32(&seed, GS_MAX_RAND_RANGE);
    } else {
        randvalue = cm_random(GS_MAX_RAND_RANGE);
    }
    cm_uint32_to_dec(randvalue, &result->v_dec);
    GS_RETURN_IFERR(cm_dec_div_int64(&result->v_dec, GS_MAX_RAND_RANGE, &result->v_dec));

    return GS_SUCCESS;
}

status_t sql_verify_rand(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    GS_RETURN_IFERR(sql_verify_func_node(verf, func, 0, 1, GS_INVALID_ID32));

    expr_tree_t *arg = func->argument;
    if (arg != NULL) {
        /* param must be one char or null */
        if (!sql_match_numeric_type(TREE_DATATYPE(arg))) {
            GS_SRC_THROW_ERROR(func->argument->root->loc, ERR_INVALID_FUNC_PARAMS,
                               "the argument of rand is incorrect");
            return GS_ERROR;
        }
    }

    func->datatype = GS_TYPE_NUMBER;
    func->size = MAX_DEC_BYTE_SZ;
    func->scale = GS_UNSPECIFIED_NUM_SCALE;
    func->precision = GS_UNSPECIFIED_NUM_PREC;
    return GS_SUCCESS;
}

status_t sql_func_rawtohex(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    return sql_bin2hex(stmt, func, GS_FALSE, result);
}

status_t sql_verify_rawtohex(sql_verifier_t *verf, expr_node_t *func)
{
    return sql_verify_bin2hex(verf, func);
}

static status_t sql_func_round_trunc_date(sql_stmt_t *stmt, variant_t *var1, expr_tree_t *arg1, variant_t *result,
    bool32 is_round)
{
    variant_t var2;
    char *fmt = (char *)"DD";
    text_t fmt_text;

    // param format
    expr_tree_t *arg2 = arg1->next;
    if (arg2 == NULL) {
        fmt_text.str = fmt;
        fmt_text.len = (uint32)strlen(fmt);
    } else {
        SQL_EXEC_FUNC_ARG_EX(arg2, &var2, result);
        if (var2.type != GS_TYPE_CHAR && var2.type != GS_TYPE_STRING && var2.type != GS_TYPE_VARCHAR) {
            GS_THROW_ERROR(ERR_UNEXPECTED_KEY, "a string value.");
            return GS_ERROR;
        }

        fmt_text = var2.v_text;
    }

    if (is_round) {
        return cm_round_date(var1->v_date, &fmt_text, &result->v_date);
    } else {
        return cm_trunc_date(var1->v_date, &fmt_text, &result->v_date);
    }
}

static status_t sql_func_round_trunc_decimal(sql_stmt_t *stmt, variant_t *var1, expr_tree_t *arg1, variant_t *result,
    bool32 is_round)
{
    variant_t var2;
    int32 scale;

    // param number
    GS_RETURN_IFERR(var_as_decimal(var1));

    // param scale
    expr_tree_t *arg2 = arg1->next;
    if (arg2 == NULL) {
        scale = 0;
    } else {
        SQL_EXEC_FUNC_ARG_EX(arg2, &var2, result);
        GS_RETURN_IFERR(var_as_floor_integer(&var2));
        scale = var2.v_int;
    }

    GS_RETURN_IFERR(cm_dec_scale(&var1->v_dec, scale, is_round ? ROUND_HALF_UP : ROUND_TRUNC));
    cm_dec_copy(&result->v_dec, &var1->v_dec);
    return GS_SUCCESS;
}

static status_t sql_func_round_trunc(sql_stmt_t *stmt, expr_node_t *func, variant_t *result, bool32 is_round)
{
    variant_t var1;

    CM_POINTER3(stmt, func, result);

    result->is_null = GS_FALSE;

    // param date or number
    expr_tree_t *arg1 = func->argument;
    CM_POINTER(arg1);
    SQL_EXEC_FUNC_ARG_EX(arg1, &var1, result);

    if (GS_IS_DATETIME_TYPE(var1.type)) {
        result->type = GS_TYPE_DATE;
        GS_RETURN_IFERR(sql_convert_variant(stmt, &var1, GS_TYPE_DATE));
        return sql_func_round_trunc_date(stmt, &var1, arg1, result, is_round);
    } else {
        result->type = GS_TYPE_NUMBER;
        return sql_func_round_trunc_decimal(stmt, &var1, arg1, result, is_round);
    }
}

status_t sql_func_round(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    return sql_func_round_trunc(stmt, func, result, GS_TRUE);
}

status_t sql_func_trunc(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    return sql_func_round_trunc(stmt, func, result, GS_FALSE);
}

status_t sql_verify_round_trunc(sql_verifier_t *verf, expr_node_t *func)
{
    /* syntax:
    round(number[,scale) round(date[,fmt)
    trunc(number[,scale) trunc(date[,fmt)
    */
    CM_POINTER2(verf, func);

    GS_RETURN_IFERR(sql_verify_func_node(verf, func, 1, 2, GS_INVALID_ID32));

    expr_tree_t *arg = func->argument;
    if (!sql_match_num_and_datetime_type(TREE_DATATYPE(arg))) {
        GS_SRC_ERROR_REQUIRE_NUM_OR_DATETIME(TREE_LOC(arg), TREE_DATATYPE(arg));
        return GS_ERROR;
    }

    if (GS_IS_DATETIME_TYPE(TREE_DATATYPE(arg))) {
        func->datatype = GS_TYPE_DATE;
        func->precision = 0;
    } else if (GS_IS_NUMERIC_TYPE(TREE_DATATYPE(arg)) || GS_IS_STRING_TYPE(TREE_DATATYPE(arg))) {
        func->datatype = GS_TYPE_NUMBER;
        func->precision = GS_UNSPECIFIED_NUM_PREC;
        func->scale = GS_UNSPECIFIED_NUM_SCALE;
    } else {
        func->datatype = GS_TYPE_UNKNOWN;
        func->precision = 0;
    }

    if (arg->next != NULL) {
        arg = arg->next;
        if (GS_IS_DATETIME_TYPE(func->datatype)) {
            if (!sql_match_string_type(TREE_DATATYPE(arg))) {
                GS_SRC_ERROR_REQUIRE_STRING(TREE_LOC(arg), TREE_DATATYPE(arg));
                return GS_ERROR;
            }
        } else {
            if (!sql_match_numeric_type(TREE_DATATYPE(arg))) {
                GS_SRC_ERROR_REQUIRE_NUMERIC(TREE_LOC(arg), TREE_DATATYPE(arg));
                return GS_ERROR;
            }
        }
    }

    func->size = cm_get_datatype_strlen(func->datatype, func->argument->root->size);
    return GS_SUCCESS;
}

status_t sql_func_sign(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t var;

    CM_POINTER3(stmt, func, result);

    expr_tree_t *arg = func->argument;
    CM_POINTER(arg);

    SQL_EXEC_FUNC_ARG_EX(arg, &var, result);

    if (GS_SUCCESS != var_as_decimal(&var)) {
        cm_set_error_loc(arg->loc);
        return GS_ERROR;
    }

    result->is_null = GS_FALSE;
    result->type = GS_TYPE_NUMBER;

    cm_dec_sign(&var.v_dec, &result->v_dec);
    return GS_SUCCESS;
}

status_t sql_verify_sign(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    GS_RETURN_IFERR(sql_verify_func_node(verf, func, 1, 1, GS_INVALID_ID32));

    func->datatype = GS_TYPE_NUMBER;
    func->size = GS_MAX_DEC_OUTPUT_ALL_PREC;

    return GS_SUCCESS;
}

status_t sql_func_sqrt(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t var;

    CM_POINTER3(stmt, func, result);

    expr_tree_t *arg = func->argument;
    CM_POINTER(arg);

    SQL_EXEC_FUNC_ARG_EX(arg, &var, result);

    GS_RETURN_IFERR(var_as_decimal(&var));

    result->is_null = GS_FALSE;
    result->type = GS_TYPE_NUMBER;
    return cm_dec_sqrt(&var.v_dec, &result->v_dec);
}

status_t sql_verify_sqrt(sql_verifier_t *verifier, expr_node_t *func)
{
    CM_POINTER2(verifier, func);

    GS_RETURN_IFERR(sql_verify_func_node(verifier, func, 1, 1, GS_INVALID_ID32));

    func->datatype = GS_TYPE_NUMBER;
    func->size = GS_MAX_DEC_OUTPUT_ALL_PREC;

    return GS_SUCCESS;
}
