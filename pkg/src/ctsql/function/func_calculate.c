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
 * func_calculate.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/function/func_calculate.c
 *
 * -------------------------------------------------------------------------
 */
#include "func_calculate.h"
#include "func_hex.h"
#include "srv_instance.h"

status_t sql_func_abs(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    CM_POINTER3(stmt, func, res);

    expr_tree_t *arg = func->argument; // the first argument
    CM_POINTER(arg);

    SQL_EXEC_FUNC_ARG_EX(arg, res, res);

    if (CT_SUCCESS != var_as_decimal(res)) {
        return CT_ERROR;
    }

    res->is_null = CT_FALSE;
    cm_dec_abs(&res->v_dec);
    res->type = CT_TYPE_NUMBER;

    return CT_SUCCESS;
}

status_t sql_verify_abs(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 1, 1, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    func->datatype = CT_TYPE_NUMBER;
    func->size = (uint16)CT_MAX_DEC_OUTPUT_ALL_PREC;
    return CT_SUCCESS;
}

status_t sql_func_sin(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    variant_t var;

    CM_POINTER3(stmt, func, res);

    expr_tree_t *arg = func->argument;
    CM_POINTER(arg);

    SQL_EXEC_FUNC_ARG_EX(arg, &var, res);

    LOC_RETURN_IFERR(var_as_decimal(&var), arg->loc);
    LOC_RETURN_IFERR(cm_dec_sin(&var.v_dec, &res->v_dec), arg->loc);

    res->is_null = CT_FALSE;
    res->type = CT_TYPE_NUMBER;

    return CT_SUCCESS;
}

/* trigonometric functions' verification, such as sin(x), cos(x), tan(x), asin(x) */
status_t sql_verify_trigonometric(sql_verifier_t *verifier, expr_node_t *func)
{
    CM_POINTER2(verifier, func);

    CT_RETURN_IFERR(sql_verify_func_node(verifier, func, 1, 1, CT_INVALID_ID32));

    if (!sql_match_numeric_type(TREE_DATATYPE(func->argument))) {
        CT_SRC_ERROR_REQUIRE_NUMERIC(func->argument->loc, TREE_DATATYPE(func->argument));
        return CT_ERROR;
    }

    func->datatype = CT_TYPE_NUMBER;
    func->size = CT_MAX_DEC_OUTPUT_ALL_PREC;

    return CT_SUCCESS;
}

status_t sql_verify_radians(sql_verifier_t *verifier, expr_node_t *func)
{
    CM_POINTER2(verifier, func);

    CT_RETURN_IFERR(sql_verify_func_node(verifier, func, 1, 1, CT_INVALID_ID32));

    func->datatype = CT_TYPE_NUMBER;
    func->size = CT_MAX_DEC_OUTPUT_ALL_PREC;

    return CT_SUCCESS;
}

status_t sql_func_cos(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    variant_t var;

    CM_POINTER3(stmt, func, res);

    expr_tree_t *arg = func->argument;
    CM_POINTER(arg);

    SQL_EXEC_FUNC_ARG_EX(arg, &var, res);

    LOC_RETURN_IFERR(var_as_decimal(&var), arg->loc);
    LOC_RETURN_IFERR(cm_dec_cos(&var.v_dec, &res->v_dec), arg->loc);

    res->is_null = CT_FALSE;
    res->type = CT_TYPE_NUMBER;

    return CT_SUCCESS;
}

status_t sql_func_tan(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    variant_t var;

    CM_POINTER3(stmt, func, res);

    expr_tree_t *arg = func->argument;
    CM_POINTER(arg);

    SQL_EXEC_FUNC_ARG_EX(arg, &var, res);

    LOC_RETURN_IFERR(var_as_decimal(&var), arg->loc);
    LOC_RETURN_IFERR(cm_dec_tan(&var.v_dec, &res->v_dec), arg->loc);

    res->is_null = CT_FALSE;
    res->type = CT_TYPE_NUMBER;

    return CT_SUCCESS;
}

status_t sql_func_asin(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    variant_t var;

    CM_POINTER3(stmt, func, res);

    expr_tree_t *arg = func->argument;
    CM_POINTER(arg);

    SQL_EXEC_FUNC_ARG_EX(arg, &var, res);

    LOC_RETURN_IFERR(var_as_decimal(&var), arg->loc);
    LOC_RETURN_IFERR(cm_dec_asin(&var.v_dec, &res->v_dec), arg->loc);

    res->is_null = CT_FALSE;
    res->type = CT_TYPE_NUMBER;

    return CT_SUCCESS;
}

status_t sql_func_acos(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    variant_t var;

    CM_POINTER3(stmt, func, res);

    expr_tree_t *arg = func->argument;
    CM_POINTER(arg);

    SQL_EXEC_FUNC_ARG_EX(arg, &var, res);

    LOC_RETURN_IFERR(var_as_decimal(&var), arg->loc);
    LOC_RETURN_IFERR(cm_dec_acos(&var.v_dec, &res->v_dec), arg->loc);

    res->is_null = CT_FALSE;
    res->type = CT_TYPE_NUMBER;

    return CT_SUCCESS;
}

status_t sql_func_atan(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    variant_t var;

    CM_POINTER3(stmt, func, res);

    expr_tree_t *arg = func->argument;

    CM_POINTER(arg);

    SQL_EXEC_FUNC_ARG_EX(arg, &var, res);
    LOC_RETURN_IFERR(var_as_decimal(&var), arg->loc);
    LOC_RETURN_IFERR(var_as_decimal(&var), arg->loc);
    LOC_RETURN_IFERR(cm_dec_atan(&var.v_dec, &res->v_dec), arg->loc);

    res->is_null = CT_FALSE;
    res->type = CT_TYPE_NUMBER;

    return CT_SUCCESS;
}

status_t sql_func_atan2(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    expr_tree_t *arg1 = NULL;
    expr_tree_t *arg2 = NULL;
    variant_t var1, var2;

    CM_POINTER3(stmt, func, res);

    arg1 = func->argument;

    CM_POINTER(arg1);
    SQL_EXEC_FUNC_ARG_EX(arg1, &var1, res);
    LOC_RETURN_IFERR(sql_convert_variant(stmt, &var1, CT_TYPE_NUMBER), arg1->loc);

    arg2 = arg1->next;

    CM_POINTER(arg2);
    SQL_EXEC_FUNC_ARG_EX(arg2, &var2, res);
    LOC_RETURN_IFERR(sql_convert_variant(stmt, &var2, CT_TYPE_NUMBER), arg2->loc);

    CT_RETURN_IFERR(cm_dec_atan2(&var1.v_dec, &var2.v_dec, &res->v_dec));

    res->is_null = CT_FALSE;
    res->type = CT_TYPE_NUMBER;

    return CT_SUCCESS;
}

status_t sql_verify_atan2(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    CT_RETURN_IFERR(sql_verify_func_node(verf, func, 2, 2, CT_INVALID_ID32));

    expr_tree_t *arg = func->argument;

    if (!sql_match_numeric_type(TREE_DATATYPE(arg))) {
        CT_SRC_ERROR_REQUIRE_NUMERIC(arg->loc, TREE_DATATYPE(arg));
        return CT_ERROR;
    }

    arg = arg->next;

    if (!sql_match_numeric_type(TREE_DATATYPE(arg))) {
        CT_SRC_ERROR_REQUIRE_NUMERIC(arg->loc, TREE_DATATYPE(arg));
        return CT_ERROR;
    }

    func->datatype = CT_TYPE_NUMBER;
    func->size = CT_MAX_DEC_OUTPUT_ALL_PREC;
    return CT_SUCCESS;
}

status_t sql_func_tanh(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    expr_tree_t *arg = NULL;
    variant_t var;

    CM_POINTER3(stmt, func, res);

    arg = func->argument;
    CM_POINTER(arg);

    SQL_EXEC_FUNC_ARG_EX(arg, &var, res);

    LOC_RETURN_IFERR(sql_convert_variant(stmt, &var, CT_TYPE_NUMBER), arg->loc);

    LOC_RETURN_IFERR(cm_dec_tanh(&var.v_dec, &res->v_dec), arg->loc);

    res->is_null = CT_FALSE;
    res->type = CT_TYPE_NUMBER;

    return CT_SUCCESS;
}

status_t sql_verify_tanh(sql_verifier_t *verifier, expr_node_t *func)
{
    CM_POINTER2(verifier, func);

    if (CT_SUCCESS != sql_verify_func_node(verifier, func, 1, 1, CT_INVALID_ID32)) {
        return CT_ERROR;
    }

    if (!sql_match_numeric_type(TREE_DATATYPE(func->argument))) {
        CT_SRC_ERROR_REQUIRE_NUMERIC(func->argument->loc, TREE_DATATYPE(func->argument));
        return CT_ERROR;
    }

    func->datatype = CT_TYPE_NUMBER;
    func->size = CT_MAX_DEC_OUTPUT_ALL_PREC;

    return CT_SUCCESS;
}

static status_t sql_func_bit_oper(sql_stmt_t *stmt, expr_node_t *func, bit_operation_t op, variant_t *res)
{
    variant_t l_var, r_var; // left and right variants

    CM_POINTER3(stmt, func, res);

    expr_tree_t *arg1 = func->argument;
    CM_POINTER(arg1);
    SQL_EXEC_FUNC_ARG_EX(arg1, &l_var, res);
    if (var_as_floor_bigint(&l_var) != CT_SUCCESS) {
        cm_set_error_loc(arg1->loc);
        return CT_ERROR;
    }

    expr_tree_t *arg2 = arg1->next;
    CM_POINTER(arg2);
    SQL_EXEC_FUNC_ARG_EX(arg2, &r_var, res);
    if (var_as_floor_bigint(&r_var) != CT_SUCCESS) {
        cm_set_error_loc(arg2->loc);
        return CT_ERROR;
    }

    switch (op) {
        case BIT_OPER_AND:
            res->v_bigint = (uint64)l_var.v_bigint & (uint64)r_var.v_bigint;
            break;

        case BIT_OPER_OR:
            res->v_bigint = (uint64)l_var.v_bigint | (uint64)r_var.v_bigint;
            break;

        case BIT_OPER_XOR:
            res->v_bigint = (uint64)l_var.v_bigint ^ (uint64)r_var.v_bigint;
            break;

        default:
            CT_THROW_ERROR(ERR_UNSUPPORT_OPER_TYPE, "bit operation", op);
            return CT_ERROR;
    }
    res->type = CT_TYPE_BIGINT;
    res->is_null = CT_FALSE;
    return CT_SUCCESS;
}

status_t sql_func_bit_and(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    return sql_func_bit_oper(stmt, func, BIT_OPER_AND, res);
}

status_t sql_verify_bit_func(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 2, 2, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    func->datatype = CT_TYPE_BIGINT;
    func->size = CT_BIGINT_SIZE;

    return CT_SUCCESS;
}

status_t sql_func_bit_or(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    return sql_func_bit_oper(stmt, func, BIT_OPER_OR, res);
}

status_t sql_func_bit_xor(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    return sql_func_bit_oper(stmt, func, BIT_OPER_XOR, res);
}

status_t sql_func_ceil(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    CM_POINTER3(stmt, func, res);

    expr_tree_t *arg = func->argument;
    CM_POINTER(arg);

    SQL_EXEC_FUNC_ARG_EX(arg, res, res);

    CT_RETURN_IFERR(var_as_decimal(res));

    res->is_null = CT_FALSE;
    res->type = CT_TYPE_NUMBER;

    return cm_dec_ceil(&res->v_dec);
}

status_t sql_verify_ceil(sql_verifier_t *verifier, expr_node_t *func)
{
    CM_POINTER2(verifier, func);

    if (CT_SUCCESS != sql_verify_func_node(verifier, func, 1, 1, CT_INVALID_ID32)) {
        return CT_ERROR;
    }

    expr_tree_t *arg1 = func->argument;
    if (!sql_match_numeric_type(TREE_DATATYPE(arg1))) {
        CT_SRC_ERROR_REQUIRE_NUMERIC(arg1->loc, TREE_DATATYPE(arg1));
        return CT_ERROR;
    }

    func->datatype = CT_TYPE_NUMBER;
    func->size = CT_MAX_DEC_OUTPUT_ALL_PREC;

    return CT_SUCCESS;
}

status_t sql_func_exp(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    variant_t e;
    CM_POINTER3(stmt, func, res);

    expr_tree_t *arg = func->argument;
    CM_POINTER(arg);

    SQL_EXEC_FUNC_ARG_EX(arg, &e, res);

    if (CT_SUCCESS != var_as_decimal(&e)) {
        cm_set_error_loc(arg->loc);
        return CT_ERROR;
    }

    res->is_null = CT_FALSE;
    if (CT_SUCCESS != cm_dec_exp(&e.v_dec, &res->v_dec)) {
        cm_set_error_loc(arg->loc);
        return CT_ERROR;
    }
    res->type = CT_TYPE_NUMBER;

    return CT_SUCCESS;
}

status_t sql_verify_exp(sql_verifier_t *verifier, expr_node_t *func)
{
    CM_POINTER2(verifier, func);

    CT_RETURN_IFERR(sql_verify_func_node(verifier, func, 1, 1, CT_INVALID_ID32));

    expr_tree_t *arg1 = func->argument;
    if (!sql_match_numeric_type(TREE_DATATYPE(arg1))) {
        CT_SRC_ERROR_REQUIRE_NUMERIC(arg1->loc, TREE_DATATYPE(arg1));
        return CT_ERROR;
    }

    func->datatype = CT_TYPE_NUMBER;
    func->size = CT_MAX_DEC_OUTPUT_ALL_PREC;

    return CT_SUCCESS;
}

status_t sql_func_floor(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    CM_POINTER3(stmt, func, res);

    expr_tree_t *arg = func->argument;
    CM_POINTER(arg);

    SQL_EXEC_FUNC_ARG_EX(arg, res, res);

    if (var_as_decimal(res) != CT_SUCCESS) {
        return CT_ERROR;
    }

    res->is_null = CT_FALSE;
    res->type = CT_TYPE_NUMBER;
    return cm_dec_floor(&res->v_dec);
}

status_t sql_verify_floor(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 1, 1, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    expr_tree_t *arg1 = func->argument;
    if (!sql_match_numeric_type(TREE_DATATYPE(arg1))) {
        CT_SRC_ERROR_REQUIRE_NUMERIC(arg1->loc, TREE_DATATYPE(arg1));
        return CT_ERROR;
    }

    func->datatype = CT_TYPE_NUMBER;
    func->size = CT_MAX_DEC_OUTPUT_ALL_PREC;

    return CT_SUCCESS;
}

static void sql_func_inet_ntoa_core(sql_stmt_t *stmt, variant_t *var, variant_t *res)
{
    uint32 byte1, byte2, byte3, byte4;

    byte1 = ((uint64)var->v_bigint & 0xFF000000) >> 24;
    byte2 = ((uint64)var->v_bigint & 0x00FF0000) >> 16;
    byte3 = ((uint64)var->v_bigint & 0x0000FF00) >> 8;
    byte4 = ((uint64)var->v_bigint & 0x000000FF);

    PRTS_RETVOID_IFERR(snprintf_s(res->v_text.str, CT_STRING_BUFFER_SIZE, CT_STRING_BUFFER_SIZE - 1, "%u.%u.%u.%u",
        byte1, byte2, byte3, byte4));

    res->v_text.len = (uint32)strlen(res->v_text.str);
    res->type = CT_TYPE_STRING;
    res->is_null = CT_FALSE;
}

status_t sql_func_inet_ntoa(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    variant_t arg;
    char *buf = NULL;

    CM_POINTER3(stmt, func, res);
    CM_POINTER(func->argument);

    SQL_EXEC_FUNC_ARG_EX(func->argument, &arg, res);
    if (var_as_bigint(&arg) != CT_SUCCESS) {
        cm_set_error_loc(func->loc);
        return CT_ERROR;
    }
    if (arg.is_null || arg.v_bigint < 0 || arg.v_bigint > (int64)0xFFFFFFFF) {
        SQL_SET_NULL_VAR(res);
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(sql_push(stmt, CT_STRING_BUFFER_SIZE, (void **)&buf));
    res->v_text.str = buf;
    res->v_text.len = 0;

    sql_func_inet_ntoa_core(stmt, &arg, res);
    return CT_SUCCESS;
}

status_t sql_verify_inet_ntoa(sql_verifier_t *verifier, expr_node_t *func)
{
    CM_POINTER2(verifier, func);

    CT_RETURN_IFERR(sql_verify_func_node(verifier, func, 1, 1, CT_INVALID_ID32));

    func->datatype = CT_TYPE_STRING;
    func->size = cm_get_datatype_strlen(func->argument->root->datatype, func->argument->root->size);
    return CT_SUCCESS;
}

status_t sql_func_ln(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    variant_t var;
    CM_POINTER3(stmt, func, res);

    expr_tree_t *arg = func->argument;
    CM_POINTER(arg);

    SQL_EXEC_FUNC_ARG_EX(arg, &var, res);

    if (CT_SUCCESS != var_as_decimal(&var)) {
        cm_set_error_loc(arg->loc);
        return CT_ERROR;
    }

    res->is_null = CT_FALSE;
    if (CT_SUCCESS != cm_dec_ln(&var.v_dec, &res->v_dec)) {
        cm_set_error_loc(arg->loc);
        return CT_ERROR;
    }
    res->type = CT_TYPE_NUMBER;

    return CT_SUCCESS;
}

status_t sql_verify_ln(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    CT_RETURN_IFERR(sql_verify_func_node(verf, func, 1, 1, CT_INVALID_ID32));

    expr_tree_t *arg1 = func->argument;
    if (!sql_match_numeric_type(TREE_DATATYPE(arg1))) {
        CT_SRC_ERROR_REQUIRE_NUMERIC(arg1->loc, TREE_DATATYPE(arg1));
        return CT_ERROR;
    }

    func->datatype = CT_TYPE_NUMBER;
    func->size = CT_MAX_DEC_OUTPUT_ALL_PREC;
    return CT_SUCCESS;
}

status_t sql_func_log(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    expr_tree_t *arg1 = NULL;
    expr_tree_t *arg2 = NULL;
    variant_t l_var, r_var;

    arg1 = func->argument;

    SQL_EXEC_FUNC_ARG_EX(arg1, &l_var, res);
    LOC_RETURN_IFERR(var_as_decimal(&l_var), arg1->loc);

    res->is_null = CT_FALSE;
    res->type = CT_TYPE_NUMBER;

    // 1. log(a) = ln(a), where a > 0
    arg2 = arg1->next;
    if (arg2 == NULL) {
        LOC_RETURN_IFERR(cm_dec_ln(&l_var.v_dec, &res->v_dec), arg1->loc);
        return CT_SUCCESS;
    }

    // 2. log(a, b) = ln(b) / ln(a), where a > 0 && a != 1 && b > 0
    SQL_EXEC_FUNC_ARG_EX(arg2, &r_var, res);
    LOC_RETURN_IFERR(var_as_decimal(&r_var), arg2->loc);

    LOC_RETURN_IFERR(cm_dec_log(&l_var.v_dec, &r_var.v_dec, &res->v_dec), func->loc);
    return CT_SUCCESS;
}

status_t sql_verify_log(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    CT_RETURN_IFERR(sql_verify_func_node(verf, func, 1, 2, CT_INVALID_ID32));

    func->datatype = CT_TYPE_NUMBER;
    func->size = MAX_DEC_BYTE_SZ;
    return CT_SUCCESS;
}

status_t sql_func_mod(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    expr_tree_t *arg1 = NULL;
    expr_tree_t *arg2 = NULL;
    variant_t l_var, r_var;

    CM_POINTER3(stmt, func, res);

    res->is_null = CT_FALSE;

    arg1 = func->argument;
    CM_POINTER(arg1);
    SQL_EXEC_FUNC_ARG_EX(arg1, &l_var, res);
    sql_keep_stack_variant(stmt, &l_var);

    arg2 = arg1->next;
    CM_POINTER(arg2);
    SQL_EXEC_FUNC_ARG_EX(arg2, &r_var, res);
    sql_keep_stack_variant(stmt, &r_var);

    if (l_var.type == CT_TYPE_INTEGER && r_var.type == CT_TYPE_INTEGER) {
        res->type = CT_TYPE_INTEGER;
        res->v_int = r_var.v_int == 0 ? l_var.v_int : l_var.v_int % r_var.v_int;
        CT_RETURN_IFERR(var_as_decimal(res));
        return CT_SUCCESS;
    }

    if (l_var.type == CT_TYPE_BIGINT && r_var.type == CT_TYPE_BIGINT) {
        res->type = CT_TYPE_BIGINT;
        res->v_bigint = r_var.v_bigint == 0 ? l_var.v_bigint : l_var.v_bigint % r_var.v_bigint;
        CT_RETURN_IFERR(var_as_decimal(res));
        return CT_SUCCESS;
    }

    if (l_var.type == CT_TYPE_BIGINT && r_var.type == CT_TYPE_INTEGER) {
        res->type = CT_TYPE_BIGINT;
        res->v_bigint = r_var.v_int == 0 ? l_var.v_bigint : l_var.v_bigint % r_var.v_int;
        CT_RETURN_IFERR(var_as_decimal(res));
        return CT_SUCCESS;
    }

    if (l_var.type == CT_TYPE_INTEGER && r_var.type == CT_TYPE_BIGINT) {
        res->type = CT_TYPE_BIGINT;
        res->v_bigint = r_var.v_bigint == 0 ? l_var.v_int : l_var.v_int % r_var.v_bigint;
        CT_RETURN_IFERR(var_as_decimal(res));
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(var_as_decimal(&l_var));
    CT_RETURN_IFERR(var_as_decimal(&r_var));

    res->type = CT_TYPE_NUMBER;
    return cm_dec_mod(&l_var.v_dec, &r_var.v_dec, &res->v_dec);
}

status_t sql_verify_mod(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    CT_RETURN_IFERR(sql_verify_func_node(verf, func, 2, 2, CT_INVALID_ID32));

    func->datatype = CT_TYPE_NUMBER;
    func->size = CT_MAX_DEC_OUTPUT_ALL_PREC;
    return CT_SUCCESS;
}

#define POWER_AS_SHIFT_BASE 2
#define POWER_AS_SHIFT_MIN_EXPN 0
#define POWER_AS_SHIFT_MAX_EXPN 30
static inline bool32 if_power_as_shift(variant_t *base, variant_t *expn)
{
    if (base->type == CT_TYPE_INTEGER && base->v_int == POWER_AS_SHIFT_BASE && expn->type == CT_TYPE_INTEGER &&
        expn->v_int >= POWER_AS_SHIFT_MIN_EXPN && expn->v_int <= POWER_AS_SHIFT_MAX_EXPN) {
        return CT_TRUE;
    }

    return CT_FALSE;
}

status_t sql_func_pi(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    CM_POINTER3(stmt, func, res);

    cm_dec8_pi(&res->v_dec);
    res->is_null = CT_FALSE;
    res->type = CT_TYPE_NUMBER;
    
    return CT_SUCCESS;
}

status_t sql_verify_pi(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    CT_RETURN_IFERR(sql_verify_func_node(verf, func, 0, 0, CT_INVALID_ID32));

    func->datatype = CT_TYPE_NUMBER;
    func->size = MAX_DEC_BYTE_SZ;
    return CT_SUCCESS;
}

status_t sql_func_power(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    expr_tree_t *arg1 = NULL;
    expr_tree_t *arg2 = NULL;
    variant_t base, expn;

    CM_POINTER3(stmt, func, res);

    res->is_null = CT_FALSE;
    res->type = CT_TYPE_NUMBER;

    arg1 = func->argument;
    CM_POINTER(arg1);
    SQL_EXEC_FUNC_ARG_EX(arg1, &base, res);

    arg2 = arg1->next;
    CM_POINTER(arg2);
    SQL_EXEC_FUNC_ARG_EX(arg2, &expn, res);

    if (if_power_as_shift(&base, &expn)) {
        res->v_int = 1 << expn.v_int;
        cm_int32_to_dec8(res->v_int, VALUE_PTR(dec8_t, res));
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(var_as_decimal(&base));
    CT_RETURN_IFERR(var_as_decimal(&expn));
    return cm_dec_power(&base.v_dec, &expn.v_dec, &res->v_dec);
}

status_t sql_verify_power(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    CT_RETURN_IFERR(sql_verify_func_node(verf, func, 2, 2, CT_INVALID_ID32));

    expr_tree_t *arg = func->argument;
    if (!sql_match_numeric_type(TREE_DATATYPE(arg))) {
        CT_SRC_ERROR_REQUIRE_NUMERIC(arg->loc, TREE_DATATYPE(arg));
        return CT_ERROR;
    }

    arg = arg->next;
    if (!sql_match_numeric_type(TREE_DATATYPE(arg))) {
        CT_SRC_ERROR_REQUIRE_NUMERIC(arg->loc, TREE_DATATYPE(arg));
        return CT_ERROR;
    }

    func->datatype = CT_TYPE_NUMBER;
    func->size = MAX_DEC_BYTE_SZ;
    return CT_SUCCESS;
}

status_t sql_func_radians(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    variant_t var;

    CM_POINTER3(stmt, func, res);

    expr_tree_t *arg = func->argument;
    CM_POINTER(arg);

    SQL_EXEC_FUNC_ARG_EX(arg, &var, res);

    if (CT_IS_LOB_TYPE(TREE_DATATYPE(func->argument)) || CT_IS_STRING_TYPE(TREE_DATATYPE(func->argument))) {
        num_errno_t nerr_no = cm_text2real_ex_no_check_err(&var.v_text, &var.v_real);
        var.type = CT_TYPE_REAL;
        CM_TRY_THROW_NUM_ERR(nerr_no);
        res->v_real = var.v_real * (CT_PI / CT_180_DEGREE);
        res->type = CT_TYPE_REAL;
        CT_RETURN_IFERR(cm_real_to_dec8_prec17(res->v_real, VALUE_PTR(dec8_t, res)));
    } else {
        LOC_RETURN_IFERR(var_as_decimal(&var), arg->loc);
        LOC_RETURN_IFERR(cm_dec8_radians(&var.v_dec, &res->v_dec), arg->loc);
    }
    res->is_null = CT_FALSE;
    res->type = CT_TYPE_NUMBER;

    return CT_SUCCESS;
}

status_t sql_func_rand(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    expr_tree_t *arg = NULL;
    uint32 randvalue;
    variant_t var_seed;
    int64 seed;

    res->is_null = CT_FALSE;
    res->type = CT_TYPE_NUMBER;

    if (func->argument != NULL) {
        arg = func->argument;

        /* get the seed value */
        if (sql_exec_expr(stmt, arg, &var_seed) != CT_SUCCESS) {
            return CT_ERROR;
        }
        SQL_CHECK_COLUMN_VAR(&var_seed, res);
        if (!(var_seed.is_null == CT_FALSE && CT_IS_NUMERIC_TYPE(var_seed.type))) {
            CT_SRC_THROW_ERROR(func->argument->root->loc, ERR_INVALID_FUNC_PARAMS,
                               "the seed of rand is incorrect");
            return CT_ERROR;
        }

        /* convert to uint64 */
        CT_RETURN_IFERR(var_to_round_bigint(&var_seed, ROUND_TRUNC, &seed, NULL));
        randvalue = cm_rand_int32(&seed, CT_MAX_RAND_RANGE);
    } else {
        randvalue = cm_random(CT_MAX_RAND_RANGE);
    }
    cm_uint32_to_dec(randvalue, &res->v_dec);
    CT_RETURN_IFERR(cm_dec_div_int64(&res->v_dec, CT_MAX_RAND_RANGE, &res->v_dec));

    return CT_SUCCESS;
}

status_t sql_verify_rand(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    CT_RETURN_IFERR(sql_verify_func_node(verf, func, 0, 1, CT_INVALID_ID32));

    expr_tree_t *arg = func->argument;
    if (arg != NULL) {
        /* param must be one char or null */
        if (!sql_match_numeric_type(TREE_DATATYPE(arg))) {
            CT_SRC_THROW_ERROR(func->argument->root->loc, ERR_INVALID_FUNC_PARAMS,
                               "the argument of rand is incorrect");
            return CT_ERROR;
        }
    }

    func->datatype = CT_TYPE_NUMBER;
    func->size = MAX_DEC_BYTE_SZ;
    func->scale = CT_UNSPECIFIED_NUM_SCALE;
    func->precision = CT_UNSPECIFIED_NUM_PREC;
    return CT_SUCCESS;
}

status_t sql_func_rawtohex(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    return sql_bin2hex(stmt, func, CT_FALSE, res);
}

status_t sql_verify_rawtohex(sql_verifier_t *verf, expr_node_t *func)
{
    return sql_verify_bin2hex(verf, func);
}

static status_t sql_func_round_trunc_date(sql_stmt_t *stmt, variant_t *var1, expr_tree_t *arg1, variant_t *res,
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
        SQL_EXEC_FUNC_ARG_EX(arg2, &var2, res);
        if (var2.type != CT_TYPE_CHAR && var2.type != CT_TYPE_STRING && var2.type != CT_TYPE_VARCHAR) {
            CT_THROW_ERROR(ERR_UNEXPECTED_KEY, "a string value.");
            return CT_ERROR;
        }

        fmt_text = var2.v_text;
    }

    if (is_round) {
        return cm_round_date(var1->v_date, &fmt_text, &res->v_date);
    } else {
        return cm_trunc_date(var1->v_date, &fmt_text, &res->v_date);
    }
}

static status_t sql_func_round_trunc_decimal(sql_stmt_t *stmt, variant_t *var1, expr_tree_t *arg1, variant_t *res,
    bool32 is_round)
{
    variant_t var2;
    int32 scale;

    // param number
    CT_RETURN_IFERR(var_as_decimal(var1));

    // param scale
    expr_tree_t *arg2 = arg1->next;
    if (arg2 == NULL) {
        scale = 0;
    } else {
        SQL_EXEC_FUNC_ARG_EX(arg2, &var2, res);
        CT_RETURN_IFERR(var_as_floor_integer(&var2));
        scale = var2.v_int;
    }

    CT_RETURN_IFERR(cm_dec_scale(&var1->v_dec, scale, is_round ? ROUND_HALF_UP : ROUND_TRUNC));
    cm_dec_copy(&res->v_dec, &var1->v_dec);
    return CT_SUCCESS;
}

static status_t sql_func_round_trunc(sql_stmt_t *stmt, expr_node_t *func, variant_t *res, bool32 is_round)
{
    variant_t var1;

    CM_POINTER3(stmt, func, res);

    res->is_null = CT_FALSE;

    // param date or number
    expr_tree_t *arg1 = func->argument;
    CM_POINTER(arg1);
    SQL_EXEC_FUNC_ARG_EX(arg1, &var1, res);

    if (CT_IS_DATETIME_TYPE(var1.type)) {
        res->type = CT_TYPE_DATE;
        CT_RETURN_IFERR(sql_convert_variant(stmt, &var1, CT_TYPE_DATE));
        return sql_func_round_trunc_date(stmt, &var1, arg1, res, is_round);
    } else {
        res->type = CT_TYPE_NUMBER;
        return sql_func_round_trunc_decimal(stmt, &var1, arg1, res, is_round);
    }
}

status_t sql_func_round(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    return sql_func_round_trunc(stmt, func, res, CT_TRUE);
}

status_t sql_func_trunc(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    return sql_func_round_trunc(stmt, func, res, CT_FALSE);
}

status_t sql_verify_round_trunc(sql_verifier_t *verf, expr_node_t *func)
{
    /* syntax:
    round(number[,scale) round(date[,fmt)
    trunc(number[,scale) trunc(date[,fmt)
    */
    CM_POINTER2(verf, func);

    CT_RETURN_IFERR(sql_verify_func_node(verf, func, 1, 2, CT_INVALID_ID32));

    expr_tree_t *arg = func->argument;
    if (!sql_match_num_and_datetime_type(TREE_DATATYPE(arg))) {
        CT_SRC_ERROR_REQUIRE_NUM_OR_DATETIME(TREE_LOC(arg), TREE_DATATYPE(arg));
        return CT_ERROR;
    }

    if (CT_IS_DATETIME_TYPE(TREE_DATATYPE(arg))) {
        func->datatype = CT_TYPE_DATE;
        func->precision = 0;
    } else if (CT_IS_NUMERIC_TYPE(TREE_DATATYPE(arg)) || CT_IS_STRING_TYPE(TREE_DATATYPE(arg))) {
        func->datatype = CT_TYPE_NUMBER;
        func->precision = CT_UNSPECIFIED_NUM_PREC;
        func->scale = CT_UNSPECIFIED_NUM_SCALE;
    } else {
        func->datatype = CT_TYPE_UNKNOWN;
        func->precision = 0;
    }

    if (arg->next != NULL) {
        arg = arg->next;
        if (CT_IS_DATETIME_TYPE(func->datatype)) {
            if (!sql_match_string_type(TREE_DATATYPE(arg))) {
                CT_SRC_ERROR_REQUIRE_STRING(TREE_LOC(arg), TREE_DATATYPE(arg));
                return CT_ERROR;
            }
        } else {
            if (!sql_match_numeric_type(TREE_DATATYPE(arg))) {
                CT_SRC_ERROR_REQUIRE_NUMERIC(TREE_LOC(arg), TREE_DATATYPE(arg));
                return CT_ERROR;
            }
        }
    }

    func->size = cm_get_datatype_strlen(func->datatype, func->argument->root->size);
    return CT_SUCCESS;
}

status_t sql_func_sign(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    variant_t var;

    CM_POINTER3(stmt, func, res);

    expr_tree_t *arg = func->argument;
    CM_POINTER(arg);

    SQL_EXEC_FUNC_ARG_EX(arg, &var, res);

    if (CT_SUCCESS != var_as_decimal(&var)) {
        cm_set_error_loc(arg->loc);
        return CT_ERROR;
    }

    res->is_null = CT_FALSE;
    res->type = CT_TYPE_NUMBER;

    cm_dec_sign(&var.v_dec, &res->v_dec);
    return CT_SUCCESS;
}

status_t sql_verify_sign(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    CT_RETURN_IFERR(sql_verify_func_node(verf, func, 1, 1, CT_INVALID_ID32));

    func->datatype = CT_TYPE_NUMBER;
    func->size = CT_MAX_DEC_OUTPUT_ALL_PREC;

    return CT_SUCCESS;
}

status_t sql_func_sqrt(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    variant_t var;

    CM_POINTER3(stmt, func, res);

    expr_tree_t *arg = func->argument;
    CM_POINTER(arg);

    SQL_EXEC_FUNC_ARG_EX(arg, &var, res);

    CT_RETURN_IFERR(var_as_decimal(&var));

    res->is_null = CT_FALSE;
    res->type = CT_TYPE_NUMBER;
    return cm_dec_sqrt(&var.v_dec, &res->v_dec);
}

status_t sql_verify_sqrt(sql_verifier_t *verifier, expr_node_t *func)
{
    CM_POINTER2(verifier, func);

    CT_RETURN_IFERR(sql_verify_func_node(verifier, func, 1, 1, CT_INVALID_ID32));

    func->datatype = CT_TYPE_NUMBER;
    func->size = CT_MAX_DEC_OUTPUT_ALL_PREC;

    return CT_SUCCESS;
}
