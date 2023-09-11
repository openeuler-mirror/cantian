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
 * func_interval.c
 *
 *
 * IDENTIFICATION
 * src/cmd/function/func_interval.c
 *
 * -------------------------------------------------------------------------
 */
#include "func_interval.h"

static status_t sql_verify_num2interval_core(sql_verifier_t *verf, expr_node_t *func)
{
    if (sql_verify_func_node(verf, func, 2, 2, GS_INVALID_ID32) != GS_SUCCESS) {
        return GS_ERROR;
    }

    expr_tree_t *arg1 = func->argument;
    if (!sql_match_numeric_type(TREE_DATATYPE(arg1))) {
        GS_SRC_ERROR_REQUIRE_NUMERIC(arg1->loc, TREE_DATATYPE(arg1));
        return GS_ERROR;
    }

    expr_tree_t *arg2 = arg1->next;
    if (!sql_match_string_type(TREE_DATATYPE(arg2))) {
        GS_SRC_ERROR_REQUIRE_STRING(arg2->loc, TREE_DATATYPE(arg2));
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

/**
 * Syntax: NUMTOYMINTERVAL(num, 'interval_unit')
 * num is a numeric
 * interval_unit = {YEAR | MONTH}
 * @author, 2018/05/09
 */
status_t sql_verify_numtoyminterval(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (sql_verify_num2interval_core(verf, func) != GS_SUCCESS) {
        return GS_ERROR;
    }

    func->datatype = GS_TYPE_INTERVAL_YM;
    func->size = sizeof(interval_ym_t);
    func->typmod.year_prec = ITVL_MAX_YEAR_PREC;
    return GS_SUCCESS;
}

/**
 * Syntax: NUMTOYMINTERVAL(num, 'interval_unit')
 * num is a numeric
 * interval_unit = {YEAR | MONTH}
 * @author, 2018/05/09
 */
status_t sql_func_numtoyminterval(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t num_var, unit_var;
    interval_unit_t ym_unit_id;

    CM_POINTER2(func, result);

    // compute numeric value
    expr_tree_t *arg1 = func->argument;
    CM_POINTER(arg1);
    SQL_EXEC_FUNC_ARG_EX(arg1, &num_var, result);
    if (!GS_IS_WEAK_NUMERIC_TYPE(num_var.type)) {
        GS_SRC_ERROR_REQUIRE_NUMERIC(arg1->loc, num_var.type);
        return GS_ERROR;
    }
    if (var_as_real(&num_var) != GS_SUCCESS) {
        cm_set_error_loc(arg1->loc);
        return GS_ERROR;
    }

    // get the unit string
    expr_tree_t *arg2 = arg1->next;
    CM_POINTER(arg2);
    SQL_EXEC_FUNC_ARG_EX(arg2, &unit_var, result);
    if (!GS_IS_STRING_TYPE(unit_var.type)) {
        GS_SRC_ERROR_REQUIRE_STRING(arg2->loc, unit_var.type);
        return GS_ERROR;
    }

    ym_unit_id = cm_get_ymitvl_unit(&unit_var.v_text);
    if (ym_unit_id == IU_YEAR) {
        GS_RETURN_IFERR(cm_year2yminterval(num_var.v_real, &result->v_itvl_ym));
    } else if (ym_unit_id == IU_MONTH) {
        GS_RETURN_IFERR(cm_month2yminterval(num_var.v_real, &result->v_itvl_ym));
    } else {
        GS_SRC_THROW_ERROR(arg2->loc, ERR_INVALID_FUNC_PARAMS, "'YEAR' or 'MONTH' expected");
        return GS_ERROR;
    }

    result->is_null = GS_FALSE;
    result->type = GS_TYPE_INTERVAL_YM;
    return GS_SUCCESS;
}

/**
 * Syntax: NUMTODSINTERVAL(num, 'interval_unit')
 * num is a numeric
 * interval_unit = {DAY | HOUR | MINUTE | SECOND}
 * @author, 2018/05/09
 */
status_t sql_verify_numtodsinterval(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (sql_verify_num2interval_core(verf, func) != GS_SUCCESS) {
        return GS_ERROR;
    }

    func->datatype = GS_TYPE_INTERVAL_DS;
    func->size = sizeof(interval_ds_t);
    func->typmod.day_prec = ITVL_MAX_DAY_PREC;
    func->typmod.frac_prec = ITVL_MAX_SECOND_PREC;
    return GS_SUCCESS;
}

static status_t sql_num2dsitvl(variant_t *num_var, interval_unit_t ds_unit_id, interval_ds_t *dsitvl)
{
    switch (ds_unit_id) {
        case IU_DAY:
            GS_RETURN_IFERR(cm_day2dsinterval(num_var->v_real, dsitvl));
            break;

        case IU_HOUR:
            GS_RETURN_IFERR(cm_hour2dsinterval(num_var->v_real, dsitvl));
            break;

        case IU_MINUTE:
            GS_RETURN_IFERR(cm_minute2dsinterval(num_var->v_real, dsitvl));
            break;

        case IU_SECOND:
            GS_RETURN_IFERR(cm_second2dsinterval(num_var->v_real, dsitvl));
            break;

        case IU_NONE:
        default:
            GS_THROW_ERROR(ERR_INVALID_FUNC_PARAMS, "'DAY', 'HOUR', 'MINUTE' or 'SECOND' expected");
            return GS_ERROR;
    }

    return GS_SUCCESS;
}
/**
 * Syntax: NUMTODSINTERVAL(num, 'interval_unit')
 * num is a numeric
 * interval_unit = {DAY | HOUR | MINUTE | SECOND}
 * @author, 2018/05/09
 */
status_t sql_func_numtodsinterval(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t num_var, unit_var;
    interval_unit_t ds_unit_id;

    CM_POINTER2(func, result);

    // compute numeric value
    expr_tree_t *arg1 = func->argument;
    CM_POINTER(arg1);
    SQL_EXEC_FUNC_ARG_EX(arg1, &num_var, result);
    if (!GS_IS_WEAK_NUMERIC_TYPE(num_var.type)) {
        GS_SRC_ERROR_REQUIRE_NUMERIC(arg1->loc, num_var.type);
        return GS_ERROR;
    }
    if (var_as_real(&num_var) != GS_SUCCESS) {
        cm_set_error_loc(arg1->loc);
        return GS_ERROR;
    }

    // get the unit string
    expr_tree_t *arg2 = arg1->next;
    CM_POINTER(arg2);
    SQL_EXEC_FUNC_ARG_EX(arg2, &unit_var, result);
    if (!GS_IS_STRING_TYPE(unit_var.type)) {
        GS_SRC_ERROR_REQUIRE_STRING(arg2->loc, unit_var.type);
        return GS_ERROR;
    }

    ds_unit_id = cm_get_dsitvl_unit(&unit_var.v_text);
    if (sql_num2dsitvl(&num_var, ds_unit_id, &result->v_itvl_ds) != GS_SUCCESS) {
        cm_set_error_loc(arg2->loc);
        return GS_ERROR;
    }

    result->is_null = GS_FALSE;
    result->type = GS_TYPE_INTERVAL_DS;
    return GS_SUCCESS;
}

/**
 * The Implementation of the function TO_YMINTERVAL
 * @author Added 2018/04/10
 */
status_t sql_func_to_yminterval(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t var1;

    CM_POINTER3(stmt, func, result);

    expr_tree_t *arg1 = func->argument; // argument string value
    CM_POINTER(arg1);
    SQL_EXEC_FUNC_ARG_EX(arg1, &var1, result);
    if (!GS_IS_STRING_TYPE(var1.type)) {
        GS_SRC_ERROR_REQUIRE_STRING(arg1->loc, var1.type);
        return GS_ERROR;
    }

    result->is_null = GS_FALSE;
    result->type = GS_TYPE_INTERVAL_YM;

    return cm_text2yminterval(&var1.v_text, &result->v_itvl_ym);
}

static status_t sql_verify_to_interval_core(sql_verifier_t *verf, expr_node_t *func)
{
    if (sql_verify_func_node(verf, func, 1, 1, GS_INVALID_ID32) != GS_SUCCESS) {
        return GS_ERROR;
    }

    expr_tree_t *arg1 = func->argument;
    if (!sql_match_string_type(TREE_DATATYPE(arg1))) {
        GS_SRC_ERROR_REQUIRE_STRING(arg1->loc, TREE_DATATYPE(arg1));
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t sql_verify_to_yminterval(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (sql_verify_to_interval_core(verf, func) != GS_SUCCESS) {
        return GS_ERROR;
    }

    func->datatype = GS_TYPE_INTERVAL_YM;
    func->size = sizeof(interval_ym_t);
    func->typmod.year_prec = ITVL_MAX_YEAR_PREC;
    return GS_SUCCESS;
}
/**
 * The Implementation of the function TO_YMINTERVAL
 * @author Added 2018/04/10
 */
status_t sql_func_to_dsinterval(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t var1;

    CM_POINTER3(stmt, func, result);

    expr_tree_t *arg1 = func->argument; // argument string value
    CM_POINTER(arg1);
    SQL_EXEC_FUNC_ARG_EX(arg1, &var1, result);
    if (!GS_IS_STRING_TYPE(var1.type)) {
        GS_SRC_ERROR_REQUIRE_STRING(arg1->loc, var1.type);
        return GS_ERROR;
    }

    result->is_null = GS_FALSE;
    result->type = GS_TYPE_INTERVAL_DS;

    return cm_text2dsinterval(&var1.v_text, &result->v_itvl_ds);
}

status_t sql_verify_to_dsinterval(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (sql_verify_to_interval_core(verf, func) != GS_SUCCESS) {
        return GS_ERROR;
    }

    func->datatype = GS_TYPE_INTERVAL_DS;
    func->size = sizeof(interval_ds_t);
    func->typmod.day_prec = ITVL_MAX_DAY_PREC;
    func->typmod.frac_prec = ITVL_MAX_SECOND_PREC;
    return GS_SUCCESS;
}
