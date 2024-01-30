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
 * func_date.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/function/func_date.c
 *
 * -------------------------------------------------------------------------
 */
#include "func_date.h"
#include "srv_instance.h"

static inline bool32 sql_is_last_month_day(date_detail_t *data_detail)
{
    return (data_detail->day == CM_MONTH_DAYS(data_detail->year, data_detail->mon));
}

static status_t sql_func_add_months_core(int32 temp_add_months, date_detail_t *time_desc)
{
    int32 year = time_desc->year;
    int32 month = time_desc->mon;
    bool32 last_mon_day;
    int32 add_months = temp_add_months;

    // check whether time_desc is the last day of current month
    last_mon_day = sql_is_last_month_day(time_desc);

    year += (add_months / 12);
    add_months %= 12;
    month += add_months;

    if (month > 12) {
        year++;
        month -= 12;
    } else if (month <= 0) {
        year--;
        month += 12;
    }

    if (!CM_IS_VALID_YEAR(year)) {
        CT_THROW_ERROR(ERR_TYPE_OVERFLOW, "DATETIME");
        return CT_ERROR;
    }

    time_desc->year = (uint16)year;
    time_desc->mon = (uint8)month;

    if (last_mon_day || (time_desc->day > CM_MONTH_DAYS(time_desc->year, time_desc->mon))) {
        time_desc->day = (uint8)CM_MONTH_DAYS(time_desc->year, time_desc->mon);
    }

    return CT_SUCCESS;
}

status_t sql_func_add_months(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    variant_t date_var, month_var;
    date_detail_t time_desc;

    CM_POINTER2(func, res);

    // get date_round
    expr_tree_t *arg1 = func->argument;
    CM_POINTER(arg1);
    SQL_EXEC_FUNC_ARG_EX(arg1, &date_var, res);
    if (var_as_date(SESSION_NLS(stmt), &date_var) != CT_SUCCESS) {
        cm_set_error_loc(arg1->loc);
        return CT_ERROR;
    }

    // get added months
    expr_tree_t *arg2 = arg1->next;
    CM_POINTER(arg2);
    SQL_EXEC_FUNC_ARG_EX(arg2, &month_var, res);

    if (var_as_floor_integer(&month_var) != CT_SUCCESS) {
        cm_set_error_loc(arg2->loc);
        return CT_ERROR;
    }

    cm_decode_date(date_var.v_date, &time_desc);
    if (sql_func_add_months_core(month_var.v_int, &time_desc) != CT_SUCCESS) {
        cm_set_error_loc(func->loc);
        return CT_ERROR;
    }

    res->is_null = CT_FALSE;
    res->type = date_var.type;
    res->v_date = cm_encode_date(&time_desc);

    return CT_SUCCESS;
}
status_t sql_verify_add_months(sql_verifier_t *verif, expr_node_t *func)
{
    CM_POINTER2(verif, func);

    if (sql_verify_func_node(verif, func, 2, 2, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    expr_tree_t *date_arg = func->argument;
    if (!sql_match_datetime_type(TREE_DATATYPE(date_arg))) {
        CT_SRC_ERROR_REQUIRE_DATETIME(date_arg->loc, TREE_DATATYPE(date_arg));
        return CT_ERROR;
    }

    expr_tree_t *mon_arg = date_arg->next;
    if (!sql_match_numeric_type(TREE_DATATYPE(mon_arg))) {
        CT_SRC_ERROR_REQUIRE_NUMERIC(mon_arg->loc, TREE_DATATYPE(mon_arg));
        return CT_ERROR;
    }

    sql_infer_func_optmz_mode(verif, func);

    /* STRING type into a DATETIME type depends on the SESSION datetime format */
    if (CT_IS_STRING_TYPE(TREE_DATATYPE(date_arg)) && CT_IS_WEAK_NUMERIC_TYPE(TREE_DATATYPE(mon_arg)) &&
        NODE_IS_OPTMZ_CONST(func)) {
        sql_add_first_exec_node(verif, func);
    }

    func->datatype = CT_TYPE_DATE;
    func->size = CT_DATE_SIZE;
    return CT_SUCCESS;
}

status_t sql_verify_current_timestamp(sql_verifier_t *verif, expr_node_t *func)
{
    int32 precision = CT_DEFAULT_DATETIME_PRECISION;
    CM_POINTER2(verif, func);

    CT_RETURN_IFERR(sql_verify_func_node(verif, func, 0, 1, CT_INVALID_ID32));

    expr_tree_t *arg = func->argument;
    if (arg != NULL) {
        if (CT_IS_INTEGER_TYPE(TREE_DATATYPE(arg)) && TREE_IS_CONST(arg)) {
            precision = VALUE(int32, &arg->root->value);
            if (precision < CT_MIN_DATETIME_PRECISION || precision > CT_MAX_DATETIME_PRECISION) {
                CT_SRC_THROW_ERROR_EX(func->loc, ERR_SQL_SYNTAX_ERROR, "fraction must between %d and %d. ",
                    CT_MIN_DATETIME_PRECISION, CT_MAX_DATETIME_PRECISION);
                return CT_ERROR;
            }
        } else if (CT_IS_UNKNOWN_TYPE(TREE_DATATYPE(arg)) && TREE_IS_BINDING_PARAM(arg)) {
            precision = CT_DEFAULT_DATETIME_PRECISION;
        } else {
            CT_SRC_THROW_ERROR(func->loc, ERR_INVALID_FUNC_PARAMS, "integer argument required");
            return CT_ERROR;
        }
    }

    if (verif->stmt->session->call_version >= CS_VERSION_8) {
        func->datatype = CT_TYPE_TIMESTAMP_TZ;
        func->size = CT_TIMESTAMP_TZ_SIZE;
    } else {
        func->datatype = CT_TYPE_TIMESTAMP_TZ_FAKE;
        func->size = CT_TIMESTAMP_SIZE;
    }
    verif->stmt->context->unsinkable = CT_TRUE;
    func->precision = (uint8)precision;
    sql_add_first_exec_node(verif, func);
    return CT_SUCCESS;
}

status_t sql_func_current_timestamp(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    int32 prec = CT_MAX_DATETIME_PRECISION;
    variant_t var;
    CM_POINTER3(stmt, func, res);

    expr_tree_t *arg = func->argument;

    if (arg != NULL) {
        SQL_EXEC_FUNC_ARG_EX(arg, &var, res);

        if (CT_IS_INTEGER_TYPE(var.type)) {
            prec = VALUE(int32, &var);
        } else {
            CT_SRC_THROW_ERROR(func->loc, ERR_INVALID_FUNC_PARAMS, "integer argument required");
            return CT_ERROR;
        }
    }

    if (prec < CT_MIN_DATETIME_PRECISION || prec > CT_MAX_DATETIME_PRECISION) {
        CT_SRC_THROW_ERROR_EX(func->loc, ERR_SQL_SYNTAX_ERROR, "fraction must between %d and %d. ",
            CT_MIN_DATETIME_PRECISION, CT_MAX_DATETIME_PRECISION);
        return CT_ERROR;
    }

    SQL_GET_STMT_SYSTIMESTAMP(stmt, res);
    if (stmt->session->call_version >= CS_VERSION_8) {
        res->type = CT_TYPE_TIMESTAMP_TZ;
        /* adjust with the session time zone */
        res->v_tstamp_tz.tstamp =
            cm_adjust_date_between_two_tzs(stmt->v_systimestamp, g_timer()->tz, sql_get_session_timezone(stmt));
        res->v_tstamp_tz.tz_offset = sql_get_session_timezone(stmt);
    } else {
        res->type = CT_TYPE_TIMESTAMP_TZ_FAKE;
    }
    res->is_null = CT_FALSE;

    return cm_adjust_timestamp_tz(&res->v_tstamp_tz, prec);
}

static status_t sql_func_extract_date(interval_unit_t unit, date_t v_date, variant_t *res)
{
    dec8_t dec;
    date_detail_t dt;
    cm_decode_date(v_date, &dt);
    res->type = CT_TYPE_INTEGER;
    res->is_null = CT_FALSE;

    switch (unit) {
        case IU_YEAR:
            res->v_int = dt.year;
            break;

        case IU_MONTH:
            res->v_int = dt.mon;
            break;

        case IU_DAY:
            res->v_int = dt.day;
            break;

        case IU_HOUR:
            res->v_int = dt.hour;
            break;

        case IU_MINUTE:
            res->v_int = dt.min;
            break;

        case IU_SECOND:
            res->v_bigint =
                (int64)dt.sec * MICROSECS_PER_SECOND + (int64)dt.millisec * MILLISECS_PER_SECOND + dt.microsec;
            cm_int64_to_dec(res->v_bigint, &dec);
            (void)cm_dec_div_int64(&dec, MICROSECS_PER_SECOND, &res->v_dec);
            res->type = CT_TYPE_NUMBER;
            break;

        default:
            CT_THROW_ERROR(ERR_INVALID_FUNC_PARAMS, "invalid extract field for extract source");
            return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t sql_func_extract_interval(interval_unit_t unit, variant_t *itvl_var, variant_t *res)
{
    dec8_t dec;
    interval_detail_t dt;

    res->type = CT_TYPE_INTEGER;
    res->is_null = CT_FALSE;

    if (itvl_var->type == CT_TYPE_INTERVAL_YM) {
        cm_decode_yminterval(itvl_var->v_itvl_ym, &dt);

        if (unit == IU_YEAR) {
            res->v_int = dt.year;
        } else if (unit == IU_MONTH) {
            res->v_int = dt.mon;
        } else {
            CT_THROW_ERROR(ERR_INVALID_FUNC_PARAMS, "invalid extract field for extract source");
            return CT_ERROR;
        }
    } else {
        cm_decode_dsinterval(itvl_var->v_itvl_ds, &dt);

        switch (unit) {
            case IU_DAY:
                res->v_int = dt.day;
                break;
            case IU_HOUR:
                res->v_int = dt.hour;
                break;
            case IU_MINUTE:
                res->v_int = dt.min;
                break;
            case IU_SECOND:
                res->v_bigint = (int64)dt.sec * MICROSECS_PER_SECOND + dt.fsec;
                cm_int64_to_dec(res->v_bigint, &dec);
                CT_RETURN_IFERR(cm_dec_div_int64(&dec, MICROSECS_PER_SECOND, &res->v_dec));
                if (dt.is_neg) {
                    cm_dec_negate(&res->v_dec);
                }
                res->type = CT_TYPE_NUMBER;
                return CT_SUCCESS;
            default:
                CT_THROW_ERROR(ERR_INVALID_FUNC_PARAMS, "invalid extract field for extract source");
                return CT_ERROR;
        }
    }
    if (dt.is_neg) {
        res->v_int = -res->v_int;
    }
    return CT_SUCCESS;
}

status_t sql_func_extract(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    expr_tree_t *arg_unit = NULL;
    expr_tree_t *arg_date = NULL;
    variant_t unit_var, date_var;

    CM_POINTER2(func, res);

    // get datetime unit
    arg_unit = func->argument;
    CM_POINTER(arg_unit);
    SQL_EXEC_FUNC_ARG_EX(arg_unit, &unit_var, res);

    // get date or interval
    arg_date = arg_unit->next;
    CM_POINTER(arg_date);
    SQL_EXEC_FUNC_ARG_EX(arg_date, &date_var, res);

    if (sql_match_interval_type(date_var.type)) {
        return sql_func_extract_interval(unit_var.v_itvl_unit_id, &date_var, res);
    } else if (var_as_timestamp_flex(&date_var) == CT_SUCCESS) {
        return sql_func_extract_date(unit_var.v_itvl_unit_id, date_var.v_date, res);
    } else {
        cm_set_error_loc(arg_date->loc);
        return CT_ERROR;
    }
}

static status_t sql_verify_datetime_unit(sql_verifier_t *verif, expr_node_t *unit_node)
{
    word_t word;
    word.text = unit_node->word.column.name;

    if (!lex_match_datetime_unit(&word)) {
        CT_SRC_THROW_ERROR(word.text.loc, ERR_INVALID_FUNC_PARAMS, "datetime unit expected");
        return CT_ERROR;
    }

    unit_node->type = EXPR_NODE_CONST;
    unit_node->datatype = CT_TYPE_ITVL_UNIT;
    unit_node->value.type = CT_TYPE_ITVL_UNIT;
    unit_node->value.v_itvl_unit_id = word.id;
    SQL_SET_OPTMZ_MODE(unit_node, OPTIMIZE_AS_CONST);

    return CT_SUCCESS;
}

status_t sql_verify_extract(sql_verifier_t *verif, expr_node_t *func)
{
    expr_tree_t *unit_arg = NULL;
    expr_tree_t *date_arg = NULL;
    CM_POINTER2(verif, func);

    // verify datetime unit node
    unit_arg = func->argument;
    if (unit_arg == NULL || unit_arg->next == NULL) {
        CT_SRC_THROW_ERROR(func->loc, ERR_INVALID_FUNC_PARAM_COUNT, T2S(&func->word.func.name), 2, 2);
        return CT_ERROR;
    }
    CT_RETURN_IFERR(sql_verify_datetime_unit(verif, unit_arg->root));

    // verify date or interval expr node
    date_arg = unit_arg->next;
    if (date_arg->next != NULL) {
        CT_SRC_THROW_ERROR(func->loc, ERR_INVALID_FUNC_PARAM_COUNT, T2S(&func->word.func.name), 2, 2);
        return CT_ERROR;
    }
    CT_RETURN_IFERR(sql_verify_expr_node(verif, date_arg->root));
    if (!(sql_match_interval_type(TREE_DATATYPE(date_arg)) || sql_match_datetime_type(TREE_DATATYPE(date_arg)))) {
        CT_SRC_ERROR_REQUIRE_DATETIME(date_arg->loc, TREE_DATATYPE(date_arg));
        return CT_ERROR;
    }

    func->datatype = (EXPR_VALUE(int32, unit_arg) == IU_SECOND) ? CT_TYPE_NUMBER : CT_TYPE_INTEGER;
    func->size = (func->datatype == CT_TYPE_INTEGER) ? sizeof(int32) : sizeof(dec8_t);
    return CT_SUCCESS;
}

status_t sql_func_from_tz(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    variant_t date_var, tz_var;
    timezone_info_t tz_info;
    CM_POINTER3(stmt, func, res);

    // check timestamp.
    expr_tree_t *arg_date = func->argument;
    CM_POINTER(arg_date);
    sql_exec_expr(stmt, arg_date, &date_var);
    SQL_CHECK_COLUMN_VAR(&date_var, res);

    if (date_var.is_null) {
        CT_SET_ERROR_MISMATCH(CT_TYPE_TIMESTAMP, date_var.type);
        return CT_ERROR;
    }
    sql_keep_stack_variant(stmt, &date_var);
    if (date_var.type != CT_TYPE_TIMESTAMP) {
        CT_SET_ERROR_MISMATCH(CT_TYPE_TIMESTAMP, date_var.type);
        return CT_ERROR;
    }

    // check tz.
    SQL_EXEC_FUNC_ARG_EX(arg_date->next, &tz_var, res);
    sql_keep_stack_variant(stmt, &tz_var);

    if (!CT_IS_STRING_TYPE(tz_var.type)) {
        CT_SET_ERROR_MISMATCH(CT_TYPE_CHAR, tz_var.type);
        return CT_ERROR;
    }
    if (cm_text2tzoffset(&tz_var.v_text, &tz_info) != CT_SUCCESS) {
        return CT_ERROR;
    }

    res->is_null = CT_FALSE;
    res->type = CT_TYPE_TIMESTAMP_TZ;
    res->v_tstamp_tz.tstamp = date_var.v_tstamp;
    res->v_tstamp_tz.tz_offset = tz_info;

    return CT_SUCCESS;
}

status_t sql_verify_from_tz(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);
    expr_tree_t *arg = func->argument;

    CT_RETURN_IFERR(sql_verify_func_node(verf, func, 2, 2, CT_INVALID_ID32));

    if (arg->root->datatype != CT_TYPE_TIMESTAMP && arg->root->datatype != CT_TYPE_UNKNOWN) {
        CT_SET_ERROR_MISMATCH(CT_TYPE_TIMESTAMP, arg->root->datatype);
        return CT_ERROR;
    }

    arg = arg->next;
    if (!CT_IS_STRING_TYPE(arg->root->datatype) && arg->root->datatype != CT_TYPE_UNKNOWN) {
        CT_SET_ERROR_MISMATCH(CT_TYPE_CHAR, arg->root->datatype);
        return CT_ERROR;
    }

    func->precision = CT_DEFAULT_DATETIME_PRECISION;
    func->datatype = CT_TYPE_TIMESTAMP_TZ;
    func->size = sizeof(timestamp_tz_t);
    return CT_SUCCESS;
}

status_t sql_verify_from_unixtime(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 1, 2, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    const expr_tree_t *arg = func->argument;

    if (!sql_match_numeric_type(TREE_DATATYPE(arg))) {
        CT_SRC_ERROR_REQUIRE_NUMERIC(arg->loc, TREE_DATATYPE(arg));
        return CT_ERROR;
    }

    arg = arg->next;
    if (arg != NULL && !sql_match_string_type(TREE_DATATYPE(arg))) {
        CT_SRC_ERROR_REQUIRE_STRING(arg->loc, TREE_DATATYPE(arg));
        return CT_ERROR;
    }

    if (arg != NULL) {
        func->datatype = CT_TYPE_VARCHAR;
    } else {
        func->datatype = CT_TYPE_TIMESTAMP;
    }
    func->precision = CT_MAX_DATETIME_PRECISION;
    func->size = cm_get_datatype_strlen(func->argument->root->datatype, func->argument->root->size);

    return CT_SUCCESS;
}

status_t sql_func_from_unixtime(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    variant_t unix_ts_var, fmt_var;
    timestamp_t tmp_tstamp;

    expr_tree_t *arg1 = func->argument;
    SQL_EXEC_FUNC_ARG_EX(arg1, &unix_ts_var, res);
    CT_RETURN_IFERR(var_as_decimal(&unix_ts_var));

    if (CT_SUCCESS != var_to_unix_timestamp(&unix_ts_var.v_dec, &res->v_tstamp, SESSION_TIME_ZONE(stmt->session))) {
        return CT_ERROR;
    }

    expr_tree_t *arg2 = arg1->next;
    if (arg2 == NULL) {
        res->type = CT_TYPE_TIMESTAMP;
    } else {
        tmp_tstamp = res->v_tstamp;
        SQL_EXEC_FUNC_ARG_EX(arg2, &fmt_var, res);
        CT_RETURN_IFERR(sql_push(stmt, CT_MAX_NUMBER_LEN, (void **)&res->v_text.str));
        res->v_text.len = 0;
        CT_RETURN_IFERR(cm_timestamp2text(tmp_tstamp, &fmt_var.v_text, &res->v_text, CT_MAX_NUMBER_LEN));
        res->type = CT_TYPE_VARCHAR;
    }
    res->is_null = CT_FALSE;
    return CT_SUCCESS;
}

status_t sql_verify_utcdate(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    CT_RETURN_IFERR(sql_verify_func_node(verf, func, 0, 0, CT_INVALID_ID32));

    func->datatype = CT_TYPE_TIMESTAMP_TZ;
    func->size = sizeof(timestamp_tz_t);
    func->precision = CT_DEFAULT_DATETIME_PRECISION;
    sql_add_first_exec_node(verf, func);
    return CT_SUCCESS;
}

status_t sql_func_utcdate(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    int32 prec = CT_DEFAULT_DATETIME_PRECISION;
    date_t dt_utc_now = CM_UNIX_EPOCH;
    timeval_t tv;
    (void)cm_gettimeofday(&tv);
    dt_utc_now += ((int64)tv.tv_sec * MICROSECS_PER_SECOND + tv.tv_usec);

    res->v_tstamp_tz.tstamp = (timestamp_t)dt_utc_now;
    res->v_tstamp_tz.tz_offset = 0;
    res->is_null = CT_FALSE;
    res->type = CT_TYPE_TIMESTAMP_TZ;

    return cm_adjust_timestamp_tz(&res->v_tstamp_tz, prec);
}

status_t sql_func_last_day(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    variant_t date_var;
    date_detail_t time_desc;

    CM_POINTER2(func, res);

    expr_tree_t *arg = func->argument;
    CM_POINTER(arg);
    SQL_EXEC_FUNC_ARG_EX(arg, &date_var, res);
    if (var_as_date(SESSION_NLS(stmt), &date_var) != CT_SUCCESS) {
        cm_set_error_loc(arg->loc);
        return CT_ERROR;
    }

    cm_decode_date(date_var.v_date, &time_desc);
    time_desc.day = (uint8)CM_MONTH_DAYS(time_desc.year, time_desc.mon);
    res->is_null = CT_FALSE;
    res->type = date_var.type;
    res->v_date = cm_encode_date(&time_desc);

    return CT_SUCCESS;
}

status_t sql_verify_last_day(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);
    if (sql_verify_func_node(verf, func, 1, 1, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    expr_tree_t *date_arg = func->argument;
    if (!sql_match_datetime_type(TREE_DATATYPE(date_arg))) {
        CT_SRC_ERROR_REQUIRE_DATETIME(date_arg->loc, TREE_DATATYPE(date_arg));
        return CT_ERROR;
    }
    func->datatype = CT_TYPE_DATE;
    func->size = CT_DATE_SIZE;
    return CT_SUCCESS;
}

status_t sql_verify_localtimestamp(sql_verifier_t *verf, expr_node_t *func)
{
    int32 precision = CT_DEFAULT_DATETIME_PRECISION;
    CM_POINTER2(verf, func);

    expr_tree_t *arg = func->argument;
    if (arg != NULL) {
        if (CT_IS_INTEGER_TYPE(arg->root->value.type) && TREE_IS_CONST(arg)) {
            precision = VALUE(int32, &arg->root->value);
        } else {
            CT_SRC_THROW_ERROR(arg->loc, ERR_INVALID_FUNC_PARAMS, "integer argument required");
            return CT_ERROR;
        }
    }

    CT_RETURN_IFERR(sql_verify_func_node(verf, func, 0, 1, CT_INVALID_ID32));
    verf->stmt->context->unsinkable = CT_TRUE;
    func->datatype = CT_TYPE_TIMESTAMP;
    func->size = CT_TIMESTAMP_SIZE;
    func->precision = (uint8)precision;
    sql_add_first_exec_node(verf, func);
    return CT_SUCCESS;
}

status_t sql_func_localtimestamp(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    int32 prec = CT_MAX_DATETIME_PRECISION;
    variant_t var;
    CM_POINTER3(stmt, func, res);

    expr_tree_t *arg = func->argument;

    if (arg != NULL) {
        SQL_EXEC_FUNC_ARG_EX(arg, &var, res);

        if (CT_IS_INTEGER_TYPE(var.type)) {
            prec = VALUE(int32, &var);
        } else {
            CT_SRC_THROW_ERROR(arg->loc, ERR_INVALID_FUNC_PARAMS, "integer argument required");
            return CT_ERROR;
        }
    }

    if (prec < CT_MIN_DATETIME_PRECISION || prec > CT_MAX_DATETIME_PRECISION) {
        CT_SRC_THROW_ERROR_EX(arg->loc, ERR_SQL_SYNTAX_ERROR, "integer argument must between %d and %d. ",
            CT_MIN_DATETIME_PRECISION, CT_MAX_DATETIME_PRECISION);
        return CT_ERROR;
    }

    SQL_GET_STMT_SYSTIMESTAMP(stmt, res);
    res->type = CT_TYPE_TIMESTAMP;
    res->is_null = CT_FALSE;
    /* adjust with the session time zone */
    res->v_tstamp =
        cm_adjust_date_between_two_tzs(stmt->v_systimestamp, g_timer()->tz, sql_get_session_timezone(stmt));

    return cm_adjust_timestamp(&res->v_tstamp, prec);
}

static status_t sql_func_months_between_core(date_t date1, date_t date2, variant_t *res)
{
    date_detail_t date_desc1, date_desc2;
    int32 year, mon, day, diff_mons;
    int64 diff_secs;
    bool32 last_mon_day;
    dec8_t dec1, dec2;

    cm_decode_date(date1, &date_desc1);
    cm_decode_date(date2, &date_desc2);

    year = (int32)((int32)date_desc1.year - (int32)date_desc2.year);
    mon = (int32)((int32)date_desc1.mon - (int32)date_desc2.mon);
    day = (int32)((int32)date_desc1.day - (int32)date_desc2.day);

    diff_mons = CT_MONTH_PER_YEAR * year + mon;

    last_mon_day = (sql_is_last_month_day(&date_desc1) && sql_is_last_month_day(&date_desc2));
    if ((day == 0) || last_mon_day) {
        cm_int32_to_dec(diff_mons, &res->v_dec);
    } else {
        /*
           Oracle calculates the fractional portion of the result based on a 31-day month
        */
        diff_secs = (int64)day * (int64)CT_SEC_PER_DAY;
        diff_secs += ((int32)date_desc1.hour - (int32)date_desc2.hour) * CT_SEC_PER_HOUR;
        diff_secs += ((int32)date_desc1.min - (int32)date_desc2.min) * CT_SEC_PER_MIN;
        diff_secs += ((int32)date_desc1.sec - (int32)date_desc2.sec);
        // convert to decimal for high precision
        cm_int64_to_dec(diff_secs, &dec1);
        CT_RETURN_IFERR(cm_dec_div_int64(&dec1, (int64)CT_SEC_PER_DAY * CT_DAY_PER_MONTH, &dec2));
        CT_RETURN_IFERR(cm_dec_add_int64(&dec2, (int64)diff_mons, &res->v_dec));
    }
    res->is_null = CT_FALSE;
    res->type = CT_TYPE_NUMBER;
    return CT_SUCCESS;
}

status_t sql_func_months_between(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    variant_t date_var1, date_var2;

    CM_POINTER2(func, res);

    // get date1
    expr_tree_t *arg_date1 = func->argument;
    CM_POINTER(arg_date1);
    SQL_EXEC_FUNC_ARG_EX(arg_date1, &date_var1, res);

    if (var_as_timestamp_flex(&date_var1) != CT_SUCCESS) {
        cm_set_error_loc(arg_date1->loc);
        return CT_ERROR;
    }

    // get date2
    expr_tree_t *arg_date2 = arg_date1->next;
    CM_POINTER(arg_date2);
    SQL_EXEC_FUNC_ARG_EX(arg_date2, &date_var2, res);

    if (var_as_timestamp_flex(&date_var2) != CT_SUCCESS) {
        cm_set_error_loc(arg_date2->loc);
        return CT_ERROR;
    }

    return sql_func_months_between_core(date_var1.v_date, date_var2.v_date, res);
}
status_t sql_verify_months_between(sql_verifier_t *verifier, expr_node_t *func)
{
    /* *
     * MONTHS_BETWEEN(date1, date2)
     * \brief Returns number of months between date1 and date2 (date1-date2).
     * \param date1: date or datetime expression
     * \param date2: date or datetime expression
     */
    CM_POINTER2(verifier, func);

    CT_RETURN_IFERR(sql_verify_func_node(verifier, func, 2, 2, CT_INVALID_ID32));

    expr_tree_t *date_arg1 = func->argument;
    if (!sql_match_datetime_type(TREE_DATATYPE(date_arg1))) {
        CT_SRC_ERROR_REQUIRE_DATETIME(date_arg1->loc, TREE_DATATYPE(date_arg1));
        return CT_ERROR;
    }

    expr_tree_t *date_arg2 = date_arg1->next;
    if (!sql_match_datetime_type(TREE_DATATYPE(date_arg2))) {
        CT_SRC_ERROR_REQUIRE_DATETIME(date_arg2->loc, TREE_DATATYPE(date_arg2));
        return CT_ERROR;
    }
    // need ajust by result
    func->datatype = CT_TYPE_NUMBER;
    func->size = (uint16)MAX_DEC_BYTE_SZ;
    return CT_SUCCESS;
}

status_t sql_func_next_day(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    variant_t date_var, week_var;
    date_detail_t time_desc;
    date_detail_ex_t detail_ex;
    expr_tree_t *arg1 = func->argument;
    CM_POINTER2(func, res);
    CM_POINTER(arg1);
    SQL_EXEC_FUNC_ARG_EX(arg1, &date_var, res);
    if (var_as_date(SESSION_NLS(stmt), &date_var) != CT_SUCCESS) {
        cm_set_error_loc(arg1->loc);
        return CT_ERROR;
    }
    cm_decode_date(date_var.v_date, &time_desc);
    cm_get_detail_ex(&time_desc, &detail_ex);
    uint8 start_week_day = detail_ex.day_of_week;

    expr_tree_t *arg2 = arg1->next;
    CM_POINTER(arg2);
    SQL_EXEC_FUNC_ARG_EX(arg2, &week_var, res);

    uint8 end_week_day;
    if (sql_match_string_type((ct_type_t)week_var.type)) {
        cm_trim_text(&week_var.v_text);
        if (!cm_str2week(&week_var.v_text, &end_week_day)) {
            CT_THROW_ERROR(ERR_INVALID_PARAMETER, "of second column");
            return CT_ERROR;
        }
    } else {
        var_as_floor_integer(&week_var);
        if (week_var.v_int < 1 || week_var.v_int > (int32)DAYS_PER_WEEK) {
            CT_THROW_ERROR(ERR_INVALID_PARAMETER, "of second column");
            return CT_ERROR;
        } else {
            end_week_day = (uint8)(week_var.v_int - 1);
        }
    }

    if (end_week_day > start_week_day) {
        CT_RETURN_IFERR(cm_date_add_days(date_var.v_date, (double)(end_week_day - start_week_day), &res->v_date));
    } else {
        CT_RETURN_IFERR(cm_date_add_days(date_var.v_date, (double)(DAYS_PER_WEEK + end_week_day - start_week_day),
            &res->v_date));
    }

    res->is_null = CT_FALSE;
    res->type = date_var.type;
    return CT_SUCCESS;
}

status_t sql_verify_next_day(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 2, 2, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    expr_tree_t *date_arg = func->argument;
    if (!sql_match_datetime_type(TREE_DATATYPE(date_arg))) {
        CT_SRC_ERROR_REQUIRE_DATETIME(date_arg->loc, TREE_DATATYPE(date_arg));
        return CT_ERROR;
    }
    expr_tree_t *week_arg = date_arg->next;
    if (week_arg != NULL) {
        if (!sql_match_num_and_str_type(TREE_DATATYPE(week_arg))) {
            CT_SRC_ERROR_REQUIRE_NUM_OR_STR(week_arg->loc, TREE_DATATYPE(week_arg));
            return CT_ERROR;
        }
    }

    func->datatype = CT_TYPE_DATE;
    func->size = CT_DATE_SIZE;
    return CT_SUCCESS;
}

status_t sql_func_sys_timestamp(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    int32 prec = CT_MAX_DATETIME_PRECISION;
    CM_POINTER3(stmt, func, result);

    SQL_GET_STMT_SYSTIMESTAMP(stmt, result);
    if (stmt->session->call_version >= CS_VERSION_8) {
        result->type = CT_TYPE_TIMESTAMP_TZ;
        /* adjust with the os time zone */
        result->v_tstamp_tz.tz_offset = g_timer()->tz;
    } else {
        result->type = CT_TYPE_TIMESTAMP_TZ_FAKE;
    }
    result->is_null = CT_FALSE;

    if (func->argument != NULL) {
        prec = VALUE(int32, &func->argument->root->value);
    }

    return cm_adjust_timestamp_tz(&result->v_tstamp_tz, prec);
}

static status_t sql_func_timestampadd_core(interval_unit_t unit, int64 itvl, date_t *date)
{
    date_t new_dt = *date;
    date_detail_t time_desc;
    uint8 day;

    switch (unit) {
        case IU_YEAR: {
            cm_decode_date(*date, &time_desc);
            day = time_desc.day;
            CT_RETURN_IFERR(sql_func_add_months_core((int32)itvl * 12, &time_desc));
            if (day < time_desc.day) {
                time_desc.day = day;
            }
            (*date) = cm_encode_date(&time_desc);
            return CT_SUCCESS;
        }
        case IU_QUARTER: {
            cm_decode_date(*date, &time_desc);
            day = time_desc.day;
            CT_RETURN_IFERR(sql_func_add_months_core((int32)itvl * 3, &time_desc));
            if (day < time_desc.day) {
                time_desc.day = day;
            }
            (*date) = cm_encode_date(&time_desc);
            return CT_SUCCESS;
        }
        case IU_MONTH: {
            cm_decode_date(*date, &time_desc);
            day = time_desc.day;
            CT_RETURN_IFERR(sql_func_add_months_core((int32)itvl, &time_desc));
            if (day < time_desc.day) {
                time_desc.day = day;
            }
            (*date) = cm_encode_date(&time_desc);
            return CT_SUCCESS;
        }

        case IU_WEEK:
            new_dt += (date_t)(itvl * UNITS_PER_DAY * 7);
            break;

        case IU_DAY:
            new_dt += (date_t)(itvl * UNITS_PER_DAY);
            break;

        case IU_HOUR:
            new_dt += (date_t)(itvl * SECONDS_PER_HOUR * MICROSECS_PER_SECOND);
            break;

        case IU_MINUTE:
            new_dt += (date_t)(itvl * SECONDS_PER_MIN * MICROSECS_PER_SECOND);
            break;

        case IU_SECOND:
            new_dt += (date_t)(itvl * MICROSECS_PER_SECOND);
            break;

        case IU_MICROSECOND:
            new_dt += itvl;
            break;

        default:
            CT_THROW_ERROR(ERR_INVALID_FUNC_PARAMS, "invalid UNIT");
            return CT_ERROR;
    }

    if (CM_IS_DATETIME_ADDTION_OVERFLOW(*date, itvl, new_dt)) {
        CT_SET_ERROR_DATETIME_OVERFLOW();
        return CT_ERROR;
    }
    (*date) = new_dt;
    return CT_SUCCESS;
}

status_t sql_func_sys_extract_utc(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    CM_POINTER3(stmt, func, res);
    variant_t time_var;
    expr_tree_t *arg_time = func->argument;
    timezone_info_t tz_offset = cm_get_session_time_zone(SESSION_NLS(stmt));
    SQL_EXEC_FUNC_ARG_EX(arg_time, &time_var, res);
    if (!sql_match_timestamp(time_var.type) || time_var.type == CT_TYPE_UNKNOWN) {
        CT_SRC_THROW_ERROR(func->loc, ERR_INVALID_FUNC_PARAMS, "timestamp argument required");
        return CT_ERROR;
    }
    if (time_var.type == CT_TYPE_TIMESTAMP_TZ) {
        tz_offset = time_var.v_tstamp_tz.tz_offset;
    }
    if (var_as_timestamp(SESSION_NLS(stmt), &time_var) != CT_SUCCESS) {
        cm_set_error_loc(arg_time->loc);
        return CT_ERROR;
    }
    tz_offset = -tz_offset;
    if (sql_func_timestampadd_core(IU_MINUTE, (int64)tz_offset, &time_var.v_tstamp) != CT_SUCCESS) {
        cm_set_error_loc(func->loc);
        return CT_ERROR;
    }
    res->v_tstamp = time_var.v_tstamp;
    res->type = CT_TYPE_TIMESTAMP;
    res->is_null = CT_FALSE;
    return CT_SUCCESS;
}

status_t sql_verify_sys_extract_utc(sql_verifier_t *verf, expr_node_t *func)
{
    if (sql_verify_func_node(verf, func, 1, 1, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }
    expr_tree_t *arg = func->argument;

    if (!sql_match_timestamp(TREE_DATATYPE(arg))) {
        CT_SRC_THROW_ERROR(func->loc, ERR_INVALID_FUNC_PARAMS, "timestamp argument required");
        return CT_ERROR;
    }
    func->datatype = CT_TYPE_TIMESTAMP;
    func->precision = CT_DEFAULT_DATETIME_PRECISION;
    func->size = CT_TIMESTAMP_SIZE;
    return CT_SUCCESS;
}

status_t sql_verify_to_date(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 1, 2, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    ct_type_t arg1_type = sql_get_func_arg1_datatype(func);
    if (!sql_match_num_and_str_type(arg1_type)) {
        CT_SRC_THROW_ERROR(func->argument->loc, ERR_INVALID_FUNC_PARAMS, "string or number argument expected");
        return CT_ERROR;
    }

    func->datatype = CT_TYPE_DATE;
    func->size = CT_DATE_SIZE;

    sql_infer_func_optmz_mode(verf, func);

    // merely has one constant argument
    if (func->value.v_func.arg_cnt == 1 && NODE_IS_OPTMZ_CONST(func)) {
        sql_add_first_exec_node(verf, func);
    }

    return CT_SUCCESS;
}

static status_t sql_func_to_date_core(sql_stmt_t *stmt, expr_node_t *func, variant_t *result, bool32 is_to_date)
{
    variant_t var1, fmt_var;
    CM_POINTER3(stmt, func, result);

    expr_tree_t *arg1 = func->argument; // argument string value
    CM_POINTER(arg1);
    SQL_EXEC_FUNC_ARG_EX(arg1, &var1, result);

    if (is_to_date) {
        if (!sql_match_num_and_str_type(var1.type)) {
            CT_SRC_THROW_ERROR(arg1->loc, ERR_INVALID_FUNC_PARAMS, "string or number argument expected");
            return CT_ERROR;
        }

        if (!CT_IS_STRING_TYPE(var1.type)) {
            if (sql_var_as_string(stmt, &var1) != CT_SUCCESS) {
                cm_set_error_loc(arg1->loc);
                return CT_ERROR;
            }
        }
    } else {
        if (!CT_IS_STRING_TYPE(var1.type)) {
            CT_SRC_THROW_ERROR(arg1->loc, ERR_INVALID_FUNC_PARAMS, "string argument expected");
            return CT_ERROR;
        }
    }

    expr_tree_t *arg2 = arg1->next; // argument format_string
    if (arg2 != NULL) {
        sql_keep_stack_variant(stmt, &var1);
        SQL_EXEC_FUNC_ARG_EX(arg2, &fmt_var, result);
        if (!CT_IS_STRING_TYPE(fmt_var.type)) {
            CT_SRC_THROW_ERROR(arg2->loc, ERR_INVALID_FUNC_PARAMS, "string argument expected");
            return CT_ERROR;
        }
    } else {
        sql_session_nlsparam_geter(stmt, is_to_date ? NLS_DATE_FORMAT : NLS_TIMESTAMP_FORMAT, &fmt_var.v_text);
    }

    result->is_null = CT_FALSE;
    result->type = CT_TYPE_DATE;

    if (cm_text2date_fixed(&var1.v_text, &fmt_var.v_text, &result->v_date) != CT_SUCCESS) {
        cm_set_error_loc(func->loc);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_func_to_date(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    return sql_func_to_date_core(stmt, func, result, CT_TRUE);
}

status_t sql_func_to_timestamp(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    if (sql_func_to_date_core(stmt, func, result, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (result->type != CT_TYPE_COLUMN) {
        result->type = CT_TYPE_TIMESTAMP;
    }
    return CT_SUCCESS;
}

status_t sql_verify_to_timestamp(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 1, 2, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    ct_type_t arg1_type = sql_get_func_arg1_datatype(func);
    if (!sql_match_string_type(arg1_type)) {
        CT_SRC_THROW_ERROR(func->argument->loc, ERR_INVALID_FUNC_PARAMS, "string argument expected");
        return CT_ERROR;
    }

    func->datatype = CT_TYPE_TIMESTAMP;
    func->size = CT_TIMESTAMP_SIZE;
    func->precision = CT_DEFAULT_DATETIME_PRECISION;

    sql_infer_func_optmz_mode(verf, func);

    // merely has one constant argument
    if (func->value.v_func.arg_cnt == 1 && NODE_IS_OPTMZ_CONST(func)) {
        sql_add_first_exec_node(verf, func);
    }

    return CT_SUCCESS;
}

status_t sql_func_timestampadd(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    variant_t unit_var, date_var, itvl_var;

    CM_POINTER2(func, res);

    // get interval unit
    expr_tree_t *arg_unit = func->argument;
    CM_POINTER(arg_unit);
    SQL_EXEC_FUNC_ARG_EX(arg_unit, &unit_var, res);

    // get interval
    expr_tree_t *arg_itvl = arg_unit->next;
    CM_POINTER(arg_itvl);
    SQL_EXEC_FUNC_ARG_EX(arg_itvl, &itvl_var, res);

    /*
      Convert second to microsecond
    */
    if (unit_var.v_itvl_unit_id == IU_SECOND) {
        // MySQL will truncate the part after microsecond,
        // Using REAL type will not result in loss of precision.
        CT_RETURN_IFERR(var_as_real(&itvl_var));
        itvl_var.v_bigint = (int64)(itvl_var.v_real * MICROSECS_PER_SECOND);
        itvl_var.type = CT_TYPE_BIGINT;
        unit_var.v_itvl_unit_id = IU_MICROSECOND;
    } else if (var_as_bigint(&itvl_var) != CT_SUCCESS) {
        cm_set_error_loc(arg_itvl->loc);
        return CT_ERROR;
    }

    if ((CT_IS_YM_UNIT(unit_var.v_itvl_unit_id) || CT_IS_DAY_UNIT(unit_var.v_itvl_unit_id)) &&
        (itvl_var.v_bigint > (int64)CM_MAX_DATE ||
        (itvl_var.v_bigint < (int64)CM_MIN_DATE && itvl_var.v_bigint != CM_ALL_ZERO_DATE))) {
        CT_SET_ERROR_TIMESTAMP_OVERFLOW();
        return CT_ERROR;
    }

    // get date
    expr_tree_t *arg_date = arg_itvl->next;
    CM_POINTER(arg_date);
    SQL_EXEC_FUNC_ARG_EX(arg_date, &date_var, res);

    if (var_as_timestamp_flex(&date_var) != CT_SUCCESS) {
        cm_set_error_loc(arg_date->loc);
        return CT_ERROR;
    }

    if (sql_func_timestampadd_core(unit_var.v_itvl_unit_id, itvl_var.v_bigint, &date_var.v_date) != CT_SUCCESS) {
        cm_set_error_loc(func->loc);
        return CT_ERROR;
    }

    res->is_null = CT_FALSE;
    res->type = CT_TYPE_TIMESTAMP;
    res->v_date = date_var.v_date;
    return CT_SUCCESS;
}

static status_t sql_verify_func_arg(sql_verifier_t *verf, expr_node_t *func, expr_tree_t *arg, bool32 is_required)
{
    if (arg == NULL) {
        if (is_required) {
            return CT_ERROR;
        }
        return CT_SUCCESS;
    }

    if (arg->root->type == EXPR_NODE_PRIOR) {
        CT_SRC_THROW_ERROR_EX(arg->loc, ERR_SQL_SYNTAX_ERROR, "prior must be in the condition of connect by");
        return CT_ERROR;
    }

    return sql_verify_expr_node(verf, arg->root);
}

status_t sql_verify_timestampadd(sql_verifier_t *verif, expr_node_t *func)
{
    /* *
     * TIMESTAMPADD(unit,interval,datetime_expr)
     * \brief Adds the integer expression interval to the date or datetime expression datetime_expr
     * \param unit:  MICROSECOND, SECOND, MINUTE, HOUR, DAY, WEEK, MONTH, QUARTER, or YEAR
     * \param interval: integer
     * \param datetime_expr: date or datetime expression
     */
    CM_POINTER2(verif, func);

    expr_tree_t *unit_arg = func->argument;
    if (unit_arg == NULL) {
        CT_SRC_THROW_ERROR(func->loc, ERR_INVALID_FUNC_PARAM_COUNT, T2S(&func->word.func.name), 3, 3);
        return CT_ERROR;
    }
    if (sql_verify_datetime_unit(verif, unit_arg->root) != CT_SUCCESS) {
        return CT_ERROR;
    }

    expr_tree_t *itvl_arg = unit_arg->next;
    if (itvl_arg == NULL) {
        CT_SRC_THROW_ERROR(func->loc, ERR_INVALID_FUNC_PARAM_COUNT, T2S(&func->word.func.name), 3, 3);
        return CT_ERROR;
    }
    CT_RETURN_IFERR(sql_verify_func_arg(verif, func, itvl_arg, CT_TRUE));
    if (!sql_match_numeric_type(TREE_DATATYPE(itvl_arg))) {
        CT_SRC_ERROR_REQUIRE_NUMERIC(itvl_arg->loc, TREE_DATATYPE(itvl_arg));
        return CT_ERROR;
    }

    expr_tree_t *date_arg = itvl_arg->next;
    if (date_arg == NULL) {
        CT_SRC_THROW_ERROR(func->loc, ERR_INVALID_FUNC_PARAM_COUNT, T2S(&func->word.func.name), 3, 3);
        return CT_ERROR;
    }
    CT_RETURN_IFERR(sql_verify_func_arg(verif, func, date_arg, CT_TRUE));
    if (!sql_match_datetime_type(TREE_DATATYPE(date_arg))) {
        CT_SRC_ERROR_REQUIRE_DATETIME(date_arg->loc, TREE_DATATYPE(date_arg));
        return CT_ERROR;
    }

    if (date_arg->next != NULL) {
        CT_SRC_THROW_ERROR(func->loc, ERR_INVALID_FUNC_PARAM_COUNT, T2S(&func->word.func.name), 3, 3);
        return CT_ERROR;
    }

    func->datatype = CT_TYPE_TIMESTAMP;
    func->precision = CT_DEFAULT_DATETIME_PRECISION;
    func->size = 8;
    return CT_SUCCESS;
}

// get the time that less than one day in micro sec
static inline int64 sql_get_time_parts_micro(date_t date)
{
    int64 micro_secs = date % UNITS_PER_DAY;
    if (micro_secs < 0) {
        micro_secs += UNITS_PER_DAY;
    }

    return micro_secs;
}

/**
 * \brief Calculate number of months between dates for TIMESTAMPDIFF
 * \param date1 cantian datetime value
 * \param date2 cantian datetime value
 * \returns number of months between dates date1 and date2 (date1-date2)
 */
static int32 sql_date_diff_months(date_t date1, date_t date2)
{
    date_detail_t date_desc1, date_desc2;
    int32 year, mon, day, diff_mons;
    int64 micro_secs;

    cm_decode_date(date1, &date_desc1);
    cm_decode_date(date2, &date_desc2);

    year = (int32)((int32)date_desc1.year - (int32)date_desc2.year);
    mon = (int32)((int32)date_desc1.mon - (int32)date_desc2.mon);
    day = (int32)((int32)date_desc1.day - (int32)date_desc2.day);
    micro_secs = sql_get_time_parts_micro(date1) - sql_get_time_parts_micro(date2);

    diff_mons = 12 * year + mon;

    if (diff_mons > 0) {
        diff_mons -= ((day < 0) || (day == 0 && micro_secs < 0)) ? 1 : 0;
    } else if (diff_mons < 0) {
        diff_mons += ((day > 0) || (day == 0 && micro_secs > 0)) ? 1 : 0;
    }
    return diff_mons;
}

status_t sql_func_timestampdiff(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    variant_t unit_var, date_var1, date_var2;

    CM_POINTER2(func, res);

    // get interval unit
    expr_tree_t *arg_unit = func->argument;
    SQL_EXEC_FUNC_ARG_EX(arg_unit, &unit_var, res);

    // get date1
    expr_tree_t *arg_date1 = arg_unit->next;
    SQL_EXEC_FUNC_ARG_EX(arg_date1, &date_var1, res);

    if (var_as_timestamp_flex(&date_var1) != CT_SUCCESS) {
        cm_set_error_loc(arg_date1->loc);
        return CT_ERROR;
    }

    // get date
    expr_tree_t *arg_date2 = arg_date1->next;
    SQL_EXEC_FUNC_ARG_EX(arg_date2, &date_var2, res);

    if (var_as_timestamp_flex(&date_var2) != CT_SUCCESS) {
        cm_set_error_loc(arg_date2->loc);
        return CT_ERROR;
    }

    switch (unit_var.v_itvl_unit_id) {
        case IU_YEAR:
            res->v_bigint = (int64)sql_date_diff_months(date_var2.v_date, date_var1.v_date);
            res->v_bigint /= 12;
            break;

        case IU_QUARTER:
            res->v_bigint = (int64)sql_date_diff_months(date_var2.v_date, date_var1.v_date);
            res->v_bigint /= 3;
            break;

        case IU_MONTH:
            res->v_bigint = (int64)sql_date_diff_months(date_var2.v_date, date_var1.v_date);
            break;

        case IU_WEEK:
            res->v_bigint = (int64)cm_date_diff_days(date_var2.v_date, date_var1.v_date);
            res->v_bigint /= 7;
            break;

        case IU_DAY:
            res->v_bigint = (int64)cm_date_diff_days(date_var2.v_date, date_var1.v_date);
            break;

        case IU_HOUR:
            res->v_bigint = (date_var2.v_date - date_var1.v_date) / SECONDS_PER_HOUR / MICROSECS_PER_SECOND;
            break;

        case IU_MINUTE:
            res->v_bigint = (date_var2.v_date - date_var1.v_date) / SECONDS_PER_MIN / MICROSECS_PER_SECOND;
            break;

        case IU_SECOND:
            res->v_bigint = (date_var2.v_date - date_var1.v_date) / MICROSECS_PER_SECOND;
            break;

        case IU_MICROSECOND:
            res->v_bigint = (date_var2.v_date - date_var1.v_date);
            break;

        default:
            CT_THROW_ERROR(ERR_INVALID_FUNC_PARAMS, "invalid UNIT");
            return CT_ERROR;
    }

    res->is_null = CT_FALSE;
    res->type = CT_TYPE_BIGINT;

    return CT_SUCCESS;
}

status_t sql_verify_timestampdiff(sql_verifier_t *verif, expr_node_t *func)
{
    uint32 arg_count;

    CM_POINTER2(verif, func);

    expr_tree_t *unit_arg = func->argument;
    if (unit_arg == NULL) {
        CT_SRC_THROW_ERROR(func->loc, ERR_INVALID_FUNC_PARAM_COUNT, T2S(&func->word.func.name), 3, 3);
        return CT_ERROR;
    }
    if (sql_verify_datetime_unit(verif, unit_arg->root) != CT_SUCCESS) {
        return CT_ERROR;
    }

    arg_count = 0;
    expr_tree_t *date_arg = unit_arg->next;
    while (date_arg != NULL) {
        arg_count++;

        if (arg_count > 2) {
            CT_SRC_THROW_ERROR(func->loc, ERR_INVALID_FUNC_PARAM_COUNT, T2S(&func->word.func.name), 3, 3);
            return CT_ERROR;
        }

        if (date_arg->root->type == EXPR_NODE_PRIOR) {
            CT_SRC_THROW_ERROR_EX(date_arg->loc, ERR_SQL_SYNTAX_ERROR, "prior must be in the condition of connect by");
            return CT_ERROR;
        }

        if (sql_verify_expr_node(verif, date_arg->root) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (!sql_match_datetime_type(TREE_DATATYPE(date_arg))) {
            CT_SRC_ERROR_REQUIRE_DATETIME(date_arg->loc, TREE_DATATYPE(date_arg));
            return CT_ERROR;
        }

        date_arg = date_arg->next;
    }

    if (arg_count < 2) {
        CT_SRC_THROW_ERROR(func->loc, ERR_INVALID_FUNC_PARAM_COUNT, T2S(&func->word.func.name), 3, 3);
        return CT_ERROR;
    }
    func->datatype = CT_TYPE_BIGINT;
    func->size = sizeof(int64);
    return CT_SUCCESS;
}

status_t sql_verify_unix_timestamp(sql_verifier_t *verf, expr_node_t *func)
{
    if (sql_verify_func_node(verf, func, 0, 1, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    expr_tree_t *arg = func->argument;
    // verify the first argument, which is a datetime or datetime string type
    if (arg != NULL && !sql_match_datetime_type(TREE_DATATYPE(arg))) {
        CT_SRC_ERROR_REQUIRE_DATETIME(arg->loc, TREE_DATATYPE(arg));
        return CT_ERROR;
    }

    func->datatype = CT_TYPE_BIGINT;
    func->size = CT_BIGINT_SIZE;
    return CT_SUCCESS;
}

status_t sql_func_unix_timestamp(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    res->type = CT_TYPE_BIGINT;
    res->is_null = CT_FALSE;

    timestamp_t ts_val;
    do {
        variant_t date_var;
        expr_tree_t *arg = func->argument;
        text_t fmt_text;
        if (arg == NULL) { // if no argument
            SQL_GET_STMT_SYSTIMESTAMP(stmt, res);
            res->v_bigint = cm_get_unix_timestamp(res->v_tstamp, CM_HOST_TIMEZONE);
            break;
        }
        // verify the first argument, which is a datetime or datetime string type
        SQL_EXEC_FUNC_ARG_EX(arg, &date_var, res);
        if (CT_IS_DATETIME_TYPE(date_var.type)) {
            ts_val = date_var.v_tstamp;
            res->v_bigint = cm_get_unix_timestamp(ts_val, SESSION_TIME_ZONE(stmt->session));
            break;
        }
        if (!CT_IS_STRING_TYPE(date_var.type)) {
            CT_SRC_ERROR_REQUIRE_DATETIME(arg->loc, TREE_DATATYPE(arg));
            return CT_ERROR;
        }

        sql_session_nlsparam_geter(stmt, NLS_TIMESTAMP_FORMAT, &fmt_text);

        if (cm_text2date(&date_var.v_text, &fmt_text, (date_t *)&ts_val) != CT_SUCCESS) {
            cm_set_error_loc(arg->loc);
            return CT_ERROR;
        }
        res->v_bigint = cm_get_unix_timestamp(ts_val, SESSION_TIME_ZONE(stmt->session));
    } while (0);

    if (res->v_bigint < CM_MIN_UTC || res->v_bigint > CM_MAX_UTC) {
        res->v_bigint = 0;
    }

    return CT_SUCCESS;
}

status_t sql_verify_utctimestamp(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);
    CT_RETURN_IFERR(sql_verify_func_node(verf, func, 0, 0, CT_INVALID_ID32));
    func->datatype = CT_TYPE_DATE;
    func->size = CT_DATE_SIZE;
    func->precision = CT_DEFAULT_DATETIME_PRECISION;
    sql_add_first_exec_node(verf, func);
    return CT_SUCCESS;
}

status_t sql_func_utctimestamp(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    res->v_date = cm_utc_now();
    res->is_null = CT_FALSE;
    res->type = CT_TYPE_DATE;
    return CT_SUCCESS;
}