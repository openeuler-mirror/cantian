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
 * func_date.c
 *
 *
 * IDENTIFICATION
 * src/cmd/function/func_date.c
 *
 * -------------------------------------------------------------------------
 */
#include "func_date.h"
#include "srv_instance.h"

static inline bool32 sql_is_last_month_day(date_detail_t *dt_detail)
{
    return (dt_detail->day == CM_MONTH_DAYS(dt_detail->year, dt_detail->mon));
}

static status_t sql_func_add_months_core(int32 temp_add_months, date_detail_t *time_desc)
{
    int32 year = time_desc->year;
    int32 mon = time_desc->mon;
    bool32 last_mon_day;
    int32 add_months = temp_add_months;

    // check whether time_desc is the last day of current mon
    last_mon_day = sql_is_last_month_day(time_desc);

    year += (add_months / 12);
    add_months %= 12;
    mon += add_months;

    if (mon > 12) {
        year++;
        mon -= 12;
    } else if (mon <= 0) {
        year--;
        mon += 12;
    }

    if (!CM_IS_VALID_YEAR(year)) {
        GS_THROW_ERROR(ERR_TYPE_OVERFLOW, "DATETIME");
        return GS_ERROR;
    }

    time_desc->year = (uint16)year;
    time_desc->mon = (uint8)mon;

    if (last_mon_day || (time_desc->day > CM_MONTH_DAYS(time_desc->year, time_desc->mon))) {
        time_desc->day = (uint8)CM_MONTH_DAYS(time_desc->year, time_desc->mon);
    }

    return GS_SUCCESS;
}

status_t sql_func_add_months(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t date_var, month_var;
    date_detail_t time_desc;

    CM_POINTER2(func, result);

    // get date_round
    expr_tree_t *arg1 = func->argument;
    CM_POINTER(arg1);
    SQL_EXEC_FUNC_ARG_EX(arg1, &date_var, result);
    if (var_as_date(SESSION_NLS(stmt), &date_var) != GS_SUCCESS) {
        cm_set_error_loc(arg1->loc);
        return GS_ERROR;
    }

    // get added months
    expr_tree_t *arg2 = arg1->next;
    CM_POINTER(arg2);
    SQL_EXEC_FUNC_ARG_EX(arg2, &month_var, result);

    if (var_as_floor_integer(&month_var) != GS_SUCCESS) {
        cm_set_error_loc(arg2->loc);
        return GS_ERROR;
    }

    cm_decode_date(date_var.v_date, &time_desc);
    if (sql_func_add_months_core(month_var.v_int, &time_desc) != GS_SUCCESS) {
        cm_set_error_loc(func->loc);
        return GS_ERROR;
    }

    result->is_null = GS_FALSE;
    result->type = date_var.type;
    result->v_date = cm_encode_date(&time_desc);

    return GS_SUCCESS;
}
status_t sql_verify_add_months(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 2, 2, GS_INVALID_ID32) != GS_SUCCESS) {
        return GS_ERROR;
    }

    expr_tree_t *date_arg = func->argument;
    if (!sql_match_datetime_type(TREE_DATATYPE(date_arg))) {
        GS_SRC_ERROR_REQUIRE_DATETIME(date_arg->loc, TREE_DATATYPE(date_arg));
        return GS_ERROR;
    }

    expr_tree_t *mon_arg = date_arg->next;
    if (!sql_match_numeric_type(TREE_DATATYPE(mon_arg))) {
        GS_SRC_ERROR_REQUIRE_NUMERIC(mon_arg->loc, TREE_DATATYPE(mon_arg));
        return GS_ERROR;
    }

    sql_infer_func_optmz_mode(verf, func);

    /* STRING type into a DATETIME type depends on the SESSION datetime format */
    if (GS_IS_STRING_TYPE(TREE_DATATYPE(date_arg)) && GS_IS_WEAK_NUMERIC_TYPE(TREE_DATATYPE(mon_arg)) &&
        NODE_IS_OPTMZ_CONST(func)) {
        sql_add_first_exec_node(verf, func);
    }

    func->datatype = GS_TYPE_DATE;
    func->size = GS_DATE_SIZE;
    return GS_SUCCESS;
}

status_t sql_verify_current_timestamp(sql_verifier_t *verf, expr_node_t *func)
{
    int32 precision = GS_DEFAULT_DATETIME_PRECISION;
    CM_POINTER2(verf, func);

    GS_RETURN_IFERR(sql_verify_func_node(verf, func, 0, 1, GS_INVALID_ID32));

    expr_tree_t *arg = func->argument;
    if (arg != NULL) {
        if (GS_IS_INTEGER_TYPE(TREE_DATATYPE(arg)) && TREE_IS_CONST(arg)) {
            precision = VALUE(int32, &arg->root->value);
            if (precision < GS_MIN_DATETIME_PRECISION || precision > GS_MAX_DATETIME_PRECISION) {
                GS_SRC_THROW_ERROR_EX(func->loc, ERR_SQL_SYNTAX_ERROR, "fraction must between %d and %d. ",
                    GS_MIN_DATETIME_PRECISION, GS_MAX_DATETIME_PRECISION);
                return GS_ERROR;
            }
        } else if (GS_IS_UNKNOWN_TYPE(TREE_DATATYPE(arg)) && TREE_IS_BINDING_PARAM(arg)) {
            precision = GS_DEFAULT_DATETIME_PRECISION;
        } else {
            GS_SRC_THROW_ERROR(func->loc, ERR_INVALID_FUNC_PARAMS, "integer argument required");
            return GS_ERROR;
        }
    }

    if (verf->stmt->session->call_version >= CS_VERSION_8) {
        func->datatype = GS_TYPE_TIMESTAMP_TZ;
        func->size = GS_TIMESTAMP_TZ_SIZE;
    } else {
        func->datatype = GS_TYPE_TIMESTAMP_TZ_FAKE;
        func->size = GS_TIMESTAMP_SIZE;
    }
    func->precision = (uint8)precision;
    sql_add_first_exec_node(verf, func);
    return GS_SUCCESS;
}

status_t sql_func_current_timestamp(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    int32 prec = GS_MAX_DATETIME_PRECISION;
    variant_t var;
    CM_POINTER3(stmt, func, result);

    expr_tree_t *arg = func->argument;

    if (arg != NULL) {
        SQL_EXEC_FUNC_ARG_EX(arg, &var, result);

        if (GS_IS_INTEGER_TYPE(var.type)) {
            prec = VALUE(int32, &var);
        } else {
            GS_SRC_THROW_ERROR(func->loc, ERR_INVALID_FUNC_PARAMS, "integer argument required");
            return GS_ERROR;
        }
    }

    if (prec < GS_MIN_DATETIME_PRECISION || prec > GS_MAX_DATETIME_PRECISION) {
        GS_SRC_THROW_ERROR_EX(func->loc, ERR_SQL_SYNTAX_ERROR, "fraction must between %d and %d. ",
            GS_MIN_DATETIME_PRECISION, GS_MAX_DATETIME_PRECISION);
        return GS_ERROR;
    }

    SQL_GET_STMT_SYSTIMESTAMP(stmt, result);
    if (stmt->session->call_version >= CS_VERSION_8) {
        result->type = GS_TYPE_TIMESTAMP_TZ;
        /* adjust with the session time zone */
        result->v_tstamp_tz.tstamp =
            cm_adjust_date_between_two_tzs(stmt->v_systimestamp, g_timer()->tz, sql_get_session_timezone(stmt));
        result->v_tstamp_tz.tz_offset = sql_get_session_timezone(stmt);
    } else {
        result->type = GS_TYPE_TIMESTAMP_TZ_FAKE;
    }
    result->is_null = GS_FALSE;

    return cm_adjust_timestamp_tz(&result->v_tstamp_tz, prec);
}

static status_t sql_func_extract_date(interval_unit_t unit, date_t v_date, variant_t *result)
{
    dec8_t dec;
    date_detail_t dt;
    cm_decode_date(v_date, &dt);
    result->type = GS_TYPE_INTEGER;
    result->is_null = GS_FALSE;

    switch (unit) {
        case IU_YEAR:
            result->v_int = dt.year;
            break;

        case IU_MONTH:
            result->v_int = dt.mon;
            break;

        case IU_DAY:
            result->v_int = dt.day;
            break;

        case IU_HOUR:
            result->v_int = dt.hour;
            break;

        case IU_MINUTE:
            result->v_int = dt.min;
            break;

        case IU_SECOND:
            result->v_bigint =
                (int64)dt.sec * MICROSECS_PER_SECOND + (int64)dt.millisec * MILLISECS_PER_SECOND + dt.microsec;
            cm_int64_to_dec(result->v_bigint, &dec);
            (void)cm_dec_div_int64(&dec, MICROSECS_PER_SECOND, &result->v_dec);
            result->type = GS_TYPE_NUMBER;
            break;

        default:
            GS_THROW_ERROR(ERR_INVALID_FUNC_PARAMS, "invalid extract field for extract source");
            return GS_ERROR;
    }
    return GS_SUCCESS;
}

static status_t sql_func_extract_interval(interval_unit_t unit, variant_t *itvl_var, variant_t *result)
{
    dec8_t dec;
    interval_detail_t dt;

    result->type = GS_TYPE_INTEGER;
    result->is_null = GS_FALSE;

    if (itvl_var->type == GS_TYPE_INTERVAL_YM) {
        cm_decode_yminterval(itvl_var->v_itvl_ym, &dt);

        if (unit == IU_YEAR) {
            result->v_int = dt.year;
        } else if (unit == IU_MONTH) {
            result->v_int = dt.mon;
        } else {
            GS_THROW_ERROR(ERR_INVALID_FUNC_PARAMS, "invalid extract field for extract source");
            return GS_ERROR;
        }
    } else {
        cm_decode_dsinterval(itvl_var->v_itvl_ds, &dt);

        switch (unit) {
            case IU_DAY:
                result->v_int = dt.day;
                break;
            case IU_HOUR:
                result->v_int = dt.hour;
                break;
            case IU_MINUTE:
                result->v_int = dt.min;
                break;
            case IU_SECOND:
                result->v_bigint = (int64)dt.sec * MICROSECS_PER_SECOND + dt.fsec;
                cm_int64_to_dec(result->v_bigint, &dec);
                GS_RETURN_IFERR(cm_dec_div_int64(&dec, MICROSECS_PER_SECOND, &result->v_dec));
                if (dt.is_neg) {
                    cm_dec_negate(&result->v_dec);
                }
                result->type = GS_TYPE_NUMBER;
                return GS_SUCCESS;
            default:
                GS_THROW_ERROR(ERR_INVALID_FUNC_PARAMS, "invalid extract field for extract source");
                return GS_ERROR;
        }
    }
    if (dt.is_neg) {
        result->v_int = -result->v_int;
    }
    return GS_SUCCESS;
}

status_t sql_func_extract(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    expr_tree_t *arg_unit = NULL;
    expr_tree_t *arg_date = NULL;
    variant_t unit_var, date_var;

    CM_POINTER2(func, result);

    // get datetime unit
    arg_unit = func->argument;
    CM_POINTER(arg_unit);
    SQL_EXEC_FUNC_ARG_EX(arg_unit, &unit_var, result);

    // get date or interval
    arg_date = arg_unit->next;
    CM_POINTER(arg_date);
    SQL_EXEC_FUNC_ARG_EX(arg_date, &date_var, result);

    if (sql_match_interval_type(date_var.type)) {
        return sql_func_extract_interval(unit_var.v_itvl_unit_id, &date_var, result);
    } else if (var_as_timestamp_flex(&date_var) == GS_SUCCESS) {
        return sql_func_extract_date(unit_var.v_itvl_unit_id, date_var.v_date, result);
    } else {
        cm_set_error_loc(arg_date->loc);
        return GS_ERROR;
    }
}

/**
 * The first argument of @sql_verify_timestampdiff and @sql_verify_timestampadd is an interval unit.
 * Thus this function is best used in the above two special functions,
 * @note the supported interval units are defined by @interval_unit_t
 * @author Added 2018/09/02
 */
static status_t sql_verify_datetime_unit(sql_verifier_t *verifier, expr_node_t *unit_node)
{
    word_t word;
    word.text = unit_node->word.column.name;

    if (!lex_match_datetime_unit(&word)) {
        GS_SRC_THROW_ERROR(word.text.loc, ERR_INVALID_FUNC_PARAMS, "datetime unit expected");
        return GS_ERROR;
    }

    unit_node->type = EXPR_NODE_CONST;
    unit_node->datatype = GS_TYPE_ITVL_UNIT;
    unit_node->value.type = GS_TYPE_ITVL_UNIT;
    unit_node->value.v_itvl_unit_id = word.id;
    SQL_SET_OPTMZ_MODE(unit_node, OPTMZ_AS_CONST);

    return GS_SUCCESS;
}

status_t sql_verify_extract(sql_verifier_t *verifier, expr_node_t *func)
{
    expr_tree_t *unit_arg = NULL;
    expr_tree_t *date_arg = NULL;
    CM_POINTER2(verifier, func);

    // verify datetime unit node
    unit_arg = func->argument;
    if (unit_arg == NULL || unit_arg->next == NULL) {
        GS_SRC_THROW_ERROR(func->loc, ERR_INVALID_FUNC_PARAM_COUNT, T2S(&func->word.func.name), 2, 2);
        return GS_ERROR;
    }
    GS_RETURN_IFERR(sql_verify_datetime_unit(verifier, unit_arg->root));

    // verify date or interval expr node
    date_arg = unit_arg->next;
    if (date_arg->next != NULL) {
        GS_SRC_THROW_ERROR(func->loc, ERR_INVALID_FUNC_PARAM_COUNT, T2S(&func->word.func.name), 2, 2);
        return GS_ERROR;
    }
    GS_RETURN_IFERR(sql_verify_expr_node(verifier, date_arg->root));
    if (!(sql_match_interval_type(TREE_DATATYPE(date_arg)) || sql_match_datetime_type(TREE_DATATYPE(date_arg)))) {
        GS_SRC_ERROR_REQUIRE_DATETIME(date_arg->loc, TREE_DATATYPE(date_arg));
        return GS_ERROR;
    }

    func->datatype = (EXPR_VALUE(int32, unit_arg) == IU_SECOND) ? GS_TYPE_NUMBER : GS_TYPE_INTEGER;
    func->size = (func->datatype == GS_TYPE_INTEGER) ? sizeof(int32) : sizeof(dec8_t);
    return GS_SUCCESS;
}

status_t sql_func_from_tz(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t date_var, tz_var;
    timezone_info_t tz_info;
    CM_POINTER3(stmt, func, result);

    // check timestamp.
    expr_tree_t *arg_date = func->argument;
    CM_POINTER(arg_date);
    sql_exec_expr(stmt, arg_date, &date_var);
    SQL_CHECK_COLUMN_VAR(&date_var, result);

    if (date_var.is_null) {
        GS_SET_ERROR_MISMATCH(GS_TYPE_TIMESTAMP, date_var.type);
        return GS_ERROR;
    }
    sql_keep_stack_variant(stmt, &date_var);
    if (date_var.type != GS_TYPE_TIMESTAMP) {
        GS_SET_ERROR_MISMATCH(GS_TYPE_TIMESTAMP, date_var.type);
        return GS_ERROR;
    }

    // check tz.
    SQL_EXEC_FUNC_ARG_EX(arg_date->next, &tz_var, result);
    sql_keep_stack_variant(stmt, &tz_var);

    if (!GS_IS_STRING_TYPE(tz_var.type)) {
        GS_SET_ERROR_MISMATCH(GS_TYPE_CHAR, tz_var.type);
        return GS_ERROR;
    }
    if (cm_text2tzoffset(&tz_var.v_text, &tz_info) != GS_SUCCESS) {
        return GS_ERROR;
    }

    result->is_null = GS_FALSE;
    result->type = GS_TYPE_TIMESTAMP_TZ;
    result->v_tstamp_tz.tstamp = date_var.v_tstamp;
    result->v_tstamp_tz.tz_offset = tz_info;

    return GS_SUCCESS;
}

status_t sql_verify_from_tz(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);
    expr_tree_t *arg = func->argument;

    GS_RETURN_IFERR(sql_verify_func_node(verf, func, 2, 2, GS_INVALID_ID32));

    if (arg->root->datatype != GS_TYPE_TIMESTAMP && arg->root->datatype != GS_TYPE_UNKNOWN) {
        GS_SET_ERROR_MISMATCH(GS_TYPE_TIMESTAMP, arg->root->datatype);
        return GS_ERROR;
    }

    arg = arg->next;
    if (!GS_IS_STRING_TYPE(arg->root->datatype) && arg->root->datatype != GS_TYPE_UNKNOWN) {
        GS_SET_ERROR_MISMATCH(GS_TYPE_CHAR, arg->root->datatype);
        return GS_ERROR;
    }

    func->precision = GS_DEFAULT_DATETIME_PRECISION;
    func->datatype = GS_TYPE_TIMESTAMP_TZ;
    func->size = sizeof(timestamp_tz_t);
    return GS_SUCCESS;
}

status_t sql_verify_from_unixtime(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 1, 2, GS_INVALID_ID32) != GS_SUCCESS) {
        return GS_ERROR;
    }

    const expr_tree_t *arg = func->argument;

    if (!sql_match_numeric_type(TREE_DATATYPE(arg))) {
        GS_SRC_ERROR_REQUIRE_NUMERIC(arg->loc, TREE_DATATYPE(arg));
        return GS_ERROR;
    }

    arg = arg->next;
    if (arg != NULL && !sql_match_string_type(TREE_DATATYPE(arg))) {
        GS_SRC_ERROR_REQUIRE_STRING(arg->loc, TREE_DATATYPE(arg));
        return GS_ERROR;
    }

    if (arg != NULL) {
        func->datatype = GS_TYPE_VARCHAR;
    } else {
        func->datatype = GS_TYPE_TIMESTAMP;
    }
    func->precision = GS_MAX_DATETIME_PRECISION;
    func->size = cm_get_datatype_strlen(func->argument->root->datatype, func->argument->root->size);

    return GS_SUCCESS;
}

status_t sql_func_from_unixtime(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t unix_ts_var, fmt_var;
    timestamp_t tmp_tstamp;

    expr_tree_t *arg1 = func->argument;
    SQL_EXEC_FUNC_ARG_EX(arg1, &unix_ts_var, result);
    GS_RETURN_IFERR(var_as_decimal(&unix_ts_var));

    if (GS_SUCCESS != var_to_unix_timestamp(&unix_ts_var.v_dec, &result->v_tstamp, SESSION_TIME_ZONE(stmt->session))) {
        return GS_ERROR;
    }

    expr_tree_t *arg2 = arg1->next;
    if (arg2 == NULL) {
        result->type = GS_TYPE_TIMESTAMP;
    } else {
        tmp_tstamp = result->v_tstamp;
        SQL_EXEC_FUNC_ARG_EX(arg2, &fmt_var, result);
        GS_RETURN_IFERR(sql_push(stmt, GS_MAX_NUMBER_LEN, (void **)&result->v_text.str));
        result->v_text.len = 0;
        GS_RETURN_IFERR(cm_timestamp2text(tmp_tstamp, &fmt_var.v_text, &result->v_text, GS_MAX_NUMBER_LEN));
        result->type = GS_TYPE_VARCHAR;
    }
    result->is_null = GS_FALSE;
    return GS_SUCCESS;
}

status_t sql_verify_utcdate(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    GS_RETURN_IFERR(sql_verify_func_node(verf, func, 0, 0, GS_INVALID_ID32));

    func->datatype = GS_TYPE_TIMESTAMP_TZ;
    func->size = sizeof(timestamp_tz_t);
    func->precision = GS_DEFAULT_DATETIME_PRECISION;
    sql_add_first_exec_node(verf, func);
    return GS_SUCCESS;
}

status_t sql_func_utcdate(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    int32 prec = GS_DEFAULT_DATETIME_PRECISION;
    date_t dt_utc_now = CM_UNIX_EPOCH;
    timeval_t tv;
    (void)cm_gettimeofday(&tv);
    dt_utc_now += ((int64)tv.tv_sec * MICROSECS_PER_SECOND + tv.tv_usec);

    result->v_tstamp_tz.tstamp = (timestamp_t)dt_utc_now;
    result->v_tstamp_tz.tz_offset = 0;
    result->is_null = GS_FALSE;
    result->type = GS_TYPE_TIMESTAMP_TZ;

    return cm_adjust_timestamp_tz(&result->v_tstamp_tz, prec);
}

status_t sql_func_last_day(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t date_var;
    date_detail_t time_desc;

    CM_POINTER2(func, result);

    expr_tree_t *arg = func->argument;
    CM_POINTER(arg);
    SQL_EXEC_FUNC_ARG_EX(arg, &date_var, result);
    if (var_as_date(SESSION_NLS(stmt), &date_var) != GS_SUCCESS) {
        cm_set_error_loc(arg->loc);
        return GS_ERROR;
    }

    cm_decode_date(date_var.v_date, &time_desc);
    time_desc.day = (uint8)CM_MONTH_DAYS(time_desc.year, time_desc.mon);
    result->is_null = GS_FALSE;
    result->type = date_var.type;
    result->v_date = cm_encode_date(&time_desc);

    return GS_SUCCESS;
}

status_t sql_verify_last_day(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);
    if (sql_verify_func_node(verf, func, 1, 1, GS_INVALID_ID32) != GS_SUCCESS) {
        return GS_ERROR;
    }

    expr_tree_t *date_arg = func->argument;
    if (!sql_match_datetime_type(TREE_DATATYPE(date_arg))) {
        GS_SRC_ERROR_REQUIRE_DATETIME(date_arg->loc, TREE_DATATYPE(date_arg));
        return GS_ERROR;
    }
    func->datatype = GS_TYPE_DATE;
    func->size = GS_DATE_SIZE;
    return GS_SUCCESS;
}

status_t sql_verify_localtimestamp(sql_verifier_t *verf, expr_node_t *func)
{
    int32 precision = GS_DEFAULT_DATETIME_PRECISION;
    CM_POINTER2(verf, func);

    expr_tree_t *arg = func->argument;
    if (arg != NULL) {
        if (GS_IS_INTEGER_TYPE(arg->root->value.type) && TREE_IS_CONST(arg)) {
            precision = VALUE(int32, &arg->root->value);
        } else {
            GS_SRC_THROW_ERROR(arg->loc, ERR_INVALID_FUNC_PARAMS, "integer argument required");
            return GS_ERROR;
        }
    }

    GS_RETURN_IFERR(sql_verify_func_node(verf, func, 0, 1, GS_INVALID_ID32));
    func->datatype = GS_TYPE_TIMESTAMP;
    func->size = GS_TIMESTAMP_SIZE;
    func->precision = (uint8)precision;
    sql_add_first_exec_node(verf, func);
    return GS_SUCCESS;
}

status_t sql_func_localtimestamp(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    int32 prec = GS_MAX_DATETIME_PRECISION;
    variant_t var;
    CM_POINTER3(stmt, func, result);

    expr_tree_t *arg = func->argument;

    if (arg != NULL) {
        SQL_EXEC_FUNC_ARG_EX(arg, &var, result);

        if (GS_IS_INTEGER_TYPE(var.type)) {
            prec = VALUE(int32, &var);
        } else {
            GS_SRC_THROW_ERROR(arg->loc, ERR_INVALID_FUNC_PARAMS, "integer argument required");
            return GS_ERROR;
        }
    }

    if (prec < GS_MIN_DATETIME_PRECISION || prec > GS_MAX_DATETIME_PRECISION) {
        GS_SRC_THROW_ERROR_EX(arg->loc, ERR_SQL_SYNTAX_ERROR, "integer argument must between %d and %d. ",
            GS_MIN_DATETIME_PRECISION, GS_MAX_DATETIME_PRECISION);
        return GS_ERROR;
    }

    SQL_GET_STMT_SYSTIMESTAMP(stmt, result);
    result->type = GS_TYPE_TIMESTAMP;
    result->is_null = GS_FALSE;
    /* adjust with the session time zone */
    result->v_tstamp =
        cm_adjust_date_between_two_tzs(stmt->v_systimestamp, g_timer()->tz, sql_get_session_timezone(stmt));

    return cm_adjust_timestamp(&result->v_tstamp, prec);
}

static status_t sql_func_months_between_core(date_t dt1, date_t dt2, variant_t *result)
{
    date_detail_t date_desc1, date_desc2;
    int32 year, mon, day, diff_mons;
    int64 diff_secs;
    bool32 last_mon_day;
    dec8_t dec1, dec2;

    cm_decode_date(dt1, &date_desc1);
    cm_decode_date(dt2, &date_desc2);

    year = (int32)((int32)date_desc1.year - (int32)date_desc2.year);
    mon = (int32)((int32)date_desc1.mon - (int32)date_desc2.mon);
    day = (int32)((int32)date_desc1.day - (int32)date_desc2.day);

    diff_mons = GS_MONTH_PER_YEAR * year + mon;

    last_mon_day = (sql_is_last_month_day(&date_desc1) && sql_is_last_month_day(&date_desc2));
    if ((day == 0) || last_mon_day) {
        cm_int32_to_dec(diff_mons, &result->v_dec);
    } else {
        /*
           Oracle calculates the fractional portion of the result based on a 31-day month
        */
        diff_secs = (int64)day * (int64)GS_SEC_PER_DAY;
        diff_secs += ((int32)date_desc1.hour - (int32)date_desc2.hour) * GS_SEC_PER_HOUR;
        diff_secs += ((int32)date_desc1.min - (int32)date_desc2.min) * GS_SEC_PER_MIN;
        diff_secs += ((int32)date_desc1.sec - (int32)date_desc2.sec);
        // convert to decimal for high precision
        cm_int64_to_dec(diff_secs, &dec1);
        GS_RETURN_IFERR(cm_dec_div_int64(&dec1, (int64)GS_SEC_PER_DAY * GS_DAY_PER_MONTH, &dec2));
        GS_RETURN_IFERR(cm_dec_add_int64(&dec2, (int64)diff_mons, &result->v_dec));
    }
    result->is_null = GS_FALSE;
    result->type = GS_TYPE_NUMBER;
    return GS_SUCCESS;
}

status_t sql_func_months_between(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t date_var1, date_var2;

    CM_POINTER2(func, result);

    // get date1
    expr_tree_t *arg_date1 = func->argument;
    CM_POINTER(arg_date1);
    SQL_EXEC_FUNC_ARG_EX(arg_date1, &date_var1, result);

    if (var_as_timestamp_flex(&date_var1) != GS_SUCCESS) {
        cm_set_error_loc(arg_date1->loc);
        return GS_ERROR;
    }

    // get date2
    expr_tree_t *arg_date2 = arg_date1->next;
    CM_POINTER(arg_date2);
    SQL_EXEC_FUNC_ARG_EX(arg_date2, &date_var2, result);

    if (var_as_timestamp_flex(&date_var2) != GS_SUCCESS) {
        cm_set_error_loc(arg_date2->loc);
        return GS_ERROR;
    }

    return sql_func_months_between_core(date_var1.v_date, date_var2.v_date, result);
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

    GS_RETURN_IFERR(sql_verify_func_node(verifier, func, 2, 2, GS_INVALID_ID32));

    expr_tree_t *date_arg1 = func->argument;
    if (!sql_match_datetime_type(TREE_DATATYPE(date_arg1))) {
        GS_SRC_ERROR_REQUIRE_DATETIME(date_arg1->loc, TREE_DATATYPE(date_arg1));
        return GS_ERROR;
    }

    expr_tree_t *date_arg2 = date_arg1->next;
    if (!sql_match_datetime_type(TREE_DATATYPE(date_arg2))) {
        GS_SRC_ERROR_REQUIRE_DATETIME(date_arg2->loc, TREE_DATATYPE(date_arg2));
        return GS_ERROR;
    }
    // need ajust by result
    func->datatype = GS_TYPE_NUMBER;
    func->size = (uint16)MAX_DEC_BYTE_SZ;
    return GS_SUCCESS;
}

status_t sql_func_next_day(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t date_var, week_var;
    date_detail_t time_desc;
    date_detail_ex_t detail_ex;
    expr_tree_t *arg1 = func->argument;
    CM_POINTER2(func, result);
    CM_POINTER(arg1);
    SQL_EXEC_FUNC_ARG_EX(arg1, &date_var, result);
    if (var_as_date(SESSION_NLS(stmt), &date_var) != GS_SUCCESS) {
        cm_set_error_loc(arg1->loc);
        return GS_ERROR;
    }
    cm_decode_date(date_var.v_date, &time_desc);
    cm_get_detail_ex(&time_desc, &detail_ex);
    uint8 start_week_day = detail_ex.day_of_week;

    expr_tree_t *arg2 = arg1->next;
    CM_POINTER(arg2);
    SQL_EXEC_FUNC_ARG_EX(arg2, &week_var, result);

    uint8 end_week_day;
    if (sql_match_string_type((gs_type_t)week_var.type)) {
        cm_trim_text(&week_var.v_text);
        if (!cm_str2week(&week_var.v_text, &end_week_day)) {
            GS_THROW_ERROR(ERR_INVALID_PARAMETER, "of second column");
            return GS_ERROR;
        }
    } else {
        var_as_floor_integer(&week_var);
        if (week_var.v_int < 1 || week_var.v_int > (int32)DAYS_PER_WEEK) {
            GS_THROW_ERROR(ERR_INVALID_PARAMETER, "of second column");
            return GS_ERROR;
        } else {
            end_week_day = (uint8)(week_var.v_int - 1);
        }
    }

    if (end_week_day > start_week_day) {
        GS_RETURN_IFERR(cm_date_add_days(date_var.v_date, (double)(end_week_day - start_week_day), &result->v_date));
    } else {
        GS_RETURN_IFERR(cm_date_add_days(date_var.v_date, (double)(DAYS_PER_WEEK + end_week_day - start_week_day),
            &result->v_date));
    }

    result->is_null = GS_FALSE;
    result->type = date_var.type;
    return GS_SUCCESS;
}

status_t sql_verify_next_day(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 2, 2, GS_INVALID_ID32) != GS_SUCCESS) {
        return GS_ERROR;
    }

    expr_tree_t *date_arg = func->argument;
    if (!sql_match_datetime_type(TREE_DATATYPE(date_arg))) {
        GS_SRC_ERROR_REQUIRE_DATETIME(date_arg->loc, TREE_DATATYPE(date_arg));
        return GS_ERROR;
    }
    expr_tree_t *week_arg = date_arg->next;
    if (week_arg != NULL) {
        if (!sql_match_num_and_str_type(TREE_DATATYPE(week_arg))) {
            GS_SRC_ERROR_REQUIRE_NUM_OR_STR(week_arg->loc, TREE_DATATYPE(week_arg));
            return GS_ERROR;
        }
    }

    func->datatype = GS_TYPE_DATE;
    func->size = GS_DATE_SIZE;
    return GS_SUCCESS;
}

status_t sql_func_sys_timestamp(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    int32 prec = GS_MAX_DATETIME_PRECISION;
    CM_POINTER3(stmt, func, result);

    SQL_GET_STMT_SYSTIMESTAMP(stmt, result);
    if (stmt->session->call_version >= CS_VERSION_8) {
        result->type = GS_TYPE_TIMESTAMP_TZ;
        /* adjust with the os time zone */
        result->v_tstamp_tz.tz_offset = g_timer()->tz;
    } else {
        result->type = GS_TYPE_TIMESTAMP_TZ_FAKE;
    }
    result->is_null = GS_FALSE;

    if (func->argument != NULL) {
        prec = VALUE(int32, &func->argument->root->value);
    }

    return cm_adjust_timestamp_tz(&result->v_tstamp_tz, prec);
}

static status_t sql_func_timestampadd_core(interval_unit_t unit, int64 itvl, date_t *dt)
{
    date_t new_dt = *dt;
    date_detail_t time_desc;
    uint8 day;

    switch (unit) {
        case IU_YEAR: {
            cm_decode_date(*dt, &time_desc);
            day = time_desc.day;
            GS_RETURN_IFERR(sql_func_add_months_core((int32)itvl * 12, &time_desc));
            if (day < time_desc.day) {
                time_desc.day = day;
            }
            (*dt) = cm_encode_date(&time_desc);
            return GS_SUCCESS;
        }
        case IU_QUARTER: {
            cm_decode_date(*dt, &time_desc);
            day = time_desc.day;
            GS_RETURN_IFERR(sql_func_add_months_core((int32)itvl * 3, &time_desc));
            if (day < time_desc.day) {
                time_desc.day = day;
            }
            (*dt) = cm_encode_date(&time_desc);
            return GS_SUCCESS;
        }
        case IU_MONTH: {
            cm_decode_date(*dt, &time_desc);
            day = time_desc.day;
            GS_RETURN_IFERR(sql_func_add_months_core((int32)itvl, &time_desc));
            if (day < time_desc.day) {
                time_desc.day = day;
            }
            (*dt) = cm_encode_date(&time_desc);
            return GS_SUCCESS;
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
            GS_THROW_ERROR(ERR_INVALID_FUNC_PARAMS, "invalid UNIT");
            return GS_ERROR;
    }

    if (CM_IS_DATETIME_ADDTION_OVERFLOW(*dt, itvl, new_dt)) {
        GS_SET_ERROR_DATETIME_OVERFLOW();
        return GS_ERROR;
    }
    (*dt) = new_dt;
    return GS_SUCCESS;
}

status_t sql_func_sys_extract_utc(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    CM_POINTER3(stmt, func, result);
    variant_t time_var;
    expr_tree_t *arg_time = func->argument;
    timezone_info_t tz_offset = cm_get_session_time_zone(SESSION_NLS(stmt));
    SQL_EXEC_FUNC_ARG_EX(arg_time, &time_var, result);
    if (!sql_match_timestamp(time_var.type) || time_var.type == GS_TYPE_UNKNOWN) {
        GS_SRC_THROW_ERROR(func->loc, ERR_INVALID_FUNC_PARAMS, "timestamp argument required");
        return GS_ERROR;
    }
    if (time_var.type == GS_TYPE_TIMESTAMP_TZ) {
        tz_offset = time_var.v_tstamp_tz.tz_offset;
    }
    if (var_as_timestamp(SESSION_NLS(stmt), &time_var) != GS_SUCCESS) {
        cm_set_error_loc(arg_time->loc);
        return GS_ERROR;
    }
    tz_offset = -tz_offset;
    if (sql_func_timestampadd_core(IU_MINUTE, (int64)tz_offset, &time_var.v_tstamp) != GS_SUCCESS) {
        cm_set_error_loc(func->loc);
        return GS_ERROR;
    }
    result->v_tstamp = time_var.v_tstamp;
    result->type = GS_TYPE_TIMESTAMP;
    result->is_null = GS_FALSE;
    return GS_SUCCESS;
}

status_t sql_verify_sys_extract_utc(sql_verifier_t *verf, expr_node_t *func)
{
    if (sql_verify_func_node(verf, func, 1, 1, GS_INVALID_ID32) != GS_SUCCESS) {
        return GS_ERROR;
    }
    expr_tree_t *arg = func->argument;

    if (!sql_match_timestamp(TREE_DATATYPE(arg))) {
        GS_SRC_THROW_ERROR(func->loc, ERR_INVALID_FUNC_PARAMS, "timestamp argument required");
        return GS_ERROR;
    }
    func->datatype = GS_TYPE_TIMESTAMP;
    func->precision = GS_DEFAULT_DATETIME_PRECISION;
    func->size = GS_TIMESTAMP_SIZE;
    return GS_SUCCESS;
}

status_t sql_verify_to_date(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 1, 2, GS_INVALID_ID32) != GS_SUCCESS) {
        return GS_ERROR;
    }

    gs_type_t arg1_type = sql_get_func_arg1_datatype(func);
    if (!sql_match_num_and_str_type(arg1_type)) {
        GS_SRC_THROW_ERROR(func->argument->loc, ERR_INVALID_FUNC_PARAMS, "string or number argument expected");
        return GS_ERROR;
    }

    func->datatype = GS_TYPE_DATE;
    func->size = GS_DATE_SIZE;

    sql_infer_func_optmz_mode(verf, func);

    // merely has one constant argument
    if (func->value.v_func.arg_cnt == 1 && NODE_IS_OPTMZ_CONST(func)) {
        sql_add_first_exec_node(verf, func);
    }

    return GS_SUCCESS;
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
            GS_SRC_THROW_ERROR(arg1->loc, ERR_INVALID_FUNC_PARAMS, "string or number argument expected");
            return GS_ERROR;
        }

        if (!GS_IS_STRING_TYPE(var1.type)) {
            if (sql_var_as_string(stmt, &var1) != GS_SUCCESS) {
                cm_set_error_loc(arg1->loc);
                return GS_ERROR;
            }
        }
    } else {
        if (!GS_IS_STRING_TYPE(var1.type)) {
            GS_SRC_THROW_ERROR(arg1->loc, ERR_INVALID_FUNC_PARAMS, "string argument expected");
            return GS_ERROR;
        }
    }

    expr_tree_t *arg2 = arg1->next; // argument format_string
    if (arg2 != NULL) {
        sql_keep_stack_variant(stmt, &var1);
        SQL_EXEC_FUNC_ARG_EX(arg2, &fmt_var, result);
        if (!GS_IS_STRING_TYPE(fmt_var.type)) {
            GS_SRC_THROW_ERROR(arg2->loc, ERR_INVALID_FUNC_PARAMS, "string argument expected");
            return GS_ERROR;
        }
    } else {
        sql_session_nlsparam_geter(stmt, is_to_date ? NLS_DATE_FORMAT : NLS_TIMESTAMP_FORMAT, &fmt_var.v_text);
    }

    result->is_null = GS_FALSE;
    result->type = GS_TYPE_DATE;

    if (cm_text2date_fixed(&var1.v_text, &fmt_var.v_text, &result->v_date) != GS_SUCCESS) {
        cm_set_error_loc(func->loc);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t sql_func_to_date(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    return sql_func_to_date_core(stmt, func, result, GS_TRUE);
}

status_t sql_func_to_timestamp(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    if (sql_func_to_date_core(stmt, func, result, GS_FALSE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (result->type != GS_TYPE_COLUMN) {
        result->type = GS_TYPE_TIMESTAMP;
    }
    return GS_SUCCESS;
}

status_t sql_verify_to_timestamp(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 1, 2, GS_INVALID_ID32) != GS_SUCCESS) {
        return GS_ERROR;
    }

    gs_type_t arg1_type = sql_get_func_arg1_datatype(func);
    if (!sql_match_string_type(arg1_type)) {
        GS_SRC_THROW_ERROR(func->argument->loc, ERR_INVALID_FUNC_PARAMS, "string argument expected");
        return GS_ERROR;
    }

    func->datatype = GS_TYPE_TIMESTAMP;
    func->size = GS_TIMESTAMP_SIZE;
    func->precision = GS_DEFAULT_DATETIME_PRECISION;

    sql_infer_func_optmz_mode(verf, func);

    // merely has one constant argument
    if (func->value.v_func.arg_cnt == 1 && NODE_IS_OPTMZ_CONST(func)) {
        sql_add_first_exec_node(verf, func);
    }

    return GS_SUCCESS;
}

status_t sql_func_timestampadd(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t unit_var, date_var, itvl_var;

    CM_POINTER2(func, result);

    // get interval unit
    expr_tree_t *arg_unit = func->argument;
    CM_POINTER(arg_unit);
    SQL_EXEC_FUNC_ARG_EX(arg_unit, &unit_var, result);

    // get interval
    expr_tree_t *arg_itvl = arg_unit->next;
    CM_POINTER(arg_itvl);
    SQL_EXEC_FUNC_ARG_EX(arg_itvl, &itvl_var, result);

    /*
      Convert second to microsecond
    */
    if (unit_var.v_itvl_unit_id == IU_SECOND) {
        // MySQL will truncate the part after microsecond,
        // Using REAL type will not result in loss of precision.
        GS_RETURN_IFERR(var_as_real(&itvl_var));
        itvl_var.v_bigint = (int64)(itvl_var.v_real * MICROSECS_PER_SECOND);
        itvl_var.type = GS_TYPE_BIGINT;
        unit_var.v_itvl_unit_id = IU_MICROSECOND;
    } else if (var_as_bigint(&itvl_var) != GS_SUCCESS) {
        cm_set_error_loc(arg_itvl->loc);
        return GS_ERROR;
    }

    if ((GS_IS_YM_UNIT(unit_var.v_itvl_unit_id) || GS_IS_DAY_UNIT(unit_var.v_itvl_unit_id)) &&
        (itvl_var.v_bigint > (int64)CM_MAX_DATE ||
        (itvl_var.v_bigint < (int64)CM_MIN_DATE && itvl_var.v_bigint != CM_ALL_ZERO_DATE))) {
        GS_SET_ERROR_TIMESTAMP_OVERFLOW();
        return GS_ERROR;
    }

    // get date
    expr_tree_t *arg_date = arg_itvl->next;
    CM_POINTER(arg_date);
    SQL_EXEC_FUNC_ARG_EX(arg_date, &date_var, result);

    if (var_as_timestamp_flex(&date_var) != GS_SUCCESS) {
        cm_set_error_loc(arg_date->loc);
        return GS_ERROR;
    }

    if (sql_func_timestampadd_core(unit_var.v_itvl_unit_id, itvl_var.v_bigint, &date_var.v_date) != GS_SUCCESS) {
        cm_set_error_loc(func->loc);
        return GS_ERROR;
    }

    result->is_null = GS_FALSE;
    result->type = GS_TYPE_TIMESTAMP;
    result->v_date = date_var.v_date;
    return GS_SUCCESS;
}

static status_t sql_verify_func_arg(sql_verifier_t *verf, expr_node_t *func, expr_tree_t *arg, bool32 is_required)
{
    if (arg == NULL) {
        if (is_required) {
            return GS_ERROR;
        }
        return GS_SUCCESS;
    }

    if (arg->root->type == EXPR_NODE_PRIOR) {
        GS_SRC_THROW_ERROR_EX(arg->loc, ERR_SQL_SYNTAX_ERROR, "prior must be in the condition of connect by");
        return GS_ERROR;
    }

    return sql_verify_expr_node(verf, arg->root);
}

status_t sql_verify_timestampadd(sql_verifier_t *verifier, expr_node_t *func)
{
    /* *
     * TIMESTAMPADD(unit,interval,datetime_expr)
     * \brief Adds the integer expression interval to the date or datetime expression datetime_expr
     * \param unit:  MICROSECOND, SECOND, MINUTE, HOUR, DAY, WEEK, MONTH, QUARTER, or YEAR
     * \param interval: integer
     * \param datetime_expr: date or datetime expression
     */
    CM_POINTER2(verifier, func);

    expr_tree_t *unit_arg = func->argument;
    if (unit_arg == NULL) {
        GS_SRC_THROW_ERROR(func->loc, ERR_INVALID_FUNC_PARAM_COUNT, T2S(&func->word.func.name), 3, 3);
        return GS_ERROR;
    }
    if (sql_verify_datetime_unit(verifier, unit_arg->root) != GS_SUCCESS) {
        return GS_ERROR;
    }

    expr_tree_t *itvl_arg = unit_arg->next;
    if (itvl_arg == NULL) {
        GS_SRC_THROW_ERROR(func->loc, ERR_INVALID_FUNC_PARAM_COUNT, T2S(&func->word.func.name), 3, 3);
        return GS_ERROR;
    }
    GS_RETURN_IFERR(sql_verify_func_arg(verifier, func, itvl_arg, GS_TRUE));
    if (!sql_match_numeric_type(TREE_DATATYPE(itvl_arg))) {
        GS_SRC_ERROR_REQUIRE_NUMERIC(itvl_arg->loc, TREE_DATATYPE(itvl_arg));
        return GS_ERROR;
    }

    expr_tree_t *date_arg = itvl_arg->next;
    if (date_arg == NULL) {
        GS_SRC_THROW_ERROR(func->loc, ERR_INVALID_FUNC_PARAM_COUNT, T2S(&func->word.func.name), 3, 3);
        return GS_ERROR;
    }
    GS_RETURN_IFERR(sql_verify_func_arg(verifier, func, date_arg, GS_TRUE));
    if (!sql_match_datetime_type(TREE_DATATYPE(date_arg))) {
        GS_SRC_ERROR_REQUIRE_DATETIME(date_arg->loc, TREE_DATATYPE(date_arg));
        return GS_ERROR;
    }

    if (date_arg->next != NULL) {
        GS_SRC_THROW_ERROR(func->loc, ERR_INVALID_FUNC_PARAM_COUNT, T2S(&func->word.func.name), 3, 3);
        return GS_ERROR;
    }

    func->datatype = GS_TYPE_TIMESTAMP;
    func->precision = GS_DEFAULT_DATETIME_PRECISION;
    func->size = 8;
    return GS_SUCCESS;
}

// get the time that less than one day in micro sec
static inline int64 sql_get_time_parts_micro(date_t dt)
{
    int64 micro_secs = dt % UNITS_PER_DAY;
    if (micro_secs < 0) {
        micro_secs += UNITS_PER_DAY;
    }

    return micro_secs;
}

/**
 * \brief Calculate number of months between dates for TIMESTAMPDIFF
 * \param dt1 cantian datetime value
 * \param dt2 cantian datetime value
 * \returns number of months between dates dt1 and dt2 (dt1-dt2)
 */
static int32 sql_date_diff_months(date_t dt1, date_t dt2)
{
    date_detail_t date_desc1, date_desc2;
    int32 year, mon, day, diff_mons;
    int64 micro_secs;

    cm_decode_date(dt1, &date_desc1);
    cm_decode_date(dt2, &date_desc2);

    year = (int32)((int32)date_desc1.year - (int32)date_desc2.year);
    mon = (int32)((int32)date_desc1.mon - (int32)date_desc2.mon);
    day = (int32)((int32)date_desc1.day - (int32)date_desc2.day);
    micro_secs = sql_get_time_parts_micro(dt1) - sql_get_time_parts_micro(dt2);

    diff_mons = 12 * year + mon;

    if (diff_mons > 0) {
        diff_mons -= ((day < 0) || (day == 0 && micro_secs < 0)) ? 1 : 0;
    } else if (diff_mons < 0) {
        diff_mons += ((day > 0) || (day == 0 && micro_secs > 0)) ? 1 : 0;
    }
    return diff_mons;
}

status_t sql_func_timestampdiff(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t unit_var, date_var1, date_var2;

    CM_POINTER2(func, result);

    // get interval unit
    expr_tree_t *arg_unit = func->argument;
    SQL_EXEC_FUNC_ARG_EX(arg_unit, &unit_var, result);

    // get date1
    expr_tree_t *arg_date1 = arg_unit->next;
    SQL_EXEC_FUNC_ARG_EX(arg_date1, &date_var1, result);

    if (var_as_timestamp_flex(&date_var1) != GS_SUCCESS) {
        cm_set_error_loc(arg_date1->loc);
        return GS_ERROR;
    }

    // get date
    expr_tree_t *arg_date2 = arg_date1->next;
    SQL_EXEC_FUNC_ARG_EX(arg_date2, &date_var2, result);

    if (var_as_timestamp_flex(&date_var2) != GS_SUCCESS) {
        cm_set_error_loc(arg_date2->loc);
        return GS_ERROR;
    }

    switch (unit_var.v_itvl_unit_id) {
        case IU_YEAR:
            result->v_bigint = (int64)sql_date_diff_months(date_var2.v_date, date_var1.v_date);
            result->v_bigint /= 12;
            break;

        case IU_QUARTER:
            result->v_bigint = (int64)sql_date_diff_months(date_var2.v_date, date_var1.v_date);
            result->v_bigint /= 3;
            break;

        case IU_MONTH:
            result->v_bigint = (int64)sql_date_diff_months(date_var2.v_date, date_var1.v_date);
            break;

        case IU_WEEK:
            result->v_bigint = (int64)cm_date_diff_days(date_var2.v_date, date_var1.v_date);
            result->v_bigint /= 7;
            break;

        case IU_DAY:
            result->v_bigint = (int64)cm_date_diff_days(date_var2.v_date, date_var1.v_date);
            break;

        case IU_HOUR:
            result->v_bigint = (date_var2.v_date - date_var1.v_date) / SECONDS_PER_HOUR / MICROSECS_PER_SECOND;
            break;

        case IU_MINUTE:
            result->v_bigint = (date_var2.v_date - date_var1.v_date) / SECONDS_PER_MIN / MICROSECS_PER_SECOND;
            break;

        case IU_SECOND:
            result->v_bigint = (date_var2.v_date - date_var1.v_date) / MICROSECS_PER_SECOND;
            break;

        case IU_MICROSECOND:
            result->v_bigint = (date_var2.v_date - date_var1.v_date);
            break;

        default:
            GS_THROW_ERROR(ERR_INVALID_FUNC_PARAMS, "invalid UNIT");
            return GS_ERROR;
    }

    result->is_null = GS_FALSE;
    result->type = GS_TYPE_BIGINT;

    return GS_SUCCESS;
}

status_t sql_verify_timestampdiff(sql_verifier_t *verifier, expr_node_t *func)
{
    /* *
     * TIMESTAMPDIFF(unit,datetime_expr1,datetime_expr2)
     * \brief Returns datetime_expr2-datetime_expr1 in specified unit
     * \param unit:  MICROSECOND, SECOND, MINUTE, HOUR, DAY, WEEK, MONTH, QUARTER, or YEAR
     * \param datetime_expr1: date or datetime expression
     * \param datetime_expr2: date or datetime expression
     */
    uint32 arg_count;

    CM_POINTER2(verifier, func);

    expr_tree_t *unit_arg = func->argument;
    if (unit_arg == NULL) {
        GS_SRC_THROW_ERROR(func->loc, ERR_INVALID_FUNC_PARAM_COUNT, T2S(&func->word.func.name), 3, 3);
        return GS_ERROR;
    }
    if (sql_verify_datetime_unit(verifier, unit_arg->root) != GS_SUCCESS) {
        return GS_ERROR;
    }

    arg_count = 0;
    expr_tree_t *date_arg = unit_arg->next;
    while (date_arg != NULL) {
        arg_count++;

        if (arg_count > 2) {
            GS_SRC_THROW_ERROR(func->loc, ERR_INVALID_FUNC_PARAM_COUNT, T2S(&func->word.func.name), 3, 3);
            return GS_ERROR;
        }

        if (date_arg->root->type == EXPR_NODE_PRIOR) {
            GS_SRC_THROW_ERROR_EX(date_arg->loc, ERR_SQL_SYNTAX_ERROR, "prior must be in the condition of connect by");
            return GS_ERROR;
        }

        if (sql_verify_expr_node(verifier, date_arg->root) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (!sql_match_datetime_type(TREE_DATATYPE(date_arg))) {
            GS_SRC_ERROR_REQUIRE_DATETIME(date_arg->loc, TREE_DATATYPE(date_arg));
            return GS_ERROR;
        }

        date_arg = date_arg->next;
    }

    if (arg_count < 2) {
        GS_SRC_THROW_ERROR(func->loc, ERR_INVALID_FUNC_PARAM_COUNT, T2S(&func->word.func.name), 3, 3);
        return GS_ERROR;
    }
    func->datatype = GS_TYPE_BIGINT;
    func->size = sizeof(int64);
    return GS_SUCCESS;
}

status_t sql_verify_unix_timestamp(sql_verifier_t *verf, expr_node_t *func)
{
    if (sql_verify_func_node(verf, func, 0, 1, GS_INVALID_ID32) != GS_SUCCESS) {
        return GS_ERROR;
    }

    expr_tree_t *arg = func->argument;
    // verify the first argument, which is a datetime or datetime string type
    if (arg != NULL && !sql_match_datetime_type(TREE_DATATYPE(arg))) {
        GS_SRC_ERROR_REQUIRE_DATETIME(arg->loc, TREE_DATATYPE(arg));
        return GS_ERROR;
    }

    func->datatype = GS_TYPE_BIGINT;
    func->size = GS_BIGINT_SIZE;
    return GS_SUCCESS;
}

status_t sql_func_unix_timestamp(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    result->type = GS_TYPE_BIGINT;
    result->is_null = GS_FALSE;

    timestamp_t ts_val;
    do {
        variant_t date_var;
        expr_tree_t *arg = func->argument;
        text_t fmt_text;
        if (arg == NULL) { // if no argument
            SQL_GET_STMT_SYSTIMESTAMP(stmt, result);
            result->v_bigint = cm_get_unix_timestamp(result->v_tstamp, CM_HOST_TIMEZONE);
            break;
        }
        // verify the first argument, which is a datetime or datetime string type
        SQL_EXEC_FUNC_ARG_EX(arg, &date_var, result);
        if (GS_IS_DATETIME_TYPE(date_var.type)) {
            ts_val = date_var.v_tstamp;
            result->v_bigint = cm_get_unix_timestamp(ts_val, SESSION_TIME_ZONE(stmt->session));
            break;
        }
        if (!GS_IS_STRING_TYPE(date_var.type)) {
            GS_SRC_ERROR_REQUIRE_DATETIME(arg->loc, TREE_DATATYPE(arg));
            return GS_ERROR;
        }

        sql_session_nlsparam_geter(stmt, NLS_TIMESTAMP_FORMAT, &fmt_text);

        if (cm_text2date(&date_var.v_text, &fmt_text, (date_t *)&ts_val) != GS_SUCCESS) {
            cm_set_error_loc(arg->loc);
            return GS_ERROR;
        }
        result->v_bigint = cm_get_unix_timestamp(ts_val, SESSION_TIME_ZONE(stmt->session));
    } while (0);

    if (result->v_bigint < CM_MIN_UTC || result->v_bigint > CM_MAX_UTC) {
        result->v_bigint = 0;
    }

    return GS_SUCCESS;
}

status_t sql_verify_utctimestamp(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);
    GS_RETURN_IFERR(sql_verify_func_node(verf, func, 0, 0, GS_INVALID_ID32));
    func->datatype = GS_TYPE_DATE;
    func->size = GS_DATE_SIZE;
    func->precision = GS_DEFAULT_DATETIME_PRECISION;
    sql_add_first_exec_node(verf, func);
    return GS_SUCCESS;
}

status_t sql_func_utctimestamp(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    result->v_date = cm_utc_now();
    result->is_null = GS_FALSE;
    result->type = GS_TYPE_DATE;
    return GS_SUCCESS;
}
