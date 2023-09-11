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
 * func_regexp.c
 *
 *
 * IDENTIFICATION
 * src/cmd/function/func_regexp.c
 *
 * -------------------------------------------------------------------------
 */
#include "func_regexp.h"
#include "cm_regexp.h"
#include "srv_instance.h"
#include "func_string.h"

static status_t sql_verify_regexp_args(sql_verifier_t *verf, expr_node_t *func, regexp_arg_type_t *arg_types,
    const char *name)
{
    int32 arg_count;
    expr_tree_t *curr = func->argument;
    arg_count = 0;
    while (curr != NULL) {
        ++arg_count;
        GS_RETURN_IFERR(sql_verify_current_expr(verf, curr));
        switch (arg_types[arg_count - 1]) {
            case REGEXP_ARG_SOURCE:
            case REGEXP_ARG_REPLACE:
                if (!sql_match_numeric_type(curr->root->datatype) && !sql_match_string_type(curr->root->datatype)) {
                    GS_THROW_ERROR(ERR_TYPE_MISMATCH, get_datatype_name_str(GS_TYPE_STRING),
                        get_datatype_name_str((int32)curr->root->datatype));
                    return GS_ERROR;
                }
                break;
            case REGEXP_ARG_PATTERN:
            case REGEXP_ARG_MATCH_PARAM:
                if (!sql_match_string_type(curr->root->datatype)) {
                    GS_THROW_ERROR(ERR_TYPE_MISMATCH, get_datatype_name_str(GS_TYPE_STRING),
                        get_datatype_name_str((int32)curr->root->datatype));
                    return GS_ERROR;
                }
                break;
            case REGEXP_ARG_POSITION:
            case REGEXP_ARG_OCCUR:
            case REGEXP_ARG_RETURN_OPT:
            case REGEXP_ARG_SUBEXPR:
                if (!sql_match_numeric_type(curr->root->datatype)) {
                    GS_THROW_ERROR(ERR_TYPE_MISMATCH, get_datatype_name_str(GS_TYPE_INTEGER),
                        get_datatype_name_str((int32)curr->root->datatype));
                    return GS_ERROR;
                }
                break;
            default: // REGEXP_ARG_DUMB the last one in the args type array, represent invalid
                GS_SRC_THROW_ERROR(func->loc, ERR_INVALID_FUNC_PARAM_COUNT, name, 2, arg_count - 1);
                return GS_ERROR;
        }
        curr = curr->next;
    }
    if (arg_count < 2) {
        while (arg_types[arg_count] != REGEXP_ARG_DUMB) {
            ++arg_count;
        }
        GS_SRC_THROW_ERROR(func->loc, ERR_INVALID_FUNC_PARAM_COUNT, name, 2, arg_count);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t sql_verify_regexp_count(sql_verifier_t *verf, expr_node_t *func)
{
    GS_RETURN_IFERR(sql_verify_regexp_args(verf, func, g_count_arg_types, "REGEXP_COUNT"));

    func->datatype = GS_TYPE_INTEGER;
    func->size = GS_INTEGER_SIZE;

    return GS_SUCCESS;
}

static status_t sql_func_regexp_count_core(sql_stmt_t *stmt, variant_t *result, void *code, regexp_args_t *args)
{
    bool32 match_null = GS_FALSE;
    int32 pos, count;
    status_t ret;
    text_t posstr;
    regexp_substr_assist_t assist;

    do {
        // if result is null, just return success
        if (result->is_null) {
            ret = GS_SUCCESS;
            break;
        }

        pos = 0;
        for (count = 0; (uint32)pos <= args->src->len; count++) {
            assist.code = code;
            assist.subject = *(args->src);
            assist.offset = args->offset - 1;
            assist.occur = 1;
            assist.subexpr = 0;
            assist.charset = GET_CHARSET_ID;
            ret = cm_regexp_instr(&pos, &assist, GS_TRUE);
            GS_BREAK_IF_ERROR(ret);

            if (pos == 0) {
                break;
            } else if (pos >= 1) {
                if (pos == args->offset) {
                    args->offset += 1;
                    match_null = GS_TRUE;
                } else {
                    posstr.str = args->src->str;
                    posstr.len = (uint32)pos - 1;
                    ret = GET_DATABASE_CHARSET->length(&posstr, (uint32 *)&pos);
                    GS_BREAK_IF_ERROR(ret);
                    pos += 1;
                    args->offset = pos;
                }
            }
        }
        if (match_null) {
            count += 1;
        }
        *(VALUE_PTR(int32, result)) = count;
    } while (GS_FALSE);

    return ret;
}

static status_t sql_regexp_calc_args(sql_stmt_t *stmt, expr_node_t *func, regexp_arg_type_t *arg_types,
    regexp_args_t *args, variant_t *result)
{
    int32 arg_count;

    expr_tree_t *curr = func->argument;
    arg_count = 0;
    cm_regexp_args_init(args);

    // if argument source, pattern, position, occur, return_opt, subexpr is null, then the result will be null
    while (curr != NULL) {
        ++arg_count;
        switch (arg_types[arg_count - 1]) {
            case REGEXP_ARG_SOURCE:
                SQL_EXEC_FUNC_ARG_EX2(curr, &args->var_src, result);
                sql_keep_stack_variant(stmt, &args->var_src);
                GS_RETURN_IFERR(sql_convert_variant(stmt, &args->var_src, GS_TYPE_STRING));
                sql_keep_stack_variant(stmt, &args->var_src);
                args->src = VALUE_PTR(text_t, &args->var_src);
                break;
            case REGEXP_ARG_PATTERN:
                SQL_EXEC_FUNC_ARG_EX2(curr, &args->var_pattern, result);
                sql_keep_stack_variant(stmt, &args->var_pattern);
                GS_RETURN_IFERR(sql_convert_variant(stmt, &args->var_pattern, GS_TYPE_STRING));
                sql_keep_stack_variant(stmt, &args->var_pattern);
                args->pattern = VALUE_PTR(text_t, &args->var_pattern);
                break;
            case REGEXP_ARG_REPLACE:
                SQL_EXEC_FUNC_ARG_EX2(curr, &args->var_replace_str, result);
                sql_keep_stack_variant(stmt, &args->var_replace_str);
                GS_RETURN_IFERR(sql_convert_variant(stmt, &args->var_replace_str, GS_TYPE_STRING));
                sql_keep_stack_variant(stmt, &args->var_replace_str);
                args->replace_str = VALUE_PTR(text_t, &args->var_replace_str);
                break;
            case REGEXP_ARG_POSITION:
                SQL_EXEC_FUNC_ARG_EX(curr, &args->var_pos, result);
                GS_RETURN_IFERR(var_as_floor_integer(&args->var_pos));
                args->offset = *VALUE_PTR(int32, &args->var_pos);
                break;
            case REGEXP_ARG_OCCUR:
                SQL_EXEC_FUNC_ARG_EX(curr, &args->var_occur, result);
                GS_RETURN_IFERR(var_as_floor_integer(&args->var_occur));
                args->occur = *VALUE_PTR(int32, &args->var_occur);
                break;
            case REGEXP_ARG_RETURN_OPT:
                SQL_EXEC_FUNC_ARG_EX(curr, &args->var_retopt, result);
                GS_RETURN_IFERR(var_as_floor_integer(&args->var_retopt));
                args->retopt = *VALUE_PTR(int32, &args->var_retopt);
                break;
            case REGEXP_ARG_MATCH_PARAM:
                GS_RETURN_IFERR(sql_exec_expr(stmt, curr, &args->var_match_param));
                if (args->var_match_param.is_null) {
                    args->match_param = NULL;
                    break;
                }
                SQL_CHECK_COLUMN_VAR(&args->var_match_param, result);
                sql_keep_stack_variant(stmt, &args->var_match_param);
                GS_RETURN_IFERR(sql_convert_variant(stmt, &args->var_match_param, GS_TYPE_STRING));
                sql_keep_stack_variant(stmt, &args->var_match_param);
                args->match_param = VALUE_PTR(text_t, &args->var_match_param);
                break;
            case REGEXP_ARG_SUBEXPR:
                SQL_EXEC_FUNC_ARG_EX(curr, &args->var_subexpr, result);
                GS_RETURN_IFERR(var_as_floor_integer(&args->var_subexpr));
                args->subexpr = *VALUE_PTR(int32, &args->var_subexpr);
                break;
            default: // REGEXP_ARG_DUMB the last one in the args type array, represent invalid
                break;
        }
        curr = curr->next;
    }
    return GS_SUCCESS;
}

status_t sql_func_regexp_count(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    regexp_args_t args;
    void *code = NULL;
    char *psz = NULL;
    int32 count;
    bool32 args_error_found;
    status_t ret;

    result->is_null = GS_FALSE;
    result->type = GS_TYPE_UNKNOWN;

    GS_RETURN_IFERR(sql_regexp_calc_args(stmt, func, g_count_arg_types, &args, result));

    args_error_found = (!args.var_pos.is_null && args.offset <= 0);
    if (args_error_found) {
        GS_THROW_ERROR(ERR_INVALID_FUNC_PARAMS, "position must be greater than 0");
        return GS_ERROR;
    }

    // if result is null, normally function should return
    // but if the pattern is not null, we should first make sure the pattern is correct
    // if some column is pending while calculating expr node, just return success
    if (args.var_pattern.is_null || result->type == GS_TYPE_COLUMN) {
        return GS_SUCCESS;
    }

    result->type = GS_TYPE_INTEGER;
    if ((uint32)args.offset > args.src->len) {
        count = 0;
        *(VALUE_PTR(int32, result)) = count;
        return GS_SUCCESS;
    }

    GS_RETURN_IFERR(sql_push(stmt, args.pattern->len * 2 + 1, (void **)&psz));
    GS_RETURN_IFERR(cm_replace_regexp_spec_chars(args.pattern, psz, args.pattern->len * 2 + 1));
    GS_LOG_DEBUG_INF("regular expression is: %s", psz);

    GS_RETURN_IFERR(cm_regexp_compile(&code, psz, args.match_param, GET_CHARSET_ID));

    ret = sql_func_regexp_count_core(stmt, result, code, &args);

    cm_regexp_free(code);
    code = NULL;
    return ret;
}

status_t sql_verify_regexp_instr(sql_verifier_t *verf, expr_node_t *func)
{
    GS_RETURN_IFERR(sql_verify_regexp_args(verf, func, g_instr_arg_types, "REGEXP_INSTR"));

    func->datatype = GS_TYPE_INTEGER;
    func->size = GS_INTEGER_SIZE;

    return GS_SUCCESS;
}

status_t sql_verify_regexp_substr(sql_verifier_t *verf, expr_node_t *func)
{
    GS_RETURN_IFERR(sql_verify_regexp_args(verf, func, g_substr_arg_types, "REGEXP_SUBSTR"));

    func->datatype = GS_TYPE_STRING;
    func->size = cm_get_datatype_strlen(func->argument->root->datatype, func->argument->root->size);

    return GS_SUCCESS;
}

status_t sql_regexp_instr_run(variant_t *result, regexp_args_t args, void *code)
{
    text_t posstr;
    regexp_substr_assist_t assist;
    status_t ret;
    int32 pos;
    do {
        // if result is null, just return success
        if (result->is_null) {
            ret = GS_SUCCESS;
            break;
        }

        result->type = GS_TYPE_INTEGER;
        assist.code = code;
        assist.subject = *args.src;
        assist.offset = args.offset - 1;
        assist.occur = args.occur;
        assist.subexpr = args.subexpr;
        assist.charset = GET_CHARSET_ID;
        ret = cm_regexp_instr(&pos, &assist, args.retopt);
        GS_BREAK_IF_ERROR(ret);

        if (pos > 1) {
            posstr.str = args.src->str;
            posstr.len = (uint32)pos - 1;
            ret = GET_DATABASE_CHARSET->length(&posstr, (uint32 *)&pos);
            GS_BREAK_IF_ERROR(ret);
            pos += 1;
        }

        *(VALUE_PTR(int32, result)) = pos;
    } while (GS_FALSE);
    return ret;
}


status_t sql_func_regexp_instr(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    regexp_args_t args;
    void *code = NULL;
    char *psz = NULL;
    bool32 args_error_found;
    status_t ret;

    result->is_null = GS_FALSE;
    result->type = GS_TYPE_UNKNOWN;

    GS_RETURN_IFERR(sql_regexp_calc_args(stmt, func, g_instr_arg_types, &args, result));

    args_error_found = (!args.var_pos.is_null && args.offset <= 0) || (!args.var_occur.is_null && args.occur <= 0) ||
        (!args.var_subexpr.is_null && args.subexpr < 0) || (!args.var_retopt.is_null && args.retopt < 0);
    if (args_error_found) {
        GS_THROW_ERROR(ERR_INVALID_REGEXP_INSTR_PARAM, args.offset, args.occur, args.subexpr, args.retopt);
        return GS_ERROR;
    }

    // if result is null, normally function should return
    // but if the pattern is not null, we should first make sure the pattern is correct
    // if some column is pending while calculating expr node, just return success
    GS_RETSUC_IFTRUE(args.var_pattern.is_null || result->type == GS_TYPE_COLUMN);

    GS_RETURN_IFERR(sql_push(stmt, args.pattern->len * 2 + 1, (void **)&psz));
    GS_RETURN_IFERR(cm_replace_regexp_spec_chars(args.pattern, psz, args.pattern->len * 2 + 1));
    GS_LOG_DEBUG_INF("regular expression is: %s", psz);

    GS_RETURN_IFERR(cm_regexp_compile(&code, psz, args.match_param, GET_CHARSET_ID));

    ret = sql_regexp_instr_run(result, args, code);

    cm_regexp_free(code);
    code = NULL;
    return ret;
}

static inline void sql_construct_rsa(regexp_substr_assist_t *rsa, void *code, regexp_args_t *args)
{
    rsa->code = code;
    rsa->subject = *(args->src);
    rsa->offset = args->offset - 1;
    rsa->occur = args->occur;
    rsa->subexpr = args->subexpr;
    rsa->charset = GET_CHARSET_ID;
}

status_t sql_func_regexp_substr(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    regexp_args_t args;
    void *code = NULL;
    char *psz = NULL;
    bool32 args_error_found;
    result->is_null = GS_FALSE;
    result->type = GS_TYPE_UNKNOWN;
    regexp_substr_assist_t assist;
    status_t ret = GS_SUCCESS;

    GS_RETURN_IFERR(sql_regexp_calc_args(stmt, func, g_substr_arg_types, &args, result));

    args_error_found = (!args.var_pos.is_null && args.offset <= 0) || (!args.var_occur.is_null && args.occur <= 0) ||
        (!args.var_subexpr.is_null && args.subexpr < 0);
    if (args_error_found) {
        GS_THROW_ERROR(ERR_INVALID_REGEXP_INSTR_PARAM_NO_OPT, args.offset, args.occur, args.subexpr);
        return GS_ERROR;
    }

    // if result is null, normally function should return
    // but if the pattern is not null, we should first make sure the pattern is correct
    // if some column is pending while calculating expr node, just return success
    GS_RETSUC_IFTRUE(args.var_pattern.is_null || result->type == GS_TYPE_COLUMN);

    GS_RETURN_IFERR(sql_push(stmt, args.pattern->len * 2 + 1, (void **)&psz));
    GS_RETURN_IFERR(cm_replace_regexp_spec_chars(args.pattern, psz, args.pattern->len * 2 + 1));
    GS_LOG_DEBUG_INF("regular expression is: %s", psz);

    GS_RETURN_IFERR(cm_regexp_compile(&code, psz, args.match_param, GET_CHARSET_ID));

    do {
        // if result is null, just return success
        if (result->is_null) {
            cm_regexp_free(code);
            return GS_SUCCESS;
        }

        result->type = GS_TYPE_STRING;
        sql_construct_rsa(&assist, code, &args);
        ret = cm_regexp_substr(VALUE_PTR(text_t, result), &assist);
        GS_BREAK_IF_ERROR(ret);
    } while (0);

    cm_regexp_free(code);
    code = NULL;
    GS_RETURN_IFERR(ret);

    if (result->v_text.len > 0) {
        // rebuild result buffer
        GS_RETURN_IFERR(sql_push(stmt, result->v_text.len, (void **)&psz));
        MEMS_RETURN_IFERR(memcpy_s(psz, result->v_text.len, result->v_text.str, result->v_text.len));
        result->v_text.str = psz;
    } else if (g_instance->sql.enable_empty_string_null) {
        SQL_SET_NULL_VAR(result);
    }

    return GS_SUCCESS;
}

status_t sql_verify_regexp_replace(sql_verifier_t *verf, expr_node_t *func)
{
    GS_RETURN_IFERR(sql_verify_regexp_args(verf, func, g_replace_arg_types, "REGEXP_REPLACE"));

    func->datatype = GS_TYPE_STRING;
    func->size = cm_get_datatype_strlen(func->argument->root->datatype, GS_MAX_COLUMN_SIZE);
    return GS_SUCCESS;
}

static status_t sql_func_regexp_replace_core(sql_stmt_t *stmt, text_t *res, const void *code, regexp_args_t *args)
{
    uint32 pos_start, pos_end;
    text_t sub_str, replace;
    bool32 is_first = GS_TRUE;
    regexp_substr_assist_t assist;

    if (args->var_replace_str.is_null) {
        replace.str = NULL;
        replace.len = 0;
    } else {
        replace = *args->replace_str;
    }
    if (args->var_occur.is_null) {
        args->occur = 0;
    }

    do {
        assist.code = code;
        assist.subject = *(args->src);
        assist.offset = args->offset - 1;
        assist.occur = args->occur;
        assist.subexpr = 0;
        assist.charset = GET_CHARSET_ID;
        GS_BREAK_IF_TRUE((uint32)args->offset > args->src->len);
        GS_RETURN_IFERR(cm_regexp_substr(&sub_str, &assist));
        GS_BREAK_IF_TRUE(sub_str.str == NULL);

        pos_start = (uint32)(sub_str.str - args->src->str);
        if (sub_str.len == 0) {
            if (is_first) {
                is_first = GS_FALSE;
            } else {
                pos_start++;
            }
        }
        pos_end = pos_start + sub_str.len;

        // copy pos characters which not matched
        GS_RETURN_IFERR(sql_func_concat_string(stmt, res, args->src, pos_start));
        // copy replaced characters
        GS_RETURN_IFERR(sql_func_concat_string(stmt, res, &replace, replace.len));
        // remove pos+replaced characters
        if (args->src->len < pos_end) {
            GS_THROW_ERROR_EX(ERR_ASSERT_ERROR, "source text len(%u) >= pos(%u) + replaced text len(%u)",
                args->src->len, pos_start, sub_str.len);
            return GS_ERROR;
        }
        CM_REMOVE_FIRST_N(args->src, pos_end);
        // if occur > 0, replace only once, if occur = 0, replace all
        GS_BREAK_IF_TRUE(args->occur > 0);
        args->offset = 1;
    } while (args->src->len > 0);

    GS_RETURN_IFERR(sql_func_concat_string(stmt, res, args->src, args->src->len));
    return GS_SUCCESS;
}

status_t sql_func_regexp_replace(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    regexp_args_t args;
    void *code = NULL;
    char *psz = NULL;
    bool32 args_error_found;
    status_t ret;
    text_t *res = VALUE_PTR(text_t, result);

    if (result->is_null) {
        return GS_SUCCESS;
    }

    result->is_null = GS_FALSE;
    result->type = GS_TYPE_UNKNOWN;
    args.var_pos.type = GS_TYPE_UNKNOWN;
    args.var_occur.type = GS_TYPE_UNKNOWN;

    GS_RETURN_IFERR(sql_regexp_calc_args(stmt, func, g_replace_arg_types, &args, result));

    args_error_found = (!args.var_pos.is_null && args.offset <= 0) || (!args.var_occur.is_null && args.occur < 0);
    if (args_error_found) {
        GS_THROW_ERROR(ERR_INVALID_REGEXP_INSTR_PARAM_NO_OPT, args.offset, args.occur, 0);
        return GS_ERROR;
    }
    // if some column is pending while calculating expr node, just return success
    GS_RETSUC_IFTRUE(result->type == GS_TYPE_COLUMN);

    result->type = GS_TYPE_STRING;
    res->len = 0;
    GS_RETURN_IFERR(sql_push(stmt, GS_MAX_COLUMN_SIZE, (void **)&res->str));

    if (args.var_pattern.is_null || args.var_src.is_null) {
        result->is_null = args.var_src.is_null;
        if (!args.var_src.is_null) {
            GS_RETURN_IFERR(cm_concat_n_string(res, GS_MAX_COLUMN_SIZE, args.src->str, args.src->len));
        }
        return GS_SUCCESS;
    }

    // if input of offset/ocuur is 'null' or '', just return
    if ((args.var_pos.is_null && args.var_pos.type != GS_TYPE_UNKNOWN) ||
        (args.var_occur.is_null && args.var_occur.type != GS_TYPE_UNKNOWN)) {
        return GS_SUCCESS;
    }

    // alloc memory for processing regular expressions
    GS_RETURN_IFERR(sql_push(stmt, args.pattern->len * 2 + 1, (void **)&psz));
    GS_RETURN_IFERR(cm_replace_regexp_spec_chars(args.pattern, psz, args.pattern->len * 2 + 1));
    GS_LOG_DEBUG_INF("regular expression is: %s", psz);
    GS_RETURN_IFERR(cm_regexp_compile(&code, psz, args.match_param, GET_CHARSET_ID));

    ret = sql_func_regexp_replace_core(stmt, res, code, &args);
    result->is_null = (res->len == 0 && g_instance->sql.enable_empty_string_null);
    cm_regexp_free(code);
    code = NULL;
    return ret;
}
