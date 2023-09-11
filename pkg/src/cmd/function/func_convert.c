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
 * func_convert.c
 *
 *
 * IDENTIFICATION
 * src/cmd/function/func_convert.c
 *
 * -------------------------------------------------------------------------
 */
#include "func_convert.h"
#include "srv_instance.h"

#define NUM_IS_POSITIVE 0xac
#define NUM_IS_NEGATIVE 0xbd

status_t sql_func_ascii(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t var;
    uint32 char_len = 0;

    CM_POINTER3(stmt, func, result);

    expr_tree_t *arg = func->argument;
    CM_POINTER(arg);

    SQL_EXEC_FUNC_ARG_EX(arg, &var, result);
    result->is_null = GS_FALSE;
    result->type = GS_TYPE_BIGINT;

    if (GS_IS_STRING_TYPE(var.type)) {
        if (var.v_text.len == 0) {
            result->is_null = GS_TRUE;
            return GS_SUCCESS;
        }
        if (GET_DATABASE_CHARSET->str_bytes(var.v_text.str, var.v_text.len, &char_len) != GS_SUCCESS) {
            GS_THROW_ERROR(ERR_NLS_INTERNAL_ERROR, "utf-8 buffer");
            return GS_ERROR;
        }

        if (char_len == 0) {
            result->is_null = GS_TRUE;
        } else {
            result->v_bigint = 0;
            for (uint32 i = 0; i < char_len; i++) {
                result->v_bigint = (uint8)var.v_text.str[i] + (((uint64)result->v_bigint) << 8);
            }
        }
    } else {
        if (GS_IS_BOOLEAN_TYPE(var.type)) {
            // convert true/false to 1/0
            var.type = GS_TYPE_INTEGER;
            var.v_int = var.v_bool ? 1 : 0;
        }

        sql_keep_stack_variant(stmt, &var);
        GS_RETURN_IFERR(sql_var_as_string(stmt, &var));
        if (var.v_text.len == 0) {
            result->is_null = GS_TRUE;
        } else {
            result->v_bigint = (uint8)var.v_text.str[0];
        }
    }

    return GS_SUCCESS;
}

status_t sql_verify_ascii(sql_verifier_t *verifier, expr_node_t *func)
{
    CM_POINTER2(verifier, func);

    if (GS_SUCCESS != sql_verify_func_node(verifier, func, 1, 1, GS_INVALID_ID32)) {
        return GS_ERROR;
    }

    func->datatype = GS_TYPE_BIGINT;
    func->size = GS_BIGINT_SIZE;

    return GS_SUCCESS;
}

static status_t sql_func_ascii_string(sql_stmt_t *stmt, variant_t *var, variant_t *result)
{
    uint32 pos_src = 0;
    uint32 one_char_len = 0;
    uint32 i = 0;
    uint32 pos = 0;
    text_t temp_tx;
    uint32 buff_len = var->v_text.len * 3;
    uint32 text_len = 0;
    uint8 tmp[UTF8_MAX_BYTE] = { 0 };
    sql_keep_stack_variant(stmt, var);
    GS_RETURN_IFERR(sql_push(stmt, buff_len, (void **)&result->v_text.str));
    result->v_text.len = buff_len;
    temp_tx = var->v_text;
    while (pos_src < temp_tx.len) {
        if (GET_DATABASE_CHARSET->str_bytes(temp_tx.str + pos_src, temp_tx.len - pos_src, &one_char_len) !=
            GS_SUCCESS) {
            SQL_POP(stmt);
            return GS_ERROR;
        }
        errno_t errcode = memcpy_s(result->v_text.str + text_len, one_char_len, temp_tx.str + pos_src, one_char_len);
        if (errcode != EOK) {
            SQL_POP(stmt);
            GS_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
            return GS_ERROR;
        }
        if (one_char_len == 1) {
            text_len++;
        } else {
            pos = one_char_len;
            if (GET_DATABASE_CHARSET->str_unicode((uint8 *)result->v_text.str + text_len, &pos) != GS_SUCCESS) {
                SQL_POP(stmt);
                return GS_ERROR;
            }
            for (i = 0; i < pos; i++) {
                tmp[i] = result->v_text.str[text_len + i];
            }
            result->v_text.str[text_len] = '\\';
            text_len++;
            for (i = 0; i < pos; i++) {
                result->v_text.str[text_len] = g_hex_map[tmp[i] >> 4];
                text_len++;
                result->v_text.str[text_len] = g_hex_map[tmp[i] & 0x0F];
                text_len++;
            }
        }
        pos_src += one_char_len;
    }
    result->v_text.len = text_len;
    if (text_len > GS_MAX_COLUMN_SIZE) {
        SQL_POP(stmt);
        GS_THROW_ERROR(ERR_VALUE_ERROR, "result string length is too long, beyond the max");
        return GS_ERROR;
    }
    SQL_POP(stmt);
    return GS_SUCCESS;
}

static status_t sql_func_ascii_nostring(sql_stmt_t *stmt, variant_t *var, variant_t *result)
{
    // buffer is enough for add string terminate
    GS_RETURN_IFERR(sql_var_as_string(stmt, var));

    if (var->v_text.len == 0) {
        result->is_null = GS_TRUE;
    } else {
        result->v_text = var->v_text;
    }

    if (var->v_text.len > GS_MAX_COLUMN_SIZE) {
        SQL_POP(stmt);
        GS_THROW_ERROR(ERR_VALUE_ERROR, "result string length is too long, beyond the max");
        return GS_ERROR;
    }

    SQL_POP(stmt);
    return GS_SUCCESS;
}

status_t sql_func_asciistr(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t var;
    expr_tree_t *arg = NULL;

    CM_POINTER3(stmt, func, result);

    arg = func->argument;
    SQL_EXEC_FUNC_ARG_EX(arg, &var, result);

    result->type = GS_TYPE_STRING;
    result->is_null = GS_FALSE;

    if (GS_IS_STRING_TYPE(var.type)) {
        return sql_func_ascii_string(stmt, &var, result);
    } else {
        return sql_func_ascii_nostring(stmt, &var, result);
    }
}

status_t sql_verify_asciistr(sql_verifier_t *verifier, expr_node_t *func)

{
    uint32 asciistr_len;

    CM_POINTER(func);

    GS_RETURN_IFERR(sql_verify_func_node(verifier, func, 1, 1, GS_INVALID_ID32));

    func->datatype = GS_TYPE_STRING;
    asciistr_len = cm_get_datatype_strlen(func->argument->root->datatype, func->argument->root->size) * 3;
    func->size = (uint16)MIN(asciistr_len, GS_MAX_COLUMN_SIZE);
    return GS_SUCCESS;
}

status_t sql_func_cast(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    char *buf = NULL;
    expr_tree_t *arg1 = func->argument;
    expr_tree_t *arg2 = arg1->next;
    const nlsparams_t *nlsparams = NULL;
    text_buf_t buffer;
    status_t status;

    if (sql_exec_expr(stmt, arg1, result) != GS_SUCCESS) {
        return GS_ERROR;
    }
    SQL_CHECK_COLUMN_VAR(result, result);

    if (GS_IS_LOB_TYPE(result->type)) {
        if (GS_IS_LOB_TYPE(arg2->root->value.v_type.datatype)) {
            return GS_SUCCESS;
        } else {
            GS_RETURN_IFERR(sql_get_lob_value(stmt, result));
        }
    }
    if (result->is_null) {
        result->type = arg2->root->value.v_type.datatype;
        return GS_SUCCESS;
    }

    sql_keep_stack_variant(stmt, result);

    nlsparams = SESSION_NLS(stmt);
    GS_RETURN_IFERR(sql_push(stmt, GS_CONVERT_BUFFER_SIZE, (void **)&buf));

    CM_INIT_TEXTBUF(&buffer, GS_CONVERT_BUFFER_SIZE, buf);

    do {
        if (arg2->root->value.v_type.is_array == GS_TRUE) {
            return GS_ERROR;
        } else if (arg2->root->datatype == GS_TYPE_COLLECTION) {
            return GS_ERROR;
        } else {
            status = var_convert(nlsparams, result, arg2->root->value.v_type.datatype, &buffer);
            GS_BREAK_IF_ERROR(status);
            if (arg2->root->exec_default) {
                status = sql_apply_typmode(result, &arg2->root->value.v_type, buf, GS_FALSE);
            } else {
                status = sql_apply_typmode(result, &arg2->root->value.v_type, buf, GS_TRUE);
            }
        }

        GS_BREAK_IF_ERROR(status);
    } while (0);

    if (status != GS_SUCCESS) {
        cm_set_error_loc(func->loc);
        SQL_POP(stmt);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t sql_verify_cast_to_collection(expr_node_t *func, expr_tree_t *arg1, expr_tree_t *arg2)
{
    return GS_ERROR;
}
status_t sql_verify_cast(sql_verifier_t *verf, expr_node_t *func)
{
    expr_tree_t *arg1 = NULL;
    expr_tree_t *arg2 = NULL;

    if (SECUREC_UNLIKELY(func->argument == NULL)) {
        GS_SRC_THROW_ERROR_EX(func->loc, ERR_SQL_SYNTAX_ERROR, "not enough argument for cast");
        return GS_ERROR;
    }

    arg1 = func->argument;
    if (sql_verify_expr_node(verf, arg1->root) != GS_SUCCESS) {
        return GS_ERROR;
    }

    arg2 = arg1->next;
    if (SECUREC_UNLIKELY(arg2 == NULL)) {
        GS_SRC_THROW_ERROR_EX(arg1->loc, ERR_SQL_SYNTAX_ERROR, "not enough argument for cast");
        return GS_ERROR;
    }

    if (TREE_DATATYPE(arg2) == GS_TYPE_COLLECTION) {
        GS_RETURN_IFERR(sql_verify_cast_to_collection(func, arg1, arg2));
    } else {
        func->typmod = EXPR_VALUE(typmode_t, arg2);
        /* LOB types are special types, they cannot be cast directly */
        if (GS_IS_LOB_TYPE(func->typmod.datatype)) {
            GS_SET_ERROR_MISMATCH_EX(func->typmod.datatype);
            cm_set_error_loc(arg2->loc);
            return GS_ERROR;
        }
        // static datatype check
        if (sql_is_skipped_expr(arg1)) {
            return GS_SUCCESS;
        }
        if (!var_datatype_matched(TREE_DATATYPE(arg2), TREE_DATATYPE(arg1))) {
            GS_SRC_ERROR_MISMATCH(TREE_LOC(arg1), TREE_DATATYPE(arg2), TREE_DATATYPE(arg1));
            return GS_ERROR;
        }
    }

    sql_infer_func_optmz_mode(verf, func);

    // cast STRING type into a DATETIME type depends on the SESSION datetime format
    if (GS_IS_STRING_TYPE(TREE_DATATYPE(arg1)) && GS_IS_DATETIME_TYPE(TREE_DATATYPE(arg2)) &&
        NODE_IS_OPTMZ_CONST(func)) {
        sql_add_first_exec_node(verf, func);
    }

    return GS_SUCCESS;
}

status_t sql_func_chr(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t var;

    CM_POINTER3(stmt, func, result);

    expr_tree_t *arg = func->argument;
    CM_POINTER(arg);

    SQL_EXEC_FUNC_ARG_EX(arg, &var, result);

    if (var_as_integer(&var) != GS_SUCCESS) {
        cm_set_error_loc(arg->loc);
        return GS_ERROR;
    }

    if (var.v_int < 0 || var.v_int > 127) {
        GS_SRC_THROW_ERROR(arg->loc, ERR_INVALID_FUNC_PARAMS, "argument value of the function must between [0, 127]");
        return GS_ERROR;
    }

    GS_RETURN_IFERR(sql_push(stmt, 1, (void **)&result->v_text.str));

    *result->v_text.str = (char)var.v_int;
    result->v_text.len = 1;
    result->type = GS_TYPE_STRING;
    result->is_null = GS_FALSE;
    return GS_SUCCESS;
}
status_t sql_verify_chr(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 1, 1, GS_INVALID_ID32) != GS_SUCCESS) {
        return GS_ERROR;
    }

    func->datatype = GS_TYPE_STRING;
    func->size = 1;

    return GS_SUCCESS;
}

static status_t sql_func_decode_core(sql_stmt_t *stmt, expr_node_t *func, variant_t *result, expr_tree_t *arg,
    gs_type_t result_type)
{
    char *buf = NULL;
    text_buf_t buffer;

    SQL_EXEC_FUNC_ARG_EX(arg, result, result);
    sql_keep_stack_variant(stmt, result);

    if (func->typmod.is_array == GS_TRUE) {
        return GS_ERROR;
    } else {
        GS_RETURN_IFERR(sql_push(stmt, GS_STRING_BUFFER_SIZE, (void **)&buf));
        CM_INIT_TEXTBUF(&buffer, GS_STRING_BUFFER_SIZE, buf);
        if (var_convert(SESSION_NLS(stmt), result, result_type, &buffer) != GS_SUCCESS) {
            SQL_POP(stmt);
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

status_t sql_func_decode(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    expr_tree_t *arg = func->argument;
    variant_t decode_var, cmp_var;
    int32 cmp_result;

    CM_POINTER3(stmt, func, result);
    SQL_EXEC_FUNC_ARG_EX2(arg, &decode_var, result);
    sql_keep_stack_variant(stmt, &decode_var);

    // check all decode param can convert to func type in func pre_execute in the future
    arg = arg->next;
    gs_type_t result_type = func->datatype;
    if (result_type == GS_TYPE_UNKNOWN) {
        variant_t third_var;
        SQL_EXEC_FUNC_ARG_EX2(arg->next, &third_var, &third_var);
        if (third_var.type == GS_TYPE_CHAR) {
            result_type = GS_TYPE_STRING;
        } else if (third_var.type == GS_TYPE_BINARY) {
            result_type = GS_TYPE_VARBINARY;
        } else {
            result_type = third_var.type;
        }
    }
    /* decode(exp1, expr2, exp3 [null]
    decode(exp1, expr2, exp3 [exp4]
    decode(exp1, expr2, exp3 [exp4, exp5] ...
    decode(exp1, expr2, exp3 [exp4, exp5] ... [default]
    */
    for (;;) {
        if (arg->next == NULL) {
            // the last argument is default value
            break;
        }

        SQL_EXEC_FUNC_ARG_EX2(arg, &cmp_var, result);

        // compare decode_var and cmp_var, if equal return value behind the cmp_var
        if (decode_var.is_null && cmp_var.is_null) {
            cmp_result = 0;
        } else {
            GS_RETURN_IFERR(sql_compare_variant(stmt, &decode_var, &cmp_var, &cmp_result));
        }

        arg = arg->next;

        if (cmp_result != 0) {
            if (arg->next == NULL) {
                SQL_SET_NULL_VAR(result);
                return GS_SUCCESS;
            }

            arg = arg->next;
            continue;
        }
        break;
    }

    GS_RETURN_IFERR(sql_func_decode_core(stmt, func, result, arg, result_type));
    return GS_SUCCESS;
}

gs_type_t decode_compatible_datatype(expr_node_t *func, expr_node_t *node, gs_type_t typ1, gs_type_t typ2)
{
    if (NODE_IS_RES_NULL(node) || (func->typmod.is_array && !node->typmod.is_array)) {
        return typ1;
    }

    // The data type of decode is determined by the first result parameter, that is, the third parameter.
    // If the type is CHAR or BINARY, change it to a variable-length type.
    if (typ1 == typ2) {
        if (typ1 == GS_TYPE_CHAR) {
            return GS_TYPE_STRING;
        }
        if (typ1 == GS_TYPE_BINARY) {
            return GS_TYPE_VARBINARY;
        }
        if (GS_IS_NUMBER_TYPE(typ1) && (func->precision != node->precision || func->scale != node->scale)) {
            // if precision and scale not same, set them to unspecified values
            func->precision = GS_UNSPECIFIED_NUM_PREC;
            func->scale = GS_UNSPECIFIED_NUM_SCALE;
        }
        return typ1;
    }

    if (GS_IS_NUMERIC_TYPE(typ1) && GS_IS_STRING_TYPE(typ2)) {
        return GS_TYPE_STRING;
    }

    if (GS_IS_NUMERIC_TYPE(typ1) && typ2 == GS_TYPE_REAL) {
        func->typmod = node->typmod;
        return typ2;
    }

    if (GS_IS_NUMERIC_TYPE2(typ1, typ2) && typ1 != GS_TYPE_REAL) {
        func->precision = GS_UNSPECIFIED_NUM_PREC;
        func->scale = GS_UNSPECIFIED_NUM_SCALE;
        return GS_TYPE_NUMBER;
    }

    return typ1;
}

status_t sql_verify_decode(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);
    expr_tree_t *expr = func->argument;
    uint16 size;

    if (sql_verify_func_node(verf, func, 3, GS_MAX_DECODE_ARGUMENTS, GS_INVALID_ID32) != GS_SUCCESS) {
        return GS_ERROR;
    }

    func->size = 0;
    expr = expr->next->next;
    func->typmod = expr->root->typmod;

    while (expr != NULL) {
        if (func->typmod.is_array == GS_TRUE || expr->root->typmod.is_array == GS_TRUE) {
            return GS_ERROR;
        } else if (!var_datatype_matched(func->datatype, expr->root->datatype)) {
            GS_THROW_ERROR(ERR_TYPE_MISMATCH, get_datatype_name_str(func->datatype),
                get_datatype_name_str(expr->root->datatype));
            return GS_ERROR;
        }

        func->datatype = decode_compatible_datatype(func, expr->root, func->datatype, expr->root->datatype);
        size = (uint16)cm_get_datatype_strlen(expr->root->datatype, expr->root->size);
        if (func->size < size) {
            func->size = size;
        }

        expr = expr->next;

        if (expr != NULL && expr->next != NULL) {
            expr = expr->next;
        }
    }

    return GS_SUCCESS;
}

status_t sql_adjust_if_type(gs_type_t l_type, gs_type_t r_type, gs_type_t *result_type)
{
    do {
        if (l_type == GS_TYPE_UNKNOWN || r_type == GS_TYPE_UNKNOWN) {
            *result_type = GS_TYPE_UNKNOWN;
            break;
        }

        if (GS_IS_RAW_TYPE(l_type) || GS_IS_RAW_TYPE(r_type)) {
            gs_type_t tmp_type = GS_IS_RAW_TYPE(l_type) ? r_type : l_type;
            if (!var_datatype_matched(GS_TYPE_RAW, tmp_type)) {
                GS_THROW_ERROR(ERR_TYPE_MISMATCH, "RAW", get_datatype_name_str(tmp_type));
                return GS_ERROR;
            }
            *result_type = GS_TYPE_RAW;
            break;
        }

        if (GS_IS_BINARY_TYPE(l_type) || GS_IS_BINARY_TYPE(r_type)) {
            *result_type = GS_TYPE_VARBINARY;
            break;
        }

        if (GS_IS_STRING_TYPE(l_type) || GS_IS_STRING_TYPE(r_type)) {
            *result_type = GS_TYPE_STRING;
            break;
        }

        if (GS_IS_CLOB_TYPE(l_type) || GS_IS_CLOB_TYPE(r_type)) {
            gs_type_t tmp_type = GS_IS_CLOB_TYPE(l_type) ? r_type : l_type;
            if (!var_datatype_matched(GS_TYPE_CLOB, tmp_type)) {
                GS_THROW_ERROR(ERR_TYPE_MISMATCH, "CLOB", get_datatype_name_str(tmp_type));
                return GS_ERROR;
            }
            *result_type = GS_TYPE_CLOB;
            break;
        }

        if (var_datatype_matched(l_type, r_type)) {
            typmode_t typmode, typmod1, typmod2;
            SQL_INIT_TYPEMOD(typmod1);
            SQL_INIT_TYPEMOD(typmod2);
            typmod1.datatype = l_type;
            typmod2.datatype = r_type;
            GS_RETURN_IFERR(cm_combine_typmode(typmod1, GS_FALSE, typmod2, GS_FALSE, &typmode));
            *result_type = typmode.datatype;
            break;
        }

        *result_type = GS_TYPE_STRING;
    } while (0);

    return GS_SUCCESS;
}

status_t sql_func_if(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    char *buf = NULL;
    bool32 pending = GS_FALSE;
    bool32 match_res;
    cond_result_t cond_result;
    expr_tree_t *result_arg = NULL;
    text_buf_t buffer;

    GS_RETURN_IFERR(sql_match_cond_argument(stmt, func->cond_arg->root, &pending, &cond_result));
    if (pending) {
        SQL_SET_COLUMN_VAR(result);
        return GS_SUCCESS;
    }
    match_res = (cond_result == COND_TRUE);

    result_arg = match_res ? func->argument : func->argument->next;
    SQL_EXEC_FUNC_ARG_EX(result_arg, result, result);
    sql_keep_stack_variant(stmt, result);

    // this block could be delete when befor_execute was supported!
    gs_type_t return_type = func->datatype;
    if (return_type == GS_TYPE_UNKNOWN) {
        variant_t tmp_var;
        expr_tree_t *other_arg = match_res ? func->argument->next : func->argument;

        SQL_EXEC_FUNC_ARG_EX2(other_arg, &tmp_var, &tmp_var);
        GS_RETURN_IFERR(sql_adjust_if_type(result->type, tmp_var.type, &return_type));
    }

    GS_RETURN_IFERR(sql_push(stmt, GS_STRING_BUFFER_SIZE, (void **)&buf));
    CM_INIT_TEXTBUF(&buffer, GS_STRING_BUFFER_SIZE, buf);

    if (var_convert(SESSION_NLS(stmt), result, return_type, &buffer)) {
        SQL_POP(stmt);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t sql_verify_if(sql_verifier_t *verf, expr_node_t *func)
{
    cond_tree_t *cond_arg = NULL;
    expr_tree_t *arg1 = NULL;
    expr_tree_t *arg2 = NULL;
    expr_tree_t *expr = NULL;

    uint16 size;
    uint32 old_excl_flags;
    uint32 new_excl_flags;

    cond_arg = func->cond_arg;
    arg1 = func->argument;

    if (arg1 == NULL) {
        GS_SRC_THROW_ERROR_EX(func->loc, ERR_SQL_SYNTAX_ERROR, "not enough argument for if");
        return GS_ERROR;
    }

    arg2 = arg1->next;
    CM_POINTER(arg2);

    old_excl_flags = verf->excl_flags;
    new_excl_flags = verf->excl_flags & (SQL_EXCL_LOB_COL ^ 0xffffffff);

    verf->excl_flags = new_excl_flags;
    GS_RETURN_IFERR(sql_verify_cond(verf, cond_arg));
    verf->excl_flags = old_excl_flags;

    GS_RETURN_IFERR(sql_verify_expr_node(verf, arg1->root));

    GS_RETURN_IFERR(sql_verify_expr_node(verf, arg2->root));

    GS_RETURN_IFERR(sql_adjust_if_type(arg1->root->datatype, arg2->root->datatype, &func->datatype));
    func->size = 0;
    expr = func->argument;
    while (expr != NULL) {
        size = (uint16)cm_get_datatype_strlen(expr->root->datatype, expr->root->size);
        if (func->size < size) {
            func->size = size;
        }

        expr = expr->next;
    }
    return GS_SUCCESS;
}

static gs_type_t sql_get_number_compatible_datatype(gs_type_t typ1, gs_type_t typ2)
{
    gs_type_t result_type = GS_TYPE_REAL;
    do {
        if (typ1 == GS_TYPE_REAL || typ2 == GS_TYPE_REAL) {
            result_type = GS_TYPE_REAL;
            break;
        }

        if (GS_IS_INTEGER_TYPE(typ1) && GS_IS_INTEGER_TYPE(typ2)) {
            if (GS_IS_UNSIGNED_INTEGER_TYPE(typ1) || GS_IS_UNSIGNED_INTEGER_TYPE(typ2)) {
                result_type = GS_TYPE_UINT64;
            } else {
                result_type = GS_TYPE_BIGINT;
            }
            break;
        }

        if (GS_IS_NUMBER_TYPE(typ1) || GS_IS_NUMBER_TYPE(typ2)) {
            result_type = GS_TYPE_NUMBER;
            break;
        }
    } while (0);

    return result_type;
}

gs_type_t sql_get_ifnull_compatible_datatype(gs_type_t typ1, gs_type_t typ2)
{
    if (typ1 == typ2) {
        return typ1;
    }

    gs_type_t result_type = GS_TYPE_VARCHAR;
    do {
        if (typ1 == GS_TYPE_BLOB || typ2 == GS_TYPE_BLOB) {
            result_type = GS_TYPE_BLOB;
            break;
        }

        if (typ1 == GS_TYPE_CLOB || typ2 == GS_TYPE_CLOB) {
            if (GS_IS_BINARY_TYPE(typ1) || GS_IS_BINARY_TYPE(typ2) || GS_IS_RAW_TYPE(typ1) || GS_IS_RAW_TYPE(typ2)) {
                result_type = GS_TYPE_BLOB;
            } else {
                result_type = GS_TYPE_CLOB;
            }
            break;
        }

        if (GS_IS_BINARY_TYPE(typ1) || GS_IS_BINARY_TYPE(typ2)) {
            result_type = GS_TYPE_VARBINARY;
            break;
        }

        if (GS_IS_NUMERIC_TYPE(typ1) && GS_IS_NUMERIC_TYPE(typ2)) {
            result_type = sql_get_number_compatible_datatype(typ1, typ2);
            break;
        }

        if (GS_IS_DATETIME_TYPE(typ1) && GS_IS_DATETIME_TYPE(typ2)) {
            result_type = GS_TYPE_TIMESTAMP;
            break;
        }
    } while (0);

    return result_type;
}

static void sql_get_datatype_precision_scale(typmode_t *typmode)
{
    switch (typmode->datatype) {
        case GS_TYPE_UTINYINT:
        case GS_TYPE_TINYINT:
            typmode->precision = 3;
            typmode->scale = 0;
            break;
        case GS_TYPE_USMALLINT:
        case GS_TYPE_SMALLINT:
            typmode->precision = 5;
            typmode->scale = 0;
            break;
        case GS_TYPE_UINT32:
        case GS_TYPE_INTEGER:
            typmode->precision = 10;
            typmode->scale = 0;
            break;
        case GS_TYPE_BIGINT:
            typmode->precision = 19;
            typmode->scale = 0;
            break;
        case GS_TYPE_UINT64:
            typmode->precision = 20;
            typmode->scale = 0;
            break;
        default:
            break;
    }
}

static inline uint16 sql_get_datatype_varchar_size(typmode_t *typmode)
{
    uint32 size = (uint32)typmode->size;
    size = cm_get_datatype_strlen(typmode->datatype, size);
    return (uint16)size;
}

static void sql_get_datatype_string_attr(typmode_t *func_typmode, typmode_t *typmode1, typmode_t *typmode2)
{
    if (GS_IS_STRING_TYPE(typmode1->datatype)) {
        func_typmode->charset = typmode1->charset;
        func_typmode->collate = typmode1->collate;
    } else if (GS_IS_STRING_TYPE(typmode2->datatype)) {
        func_typmode->charset = typmode2->charset;
        func_typmode->collate = typmode2->collate;
    } else {
        func_typmode->charset = 0;
        func_typmode->collate = 0;
    }
}

static void sql_get_num_typmode(typmode_t *func_typmode, typmode_t *typmode1, typmode_t *typmode2, gs_type_t type)
{
    sql_get_datatype_precision_scale(typmode1);
    sql_get_datatype_precision_scale(typmode2);
    if (typmode1->precision == GS_UNSPECIFIED_NUM_PREC || typmode2->precision == GS_UNSPECIFIED_NUM_PREC) {
        func_typmode->precision = GS_UNSPECIFIED_NUM_PREC;
        func_typmode->scale = GS_UNSPECIFIED_NUM_SCALE;
        func_typmode->size = GS_IS_NUMBER2_TYPE(type) ? MAX_DEC2_BYTE_SZ : MAX_DEC_BYTE_SZ;
        return;
    }
    func_typmode->scale = MAX(typmode1->scale, typmode2->scale);
    func_typmode->precision =
        MAX(typmode1->precision - typmode1->scale, typmode2->precision - typmode2->scale) + func_typmode->scale;
    func_typmode->size = GS_IS_NUMBER2_TYPE(type) ? MAX_DEC2_BYTE_BY_PREC(func_typmode->precision) :
                                                    MAX_DEC_BYTE_BY_PREC(func_typmode->precision);
}

static void sql_get_datatype_typmode(typmode_t *func_typmode, typmode_t *typmode1, typmode_t *typmode2)
{
    func_typmode->precision = func_typmode->scale = 0;
    switch (func_typmode->datatype) {
        case GS_TYPE_UINT32:
        case GS_TYPE_INTEGER:
            func_typmode->size = sizeof(int32);
            break;
        case GS_TYPE_BIGINT:
            func_typmode->size = sizeof(int64);
            break;
        case GS_TYPE_REAL:
            func_typmode->size = sizeof(double);
            break;
        case GS_TYPE_NUMBER:
        case GS_TYPE_DECIMAL:
        case GS_TYPE_NUMBER2:
            sql_get_num_typmode(func_typmode, typmode1, typmode2, func_typmode->datatype);
            break;
        case GS_TYPE_DATE:
            func_typmode->size = sizeof(date_t);
            break;
        case GS_TYPE_TIMESTAMP:
        case GS_TYPE_TIMESTAMP_LTZ:
        case GS_TYPE_TIMESTAMP_TZ_FAKE:
            func_typmode->size = sizeof(timestamp_t);
            func_typmode->precision = MAX(typmode1->precision, typmode2->precision);
            break;
        case GS_TYPE_TIMESTAMP_TZ:
            func_typmode->size = sizeof(timestamp_tz_t);
            func_typmode->precision = MAX(typmode1->precision, typmode2->precision);
            break;
        case GS_TYPE_CHAR:
        case GS_TYPE_VARCHAR:
        case GS_TYPE_STRING: {
            uint16 size1 = sql_get_datatype_varchar_size(typmode1);
            uint16 size2 = sql_get_datatype_varchar_size(typmode2);
            func_typmode->size = MAX(size1, size2);
            sql_get_datatype_string_attr(func_typmode, typmode1, typmode2);
        } break;
        case GS_TYPE_BINARY:
        case GS_TYPE_VARBINARY:
        case GS_TYPE_RAW: {
            uint16 size1 = sql_get_datatype_varchar_size(typmode1);
            uint16 size2 = sql_get_datatype_varchar_size(typmode2);
            func_typmode->size = MAX(size1, size2);
        } break;
        case GS_TYPE_CLOB:
        case GS_TYPE_BLOB:
        case GS_TYPE_IMAGE:
            func_typmode->size = GS_MAX_COLUMN_SIZE;
            break;
        case GS_TYPE_BOOLEAN:
            func_typmode->size = sizeof(bool32);
            break;
        case GS_TYPE_INTERVAL_YM:
            func_typmode->size = sizeof(interval_ym_t);
            func_typmode->year_prec = MAX(typmode1->year_prec, typmode2->year_prec);
            break;
        case GS_TYPE_INTERVAL_DS:
            func_typmode->size = sizeof(interval_ds_t);
            func_typmode->day_prec = MAX(typmode1->day_prec, typmode2->day_prec);
            func_typmode->frac_prec = MAX(typmode1->frac_prec, typmode2->frac_prec);
            break;
        case GS_TYPE_UINT64:
            func_typmode->size = sizeof(uint64);
            break;
        case GS_TYPE_SMALLINT:
            func_typmode->size = sizeof(int16);
            break;
        case GS_TYPE_USMALLINT:
            func_typmode->size = sizeof(uint16);
            break;
        case GS_TYPE_TINYINT:
            func_typmode->size = sizeof(int8);
            break;
        case GS_TYPE_UTINYINT:
            func_typmode->size = sizeof(uint8);
            break;
        default:
            func_typmode->size = GS_MAX_COLUMN_SIZE;
            break;
    }
}

status_t sql_verify_ifnull(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);
    if (sql_verify_func_node(verf, func, 2, 2, GS_INVALID_ID32) != GS_SUCCESS) {
        return GS_ERROR;
    }

    expr_tree_t *arg1 = func->argument;
    expr_tree_t *arg2 = arg1->next;

    if (TREE_IS_RES_NULL(arg1)) {
        func->typmod = TREE_TYPMODE(arg2);
        return GS_SUCCESS;
    }
    if (TREE_IS_RES_NULL(arg2)) {
        func->typmod = TREE_TYPMODE(arg1);
        return GS_SUCCESS;
    }

    typmode_t typmode1, typmode2;
    typmode1 = TREE_TYPMODE(arg1);
    typmode2 = TREE_TYPMODE(arg2);
    if (typmode1.datatype == GS_TYPE_UNKNOWN || typmode2.datatype == GS_TYPE_UNKNOWN) {
        func->typmod.datatype = GS_TYPE_UNKNOWN;
        return GS_SUCCESS;
    }

    func->typmod.datatype = sql_get_ifnull_compatible_datatype(typmode1.datatype, typmode2.datatype);
    sql_get_datatype_typmode(&func->typmod, &typmode1, &typmode2);

    return GS_SUCCESS;
}

status_t sql_func_ifnull(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    expr_tree_t *arg1 = NULL;
    expr_tree_t *arg2 = NULL;
    variant_t var1, var2;
    arg1 = func->argument;
    arg2 = arg1->next;

    GS_RETURN_IFERR(sql_exec_expr(stmt, arg1, &var1));
    SQL_CHECK_COLUMN_VAR(&var1, result);
    sql_keep_stack_variant(stmt, &var1);

    GS_RETURN_IFERR(sql_exec_expr(stmt, arg2, &var2));
    SQL_CHECK_COLUMN_VAR(&var2, result);
    sql_keep_stack_variant(stmt, &var2);

    *result = (var1.is_null) ? var2 : var1;

    if (TREE_IS_RES_NULL(arg1)) {
        return GS_SUCCESS;
    }

    if (TREE_IS_RES_NULL(arg2)) {
        return GS_SUCCESS;
    }

    gs_type_t result_type = func->typmod.datatype;
    if (result_type == GS_TYPE_UNKNOWN) {
        result_type = sql_get_ifnull_compatible_datatype(var1.type, var2.type);
    }

    if (!GS_IS_LOB_TYPE(result_type) && GS_IS_LOB_TYPE(result->type)) {
        // convert lob to other datatype
        GS_RETURN_IFERR(sql_get_lob_value(stmt, result));
        GS_RETURN_IFERR(sql_convert_variant(stmt, result, result_type));
    } else if (result->type != result_type) {
        GS_RETURN_IFERR(sql_convert_variant(stmt, result, result_type));
    }

    return GS_SUCCESS;
}

status_t sql_func_lnnvl(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    bool32 pending = GS_FALSE;
    bool32 match_res;
    cond_result_t cond_result;

    GS_RETURN_IFERR(sql_match_cond_argument(stmt, func->cond_arg->root, &pending, &cond_result));
    if (pending) {
        SQL_SET_COLUMN_VAR(result);
        return GS_SUCCESS;
    }
    match_res = (cond_result == COND_TRUE);

    result->is_null = GS_FALSE;
    result->type = func->datatype;
    if (match_res) {
        result->v_bool = GS_FALSE;
    } else {
        result->v_bool = GS_TRUE;
    }

    return GS_SUCCESS;
}

bool32 chk_lnnvl_unsupport_cmp_type(cond_node_t *cond)
{
    switch (cond->cmp->type) {
        case CMP_TYPE_EQUAL:
        case CMP_TYPE_GREAT:
        case CMP_TYPE_GREAT_EQUAL:
        case CMP_TYPE_LESS:
        case CMP_TYPE_LESS_EQUAL:
        case CMP_TYPE_NOT_EQUAL:
        case CMP_TYPE_IS_NULL:
        case CMP_TYPE_IS_NOT_NULL:
        case CMP_TYPE_LIKE:
        case CMP_TYPE_NOT_LIKE:
        case CMP_TYPE_REGEXP:
        case CMP_TYPE_NOT_REGEXP:
        case CMP_TYPE_EXISTS:
        case CMP_TYPE_NOT_EXISTS:
        case CMP_TYPE_REGEXP_LIKE:
        case CMP_TYPE_NOT_REGEXP_LIKE:
        case CMP_TYPE_IS_JSON:
        case CMP_TYPE_IS_NOT_JSON:
            return GS_FALSE;
        default:
            return GS_TRUE;
    }
}

status_t sql_verify_lnnvl(sql_verifier_t *verf, expr_node_t *func)
{
    cond_tree_t *cond_arg = func->cond_arg;
    uint32 old_excl_flags;

    if (cond_arg == NULL) {
        GS_SRC_THROW_ERROR(func->loc, ERR_SQL_SYNTAX_ERROR, "not enough argument for LNNVL");
        return GS_ERROR;
    }

    if (cond_arg->root->type == COND_NODE_AND || cond_arg->root->type == COND_NODE_OR) {
        GS_SRC_THROW_ERROR(cond_arg->loc, ERR_INVALID_FUNC_PARAMS, "invalid argument for LNNVL function");
        return GS_ERROR;
    }

    if (chk_lnnvl_unsupport_cmp_type(cond_arg->root)) {
        GS_SRC_THROW_ERROR(cond_arg->loc, ERR_INVALID_FUNC_PARAMS, "invalid argument for LNNVL function");
        return GS_ERROR;
    }
    old_excl_flags = verf->excl_flags;
    verf->excl_flags |= SQL_EXCL_STAR;
    GS_RETURN_IFERR(sql_verify_cond(verf, cond_arg));
    verf->excl_flags = old_excl_flags;

    func->datatype = GS_TYPE_BOOLEAN;
    func->size = GS_BOOLEAN_SIZE;

    return GS_SUCCESS;
}

status_t sql_func_nullif(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    CM_POINTER3(stmt, func, result);
    expr_tree_t *arg1 = NULL;
    expr_tree_t *arg2 = NULL;
    variant_t var1;
    variant_t var2;
    int32 cmp_result;
    arg1 = func->argument;
    arg2 = arg1->next;

    GS_RETURN_IFERR(sql_exec_expr(stmt, arg1, &var1));
    SQL_CHECK_COLUMN_VAR(&var1, result);
    sql_keep_stack_variant(stmt, &var1);

    GS_RETURN_IFERR(sql_exec_expr(stmt, arg2, &var2));
    SQL_CHECK_COLUMN_VAR(&var2, result);
    sql_keep_stack_variant(stmt, &var2);

    gs_type_t result_type = func->typmod.datatype;

    if (result_type == GS_TYPE_UNKNOWN) { // for bind param: nullif(?,?)
        typmode_t typmode, typmod1, typmod2;
        SQL_INIT_TYPEMOD(typmod1);
        SQL_INIT_TYPEMOD(typmod2);
        typmod1.datatype = var1.type;
        typmod2.datatype = var2.type;
        GS_RETURN_IFERR(cm_combine_typmode(typmod1, GS_FALSE, typmod2, GS_FALSE, &typmode));
        result_type = GS_IS_NUMERIC_TYPE(typmode.datatype) ? typmode.datatype : var1.type;
    }

    GS_RETURN_IFERR(sql_compare_variant(stmt, &var1, &var2, &cmp_result));

    if (cmp_result == 0) {
        result->type = GS_DATATYPE_OF_NULL;
        result->is_null = GS_TRUE;
    } else {
        *result = var1;
    }

    if (result->type != result_type && GS_IS_STRING_TYPE(result->type) != GS_TRUE) {
        GS_RETURN_IFERR(sql_convert_variant(stmt, result, result_type));
    }

    return GS_SUCCESS;
}

status_t sql_verify_nullif(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);
    if (sql_verify_func_node(verf, func, 2, 2, GS_INVALID_ID32) != GS_SUCCESS) {
        return GS_ERROR;
    }

    expr_tree_t *arg1 = func->argument;
    expr_tree_t *arg2 = arg1->next;

    if (TREE_IS_RES_NULL(arg1)) {
        GS_THROW_ERROR(ERR_FUNC_ARG_NEEDED, 1, "NOT NULL");
        return GS_ERROR;
    }

    // for bind param : nullif(?,?)
    if (TREE_DATATYPE(arg1) == GS_TYPE_UNKNOWN || TREE_DATATYPE(arg2) == GS_TYPE_UNKNOWN) {
        func->typmod.datatype = GS_TYPE_UNKNOWN;
        return GS_SUCCESS;
    }

    GS_RETURN_IFERR(cm_combine_typmode(TREE_TYPMODE(arg1), GS_FALSE, TREE_TYPMODE(arg2), GS_FALSE, &func->typmod));
    if (!GS_IS_NUMERIC_TYPE(func->typmod.datatype)) {
        func->typmod = TREE_TYPMODE(arg1);
    }

    return GS_SUCCESS;
}

// try convert src_var to dest_var
static status_t sql_func_nvl_verify_datatype_compatible(sql_stmt_t *stmt, expr_tree_t *arg1, expr_tree_t *arg2,
    variant_t *var1, variant_t *var2, variant_t *result_var)
{
    if (TREE_IS_RES_NULL(arg2) || TREE_IS_RES_NULL(arg1)) {
        return GS_SUCCESS;
    }

    if (var2->type == var1->type) {
        return GS_SUCCESS;
    }

    gs_type_t result_type = var1->type;

    // need to check two type whether are compatible
    if (!var_datatype_matched(var1->type, var2->type)) {
        GS_SET_ERROR_MISMATCH(var1->type, var2->type);
        return GS_ERROR;
    }

    // check binary string whether is valid
    if ((var1->type == GS_TYPE_BLOB || GS_IS_BINARY_TYPE(var1->type) || GS_IS_RAW_TYPE(var1->type)) &&
        (GS_IS_STRING_TYPE(var2->type) && !var2->is_null)) {
        GS_RETURN_IFERR(cm_verify_hex_string(&var2->v_text));
    } else if (GS_IS_DATETIME_TYPE(var1->type) && GS_IS_STRING_TYPE(var2->type) && !var2->is_null) {
        // check string whether is valid date format string
        GS_RETURN_IFERR(var_as_date(SESSION_NLS(stmt), var2));
    }

    if (!GS_IS_LOB_TYPE(result_type) && GS_IS_LOB_TYPE(result_var->type)) {
        // convert lob to other datatype
        GS_RETURN_IFERR(sql_get_lob_value(stmt, result_var));
        GS_RETURN_IFERR(sql_convert_variant(stmt, result_var, result_type));
    } else if (result_var->type != result_type) {
        GS_RETURN_IFERR(sql_convert_variant(stmt, result_var, result_type));
    } else if (!GS_IS_LOB_TYPE(var2->type)) {
        GS_RETURN_IFERR(sql_convert_variant(stmt, var2, result_type));
    } else if (GS_IS_LOB_TYPE(var2->type)) {
        GS_RETURN_IFERR(sql_get_lob_value(stmt, var2));
        GS_RETURN_IFERR(sql_convert_variant(stmt, var2, result_type));
    }

    return GS_SUCCESS;
}

status_t sql_func_nvl(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    CM_POINTER3(stmt, func, result);
    expr_tree_t *arg1 = NULL;
    expr_tree_t *arg2 = NULL;
    variant_t var1, var2;
    arg1 = func->argument;
    arg2 = arg1->next;

    GS_RETURN_IFERR(sql_exec_expr(stmt, arg1, &var1));
    SQL_CHECK_COLUMN_VAR(&var1, result);
    sql_keep_stack_variant(stmt, &var1);

    GS_RETURN_IFERR(sql_exec_expr(stmt, arg2, &var2));
    SQL_CHECK_COLUMN_VAR(&var2, result);
    sql_keep_stack_variant(stmt, &var2);

    *result = (var1.is_null) ? var2 : var1;

    return sql_func_nvl_verify_datatype_compatible(stmt, arg1, arg2, &var1, &var2, result);
}

status_t sql_verify_nvl_args(expr_tree_t *arg1, expr_tree_t *arg2)
{
    if (IS_COMPLEX_TYPE(TREE_TYPMODE(arg1).datatype)) {
        GS_SRC_THROW_ERROR(arg1->loc, ERR_SQL_SYNTAX_ERROR, "unsupported parameter type");
        return GS_ERROR;
    }

    if (IS_COMPLEX_TYPE(TREE_TYPMODE(arg2).datatype)) {
        GS_SRC_THROW_ERROR(arg2->loc, ERR_SQL_SYNTAX_ERROR, "unsupported parameter type");
        return GS_ERROR;
    }

    if (!var_datatype_matched(TREE_TYPMODE(arg1).datatype, TREE_TYPMODE(arg2).datatype)) {
        GS_SET_ERROR_MISMATCH(TREE_TYPMODE(arg1).datatype, TREE_TYPMODE(arg2).datatype);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t sql_verify_nvl(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);
    if (sql_verify_func_node(verf, func, 2, 2, GS_INVALID_ID32) != GS_SUCCESS) {
        return GS_ERROR;
    }

    expr_tree_t *arg1 = func->argument;
    expr_tree_t *arg2 = arg1->next;
    uint32 size1, size2;

    if (TREE_IS_RES_NULL(arg1)) {
        func->typmod = TREE_TYPMODE(arg2);
    } else {
        func->typmod = TREE_TYPMODE(arg1);
    }

    GS_RETURN_IFERR(sql_verify_nvl_args(arg1, arg2));

    size1 = cm_get_datatype_strlen(arg1->root->datatype, arg1->root->size);
    size2 = cm_get_datatype_strlen(arg2->root->datatype, arg2->root->size);
    func->size = (uint16)MAX(size1, size2);
    return GS_SUCCESS;
}

status_t sql_func_nvl2(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    CM_POINTER3(stmt, func, result);

    expr_tree_t *arg1 = func->argument;
    expr_tree_t *arg2 = arg1->next;
    expr_tree_t *arg3 = arg2->next;
    variant_t var1, var2, var3;

    GS_RETURN_IFERR(sql_exec_expr(stmt, arg1, &var1));
    SQL_CHECK_COLUMN_VAR(&var1, result);
    sql_keep_stack_variant(stmt, &var1);

    GS_RETURN_IFERR(sql_exec_expr(stmt, arg2, &var2));
    SQL_CHECK_COLUMN_VAR(&var2, result);
    sql_keep_stack_variant(stmt, &var2);

    GS_RETURN_IFERR(sql_exec_expr(stmt, arg3, &var3));
    SQL_CHECK_COLUMN_VAR(&var3, result);
    sql_keep_stack_variant(stmt, &var3);

    *result = (var1.is_null) ? var3 : var2;

    return sql_func_nvl_verify_datatype_compatible(stmt, arg2, arg3, &var2, &var3, result);
}

status_t sql_verify_nvl2(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    GS_RETURN_IFERR(sql_verify_func_node(verf, func, 3, 3, GS_INVALID_ID32));

    expr_tree_t *arg2 = func->argument->next;
    expr_tree_t *arg3 = arg2->next;
    uint32 size2, size3;

    if (TREE_IS_RES_NULL(arg2)) {
        func->typmod = TREE_TYPMODE(arg3);
    } else {
        func->typmod = TREE_TYPMODE(arg2);
    }

    GS_RETURN_IFERR(sql_verify_nvl_args(arg2, arg3));

    size2 = cm_get_datatype_strlen(arg2->root->datatype, arg2->root->size);
    size3 = cm_get_datatype_strlen(arg3->root->datatype, arg3->root->size);
    func->size = (uint16)MAX(size2, size3);
    return GS_SUCCESS;
}

status_t sql_verify_to_int(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 1, 1, GS_INVALID_ID32) != GS_SUCCESS) {
        return GS_ERROR;
    }

    expr_tree_t *arg = func->argument;
    if (!sql_match_num_and_str_type(TREE_DATATYPE(arg))) {
        GS_SRC_ERROR_REQUIRE_NUM_OR_STR(TREE_LOC(arg), TREE_DATATYPE(arg));
        return GS_ERROR;
    }

    func->datatype = GS_TYPE_INTEGER;
    func->size = GS_INTEGER_SIZE;
    return GS_SUCCESS;
}

status_t sql_verify_to_bigint(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 1, 1, GS_INVALID_ID32) != GS_SUCCESS) {
        return GS_ERROR;
    }

    expr_tree_t *arg = func->argument;
    if (!sql_match_num_and_str_type(TREE_DATATYPE(arg))) {
        GS_SRC_ERROR_REQUIRE_NUM_OR_STR(TREE_LOC(arg), TREE_DATATYPE(arg));
        return GS_ERROR;
    }

    func->datatype = GS_TYPE_BIGINT;
    func->size = GS_BIGINT_SIZE;
    return GS_SUCCESS;
}
/**
 * Syntax: TO_NUMBER(num, 'fmt')
 */
status_t sql_verify_to_number(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 1, 2, GS_INVALID_ID32) != GS_SUCCESS) {
        return GS_ERROR;
    }

    expr_tree_t *arg = func->argument;
    if (!sql_match_num_and_str_type(TREE_DATATYPE(arg))) {
        GS_SRC_ERROR_REQUIRE_NUM_OR_STR(TREE_LOC(arg), TREE_DATATYPE(arg));
        return GS_ERROR;
    }

    if (arg->next != NULL) { // if exist the second argument
        arg = arg->next;
        if (!sql_match_string_type(TREE_DATATYPE(arg))) {
            GS_SRC_ERROR_REQUIRE_STRING(TREE_LOC(arg), TREE_DATATYPE(arg));
            return GS_ERROR;
        }
    }

    func->datatype = GS_TYPE_NUMBER;
    func->size = MAX_DEC_BYTE_SZ;
    return GS_SUCCESS;
}

status_t sql_func_to_int(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    status_t status;

    CM_POINTER2(func, result);

    // compute numeric value
    expr_tree_t *num_arg = func->argument;
    CM_POINTER(num_arg);
    SQL_EXEC_FUNC_ARG_EX(num_arg, result, result);
    if (!GS_IS_WEAK_NUMERIC_TYPE(result->type)) { // numeric or string value is allowed
        GS_SRC_ERROR_REQUIRE_NUMERIC(num_arg->loc, result->type);
        return GS_ERROR;
    }

    status = var_as_integer(result);
    return status;
}

status_t sql_func_to_bigint(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    status_t status;

    CM_POINTER2(func, result);

    // compute numeric value
    expr_tree_t *num_arg = func->argument;
    CM_POINTER(num_arg);
    SQL_EXEC_FUNC_ARG_EX(num_arg, result, result);
    if (!GS_IS_WEAK_NUMERIC_TYPE(result->type)) { // numeric or string value is allowed
        GS_SRC_ERROR_REQUIRE_NUMERIC(num_arg->loc, result->type);
        return GS_ERROR;
    }

    status = var_as_bigint(result);
    return status;
}

static bool32 sql_is_digital_fmt(text_t *fmt, uint32 *point_count, uint32 *pre_point_len)
{
    uint32 i;

    for (i = 0; i < fmt->len; i++) {
        if (fmt->str[i] == '0') {
            if (*point_count == 0) {
                (*pre_point_len)++;
            }
            continue;
        }

        if (fmt->str[i] == '.') {
            (*point_count)++;
            continue;
        }

        return GS_FALSE;
    }

    return GS_TRUE;
}

static status_t sql_calc_digital_number(sql_stmt_t *stmt, text_t *num, text_t *fmt, uint32 fmt_point_count,
    uint32 fmt_pre_len)
{
    uint32 fmt_pos_len;
    uint32 i, num_point_count, num_pre_len, num_pos_len;

    // get detail info of fmt
    if (fmt->len == 0 || fmt_point_count > 1) {
        GS_THROW_ERROR(ERR_INVALID_NUMBER, "");
        return GS_ERROR;
    }

    fmt_pos_len = fmt->len - (fmt_pre_len + fmt_point_count);

    num_point_count = num_pre_len = 0;

    for (i = 0; i < num->len; i++) {
        if (num->str[i] == '.') {
            num_point_count++;
            break;
        }

        num_pre_len++;
    }
    num_pos_len = num->len - (num_pre_len + num_point_count);

    // check valid of  digital number
    if (num->len > fmt->len || num_pre_len != fmt_pre_len || fmt_pos_len < num_pos_len) {
        GS_THROW_ERROR(ERR_INVALID_NUMBER, "");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t sql_check_num_fmt(const text_t *fmt_text, bool32 *is_hex_fmt)
{
    bool32 has_hex_elem = GS_FALSE;
    uint32 i;

    *is_hex_fmt = GS_FALSE;
    if (CM_IS_EMPTY(fmt_text)) {
        GS_THROW_ERROR(ERR_INVALID_NUMBER_FORAMT);
        return GS_ERROR;
    }

    for (i = 0; i < fmt_text->len - 1; i++) {
        if (CM_IS_NONZERO(fmt_text->str[i])) {
            break;
        }
    }

    for (; i < fmt_text->len; i++) {
        if (!has_hex_elem) {
            if (!GS_IS_HEX_ELEM(fmt_text->str[i])) {
                return GS_SUCCESS;
            }
            has_hex_elem = GS_TRUE;
            continue;
        }

        if (!GS_IS_HEX_ELEM(fmt_text->str[i])) {
            GS_THROW_ERROR(ERR_INVALID_NUMBER_FORAMT);
            return GS_ERROR;
        }
    }

    *is_hex_fmt = GS_TRUE;
    return GS_SUCCESS;
}

static inline status_t sql_hex_text2dec(const text_t *num_text, const text_t *fmt, dec8_t *dec)
{
    if (fmt->len < num_text->len || (CM_TEXT_FIRST(fmt) == '0' && fmt->len > num_text->len)) {
        GS_THROW_ERROR(ERR_INVALID_NUMBER, "");
        return GS_ERROR;
    }

    return cm_hext_to_dec(num_text, dec);
}

/**
 * Syntax: TO_NUMBER(num, 'fmt')
 */
status_t sql_func_to_number(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t fmt_var;
    uint32 fmt_point_count = 0;
    uint32 fmt_pre_len = 0;
    char num_buf[GS_MAX_NUMBER_LEN];
    bool32 is_hex_fmt = GS_FALSE;

    CM_POINTER2(func, result);

    // compute numeric value
    expr_tree_t *num_arg = func->argument;
    SQL_EXEC_FUNC_ARG_EX(num_arg, result, result);
    if (!GS_IS_WEAK_NUMERIC_TYPE(result->type)) { // numeric or string value is allowed
        GS_SRC_ERROR_REQUIRE_NUMERIC(num_arg->loc, result->type);
        return GS_ERROR;
    }

    expr_tree_t *fmt_arg = num_arg->next;
    if (fmt_arg == NULL) { // if fmt argument is absent
        LOC_RETURN_IFERR(var_as_number(result), func->loc);
        result->is_null = GS_FALSE;
        return GS_SUCCESS;
    }

    if (GS_IS_STRING_TYPE(result->type)) {
        sql_keep_stack_variant(stmt, result);
    } else {
        text_buf_t ntbuf = {
            .str = num_buf,
            .len = 0,
            .max_size = GS_MAX_NUMBER_LEN
        };
        LOC_RETURN_IFERR(var_as_string(SESSION_NLS(stmt), result, &ntbuf), func->loc);
    }

    // compute fmt argument
    SQL_EXEC_FUNC_ARG_EX(fmt_arg, &fmt_var, result);
    if (!GS_IS_STRING_TYPE(fmt_var.type)) {
        GS_SRC_ERROR_REQUIRE_STRING(fmt_arg->loc, fmt_var.type);
        return GS_ERROR;
    }

    text_t num_text = result->v_text;
    cm_trim_text(&num_text);

    if (sql_is_digital_fmt(&fmt_var.v_text, &fmt_point_count, &fmt_pre_len)) {
        LOC_RETURN_IFERR(sql_calc_digital_number(stmt, &num_text, &fmt_var.v_text, fmt_point_count, fmt_pre_len),
            func->loc);
        LOC_RETURN_IFERR(cm_text_to_dec(&num_text, &result->v_dec), num_arg->loc);

        result->is_null = GS_FALSE;
        result->type = GS_TYPE_NUMBER;
        return GS_SUCCESS;
    }

    LOC_RETURN_IFERR(sql_check_num_fmt(&fmt_var.v_text, &is_hex_fmt), fmt_arg->loc);

    if (is_hex_fmt) {
        LOC_RETURN_IFERR(sql_hex_text2dec(&num_text, &fmt_var.v_text, &result->v_dec), num_arg->loc);
        result->is_null = GS_FALSE;
        result->type = GS_TYPE_NUMBER;
        return GS_SUCCESS;
    }

    GS_SRC_THROW_ERROR(func->loc, ERR_CAPABILITY_NOT_SUPPORT, "number format");
    return GS_ERROR;
}

static inline void sql_func_to_char_number_init(text_t *pfmt_text, char *num_buf, fmt_dot_pos_t *number_pos,
    text_t *num_text)
{
    number_pos->fill_mode = GS_FALSE;
    num_text->str = num_buf;
    num_text->len = 0;

    // check fill mode
    if (pfmt_text->len >= 2 && UPPER(pfmt_text->str[0]) == 'F' && UPPER(pfmt_text->str[1]) == 'M') {
        pfmt_text->str += 2;
        pfmt_text->len -= 2;
        number_pos->fill_mode = GS_TRUE;
    }
}

static status_t sql_verify_number_fmt(text_t *pfmt_text, text_t *result, uint32 *max_scale, uint32 *fmt_dot_pos)
{
    uint32 i;

    *fmt_dot_pos = pfmt_text->len;
    for (i = 0; i < pfmt_text->len; ++i) {
        if (pfmt_text->str[i] == '.') {
            if (*fmt_dot_pos < i) {
                return GS_ERROR;
            }
            *fmt_dot_pos = i;
            *max_scale = pfmt_text->len - i - 1;
        } else if (pfmt_text->str[i] != '0' && pfmt_text->str[i] != '9') {
            return GS_ERROR;
        }
        result->str[i + 1] = '#';
    }

    return GS_SUCCESS;
}

static status_t sql_convert_number_to_text(variant_t *var, text_t *num_text, uint32 *max_scale, uint32 *dot_pos,
    bool32 *empty_zero, uint32 *sign_flag)
{
    dec8_t v_dec;

    switch (var->type) {
        case GS_TYPE_UINT32:
            cm_uint32_to_text(var->v_uint32, num_text);
            break;
        case GS_TYPE_INTEGER:
            cm_int2text(var->v_int, num_text);
            break;
        case GS_TYPE_BIGINT:
            cm_bigint2text(var->v_bigint, num_text);
            break;
        case GS_TYPE_REAL:
            (void)cm_real_to_dec(var->v_real, &v_dec);
            break;
        case GS_TYPE_NUMBER:
        case GS_TYPE_DECIMAL:
        case GS_TYPE_NUMBER2:
            v_dec = var->v_dec;
            break;
        default:
            return GS_ERROR;
    }

    if (!GS_IS_INTEGER_TYPE(var->type)) {
        GS_RETURN_IFERR(cm_adjust_dec(&v_dec, GS_MAX_DEC_OUTPUT_ALL_PREC, (int32)*max_scale));
        (void)cm_dec_to_text(&v_dec, GS_MAX_DEC_OUTPUT_ALL_PREC, num_text);

        *dot_pos = cm_get_first_pos(num_text, '.');
        if (*dot_pos == GS_INVALID_ID32) {
            *dot_pos = num_text->len;
        }
        *sign_flag = (IS_DEC8_NEG(&v_dec)) ? NUM_IS_NEGATIVE : NUM_IS_POSITIVE;
        *empty_zero = DECIMAL8_IS_ZERO(&v_dec);
    } else {
        *dot_pos = num_text->len;
        *sign_flag = (var->v_bigint >= 0) ? NUM_IS_POSITIVE : NUM_IS_NEGATIVE;
        *empty_zero = (var->v_bigint == 0);
    }

    return GS_SUCCESS;
}

static void fmt_before_dot_pos(text_t *pfmt_text, text_t *num_text, text_t *result, fmt_dot_pos_t *number_pos,
    uint32 *empty_zero, bool32 *lead_zero, uint32 i, uint32 *j)
{
    if (pfmt_text->str[i] == '0') {
        if (i < number_pos->fmt_dot_pos - number_pos->int_len) {
            *lead_zero = GS_TRUE;
            CM_TEXT_APPEND(result, '0');
        } else {
            CM_TEXT_APPEND(result, num_text->str[(*j)++]);
        }
        *empty_zero = GS_FALSE;
    } else {
        if (i < number_pos->fmt_dot_pos - number_pos->int_len) {
            if (*lead_zero) {
                CM_TEXT_APPEND(result, '0');
            } else if (!number_pos->fill_mode) {
                CM_TEXT_APPEND(result, ' ');
            }
        } else {
            CM_TEXT_APPEND(result, num_text->str[(*j)++]);
            *empty_zero = GS_FALSE;
        }
    }
}

static void fmt_after_dot_pos(text_t *pfmt_text, text_t *num_text, text_t *result, fmt_dot_pos_t *number_pos, uint32 i,
    uint32 *j)
{
    if (*j < num_text->len) {
        CM_TEXT_APPEND(result, num_text->str[(*j)++]);
    } else {
        CM_TEXT_APPEND(result, '0');
    }
    if (pfmt_text->str[i] == '0') {
        number_pos->last_zero_pos = result->len;
    }
}

static status_t sql_print_result_fmt(text_t *pfmt_text, text_t *num_text, text_t *result, fmt_dot_pos_t *number_pos,
    uint32 *empty_zero)
{
    uint32 i;
    uint32 j = number_pos->start_pos;
    bool32 lead_zero = GS_FALSE;

    number_pos->last_zero_pos = GS_MAX_UINT32;
    for (i = 0; i < pfmt_text->len; ++i) {
        if (i < number_pos->fmt_dot_pos) {
            if (pfmt_text->str[i] == '0' || pfmt_text->str[i] == '9') {
                fmt_before_dot_pos(pfmt_text, num_text, result, number_pos, empty_zero, &lead_zero, i, &j);
            } else {
                return GS_ERROR;
            }
        } else if (i == number_pos->fmt_dot_pos) {
            CM_TEXT_APPEND(result, '.');
            ++j; // skip dot
            *empty_zero = GS_FALSE;
            number_pos->last_zero_pos = result->len;
        } else {
            if (pfmt_text->str[i] == '0' || pfmt_text->str[i] == '9') {
                fmt_after_dot_pos(pfmt_text, num_text, result, number_pos, i, &j);
            } else {
                return GS_ERROR;
            }
        }
    }

    return GS_SUCCESS;
}

static status_t sql_func_to_char_number(variant_t *var, text_t *pfmt_text, text_t *result)
{
    bool32 empty_zero = GS_FALSE;
    uint32 sign_flag, max_scale;
    fmt_dot_pos_t number_pos;
    text_t num_text;
    char num_buf[GS_MAX_NUMBER_LEN] = { 0 };

    CM_POINTER3(var, pfmt_text, result);

    sql_func_to_char_number_init(pfmt_text, num_buf, &number_pos, &num_text);

    // verify number format
    max_scale = 0;
    if (sql_verify_number_fmt(pfmt_text, result, &max_scale, &number_pos.fmt_dot_pos) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_TEXT_FORMAT_ERROR, "number");
        return GS_ERROR;
    }

    // convert num to text
    GS_RETURN_IFERR(
        sql_convert_number_to_text(var, &num_text, &max_scale, &number_pos.dot_pos, &empty_zero, &sign_flag));

    // check sign flag
    number_pos.start_pos = (sign_flag == NUM_IS_POSITIVE) ? 0 : 1;

    // skip single 0 before priod(.)
    number_pos.int_len = number_pos.dot_pos - number_pos.start_pos;
    if (num_text.str[number_pos.start_pos] == '0' && number_pos.int_len == 1) {
        number_pos.int_len = 0;
        number_pos.start_pos++;
    }

    // return ### if fmt is not long enough
    if (number_pos.fmt_dot_pos < number_pos.int_len) {
        result->len = pfmt_text->len + 1;
        result->str[0] = '#';
        return GS_SUCCESS;
    }

    // reserve space for sign flag
    result->len = 0;
    if (!(number_pos.fill_mode && sign_flag == NUM_IS_POSITIVE)) {
        CM_TEXT_APPEND(result, ' ');
    }

    // print result by pfmt and check result
    if (sql_print_result_fmt(pfmt_text, &num_text, result, &number_pos, &empty_zero) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_TEXT_FORMAT_ERROR, "number");
        return GS_ERROR;
    }

    // fix empty zero
    if (empty_zero) {
        if (result->len == 0) {
            result->len++;
        }
        result->str[result->len - 1] = '0';
    }

    // trim tailing zeros
    if (number_pos.fill_mode) {
        while (result->str[result->len - 1] == '0' && result->len > number_pos.last_zero_pos) {
            --result->len;
        }
    }

    // set sign flag
    if (sign_flag == NUM_IS_NEGATIVE) {
        uint32 i = 0;
        while (result->str[i + 1] == ' ') {
            ++i;
        }
        result->str[i] = '-';
    }
    return GS_SUCCESS;
}

static status_t sql_func_to_char_core(sql_stmt_t *stmt, variant_t *var, text_t *pfmt_text)
{
    char *result_buf = NULL;
    text_t text;
    text_t ss_fmt;
    status_t status = GS_SUCCESS;

    GS_RETURN_IFERR(sql_push(stmt, GS_CONVERT_BUFFER_SIZE, (void **)&result_buf));
    text.str = result_buf;

    var->is_null = GS_FALSE;
    if (pfmt_text != NULL && GS_IS_NUMERIC_TYPE(var->type)) {
        status = sql_func_to_char_number(var, pfmt_text, &text);
    } else {
        switch (var->type) {
            case GS_TYPE_UINT32:
                cm_uint32_to_text(VALUE(uint32, var), &text);
                break;
            case GS_TYPE_INTEGER:
                cm_int2text(VALUE(int32, var), &text);
                break;

            case GS_TYPE_BOOLEAN:
                cm_bool2text(VALUE(bool32, var), &text);
                break;

            case GS_TYPE_BIGINT:
                cm_bigint2text(VALUE(int64, var), &text);
                break;

            case GS_TYPE_REAL:
                cm_real2text(VALUE(double, var), &text);
                break;

            case GS_TYPE_NUMBER:
            case GS_TYPE_DECIMAL:
            case GS_TYPE_NUMBER2:
                (void)cm_dec_to_text(VALUE_PTR(dec8_t, var), GS_MAX_DEC_OUTPUT_PREC, &text);
                break;

            case GS_TYPE_DATE: {
                if (pfmt_text == NULL) {
                    sql_session_nlsparam_geter(stmt, NLS_DATE_FORMAT, &ss_fmt);
                    pfmt_text = &ss_fmt;
                }
                status = cm_date2text(VALUE(date_t, var), pfmt_text, &text, GS_CONVERT_BUFFER_SIZE);
                break;
            }

            case GS_TYPE_TIMESTAMP:
            case GS_TYPE_TIMESTAMP_TZ_FAKE: {
                if (pfmt_text == NULL) {
                    sql_session_nlsparam_geter(stmt, NLS_TIMESTAMP_FORMAT, &ss_fmt);
                    pfmt_text = &ss_fmt;
                }
                status = cm_timestamp2text(VALUE(timestamp_t, var), pfmt_text, &text, GS_CONVERT_BUFFER_SIZE);
                break;
            }

            case GS_TYPE_TIMESTAMP_TZ: {
                if (pfmt_text == NULL) {
                    sql_session_nlsparam_geter(stmt, NLS_TIMESTAMP_TZ_FORMAT, &ss_fmt);
                    pfmt_text = &ss_fmt;
                }
                status = cm_timestamp_tz2text(VALUE_PTR(timestamp_tz_t, var), pfmt_text, &text, GS_CONVERT_BUFFER_SIZE);
                break;
            }

            case GS_TYPE_TIMESTAMP_LTZ: {
                if (pfmt_text == NULL) {
                    sql_session_nlsparam_geter(stmt, NLS_TIMESTAMP_FORMAT, &ss_fmt);
                    pfmt_text = &ss_fmt;
                }

                /* convert from dbtiomezone to sessiontimezone */
                var->v_tstamp_ltz = cm_adjust_date_between_two_tzs(var->v_tstamp_ltz, cm_get_db_timezone(),
                    sql_get_session_timezone(stmt));
                status = cm_timestamp2text(VALUE(timestamp_t, var), pfmt_text, &text, GS_CONVERT_BUFFER_SIZE);
                break;
            }

            case GS_TYPE_BINARY:
            case GS_TYPE_VARBINARY:
                var->type = GS_TYPE_STRING;
                return GS_SUCCESS;

            case GS_TYPE_RAW:
                text.len = GS_CONVERT_BUFFER_SIZE;
                status = cm_bin2text(VALUE_PTR(binary_t, var), GS_FALSE, &text);
                break;

            case GS_TYPE_INTERVAL_DS:
                cm_dsinterval2text(var->v_itvl_ds, &text);
                break;

            case GS_TYPE_INTERVAL_YM:
                cm_yminterval2text(var->v_itvl_ym, &text);
                break;

            case GS_TYPE_ARRAY:
                text.len = GS_CONVERT_BUFFER_SIZE;
                status = cm_array2text(SESSION_NLS(stmt), &var->v_array, &text);
                break;

            default:
                GS_THROW_ERROR(ERR_CONVERT_TYPE, get_datatype_name_str((int32)var->type), "STRING");
                SQL_POP(stmt);
                return GS_ERROR;
        }
    }

    if (status != GS_SUCCESS) {
        SQL_POP(stmt);
        return GS_ERROR;
    }

    var->v_text = text;
    var->type = GS_TYPE_STRING;
    sql_keep_stack_variant(stmt, var);
    return GS_SUCCESS;
}
status_t sql_func_to_char(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t var2;
    text_t *format = NULL;

    expr_tree_t *arg1 = func->argument;
    expr_tree_t *arg2 = arg1->next; // argument format, for date/timestamp

    SQL_EXEC_FUNC_ARG_EX(arg1, result, result);
    sql_keep_stack_variant(stmt, result);

    if (arg2 != NULL) {
        SQL_EXEC_FUNC_ARG_EX(arg2, &var2, result);
        if (!sql_match_string_type(var2.type)) {
            GS_SRC_ERROR_REQUIRE_STRING(arg2->loc, TREE_DATATYPE(arg2));
            return GS_ERROR;
        }
        sql_keep_stack_variant(stmt, &var2);
        format = &var2.v_text;
    }

    if (format != NULL) {
        if (!GS_IS_DATETIME_TYPE(result->type)) {
            GS_RETURN_IFERR(var_as_num(result));
        }
    }

    if (GS_IS_STRING_TYPE(result->type)) {
        return GS_SUCCESS;
    }

    return sql_func_to_char_core(stmt, result, format);
}
status_t sql_verify_to_char(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 1, 2, GS_INVALID_ID32) != GS_SUCCESS) {
        return GS_ERROR;
    }

    // if the second argument is specified, it must be a string type
    const expr_tree_t *arg2 = func->argument->next;
    if (arg2 != NULL) {
        if (!sql_match_string_type(TREE_DATATYPE(arg2))) {
            GS_SRC_ERROR_REQUIRE_STRING(arg2->loc, TREE_DATATYPE(arg2));
            return GS_ERROR;
        }
    }

    func->datatype = (GS_TYPE_CHAR == func->argument->root->datatype) ? GS_TYPE_CHAR : GS_TYPE_STRING;
    func->size = cm_get_datatype_strlen(func->argument->root->datatype, func->argument->root->size);

    sql_infer_func_optmz_mode(verf, func);

    if (NODE_IS_OPTMZ_CONST(func)) {
        sql_add_first_exec_node(verf, func);
    }

    return GS_SUCCESS;
}

status_t sql_func_to_nchar(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    return sql_func_to_char(stmt, func, result);
}

status_t sql_verify_to_nchar(sql_verifier_t *verifier, expr_node_t *func)
{
    return sql_verify_to_char(verifier, func);
}

status_t sql_func_to_multi_byte(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    expr_tree_t *arg = func->argument;
    variant_t var;

    CM_POINTER3(stmt, func, result);

    SQL_EXEC_FUNC_ARG_EX(arg, &var, result);

    result->type = func->datatype;
    result->is_null = GS_FALSE;

    sql_keep_stack_variant(stmt, &var);

    if (!GS_IS_STRING_TYPE(var.type)) {
        GS_RETURN_IFERR(sql_var_as_string(stmt, &var));
    }

    GS_RETURN_IFERR(sql_push(stmt, var.v_text.len * UTF8_MAX_BYTE, (void **)&result->v_text.str));
    result->v_text.len = var.v_text.len * UTF8_MAX_BYTE;

    GS_RETURN_IFERR(GET_DATABASE_CHARSET->multi_byte(&var.v_text, &result->v_text));

    return GS_SUCCESS;
}

status_t sql_func_to_single_byte(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    expr_tree_t *arg = func->argument;
    variant_t var;

    CM_POINTER3(stmt, func, result);

    SQL_EXEC_FUNC_ARG_EX(arg, &var, result);

    result->type = func->datatype;
    result->is_null = GS_FALSE;

    sql_keep_stack_variant(stmt, &var);

    if (!GS_IS_STRING_TYPE(var.type)) {
        GS_RETURN_IFERR(sql_var_as_string(stmt, &var));
    }
    GS_RETURN_IFERR(sql_push(stmt, var.v_text.len, (void **)&result->v_text.str));
    result->v_text.len = var.v_text.len;

    GS_RETURN_IFERR(GET_DATABASE_CHARSET->single_byte(&var.v_text, &result->v_text));

    return GS_SUCCESS;
}

status_t sql_verify_to_single_or_multi_byte(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);
    if (sql_verify_func_node(verf, func, 1, 1, GS_INVALID_ID32) != GS_SUCCESS) {
        return GS_ERROR;
    }

    func->datatype = (GS_TYPE_CHAR == func->argument->root->datatype) ? GS_TYPE_CHAR : GS_TYPE_STRING;
    func->size = cm_get_datatype_strlen(func->argument->root->datatype, func->argument->root->size);

    return GS_SUCCESS;
}
