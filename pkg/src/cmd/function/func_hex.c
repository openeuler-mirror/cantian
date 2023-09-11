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
 * func_hex.c
 *
 *
 * IDENTIFICATION
 * src/cmd/function/func_hex.c
 *
 * -------------------------------------------------------------------------
 */
#include "func_hex.h"
#include "srv_instance.h"

status_t sql_bin2hex(sql_stmt_t *stmt, expr_node_t *func, bool32 hex_prefix, variant_t *result)
{
    variant_t expr_var;
    char *buf = NULL;

    CM_POINTER3(stmt, func, result);
    result->type = GS_TYPE_STRING;
    result->is_null = GS_TRUE;

    expr_node_t *expr_node = func->argument->root;
    if (sql_exec_expr_node(stmt, expr_node, &expr_var) != GS_SUCCESS) {
        return GS_ERROR;
    }
    SQL_CHECK_COLUMN_VAR(&expr_var, result);

    if (expr_var.is_null) {
        return GS_SUCCESS;
    }

    if (!GS_IS_VARLEN_TYPE(expr_var.type)) {
        GS_THROW_ERROR(ERR_INVALID_FUNC_PARAMS, "parameter is not string or binary type.");
        return GS_ERROR;
    }
    sql_keep_stack_variant(stmt, &expr_var);

    result->v_text.len = expr_var.v_bin.size * 2 + 3; // include '0x' + '\0'
    if (result->v_text.len >= SIZE_K(64)) {
        GS_THROW_ERROR(ERR_INVALID_FUNC_PARAMS, "length of value to bin2hex exceeds maxdium.");
        return GS_ERROR;
    }
    GS_RETURN_IFERR(sql_push(stmt, result->v_text.len, (void **)&buf));
    result->v_text.str = buf;

    if (cm_bin2text(&expr_var.v_bin, hex_prefix, &result->v_text) != GS_SUCCESS) {
        SQL_POP(stmt);
        cm_set_error_loc(expr_node->loc);
        return GS_ERROR;
    }

    result->is_null = GS_FALSE;
    return GS_SUCCESS;
}

status_t sql_func_bin2hex(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    return sql_bin2hex(stmt, func, GS_TRUE, result);
}

status_t sql_verify_bin2hex(sql_verifier_t *verf, expr_node_t *func)
{
    uint32 hex_len;

    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 1, 1, GS_INVALID_ID32) != GS_SUCCESS) {
        return GS_ERROR;
    }

    func->datatype = GS_TYPE_STRING;
    hex_len = cm_get_datatype_strlen(func->argument->root->datatype, func->argument->root->size) * 2 + 3;
    func->size = (uint16)MIN(hex_len, SIZE_K(64) - 1);
    return GS_SUCCESS;
}

static status_t sql_hex2bin(sql_stmt_t *stmt, expr_node_t *func, bool32 hex_prefix, variant_t *result)
{
    expr_tree_t *arg = NULL;
    variant_t var;
    char *buf = NULL;

    CM_POINTER3(stmt, func, result);
    arg = func->argument;
    CM_POINTER(arg);

    SQL_EXEC_FUNC_ARG_EX(arg, &var, result);

    if (!GS_IS_STRING_TYPE(var.type)) {
        GS_SRC_THROW_ERROR(func->loc, ERR_INVALID_FUNC_PARAMS,
            "the argument of the function must be a string variant.");
        return GS_ERROR;
    }
    if (var.v_text.len == 0 && !g_instance->sql.enable_empty_string_null) {
        result->v_bin.size = 0;
    } else {
        sql_keep_stack_variant(stmt, &var);
        if (hex_prefix) {
            if ((var.v_text.len < SQL_MIN_HEX_STR_LEN) || (cm_strcmpni(var.v_text.str, "0x", SQL_MIN_HEX_STR_LEN))) {
                GS_SRC_THROW_ERROR(func->loc, ERR_VALUE_ERROR,
                    "the argument of the function is not a valid hex string.");
                return GS_ERROR;
            }
        }

        GS_RETURN_IFERR(sql_push(stmt, (var.v_text.len + 1) / 2, (void **)&buf));
        result->v_bin.bytes = (uint8 *)buf;

        if (cm_text2bin(&var.v_text, hex_prefix, &result->v_bin, (uint32)((var.v_text.len + 1) / 2)) != GS_SUCCESS) {
            SQL_POP(stmt);
            cm_set_error_loc(func->loc);
            return GS_ERROR;
        }
    }
    result->is_null = GS_FALSE;
    result->type = g_instance->sql.string_as_hex_binary ? GS_TYPE_RAW : GS_TYPE_BINARY;
    result->v_bin.is_hex_const = GS_FALSE;
    return GS_SUCCESS;
}

static status_t sql_func_hex_real(double val_real, variant_t *result)
{
    if (val_real >= ULLONG_MAX || val_real < LLONG_MIN) {
        result->v_text.len = 2 * sizeof(uint64);
        // ULLONG_MAX
        MEMS_RETURN_IFERR(memcpy_s(result->v_text.str, GS_MAX_INT64_STRLEN, "FFFFFFFFFFFFFFFF", result->v_text.len));
    } else {
        double val = cm_round_real(val_real, ROUND_HALF_UP);
        int64 i64 = (int64)val;
        double diff = (double)(i64) - val;
        double min_diff = 0.00000001;                             // minimum difference for double comparison
        double min_double_for_overflow = -9.2233720368547747e+18; // minimum double to judge downward overflow
        double max_double_for_overflow = 9.2233720368547750e+18;  // maximum double to judge upward overflow
        if (!(diff >= -min_diff && diff <= min_diff) || (val < min_double_for_overflow) ||
            (val > max_double_for_overflow)) {
            GS_THROW_ERROR(ERR_TYPE_OVERFLOW, "BIGINT");
            return GS_ERROR;
        }
        cm_bigint2hex((uint64)(int64)val, &result->v_text);
    }
    return GS_SUCCESS;
}

static status_t sql_func_hex_num(sql_stmt_t *stmt, variant_t *var, variant_t *result)
{
    uint64 val_uint64;
    int64 val_int64;

    GS_RETURN_IFERR(sql_push(stmt, GS_MAX_INT64_STRLEN, (void **)&result->v_text.str));
    result->v_text.len = 0;

    switch (var->type) {
        case GS_TYPE_UINT32:
            cm_bigint2hex((uint64)var->v_uint32, &result->v_text);
            break;
        case GS_TYPE_INTEGER:
            cm_bigint2hex((uint64)var->v_int, &result->v_text);
            break;

        case GS_TYPE_BIGINT:
            cm_bigint2hex((uint64)var->v_bigint, &result->v_text);
            break;

        case GS_TYPE_REAL:
            GS_RETURN_IFERR(sql_func_hex_real(var->v_real, result));
            break;

        case GS_TYPE_NUMBER:
        case GS_TYPE_DECIMAL:
        case GS_TYPE_NUMBER2:
            if (cm_dec_to_uint64(&var->v_dec, &val_uint64, ROUND_HALF_UP) == GS_SUCCESS) {
                cm_bigint2hex(val_uint64, &result->v_text);
            } else if (cm_dec_to_int64(&var->v_dec, &val_int64, ROUND_HALF_UP) == GS_SUCCESS) {
                cm_bigint2hex((uint64)val_int64, &result->v_text);
            } else {
                result->v_text.len = 2 * sizeof(uint64);
                // ULLONG_MAX
                MEMS_RETURN_IFERR(
                    memcpy_s(result->v_text.str, GS_MAX_INT64_STRLEN, "FFFFFFFFFFFFFFFF", result->v_text.len));
            }
            break;
        default:
            GS_THROW_ERROR(ERR_INVALID_FUNC_PARAMS, "Don't support the argument datatype of hex.");
            return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t sql_func_hex_string(sql_stmt_t *stmt, variant_t *var, variant_t *result)
{
    uint32 buff_len = var->v_text.len * 2 + 1;

    if (buff_len >= SIZE_K(64)) {
        GS_THROW_ERROR(ERR_INVALID_FUNC_PARAMS, "length of value to hex exceeds maxdium.");
        return GS_ERROR;
    }

    GS_RETURN_IFERR(sql_push(stmt, buff_len, (void **)&result->v_text.str));
    result->v_text.len = buff_len;

    return cm_bin2text(&var->v_bin, GS_FALSE, &result->v_text);
}

static inline status_t sql_func_hex_bin(sql_stmt_t *stmt, variant_t *var, variant_t *result)
{
    return sql_func_hex_string(stmt, var, result);
}

status_t sql_func_hex(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t var;

    CM_POINTER3(stmt, func, result);
    expr_tree_t *arg = func->argument;
    CM_POINTER(arg);

    SQL_EXEC_FUNC_ARG_EX(arg, &var, result);

    result->type = GS_TYPE_STRING;
    result->is_null = GS_FALSE;

    if (GS_IS_STRING_TYPE(var.type)) {
        sql_keep_stack_variant(stmt, &var);
        return sql_func_hex_string(stmt, &var, result);
    } else if (GS_IS_NUMERIC_TYPE(var.type)) {
        return sql_func_hex_num(stmt, &var, result);
    } else if (var.type == GS_TYPE_BINARY || var.type == GS_TYPE_VARBINARY || var.type == GS_TYPE_RAW) {
        sql_keep_stack_variant(stmt, &var);
        return sql_func_hex_bin(stmt, &var, result);
    } else {
        GS_SRC_THROW_ERROR(func->loc, ERR_INVALID_FUNC_PARAMS,
            "the argument of hex must be a string or number variant.");
        return GS_ERROR;
    }
}

status_t sql_verify_hex(sql_verifier_t *verf, expr_node_t *func)
{
    uint32 hex_len;

    CM_POINTER2(verf, func);

    GS_RETURN_IFERR(sql_verify_func_node(verf, func, 1, 1, GS_INVALID_ID32));

    func->datatype = GS_TYPE_STRING;
    hex_len = cm_get_datatype_strlen(func->argument->root->datatype, func->argument->root->size) * 2;
    func->size = (uint16)MIN(hex_len, SIZE_K(64) - 1);
    return GS_SUCCESS;
}

status_t sql_func_hex2bin(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    return sql_hex2bin(stmt, func, GS_TRUE, result);
}

status_t sql_func_hextoraw(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    status_t status = sql_hex2bin(stmt, func, GS_FALSE, result);
    if (result->type != GS_TYPE_COLUMN) {
        result->type = GS_TYPE_RAW;
    }
    return status;
}

status_t sql_verify_hex2bin(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 1, 1, GS_INVALID_ID32) != GS_SUCCESS) {
        return GS_ERROR;
    }

    func->datatype = g_instance->sql.string_as_hex_binary ? GS_TYPE_RAW : GS_TYPE_BINARY;
    func->size = func->argument->root->size;

    return GS_SUCCESS;
}

status_t sql_verify_hextoraw(sql_verifier_t *verf, expr_node_t *func)
{
    GS_RETURN_IFERR(sql_verify_hex2bin(verf, func));
    func->datatype = GS_TYPE_RAW;
    return GS_SUCCESS;
}


static status_t sql_func_unhex_text2bin(sql_stmt_t *stmt, text_t *text, variant_t *result)
{
    if (text->len == 0) {
        result->is_null = GS_TRUE;
        return GS_SUCCESS;
    }

    uint8 *buf = NULL;
    uint32 bytesLen = (text->len + 1) / 2;
    GS_RETURN_IFERR(sql_push(stmt, bytesLen, (void **)&buf));

    uint32 pos = 0;
    uint32 i = 0;
    if (text->len % 2 == 1) {
        buf[pos] = cm_hex2int8((uint8)text->str[0]);
        if (buf[pos] == 0xFF) {
            SQL_POP(stmt);
            result->is_null = GS_TRUE;
            return GS_SUCCESS;
        }
        i++;
        pos++;
    }

    uint8 higher_half_byte = 0;
    uint8 lower_half_byte = 0;
    for (; i < text->len; i += 2) {
        higher_half_byte = cm_hex2int8((uint8)text->str[i]);
        lower_half_byte = cm_hex2int8((uint8)text->str[i + 1]);
        if ((higher_half_byte == 0xFF) || (lower_half_byte == 0xFF)) {
            SQL_POP(stmt);
            result->is_null = GS_TRUE;
            return GS_SUCCESS;
        }
        buf[pos] = (uint8)(higher_half_byte << 4);
        buf[pos] += lower_half_byte;
        pos++;
    }

    result->is_null = GS_FALSE;
    result->v_bin.bytes = buf;
    result->v_bin.size = pos;
    result->v_bin.is_hex_const = GS_FALSE;
    return GS_SUCCESS;
}

status_t sql_func_unhex(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    CM_POINTER3(stmt, func, result);
    expr_tree_t *arg = func->argument;
    CM_POINTER(arg);
    variant_t var;
    SQL_EXEC_FUNC_ARG_EX(arg, &var, result);

    result->type = g_instance->sql.string_as_hex_binary ? GS_TYPE_RAW : GS_TYPE_BINARY;

    if (GS_IS_STRING_TYPE(var.type)) {
        sql_keep_stack_variant(stmt, &var);
        return sql_func_unhex_text2bin(stmt, &var.v_text, result);
    } else {
        GS_SRC_THROW_ERROR(func->loc, ERR_INVALID_FUNC_PARAMS, "the argument of unhex must be a string variant.");
        return GS_ERROR;
    }
}

status_t sql_verify_unhex(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);
    GS_RETURN_IFERR(sql_verify_func_node(verf, func, 1, 1, GS_INVALID_ID32));
    func->datatype = g_instance->sql.string_as_hex_binary ? GS_TYPE_RAW : GS_TYPE_BINARY;
    func->size = cm_get_datatype_strlen(func->argument->root->datatype, func->argument->root->size);
    return GS_SUCCESS;
}