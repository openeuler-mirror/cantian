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
 * ctsql_jsonb.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/json/ctsql_jsonb.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_jsonb.h"
#include "ctsql_json_utils.h"
#include "ctsql_jsonb_utils.h"
#include "ctsql_func.h"

#ifdef __cplusplus
extern "C" {
#endif

#define JSONB_VERIFY_RETURNING_VARCHAR2(func, json_func_attr) \
    do {                                                      \
        (func)->datatype = CT_TYPE_STRING;                    \
        (func)->size = (json_func_attr).return_size;          \
        (func)->typmod.is_char = CT_TRUE;                     \
    } while (0)

#define JSONB_VERIFY_RETURNING_CLOB(func)    \
    do {                                     \
        (func)->datatype = CT_TYPE_CLOB;     \
        (func)->size = CT_MAX_EXEC_LOB_SIZE; \
        (func)->typmod.is_char = CT_FALSE;   \
    } while (0)

#define JSONB_VERIFY_RETURNING_BLOB(func)    \
    do {                                     \
        (func)->datatype = CT_TYPE_BLOB;     \
        (func)->size = CT_MAX_EXEC_LOB_SIZE; \
        (func)->typmod.is_char = CT_FALSE;   \
    } while (0)

#define JSONB_VERIFY_RETURNING_CLAUSE(func, json_func_attr)                                      \
    do {                                                                                         \
        if (!JSON_FUNC_ATT_HAS_RETURNING((json_func_attr).ids) ||                                    \
            (JSON_FUNC_ATT_GET_RETURNING((json_func_attr).ids) == JSON_FUNC_ATT_RETURNING_VARCHAR2)) {   \
            JSONB_VERIFY_RETURNING_VARCHAR2(func, json_func_attr);                               \
        } else if (JSON_FUNC_ATT_GET_RETURNING((json_func_attr).ids) == JSON_FUNC_ATT_RETURNING_CLOB) {  \
            JSONB_VERIFY_RETURNING_CLOB(func);                                                   \
        } else if (JSON_FUNC_ATT_GET_RETURNING((json_func_attr).ids) == JSON_FUNC_ATT_RETURNING_JSONB) { \
            JSONB_VERIFY_RETURNING_BLOB(func);                                                   \
        }                                                                                        \
    } while (0)

static void set_default_for_jsonb_func_attr(expr_node_t *func, json_func_attr_t json_func_attr, bool32 is_error,
    bool32 is_array_null, bool32 is_object_null)
{
    // set default for returning
    if (!JSON_FUNC_ATT_HAS_RETURNING(json_func_attr.ids)) {
        func->json_func_attr.ids |= JSON_FUNC_ATT_RETURNING_VARCHAR2;
        func->json_func_attr.return_size = JSON_FUNC_LEN_DEFAULT;
    }

    // set default for on_error_clause
    if (is_error && !JSON_FUNC_ATT_HAS_ON_ERROR(json_func_attr.ids)) {
        func->json_func_attr.ids |= JSON_FUNC_ATT_NULL_ON_ERROR;
    }

    // set default for array on_null_clause
    if (is_array_null && !JSON_FUNC_ATT_HAS_ON_NULL(json_func_attr.ids)) {
        func->json_func_attr.ids |= JSON_FUNC_ATT_ABSENT_ON_NULL;
    }

    // set default for  object  for on_null_clause
    if (is_object_null && !JSON_FUNC_ATT_HAS_ON_NULL(json_func_attr.ids)) {
        func->json_func_attr.ids |= JSON_FUNC_ATT_NULL_ON_NULL;
    }
}

status_t sql_verify_jsonb_value(sql_verifier_t *verf, expr_node_t *func)
{
    json_func_attr_t json_func_attr;

    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 2, 2, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    json_func_attr = func->json_func_attr;

    // verify clauses
    JSONB_VERIFY_RETURNING_CLAUSE(func, json_func_attr);
    if ((json_func_attr.ids & ~(JSON_FUNC_ATT_RETURNING_MASK | JSON_FUNC_ATT_ON_ERROR_MASK | JSON_FUNC_ATT_ON_EMPTY_MASK)) ||
        (JSON_FUNC_ATT_HAS_RETURNING(json_func_attr.ids) &&
        JSON_FUNC_ATT_GET_RETURNING(json_func_attr.ids) == JSON_FUNC_ATT_RETURNING_JSONB) ||
        (JSON_FUNC_ATT_HAS_ON_ERROR(json_func_attr.ids) &&
        JSON_FUNC_ATT_GET_ON_ERROR(json_func_attr.ids) != JSON_FUNC_ATT_NULL_ON_ERROR &&
        JSON_FUNC_ATT_GET_ON_ERROR(json_func_attr.ids) != JSON_FUNC_ATT_ERROR_ON_ERROR) ||
        (JSON_FUNC_ATT_HAS_ON_EMPTY(json_func_attr.ids) &&
        JSON_FUNC_ATT_GET_ON_EMPTY(json_func_attr.ids) != JSON_FUNC_ATT_NULL_ON_EMPTY &&
        JSON_FUNC_ATT_GET_ON_EMPTY(json_func_attr.ids) != JSON_FUNC_ATT_ERROR_ON_EMPTY)) {
        CT_THROW_ERROR(ERR_JSON_INVLID_CLAUSE, "RETURNING/ON ERROR/ON EMPTY", "");
        return CT_ERROR;
    }

    // set default for returning and on_error_clause
    set_default_for_jsonb_func_attr(func, json_func_attr, CT_TRUE, CT_FALSE, CT_FALSE);

    // set default for on_error_clause
    // Caution: As ERROR if on_empty_clause not specified
    return CT_SUCCESS;
}

status_t jsonb_retrive(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    json_assist_t json_ass;
    CM_POINTER3(stmt, func, res);

    JSON_ASSIST_INIT(&json_ass, stmt);
    status_t ret = jsonb_retrieve_core(&json_ass, func, res);
    JSON_ASSIST_DESTORY(&json_ass);

    return ret;
}

status_t sql_func_jsonb_value(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    return jsonb_retrive(stmt, func, res);
}

status_t sql_verify_jsonb_query(sql_verifier_t *verf, expr_node_t *func)
{
    json_func_attr_t json_func_attr;

    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 2, 2, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    json_func_attr = func->json_func_attr;

    // verify clauses
    JSONB_VERIFY_RETURNING_CLAUSE(func, json_func_attr);
    if ((json_func_attr.ids &
        ~(JSON_FUNC_ATT_RETURNING_MASK | JSON_FUNC_ATT_ON_ERROR_MASK | JSON_FUNC_ATT_ON_EMPTY_MASK | JSON_FUNC_ATT_WRAPPER_MASK)) ||
        (JSON_FUNC_ATT_HAS_ON_ERROR(json_func_attr.ids) &&
        (JSON_FUNC_ATT_GET_ON_ERROR(json_func_attr.ids) == JSON_FUNC_ATT_TRUE_ON_ERROR ||
        JSON_FUNC_ATT_GET_ON_ERROR(json_func_attr.ids) == JSON_FUNC_ATT_FALSE_ON_ERROR))) {
        CT_THROW_ERROR(ERR_JSON_INVLID_CLAUSE, "RETURNING/ON ERROR/ON EMPTY/WITH WRAPPER", "");
        return CT_ERROR;
    }

    // set default for returning
    if (!JSON_FUNC_ATT_HAS_RETURNING(json_func_attr.ids)) {
        func->json_func_attr.ids |= JSON_FUNC_ATT_RETURNING_VARCHAR2;
        func->json_func_attr.return_size = JSON_FUNC_LEN_DEFAULT;
    }

    // set default for on_error_clause
    // Caution: As ERROR if on_empty_clause not specified
    if (!JSON_FUNC_ATT_HAS_ON_ERROR(json_func_attr.ids)) {
        func->json_func_attr.ids |= JSON_FUNC_ATT_NULL_ON_ERROR;
    }

    // set default for wrapper_clause
    if (!JSON_FUNC_ATT_HAS_WRAPPER(json_func_attr.ids)) {
        func->json_func_attr.ids |= JSON_FUNC_ATT_WITHOUT_WRAPPER;
    }

    return CT_SUCCESS;
}

status_t sql_func_jsonb_query(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    return jsonb_retrive(stmt, func, res);
}

status_t sql_verify_jsonb_exists(sql_verifier_t *verf, expr_node_t *func)
{
    json_func_attr_t json_func_attr;

    CM_POINTER2(verf, func);
    CT_RETURN_IFERR(sql_verify_func_node(verf, func, 1, 2, CT_INVALID_ID32));

    json_func_attr = func->json_func_attr;

    if (verf->incl_flags & SQL_INCL_JSON_TABLE) {
        if (JSON_FUNC_ATT_HAS_RETURNING(json_func_attr.ids) &&
            JSON_FUNC_ATT_GET_RETURNING(json_func_attr.ids) == JSON_FUNC_ATT_RETURNING_JSONB) {
            CT_THROW_ERROR(ERR_JSON_INVLID_CLAUSE, "ON RETURNING", "");
            return CT_ERROR;
        }
        JSONB_VERIFY_RETURNING_CLAUSE(func, json_func_attr);
        json_func_attr.ids &= (~JSON_FUNC_ATT_RETURNING_MASK);
    } else {
        func->datatype = CT_TYPE_BOOLEAN;
        func->size = sizeof(bool32);
    }
    if ((json_func_attr.ids & ~(JSON_FUNC_ATT_ON_ERROR_MASK)) || (JSON_FUNC_ATT_HAS_ON_ERROR(json_func_attr.ids) &&
        (JSON_FUNC_ATT_GET_ON_ERROR(json_func_attr.ids) != JSON_FUNC_ATT_TRUE_ON_ERROR) &&
        (JSON_FUNC_ATT_GET_ON_ERROR(json_func_attr.ids) != JSON_FUNC_ATT_FALSE_ON_ERROR) &&
        (JSON_FUNC_ATT_GET_ON_ERROR(json_func_attr.ids) != JSON_FUNC_ATT_ERROR_ON_ERROR))) {
        CT_THROW_ERROR(ERR_JSON_INVLID_CLAUSE, "ON ERROR", "");
        return CT_ERROR;
    }

    // set default for on_error_clause
    if (!JSON_FUNC_ATT_HAS_ON_ERROR(json_func_attr.ids)) {
        func->json_func_attr.ids |= JSON_FUNC_ATT_FALSE_ON_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_func_jsonb_exists(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    return jsonb_retrive(stmt, func, res);
}

status_t sql_verify_jsonb_mergepatch(sql_verifier_t *verf, expr_node_t *func)
{
    json_func_attr_t json_func_attr;

    CM_POINTER2(verf, func);

    CT_RETURN_IFERR(sql_verify_func_node(verf, func, 2, 2, CT_INVALID_ID32));

    json_func_attr = func->json_func_attr;

    // verify clauses
    JSONB_VERIFY_RETURNING_CLAUSE(func, json_func_attr);
    if ((json_func_attr.ids & ~(JSON_FUNC_ATT_RETURNING_MASK | JSON_FUNC_ATT_ON_ERROR_MASK)) ||
        (JSON_FUNC_ATT_HAS_ON_ERROR(json_func_attr.ids) &&
        JSON_FUNC_ATT_GET_ON_ERROR(json_func_attr.ids) != JSON_FUNC_ATT_NULL_ON_ERROR &&
        JSON_FUNC_ATT_GET_ON_ERROR(json_func_attr.ids) != JSON_FUNC_ATT_ERROR_ON_ERROR)) {
        CT_THROW_ERROR(ERR_JSON_INVLID_CLAUSE, "ON ERROR",
            "JSON_MERGEPATCH ONLY SUPPORT \"NULL ON ERROR\" or \"ERROR ON ERROR\"");
        return CT_ERROR;
    }

    // set default for returning and on_error_clause
    set_default_for_jsonb_func_attr(func, json_func_attr, CT_TRUE, CT_FALSE, CT_FALSE);

    return CT_SUCCESS;
}

status_t sql_func_jsonb_mergepatch(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    json_assist_t json_ass;
    CM_POINTER3(stmt, func, res);

    JSON_ASSIST_INIT(&json_ass, stmt);
    status_t ret = jsonb_mergepatch_core(&json_ass, func, res);
    JSON_ASSIST_DESTORY(&json_ass);

    return ret;
}

status_t sql_verify_jsonb_set(sql_verifier_t *verf, expr_node_t *func)
{
    json_func_attr_t json_func_attr;

    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 2, 4, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    json_func_attr = func->json_func_attr;

    // verify clauses
    JSONB_VERIFY_RETURNING_CLAUSE(func, json_func_attr);
    if ((json_func_attr.ids & ~(JSON_FUNC_ATT_RETURNING_MASK | JSON_FUNC_ATT_ON_ERROR_MASK)) ||
        (JSON_FUNC_ATT_HAS_ON_ERROR(json_func_attr.ids) &&
        JSON_FUNC_ATT_GET_ON_ERROR(json_func_attr.ids) != JSON_FUNC_ATT_NULL_ON_ERROR &&
        JSON_FUNC_ATT_GET_ON_ERROR(json_func_attr.ids) != JSON_FUNC_ATT_ERROR_ON_ERROR)) {
        CT_THROW_ERROR(ERR_JSON_INVLID_CLAUSE, "RETURNING/ON ERROR", "");
        return CT_ERROR;
    }

    // set default for returning and on_error_clause
    if (!JSON_FUNC_ATT_HAS_RETURNING(json_func_attr.ids)) {
        func->json_func_attr.ids |= JSON_FUNC_ATT_RETURNING_VARCHAR2;
        func->json_func_attr.return_size = JSON_FUNC_LEN_DEFAULT;
    }

    // set default for on_error_clause
    // Caution: As ERROR if on_empty_clause not specified
    if (!JSON_FUNC_ATT_HAS_ON_ERROR(json_func_attr.ids)) {
        func->json_func_attr.ids |= JSON_FUNC_ATT_NULL_ON_ERROR;
    }

    // set default for on_error_clause
    // Caution: As ERROR if on_empty_clause not specified
    return CT_SUCCESS;
}

status_t sql_func_jsonb_set(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    json_assist_t json_ass;
    CM_POINTER3(stmt, func, res);

    JSON_ASSIST_INIT(&json_ass, stmt);
    status_t ret = jsonb_set(&json_ass, func, res);
    JSON_ASSIST_DESTORY(&json_ass);

    return ret;
}

status_t sql_verify_jsonb_array_length(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);
    if (CT_SUCCESS != sql_verify_func_node(verf, func, 1, 1, CT_INVALID_ID32)) {
        return CT_ERROR;
    }

    func->datatype = CT_TYPE_BIGINT;
    func->size = CT_BIGINT_SIZE;
    return CT_SUCCESS;
}

status_t sql_func_jsonb_array_length(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    json_assist_t json_ass;
    CM_POINTER3(stmt, func, res);

    JSON_ASSIST_INIT(&json_ass, stmt);
    status_t ret = jsonb_array_length_core(&json_ass, func, res);
    JSON_ASSIST_DESTORY(&json_ass);

    return ret;
}

status_t jsonb_convert_core(json_assist_t *json_ass, variant_t *value)
{
    json_value_t jv;
    source_location_t loc = { 0 };
    json_analyse_t analyse = { 0 };

    /* 1. load the string or clob data into a continous memory. */
    CT_RETURN_IFERR(sql_exec_flatten_to_varchar(json_ass, value));

    /* 2. parse the string to jv tree. */
    cm_trim_text(&value->v_text);
    if (value->v_text.len == 0 || (value->v_text.str[0] != '{' && value->v_text.str[0] != '[')) {
        CT_THROW_ERROR(ERR_JSON_SYNTAX_ERROR, "input data is not valid JSON");
        return CT_ERROR;
    }
    CT_RETURN_IFERR(json_parse(json_ass, &value->v_text, &jv, loc));

    /* 3. analyse jv tree, for some statistic information. */
    CT_RETURN_IFERR(json_analyse(json_ass, &jv, &analyse));

    /* 4. parse jv tree to jsonb. */
    json_ass->janalys = &analyse;
    CT_RETURN_IFERR(get_jsonb_from_jsonvalue(json_ass, &jv, value, CT_TRUE));

    return CT_SUCCESS;
}

status_t sql_convert_variant_to_jsonb(sql_stmt_t *stmt, variant_t *value)
{
    json_assist_t json_ass;
    CM_POINTER2(stmt, value);

    JSON_ASSIST_INIT(&json_ass, stmt);
    status_t ret = jsonb_convert_core(&json_ass, value);
    JSON_ASSIST_DESTORY(&json_ass);

    return ret;
}

status_t sql_valiate_jsonb_format(sql_stmt_t *stmt, variant_t *value)
{
    json_assist_t json_ass;
    CM_POINTER2(stmt, value);

    JSON_ASSIST_INIT(&json_ass, stmt);

    /* 1. flatten data into a continues memory */
    CT_RETURN_IFERR(sql_exec_flatten_to_binary(&json_ass, value));

    /* valiate the format */
    CT_RETURN_IFERR(jsonb_format_valiate_core(&json_ass, value));

    JSON_ASSIST_DESTORY(&json_ass);

    return CT_SUCCESS;
}

#ifdef __cplusplus
}
#endif
