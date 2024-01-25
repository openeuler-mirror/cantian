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
 * ctsql_json.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/json/ctsql_json.c
 *
 * -------------------------------------------------------------------------
 */

#include "ctsql_json.h"
#include "ctsql_json_utils.h"
#include "ctsql_func.h"
#include "expr_parser.h"

status_t sql_build_func_args_json_core(sql_stmt_t *stmt, word_t *word, expr_node_t *func_node, sql_text_t *arg_text,
    bool32 is_object)
{
    lex_t *lex = stmt->session->lex;
    expr_tree_t **arg_expr = &func_node->argument;
    bool32 exist = CT_FALSE;
    text_t json_func_txt;
    json_func_att_init(&(func_node->json_func_attr));

    for (;;) {
        if (is_object) {
            /* just support key XX value XX pairs syntax now. */
            if (word->type == WORD_TYPE_EOF || word->type == WORD_TYPE_OPERATOR) {
                break;
            }
            /* key maybe not exists is also ok */
            CT_RETURN_IFERR(lex_try_fetch(lex, "KEY", &exist));

            if (sql_create_expr_until(stmt, arg_expr, word) != CT_SUCCESS) {
                lex_pop(lex);
                return CT_ERROR;
            }

            if (word->type == WORD_TYPE_EOF || word->type == WORD_TYPE_OPERATOR) {
                CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "expr after key expected but %s found",
                    W2S(word));
                return CT_ERROR;
            }

            /* is key word must exists */
            if (IS_SPEC_CHAR(word, ':')) {
                if (exist) {
                    CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "missing IS keyword");
                    return CT_ERROR;
                }
            } else if (word->id != KEY_WORD_IS) {
                CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "'is' expected but %s found", W2S(word));
                return CT_ERROR;
            }
            arg_expr = &(*arg_expr)->next;
        }

        if (sql_create_expr_until(stmt, arg_expr, word) != CT_SUCCESS) {
            lex_pop(lex);
            return CT_ERROR;
        }

        if (word->type == WORD_TYPE_EOF || word->type == WORD_TYPE_OPERATOR) {
            break;
        }

        /* see if exists format json... */
        (*arg_expr)->root->format_json = CT_FALSE;

        if (IS_SPEC_CHAR(word, ',')) {
            arg_expr = &(*arg_expr)->next;
            continue;
        }

        if (word->id == KEY_WORD_FORMAT) {
            CT_RETURN_IFERR(lex_expected_fetch(lex, word));

            /* ... format json ... */
            if ((key_wid_t)word->id != KEY_WORD_JSON) {
                CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "'json' expected but %s found", W2S(word));
                return CT_ERROR;
            }

            (*arg_expr)->root->format_json = CT_TRUE;

            /* skip this json word, to reach the , or end */
            word->ex_count = 0;
            CT_RETURN_IFERR(lex_fetch(lex, word));
            if (word->type == WORD_TYPE_EOF) {
                break;
            }

            if (IS_SPEC_CHAR(word, ',')) {
                arg_expr = &(*arg_expr)->next;
                continue;
            }
        }

        /* maybe there is some clause, and it must appers at the end */
        json_func_txt.str = word->text.value.str;
        json_func_txt.len = (uint32)(arg_text->value.len - (uint32)(word->text.value.str - arg_text->value.str));
        CT_RETURN_IFERR(json_func_att_match(&json_func_txt, &(func_node->json_func_attr)));

        break;
    }

    return CT_SUCCESS;
}

status_t sql_build_func_args_json_array(sql_stmt_t *stmt, word_t *word, expr_node_t *func_node, sql_text_t *arg_text)
{
    func_node->format_json = CT_TRUE;
    return sql_build_func_args_json_core(stmt, word, func_node, arg_text, CT_FALSE);
}

status_t sql_build_func_args_json_object(sql_stmt_t *stmt, word_t *word, expr_node_t *func_node, sql_text_t *arg_text)
{
    func_node->format_json = CT_TRUE;
    return sql_build_func_args_json_core(stmt, word, func_node, arg_text, CT_TRUE);
}

status_t sql_build_func_args_json_retrieve(sql_stmt_t *stmt, word_t *word, expr_node_t *func_node, sql_text_t *arg_text)
{
    text_t json_func_txt;

    json_func_att_init(&(func_node->json_func_attr));

    CT_RETURN_IFERR(sql_create_expr_until(stmt, &func_node->argument, word));
    if (word->type == WORD_TYPE_EOF || word->type == WORD_TYPE_OPERATOR) {
        CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "path expr expected but %s found", W2S(word));
        return CT_ERROR;
    }

    CT_RETURN_IFERR(sql_create_expr_until(stmt, &func_node->argument->next, word));
    if (word->type == WORD_TYPE_EOF || word->type == WORD_TYPE_OPERATOR) {
        return CT_SUCCESS;
    }

    json_func_txt.str = word->text.value.str;
    json_func_txt.len = (uint32)(arg_text->value.len - (uint32)(word->text.value.str - arg_text->value.str));
    CT_RETURN_IFERR(json_func_att_match(&json_func_txt, &(func_node->json_func_attr)));

    word->type = WORD_TYPE_EOF;
    word->text.len = 0;
    word->text.str = json_func_txt.str + json_func_txt.len;
    return CT_SUCCESS;
}

status_t sql_build_func_args_json_query(sql_stmt_t *stmt, word_t *word, expr_node_t *func_node, sql_text_t *arg_text)
{
    func_node->format_json = CT_TRUE;
    return sql_build_func_args_json_retrieve(stmt, word, func_node, arg_text);
}

status_t sql_build_func_args_json_set(sql_stmt_t *stmt, word_t *word, expr_node_t *func_node, sql_text_t *arg_text)
{
    text_t json_func_txt;

    json_func_att_init(&(func_node->json_func_attr));

    CT_RETURN_IFERR(sql_create_expr_until(stmt, &func_node->argument, word));
    if (word->type == WORD_TYPE_EOF || word->type == WORD_TYPE_OPERATOR) {
        CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "path expr expected but %s found", W2S(word));
        return CT_ERROR;
    }

    CT_RETURN_IFERR(sql_create_expr_until(stmt, &func_node->argument->next, word));
    if (word->type == WORD_TYPE_EOF || word->type == WORD_TYPE_OPERATOR) {
        return CT_SUCCESS;
    }

    if (word->type == WORD_TYPE_SPEC_CHAR) {
        CT_RETURN_IFERR(sql_create_expr_until(stmt, &func_node->argument->next->next, word));
        if (word->type == WORD_TYPE_EOF || word->type == WORD_TYPE_OPERATOR) {
            return CT_SUCCESS;
        }
    }

    if (word->type == WORD_TYPE_SPEC_CHAR) {
        CT_RETURN_IFERR(sql_create_expr_until(stmt, &func_node->argument->next->next->next, word));
        if (word->type == WORD_TYPE_EOF || word->type == WORD_TYPE_OPERATOR) {
            return CT_SUCCESS;
        }
    }

    json_func_txt.str = word->text.value.str;
    json_func_txt.len = (uint32)(arg_text->value.len - (uint32)(word->text.value.str - arg_text->value.str));
    CT_RETURN_IFERR(json_func_att_match(&json_func_txt, &(func_node->json_func_attr)));

    word->type = WORD_TYPE_EOF;
    word->text.len = 0;
    word->text.str = json_func_txt.str + json_func_txt.len;

    return CT_SUCCESS;
}

static status_t sql_func_is_json_core(json_assist_t *ja, expr_tree_t *node, variant_t *result)
{
    variant_t var;

    if (sql_exec_json_func_arg(ja, node, &var, result) != CT_SUCCESS) {
        if (CT_ERRNO == ERR_JSON_SYNTAX_ERROR) {
            result->v_bool = CT_FALSE;
            cm_reset_error();
            return CT_SUCCESS;
        }
        return CT_ERROR;
    }
    CT_RETSUC_IFTRUE(result->is_null || result->type == CT_TYPE_COLUMN);

    result->is_null = CT_FALSE;
    result->type = CT_TYPE_BOOLEAN;
    result->v_bool = CT_TRUE;

    if (json_parse(ja, &var.v_text, NULL, node->loc) != CT_SUCCESS) {
        result->v_bool = CT_FALSE;
        if (ja->is_overflow == CT_TRUE) {
            return CT_ERROR;
        }
        cm_reset_error();
    }

    return CT_SUCCESS;
}

status_t sql_func_is_json(sql_stmt_t *stmt, expr_tree_t *node, variant_t *result)
{
    json_assist_t json_ass;
    JSON_ASSIST_INIT(&json_ass, stmt);

    status_t ret = sql_func_is_json_core(&json_ass, node, result);
    JSON_ASSIST_DESTORY(&json_ass);

    return ret;
}

#define JSON_VERIFY_RETURNING_CLAUSE(func, json_func_attr)                                      \
    do {                                                                                        \
        if (!JSON_FUNC_ATT_HAS_RETURNING((json_func_attr).ids) ||                                   \
            (JSON_FUNC_ATT_GET_RETURNING((json_func_attr).ids) == JSON_FUNC_ATT_RETURNING_VARCHAR2)) {  \
            (func)->datatype = CT_TYPE_STRING;                                                  \
            (func)->size = (json_func_attr).return_size;                                        \
            (func)->typmod.is_char = CT_TRUE;                                                   \
        } else if (JSON_FUNC_ATT_GET_RETURNING((json_func_attr).ids) == JSON_FUNC_ATT_RETURNING_CLOB) { \
            (func)->datatype = CT_TYPE_CLOB;                                                    \
            (func)->size = CT_MAX_EXEC_LOB_SIZE;                                                \
            (func)->typmod.is_char = CT_FALSE;                                                  \
        } else {                                                                                \
            CT_THROW_ERROR(ERR_JSON_INVLID_CLAUSE, "RETURNING/ON ERROR/ON EMPTY", "");          \
            return CT_ERROR;                                                                    \
        }                                                                                       \
    } while (0)

static inline void set_default_for_json_func_attr(expr_node_t *json_func, json_func_attr_t json_func_attr, bool32 is_error,
    bool32 is_array_null, bool32 is_object_null)
{
    // set default for returning
    if (!JSON_FUNC_ATT_HAS_RETURNING(json_func_attr.ids)) {
        json_func->json_func_attr.ids |= JSON_FUNC_ATT_RETURNING_VARCHAR2;
        json_func->json_func_attr.return_size = JSON_FUNC_LEN_DEFAULT;
    }

    // set default for on_error_clause
    if (is_error && !JSON_FUNC_ATT_HAS_ON_ERROR(json_func_attr.ids)) {
        json_func->json_func_attr.ids |= JSON_FUNC_ATT_NULL_ON_ERROR;
    }

    // set default for array on_null_clause
    if (is_array_null && !JSON_FUNC_ATT_HAS_ON_NULL(json_func_attr.ids)) {
        json_func->json_func_attr.ids |= JSON_FUNC_ATT_ABSENT_ON_NULL;
    }

    // set default for  object  for on_null_clause
    if (is_object_null && !JSON_FUNC_ATT_HAS_ON_NULL(json_func_attr.ids)) {
        json_func->json_func_attr.ids |= JSON_FUNC_ATT_NULL_ON_NULL;
    }
}

status_t sql_verify_json_value(sql_verifier_t *verf, expr_node_t *func)
{
    json_func_attr_t json_func;

    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 2, 2, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    json_func = func->json_func_attr;

    // verify clauses
    JSON_VERIFY_RETURNING_CLAUSE(func, json_func);
    if ((json_func.ids & ~(JSON_FUNC_ATT_RETURNING_MASK | JSON_FUNC_ATT_ON_ERROR_MASK | JSON_FUNC_ATT_ON_EMPTY_MASK)) ||
        (JSON_FUNC_ATT_HAS_ON_ERROR(json_func.ids) &&
        JSON_FUNC_ATT_GET_ON_ERROR(json_func.ids) != JSON_FUNC_ATT_NULL_ON_ERROR &&
        JSON_FUNC_ATT_GET_ON_ERROR(json_func.ids) != JSON_FUNC_ATT_ERROR_ON_ERROR) ||
        (JSON_FUNC_ATT_HAS_ON_EMPTY(json_func.ids) &&
        JSON_FUNC_ATT_GET_ON_EMPTY(json_func.ids) != JSON_FUNC_ATT_NULL_ON_EMPTY &&
        JSON_FUNC_ATT_GET_ON_EMPTY(json_func.ids) != JSON_FUNC_ATT_ERROR_ON_EMPTY)) {
        CT_THROW_ERROR(ERR_JSON_INVLID_CLAUSE, "RETURNING/ON ERROR/ON EMPTY", "");
        return CT_ERROR;
    }

    // set default for returning and on_error_clause
    set_default_for_json_func_attr(func, json_func, CT_TRUE, CT_FALSE, CT_FALSE);

    // set default for on_error_clause
    // Caution: As ERROR if on_empty_clause not specified
    return CT_SUCCESS;
}

status_t json_retrive(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    json_assist_t json_ass;
    CM_POINTER3(stmt, func, result);

    JSON_ASSIST_INIT(&json_ass, stmt);
    status_t ret = json_retrieve_core(&json_ass, func, result);
    JSON_ASSIST_DESTORY(&json_ass);

    return ret;
}

status_t sql_func_json_value(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    return json_retrive(stmt, func, result);
}

status_t sql_verify_json_query(sql_verifier_t *verf, expr_node_t *func)
{
    json_func_attr_t json_func;

    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 2, 2, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    json_func = func->json_func_attr;

    // verify clauses
    JSON_VERIFY_RETURNING_CLAUSE(func, json_func);
    if ((json_func.ids &
        ~(JSON_FUNC_ATT_RETURNING_MASK | JSON_FUNC_ATT_ON_ERROR_MASK | JSON_FUNC_ATT_ON_EMPTY_MASK | JSON_FUNC_ATT_WRAPPER_MASK)) ||
        (JSON_FUNC_ATT_HAS_ON_ERROR(json_func.ids) &&
        (JSON_FUNC_ATT_GET_ON_ERROR(json_func.ids) == JSON_FUNC_ATT_TRUE_ON_ERROR ||
        JSON_FUNC_ATT_GET_ON_ERROR(json_func.ids) == JSON_FUNC_ATT_FALSE_ON_ERROR))) {
        CT_THROW_ERROR(ERR_JSON_INVLID_CLAUSE, "RETURNING/ON ERROR/ON EMPTY/WITH WRAPPER", "");
        return CT_ERROR;
    }

    // set default for returning
    if (!JSON_FUNC_ATT_HAS_RETURNING(json_func.ids)) {
        func->json_func_attr.ids |= JSON_FUNC_ATT_RETURNING_VARCHAR2;
        func->json_func_attr.return_size = JSON_FUNC_LEN_DEFAULT;
    }

    // set default for on_error_clause
    // Caution: As ERROR if on_empty_clause not specified
    if (!JSON_FUNC_ATT_HAS_ON_ERROR(json_func.ids)) {
        func->json_func_attr.ids |= JSON_FUNC_ATT_NULL_ON_ERROR;
    }

    // set default for wrapper_clause
    if (!JSON_FUNC_ATT_HAS_WRAPPER(json_func.ids)) {
        func->json_func_attr.ids |= JSON_FUNC_ATT_WITHOUT_WRAPPER;
    }

    return CT_SUCCESS;
}

status_t sql_func_json_query(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    return json_retrive(stmt, func, result);
}

status_t sql_verify_json_mergepatch(sql_verifier_t *verf, expr_node_t *func)
{
    json_func_attr_t json_func;

    CM_POINTER2(verf, func);

    CT_RETURN_IFERR(sql_verify_func_node(verf, func, 2, 2, CT_INVALID_ID32));

    json_func = func->json_func_attr;

    // verify clauses
    JSON_VERIFY_RETURNING_CLAUSE(func, json_func);
    if ((json_func.ids & ~(JSON_FUNC_ATT_RETURNING_MASK | JSON_FUNC_ATT_ON_ERROR_MASK)) ||
        (JSON_FUNC_ATT_HAS_ON_ERROR(json_func.ids) &&
        JSON_FUNC_ATT_GET_ON_ERROR(json_func.ids) != JSON_FUNC_ATT_NULL_ON_ERROR &&
        JSON_FUNC_ATT_GET_ON_ERROR(json_func.ids) != JSON_FUNC_ATT_ERROR_ON_ERROR)) {
        CT_THROW_ERROR(ERR_JSON_INVLID_CLAUSE, "ON ERROR",
            "JSON_MERGEPATCH ONLY SUPPORT \"NULL ON ERROR\" or \"ERROR ON ERROR\"");
        return CT_ERROR;
    }

    // set default for returning and on_error_clause
    set_default_for_json_func_attr(func, json_func, CT_TRUE, CT_FALSE, CT_FALSE);

    return CT_SUCCESS;
}

status_t sql_func_json_mergepatch_core(json_assist_t *json_ass, expr_node_t *func, variant_t *result)
{
    expr_tree_t *arg = NULL;
    variant_t var_target;
    variant_t var_patch;
    json_value_t json_val_target;
    json_value_t json_val_patch;
    json_value_t *json_val = NULL;
    json_func_attr_t attr = func->json_func_attr;

    // 1. eval patch_expr, parse
    arg = func->argument->next;
    CT_RETURN_IFERR(sql_exec_json_func_arg(json_ass, arg, &var_patch, result));
    CT_RETSUC_IFTRUE(result->type == CT_TYPE_COLUMN);
    var_patch.v_text.len = var_patch.is_null ? 0 : var_patch.v_text.len;
    cm_trim_text(&var_patch.v_text);
    if (var_patch.v_text.len == 0 || (var_patch.v_text.str[0] != '{' && var_patch.v_text.str[0] != '[')) {
        CT_THROW_ERROR(ERR_JSON_SYNTAX_ERROR, "patch is not valid JSON");
        return CT_ERROR;
    }
    if (json_parse(json_ass, &var_patch.v_text, &json_val_patch, arg->loc) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_JSON_SYNTAX_ERROR, "patch is not valid JSON");
        return CT_ERROR;
    }

    // 2. eval target_expr
    arg = func->argument;
    CT_RETURN_IFERR(sql_exec_json_func_arg(json_ass, arg, &var_target, result));
    CT_RETSUC_IFTRUE(var_target.is_null || result->type == CT_TYPE_COLUMN);

    // 3. parse target_expr
    cm_trim_text(&var_target.v_text);
    if (var_target.v_text.len == 0 || (var_target.v_text.str[0] != '{' && var_target.v_text.str[0] != '[')) {
        CT_THROW_ERROR(ERR_JSON_SYNTAX_ERROR, "expect non-scalar");
        JSON_RETURN_IF_ON_ERROR_HANDLED(CT_ERROR, json_ass, attr, result);
    }
    JSON_RETURN_IF_ON_ERROR_HANDLED(json_parse(json_ass, &var_target.v_text, &json_val_target, arg->loc),
                                    json_ass, attr, result);

    // 4. merge
    JSON_RETURN_IF_ON_ERROR_HANDLED(json_merge_patch(json_ass, &json_val_target, &json_val_patch, &json_val),
                                    json_ass, attr, result);

    // 5. handle returning clause
    JSON_RETURN_IF_ON_ERROR_HANDLED(handle_returning_clause(json_ass, json_val, attr, result, CT_FALSE),
                                    json_ass, attr, result);

    return CT_SUCCESS;
}

status_t sql_func_json_mergepatch(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    json_assist_t json_ass;
    CM_POINTER3(stmt, func, result);

    JSON_ASSIST_INIT(&json_ass, stmt);
    status_t ret = sql_func_json_mergepatch_core(&json_ass, func, result);
    JSON_ASSIST_DESTORY(&json_ass);

    return ret;
}

status_t sql_verify_json_array(sql_verifier_t *verf, expr_node_t *func)
{
    json_func_attr_t json_func;

    CM_POINTER2(verf, func);
    CT_RETURN_IFERR(sql_verify_func_node(verf, func, 0, JSON_MAX_FUN_ARGS, CT_INVALID_ID32));

    json_func = func->json_func_attr;

    // verify clauses
    JSON_VERIFY_RETURNING_CLAUSE(func, json_func);
    if ((json_func.ids & ~(JSON_FUNC_ATT_RETURNING_MASK | JSON_FUNC_ATT_ON_NULL_MASK))) {
        CT_THROW_ERROR(ERR_JSON_INVLID_CLAUSE, "RETURNING/ON NULL", "");
        return CT_ERROR;
    }

    // set default for returning and on_null_clause
    set_default_for_json_func_attr(func, json_func, CT_FALSE, CT_TRUE, CT_FALSE);

    return CT_SUCCESS;
}

status_t sql_func_json_array_core(json_assist_t *json_ass, expr_node_t *func, variant_t *result)
{
    expr_tree_t *arg = NULL;

    variant_t var_json_val;
    json_value_t json_val;
    text_buf_t escaped_txt;
    json_func_attr_t attr = func->json_func_attr;

    json_val.type = JSON_VAL_ARRAY;
    CT_RETURN_IFERR(json_item_array_init(json_ass, &json_val.array, JSON_MEM_LARGE_POOL));

    arg = func->argument;
    while (arg != NULL) {
        json_value_t *new_jv = NULL;

        // 1. get element value str
        CT_RETURN_IFERR(sql_exec_json_func_arg(json_ass, arg, &var_json_val, result));
        CT_RETSUC_IFTRUE(result->type == CT_TYPE_COLUMN);
        if (var_json_val.is_null) {
            // handle on null clause , ABSENT_ON_NULL is default
            if (JSON_FUNC_ATT_GET_ON_NULL(attr.ids) == JSON_FUNC_ATT_NULL_ON_NULL) {
                CT_RETURN_IFERR(cm_galist_new(json_val.array, sizeof(json_value_t), (pointer_t *)&new_jv));
                new_jv->type = JSON_VAL_NULL;
            }
            arg = arg->next;
            continue;
        }

        // 3. parse the src json data and merge to json_val
        if (arg->root->format_json) {
            json_value_t jv_value;
            CT_RETURN_IFERR(json_parse(json_ass, &var_json_val.v_text, &jv_value, arg->loc));
            CT_RETURN_IFERR(cm_galist_new(json_val.array, sizeof(json_value_t), (pointer_t *)&new_jv));
            *new_jv = jv_value;
        } else {
            // 2. add escaped char
            CT_RETURN_IFERR(JSON_ALLOC(json_ass, var_json_val.v_text.len * 2, (void **)&escaped_txt.str));
            escaped_txt.max_size = var_json_val.v_text.len * 2;
            CT_RETURN_IFERR(json_escape_string(&var_json_val.v_text, &escaped_txt));

            CT_RETURN_IFERR(cm_galist_new(json_val.array, sizeof(json_value_t), (pointer_t *)&new_jv));
            new_jv->type = JSON_VAL_STRING;
            new_jv->string.str = escaped_txt.str;
            new_jv->string.len = escaped_txt.len;
        }

        arg = arg->next;
    }

    // 6. make result
    CT_RETURN_IFERR(handle_returning_clause(json_ass, &json_val, attr, result, CT_FALSE));

    return CT_SUCCESS;
}

status_t sql_func_json_array_length_core(json_assist_t *json_ass, expr_node_t *func, variant_t *result)
{
    variant_t var_json_val;
    json_value_t jv_value;

    CT_RETURN_IFERR(sql_exec_json_func_arg(json_ass, func->argument, &var_json_val, result));
    if (result->is_null || result->type == CT_TYPE_COLUMN) {
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(json_array_parse(json_ass, &var_json_val.v_text, &jv_value, func->argument->loc));

    result->type = CT_TYPE_UINT32;
    result->is_null = CT_FALSE;
    result->v_uint32 = jv_value.array->count;

    return CT_SUCCESS;
}


status_t sql_func_json_array(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    json_assist_t json_ass;
    CM_POINTER3(stmt, func, result);

    JSON_ASSIST_INIT(&json_ass, stmt);

    status_t ret = sql_func_json_array_core(&json_ass, func, result);
    JSON_ASSIST_DESTORY(&json_ass);
    return ret;
}

status_t sql_verify_json_array_length(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);
    if (CT_SUCCESS != sql_verify_func_node(verf, func, 1, 1, CT_INVALID_ID32)) {
        return CT_ERROR;
    }
    func->datatype = CT_TYPE_BIGINT;
    func->size = CT_BIGINT_SIZE;

    return CT_SUCCESS;
}

status_t sql_func_json_array_length(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    json_assist_t json_ass;
    CM_POINTER3(stmt, func, result);
    JSON_ASSIST_INIT(&json_ass, stmt);

    status_t ret = sql_func_json_array_length_core(&json_ass, func, result);
    JSON_ASSIST_DESTORY(&json_ass);

    return ret;
}


// JSON_OBJECT([key xx IS xxx],....)
status_t sql_verify_json_object(sql_verifier_t *verf, expr_node_t *func)
{
    json_func_attr_t json_func;
    status_t status;

    CM_POINTER2(verf, func);
    status = sql_verify_func_node(verf, func, 2, JSON_MAX_FUN_ARGS * 2, CT_INVALID_ID32);
    if (status != CT_SUCCESS) {
        int32 err_code;
        const char *err_msg = NULL;

        cm_get_error(&err_code, &err_msg, NULL);
        if (err_code == ERR_INVALID_FUNC_PARAM_COUNT) {
            cm_reset_error();
            CT_SRC_THROW_ERROR(func->loc, ERR_INVALID_FUNC_PARAM_COUNT, T2S(&func->word.func.name), 1,
                JSON_MAX_FUN_ARGS);
        }

        return status;
    }

    json_func = func->json_func_attr;

    // verify clauses
    JSON_VERIFY_RETURNING_CLAUSE(func, json_func);
    if ((json_func.ids & ~(JSON_FUNC_ATT_RETURNING_MASK | JSON_FUNC_ATT_ON_NULL_MASK))) {
        CT_THROW_ERROR(ERR_JSON_INVLID_CLAUSE, "RETURNING/ON NULL", "");
        return CT_ERROR;
    }

    // set default for returning and on_null_clause
    set_default_for_json_func_attr(func, json_func, CT_FALSE, CT_FALSE, CT_TRUE);

    return CT_SUCCESS;
}

status_t sql_func_json_object_core(json_assist_t *json_ass, expr_node_t *func, variant_t *result)
{
    expr_tree_t *arg = NULL;

    variant_t var_json_key;
    variant_t var_json_val;
    json_value_t json_val;
    text_buf_t escaped_txt_key;
    text_buf_t escaped_txt_val;
    json_func_attr_t attr = func->json_func_attr;

    json_val.type = JSON_VAL_OBJECT;
    CT_RETURN_IFERR(json_item_array_init(json_ass, &json_val.object, JSON_MEM_LARGE_POOL));

    arg = func->argument;
    while (arg != NULL) {
        json_pair_t *new_json_val = NULL;

        // 1. get key str
        CT_RETURN_IFERR(sql_exec_json_func_arg(json_ass, arg, &var_json_key, result));
        CT_RETSUC_IFTRUE(result->type == CT_TYPE_COLUMN);
        if (var_json_key.is_null) {
            CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "Name input to JSON generation function cannot be null.");
            return CT_ERROR;
        }
        if (!CT_IS_STRING_TYPE(var_json_key.type)) {
            CT_SRC_ERROR_REQUIRE_STRING(arg->loc, var_json_key.type);
            return CT_ERROR;
        }

        // 2. add escaped char
        CT_RETURN_IFERR(JSON_ALLOC(json_ass, var_json_key.v_text.len, (void **)&escaped_txt_key.str));
        escaped_txt_key.max_size = var_json_key.v_text.len * 2;
        CT_RETURN_IFERR(json_escape_string(&var_json_key.v_text, &escaped_txt_key));

        // alloc key string mem
        CT_RETURN_IFERR(cm_galist_new(json_val.object, sizeof(json_pair_t), (pointer_t *)&new_json_val));
        new_json_val->key.type = JSON_VAL_STRING;
        new_json_val->key.string.str = escaped_txt_key.str;
        new_json_val->key.string.len = escaped_txt_key.len;

        // 3. get value str
        arg = arg->next;
        CT_RETURN_IFERR(sql_exec_json_func_arg(json_ass, arg, &var_json_val, result));
        CT_RETSUC_IFTRUE(result->type == CT_TYPE_COLUMN);
        if (var_json_val.is_null) {
            // handle on null clause, NULL_ON_NULL is default
            new_json_val->val.type = JSON_VAL_NULL;
            if (JSON_FUNC_ATT_GET_ON_NULL(attr.ids) == JSON_FUNC_ATT_ABSENT_ON_NULL) {
                cm_galist_delete(json_val.object, json_val.object->count - 1);
            }
            arg = arg->next;
            continue;
        }

        // 4. parse the src json data and merge to json_val
        if (arg->root->format_json) {
            json_value_t jv_value;
            CT_RETURN_IFERR(json_parse(json_ass, &var_json_val.v_text, &jv_value, arg->loc));
            new_json_val->val = jv_value;
        } else {
            CT_RETURN_IFERR(JSON_ALLOC(json_ass, var_json_val.v_text.len * 2, (void **)&escaped_txt_val.str));

            escaped_txt_val.max_size = var_json_val.v_text.len * 2;
            CT_RETURN_IFERR(json_escape_string(&var_json_val.v_text, &escaped_txt_val));

            new_json_val->val.type = JSON_VAL_STRING;
            new_json_val->val.string.str = escaped_txt_val.str;
            new_json_val->val.string.len = escaped_txt_val.len;
        }

        arg = arg->next;
    }

    // 5. make result
    CT_RETURN_IFERR(handle_returning_clause(json_ass, &json_val, attr, result, CT_FALSE));

    return CT_SUCCESS;
}

status_t sql_func_json_object(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    json_assist_t json_ass;
    CM_POINTER3(stmt, func, result);

    JSON_ASSIST_INIT(&json_ass, stmt);

    status_t ret = sql_func_json_object_core(&json_ass, func, result);
    JSON_ASSIST_DESTORY(&json_ass);

    return ret;
}

status_t sql_verify_json_exists(sql_verifier_t *verf, expr_node_t *func)
{
    json_func_attr_t json_func;

    CM_POINTER2(verf, func);
    CT_RETURN_IFERR(sql_verify_func_node(verf, func, 1, 2, CT_INVALID_ID32));

    json_func = func->json_func_attr;

    if (verf->incl_flags & SQL_INCL_JSON_TABLE) {
        JSON_VERIFY_RETURNING_CLAUSE(func, json_func);
        json_func.ids &= (~JSON_FUNC_ATT_RETURNING_MASK);
    } else {
        func->datatype = CT_TYPE_BOOLEAN;
        func->size = sizeof(bool32);
    }
    if ((json_func.ids & ~(JSON_FUNC_ATT_ON_ERROR_MASK)) || (JSON_FUNC_ATT_HAS_ON_ERROR(json_func.ids) &&
        (JSON_FUNC_ATT_GET_ON_ERROR(json_func.ids) != JSON_FUNC_ATT_TRUE_ON_ERROR) &&
        (JSON_FUNC_ATT_GET_ON_ERROR(json_func.ids) != JSON_FUNC_ATT_FALSE_ON_ERROR) &&
        (JSON_FUNC_ATT_GET_ON_ERROR(json_func.ids) != JSON_FUNC_ATT_ERROR_ON_ERROR))) {
        CT_THROW_ERROR(ERR_JSON_INVLID_CLAUSE, "ON ERROR", "");
        return CT_ERROR;
    }

    // set default for on_error_clause
    if (!JSON_FUNC_ATT_HAS_ON_ERROR(json_func.ids)) {
        func->json_func_attr.ids |= JSON_FUNC_ATT_FALSE_ON_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_func_json_exists(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    return json_retrive(stmt, func, res);
}

status_t sql_verify_json_set(sql_verifier_t *verf, expr_node_t *func)
{
    json_func_attr_t json_func;

    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 2, 4, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    json_func = func->json_func_attr;

    // verify clauses
    JSON_VERIFY_RETURNING_CLAUSE(func, json_func);
    if ((json_func.ids & ~(JSON_FUNC_ATT_RETURNING_MASK | JSON_FUNC_ATT_ON_ERROR_MASK)) ||
        (JSON_FUNC_ATT_HAS_ON_ERROR(json_func.ids) &&
        JSON_FUNC_ATT_GET_ON_ERROR(json_func.ids) != JSON_FUNC_ATT_NULL_ON_ERROR &&
        JSON_FUNC_ATT_GET_ON_ERROR(json_func.ids) != JSON_FUNC_ATT_ERROR_ON_ERROR)) {
        CT_THROW_ERROR(ERR_JSON_INVLID_CLAUSE, "RETURNING/ON ERROR/ON EMPTY", "");
        return CT_ERROR;
    }

    // set default for returning and on_error_clause
    if (!JSON_FUNC_ATT_HAS_RETURNING(json_func.ids)) {
        func->json_func_attr.ids |= JSON_FUNC_ATT_RETURNING_VARCHAR2;
        func->json_func_attr.return_size = JSON_FUNC_LEN_DEFAULT;
    }

    // set default for on_error_clause
    // Caution: As ERROR if on_empty_clause not specified
    if (!JSON_FUNC_ATT_HAS_ON_ERROR(json_func.ids)) {
        func->json_func_attr.ids |= JSON_FUNC_ATT_NULL_ON_ERROR;
    }

    // set default for on_error_clause
    // Caution: As ERROR if on_empty_clause not specified
    return CT_SUCCESS;
}

#define JSON_SET_BOOL_IDX 4
status_t json_set(json_assist_t *json_ass, expr_node_t *func, variant_t *result)
{
    variant_t var_target, var_path, var_new_val, var_create;
    json_path_t path;
    json_value_t json_val_target, jv_new_val;
    json_func_attr_t attr = func->json_func_attr;

    // 1. parse the 2nd parameter, eval path expr, then compile
    CT_RETURN_IFERR(sql_exec_json_func_arg(json_ass, func->argument->next, &var_path, result));
    CT_RETSUC_IFTRUE(result->type == CT_TYPE_COLUMN);
    if (result->is_null) {
        CT_THROW_ERROR(ERR_JSON_PATH_SYNTAX_ERROR, "missing expression");
        return CT_ERROR;
    }
    path.count = 0;
    CT_RETURN_IFERR(json_path_compile(json_ass, &var_path.v_text, &path, func->argument->next->loc));
    if (path.func != NULL && func->value.v_func.func_id == ID_FUNC_ITEM_JSON_EXISTS) {
        CT_THROW_ERROR(ERR_JSON_PATH_SYNTAX_ERROR, "missing expression");
        return CT_ERROR;
    }

    if (func->argument->next->next != NULL) {
        // 2. parse the 3rd parameter, parse json text to json_value_t
        CT_RETURN_IFERR(sql_exec_json_func_arg(json_ass, func->argument->next->next, &var_new_val, result));
        CT_RETSUC_IFTRUE(result->is_null || result->type == CT_TYPE_COLUMN);
        JSON_RETURN_IF_ON_ERROR_HANDLED(
            json_parse(json_ass, &var_new_val.v_text, &jv_new_val, func->argument->next->next->loc),
            json_ass, attr, result);
        json_ass->jv_new_val = &jv_new_val;

        var_create.type = CT_TYPE_BOOLEAN;
        var_create.v_bool = CT_TRUE; /* default value */
        if (func->argument->next->next->next != NULL) {
            // 3. parse the 4th parameter, get the bool value (whether creating on missing).
            CT_RETURN_IFERR(sql_exec_expr(json_ass->stmt, func->argument->next->next->next, &var_create) != CT_SUCCESS);
            CT_RETSUC_IFTRUE(var_create.is_null || var_create.type == CT_TYPE_COLUMN);
            if (!CT_IS_BOOLEAN_TYPE(var_create.type)) {
                CT_THROW_ERROR(ERR_FUNC_ARGUMENT_WRONG_TYPE, JSON_SET_BOOL_IDX, "boolean");
                return CT_ERROR;
            }
        }

        json_ass->policy = var_create.v_bool ? JEP_REPLACE_OR_INSERT : JEP_REPLACE_ONLY;
    } else {
        json_ass->policy = JEP_DELETE;
    }

    // 4. parse the 1st parameter, parse json text to json_value_t
    CT_RETURN_IFERR(sql_exec_json_func_arg(json_ass, func->argument, &var_target, result));
    CT_RETSUC_IFTRUE(result->is_null || result->type == CT_TYPE_COLUMN);

    cm_trim_text(&var_target.v_text);
    if (var_target.v_text.len == 0 || (var_target.v_text.str[0] != '{' && var_target.v_text.str[0] != '[')) {
        CT_THROW_ERROR(ERR_JSON_SYNTAX_ERROR, "expect non-scalar");
        JSON_RETURN_IF_ON_ERROR_HANDLED(CT_ERROR, json_ass, attr, result);
    }
    JSON_RETURN_IF_ON_ERROR_HANDLED(json_parse(json_ass, &var_target.v_text, &json_val_target, func->argument->loc),
                                    json_ass, attr,
        result);

    /* 5. after get all the parameters, we can do set procession. */
    CT_RETURN_IFERR(json_set_core(json_ass, &json_val_target, &path, attr, result));
    return CT_SUCCESS;
}

status_t sql_func_json_set(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    json_assist_t json_ass;
    CM_POINTER3(stmt, func, result);

    JSON_ASSIST_INIT(&json_ass, stmt);
    status_t ret = json_set(&json_ass, func, result);
    JSON_ASSIST_DESTORY(&json_ass);

    return ret;
}