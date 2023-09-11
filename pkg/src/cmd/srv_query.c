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
 * srv_query.c
 *
 *
 * IDENTIFICATION
 * src/cmd/srv_query.c
 *
 * -------------------------------------------------------------------------
 */
#include "srv_query.h"
#include "cm_defs.h"
#include "cm_log.h"
#include "srv_instance.h"
#include "srv_param_common.h"
#include "dtc_database.h"
#include "dtc_dls.h"
#include "dtc_dc.h"
#include "cm_file.h"
#include "cm_list.h"
#include "srv_session.h"
#include "cm_array.h"
#include "cm_nls.h"
#include "cs_protocol.h"
#include "sys/wait.h"
#include "stats_defs.h"
#include "cm_error.h"
#include "cm_hash.h"
#include "sql_json_table.h"
#include "cm_dbs_intf.h"
#include "cm_config.h"
#include "cm_license.h"
#include "srv_param_common.h"
#include "cm_pbl.h"
#include "cm_date.h"
#include "cm_binary.h"
#include "cm_decimal.h"
#include "cm_base.h"
#include "cm_regexp.h"
#include "func_calculate.h"
#include "func_string.h"
#include "func_aggr.h"
#include "func_interval.h"
#include "func_date.h"
#include "func_regexp.h"
#include "func_hex.h"
#include "func_convert.h"
#include "func_group.h"
#include "func_others.h"
#include "dtc_drc.h"
#include "cs_protocol.h"
#include "cm_utils.h"
#ifdef TIME_STATISTIC
#include "cm_statistic.h"
#endif
#include "cm_array.h"

#define LOAD_RET_FD_SIZE 2

#define COMM_FILE_TEXT_LEN 10
#define COMM_PAGE_TEXT_LEN 8

#define DICT_FILE_TEXT_LEN 4
#define DICT_PAGE_TEXT_LEN 10
#define SLOT_TEXT_LEN 4

#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
#include "var_inc.h"
#endif

#define MIN_REGEXP_LIKE_ARG_NUM 2
#define MAX_REGEXP_LIKE_ARG_NUM 3

status_t sql_build_func_args_json_core(sql_stmt_t *stmt, word_t *word, expr_node_t *func_node, sql_text_t *arg_text,
                                       bool32 is_object)
{
    lex_t *lex = stmt->session->lex;
    expr_tree_t **arg_expr = &func_node->argument;
    bool32 exist = GS_FALSE;
    text_t jfunc_att_txt;

    json_func_att_init(&(func_node->json_func_attr));

    for (;;) {
        if (is_object) {
            /* just support key XX value XX pairs syntax now. */
            if (word->type == WORD_TYPE_EOF || word->type == WORD_TYPE_OPERATOR) {
                break;
            }

            /* key maybe not exists is also ok */
            GS_RETURN_IFERR(lex_try_fetch(lex, "KEY", &exist));

            if (sql_create_expr_until(stmt, arg_expr, word) != GS_SUCCESS) {
                lex_pop(lex);
                return GS_ERROR;
            }

            if (word->type == WORD_TYPE_EOF || word->type == WORD_TYPE_OPERATOR) {
                GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "expr after key expected but %s found",
                                      W2S(word));
                return GS_ERROR;
            }

            /* is key word must exists */
            if (IS_SPEC_CHAR(word, ':')) {
                if (exist) {
                    GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "missing IS keyword");
                    return GS_ERROR;
                }
            } else if (word->id != KEY_WORD_IS) {
                GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "'is' expected but %s found", W2S(word));
                return GS_ERROR;
            }
            arg_expr = &(*arg_expr)->next;
        }

        if (sql_create_expr_until(stmt, arg_expr, word) != GS_SUCCESS) {
            lex_pop(lex);
            return GS_ERROR;
        }

        if (word->type == WORD_TYPE_EOF || word->type == WORD_TYPE_OPERATOR) {
            break;
        }

        /* see if exists format json... */
        (*arg_expr)->root->format_json = GS_FALSE;

        if (IS_SPEC_CHAR(word, ',')) {
            arg_expr = &(*arg_expr)->next;
            continue;
        }

        if (word->id == KEY_WORD_FORMAT) {
            GS_RETURN_IFERR(lex_expected_fetch(lex, word));

            /* ... format json ... */
            if ((key_wid_t)word->id != KEY_WORD_JSON) {
                GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "'json' expected but %s found", W2S(word));
                return GS_ERROR;
            }

            (*arg_expr)->root->format_json = GS_TRUE;

            /* skip this json word, to reach the , or end */
            word->ex_count = 0;
            GS_RETURN_IFERR(lex_fetch(lex, word));
            if (word->type == WORD_TYPE_EOF) {
                break;
            }

            if (IS_SPEC_CHAR(word, ',')) {
                arg_expr = &(*arg_expr)->next;
                continue;
            }
        }

        /* maybe there is some clause, and it must appers at the end */
        jfunc_att_txt.str = word->text.value.str;
        jfunc_att_txt.len = (uint32)(arg_text->value.len - (uint32)(word->text.value.str - arg_text->value.str));
        GS_RETURN_IFERR(json_func_att_match(&jfunc_att_txt, &(func_node->json_func_attr)));

        break;
    }

    return GS_SUCCESS;
}

status_t sql_build_func_args_json_array(sql_stmt_t *stmt, word_t *word, expr_node_t *func_node, sql_text_t *arg_text)
{
    func_node->format_json = GS_TRUE;
    return sql_build_func_args_json_core(stmt, word, func_node, arg_text, GS_FALSE);
}

status_t sql_build_func_args_json_object(sql_stmt_t *stmt, word_t *word, expr_node_t *func_node, sql_text_t *arg_text)
{
    func_node->format_json = GS_TRUE;
    return sql_build_func_args_json_core(stmt, word, func_node, arg_text, GS_TRUE);
}

status_t sql_build_func_args_json_retrieve(sql_stmt_t *stmt, word_t *word, expr_node_t *func_node, sql_text_t *arg_text)
{
    text_t jfunc_att_txt;

    json_func_att_init(&(func_node->json_func_attr));

    GS_RETURN_IFERR(sql_create_expr_until(stmt, &func_node->argument, word));
    if (word->type == WORD_TYPE_EOF || word->type == WORD_TYPE_OPERATOR) {
        GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "path expr expected but %s found", W2S(word));
        return GS_ERROR;
    }

    GS_RETURN_IFERR(sql_create_expr_until(stmt, &func_node->argument->next, word));
    if (word->type == WORD_TYPE_EOF || word->type == WORD_TYPE_OPERATOR) {
        return GS_SUCCESS;
    }

    jfunc_att_txt.str = word->text.value.str;
    jfunc_att_txt.len = (uint32)(arg_text->value.len - (uint32)(word->text.value.str - arg_text->value.str));
    GS_RETURN_IFERR(json_func_att_match(&jfunc_att_txt, &(func_node->json_func_attr)));

    word->type = WORD_TYPE_EOF;
    word->text.len = 0;
    word->text.str = jfunc_att_txt.str + jfunc_att_txt.len;
    return GS_SUCCESS;
}

status_t sql_build_func_args_json_query(sql_stmt_t *stmt, word_t *word, expr_node_t *func_node, sql_text_t *arg_text)
{
    func_node->format_json = GS_TRUE;
    return sql_build_func_args_json_retrieve(stmt, word, func_node, arg_text);
}

#define JSON_VERIFY_RETURNING_CLAUSE(func, json_func_attr)                                      \
    do {                                                                                        \
        if (!JFUNC_ATT_HAS_RETURNING((json_func_attr).ids) ||                                   \
            (JFUNC_ATT_GET_RETURNING((json_func_attr).ids) == JFUNC_ATT_RETURNING_VARCHAR2)) {  \
            (func)->datatype = GS_TYPE_STRING;                                                  \
            (func)->size = (json_func_attr).return_size;                                        \
            (func)->typmod.is_char = GS_TRUE;                                                   \
        } else if (JFUNC_ATT_GET_RETURNING((json_func_attr).ids) == JFUNC_ATT_RETURNING_CLOB) { \
            (func)->datatype = GS_TYPE_CLOB;                                                    \
            (func)->size = GS_MAX_EXEC_LOB_SIZE;                                                \
            (func)->typmod.is_char = GS_FALSE;                                                  \
        } else {                                                                                \
            GS_THROW_ERROR(ERR_JSON_INVLID_CLAUSE, "RETURNING/ON ERROR/ON EMPTY", "");          \
            return GS_ERROR;                                                                    \
        }                                                                                       \
    } while (0)

static inline void set_default_for_json_func_attr(expr_node_t *func, json_func_attr_t json_func_attr, bool32 is_error,
                                                  bool32 is_array_null, bool32 is_object_null)
{
    // set default for returning
    if (!JFUNC_ATT_HAS_RETURNING(json_func_attr.ids)) {
        func->json_func_attr.ids |= JFUNC_ATT_RETURNING_VARCHAR2;
        func->json_func_attr.return_size = JSON_FUNC_LEN_DEFAULT;
    }

    // set default for on_error_clause
    if (is_error && !JFUNC_ATT_HAS_ON_ERROR(json_func_attr.ids)) {
        func->json_func_attr.ids |= JFUNC_ATT_NULL_ON_ERROR;
    }

    // set default for array on_null_clause
    if (is_array_null && !JFUNC_ATT_HAS_ON_NULL(json_func_attr.ids)) {
        func->json_func_attr.ids |= JFUNC_ATT_ABSENT_ON_NULL;
    }

    // set default for  object  for on_null_clause
    if (is_object_null && !JFUNC_ATT_HAS_ON_NULL(json_func_attr.ids)) {
        func->json_func_attr.ids |= JFUNC_ATT_NULL_ON_NULL;
    }
}

status_t sql_verify_json_value(sql_verifier_t *verf, expr_node_t *func)
{
    json_func_attr_t json_func_attr;

    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 2, 2, GS_INVALID_ID32) != GS_SUCCESS) {
        return GS_ERROR;
    }

    json_func_attr = func->json_func_attr;

    // verify clauses
    JSON_VERIFY_RETURNING_CLAUSE(func, json_func_attr);
    if ((json_func_attr.ids & ~(JFUNC_ATT_RETURNING_MASK | JFUNC_ATT_ON_ERROR_MASK | JFUNC_ATT_ON_EMPTY_MASK)) ||
        (JFUNC_ATT_HAS_ON_ERROR(json_func_attr.ids) &&
         JFUNC_ATT_GET_ON_ERROR(json_func_attr.ids) != JFUNC_ATT_NULL_ON_ERROR &&
         JFUNC_ATT_GET_ON_ERROR(json_func_attr.ids) != JFUNC_ATT_ERROR_ON_ERROR) ||
        (JFUNC_ATT_HAS_ON_EMPTY(json_func_attr.ids) &&
         JFUNC_ATT_GET_ON_EMPTY(json_func_attr.ids) != JFUNC_ATT_NULL_ON_EMPTY &&
         JFUNC_ATT_GET_ON_EMPTY(json_func_attr.ids) != JFUNC_ATT_ERROR_ON_EMPTY)) {
        GS_THROW_ERROR(ERR_JSON_INVLID_CLAUSE, "RETURNING/ON ERROR/ON EMPTY", "");
        return GS_ERROR;
    }

    // set default for returning and on_error_clause
    set_default_for_json_func_attr(func, json_func_attr, GS_TRUE, GS_FALSE, GS_FALSE);

    // set default for on_error_clause
    // Caution: As ERROR if on_empty_clause not specified
    return GS_SUCCESS;
}

status_t sql_verify_json_array(sql_verifier_t *verf, expr_node_t *func)
{
    json_func_attr_t json_func_attr;

    CM_POINTER2(verf, func);
    GS_RETURN_IFERR(sql_verify_func_node(verf, func, 0, JSON_MAX_FUN_ARGS, GS_INVALID_ID32));

    json_func_attr = func->json_func_attr;

    // verify clauses
    JSON_VERIFY_RETURNING_CLAUSE(func, json_func_attr);
    if ((json_func_attr.ids & ~(JFUNC_ATT_RETURNING_MASK | JFUNC_ATT_ON_NULL_MASK))) {
        GS_THROW_ERROR(ERR_JSON_INVLID_CLAUSE, "RETURNING/ON NULL", "");
        return GS_ERROR;
    }

    // set default for returning and on_null_clause
    set_default_for_json_func_attr(func, json_func_attr, GS_FALSE, GS_TRUE, GS_FALSE);

    return GS_SUCCESS;
}

status_t sql_func_json_array_core(json_assist_t *ja, expr_node_t *func, variant_t *result)
{
    expr_tree_t *arg = NULL;

    variant_t var_json_val;
    json_value_t jv_result;
    text_buf_t escaped_txt;
    json_func_attr_t attr = func->json_func_attr;

    jv_result.type = JV_ARRAY;
    GS_RETURN_IFERR(json_item_array_init(ja, &jv_result.array, JSON_MEM_LARGE_POOL));

    arg = func->argument;
    while (arg != NULL) {
        json_value_t *new_jv = NULL;

        // 1. get element value str
        GS_RETURN_IFERR(sql_exec_json_func_arg(ja, arg, &var_json_val, result));
        GS_RETSUC_IFTRUE(result->type == GS_TYPE_COLUMN);
        if (var_json_val.is_null) {
            // handle on null clause , ABSENT_ON_NULL is default
            if (JFUNC_ATT_GET_ON_NULL(attr.ids) == JFUNC_ATT_NULL_ON_NULL) {
                GS_RETURN_IFERR(cm_galist_new(jv_result.array, sizeof(json_value_t), (pointer_t *)&new_jv));
                new_jv->type = JV_NULL;
            }
            arg = arg->next;
            continue;
        }

        // 3. parse the src json data and merge to jv_result
        if (arg->root->format_json) {
            json_value_t jv_value;
            GS_RETURN_IFERR(json_parse(ja, &var_json_val.v_text, &jv_value, arg->loc));
            GS_RETURN_IFERR(cm_galist_new(jv_result.array, sizeof(json_value_t), (pointer_t *)&new_jv));
            *new_jv = jv_value;
        } else {
            // 2. add escaped char
            GS_RETURN_IFERR(JSON_ALLOC(ja, var_json_val.v_text.len * 2, (void **)&escaped_txt.str));
            escaped_txt.max_size = var_json_val.v_text.len * 2;
            GS_RETURN_IFERR(json_escape_string(&var_json_val.v_text, &escaped_txt));

            GS_RETURN_IFERR(cm_galist_new(jv_result.array, sizeof(json_value_t), (pointer_t *)&new_jv));
            new_jv->type = JV_STRING;
            new_jv->string.str = escaped_txt.str;
            new_jv->string.len = escaped_txt.len;
        }

        arg = arg->next;
    }

    // 6. make result
    GS_RETURN_IFERR(handle_returning_clause(ja, &jv_result, attr, result, GS_FALSE));

    return GS_SUCCESS;
}

status_t sql_func_json_array_length_core(json_assist_t *ja, expr_node_t *func, variant_t *result)
{
    variant_t var_json_val;
    json_value_t jv_value;

    GS_RETURN_IFERR(sql_exec_json_func_arg(ja, func->argument, &var_json_val, result));
    if (result->is_null || result->type == GS_TYPE_COLUMN) {
        return GS_SUCCESS;
    }

    GS_RETURN_IFERR(json_array_parse(ja, &var_json_val.v_text, &jv_value, func->argument->loc));

    result->type = GS_TYPE_UINT32;
    result->is_null = GS_FALSE;
    result->v_uint32 = jv_value.array->count;

    return GS_SUCCESS;
}

status_t sql_func_json_array(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    json_assist_t ja;
    CM_POINTER3(stmt, func, result);

    JSON_ASSIST_INIT(&ja, stmt);

    status_t ret = sql_func_json_array_core(&ja, func, result);
    JSON_ASSIST_DESTORY(&ja);
    return ret;
}

status_t sql_verify_json_query(sql_verifier_t *verf, expr_node_t *func)
{
    json_func_attr_t json_func_attr;

    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 2, 2, GS_INVALID_ID32) != GS_SUCCESS) {
        return GS_ERROR;
    }

    json_func_attr = func->json_func_attr;

    // verify clauses
    JSON_VERIFY_RETURNING_CLAUSE(func, json_func_attr);
    if ((json_func_attr.ids &
        ~(JFUNC_ATT_RETURNING_MASK | JFUNC_ATT_ON_ERROR_MASK | JFUNC_ATT_ON_EMPTY_MASK | JFUNC_ATT_WRAPPER_MASK)) ||
        (JFUNC_ATT_HAS_ON_ERROR(json_func_attr.ids) &&
        (JFUNC_ATT_GET_ON_ERROR(json_func_attr.ids) == JFUNC_ATT_TRUE_ON_ERROR ||
        JFUNC_ATT_GET_ON_ERROR(json_func_attr.ids) == JFUNC_ATT_FALSE_ON_ERROR))) {
        GS_THROW_ERROR(ERR_JSON_INVLID_CLAUSE, "RETURNING/ON ERROR/ON EMPTY/WITH WRAPPER", "");
        return GS_ERROR;
    }

    // set default for returning
    if (!JFUNC_ATT_HAS_RETURNING(json_func_attr.ids)) {
        func->json_func_attr.ids |= JFUNC_ATT_RETURNING_VARCHAR2;
        func->json_func_attr.return_size = JSON_FUNC_LEN_DEFAULT;
    }

    // set default for on_error_clause
    // Caution: As ERROR if on_empty_clause not specified
    if (!JFUNC_ATT_HAS_ON_ERROR(json_func_attr.ids)) {
        func->json_func_attr.ids |= JFUNC_ATT_NULL_ON_ERROR;
    }

    // set default for wrapper_clause
    if (!JFUNC_ATT_HAS_WRAPPER(json_func_attr.ids)) {
        func->json_func_attr.ids |= JFUNC_ATT_WITHOUT_WRAPPER;
    }

    return GS_SUCCESS;
}

status_t json_retrive(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    json_assist_t ja;
    CM_POINTER3(stmt, func, result);

    JSON_ASSIST_INIT(&ja, stmt);
    status_t ret = json_retrieve_core(&ja, func, result);
    JSON_ASSIST_DESTORY(&ja);

    return ret;
}

status_t sql_func_json_value(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    return json_retrive(stmt, func, result);
}

status_t sql_func_json_query(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    return json_retrive(stmt, func, result);
}

status_t sql_verify_json_array_length(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);
    if (GS_SUCCESS != sql_verify_func_node(verf, func, 1, 1, GS_INVALID_ID32)) {
        return GS_ERROR;
    }
    func->datatype = GS_TYPE_BIGINT;
    func->size = GS_BIGINT_SIZE;

    return GS_SUCCESS;
}

status_t sql_func_json_array_length(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    json_assist_t ja;
    CM_POINTER3(stmt, func, result);
    JSON_ASSIST_INIT(&ja, stmt);

    status_t ret = sql_func_json_array_length_core(&ja, func, result);
    JSON_ASSIST_DESTORY(&ja);

    return ret;
}
// JSON_OBJECT([key xx IS xxx],....)
status_t sql_verify_json_object(sql_verifier_t *verf, expr_node_t *func)
{
    json_func_attr_t json_func_attr;
    status_t status;

    CM_POINTER2(verf, func);
    status = sql_verify_func_node(verf, func, 2, JSON_MAX_FUN_ARGS * 2, GS_INVALID_ID32);
    if (status != GS_SUCCESS) {
        int32 err_code;
        const char *err_msg = NULL;

        cm_get_error(&err_code, &err_msg, NULL);
        if (err_code == ERR_INVALID_FUNC_PARAM_COUNT) {
            cm_reset_error();
            GS_SRC_THROW_ERROR(func->loc, ERR_INVALID_FUNC_PARAM_COUNT, T2S(&func->word.func.name), 1,
                JSON_MAX_FUN_ARGS);
        }

        return status;
    }

    json_func_attr = func->json_func_attr;

    // verify clauses
    JSON_VERIFY_RETURNING_CLAUSE(func, json_func_attr);
    if ((json_func_attr.ids & ~(JFUNC_ATT_RETURNING_MASK | JFUNC_ATT_ON_NULL_MASK))) {
        GS_THROW_ERROR(ERR_JSON_INVLID_CLAUSE, "RETURNING/ON NULL", "");
        return GS_ERROR;
    }

    // set default for returning and on_null_clause
    set_default_for_json_func_attr(func, json_func_attr, GS_FALSE, GS_FALSE, GS_TRUE);

    return GS_SUCCESS;
}

status_t sql_func_json_object_core(json_assist_t *ja, expr_node_t *func, variant_t *result)
{
    expr_tree_t *arg = NULL;

    variant_t var_json_key;
    variant_t var_json_val;
    json_value_t jv_result;
    text_buf_t escaped_txt_key;
    text_buf_t escaped_txt_val;
    json_func_attr_t attr = func->json_func_attr;

    jv_result.type = JV_OBJECT;
    GS_RETURN_IFERR(json_item_array_init(ja, &jv_result.object, JSON_MEM_LARGE_POOL));

    arg = func->argument;
    while (arg != NULL) {
        json_pair_t *new_jv = NULL;

        // 1. get key str
        GS_RETURN_IFERR(sql_exec_json_func_arg(ja, arg, &var_json_key, result));
        GS_RETSUC_IFTRUE(result->type == GS_TYPE_COLUMN);
        if (var_json_key.is_null) {
            GS_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "Name input to JSON generation function cannot be null.");
            return GS_ERROR;
        }
        if (!GS_IS_STRING_TYPE(var_json_key.type)) {
            GS_SRC_ERROR_REQUIRE_STRING(arg->loc, var_json_key.type);
            return GS_ERROR;
        }

        // 2. add escaped char
        GS_RETURN_IFERR(JSON_ALLOC(ja, var_json_key.v_text.len, (void **)&escaped_txt_key.str));
        escaped_txt_key.max_size = var_json_key.v_text.len * 2;
        GS_RETURN_IFERR(json_escape_string(&var_json_key.v_text, &escaped_txt_key));

        // alloc key string mem
        GS_RETURN_IFERR(cm_galist_new(jv_result.object, sizeof(json_pair_t), (pointer_t *)&new_jv));
        new_jv->key.type = JV_STRING;
        new_jv->key.string.str = escaped_txt_key.str;
        new_jv->key.string.len = escaped_txt_key.len;

        // 3. get value str
        arg = arg->next;
        GS_RETURN_IFERR(sql_exec_json_func_arg(ja, arg, &var_json_val, result));
        GS_RETSUC_IFTRUE(result->type == GS_TYPE_COLUMN);
        if (var_json_val.is_null) {
            // handle on null clause, NULL_ON_NULL is default
            new_jv->val.type = JV_NULL;
            if (JFUNC_ATT_GET_ON_NULL(attr.ids) == JFUNC_ATT_ABSENT_ON_NULL) {
                cm_galist_delete(jv_result.object, jv_result.object->count - 1);
            }
            arg = arg->next;
            continue;
        }

        // 4. parse the src json data and merge to jv_result
        if (arg->root->format_json) {
            json_value_t jv_value;
            GS_RETURN_IFERR(json_parse(ja, &var_json_val.v_text, &jv_value, arg->loc));
            new_jv->val = jv_value;
        } else {
            GS_RETURN_IFERR(JSON_ALLOC(ja, var_json_val.v_text.len * 2, (void **)&escaped_txt_val.str));

            escaped_txt_val.max_size = var_json_val.v_text.len * 2;
            GS_RETURN_IFERR(json_escape_string(&var_json_val.v_text, &escaped_txt_val));

            new_jv->val.type = JV_STRING;
            new_jv->val.string.str = escaped_txt_val.str;
            new_jv->val.string.len = escaped_txt_val.len;
        }

        arg = arg->next;
    }

    // 5. make result
    GS_RETURN_IFERR(handle_returning_clause(ja, &jv_result, attr, result, GS_FALSE));

    return GS_SUCCESS;
}

status_t sql_func_json_object(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    json_assist_t ja;
    CM_POINTER3(stmt, func, result);

    JSON_ASSIST_INIT(&ja, stmt);

    status_t ret = sql_func_json_object_core(&ja, func, result);
    JSON_ASSIST_DESTORY(&ja);

    return ret;
}

status_t sql_verify_json_exists(sql_verifier_t *verf, expr_node_t *func)
{
    json_func_attr_t json_func_attr;

    CM_POINTER2(verf, func);
    GS_RETURN_IFERR(sql_verify_func_node(verf, func, 1, 2, GS_INVALID_ID32));

    json_func_attr = func->json_func_attr;

    if (verf->incl_flags & SQL_INCL_JSON_TABLE) {
        JSON_VERIFY_RETURNING_CLAUSE(func, json_func_attr);
        json_func_attr.ids &= (~JFUNC_ATT_RETURNING_MASK);
    } else {
        func->datatype = GS_TYPE_BOOLEAN;
        func->size = sizeof(bool32);
    }
    if ((json_func_attr.ids & ~(JFUNC_ATT_ON_ERROR_MASK)) || (JFUNC_ATT_HAS_ON_ERROR(json_func_attr.ids) &&
        (JFUNC_ATT_GET_ON_ERROR(json_func_attr.ids) != JFUNC_ATT_TRUE_ON_ERROR) &&
        (JFUNC_ATT_GET_ON_ERROR(json_func_attr.ids) != JFUNC_ATT_FALSE_ON_ERROR) &&
        (JFUNC_ATT_GET_ON_ERROR(json_func_attr.ids) != JFUNC_ATT_ERROR_ON_ERROR))) {
        GS_THROW_ERROR(ERR_JSON_INVLID_CLAUSE, "ON ERROR", "");
        return GS_ERROR;
    }

    // set default for on_error_clause
    if (!JFUNC_ATT_HAS_ON_ERROR(json_func_attr.ids)) {
        func->json_func_attr.ids |= JFUNC_ATT_FALSE_ON_ERROR;
    }

    return GS_SUCCESS;
}

status_t sql_func_json_exists(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    return json_retrive(stmt, func, result);
}

status_t sql_verify_json_set(sql_verifier_t *verf, expr_node_t *func)
{
    json_func_attr_t json_func_attr;

    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 2, 4, GS_INVALID_ID32) != GS_SUCCESS) {
        return GS_ERROR;
    }

    json_func_attr = func->json_func_attr;

    // verify clauses
    JSON_VERIFY_RETURNING_CLAUSE(func, json_func_attr);
    if ((json_func_attr.ids & ~(JFUNC_ATT_RETURNING_MASK | JFUNC_ATT_ON_ERROR_MASK)) ||
        (JFUNC_ATT_HAS_ON_ERROR(json_func_attr.ids) &&
        JFUNC_ATT_GET_ON_ERROR(json_func_attr.ids) != JFUNC_ATT_NULL_ON_ERROR &&
        JFUNC_ATT_GET_ON_ERROR(json_func_attr.ids) != JFUNC_ATT_ERROR_ON_ERROR)) {
        GS_THROW_ERROR(ERR_JSON_INVLID_CLAUSE, "RETURNING/ON ERROR/ON EMPTY", "");
        return GS_ERROR;
    }

    // set default for returning and on_error_clause
    if (!JFUNC_ATT_HAS_RETURNING(json_func_attr.ids)) {
        func->json_func_attr.ids |= JFUNC_ATT_RETURNING_VARCHAR2;
        func->json_func_attr.return_size = JSON_FUNC_LEN_DEFAULT;
    }

    // set default for on_error_clause
    // Caution: As ERROR if on_empty_clause not specified
    if (!JFUNC_ATT_HAS_ON_ERROR(json_func_attr.ids)) {
        func->json_func_attr.ids |= JFUNC_ATT_NULL_ON_ERROR;
    }

    // set default for on_error_clause
    // Caution: As ERROR if on_empty_clause not specified
    return GS_SUCCESS;
}

#define JSON_SET_BOOL_IDX 4
status_t json_set(json_assist_t *ja, expr_node_t *func, variant_t *result)
{
    variant_t var_target, var_path, var_new_val, var_create;
    json_path_t path;
    json_value_t jv_target, jv_new_val;
    json_func_attr_t attr = func->json_func_attr;

    // 1. parse the 2nd parameter, eval path expr, then compile
    GS_RETURN_IFERR(sql_exec_json_func_arg(ja, func->argument->next, &var_path, result));
    GS_RETSUC_IFTRUE(result->type == GS_TYPE_COLUMN);
    if (result->is_null) {
        GS_THROW_ERROR(ERR_JSON_PATH_SYNTAX_ERROR, "missing expression");
        return GS_ERROR;
    }
    path.count = 0;
    GS_RETURN_IFERR(json_path_compile(ja, &var_path.v_text, &path, func->argument->next->loc));
    if (path.func != NULL && func->value.v_func.func_id == ID_FUNC_ITEM_JSON_EXISTS) {
        GS_THROW_ERROR(ERR_JSON_PATH_SYNTAX_ERROR, "missing expression");
        return GS_ERROR;
    }

    if (func->argument->next->next != NULL) {
        // 2. parse the 3rd parameter, parse json text to json_value_t
        GS_RETURN_IFERR(sql_exec_json_func_arg(ja, func->argument->next->next, &var_new_val, result));
        GS_RETSUC_IFTRUE(result->is_null || result->type == GS_TYPE_COLUMN);
        JSON_RETURN_IF_ON_ERROR_HANDLED(
            json_parse(ja, &var_new_val.v_text, &jv_new_val, func->argument->next->next->loc), ja, attr, result);
        ja->jv_new_val = &jv_new_val;

        var_create.type = GS_TYPE_BOOLEAN;
        var_create.v_bool = GS_TRUE; /* default value */
        if (func->argument->next->next->next != NULL) {
            // 3. parse the 4th parameter, get the bool value (whether creating on missing).
            GS_RETURN_IFERR(sql_exec_expr(ja->stmt, func->argument->next->next->next, &var_create) != GS_SUCCESS);
            GS_RETSUC_IFTRUE(var_create.is_null || var_create.type == GS_TYPE_COLUMN);
            if (!GS_IS_BOOLEAN_TYPE(var_create.type)) {
                GS_THROW_ERROR(ERR_FUNC_ARGUMENT_WRONG_TYPE, JSON_SET_BOOL_IDX, "boolean");
                return GS_ERROR;
            }
        }

        ja->policy = var_create.v_bool ? JEP_REPLACE_OR_INSERT : JEP_REPLACE_ONLY;
    } else {
        ja->policy = JEP_DELETE;
    }

    // 4. parse the 1st parameter, parse json text to json_value_t
    GS_RETURN_IFERR(sql_exec_json_func_arg(ja, func->argument, &var_target, result));
    GS_RETSUC_IFTRUE(result->is_null || result->type == GS_TYPE_COLUMN);

    cm_trim_text(&var_target.v_text);
    if (var_target.v_text.len == 0 || (var_target.v_text.str[0] != '{' && var_target.v_text.str[0] != '[')) {
        GS_THROW_ERROR(ERR_JSON_SYNTAX_ERROR, "expect non-scalar");
        JSON_RETURN_IF_ON_ERROR_HANDLED(GS_ERROR, ja, attr, result);
    }
    JSON_RETURN_IF_ON_ERROR_HANDLED(json_parse(ja, &var_target.v_text, &jv_target, func->argument->loc), ja, attr,
        result);

    /* 5. after get all the parameters, we can do set procession. */
    GS_RETURN_IFERR(json_set_core(ja, &jv_target, &path, attr, result));
    return GS_SUCCESS;
}

status_t sql_func_json_set(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    json_assist_t ja;
    CM_POINTER3(stmt, func, result);

    JSON_ASSIST_INIT(&ja, stmt);
    status_t ret = json_set(&ja, func, result);
    JSON_ASSIST_DESTORY(&ja);

    return ret;
}

static status_t sql_check_const_concat_sort(sql_stmt_t *stmt, expr_tree_t *arg, sort_item_t *sort_item,
    bool32 *is_found)
{
    uint32 idx = 1;
    expr_node_t *node = sort_item->expr->root;
    *is_found = GS_FALSE;

    if (!NODE_IS_CONST(node) || !GS_IS_NUMERIC_TYPE(node->value.type)) {
        return GS_SUCCESS;
    }

    GS_RETURN_IFERR(var_as_floor_integer(&node->value));

    if (node->value.v_int < 1) {
        GS_SRC_THROW_ERROR_EX(node->loc, ERR_SQL_SYNTAX_ERROR, "unknown column '%d' in order clause",
            node->value.v_int);
        return GS_ERROR;
    }

    while (arg != NULL) {
        if (idx == (uint32)node->value.v_int) {
            GS_RETURN_IFERR(sql_clone_expr_node(stmt->context, arg->root, &sort_item->expr->root, sql_alloc_mem));
            *is_found = GS_TRUE;
            break;
        }
        arg = arg->next;
        idx++;
    }

    if (!(*is_found)) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "unknown column '%d' in order clause", node->value.v_int);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}


status_t sql_verify_listagg_order(sql_verifier_t *verf, galist_t *sort_items)
{
    uint32 i, excl_flags;
    sort_item_t *item = NULL;

    excl_flags = verf->excl_flags;
    verf->excl_flags = SQL_ORDER_EXCL | SQL_GROUP_BY_EXCL;

    for (i = sort_items->count; i > 0; i--) {
        item = (sort_item_t *)cm_galist_get(sort_items, i - 1);
        if (TREE_IS_CONST(item->expr)) {
            cm_galist_delete(sort_items, i - 1);
            continue;
        }

        GS_RETURN_IFERR(sql_verify_expr(verf, item->expr));
    }

    verf->excl_flags = excl_flags;
    return GS_SUCCESS;
}

status_t sql_verify_group_concat_order(sql_verifier_t *verf, expr_node_t *func, galist_t *sort_items)
{
    uint32 i, excl_flags;
    sort_item_t *item = NULL;
    bool32 is_found = GS_FALSE;
    expr_tree_t *arg = func->argument->next; // the first argument is separator

    if (sort_items->count == 0) {
        return GS_SUCCESS;
    }

    excl_flags = verf->excl_flags;
    verf->excl_flags = SQL_ORDER_EXCL | SQL_GROUP_BY_EXCL;

    for (i = sort_items->count; i > 0; i--) {
        item = (sort_item_t *)cm_galist_get(sort_items, i - 1);
        if (TREE_IS_BINDING_PARAM(item->expr)) {
            cm_galist_delete(sort_items, i - 1);
            continue;
        }
        GS_RETURN_IFERR(sql_check_const_concat_sort(verf->stmt, arg, item, &is_found));

        if (is_found) {
            continue;
        }

        GS_RETURN_IFERR(sql_verify_expr(verf, item->expr));
    }
    verf->excl_flags = excl_flags;
    return GS_SUCCESS;
}

lang_type_t sql_diag_begin_type(sql_stmt_t *stmt)
{
    word_t word;

    if (lex_push(stmt->session->lex, stmt->session->lex->curr_text) != GS_SUCCESS) {
        return LANG_INVALID;
    }

    if (lex_fetch(stmt->session->lex, &word) != GS_SUCCESS) {
        lex_pop(stmt->session->lex);
        return LANG_INVALID;
    }

    lex_pop(stmt->session->lex);

    if (word.type == WORD_TYPE_EOF || word.id == KEY_WORD_TRANSACTION) {
        return LANG_DCL;
    }

    return LANG_PL;
}
lang_type_t sql_diag_alter_type(sql_stmt_t *stmt)
{
    uint32 matched_id;

    if (lex_push(stmt->session->lex, stmt->session->lex->curr_text) != GS_SUCCESS) {
        return LANG_DDL;
    }
    if (lex_try_fetch_1of2(stmt->session->lex, "SYSTEM", "SESSION", &matched_id) != GS_SUCCESS) {
        lex_pop(stmt->session->lex);
        return LANG_DDL;
    } else {
        if (matched_id != GS_INVALID_ID32) {
            lex_pop(stmt->session->lex);
            return LANG_DCL;
        }
    }
    lex_pop(stmt->session->lex);
    return LANG_DDL;
}

lang_type_t sql_diag_lang_type(sql_stmt_t *stmt, sql_text_t *sql, word_t *leader_word)
{
    lex_init_for_native_type(stmt->session->lex, sql, &stmt->session->curr_user, stmt->session->call_version,
                             USE_NATIVE_DATATYPE);

    GS_RETVALUE_IFTRUE((lex_fetch(stmt->session->lex, leader_word) != GS_SUCCESS), LANG_INVALID);

    /* sql text enclosed by brackets must be select statement */
    if (leader_word->type == WORD_TYPE_BRACKET) {
        leader_word->id = KEY_WORD_SELECT;
    }

    switch (leader_word->id) {
        case KEY_WORD_SELECT:
        case KEY_WORD_INSERT:
        case KEY_WORD_UPDATE:
        case KEY_WORD_DELETE:
        case KEY_WORD_MERGE:
        case KEY_WORD_WITH:
        case KEY_WORD_REPLACE:
            return LANG_DML;

        case KEY_WORD_EXPLAIN:
            return LANG_EXPLAIN;

        case KEY_WORD_DECLARE:
        case KEY_WORD_CALL:
        case KEY_WORD_EXEC:
        case KEY_WORD_EXECUTE:
            return LANG_PL;

        /* pgs protocol special */
        case KEY_WORD_BEGIN:
            return sql_diag_begin_type(stmt);
        case KEY_WORD_START:
        case KEY_WORD_END:
            return LANG_DCL;

        case KEY_WORD_CREATE:
        case KEY_WORD_DROP:
        case KEY_WORD_TRUNCATE:
        case KEY_WORD_FLASHBACK:
        case KEY_WORD_PURGE:
        case KEY_WORD_COMMENT:
        case KEY_WORD_GRANT:
        case KEY_WORD_REVOKE:
        case KEY_WORD_ANALYZE:
            return LANG_DDL;
        case KEY_WORD_ALTER:
            return sql_diag_alter_type(stmt);

        case KEY_WORD_PREPARE:
        case KEY_WORD_COMMIT:
        case KEY_WORD_SAVEPOINT:
        case KEY_WORD_RELEASE:
        case KEY_WORD_SET:
        case KEY_WORD_ROLLBACK:
        case KEY_WORD_BACKUP:
        case KEY_WORD_RESTORE:
        case KEY_WORD_RECOVER:
        case KEY_WORD_DAAC:
        case KEY_WORD_SHUTDOWN:
        case KEY_WORD_BUILD:
        case KEY_WORD_VALIDATE:
#ifdef DB_DEBUG_VERSION
        case KEY_WORD_SYNCPOINT:
#endif /* DB_DEBUG_VERSION */
        case KEY_WORD_LOCK:
            return LANG_DCL;

        default:
            return LANG_INVALID;
    }
}

static status_t sql_parse_by_lang_type(sql_stmt_t *stmt, sql_text_t *sql_text, word_t *leader_word)
{
    status_t status;

    switch (stmt->lang_type) {
        case LANG_DML:
            status = sql_parse_dml(stmt, leader_word->id);
            break;

        case LANG_DDL:
            status = sql_parse_ddl(stmt, leader_word->id);
            break;

        case LANG_DCL:
            status = sql_parse_dcl(stmt, leader_word->id);
            break;

        case LANG_PL:
        default:
            GS_SRC_THROW_ERROR(sql_text->loc, ERR_SQL_SYNTAX_ERROR, "key word expected");
            status = GS_ERROR;
    }

    sql_free_vmemory(stmt);

    if (status != GS_SUCCESS) {
        sql_unlock_lnk_tabs(stmt);
        sql_release_context(stmt);
        OBJ_STACK_RESET(&stmt->ssa_stack);
        OBJ_STACK_RESET(&stmt->node_stack);
    }

    return status;
}

static status_t sql_parse_core(sql_stmt_t *stmt, text_t *sql, source_location_t *loc)
{
    sql_text_t sql_text;
    word_t leader_word;
    status_t status;
    timeval_t tv_end;
    timeval_t tv_begin;

    stmt->pl_failed = GS_FALSE;

    sql_text.value = *sql;
    sql_text.loc = *loc;

    (void)cm_gettimeofday(&tv_begin);
    SQL_SAVE_STACK(stmt);
    stmt->lang_type = sql_diag_lang_type(stmt, &sql_text, &leader_word);

    status = sql_parse_by_lang_type(stmt, &sql_text, &leader_word);
    SQL_RESTORE_STACK(stmt);
    (void)cm_gettimeofday(&tv_end);
    g_instance->library_cache_info[stmt->lang_type].lang_type = stmt->lang_type;
    return status;
}

status_t sql_parse(sql_stmt_t *stmt, text_t *sql, source_location_t *loc)
{
    word_t leader_word;
    status_t status;
    sql_text_t sql_text = { 0 };

    SQL_SAVE_STACK(stmt);
    sql_text.value = *sql;
    sql_text.loc = *loc;
    stmt->lang_type = sql_diag_lang_type(stmt, &sql_text, &leader_word);

    status = sql_parse_core(stmt, sql, loc);

    SQL_RESTORE_STACK(stmt);
    return status;
}
static status_t sql_generate_cond(sql_stmt_t *stmt, cond_tree_t *cond, bool32 *is_expr);
status_t sql_parse_in(sql_stmt_t *stmt, cmp_node_t *node, word_t *word);

static status_t sql_create_cond_node(sql_stmt_t *stmt, cond_tree_t *cond, cond_node_type_t type)
{
    cond_node_t *node = NULL;

    if (sql_alloc_mem(stmt->context, sizeof(cond_node_t), (void **)&node) != GS_SUCCESS) {
        return GS_ERROR;
    }

    node->type = type;
    APPEND_CHAIN(&cond->chain, node);
    return GS_SUCCESS;
}

static status_t sql_create_cmp_node(sql_stmt_t *stmt, cond_tree_t *cond)
{
    cond_node_t *node = NULL;

    if (sql_create_cond_node(stmt, cond, COND_NODE_COMPARE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    node = cond->chain.last;

    if (sql_alloc_mem(stmt->context, sizeof(cmp_node_t), (void **)&node->cmp) != GS_SUCCESS) {
        return GS_ERROR;
    }

    node->cmp->rnum_pending = GS_FALSE;
    node->cmp->has_conflict_chain = GS_FALSE;
    node->cmp->anti_join_cond = GS_FALSE;
    return GS_SUCCESS;
}

status_t sql_parse_like(sql_stmt_t *stmt, cmp_node_t *cmp_node, word_t *word)
{
    expr_tree_t *escape_expr = NULL;
    variant_t *escape_var = NULL;
    char escape_ch;

    GS_RETURN_IFERR(sql_create_expr_until(stmt, &cmp_node->right, word));

    if (word->id != KEY_WORD_ESCAPE) {
        return GS_SUCCESS;
    }

    GS_RETURN_IFERR(sql_create_expr_until(stmt, &cmp_node->right->next, word));

    do {
        escape_expr = cmp_node->right->next;

        if (escape_expr->root->type == EXPR_NODE_CONST) {
            escape_var = &escape_expr->root->value;
            if (escape_var->is_null || !GS_IS_STRING_TYPE(escape_var->type)) {
                break;
            }
            GS_BREAK_IF_ERROR(lex_check_asciichar(&escape_var->v_text, &escape_expr->loc, &escape_ch, GS_FALSE));
            escape_var->v_text.str[0] = escape_ch;
            escape_var->v_text.len = 1;
            return GS_SUCCESS;
        }

        if (NODE_IS_RES_NULL(escape_expr->root)) {
            break;
        }

        if (escape_expr->root->type == EXPR_NODE_PARAM) {
            return GS_SUCCESS;
        }
    } while (0);

    GS_SRC_THROW_ERROR(word->loc, ERR_SQL_SYNTAX_ERROR, "invalid escape character");
    return GS_ERROR;
}

static status_t sql_parse_group_compare_right(sql_stmt_t *stmt, cmp_node_t *node, word_t *word)
{
    switch (node->type) {
        case CMP_TYPE_EQUAL_ANY:
        case CMP_TYPE_NOT_EQUAL_ANY:
        case CMP_TYPE_GREAT_EQUAL_ANY:
        case CMP_TYPE_GREAT_ANY:
        case CMP_TYPE_LESS_ANY:
        case CMP_TYPE_LESS_EQUAL_ANY:
        case CMP_TYPE_EQUAL_ALL:
        case CMP_TYPE_NOT_EQUAL_ALL:
        case CMP_TYPE_GREAT_EQUAL_ALL:
        case CMP_TYPE_GREAT_ALL:
        case CMP_TYPE_LESS_ALL:
        case CMP_TYPE_LESS_EQUAL_ALL:
            GS_SRC_THROW_ERROR(word->loc, ERR_SQL_SYNTAX_ERROR, "group compare right not supported.");
            return GS_ERROR;
        default:
            return sql_create_expr_until(stmt, &node->right, word);
    }
}

cmp_node_t *sql_get_last_comp_node(sql_stmt_t *stmt, cond_tree_t *cond, word_t *word)
{
    cond_node_t *last_cond_node = NULL;
    CM_POINTER(word);

    if (cond->chain.count == 0) {
        if (sql_create_cmp_node(stmt, cond) != GS_SUCCESS) {
            return NULL;
        }

        last_cond_node = cond->chain.last;
    } else {
        last_cond_node = cond->chain.last;
        CM_POINTER(last_cond_node);

        if (IS_LOGICAL_NODE(last_cond_node)) {
            if (sql_create_cmp_node(stmt, cond) != GS_SUCCESS) {
                return NULL;
            }
            last_cond_node = cond->chain.last;
        }
    }
    return last_cond_node->cmp;
}

status_t sql_set_node_type_by_keyword(sql_stmt_t *stmt, word_t *word, cmp_type_t *type)
{
    uint32 match_id;
    lex_t *lex = stmt->session->lex;
    CM_POINTER3(stmt, word, type);

    switch (word->id) {
        case (uint32)KEY_WORD_NOT:
            GS_RETURN_IFERR(lex_expected_fetch_1ofn(lex, &match_id, 4, "IN", "BETWEEN", "LIKE", "REGEXP"));
            if (0 == match_id) {
                *type = CMP_TYPE_NOT_IN;
            } else if (1 == match_id) {
                *type = CMP_TYPE_NOT_BETWEEN;
            } else if (2 == match_id) {
                *type = CMP_TYPE_NOT_LIKE;
            } else if (3 == match_id) {
                *type = CMP_TYPE_NOT_REGEXP;
            }
            break;
        case (uint32)KEY_WORD_IN:
            *type = CMP_TYPE_IN;
            break;

        case (uint32)KEY_WORD_BETWEEN:
            *type = CMP_TYPE_BETWEEN;
            break;

        case (uint32)KEY_WORD_IS: {
            bool32 match_not = GS_FALSE;
            GS_RETURN_IFERR(lex_try_fetch(lex, "NOT", &match_not));

            GS_RETURN_IFERR(lex_expected_fetch_1of2(lex, "NULL", "JSON", &match_id));
            if (0 == match_id) {
                *type = match_not ? CMP_TYPE_IS_NOT_NULL : CMP_TYPE_IS_NULL;
                break;
            }

            *type = match_not ? CMP_TYPE_IS_NOT_JSON : CMP_TYPE_IS_JSON;
            break;
        }
        case (uint32)KEY_WORD_LIKE:
            *type = CMP_TYPE_LIKE;
            break;

        case (uint32)KEY_WORD_REGEXP:
            *type = CMP_TYPE_REGEXP;
            // fall through

        default:
            break;
    }

    return GS_SUCCESS;
}

status_t sql_set_comp_nodetype(sql_stmt_t *stmt, word_t *word, cmp_type_t *type)
{
    CM_POINTER3(stmt, word, type);

    switch (word->type) {
        case WORD_TYPE_COMPARE:
            *type = word->id;
            break;
        case WORD_TYPE_KEYWORD:
            if (!word->namable || word->id == KEY_WORD_REGEXP) {
                return sql_set_node_type_by_keyword(stmt, word, type);
            }
            break;
        default:
            return GS_SUCCESS;
    }

    return GS_SUCCESS;
}

status_t sql_identify_comp_node_type(sql_stmt_t *stmt, word_t *word, cmp_node_t *cmp_node)
{
    lex_t *lex = stmt->session->lex;

    bool32 is_true1 = (cmp_node->left == NULL) &&
                      ((IS_UNNAMABLE_KEYWORD(word) && word->id != KEY_WORD_CASE) || word->id == KEY_WORD_REGEXP_LIKE);
    bool32 is_true2 = (cmp_node->left == NULL) &&
                      (((uint32)word->type & (uint32)EXPR_VAR_WORDS) || (word->type == WORD_TYPE_OPERATOR));
    /* if first word is key word, only hit regexp_like  or exist cond, so it can identified the cmp ype */
    if (is_true1) {
        GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "the \"%s\" is not a correct keyword",
                              T2S(&word->text));
        return GS_ERROR;
    }
    /* if the first word is variant, it must be expr or expr list */
    if (is_true2) {
        lex_back(lex, word);
        GS_RETURN_IFERR(sql_create_expr_until(stmt, &cmp_node->left, word));
    }

    /* if cond->left have been resolved, so cmp type is decided the next word */
    is_true1 = word->type == WORD_TYPE_COMPARE || word->type == WORD_TYPE_KEYWORD;
    if (is_true1) {
        if (cmp_node->left == NULL || cmp_node->left->root == NULL || cmp_node->type != CMP_TYPE_UNKNOWN) {
            GS_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR, "expect expression but comparison is found");
            return GS_ERROR;
        }

        return sql_set_comp_nodetype(stmt, word, &cmp_node->type);
    }

    return GS_SUCCESS;
}

static status_t sql_parse_compare_right(sql_stmt_t *stmt, cmp_node_t *node, word_t *word)
{
    switch (node->type) {
        case CMP_TYPE_EQUAL_ANY:
        case CMP_TYPE_NOT_EQUAL_ANY:
        case CMP_TYPE_GREAT_EQUAL_ANY:
        case CMP_TYPE_GREAT_ANY:
        case CMP_TYPE_LESS_ANY:
        case CMP_TYPE_LESS_EQUAL_ANY:
        case CMP_TYPE_EQUAL:
        case CMP_TYPE_GREAT_EQUAL:
        case CMP_TYPE_GREAT:
        case CMP_TYPE_LESS:
        case CMP_TYPE_LESS_EQUAL:
        case CMP_TYPE_NOT_EQUAL:
        case CMP_TYPE_EQUAL_ALL:
        case CMP_TYPE_NOT_EQUAL_ALL:
        case CMP_TYPE_GREAT_EQUAL_ALL:
        case CMP_TYPE_GREAT_ALL:
        case CMP_TYPE_LESS_ALL:
        case CMP_TYPE_LESS_EQUAL_ALL:

            return sql_parse_group_compare_right(stmt, node, word);
        case CMP_TYPE_LIKE:
        case CMP_TYPE_NOT_LIKE:
            return sql_parse_like(stmt, node, word);

        case CMP_TYPE_IN:
        case CMP_TYPE_NOT_IN:
        case CMP_TYPE_BETWEEN:
        case CMP_TYPE_NOT_BETWEEN:
        /* is [not] null/[not] exist/[not] regexp_like/ cond no need to process again */
        case CMP_TYPE_IS_NULL:
        case CMP_TYPE_IS_NOT_NULL:
        case CMP_TYPE_IS_JSON:
        case CMP_TYPE_IS_NOT_JSON:
        case CMP_TYPE_EXISTS:
        case CMP_TYPE_NOT_EXISTS:
        case CMP_TYPE_REGEXP_LIKE:
        case CMP_TYPE_NOT_REGEXP_LIKE:
        default:
            GS_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR, "expression not supported.");
            return GS_ERROR;
    }
}

static status_t sql_parse_compare(sql_stmt_t *stmt, cond_tree_t *cond, word_t *word)
{
    cond_node_t *last_cond_node = cond->chain.last;
    cmp_node_t *node = sql_get_last_comp_node(stmt, cond, word);
    if (node == NULL) {
        return GS_ERROR;
    }

    /* logical node must appear between two cmp node
       cmp --> cmp is invalid */
    if (last_cond_node == cond->chain.last) {
        GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "invalid word '%s' found", W2S(word));
        return GS_ERROR;
    }

    if (node->type == CMP_TYPE_UNKNOWN) {
        GS_RETURN_IFERR(sql_identify_comp_node_type(stmt, word, node));
    }

    return sql_parse_compare_right(stmt, node, word);
}

static key_word_t g_cause_key_words[] = { { (uint32)KEY_WORD_FULL, GS_TRUE, { (char *)"full", 4 } },
                                          { (uint32)KEY_WORD_INNER, GS_TRUE, { (char *)"inner", 5 } },
                                          { (uint32)KEY_WORD_JOIN, GS_TRUE, { (char *)"join", 4 } },
                                          { (uint32)KEY_WORD_LIMIT, GS_TRUE, { (char *)"limit", 5 } },
                                          { (uint32)KEY_WORD_LOOP, GS_TRUE, { (char *)"loop", 4 } },
                                          { (uint32)KEY_WORD_PIVOT, GS_TRUE, { (char *)"pivot", 5 } },
                                          { (uint32)KEY_WORD_UNPIVOT, GS_TRUE, { (char *)"unpivot", 7 } },
                                          { (uint32)KEY_WORD_WHEN, GS_TRUE, { (char *)"when", 4 } } };

static status_t sql_add_cond_words(sql_stmt_t *stmt, word_t *word, cond_tree_t *cond, bool32 *is_expr)
{
    if (word->type == WORD_TYPE_BRACKET) {
        GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "'(' not supported.");
        return GS_ERROR;
    }

    bool32 is_logical1 = (word->id == KEY_WORD_NOT) && (cond->chain.count == 0 || IS_LOGICAL_NODE(cond->chain.last));
    bool32 is_logical2 = (word->id == KEY_WORD_AND) || (word->id == KEY_WORD_OR);
    if (is_logical1 || is_logical2) {
        GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "and/or/not not supported.");
        return GS_ERROR;
    }

    return sql_parse_compare(stmt, cond, word);
}

status_t sql_create_cond_until(sql_stmt_t *stmt, cond_tree_t **cond, word_t *word)
{
    sql_text_t cond_text;
    lex_t *lex = stmt->session->lex;
    bool32 is_expr = GS_FALSE;
    key_word_t *save_key_words = lex->key_words;
    uint32 save_key_word_count = lex->key_word_count;

    /* arranged lexicographically */
    lex->flags |= LEX_IN_COND;
    GS_RETURN_IFERR(sql_create_cond_tree(stmt->context, cond));
    (*cond)->loc = word->text.loc;
    cond_text = *lex->curr_text;
    GS_RETURN_IFERR(lex_fetch(lex, word));

    if (word->type == WORD_TYPE_EOF) {
        GS_SRC_THROW_ERROR(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "more text expected but terminated");
        return GS_ERROR;
    }

    lex->key_words = g_cause_key_words;
    lex->key_word_count = ELEMENT_COUNT(g_cause_key_words);

    for (;;) {
        if (sql_add_cond_words(stmt, word, *cond, &is_expr) != GS_SUCCESS) {
            lex->key_words = save_key_words;
            lex->key_word_count = save_key_word_count;
            return GS_ERROR;
        }
        /* If the conditional split keyword can be named and used as function, it should separate judement, othewise
           should be fill in g_cause_key_words array */
        if (word->type == WORD_TYPE_EOF || IS_SPEC_CHAR(word, ';') || IS_KEY_WORD(word, KEY_WORD_LEFT) ||
            IS_KEY_WORD(word, KEY_WORD_RIGHT) || IS_KEY_WORD(word, KEY_WORD_CROSS) || IS_SPEC_CHAR(word, ',') ||
            (IS_CLAUSE_WORD(word->id) && !word->namable)) {
            break;
        }
    }

    lex->flags &= ~LEX_IN_COND;
    if (sql_generate_cond(stmt, *cond, &is_expr) != GS_SUCCESS) {
        lex->key_words = save_key_words;
        lex->key_word_count = save_key_word_count;
        cm_try_set_error_loc(word->text.loc);
        return GS_ERROR;
    }

    lex->key_words = save_key_words;
    lex->key_word_count = save_key_word_count;
    if (is_expr) {
        GS_SRC_THROW_ERROR(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "expect condition text");
        return GS_ERROR;
    }
    cond_text.len = (uint32)(word->text.str - cond_text.str);
    GS_LOG_DEBUG_INF("parse condition text\"%s\" sucessfully", T2S((text_t *)&cond_text));

    return GS_SUCCESS;
}

static status_t sql_generate_cond(sql_stmt_t *stmt, cond_tree_t *cond, bool32 *is_expr)
{
    cond_node_t *node = NULL;
    cmp_node_t *cmp_node = NULL;

    if (cond->chain.count == 0) {
        GS_SRC_THROW_ERROR(cond->loc, ERR_SQL_SYNTAX_ERROR, "condition error");
        return GS_ERROR;
    }
    node = cond->chain.first;

    if (node->next == NULL && node->type == COND_NODE_COMPARE) {
        cmp_node = node->cmp;
        if (cmp_node->type == CMP_TYPE_UNKNOWN) {
            *is_expr = GS_TRUE;
            return GS_SUCCESS;
        }
    }
    *is_expr = GS_FALSE;

    if (cond->chain.count != 1) {
        GS_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "condition error");
        return GS_ERROR;
    }

    cond->root = cond->chain.first;
    return GS_SUCCESS;
}
static status_t sql_parse_match_config(knl_session_t *se, knl_alter_sys_def_t *def, lex_t *lex)
{
    config_item_t *item = NULL;
    if (IS_LOG_MODE(def->param)) {
        text_t name = { .str = "_LOG_LEVEL", .len = sizeof("_LOG_LEVEL") - 1 };
        item = cm_get_config_item(GET_CONFIG, &name, GS_TRUE);
    } else {
        text_t name = { .str = def->param, .len = (uint32)strlen(def->param) };
        item = cm_get_config_item(GET_CONFIG, &name, GS_TRUE);
    }

    if (item == NULL) {
        GS_SRC_THROW_ERROR(lex->loc, ERR_INVALID_PARAMETER_NAME, def->param);
        return GS_ERROR;
    }

    def->param_id = item->id;

    /* VERIFY SET VALUE HERE. */
    if ((item->verify) && (item->verify((knl_handle_t)se, (void *)lex, (void *)def) != GS_SUCCESS)) {
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

static status_t sql_parse_alsys_set(session_t *session, knl_alter_sys_def_t *def, word_t *word)
{
    status_t status;

    lex_t *lex = session->lex;

    def->is_coord_conn = GS_FALSE;
    status = lex_expected_fetch_variant(lex, word);
    GS_RETURN_IFERR(status);

    def->action = ALSYS_SET_PARAM;
    GS_RETURN_IFERR(cm_text2str((text_t *)&word->text, def->param, GS_NAME_BUFFER_SIZE));
    cm_str_upper(def->param);

    status = lex_expected_fetch_word(lex, "=");
    GS_RETURN_IFERR(status);

    status = sql_parse_match_config(&session->knl_session, def, lex);
    GS_RETURN_IFERR(status);

    GS_RETURN_IFERR(sql_parse_scope_clause(def, lex));

    return lex_expected_end(lex);
}

static status_t sql_parse_alsys_load(sql_stmt_t *stmt, knl_alter_sys_def_t *def, word_t *word)
{
    lex_t *lex = stmt->session->lex;
    text_t user;
    text_t name;

    lex->flags = LEX_WITH_OWNER;

    if (lex_expected_fetch_word(lex, "DICTIONARY") != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (lex_expected_fetch_word(lex, "FOR") != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (lex_expected_fetch_variant(lex, word) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (sql_convert_object_name(stmt, word, &user, NULL, &name) != GS_SUCCESS) {
        return GS_ERROR;
    }

    GS_RETURN_IFERR(cm_text2str(&user, def->param, GS_NAME_BUFFER_SIZE));
    GS_RETURN_IFERR(cm_text2str(&name, def->value, GS_PARAM_BUFFER_SIZE));

    def->action = ALSYS_LOAD_DC;

    return lex_expected_end(lex);
}

static status_t sql_parse_alsys_reset(sql_stmt_t *stmt, lex_t *lex, knl_alter_sys_def_t *def)
{
    def->action = ALSYS_RESET_STATISTIC;
    if (lex_expected_fetch_word(lex, "statistic") != GS_SUCCESS) {
        return GS_ERROR;
    }
    return lex_expected_end(lex);
}

static status_t sql_parse_alsys_checkpoint(lex_t *lex, knl_alter_sys_def_t *def)
{
    uint32 match_id;

    GS_RETURN_IFERR(lex_try_fetch_1of2(lex, "GLOBAL", "LOCAL", &match_id));

    switch (match_id) {
        case 0:
            def->ckpt_type = CKPT_TYPE_GLOBAL;
            break;
        case 1:
        default:
            def->ckpt_type = CKPT_TYPE_LOCAL;
            break;
    }

    GS_RETURN_IFERR(lex_expected_end(lex));

    def->action = ALSYS_CHECKPOINT;
    return GS_SUCCESS;
}

static status_t sql_parse_alter_system(sql_stmt_t *stmt)
{
    word_t word;
    knl_alter_sys_def_t *def = NULL;
    status_t status;

    stmt->context->type = SQL_TYPE_ALTER_SYSTEM;
    status = sql_alloc_mem(stmt->context, sizeof(knl_alter_sys_def_t), (void **)&def);
    GS_RETURN_IFERR(status);

    status = lex_expected_fetch(stmt->session->lex, &word);
    GS_RETURN_IFERR(status);

    switch ((key_wid_t)word.id) {
        case KEY_WORD_SET:
            status = sql_parse_alsys_set(stmt->session, def, &word);
            break;

        case KEY_WORD_LOAD:
            status = sql_parse_alsys_load(stmt, def, &word);
            break;

        case KEY_WORD_INIT:
        case KEY_WORD_FLUSH:
        case KEY_WORD_RECYCLE:
        case KEY_WORD_DUMP:
        case KEY_WORD_KILL:
            status = GS_ERROR;
            break;

        case KEY_WORD_RESET:
            status = sql_parse_alsys_reset(stmt, stmt->session->lex, def);
            break;

        case KEY_WORD_CHECKPOINT:
            status = sql_parse_alsys_checkpoint(stmt->session->lex, def);
            break;

        case KEY_WORD_RELOAD:
        case KEY_WORD_REFRESH:
        case KEY_WORD_ADD:
        case KEY_WORD_DELETE:
        case KEY_WORD_DEBUG:
        case KEY_WORD_REPAIR:
            status = GS_ERROR;
            break;
        default:
            GS_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "key word expected but %s found", W2S(&word));
            return GS_ERROR;
    }

    stmt->context->entry = def;

    return status;
}

status_t sql_parse_dcl_alter(sql_stmt_t *stmt)
{
    word_t word;
    status_t status;

    status = lex_fetch(stmt->session->lex, &word);
    GS_RETURN_IFERR(status);

    switch ((uint32)word.id) {
        case KEY_WORD_SYSTEM:
            status = sql_parse_alter_system(stmt);
            break;

        case KEY_WORD_SESSION:
        default:
            GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "object type expected but %s found", W2S(&word));
            status = GS_ERROR;
            break;
    }

    return status;
}
static status_t sql_set_backup_type(knl_backup_t *param, backup_type_t type)
{
    if (param->type != BACKUP_MODE_INVALID) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "can not contain backup type more than once");
        return GS_ERROR;
    }

    param->type = type;
    return GS_SUCCESS;
}

static status_t sql_parse_backup_format(sql_stmt_t *stmt, word_t *word, knl_backup_t *param)
{
    status_t status;
    text_t sub_param;

    status = lex_expected_fetch_string(stmt->session->lex, word);
    GS_RETURN_IFERR(status);
    if (param->format.len > 0) {
        GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "can not set format more than once");
        return GS_ERROR;
    }

    if (!cm_fetch_text(&word->text.value, ':', '\0', &sub_param)) {
        GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "invalid format, can not find policy name");
        return GS_ERROR;
    }

    if (word->text.value.len > 0) {
        if (!cm_compare_text_str(&sub_param, "nbu")) {
            param->device = DEVICE_UDS;
            if (!cm_fetch_text(&word->text.value, ':', '\0', &param->policy)) {
                GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "invalid format, can not find policy name");
                return GS_ERROR;
            }

            if (param->policy.len >= GS_BACKUP_PARAM_SIZE) {
                GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR,
                                      "policy name exceeded the maximum length %u", GS_BACKUP_PARAM_SIZE);
                return GS_ERROR;
            }
        } else if (cm_compare_text_str(&sub_param, "disk")) {
            GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "invalid device type:%s", T2S(&sub_param));
            return GS_ERROR;
        }

        if (!cm_fetch_text(&word->text.value, ':', '\0', &sub_param)) {
            GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "invalid format, no dest path specified");
            return GS_ERROR;
        }
    }

    status = sql_copy_file_name(stmt->context, &sub_param, &param->format);
    GS_RETURN_IFERR(status);

    if (cm_fetch_text(&word->text.value, ':', '\0', &sub_param)) {
        GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "invalid format, %s value is invalid",
                              T2S(&sub_param));
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t sql_parse_backup_incremental(lex_t *lex, word_t *word, knl_backup_t *param)
{
    int32 level;

    if (sql_set_backup_type(param, BACKUP_MODE_INCREMENTAL) != GS_SUCCESS) {
        cm_try_set_error_loc(LEX_LOC);
        return GS_ERROR;
    }

    if (lex_expected_fetch_word(lex, "level") != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (lex_expected_fetch_int32(lex, &level) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (level != 0 && level != 1) {
        GS_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "level must be 0 or 1");
        return GS_ERROR;
    }

    param->level = level;
    return GS_SUCCESS;
}

static status_t sql_set_backup_prepare(knl_backup_t *param)
{
    if (param->finish_scn != GS_INVALID_ID64) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "can not set prepare and finish at the same time");
        return GS_ERROR;
    }

    param->prepare = GS_TRUE;
    return GS_SUCCESS;
}

static status_t sql_set_backup_finish(sql_stmt_t *stmt, word_t *word, knl_backup_t *param)
{
    if (param->prepare) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "can not set prepare and finish at the same time");
        return GS_ERROR;
    }

    if (param->finish_scn != GS_INVALID_ID64) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "can not set finish more than once");
        return GS_ERROR;
    }

    if (lex_expected_fetch_word(stmt->session->lex, "scn") != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (lex_expected_fetch_uint64(stmt->session->lex, &param->finish_scn) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t sql_parse_backup_tag(sql_stmt_t *stmt, word_t *word, char *tag)
{
    if (strlen(tag) > 0) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "can not set tag more than once");
        return GS_ERROR;
    }

    if (lex_expected_fetch_string(stmt->session->lex, word) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (word->text.len > GS_MAX_NAME_LEN) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "tag name exceed max name lengths %u", GS_MAX_NAME_LEN);
        return GS_ERROR;
    }

    if (word->text.len == 0) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "tag name can not set empty string");
        return GS_ERROR;
    }

    return cm_text2str(&word->text.value, tag, GS_NAME_BUFFER_SIZE);
}

static status_t sql_set_backup_cumulative(knl_backup_t *param)
{
    if (param->cumulative) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "can not set cumulative more than once");
        return GS_ERROR;
    }

    param->cumulative = GS_TRUE;
    return GS_SUCCESS;
}

static status_t sql_set_backup_as(sql_stmt_t *stmt, knl_backup_t *param)
{
    bool32 fetch_result = GS_FALSE;
    uint32 level;
    uint32 matched_id = GS_INVALID_ID32;
    compress_algo_e algorithm = COMPRESS_ZSTD;

    if (lex_try_fetch_1of3(stmt->session->lex, "zlib", "zstd", "lz4", &matched_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    switch (matched_id) {
        case 0:
            // warning "zlib compression algorithm is no longer supported"
            algorithm = COMPRESS_ZLIB;
            break;
        case 1:
            algorithm = COMPRESS_ZSTD;
            break;
        case 2:
            algorithm = COMPRESS_LZ4;
            break;
        default:
            break;
    }

    if (lex_expected_fetch_word(stmt->session->lex, "compressed") != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (lex_expected_fetch_word(stmt->session->lex, "backupset") != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (param->compress_algo != COMPRESS_NONE) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "can not set compressed more than once");
        return GS_ERROR;
    }
    param->compress_algo = algorithm;

    if (lex_try_fetch(stmt->session->lex, "level", &fetch_result) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (!fetch_result) {
        param->compress_level = Z_BEST_SPEED;  // level 1 with best speed
        return GS_SUCCESS;
    }

    if (lex_expected_fetch_uint32(stmt->session->lex, &level) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (level < Z_BEST_SPEED || level > Z_BEST_COMPRESSION) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "level value should be in [1, 9]");
        return GS_ERROR;
    }
    param->compress_level = level;
    return GS_SUCCESS;
}

static status_t sql_verify_backup_passwd(char *password)
{
    const char *pText;
    size_t len;
    bool32 num_flag = GS_FALSE;
    bool32 upper_flag = GS_FALSE;
    bool32 lower_flag = GS_FALSE;
    bool32 special_flag = GS_FALSE;
    uint32 type_count = 0;

    pText = password;
    len = strlen(pText);
    /* enforce minimum length */
    if (len < GS_PASSWD_MIN_LEN) {
        GS_THROW_ERROR(ERR_PASSWORD_FORMAT_ERROR, "password can't be less than min length characters");
        return GS_ERROR;
    }
    /* check maximum length */
    if (len > GS_PASSWD_MAX_LEN) {
        GS_THROW_ERROR(ERR_PASSWORD_FORMAT_ERROR, "password can't be greater than max length characters");
        return GS_ERROR;
    }

    /* The pwd should contain at least two type the following characters:
    A. at least one lowercase letter
    B. at least one uppercase letter
    C. at least one digit
    D. at least one special character: `~!@#$%^&*()-_=+\|[{}];:'",<.>/? and space
    If pwd contains the other character ,will return error. */
    for (uint32 i = 0; i < len; i++) {
        if (cm_verify_password_check(pText, i, &type_count, &num_flag, &upper_flag, &lower_flag, &special_flag) !=
            GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (type_count < CM_PASSWD_MIN_TYPE) {
        GS_THROW_ERROR(ERR_PASSWORD_IS_TOO_SIMPLE);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t sql_set_backup_password(sql_stmt_t *stmt, char *password, bool32 is_backup)
{
    word_t word;
    status_t status;

    status = lex_expected_fetch(stmt->session->lex, &word);
    GS_RETURN_IFERR(status);

    if (word.type != WORD_TYPE_VARIANT && word.type != WORD_TYPE_STRING && word.type != WORD_TYPE_DQ_STRING) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "The password must be identifier or string");
        return GS_ERROR;
    }
    if (word.type == WORD_TYPE_STRING) {
        LEX_REMOVE_WRAP(&word);
    }
    if (word.text.len == 0) {
        GS_SRC_THROW_ERROR_EX(word.loc, ERR_SQL_SYNTAX_ERROR, "invalid identifier, length 0");
        return GS_ERROR;
    }

    GS_RETURN_IFERR(cm_text2str((text_t *)&word.text, password, GS_PASSWORD_BUFFER_SIZE));
    if (GS_SUCCESS != sql_replace_password(stmt, &word.text.value)) {
        return GS_ERROR;
    }

    if (!is_backup) {
        // do not check restore's pwd
        return GS_SUCCESS;
    }

    return sql_verify_backup_passwd(password);
}

static status_t sql_set_backup_encrypt(sql_stmt_t *stmt, knl_backup_cryptinfo_t *crypt_info, bool32 is_backup)
{
    status_t status;

    if (crypt_info->encrypt_alg != ENCRYPT_NONE) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "can not set encrypted more than once");
        return GS_ERROR;
    }
    status = sql_set_backup_password(stmt, crypt_info->password, is_backup);
    crypt_info->encrypt_alg = AES_256_GCM;

    return status;
}

static status_t sql_set_backup_section(sql_stmt_t *stmt, knl_backup_t *param)
{
    int64 sec_thresh;

    if (param->section_threshold > 0) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "can not set section threshold more than once");
        return GS_ERROR;
    }

    if (lex_expected_fetch_word(stmt->session->lex, "threshold") != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (lex_expected_fetch_size(stmt->session->lex, &sec_thresh, BAK_MIN_SECTION_THRESHOLD,
                                BAK_MAX_SECTION_THRESHOLD) != GS_SUCCESS) {
        return GS_ERROR;
    }

    param->section_threshold = sec_thresh;
    return GS_SUCCESS;
}

static status_t sql_set_backup_parallelism(sql_stmt_t *stmt, uint32 *paral_num)
{
    if (paral_num == NULL) {
        return GS_ERROR;
    }

    if (*paral_num > 0) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "can not set parallelism more than once");
        return GS_ERROR;
    }

    if (lex_expected_fetch_uint32(stmt->session->lex, paral_num) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (*paral_num < 1 || *paral_num > (GS_MAX_BACKUP_PROCESS - BAK_PARAL_LOG_PROC_NUM - 1)) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "parallelism value should be in [%u, %u]", (uint32)1,
                          (uint32)(GS_MAX_BACKUP_PROCESS - BAK_PARAL_LOG_PROC_NUM - 1));
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t sql_check_backup_param(sql_stmt_t *stmt, knl_backup_t *param)
{
    bool32 result;
    uint32 buffer_size = (uint32)stmt->session->knl_session.kernel->attr.backup_buf_size;

    result = (param->prepare || param->finish_scn != GS_INVALID_ID64 || param->device == DEVICE_UDS);
    if (result) {
        if (strlen(param->tag) == 0) {
            GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "tag is not specified in bakcup command");
            return GS_ERROR;
        }
    }

    if (param->finish_scn != GS_INVALID_ID64) {
        if (param->type != BACKUP_MODE_INVALID) {
            GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "can not specify backup type when specified finish");
            return GS_ERROR;
        }

        if (param->format.len != 0) {
            GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "can not specify format when specified finish");
            return GS_ERROR;
        }

        if (param->crypt_info.encrypt_alg != ENCRYPT_NONE) {
            GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "can not specify password when specified finish");
            return GS_ERROR;
        }

        if (param->buffer_size != 0) {
            GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "can not specify buffer size when specified finish");
            return GS_ERROR;
        }

        param->type = BACKUP_MODE_FINISH_LOG;
    }

    if (param->type == BACKUP_MODE_INVALID) {
        param->type = BACKUP_MODE_FULL;
    }

    if (param->exclude_spcs->count > 0 && param->type == BACKUP_MODE_TABLESPACE) {
        GS_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "can not specify exclude with copy of");
        return GS_ERROR;
    }

    if (param->cumulative && param->type != BACKUP_MODE_INCREMENTAL) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "can not specify cumulative without incremental");
        return GS_ERROR;
    }

    if (param->finish_scn != GS_INVALID_ID64 && param->compress_algo) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "can not specify compress in finish");
        return GS_ERROR;
    }

    if (param->buffer_size == 0) {
        param->buffer_size = buffer_size;
    }

    return GS_SUCCESS;
}

static status_t sql_parse_backup_exclude(sql_stmt_t *stmt, word_t *word, knl_backup_t *param)
{
    lex_t *lex = stmt->session->lex;
    text_t *spc_name = NULL;
    sql_text_t save_text;

    if (param->exclude_spcs->count > 0) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "can not set exclude more than once");
        return GS_ERROR;
    }

    if (lex_expected_fetch_word(lex, "for") != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (lex_expected_fetch_word(lex, "tablespace") != GS_SUCCESS) {
        return GS_ERROR;
    }

    for (;;) {
        if (lex_expected_fetch_variant(lex, word) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (cm_galist_new(param->exclude_spcs, sizeof(text_t), (pointer_t *)&spc_name) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (sql_copy_object_name(stmt->context, word->type, (text_t *)&word->text, spc_name) != GS_SUCCESS) {
            return GS_ERROR;
        }

        save_text = *(lex->curr_text);
        if (lex_fetch(lex, word) != GS_SUCCESS) {
            return GS_ERROR;
        }

        GS_BREAK_IF_TRUE(word->type == WORD_TYPE_EOF);
        if (!(IS_SPEC_CHAR(word, ','))) {
            *(lex->curr_text) = save_text;
            break;
        }

        if (param->exclude_spcs->count >= GS_MAX_SPACES) {
            GS_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "exclude spaces number out of max spaces number");
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t sql_parse_backup_target(sql_stmt_t *stmt, word_t *word, knl_backup_t *param)
{
    lex_t *lex = stmt->session->lex;
    text_t *spc_name = NULL;
    sql_text_t save_text;

    status_t status = lex_expected_fetch_word(stmt->session->lex, "of");
    GS_RETURN_IFERR(status);
    status = lex_expected_fetch_word(lex, "tablespace");
    GS_RETURN_IFERR(status);

    if (param->type != BACKUP_MODE_INVALID && param->type != BACKUP_MODE_FULL) {
        GS_THROW_ERROR(ERR_INVALID_OPERATION, ", because there has a incompatible backup type for tablespace");
        return GS_ERROR;
    }

    for (;;) {
        if (lex_expected_fetch_variant(lex, word) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (cm_galist_new(param->target_info.target_list, sizeof(text_t), (pointer_t *)&spc_name) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (sql_copy_object_name(stmt->context, word->type, (text_t *)&word->text, spc_name) != GS_SUCCESS) {
            return GS_ERROR;
        }

        save_text = *(lex->curr_text);
        if (lex_fetch(lex, word) != GS_SUCCESS) {
            return GS_ERROR;
        }

        GS_BREAK_IF_TRUE(word->type == WORD_TYPE_EOF);
        if (!(IS_SPEC_CHAR(word, ','))) {
            *(lex->curr_text) = save_text;
            break;
        }

        if (param->target_info.target_list->count >= GS_MAX_SPACES) {
            GS_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "spaces number out of max spaces number");
            return GS_ERROR;
        }
    }

    param->type = BACKUP_MODE_TABLESPACE;
    param->target_info.target = TARGET_TABLESPACE;
    return GS_SUCCESS;
}

static status_t sql_parse_buffer_size(sql_stmt_t *stmt, uint32 *buffer_size)
{
    int64 size;

    if (lex_expected_fetch_word(stmt->session->lex, "size") != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (lex_expected_fetch_size(stmt->session->lex, &size, GS_MIN_BACKUP_BUF_SIZE, GS_MAX_BACKUP_BUF_SIZE) !=
        GS_SUCCESS) {
        return GS_ERROR;
    }

    *buffer_size = size;

    if ((*buffer_size) < GS_MIN_BACKUP_BUF_SIZE || (*buffer_size) > GS_MAX_BACKUP_BUF_SIZE) {
        GS_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "BACKUP_BUFFER_SIZE", (int64)GS_MIN_BACKUP_BUF_SIZE,
                       (int64)GS_MAX_BACKUP_BUF_SIZE);
        return GS_ERROR;
    }
    if ((*buffer_size) % (uint32)SIZE_M(8) != 0) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "buffer size (%u) is not an integral multiple of 8M.", *buffer_size);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t sql_parse_backup_arch_from(sql_stmt_t *stmt, knl_backup_t *param)
{
    if (lex_expected_fetch_word(stmt->session->lex, "asn") != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (lex_expected_fetch_uint32(stmt->session->lex, &param->target_info.backup_begin_asn) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t sql_parse_backup_archivelog(sql_stmt_t *stmt, knl_backup_t *param)
{
    status_t status;
    word_t word;
    uint32 match_id;

    param->target_info.target = TARGET_ARCHIVE;
    param->type = BACKUP_MODE_ARCHIVELOG;
    param->target_info.backup_arch_mode = ARCHIVELOG_ALL;
    status = lex_expected_fetch_1of2(stmt->session->lex, "all", "from", &match_id);
    GS_RETURN_IFERR(status);

    if (match_id == 1) {
        param->target_info.backup_arch_mode = ARCHIVELOG_FROM;
        status = sql_parse_backup_arch_from(stmt, param);
        GS_RETURN_IFERR(status);
    }

    for (;;) {
        status = lex_fetch(stmt->session->lex, &word);
        GS_RETURN_IFERR(status);

        if (word.type == WORD_TYPE_EOF) {
            break;
        }

        switch (word.id) {
            case KEY_WORD_FORMAT:
                status = sql_parse_backup_format(stmt, &word, param);
                break;
            case KEY_WORD_AS:
                status = sql_set_backup_as(stmt, param);
                break;
            case KEY_WORD_TAG:
                status = sql_parse_backup_tag(stmt, &word, param->tag);
                break;
            case KEY_WORD_BUFFER:
                status = sql_parse_buffer_size(stmt, &param->buffer_size);
                break;
            default:
                GS_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "key word expected but %s found",
                                      W2S(&word));
                return GS_ERROR;
        }

        if (status != GS_SUCCESS) {
            cm_try_set_error_loc(word.text.loc);
            return GS_ERROR;
        }
    }

    if (sql_check_backup_param(stmt, param) != GS_SUCCESS) {
        cm_try_set_error_loc(word.text.loc);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t sql_prase_backup_cancel(sql_stmt_t *stmt, knl_backup_t *param)
{
    status_t status;

    status = lex_expected_fetch_word(stmt->session->lex, "current");
    GS_RETURN_IFERR(status);
    status = lex_expected_fetch_word(stmt->session->lex, "process");
    GS_RETURN_IFERR(status);

    status = lex_expected_end(stmt->session->lex);
    GS_RETURN_IFERR(status);

    param->force_cancel = GS_TRUE;
    return GS_SUCCESS;
}

static status_t sql_parse_backup_core(sql_stmt_t *stmt, word_t word, knl_backup_t *param)
{
    status_t status;
    switch (word.id) {
        case KEY_WORD_FULL:
            status = sql_set_backup_type(param, BACKUP_MODE_FULL);
            break;
        case KEY_WORD_INCREMENTAL:
            status = sql_parse_backup_incremental(stmt->session->lex, &word, param);
            break;
        case KEY_WORD_FORMAT:
            status = sql_parse_backup_format(stmt, &word, param);
            break;
        case KEY_WORD_PREPARE:
            status = sql_set_backup_prepare(param);
            break;
        case KEY_WORD_FINISH:
            status = sql_set_backup_finish(stmt, &word, param);
            break;
        case KEY_WORD_TAG:
            status = sql_parse_backup_tag(stmt, &word, param->tag);
            break;
        case KEY_WORD_CUMULATIVE:
            status = sql_set_backup_cumulative(param);
            break;
        case KEY_WORD_AS:
            status = sql_set_backup_as(stmt, param);
            break;
        case KEY_WORD_SECTION:
            status = sql_set_backup_section(stmt, param);
            break;
        case KEY_WORD_PARALLELISM:
            status = sql_set_backup_parallelism(stmt, &param->parallelism);
            break;
        case KEY_WORD_EXCLUDE:
            status = sql_parse_backup_exclude(stmt, &word, param);
            break;
        case KEY_WORD_PASSWORD:
            status = sql_set_backup_encrypt(stmt, &param->crypt_info, GS_TRUE);
            break;
        case KEY_WORD_COPY:
            status = sql_parse_backup_target(stmt, &word, param);
            break;
        case KEY_WORD_BUFFER:
            status = sql_parse_buffer_size(stmt, &param->buffer_size);
            break;
        default:
            GS_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "key word expected but %s found", W2S(&word));
            return GS_ERROR;
    }
    if (status != GS_SUCCESS) {
        cm_try_set_error_loc(word.text.loc);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t sql_parse_backup(sql_stmt_t *stmt)
{
    status_t status;
    word_t word;
    knl_backup_t *param = NULL;

    status = sql_alloc_mem(stmt->context, sizeof(knl_backup_t), (void **)&param);
    GS_RETURN_IFERR(status);
    stmt->context->entry = param;

    MEMS_RETURN_IFERR(memset_s(param, sizeof(knl_backup_t), 0, sizeof(knl_backup_t)));

    param->finish_scn = GS_INVALID_ID64;
    param->type = BACKUP_MODE_INVALID;

    if (sql_create_list(stmt, &param->exclude_spcs) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (sql_create_list(stmt, &param->target_info.target_list) != GS_SUCCESS) {
        return GS_ERROR;
    }

    uint32 match_id;
    status = lex_expected_fetch_1of3(stmt->session->lex, "archivelog", "cancel", "database", &match_id);
    GS_RETURN_IFERR(status);

    if (match_id == 0) {
        return sql_parse_backup_archivelog(stmt, param);
    }

    if (match_id == 1) {
        return sql_prase_backup_cancel(stmt, param);
    }

    for (;;) {
        status = lex_fetch(stmt->session->lex, &word);
        GS_RETURN_IFERR(status);

        if (word.type == WORD_TYPE_EOF) {
            break;
        }

        GS_RETURN_IFERR(sql_parse_backup_core(stmt, word, param));
    }

    if (sql_check_backup_param(stmt, param) != GS_SUCCESS) {
        cm_try_set_error_loc(word.text.loc);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t sql_parse_until(sql_stmt_t *stmt, knl_restore_t *param)
{
    if (lex_expected_fetch_word(stmt->session->lex, "lfn") != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (lex_expected_fetch_uint64(stmt->session->lex, &param->lfn) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t sql_parse_restore_from(sql_stmt_t *stmt, word_t *word, knl_restore_t *param, bool32 block_recover)
{
    text_t sub_param;

    GS_RETURN_IFERR(lex_expected_fetch_string(stmt->session->lex, word));

    if (param->path.len > 0) {
        GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "can not set from more than once");
        return GS_ERROR;
    }

    (void)cm_fetch_text(&word->text.value, ':', '\0', &sub_param);
    if (word->text.value.len > 0) {
        if (!cm_compare_text_str(&sub_param, "nbu") && !block_recover) {
            param->device = DEVICE_UDS;
            if (!cm_fetch_text(&word->text.value, ':', '\0', &param->policy)) {
                GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "invalid format, can not find policy name");
                return GS_ERROR;
            }

            if (param->policy.len >= GS_BACKUP_PARAM_SIZE) {
                GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR,
                                      "policy name exceeded the maximum length %u", GS_BACKUP_PARAM_SIZE);
                return GS_ERROR;
            }
        } else if (cm_compare_text_str(&sub_param, "disk")) {
            GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "invalid device type:%s", T2S(&sub_param));
            return GS_ERROR;
        }

        if (!cm_fetch_text(&word->text.value, ':', '\0', &sub_param)) {
            GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "invalid format, no dest path specified");
            return GS_ERROR;
        }
    }

    GS_RETURN_IFERR(sql_copy_file_name(stmt->context, &sub_param, &param->path));

    if (cm_fetch_text(&word->text.value, ':', '\0', &sub_param)) {
        GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "invalid format, %s value is invalid",
                              T2S(&sub_param));
        return GS_ERROR;
    }

    param->type = block_recover ? RESTORE_BLOCK_RECOVER : RESTORE_FROM_PATH;
    return GS_SUCCESS;
}

static status_t sql_parse_restore_blockrecover(sql_stmt_t *stmt, knl_restore_t *param)
{
    status_t status;
    uint32 value;

    status = lex_expected_fetch_word(stmt->session->lex, "datafile");
    GS_RETURN_IFERR(status);

    if (lex_expected_fetch_uint32(stmt->session->lex, &value) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (value >= INVALID_FILE_ID) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "datafile value should be in [%u, %u]", (uint32)0,
                          (uint32)(INVALID_FILE_ID - 1));
        return GS_ERROR;
    }

    param->page_need_repair.file = value;

    status = lex_expected_fetch_word(stmt->session->lex, "page");
    GS_RETURN_IFERR(status);

    if (lex_expected_fetch_uint32(stmt->session->lex, &value) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (value == 0) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "page value should not be 0");
        return GS_ERROR;
    }

    param->page_need_repair.page = value;
    return status;
}

static status_t sql_parse_restore_filerecover(sql_stmt_t *stmt, knl_restore_t *param)
{
    uint32 match_id, value;
    word_t word;

    status_t status = lex_expected_fetch_1of2(stmt->session->lex, "filename", "fileid", &match_id);
    GS_RETURN_IFERR(status);

    if (match_id == 0) {
        if (lex_expected_fetch_string(stmt->session->lex, &word) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (sql_copy_file_name(stmt->context, (text_t *)&word.text, &param->file_repair_name) != GS_SUCCESS) {
            return GS_ERROR;
        }

        param->file_repair = GS_INVALID_FILEID;
    } else {
        if (lex_expected_fetch_uint32(stmt->session->lex, &value) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (value >= INVALID_FILE_ID) {
            GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "fileid value should be in [%u, %u]", (uint32)0,
                              (uint32)(INVALID_FILE_ID - 1));
            return GS_ERROR;
        }

        param->file_repair = value;
    }

    return GS_SUCCESS;
}

static status_t sql_parse_disconnect(sql_stmt_t *stmt, knl_restore_t *param)
{
    status_t status;

    if (param->disconnect == GS_TRUE) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "can not set disconnect more than once");
        return GS_ERROR;
    }

    status = lex_expected_fetch_word(stmt->session->lex, "from");
    GS_RETURN_IFERR(status);

    status = lex_expected_fetch_word(stmt->session->lex, "session");
    GS_RETURN_IFERR(status);

    param->disconnect = GS_TRUE;
    return GS_SUCCESS;
}

static status_t sql_parse_restore_type(sql_stmt_t *stmt, knl_restore_t *param)
{
    status_t status;
    uint32 match_id = GS_INVALID_ID32;

    if (IS_ZTRST_INSTANCE) {
        status = lex_expected_fetch_1of2(stmt->session->lex, "database", "blockrecover", &match_id);
    } else {
        status = lex_expected_fetch_1of3(stmt->session->lex, "database", "filerecover", "archivelog", &match_id);
    }
    GS_RETURN_IFERR(status);

    if (match_id == 1) {
        if (IS_ZTRST_INSTANCE) {
            param->type = RESTORE_BLOCK_RECOVER;
            status = sql_parse_restore_blockrecover(stmt, param);
        } else {
            param->file_type = RESTORE_DATAFILE;
            status = sql_parse_restore_filerecover(stmt, param);
        }

        GS_RETURN_IFERR(status);
    }

    if (match_id == 2) {
        param->file_type = RESTORE_ARCHFILE;
    }

    return GS_SUCCESS;
}

static status_t sql_check_restore_param(sql_stmt_t *stmt, knl_restore_t *param, word_t *word)
{
    uint32 buffer_size = (uint32)stmt->session->knl_session.kernel->attr.backup_buf_size;

    if (param->type != RESTORE_FROM_PATH) {
        GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "backup set path is not specified");
        return GS_ERROR;
    }

    if (param->buffer_size == 0) {
        param->buffer_size = buffer_size;
    }

    return GS_SUCCESS;
}

status_t sql_parse_restore(sql_stmt_t *stmt)
{
    knl_restore_t *param = NULL;
    word_t word;
    status_t status;

    status = sql_alloc_mem(stmt->context, sizeof(knl_restore_t), (void **)&param);
    GS_RETURN_IFERR(status);
    stmt->context->entry = param;

    MEMS_RETURN_IFERR(memset_s(param, sizeof(knl_restore_t), 0, sizeof(knl_restore_t)));

    status = sql_parse_restore_type(stmt, param);
    GS_RETURN_IFERR(status);

    status = lex_expected_fetch_word(stmt->session->lex, "from");
    GS_RETURN_IFERR(status);

    status = sql_parse_restore_from(stmt, &word, param, param->type == RESTORE_BLOCK_RECOVER);
    GS_RETURN_IFERR(status);

    if (param->file_type == RESTORE_ARCHFILE || param->file_type == RESTORE_DATAFILE) {
        status = lex_fetch(stmt->session->lex, &word);
        GS_RETURN_IFERR(status);

        if (word.id == KEY_WORD_BUFFER) {
            status = sql_parse_buffer_size(stmt, &param->buffer_size);
            GS_RETURN_IFERR(status);
        }
        uint32 buffer_size = (uint32)stmt->session->knl_session.kernel->attr.backup_buf_size;
        if (param->buffer_size == 0) {
            param->buffer_size = buffer_size;
        }

        return lex_expected_end(stmt->session->lex);
    }

    if (param->type == RESTORE_BLOCK_RECOVER) {
        status = lex_fetch(stmt->session->lex, &word);
        GS_RETURN_IFERR(status);

        if (word.id == KEY_WORD_UNTIL) {
            status = sql_parse_until(stmt, param);
            GS_RETURN_IFERR(status);
        } else if (word.type != WORD_TYPE_EOF) {
            GS_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "expected end but %s found", W2S(&word));
            return GS_ERROR;
        }

        return GS_SUCCESS;
    }

    for (;;) {
        status = lex_fetch(stmt->session->lex, &word);
        GS_RETURN_IFERR(status);

        if (word.type == WORD_TYPE_EOF) {
            break;
        }

        switch (word.id) {
            case KEY_WORD_DISCONNECT:
                status = sql_parse_disconnect(stmt, param);
                break;
            case KEY_WORD_PARALLELISM:
                status = sql_set_backup_parallelism(stmt, &param->parallelism);
                break;
            case KEY_WORD_TABLESPACE:
                status = lex_expected_fetch_variant(stmt->session->lex, &word);
                GS_RETURN_IFERR(status);
                status = sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, &param->spc_name);
                GS_RETURN_IFERR(status);
                break;
            case KEY_WORD_PASSWORD:
                status = sql_set_backup_encrypt(stmt, &param->crypt_info, GS_FALSE);
                break;
            case KEY_WORD_BUFFER:
                status = sql_parse_buffer_size(stmt, &param->buffer_size);
                break;
            default:
                GS_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "key word expected but %s found",
                                      W2S(&word));
                return GS_ERROR;
        }

        if (status != GS_SUCCESS) {
            cm_try_set_error_loc(word.text.loc);
            return GS_ERROR;
        }
    }

    if (sql_check_restore_param(stmt, param, &word) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t sql_parse_recover(sql_stmt_t *stmt)
{
    knl_recover_t *param = NULL;
    word_t word;
    text_t fmt_text;
    date_t date;
    uint32 match_id;

    GS_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(knl_recover_t), (void **)&param));
    stmt->context->entry = param;
    param->time.tv_sec = (long)GS_INVALID_INT64;
    param->time.tv_usec = 0;

    if (lex_expected_fetch_word(stmt->session->lex, "database") != GS_SUCCESS) {
        return GS_ERROR;
    }

    GS_RETURN_IFERR(lex_fetch(stmt->session->lex, &word));

    if (word.type == WORD_TYPE_EOF) {
        param->action = RECOVER_NORMAL;
        return GS_SUCCESS;
    }

    if (word.id != KEY_WORD_UNTIL) {
        GS_SRC_THROW_ERROR_EX(stmt->session->lex->loc, ERR_SQL_SYNTAX_ERROR, "until expected");
        return GS_ERROR;
    }

    if (lex_expected_fetch_1of3(stmt->session->lex, "time", "scn", "cancel", &match_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (match_id == 0) {
        if (lex_expected_fetch_string(stmt->session->lex, &word) != GS_SUCCESS) {
            return GS_ERROR;
        }
        sql_session_nlsparam_geter(stmt, NLS_DATE_FORMAT, &fmt_text);
        if (cm_text2date(&word.text.value, &fmt_text, &date) != GS_SUCCESS) {
            return GS_ERROR;
        }

        cm_date2timeval(date, &param->time);
        param->action = RECOVER_UNTIL_TIME;
        GS_LOG_RUN_INF("[RCY] start pitr until to time %s", T2S(&word.text.value));
    } else if (match_id == 1) {
        if (lex_expected_fetch_uint64(stmt->session->lex, &param->scn) != GS_SUCCESS) {
            return GS_ERROR;
        }
        param->action = RECOVER_UNTIL_SCN;
    } else {
        param->action = RECOVER_UNTIL_CANCEL;
    }

    return lex_expected_end(stmt->session->lex);
}

status_t sql_parse_shutdown(sql_stmt_t *stmt)
{
    lex_t *lex = stmt->session->lex;
    shutdown_context_t *param = NULL;
    uint32 matched_id;

    if (sql_alloc_mem(stmt->context, sizeof(shutdown_context_t), (void **)&param) != GS_SUCCESS) {
        return GS_ERROR;
    }

    stmt->context->entry = param;

    if (lex_try_fetch_1of2(lex, "immediate", "abort", &matched_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (matched_id == 0) {
        param->mode = SHUTDOWN_MODE_IMMEDIATE;
    } else if (matched_id == 1) {
        param->mode = SHUTDOWN_MODE_ABORT;
    } else {
        param->mode = SHUTDOWN_MODE_NORMAL;
    }

    return lex_expected_end(lex);
}

status_t sql_parse_dcl(sql_stmt_t *stmt, key_wid_t wid)
{
    status_t status;

    status = sql_alloc_context(stmt);
    GS_RETURN_IFERR(status);

    switch (wid) {
        case KEY_WORD_ALTER:
            status = sql_parse_dcl_alter(stmt);
            break;

        case KEY_WORD_COMMIT:
        case KEY_WORD_ROLLBACK:
        case KEY_WORD_SAVEPOINT:
        case KEY_WORD_RELEASE:
        case KEY_WORD_SET:
        case KEY_WORD_DAAC:
            status = GS_ERROR;
            break;

        case KEY_WORD_BACKUP:
            stmt->context->type = SQL_TYPE_BACKUP;
            status = sql_parse_backup(stmt);
            break;

        case KEY_WORD_RESTORE:
            stmt->context->type = SQL_TYPE_RESTORE;
            status = sql_parse_restore(stmt);
            break;

        case KEY_WORD_RECOVER:
            stmt->context->type = SQL_TYPE_RECOVER;
            status = sql_parse_recover(stmt);
            break;

        case KEY_WORD_SHUTDOWN:
            stmt->context->type = SQL_TYPE_SHUTDOWN;
            return sql_parse_shutdown(stmt);

        case KEY_WORD_CHECKPOINT:
            stmt->context->type = SQL_TYPE_CHECKPOINT;
            status = lex_expected_end(stmt->session->lex);
            break;
        default:
            GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "key word expected");
            status = GS_ERROR;
            break;
    }

    return status;
}

#define SQL_CONVERT_BUFFER_SIZE 80

cols_used_t g_cols_used_init;

static inline uint32 sql_concat_result_len(variant_t *v1, variant_t *v2)
{
    uint32 len;

    if (v1->is_null) {
        len = 0;
    } else {
        if (GS_IS_STRING_TYPE(v1->type)) {
            len = v1->v_text.len;
        } else if (GS_IS_BINARY_TYPE(v1->type) || GS_IS_RAW_TYPE(v1->type)) {
            len = 2 * (v1->v_bin.size + 1);
        } else {
            len = cm_get_datatype_strlen(v1->type, SQL_CONVERT_BUFFER_SIZE);
        }
    }

    if (!v2->is_null) {
        if (GS_IS_STRING_TYPE(v2->type)) {
            len += v2->v_text.len;
        } else if (GS_IS_BINARY_TYPE(v2->type) || GS_IS_RAW_TYPE(v2->type)) {
            len += 2 * (v2->v_bin.size + 1);
        } else {
            len += cm_get_datatype_strlen(v2->type, SQL_CONVERT_BUFFER_SIZE);
        }
    }

    return MIN(len, GS_MAX_STRING_LEN);
}

static status_t sql_exec_concat_normal(sql_stmt_t *stmt, variant_t *l_var, variant_t *r_var, variant_t *result)
{
    uint32 result_len;
    result_len = sql_concat_result_len(l_var, r_var);
    GS_RETURN_IFERR(sql_push(stmt, result_len, (void **)&result->v_text.str));
    result->v_text.len = result_len;
    return opr_exec(OPER_TYPE_CAT, SESSION_NLS(stmt), l_var, r_var, result);
}

status_t sql_exec_concat(sql_stmt_t *stmt, variant_t *l_var, variant_t *r_var, variant_t *result)
{
    if (l_var->is_null && r_var->is_null) {
        VAR_SET_NULL(result, GS_DATATYPE_OF_NULL);
        return GS_SUCCESS;
    }

    if (GS_IS_CLOB_TYPE(l_var->type) || GS_IS_CLOB_TYPE(r_var->type)) {
        return GS_ERROR;
    } else {
        return sql_exec_concat_normal(stmt, l_var, r_var, result);
    }
}

#define SQL_EXEC_EXPR_OPRAND(expr, var, result, stmt)               \
    do {                                                            \
        GS_RETURN_IFERR(sql_exec_expr_node((stmt), (expr), (var))); \
        if ((var)->type == GS_TYPE_COLUMN) {                        \
            (result)->type = GS_TYPE_COLUMN;                        \
            (result)->is_null = GS_FALSE;                           \
            return GS_SUCCESS;                                      \
        }                                                           \
        sql_keep_stack_variant((stmt), (var));                      \
    } while (0)

status_t sql_exec_oper(sql_stmt_t *stmt, expr_node_t *node, variant_t *result)
{
    status_t status;
    variant_t l_var, r_var;

    SQL_EXEC_EXPR_OPRAND(node->left, &l_var, result, stmt);

    /* return null if result of left expression is null except concat */
    if (l_var.is_null == GS_TRUE && node->type != EXPR_NODE_CAT) {
        result->type = GS_DATATYPE_OF_NULL;
        result->is_null = GS_TRUE;
        return GS_SUCCESS;
    }

    SQL_EXEC_EXPR_OPRAND(node->right, &r_var, result, stmt);

    if (node->type == EXPR_NODE_CAT) {
        return sql_exec_concat(stmt, &l_var, &r_var, result);
    }

    status = opr_exec((operator_type_t)node->type, SESSION_NLS(stmt), &l_var, &r_var, result);
    if (SECUREC_UNLIKELY(status != GS_SUCCESS)) {
        cm_set_error_loc(node->loc);
    }

    return status;
}

status_t sql_exec_unary(expr_node_t *node, variant_t *var)
{
    if (var->is_null || node->unary == UNARY_OPER_ROOT) {
        return GS_SUCCESS;
    }

    if (var_as_num(var) != GS_SUCCESS) {
        GS_SRC_THROW_ERROR(node->loc, ERR_INVALID_NUMBER, cm_get_num_errinfo(NERR_ERROR));
        return GS_ERROR;
    }

    if (!UNARY_INCLUDE_NEGATIVE(node)) {
        return GS_SUCCESS;
    }

    switch (var->type) {
        case GS_TYPE_INTEGER:
            VALUE(int32, var) = -VALUE(int32, var);
            break;

        case GS_TYPE_BIGINT:
            VALUE(int64, var) = -VALUE(int64, var);
            break;

        case GS_TYPE_REAL:
            VALUE(double, var) = -VALUE(double, var);
            break;

        case GS_TYPE_NUMBER2:
        case GS_TYPE_NUMBER:
        case GS_TYPE_DECIMAL:
            cm_dec_negate(&var->v_dec);
            break;

        default:
            CM_NEVER;
            break;
    }

    return GS_SUCCESS;
}

static status_t sql_exec_unary_oper(sql_stmt_t *stmt, expr_node_t *node, variant_t *result)
{
    status_t status;
    variant_t var;
    SQL_EXEC_EXPR_OPRAND(node->right, &var, result, stmt);

    if (var.is_null) {
        result->type = GS_DATATYPE_OF_NULL;
        result->is_null = GS_TRUE;
        return GS_SUCCESS;
    }

    if (var_as_num(&var) != GS_SUCCESS) {
        GS_SRC_THROW_ERROR(node->loc, ERR_INVALID_NUMBER, "");
        return GS_ERROR;
    }

    result->is_null = GS_FALSE;

    status = opr_unary(&var, result);
    if (status != GS_SUCCESS) {
        cm_set_error_loc(node->loc);
    }

    return status;
}

inline status_t sql_get_reserved_value(sql_stmt_t *stmt, expr_node_t *node, variant_t *value)
{
    switch (node->value.v_int) {
        case RES_WORD_NULL:
        case RES_WORD_DUMMY:
            value->type = GS_DATATYPE_OF_NULL;
            value->is_null = GS_TRUE;
            break;

        case RES_WORD_CURDATE:
            value->type = GS_TYPE_DATE;
            value->is_null = GS_FALSE;
            if (stmt->v_sysdate == SQL_UNINITIALIZED_DATE) {
                /* drop millsec and microsec data */
                stmt->v_sysdate = cm_adjust_date(cm_now());
            }

            /* adjust with the session time zone */
            VALUE(date_t, value) = cm_adjust_date_between_two_tzs(stmt->v_sysdate, g_timer()->tz,
                                                                  sql_get_session_timezone(stmt));

            break;

        case RES_WORD_SYSDATE:
            value->type = GS_TYPE_DATE;
            value->is_null = GS_FALSE;
            SQL_GET_STMT_SYSDATE(stmt, value);
            break;

        case RES_WORD_CURTIMESTAMP:
            if (stmt->session->call_version >= CS_VERSION_8) {
                value->type = GS_TYPE_TIMESTAMP_TZ;
                value->v_tstamp_tz.tz_offset = sql_get_session_timezone(stmt);
            } else {
                value->type = GS_TYPE_TIMESTAMP_TZ_FAKE;
            }
            value->is_null = GS_FALSE;

            if ((stmt)->v_systimestamp == SQL_UNINITIALIZED_TSTAMP) {
                (stmt)->v_systimestamp = cm_now();
            }
            /* adjust with the session time zone */
            value->v_tstamp_tz.tstamp = cm_adjust_date_between_two_tzs(stmt->v_systimestamp, g_timer()->tz,
                                                                       sql_get_session_timezone(stmt));
            break;

        case RES_WORD_SYSTIMESTAMP:
            if (stmt->session->call_version >= CS_VERSION_8) {
                value->type = GS_TYPE_TIMESTAMP_TZ;
                value->v_tstamp_tz.tz_offset = g_timer()->tz;
            } else {
                value->type = GS_TYPE_TIMESTAMP_TZ_FAKE;
            }
            value->is_null = GS_FALSE;

            if ((stmt)->v_systimestamp == SQL_UNINITIALIZED_TSTAMP) {
                (stmt)->v_systimestamp = cm_now();
            }
            value->v_tstamp_tz.tstamp = stmt->v_systimestamp;
            break;

        case RES_WORD_LOCALTIMESTAMP:
            value->type = GS_TYPE_TIMESTAMP;
            value->is_null = GS_FALSE;

            if ((stmt)->v_systimestamp == SQL_UNINITIALIZED_TSTAMP) {
                (stmt)->v_systimestamp = cm_now();
            }

            /* adjust with the session time zone */
            value->v_tstamp = cm_adjust_date_between_two_tzs(stmt->v_systimestamp, g_timer()->tz,
                                                             sql_get_session_timezone(stmt));
            break;

        case RES_WORD_UTCTIMESTAMP:
            value->v_date = cm_utc_now();
            value->is_null = GS_FALSE;
            value->type = GS_TYPE_DATE;
            break;

        case RES_WORD_ROWNUM:
            return sql_get_rownum(stmt, value);

        case RES_WORD_ROWID:
            return sql_get_rowid(stmt, &node->value.v_rid, value);

        case RES_WORD_ROWNODEID:
            return GS_ERROR;

        case RES_WORD_ROWSCN:
            return sql_get_rowscn(stmt, &node->value.v_rid, value);

        case RES_WORD_DEFAULT:
            return GS_ERROR;

        case RES_WORD_TRUE:
            value->type = GS_TYPE_BOOLEAN;
            value->is_null = GS_FALSE;
            value->v_bool = GS_TRUE;
            break;

        case RES_WORD_FALSE:
            value->type = GS_TYPE_BOOLEAN;
            value->is_null = GS_FALSE;
            value->v_bool = GS_FALSE;
            break;

        case RES_WORD_DELETING:
        case RES_WORD_INSERTING:
        case RES_WORD_UPDATING:
        case RES_WORD_LEVEL:
        case RES_WORD_CONNECT_BY_ISLEAF:
        case RES_WORD_CONNECT_BY_ISCYCLE:
            return GS_ERROR;

        case RES_WORD_USER:
            value->type = GS_TYPE_STRING;
            value->is_null = GS_FALSE;
            value->v_text.str = stmt->session->db_user;
            value->v_text.len = (uint32)strlen(stmt->session->db_user);
            break;

        case RES_WORD_DATABASETZ:
            value->type = GS_TYPE_STRING;
            value->is_null = GS_FALSE;

            char *dbtz = server_get_param("DB_TIMEZONE");
            value->v_text.str = dbtz;
            value->v_text.len = (uint32)strlen(dbtz);
            break;

        case RES_WORD_SESSIONTZ:
            value->type = GS_TYPE_STRING;
            value->is_null = GS_FALSE;
            GS_RETURN_IFERR(sql_push(stmt, TIMEZONE_OFFSET_STRLEN, (void **)&(value->v_text.str)));
            if (cm_tzoffset2text(sql_get_session_timezone(stmt), &(value->v_text)) != GS_SUCCESS) {
                SQL_POP(stmt);
                return GS_ERROR;
            }
            sql_keep_stack_variant(stmt, value);
            break;

        default:
            GS_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "reserved word not in list");
            return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t sql_get_lob_value_from_knl(sql_stmt_t *stmt, variant_t *result)
{
    char *buf = NULL;
    uint32 len;
    knl_handle_t lob_locator;

    lob_locator = (knl_handle_t)result->v_lob.knl_lob.bytes;
    len = knl_lob_size(lob_locator);
    if (len != 0) {
        if (len > g_instance->attr.lob_max_exec_size) {
            GS_THROW_ERROR(ERR_ILEGAL_LOB_READ, len, g_instance->attr.lob_max_exec_size);
            return GS_ERROR;
        }
        sql_keep_stack_variant(stmt, result);
        GS_RETURN_IFERR(sql_push(stmt, len, (void **)&buf));
        GS_RETURN_IFERR(knl_read_lob(stmt->session, lob_locator, 0, (void *)buf, len, NULL));
    }

    if (result->type == GS_TYPE_CLOB || result->type == GS_TYPE_IMAGE) {
        result->type = GS_TYPE_STRING;
        result->v_text.str = buf;
        result->v_text.len = len;
    } else {
        result->type = GS_TYPE_RAW;
        result->v_bin.bytes = (uint8 *)buf;
        result->v_bin.size = len;
    }
    return GS_SUCCESS;
}

status_t sql_get_lob_value(sql_stmt_t *stmt, variant_t *result)
{
    if (result->is_null) {
        result->type = (result->type == GS_TYPE_CLOB || result->type == GS_TYPE_IMAGE) ? GS_TYPE_STRING : GS_TYPE_RAW;
        return GS_SUCCESS;
    }

    switch (result->v_lob.type) {
        case GS_LOB_FROM_KERNEL:
            GS_RETURN_IFERR(sql_get_lob_value_from_knl(stmt, result));
            break;

        case GS_LOB_FROM_NORMAL:
        //fall through
        case GS_LOB_FROM_VMPOOL:
        //fall through
        default:
            GS_THROW_ERROR(ERR_UNKNOWN_LOB_TYPE, "do get lob value");
            return GS_ERROR;
    }

    if (g_instance->sql.enable_empty_string_null == GS_TRUE && result->v_text.len == 0 &&
        (GS_IS_STRING_TYPE(result->type) || GS_IS_BINARY_TYPE(result->type) || GS_IS_RAW_TYPE(result->type))) {
        result->is_null = GS_TRUE;
    }
    return GS_SUCCESS;
}

static sql_table_t g_init_table = {
    .id = 0,
    .type = NORMAL_TABLE,
};

status_t sql_get_param_value(sql_stmt_t *stmt, uint32 id, variant_t *result)
{
    if (stmt->is_explain) {
        result->is_null = GS_TRUE;
        return GS_SUCCESS;
    }

    {
        var_copy(&stmt->param_info.params[id].value, result);
        return GS_SUCCESS;
    }
}

void sql_copy_first_exec_var(sql_stmt_t *stmt, variant_t *src, variant_t *dst)
{
    if (src->is_null) {
        dst->ctrl = src->ctrl;
        return;
    }

    if (!GS_IS_VARLEN_TYPE(src->type)) {  // copy non-var-len datatype
        var_copy(src, dst);
        return;
    }

    // copy var-len datatype
    // if buff space is insufficient, then do not optimize
    if ((stmt->fexec_info.fexec_buff_offset + src->v_text.len) > stmt->context->fexec_vars_bytes) {
        return;
    }

    // compute the data buff address
    dst->v_text.str = (char *)stmt->fexec_info.first_exec_vars + (stmt->context->fexec_vars_cnt * sizeof(variant_t)) +
                      stmt->fexec_info.fexec_buff_offset;

    if (src->v_text.len != 0) {
        MEMS_RETVOID_IFERR(memcpy_s(dst->v_text.str, src->v_text.len, src->v_text.str, src->v_text.len));
    }
    if (src->type == GS_TYPE_BINARY) {
        dst->v_bin.is_hex_const = src->v_bin.is_hex_const;
    }

    dst->ctrl = src->ctrl;
    dst->v_text.len = src->v_text.len;
    stmt->fexec_info.fexec_buff_offset += dst->v_text.len;
}

status_t sql_exec_expr_node(sql_stmt_t *stmt, expr_node_t *node, variant_t *result)
{
    status_t status;
    sql_cursor_t *cursor = NULL;
    sql_cursor_t *saved_cursor = NULL;
    bool32 exist_first_exec_vars = (bool32)(NODE_IS_FIRST_EXECUTABLE(node) && F_EXEC_VARS(stmt) != NULL);

    GS_RETURN_IFERR(sql_stack_safe(stmt));
    if (exist_first_exec_vars && F_EXEC_VALUE(stmt, node)->type != GS_TYPE_UNINITIALIZED) {
        var_copy(F_EXEC_VALUE(stmt, node), result);
        return GS_SUCCESS;
    }

    bool32 unary_root = ((int32)node->unary == (int32)UNARY_OPER_ROOT || (int32)node->unary == -(int32)UNARY_OPER_ROOT);

    if (SECUREC_UNLIKELY(unary_root)) {
        if (stmt->cursor_stack.depth == 0) {
            GS_SRC_THROW_ERROR_EX(node->loc, ERR_SQL_SYNTAX_ERROR, "CONNECT BY clause required in this query block");
            return GS_ERROR;
        }
        cursor = SQL_CURR_CURSOR(stmt);
        if (cursor->connect_data.first_level_cursor == NULL) {
            GS_SRC_THROW_ERROR_EX(node->loc, ERR_SQL_SYNTAX_ERROR, "CONNECT BY clause required in this query block");
            return GS_ERROR;
        }

        saved_cursor = cursor->connect_data.cur_level_cursor;
        cursor->connect_data.cur_level_cursor = cursor->connect_data.first_level_cursor;
        GS_RETURN_IFERR(SQL_CURSOR_PUSH(stmt, cursor));
    }

    status = sql_get_node_func(node->type)->invoke(stmt, node, result);

    if (SECUREC_UNLIKELY(unary_root)) {
        cursor->connect_data.cur_level_cursor = saved_cursor;
        SQL_CURSOR_POP(stmt);
    }

    if (status != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (node->unary != UNARY_OPER_NONE) {
        GS_RETURN_IFERR(sql_exec_unary(node, result));
    }

    if (exist_first_exec_vars) {
        if (result->type == GS_TYPE_ARRAY) {
            return GS_SUCCESS;
        }
        sql_copy_first_exec_var(stmt, result, F_EXEC_VALUE(stmt, node));
    }

    if (node->type != EXPR_NODE_PARAM && !result->is_null && GS_IS_NUMBER_TYPE(result->type)) {
        GS_RETURN_IFERR(cm_dec_check_overflow(VALUE_PTR(dec8_t, result), result->type));
    }
    return GS_SUCCESS;
}

status_t sql_exec_default(void *stmt, void *default_expr, variant_t *value)
{
    return sql_exec_expr((sql_stmt_t *)stmt, (expr_tree_t *)default_expr, value);
}

/*
  This function will be called when create an function index.
  We should compare the expression node rather than the expression text only.
*/
bool32 sql_compare_index_expr(knl_handle_t session, text_t *func_text1, text_t *func_text2)
{
    sql_stmt_t *stmt = ((session_t *)session)->current_stmt;
    sql_text_t sql_text;
    sql_verifier_t verf = { 0 };
    expr_tree_t *expr1 = NULL;
    expr_tree_t *expr2 = NULL;

    verf.stmt = stmt;
    verf.context = stmt->context;
    verf.is_check_cons = GS_TRUE;
    verf.table_def = ((stmt->context->type == SQL_TYPE_CREATE_TABLE) &&
                      DB_ATTR_COMPATIBLE_MYSQL((knl_session_t *)session))
                         ? (knl_table_def_t *)stmt->context->entry
                         : NULL;
    verf.excl_flags = SQL_EXCL_AGGR | SQL_EXCL_STAR | SQL_EXCL_SUBSELECT | SQL_EXCL_BIND_PARAM | SQL_EXCL_PRIOR |
                      SQL_EXCL_JOIN | SQL_EXCL_ROWNUM | SQL_EXCL_ROWID | SQL_EXCL_DEFAULT | SQL_EXCL_ROWSCN |
                      SQL_EXCL_SEQUENCE | SQL_EXCL_WIN_SORT | SQL_EXCL_GROUPING | SQL_EXCL_PATH_FUNC;

    sql_text.value = *func_text1;
    sql_text.loc.column = 1;
    sql_text.loc.line = 1;

    lex_t *lex = ((session_t *)session)->lex;
    lex->flags |= (LEX_WITH_ARG | LEX_WITH_OWNER);

    if (sql_create_expr_from_text(stmt, &sql_text, &expr1, WORD_FLAG_NONE) != GS_SUCCESS) {
        return GS_FALSE;
    }

    if (sql_verify_expr_node(&verf, expr1->root) != GS_SUCCESS) {
        return GS_ERROR;
    }

    sql_text.value = *func_text2;
    sql_text.loc.column = 1;
    sql_text.loc.line = 1;
    if (sql_create_expr_from_text(stmt, &sql_text, &expr2, WORD_FLAG_NONE) != GS_SUCCESS) {
        return GS_FALSE;
    }

    if (sql_verify_expr_node(&verf, expr2->root) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return sql_expr_node_equal(stmt, expr1->root, expr2->root, NULL);
}

/*
  this function will be called when alter column's precision or datatype
*/
status_t sql_get_func_index_expr_size(knl_handle_t session, text_t *default_text, typmode_t *typmode)
{
    sql_stmt_t *stmt = ((session_t *)session)->current_stmt;
    sql_text_t sql_text;
    sql_verifier_t verf = { 0 };
    expr_tree_t *expr = NULL;

    lex_t *lex = ((session_t *)session)->lex;

    sql_text.value = *default_text;
    sql_text.loc.column = 1;
    sql_text.loc.line = 1;
    lex->flags |= (LEX_WITH_ARG | LEX_WITH_OWNER);

    if (sql_create_expr_from_text(stmt, &sql_text, &expr, WORD_FLAG_NONE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    verf.stmt = stmt;
    verf.context = stmt->context;
    verf.is_check_cons = GS_TRUE;
    verf.typmode = typmode;
    verf.excl_flags = SQL_EXCL_AGGR | SQL_EXCL_STAR | SQL_EXCL_SUBSELECT | SQL_EXCL_BIND_PARAM | SQL_EXCL_PRIOR |
                      SQL_EXCL_JOIN | SQL_EXCL_ROWNUM | SQL_EXCL_ROWID | SQL_EXCL_DEFAULT | SQL_EXCL_ROWSCN |
                      SQL_EXCL_SEQUENCE | SQL_EXCL_WIN_SORT | SQL_EXCL_GROUPING | SQL_EXCL_PATH_FUNC;

    if (sql_verify_expr_node(&verf, expr->root) != GS_SUCCESS) {
        return GS_ERROR;
    }

    *typmode = TREE_TYPMODE(expr);
    return GS_SUCCESS;
}

/*
 * This function will be called when executing:
 * 1. add index/constraint
 * 2. insert/update
 */
status_t sql_exec_index_col_func(knl_handle_t sess, knl_handle_t knl_cursor, gs_type_t datatype, void *expr,
                                 variant_t *result, bool32 is_new)
{
    status_t status;
    session_t *session = (session_t *)sess;
    sql_stmt_t *stmt = session->current_stmt;
    knl_cursor_t *knl_cur = (knl_cursor_t *)knl_cursor;
    knl_cursor_t *saved_cur = stmt->direct_knl_cursor;
    bool32 saved_check = stmt->is_check;
    typmode_t *mode = &TREE_TYPMODE((expr_tree_t *)expr);

    SQL_SAVE_STACK(stmt);

    stmt->direct_knl_cursor = knl_cur;
    stmt->is_check = is_new;
    do {
        status = sql_exec_expr(stmt, (expr_tree_t *)expr, result);
        GS_BREAK_IF_ERROR(status);
        if (result->type != datatype) {
            status = sql_convert_variant(stmt, result, datatype);
        }
        GS_BREAK_IF_ERROR(status);
        if (!result->is_null && result->type == GS_TYPE_CHAR && datatype == GS_TYPE_CHAR) {
            status = sql_convert_char(KNL_SESSION(stmt), result, mode->size, mode->is_char);
        }
    } while (0);

    stmt->is_check = saved_check;
    stmt->direct_knl_cursor = saved_cur;

    SQL_RESTORE_STACK(stmt);
    return status;
}

status_t sql_convert_to_scn(sql_stmt_t *stmt, void *expr, bool32 scn_type, uint64 *scn)
{
    variant_t value;

    if (sql_exec_expr(stmt, (expr_tree_t *)expr, &value) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (value.is_null) {
        GS_THROW_ERROR(ERR_VALUE_ERROR, "NULL value is not a valid system change number");
        return GS_ERROR;
    }

    if (scn_type) {
        if (var_as_floor_bigint(&value) != GS_SUCCESS) {
            return GS_ERROR;
        }

        *scn = (uint64)value.v_bigint;
        if (*scn >= knl_next_scn(&stmt->session->knl_session)) {
            GS_THROW_ERROR(ERR_VALUE_ERROR, "specified number is not a valid system change number");
            return GS_ERROR;
        }
    } else {
        if (var_as_timestamp(SESSION_NLS(stmt), &value) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (knl_timestamp_to_scn(&stmt->session->knl_session, value.v_tstamp, scn) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (*scn >= knl_next_scn(&stmt->session->knl_session)) {
            GS_THROW_ERROR(ERR_VALUE_ERROR, "invalid timestamp specified");
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t sql_clone_text(void *ctx, text_t *src, text_t *dest, ga_alloc_func_t alloc_mem_func)
{
    char *buf = NULL;

    if (src == NULL) {
        return GS_SUCCESS;
    }

    if (src->len == 0 && g_instance->sql.enable_empty_string_null) {
        // empty text is used as NULL like oracle
        dest->str = NULL;
        dest->len = 0;
        return GS_SUCCESS;
    }

    GS_RETURN_IFERR(alloc_mem_func(ctx, sizeof(char) * (src->len + 1), (void **)&buf));
    if (src->len > 0) {
        MEMS_RETURN_IFERR(memcpy_s(buf, src->len, src->str, src->len));
        buf[src->len] = 0;
    }

    dest->str = buf;
    dest->len = src->len;
    return GS_SUCCESS;
}

static status_t sql_clone_sql_text(void *ctx, sql_text_t *src, sql_text_t *dest, ga_alloc_func_t alloc_mem_func)
{
    GS_RETURN_IFERR(sql_clone_text(ctx, &src->value, &dest->value, alloc_mem_func));
    dest->implicit = src->implicit;
    dest->len = src->len;
    dest->loc = src->loc;
    dest->str = dest->value.str;
    return GS_SUCCESS;
}

static status_t sql_clone_var_word(expr_node_type_t type, void *ctx, var_word_t *src, var_word_t *dest,
                                   ga_alloc_func_t alloc_mem_func)
{
    if (src == NULL) {
        return GS_SUCCESS;
    }
    if (dest == NULL) {
        GS_RETURN_IFERR(alloc_mem_func(ctx, sizeof(var_word_t), (void **)&dest));
    }

    // 1. var_word_t is union, deep clone can't clone every union member
    // 2. func.args (expr string) may be very long ( larger than 16KB),
    //    it will cause memory alloc fail.
    *dest = *src;

    // func.user func.pack func.name should be cloned
    if (type == EXPR_NODE_FUNC || type == EXPR_NODE_USER_FUNC || type == EXPR_NODE_PROC ||
        type == EXPR_NODE_USER_PROC) {
        GS_RETURN_IFERR(sql_clone_sql_text(ctx, &src->func.user, &dest->func.user, alloc_mem_func));
        GS_RETURN_IFERR(sql_clone_sql_text(ctx, &src->func.pack, &dest->func.pack, alloc_mem_func));
        GS_RETURN_IFERR(sql_clone_sql_text(ctx, &src->func.name, &dest->func.name, alloc_mem_func));
    }

    return GS_SUCCESS;
}

status_t sql_clone_var_column(void *ctx, var_column_t *src, var_column_t *dest, ga_alloc_func_t alloc_mem_func)
{
    if (src == NULL) {
        return GS_SUCCESS;
    }
    if (dest == NULL) {
        GS_RETURN_IFERR(alloc_mem_func(ctx, sizeof(var_column_t), (void **)&dest));
    }

    dest->datatype = src->datatype;
    dest->tab = src->tab;
    dest->col = src->col;
    dest->ancestor = src->ancestor;
    dest->is_ddm_col = src->is_ddm_col;
    dest->is_array = src->is_array;
    dest->is_jsonb = src->is_jsonb;
    dest->ss_start = src->ss_start;
    dest->ss_end = src->ss_end;

    return GS_SUCCESS;
}

static status_t sql_clone_lob(void *ctx, variant_t *src, variant_t *dest, ga_alloc_func_t alloc_mem_func)
{
    if (src == NULL) {
        return GS_SUCCESS;
    }
    *dest = *src;

    if (src->v_lob.type != GS_LOB_FROM_NORMAL) {
        return GS_SUCCESS;
    }

    return sql_clone_text(ctx, &src->v_lob.normal_lob.value, &dest->v_lob.normal_lob.value, alloc_mem_func);
}

/*
 * sql_clone_variant
 * - This function is used to deep clone a variant_t.
 *
 */
static status_t sql_clone_variant(void *ctx, variant_t *src, variant_t *dest, ga_alloc_func_t alloc_mem_func)
{
    dest->ctrl = src->ctrl;
    if (src->is_null) {
        return GS_SUCCESS;
    }

    switch (src->type) {
        case GS_TYPE_CHAR:    /* char(n) */
        case GS_TYPE_VARCHAR: /* varchar, varchar2 */
        case GS_TYPE_STRING:  /* native char * */
            GS_RETURN_IFERR(sql_clone_text(ctx, &src->v_text, &dest->v_text, alloc_mem_func));
            break;
        case GS_TYPE_COLUMN: /* column type, internal used */
            GS_RETURN_IFERR(sql_clone_var_column(ctx, &src->v_col, &dest->v_col, alloc_mem_func));
            break;
        case GS_TYPE_BINARY:
        case GS_TYPE_VARBINARY:
        case GS_TYPE_RAW:
        case GS_TYPE_IMAGE:
        case GS_TYPE_CLOB:
        case GS_TYPE_BLOB:
            GS_RETURN_IFERR(sql_clone_lob(ctx, src, dest, alloc_mem_func));
            break;
        default:
            MEMS_RETURN_IFERR(memcpy_s(dest, sizeof(variant_t), src, sizeof(variant_t)));
            break;
    }

    return GS_SUCCESS;
}

static status_t sql_clone_func_node_args(void *ctx, expr_node_t *src_expr_node, expr_node_t *dest_node,
                                         ga_alloc_func_t alloc_mem_func)
{
    if (src_expr_node->value.v_func.is_winsort_func) {
        return GS_SUCCESS;
    }

    sql_func_t *func = sql_get_func(&src_expr_node->value.v_func);
    switch (func->builtin_func_id) {
        case ID_FUNC_ITEM_IF:
        case ID_FUNC_ITEM_LNNVL:
        case ID_FUNC_ITEM_TRIM:
        case ID_FUNC_ITEM_GROUP_CONCAT:
        case ID_FUNC_ITEM_MEDIAN:
            return GS_ERROR;

        default:
            return GS_SUCCESS;
    }
}
/*
 * sql_clone_expr_node
 * - This function is used to deep clone a expr node.
 *
 */
status_t sql_clone_expr_node(void *ctx, expr_node_t *src_expr_node, expr_node_t **dest_expr_node,
                             ga_alloc_func_t alloc_mem_func)
{
    expr_node_t *node = NULL;
    expr_tree_t *node_argument = NULL;
    expr_node_t *node_left = NULL;
    expr_node_t *node_right = NULL;

    if (src_expr_node == NULL) {
        *dest_expr_node = NULL;
        return GS_SUCCESS;
    }

    GS_RETURN_IFERR(alloc_mem_func(ctx, sizeof(expr_node_t), (void **)&node));

    /* to clone the header of the node */
    node->type = src_expr_node->type;
    node->unary = src_expr_node->unary;
    node->optmz_info = src_expr_node->optmz_info;
    node->loc = src_expr_node->loc;
    node->typmod = src_expr_node->typmod;
    node->cond_arg = NULL;
    node->owner = NULL;
    node->json_func_attr = src_expr_node->json_func_attr;
    node->dis_info = src_expr_node->dis_info;
    node->exec_default = src_expr_node->exec_default;
    node->format_json = src_expr_node->format_json;
    node->nullaware = src_expr_node->nullaware;
    node->has_verified = src_expr_node->has_verified;
    node->is_median_expr = src_expr_node->is_median_expr;
    node->ignore_nulls = src_expr_node->ignore_nulls;
    node->lang_type = src_expr_node->lang_type;
    node->is_pkg = src_expr_node->is_pkg;

    /* to clone word of var_word_t type */
    GS_RETURN_IFERR(sql_clone_var_word(node->type, ctx, &src_expr_node->word, &node->word, alloc_mem_func));

    /* to clone value of variant_t type */
    switch (node->type) {
        case EXPR_NODE_RESERVED:
            MEMS_RETURN_IFERR(memcpy_s(&node->value, sizeof(variant_t), &src_expr_node->value, sizeof(variant_t)));
            break;

        case EXPR_NODE_SEQUENCE:
            node->value.v_seq.mode = src_expr_node->value.v_seq.mode;
            GS_RETURN_IFERR(
                sql_clone_text(ctx, &src_expr_node->value.v_seq.user, &node->value.v_seq.user, alloc_mem_func));
            GS_RETURN_IFERR(
                sql_clone_text(ctx, &src_expr_node->value.v_seq.name, &node->value.v_seq.name, alloc_mem_func));
            break;

        case EXPR_NODE_FUNC:
            GS_RETURN_IFERR(sql_clone_func_node_args(ctx, src_expr_node, node, alloc_mem_func));
            GS_RETURN_IFERR(sql_clone_variant(ctx, &src_expr_node->value, &node->value, alloc_mem_func));
            break;

        case EXPR_NODE_OVER:
            return GS_ERROR;

        case EXPR_NODE_CASE:
        case EXPR_NODE_USER_FUNC:
        case EXPR_NODE_USER_PROC:
            return GS_ERROR;

        default:
            GS_RETURN_IFERR(sql_clone_variant(ctx, &src_expr_node->value, &node->value, alloc_mem_func));
            if (node->type == EXPR_NODE_SELECT && alloc_mem_func == sql_alloc_mem) {
                knl_panic(0);
            }
            break;
    }

    /* to clone argument, left and right */
    if (src_expr_node->argument != NULL) {
        GS_RETURN_IFERR(sql_clone_expr_tree(ctx, src_expr_node->argument, &node_argument, alloc_mem_func));
    }
    if (src_expr_node->left != NULL) {
        GS_RETURN_IFERR(sql_clone_expr_node(ctx, src_expr_node->left, &node_left, alloc_mem_func));
    }
    if (src_expr_node->right != NULL) {
        GS_RETURN_IFERR(sql_clone_expr_node(ctx, src_expr_node->right, &node_right, alloc_mem_func));
    }

    /* to clone the prev and next expr_node */
    node->prev = NULL;
    node->next = NULL;

    node->argument = node_argument;
    node->left = node_left;
    node->right = node_right;
    *dest_expr_node = node;

    return GS_SUCCESS;
}

static status_t clone_expr_tree_inner(void *ctx, expr_tree_t *src_expr_tree, expr_tree_t **dest_expr_tree,
                                      ga_alloc_func_t alloc_mem_func)
{
    expr_tree_t *node = NULL;
    expr_node_t *root_node = NULL;

    if (src_expr_tree == NULL) {
        *dest_expr_tree = NULL;
        return GS_SUCCESS;
    }

    if (alloc_mem_func(ctx, sizeof(expr_tree_t), (void **)&node) != GS_SUCCESS) {
        return GS_ERROR;
    }

    GS_RETURN_IFERR(sql_clone_expr_node(ctx, src_expr_tree->root, &root_node, alloc_mem_func));
    node->expecting = src_expr_tree->expecting;
    node->unary = src_expr_tree->unary;
    node->generated = src_expr_tree->generated;
    node->loc = src_expr_tree->loc;
    node->subscript = src_expr_tree->subscript;
    node->root = root_node;
    GS_RETURN_IFERR(sql_clone_text(ctx, &src_expr_tree->arg_name, &node->arg_name, alloc_mem_func));
    root_node->owner = node;
    node->chain.count = src_expr_tree->chain.count;
    node->chain.first = root_node;
    node->chain.last = root_node;
    node->next = NULL;
    *dest_expr_tree = node;

    return GS_SUCCESS;
}

/*
 * sql_clone_expr_tree
 *
 * This function clone a expr tree.
 *
 * Parameters Description
 * stmt          : The execute sql statement
 * old_expr   : The src expr tree
 * new_expr : The dest expr tree
 */
status_t sql_clone_expr_tree(void *ctx, expr_tree_t *src_expr_tree, expr_tree_t **dest_expr_tree,
                             ga_alloc_func_t alloc_mem_func)
{
    if (src_expr_tree == NULL) {
        *dest_expr_tree = NULL;
        return GS_SUCCESS;
    }

    do {
        GS_RETURN_IFERR(clone_expr_tree_inner(ctx, src_expr_tree, dest_expr_tree, alloc_mem_func));
        if (src_expr_tree != NULL) {
            src_expr_tree = src_expr_tree->next;
        }

        if (*dest_expr_tree != NULL) {
            dest_expr_tree = &(*dest_expr_tree)->next;
        }
    } while (src_expr_tree != NULL);

    return GS_SUCCESS;
}

bool32 sql_expr_tree_equal(sql_stmt_t *stmt, expr_tree_t *tree1, expr_tree_t *tree2, uint32 *tab_map)
{
    expr_tree_t *d_tree1 = (tree1);
    expr_tree_t *d_tree2 = (tree2);
    while (d_tree1 != NULL) {
        if (d_tree2 == NULL) {
            return GS_FALSE;
        }
        if (!sql_expr_node_equal(stmt, d_tree1->root, d_tree2->root, tab_map)) {
            return GS_FALSE;
        }
        d_tree1 = d_tree1->next;
        d_tree2 = d_tree2->next;
    }

    if (d_tree2 != NULL) {
        return GS_FALSE;
    }

    return GS_TRUE;
}

static inline bool32 sql_reserved_node_is_equal(expr_node_t *node1, expr_node_t *node2)
{
    if (VALUE(uint32, &node1->value) != VALUE(uint32, &node2->value)) {
        return GS_FALSE;
    }

    if (VALUE(uint32, &node1->value) == RES_WORD_ROWID) {
        return (bool32)(ROWID_NODE_TAB(node1) == ROWID_NODE_TAB(node2) &&
                        ROWID_NODE_ANCESTOR(node1) == ROWID_NODE_ANCESTOR(node2));
    }
    return GS_TRUE;
}
static bool32 sql_column_node_is_equal(expr_node_t *node1, expr_node_t *node2, uint32 *tab_map)
{
    if (tab_map == NULL) {
        if (VAR_ANCESTOR(&node1->value) != VAR_ANCESTOR(&node2->value) ||
            VAR_TAB(&node1->value) != VAR_TAB(&node2->value) || VAR_COL(&node1->value) != VAR_COL(&node2->value)) {
            return GS_FALSE;
        }

        /* array or array element node, need compare subscript */
        if (node1->value.v_col.is_array == GS_TRUE && node2->value.v_col.is_array == GS_TRUE) {
            return (bool32)(node1->value.v_col.ss_start == node2->value.v_col.ss_start &&
                            node1->value.v_col.ss_end == node2->value.v_col.ss_end);
        } else if (VAR_COL_IS_ARRAY_ELEMENT(&node1->value.v_col) && VAR_COL_IS_ARRAY_ELEMENT(&node2->value.v_col)) {
            return (bool32)(node1->value.v_col.ss_start == node2->value.v_col.ss_start);
        }

        return GS_TRUE;
    }
    return (bool32)(tab_map[NODE_TAB(node1)] == NODE_TAB(node2) && NODE_COL(node1) == NODE_COL(node2));
}

bool32 sql_expr_node_equal(sql_stmt_t *stmt, expr_node_t *node1, expr_node_t *node2, uint32 *tab_map)
{
    if (node1 == node2) {
        return GS_TRUE;
    }

    if (node1->type != node2->type) {
        node1 = sql_get_origin_ref(node1);
        node2 = sql_get_origin_ref(node2);
        if (node1->type != node2->type) {
            return GS_FALSE;
        }
    }

    switch (node1->type) {
        case EXPR_NODE_CONST:
            return var_const_equal(&node1->value, &node2->value);

        case EXPR_NODE_COLUMN:
        case EXPR_NODE_DIRECT_COLUMN:
            return sql_column_node_is_equal(node1, node2, tab_map);

        case EXPR_NODE_GROUP:
            return (bool32)(NODE_VM_ID(node1) == NODE_VM_ID(node2) &&
                            NODE_VM_ANCESTOR(node1) == NODE_VM_ANCESTOR(node2));

        case EXPR_NODE_AGGR:
            return (bool32)(VALUE(uint32, &node1->value) == VALUE(uint32, &node2->value));

        case EXPR_NODE_RESERVED:
            return sql_reserved_node_is_equal(node1, node2);

        case EXPR_NODE_PARAM:
        case EXPR_NODE_CSR_PARAM:
            if (stmt->pl_compiler != NULL || stmt->pl_exec != NULL) {
                return GS_FALSE;
            }

            return (bool32)(VALUE(uint32, &node1->value) == VALUE(uint32, &node2->value));

        case EXPR_NODE_FUNC:
        case EXPR_NODE_USER_FUNC:
            return GS_ERROR;

        case EXPR_NODE_ADD:
        case EXPR_NODE_MUL:
        case EXPR_NODE_BITAND:
        case EXPR_NODE_BITOR:
        case EXPR_NODE_BITXOR:
        case EXPR_NODE_LSHIFT:
        case EXPR_NODE_RSHIFT:
            if (sql_expr_node_equal(stmt, node1->left, node2->left, tab_map) &&
                sql_expr_node_equal(stmt, node1->right, node2->right, tab_map)) {
                return GS_TRUE;
            }

            return (bool32)(sql_expr_node_equal(stmt, node1->left, node2->right, tab_map) &&
                            sql_expr_node_equal(stmt, node1->right, node2->left, tab_map));

        case EXPR_NODE_SUB:
        case EXPR_NODE_DIV:
        case EXPR_NODE_MOD:
        case EXPR_NODE_CAT:
            return (bool32)(sql_expr_node_equal(stmt, node1->left, node2->left, tab_map) &&
                            sql_expr_node_equal(stmt, node1->right, node2->right, tab_map));

        case EXPR_NODE_NEGATIVE:
        case EXPR_NODE_PRIOR:
            return (bool32)(sql_expr_node_equal(stmt, node1->right, node2->right, tab_map));

        case EXPR_NODE_STAR:
            return GS_TRUE;

        case EXPR_NODE_CASE:
            return GS_ERROR;

        case EXPR_NODE_V_ADDR:
        case EXPR_NODE_OVER:
            knl_panic(0);
            return GS_FALSE;

        case EXPR_NODE_SELECT:
            return (node1->value.v_obj.id == node2->value.v_obj.id && node1->value.v_obj.ptr == node2->value.v_obj.ptr)
                       ? GS_TRUE
                       : GS_FALSE;

        case EXPR_NODE_ARRAY:
            knl_panic(0);
            return GS_FALSE;

        default:
            return GS_FALSE;
    }
}

status_t sql_get_expr_datatype(sql_stmt_t *stmt, expr_tree_t *expr, gs_type_t *type)
{
    variant_t var;
    expr_node_t *node = expr->root;
    if (node->type == EXPR_NODE_PRIOR) {
        node = node->right;
    }
    if (node->type != EXPR_NODE_PARAM && NODE_DATATYPE(node) != GS_TYPE_UNKNOWN) {
        *type = NODE_DATATYPE(node);
        return GS_SUCCESS;
    }
    if (sql_get_expr_node_value(stmt, node, &var) != GS_SUCCESS) {
        return GS_ERROR;
    }
    *type = var.type;
    return GS_SUCCESS;
}

void sql_init_visit_assist(visit_assist_t *va, sql_stmt_t *stmt, sql_query_t *query)
{
    va->stmt = stmt;
    va->query = query;
    va->excl_flags = VA_EXCL_NONE;
    va->param0 = NULL;
    va->param1 = NULL;
    va->param2 = NULL;
    va->param3 = NULL;
    va->result0 = GS_INVALID_ID32;
    va->result1 = GS_INVALID_ID32;
    va->result2 = GS_INVALID_ID32;
    va->time = 0;
}
static inline status_t visit_cmp_node(visit_assist_t *va, cmp_node_t *cmp, visit_func_t visit_func)
{
    GS_RETURN_IFERR(visit_expr_tree(va, cmp->left, visit_func));
    return visit_expr_tree(va, cmp->right, visit_func);
}

status_t visit_cond_node(visit_assist_t *va, cond_node_t *cond, visit_func_t visit_func)
{
    switch (cond->type) {
        case COND_NODE_OR:
        case COND_NODE_AND:
            GS_RETURN_IFERR(visit_cond_node(va, cond->left, visit_func));
            return visit_cond_node(va, cond->right, visit_func);

        case COND_NODE_COMPARE:
            return visit_cmp_node(va, cond->cmp, visit_func);
        default:
            return GS_SUCCESS;
    }
}

status_t visit_func_node(visit_assist_t *va, expr_node_t *node, visit_func_t visit_func)
{
    if (node->type == EXPR_NODE_FUNC) {
        node->value.v_func.func_id = sql_get_func_id((text_t *)&node->word.func.name);
        node->value.v_func.pack_id = GS_INVALID_ID32;
        node->value.v_func.is_proc = GS_FALSE;
    }

    GS_RETURN_IFERR(visit_expr_tree(va, node->argument, visit_func));
    if (node->type == EXPR_NODE_FUNC) {
        sql_func_t *func = sql_get_func(&node->value.v_func);
        if ((func->builtin_func_id == ID_FUNC_ITEM_IF || func->builtin_func_id == ID_FUNC_ITEM_LNNVL) &&
            node->cond_arg != NULL) {
            GS_RETURN_IFERR(visit_cond_node(va, node->cond_arg->root, visit_func));
        }

        if ((func->aggr_type == AGGR_TYPE_GROUP_CONCAT || func->aggr_type == AGGR_TYPE_MEDIAN) &&
            node->sort_items != NULL) {
            for (uint32 i = 0; i < node->sort_items->count; i++) {
                sort_item_t *sort_item = (sort_item_t *)cm_galist_get(node->sort_items, i);
                GS_RETURN_IFERR(visit_expr_tree(va, sort_item->expr, visit_func));
            }
        }
    }
    return GS_SUCCESS;
}

status_t visit_expr_node(visit_assist_t *va, expr_node_t **node, visit_func_t visit_func)
{
    switch ((*node)->type) {
        case EXPR_NODE_ADD:
        case EXPR_NODE_SUB:
        case EXPR_NODE_MUL:
        case EXPR_NODE_DIV:
        case EXPR_NODE_MOD:
        case EXPR_NODE_BITAND:
        case EXPR_NODE_BITOR:
        case EXPR_NODE_BITXOR:
        case EXPR_NODE_CAT:
        case EXPR_NODE_LSHIFT:
        case EXPR_NODE_RSHIFT:
            GS_RETURN_IFERR(visit_expr_node(va, &(*node)->left, visit_func));
            return visit_expr_node(va, &(*node)->right, visit_func);

        case EXPR_NODE_NEGATIVE:
            return visit_expr_node(va, &(*node)->right, visit_func);

        case EXPR_NODE_PRIOR:
            if (va->excl_flags & VA_EXCL_PRIOR) {
                return visit_func(va, node);
            }
            return visit_expr_node(va, &(*node)->right, visit_func);

        case EXPR_NODE_ARRAY:
            return visit_expr_tree(va, (*node)->argument, visit_func);

        case EXPR_NODE_FUNC:
            if (va->excl_flags & VA_EXCL_FUNC) {
                return visit_func(va, node);
            }
            // fall-through
        case EXPR_NODE_USER_FUNC:
        case EXPR_NODE_V_METHOD:
        case EXPR_NODE_V_CONSTRUCT:
            if (va->excl_flags & VA_EXCL_PROC) {
                return visit_func(va, node);
            }
            return visit_func_node(va, *node, visit_func);

        case EXPR_NODE_CASE:
        case EXPR_NODE_OVER:
            return GS_ERROR;

        default:
            return visit_func(va, node);
    }
}

status_t visit_expr_tree(visit_assist_t *va, expr_tree_t *tree, visit_func_t visit_func)
{
    while (tree != NULL) {
        GS_RETURN_IFERR(visit_expr_node(va, &tree->root, visit_func));
        tree = tree->next;
    }
    return GS_SUCCESS;
}

static inline status_t sql_exec_const_node(sql_stmt_t *stmt, expr_node_t *node, variant_t *result)
{
    var_copy(&node->value, result);
    return GS_SUCCESS;
}

static inline status_t sql_exec_func_node(sql_stmt_t *stmt, expr_node_t *node, variant_t *result)
{
    SQL_SAVE_STACK(stmt);
    status_t status = sql_invoke_func(stmt, node, result);
    SQL_RESTORE_STACK(stmt);
    return status;
}

static inline status_t sql_exec_param_node(sql_stmt_t *stmt, expr_node_t *node, variant_t *result)
{
    return sql_get_param_value(stmt, VALUE(uint32, &node->value), result);
}

status_t oprf_column(sql_stmt_t *stmt, expr_node_t *node, variant_t *result)
{
    status_t status;
    status = sql_get_table_value(stmt, VALUE_PTR(var_column_t, &node->value), result);
    return status;
}
#define sql_exec_column_node oprf_column
#define sql_exec_reserved_node sql_get_reserved_value

static inline status_t sql_exec_direct_column(sql_stmt_t *stmt, expr_node_t *node, variant_t *result)
{
    return sql_get_ddm_kernel_value(stmt, &g_init_table, stmt->direct_knl_cursor, &node->value.v_col, result);
}

static inline status_t sql_exec_unary_node(sql_stmt_t *stmt, expr_node_t *node, variant_t *result)
{
    SQL_SAVE_STACK(stmt);
    status_t status = sql_exec_unary_oper(stmt, node, result);
    SQL_RESTORE_STACK(stmt);
    return status;
}

static inline status_t sql_exec_oper_node(sql_stmt_t *stmt, expr_node_t *node, variant_t *result)
{
    SQL_SAVE_STACK(stmt);
    status_t status = sql_exec_oper(stmt, node, result);
    SQL_RESTORE_STACK(stmt);
    return status;
}

static inline status_t sql_exec_invalid_node(sql_stmt_t *stmt, expr_node_t *node, variant_t *result)
{
    GS_SRC_THROW_ERROR(node->loc, ERR_INVALID_EXPRESSION);
    return GS_ERROR;
}

node_func_tab_t g_oper_calc_func_tab[] = {
    { OPER_TYPE_ROOT, sql_exec_invalid_node }, { OPER_TYPE_PRIOR, NULL },
    { OPER_TYPE_MUL, sql_exec_oper_node },     { OPER_TYPE_DIV, sql_exec_oper_node },
    { OPER_TYPE_MOD, sql_exec_oper_node },     { OPER_TYPE_ADD, sql_exec_oper_node },
    { OPER_TYPE_SUB, sql_exec_oper_node },     { OPER_TYPE_LSHIFT, sql_exec_oper_node },
    { OPER_TYPE_RSHIFT, sql_exec_oper_node },  { OPER_TYPE_BITAND, sql_exec_oper_node },
    { OPER_TYPE_BITXOR, sql_exec_oper_node },  { OPER_TYPE_BITOR, sql_exec_oper_node },
    { OPER_TYPE_CAT, sql_exec_oper_node },     { OPER_TYPE_VARIANT_CEIL, sql_exec_invalid_node },
};

node_func_tab_t g_node_calc_func_tab[] = { { EXPR_NODE_CONST, sql_exec_const_node },
                                           { EXPR_NODE_FUNC, sql_exec_func_node },
                                           { EXPR_NODE_JOIN, sql_exec_invalid_node },
                                           { EXPR_NODE_PARAM, sql_exec_param_node },
                                           { EXPR_NODE_COLUMN, sql_exec_column_node },
                                           { EXPR_NODE_RS_COLUMN, NULL },
                                           { EXPR_NODE_STAR, sql_exec_invalid_node },
                                           { EXPR_NODE_RESERVED, sql_exec_reserved_node },
                                           { EXPR_NODE_SELECT, NULL },
                                           { EXPR_NODE_SEQUENCE, NULL },
                                           { EXPR_NODE_CASE, NULL },
                                           { EXPR_NODE_GROUP, NULL },
                                           { EXPR_NODE_AGGR, NULL },
                                           { EXPR_NODE_USER_FUNC, NULL },
                                           { EXPR_NODE_USER_PROC, NULL },
                                           { EXPR_NODE_PROC, sql_exec_func_node },
                                           { EXPR_NODE_NEW_COL, NULL },
                                           { EXPR_NODE_OLD_COL, NULL },
                                           { EXPR_NODE_PL_ATTR, NULL },
                                           { EXPR_NODE_OVER, NULL },
                                           { EXPR_NODE_TRANS_COLUMN, sql_exec_invalid_node },
                                           { EXPR_NODE_NEGATIVE, sql_exec_unary_node },
                                           { EXPR_NODE_DIRECT_COLUMN, sql_exec_direct_column },
                                           { EXPR_NODE_ARRAY, NULL },
                                           { EXPR_NODE_V_METHOD, NULL },
                                           { EXPR_NODE_V_ADDR, NULL },
                                           { EXPR_NODE_V_CONSTRUCT, NULL },
                                           { EXPR_NODE_CSR_PARAM, NULL } };

node_func_tab_t *g_expr_calc_funcs[] = { g_oper_calc_func_tab, g_node_calc_func_tab };

/*
-------------------------------------------------------
AND                  FALSE           TRUE       UNKNOWN
-------------------------------------------------------
FALSE                FALSE           FALSE      FALSE
-------------------------------------------------------
TRUE                 FALSE           TRUE       UNKNOWN
-------------------------------------------------------
UNKNOWN              FALSE           UNKNOWN    UNKNOWN
-------------------------------------------------------
*/
static cond_result_t g_and_true_table[COND_END][COND_END] = { { COND_FALSE, COND_FALSE, COND_FALSE },
                                                              { COND_FALSE, COND_TRUE, COND_UNKNOWN },
                                                              { COND_FALSE, COND_UNKNOWN, COND_UNKNOWN } };

/*
-------------------------------------------------------
OR                   FALSE           TRUE       UNKNOWN
-------------------------------------------------------
FALSE                FALSE           TRUE       UNKNOWN
-------------------------------------------------------
TRUE                 TRUE            TRUE       TRUE
-------------------------------------------------------
UNKNOWN              UNKNOWN         TRUE    UNKNOWN
-------------------------------------------------------
*/
static cond_result_t g_or_true_table[COND_END][COND_END] = { { COND_FALSE, COND_TRUE, COND_UNKNOWN },
                                                             { COND_TRUE, COND_TRUE, COND_TRUE },
                                                             { COND_UNKNOWN, COND_TRUE, COND_UNKNOWN } };

/*
-------------------------------------------------------
--                  FALSE           TRUE       UNKNOWN
-------------------------------------------------------
NOT                 TRUE           FALSE       UNKNOWN
-------------------------------------------------------
*/

static cond_result_t g_not_true_table[COND_END] = { COND_TRUE, COND_FALSE, COND_UNKNOWN };

status_t sql_create_cond_tree(sql_context_t *context, cond_tree_t **cond)
{
    CM_POINTER2(context, cond);

    if (sql_alloc_mem(context, sizeof(cond_tree_t), (void **)cond) != GS_SUCCESS) {
        return GS_ERROR;
    }

    sql_init_cond_tree(context, *cond, sql_alloc_mem);
    return GS_SUCCESS;
}

typedef struct st_parent_node {
    uint32 depth;
    cond_node_t *cond_node;
    cond_node_t *parent_node;
} insert_node_t;

void sql_convert_match_result(cmp_type_t cmp_type, int32 cmp_result, bool32 *result)
{
    switch (cmp_type) {
        case CMP_TYPE_EQUAL:
        case CMP_TYPE_EQUAL_ANY:
        case CMP_TYPE_IN:
        case CMP_TYPE_EQUAL_ALL:
            *result = (cmp_result == 0);
            break;

        case CMP_TYPE_GREAT:
        case CMP_TYPE_GREAT_ANY:
        case CMP_TYPE_GREAT_ALL:
            *result = (cmp_result > 0);
            break;

        case CMP_TYPE_GREAT_EQUAL:
        case CMP_TYPE_GREAT_EQUAL_ANY:
        case CMP_TYPE_GREAT_EQUAL_ALL:
            *result = (cmp_result >= 0);
            break;

        case CMP_TYPE_LESS:
        case CMP_TYPE_LESS_ANY:
        case CMP_TYPE_LESS_ALL:
            *result = (cmp_result < 0);
            break;

        case CMP_TYPE_LESS_EQUAL:
        case CMP_TYPE_LESS_EQUAL_ANY:
        case CMP_TYPE_LESS_EQUAL_ALL:
            *result = (cmp_result <= 0);
            break;

        case CMP_TYPE_NOT_EQUAL:
        case CMP_TYPE_NOT_EQUAL_ANY:
        case CMP_TYPE_NOT_IN:
        case CMP_TYPE_NOT_EQUAL_ALL:
            *result = (cmp_result != 0);
            break;

        default:
            *result = GS_TRUE;
            break;
    }
}

status_t sql_exec_escape_character(expr_tree_t *expr, variant_t *var, char *escape)
{
    do {
        if (var->is_null || !GS_IS_STRING_TYPE(var->type)) {
            break;
        }
        GS_BREAK_IF_ERROR(lex_check_asciichar(&var->v_text, &expr->loc, escape, GS_FALSE));
        return GS_SUCCESS;
    } while (0);

    GS_SRC_THROW_ERROR(expr->loc, ERR_SQL_SYNTAX_ERROR, "invalid escape character");
    return GS_ERROR;
}

static status_t sql_match_like(sql_stmt_t *stmt, cmp_node_t *node, bool32 *pending, cond_result_t *cond_ret)
{
    variant_t l_var, r_var, escape_var;
    bool8 has_escape = (node->right->next != NULL);
    char escape = GS_INVALID_INT8;

    SQL_EXEC_CMP_OPERAND_EX(node->left, &l_var, cond_ret, pending, stmt);
    SQL_EXEC_CMP_OPERAND_EX(node->right, &r_var, cond_ret, pending, stmt);
    if (has_escape) {
        SQL_EXEC_CMP_OPERAND_EX(node->right->next, &escape_var, cond_ret, pending, stmt);
        GS_RETURN_IFERR(sql_exec_escape_character(node->right->next, &escape_var, &escape));
    }

    /* character. If any of char1, char2, or esc_char is null, then the result is unknown */
    if (l_var.is_null || r_var.is_null) {
        *cond_ret = COND_UNKNOWN;
    } else {
        SQL_SAVE_STACK(stmt);

        if (!GS_IS_STRING_TYPE(l_var.type)) {
            if (sql_convert_variant(stmt, &l_var, GS_TYPE_STRING) != GS_SUCCESS) {
                SQL_RESTORE_STACK(stmt);
                return GS_ERROR;
            }
            sql_keep_stack_variant(stmt, &l_var);
        }
        if (!GS_IS_STRING_TYPE(r_var.type)) {
            if (sql_convert_variant(stmt, &r_var, GS_TYPE_STRING) != GS_SUCCESS) {
                SQL_RESTORE_STACK(stmt);
                return GS_ERROR;
            }
            sql_keep_stack_variant(stmt, &r_var);
        }

        if (var_like(&l_var, &r_var, (bool32 *)cond_ret, has_escape, escape, GET_CHARSET_ID) != GS_SUCCESS) {
            SQL_RESTORE_STACK(stmt);
            return GS_ERROR;
        }
        SQL_RESTORE_STACK(stmt);
    }

    if (node->type == CMP_TYPE_NOT_LIKE) {
        *cond_ret = g_not_true_table[*cond_ret];
    }
    return GS_SUCCESS;
}

static status_t sql_match_normal(sql_stmt_t *stmt, cmp_node_t *node, bool32 *pending, cond_result_t *result)
{
    variant_t l_var, r_var;
    int32 cmp_result;

    // evaluate the left node
    SQL_EXEC_CMP_OPERAND_EX(node->left, &l_var, result, pending, stmt);

    // evaluate the right node
    SQL_EXEC_CMP_OPERAND_EX(node->right, &r_var, result, pending, stmt);

    if (l_var.is_null || r_var.is_null) {
        if (stmt->is_check) {
            *result = COND_UNKNOWN;
        } else {
            *result = COND_FALSE;
        }
        return GS_SUCCESS;
    }

    if (sql_compare_variant(stmt, &l_var, &r_var, &cmp_result) != GS_SUCCESS) {
        return GS_ERROR;
    }

    sql_convert_match_result(node->type, cmp_result, (bool32 *)result);
    return GS_SUCCESS;
}

static status_t sql_match_compare_node(sql_stmt_t *stmt, cmp_node_t *node, bool32 *pending, cond_result_t *result)
{
    status_t status;
    bool32 cmp_pending = GS_FALSE;

    SQL_SAVE_STACK(stmt);
    switch (node->type) {
        case CMP_TYPE_EQUAL_ANY:
        case CMP_TYPE_NOT_EQUAL_ANY:
        case CMP_TYPE_GREAT_EQUAL_ANY:
        case CMP_TYPE_GREAT_ANY:
        case CMP_TYPE_LESS_ANY:
        case CMP_TYPE_LESS_EQUAL_ANY:
        case CMP_TYPE_IN:
        case CMP_TYPE_NOT_IN:
        case CMP_TYPE_EQUAL_ALL:
        case CMP_TYPE_NOT_EQUAL_ALL:
        case CMP_TYPE_GREAT_ALL:
        case CMP_TYPE_GREAT_EQUAL_ALL:
        case CMP_TYPE_LESS_ALL:
        case CMP_TYPE_LESS_EQUAL_ALL:
        case CMP_TYPE_IS_NULL:
        case CMP_TYPE_IS_NOT_NULL:
        case CMP_TYPE_IS_JSON:
        case CMP_TYPE_IS_NOT_JSON:
            status = GS_ERROR;
            break;

        case CMP_TYPE_LIKE:
        case CMP_TYPE_NOT_LIKE:
            status = sql_match_like(stmt, node, &cmp_pending, result);
            break;

        case CMP_TYPE_REGEXP:
        case CMP_TYPE_NOT_REGEXP:
            status = GS_ERROR;
            break;

        case CMP_TYPE_BETWEEN:
        case CMP_TYPE_NOT_BETWEEN:
        case CMP_TYPE_EXISTS:
        case CMP_TYPE_NOT_EXISTS:
        case CMP_TYPE_REGEXP_LIKE:
        case CMP_TYPE_NOT_REGEXP_LIKE:
            status = GS_ERROR;
            break;

        default:
            status = sql_match_normal(stmt, node, &cmp_pending, result);
            break;
    }

    if (cmp_pending) {
        *pending = GS_TRUE;
    }
    SQL_RESTORE_STACK(stmt);
    if (status != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_ASSERT_ERROR, "sql_match_compare_node not supported.");
    }
    return status;
}

status_t sql_match_cond_argument(sql_stmt_t *stmt, cond_node_t *node, bool32 *pending, cond_result_t *result)
{
    cond_result_t l_result;
    cond_result_t r_result;
    if (node->type == COND_NODE_COMPARE) {
        return sql_match_compare_node(stmt, node->cmp, pending, result);
    }
    if (node->type == COND_NODE_TRUE) {
        *result = COND_TRUE;
        return GS_SUCCESS;
    }
    if (node->type == COND_NODE_FALSE) {
        *result = COND_FALSE;
        return GS_SUCCESS;
    }

    if (sql_match_cond_argument(stmt, node->left, pending, &l_result) != GS_SUCCESS) {
        return GS_ERROR;
    }

    // ignore cond node not, it will be converted in parsing phase
    if (node->type == COND_NODE_AND && l_result == COND_FALSE) {
        *result = COND_FALSE;
        return GS_SUCCESS;
    }

    if (node->type == COND_NODE_OR && l_result == COND_TRUE) {
        *result = COND_TRUE;
        return GS_SUCCESS;
    }

    if (sql_match_cond_argument(stmt, node->right, pending, &r_result) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (node->type == COND_NODE_AND) {
        *result = g_and_true_table[l_result][r_result];
    }
    if (node->type == COND_NODE_OR) {
        *result = g_or_true_table[l_result][r_result];
    }
    return GS_SUCCESS;
}

status_t sql_match_cond_node(sql_stmt_t *stmt, cond_node_t *node, bool32 *result)
{
    cond_result_t cond_ret;
    bool32 pending = GS_FALSE;
    if (sql_match_cond_argument(stmt, node, &pending, &cond_ret)) {
        return GS_ERROR;
    }
    *result = (cond_ret == COND_TRUE);
    return GS_SUCCESS;
}

status_t sql_match_cond_tree(void *stmt, void *node, cond_result_t *result)
{
    bool32 pending = GS_FALSE;
    return sql_match_cond_argument((sql_stmt_t *)stmt, ((cond_tree_t *)node)->root, &pending, result);
}

status_t sql_match_cond(void *arg, bool32 *result)
{
    sql_stmt_t *stmt = (sql_stmt_t *)arg;

    if (stmt == NULL) {
        *result = COND_TRUE;
        return GS_SUCCESS;
    }

    cond_tree_t *cond = SQL_CURR_CURSOR(stmt)->cond;
    if (cond == NULL || cond->root == NULL) {
        *result = COND_TRUE;
        return GS_SUCCESS;
    }

    *result = COND_FALSE;
    return sql_match_cond_node(stmt, cond->root, result);
}

/* !
 * \brief Try to evaluate an AND condition node.
 *
 */
void try_eval_logic_and(cond_node_t *node)
{
    if (node->type != COND_NODE_AND) {
        return;
    }

    /* If one of the two child nodes is false, then the node is false */
    if (node->left->type == COND_NODE_FALSE || node->right->type == COND_NODE_FALSE) {
        node->type = COND_NODE_FALSE;
        return;
    }

    if (node->left->type == COND_NODE_TRUE) {
        if (node->right->type == COND_NODE_TRUE) {
            node->type = COND_NODE_TRUE;
        } else {
            *node = *node->right;
        }
        return;
    }

    if (node->right->type == COND_NODE_TRUE) {
        *node = *node->left;
    }
}

/* !
 * \brief Try to evaluate an OR condition node.
 *
 */
void try_eval_logic_or(cond_node_t *node)
{
    if (node->type != COND_NODE_OR) {
        return;
    }

    /* If one of the two child nodes is true, then the node is true */
    if (node->left->type == COND_NODE_TRUE || node->right->type == COND_NODE_TRUE) {
        node->type = COND_NODE_TRUE;
        return;
    }

    if (node->left->type == COND_NODE_FALSE) {
        if (node->right->type == COND_NODE_FALSE) {
            node->type = COND_NODE_FALSE;
            return;
        } else {
            *node = *node->right;
            return;
        }
    }

    if (node->right->type == COND_NODE_FALSE) {
        *node = *node->left;
        return;
    }

    return;
}

static bool32 is_filter_col_column(expr_node_t *expr_node, sql_array_t *l_tabs, bool32 *exists_col)
{
    if (NODE_ANCESTOR(expr_node) > 0) {
        return GS_TRUE;
    }

    if (!sql_table_in_list(l_tabs, NODE_TAB(expr_node))) {
        return GS_FALSE;
    }

    *exists_col = GS_TRUE;
    return GS_TRUE;
}

static bool32 is_filter_col_reserved(expr_node_t *expr_node, sql_array_t *l_tabs, bool32 *exists_col)
{
    if (!NODE_IS_RES_ROWID(expr_node) || ROWID_NODE_ANCESTOR(expr_node) > 0) {
        return GS_TRUE;
    }

    if (!sql_table_in_list(l_tabs, ROWID_NODE_TAB(expr_node))) {
        return GS_FALSE;
    }

    *exists_col = GS_TRUE;
    return GS_TRUE;
}

static inline bool32 is_filter_col_expr_tree(expr_tree_t *tree, sql_array_t *l_tabs, bool32 *exists_col,
                                             bool32 is_right_node);
static bool32 is_filter_col_expr_node(expr_node_t *expr_node, sql_array_t *l_tabs, bool32 *exists_col,
                                      bool32 is_right_node);

static bool32 is_filter_col_cond(cond_node_t *cond_node, sql_array_t *l_tabs, bool32 *exists_col, bool32 is_right_node)
{
    if (cond_node == NULL) {
        return GS_TRUE;
    }

    switch (cond_node->type) {
        case COND_NODE_OR:
        case COND_NODE_AND:
            return (bool32)(is_filter_col_cond(cond_node->left, l_tabs, exists_col, is_right_node) &&
                            is_filter_col_cond(cond_node->right, l_tabs, exists_col, is_right_node));

        case COND_NODE_COMPARE:
            if (cond_node->cmp->type == CMP_TYPE_IS_NULL) {
                return GS_FALSE;
            }
            return (bool32)(is_filter_col_expr_tree(cond_node->cmp->left, l_tabs, exists_col, is_right_node) &&
                            is_filter_col_expr_tree(cond_node->cmp->right, l_tabs, exists_col, is_right_node));

        default:
            return GS_TRUE;
    }
}

static bool32 is_filter_col_case(expr_node_t *expr_node, sql_array_t *l_tabs, bool32 *exists_col, bool32 is_right_node)
{
    if (is_right_node) {
        return GS_FALSE;
    }

    case_expr_t *case_expr = (case_expr_t *)expr_node->value.v_pointer;
    if (!case_expr->is_cond) {
        if (!is_filter_col_expr_tree(case_expr->expr, l_tabs, exists_col, is_right_node)) {
            return GS_FALSE;
        }
    }

    for (uint32 i = 0; i < case_expr->pairs.count; i++) {
        case_pair_t *case_pair = (case_pair_t *)cm_galist_get(&case_expr->pairs, i);
        if (case_expr->is_cond) {
            if (!is_filter_col_cond(case_pair->when_cond->root, l_tabs, exists_col, is_right_node)) {
                return GS_FALSE;
            }
        } else {
            if (!is_filter_col_expr_tree(case_pair->when_expr, l_tabs, exists_col, is_right_node)) {
                return GS_FALSE;
            }
        }
        if (!is_filter_col_expr_tree(case_pair->value, l_tabs, exists_col, is_right_node)) {
            return GS_FALSE;
        }
    }

    if (case_expr->default_expr != NULL) {
        if (!is_filter_col_expr_tree(case_expr->default_expr, l_tabs, exists_col, is_right_node)) {
            return GS_FALSE;
        }
    }

    return GS_TRUE;
}

static bool32 is_filter_col_func(expr_node_t *expr_node, sql_array_t *l_tabs, bool32 *exists_col, bool32 is_right_node)
{
    expr_tree_t *arg = expr_node->argument;

    if (is_right_node) {
        return GS_FALSE;
    }

    while (arg != NULL) {
        if (!is_filter_col_expr_node(arg->root, l_tabs, exists_col, is_right_node)) {
            return GS_FALSE;
        }
        arg = arg->next;
    }

    sql_func_t *func = sql_get_func(&expr_node->value.v_func);
    if ((func->builtin_func_id == ID_FUNC_ITEM_IF || func->builtin_func_id == ID_FUNC_ITEM_LNNVL) &&
        expr_node->cond_arg != NULL) {
        if (!is_filter_col_cond(expr_node->cond_arg->root, l_tabs, exists_col, is_right_node)) {
            return GS_FALSE;
        }
    }

    if ((func->aggr_type == AGGR_TYPE_GROUP_CONCAT || func->aggr_type == AGGR_TYPE_MEDIAN) &&
        expr_node->sort_items != NULL) {
        for (uint32 i = 0; i < expr_node->sort_items->count; i++) {
            sort_item_t *sort_item = (sort_item_t *)cm_galist_get(expr_node->sort_items, i);
            if (!is_filter_col_expr_tree(sort_item->expr, l_tabs, exists_col, is_right_node)) {
                return GS_FALSE;
            }
        }
    }

    return GS_TRUE;
}

static bool32 is_filter_col_expr_node(expr_node_t *expr_node, sql_array_t *l_tabs, bool32 *exists_col,
                                      bool32 is_right_node)
{
    switch (expr_node->type) {
        case EXPR_NODE_ADD:
        case EXPR_NODE_SUB:
        case EXPR_NODE_MUL:
        case EXPR_NODE_DIV:
        case EXPR_NODE_MOD:
        case EXPR_NODE_BITAND:
        case EXPR_NODE_BITOR:
        case EXPR_NODE_BITXOR:
        case EXPR_NODE_LSHIFT:
        case EXPR_NODE_RSHIFT:
            return (bool32)(is_filter_col_expr_node(expr_node->left, l_tabs, exists_col, is_right_node) &&
                            is_filter_col_expr_node(expr_node->right, l_tabs, exists_col, is_right_node));

        case EXPR_NODE_NEGATIVE:
            return (bool32)(is_filter_col_expr_node(expr_node->right, l_tabs, exists_col, is_right_node));

        case EXPR_NODE_COLUMN:
        case EXPR_NODE_TRANS_COLUMN:
            return is_filter_col_column(expr_node, l_tabs, exists_col);

        case EXPR_NODE_CASE:
            return is_filter_col_case(expr_node, l_tabs, exists_col, is_right_node);

        case EXPR_NODE_FUNC:
            return is_filter_col_func(expr_node, l_tabs, exists_col, is_right_node);

        case EXPR_NODE_V_METHOD:
        case EXPR_NODE_V_CONSTRUCT:
        case EXPR_NODE_USER_FUNC:
        case EXPR_NODE_SELECT:
        case EXPR_NODE_PRIOR:
        case EXPR_NODE_CAT:
        case EXPR_NODE_ARRAY:
            return GS_FALSE;

        case EXPR_NODE_RESERVED:
            return is_filter_col_reserved(expr_node, l_tabs, exists_col);

        default:
            return GS_TRUE;
    }
}

static inline bool32 is_filter_col_expr_tree(expr_tree_t *tree, sql_array_t *l_tabs, bool32 *exists_col,
                                             bool32 is_right_node)
{
    while (tree != NULL) {
        GS_RETVALUE_IFTRUE(!is_filter_col_expr_node(tree->root, l_tabs, exists_col, is_right_node), GS_FALSE);
        tree = tree->next;
    }
    return GS_TRUE;
}

static inline bool32 is_filter_col_node(expr_tree_t *tree, sql_array_t *l_tabs, bool32 is_right_node)
{
    bool32 exists_col = GS_FALSE;
    return (bool32)(is_filter_col_expr_tree(tree, l_tabs, &exists_col, is_right_node) && exists_col);
}

static bool32 is_filter_value_column(expr_node_t *node, sql_array_t *l_tabs, sql_array_t *p_tabs,
                                     sql_join_type_t join_type, bool32 is_right_node)
{
    if (NODE_ANCESTOR(node) > 0) {
        return GS_TRUE;
    }
    if (sql_table_in_list(l_tabs, NODE_TAB(node))) {
        return GS_TRUE;
    }
    if (!is_right_node || join_type == JOIN_TYPE_FULL) {
        return GS_FALSE;
    }
    return sql_table_in_list(p_tabs, NODE_TAB(node));
}

static bool32 is_filter_value_reserved(expr_node_t *node, sql_array_t *l_tabs, sql_array_t *p_tabs,
                                       sql_join_type_t join_type, bool32 is_right_node)
{
    if (VALUE(int32, &node->value) == RES_WORD_SYSDATE || VALUE(int32, &node->value) == RES_WORD_SYSTIMESTAMP) {
        return GS_TRUE;
    }

    if (VALUE(int32, &node->value) == RES_WORD_ROWID) {
        if (ROWID_NODE_ANCESTOR(node) > 0) {
            return GS_TRUE;
        }

        if (sql_table_in_list(l_tabs, ROWID_NODE_TAB(node))) {
            return GS_TRUE;
        }

        if (!is_right_node || join_type == JOIN_TYPE_FULL) {
            return GS_FALSE;
        }
        return sql_table_in_list(p_tabs, ROWID_NODE_TAB(node));
    }
    return GS_FALSE;
}

static inline bool32 is_filter_value_expr_tree(expr_tree_t *expr, sql_array_t *l_tabs, sql_array_t *p_tabs,
                                               sql_join_type_t join_type, bool32 is_right_node);
static bool32 is_filter_value_cond(cond_node_t *node, sql_array_t *l_tabs, sql_array_t *p_tabs,
                                   sql_join_type_t join_type, bool32 is_right_node)
{
    cmp_node_t *cmp = NULL;
    switch (node->type) {
        case COND_NODE_AND:
        case COND_NODE_OR:
            return (bool32)(is_filter_value_cond(node->left, l_tabs, p_tabs, join_type, is_right_node) &&
                            is_filter_value_cond(node->right, l_tabs, p_tabs, join_type, is_right_node));
        case COND_NODE_COMPARE:
            cmp = node->cmp;
            if (cmp->type == CMP_TYPE_IS_NULL) {
                return GS_FALSE;
            }
            return (bool32)(is_filter_value_expr_tree(cmp->left, l_tabs, p_tabs, join_type, is_right_node) &&
                            is_filter_value_expr_tree(cmp->right, l_tabs, p_tabs, join_type, is_right_node));
        default:
            return GS_TRUE;
    }
}

static bool32 is_filter_value_func(expr_node_t *node, sql_array_t *l_tabs, sql_array_t *p_tabs,
                                   sql_join_type_t join_type, bool32 is_right_node)
{
    sql_func_t *func = NULL;
    if (!is_filter_value_expr_tree(node->argument, l_tabs, p_tabs, join_type, is_right_node)) {
        return GS_FALSE;
    }
    func = sql_get_func(&node->value.v_func);
    if ((func->builtin_func_id == ID_FUNC_ITEM_IF || func->builtin_func_id == ID_FUNC_ITEM_LNNVL) &&
        node->cond_arg != NULL) {
        return is_filter_value_cond(node->cond_arg->root, l_tabs, p_tabs, join_type, is_right_node);
    }
    return GS_TRUE;
}

static inline bool32 is_filter_value_subslct(expr_node_t *node)
{
    sql_select_t *select_ctx = (sql_select_t *)VALUE_PTR(var_object_t, &node->value)->ptr;
    return (bool32)((select_ctx->type == SELECT_AS_VARIANT || select_ctx->type == SELECT_AS_LIST) &&
                    select_ctx->parent_refs->count == 0);
}

static bool32 is_filter_value_case(expr_node_t *node, sql_array_t *l_tabs, sql_array_t *p_tabs,
                                   sql_join_type_t join_type, bool32 is_right_node)
{
    case_pair_t *case_pair = NULL;
    case_expr_t *case_expr = NULL;

    case_expr = (case_expr_t *)node->value.v_pointer;
    if (!case_expr->is_cond) {
        GS_RETVALUE_IFTRUE(!is_filter_value_expr_tree(case_expr->expr, l_tabs, p_tabs, join_type, is_right_node),
                           GS_FALSE);
    }

    for (uint32 i = 0; i < case_expr->pairs.count; i++) {
        case_pair = (case_pair_t *)cm_galist_get(&case_expr->pairs, i);
        if (case_expr->is_cond) {
            GS_RETVALUE_IFTRUE(!is_filter_value_cond(case_pair->when_cond->root, l_tabs, p_tabs, join_type,
                                                     is_right_node),
                               GS_FALSE);
        } else {
            GS_RETVALUE_IFTRUE(!is_filter_value_expr_tree(case_pair->when_expr, l_tabs, p_tabs, join_type,
                                                          is_right_node),
                               GS_FALSE);
        }
        GS_RETVALUE_IFTRUE(!is_filter_value_expr_tree(case_pair->value, l_tabs, p_tabs, join_type, is_right_node),
                           GS_FALSE);
    }

    if (case_expr->default_expr == NULL) {
        return GS_TRUE;
    }
    return is_filter_value_expr_tree(case_expr->default_expr, l_tabs, p_tabs, join_type, is_right_node);
}

static bool32 is_filter_value_expr_node(expr_node_t *node, sql_array_t *l_tabs, sql_array_t *p_tabs,
                                        sql_join_type_t join_type, bool32 is_right_node)
{
    switch (node->type) {
        case EXPR_NODE_ADD:
        case EXPR_NODE_SUB:
        case EXPR_NODE_MUL:
        case EXPR_NODE_DIV:
        case EXPR_NODE_MOD:
        case EXPR_NODE_CAT:
        case EXPR_NODE_BITAND:
        case EXPR_NODE_BITOR:
        case EXPR_NODE_BITXOR:
        case EXPR_NODE_LSHIFT:
        case EXPR_NODE_RSHIFT:
            return (bool32)(is_filter_value_expr_node(node->left, l_tabs, p_tabs, join_type, is_right_node) &&
                            is_filter_value_expr_node(node->right, l_tabs, p_tabs, join_type, is_right_node));

        case EXPR_NODE_NEGATIVE:
            return is_filter_value_expr_node(node->right, l_tabs, p_tabs, join_type, is_right_node);

        case EXPR_NODE_CONST:
        case EXPR_NODE_PARAM:
        case EXPR_NODE_CSR_PARAM:
        case EXPR_NODE_SEQUENCE:
        case EXPR_NODE_PL_ATTR:
        case EXPR_NODE_PRIOR:
            return GS_TRUE;

        case EXPR_NODE_RESERVED:
            return is_filter_value_reserved(node, l_tabs, p_tabs, join_type, is_right_node);

        case EXPR_NODE_COLUMN:
        case EXPR_NODE_TRANS_COLUMN:
            return is_filter_value_column(node, l_tabs, p_tabs, join_type, is_right_node);

        case EXPR_NODE_SELECT:
            return is_filter_value_subslct(node);

        case EXPR_NODE_FUNC:
            return is_filter_value_func(node, l_tabs, p_tabs, join_type, is_right_node);

        case EXPR_NODE_CASE:
            return is_filter_value_case(node, l_tabs, p_tabs, join_type, is_right_node);

        case EXPR_NODE_V_ADDR:
            return sql_pair_type_is_plvar(node);
        default:
            return GS_FALSE;
    }
}

static inline bool32 is_filter_value_expr_tree(expr_tree_t *expr, sql_array_t *l_tabs, sql_array_t *p_tabs,
                                               sql_join_type_t join_type, bool32 is_right_node)
{
    while (expr != NULL) {
        GS_RETVALUE_IFTRUE(!is_filter_value_expr_node(expr->root, l_tabs, p_tabs, join_type, is_right_node), GS_FALSE);
        expr = expr->next;
    }
    return GS_TRUE;
}

bool32 sql_cmp_node_equal(sql_stmt_t *stmt, cmp_node_t *cmp1, cmp_node_t *cmp2, uint32 *tab_map)
{
    if ((uint32)cmp1->join_type ^ (uint32)cmp2->join_type) {
        return GS_FALSE;
    }

    if (cmp1->type ^ cmp2->type) {
        return GS_FALSE;
    }

    if (sql_expr_tree_equal(stmt, cmp1->left, cmp2->left, tab_map) &&
        sql_expr_tree_equal(stmt, cmp1->right, cmp2->right, tab_map)) {
        return GS_TRUE;
    }

    if (cmp1->type != CMP_TYPE_EQUAL) {
        return GS_FALSE;
    }

    if (sql_expr_tree_equal(stmt, cmp1->left, cmp2->right, tab_map) &&
        sql_expr_tree_equal(stmt, cmp1->right, cmp2->left, tab_map)) {
        return GS_TRUE;
    }

    return GS_FALSE;
}

bool32 sql_cond_node_equal(sql_stmt_t *stmt, cond_node_t *cond1, cond_node_t *cond2, uint32 *tab_map)
{
    if (cond1->type ^ cond2->type) {
        return GS_FALSE;
    }

    if (!((cond1->cmp == NULL && cond2->cmp == NULL) || (cond1->cmp != NULL && cond2->cmp != NULL)) ||
        !((cond1->left == NULL && cond2->left == NULL) || (cond1->left != NULL && cond2->left != NULL)) ||
        !((cond1->right == NULL && cond2->right == NULL) || (cond1->right != NULL && cond2->right != NULL))) {
        return GS_FALSE;
    }

    if (cond1->left != NULL) {
        if (!sql_cond_node_equal(stmt, cond1->left, cond2->left, tab_map)) {
            return GS_FALSE;
        }
    }
    if (cond1->right != NULL) {
        if (!sql_cond_node_equal(stmt, cond1->right, cond2->right, tab_map)) {
            return GS_FALSE;
        }
    }
    if (cond1->cmp != NULL) {
        if (!sql_cmp_node_equal(stmt, cond1->cmp, cond2->cmp, tab_map)) {
            return GS_FALSE;
        }
    }
    return GS_TRUE;
}

static text_t g_rowid = { "ROWID", 5 };
static text_t g_rowscn = { "ROWSCN", 6 };
static text_t g_rownodeid = { "ROWNODEID", 9 };

void sql_init_udo_with_str(var_udo_t *obj, char *user, char *pack, char *name)
{
    obj->user.str = user;
    obj->user.len = 0;
    obj->pack.str = pack;
    obj->pack.len = 0;
    obj->name.str = name;
    obj->name.len = 0;
    obj->unused = 0;
    obj->name_sensitive = GS_FALSE;
    obj->pack_sensitive = GS_FALSE;
    obj->user_explicit = GS_FALSE;
}

static inline bool32 if_need_add_func_node(sql_verifier_t *verf, expr_node_t *node)
{
    if (!g_instance->sql.enable_func_idx_only || node->type != EXPR_NODE_FUNC || verf->stmt == NULL ||
        verf->stmt->context == NULL) {
        return GS_FALSE;
    }

    sql_type_t type = verf->stmt->context->type;
    if ((type == SQL_TYPE_SELECT || type == SQL_TYPE_INSERT || type == SQL_TYPE_CREATE_TABLE) &&
        verf->select_ctx != NULL) {
        return GS_TRUE;
    }

    return GS_FALSE;
}

status_t sql_add_ref_func_node(sql_verifier_t *verf, expr_node_t *node)
{
    if (NODE_IS_RES_ROWNUM(node) && (verf->excl_flags & SQL_EXCL_ROWNUM)) {
        GS_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "unexpected rownum occurs");
        return GS_ERROR;
    }

    if (!if_need_add_func_node(verf, node)) {
        return GS_SUCCESS;
    }

    return GS_ERROR;
}

status_t sql_verify(sql_stmt_t *stmt)
{
    void *entry = stmt->context->entry;
    cm_reset_error_loc();
    if (stmt->context->params->count > GS_MAX_SQL_PARAM_COUNT) {
        GS_THROW_ERROR(ERR_TOO_MANY_BIND, stmt->context->params->count, GS_MAX_SQL_PARAM_COUNT);
        return GS_ERROR;
    }
    SAVE_AND_RESET_NODE_STACK(stmt);
    if (stmt->context->type == SQL_TYPE_SELECT) {
        GS_RETURN_IFERR(sql_verify_select(stmt, (sql_select_t *)entry));
    } else {
        GS_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "semantic error");
        return GS_ERROR;
    }
    SQL_RESTORE_NODE_STACK(stmt);
    return GS_SUCCESS;
}

bool32 sql_check_reserved_is_const(expr_node_t *node)
{
    switch (VALUE(uint32, &node->value)) {
        case RES_WORD_ROWNUM:
        case RES_WORD_ROWID:
        case RES_WORD_ROWSCN:
        case RES_WORD_LEVEL:
        case RES_WORD_CONNECT_BY_ISCYCLE:
        case RES_WORD_CONNECT_BY_ISLEAF:
        case RES_WORD_ROWNODEID:
            return GS_FALSE;
        default:
            return GS_TRUE;
    }
}

static status_t sql_create_proj_col_array(sql_stmt_t *stmt, sql_table_t *table, uint32 col_count)
{
    uint32 column_count = col_count;
    if (column_count == 0) {
        GS_THROW_ERROR(ERR_COLUMNS_MISMATCH);
        return GS_ERROR;
    }

    // add one additional column for reserved word:rownodeid,
    // if add new reserved word, please change COL_RESERVED_CEIL
    column_count = column_count + COL_RESERVED_CEIL;

    GS_RETURN_IFERR(
        sql_alloc_mem((void *)(stmt->context), sizeof(project_col_array_t), (void **)&table->project_col_array));
    uint32 size = (column_count - 1) / PROJECT_COL_ARRAY_STEP + 1;
    uint32 proj_col_array_size;
    if (opr_uint32mul_overflow(sizeof(project_col_info_t *), size, &proj_col_array_size)) {
        GS_THROW_ERROR(ERR_TYPE_OVERFLOW, "UINT32");
        return GS_ERROR;
    }

    GS_RETURN_IFERR(
        sql_alloc_mem((void *)(stmt->context), proj_col_array_size, (void **)&table->project_col_array->base));

    for (uint32 i = 0; i < size; i++) {
        GS_RETURN_IFERR(sql_alloc_mem((void *)(stmt->context), sizeof(project_col_info_t) * PROJECT_COL_ARRAY_STEP,
                                      (void **)&table->project_col_array->base[i]));
    }

    table->project_col_array->count = column_count;
    return GS_SUCCESS;
}

status_t sql_create_project_columns(sql_stmt_t *stmt, sql_table_t *table)
{
    if (table->project_col_array != NULL) {
        return GS_SUCCESS;
    }

    uint32 column_count = 0;
    if (table->type != NORMAL_TABLE) {
        column_count = table->select_ctx->first_query->rs_columns->count;
    } else {
        column_count = knl_get_column_count(table->entry->dc.handle);
    }

    GS_RETURN_IFERR(sql_create_proj_col_array(stmt, table, column_count));

    return GS_SUCCESS;
}
static status_t sql_verify_like(sql_verifier_t *verf, cmp_node_t *node)
{
    verf->excl_flags |= SQL_EXCL_JOIN;

    GS_RETURN_IFERR(sql_verify_expr(verf, node->left));

    GS_RETURN_IFERR(sql_verify_expr(verf, node->right));

    return GS_SUCCESS;
}

static inline status_t sql_verify_join_symbol_cmp(sql_verifier_t *verf, cmp_node_t *node, uint32 left_tab_id,
                                                  uint32 right_tab_id)
{
    join_symbol_cmp_t *join_symbol_cmp = NULL;
    if (node->join_type == JOIN_TYPE_RIGHT) {
        if (left_tab_id == right_tab_id) {
            GS_SRC_THROW_ERROR(node->right->loc, ERR_SQL_SYNTAX_ERROR,
                               "not support same table on two side of the operator symbol when using (+)");
            return GS_ERROR;
        }
        GS_RETURN_IFERR(cm_galist_new(verf->join_symbol_cmps, sizeof(join_symbol_cmp_t), (void **)&join_symbol_cmp));
        join_symbol_cmp->cmp_node = node;
        join_symbol_cmp->left_tab = left_tab_id;
        join_symbol_cmp->right_tab = right_tab_id;
    } else if (node->join_type == JOIN_TYPE_LEFT) {
        if (left_tab_id == right_tab_id) {
            GS_SRC_THROW_ERROR(node->left->loc, ERR_SQL_SYNTAX_ERROR,
                               "not support same table on two side of the operator symbol when using (+)");
            return GS_ERROR;
        }
        GS_RETURN_IFERR(cm_galist_new(verf->join_symbol_cmps, sizeof(join_symbol_cmp_t), (void **)&join_symbol_cmp));
        join_symbol_cmp->cmp_node = node;
        join_symbol_cmp->left_tab = right_tab_id;
        join_symbol_cmp->right_tab = left_tab_id;
    }

    return GS_SUCCESS;
}

static status_t sql_verify_compare_normal(sql_verifier_t *verf, cmp_node_t *node)
{
    verf->join_tab_id = GS_INVALID_ID32;
    verf->same_join_tab = GS_TRUE;

    GS_RETURN_IFERR(sql_verify_expr(verf, node->left));
    uint32 left_tab_id = verf->join_tab_id;

    if (verf->incl_flags & SQL_INCL_JOIN) {
        if (!verf->same_join_tab) {
            GS_SRC_THROW_ERROR(node->left->loc, ERR_SQL_SYNTAX_ERROR,
                               "not support multiple tables on one side of the operator symbol when using (+)");
            return GS_ERROR;
        }

        if (left_tab_id == GS_INVALID_ID32) {
            GS_SRC_THROW_ERROR(node->left->loc, ERR_SQL_SYNTAX_ERROR,
                               "The (+) operator can be applied only to a column of a table");
            return GS_ERROR;
        }

        node->join_type = JOIN_TYPE_LEFT;
        verf->excl_flags |= SQL_EXCL_JOIN;
        verf->incl_flags &= ~SQL_INCL_JOIN;
    }

    if (!verf->same_join_tab) {
        verf->excl_flags |= SQL_EXCL_JOIN;
        verf->same_join_tab = GS_TRUE;
    }

    verf->join_tab_id = GS_INVALID_ID32;
    GS_RETURN_IFERR(sql_verify_expr(verf, node->right));
    uint32 right_tab_id = verf->join_tab_id;

    if (verf->incl_flags & SQL_INCL_JOIN) {
        if (right_tab_id == GS_INVALID_ID32) {
            GS_SRC_THROW_ERROR(node->right->loc, ERR_SQL_SYNTAX_ERROR,
                               "The (+) operator can be applied only to a column of a table");
            return GS_ERROR;
        }

        node->join_type = JOIN_TYPE_RIGHT;
        verf->incl_flags &= ~SQL_INCL_JOIN;
    }

    if (node->join_type != JOIN_TYPE_NONE && !verf->same_join_tab) {
        GS_SRC_THROW_ERROR(node->right->loc, ERR_SQL_SYNTAX_ERROR,
                           "not support multiple tables on one side of the operator symbol when using (+)");
        return GS_ERROR;
    }

    if (verf->join_symbol_cmps != NULL) {
        GS_RETURN_IFERR(sql_verify_join_symbol_cmp(verf, node, left_tab_id, right_tab_id));
    }

    return GS_SUCCESS;
}

static status_t sql_verify_compare(sql_verifier_t *verf, cmp_node_t *node)
{
    uint32 excl_flags_bak = verf->excl_flags;

    switch (node->type) {
        case CMP_TYPE_IS_NULL:
        case CMP_TYPE_IS_NOT_NULL:
            verf->excl_flags |= SQL_EXCL_JOIN;
            GS_RETURN_IFERR(sql_verify_expr(verf, node->left));
            break;

        case CMP_TYPE_IS_JSON:
        case CMP_TYPE_IS_NOT_JSON:
        case CMP_TYPE_IN:
        case CMP_TYPE_NOT_IN:
        case CMP_TYPE_EQUAL_ANY:
        case CMP_TYPE_NOT_EQUAL_ANY:
        case CMP_TYPE_GREAT_EQUAL_ANY:
        case CMP_TYPE_GREAT_ANY:
        case CMP_TYPE_LESS_ANY:
        case CMP_TYPE_LESS_EQUAL_ANY:
        case CMP_TYPE_EQUAL_ALL:
        case CMP_TYPE_NOT_EQUAL_ALL:
        case CMP_TYPE_GREAT_EQUAL_ALL:
        case CMP_TYPE_GREAT_ALL:
        case CMP_TYPE_LESS_ALL:
        case CMP_TYPE_LESS_EQUAL_ALL:
        case CMP_TYPE_BETWEEN:
        case CMP_TYPE_NOT_BETWEEN:
        case CMP_TYPE_EXISTS:
        case CMP_TYPE_NOT_EXISTS:
        case CMP_TYPE_REGEXP_LIKE:
        case CMP_TYPE_NOT_REGEXP_LIKE:
        case CMP_TYPE_REGEXP:
        case CMP_TYPE_NOT_REGEXP:
            GS_SRC_THROW_ERROR(node->left->loc, ERR_SQL_SYNTAX_ERROR, "not supported");
            return GS_ERROR;

        case CMP_TYPE_LIKE:
        case CMP_TYPE_NOT_LIKE:
            verf->excl_flags |= SQL_EXCL_JOIN;
            GS_RETURN_IFERR(sql_verify_like(verf, node));
            break;

        case CMP_TYPE_EQUAL:
        case CMP_TYPE_NOT_EQUAL:
        case CMP_TYPE_GREAT_EQUAL:
        case CMP_TYPE_GREAT:
        case CMP_TYPE_LESS:
        case CMP_TYPE_LESS_EQUAL:
        default:
            verf->excl_flags |= SQL_EXCL_ARRAY;
            GS_RETURN_IFERR(sql_verify_compare_normal(verf, node));
            break;
    }

    verf->excl_flags = excl_flags_bak;
    return GS_SUCCESS;
}

static status_t sql_static_check_exprs(const expr_tree_t *left, const expr_tree_t *right)
{
    if (sql_is_skipped_expr(left) || sql_is_skipped_expr(right)) {
        return GS_SUCCESS;
    }

    if (get_cmp_datatype(TREE_DATATYPE(left), TREE_DATATYPE(right)) == INVALID_CMP_DATATYPE) {
        if (IS_COMPLEX_TYPE(TREE_DATATYPE(left)) || IS_COMPLEX_TYPE(TREE_DATATYPE(right))) {
            GS_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "complex type cannot be used for condition");
        } else {
            GS_SRC_ERROR_MISMATCH(TREE_LOC(right), TREE_DATATYPE(left), TREE_DATATYPE(right));
        }
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

/**
 * static check the inconsistency of two datatypes in WHERE clause
 * @author 2018/01/20
 */
static status_t sql_static_check_compare(const cmp_node_t *node)
{
    switch (node->type) {
        case CMP_TYPE_EQUAL_ANY:
        case CMP_TYPE_NOT_EQUAL_ANY:
        case CMP_TYPE_GREAT_EQUAL_ANY:
        case CMP_TYPE_GREAT_ANY:
        case CMP_TYPE_LESS_ANY:
        case CMP_TYPE_LESS_EQUAL_ANY:
        case CMP_TYPE_EQUAL_ALL:
        case CMP_TYPE_NOT_EQUAL_ALL:
        case CMP_TYPE_GREAT_EQUAL_ALL:
        case CMP_TYPE_GREAT_ALL:
        case CMP_TYPE_LESS_ALL:
        case CMP_TYPE_LESS_EQUAL_ALL:
        case CMP_TYPE_IN:
        case CMP_TYPE_NOT_IN:
        case CMP_TYPE_BETWEEN:
        case CMP_TYPE_NOT_BETWEEN:
            return GS_ERROR;

        case CMP_TYPE_EQUAL:
        case CMP_TYPE_GREAT_EQUAL:
        case CMP_TYPE_GREAT:
        case CMP_TYPE_LESS:
        case CMP_TYPE_LESS_EQUAL:
        case CMP_TYPE_NOT_EQUAL:
            return sql_static_check_exprs(node->left, node->right);

        case CMP_TYPE_LIKE:
        case CMP_TYPE_NOT_LIKE:
        case CMP_TYPE_EXISTS:
        case CMP_TYPE_NOT_EXISTS:
        case CMP_TYPE_IS_NULL:
        case CMP_TYPE_IS_NOT_NULL:
        case CMP_TYPE_IS_JSON:
        case CMP_TYPE_IS_NOT_JSON:

        default:
            return GS_SUCCESS;
    }
}

//         To evaluate constant condition node at verification stage.
static status_t sql_verify_cond_node(sql_verifier_t *verf, cond_node_t *node, uint32 *rnum_upper, bool8 *rnum_pending)
{
    GS_RETURN_IFERR(sql_stack_safe(verf->stmt));

    switch (node->type) {
        case COND_NODE_COMPARE:

            GS_RETURN_IFERR(sql_verify_compare(verf, node->cmp));

            GS_RETURN_IFERR(sql_static_check_compare(node->cmp));

            *rnum_upper = GS_INFINITE32;
            *rnum_pending = GS_FALSE;
            node->cmp->rnum_pending = *rnum_pending;

            if (node->cmp->join_type == JOIN_TYPE_LEFT || node->cmp->join_type == JOIN_TYPE_RIGHT) {
                node->type = COND_NODE_TRUE;
            }
            break;

        case COND_NODE_OR:
        case COND_NODE_AND:
        case COND_NODE_FALSE:
        case COND_NODE_TRUE:
        case COND_NODE_NOT:  // already eliminated in parsing phase
        default:
            return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t sql_verify_cond(sql_verifier_t *verf, cond_tree_t *cond)
{
    if (cond == NULL) {
        return GS_SUCCESS;
    }

    verf->excl_flags |= SQL_EXCL_ROWNODEID;
    verf->incl_flags |= SQL_INCL_COND_COL;
    if (sql_verify_cond_node(verf, cond->root, &cond->rownum_upper, &cond->rownum_pending) != GS_SUCCESS) {
        return GS_ERROR;
    }

    verf->incl_flags &= ~(SQL_INCL_COND_COL);
    cond->incl_flags = verf->incl_flags;
    return GS_SUCCESS;
}

status_t sql_verify_query_where(sql_verifier_t *verf, sql_query_t *query)
{
    if (query->cond == NULL) {
        return GS_SUCCESS;
    }

    verf->tables = &query->tables;
    verf->curr_query = query;
    verf->incl_flags = 0;
    verf->excl_flags = SQL_WHERE_EXCL;
    verf->has_acstor_col = GS_FALSE;
    verf->join_symbol_cmps = query->join_symbol_cmps;

    if (sql_verify_cond(verf, query->cond) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (verf->has_acstor_col) {
        query->cond_has_acstor_col = GS_TRUE;
    }

    /* if exists connect by and where_cond in query->cond,where_cond needs down query->filter_cond
           reason: if do not push the where_cond which in query->cond down to query->filter_cond at here,
           the query->cond will contain both where_cond and join_on_cond at transform stage.At that time,
           we will not be able to distinguish them, so they will both be pushed down to query->filter_cond
           in error if exists connect by.
        */
    knl_panic(query->connect_by_cond == NULL);
    return GS_SUCCESS;
}
static status_t sql_verify_array_subscript(expr_node_t *node, knl_column_t *knl_col, var_column_t *v_col)
{
    if (KNL_COLUMN_IS_ARRAY(knl_col)) {
        return GS_ERROR;
    } else {
        if (node->word.column.ss_start != GS_INVALID_ID32) {
            GS_SRC_THROW_ERROR(node->loc, ERR_USE_WRONG_SUBSCRIPT, knl_col->name);
            return GS_ERROR;
        }

        v_col->is_array = GS_FALSE;
        v_col->ss_start = GS_INVALID_ID32;
        v_col->ss_end = GS_INVALID_ID32;
    }

    return GS_SUCCESS;
}

static status_t sql_verify_knl_column_in_knl_table(sql_verifier_t *verf, sql_table_t *table, expr_node_t *node,
                                                   var_column_t *v_col, knl_column_t *knl_col)
{
    if (table->type == VIEW_AS_TABLE) {
        return GS_ERROR;
    } else {
        v_col->datatype = knl_col->datatype;
        v_col->is_jsonb = KNL_COLUMN_IS_JSONB(knl_col);
        sql_typmod_from_knl_column(&node->typmod, knl_col);
    }

    return GS_SUCCESS;
}

static status_t sql_try_find_column_in_knl_table(sql_verifier_t *verf, sql_table_t *table, expr_node_t *node,
                                                 text_t *column, bool32 *is_found)
{
    uint16 tmp_col_id;
    query_field_t query_field;
    knl_column_t *knl_col = NULL;
    var_column_t *v_col = VALUE_PTR(var_column_t, &node->value);

    if (table->entry->dc.type == DICT_TYPE_UNKNOWN) {
        return GS_SUCCESS;
    }

    tmp_col_id = knl_get_column_id(&table->entry->dc, column);
    if (GS_INVALID_ID16 == tmp_col_id) {
        return GS_SUCCESS;
    }

    knl_col = knl_get_column(table->entry->dc.handle, tmp_col_id);
    if (KNL_COLUMN_INVISIBLE(knl_col)) {
        return GS_SUCCESS;
    }

    // add sequence from default value
    if (knl_col->default_text.len != 0) {
        GS_RETURN_IFERR(sql_add_sequence_node(verf->stmt, ((expr_tree_t *)knl_col->default_expr)->root));
    }

    v_col->tab = table->id;
    v_col->col = tmp_col_id;

    GS_RETURN_IFERR(sql_verify_knl_column_in_knl_table(verf, table, node, v_col, knl_col));

    if (table->project_col_array != NULL) {
        project_col_info_t *project_col_info = sql_get_project_info_col(table->project_col_array, v_col->col);
        project_col_info->col_name = column;
        project_col_info->col_name_has_quote = KNL_COLUMN_HAS_QUOTE(knl_col) ? GS_TRUE : GS_FALSE;
    }
    *is_found = GS_TRUE;

    /* if the column is an array filed, then verify the subscript */
    if (sql_verify_array_subscript(node, knl_col, v_col) != GS_SUCCESS) {
        return GS_ERROR;
    }

    SQL_SET_QUERY_FIELD_INFO(&query_field, v_col->datatype, v_col->col, v_col->is_array, v_col->ss_start,
                             v_col->ss_end);

    if (verf->incl_flags & SQL_INCL_COND_COL) {
        return sql_table_cache_cond_query_field(verf->stmt, table, &query_field);
    }

    return sql_table_cache_query_field(verf->stmt, table, &query_field);
}

static status_t sql_try_find_column(sql_verifier_t *verf, sql_table_t *table, expr_node_t *node, text_t *user,
                                    text_t *column, bool32 *is_found)
{
    if (table == NULL) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "can not find column:%s", T2S(column));
        return GS_ERROR;
    }
    *is_found = GS_FALSE;

    if (user->len > 0 && !cm_text_equal((text_t *)&table->user, user)) {
        return GS_SUCCESS;
    }

    switch (table->type) {
        case SUBSELECT_AS_TABLE:
        case WITH_AS_TABLE:
        case FUNC_AS_TABLE:
        case JSON_TABLE:
            knl_panic(0);
            return GS_ERROR;
        default:
            return sql_try_find_column_in_knl_table(verf, table, node, column, is_found);
    }
}

static status_t sql_search_column_in_table_list(sql_verifier_t *verf, sql_array_t *tables, expr_node_t *node,
                                                text_t *user, text_t *column, bool32 *is_found)
{
    bool32 tmp_is_found = GS_FALSE;

    for (uint32 i = 0; i < tables->count; i++) {
        sql_table_t *tmp_table = (sql_table_t *)sql_array_get(tables, i);

        if (sql_try_find_column(verf, tmp_table, node, user, column, &tmp_is_found) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (!tmp_is_found) {
            continue;
        }

        if (*is_found) {
            GS_SRC_THROW_ERROR_EX(node->loc, ERR_SQL_SYNTAX_ERROR, "column '%s' ambiguously defined", T2S(column));
            return GS_ERROR;
        }
        *is_found = GS_TRUE;
        if (verf->join_tab_id == GS_INVALID_ID32) {
            verf->join_tab_id = tmp_table->id;
        } else if (verf->join_tab_id != tmp_table->id) {
            verf->same_join_tab = GS_FALSE;
        }
    }
    return GS_SUCCESS;
}

static status_t sql_search_column_local(sql_verifier_t *verf, expr_node_t *node, text_t *user, text_t *column,
                                        bool32 *is_found)
{
    if (verf->tables == NULL) {  // for non select
        return sql_try_find_column(verf, verf->table, node, user, column, is_found);
    }

    return sql_search_column_in_table_list(verf, verf->tables, node, user, column, is_found);
}

static status_t sql_search_column(sql_verifier_t *verf, expr_node_t *node, text_t *user, text_t *column)
{
    uint32 level = 0;
    bool32 is_found = GS_FALSE;
    var_column_t *v_col = VALUE_PTR(var_column_t, &node->value);

    do {
        if (verf->table != NULL || verf->tables != NULL) {
            GS_RETURN_IFERR(sql_search_column_local(verf, node, user, column, &is_found));
            if (is_found) {
                break;
            }
        }

        GS_RETURN_IFERR(sql_try_verify_noarg_func(verf, node, &is_found));
        if (is_found) {
            return GS_SUCCESS;
        }

        // reserved return false
        if (node->type == EXPR_NODE_RESERVED) {
            GS_SRC_THROW_ERROR_EX(node->loc, ERR_SQL_SYNTAX_ERROR, "invalid column name '%s'", T2S(column));
            return GS_ERROR;
        }
    } while (0);

    v_col->ancestor = level;

    if (level > 0) {
        verf->has_acstor_col = GS_TRUE;
    }

    return GS_SUCCESS;
}

static status_t sql_try_verify_column(sql_verifier_t *verf, expr_node_t *node)
{
    bool32 result = GS_FALSE;
    sql_text_t *user = NULL;
    sql_text_t *table = NULL;
    column_word_t *col = NULL;

    if ((verf->excl_flags & SQL_EXCL_COLUMN) != 0) {
        GS_RETURN_IFERR(sql_try_verify_noarg_func(verf, node, &result));
        if (result) {
            return GS_SUCCESS;
        }
        GS_SRC_THROW_ERROR_EX(node->loc, ERR_SQL_SYNTAX_ERROR, "invalid column name '%s'",
                              T2S(&node->word.column.name.value));
        return GS_ERROR;
    }

    col = &node->word.column;
    user = &col->user;
    table = &col->table;

    if (verf->is_check_cons) {
        GS_SRC_THROW_ERROR_EX(node->loc, ERR_SQL_SYNTAX_ERROR, "check cons not supported");
        return GS_ERROR;
    }

    if (table->len > 0) {
        GS_SRC_THROW_ERROR_EX(node->loc, ERR_SQL_SYNTAX_ERROR, "table name not supported");
        return GS_ERROR;
    } else {
        GS_RETURN_IFERR(sql_search_column(verf, node, &user->value, &col->name.value));
    }

    return GS_SUCCESS;
}

status_t sql_verify_column_expr(sql_verifier_t *verf, expr_node_t *node)
{
    column_word_t *col = NULL;
    bool32 result = GS_FALSE;

    /* verify dbms const, such as DBE_STATS.AUTO_SAMPLE_SIZE */
    GS_RETURN_IFERR(sql_try_verify_dbmsconst(verf, node, &result));
    if (result) {
        return GS_SUCCESS;
    }

    GS_RETURN_IFERR(sql_try_verify_rowid(verf, node, &result));
    if (result) {
        return GS_SUCCESS;
    }

    GS_RETURN_IFERR(sql_try_verify_rowscn(verf, node, &result));
    if (result) {
        return GS_SUCCESS;
    }

    GS_RETURN_IFERR(sql_try_verify_rownodeid(verf, node, &result));

    if (result) {
        return GS_SUCCESS;
    }

    GS_RETURN_IFERR(sql_try_verify_column(verf, node));

    col = &node->word.column;
    if (verf->merge_insert_status != SQL_MERGE_INSERT_NONE && node->type != EXPR_NODE_USER_FUNC &&
        node->value.v_col.tab == 0) {
        if (verf->merge_insert_status == SQL_MERGE_INSERT_VALUES) {
            GS_SRC_THROW_ERROR_EX(node->loc, ERR_SQL_SYNTAX_ERROR, "invalid column in the INSERT VALUES clause: %s",
                                  T2S(&col->name.value));
        } else {
            GS_SRC_THROW_ERROR_EX(node->loc, ERR_SQL_SYNTAX_ERROR, "invalid column in the INSERT WHERE clause: %s",
                                  T2S(&col->name.value));
        }
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

static status_t sql_extract_table_column(sql_verifier_t *verf, rs_column_t *rs_col, sql_table_t *table,
                                         knl_column_t *knl_col, uint32 col_id, bool32 always_null)
{
    project_col_info_t *project_col_info = NULL;

    rs_col->type = RS_COL_COLUMN;
    rs_col->name.str = knl_col->name;
    rs_col->name.len = (uint32)strlen(knl_col->name);
    rs_col->v_col.tab = table->id;
    rs_col->v_col.col = col_id;
    rs_col->v_col.is_array = KNL_COLUMN_IS_ARRAY(knl_col);
    rs_col->v_col.is_jsonb = KNL_COLUMN_IS_JSONB(knl_col);
    rs_col->v_col.ss_start = GS_INVALID_ID32;
    rs_col->v_col.ss_end = GS_INVALID_ID32;

    if (table->type == VIEW_AS_TABLE) {
        return GS_ERROR;
    } else {
        GS_BIT_RESET(rs_col->rs_flag, RS_EXIST_ALIAS);
        RS_SET_FLAG(always_null || knl_col->nullable, rs_col, RS_NULLABLE);
        sql_typmod_from_knl_column(&rs_col->typmod, knl_col);
        rs_col->v_col.datatype = knl_col->datatype;
    }

    RS_SET_FLAG(KNL_COLUMN_HAS_QUOTE(knl_col), rs_col, RS_HAS_QUOTE);
    RS_SET_FLAG(KNL_COLUMN_IS_SERIAL(knl_col), rs_col, RS_IS_SERIAL);
    GS_BIT_SET(rs_col->rs_flag, RS_SINGLE_COL);
    project_col_info = sql_get_project_info_col(table->project_col_array, col_id);
    project_col_info->col_name = (rs_col->z_alias.len == 0) ? &rs_col->name : &rs_col->z_alias;
    project_col_info->col_name_has_quote = GS_BIT_TEST(rs_col->rs_flag, RS_HAS_QUOTE) ? GS_TRUE : GS_FALSE;

    return GS_SUCCESS;
}

static status_t sql_extract_table_columns(sql_verifier_t *verf, sql_query_t *query, sql_table_t *table,
                                          expr_node_t *node)
{
    uint32 i, cols;
    knl_column_t *knl_col = NULL;
    rs_column_t *rs_col = NULL;
    bool32 always_null = verf->select_ctx->root->type != SELECT_NODE_QUERY;

    query_field_t query_field;
    CM_ASSERT(table != NULL);
    cols = knl_get_column_count(table->entry->dc.handle);

    // for: select * from tab;
    if ((query->tables.count == 1) && (query->columns->count == 1) && (query->ssa.count == 0)) {
        table->ret_full_fields = GS_TRUE;
    }

    for (i = 0; i < cols; i++) {
        knl_col = knl_get_column(table->entry->dc.handle, i);
        if (KNL_COLUMN_INVISIBLE(knl_col)) {
            continue;
        }

        if (GS_IS_LOB_TYPE(knl_col->datatype) && ((verf->excl_flags & SQL_EXCL_LOB_COL) != 0)) {
            GS_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "unexpected lob column occurs");
            return GS_ERROR;
        }

        if (cm_galist_new(query->rs_columns, sizeof(rs_column_t), (void **)&rs_col) != GS_SUCCESS) {
            return GS_ERROR;
        }

        GS_RETURN_IFERR(sql_extract_table_column(verf, rs_col, table, knl_col, i, always_null));

        SQL_SET_QUERY_FIELD_INFO(&query_field, rs_col->v_col.datatype, rs_col->v_col.col, rs_col->v_col.is_array,
                                 rs_col->v_col.ss_start, rs_col->v_col.ss_end);
        GS_RETURN_IFERR(sql_table_cache_query_field(verf->stmt, table, &query_field));
    }
    return GS_SUCCESS;
}

static status_t sql_extract_columns(sql_verifier_t *verf, sql_query_t *query, sql_table_t *table, expr_node_t *node)
{
    switch (table->type) {
        case SUBSELECT_AS_TABLE:
        case WITH_AS_TABLE:
        case FUNC_AS_TABLE:
        case JSON_TABLE:
        case VIEW_AS_TABLE:
            return GS_ERROR;
        case NORMAL_TABLE:
        default:
            GS_RETURN_IFERR(sql_extract_table_columns(verf, query, table, node));
            break;
    }
    return GS_SUCCESS;
}

static status_t sql_expand_star(sql_verifier_t *verf, sql_query_t *query, expr_node_t *node)
{
    table_word_t *word = &node->word.table;
    sql_table_t *table = NULL;
    bool32 is_found = GS_FALSE;

    if (word->name.len != 0) {
        GS_RETURN_IFERR(
            sql_search_table_local(verf, node, (text_t *)&word->user, (text_t *)&word->name, &table, &is_found));
        if (!is_found) {
            GS_SRC_THROW_ERROR_EX(node->loc, ERR_SQL_SYNTAX_ERROR, "invalid table '%s'", T2S((text_t *)&word->name));
            return GS_ERROR;
        }
        node->value.v_col.tab = table->id;
        return sql_extract_columns(verf, query, table, node);
    }

    for (uint32 i = 0; i < query->tables.count; i++) {
        table = (sql_table_t *)sql_array_get(&query->tables, i);
        GS_RETURN_IFERR(sql_extract_columns(verf, query, table, node));
    }

    return GS_SUCCESS;
}

static void sql_get_normal_column_desc(sql_verifier_t *very, rs_column_t *rs_col)
{
    sql_table_t *table = NULL;
    knl_column_t *knl_col = NULL;
    bool32 always_null = GS_FALSE;
    bool32 nullable = GS_FALSE;

    // In a sub-select, and reference to parent query
    // precision,scale,nullable derivation have no use
    // use thread very->query->select_ctx->parent to find the right table
    if (rs_col->v_col.ancestor != 0 || very->curr_query == NULL || very->select_ctx == NULL) {
        return;
    }

    table = (sql_table_t *)sql_array_get(&very->curr_query->tables, rs_col->v_col.tab);
    always_null = very->select_ctx->root->type != SELECT_NODE_QUERY;
    switch (table->type) {
        case SUBSELECT_AS_TABLE:
        case VIEW_AS_TABLE:
        case WITH_AS_TABLE:
        case FUNC_AS_TABLE:
        case JSON_TABLE:
            knl_panic(0);
            break;

        case NORMAL_TABLE:
        default:
            knl_col = knl_get_column(table->entry->dc.handle, rs_col->v_col.col);
            nullable = always_null || table->rs_nullable || knl_col->nullable;
            RS_SET_FLAG(nullable, rs_col, RS_NULLABLE);
            RS_SET_FLAG(KNL_COLUMN_HAS_QUOTE(knl_col), rs_col, RS_HAS_QUOTE);
            RS_SET_FLAG(KNL_COLUMN_IS_SERIAL(knl_col), rs_col, RS_IS_SERIAL);
            break;
    }
}

static status_t sql_gen_column_z_alias(sql_stmt_t *stmt, query_column_t *column, uint32 col_id)
{
    if (column->exist_alias || IS_LOCAL_COLUMN(column->expr)) {
        column->z_alias.str = NULL;
        column->z_alias.len = 0;
        return GS_SUCCESS;
    }

    char buff[GS_MAX_NAME_LEN];
    PRTS_RETURN_IFERR(snprintf_s(buff, GS_MAX_NAME_LEN, GS_MAX_NAME_LEN - 1, "Z_ALIAS_%u", col_id));
    text_t txt = { .str = buff };
    txt.len = (uint32)strlen(buff);
    GS_RETURN_IFERR(sql_copy_name(stmt->context, &txt, &column->z_alias));
    return GS_SUCCESS;
}

static status_t sql_gen_rs_column(sql_verifier_t *verf, query_column_t *column, expr_node_t *node, rs_column_t *rs_col)
{
    var_column_t *v_col = NULL;

    rs_col->name = column->alias;
    rs_col->z_alias = column->z_alias;
    rs_col->typmod = node->typmod;
    RS_SET_FLAG(column->exist_alias, rs_col, RS_EXIST_ALIAS);

    if (GS_BIT_TEST(verf->incl_flags, SQL_INCL_ROWNUM)) {
        GS_BIT_SET(rs_col->rs_flag, RS_HAS_ROWNUM);
    }

    if (GS_BIT_TEST(verf->incl_flags, SQL_COND_UNABLE_INCL)) {
        GS_BIT_SET(rs_col->rs_flag, RS_COND_UNABLE);
    } else {
        GS_BIT_RESET(rs_col->rs_flag, RS_COND_UNABLE);
    }

    if (IS_NORMAL_COLUMN(column->expr) && EXPR_ANCESTOR(column->expr) == 0) {
        v_col = VALUE_PTR(var_column_t, &node->value);
        rs_col->type = RS_COL_COLUMN;
        GS_BIT_SET(rs_col->rs_flag, RS_SINGLE_COL);
        rs_col->v_col = *v_col;
        sql_get_normal_column_desc(verf, rs_col);
    } else {
        rs_col->type = RS_COL_CALC;
        GS_BIT_RESET(rs_col->rs_flag, RS_SINGLE_COL);
        rs_col->expr = column->expr;
        GS_BIT_SET(rs_col->rs_flag, RS_NULLABLE);
    }

    return GS_SUCCESS;
}

static status_t sql_verify_query_column(sql_verifier_t *verf, query_column_t *column)
{
    expr_node_t *node = NULL;
    rs_column_t *rs_col = NULL;
    sql_query_t *query = verf->curr_query;
    bool32 exists_rownum = GS_BIT_TEST(verf->incl_flags, SQL_INCL_ROWNUM);

    verf->aggr_flags = SQL_GEN_AGGR_FROM_COLUMN;
    node = column->expr->root;

    if (node->type == EXPR_NODE_STAR) {
        if ((verf->excl_flags & SQL_EXCL_STAR) != 0) {
            GS_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "unexpected '*'");
            return GS_ERROR;
        }

        if (column->expr->root->type == EXPR_NODE_PRIOR) {
            GS_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "unexpected 'prior'");
            return GS_ERROR;
        }

        return sql_expand_star(verf, query, node);
    }

    GS_BIT_RESET(verf->incl_flags, SQL_INCL_ROWNUM);
    GS_RETURN_IFERR(sql_verify_expr(verf, column->expr));
    GS_RETURN_IFERR(sql_gen_column_z_alias(verf->stmt, column, query->rs_columns->count));

    GS_RETURN_IFERR(cm_galist_new(query->rs_columns, sizeof(rs_column_t), (pointer_t *)&rs_col));
    GS_RETURN_IFERR(sql_gen_rs_column(verf, column, node, rs_col));

    if (exists_rownum) {
        GS_BIT_SET(verf->incl_flags, SQL_INCL_ROWNUM);
    }

    verf->aggr_flags = 0;
    return GS_SUCCESS;
}

static inline void sql_set_query_incl_flags(sql_verifier_t *verf, sql_query_t *query)
{
    if (verf->incl_flags & SQL_INCL_PRNT_OR_ANCSTR) {
        query->incl_flags |= RS_INCL_PRNT_OR_ANCSTR;
    }

    if (verf->incl_flags & SQL_INCL_SUBSLCT) {
        query->incl_flags |= RS_INCL_SUBSLCT;
    }

    if (verf->incl_flags & SQL_INCL_GROUPING) {
        query->incl_flags |= RS_INCL_GROUPING;
    }

    if (verf->incl_flags & SQL_INCL_ARRAY) {
        query->incl_flags |= RS_INCL_ARRAY;
    }
}

static status_t sql_verify_qry_col_inside(sql_verifier_t *verf, sql_query_t *query, uint32 *aggrs_expr_count,
                                          bool32 *has_single_column)
{
    query_column_t *column = NULL;

    verf->tables = &query->tables;
    verf->aggrs = query->aggrs;
    verf->cntdis_columns = query->cntdis_columns;
    verf->curr_query = query;
    verf->excl_flags = SQL_EXCL_DEFAULT | SQL_EXCL_JOIN;
    verf->has_excl_const = GS_FALSE;

    if (verf->has_union || verf->has_minus || verf->has_except_intersect) {
        verf->excl_flags |= SQL_EXCL_LOB_COL;
    }
    if (verf->stmt->context->type == SQL_TYPE_CREATE_VIEW) {
        verf->excl_flags |= SQL_EXCL_SEQUENCE;
    }

    for (uint32 i = 0; i < query->columns->count; i++) {
        verf->excl_flags |= query->has_distinct ? SQL_EXCL_LOB_COL : 0;
        verf->incl_flags = 0;

        column = (query_column_t *)cm_galist_get(query->columns, i);

        GS_RETURN_IFERR(sql_verify_query_column(verf, column));

        if (verf->incl_flags & SQL_INCL_AGGR) {
            (*aggrs_expr_count)++;

            // like substr(f1, 1, count(f2)), f1 is single column
            return GS_ERROR;
        } else if (sql_check_table_column_exists(verf->stmt, query, column->expr->root)) {
            verf->has_excl_const = GS_TRUE;
        }

        // set rs incl flags
        sql_set_query_incl_flags(verf, query);
    }
    if (query->path_func_nodes->count > 0) {
        // sys_connect_by_path is not a const
        verf->has_excl_const = GS_TRUE;
    }

    return GS_SUCCESS;
}

status_t sql_verify_query_columns(sql_verifier_t *verf, sql_query_t *query)
{
    uint32 aggrs_expr_count = 0;
    bool32 has_single_column = GS_FALSE;
    bool32 is_true = GS_FALSE;

    GS_RETURN_IFERR(sql_verify_qry_col_inside(verf, query, &aggrs_expr_count, &has_single_column));

    // verify columns with group by
    // case 1: has no group by
    is_true = (aggrs_expr_count > 0 && query->group_sets->count == 0);
    is_true = is_true && ((aggrs_expr_count != query->columns->count && verf->has_excl_const) || has_single_column);
    if (is_true) {
        // not ok: select f1, count(f2) from t1
        // not ok: select substr(f1, count(f2)), case when 1=1 then f1 else count(f2) end, f1+count(f2), 123 from t1
        // ok:     select 1, :p1, 1+:p2, count(f1) from t1
        GS_THROW_ERROR(ERR_EXPR_NOT_IN_GROUP_LIST);
        return GS_ERROR;
    }

    if (query->group_sets->count != 0) {
        GS_SRC_THROW_ERROR(query->loc, ERR_SQL_SYNTAX_ERROR, "group by not supported");
        return GS_ERROR;
    }

    // case 3: has winsort node
    if (query->winsort_list->count > 0) {
        GS_SRC_THROW_ERROR(query->loc, ERR_SQL_SYNTAX_ERROR, "winsort not supported");
        return GS_ERROR;
    }

    if (query->owner->type == SELECT_AS_VARIANT) {
        if (query->rs_columns->count > 1) {
            GS_SRC_THROW_ERROR(query->loc, ERR_SQL_SYNTAX_ERROR, "too many columns");
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}
static status_t check_table_column_exists(visit_assist_t *va, expr_node_t **node)
{
    if (va->result0 == GS_TRUE) {
        return GS_SUCCESS;
    }
    switch ((*node)->type) {
        case EXPR_NODE_SELECT:
            if (((sql_select_t *)(*node)->value.v_obj.ptr)->parent_refs->count > 0) {
                va->result0 = GS_TRUE;
            }
            break;
        case EXPR_NODE_COLUMN:
            if (NODE_ANCESTOR(*node) == 0) {
                va->result0 = GS_TRUE;
            }
            break;
        case EXPR_NODE_RESERVED:
            if (!sql_check_reserved_is_const(*node)) {
                va->result0 = GS_TRUE;
            }
            break;
        case EXPR_NODE_CONST:
        case EXPR_NODE_PARAM:
        case EXPR_NODE_V_ADDR:
        case EXPR_NODE_PROC:
        case EXPR_NODE_NEW_COL:
        case EXPR_NODE_OLD_COL:
        case EXPR_NODE_PL_ATTR:
            break;
        default:
            va->result0 = GS_TRUE;
            break;
    }
    return GS_SUCCESS;
}

bool32 sql_check_table_column_exists(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *node)
{
    // if modify this function, do modify sql_match_group_node_by_node_type at the same time
    visit_assist_t va;
    sql_init_visit_assist(&va, stmt, query);
    va.excl_flags = VA_EXCL_PRIOR;
    va.result0 = GS_FALSE;
    if (visit_expr_node(&va, &node, check_table_column_exists) == GS_SUCCESS && va.result0 == GS_FALSE) {
        return GS_FALSE;
    }
    return GS_TRUE;
}

static status_t sql_verify_column_value(sql_verifier_t *verf, expr_node_t *node)
{
    column_word_t *col = NULL;
    uint32 ancestor = 0;
    sql_table_t *table = NULL;

    col = &node->word.column;

    if (col->table.len == 0) {
        if (verf->tables == NULL) {
            // for nonselect
            table = verf->table;
        } else {
            // for select
            if (verf->tables->count > 1) {
                GS_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "rowid ambiguously defined at");
                return GS_ERROR;
            }
            table = (sql_table_t *)sql_array_get(verf->tables, 0);
        }
    }

    if (sql_search_table(verf, node, (text_t *)&col->user, (text_t *)&col->table, &table, &ancestor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

/* When an expr_node_t is a reserved word, its reserved type is stored in
 * node->value->rowid */
static inline status_t sql_verify_reserved_value(sql_verifier_t *verf, expr_node_t *node)
{
    status_t status = GS_SUCCESS;

    switch (VALUE(uint32, &node->value)) {
        case RES_WORD_ROWNUM:
            if (verf->excl_flags & SQL_EXCL_ROWNUM) {
                GS_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "unexpected rownum occurs");
                return GS_ERROR;
            }
            if (verf->curr_query != NULL) {
                verf->curr_query->incl_flags |= verf->incl_flags & SQL_INCL_COND_COL ? COND_INCL_ROWNUM
                                                                                     : EXPR_INCL_ROWNUM;
            }
            node->datatype = GS_TYPE_INTEGER;
            node->size = sizeof(int32);
            verf->incl_flags |= SQL_INCL_ROWNUM;
            break;

        case RES_WORD_ROWID:
            status = GS_ERROR;
            break;

        case RES_WORD_ROWSCN:
            status = GS_ERROR;
            break;

        case RES_WORD_ROWNODEID:
            status = GS_ERROR;
            break;

        case RES_WORD_CURDATE:
            node->datatype = GS_TYPE_DATE;
            node->size = sizeof(date_t);
            sql_add_first_exec_node(verf, node);
            break;

        case RES_WORD_SYSDATE:
            node->datatype = GS_TYPE_DATE;
            node->size = sizeof(date_t);
            sql_add_first_exec_node(verf, node);
            break;

        case RES_WORD_CURTIMESTAMP:
            if (verf->stmt->session->call_version >= CS_VERSION_8) {
                node->datatype = GS_TYPE_TIMESTAMP_TZ;
                node->size = sizeof(timestamp_tz_t);
            } else {
                node->datatype = GS_TYPE_TIMESTAMP_TZ_FAKE;
                node->size = sizeof(timestamp_t);
            }

            node->precision = GS_DEFAULT_DATETIME_PRECISION;
            sql_add_first_exec_node(verf, node);
            break;

        case RES_WORD_SYSTIMESTAMP:
            if (verf->stmt->session->call_version >= CS_VERSION_8) {
                node->datatype = GS_TYPE_TIMESTAMP_TZ;
                node->size = sizeof(timestamp_tz_t);
            } else {
                node->datatype = GS_TYPE_TIMESTAMP_TZ_FAKE;
                node->size = sizeof(timestamp_t);
            }

            node->precision = GS_DEFAULT_DATETIME_PRECISION;
            sql_add_first_exec_node(verf, node);
            break;

        case RES_WORD_LOCALTIMESTAMP:
            node->datatype = GS_TYPE_TIMESTAMP;
            node->size = sizeof(timestamp_t);
            node->precision = GS_DEFAULT_DATETIME_PRECISION;
            sql_add_first_exec_node(verf, node);
            break;

        case RES_WORD_UTCTIMESTAMP:
            node->datatype = GS_TYPE_DATE;
            node->size = sizeof(timestamp_t);
            sql_add_first_exec_node(verf, node);
            break;

        case RES_WORD_DEFAULT:
            if (verf->excl_flags & SQL_EXCL_DEFAULT) {
                GS_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "unexpected DEFAULT occurs");
                return GS_ERROR;
            }

            node->datatype = GS_TYPE_UNKNOWN;
            node->size = 0;
            break;

        case RES_WORD_NULL:
            if (node->owner->root->type == EXPR_NODE_NEGATIVE) {
                node->datatype = GS_TYPE_NUMBER;
            } else {
                node->datatype = GS_DATATYPE_OF_NULL;
            }

            node->size = GS_SIZE_OF_NULL;
            node->optmz_info.mode = OPTMZ_AS_CONST;
            break;

        case RES_WORD_TRUE:
        case RES_WORD_FALSE:
            node->datatype = GS_TYPE_BOOLEAN;
            node->size = sizeof(bool32);
            node->optmz_info.mode = OPTMZ_AS_CONST;
            break;

        case RES_WORD_DELETING:
        case RES_WORD_INSERTING:
        case RES_WORD_UPDATING:
        case RES_WORD_LEVEL:
        case RES_WORD_CONNECT_BY_ISLEAF:
        case RES_WORD_CONNECT_BY_ISCYCLE:
            status = GS_ERROR;
            break;

        case RES_WORD_USER:
            node->datatype = GS_TYPE_STRING;
            node->size = GS_NAME_BUFFER_SIZE;
            break;

        case RES_WORD_DATABASETZ:
            node->datatype = GS_TYPE_STRING;
            node->size = TIMEZONE_OFFSET_STRLEN;
            break;

        case RES_WORD_SESSIONTZ:
            node->datatype = GS_TYPE_STRING;
            node->size = TIMEZONE_OFFSET_STRLEN;
            break;
        case RES_WORD_COLUMN_VALUE:
            status = sql_verify_column_value(verf, node);
            break;

        default:
            break;
    }

    return status;
}

static inline status_t sql_verify_oper_node(sql_verifier_t *verf, expr_node_t *node)
{
    if (sql_verify_expr_node(verf, node->left) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (sql_verify_expr_node(verf, node->right) != GS_SUCCESS) {
        return GS_ERROR;
    }

    sql_infer_oper_optmz_mode(verf, node);

    return GS_SUCCESS;
}

static inline status_t sql_verify_unary_oper_node(sql_verifier_t *verf, expr_node_t *node)
{
    if (node->right == NULL) {
        GS_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "missing expression");
        return GS_ERROR;
    }

    if (sql_verify_expr_node(verf, node->right) != GS_SUCCESS) {
        return GS_ERROR;
    }

    sql_infer_unary_oper_optmz_mode(verf, node);

    return GS_SUCCESS;
}

static inline status_t sql_verify_prior_node(sql_verifier_t *verf, expr_node_t *node)
{
    if (verf->excl_flags & SQL_EXCL_PRIOR) {
        GS_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "'prior' operator not allowed here");
        return GS_ERROR;
    }

    if (verf->curr_query == NULL || verf->curr_query->connect_by_cond == NULL) {
        GS_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "If there is no 'connect by', 'prior' is not allowed");
        return GS_ERROR;
    }

    if (node->right == NULL) {
        GS_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "missing expression");
        return GS_ERROR;
    }

    uint32 saved_flags = verf->excl_flags;
    verf->excl_flags |= SQL_PRIOR_EXCL;
    if (sql_verify_expr_node(verf, node->right) != GS_SUCCESS) {
        return GS_ERROR;
    }
    verf->excl_flags = saved_flags;
    verf->curr_query->connect_by_prior = GS_TRUE;
    SQL_SET_OPTMZ_MODE(node, OPTMZ_NONE);

    node->typmod = node->right->typmod;
    return GS_SUCCESS;
}

static inline status_t sql_verify_cat(sql_verifier_t *verf, expr_node_t *node)
{
    uint32 concat_len;

    if (sql_verify_expr_node(verf, node->left) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (sql_verify_expr_node(verf, node->right) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (GS_IS_BLOB_TYPE(NODE_DATATYPE(node->left)) || GS_IS_BLOB_TYPE(NODE_DATATYPE(node->right))) {
        OPR_THROW_ERROR("||", NODE_DATATYPE(node->left), NODE_DATATYPE(node->right));
        return GS_ERROR;
    }

    if (GS_IS_CLOB_TYPE(NODE_DATATYPE(node->left)) || GS_IS_CLOB_TYPE(NODE_DATATYPE(node->right))) {
        node->datatype = GS_TYPE_CLOB;
    } else {
        node->datatype = GS_TYPE_STRING;
    }

    sql_infer_oper_optmz_mode(verf, node);

    concat_len = cm_get_datatype_strlen(node->left->datatype, node->left->size) +
                 cm_get_datatype_strlen(node->right->datatype, node->right->size);
    node->size = (uint16)MIN(concat_len, GS_MAX_STRING_LEN);
    node->typmod.is_char = node->left->typmod.is_char || node->right->typmod.is_char;

    if (NODE_IS_OPTMZ_CONST(node)) {
        if (node->size > SQL_MAX_OPTMZ_CONCAT_LEN) {
            sql_add_first_exec_node(verf, node);
        }
    } else if (NODE_IS_FIRST_EXECUTABLE(node)) {
        verf->context->fexec_vars_bytes += node->size;
    }

    return GS_SUCCESS;
}

static void sql_infer_neg_type(gs_type_t right_type, gs_type_t *result)
{
    switch (right_type) {
        case GS_TYPE_UINT32:
        case GS_TYPE_INTEGER:
        case GS_TYPE_BIGINT:
        case GS_TYPE_UINT64:
            *result = GS_TYPE_BIGINT;
            break;
        case GS_TYPE_REAL:
        case GS_TYPE_FLOAT:
            *result = GS_TYPE_REAL;
            break;

        case GS_TYPE_NUMBER:
        case GS_TYPE_DECIMAL:
        case GS_TYPE_CHAR:
        case GS_TYPE_VARCHAR:
        case GS_TYPE_STRING:
        case GS_TYPE_BINARY:
        case GS_TYPE_VARBINARY:
            *result = GS_TYPE_NUMBER;
            break;

        case GS_TYPE_NUMBER2:
            *result = GS_TYPE_NUMBER2;
            break;
        default:
            *result = right_type;
            break;
    }
    return;
}

static status_t sql_adjust_node_datatype(sql_verifier_t *verf, expr_node_t *node)
{
    if (node->type == EXPR_NODE_NEGATIVE) {
        sql_infer_neg_type(node->right->datatype, &node->datatype);
        node->typmod.is_array = node->right->typmod.is_array;
    } else {
        if (opr_infer_type((operator_type_t)node->type, node->left->datatype, node->right->datatype, &node->datatype) !=
            GS_SUCCESS) {
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

status_t sql_adjust_oper_node(sql_verifier_t *verf, expr_node_t *node)
{
    GS_RETURN_IFERR(sql_adjust_node_datatype(verf, node));
    switch (node->datatype) {
        case GS_TYPE_UINT32:
        case GS_TYPE_INTEGER:
        case GS_TYPE_BOOLEAN:
            node->size = sizeof(int32);
            break;
        case GS_TYPE_UINT64:
        case GS_TYPE_BIGINT:
        case GS_TYPE_REAL:
            node->size = sizeof(int64);
            break;
        case GS_TYPE_NUMBER:
        case GS_TYPE_DECIMAL:
        case GS_TYPE_NUMBER2:
            node->size = GS_MAX_DEC_OUTPUT_ALL_PREC;
            break;
        case GS_TYPE_DATE:
        case GS_TYPE_TIMESTAMP:
        case GS_TYPE_TIMESTAMP_TZ_FAKE:
        case GS_TYPE_TIMESTAMP_LTZ:
            node->size = sizeof(timestamp_t);
            node->precision = GS_MAX_DATETIME_PRECISION;
            break;

        case GS_TYPE_TIMESTAMP_TZ:
            node->size = sizeof(timestamp_tz_t);
            node->precision = GS_MAX_DATETIME_PRECISION;
            break;

        case GS_TYPE_INTERVAL_DS:
            node->size = sizeof(interval_ds_t);
            node->typmod.day_prec = ITVL_MAX_DAY_PREC;
            node->typmod.frac_prec = ITVL_MAX_SECOND_PREC;
            break;

        case GS_TYPE_INTERVAL_YM:
            node->size = sizeof(interval_ym_t);
            node->typmod.year_prec = ITVL_MAX_YEAR_PREC;
            break;

        case GS_TYPE_BINARY:
        case GS_TYPE_VARBINARY:
        case GS_TYPE_CHAR:
        case GS_TYPE_VARCHAR:
        case GS_TYPE_STRING:
        case GS_TYPE_UNKNOWN:
            break;
        default:
            GS_THROW_ERROR(ERR_CONVERT_TYPE, get_datatype_name_str((int32)node->datatype), "NUMERIC");
            return GS_ERROR;
    }

    return GS_SUCCESS;
}

static inline status_t sql_verify_unary(sql_verifier_t *verf, expr_node_t *node)
{
    if (node->type != EXPR_NODE_NEGATIVE) {
        return GS_SUCCESS;
    }

    if (GS_IS_UNSIGNED_INTEGER_TYPE(node->datatype)) {
        node->datatype = GS_TYPE_BIGINT;
        return GS_SUCCESS;
    }
    if (GS_IS_NUMERIC_TYPE(node->datatype) || GS_IS_UNKNOWN_TYPE(node->datatype)) {
        return GS_SUCCESS;
    }

    if (GS_IS_STRING_TYPE(node->datatype) || GS_IS_BINARY_TYPE(node->datatype)) {
        node->datatype = GS_TYPE_NUMBER;
        node->precision = GS_UNSPECIFIED_NUM_PREC; /* *< 0 stands for precision is not defined when create table */
        node->scale = GS_UNSPECIFIED_NUM_SCALE;
        node->size = MAX_DEC_BYTE_SZ;
        return GS_SUCCESS;
    }

    GS_SRC_THROW_ERROR(node->loc, ERR_TYPE_MISMATCH, "NUMERIC", get_datatype_name_str((int32)(node->datatype)));
    return GS_ERROR;
}

static inline status_t sql_verify_column_nodetype(sql_verifier_t *verf, expr_node_t *node)
{
    if ((verf->excl_flags & SQL_EXCL_ARRAY) && node->typmod.is_array == GS_TRUE) {
        GS_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "unexpected array expression");
        return GS_ERROR;
    }
    if ((verf->excl_flags & SQL_EXCL_COLUMN) &&
        (node->type == EXPR_NODE_COLUMN || node->type == EXPR_NODE_DIRECT_COLUMN)) {
        GS_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "unexpected column expression");
        return GS_ERROR;
    }
    if ((verf->excl_flags & SQL_EXCL_AGGR) && node->type == EXPR_NODE_AGGR) {
        GS_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "unexpected aggr expression");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t sql_verify_expr_node_core(sql_verifier_t *verf, expr_node_t *node)
{
    status_t status;
    CM_POINTER2(node, verf);
    cm_reset_error_loc();

    switch (node->type) {
        case EXPR_NODE_CONST:
            node->datatype = node->value.type;
            node->size = (uint16)var_get_size(&node->value);
            node->optmz_info.mode = OPTMZ_AS_CONST;
            if (GS_IS_STRING_TYPE(node->datatype)) {
                node->typmod.is_char = GS_FALSE;
            }
            return GS_SUCCESS;

        case EXPR_NODE_PARAM:
            if ((verf->excl_flags & SQL_EXCL_BIND_PARAM) != 0) {
                GS_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "unexpected param occurs");
                return GS_ERROR;
            }

            // if parameter exists in condition, then need bind peeking
            if (verf->incl_flags & SQL_INCL_COND_COL) {
                verf->stmt->context->need_vpeek = GS_TRUE;
            }

            node->optmz_info.mode = OPTMZ_AS_PARAM;
            knl_panic(verf->stmt->pl_compiler == NULL);
            knl_panic(!verf->stmt->cursor_info.reverify_in_fetch);
            node->datatype = GS_TYPE_UNKNOWN;
            return GS_SUCCESS;

        case EXPR_NODE_RESERVED:
            if (node->value.v_res.namable) {
                cm_set_ignore_log(GS_TRUE);
                if (sql_verify_column_expr(verf, node) == GS_SUCCESS) {
                    node->type = EXPR_NODE_COLUMN;
                    cm_set_ignore_log(GS_FALSE);
                    return GS_SUCCESS;
                }
                cm_set_ignore_log(GS_FALSE);
                cm_reset_error();
                node->value.type = GS_TYPE_INTEGER;
            }
            return sql_verify_reserved_value(verf, node);

        case EXPR_NODE_COLUMN:
        case EXPR_NODE_DIRECT_COLUMN:
            GS_RETURN_IFERR(sql_verify_column_expr(verf, node));
            status = sql_verify_column_nodetype(verf, node);
            break;

        case EXPR_NODE_CASE:
            return GS_ERROR;

        case EXPR_NODE_JOIN:
            GS_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "join not supported.");
            return GS_ERROR;

        case EXPR_NODE_SELECT:
            GS_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "nested select not supported.");
            return GS_ERROR;

        case EXPR_NODE_CAT:
            status = sql_verify_cat(verf, node);
            break;

        /* The following case branches are used to compute constant expressions. */
        case EXPR_NODE_ADD:
        case EXPR_NODE_SUB:
        case EXPR_NODE_MUL:
        case EXPR_NODE_DIV:
        case EXPR_NODE_MOD: {
            GS_RETURN_IFERR(sql_verify_oper_node(verf, node));
            status = sql_adjust_oper_node(verf, node);
            break;
        }
        case EXPR_NODE_NEGATIVE: {
            GS_RETURN_IFERR(sql_verify_unary_oper_node(verf, node));
            status = sql_adjust_oper_node(verf, node);
            break;
        }
        case EXPR_NODE_PRIOR: {
            status = sql_verify_prior_node(verf, node);
            break;
        }
        case EXPR_NODE_BITAND:
        case EXPR_NODE_BITOR:
        case EXPR_NODE_BITXOR:
        case EXPR_NODE_LSHIFT:
        case EXPR_NODE_RSHIFT:
            GS_RETURN_IFERR(sql_verify_oper_node(verf, node));
            node->datatype = GS_TYPE_BIGINT;
            node->size = sizeof(int64);
            status = GS_SUCCESS;
            break;

        case EXPR_NODE_FUNC:
        case EXPR_NODE_PROC:
        case EXPR_NODE_USER_FUNC:
        case EXPR_NODE_USER_PROC:
            GS_RETURN_IFERR(sql_verify_func(verf, node));
            status = sql_add_ref_func_node(verf, node);
            break;

        case EXPR_NODE_STAR:
        case EXPR_NODE_AGGR:
        case EXPR_NODE_GROUP:
        case EXPR_NODE_V_ADDR:
        case EXPR_NODE_V_METHOD:
        case EXPR_NODE_V_CONSTRUCT:
        case EXPR_NODE_PL_ATTR:
        case EXPR_NODE_OVER:
        case EXPR_NODE_ARRAY:
        case EXPR_NODE_CSR_PARAM:
        default:
            knl_panic(0);
            GS_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "unknown expr node type");
            return GS_ERROR;
    }

    if (status != GS_SUCCESS) {
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t sql_verify_expr_node(sql_verifier_t *verf, expr_node_t *node)
{
    if (node->has_verified) {
        return GS_SUCCESS;
    }
    GS_RETURN_IFERR(sql_stack_safe(verf->stmt));

    GS_RETURN_IFERR(sql_verify_expr_node_core(verf, node));

    return sql_verify_unary(verf, node);
}

status_t sql_verify_current_expr(sql_verifier_t *verf, expr_tree_t *verf_expr)
{
    if (sql_verify_expr_node(verf, verf_expr->root) != GS_SUCCESS) {
        cm_try_set_error_loc(verf_expr->root->loc);
        return GS_ERROR;
    }

    if ((GS_IS_LOB_TYPE(verf_expr->root->datatype)) && ((verf->excl_flags & SQL_EXCL_LOB_COL) != 0)) {
        GS_SRC_THROW_ERROR(verf_expr->loc, ERR_SQL_SYNTAX_ERROR, "unexpected lob column occurs");
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t sql_verify_expr(sql_verifier_t *verf, expr_tree_t *expr)
{
    expr_tree_t *verf_expr = expr;

    // The expr_tree may be a expr tree list
    while (verf_expr != NULL) {
        GS_RETURN_IFERR(sql_verify_current_expr(verf, verf_expr));
        verf_expr = verf_expr->next;
    }

    return GS_SUCCESS;
}

status_t sql_try_verify_dbmsconst(sql_verifier_t *verf, expr_node_t *node, bool32 *result)
{
    *result = GS_FALSE;

    return GS_SUCCESS;
}

status_t sql_try_verify_rowid(sql_verifier_t *verf, expr_node_t *node, bool32 *result)
{
    column_word_t *col = &node->word.column;
    *result = GS_FALSE;

    if (!cm_text_equal((text_t *)&col->name, &g_rowid)) {
        return GS_SUCCESS;
    }
    GS_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "'rowid' not supported.");
    return GS_ERROR;
}

status_t sql_try_verify_rowscn(sql_verifier_t *verf, expr_node_t *node, bool32 *result)
{
    column_word_t *col = &node->word.column;
    *result = GS_FALSE;

    if (!cm_text_equal((text_t *)&col->name, &g_rowscn)) {
        return GS_SUCCESS;
    }
    GS_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "'rowscn' not supported.");
    return GS_ERROR;
}

status_t sql_try_verify_rownodeid(sql_verifier_t *verf, expr_node_t *node, bool32 *result)
{
    column_word_t *col = &node->word.column;
    *result = GS_FALSE;

    if (!cm_text_equal((text_t *)&col->name, &g_rownodeid)) {
        return GS_SUCCESS;
    }

    GS_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "'rownodeid' not supported.");
    return GS_ERROR;
}

static status_t sql_verify_select_rs_columns(sql_verifier_t *verf, sql_query_t *query)
{
    if (query->owner->type == SELECT_AS_RESULT) {
        if (verf->context->rs_columns == NULL) {
            verf->context->rs_columns = query->rs_columns;
        }
    }

    if (query->owner->rs_columns == NULL) {
        query->owner->rs_columns = query->rs_columns;
        return GS_SUCCESS;
    }

    GS_SRC_THROW_ERROR(query->loc, ERR_SQL_SYNTAX_ERROR, "query block unsupported.");
    return GS_ERROR;
}

static status_t sql_verify_query(sql_verifier_t *verf, sql_query_t *query)
{
    CM_POINTER2(verf, query);

    query->for_update = verf->for_update;
    query->owner = verf->select_ctx;
    SET_NODE_STACK_CURR_QUERY(verf->stmt, query);

    GS_RETURN_IFERR(sql_verify_tables(verf, query));

    GS_RETURN_IFERR(sql_verify_query_columns(verf, query));

    GS_RETURN_IFERR(sql_verify_query_where(verf, query));

    GS_RETURN_IFERR(sql_verify_select_rs_columns(verf, query));

    SQL_RESTORE_NODE_STACK(verf->stmt);
    return GS_SUCCESS;
}

static status_t sql_verify_select_node(sql_verifier_t *verf, select_node_t *node)
{
    GS_RETURN_IFERR(sql_stack_safe(verf->stmt));

    switch (node->type) {
        case SELECT_NODE_QUERY:
            return sql_verify_query(verf, node->query);

        case SELECT_NODE_UNION:
            if (verf->has_union) {
                node->type = SELECT_NODE_UNION_ALL;
            } else {
                verf->has_union = GS_TRUE;
            }

            GS_RETURN_IFERR(sql_verify_select_node(verf, node->left));
            GS_RETURN_IFERR(sql_verify_select_node(verf, node->right));

            if (node->type == SELECT_NODE_UNION) {
                verf->has_union = GS_FALSE;
            }

            return GS_SUCCESS;

        case SELECT_NODE_UNION_ALL:
            GS_RETURN_IFERR(sql_verify_select_node(verf, node->left));
            return sql_verify_select_node(verf, node->right);

        case SELECT_NODE_MINUS:
        case SELECT_NODE_EXCEPT:
            verf->has_minus = GS_TRUE;
            GS_RETURN_IFERR(sql_verify_select_node(verf, node->left));
            GS_RETURN_IFERR(sql_verify_select_node(verf, node->right));
            verf->has_minus = GS_FALSE;
            return GS_SUCCESS;
        case SELECT_NODE_INTERSECT:
        case SELECT_NODE_INTERSECT_ALL:
        case SELECT_NODE_EXCEPT_ALL:
            verf->has_except_intersect = GS_TRUE;
            GS_RETURN_IFERR(sql_verify_select_node(verf, node->left));
            GS_RETURN_IFERR(sql_verify_select_node(verf, node->right));
            verf->has_except_intersect = GS_FALSE;
            return GS_SUCCESS;
        default:
            GS_THROW_ERROR(ERR_UNSUPPORT_OPER_TYPE, "set", node->type);
            return GS_ERROR;
    }
}

static void sql_set_query_rs_datatype(galist_t *select_rs_cols, select_node_t *node)
{
    uint32 i;
    rs_column_t *select_rs_col = NULL;
    rs_column_t *query_rs_col = NULL;

    switch (node->type) {
        case SELECT_NODE_QUERY: {
            if (select_rs_cols == node->query->rs_columns) {
                return;
            }
            for (i = 0; i < select_rs_cols->count; ++i) {
                select_rs_col = (rs_column_t *)cm_galist_get(select_rs_cols, i);
                query_rs_col = (rs_column_t *)cm_galist_get(node->query->rs_columns, i);
                query_rs_col->typmod = select_rs_col->typmod;
                if (select_rs_col->type == RS_COL_CALC && select_rs_col->expr != NULL &&
                    select_rs_col->expr->root->type == EXPR_NODE_ARRAY) {
                    select_rs_col->expr->root->datatype = select_rs_col->datatype;
                    query_rs_col->expr->root->datatype = select_rs_col->datatype;
                }
            }
            return;
        }

        default:
            sql_set_query_rs_datatype(select_rs_cols, node->left);
            sql_set_query_rs_datatype(select_rs_cols, node->right);
            return;
    }
}

static void sql_record_pending_column(sql_select_t *select_ctx)
{
    rs_column_t *rs_column = NULL;
    uint32 i;

    select_ctx->pending_col_count = 0;

    for (i = 0; i < select_ctx->rs_columns->count; ++i) {
        rs_column = (rs_column_t *)cm_galist_get(select_ctx->rs_columns, i);
        if (rs_column->datatype == GS_TYPE_UNKNOWN) {
            select_ctx->pending_col_count++;
        }
    }
}

static inline void sql_try_optmz_select_type(sql_verifier_t *verf, sql_select_t *select_ctx)
{
    sql_query_t *query = NULL;

    if (select_ctx->type != SELECT_AS_LIST) {
        return;
    }
    if (select_ctx->root->type != SELECT_NODE_QUERY) {
        return;
    }
    query = select_ctx->first_query;

    // ignore group or winsort
    if (query->group_sets->count != 0 || query->winsort_list->count != 0) {
        return;
    }

    // make sure the result is only one
    if (query->aggrs->count == 1 && query->rs_columns->count == 1) {
        select_ctx->type = SELECT_AS_VARIANT;
    }
}

status_t sql_verify_select_context(sql_verifier_t *verf, sql_select_t *select_ctx)
{
    verf->select_ctx = select_ctx;

    if (select_ctx->withass != NULL) {
        return GS_ERROR;
    }

    GS_RETURN_IFERR(sql_verify_select_node(verf, select_ctx->root));

    sql_set_query_rs_datatype(select_ctx->rs_columns, select_ctx->root);
    sql_record_pending_column(select_ctx);
    sql_try_optmz_select_type(verf, select_ctx);

    return GS_SUCCESS;
}

status_t sql_verify_select(sql_stmt_t *stmt, sql_select_t *select_ctx)
{
    sql_verifier_t verf = { 0 };

    verf.stmt = stmt;
    verf.context = stmt->context;
    verf.select_ctx = select_ctx;
    verf.pl_dc_lst = select_ctx->pl_dc_lst;
    verf.for_update = select_ctx->for_update;
    verf.excl_flags = SQL_EXCL_DEFAULT;
    verf.do_expr_optmz = GS_TRUE;
    verf.parent = NULL;
    knl_panic(stmt->pl_compiler == NULL);

    GS_RETURN_IFERR(sql_verify_select_context(&verf, select_ctx));
    if ((verf.has_ddm_col == GS_TRUE) && (stmt->context->type == SQL_TYPE_CREATE_TABLE)) {
        GS_THROW_ERROR(ERR_INVALID_OPERATION, ", the command references a redacted object");
        return GS_ERROR;
    }
    return GS_SUCCESS;
}
static status_t inline sql_adjust_func_node(sql_stmt_t *stmt, expr_node_t *node)
{
    node->type = EXPR_NODE_FUNC;
    if (!CM_IS_EMPTY(&node->word.column.user)) {
        node->word.func.user = node->word.column.user;
        node->word.func.pack = node->word.column.table;
        node->word.func.name = node->word.column.name;
        node->word.func.count = 3;
    } else {
        node->word.func.org_user = node->word.column.table;
        node->word.func.user = node->word.column.user_ex;
        node->word.func.pack.value = CM_NULL_TEXT;
        node->word.func.name = node->word.column.name;
        if (CM_IS_EMPTY(&node->word.func.user)) {
            node->word.func.count = 1;
        } else {
            node->word.func.count = 2;
        }
    }
    node->word.func.user_func_first = GS_TRUE;
    node->word.func.args.value = CM_NULL_TEXT;

    if (cm_text_str_equal_ins(&node->word.func.user.value, SYS_USER_NAME)) {
        return sql_check_user_tenant(KNL_SESSION(stmt));
    }

    return GS_SUCCESS;
}

static status_t sql_try_verify_func1(sql_verifier_t *verf, expr_node_t *node, var_udo_t *obj, bool32 *is_found)
{
    status_t status = pl_try_verify_builtin_func(verf, node, obj, is_found);
    if (*is_found) {
        return status;
    }

    pl_revert_last_error(status);

    return GS_SUCCESS;
}

status_t pl_check_same_arg_name(expr_node_t *func)
{
    expr_tree_t *arg1 = NULL;
    expr_tree_t *arg2 = NULL;
    for (arg1 = func->argument; arg1 != NULL; arg1 = arg1->next) {
        GS_CONTINUE_IFTRUE(arg1->arg_name.len == 0);
        for (arg2 = arg1->next; arg2 != NULL; arg2 = arg2->next) {
            GS_CONTINUE_IFTRUE(arg2->arg_name.len == 0);
            if (cm_compare_text(&arg1->arg_name, &arg2->arg_name) == 0) {
                GS_SRC_THROW_ERROR(arg1->loc, ERR_PL_DUP_ARG_FMT, T2S(&arg1->arg_name),
                                   T2S_EX(&func->word.func.name.value));
                return GS_ERROR;
            }
        }
    }

    return GS_SUCCESS;
}

static status_t sql_try_verify_func(sql_verifier_t *verf, expr_node_t *node, bool32 *is_found)
{
    var_udo_t obj;
    char user[GS_NAME_BUFFER_SIZE];
    char pack[GS_NAME_BUFFER_SIZE];
    char name[GS_NAME_BUFFER_SIZE];

    sql_init_udo_with_str(&obj, user, pack, name);
    GS_RETURN_IFERR(pl_check_same_arg_name(node));
    if (node->word.func.count == 1 || node->word.func.count == 0) {
        return sql_try_verify_func1(verf, node, &obj, is_found);
    } else {
        knl_panic(0);
    }
    return GS_ERROR;
}

status_t sql_verify_func(sql_verifier_t *verf, expr_node_t *node)
{
    bool32 is_found = GS_FALSE;
    verf->excl_flags |= SQL_EXCL_METH_PROC;
    uint32 save_excl_flags = verf->excl_flags;
    verf->excl_flags &= (~SQL_EXCL_ARRAY);
    status_t status = sql_try_verify_func(verf, node, &is_found);
    verf->excl_flags = save_excl_flags;
    GS_RETURN_IFERR(status);
    if (!is_found) {
        return GS_ERROR;
    }
    if ((node->type == EXPR_NODE_PROC || node->type == EXPR_NODE_USER_PROC) && (verf->excl_flags & SQL_EXCL_PL_PROC)) {
        GS_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "procedure is not allowed here.");
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t sql_try_verify_noarg_func(sql_verifier_t *verf, expr_node_t *node, bool32 *is_found)
{
    if (node->type == EXPR_NODE_RESERVED) {
        return GS_FALSE;
    }

    expr_node_t node_bak = *node;
    if (sql_adjust_func_node(verf->stmt, node) != GS_SUCCESS) {
        *node = node_bak;
        return GS_ERROR;
    }

    status_t status = sql_try_verify_func(verf, node, is_found);
    GS_RETURN_IFERR(status);
    if (!(*is_found)) {
        *node = node_bak;
    }
    return GS_SUCCESS;
}

/* * Merge the current first executable node as the sub-node of the new_idx */
static inline void sql_merge_first_exec_node(sql_verifier_t *verf, expr_node_t *node, uint32 new_idx)
{
    SQL_SET_OPTMZ_MODE(node, OPTMZ_FIRST_EXEC_NODE);
    if (new_idx != NODE_OPTMZ_IDX(node)) {
        --(verf->context->fexec_vars_cnt);
        node->optmz_info.idx = (uint16)new_idx;
    }

    // If the merged node is var-length datatype, its memory should be reduced
    if (GS_IS_VARLEN_TYPE(node->datatype)) {
        verf->context->fexec_vars_bytes -= node->size;
    }
}

static inline status_t sql_scan_func_args_optmz_mode(expr_node_t *func, expr_tree_t *expr,
                                                     expr_optmz_info_t *func_optmz_info)
{
    while (expr != NULL) {
        if (func_optmz_info->mode > NODE_OPTMZ_MODE(expr->root)) {
            func_optmz_info->mode = NODE_OPTMZ_MODE(expr->root);
            switch (func_optmz_info->mode) {
                case OPTMZ_NONE:
                    // if one of the argument can not be optimized,
                    // then the function also can not be optimized
                    SQL_SET_OPTMZ_MODE(func, OPTMZ_NONE);
                    return GS_ERROR;
                case OPTMZ_FIRST_EXEC_ROOT:
                    func_optmz_info->idx = MIN(func_optmz_info->idx, NODE_OPTMZ_IDX(expr->root));
                    break;
                case OPTMZ_AS_CONST:
                case OPTMZ_AS_PARAM:
                    break;
                default:
                    CM_NEVER;
                    break;
            }
        }

        expr = expr->next;
    }

    return GS_SUCCESS;
}

/* * scan the func's arguments, and decide the optmz mode */
void sql_infer_func_optmz_mode(sql_verifier_t *verf, expr_node_t *func)
{
    // Step 1: scan all modes of arguments
    expr_tree_t *expr = func->argument;
    if (expr == NULL) {
        return;
    }

    expr_optmz_info_t func_optmz_info = { .mode = OPTMZ_INVAILD, .idx = GS_INVALID_ID16 };

    GS_RETVOID_IFERR(sql_scan_func_args_optmz_mode(func, expr, &func_optmz_info));

    // Step 2: decide the optmz mode
    // if all arguments are constant, the function can be constantly optimized.
    if (func_optmz_info.mode == OPTMZ_AS_CONST) {
        SQL_SET_OPTMZ_MODE(func, OPTMZ_AS_CONST);
        return;
    }

    // if all arguments are params or params and constants
    // the function can be computed in advance on the first execution
    if (func_optmz_info.mode == OPTMZ_AS_PARAM) {
        sql_add_first_exec_node(verf, func);
        return;
    }

    if (func_optmz_info.idx == GS_INVALID_ID16) {
        GS_THROW_ERROR_EX(ERR_ASSERT_ERROR, "idx(%u) != GS_INVALID_ID16(%u)", (uint32)func_optmz_info.idx,
                          (uint32)GS_INVALID_ID16);
    }
    if (func_optmz_info.mode != OPTMZ_FIRST_EXEC_ROOT) {
        GS_THROW_ERROR_EX(ERR_ASSERT_ERROR, "mode(%u) == OPTMZ_FIRST_EXEC_ROOT(%u)", (uint32)func_optmz_info.mode,
                          (uint32)OPTMZ_FIRST_EXEC_ROOT);
    }

    func->optmz_info.mode = OPTMZ_FIRST_EXEC_ROOT;
    func->optmz_info.idx = func_optmz_info.idx;
    expr = func->argument;
    while (expr != NULL) {
        if (NODE_IS_FIRST_EXECUTABLE(expr->root)) {
            sql_merge_first_exec_node(verf, expr->root, func_optmz_info.idx);
        }
        expr = expr->next;
    }

    if (GS_IS_VARLEN_TYPE(func->datatype)) {
        verf->context->fexec_vars_bytes += func->size;
    }
}

/* * decide the optmz mode of a binary operator node, such as +, - *, /. */
void sql_infer_oper_optmz_mode(sql_verifier_t *verf, expr_node_t *node)
{
    // Step 1: scan all modes of arguments
    optmz_mode_t mode = MIN(NODE_OPTMZ_MODE(node->left), NODE_OPTMZ_MODE(node->right));
    uint32 idx = GS_INVALID_ID16;

    if (mode == OPTMZ_NONE || mode == OPTMZ_AS_CONST || mode == OPTMZ_AS_PARAM) {
        SQL_SET_OPTMZ_MODE(node, mode);
        return;
    }

    if (mode != OPTMZ_FIRST_EXEC_ROOT) {
        GS_THROW_ERROR_EX(ERR_ASSERT_ERROR, "mode(%u) == OPTMZ_FIRST_EXEC_ROOT(%u)", (uint32)mode,
                          (uint32)OPTMZ_FIRST_EXEC_ROOT);
    }

    if (NODE_IS_FIRST_EXECUTABLE(node->left)) {
        idx = NODE_OPTMZ_IDX(node->left);
    }
    if (NODE_IS_FIRST_EXECUTABLE(node->right)) {
        idx = MIN(idx, NODE_OPTMZ_IDX(node->right));
    }

    node->optmz_info.mode = OPTMZ_FIRST_EXEC_ROOT;
    node->optmz_info.idx = (uint16)idx;

    if (NODE_IS_FIRST_EXECUTABLE(node->left)) {
        sql_merge_first_exec_node(verf, node->left, idx);
    }

    if (NODE_IS_FIRST_EXECUTABLE(node->right)) {
        sql_merge_first_exec_node(verf, node->right, idx);
    }
}

/* * decide the optmz mode of a unary operator node, such as +, - */
void sql_infer_unary_oper_optmz_mode(sql_verifier_t *verf, expr_node_t *node)
{
    // Step 1: scan all modes of arguments
    optmz_mode_t mode = NODE_OPTMZ_MODE(node->right);
    uint32 idx = GS_INVALID_ID16;

    if (mode == OPTMZ_NONE || mode == OPTMZ_AS_CONST || mode == OPTMZ_AS_PARAM) {
        SQL_SET_OPTMZ_MODE(node, mode);
        return;
    }

    if (mode != OPTMZ_FIRST_EXEC_ROOT) {
        GS_THROW_ERROR_EX(ERR_ASSERT_ERROR, "mode(%u) == OPTMZ_FIRST_EXEC_ROOT(%u)", (uint32)mode,
                          (uint32)OPTMZ_FIRST_EXEC_ROOT);
    }

    if (NODE_IS_FIRST_EXECUTABLE(node->right)) {
        idx = MIN(idx, NODE_OPTMZ_IDX(node->right));
    }

    node->optmz_info.mode = OPTMZ_FIRST_EXEC_ROOT;
    node->optmz_info.idx = (uint16)idx;

    if (NODE_IS_FIRST_EXECUTABLE(node->right)) {
        sql_merge_first_exec_node(verf, node->right, idx);
    }
}

/* * add an expr node that can be evaluated at first execution */
/* author Added 2018/10/09 */
void sql_add_first_exec_node(sql_verifier_t *verf, expr_node_t *node)
{
    while (verf->do_expr_optmz) {
        // too much first executable variants
        if (verf->context->fexec_vars_cnt >= SQL_MAX_FEXEC_VARS) {
            break;
        }

        // do not optimize LOB node
        if (GS_IS_LOB_TYPE(node->datatype)) {
            break;
        }

        if (GS_IS_VARLEN_TYPE(node->datatype)) {
            // if the first executable is insufficient
            if (verf->context->fexec_vars_bytes + node->size >= SQL_MAX_FEXEC_VAR_BYTES) {
                break;
            }
            verf->context->fexec_vars_bytes += node->size;
        }

        node->optmz_info.idx = verf->context->fexec_vars_cnt++;
        node->optmz_info.mode = OPTMZ_FIRST_EXEC_ROOT;
        return;
    }

    SQL_SET_OPTMZ_MODE(node, OPTMZ_NONE);
}

status_t sql_add_sequence_node(sql_stmt_t *stmt, expr_node_t *node)
{
    sql_seq_t *item = NULL;
    expr_node_t *seq_node = NULL;

        if (node->type == EXPR_NODE_SEQUENCE) {
            seq_node = node;
        } else if (node->type == EXPR_NODE_FUNC) {
            seq_node = node->argument->root;
        } else {
            seq_node = NULL;
        }

        if (seq_node == NULL || seq_node->type != EXPR_NODE_SEQUENCE) {
            return GS_SUCCESS;
        }

        knl_panic (stmt->pl_context == NULL);

        if (stmt->context->sequences == NULL) {
            GS_RETURN_IFERR(sql_create_list(stmt, &stmt->context->sequences));
        }

        for (uint32 i = 0; i < stmt->context->sequences->count; ++i) {
            item = (sql_seq_t *)cm_galist_get(stmt->context->sequences, i);
            item->seq.mode = seq_node->value.v_seq.mode;
            if (var_seq_equal(&seq_node->value.v_seq, &item->seq)) {
                    item->flags |= (uint32)seq_node->value.v_seq.mode;
                    break;
                }
            item = NULL;
        }

        if (item == NULL) {
            GS_RETURN_IFERR(cm_galist_new(stmt->context->sequences, sizeof(sql_seq_t), (void **)&item));
            item->seq = seq_node->value.v_seq;
            item->flags = seq_node->value.v_seq.mode;
            item->processed = GS_FALSE;
            item->value = 0;
        }
    return GS_SUCCESS;
}

bool32 sql_search_table_name(sql_table_t *query_table, text_t *user, text_t *alias)
{
    if (user->len > 0 && !cm_text_equal(&query_table->user.value, user)) {
        return GS_FALSE;
    }

    if (query_table->alias.value.len > 0 && !query_table->alias.implicit) {
        return cm_text_equal(&query_table->alias.value, alias);
    }

    return cm_text_equal(&query_table->name.value, alias);
}

static status_t sql_search_table_in_table(sql_table_t *src_table, text_t *user, text_t *alias, sql_table_t **table,
                                          bool32 *is_found)
{
    if (sql_search_table_name(src_table, user, alias)) {
        *table = src_table;
        *is_found = GS_TRUE;
    }
    return GS_SUCCESS;
}

static status_t sql_search_table_in_table_list(sql_array_t *tables, expr_node_t *node, text_t *user, text_t *alias,
                                               sql_table_t **table, bool32 *is_found)
{
    for (uint32 i = 0; i < tables->count; i++) {
        sql_table_t *tmp_table = (sql_table_t *)sql_array_get(tables, i);

        if (sql_search_table_name(tmp_table, user, alias)) {
            if (*is_found) {
                GS_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "column ambiguously defined");
                return GS_ERROR;
            }
            *is_found = GS_TRUE;
            *table = tmp_table;
        }
    }
    return GS_SUCCESS;
}

status_t sql_search_table_local(sql_verifier_t *verf, expr_node_t *node, text_t *user, text_t *alias,
                                sql_table_t **table, bool32 *is_found)
{
    if (verf->tables == NULL) {  // for non select
        if (verf->table == NULL) {
            GS_SRC_THROW_ERROR_EX(node->loc, ERR_SQL_SYNTAX_ERROR, "invalid table alias '%s'", T2S(alias));
            return GS_ERROR;
        }
        GS_RETURN_IFERR(sql_search_table_in_table(verf->table, user, alias, table, is_found));
    } else {
        GS_RETURN_IFERR(sql_search_table_in_table_list(verf->tables, node, user, alias, table, is_found));
    }

    if (*is_found) {
        if (verf->join_tab_id == GS_INVALID_ID32) {
            verf->join_tab_id = (*table)->id;
        } else if (verf->join_tab_id != (*table)->id) {
            verf->same_join_tab = GS_FALSE;
        }
    }

    return GS_SUCCESS;
}
status_t sql_search_table(sql_verifier_t *verf, expr_node_t *node, text_t *user, text_t *alias, sql_table_t **table,
                          uint32 *level)
{
    bool32 is_found = GS_FALSE;

    GS_RETURN_IFERR(sql_search_table_local(verf, node, user, alias, table, &is_found));
    if (!is_found) {
        GS_SRC_THROW_ERROR_EX(node->loc, ERR_SQL_SYNTAX_ERROR, "invalid table alias '%s'", T2S(alias));
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t sql_table_cache_query_field_impl(sql_stmt_t *stmt, sql_table_t *table, query_field_t *src_query_field,
                                          bool8 is_cond_col)
{
    query_field_t *query_field = NULL;
    query_field_t *new_field = NULL;
    bilist_node_t *node = cm_bilist_head(&table->query_fields);

    for (; node != NULL; node = BINODE_NEXT(node)) {
        query_field = BILIST_NODE_OF(query_field_t, node, bilist_node);
        if (src_query_field->col_id < query_field->col_id) {
            break;
        }
        if (src_query_field->col_id == query_field->col_id) {
            if (is_cond_col) {
                query_field->is_cond_col = is_cond_col;
            }
            query_field->ref_count++;
            return GS_SUCCESS;
        }
    }
    GS_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(query_field_t), (void **)&new_field));
    new_field->col_id = src_query_field->col_id;
    new_field->datatype = src_query_field->datatype;
    new_field->is_array = src_query_field->is_array;
    new_field->start = src_query_field->start;
    new_field->end = src_query_field->end;
    new_field->is_cond_col = is_cond_col;
    new_field->ref_count = 1;

    if (node == NULL) {
        cm_bilist_add_tail(&new_field->bilist_node, &table->query_fields);
    } else {
        cm_bilist_add_prev(&new_field->bilist_node, node, &table->query_fields);
    }
    return GS_SUCCESS;
}

status_t sql_table_cache_query_field(sql_stmt_t *stmt, sql_table_t *table, query_field_t *src_query_field)
{
    return sql_table_cache_query_field_impl(stmt, table, src_query_field, GS_FALSE);
}

status_t sql_table_cache_cond_query_field(sql_stmt_t *stmt, sql_table_t *table, query_field_t *src_query_field)
{
    return sql_table_cache_query_field_impl(stmt, table, src_query_field, GS_TRUE);
}

status_t sql_init_normal_query_table(sql_stmt_t *stmt, sql_table_t *sql_table, sql_query_t *parent_query)
{
    if (sql_create_project_columns(stmt, sql_table) != GS_SUCCESS) {
        return GS_ERROR;
    }

    GS_RETURN_IFERR(sql_apend_dependency_table(stmt, sql_table));
    if (sql_table->entry->dc.type == DICT_TYPE_VIEW) {
        knl_panic(0);
    }
    return GS_SUCCESS;
}

static status_t sql_get_table_dc(sql_stmt_t *stmt, sql_table_t *sql_table)
{
    knl_handle_t knl_session = &stmt->session->knl_session;
    knl_dictionary_t dc;

    knl_set_session_scn(knl_session, GS_INVALID_ID64);

    if (knl_open_dc_with_public(knl_session, &sql_table->user.value, sql_table->user.implicit, &sql_table->name.value,
                                &dc) != GS_SUCCESS) {
        cm_set_error_loc(sql_table->user.loc);
        return GS_ERROR;
    }

    sql_table->entry->dc = dc;
    return GS_SUCCESS;
}

status_t sql_init_table_dc(sql_stmt_t *stmt, sql_table_t *sql_table)
{
    // normal table no need to reload entry except dblink table
    if (sql_table->entry->dc.type != DICT_TYPE_UNKNOWN && sql_table->dblink.len == 0) {
        return GS_SUCCESS;
    }

    GS_RETURN_IFERR(sql_get_table_dc(stmt, sql_table));

    return GS_SUCCESS;
}

status_t sql_init_normal_table_dc(sql_stmt_t *stmt, sql_table_t *sql_table, sql_query_t *parent_query)
{
    if (sql_table->type == SUBSELECT_AS_TABLE || sql_table->type == WITH_AS_TABLE || sql_table->type == FUNC_AS_TABLE ||
        sql_table->type == JSON_TABLE) {
        return GS_SUCCESS;
    }
    GS_RETURN_IFERR(sql_init_table_dc(stmt, sql_table));
    GS_RETURN_IFERR(sql_init_normal_query_table(stmt, sql_table, parent_query));
    return GS_SUCCESS;
}

status_t sql_verify_tables(sql_verifier_t *verf, sql_query_t *query)
{
    sql_array_t *tables = &query->tables;

    verf->tables = NULL;
    for (uint32 i = 0; i < tables->count; i++) {
        sql_table_t *table = (sql_table_t *)sql_array_get(tables, i);
        if (table->type != NORMAL_TABLE || sql_init_normal_table_dc(verf->stmt, table, query) != GS_SUCCESS) {
            cm_reset_error_user(ERR_TABLE_OR_VIEW_NOT_EXIST, T2S(&table->user.value), T2S_EX(&table->name.value),
                                ERR_TYPE_TABLE_OR_VIEW);
            cm_set_error_loc(table->user.loc);
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

bool32 sql_check_ref_exists(galist_t *ref_objects, object_address_t *ref_obj)
{
    object_address_t *obj = NULL;
    uint32 i;

    if (ref_objects == NULL) {
        return GS_FALSE;
    }

    for (i = 0; i < ref_objects->count; i++) {
        obj = (object_address_t *)cm_galist_get(ref_objects, i);
        if (obj->uid == ref_obj->uid && obj->oid == ref_obj->oid && obj->tid == ref_obj->tid) {
            return GS_TRUE;
        }
    }

    return GS_FALSE;
}
status_t sql_append_reference_knl_dc(galist_t *dest, knl_dictionary_t *dc)
{
    object_address_t ref;
    dc_entry_t *dc_entry = NULL;
    dc_entity_t *entity = NULL;
    if (dc->is_sysnonym) {
        dc_entry = (dc_entry_t *)dc->syn_handle;
        ref.tid = OBJ_TYPE_SYNONYM;
        ref.oid = dc_entry->id;
        ref.uid = dc_entry->uid;
        ref.scn = dc->chg_scn;
        MEMS_RETURN_IFERR(strcpy_s(ref.name, GS_NAME_BUFFER_SIZE, dc_entry->name));
    } else {
        ref.tid = knl_get_object_type(dc->type);
        ref.oid = dc->oid;
        ref.uid = dc->uid;
        ref.scn = dc->chg_scn;
        entity = (dc_entity_t *)dc->handle;
        MEMS_RETURN_IFERR(strcpy_s(ref.name, GS_NAME_BUFFER_SIZE, entity->entry->name));
    }
    if (!sql_check_ref_exists(dest, &ref)) {
        return cm_galist_copy_append(dest, sizeof(object_address_t), &ref);
    }
    return GS_SUCCESS;
}
status_t sql_apend_dependency_table(sql_stmt_t *stmt, sql_table_t *sql_table)
{
    knl_dictionary_t *dc = &sql_table->entry->dc;
    if (stmt->context->ref_objects == NULL) {  // only DML context will init
        return GS_SUCCESS;
    }
    return sql_append_reference_knl_dc(stmt->context->ref_objects, dc);
}

#define SQL_FUNC_COUNT ELEMENT_COUNT(g_func_tab)
/*
 * **NOTE:**
 * 1. The function must be arranged by alphabetical ascending order.
 * 2. An enum stands for function index was added in sql_func.h for z_sharding.
 * if any built-in function added or removed from the following array,
 * please modify the enum definition, too.
 * 3. add function should add the define id in en_function_item_id at sql_func.h.
 */
/* **NOTE:** The function must be arranged by alphabetical ascending order. */
sql_func_t g_func_tab[] = {
    { { (char *)"abs", 3 }, sql_func_abs, sql_verify_abs, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_ABS, FO_USUAL, GS_TRUE },
    { { (char *)"acos", 4 }, sql_func_acos, sql_verify_trigonometric, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_ACOS, FO_USUAL, GS_FALSE },
    { { (char *)"add_months", 10 }, sql_func_add_months, sql_verify_add_months, AGGR_TYPE_NONE, FO_SPECIAL, ID_FUNC_ITEM_ADD_MONTHS, FO_USUAL, GS_FALSE },
    { { (char *)"array_agg", 9 }, sql_func_array_agg, sql_verify_array_agg, AGGR_TYPE_ARRAY_AGG, FO_NONE, ID_FUNC_ITEM_ARRAY_AGG, FO_USUAL, GS_FALSE },
    { { (char *)"array_length", 12 }, sql_func_array_length, sql_verify_array_length, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_ARRAY_LENGTH, FO_USUAL, GS_FALSE },
    { { (char *)"ascii", 5 }, sql_func_ascii, sql_verify_ascii, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_ASCII, FO_USUAL, GS_FALSE },
    { { (char *)"asciistr", 8 }, sql_func_asciistr, sql_verify_asciistr, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_ASCIISTR, FO_USUAL, GS_FALSE },
    { { (char *)"asin", 4 }, sql_func_asin, sql_verify_trigonometric, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_ASIN, FO_USUAL, GS_FALSE },
    { { (char *)"atan", 4 }, sql_func_atan, sql_verify_trigonometric, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_ATAN, FO_USUAL, GS_FALSE },
    { { (char *)"atan2", 5 }, sql_func_atan2, sql_verify_atan2, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_ATAN2, FO_USUAL, GS_FALSE },
    { { (char *)"avg", 3 }, sql_func_normal_aggr, sql_verify_avg, AGGR_TYPE_AVG, FO_NONE, ID_FUNC_ITEM_AVG, FO_USUAL, GS_FALSE },
    { { (char *)"bin2hex", 7 }, sql_func_bin2hex, sql_verify_bin2hex, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_BIN2HEX, FO_USUAL, GS_FALSE },
    { { (char *)"bitand", 6 }, sql_func_bit_and, sql_verify_bit_func, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_BITAND, FO_USUAL, GS_FALSE },
    { { (char *)"bitor", 5 }, sql_func_bit_or, sql_verify_bit_func, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_BITOR, FO_USUAL, GS_FALSE },
    { { (char *)"bitxor", 6 }, sql_func_bit_xor, sql_verify_bit_func, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_BITXOR, FO_USUAL, GS_FALSE },
    { { (char *)"cast", 4 }, sql_func_cast, sql_verify_cast, AGGR_TYPE_NONE, FO_SPECIAL, ID_FUNC_ITEM_CAST, FO_USUAL, GS_FALSE },
    { { (char *)"ceil", 4 }, sql_func_ceil, sql_verify_ceil, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_CEIL, FO_USUAL, GS_FALSE },
    { { (char *)"char", 4 }, sql_func_chr, sql_verify_chr, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_CHAR, FO_USUAL, GS_FALSE },
    { { (char *)"char_length", 11 }, sql_func_length, sql_verify_length, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_CHAR_LENGTH, FO_USUAL, GS_FALSE },
    { { (char *)"chr", 3 }, sql_func_chr, sql_verify_chr, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_CHR, FO_USUAL, GS_FALSE },
    { { (char *)"coalesce", 8 }, sql_func_coalesce, sql_verify_coalesce, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_COALESCE, FO_USUAL, GS_FALSE },
    { { (char *)"concat", 6 }, sql_func_concat, sql_verify_concat, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_CONCAT, FO_USUAL, GS_FALSE },
    { { (char *)"concat_ws", 9 }, sql_func_concat_ws, sql_verify_concat_ws, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_CONCAT_WS, FO_USUAL, GS_FALSE },
    { { (char *)"connection_id", 13 }, sql_func_connection_id, sql_verify_connection_id, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_CONNECTION_ID, FO_USUAL, GS_FALSE },
    { { (char *)"convert", 7 }, sql_func_cast, sql_verify_cast, AGGR_TYPE_NONE, FO_SPECIAL, ID_FUNC_ITEM_CONVERT, FO_USUAL, GS_FALSE },
    { { (char *)"corr", 4 }, sql_func_covar_or_corr, sql_verify_covar_or_corr, AGGR_TYPE_CORR, FO_NONE, ID_FUNC_ITEM_CORR, FO_COVAR, GS_FALSE },
    { { (char *)"cos", 3 }, sql_func_cos, sql_verify_trigonometric, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_COS, FO_USUAL, GS_FALSE },
    { { (char *)"count", 5 }, sql_func_count, sql_verify_count, AGGR_TYPE_COUNT, FO_NONE, ID_FUNC_ITEM_COUNT, FO_USUAL, GS_FALSE },
    { { (char *)"covar_pop", 9 }, sql_func_covar_or_corr, sql_verify_covar_or_corr, AGGR_TYPE_COVAR_POP, FO_NONE, ID_FUNC_ITEM_COVAR_POP, FO_COVAR, GS_FALSE },
    { { (char *)"covar_samp", 10 }, sql_func_covar_or_corr, sql_verify_covar_or_corr, AGGR_TYPE_COVAR_SAMP, FO_NONE, ID_FUNC_ITEM_COVAR_SAMP, FO_COVAR, GS_FALSE },
    { { (char *)"cume_dist", 9 }, sql_func_cume_dist, sql_verify_cume_dist, AGGR_TYPE_CUME_DIST, FO_NONE, ID_FUNC_ITEM_CUME_DIST, FO_USUAL, GS_FALSE },
    { { (char *)"current_timestamp", 17 }, sql_func_current_timestamp, sql_verify_current_timestamp, AGGR_TYPE_NONE, FO_SPECIAL, ID_FUNC_ITEM_CURRENT_TIMESTAMP, FO_USUAL, GS_FALSE },
    { { (char *)"dba_exec_ddl", 12 }, sql_func_dba_exec_ddl, sql_verify_dba_exec_ddl, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_DBA_EXEC_DDL, FO_USUAL, GS_FALSE },
    { { (char *)"decode", 6 }, sql_func_decode, sql_verify_decode, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_DECODE, FO_USUAL, GS_TRUE },
    { { (char *)"dense_rank", 10 }, sql_func_dense_rank, sql_verify_dense_rank, AGGR_TYPE_DENSE_RANK, FO_NONE, ID_FUNC_ITEM_DENSE_RANK, FO_USUAL, GS_FALSE },
    { { (char *)"empty_blob", 10 }, sql_func_empty_blob, sql_verify_empty_blob, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_EMPTY_BLOB, FO_USUAL, GS_FALSE },
    { { (char *)"empty_clob", 10 }, sql_func_empty_clob, sql_verify_empty_clob, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_EMPTY_CLOB, FO_USUAL, GS_FALSE },
    { { (char *)"exp", 3 }, sql_func_exp, sql_verify_exp, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_EXP, FO_USUAL, GS_FALSE },
    { { (char *)"extract", 7 }, sql_func_extract, sql_verify_extract, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_EXTRACT, FO_USUAL, GS_FALSE },
    { { (char *)"find_in_set", 11 }, sql_func_find_in_set, sql_verify_find_in_set, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_FIND_IN_SET, FO_USUAL, GS_FALSE },
    { { (char *)"floor", 5 }, sql_func_floor, sql_verify_floor, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_FLOOR, FO_USUAL, GS_FALSE },
    { { (char *)"found_rows", 10 }, sql_func_found_rows, sql_verify_found_rows, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_FOUND_ROWS, FO_USUAL, GS_FALSE },
    { { (char *)"from_tz", 7 }, sql_func_from_tz, sql_verify_from_tz, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_FROM_TZ, FO_USUAL, GS_FALSE },
    { { (char *)"from_unixtime", 13 }, sql_func_from_unixtime, sql_verify_from_unixtime, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_FROM_UNIXTIME, FO_USUAL, GS_FALSE },
    { { (char *)"getutcdate", 10 }, sql_func_utcdate, sql_verify_utcdate, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_GETUTCDATE, FO_USUAL, GS_FALSE },
    { { (char *)"get_lock", 8 }, sql_func_get_lock, sql_verify_alck_nm_and_to, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_GET_LOCK, FO_USUAL, GS_FALSE },
    { { (char *)"get_shared_lock", 15 }, sql_func_get_shared_lock, sql_verify_alck_nm_and_to, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_GET_SHARED_LOCK, FO_USUAL, GS_FALSE },
    { { (char *)"get_xact_lock", 13 }, sql_func_get_xact_lock, sql_verify_alck_nm_and_to, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_GET_XACT_LOCK, FO_USUAL, GS_FALSE },
    { { (char *)"get_xact_shared_lock", 20 }, sql_func_get_xact_shared_lock, sql_verify_alck_nm_and_to, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_GET_XACT_SHARED_LOCK, FO_USUAL, GS_FALSE },
    { { (char *)"greatest", 8 }, sql_func_greatest, sql_verify_least_greatest, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_GREATEST, FO_USUAL, GS_FALSE },
    { { (char *)"grouping", 8 }, sql_func_grouping, sql_verify_grouping, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_GROUPING, FO_USUAL, GS_FALSE },
    { { (char *)"grouping_id", 11 }, sql_func_grouping_id, sql_verify_grouping_id, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_GROUPING_ID, FO_USUAL, GS_FALSE },
    { { (char *)"group_concat", 12 }, sql_func_group_concat, sql_verify_group_concat, AGGR_TYPE_GROUP_CONCAT, FO_NONE, ID_FUNC_ITEM_GROUP_CONCAT, FO_USUAL, GS_FALSE },
    { { (char *)"gscn2date", 9 }, sql_func_gscn2date, sql_verify_gscn2date, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_GSCN2DATE, FO_USUAL, GS_FALSE },
    { { (char *)"gs_hash", 7 }, sql_func_gs_hash, sql_verify_gs_hash, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_GS_HASH, FO_USUAL, GS_FALSE },
    { { (char *)"hash", 4 }, sql_func_hash, sql_verify_hash, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_HASH, FO_USUAL, GS_FALSE },
    { { (char *)"hex", 3 }, sql_func_hex, sql_verify_hex, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_HEX, FO_USUAL, GS_FALSE },
    { { (char *)"hex2bin", 7 }, sql_func_hex2bin, sql_verify_hex2bin, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_HEX2BIN, FO_USUAL, GS_FALSE },
    { { (char *)"hextoraw", 8 }, sql_func_hextoraw, sql_verify_hextoraw, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_HEXTORAW, FO_USUAL, GS_FALSE },
    { { (char *)"if", 2 }, sql_func_if, sql_verify_if, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_IF, FO_USUAL, GS_FALSE },
    { { (char *)"ifnull", 6 }, sql_func_ifnull, sql_verify_ifnull, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_IFNULL, FO_USUAL, GS_FALSE },
    { { (char *)"inet_aton", 9 }, sql_func_inet_aton, sql_verify_inet_aton, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_INET_ATON, FO_USUAL, GS_FALSE },
    { { (char *)"inet_ntoa", 9 }, sql_func_inet_ntoa, sql_verify_inet_ntoa, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_INET_NTOA, FO_USUAL, GS_FALSE },
    { { (char *)"insert", 6 }, sql_func_insert, sql_verify_insert_func, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_INSERT, FO_USUAL, GS_FALSE },
    { { (char *)"instr", 5 }, sql_func_instr, sql_verify_instr, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_INSTR, FO_USUAL, GS_FALSE },
    { { (char *)"instrb", 6 }, sql_func_instrb, sql_verify_instr, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_INSTRB, FO_USUAL, GS_FALSE },
    { { (char *)"isnumeric", 9 }, sql_func_is_numeric, sql_verify_is_numeric, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_ISNUMERIC, FO_USUAL, GS_FALSE },
    { { (char *)"json_array", 10 }, sql_func_json_array, sql_verify_json_array, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_JSON_ARRAY, FO_USUAL, GS_FALSE },
    { { (char *)"json_array_length", 17 }, sql_func_json_array_length, sql_verify_json_array_length, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_JSON_ARRAY_LENGTH, FO_USUAL, GS_FALSE },
    { { (char *)"json_exists", 11 }, sql_func_json_exists, sql_verify_json_exists, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_JSON_EXISTS, FO_USUAL, GS_FALSE },
    { { (char *)"json_object", 11 }, sql_func_json_object, sql_verify_json_object, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_JSON_OBJECT, FO_USUAL, GS_FALSE },
    { { (char *)"json_query", 10 }, sql_func_json_query, sql_verify_json_query, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_JSON_QUERY, FO_USUAL, GS_FALSE },
    { { (char *)"json_set", 8 }, sql_func_json_set, sql_verify_json_set, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_JSON_SET, FO_USUAL, GS_FALSE },
    { { (char *)"json_value", 10 }, sql_func_json_value, sql_verify_json_value, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_JSON_VALUE, FO_USUAL, GS_TRUE },
    { { (char *)"last_day", 8 }, sql_func_last_day, sql_verify_last_day, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_LAST_DAY, FO_USUAL, GS_FALSE },
    { { (char *)"last_insert_id", 14 }, sql_func_last_insert_id, sql_verify_last_insert_id, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_LAST_INSERT_ID, FO_USUAL, GS_FALSE },
    { { (char *)"least", 5 }, sql_func_least, sql_verify_least_greatest, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_LEAST, FO_USUAL, GS_FALSE },
    { { (char *)"left", 4 }, sql_func_left, sql_verify_left, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_LEFT, FO_USUAL, GS_FALSE },
    { { (char *)"length", 6 }, sql_func_length, sql_verify_length, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_LENGTH, FO_USUAL, GS_FALSE },
    { { (char *)"lengthb", 7 }, sql_func_lengthb, sql_verify_length, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_LENGTHB, FO_USUAL, GS_FALSE },
    { { (char *)"listagg", 7 }, sql_func_group_concat, sql_verify_listagg, AGGR_TYPE_GROUP_CONCAT, FO_NONE, ID_FUNC_ITEM_LISTAGG, FO_USUAL, GS_FALSE },
    { { (char *)"ln", 2 }, sql_func_ln, sql_verify_ln, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_LN, FO_USUAL, GS_FALSE },
    { { (char *)"lnnvl", 5 }, sql_func_lnnvl, sql_verify_lnnvl, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_LNNVL, FO_USUAL, GS_FALSE },
    { { (char *)"localtimestamp", 14 }, sql_func_localtimestamp, sql_verify_localtimestamp, AGGR_TYPE_NONE, FO_SPECIAL, ID_FUNC_ITEM_LOCALTIMESTAMP, FO_USUAL, GS_FALSE },
    { { (char *)"locate", 6 }, sql_func_locate, sql_verify_locate, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_LOCATE, FO_USUAL, GS_FALSE },
    { { (char *)"log", 3 }, sql_func_log, sql_verify_log, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_LOG, FO_USUAL, GS_FALSE },
    { { (char *)"lower", 5 }, sql_func_lower, sql_verify_lower, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_LOWER, FO_USUAL, GS_TRUE },
    { { (char *)"lpad", 4 }, sql_func_lpad, sql_verify_pad, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_LPAD, FO_USUAL, GS_FALSE },
    { { (char *)"ltrim", 5 }, sql_func_ltrim, sql_verify_rltrim, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_LTRIM, FO_USUAL, GS_FALSE },
    { { (char *)"max", 3 }, sql_func_normal_aggr, sql_verify_min_max, AGGR_TYPE_MAX, FO_NONE, ID_FUNC_ITEM_MAX, FO_USUAL, GS_FALSE },
    { { (char *)"md5", 3 }, sql_func_md5, sql_verify_md5, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_MD5, FO_USUAL, GS_FALSE },
    { { (char *)"median", 6 }, sql_func_normal_aggr, sql_verify_median, AGGR_TYPE_MEDIAN, FO_NONE, ID_FUNC_ITEM_MEDIAN, FO_USUAL, GS_FALSE },
    { { (char *)"min", 3 }, sql_func_normal_aggr, sql_verify_min_max, AGGR_TYPE_MIN, FO_NONE, ID_FUNC_ITEM_MIN, FO_USUAL, GS_FALSE },
    { { (char *)"mod", 3 }, sql_func_mod, sql_verify_mod, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_MOD, FO_USUAL, GS_FALSE },
    { { (char *)"months_between", 14 }, sql_func_months_between, sql_verify_months_between, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_MONTHS_BETWEEN, FO_USUAL, GS_FALSE },
    { { (char *)"next_day", 8 }, sql_func_next_day, sql_verify_next_day, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_NEXT_DAY, FO_USUAL, GS_FALSE },
    { { (char *)"now", 3 }, sql_func_current_timestamp, sql_verify_current_timestamp, AGGR_TYPE_NONE, FO_SPECIAL, ID_FUNC_ITEM_NOW, FO_USUAL, GS_FALSE },
    { { (char *)"nullif", 6 }, sql_func_nullif, sql_verify_nullif, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_NULLIF, FO_USUAL, GS_FALSE },
    { { (char *)"numtodsinterval", 15 }, sql_func_numtodsinterval, sql_verify_numtodsinterval, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_NUMTODSINTERVAL, FO_USUAL, GS_FALSE },
    { { (char *)"numtoyminterval", 15 }, sql_func_numtoyminterval, sql_verify_numtoyminterval, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_NUMTOYMINTERVAL, FO_USUAL, GS_FALSE },
    { { (char *)"nvl", 3 }, sql_func_nvl, sql_verify_nvl, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_NVL, FO_USUAL, GS_TRUE },
    { { (char *)"nvl2", 4 }, sql_func_nvl2, sql_verify_nvl2, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_NVL2, FO_USUAL, GS_TRUE },
    { { (char *)"object_id", 9 }, sql_func_object_id, sql_verify_object_id, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_OBJECT_ID, FO_USUAL, GS_FALSE },
    { { (char *)"pi", 2 }, sql_func_pi, sql_verify_pi, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_PI, FO_USUAL, GS_FALSE },
    { { (char *)"power", 5 }, sql_func_power, sql_verify_power, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_POWER, FO_USUAL, GS_FALSE },
    { { (char *)"radians", 7 }, sql_func_radians, sql_verify_trigonometric, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_RADIANS, FO_USUAL, GS_TRUE },
    { { (char *)"rand", 4 }, sql_func_rand, sql_verify_rand, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_RAND, FO_USUAL, GS_FALSE },
    { { (char *)"rank", 4 }, sql_func_dense_rank, sql_verify_dense_rank, AGGR_TYPE_RANK, FO_NONE, ID_FUNC_ITEM_RANK, FO_USUAL, GS_FALSE },
    { { (char *)"rawtohex", 8 }, sql_func_rawtohex, sql_verify_rawtohex, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_RAWTOHEX, FO_USUAL, GS_FALSE },
    { { (char *)"regexp_count", 12 }, sql_func_regexp_count, sql_verify_regexp_count, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_REGEXP_COUNT, FO_USUAL, GS_FALSE },
    { { (char *)"regexp_instr", 12 }, sql_func_regexp_instr, sql_verify_regexp_instr, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_REGEXP_INSTR, FO_USUAL, GS_TRUE },
    { { (char *)"regexp_replace", 14 }, sql_func_regexp_replace, sql_verify_regexp_replace, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_REGEXP_REPLACE, FO_USUAL, GS_FALSE },
    { { (char *)"regexp_substr", 13 }, sql_func_regexp_substr, sql_verify_regexp_substr, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_REGEXP_SUBSTR, FO_USUAL, GS_TRUE },
    { { (char *)"release_lock", 12 }, sql_func_release_lock, sql_verify_alck_name, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_RELEASE_LOCK, FO_USUAL, GS_FALSE },
    { { (char *)"release_shared_lock", 19 }, sql_func_release_shared_lock, sql_verify_alck_name, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_RELEASE_SHARED_LOCK, FO_USUAL, GS_FALSE },
    { { (char *)"repeat", 6 }, sql_func_repeat, sql_verify_repeat, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_PEPEAT, FO_USUAL, GS_FALSE },
    { { (char *)"replace", 7 }, sql_func_replace, sql_verify_replace, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_REPLACE, FO_USUAL, GS_FALSE },
    { { (char *)"reverse", 7 }, sql_func_reverse, sql_verify_reverse, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_REVERSE, FO_USUAL, GS_TRUE },
    { { (char *)"right", 5 }, sql_func_right, sql_verify_right, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_RIGHT, FO_USUAL, GS_FALSE },
    { { (char *)"round", 5 }, sql_func_round, sql_verify_round_trunc, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_ROUND, FO_USUAL, GS_FALSE },
    { { (char *)"rpad", 4 }, sql_func_rpad, sql_verify_pad, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_RPAD, FO_USUAL, GS_FALSE },
    { { (char *)"rtrim", 5 }, sql_func_rtrim, sql_verify_rltrim, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_RTRIM, FO_USUAL, GS_FALSE },
    { { (char *)"scn2date", 8 }, sql_func_scn2date, sql_verify_scn2date, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_SCN2DATE, FO_USUAL, GS_FALSE },
    { { (char *)"sha", 3 }, sql_func_sha1, sql_verify_sha1, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_SHA, FO_USUAL, GS_FALSE },
    { { (char *)"sha1", 4 }, sql_func_sha1, sql_verify_sha1, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_SHA1, FO_USUAL, GS_FALSE },
    { { (char *)"sign", 4 }, sql_func_sign, sql_verify_sign, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_SIGN, FO_USUAL, GS_FALSE },
    { { (char *)"sin", 3 }, sql_func_sin, sql_verify_trigonometric, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_SIN, FO_USUAL, GS_FALSE },
    { { (char *)"soundex", 7 }, sql_func_soundex, sql_verify_soundex, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_SOUNDEX, FO_USUAL, GS_FALSE },
    { { (char *)"space", 5 }, sql_func_space, sql_verify_space, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_SPACE, FO_USUAL, GS_FALSE },
    { { (char *)"sqrt", 4 }, sql_func_sqrt, sql_verify_sqrt, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_SQRT, FO_USUAL, GS_FALSE },
    { { (char *)"stddev", 6 }, sql_func_normal_aggr, sql_verify_stddev_intern, AGGR_TYPE_STDDEV, FO_NONE, ID_FUNC_ITEM_STDDEV, FO_USUAL, GS_FALSE },
    { { (char *)"stddev_pop", 10 }, sql_func_normal_aggr, sql_verify_stddev_intern, AGGR_TYPE_STDDEV_POP, FO_NONE, ID_FUNC_ITEM_STDDEV_POP, FO_USUAL, GS_FALSE },
    { { (char *)"stddev_samp", 11 }, sql_func_normal_aggr, sql_verify_stddev_intern, AGGR_TYPE_STDDEV_SAMP, FO_NONE, ID_FUNC_ITEM_STDDEV_SAMP, FO_USUAL, GS_FALSE },
    { { (char *)"substr", 6 }, sql_func_substr, sql_verify_substr, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_SUBSTR, FO_USUAL, GS_TRUE },
    { { (char *)"substrb", 7 }, sql_func_substrb, sql_verify_substr, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_SUBSTRB, FO_USUAL, GS_FALSE },
    { { (char *)"substring", 9 }, sql_func_substr, sql_verify_substr, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_SUBSTRING, FO_USUAL, GS_FALSE },
    { { (char *)"substring_index", 15 }, sql_func_substring_index, sql_verify_substring_index, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_SUBSTRING_INDEX, FO_USUAL, GS_FALSE },
    { { (char *)"sum", 3 }, sql_func_normal_aggr, sql_verify_sum, AGGR_TYPE_SUM, FO_NONE, ID_FUNC_ITEM_SUM, FO_USUAL, GS_FALSE },
    { { (char *)"systimestamp", 12 }, sql_func_sys_timestamp, sql_verify_current_timestamp, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_SYSTIMESTAMP, FO_USUAL, GS_FALSE },
    { { (char *)"sys_connect_by_path", 19 }, sql_func_sys_connect_by_path, sql_verify_sys_connect_by_path, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_SYS_CONNECT_BY_PATH, FO_USUAL, GS_FALSE },
    { { (char *)"sys_context", 11 }, sql_func_sys_context, sql_verify_sys_context, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_SYS_CONTEXT, FO_USUAL, GS_FALSE },
    { { (char *)"sys_extract_utc", 15 }, sql_func_sys_extract_utc, sql_verify_sys_extract_utc, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_SYS_EXTRACT_UTC, FO_USUAL, GS_FALSE },
    { { (char *)"sys_guid", 8 }, sql_func_sys_guid, sql_verify_sys_guid, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_SYS_GUID, FO_USUAL, GS_FALSE },
    { { (char *)"tan", 3 }, sql_func_tan, sql_verify_trigonometric, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_TAN, FO_USUAL, GS_FALSE },
    { { (char *)"tanh", 4 }, sql_func_tanh, sql_verify_tanh, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_TANH, FO_USUAL, GS_FALSE },
    { { (char *)"timestampadd", 12 }, sql_func_timestampadd, sql_verify_timestampadd, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_TIMESTAMPADD, FO_USUAL, GS_FALSE },
    { { (char *)"timestampdiff", 13 }, sql_func_timestampdiff, sql_verify_timestampdiff, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_TIMESTAMPDIFF, FO_USUAL, GS_FALSE },
    { { (char *)"to_char", 7 }, sql_func_to_char, sql_verify_to_char, AGGR_TYPE_NONE, FO_SPECIAL, ID_FUNC_ITEM_TO_CHAR, FO_USUAL, GS_TRUE },
    { { (char *)"to_date", 7 }, sql_func_to_date, sql_verify_to_date, AGGR_TYPE_NONE, FO_SPECIAL, ID_FUNC_ITEM_TO_DATE, FO_USUAL, GS_TRUE },
    { { (char *)"to_dsinterval", 13 }, sql_func_to_dsinterval, sql_verify_to_dsinterval, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_TO_DSINTERVAL, FO_USUAL, GS_FALSE },
    { { (char *)"to_multi_byte", 13 }, sql_func_to_multi_byte, sql_verify_to_single_or_multi_byte, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_TO_MULTI_BYTE, FO_USUAL, GS_FALSE },
    { { (char *)"to_nchar", 8 }, sql_func_to_nchar, sql_verify_to_nchar, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_TO_NCHAR, FO_USUAL, GS_FALSE },
    { { (char *)"to_number", 9 }, sql_func_to_number, sql_verify_to_number, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_TO_NUMBER, FO_USUAL, GS_TRUE },
    { { (char *)"to_single_byte", 14 }, sql_func_to_single_byte, sql_verify_to_single_or_multi_byte, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_TO_SINGLE_BYTE, FO_USUAL, GS_FALSE },
    { { (char *)"to_timestamp", 12 }, sql_func_to_timestamp, sql_verify_to_timestamp, AGGR_TYPE_NONE, FO_SPECIAL, ID_FUNC_ITEM_TO_TIMESTAMP, FO_USUAL, GS_FALSE },
    { { (char *)"to_yminterval", 13 }, sql_func_to_yminterval, sql_verify_to_yminterval, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_TO_YMINTERVAL, FO_USUAL, GS_FALSE },
    { { (char *)"translate", 9 }, sql_func_translate, sql_verify_translate, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_TRANSLATE, FO_USUAL, GS_FALSE },
    { { (char *)"trim", 4 }, sql_func_trim, sql_verify_trim, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_TRIM, FO_USUAL, GS_TRUE },
    { { (char *)"trunc", 5 }, sql_func_trunc, sql_verify_round_trunc, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_TRUNC, FO_USUAL, GS_TRUE },
    { { (char *)"try_get_lock", 12 }, sql_func_try_get_lock, sql_verify_alck_name, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_TRY_GET_LOCK, FO_USUAL, GS_FALSE },
    { { (char *)"try_get_shared_lock", 19 }, sql_func_try_get_shared_lock, sql_verify_alck_name, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_TRY_GET_SHARED_LOCK, FO_USUAL, GS_FALSE },
    { { (char *)"try_get_xact_lock", 17 }, sql_func_try_get_xact_lock, sql_verify_alck_name, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_TRY_GET_XACT_LOCK, FO_USUAL, GS_FALSE },
    { { (char *)"try_get_xact_shared_lock", 24 }, sql_func_try_get_xact_shared_lock, sql_verify_alck_name, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_TRY_GET_XACT_SHARED_LOCK, FO_USUAL, GS_FALSE },
    { { (char *)"type_id2name", 12 }, sql_func_type_name, sql_verify_to_type_mapped, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_TYPE_ID2NAME, FO_USUAL, GS_FALSE },
    { { (char *)"unhex", 5 }, sql_func_unhex, sql_verify_unhex, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_UNHEX, FO_USUAL, GS_FALSE },
    { { (char *)"unix_timestamp", 14 }, sql_func_unix_timestamp, sql_verify_unix_timestamp, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_UNIX_TIMESTAMP, FO_USUAL, GS_FALSE },
    { { (char *)"updating", 8 }, NULL, sql_verify_updating, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_UPDATING, FO_USUAL, GS_FALSE },
    { { (char *)"upper", 5 }, sql_func_upper, sql_verify_upper, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_UPPER, FO_USUAL, GS_TRUE },
    { { (char *)"userenv", 7 }, sql_func_userenv, sql_verify_userenv, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_USERENV, FO_USUAL, GS_FALSE },
    { { (char *)"utc_date", 8 }, sql_func_utcdate, sql_verify_utcdate, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_UTCDATE, FO_USUAL, GS_FALSE },
    { { (char *)"utc_timestamp", 13 }, sql_func_utctimestamp, sql_verify_utctimestamp, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_UTCTIMESTAMP, FO_USUAL, GS_FALSE },
    { { (char *)"uuid", 4 }, sql_func_sys_guid, sql_verify_sys_guid, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_UUID, FO_USUAL, GS_FALSE },
    { { (char *)"values", 6 }, sql_func_values, sql_verify_values, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_VALUES, FO_USUAL, GS_FALSE },
    { { (char *)"variance", 8 }, sql_func_normal_aggr, sql_verify_stddev_intern, AGGR_TYPE_VARIANCE, FO_NONE, ID_FUNC_ITEM_VARIANCE, FO_USUAL, GS_FALSE },
    { { (char *)"var_pop", 7 }, sql_func_normal_aggr, sql_verify_stddev_intern, AGGR_TYPE_VAR_POP, FO_NONE, ID_FUNC_ITEM_VAR_POP, FO_USUAL, GS_FALSE },
    { { (char *)"var_samp", 8 }, sql_func_normal_aggr, sql_verify_stddev_intern, AGGR_TYPE_VAR_SAMP, FO_NONE, ID_FUNC_ITEM_VAR_SAMP, FO_USUAL, GS_FALSE },
    { { (char *)"version", 7 }, sql_func_version, sql_verify_version, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_VERSION, FO_USUAL, GS_FALSE },
    { { (char *)"vsize", 5 }, sql_func_vsize, sql_verify_vsize, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_VSIZE, FO_USUAL, GS_FALSE },
};

/* *************************************************************************** */
/*    End of type declarations for internal use within sql_func.c            */
/* *************************************************************************** */

uint32 sql_func_binsearch(const text_t *name, sql_func_item_t get_item, void *set, uint32 count)
{
    uint32 begin_pos, end_pos, mid_pos;
    int32 comp;

    comp = cm_compare_text_ins(name, get_item(set, 0));
    if (comp == 0) {
        return 0;
    } else if (comp < 0) {
        return GS_INVALID_ID32;
    }

    comp = cm_compare_text_ins(name, get_item(set, count - 1));
    if (comp == 0) {
        return count - 1;
    } else if (comp > 0) {
        return GS_INVALID_ID32;
    }

    begin_pos = 0;
    end_pos = count - 1;
    mid_pos = (begin_pos + end_pos) / 2;

    while (end_pos - 1 > begin_pos) {
        comp = cm_compare_text_ins(name, get_item(set, mid_pos));
        if (comp == 0) {
            return mid_pos;
        } else if (comp < 0) {
            end_pos = mid_pos;
            mid_pos = (end_pos + begin_pos) / 2;
        } else {
            begin_pos = mid_pos;
            mid_pos = (end_pos + begin_pos) / 2;
        }
    }
    return GS_INVALID_ID32;
}
uint32 sql_get_func_id(const text_t *func_name)
{
    uint32 begin_pos, end_pos, mid_pos;
    int32 comp;

    comp = cm_compare_text_ins(func_name, &g_func_tab[0].name);
    if (comp == 0) {
        return 0;
    } else if (comp < 0) {
        return GS_INVALID_ID32;
    }

    comp = cm_compare_text_ins(func_name, &g_func_tab[SQL_FUNC_COUNT - 1].name);
    if (comp == 0) {
        return SQL_FUNC_COUNT - 1;
    } else if (comp > 0) {
        return GS_INVALID_ID32;
    }

    begin_pos = 0;
    end_pos = SQL_FUNC_COUNT - 1;
    mid_pos = (begin_pos + end_pos) / 2;

    while (end_pos - 1 > begin_pos) {
        comp = cm_compare_text_ins(func_name, &g_func_tab[mid_pos].name);
        if (comp == 0) {
            return mid_pos;
        } else if (comp < 0) {
            end_pos = mid_pos;
            mid_pos = (end_pos + begin_pos) / 2;
        } else {
            begin_pos = mid_pos;
            mid_pos = (end_pos + begin_pos) / 2;
        }
    }
    return GS_INVALID_ID32;
}

status_t sql_verify_func_node(sql_verifier_t *verf, expr_node_t *func, uint16 min_args, uint16 max_args,
                              uint32 type_arg_no)
{
    uint16 arg_count = 0;

    CM_POINTER2(verf, func);
    expr_tree_t *expr = func->argument;
    while (expr != NULL) {
        arg_count++;
        if ((expr->root->type == EXPR_NODE_PRIOR) && (verf->excl_flags & SQL_EXCL_PRIOR)) {
            GS_SRC_THROW_ERROR_EX(expr->loc, ERR_SQL_SYNTAX_ERROR, "prior must be in the condition of connect by");
            return GS_ERROR;
        }

        if (sql_verify_expr_node(verf, expr->root) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (arg_count == type_arg_no) {
            func->typmod = TREE_TYPMODE(expr);
        }

        expr = expr->next;
    }

    if (arg_count < min_args || arg_count > max_args) {
        GS_SRC_THROW_ERROR(func->loc, ERR_INVALID_FUNC_PARAM_COUNT, T2S(&func->word.func.name), min_args, max_args);
        return GS_ERROR;
    }

    func->value.v_func.arg_cnt = arg_count;

    return GS_SUCCESS;
}

status_t sql_invoke_func(sql_stmt_t *stmt, expr_node_t *node, variant_t *result)
{
    uint32 id = node->value.v_func.func_id;
    sql_func_t *func = NULL;
    status_t status;
    bool32 ready = GS_FALSE;
    CM_POINTER2(stmt, result);

    result->ctrl = 0;

    knl_panic(node->value.v_func.pack_id == GS_INVALID_ID32);

    if (id >= SQL_FUNC_COUNT) {
        // only if some built-in functions been removed
        GS_THROW_ERROR(ERR_INVALID_FUNC, id);
        return GS_ERROR;
    }

    result->type = GS_TYPE_UNKNOWN;
    func = sql_get_func(&node->value.v_func);
    SQL_SAVE_STACK(stmt);
    if (stmt->context != NULL && stmt->context->has_func_index && func->indexable) {
        knl_panic(0);
    }
    if (ready) {
        status = GS_SUCCESS;
    } else {
        status = func->invoke(stmt, node, result);
    }

    SQL_RESTORE_STACK(stmt);
    return status;
}

status_t sql_exec_expr_as_string(sql_stmt_t *stmt, expr_tree_t *arg, variant_t *var, text_t **text)
{
    text_buf_t buffer;

    GS_RETURN_IFERR(sql_exec_expr(stmt, arg, var));
    if (var->type == GS_TYPE_COLUMN) {
        return GS_SUCCESS;
    }

    *text = VALUE_PTR(text_t, var);

    if (var->is_null) {
        (*text)->len = 0;
        return GS_SUCCESS;
    }

    if (GS_IS_BINSTR_TYPE2(arg->root->datatype, var->type)) {
        if (var_as_string(SESSION_NLS(stmt), var, NULL) != GS_SUCCESS) {
            return GS_ERROR;
        }
        sql_keep_stack_variant(stmt, var);
        return GS_SUCCESS;
    }

    SQL_SAVE_STACK(stmt);

    sql_keep_stack_variant(stmt, var);
    if (sql_push_textbuf(stmt, GS_CONVERT_BUFFER_SIZE, &buffer) != GS_SUCCESS) {
        SQL_RESTORE_STACK(stmt);
        return GS_ERROR;
    }
    switch (arg->root->datatype) {
        case GS_TYPE_TIMESTAMP:
        case GS_TYPE_TIMESTAMP_TZ:
        case GS_TYPE_TIMESTAMP_LTZ:
        case GS_TYPE_TIMESTAMP_TZ_FAKE:
        case GS_TYPE_INTERVAL_DS:
        case GS_TYPE_INTERVAL_YM:
            if (var_as_string2(SESSION_NLS(stmt), var, &buffer, &arg->root->typmod) != GS_SUCCESS) {
                SQL_RESTORE_STACK(stmt);
                return GS_ERROR;
            }
            break;
        default:
            if (var_as_string(SESSION_NLS(stmt), var, &buffer) != GS_SUCCESS) {
                SQL_RESTORE_STACK(stmt);
                return GS_ERROR;
            }
    }

    SQL_RESTORE_STACK(stmt);
    sql_keep_stack_variant(stmt, var);
    return GS_SUCCESS;
}

static status_t pl_verify_func_array_arg(uint32 func_id, expr_node_t *node)
{
    expr_tree_t *arg = node->argument;
    expr_node_t *arg_node = NULL;

    switch (func_id) {
        case ID_FUNC_ITEM_ARRAY_LENGTH:
        case ID_FUNC_ITEM_DECODE:
        case ID_FUNC_ITEM_CAST:
        case ID_FUNC_ITEM_TO_CHAR:
            break;

        default:
            while (arg != NULL) {
                arg_node = arg->root;
                if (arg_node->typmod.is_array == GS_TRUE) {
                    GS_SRC_THROW_ERROR(NODE_LOC(node), ERR_INVALID_ARG_TYPE);
                    return GS_ERROR;
                }
                arg = arg->next;
            }
            break;
    }

    return GS_SUCCESS;
}

static status_t pl_update_node_type(expr_node_t *node, sql_func_t *func)
{
    CM_ASSERT(func != NULL);
    if (node->type == EXPR_NODE_PROC || node->type == EXPR_NODE_USER_PROC) {
        if (func->options == FO_NORMAL || func->options == FO_PROC) {
            return GS_SUCCESS;
        } else {
            GS_SRC_THROW_ERROR(node->word.func.name.loc, ERR_SQL_SYNTAX_ERROR,
                               "expect a procedure here but meet a function");
        }
    } else if (func->options == FO_PROC) {
        node->type = EXPR_NODE_PROC;
    } else {
        node->type = EXPR_NODE_FUNC;
    }
    return GS_SUCCESS;
}

status_t pl_try_verify_builtin_func(sql_verifier_t *verf, expr_node_t *node, var_udo_t *obj, bool32 *is_found)
{
    sql_func_t *func = NULL;

    CM_TEXT_CLEAR(&obj->user);
    CM_TEXT_CLEAR(&obj->pack);
    cm_text_copy(&obj->name, GS_NAME_BUFFER_SIZE, &node->word.func.name.value);

    CM_POINTER2(verf, node);
    var_func_t vf = node->value.v_func;

    vf.func_id = sql_get_func_id((text_t *)&node->word.func.name);
    vf.pack_id = GS_INVALID_ID32;
    vf.is_proc = GS_FALSE;

    /*
     * The avg_collect() does not support input from original sql.
     * It only used for transform of z_sharding.
     */
    if (vf.func_id != GS_INVALID_ID32 && vf.func_id != ID_FUNC_ITEM_AVG_COLLECT) {
        *is_found = GS_TRUE;
        func = sql_get_func(&vf);
        node->value.v_func = vf;
    } else {
        *is_found = GS_FALSE;
        return GS_SUCCESS;
    }

    /* check expect type */
    if (node->type == EXPR_NODE_PROC || node->type == EXPR_NODE_USER_PROC) {
        GS_SRC_THROW_ERROR(node->loc, ERR_USER_OBJECT_NOT_EXISTS, "procedure", verf->stmt->session->curr_schema,
                           T2S(&node->word.func.name.value));
        return GS_ERROR;
    }

    /*
     * Not support grouping function in aggr
     */
    uint32 saved_flags = verf->excl_flags;
    if (func->aggr_type != AGGR_TYPE_NONE) {
        verf->excl_flags |= SQL_AGGR_EXCL;
    }

    if (func->verify(verf, node) != GS_SUCCESS) {
        return GS_ERROR;
    }
    verf->excl_flags = saved_flags;

    if (pl_verify_func_array_arg(vf.func_id, node) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (func->options == FO_NORMAL) {  // this IF branch may be removed when all function are
        sql_infer_func_optmz_mode(verf, node);
    }

    if (func->aggr_type != AGGR_TYPE_NONE) {
        GS_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "'count' not supported");
        return GS_ERROR;
    }
    if (node->dis_info.need_distinct) {
        GS_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "'distinct' not supported");
        return GS_ERROR;
    }

    node->value.type = GS_TYPE_INTEGER;
    GS_RETURN_IFERR(pl_update_node_type(node, func));
    return GS_SUCCESS;
}

void pl_revert_last_error(status_t status)
{
    if (status != GS_SUCCESS) {
        cm_revert_pl_last_error();
    }
}

#define MQ_MAX_PRECISION 6

#define IS_PL_SQL(stmt) ((stmt)->pl_context != NULL || (stmt)->pl_exec != NULL)

void sql_init_stmt(session_t *session, sql_stmt_t *stmt, uint32 stmt_id)
{
    sql_context_t *context = (session->disable_soft_parse) ? stmt->context : NULL;

    MEMS_RETVOID_IFERR(memset_s(stmt, sizeof(sql_stmt_t), 0, sizeof(sql_stmt_t)));

    vmc_init(&session->vmp, &stmt->vmc);
    cm_galist_init(&stmt->vmc_list, &stmt->vmc, vmc_alloc_mem);

    stmt->id = stmt_id;
    stmt->session = session;
    SET_STMT_CONTEXT(stmt, context);
    stmt->mtrl.sort_cmp = NULL;
    stmt->mtrl.session = NULL;
    stmt->vm_ctx = &stmt->vm_ctx_data;
    vm_init_ctx(GET_VM_CTX(stmt), (handle_t)session, &session->stack, session->knl_session.temp_pool);
    stmt->status = STMT_STATUS_IDLE;
    stmt->prefetch_rows = g_instance->sql.prefetch_rows;
    stmt->chk_priv = GS_TRUE;
    stmt->is_verifying = GS_FALSE;
    stmt->v_sysdate = SQL_UNINITIALIZED_DATE;
    stmt->v_systimestamp = SQL_UNINITIALIZED_TSTAMP;
    stmt->eof = GS_TRUE;
    stmt->into = NULL;
    stmt->outlines = NULL;
    stmt->is_temp_alloc = GS_FALSE;
    stmt->trace_disabled = GS_FALSE;
    stmt->context_refered = GS_FALSE;
    stmt->hash_mtrl_ctx_list = NULL;
    array_set_handle((void *)&session->knl_session, (void *)session->knl_session.temp_pool);
}

status_t sql_alloc_stmt(session_t *session, sql_stmt_t **statement)
{
    uint32 i;
    sql_stmt_t *stmt = NULL;

    cm_spin_lock(&session->sess_lock, NULL);

    for (i = 0; i < session->stmts.count; i++) {
        stmt = (sql_stmt_t *)cm_list_get(&session->stmts, i);
        if (stmt->status == STMT_STATUS_FREE) {
            sql_init_stmt(session, stmt, i);
            *statement = stmt;
            session->stmts_cnt++;
            cm_spin_unlock(&session->sess_lock);
            return GS_SUCCESS;
        }
    }
    if (session->stmts.count >= g_instance->attr.open_cursors) {
        cm_spin_unlock(&session->sess_lock);
        GS_THROW_ERROR(ERR_EXCEED_MAX_STMTS, g_instance->attr.open_cursors);
        return GS_ERROR;
    }

    if (cm_list_new(&session->stmts, (void **)&stmt) != GS_SUCCESS) {
        cm_spin_unlock(&session->sess_lock);
        GS_THROW_ERROR(ERR_NO_FREE_VMEM, "alloc space for statement failed");
        return GS_ERROR;
    }
    sql_init_stmt(session, stmt, session->stmts.count - 1);
    *statement = stmt;
    session->stmts_cnt++;
    cm_spin_unlock(&session->sess_lock);
    return GS_SUCCESS;
}

/**
 * Set current statement query scn
 * @attention once we set the query_scn all the cursors in current
 * statement would share the same query_scn.
 * @param sql statement
 */
void sql_set_scn(sql_stmt_t *stmt)
{
    if (stmt->session->pipe != NULL && CS_XACT_WITH_TS(stmt->session->recv_pack->head->flags) &&
        stmt->session->proto_type == PROTO_TYPE_GS) {
        knl_set_session_scn(&stmt->session->knl_session, stmt->sync_scn);
    } else {
        /* *
         * return error, hint: select 1;
         * if no valid scn in the request pack and connection from CN,
         * the consistency model must be GTS-free
         */
        knl_set_session_scn(&stmt->session->knl_session, GS_INVALID_ID64);
    }

    stmt->query_scn = stmt->session->knl_session.query_scn;
}

void sql_set_ssn(sql_stmt_t *stmt)
{
    knl_inc_session_ssn(&stmt->session->knl_session);
    stmt->ssn = stmt->session->knl_session.ssn;
    stmt->xact_ssn = stmt->session->knl_session.rm->ssn;
}

void do_release_context(sql_stmt_t *stmt, sql_context_t *context)
{
    CM_ASSERT(stmt->pl_context == NULL);
    if (context->type < SQL_TYPE_DML_CEIL) {
        if (context->in_sql_pool) {
            ctx_dec_ref(sql_pool, &context->ctrl);
        } else if (context->ctrl.ref_count > 0) {
            ctx_dec_ref2(&context->ctrl);
        } else {
            sql_free_context(context);
        }
    } else {
        sql_free_context(context);
    }
}

void sql_release_context(sql_stmt_t *stmt)
{
    sql_unlock_lnk_tabs(stmt);
    sql_context_t *context = NULL;

    if (stmt->context == NULL) {
        CM_ASSERT(stmt->pl_context == NULL);
        return;
    }

    context = stmt->context;
    cm_spin_lock(&context->ctrl.lock, NULL);
    cm_spin_unlock(&context->ctrl.lock);

    knl_panic(stmt->pl_context == NULL);
    SET_STMT_CONTEXT(stmt, NULL);

    sql_context_t *parent = context->parent;
    if (parent == NULL) {
        do_release_context(stmt, context);
        return;
    }
    ctx_dec_ref(parent->ctrl.subpool, &context->ctrl);
    do_release_context(stmt, parent);
}

static inline void sql_release_pool_objects(sql_stmt_t *stmt)
{
    object_pool_t *pool = NULL;

    if (stmt->sql_curs.count > 0) {
        sql_free_cursors(stmt);
    }

    if (stmt->knl_curs.count > 0) {
        pool = &stmt->session->knl_cur_pool;
        opool_free_list(pool, &stmt->knl_curs);
        olist_init(&stmt->knl_curs);
    }
}

static void sql_release_varea(sql_stmt_t *stmt)
{
    stmt->cursor_info.param_buf = NULL;
    stmt->cursor_info.param_types = NULL;
    stmt->fexec_info.first_exec_buf = NULL;
    stmt->plan_cnt = 0;
    stmt->plan_time = NULL;

    sql_free_vmemory(stmt);
    vmc_free(&stmt->vmc);
}

void sql_mark_lob_info(sql_stmt_t *stmt)
{
    if (stmt->session->call_version >= CS_VERSION_10) {
        vm_free_list(stmt->session, stmt->mtrl.pool, &stmt->lob_info_ex.exec_list);
        stmt->lob_info_ex.pre_expired = GS_TRUE;
    }
}

void sql_release_lob_info(sql_stmt_t *stmt)
{
    if (stmt->session->call_version >= CS_VERSION_10) {
        vm_free_list(stmt->session, stmt->mtrl.pool, &stmt->lob_info_ex.pre_list);
        vm_free_list(stmt->session, stmt->mtrl.pool, &stmt->lob_info_ex.exec_list);
        stmt->lob_info_ex.pre_expired = GS_FALSE;
    }
}

static void sql_reset_vmctx(sql_stmt_t *stmt)
{
    if (GET_VM_CTX(stmt) != &stmt->vm_ctx_data) {
        return;
    }
#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
    if (stmt->is_success) {
        (void)vmctx_check_memory(stmt->vm_ctx);
    }
#endif  // DEBUG
    vmctx_reset(GET_VM_CTX(stmt));
}

static void sql_free_trigger_list(sql_stmt_t *stmt)
{
    stmt->trigger_list = NULL;
}

void sql_release_resource(sql_stmt_t *stmt, bool32 is_force)
{
    sql_dec_ctx_ref(stmt, stmt->context);
    sql_free_trigger_list(stmt);

    if (!stmt->resource_inuse) {
        // we have used vmc memory in sql prepare phase, need to free it.
        sql_free_vmemory(stmt);
        vmc_free(&stmt->vmc);
        sql_reset_vmctx(stmt);
        return;
    }
    if (stmt->cursor_stack.depth > 0) {
        sql_free_cursor(stmt, SQL_ROOT_CURSOR(stmt));
    }
    sql_release_varea(stmt);

    sql_release_pool_objects(stmt);
    mtrl_release_context(&stmt->mtrl);
    OBJ_STACK_RESET(&stmt->cursor_stack);
    OBJ_STACK_RESET(&stmt->ssa_stack);
    OBJ_STACK_RESET(&stmt->node_stack);

    if (stmt->session->call_version < CS_VERSION_10) {
        // version under 11 , need to free lob_info here.
        if (!stmt->dc_invalid && (is_force || stmt->lob_info.inuse_count == 0)) {
            vm_free_list(stmt->session, stmt->mtrl.pool, &stmt->lob_info.list);
            stmt->lob_info.inuse_count = 0;
            stmt->resource_inuse = GS_FALSE;
        }
    } else {
        // lob info free at 'sql_release_lob_info'
        stmt->resource_inuse = GS_FALSE;
    }
    sql_reset_vmctx(stmt);

    stmt->is_check = GS_FALSE;
}

void sql_free_stmt(sql_stmt_t *stmt)
{
    if (stmt == NULL) {
        return;
    }

    if (stmt->status == STMT_STATUS_FREE) {
        return;
    }

    sql_release_lob_info(stmt);
    sql_release_resource(stmt, GS_TRUE);
    sql_release_context(stmt);
    stmt->status = STMT_STATUS_FREE;
    stmt->is_temp_alloc = GS_FALSE;
    stmt->parent_stmt = NULL;
    if (!stmt->eof) {
        stmt->eof = GS_TRUE;
        sql_dec_active_stmts(stmt);
    }
    stmt->session->stmts_cnt--;

    stmt->into = NULL;
    stmt->outlines = NULL;
}

status_t sql_init_sequence(sql_stmt_t *stmt)
{
    uint32 count;
    sql_seq_t *item = NULL;

    if (stmt->context == NULL) {
        GS_THROW_ERROR(ERR_INVALID_CURSOR);
        return GS_ERROR;
    }

    if (stmt->context->sequences == NULL) {
        stmt->v_sequences = NULL;
        return GS_SUCCESS;
    }

    count = stmt->context->sequences->count;
    GS_RETURN_IFERR(sql_push(stmt, sizeof(sql_seq_t) * count, (void **)&stmt->v_sequences));

    for (uint32 i = 0; i < count; ++i) {
        item = (sql_seq_t *)cm_galist_get(stmt->context->sequences, i);
        stmt->v_sequences[i].seq = item->seq;
        stmt->v_sequences[i].flags = item->flags;
        stmt->v_sequences[i].processed = GS_FALSE;
        stmt->v_sequences[i].value = 0;
    }
    return GS_SUCCESS;
}

void sql_free_vmemory(sql_stmt_t *stmt)
{
    for (uint32 i = 0; i < stmt->vmc_list.count; ++i) {
        vmc_t *vmc = (vmc_t *)cm_galist_get(&stmt->vmc_list, i);
        vmc_free(vmc);
    }
    cm_galist_init(&stmt->vmc_list, &stmt->vmc, vmc_alloc_mem);
}

static void sql_reset_stmt_resource(sql_stmt_t *stmt)
{
    stmt->query_scn = GS_INVALID_ID64;
    stmt->gts_scn = GS_INVALID_ID64;
    stmt->is_explain = GS_FALSE;
    stmt->is_reform_call = GS_FALSE;
    stmt->params_ready = GS_FALSE;
    stmt->text_shift = 0;
}

status_t sql_prepare(sql_stmt_t *stmt)
{
    text_t sql;
    cs_packet_t *recv_pack = NULL;
    source_location_t loc;

    sql_release_resource(stmt, GS_TRUE);
    sql_release_context(stmt);

    recv_pack = stmt->session->recv_pack;
    if (recv_pack->head->flags & CS_FLAG_MORE_DATA) {
        return GS_ERROR;
    } else {
        GS_RETURN_IFERR(cs_get_text(recv_pack, &sql));
        if (sql.len > AGENT_STACK_SIZE) {
            GS_THROW_ERROR(ERR_SQL_TOO_LONG, sql.len);
            return GS_ERROR;
        }
    }
    sql_reset_stmt_resource(stmt);
    loc.line = 1;
    loc.column = 1;

    stmt->status = STMT_STATUS_IDLE;
    if (sql_parse(stmt, &sql, &loc) != GS_SUCCESS) {
        /* check whether is multiple sql when parsed failed */
        if (cm_is_multiple_sql(&sql)) {
            cm_reset_error();
            GS_THROW_ERROR(ERR_CLT_MULTIPLE_SQL);
        }
        return GS_ERROR;
    }

    if (sql_check_privilege(stmt, GS_TRUE) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
        return GS_ERROR;
    }
    GS_RETURN_IFERR(my_sender(stmt)->send_parsed_stmt(stmt));

    stmt->status = STMT_STATUS_PREPARED;
    return GS_SUCCESS;
}

static inline void sql_write_debug_err_dml(sql_stmt_t *stmt)
{
    if (!LOG_DEBUG_ERR_ON || stmt->context == NULL) {
        return;
    }

    text_t sql_text;
    vmc_t vmc;
    vmc_init(&stmt->session->vmp, &vmc);
    if (vmc_alloc(&vmc, stmt->context->ctrl.text_size + 1, (void **)&sql_text.str) != GS_SUCCESS) {
        GS_LOG_DEBUG_ERR("Read dml context failed.");
        return;
    }
    sql_text.len = stmt->context->ctrl.text_size + 1;
    if (ctx_read_text(sql_pool, &stmt->context->ctrl, &sql_text, GS_FALSE) != GS_SUCCESS) {
        GS_LOG_DEBUG_ERR("Execute DML failed");
        vmc_free(&vmc);
        return;
    }
    GS_LOG_DEBUG_ERR("Execute DML failed, DML = %s", sql_text.str);
    vmc_free(&vmc);
}

status_t sql_check_tables(sql_stmt_t *stmt, sql_context_t *ctx)
{
    sql_table_entry_t *table = NULL;

    if (ctx->tables != NULL) {
        for (uint32 i = 0; i < ctx->tables->count; i++) {
            table = (sql_table_entry_t *)cm_galist_get(ctx->tables, i);
            if (table == NULL) {
                continue;
            }

            if (knl_check_dc(KNL_SESSION(stmt), &table->dc) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }
    return GS_SUCCESS;
}

status_t sql_check_ltt_dc(sql_stmt_t *stmt)
{
    if (!stmt->context->has_ltt) {
        return GS_SUCCESS;
    }

    sql_table_entry_t *table = NULL;
    for (uint32 i = 0; i < stmt->context->tables->count; i++) {
        table = (sql_table_entry_t *)cm_galist_get(stmt->context->tables, i);
        if (IS_LTT_BY_NAME(table->name.str)) {
            knl_session_t *curr = (knl_session_t *)knl_get_curr_sess();
            dc_entity_t *entity = DC_ENTITY(&table->dc);
            uint32 tab_id = entity->table.desc.id;
            dc_entry_t *entry = entity->entry;
            if (entry == NULL || tab_id < GS_LTT_ID_OFFSET ||
                tab_id >= (GS_LTT_ID_OFFSET + curr->temp_table_capacity)) {
                GS_THROW_ERROR(ERR_DC_INVALIDATED);
                return GS_ERROR;
            }

            dc_entry_t *sess_entry = (dc_entry_t *)curr->temp_dc->entries[tab_id - GS_LTT_ID_OFFSET];
            if (entry != sess_entry || table->dc.org_scn != sess_entry->org_scn) {
                GS_THROW_ERROR(ERR_DC_INVALIDATED);
                return GS_ERROR;
            }
        }
    }

    return GS_SUCCESS;
}

static inline status_t sql_execute_dml(sql_stmt_t *stmt)
{
    int32 code;
    const char *message = NULL;
    if (!stmt->is_sub_stmt) {
        GS_RETURN_IFERR(sql_prepare_params(stmt));
    }

    SQL_SAVE_STACK(stmt);
    for (;;) {
        if (sql_try_execute_dml(stmt) == GS_SUCCESS) {
            return GS_SUCCESS;
        }

        GS_RETURN_IFERR(knl_check_session_status(KNL_SESSION(stmt)));

        cm_get_error(&code, &message, NULL);
        if (code != ERR_DC_INVALIDATED) {
            if (stmt->auto_commit) {
                do_rollback(stmt->session, NULL);
            }

            sql_write_debug_err_dml(stmt);
            return GS_ERROR;
        }
        SQL_RESTORE_STACK(stmt);
    }
}

static inline status_t sql_execute_dml_and_send(sql_stmt_t *stmt)
{
    if (my_sender(stmt)->send_exec_begin(stmt) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (sql_execute_dml(stmt) != GS_SUCCESS) {
        return GS_ERROR;
    }

    my_sender(stmt)->send_exec_end(stmt);

    return GS_SUCCESS;
}

static status_t sql_init_trigger_list_core(sql_stmt_t *stmt)
{
    if (vmc_alloc(&stmt->vmc, sizeof(galist_t), (void **)&stmt->trigger_list) != GS_SUCCESS) {
        return GS_ERROR;
    }
    cm_galist_init(stmt->trigger_list, &stmt->vmc, vmc_alloc);
    stmt->resource_inuse = GS_TRUE;
    return GS_SUCCESS;
}

status_t sql_init_trigger_list(sql_stmt_t *stmt)
{
    if (stmt->trigger_list != NULL) {
        return GS_SUCCESS;
    }
    return sql_init_trigger_list_core(stmt);
}

static status_t sql_init_ref_dc_list(sql_stmt_t *stmt)
{
    if (vmc_alloc(&stmt->vmc, sizeof(galist_t), (void **)&stmt->pl_ref_entry) != GS_SUCCESS) {
        return GS_ERROR;
    }
    cm_galist_init(stmt->pl_ref_entry, &stmt->vmc, vmc_alloc);
    stmt->resource_inuse = GS_TRUE;
    stmt->has_pl_ref_dc = GS_TRUE;
    return GS_SUCCESS;
}

status_t sql_init_pl_ref_dc(sql_stmt_t *stmt)
{
    if (stmt->pl_ref_entry != NULL) {
        return GS_SUCCESS;
    }
    return sql_init_ref_dc_list(stmt);
}

static inline void init_stmt(sql_stmt_t *stmt)
{
    stmt->total_rows = 0;
    stmt->batch_rows = 0;
    stmt->actual_batch_errs = 0;
    stmt->pairs_pos = 0;
    stmt->mark_pending_done = GS_FALSE;
    stmt->param_info.paramset_offset = 0;
    stmt->dc_invalid = GS_FALSE;
    stmt->default_info.default_on = GS_FALSE;
    stmt->is_success = GS_FALSE;
    stmt->trace_disabled = GS_FALSE;
    {
        stmt->param_info.param_buf = NULL;
        stmt->param_info.param_types = NULL;
        stmt->param_info.params = NULL;
        stmt->params_ready = GS_FALSE;
        stmt->param_info.param_offset = 0;
        stmt->param_info.param_strsize = 0;
    }
}

void sql_unlock_lnk_tabs(sql_stmt_t *stmt)
{
    if (stmt->context == NULL || stmt->context->has_dblink == GS_FALSE) {
        return;
    }
}

static void sql_release_exec_resource(sql_stmt_t *stmt)
{
    if (stmt->context == NULL) {
        return;
    }
    if (stmt->eof) {
        sql_unlock_lnk_tabs(stmt);
        sql_release_resource(stmt, GS_FALSE);
        sql_dec_active_stmts(stmt);
    }
    if (IS_DDL(stmt) || IS_DCL(stmt)) {
        sql_release_context(stmt);
    }
    stmt->fexec_info.first_exec_vars = NULL;
}

static status_t sql_init_exec_data(sql_stmt_t *stmt)
{
    init_stmt(stmt);
    sql_release_resource(stmt, GS_FALSE);
    reset_tls_plc_error();

    /* reset reserved values */
    stmt->v_sysdate = SQL_UNINITIALIZED_DATE;
    stmt->v_systimestamp = SQL_UNINITIALIZED_TSTAMP;
    GS_RETURN_IFERR(sql_init_sequence(stmt));
    GS_RETURN_IFERR(sql_init_first_exec_info(stmt));
    GS_RETURN_IFERR(sql_init_trigger_list(stmt));
    return sql_init_pl_ref_dc(stmt);
}

status_t sql_execute(sql_stmt_t *stmt)
{
    status_t status = GS_SUCCESS;
    timeval_t tv_begin;

    (void)cm_gettimeofday(&tv_begin);
    stmt->status = STMT_STATUS_EXECUTING;
    if (sql_init_exec_data(stmt) != GS_SUCCESS) {
        sql_release_exec_resource(stmt);
        return GS_ERROR;
    }

    bool32 stmt_eof = stmt->eof;
    /* must do it at last!!! */
    if (stmt_eof) {
        stmt->eof = GS_FALSE;
        sql_inc_active_stmts(stmt);
    }
    sql_inc_ctx_ref(stmt, stmt->context);

    if (sql_check_privilege(stmt, GS_FALSE) != GS_SUCCESS) {
        sql_dec_ctx_ref(stmt, stmt->context);
        if (stmt_eof) {
            sql_dec_active_stmts(stmt);
        }
        sql_release_exec_resource(stmt);
        cm_reset_error();
        GS_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
        return GS_ERROR;
    }

    /* do execute */
    if (SQL_TYPE(stmt) < SQL_TYPE_DML_CEIL) {
        status = sql_execute_dml_and_send(stmt);
        if (stmt->eof && status == GS_SUCCESS && NEED_TRACE(stmt)) {
            status = sql_trace_dml_and_send(stmt);
        }
    } else if (SQL_TYPE(stmt) < SQL_TYPE_DCL_CEIL) {
        knl_panic(SQL_TYPE(stmt) != SQL_TYPE_ANONYMOUS_BLOCK);
        status = sql_execute_dcl(stmt);
        stmt->eof = GS_TRUE;
    } else if (SQL_TYPE(stmt) < SQL_TYPE_DDL_CEIL) {
        status = sql_execute_ddl(stmt);
        stmt->eof = GS_TRUE;
    }

    stmt->status = STMT_STATUS_EXECUTED;

    if (status == GS_SUCCESS) {
        stmt->is_success = GS_TRUE;
        GS_LOG_DEBUG_INF("Execute SQL successfully");
    }

    sql_release_exec_resource(stmt);
    return status;
}

status_t sql_init_first_exec_info(sql_stmt_t *stmt)
{
    /* init first execute vars */
    uint32 count = stmt->context->fexec_vars_cnt;
    if (count != 0) {
        // the memory of first executable variants comes from stack, as well as
        // the memory of var-length variants, such as VARCHAR, BINARY, RAW
        // see @sql_copy_first_exec_var
        GS_RETURN_IFERR(cm_stack_alloc(stmt->session->stack,
                                       sizeof(variant_t) * count + stmt->context->fexec_vars_bytes,
                                       (void **)&stmt->fexec_info.first_exec_vars));
        sql_reset_first_exec_vars(stmt);
    } else {
        stmt->fexec_info.first_exec_vars = NULL;
    }

    /* init first execute subs */
    stmt->fexec_info.first_exec_subs = NULL;

    return GS_SUCCESS;
}

status_t sql_get_table_value(sql_stmt_t *stmt, var_column_t *v_col, variant_t *value)
{
    sql_table_cursor_t *tab_cur = NULL;
    sql_cursor_t *cursor = SQL_CURR_CURSOR(stmt);

    if (SECUREC_UNLIKELY(stmt->is_explain)) {
        value->is_null = GS_TRUE;
        return GS_SUCCESS;
    }

    /* get value from par cursor */
    cursor = sql_get_proj_cursor(cursor);
    /* hit scenario: multi table update, check cond column expr var_column_t->tab always 0 */
    if (SECUREC_UNLIKELY(stmt->is_check && cursor->table_count > 1)) {
        return sql_get_ddm_kernel_value(stmt, &g_init_table, stmt->direct_knl_cursor, v_col, value);
    }

    GS_RETURN_IFERR(sql_get_ancestor_cursor(cursor, v_col->ancestor, &cursor));
    tab_cur = &cursor->tables[v_col->tab];
    if (tab_cur->table == NULL) {
        GS_THROW_ERROR(ERR_ASSERT_ERROR, "table cannot be NULL");
        return GS_ERROR;
    }

    if (SECUREC_UNLIKELY(cursor->table_count != 1 && tab_cur->table->plan_id > cursor->last_table)) {
        value->type = GS_TYPE_COLUMN;
        value->is_null = GS_FALSE;
        return GS_SUCCESS;
    }

    knl_panic(!GS_IS_SUBSELECT_TABLE(tab_cur->table->type));
    return sql_get_ddm_kernel_value(stmt, tab_cur->table, tab_cur->knl_cur, v_col, value);
}

status_t sql_get_rowid(sql_stmt_t *stmt, var_rowid_t *rowid, variant_t *value)
{
    rowid_t row_id;
    sql_table_cursor_t *tab_cur = NULL;

    CM_POINTER2(stmt, value);
    sql_cursor_t *cursor = SQL_CURR_CURSOR(stmt);

    GS_RETURN_IFERR(sql_get_ancestor_cursor(cursor, rowid->ancestor, &cursor));
    tab_cur = &cursor->tables[rowid->tab_id];

    if (cursor->table_count > 1 && tab_cur->table->plan_id > cursor->last_table) {
        value->type = GS_TYPE_COLUMN;
        value->is_null = GS_FALSE;
        return GS_SUCCESS;
    }

    if (tab_cur->knl_cur->eof) {
        value->type = GS_TYPE_STRING;
        value->is_null = GS_TRUE;
        return GS_SUCCESS;
    }

    value->type = GS_TYPE_STRING;
    value->is_null = GS_FALSE;
    row_id = tab_cur->knl_cur->rowid;

    // hit hash join fill null record
    if (sql_is_invalid_rowid(&row_id, tab_cur->table->entry->dc.type)) {
        value->type = GS_TYPE_STRING;
        value->is_null = GS_TRUE;
        return GS_SUCCESS;
    }

    if (sql_push(stmt, GS_MAX_ROWID_BUFLEN, (void **)&value->v_text.str) != GS_SUCCESS) {
        return GS_ERROR;
    }

    sql_rowid2str(&row_id, value, tab_cur->table->entry->dc.type);

    SQL_POP(stmt);
    return GS_SUCCESS;
}

status_t sql_get_rowscn(sql_stmt_t *stmt, var_rowid_t *rowid, variant_t *value)
{
    CM_POINTER2(stmt, value);
    sql_cursor_t *cursor = SQL_CURR_CURSOR(stmt);
    sql_table_cursor_t *tab_cur = NULL;
    GS_RETURN_IFERR(sql_get_ancestor_cursor(cursor, rowid->ancestor, &cursor));
    tab_cur = &cursor->tables[rowid->tab_id];

    if (cursor->table_count > 1 && tab_cur->table->plan_id > cursor->last_table) {
        value->type = GS_TYPE_COLUMN;
        value->is_null = GS_FALSE;
        return GS_SUCCESS;
    }

    if (tab_cur->knl_cur->eof) {
        value->type = GS_TYPE_STRING;
        value->is_null = GS_TRUE;
        return GS_SUCCESS;
    }

    // revers?
    value->type = GS_TYPE_BIGINT;
    value->is_null = GS_FALSE;
    value->v_bigint = (int64)tab_cur->knl_cur->scn;

    return GS_SUCCESS;
}

status_t sql_get_rownum(sql_stmt_t *stmt, variant_t *value)
{
    sql_cursor_t *cursor = NULL;
    CM_POINTER2(stmt, value);

    cursor = SQL_CURR_CURSOR(stmt);
    // rownum is judged only on the last join table
    if (cursor->table_count > 1 && cursor->last_table < cursor->table_count - 1) {
        value->type = GS_TYPE_COLUMN;
        value->is_null = GS_FALSE;
        return GS_SUCCESS;
    }

    value->type = GS_TYPE_INTEGER;
    value->is_null = GS_FALSE;
    value->v_int = (int32)cursor->rownum;

    return GS_SUCCESS;
}

status_t sql_execute_directly(session_t *session, text_t *sql, sql_type_t *type, bool32 chk_priv)
{
    sql_stmt_t *stmt = NULL;
    status_t status;
    source_location_t loc;

    if (sql->len == 0) {
        return GS_SUCCESS;
    }

    GS_RETURN_IFERR(sql_get_unnamed_stmt(session, &session->current_stmt));

    /* prepare stmt */
    stmt = session->current_stmt;
    sql_release_lob_info(stmt);
    sql_release_resource(stmt, GS_TRUE);
    sql_release_context(stmt);

    stmt->is_explain = GS_FALSE;
    if (sql->str[(sql->len - 1)] == ';') {
        sql->len--;
    }
    loc.line = 1;
    loc.column = 1;

    if (sql_parse(stmt, sql, &loc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    stmt->status = STMT_STATUS_PREPARED;

    if (type != NULL) {
        *type = stmt->context->type;
    }

    /* execute and reply to psql */
    stmt->chk_priv = (bool8)chk_priv;
    status = sql_execute(stmt);
    stmt->chk_priv = GS_TRUE;
    return status;
}

static inline void sql_reset_sess_stmt(session_t *session, sql_stmt_t *save_curr_stmt, sql_stmt_t *save_unnamed_stmt)
{
    context_ctrl_t *ctrl = NULL;
    if (session->unnamed_stmt != NULL && session->unnamed_stmt->context != NULL) {
        ctrl = &session->unnamed_stmt->context->ctrl;
        cm_spin_lock(&ctrl->lock, NULL);
        ctrl->valid = GS_FALSE;
        cm_spin_unlock(&ctrl->lock);
    }

    sql_free_stmt(session->unnamed_stmt);
    session->current_stmt = save_curr_stmt;
    session->unnamed_stmt = save_unnamed_stmt;
}
status_t sql_execute_check(knl_handle_t handle, text_t *sql, bool32 *exist)
{
    session_t *session = (session_t *)handle;

    sql_stmt_t *save_curr_stmt = session->current_stmt;
    sql_stmt_t *save_unnamed_stmt = session->unnamed_stmt;
    char *send_pack_buf = NULL;
    uint32 send_pack_size;
    errno_t errcode;

    *exist = GS_FALSE;

    if (session->unnamed_stmt != NULL) {
        session->unnamed_stmt = NULL;
    }

    /* save prepared send pack */
    send_pack_size = session->send_pack->head->size;
    GS_RETURN_IFERR(sql_push(save_curr_stmt, send_pack_size, (void **)&send_pack_buf));
    errcode = memcpy_s(send_pack_buf, send_pack_size, session->send_pack->buf, send_pack_size);
    if (errcode != EOK) {
        GS_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        SQL_POP(save_curr_stmt);
        return GS_ERROR;
    }

    if (sql_execute_directly(session, sql, NULL, GS_FALSE) != GS_SUCCESS) {
        sql_reset_sess_stmt(session, save_curr_stmt, save_unnamed_stmt);
        SQL_POP(save_curr_stmt);
        return GS_ERROR;
    }
    errno_t ret = memcpy_s(session->send_pack->buf, send_pack_size, send_pack_buf, send_pack_size);
    if (ret != EOK) {
        sql_reset_sess_stmt(session, save_curr_stmt, save_unnamed_stmt);
        SQL_POP(save_curr_stmt);
        return GS_ERROR;
    }
    /* restore prepared send pack */
    SQL_POP(save_curr_stmt);

    if (session->unnamed_stmt->total_rows != 0) {
        *exist = GS_TRUE;
    }

    sql_reset_sess_stmt(session, save_curr_stmt, save_unnamed_stmt);
    return GS_SUCCESS;
}

status_t sql_check_exist_cols_type(sql_stmt_t *stmt, uint32 col_type, bool32 *exist)
{
    status_t status;
    text_t sql;
    char *clause = NULL;
    uint32 len = GS_EXIST_COL_TYPE_SQL_LEN + 2 * GS_MAX_NAME_LEN;
    errno_t iret_len;

    GS_RETURN_IFERR(sql_push(stmt, len, (void **)&clause));

    iret_len = snprintf_s(clause, len, len - 1, GS_EXIST_COL_TYPE_SQL_FORMAT, SYS_USER_NAME, SYS_COLUMN_TABLE_NAME,
                          col_type);
    if (iret_len == -1) {
        SQL_POP(stmt);
        GS_THROW_ERROR(ERR_SYSTEM_CALL, iret_len);
        return GS_ERROR;
    }

    sql.len = (uint32)iret_len;
    sql.str = clause;
    status = sql_execute_check((void *)stmt->session, &sql, exist);
    SQL_POP(stmt);

    return status;
}

status_t sql_alloc_mem_from_dc(void *mem, uint32 size, void **buf)
{
    if (dc_alloc_mem(&g_instance->kernel.dc_ctx, (memory_context_t *)mem, size, buf) != GS_SUCCESS) {
        return GS_ERROR;
    }

    errno_t err = memset_s(*buf, size, 0, size);
    MEMS_RETURN_IFERR(err);

    return GS_SUCCESS;
}

void sql_convert_column_t(knl_column_t *column, knl_column_def_t *column_def)
{
    /* mainly used */
    column_def->name.str = column->name;
    column_def->name.len = (uint32)strlen(column->name);

    column_def->typmod.datatype = column->datatype;
    column_def->typmod.size = column->size;
    column_def->typmod.precision = column->precision;
    column_def->typmod.scale = column->scale;
    if (GS_IS_STRING_TYPE(column->datatype)) {
        column_def->typmod.is_char = KNL_COLUMN_IS_CHARACTER(column);
    }
    if (KNL_COLUMN_HAS_QUOTE(column)) {
        column_def->has_quote = GS_TRUE;
    }
    column_def->default_text.str = column->default_text.str;
    column_def->default_text.len = column->default_text.len;

    return;
}

status_t sql_clone_default_expr_tree(session_t *session, memory_context_t *memory, expr_tree_t *expr_tree_src,
                                     void **expr_tree, expr_tree_t *expr_update_tree_src, void **expr_update_tree)
{
    status_t status;

    status = sql_clone_expr_tree(memory, expr_tree_src, (expr_tree_t **)expr_tree, sql_alloc_mem_from_dc);
    if (status != GS_SUCCESS) {
        return status;
    }

    if (expr_update_tree_src != NULL) {
        status = sql_clone_expr_tree(memory, expr_update_tree_src, (expr_tree_t **)expr_update_tree,
                                     sql_alloc_mem_from_dc);
        if (status != GS_SUCCESS) {
            return status;
        }
    }

    return GS_SUCCESS;
}

static status_t sql_verify_virtual_column_expr(sql_verifier_t *verf, knl_handle_t entity, expr_tree_t *expr_tree)
{
    sql_table_t table;
    sql_table_entry_t table_entry;

    MEMS_RETURN_IFERR(memset_s(&table, sizeof(sql_table_t), 0, sizeof(sql_table_t)));

    table_entry.dc.type = DICT_TYPE_TABLE;
    table_entry.dc.handle = entity;
    table.entry = &table_entry;
    knl_table_desc_t *desc = knl_get_table(&table_entry.dc);

    table_entry.dblink.len = 0;
    table_entry.user.len = 0;
    cm_str2text(desc->name, &table_entry.name);

    table.id = 0;
    table.type = NORMAL_TABLE;
    table.name.value = table_entry.name;

    verf->is_check_cons = GS_FALSE;
    verf->table = &table;
    verf->excl_flags = SQL_EXCL_AGGR | SQL_EXCL_STAR | SQL_EXCL_SUBSELECT | SQL_EXCL_BIND_PARAM | SQL_EXCL_PRIOR |
                       SQL_EXCL_JOIN | SQL_EXCL_ROWNUM | SQL_EXCL_ROWID | SQL_EXCL_DEFAULT | SQL_EXCL_ROWSCN |
                       SQL_EXCL_SEQUENCE | SQL_EXCL_ROWNODEID;

    return sql_verify_expr(verf, expr_tree);
}

status_t sql_verify_column_expr_tree(sql_verifier_t *verf, knl_column_t *column, expr_tree_t *expr_tree_src,
                                     expr_tree_t *expr_update_tree_src)
{
    knl_column_def_t column_def;
    sql_convert_column_t(column, &column_def);

    verf->column = &column_def;
    verf->excl_flags = SQL_DEFAULT_EXCL;

    if (sql_verify_column_default_expr(verf, expr_tree_src, &column_def) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (expr_update_tree_src != NULL) {
        if (sql_verify_column_default_expr(verf, expr_update_tree_src, &column_def) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t sql_ajust_node_type(visit_assist_t *va, expr_node_t **node)
{
    if ((*node)->type == EXPR_NODE_COLUMN) {
        (*node)->type = EXPR_NODE_DIRECT_COLUMN;
    }

    return GS_SUCCESS;
}

static status_t sql_create_expr_tree_from_text(sql_stmt_t *stmt, knl_column_t *column, expr_tree_t **expr_tree,
                                               expr_tree_t **expr_update_tree, text_t parse_text)
{
    typmode_t col_datatype;
    lex_t *lex = NULL;
    word_t word;
    status_t status;
    uint32 src_lex_flags;

    CM_POINTER4(stmt, column, expr_tree, expr_update_tree);

    word.id = RES_WORD_DEFAULT;
    lex = stmt->session->lex;
    lex->infer_numtype = USE_NATIVE_DATATYPE;
    src_lex_flags = lex->flags;

    word.type = WORD_TYPE_RESERVED;
    word.begin_addr = parse_text.str;
    word.loc.line = 1;
    word.loc.column = 1;
    word.text.value.str = parse_text.str;
    word.text.value.len = parse_text.len;
    word.text.loc.line = 1;
    word.text.loc.column = 1;

    if (lex_push(lex, &word.text) != GS_SUCCESS) {
        return GS_ERROR;
    }

    lex->flags = LEX_WITH_ARG | LEX_WITH_OWNER;
    status = sql_create_expr_until(stmt, expr_tree, &word);
    if (status != GS_SUCCESS) {
        lex_pop(lex);
        lex->flags = src_lex_flags;
        return status;
    }

    // add cast node for normal column
    if (!KNL_COLUMN_IS_VIRTUAL(column)) {
        col_datatype.datatype = column->datatype;
        col_datatype.size = column->size;
        col_datatype.precision = column->precision;
        col_datatype.scale = column->scale;
        col_datatype.is_array = KNL_COLUMN_IS_ARRAY(column);

        if (sql_build_cast_expr(stmt, TREE_LOC(*expr_tree), *expr_tree, &col_datatype, expr_tree) != GS_SUCCESS) {
            lex_pop(lex);
            lex->flags = src_lex_flags;
            GS_SRC_THROW_ERROR(LEX_LOC, ERR_CAST_TO_COLUMN, "default value", T2S(&word.text.value));
            return GS_ERROR;
        }
    } else {
        visit_assist_t va;
        sql_init_visit_assist(&va, stmt, NULL);
        GS_RETURN_IFERR(visit_expr_tree(&va, *expr_tree, sql_ajust_node_type));
    }

    if (word.id == KEY_WORD_ON) {
        status = lex_expected_fetch_word(lex, "UPDATE");
        if (status != GS_SUCCESS) {
            lex_pop(lex);
            lex->flags = src_lex_flags;
            return status;
        }

        lex->flags = LEX_WITH_ARG | LEX_WITH_OWNER;
        status = sql_create_expr_until(stmt, expr_update_tree, &word);
        if (status != GS_SUCCESS) {
            lex_pop(lex);
            lex->flags = src_lex_flags;
            return status;
        }

        if (GS_SUCCESS != sql_build_cast_expr(stmt, TREE_LOC(*expr_update_tree), *expr_update_tree, &col_datatype,
                                              expr_update_tree)) {
            lex_pop(lex);
            lex->flags = src_lex_flags;
            GS_SRC_THROW_ERROR(LEX_LOC, ERR_CAST_TO_COLUMN, "update default value", T2S(&word.text.value));
            return GS_ERROR;
        }
    }

    lex_pop(lex);
    lex->flags = src_lex_flags;
    if (word.type != WORD_TYPE_EOF) {
        GS_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "end of expression text expected but %s found",
                              W2S(&word));
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static inline void sql_inv_ctx_and_free_stmt(sql_stmt_t *stmt)
{
    if (stmt->context != NULL) {
        context_ctrl_t *ctrl = &stmt->context->ctrl;
        cm_spin_lock(&ctrl->lock, NULL);
        ctrl->valid = GS_FALSE;
        cm_spin_unlock(&ctrl->lock);
    }
    sql_free_stmt(stmt);
}

static status_t sql_prepare_new_stmt(session_t *session)
{
    status_t status;
    /* get a new stmt */
    if (sql_alloc_stmt(session, &session->current_stmt) != GS_SUCCESS) {
        return GS_ERROR;
    }

    status = sql_alloc_context(session->current_stmt);
    if (status != GS_SUCCESS) {
        sql_inv_ctx_and_free_stmt(session->current_stmt);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

static inline void sql_restore_session(session_t *session, sql_stmt_t *curr_stmt, sql_stmt_t *uname_stmt, lex_t *lex)
{
    session->current_stmt = curr_stmt;
    session->unnamed_stmt = uname_stmt;
    session->lex = lex;
}

status_t sql_parse_default_from_text(knl_handle_t handle, knl_handle_t dc_entity, knl_handle_t column,
                                     memory_context_t *memory, void **expr_tree, void **expr_update_tree,
                                     text_t parse_text)
{
    status_t status = GS_ERROR;
    knl_column_t *column_info = (knl_column_t *)column;
    session_t *session = (session_t *)handle;
    sql_stmt_t *save_stmt = session->current_stmt;
    sql_stmt_t *save_unnamed_stmt = session->unnamed_stmt;
    lex_t *save_lex = session->lex;
    expr_tree_t *expr_tree_src = NULL;
    expr_tree_t *expr_update_tree_src = NULL;
    saved_schema_t schema;

    (*expr_tree) = (*expr_update_tree) = NULL;

    if (parse_text.len == 0) {
        return GS_SUCCESS;
    }

    if (sql_prepare_new_stmt(session) != GS_SUCCESS) {
        sql_restore_session(session, save_stmt, save_unnamed_stmt, save_lex);
        return GS_ERROR;
    }
    sql_stmt_t *parse_expr_stmt = session->current_stmt;

    do {
        /* create the default expr tree */
        parse_expr_stmt->context->type = SQL_TYPE_CREATE_EXPR_FROM_TEXT;
        GS_BREAK_IF_ERROR(sql_create_expr_tree_from_text(parse_expr_stmt, column_info, &expr_tree_src,
                                                         &expr_update_tree_src, parse_text));

        (void)sql_switch_schema_by_uid(parse_expr_stmt, ((dc_entity_t *)dc_entity)->entry->uid, &schema);
        sql_verifier_t verf = { 0 };
        verf.stmt = parse_expr_stmt;
        verf.context = parse_expr_stmt->context;
        verf.do_expr_optmz = GS_FALSE;
        verf.from_table_define = GS_TRUE;
        /* verify the default expr tree */
        if (KNL_COLUMN_IS_VIRTUAL(column_info)) {
            status = sql_verify_virtual_column_expr(&verf, dc_entity, expr_tree_src);
        } else {
            status = sql_verify_column_expr_tree(&verf, column_info, expr_tree_src, expr_update_tree_src);
        }
        sql_restore_schema(parse_expr_stmt, &schema);
        GS_BREAK_IF_ERROR(status);

        /* deeply copy the default expr tree */
        status = sql_clone_default_expr_tree(session, memory, expr_tree_src, expr_tree, expr_update_tree_src,
                                             expr_update_tree);
    } while (0);

    /* finally, free stmt and */
    sql_inv_ctx_and_free_stmt(parse_expr_stmt);
    sql_restore_session(session, save_stmt, save_unnamed_stmt, save_lex);
    return status;
}

status_t sql_verify_default_from_text(knl_handle_t handle, knl_handle_t column_handle, text_t parse_text)
{
    status_t status = GS_ERROR;
    knl_column_t *column = (knl_column_t *)column_handle;
    session_t *session = (session_t *)handle;
    sql_stmt_t *save_stmt = session->current_stmt;
    sql_stmt_t *save_unnamed_stmt = session->unnamed_stmt;
    lex_t *save_lex = session->lex;
    expr_tree_t *expr_tree_src = NULL;
    expr_tree_t *expr_update_tree_src = NULL;

    if (parse_text.len == 0) {
        return GS_SUCCESS;
    }

    if (sql_prepare_new_stmt(session) != GS_SUCCESS) {
        sql_restore_session(session, save_stmt, save_unnamed_stmt, save_lex);
        return GS_ERROR;
    }
    sql_stmt_t *parse_expr_stmt = session->current_stmt;

    do {
        /* create the default expr tree */
        parse_expr_stmt->context->type = SQL_TYPE_CREATE_EXPR_FROM_TEXT;
        GS_BREAK_IF_ERROR(
            sql_create_expr_tree_from_text(parse_expr_stmt, column, &expr_tree_src, &expr_update_tree_src, parse_text));

        sql_verifier_t verf = { 0 };
        verf.stmt = parse_expr_stmt;
        verf.context = parse_expr_stmt->context;
        verf.do_expr_optmz = GS_FALSE;
        verf.from_table_define = GS_TRUE;
        /* verify the default expr tree */
        knl_panic(!KNL_COLUMN_IS_VIRTUAL(column));
        status = sql_verify_column_expr_tree(&verf, column, expr_tree_src, expr_update_tree_src);
        GS_BREAK_IF_ERROR(status);
    } while (0);

    /* finally, free stmt and */
    sql_inv_ctx_and_free_stmt(parse_expr_stmt);
    sql_restore_session(session, save_stmt, save_unnamed_stmt, save_lex);
    return status;
}

status_t sql_create_cond_tree_from_text(sql_stmt_t *stmt, text_t *text, cond_tree_t **tree)
{
    lex_t *lex = NULL;
    word_t word;
    uint32 src_lex_flags;

    CM_POINTER3(stmt, text, tree);

    word.id = 0xFFFFFFFF;
    lex = stmt->session->lex;
    src_lex_flags = lex->flags;

    word.type = WORD_TYPE_BRACKET;
    word.begin_addr = text->str;
    word.loc.line = 1;
    word.loc.column = 1;
    word.text.value.str = text->str;
    word.text.value.len = text->len;
    word.text.loc.line = 1;
    word.text.loc.column = 1;

    if (lex_push(lex, &word.text) != GS_SUCCESS) {
        return GS_ERROR;
    }

    lex->flags = LEX_WITH_ARG | LEX_WITH_OWNER;
    if (sql_create_cond_until(stmt, tree, &word) != GS_SUCCESS) {
        lex_pop(lex);
        lex->flags = src_lex_flags;
        return GS_ERROR;
    }
    lex_pop(lex);
    lex->flags = src_lex_flags;
    if (word.type != WORD_TYPE_EOF) {
        GS_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "end of condition text expected but %s found",
                              W2S(&word));
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t sql_parse_check_from_text(knl_handle_t handle, text_t *cond_text, knl_handle_t entity,
                                   memory_context_t *memory, void **cond_tree)
{
    return GS_ERROR;
}

void sql_init_session(session_t *session)
{
    session->sender = &g_instance->sql.sender;
    session->knl_session.match_cond = sql_match_cond;
    if (SECUREC_UNLIKELY(session->knl_session.temp_pool == NULL)) {
        session->knl_session.temp_pool = &g_instance->kernel.temp_pool[0];
        session->knl_session.temp_mtrl->pool = &g_instance->kernel.temp_pool[0];
    }
}

/* decode params efficiently:
types | total_len flags param ... param | ... | total_len flags param ... param
*/
static status_t sql_decode_params_eff(sql_stmt_t *stmt, char *param_buf, uint32 *actual_len)
{
    uint32 i, offset, count;
    uint8 *flags = NULL;
    char *data = NULL;
    sql_param_t *param = NULL;
    variant_t *value = NULL;
    text_t num_text;

    stmt->param_info.outparam_cnt = 0;

    count = stmt->context->params->count;

    // total_len
    offset = sizeof(uint32);
    CM_CHECK_RECV_PACK_FREE(stmt->session->recv_pack, sizeof(uint32));
    stmt->session->recv_pack->offset += sizeof(uint32);

    // flags
    offset += CM_ALIGN4(count);
    CM_CHECK_RECV_PACK_FREE(stmt->session->recv_pack, CM_ALIGN4(count));
    stmt->session->recv_pack->offset += CM_ALIGN4(count);
    flags = (uint8 *)(param_buf + sizeof(uint32));

    // bound_value
    for (i = 0; i < count; i++) {
        param = &stmt->param_info.params[i];
        param->direction = cs_get_param_direction(flags[i]);
        if (param->direction == GS_OUTPUT_PARAM || param->direction == GS_INOUT_PARAM) {
            stmt->param_info.outparam_cnt++;
        }

        value = &param->value;
        value->is_null = cs_get_param_isnull(flags[i]);
        value->type = (stmt->param_info.param_types[i] == GS_TYPE_UNKNOWN)
                          ? GS_TYPE_UNKNOWN
                          : ((gs_type_t)stmt->param_info.param_types[i] + GS_TYPE_BASE);

        if (param->direction == GS_OUTPUT_PARAM || value->is_null) {
            value->is_null = GS_TRUE;
            continue;
        }

        data = (char *)(param_buf + offset);

        switch (value->type) {
            case GS_TYPE_INTEGER:
                offset += sizeof(int32);
                CM_CHECK_RECV_PACK_FREE(stmt->session->recv_pack, sizeof(int32));
                VALUE(int32, value) = *(int32 *)data;
                stmt->session->recv_pack->offset += sizeof(int32);
                break;

            case GS_TYPE_BIGINT:
            case GS_TYPE_DATE:
            case GS_TYPE_TIMESTAMP:
            case GS_TYPE_TIMESTAMP_TZ_FAKE:
            case GS_TYPE_TIMESTAMP_LTZ:
                offset += sizeof(int64);
                CM_CHECK_RECV_PACK_FREE(stmt->session->recv_pack, sizeof(int64));
                VALUE(int64, value) = *(int64 *)data;
                stmt->session->recv_pack->offset += sizeof(int64);
                break;

            case GS_TYPE_REAL:
                offset += sizeof(double);
                CM_CHECK_RECV_PACK_FREE(stmt->session->recv_pack, sizeof(double));
                VALUE(double, value) = *(double *)data;
                stmt->session->recv_pack->offset += sizeof(double);
                break;

            case GS_TYPE_NUMBER:
            case GS_TYPE_DECIMAL:
            case GS_TYPE_NUMBER2:
                offset += sizeof(uint32) + CM_ALIGN4(*(uint32 *)data);
                CM_CHECK_RECV_PACK_FREE(stmt->session->recv_pack, sizeof(uint32) + CM_ALIGN4(*(uint32 *)data));
                num_text.str = data + sizeof(uint32);
                num_text.len = *(uint32 *)data;
                stmt->param_info.param_strsize += num_text.len;
                GS_RETURN_IFERR(cm_text_to_dec(&num_text, &VALUE(dec8_t, value)));
                stmt->session->recv_pack->offset += sizeof(uint32) + CM_ALIGN4(*(uint32 *)data);
                break;

            case GS_TYPE_BINARY:
            case GS_TYPE_VARBINARY:
            case GS_TYPE_RAW:
                value->v_bin.is_hex_const = GS_FALSE;
                /* fall-through */
            case GS_TYPE_CHAR:
            case GS_TYPE_VARCHAR:
            case GS_TYPE_STRING:
                offset += sizeof(uint32) + CM_ALIGN4(*(uint32 *)data);
                CM_CHECK_RECV_PACK_FREE(stmt->session->recv_pack, sizeof(uint32) + CM_ALIGN4(*(uint32 *)data));
                value->v_text.len = *(uint32 *)data;
                stmt->param_info.param_strsize += value->v_text.len;
                value->v_text.str = data + sizeof(uint32);

                if (g_instance->sql.enable_empty_string_null) {
                    value->is_null = (value->v_text.len == 0);
                }
                stmt->session->recv_pack->offset += sizeof(uint32) + CM_ALIGN4(*(uint32 *)data);
                break;

            case GS_TYPE_CLOB:
            case GS_TYPE_BLOB:
            case GS_TYPE_IMAGE:
            case GS_TYPE_ARRAY:
                return GS_ERROR;

            case GS_TYPE_BOOLEAN:
                offset += sizeof(bool32);
                CM_CHECK_RECV_PACK_FREE(stmt->session->recv_pack, sizeof(bool32));
                VALUE(bool32, value) = *(bool32 *)data;
                stmt->session->recv_pack->offset += sizeof(bool32);
                break;

            case GS_TYPE_INTERVAL_YM:
                return GS_ERROR;

            case GS_TYPE_INTERVAL_DS:
                return GS_ERROR;

            case GS_TYPE_UINT32:
                offset += sizeof(uint32);
                CM_CHECK_RECV_PACK_FREE(stmt->session->recv_pack, sizeof(uint32));
                VALUE(uint32, value) = *(uint32 *)data;
                stmt->session->recv_pack->offset += sizeof(uint32);
                break;

            case GS_TYPE_TIMESTAMP_TZ:
                offset += sizeof(timestamp_tz_t);
                CM_CHECK_RECV_PACK_FREE(stmt->session->recv_pack, sizeof(timestamp_tz_t));
                VALUE(timestamp_tz_t, value) = *(timestamp_tz_t *)data;
                stmt->session->recv_pack->offset += sizeof(timestamp_tz_t);
                break;

            default:
                GS_THROW_ERROR(ERR_UNSUPPORT_DATATYPE, get_datatype_name_str(value->type));
                return GS_ERROR;
        }
    }

    *actual_len = offset;
    return GS_SUCCESS;
}

static inline status_t sql_read_local_params(sql_stmt_t *stmt)
{
    uint32 offset;
    GS_RETSUC_IFTRUE(stmt->context->params == NULL);
    GS_RETSUC_IFTRUE(stmt->context->params->count == 0);

    /* check whether remain pack len if less than sizeof(uint32) */
    char *param_buf = NULL;
    uint32 total_len, actual_len;
    status_t status;

    if (stmt->session->pipe != NULL) {
        CM_CHECK_RECV_PACK_FREE(stmt->session->recv_pack, sizeof(uint32));
        param_buf = CS_READ_ADDR(stmt->session->recv_pack);
    } else {
        param_buf = stmt->param_info.param_buf + stmt->param_info.param_offset;
    }

    if (param_buf == NULL) {
        return GS_SUCCESS;
    }

    offset = stmt->session->recv_pack->offset;

    total_len = *(uint32 *)param_buf;
    CM_CHECK_RECV_PACK_FREE(stmt->session->recv_pack, total_len);
    actual_len = 0;

    status = sql_decode_params_eff(stmt, param_buf, &actual_len);

    if (status == GS_SUCCESS && total_len != actual_len) {
        GS_THROW_ERROR(ERR_INVALID_TCP_PACKET, "decode params", total_len, actual_len);
        status = GS_ERROR;
    }

    stmt->params_ready = (status == GS_SUCCESS);

    // record param offset before decode.
    stmt->param_info.param_offset = offset;

    return status;
}

status_t sql_read_params(sql_stmt_t *stmt)
{
    if (stmt->session->proto_type != PROTO_TYPE_GS) {
        return GS_SUCCESS;
    }

    GS_RETURN_IFERR(sql_read_local_params(stmt));

    return GS_SUCCESS;
}

status_t sql_fill_null_params(sql_stmt_t *stmt)
{
    uint32 i, count;

    count = stmt->context->params->count;
    if (count == 0) {
        return GS_SUCCESS;
    }

    GS_RETURN_IFERR(sql_alloc_params_buf(stmt));

    for (i = 0; i < count; i++) {
        stmt->param_info.params[i].direction = GS_INPUT_PARAM;
        stmt->param_info.params[i].value.is_null = GS_TRUE;
        stmt->param_info.params[i].value.type = GS_TYPE_STRING;
    }

    return GS_SUCCESS;
}

status_t sql_keep_params(sql_stmt_t *stmt)
{
    uint32 types_cost, value_cost;
    char *param_buf = stmt->param_info.param_buf;
    char *param_types = stmt->param_info.param_types;

    if (stmt->context->params->count == 0) {
        return GS_SUCCESS;
    }

    if (stmt->session->call_version >= CS_VERSION_7) {
        types_cost = CM_ALIGN4(stmt->context->params->count);
        GS_RETURN_IFERR(vmc_alloc(&stmt->vmc, types_cost, (void **)&stmt->param_info.param_types));
        MEMS_RETURN_IFERR(memcpy_sp(stmt->param_info.param_types, types_cost, param_types, types_cost));
    }

    value_cost = *(uint32 *)stmt->param_info.param_buf;
    GS_RETURN_IFERR(vmc_alloc(&stmt->vmc, value_cost, (void **)&stmt->param_info.param_buf));
    MEMS_RETURN_IFERR(memcpy_sp(stmt->param_info.param_buf, value_cost, param_buf, value_cost));

    return GS_SUCCESS;
}

/* decode params efficiently:
types | total_len flags param ... param | ... | total_len flags param ... param
*/
static status_t sql_decode_kept_params_eff(sql_stmt_t *stmt, char *param_buf)
{
    uint32 i, offset, count;
    int8 *types = NULL;
    uint8 *flags = NULL;
    char *data = NULL;
    sql_param_t *param = NULL;
    variant_t *value = NULL;
    char *param_str_buf = NULL;
    uint32 param_str_offset = 0;
    text_t num_text;

    stmt->param_info.outparam_cnt = 0;

    count = stmt->context->params->count;

    GS_RETURN_IFERR(sql_push(stmt, stmt->param_info.param_strsize, (void **)&param_str_buf));

    // types
    types = (int8 *)stmt->param_info.param_types;

    // total_len
    offset = sizeof(uint32);

    // flags
    flags = (uint8 *)(param_buf + offset);
    offset += CM_ALIGN4(count);

    // bound_value
    for (i = 0; i < count; i++) {
        data = (char *)(param_buf + offset);

        param = &stmt->param_info.params[i];
        param->direction = cs_get_param_direction(flags[i]);
        if (param->direction == GS_OUTPUT_PARAM || param->direction == GS_INOUT_PARAM) {
            stmt->param_info.outparam_cnt++;
        }

        value = &param->value;
        value->is_null = cs_get_param_isnull(flags[i]);
        value->type = (types[i] == GS_TYPE_UNKNOWN) ? GS_TYPE_UNKNOWN : ((gs_type_t)types[i] + GS_TYPE_BASE);

        if (param->direction == GS_OUTPUT_PARAM || value->is_null) {
            value->is_null = GS_TRUE;
            continue;
        }

        switch (value->type) {
            case GS_TYPE_INTEGER:
                VALUE(int32, value) = *(int32 *)data;
                offset += sizeof(int32);
                break;

            case GS_TYPE_BIGINT:
            case GS_TYPE_DATE:
            case GS_TYPE_TIMESTAMP:
            case GS_TYPE_TIMESTAMP_TZ_FAKE:
            case GS_TYPE_TIMESTAMP_LTZ:
                VALUE(int64, value) = *(int64 *)data;
                offset += sizeof(int64);
                break;

            case GS_TYPE_REAL:
                VALUE(double, value) = *(double *)data;
                offset += sizeof(double);
                break;

            case GS_TYPE_NUMBER:
            case GS_TYPE_DECIMAL:
            case GS_TYPE_NUMBER2:
                num_text.str = param_str_buf + param_str_offset;
                num_text.len = *(uint32 *)data;
                param_str_offset += num_text.len;
                if (num_text.len != 0) {
                    MEMS_RETURN_IFERR(memcpy_s(num_text.str, num_text.len, data + sizeof(uint32), num_text.len));
                }

                GS_RETURN_IFERR(cm_text_to_dec(&num_text, &VALUE(dec8_t, value)));

                offset += sizeof(uint32) + CM_ALIGN4(num_text.len);
                break;

            case GS_TYPE_CHAR:
            case GS_TYPE_VARCHAR:
            case GS_TYPE_STRING:
            case GS_TYPE_BINARY:
            case GS_TYPE_VARBINARY:
            case GS_TYPE_RAW:
                value->v_text.len = *(uint32 *)data;
                value->v_text.str = param_str_buf + param_str_offset;
                param_str_offset += value->v_text.len;
                if (value->v_text.len != 0) {
                    MEMS_RETURN_IFERR(
                        memcpy_s(value->v_text.str, value->v_text.len, data + sizeof(uint32), value->v_text.len));
                }

                if (g_instance->sql.enable_empty_string_null) {
                    value->is_null = (value->v_text.len == 0);
                }

                offset += sizeof(uint32) + CM_ALIGN4(value->v_text.len);
                break;

            case GS_TYPE_CLOB:
            case GS_TYPE_BLOB:
            case GS_TYPE_IMAGE:
                VALUE(var_lob_t, value).type = GS_LOB_FROM_VMPOOL;
                cm_vmcli_lob2vm_lob(&(VALUE(var_lob_t, value).vm_lob), (vm_cli_lob_t *)data);
                VALUE(var_lob_t, value).vm_lob.type = GS_LOB_FROM_VMPOOL;

                if (g_instance->sql.enable_empty_string_null) {
                    value->is_null = (VALUE(var_lob_t, value).vm_lob.size == 0);
                }

                if (stmt->session->call_version < CS_VERSION_10 && (VALUE(var_lob_t, value).vm_lob.size > 0) &&
                    (stmt->lob_info.inuse_count > 0)) {
                    stmt->lob_info.inuse_count--;
                }

                offset += sizeof(vm_cli_lob_t);
                break;

            case GS_TYPE_BOOLEAN:
                VALUE(bool32, value) = *(bool32 *)data;
                offset += sizeof(bool32);
                break;

            case GS_TYPE_INTERVAL_YM:
                VALUE(interval_ym_t, value) = *(interval_ym_t *)data;
                offset += sizeof(interval_ym_t);
                break;

            case GS_TYPE_INTERVAL_DS:
                VALUE(interval_ds_t, value) = *(interval_ds_t *)data;
                offset += sizeof(interval_ds_t);
                break;

            case GS_TYPE_UINT32:
                VALUE(uint32, value) = *(uint32 *)data;
                offset += sizeof(uint32);
                break;

            case GS_TYPE_TIMESTAMP_TZ:
                VALUE(timestamp_tz_t, value) = *(timestamp_tz_t *)data;
                offset += sizeof(timestamp_tz_t);
                break;

            default:
                GS_THROW_ERROR(ERR_UNSUPPORT_DATATYPE, get_datatype_name_str(value->type));
                return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

/* params data to decode may from execute request package or varea which used to keep params for process fetch */
static status_t sql_decode_kept_params(sql_stmt_t *stmt, char *param_buf)
{
    uint32 i, offset, count;
    cs_param_head_t *head = NULL;
    char *data = NULL;
    sql_param_t *param = NULL;
    variant_t *value = NULL;
    char *param_str_buf = NULL;
    uint32 param_str_offset = 0;
    text_t num_text;

    stmt->param_info.outparam_cnt = 0;

    count = stmt->context->params->count;

    GS_RETURN_IFERR(sql_push(stmt, stmt->param_info.param_strsize, (void **)&param_str_buf));

    offset = sizeof(uint32);

    for (i = 0; i < count; i++) {
        head = (cs_param_head_t *)(param_buf + offset);
        data = (char *)head + sizeof(cs_param_head_t);
        offset += (uint32)head->len;

        param = &stmt->param_info.params[i];
        param->direction = cs_get_param_direction(head->flag);
        if (param->direction == GS_OUTPUT_PARAM || param->direction == GS_INOUT_PARAM) {
            stmt->param_info.outparam_cnt++;
        }
        value = &param->value;
        value->is_null = cs_get_param_isnull(head->flag);
        value->type = (head->type == GS_TYPE_UNKNOWN) ? GS_TYPE_UNKNOWN : ((gs_type_t)head->type + GS_TYPE_BASE);

        if (param->direction == GS_OUTPUT_PARAM || value->is_null) {
            value->is_null = GS_TRUE;
            continue;
        }

        switch (value->type) {
            case GS_TYPE_INTEGER:
                VALUE(int32, value) = *(int32 *)data;
                break;

            case GS_TYPE_BIGINT:
            case GS_TYPE_DATE:
            case GS_TYPE_TIMESTAMP:
            case GS_TYPE_TIMESTAMP_TZ_FAKE:
            case GS_TYPE_TIMESTAMP_LTZ:
                VALUE(int64, value) = *(int64 *)data;
                break;

            case GS_TYPE_REAL:
                VALUE(double, value) = *(double *)data;
                break;

            case GS_TYPE_NUMBER:
            case GS_TYPE_DECIMAL:
            case GS_TYPE_NUMBER2:
                num_text.str = param_str_buf + param_str_offset;
                ;
                num_text.len = *(uint32 *)data;
                param_str_offset += num_text.len;
                if (num_text.len != 0) {
                    MEMS_RETURN_IFERR(memcpy_s(num_text.str, num_text.len, data + sizeof(uint32), num_text.len));
                }

                GS_RETURN_IFERR(cm_text_to_dec(&num_text, &VALUE(dec8_t, value)));
                break;

            case GS_TYPE_CHAR:
            case GS_TYPE_VARCHAR:
            case GS_TYPE_STRING:
            case GS_TYPE_BINARY:
            case GS_TYPE_VARBINARY:
            case GS_TYPE_RAW:
                value->v_text.len = *(uint32 *)data;
                value->v_text.str = param_str_buf + param_str_offset;
                param_str_offset += value->v_text.len;
                if (value->v_text.len != 0) {
                    MEMS_RETURN_IFERR(
                        memcpy_s(value->v_text.str, value->v_text.len, data + sizeof(uint32), value->v_text.len));
                }

                if (g_instance->sql.enable_empty_string_null) {
                    value->is_null = (value->v_text.len == 0);
                }
                break;

            case GS_TYPE_CLOB:
            case GS_TYPE_BLOB:
            case GS_TYPE_IMAGE:
                VALUE(var_lob_t, value).type = GS_LOB_FROM_VMPOOL;
                cm_vmcli_lob2vm_lob(&(VALUE(var_lob_t, value).vm_lob), (vm_cli_lob_t *)data);
                VALUE(var_lob_t, value).vm_lob.type = GS_LOB_FROM_VMPOOL;

                if (g_instance->sql.enable_empty_string_null) {
                    value->is_null = (VALUE(var_lob_t, value).vm_lob.size == 0);
                }

                if (stmt->session->call_version < CS_VERSION_10 && (VALUE(var_lob_t, value).vm_lob.size > 0) &&
                    (stmt->lob_info.inuse_count > 0)) {
                    stmt->lob_info.inuse_count--;
                }
                break;

            case GS_TYPE_BOOLEAN:
                VALUE(bool32, value) = *(bool32 *)data;
                break;

            case GS_TYPE_INTERVAL_YM:
                VALUE(interval_ym_t, value) = *(interval_ym_t *)data;
                break;

            case GS_TYPE_INTERVAL_DS:
                VALUE(interval_ds_t, value) = *(interval_ds_t *)data;
                break;

            case GS_TYPE_UINT32:
                VALUE(uint32, value) = *(uint32 *)data;
                break;

            case GS_TYPE_TIMESTAMP_TZ:
                VALUE(timestamp_tz_t, value) = *(timestamp_tz_t *)data;
                break;

            default:
                GS_THROW_ERROR(ERR_UNSUPPORT_DATATYPE, get_datatype_name_str(value->type));
                return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t sql_read_kept_params(sql_stmt_t *stmt)
{
    if (stmt->is_explain) {
        return GS_SUCCESS;
    }
    GS_RETURN_IFERR(sql_alloc_params_buf(stmt));

    if (stmt->context->params->count == 0) {
        return GS_SUCCESS;
    }

    if (stmt->param_info.param_buf == NULL) {
        GS_THROW_ERROR(ERR_VALUE_ERROR, "param_buf can't be NULL");
        return GS_ERROR;
    }

    if (stmt->session->call_version >= CS_VERSION_7) {
        return sql_decode_kept_params_eff(stmt, stmt->param_info.param_buf);
    } else {
        return sql_decode_kept_params(stmt, stmt->param_info.param_buf);
    }
}

status_t sql_prepare_params(sql_stmt_t *stmt)
{
    uint32 params_count = stmt->context->params->count;

    if (params_count == 0) {
        stmt->param_info.param_types = NULL;
        stmt->param_info.param_buf = NULL;
    } else {
        if (stmt->session->call_version >= CS_VERSION_7) {
            GS_RETURN_IFERR(
                cs_get_data(stmt->session->recv_pack, params_count, (void **)&stmt->param_info.param_types));
        }
        stmt->param_info.param_buf = CS_READ_ADDR(stmt->session->recv_pack);
        stmt->param_info.param_offset = CS_PACKET_OFFSET(stmt->session->recv_pack);
    }

    GS_RETURN_IFERR(sql_alloc_params_buf(stmt));
    return GS_SUCCESS;
}

status_t sql_set_row_value(sql_stmt_t *stmt, row_assist_t *ra, gs_type_t type, variant_t *value, uint32 col_id);

/* Keep the results of first executable nodes into variant_area */
status_t sql_keep_first_exec_vars(sql_stmt_t *stmt)
{
    uint32 var_cnt = stmt->context->fexec_vars_cnt;
    if (var_cnt == 0) {
        return GS_SUCCESS;
    }

    uint32 types_cost;
    uint32 *typs_buf = NULL;
    char *vars_buf = NULL;
    uint32 i;
    row_assist_t ra;
    variant_t *fvar = NULL;

    SQL_SAVE_STACK(stmt);

    types_cost = var_cnt * sizeof(uint32);
    GS_RETURN_IFERR(sql_push(stmt, types_cost + SQL_MAX_FEXEC_VAR_BYTES, (void **)&typs_buf));
    vars_buf = ((char *)typs_buf) + types_cost;
    row_init(&ra, vars_buf, GS_MAX_ROW_SIZE, var_cnt);
    for (i = 0; i < var_cnt; i++) {
        fvar = &stmt->fexec_info.first_exec_vars[i];
        typs_buf[i] = (uint32)fvar->type;

        if (sql_set_row_value(stmt, &ra, fvar->type, fvar, i) != GS_SUCCESS) {
            SQL_RESTORE_STACK(stmt);
            return GS_ERROR;
        }
    }

    uint32 mem_size = types_cost + (uint32)ra.head->size;
    if (vmc_alloc(&stmt->vmc, mem_size, (void **)&stmt->fexec_info.first_exec_buf) != GS_SUCCESS) {
        SQL_RESTORE_STACK(stmt);
        return GS_ERROR;
    }
    errno_t ret = memcpy_sp(stmt->fexec_info.first_exec_buf, mem_size, (char *)typs_buf, mem_size);
    if (ret != EOK) {
        SQL_RESTORE_STACK(stmt);
        GS_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return GS_ERROR;
    }

    SQL_RESTORE_STACK(stmt);
    return GS_SUCCESS;
}

/* Load the results of first executable nodes from variant_area at FETCH phase */
status_t sql_load_first_exec_vars(sql_stmt_t *stmt)
{
    if (stmt->fexec_info.first_exec_buf == NULL) {
        return GS_SUCCESS;
    }

    uint32 *typs_buf = NULL;
    char *vars_buf = NULL;
    uint32 var_cnt = stmt->context->fexec_vars_cnt;
    uint16 offsets[SQL_MAX_FEXEC_VARS] = { 0 };
    uint16 lens[SQL_MAX_FEXEC_VARS] = { 0 };
    variant_t *fvar = NULL;
    char *data = NULL;

    stmt->fexec_info.fexec_buff_offset = 0;

    GS_RETURN_IFERR(cm_stack_alloc(stmt->session->stack, sizeof(variant_t) * var_cnt + stmt->context->fexec_vars_bytes,
                                   (void **)&stmt->fexec_info.first_exec_vars));

    typs_buf = (uint32 *)stmt->fexec_info.first_exec_buf;
    vars_buf = ((char *)typs_buf) + var_cnt * sizeof(uint32);
    cm_decode_row(vars_buf, offsets, lens, NULL);
    for (uint32 i = 0; i < var_cnt; i++) {
        fvar = &stmt->fexec_info.first_exec_vars[i];
        fvar->type = (gs_type_t)typs_buf[i];
        if (fvar->type == GS_TYPE_LOGIC_TRUE) {
            fvar->is_null = GS_FALSE;
            continue;
        }
        if (lens[i] == GS_NULL_VALUE_LEN) {
            fvar->is_null = GS_TRUE;
            continue;
        }
        fvar->is_null = GS_FALSE;
        data = vars_buf + offsets[i];
        switch (fvar->type) {
            case GS_TYPE_BIGINT:
            case GS_TYPE_DATE:
            case GS_TYPE_TIMESTAMP:
            case GS_TYPE_TIMESTAMP_TZ_FAKE:
            case GS_TYPE_TIMESTAMP_LTZ:
                VALUE(int64, fvar) = *(int64 *)data;
                break;

            case GS_TYPE_TIMESTAMP_TZ:
                VALUE(timestamp_tz_t, fvar) = *(timestamp_tz_t *)data;
                break;

            case GS_TYPE_INTERVAL_DS:
                VALUE(interval_ds_t, fvar) = *(interval_ds_t *)data;
                break;

            case GS_TYPE_INTERVAL_YM:
                VALUE(interval_ym_t, fvar) = *(interval_ym_t *)data;
                break;
            case GS_TYPE_UINT32:
                VALUE(uint32, fvar) = *(uint32 *)data;
                break;

            case GS_TYPE_INTEGER:
                VALUE(int32, fvar) = *(int32 *)data;
                break;

            case GS_TYPE_BOOLEAN:
                VALUE(bool32, fvar) = *(bool32 *)data;
                break;

            case GS_TYPE_REAL:
                VALUE(double, fvar) = *(double *)data;
                break;

            case GS_TYPE_NUMBER:
            case GS_TYPE_DECIMAL:
                GS_RETURN_IFERR(cm_dec_4_to_8(&VALUE(dec8_t, fvar), (dec4_t *)data, lens[i]));
                break;
            case GS_TYPE_NUMBER2:
                GS_RETURN_IFERR(cm_dec_2_to_8(&VALUE(dec8_t, fvar), (const payload_t *)data, lens[i]));
                break;

            case GS_TYPE_CLOB:
            case GS_TYPE_BLOB:
            case GS_TYPE_IMAGE: {
                // decode from row_put_lob(size + type + lob_locator)
                uint32 lob_type = *(uint32 *)(data + sizeof(uint32));
                VALUE(var_lob_t, fvar).type = lob_type;
                if (lob_type == GS_LOB_FROM_KERNEL) {
                    VALUE(var_lob_t, fvar).knl_lob.bytes = (uint8 *)data;
                    VALUE(var_lob_t, fvar).knl_lob.size = KNL_LOB_LOCATOR_SIZE;
                } else if (lob_type == GS_LOB_FROM_VMPOOL) {
                    VALUE(var_lob_t, fvar).vm_lob = *(vm_lob_t *)data;
                } else {
                    GS_THROW_ERROR(ERR_UNKNOWN_LOB_TYPE, "do decode pl_inputs");
                }
                break;
            }

            default:
                // copy var-len datatype
                // if buff space is insufficient, then do not optimize
                if ((stmt->fexec_info.fexec_buff_offset + lens[i]) > stmt->context->fexec_vars_bytes) {
                    fvar->type = GS_TYPE_UNINITIALIZED;
                    break;
                }

                fvar->v_text.len = lens[i];
                fvar->v_text.str = (char *)stmt->fexec_info.first_exec_vars +
                                   (stmt->context->fexec_vars_cnt * sizeof(variant_t)) +
                                   stmt->fexec_info.fexec_buff_offset;
                if (lens[i] != 0) {
                    MEMS_RETURN_IFERR(memcpy_s(fvar->v_text.str, lens[i], data, lens[i]));
                }
                stmt->fexec_info.fexec_buff_offset += lens[i];
                break;
        }
    }

    return GS_SUCCESS;
}

static inline void sql_get_column_def_typmod(rs_column_t *rs_col, typmode_t *typmod)
{
    typmod->datatype = (uint16)(rs_col->datatype - GS_TYPE_BASE);
    typmod->precision = 0;
    typmod->scale = 0;

    switch (rs_col->datatype) {
        case GS_TYPE_UNKNOWN:
            typmod->datatype = (uint16)GS_TYPE_UNKNOWN;
            typmod->size = GS_MAX_COLUMN_SIZE;
            break;

        case GS_TYPE_UINT32:
        case GS_TYPE_INTEGER:
        case GS_TYPE_BOOLEAN:
            typmod->size = sizeof(int32);
            break;
        case GS_TYPE_BIGINT:
            typmod->size = sizeof(int64);
            break;
        case GS_TYPE_REAL:
            typmod->size = sizeof(double);
            break;

        case GS_TYPE_DECIMAL:
            typmod->datatype = (uint16)(GS_TYPE_NUMBER - GS_TYPE_BASE);
            /* fall-through */
        case GS_TYPE_NUMBER:
            if (rs_col->precision == GS_UNSPECIFIED_NUM_PREC) {
                typmod->size = MAX_DEC_BYTE_SZ;
            } else {
                typmod->size = MAX_DEC_BYTE_BY_PREC(rs_col->precision);
            }
            typmod->precision = rs_col->precision;
            typmod->scale = rs_col->scale;
            break;
        case GS_TYPE_NUMBER2:
            if (rs_col->precision == GS_UNSPECIFIED_NUM_PREC) {
                typmod->size = MAX_DEC2_BYTE_SZ;
            } else {
                typmod->size = MAX_DEC2_BYTE_BY_PREC(rs_col->precision);
            }
            typmod->precision = rs_col->precision;
            typmod->scale = rs_col->scale;
            break;
        case GS_TYPE_DATE:
            typmod->size = sizeof(date_t);
            typmod->precision = rs_col->precision;
            break;

        case GS_TYPE_TIMESTAMP:
        case GS_TYPE_TIMESTAMP_TZ_FAKE:
        case GS_TYPE_TIMESTAMP_LTZ:
            typmod->size = sizeof(timestamp_t);
            typmod->precision = rs_col->precision;
            break;

        case GS_TYPE_TIMESTAMP_TZ:
            typmod->size = sizeof(timestamp_tz_t);
            typmod->precision = rs_col->precision;
            break;

        case GS_TYPE_CHAR:
        case GS_TYPE_VARCHAR:
        case GS_TYPE_STRING:
        case GS_TYPE_BINARY:
        case GS_TYPE_VARBINARY:
        case GS_TYPE_RAW:
            typmod->size = (!GS_BIT_TEST(rs_col->rs_flag, RS_NULLABLE) && rs_col->size == 0)
                               ? GS_MAX_COLUMN_SIZE
                               : MIN(rs_col->size, GS_MAX_EXEC_LOB_SIZE);
            break;

        case GS_TYPE_CLOB:
        case GS_TYPE_BLOB:
        case GS_TYPE_IMAGE:
            typmod->size = g_instance->sql.sql_lob_locator_size;
            break;

        case GS_TYPE_INTERVAL_YM:
            typmod->size = sizeof(interval_ym_t);
            typmod->precision = rs_col->typmod.precision;
            typmod->scale = rs_col->typmod.scale;
            break;

        case GS_TYPE_INTERVAL_DS:
            typmod->size = sizeof(interval_ds_t);
            typmod->precision = rs_col->typmod.precision;
            typmod->scale = rs_col->typmod.scale;
            break;

        default:
            typmod->size = GS_MAX_COLUMN_SIZE;
            break;
    }
}

static void sql_set_column_attr(rs_column_t *rs_col, cs_column_def_t *column_def, typmode_t typmode)
{
    column_def->datatype = typmode.datatype;
    column_def->size = typmode.size;
    column_def->precision = typmode.precision;
    column_def->scale = typmode.scale;

    if (GS_BIT_TEST(rs_col->rs_flag, RS_NULLABLE)) {
        GS_COLUMN_SET_NULLABLE(column_def);
    }

    if (GS_BIT_TEST(rs_col->rs_flag, RS_IS_SERIAL)) {
        GS_COLUMN_SET_AUTO_INCREMENT(column_def);
    }

    if (GS_IS_CHAR_DATATYPE(rs_col->datatype) && rs_col->typmod.is_char) {
        GS_COLUMN_SET_CHARACTER(column_def);
    }
}

status_t sql_send_parsed_stmt_normal(sql_stmt_t *stmt, uint16 columnCount)
{
    rs_column_t *rs_col = NULL;
    sql_context_t *ctx = (sql_context_t *)stmt->context;
    cs_packet_t *send_pack = stmt->session->send_pack;
    cs_column_def_t *column_def = NULL;
    typmode_t typmode;
    uint32 column_def_offset, column_name_offset;

    if (columnCount == 0) {
        return GS_SUCCESS;
    }

    // check whether project column count is valid for client
    if (columnCount >= GS_SPRS_COLUMNS && stmt->session->call_version <= CS_VERSION_3) {
        GS_THROW_ERROR(ERR_MAX_COLUMN_SIZE, GS_SPRS_COLUMNS - 1);
        return GS_ERROR;
    }

    for (uint32 i = 0; i < ctx->rs_columns->count; i++) {
        rs_col = (rs_column_t *)cm_galist_get(ctx->rs_columns, i);

        GS_RETURN_IFERR(cs_reserve_space(send_pack, sizeof(cs_column_def_t), &column_def_offset));
        column_def = (cs_column_def_t *)CS_RESERVE_ADDR(send_pack, column_def_offset);
        MEMS_RETURN_IFERR(memset_sp(column_def, sizeof(cs_column_def_t), 0, sizeof(cs_column_def_t)));

        if ((rs_col->type == RS_COL_COLUMN && rs_col->v_col.is_array == GS_TRUE &&
             rs_col->v_col.ss_start <= rs_col->v_col.ss_end) ||
            (rs_col->type == RS_COL_CALC && rs_col->expr->root->typmod.is_array == GS_TRUE)) {
            if (stmt->session->call_version >= CS_VERSION_10) {
                GS_COLUMN_SET_ARRAY(column_def);
            } else {
                GS_THROW_ERROR(ERR_ARRAY_NOT_SUPPORT);
                return GS_ERROR;
            }
        }

        if (stmt->session->call_version >= CS_VERSION_24 && rs_col->v_col.is_jsonb) {
            GS_COLUMN_SET_JSONB(column_def);
        }

        column_def->name_len = rs_col->name.len;
        if (column_def->name_len > 0) {
            GS_RETURN_IFERR(cs_reserve_space(send_pack, column_def->name_len, &column_name_offset));

            /* after "cs_reserve_space" column_def should be refresh by "CS_RESERVE_ADDR" */
            column_def = (cs_column_def_t *)CS_RESERVE_ADDR(send_pack, column_def_offset);
            char *name = CS_RESERVE_ADDR(send_pack, column_name_offset);
            uint32 align_len = CM_ALIGN4(column_def->name_len);
            MEMS_RETURN_IFERR(memcpy_sp(name, align_len, rs_col->name.str, rs_col->name.len));
            if (column_def->name_len < align_len) {
                name[column_def->name_len] = '\0';
            }
        }

        sql_get_column_def_typmod(rs_col, &typmode);
        sql_set_column_attr(rs_col, column_def, typmode);
    }

    return GS_SUCCESS;
}

void sql_set_ack_column_count(sql_stmt_t *stmt, cs_prepare_ack_t *ack)
{
    if (stmt->is_explain) {
        ack->column_count = 1;
    } else {
        sql_context_t *ctx = (sql_context_t *)stmt->context;
        ack->column_count = (ctx->rs_columns == NULL) ? 0 : ctx->rs_columns->count;
    }
}

static status_t sql_send_param_info_impl(sql_stmt_t *stmt, galist_t *params_list)
{
    sql_param_mark_t *pmark = NULL;
    uint32 params_offset, param_name_offset, param_count;
    cs_packet_t *send_pack = stmt->session->send_pack;
    char *sql = NULL;
    uint32 sql_len;

    knl_panic(stmt->pl_context == NULL);
    {
        sql = stmt->context->ctrl.text_addr;
        sql_len = stmt->context->ctrl.text_size;
    }

    param_count = params_list->count;

    // new communication protocol for support cursor sharing
    for (uint32 i = 0; i < param_count; i++) {
        GS_RETURN_IFERR(cs_reserve_space(send_pack, sizeof(cs_param_def_new_t), &params_offset));
        cs_param_def_new_t *param_new = (cs_param_def_new_t *)CS_RESERVE_ADDR(send_pack, params_offset);
        MEMS_RETURN_IFERR(memset_sp(param_new, sizeof(cs_param_def_new_t), 0, sizeof(cs_param_def_new_t)));
        pmark = (sql_param_mark_t *)cm_galist_get(params_list, i);
        param_new->len = pmark->len;
        if (pmark->len > 0) {
            GS_RETURN_IFERR(cs_reserve_space(send_pack, pmark->len, &param_name_offset));
            char *name = CS_RESERVE_ADDR(send_pack, param_name_offset);
            uint32 align_len = CM_ALIGN4(pmark->len);
            if (pmark->offset >= sql_len || pmark->offset + pmark->len > sql_len) {
                GS_THROW_ERROR(ERR_CURSOR_SHARING, "params offset or params len is large than sql len.");
                return GS_ERROR;
            }
            MEMS_RETURN_IFERR(memcpy_sp(name, align_len, sql + pmark->offset - stmt->text_shift, pmark->len));
            if (pmark->len < align_len) {
                name[pmark->len] = '\0';
            }
        }
    }
    return GS_SUCCESS;
}

static status_t sql_send_params_info(sql_stmt_t *stmt, cs_prepare_ack_t *ack)
{
    galist_t *params_list = NULL;
    sql_context_t *ctx = (sql_context_t *)stmt->context;

    ack->param_count = (ctx->params == NULL) ? 0 : ctx->params->count;
    if (ack->param_count > 0) {
        params_list = ctx->params;
        GS_RETURN_IFERR(sql_send_param_info_impl(stmt, params_list));
    }
    return GS_SUCCESS;
}

status_t sql_send_parsed_stmt(sql_stmt_t *stmt)
{
    cs_prepare_ack_t *ack = NULL;
    uint32 ack_offset;
    cs_packet_t *send_pack = stmt->session->send_pack;

    GS_BIT_RESET(send_pack->head->flags, CS_FLAG_WITH_TS);
    GS_RETURN_IFERR(cs_reserve_space(send_pack, sizeof(cs_prepare_ack_t), &ack_offset));

    ack = (cs_prepare_ack_t *)CS_RESERVE_ADDR(send_pack, ack_offset);
    ack->stmt_id = stmt->id;
    if (stmt->context == NULL) {
        GS_THROW_ERROR(ERR_INVALID_CURSOR);
        return GS_ERROR;
    }

    ack->stmt_type = ACK_STMT_TYPE(stmt->lang_type, stmt->context->type);
    sql_set_ack_column_count(stmt, ack);

    // Do not optimize the temporary variables column_count,
    // because the message expansion may cause the ack address to change,
    // and the ack address cannot be used later
    uint16 column_count = ack->column_count;
    GS_RETURN_IFERR(sql_send_params_info(stmt, ack));

    {
        GS_RETURN_IFERR(sql_send_parsed_stmt_normal(stmt, column_count));
    }

    knl_panic(stmt->lang_type != LANG_PL);

    return GS_SUCCESS;
}

status_t sql_send_exec_begin(sql_stmt_t *stmt)
{
    sql_select_t *select_ctx = NULL;
    rs_column_t *rs_col = NULL;
    typmode_t typmode;
    uint32 i;
    cs_execute_ack_t *exec_ack = NULL;
    uint32 pending_col_defs_offset;

    if (stmt->session->agent->recv_pack.head->cmd == CS_CMD_EXE_MULTI_SQL) {
        return GS_SUCCESS;
    }

    if (CS_XACT_WITH_TS(stmt->session->recv_pack->head->flags)) {
        stmt->session->send_pack->head->flags |= CS_FLAG_WITH_TS;
        stmt->gts_offset = stmt->session->send_pack->head->size;
        GS_RETURN_IFERR(cs_put_scn(stmt->session->send_pack, &stmt->gts_scn));
    }

    GS_RETURN_IFERR(cs_reserve_space(stmt->session->send_pack, sizeof(cs_execute_ack_t), &stmt->exec_ack_offset));
    exec_ack = (cs_execute_ack_t *)CS_RESERVE_ADDR(stmt->session->send_pack, stmt->exec_ack_offset);
    MEMS_RETURN_IFERR(memset_s(exec_ack, sizeof(cs_execute_ack_t), 0, sizeof(cs_execute_ack_t)));

    if (!stmt->is_explain && stmt->context != NULL && stmt->context->type == SQL_TYPE_SELECT) {
        select_ctx = (sql_select_t *)stmt->context->entry;
        if (select_ctx->pending_col_count > 0) {
            exec_ack->pending_col_count = select_ctx->rs_columns->count;
            GS_RETURN_IFERR(cs_reserve_space(stmt->session->send_pack,
                                             select_ctx->rs_columns->count * sizeof(cs_final_column_def_t),
                                             &pending_col_defs_offset));
            /* after "cs_reserve_space" exec_ack should be refresh by "CS_RESERVE_ADDR" */
            exec_ack = (cs_execute_ack_t *)CS_RESERVE_ADDR(stmt->session->send_pack, stmt->exec_ack_offset);
            *((cs_final_column_def_t **)&exec_ack->pending_col_defs) =
                (cs_final_column_def_t *)CS_RESERVE_ADDR(stmt->session->send_pack, pending_col_defs_offset);
            for (i = 0; i < select_ctx->rs_columns->count; i++) {
                rs_col = (rs_column_t *)cm_galist_get(select_ctx->rs_columns, i);
                sql_get_column_def_typmod(rs_col, &typmode);
                exec_ack->pending_col_defs[i].col_id = i;
                exec_ack->pending_col_defs[i].datatype = typmode.datatype;
                exec_ack->pending_col_defs[i].size = typmode.size;
                exec_ack->pending_col_defs[i].precision = typmode.precision;
                exec_ack->pending_col_defs[i].scale = typmode.scale;
            }
        }
    }

    return GS_SUCCESS;
}

void sql_send_exec_end(sql_stmt_t *stmt)
{
    if (stmt->session->agent->recv_pack.head->cmd == CS_CMD_EXE_MULTI_SQL) {
        return;
    }

    uint32 i;
    gs_type_t type;
    sql_select_t *select_ctx = NULL;
    rs_column_t *rs_col = NULL;
    cs_execute_ack_t *exec_ack = (cs_execute_ack_t *)CS_RESERVE_ADDR(stmt->session->send_pack, stmt->exec_ack_offset);

    exec_ack->batch_count = 1;
    exec_ack->total_rows = stmt->total_rows;
    exec_ack->batch_rows = stmt->batch_rows;
    exec_ack->rows_more = !stmt->eof;
    exec_ack->xact_status = knl_xact_status(&stmt->session->knl_session);
    exec_ack->batch_errs = stmt->actual_batch_errs;

    if (exec_ack->pending_col_count > 0 && !stmt->mark_pending_done) {
        select_ctx = (sql_select_t *)stmt->context->entry;
        for (i = 0; i < exec_ack->pending_col_count; i++) {
            if (exec_ack->pending_col_defs[i].datatype != (uint16)GS_TYPE_UNKNOWN) {
                continue;
            }
            rs_col = (rs_column_t *)cm_galist_get(select_ctx->rs_columns, i);
            type = GS_TYPE_UNKNOWN;
            if (rs_col->type == RS_COL_CALC && rs_col->expr->root->type == EXPR_NODE_PARAM) {
                (void)sql_get_expr_datatype(stmt, rs_col->expr, &type);
            }
            exec_ack->pending_col_defs[i].datatype = (type == GS_TYPE_UNKNOWN)
                                                         ? (uint16)(GS_TYPE_VARCHAR - GS_TYPE_BASE)
                                                         : (uint16)(type - GS_TYPE_BASE);
        }
    }
}

status_t sql_send_import_rows(sql_stmt_t *stmt)
{
    GS_RETURN_IFERR(sql_send_exec_begin(stmt));
    sql_send_exec_end(stmt);
    stmt->session->send_pack->head->flags |= GS_FLAG_CREATE_TABLE_AS;
    return GS_SUCCESS;
}
status_t sql_send_fetch_begin(sql_stmt_t *stmt)
{
    return cs_reserve_space(stmt->session->send_pack, sizeof(cs_fetch_ack_t), &stmt->fetch_ack_offset);
}

void sql_send_fetch_end(sql_stmt_t *stmt)
{
    cs_fetch_ack_t *fetch_ack = (cs_fetch_ack_t *)CS_RESERVE_ADDR(stmt->session->send_pack, stmt->fetch_ack_offset);
    fetch_ack->total_rows = stmt->total_rows;
    fetch_ack->batch_rows = stmt->batch_rows;
    fetch_ack->rows_more = !stmt->eof;
}

bool32 sql_send_check_is_full(sql_stmt_t *stmt)
{
    cs_packet_t *send_pack = stmt->session->send_pack;

    if (stmt->return_generated_key &&
        (stmt->context->type == SQL_TYPE_INSERT || stmt->context->type == SQL_TYPE_MERGE)) {
        // when JDBC wants Server to return auto_increment keys (insert SQL),
        // should not judge prefetch rows count and remove GS_MAX_ROW_SIZE limit
        return (send_pack->head->size + GS_GENERATED_KEY_ROW_SIZE > send_pack->buf_size);
    } else {
        if ((stmt->batch_rows + 1 >= stmt->prefetch_rows) ||
            (CM_REALLOC_SEND_PACK_SIZE(send_pack, GS_MAX_ROW_SIZE) > send_pack->max_buf_size)) {
            return GS_TRUE;
        }
    }

    return GS_FALSE;
}

status_t sql_send_serveroutput(sql_stmt_t *stmt, text_t *output)
{
    return GS_SUCCESS;
}

status_t sql_send_return_result(sql_stmt_t *stmt, uint32 stmt_id)
{
    return GS_SUCCESS;
}

status_t sql_send_nls_feedback(sql_stmt_t *stmt, nlsparam_id_t id, text_t *value)
{
    cs_packet_t *send_pack;

    send_pack = stmt->session->send_pack;
    send_pack->head->flags = CS_FLAG_FEEDBACK;
    // put the feedback type
    GS_RETURN_IFERR(cs_put_int32(send_pack, FB_ALTSESSION_SET_NLS));
    // put the feedback data
    GS_RETURN_IFERR(cs_put_int32(send_pack, id));
    GS_RETURN_IFERR(cs_put_text(send_pack, value));

    return GS_SUCCESS;
}

status_t sql_send_session_tz_feedback(sql_stmt_t *stmt, timezone_info_t client_timezone)
{
    cs_packet_t *send_pack;

    send_pack = stmt->session->send_pack;
    send_pack->head->flags = CS_FLAG_FEEDBACK;
    // put the feedback type
    GS_RETURN_IFERR(cs_put_int32(send_pack, FB_ALTSESSION_SET_SESSIONTZ));
    // put the feedback data
    GS_RETURN_IFERR(cs_put_int32(send_pack, client_timezone));

    return GS_SUCCESS;
}

status_t sql_send_row_entire(sql_stmt_t *stmt, char *row, bool32 *is_full)
{
    char *buf = NULL;
    uint32 buf_offset;
    cs_packet_t *send_pack = stmt->session->send_pack;

    GS_RETURN_IFERR(cs_reserve_space(send_pack, ROW_SIZE(row), &buf_offset));
    buf = CS_RESERVE_ADDR(send_pack, buf_offset);
    if (0 != ROW_SIZE(row)) {
        MEMS_RETURN_IFERR(memcpy_s(buf, ROW_SIZE(row), row, ROW_SIZE(row)));
    }
    *is_full = sql_send_check_is_full(stmt);

    return GS_SUCCESS;
}

// generate result set for client
void sql_init_sender(session_t *session)
{
    cs_init_set(session->send_pack, CS_LOCAL_VERSION);
}

void sql_init_sender_row(sql_stmt_t *stmt, char *buffer, uint32 size, uint32 column_count)
{
    row_init(&stmt->ra, buffer, size, column_count);
}

void sql_get_error(int32 *code, const char **message, source_location_t *loc)
{
    cm_get_error(code, message, loc);
    if (SECUREC_UNLIKELY(*code == 0)) {
        GS_THROW_ERROR_EX(ERR_ASSERT_ERROR, "has error info at %s:%u", g_tls_error.err_file, g_tls_error.err_line);
        cm_get_error(code, message, loc);
    }
}

status_t sql_send_result_error(session_t *session)
{
    int32 code;
    const char *message = NULL;
    cs_packet_t *pack = NULL;
    source_location_t loc;
    sql_stmt_t *stmt = NULL;

    CM_POINTER(session);
    pack = &session->agent->send_pack;
    cs_init_set(pack, session->call_version);
    pack->head->cmd = session->agent->recv_pack.head->cmd;
    pack->head->result = (uint8)GS_ERROR;
    pack->head->flags = 0;
    pack->head->serial_number = session->agent->recv_pack.head->serial_number;
    sql_get_error(&code, &message, &loc);

    if (code == 0) {
        CM_ASSERT(0);
        GS_LOG_RUN_ERR("error returned without throwing error msg");
    }

    if (code == ERR_PL_EXEC) {
        loc.line = 0;
        loc.column = 0;
    }

    GS_RETURN_IFERR(cs_put_int32(pack, (uint32)code));
    GS_RETURN_IFERR(cs_put_int16(pack, loc.line));
    GS_RETURN_IFERR(cs_put_int16(pack, loc.column));
    GS_RETURN_IFERR(cs_put_err_msg(pack, session->call_version, message));

    // Beside error info, some st_cs_execute_ack may be useful and should
    // be send to client.
    stmt = session->current_stmt;
    if (stmt != NULL) {
        GS_RETURN_IFERR(cs_put_int32(pack, stmt->total_rows));
        GS_RETURN_IFERR(cs_put_int32(pack, stmt->batch_rows));
    }

    return cs_write(session->pipe, pack);
}

status_t sql_send_result_success(session_t *session)
{
    cs_packet_t *pack = NULL;
    CM_POINTER(session);
    pack = &session->agent->send_pack;
    pack->head->cmd = session->agent->recv_pack.head->cmd;
    pack->head->result = (uint8)GS_SUCCESS;
    pack->head->serial_number = session->agent->recv_pack.head->serial_number;
    return cs_write(session->pipe, pack);
}

status_t sql_send_row_begin(sql_stmt_t *stmt, uint32 column_count)
{
    char *buf = NULL;

    CM_CHECK_SEND_PACK_FREE(stmt->session->send_pack, GS_MAX_ROW_SIZE);
    buf = CS_WRITE_ADDR(stmt->session->send_pack);
    row_init(&stmt->ra, buf, GS_MAX_ROW_SIZE, column_count);

    return GS_SUCCESS;
}

status_t sql_send_row_end(sql_stmt_t *stmt, bool32 *is_full)
{
    cs_packet_t *send_pack = stmt->session->send_pack;
    GS_RETURN_IFERR(cs_reserve_space(send_pack, stmt->ra.head->size, NULL));
    *is_full = sql_send_check_is_full(stmt);
    return GS_SUCCESS;
}

status_t sql_send_column_null(sql_stmt_t *stmt, uint32 type)
{
    return row_put_null(&stmt->ra);
}

status_t sql_send_column_uint32(sql_stmt_t *stmt, uint32 v)
{
    return row_put_uint32(&stmt->ra, v);
}

status_t sql_send_column_int32(sql_stmt_t *stmt, int32 v)
{
    return row_put_int32(&stmt->ra, v);
}

status_t sql_send_column_int64(sql_stmt_t *stmt, int64 v)
{
    return row_put_int64(&stmt->ra, v);
}

status_t sql_send_column_real(sql_stmt_t *stmt, double v)
{
    return row_put_real(&stmt->ra, v);
}

status_t sql_send_column_date(sql_stmt_t *stmt, date_t v)
{
    return row_put_date(&stmt->ra, v);
}

status_t sql_send_column_ts(sql_stmt_t *stmt, date_t v)
{
    return row_put_date(&stmt->ra, v);
}

status_t sql_send_column_tstz(sql_stmt_t *stmt, timestamp_tz_t *v)
{
    return row_put_timestamp_tz(&stmt->ra, v);
}

status_t sql_send_column_tsltz(sql_stmt_t *stmt, timestamp_ltz_t v)
{
    /* send as timestamp */
    return sql_send_column_ts(stmt, v);
}

status_t sql_get_array_vm_lob(sql_stmt_t *stmt, var_lob_t *var_lob, vm_lob_t *vm_lob)
{
    GS_THROW_ERROR(ERR_UNKNOWN_LOB_TYPE, "lob value");
    return GS_ERROR;
}

status_t sql_row_put_array(sql_stmt_t *stmt, row_assist_t *ra, var_array_t *v)
{
    return GS_ERROR;
}

status_t sql_send_column_array(sql_stmt_t *stmt, var_array_t *v)
{
    return sql_row_put_array(stmt, &stmt->ra, v);
}

status_t sql_row_set_lob(sql_stmt_t *stmt, row_assist_t *ra, uint32 lob_locator_size, var_lob_t *lob, uint32 col_id)
{
    return GS_ERROR;
}

status_t sql_row_set_array(sql_stmt_t *stmt, row_assist_t *ra, variant_t *value, uint16 col_id)
{
    ra->col_id = col_id;
    return sql_row_put_array(stmt, ra, &value->v_array);
}

status_t sql_send_column_lob(sql_stmt_t *stmt, var_lob_t *v)
{
    return GS_ERROR;
}

status_t sql_send_column_str(sql_stmt_t *stmt, char *str)
{
    return row_put_str(&stmt->ra, str);
}

status_t sql_send_column_text(sql_stmt_t *stmt, text_t *text)
{
    return row_put_text(&stmt->ra, text);
}

status_t sql_send_column_bin(sql_stmt_t *stmt, binary_t *bin)
{
    return row_put_bin(&stmt->ra, bin);
}

status_t sql_send_column_decimal(sql_stmt_t *stmt, dec8_t *dec)
{
    return row_put_dec4(&stmt->ra, dec);
}

status_t sql_send_column_decimal2(sql_stmt_t *stmt, dec8_t *dec)
{
    return row_put_dec2(&stmt->ra, dec);
}

status_t sql_send_column_cursor(sql_stmt_t *stmt, cursor_t *cursor)
{
    return row_put_cursor(&stmt->ra, cursor);
}

status_t sql_send_return_values(sql_stmt_t *stmt, gs_type_t type, typmode_t *typmod, variant_t *v)
{
    return sql_send_value(stmt, NULL, type, typmod, v);
}

static inline uint16 sql_get_datatype_size(int32 datatype)
{
    switch (datatype) {
        case GS_TYPE_UINT32:
        case GS_TYPE_INTEGER:
        case GS_TYPE_BOOLEAN:
        case GS_TYPE_INTERVAL_YM:
        case GS_TYPE_SMALLINT:
        case GS_TYPE_USMALLINT:
        case GS_TYPE_TINYINT:
        case GS_TYPE_UTINYINT:
            return sizeof(int32);

        case GS_TYPE_BIGINT:
        case GS_TYPE_DATE:
        case GS_TYPE_TIMESTAMP:
        case GS_TYPE_TIMESTAMP_TZ_FAKE:
        case GS_TYPE_TIMESTAMP_LTZ:
        case GS_TYPE_INTERVAL_DS:
            return sizeof(int64);

        case GS_TYPE_TIMESTAMP_TZ:
            return sizeof(timestamp_tz_t);

        case GS_TYPE_REAL:
            return sizeof(double);

        case GS_TYPE_NUMBER:
        case GS_TYPE_DECIMAL:
            return MAX_DEC_BYTE_SZ;
        case GS_TYPE_NUMBER2:
            return MAX_DEC2_BYTE_SZ;

        case GS_TYPE_CLOB:
        case GS_TYPE_BLOB:
        case GS_TYPE_IMAGE:
            return g_instance->sql.sql_lob_locator_size;

        case GS_TYPE_CHAR:
        case GS_TYPE_VARCHAR:
        case GS_TYPE_STRING:
        case GS_TYPE_BINARY:
        case GS_TYPE_VARBINARY:
        case GS_TYPE_RAW:
        default:
            return GS_MAX_COLUMN_SIZE;
    }
}

void sql_send_column_def(sql_stmt_t *stmt, void *sql_cursor)
{
    sql_select_t *select_ctx = NULL;
    sql_cursor_t *cursor = (sql_cursor_t *)sql_cursor;
    uint8 cmd;

    // 1.pending col has been fixed  2.no need to fix if it has no resultset
    if (stmt->mark_pending_done || stmt->batch_rows == 0) {
        return;
    }

    if (stmt->session->pipe != NULL) {
        cmd = stmt->session->recv_pack->head->cmd;
        // the type of pl-variant which in cursor query is unknown until calc.
        // the cmd include CS_CMD_EXECUTE / CS_CMD_PREP_AND_EXEC
        if (!(cmd == CS_CMD_EXECUTE || cmd == CS_CMD_PREP_AND_EXEC)) {
            return;
        }

        if (stmt->context->type != SQL_TYPE_SELECT) {
            return;
        }
    } else {
        return;
    }

    select_ctx = (sql_select_t *)stmt->context->entry;
    if (select_ctx->pending_col_count == 0 || select_ctx != cursor->select_ctx) {
        return;
    }
    knl_panic(0);
}

static void sql_read_sqltext(text_t *text, text_t *sql)
{
    text_t line;

    sql->str = text->str;
    sql->len = text->len;

    while (cm_fetch_line(text, &line, GS_TRUE)) {
        cm_rtrim_text(&line);
        if (line.len == 1 && *line.str == '/') {
            sql->len = (uint32)(line.str - sql->str);
            break;
        }
    }
}

static status_t sql_process_sqlfile(session_t *session, int32 file, char *buf, uint32 buf_size)
{
    int32 read_size;
    text_t text, sql;

    if (cm_seek_file(file, 0, SEEK_SET) != 0) {
        GS_THROW_ERROR(ERR_SEEK_FILE, 0, SEEK_SET, errno);
        GS_LOG_RUN_ERR("failed to seek file head");
        return GS_ERROR;
    }

    if (cm_read_file(file, buf, (int32)buf_size, &read_size) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("failed to read data from file");
        return GS_ERROR;
    }

    text.str = buf;
    text.len = (uint32)read_size;

    cm_trim_text(&text);

    while (text.len > 0) {
        sql_read_sqltext(&text, &sql);
        cm_trim_text(&sql);

        if (sql.len == 0) {
            continue;
        }

        if (sql_execute_directly(session, &sql, NULL, GS_TRUE) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

static status_t sql_load_sql_file(knl_handle_t handle, const char *full_name)
{
    session_t *session = (session_t *)handle;
    char *buf = NULL;
    int32 file;
    int64 file_size;
    status_t status;

    if (cm_open_file(full_name, O_RDONLY | O_BINARY, &file) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("failed to open file %s", full_name);
        return GS_ERROR;
    }

    file_size = cm_file_size(file);
    if (file_size == -1) {
        cm_close_file(file);
        GS_LOG_RUN_ERR("failed to get file %s size", full_name);
        GS_THROW_ERROR(ERR_SEEK_FILE, 0, SEEK_END, errno);
        return GS_ERROR;
    }

    if (file_size > (int64)GS_MAX_SQLFILE_SIZE) {
        cm_close_file(file);
        GS_THROW_ERROR(ERR_FILE_SIZE_TOO_LARGE, full_name);
        return GS_ERROR;
    }

    buf = (char *)malloc(GS_MAX_SQLFILE_SIZE);
    if (buf == NULL) {
        cm_close_file(file);
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)GS_MAX_SQLFILE_SIZE, "loading sql file");
        return GS_ERROR;
    }

    status = sql_process_sqlfile(session, file, buf, GS_MAX_SQLFILE_SIZE);

    CM_FREE_PTR(buf);
    cm_close_file(file);
    return status;
}

static status_t sql_get_scripts_name(char *full_name, const char *file_name)
{
    char *home = getenv(GS_ENV_HOME);

    if (home == NULL) {
        GS_THROW_ERROR(ERR_HOME_PATH_NOT_FOUND, GS_ENV_HOME);
        return GS_ERROR;
    }

    if (strlen(home) > GS_MAX_PATH_BUFFER_SIZE - 1) {
        GS_THROW_ERROR(ERR_FILE_PATH_TOO_LONG, GS_MAX_PATH_BUFFER_SIZE - 1);
        return GS_ERROR;
    }

    if (cm_check_exist_special_char(home, (uint32)strlen(home))) {
        GS_THROW_ERROR(ERR_INVALID_DIR, home);
        return GS_ERROR;
    }

    PRTS_RETURN_IFERR(snprintf_s(full_name, GS_FILE_NAME_BUFFER_SIZE, GS_FILE_NAME_BUFFER_SIZE - 1,
                                 "%s/admin/scripts/%s", home, file_name));

    if (!cm_file_exist(full_name)) {
        GS_THROW_ERROR(ERR_FILE_NOT_EXIST, "scripts", file_name);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t sql_load_scripts(knl_handle_t handle, const char *file_name, bool8 is_necessary)
{
    char full_name[GS_FILE_NAME_BUFFER_SIZE] = { '\0' };

    PRTS_RETURN_IFERR(snprintf_s(full_name, GS_FILE_NAME_BUFFER_SIZE, GS_FILE_NAME_BUFFER_SIZE - 1,
                                 "%s/admin/scripts/%s", g_instance->home, file_name));

    if (!cm_file_exist(full_name)) {
        if (sql_get_scripts_name(full_name, file_name) == GS_ERROR) {
            if (!is_necessary) {
                int32 err_code = cm_get_error_code();
                if (err_code == ERR_FILE_NOT_EXIST) {
                    cm_reset_error();
                    return GS_SUCCESS;
                }
            }
            return GS_ERROR;
        }
    }

    return sql_load_sql_file(handle, full_name);
}

status_t sql_read_lob(sql_stmt_t *stmt, void *locator, uint32 offset, void *buf, uint32 size, uint32 *read_size)
{
    return GS_ERROR;
}

status_t do_commit(session_t *session)
{
    if (session->knl_session.kernel->db.is_readonly) {
        GS_LOG_DEBUG_WAR("[INST] [COMMIT]:operation not supported on read only mode");
        return GS_SUCCESS;
    }

    knl_commit(&session->knl_session);
    return GS_SUCCESS;
}

void do_rollback(session_t *session, knl_savepoint_t *savepoint)
{
    if (session->knl_session.kernel->db.is_readonly) {
        GS_LOG_DEBUG_WAR("[INST] [ROLLBACK]:operation not supported on read only mode");
        return;
    }

    knl_rollback(&session->knl_session, savepoint);
}

status_t sql_alloc_object_id(sql_stmt_t *stmt, int64 *id)
{
    text_t name;
    text_t sys = { .str = SYS_USER_NAME, .len = 3 };
    cm_str2text("OBJECT_ID$", &name);

    return knl_seq_nextval(stmt->session, &sys, &name, id);
}

/*
 * sql_stack_reach_limit
 *
 * This function is used to check the using of current stack.
 */
const long g_stack_reserve_size = (long)GS_STACK_DEPTH_THRESHOLD_SIZE;
static inline bool32 sql_stack_reach_limit(stack_base_t n)
{
    char stack_top_loc;
    if (SECUREC_UNLIKELY(n == NULL)) {
        return GS_FALSE;
    }

    if (labs((long)(n - &stack_top_loc)) > ((long)g_instance->kernel.attr.thread_stack_size - g_stack_reserve_size)) {
        return GS_TRUE;
    }

    return GS_FALSE;
}

/*
 * sql_stack_safe
 *
 * This function is used to check the stack is safe or not.
 */
status_t sql_stack_safe(sql_stmt_t *stmt)
{
    if (SECUREC_UNLIKELY(stmt->session->agent == NULL) || stmt->session->type == SESSION_TYPE_SQL_PAR ||
        stmt->session->type == SESSION_TYPE_KERNEL_PAR) {
        return GS_SUCCESS;
    }

    if (sql_stack_reach_limit(stmt->session->agent->thread.stack_base)) {
        GS_THROW_ERROR(ERR_STACK_LIMIT_EXCEED);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t sql_stack_alloc(void *sql_stmt, uint32 size, void **ptr)
{
    sql_stmt_t *stmt = (sql_stmt_t *)sql_stmt;

    if (cm_stack_alloc(stmt->session->stack, size, ptr) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_STACK_OVERFLOW);
        return GS_ERROR;
    }

    if (size != 0) {
        MEMS_RETURN_IFERR(memset_sp(*ptr, size, 0, size));
    }
    return GS_SUCCESS;
}

status_t var_get_value_in_row(variant_t *var, char *buf, uint32 size, uint16 *len)
{
    errno_t err;
    uint16 offset;
    row_assist_t ra;
    status_t status;
    date_t date_val;

    row_init(&ra, buf, size, 1);
    switch (var->type) {
        case GS_TYPE_UINT32:
            status = row_put_uint32(&ra, var->v_uint32);
            break;

        case GS_TYPE_INTEGER:
            status = row_put_int32(&ra, var->v_int);
            break;

        case GS_TYPE_BOOLEAN:
            status = row_put_bool(&ra, var->v_bool);
            break;

        case GS_TYPE_BIGINT:
            status = row_put_int64(&ra, var->v_bigint);
            break;

        case GS_TYPE_NUMBER:
        case GS_TYPE_DECIMAL:
            status = row_put_dec4(&ra, &var->v_dec);
            break;
        case GS_TYPE_NUMBER2:
            status = row_put_dec2(&ra, &var->v_dec);
            break;

        case GS_TYPE_REAL:
            status = row_put_real(&ra, var->v_real);
            break;

        case GS_TYPE_DATE:
            date_val = cm_adjust_date(var->v_date);
            status = row_put_int64(&ra, date_val);
            break;

        case GS_TYPE_TIMESTAMP:
        case GS_TYPE_TIMESTAMP_TZ_FAKE:
        case GS_TYPE_TIMESTAMP_LTZ:
            status = row_put_int64(&ra, var->v_tstamp);
            break;

        case GS_TYPE_TIMESTAMP_TZ:
            status = row_put_timestamp_tz(&ra, &var->v_tstamp_tz);
            break;

        case GS_TYPE_INTERVAL_DS:
            status = row_put_dsinterval(&ra, var->v_itvl_ds);
            break;

        case GS_TYPE_INTERVAL_YM:

            status = row_put_yminterval(&ra, var->v_itvl_ym);
            break;

        case GS_TYPE_CHAR:
        case GS_TYPE_VARCHAR:
        case GS_TYPE_STRING:
            status = row_put_text(&ra, &var->v_text);
            break;

        default:
            GS_THROW_ERROR(ERR_VALUE_ERROR, "the data type of column is not supported");
            status = GS_ERROR;
            break;
    }

    if (status != GS_SUCCESS) {
        return GS_ERROR;
    }

    cm_decode_row((char *)ra.head, &offset, len, NULL);
    err = memmove_s(buf, size, ra.buf + offset, *len);
    if (err != EOK) {
        GS_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t array_convert_datatype(const nlsparams_t *nls, array_assist_t *aa, vm_lob_t *src, text_buf_t *src_textbuf,
                                typmode_t *mode, vm_lob_t *dst, text_buf_t *dst_textbuf)
{
    uint16 len;
    int32 type;
    uint32 dir_vmid;
    elem_dir_t dir;
    vm_page_t *dir_page = NULL;
    array_head_t *head = NULL;
    array_assist_t dst_aa;
    variant_t var;
    char *val = NULL;

    GS_RETURN_IFERR(array_init(&dst_aa, aa->session, aa->pool, aa->list, dst));

    aa->dir_curr = sizeof(array_head_t);
    GS_RETURN_IFERR(vm_open(aa->session, aa->pool, src->entry_vmid, &dir_page));

    head = (array_head_t *)(dir_page->data);
    type = head->datatype;
    aa->dir_end = sizeof(array_head_t) + sizeof(elem_dir_t) * head->count;
    vm_close(aa->session, aa->pool, src->entry_vmid, VM_ENQUE_TAIL);

    /* convert datatype for each element in src */
    while (aa->dir_curr < aa->dir_end) {
        dir_vmid = array_get_vmid_by_offset(aa, src, aa->dir_curr);
        if (dir_vmid == GS_INVALID_ID32) {
            return GS_ERROR;
        }

        GS_RETURN_IFERR(vm_open(aa->session, aa->pool, dir_vmid, &dir_page));

        dir = *(elem_dir_t *)(dir_page->data + aa->dir_curr % GS_VMEM_PAGE_SIZE);
        vm_close(aa->session, aa->pool, dir_vmid, VM_ENQUE_TAIL);

        if (dir.size == 0) {
            GS_RETURN_IFERR(
                array_append_element(&dst_aa, (uint32)dir.subscript, NULL, 0, ELEMENT_IS_NULL(&dir), dir.last, dst));
            aa->dir_curr += sizeof(elem_dir_t);
            continue;
        }

        GS_RETURN_IFERR(array_get_value_by_dir(aa, src_textbuf->str, src_textbuf->max_size, src, &dir));

        src_textbuf->len = dir.size;
        GS_RETURN_IFERR(var_gen_variant(src_textbuf->str, src_textbuf->len, (uint32)type, &var));

        GS_RETURN_IFERR(var_convert(nls, &var, mode->datatype, dst_textbuf));

        GS_RETURN_IFERR(sql_apply_typmode(&var, mode, dst_textbuf->str, GS_TRUE));

        /* save the convert value to vm lob */
        if (GS_IS_VARLEN_TYPE(var.type) && var.v_text.str != src_textbuf->str) {
            GS_RETURN_IFERR(var_get_value_in_row(&var, src_textbuf->str, src_textbuf->max_size, &len));
            val = src_textbuf->str;
        } else {
            GS_RETURN_IFERR(var_get_value_in_row(&var, dst_textbuf->str, dst_textbuf->max_size, &len));
            val = dst_textbuf->str;
        }
        GS_RETURN_IFERR(
            array_append_element(&dst_aa, (uint32)dir.subscript, val, (uint32)len, GS_FALSE, dir.last, dst));

        aa->dir_curr += sizeof(elem_dir_t);
    }

    return array_update_head_datatype(&dst_aa, dst, (uint32)mode->datatype);
}

status_t sql_compare_array(sql_stmt_t *stmt, variant_t *v1, variant_t *v2, int32 *result)
{
    GS_THROW_ERROR(ERR_INVALID_DATA_TYPE, "comparision");
    return GS_ERROR;
}

/* define convert type methods */
static status_t sql_apply_typmode_char(variant_t *var, const typmode_t *typmod, char *buf)
{
    uint32 value_len, blank_count;

    // column is defined char attr
    if (typmod->is_char) {
        GS_RETURN_IFERR(GET_DATABASE_CHARSET->length(&var->v_text, &value_len));
    } else {
        value_len = var->v_text.len;
    }

    if (value_len == (uint32)typmod->size) {
        return GS_SUCCESS;
    }

    if (value_len > (uint32)typmod->size) {
        var->v_text.len = (uint32)typmod->size;
        blank_count = 0;
    } else {
        blank_count = (uint32)typmod->size - value_len;
    }

    if (var->v_text.str != buf) {
        if (var->v_text.len > 0) {
            MEMS_RETURN_IFERR(memcpy_s(buf, var->v_text.len, var->v_text.str, var->v_text.len));
        }

        if (blank_count != 0) {
            MEMS_RETURN_IFERR(memset_s(buf + var->v_text.len, blank_count, ' ', blank_count));
        }
        var->v_text.str = buf;
    } else {
        if (blank_count != 0) {
            MEMS_RETURN_IFERR(memset_s(var->v_text.str + var->v_text.len, blank_count, ' ', blank_count));
        }
    }

    var->v_text.len += blank_count;

    return GS_SUCCESS;
}

static status_t sql_apply_typmode_str(variant_t *var, const typmode_t *typmod, bool32 is_truc)
{
    uint32 value_len;

    if (typmod->is_char) {
        GS_RETURN_IFERR(GET_DATABASE_CHARSET->length(&var->v_text, &value_len));
    } else {
        value_len = var->v_text.len;
    }

    if (value_len > typmod->size) {
        if (is_truc) {
            var->v_text.len = typmod->size;
        } else {
            GS_THROW_ERROR(ERR_VALUE_CAST_FAILED, value_len, (uint32)typmod->size);
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t sql_apply_typmode_bin(variant_t *var, const typmode_t *typmod, char *buf)
{
    uint32 blank_count;

    if (var->v_bin.size == (uint32)typmod->size) {
        return GS_SUCCESS;
    }

    // char that large than definition will be ignore
    if (var->v_bin.size > (uint32)typmod->size) {
        GS_THROW_ERROR(ERR_VALUE_CAST_FAILED, var->v_bin.size, (uint32)typmod->size);
        return GS_ERROR;
    }

    blank_count = (uint32)typmod->size - var->v_bin.size;
    if (var->v_bin.bytes != (uint8 *)buf) {
        if (var->v_bin.size > 0) {
            MEMS_RETURN_IFERR(memcpy_s(buf, var->v_bin.size, var->v_bin.bytes, var->v_bin.size));
        }

        if (blank_count != 0) {
            MEMS_RETURN_IFERR(memset_s(buf + var->v_bin.size, blank_count, 0x00, blank_count));
        }
        var->v_bin.bytes = (uint8 *)buf;
    } else {
        if (blank_count != 0) {
            MEMS_RETURN_IFERR(memset_s(var->v_bin.bytes + var->v_bin.size, blank_count, 0x00, blank_count));
        }
    }

    var->v_bin.size += blank_count;

    return GS_SUCCESS;
}

status_t sql_apply_typmode(variant_t *var, const typmode_t *typmod, char *buf, bool32 is_truc)
{
    switch (typmod->datatype) {
        case GS_TYPE_NUMBER:
        case GS_TYPE_DECIMAL:
        case GS_TYPE_NUMBER3:
        case GS_TYPE_NUMBER2:
            return cm_adjust_dec(&var->v_dec, typmod->precision, typmod->scale);

        case GS_TYPE_TIMESTAMP:
        case GS_TYPE_TIMESTAMP_TZ_FAKE:
        case GS_TYPE_TIMESTAMP_LTZ:
            return cm_adjust_timestamp(&var->v_tstamp, typmod->precision);

        case GS_TYPE_TIMESTAMP_TZ:
            return cm_adjust_timestamp_tz(&var->v_tstamp_tz, typmod->precision);

        case GS_TYPE_CHAR:
            return sql_apply_typmode_char(var, typmod, buf);

        case GS_TYPE_VARCHAR:
        case GS_TYPE_STRING:
            return sql_apply_typmode_str(var, typmod, is_truc);

        case GS_TYPE_BINARY:
            return sql_apply_typmode_bin(var, typmod, buf);

        case GS_TYPE_VARBINARY:
        case GS_TYPE_RAW:
            if (var->v_bin.size > typmod->size) {
                GS_THROW_ERROR(ERR_VALUE_CAST_FAILED, var->v_bin.size, (uint32)typmod->size);
                return GS_ERROR;
            }
            return GS_SUCCESS;

        case GS_TYPE_CLOB:
        case GS_TYPE_BLOB:
        case GS_TYPE_IMAGE:
        case GS_TYPE_ARRAY:

        case GS_TYPE_BOOLEAN:
        case GS_TYPE_INTERVAL_YM:
        case GS_TYPE_INTERVAL_DS:
        case GS_TYPE_DATE:
        case GS_TYPE_DATETIME_MYSQL:
        case GS_TYPE_TIME_MYSQL:
        case GS_TYPE_DATE_MYSQL:
        case GS_TYPE_UINT32:
        case GS_TYPE_INTEGER:
        case GS_TYPE_BIGINT:
        case GS_TYPE_UINT64:

        case GS_TYPE_RECORD:
            return GS_SUCCESS;

        case GS_TYPE_REAL:
            return cm_adjust_double(&var->v_real, typmod->precision, typmod->scale);

        case GS_TYPE_CURSOR:
        case GS_TYPE_COLUMN:
        case GS_TYPE_BASE:

        default:
            GS_THROW_ERROR(ERR_INVALID_DATA_TYPE, "casting");
            return GS_ERROR;
    }
}

status_t sql_convert_bin(sql_stmt_t *stmt, variant_t *v, uint32 def_size)
{
    char *buf = NULL;
    errno_t errcode;

    if (v->v_bin.size == def_size) {
        return GS_SUCCESS;
    }

    if (v->v_bin.size > def_size) {
        GS_THROW_ERROR(ERR_SIZE_ERROR, v->v_bin.size, def_size, "binary");
        return GS_ERROR;
    }

    SQL_SAVE_STACK(stmt);
    sql_keep_stack_variant(stmt, v);

    if (sql_push(stmt, def_size, (void **)&buf) != GS_SUCCESS) {
        SQL_RESTORE_STACK(stmt);
        return GS_ERROR;
    }
    if ((v->v_bin.size) != 0) {
        errcode = memcpy_s(buf, def_size, v->v_bin.bytes, v->v_bin.size);
        if (errcode != EOK) {
            SQL_RESTORE_STACK(stmt);
            GS_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return GS_ERROR;
        }
    }
    if ((def_size - v->v_bin.size) != 0) {
        errcode = memset_s(buf + v->v_bin.size, def_size - v->v_bin.size, 0x00, def_size - v->v_bin.size);
        if (errcode != EOK) {
            SQL_RESTORE_STACK(stmt);
            GS_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return GS_ERROR;
        }
    }
    v->v_bin.bytes = (uint8 *)buf;
    v->v_bin.size = def_size;

    SQL_RESTORE_STACK(stmt);
    return GS_SUCCESS;
}

status_t sql_get_char_length(text_t *text, uint32 *characters, uint32 def_size)
{
    uint32 pos, temp_bytes, temp_characters;

    pos = temp_characters = 0;

    while (pos < text->len) {
        (void)GET_DATABASE_CHARSET->str_bytes(text->str + pos, text->len - pos, &temp_bytes);

        if (temp_characters == def_size) {
            text->len = pos;
            break;
        }

        pos += temp_bytes;
        temp_characters++;
    }

    *characters = temp_characters;
    return GS_SUCCESS;
}

status_t sql_convert_char(knl_session_t *session, variant_t *v, uint32 def_size, bool32 is_character)
{
    char *buf = NULL;
    uint32 value_len, column_len;
    errno_t errcode;

    if (v->v_text.len > GS_MAX_COLUMN_SIZE) {
        GS_THROW_ERROR(ERR_SIZE_ERROR, v->v_text.len, GS_MAX_COLUMN_SIZE, "char");
        return GS_ERROR;
    }

    if (is_character) {
        GS_RETURN_IFERR(sql_get_char_length(&v->v_text, &value_len, def_size));
    } else {
        value_len = v->v_text.len;
    }

    if (value_len == def_size) {
        return GS_SUCCESS;
    }

    if (value_len > def_size) {
        GS_THROW_ERROR(ERR_SIZE_ERROR, v->v_text.len, def_size, "char");
        return GS_ERROR;
    }

    // one_character may contain multi char
    column_len = MIN((v->v_text.len + (def_size - value_len)), GS_MAX_COLUMN_SIZE);

    CM_SAVE_STACK(session->stack);
    cm_keep_stack_variant(session->stack, v->v_text.str);

    buf = cm_push(session->stack, column_len);
    if (buf == NULL) {
        GS_THROW_ERROR(ERR_STACK_OVERFLOW);
        return GS_ERROR;
    }

    if (v->v_text.len != 0) {
        errcode = memcpy_s(buf, column_len, v->v_text.str, v->v_text.len);
        if (errcode != EOK) {
            CM_RESTORE_STACK(session->stack);
            GS_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return GS_ERROR;
        }
    }
    if ((column_len - v->v_text.len) != 0) {
        errcode = memset_sp(buf + v->v_text.len, column_len - v->v_text.len, ' ', column_len - v->v_text.len);
        if (errcode != EOK) {
            CM_RESTORE_STACK(session->stack);
            GS_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return GS_ERROR;
        }
    }
    v->v_text.str = buf;
    v->v_text.len = column_len;

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t sql_convert_char_cb(knl_handle_t session, text_t *text, uint32 def_size, bool32 is_char)
{
    variant_t v;
    v.type = GS_TYPE_CHAR;
    v.v_text.str = text->str;
    v.v_text.len = text->len;

    GS_RETURN_IFERR(sql_convert_char((knl_session_t *)session, &v, def_size, is_char));

    text->str = v.v_text.str;
    text->len = v.v_text.len;
    return GS_SUCCESS;
}

/* define put key methods */
status_t sql_part_put_number_key(variant_t *value, gs_type_t data_type, part_key_t *partkey, uint32 precision)
{
    switch (data_type) {
        case GS_TYPE_UINT32:
            return part_put_uint32(partkey, value->v_uint32);
        case GS_TYPE_UINT64:
            return part_put_uint64(partkey, value->v_ubigint);
        case GS_TYPE_INTEGER:
            return part_put_int32(partkey, value->v_int);

        case GS_TYPE_BIGINT:
            return part_put_int64(partkey, value->v_bigint);

        case GS_TYPE_REAL:
            return part_put_real(partkey, value->v_real);

        case GS_TYPE_NUMBER:
        case GS_TYPE_NUMBER3:
        case GS_TYPE_DECIMAL:
            return part_put_dec4(partkey, &value->v_dec);

        case GS_TYPE_NUMBER2:
            return part_put_dec2(partkey, &value->v_dec);

        case GS_TYPE_DATE:
        case GS_TYPE_DATE_MYSQL:
            return part_put_date(partkey, value->v_date);

        case GS_TYPE_TIMESTAMP:
        case GS_TYPE_TIMESTAMP_TZ_FAKE:
        case GS_TYPE_TIMESTAMP_LTZ:
            return part_put_timestamp(partkey, value->v_tstamp);

        case GS_TYPE_TIMESTAMP_TZ:
            return part_put_timestamptz(partkey, &value->v_tstamp_tz);

        case GS_TYPE_INTERVAL_DS:
            return part_put_dsinterval(partkey, value->v_itvl_ds);

        case GS_TYPE_INTERVAL_YM:
            return part_put_yminterval(partkey, value->v_itvl_ym);

        default:
            GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "invalid partition key type");
            return GS_ERROR;
    }
}

status_t sql_part_put_scan_key(sql_stmt_t *stmt, variant_t *value, gs_type_t data_type, part_key_t *partkey)
{
    if (value->is_null) {
        part_put_null(partkey);
        return GS_SUCCESS;
    }

    if (value->type != data_type) {
        GS_RETURN_IFERR(sql_convert_variant(stmt, value, data_type));
    }

    switch (data_type) {
        case GS_TYPE_CHAR:
        case GS_TYPE_VARCHAR:
        case GS_TYPE_STRING:
            return part_put_text(partkey, &value->v_text);

        case GS_TYPE_BINARY:
        case GS_TYPE_VARBINARY:
        case GS_TYPE_RAW:
            return part_put_bin(partkey, &value->v_bin);

        default:
            return sql_part_put_number_key(value, data_type, partkey, MQ_MAX_PRECISION);
    }
}

status_t sql_part_put_key(sql_stmt_t *stmt, variant_t *value, gs_type_t data_type, uint32 def_size, bool32 is_character,
                          uint32 precision, int32 scale, part_key_t *partkey)
{
    uint32 value_len;

    if (value->is_null) {
        part_put_null(partkey);
        return GS_SUCCESS;
    }

    if (value->type != data_type) {
        GS_RETURN_IFERR(sql_convert_variant(stmt, value, data_type));
    }

    switch (data_type) {
        case GS_TYPE_CHAR:
            GS_RETURN_IFERR(sql_convert_char(KNL_SESSION(stmt), value, def_size, is_character));
            return part_put_text(partkey, &value->v_text);

        case GS_TYPE_VARCHAR:
        case GS_TYPE_STRING:
            if (is_character) {
                GS_RETURN_IFERR(sql_get_char_length(&value->v_text, &value_len, def_size));
            } else {
                value_len = value->v_text.len;
            }

            return part_put_text(partkey, &value->v_text);

        case GS_TYPE_BINARY:
            GS_RETURN_IFERR(sql_convert_bin(stmt, value, def_size));
            return part_put_bin(partkey, &value->v_bin);

        case GS_TYPE_VARBINARY:
        case GS_TYPE_RAW:
            if (value->v_bin.size > def_size) {
                GS_THROW_ERROR(ERR_SIZE_ERROR, value->v_text.len, def_size, "varchar");
                return GS_ERROR;
            }
            return part_put_bin(partkey, &value->v_bin);

        case GS_TYPE_DECIMAL:
        case GS_TYPE_NUMBER:
            GS_RETURN_IFERR(cm_adjust_dec(&value->v_dec, precision, scale));
            return part_put_dec4(partkey, &value->v_dec);

        case GS_TYPE_NUMBER2:
            GS_RETURN_IFERR(cm_adjust_dec(&value->v_dec, precision, scale));
            return part_put_dec2(partkey, &value->v_dec);

        case GS_TYPE_TIMESTAMP:
        case GS_TYPE_TIMESTAMP_TZ_FAKE:
        case GS_TYPE_TIMESTAMP_LTZ:
            GS_RETURN_IFERR(cm_adjust_timestamp(&value->v_tstamp, precision));
            return part_put_timestamp(partkey, value->v_tstamp);

        case GS_TYPE_TIMESTAMP_TZ:
            GS_RETURN_IFERR(cm_adjust_timestamp_tz(&value->v_tstamp_tz, precision));
            return part_put_timestamptz(partkey, &value->v_tstamp_tz);

        case GS_TYPE_REAL:
            GS_RETURN_IFERR(cm_adjust_double(&value->v_real, precision, scale));
            return part_put_real(partkey, value->v_real);

        default:
            return sql_part_put_number_key(value, data_type, partkey, precision);
    }
}

status_t sql_stmt_clone(sql_stmt_t *src, sql_stmt_t *dest)
{
    uint32 pos = 0;
    uint32 count = src->context->params->count;

    dest->parent_stmt = src;

    dest->context = src->context;
    dest->query_scn = src->query_scn;
    dest->gts_scn = src->gts_scn;
    dest->ssn = src->ssn;
    dest->xact_ssn = src->xact_ssn;
    dest->rs_plan = src->rs_plan;
    dest->rs_type = src->rs_type;
    dest->status = src->status;
    dest->param_info = src->param_info;
    if (count > 0) {
        GS_RETURN_IFERR(sql_alloc_params_buf(dest));
        for (pos = 0; pos < count; pos++) {
            dest->param_info.params[pos] = src->param_info.params[pos];
        }
    }
    dest->params_ready = src->params_ready;

    // reinit
    if (dest->context->fexec_vars_cnt > 0) {
        GS_RETURN_IFERR(
            cm_stack_alloc(dest->session->stack,
                           sizeof(variant_t) * dest->context->fexec_vars_cnt + dest->context->fexec_vars_bytes,
                           (void **)&dest->fexec_info.first_exec_vars));

        sql_reset_first_exec_vars(dest);
    }

    dest->fexec_info.fexec_buff_offset = 0;
    dest->fexec_info.first_exec_buf = NULL;

    return GS_SUCCESS;
}

status_t sql_trace_dml_and_send(sql_stmt_t *stmt)
{
    if (stmt->trace_disabled) {
        return GS_SUCCESS;
    }
    GS_RETURN_IFERR(server_return_success(stmt->session));

    stmt->is_explain = GS_TRUE;
    stmt->lang_type = LANG_EXPLAIN;
    stmt->session->send_pack->head->size = sizeof(cs_packet_head_t);
    stmt->batch_rows = 0;
    stmt->eof = GS_FALSE;

    if (stmt->cursor_stack.depth > 0) {
        sql_free_cursor(stmt, SQL_ROOT_CURSOR(stmt));
    }
    OBJ_STACK_RESET(&stmt->cursor_stack);

    GS_RETURN_IFERR(sql_send_parsed_stmt(stmt));
    return GS_SUCCESS;
}

status_t sql_init_stmt_plan_time(sql_stmt_t *stmt)
{
    if (stmt->context->plan_count == 0) {
        return GS_SUCCESS;
    }
    if (stmt->plan_cnt < stmt->context->plan_count) {
        GS_RETURN_IFERR(vmc_alloc(&stmt->vmc, sizeof(date_t) * stmt->context->plan_count, (void **)&stmt->plan_time));
        stmt->plan_cnt = stmt->context->plan_count;
        for (uint32 i = 0; i < stmt->context->plan_count; i++) {
            stmt->plan_time[i] = 0;
        }
    }
    return GS_SUCCESS;
}

static inline status_t sql_init_context_sign(sql_stmt_t *stmt, sql_context_t *ctx)
{
    GS_RETURN_IFERR(sql_alloc_mem(ctx, GS_MD5_SIZE, (void **)&ctx->ctrl.signature.str));
    ctx->ctrl.signature.len = GS_MD5_SIZE;
    GS_RETURN_IFERR(sql_alloc_mem(ctx, GS_MD5_SIZE, (void **)&ctx->sql_sign.str));
    ctx->sql_sign.len = GS_MD5_SIZE;
    return GS_SUCCESS;
}

static status_t sql_init_context(sql_stmt_t *stmt, sql_context_t *ctx)
{
    GS_RETURN_IFERR(sql_init_context_sign(stmt, ctx));
    GS_RETURN_IFERR(sql_alloc_mem(ctx, sizeof(galist_t), (void **)&ctx->tables));
    cm_galist_init(ctx->tables, ctx, sql_alloc_mem);

    GS_RETURN_IFERR(sql_alloc_mem(ctx, sizeof(galist_t), (void **)&ctx->selects));
    cm_galist_init(ctx->selects, ctx, sql_alloc_mem);

    GS_RETURN_IFERR(sql_alloc_mem(ctx, sizeof(galist_t), (void **)&ctx->dc_lst));
    cm_galist_init(ctx->dc_lst, ctx, sql_alloc_mem);

    GS_RETURN_IFERR(sql_alloc_mem(ctx, sizeof(uint32) * TAB_TYPE_MAX, (void **)&ctx->unnamed_tab_counter));

    ctx->large_page_id = GS_INVALID_ID32;
    ctx->sequences = NULL;

    ctx->ref_objects = NULL;
    ctx->fexec_vars_cnt = 0;
    ctx->fexec_vars_bytes = 0;
    ctx->hash_optm_count = 0;
    ctx->withas_entry = NULL;
    ctx->opt_by_rbo = GS_FALSE;
    ctx->module_kind = CLIENT_KIND_UNKNOWN;
    ctx->obj_belong_self = GS_TRUE;
    ctx->has_pl_objects = GS_FALSE;
    ctx->hash_bucket_size = 0;
    ctx->sql_whitelist = GS_FALSE;
    ctx->policy_used = GS_FALSE;
    ctx->nl_batch_cnt = 0;
    ctx->plan_count = 0;
    ctx->parent = NULL;
    ctx->sub_map_id = GS_INVALID_ID32;
    ctx->in_sql_pool = GS_FALSE;
    ctx->cacheable = GS_TRUE;
    ctx->dynamic_sampling = 0;
    ctx->vm_view_count = 0;
    ctx->hash_mtrl_count = 0;
    ctx->query_count = 0;
    return GS_SUCCESS;
}

status_t sql_alloc_context(sql_stmt_t *stmt)
{
    CM_ASSERT(stmt->context == NULL);
    cm_spin_lock(&stmt->stmt_lock, NULL);
    if (ctx_create(sql_pool, (context_ctrl_t **)&stmt->context)) {
        cm_spin_unlock(&stmt->stmt_lock);
        return GS_ERROR;
    }

    cm_spin_unlock(&stmt->stmt_lock);

#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
    test_memory_pool_maps(sql_pool->memory);
#endif  // DEBUG

    return sql_init_context(stmt, stmt->context);
}

bool8 g_subselect_flags[] = { GS_FALSE, GS_TRUE, GS_TRUE, GS_FALSE, GS_FALSE, GS_TRUE, GS_FALSE };

/* object name case sensitive sql types */
static const sql_type_t g_cs_sql_types[] = {
    SQL_TYPE_SELECT,
    SQL_TYPE_UPDATE,
    SQL_TYPE_INSERT,
    SQL_TYPE_DELETE,
    SQL_TYPE_MERGE,
    SQL_TYPE_REPLACE,
    SQL_TYPE_LOCK_TABLE,
    SQL_TYPE_CREATE_SEQUENCE,
    SQL_TYPE_CREATE_TABLESPACE,
    SQL_TYPE_CREATE_TABLE,
    SQL_TYPE_CREATE_INDEX,
    SQL_TYPE_CREATE_VIEW,
    SQL_TYPE_CREATE_SYNONYM,
    SQL_TYPE_DROP_SEQUENCE,
    SQL_TYPE_DROP_TABLESPACE,
    SQL_TYPE_DROP_TABLE,
    SQL_TYPE_DROP_INDEX,
    SQL_TYPE_DROP_VIEW,
    SQL_TYPE_DROP_SYNONYM,
    SQL_TYPE_TRUNCATE_TABLE,
    SQL_TYPE_PURGE,
    SQL_TYPE_COMMENT,
    SQL_TYPE_FLASHBACK_TABLE,
    SQL_TYPE_ALTER_SEQUENCE,
    SQL_TYPE_ALTER_TABLESPACE,
    SQL_TYPE_ALTER_TABLE,
    SQL_TYPE_ALTER_INDEX,
    SQL_TYPE_ALTER_TRIGGER,
    SQL_TYPE_ANALYSE_TABLE,
    SQL_TYPE_ANONYMOUS_BLOCK,
    SQL_TYPE_CREATE_PROC,
    SQL_TYPE_CREATE_FUNC,
    SQL_TYPE_CREATE_TRIG,
    SQL_TYPE_CREATE_PACK_SPEC,
    SQL_TYPE_CREATE_PACK_BODY,
    SQL_TYPE_DROP_PROC,
    SQL_TYPE_DROP_FUNC,
    SQL_TYPE_DROP_TRIG,
    SQL_TYPE_DROP_PACK_SPEC,
    SQL_TYPE_DROP_PACK_BODY,
    SQL_TYPE_CREATE_USER,
    SQL_TYPE_ALTER_USER,
    SQL_TYPE_CREATE_CHECK_FROM_TEXT,
    SQL_TYPE_CREATE_EXPR_FROM_TEXT,
    SQL_TYPE_CREATE_TYPE_SPEC,
    SQL_TYPE_CREATE_TYPE_BODY,
    SQL_TYPE_DROP_TYPE_SPEC,
    SQL_TYPE_DROP_TYPE_BODY,
    SQL_TYPE_BACKUP,
    SQL_TYPE_RESTORE,
    SQL_TYPE_CREATE_INDEXES,
};
static const uint32 g_cs_type_count = sizeof(g_cs_sql_types) / sizeof(sql_type_t);

ack_sender_t *sql_get_pl_sender(void)
{
    return &g_instance->sql.pl_sender;
}

void sql_create_sender(void)
{
    ack_sender_t *sender = &g_instance->sql.sender;
    sender->init = (init_sender_t)sql_init_sender;
    sender->send_result_success = (send_result_success_t)sql_send_result_success;
    sender->send_result_error = (send_result_error_t)sql_send_result_error;
    sender->send_exec_begin = (send_exec_begin_t)sql_send_exec_begin;
    sender->send_exec_end = (send_exec_end_t)sql_send_exec_end;
    sender->send_import_rows = (send_import_rows_t)sql_send_import_rows;
    sender->send_fetch_begin = (send_fetch_begin_t)sql_send_fetch_begin;
    sender->send_fetch_end = (send_fetch_end_t)sql_send_fetch_end;
    sender->init_row = (init_sender_row_t)sql_init_sender_row;
    sender->send_row_begin = (send_row_begin_t)sql_send_row_begin;
    sender->send_row_end = (send_row_end_t)sql_send_row_end;
    sender->send_row_data = (send_row_data_t)sql_send_row_entire;
    sender->send_parsed_stmt = (send_parsed_stmt_t)sql_send_parsed_stmt;
    sender->send_column_null = (send_column_null_t)sql_send_column_null;
    sender->send_column_uint32 = (send_column_uint32_t)sql_send_column_uint32;
    sender->send_column_int32 = (send_column_int32_t)sql_send_column_int32;
    sender->send_column_int64 = (send_column_int64_t)sql_send_column_int64;
    sender->send_column_real = (send_column_real_t)sql_send_column_real;
    sender->send_column_date = (send_column_date_t)sql_send_column_date;
    sender->send_column_ts = (send_column_ts_t)sql_send_column_ts;
    sender->send_column_tstz = (send_column_ts_tz_t)sql_send_column_tstz;
    sender->send_column_tsltz = (send_column_ts_ltz_t)sql_send_column_tsltz;
    sender->send_column_str = (send_column_str_t)sql_send_column_str;
    sender->send_column_text = (send_column_text_t)sql_send_column_text;
    sender->send_column_bin = (send_column_bin_t)sql_send_column_bin;  // cooperate pl distinguish bin and raw
    sender->send_column_raw = (send_column_bin_t)sql_send_column_bin;  // cooperate pl distinguish bin and raw
    sender->send_column_decimal = (send_column_decimal_t)sql_send_column_decimal;
    sender->send_column_decimal2 = (send_column_decimal2_t)sql_send_column_decimal2;
    sender->send_column_clob = (send_column_lob_t)sql_send_column_lob;
    sender->send_column_blob = (send_column_lob_t)sql_send_column_lob;
    sender->send_column_bool = (send_column_bool_t)sql_send_column_int32;
    sender->send_column_ymitvl = (send_column_ymitvl_t)sql_send_column_ysintvl;
    sender->send_column_dsitvl = (send_column_dsitvl_t)sql_send_column_dsintvl;
    sender->send_serveroutput = (send_serveroutput_t)sql_send_serveroutput;
    sender->send_return_result = (send_return_result_t)sql_send_return_result;
    sender->send_column_cursor = (send_column_cursor_t)sql_send_column_cursor;
    sender->send_column_def = (send_column_def_t)sql_send_column_def;
    sender->send_column_array = (send_column_array_t)sql_send_column_array;
    sender->send_return_value = (send_return_value_t)sql_send_return_values;
    sender->send_nls_feedback = (send_nls_feedback_t)sql_send_nls_feedback;
    sender->send_session_tz_feedback = (send_session_tz_feedback_t)sql_send_session_tz_feedback;

    sender = &g_instance->sql.pl_sender;
    (void)memset_s(sender, sizeof(g_instance->sql.pl_sender), 0, sizeof(g_instance->sql.pl_sender));

    sender = &g_instance->sql.gdv_sender;
    (void)memset_s(sender, sizeof(g_instance->sql.gdv_sender), 0, sizeof(g_instance->sql.gdv_sender));

    sender->send_column_null = (send_column_null_t)sql_send_column_null;
    sender->send_column_uint32 = (send_column_uint32_t)sql_send_column_uint32;
    sender->send_column_int32 = (send_column_int32_t)sql_send_column_int32;
    sender->send_column_int64 = (send_column_int64_t)sql_send_column_int64;
    sender->send_column_real = (send_column_real_t)sql_send_column_real;
    sender->send_column_date = (send_column_date_t)sql_send_column_date;
    sender->send_column_ts = (send_column_ts_t)sql_send_column_ts;
    sender->send_column_tstz = (send_column_ts_tz_t)sql_send_column_tstz;
    sender->send_column_tsltz = (send_column_ts_ltz_t)sql_send_column_tsltz;
    sender->send_column_str = (send_column_str_t)sql_send_column_str;
    sender->send_column_text = (send_column_text_t)sql_send_column_text;
    sender->send_column_bin = (send_column_bin_t)sql_send_column_bin;  // cooperate pl distinguish bin and raw
    sender->send_column_raw = (send_column_bin_t)sql_send_column_bin;  // cooperate pl distinguish bin and raw
    sender->send_column_decimal = (send_column_decimal_t)sql_send_column_decimal;
    sender->send_column_clob = (send_column_lob_t)sql_send_column_lob;
    sender->send_column_blob = (send_column_lob_t)sql_send_column_lob;
    sender->send_column_bool = (send_column_bool_t)sql_send_column_int32;
    sender->send_column_ymitvl = (send_column_ymitvl_t)sql_send_column_ysintvl;
    sender->send_column_dsitvl = (send_column_dsitvl_t)sql_send_column_dsintvl;
    sender->send_serveroutput = (send_serveroutput_t)sql_send_serveroutput;
    sender->send_return_result = (send_return_result_t)sql_send_return_result;
    sender->send_column_cursor = (send_column_cursor_t)sql_send_column_cursor;
    sender->send_column_def = (send_column_def_t)sql_send_column_def;
    sender->send_column_array = (send_column_array_t)sql_send_column_array;
}

status_t sql_instance_startup(void)
{
    GS_RETURN_IFERR(sql_create_context_pool());
    lex_init_keywords();
    sql_create_sender();
    return GS_SUCCESS;
}

/* close the resource(like dc in sql, sqls in anonymous block) if the context ref count is 0 */
void sql_close_context_resource(context_ctrl_t *ctrl)
{
    if (ctrl->cleaned) {
        return;
    }
    sql_close_dc(ctrl);
    ctrl->cleaned = GS_TRUE;
}
/* close the dc if the context ref count is 0 */
void sql_close_dc(context_ctrl_t *ctrl)
{
    sql_context_t *ctx = (sql_context_t *)ctrl;
    sql_table_entry_t *table = NULL;

    if (ctrl->cleaned) {
        return;
    }

    for (uint32 i = 0; ctx->tables != NULL && i < ctx->tables->count; i++) {
        table = (sql_table_entry_t *)cm_galist_get(ctx->tables, i);
        // if dc open failed before,table name may be null.due to this no need close dc here
        if (table->name.str == NULL) {
            continue;
        }
        if (IS_LTT_BY_NAME(table->name.str) || IS_DBLINK_TABLE(table)) {
            // do nothing for ltt dc or dblink table dc
            continue;
        }
        knl_close_dc(&table->dc);
    }
}

void sql_context_uncacheable(sql_context_t *ctx)
{
    if (ctx == NULL) {
        return;
    }

    ctx->cacheable = GS_FALSE;
}

void sql_free_context(sql_context_t *ctx)
{
    if (ctx == NULL) {
        return;
    }
    if (ctx->in_sql_pool) {
        text_t sql_text;
        ctx_read_first_page_text(ctx->ctrl.pool, &ctx->ctrl, &sql_text);
        GS_THROW_ERROR_EX(ERR_ASSERT_ERROR, "cannot free context cached in sql pool, sql=[%s]", T2S(&sql_text));
        return;
    }

    if (ctx->large_page_id != GS_INVALID_ID32) {
        mpool_free_page(&g_instance->sga.large_pool, ctx->large_page_id);
        ctx->large_page_id = GS_INVALID_ID32;
    }

    sql_close_dc(&ctx->ctrl);
    CM_ASSERT(ctx->ctrl.hash_next == NULL);
    CM_ASSERT(ctx->ctrl.hash_prev == NULL);
    CM_ASSERT(ctx->ctrl.lru_next == NULL);
    CM_ASSERT(ctx->ctrl.lru_prev == NULL);
    CM_ASSERT(ctx->ctrl.ref_count == 0);
    mctx_destroy(ctx->ctrl.memory);
#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
    test_memory_pool_maps(sql_pool->memory);
#endif  // DEBUG
}

void ctx_recycle_all(void)
{
    ctx_recycle_all_core(sql_pool);
}

void dc_recycle_external(void)
{
    ctx_recycle_all();
}

bool32 ctx_recycle_internal(void)
{
    return ctx_recycle_internal_core(sql_pool);
}

status_t sql_alloc_mem(void *context, uint32 size, void **buf)
{
    sql_context_t *ctx = (sql_context_t *)context;
    CM_ASSERT(!ctx->readonly);
    return sql_ctx_alloc_mem(ctx->ctrl.pool, ctx->ctrl.memory, size, buf);
}

bool32 sql_upper_case_name(sql_context_t *ctx)
{
    if (IS_CASE_INSENSITIVE) {
        return GS_TRUE;
    }
    for (uint32 i = 0; i < g_cs_type_count; ++i) {
        if (ctx->type == g_cs_sql_types[i]) {
            return GS_FALSE;
        }
    }

    if (IS_COMPATIBLE_MYSQL_INST) {
        return GS_FALSE;
    }
    return GS_TRUE;
}

status_t sql_copy_name_cs(sql_context_t *ctx, text_t *src, text_t *dst)
{
    if (IS_CASE_INSENSITIVE) {
        return sql_copy_name(ctx, src, dst);
    }
    if (src->len > GS_MAX_NAME_LEN) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "'%s' is too long to as name", T2S(src));
        return GS_ERROR;
    }
    if (src->len == 0) {
        dst->len = 0;
        return GS_SUCCESS;
    }
    return sql_copy_text(ctx, src, dst);
}

status_t sql_copy_name(sql_context_t *ctx, text_t *src, text_t *dst)
{
    uint32 i;

    if (src->len > GS_MAX_NAME_LEN) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "'%s' is too long to as name", T2S(src));
        return GS_ERROR;
    }

    if (src->len == 0) {
        dst->len = 0;
        return GS_SUCCESS;
    }

    if (sql_alloc_mem(ctx, src->len, (void **)&dst->str) != GS_SUCCESS) {
        return GS_ERROR;
    }

    dst->len = src->len;
    for (i = 0; i < dst->len; i++) {
        dst->str[i] = UPPER(src->str[i]);
    }

    return GS_SUCCESS;
}

status_t sql_copy_name_loc(sql_context_t *ctx, sql_text_t *src, sql_text_t *dst)
{
    dst->loc = src->loc;
    return sql_copy_name(ctx, &src->value, &dst->value);
}

status_t sql_copy_name_prefix_tenant_loc(void *stmt_in, sql_text_t *src, sql_text_t *dst)
{
    sql_stmt_t *stmt = stmt_in;

    dst->loc = src->loc;
    return sql_copy_prefix_tenant(stmt, &src->value, &dst->value, sql_copy_name);
}

status_t sql_copy_object_name(sql_context_t *ctx, word_type_t type, text_t *src, text_t *dst)
{
    if (IS_DQ_STRING(type)) {
        return sql_copy_text(ctx, src, dst);
    }
    return sql_upper_case_name(ctx) ? sql_copy_name(ctx, src, dst) : sql_copy_name_cs(ctx, src, dst);
}

status_t sql_copy_object_name_prefix_tenant(void *stmt_in, word_type_t type, text_t *src, text_t *dst)
{
    sql_stmt_t *stmt = stmt_in;

    if (IS_DQ_STRING(type)) {
        return sql_copy_prefix_tenant(stmt, src, dst, sql_copy_text);
    }

    if (sql_upper_case_name(stmt->context)) {
        return sql_copy_prefix_tenant(stmt, src, dst, sql_copy_name);
    }

    return sql_copy_prefix_tenant(stmt, src, dst, sql_copy_name_cs);
}

status_t sql_copy_prefix_tenant(void *stmt_in, text_t *src, text_t *dst, sql_copy_func_t sql_copy_func)
{
    text_t name;
    char buf[GS_NAME_BUFFER_SIZE];
    sql_stmt_t *stmt = stmt_in;

    if (sql_upper_case_name(stmt->context)) {
        cm_text2str_with_upper(src, buf, GS_NAME_BUFFER_SIZE);
    } else {
        if (cm_text2str(src, buf, GS_NAME_BUFFER_SIZE) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    cm_str2text(buf, &name);
    if (sql_copy_func(stmt->context, &name, dst) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t sql_copy_object_name_loc(sql_context_t *ctx, word_type_t type, sql_text_t *src, sql_text_t *dst)
{
    dst->loc = src->loc;
    return sql_copy_object_name(ctx, type, &src->value, &dst->value);
}

status_t sql_copy_object_name_prefix_tenant_loc(void *stmt_in, word_type_t type, sql_text_t *src, sql_text_t *dst)
{
    sql_stmt_t *stmt = stmt_in;

    dst->loc = src->loc;
    return sql_copy_object_name_prefix_tenant(stmt, type, &src->value, &dst->value);
}

status_t sql_user_text_prefix_tenant(void *session_in, text_t *user, char *buf, uint32 buf_size)
{
    GS_RETURN_IFERR(cm_text2str(user, buf, buf_size));
    cm_str2text(buf, user);
    return GS_SUCCESS;
}

status_t sql_copy_object_name_ci(sql_context_t *ctx, word_type_t type, text_t *src, text_t *dst)
{
    if (IS_DQ_STRING(type)) {
        return sql_copy_text(ctx, src, dst);
    }
    return sql_copy_name(ctx, src, dst);
}
status_t sql_copy_str_safe(sql_context_t *ctx, char *src, uint32 len, text_t *dst)
{
    text_t src_text;
    cm_str2text_safe(src, len, &src_text);
    return sql_copy_text(ctx, &src_text, dst);
}
status_t sql_copy_str(sql_context_t *ctx, char *src, text_t *dst)
{
    text_t src_text;
    cm_str2text_safe(src, (uint32)strlen(src), &src_text);
    return sql_copy_text(ctx, &src_text, dst);
}

status_t sql_copy_text(sql_context_t *ctx, text_t *src, text_t *dst)
{
    if (sql_alloc_mem(ctx, src->len, (void **)&dst->str) != GS_SUCCESS) {
        return GS_ERROR;
    }
    if (src->len != 0) {
        MEMS_RETURN_IFERR(memcpy_s(dst->str, src->len, src->str, src->len));
    }
    dst->len = src->len;
    return GS_SUCCESS;
}

status_t sql_copy_binary(sql_context_t *ctx, binary_t *src, binary_t *dst)
{
    if (sql_alloc_mem(ctx, src->size, (void **)&dst->bytes) != GS_SUCCESS) {
        return GS_ERROR;
    }
    if (src->size != 0) {
        MEMS_RETURN_IFERR(memcpy_s(dst->bytes, src->size, src->bytes, src->size));
    }
    dst->size = src->size;
    return GS_SUCCESS;
}

status_t sql_copy_text_upper(sql_context_t *ctx, text_t *src, text_t *dst)
{
    uint32 i;
    if (sql_alloc_mem(ctx, src->len, (void **)&dst->str) != GS_SUCCESS) {
        return GS_ERROR;
    }

    dst->len = src->len;
    for (i = 0; i < dst->len; i++) {
        dst->str[i] = UPPER(src->str[i]);
    }

    return GS_SUCCESS;
}

static inline void sql_convert_slash(text_t *dst, uint32 size)
{
    for (uint32 i = 0; i < size; i++) {
        if (dst->str[i] == '/') {
            dst->str[i] = '\\';
        }
    }
}

status_t sql_copy_file_name(sql_context_t *ctx, text_t *src, text_t *dst)
{
    uint32 size, home_len, offset, len;
    text_t file_name = *src;
    bool32 in_home = GS_FALSE;
    bool32 in_home_data = GS_FALSE;
    cm_trim_text(&file_name);

    if (file_name.len == 0) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "file name missing");
        return GS_ERROR;
    }

    home_len = (uint32)strlen(g_instance->home);

    if (file_name.str[0] == '?') {
        file_name.len--;
        file_name.str++;
        size = home_len + file_name.len;

        in_home = GS_TRUE;
    } else if (file_name.str[0] != '*' && file_name.str[0] != '-' && file_name.str[0] != '+' &&
               file_name.str[0] != '/' && file_name.str[1] != ':') {
        size = home_len + file_name.len + (uint32)strlen("/data/");
        in_home_data = GS_TRUE;
    } else {
        size = file_name.len;
    }

    if (size > GS_MAX_FILE_NAME_LEN) {
        GS_THROW_ERROR(ERR_NAME_TOO_LONG, "datafile", size, GS_MAX_FILE_NAME_LEN);
        return GS_ERROR;
    }
    len = size + 1;
    offset = 0;
    GS_RETURN_IFERR(sql_alloc_mem(ctx, len, (void **)&dst->str));

    if (in_home) {
        if (home_len != 0) {
            MEMS_RETURN_IFERR(memcpy_s(dst->str, len, g_instance->home, home_len));
        }
        offset += home_len;
        if (file_name.len != 0) {
            MEMS_RETURN_IFERR(memcpy_s(dst->str + offset, len - offset, file_name.str, file_name.len));
        }
    } else if (in_home_data) {
        if (home_len != 0) {
            MEMS_RETURN_IFERR(memcpy_s(dst->str, len, g_instance->home, home_len));
        }
        offset += home_len;
        MEMS_RETURN_IFERR(memcpy_s(dst->str + offset, len - offset, "/data/", strlen("/data/")));

        offset += (uint32)strlen("/data/");
        if (file_name.len != 0) {
            MEMS_RETURN_IFERR(memcpy_s(dst->str + offset, len - offset, file_name.str, file_name.len));
        }
    } else {
        if (file_name.len != 0) {
            MEMS_RETURN_IFERR(memcpy_s(dst->str, len, file_name.str, file_name.len));
        }
    }

    dst->len = size;
    dst->str[size] = '\0';

#ifdef WIN32
    sql_convert_slash(dst, size);
#endif /* WIN32 */

    return GS_SUCCESS;
}

status_t sql_array_put(sql_array_t *array, pointer_t ptr)
{
    if (array->count >= array->capacity) {
        GS_THROW_ERROR(ERR_OUT_OF_INDEX, "array", array->capacity);
        return GS_ERROR;
    }

    array->items[array->count] = ptr;
    array->count++;
    return GS_SUCCESS;
}

status_t sql_array_concat(sql_array_t *array1, sql_array_t *array2)
{
    uint32 i;

    if (array1->count + array2->count > array1->capacity) {
        GS_THROW_ERROR(ERR_OUT_OF_INDEX, "array", array1->capacity);
        return GS_ERROR;
    }

    for (i = 0; i < array2->count; i++) {
        array1->items[array1->count] = array2->items[i];
        array1->count++;
    }

    return GS_SUCCESS;
}

status_t sql_array_delete(sql_array_t *array, uint32 index)
{
    if (index >= array->count) {
        GS_THROW_ERROR(ERR_OUT_OF_INDEX, "array", array->count);
        return GS_ERROR;
    }
    for (uint32 i = index; i < array->count - 1; ++i) {
        array->items[i] = array->items[i + 1];
    }
    array->count--;
    return GS_SUCCESS;
}

status_t sql_array_set(sql_array_t *array, uint32 index, pointer_t ptr)
{
    if (index >= array->count) {
        GS_THROW_ERROR(ERR_OUT_OF_INDEX, "array", array->count);
        return GS_ERROR;
    }

    array->items[index] = ptr;
    return GS_SUCCESS;
}

void sql_destroy_context_pool(void)
{
    ctx_pool_destroy(g_instance->sql.pool);
}

status_t sql_create_context_pool(void)
{
    context_pool_profile_t profile;

    profile.area = &g_instance->sga.shared_area;
    profile.name = "sql pool";
    profile.clean = sql_close_context_resource;
    profile.init_pages = GS_MIN_SQL_PAGES;
    profile.optimize_pages =
        (uint32)(int32)(g_instance->sga.shared_area.page_count * g_instance->kernel.attr.sql_pool_factor);
    if (profile.optimize_pages < GS_MIN_SQL_PAGES) {
        profile.optimize_pages = GS_MIN_SQL_PAGES;
    }
    profile.context_size = sizeof(sql_context_t);
    profile.bucket_count = GS_SQL_BUCKETS;

    if (ctx_pool_create(&profile, &sql_pool) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

project_col_info_t *sql_get_project_info_col(project_col_array_t *project_col_array, uint32 col_id)
{
    if (col_id >= project_col_array->count) {
        GS_THROW_ERROR_EX(ERR_ASSERT_ERROR, "col_id(%u) < project_col_array->count(%u)", col_id,
                          project_col_array->count);
    }
    uint32 index = col_id / PROJECT_COL_ARRAY_STEP;
    uint32 offset = col_id % PROJECT_COL_ARRAY_STEP;
    return &project_col_array->base[index][offset];
}

bool32 sql_if_all_comma_join(sql_join_node_t *join_node)
{
    if (join_node->type == JOIN_TYPE_COMMA || join_node->type == JOIN_TYPE_CROSS) {
        return (bool32)(sql_if_all_comma_join(join_node->left) && sql_if_all_comma_join(join_node->right));
    }

    return (join_node->type == JOIN_TYPE_NONE);
}

void sql_context_inc_exec(sql_context_t *context)
{
    context_ctrl_t *ctrl = NULL;

    if (context == NULL) {
        return;
    }
    ctrl = &context->ctrl;
    cm_spin_lock(&ctrl->lock, NULL);
    CM_ASSERT(ctrl->exec_count >= 0);
    ctrl->exec_count++;
    cm_spin_unlock(&ctrl->lock);
}

void sql_context_dec_exec(sql_context_t *context)
{
    context_ctrl_t *ctrl = NULL;

    if (context == NULL) {
        return;
    }
    ctrl = &context->ctrl;
    ctx_dec_exec(ctrl);
}

static unnamed_tab_info_t g_unnamed_tab_info[] = {
    { TAB_TYPE_PIVOT, { (char *)"$FROM_PIVOT_", 12 } },    { TAB_TYPE_UNPIVOT, { (char *)"$FROM_UNPIVOT_", 14 } },
    { TAB_TYPE_TABLE_FUNC, { (char *)"$FROM_FT_", 9 } },   { TAB_TYPE_OR_EXPAND, { (char *)"$FROM_ORE_", 10 } },
    { TAB_TYPE_WINMAGIC, { (char *)"$FROM_WMR_", 10 } },   { TAB_TYPE_SUBQRY_TO_TAB, { (char *)"$FROM_SQ_", 9 } },
    { TAB_TYPE_UPDATE_SET, { (char *)"$FROM_UUS_", 10 } },
};

status_t sql_generate_unnamed_table_name(void *stmt_in, sql_table_t *table, unnamed_tab_type_t type)
{
    sql_stmt_t *stmt = (sql_stmt_t *)stmt_in;
    text_t prefix = g_unnamed_tab_info[type].prefix;
    text_t name = { 0 };
    uint32 id = stmt->context->unnamed_tab_counter[type];
    char row_id[GS_MAX_INT32_STRLEN + 1] = { 0 };

    int32 len = snprintf_s(row_id, GS_MAX_INT32_STRLEN + 1, GS_MAX_INT32_STRLEN, PRINT_FMT_UINT32, id);
    PRTS_RETURN_IFERR(len);
    uint32 max_size = (uint32)len + prefix.len;

    GS_RETURN_IFERR(sql_push(stmt, max_size, (void **)&name.str));

    cm_concat_text(&name, max_size, &prefix);
    GS_RETURN_IFERR(cm_concat_n_string(&name, max_size, row_id, len));

    GS_RETURN_IFERR(sql_copy_text(stmt->context, &name, &table->alias.value));
    table->alias.implicit = GS_TRUE;

    stmt->context->unnamed_tab_counter[type]++;

    SQL_POP(stmt);

    return GS_SUCCESS;
}

status_t sql_create_list(sql_stmt_t *stmt, galist_t **list)
{
    if (sql_alloc_mem(stmt->context, sizeof(galist_t), (void **)list) != GS_SUCCESS) {
        return GS_ERROR;
    }

    cm_galist_init((*list), stmt->context, sql_alloc_mem);
    return GS_SUCCESS;
}

static status_t sql_create_dml_context(sql_stmt_t *stmt, sql_text_t *sql, key_wid_t wid)
{
    sql_context_t *ctx = stmt->context;

    // write dml sql into context
    GS_RETURN_IFERR(ctx_write_text(&ctx->ctrl, (text_t *)sql));

    GS_RETURN_IFERR(sql_create_list(stmt, &ctx->params));
    GS_RETURN_IFERR(sql_create_list(stmt, &ctx->csr_params));
    GS_RETURN_IFERR(sql_create_list(stmt, &ctx->ref_objects));
    GS_RETURN_IFERR(sql_create_list(stmt, &ctx->outlines));

    stmt->session->lex->flags = LEX_WITH_OWNER | LEX_WITH_ARG;

    switch (wid) {
        case KEY_WORD_SELECT:
            stmt->context->type = SQL_TYPE_SELECT;
            return sql_create_select_context(stmt, sql, SELECT_AS_RESULT, (sql_select_t **)&ctx->entry);

        case KEY_WORD_WITH:
        case KEY_WORD_UPDATE:
        case KEY_WORD_INSERT:
        case KEY_WORD_DELETE:
            GS_SRC_THROW_ERROR(sql->loc, ERR_CAPABILITY_NOT_SUPPORT, "insert/update/delete");
            return GS_ERROR;
        default:
            GS_SRC_THROW_ERROR(sql->loc, ERR_SQL_SYNTAX_ERROR, "missing keyword");
            return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t sql_create_dml(sql_stmt_t *stmt, sql_text_t *sql, key_wid_t wid)
{
    GS_RETURN_IFERR(sql_create_dml_context(stmt, sql, wid));
    GS_RETURN_IFERR(sql_verify(stmt));

    return sql_create_dml_plan(stmt);
}

status_t sql_create_dml_currently(sql_stmt_t *stmt, sql_text_t *sql, key_wid_t wid)
{
    cm_spin_lock(&stmt->session->sess_lock, NULL);
    stmt->session->current_sql = sql->value;
    stmt->session->sql_id = stmt->context->ctrl.hash_value;
    cm_spin_unlock(&stmt->session->sess_lock);

    status_t ret = sql_create_dml(stmt, sql, wid);

    cm_spin_lock(&stmt->session->sess_lock, NULL);
    stmt->session->current_sql = CM_NULL_TEXT;
    stmt->session->sql_id = 0;
    cm_spin_unlock(&stmt->session->sess_lock);
    return ret;
}

bool32 sql_has_ltt(sql_stmt_t *stmt, text_t *sql)
{
    // simple scan sql to find name starts with `#`
    bool32 quote = GS_FALSE;
    for (uint32 i = 0; i < sql->len; i++) {
        if (sql->str[i] == '\'') {
            quote = !quote;
        }

        if (quote) {
            continue;
        }

        if (knl_is_llt_by_name(sql->str[i]) && i > 0) {
            char c = sql->str[i - 1];
            if (c == '`' || c == '"' || is_splitter(c)) {
                return GS_TRUE;
            }
        }
    }
    return GS_FALSE;
}

uint32 sql_has_special_word(sql_stmt_t *stmt, text_t *sql)
{
    // simple scan sql to find name starts with `#`
    bool32 quote = GS_FALSE;
    uint32 result = SQL_HAS_NONE;
    for (uint32 i = 0; i < sql->len; i++) {
        if (sql->str[i] == '\'') {
            quote = !quote;
        }

        if (quote) {
            continue;
        }

        // dblink
        if (sql->str[i] == '@') {
            result |= SQL_HAS_DBLINK;
        }

        // local temporary table
        if (knl_is_llt_by_name(sql->str[i]) && i > 0) {
            char c = sql->str[i - 1];
            if (c == '`' || c == '"' || is_splitter(c)) {
                result |= SQL_HAS_LTT;
            }
        }
    }
    return result;
}

static inline void sql_init_plan_count(sql_stmt_t *stmt)
{
    stmt->context->clause_info.union_all_count = 0;
}

void sql_parse_set_context_procinfo(sql_stmt_t *stmt)
{
    CM_POINTER2(stmt, stmt->context);

    /* for the ANONYMOUS BLOCK or CALL statement, there is no procedure oid */
    knl_panic(stmt->pl_compiler == NULL);
}

void sql_enrich_context_for_uncached(sql_stmt_t *stmt, timeval_t *tv_begin)
{
    timeval_t tv_end;
    (void)cm_gettimeofday(&tv_end);
    stmt->context->module_kind = SESSION_CLIENT_KIND(stmt->session);
    stmt->context->ctrl.ref_count = 0;
    sql_parse_set_context_procinfo(stmt);
    if (stmt->context->ctrl.memory != NULL) {
        cm_atomic_add(&g_instance->library_cache_info[stmt->lang_type].pins,
                      (int64)stmt->context->ctrl.memory->pages.count);
        cm_atomic_inc(&g_instance->library_cache_info[stmt->lang_type].reloads);
    }
}

status_t sql_parse_dml_directly(sql_stmt_t *stmt, key_wid_t wid, sql_text_t *sql)
{
    GS_RETURN_IFERR(sql_alloc_context(stmt));

    sql_context_uncacheable(stmt->context);
    ((context_ctrl_t *)stmt->context)->uid = stmt->session->knl_session.uid;
    sql_init_plan_count(stmt);

    timeval_t tv_begin;
    (void)cm_gettimeofday(&tv_begin);

    GS_RETURN_IFERR(sql_create_dml_currently(stmt, sql, wid));

    sql_enrich_context_for_uncached(stmt, &tv_begin);
    return GS_SUCCESS;
}

status_t sql_parse_dml(sql_stmt_t *stmt, key_wid_t wid)
{
    GS_LOG_DEBUG_INF("Begin parse DML, SQL = %s", T2S(&stmt->session->lex->text.value));
    cm_atomic_inc(&g_instance->library_cache_info[stmt->lang_type].hits);
    // maybe need load entity from proc$
    knl_set_session_scn(&stmt->session->knl_session, GS_INVALID_ID64);

    uint32 special_word = sql_has_special_word(stmt, &stmt->session->lex->text.value);

    GS_RETURN_IFERR(sql_parse_dml_directly(stmt, wid, &stmt->session->lex->text));
    stmt->context->has_ltt = (special_word & SQL_HAS_LTT);

    return GS_SUCCESS;
}
status_t sql_try_parse_table_alias(sql_stmt_t *stmt, sql_text_t *alias, word_t *word)
{
    if (word->type == WORD_TYPE_EOF || !IS_VARIANT(word)) {
        return GS_SUCCESS;
    }

    GS_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR, "only single simple select supported.");
    return GS_ERROR;
}

status_t sql_decode_object_name(sql_stmt_t *stmt, word_t *word, sql_text_t *user, sql_text_t *name)
{
    var_word_t var_word;

    if (sql_word_as_table(stmt, word, &var_word) != GS_SUCCESS) {
        return GS_ERROR;
    }

    *user = var_word.table.user;
    *name = var_word.table.name;

    return GS_SUCCESS;
}

status_t sql_regist_table(sql_stmt_t *stmt, sql_table_t *table)
{
    uint32 i;
    sql_context_t *context = stmt->context;
    sql_table_entry_t *table_entry = NULL;

    for (i = 0; i < context->tables->count; i++) {
        table_entry = (sql_table_entry_t *)cm_galist_get(context->tables, i);
        if (cm_text_equal(&table_entry->name, &table->name.value) &&
            cm_text_equal(&table_entry->user, &table->user.value) &&
            cm_text_equal(&table_entry->dblink, &table->dblink.value)) {
            table->entry = table_entry;
            return GS_SUCCESS;
        }
    }

    GS_RETURN_IFERR(cm_galist_new(context->tables, sizeof(sql_table_entry_t), (pointer_t *)&table_entry));

    table_entry->name = table->name.value;
    table_entry->user = table->user.value;
    table_entry->dblink = table->dblink.value;
    table_entry->dc.type = DICT_TYPE_UNKNOWN;

    table->entry = table_entry;
    return GS_SUCCESS;
}

static status_t sql_convert_normal_table(sql_stmt_t *stmt, word_t *word, sql_table_t *table)
{
    if (word->ex_count == 1) {
        if (word->type == WORD_TYPE_DQ_STRING) {
            table->user_has_quote = GS_TRUE;
        }
        table->tab_name_has_quote = (word->ex_words[0].type == WORD_TYPE_DQ_STRING) ? GS_TRUE : GS_FALSE;
    } else {
        if (word->type == WORD_TYPE_DQ_STRING) {
            table->tab_name_has_quote = GS_TRUE;
        }
    }

    if (sql_decode_object_name(stmt, word, &table->user, &table->name) != GS_SUCCESS) {
        cm_set_error_loc(word->loc);
        return GS_ERROR;
    }

    if (sql_regist_table(stmt, table) != GS_SUCCESS) {
        cm_set_error_loc(word->loc);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t sql_try_parse_table_version(sql_stmt_t *stmt, sql_table_snapshot_t *version, word_t *word);

static status_t sql_try_parse_table_attribute(sql_stmt_t *stmt, word_t *word, sql_table_t *query_table,
                                              bool32 *pivot_table)
{
    uint32 flags = stmt->session->lex->flags;
    stmt->session->lex->flags = LEX_SINGLE_WORD;
    GS_RETURN_IFERR(sql_try_parse_table_version(stmt, &query_table->version, word));
    if (query_table->version.type != CURR_VERSION && IS_DBLINK_TABLE(query_table)) {
        GS_SRC_THROW_ERROR(word->loc, ERR_CAPABILITY_NOT_SUPPORT, "pivot or unpivot on dblink table");
        return GS_ERROR;
    }

    if (word->id == KEY_WORD_PARTITION || word->id == KEY_WORD_SUBPARTITION) {
        if (word->id == KEY_WORD_PARTITION) {
            query_table->part_info.is_subpart = GS_FALSE;
        } else {
            query_table->part_info.is_subpart = GS_TRUE;
        }

        knl_panic(0);
    }

    stmt->session->lex->flags = flags;
    knl_panic(word->id != KEY_WORD_PIVOT && word->id != KEY_WORD_UNPIVOT);
    stmt->session->lex->flags = LEX_SINGLE_WORD;
    if (query_table->alias.len == 0) {
        GS_RETURN_IFERR(sql_try_parse_table_alias(stmt, &query_table->alias, word));
    }

    if (query_table->alias.len > 0) {
        if (query_table->type == JOIN_AS_TABLE) {
            GS_SRC_THROW_ERROR(word->loc, ERR_SQL_SYNTAX_ERROR, "table join does not support aliases");
            return GS_ERROR;
        }
        knl_panic(0);
    }

    stmt->session->lex->flags = flags;

    return GS_SUCCESS;
}

static status_t sql_create_query_table(sql_stmt_t *stmt, sql_array_t *tables, sql_join_assist_t *join_assist,
                                       sql_table_t *query_table, word_t *word);

#define IS_INCLUDE_SPEC_WORD(word)                                                                             \
    (((*(word)).id == KEY_WORD_LEFT) || ((*(word)).id == KEY_WORD_RIGHT) || ((*(word)).id == KEY_WORD_FULL) || \
     ((*(word)).id == KEY_WORD_JOIN) || ((*(word)).id == KEY_WORD_INNER) || (IS_SPEC_CHAR((word), ',')))

static status_t sql_try_parse_partition_table_outside_alias(sql_stmt_t *stmt, sql_table_t *query_table, lex_t *lex,
                                                            word_t *word, sql_array_t *tables)
{
    // select * from ((tableA) partition(p2)) aliasA
    if (query_table->alias.len == 0) {
        GS_RETURN_IFERR(sql_try_parse_table_attribute(stmt, word, query_table, NULL));
    } else {
        GS_SRC_THROW_ERROR(word->loc, ERR_SQL_SYNTAX_ERROR, "table alias not supported.");
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

static status_t sql_try_parse_table_wrapped(sql_stmt_t *stmt, sql_array_t *tables, sql_join_assist_t *join_assist,
                                            sql_table_t *query_table, word_t *word)
{
    lex_t *lex = stmt->session->lex;
    GS_RETURN_IFERR(lex_expected_fetch(lex, word));
    if (word->type != WORD_TYPE_DQ_STRING) {
        cm_trim_text(&word->text.value);
        cm_remove_brackets(&word->text.value);
    }

    if (word->text.len > 0 && word->text.str[0] == '(' && word->type == WORD_TYPE_BRACKET) {
        GS_SRC_THROW_ERROR(word->loc, ERR_SQL_SYNTAX_ERROR, "'(' not supported.");
        return GS_ERROR;
    }

    GS_RETURN_IFERR(sql_create_query_table(stmt, tables, join_assist, query_table, word));
    return sql_try_parse_partition_table_outside_alias(stmt, query_table, lex, word, tables);
}

static status_t sql_parse_query_table(sql_stmt_t *stmt, sql_array_t *tables, sql_join_assist_t *join_assist,
                                      sql_table_t **query_table, word_t *word)
{
    if (sql_array_new(tables, sizeof(sql_table_t), (void **)query_table) != GS_SUCCESS) {
        return GS_ERROR;
    }
    (*query_table)->id = tables->count - 1;
    (*query_table)->rs_nullable = GS_FALSE;

    return sql_try_parse_table_wrapped(stmt, tables, join_assist, *query_table, word);
}

static status_t sql_create_normal_query_table(sql_stmt_t *stmt, word_t *word, sql_table_t *query_table)
{
    return sql_convert_normal_table(stmt, word, query_table);
}

static status_t sql_create_query_table(sql_stmt_t *stmt, sql_array_t *tables, sql_join_assist_t *join_assist,
                                       sql_table_t *query_table, word_t *word)
{
    if (IS_VARIANT(word)) {
        return sql_create_normal_query_table(stmt, word, query_table);
    } else {
        GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "table name or subselect expected but %s found.",
                              W2S(word));
        return GS_ERROR;
    }
}

static status_t sql_verify_table_version(sql_stmt_t *stmt, sql_table_snapshot_t *version, word_t *word)
{
    sql_verifier_t verf = { 0 };
    gs_type_t expr_type;
    expr_node_type_t node_type;

    verf.context = stmt->context;
    verf.stmt = stmt;
    verf.excl_flags = SQL_EXCL_AGGR | SQL_EXCL_COLUMN | SQL_EXCL_STAR | SQL_EXCL_SEQUENCE | SQL_EXCL_SUBSELECT |
                      SQL_EXCL_JOIN | SQL_EXCL_ROWNUM | SQL_EXCL_ROWID | SQL_EXCL_DEFAULT | SQL_EXCL_ROWSCN |
                      SQL_EXCL_WIN_SORT | SQL_EXCL_GROUPING | SQL_EXCL_ROWNODEID;

    if (sql_verify_expr(&verf, (expr_tree_t *)version->expr) != GS_SUCCESS) {
        return GS_ERROR;
    }

    expr_type = TREE_DATATYPE((expr_tree_t *)version->expr);
    node_type = TREE_EXPR_TYPE((expr_tree_t *)version->expr);
    if (version->type == SCN_VERSION) {
        if (!GS_IS_WEAK_NUMERIC_TYPE(expr_type) && node_type != EXPR_NODE_PARAM) {
            cm_try_set_error_loc(word->text.loc);
            GS_SET_ERROR_MISMATCH(GS_TYPE_BIGINT, expr_type);
            return GS_ERROR;
        }
    } else {
        if (!GS_IS_DATETIME_TYPE(expr_type)) {
            cm_try_set_error_loc(word->text.loc);
            GS_SET_ERROR_MISMATCH(GS_TYPE_TIMESTAMP, expr_type);
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t sql_try_parse_table_version(sql_stmt_t *stmt, sql_table_snapshot_t *version, word_t *word)
{
    bool32 result = GS_FALSE;
    lex_t *lex = stmt->session->lex;
    uint32 matched_id;
    uint32 flags = lex->flags;

    if (lex_fetch(lex, word) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (word->id != KEY_WORD_AS) {
        version->type = CURR_VERSION;
        return GS_SUCCESS;
    }

    if (lex_try_fetch(lex, "OF", &result) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (!result) {
        version->type = CURR_VERSION;
        return GS_SUCCESS;
    }

    if (lex_expected_fetch_1of2(lex, "SCN", "TIMESTAMP", &matched_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    version->type = (matched_id == 0) ? SCN_VERSION : TIMESTAMP_VERSION;

    lex->flags = LEX_WITH_ARG;
    if (sql_create_expr_until(stmt, (expr_tree_t **)&version->expr, word) != GS_SUCCESS) {
        return GS_ERROR;
    }

    GS_RETURN_IFERR(sql_verify_table_version(stmt, version, word));

    lex->flags = flags;
    return GS_SUCCESS;
}

static status_t sql_parse_join(sql_stmt_t *stmt, sql_array_t *tables, sql_join_assist_t *join_assist, word_t *word)
{
    sql_table_t *table = NULL;
    join_assist->join_node = NULL;

    GS_RETURN_IFERR(sql_stack_safe(stmt));

    GS_RETURN_IFERR(sql_parse_query_table(stmt, tables, join_assist, &table, word));

    if (word->id == KEY_WORD_JOIN || word->id == KEY_WORD_INNER || word->id == KEY_WORD_LEFT ||
        word->id == KEY_WORD_RIGHT || word->id == KEY_WORD_FULL || IS_SPEC_CHAR(word, ',')) {
        GS_SRC_THROW_ERROR(word->loc, ERR_CAPABILITY_NOT_SUPPORT, "only simple select supported.");
        return GS_ERROR;
    }

    join_assist->join_node = table->join_node;

    return GS_SUCCESS;
}

static status_t sql_remove_join_table(sql_stmt_t *stmt, sql_query_t *query)
{
    sql_array_t new_tables;

    GS_RETURN_IFERR(sql_create_array(stmt->context, &new_tables, "QUERY TABLES", GS_MAX_JOIN_TABLES));

    for (uint32 i = 0; i < query->tables.count; ++i) {
        sql_table_t *table = (sql_table_t *)sql_array_get(&query->tables, i);
        if (table->type == JOIN_AS_TABLE) {
            continue;
        }
        table->id = new_tables.count;
        GS_RETURN_IFERR(sql_array_put(&new_tables, table));
    }

    query->tables = new_tables;

    return GS_SUCCESS;
}

status_t sql_parse_join_entry(sql_stmt_t *stmt, sql_query_t *query, word_t *word)
{
    GS_RETURN_IFERR(sql_parse_join(stmt, &query->tables, &query->join_assist, word));
    if (query->join_assist.outer_node_count > 0) {
        return GS_ERROR;
    }
    return sql_remove_join_table(stmt, query);
}

status_t sql_parse_query_tables(sql_stmt_t *stmt, sql_query_t *query, word_t *word)
{
    sql_table_t *table = NULL;
    lex_t *lex = NULL;

    CM_POINTER3(stmt, query, word);
    lex = stmt->session->lex;

    if (word->type == WORD_TYPE_EOF) {
        word->ex_count = 0;
        word->type = WORD_TYPE_VARIANT;
        word->text.str = "SYS_DUMMY";
        word->text.len = (uint32)strlen(word->text.str);
        word->text.loc = LEX_LOC;

        GS_RETURN_IFERR(sql_array_new(&query->tables, sizeof(sql_table_t), (void **)&table));
        table->id = query->tables.count - 1;
        table->rs_nullable = GS_FALSE;
        table->ineliminable = GS_FALSE;

        GS_RETURN_IFERR(sql_create_query_table(stmt, &query->tables, &query->join_assist, table, word));
        word->type = WORD_TYPE_EOF;

        return GS_SUCCESS;
    }

    if (word->id != KEY_WORD_FROM) {
        GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "FROM expected but %s found", W2S(word));
        return GS_ERROR;
    }

    return sql_parse_join_entry(stmt, query, word);
}

status_t sql_set_table_qb_name(sql_stmt_t *stmt, sql_query_t *query)
{
    sql_table_t *table = NULL;
    for (uint32 i = 0; i < query->tables.count; i++) {
        table = (sql_table_t *)sql_array_get(&query->tables, i);
        GS_RETURN_IFERR(sql_copy_text(stmt->context, &query->block_info->origin_name, &table->qb_name));
    }
    return GS_SUCCESS;
}
status_t sql_try_parse_alias(sql_stmt_t *stmt, text_t *alias, word_t *word)
{
    if (word->id == KEY_WORD_FROM || IS_SPEC_CHAR(word, ',')) {
        return GS_SUCCESS;
    }

    GS_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR, "invalid column alias");
    return GS_ERROR;
}

status_t sql_parse_column(sql_stmt_t *stmt, galist_t *columns, word_t *word)
{
    text_t alias;
    query_column_t *column = NULL;
    lex_t *lex = stmt->session->lex;

    GS_RETURN_IFERR(cm_galist_new(columns, sizeof(query_column_t), (void **)&column));
    column->exist_alias = GS_FALSE;

    alias.str = lex->curr_text->str;

    GS_RETURN_IFERR(sql_create_expr_until(stmt, &column->expr, word));

    if (column->expr->root->type == EXPR_NODE_STAR) {
        alias.len = (uint32)(word->text.str - alias.str);
        // modified since the right side has an space
        cm_trim_text(&alias);
        column->expr->star_loc.end = column->expr->star_loc.begin + alias.len;
        return GS_SUCCESS;
    }

    if (word->id == KEY_WORD_AS) {
        GS_SRC_THROW_ERROR(lex->loc, ERR_CAPABILITY_NOT_SUPPORT, "AS");
        return GS_ERROR;
    } else if (sql_try_parse_alias(stmt, &column->alias, word) != GS_SUCCESS) {
        return GS_ERROR;
    }

    column->exist_alias = GS_TRUE;
    if (column->alias.len == 0) {
        column->exist_alias = GS_FALSE;
        if (column->expr->root->type == EXPR_NODE_COLUMN) {
            alias = column->expr->root->word.column.name.value;
            return sql_copy_text(stmt->context, &alias, &column->alias);
        }
        /* if ommit alias ,then alias is whole expr string */
        alias.len = (uint32)(word->text.str - alias.str);

        // modified since the right side has an space
        cm_trim_text(&alias);

        if (alias.len > GS_MAX_NAME_LEN) {
            alias.len = GS_MAX_NAME_LEN;
        }
        return sql_copy_name(stmt->context, &alias, &column->alias);
    }
    return GS_SUCCESS;
}

static status_t sql_parse_query_columns(sql_stmt_t *stmt, sql_query_t *query, word_t *word)
{
    lex_t *lex = NULL;
    bool32 has_distinct = GS_FALSE;

    CM_POINTER3(stmt, query, word);

    lex = stmt->session->lex;

    if (lex_try_fetch(lex, "DISTINCT", &has_distinct) != GS_SUCCESS) {
        return GS_ERROR;
    }
    if (has_distinct) {
        GS_SRC_THROW_ERROR(lex->loc, ERR_CAPABILITY_NOT_SUPPORT, "disinct");
        return GS_ERROR;
    }
    query->has_distinct = GS_FALSE;

    for (;;) {
        if (sql_parse_column(stmt, query->columns, word) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (IS_SPEC_CHAR(word, ',')) {
            continue;
        }
        break;
    }

    return GS_SUCCESS;
}

status_t sql_init_join_assist(sql_stmt_t *stmt, sql_join_assist_t *join_assist)
{
    join_assist->join_node = NULL;
    join_assist->outer_plan_count = 0;
    join_assist->outer_node_count = 0;
    join_assist->inner_plan_count = 0;
    join_assist->mj_plan_count = 0;
    join_assist->has_hash_oper = GS_FALSE;
    return GS_SUCCESS;
}

status_t sql_init_query(sql_stmt_t *stmt, sql_select_t *select_ctx, source_location_t loc, sql_query_t *query)
{
    GS_RETURN_IFERR(sql_create_list(stmt, &query->aggrs));

    GS_RETURN_IFERR(sql_create_list(stmt, &query->cntdis_columns));

    GS_RETURN_IFERR(sql_create_array(stmt->context, &query->tables, "QUERY TABLES", GS_MAX_JOIN_TABLES));

    GS_RETURN_IFERR(sql_create_array(stmt->context, &query->ssa, "SUB-SELECT", GS_MAX_SUBSELECT_EXPRS));

    GS_RETURN_IFERR(sql_create_list(stmt, &query->columns));

    GS_RETURN_IFERR(sql_create_list(stmt, &query->rs_columns));

    GS_RETURN_IFERR(sql_create_list(stmt, &query->winsort_rs_columns));

    GS_RETURN_IFERR(sql_create_list(stmt, &query->sort_items));

    GS_RETURN_IFERR(sql_create_list(stmt, &query->group_sets));

    GS_RETURN_IFERR(sql_create_list(stmt, &query->distinct_columns));

    GS_RETURN_IFERR(sql_create_list(stmt, &query->winsort_list));

    GS_RETURN_IFERR(sql_create_list(stmt, &query->join_symbol_cmps));

    GS_RETURN_IFERR(sql_create_list(stmt, &query->path_func_nodes));

    GS_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(query_block_info_t), (void **)&query->block_info));

    query->owner = select_ctx;
    query->loc = loc;
    query->has_distinct = GS_FALSE;
    query->for_update = GS_FALSE;
    query->cond = NULL;
    query->having_cond = NULL;
    query->filter_cond = NULL;
    query->start_with_cond = NULL;
    query->connect_by_cond = NULL;
    query->connect_by_nocycle = GS_FALSE;
    query->connect_by_iscycle = GS_FALSE;
    query->exists_covar = GS_FALSE;
    query->is_s_query = GS_FALSE;
    query->hint_info = NULL;

    GS_RETURN_IFERR(sql_init_join_assist(stmt, &query->join_assist));
    query->aggr_dis_count = 0;
    query->remote_keys = NULL;
    query->incl_flags = 0;
    query->order_siblings = GS_FALSE;
    query->group_cubes = NULL;
    query->vpeek_assist = NULL;
    query->cb_mtrl_info = NULL;
    query->join_card = GS_INVALID_INT64;

    GS_RETURN_IFERR(vmc_alloc_mem(&stmt->vmc, sizeof(vmc_t), (void **)&query->vmc));
    vmc_init(&stmt->session->vmp, query->vmc);
    query->filter_infos = NULL;
    return cm_galist_insert(&stmt->vmc_list, query->vmc);
}

static inline status_t sql_calc_found_rows_needed(sql_stmt_t *stmt, sql_select_t *select_ctx, select_type_t type,
                                                  bool32 *found_rows_needed)
{
    *found_rows_needed = GS_FALSE;

    /* check if there is "SQL_CALC_FOUND_ROWS" following "SELECT" */
    if ((type == SELECT_AS_RESULT) ||                            /* simple select statement */
        (type == SELECT_AS_VALUES) || (type == SELECT_AS_SET)) { /* subset select statement in union */
        GS_RETURN_IFERR(lex_try_fetch(stmt->session->lex, "sql_calc_found_rows", found_rows_needed));

        if (*found_rows_needed) {
            if (select_ctx->first_query == NULL) {
                /*
                 * we cannot here identify whether the current sql_select_t is a subset sql_selet_t in union,
                 * or a main sql_selet_t for simple query. so set the calc_found_rows of sql_selet_t into true
                 * and pass it to the main sql_selet_t if it is the first subset select in union
                 *
                 * for the value pass of calc_found_rows, please refer to sql_parse_select_wrapped()
                 */
                select_ctx->calc_found_rows = GS_TRUE;
            } else {
                /* "SQL_CALC_FOUND_ROWS" cannot show up in the non-first query of UNION statement */
                GS_SRC_THROW_ERROR(stmt->session->lex->loc, ERR_SQL_SYNTAX_ERROR,
                                   "Incorrect usage/placement of \"SQL_CALC_FOUND_ROWS\"");
                return GS_ERROR;
            }
        }
    }

    return GS_SUCCESS;
}

static status_t sql_parse_query_clauses(sql_stmt_t *stmt, sql_query_t *query, word_t *word)
{
    GS_RETURN_IFERR(sql_parse_query_columns(stmt, query, word));

    GS_RETURN_IFERR(sql_parse_query_tables(stmt, query, word));

    if (word->id == KEY_WORD_WHERE) {
        GS_RETURN_IFERR(sql_create_cond_until(stmt, &query->cond, word));
    }

    if ((word->id == KEY_WORD_PIVOT) || (word->id == KEY_WORD_UNPIVOT) || (word->id == KEY_WORD_START) ||
        (word->id == KEY_WORD_CONNECT) || (word->id == KEY_WORD_GROUP) || (word->id == KEY_WORD_HAVING) ||
        (word->id == KEY_WORD_LIMIT) || (word->id == KEY_WORD_OFFSET) || word->id == KEY_WORD_ORDER) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "single select only.");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t sql_form_select_with_oper(sql_select_t *select_ctx, select_node_type_t type)
{
    select_node_t *node = NULL;

    /* get next node ,merge node is needed at least two node */
    node = select_ctx->chain.first->next;

    if (node != NULL) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "only single table supported.");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t sql_generate_select(sql_select_t *select_ctx)
{
    if (select_ctx->chain.count == 0) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "missing SELECT keyword");
        return GS_ERROR;
    }

    if (sql_form_select_with_oper(select_ctx, SELECT_NODE_UNION_ALL | SELECT_NODE_UNION | SELECT_NODE_INTERSECT |
                                                  SELECT_NODE_MINUS | SELECT_NODE_INTERSECT_ALL |
                                                  SELECT_NODE_EXCEPT_ALL | SELECT_NODE_EXCEPT) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (select_ctx->chain.count != 1) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "missing SELECT keyword");
        return GS_ERROR;
    }

    select_ctx->root = select_ctx->chain.first;
    return GS_SUCCESS;
}

status_t sql_alloc_select_context(sql_stmt_t *stmt, select_type_t type, sql_select_t **select_ctx)
{
    if (sql_alloc_mem(stmt->context, sizeof(sql_select_t), (void **)select_ctx) != GS_SUCCESS) {
        return GS_ERROR;
    }

    (*select_ctx)->type = type;
    (*select_ctx)->for_update = GS_FALSE;
    (*select_ctx)->pending_col_count = 0;

    GS_RETURN_IFERR(sql_create_list(stmt, &(*select_ctx)->sort_items));
    GS_RETURN_IFERR(sql_create_list(stmt, &(*select_ctx)->parent_refs));
    GS_RETURN_IFERR(sql_create_list(stmt, &(*select_ctx)->pl_dc_lst));
    (*select_ctx)->plan = NULL;
    (*select_ctx)->for_update_cols = NULL;
    (*select_ctx)->withass = NULL;
    (*select_ctx)->is_withas = GS_FALSE;
    (*select_ctx)->can_sub_opt = GS_TRUE;
    return GS_SUCCESS;
}

static status_t sql_create_select_node(sql_stmt_t *stmt, sql_select_t *select_ctx, uint32 wid)
{
    bool32 result = GS_FALSE;
    select_node_t *node = NULL;

    if (sql_alloc_mem(stmt->context, sizeof(select_node_t), (void **)&node) != GS_SUCCESS) {
        return GS_ERROR;
    }

    APPEND_CHAIN(&select_ctx->chain, node);

    if (wid == KEY_WORD_SELECT) {
        node->type = SELECT_NODE_QUERY;
    } else if (wid == KEY_WORD_UNION) {
        if (lex_try_fetch(stmt->session->lex, "ALL", &result) != GS_SUCCESS) {
            return GS_ERROR;
        }

        node->type = result ? SELECT_NODE_UNION_ALL : SELECT_NODE_UNION;
    } else if (wid == KEY_WORD_MINUS) {
        node->type = SELECT_NODE_MINUS;
    } else if (wid == KEY_WORD_EXCEPT) {
        if (lex_try_fetch(stmt->session->lex, "ALL", &result) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (!result) {
            bool32 hasDistinct = GS_FALSE;
            if (lex_try_fetch(stmt->session->lex, "DISTINCT", &hasDistinct) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
        node->type = result ? SELECT_NODE_EXCEPT_ALL : SELECT_NODE_EXCEPT;
    } else if (wid == KEY_WORD_INTERSECT) {
        if (lex_try_fetch(stmt->session->lex, "ALL", &result) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (!result) {
            bool32 hasDistinct = GS_FALSE;
            if (lex_try_fetch(stmt->session->lex, "DISTINCT", &hasDistinct) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
        node->type = result ? SELECT_NODE_INTERSECT_ALL : SELECT_NODE_INTERSECT;
    } else {
        node->type = SELECT_NODE_INTERSECT;
    }

    return GS_SUCCESS;
}

status_t sql_set_origin_query_block_name(sql_stmt_t *stmt, sql_query_t *query)
{
    text_t id_text = { 0 };
    SQL_SAVE_STACK(stmt);
    GS_RETURN_IFERR(sql_push(stmt, GS_MAX_UINT32_STRLEN + 1, (void **)&id_text.str));
    cm_uint32_to_text(query->block_info->origin_id, &id_text);
    uint32 qb_name_len = id_text.len + SEL_QUERY_BLOCK_PREFIX_LEN;
    GS_RETURN_IFERR(sql_alloc_mem(stmt->context, qb_name_len, (void **)&query->block_info->origin_name.str));
    GS_RETURN_IFERR(cm_concat_string(&query->block_info->origin_name, qb_name_len, SEL_QUERY_BLOCK_PREFIX));
    cm_concat_text(&query->block_info->origin_name, qb_name_len, &id_text);

    SQL_RESTORE_STACK(stmt);
    return GS_SUCCESS;
}

static status_t sql_parse_query(sql_stmt_t *stmt, sql_select_t *select_ctx, select_type_t type, word_t *word,
                                sql_query_t **query_res, bool32 *found_rows_needed)
{
    status_t status;
    sql_query_t *query = NULL;

    GS_RETURN_IFERR(sql_stack_safe(stmt));

    GS_RETURN_IFERR(sql_create_select_node(stmt, select_ctx, KEY_WORD_SELECT));

    GS_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(sql_query_t), (void **)&query));

    GS_RETURN_IFERR(sql_init_query(stmt, select_ctx, stmt->session->lex->loc, query));
    query->block_info->origin_id = ++stmt->context->query_count;
    GS_RETURN_IFERR(sql_set_origin_query_block_name(stmt, query));

    GS_RETURN_IFERR(sql_calc_found_rows_needed(stmt, select_ctx, type, found_rows_needed));

    *query_res = query;
    if (select_ctx->first_query == NULL) {
        select_ctx->first_query = query;
    }

    select_ctx->chain.last->query = query;

    GS_RETURN_IFERR(SQL_NODE_PUSH(stmt, query));
    GS_RETURN_IFERR(SQL_SSA_PUSH(stmt, &query->ssa));
    status = sql_parse_query_clauses(stmt, query, word);
    SQL_SSA_POP(stmt);
    SQL_NODE_POP(stmt);
    if (status == GS_ERROR) {
        return GS_ERROR;
    }
    return sql_set_table_qb_name(stmt, query);
}

static status_t sql_parse_single_select_context(sql_stmt_t *stmt, select_type_t type, word_t *word,
                                                sql_select_t **select_ctx, sql_query_t **query)
{
    lex_t *lex = stmt->session->lex;
    bool32 result = GS_FALSE;

    GS_RETURN_IFERR(lex_try_fetch(lex, "select", &result));
    if (result) {
        bool32 found_rows_needed = GS_FALSE;

        stmt->in_parse_query = GS_TRUE;
        GS_RETURN_IFERR(sql_parse_query(stmt, *select_ctx, type, word, query, &found_rows_needed));
        stmt->in_parse_query = GS_FALSE;

        if (found_rows_needed && type == SELECT_AS_RESULT) {
            (*query)->calc_found_rows = found_rows_needed;
        }
    } else {
        GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "SELECT expected but %s found", W2S(word));
        return GS_ERROR;
    }

    if (word->id == KEY_WORD_FOR) {
        GS_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "expected end but %s found", W2S(word));
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t sql_parse_select_context(sql_stmt_t *stmt, select_type_t type, word_t *word, sql_select_t **select_ctx)
{
    lex_t *lex = stmt->session->lex;
    sql_query_t *query = NULL;
    bool32 has_set = GS_FALSE;
    bool32 result = GS_FALSE;

    GS_RETURN_IFERR(sql_alloc_select_context(stmt, type, select_ctx));

    lex->flags = LEX_WITH_OWNER | LEX_WITH_ARG;

    // try parse with as select clause
    GS_RETURN_IFERR(lex_try_fetch(lex, "WITH", &result));
    if (result) {
        knl_panic(0);
    }

    while (1) {
        GS_RETURN_IFERR(sql_parse_single_select_context(stmt, type, word, select_ctx, &query));
        GS_BREAK_IF_TRUE(word->type == WORD_TYPE_EOF);

        if (word->id == KEY_WORD_UNION || word->id == KEY_WORD_MINUS || word->id == KEY_WORD_EXCEPT ||
            word->id == KEY_WORD_INTERSECT) {
            knl_panic(0);
            // for insert xxx select xxx on duplicate key update xxx clause
        } else if (word->id == KEY_WORD_ON) {
            knl_panic(0);
            GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "invalid word '%s' found", W2S(word));
            return GS_ERROR;
        } else {
            GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "invalid word '%s' found", W2S(word));
            return GS_ERROR;
        }

        /*
         * prevent the ambiguous limit/order by clause in the subset query which has no parentheses.
         *
         * the prevention relied on the following conditions.
         * has_set == GS_TRUE:  the entire SELECT statement encountered a set-operator(UNION/UNION ALL/MINUS)
         * if no set-operator encountered, simple SELECT does not need the check
         * query != NULL:  the query was not parsed by sql_parse_select_wrapped() which means no parenthes enclosed
         * type != SELECT_AS_SET: if SELECT_AS_SET, it means this check is being executed by
         * sql_parse_select_wrapped() which does not need this check
         */
        if (has_set == GS_TRUE && query != NULL &&
            (LIMIT_CLAUSE_OCCUR(&query->limit) || query->sort_items->count > 0)) {
            GS_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR,
                               "\"LIMIT\" clause or \"ORDER BY\" clause of "
                               "the subset should be placed inside the parentheses that enclose the SELECT");
            return GS_ERROR;
        }
    }

    if (sql_generate_select(*select_ctx) != GS_SUCCESS) {
        cm_try_set_error_loc(word->text.loc);
        return GS_ERROR;
    }
    return cm_galist_insert(stmt->context->selects, *select_ctx);
}

status_t sql_create_select_context(sql_stmt_t *stmt, sql_text_t *sql, select_type_t type, sql_select_t **select_ctx)
{
    word_t word;
    lex_t *lex = stmt->session->lex;
    uint32 save_flags = lex->flags;

    GS_RETURN_IFERR(sql_stack_safe(stmt));

    if (lex_push(lex, sql) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (sql_parse_select_context(stmt, type, &word, select_ctx) != GS_SUCCESS) {
        lex_pop(lex);
        return GS_ERROR;
    }

    lex->flags = save_flags;
    GS_RETURN_IFERR(lex_expected_end(lex));
    lex_pop(lex);
    return GS_SUCCESS;
}

static status_t dtc_parse_undo_space(sql_stmt_t *stmt, dtc_node_def_t *node, word_t *word)
{
    lex_t *lex = stmt->session->lex;
    char *name;
    errno_t code;

    if (lex_expected_fetch_word(lex, "tablespace") != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (sql_alloc_mem(stmt->context, GS_NAME_BUFFER_SIZE, (void **)&name) != GS_SUCCESS) {
        return GS_ERROR;
    }

    code = snprintf_s(name, GS_NAME_BUFFER_SIZE, GS_NAME_BUFFER_SIZE - 1, "UNDO_%02u", node->id);
    PRTS_RETURN_IFERR(code);

    node->undo_space.name.str = name;
    node->undo_space.name.len = (uint32)strlen(name);
    node->undo_space.type = SPACE_TYPE_UNDO | SPACE_TYPE_DEFAULT;

    if (lex_expected_fetch_word(lex, "datafile") != GS_SUCCESS) {
        return GS_ERROR;
    }

    return sql_parse_dbca_datafile_spec(stmt, lex, word, &node->undo_space);
}

static status_t dtc_parse_temp_undo_space(sql_stmt_t *stmt, dtc_node_def_t *node, word_t *word)
{
    lex_t *lex = stmt->session->lex;
    char *name;
    errno_t code;

    if (lex_expected_fetch_word(lex, "undo") != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (lex_expected_fetch_word(lex, "tablespace") != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (sql_alloc_mem(stmt->context, GS_NAME_BUFFER_SIZE, (void **)&name) != GS_SUCCESS) {
        return GS_ERROR;
    }

    code = snprintf_s(name, GS_NAME_BUFFER_SIZE, GS_NAME_BUFFER_SIZE - 1, "TEMP_UNDO_%u1", node->id);
    PRTS_RETURN_IFERR(code);

    node->temp_undo_space.name.str = name;
    node->temp_undo_space.name.len = (uint32)strlen(name);
    node->temp_undo_space.type = SPACE_TYPE_UNDO | SPACE_TYPE_DEFAULT | SPACE_TYPE_TEMP;

    if (lex_expected_fetch_word(lex, "TEMPFILE") != GS_SUCCESS) {
        return GS_ERROR;
    }

    return sql_parse_dbca_datafile_spec(stmt, lex, word, &node->temp_undo_space);
}

static status_t dtc_parse_swap_space(sql_stmt_t *stmt, dtc_node_def_t *node, word_t *word)
{
    lex_t *lex = stmt->session->lex;
    char *name;
    errno_t code;

    if (lex_expected_fetch_word(lex, "tablespace") != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (sql_alloc_mem(stmt->context, GS_NAME_BUFFER_SIZE, (void **)&name) != GS_SUCCESS) {
        return GS_ERROR;
    }

    code = snprintf_s(name, GS_NAME_BUFFER_SIZE, GS_NAME_BUFFER_SIZE - 1, "SWAP_%02u", node->id);
    PRTS_RETURN_IFERR(code);

    node->swap_space.name.str = name;
    node->swap_space.name.len = (uint32)strlen(name);
    node->swap_space.type = SPACE_TYPE_TEMP | SPACE_TYPE_SWAP | SPACE_TYPE_DEFAULT;

    if (lex_expected_fetch_word(lex, "TEMPFILE") != GS_SUCCESS) {
        return GS_ERROR;
    }

    return sql_parse_dbca_datafile_spec(stmt, lex, word, &node->swap_space);
}

static status_t dtc_parse_node_def(sql_stmt_t *stmt, knl_database_def_t *def, word_t *word)
{
    dtc_node_def_t *node;
    lex_t *lex = stmt->session->lex;

    if (cm_galist_new(&def->nodes, sizeof(dtc_node_def_t), (pointer_t *)&node) != GS_SUCCESS) {
        return GS_ERROR;
    }

    node->id = def->nodes.count - 1;
    cm_galist_init(&node->logfiles, stmt->context, sql_alloc_mem);
    cm_galist_init(&node->undo_space.datafiles, stmt->context, sql_alloc_mem);
    cm_galist_init(&node->swap_space.datafiles, stmt->context, sql_alloc_mem);
    cm_galist_init(&node->temp_undo_space.datafiles, stmt->context, sql_alloc_mem);

    if (lex_expected_fetch(lex, word) != GS_SUCCESS) {
        return GS_ERROR;
    }

    for (;;) {
        switch (word->id) {
            case KEY_WORD_UNDO:
                if (dtc_parse_undo_space(stmt, node, word) != GS_SUCCESS) {
                    return GS_ERROR;
                }
                break;

            case KEY_WORD_LOGFILE:
                if (sql_parse_dbca_logfiles(stmt, &node->logfiles, word) != GS_SUCCESS) {
                    return GS_ERROR;
                }
                break;

            case KEY_WORD_TEMPORARY:
                if (dtc_parse_swap_space(stmt, node, word) != GS_SUCCESS) {
                    return GS_ERROR;
                }
                break;
            case KEY_WORD_NO_LOGGING:
                if (dtc_parse_temp_undo_space(stmt, node, word) != GS_SUCCESS) {
                    return GS_ERROR;
                }
                break;
            default:
                return GS_SUCCESS;
        }
    }

    return GS_SUCCESS;
}

static status_t dtc_parse_nodes(sql_stmt_t *stmt, knl_database_def_t *def, word_t *word)
{
    uint32 node_id, id;
    lex_t *lex = stmt->session->lex;

    if (lex_expected_fetch_word(lex, "node")) {
        return GS_ERROR;
    }

    node_id = 0;

    for (;;) {
        if (lex_expected_fetch_uint32(lex, &id) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (id != node_id) {
            GS_SRC_THROW_ERROR_EX(lex->loc, ERR_INVALID_DATABASE_DEF, "instance number error, '%u' expected", node_id);
            return GS_ERROR;
        }

        if (dtc_parse_node_def(stmt, def, word) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (word->id != KEY_WORD_NODE) {
            break;
        }

        node_id++;
    }

    return GS_SUCCESS;
}

status_t dtc_parse_instance(sql_stmt_t *stmt, knl_database_def_t *def, word_t *word)
{
    lex_t *lex = stmt->session->lex;

    if (def->nodes.count > 0) {
        GS_SRC_THROW_ERROR(lex->loc, ERR_SQL_SYNTAX_ERROR, "INSTANCE is already defined");
        return GS_ERROR;
    }

    return dtc_parse_nodes(stmt, def, word);
}

status_t dtc_parse_maxinstance(sql_stmt_t *stmt, knl_database_def_t *def, word_t *word)
{
    lex_t *lex = stmt->session->lex;

    return lex_expected_fetch_uint32(lex, &def->max_instance);
}

static status_t dtc_verify_node(sql_stmt_t *stmt, knl_database_def_t *def, uint32 id)
{
    dtc_node_def_t *node;
    node = (dtc_node_def_t *)cm_galist_get(&def->nodes, id);
    if (node->undo_space.name.len == 0 || node->undo_space.datafiles.count == 0) {
        GS_THROW_ERROR(ERR_INVALID_DATABASE_DEF, "UNDO tablespace of instances %d is not specific", id + 1);
        return GS_ERROR;
    }

    if (node->swap_space.name.len == 0 || node->swap_space.datafiles.count == 0) {
        GS_THROW_ERROR(ERR_INVALID_DATABASE_DEF, "no device specified for swap tablespace");
        return GS_ERROR;
    }

    if (node->temp_undo_space.name.len == 0 || node->temp_undo_space.datafiles.count == 0) {
        GS_THROW_ERROR(ERR_INVALID_DATABASE_DEF, "TEMP_UNDO tablespace of instances %d is not specific", id + 1);
        return GS_ERROR;
    }

    if (cm_dbs_is_enable_dbs() == GS_TRUE) {
        if (node->logfiles.count == 1) {
            return GS_SUCCESS;
        }
        GS_THROW_ERROR(ERR_INVALID_DATABASE_DEF, "the number of redo log files is invalid, should be 1 for DBstor.");
        return GS_ERROR;
    }

    if (node->logfiles.count < GS_MIN_LOG_FILES || node->logfiles.count > GS_MAX_LOG_FILES) {
        GS_THROW_ERROR(ERR_INVALID_DATABASE_DEF, "the number of redo log files is invalid, should be in [3, 256]");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t dtc_verify_instances(sql_stmt_t *stmt, knl_database_def_t *def)
{
    uint32 i;

    if (def->nodes.count < 1 || def->nodes.count > GS_MAX_INSTANCES) {
        GS_THROW_ERROR(ERR_INVALID_DATABASE_DEF, "the number of instances is invalid");
        return GS_ERROR;
    }

    for (i = 0; i < def->nodes.count; i++) {
        if (dtc_verify_node(stmt, def, i) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

status_t dtc_verify_database_def(sql_stmt_t *stmt, knl_database_def_t *def)
{
    galist_t *list = NULL;
    knl_device_def_t *dev = NULL;

    list = &def->ctrlfiles;
    if (list->count < 2 || list->count > GS_MAX_CTRL_FILES) {
        GS_THROW_ERROR(ERR_INVALID_DATABASE_DEF, "the number of control files is invalid");
        return GS_ERROR;
    }

    if (dtc_verify_instances(stmt, def) != GS_SUCCESS) {
        return GS_ERROR;
    }

    list = &def->system_space.datafiles;
    if (list->count == 0) {
        GS_THROW_ERROR(ERR_INVALID_DATABASE_DEF, "no device specified for system tablespace");
        return GS_ERROR;
    }

    dev = cm_galist_get(list, 0);
    if (dev->size < SYSTEM_FILE_MIN_SIZE) {
        GS_THROW_ERROR(ERR_INVALID_DATABASE_DEF, "first system file size less than %d(MB)",
                       SYSTEM_FILE_MIN_SIZE / SIZE_M(1));
        return GS_ERROR;
    }

    list = &def->temp_space.datafiles;
    if (list->count == 0) {
        GS_THROW_ERROR(ERR_INVALID_DATABASE_DEF, "no device specified for temporary tablespace");
        return GS_ERROR;
    }

    list = &def->temp_undo_space.datafiles;
    if (list->count == 0) {
        GS_THROW_ERROR(ERR_INVALID_DATABASE_DEF, "no device specified for temporary undo tablespace");
        return GS_ERROR;
    }

    if (strlen(def->sys_password) != 0 && cm_compare_str_ins(def->sys_password, SYS_USER_NAME) != 0) {
        GS_RETURN_IFERR(cm_verify_password_str(SYS_USER_NAME, def->sys_password, GS_PASSWD_MIN_LEN));
    }

    if (g_instance->kernel.db.status != DB_STATUS_NOMOUNT) {
        GS_THROW_ERROR(ERR_DATABASE_ALREADY_MOUNT, "database already mounted");
        return GS_ERROR;
    }

    list = &def->sysaux_space.datafiles;
    if (list->count != 1) {
        GS_THROW_ERROR(ERR_INVALID_DATABASE_DEF, "sysaux must have only one datafile");
        return GS_ERROR;
    }
    dev = cm_galist_get(list, 0);
    uint32 min_size = GS_MIN_SYSAUX_DATAFILE_SIZE +
                      (def->nodes.count - 1) * DOUBLE_WRITE_PAGES * SIZE_K(8); /* default page size is SIZE_K(8) */
    if (dev->size < min_size) {
        GS_THROW_ERROR_EX(ERR_INVALID_DATABASE_DEF, "first datafile size less than %d(MB), node count(%d)",
                          min_size / SIZE_M(1), def->nodes.count);
        return GS_ERROR;
    }

    if (def->max_instance > GS_MAX_INSTANCES) {
        GS_THROW_ERROR(ERR_INVALID_DATABASE_DEF, "MAXINSTANCES larger than 64");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t sql_try_fetch_func_arg(sql_stmt_t *stmt, text_t *arg_name)
{
    char curr, next;
    word_t word;
    lex_t *lex = stmt->session->lex;
    bool32 result = GS_FALSE;

    LEX_SAVE(lex);

    if (lex_try_fetch_variant(lex, &word, &result) != GS_SUCCESS) {
        LEX_RESTORE(lex);
        return GS_ERROR;
    }

    if (!result) {
        LEX_RESTORE(lex);
        return GS_SUCCESS;
    }

    lex_trim(lex->curr_text);
    lex->loc = lex->curr_text->loc;
    lex->begin_addr = lex->curr_text->str;

    if (lex->curr_text->len < sizeof("=>") - 1) {
        LEX_RESTORE(lex);
        return GS_SUCCESS;
    }

    curr = CM_TEXT_BEGIN(lex->curr_text);
    next = lex_skip(lex, 1);
    (void)lex_skip(lex, 1);

    if (curr != '=' || next != '>') {
        LEX_RESTORE(lex);
        return GS_SUCCESS;
    }

    return sql_copy_object_name_ci(stmt->context, word.type, &word.text.value, arg_name);
}

static key_word_t g_pkg_key_words[] = { { (uint32)KEY_WORD_ALL, GS_TRUE, { (char *)"all", 3 } } };

/* the parse logic of the argument expression for the most generic case (syntax:  function(arg1, arg2, ...)) */
static status_t sql_build_func_args(sql_stmt_t *stmt, word_t *word, expr_node_t *func_node, sql_text_t *arg_text)
{
    lex_t *lex = stmt->session->lex;
    expr_tree_t **arg_expr = NULL;
    bool32 assign_arg = GS_FALSE;
    text_t arg_name;
    key_word_t *save_key_words = lex->key_words;
    uint32 save_key_word_count = lex->key_word_count;

    arg_expr = &func_node->argument;

    lex->key_words = g_pkg_key_words;
    lex->key_word_count = ELEMENT_COUNT(g_pkg_key_words);

    for (;;) {
        arg_name.len = 0;
        if (sql_try_fetch_func_arg(stmt, &arg_name)) {
            lex->key_words = save_key_words;
            lex->key_word_count = save_key_word_count;
            return GS_ERROR;
        }
        if (arg_name.len == 0 && assign_arg) {
            lex->key_words = save_key_words;
            lex->key_word_count = save_key_word_count;
            GS_SRC_THROW_ERROR(LEX_LOC, ERR_SQL_SYNTAX_ERROR, " '=>' expected");
            return GS_ERROR;
        }

        if (sql_create_expr_until(stmt, arg_expr, word) != GS_SUCCESS) {
            lex->key_words = save_key_words;
            lex->key_word_count = save_key_word_count;
            return GS_ERROR;
        }

        if (arg_name.len > 0) {
            assign_arg = GS_TRUE;
            (*arg_expr)->arg_name = arg_name;
        }

        GS_BREAK_IF_TRUE(word->type == WORD_TYPE_EOF);
        GS_BREAK_IF_TRUE(word->type == WORD_TYPE_OPERATOR);

        if (!IS_SPEC_CHAR(word, ',')) {
            lex->key_words = save_key_words;
            lex->key_word_count = save_key_word_count;
            GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "',' expected but %s found", W2S(word));
            return GS_ERROR;
        }

        arg_expr = &(*arg_expr)->next;
    }
    lex->key_words = save_key_words;
    lex->key_word_count = save_key_word_count;
    return GS_SUCCESS;
}

/*
 * compatible MySQL syntax substr('xxx' from xx for xx)
 * parse substr/substring args alone
 */
static status_t sql_build_func_args_substr(sql_stmt_t *stmt, word_t *word, expr_node_t *func_node, sql_text_t *arg_text)
{
    bool32 has_from = GS_FALSE;
    lex_t *lex = stmt->session->lex;
    expr_tree_t **arg_expr = &func_node->argument;

    for (;;) {
        if (sql_create_expr_until(stmt, arg_expr, word) != GS_SUCCESS) {
            lex_pop(lex);
            return GS_ERROR;
        }

        if (word->type == WORD_TYPE_EOF || word->type == WORD_TYPE_OPERATOR) {
            break;
        }
        arg_expr = &(*arg_expr)->next;

        if (word->id == KEY_WORD_FROM) {
            has_from = GS_TRUE;
            continue;
        }

        if (!has_from && !(IS_SPEC_CHAR(word, ','))) {
            GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "',' expected but %s found", W2S(word));
            return GS_ERROR;
        }

        if (has_from && word->id != KEY_WORD_FOR) {
            GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "'for' expected but %s found", W2S(word));
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}


/*
 * create a expression of a const node according to the c-style string specified.
 * the c-style string is expected to be terminated with '\0'
 */
status_t sql_create_const_string_expr(sql_stmt_t *stmt, expr_tree_t **new_expr, const char *cstring)
{
    expr_tree_t *retval = NULL;
    expr_node_t *const_node = NULL;
    char *txt_buf = NULL;
    uint32 txt_len;

    CM_POINTER3(stmt, new_expr, cstring);

    GS_RETURN_IFERR(sql_alloc_mem((void *)stmt->context, sizeof(expr_tree_t), (void **)&retval));
    GS_RETURN_IFERR(sql_alloc_mem((void *)stmt->context, sizeof(expr_node_t), (void **)&const_node));
    txt_len = (uint32)strlen(cstring);
    if (txt_len > 0) {
        GS_RETURN_IFERR(sql_alloc_mem((void *)stmt->context, (uint32)strlen(cstring), (void **)&txt_buf));
        MEMS_RETURN_IFERR(memcpy_s(txt_buf, txt_len, cstring, txt_len));
    }
    const_node->type = EXPR_NODE_CONST;
    const_node->owner = retval;
    const_node->datatype = GS_TYPE_STRING;
    const_node->value.is_null = GS_FALSE;
    const_node->value.type = GS_TYPE_STRING;
    const_node->value.v_text.len = txt_len;
    const_node->value.v_text.str = txt_buf;

    retval->owner = stmt->context;
    retval->root = const_node;
    retval->generated = GS_TRUE;
    retval->next = NULL;

    *new_expr = retval;
    return GS_SUCCESS;
}

static status_t sql_build_func_node_unconfiged(sql_stmt_t *stmt, word_t *word, expr_node_t *node, bool32 *matched)
{
    switch (word->id) {
        case KEY_WORD_CAST:
        case KEY_WORD_CONVERT:
        case KEY_WORD_IF:
        case KEY_WORD_CASE:
        case KEY_WORD_LNNVL:
            return GS_ERROR;
        default:
            break;
    }
    *matched = GS_FALSE;
    return GS_SUCCESS;
}

typedef status_t (*arg_build_func_t)(sql_stmt_t *stmt, word_t *word, expr_node_t *func_node, sql_text_t *arg_text);

typedef struct st_arg_build {
    const char *func_name;
    arg_build_func_t invoke;
} arg_build_t;

static arg_build_t g_arg_build_tab[] = {
    { "TRIM", NULL},
    { "GROUP_CONCAT", NULL},
    { "SUBSTR", sql_build_func_args_substr },
    { "SUBSTRING", sql_build_func_args_substr },
    { "EXTRACT", NULL},
    { "JSON_ARRAY", sql_build_func_args_json_array },
    { "JSON_OBJECT", sql_build_func_args_json_object },
    { "JSON_QUERY", sql_build_func_args_json_query },
    { "JSON_MERGEPATCH", sql_build_func_args_json_query },
    { "JSON_VALUE", sql_build_func_args_json_retrieve },
    { "JSON_EXISTS", sql_build_func_args_json_retrieve },
    { "JSON_SET", NULL},
    { "JSONB_QUERY", sql_build_func_args_json_query },
    { "JSONB_MERGEPATCH", sql_build_func_args_json_query },
    { "JSONB_VALUE", sql_build_func_args_json_retrieve },
    { "JSONB_EXISTS", sql_build_func_args_json_retrieve },
    { "JSONB_SET", NULL},
    { "FIRST_VALUE", NULL},
    { "LAST_VALUE", NULL},
};

static status_t sql_build_func_node_arg(sql_stmt_t *stmt, word_t *word, expr_node_t *node, sql_text_t *arg_text)
{
    lex_t *lex = stmt->session->lex;
    GS_RETURN_IFERR(lex_try_fetch(lex, "DISTINCT", &node->dis_info.need_distinct));
    if (node->dis_info.need_distinct || node->word.func.user_func_first) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "DISTINCT/udf option not allowed");
        return GS_ERROR;
    }
    
    /*
     * for more special functions, the parse logic of the argument expression
     * can be called respectively. SUCH AS TRIM expression, SUBSTRING expression, etc.
     */
    uint32 len = sizeof(g_arg_build_tab) / sizeof(arg_build_t);

    for (uint32 i = 0; i < len; i++) {
        if (cm_compare_text_str_ins(&node->word.func.name.value, g_arg_build_tab[i].func_name) == 0) {
            return g_arg_build_tab[i].invoke(stmt, word, node, arg_text);
        }
    }

    /*
     * execute the generic parse logic by default,
     * for the generic argument expression, like func(arg1, arg2, ...)
     */
    return sql_build_func_args(stmt, word, node, arg_text);
}

status_t plc_prepare_noarg_call(word_t *word)
{
    uint32 count = word->ex_count;

    if (count >= MAX_EXTRA_TEXTS) {
        GS_SRC_THROW_ERROR(word->loc, ERR_PL_SYNTAX_ERROR_FMT, "more than extra word max limit");
        return GS_ERROR;
    }
    word->ex_words[count].type = WORD_TYPE_BRACKET;
    word->ex_words[count].text.value = CM_NULL_TEXT;
    word->ex_count++;
    return GS_SUCCESS;
}

/*
 * in SQL standard, the argument expression in some function is not always like "func(arg1, arg2, ...)"
 * so it is necessary to implement some special expression rules for the special functions, such as
 * - TRIM(arg2 FROM arg1)
 * - SUBSTRING(arg1 FROM arg2 FOR arg3)
 * - etc.
 *
 * in the future, we can use a function point(status_t *fn_ptr(sql_stmt_t * stmt, word_t * word, expr_node_t * node)) to
 * handle the special argument expression respectively
 */
status_t sql_build_func_node(sql_stmt_t *stmt, word_t *word, expr_node_t *node)
{
    sql_text_t *arg_text = NULL;
    lex_t *lex = stmt->session->lex;
    status_t status;

    node->word.func.user_func_first = GS_FALSE;
    if (word->ex_count == 1) {
        {
            bool32 built = GS_TRUE;
            GS_RETURN_IFERR(sql_build_func_node_unconfiged(stmt, word, node, &built));
            GS_RETSUC_IFTRUE(built);
        }
    }

    knl_panic(stmt->pl_compiler == NULL);
    GS_RETSUC_IFTRUE(IS_UDT_EXPR(node->type));

    if (word->type != WORD_TYPE_FUNCTION && plc_prepare_noarg_call(word) != GS_SUCCESS) {
        // dedicate no_args UDF/PROC call, eg.begin f1; p1; end;
        GS_SRC_THROW_ERROR(word->loc, ERR_PLSQL_ILLEGAL_LINE_FMT, "too complex function to call");
        return GS_ERROR;
    }
    GS_RETURN_IFERR(sql_word_as_func(stmt, word, &node->word));

    if (cm_compare_text_str_ins(&word->text.value, "LISTAGG") == 0 ||
        cm_compare_text_str_ins(&word->text.value, "CUME_DIST") == 0 ||
        cm_compare_text_str_ins(&word->text.value, "DENSE_RANK") == 0 ||
        cm_compare_text_str_ins(&word->text.value, "RANK") == 0) {
        GS_SRC_THROW_ERROR(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "function not supported.");
        return GS_ERROR;
    }

    arg_text = &node->word.func.args;

    if (arg_text->len == 0) {
        return GS_SUCCESS;
    }

    GS_RETURN_IFERR(lex_push(lex, arg_text));

    status = sql_build_func_node_arg(stmt, word, node, arg_text);
    lex_pop(lex);
    return status;
}

status_t sql_build_func_over(sql_stmt_t *stmt, expr_tree_t *expr, word_t *word, expr_node_t **node)
{
    lex_t *lex = stmt->session->lex;
    word_t word_ahead;

    LEX_SAVE(lex);
    GS_RETURN_IFERR(lex_fetch(lex, &word_ahead));
    if (cm_text_str_equal_ins((text_t *)&word_ahead.text, "over") && (word_ahead.ex_count != 0)) {
        GS_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR,
                           "window specification for this function not supported.");
        return GS_ERROR;
    } else {
        LEX_RESTORE(lex);
    }

    return GS_SUCCESS;
}

status_t sql_build_cast_expr(sql_stmt_t *stmt, source_location_t loc, expr_tree_t *expr, typmode_t *type,
                             expr_tree_t **r_result)
{
    sql_text_t cast_name;
    expr_node_t *cast_node = NULL;
    expr_tree_t *arg2 = NULL;
    expr_tree_t *cast_expr = NULL;

    if (sql_create_expr(stmt, &cast_expr) != GS_SUCCESS) {
        return GS_ERROR;
    }
    cast_expr->expecting = EXPR_EXPECT_OPER;

    if (sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)&cast_node) != GS_SUCCESS) {
        return GS_ERROR;
    }

    cast_node->owner = cast_expr;
    cast_node->type = EXPR_NODE_FUNC;
    cast_node->loc = loc;
    cm_str2text(CAST_FUNCTION_NAME, &cast_name.value);
    cast_name.str = CAST_FUNCTION_NAME;
    cast_name.len = (uint32)strlen(CAST_FUNCTION_NAME);
    cast_name.loc = loc;

    cast_node->word.func.name = cast_name;
    cast_node->argument = expr;

    if (sql_create_expr(stmt, &expr->next) != GS_SUCCESS) {
        return GS_ERROR;
    }

    arg2 = expr->next;
    if (sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)&arg2->root) != GS_SUCCESS) {
        return GS_ERROR;
    }

    arg2->root->value.v_type = *type;
    arg2->root->value.type = (int16)GS_TYPE_TYPMODE;
    arg2->root->datatype = type->datatype;
    arg2->root->type = EXPR_NODE_CONST;
    arg2->root->exec_default = GS_TRUE;

    APPEND_CHAIN(&(cast_expr->chain), cast_node);

    *r_result = cast_expr;
    return sql_generate_expr(*r_result);
}

static inline void sql_var2entype(word_t *word, expr_node_type_t *type)
{
    switch (word->type) {
        case WORD_TYPE_PARAM:
            *type = EXPR_NODE_PARAM;
            break;

        case WORD_TYPE_FUNCTION:
            *type = EXPR_NODE_FUNC;
            break;

        case WORD_TYPE_VARIANT:
        case WORD_TYPE_DQ_STRING:
        case WORD_TYPE_JOIN_COL:
            *type = EXPR_NODE_COLUMN;
            break;

        case WORD_TYPE_BRACKET:
            *type = EXPR_NODE_UNKNOWN;
            break;

        case WORD_TYPE_RESERVED:
            *type = EXPR_NODE_RESERVED;
            break;

        case WORD_TYPE_KEYWORD:
        case WORD_TYPE_DATATYPE:
            if (word->id == KEY_WORD_CASE) {
                *type = EXPR_NODE_CASE;
            } else {
                *type = (word->namable) ? EXPR_NODE_COLUMN : EXPR_NODE_UNKNOWN;
            }
            break;

        case WORD_TYPE_PL_NEW_COL:
            *type = EXPR_NODE_NEW_COL;
            break;

        case WORD_TYPE_PL_OLD_COL:
            *type = EXPR_NODE_OLD_COL;
            break;

        case WORD_TYPE_PL_ATTR:
            *type = EXPR_NODE_PL_ATTR;
            break;

        case WORD_TYPE_ARRAY:
            *type = EXPR_NODE_ARRAY;
            break;

        default:
            *type = EXPR_NODE_CONST;
            break;
    }
}

static inline void sql_oper2entype(word_t *word, expr_node_type_t *type)
{
    switch ((operator_type_t)word->id) {
        case OPER_TYPE_ADD:
            *type = EXPR_NODE_ADD;
            break;

        case OPER_TYPE_SUB:
            *type = EXPR_NODE_SUB;
            break;

        case OPER_TYPE_MUL:
            *type = EXPR_NODE_MUL;
            break;

        case OPER_TYPE_DIV:
            *type = EXPR_NODE_DIV;
            break;

        case OPER_TYPE_MOD:
            *type = EXPR_NODE_MOD;
            break;

        case OPER_TYPE_CAT:
            *type = EXPR_NODE_CAT;
            break;
        case OPER_TYPE_BITAND:
            *type = EXPR_NODE_BITAND;
            break;
        case OPER_TYPE_BITOR:
            *type = EXPR_NODE_BITOR;
            break;
        case OPER_TYPE_BITXOR:
            *type = EXPR_NODE_BITXOR;
            break;
        case OPER_TYPE_LSHIFT:
            *type = EXPR_NODE_LSHIFT;
            break;
        case OPER_TYPE_RSHIFT:
            *type = EXPR_NODE_RSHIFT;
            break;
        default:
            *type = EXPR_NODE_UNKNOWN;
            break;
    }
}

static bool32 sql_match_expected(expr_tree_t *expr, word_t *word, expr_node_type_t *type)
{
    if (expr->expecting == EXPR_EXPECT_UNARY) {
        expr->expecting = EXPR_EXPECT_VAR;
        if (word->id == OPER_TYPE_PRIOR) {
            *type = (expr_node_type_t)EXPR_NODE_PRIOR;
        } else {
            *type = (expr_node_type_t)EXPR_NODE_NEGATIVE;
        }
        return GS_TRUE;
    }

    if ((expr->expecting & EXPR_EXPECT_ALPHA) && word->type == WORD_TYPE_ALPHA_PARAM) {
        expr->expecting = EXPR_EXPECT_ALPHA;
        *type = (expr_node_type_t)EXPR_NODE_CSR_PARAM;
        return GS_TRUE;
    }

    /* BEGIN for the parse of count(*) branch */
    if (((expr)->expecting & EXPR_EXPECT_STAR) != 0 && EXPR_IS_STAR(word)) {
        expr->expecting = 0;
        *type = (expr_node_type_t)EXPR_NODE_STAR;
        return GS_TRUE;
    }

    /* END for the parse of count(*) branch */
    if ((expr->expecting & EXPR_EXPECT_VAR) && ((uint32)word->type & EXPR_VAR_WORDS)) {
        expr->expecting = EXPR_EXPECT_OPER;
        sql_var2entype(word, type);
        return GS_TRUE;
    }

    if ((expr->expecting & EXPR_EXPECT_OPER) != 0 && EXPR_IS_OPER(word)) {
        sql_oper2entype(word, type);
        expr->expecting = EXPR_EXPECT_VAR | EXPR_EXPECT_UNARY_OP;
        return GS_TRUE;
    }
    return GS_FALSE;
}

static status_t sql_parse_size(lex_t *lex, uint16 max_size, bool32 is_requred, typmode_t *type, datatype_wid_t dtyp_id)
{
    bool32 result = GS_FALSE;
    word_t word;
    int32 size;
    text_t text_size, text_char;

    GS_RETURN_IFERR(lex_try_fetch_bracket(lex, &word, &result));

    if (!result) {         // if no bracket found, i.e., the size is not specified
        if (is_requred) {  // but the size must be specified, then throw an error
            GS_SRC_THROW_ERROR(word.text.loc, ERR_SQL_SYNTAX_ERROR, "the column size must be specified");
            return GS_ERROR;
        }
        type->size = 1;
        return GS_SUCCESS;
    }

    lex_remove_brackets(&word.text);
    text_size = *(text_t *)&word.text;

    // try get char or byte attr
    if (type->datatype == GS_TYPE_CHAR || type->datatype == GS_TYPE_VARCHAR) {
        cm_trim_text((text_t *)&word.text);
        cm_split_text((text_t *)&word.text, ' ', '\0', &text_size, &text_char);

        if (text_char.len > 0) {
            if (dtyp_id == DTYP_NCHAR || dtyp_id == DTYP_NVARCHAR) {
                source_location_t loc;
                loc.line = word.text.loc.line;
                loc.column = word.text.loc.column + text_size.len;
                GS_SRC_THROW_ERROR(loc, ERR_SQL_SYNTAX_ERROR, "missing right parenthesis");
                return GS_ERROR;
            }
            cm_trim_text(&text_char);
            if (cm_text_str_equal_ins(&text_char, "CHAR")) {
                type->is_char = GS_TRUE;
            } else if (!cm_text_str_equal_ins(&text_char, "BYTE")) {
                GS_SRC_THROW_ERROR(word.text.loc, ERR_SQL_SYNTAX_ERROR, "the column char type must be CHAR or BYTE");
                return GS_ERROR;
            }
        }
    }

    if (!cm_is_int(&text_size)) {
        GS_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "integer size value expected but %s found",
                              W2S(&word));
        return GS_ERROR;
    }

    GS_RETURN_IFERR(cm_text2int(&text_size, &size));

    if (size <= 0 || size > (int32)max_size) {
        GS_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "size value must between 1 and %u", max_size);
        return GS_ERROR;
    }

    type->size = (uint16)size;

    return GS_SUCCESS;
}

static status_t sql_parse_precision(lex_t *lex, typmode_t *type)
{
    bool32 result = GS_FALSE;
    text_t text_prec, text_scale;
    word_t word;
    int32 precision, scale;  // to avoid overflow

    GS_RETURN_IFERR(lex_try_fetch_bracket(lex, &word, &result));

    if (!result) {                                 // both precision and scale are not specified
        type->precision = GS_UNSPECIFIED_NUM_PREC; /* *< 0 stands for precision is not defined when create table */
        type->scale = GS_UNSPECIFIED_NUM_SCALE;
        type->size = GS_IS_NUMBER2_TYPE(type->datatype) ? (uint16)MAX_DEC2_BYTE_SZ : (uint16)MAX_DEC_BYTE_SZ;
        return GS_SUCCESS;
    }

    lex_remove_brackets(&word.text);
    cm_split_text((text_t *)&word.text, ',', '\0', &text_prec, &text_scale);

    if (!cm_is_int(&text_prec)) {
        GS_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "precision expected but %s found", W2S(&word));
        return GS_ERROR;
    }

    // type->precision
    GS_RETURN_IFERR(cm_text2int(&text_prec, &precision));

    if (precision < GS_MIN_NUM_PRECISION || precision > GS_MAX_NUM_PRECISION) {
        GS_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "precision must between %d and %d",
                              GS_MIN_NUM_PRECISION, GS_MAX_NUM_PRECISION);
        return GS_ERROR;
    }
    type->precision = (uint8)precision;
    type->size = GS_IS_NUMBER2_TYPE(type->datatype) ? (uint16)MAX_DEC2_BYTE_BY_PREC(type->precision)
                                                    : (uint16)MAX_DEC_BYTE_BY_PREC(type->precision);

    cm_trim_text(&text_scale);
    if (text_scale.len == 0) {  // Only the precision is specified and the scale is not specified
        type->scale = 0;        // then the scale is 0
        return GS_SUCCESS;
    }

    if (!cm_is_int(&text_scale)) {
        GS_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "scale expected but %s found", W2S(&word));
        return GS_ERROR;
    }

    GS_RETURN_IFERR(cm_text2int(&text_scale, &scale));

    int32 min_scale = GS_MIN_NUM_SCALE;
    int32 max_scale = GS_MAX_NUM_SCALE;
    if (scale > max_scale || scale < min_scale) {
        GS_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "numeric scale specifier is out of range (%d to %d)",
                              min_scale, max_scale);
        return GS_ERROR;
    }
    type->scale = (int8)scale;
    return GS_SUCCESS;
}

static status_t sql_parse_real_mode(lex_t *lex, pmode_t pmod, typmode_t *type)
{
    bool32 result = GS_FALSE;
    text_t text_prec, text_scale;
    word_t word;
    int32 precision, scale;  // to avoid overflow

    type->size = sizeof(double);
    do {
        if (pmod == PM_PL_ARG) {
            result = GS_FALSE;
            break;
        }
        GS_RETURN_IFERR(lex_try_fetch_bracket(lex, &word, &result));
    } while (0);

    if (!result) {                                  // both precision and scale are not specified
        type->precision = GS_UNSPECIFIED_REAL_PREC; /* *< 0 stands for precision is not defined when create table */
        type->scale = GS_UNSPECIFIED_REAL_SCALE;
        return GS_SUCCESS;
    }

    lex_remove_brackets(&word.text);
    cm_split_text((text_t *)&word.text, ',', '\0', &text_prec, &text_scale);

    if (cm_text2int_ex(&text_prec, &precision) != NERR_SUCCESS) {
        GS_SRC_THROW_ERROR(word.text.loc, ERR_SQL_SYNTAX_ERROR, "precision must be an integer");
        return GS_ERROR;
    }

    if (precision < GS_MIN_REAL_PRECISION || precision > GS_MAX_REAL_PRECISION) {
        GS_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "precision must between %d and %d",
                              GS_MIN_NUM_PRECISION, GS_MAX_NUM_PRECISION);
        return GS_ERROR;
    }
    type->precision = (uint8)precision;

    cm_trim_text(&text_scale);
    if (text_scale.len == 0) {  // Only the precision is specified and the scale is not specified
        type->scale = 0;        // then the scale is 0
        return GS_SUCCESS;
    }

    if (cm_text2int_ex(&text_scale, &scale) != NERR_SUCCESS) {
        GS_SRC_THROW_ERROR(word.text.loc, ERR_SQL_SYNTAX_ERROR, "scale must be an integer");
        return GS_ERROR;
    }

    if (scale > GS_MAX_REAL_SCALE || scale < GS_MIN_REAL_SCALE) {
        GS_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "scale must between %d and %d", GS_MIN_REAL_SCALE,
                              GS_MAX_REAL_SCALE);
        return GS_ERROR;
    }
    type->scale = (int8)scale;
    return GS_SUCCESS;
}

/* used for parsing a number/decimal type in PL argument
 * e.g. the type of t_column, the precison and scale of NUMBER are not allowed here.
 * CREATE OR REPLACE PROCEDURE select_item ( *   t_column in NUMBER,
 * )
 * IS
 * temp1 VARCHAR2(10);
 * BEGIN
 * temp1 := t_column;
 * DBE_OUTPUT.PRINT_LINE ('No Data found for SELECT on ' || temp1);
 * END;
 * /
 *
 * @see sql_parse_rough_interval_attr
 *  */
static inline status_t sql_parse_rough_precision(lex_t *lex, typmode_t *type)
{
    type->precision = GS_UNSPECIFIED_NUM_PREC; /* *< 0 stands for precision is not defined when create table */
    type->scale = GS_UNSPECIFIED_NUM_SCALE;
    type->size = GS_IS_NUMBER2_TYPE(type->datatype) ? MAX_DEC2_BYTE_SZ : MAX_DEC_BYTE_SZ;
    return GS_SUCCESS;
}

/**
 * Parse the precision of a DATATIME or INTERVAL datatype
 * The specified precision must be between *min_prec* and *max_prec*.
 * If it not specified, then the default value is used
 */
static status_t sql_parse_datetime_precision(lex_t *lex, int32 *val_int32, int32 def_prec, int32 min_prec,
                                             int32 max_prec, const char *field_name)
{
    bool32 result = GS_FALSE;
    word_t word;

    GS_RETURN_IFERR(lex_try_fetch_bracket(lex, &word, &result));

    if (!result) {
        *val_int32 = def_prec;
        return GS_SUCCESS;
    }

    lex_remove_brackets(&word.text);

    if (cm_text2int_ex((text_t *)&word.text, val_int32) != NERR_SUCCESS) {
        GS_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "invalid %s precision, expected integer",
                              field_name);
        return GS_ERROR;
    }

    if (*val_int32 < min_prec || *val_int32 > max_prec) {
        GS_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "%s precision must be between %d and %d", field_name,
                              min_prec, max_prec);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

/**
 * Parse the leading precision and fractional_seconds_precsion of SECOND
 *
 */
static status_t sql_parse_second_precision(lex_t *lex, int32 *lead_prec, int32 *frac_prec)
{
    bool32 result = GS_FALSE;
    word_t word;
    status_t status;

    GS_RETURN_IFERR(lex_try_fetch_bracket(lex, &word, &result));

    if (!result) {
        *lead_prec = ITVL_DEFAULT_DAY_PREC;
        *frac_prec = ITVL_DEFAULT_SECOND_PREC;
        return GS_SUCCESS;
    }

    lex_remove_brackets(&word.text);
    GS_RETURN_IFERR(lex_push(lex, &word.text));

    do {
        status = GS_ERROR;
        GS_BREAK_IF_ERROR(lex_fetch(lex, &word));

        if (cm_text2int_ex((text_t *)&word.text, lead_prec) != NERR_SUCCESS) {
            GS_SRC_THROW_ERROR(word.text.loc, ERR_SQL_SYNTAX_ERROR, "invalid precision, expected integer");
            break;
        }

        if (*lead_prec > ITVL_MAX_DAY_PREC || *lead_prec < ITVL_MIN_DAY_PREC) {
            GS_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "DAY precision must be between %d and %d",
                                  ITVL_MIN_DAY_PREC, ITVL_MAX_DAY_PREC);
            break;
        }

        GS_BREAK_IF_ERROR(lex_try_fetch_char(lex, ',', &result));
        if (!result) {
            *frac_prec = ITVL_DEFAULT_SECOND_PREC;
            status = GS_SUCCESS;
            break;
        }

        GS_BREAK_IF_ERROR(lex_fetch(lex, &word));
        if (cm_text2int_ex((text_t *)&word.text, frac_prec) != NERR_SUCCESS) {
            GS_SRC_THROW_ERROR(word.text.loc, ERR_SQL_SYNTAX_ERROR, "invalid precision, expected integer");
            break;
        }

        if (*frac_prec > ITVL_MAX_SECOND_PREC || *frac_prec < ITVL_MIN_SECOND_PREC) {
            GS_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR,
                                  "fractional second precision must be between %d and %d", ITVL_MIN_SECOND_PREC,
                                  ITVL_MAX_SECOND_PREC);
            break;
        }
        status = GS_SUCCESS;
    } while (0);

    lex_pop(lex);
    return status;
}

static inline status_t sql_parse_timestamp_mod(lex_t *lex, typmode_t *type, pmode_t pmod, word_t *word)
{
    uint32 match_id;
    bool32 is_local = GS_FALSE;
    int32 prec_val = GS_MAX_DATETIME_PRECISION;

    type->datatype = GS_TYPE_TIMESTAMP;

    if (pmod != PM_PL_ARG) {
        if (sql_parse_datetime_precision(lex, &prec_val, GS_DEFAULT_DATETIME_PRECISION, GS_MIN_DATETIME_PRECISION,
                                         GS_MAX_DATETIME_PRECISION, "timestamp") != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    type->precision = (uint8)prec_val;
    type->scale = 0;
    type->size = sizeof(timestamp_t);

    if (lex_try_fetch_1of2(lex, "WITH", "WITHOUT", &match_id) != GS_SUCCESS) {
        return GS_ERROR;
    }
    if (match_id == GS_INVALID_ID32) {
        return GS_SUCCESS;
    }

    GS_RETURN_IFERR(lex_try_fetch(lex, "LOCAL", &is_local));

    GS_RETURN_IFERR(lex_expected_fetch_word2(lex, "TIME", "ZONE"));

    if (match_id == 1) {
        /* timestamp without time zone : do the same as timestamp. */
        return GS_SUCCESS;
    }

    if (is_local) {
        type->datatype = GS_TYPE_TIMESTAMP_LTZ;
        word->id = DTYP_TIMESTAMP_LTZ;
    } else {
        if (lex->call_version >= CS_VERSION_8) {
            type->datatype = GS_TYPE_TIMESTAMP_TZ;
            type->size = sizeof(timestamp_tz_t);
        } else {
            /* GS_TYPE_TIMESTAMP_TZ_FAKE is same with timestamp */
            type->datatype = GS_TYPE_TIMESTAMP_TZ_FAKE;
            type->size = sizeof(timestamp_t);
        }
        word->id = DTYP_TIMESTAMP_TZ;
    }

    return GS_SUCCESS;
}

static status_t sql_parse_interval_ds(lex_t *lex, typmode_t *type, uint32 *pfmt, uint32 match_id, uint32 *itvl_fmt)
{
    int32 prec, frac;
    bool32 result = GS_FALSE;
    uint32 match_id2;
    const interval_unit_t itvl_uints[] = { IU_YEAR, IU_MONTH, IU_DAY, IU_HOUR, IU_MINUTE, IU_SECOND };

    type->datatype = GS_TYPE_INTERVAL_DS;
    type->size = sizeof(interval_ds_t);

    if (match_id < 5) {
        // parse leading precision
        GS_RETURN_IFERR(sql_parse_datetime_precision(lex, &prec, ITVL_DEFAULT_DAY_PREC, ITVL_MIN_DAY_PREC,
                                                     ITVL_MAX_DAY_PREC, "DAY"));
        type->day_prec = (uint8)prec;
        type->frac_prec = 0;

        GS_RETURN_IFERR(lex_try_fetch(lex, "TO", &result));
        if (!result) {
            if (pfmt != NULL) {
                (*pfmt) = *itvl_fmt;
            }
            return GS_SUCCESS;
        }
        GS_RETURN_IFERR(lex_expected_fetch_1ofn(lex, &match_id2, 4, "DAY", "HOUR", "MINUTE", "SECOND"));
        match_id2 += 2;

        if (match_id2 < match_id) {
            GS_SRC_THROW_ERROR(LEX_LOC, ERR_INVALID_INTERVAL_TEXT, "-- invalid field name");
            return GS_ERROR;
        }
        for (uint32 i = match_id + 1; i <= match_id2; ++i) {
            *itvl_fmt |= itvl_uints[i];
        }
        if (match_id2 == 5) {
            // parse second frac_precision
            GS_RETURN_IFERR(sql_parse_datetime_precision(lex, &frac, ITVL_DEFAULT_SECOND_PREC, ITVL_MIN_SECOND_PREC,
                                                         ITVL_MAX_SECOND_PREC, "fractional second"));
            type->frac_prec = (uint8)frac;
        }
    } else {
        // parse leading and fractional precision
        GS_RETURN_IFERR(sql_parse_second_precision(lex, &prec, &frac));
        type->day_prec = (uint8)prec;
        type->frac_prec = (uint8)frac;
    }
    return GS_SUCCESS;
}

/* parsing an interval literal in a SQL expression
 * e.g., INTERVAL '123-2' YEAR(3) TO MONTH, INTERVAL '4 5:12' DAY TO MINUTE */
static inline status_t sql_parse_interval_literal(lex_t *lex, typmode_t *type, uint32 *pfmt)
{
    uint32 match_id, match_id2;
    int32 prec;
    bool32 result = GS_FALSE;
    uint32 itvl_fmt;

    const interval_unit_t itvl_uints[] = { IU_YEAR, IU_MONTH, IU_DAY, IU_HOUR, IU_MINUTE, IU_SECOND };

    GS_RETURN_IFERR(lex_expected_fetch_1ofn(lex, &match_id, 6, "YEAR", "MONTH", "DAY", "HOUR", "MINUTE", "SECOND"));

    itvl_fmt = itvl_uints[match_id];

    if (match_id < 2) {
        type->datatype = GS_TYPE_INTERVAL_YM;
        type->size = sizeof(interval_ym_t);
        // parse leading precision
        GS_RETURN_IFERR(sql_parse_datetime_precision(lex, &prec, ITVL_DEFAULT_YEAR_PREC, ITVL_MIN_YEAR_PREC,
                                                     ITVL_MAX_YEAR_PREC, "YEAR"));
        type->year_prec = (uint8)prec;
        type->reserved = 0;

        if (match_id == 0) {
            GS_RETURN_IFERR(lex_try_fetch(lex, "TO", &result));
            if (result) {
                GS_RETURN_IFERR(lex_expected_fetch_1of2(lex, "YEAR", "MONTH", &match_id2));
                itvl_fmt |= itvl_uints[match_id2];
            }
        }
    } else {
        GS_RETURN_IFERR(sql_parse_interval_ds(lex, type, pfmt, match_id, &itvl_fmt));
    }

    if (pfmt != NULL) {
        (*pfmt) = itvl_fmt;
    }
    return GS_SUCCESS;
}

/**
 * Further distinguish two INTERVAL datatypes, with syntax:
 * INTERVAL  YEAR [( year_precision)]  TO  MONTH
 * INTERVAL  DAY [( day_precision)]  TO  SECOND[( fractional_seconds_precision)]
 */
static inline status_t sql_parse_interval_attr(lex_t *lex, typmode_t *type, word_t *word)
{
    uint32 match_id;
    int32 prec;

    GS_RETURN_IFERR(lex_expected_fetch_1of2(lex, "YEAR", "DAY", &match_id));

    if (match_id == 0) {
        // parse year_precision
        if (sql_parse_datetime_precision(lex, &prec, ITVL_DEFAULT_YEAR_PREC, ITVL_MIN_YEAR_PREC, ITVL_MAX_YEAR_PREC,
                                         "YEAR") != GS_SUCCESS) {
            return GS_ERROR;
        }
        type->year_prec = (uint8)prec;
        type->reserved = 0;
        GS_RETURN_IFERR(lex_expected_fetch_word2(lex, "TO", "MONTH"));

        type->datatype = GS_TYPE_INTERVAL_YM;
        type->size = sizeof(interval_ym_t);
        word->id = DTYP_INTERVAL_YM;
    } else {
        // parse day_precision
        if (sql_parse_datetime_precision(lex, &prec, ITVL_DEFAULT_DAY_PREC, ITVL_MIN_DAY_PREC, ITVL_MAX_DAY_PREC,
                                         "DAY") != GS_SUCCESS) {
            return GS_ERROR;
        }
        type->day_prec = (uint8)prec;

        GS_RETURN_IFERR(lex_expected_fetch_word2(lex, "TO", "SECOND"));

        // parse fractional_seconds_precision
        if (sql_parse_datetime_precision(lex, &prec, ITVL_DEFAULT_SECOND_PREC, ITVL_MIN_SECOND_PREC,
                                         ITVL_MAX_SECOND_PREC, "SECOND") != GS_SUCCESS) {
            return GS_ERROR;
        }
        type->frac_prec = (uint8)prec;

        type->datatype = GS_TYPE_INTERVAL_DS;
        type->size = sizeof(interval_ds_t);
        word->id = DTYP_INTERVAL_DS;
    }

    return GS_SUCCESS;
}

/**
 * Further distinguish two INTERVAL datatypes, with syntax:
 * INTERVAL  YEAR TO  MONTH
 * INTERVAL  DAY TO  SECOND
 *
 * @see sql_parse_rough_precision
 */
static inline status_t sql_parse_rough_interval_attr(lex_t *lex, typmode_t *type, word_t *word)
{
    uint32 match_id;

    GS_RETURN_IFERR(lex_expected_fetch_1of2(lex, "YEAR", "DAY", &match_id));

    if (match_id == 0) {
        GS_RETURN_IFERR(lex_expected_fetch_word2(lex, "TO", "MONTH"));

        // set year_precision
        type->year_prec = (uint8)ITVL_MAX_YEAR_PREC;
        type->reserved = 0;
        type->datatype = GS_TYPE_INTERVAL_YM;
        type->size = sizeof(interval_ym_t);
        word->id = DTYP_INTERVAL_YM;
    } else {
        GS_RETURN_IFERR(lex_expected_fetch_word2(lex, "TO", "SECOND"));

        // set day_precision
        type->day_prec = (uint8)ITVL_MAX_DAY_PREC;
        // set fractional_seconds_precision
        type->frac_prec = (uint8)ITVL_MAX_SECOND_PREC;
        type->datatype = GS_TYPE_INTERVAL_DS;
        type->size = sizeof(interval_ds_t);
        word->id = DTYP_INTERVAL_DS;
    }

    return GS_SUCCESS;
}

static status_t sql_parse_datatype_charset(lex_t *lex, uint8 *charset)
{
    word_t word;
    bool32 result = GS_FALSE;
    uint16 charset_id;

    if (lex_try_fetch(lex, "CHARACTER", &result) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (!result) {
        return GS_SUCCESS;
    }

    if (lex_expected_fetch_word(lex, "SET") != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (lex_fetch(lex, &word) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (word.type == WORD_TYPE_STRING) {
        LEX_REMOVE_WRAP(&word);
    }

    charset_id = cm_get_charset_id_ex(&word.text.value);
    if (charset_id == GS_INVALID_ID16) {
        GS_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "unknown charset option %s", T2S(&word.text.value));
        return GS_ERROR;
    }

    *charset = (uint8)charset_id;

    return GS_SUCCESS;
}

static status_t sql_parse_datatype_collate(lex_t *lex, uint8 *collate)
{
    word_t word;
    bool32 result = GS_FALSE;
    uint16 collate_id;

    if (lex_try_fetch(lex, "COLLATE", &result) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (!result) {
        return GS_SUCCESS;
    }

    if (lex_fetch(lex, &word) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (word.type == WORD_TYPE_STRING) {
        LEX_REMOVE_WRAP(&word);
    }

    collate_id = cm_get_collation_id(&word.text.value);
    if (collate_id == GS_INVALID_ID16) {
        GS_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "unknown collation option %s",
                              T2S(&word.text.value));
        return GS_ERROR;
    }

    *collate = (uint8)collate_id;
    return GS_SUCCESS;
}

#define sql_set_default_typmod(typmod, typsz) ((typmod)->size = (uint16)(typsz), GS_SUCCESS)

static inline status_t sql_parse_varchar_mode(lex_t *lex, pmode_t pmod, typmode_t *typmod, datatype_wid_t dword_id)
{
    if (pmod == PM_PL_ARG) {
        return sql_set_default_typmod(typmod, GS_MAX_STRING_LEN);
    }
    return sql_parse_size(lex, (pmod == PM_NORMAL) ? GS_MAX_COLUMN_SIZE : GS_MAX_STRING_LEN, GS_TRUE, typmod, dword_id);
}

static status_t sql_parse_orcl_typmod(lex_t *lex, pmode_t pmod, typmode_t *typmod, word_t *typword)
{
    datatype_wid_t dword_id = (datatype_wid_t)typword->id;
    switch (dword_id) {
        case DTYP_BIGINT:
        case DTYP_UBIGINT:
        case DTYP_INTEGER:
        case DTYP_UINTEGER:
        case DTYP_SMALLINT:
        case DTYP_USMALLINT:
        case DTYP_TINYINT:
        case DTYP_UTINYINT:
            typmod->datatype = GS_TYPE_NUMBER;
            typmod->precision = GS_MAX_NUM_PRECISION;
            typmod->scale = 0;
            typmod->size = MAX_DEC_BYTE_BY_PREC(GS_MAX_NUM_PRECISION);
            return GS_SUCCESS;

        case DTYP_BOOLEAN:
            typmod->datatype = GS_TYPE_BOOLEAN;
            typmod->size = sizeof(bool32);
            return GS_SUCCESS;

        case DTYP_DOUBLE:
        case DTYP_FLOAT:
        case DTYP_NUMBER:
        case DTYP_DECIMAL:
            typmod->datatype = GS_TYPE_NUMBER;
            return (pmod != PM_PL_ARG) ? sql_parse_precision(lex, typmod) : sql_parse_rough_precision(lex, typmod);
        case DTYP_NUMBER2:
            typmod->datatype = GS_TYPE_NUMBER2;
            return (pmod != PM_PL_ARG) ? sql_parse_precision(lex, typmod) : sql_parse_rough_precision(lex, typmod);

        case DTYP_BINARY:
            typmod->datatype = g_instance->sql.string_as_hex_binary ? GS_TYPE_RAW : GS_TYPE_BINARY;
            return (pmod != PM_PL_ARG) ? sql_parse_size(lex, (uint16)GS_MAX_COLUMN_SIZE, GS_FALSE, typmod, dword_id)
                                       : sql_set_default_typmod(typmod, GS_MAX_COLUMN_SIZE);

        case DTYP_VARBINARY:
            typmod->datatype = g_instance->sql.string_as_hex_binary ? GS_TYPE_RAW : GS_TYPE_VARBINARY;
            return (pmod != PM_PL_ARG) ? sql_parse_size(lex, (uint16)GS_MAX_COLUMN_SIZE, GS_TRUE, typmod, dword_id)
                                       : sql_set_default_typmod(typmod, GS_MAX_COLUMN_SIZE);

        case DTYP_RAW:
            typmod->datatype = GS_TYPE_RAW;
            return (pmod != PM_PL_ARG) ? sql_parse_size(lex, (uint16)GS_MAX_COLUMN_SIZE, GS_FALSE, typmod, dword_id)
                                       : sql_set_default_typmod(typmod, GS_MAX_COLUMN_SIZE);

        case DTYP_CHAR:
            typmod->datatype = GS_TYPE_CHAR;
            return (pmod != PM_PL_ARG) ? sql_parse_size(lex, (uint16)GS_MAX_COLUMN_SIZE, GS_FALSE, typmod, dword_id)
                                       : sql_set_default_typmod(typmod, GS_MAX_COLUMN_SIZE);

        case DTYP_VARCHAR:
            typmod->datatype = GS_TYPE_VARCHAR;
            return sql_parse_varchar_mode(lex, pmod, typmod, dword_id);

        case DTYP_DATE:
            typmod->datatype = GS_TYPE_DATE;
            typmod->size = sizeof(date_t);
            return GS_SUCCESS;

        case DTYP_TIMESTAMP:
            return sql_parse_timestamp_mod(lex, typmod, pmod, typword);

        case DTYP_INTERVAL:
            return (pmod != PM_PL_ARG) ? sql_parse_interval_attr(lex, typmod, typword)
                                       : sql_parse_rough_interval_attr(lex, typmod, typword);

        case DTYP_BINARY_DOUBLE:
        case DTYP_BINARY_FLOAT:
            typmod->datatype = GS_TYPE_REAL;
            typmod->size = sizeof(double);
            return GS_SUCCESS;

        case DTYP_BINARY_UINTEGER:
            typmod->datatype = GS_TYPE_UINT32;
            typmod->size = sizeof(uint32);
            return GS_SUCCESS;
        case DTYP_BINARY_INTEGER:
            typmod->datatype = GS_TYPE_INTEGER;
            typmod->size = sizeof(int32);
            return GS_SUCCESS;

        case DTYP_SERIAL:
        case DTYP_BINARY_BIGINT:
            typmod->datatype = GS_TYPE_BIGINT;
            typmod->size = sizeof(int64);
            return GS_SUCCESS;

        case DTYP_BLOB: {
            typmod->datatype = GS_TYPE_BLOB;
            return sql_set_default_typmod(typmod, GS_MAX_COLUMN_SIZE);
        }

        case DTYP_CLOB: {
            typmod->datatype = GS_TYPE_CLOB;
            return sql_set_default_typmod(typmod, GS_MAX_COLUMN_SIZE);
        }

        case DTYP_IMAGE:
            typmod->datatype = GS_TYPE_IMAGE;
            return sql_set_default_typmod(typmod, GS_MAX_COLUMN_SIZE);

        case DTYP_NVARCHAR:
            typmod->datatype = GS_TYPE_VARCHAR;
            GS_RETURN_IFERR(sql_parse_varchar_mode(lex, pmod, typmod, dword_id));
            typmod->is_char = GS_TRUE;
            return GS_SUCCESS;

        case DTYP_NCHAR:
            typmod->datatype = GS_TYPE_CHAR;
            if (pmod != PM_PL_ARG) {
                GS_RETURN_IFERR(sql_parse_size(lex, (uint16)GS_MAX_COLUMN_SIZE, GS_FALSE, typmod, dword_id));
            } else {
                GS_RETURN_IFERR(sql_set_default_typmod(typmod, GS_MAX_COLUMN_SIZE));
            }

            typmod->is_char = GS_TRUE;
            return GS_SUCCESS;

        case DTYP_BINARY_UBIGINT:
            GS_SRC_THROW_ERROR(typword->loc, ERR_CAPABILITY_NOT_SUPPORT, "datatype");
            return GS_ERROR;

        default:
            GS_SRC_THROW_ERROR_EX(typword->loc, ERR_SQL_SYNTAX_ERROR, "unrecognized datatype word: %s",
                                  T2S(&typword->text.value));
            return GS_ERROR;
    }
}

static status_t sql_parse_native_typmod(lex_t *lex, pmode_t pmod, typmode_t *typmod, word_t *typword)
{
    status_t status;
    datatype_wid_t dword_id = (datatype_wid_t)typword->id;
    switch (dword_id) {
        /* now we map smallint/tinyint unsigned into uint */
        case DTYP_UINTEGER:
        case DTYP_BINARY_UINTEGER:
        case DTYP_USMALLINT:
        case DTYP_UTINYINT:
            typmod->datatype = GS_TYPE_UINT32;
            typmod->size = sizeof(uint32);
            return GS_SUCCESS;
        /* now we map smallint/tinyint signed into int */
        case DTYP_SMALLINT:
        case DTYP_TINYINT:
        case DTYP_INTEGER:
        case DTYP_PLS_INTEGER:
        case DTYP_BINARY_INTEGER:
            typmod->datatype = GS_TYPE_INTEGER;
            typmod->size = sizeof(int32);
            return GS_SUCCESS;

        case DTYP_BOOLEAN:
            typmod->datatype = GS_TYPE_BOOLEAN;
            typmod->size = sizeof(bool32);
            return GS_SUCCESS;

        case DTYP_NUMBER:
            typmod->datatype = GS_TYPE_NUMBER;
            status = (pmod != PM_PL_ARG) ? sql_parse_precision(lex, typmod) : sql_parse_rough_precision(lex, typmod);
            return status;

        case DTYP_NUMBER2:
            typmod->datatype = GS_TYPE_NUMBER2;
            return (pmod != PM_PL_ARG) ? sql_parse_precision(lex, typmod) : sql_parse_rough_precision(lex, typmod);

        case DTYP_DECIMAL:
            typmod->datatype = GS_TYPE_NUMBER;
            return (pmod != PM_PL_ARG) ? sql_parse_precision(lex, typmod) : sql_parse_rough_precision(lex, typmod);

        case DTYP_BINARY:
            typmod->datatype = g_instance->sql.string_as_hex_binary ? GS_TYPE_RAW : GS_TYPE_BINARY;
            return (pmod != PM_PL_ARG) ? sql_parse_size(lex, (uint16)GS_MAX_COLUMN_SIZE, GS_TRUE, typmod, dword_id)
                                       : sql_set_default_typmod(typmod, GS_MAX_COLUMN_SIZE);

        case DTYP_VARBINARY:
            typmod->datatype = g_instance->sql.string_as_hex_binary ? GS_TYPE_RAW : GS_TYPE_VARBINARY;
            return (pmod != PM_PL_ARG) ? sql_parse_size(lex, (uint16)GS_MAX_COLUMN_SIZE, GS_TRUE, typmod, dword_id)
                                       : sql_set_default_typmod(typmod, GS_MAX_COLUMN_SIZE);

        case DTYP_RAW:
            typmod->datatype = GS_TYPE_RAW;
            return (pmod != PM_PL_ARG) ? sql_parse_size(lex, (uint16)GS_MAX_COLUMN_SIZE, GS_TRUE, typmod, dword_id)
                                       : sql_set_default_typmod(typmod, GS_MAX_COLUMN_SIZE);

        case DTYP_CHAR:
            typmod->datatype = GS_TYPE_CHAR;
            return (pmod != PM_PL_ARG) ? sql_parse_size(lex, (uint16)GS_MAX_COLUMN_SIZE, GS_FALSE, typmod, dword_id)
                                       : sql_set_default_typmod(typmod, GS_MAX_COLUMN_SIZE);

        case DTYP_VARCHAR:
        case DTYP_STRING:
            typmod->datatype = GS_TYPE_VARCHAR;
            return sql_parse_varchar_mode(lex, pmod, typmod, dword_id);

        case DTYP_DATE:
            typmod->datatype = GS_TYPE_DATE;
            typmod->size = sizeof(date_t);
            return GS_SUCCESS;

        case DTYP_TIMESTAMP:
            return sql_parse_timestamp_mod(lex, typmod, pmod, typword);

        case DTYP_INTERVAL:
            return (pmod != PM_PL_ARG) ? sql_parse_interval_attr(lex, typmod, typword)
                                       : sql_parse_rough_interval_attr(lex, typmod, typword);

        case DTYP_DOUBLE:
        case DTYP_FLOAT:
            typmod->datatype = GS_TYPE_REAL;
            return sql_parse_real_mode(lex, pmod, typmod);

        case DTYP_BINARY_DOUBLE:
        case DTYP_BINARY_FLOAT:
            typmod->datatype = GS_TYPE_REAL;
            typmod->size = sizeof(double);
            typmod->precision = GS_UNSPECIFIED_REAL_PREC;
            typmod->scale = GS_UNSPECIFIED_REAL_SCALE;
            return GS_SUCCESS;

        case DTYP_SERIAL:
        case DTYP_BIGINT:
        case DTYP_BINARY_BIGINT:
            typmod->datatype = GS_TYPE_BIGINT;
            typmod->size = sizeof(int64);
            return GS_SUCCESS;

        case DTYP_JSONB:
        case DTYP_BLOB: {
            typmod->datatype = GS_TYPE_BLOB;
            return sql_set_default_typmod(typmod, GS_MAX_COLUMN_SIZE);
        }

        case DTYP_CLOB: {
            typmod->datatype = GS_TYPE_CLOB;
            return sql_set_default_typmod(typmod, GS_MAX_COLUMN_SIZE);
        }

        case DTYP_IMAGE:
            typmod->datatype = GS_TYPE_IMAGE;
            return sql_set_default_typmod(typmod, GS_MAX_COLUMN_SIZE);

        case DTYP_NVARCHAR:
            typmod->datatype = GS_TYPE_VARCHAR;
            GS_RETURN_IFERR(sql_parse_varchar_mode(lex, pmod, typmod, dword_id));
            typmod->is_char = GS_TRUE;
            return GS_SUCCESS;

        case DTYP_NCHAR:
            typmod->datatype = GS_TYPE_CHAR;
            if (pmod != PM_PL_ARG) {
                GS_RETURN_IFERR(sql_parse_size(lex, (uint16)GS_MAX_COLUMN_SIZE, GS_FALSE, typmod, dword_id));
            } else {
                GS_RETURN_IFERR(sql_set_default_typmod(typmod, GS_MAX_COLUMN_SIZE));
            }

            typmod->is_char = GS_TRUE;
            return GS_SUCCESS;

        case DTYP_UBIGINT:
        case DTYP_BINARY_UBIGINT:
            GS_SRC_THROW_ERROR(typword->loc, ERR_CAPABILITY_NOT_SUPPORT, "datatype");
            return GS_ERROR;

        default:
            GS_SRC_THROW_ERROR_EX(typword->loc, ERR_SQL_SYNTAX_ERROR, "unrecognized datatype word: %s",
                                  T2S(&typword->text.value));
            return GS_ERROR;
    }
}

status_t sql_parse_typmode(lex_t *lex, pmode_t pmod, typmode_t *typmod, word_t *typword)
{
    status_t status;
    typmode_t tmode = { 0 };
    uint8 charset = 0;
    uint8 collate = 0;

    if (USE_NATIVE_DATATYPE) {
        status = sql_parse_native_typmod(lex, pmod, &tmode, typword);
        GS_RETURN_IFERR(status);
    } else {
        status = sql_parse_orcl_typmod(lex, pmod, &tmode, typword);
        GS_RETURN_IFERR(status);
    }

    if (GS_IS_STRING_TYPE(tmode.datatype)) {
        status = sql_parse_datatype_charset(lex, &charset);
        GS_RETURN_IFERR(status);
        tmode.charset = charset;

        status = sql_parse_datatype_collate(lex, &collate);
        GS_RETURN_IFERR(status);
        tmode.collate = collate;
    }

    if (typmod != NULL) {
        *typmod = tmode;
    }

    return GS_SUCCESS;
}

status_t sql_parse_datatype_typemode(lex_t *lex, pmode_t pmod, typmode_t *typmod, word_t *typword, word_t *tword)
{
    GS_RETURN_IFERR(sql_parse_typmode(lex, pmod, typmod, tword));

    if (typword != NULL) {
        *typword = *tword;
    }

    if (lex_try_match_array(lex, &typmod->is_array, typmod->datatype) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

/**
 * An important interface to parse a datatype starting from the current LEX,
 * Argument description:
 * + pmod    : see definition of @pmode_t
 * + typmode : The typemode of the parsing datatype. If it is NULL, the output typmode is ignored.
 * + typword : The word of a datatype. It includes type location in SQL, type ID. If it is NULL, it is ignored.
 */
status_t sql_parse_datatype(lex_t *lex, pmode_t pmod, typmode_t *typmod, word_t *typword)
{
    bool32 is_found = GS_FALSE;
    word_t tword;
    if (lex_try_fetch_datatype(lex, &tword, &is_found) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (!is_found) {
        GS_SRC_THROW_ERROR_EX(lex->loc, ERR_SQL_SYNTAX_ERROR, "datatype expected, but got '%s'", W2S(&tword));
        return GS_ERROR;
    }

    if (sql_parse_datatype_typemode(lex, pmod, typmod, typword, &tword) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

/*
    INTERVAL 'integer [-integer]' {YEAR|MONTH}[(prec)] [TO {YEAR|MONTH}]
    OR
    INTERVAL '{integer|integer time_expr|time_expr}'
        {DAY|HOUR|MINUTE|SECOND}[(prec)] [TO {DAY|HOUR|MINUTE|SECOND[(sec_prec)]}]
*/
static status_t sql_try_parse_interval_expr(sql_stmt_t *stmt, expr_node_t *node, bool32 *result)
{
    lex_t *lex = stmt->session->lex;
    text_t itvl_text;
    typmode_t type = { 0 };
    uint32 itvl_fmt = 0;
    interval_detail_t itvl_detail;
    word_t word;

    GS_RETURN_IFERR(lex_fetch(lex, &word));
    if (word.type != WORD_TYPE_STRING) {
        (*result) = GS_FALSE;
        lex_back(lex, &word);
        return GS_SUCCESS;
    }
    (*result) = GS_TRUE;
    itvl_text = word.text.value;
    itvl_text.str += 1;
    itvl_text.len -= 2;

    GS_RETURN_IFERR(sql_parse_interval_literal(lex, &type, &itvl_fmt));

    node->type = EXPR_NODE_CONST;
    node->datatype = type.datatype;
    node->value.type = (int16)type.datatype;
    node->value.is_null = GS_FALSE;
    node->typmod = type;

    GS_RETURN_IFERR(cm_text2intvl_detail(&itvl_text, type.datatype, &itvl_detail, itvl_fmt));

    if (type.datatype == GS_TYPE_INTERVAL_YM) {
        GS_RETURN_IFERR(cm_encode_yminterval(&itvl_detail, &node->value.v_itvl_ym));
        GS_RETURN_IFERR(cm_adjust_yminterval(&node->value.v_itvl_ym, type.year_prec));
    } else {
        GS_RETURN_IFERR(cm_encode_dsinterval(&itvl_detail, &node->value.v_itvl_ds));
        GS_RETURN_IFERR(cm_adjust_dsinterval(&node->value.v_itvl_ds, type.day_prec, type.frac_prec));
    }

    return GS_SUCCESS;
}

/*
  DATE '1995-01-01' OR TIMESTAMP '1995-01-01 11:22:33.456'
*/
static status_t sql_try_parse_date_expr(sql_stmt_t *stmt, word_t *word, expr_node_t *node, bool32 *result)
{
    lex_t *lex = stmt->session->lex;
    uint32 type_id = word->id;
    word_t next_word;

    if (!cm_text_str_equal_ins(&word->text.value, "DATE") && !cm_text_str_equal_ins(&word->text.value, "TIMESTAMP")) {
        (*result) = GS_FALSE;
        return GS_SUCCESS;
    }

    GS_RETURN_IFERR(lex_fetch(lex, &next_word));
    if (next_word.type != WORD_TYPE_STRING) {
        (*result) = GS_FALSE;
        lex_back(lex, &next_word);
        return GS_SUCCESS;
    }
    (*result) = GS_TRUE;
    CM_REMOVE_ENCLOSED_CHAR(&next_word.text.value);

    if (type_id == DTYP_DATE) {
        node->datatype = GS_TYPE_DATE;
        node->typmod.precision = 0;
        GS_RETURN_IFERR(cm_text2date_def(&next_word.text.value, &node->value.v_date));
    } else if (type_id == DTYP_TIMESTAMP) {
        node->datatype = GS_TYPE_TIMESTAMP;
        node->typmod.precision = GS_DEFAULT_DATETIME_PRECISION;
        GS_RETURN_IFERR(cm_text2timestamp_def(&next_word.text.value, &node->value.v_date));
    } else {
        GS_SRC_THROW_ERROR_EX(next_word.text.loc, ERR_SQL_SYNTAX_ERROR, "invalid datatype word id: %u", type_id);
        return GS_ERROR;
    }

    node->type = EXPR_NODE_CONST;
    node->value.type = node->datatype;
    node->value.is_null = GS_FALSE;
    node->typmod.size = sizeof(date_t);

    return GS_SUCCESS;
}

status_t sql_copy_text_remove_quotes(sql_context_t *ctx, text_t *src, text_t *dst)
{
    if (sql_alloc_mem(ctx, src->len, (void **)&dst->str) != GS_SUCCESS) {
        return GS_ERROR;
    }
    dst->len = 0;
    for (uint32 i = 0; i < src->len; i++) {
        CM_TEXT_APPEND(dst, CM_GET_CHAR(src, i));

        // if existing two continuous '
        if (CM_GET_CHAR(src, i) == '\'') {
            ++i;
            if (i >= src->len) {
                break;
            }
            if (CM_GET_CHAR(src, i) != '\'') {
                CM_TEXT_APPEND(dst, CM_GET_CHAR(src, i));
            }
        }
    }

    return GS_SUCCESS;
}

status_t sql_word2text(sql_stmt_t *stmt, word_t *word, expr_node_t *node)
{
    text_t const_text;
    text_t *value_text = NULL;

    const_text = word->text.value;
    CM_REMOVE_ENCLOSED_CHAR(&const_text);

    /*
     * The max size of text in sql is GS_MAX_COLUMN_SIZE.
     * The max size of text in plsql is GS_SHARED_PAGE_SIZE.
     */
    if (SQL_TYPE(stmt) <= SQL_TYPE_DDL_CEIL && const_text.len > GS_MAX_COLUMN_SIZE) {
        GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_VALUE_ERROR, "constant string in SQL is too long, can not exceed %u",
                              GS_MAX_COLUMN_SIZE);
        return GS_ERROR;
    }
    if (SQL_TYPE(stmt) >= SQL_TYPE_CREATE_PROC && SQL_TYPE(stmt) < SQL_TYPE_PL_CEIL_END &&
        const_text.len > sql_pool->memory->page_size) {
        GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_VALUE_ERROR,
                              "constant string in PL/SQL is too long, can not exceed %u", sql_pool->memory->page_size);
        return GS_ERROR;
    }

    value_text = VALUE_PTR(text_t, &node->value);
    node->value.type = GS_TYPE_CHAR;

    if (const_text.len == 0) {
        if (g_instance->sql.enable_empty_string_null) {
            // empty text is used as NULL like oracle
            value_text->str = NULL;
            value_text->len = 0;
            node->value.is_null = GS_TRUE;
            return GS_SUCCESS;
        }
    }

    return sql_copy_text_remove_quotes(stmt->context, &const_text, value_text);
}

status_t word_to_variant_number(word_t *word, variant_t *var)
{
    num_errno_t err_no = NERR_ERROR;
    var->is_null = GS_FALSE;
    var->type = (gs_type_t)word->id;

    switch (var->type) {
        case GS_TYPE_UINT32:
            err_no = cm_numpart2uint32(&word->np, &var->v_uint32);
            break;
        case GS_TYPE_INTEGER:
            err_no = cm_numpart2int(&word->np, &var->v_int);
            break;

        case GS_TYPE_BIGINT:
            err_no = cm_numpart2bigint(&word->np, &var->v_bigint);
            if (var->v_bigint == (int64)(GS_MIN_INT32)) {
                var->type = GS_TYPE_INTEGER;
                var->v_int = GS_MIN_INT32;
            }
            break;
        case GS_TYPE_UINT64:
            err_no = cm_numpart2uint64(&word->np, &var->v_ubigint);
            break;
        case GS_TYPE_REAL:
            err_no = cm_numpart2real(&word->np, &var->v_real);
            break;

        case GS_TYPE_NUMBER:
        case GS_TYPE_NUMBER2:
        case GS_TYPE_DECIMAL: {
            err_no = cm_numpart_to_dec8(&word->np, &var->v_dec);
            if (NUMPART_IS_ZERO(&word->np) && word->np.has_dot) {
                var->type = GS_TYPE_INTEGER;
                var->v_int = 0;
            }
            break;
        }

        default:
            CM_NEVER;
            break;
    }

    if (err_no != NERR_SUCCESS) {
        if (err_no == NERR_OVERFLOW) {
            GS_THROW_ERROR(ERR_NUM_OVERFLOW);
        } else {
            GS_SRC_THROW_ERROR(word->loc, ERR_INVALID_NUMBER, cm_get_num_errinfo(err_no));
        }
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t sql_word2number(word_t *word, expr_node_t *node)
{
    if (UNARY_INCLUDE_NEGATIVE(node)) {
        word->np.is_neg = !word->np.is_neg;
    }

    GS_RETURN_IFERR(word_to_variant_number(word, &node->value));

    if (UNARY_INCLUDE_ROOT(node)) {
        node->unary = UNARY_OPER_ROOT;
    } else {
        node->unary = UNARY_OPER_NONE;
    }

    return GS_SUCCESS;
}

#define CHECK_PARAM_NAME_NEEDED(stmt) ((stmt)->context->type == SQL_TYPE_ANONYMOUS_BLOCK)

status_t sql_add_param_mark(sql_stmt_t *stmt, word_t *word, bool32 *is_repeated, uint32 *pnid)
{
    sql_param_mark_t *param = NULL;
    text_t name;
    uint32 i, num;
    text_t num_text;

    *is_repeated = GS_FALSE;

    if (word->text.len >= 2 && word->text.str[0] == '$') {  // $parameter minimum length2
        /* using '$' as param identifier can only be followed with number */
        num_text.str = word->text.str + 1;
        num_text.len = word->text.len - 1;
        GS_RETURN_IFERR(cm_text2uint32(&num_text, &num)); /* here just checking whether it can be tranform */
    }
    if (word->text.len >= 2 && CHECK_PARAM_NAME_NEEDED(stmt)) {  // $parameter minimum length2
        *pnid = stmt->context->pname_count;                      // paramter name id
        for (i = 0; i < stmt->context->params->count; i++) {
            param = (sql_param_mark_t *)cm_galist_get(stmt->context->params, i);
            name.len = param->len;
            name.str = stmt->session->lex->text.str + param->offset - stmt->text_shift;

            if (cm_text_equal_ins(&name, &word->text.value)) {
                // parameter name is found
                *is_repeated = GS_TRUE;
                *pnid = param->pnid;
                break;
            }
        }

        // not found
        if (!(*is_repeated)) {
            stmt->context->pname_count++;
        }
    } else {
        *is_repeated = GS_FALSE;
        *pnid = stmt->context->pname_count;
        stmt->context->pname_count++;
    }

    if (cm_galist_new(stmt->context->params, sizeof(sql_param_mark_t), (void **)&param) != GS_SUCCESS) {
        return GS_ERROR;
    }

    param->offset = LEX_OFFSET(stmt->session->lex, word) + stmt->text_shift;
    param->len = word->text.len;
    param->pnid = *pnid;
    return GS_SUCCESS;
}

static status_t sql_word2csrparam(sql_stmt_t *stmt, word_t *word, expr_node_t *node)
{
    if (!(stmt->context->type < SQL_TYPE_DML_CEIL)) {
        GS_SRC_THROW_ERROR(word->loc, ERR_SQL_SYNTAX_ERROR, "cursor sharing param only allowed in dml");
        return GS_ERROR;
    }

    node->value.is_null = GS_FALSE;
    node->value.type = GS_TYPE_INTEGER;
    VALUE(uint32, &node->value) = stmt->context->csr_params->count;
    GS_RETURN_IFERR(cm_galist_insert(stmt->context->csr_params, node));
    return GS_SUCCESS;
}

static status_t sql_word2param(sql_stmt_t *stmt, word_t *word, expr_node_t *node)
{
    uint32 param_id;
    bool32 is_repeated = GS_FALSE;
    if (IS_DDL(stmt) || IS_DCL(stmt)) {
        GS_SRC_THROW_ERROR(word->loc, ERR_SQL_SYNTAX_ERROR, "param only allowed in dml or anonymous block or call");
        return GS_ERROR;
    }
    if (stmt->context->params == NULL) {
        GS_SRC_THROW_ERROR(word->loc, ERR_SQL_SYNTAX_ERROR, "Current position cannot use params");
        return GS_ERROR;
    }

    node->value.is_null = GS_FALSE;
    node->value.type = GS_TYPE_INTEGER;
    VALUE(uint32, &node->value) = stmt->context->params->count;

    GS_RETURN_IFERR(sql_add_param_mark(stmt, word, &is_repeated, &param_id));

    knl_panic(stmt->context->type != SQL_TYPE_ANONYMOUS_BLOCK);

    return GS_SUCCESS;
}

static status_t sql_word2column(sql_stmt_t *stmt, expr_tree_t *expr, word_t *word, expr_node_t *node)
{
    lex_t *lex = stmt->session->lex;

    node->value.type = GS_TYPE_COLUMN;
    if (sql_word_as_column(stmt, word, &node->word) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return lex_try_fetch_subscript(lex, &node->word.column.ss_start, &node->word.column.ss_end);
}

static status_t sql_word2reserved(expr_tree_t *expr, word_t *word, expr_node_t *node)
{
    node->value.type = GS_TYPE_INTEGER;
    node->value.v_res.res_id = word->id;
    node->value.v_res.namable = word->namable;
    return GS_SUCCESS;
}

static status_t sql_convert_expr_word(sql_stmt_t *stmt, expr_tree_t *expr, word_t *word, expr_node_t *node)
{
    switch (word->type) {
        case WORD_TYPE_STRING:
            return sql_word2text(stmt, word, node);

        case WORD_TYPE_NUMBER:
            return sql_word2number(word, node);

        case WORD_TYPE_PARAM:
            return sql_word2param(stmt, word, node);

        case WORD_TYPE_ALPHA_PARAM:
            return sql_word2csrparam(stmt, word, node);

        case WORD_TYPE_RESERVED:
            GS_RETURN_IFERR(sql_word2reserved(expr, word, node));
            return word->namable ? sql_word2column(stmt, expr, word, node) : GS_SUCCESS;

        case WORD_TYPE_VARIANT:
        case WORD_TYPE_DQ_STRING:
        case WORD_TYPE_JOIN_COL:
            if (stmt->context->type >= SQL_TYPE_CREATE_PROC && stmt->context->type < SQL_TYPE_PL_CEIL_END) {
                knl_panic(0);
            }
            return sql_word2column(stmt, expr, word, node);

        case WORD_TYPE_KEYWORD:
        case WORD_TYPE_DATATYPE:
            /* when used as variant */
            if (stmt->context->type >= SQL_TYPE_CREATE_PROC && stmt->context->type < SQL_TYPE_PL_CEIL_END &&
                word->namable == GS_TRUE) {
                knl_panic(0);
            }
            return sql_word2column(stmt, expr, word, node);

        case WORD_TYPE_PL_ATTR:
            knl_panic(0);

        case WORD_TYPE_PL_NEW_COL:
        case WORD_TYPE_PL_OLD_COL: {
            knl_panic(0);
            return GS_ERROR;
        }
        case WORD_TYPE_HEXADECIMAL:
            knl_panic(0);
            return GS_ERROR;

        default:
            GS_SRC_THROW_ERROR_EX(word->loc, ERR_SQL_SYNTAX_ERROR, "unexpected word %s found", W2S(word));
            return GS_ERROR;
    }
}
static inline status_t sql_parse_one_case_pair(sql_stmt_t *stmt, word_t *word, galist_t *case_pairs, bool32 is_cond)
{
    status_t status;
    case_pair_t *pair = NULL;

    if (cm_galist_new(case_pairs, sizeof(case_pair_t), (void **)&pair) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (is_cond) {
        status = sql_create_cond_until(stmt, &pair->when_cond, word);
    } else {
        status = sql_create_expr_until(stmt, &pair->when_expr, word);
    }

    if (status != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (word->id != KEY_WORD_THEN) {
        GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "THEN expected but %s found", W2S(word));
        return GS_ERROR;
    }

    if (sql_create_expr_until(stmt, &pair->value, word) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static inline status_t sql_parse_case_pairs(sql_stmt_t *stmt, word_t *word, galist_t *case_pairs, bool32 is_cond)
{
    for (;;) {
        if (sql_parse_one_case_pair(stmt, word, case_pairs, is_cond) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (!(word->id == KEY_WORD_WHEN || word->id == KEY_WORD_ELSE || word->id == KEY_WORD_END)) {
            GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "WHEN/ELSE/END expected but %s found",
                W2S(word));
            return GS_ERROR;
        }

        if (word->id == KEY_WORD_ELSE || word->id == KEY_WORD_END) {
            break;
        }
    }
    return GS_SUCCESS;
}
static inline status_t sql_parse_case_default_expr(sql_stmt_t *stmt, word_t *word, expr_tree_t **default_expr)
{
    if (word->id == KEY_WORD_ELSE) {
        if (sql_create_expr_until(stmt, default_expr, word) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (word->id != KEY_WORD_END) {
            GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "THEN expected but %s found", W2S(word));
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}
status_t sql_parse_case_expr(sql_stmt_t *stmt, word_t *word, expr_node_t *node)
{
    lex_t *lex = stmt->session->lex;
    key_word_t *save_key_words = lex->key_words;
    uint32 save_key_word_count = lex->key_word_count;
    bool32 is_cond = GS_FALSE;
    case_expr_t *case_expr = NULL;
    key_word_t key_words[] = { { (uint32)KEY_WORD_END, GS_FALSE, { (char *)"end", 3 } },
                               { (uint32)KEY_WORD_WHEN, GS_FALSE, { (char *)"when", 4 } }
                             };

    node->type = EXPR_NODE_CASE;
    if (sql_alloc_mem(stmt->context, sizeof(case_expr_t), (void **)&case_expr) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (lex_try_fetch(stmt->session->lex, "WHEN", &is_cond) != GS_SUCCESS) {
        return GS_SUCCESS;
    }

    cm_galist_init(&case_expr->pairs, (void *)stmt->context, (ga_alloc_func_t)sql_alloc_mem);
    case_expr->is_cond = is_cond;

    lex->key_words = key_words;
    lex->key_word_count = ELEMENT_COUNT(key_words);

    if (!is_cond) {
        if (sql_create_expr_until(stmt, &case_expr->expr, word) != GS_SUCCESS) {
            lex->key_words = save_key_words;
            lex->key_word_count = save_key_word_count;
            return GS_ERROR;
        }

        if (word->id != KEY_WORD_WHEN) {
            lex->key_words = save_key_words;
            lex->key_word_count = save_key_word_count;
            GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "WHEN expected but %s found", W2S(word));
            return GS_ERROR;
        }
    }

    if (sql_parse_case_pairs(stmt, word, &case_expr->pairs, is_cond) != GS_SUCCESS) {
        lex->key_words = save_key_words;
        lex->key_word_count = save_key_word_count;
        return GS_ERROR;
    }

    if (sql_parse_case_default_expr(stmt, word, &case_expr->default_expr) != GS_SUCCESS) {
        lex->key_words = save_key_words;
        lex->key_word_count = save_key_word_count;
        return GS_ERROR;
    }

    VALUE(pointer_t, &node->value) = case_expr;
    lex->key_words = save_key_words;
    lex->key_word_count = save_key_word_count;

    return GS_SUCCESS;
}

static status_t sql_create_expr_node(sql_stmt_t *stmt, expr_tree_t *expr, word_t *word, expr_node_type_t node_type,
                                     expr_node_t **node)
{
    GS_RETURN_IFERR(sql_stack_safe(stmt));

    if (sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)node) != GS_SUCCESS) {
        return GS_ERROR;
    }

    (*node)->owner = expr;
    (*node)->type = (word->type == WORD_TYPE_JOIN_COL) ? EXPR_NODE_JOIN : node_type;
    (*node)->unary = expr->unary;
    (*node)->loc = word->text.loc;
    (*node)->dis_info.need_distinct = GS_FALSE;
    (*node)->dis_info.idx = GS_INVALID_ID32;
    (*node)->optmz_info = (expr_optmz_info_t){ OPTMZ_NONE, 0 };
    (*node)->format_json = GS_FALSE;
    (*node)->json_func_attr = (json_func_attr_t){ 0, 0 };
    (*node)->typmod.is_array = 0;
    (*node)->value.v_col.ss_start = GS_INVALID_ID32;
    (*node)->value.v_col.ss_end = GS_INVALID_ID32;

    if (word->type == WORD_TYPE_DATATYPE && (word->id == DTYP_DATE || word->id == DTYP_TIMESTAMP)) {
        bool32 result = GS_FALSE;
        GS_RETURN_IFERR(sql_try_parse_date_expr(stmt, word, *node, &result));
        GS_RETSUC_IFTRUE(result);
    }

    if (node_type <= EXPR_NODE_OPCEIL) {
        return GS_SUCCESS;
    }

    if (node_type == EXPR_NODE_NEGATIVE) {
        word->flag_type = (uint32)word->flag_type ^ (uint32)WORD_FLAG_NEGATIVE;
        return GS_SUCCESS;
    }

    if (node_type == EXPR_NODE_FUNC) {
        GS_RETURN_IFERR(sql_build_func_node(stmt, word, *node));
        // to support analytic function
        GS_RETURN_IFERR(sql_build_func_over(stmt, expr, word, node));

        return GS_SUCCESS;
    }

    if (node_type == EXPR_NODE_CASE) {
        return GS_ERROR;
    }

    if (node_type == EXPR_NODE_ARRAY) {
        return GS_ERROR;
    }

    if (word->type == WORD_TYPE_DATATYPE && word->id == DTYP_INTERVAL) {
        bool32 result = GS_FALSE;
        GS_RETURN_IFERR(sql_try_parse_interval_expr(stmt, *node, &result));
        GS_RETSUC_IFTRUE(result);
    }

    return sql_convert_expr_word(stmt, expr, word, *node);
}

status_t sql_add_expr_word_inside(sql_stmt_t *stmt, expr_tree_t *expr, word_t *word, expr_node_type_t node_type)
{
    expr_node_t *node = NULL;
    expr_tree_t *sub_expr = NULL;
    if (word->type == (uint32)WORD_TYPE_BRACKET) {
        if (sql_create_expr_from_text(stmt, &word->text, &sub_expr, word->flag_type) != GS_SUCCESS) {
            return GS_ERROR;
        }
 
        node = sub_expr->root;
 
        if (expr->chain.count > 0 &&
            (expr->chain.last->type == EXPR_NODE_NEGATIVE || expr->chain.last->type == EXPR_NODE_PRIOR) &&
            word->type != WORD_TYPE_OPERATOR) {
            expr->chain.last->right = node;
        } else {
            APPEND_CHAIN(&expr->chain, node);
            UNARY_REDUCE_NEST(expr, node);
        }
    } else {
        if (sql_create_expr_node(stmt, expr, word, node_type, &node) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (expr->chain.count > 0 &&
            (expr->chain.last->type == EXPR_NODE_NEGATIVE || expr->chain.last->type == EXPR_NODE_PRIOR) &&
            word->type != WORD_TYPE_OPERATOR) {
            expr->chain.last->right = node;
        } else {
            APPEND_CHAIN(&expr->chain, node);
        }
    }
    return GS_SUCCESS;
}

status_t sql_add_expr_word(sql_stmt_t *stmt, expr_tree_t *expr, word_t *word)
{
    expr_node_type_t node_type;

    if (word->type == WORD_TYPE_ANCHOR) {
        return GS_ERROR;
    }

    if ((expr->expecting & EXPR_EXPECT_UNARY_OP) && EXPR_IS_UNARY_OP_ROOT(word)) {
        expr->expecting = EXPR_EXPECT_VAR;
        return GS_ERROR;
    }

    if ((expr->expecting & EXPR_EXPECT_UNARY_OP) && EXPR_IS_UNARY_OP(word)) {
        if (word->id == (uint32)OPER_TYPE_ADD) {
            expr->expecting = EXPR_EXPECT_VAR;
            return GS_SUCCESS;
        }
        expr->expecting = EXPR_EXPECT_UNARY;
    }

    if (!sql_match_expected(expr, word, &node_type)) {
        GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "the word \"%s\" is not correct", W2S(word));
        return GS_ERROR;
    }

    if (sql_add_expr_word_inside(stmt, expr, word, node_type) != GS_SUCCESS) {
        return GS_ERROR;
    }

    expr->unary = UNARY_OPER_NONE;
    return GS_SUCCESS;
}

status_t sql_create_expr(sql_stmt_t *stmt, expr_tree_t **expr)
{
    if (sql_alloc_mem(stmt->context, sizeof(expr_tree_t), (void **)expr) != GS_SUCCESS) {
        return GS_ERROR;
    }

    (*expr)->owner = stmt->context;
    (*expr)->expecting = (EXPR_EXPECT_UNARY_OP | EXPR_EXPECT_VAR | EXPR_EXPECT_STAR);
    (*expr)->next = NULL;

    return GS_SUCCESS;
}

static status_t sql_build_star_expr(sql_stmt_t *stmt, expr_tree_t *expr, word_t *word)
{
    lex_t *lex = stmt->session->lex;

    if (expr->chain.count > 0) {
        GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "expression expected but %s found", W2S(word));
        return GS_ERROR;
    }

    if (sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)&expr->root) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (sql_word_as_column(stmt, word, &expr->root->word) != GS_SUCCESS) {
        return GS_ERROR;
    }

    expr->root->type = EXPR_NODE_STAR;
    expr->root->loc = word->text.loc;
    expr->star_loc.begin = word->ori_type == WORD_TYPE_DQ_STRING ? LEX_OFFSET(lex, word) - 1 : LEX_OFFSET(lex, word);

    return lex_fetch(lex, word);
}

status_t sql_create_expr_until(sql_stmt_t *stmt, expr_tree_t **expr, word_t *word)
{
    lex_t *lex = stmt->session->lex;
    word_type_t last_type;
    uint32 save_flags = stmt->session->lex->flags;

    word->flag_type = WORD_FLAG_NONE;
    last_type = WORD_TYPE_OPERATOR;

    GS_RETURN_IFERR(sql_create_expr(stmt, expr));

    GS_RETURN_IFERR(lex_skip_comments(lex, NULL));

    (*expr)->loc = LEX_LOC;

    for (;;) {
        if ((*expr)->expecting == EXPR_EXPECT_OPER) {
            stmt->session->lex->flags &= (~LEX_WITH_ARG);
        } else {
            stmt->session->lex->flags = save_flags;
        }

        GS_RETURN_IFERR(lex_fetch(stmt->session->lex, word));
        GS_BREAK_IF_TRUE(word->type == WORD_TYPE_EOF);

        if ((IS_SPEC_CHAR(word, '*') && last_type == WORD_TYPE_OPERATOR) || word->type == WORD_TYPE_STAR) {
            return sql_build_star_expr(stmt, *expr, word);
        }

        GS_BREAK_IF_TRUE((IS_UNNAMABLE_KEYWORD(word) && word->id != KEY_WORD_CASE) || IS_SPEC_CHAR(word, ',') ||
                         (word->type == WORD_TYPE_COMPARE) || (word->type == WORD_TYPE_PL_TERM) ||
                         (word->type == WORD_TYPE_PL_RANGE));

        GS_BREAK_IF_TRUE((word->type == WORD_TYPE_VARIANT || word->type == WORD_TYPE_JOIN_COL ||
                          word->type == WORD_TYPE_STRING || word->type == WORD_TYPE_KEYWORD ||
                          word->type == WORD_TYPE_DATATYPE || word->type == WORD_TYPE_DQ_STRING ||
                          word->type == WORD_TYPE_FUNCTION || word->type == WORD_TYPE_RESERVED) &&
                         last_type != WORD_TYPE_OPERATOR);

        if (word->id == KEY_WORD_PRIMARY) {
            bool32 ret;
            GS_RETURN_IFERR(lex_try_fetch(lex, "KEY", &ret));

            // KEY WORD NOT VARIANT.
            GS_BREAK_IF_TRUE(ret);
        }

        last_type = word->type;

        GS_RETURN_IFERR(sql_add_expr_word(stmt, *expr, word));
    }

    GS_RETURN_IFERR(sql_generate_expr(*expr));

    stmt->session->lex->flags = save_flags;

    return GS_SUCCESS;
}

static status_t sql_parse_select_expr(sql_stmt_t *stmt, expr_tree_t *expr, sql_text_t *sql)
{
    sql_select_t *select_ctx = NULL;

    if (stmt->ssa_stack.depth == 0) {
        GS_SRC_THROW_ERROR(stmt->session->lex->loc, ERR_UNEXPECTED_KEY, "SUBSELECT");
        return GS_ERROR;
    }

    if (sql_create_select_context(stmt, sql, SELECT_AS_VARIANT, &select_ctx) != GS_SUCCESS) {
        return GS_ERROR;
    }

    expr->generated = GS_TRUE;
    if (sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)&expr->root) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (sql_array_put(SQL_CURR_SSA(stmt), select_ctx) != GS_SUCCESS) {
        return GS_ERROR;
    }

    select_ctx->parent = SQL_CURR_NODE(stmt);
    expr->root->type = EXPR_NODE_SELECT;
    expr->root->value.type = GS_TYPE_INTEGER;
    expr->root->value.v_obj.id = SQL_CURR_SSA(stmt)->count - 1;
    expr->root->value.v_obj.ptr = select_ctx;
    return GS_SUCCESS;
}

static status_t sql_parse_normal_expr(sql_stmt_t *stmt, expr_tree_t *expr, word_t *word)
{
    while (word->type != WORD_TYPE_EOF) {
        if (sql_add_expr_word(stmt, expr, word) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (lex_fetch(stmt->session->lex, word) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (sql_generate_expr(expr) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t sql_create_expr_from_text(sql_stmt_t *stmt, sql_text_t *text, expr_tree_t **expr, word_flag_t flag_type)
{
    word_t word;
    lex_t *lex = stmt->session->lex;
    status_t status;
    const char *words[] = { "UNION", "MINUS", "EXCEPT", "INTERSECT" };
    const uint32 words_count = sizeof(words) / sizeof(char *);
    bool32 result = GS_FALSE;

    word.flag_type = flag_type;
    *expr = NULL;

    GS_RETURN_IFERR(sql_stack_safe(stmt));

    GS_RETURN_IFERR(lex_push(lex, text));

    if (sql_create_expr(stmt, expr) != GS_SUCCESS) {
        lex_pop(lex);
        return GS_ERROR;
    }

    if (lex_fetch(lex, &word) != GS_SUCCESS) {
        lex_pop(lex);
        return GS_ERROR;
    }

    LEX_SAVE(lex);
    // Judge whether the next word is UNION/MINUS/EXCEPT/INTERSECT.
    if (lex_try_fetch_anyone(lex, words_count, words, &result) != GS_SUCCESS) {
        lex_pop(lex);
        return GS_ERROR;
    }
    LEX_RESTORE(lex);

    if (result || word.id == KEY_WORD_SELECT || word.id == KEY_WORD_WITH) {
        word.text = *text;
        status = sql_parse_select_expr(stmt, *expr, &word.text);
    } else {
        status = sql_parse_normal_expr(stmt, *expr, &word);
    }

    lex_pop(lex);

    return status;
}

status_t sql_create_expr_from_word(sql_stmt_t *stmt, word_t *word, expr_tree_t **expr)
{
    if (sql_create_expr(stmt, expr) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return sql_add_expr_word(stmt, *expr, word);
}

static void sql_down_expr_node(expr_tree_t *expr, expr_node_t *node)
{
    node->left = node->prev;
    node->right = node->next;

    node->next = node->next->next;
    node->prev = node->prev->prev;

    if (node->prev != NULL) {
        node->prev->next = node;
    } else {
        expr->chain.first = node;
    }

    if (node->next != NULL) {
        node->next->prev = node;
    } else {
        expr->chain.last = node;
    }

    node->left->prev = NULL;
    node->left->next = NULL;
    node->right->prev = NULL;
    node->right->next = NULL;

    expr->chain.count -= 2;
}

static status_t sql_form_expr_with_opers(expr_tree_t *expr, uint32 opers)
{
    expr_node_t *prev = NULL;
    expr_node_t *next = NULL;
    expr_node_t *node;

    /* get next expr node ,merge node is needed at least two node */
    node = expr->chain.first->next;

    while (node != NULL) {
        if (node->type >= EXPR_NODE_CONST || node->left != NULL ||
            (IS_OPER_NODE(node) && g_opr_priority[node->type] != g_opr_priority[opers])) {
            node = node->next;
            continue;
        }

        prev = node->prev;
        next = node->next;

        /* if is not a correct expression */
        if (prev == NULL || next == NULL) {
            GS_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "expression error");
            return GS_ERROR;
        }

        sql_down_expr_node(expr, node);

        node = node->next;
    }

    return GS_SUCCESS;
}

status_t sql_generate_expr(expr_tree_t *expr)
{
    if (expr->chain.count == 0) {
        GS_SRC_THROW_ERROR(expr->loc, ERR_SQL_SYNTAX_ERROR, "invalid expression");
        return GS_ERROR;
    }

    for (uint32 oper_mode = OPER_TYPE_MUL; oper_mode <= OPER_TYPE_CAT; ++oper_mode) {
        if (sql_form_expr_with_opers(expr, oper_mode) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (expr->chain.count != 1) {
        GS_SRC_THROW_ERROR(expr->loc, ERR_SQL_SYNTAX_ERROR, "expression error");
        return GS_ERROR;
    }

    expr->generated = GS_TRUE;
    expr->root = expr->chain.first;
    return GS_SUCCESS;
}
status_t sql_check_privs_duplicated(galist_t *priv_list, const text_t *priv_str, priv_type_def priv_type)
{
    uint32 i;
    knl_priv_def_t *priv = NULL;

    for (i = 0; i < priv_list->count; i++) {
        priv = (knl_priv_def_t *)cm_galist_get(priv_list, i);
        if (cm_text_equal_ins(&priv->priv_name, priv_str)) {
            return GS_ERROR;
        }

        if (priv->priv_type == PRIV_TYPE_ALL_PRIV || priv_type == PRIV_TYPE_ALL_PRIV) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t sql_check_duplicate_holders(galist_t *holders, const text_t *hold_name)
{
    uint32 i;
    knl_holders_def_t *holder = NULL;

    for (i = 0; i < holders->count; i++) {
        holder = (knl_holders_def_t *)cm_galist_get(holders, i);
        if (cm_text_equal(&holder->name, hold_name)) {
            GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "user or role %s is already exists", T2S(hold_name));
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t sql_parse_priv_type(sql_stmt_t *stmt, priv_info *priv, priv_type_def *priv_type, uint32 *priv_id)
{
    uint32 rid;
    sys_privs_id spid;
    obj_privs_id opid;
    user_privs_id upid;

    if (cm_text_str_equal_ins(&priv->priv_name, "ALL") || cm_text_str_equal_ins(&priv->priv_name, "ALL PRIVILEGES")) {
        *priv_type = PRIV_TYPE_ALL_PRIV;
        *priv_id = (uint32)ALL_PRIVILEGES;
        return GS_SUCCESS;
    }

    if (knl_sys_priv_match(&priv->priv_name, &spid)) {
        *priv_type = PRIV_TYPE_SYS_PRIV;
        *priv_id = (uint32)spid;
        return GS_SUCCESS;
    }

    if (knl_obj_priv_match(&priv->priv_name, &opid)) {
        *priv_type = PRIV_TYPE_OBJ_PRIV;
        *priv_id = (uint32)opid;
        return GS_SUCCESS;
    }

    if (knl_user_priv_match(&priv->priv_name, &upid)) {
        *priv_type = PRIV_TYPE_USER_PRIV;
        *priv_id = (uint32)upid;
        return GS_SUCCESS;
    }

    if (knl_get_role_id(&stmt->session->knl_session, &priv->priv_name, &rid)) {
        *priv_type = PRIV_TYPE_ROLE;
        *priv_id = rid;
        return GS_SUCCESS;
    }

    GS_SRC_THROW_ERROR_EX(priv->start_loc, ERR_SQL_SYNTAX_ERROR, "invalid privilege or role name");

    return GS_ERROR;
}

status_t sql_parse_priv_name(sql_stmt_t *stmt, word_t *word, galist_t *privs, priv_info *priv)
{
    knl_priv_def_t *priv_def = NULL;
    priv_type_def priv_type;
    uint32 priv_id;
    status_t status;

    if (priv->priv_name.len == 0) {
        GS_SRC_THROW_ERROR_EX(word->loc, ERR_SQL_SYNTAX_ERROR, "missing or invalid privilege");
        return GS_ERROR;
    }

    status = sql_parse_priv_type(stmt, priv, &priv_type, &priv_id);
    GS_RETURN_IFERR(status);

    if (sql_check_privs_duplicated(privs, &priv->priv_name, priv_type) != GS_SUCCESS) {
        GS_SRC_THROW_ERROR_EX(priv->start_loc, ERR_SQL_SYNTAX_ERROR, "duplicate privilege listed");
        return GS_ERROR;
    }

    status = cm_galist_new(privs, sizeof(knl_priv_def_t), (pointer_t *)&priv_def);
    GS_RETURN_IFERR(status);

    status = sql_copy_name(stmt->context, &priv->priv_name, &priv_def->priv_name);
    GS_RETURN_IFERR(status);

    priv_def->priv_id = priv_id;
    priv_def->priv_type = priv_type;
    /* can not check the priv_type now because we do not known the privilege is system privilege type or object
    privilege type yet. so we save the privilege name location for sql_check_privs_type */
    priv_def->start_loc = priv->start_loc;
    return GS_SUCCESS;
}

status_t sql_parse_objpriv_column(knl_grant_def_t *def)
{
    return GS_SUCCESS;
}

static status_t sql_try_parse_special_privs(lex_t *lex, word_t *word, priv_info *priv, bool32 *reserved)
{
    bool32 result = GS_FALSE;

    *reserved = GS_FALSE;
    if (word->id == KEY_WORD_ON) {
        GS_RETURN_IFERR(lex_try_fetch2(lex, "COMMIT", "REFRESH", &result));
        if (result) {
            /* continue parse a privilege name */
            if (priv->priv_name.len > 0) {
                CM_TEXT_APPEND(&priv->priv_name, ' ');
            } else {
                priv->start_loc = word->loc;
            }

            text_t priv_name = { "ON COMMIT REFRESH", 17 };
            cm_concat_text_upper(&priv->priv_name, &priv_name);
            return lex_expected_fetch(lex, word);
        } else {
            *reserved = GS_TRUE;
        }
    }
    return GS_SUCCESS;
}

static status_t sql_try_parse_dir_privs(lex_t *lex, word_t *word, priv_info *priv, bool32 *dire_priv)
{
    bool32 result = GS_FALSE;

    if (word->id == KEY_WORD_ON) {
        GS_RETURN_IFERR(lex_try_fetch(lex, "DIRECTORY", &result));
        if (result) {
            if (priv->priv_name.len > 0) {
                CM_TEXT_APPEND(&priv->priv_name, ' ');
            } else {
                priv->start_loc = word->loc;
            }

            text_t priv_name = { "ON DIRECTORY", 12 };
            cm_concat_text_upper(&priv->priv_name, &priv_name);
            *dire_priv = GS_TRUE;
        }
    }

    return GS_SUCCESS;
}

static status_t sql_try_parse_user_privs(lex_t *lex, word_t *word, priv_info *priv, bool32 *user_priv)
{
    bool32 result = GS_FALSE;

    if (word->id == KEY_WORD_ON) {
        GS_RETURN_IFERR(lex_try_fetch(lex, "USER", &result));
        if (result) {
            *user_priv = GS_TRUE;
        }
    }

    return GS_SUCCESS;
}

status_t sql_parse_privs(sql_stmt_t *stmt, galist_t *privs, priv_type_def *priv_type)
{
    uint32 kid;
    bool32 dire_priv = GS_FALSE;
    bool32 user_priv = GS_FALSE;
    bool32 reserved = GS_FALSE;
    word_t word;
    lex_t *lex = stmt->session->lex;

    priv_info priv = { { NULL, 0 }, { 0, 0 } };

    GS_RETURN_IFERR(sql_alloc_mem(stmt->context, GS_NAME_BUFFER_SIZE, (void **)&priv.priv_name.str));

    GS_RETURN_IFERR(lex_expected_fetch(lex, &word));

    kid = stmt->context->type == SQL_TYPE_GRANT ? KEY_WORD_TO : KEY_WORD_FROM;
    while (word.id != kid) {
        GS_RETURN_IFERR(sql_try_parse_dir_privs(lex, &word, &priv, &dire_priv));
        if (word.id == kid || dire_priv) {
            break;
        }

        GS_RETURN_IFERR(sql_try_parse_user_privs(lex, &word, &priv, &user_priv));
        if (word.id == kid || user_priv) {
            break;
        }

        GS_RETURN_IFERR(sql_try_parse_special_privs(lex, &word, &priv, &reserved));
        if (word.id == kid || reserved) {
            break;
        }

        if (IS_SPEC_CHAR(&word, ',')) {
            /* find an entire privilege name */
            GS_RETURN_IFERR(sql_parse_priv_name(stmt, &word, privs, &priv));
            CM_TEXT_CLEAR(&priv.priv_name);
            priv.start_loc.column = 0;
            priv.start_loc.line = 0;
        } else {
            /* continue parse a privilege name */
            if (priv.priv_name.len > 0) {
                CM_TEXT_APPEND(&priv.priv_name, ' ');
            } else {
                priv.start_loc = word.loc;
            }

            if (priv.priv_name.len + word.text.value.len >= GS_NAME_BUFFER_SIZE) {
                GS_SRC_THROW_ERROR(word.loc, ERR_BUFFER_OVERFLOW, priv.priv_name.len + word.text.value.len,
                                   GS_NAME_BUFFER_SIZE);
                return GS_ERROR;
            }

            cm_concat_text_upper(&priv.priv_name, &word.text.value);
        }

        GS_RETURN_IFERR(lex_expected_fetch(lex, &word));
    }

    *priv_type = (word.id == KEY_WORD_ON) ? PRIV_TYPE_OBJ_PRIV : PRIV_TYPE_SYS_PRIV;

    if (user_priv) {
        *priv_type = PRIV_TYPE_USER_PRIV;
    }

    /* parse the last privilege name before on/to key word */
    return sql_parse_priv_name(stmt, &word, privs, &priv);
}

status_t sql_check_privs_type(sql_stmt_t *stmt, galist_t *privs, priv_type_def priv_type, object_type_t objtype,
                              text_t *typename)
{
    uint32 i;
    knl_priv_def_t *priv_def = NULL;

    for (i = 0; i < privs->count; i++) {
        priv_def = cm_galist_get(privs, i);
        if (priv_def->priv_type == PRIV_TYPE_ALL_PRIV) {
            continue;
        }

        if (priv_type == PRIV_TYPE_USER_PRIV) {
            if (priv_def->priv_type != PRIV_TYPE_USER_PRIV) {
                GS_SRC_THROW_ERROR_EX(priv_def->start_loc, ERR_SQL_SYNTAX_ERROR, "invalid privilege");
                return GS_ERROR;
            }
            continue;
        }

        if (priv_type == PRIV_TYPE_SYS_PRIV &&
            !(priv_def->priv_type == PRIV_TYPE_SYS_PRIV || priv_def->priv_type == PRIV_TYPE_ROLE)) {
            GS_SRC_THROW_ERROR_EX(priv_def->start_loc, ERR_SQL_SYNTAX_ERROR, "invalid privilege");
            return GS_ERROR;
        }

        if (priv_type == PRIV_TYPE_OBJ_PRIV) {
            if (priv_def->priv_type != PRIV_TYPE_OBJ_PRIV) {
                GS_SRC_THROW_ERROR_EX(priv_def->start_loc, ERR_SQL_SYNTAX_ERROR, "invalid privilege");
                return GS_ERROR;
            } else {
                /* check priv by object type
                e.g. grant select privilege on function to a user is invalid */
                if (knl_check_obj_priv_scope(priv_def->priv_id, objtype) != GS_SUCCESS) {
                    GS_SRC_THROW_ERROR_EX(priv_def->start_loc, ERR_SQL_SYNTAX_ERROR, "%s privilege not allowed for %s",
                                          T2S(&priv_def->priv_name), T2S_EX(typename));
                    return GS_ERROR;
                }
            }
        }
    }

    return GS_SUCCESS;
}

status_t sql_parse_grant_privs(sql_stmt_t *stmt, knl_grant_def_t *def)
{
    status_t status;

    status = sql_parse_privs(stmt, &def->privs, &def->priv_type);
    GS_RETURN_IFERR(status);

    if (def->priv_type == PRIV_TYPE_OBJ_PRIV) {
        status = sql_parse_objpriv_column(def);
    }

    return status;
}

status_t sql_parse_grant_option_def(lex_t *lex, knl_grant_def_t *def, word_t *word)
{
    uint32 i;
    knl_holders_def_t *grantee = NULL;

    /* with grant option ? */
    GS_RETURN_IFERR(lex_expected_fetch_word(lex, "GRANT"));
    GS_RETURN_IFERR(lex_expected_fetch_word(lex, "OPTION"));
    GS_RETURN_IFERR(lex_expected_end(lex));

    for (i = 0; i < def->grantees.count; i++) {
        grantee = cm_galist_get(&def->grantees, i);
        if (grantee->type == TYPE_ROLE) {
            GS_SRC_THROW_ERROR_EX(word->loc, ERR_SQL_SYNTAX_ERROR, "cannot GRANT to a role WITH GRANT OPTION");
            return GS_ERROR;
        }
    }

    def->grant_opt = 1;
    return GS_SUCCESS;
}

status_t sql_parse_holder_type(sql_stmt_t *stmt, word_t *word, knl_holders_def_t *holder)
{
    uint32 id;

    if (knl_get_user_id(&stmt->session->knl_session, &holder->name, &id)) {
        holder->type = TYPE_USER;
        return GS_SUCCESS;
    }

    if (knl_get_role_id(&stmt->session->knl_session, &holder->name, &id)) {
        holder->type = TYPE_ROLE;
        return GS_SUCCESS;
    }

    GS_SRC_THROW_ERROR_EX(word->loc, ERR_SQL_SYNTAX_ERROR, "user or role '%s' does not exist", T2S(&holder->name));
    return GS_ERROR;
}
bool32 sql_parse_holder_no_prefix_tenant(sql_stmt_t *stmt, word_t *word)
{
    uint32 id;
    text_t public_user = { PUBLIC_USER, (uint32)strlen(PUBLIC_USER) };
    if (knl_get_role_id(&stmt->session->knl_session, &word->text.value, &id)) {
        return GS_TRUE;
    }
    if (cm_text_equal_ins(&word->text.value, &public_user)) {
        return GS_TRUE;
    }
    return GS_FALSE;
}
status_t sql_parse_holder_check_name(sql_stmt_t *stmt, galist_t *list, word_t *word, sql_priv_check_t *priv_check,
                                     text_t *name)
{
    sql_copy_func_t sql_copy_func;
    if (IS_COMPATIBLE_MYSQL_INST) {
        sql_copy_func = sql_copy_name_cs;
    } else {
        sql_copy_func = sql_copy_name;
    }

    if (sql_parse_holder_no_prefix_tenant(stmt, word)) {
        sql_copy_name(stmt->context, &word->text.value, name);
    } else {
        GS_RETURN_IFERR(sql_copy_prefix_tenant(stmt, (text_t *)&word->text, name, sql_copy_func));
    }

    if (stmt->context->type == SQL_TYPE_REVOKE &&
        (cm_text_str_equal_ins(name, DBA_ROLE) ||
         (cm_text_str_equal_ins(name, SYS_USER_NAME) && priv_check->priv_type != PRIV_TYPE_OBJ_PRIV &&
          priv_check->priv_type != PRIV_TYPE_USER_PRIV))) {
        GS_THROW_ERROR(ERR_INVALID_REVOKEE, T2S_CASE(name, 0));
        return GS_ERROR;
    }

    return sql_check_duplicate_holders(list, name);
}

status_t sql_parse_holder(sql_stmt_t *stmt, galist_t *list, word_t *word, sql_priv_check_t *priv_check)
{
    text_t name;
    knl_holders_def_t *holder = NULL;
    status_t ret;

    GS_RETURN_IFERR(sql_parse_holder_check_name(stmt, list, word, priv_check, &name));

    GS_RETURN_IFERR(cm_galist_new(list, sizeof(knl_holders_def_t), (pointer_t *)&holder));

    holder->name = name;
    ret = sql_parse_holder_type(stmt, word, holder);
    if (ret == GS_ERROR) {
        cm_reset_error();
        GS_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
    }
    return ret;
}

status_t sql_parse_grantee_def(sql_stmt_t *stmt, lex_t *lex, knl_grant_def_t *def)
{
    word_t word;
    status_t status;
    bool32 grantee_expect = GS_TRUE;

    def->grant_opt = 0;
    def->admin_opt = 0;

    GS_RETURN_IFERR(lex_fetch(lex, &word));

    sql_priv_check_t priv_check;
    priv_check.objowner = &def->schema;
    priv_check.objname = &def->objname;
    priv_check.priv_list = &def->privs;
    priv_check.objtype = def->objtype;
    priv_check.priv_type = def->priv_type;

    while (word.type != WORD_TYPE_EOF && word.id != KEY_WORD_WITH) {
        /* got a grantee */
        if (!IS_SPEC_CHAR(&word, ',')) {
            if (grantee_expect) {
                status = sql_parse_holder(stmt, &def->grantees, &word, &priv_check);
                GS_RETURN_IFERR(status);
                grantee_expect = GS_FALSE;
            } else {
                GS_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, ", expected, but %s found", T2S(&word.text.value));
                return GS_ERROR;
            }
        } else {
            if (grantee_expect) {
                GS_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "grantee expected, but , found");
                return GS_ERROR;
            } else {
                grantee_expect = GS_TRUE;
            }
        }

        GS_RETURN_IFERR(lex_fetch(lex, &word));
    }

    if (grantee_expect) {
        GS_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "grantee expected, but %s found", T2S(&word.text.value));
        return GS_ERROR;
    }

    if (word.id == KEY_WORD_WITH) {
        GS_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "'with' not supported.");
        return GS_ERROR;
    }

    return status;
}

/*
 * @Note: if the caller wants to know if the owner(schema) was explicitly specified by user,
 * the caller should pass a pointer to a bool32 variable as the optional argument "owner_explict"
 * otherwise, a NULL is enough
 */
status_t sql_convert_object_name(sql_stmt_t *stmt, word_t *word, text_t *owner, bool32 *owner_explict, text_t *name)
{
    bool32 is_explict = GS_TRUE;
    sql_copy_func_t sql_copy_func;
    if (IS_COMPATIBLE_MYSQL_INST) {
        sql_copy_func = sql_copy_name_cs;
    } else {
        sql_copy_func = sql_copy_name;
    }

    if (word->ex_count == 1) {
        if (sql_copy_prefix_tenant(stmt, (text_t *)&word->text, owner, sql_copy_func) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (sql_copy_object_name(stmt->context, word->ex_words[0].type, (text_t *)&word->ex_words[0].text, name) !=
            GS_SUCCESS) {
            return GS_ERROR;
        }
    } else if (word->ex_count == 0) {
        cm_str2text(stmt->session->curr_schema, owner);
        is_explict = GS_FALSE;
        if (sql_copy_object_name(stmt->context, word->type, (text_t *)&word->text, name) != GS_SUCCESS) {
            return GS_ERROR;
        }
    } else {
        GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "invalid name");
        return GS_ERROR;
    }

    if (owner_explict != NULL) {
        *owner_explict = is_explict;
    }

    return GS_SUCCESS;
}

status_t sql_try_parse_if_not_exists(lex_t *lex, uint32 *options)
{
    bool32 result = GS_FALSE;

    if (lex_try_fetch(lex, "IF", &result) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (result) {
        if (lex_expected_fetch_word(lex, "NOT") != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (lex_expected_fetch_word(lex, "EXISTS") != GS_SUCCESS) {
            return GS_ERROR;
        }

        *options |= CREATE_IF_NOT_EXISTS;
    }

    return GS_SUCCESS;
}

status_t sql_try_parse_if_exists(lex_t *lex, uint32 *options)
{
    bool32 result = GS_FALSE;

    if (lex_try_fetch(lex, "IF", &result) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (result) {
        if (lex_expected_fetch_word(lex, "EXISTS") != GS_SUCCESS) {
            return GS_ERROR;
        }

        *options |= DROP_IF_EXISTS;
    }

    return GS_SUCCESS;
}

status_t sql_parse_drop_object(sql_stmt_t *stmt, knl_drop_def_t *def)
{
    word_t word;
    lex_t *lex = stmt->session->lex;
    lex->flags = LEX_WITH_OWNER;

    if (sql_try_parse_if_exists(lex, &def->options) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (lex_expected_fetch_variant(lex, &word) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (sql_convert_object_name(stmt, &word, &def->owner, NULL, &def->name) != GS_SUCCESS) {
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t sql_parse_pctfree(lex_t *lex, word_t *word, uint32 *pct_free)
{
    uint32 value;

    if (*pct_free != GS_INVALID_ID32) {
        GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, " duplicate pct_free specification");
        return GS_ERROR;
    }

    if (lex_expected_fetch_uint32(lex, &value) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (value > GS_PCT_FREE_MAX) {
        GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "%s must between 0 and 80 ", W2S(word));
        return GS_ERROR;
    }

    *pct_free = value;
    return GS_SUCCESS;
}

static status_t sql_parse_storage_maxsize(lex_t *lex, word_t *word, int64 *maxsize)
{
    status_t status;

    if ((*maxsize) > 0) {
        GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "duplicate storage option specification");
        return GS_ERROR;
    }

    LEX_SAVE(lex);

    status = lex_fetch(lex, word);
    GS_RETURN_IFERR(status);

    if (word->type == WORD_TYPE_KEYWORD) {
        if (word->id != KEY_WORD_UNLIMITED) {
            GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "invalid STORAGE option");
            return GS_ERROR;
        }
        *maxsize = GS_INVALID_INT64;
    } else {
        LEX_RESTORE(lex);
        status = lex_expected_fetch_size(lex, maxsize, GS_MIN_STORAGE_MAXSIZE, GS_MAX_STORAGE_MAXSIZE);
        GS_RETURN_IFERR(status);
    }

    return GS_SUCCESS;
}

static status_t sql_parse_storage_initial(lex_t *lex, word_t *word, int64 *initial)
{
    status_t status;

    if ((*initial) > 0) {
        GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "duplicate storage option specification");
        return GS_ERROR;
    }

    status = lex_expected_fetch_size(lex, initial, GS_MIN_STORAGE_INITIAL, GS_MAX_STORAGE_INITIAL);
    GS_RETURN_IFERR(status);

    return GS_SUCCESS;
}

static status_t sql_parse_storage_next(lex_t *lex, word_t *word, int64 *next)
{
    status_t status;

    if ((*next) > 0) {
        GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "duplicate storage option specification");
        return GS_ERROR;
    }

    status = lex_expected_fetch_size(lex, next, GS_INVALID_INT64, GS_INVALID_INT64);
    GS_RETURN_IFERR(status);

    return GS_SUCCESS;
}

static status_t sql_parse_storage_attr(lex_t *lex, word_t *word, knl_storage_def_t *storage_def, bool32 alter)
{
    status_t status;

    if ((storage_def->initial > 0) || (storage_def->next > 0) || (storage_def->maxsize > 0)) {
        GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "duplicate storage option specification");
        return GS_ERROR;
    }

    for (;;) {
        if (lex_fetch(lex, word) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (word->type == WORD_TYPE_EOF) {
            return GS_SUCCESS;
        }

        if (word->type != WORD_TYPE_KEYWORD) {
            GS_SRC_THROW_ERROR_EX(word->loc, ERR_SQL_SYNTAX_ERROR, "unexpected word %s found.", W2S(word));
            return GS_ERROR;
        }

        switch (word->id) {
            case KEY_WORD_INITIAL:
                if (alter) {
                    GS_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "INITIAL storage options");
                    return GS_ERROR;
                }
                status = sql_parse_storage_initial(lex, word, &storage_def->initial);
                GS_RETURN_IFERR(status);
                break;
            case KEY_WORD_NEXT:
                if (alter) {
                    GS_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "NEXT storage options");
                    return GS_ERROR;
                }
                status = sql_parse_storage_next(lex, word, &storage_def->next);
                GS_RETURN_IFERR(status);
                break;
            case KEY_WORD_MAXSIZE:
                status = sql_parse_storage_maxsize(lex, word, &storage_def->maxsize);
                GS_RETURN_IFERR(status);
                break;
            default:
                break;
        }
    }

    return GS_SUCCESS;
}

status_t sql_parse_storage(lex_t *lex, word_t *word, knl_storage_def_t *storage_def, bool32 alter)
{
    uint32 flags = lex->flags;
    lex->flags = LEX_SINGLE_WORD;

    GS_RETURN_IFERR(lex_expected_fetch_bracket(lex, word));
    if (word->text.len == 0) {
        GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "missing STORAGE option");
        return GS_ERROR;
    }

    GS_RETURN_IFERR(lex_push(lex, &word->text));
    if (sql_parse_storage_attr(lex, word, storage_def, alter) != GS_SUCCESS) {
        lex_pop(lex);
        return GS_ERROR;
    }

    lex_pop(lex);

    lex->flags = flags;
    return GS_SUCCESS;
}
status_t sql_parse_dbca_ctrlfiles(sql_stmt_t *stmt, knl_database_def_t *def, word_t *word)
{
    status_t status;
    text_t *file_name = NULL;
    lex_t *lex = stmt->session->lex;

    if (def->ctrlfiles.count != 0) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "CONTROLFILE is already defined");
        return GS_ERROR;
    }

    status = lex_expected_fetch_bracket(lex, word);
    if (status != GS_SUCCESS) {
        return status;
    }

    GS_RETURN_IFERR(lex_push(lex, &word->text));

    while (1) {
        if (lex_expected_fetch_string(lex, word) != GS_SUCCESS) {
            lex_pop(lex);
            return GS_ERROR;
        }

        if (cm_galist_new(&def->ctrlfiles, sizeof(text_t), (pointer_t *)&file_name) != GS_SUCCESS) {
            lex_pop(lex);
            return GS_ERROR;
        }

        if (sql_copy_file_name(stmt->context, (text_t *)&word->text, file_name) != GS_SUCCESS) {
            lex_pop(lex);
            return GS_ERROR;
        }

        if (lex_fetch(lex, word) != GS_SUCCESS) {
            lex_pop(lex);
            return GS_ERROR;
        }

        if (word->type == WORD_TYPE_EOF) {
            break;
        }

        if (!IS_SPEC_CHAR(word, ',')) {
            lex_pop(lex);
            GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "\",\" expected but %s found", W2S(word));
            return GS_ERROR;
        }
    }

    lex_pop(lex);

    return lex_fetch(lex, word);
}

status_t sql_parse_dbca_charset(sql_stmt_t *stmt, knl_database_def_t *def, word_t *word)
{
    lex_t *lex = stmt->session->lex;

    if (def->charset.len != 0) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "CHARACTER SET is already defined");
        return GS_ERROR;
    }

    if (lex_expected_fetch_word(lex, "SET") != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (lex_expected_fetch(lex, word) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (sql_copy_text(stmt->context, (text_t *)&word->text, &def->charset) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return lex_fetch(lex, word);
}

static status_t sql_try_parse_file_blocksize(lex_t *lex, int32 *blocksize)
{
    bool32 result = GS_FALSE;
    int64 size;

    if (lex_try_fetch(lex, "BLOCKSIZE", &result) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (result) {
        if (lex_expected_fetch_size(lex, &size, FILE_BLOCK_SIZE_512, FILE_BLOCK_SIZE_4096) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (size != FILE_BLOCK_SIZE_512 && size != FILE_BLOCK_SIZE_4096) {
            GS_THROW_ERROR(ERR_INVALID_PARAMETER, "BLOCKSIZE");
            return GS_ERROR;
        }
        *blocksize = (int32)size;
    }

    return GS_SUCCESS;
}

status_t sql_parse_dbca_logfiles(sql_stmt_t *stmt, galist_t *logfiles, word_t *word)
{
    status_t status;
    knl_device_def_t *log_file = NULL;
    lex_t *lex = stmt->session->lex;

    if (logfiles->count != 0) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "LOGFILE is already defined");
        return GS_ERROR;
    }

    status = lex_expected_fetch_bracket(lex, word);
    GS_RETURN_IFERR(status);

    GS_RETURN_IFERR(lex_push(lex, &word->text));

    while (GS_TRUE) {
        status = lex_expected_fetch_string(lex, word);
        GS_BREAK_IF_ERROR(status);

        status = cm_galist_new(logfiles, sizeof(knl_device_def_t), (pointer_t *)&log_file);
        GS_BREAK_IF_ERROR(status);

        status = sql_copy_file_name(stmt->context, (text_t *)&word->text, &log_file->name);
        GS_BREAK_IF_ERROR(status);

        status = lex_expected_fetch_word(lex, "SIZE");
        GS_BREAK_IF_ERROR(status);

        status = lex_expected_fetch_size(lex, &log_file->size, GS_INVALID_INT64, GS_INVALID_INT64);
        GS_BREAK_IF_ERROR(status);

        status = sql_try_parse_file_blocksize(lex, &log_file->block_size);
        GS_BREAK_IF_ERROR(status);

        status = lex_fetch(lex, word);
        GS_BREAK_IF_ERROR(status);

        if (word->type == WORD_TYPE_EOF) {
            break;
        }

        if (!IS_SPEC_CHAR(word, ',')) {
            GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "\",\" expected but %s found", W2S(word));
            status = GS_ERROR;
            break;
        }
    }

    lex_pop(lex);
    GS_RETURN_IFERR(status);

    return lex_fetch(lex, word);
}

static status_t sql_check_filesize(const text_t *space_name, knl_device_def_t *dev_def)
{
    int64 min_filesize;
    int64 max_filesize = (int64)g_instance->kernel.attr.page_size * GS_MAX_DATAFILE_PAGES;

    if (cm_text_equal(space_name, &g_system) || cm_text_equal(space_name, &g_undo)) {
        min_filesize = GS_MIN_SYSTEM_DATAFILE_SIZE;
    } else if (cm_text_equal(space_name, &g_sysaux)) {
        min_filesize = GS_MIN_SYSAUX_DATAFILE_SIZE;
    } else {
        min_filesize = GS_MIN_USER_DATAFILE_SIZE;
    }

    if (dev_def->size > max_filesize) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "size value is bigger than maximum(%llu) required", max_filesize);
        return GS_ERROR;
    }

    if (dev_def->size < min_filesize) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "size value is smaller than minimum(%llu) required", min_filesize);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t sql_parse_dbca_datafile_spec(sql_stmt_t *stmt, lex_t *lex, word_t *word, knl_space_def_t *space_def)
{
    status_t status;
    bool32 isRelative = GS_FALSE;
    knl_device_def_t *dev_def = NULL;

    while (1) {
        uint32 i;
        knl_device_def_t *cur = NULL;

        status = cm_galist_new(&space_def->datafiles, sizeof(knl_device_def_t), (pointer_t *)&dev_def);
        GS_RETURN_IFERR(status);

        status = sql_parse_datafile(stmt, dev_def, word, &isRelative);
        GS_RETURN_IFERR(status);

        /* prevent the duplicate datafile being passed to storage engine */
        for (i = 0; i < space_def->datafiles.count; i++) {
            cur = (knl_device_def_t *)cm_galist_get(&space_def->datafiles, i);
            if (cur != dev_def) {
                if (cm_text_equal_ins(&dev_def->name, &cur->name)) {
                    GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "it is not allowed to specify duplicate datafile");
                    return GS_ERROR;
                }
            }
        }

        status = sql_check_filesize(&space_def->name, dev_def);
        GS_RETURN_IFERR(status);

        if (word->type == WORD_TYPE_EOF) {
            break;
        }

        if (!IS_SPEC_CHAR(word, ',')) {
            break;
        }
    }

    if (word->id == KEY_WORD_ALL) {
        status = lex_expected_fetch_word(lex, "IN");
        GS_RETURN_IFERR(status);

        status = lex_expected_fetch_word(lex, "MEMORY");
        GS_RETURN_IFERR(status);

        space_def->in_memory = GS_TRUE;
        return lex_fetch(lex, word);
    } else {
        space_def->in_memory = GS_FALSE;
    }

    return GS_SUCCESS;
}

static status_t sql_parse_dbca_space(sql_stmt_t *stmt, knl_database_def_t *def, word_t *word)
{
    lex_t *lex = stmt->session->lex;
    knl_space_def_t *space_def = NULL;
    bool32 is_temp = GS_FALSE;
    status_t status;

    if (word->id == KEY_WORD_TEMPORARY) {
        knl_panic(stmt->context->type == SQL_TYPE_CREATE_DATABASE);
        dtc_node_def_t *node = cm_galist_get(&def->nodes, 0); /* single node goes here. */
        is_temp = GS_TRUE;
        space_def = &node->swap_space;
        space_def->name = g_swap;
    } else if (word->id == KEY_WORD_NO_LOGGING) {
        is_temp = GS_TRUE;
        bool32 result = GS_FALSE;
        status = lex_try_fetch(lex, "UNDO", &result);
        GS_RETURN_IFERR(status);
        if (result) {
            space_def = &def->temp_undo_space;
            space_def->name = g_temp_undo;
        } else {
            space_def = &def->temp_space;
            space_def->name = g_temp;
        }
    } else if (word->id == KEY_WORD_SYSTEM) {
        space_def = &def->system_space;
        space_def->name = g_system;
    } else if (word->id == KEY_WORD_UNDO) {
        knl_panic(stmt->context->type == SQL_TYPE_CREATE_DATABASE);
        dtc_node_def_t *node = cm_galist_get(&def->nodes, 0); /* single node goes here. */
        space_def = &node->undo_space;
        space_def->name = g_undo;
    } else if (word->id == KEY_WORD_SYSAUX) {
        space_def = &def->sysaux_space;
        space_def->name = g_sysaux;
    } else {
        space_def = &def->user_space;
        space_def->name = g_users;
    }

    if (space_def->datafiles.count != 0) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "%s tablesapce is already defined", W2S(word));
        return GS_ERROR;
    }

    status = lex_expected_fetch_word(lex, "TABLESPACE");
    GS_RETURN_IFERR(status);

    if (is_temp) {
        status = lex_expected_fetch_word(lex, "TEMPFILE");
        GS_RETURN_IFERR(status);
    } else {
        status = lex_expected_fetch_word(lex, "DATAFILE");
        GS_RETURN_IFERR(status);
    }

    return sql_parse_dbca_datafile_spec(stmt, lex, word, space_def);
}

static status_t sql_parse_config_ctrlfiles(sql_stmt_t *stmt, knl_database_def_t *def)
{
    status_t status = GS_ERROR;
    text_t files, name;
    text_t *file_name = NULL;
    char *value = cm_get_config_value(&g_instance->config, "CONTROL_FILES");

    if (CM_IS_EMPTY_STR(value)) {
        return GS_SUCCESS;
    }
    if (def->ctrlfiles.count > 0) {
        return GS_SUCCESS;
    }

    cm_str2text(value, &files);
    cm_remove_brackets(&files);

    while (GS_TRUE) {
        if (!cm_fetch_text(&files, ',', '\0', &name)) {
            status = GS_SUCCESS;
            break;
        }
        cm_trim_text(&name);
        if (name.str[0] == '\'') {
            name.str++;
            name.len -= 2;
            cm_trim_text(&name);
        }

        if (cm_galist_new(&def->ctrlfiles, sizeof(text_t), (pointer_t *)&file_name) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (sql_copy_file_name(stmt->context, &name, file_name) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (status != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, "CONTROL_FILES");
    }
    return status;
}

static status_t sql_try_set_files(sql_stmt_t *stmt, galist_t *files, const char *name, int32 count)
{
    char str[GS_FILE_NAME_BUFFER_SIZE];
    text_t *file_name = NULL;
    char file_path[GS_FILE_NAME_BUFFER_SIZE];

    if (files->count != 0) {
        return GS_SUCCESS;
    }

    for (int32 i = 1; i <= count; i++) {
        PRTS_RETURN_IFERR(snprintf_s(file_path, GS_FILE_NAME_BUFFER_SIZE, GS_FILE_NAME_BUFFER_SIZE - 1, "%s/data/%s%d",
                                     g_instance->home, name, i));
        if (realpath_file(file_path, str, GS_FILE_NAME_BUFFER_SIZE) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (cm_galist_new(files, sizeof(text_t), (void **)&file_name) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (sql_copy_str_safe(stmt->context, file_path, (uint32)strlen(file_path), file_name) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t sql_try_set_devices(sql_stmt_t *stmt, galist_t *devices, const char *name, int32 count, int64 size,
                                    int64 extend_size, int64 max_extend_size)
{
    char str[GS_FILE_NAME_BUFFER_SIZE];
    knl_device_def_t *dev = NULL;
    text_t src_text;
    char file_path[GS_FILE_NAME_BUFFER_SIZE];

    if (devices->count != 0) {
        return GS_SUCCESS;
    }

    for (int32 i = 1; i <= count; i++) {
        if (cm_galist_new(devices, sizeof(knl_device_def_t), (void **)&dev) != GS_SUCCESS) {
            return GS_ERROR;
        }

        dev->size = size;
        dev->autoextend.enabled = (extend_size != GS_INVALID_INT64) ? GS_TRUE : GS_FALSE;
        dev->autoextend.nextsize = extend_size;
        dev->autoextend.maxsize = max_extend_size;

        if (count > 1) {
            PRTS_RETURN_IFERR(snprintf_s(file_path, GS_FILE_NAME_BUFFER_SIZE, GS_FILE_NAME_BUFFER_SIZE - 1,
                                         "%s/data/%s%d", g_instance->home, name, i));
            if (realpath_file(file_path, str, GS_FILE_NAME_BUFFER_SIZE) != GS_SUCCESS) {
                return GS_ERROR;
            }
        } else {
            PRTS_RETURN_IFERR(snprintf_s(file_path, GS_FILE_NAME_BUFFER_SIZE, GS_FILE_NAME_BUFFER_SIZE - 1,
                                         "%s/data/%s", g_instance->home, name));
            if (realpath_file(file_path, str, GS_FILE_NAME_BUFFER_SIZE) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        cm_str2text_safe(file_path, (uint32)strlen(file_path), &src_text);
        if (sql_copy_file_name(stmt->context, &src_text, &dev->name) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t sql_set_database_default(sql_stmt_t *stmt, knl_database_def_t *def, bool32 clustered)
{
    galist_t *list = NULL;
    uint32 page_size;

    GS_RETURN_IFERR(sql_parse_config_ctrlfiles(stmt, def));

    GS_RETURN_IFERR(sql_try_set_files(stmt, &def->ctrlfiles, "ctrl", DEFAULT_CTRL_FILE_COUNT));

    GS_RETURN_IFERR(knl_get_page_size(KNL_SESSION(stmt), &page_size));

    list = &def->system_space.datafiles;
    if (sql_try_set_devices(stmt, list, "system", 1, DEFAULT_SYSTEM_SPACE_SIZE, DEFAULT_AUTOEXTEND_SIZE,
                            ((int64)GS_MAX_DATAFILE_PAGES * page_size)) != GS_SUCCESS) {
        return GS_ERROR;
    }

    dtc_node_def_t *node = NULL;

    /* log, undo and swap space must be specified explicitly for clustered database */
    for (uint32 i = 0; i < def->nodes.count && !clustered; i++) {
        node = cm_galist_get(&def->nodes, i);

        list = &node->logfiles;
        if (sql_try_set_devices(stmt, list, "redo", 3, DEFAULT_LOGFILE_SIZE, GS_INVALID_INT64,
                                ((int64)GS_MAX_DATAFILE_PAGES * page_size)) != GS_SUCCESS) {
            return GS_ERROR;
        }

        list = &node->undo_space.datafiles;
        if (sql_try_set_devices(stmt, list, "undo", 1, DEFAULT_UNDO_SPACE_SIZE, DEFAULT_AUTOEXTEND_SIZE,
                                ((int64)GS_MAX_UNDOFILE_PAGES * page_size)) != GS_SUCCESS) {
            return GS_ERROR;
        }

        list = &node->swap_space.datafiles;
        if (sql_try_set_devices(stmt, list, "temp", 1, DEFAULT_TEMP_SPACE_SIZE, DEFAULT_AUTOEXTEND_SIZE,
                                ((int64)GS_MAX_DATAFILE_PAGES * page_size)) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    list = &def->user_space.datafiles;
    if (sql_try_set_devices(stmt, list, "user", 1, DEFAULT_USER_SPACE_SIZE, DEFAULT_AUTOEXTEND_SIZE,
                            ((int64)GS_MAX_DATAFILE_PAGES * page_size)) != GS_SUCCESS) {
        return GS_ERROR;
    }

    list = &def->temp_space.datafiles;
    if (sql_try_set_devices(stmt, list, "temp2_01", 1, DEFAULT_USER_SPACE_SIZE, DEFAULT_AUTOEXTEND_SIZE,
                            ((int64)GS_MAX_DATAFILE_PAGES * page_size)) != GS_SUCCESS) {
        return GS_ERROR;
    }

    list = &def->temp_undo_space.datafiles;
    if (sql_try_set_devices(stmt, list, "temp2_undo", 1, DEFAULT_UNDO_SPACE_SIZE, DEFAULT_AUTOEXTEND_SIZE,
                            ((int64)GS_MAX_UNDOFILE_PAGES * page_size)) != GS_SUCCESS) {
        return GS_ERROR;
    }

    list = &def->sysaux_space.datafiles;
    if (sql_try_set_devices(stmt, list, "sysaux", 1, DEFAULT_SYSAUX_SPACE_SIZE, DEFAULT_AUTOEXTEND_SIZE,
                            ((int64)GS_MAX_DATAFILE_PAGES * page_size)) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t sql_parse_create_database(sql_stmt_t *stmt, bool32 clustered)
{
    word_t word;
    status_t status;
    knl_database_def_t *def = NULL;
    archive_mode_t arch_mode = ARCHIVE_LOG_OFF;
    dtc_node_def_t *node = NULL;

    status = sql_alloc_mem(stmt->context, sizeof(knl_database_def_t), (pointer_t *)&def);
    GS_RETURN_IFERR(status);

    stmt->context->entry = def;
    stmt->context->type = clustered ? SQL_TYPE_CREATE_CLUSTERED_DATABASE : SQL_TYPE_CREATE_DATABASE;
    status = lex_expected_fetch_variant(stmt->session->lex, &word);
    GS_RETURN_IFERR(status);

    cm_galist_init(&def->ctrlfiles, stmt->context, sql_alloc_mem);
    cm_galist_init(&def->nodes, stmt->context, sql_alloc_mem);
    cm_galist_init(&def->system_space.datafiles, stmt->context, sql_alloc_mem);
    cm_galist_init(&def->user_space.datafiles, stmt->context, sql_alloc_mem);
    cm_galist_init(&def->temp_space.datafiles, stmt->context, sql_alloc_mem);
    cm_galist_init(&def->temp_undo_space.datafiles, stmt->context, sql_alloc_mem);
    cm_galist_init(&def->sysaux_space.datafiles, stmt->context, sql_alloc_mem);

    def->system_space.name = g_system;
    def->system_space.type = SPACE_TYPE_SYSTEM | SPACE_TYPE_DEFAULT;
    def->user_space.name = g_users;
    def->user_space.type = SPACE_TYPE_USERS | SPACE_TYPE_DEFAULT;
    def->temp_space.name = g_temp;
    def->temp_space.type = SPACE_TYPE_TEMP | SPACE_TYPE_USERS | SPACE_TYPE_DEFAULT;
    def->temp_undo_space.name = g_temp_undo;
    def->temp_undo_space.type = SPACE_TYPE_UNDO | SPACE_TYPE_TEMP | SPACE_TYPE_DEFAULT;
    def->sysaux_space.name = g_sysaux;
    def->sysaux_space.type = SPACE_TYPE_SYSAUX | SPACE_TYPE_DEFAULT;
    def->max_instance = clustered ? GS_DEFAULT_INSTANCE : 1;
    if (!clustered) {
        if (cm_galist_new(&def->nodes, sizeof(dtc_node_def_t), (pointer_t *)&node) != GS_SUCCESS) {
            return GS_ERROR;
        }
        cm_galist_init(&node->logfiles, stmt->context, sql_alloc_mem);
        cm_galist_init(&node->undo_space.datafiles, stmt->context, sql_alloc_mem);
        cm_galist_init(&node->swap_space.datafiles, stmt->context, sql_alloc_mem);
        cm_galist_init(&node->temp_undo_space.datafiles, stmt->context, sql_alloc_mem);
        node->undo_space.name = g_undo;
        node->undo_space.type = SPACE_TYPE_UNDO | SPACE_TYPE_DEFAULT;
        node->swap_space.name = g_swap;
        node->swap_space.type = SPACE_TYPE_TEMP | SPACE_TYPE_DEFAULT | SPACE_TYPE_SWAP;
        node->temp_undo_space.name = g_temp_undo;
        node->temp_undo_space.type = SPACE_TYPE_TEMP | SPACE_TYPE_DEFAULT | SPACE_TYPE_UNDO;
    }

    if (word.text.len > GS_DB_NAME_LEN - 2) {
        GS_THROW_ERROR(ERR_NAME_TOO_LONG, "database", word.text.len, GS_DB_NAME_LEN - 2);
        return GS_ERROR;
    }

    status = sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, &def->name);
    GS_RETURN_IFERR(status);
    status = lex_fetch(stmt->session->lex, &word);
    GS_RETURN_IFERR(status);

    while (word.type != WORD_TYPE_EOF) {
        switch (word.id) {
            case RES_WORD_USER:
                knl_panic(0);
                break;

            case KEY_WORD_CONTROLFILE:
                status = sql_parse_dbca_ctrlfiles(stmt, def, &word);
                break;

            case KEY_WORD_CHARACTER:
                status = sql_parse_dbca_charset(stmt, def, &word);
                break;

            case KEY_WORD_LOGFILE:
                status = sql_parse_dbca_logfiles(stmt, &node->logfiles, &word);
                break;

            case KEY_WORD_ARCHIVELOG:
                arch_mode = ARCHIVE_LOG_ON;
                status = lex_fetch(stmt->session->lex, &word);
                break;

            case KEY_WORD_NOARCHIVELOG:
                arch_mode = ARCHIVE_LOG_OFF;
                status = lex_fetch(stmt->session->lex, &word);
                break;

            case RES_WORD_DEFAULT: /* default tablespace */
            case KEY_WORD_TEMPORARY:
            case KEY_WORD_NO_LOGGING:
            case KEY_WORD_UNDO:
            case KEY_WORD_SYSAUX:
            case KEY_WORD_SYSTEM:
                status = sql_parse_dbca_space(stmt, def, &word);
                break;

            case KEY_WORD_INSTANCE:
                status = dtc_parse_instance(stmt, def, &word);
                break;

            case KEY_WORD_MAXINSTANCES:
                status = dtc_parse_maxinstance(stmt, def, &word);
                if (status != GS_SUCCESS) {
                    return GS_ERROR;
                }
                status = lex_fetch(stmt->session->lex, &word);
                break;

            default:
                GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "key word expected but %s found", W2S(&word));
                return GS_ERROR;
        }

        if (status != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    def->arch_mode = arch_mode;
    status = sql_set_database_default(stmt, def, clustered);
    GS_RETURN_IFERR(status);

    return dtc_verify_database_def(stmt, def);
}

status_t sql_create_database_lead(sql_stmt_t *stmt)
{
    bool32 result = GS_FALSE;
    if (lex_try_fetch(stmt->session->lex, "LINK", &result) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (lex_try_fetch(stmt->session->lex, "CLUSTERED", &result) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return sql_parse_create_database(stmt, result);
}

static status_t sql_parse_alterdb_alter_open(sql_stmt_t *stmt, knl_alterdb_def_t *def)
{
    lex_t *lex = stmt->session->lex;
    bool32 is_found = GS_FALSE;
    db_open_opt_t *options = &def->open_options;

    def->open_options.lfn = GS_INVALID_LFN;
    def->open_options.is_creating = GS_FALSE;
    for (;;) {
        if (lex_try_fetch2(lex, "read", "only", &is_found) != GS_SUCCESS) {
            return GS_ERROR;
        }
        if (is_found) {
            options->readonly = GS_TRUE;
            break;
        }

        if (is_found) {
            break;
        }

        if (lex_try_fetch(lex, "restricted", &is_found) != GS_SUCCESS) {
            return GS_ERROR;
        }
        if (is_found) {
            options->open_status = DB_OPEN_STATUS_RESTRICT;
            break;
        }

        if (lex_try_fetch2(lex, "read", "write", &is_found) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (lex_try_fetch(stmt->session->lex, "resetlogs", &options->resetlogs) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (lex_try_fetch3(lex, "force", "ignore", "logs", &is_found) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (is_found) {
            options->ignore_logs = GS_TRUE;
            if (options->readonly || options->open_status >= DB_OPEN_STATUS_RESTRICT || options->resetlogs) {
                GS_THROW_ERROR(ERR_SQL_SYNTAX_ERROR);
                return GS_ERROR;
            }
        }
        break;
    }

    if (lex_try_fetch2(lex, "ignore", "systime", &options->ignore_systime) != GS_SUCCESS) {
    }

    return GS_SUCCESS;
}

static status_t sql_parse_delete_archivelog_time(sql_stmt_t *stmt, knl_alterdb_def_t *def, word_t *word)
{
    lex_t *lex = stmt->session->lex;

    if (lex_expected_fetch_word(lex, "time") != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (lex_expected_fetch_string(lex, word) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (cm_text2date(&word->text.value, NULL, &def->dele_arch.until_time) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (lex_fetch(lex, word) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if ((key_wid_t)word->id == KEY_WORD_FORCE) {
        def->dele_arch.force_delete = GS_TRUE;
    } else if (word->type == WORD_TYPE_EOF) {
        def->dele_arch.force_delete = GS_FALSE;
    } else {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "key word expected but %s found", W2S(word));
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t sql_parse_altdb_delete_archivelog(sql_stmt_t *stmt, knl_alterdb_def_t *def)
{
    lex_t *lex = stmt->session->lex;
    word_t word;
    status_t status = GS_SUCCESS;

    if (lex_expected_fetch(lex, &word) != GS_SUCCESS) {
        return GS_ERROR;
    }

    switch ((key_wid_t)word.id) {
        case KEY_WORD_ALL:
            if (lex_fetch(lex, &word) != GS_SUCCESS) {
                status = GS_ERROR;
            }

            def->dele_arch.all_delete = GS_TRUE;

            if ((key_wid_t)word.id == KEY_WORD_FORCE) {
                def->dele_arch.force_delete = GS_TRUE;
            } else if (word.type == WORD_TYPE_EOF) {
                def->dele_arch.force_delete = GS_FALSE;
            } else {
                GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "key word expected but %s found", W2S(&word));
                return GS_ERROR;
            }
            break;

        case KEY_WORD_UNTIL:
            def->dele_arch.all_delete = GS_FALSE;
            status = sql_parse_delete_archivelog_time(stmt, def, &word);
            break;

        default:
            GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "key word expected but %s found", W2S(&word));
            break;
    }

    return status;
}

static status_t sql_parse_altdb_delete_backupset(sql_stmt_t *stmt, knl_alterdb_def_t *def)
{
    lex_t *lex = stmt->session->lex;
    word_t word;

    if (lex_expected_fetch_word(lex, "TAG") != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (sql_parse_backup_tag(stmt, &word, def->dele_bakset.tag) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (lex_fetch(lex, &word) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if ((key_wid_t)word.id == KEY_WORD_FORCE) {
        def->dele_bakset.force_delete = GS_TRUE;
    } else if (word.type == WORD_TYPE_EOF) {
        def->dele_bakset.force_delete = GS_FALSE;
    } else {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "key word expected but %s found", W2S(&word));
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t sql_parse_alterdb_delete(sql_stmt_t *stmt, knl_alterdb_def_t *def)
{
    lex_t *lex = stmt->session->lex;
    uint32 match_id;

    if (lex_expected_fetch_1of2(lex, "ARCHIVELOG", "BACKUPSET", &match_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (match_id == 0) {
        def->action = DELETE_ARCHIVELOG;
        return sql_parse_altdb_delete_archivelog(stmt, def);
    } else {
        def->action = DELETE_BACKUPSET;
        return sql_parse_altdb_delete_backupset(stmt, def);
    }
}

static status_t sql_parse_alterdb_key_fetch(sql_stmt_t *stmt, knl_alterdb_def_t *def, word_t *word)
{
    status_t status = GS_ERROR;

    switch ((key_wid_t)word->id) {
        case KEY_WORD_MOUNT:
            def->action = STARTUP_DATABASE_MOUNT;
            status = GS_SUCCESS;
            break;

        case KEY_WORD_OPEN:
            def->action = STARTUP_DATABASE_OPEN;
            status = sql_parse_alterdb_alter_open(stmt, def);
            break;

        case KEY_WORD_UPDATE:
        case KEY_WORD_TEMPFILE:
        case KEY_WORD_DATAFILE:
        case KEY_WORD_SET:
        case KEY_WORD_SWITCHOVER:
        case KEY_WORD_FAILOVER:
        case KEY_WORD_CONVERT:
            status = GS_ERROR;
            break;

        case KEY_WORD_ARCHIVELOG:
            def->action = DATABASE_ARCHIVELOG;
            status = GS_SUCCESS;
            break;

        case KEY_WORD_NOARCHIVELOG:
            def->action = DATABASE_NOARCHIVELOG;
            status = GS_SUCCESS;
            break;

        case KEY_WORD_ADD:
        case KEY_WORD_DROP:
        case KEY_WORD_ARCHIVE:
            status = GS_ERROR;
            break;

        case KEY_WORD_DELETE:
            status = sql_parse_alterdb_delete(stmt, def);
            break;

        case KEY_WORD_ENABLE_LOGIC_REPLICATION:
            status = GS_ERROR;
            break;

        case KEY_WORD_CHARACTER:
        case KEY_WORD_REBUILD:
        case KEY_WORD_CANCEL:
            status = GS_ERROR;
            break;

        default:
            GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "key word expected, but %s found", W2S(word));
            return GS_ERROR;
    }

    if (status == GS_SUCCESS) {
        status = lex_expected_end(stmt->session->lex);
    }

    return status;
}

static status_t sql_parse_alterdb_clear(sql_stmt_t *stmt, knl_alterdb_def_t *def)
{
    def->action = DATABASE_CLEAR_LOGFILE;

    if (lex_expected_fetch_word(stmt->session->lex, "logfile") != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (lex_expected_fetch_uint32(stmt->session->lex, &def->clear_logfile_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return lex_expected_end(stmt->session->lex);
}

status_t sql_parse_alter_database(sql_stmt_t *stmt)
{
    word_t word;
    knl_alterdb_def_t *def = NULL;
    lex_t *lex = stmt->session->lex;
    char *db_name = NULL;
    text_t name;
    bool32 is_clear_logfile = GS_FALSE;
    status_t status;
    bool32 upgrade_pl;

    stmt->context->type = SQL_TYPE_ALTER_DATABASE;

    status = sql_alloc_mem(stmt->context, sizeof(knl_alterdb_def_t), (void **)&def);
    GS_RETURN_IFERR(status);

    stmt->context->entry = def;

    GS_RETURN_IFERR(lex_try_fetch2(lex, "UPGRADE", "PROCEDURE", &upgrade_pl));
    if (upgrade_pl) {
        def->action = UPGRADE_PROCEDURE;
        return GS_SUCCESS;
    }

    GS_RETURN_IFERR(lex_expected_fetch(lex, &word));

    if (IS_VARIANT(&word)) {
        status = sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, &name);
        GS_RETURN_IFERR(status);

        db_name = knl_get_db_name(&stmt->session->knl_session);
        if (cm_text_str_equal(&name, db_name)) {
            def->name = name;
            def->is_named = GS_TRUE;
        } else if (cm_text_str_equal_ins(&name, "CLEAR")) {
            is_clear_logfile = GS_TRUE;
        }
    }

    if (def->is_named) {
        if (word.type != WORD_TYPE_KEYWORD) {
            status = lex_expected_fetch(lex, &word);
            GS_RETURN_IFERR(status);
        }

        status = sql_parse_alterdb_key_fetch(stmt, def, &word);
        GS_RETURN_IFERR(status);
    } else if (is_clear_logfile) {
        status = sql_parse_alterdb_clear(stmt, def);
        GS_RETURN_IFERR(status);
    } else {
        if (word.type == WORD_TYPE_KEYWORD) {
            status = sql_parse_alterdb_key_fetch(stmt, def, &word);
            GS_RETURN_IFERR(status);
        } else {
            if (knl_get_db_status(&stmt->session->knl_session) == DB_STATUS_NOMOUNT) {
                GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "database name input is NOT supported in nomount status");
            } else {
                GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "name %s does not match actual database name", W2S(&word));
            }
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t sql_parse_alter_database_lead(sql_stmt_t *stmt)
{
    bool32 result = GS_FALSE;
    if (lex_try_fetch(stmt->session->lex, "LINK", &result) != GS_SUCCESS) {
        return GS_ERROR;
    }
    {
        return sql_parse_alter_database(stmt);
    }
}

// invoker should input the first word
static status_t sql_try_parse_column_datatype(lex_t *lex, knl_column_def_t *column, word_t *word, bool32 *found)
{
    GS_RETURN_IFERR(lex_try_match_datatype(lex, word, found));

    if (!(*found)) {
        return GS_SUCCESS;
    }

    MEMS_RETURN_IFERR(memset_s(&column->typmod, sizeof(typmode_t), 0, sizeof(typmode_t)));

    if (word->id == DTYP_SERIAL) {
        column->typmod.datatype = GS_TYPE_BIGINT;
        column->typmod.size = sizeof(int64);
        column->is_serial = GS_TRUE;
        return GS_SUCCESS;
    }

    if (sql_parse_typmode(lex, PM_NORMAL, &column->typmod, word) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (lex_try_match_array(lex, &column->typmod.is_array, column->typmod.datatype) != GS_SUCCESS) {
        return GS_ERROR;
    }

    column->is_jsonb = (word->id == DTYP_JSONB);
    return GS_SUCCESS;
}

status_t sql_check_duplicate_column(galist_t *columns, const text_t *name)
{
    uint32 i;
    knl_column_def_t *column = NULL;

    for (i = 0; i < columns->count; i++) {
        column = (knl_column_def_t *)cm_galist_get(columns, i);
        if (cm_text_equal(&column->name, name)) {
            GS_THROW_ERROR(ERR_DUPLICATE_NAME, "column", T2S(name));
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t sql_verify_column_default_expr(sql_verifier_t *verf, expr_tree_t *cast_expr, knl_column_def_t *def)
{
    status_t status = GS_SUCCESS;
    variant_t *pvar = NULL;
    uint32 value_len;
    const typmode_t *cmode = NULL;
    var_func_t v;
    expr_node_t *cast_func = cast_expr->root;
    expr_tree_t *default_expr = cast_func->argument;

    v.func_id = sql_get_func_id((text_t *)&cast_func->word.func.name);
    v.pack_id = GS_INVALID_ID32;
    v.is_proc = GS_FALSE;
    v.is_winsort_func = GS_FALSE;
    v.arg_cnt = GS_TRUE;
    cast_func->value.type = GS_TYPE_INTEGER;
    cast_func->value.v_func = v;

    if (sql_verify_expr_node(verf, default_expr->root) != GS_SUCCESS) {
        cm_set_error_loc(default_expr->loc);
        return GS_ERROR;
    }

    cmode = &def->typmod;
    cast_func->typmod = def->typmod;
    cast_func->size = default_expr->next->root->value.v_type.size;

    if (sql_is_skipped_expr(default_expr)) {
        return GS_SUCCESS;
    }

    if (!var_datatype_matched(cmode->datatype, TREE_DATATYPE(default_expr))) {
        GS_SRC_ERROR_MISMATCH(TREE_LOC(default_expr), cmode->datatype, TREE_DATATYPE(default_expr));
        return GS_ERROR;
    }

    GS_RETVALUE_IFTRUE(!TREE_IS_CONST(default_expr), GS_SUCCESS);

    pvar = &default_expr->root->value;
    if (cmode->datatype != TREE_DATATYPE(default_expr)) {
        GS_RETVALUE_IFTRUE((pvar->is_null), GS_SUCCESS);
        GS_RETURN_IFERR(sql_convert_variant(verf->stmt, pvar, cmode->datatype));
        TREE_DATATYPE(default_expr) = cmode->datatype;
    }

    // copy string, binary, and raw datatype into SQL context
    if ((!pvar->is_null) && GS_IS_VARLEN_TYPE(pvar->type)) {
        text_t text_bak = pvar->v_text;
        GS_RETURN_IFERR(sql_copy_text(verf->stmt->context, &text_bak, &pvar->v_text));
    }

    if ((!pvar->is_null) && GS_IS_LOB_TYPE(pvar->type)) {
        var_lob_t lob_bak = pvar->v_lob;
        GS_RETURN_IFERR(sql_copy_text(verf->stmt->context, &lob_bak.normal_lob.value, &pvar->v_lob.normal_lob.value));
    }

    switch (cmode->datatype) {
        case GS_TYPE_NUMBER:
        case GS_TYPE_DECIMAL:
        case GS_TYPE_NUMBER2:
        case GS_TYPE_NUMBER3:
            status = cm_adjust_dec(&pvar->v_dec, cmode->precision, cmode->scale);
            break;

        case GS_TYPE_TIMESTAMP:
        case GS_TYPE_TIMESTAMP_TZ_FAKE:
        case GS_TYPE_TIMESTAMP_LTZ:
            status = cm_adjust_timestamp(&pvar->v_tstamp, cmode->precision);
            break;

        case GS_TYPE_TIMESTAMP_TZ:
            status = cm_adjust_timestamp_tz(&pvar->v_tstamp_tz, cmode->precision);
            break;

        case GS_TYPE_INTERVAL_DS:
            status = cm_adjust_dsinterval(&pvar->v_itvl_ds, (uint32)cmode->day_prec, (uint32)cmode->frac_prec);
            break;

        case GS_TYPE_INTERVAL_YM:
            status = cm_adjust_yminterval(&pvar->v_itvl_ym, (uint32)cmode->year_prec);
            break;

        case GS_TYPE_CHAR:
        case GS_TYPE_VARCHAR:
        case GS_TYPE_STRING:
            if (cmode->is_char) {
                GS_RETURN_IFERR(GET_DATABASE_CHARSET->length(&pvar->v_text, &value_len));
                if (pvar->v_text.len > GS_MAX_COLUMN_SIZE) {
                    GS_THROW_ERROR(ERR_VALUE_ERROR, "default string length is too long, beyond the max");
                    return GS_ERROR;
                }
            } else {
                value_len = pvar->v_text.len;
            }
            if (!pvar->is_null && value_len > cmode->size) {
                GS_THROW_ERROR(ERR_DEFAULT_LEN_TOO_LARGE, pvar->v_text.len, T2S(&def->name), cmode->size);
                status = GS_ERROR;
            }
            break;

        case GS_TYPE_BINARY:
        case GS_TYPE_VARBINARY:
        case GS_TYPE_RAW:
            if (!pvar->is_null && pvar->v_bin.size > cmode->size) {
                GS_THROW_ERROR(ERR_DEFAULT_LEN_TOO_LARGE, pvar->v_bin.size, T2S(&def->name), cmode->size);
                status = GS_ERROR;
            }
            break;

        case GS_TYPE_UINT32:
        case GS_TYPE_INTEGER:
        case GS_TYPE_BOOLEAN:
        case GS_TYPE_BIGINT:
        case GS_TYPE_UINT64:
        case GS_TYPE_REAL:
        case GS_TYPE_DATE:
        case GS_TYPE_DATETIME_MYSQL:
        case GS_TYPE_TIME_MYSQL:
        case GS_TYPE_DATE_MYSQL:
            return GS_SUCCESS;

        case GS_TYPE_CLOB:
        case GS_TYPE_BLOB:
        case GS_TYPE_IMAGE:
            return GS_SUCCESS;

        default:
            GS_THROW_ERROR(ERR_VALUE_ERROR, "the data type of column is not supported");
            return GS_ERROR;
    }

    if (status != GS_SUCCESS) {
        cm_set_error_loc(default_expr->loc);
    }

    return status;
}

static status_t sql_verify_cast_default_expr(sql_stmt_t *stmt, knl_column_def_t *column, expr_tree_t **expr)
{
    sql_verifier_t verf = { 0 };
    verf.context = stmt->context;
    verf.stmt = stmt;
    verf.column = column;
    verf.excl_flags = SQL_DEFAULT_EXCL;

    if (GS_SUCCESS != sql_build_cast_expr(stmt, TREE_LOC(*expr), *expr, &column->typmod, expr)) {
        GS_SRC_THROW_ERROR(TREE_LOC(*expr), ERR_CAST_TO_COLUMN, "default value", T2S(&column->name));
        return GS_ERROR;
    }

    return sql_verify_column_default_expr(&verf, *expr, column);
}

static status_t sql_verify_column_default(sql_stmt_t *stmt, knl_column_def_t *column)
{
    text_t save_text;
    lex_t *lex = stmt->session->lex;

    if (column->is_serial) {
        GS_THROW_ERROR(ERR_MUTI_DEFAULT_VALUE, T2S(&(column->name)));
        return GS_ERROR;
    }

    if (column->default_text.len > GS_MAX_DFLT_VALUE_LEN) {
        GS_SRC_THROW_ERROR_EX(TREE_LOC((expr_tree_t *)column->insert_expr), ERR_SQL_SYNTAX_ERROR,
                              "default value string is too long, exceed %d", GS_MAX_DFLT_VALUE_LEN);
        return GS_ERROR;
    }

    if (sql_verify_cast_default_expr(stmt, column, (expr_tree_t **)&column->insert_expr) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (column->update_expr != NULL) {
        if (sql_verify_cast_default_expr(stmt, column, (expr_tree_t **)&column->update_expr) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (column->typmod.is_array == GS_TRUE) {
        GS_SRC_THROW_ERROR(LEX_LOC, ERR_SET_DEF_ARRAY_VAL);
        return GS_ERROR;
    }
    save_text = column->default_text;
    return sql_copy_text(stmt->context, &save_text, &column->default_text);
}

static status_t sql_parse_column_default(sql_stmt_t *stmt, lex_t *lex, knl_column_def_t *column, word_t *word,
                                         uint32 *ex_flags)
{
    status_t status;
    text_t default_content;

    if (*ex_flags & COLUMN_EX_DEFAULT) {
        GS_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "duplicate or conflicting default specifications");
        return GS_ERROR;
    }

    column->default_text = lex->curr_text->value;
    lex->flags = LEX_WITH_ARG | LEX_WITH_OWNER;
    status = sql_create_expr_until(stmt, (expr_tree_t **)&column->insert_expr, word);
    GS_RETURN_IFERR(status);
    column->is_default = GS_TRUE;
    *ex_flags |= COLUMN_EX_DEFAULT;

    if (word->id == KEY_WORD_ON) {
        status = lex_expected_fetch_word(lex, "UPDATE");
        GS_RETURN_IFERR(status);

        if (*ex_flags & COLUMN_EX_UPDATE_DEFAULT) {
            GS_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR,
                                  "duplicate or conflicting on update default specifications");
            return GS_ERROR;
        }

        lex->flags = LEX_WITH_ARG | LEX_WITH_OWNER;
        status = sql_create_expr_until(stmt, (expr_tree_t **)&column->update_expr, word);
        GS_RETURN_IFERR(status);

        column->is_update_default = GS_TRUE;
        *ex_flags |= COLUMN_EX_UPDATE_DEFAULT;
    }

    lex->flags = LEX_SINGLE_WORD;
    if (word->type != WORD_TYPE_EOF) {
        column->default_text.len = (uint32)(word->text.str - column->default_text.str);
        lex_back(lex, word);
    }

    /* extract content of column default value */
    if (column->default_text.len > 0) {
        GS_RETURN_IFERR(sql_alloc_mem(stmt->context, column->default_text.len, (void **)&default_content.str));
        cm_extract_content(&column->default_text, &default_content);
        column->default_text = default_content;
    }
    cm_trim_text(&column->default_text);

    if (column->typmod.datatype == GS_TYPE_UNKNOWN) {
        // datatype may be know after 'as select' clause parsed,delay verify at 'sql_verify_default_column'
        column->delay_verify = GS_TRUE;
        return GS_SUCCESS;
    }

    return sql_verify_column_default(stmt, column);
}

// verify default column after column datatype get from  'as select' clause
status_t sql_delay_verify_default(sql_stmt_t *stmt, knl_table_def_t *def)
{
    galist_t *def_columns = NULL;
    knl_column_def_t *column = NULL;
    uint32 loop;

    def_columns = &def->columns;

    for (loop = 0; loop < def_columns->count; ++loop) {
        column = (knl_column_def_t *)cm_galist_get(def_columns, loop);
        // not default column or default column is already parsed before,continue
        if (!column->is_default || !column->delay_verify) {
            continue;
        }

        GS_RETURN_IFERR(sql_verify_column_default(stmt, column));
    }

    return GS_SUCCESS;
}

static status_t sql_parse_col_ex_with_input_word_core(sql_stmt_t *stmt, lex_t *lex, knl_column_def_t *column,
                                                      word_t *word, uint32 *ex_flags)
{
    status_t status = GS_SUCCESS;
    switch (word->id) {
        case RES_WORD_DEFAULT:
            status = sql_parse_column_default(stmt, lex, column, word, ex_flags);
            break;

        case KEY_WORD_COMMENT:
        case KEY_WORD_AUTO_INCREMENT:
        case KEY_WORD_COLLATE:
            knl_panic(0);
            break;

        case KEY_WORD_PRIMARY: {
            status = sql_parse_inline_constraint_elemt(stmt, lex, column, word, ex_flags, NULL);
        } break;

        case KEY_WORD_UNIQUE:
        case KEY_WORD_REFERENCES:
        case KEY_WORD_CHECK:
            knl_panic(0);
            break;

        case KEY_WORD_WITH:
        case KEY_WORD_NOT:
        case RES_WORD_NULL:
            status = sql_parse_inline_constraint_elemt(stmt, lex, column, word, ex_flags, NULL);
            break;

        case KEY_WORD_CONSTRAINT:
            knl_panic(0);
            break;

        default:
            GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "constraint expected but %s found", W2S(word));
            return GS_ERROR;
    }
    return status;
}

static status_t sql_parse_col_ex_with_input_word(sql_stmt_t *stmt, lex_t *lex, knl_column_def_t *column, word_t *word)
{
    status_t status;
    column->nullable = GS_TRUE;
    column->primary = GS_FALSE;
    uint32 ex_flags = 0;
    for (;;) {
        status = sql_parse_col_ex_with_input_word_core(stmt, lex, column, word, &ex_flags);
        GS_RETURN_IFERR(status);
        status = lex_fetch(lex, word);
        GS_RETURN_IFERR(status);

        if (word->type == WORD_TYPE_EOF || IS_SPEC_CHAR(word, ',')) {
            break;
        }
    }

    if (CM_IS_EMPTY(&column->default_text)) {
        if (g_instance->sql.enable_empty_string_null) {
            column->is_default_null = GS_TRUE;
        }
    }
    return GS_SUCCESS;
}

// extra attributes, such as constraints, default value, ...
static status_t sql_try_parse_column_ex(sql_stmt_t *stmt, lex_t *lex, knl_column_def_t *column, word_t *word)
{
    status_t status;

    status = lex_fetch(lex, word);
    GS_RETURN_IFERR(status);

    if (word->type == WORD_TYPE_EOF || IS_SPEC_CHAR(word, ',')) {
        column->nullable = GS_TRUE;
        column->primary = GS_FALSE;
        return GS_SUCCESS;
    }

    return sql_parse_col_ex_with_input_word(stmt, lex, column, word);
}

static inline status_t sql_check_col_name_vaild(word_t *word)
{
    if (!IS_VARIANT(word)) {
        GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "invalid column name '%s'", W2S(word));
        return GS_ERROR;
    }
    if (word->ex_count != 0) {
        GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "too many dot for column");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t sql_parse_column_attr(sql_stmt_t *stmt, lex_t *lex, word_t *word, knl_table_def_t *def,
                                      bool32 *expect_as)
{
    text_t name;
    status_t status;
    knl_column_def_t *column = NULL;
    bool32 found = GS_FALSE;

    GS_RETURN_IFERR(sql_check_col_name_vaild(word));

    GS_RETURN_IFERR(sql_copy_object_name(stmt->context, word->type, (text_t *)&word->text, &name));

    GS_RETURN_IFERR(sql_check_duplicate_column(&def->columns, &name));

    GS_RETURN_IFERR(cm_galist_new(&def->columns, sizeof(knl_column_def_t), (pointer_t *)&column));

    if (word->type == WORD_TYPE_DQ_STRING) {
        column->has_quote = GS_TRUE;
    }

    column->nullable = GS_TRUE;
    column->name = name;
    column->table = (void *)def;
    cm_galist_init(&column->ref_columns, stmt->context, sql_alloc_mem);

    // considering syntax create table(a, b, c) as select, columns may have no data type
    GS_RETURN_IFERR(lex_fetch(lex, word));

    if (word->type == WORD_TYPE_EOF || IS_SPEC_CHAR(word, ',')) {
        *expect_as = GS_TRUE;
        column->datatype = GS_TYPE_UNKNOWN;
        return GS_SUCCESS;
    }

    // try to parse datatype, considering syntax create(a not null,b default 'c',c primary key) as select
    GS_RETURN_IFERR(sql_try_parse_column_datatype(lex, column, word, &found));
    if (found) {
        // parse extended attribute, like not null, default, primary key, or is array field.
        status = sql_try_parse_column_ex(stmt, lex, column, word);
        GS_RETURN_IFERR(status);
    } else if (word->type == WORD_TYPE_KEYWORD || word->type == WORD_TYPE_RESERVED) {
        *expect_as = GS_TRUE;
        // parse extended attribute, use current word as first word
        column->datatype = GS_TYPE_UNKNOWN;
        status = sql_parse_col_ex_with_input_word(stmt, lex, column, word);
        GS_RETURN_IFERR(status);
    } else {
        GS_SRC_THROW_ERROR_EX(lex->loc, ERR_SQL_SYNTAX_ERROR, "datatype expected, but got '%s'", W2S(word));
        return GS_ERROR;
    }

    if (column->primary) {
        if (def->pk_inline) {
            GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "table can have only one primary key.");
            return GS_ERROR;
        }
        def->pk_inline = GS_TRUE;
    }

    def->rf_inline = def->rf_inline || (column->is_ref);
    def->uq_inline = def->uq_inline || (column->unique);
    def->chk_inline = def->chk_inline || (column->is_check);

    return GS_SUCCESS;
}

status_t sql_verify_cons_def(knl_table_def_t *def)
{
    uint32 i, j, m, n;
    text_t *column_name = NULL;
    galist_t *columns = &def->columns;
    knl_column_def_t *column = NULL;
    knl_index_col_def_t *index_column = NULL;
    knl_constraint_def_t *cons1 = NULL;
    knl_constraint_def_t *cons2 = NULL;

    for (i = 0; i < def->constraints.count; i++) {
        cons1 = (knl_constraint_def_t *)cm_galist_get(&def->constraints, i);

        for (m = 0; m < cons1->columns.count; m++) {
            if (cons1->type == CONS_TYPE_PRIMARY || cons1->type == CONS_TYPE_UNIQUE) {
                index_column = (knl_index_col_def_t *)cm_galist_get(&cons1->columns, m);
                column_name = &index_column->name;
            } else {
                column_name = (text_t *)cm_galist_get(&cons1->columns, m);
            }

            for (n = 0; n < columns->count; n++) {
                column = (knl_column_def_t *)cm_galist_get(columns, n);
                if (cm_text_equal_ins(&column->name, column_name)) {
                    break;
                }
            }

            if (n == columns->count) {
                GS_THROW_ERROR(ERR_COLUMN_NOT_EXIST, T2S(&def->schema), T2S_EX(column_name));
                return GS_ERROR;
            }
        }
        for (j = i + 1; j < def->constraints.count; j++) {
            cons2 = (knl_constraint_def_t *)cm_galist_get(&def->constraints, j);
            if (cm_text_equal(&cons1->name, &cons2->name)) {
                GS_THROW_ERROR(ERR_OBJECT_EXISTS, "constraint", T2S(&cons1->name));
                return GS_ERROR;
            }
        }
    }

    return GS_SUCCESS;
}

status_t sql_verify_array_columns(table_type_t type, galist_t *columns)
{
    knl_column_def_t *column = NULL;

    if (type == TABLE_TYPE_HEAP) {
        return GS_SUCCESS;
    }

    /* non-heap table can not have array type columns */
    for (uint32 i = 0; i < columns->count; i++) {
        column = (knl_column_def_t *)cm_galist_get(columns, i);
        if (column != NULL && column->typmod.is_array == GS_TRUE) {
            GS_THROW_ERROR(ERR_WRONG_TABLE_TYPE);
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t sql_verify_auto_increment(sql_stmt_t *stmt, knl_table_def_t *def)
{
    uint32 i;
    uint32 serial_colums = 0;
    knl_column_def_t *column = NULL;
    knl_column_def_t *serial_column = NULL;
    knl_constraint_def_t *cons = NULL;
    knl_index_col_def_t *index_col = NULL;

    for (i = 0; i < def->columns.count; i++) {
        column = (knl_column_def_t *)cm_galist_get(&def->columns, i);
        if (column->is_serial) {
            serial_column = column;
            serial_colums++;
            if (column->delay_verify_auto_increment == GS_TRUE && column->datatype != GS_TYPE_BIGINT &&
                column->datatype != GS_TYPE_INTEGER && column->datatype != GS_TYPE_UINT32 &&
                column->datatype != GS_TYPE_UINT64) {
                GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "auto increment column %s only support int type",
                                  T2S(&column->name));
                return GS_ERROR;
            }
        }
    }

    if (serial_colums == 0) {
        return GS_SUCCESS;
    } else if (serial_colums > 1) {
        GS_THROW_ERROR(ERR_DUPLICATE_AUTO_COLUMN);
        return GS_ERROR;
    }

    for (i = 0; i < def->constraints.count; i++) {
        cons = (knl_constraint_def_t *)cm_galist_get(&def->constraints, i);
        if (cons->type == CONS_TYPE_PRIMARY || cons->type == CONS_TYPE_UNIQUE) {
            if (cons->columns.count == 0) {
                continue;
            }

            index_col = (knl_index_col_def_t *)cm_galist_get(&cons->columns, 0);
            if (cm_text_equal(&index_col->name, &serial_column->name)) {
                break;
            }
        }
    }

    if (IS_COMPATIBLE_MYSQL_INST) {
        return GS_SUCCESS;
    }

    if (i == def->constraints.count) {
        GS_THROW_ERROR(ERR_DUPLICATE_AUTO_COLUMN);
        return GS_ERROR;
    }

    variant_t value = { .type = GS_TYPE_BIGINT, .is_null = GS_FALSE, .v_bigint = def->serial_start };
    return sql_convert_variant(stmt, &value, serial_column->datatype);
}

status_t sql_parse_column_defs(sql_stmt_t *stmt, lex_t *lex, knl_table_def_t *def, bool32 *expect_as)
{
    status_t status;
    word_t word;
    bool32 result = GS_FALSE;

    for (;;) {
        status = lex_expected_fetch(lex, &word);
        GS_RETURN_IFERR(status);

        status = sql_try_parse_cons(stmt, lex, def, &word, &result);
        GS_RETURN_IFERR(status);

        if (result) {
            if (word.type == WORD_TYPE_EOF) {
                break;
            }

            continue;
        }

        status = sql_parse_column_attr(stmt, lex, &word, def, expect_as);
        GS_RETURN_IFERR(status);

        if (word.type == WORD_TYPE_EOF) {
            break;
        }
    }

    return GS_SUCCESS;
}

status_t sql_parse_create(sql_stmt_t *stmt)
{
    word_t word;
    status_t status;

    status = lex_fetch(stmt->session->lex, &word);
    GS_RETURN_IFERR(status);

    switch ((uint32)word.id) {
        case KEY_WORD_DATABASE:
            status = sql_create_database_lead(stmt);
            break;
        case KEY_WORD_ROLE:
            status = sql_parse_create_role(stmt);
            break;
        case RES_WORD_USER:
        case KEY_WORD_TENANT:
            status = GS_ERROR;
            break;
        case KEY_WORD_TABLE:
            status = sql_parse_create_table(stmt, GS_FALSE, GS_FALSE);
            break;
        case KEY_WORD_INDEX:
            status = sql_parse_create_index(stmt, GS_FALSE);
            break;
        case KEY_WORD_INDEXCLUSTER:
            status = GS_ERROR;
            break;
        case KEY_WORD_SEQUENCE:
            status = sql_parse_create_sequence(stmt);
            break;
        case KEY_WORD_TABLESPACE:
        case KEY_WORD_TEMPORARY:
            status = GS_ERROR;
            break;
        case KEY_WORD_GLOBAL:
            status = sql_create_global_lead(stmt);
            break;
        case KEY_WORD_UNIQUE:
            status = sql_parse_create_unique_lead(stmt);
            break;
        case KEY_WORD_UNDO:
        case KEY_WORD_VIEW:
        case KEY_WORD_PROCEDURE:
        case KEY_WORD_FUNCTION:
        case KEY_WORD_PACKAGE:
        case KEY_WORD_TYPE:
        case KEY_WORD_TRIGGER:
        case KEY_WORD_OR:
        case KEY_WORD_PUBLIC:
        case KEY_WORD_SYNONYM:
        case KEY_WORD_PROFILE:
        case KEY_WORD_DIRECTORY:
        case KEY_WORD_LIBRARY:
        case KEY_WORD_CTRLFILE:
            knl_panic(0);
            break;
        default:
            GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "object type expected but %s found", W2S(&word));
            status = GS_ERROR;
            break;
    }

    return status;
}

status_t sql_parse_drop(sql_stmt_t *stmt)
{
    word_t word;
    status_t status;

    status = lex_fetch(stmt->session->lex, &word);
    GS_RETURN_IFERR(status);

    switch ((uint32)word.id) {
        case KEY_WORD_TABLE:
        case KEY_WORD_INDEX:
        case KEY_WORD_SEQUENCE:
        case KEY_WORD_TABLESPACE:
        case KEY_WORD_TEMPORARY:
        case KEY_WORD_VIEW:
        case RES_WORD_USER:
        case KEY_WORD_TENANT:
        case KEY_WORD_PUBLIC:
        case KEY_WORD_ROLE:
        case KEY_WORD_PROFILE:
        case KEY_WORD_DIRECTORY:
        case KEY_WORD_PROCEDURE:
        case KEY_WORD_FUNCTION:
        case KEY_WORD_TRIGGER:
        case KEY_WORD_PACKAGE:
        case KEY_WORD_TYPE:
        case KEY_WORD_SYNONYM:
        case KEY_WORD_DATABASE:
        case KEY_WORD_SQL_MAP:
        case KEY_WORD_LIBRARY:
            status = GS_ERROR;
            break;

        default:
            GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "object type expected but %s found", W2S(&word));
            status = GS_ERROR;
            break;
    }

    return status;
}

void sql_init_grant_def(sql_stmt_t *stmt, knl_grant_def_t *def)
{
    cm_galist_init(&def->privs, stmt->context, sql_alloc_mem);
    cm_galist_init(&def->columns, stmt->context, sql_alloc_mem);
    cm_galist_init(&def->grantees, stmt->context, sql_alloc_mem);
    cm_galist_init(&def->privs_list, stmt->context, sql_alloc_mem);
    cm_galist_init(&def->grantee_list, stmt->context, sql_alloc_mem);
    def->grant_uid = stmt->session->curr_schema_id;
    return;
}

status_t sql_parse_grant(sql_stmt_t *stmt)
{
    lex_t *lex = stmt->session->lex;
    knl_session_t *se = &stmt->session->knl_session;
    status_t status;
    knl_grant_def_t *def = NULL;
    stmt->context->type = SQL_TYPE_GRANT;

    if (knl_ddl_enabled(se, GS_TRUE) != GS_SUCCESS) {
        return GS_ERROR;
    }
    status = sql_alloc_mem(stmt->context, sizeof(knl_grant_def_t), (void **)&def);
    GS_RETURN_IFERR(status);

    sql_init_grant_def(stmt, def);
    status = sql_parse_grant_privs(stmt, def);
    GS_RETURN_IFERR(status);

    if (def->priv_type == PRIV_TYPE_OBJ_PRIV) {
        return GS_ERROR;
    }

    if (def->priv_type == PRIV_TYPE_USER_PRIV) {
        return GS_ERROR;
    }

    GS_RETURN_IFERR(sql_parse_grantee_def(stmt, lex, def));
    if (def->priv_type == PRIV_TYPE_OBJ_PRIV) {
        return GS_ERROR;
    }
    /* check privilege's type */
    status = sql_check_privs_type(stmt, &def->privs, def->priv_type, def->objtype, &def->type_name);
    GS_RETURN_IFERR(status);

    stmt->context->entry = (void *)def;
    return GS_SUCCESS;
}

status_t sql_parse_revoke(sql_stmt_t *stmt)
{
    return GS_ERROR;
}

status_t sql_parse_ddl(sql_stmt_t *stmt, key_wid_t wid)
{
    status_t status;
    text_t origin_sql = stmt->session->lex->text.value;

    GS_RETURN_IFERR(sql_alloc_context(stmt));

    GS_RETURN_IFERR(sql_create_list(stmt, &stmt->context->ref_objects));

    switch (wid) {
        case KEY_WORD_CREATE:
            status = sql_parse_create(stmt);
            break;

        case KEY_WORD_DROP:
            status = sql_parse_drop(stmt);
            break;

        case KEY_WORD_TRUNCATE:
        case KEY_WORD_FLASHBACK:
        case KEY_WORD_PURGE:
        case KEY_WORD_COMMENT:
            knl_panic(0);
            break;

        case KEY_WORD_GRANT:
            status = sql_parse_grant(stmt);
            break;

        case KEY_WORD_REVOKE:
            status = sql_parse_revoke(stmt);
            break;

        case KEY_WORD_ANALYZE:
        default:
            knl_panic(0);
            break;
    }

    // write ddl sql into context, exclude operate pwd ddl
    if (!SQL_OPT_PWD_DDL_TYPE(stmt->context->type)) {
        GS_RETURN_IFERR(ctx_write_text(&stmt->context->ctrl, &origin_sql));
        stmt->context->ctrl.hash_value = cm_hash_text(&origin_sql, INFINITE_HASH_RANGE);
    }

    return status;
}

status_t sql_parse_scope_clause_inner(knl_alter_sys_def_t *def, lex_t *lex, bool32 force)
{
    bool32 result = GS_FALSE;
    uint32 match_id;
    status_t status;

    // if already parsed scope clause, must return
    if (def->scope >= CONFIG_SCOPE_MEMORY) {
        return GS_SUCCESS;
    }

    if (force) {
        status = lex_expected_fetch_word(lex, "scope");
        GS_RETURN_IFERR(status);
    } else {
        status = lex_try_fetch(lex, "scope", &result);
        GS_RETURN_IFERR(status);
        if (!result) {
            def->scope = CONFIG_SCOPE_BOTH;
            return GS_SUCCESS;
        }
    }

    status = lex_expected_fetch_word(lex, "=");
    GS_RETURN_IFERR(status);

    status = lex_expected_fetch_1of3(lex, "memory", "pfile", "both", &match_id);
    GS_RETURN_IFERR(status);

    if (match_id == LEX_MATCH_FIRST_WORD) {
        def->scope = CONFIG_SCOPE_MEMORY;
    } else if (match_id == LEX_MATCH_SECOND_WORD) {
        def->scope = CONFIG_SCOPE_DISK;
    } else {
        def->scope = CONFIG_SCOPE_BOTH;
    }

    return GS_SUCCESS;
}

status_t sql_parse_expected_scope_clause(knl_alter_sys_def_t *def, lex_t *lex)
{
    return sql_parse_scope_clause_inner(def, lex, GS_TRUE);
}

status_t sql_parse_scope_clause(knl_alter_sys_def_t *def, lex_t *lex)
{
    return sql_parse_scope_clause_inner(def, lex, GS_FALSE);
}

#ifndef WIN32
status_t sql_verify_lib_host(char *realfile)
{
    char file_host[GS_FILE_NAME_BUFFER_SIZE];
    if (cm_get_file_host_name(realfile, file_host) != GS_SUCCESS) {
        return GS_ERROR;
    }
    if (!cm_str_equal(file_host, cm_sys_user_name())) {
        return GS_ERROR;
    }
    return GS_SUCCESS;
}
#endif

status_t sql_verify_cpu_inf_str(void *se, void *lex, void *def)
{
    return GS_SUCCESS;
}
status_t sql_verify_als_mq_thd_num(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != GS_SUCCESS) {
        return GS_ERROR;
    }
    if (num < GS_MQ_MIN_THD_NUM) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "SHM_MQ_MSG_RECV_THD_NUM", (int64)GS_MQ_MIN_THD_NUM);
        return GS_ERROR;
    }
    if (num > GS_MQ_MAX_THD_NUM) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "SHM_MQ_MSG_RECV_THD_NUM", (int64)GS_MQ_MAX_THD_NUM);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t sql_verify_als_mq_queue_num(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != GS_SUCCESS) {
        return GS_ERROR;
    }
    if (num < GS_MQ_MIN_QUEUE_NUM) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "SHM_MQ_MSG_QUEUE_NUM", (int64)GS_MQ_MIN_QUEUE_NUM);
        return GS_ERROR;
    }
    if (num > GS_MQ_MAX_QUEUE_NUM) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "SHM_MQ_MSG_QUEUE_NUM", (int64)GS_MQ_MAX_QUEUE_NUM);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t sql_verify_als_ctc_inst_num(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != GS_SUCCESS) {
        return GS_ERROR;
    }
    if (num < GS_CTC_MIN_INST_NUM) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "CTC_MAX_INST_PER_NODE", (int64)GS_CTC_MIN_INST_NUM);
        return GS_ERROR;
    }
    if (num > GS_CTC_MAX_INST_NUM) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "CTC_MAX_INST_PER_NODE", (int64)GS_CTC_MAX_INST_NUM);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t sql_verify_als_mq_thd_cool_time_num(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != GS_SUCCESS) {
        return GS_ERROR;
    }
    if (num < GS_MQ_MIN_COOL_TIME) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "SHM_MQ_MSG_THD_COOL_TIME_US", (int64)GS_MQ_MIN_COOL_TIME);
        return GS_ERROR;
    }
    if (num > GS_MQ_MAX_COOL_TIME) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "SHM_MQ_MSG_THD_COOL_TIME_US", (int64)GS_MQ_MAX_COOL_TIME);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t sql_parse_purge_partition(sql_stmt_t *stmt, knl_purge_def_t *def)
{
    word_t word;
    lex_t *lex = stmt->session->lex;
    status_t status;

    lex->flags = LEX_WITH_OWNER;
    stmt->context->entry = def;

    status = lex_expected_fetch_string(lex, &word);
    GS_RETURN_IFERR(status);

    status = sql_convert_object_name(stmt, &word, &def->owner, NULL, &def->name);
    GS_RETURN_IFERR(status);

    def->type = PURGE_PART_OBJECT;

    return lex_expected_end(lex);
}

status_t sql_list_store_define_key(part_key_t *curr_key, knl_part_def_t *parent_part_def, knl_part_obj_def_t *obj_def,
                                   const text_t *part_name)
{
    int32 cmp_result;
    part_key_t *prev_key = NULL;
    galist_t *temp_part_keys = &obj_def->part_keys;
    galist_t *temp_group_keys = &obj_def->group_keys;

    if (parent_part_def != NULL) {
        temp_part_keys = &obj_def->subpart_keys;
        temp_group_keys = &parent_part_def->group_subkeys;
    }

    for (uint32 i = 0; i < temp_group_keys->count; i++) {
        prev_key = cm_galist_get(temp_group_keys, i);
        cmp_result = knl_compare_defined_key(temp_part_keys, prev_key, curr_key);
        if (cmp_result == 0) {
            GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "duplicate value in partition %s", T2S(part_name));
            return GS_ERROR;
        }
    }

    return cm_galist_insert(temp_group_keys, curr_key);
}

status_t sql_part_verify_key_type(typmode_t *typmod)
{
    if (typmod->is_array) {
        GS_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "invalid partition key type - got ARRAY");
        return GS_ERROR;
    }

    switch (typmod->datatype) {
        case GS_TYPE_UINT32:
        case GS_TYPE_UINT64:
        case GS_TYPE_INTEGER:
        case GS_TYPE_BIGINT:
        case GS_TYPE_REAL:
        case GS_TYPE_NUMBER:
        case GS_TYPE_NUMBER2:
        case GS_TYPE_NUMBER3:
        case GS_TYPE_DECIMAL:
        case GS_TYPE_DATE:
        case GS_TYPE_TIMESTAMP:
        case GS_TYPE_INTERVAL_DS:
        case GS_TYPE_INTERVAL_YM:
        case GS_TYPE_CHAR:
        case GS_TYPE_VARCHAR:
        case GS_TYPE_STRING:
        case GS_TYPE_BINARY:
        case GS_TYPE_RAW:
        case GS_TYPE_DATE_MYSQL:
        case GS_TYPE_DATETIME_MYSQL:
        case GS_TYPE_TIME_MYSQL:
            return GS_SUCCESS;
        default:
            break;
    }

    if (GS_IS_LOB_TYPE(typmod->datatype)) {
        GS_THROW_ERROR(ERR_LOB_PART_COLUMN);
    } else {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "invalid partition key type - got %s",
                          get_datatype_name_str((int32)(typmod->datatype)));
    }

    return GS_ERROR;
}

status_t sql_parse_space(sql_stmt_t *stmt, lex_t *lex, word_t *word, text_t *space)
{
    if (space->len != 0) {
        GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "duplicate tablespace specification");
        return GS_ERROR;
    }

    if (lex_expected_fetch_variant(lex, word) != GS_SUCCESS) {
        return GS_ERROR;
    }
    return sql_copy_object_name(stmt->context, word->type, (text_t *)&word->text, &(*space));
}

static status_t sql_parse_auto_extend_on(device_type_t type, sql_stmt_t *stmt, knl_autoextend_def_t *autoextend_def)
{
    bool32 next_sized = GS_FALSE;
    bool32 max_sized = GS_FALSE;
    bool32 max_ulimited = GS_FALSE;
    int64 tmp_next_size = 0;
    int64 tmp_max_size = 0;
    lex_t *lex = stmt->session->lex;

    uint32 page_size = 0;
    autoextend_def->enabled = GS_TRUE;

    /* check if next clause exists */
    GS_RETURN_IFERR(lex_try_fetch(lex, "NEXT", &next_sized));
    if (next_sized == GS_TRUE) {
        GS_RETURN_IFERR(
            lex_expected_fetch_size(lex, (int64 *)(&tmp_next_size), GS_MIN_AUTOEXTEND_SIZE, GS_INVALID_INT64));
        GS_RETURN_IFERR(cm_check_device_size(type, tmp_next_size));
    } else {
        /* "NEXTSIZE" not specified, set 0, and knl_datafile will init this value by DEFALUD VAULE */
        tmp_next_size = 0;
    }

    /* check if maxsize clause exists */
    GS_RETURN_IFERR(knl_get_page_size(KNL_SESSION(stmt), &page_size));
    GS_RETURN_IFERR(lex_try_fetch(lex, "MAXSIZE", &max_sized));
    if (max_sized == GS_TRUE) {
        GS_RETURN_IFERR(lex_try_fetch(lex, "UNLIMITED", &max_ulimited));
        if (max_ulimited != GS_TRUE) {
            GS_RETURN_IFERR(
                lex_expected_fetch_size(lex, (int64 *)(&tmp_max_size), GS_MIN_AUTOEXTEND_SIZE, GS_INVALID_INT64));
            GS_RETURN_IFERR(cm_check_device_size(type, tmp_max_size));
            if (tmp_max_size > ((int64)GS_MAX_DATAFILE_PAGES * page_size)) {
                GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR,
                                  "\"MAXSIZE\" specified in autoextend clause cannot "
                                  "be greater than %lld. \"MAXSIZE\": %lld",
                                  ((int64)GS_MAX_DATAFILE_PAGES * page_size), tmp_max_size);
                return GS_ERROR;
            }
        } else {
            tmp_max_size = 0;
        }
    } else {
        /* "MAXSIZE" not specified, take (GS_MAX_DATAFILE_PAGES * page_size) as the default value */
        tmp_max_size = 0;
    }

    if ((tmp_max_size > 0) && (tmp_next_size > tmp_max_size)) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR,
                          "\"NEXT\" size specified in autoextend clause cannot be "
                          "greater than the \"MAX\" size. \"Next\" size is %lld, \"MAX\" size is %lld",
                          tmp_next_size, tmp_max_size);
        return GS_ERROR;
    }

    /* assign the parsed size value respectively */
    autoextend_def->nextsize = tmp_next_size;
    autoextend_def->maxsize = tmp_max_size;

    return GS_SUCCESS;
}

/*
 * the common routine for parsing auto-extend clause (keyword "AUTOEXTEND" excluded)
 * auto-extend clause (excluding "AUTOEXTEND") means:
 * { OFF | ON [ NEXT size_clause] [ MAXSIZE { UNLIMITED | size_clause }] }
 *
 * @Note:
 * 1. when "ON" specified but "NEXT" size not specified, take 16MB as the default "NEXT" size
 * 2. when "ON" specified but "MAXSIZE" size not specified, take the de-facto maxsize(*) as the default "MAXSIZE"
 * the de-facto maxsize is max_pages(4194303 pages per datafile) * length of page(8KB)
 * 3. if "ON" specified, even "MAXSIZE UNLIMITED" specified, the de-facto value of "MAXSIZE" is
 * max_pages(4194303 pages per datafile) * length of page(8KB)
 * 4. if "OFF" specified, do not use the "nextsize" and "maxsize" of the argument "autoextend_def"
 */
status_t sql_parse_autoextend_clause_core(device_type_t type, sql_stmt_t *stmt, knl_autoextend_def_t *autoextend_def,
                                          word_t *next_word)
{
    CM_POINTER3(stmt, autoextend_def, next_word);
    word_t word;
    lex_t *lex = stmt->session->lex;

    GS_RETURN_IFERR(lex_expected_fetch(lex, &word));
    if (word.type != WORD_TYPE_KEYWORD) {
        GS_SRC_THROW_ERROR_EX(word.loc, ERR_SQL_SYNTAX_ERROR, "ON or OFF expected but \"%s\" found.",
                              (*(W2S(&word)) == '\0' ? "emtpy string" : W2S(&word)));
        return GS_ERROR;
    }

    if (word.id == KEY_WORD_OFF) {
        autoextend_def->enabled = GS_FALSE;
    } else if (word.id == KEY_WORD_ON) {
        GS_RETURN_IFERR(sql_parse_auto_extend_on(type, stmt, autoextend_def));
    } else {
        GS_SRC_THROW_ERROR_EX(word.loc, ERR_SQL_SYNTAX_ERROR, "ON or OFF expected but \"%s\" found.",
                              (*(W2S(&word)) == '\0' ? "emtpy string" : W2S(&word)));
        return GS_ERROR;
    }

    GS_RETURN_IFERR(lex_fetch(lex, next_word));

    return GS_SUCCESS;
}

status_t sql_parse_datafile(sql_stmt_t *stmt, knl_device_def_t *dev_def, word_t *word, bool32 *isRelative)
{
    status_t status;
    lex_t *lex = stmt->session->lex;
    int64 max_filesize = (int64)g_instance->kernel.attr.page_size * GS_MAX_DATAFILE_PAGES;
    bool32 reuse_specified = GS_FALSE;

    status = lex_expected_fetch_string(lex, word);
    GS_RETURN_IFERR(status);

    if (word->text.str[0] != '/') {
        *isRelative = GS_TRUE;
    }

    status = sql_copy_file_name(stmt->context, (text_t *)&word->text, &dev_def->name);
    GS_RETURN_IFERR(status);

    status = lex_expected_fetch_word(lex, "SIZE");
    GS_RETURN_IFERR(status);

    status = lex_expected_fetch_size(lex, &dev_def->size, GS_MIN_USER_DATAFILE_SIZE, max_filesize);
    GS_RETURN_IFERR(status);

    device_type_t type = cm_device_type(dev_def->name.str);
    GS_RETURN_IFERR(cm_check_device_size(type, dev_def->size));

    GS_RETURN_IFERR(lex_try_fetch(lex, "REUSE", &reuse_specified));
    if (reuse_specified == GS_TRUE) {
        /* support "REUSE" only for the syntax compatibility */
        GS_LOG_RUN_WAR("\"REUSE\" specified in statement \"%s\", but it will not take effect.",
                       T2S(&(lex->text.value)));
    }

    GS_RETURN_IFERR(lex_try_fetch(lex, "COMPRESS", &dev_def->compress));

    /*
     * read the next word.
     * if it is "AUTOEXTEND", start to parse the auto-extend clause
     * if not, take the word out of the function and let the caller to judge
     */
    status = lex_fetch(lex, word);
    GS_RETURN_IFERR(status);

    if (word->type == WORD_TYPE_KEYWORD && word->id == KEY_WORD_AUTOEXTEND) {
        GS_RETURN_IFERR(sql_parse_autoextend_clause_core(type, stmt, &dev_def->autoextend, word));

        if (dev_def->autoextend.enabled && dev_def->autoextend.maxsize > 0 &&
            (dev_def->autoextend.maxsize < dev_def->size)) {
            GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR,
                                  "\"MAXSIZE\" specified in autoextend clause "
                                  "cannot be less than the value of \"SIZE\". \"MAXSIZE\": %lld, \"SIZE\": %lld",
                                  dev_def->autoextend.maxsize, dev_def->size);
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t sql_alloc_inline_cons(sql_stmt_t *stmt, constraint_type_t type, galist_t *constraints,
                                      knl_constraint_def_t **cons)
{
    if (cm_galist_new(constraints, sizeof(knl_constraint_def_t), (pointer_t *)cons) != GS_SUCCESS) {
        return GS_ERROR;
    }

    (*cons)->type = type;

    if (sql_alloc_mem(stmt->context, GS_NAME_BUFFER_SIZE, (pointer_t *)&(*cons)->name.str) != GS_SUCCESS) {
        return GS_ERROR;
    }

    knl_get_system_name(&stmt->session->knl_session, type, (*cons)->name.str, GS_NAME_BUFFER_SIZE);
    (*cons)->name.len = (uint32)strlen((*cons)->name.str);
    (*cons)->cons_state.is_anonymous = GS_TRUE;
    (*cons)->cons_state.is_enable = GS_TRUE;
    (*cons)->cons_state.is_validate = GS_TRUE;
    return GS_SUCCESS;
}

static status_t sql_create_inline_cons_index(sql_stmt_t *stmt, knl_table_def_t *def)
{
    uint32 i;
    knl_column_def_t *column = NULL;
    knl_constraint_def_t *cons = NULL;
    knl_index_col_def_t *index_column = NULL;
    constraint_type_t type;

    for (i = 0; i < def->columns.count; i++) {
        column = cm_galist_get(&def->columns, i);
        if ((!column->primary) && (!column->unique)) {
            continue;
        }

        if (column->typmod.is_array == GS_TRUE) {
            GS_THROW_ERROR(ERR_INDEX_ON_ARRAY_FIELD, T2S(&column->name));
            return GS_ERROR;
        }

        type = column->primary ? CONS_TYPE_PRIMARY : CONS_TYPE_UNIQUE;
        if (sql_alloc_inline_cons(stmt, type, &def->constraints, &cons) != GS_SUCCESS) {
            return GS_ERROR;
        }
        if (type == CONS_TYPE_PRIMARY) {
            if (!CM_IS_EMPTY(&column->inl_pri_cons_name)) {
                cons->name = column->inl_pri_cons_name;
                cons->cons_state.is_anonymous = GS_FALSE;
            }
        } else {
            if (!CM_IS_EMPTY(&column->inl_uq_cons_name)) {
                cons->name = column->inl_uq_cons_name;
                cons->cons_state.is_anonymous = GS_FALSE;
            }
        }
        cm_galist_init(&cons->columns, stmt->context, sql_alloc_mem);

        if (cm_galist_new(&cons->columns, sizeof(knl_index_col_def_t), (pointer_t *)&index_column) != GS_SUCCESS) {
            return GS_ERROR;
        }

        index_column->name = column->name;
        index_column->mode = SORT_MODE_ASC;
        cons->index.primary = (type == CONS_TYPE_PRIMARY);
        cons->index.unique = (type == CONS_TYPE_UNIQUE);
        cons->index.cr_mode = GS_INVALID_ID8;
        cons->index.pctfree = GS_INVALID_ID32;
    }

    return GS_SUCCESS;
}

status_t sql_create_inline_cons(sql_stmt_t *stmt, knl_table_def_t *def)
{
    if (def->pk_inline || def->uq_inline) {
        if (sql_create_inline_cons_index(stmt, def) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (def->rf_inline) {
        knl_panic(0);
    }

    if (def->chk_inline) {
        knl_panic(0);
    }

    return GS_SUCCESS;
}

static status_t sql_parse_column_not_null(sql_stmt_t *stmt, lex_t *lex, knl_column_def_t *column, word_t *word,
                                          uint32 *ex_flags)
{
    if (*ex_flags & COLUMN_EX_NULLABLE) {
        GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR,
                              "duplicate or conflicting not null/null specifications");
        return GS_ERROR;
    }

    if (lex_expected_fetch_word(lex, "NULL") != GS_SUCCESS) {
        return GS_ERROR;
    }

    *ex_flags |= COLUMN_EX_NULLABLE;
    column->nullable = GS_FALSE;
    column->has_null = GS_TRUE;

    return GS_SUCCESS;
}

static status_t sql_parse_column_primary(sql_stmt_t *stmt, lex_t *lex, knl_column_def_t *column, word_t *word,
                                         uint32 *ex_flags)
{
    if (*ex_flags & COLUMN_EX_KEY) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "duplicate or conflicting primary key/unique specifications");
        return GS_ERROR;
    }

    CHECK_CONS_TZ_TYPE_RETURN(column->datatype);

    if (lex_expected_fetch_word(lex, "KEY") != GS_SUCCESS) {
        return GS_ERROR;
    }

    *ex_flags |= COLUMN_EX_KEY;
    column->primary = GS_TRUE;
    column->nullable = GS_FALSE;
    column->has_null = GS_TRUE;

    return GS_SUCCESS;
}

status_t sql_parse_inline_constraint_elemt(sql_stmt_t *stmt, lex_t *lex, knl_column_def_t *column, word_t *word,
                                           uint32 *ex_flags, text_t *cons_name)
{
    status_t status;
    switch (word->id) {
        case KEY_WORD_NOT:
            status = sql_parse_column_not_null(stmt, lex, column, word, ex_flags);
            GS_RETURN_IFERR(status);
            break;

        case KEY_WORD_PRIMARY:
            status = sql_parse_column_primary(stmt, lex, column, word, ex_flags);
            GS_RETURN_IFERR(status);
            if (cons_name != NULL) {
                column->inl_pri_cons_name = *cons_name;
            }
            break;

        case RES_WORD_NULL:
            if (*ex_flags & COLUMN_EX_NULLABLE) {
                GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR,
                                      "duplicate or conflicting not null/null specifications");
                return GS_ERROR;
            }
            column->has_null = GS_TRUE;
            *ex_flags |= COLUMN_EX_NULLABLE;
            break;

        case KEY_WORD_REFERENCES:
        case KEY_WORD_UNIQUE:
        case KEY_WORD_CHECK:
            knl_panic(0);
            break;

        default:
            GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "constraint expected but %s found", W2S(word));
            return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t sql_parse_inline_constraint(sql_stmt_t *stmt, lex_t *lex, knl_column_def_t *column, word_t *word,
                                     uint32 *ex_flags)
{
    text_t inl_constr = { .str = NULL, .len = 0 };

    if (lex_expected_fetch_variant(lex, word) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (sql_copy_object_name(stmt->context, word->type, (text_t *)&word->text, &inl_constr) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (lex_fetch(lex, word) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return sql_parse_inline_constraint_elemt(stmt, lex, column, word, ex_flags, &inl_constr);
}

status_t sql_try_parse_cons(sql_stmt_t *stmt, lex_t *lex, knl_table_def_t *def, word_t *word, bool32 *result)
{
    *result = GS_FALSE;
    knl_panic(!IS_CONSTRAINT_KEYWORD(word->id));
    return GS_SUCCESS;
}

status_t sql_verify_check_constraint(sql_stmt_t *stmt, knl_table_def_t *def)
{
    uint32 loop;
    knl_constraint_def_t *cons = NULL;
    knl_column_def_t *col = NULL;

    // verify check in out line constraint
    for (loop = 0; loop < def->constraints.count; loop++) {
        cons = (knl_constraint_def_t *)cm_galist_get(&def->constraints, loop);
        if (cons->type != CONS_TYPE_CHECK) {
            continue;
        }
        knl_panic(0);
    }

    // verify check in column definition
    for (loop = 0; loop < def->columns.count; loop++) {
        col = (knl_column_def_t *)cm_galist_get(&def->columns, loop);
        if (!col->is_check) {
            continue;
        }
        knl_panic(0);
    }
    return GS_SUCCESS;
}
status_t sql_check_duplicate_index_column(sql_stmt_t *stmt, galist_t *columns, knl_index_col_def_t *new_column)
{
    uint32 i;
    knl_index_col_def_t *column = NULL;

    for (i = 0; i < columns->count; i++) {
        column = (knl_index_col_def_t *)cm_galist_get(columns, i);
        GS_CONTINUE_IFTRUE(column->is_func != new_column->is_func);

        if (!column->is_func) {
            if (cm_text_equal(&column->name, &new_column->name)) {
                GS_THROW_ERROR(ERR_DUPLICATE_NAME, "column", T2S(&column->name));
                return GS_ERROR;
            }
        } else {
            if (sql_expr_node_equal(stmt, ((expr_tree_t *)column->func_expr)->root,
                                    ((expr_tree_t *)new_column->func_expr)->root, NULL)) {
                GS_THROW_ERROR(ERR_DUPLICATE_NAME, "column", T2S(&column->func_text));
                return GS_ERROR;
            }
        }
    }

    return GS_SUCCESS;
}

static status_t sql_parse_index_column(sql_stmt_t *stmt, lex_t *lex, knl_index_col_def_t *column, bool32 *have_func)
{
    status_t status;
    word_t word;

    status = lex_expected_fetch(lex, &word);
    GS_RETURN_IFERR(status);

    if (IS_VARIANT(&word)) {
        column->is_func = GS_FALSE;
        column->func_expr = NULL;
        column->func_text.len = 0;
        return sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, &column->name);
    }
    return GS_ERROR;
}

status_t sql_parse_column_list(sql_stmt_t *stmt, lex_t *lex, galist_t *column_list, bool32 have_sort, bool32 *have_func)
{
    word_t word;
    knl_index_col_def_t *column = NULL;
    knl_index_col_def_t tmp_col;
    status_t status;

    GS_RETURN_IFERR(lex_expected_fetch_bracket(lex, &word));
    GS_RETURN_IFERR(lex_push(lex, &word.text));

    uint32 pre_flags = lex->flags;
    lex->flags = LEX_WITH_OWNER;
    if (have_sort) {
        lex->flags |= LEX_WITH_ARG;
    }
    if (have_func != NULL) {
        *have_func = GS_FALSE;
    }
    cm_galist_init(column_list, stmt->context, sql_alloc_mem);

    for (;;) {
        status = sql_parse_index_column(stmt, lex, &tmp_col, have_func);
        GS_BREAK_IF_ERROR(status);

        status = sql_check_duplicate_index_column(stmt, column_list, &tmp_col);
        GS_BREAK_IF_ERROR(status);

        status = cm_galist_new(column_list, sizeof(knl_index_col_def_t), (void **)&column);
        GS_BREAK_IF_ERROR(status);
        *column = tmp_col;

        // set func flag
        if (column->is_func && have_func) {
            *have_func = GS_TRUE;
        }

        status = lex_fetch(lex, &word);
        GS_BREAK_IF_ERROR(status);

        column->mode = SORT_MODE_ASC;
        if (have_sort && (word.id == KEY_WORD_DESC || word.id == KEY_WORD_ASC)) {
            column->mode = (word.id == KEY_WORD_DESC) ? SORT_MODE_DESC : SORT_MODE_ASC;
            status = lex_fetch(stmt->session->lex, &word);
            GS_BREAK_IF_ERROR(status);
        }

        GS_BREAK_IF_TRUE(word.type == (uint32)WORD_TYPE_EOF);

        if (!IS_SPEC_CHAR(&word, ',')) {
            GS_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "invalid identifier");
            status = GS_ERROR;
            break;
        }
    }

    if (status == GS_SUCCESS) {
        lex->flags = pre_flags;
    }
    lex_pop(lex);
    return status;
}

status_t sql_parse_index_attrs(sql_stmt_t *stmt, lex_t *lex, knl_index_def_t *def)
{
    status_t status;
    word_t word;

    def->cr_mode = GS_INVALID_ID8;
    def->online = GS_FALSE;
    def->pctfree = GS_INVALID_ID32;
    def->parallelism = 0;
    def->is_reverse = GS_FALSE;

    for (;;) {
        GS_RETURN_IFERR(lex_fetch(lex, &word));

        if (word.type == WORD_TYPE_EOF || IS_SPEC_CHAR(&word, ',')) {
            lex_back(lex, &word);
            break;
        }

        switch (word.id) {
            case KEY_WORD_TABLESPACE:
                status = sql_parse_space(stmt, lex, &word, &def->space);
                break;

            case KEY_WORD_INITRANS:
            case KEY_WORD_LOCAL:
            case KEY_WORD_PCTFREE:
            case KEY_WORD_CRMODE:
            case KEY_WORD_ONLINE:
            case KEY_WORD_PARALLEL:
            case KEY_WORD_REVERSE:
            case KEY_WORD_NO_LOGGING:
                knl_panic(0);
                break;

            default:
                GS_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "unexpected text %s", W2S(&word));
                return GS_ERROR;
        }

        GS_RETURN_IFERR(status);
    }

    if (def->initrans == 0) {
        def->initrans = cm_text_str_equal_ins(&def->user, "SYS") ? GS_INI_TRANS
                                                                 : stmt->session->knl_session.kernel->attr.initrans;
    }

    if (def->pctfree == GS_INVALID_ID32) {
        def->pctfree = GS_PCT_FREE;
    }

    if (def->online && def->parallelism != 0) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "parallel creating", "create index online");
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

static status_t sql_parse_index_def(sql_stmt_t *stmt, lex_t *lex, knl_index_def_t *def)
{
    text_t index_schema;
    word_t word;
    bool32 idx_schema_explict = GS_FALSE;

    lex->flags |= LEX_WITH_OWNER;
    word.text.str = NULL;
    word.text.len = 0;
    def->user = word.text.value;

    if (lex_expected_fetch_variant(lex, &word) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (sql_convert_object_name(stmt, &word, &index_schema, &idx_schema_explict, &def->name) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (lex_expected_fetch_word(lex, "ON") != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (lex_expected_fetch_variant(lex, &word) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (sql_convert_object_name(stmt, &word, &def->user, NULL, &def->table) != GS_SUCCESS) {
        return GS_ERROR;
    }

    /*
     * if index's schema specified explicitly and differed from the table's schema(no matter specified explicitly or
     * implicitly) an error should be raised
     */
    if (idx_schema_explict == GS_TRUE && cm_compare_text_ins(&index_schema, &def->user)) {
        GS_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR,
                              "index user(%s) is not consistent with table "
                              "user(%s)",
                              T2S(&index_schema), T2S_EX(&def->user));
        return GS_ERROR;
    }

    /*
     * regist ddl table
     */
    GS_RETURN_IFERR(sql_regist_ddl_table(stmt, &def->user, &def->table));

    cm_galist_init(&def->columns, stmt->context, sql_alloc_mem);

    if (sql_parse_column_list(stmt, lex, &def->columns, GS_TRUE, &def->is_func) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (sql_parse_index_attrs(stmt, lex, def) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

/**
 * Parse create index statement
 * @param[in]    sql statement handle
 * @param[in]    if index is unique
 * @return
 * - GS_SUCCESS
 * - GS_ERROR
 * @note must call after instance is startup
 * @see sql_parse_create
 */
status_t sql_parse_create_index(sql_stmt_t *stmt, bool32 is_unique)
{
    status_t status;
    knl_index_def_t *def = NULL;
    lex_t *lex = stmt->session->lex;

    if (sql_alloc_mem(stmt->context, sizeof(knl_index_def_t), (void **)&def) != GS_SUCCESS) {
        return GS_ERROR;
    }

    stmt->context->type = SQL_TYPE_CREATE_INDEX;
    def->unique = is_unique;

    status = sql_try_parse_if_not_exists(lex, &def->options);
    GS_RETURN_IFERR(status);

    if (sql_parse_index_def(stmt, lex, def) != GS_SUCCESS) {
        return GS_ERROR;
    }

    stmt->context->entry = def;

    GS_RETURN_IFERR(lex_expected_end(lex));
    return GS_SUCCESS;
}

status_t sql_parse_create_unique_lead(sql_stmt_t *stmt)
{
    if (GS_SUCCESS != lex_expected_fetch_word(stmt->session->lex, "INDEX")) {
        return GS_ERROR;
    }

    return sql_parse_create_index(stmt, GS_TRUE);
}

static void sql_init_create_sequence(sql_stmt_t *stmt, knl_sequence_def_t *sequence_def)
{
    CM_POINTER(sequence_def);
    sequence_def->name.len = 0;
    sequence_def->start = 1;
    sequence_def->step = DDL_SEQUENCE_DEFAULT_INCREMENT;
    sequence_def->min_value = 1;
    sequence_def->max_value = DDL_ASC_SEQUENCE_DEFAULT_MAX_VALUE;
    sequence_def->cache = DDL_SEQUENCE_DEFAULT_CACHE;
    sequence_def->is_cycle = GS_FALSE;  // default is no cycle
    sequence_def->nocache = GS_FALSE;   // no_cache is not specified
    sequence_def->nominval = GS_TRUE;   // no_min_value is not specified
    sequence_def->nomaxval = GS_TRUE;   // no_max_value is not specified
    sequence_def->is_order = GS_FALSE;  // order is not specified
    sequence_def->is_option_set = (uint32)0;
}

/* ****************************************************************************
Description  : check sequence max/min value is valid or not according to the
grammar
Input        : knl_sequence_def_t * stmt
Output       : None
Modification : Create function
Date         : 2017-02-23
**************************************************************************** */
static status_t sql_check_sequence_scop_value_valid(knl_sequence_def_t *sequence_def)
{
    if (sequence_def->max_value <= sequence_def->min_value) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "MINVALUE must less than MAXVALUE");
        return GS_ERROR;
    }

    int64 next;
    if (sequence_def->step > 0) {
        if ((opr_int64add_overflow(sequence_def->min_value, sequence_def->step, &next)) ||
            (sequence_def->max_value < next)) {
            GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "INCREMENT must be less than MAX value minus MIN value");
            return GS_ERROR;
        }
    }

    if (sequence_def->step < 0) {
        if ((opr_int64add_overflow(sequence_def->max_value, sequence_def->step, &next)) ||
            (sequence_def->min_value > next)) {
            GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "INCREMENT must be less than MAX value minus MIN value");
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}
/* ****************************************************************************
Description  : format sequence max/min value according to the grammar
Input        : knl_sequence_def_t * stmt
Output       : None
Modification : Create function
Date         : 2017-02-23
**************************************************************************** */
static status_t sql_format_sequence_scop_value(knl_sequence_def_t *sequence_def)
{
    sequence_def->nominval = sequence_def->is_minval_set ? GS_FALSE : GS_TRUE;
    sequence_def->nomaxval = sequence_def->is_maxval_set ? GS_FALSE : GS_TRUE;

    /* if minvalue is not specified, then depending on the increment value,
    assign the ascending or descending sequence's default min value */
    if (sequence_def->nominval) {
        sequence_def->min_value = sequence_def->step < 0 ? DDL_DESC_SEQUENCE_DEFAULT_MIN_VALUE
                                                         : DDL_ASC_SEQUENCE_DEFAULT_MIN_VALUE;
        sequence_def->is_minval_set = sequence_def->is_nominval_set ? 1 : 0; /* specify the 'nominvalue' */
    }

    /* if maxvalue is not specified, then depending on the increment value,
    assign the ascending or descending sequence's default max value */
    if (sequence_def->nomaxval) {
        sequence_def->max_value = sequence_def->step < 0 ? DDL_DESC_SEQUENCE_DEFAULT_MAX_VALUE
                                                         : DDL_ASC_SEQUENCE_DEFAULT_MAX_VALUE;
        sequence_def->is_maxval_set = sequence_def->is_nomaxval_set ? 1 : 0; /* specify the 'nomaxvalue' */
    }

    return sql_check_sequence_scop_value_valid(sequence_def);
}
/* ****************************************************************************
Description  : check sequence start with value is valid or not according to
the grammar
Input        : knl_sequence_def_t * stmt
Output       : None
Modification : Create function
Date         : 2017-02-23
**************************************************************************** */
static status_t sql_check_sequence_start_value(knl_sequence_def_t *sequence_def)
{
    if (sequence_def->step > 0) {
        if (sequence_def->start - sequence_def->step > sequence_def->max_value) {
            GS_THROW_ERROR(ERR_SEQ_INVALID, "start value cannot be greater than max value plus increment");
            return GS_ERROR;
        }

        if (sequence_def->start < sequence_def->min_value) {
            GS_THROW_ERROR(ERR_SEQ_INVALID, "start value cannot be less than min value");
            return GS_ERROR;
        }
    } else {
        if (sequence_def->start - sequence_def->step < sequence_def->min_value) {
            GS_THROW_ERROR(ERR_SEQ_INVALID, "start value cannot be less than min value plus increment");
            return GS_ERROR;
        }

        if (sequence_def->start > sequence_def->max_value) {
            GS_THROW_ERROR(ERR_SEQ_INVALID, "start value cannot be greater than max value");
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

/* ****************************************************************************
Description  : format sequence start with value according to the grammar
Input        : knl_sequence_def_t * stmt
Output       : None
Modification : Create function
Date         : 2017-02-23
**************************************************************************** */
static status_t sql_format_sequence_start_value(knl_sequence_def_t *sequence_def)
{
    /* if no start value is specified, then min value would be the start value */
    if (!sequence_def->is_start_set) {
        sequence_def->start = sequence_def->step > 0 ? sequence_def->min_value : sequence_def->max_value;
    }

    return sql_check_sequence_start_value(sequence_def);
}

static status_t sql_check_sequence_cache_value(knl_sequence_def_t *sequence_def)
{
    int64 step = cm_abs64(sequence_def->step);
    if (sequence_def->cache <= 1) {
        GS_THROW_ERROR(ERR_SEQ_INVALID, "CACHE value must be larger than 1");
        return GS_ERROR;
    }

    if (sequence_def->is_nocache_set) {
        sequence_def->cache = 0;
        sequence_def->is_cache_set = 1;
    }

    if (!sequence_def->nocache && sequence_def->cache < 2) {
        GS_THROW_ERROR(ERR_SEQ_INVALID, "number to CACHE must be more than 1");
        return GS_ERROR;
    }

    if (sequence_def->is_cycle && ((uint64)sequence_def->cache >
                                   ceil((double)((uint64)sequence_def->max_value - sequence_def->min_value) / step))) {
        GS_THROW_ERROR(ERR_SEQ_INVALID, "number to CACHE must be less than one cycle");
        return GS_ERROR;
    }

    if (sequence_def->step >= 1 &&
        (sequence_def->cache > (DDL_ASC_SEQUENCE_DEFAULT_MAX_VALUE / cm_abs64(sequence_def->step)))) {
        GS_THROW_ERROR(ERR_SEQ_INVALID, "CACHE multiply abs of STEP must be less than DEFAULT MAXVALUE");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t sql_format_sequence(sql_stmt_t *stmt, knl_sequence_def_t *sequence_def)
{
    if (sql_format_sequence_scop_value(sequence_def) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (sql_format_sequence_start_value(sequence_def) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (sql_check_sequence_cache_value(sequence_def) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t sql_parse_increment(lex_t *lex, knl_sequence_def_t *sequence_def)
{
    int64 increment = 0;

    if (lex_expected_fetch_word(lex, "BY") != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (lex_expected_fetch_seqval(lex, &increment) != GS_SUCCESS) {
        GS_SRC_THROW_ERROR_EX(lex->loc, ERR_SQL_SYNTAX_ERROR, "sequence INCREMENT must be a bigint");
        return GS_ERROR;
    }

    if (increment == 0) {
        GS_SRC_THROW_ERROR(lex->loc, ERR_SEQ_INVALID, "sequence INCREMENT must be a non-zero integer");
        return GS_ERROR;
    }

    sequence_def->step = increment;

    return GS_SUCCESS;
}

static status_t sql_parse_start_with(lex_t *lex, knl_sequence_def_t *sequence_def)
{
    if (lex_expected_fetch_word(lex, "WITH") != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (lex_expected_fetch_seqval(lex, &sequence_def->start) != GS_SUCCESS) {
        GS_SRC_THROW_ERROR_EX(lex->loc, ERR_SQL_SYNTAX_ERROR, "sequence START WITH must be a bigint");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t sql_parse_sequence_parameters(sql_stmt_t *stmt, knl_sequence_def_t *sequence_def, word_t *word,
                                              bool32 allow_groupid)
{
    status_t status;
    lex_t *lex = stmt->session->lex;

    for (;;) {
        status = lex_fetch(stmt->session->lex, word);
        GS_RETURN_IFERR(status);

        if (word->type == WORD_TYPE_EOF) {
            break;
        }

        switch (word->id) {
            case (uint32)KEY_WORD_INCREMENT:
                if (sequence_def->is_step_set == GS_TRUE) {
                    GS_SRC_THROW_ERROR_EX(lex->loc, ERR_SQL_SYNTAX_ERROR, "duplicate INCREMENT specifications");
                    return GS_ERROR;
                }
                status = sql_parse_increment(lex, sequence_def);
                GS_RETURN_IFERR(status);
                sequence_def->is_step_set = 1;
                break;

            case (uint32)KEY_WORD_MINVALUE:
                if (sequence_def->is_minval_set == GS_TRUE) {
                    GS_SRC_THROW_ERROR_EX(lex->loc, ERR_SQL_SYNTAX_ERROR, "duplicate MINVALUE specifications");
                    return GS_ERROR;
                }
                if (lex_expected_fetch_seqval(lex, &sequence_def->min_value) != GS_SUCCESS) {
                    GS_SRC_THROW_ERROR_EX(lex->loc, ERR_SQL_SYNTAX_ERROR, "sequence MINVALUE must be a bigint");
                    return GS_ERROR;
                }
                sequence_def->nominval = GS_FALSE;
                sequence_def->is_minval_set = 1;
                break;

            case (uint32)KEY_WORD_NO_MINVALUE:
                if (sequence_def->is_nominval_set == GS_TRUE) {
                    GS_SRC_THROW_ERROR_EX(lex->loc, ERR_SQL_SYNTAX_ERROR, "duplicate NO_MINVALUE specifications");
                    return GS_ERROR;
                }
                sequence_def->nominval = GS_TRUE;
                sequence_def->is_nominval_set = 1;
                break;

            case (uint32)KEY_WORD_MAXVALUE:
                if (sequence_def->is_maxval_set == GS_TRUE) {
                    GS_SRC_THROW_ERROR_EX(lex->loc, ERR_SQL_SYNTAX_ERROR, "duplicate MAXVALUE specifications");
                    return GS_ERROR;
                }
                if (lex_expected_fetch_seqval(lex, &sequence_def->max_value) != GS_SUCCESS) {
                    GS_SRC_THROW_ERROR_EX(lex->loc, ERR_SQL_SYNTAX_ERROR, "sequence MAXVALUE must be a bigint");
                    return GS_ERROR;
                }
                sequence_def->nomaxval = GS_FALSE;
                sequence_def->is_maxval_set = 1;
                break;

            case (uint32)KEY_WORD_NO_MAXVALUE:
                if (sequence_def->is_nomaxval_set == GS_TRUE) {
                    GS_SRC_THROW_ERROR_EX(lex->loc, ERR_SQL_SYNTAX_ERROR, "duplicate NO_MAXVALUE specifications");
                    return GS_ERROR;
                }
                sequence_def->nomaxval = GS_TRUE;
                sequence_def->is_nomaxval_set = 1;
                break;

            case (uint32)KEY_WORD_START:
                if (sequence_def->is_start_set == GS_TRUE) {
                    GS_SRC_THROW_ERROR_EX(lex->loc, ERR_SQL_SYNTAX_ERROR, "duplicate START specifications");
                    return GS_ERROR;
                }
                status = sql_parse_start_with(lex, sequence_def);
                GS_RETURN_IFERR(status);
                sequence_def->is_start_set = GS_TRUE;
                break;

            case (uint32)KEY_WORD_CACHE:
                if (sequence_def->is_cache_set == GS_TRUE) {
                    GS_SRC_THROW_ERROR_EX(lex->loc, ERR_SQL_SYNTAX_ERROR, "duplicate CACHE specifications");
                    return GS_ERROR;
                }
                if (lex_expected_fetch_seqval(lex, &sequence_def->cache) != GS_SUCCESS) {
                    GS_SRC_THROW_ERROR_EX(lex->loc, ERR_SQL_SYNTAX_ERROR, "sequence CACHE must be a bigint");
                    return GS_ERROR;
                }
                sequence_def->is_cache_set = 1;
                break;

            case (uint32)KEY_WORD_NO_CACHE:
                if (sequence_def->is_nocache_set == GS_TRUE) {
                    GS_SRC_THROW_ERROR_EX(lex->loc, ERR_SQL_SYNTAX_ERROR, "duplicate NO_CACHE specifications");
                    return GS_ERROR;
                }
                sequence_def->nocache = GS_TRUE;
                sequence_def->is_nocache_set = 1;
                break;

            case (uint32)KEY_WORD_CYCLE:
                if (sequence_def->is_cycle_set == GS_TRUE) {
                    GS_SRC_THROW_ERROR_EX(lex->loc, ERR_SQL_SYNTAX_ERROR,
                                          "duplicate or conflicting CYCLE/NOCYCLE specifications");
                    return GS_ERROR;
                }
                sequence_def->is_cycle = GS_TRUE;
                sequence_def->is_cycle_set = 1;
                break;

            case (uint32)KEY_WORD_NO_CYCLE:
                if (sequence_def->is_cycle_set == GS_TRUE) {
                    GS_SRC_THROW_ERROR_EX(lex->loc, ERR_SQL_SYNTAX_ERROR,
                                          "duplicate or conflicting CYCLE/NOCYCLE specifications");
                    return GS_ERROR;
                }
                sequence_def->is_cycle = GS_FALSE;
                sequence_def->is_cycle_set = 1;
                break;

            case (uint32)KEY_WORD_ORDER:
                if (sequence_def->is_order_set == GS_TRUE) {
                    GS_SRC_THROW_ERROR_EX(lex->loc, ERR_SQL_SYNTAX_ERROR,
                                          "duplicate or conflicting ORDER/NOORDER specifications");
                    return GS_ERROR;
                }
                sequence_def->is_order = GS_TRUE;
                sequence_def->is_order_set = 1;
                break;

            case (uint32)KEY_WORD_NO_ORDER:
                if (sequence_def->is_order_set == GS_TRUE) {
                    GS_SRC_THROW_ERROR_EX(lex->loc, ERR_SQL_SYNTAX_ERROR,
                                          "duplicate or conflicting ORDER/NOORDER specifications");
                    return GS_ERROR;
                }
                sequence_def->is_order = GS_FALSE;
                sequence_def->is_order_set = 1;
                break;
            default:
                GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "syntax error in sequence statement");
                return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t sql_check_sequence_conflict_parameters(sql_stmt_t *stmt, knl_sequence_def_t *def)
{
    bool32 result;

    result = (def->is_minval_set && def->is_nominval_set);
    if (result) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "duplicate or conflicting MINVAL/NOMINVAL specifications");
        return GS_ERROR;
    }
    result = (def->is_maxval_set && def->is_nomaxval_set);
    if (result) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "duplicate or conflicting MAX/NOMAXVAL specifications");
        return GS_ERROR;
    }

    result = (def->is_cache_set && def->is_nocache_set);
    if (result) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "duplicate or conflicting CACHE/NOCACHE specifications");
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t sql_check_sequence_parameters_relation(sql_stmt_t *stmt, knl_sequence_def_t *def)
{
    bool32 result;

    GS_RETURN_IFERR(sql_check_sequence_conflict_parameters(stmt, def));

    result = (!def->is_maxval_set && def->is_cycle && (def->step > 0));
    if (result) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "ascending sequences that CYCLE must specify MAXVALUE");
        return GS_ERROR;
    }

    result = (!def->is_minval_set && def->is_cycle && (def->step < 0));
    if (result) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "descending sequences that CYCLE must specify MINVALUE");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t sql_parse_create_sequence(sql_stmt_t *stmt)
{
    status_t status;
    knl_sequence_def_t *sequence_def = NULL;
    word_t word;
    lex_t *lex = stmt->session->lex;

    lex->flags |= LEX_WITH_OWNER;

    status = sql_alloc_mem(stmt->context, sizeof(knl_sequence_def_t), (void **)&sequence_def);
    GS_RETURN_IFERR(status);

    sql_init_create_sequence(stmt, sequence_def);
    stmt->context->entry = sequence_def;
    stmt->context->type = SQL_TYPE_CREATE_SEQUENCE;
    // parse the sequence name
    status = lex_expected_fetch_variant(stmt->session->lex, &word);
    GS_RETURN_IFERR(status);

    status = sql_convert_object_name(stmt, &word, &sequence_def->user, NULL, &sequence_def->name);
    GS_RETURN_IFERR(status);

    status = sql_parse_sequence_parameters(stmt, sequence_def, &word, GS_TRUE);
    GS_RETURN_IFERR(status);
    status = sql_check_sequence_parameters_relation(stmt, sequence_def);
    GS_RETURN_IFERR(status);

    return sql_format_sequence(stmt, sequence_def);
}
static inline status_t sql_check_sysid(word_t *word, int32 sysid)
{
    if (sysid <= 0 || sysid >= GS_EX_SYSID_END || (sysid >= GS_RESERVED_SYSID && sysid < GS_EX_SYSID_START)) {
        GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "%s must between 1 and %d or %d and %d ", W2S(word),
                              GS_RESERVED_SYSID, GS_EX_SYSID_START, GS_EX_SYSID_END);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t sql_parse_sysid(lex_t *lex, word_t *word, uint32 *id)
{
    int32 tmp_id;
    if (*id != GS_INVALID_ID32) {
        GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "duplicate %s specification", W2S(word));
        return GS_ERROR;
    }

    if (lex_expected_fetch_int32(lex, &tmp_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (sql_check_sysid(word, tmp_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    *id = (uint32)tmp_id;
    return GS_SUCCESS;
}

static status_t sql_parse_temp_table(sql_stmt_t *stmt, lex_t *lex, word_t *word, knl_table_def_t *def)
{
    if (lex_fetch(lex, word) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (word->id != KEY_WORD_COMMIT) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "COMMIT expected but %s found", W2S(word));
        return GS_ERROR;
    }

    if (lex_fetch(lex, word) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (word->id == KEY_WORD_DELETE) {
        def->type = TABLE_TYPE_TRANS_TEMP;
    } else if (word->id == KEY_WORD_PRESERVE) {
        def->type = TABLE_TYPE_SESSION_TEMP;
    } else {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "DELETE/PRESERVE expected but %s found", W2S(word));
        return GS_ERROR;
    }

    if (lex_fetch(lex, word) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (word->id != KEY_WORD_ROWS) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "ROWS expected but %s found", W2S(word));
        return GS_ERROR;
    }

    if (IS_LTT_BY_NAME(def->name.str) && def->type == TABLE_TYPE_TRANS_TEMP) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "local temporary table don't support on commit delete rows");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t sql_set_table_attrs(sql_stmt_t *stmt, knl_table_def_t *def)
{
    if (def->initrans == 0) {
        def->initrans = cm_text_str_equal_ins(&def->schema, "SYS") ? GS_INI_TRANS
                                                                   : stmt->session->knl_session.kernel->attr.initrans;
    }

    if (def->pctfree == GS_INVALID_ID32) {
        def->pctfree = GS_PCT_FREE;
    }

    if (def->cr_mode == GS_INVALID_ID8) {
        def->cr_mode = stmt->session->knl_session.kernel->attr.cr_mode;
    }

    if (def->type != TABLE_TYPE_HEAP && def->type != TABLE_TYPE_NOLOGGING) {
        if (def->csf == ROW_FORMAT_CSF) {
            GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, " not support csf for current table type.");
            return GS_ERROR;
        }
    }

    if (def->sysid != GS_INVALID_ID32 || def->csf == GS_INVALID_ID8) {
        def->csf = GS_FALSE;
        if (def->type == TABLE_TYPE_HEAP || def->type == TABLE_TYPE_NOLOGGING) {
            def->csf = (stmt->session->knl_session.kernel->attr.row_format == ROW_FORMAT_CSF);
        }
    }
    return GS_SUCCESS;
}

status_t sql_parse_table_attrs(sql_stmt_t *stmt, lex_t *lex, knl_table_def_t *def, bool32 *expect_as, word_t *word)
{
    status_t status = GS_ERROR;
    uint32 ex_flags = 0;

    def->cr_mode = GS_INVALID_ID8;
    def->pctfree = GS_INVALID_ID32;
    def->csf = GS_INVALID_ID8;

    for (;;) {
        status = lex_fetch(lex, word);
        GS_RETURN_IFERR(status);
        if (word->type == WORD_TYPE_EOF || word->id == KEY_WORD_AS) {
            break;
        }

        switch (word->id) {
            case KEY_WORD_TABLESPACE:
                status = sql_parse_space(stmt, lex, word, &def->space);
                break;

            case KEY_WORD_INITRANS:
            case KEY_WORD_MAXTRANS:
                knl_panic(0);
                break;

            case KEY_WORD_PCTFREE:
                status = sql_parse_pctfree(lex, word, &def->pctfree);
                break;

            case KEY_WORD_CRMODE:
            case KEY_WORD_FORMAT:
                knl_panic(0);
                break;

            case KEY_WORD_SYSTEM:
                status = sql_parse_sysid(lex, word, &def->sysid);
                break;

            case KEY_WORD_STORAGE:
                status = sql_parse_storage(lex, word, &def->storage_def, GS_FALSE);
                break;

            case KEY_WORD_LOB:
                knl_panic(0);
                break;

            case KEY_WORD_ON:
                if (def->type == TABLE_TYPE_HEAP) {
                    GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "ON COMMIT only used on temporary table");
                    return GS_ERROR;
                }
                if (ex_flags & TEMP_TBL_ATTR_PARSED) {
                    GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "too many option for table");
                    return GS_ERROR;
                }
                status = sql_parse_temp_table(stmt, lex, word, def);
                ex_flags |= TEMP_TBL_ATTR_PARSED;
                break;
            case KEY_WORD_APPENDONLY:
            case KEY_WORD_PARTITION:
            case KEY_WORD_AUTO_INCREMENT:
            case RES_WORD_DEFAULT:
            case KEY_WORD_CHARSET:
            case KEY_WORD_CHARACTER:
            case KEY_WORD_COLLATE:
            case KEY_WORD_CACHE:
            case KEY_WORD_NO_CACHE:
            case KEY_WORD_LOGGING:
            case KEY_WORD_NO_LOGGING:
            case KEY_WORD_COMPRESS:
            case KEY_WORD_NO_COMPRESS:
                knl_panic(0);
                break;

            default:
                GS_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "unexpected text %s", W2S(word));
                return GS_ERROR;
        }

        if (status != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    GS_RETURN_IFERR(sql_set_table_attrs(stmt, def));

    return GS_SUCCESS;
}

static inline bool8 sql_table_has_special_char(text_t *name)
{
    uint32 i;

    for (i = 0; i < name->len; i++) {
        if (name->str[i] == '\"') {
            return GS_TRUE;
        }
    }

    return GS_FALSE;
}

status_t sql_verify_table_storage(sql_stmt_t *stmt, knl_table_def_t *def)
{
    // check table type, not suppport for temprory table
    if (def->storage_def.initial > 0 || def->storage_def.maxsize) {
        if (def->type != TABLE_TYPE_HEAP && def->type != TABLE_TYPE_NOLOGGING) {
            GS_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "storage option without heap table");
            return GS_ERROR;
        }
    }

    // check table storage, initial should not large than maxsize
    if (def->storage_def.initial > 0 && def->storage_def.maxsize > 0 &&
        (def->storage_def.initial > def->storage_def.maxsize)) {
        GS_THROW_ERROR(ERR_EXCEED_SEGMENT_MAXSIZE);
        return GS_ERROR;
    }

    if (!def->parted || def->part_def == NULL) {
        return GS_SUCCESS;
    }

    knl_part_def_t *part_def = NULL;
    int64 initial;
    int64 maxsize;

    // check partition storage, initial should not large than maxsize
    for (uint32 i = 0; i < def->part_def->parts.count; i++) {
        part_def = (knl_part_def_t *)cm_galist_get(&def->part_def->parts, i);
        initial = (part_def->storage_def.initial > 0) ? (part_def->storage_def.initial) : def->storage_def.initial;
        maxsize = (part_def->storage_def.maxsize > 0) ? (part_def->storage_def.maxsize) : def->storage_def.maxsize;

        if (initial > 0 && maxsize > 0 && (initial > maxsize)) {
            GS_THROW_ERROR(ERR_EXCEED_SEGMENT_MAXSIZE);
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t sql_parse_create_table(sql_stmt_t *stmt, bool32 is_temp, bool32 has_global)
{
    word_t word;
    knl_table_def_t *def = NULL;
    lex_t *lex = stmt->session->lex;
    bool32 result = GS_FALSE;
    bool32 expect_as = GS_FALSE;
    bool32 external_table = GS_FALSE;

    GS_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(knl_table_def_t), (pointer_t *)&def));

    def->sysid = GS_INVALID_ID32;
    stmt->context->type = SQL_TYPE_CREATE_TABLE;
    lex->flags |= LEX_WITH_OWNER;

    GS_RETURN_IFERR(sql_try_parse_if_not_exists(lex, &def->options));
    GS_RETURN_IFERR(lex_expected_fetch_variant(lex, &word));

    def->type = is_temp ? TABLE_TYPE_TRANS_TEMP : TABLE_TYPE_HEAP;
    GS_RETURN_IFERR(sql_convert_object_name(stmt, &word, &def->schema, NULL, &def->name));
    if (is_temp && !has_global) {
        if (!stmt->session->knl_session.kernel->attr.enable_ltt) {
            GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR,
                              "parameter LOCAL_TEMPORARY_TABLE_ENABLED is false, can't create local temporary table");
            return GS_ERROR;
        }

        if (!knl_is_llt_by_name(def->name.str[0])) {
            GS_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR,
                                  "local temporary table name should start with '#'");
            return GS_ERROR;
        }

    } else {
        if (knl_is_llt_by_name(def->name.str[0])) {
            GS_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "table name is invalid");
            return GS_ERROR;
        }
    }

    if (sql_table_has_special_char(&def->name)) {
        GS_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "invalid variant/object name was found");
        return GS_ERROR;
    }

    cm_galist_init(&def->columns, stmt->context, sql_alloc_mem);
    cm_galist_init(&def->constraints, stmt->context, sql_alloc_mem);
    cm_galist_init(&def->indexs, stmt->context, sql_alloc_mem);
    cm_galist_init(&def->lob_stores, stmt->context, sql_alloc_mem);

    GS_RETURN_IFERR(lex_try_fetch_bracket(lex, &word, &result));
    if (result) {
        if (word.text.len == 0) {
            GS_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "column definitions expected");
            return GS_ERROR;
        }
        GS_RETURN_IFERR(lex_push(lex, &word.text));
        status_t status = sql_parse_column_defs(stmt, lex, def, &expect_as);
        lex_pop(lex);
        GS_RETURN_IFERR(status);
    }

    GS_RETURN_IFERR(lex_try_fetch(lex, "organization", &external_table));
    if (external_table) {
        knl_panic(0);
    } else {
        GS_RETURN_IFERR(sql_parse_table_attrs(stmt, lex, def, &expect_as, &word));
    }

    // syntax:1.create table (...) as select; 2.create table as select
    if (word.id == KEY_WORD_AS) {
        knl_panic(0);
    } else if (!result || expect_as) {
        // when column is not defined, as-select clause must appear
        GS_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "As-select clause expected");
        return GS_ERROR;
    }
    knl_panic(def->part_def == NULL);
    // column type may be known after as-select parsed, so delay check default/default on update verifying
    GS_RETURN_IFERR(sql_delay_verify_default(stmt, def));

    // column type may be known after as-select parsed, so delay check constraint verifying
    GS_RETURN_IFERR(sql_verify_check_constraint(stmt, def));
    GS_RETURN_IFERR(sql_create_inline_cons(stmt, def));

    GS_RETURN_IFERR(sql_verify_cons_def(def));
    GS_RETURN_IFERR(sql_verify_auto_increment(stmt, def));
    GS_RETURN_IFERR(sql_verify_array_columns(def->type, &def->columns));

    GS_RETURN_IFERR(sql_verify_table_storage(stmt, def));

    stmt->context->entry = def;
    return GS_SUCCESS;
}

status_t sql_create_global_lead(sql_stmt_t *stmt)
{
    word_t word;
    if (lex_fetch(stmt->session->lex, &word) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (word.id != KEY_WORD_TEMPORARY) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "TEMPORARY expected but %s found", W2S(&word));
        return GS_ERROR;
    }

    if (lex_fetch(stmt->session->lex, &word) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (word.id == KEY_WORD_TABLE) {
        return sql_parse_create_table(stmt, GS_TRUE, GS_TRUE);
    } else {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "TABLE expected but %s found", W2S(&word));
        return GS_ERROR;
    }
}

status_t sql_regist_ddl_table(sql_stmt_t *stmt, text_t *user, text_t *name)
{
    uint32 i;
    sql_table_entry_t *table = NULL;
    knl_handle_t knl = &stmt->session->knl_session;
    sql_context_t *context = stmt->context;

    for (i = 0; i < context->tables->count; i++) {
        table = (sql_table_entry_t *)cm_galist_get(context->tables, i);
        if (cm_text_equal(&table->name, name) && cm_text_equal(&table->user, user)) {
            return GS_SUCCESS;
        }
    }

    if (cm_galist_new(context->tables, sizeof(sql_table_entry_t), (pointer_t *)&table) != GS_SUCCESS) {
        return GS_ERROR;
    }

    table->name = *name;
    table->user = *user;

    knl_set_session_scn(knl, GS_INVALID_ID64);
    if (GS_SUCCESS != knl_open_dc(knl, user, name, &(table->dc))) {
        context->tables->count--;
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

static status_t sql_parse_user_name(sql_stmt_t *stmt, char *buf, bool32 for_user)
{
    word_t word;
    lex_t *lex = stmt->session->lex;

    GS_RETURN_IFERR(lex_expected_fetch_variant(lex, &word));

    cm_text2str_with_upper((text_t *)&word.text, buf, GS_NAME_BUFFER_SIZE);

    if (contains_nonnaming_char(buf)) {
        GS_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "invalid variant/object name was found");
        return GS_ERROR;
    }

    /* can not create user name default DBA user's name */
    if (strlen(buf) == strlen(SYS_USER_NAME) && !strncmp(buf, SYS_USER_NAME, strlen(buf))) {
        GS_SRC_THROW_ERROR(word.text.loc, ERR_FORBID_CREATE_SYS_USER);
        return GS_ERROR;
    }

    /* can not create user name default DBA user's name:CM_SYSDBA_USER_NAME */
    if (strlen(buf) == strlen(CM_SYSDBA_USER_NAME) && !strncmp(buf, CM_SYSDBA_USER_NAME, strlen(buf))) {
        GS_SRC_THROW_ERROR(word.text.loc, ERR_FORBID_CREATE_SYS_USER);
        return GS_ERROR;
    }

    /* can not create user name default DBA user's name:CM_CLSMGR_USER_NAME */
    if (strlen(buf) == strlen(CM_CLSMGR_USER_NAME) && !strncmp(buf, CM_CLSMGR_USER_NAME, strlen(buf))) {
        GS_SRC_THROW_ERROR(word.text.loc, ERR_FORBID_CREATE_SYS_USER);
        return GS_ERROR;
    }

    if (IS_COMPATIBLE_MYSQL_INST) {
        cm_text2str((text_t *)&word.text, buf, GS_NAME_BUFFER_SIZE);
    }

    return GS_SUCCESS;
}

status_t sql_parse_create_role(sql_stmt_t *stmt)
{
    word_t word;
    knl_role_def_t *def = NULL;
    lex_t *lex = stmt->session->lex;
    if (sql_alloc_mem(stmt->context, sizeof(knl_role_def_t), (void **)&def) != GS_SUCCESS) {
        return GS_ERROR;
    }

    def->owner_uid = stmt->session->knl_session.uid;
    stmt->context->type = SQL_TYPE_CREATE_ROLE;

    if (sql_parse_user_name(stmt, def->name, GS_FALSE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (lex_fetch(lex, &word) != GS_SUCCESS) {
        return GS_ERROR;
    }

    knl_panic(word.type == WORD_TYPE_EOF);
    stmt->context->entry = def;
    return GS_SUCCESS;
}

void sql_init_plan_assist_impl(sql_stmt_t *stmt, plan_assist_t *pa, sql_query_t *query, sql_node_type_t type,
                               plan_assist_t *parent)
{
    pa->stmt = stmt;
    {
        pa->cond = query->cond;
    }
    pa->type = type;
    pa->query = query;
    pa->top_pa = NULL;
    pa->cbo_flags = CBO_NONE_FLAG;
    pa->cbo_index_ast = NONE_INDEX;
    pa->col_use_flag = USE_NONE_FLAG;
    pa->spec_drive_flag = DRIVE_FOR_NONE;
    pa->has_parent_join = query->cond_has_acstor_col;
    pa->max_ancestor = 0;
    pa->no_nl_batch = GS_FALSE;
    pa->resv_outer_join = GS_FALSE;
    pa->hj_pos = 0;
    pa->sort_items = NULL;
    pa->list_expr_count = 0;
    pa->plan_count = 0;
    pa->table_count = query->tables.count;
    pa->join_assist = &query->join_assist;
    pa->join_assist->has_hash_oper = GS_FALSE;
    pa->join_oper_map = NULL;
    pa->parent = parent;
    pa->scan_part_cnt = 1;
    pa->is_final_plan = (parent == NULL) ? GS_FALSE : parent->is_final_plan;
    pa->ignore_hj = (parent == NULL) ? GS_FALSE : parent->ignore_hj;
    pa->is_subqry_cost = GS_FALSE;
    pa->join_card_map = NULL;
    pa->nlf_mtrl_cnt = 0;
    pa->nlf_dupl_plan_cnt = 0;
    pa->is_nl_full_opt = GS_FALSE;
    pa->save_plcnt = 0;
    pa->filter_node_pptr = NULL;
    pa->vpeek_flag = GS_FALSE;
}

static inline void set_query_sort_plan_flag(sql_query_t *query, uint32 *plan_flag)
{
    if (query->sort_items->count > 0) {
        if (query->order_siblings && !query->has_distinct) {
            (*plan_flag) |= EX_QUERY_SIBL_SORT;
        } else {
            (*plan_flag) |= EX_QUERY_SORT;
        }
    }
}

uint32 get_query_plan_flag(sql_query_t *query)
{
    bool32 plan_flag = 0;
    if (query->for_update != GS_FALSE) {
        plan_flag |= EX_QUERY_FOR_UPDATE;
    }

    if (query->has_distinct != GS_FALSE) {
        plan_flag |= EX_QUERY_DISTINCT;
    }

    if (query->having_cond != NULL) {
        plan_flag |= EX_QUERY_HAVING;
    }

    set_query_sort_plan_flag(query, &plan_flag);

    if (query->group_cubes != NULL) {
        plan_flag |= EX_QUERY_CUBE;
    }

    if (query->aggrs->count > 0 || query->group_sets->count > 0) {
        plan_flag |= EX_QUERY_AGGR;
    }

    if (LIMIT_CLAUSE_OCCUR(&query->limit)) {
        plan_flag |= EX_QUERY_LIMIT;
    }

    if (query->connect_by_cond != NULL) {
        plan_flag |= EX_QUERY_CONNECT;
    }
    if (query->filter_cond != NULL) {
        plan_flag |= EX_QUERY_FILTER;
    }

    if (query->winsort_list->count > 0) {
        plan_flag |= EX_QUERY_WINSORT;
    }

    // (query->cond != NULL && query->cond->rownum_upper == 0) == > rownum count
    if (QUERY_HAS_ROWNUM(query) || (query->cond != NULL && query->cond->rownum_upper == 0)) {
        plan_flag |= EX_QUERY_ROWNUM;
    }
    return plan_flag;
}

void sql_init_plan_assist(sql_stmt_t *stmt, plan_assist_t *pa, sql_query_t *query, sql_node_type_t type,
                          plan_assist_t *parent)
{
    sql_init_plan_assist_impl(stmt, pa, query, type, parent);
    for (uint32 i = 0; i < pa->table_count; i++) {
        pa->tables[i] = (sql_table_t *)sql_array_get(&query->tables, i);
        pa->plan_tables[i] = pa->tables[i];
        pa->plan_tables[i]->scan_mode = SCAN_MODE_TABLE_FULL;
        pa->plan_tables[i]->scan_flag = 0;
        pa->plan_tables[i]->index = NULL;
        pa->plan_tables[i]->plan_id = (pa->table_count > 1) ? GS_INVALID_ID32 : 0;
        pa->query->filter_infos = NULL;
        /* set table extra attr memory allocator */
        TABLE_CBO_ATTR_OWNER(pa->tables[i]) = query->vmc;
        TABLE_CBO_SET_FLAG(pa->tables[i], SELTION_NO_HASH_JOIN);
    }
    pa->max_ancestor = 0;
}

void sql_prepare_query_plan(sql_stmt_t *stmt, plan_assist_t *pa, sql_query_t *query, sql_node_type_t type,
                            plan_assist_t *parent)
{
    sql_init_plan_assist(stmt, pa, query, type, parent);

    query->has_filter_opt = GS_FALSE;
    query->extra_flags = 0;
    query->extra_flags = get_query_plan_flag(query);
}

status_t sql_create_query_plan(sql_stmt_t *stmt, sql_query_t *query, sql_node_type_t type, plan_node_t **query_plan,
                               plan_assist_t *parent)
{
    plan_node_t *plan = NULL;
    plan_assist_t pa;

    SET_NODE_STACK_CURR_QUERY(stmt, query);
    if (sql_alloc_mem(stmt->context, sizeof(plan_node_t), (void **)query_plan) != GS_SUCCESS) {
        return GS_ERROR;
    }

    plan = *query_plan;
    plan->type = PLAN_NODE_QUERY;
    plan->plan_id = stmt->context->plan_count++;
    plan->query.ref = query;

    sql_prepare_query_plan(stmt, &pa, query, type, parent);

    if (query->extra_flags != 0) {
        return GS_ERROR;
    } else {
        GS_RETURN_IFERR(sql_create_query_scan_plan(stmt, &pa, &plan->query.next));
    }

    SQL_RESTORE_NODE_STACK(stmt);
    return GS_SUCCESS;
}
static status_t sql_init_plan_range_list(sql_stmt_t *stmt, gs_type_t datatype, knl_column_t *knl_col,
                                         plan_range_list_t *list)
{
    list->type = RANGE_LIST_EMPTY;
    if (sql_alloc_mem(stmt->context, sizeof(galist_t), (void **)&list->items) != GS_SUCCESS) {
        return GS_ERROR;
    }

    cm_galist_init(list->items, stmt->context, sql_alloc_mem);

    // list->typmode.size's max value is GS_INVALID_ID16(0xFFFF)
    // now index can not be built at lob column.
    if (knl_col->size >= (uint32)GS_INVALID_ID16) {
        GS_THROW_ERROR_EX(ERR_ASSERT_ERROR, "knl_col->size(%u) < (uint32)GS_INVALID_ID16(%u)", knl_col->size,
                          (uint32)GS_INVALID_ID16);
        return GS_ERROR;
    }
    list->typmode.size = (uint16)knl_col->size;
    list->typmode.is_char = KNL_COLUMN_IS_CHARACTER(knl_col);
    list->typmode.datatype = datatype;
    return GS_SUCCESS;
}

status_t sql_create_range_list(sql_stmt_t *stmt, plan_assist_t *pa, expr_node_t *match_node, knl_column_t *knl_col,
                               cond_node_t *node, plan_range_list_t **list, bool32 index_reverse,
                               bool32 index_first_col)
{
    GS_RETURN_IFERR(sql_stack_safe(stmt));

    GS_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(plan_range_list_t), (void **)list));

    GS_RETURN_IFERR(sql_init_plan_range_list(stmt, match_node->datatype, knl_col, *list));

    switch (node->type) {
        case COND_NODE_AND:
        case COND_NODE_OR:
        case COND_NODE_TRUE:
        case COND_NODE_FALSE:
            return GS_ERROR;

        case COND_NODE_COMPARE:
            (*list)->type = RANGE_LIST_FULL;
            return GS_SUCCESS;

        default:
            return GS_ERROR;
    }
}

static status_t sql_create_partition_range_list(sql_stmt_t *stmt, plan_assist_t *pa, sql_table_t *table,
                                                sql_array_t *part_array, bool32 is_sub_part)
{
    uint16 col_id;
    expr_node_t node;
    knl_column_t *knl_col = NULL;
    plan_range_list_t *list = NULL;

    if (pa->cond == NULL) {
        return GS_SUCCESS;
    }
    uint16 key_count = is_sub_part ? knl_subpart_key_count(table->entry->dc.handle)
                                   : knl_part_key_count(table->entry->dc.handle);

    for (uint16 i = 0; i < key_count; i++) {
        col_id = is_sub_part ? knl_subpart_key_column_id(table->entry->dc.handle, i)
                             : knl_part_key_column_id(table->entry->dc.handle, i);
        knl_col = knl_get_column(table->entry->dc.handle, col_id);
        node.value.v_col.tab = table->id;
        node.value.v_col.col = col_id;
        node.value.v_col.datatype = knl_col->datatype;
        node.value.v_col.ancestor = 0;
        node.value.v_col.ss_start = GS_INVALID_ID32;
        node.value.v_col.ss_end = GS_INVALID_ID32;
        node.datatype = knl_col->datatype;
        node.unary = UNARY_OPER_NONE;
        node.type = EXPR_NODE_COLUMN;
        node.left = node.right = NULL;

        if (sql_create_range_list(stmt, pa, &node, knl_col, pa->cond->root, &list, GS_FALSE, GS_FALSE) != GS_SUCCESS) {
            return GS_ERROR;
        }
        if (sql_array_put(part_array, list) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

status_t sql_create_subpart_scan_ranges(sql_stmt_t *stmt, plan_assist_t *pa, sql_table_t *table,
                                        sql_array_t *subpart_array)
{
    if (sql_create_array(stmt->context, subpart_array, "SUBPARTITION RANGE", GS_MAX_PARTKEY_COLUMNS) != GS_SUCCESS) {
        return GS_ERROR;
    }
    return sql_create_partition_range_list(stmt, pa, table, subpart_array, GS_TRUE);
}

status_t sql_create_part_scan_ranges(sql_stmt_t *stmt, plan_assist_t *pa, sql_table_t *table, sql_array_t *array)
{
    // common table not need create part scan range
    if (!knl_is_part_table(table->entry->dc.handle)) {
        return GS_SUCCESS;
    }

    if (sql_create_array(stmt->context, array, "PARTITION RANGE", GS_MAX_PARTKEY_COLUMNS) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return sql_create_partition_range_list(stmt, pa, table, array, GS_FALSE);
}

static void check_multi_parts_index_scan(sql_table_t *table, sql_query_t *query)
{
    table->multi_parts_scan = GS_FALSE;
}

status_t sql_create_scan_ranges(sql_stmt_t *stmt, plan_assist_t *pa, sql_table_t *table, scan_plan_t *scan_plan)
{
    // not need create scan range while have no where clause or subselect or view
    if (table->type != NORMAL_TABLE) {
        return GS_SUCCESS;
    }

    GS_RETURN_IFERR(sql_create_part_scan_ranges(stmt, pa, table, &scan_plan->part_array));
    // common table not need create part scan range
    if (knl_is_compart_table(table->entry->dc.handle)) {
        GS_RETURN_IFERR(sql_create_subpart_scan_ranges(stmt, pa, table, &scan_plan->subpart_array));
    }

    check_multi_parts_index_scan(table, pa->query);

    return GS_SUCCESS;
}

static status_t sql_finalize_range_list_full(sql_stmt_t *stmt, scan_range_list_t *scan_list)
{
    scan_range_t *scan_range = NULL;

    GS_RETURN_IFERR(sql_push(stmt, sizeof(pointer_t), (void **)&scan_list->ranges));

    GS_RETURN_IFERR(sql_push(stmt, sizeof(scan_range_t), (void **)&scan_range));

    scan_range->type = RANGE_FULL;
    scan_range->left.type = BORDER_INFINITE_LEFT;
    scan_range->right.type = BORDER_INFINITE_RIGHT;
    scan_list->ranges[0] = scan_range;
    scan_list->count = 1;

    return GS_SUCCESS;
}

static bool32 if_need_finalize_range(sql_stmt_t *stmt, plan_range_list_t *plan_list, scan_range_list_t *scan_list,
                                     status_t *status)
{
    scan_list->type = plan_list->type;
    scan_list->datatype = plan_list->typmode.datatype;
    scan_list->count = 0;
    scan_list->rid = 0;
    *status = GS_SUCCESS;

    if (scan_list->type == RANGE_LIST_EMPTY) {
        return GS_FALSE;
    }

    if (scan_list->type == RANGE_LIST_FULL) {
        *status = sql_finalize_range_list_full(stmt, scan_list);
        return GS_FALSE;
    }

    if (sql_push(stmt, plan_list->items->count * sizeof(pointer_t), (void **)&scan_list->ranges) != GS_SUCCESS) {
        *status = GS_ERROR;
        return GS_FALSE;
    }

    return GS_TRUE;
}

status_t sql_finalize_range_list(sql_stmt_t *stmt, plan_range_list_t *plan_list, scan_range_list_t *scan_list,
                                 uint32 *list_flag, calc_mode_t calc_mode, uint32 *is_optm)
{
    status_t status;

    // the parameter '_INDEX_SACN_RANGE_CACHE' control this optimization's switch
    if (g_instance->sql.index_scan_range_cache == 0 ||
        plan_list->items->count < g_instance->sql.index_scan_range_cache) {
        *is_optm = GS_FALSE;
    }

    if (!if_need_finalize_range(stmt, plan_list, scan_list, &status)) {
        return status;
    }

    return GS_ERROR;
    ;
}

status_t sql_finalize_scan_range(sql_stmt_t *stmt, sql_array_t *plan_ranges, scan_list_array_t *ar, sql_table_t *table,
                                 sql_cursor_t *cursor, galist_t **list, calc_mode_t calc_mode)
{
    plan_range_list_t *plan_list = NULL;

    if (sql_push(stmt, ar->count * sizeof(scan_range_list_t), (void **)&ar->items) != GS_SUCCESS) {
        return GS_ERROR;
    }

    for (uint32 i = 0; i < ar->count; i++) {
        plan_list = (plan_range_list_t *)plan_ranges->items[i];

        {
            bool32 is_optm = GS_TRUE;
            if (sql_finalize_range_list(stmt, plan_list, &ar->items[i], &ar->flags, calc_mode, &is_optm) !=
                GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        if (ar->items[i].type == RANGE_LIST_EMPTY) {
            ar->flags |= LIST_EXIST_LIST_EMPTY;
            return GS_SUCCESS;
        }
        if (ar->items[i].type == RANGE_LIST_FULL) {
            ar->flags |= LIST_EXIST_LIST_FULL;
        }
        ar->total_ranges = i == 0 ? ar->items[i].count : ar->items[i].count * ar->total_ranges;
    }
    return GS_SUCCESS;
}
static status_t sql_create_select_plan(sql_stmt_t *stmt, select_node_t *node, plan_node_t **plan, plan_assist_t *parent)
{
    if (node->type == SELECT_NODE_QUERY) {
        return sql_create_query_plan(stmt, node->query, SQL_SELECT_NODE, plan, parent);
    }
    return GS_ERROR;
}

static void sql_get_query_rs_type(sql_select_t *select_ctx, plan_node_t *plan)
{
    select_ctx->rs_plan = plan->query.next;

    // optimize table function in making result period by putting row into send-packet directly
    // like 'select * from table(get_tab_rows(x,x,x,x,x))'
    // but any other complex query cannot.
    if (select_ctx->rs_type == RS_TYPE_ROW && plan->query.next->type == PLAN_NODE_SCAN) {
        return;
    }

    switch (plan->query.next->type) {
        case PLAN_NODE_QUERY_SORT:
            select_ctx->rs_type = RS_TYPE_SORT;
            break;
        case PLAN_NODE_QUERY_SIBL_SORT:
        case PLAN_NODE_HAVING:
        case PLAN_NODE_SORT_GROUP:
            knl_panic(0);
        case PLAN_NODE_HASH_GROUP:
            select_ctx->rs_type = RS_TYPE_HASH_GROUP;
            break;

        case PLAN_NODE_MERGE_SORT_GROUP:
        case PLAN_NODE_HASH_GROUP_PAR:
        case PLAN_NODE_SORT_DISTINCT:
        case PLAN_NODE_HASH_DISTINCT:
        case PLAN_NODE_INDEX_DISTINCT:
            knl_panic(0);
            break;

        case PLAN_NODE_QUERY_LIMIT:
            select_ctx->rs_type = RS_TYPE_LIMIT;
            break;

        case PLAN_NODE_WINDOW_SORT:
            select_ctx->rs_type = RS_TYPE_WINSORT;
            break;

        case PLAN_NODE_HASH_MTRL:
        case PLAN_NODE_GROUP_CUBE:
            knl_panic(0);
            break;

        case PLAN_NODE_ROWNUM:
            select_ctx->rs_type = RS_TYPE_ROWNUM;
            break;

        case PLAN_NODE_FOR_UPDATE:
        case PLAN_NODE_WITHAS_MTRL:
            knl_panic(0);
            break;

        default:
            if (plan->query.ref->aggrs->count > 0) {
                select_ctx->rs_type = RS_TYPE_AGGR;
            } else {
                select_ctx->rs_type = RS_TYPE_NORMAL;
            }
            break;
    }
}

static void sql_select_get_rs_type(sql_select_t *select_ctx, select_plan_t *select_p)
{
    select_ctx->rs_plan = select_p->next;

    switch (select_p->next->type) {
        case PLAN_NODE_UNION:
            select_ctx->rs_type = RS_TYPE_UNION;
            break;

        case PLAN_NODE_UNION_ALL:
            select_ctx->rs_type = RS_TYPE_UNION_ALL;
            break;

        case PLAN_NODE_MINUS:
            select_ctx->rs_type = RS_TYPE_MINUS;
            break;

        case PLAN_NODE_HASH_MINUS:
            knl_panic(0);
            break;

        case PLAN_NODE_SELECT_SORT:
            select_ctx->rs_type = RS_TYPE_SORT;
            break;

        case PLAN_NODE_SELECT_LIMIT:
            select_ctx->rs_type = RS_TYPE_LIMIT;
            break;

        default:
            sql_get_query_rs_type(select_ctx, select_p->next);
            break;
    }
}

status_t sql_generate_select_plan(sql_stmt_t *stmt, sql_select_t *select_ctx, plan_assist_t *parent)
{
    select_plan_t *select_p = NULL;

    if (select_ctx->plan != NULL || select_ctx->type == SELECT_AS_SET) {
        return GS_ERROR;
    }

    GS_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(plan_node_t), (void **)&select_ctx->plan));

    select_ctx->plan->type = PLAN_NODE_SELECT;
    select_ctx->plan->plan_id = stmt->context->plan_count++;
    select_p = &select_ctx->plan->select_p;
    select_p->select = select_ctx;

    knl_panic(!LIMIT_CLAUSE_OCCUR(&select_ctx->limit) && !select_ctx->select_sort_items);
    GS_RETURN_IFERR(sql_create_select_plan(stmt, select_ctx->root, &select_p->next, parent));
    sql_select_get_rs_type(select_ctx, select_p);
    if (select_ctx->type == SELECT_AS_TABLE) {
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

#define MATCH_LOCAL_WITHAS(t, v) ((t)->session->withas_subquery == (v))
#define MATCH_GLOBAL_WITHAS(t, v) \
    ((t)->session->withas_subquery == WITHAS_UNSET && g_instance->sql.withas_subquery == (v))
#define MATCH_WITHAS_SUBQUERY(t, v) (MATCH_LOCAL_WITHAS(t, v) || MATCH_GLOBAL_WITHAS(t, v))

status_t sql_create_dml_plan(sql_stmt_t *stmt)
{
    void *entry = stmt->context->entry;
    status_t ret = GS_SUCCESS;
    plan_assist_t *parent = NULL;
    SQL_LOG_OPTINFO(stmt, ">>> Begin create DML plan, SQL = %s", T2S(&stmt->session->lex->text.value));

    SAVE_AND_RESET_NODE_STACK(stmt);
    stmt->context->plan_count = 0;
    switch (stmt->context->type) {
        case SQL_TYPE_SELECT:
            ret = sql_generate_select_plan(stmt, (sql_select_t *)entry, parent);
            break;
        case SQL_TYPE_INSERT:
        case SQL_TYPE_DELETE:
        case SQL_TYPE_UPDATE:
        case SQL_TYPE_REPLACE:
        default:
            ret = GS_ERROR;
            break;
    }

    if (ret != GS_SUCCESS) {
        return GS_ERROR;
    }

    SQL_RESTORE_NODE_STACK(stmt);

    return GS_SUCCESS;
}
#define SQL_RETURN_IF_CBO(stmt, table, pa)         \
    do {                                           \
        if (sql_match_cbo_cond(stmt, table, pa)) { \
            return GS_SUCCESS;                     \
        }                                          \
    } while (0)

status_t sql_check_table_indexable(sql_stmt_t *stmt, plan_assist_t *pa, sql_table_t *table, cond_tree_t *cond)
{
    knl_panic(table->type == NORMAL_TABLE);

    sql_init_table_indexable(table, NULL);

    return GS_SUCCESS;  // don't use index
}

static status_t sql_create_scan_plan(sql_stmt_t *stmt, plan_assist_t *pa, cond_tree_t *cond, sql_table_t *table,
                                     plan_node_t **plan)
{
    plan_node_t *scan_plan = NULL;

    if (sql_alloc_mem(stmt->context, sizeof(plan_node_t), (void **)&scan_plan) != GS_SUCCESS) {
        return GS_ERROR;
    }

    *plan = scan_plan;
    pa->cond = cond;
    scan_plan->type = PLAN_NODE_SCAN;
    scan_plan->plan_id = stmt->context->plan_count++;
    scan_plan->scan_p.table = table;
    scan_plan->scan_p.par_exec = GS_FALSE;
    scan_plan->scan_p.sort_items = pa->sort_items;
    scan_plan->cost = table->cost;
    scan_plan->rows = table->card;

    return sql_create_scan_ranges(stmt, pa, table, &scan_plan->scan_p);
}

status_t sql_create_table_scan_plan(sql_stmt_t *stmt, plan_assist_t *pa, cond_tree_t *cond, sql_table_t *table,
                                    plan_node_t **plan)
{
    plan_node_t *scan_plan = NULL;

    GS_RETURN_IFERR(sql_create_scan_plan(stmt, pa, cond, table, &scan_plan));
    if (table->sub_tables == NULL) {
        *plan = scan_plan;
        return GS_SUCCESS;
    }
    return GS_ERROR;
}

status_t sql_create_query_scan_plan(sql_stmt_t *stmt, plan_assist_t *pa, plan_node_t **plan)
{
    if (pa->table_count > 1) {
        return GS_ERROR;
    }

    pa->has_parent_join = (bool8)pa->query->cond_has_acstor_col;
    CBO_SET_FLAGS(pa, CBO_CHECK_FILTER_IDX | CBO_CHECK_JOIN_IDX);
    GS_RETURN_IFERR(sql_check_table_indexable(stmt, pa, pa->tables[0], pa->cond));
    if (pa->query->join_card == GS_INVALID_INT64) {
        pa->query->join_card = TABLE_CBO_FILTER_ROWS(pa->tables[0]);
    }

    pa->cbo_flags = CBO_NONE_FLAG;
    return sql_create_table_scan_plan(stmt, pa, pa->cond, pa->tables[0], plan);
}

void sql_prepare_scan(sql_stmt_t *stmt, knl_dictionary_t *dc, knl_cursor_t *cursor)
{
    cursor->stmt = stmt;
    cursor->query_scn = stmt->query_scn;

    if (dc->type == DICT_TYPE_TEMP_TABLE_SESSION || dc->type == DICT_TYPE_TEMP_TABLE_TRANS) {
        cursor->ssn = stmt->ssn;
    } else {
        cursor->ssn = stmt->xact_ssn;
    }
}

static status_t sql_create_full_part_scan_keys(sql_stmt_t *stmt, scan_plan_t *plan, sql_table_cursor_t *cursor,
                                               knl_handle_t handle, calc_mode_t calc_mode)
{
    cursor->curr_part.left = 0;
    cursor->curr_part.right = knl_part_count(handle);
    if (!knl_is_compart_table(handle)) {
        return GS_SUCCESS;
    }

    return GS_ERROR;
}

static status_t sql_create_part_scan_keys(sql_stmt_t *stmt, scan_plan_t *plan, sql_table_cursor_t *cursor,
                                          knl_handle_t handle, scan_list_array_t *ar, calc_mode_t calc_mode)
{
    cursor->curr_subpart.left = GS_INVALID_ID32;
    cursor->curr_subpart.right = GS_INVALID_ID32;
    cursor->curr_subpart.parent_partno = GS_INVALID_ID32;

    return sql_create_full_part_scan_keys(stmt, plan, cursor, handle, calc_mode);
}

static bool32 sql_load_part_scan_key(sql_table_cursor_t *cursor)
{
    char *buf = NULL;
    uint32 len;

    if (cursor->part_set.key_data == NULL) {
        return GS_FALSE;
    }

    buf = (char *)cursor->part_set.key_data;
    len = *(uint32 *)buf;

    if (cursor->part_set.offset >= len) {
        return GS_FALSE;
    }

    cursor->curr_part = *(part_scan_key_t *)(buf + cursor->part_set.offset);
    cursor->part_set.offset += sizeof(part_scan_key_t);

    knl_handle_t handle = cursor->table->entry->dc.handle;
    if (knl_is_compart_table(handle)) {
        if (cursor->table->index_dsc) {
            cursor->part_scan_index = cursor->curr_part.sub_scan_key->count - 1;
        } else {
            cursor->part_scan_index = 0;
        }
    }

    return GS_TRUE;
}

static knl_part_locate_t sql_fetch_next_part_asc(sql_table_cursor_t *cursor)
{
    knl_handle_t handle = cursor->table->entry->dc.handle;
    knl_part_locate_t part_loc = { .part_no = GS_INVALID_ID32, .subpart_no = GS_INVALID_ID32 };

    if (knl_is_compart_table(handle)) {
        return part_loc;
    }

    if (cursor->curr_part.left >= cursor->curr_part.right) {
        if (!sql_load_part_scan_key(cursor)) {
            return part_loc;
        }
    }

    while (cursor->curr_part.left < cursor->curr_part.right) {
        part_loc.part_no = cursor->curr_part.left++;
        if (IS_REAL_PART(cursor->table->entry->dc.handle, part_loc.part_no)) {
            break;
        }
    }
    part_loc.subpart_no = GS_INVALID_ID32;
    return part_loc;
}

knl_part_locate_t sql_fetch_next_part(sql_table_cursor_t *cursor)
{
    knl_part_locate_t part_loc = { .part_no = GS_INVALID_ID32, .subpart_no = GS_INVALID_ID32 };

    if (cursor->part_set.type == KEY_SET_EMPTY) {
        return part_loc;
    }

    return sql_fetch_next_part_asc(cursor);
}

static bool32 sql_set_table_scan_key(sql_table_cursor_t *cursor)
{
    knl_part_locate_t part_loc;

    if (cursor->knl_cur->scan_mode == SCAN_MODE_INDEX && !cursor->multi_parts_info.stop_index_key) {
        knl_panic(0);
    }

    if (!knl_is_part_table(cursor->table->entry->dc.handle)) {
        return GS_TRUE;
    }

    if (cursor->knl_cur->scan_mode == SCAN_MODE_INDEX && !cursor->table->index->parted) {
        knl_panic(0);
        return GS_TRUE;
    }

    part_loc = sql_fetch_next_part(cursor);
    if (part_loc.part_no == GS_INVALID_ID32) {
        return GS_FALSE;
    }

    cursor->knl_cur->part_loc = part_loc;
    return GS_TRUE;
}

static inline status_t pre_set_knl_cur(sql_stmt_t *stmt, sql_table_cursor_t *tab_cur, knl_cursor_t *knl_cur)
{
    // table func set partno
    if (tab_cur->table->func.desc != NULL) {
        knl_panic(0);
    }

    // sql parallel scan set partno
    if (tab_cur->scan_flag > SEQ_TFM_SCAN) {
        knl_cur->part_loc = tab_cur->range.part_loc;
    }

    return GS_SUCCESS;
}

static inline status_t set_knl_cur(sql_stmt_t *stmt, sql_table_cursor_t *tab_cur, knl_session_t *knl_ses,
                                   knl_cursor_t *knl_cur)
{
    // table func set scan range
    if (tab_cur->table->func.desc != NULL) {
        knl_panic(0);
    }

    // sql parallel scan set scan range
    if (tab_cur->scan_flag > SEQ_TFM_SCAN) {
        knl_set_table_scan_range(knl_ses, knl_cur, *(page_id_t *)(&tab_cur->range.l_page),
                                 *(page_id_t *)(&tab_cur->range.r_page));
    }

    return GS_SUCCESS;
}

status_t sql_execute_table_scan(sql_stmt_t *stmt, sql_table_cursor_t *cursor)
{
    if (GS_IS_SUBSELECT_TABLE(cursor->table->type)) {
        return sql_execute_select_plan(stmt, cursor->sql_cur, cursor->sql_cur->plan->select_p.next);
    }

    knl_dictionary_t *dc = &cursor->table->entry->dc;
    knl_cursor_t *knl_cur = cursor->knl_cur;
    knl_cur->scan_mode = SCAN_MODE_TABLE_FULL;
    knl_cur->index_slot = INVALID_INDEX_SLOT;
    knl_cur->index_flag = 0;

    if (!sql_set_table_scan_key(cursor)) {
        knl_cur->eof = GS_TRUE;
        return GS_SUCCESS;
    }

    // scan as table function
    GS_RETURN_IFERR(pre_set_knl_cur(stmt, cursor, knl_cur));

    GS_RETURN_IFERR(knl_open_cursor(&stmt->session->knl_session, knl_cur, dc));

    GS_RETURN_IFERR(set_knl_cur(stmt, cursor, &stmt->session->knl_session, knl_cur));

    sql_prepare_scan(stmt, dc, knl_cur);

    if (cursor->scn != GS_INVALID_ID64) {
        if (cursor->scn <= dc->chg_scn) {
            GS_THROW_ERROR(ERR_DEF_CHANGED, T2S(&cursor->table->user), T2S_EX(&cursor->table->name));
            return GS_ERROR;
        }

        /* * for flashback query, we should not run under transaction */
        knl_cur->xid = GS_INVALID_ID64;
        knl_cur->query_scn = cursor->scn;
        if (knl_cur->isolevel == (uint8)ISOLATION_CURR_COMMITTED) {
            knl_cur->isolevel = (uint8)ISOLATION_READ_COMMITTED;
        }
    }

    return GS_SUCCESS;
}

static void sql_init_part_scan_keys(sql_table_cursor_t *cursor)
{
    cursor->part_set.type = KEY_SET_NORMAL;
    cursor->part_set.key_data = NULL;
    cursor->part_scan_index = 0;
    cursor->curr_part.left = GS_INVALID_ID32;
    cursor->curr_part.right = GS_INVALID_ID32;
    cursor->curr_part.parent_partno = GS_INVALID_ID32;
    cursor->curr_part.sub_scan_key = NULL;
    cursor->curr_subpart.left = GS_INVALID_ID32;
    cursor->curr_subpart.right = GS_INVALID_ID32;
    cursor->curr_subpart.parent_partno = GS_INVALID_ID32;
}

static bool32 sql_check_part_full_scan(sql_table_t *table, scan_list_array_t *part_array, bool32 is_subpart)
{
    if (part_array->flags & (LIST_EXIST_LIST_UNKNOWN | LIST_EXIST_LIST_ANY)) {
        return GS_TRUE;
    }

    knl_handle_t handle = table->entry->dc.handle;
    part_type_t part_type = is_subpart ? knl_subpart_table_type(handle) : knl_part_table_type(handle);
    if (part_type == PART_TYPE_RANGE) {
        return (part_array->items[0].type == RANGE_LIST_FULL);
    } else if (part_type == PART_TYPE_HASH) {
        return (part_array->flags & (LIST_EXIST_RANGE_UNEQUAL | LIST_EXIST_LIST_FULL));
    }

    // for PART_TYPE_LIST
    bool32 full_scan = GS_TRUE;
    for (uint32 i = 0; i < part_array->count; i++) {
        if (part_array->items[i].type != RANGE_LIST_FULL) {
            full_scan = GS_FALSE;
        } else {
            part_array->flags |= LIST_EXIST_RANGE_UNEQUAL;
        }
    }
    return full_scan;
}

static bool32 inline array_is_exist_empty(uint32 flags, sql_table_cursor_t *cursor)
{
    if (flags & LIST_EXIST_LIST_EMPTY) {
        cursor->part_set.type = KEY_SET_EMPTY;
        return GS_TRUE;
    }
    return GS_FALSE;
}

status_t sql_make_part_scan_keys(sql_stmt_t *stmt, scan_plan_t *plan, sql_table_cursor_t *cursor,
                                 sql_cursor_t *sql_cursor, calc_mode_t calc_mode)
{
    galist_t **list = NULL;
    scan_list_array_t part_array = { 0 };
    knl_handle_t handle = cursor->table->entry->dc.handle;

    sql_init_part_scan_keys(cursor);
    if (cursor->table->part_info.type != SPECIFY_PART_NONE) {
        knl_panic(0);
        return GS_ERROR;
    }

    if (plan->part_array.count == 0) {
        cursor->part_set.type = KEY_SET_FULL;
        GS_RETURN_IFERR(sql_create_part_scan_keys(stmt, plan, cursor, handle, &part_array, calc_mode));
        if (!knl_is_compart_table(handle)) {
            return GS_SUCCESS;
        }

        return GS_ERROR;
    }

    part_array.count = knl_part_key_count(handle);

    if (sql_cursor != NULL) {
        list = &sql_cursor->exec_data.part_scan_range_ar;
    }

    GS_RETURN_IFERR(sql_finalize_scan_range(stmt, &plan->part_array, &part_array, cursor->table, sql_cursor, list,
                                            CALC_IN_EXEC_PART_KEY));

    GS_RETSUC_IFTRUE(array_is_exist_empty(part_array.flags, cursor));

    if (sql_check_part_full_scan(cursor->table, &part_array, GS_FALSE)) {
        cursor->part_set.type = KEY_SET_FULL;
    }

    GS_RETURN_IFERR(sql_create_part_scan_keys(stmt, plan, cursor, handle, &part_array, calc_mode));
    if (knl_is_compart_table(handle) && cursor->part_set.type != KEY_SET_EMPTY) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t sql_scan_normal_table(sql_stmt_t *stmt, sql_table_t *table, sql_table_cursor_t *tab_cur, plan_node_t *plan,
                               sql_cursor_t *cursor)
{
    if (knl_is_part_table(table->entry->dc.handle)) {
        SQL_SAVE_STACK(stmt);

        if (sql_make_part_scan_keys(stmt, &plan->scan_p, tab_cur, cursor, CALC_IN_EXEC) != GS_SUCCESS) {
            SQL_RESTORE_STACK(stmt);
            return GS_ERROR;
        }
        SQL_RESTORE_STACK(stmt);
    }

    if (table->scan_mode == SCAN_MODE_INDEX) {
        knl_panic(0);
    } else if (table->scan_mode == SCAN_MODE_TABLE_FULL) {
        return sql_execute_table_scan(stmt, tab_cur);
    } else if (table->scan_mode == SCAN_MODE_ROWID) {
        knl_panic(0);
    }
    return GS_SUCCESS;
}

status_t sql_execute_scan(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    CM_TRACE_BEGIN;
    sql_table_t *table = plan->scan_p.table;
    sql_table_cursor_t *tab_cur = &cursor->tables[table->id];

    GS_RETURN_IFERR(sql_stack_safe(stmt));
    tab_cur->table = table;
    tab_cur->scan_mode = table->scan_mode;
    knl_panic(table->type == NORMAL_TABLE);
    {
        GS_RETURN_IFERR(sql_scan_normal_table(stmt, table, tab_cur, plan, cursor));
    }
    CM_TRACE_END(stmt, plan->plan_id);
    return GS_SUCCESS;
}

status_t sql_get_trig_kernel_value(sql_stmt_t *stmt, row_head_t *row, uint16 *offsets, uint16 *lens,
                                   var_column_t *v_col, variant_t *value)
{
    char *ptr = NULL;
    uint32 len;

    value->is_null = GS_FALSE;
    len = v_col->col >= ROW_COLUMN_COUNT(row) ? GS_NULL_VALUE_LEN : lens[v_col->col];
    ptr = (char *)row + offsets[v_col->col];

    return sql_get_row_value(stmt, ptr, len, v_col, value, GS_TRUE);
}

static inline status_t sql_get_lob_row_value(char *ptr, uint32 len, variant_t *value, bool8 set_lob_nodeid)
{
    value->v_lob.type = *(uint32 *)(ptr + sizeof(uint32));

    if (value->v_lob.type == GS_LOB_FROM_KERNEL) {
        value->v_lob.knl_lob.bytes = (uint8 *)ptr;
        value->v_lob.knl_lob.size = len;
        value->v_lob.knl_lob.is_hex_const = GS_FALSE;
    } else if (value->v_lob.type == GS_LOB_FROM_VMPOOL) {
        value->v_lob.vm_lob = *(vm_lob_t *)ptr;
    } else {
        GS_THROW_ERROR(ERR_UNKNOWN_LOB_TYPE, "get lob row value");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static inline gs_type_t sql_get_value_type(var_column_t *v_col, bool8 is_array_elem, void *ptr)
{
    if (SECUREC_UNLIKELY(v_col->is_array == GS_TRUE)) {
        return GS_TYPE_ARRAY;
    }

    if (SECUREC_UNLIKELY(is_array_elem == GS_TRUE)) {
        uint32 lob_type = *(uint32 *)((char *)ptr + sizeof(uint32));
        if (lob_type == GS_LOB_FROM_KERNEL || lob_type == GS_LOB_FROM_VMPOOL) {
            return GS_TYPE_ARRAY;
        }
    }

    return v_col->datatype;
}

status_t sql_get_row_value(sql_stmt_t *stmt, char *ptr, uint32 len, var_column_t *v_col, variant_t *value,
                           bool8 set_lob_nodeid)
{
    bool8 is_array_elem = VAR_COL_IS_ARRAY_ELEMENT(v_col);

    /* get data type of value */
    value->type = sql_get_value_type(v_col, is_array_elem, ptr);

    /* value is null */
    if (len == GS_NULL_VALUE_LEN) {
        if (SECUREC_UNLIKELY(is_array_elem == GS_TRUE)) {
            /* for example, f1 int[] is array type and f1[1] is int type */
            value->type = v_col->datatype;
        }
        value->is_null = GS_TRUE;
        return GS_SUCCESS;
    }

    /* value is not null */
    value->is_null = GS_FALSE;
    switch ((gs_type_t)value->type) {
        case GS_TYPE_UINT32:
            VALUE(uint32, value) = *(uint32 *)ptr;
            break;

        case GS_TYPE_INTEGER:
            VALUE(int32, value) = *(int32 *)ptr;
            break;

        case GS_TYPE_BOOLEAN:
            VALUE(bool32, value) = *(bool32 *)ptr;
            break;

        case GS_TYPE_BIGINT:
            if (len == sizeof(int32)) {
                VALUE(int64, value) = (int64)(*(int32 *)ptr);
                break;
            }
            // fall through
        case GS_TYPE_DATE:
        case GS_TYPE_TIMESTAMP:
        case GS_TYPE_TIMESTAMP_TZ_FAKE:
            VALUE(int64, value) = *(int64 *)ptr;
            break;

        case GS_TYPE_TIMESTAMP_LTZ:
            VALUE(timestamp_ltz_t, value) = *(timestamp_ltz_t *)ptr;
            break;

        case GS_TYPE_TIMESTAMP_TZ:
            VALUE(timestamp_tz_t, value) = *(timestamp_tz_t *)ptr;
            break;

        case GS_TYPE_INTERVAL_DS:
            VALUE(interval_ds_t, value) = *(interval_ds_t *)ptr;
            break;

        case GS_TYPE_INTERVAL_YM:
            VALUE(interval_ym_t, value) = *(interval_ym_t *)ptr;
            break;

        case GS_TYPE_REAL:
            VALUE(double, value) = *(double *)ptr;
            break;

        case GS_TYPE_NUMBER:
        case GS_TYPE_DECIMAL:
            (void)cm_dec_4_to_8(VALUE_PTR(dec8_t, value), (dec4_t *)ptr, len);
            break;
        case GS_TYPE_NUMBER2:
            GS_RETURN_IFERR(cm_dec_2_to_8(VALUE_PTR(dec8_t, value), (const payload_t *)ptr, len));
            break;

        case GS_TYPE_STRING:
        case GS_TYPE_CHAR:
        case GS_TYPE_VARCHAR:
            VALUE_PTR(text_t, value)->str = ptr;
            VALUE_PTR(text_t, value)->len = len;
            break;

        case GS_TYPE_CLOB:
        case GS_TYPE_BLOB:
        case GS_TYPE_IMAGE:
            GS_RETURN_IFERR(sql_get_lob_row_value(ptr, len, value, set_lob_nodeid));
            break;

        case GS_TYPE_ARRAY:
            return GS_ERROR;
            break;

        default:
            VALUE_PTR(binary_t, value)->bytes = (uint8 *)ptr;
            VALUE_PTR(binary_t, value)->size = len;
            VALUE_PTR(binary_t, value)->is_hex_const = GS_FALSE;
            break;
    }

    return GS_SUCCESS;
}

status_t sql_get_ddm_kernel_value(sql_stmt_t *stmt, sql_table_t *table, knl_cursor_t *knl_cur, var_column_t *v_col,
                                  variant_t *value)
{
    return sql_get_kernel_value(stmt, table, knl_cur, v_col, value);
}

status_t sql_get_kernel_value(sql_stmt_t *stmt, sql_table_t *table, knl_cursor_t *knl_cur, var_column_t *v_col,
                              variant_t *value)
{
    bool32 exist = GS_FALSE;
    uint32 i = 0;
    char *ptr = NULL;
    uint32 len;
    uint16 id;

    /* knl_cursor is eof, return NULL value */
    if (knl_cur->eof) {
        value->type = (v_col->is_array == GS_TRUE) ? GS_TYPE_ARRAY : v_col->datatype;
        value->is_null = GS_TRUE;
        return GS_SUCCESS;
    }

    id = (knl_cur->index_only && table != NULL) ? table->idx_col_map[v_col->col] : v_col->col;

    if (knl_cur->action == CURSOR_ACTION_UPDATE && stmt->is_check) {
        knl_update_info_t *ui = &knl_cur->update_info;
        for (i = 0; i < ui->count; i++) {
            if (id == ui->columns[i]) {
                exist = GS_TRUE;
                break;
            }
        }
    }

    if (exist) {
        len = CURSOR_UPDATE_COLUMN_SIZE(knl_cur, i);
        ptr = CURSOR_UPDATE_COLUMN_DATA(knl_cur, i);
    } else {
        len = CURSOR_COLUMN_SIZE(knl_cur, id);
        ptr = CURSOR_COLUMN_DATA(knl_cur, id);
    }

    bool8 is_array_elem = VAR_COL_IS_ARRAY_ELEMENT(v_col);
    /* get data type of value */
    value->type = sql_get_value_type(v_col, is_array_elem, ptr);

    /* value is null */
    if (len == GS_NULL_VALUE_LEN) {
        if (SECUREC_UNLIKELY(is_array_elem == GS_TRUE)) {
            /* for example, f1 int[] is array type and f1[1] is int type */
            value->type = v_col->datatype;
        }
        value->is_null = GS_TRUE;
        return GS_SUCCESS;
    }

    /* value is not null */
    value->is_null = GS_FALSE;
    switch ((gs_type_t)value->type) {
        case GS_TYPE_UINT32:
            VALUE(uint32, value) = *(uint32 *)ptr;
            break;

        case GS_TYPE_INTEGER:
            VALUE(int32, value) = *(int32 *)ptr;
            break;

        case GS_TYPE_BOOLEAN:
            VALUE(bool32, value) = *(bool32 *)ptr;
            break;

        case GS_TYPE_BIGINT:
            if (len == sizeof(int32)) {
                VALUE(int64, value) = (int64)(*(int32 *)ptr);
                break;
            }
            // fall through
        case GS_TYPE_DATE:
        case GS_TYPE_TIMESTAMP:
        case GS_TYPE_TIMESTAMP_TZ_FAKE:
            VALUE(int64, value) = *(int64 *)ptr;
            break;

        case GS_TYPE_TIMESTAMP_LTZ:
            VALUE(timestamp_ltz_t, value) = *(timestamp_ltz_t *)ptr;
            break;

        case GS_TYPE_TIMESTAMP_TZ:
            VALUE(timestamp_tz_t, value) = *(timestamp_tz_t *)ptr;
            break;

        case GS_TYPE_INTERVAL_DS:
            VALUE(interval_ds_t, value) = *(interval_ds_t *)ptr;
            break;

        case GS_TYPE_INTERVAL_YM:
            VALUE(interval_ym_t, value) = *(interval_ym_t *)ptr;
            break;

        case GS_TYPE_REAL:
            VALUE(double, value) = *(double *)ptr;
            break;

        case GS_TYPE_NUMBER:
        case GS_TYPE_DECIMAL:
            (void)cm_dec_4_to_8(VALUE_PTR(dec8_t, value), (dec4_t *)ptr, len);
            break;

        case GS_TYPE_NUMBER2:
            GS_RETURN_IFERR(cm_dec_2_to_8(VALUE_PTR(dec8_t, value), (const payload_t *)ptr, len));
            break;

        case GS_TYPE_STRING:
        case GS_TYPE_CHAR:
        case GS_TYPE_VARCHAR:
            VALUE_PTR(text_t, value)->str = ptr;
            VALUE_PTR(text_t, value)->len = len;
            break;

        case GS_TYPE_CLOB:
        case GS_TYPE_BLOB:
        case GS_TYPE_IMAGE:
            GS_RETURN_IFERR(sql_get_lob_row_value(ptr, len, value, GS_TRUE));
            break;

        case GS_TYPE_ARRAY:
            return GS_ERROR;

        default:
            VALUE_PTR(binary_t, value)->bytes = (uint8 *)ptr;
            VALUE_PTR(binary_t, value)->size = len;
            VALUE_PTR(binary_t, value)->is_hex_const = GS_FALSE;
            break;
    }
    return GS_SUCCESS;
}

bool32 sql_try_fetch_next_part(sql_table_cursor_t *cursor)
{
    knl_part_locate_t part_loc;
    knl_handle_t dc_entity = cursor->table->entry->dc.handle;

    if (!knl_is_part_table(dc_entity) ||
        (cursor->knl_cur->scan_mode == SCAN_MODE_INDEX && !cursor->table->index->parted) ||
        (cursor->knl_cur->scan_mode == SCAN_MODE_ROWID) || (cursor->scan_flag > SEQ_TFM_SCAN)) {
        return GS_FALSE;
    }

    part_loc = sql_fetch_next_part(cursor);
    if (part_loc.part_no == GS_INVALID_ID32) {
        return GS_FALSE;
    }
    cursor->knl_cur->part_loc = part_loc;

    knl_panic(cursor->knl_cur->scan_mode == SCAN_MODE_TABLE_FULL);
    return GS_TRUE;
}

status_t sql_try_switch_part(sql_stmt_t *stmt, sql_table_cursor_t *tab_cur, sql_table_t *table, bool32 *result)
{
    *result = sql_try_fetch_next_part(tab_cur);
    if (!(*result)) {
        return GS_SUCCESS;
    }
    return knl_reopen_cursor(KNL_SESSION(stmt), tab_cur->knl_cur, &table->entry->dc);
}

status_t sql_fetch_one_part(sql_stmt_t *stmt, sql_table_cursor_t *tab_cur, sql_table_t *table)
{
    for (;;) {
        GS_RETURN_IFERR(knl_fetch(KNL_SESSION(stmt), tab_cur->knl_cur));
        return GS_SUCCESS;
    }
}

static status_t sql_fetch_table_scan(sql_stmt_t *stmt, sql_table_cursor_t *tab_cur, sql_table_t *table)
{
    bool32 result = GS_FALSE;

    for (;;) {
        GS_RETURN_IFERR(sql_fetch_one_part(stmt, tab_cur, table));
        if (tab_cur->knl_cur->eof) {
            GS_RETURN_IFERR(sql_try_switch_part(stmt, tab_cur, table, &result));
            if (result) {
                continue;
            }
            sql_free_varea_set(tab_cur);
        }
        return GS_SUCCESS;
    }
}

static inline status_t sql_fetch_normal_scan(sql_stmt_t *stmt, sql_table_t *table, sql_table_cursor_t *tab_cur,
                                             bool32 *eof)
{
    GS_RETURN_IFERR(sql_fetch_table_scan(stmt, tab_cur, table));
    *eof = (bool32)tab_cur->knl_cur->eof;

    return GS_SUCCESS;
}

status_t sql_fetch_scan(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof)
{
    sql_table_t *table = plan->scan_p.table;
    sql_table_cursor_t *tab_cur = &cursor->tables[table->id];
    CM_TRACE_BEGIN;

    if (cursor->eof) {
        *eof = GS_TRUE;
        return GS_SUCCESS;
    }

    SQL_CHECK_SESSION_VALID_FOR_RETURN(stmt);

    if (table->type != NORMAL_TABLE) {
        knl_panic(0);
    } else if (table->multi_parts_scan) {
        knl_panic(0);
    } else {
        GS_RETURN_IFERR(sql_fetch_normal_scan(stmt, table, tab_cur, eof));
    }
    CM_TRACE_END(stmt, plan->plan_id);
    return GS_SUCCESS;
}

bool32 can_print_subpart_no(sql_table_cursor_t *cursor)
{
    if (!knl_is_compart_table(cursor->table->entry->dc.handle)) {
        return GS_FALSE;
    }
    char *buf = (char *)cursor->part_set.key_data;
    if ((buf != NULL && cursor->part_set.offset >= *(uint32 *)buf) ||
        (cursor->curr_part.right - cursor->curr_part.left != 1)) {
        return GS_FALSE;
    }
    if (cursor->curr_subpart.right - cursor->curr_subpart.left == 1) {
        return GS_TRUE;
    }
    return GS_FALSE;
}

void sql_print_part_info(sql_table_cursor_t *cursor, char *buf, uint32 size, uint32 *offset)
{
    int32 iret_snprintf;
    do {
        iret_snprintf = snprintf_s(buf + *offset, size - *offset, size - *offset - 1, "[%u,%u),",
                                   cursor->curr_part.left, cursor->curr_part.right);
        if (iret_snprintf == -1) {
            GS_THROW_ERROR(ERR_SYSTEM_CALL, iret_snprintf);
            break;
        }
        *offset += iret_snprintf;
    } while (sql_load_part_scan_key(cursor));
    buf[*offset - 1] = '\0';
}

void sql_print_subpart_info(sql_table_cursor_t *cursor, char *buf, uint32 size, uint32 *offset)
{
    int32 iret_snprintf;
    iret_snprintf = snprintf_s(buf + *offset, size - *offset, size - *offset - 1, "{[%u,%u):[%u,%u)}",
                               cursor->curr_part.left, cursor->curr_part.right, cursor->curr_subpart.left,
                               cursor->curr_subpart.right);
    if (iret_snprintf == -1) {
        GS_THROW_ERROR(ERR_SYSTEM_CALL, iret_snprintf);
        return;
    }
    (*offset) += iret_snprintf;
    buf[(*offset)++] = '\0';
}

static status_t sql_adjust_ancestor_in_col(visit_assist_t *va, expr_node_t **node)
{
    if ((*node)->type == EXPR_NODE_COLUMN) {
        (*node)->value.v_col.ancestor = 0;
    }
    return GS_SUCCESS;
}

void rbo_adjust_ancestor_in_expr(sql_stmt_t *stmt, expr_node_t **node)
{
    visit_assist_t va;
    sql_init_visit_assist(&va, stmt, NULL);
    (void)visit_expr_node(&va, node, sql_adjust_ancestor_in_col);
}

status_t sql_row_put_value(sql_stmt_t *stmt, row_assist_t *ra, variant_t *value)
{
    switch (value->type) {
        case GS_TYPE_UINT32:
            return row_put_uint32(ra, VALUE(uint32, value));

        case GS_TYPE_INTEGER:
            return row_put_int32(ra, VALUE(int32, value));

        case GS_TYPE_BOOLEAN:
            return row_put_bool(ra, value->v_bool);

        case GS_TYPE_BIGINT:
            return row_put_int64(ra, VALUE(int64, value));

        case GS_TYPE_REAL:
            return row_put_real(ra, VALUE(double, value));

        case GS_TYPE_DATE:
            return row_put_date(ra, VALUE(date_t, value));

        case GS_TYPE_TIMESTAMP:
        case GS_TYPE_TIMESTAMP_TZ_FAKE:
        case GS_TYPE_TIMESTAMP_LTZ:
            return row_put_date(ra, VALUE(date_t, value));

        case GS_TYPE_TIMESTAMP_TZ:
            return row_put_timestamp_tz(ra, VALUE_PTR(timestamp_tz_t, value));

        case GS_TYPE_INTERVAL_DS:
            return row_put_dsinterval(ra, VALUE(interval_ds_t, value));

        case GS_TYPE_INTERVAL_YM:
            return row_put_yminterval(ra, VALUE(interval_ym_t, value));

        case GS_TYPE_CHAR:
        case GS_TYPE_VARCHAR:
        case GS_TYPE_STRING:
            return row_put_text(ra, VALUE_PTR(text_t, value));

        case GS_TYPE_NUMBER:
        case GS_TYPE_DECIMAL:
            return row_put_dec4(ra, VALUE_PTR(dec8_t, value));
        case GS_TYPE_NUMBER2:
            return row_put_dec2(ra, VALUE_PTR(dec8_t, value));

        case GS_TYPE_CLOB:
        case GS_TYPE_BLOB:
        case GS_TYPE_IMAGE:
            return GS_ERROR;

        case GS_TYPE_ARRAY:
            return sql_row_put_array(stmt, ra, &value->v_array);

        case GS_TYPE_BINARY:
        case GS_TYPE_RAW:
        default:
            return row_put_bin(ra, VALUE_PTR(binary_t, value));
    }
}

status_t sql_put_row_value(sql_stmt_t *stmt, char *pending_buf, row_assist_t *ra, gs_type_t temp_type, variant_t *value)
{
    gs_type_t type = temp_type;
    // try make pending column definition when project column
    if (type == GS_TYPE_UNKNOWN) {
        return GS_ERROR;
    }

    if (value->is_null) {
        return row_put_null(ra);
    }

    if (value->type == GS_TYPE_VM_ROWID) {
        return row_put_vmid(ra, &value->v_vmid);
    }

    if (value->type != type && value->type != GS_TYPE_ARRAY) {
        GS_RETURN_IFERR(sql_convert_variant(stmt, value, type));
    }

    return sql_row_put_value(stmt, ra, value);
}

static inline status_t sql_convert_row_value(sql_stmt_t *stmt, variant_t *value, gs_type_t type)
{
    if (value->type == type || value->type == GS_TYPE_ARRAY) {
        return GS_SUCCESS;
    }
    return sql_convert_variant(stmt, value, type);
}

status_t sql_set_row_value(sql_stmt_t *stmt, row_assist_t *ra, gs_type_t type, variant_t *value, uint32 col_id)
{
    // The GS_TYPE_LOGIC_TRUE indicates that the result set is empty in ALL(xxx) conditon, which different from NULL.
    if (value->is_null || value->type == GS_TYPE_LOGIC_TRUE) {
        return row_set_null(ra, col_id);
    }

    GS_RETURN_IFERR(sql_convert_row_value(stmt, value, type));
    switch (value->type) {
        case GS_TYPE_UINT32:
            return row_set_uint32(ra, VALUE(uint32, value), col_id);

        case GS_TYPE_INTEGER:
            return row_set_int32(ra, VALUE(int32, value), col_id);

        case GS_TYPE_BOOLEAN:
            return row_set_bool(ra, value->v_bool, col_id);

        case GS_TYPE_BIGINT:
            return row_set_int64(ra, VALUE(int64, value), col_id);

        case GS_TYPE_REAL:
            return row_set_real(ra, VALUE(double, value), col_id);

        case GS_TYPE_DATE:
            return row_set_date(ra, VALUE(date_t, value), col_id);

        case GS_TYPE_TIMESTAMP:
        case GS_TYPE_TIMESTAMP_TZ_FAKE:
        case GS_TYPE_TIMESTAMP_LTZ:
            return row_set_date(ra, VALUE(date_t, value), col_id);

        case GS_TYPE_TIMESTAMP_TZ:
            return row_set_timestamp_tz(ra, VALUE_PTR(timestamp_tz_t, value), col_id);

        case GS_TYPE_INTERVAL_DS:
            return row_set_dsinterval(ra, VALUE(interval_ds_t, value), col_id);

        case GS_TYPE_INTERVAL_YM:
            return row_set_yminterval(ra, VALUE(interval_ym_t, value), col_id);

        case GS_TYPE_CHAR:
        case GS_TYPE_VARCHAR:
        case GS_TYPE_STRING:
            return row_set_text(ra, VALUE_PTR(text_t, value), col_id);

        case GS_TYPE_NUMBER:
        case GS_TYPE_DECIMAL:
            return row_set_dec4(ra, VALUE_PTR(dec8_t, value), col_id);
        case GS_TYPE_NUMBER2:
            return row_set_dec2(ra, VALUE_PTR(dec8_t, value), col_id);
        case GS_TYPE_CLOB:
        case GS_TYPE_BLOB:
        case GS_TYPE_IMAGE:
            return sql_row_set_lob(stmt, ra, g_instance->sql.sql_lob_locator_size, VALUE_PTR(var_lob_t, value), col_id);

        case GS_TYPE_ARRAY:
            return sql_row_set_array(stmt, ra, value, col_id);

        case GS_TYPE_BINARY:
        case GS_TYPE_RAW:
        default:
            return row_set_bin(ra, VALUE_PTR(binary_t, value), col_id);
    }
}


status_t sql_get_rs_table_val(sql_stmt_t *stmt, rs_column_t *rs_col, variant_t *value)
{
    return sql_get_table_value(stmt, &rs_col->v_col, value);
}

status_t sql_get_rs_expr_val(sql_stmt_t *stmt, rs_column_t *rs_col, variant_t *value)
{
    return sql_exec_expr(stmt, rs_col->expr, value);
}

typedef status_t (*sql_get_rs_val_t)(sql_stmt_t *stmt, rs_column_t *rs_col, variant_t *value);

static status_t sql_send_value_type(sql_stmt_t *stmt, variant_t *value)
{
    switch (value->type) {
        case GS_TYPE_UINT32:
            return my_sender(stmt)->send_column_uint32(stmt, VALUE(uint32, value));

        case GS_TYPE_INTEGER:
            return my_sender(stmt)->send_column_int32(stmt, VALUE(int32, value));

        case GS_TYPE_BIGINT:
            return my_sender(stmt)->send_column_int64(stmt, VALUE(int64, value));

        case GS_TYPE_REAL:
            return my_sender(stmt)->send_column_real(stmt, VALUE(double, value));

        case GS_TYPE_DATE:
            return my_sender(stmt)->send_column_date(stmt, VALUE(date_t, value));

        case GS_TYPE_TIMESTAMP:
        case GS_TYPE_TIMESTAMP_TZ_FAKE:
            return my_sender(stmt)->send_column_ts(stmt, VALUE(date_t, value));

        case GS_TYPE_TIMESTAMP_LTZ:
            return my_sender(stmt)->send_column_tsltz(stmt, VALUE(timestamp_ltz_t, value));

        case GS_TYPE_TIMESTAMP_TZ:
            return my_sender(stmt)->send_column_tstz(stmt, VALUE_PTR(timestamp_tz_t, value));

        case GS_TYPE_CHAR:
        case GS_TYPE_VARCHAR:
        case GS_TYPE_STRING:
            return my_sender(stmt)->send_column_text(stmt, VALUE_PTR(text_t, value));

        case GS_TYPE_CLOB:
        case GS_TYPE_IMAGE:
            return my_sender(stmt)->send_column_clob(stmt, VALUE_PTR(var_lob_t, value));

        case GS_TYPE_BLOB:
            return my_sender(stmt)->send_column_blob(stmt, VALUE_PTR(var_lob_t, value));

        case GS_TYPE_BINARY:
        case GS_TYPE_VARBINARY:
            return my_sender(stmt)->send_column_bin(stmt, VALUE_PTR(binary_t, value));
        case GS_TYPE_RAW:
            return my_sender(stmt)->send_column_raw(stmt, VALUE_PTR(binary_t, value));

        case GS_TYPE_NUMBER:
        case GS_TYPE_DECIMAL:
            return my_sender(stmt)->send_column_decimal(stmt, VALUE_PTR(dec8_t, value));
        case GS_TYPE_NUMBER2:
            return my_sender(stmt)->send_column_decimal2(stmt, VALUE_PTR(dec8_t, value));

        case GS_TYPE_BOOLEAN:
            return my_sender(stmt)->send_column_bool(stmt, VALUE(bool32, value));

        case GS_TYPE_INTERVAL_YM:
            return my_sender(stmt)->send_column_ymitvl(stmt, VALUE(interval_ym_t, value));

        case GS_TYPE_INTERVAL_DS:
            return my_sender(stmt)->send_column_dsitvl(stmt, VALUE(interval_ds_t, value));

        case GS_TYPE_CURSOR:
            return my_sender(stmt)->send_column_null(stmt, GS_TYPE_CURSOR);

        case GS_TYPE_ARRAY:
            return my_sender(stmt)->send_column_array(stmt, VALUE_PTR(var_array_t, value));

        default:
            break;
    }
    return GS_SUCCESS;
}

status_t sql_send_value(sql_stmt_t *stmt, char *pending_buf, gs_type_t temp_type, typmode_t *typmod, variant_t *value)
{
    // try make pending column definition when project column
    gs_type_t type = temp_type;
    if (type == GS_TYPE_UNKNOWN) {
        return GS_ERROR;
    }

    if (value->is_null) {
        return my_sender(stmt)->send_column_null(stmt, (uint32)type);
    }

    if ((value->type != type) && (my_sender(stmt) != sql_get_pl_sender())) {
        return GS_ERROR;
    }

    return sql_send_value_type(stmt, value);
}

status_t sql_send_column(sql_stmt_t *stmt, sql_cursor_t *cursor, rs_column_t *rs_col, variant_t *value)
{
    sql_table_cursor_t *tab_cur = NULL;

    cursor = SQL_CURR_CURSOR(stmt);

    tab_cur = &cursor->tables[rs_col->v_col.tab];

    knl_panic(!GS_IS_SUBSELECT_TABLE(tab_cur->table->type));
    return sql_get_ddm_kernel_value(stmt, tab_cur->table, tab_cur->knl_cur, &rs_col->v_col, value);
}

status_t sql_send_calc_column(sql_stmt_t *stmt, rs_column_t *rs_col, variant_t *value)
{
    value->is_null = GS_TRUE;

    if (sql_exec_expr(stmt, rs_col->expr, value) != GS_SUCCESS) {
        return GS_ERROR;
    }

    /* If the return type is cursor, send the cursor id to client. */
    knl_panic(value->type != GS_TYPE_CURSOR);

    return GS_SUCCESS;
}

status_t sql_send_row(sql_stmt_t *stmt, sql_cursor_t *cursor, bool32 *is_full)
{
    uint32 i;
    rs_column_t *rs_col = NULL;
    variant_t value;

    sql_cursor_t *tmp_cursor = sql_get_proj_cursor(cursor);

    SQL_CURSOR_PUSH(stmt, tmp_cursor);

    GS_RETURN_IFERR(my_sender(stmt)->send_row_begin(stmt, tmp_cursor->columns->count));

    for (i = 0; i < tmp_cursor->columns->count; i++) {
        rs_col = (rs_column_t *)cm_galist_get(tmp_cursor->columns, i);
        if (rs_col->type == RS_COL_COLUMN) {
            GS_RETURN_IFERR(sql_send_column(stmt, tmp_cursor, rs_col, &value));
        } else {
            GS_RETURN_IFERR(sql_send_calc_column(stmt, rs_col, &value));
        }

        GS_RETURN_IFERR(sql_send_value(stmt, NULL, rs_col->datatype, &rs_col->typmod, &value));
    }

    SQL_CURSOR_POP(stmt);

    GS_RETURN_IFERR(my_sender(stmt)->send_row_end(stmt, is_full));
    sql_inc_rows(stmt, cursor);
    SQL_POP(stmt);
    return GS_SUCCESS;
}

status_t sql_check_privilege(sql_stmt_t *stmt, bool32 need_lock_ctrl)
{
    /* no need to check SELECT privilege when execute add/enable check constraint sql */
    if (stmt->chk_priv == GS_FALSE) {
        return GS_SUCCESS;
    }

    return sql_check_user_tenant(&stmt->session->knl_session);
}

// return SUCCESS while user belong to TENANT$ROOT
status_t sql_check_user_tenant(knl_session_t *session)
{
    dc_user_t *user = NULL;

    if (dc_open_user_by_id(session, session->uid, &user) != GS_SUCCESS) {
        return GS_ERROR;
    }
    if (user->desc.tenant_id != SYS_TENANTROOT_ID) {
        GS_THROW_ERROR(ERR_INVALID_OPERATION, ", only support for users in TENANT$ROOT");
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

static void sql_reset_connect_data(sql_cursor_t *cursor)
{
    cursor->connect_data.next_level_cursor = NULL;
    cursor->connect_data.last_level_cursor = NULL;
    cursor->connect_data.first_level_cursor = NULL;
    cursor->connect_data.cur_level_cursor = NULL;
    cursor->connect_data.connect_by_isleaf = GS_FALSE;
    cursor->connect_data.connect_by_iscycle = GS_FALSE;
    cursor->connect_data.level = 0;
    cursor->connect_data.first_level_rownum = 0;
    cursor->connect_data.path_func_nodes = NULL;
    cursor->connect_data.prior_exprs = NULL;
    cursor->connect_data.path_stack = NULL;
}

static inline void sql_init_cur_exec_data(plan_exec_data_t *exec_data)
{
    exec_data->query_limit = NULL;
    exec_data->select_limit = NULL;
    exec_data->union_all = NULL;
    exec_data->minus.r_continue_fetch = GS_TRUE;
    exec_data->minus.rs_vmid = GS_INVALID_ID32;
    exec_data->minus.rnums = 0;
    exec_data->explain_col_max_size = NULL;
    exec_data->qb_col_max_size = NULL;
    exec_data->outer_join = NULL;
    exec_data->inner_join = NULL;
    exec_data->join = NULL;
    exec_data->aggr_dis = NULL;
    exec_data->select_view = NULL;
    exec_data->tab_parallel = NULL;
    exec_data->group = NULL;
    exec_data->group_cube = NULL;
    exec_data->nl_batch = NULL;
    exec_data->ext_knl_cur = NULL;
    exec_data->right_semi = NULL;
    exec_data->index_scan_range_ar = NULL;
    exec_data->part_scan_range_ar = NULL;
    exec_data->dv_plan_buf = NULL;
    CM_INIT_TEXTBUF(&exec_data->sort_concat, 0, NULL);
}

static inline void sql_init_cursor_hash_info(sql_cursor_t *cursor)
{
    cursor->merge_into_hash.already_update = GS_FALSE;
    cursor->hash_table_status = HASH_TABLE_STATUS_NOINIT;

    for (uint32 i = 0; i < GS_MAX_JOIN_TABLES; i++) {
        cursor->hash_mtrl.hj_tables[i] = NULL;
    }
}

void sql_init_sql_cursor(sql_stmt_t *stmt, sql_cursor_t *cursor)
{
    cursor->stmt = stmt;
    cursor->plan = NULL;
    cursor->select_ctx = NULL;
    cursor->cond = NULL;
    cursor->query = NULL;
    cursor->columns = NULL;
    cursor->aggr_page = NULL;
    cursor->eof = GS_FALSE;
    cursor->total_rows = 0;
    cursor->rownum = 0;
    cursor->max_rownum = GS_INVALID_ID32;
    cursor->last_table = 0;
    cursor->table_count = 0;
    cursor->tables = NULL;
    cursor->scn = GS_INVALID_ID64;
    cursor->is_mtrl_cursor = GS_FALSE;
    biqueue_init(&cursor->ssa_cursors);

    // init exec data of plan
    vmc_init(&stmt->session->vmp, &cursor->vmc);
    sql_init_cur_exec_data(&cursor->exec_data);

    // init connect by exec data
    sql_reset_connect_data(cursor);

    // init hash clause exec data
    sql_init_cursor_hash_info(cursor);

    cursor->unpivot_ctx = NULL;
    cursor->m_join = NULL;

    cursor->is_open = GS_FALSE;
    cursor->is_result_cached = GS_FALSE;
    cursor->exists_result = GS_FALSE;
    cursor->left_cursor = NULL;
    cursor->right_cursor = NULL;
    cursor->ancestor_ref = NULL;
    cursor->winsort_ready = GS_FALSE;
    cursor->global_cached = GS_FALSE;
    cursor->idx_func_cache = NULL;
}

bool32 sql_try_extend_global_cursor(object_t **object)
{
    char *buf = NULL;
    uint32 sql_cur_size = CM_ALIGN8(OBJECT_HEAD_SIZE + sizeof(sql_cursor_t));
    uint32 ext_cnt, ext_buf_size;
    uint32 max_sql_cursors = g_instance->attr.reserved_sql_cursors +
                             (g_instance->attr.sql_cursors_each_sess * g_instance->session_pool.max_sessions);
    object_pool_t extend_pool;
    errno_t rc_memzero;

    if (g_instance->sql_cur_pool.cnt >= max_sql_cursors) {
        return GS_FALSE;
    }

    cm_spin_lock(&g_instance->sql_cur_pool.lock, NULL);
    if (g_instance->sql_cur_pool.cnt < max_sql_cursors) {
        ext_cnt = MIN(max_sql_cursors - g_instance->sql_cur_pool.cnt, EXTEND_SQL_CURS_EACH_TIME);
        ext_buf_size = ext_cnt * sql_cur_size;
        if (ext_buf_size == 0 || ext_buf_size / sql_cur_size != ext_cnt) {
            cm_spin_unlock(&g_instance->sql_cur_pool.lock);
            return GS_FALSE;
        }
        buf = (char *)malloc(ext_buf_size);
        if (buf == NULL) {
            cm_spin_unlock(&g_instance->sql_cur_pool.lock);
            return GS_FALSE;
        }
        rc_memzero = memset_s(buf, ext_buf_size, 0, ext_buf_size);
        if (rc_memzero != EOK) {
            cm_spin_unlock(&g_instance->sql_cur_pool.lock);
            CM_FREE_PTR(buf);
            return GS_FALSE;
        }
        opool_attach(buf, ext_buf_size, sql_cur_size, &extend_pool);
        olist_concat(&g_instance->sql_cur_pool.pool.free_objects, &extend_pool.free_objects);
        g_instance->sql_cur_pool.cnt += ext_cnt;
        *object = opool_alloc(&g_instance->sql_cur_pool.pool);
        cm_spin_unlock(&g_instance->sql_cur_pool.lock);
        return GS_TRUE;
    }
    cm_spin_unlock(&g_instance->sql_cur_pool.lock);
    return GS_FALSE;
}

/**
1.apply sql cursor from global sql cursor pools,if not enough,go to step 2
2.try to extend the global sql cursor pools, and return one sql cursor.if the extension fails,go to step 3
3.apply sql cursor via malloc,if malloc fails, return NULL
* */
status_t sql_alloc_global_sql_cursor(object_t **object)
{
    sql_cursor_t *cursor = NULL;
    object_pool_t *pool = &g_instance->sql_cur_pool.pool;
    errno_t errcode;
    if (pool->free_objects.count > 0) {
        cm_spin_lock(&g_instance->sql_cur_pool.lock, NULL);
        if (pool->free_objects.count > 0) {
            (*object) = opool_alloc(pool);
            cm_spin_unlock(&g_instance->sql_cur_pool.lock);
            return GS_SUCCESS;
        }
        cm_spin_unlock(&g_instance->sql_cur_pool.lock);
    }

    if (!sql_try_extend_global_cursor(object)) {
        *object = (object_t *)malloc(OBJECT_HEAD_SIZE + sizeof(sql_cursor_t));
        if ((*object) == NULL) {
            GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)sizeof(sql_cursor_t), "creating sql cursor");
            return GS_ERROR;
        }
        errcode = memset_s(*object, OBJECT_HEAD_SIZE + sizeof(sql_cursor_t), 0,
                           OBJECT_HEAD_SIZE + sizeof(sql_cursor_t));
        if (errcode != EOK) {
            CM_FREE_PTR(*object);
            GS_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return GS_ERROR;
        }
        cursor = (sql_cursor_t *)(*object)->data;
        cursor->not_cache = GS_TRUE;
    }
    return GS_SUCCESS;
}

status_t sql_alloc_cursor(sql_stmt_t *stmt, sql_cursor_t **cursor)
{
    object_t *object = NULL;
    object_pool_t *pool = &stmt->session->sql_cur_pool;
    // apply preferentially from session. if not enough, apply from the global sql cursor pool.
    if (pool->free_objects.count > 0) {
        object = opool_alloc(pool);
    } else {
        GS_RETURN_IFERR(sql_alloc_global_sql_cursor(&object));
    }
    if (object == NULL) {
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)(OBJECT_HEAD_SIZE + sizeof(sql_cursor_t)), "creating sql cursor");
        return GS_ERROR;
    }

    *cursor = (sql_cursor_t *)object->data;
    sql_init_sql_cursor(stmt, *cursor);
    olist_concat_single(&stmt->sql_curs, object);
    return GS_SUCCESS;
}

status_t sql_alloc_knl_cursor(sql_stmt_t *stmt, knl_cursor_t **cursor)
{
    object_pool_t *pool = &stmt->session->knl_cur_pool;
    object_t *object = opool_alloc(pool);
    if (object == NULL) {
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)(OBJECT_HEAD_SIZE + g_instance->kernel.attr.cursor_size),
                       "creating kernel cursor");
        return GS_ERROR;
    }

    *cursor = (knl_cursor_t *)object->data;
    KNL_INIT_CURSOR(*cursor);
    (*cursor)->stmt = stmt;
    knl_init_cursor_buf(&stmt->session->knl_session, *cursor);

    (*cursor)->rowid = g_invalid_rowid;
    (*cursor)->scn = KNL_INVALID_SCN;
    olist_concat_single(&stmt->knl_curs, object);
    return GS_SUCCESS;
}

static void sql_free_sql_cursor_by_type(sql_stmt_t *stmt, sql_cursor_t *cursor)
{
    object_t *object = (object_t *)((char *)cursor - OBJECT_HEAD_SIZE);
    object_pool_t *pool = &stmt->session->sql_cur_pool;
    if (cursor->not_cache) {
        CM_FREE_PTR(object);
    } else if (pool->free_objects.count < g_instance->attr.sql_cursors_each_sess) {
        olist_concat_single(&pool->free_objects, object);
    } else {
        pool = &g_instance->sql_cur_pool.pool;
        cm_spin_lock(&g_instance->sql_cur_pool.lock, NULL);
        olist_concat_single(&pool->free_objects, object);
        cm_spin_unlock(&g_instance->sql_cur_pool.lock);
    }
}

void sql_free_cursor(sql_stmt_t *stmt, sql_cursor_t *cursor)
{
    if (cursor == NULL) {
        return;
    }
    object_t *object = (object_t *)((char *)cursor - OBJECT_HEAD_SIZE);

    if (cursor->is_open) {
        sql_close_cursor(stmt, cursor);
    }

    if (cursor->connect_data.first_level_cursor != NULL) {
        sql_reset_connect_data(cursor);
    }

    olist_remove(&stmt->sql_curs, object);
    sql_free_sql_cursor_by_type(stmt, cursor);
}

void sql_free_cursors(sql_stmt_t *stmt)
{
    while (stmt->sql_curs.first != NULL) {
        sql_free_cursor(stmt, (sql_cursor_t *)stmt->sql_curs.first->data);
    }
}

void sql_free_knl_cursor(sql_stmt_t *stmt, knl_cursor_t *cursor)
{
    object_pool_t *pool = &stmt->session->knl_cur_pool;
    object_t *object = (object_t *)((char *)cursor - OBJECT_HEAD_SIZE);

    if (cursor->file != -1) {
        cm_close_file(cursor->file);
    }
    knl_close_cursor(&stmt->session->knl_session, cursor);
    olist_remove(&stmt->knl_curs, object);
    opool_free(pool, object);
}

static void sql_release_multi_parts_resources(sql_stmt_t *stmt, sql_table_cursor_t *tab_cur)
{
    if (tab_cur->multi_parts_info.knlcur_list == NULL || tab_cur->multi_parts_info.knlcur_list->count == 0) {
        tab_cur->multi_parts_info.knlcur_list = NULL;
        tab_cur->multi_parts_info.knlcur_id = 0;
        tab_cur->multi_parts_info.sort_info = NULL;
        return;
    }
    mps_knlcur_t *knlcur_info = (mps_knlcur_t *)cm_galist_get(tab_cur->multi_parts_info.knlcur_list, 0);
    tab_cur->knl_cur = knlcur_info->knl_cursor;

    uint32 count = tab_cur->multi_parts_info.knlcur_list->count;
    for (uint32 i = 1; i < count; i++) {
        knlcur_info = (mps_knlcur_t *)cm_galist_get(tab_cur->multi_parts_info.knlcur_list, i);
        knl_close_cursor(&stmt->session->knl_session, knlcur_info->knl_cursor);
    }
    tab_cur->multi_parts_info.knlcur_list = NULL;
    tab_cur->multi_parts_info.knlcur_id = 0;
    tab_cur->multi_parts_info.sort_info = NULL;
}

static inline void sql_free_table_cursor(sql_stmt_t *stmt, sql_table_cursor_t *cursor)
{
    sql_release_multi_parts_resources(stmt, cursor);

    cursor->scan_flag = SEQ_SQL_SCAN;

    if (GS_IS_SUBSELECT_TABLE(cursor->table->type)) {
        if (cursor->sql_cur != NULL) {
            if (cursor->table->type == VIEW_AS_TABLE && cursor->action == CURSOR_ACTION_INSERT) {
                sql_free_knl_cursor(stmt, cursor->knl_cur);
            } else {
                sql_free_cursor(stmt, cursor->sql_cur);
            }
        }
        return;
    }

    knl_panic(cursor->table->type != JSON_TABLE);
    {
        sql_free_varea_set(cursor);
    }

    {
        sql_free_knl_cursor(stmt, cursor->knl_cur);
    }
}

void sql_free_merge_join_data(sql_stmt_t *stmt, join_data_t *m_join)
{
    if (m_join->left != NULL) {
        sql_free_cursor(stmt, m_join->left);
        m_join->left = NULL;
    }
    if (m_join->right != NULL) {
        sql_free_cursor(stmt, m_join->right);
        m_join->right = NULL;
    }
}

void sql_free_nl_batch_exec_data(sql_stmt_t *stmt, sql_cursor_t *cursor, uint32 count)
{
    for (uint32 i = 0; i < count; ++i) {
        if (cursor->exec_data.nl_batch[i].cache_cur != NULL) {
            sql_free_cursor(stmt, cursor->exec_data.nl_batch[i].cache_cur);
            cursor->exec_data.nl_batch[i].cache_cur = NULL;
        }
    }
}

void sql_free_va_set(sql_stmt_t *stmt, sql_cursor_t *cursor)
{
    cursor->exec_data.query_limit = NULL;
    cursor->exec_data.select_limit = NULL;
    cursor->exec_data.union_all = NULL;
    cursor->exec_data.minus.r_continue_fetch = GS_TRUE;
    cursor->exec_data.minus.rnums = 0;
    cursor->exec_data.explain_col_max_size = NULL;
    cursor->exec_data.qb_col_max_size = NULL;
    cursor->exec_data.outer_join = NULL;
    cursor->exec_data.inner_join = NULL;
    cursor->exec_data.join = NULL;
    cursor->exec_data.select_view = NULL;
    cursor->exec_data.tab_parallel = NULL;
    cursor->exec_data.group = NULL;
    cursor->exec_data.right_semi = NULL;
    CM_INIT_TEXTBUF(&cursor->exec_data.sort_concat, 0, NULL);

    if (cursor->exec_data.aggr_dis != NULL) {
        knl_panic(0);
        cursor->exec_data.aggr_dis = NULL;
    }

    if (cursor->exec_data.group_cube != NULL) {
        knl_panic(0);
        cursor->exec_data.group_cube = NULL;
    }

    if (cursor->exec_data.nl_batch != NULL) {
        knl_panic(0);
        cursor->exec_data.nl_batch = NULL;
    }

    if (cursor->exec_data.minus.rs_vmid != GS_INVALID_ID32) {
        knl_panic(0);
        cursor->exec_data.minus.rs_vmid = GS_INVALID_ID32;
    }

    cursor->exec_data.index_scan_range_ar = NULL;
    cursor->exec_data.part_scan_range_ar = NULL;
    cursor->exec_data.dv_plan_buf = NULL;
}

static void sql_free_hash_join_data(sql_stmt_t *stmt, sql_cursor_t *cursor)
{
    for (uint32 i = 0; i < GS_MAX_JOIN_TABLES; i++) {
        if (cursor->hash_mtrl.hj_tables[i] != NULL) {
            sql_free_cursor(stmt, cursor->hash_mtrl.hj_tables[i]);
            cursor->hash_mtrl.hj_tables[i] = NULL;
        }
    }
}

static inline void sql_free_ssa_cursors(sql_stmt_t *stmt, sql_cursor_t *cursor)
{
    sql_cursor_t *ssa_cur = NULL;
    biqueue_node_t *curr = NULL;
    biqueue_node_t *end = NULL;

    curr = biqueue_first(&cursor->ssa_cursors);
    end = biqueue_end(&cursor->ssa_cursors);

    while (curr != end) {
        ssa_cur = OBJECT_OF(sql_cursor_t, curr);
        curr = curr->next;
        sql_free_cursor(cursor->stmt, ssa_cur);
    }
    biqueue_init(&cursor->ssa_cursors);
}

static void sql_free_merge_join_resource(sql_stmt_t *stmt, sql_cursor_t *cursor)
{
    if (cursor->m_join == NULL) {
        return;
    }
    uint32 mj_plan_count = cursor->query->join_assist.mj_plan_count;
    if (cursor->query->s_query != NULL) {
        mj_plan_count = MAX(mj_plan_count, cursor->query->s_query->join_assist.mj_plan_count);
    }
    for (uint32 i = 0; i < mj_plan_count; i++) {
        sql_free_merge_join_data(stmt, &cursor->m_join[i]);
    }
    cursor->m_join = NULL;
}

static inline void sql_free_cursor_tables(sql_stmt_t *stmt, sql_cursor_t *cursor)
{
    for (uint32 i = 0; i < cursor->table_count; i++) {
        sql_free_table_cursor(stmt, &cursor->tables[cursor->id_maps[i]]);
    }
    cursor->table_count = 0;
    cursor->tables = NULL;
}

void sql_close_cursor(sql_stmt_t *stmt, sql_cursor_t *cursor)
{
    GS_RETVOID_IFTRUE(!cursor->is_open)
    cursor->is_open = GS_FALSE;
    cursor->idx_func_cache = NULL;

    knl_panic(cursor->nl_full_ctx_list == NULL);

    if (cursor->left_cursor != NULL) {
        sql_free_cursor(stmt, cursor->left_cursor);
        cursor->left_cursor = NULL;
    }

    if (cursor->right_cursor != NULL) {
        sql_free_cursor(stmt, cursor->right_cursor);
        cursor->right_cursor = NULL;
    }

    sql_free_hash_join_data(stmt, cursor);

    if (cursor->exec_data.ext_knl_cur != NULL) {
        sql_free_knl_cursor(stmt, cursor->exec_data.ext_knl_cur);
        cursor->exec_data.ext_knl_cur = NULL;
    }
    sql_free_cursor_tables(stmt, cursor);
    sql_free_ssa_cursors(stmt, cursor);

    if (cursor->query != NULL) {
        sql_free_merge_join_resource(stmt, cursor);
    }

    sql_free_va_set(stmt, cursor);

    cursor->unpivot_ctx = NULL;

    if (cursor->connect_data.first_level_cursor != NULL) {
        knl_panic(0);
    }

    vmc_free(&cursor->vmc);
}

static rs_fetch_func_tab_t g_rs_fetch_func_tab[] = {
    { RS_TYPE_NONE, sql_fetch_query },
    { RS_TYPE_NORMAL, sql_fetch_query },
    { RS_TYPE_SORT, NULL },
    { RS_TYPE_HASH_GROUP, NULL },
    { RS_TYPE_AGGR, NULL },
    { RS_TYPE_UNION, NULL },
    { RS_TYPE_UNION_ALL, NULL },
    { RS_TYPE_MINUS, NULL },
    { RS_TYPE_LIMIT, NULL },
    { RS_TYPE_WINSORT, NULL },
    { RS_TYPE_ROW, sql_fetch_query },
    { RS_TYPE_ROWNUM, sql_fetch_rownum },
    { RS_TYPE_FOR_UPDATE, NULL },
};

static inline sql_fetch_func_t sql_get_fetch_func(sql_stmt_t *stmt, sql_cursor_t *cursor)
{
    return g_rs_fetch_func_tab[stmt->rs_type].sql_fetch_func;
}

status_t sql_make_result_set(sql_stmt_t *stmt, sql_cursor_t *cursor)
{
    status_t status;

    if (cursor->eof) {
        sql_close_cursor(stmt, cursor);
        return GS_SUCCESS;
    }
    CM_TRACE_BEGIN;
    date_t rs_plan_time = AUTOTRACE_ON(stmt) ? stmt->plan_time[stmt->rs_plan->plan_id] : 0;

    sql_send_row_func_t sql_send_row_func = sql_get_send_row_func(stmt, stmt->rs_plan);
    sql_fetch_func_t sql_fetch_func = sql_get_fetch_func(stmt, cursor);
    stmt->need_send_ddm = GS_TRUE;
    status = sql_make_normal_rs(stmt, cursor, sql_fetch_func, sql_send_row_func);
    if (status != GS_SUCCESS) {
        sql_close_cursor(stmt, cursor);
    }
    if (AUTOTRACE_ON(stmt) && stmt->plan_time[stmt->rs_plan->plan_id] == rs_plan_time) {
        CM_TRACE_END(stmt, stmt->rs_plan->plan_id);
    }
    stmt->need_send_ddm = GS_FALSE;
    return status;
}

status_t sql_execute_single_dml(sql_stmt_t *stmt, knl_savepoint_t *savepoint)
{
    status_t status;

    GS_RETURN_IFERR(sql_check_tables(stmt, stmt->context));

    sql_set_scn(stmt);

    switch (stmt->context->type) {
        case SQL_TYPE_SELECT:
            status = sql_execute_select(stmt);
            break;

        case SQL_TYPE_UPDATE:
        case SQL_TYPE_INSERT:
        case SQL_TYPE_DELETE:
        case SQL_TYPE_REPLACE:
        case SQL_TYPE_MERGE:
        default:
            status = GS_ERROR;
            break;
    }

    if (status != GS_SUCCESS) {
        do_rollback(stmt->session, savepoint);
        knl_reset_index_conflicts(KNL_SESSION(stmt));
    }

    return status;
}

#define CHECK_IGNORE_BATCH_ERROR(stmt, i, status)                                 \
    if ((status) != GS_SUCCESS) {                                                 \
        GS_LOG_DEBUG_ERR("error occurs when issue dml, paramset index: %u", (i)); \
        break;                                                                    \
    }

static status_t sql_issue_parametered_dml(sql_stmt_t *stmt, sql_cursor_t *cursor)
{
    status_t status = GS_SUCCESS;
    knl_savepoint_t savepoint;

    SQL_SAVE_STACK(stmt);

    for (uint32 i = stmt->param_info.paramset_offset; i < stmt->param_info.paramset_size; i++) {
        SQL_RESTORE_STACK(stmt);

        // do read params from req packet
        status = sql_read_params(stmt);
        // try allowed batch errors if execute error
        CHECK_IGNORE_BATCH_ERROR(stmt, i, status);

        if ((stmt->context->type == SQL_TYPE_SELECT && i != stmt->param_info.paramset_size - 1)) {
            // for select, only the last
            stmt->param_info.paramset_offset++;
            continue;
        }

        knl_savepoint(&stmt->session->knl_session, &savepoint);
        cursor->total_rows = 0;

        // need clean value with the previous parameters
        sql_reset_first_exec_vars(stmt);
        sql_reset_sequence(stmt);
        // the context may be changed in try_get_execute_context, and the context-related content in cursor will become
        // invalid, so cursor should be closed in advance
        sql_close_cursor(stmt, cursor);

        stmt->context->readonly = GS_TRUE;

        if (AUTOTRACE_ON(stmt)) {
            GS_RETURN_IFERR(sql_init_stmt_plan_time(stmt));
        }
        status = sql_execute_single_dml(stmt, &savepoint);

        // try allowed batch errors if execute error
        CHECK_IGNORE_BATCH_ERROR(stmt, i, status);

        stmt->param_info.paramset_offset++;
        stmt->eof = cursor->eof;
        // execute batch need to return total affected rows
        stmt->total_rows += cursor->total_rows;
    }

    return status;
}

static status_t sql_issue_dml(sql_stmt_t *stmt)
{
    sql_cursor_t *cursor = SQL_ROOT_CURSOR(stmt);
    status_t status = GS_SUCCESS;

    if ((stmt->param_info.paramset_size == 0 || stmt->context->rs_columns != NULL)) {
        stmt->param_info.paramset_size = 1;
    }

    stmt->param_info.param_strsize = 0;
    stmt->params_ready = GS_FALSE;

    status = sql_issue_parametered_dml(stmt, cursor);
    stmt->session->recent_foundrows = cursor->total_rows + cursor->found_rows.limit_skipcount +
                                      cursor->found_rows.offset_skipcount;

    if (status != GS_SUCCESS) {  // Error happens when executes DML
        return GS_ERROR;
    }

    if (stmt->context->type == SQL_TYPE_SELECT && !stmt->eof) {
        GS_RETURN_IFERR(sql_keep_params(stmt));
        GS_RETURN_IFERR(sql_keep_first_exec_vars(stmt));
    }

    return GS_SUCCESS;
}

status_t sql_begin_dml(sql_stmt_t *stmt)
{
    sql_cursor_t *cursor = NULL;

    if (sql_alloc_cursor(stmt, &cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (SQL_CURSOR_PUSH(stmt, cursor) != GS_SUCCESS) {
        sql_free_cursor(stmt, cursor);
        return GS_ERROR;
    }
    stmt->resource_inuse = GS_TRUE;
    return GS_SUCCESS;
}

status_t sql_try_execute_dml(sql_stmt_t *stmt)
{
    int32 code;
    const char *message = NULL;

    if (stmt->context == NULL) {
        GS_THROW_ERROR(ERR_REQUEST_OUT_OF_SQUENCE, "prepared.");
        return GS_ERROR;
    }

    if (!stmt->context->ctrl.valid) {
        GS_THROW_ERROR(ERR_DC_INVALIDATED);
        return GS_ERROR;
    }

    GS_RETURN_IFERR(sql_check_ltt_dc(stmt));

    if (sql_begin_dml(stmt) != GS_SUCCESS) {
        return GS_ERROR;
    }

    status_t status = sql_issue_dml(stmt);

    if (status != GS_SUCCESS) {
        cm_get_error(&code, &message, NULL);
        stmt->dc_invalid = (code == ERR_DC_INVALIDATED);
        sql_release_resource(stmt, GS_TRUE);
        stmt->dc_invalid = GS_FALSE;
        SQL_CURSOR_POP(stmt);
        return GS_ERROR;
    }

    if (stmt->auto_commit == GS_TRUE) {
        GS_RETURN_IFERR(do_commit(stmt->session));
    }

    return GS_SUCCESS;
}
status_t sql_execute_fetch_medatata(sql_stmt_t *stmt)
{
    if (stmt->status < STMT_STATUS_PREPARED) {
        GS_THROW_ERROR(ERR_INVALID_CURSOR);
        return GS_ERROR;
    }

    return my_sender(stmt)->send_parsed_stmt(stmt);
}

static status_t sql_reload_text(sql_stmt_t *stmt, sql_text_t *sql)
{
    if (ctx_read_text(sql_pool, &stmt->context->ctrl, &sql->value, GS_FALSE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    sql->implicit = GS_FALSE;
    sql->loc.line = 1;
    sql->loc.column = 1;
    return GS_SUCCESS;
}
static status_t sql_fork_stmt(sql_stmt_t *stmt, sql_stmt_t **ret)
{
    sql_stmt_t *sub_stmt = NULL;
    // PUSH stack will release by ple_exec_dynamic_sql
    GS_RETURN_IFERR(sql_push(stmt, sizeof(sql_stmt_t), (void **)&sub_stmt));

    sql_init_stmt(stmt->session, sub_stmt, stmt->id);
    SET_STMT_CONTEXT(sub_stmt, NULL);
    SET_STMT_PL_CONTEXT(sub_stmt, NULL);
    sub_stmt->status = STMT_STATUS_IDLE;
    sub_stmt->is_verifying = stmt->is_verifying;
    sub_stmt->is_srvoutput_on = stmt->is_srvoutput_on;
    sub_stmt->is_sub_stmt = GS_TRUE;
    sub_stmt->parent_stmt = stmt;
    sub_stmt->cursor_info.type = PL_FORK_CURSOR;
    sub_stmt->cursor_info.reverify_in_fetch = GS_TRUE;
    *ret = sub_stmt;
    return GS_SUCCESS;
}

// notice: only use in return result
status_t sql_execute_fetch_cursor_medatata(sql_stmt_t *stmt)
{
    if (stmt->status < STMT_STATUS_PREPARED || (stmt->cursor_info.has_fetched && stmt->eof)) {
        GS_THROW_ERROR(ERR_INVALID_CURSOR);
        return GS_ERROR;
    }

    sql_select_t *select_ctx = (sql_select_t *)stmt->context->entry;
    if (select_ctx->pending_col_count == 0) {
        return my_sender(stmt)->send_parsed_stmt(stmt);
    }

    sql_text_t sql;
    sql_stmt_t *sub_stmt = NULL;
    vmc_t vmc;
    vmc_init(&stmt->session->vmp, &vmc);
    GS_RETURN_IFERR(vmc_alloc(&vmc, stmt->context->ctrl.text_size + 1, (void **)&sql.str));
    sql.len = stmt->context->ctrl.text_size + 1;
    if (sql_reload_text(stmt, &sql) != GS_SUCCESS) {
        vmc_free(&vmc);
        return GS_ERROR;
    }
    SQL_SAVE_STACK(stmt);
    if (sql_fork_stmt(stmt, &sub_stmt) != GS_SUCCESS) {
        vmc_free(&vmc);
        return GS_ERROR;
    }

    status_t status = GS_ERROR;
    do {
        lex_reset(stmt->session->lex);
        GS_BREAK_IF_ERROR(sql_read_kept_params(stmt));
        sub_stmt->param_info.params = stmt->param_info.params;
        GS_BREAK_IF_ERROR(sql_parse_dml_directly(sub_stmt, KEY_WORD_SELECT, &sql));
        status = my_sender(stmt)->send_parsed_stmt(sub_stmt);
    } while (0);

    sql_free_context(sub_stmt->context);
    sql_release_resource(sub_stmt, GS_TRUE);
    SQL_RESTORE_STACK(stmt);
    vmc_free(&vmc);
    return status;
}

static inline status_t sql_send_fetch_result(sql_stmt_t *stmt, sql_cursor_t *cursor)
{
    if (cursor == NULL) {
        GS_THROW_ERROR(ERR_INVALID_CURSOR);
        return GS_ERROR;
    }
    if (sql_make_result_set(stmt, cursor) != GS_SUCCESS) {
        sql_release_resource(stmt, GS_TRUE);
        return GS_ERROR;
    }

    stmt->total_rows = cursor->total_rows;
    stmt->eof = cursor->eof;
    return GS_SUCCESS;
}

status_t sql_execute_fetch(sql_stmt_t *stmt)
{
    sql_cursor_t *cursor = SQL_ROOT_CURSOR(stmt);
    bool32 pre_eof = stmt->eof;

    if (stmt->status < STMT_STATUS_EXECUTED) {
        GS_THROW_ERROR(ERR_REQUEST_OUT_OF_SQUENCE, "executed.");
        return GS_ERROR;
    }

    if (stmt->eof) {
        stmt->total_rows = 0;
        stmt->batch_rows = 0;
        GS_RETURN_IFERR(my_sender(stmt)->send_fetch_begin(stmt));
        my_sender(stmt)->send_fetch_end(stmt);
        return GS_SUCCESS;
    }

    if (!stmt->resource_inuse) {
        GS_THROW_ERROR(ERR_INVALID_OPERATION, ",resource is already destroyed");
        return GS_ERROR;
    }

    GS_RETURN_IFERR(sql_read_kept_params(stmt));
    GS_RETURN_IFERR(sql_init_sequence(stmt));
    GS_RETURN_IFERR(sql_load_first_exec_vars(stmt));
    GS_RETURN_IFERR(sql_init_trigger_list(stmt));
    GS_RETURN_IFERR(sql_init_pl_ref_dc(stmt));

    stmt->batch_rows = 0;

    GS_RETURN_IFERR(my_sender(stmt)->send_fetch_begin(stmt));
    GS_RETURN_IFERR(sql_send_fetch_result(stmt, cursor));

    /*
     * if the "SQL_CALC_FOUND_ROWS" flag specified, the recent_foundrows should be calculated extra
     * otherwise it should be the same as the actually sent rows
     */
    stmt->session->recent_foundrows =
        cursor->total_rows + cursor->found_rows.limit_skipcount + cursor->found_rows.offset_skipcount;

    my_sender(stmt)->send_fetch_end(stmt);
    stmt->is_success = GS_TRUE;

    if (stmt->eof) {
        sql_unlock_lnk_tabs(stmt);
        if (NEED_TRACE(stmt) && sql_trace_dml_and_send(stmt) != GS_SUCCESS) {
            sql_release_resource(stmt, GS_FALSE);
            return GS_ERROR;
        }
        if (stmt->eof) {
            sql_release_resource(stmt, GS_FALSE);
            if (!pre_eof) {
                sql_dec_active_stmts(stmt);
            }
        }
    }

    return GS_SUCCESS;
}

void sql_init_varea_set(sql_stmt_t *stmt, sql_table_cursor_t *cursor)
{
    vmc_init(&stmt->session->vmp, &cursor->vmc);
    if (cursor->table != NULL && (cursor->table->type == JSON_TABLE)) {
        cursor->json_table_exec.json_assist = NULL;
        cursor->json_table_exec.json_value = NULL;
        cursor->json_table_exec.loc = NULL;
    } else {
        cursor->key_set.key_data = NULL;
        cursor->part_set.key_data = NULL;
        cursor->key_set.type = KEY_SET_FULL;
        cursor->part_set.type = KEY_SET_FULL;
    }
}

void sql_free_varea_set(sql_table_cursor_t *cursor)
{
    vmc_free(&cursor->vmc);
    cursor->key_set.key_data = NULL;
    cursor->part_set.key_data = NULL;
}

static status_t sql_execute_create_database(sql_stmt_t *stmt, bool32 clustered)
{
    status_t status;
    void *def = stmt->context->entry;

    status = knl_create_database(&stmt->session->knl_session, (knl_database_def_t *)def, clustered);
    if (status != GS_SUCCESS) {
        (void)server_shutdown(stmt->session, SHUTDOWN_MODE_ABORT);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t sql_try_import_rows(void *sql_stmt, uint32 count)
{
    sql_stmt_t *stmt = (sql_stmt_t *)sql_stmt;
    knl_table_def_t *table_def = NULL;

    // temporary table, on-commit-preserved-rows not specified, no need to import rows
    table_def = (knl_table_def_t *)stmt->context->entry;
    if (table_def->type == TABLE_TYPE_TRANS_TEMP) {
        return GS_SUCCESS;
    }

    // considering create table as select, stmt->context->supplement will not be null
    knl_panic(!stmt->context->supplement);
    return GS_SUCCESS;
}
static status_t sql_execute_create_table(sql_stmt_t *stmt)
{
    knl_table_def_t *table_def = (knl_table_def_t *)stmt->context->entry;
    knl_part_obj_def_t *obj_def = table_def->part_def;
    char name_arr[GS_NAME_BUFFER_SIZE] = { '\0' };
    text_t part_name;

    if (IS_LTT_BY_NAME(table_def->name.str)) {
        return GS_ERROR;
    }

    // generate the partition name
    if (obj_def != NULL) {
        int64 part_name_id = 0;
        knl_part_def_t *part_def = NULL;
        knl_part_def_t *subpart_def = NULL;
        for (uint32 i = 0; i < obj_def->parts.count; i++) {
            part_def = (knl_part_def_t *)cm_galist_get(&obj_def->parts, i);
            if (part_def->name.len == 0) {
                GS_RETURN_IFERR(sql_alloc_object_id(stmt, &part_name_id));
                PRTS_RETURN_IFERR(
                    snprintf_s(name_arr, GS_NAME_BUFFER_SIZE, GS_NAME_BUFFER_SIZE - 1, "SYS_P%lld", part_name_id));
                part_name.len = (uint32)strlen(name_arr);
                part_name.str = name_arr;

                GS_RETURN_IFERR(sql_copy_object_name(stmt->context, WORD_TYPE_STRING, &part_name, &part_def->name));
            }

            if (!part_def->is_parent) {
                continue;
            }

            for (uint32 j = 0; j < part_def->subparts.count; j++) {
                subpart_def = (knl_part_def_t *)cm_galist_get(&part_def->subparts, j);
                if (subpart_def->name.len == 0) {
                    GS_RETURN_IFERR(sql_alloc_object_id(stmt, &part_name_id));
                    PRTS_RETURN_IFERR(snprintf_s(name_arr, GS_NAME_BUFFER_SIZE, GS_NAME_BUFFER_SIZE - 1, "SYS_SUBP%lld",
                                                 part_name_id));
                    part_name.len = (uint32)strlen(name_arr);
                    part_name.str = name_arr;
                    GS_RETURN_IFERR(
                        sql_copy_object_name(stmt->context, WORD_TYPE_STRING, &part_name, &subpart_def->name));
                }
            }
        }
    }

    /*
    create table as select scenarios:
               IS_COORD_CONN && distribute_type != none
       1.CN:        0                  1   --> create_table_as_select
       2.DN:        1                  1   --> create_table
       3.singleton: 0                  0   --> create_table_as_select
       4.singleton --datanode with SYSDBA Login:
                    1                  0   --> create_table_as_select
    */
    if (stmt->context->supplement == NULL) {
        return knl_create_table(&stmt->session->knl_session, stmt, table_def);
    }

    return knl_create_table_as_select(&stmt->session->knl_session, stmt, table_def);
}

static status_t sql_execute_create_user(sql_stmt_t *stmt)
{
    status_t ret = GS_SUCCESS;
    errno_t errcode;

    knl_user_def_t *user_def = (knl_user_def_t *)stmt->context->entry;

    ret = knl_create_user(&stmt->session->knl_session, user_def);
    errcode = memset_s(user_def->password, GS_PASSWORD_BUFFER_SIZE, 0, GS_PASSWORD_BUFFER_SIZE);
    if (errcode != EOK) {
        GS_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return GS_ERROR;
    }
    return ret;
}

static status_t sql_execute_create_role(sql_stmt_t *stmt)
{
    status_t ret = GS_SUCCESS;
    errno_t errcode;

    knl_role_def_t *role_def = (knl_role_def_t *)stmt->context->entry;
    ret = knl_create_role(&stmt->session->knl_session, role_def);
    errcode = memset_s(role_def->password, GS_PASSWORD_BUFFER_SIZE, 0, GS_PASSWORD_BUFFER_SIZE);
    if (errcode != EOK) {
        GS_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return GS_ERROR;
    }

    return ret;
}

static status_t sql_execute_create_sequence(sql_stmt_t *stmt)
{
    knl_sequence_def_t *seuqence_def = (knl_sequence_def_t *)stmt->context->entry;
    return knl_create_sequence(&stmt->session->knl_session, stmt, seuqence_def);
}

status_t sql_execute_create_index(sql_stmt_t *stmt)
{
    knl_index_def_t *def = (knl_index_def_t *)stmt->context->entry;
    status_t status;

    if (IS_LTT_BY_NAME(def->table.str)) {
        status = knl_create_ltt_index(&stmt->session->knl_session, def);
    } else {
        status = knl_create_index(&stmt->session->knl_session, stmt, def);
    }

    return status;
}

static status_t sql_execute_drop_table(sql_stmt_t *stmt)
{
    knl_drop_def_t *def = (knl_drop_def_t *)stmt->context->entry;
    status_t status;

    if (IS_LTT_BY_NAME(def->name.str)) {
        status = knl_drop_ltt(&stmt->session->knl_session, def);
    } else {
        status = knl_drop_table(&stmt->session->knl_session, stmt, def);
        if (status == GS_ERROR) {
            int32 code = cm_get_error_code();
            if (((ERR_TABLE_OR_VIEW_NOT_EXIST == code) || (ERR_USER_NOT_EXIST == code)) &&
                (def->options & DROP_IF_EXISTS)) {
                // return success if drop clause containt if exists and object is not exists
                cm_reset_error();
                return GS_SUCCESS;
            }
        }
    }
    return status;
}

status_t sql_execute_drop_index(sql_stmt_t *stmt)
{
    knl_drop_def_t *def = (knl_drop_def_t *)stmt->context->entry;
    status_t status;
    if (def->ex_name.str != NULL && IS_LTT_BY_NAME(def->ex_name.str)) {
        status = knl_drop_ltt_index(&stmt->session->knl_session, def);
    } else {
        status = knl_drop_index(&stmt->session->knl_session, stmt, def);
    }
    return status;
}

static status_t sql_execute_flashback_table(sql_stmt_t *stmt)
{
    knl_flashback_def_t *def = (knl_flashback_def_t *)stmt->context->entry;

    if (def->type == FLASHBACK_TO_SCN) {
        if (sql_convert_to_scn(stmt, def->expr, GS_TRUE, &def->scn) != GS_SUCCESS) {
            return GS_ERROR;
        }
    } else if (def->type == FLASHBACK_TO_TIMESTAMP) {
        if (sql_convert_to_scn(stmt, def->expr, GS_FALSE, &def->scn) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return knl_flashback_table(&stmt->session->knl_session, def);
}

static status_t sql_execute_purge(sql_stmt_t *stmt)
{
    knl_purge_def_t *def = (knl_purge_def_t *)stmt->context->entry;

    return knl_purge(&stmt->session->knl_session, def);
}

static status_t sql_execute_analyze_table(sql_stmt_t *stmt)
{
    knl_analyze_tab_def_t *def = (knl_analyze_tab_def_t *)stmt->context->entry;
    status_t status;

    if (!def->is_report) {
        def->sample_ratio = 0;
        def->sample_type = STATS_AUTO_SAMPLE;
    }

    status = knl_analyze_table(&stmt->session->knl_session, def);
    return status;
}

static status_t sql_execute_analyze_index(sql_stmt_t *stmt)
{
    knl_analyze_index_def_t *def = (knl_analyze_index_def_t *)stmt->context->entry;

    return knl_analyze_index(&stmt->session->knl_session, def);
}

#define MAX_KNL_NODE_HASH_RANGE 10000

static status_t sql_execute_grant(sql_stmt_t *stmt)
{
    knl_grant_def_t *def = (knl_grant_def_t *)stmt->context->entry;

    return knl_exec_grant_privs(&stmt->session->knl_session, def);
}

static status_t sql_execute_revoke(sql_stmt_t *stmt)
{
    knl_revoke_def_t *def = (knl_revoke_def_t *)stmt->context->entry;

    return knl_exec_revoke_privs(&stmt->session->knl_session, def);
}

status_t sql_execute_ddl(sql_stmt_t *stmt)
{
    status_t status;

    sql_set_scn(stmt);
    sql_set_ssn(stmt);

    switch (stmt->context->type) {
        case SQL_TYPE_CREATE_DATABASE:
            status = sql_execute_create_database(stmt, GS_FALSE);
            // 'create database ...' will execute multiple SQL by calling multiple sql_execute_directly
            break;

        case SQL_TYPE_CREATE_CLUSTERED_DATABASE:
            status = sql_execute_create_database(stmt, GS_TRUE);
            break;

        case SQL_TYPE_CREATE_SEQUENCE:
            status = sql_execute_create_sequence(stmt);
            break;
        case SQL_TYPE_CREATE_TABLESPACE:
            status = GS_ERROR;
            break;
        case SQL_TYPE_CREATE_TABLE:
            status = sql_execute_create_table(stmt);
            break;
        case SQL_TYPE_CREATE_INDEX:
            status = sql_execute_create_index(stmt);
            break;
        case SQL_TYPE_CREATE_INDEXES:
            status = GS_ERROR;
            break;
        case SQL_TYPE_CREATE_USER:
            status = sql_execute_create_user(stmt);
            break;
        case SQL_TYPE_CREATE_ROLE:
            status = sql_execute_create_role(stmt);
            break;
        case SQL_TYPE_DROP_TABLE:
            status = sql_execute_drop_table(stmt);
            break;
        case SQL_TYPE_CREATE_VIEW:
        case SQL_TYPE_CREATE_SYNONYM:
        case SQL_TYPE_CREATE_PROFILE:
        case SQL_TYPE_CREATE_DIRECTORY:
        case SQL_TYPE_CREATE_CTRLFILE:
        case SQL_TYPE_CREATE_LIBRARY:
        case SQL_TYPE_DROP_SEQUENCE:
        case SQL_TYPE_DROP_TABLESPACE:
            status = GS_ERROR;
            break;
        case SQL_TYPE_DROP_INDEX:
            status = sql_execute_drop_index(stmt);
            break;
        case SQL_TYPE_DROP_USER:
        case SQL_TYPE_DROP_ROLE:
        case SQL_TYPE_DROP_VIEW:
        case SQL_TYPE_DROP_SYNONYM:
        case SQL_TYPE_DROP_PROFILE:
        case SQL_TYPE_DROP_DIRECTORY:
        case SQL_TYPE_DROP_LIBRARY:
        case SQL_TYPE_TRUNCATE_TABLE:
            status = GS_ERROR;
            break;
        case SQL_TYPE_PURGE:
            status = sql_execute_purge(stmt);
            break;
        case SQL_TYPE_COMMENT:
            status = GS_ERROR;
            break;
        case SQL_TYPE_FLASHBACK_TABLE:
            status = sql_execute_flashback_table(stmt);
            break;
        case SQL_TYPE_ALTER_SEQUENCE:
        case SQL_TYPE_ALTER_TABLESPACE:
        case SQL_TYPE_ALTER_TABLE:
        case SQL_TYPE_ALTER_INDEX:
        case SQL_TYPE_ALTER_USER:
        case SQL_TYPE_ALTER_DATABASE:
        case SQL_TYPE_ALTER_PROFILE:
            status = GS_ERROR;
            break;
        case SQL_TYPE_ANALYSE_TABLE:
            status = sql_execute_analyze_table(stmt);
            break;
        case SQL_TYPE_ANALYZE_INDEX:
            status = sql_execute_analyze_index(stmt);
            break;
        case SQL_TYPE_GRANT:
            status = sql_execute_grant(stmt);
            break;
        case SQL_TYPE_REVOKE:
            status = sql_execute_revoke(stmt);
            break;
        case SQL_TYPE_ALTER_TRIGGER:
        case SQL_TYPE_ALTER_SQL_MAP:
        case SQL_TYPE_DROP_SQL_MAP:
        case SQL_TYPE_CREATE_PROC:
        case SQL_TYPE_CREATE_FUNC:
        case SQL_TYPE_CREATE_PACK_SPEC:
        case SQL_TYPE_CREATE_PACK_BODY:
        case SQL_TYPE_CREATE_TRIG:
        case SQL_TYPE_CREATE_TYPE_SPEC:
        case SQL_TYPE_CREATE_TYPE_BODY:
        case SQL_TYPE_DROP_PROC:
        case SQL_TYPE_DROP_FUNC:
        case SQL_TYPE_DROP_TRIG:
        case SQL_TYPE_DROP_PACK_SPEC:
        case SQL_TYPE_DROP_PACK_BODY:
        case SQL_TYPE_DROP_TYPE_SPEC:
        case SQL_TYPE_DROP_TYPE_BODY:
            status = GS_ERROR;
            break;
        default:
            stmt->eof = GS_TRUE;
            GS_THROW_ERROR(ERR_INVALID_COMMAND, "ddl");
            return GS_ERROR;
    }

    if (status == GS_SUCCESS) {
        (void)do_commit(stmt->session);
    } else {
        do_rollback(stmt->session, NULL);
    }

    return status;
}

static status_t sql_set_param(sql_stmt_t *stmt, knl_alter_sys_def_t *def)
{
    CM_POINTER(stmt);
    knl_session_t *se = KNL_SESSION(stmt);
    database_t *db = &se->kernel->db;
    config_item_t *item = NULL;
    bool32 force = GS_TRUE;
    if (db->status != DB_STATUS_MOUNT && db->status != DB_STATUS_OPEN) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "set param only work in mount or open state");
        return GS_ERROR;
    }

    item = &se->kernel->attr.config->items[def->param_id];
    if (def->param_id != item->id) {
        GS_THROW_ERROR_EX(ERR_ASSERT_ERROR, "def->param_id(%u) == item->id(%u)", def->param_id, item->id);
        return GS_ERROR;
    }

    if (def->scope != CONFIG_SCOPE_DISK) {
        if (item->notify && item->notify((knl_handle_t)se, (void *)item, def->value)) {
            return GS_ERROR;
        }
    } else {
        if (item->notify_pfile && item->notify_pfile((knl_handle_t)se, (void *)item, def->value)) {
            return GS_ERROR;
        }
    }

    if (item->attr & ATTR_READONLY) {
#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
        force = GS_TRUE;
#else
        force = GS_FALSE;  // can not alter parameter whose attr is readonly  for release
#endif
    }
    if (cm_alter_config(se->kernel->attr.config, def->param, def->value, def->scope, force) != GS_SUCCESS) {
        return GS_ERROR;
    }
    GS_LOG_RUN_WAR("parameter %s has been changed successfully", def->param);
    GS_LOG_ALARM(WARN_PARAMCHANGE, "parameter : %s", def->param);
    return GS_SUCCESS;
}

status_t sql_recycle_sharedpool(sql_stmt_t *stmt, knl_alter_sys_def_t *def)
{
    knl_session_t *session = &stmt->session->knl_session;
    memory_pool_t *sqlpool = g_instance->sql.pool->memory;
    memory_pool_t *dc_pool = &session->kernel->dc_ctx.pool;
    memory_area_t *area = sqlpool->area;
    database_t *db = &session->kernel->db;

    if (db->status != DB_STATUS_MOUNT && db->status != DB_STATUS_OPEN) {
        GS_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "recycle sharedpool only work in mount or open state");
        return GS_ERROR;
    }
    if (def->force_recycle) {
        ctx_flush_shared_pool(sql_pool);
    }
    ctx_recycle_all();
    dc_recycle_all(session);

    if (sqlpool->free_pages.count > 0) {
        cm_spin_lock(&sqlpool->lock, NULL);
        if (sqlpool->free_pages.count > 0) {
            cm_spin_lock(&area->lock, NULL);
            cm_concat_page_list(area->maps, &area->free_pages, &sqlpool->free_pages);
            cm_spin_unlock(&area->lock);
            CM_ASSERT(sqlpool->page_count >= sqlpool->free_pages.count);
            sqlpool->page_count -= sqlpool->free_pages.count;
            sqlpool->free_pages.count = 0;
        }
        cm_spin_unlock(&sqlpool->lock);
    }
    if (dc_pool->free_pages.count > 0) {
        cm_spin_lock(&dc_pool->lock, NULL);
        if (dc_pool->free_pages.count > 0) {
            cm_spin_lock(&area->lock, NULL);
            cm_concat_page_list(area->maps, &area->free_pages, &dc_pool->free_pages);
            cm_spin_unlock(&area->lock);
            CM_ASSERT(dc_pool->page_count >= dc_pool->free_pages.count);
            dc_pool->page_count -= dc_pool->free_pages.count;
            dc_pool->free_pages.count = 0;
        }
        cm_spin_unlock(&dc_pool->lock);
    }

    return GS_SUCCESS;
}

status_t sql_execute_alter_system(sql_stmt_t *stmt)
{
    knl_alter_sys_def_t *def = (knl_alter_sys_def_t *)stmt->context->entry;

    switch (def->action) {
        case ALSYS_SWITCHLOG:
            return knl_switch_log(&stmt->session->knl_session);
        case ALSYS_SET_PARAM:
            return sql_set_param(stmt, def);
        case ALSYS_LOAD_DC:
            return knl_load_sys_dc(&stmt->session->knl_session, def);
        case ALSYS_INIT_ENTRY:
            return knl_init_entry(&stmt->session->knl_session, def);
        case ALSYS_DUMP_PAGE:
            return knl_dump_page(&stmt->session->knl_session, def);

        case ALSYS_DUMP_CTRLPAGE:
            return knl_dump_ctrl_page(&stmt->session->knl_session, def);
        case ALSYS_DUMP_DC:
            return knl_dump_dc(&stmt->session->knl_session, def);
        case ALSYS_FLUSH_BUFFER:
            return knl_flush_buffer(&stmt->session->knl_session, def);
        case ALSYS_RECYCLE_SHAREDPOOL:
            return sql_recycle_sharedpool(stmt, def);

        case ALSYS_KILL_SESSION:
        case ALSYS_RESET_STATISTIC:
            return GS_ERROR;

        case ALSYS_CHECKPOINT:
            return knl_checkpoint(&stmt->session->knl_session, def->ckpt_type);

        case ALSYS_RELOAD_HBA:
            return server_load_hba(GS_FALSE);

        case ALSYS_RELOAD_PBL:
            return server_load_pbl(GS_FALSE);

        case ALSYS_ADD_HBA_ENTRY:
            return GS_ERROR;

        case ALSYS_REFRESH_SYSDBA:
            return server_refresh_sysdba_privilege();
        case ALSYS_ADD_LSNR_ADDR:
        case ALSYS_DELETE_LSNR_ADDR:
        case ALSYS_DEL_HBA_ENTRY:
        case ALSYS_DEBUG_MODE:
        case ALSYS_MODIFY_REPLICA:
        case ALSYS_STOP_REPLICA:
            return GS_ERROR;
        case ALSYS_STOP_BUILD:
            return knl_stop_build(&stmt->session->knl_session);
        case ALSYS_REPAIR_CATALOG:
            return knl_repair_catalog(&stmt->session->knl_session);
        default:
            GS_THROW_ERROR(ERR_INVALID_COMMAND, "ddl");
            return GS_ERROR;
    }
}

static status_t sql_execute_alter_session(sql_stmt_t *stmt)
{
    alter_session_def_t *def = (alter_session_def_t *)stmt->context->entry;

    switch (def->action) {
        case ALTSES_SET:
        case ALTSES_DISABLE:
        case ALTSES_ENABLE:
        default:
            GS_THROW_ERROR(ERR_INVALID_COMMAND, "dcl");
            return GS_ERROR;
    }
}

static status_t sql_execute_backup(sql_stmt_t *stmt)
{
    knl_backup_t *param = (knl_backup_t *)stmt->context->entry;
    return knl_backup(&stmt->session->knl_session, param);
}

static status_t sql_execute_restore(sql_stmt_t *stmt)
{
    knl_restore_t *param = (knl_restore_t *)stmt->context->entry;

    return knl_restore(&stmt->session->knl_session, param);
}

static status_t sql_execute_recover(sql_stmt_t *stmt)
{
    knl_recover_t *param = (knl_recover_t *)stmt->context->entry;
    return knl_recover(&stmt->session->knl_session, param);
}

static status_t sql_execute_daac_recover(sql_stmt_t *stmt)
{
    knl_daac_recover_t *param = (knl_daac_recover_t *)stmt->context->entry;
    return knl_daac_recover(&stmt->session->knl_session, param);
}

static status_t sql_execute_validate(sql_stmt_t *stmt)
{
    knl_validate_t *param = (knl_validate_t *)stmt->context->entry;
    return knl_validate(&stmt->session->knl_session, param);
}

static status_t sql_execute_shutdown(sql_stmt_t *stmt)
{
    GS_LOG_RUN_INF("sql begin to execute shutdown");
    shutdown_context_t *param = (shutdown_context_t *)stmt->context->entry;

    return server_shutdown(stmt->session, param->mode);
}

static status_t sql_check_commit_for_dcl(sql_stmt_t *stmt)
{
    switch (stmt->context->type) {
        case SQL_TYPE_COMMIT_PHASE1:
        case SQL_TYPE_ALTER_SYSTEM:
        case SQL_TYPE_ALTER_SESSION:
        case SQL_TYPE_COMMIT_PHASE2:
        case SQL_TYPE_COMMIT:
        case SQL_TYPE_ROLLBACK_PHASE2:
        case SQL_TYPE_ROLLBACK:
        case SQL_TYPE_ROLLBACK_TO:
        case SQL_TYPE_SAVEPOINT:
        case SQL_TYPE_RELEASE_SAVEPOINT:
        case SQL_TYPE_SET_TRANS:
        default:
            return GS_SUCCESS;
    }
}

status_t sql_execute_dcl(sql_stmt_t *stmt)
{
    status_t status;
    sql_set_scn(stmt);
    sql_set_ssn(stmt);

    if (sql_check_commit_for_dcl(stmt) != GS_SUCCESS) {
        return GS_ERROR;
    }

    switch (stmt->context->type) {
        case SQL_TYPE_COMMIT_PHASE1:
            status = GS_ERROR;
            break;
        case SQL_TYPE_ALTER_SYSTEM:
            status = sql_execute_alter_system(stmt);
            break;
        case SQL_TYPE_ALTER_SESSION:
            status = sql_execute_alter_session(stmt);
            break;
        case SQL_TYPE_COMMIT_PHASE2:
        case SQL_TYPE_COMMIT:
        case SQL_TYPE_ROLLBACK_PHASE2:
        case SQL_TYPE_ROLLBACK:
        case SQL_TYPE_ROLLBACK_TO:
        case SQL_TYPE_SAVEPOINT:
        case SQL_TYPE_RELEASE_SAVEPOINT:
        case SQL_TYPE_SET_TRANS:
            status = GS_ERROR;
            break;
        case SQL_TYPE_BACKUP:
            status = sql_execute_backup(stmt);
            break;
        case SQL_TYPE_RESTORE:
            status = sql_execute_restore(stmt);
            break;
        case SQL_TYPE_RECOVER:
            status = sql_execute_recover(stmt);
            break;
        case SQL_TYPE_DAAC:
            status = sql_execute_daac_recover(stmt);
            break;
        case SQL_TYPE_SHUTDOWN:
            status = sql_execute_shutdown(stmt);
            break;
        case SQL_TYPE_LOCK_TABLE:
        case SQL_TYPE_BUILD:
            status = GS_ERROR;
            break;
        case SQL_TYPE_VALIDATE:
            status = sql_execute_validate(stmt);
            break;
        default:
            stmt->eof = GS_TRUE;
            GS_THROW_ERROR(ERR_INVALID_COMMAND, "dcl");
            return GS_ERROR;
    }
    return status;
}

static inline status_t sql_check_node_pending(sql_cursor_t *parent_cursor, uint32 tab, bool32 *pending)
{
    sql_table_cursor_t *tab_cur = &parent_cursor->tables[tab];

    if (parent_cursor->table_count > 1 && tab_cur->table->plan_id > parent_cursor->last_table) {
        *pending = GS_TRUE;
    }
    return GS_SUCCESS;
}

status_t sql_check_sub_select_pending(sql_cursor_t *parent_cursor, sql_select_t *select_ctx, bool32 *pending)
{
    uint32 table_id;
    parent_ref_t *parent_ref = NULL;

    if (select_ctx->parent_refs->count == 0) {
        return GS_SUCCESS;
    }

    for (uint32 i = 0; i < select_ctx->parent_refs->count; i++) {
        parent_ref = (parent_ref_t *)cm_galist_get(select_ctx->parent_refs, i);
        table_id = parent_ref->tab;
        GS_RETURN_IFERR(sql_check_node_pending(parent_cursor, table_id, pending));
        GS_BREAK_IF_TRUE(*pending);
    }
    return GS_SUCCESS;
}

static void sql_set_cursor_cond(sql_cursor_t *cursor, sql_query_t *query)
{
    if (query->connect_by_cond == NULL) {
        cursor->cond = query->cond;
        return;
    }

    if (cursor->connect_data.last_level_cursor == NULL) {
        cursor->cond = query->start_with_cond;
    } else {
        cursor->cond = query->connect_by_cond;
    }
}

static status_t sql_init_outer_join_exec_data(sql_stmt_t *stmt, sql_cursor_t *cursor, uint32 count)
{
    uint32 i, mem_cost_size;

    mem_cost_size = count * sizeof(outer_join_data_t);
    GS_RETURN_IFERR(vmc_alloc(&cursor->vmc, mem_cost_size, (void **)&cursor->exec_data.outer_join));

    for (i = 0; i < count; ++i) {
        cursor->exec_data.outer_join[i].need_reset_right = GS_TRUE;
        cursor->exec_data.outer_join[i].right_matched = GS_FALSE;
        cursor->exec_data.outer_join[i].need_swap_driver = GS_FALSE;
        cursor->exec_data.outer_join[i].nl_full_opt_ctx = NULL;
    }
    return GS_SUCCESS;
}

static status_t sql_init_inner_join_exec_data(sql_stmt_t *stmt, sql_cursor_t *cursor, uint32 count)
{
    if (count == 0) {
        return GS_SUCCESS;
    }
    uint32 i, mem_cost_size;

    mem_cost_size = count * sizeof(inner_join_data_t);
    GS_RETURN_IFERR(vmc_alloc(&cursor->vmc, mem_cost_size, (void **)&cursor->exec_data.inner_join));

    for (i = 0; i < count; ++i) {
        cursor->exec_data.inner_join[i].right_fetched = GS_FALSE;
    }
    return GS_SUCCESS;
}

status_t sql_generate_cursor_exec_data(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_query_t *query)
{
    sql_query_t *s_query = query->s_query;

    if (query->join_assist.outer_node_count > 0 || (s_query != NULL && s_query->join_assist.outer_node_count > 0)) {
        uint32 outer_plan_count = query->join_assist.outer_plan_count;
        if (s_query != NULL) {
            outer_plan_count = MAX(outer_plan_count, s_query->join_assist.outer_plan_count);
        }
        GS_RETURN_IFERR(sql_init_outer_join_exec_data(stmt, cursor, outer_plan_count));
    }

    // start-with clause may generated new join plan node
    if (query->tables.count > 1 || s_query != NULL) {
        uint32 inner_plan_count = query->join_assist.inner_plan_count;
        if (s_query != NULL) {
            inner_plan_count = MAX(inner_plan_count, s_query->join_assist.inner_plan_count);
        }
        GS_RETURN_IFERR(sql_init_inner_join_exec_data(stmt, cursor, inner_plan_count));
    }

    if (query->aggr_dis_count > 0) {
        knl_panic(0);
    }

    if (cursor->select_ctx != NULL && cursor->select_ctx->pending_col_count > 0) {
        knl_panic(0);
    }

    if (stmt->context->nl_batch_cnt > 0) {
        knl_panic(0);
    }

    if (query->join_assist.mj_plan_count > 0 || (s_query != NULL && s_query->join_assist.mj_plan_count > 0)) {
        knl_panic(0);
    }

    return GS_SUCCESS;
}

uint16 sql_get_decode_count(sql_table_t *table)
{
    bilist_node_t *node = NULL;
    query_field_t *query_field = NULL;

    if (table->query_fields.count == 0) {
        return 0;
    }
    node = cm_bilist_tail(&table->query_fields);
    query_field = BILIST_NODE_OF(query_field_t, node, bilist_node);
    return (uint16)(query_field->col_id + 1);
}

static inline status_t sql_calc_rownum_core(sql_stmt_t *stmt, cond_node_t *node, expr_node_t *var_expr,
                                            cmp_type_t cmp_type, uint32 *max_rownum)
{
    variant_t tmp_var;
    variant_t *var = NULL;

    if (var_expr->type != EXPR_NODE_CONST && var_expr->type != EXPR_NODE_PARAM) {
        return GS_SUCCESS;
    }

    if (NODE_IS_CONST(var_expr)) {
        var = &var_expr->value;
    } else {
        GS_RETURN_IFERR(sql_exec_expr_node(stmt, var_expr, &tmp_var));
        var = &tmp_var;
        if (var->is_null) {
            *max_rownum = 0U;
            return GS_SUCCESS;
        }
    }

    switch (cmp_type) {
        case CMP_TYPE_EQUAL:
            /* rownum=v, v<1 ==> false */
            /* rownum=v, v is real with non-zero tail (e.g., 2.3) */
            GS_RETURN_IFERR(var_as_real(var));
            if (var->v_real < 1 || (fabs(var->v_real - (uint32)(int32)var->v_real) >= GS_REAL_PRECISION)) {
                *max_rownum = 0U;
            } else {
                *max_rownum = (uint32)(int32)var->v_real;
            }
            break;

        case CMP_TYPE_LESS:
            /* rownum<v, v<=1  ==> false */
            GS_RETURN_IFERR(var_as_real(var));
            if (var->v_real <= 1) {
                *max_rownum = 0U;
            } else {
                *max_rownum = (uint32)(int32)ceil(var->v_real - 1.0);
            }
            break;

        case CMP_TYPE_LESS_EQUAL:
            /* rownum<=v, v<1  ==> false */
            GS_RETURN_IFERR(var_as_real(var));
            if (var->v_real < 1) {
                *max_rownum = 0U;
            } else {
                *max_rownum = (uint32)(int32)var->v_real;
            }
            break;

        default:
            *max_rownum = GS_INFINITE32;
            break;
    }

    return GS_SUCCESS;
}

static inline status_t sql_calc_rownum_right(sql_stmt_t *stmt, cond_node_t *node, uint32 *max_rownum)
{
    cmp_node_t *cmp_node = node->cmp;

    switch (cmp_node->type) {
        case CMP_TYPE_IS_NULL:
            *max_rownum = 0U;
            return GS_SUCCESS;

        case CMP_TYPE_IS_NOT_NULL:
            *max_rownum = GS_INFINITE32;
            return GS_SUCCESS;

        case CMP_TYPE_EQUAL:
        case CMP_TYPE_LESS:
        case CMP_TYPE_LESS_EQUAL:
        case CMP_TYPE_GREAT_EQUAL:
        case CMP_TYPE_GREAT:
        case CMP_TYPE_NOT_EQUAL:
            return sql_calc_rownum_core(stmt, node, cmp_node->right->root, cmp_node->type, max_rownum);

        default:
            break;
    }
    return GS_SUCCESS;
}

static inline status_t sql_calc_rownum_left(sql_stmt_t *stmt, cond_node_t *node, uint32 *max_rownum)
{
    cmp_node_t *cmp_node = node->cmp;

    switch (cmp_node->type) {
        case CMP_TYPE_GREAT_EQUAL:
            return sql_calc_rownum_core(stmt, node, cmp_node->left->root, CMP_TYPE_LESS_EQUAL, max_rownum);

        case CMP_TYPE_GREAT:
            return sql_calc_rownum_core(stmt, node, cmp_node->left->root, CMP_TYPE_LESS, max_rownum);

        case CMP_TYPE_EQUAL:
        case CMP_TYPE_LESS:
        case CMP_TYPE_LESS_EQUAL:
        case CMP_TYPE_NOT_EQUAL:
            return sql_calc_rownum_core(stmt, node, cmp_node->left->root, cmp_node->type, max_rownum);

        default:
            break;
    }
    return GS_SUCCESS;
}

static inline status_t sql_calc_cmp_rownum(sql_stmt_t *stmt, cond_node_t *node, uint32 *max_rownum)
{
    cmp_node_t *cmp_node = node->cmp;
    expr_node_t *left = NULL;
    expr_node_t *right = NULL;

    *max_rownum = GS_INFINITE32;

    /* already set rnum_pending flag in rbo_try_rownum_optmz */
    if (!cmp_node->rnum_pending) {
        return GS_SUCCESS;
    }

    left = cmp_node->left->root;
    if (NODE_IS_RES_ROWNUM(left)) {
        GS_RETURN_IFERR(sql_calc_rownum_right(stmt, node, max_rownum));
    }

    if (cmp_node->type == CMP_TYPE_IS_NULL || cmp_node->type == CMP_TYPE_IS_NOT_NULL) {
        return GS_SUCCESS;
    }

    right = cmp_node->right->root;
    if ((cmp_node->right->next == NULL) && NODE_IS_RES_ROWNUM(right)) {
        GS_RETURN_IFERR(sql_calc_rownum_left(stmt, node, max_rownum));
    }

    return GS_SUCCESS;
}

static inline status_t sql_calc_cond_rownum(sql_stmt_t *stmt, cond_node_t *node, uint32 *rnum_upper)
{
    uint32 l_upper, r_upper;

    GS_RETURN_IFERR(sql_stack_safe(stmt));

    switch (node->type) {
        case COND_NODE_COMPARE:
            GS_RETURN_IFERR(sql_calc_cmp_rownum(stmt, node, rnum_upper));
            break;

        case COND_NODE_OR:
            GS_RETURN_IFERR(sql_calc_cond_rownum(stmt, node->left, &l_upper));
            GS_RETURN_IFERR(sql_calc_cond_rownum(stmt, node->right, &r_upper));
            *rnum_upper = MAX(l_upper, r_upper);
            break;

        case COND_NODE_AND:
            GS_RETURN_IFERR(sql_calc_cond_rownum(stmt, node->left, &l_upper));
            GS_RETURN_IFERR(sql_calc_cond_rownum(stmt, node->right, &r_upper));
            *rnum_upper = MIN(l_upper, r_upper);
            break;

        default:
            *rnum_upper = GS_INFINITE32;
            break;
    }

    return GS_SUCCESS;
}

static void sql_set_cursor_max_rownum(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_query_t *query)
{
    cursor->max_rownum = GS_INFINITE32;
    if (cursor->connect_data.last_level_cursor != NULL) {
        return;
    }

    cond_tree_t *cond = NULL;
    if (query->join_assist.outer_node_count > 0 && query->filter_cond != NULL) {  // only used for rownum filter
        cond = query->filter_cond;
        cursor->max_rownum = cond->rownum_upper;
    } else if (query->cond != NULL) {  // used for rownum filter, also used for rownum count
        cond = query->cond;
        cursor->max_rownum = cond->rownum_upper;
    }

    if (cursor->max_rownum == GS_INFINITE32 && cond != NULL && cond->rownum_pending) {
        (void)sql_calc_cond_rownum(stmt, cond->root, &cursor->max_rownum);
    }
}

status_t sql_fetch_rownum(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof)
{
    if (cursor->rownum >= cursor->max_rownum) {
        cursor->connect_data.cur_level_cursor = NULL;
        *eof = GS_TRUE;
        return GS_SUCCESS;
    }
    cursor->rownum++;
    GS_RETURN_IFERR(sql_fetch_query(stmt, cursor, plan->rownum_p.next, eof));
    if (*eof) {
        return GS_SUCCESS;
    }
    return GS_SUCCESS;
}

static status_t sql_open_table_cursor(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_table_cursor_t *tab_cur,
                                      knl_cursor_action_t cursor_action, bool32 is_select)
{
    sql_table_t *table = tab_cur->table;
    sql_query_t *query = cursor->query;

    tab_cur->scan_flag = table->tf_scan_flag;
    tab_cur->hash_table = GS_FALSE;
    tab_cur->action = cursor_action;
    sql_init_varea_set(stmt, tab_cur);

    if (table->version.type == CURR_VERSION) {
        tab_cur->scn = cursor->scn;
    } else {
        bool32 scn_type = (table->version.type == SCN_VERSION) ? GS_TRUE : GS_FALSE;
        GS_RETURN_IFERR(sql_convert_to_scn(stmt, table->version.expr, scn_type, &tab_cur->scn));
    }

    if (GS_IS_SUBSELECT_TABLE(table->type)) {
        GS_RETURN_IFERR(sql_alloc_cursor(stmt, &tab_cur->sql_cur));
        tab_cur->sql_cur->scn = tab_cur->scn;
        tab_cur->sql_cur->select_ctx = table->select_ctx;
        tab_cur->sql_cur->plan = table->select_ctx->plan;
        tab_cur->sql_cur->global_cached = cursor->global_cached || table->global_cached;
        tab_cur->sql_cur->ancestor_ref = cursor;
        tab_cur->sql_cur->select_ctx->for_update_params.type = is_select ? cursor->select_ctx->for_update_params.type
                                                                         : ROWMARK_WAIT_BLOCK;
        tab_cur->sql_cur->select_ctx->for_update_params.wait_seconds =
            is_select ? cursor->select_ctx->for_update_params.wait_seconds : 0;
        return GS_SUCCESS;
    }

    if (table->type == JSON_TABLE) {
        MEMS_RETURN_IFERR(
            memset_sp(&tab_cur->json_table_exec, sizeof(json_table_exec_t), 0, sizeof(json_table_exec_t)));
    }

    GS_RETURN_IFERR(sql_alloc_knl_cursor(stmt, &tab_cur->knl_cur));
    tab_cur->knl_cur->action = (IF_LOCK_IN_FETCH(query) && table->for_update) ? CURSOR_ACTION_UPDATE : cursor_action;
    tab_cur->knl_cur->for_update_fetch = table->for_update;
    tab_cur->knl_cur->rowmark.type = is_select ? cursor->select_ctx->for_update_params.type : ROWMARK_WAIT_BLOCK;
    tab_cur->knl_cur->rowmark.wait_seconds = is_select ? cursor->select_ctx->for_update_params.wait_seconds : 0;
    tab_cur->knl_cur->update_info.count = 0;
    tab_cur->knl_cur->global_cached = cursor->global_cached || table->global_cached;

    if (is_select) {
        tab_cur->knl_cur->decode_count = sql_get_decode_count(table);
    }

    return GS_SUCCESS;
}

status_t sql_open_cursors(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_query_t *query, knl_cursor_action_t cursor_action,
                          bool32 is_select)
{
    if (cursor->is_open) {
        sql_close_cursor(stmt, cursor);
    }

    cursor->is_open = GS_TRUE;
    cursor->select_ctx = query->owner;
    cursor->query = query;
    cursor->eof = GS_FALSE;
    cursor->rownum = 0;

    sql_set_cursor_cond(cursor, query);
    sql_set_cursor_max_rownum(stmt, cursor, query);

    cursor->columns = query->rs_columns;
    cursor->table_count = 0;
    cursor->winsort_ready = GS_FALSE;
    /*
     * @NOTE
     * "cursor->table_count" is related to the sql_close_cursor() in dml_executor.c
     * if the counting method changed, check sql_close_cursor() too.
     */
    sql_array_t *tables = sql_get_query_tables(cursor, query);
    GS_RETURN_IFERR(sql_alloc_table_cursors(cursor, tables->count));

    for (uint32 i = 0; i < tables->count; i++) {
        sql_table_t *table = (sql_table_t *)sql_array_get(tables, i);
        cursor->tables[i].table = table;
        cursor->id_maps[i] = table->id;

        GS_RETURN_IFERR(sql_open_table_cursor(stmt, cursor, &cursor->tables[i], cursor_action, is_select));

        cursor->table_count++;
    }

    sql_init_ssa_cursor_maps(cursor, query->ssa.count);
    /* generate exec data for open cursor, exec data contains:
       out join, aggr_distinct and etc.
    */
    return sql_generate_cursor_exec_data(stmt, cursor, query);
}

static inline void sql_open_cursor_4_hash_mtrl(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_query_t *query)
{
    if (cursor->is_open) {
        sql_close_cursor(stmt, cursor);
    }
    cursor->eof = GS_FALSE;
    cursor->query = query;
    cursor->rownum = 0;
    cursor->is_open = GS_TRUE;
    cursor->select_ctx = query->owner;
}

status_t sql_open_query_cursor(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_query_t *query)
{
    return sql_open_cursors(stmt, cursor, query, CURSOR_ACTION_SELECT, GS_TRUE);
}

status_t sql_fetch_query(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof)
{
    status_t status = GS_SUCCESS;

    if (cursor->eof) {
        *eof = GS_TRUE;
        return GS_SUCCESS;
    }

    /* reset cached sequence */
    sql_reset_sequence(stmt);

    CM_TRACE_BEGIN;

    switch (plan->type) {
        case PLAN_NODE_SCAN:
            status = sql_fetch_scan(stmt, cursor, plan, eof);
            break;

        case PLAN_NODE_CONCATE:
        case PLAN_NODE_JOIN:
        case PLAN_NODE_QUERY_SORT:
        case PLAN_NODE_QUERY_SIBL_SORT:
        case PLAN_NODE_SORT_GROUP:
        case PLAN_NODE_MERGE_SORT_GROUP:
        case PLAN_NODE_HASH_GROUP:
        case PLAN_NODE_HASH_GROUP_PAR:
        case PLAN_NODE_HASH_GROUP_PIVOT:
        case PLAN_NODE_INDEX_GROUP:
        case PLAN_NODE_AGGR:
        case PLAN_NODE_INDEX_AGGR:
        case PLAN_NODE_QUERY_LIMIT:
        case PLAN_NODE_SORT_DISTINCT:
        case PLAN_NODE_HASH_DISTINCT:
        case PLAN_NODE_INDEX_DISTINCT:
        case PLAN_NODE_HAVING:
        case PLAN_NODE_CONNECT:
        case PLAN_NODE_CONNECT_HASH:
        case PLAN_NODE_FILTER:
        case PLAN_NODE_WINDOW_SORT:
        case PLAN_NODE_HASH_MTRL:
        case PLAN_NODE_GROUP_CUBE:
        case PLAN_NODE_UNPIVOT:
            status = GS_ERROR;
            break;

        case PLAN_NODE_ROWNUM:
            status = sql_fetch_rownum(stmt, cursor, plan, eof);
            break;

        case PLAN_NODE_FOR_UPDATE:
        case PLAN_NODE_CONNECT_MTRL:
        case PLAN_NODE_WITHAS_MTRL:
        case PLAN_NODE_VM_VIEW_MTRL:
            knl_panic(0);  // wei: todo
            break;

        default:
            status = sql_fetch_scan(stmt, cursor, plan, eof);
            break;
    }

    SQL_CHECK_SESSION_VALID_FOR_RETURN(stmt);
    if (!IS_QUERY_SCAN_PLAN(plan->type)) {
        CM_TRACE_END(stmt, plan->plan_id);
    }
    return status;
}

status_t sql_execute_query_plan(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    GS_RETURN_IFERR(sql_stack_safe(stmt));
    CM_TRACE_BEGIN;
    status_t status;
    switch (plan->type) {
        case PLAN_NODE_SCAN:
            status = sql_execute_scan(stmt, cursor, plan);
            break;
        case PLAN_NODE_QUERY_SORT:
        case PLAN_NODE_AGGR:
        case PLAN_NODE_JOIN:
        case PLAN_NODE_CONCATE:
        case PLAN_NODE_SORT_GROUP:
        case PLAN_NODE_MERGE_SORT_GROUP:
        case PLAN_NODE_HASH_GROUP:
        case PLAN_NODE_HASH_GROUP_PAR:
        case PLAN_NODE_HASH_GROUP_PIVOT:
        case PLAN_NODE_UNPIVOT:
        case PLAN_NODE_QUERY_SORT_PAR:
        case PLAN_NODE_QUERY_SIBL_SORT:
        case PLAN_NODE_INDEX_GROUP:
        case PLAN_NODE_INDEX_AGGR:
        case PLAN_NODE_SORT_DISTINCT:
        case PLAN_NODE_HASH_DISTINCT:
        case PLAN_NODE_INDEX_DISTINCT:
        case PLAN_NODE_HAVING:
        case PLAN_NODE_QUERY_LIMIT:
        case PLAN_NODE_CONNECT:
        case PLAN_NODE_CONNECT_HASH:
        case PLAN_NODE_FILTER:
        case PLAN_NODE_WINDOW_SORT:
        case PLAN_NODE_HASH_MTRL:
        case PLAN_NODE_GROUP_CUBE:
        case PLAN_NODE_ROWNUM:
        case PLAN_NODE_FOR_UPDATE:
        case PLAN_NODE_CONNECT_MTRL:
        default:
            status = GS_ERROR;
            GS_THROW_ERROR(ERR_UNKNOWN_PLAN_TYPE, (int32)plan->type, "execute sql");
            break;
    }
    if (!IS_QUERY_SCAN_PLAN(plan->type)) {
        CM_TRACE_END(stmt, plan->plan_id);
    }
    return status;
}

status_t sql_execute_query(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    plan_node_t *next = plan->query.next;

    GS_RETURN_IFERR(sql_open_query_cursor(stmt, cursor, plan->query.ref));

    return sql_execute_query_plan(stmt, cursor, next);
}

status_t sql_make_normal_rs(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_fetch_func_t sql_fetch_func,
                            sql_send_row_func_t sql_send_row_func)
{
    bool32 is_full = GS_FALSE;

    do {
        SQL_SAVE_STACK(stmt);
        if (sql_fetch_func(stmt, cursor, stmt->rs_plan, &cursor->eof) != GS_SUCCESS) {
            SQL_RESTORE_STACK(stmt);
            return GS_ERROR;
        }

        if (cursor->eof) {
            my_sender(stmt)->send_column_def(stmt, cursor);
            sql_close_cursor(stmt, cursor);
            SQL_RESTORE_STACK(stmt);
            return GS_SUCCESS;
        }

        if (sql_send_row_func(stmt, cursor, &is_full) != GS_SUCCESS) {
            SQL_RESTORE_STACK(stmt);
            return GS_ERROR;
        }
        SQL_RESTORE_STACK(stmt);

        SQL_CHECK_SESSION_VALID_FOR_RETURN(stmt);
    } while (!is_full);

    my_sender(stmt)->send_column_def(stmt, cursor);
    return GS_SUCCESS;
}

sql_send_row_func_t sql_get_send_row_func(sql_stmt_t *stmt, plan_node_t *plan)
{
    if (SECUREC_UNLIKELY(stmt->rs_type == RS_TYPE_ROW)) {
        knl_panic(0);
    }
    switch (plan->type) {
        case PLAN_NODE_QUERY:
            return sql_get_send_row_func(stmt, plan->query.next);

        case PLAN_NODE_SORT_DISTINCT:
        case PLAN_NODE_SELECT_SORT:
        case PLAN_NODE_MINUS:
        case PLAN_NODE_HASH_MINUS:
        case PLAN_NODE_QUERY_SORT_PAR:
        case PLAN_NODE_QUERY_SIBL_SORT:
        case PLAN_NODE_QUERY_SORT:
        case PLAN_NODE_SELECT_LIMIT:
        case PLAN_NODE_QUERY_LIMIT:
        case PLAN_NODE_WINDOW_SORT:
            return NULL;

        default:
            return sql_send_row;
    }
}

void sql_open_select_cursor(sql_stmt_t *stmt, sql_cursor_t *cursor, galist_t *rs_columns)
{
    if (cursor->is_open) {
        sql_close_cursor(stmt, cursor);
    }

    cursor->eof = GS_FALSE;
    cursor->rownum = 0;
    cursor->columns = rs_columns;
    cursor->is_open = GS_TRUE;
}

status_t sql_execute_select_plan(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    status_t status;
    GS_RETURN_IFERR(sql_stack_safe(stmt));
    GS_RETURN_IFERR(SQL_CURSOR_PUSH(stmt, cursor));
    CM_TRACE_BEGIN;

    switch (plan->type) {
        case PLAN_NODE_QUERY:
            status = sql_execute_query(stmt, cursor, plan);
            break;

        case PLAN_NODE_UNION_ALL:
        case PLAN_NODE_UNION:
        case PLAN_NODE_MINUS:
        case PLAN_NODE_HASH_MINUS:
        case PLAN_NODE_SELECT_SORT:
        case PLAN_NODE_SELECT_LIMIT:
        case PLAN_NODE_WITHAS_MTRL:
        case PLAN_NODE_VM_VIEW_MTRL:
        default:
            GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "Don't support the plan type(%d)", plan->type);
            status = GS_ERROR;
            break;
    }
    CM_TRACE_END(stmt, plan->plan_id);
    SQL_CURSOR_POP(stmt);
    return status;
}

status_t sql_execute_select(sql_stmt_t *stmt)
{
    sql_select_t *select = NULL;
    sql_cursor_t *cursor = NULL;
    sql_set_ssn(stmt);
    CM_TRACE_BEGIN;
    select = (sql_select_t *)stmt->context->entry;

    cursor = SQL_ROOT_CURSOR(stmt);
    cursor->plan = select->plan;
    cursor->select_ctx = select;
    cursor->scn = GS_INVALID_ID64;
    cursor->found_rows.offset_skipcount = 0;
    cursor->found_rows.limit_skipcount = 0;
    cursor->total_rows = 0;

    stmt->need_send_ddm = GS_TRUE;
    if (sql_execute_select_plan(stmt, cursor, cursor->plan->select_p.next) != GS_SUCCESS) {
        return GS_ERROR;
    }
    stmt->need_send_ddm = GS_FALSE;
    stmt->rs_type = select->rs_type;
    stmt->rs_plan = select->rs_plan;

    GS_RETURN_IFERR(sql_make_result_set(stmt, cursor));
    CM_TRACE_END(stmt, select->plan->plan_id);
    return GS_SUCCESS;
}

static inline void sql_free_scan(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    sql_table_t *table = plan->scan_p.table;
    sql_table_cursor_t *tab_cur = &cursor->tables[table->id];

    if ((tab_cur->sql_cur != NULL) && GS_IS_SUBSELECT_TABLE(table->type)) {
        sql_free_cursor(stmt, tab_cur->sql_cur);
        tab_cur->sql_cur = NULL;
    }
}

status_t sql_get_stmt(session_t *session, uint32 stmt_id)
{
    if (stmt_id >= session->stmts.count) {
        GS_THROW_ERROR(ERR_INVALID_STATEMENT_ID, stmt_id);
        return GS_ERROR;
    }

    session->current_stmt = (sql_stmt_t *)cm_list_get(&session->stmts, stmt_id);
    if (session->current_stmt == NULL || session->current_stmt->status == STMT_STATUS_FREE) {
        GS_THROW_ERROR(ERR_INVALID_STATEMENT_ID, stmt_id);
        return GS_ERROR;
    }

    array_set_handle((void *)&session->knl_session, session->knl_session.temp_mtrl->pool);
    return GS_SUCCESS;
}

status_t sql_process_free_stmt(session_t *session)
{
    uint16 stmt_id = 0;

    GS_RETURN_IFERR(cs_get_int16(session->recv_pack, (int16 *)&stmt_id));

    if (stmt_id == GS_INVALID_ID16 || sql_get_stmt(session, stmt_id) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_INVALID_STATEMENT_ID, stmt_id);
        return GS_ERROR;
    }

    sql_free_stmt(session->current_stmt);
    return GS_SUCCESS;
}

static status_t sql_process_get_alter_set(session_t *session, alter_set_info_t *alter_set_info, nlsparams_t *nls_params)
{
    int32 alter_se_lenth;
    GS_RETURN_IFERR(cs_get_int32(session->recv_pack, &alter_se_lenth));
    knl_panic(alter_se_lenth == 0);
    return GS_SUCCESS;
}

static status_t sql_process_alter_set(session_t *session)
{
    alter_set_info_t alter_set_info;
    nlsparams_t nls_params;
    GS_RETURN_IFERR(sql_process_get_alter_set(session, &alter_set_info, &nls_params));
    return GS_SUCCESS;
}

static inline void sql_set_autotrace(session_t *session, cs_prepare_req_t *req)
{
    session->knl_session.autotrace = GS_FALSE;
}

static inline status_t sql_get_stmt_id(session_t *session, uint16 stmt_id)
{
    if (stmt_id == GS_INVALID_ID16) {
        GS_RETURN_IFERR(sql_alloc_stmt(session, &session->current_stmt));
        session->current_stmt->is_temp_alloc = GS_TRUE;
    } else {
        GS_RETURN_IFERR(sql_get_stmt(session, stmt_id));
    }

    return GS_SUCCESS;
}

status_t sql_process_prepare(session_t *session)
{
    cs_prepare_req_t *req = NULL;
    sql_stmt_t *stmt = NULL;

    GS_RETURN_IFERR(cs_get_data(session->recv_pack, sizeof(cs_prepare_req_t), (void **)&req));
    GS_RETURN_IFERR(sql_process_alter_set(session));
    /* get stmt to prepare sql */
    GS_RETURN_IFERR(sql_get_stmt_id(session, req->stmt_id));
    stmt = session->current_stmt;

    /* set autotrace flag */
    sql_set_autotrace(session, req);

    sql_release_lob_info(stmt);

    return sql_prepare(stmt);
}

void sql_clean_returned_rs(sql_stmt_t *stmt)
{
    sql_stmt_t *item = NULL;
    for (uint32 i = 0; i < stmt->session->stmts.count; i++) {
        item = (sql_stmt_t *)cm_list_get(&stmt->session->stmts, i);
        if (item->status == STMT_STATUS_FREE) {
            continue;
        }

        if (item->cursor_info.is_returned && item->cursor_info.rrs_sn == item->session->rrs_sn) {
            sql_free_stmt(item);
        }
    }
}

static void sql_init_stmt_before_exec(session_t *session, sql_stmt_t *stmt, cs_execute_req_t *exec_req)
{
    stmt->param_info.paramset_size = exec_req->paramset_size;
    stmt->prefetch_rows = (exec_req->prefetch_rows == 0 ? g_instance->sql.prefetch_rows : exec_req->prefetch_rows);
    stmt->auto_commit = exec_req->auto_commit;
    session->auto_commit = stmt->auto_commit;

    stmt->is_srvoutput_on = ((session->recv_pack->head->flags & CS_FLAG_SERVEROUPUT) != 0);
    stmt->return_generated_key = (session->recv_pack->head->flags & CS_FLAG_RETURN_GENERATED_KEY) ? GS_TRUE : GS_FALSE;

    return;
}

status_t sql_process_execute(session_t *session)
{
    cs_execute_req_t *exec_req = NULL;
    sql_stmt_t *stmt = NULL;
    status_t ret;
    knl_scn_t local_scn = GS_INVALID_ID64;

    GS_RETURN_IFERR(cs_get_data(session->recv_pack, sizeof(cs_execute_req_t), (void **)&exec_req));

    GS_RETURN_IFERR(sql_get_stmt(session, exec_req->stmt_id));
    stmt = session->current_stmt;

    stmt->sync_scn = local_scn;
    stmt->gts_offset = 0;

    sql_mark_lob_info(stmt);

    sql_init_stmt_before_exec(session, stmt, exec_req);

    if ((session->recv_pack->head->flags & GS_FLAG_ALLOWED_BATCH_ERRS) != 0) {
        GS_RETURN_IFERR(cs_get_int32(session->recv_pack, (int32 *)&stmt->allowed_batch_errs));
    } else {
        stmt->allowed_batch_errs = 0;
    }

    do {
        ret = sql_execute(stmt);

        GS_BREAK_IF_ERROR(ret);
    } while (GS_FALSE);

    if (ret != GS_SUCCESS) {
        sql_clean_returned_rs(stmt);
    }

    knl_panic(stmt->pl_set_schema[0] == '\0');

    return ret;
}

status_t sql_process_fetch(session_t *session)
{
    cs_fetch_req_t *req = NULL;
    sql_stmt_t *stmt = NULL;
    status_t status;

    GS_RETURN_IFERR(cs_get_data(session->recv_pack, sizeof(cs_fetch_req_t), (void **)&req));

    if (sql_get_stmt(session, req->stmt_id) != GS_SUCCESS) {
        return GS_ERROR;
    }
    stmt = session->current_stmt;

    stmt->status = STMT_STATUS_FETCHING;

    do {
        if (req->fetch_mode == CS_FETCH_NORMAL) {
            status = sql_execute_fetch(stmt);
        } else if (req->fetch_mode == CS_FETCH_WITH_PREP_EXEC) {
            status = sql_execute_fetch_medatata(stmt);
            GS_BREAK_IF_ERROR(status);
            status = sql_read_params(stmt);
            GS_BREAK_IF_ERROR(status);
            status = sql_execute(stmt);
        } else if (req->fetch_mode == CS_FETCH_WITH_PREP) {
            status = sql_execute_fetch_cursor_medatata(stmt);
            GS_BREAK_IF_ERROR(status);
            status = sql_execute_fetch(stmt);
        } else {
            GS_THROW_ERROR(ERR_REQUEST_OUT_OF_SQUENCE, "fetch.");
            status = GS_ERROR;
        }
    } while (GS_FALSE);

    stmt->param_info.paramset_size = 0;
    stmt->status = STMT_STATUS_FETCHED;

    return status;
}

status_t sql_process_commit(session_t *session)
{
    CM_POINTER(session);
    GS_RETURN_IFERR(do_commit(session));
    return GS_SUCCESS;
}

status_t sql_process_query(session_t *session)
{
    /* sql_process_query contains prepare and execute:
    request content is "cs_execute_req_t + sql"
    response content is "cs_prepare_ack_t + cs_execute_ack_t"
    */
    cs_execute_req_t *req = NULL;
    sql_stmt_t *stmt = NULL;

    GS_RETURN_IFERR(cs_get_data(session->recv_pack, sizeof(cs_execute_req_t), (void **)&req));

    /* get stmt to prepare sql */
    GS_RETURN_IFERR(sql_get_stmt_id(session, req->stmt_id));

    stmt = session->current_stmt;

    stmt->param_info.paramset_size = req->paramset_size;
    stmt->prefetch_rows = (req->prefetch_rows == 0 ? g_instance->sql.prefetch_rows : req->prefetch_rows);
    stmt->auto_commit = req->auto_commit;
    session->auto_commit = stmt->auto_commit;
    stmt->is_srvoutput_on = ((session->recv_pack->head->flags & CS_FLAG_SERVEROUPUT) != 0);

    GS_RETURN_IFERR(sql_prepare(stmt));
    return sql_execute(stmt);
}
