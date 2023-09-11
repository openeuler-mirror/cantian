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
 * func_others.c
 *
 *
 * IDENTIFICATION
 * src/cmd/function/func_others.c
 *
 * -------------------------------------------------------------------------
 */
#include "func_others.h"
#include "srv_instance.h"
#include "srv_view.h"
#include "srv_query.h"


static funcoi_support_type_t g_objtype_support_range[FUNC_OBJ_ID_TYPE_COUNT] = {
    { FUNC_OBJ_ID_TABLE,     "TABLE" },
    { FUNC_OBJ_ID_VIEW,      "VIEW" },
    { FUNC_OBJ_ID_DYNVIEW,   "DYNAMIC VIEW" },
    { FUNC_OBJ_ID_PROCEDURE, "PROCEDURE" },
    { FUNC_OBJ_ID_FUNCTION,  "FUNCTION" },
    { FUNC_OBJ_ID_TRIGGER,   "TRIGGER" },
};

static status_t sql_func_userenv_arg_option_processor(sql_stmt_t *stmt, expr_tree_t *arg, variant_t *arg_var);
static status_t sql_func_sysctx_userenv_options_handler(sql_stmt_t *stmt, int32 option_id, variant_t *result);

/*
 * cantian doest not support "DBE_SESSION.SET_CONTEXT" currently, so we can use an internal global array to store
 * the handlers of the default context "USERENV". however, if the "DBE_SESSION.SET_CONTEXT" is to be implemented,
 * we should re-design the method to support various context.
 */
static funcctx_support_type_t g_sysctx_support_range[] = {
    { "USERENV", sql_func_userenv_arg_option_processor, sql_func_sysctx_userenv_options_handler },
};
static uint32 g_sysctx_support_range_count = (uint32)(sizeof(g_sysctx_support_range) / sizeof(funcctx_support_type_t));

status_t sql_func_userenv_arg_option_processor(sql_stmt_t *stmt, expr_tree_t *arg, variant_t *arg_var)
{
    variant_t tmp;
    int32 i;
    funcctx_support_option_t supported_options[(int32)FUNC_SYS_CTX_OPTIONS_COUNT] = {
        { FUNC_SYS_CTX_SID,            "SID" },
        { FUNC_SYS_CTX_TERMINAL,       "TERMINAL" },
        { FUNC_SYS_CTX_CURR_SCHEMA,    "CURRENT_SCHEMA" },
        { FUNC_SYS_CTX_CURR_SCHEMA_ID, "CURRENT_SCHEMAID" },
        { FUNC_SYS_CTX_DB_NAME,        "DB_NAME" },
        { FUNC_SYS_CTX_OS_USER,        "OS_USER" },
        { FUNC_SYS_CTX_TENANT_NAME,    "TENANT_NAME" },
        { FUNC_SYS_CTX_TENANT_ID,      "TENANT_ID" },
    };
    funcctx_support_option_t *option_found = NULL;

    GS_RETURN_IFERR(sql_exec_expr(stmt, arg, &tmp));
    if (!GS_IS_STRING_TYPE(tmp.type)) {
        GS_SRC_ERROR_REQUIRE_STRING(arg->loc, tmp.type);
        return GS_ERROR;
    }
    if (tmp.is_null) {
        GS_SRC_THROW_ERROR(arg->loc, ERR_INVALID_FUNC_PARAMS, "the option name cannot be NULL");
        return GS_ERROR;
    }

    arg_var->type = GS_TYPE_INTEGER;
    arg_var->is_null = GS_FALSE;

    for (i = 0; i < (int32)FUNC_SYS_CTX_OPTIONS_COUNT; i++) {
        if (!cm_compare_text_str_ins(&tmp.v_text, supported_options[i].opname)) {
            option_found = &supported_options[i];
            break;
        }
    }
    if (option_found == NULL) {
        GS_SRC_THROW_ERROR_EX(arg->loc, ERR_INVALID_FUNC_PARAMS, "unrecognised option name \"%s\".", T2S(&tmp.v_text));
        return GS_ERROR;
    }

    arg_var->v_int = (int32)option_found->opid;
    return GS_SUCCESS;
}

static status_t sql_func_userenv_arg_retval_len_processor(sql_stmt_t *stmt, expr_tree_t *arg, variant_t *arg_var)
{
    variant_t tmp;

    arg_var->type = GS_TYPE_INTEGER;
    arg_var->is_null = GS_FALSE;
    if (arg == NULL) {
        arg_var->v_int = SQL_USERENV_VALUE_DEFAULT_LEN;
    } else {
        GS_RETURN_IFERR(sql_exec_expr(stmt, arg, &tmp));

        /* sql_keep_stack_variant() will be called in sql_convert_variant() */
        GS_RETURN_IFERR(sql_convert_variant(stmt, &tmp, GS_TYPE_INTEGER));
        if ((tmp.v_int < 1) || (tmp.v_int > 4000)) {
            /* invalid value would be ignored */
            arg_var->v_int = SQL_USERENV_VALUE_DEFAULT_LEN;
        } else {
            arg_var->v_int = tmp.v_int;
        }
    }
    return GS_SUCCESS;
}

static status_t sql_func_sysctx_process_namespace(sql_stmt_t *stmt, expr_tree_t *arg_namespc,
    funcctx_support_type_t **ctx_type, variant_t *result)
{
    variant_t namespc_var;
    uint32 i;
    funcctx_support_type_t *found_type = NULL;

    GS_RETURN_IFERR(sql_exec_expr(stmt, arg_namespc, &namespc_var));
    SQL_CHECK_COLUMN_VAR(&namespc_var, result);

    if (!GS_IS_STRING_TYPE(namespc_var.type)) {
        GS_SRC_ERROR_REQUIRE_STRING(arg_namespc->loc, namespc_var.type);
        return GS_ERROR;
    }

    if (namespc_var.is_null) {
        GS_SRC_THROW_ERROR(arg_namespc->loc, ERR_INVALID_FUNC_PARAMS, "namespace cannot be NULL");
        return GS_ERROR;
    }

    for (i = 0; i < g_sysctx_support_range_count; i++) {
        if (!cm_compare_text_str_ins(&namespc_var.v_text, g_sysctx_support_range[i].namespc)) {
            found_type = &g_sysctx_support_range[i];
            break;
        }
    }

    if (found_type == NULL) {
        GS_SRC_THROW_ERROR_EX(arg_namespc->loc, ERR_INVALID_FUNC_PARAMS, "unrecognised namespace name \"%s\".",
            T2S(&namespc_var.v_text));
        return GS_ERROR;
    }

    *ctx_type = found_type;
    return GS_SUCCESS;
}

status_t sql_func_sysctx_userenv_options_handler(sql_stmt_t *stmt, int32 option_id, variant_t *result)
{
    variant_t int_var;
    uint32 cpy_len = 0;
    switch (option_id) {
        case (int32)FUNC_SYS_CTX_SID:
            int_var.type = GS_TYPE_INTEGER;
            int_var.is_null = GS_FALSE;
            int_var.v_int = (int32)(KNL_SESSION(stmt)->id);

            GS_RETURN_IFERR(sql_convert_variant(stmt, &int_var, GS_TYPE_STRING));
            cpy_len = int_var.v_text.len;
            if (cpy_len > result->v_text.len) {
                cpy_len = result->v_text.len;
            }
            if (cpy_len != 0) {
                MEMS_RETURN_IFERR(memcpy_s(result->v_text.str, result->v_text.len, int_var.v_text.str, cpy_len));
            }
            result->v_text.len = cpy_len; /* make the field "len" as the actual length of string */
            break;
        case (int32)FUNC_SYS_CTX_TERMINAL:
            cpy_len = (uint32)strlen(stmt->session->os_host); /* end with '\0' */
            if (cpy_len > result->v_text.len) {
                cpy_len = result->v_text.len; /* the user-specified length is too small, so trunc the string */
            }
            /*
             * the "os_host" field of "session_t" structure stores the remote client's hostname,
             * which also stands for the column "MACHINE" in DV_SESSIONS and the column "OS_HOST" in DV_ME.
             * please refer to the function vw_make_session_rows() and vw_me_fetch()
             */
            if (cpy_len != 0) {
                MEMS_RETURN_IFERR(memcpy_s(result->v_text.str, result->v_text.len, stmt->session->os_host, cpy_len));
            }
            result->v_text.len = cpy_len; /* make the field "len" as the actual length of string */
            break;
        case (int32)FUNC_SYS_CTX_CURR_SCHEMA:
            cpy_len = (uint32)strlen(stmt->session->curr_schema);
            if (cpy_len > result->v_text.len) {
                cpy_len = result->v_text.len;
            }
            if (cpy_len != 0) {
                MEMS_RETURN_IFERR(
                    memcpy_s(result->v_text.str, result->v_text.len, stmt->session->curr_schema, cpy_len));
            }
            result->v_text.len = cpy_len; /* make the field "len" as the actual length of string */
            break;
        case (int32)FUNC_SYS_CTX_CURR_SCHEMA_ID:
            int_var.type = GS_TYPE_INTEGER;
            int_var.is_null = GS_FALSE;
            int_var.v_int = (int32)stmt->session->curr_schema_id;

            GS_RETURN_IFERR(sql_convert_variant(stmt, &int_var, GS_TYPE_STRING));
            cpy_len = int_var.v_text.len;
            if (cpy_len > result->v_text.len) {
                cpy_len = result->v_text.len;
            }
            if (cpy_len != 0) {
                MEMS_RETURN_IFERR(memcpy_s(result->v_text.str, result->v_text.len, int_var.v_text.str, cpy_len));
            }
            result->v_text.len = cpy_len; /* make the field "len" as the actual length of string */
            break;
        case (int32)FUNC_SYS_CTX_DB_NAME:
            cpy_len = (uint32)strlen(KNL_SESSION(stmt)->kernel->db.ctrl.core.name);
            if (cpy_len > result->v_text.len) {
                cpy_len = result->v_text.len;
            }
            if (cpy_len != 0) {
                MEMS_RETURN_IFERR(memcpy_s(result->v_text.str, result->v_text.len,
                    KNL_SESSION(stmt)->kernel->db.ctrl.core.name, cpy_len));
            }
            result->v_text.len = cpy_len; /* make the field "len" as the actual length of string */
            break;
        case (int32)FUNC_SYS_CTX_OS_USER:
            cpy_len = (uint32)strlen(stmt->session->os_user);
            if (cpy_len > result->v_text.len) {
                cpy_len = result->v_text.len;
            }
            if (cpy_len != 0) {
                MEMS_RETURN_IFERR(memcpy_s(result->v_text.str, result->v_text.len, stmt->session->os_user, cpy_len));
            }
            result->v_text.len = cpy_len; /* make the field "len" as the actual length of string */
            break;
        case (int32)FUNC_SYS_CTX_TENANT_NAME:
            cpy_len = (uint32)strlen(stmt->session->curr_tenant);
            if (cpy_len > result->v_text.len) {
                cpy_len = result->v_text.len;
            }
            if (cpy_len != 0) {
                MEMS_RETURN_IFERR(
                    memcpy_s(result->v_text.str, result->v_text.len, stmt->session->curr_tenant, cpy_len));
            }
            result->v_text.len = cpy_len; /* make the field "len" as the actual length of string */
            break;
        case (int32)FUNC_SYS_CTX_TENANT_ID:
            int_var.type = GS_TYPE_INTEGER;
            int_var.is_null = GS_FALSE;
            int_var.v_int = (int32)stmt->session->curr_tenant_id;

            GS_RETURN_IFERR(sql_convert_variant(stmt, &int_var, GS_TYPE_STRING));
            cpy_len = int_var.v_text.len;
            if (cpy_len > result->v_text.len) {
                cpy_len = result->v_text.len;
            }
            if (cpy_len != 0) {
                MEMS_RETURN_IFERR(memcpy_s(result->v_text.str, result->v_text.len, int_var.v_text.str, cpy_len));
            }
            result->v_text.len = cpy_len; /* make the field "len" as the actual length of string */
            break;
        default:
            GS_THROW_ERROR(ERR_VALUE_ERROR, "unrecgnised option code");
            return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t sql_verify_md5(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 1, 1, GS_INVALID_ID32) != GS_SUCCESS) {
        return GS_ERROR;
    }

    func->datatype = GS_TYPE_STRING;
    func->size = GS_MD5_SIZE;
    return GS_SUCCESS;
}

status_t sql_func_md5(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    uchar       digest[GS_MD5_HASH_SIZE] = { 0 };
    variant_t var;
    binary_t bin = {
        .bytes = digest,
        .size = GS_MD5_HASH_SIZE
    };

    CM_POINTER3(stmt, func, result);
    expr_tree_t *arg = func->argument;
    CM_POINTER(arg);

    SQL_EXEC_FUNC_ARG_EX(arg, &var, result);
    sql_keep_stack_variant(stmt, &var);
    if (sql_var_as_string(stmt, &var) != GS_SUCCESS) {
        cm_set_error_loc(arg->loc);
        return GS_ERROR;
    }

    cm_calc_md5((const uchar *)var.v_text.str, var.v_text.len, (uchar *)digest);

    if (sql_push(stmt, GS_MD5_SIZE + 1, (void **)&result->v_text.str) != GS_SUCCESS) {
        SQL_POP(stmt);
        cm_set_error_loc(arg->loc);
        return GS_ERROR;
    }
    result->v_text.len = GS_MD5_SIZE + 1;
    if (cm_bin2text(&bin, GS_FALSE, &result->v_text) != GS_SUCCESS) {
        SQL_POP(stmt);
        cm_set_error_loc(arg->loc);
        return GS_ERROR;
    }
    cm_text_lower(&result->v_text);
    result->type = GS_TYPE_STRING;
    result->is_null = GS_FALSE;
    return GS_SUCCESS;
}

status_t sql_func_hash(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    uint32 arg_count;
    variant_t arg_var;
    expr_tree_t *arg = func->argument;
    char *buf = NULL;
    row_assist_t ra;

    if (sql_push(stmt, GS_MAX_ROW_SIZE, (void **)&buf) != GS_SUCCESS) {
        return GS_ERROR;
    }
    arg_count = sql_expr_list_len(arg);
    row_init(&ra, buf, GS_MAX_ROW_SIZE, arg_count);

    SQL_SAVE_STACK(stmt);

    while (arg != NULL) {
        SQL_EXEC_FUNC_ARG_EX(arg, &arg_var, result);
        sql_keep_stack_variant(stmt, &arg_var);

        if (sql_put_row_value(stmt, NULL, &ra, arg_var.type, &arg_var) != GS_SUCCESS) {
            SQL_RESTORE_STACK(stmt);
            SQL_POP(stmt);
            return GS_ERROR;
        }
        SQL_RESTORE_STACK(stmt);
        arg = arg->next;
    }

    result->type = GS_TYPE_UINT32;
    result->v_uint32 = sql_hash_func(buf);
    result->is_null = GS_FALSE;
    SQL_POP(stmt);
    return GS_SUCCESS;
}

status_t sql_func_gs_hash(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t var_data, var_max_bucket;
    expr_tree_t *arg_data = NULL;
    expr_tree_t *arg_max_bucket = NULL;

    CM_POINTER3(stmt, func, result);
    result->type = GS_TYPE_UINT32;
    arg_data = func->argument;
    CM_POINTER(arg_data);

    SQL_EXEC_FUNC_ARG_EX(arg_data, &var_data, result);
    sql_keep_stack_variant(stmt, &var_data);
    if (var_data.is_null) {
        result->is_null = GS_TRUE;
        return GS_SUCCESS;
    }

    arg_max_bucket = arg_data->next;
    if (arg_max_bucket == NULL) {
        var_max_bucket.is_null = GS_FALSE;
        var_max_bucket.v_uint32 = GS_INVALID_ID32;
        var_max_bucket.type = GS_TYPE_UINT32;
    } else {
        SQL_EXEC_FUNC_ARG_EX(arg_max_bucket, &var_max_bucket, result);
        GS_RETURN_IFERR(var_as_uint32(&var_max_bucket));
    }

    result->v_uint32 = knl_get_bucket_by_variant(&var_data, var_max_bucket.v_uint32);
    result->is_null = GS_FALSE;
    return GS_SUCCESS;
}

status_t sql_verify_gs_hash(sql_verifier_t *verifier, expr_node_t *func)
{
    GS_RETURN_IFERR(sql_verify_func_node(verifier, func, 1, 2, GS_INVALID_ID32));

    func->datatype = GS_TYPE_UINT32;
    func->size = GS_INTEGER_SIZE;
    return GS_SUCCESS;
}

status_t sql_verify_hash(sql_verifier_t *verifier, expr_node_t *func)
{
    if (sql_verify_func_node(verifier, func, 1, GS_MAX_FUNC_ARGUMENTS, GS_INVALID_ID32) != GS_SUCCESS) {
        return GS_ERROR;
    }
    func->datatype = GS_TYPE_UINT32;
    func->size = GS_INTEGER_SIZE;
    return GS_SUCCESS;
}

/*
 * CONNECTION_ID(): returns the id of the current session.
 */
status_t sql_func_connection_id(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    CM_POINTER3(stmt, func, result);

    result->v_int = (int32)stmt->session->knl_session.id;
    result->type = GS_TYPE_INTEGER;
    result->is_null = GS_FALSE;

    return GS_SUCCESS;
}

status_t sql_verify_connection_id(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (func->argument != NULL) {
        GS_SRC_THROW_ERROR(func->loc, ERR_INVALID_FUNC_PARAM_COUNT, T2S(&func->word.func.name), 0, 0);
        return GS_ERROR;
    }

    func->datatype = GS_TYPE_INTEGER;
    func->size = GS_INTEGER_SIZE;

    return GS_SUCCESS;
}

status_t sql_verify_found_rows(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    GS_RETURN_IFERR(sql_verify_func_node(verf, func, 0, 0, GS_INVALID_ID32));

    func->datatype = GS_TYPE_BIGINT;
    func->size = sizeof(int64);

    return GS_SUCCESS;
}

status_t sql_func_found_rows(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    CM_POINTER3(stmt, func, result);

    result->type = func->datatype;
    result->is_null = GS_FALSE;
    result->v_bigint = (int64)(SESSION_GET_FOUND_COUNT(stmt->session));

    return GS_SUCCESS;
}

status_t sql_func_dba_exec_ddl(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    text_t ddl_info;
    variant_t value;
    uint32 used_encrypt = 0;
    status_t status = GS_SUCCESS;
    sql_stmt_t *save_curr_stmt = stmt->session->current_stmt;
    sql_stmt_t *save_unnamed_stmt = stmt->session->unnamed_stmt;

    CM_POINTER3(stmt, func, result);

    result->type = GS_TYPE_INTEGER;
    result->is_null = GS_FALSE;
    CM_SAVE_STACK(stmt->session->stack);
    do {
        status = sql_exec_expr(stmt, func->argument, &value);
        GS_BREAK_IF_ERROR(status);
        SQL_CHECK_COLUMN_VAR(&value, result);
        status = sql_convert_variant(stmt, &value, GS_TYPE_STRING);
        GS_BREAK_IF_ERROR(status);
        if (value.is_null) {
            GS_THROW_ERROR(ERR_TF_TABLE_DIST_DDL_ID_NULL);
            status = GS_ERROR;
            break;
        }
        char decrypt_ddl[GS_PASSWORD_BUFFER_SIZE + 1];
        uint32 decrypt_ddl_size = GS_PASSWORD_BUFFER_SIZE;
        if (used_encrypt > 0) {
            aes_and_kmc_t aes_kmc = { 0 };
            cm_kmc_set_aes_key_with_config(&aes_kmc, &g_instance->config);
            cm_kmc_set_kmc(&aes_kmc, GS_KMC_SERVER_DOMAIN, KMC_ALGID_AES256_CBC);
            cm_kmc_set_buf(&aes_kmc, decrypt_ddl, decrypt_ddl_size, ddl_info.str, ddl_info.len);
            // can not use like this way at present:GS_RETURN_IFERR(cm_decrypt_passwd_with_key_by_kmc(&aes_kmc));
            // because not all NODE share the MK of KMC, and all the data just in MEM, so just be the old way
            status = cm_decrypt_passwd_with_key(&aes_kmc);
            GS_BREAK_IF_ERROR(status);
            ddl_info.str = decrypt_ddl;
            ddl_info.len = (uint32)strlen(decrypt_ddl);
        }

        stmt->session->unnamed_stmt = NULL;
        status = sql_execute_directly(stmt->session, &ddl_info, NULL, GS_TRUE);
        sql_free_stmt(stmt->session->unnamed_stmt);
        stmt->session->unnamed_stmt = save_unnamed_stmt;
        stmt->session->current_stmt = save_curr_stmt;
        GS_BREAK_IF_ERROR(status);
    } while (0);

    result->v_int = status;
    CM_RESTORE_STACK(stmt->session->stack);

    return status;
}

status_t sql_verify_dba_exec_ddl(sql_verifier_t *verifier, expr_node_t *func)
{
    CM_POINTER2(verifier, func);

    GS_RETURN_IFERR(sql_verify_func_node(verifier, func, 1, 1, GS_INVALID_ID32));

    func->datatype = GS_TYPE_INTEGER;
    func->size = GS_INTEGER_SIZE;

    return GS_SUCCESS;
}

status_t sql_verify_updating(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);
    if (verf->context == NULL || verf->context->type != SQL_TYPE_CREATE_TRIG) {
        GS_SRC_THROW_ERROR_EX(func->loc, ERR_SQL_SYNTAX_ERROR, "'%s' must be in a trigger", T2S(&func->word.func.name));
        return GS_ERROR;
    }

    GS_RETURN_IFERR(sql_verify_func_node(verf, func, 1, 1, GS_INVALID_ID32));

    func->datatype = GS_TYPE_BOOLEAN;
    func->size = GS_BOOLEAN_SIZE;
    return GS_SUCCESS;
}

static status_t sql_get_endian_arg(sql_stmt_t *stmt, expr_node_t *func, bool32 is_least, variant_t *result)
{
    expr_tree_t *arg = NULL;
    variant_t var;
    int32 cmp_code;
    char *addr = NULL;
    text_buf_t buffer;

    arg = func->argument;

    if (GS_IS_VARLEN_TYPE(func->datatype)) {
        GS_RETURN_IFERR(sql_push(stmt, GS_STRING_BUFFER_SIZE, (void **)&addr));
        CM_INIT_TEXTBUF(&buffer, GS_STRING_BUFFER_SIZE, addr);
    } else {
        CM_INIT_TEXTBUF(&buffer, 0, NULL);
    }

    SQL_EXEC_FUNC_ARG_EX(arg, result, result);
    sql_keep_stack_variant(stmt, result);

    arg = arg->next;
    while (arg != NULL) {
        SQL_EXEC_FUNC_ARG_EX(arg, &var, result);

        if (var_convert(SESSION_NLS(stmt), &var, result->type, &buffer) != GS_SUCCESS) {
            cm_set_error_loc(arg->loc);
            return GS_ERROR;
        }

        if (sql_compare_variant(stmt, &var, result, &cmp_code) != GS_SUCCESS) {
            cm_set_error_loc(arg->loc);
            return GS_ERROR;
        }

        if (cmp_code == 0) {
            arg = arg->next;
            continue;
        }

        if (is_least) {
            if (cmp_code < 0) {
                var_copy(&var, result);
            }
        } else if (cmp_code > 0) {
            var_copy(&var, result);
        }

        arg = arg->next;
    }

    return GS_SUCCESS;
}

status_t sql_func_least(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    return sql_get_endian_arg(stmt, func, GS_TRUE, result);
}

status_t sql_func_greatest(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    return sql_get_endian_arg(stmt, func, GS_FALSE, result);
}

status_t sql_verify_least_greatest(sql_verifier_t *verifier, expr_node_t *func)
{
    CM_POINTER(func);
    GS_RETURN_IFERR(sql_verify_func_node(verifier, func, 1, GS_MAX_DECODE_ARGUMENTS, 1));

    return GS_SUCCESS;
}


/*
 * the options may vary from context to context, so a context entity owns
 * a parse function of the option and a execute function of the option
 *
 * the following function is the actual entry to parse the option and retrieve the
 * needed context information.
 */
static status_t sql_func_sys_context_core(sql_stmt_t *stmt, funcctx_support_type_t *context_type,
    expr_tree_t *arg_option, uint32 retval_len, variant_t *result)
{
    variant_t option;

    /* parse the option */
    GS_RETURN_IFERR(context_type->option_processor(stmt, arg_option, &option));

    result->type = GS_TYPE_STRING;
    result->is_null = GS_FALSE;
    GS_RETURN_IFERR(sql_push(stmt, retval_len, (void **)&result->v_text.str));
    result->v_text.len = retval_len; /* use the field "len" as the buffer size before value assignment */
    /* keep the buffer of result because option_handler may also allocate stack memory */
    sql_keep_stack_variant(stmt, result);

    /* retrieve the information according to the specified option */
    GS_RETURN_IFERR(context_type->option_handler(stmt, option.v_int, result));

    return GS_SUCCESS;
}

status_t sql_func_sys_context(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    funcctx_support_type_t *spec_ctx = NULL;
    variant_t var_retlen;

    CM_POINTER5(stmt, func, func->argument, func->argument->next, result);

    GS_RETURN_IFERR(sql_func_sysctx_process_namespace(stmt, func->argument, &spec_ctx, result));
    if (result->type == GS_TYPE_COLUMN) {
        return GS_SUCCESS;
    }

    if (func->argument->next->next != NULL) {
        GS_RETURN_IFERR(sql_func_userenv_arg_retval_len_processor(stmt, func->argument->next->next, &var_retlen));
    } else {
        GS_RETURN_IFERR(sql_func_userenv_arg_retval_len_processor(stmt, NULL, &var_retlen));
    }

    GS_RETURN_IFERR(sql_func_sys_context_core(stmt, spec_ctx, func->argument->next, (uint32)var_retlen.v_int, result));

    return GS_SUCCESS;
}

status_t sql_verify_sys_context(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 2, 3, GS_INVALID_ID32) != GS_SUCCESS) {
        return GS_ERROR;
    }

    expr_tree_t *arg = func->argument;
    if (TREE_IS_RES_NULL(arg)) {
        GS_SRC_THROW_ERROR(arg->loc, ERR_INVALID_FUNC_PARAMS, "namespace cannot be NULL");
        return GS_ERROR;
    }

    arg = arg->next;
    if (TREE_IS_RES_NULL(arg)) {
        GS_SRC_THROW_ERROR(arg->loc, ERR_INVALID_FUNC_PARAMS, "the option name cannot be NULL");
        return GS_ERROR;
    }

    func->datatype = GS_TYPE_STRING;
    func->size = SQL_USERENV_VALUE_DEFAULT_LEN;
    return GS_SUCCESS;
}

status_t sql_func_userenv(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    funcctx_support_type_t *spec_ctx = &g_sysctx_support_range[0]; /* default context */

    GS_RETURN_IFERR(sql_func_sys_context_core(stmt, spec_ctx, func->argument, SQL_USERENV_VALUE_DEFAULT_LEN, result));

    return GS_SUCCESS;
}
status_t sql_verify_userenv(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 1, 1, GS_INVALID_ID32) != GS_SUCCESS) {
        return GS_ERROR;
    }

    func->datatype = GS_TYPE_STRING;
    func->size = SQL_USERENV_VALUE_DEFAULT_LEN;
    return GS_SUCCESS;
}

status_t sql_func_version(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    char *str = cantiand_get_dbversion();

    result->type = GS_TYPE_STRING;
    result->is_null = GS_FALSE;
    GS_RETURN_IFERR(sql_push(stmt, 50, (void **)&result->v_text.str));
    result->v_text.len = (uint32)strlen(str);
    result->v_text.str = str;
    sql_keep_stack_variant(stmt, result);

    return GS_SUCCESS;
}

status_t sql_verify_version(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (func->argument != NULL) {
        GS_THROW_ERROR(ERR_INVALID_FUNC_PARAMS, "parameter is not null.");
        return GS_ERROR;
    }

    func->datatype = GS_TYPE_STRING;
    func->size = SQL_VERSION_VALUE_DEFAULT_LEN;
    return GS_SUCCESS;
}

status_t sql_func_type_name(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    const text_t *name_text = NULL;

    GS_RETURN_IFERR(sql_exec_expr(stmt, func->argument, res));
    SQL_CHECK_COLUMN_VAR(res, res);
    if (res->is_null) {
        name_text = get_datatype_name(GS_TYPE_UNKNOWN);
    } else {
        if (var_as_integer(res) != GS_SUCCESS) {
            return GS_ERROR;
        }

        name_text = get_datatype_name(res->v_int);
    }

    res->is_null = GS_FALSE;
    res->v_text = *name_text;
    res->type = GS_TYPE_STRING;
    return GS_SUCCESS;
}

status_t sql_verify_to_type_mapped(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 1, 1, GS_INVALID_ID32) != GS_SUCCESS) {
        return GS_ERROR;
    }

    func->datatype = GS_TYPE_VARCHAR;
    func->size = GS_MAX_NAME_LEN;

    return GS_SUCCESS;
}

status_t sql_func_scn2date(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t arg_var;

    CM_POINTER3(stmt, func, result);
    CM_POINTER(func->argument);

    SQL_EXEC_FUNC_ARG_EX(func->argument, &arg_var, result);
    if (var_as_bigint(&arg_var) != GS_SUCCESS) {
        cm_set_error_loc(func->loc);
        return GS_ERROR;
    }

    struct timeval tv;
    knl_scn_to_timeval(stmt->session, arg_var.v_bigint, &tv);
    result->is_null = GS_FALSE;
    result->v_date = cm_timeval2date(tv);
    result->type = GS_TYPE_DATE;
    return GS_SUCCESS;
}

status_t sql_verify_scn2date(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 1, 1, GS_INVALID_ID32) != GS_SUCCESS) {
        return GS_ERROR;
    }

    func->datatype = GS_TYPE_DATE;
    func->size = GS_DATE_SIZE;

    return GS_SUCCESS;
}

/*
 * convert GTS scn to date
 */
status_t sql_func_gscn2date(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t arg_var;

    CM_POINTER3(stmt, func, result);
    CM_POINTER(func->argument);

    SQL_EXEC_FUNC_ARG_EX(func->argument, &arg_var, result);
    if (var_as_bigint(&arg_var) != GS_SUCCESS) {
        cm_set_error_loc(func->loc);
        return GS_ERROR;
    }

    uint64 gts_scn = (uint64)arg_var.v_bigint;
    struct timeval tv;
    KNL_SCN_TO_TIME(gts_scn, &tv, CM_GTS_BASETIME);
    result->is_null = GS_FALSE;
    result->v_date = cm_timeval2date(tv);
    result->type = GS_TYPE_DATE;
    return GS_SUCCESS;
}

status_t sql_verify_gscn2date(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 1, 1, GS_INVALID_ID32) != GS_SUCCESS) {
        return GS_ERROR;
    }

    func->datatype = GS_TYPE_DATE;
    func->size = GS_DATE_SIZE;

    return GS_SUCCESS;
}

status_t sql_verify_coalesce(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);
    expr_tree_t *arg = NULL;
    expr_tree_t *arg_pre = func->argument;
    bool32 is_settype = GS_FALSE;
    bool32 is_difftype = GS_FALSE;
    uint32 strsize, strsize_pre;
    typmode_t typmod;

    if (sql_verify_func_node(verf, func, 1, GS_MAX_FUNC_ARGUMENTS, GS_INVALID_ID32) != GS_SUCCESS) {
        return GS_ERROR;
    }

    for (arg = func->argument; arg != NULL; arg = arg->next) {
        // Determine if all parameters are the same, or convert to varchar type uniformly
        if (cm_combine_typmode(TREE_TYPMODE(arg_pre), GS_FALSE, TREE_TYPMODE(arg), GS_FALSE, &typmod) != GS_SUCCESS) {
            cm_reset_error();
            strsize_pre = cm_get_datatype_strlen(arg_pre->root->datatype, arg_pre->root->size);
            strsize = cm_get_datatype_strlen(arg->root->datatype, arg->root->size);
            func->typmod.datatype = GS_TYPE_VARCHAR;
            func->typmod.size = (strsize_pre > strsize) ? strsize_pre : strsize;
            is_difftype = GS_TRUE;
        }
        arg_pre = arg;

        // Use first non-NULL arg type as func->datatype,
        if (!TREE_IS_RES_NULL(arg) && !is_settype && !is_difftype) {
            func->typmod = TREE_TYPMODE(arg);
            is_settype = GS_TRUE;
        } else if (is_settype && !is_difftype &&
            (get_datatype_weight(typmod.datatype) > get_datatype_weight(func->typmod.datatype))) {
            /* get the last combine typmode */
            func->typmod = typmod;
        }
    }

    if (is_difftype) {
        cm_reset_error();
    } else if (!is_settype) {
        // Use GS_TYPE_UNKNOWN if non-NULL args unavailable
        func->datatype = GS_DATATYPE_OF_NULL;
        func->size = GS_SIZE_OF_NULL;
    }

    return GS_SUCCESS;
}

status_t sql_func_coalesce(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    expr_tree_t *arg = NULL;

    CM_POINTER3(stmt, func, result);
    for (arg = func->argument; arg; arg = arg->next) {
        GS_RETURN_IFERR(sql_exec_expr(stmt, arg, result));
        SQL_CHECK_COLUMN_VAR(result, result);
        if (!result->is_null) {
            return GS_SUCCESS;
        }
    }
    SQL_SET_NULL_VAR(result);
    return GS_SUCCESS;
}

status_t sql_generate_guid_info(char *mac_address, uint16 mac_address_len, uint32 *self_increase_seq, uint32 thread_id)
{
    MEMS_RETURN_IFERR(memcpy_s(mac_address, mac_address_len, g_instance->g_uuid_info.mac_address, GS_MAC_ADDRESS_LEN));

    cm_spin_lock(&(g_instance->g_uuid_info.lock), NULL);
    if (++g_instance->g_uuid_info.self_increase_seq >= (uint32)0x000FFFFF) {
        g_instance->g_uuid_info.self_increase_seq = cm_hash_uint32_shard(thread_id);
        g_instance->g_uuid_info.self_increase_seq = g_instance->g_uuid_info.self_increase_seq & 0x000FFFFF;
    }
    *self_increase_seq = g_instance->g_uuid_info.self_increase_seq;
    cm_spin_unlock(&(g_instance->g_uuid_info.lock));

    return GS_SUCCESS;
}

static status_t sql_uuid_create(uuid_t *uuid, const char *mac_address, uint16 mac_address_len,
    const uint32 uuid_increase, const uint32 thread_id)
{
    uint64 time;

    time = (uint64)(cm_now() / MICROSECS_PER_MILLISEC);

    uuid->Data1 = (uint32)(time >> 12);
    uuid->Data2 = (uint16)(((time & 0x0fff) << 4) | ((uuid_increase >> 16) & 0x0f));
    uuid->Data3 = (uint16)(uuid_increase & 0xffff);

    uuid->Data4[0] = (uchar)((thread_id >> 8) & 0xff);
    uuid->Data4[1] = (uchar)(thread_id & 0xff);

    MEMS_RETURN_IFERR(memcpy_s((char *)(uuid->Data4 + 2), GS_MAC_ADDRESS_LEN, mac_address, mac_address_len));

    if (!IS_BIG_ENDIAN) {
        uuid->Data1 = cs_reverse_int32(uuid->Data1);
        uuid->Data2 = cs_reverse_int16(uuid->Data2);
        uuid->Data3 = cs_reverse_int16(uuid->Data3);
    }

    return GS_SUCCESS;
}

status_t sql_func_sys_guid(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    uuid_t uuid;
    char uuid_value[CM_GUID_LENGTH + 1] = { 0 };
    uint32 thread_id = cm_get_current_thread_id();
    uint32 self_increase_seq = 0;
    char mac_address[GS_MAC_ADDRESS_LEN] = { 0 };
    CM_POINTER3(stmt, func, result);

    GS_RETURN_IFERR(sql_generate_guid_info(mac_address, GS_MAC_ADDRESS_LEN, &self_increase_seq, thread_id));
    GS_RETURN_IFERR(sql_uuid_create(&uuid, mac_address, GS_MAC_ADDRESS_LEN, self_increase_seq, thread_id));

    // copy the last 6 bytes MAC addr from uuid.Data4
    MEMS_RETURN_IFERR(memcpy_s((char *)uuid_value, CM_GUID_LENGTH + 1, (char *)(uuid.Data4 + 2), GS_MAC_ADDRESS_LEN));
    // copy the head 2 bytes ThreadID from uuid.Data4
    MEMS_RETURN_IFERR(memcpy_s((char *)uuid_value + 6, CM_GUID_LENGTH + 1 - GS_MAC_ADDRESS_LEN, (char *)uuid.Data4,
        CM_THREAD_ID_LENGTH));
    // copy the last 8 bytes from uuid struct
    MEMS_RETURN_IFERR(memcpy_s((char *)uuid_value + 8, CM_GUID_LENGTH + 1 - GS_MAC_ADDRESS_LEN - CM_THREAD_ID_LENGTH,
        (char *)&uuid.Data1, CM_GUID_LAST_LENGTH));

    result->type = func->datatype;
    result->is_null = GS_FALSE;
    GS_RETURN_IFERR(sql_push(stmt, CM_GUID_LENGTH, (void **)&result->v_bin.bytes));
    MEMS_RETURN_IFERR(memcpy_s(result->v_bin.bytes, CM_GUID_LENGTH, (uint8 *)uuid_value, CM_GUID_LENGTH));
    result->v_bin.size = CM_GUID_LENGTH;

    return GS_SUCCESS;
}


status_t sql_verify_sys_guid(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (func->argument != NULL) {
        GS_SRC_THROW_ERROR(func->loc, ERR_INVALID_FUNC_PARAM_COUNT, T2S(&func->word.func.name), 0, 0);
        return GS_ERROR;
    }
    func->datatype = GS_TYPE_RAW;
    func->size = CM_GUID_LENGTH;

    return GS_SUCCESS;
}

static bool32 sql_func_object_id_get_dynview_id(text_t *dynview_name, uint32 *dynview_id)
{
    int32 i;
    bool32 retval = GS_FALSE;
    knl_dynview_t view;
    dynview_desc_t *view_desc = NULL;

    for (i = 0; i <= DYN_VIEW_SELF; i++) {
        view = g_dynamic_views[i];
        view_desc = view.describe(view.id);
        if (view_desc != NULL) {
            if (!cm_compare_text_str_ins(dynview_name, view_desc->name)) {
                *dynview_id = view.id;
                retval = GS_TRUE;
                break;
            }
        }
    }

    return retval;
}

static status_t sql_func_object_id_core_table_like(sql_stmt_t *stmt, text_t *obj_name, funcoi_object_type_t obj_type,
    text_t *obj_owner, variant_t *result)
{
    knl_dictionary_t dc;
    uint32 objid = 0;
    bool32 obj_exist = GS_FALSE;

    GS_RETURN_IFERR(knl_open_dc_if_exists(KNL_SESSION(stmt), obj_owner, obj_name, &dc, &obj_exist));
    if (!obj_exist) {
        result->is_null = GS_TRUE;
        return GS_SUCCESS;
    }

    switch (obj_type) {
        case FUNC_OBJ_ID_TABLE:
            if (dc.type != DICT_TYPE_TABLE && dc.type != DICT_TYPE_TABLE_NOLOGGING) {
                obj_exist = GS_FALSE;
            } else {
                objid = dc.oid;
            }
            break;
        case FUNC_OBJ_ID_VIEW:
            if (dc.type != DICT_TYPE_VIEW) {
                obj_exist = GS_FALSE;
            } else {
                objid = dc.oid;
            }
            break;
        case FUNC_OBJ_ID_DYNVIEW:
            if (dc.type != DICT_TYPE_DYNAMIC_VIEW) {
                obj_exist = GS_FALSE;
            } else {
                bool32 dynview_found = GS_FALSE;
                /*
                 * the dc.oid IS NOT the id displayed in the DV_DYNAMIC_VIEW,
                 * however, the object_id retrieved from USER_OBJECTS is actually the id in DV_DYNAMIC_VIEW
                 * so we have to get the "id" by searching the g_dynamic_views array.
                 */
                dynview_found = sql_func_object_id_get_dynview_id(obj_name, &objid);
                if (!dynview_found) {
                    /* it is wired that we can find the dynamic view by knl_dictionary_t
                     * but we cannot find it in the g_dynamic_views.
                     * under this circumstance we have to report an error
                     * which means an code-level bug did exist */
                    knl_close_dc(&dc);
                    GS_THROW_ERROR(ERR_VALUE_ERROR, "Schrodinger's dynamic view");
                    return GS_ERROR;
                }
            }
            break;
        default:
            knl_close_dc(&dc);
            GS_THROW_ERROR(ERR_NOT_SUPPORT_TYPE, (int32)obj_type);
            return GS_ERROR;
    }

    /* check the flag of obj_exist again because it might be changed */
    if (!obj_exist) {
        result->is_null = GS_TRUE;
        knl_close_dc(&dc);
        return GS_SUCCESS;
    }

    if (result->type != GS_TYPE_BIGINT) {
        knl_close_dc(&dc);
        GS_THROW_ERROR_EX(ERR_ASSERT_ERROR, "result->type(%u) == GS_TYPE_BIGINT(%u)", (uint32)result->type,
            (uint32)GS_TYPE_BIGINT);
        return GS_ERROR;
    }
    result->is_null = GS_FALSE;
    result->v_bigint = (int64)objid;
    knl_close_dc(&dc);
    return GS_SUCCESS;
}

static status_t sql_func_object_id_core_proc_like(sql_stmt_t *stmt, text_t *obj_name, funcoi_object_type_t obj_type,
    text_t *obj_owner, variant_t *result)
{
    knl_cursor_t *cursor = NULL;
    uint32 owner_id = 0;
    uint32 proc_class;
    int64 obj_id = 0;
    uchar actual_type;

    if (result->type != GS_TYPE_BIGINT) {
        GS_THROW_ERROR_EX(ERR_ASSERT_ERROR, "result->type(%u) == GS_TYPE_BIGINT(%u)", (uint32)result->type,
            (uint32)GS_TYPE_BIGINT);
        return GS_ERROR;
    }
    if (!knl_get_user_id(KNL_SESSION(stmt), obj_owner, &owner_id)) {
        GS_THROW_ERROR(ERR_USER_NOT_EXIST, T2S(obj_owner));
        return GS_ERROR;
    }
    proc_class = (obj_type == FUNC_OBJ_ID_TRIGGER) ? 2 : 1; /* ref: plm_create_and_lock() */

    SQL_SAVE_STACK(stmt);
    if (sql_push_knl_cursor(&stmt->session->knl_session, &cursor) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_STACK_OVERFLOW);
        SQL_RESTORE_STACK(stmt);
        return GS_ERROR;
    }

    knl_open_sys_cursor(&stmt->session->knl_session, cursor, CURSOR_ACTION_SELECT, SYS_PROC_ID, 0);

    /* PROC_IX_001 is an unique index */
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_STRING, obj_name->str, obj_name->len,
        0);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &owner_id, sizeof(uint32),
        1);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &proc_class, sizeof(uint32),
        2);

    if (knl_fetch(stmt->session, cursor) != GS_SUCCESS) {
        SQL_RESTORE_STACK(stmt);
        return GS_ERROR;
    }

    if (cursor->eof) {
        /* no such record */
        result->is_null = GS_TRUE;
    } else {
        bool32 type_match = GS_FALSE;

        obj_id = *(int64 *)CURSOR_COLUMN_DATA(cursor, 1);      /* column "OBJ#" */
        actual_type = *(uchar *)CURSOR_COLUMN_DATA(cursor, 4); /* column "TYPE" */

        /* recheck the type according to the column "TYPE" to decide if to return the found id */
        switch (obj_type) {
            case FUNC_OBJ_ID_PROCEDURE:
                type_match = (actual_type == 'P') ? GS_TRUE : GS_FALSE;
                break;
            case FUNC_OBJ_ID_FUNCTION:
                type_match = (actual_type == 'F') ? GS_TRUE : GS_FALSE;
                break;
            case FUNC_OBJ_ID_TRIGGER:
                type_match = (actual_type == 'T') ? GS_TRUE : GS_FALSE;
                break;
            default:
                break;
        }

        if (type_match) {
            result->is_null = GS_FALSE;
            result->v_bigint = obj_id;
        } else {
            result->is_null = GS_TRUE;
        }
    }

    SQL_RESTORE_STACK(stmt);
    return GS_SUCCESS;
}

static status_t sql_func_object_id_core(sql_stmt_t *stmt, text_t *obj_name, funcoi_object_type_t obj_type,
    text_t *obj_owner, variant_t *result)
{
    switch (obj_type) {
        case FUNC_OBJ_ID_TABLE:
        case FUNC_OBJ_ID_VIEW:
        case FUNC_OBJ_ID_DYNVIEW:
            return sql_func_object_id_core_table_like(stmt, obj_name, obj_type, obj_owner, result);
        case FUNC_OBJ_ID_PROCEDURE:
        case FUNC_OBJ_ID_FUNCTION:
        case FUNC_OBJ_ID_TRIGGER:
            return sql_func_object_id_core_proc_like(stmt, obj_name, obj_type, obj_owner, result);
        default:
            GS_THROW_ERROR(ERR_NOT_SUPPORT_TYPE, (int32)obj_type);
            return GS_ERROR;
    }
}

static status_t sql_func_oid_get_argname(sql_stmt_t *stmt, expr_tree_t *arg, variant_t *arg_var)
{
    SQL_EXEC_FUNC_ARG_EX(arg, arg_var, arg_var);

    if (!GS_IS_STRING_TYPE(arg_var->type)) {
        GS_SRC_ERROR_REQUIRE_STRING(arg->loc, arg_var->type);
        return GS_ERROR;
    }
    if (arg_var->v_text.len > GS_MAX_NAME_LEN) {
        GS_SRC_THROW_ERROR_EX(arg->loc, ERR_SQL_SYNTAX_ERROR, "input object name is too long, object is %s",
            T2S(&arg_var->v_text));
        return GS_ERROR;
    }
    if (IS_CASE_INSENSITIVE) {
        (void)cm_text_upper(&arg_var->v_text);
    }

    sql_keep_stack_variant(stmt, arg_var);

    return GS_SUCCESS;
}

static status_t sql_func_oid_get_argtype(sql_stmt_t *stmt, expr_tree_t *arg, variant_t *arg_var)
{
    arg_var->type = GS_TYPE_INTEGER;
    arg_var->is_null = GS_FALSE;
    if (arg == NULL) {
        arg_var->v_int = (int32)FUNC_OBJ_ID_TABLE;
    } else {
        variant_t tmp;
        text_t *type_name = NULL;
        int32 i;
        funcoi_support_type_t *target_type = NULL;

        GS_RETURN_IFERR(sql_exec_expr(stmt, arg, &tmp));
        if (!GS_IS_STRING_TYPE(tmp.type)) {
            GS_SRC_ERROR_REQUIRE_STRING(arg->loc, tmp.type);
            return GS_ERROR;
        }
        if ((tmp.is_null == GS_TRUE) || (tmp.v_text.len == 0)) {
            GS_SRC_THROW_ERROR(arg->loc, ERR_INVALID_FUNC_PARAMS, "object owner cannot be a NULL nor an empty string");
            return GS_ERROR;
        }

        type_name = &tmp.v_text;
        for (i = 0; i < (int32)FUNC_OBJ_ID_TYPE_COUNT; i++) {
            if (cm_compare_text_str_ins(type_name, g_objtype_support_range[i].typename) == 0) {
                target_type = &g_objtype_support_range[i];
                break;
            }
        }

        if (target_type == NULL) {
            GS_SRC_THROW_ERROR_EX(arg->loc, ERR_INVALID_FUNC_PARAMS, "unrecognised object type \"%s\".",
                T2S(type_name));
            return GS_ERROR;
        }

        arg_var->v_int = (int32)target_type->typeid;
    }

    return GS_SUCCESS;
}

static status_t sql_func_oid_get_argowner(sql_stmt_t *stmt, expr_tree_t *arg, variant_t *arg_var)
{
    uint32 owner_id = 0;
    arg_var->type = GS_TYPE_STRING;
    arg_var->is_null = GS_FALSE;

    if (arg == NULL) {
        /* if argument "owner" not specified, use the current user as target owner */
        text_t *curr_user = &arg_var->v_text;
        curr_user->len = (uint32)strlen(stmt->session->db_user);
        GS_RETURN_IFERR(sql_push(stmt, curr_user->len, (void **)&curr_user->str));
        if (curr_user->len != 0) {
            MEMS_RETURN_IFERR(memcpy_s(curr_user->str, curr_user->len, stmt->session->db_user, curr_user->len));
        }
        sql_keep_stack_variant(stmt, arg_var);
    } else {
        variant_t tmp;

        GS_RETURN_IFERR(sql_exec_expr(stmt, arg, &tmp));
        if (!GS_IS_STRING_TYPE(tmp.type)) {
            GS_SRC_ERROR_REQUIRE_STRING(arg->loc, tmp.type);
            return GS_ERROR;
        }

        if ((tmp.is_null == GS_TRUE) || (tmp.v_text.len == 0)) {
            GS_SRC_THROW_ERROR(arg->loc, ERR_INVALID_FUNC_PARAMS, "object owner cannot be a NULL nor an empty string");
            return GS_ERROR;
        }

        (void)cm_text_upper(&tmp.v_text);
        /* check if the specified user existed */
        if (!knl_get_user_id(KNL_SESSION(stmt), &tmp.v_text, &owner_id)) {
            /*
             * if the user does not exist, set the arg_var as NULL, and let the object_id return NULL directly
             * the reason why we dare to use NULL here is that the manually inputed NULL would be guarded
             * by the code above
             */
            arg_var->is_null = GS_TRUE;
        } else {
            arg_var->v_text = tmp.v_text;
            sql_keep_stack_variant(stmt, arg_var);
        }
    }

    return GS_SUCCESS;
}

#define FUNC_OBJECT_ID_ARGSNUM 3

status_t sql_func_object_id(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    int32 i;
    expr_tree_t *arg = func->argument;
    variant_t arg_var[FUNC_OBJECT_ID_ARGSNUM];
    sql_func_arg_processor processor[FUNC_OBJECT_ID_ARGSNUM] = {
        sql_func_oid_get_argname,
        sql_func_oid_get_argtype,
        sql_func_oid_get_argowner,
    };

    /* calculate the arguments */
    for (i = 0; i < FUNC_OBJECT_ID_ARGSNUM; i++) {
        GS_RETURN_IFERR(processor[i](stmt, ((arg != NULL) ? arg : NULL), &(arg_var[i])));
        SQL_CHECK_COLUMN_VAR(&(arg_var[i]), result);
        if (arg != NULL) {
            arg = arg->next;
        }
    }

    result->type = func->datatype;

    /*
     * if the object name is NULL or empty string, or the user name specified does not exist,
     * return NULL directly
     */
    if ((arg_var[0].is_null == GS_TRUE) || (arg_var[0].v_text.len == 0) || (arg_var[2].is_null == GS_TRUE)) {
        result->is_null = GS_TRUE;
        return GS_SUCCESS;
    }

    GS_RETURN_IFERR(sql_func_object_id_core(stmt, &arg_var[0].v_text, (funcoi_object_type_t)arg_var[1].v_int,
        &arg_var[2].v_text, result));

    return GS_SUCCESS;
}
#undef FUNC_OBJECT_ID_ARGSNUM

status_t sql_verify_object_id(sql_verifier_t *verf, expr_node_t *func)
{
    expr_tree_t *arg = NULL;

    CM_POINTER2(verf, func);

    GS_RETURN_IFERR(sql_verify_func_node(verf, func, 1, 3, GS_INVALID_ID32));

    /* make sure the 2nd and the 3rd argument(if any) being const or binding parameter */
    arg = func->argument->next;
    while (arg != NULL) {
        if (sql_is_single_const_or_param(arg->root) != GS_TRUE) {
            GS_SRC_THROW_ERROR_EX(arg->loc, ERR_SQL_SYNTAX_ERROR,
                "the 2nd and the 3rd argument of \"%s\" must be a const or a binding paramter",
                T2S(&func->word.func.name));
            return GS_ERROR;
        }
        arg = arg->next;
    }

    func->datatype = GS_TYPE_BIGINT;
    func->size = sizeof(int64);
    return GS_SUCCESS;
}


status_t sql_func_sha1(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t plain_text;
    binary_t plain_bin;
    uchar hash_val[GS_MAX_SHA1_BINLEN] = { 0x00 };

    CM_POINTER3(stmt, func, result);

    result->type = GS_TYPE_STRING;

    GS_RETURN_IFERR(sql_exec_expr(stmt, func->argument, &plain_text));
    SQL_CHECK_COLUMN_VAR(&plain_text, result);
    if (plain_text.is_null) {
        result->is_null = GS_TRUE;
        return GS_SUCCESS;
    }

    /* generate sha1 from plain text */
    if (!GS_IS_STRING_TYPE(plain_text.type)) {
        GS_RETURN_IFERR(sql_convert_variant(stmt, &plain_text, GS_TYPE_STRING));
    }

    plain_bin.bytes = hash_val;
    plain_bin.size = GS_MAX_SHA1_BINLEN;

    if (cm_generate_sha1(plain_text.v_text.str, plain_text.v_text.len, plain_bin.bytes, &plain_bin.size) !=
        GS_SUCCESS) {
        GS_THROW_ERROR(ERR_GENERATE_SHA1, T2S(&(plain_text.v_text)));
        return GS_ERROR;
    }

    /* a bytes array retrieved from cm_generate_sha1(), so we have to convert it */
    if (plain_bin.size != GS_MAX_SHA1_BINLEN) {
        GS_THROW_ERROR_EX(ERR_ASSERT_ERROR, "hash_len(%u) == GS_MAX_SHA1_BINLEN(%u)", plain_bin.size,
            (uint32)GS_MAX_SHA1_BINLEN);
        return GS_ERROR;
    }

    /* convert sha1 format from binary to string */
    result->v_text.len = GS_MAX_SHA1_BINLEN * 2;
    GS_RETURN_IFERR(sql_push(stmt, result->v_text.len, (void **)&result->v_text.str));
    GS_RETURN_IFERR(cm_bin2text(&plain_bin, GS_FALSE, &result->v_text));

    return GS_SUCCESS;
}

status_t sql_verify_sha1(sql_verifier_t *verifier, expr_node_t *func)
{
    CM_POINTER2(verifier, func);

    if (GS_SUCCESS != sql_verify_func_node(verifier, func, 1, 1, GS_INVALID_ID32)) {
        return GS_ERROR;
    }

    func->datatype = GS_TYPE_STRING;
    func->size = GS_MAX_SHA1_BINLEN * 2;

    return GS_SUCCESS;
}

void sql_func_soundex_core_deal(uint32 i, uint32 *j, const char *src, char *output, int32 flag)
{
    uint32 array[26] = { 0, 1, 2, 3, 0, 1, 2, 0, 0, 2, 2, 4, 5, 5, 0, 1, 2, 6, 2, 3, 0, 1, 0, 2, 0, 2 };
    char temp = '0';
    if (*j == 0) {
        output[(*j)++] = src[i] - 32 * flag;
        return;
    }
    // if continuous appearing the same as the first letter, should be ignored. eg:'bbbc'-->B200
    if (output[0] == src[i] - 32 * flag) {
        return;
    }

    if (*j > 3) {
        return;
    }

    if (flag == 1) {
        temp = (char)(array[src[i] - 'a'] + '0');
    }

    if (flag == 0) {
        temp = (char)(array[src[i] - 'A'] + '0');
    }

    if (*j == 1) {
        if (temp != '0') {
            output[(*j)++] = temp;
        }
        return;
    }
    if (*j == 2) {
        if ((temp != '0') && (temp != output[1])) {
            output[(*j)++] = temp;
        }
        return;
    }
    if (*j == 3) {
        if ((temp != '0') && (temp != output[2])) {
            output[(*j)++] = temp;
            return;
        }
    }
    return;
}

void sql_func_soundex_core(const char *input, uint32 len, char *output)
{
    uint32 i = 0;
    uint32 j = 0;
    int32 flag = -1;

    for (i = 0; i < len; i++) {
        if (input[i] >= 'a' && input[i] <= 'z') { // character is small letter
            flag = 1;
            sql_func_soundex_core_deal(i, &j, input, output, flag);
        } else if (input[i] >= 'A' && input[i] <= 'Z') { // character is big letter
            flag = 0;
            sql_func_soundex_core_deal(i, &j, input, output, flag);
        } else {
            continue;
        }
    }

    return;
}

status_t sql_func_soundex(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t arg_var;
    char *buf = NULL;

    CM_POINTER3(stmt, func, result);

    expr_tree_t *arg_node = func->argument;
    CM_POINTER(arg_node);

    SQL_EXEC_FUNC_ARG_EX(arg_node, &arg_var, result);

    sql_keep_stack_variant(stmt, &arg_var);

    if (!GS_IS_STRING_TYPE(arg_var.type)) {
        GS_RETURN_IFERR(sql_var_as_string(stmt, &arg_var));
    }

    GS_RETURN_IFERR(sql_push(stmt, GS_CONST_FOUR, (void **)&buf));
    result->v_text.str = (char *)buf;
    MEMS_RETURN_IFERR(memcpy_s(result->v_text.str, GS_CONST_FOUR, "0000", GS_CONST_FOUR));
    result->v_text.len = GS_CONST_FOUR;
    sql_func_soundex_core(arg_var.v_text.str, arg_var.v_text.len, result->v_text.str);

    result->type = func->datatype;
    result->is_null = (result->v_text.str[0] == '0');
    return GS_SUCCESS;
}

status_t sql_verify_soundex(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    GS_RETURN_IFERR(sql_verify_func_node(verf, func, 1, 1, GS_INVALID_ID32));

    func->datatype = GS_TYPE_VARCHAR;
    func->size = GS_VARCHAR_SIZE;

    return GS_SUCCESS;
}

status_t sql_func_vsize(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t arg_var;

    CM_POINTER2(func, result);
    CM_POINTER(func->argument);

    /* if argument is null, result will be returned as null */
    SQL_EXEC_LENGTH_FUNC_ARG(func->argument, &arg_var, result, stmt);

    result->type = GS_TYPE_BIGINT;
    result->v_bigint = (int64)var_get_size(&arg_var);
    return GS_SUCCESS;
}

status_t sql_verify_vsize(sql_verifier_t *verifier, expr_node_t *func)
{
    CM_POINTER2(verifier, func);

    GS_RETURN_IFERR(sql_verify_func_node(verifier, func, 1, 1, GS_INVALID_ID32));

    func->datatype = GS_TYPE_BIGINT;
    func->size = GS_BIGINT_SIZE;
    return GS_SUCCESS;
}

status_t sql_verify_last_insert_id(sql_verifier_t *verifier, expr_node_t *func)
{
    CM_POINTER2(verifier, func);

    GS_RETURN_IFERR(sql_verify_func_node(verifier, func, 0, 1, GS_INVALID_ID32));

    func->datatype = GS_TYPE_BIGINT;
    func->size = GS_BIGINT_SIZE;
    return GS_SUCCESS;
}

status_t sql_func_last_insert_id(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    CM_POINTER3(stmt, func, result);

    expr_tree_t *arg = func->argument;
    if (arg != NULL) {
        SQL_EXEC_FUNC_ARG_EX(arg, result, result);

        GS_RETURN_IFERR(var_as_bigint(result));

        result->is_null = GS_FALSE;
        result->type = GS_TYPE_BIGINT;
        stmt->session->last_insert_id = result->v_bigint;
    } else {
        result->is_null = GS_FALSE;
        result->type = GS_TYPE_BIGINT;
        result->v_bigint = stmt->session->last_insert_id;
    }

    return GS_SUCCESS;
}

status_t sql_func_is_numeric(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t value;
    num_part_t np;
    np.excl_flag = NF_NONE;

    expr_tree_t *arg = func->argument;
    SQL_EXEC_FUNC_ARG(arg, &value, result, stmt);
    do {
        if (value.is_null) {
            result->v_int = 0;
            break;
        }
        if (GS_IS_NUMERIC_TYPE((&value)->type)) {
            result->v_int = 1;
            break;
        }
        // numeric or string value is allowed
        if ((GS_IS_STRING_TYPE((&value)->type) || GS_IS_BINARY_TYPE((&value)->type)) &&
            cm_split_num_text(&value.v_text, &np) == NERR_SUCCESS) {
            result->v_int = 1;
        } else {
            result->v_int = 0;
        }
    } while (0);
    result->is_null = GS_FALSE;
    result->type = GS_TYPE_INTEGER;
    return GS_SUCCESS;
}

status_t sql_verify_is_numeric(sql_verifier_t *verifier, expr_node_t *func)
{
    GS_RETURN_IFERR(sql_verify_func_node(verifier, func, 1, 1, GS_INVALID_ID32));
    func->datatype = GS_TYPE_INTEGER;
    func->size = GS_INTEGER_SIZE;
    return GS_SUCCESS;
}

status_t sql_verify_alck_name(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);
    GS_RETURN_IFERR(sql_verify_func_node(verf, func, 1, 1, GS_INVALID_ID32));
    GS_RETURN_IFERR(alck_check_db_status(KNL_SESSION(verf->stmt)));
    func->datatype = GS_TYPE_INTEGER;
    func->size = GS_INTEGER_SIZE;
    return GS_SUCCESS;
}

status_t sql_verify_alck_nm_and_to(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 1, 2, GS_INVALID_ID32) != GS_SUCCESS) {
        return GS_ERROR;
    }
    GS_RETURN_IFERR(alck_check_db_status(KNL_SESSION(verf->stmt)));
    func->datatype = GS_TYPE_INTEGER;
    func->size = GS_INTEGER_SIZE;

    return GS_SUCCESS;
}

static status_t sql_func_alck_get_name(sql_stmt_t *stmt, expr_tree_t *arg, variant_t *name)
{
    CM_POINTER3(stmt, arg, name);

    GS_RETURN_IFERR(sql_exec_expr(stmt, arg, name));
    sql_keep_stack_variant(stmt, name);
    if (name->is_null) {
        GS_SRC_THROW_ERROR(arg->loc, ERR_INVALID_FUNC_PARAMS, "Incorrect user-level lock name NULL");
        return GS_ERROR;
    }
    GS_RETSUC_IFTRUE(name->type == GS_TYPE_COLUMN);
    if (!GS_IS_STRING_TYPE(name->type)) {
        GS_RETURN_IFERR(sql_convert_variant(stmt, name, GS_TYPE_STRING));
    }
    if (name->v_text.len > GS_MAX_ALCK_USER_NAME_LEN) {
        GS_SRC_THROW_ERROR_EX(arg->loc, ERR_INVALID_FUNC_PARAMS, "user-level lock name cannot exceed %d bytes",
            (int32)GS_MAX_ALCK_USER_NAME_LEN);
        return GS_ERROR;
    }
    sql_keep_stack_variant(stmt, name);
    if (!IS_CASE_INSENSITIVE) {
        cm_text_upper(&name->v_text);
    }
    return GS_SUCCESS;
}

static status_t sql_func_alck_get_timeout(sql_stmt_t *stmt, expr_tree_t *arg, variant_t *timeout)
{
    variant_t tmp;
    CM_POINTER3(stmt, arg, timeout);

    GS_RETURN_IFERR(sql_exec_expr(stmt, arg, &tmp));
    SQL_CHECK_COLUMN_VAR(&tmp, timeout);
    sql_keep_stack_variant(stmt, &tmp);
    if (tmp.is_null) {
        GS_SRC_THROW_ERROR(arg->loc, ERR_INVALID_FUNC_PARAMS, "Incorrect user-level timeout NULL");
        return GS_ERROR;
    }

    if (!GS_IS_INTEGER_TYPE(tmp.type)) {
        GS_RETURN_IFERR(sql_convert_variant(stmt, &tmp, GS_TYPE_INTEGER));
    }

    *timeout = tmp;
    if (timeout->v_int < 0) {
        timeout->v_int = 0; /* it means no timeout */
    }
    return GS_SUCCESS;
}

status_t sql_func_get_lock(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t name, timeout;
    ADVLCK_INIT_WITH_NAME_TIMEOUT(func, timeout, result);
    bool32 locked = GS_FALSE;
    GS_RETURN_IFERR(knl_alck_se_lock_ex(stmt->session, &name.v_text, (uint32)timeout.v_int, &locked));
    result->v_int = (int32)locked;
    return GS_SUCCESS;
}

status_t sql_func_try_get_lock(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t name;
    ADVLCK_INIT_WITH_NAME(result, func);
    bool32 locked = GS_FALSE;
    GS_RETURN_IFERR(knl_alck_se_try_lock_ex(stmt->session, &name.v_text, &locked));
    result->v_int = (int32)locked;
    return GS_SUCCESS;
}

status_t sql_func_release_lock(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t name;
    ADVLCK_INIT_WITH_NAME(result, func);
    bool32 unlocked = GS_FALSE;
    GS_RETURN_IFERR(knl_alck_se_unlock_ex(stmt->session, &name.v_text, &unlocked));
    result->v_int = (int32)unlocked;
    result->is_null = !result->v_int;
    return GS_SUCCESS;
}

status_t sql_func_get_shared_lock(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t name, timeout;
    ADVLCK_INIT_WITH_NAME_TIMEOUT(func, timeout, result);
    bool32 locked = GS_FALSE;
    GS_RETURN_IFERR(knl_alck_se_lock_sh(stmt->session, &name.v_text, (uint32)timeout.v_int, &locked));
    result->v_int = (int32)locked;
    return GS_SUCCESS;
}

status_t sql_func_try_get_shared_lock(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t name;
    ADVLCK_INIT_WITH_NAME(result, func);
    bool32 locked = GS_FALSE;
    GS_RETURN_IFERR(knl_alck_se_try_lock_sh(stmt->session, &name.v_text, &locked));
    result->v_int = (int32)locked;
    return GS_SUCCESS;
}

status_t sql_func_release_shared_lock(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t name;
    ADVLCK_INIT_WITH_NAME(result, func);
    bool32 unlocked = GS_FALSE;
    GS_RETURN_IFERR(knl_alck_se_unlock_sh(stmt->session, &name.v_text, &unlocked));
    result->v_int = (int32)unlocked;
    result->is_null = !result->v_int;
    return GS_SUCCESS;
}

status_t sql_func_get_xact_lock(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t name, timeout;
    ADVLCK_INIT_WITH_NAME_TIMEOUT(func, timeout, result);
    bool32 locked = GS_FALSE;
    GS_RETURN_IFERR(knl_alck_tx_lock_ex(stmt->session, &name.v_text, (uint32)timeout.v_int, &locked));
    result->v_int = (int32)locked;
    return GS_SUCCESS;
}

status_t sql_func_try_get_xact_lock(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t name;
    ADVLCK_INIT_WITH_NAME(result, func);
    bool32 locked = GS_FALSE;
    GS_RETURN_IFERR(knl_alck_tx_try_lock_ex(stmt->session, &name.v_text, &locked));
    result->v_int = (int32)locked;
    return GS_SUCCESS;
}

status_t sql_func_get_xact_shared_lock(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t name, timeout;
    ADVLCK_INIT_WITH_NAME_TIMEOUT(func, timeout, result);
    bool32 locked = GS_FALSE;
    GS_RETURN_IFERR(knl_alck_tx_lock_sh(stmt->session, &name.v_text, (uint32)timeout.v_int, &locked));
    result->v_int = (int32)locked;
    return GS_SUCCESS;
}

status_t sql_func_try_get_xact_shared_lock(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t name;
    ADVLCK_INIT_WITH_NAME(result, func);
    bool32 locked = GS_FALSE;
    GS_RETURN_IFERR(knl_alck_tx_try_lock_sh(stmt->session, &name.v_text, &locked));
    result->v_int = (int32)locked;
    return GS_SUCCESS;
}

status_t sql_func_array_length(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    char *buf = NULL;
    uint32 dimension = 0;
    bool32 last = GS_FALSE;
    text_t array_str, element_str;
    variant_t value;
    expr_tree_t *arg = func->argument;

    SQL_EXEC_FUNC_ARG(arg, &value, result, stmt);
    if (value.type == GS_TYPE_ARRAY) {
        return GS_ERROR;
    } else if (!GS_IS_ARRAY_TYPE(value.type)) {
        GS_THROW_ERROR(ERR_TYPE_MISMATCH, "ARRAY", get_datatype_name_str(arg->root->datatype));
    }

    array_str = value.v_text;
    if (value.is_null || array_str_invalid(&array_str)) {
        GS_THROW_ERROR(ERR_INVALID_ARRAY_FORMAT);
        return GS_ERROR;
    }

    if (array_str_null(&array_str)) {
        result->is_null = GS_FALSE;
        result->type = GS_TYPE_UINT32;
        result->v_uint32 = 0;
        return GS_SUCCESS;
    }

    sql_keep_stack_variant(stmt, &value);
    GS_RETURN_IFERR(sql_push(stmt, array_str.len, (void **)&buf));

    element_str.str = buf;
    element_str.len = 0;
    while (!last) {
        if (array_get_element_str(&array_str, &element_str, &last) != GS_SUCCESS) {
            SQL_POP(stmt);
            return GS_ERROR;
        }

        dimension++;
        element_str.str = buf;
        element_str.len = 0;
    }

    SQL_POP(stmt);
    result->v_uint32 = dimension;
    result->is_null = GS_FALSE;
    result->type = GS_TYPE_UINT32;
    return GS_SUCCESS;
}

status_t sql_verify_array_length(sql_verifier_t *verifier, expr_node_t *func)
{
    expr_tree_t *arg = NULL;

    GS_RETURN_IFERR(sql_verify_func_node(verifier, func, 1, 1, GS_INVALID_ID32));

    GS_RETURN_IFERR(sql_verify_expr(verifier, func->argument));

    verifier->incl_flags |= SQL_INCL_ARRAY;

    arg = func->argument;
    if (arg->root->typmod.is_array == GS_TRUE || GS_IS_ARRAY_TYPE(arg->root->datatype)) {
        func->datatype = GS_TYPE_UINT32;
        func->size = sizeof(uint32);
        return GS_SUCCESS;
    }

    GS_THROW_ERROR(ERR_TYPE_MISMATCH, "ARRAY", get_datatype_name_str(arg->root->datatype));
    return GS_ERROR;
}

status_t sql_verify_values(sql_verifier_t *verf, expr_node_t *func)
{
    expr_tree_t *arg = NULL;

    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 1, 1, GS_INVALID_ID32) != GS_SUCCESS) {
        return GS_ERROR;
    }

    arg = func->argument;
    if (arg->root->type != EXPR_NODE_COLUMN) {
        GS_SRC_THROW_ERROR(func->loc, ERR_SQL_SYNTAX_ERROR, "function VALUES argument invalid");
        return GS_ERROR;
    }

    if (arg->root->datatype == GS_TYPE_CLOB || arg->root->datatype == GS_TYPE_BLOB ||
        arg->root->datatype == GS_TYPE_IMAGE) {
        GS_SRC_THROW_ERROR(func->loc, ERR_SQL_SYNTAX_ERROR, "function VALUES argument not support LOB type");
        return GS_ERROR;
    }

    func->datatype = arg->root->datatype;
    func->size = arg->root->size;
    return GS_SUCCESS;
}

// The VALUES(col_name) function is meaningful only in INSERT ... UPDATE statements
// and returns NULL otherwise.
status_t sql_func_values(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    var_column_t *v_col = &func->argument->root->value.v_col;
    knl_cursor_t *knl_cur = SQL_CURR_CURSOR(stmt)->tables[v_col->tab].knl_cur;
    char *ptr = NULL;
    uint32 len;

    // knl_cursor_t::insert_info only set in INSERT ... UPDATE
    if (knl_cur->insert_info.data == NULL) {
        result->is_null = GS_TRUE;
        result->type = func->argument->root->datatype;
        return GS_SUCCESS;
    }

    // VALUES(col_name) referred to col_name value that would be inserted
    ptr = (char *)knl_cur->insert_info.data + knl_cur->insert_info.offsets[v_col->col];
    len = knl_cur->insert_info.lens[v_col->col];

    return sql_get_row_value(stmt, ptr, len, v_col, result, GS_FALSE);
}
