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
 * ddl_parser.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/parser_ddl/ddl_parser.c
 *
 * -------------------------------------------------------------------------
 */
#include "ddl_parser.h"
#include "cm_config.h"
#include "cm_hash.h"
#include "cm_file.h"
#include "dml_parser.h"
#include "ddl_user_parser.h"
#include "ddl_table_parser.h"
#include "ddl_database_parser.h"
#include "ddl_space_parser.h"
#include "ddl_index_parser.h"
#include "ddl_privilege_parser.h"
#include "ddl_column_parser.h"
#include "ddl_partition_parser.h"
#include "ddl_view_parser.h"
#include "ddl_parser_common.h"
#include "cm_license.h"
#include "ctsql_privilege.h"
#include "cm_defs.h"
#include "pl_ddl_parser.h"
#include "srv_param_common.h"
#ifdef Z_SHARDING
#include "shd_parser.h"
#include "shd_longsql.h"
#include "shd_ddl_executor.h"
#include "shd_transform.h"

#endif
#ifdef __cplusplus
extern "C" {
#endif

static status_t sql_create_or_replace_lead(sql_stmt_t *stmt)
{
    word_t word;
    status_t status;
    bool32 is_force = CT_FALSE;

    if (lex_expected_fetch_word(stmt->session->lex, "REPLACE") != CT_SUCCESS) {
        return CT_ERROR;
    }

    CT_RETURN_IFERR(lex_try_fetch(stmt->session->lex, "FORCE", &is_force));

    if (lex_fetch(stmt->session->lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    switch (word.id) {
        case KEY_WORD_VIEW: {
            status = sql_parse_create_view(stmt, CT_TRUE, is_force);
            break;
        }
        case KEY_WORD_PUBLIC: {
            if (lex_expected_fetch_word(stmt->session->lex, "SYNONYM") != CT_SUCCESS) {
                return CT_ERROR;
            }

            status = sql_parse_create_synonym(stmt, SYNONYM_IS_PUBLIC + SYNONYM_IS_REPLACE);
            break;
        }
        case KEY_WORD_PACKAGE:
        case KEY_WORD_FUNCTION:
        case KEY_WORD_PROCEDURE:
        case KEY_WORD_TYPE:
            status = pl_parse_create(stmt, CT_TRUE, &word);
            break;
        case KEY_WORD_TRIGGER:
            status = pl_parse_create_trigger(stmt, CT_TRUE, &word);
            break;
        case KEY_WORD_SYNONYM: {
            status = sql_parse_create_synonym(stmt, SYNONYM_IS_REPLACE);
            break;
        }

        case KEY_WORD_DIRECTORY: {
            status = sql_parse_create_directory(stmt, CT_TRUE);
            break;
        }

        case KEY_WORD_LIBRARY: {
            status = sql_parse_create_library(stmt, CT_TRUE);
            break;
        }

        case KEY_WORD_PROFILE: {
            status = sql_parse_create_profile(stmt, CT_TRUE);
            break;
        }

        default: {
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "VIEW or PUBLIC expected but %s found", W2S(&word));
            return CT_ERROR;
        }
    }

    return status;
}

static status_t sql_create_public_lead(sql_stmt_t *stmt)
{
    word_t word;
    status_t status;

    if (lex_fetch(stmt->session->lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    switch (word.id) {
        case KEY_WORD_SYNONYM: {
            status = sql_parse_create_synonym(stmt, SYNONYM_IS_PUBLIC);
            break;
        }

        default: {
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "SYNONYM expected but %s found", W2S(&word));
            return CT_ERROR;
        }
    }

    return status;
}

status_t sql_parse_create_directory(sql_stmt_t *stmt, bool32 is_replace)
{
    word_t word;
    status_t status;
    knl_directory_def_t *dir_def = NULL;
    lex_t *lex = stmt->session->lex;

#ifdef Z_SHARDING
    if (IS_COORDINATOR && IS_APP_CONN(stmt->session)) {
        CT_THROW_ERROR(ERR_COORD_NOT_SUPPORT, "Create directory");
        return CT_ERROR;
    }
#endif

    status = sql_alloc_mem(stmt->context, sizeof(knl_directory_def_t), (void **)&dir_def);
    CT_RETURN_IFERR(status);

    dir_def->is_replace = is_replace;
    status = lex_expected_fetch_variant(lex, &word);
    CT_RETURN_IFERR(status);

    status = sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, &dir_def->name);
    CT_RETURN_IFERR(status);

    status = lex_expected_fetch_word(lex, "as");
    CT_RETURN_IFERR(status);

    status = lex_expected_fetch_string(lex, &word);
    CT_RETURN_IFERR(status);

    status = sql_copy_text(stmt->context, (text_t *)&word.text, &dir_def->path);
    CT_RETURN_IFERR(status);

    if (lex_expected_end(stmt->session->lex) != CT_SUCCESS) {
        return CT_ERROR;
    }

    stmt->context->entry = (void *)dir_def;
    stmt->context->type = CTSQL_TYPE_CREATE_DIRECTORY;
    return CT_SUCCESS;
}

status_t sql_parse_create(sql_stmt_t *stmt)
{
    word_t word;
    status_t status;

    status = lex_fetch(stmt->session->lex, &word);
    CT_RETURN_IFERR(status);

    switch ((uint32)word.id) {
        case KEY_WORD_DATABASE:
            status = sql_create_database_lead(stmt);
            break;
        case RES_WORD_USER:
            status = sql_parse_create_user(stmt);
            CT_RETURN_IFERR(sql_clear_origin_sql_if_error(stmt, status));
            break;
        case KEY_WORD_ROLE:
            status = sql_parse_create_role(stmt);
            CT_RETURN_IFERR(sql_clear_origin_sql_if_error(stmt, status));
            break;
        case KEY_WORD_TENANT:
            status = sql_parse_create_tenant(stmt);
            break;
        case KEY_WORD_TABLE:
            status = sql_parse_create_table(stmt, CT_FALSE, CT_FALSE);
            break;
        case KEY_WORD_INDEX:
            status = sql_parse_create_index(stmt, CT_FALSE);
            break;
        case KEY_WORD_INDEXCLUSTER:
            status = sql_parse_create_indexes(stmt);
            break;
        case KEY_WORD_SEQUENCE:
            status = sql_parse_create_sequence(stmt);
            break;
        case KEY_WORD_TABLESPACE:
            status = sql_parse_create_space(stmt, CT_FALSE, CT_FALSE);
            break;
        case KEY_WORD_TEMPORARY:
            status = sql_create_temporary_lead(stmt);
            break;
        case KEY_WORD_GLOBAL:
            status = sql_create_global_lead(stmt);
            break;
        case KEY_WORD_UNIQUE:
            status = sql_parse_create_unique_lead(stmt);
            break;
        case KEY_WORD_UNDO:
            status = sql_parse_create_undo_space(stmt);
            break;
        case KEY_WORD_VIEW:
            status = sql_parse_create_view(stmt, CT_FALSE, CT_FALSE);
            break;

        case KEY_WORD_PROCEDURE:
        case KEY_WORD_FUNCTION:
        case KEY_WORD_PACKAGE:
        case KEY_WORD_TYPE:
            status = pl_parse_create(stmt, CT_FALSE, &word);
            break;
        case KEY_WORD_TRIGGER:
            status = pl_parse_create_trigger(stmt, CT_FALSE, &word);
            break;
        case KEY_WORD_OR:
            status = sql_create_or_replace_lead(stmt);
            break;
        case KEY_WORD_PUBLIC:
            status = sql_create_public_lead(stmt);
            break;
        case KEY_WORD_SYNONYM:
            status = sql_parse_create_synonym(stmt, SYNONYM_IS_NULL);
            break;
        case KEY_WORD_PROFILE:
            status = sql_parse_create_profile(stmt, CT_FALSE);
            break;
        case KEY_WORD_DIRECTORY:
            status = sql_parse_create_directory(stmt, CT_FALSE);
            break;
        case KEY_WORD_CTRLFILE:
            status = sql_parse_create_ctrlfiles(stmt);
            break;
        case KEY_WORD_LIBRARY:
            status = sql_parse_create_library(stmt, CT_FALSE);
            break;
        default:
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "object type expected but %s found", W2S(&word));
            status = CT_ERROR;
            break;
    }

    return status;
}

static status_t sql_parse_alter_trigger(sql_stmt_t *stmt)
{
    status_t status;
    word_t word;
    lex_t *lex = stmt->session->lex;
    knl_alttrig_def_t *alttrig_def = NULL;
    bool32 result = CT_FALSE;

    lex->flags |= LEX_WITH_OWNER;
    stmt->context->type = CTSQL_TYPE_ALTER_TRIGGER;

    status = sql_alloc_mem(stmt->context, sizeof(knl_alttrig_def_t), (void **)&alttrig_def);
    CT_RETURN_IFERR(status);

    stmt->context->entry = (void *)alttrig_def;

    status = lex_expected_fetch_variant(lex, &word);
    CT_RETURN_IFERR(status);

    status = sql_convert_object_name(stmt, &word, &alttrig_def->user, NULL, &alttrig_def->name);
    CT_RETURN_IFERR(status);

    status = lex_try_fetch(stmt->session->lex, "ENABLE", &result);
    CT_RETURN_IFERR(status);

    if (result) {
        alttrig_def->enable = CT_TRUE;
        return CT_SUCCESS;
    }

    status = lex_try_fetch(stmt->session->lex, "DISABLE", &result);
    CT_RETURN_IFERR(status);

    if (result) {
        alttrig_def->enable = CT_FALSE;
        return lex_expected_end(stmt->session->lex);
    }

    CT_SRC_THROW_ERROR_EX(lex->loc, ERR_SQL_SYNTAX_ERROR, "ENABLE or DISABLE expected");
    return CT_ERROR;
}


static status_t sql_parse_ddl_alter(sql_stmt_t *stmt)
{
    word_t word;
    status_t status;

    status = lex_fetch(stmt->session->lex, &word);
    CT_RETURN_IFERR(status);

    switch ((uint32)word.id) {
        case KEY_WORD_TABLE:
            status = sql_parse_alter_table(stmt);
            CT_BREAK_IF_ERROR(status);
            status = sql_verify_alter_table(stmt);
            break;

        case KEY_WORD_TABLESPACE:
            status = sql_parse_alter_space(stmt);
            break;

        case KEY_WORD_DATABASE:
            status = sql_parse_alter_database_lead(stmt);
            break;

        case KEY_WORD_SEQUENCE:
            status = sql_parse_alter_sequence(stmt);
            break;

        case KEY_WORD_INDEX:
            status = sql_parse_alter_index(stmt);
            break;

        case RES_WORD_USER:
            status = sql_parse_alter_user(stmt);
            CT_RETURN_IFERR(sql_clear_origin_sql_if_error(stmt, status));
            break;

        case KEY_WORD_TENANT:
            status = sql_parse_alter_tenant(stmt);
            break;

        case KEY_WORD_PROFILE:
            status = sql_parse_alter_profile(stmt);
            break;

        case KEY_WORD_FUNCTION:
            CT_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "alter function");
            status = CT_ERROR;
            break;

        case KEY_WORD_TRIGGER:
            status = sql_parse_alter_trigger(stmt);
            break;

        /* fall-through */
        default:
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "object type expected but %s found", W2S(&word));
            status = CT_ERROR;
            break;
    }

    return status;
}

static status_t sql_drop_public_lead(sql_stmt_t *stmt)
{
    word_t word;
    status_t status;

    if (lex_fetch(stmt->session->lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    switch (word.id) {
        case KEY_WORD_SYNONYM: {
            status = sql_parse_drop_synonym(stmt, SYNONYM_IS_PUBLIC);
            break;
        }
        default: {
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "SYNONYM expected but %s found", W2S(&word));
            return CT_ERROR;
        }
    }

    return status;
}

status_t sql_parse_analyze(sql_stmt_t *stmt)
{
    word_t word;
    status_t status;
    if (lex_fetch(stmt->session->lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    switch ((key_wid_t)word.id) {
        case KEY_WORD_TABLE:
            status = sql_parse_analyze_table(stmt);
            break;

        case KEY_WORD_INDEX:
            status = sql_parse_analyze_index(stmt);
            break;

        default:
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "object type expected but %s found", W2S(&word));
            return CT_ERROR;
    }

    return status;
}

static status_t sql_parse_drop_directory(sql_stmt_t *stmt)
{
    word_t word;
    status_t status;
    knl_drop_def_t *def = NULL;
    lex_t *lex = stmt->session->lex;

#ifdef Z_SHARDING
    if (IS_COORDINATOR && IS_APP_CONN(stmt->session)) {
        CT_THROW_ERROR(ERR_COORD_NOT_SUPPORT, "Create directory");
        return CT_ERROR;
    }
#endif

    status = sql_alloc_mem(stmt->context, sizeof(knl_drop_def_t), (void **)&def);
    CT_RETURN_IFERR(status);

    status = lex_expected_fetch_variant(lex, &word);
    CT_RETURN_IFERR(status);

    status = sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, &def->name);
    CT_RETURN_IFERR(status);

    if (lex_expected_end(stmt->session->lex) != CT_SUCCESS) {
        return CT_ERROR;
    }

    stmt->context->entry = (void *)def;
    stmt->context->type = CTSQL_TYPE_DROP_DIRECTORY;
    return lex_expected_end(lex);
}

status_t sql_parse_drop_library(sql_stmt_t *stmt)
{
    knl_drop_def_t *def = NULL;
    lex_t *lex = stmt->session->lex;
    lex->flags = LEX_WITH_OWNER;

    stmt->context->type = CTSQL_TYPE_DROP_LIBRARY;

    if (sql_alloc_mem(stmt->context, sizeof(knl_drop_def_t), (void **)&def) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_parse_drop_object(stmt, def) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_expected_end(lex) != CT_SUCCESS) {
        return CT_ERROR;
    }

    stmt->context->entry = def;
    return CT_SUCCESS;
}

status_t sql_parse_drop(sql_stmt_t *sql_stmt)
{
    word_t word;
    status_t status;

    status = lex_fetch(sql_stmt->session->lex, &word);
    CT_RETURN_IFERR(status);

    switch ((uint32)word.id) {
        case KEY_WORD_TABLE:
            status = sql_parse_drop_table(sql_stmt, CT_FALSE);
            break;
        case KEY_WORD_INDEX:
            status = sql_parse_drop_index(sql_stmt);
            break;
        case KEY_WORD_SEQUENCE:
            status = sql_parse_drop_sequence(sql_stmt);
            break;
        case KEY_WORD_TABLESPACE:
            status = sql_parse_drop_tablespace(sql_stmt);
            break;
        case KEY_WORD_TEMPORARY:
            status = sql_parse_drop_temporary_lead(sql_stmt);
            break;
        case KEY_WORD_VIEW:
            status = sql_parse_drop_view(sql_stmt);
            break;
        case RES_WORD_USER:
            status = sql_parse_drop_user(sql_stmt);
            break;
        case KEY_WORD_TENANT:
            status = sql_parse_drop_tenant(sql_stmt);
            break;
        case KEY_WORD_PUBLIC:
            status = sql_drop_public_lead(sql_stmt);
            break;
        case KEY_WORD_ROLE:
            status = sql_parse_drop_role(sql_stmt);
            break;
        case KEY_WORD_PROFILE:
            status = sql_parse_drop_profile(sql_stmt);
            break;
        case KEY_WORD_DIRECTORY:
            status = sql_parse_drop_directory(sql_stmt);
            break;
        case KEY_WORD_PROCEDURE:
        case KEY_WORD_FUNCTION:
            status = pl_parse_drop_procedure(sql_stmt, &word);
            break;
        case KEY_WORD_TRIGGER:
            status = pl_parse_drop_trigger(sql_stmt, &word);
            break;
        case KEY_WORD_PACKAGE:
            status = pl_parse_drop_package(sql_stmt, &word);
            break;
        case KEY_WORD_TYPE:
            status = pl_parse_drop_type(sql_stmt, &word);
            break;
        case KEY_WORD_SYNONYM:
            status = sql_parse_drop_synonym(sql_stmt, SYNONYM_IS_NULL);
            break;
        case KEY_WORD_DATABASE:
            status = sql_drop_database_lead(sql_stmt);
            break;
        case KEY_WORD_LIBRARY:
            status = sql_parse_drop_library(sql_stmt);
            break;

        default:
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "object type expected but %s found", W2S(&word));
            status = CT_ERROR;
            break;
    }

    return status;
}

status_t sql_parse_purge(sql_stmt_t *stmt)
{
    word_t word;
    lex_t *lex = stmt->session->lex;
    knl_purge_def_t *purge_def = NULL;
    status_t status;

    stmt->context->type = CTSQL_TYPE_PURGE;

    if (sql_alloc_mem(stmt->context, sizeof(knl_purge_def_t), (void **)&purge_def) != CT_SUCCESS) {
        return CT_ERROR;
    }

    purge_def->part_name.len = 0;
    purge_def->part_name.str = NULL;

    if (lex_fetch(stmt->session->lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    switch ((key_wid_t)word.id) {
        case KEY_WORD_TABLE:
            status = sql_parse_purge_table(stmt, purge_def);
            break;
        case KEY_WORD_INDEX:
            status = sql_parse_purge_index(stmt, purge_def);
            break;
        case KEY_WORD_PARTITION:
            status = sql_parse_purge_partition(stmt, purge_def);
            break;
        case KEY_WORD_TABLESPACE:
            status = sql_parse_purge_tablespace(stmt, purge_def);
            break;
        case KEY_WORD_RECYCLEBIN:
            purge_def->type = PURGE_RECYCLEBIN;
            stmt->context->entry = purge_def;
            status = lex_expected_end(lex);
            break;
        default:
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "object type expected but %s found", W2S(&word));
            status = CT_ERROR;
            break;
    }

    return status;
}

status_t sql_parse_truncate(sql_stmt_t *stmt)
{
    word_t word;
    status_t status;

    if (lex_fetch(stmt->session->lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    switch ((key_wid_t)word.id) {
        case KEY_WORD_TABLE:
            status = sql_parse_truncate_table(stmt);
            break;
        default:
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "object type expected but %s found", W2S(&word));
            status = CT_ERROR;
            break;
    }
    return status;
}

status_t sql_parse_flashback(sql_stmt_t *stmt)
{
    word_t word;
    status_t status;

    if (lex_fetch(stmt->session->lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    switch ((key_wid_t)word.id) {
        case KEY_WORD_TABLE:
            status = sql_parse_flashback_table(stmt);
            break;
        default:
            CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "object type expected but %s found", W2S(&word));
            status = CT_ERROR;
            break;
    }
    return status;
}
void sql_init_grant_def(sql_stmt_t *stmt, knl_grant_def_t *grant_def)
{
    cm_galist_init(&grant_def->privs, stmt->context, sql_alloc_mem);
    cm_galist_init(&grant_def->columns, stmt->context, sql_alloc_mem);
    cm_galist_init(&grant_def->grantees, stmt->context, sql_alloc_mem);
    cm_galist_init(&grant_def->privs_list, stmt->context, sql_alloc_mem);
    cm_galist_init(&grant_def->grantee_list, stmt->context, sql_alloc_mem);
    grant_def->grant_uid = stmt->session->curr_schema_id;
    return;
}

status_t sql_parse_grant(sql_stmt_t *stmt)
{
    lex_t *lex = stmt->session->lex;
    knl_session_t *se = &stmt->session->knl_session;
    status_t status;
    knl_grant_def_t *def = NULL;
    bool32 dire_priv = CT_FALSE;
    stmt->session->sql_audit.audit_type = SQL_AUDIT_DCL;
    stmt->context->type = CTSQL_TYPE_GRANT;

    if (knl_ddl_enabled(se, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }
    status = sql_alloc_mem(stmt->context, sizeof(knl_grant_def_t), (void **)&def);
    CT_RETURN_IFERR(status);

    sql_init_grant_def(stmt, def);
    status = sql_parse_grant_privs(stmt, def);
    CT_RETURN_IFERR(status);

    if (def->priv_type == PRIV_TYPE_OBJ_PRIV) {
        CT_RETURN_IFERR(sql_check_dir_priv(&def->privs, &dire_priv));
        if (dire_priv) {
            def->objtype = OBJ_TYPE_DIRECTORY;
        }
        CT_BIT_SET(lex->flags, LEX_WITH_OWNER);
        CT_RETURN_IFERR(sql_parse_grant_objprivs_def(stmt, lex, def));
        CT_BIT_RESET(lex->flags, LEX_WITH_OWNER);
    }

    if (def->priv_type == PRIV_TYPE_USER_PRIV) {
        CT_RETURN_IFERR(sql_check_user_privileges(&def->privs));
        def->objtype = OBJ_TYPE_USER;
        CT_BIT_SET(lex->flags, LEX_WITH_OWNER);
        CT_RETURN_IFERR(sql_parse_grant_objprivs_def(stmt, lex, def));
        CT_BIT_RESET(lex->flags, LEX_WITH_OWNER);
    }

    CT_RETURN_IFERR(sql_parse_grantee_def(stmt, lex, def));
    if (def->priv_type == PRIV_TYPE_OBJ_PRIV) {
        // User who has GRANT ANY OBJECT PRIVILEGE  can't grant privilege to himself except his owner object
        if (sql_check_obj_owner(lex, &stmt->session->curr_user, &def->grantees) != CT_SUCCESS) {
            if (cm_compare_text(&stmt->session->curr_user, &def->schema) != 0) {
                return CT_ERROR;
            } else {
                // sql_check_obj_owner may set error code, if object owner is current user we must clear error code.
                cm_reset_error();
            }
        }
    }
    /* check privilege's type */
    status = sql_check_privs_type(stmt, &def->privs, def->priv_type, def->objtype, &def->type_name);
    CT_RETURN_IFERR(status);

    stmt->context->entry = (void *)def;
    return CT_SUCCESS;
}

status_t sql_parse_revoke(sql_stmt_t *stmt)
{
    lex_t *lex = stmt->session->lex;
    knl_session_t *se = &stmt->session->knl_session;
    status_t status;
    knl_revoke_def_t *def = NULL;
    bool32 dire_priv = CT_FALSE;
    stmt->session->sql_audit.audit_type = SQL_AUDIT_DCL;
    stmt->context->type = CTSQL_TYPE_REVOKE;

    if (knl_ddl_enabled(se, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }
    status = sql_alloc_mem(stmt->context, sizeof(knl_revoke_def_t), (void **)&def);
    CT_RETURN_IFERR(status);

    cm_galist_init(&def->privs, stmt->context, sql_alloc_mem);
    cm_galist_init(&def->revokees, stmt->context, sql_alloc_mem);
    cm_galist_init(&def->privs_list, stmt->context, sql_alloc_mem);
    cm_galist_init(&def->revokee_list, stmt->context, sql_alloc_mem);

    status = sql_parse_revoke_privs(stmt, def);
    CT_RETURN_IFERR(status);

    if (def->priv_type == PRIV_TYPE_OBJ_PRIV) {
        CT_RETURN_IFERR(sql_check_dir_priv(&def->privs, &dire_priv));
        if (dire_priv) {
            def->objtype = OBJ_TYPE_DIRECTORY;
        }
        CT_BIT_SET(lex->flags, LEX_WITH_OWNER);
        CT_RETURN_IFERR(sql_parse_revoke_objprivs_def(stmt, lex, def));
        CT_BIT_RESET(lex->flags, LEX_WITH_OWNER);
    }

    if (def->priv_type == PRIV_TYPE_USER_PRIV) {
        CT_RETURN_IFERR(sql_check_user_privileges(&def->privs));
        def->objtype = OBJ_TYPE_USER;
        CT_BIT_SET(lex->flags, LEX_WITH_OWNER);
        CT_RETURN_IFERR(sql_parse_revoke_objprivs_def(stmt, lex, def));
        CT_BIT_RESET(lex->flags, LEX_WITH_OWNER);
    }

    CT_RETURN_IFERR(sql_parse_revokee_def(stmt, lex, def));

    if (def->priv_type == PRIV_TYPE_OBJ_PRIV) {
        CT_RETURN_IFERR(sql_check_obj_owner(lex, &stmt->session->curr_user, &def->revokees));
        CT_RETURN_IFERR(sql_check_obj_schema(lex, &def->schema, &def->revokees));
    }

    /* check privilege's type */
    status = sql_check_privs_type(stmt, &def->privs, def->priv_type, def->objtype, &def->type_name);
    CT_RETURN_IFERR(status);

    stmt->context->entry = (void *)def;
    return CT_SUCCESS;
}

status_t sql_parse_comment(sql_stmt_t *stmt)
{
    word_t word;
    lex_t *lex = stmt->session->lex;
    status_t status;

    stmt->context->type = CTSQL_TYPE_COMMENT;

    if (lex_expected_fetch_word(lex, "ON") != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_fetch(lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    switch (word.id) {
        case KEY_WORD_TABLE:
        case KEY_WORD_COLUMN:
            status = sql_parse_comment_table(stmt, (key_wid_t)word.id);
            break;
        default:
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "object expected but %s found", W2S(&word));
            return CT_ERROR;
    }

    return status;
}

status_t sql_parse_ddl(sql_stmt_t *stmt, key_wid_t wid)
{
    status_t status;
    text_t origin_sql = stmt->session->lex->text.value;
    stmt->session->sql_audit.audit_type = SQL_AUDIT_DDL;
    CT_RETURN_IFERR(sql_alloc_context(stmt));
    CT_RETURN_IFERR(sql_create_list(stmt, &stmt->context->ref_objects));

    switch (wid) {
        case KEY_WORD_CREATE:
            status = sql_parse_create(stmt);
            break;
        case KEY_WORD_DROP:
            status = sql_parse_drop(stmt);
            break;
        case KEY_WORD_TRUNCATE:
            status = sql_parse_truncate(stmt);
            break;
        case KEY_WORD_FLASHBACK:
            status = sql_parse_flashback(stmt);
            break;
        case KEY_WORD_PURGE:
            status = sql_parse_purge(stmt);
            break;
        case KEY_WORD_COMMENT:
            status = sql_parse_comment(stmt);
            break;
        case KEY_WORD_GRANT:
            status = sql_parse_grant(stmt);
            break;
        case KEY_WORD_REVOKE:
            status = sql_parse_revoke(stmt);
            break;
        case KEY_WORD_ANALYZE:
            status = sql_parse_analyze(stmt);
            break;
        default:
            status = sql_parse_ddl_alter(stmt);
            break;
    }

    // write ddl sql into context, exclude operate pwd ddl
    if (!SQL_OPT_PWD_DDL_TYPE(stmt->context->type)) {
        CT_RETURN_IFERR(ctx_write_text(&stmt->context->ctrl, &origin_sql));
        stmt->context->ctrl.hash_value = cm_hash_text(&origin_sql, INFINITE_HASH_RANGE);
    }

    return status;
}

status_t sql_parse_scope_clause_inner(knl_alter_sys_def_t *def, lex_t *lex, bool32 force)
{
    bool32 result = CT_FALSE;
    uint32 match_id;
    status_t status;

    // if already parsed scope clause, must return
    if (def->scope >= CONFIG_SCOPE_MEMORY) {
        return CT_SUCCESS;
    }

    if (force) {
        status = lex_expected_fetch_word(lex, "scope");
        CT_RETURN_IFERR(status);
    } else {
        status = lex_try_fetch(lex, "scope", &result);
        CT_RETURN_IFERR(status);
        if (!result) {
            def->scope = CONFIG_SCOPE_BOTH;
            return CT_SUCCESS;
        }
    }

    status = lex_expected_fetch_word(lex, "=");
    CT_RETURN_IFERR(status);

    status = lex_expected_fetch_1of3(lex, "memory", "pfile", "both", &match_id);
    CT_RETURN_IFERR(status);

    if (match_id == LEX_MATCH_FIRST_WORD) {
        def->scope = CONFIG_SCOPE_MEMORY;
    } else if (match_id == LEX_MATCH_SECOND_WORD) {
        def->scope = CONFIG_SCOPE_DISK;
    } else {
        def->scope = CONFIG_SCOPE_BOTH;
    }

    return CT_SUCCESS;
}

status_t sql_parse_expected_scope_clause(knl_alter_sys_def_t *def, lex_t *lex)
{
    return sql_parse_scope_clause_inner(def, lex, CT_TRUE);
}

status_t sql_parse_scope_clause(knl_alter_sys_def_t *def, lex_t *lex)
{
    return sql_parse_scope_clause_inner(def, lex, CT_FALSE);
}

#ifndef WIN32
status_t sql_verify_lib_host(char *realfile)
{
    char file_host[CT_FILE_NAME_BUFFER_SIZE];
    if (cm_get_file_host_name(realfile, file_host) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (!cm_str_equal(file_host, cm_sys_user_name())) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}
#endif

status_t sql_verify_library(sql_stmt_t *stmt, pl_library_def_t *def)
{
    if (sql_check_priv(stmt, &stmt->session->curr_user, &def->owner, CREATE_LIBRARY, CREATE_ANY_LIBRARY) !=
        CT_SUCCESS) {
        CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
        return CT_ERROR;
    }

    if (def->path.len >= CT_FILE_NAME_BUFFER_SIZE) {
        CT_THROW_ERROR(ERR_FILE_PATH_TOO_LONG, CT_FILE_NAME_BUFFER_SIZE - 1);
        return CT_ERROR;
    }
    char lib_path[CT_FILE_NAME_BUFFER_SIZE];
    char realfile[CT_FILE_NAME_BUFFER_SIZE];

    CT_RETURN_IFERR(cm_text2str(&def->path, lib_path, CT_FILE_NAME_BUFFER_SIZE));
    CT_RETURN_IFERR(realpath_file((const char *)lib_path, realfile, CT_FILE_NAME_BUFFER_SIZE));
    if (strlen(realfile) == 0 || !cm_file_exist(realfile)) {
        CT_THROW_ERROR(ERR_FILE_NOT_EXIST, "library", realfile);
        return CT_ERROR;
    }

    if (cm_access_file(realfile, X_OK) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_EXECUTE_FILE, realfile, cm_get_os_error());
        return CT_ERROR;
    }
    void *lib_handle = NULL;
#ifndef WIN32
    if (cm_open_dl(&lib_handle, realfile) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_LOAD_LIBRARY, realfile, cm_get_os_error());
        return CT_ERROR;
    }
    cm_close_dl(lib_handle);
    if (cm_verify_file_host(realfile) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_FILE_EXEC_PRIV, realfile);
        return CT_ERROR;
    }
#endif

#ifdef WIN32
    char *leaf_name = strrchr(realfile, '\\');
#else
    char *leaf_name = strrchr(realfile, '/');
#endif

    if (leaf_name == NULL || strlen(leaf_name) == 1) {
        CT_THROW_ERROR(ERR_TEXT_FORMAT_ERROR, "dynamic link library");
        return CT_ERROR;
    }
    leaf_name = leaf_name + 1;
    return sql_copy_str_safe(stmt->context, leaf_name, (uint32)strlen(leaf_name), &def->leaf_name);
}

status_t sql_parse_create_library(sql_stmt_t *stmt, bool32 is_replace)
{
    word_t word;
    pl_library_def_t *def = NULL;
    lex_t *lex = stmt->session->lex;
    lex->flags = LEX_WITH_OWNER;

    stmt->context->type = CTSQL_TYPE_CREATE_LIBRARY;
    if (sql_alloc_mem(stmt->context, sizeof(pl_library_def_t), (pointer_t *)&def) != CT_SUCCESS) {
        return CT_ERROR;
    }

    def->is_replace = is_replace;

    if (lex_expected_fetch_variant(lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_convert_object_name(stmt, &word, &def->owner, NULL, &def->name) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_fetch(lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (word.id != KEY_WORD_AS && word.id != KEY_WORD_IS) {
        CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "expected as or is but %s found", W2S(&word));
        return CT_ERROR;
    }

    if (lex_expected_fetch_string(lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_copy_text(stmt->context, (text_t *)&word.text, &def->path) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_verify_library(stmt, def)) {
        return CT_ERROR;
    }

    stmt->context->entry = def;

    return lex_expected_end(lex);
}
status_t sql_verify_als_cpu_inf_str(void *se, void *lex, void *def)
{
    return CT_SUCCESS;
}
status_t sql_verify_als_mq_thd_num(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (num < CT_MQ_MIN_THD_NUM) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "SHM_MQ_MSG_RECV_THD_NUM", (int64)CT_MQ_MIN_THD_NUM);
        return CT_ERROR;
    }
    if (num > CT_MQ_MAX_THD_NUM) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "SHM_MQ_MSG_RECV_THD_NUM", (int64)CT_MQ_MAX_THD_NUM);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_verify_als_mq_queue_num(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (num < CT_MQ_MIN_QUEUE_NUM) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "SHM_MQ_MSG_QUEUE_NUM", (int64)CT_MQ_MIN_QUEUE_NUM);
        return CT_ERROR;
    }
    if (num > CT_MQ_MAX_QUEUE_NUM) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "SHM_MQ_MSG_QUEUE_NUM", (int64)CT_MQ_MAX_QUEUE_NUM);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_verify_als_ctc_inst_num(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (num < CT_CTC_MIN_INST_NUM) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "CTC_MAX_INST_PER_NODE", (int64)CT_CTC_MIN_INST_NUM);
        return CT_ERROR;
    }
    if (num > CT_CTC_MAX_INST_NUM) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "CTC_MAX_INST_PER_NODE", (int64)CT_CTC_MAX_INST_NUM);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_verify_als_mq_thd_cool_time(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (num < CT_MQ_MIN_COOL_TIME) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "SHM_MQ_MSG_THD_COOL_TIME_US", (int64)CT_MQ_MIN_COOL_TIME);
        return CT_ERROR;
    }
    if (num > CT_MQ_MAX_COOL_TIME) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "SHM_MQ_MSG_THD_COOL_TIME_US", (int64)CT_MQ_MAX_COOL_TIME);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}
#ifdef __cplusplus
}
#endif
