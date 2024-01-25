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
 * ctsql_parser.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/parser/ctsql_parser.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_parser.h"
#include "dml_parser.h"
#include "ddl_parser.h"
#include "dcl_parser.h"
#include "srv_instance.h"
#include "pl_compiler.h"
#include "pl_executor.h"
#include "ctsql_audit.h"
#include "dml_executor.h"

#ifdef __cplusplus
extern "C" {
#endif


#define SQL_REFORM_CALL_HEAD_SIZE 6

static status_t sql_reform_call(sql_stmt_t *stmt)
{
    sql_text_t origin_sql;
    uint32 buf_len = stmt->session->lex->curr_text->len + (uint32)strlen("begin\n") + (uint32)strlen(";\nend;\n/");
    char *buffer = NULL;

    CT_RETURN_IFERR(sql_push(stmt, buf_len, (void **)&buffer));
    text_t sql = {
        .str = buffer,
        .len = 0
    };
    source_location_t loc = {
        .line = 0,
        .column = 1
    };
    status_t status;

    // save origin sql like 'call proc'
    origin_sql = stmt->session->lex->text;

    cm_concat_string(&sql, buf_len, "begin\n");
    cm_concat_text(&sql, buf_len, &stmt->session->lex->curr_text->value);
    cm_concat_string(&sql, buf_len, ";\nend;\n/");
    stmt->is_reform_call = CT_TRUE;
    stmt->text_shift =
        (int32)(stmt->session->lex->curr_text->str - stmt->session->lex->text.str) - SQL_REFORM_CALL_HEAD_SIZE;

    status = sql_parse(stmt, &sql, &loc);

    // recovery origin sql like 'call proc' avoid to record wrong audit log
    stmt->session->sql_audit.sql = origin_sql.value;

    return status;
}

status_t sql_aud_proc_check(sql_stmt_t *stmt, word_t *leader)
{
    text_t clean_aud_log_name = {
        .str = "AUD$CLEAN_AUD_LOG",
        .len = 17
    };
    text_t modify_setting_name = {
        .str = "AUD$MODIFY_SETTING",
        .len = 18
    };
    text_t sys_user_name = {
        .str = SYS_USER_NAME,
        .len = SYS_USER_NAME_LEN
    };
    text_t *curr_user = &stmt->session->curr_user;
    text_t owner;
    text_t name;
    char buffer[CT_NAME_BUFFER_SIZE];
    lex_t *lex = stmt->session->lex;
    word_t word;
    LEX_SAVE(lex);
    uint32 prev_flags = lex->flags;
    lex->flags = LEX_WITH_OWNER;
    CT_RETURN_IFERR(lex_expected_fetch_variant(lex, &word));
    if (word.ex_count == 1) {
        CT_RETURN_IFERR(cm_text2str(&word.text.value, buffer, CT_MAX_NAME_LEN));
        CT_RETURN_IFERR(sql_user_prefix_tenant(stmt->session, buffer));
        cm_str2text_safe(buffer, (uint32)strlen(buffer), &owner);
        name = word.ex_words[0].text.value;
    } else if (word.ex_count == 0) {
        owner.str = stmt->session->curr_schema;
        owner.len = (uint32)strlen(stmt->session->curr_schema);
        name = word.text.value;
    } else {
        LEX_RESTORE(lex);
        lex->flags = prev_flags;
        return CT_SUCCESS;
    }
    if ((cm_compare_text_ins(&name, &modify_setting_name) == 0) ||
        (cm_compare_text_ins(&name, &clean_aud_log_name) == 0)) {
        if (cm_compare_text_ins(&owner, &sys_user_name) == 0) {
            if (cm_compare_text_ins(curr_user, &sys_user_name) != 0) {
                LEX_RESTORE(lex);
                lex->flags = prev_flags;
                CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "The common user can't call this procedure, only for sys.");
                return CT_ERROR;
            }
        }
    }
    LEX_RESTORE(lex);
    lex->flags = prev_flags;
    return CT_SUCCESS;
}

static status_t sql_parse_anonymous(sql_stmt_t *stmt, word_t *leader)
{
    if (!GET_PL_MGR->initialized) {
        CT_THROW_ERROR(ERR_DATABASE_NOT_AVAILABLE);
        return CT_ERROR;
    }

    {
        CT_RETURN_IFERR(sql_parse_anonymous_directly(stmt, leader, &stmt->session->lex->text));
    }

    return CT_SUCCESS;
}

status_t sql_parse_pl(sql_stmt_t *stmt, word_t *leader)
{
    status_t status;

    SQL_SET_IGNORE_PWD(stmt->session);
    SQL_SET_COPY_LOG(stmt->session, CT_TRUE);
    if (leader->id == KEY_WORD_CALL || leader->id == KEY_WORD_EXEC || leader->id == KEY_WORD_EXECUTE) {
        CT_RETURN_IFERR(sql_aud_proc_check(stmt, leader));
    }
    // maybe need load entity from proc$
    knl_set_session_scn(&stmt->session->knl_session, CT_INVALID_ID64);
    stmt->session->sql_audit.audit_type = SQL_AUDIT_PL;

    CTSQL_SAVE_STACK(stmt);
    if (leader->id == KEY_WORD_CALL || leader->id == KEY_WORD_EXEC || leader->id == KEY_WORD_EXECUTE) {
        status = sql_reform_call(stmt);
    } else {
        status = sql_parse_anonymous(stmt, leader);
    }
    CTSQL_RESTORE_STACK(stmt);

    return status;
}

lang_type_t sql_diag_begin_type(sql_stmt_t *stmt)
{
    word_t word;

    if (lex_push(stmt->session->lex, stmt->session->lex->curr_text) != CT_SUCCESS) {
        return LANG_INVALID;
    }

    if (lex_fetch(stmt->session->lex, &word) != CT_SUCCESS) {
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

    if (lex_push(stmt->session->lex, stmt->session->lex->curr_text) != CT_SUCCESS) {
        return LANG_DDL;
    }
    if (lex_try_fetch_1of2(stmt->session->lex, "SYSTEM", "SESSION", &matched_id) != CT_SUCCESS) {
        lex_pop(stmt->session->lex);
        return LANG_DDL;
    } else {
        if (matched_id != CT_INVALID_ID32) {
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

    CT_RETVALUE_IFTRUE((lex_fetch(stmt->session->lex, leader_word) != CT_SUCCESS), LANG_INVALID);

    /* sql text enclosed by brackets must be select statement */
    if (leader_word->type == WORD_TYPE_BRACKET) {
        leader_word->id = KEY_WORD_SELECT;
    }

    if (IS_PL_LABEL(leader_word)) {
        leader_word->id = KEY_WORD_DECLARE;
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
            status = sql_parse_pl(stmt, leader_word);
            break;
        default:
            CT_SRC_THROW_ERROR(sql_text->loc, ERR_SQL_SYNTAX_ERROR, "key word expected");
            status = CT_ERROR;
    }

    text_t sql_log_text = stmt->session->sql_audit.sql;
    if (LOG_DEBUG_ERR_ON || LOG_DEBUG_INF_ON) {
        sql_ignore_passwd_log(stmt->session, &sql_log_text);
    }
    sql_free_vmemory(stmt);

    if (status != CT_SUCCESS) {
        sql_unlock_lnk_tabs(stmt);
        sql_release_context(stmt);
        OBJ_STACK_RESET(&stmt->ssa_stack);
        OBJ_STACK_RESET(&stmt->node_stack);
        CT_LOG_DEBUG_ERR("Parse SQL failed, SQL = %s", T2S(&sql_log_text));
    } else {
        CT_LOG_DEBUG_INF("Parse SQL successfully, SQL = %s", T2S(&sql_log_text));
    }

    return status;
}

static status_t sql_parse_core(sql_stmt_t *stmt, text_t *sql, source_location_t *loc)
{
    sql_text_t sql_text;
    word_t leader_word;
    status_t status;
    timeval_t timeval_end;
    timeval_t timeval_begin;

    stmt->pl_failed = CT_FALSE;
    stmt->session->sql_audit.sql = *sql;

    sql_text.value = *sql;
    sql_text.loc = *loc;

    SQL_SET_COPY_LOG(stmt->session, CT_FALSE);

    if (stmt->pl_exec != NULL || stmt->pl_compiler != NULL) { // can't modify sql in pl
        SQL_SET_COPY_LOG(stmt->session, CT_TRUE);
    }

    (void)cm_gettimeofday(&timeval_begin);
    CTSQL_SAVE_STACK(stmt);
    stmt->lang_type = sql_diag_lang_type(stmt, &sql_text, &leader_word);

    status = sql_parse_by_lang_type(stmt, &sql_text, &leader_word);
    CTSQL_RESTORE_STACK(stmt);
    (void)cm_gettimeofday(&timeval_end);
    stmt->session->stat.parses++;
    stmt->session->stat.parses_time_elapse += TIMEVAL_DIFF_US(&timeval_begin, &timeval_end);
    g_instance->library_cache_info[stmt->lang_type].lang_type = stmt->lang_type;
    return status;
}

status_t sql_parse(sql_stmt_t *stmt, text_t *sql, source_location_t *loc)
{
    word_t leader_word;
    status_t status;
    sql_text_t sql_text = { 0 };

    CTSQL_SAVE_STACK(stmt);
    sql_text.value = *sql;
    sql_text.loc = *loc;
    stmt->lang_type = sql_diag_lang_type(stmt, &sql_text, &leader_word);

    status = sql_parse_core(stmt, sql, loc);

    CTSQL_RESTORE_STACK(stmt);
    return status;
}

#ifdef __cplusplus
}
#endif
