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
 * ctsql_replace.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/executor/ctsql_replace.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_base.h"
#include "ctsql_insert.h"
#include "ctsql_update.h"
#include "ctsql_select.h"
#include "ctsql_proj.h"
#include "srv_instance.h"
#include "ctsql_scan.h"
#include "ctsql_replace.h"
#include "ctsql_delete.h"

static status_t sql_fetch_replace_delete(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_insert_t *insert_ctx,
    knl_cursor_t *knl_cur, bool32 *is_found)
{
    CT_RETURN_IFERR(SQL_CURSOR_PUSH(stmt, cursor));
    CT_RETURN_IFERR(knl_fetch_by_rowid(KNL_SESSION(stmt), knl_cur, is_found));

    if (!(*is_found)) {
        SQL_CURSOR_POP(stmt);
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(knl_delete(&stmt->session->knl_session, knl_cur));

    cursor->total_rows++;
    SQL_CURSOR_POP(stmt);
    return CT_SUCCESS;
}

static status_t sql_execute_replace_delete(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_insert_t *insert_ctx,
                                           knl_dictionary_t *dc, bool32 *is_found)
{
    knl_cursor_t *insert_cursor = cursor->tables[0].knl_cur;
    knl_cursor_t *delete_knl_cur = cursor->exec_data.ext_knl_cur;
    status_t status;
    errno_t ret;

    CT_RETURN_IFERR(sql_execute_delete_triggers(stmt, insert_ctx->table, TRIG_BEFORE_EACH_ROW, insert_cursor));

    delete_knl_cur->action = CURSOR_ACTION_DELETE;
    CT_RETURN_IFERR(knl_open_cursor(KNL_SESSION(stmt), delete_knl_cur, dc));
    CT_RETURN_IFERR(sql_push(stmt, CT_MAX_ROW_SIZE, (void **)&delete_knl_cur->row));
    ret = memset_sp(delete_knl_cur->row, CT_MAX_ROW_SIZE, 0, CT_MAX_ROW_SIZE);
    if (ret != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        CTSQL_POP(stmt);
        return CT_ERROR;
    }
    // set statement ssn when replace and before do delete
    sql_set_ssn(stmt);

    // replace delete set ssn
    delete_knl_cur->query_scn = insert_cursor->query_scn;
    if (dc->type == DICT_TYPE_TEMP_TABLE_SESSION || dc->type == DICT_TYPE_TEMP_TABLE_TRANS) {
        delete_knl_cur->ssn = stmt->ssn;
    } else {
        delete_knl_cur->ssn = stmt->xact_ssn;
    }

    ROWID_COPY(delete_knl_cur->rowid, insert_cursor->conflict_rid);
    // may call sql_match_cond in knl_match_cond, need used current cursor in sql_match_cond
    status = sql_fetch_replace_delete(stmt, cursor, insert_ctx, delete_knl_cur, is_found);
    /* if row is not found while delete, do not execute after trigger and foreign key check */
    if (*is_found && status == CT_SUCCESS) {
        CT_RETURN_IFERR(sql_execute_delete_triggers(stmt, insert_ctx->table, TRIG_AFTER_EACH_ROW, delete_knl_cur));
        CT_RETURN_IFERR(knl_verify_children_dependency(&stmt->session->knl_session, delete_knl_cur, false, 0, false));
    }

    CTSQL_POP(stmt);
    return status;
}

static status_t sql_replace_single_row(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_insert_t *insert_ctx,
    knl_dictionary_t *dc, knl_cursor_t *knl_cur, sql_cursor_t *cur_select)
{
    char *buffer = NULL;
    status_t status;
    bool32 is_found = CT_FALSE;
    insert_assist_t assist;
    insert_data_t insert_data = {
        .cur_select = cur_select,
        .row_modify = CT_FALSE
    };

    sql_init_insert_assist(&assist, &insert_data, insert_ctx, cur_select);
    CT_RETURN_IFERR(sql_generate_insert_data(stmt, knl_cur, &assist));

    if (insert_ctx->table->type == VIEW_AS_TABLE) {
        return sql_insteadof_triggers(stmt, insert_ctx->table, knl_cur, &insert_data, TRIG_EVENT_INSERT);
    }
    CT_RETURN_IFERR(sql_execute_insert_triggers(stmt, insert_ctx->table, TRIG_BEFORE_EACH_ROW, knl_cur, &insert_data));
    CT_RETURN_IFERR(sql_push(stmt, g_instance->kernel.attr.max_row_size, (void **)&buffer));

    do {
        CT_BREAK_IF_ERROR(sql_insert_inner(stmt, cursor, knl_cur, &assist, &status));

        // knl_insert return success
        if (status == CT_SUCCESS) {
            CTSQL_POP(stmt);
            return CT_SUCCESS;
        }

        // for on duplicate key update
        CT_BREAK_IF_TRUE(CT_ERRNO != ERR_DUPLICATE_KEY);

        // to release lob insert page when  insert failed result from primary key
        // or unique key  violation using sql "on duplicate key"
        CT_BREAK_IF_ERROR(knl_recycle_lob_insert_pages(&stmt->session->knl_session, knl_cur));

        if (HAS_SPEC_TYPE_HINT(insert_ctx->hint_info, OPTIM_HINT, HINT_KEY_WORD_THROW_DUPLICATE)) {
            break;
        }

        // row has been modified by trigger, store it
        CT_BREAK_IF_ERROR(sql_store_row_if_trigger_modify(&insert_data, knl_cur, buffer));

        // execute insert update
        cm_reset_error();

        // delete + insert
        CT_BREAK_IF_ERROR(sql_execute_replace_delete(stmt, cursor, insert_ctx, dc, &is_found));

        if (is_found) {
            sql_reset_insert_assist(&assist);
            CT_BREAK_IF_ERROR(sql_generate_insert_data(stmt, knl_cur, &assist));

            CT_BREAK_IF_ERROR(sql_insert_inner(stmt, cursor, knl_cur, &assist, &status));

            if (status == CT_SUCCESS) {
                CTSQL_POP(stmt);
                return CT_SUCCESS;
            }

            // for on duplicate key update
            CT_BREAK_IF_TRUE(CT_ERRNO != ERR_DUPLICATE_KEY);
        }

        // row has been modified by trigger, restore it
        CT_BREAK_IF_ERROR(sql_restore_row_if_trigger_modify(&insert_data, knl_cur, buffer, stmt, &assist));

        SQL_CHECK_SESSION_VALID_FOR_RETURN(stmt);
    } while (CT_TRUE);

    CTSQL_POP(stmt);
    return CT_ERROR;
}

static status_t sql_execute_replace_select_plan(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_insert_t *insert_ctx,
    knl_dictionary_t *dc, knl_cursor_t *knl_cur)
{
    sql_cursor_t *sub_cursor = NULL;
    bool32 eof = CT_FALSE;
    plan_node_t *plan = insert_ctx->select_ctx->plan;
    status_t status = CT_SUCCESS;

    if (sql_alloc_cursor(stmt, &sub_cursor) != CT_SUCCESS) {
        return CT_ERROR;
    }
    sub_cursor->plan = plan;
    sub_cursor->select_ctx = insert_ctx->select_ctx;
    sub_cursor->scn = CT_INVALID_ID64;
    if (sql_execute_select_plan(stmt, sub_cursor, sub_cursor->plan->select_p.next) != CT_SUCCESS) {
        sql_free_cursor(stmt, sub_cursor);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(SQL_CURSOR_PUSH(stmt, sub_cursor));

    for (;;) {
        CTSQL_SAVE_STACK(stmt);
        if (sql_fetch_cursor(stmt, sub_cursor, sub_cursor->plan->select_p.next, &eof) != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            status = CT_ERROR;
            break;
        }

        if (eof) {
            CTSQL_RESTORE_STACK(stmt);
            break;
        }

        if (sql_replace_single_row(stmt, cursor, insert_ctx, dc, knl_cur, sub_cursor) != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            status = CT_ERROR;
            break;
        }
        CTSQL_RESTORE_STACK(stmt);
        cursor->total_rows++;
    }

    SQL_CURSOR_POP(stmt);
    sql_free_cursor(stmt, sub_cursor);
    return status;
}

status_t sql_execute_replace_plan(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_insert_t *insert_ctx)
{
    uint32 i;
    status_t status = CT_SUCCESS;
    knl_dictionary_t *dc = &cursor->tables[0].table->entry->dc;
    knl_cursor_t *knl_cursor = cursor->tables[0].knl_cur;
    bool32 table_nologging_enabled = knl_table_nologging_enabled(dc->handle);
    if (stmt->context->type == CTSQL_TYPE_INSERT && !stmt->is_sub_stmt &&
        (stmt->session->nologging_enable || table_nologging_enabled)) {
        if (!DB_IS_SINGLE(&stmt->session->knl_session) ||
            (DB_IS_RCY_CHECK_PCN(&stmt->session->knl_session) && stmt->session->nologging_enable)) {
            CT_LOG_DEBUG_WAR("forbid to nologging load when database in HA mode or \
                when _RCY_CHECK_PCN is TRUE on session_level nologging insert");
            knl_cursor->logging = CT_TRUE;
            knl_cursor->nologging_type = LOGGING_LEVEL;
            stmt->session->knl_session.rm->logging = CT_TRUE;
            knl_cursor->nologging_type = LOGGING_LEVEL;
            stmt->session->knl_session.rm->nolog_type = knl_cursor->nologging_type;
        } else {
            knl_cursor->logging = CT_FALSE;
            stmt->session->knl_session.rm->logging = CT_FALSE;
            knl_cursor->nologging_type = knl_table_nologging_enabled(dc->handle) ? TABLE_LEVEL : SESSION_LEVEL;
            stmt->session->knl_session.rm->nolog_type = knl_cursor->nologging_type;
        }
    }

    if (knl_open_cursor(&stmt->session->knl_session, knl_cursor, dc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_push(stmt, CT_MAX_ROW_SIZE, (void **)&knl_cursor->row) != CT_SUCCESS) {
        return CT_ERROR;
    }

    sql_prepare_scan(stmt, dc, knl_cursor);

    if (insert_ctx->select_ctx != NULL) {
        status = sql_execute_replace_select_plan(stmt, cursor, insert_ctx, dc, knl_cursor);
    } else {
        for (i = 0; i < insert_ctx->pairs_count; i++) {
            stmt->pairs_pos = i;
            CTSQL_SAVE_STACK(stmt);
            status = sql_replace_single_row(stmt, cursor, insert_ctx, dc, knl_cursor, NULL);
            CTSQL_RESTORE_STACK(stmt);
            if (status != CT_SUCCESS) {
                break;
            }

            cursor->total_rows++;
        }
    }

    CTSQL_POP(stmt);

    stmt->default_column = NULL;
    return status;
}

status_t sql_execute_replace_with_ctx(sql_stmt_t *stmt, sql_replace_t *replace_ctx)
{
    sql_cursor_t *cursor = CTSQL_ROOT_CURSOR(stmt);
    status_t status;

    cursor->scn = CT_INVALID_ID64;

    CT_RETURN_IFERR(
        sql_execute_insert_triggers(stmt, replace_ctx->insert_ctx.table, TRIG_BEFORE_STATEMENT, NULL, NULL));

    // set statement ssn after the before statement triggers executed
    sql_set_scn(stmt);
    sql_set_ssn(stmt);
    CT_RETURN_IFERR(sql_open_insert_cursor(stmt, cursor, &replace_ctx->insert_ctx));

    status = sql_execute_replace_plan(stmt, cursor, &replace_ctx->insert_ctx);

    stmt->session->knl_session.rm->logging = CT_TRUE;
    CT_RETURN_IFERR(status);
    CT_RETURN_IFERR(sql_execute_insert_triggers(stmt, replace_ctx->insert_ctx.table, TRIG_AFTER_STATEMENT, NULL, NULL));

    stmt->eof = CT_TRUE;
    cursor->eof = CT_TRUE;
    return CT_SUCCESS;
}

static status_t sql_execute_replace_core(sql_stmt_t *stmt)
{
    uint64 conflicts = 0;
    /*
     * reset index conflicts to 0, and check it after stmt
     * to see if unique constraints violated.
     */
    knl_init_index_conflicts(KNL_SESSION(stmt), &conflicts);
    CT_RETURN_IFERR(sql_execute_replace_with_ctx(stmt, (sql_replace_t *)stmt->context->entry));
    return knl_check_index_conflicts(KNL_SESSION(stmt), conflicts);
}

status_t sql_execute_replace(sql_stmt_t *stmt)
{
    status_t status = CT_ERROR;
    knl_savepoint_t sp;

    do {
        knl_savepoint(KNL_SESSION(stmt), &sp);
        status = sql_execute_replace_core(stmt);
        // execute replace failed when shrink table, need restart
        if (status == CT_ERROR && cm_get_error_code() == ERR_NEED_RESTART) {
            CT_LOG_RUN_INF("replace failed when shrink table, replace restart");
            cm_reset_error();
            knl_rollback(KNL_SESSION(stmt), &sp);
            sql_set_scn(stmt);
            continue;
        } else {
            break;
        }
    } while (CT_TRUE);

    return status;
}