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
 * ctsql_select.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/executor/ctsql_select.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_SELECT_H__
#define __SQL_SELECT_H__

#include "cm_hash.h"
#include "dml_executor.h"

static inline void sql_reset_cursor_action(sql_cursor_t *cursor, knl_cursor_action_t action)
{
    sql_table_cursor_t *tab_cur = NULL;

    for (uint32 i = 0; i < cursor->table_count; i++) {
        tab_cur = &cursor->tables[i];
        if (tab_cur->table->type != NORMAL_TABLE || tab_cur->knl_cur->eof) {
            continue;
        }
        tab_cur->knl_cur->action = action;
    }
}

static inline status_t sql_lock_row(sql_stmt_t *stmt, sql_cursor_t *cursor, knl_cursor_t **knl_curs,
    knl_cursor_action_t action, bool32 *is_found)
{
    bool32 found = CT_FALSE;
    sql_table_cursor_t *tab_cur = NULL;

    for (uint32 i = 0; i < cursor->table_count; i++) {
        tab_cur = &cursor->tables[i];

        if (tab_cur->table->type != NORMAL_TABLE || tab_cur->knl_cur->eof ||
            sql_is_invalid_rowid(&tab_cur->knl_cur->rowid, tab_cur->table->entry->dc.type)) {
            continue;
        }

        if (tab_cur->hash_table) {
            knl_curs[tab_cur->table->id]->rowid = tab_cur->knl_cur->rowid;
            CT_RETURN_IFERR(knl_fetch_by_rowid(KNL_SESSION(stmt), knl_curs[tab_cur->table->id], &found));
        } else {
            tab_cur->knl_cur->action = action;
            CT_RETURN_IFERR(knl_lock_row(KNL_SESSION(stmt), tab_cur->knl_cur, &found));
        }

        if (!found) {
            *is_found = CT_FALSE;
            return CT_SUCCESS;
        }
    }
    *is_found = CT_TRUE;
    return CT_SUCCESS;
}

static inline sql_array_t *sql_get_query_tables(sql_cursor_t *cursor, sql_query_t *query)
{
    if (cursor->connect_data.last_level_cursor != NULL || query->s_query == NULL) {
        return &query->tables;
    }
    return &query->s_query->tables;
}

status_t sql_init_multi_update(sql_stmt_t *stmt, sql_cursor_t *cursor, knl_cursor_action_t action,
    knl_cursor_t **knl_curs);

typedef status_t (*sql_fetch_func_t)(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof);
typedef status_t (*sql_send_row_func_t)(sql_stmt_t *stmt, sql_cursor_t *cursor, bool32 *is_full);

typedef struct st_rs_fetch_func_tab {
    uint8 rs_type;
    sql_fetch_func_t sql_fetch_func;
} rs_fetch_func_tab_t;

status_t sql_execute_select(sql_stmt_t *stmt);
status_t sql_open_query_cursor(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_query_t *query);
status_t sql_fetch_cursor(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan_node, bool32 *eof);
status_t sql_fetch_query(sql_stmt_t *stmt, sql_cursor_t *cur, plan_node_t *plan, bool32 *eof);
status_t sql_execute_query(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan);
status_t sql_execute_query_plan(sql_stmt_t *stmt, sql_cursor_t *cur, plan_node_t *plan);
status_t sql_execute_select_plan(sql_stmt_t *stmt, sql_cursor_t *cur, plan_node_t *plan);
void sql_open_select_cursor(sql_stmt_t *stmt, sql_cursor_t *cur, galist_t *rs_columns);
status_t shd_refuse_sql(sql_stmt_t *stmt);
status_t sql_execute_join(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof);
status_t sql_fetch_join(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan_node, bool32 *eof);
status_t sql_make_normal_rs(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_fetch_func_t sql_fetch_func,
    sql_send_row_func_t sql_send_row_func);
sql_send_row_func_t sql_get_send_row_func(sql_stmt_t *stmt, plan_node_t *plan);
status_t sql_open_cursors(sql_stmt_t *stmt, sql_cursor_t *cur, sql_query_t *query, knl_cursor_action_t cursor_action,
                          bool32 is_select);
uint16 sql_get_decode_count(sql_table_t *table);
status_t sql_check_sub_select_pending(sql_cursor_t *parent_cursor, sql_select_t *select_context, bool32 *pending);
status_t sql_generate_cursor_exec_data(sql_stmt_t *stmt, sql_cursor_t *cur, sql_query_t *query);
status_t sql_free_query_mtrl(sql_stmt_t *stmt, sql_cursor_t *cur, plan_node_t *plan);
status_t sql_fetch_rownum(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof);
status_t sql_fetch_for_update(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof);
status_t sql_get_parent_remote_table_id(sql_cursor_t *parent_cursor, uint32 tab_id, uint32 *remote_id);

#define CHECK_SESSION_VALID_IN_FETCH(stmt, cursor)  \
    do {                                            \
        if (KNL_SESSION(stmt)->killed) {            \
            sql_close_cursor((stmt), (cursor));     \
            CT_THROW_ERROR(ERR_OPERATION_KILLED);   \
            return CT_ERROR;                        \
        }                                           \
        if (KNL_SESSION(stmt)->canceled) {          \
            sql_close_cursor((stmt), (cursor));     \
            CT_THROW_ERROR(ERR_OPERATION_CANCELED); \
            return CT_ERROR;                        \
        }                                           \
    } while (0)

#define CM_TRACE_BEGIN                        \
    date_t __starttime__ = 0;                 \
    do {                                      \
        if (SECUREC_UNLIKELY(AUTOTRACE_ON(stmt))) { \
            __starttime__ = cm_now();         \
        }                                     \
    } while (0)

#define CM_TRACE_END(stmt, plan_id)                                          \
    do {                                                                     \
        if (SECUREC_UNLIKELY(AUTOTRACE_ON(stmt) && ((stmt)->plan_time != NULL))) { \
            (stmt)->plan_time[(plan_id)] += (cm_now() - __starttime__);      \
        }                                                                    \
    } while (0)

#define IS_QUERY_SCAN_PLAN(type) \
    (type == PLAN_NODE_JOIN || type == PLAN_NODE_SCAN || type == PLAN_NODE_CONCATE || type == PLAN_NODE_REMOTE_SCAN)
#endif
