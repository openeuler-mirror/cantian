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
 * ctsql_nl_join.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/executor/ctsql_nl_join.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_NL_JOIN_H__
#define __SQL_NL_JOIN_H__

#include "dml_executor.h"

#define NEST_LOOP_BATCH_SIZE 256

static inline void sql_save_cursor_cond(sql_cursor_t *cursor, cond_tree_t *new_cond, cond_tree_t **old_cond)
{
    *old_cond = cursor->cond;
    cursor->cond = new_cond;
}

static inline void sql_restore_cursor_cond(sql_cursor_t *cursor, cond_tree_t *old_cond)
{
    cursor->cond = old_cond;
}

static inline void sql_try_save_cursor_cond(sql_cursor_t *cursor, cond_tree_t *new_cond, cond_tree_t **old_cond,
    bool32 *need_restore)
{
    // if new_cond is null, only inner join in sql
    *need_restore = CT_FALSE;
    if (new_cond != NULL) {
        *need_restore = CT_TRUE;
        sql_save_cursor_cond(cursor, new_cond, old_cond);
    }
}

static inline void sql_try_restore_cursor_cond(sql_cursor_t *cursor, cond_tree_t *old_cond, bool32 need_restore)
{
    if (need_restore) {
        sql_restore_cursor_cond(cursor, old_cond);
    }
}
void sql_end_plan_cursor_fetch(sql_cursor_t *cursor, plan_node_t *plan_node);
status_t sql_execute_nest_loop(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof);
status_t sql_fetch_nest_loop(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof);
status_t sql_execute_nest_loop_left(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof);
status_t sql_fetch_nest_loop_left(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof);
status_t sql_execute_nest_loop_full(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan_node, bool32 *eof);
status_t sql_execute_nest_loop_batch(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof);
status_t sql_fetch_nest_loop_batch(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof);
status_t sql_fetch_nest_loop_full_rowid_mtrl(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof);
status_t sql_fetch_nest_loop_full_normal(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof);

static inline status_t sql_fetch_nest_loop_full(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof)
{
    if (plan->join_p.nl_full_opt_type == NL_FULL_ROWID_MTRL) {
        return sql_fetch_nest_loop_full_rowid_mtrl(stmt, cursor, plan, eof);
    }
    return sql_fetch_nest_loop_full_normal(stmt, cursor, plan, eof);
}

#endif