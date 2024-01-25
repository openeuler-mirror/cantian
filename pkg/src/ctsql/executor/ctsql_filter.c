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
 * ctsql_filter.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/executor/ctsql_filter.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_filter.h"
#include "ctsql_select.h"

status_t sql_execute_filter(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    if (IS_COND_FALSE(plan->filter.cond)) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }
    return sql_execute_query_plan(stmt, cursor, plan->filter.next);
}

status_t sql_fetch_filter(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof)
{
    if (IS_COND_FALSE(plan->filter.cond)) {
        *eof = CT_TRUE;
        return CT_SUCCESS;
    }
    bool32 is_found = CT_FALSE;

    for (;;) {
        CTSQL_SAVE_STACK(stmt);
        if (sql_fetch_query(stmt, cursor, plan->filter.next, eof) != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            return CT_ERROR;
        }

        if (*eof) {
            CTSQL_RESTORE_STACK(stmt);
            return CT_SUCCESS;
        }
        if (plan->filter.next->type == PLAN_NODE_QUERY_SIBL_SORT) {
            CTSQL_RESTORE_STACK(stmt);
            return CT_SUCCESS;
        }
        if (sql_match_cond_node(stmt, plan->filter.cond->root, &is_found) != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            return CT_ERROR;
        }

        if (is_found) {
            return CT_SUCCESS; // should not invoke CTSQL_RESTORE_STACK
        }
        CTSQL_RESTORE_STACK(stmt);
    }
}
