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
 * ctsql_limit.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/executor/ctsql_limit.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_limit.h"
#include "ctsql_select.h"

status_t sql_convert_limit_num(variant_t *var)
{
    switch (var->type) {
        case CT_TYPE_UINT32:
        case CT_TYPE_INTEGER:
            var->type = CT_TYPE_BIGINT;
            var->v_bigint = (int64)var->v_int;
            return CT_SUCCESS;

        case CT_TYPE_BIGINT:
            return CT_SUCCESS;

        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
        case CT_TYPE_STRING:
            if (cm_text_to_dec(&var->v_text, &var->v_dec) != CT_SUCCESS) {
                return CT_ERROR;
            }

            if (!cm_dec_is_integer(&var->v_dec)) {
                CT_THROW_ERROR(ERR_MUST_BE_FIX_DATATYPE, "number for limit/offset clause", "integer or bigint");
                return CT_ERROR;
            }

            var->type = CT_TYPE_BIGINT;
            return cm_dec_to_int64(&var->v_dec, &var->v_bigint, ROUND_TRUNC);

        case CT_TYPE_REAL:
            if (cm_real_to_dec(var->v_real, &var->v_dec) != CT_SUCCESS) {
                return CT_ERROR;
            }
            // fall-through
        case CT_TYPE_NUMBER:
        case CT_TYPE_DECIMAL:
        case CT_TYPE_NUMBER2:
            if (!cm_dec_is_integer(&var->v_dec)) {
                CT_THROW_ERROR(ERR_MUST_BE_FIX_DATATYPE, "number for limit/offset clause", "integer or bigint");
                return CT_ERROR;
            }

            var->type = CT_TYPE_BIGINT;
            return cm_dec_to_int64(&var->v_dec, &var->v_bigint, ROUND_TRUNC);

        default:
            CT_THROW_ERROR(ERR_MUST_BE_FIX_DATATYPE, "number for limit/offset clause", "integer or bigint");
            return CT_ERROR;
    }
}

static status_t sql_get_limit_value(sql_stmt_t *stmt, plan_node_t *plan, variant_t *limit_count_var,
    variant_t *limit_offset_var)
{
    if (plan->limit.item.offset != NULL) {
        CT_RETURN_IFERR(sql_exec_expr(stmt, (expr_tree_t *)plan->limit.item.offset, limit_offset_var));
        if (limit_offset_var->is_null) {
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "offset must not be null");
            return CT_ERROR;
        }

        CT_RETURN_IFERR(sql_convert_limit_num(limit_offset_var));
        if (limit_offset_var->v_bigint < 0) {
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "offset must not be negative");
            return CT_ERROR;
        }
    }

    if (plan->limit.item.count != NULL) {
        CT_RETURN_IFERR(sql_exec_expr(stmt, (expr_tree_t *)plan->limit.item.count, limit_count_var));
        if (limit_count_var->is_null) {
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "limit must not be null");
            return CT_ERROR;
        }

        CT_RETURN_IFERR(sql_convert_limit_num(limit_count_var));

        if (limit_count_var->v_bigint < 0) {
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "limit must not be negative");
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

static status_t sql_init_limit_exec_data(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan_node,
    limit_data_t **limit_data, bool32 *finished)
{
    variant_t limit_offset_var, limit_count_var;
    CT_RETURN_IFERR(sql_get_limit_value(stmt, plan_node, &limit_count_var, &limit_offset_var));
    if (!plan_node->limit.calc_found_rows && plan_node->limit.item.count != NULL && limit_count_var.v_bigint == 0) {
        cursor->eof = CT_TRUE;
        *finished = CT_TRUE;
        return CT_SUCCESS;
    }
    if (*limit_data == NULL) {
        CT_RETURN_IFERR(vmc_alloc(&cursor->vmc, sizeof(limit_data_t), (void **)limit_data));
    }
    (*limit_data)->fetch_row_count = 0;
    (*limit_data)->limit_offset = 0;
    (*limit_data)->limit_count = CT_INVALID_ID64;

    if (plan_node->limit.item.offset != NULL) {
        (*limit_data)->limit_offset = limit_offset_var.v_bigint;
    }

    if (plan_node->limit.item.count != NULL) {
        (*limit_data)->limit_count = limit_count_var.v_bigint;
    }
    return CT_SUCCESS;
}

status_t sql_execute_select_limit(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    if (cursor->is_open) {
        sql_close_cursor(stmt, cursor);
    }
    bool32 finished = CT_FALSE;
    CT_RETURN_IFERR(sql_init_limit_exec_data(stmt, cursor, plan, &cursor->exec_data.select_limit, &finished));
    if (finished) {
        return CT_SUCCESS;
    }
    return sql_execute_select_plan(stmt, cursor, plan->limit.next);
}

status_t sql_execute_query_limit(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    bool32 finished = CT_FALSE;
    CT_RETURN_IFERR(sql_init_limit_exec_data(stmt, cursor, plan, &cursor->exec_data.query_limit, &finished));
    if (finished) {
        return CT_SUCCESS;
    }
    return sql_execute_query_plan(stmt, cursor, plan->limit.next);
}

status_t sql_fetch_limit(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan_node, bool32 *eof)
{
    limit_data_t **limit_data =
        plan_node->type == PLAN_NODE_SELECT_LIMIT ? &cursor->exec_data.select_limit : &cursor->exec_data.query_limit;
    uint64 limit_offset;

    limit_offset = (*limit_data)->limit_offset;
    for (uint64 i = 0; i < limit_offset; ++i) {
        CTSQL_SAVE_STACK(stmt);
        if (sql_fetch_cursor(stmt, cursor, plan_node->limit.next, eof) != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            return CT_ERROR;
        }
        CTSQL_RESTORE_STACK(stmt);
        if (*eof) {
            return CT_SUCCESS;
        }

        /* calculate the actually skipped row count due to limit offset.
        because for a table with 10 rows, clause "LIMIT 50, 5" will only skip 10 rows */
        if (plan_node->limit.calc_found_rows) {
            cursor->found_rows.offset_skipcount++;
        }
    }

    if (limit_offset > 0) {
        (*limit_data)->limit_offset = 0;
    }

    if ((*limit_data)->fetch_row_count == (*limit_data)->limit_count) {
        if (plan_node->limit.calc_found_rows) {
            bool32 fetch_end = CT_FALSE;

            /* continue to fetch the rest rows to calculate the total rows */
            while (!fetch_end) {
                if (sql_fetch_cursor(stmt, cursor, plan_node->limit.next, &fetch_end) != CT_SUCCESS) {
                    return CT_ERROR;
                }
                if (!fetch_end) {
                    cursor->found_rows.limit_skipcount++;
                }
            }
        }
        *eof = CT_TRUE;
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(sql_fetch_cursor(stmt, cursor, plan_node->limit.next, eof));

    if (*eof) {
        return CT_SUCCESS;
    }

    (*limit_data)->fetch_row_count++;
    return CT_SUCCESS;
}
