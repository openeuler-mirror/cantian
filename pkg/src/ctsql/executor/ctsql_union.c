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
 * ctsql_union.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/executor/ctsql_union.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_union.h"
#include "ctsql_select.h"
#include "ctsql_mtrl.h"
#include "ctsql_sort.h"
#include "ctsql_group.h"
#include "ctsql_proj.h"
#include "ctsql_distinct.h"
#include "srv_instance.h"

static status_t sql_init_union_all_exec_data(sql_stmt_t *stmt, sql_cursor_t *cur, uint32 exec_id, uint32 pos)
{
    uint32 mem_cost_size;

    if (cur->exec_data.union_all != NULL) {
        cur->exec_data.union_all[exec_id].pos = pos;
        return CT_SUCCESS;
    }

    mem_cost_size = stmt->context->clause_info.union_all_count * sizeof(union_all_data_t);
    CT_RETURN_IFERR(vmc_alloc(&cur->vmc, mem_cost_size, (void **)&cur->exec_data.union_all));

    MEMS_RETURN_IFERR(memset_s((char *)cur->exec_data.union_all, mem_cost_size, 0, mem_cost_size));

    cur->exec_data.union_all[exec_id].pos = pos;
    return CT_SUCCESS;
}

static status_t sql_copy_union_all_exec_data(sql_stmt_t *stmt, sql_cursor_t *cur, union_all_data_t *data)
{
    uint32 mem_cost_size;
    union_all_data_t *union_all = cur->exec_data.union_all;

    if (union_all != NULL) {
        for (uint32 i = 0; i < stmt->context->clause_info.union_all_count; ++i) {
            union_all[i].pos = MAX(union_all[i].pos, data[i].pos);
        }
        return CT_SUCCESS;
    }

    mem_cost_size = stmt->context->clause_info.union_all_count * sizeof(union_all_data_t);
    CT_RETURN_IFERR(vmc_alloc(&cur->vmc, mem_cost_size, (void **)&cur->exec_data.union_all));

    if (mem_cost_size != 0) {
        MEMS_RETURN_IFERR(memcpy_s((char *)cur->exec_data.union_all, mem_cost_size, data, mem_cost_size));
    }
    return CT_SUCCESS;
}

static inline status_t sql_save_varea(sql_stmt_t *stmt, sql_cursor_t *cur, char **union_all_data_buf,
    limit_data_t **limit_data, char **pending_rs_types)
{
    uint32 mem_cost;

    mem_cost = sizeof(union_all_data_t) * stmt->context->clause_info.union_all_count;
    CT_RETURN_IFERR(sql_push(stmt, mem_cost, (void **)union_all_data_buf));

    if (mem_cost != 0) {
        MEMS_RETURN_IFERR(memcpy_s(*union_all_data_buf, mem_cost, (char *)cur->exec_data.union_all, mem_cost));
    }

    if (cur->exec_data.select_limit != NULL) {
        CT_RETURN_IFERR(sql_push(stmt, sizeof(limit_data_t), (void **)limit_data));
        **limit_data = *cur->exec_data.select_limit;
    }

    if (cur->mtrl.rs.buf != NULL) {
        mem_cost = *(uint32 *)cur->mtrl.rs.buf;
        CT_RETURN_IFERR(sql_push(stmt, mem_cost, (void **)pending_rs_types));
        MEMS_RETURN_IFERR(memcpy_s(*pending_rs_types, mem_cost, cur->mtrl.rs.buf, mem_cost));
    }

    return CT_SUCCESS;
}

static inline status_t sql_restore_varea(sql_stmt_t *stmt, sql_cursor_t *cur, char *union_all_data_buf,
    limit_data_t *limit_data, const char *pending_rs_types)
{
    uint32 mem_cost;

    // sql_execute_select_plan->open cursor->close cursor: free union_all varea, so need to copy the varea here
    CT_RETURN_IFERR(sql_copy_union_all_exec_data(stmt, cur, (union_all_data_t *)union_all_data_buf));

    if (limit_data != NULL && cur->exec_data.select_limit == NULL) {
        CT_RETURN_IFERR(vmc_alloc(&cur->vmc, sizeof(limit_data_t), (void **)&cur->exec_data.select_limit));
        *cur->exec_data.select_limit = *limit_data;
    }

    if (pending_rs_types != NULL) {
        mem_cost = *(uint32 *)pending_rs_types;
        CT_RETURN_IFERR(vmc_alloc(&cur->vmc, mem_cost, (void **)&cur->mtrl.rs.buf));
        MEMS_RETURN_IFERR(memcpy_s(cur->mtrl.rs.buf, mem_cost, pending_rs_types, mem_cost));
    }

    return CT_SUCCESS;
}

static inline status_t sql_reverify_union_columns(sql_stmt_t *stmt, sql_cursor_t *cur)
{
    rs_column_t *rs_col = NULL;
    expr_node_t *node = NULL;
    variant_t value;

    if (stmt->context->params == NULL || stmt->context->params->count == 0) {
        return CT_SUCCESS;
    }

    for (uint32 i = 0; i < cur->columns->count; i++) {
        rs_col = (rs_column_t *)cm_galist_get(cur->columns, i);
        if (rs_col->type != RS_COL_CALC || rs_col->expr == NULL) {
            continue;
        }

        node = rs_col->expr->root;
        if (node->type != EXPR_NODE_PARAM) {
            continue;
        }
        if (sql_get_param_value(stmt, VALUE(int32, &node->value), &value) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (CT_IS_LOB_TYPE(value.type)) {
            CT_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "unexpected lob column occurs");
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

static status_t sql_execute_union_all_left(sql_stmt_t *stmt, sql_cursor_t *cur, plan_node_t *plan)
{
    char *union_all_data_buf = NULL;
    limit_data_t *limit_data = NULL;
    char *pending_rs_types = NULL;
    cur->eof = CT_FALSE;

    CTSQL_SAVE_STACK(stmt);
    if (sql_save_varea(stmt, cur, &union_all_data_buf, &limit_data, &pending_rs_types) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }

    if (sql_execute_select_plan(stmt, cur, plan) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }

    if (sql_restore_varea(stmt, cur, union_all_data_buf, limit_data, pending_rs_types) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }

    CTSQL_RESTORE_STACK(stmt);

    return CT_SUCCESS;
}

status_t sql_execute_union_all(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    union_all_data_t *exec_data = NULL;
    plan_node_t *child_plan = NULL;
    uint32 pos = 0;

    child_plan = (plan_node_t *)cm_galist_get(plan->set_p.list, pos);
    CT_RETURN_IFERR(sql_execute_select_plan(stmt, cursor, child_plan));
    CT_RETURN_IFERR(sql_init_union_all_exec_data(stmt, cursor, plan->set_p.union_all_p.exec_id, pos));

    if (!cursor->eof) {
        return CT_SUCCESS;
    }
    while (pos < plan->set_p.list->count - 1) {
        /* execute left part of union all */
        pos++;
        /* update pos to do union all */
        exec_data = &cursor->exec_data.union_all[plan->set_p.union_all_p.exec_id];
        exec_data->pos = pos;

        child_plan = (plan_node_t *)cm_galist_get(plan->set_p.list, pos);
        CT_RETURN_IFERR(sql_execute_union_all_left(stmt, cursor, child_plan));

        if (!cursor->eof) {
            break;
        }
    }

    return CT_SUCCESS;
}

status_t sql_fetch_union_all(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof)
{
    union_all_data_t *exec_data = &cursor->exec_data.union_all[plan->set_p.union_all_p.exec_id];
    plan_node_t *child_plan = NULL;
    uint32 pos = exec_data->pos;

    /* fetch record from current part of union all */
    child_plan = (plan_node_t *)cm_galist_get(plan->set_p.list, pos);
    CT_RETURN_IFERR(sql_fetch_cursor(stmt, cursor, child_plan, &cursor->eof));

    if (!cursor->eof) {
        *eof = CT_FALSE;
        return CT_SUCCESS;
    }
    while (pos < plan->set_p.list->count - 1) {
        /* fetch record from left part of union all */
        pos++;
        /* update pos to do union all */
        exec_data = &cursor->exec_data.union_all[plan->set_p.union_all_p.exec_id];
        exec_data->pos = pos;

        child_plan = (plan_node_t *)cm_galist_get(plan->set_p.list, pos);
        CT_RETURN_IFERR(sql_execute_union_all_left(stmt, cursor, child_plan));
        CT_RETURN_IFERR(sql_fetch_cursor(stmt, cursor, child_plan, &cursor->eof));

        if (!cursor->eof) {
            break;
        }
    }

    *eof = cursor->eof;
    return CT_SUCCESS;
}

static inline status_t sql_execute_hash_union_init_rscol_datatype(sql_stmt_t *stmt, char **rs_buf_new,
    const char *rs_buf)
{
    if (rs_buf == NULL) {
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(vmc_alloc(&stmt->vmc, *(uint32 *)rs_buf, (void **)rs_buf_new));

    MEMS_RETURN_IFERR(memcpy_s(*rs_buf_new, *(uint32 *)rs_buf, rs_buf, *(uint32 *)rs_buf));

    return CT_SUCCESS;
}

status_t sql_execute_hash_union(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    set_plan_t *set_p = &plan->set_p;
    sql_open_select_cursor(stmt, cursor, set_p->union_p.rs_columns);

    CT_RETURN_IFERR(mtrl_create_segment(&stmt->mtrl, MTRL_SEGMENT_DISTINCT, NULL, &cursor->mtrl.distinct));
    CT_RETURN_IFERR(sql_alloc_distinct_ctx(stmt, cursor, plan, HASH_UNION));
    cursor->mtrl.cursor.distinct.eof = CT_FALSE;

    CT_RETURN_IFERR(sql_alloc_cursor(stmt, &cursor->right_cursor));
    CT_RETURN_IFERR(sql_alloc_cursor(stmt, &cursor->left_cursor));
    cursor->right_cursor->ancestor_ref = cursor->ancestor_ref;
    cursor->left_cursor->ancestor_ref = cursor->ancestor_ref;
    CT_RETURN_IFERR(sql_execute_select_plan(stmt, cursor->right_cursor, plan->set_p.right));
    CT_RETURN_IFERR(sql_reverify_union_columns(stmt, cursor->right_cursor));
    if (cursor->right_cursor->eof) {
        CT_RETURN_IFERR(sql_execute_select_plan(stmt, cursor->left_cursor, plan->set_p.left));
        CT_RETURN_IFERR(sql_reverify_union_columns(stmt, cursor->left_cursor));
        CT_RETURN_IFERR(
            sql_execute_hash_union_init_rscol_datatype(stmt, &cursor->mtrl.rs.buf, cursor->left_cursor->mtrl.rs.buf));
    } else {
        CT_RETURN_IFERR(
            sql_execute_hash_union_init_rscol_datatype(stmt, &cursor->mtrl.rs.buf, cursor->right_cursor->mtrl.rs.buf));
    }

    return CT_SUCCESS;
}

static status_t sql_fetch_hash_union_one_record(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof)
{
    if (!cursor->right_cursor->eof) {
        CT_RETURN_IFERR(SQL_CURSOR_PUSH(stmt, cursor->right_cursor));
        CT_RETURN_IFERR(sql_fetch_cursor(stmt, cursor->right_cursor, plan->set_p.right, &cursor->right_cursor->eof));
        SQL_CURSOR_POP(stmt);

        if (cursor->right_cursor->eof) {
            CT_RETURN_IFERR(sql_execute_select_plan(stmt, cursor->left_cursor, plan->set_p.left));
            CT_RETURN_IFERR(sql_reverify_union_columns(stmt, cursor->left_cursor));
        }
        *eof = cursor->right_cursor->eof;
    }

    if (cursor->right_cursor->eof) {
        CT_RETURN_IFERR(SQL_CURSOR_PUSH(stmt, cursor->left_cursor));
        CT_RETURN_IFERR(sql_fetch_cursor(stmt, cursor->left_cursor, plan->set_p.left, &cursor->left_cursor->eof));
        SQL_CURSOR_POP(stmt);

        *eof = cursor->left_cursor->eof;
    }

    return CT_SUCCESS;
}

status_t sql_fetch_hash_union(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof)
{
    bool32 exist_row = CT_FALSE;
    char *buf = NULL;
    hash_segment_t *hash_segment = NULL;
    hash_table_entry_t *hash_table_entry = NULL;

    if (cursor->eof) {
        *eof = CT_TRUE;
        cursor->mtrl.cursor.distinct.eof = CT_TRUE;
        cursor->mtrl.cursor.type = MTRL_CURSOR_HASH_DISTINCT;
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(sql_push(stmt, CT_MAX_ROW_SIZE, (void **)&buf));

    for (;;) {
        CTSQL_SAVE_STACK(stmt);
        CT_RETURN_IFERR(sql_fetch_hash_union_one_record(stmt, cursor, plan, eof));

        if (*eof) {
            CTSQL_RESTORE_STACK(stmt);
            CTSQL_POP(stmt);
            cursor->mtrl.cursor.distinct.eof = CT_TRUE;
            cursor->mtrl.cursor.type = MTRL_CURSOR_HASH_DISTINCT;
            return CT_SUCCESS;
        }

        if (!cursor->right_cursor->eof) {
            CT_RETURN_IFERR(SQL_CURSOR_PUSH(stmt, cursor->right_cursor));
            CT_RETURN_IFERR(sql_make_mtrl_rs_row(stmt, cursor->mtrl.rs.buf, cursor->right_cursor->columns, buf));
            SQL_CURSOR_POP(stmt);
        } else {
            CT_RETURN_IFERR(SQL_CURSOR_PUSH(stmt, cursor->left_cursor));
            CT_RETURN_IFERR(sql_make_mtrl_rs_row(stmt, cursor->mtrl.rs.buf, cursor->left_cursor->columns, buf));
            SQL_CURSOR_POP(stmt);
        }

        hash_segment = &cursor->distinct_ctx->hash_segment;
        hash_table_entry = &cursor->distinct_ctx->hash_table_entry;
        CT_RETURN_IFERR(
            vm_hash_table_insert2(&exist_row, hash_segment, hash_table_entry, buf, ((row_head_t *)buf)->size));
        CTSQL_RESTORE_STACK(stmt);

        if (!exist_row) {
            break;
        }
    }

    CTSQL_POP(stmt);
    return CT_SUCCESS;
}
