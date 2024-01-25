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
 * ctsql_nl_join.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/executor/ctsql_nl_join.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_nl_join.h"
#include "ctsql_join_comm.h"
#include "ctsql_select.h"
#include "ctsql_scan.h"
#include "ctsql_concate.h"
#include "ctsql_mtrl.h"


static status_t sql_fetch_nest_loop_comm(sql_stmt_t *stmt, sql_cursor_t *sql_cursor, plan_node_t *plan, bool32 *eof)
{
    switch (plan->type) {
        case PLAN_NODE_JOIN:
            return sql_fetch_join(stmt, sql_cursor, plan, eof);

        case PLAN_NODE_SCAN:
            sql_cursor->last_table = plan->scan_p.table->plan_id;
            return sql_fetch_scan(stmt, sql_cursor, plan, eof);

        case PLAN_NODE_CONCATE:
            return sql_fetch_concate(stmt, sql_cursor, plan, eof);

        case PLAN_NODE_REMOTE_SCAN:
        default:
            knl_panic(0);
	    return CT_ERROR;
    }
}

static status_t sql_fetch_nest_loop_full_comm(sql_stmt_t *stmt, sql_cursor_t *sql_cursor, plan_node_t *plan,
                                              bool32 *eof)
{
    switch (plan->type) {
        case PLAN_NODE_JOIN:
            return sql_fetch_join(stmt, sql_cursor, plan, eof);

        case PLAN_NODE_REMOTE_SCAN:
	    knl_panic(0);
	    return CT_ERROR;

        case PLAN_NODE_CONCATE:
            return sql_fetch_concate(stmt, sql_cursor, plan, eof);

        default:
            return sql_fetch_scan(stmt, sql_cursor, plan, eof);
    }
}

status_t sql_prepare_nest_loop(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof)
{
    bool32 r_eof = CT_FALSE;
    for (;;) {
        CT_RETURN_IFERR(sql_fetch_nest_loop_comm(stmt, cursor, plan->join_p.left, eof));
        if (*eof) {
            /* need end the cursor fetch of t2 when t1 is eof */
            sql_end_plan_cursor_fetch(cursor, plan->join_p.right);
            cursor->last_table = CT_INVALID_ID32;
            return CT_SUCCESS;
        }

        if (plan->join_p.right->type == PLAN_NODE_JOIN) {
            CT_RETURN_IFERR(sql_execute_join(stmt, cursor, plan->join_p.right, &r_eof));

            if (r_eof) {
                continue;
            }

            return CT_SUCCESS;
        }

        return sql_execute_query_plan(stmt, cursor, plan->join_p.right);
    }
}

status_t sql_execute_nest_loop(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof)
{
    *eof = CT_FALSE;
    cond_tree_t *old_cond = NULL;
    bool32 need_restore = CT_FALSE;
    inner_join_data_t *plan_exec_data = &cursor->exec_data.inner_join[plan->join_p.exec_data_index];

    if (plan->join_p.left->type == PLAN_NODE_JOIN) {
        CT_RETURN_IFERR(sql_execute_join(stmt, cursor, plan->join_p.left, eof));
        if (*eof) {
            /* need end the cursor fetch of t2 when t1 is eof */
            sql_end_plan_cursor_fetch(cursor, plan->join_p.right);
            cursor->last_table = CT_INVALID_ID32;
            return CT_SUCCESS;
        }
    } else {
        CT_RETURN_IFERR(sql_execute_query_plan(stmt, cursor, plan->join_p.left));
    }

    sql_try_save_cursor_cond(cursor, plan->join_p.filter, &old_cond, &need_restore);

    CT_RETURN_IFERR(sql_prepare_nest_loop(stmt, cursor, plan, eof));
    plan_exec_data->right_fetched = CT_FALSE;

    sql_try_restore_cursor_cond(cursor, old_cond, need_restore);
    return CT_SUCCESS;
}

static inline status_t sql_init_nl_batch_data(sql_stmt_t *stmt, sql_cursor_t *cursor, uint32 id)
{
    sql_cursor_t *cache_cur = cursor->exec_data.nl_batch[id].cache_cur;
    if (cache_cur == NULL) {
        CT_RETURN_IFERR(sql_alloc_cursor(stmt, &cache_cur));
        cursor->exec_data.nl_batch[id].cache_cur = cache_cur;
    }
    cache_cur->is_open = CT_TRUE;
    return CT_SUCCESS;
}

static inline void sql_make_vm_rowid_row(sql_table_cursor_t *tab_cursor, char *buf)
{
    row_assist_t ra;
    row_init(&ra, buf, CT_MAX_ROW_SIZE, 1);
    *(rowid_t *)(ra.buf + ra.head->size) = tab_cursor->knl_cur->rowid;
    ra.head->size += KNL_ROWID_LEN;
}

static status_t sql_prepare_batch_rowid(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof)
{
    char *buf = NULL;
    mtrl_rowid_t mtrl_rid;
    uint32 row_count = 0;
    sql_table_cursor_t *tab_cursor = &cursor->tables[plan->join_p.cache_tab->id];
    nl_batch_data_t *exec_data = &cursor->exec_data.nl_batch[plan->join_p.nl_pos];

    sql_reset_mtrl(stmt, exec_data->cache_cur);
    CT_RETURN_IFERR(mtrl_create_segment(&stmt->mtrl, MTRL_SEGMENT_RS, NULL, &exec_data->cache_cur->mtrl.rs.sid));
    CT_RETURN_IFERR(mtrl_open_segment(&stmt->mtrl, exec_data->cache_cur->mtrl.rs.sid));

    CT_RETURN_IFERR(sql_push(stmt, CT_MAX_ROW_SIZE, (void **)&buf));
    CTSQL_SAVE_STACK(stmt);

    for (;;) {
        CT_RETURN_IFERR(sql_fetch_nest_loop(stmt, cursor, plan, &exec_data->last_batch));
        if (exec_data->last_batch) {
            break;
        }

        sql_make_vm_rowid_row(tab_cursor, buf);
        CT_RETURN_IFERR(mtrl_insert_row(&stmt->mtrl, exec_data->cache_cur->mtrl.rs.sid, buf, &mtrl_rid));
        if (++row_count >= NEST_LOOP_BATCH_SIZE) {
            break;
        }
        CTSQL_RESTORE_STACK(stmt);
    }
    *eof = (row_count == 0);
    tab_cursor->knl_cur->eof = CT_FALSE;
    CTSQL_RESTORE_STACK(stmt);
    CTSQL_POP(stmt);
    mtrl_close_segment(&stmt->mtrl, exec_data->cache_cur->mtrl.rs.sid);
    return mtrl_open_rs_cursor(&stmt->mtrl, exec_data->cache_cur->mtrl.rs.sid, &exec_data->cache_cur->mtrl.cursor);
}

status_t sql_execute_nest_loop_batch(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof)
{
    CT_RETURN_IFERR(sql_init_nl_batch_data(stmt, cursor, plan->join_p.nl_pos));
    CT_RETURN_IFERR(sql_execute_nest_loop(stmt, cursor, plan, eof));
    if (*eof) {
        return CT_SUCCESS;
    }
    return sql_prepare_batch_rowid(stmt, cursor, plan, eof);
}

status_t sql_fetch_nest_loop(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof)
{
    bool32 r_eof = CT_FALSE;
    bool32 result = CT_FALSE;
    cond_tree_t *save_cond = NULL;
    bool32 need_restore = CT_FALSE;
    inner_join_data_t *plan_exec_data = &cursor->exec_data.inner_join[plan->join_p.exec_data_index];

    sql_try_save_cursor_cond(cursor, plan->join_p.filter, &save_cond, &need_restore);
    for (;;) {
        CT_RETURN_IFERR(sql_fetch_nest_loop_comm(stmt, cursor, plan->join_p.right, &r_eof));
        if (r_eof) {
            if (plan->join_p.r_eof_flag && !plan_exec_data->right_fetched) {
                *eof = CT_TRUE;
                /* need end the cursor fetch of t2 when t1 is eof */
                sql_end_plan_cursor_fetch(cursor, plan->join_p.right);
                cursor->last_table = CT_INVALID_ID32;
            } else {
                CT_RETURN_IFERR(sql_prepare_nest_loop(stmt, cursor, plan, eof));
                plan_exec_data->right_fetched = CT_FALSE;
            }

            if (*eof) {
                sql_try_restore_cursor_cond(cursor, save_cond, need_restore);
                return CT_SUCCESS;
            }
            continue;
        } else {
            plan_exec_data->right_fetched = CT_TRUE;
            CT_RETURN_IFERR(match_nl_join_final_cond(stmt, save_cond, plan->join_p.filter, &result));
            if (!result) {
                continue;
            }
            *eof = CT_FALSE;
        }
        sql_try_restore_cursor_cond(cursor, save_cond, need_restore);
        return CT_SUCCESS;
    }
}

static inline status_t sql_fetch_vm_rowid(sql_stmt_t *stmt, sql_cursor_t *cursor, rowid_t *rowid)
{
    CT_RETURN_IFERR(mtrl_fetch_rs(&stmt->mtrl, &cursor->mtrl.cursor, CT_FALSE));
    if (cursor->mtrl.cursor.eof) {
        return CT_SUCCESS;
    }
    char *row = cursor->mtrl.cursor.row.data;
    uint32 row_size = ((row_head_t *)row)->size;
    *rowid = *(rowid_t *)(row + row_size - KNL_ROWID_LEN);
    return CT_SUCCESS;
}

status_t sql_fetch_nest_loop_batch(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof)
{
    sql_table_cursor_t *tab_cursor = &cursor->tables[plan->join_p.cache_tab->id];
    nl_batch_data_t *exec_data = &cursor->exec_data.nl_batch[plan->join_p.nl_pos];

    for (;;) {
        CT_RETURN_IFERR(sql_fetch_vm_rowid(stmt, exec_data->cache_cur, &tab_cursor->knl_cur->rowid));
        if (!exec_data->cache_cur->mtrl.cursor.eof) {
            return CT_SUCCESS;
        }

        if (exec_data->last_batch) {
            *eof = CT_TRUE;
            return CT_SUCCESS;
        }

        CT_RETURN_IFERR(sql_prepare_batch_rowid(stmt, cursor, plan, eof));
        if (*eof) {
            return CT_SUCCESS;
        }
    }
}

static inline void sql_init_cursor_part_info(sql_table_cursor_t *tab_cursor)
{
    tab_cursor->curr_part.left = 0;
    tab_cursor->curr_part.right = 0;
    tab_cursor->curr_part.sub_scan_key = NULL;
    tab_cursor->curr_subpart.left = 0;
    tab_cursor->curr_subpart.right = 0;
    tab_cursor->part_set.key_data = NULL;
}

void release_nl_full_opt_resource(sql_cursor_t *cursor, join_plan_t *join_plan)
{
    if (join_plan->oper == JOIN_OPER_NL_FULL && join_plan->nl_full_opt_type == NL_FULL_ROWID_MTRL) {
        outer_join_data_t *plan_exec_data = &cursor->exec_data.outer_join[join_plan->exec_data_index];
        if (plan_exec_data->nl_full_opt_ctx != NULL) {
            sql_free_nl_full_opt_ctx(plan_exec_data->nl_full_opt_ctx);
        }
    }
}

// "select t1.f1, t2.f1 from t1 left join t2", when t2 is fetch over, should end all cursors from t2 part
void sql_end_plan_cursor_fetch(sql_cursor_t *cursor, plan_node_t *plan_node)
{
    sql_table_t *table = NULL;
    plan_node_t *child = NULL;
    sql_table_cursor_t *tab_cursor = NULL;

    switch (plan_node->type) {
        case PLAN_NODE_JOIN:
            sql_end_plan_cursor_fetch(cursor, plan_node->join_p.left);
            sql_end_plan_cursor_fetch(cursor, plan_node->join_p.right);
            release_nl_full_opt_resource(cursor, &plan_node->join_p);
            break;

        case PLAN_NODE_REMOTE_SCAN:
	    knl_panic(0);
            break;

        case PLAN_NODE_CONCATE:
            /* All the plans in list are equivalent at the table level. */
            child = (plan_node_t *)cm_galist_get(plan_node->cnct_p.plans, 0);
            sql_end_plan_cursor_fetch(cursor, child);
            break;

        default:
            table = plan_node->scan_p.table;
            tab_cursor = &cursor->tables[table->id];
            switch (table->type) {
                case JSON_TABLE:
                    sql_release_json_table(tab_cursor);
                    break;
                case NORMAL_TABLE:
                case FUNC_AS_TABLE:
                    tab_cursor->knl_cur->eof = CT_TRUE;
                    tab_cursor->knl_cur->scan_mode = 0;
                    sql_free_varea_set(tab_cursor);
                    sql_init_cursor_part_info(tab_cursor);
                    break;
                default:
                    tab_cursor->sql_cur->eof = CT_TRUE;
                    break;
            }
    }
}

status_t sql_execute_nest_loop_left(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof)
{
    outer_join_data_t *plan_exec_data = &cursor->exec_data.outer_join[plan->join_p.exec_data_index];

    plan_exec_data->need_reset_right = CT_TRUE;
    plan_exec_data->right_matched = CT_FALSE;

    *eof = CT_FALSE;

    if (plan->join_p.left->type == PLAN_NODE_JOIN) {
        CT_RETURN_IFERR(sql_execute_join(stmt, cursor, plan->join_p.left, eof));
        if (*eof) {
            sql_end_plan_cursor_fetch(cursor, plan->join_p.right);
            cursor->last_table = CT_INVALID_ID32;
        }
        return CT_SUCCESS;
    }
    return sql_execute_query_plan(stmt, cursor, plan->join_p.left);
}

static status_t sql_prepare_nest_loop_left(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof,
    bool32 *r_eof)
{
    CT_RETURN_IFERR(sql_fetch_nest_loop_comm(stmt, cursor, plan->join_p.left, eof));
    if (*eof) {
        /* need end the cursor fetch of t2 when t1 is eof */
        sql_end_plan_cursor_fetch(cursor, plan->join_p.right);
        cursor->last_table = CT_INVALID_ID32;
        return CT_SUCCESS;
    }

    if (plan->join_p.right->type == PLAN_NODE_JOIN) {
        CT_RETURN_IFERR(sql_execute_join(stmt, cursor, plan->join_p.right, r_eof));
    } else {
        CT_RETURN_IFERR(sql_execute_query_plan(stmt, cursor, plan->join_p.right));
    }

    outer_join_data_t *plan_exec_data = &cursor->exec_data.outer_join[plan->join_p.exec_data_index];
    plan_exec_data->need_reset_right = CT_FALSE;
    plan_exec_data->right_matched = CT_FALSE;
    return CT_SUCCESS;
}

status_t sql_fetch_nest_loop_left(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof)
{
    outer_join_data_t *plan_exec_data = &cursor->exec_data.outer_join[plan->join_p.exec_data_index];
    bool32 r_eof = CT_FALSE;
    bool32 result = CT_FALSE;
    cond_tree_t *save_cond = NULL;
    uint32 last_table = get_last_table_id(plan);

    sql_save_cursor_cond(cursor, plan->join_p.filter, &save_cond);

    for (;;) {
        r_eof = CT_FALSE;

        if (plan_exec_data->need_reset_right) {
            CT_RETURN_IFERR(sql_prepare_nest_loop_left(stmt, cursor, plan, eof, &r_eof));
            if (*eof) {
                sql_restore_cursor_cond(cursor, save_cond);
                return CT_SUCCESS;
            }
        }

        if (!r_eof) {
            CT_RETURN_IFERR(sql_fetch_nest_loop_comm(stmt, cursor, plan->join_p.right, &r_eof));
        }

        if (r_eof) {
            /* need end cursor t1 fetch when cursor t2 is eof because result set may get column value from t1
               cursor->last_table is unless and should set to CT_INVALID_ID32 */
            sql_end_plan_cursor_fetch(cursor, plan->join_p.right);
            cursor->last_table = last_table;

            plan_exec_data->need_reset_right = CT_TRUE;
            if (plan_exec_data->right_matched) {
                continue;
            }
        } else {
            CT_RETURN_IFERR(sql_match_cond_node(stmt, plan->join_p.cond->root, &result));
            if (!result) {
                continue;
            }

            plan_exec_data->right_matched = CT_TRUE;
        }

        CT_RETURN_IFERR(match_nl_join_final_cond(stmt, save_cond, plan->join_p.filter, &result));
        if (!result) {
            continue;
        }
        *eof = CT_FALSE;
        sql_restore_cursor_cond(cursor, save_cond);
        return CT_SUCCESS;
    }
}

void reset_cursor_tables(sql_cursor_t *cursor, plan_node_t *plan_node)
{
    if (plan_node->type != PLAN_NODE_SCAN) {
        reset_cursor_tables(cursor, plan_node->join_p.left);
        reset_cursor_tables(cursor, plan_node->join_p.right);
        return;
    }
    sql_table_cursor_t *table_cur = &cursor->tables[plan_node->scan_p.table->id];
    table_cur->table = plan_node->scan_p.table;
}

status_t sql_execute_nest_loop_full_right(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan_node, bool32 *eof)
{
    outer_join_data_t *plan_exec_data = &cursor->exec_data.outer_join[plan_node->join_p.exec_data_index];

    plan_exec_data->need_reset_right = CT_TRUE;
    plan_exec_data->right_matched = CT_FALSE;
    plan_exec_data->need_swap_driver = CT_TRUE;
    *eof = CT_FALSE;

    cond_tree_t *save_cond = NULL;

    switch (plan_node->join_p.nl_full_opt_type) {
        case NL_FULL_ROWID_MTRL:
            plan_exec_data->right_plan = plan_node->join_p.r_drive_plan;
            plan_exec_data->left_plan = NULL;
            break;
        case NL_FULL_DUPL_DRIVE:
            plan_exec_data->right_plan = plan_node->join_p.r_drive_plan->join_p.left;
            plan_exec_data->left_plan = plan_node->join_p.r_drive_plan->join_p.right;
            plan_exec_data->filter = plan_node->join_p.r_drive_plan->join_p.filter;
            plan_exec_data->cond = plan_node->join_p.r_drive_plan->join_p.cond;
            reset_cursor_tables(cursor, plan_node->join_p.r_drive_plan);
            break;
        case NL_FULL_OPT_NONE:
        default:
            plan_exec_data->right_plan = plan_node->join_p.right;
            plan_exec_data->left_plan = plan_node->join_p.left;
            plan_exec_data->filter = plan_node->join_p.filter;
            plan_exec_data->cond = plan_node->join_p.cond;
    }
    sql_save_cursor_cond(cursor, plan_node->join_p.filter, &save_cond);

    if (plan_exec_data->right_plan->type == PLAN_NODE_JOIN) {
        CT_RETURN_IFERR(sql_execute_join(stmt, cursor, plan_exec_data->right_plan, eof));
    } else {
        CT_RETURN_IFERR(sql_execute_query_plan(stmt, cursor, plan_exec_data->right_plan));
    }
    sql_restore_cursor_cond(cursor, save_cond);
    return CT_SUCCESS;
}

status_t sql_execute_nest_loop_full_normal(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan_node, bool32 *eof)
{
    outer_join_data_t *plan_exec_data = &cursor->exec_data.outer_join[plan_node->join_p.exec_data_index];

    plan_exec_data->need_swap_driver = CT_FALSE;
    *eof = CT_FALSE;

    if (plan_node->join_p.nl_full_opt_type == NL_FULL_DUPL_DRIVE) {
        reset_cursor_tables(cursor, plan_node);
    }

    // t1 full join t2, execute t1 left join t2
    CT_RETURN_IFERR(sql_execute_nest_loop_left(stmt, cursor, plan_node, eof));

    // if t1 left join t2 is eof, begin to execute t2 left join t1
    if (*eof) {
        CT_RETURN_IFERR(sql_execute_nest_loop_full_right(stmt, cursor, plan_node, eof));
    }
    return CT_SUCCESS;
}

status_t sql_execute_nest_loop_full_rowid_mtrl(sql_stmt_t *stmt, sql_cursor_t *cursor,
                                               plan_node_t *plan_node, bool32 *eof)
{
    outer_join_data_t *plan_exec_data = &cursor->exec_data.outer_join[plan_node->join_p.exec_data_index];
    nl_full_opt_ctx_t *opt_context = plan_exec_data->nl_full_opt_ctx;

    plan_exec_data->need_swap_driver = CT_FALSE;
    *eof = CT_FALSE;

    if (SECUREC_UNLIKELY(cursor->nl_full_ctx_list == NULL)) {
        CT_RETURN_IFERR(vmc_alloc(&cursor->vmc, sizeof(galist_t), (void **)&cursor->nl_full_ctx_list));
        cm_galist_init(cursor->nl_full_ctx_list, &cursor->vmc, vmc_alloc);
    }
    if (opt_context == NULL) {
        CT_RETURN_IFERR(vmc_alloc_mem(&cursor->vmc, sizeof(nl_full_opt_ctx_t), (void **)&opt_context));
        CT_RETURN_IFERR(cm_galist_insert(cursor->nl_full_ctx_list, (void *)opt_context));
    } else {
        sql_free_nl_full_opt_ctx(opt_context);
    }
    opt_context->id = plan_node->join_p.nl_full_mtrl_pos;
    vm_hash_segment_init((handle_t)&stmt->session->knl_session, stmt->mtrl.pool, &opt_context->hash_seg, PMA_POOL,
        HASH_PAGES_HOLD, HASH_AREA_SIZE);
    CT_RETURN_IFERR(vm_hash_table_alloc(&opt_context->hash_table_entry,
                                        &opt_context->hash_seg, plan_node->join_p.right->rows));
    CT_RETURN_IFERR(vm_hash_table_init(&opt_context->hash_seg, &opt_context->hash_table_entry, NULL, NULL, cursor));
    sql_init_hash_iter(&opt_context->iter, NULL);
    plan_exec_data->nl_full_opt_ctx = opt_context;

    // t1 full join t2, execute t1 left join t2
    CT_RETURN_IFERR(sql_execute_nest_loop_left(stmt, cursor, plan_node, eof));
    plan_exec_data->left_empty = *eof;

    // if t1 left join t2 is eof, begin to execute t2 left join t1
    if (*eof) {
        sql_end_plan_cursor_fetch(cursor, plan_node->join_p.left);
        return sql_execute_nest_loop_full_right(stmt, cursor, plan_node, eof);
    }
    return CT_SUCCESS;
}

status_t sql_execute_nest_loop_full(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan_node, bool32 *eof)
{
    if (plan_node->join_p.nl_full_opt_type == NL_FULL_ROWID_MTRL) {
        return sql_execute_nest_loop_full_rowid_mtrl(stmt, cursor, plan_node, eof);
    }
    return sql_execute_nest_loop_full_normal(stmt, cursor, plan_node, eof);
}

static status_t sql_prepare_nest_loop_full_right(sql_stmt_t *stmt, sql_cursor_t *cursor,
                                                 plan_node_t *plan_node, bool32 *eof, bool32 *l_eof)
{
    outer_join_data_t *plan_exec_data = &cursor->exec_data.outer_join[plan_node->join_p.exec_data_index];
    CT_RETURN_IFERR(sql_fetch_nest_loop_full_comm(stmt, cursor, plan_exec_data->right_plan, eof));
    if (*eof) {
        return CT_SUCCESS;
    }
    *l_eof = CT_FALSE;

    if (plan_exec_data->left_plan->type == PLAN_NODE_JOIN) {
        CT_RETURN_IFERR(sql_execute_join(stmt, cursor, plan_exec_data->left_plan, l_eof));
    } else {
        CT_RETURN_IFERR(sql_execute_query_plan(stmt, cursor, plan_exec_data->left_plan));
    }

    plan_exec_data->need_reset_right = CT_FALSE;
    plan_exec_data->right_matched = CT_FALSE;
    return CT_SUCCESS;
}

status_t sql_fetch_nest_loop_full_right(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof)
{
    outer_join_data_t *exec_data = &cursor->exec_data.outer_join[plan->join_p.exec_data_index];
    bool32 l_eof = CT_FALSE;
    bool32 result = CT_FALSE;
    cond_tree_t *save_cond = NULL;
    uint32 last_table = get_last_table_id(plan);

    /* execute t1 full join t2, when do t2 left join t1 make sure cursor->last_table is useless.
    by the way, sql_join_cond_down_cond can't operate full join!!!
    */
    cursor->last_table = last_table;
    sql_save_cursor_cond(cursor, plan->join_p.filter, &save_cond);

    for (;;) {
        l_eof = CT_FALSE;

        if (exec_data->need_reset_right) {
            CT_RETURN_IFERR(sql_prepare_nest_loop_full_right(stmt, cursor, plan, eof, &l_eof));
            cursor->last_table = last_table;
            if (*eof) {
                sql_restore_cursor_cond(cursor, save_cond);
                /* need end cursor t1 fetch when cursor t2 is eof because result set may get column value from t1,
                   cursor->last_table is unless and should set to CT_INVALID_ID32 */
                sql_end_plan_cursor_fetch(cursor, exec_data->left_plan);
                return CT_SUCCESS;
            }
        }

        if (!l_eof) {
            CT_RETURN_IFERR(sql_fetch_nest_loop_full_comm(stmt, cursor, exec_data->left_plan, &l_eof));
        }
        cursor->last_table = last_table;

        if (l_eof) {
            exec_data->need_reset_right = CT_TRUE;
            sql_end_plan_cursor_fetch(cursor, exec_data->left_plan);
            if (exec_data->right_matched) {
                continue;
            }
        } else {
            if (exec_data->cond != NULL) {
                CT_RETURN_IFERR(sql_match_cond_node(stmt, exec_data->cond->root, &result));
                if (!result) {
                    continue;
                }
            }

            exec_data->right_matched = CT_TRUE;

            // t1 full join t2, fetch t2 left join t1, ignore the matched row
            exec_data->need_reset_right = CT_TRUE;
            sql_end_plan_cursor_fetch(cursor, exec_data->left_plan);
            continue;
        }

        CT_RETURN_IFERR(match_nl_join_final_cond(stmt, save_cond, exec_data->filter, &result));
        if (!result) {
            continue;
        }

        sql_restore_cursor_cond(cursor, save_cond);
        *eof = CT_FALSE;
        return CT_SUCCESS;
    }
}

status_t sql_fetch_nest_loop_full_normal(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof)
{
    outer_join_data_t *exec_data = &cursor->exec_data.outer_join[plan->join_p.exec_data_index];

    // t1 full join t2, fetch t1 left join t2
    if (!exec_data->need_swap_driver) {
        CT_RETURN_IFERR(sql_fetch_nest_loop_left(stmt, cursor, plan, eof));
        if (!*eof) {
            return CT_SUCCESS;
        }

        // t1 full join t2, t1 left join t2 is done, begin to execute t2 left join t1
        CT_RETURN_IFERR(sql_execute_nest_loop_full_right(stmt, cursor, plan, eof));
        if (*eof) {
            return CT_SUCCESS;
        }
    }

    // t1 full join t2, fetch t2 left join t1
    return sql_fetch_nest_loop_full_right(stmt, cursor, plan, eof);
}

static inline status_t sql_make_rowid_key(sql_stmt_t *stmt, sql_table_cursor_t *tab_cursor, char *row_buf,
    uint32 buffer_len)
{
    char rowid_buf[CT_MAX_ROWID_BUFLEN];
    variant_t v_rowid;
    row_assist_t ra;

    v_rowid.v_text.str = rowid_buf;
    sql_rowid2str(&tab_cursor->knl_cur->rowid, &v_rowid, tab_cursor->table->entry->dc.type);
    row_init(&ra, row_buf, buffer_len, 1);
    return row_put_text(&ra, &v_rowid.v_text);
}

status_t sql_fetch_nest_loop_full_right_by_rowid(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof)
{
    outer_join_data_t *exec_data = &cursor->exec_data.outer_join[plan->join_p.exec_data_index];
    uint32 last_table = get_last_table_id(plan);
    if (SECUREC_UNLIKELY(exec_data->left_empty)) {
        cursor->last_table = last_table;
        return sql_fetch_nest_loop_full_comm(stmt, cursor, plan->join_p.r_drive_plan, eof);
    }

    bool32 found = CT_FALSE;
    sql_table_cursor_t *tab_cursor = &cursor->tables[plan->join_p.r_drive_plan->scan_p.table->id];
    nl_full_opt_ctx_t *opt_ctx = exec_data->nl_full_opt_ctx;
    char row_buf[CT_MAX_ROWID_BUFLEN + sizeof(row_head_t)];
    hash_scan_assist_t scan_assist;

    for (;;) {
        cursor->last_table = last_table;
        if (sql_fetch_nest_loop_full_comm(stmt, cursor, plan->join_p.r_drive_plan, eof) != CT_SUCCESS) {
            return CT_ERROR;
        }
        if (*eof) {
            if (opt_ctx->iter.hash_table != NULL) {
                opt_ctx->iter.hash_table = NULL;
                vm_hash_close_page(&opt_ctx->hash_seg, &opt_ctx->hash_table_entry.page);
            }
            break;
        }
        if (sql_make_rowid_key(stmt, tab_cursor, row_buf, CT_MAX_ROWID_BUFLEN) != CT_SUCCESS) {
            return CT_ERROR;
        }
        sql_init_scan_assist(row_buf, &scan_assist);
        if (vm_hash_table_open(&opt_ctx->hash_seg, &opt_ctx->hash_table_entry, &scan_assist, &found, &opt_ctx->iter) !=
            CT_SUCCESS) {
            return CT_ERROR;
        }
        if (!found) {
            break;
        }
    }
    return CT_SUCCESS;
}

static inline status_t sql_mtrl_nl_full_right_rowid(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan,
    nl_full_opt_ctx_t *opt_ctx)
{
    bool32 found = CT_FALSE;
    char row_buf[CT_MAX_ROWID_BUFLEN + sizeof(row_head_t)];
    sql_table_cursor_t *tab_cursor = &cursor->tables[plan->join_p.right->scan_p.table->id];

    if (sql_make_rowid_key(stmt, tab_cursor, row_buf, CT_MAX_ROWID_BUFLEN) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return vm_hash_table_insert2(&found, &opt_ctx->hash_seg, &opt_ctx->hash_table_entry, row_buf, CT_MAX_ROWID_BUFLEN);
}

status_t sql_fetch_nest_loop_full_rowid_mtrl(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof)
{
    outer_join_data_t *plan_exec_data = &cursor->exec_data.outer_join[plan->join_p.exec_data_index];

    // t1 full join t2, fetch t1 left join t2
    if (!plan_exec_data->need_swap_driver) {
        if (sql_fetch_nest_loop_left(stmt, cursor, plan, eof) != CT_SUCCESS) {
            return CT_ERROR;
        }
        if (!*eof) {
            if (plan_exec_data->right_matched) {
                return sql_mtrl_nl_full_right_rowid(stmt, cursor, plan, plan_exec_data->nl_full_opt_ctx);
            }
            return CT_SUCCESS;
        }
        // t1 full join t2, t1 left join t2 is done, begin to execute t2 left join t1
        sql_end_plan_cursor_fetch(cursor, plan->join_p.left);
        if (sql_execute_nest_loop_full_right(stmt, cursor, plan, eof) != CT_SUCCESS) {
            return CT_ERROR;
        }
        if (*eof) {
            return CT_SUCCESS;
        }
    }

    return sql_fetch_nest_loop_full_right_by_rowid(stmt, cursor, plan, eof);
}
