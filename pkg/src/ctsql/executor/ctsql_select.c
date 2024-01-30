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
 * ctsql_select.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/executor/ctsql_select.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_select.h"
#include "ctsql_mtrl.h"
#include "ctsql_scan.h"
#include "ctsql_aggr.h"
#include "ctsql_sort.h"
#include "ctsql_union.h"
#include "ctsql_proj.h"
#include "ctsql_group.h"
#include "ctsql_sort_group.h"
#include "ctsql_index_group.h"
#include "ctsql_hash_mtrl.h"
#include "ctsql_distinct.h"
#include "ctsql_nl_join.h"
#include "ctsql_limit.h"
#include "ctsql_connect.h"
#include "ctsql_filter.h"
#include "ctsql_minus.h"
#include "ctsql_winsort.h"
#include "ctsql_privilege.h"
#include "../../server/srv_instance.h"
#include "ctsql_concate.h"
#include "ctsql_update.h"
#include "ctsql_group_cube.h"
#include "ctsql_unpivot.h"
#include "ctsql_withas_mtrl.h"
#include "ctsql_connect_mtrl.h"
#include "ctsql_vm_view_mtrl.h"
#include "gdv_context.h"

static inline status_t sql_check_node_pending(sql_cursor_t *parent_cursor, uint32 tab, bool32 *pending)
{
    sql_table_cursor_t *table_cur = &parent_cursor->tables[tab];

    if (parent_cursor->table_count > 1 && table_cur->table->plan_id > parent_cursor->last_table) {
        *pending = CT_TRUE;
    }
    return CT_SUCCESS;
}

#ifdef Z_SHARDING
status_t sql_get_parent_remote_table_id(sql_cursor_t *parent_cursor, uint32 tab_id, uint32 *remote_id)
{
    sql_table_cursor_t *table_cur = NULL;

    // all parent table is distribute_none
    *remote_id = tab_id;
    for (uint32 i = 0; i < parent_cursor->table_count; i++) {
        table_cur = &parent_cursor->tables[i];
        CT_CONTINUE_IFTRUE(table_cur->table == NULL);
        CT_CONTINUE_IFTRUE(table_cur->table->remote_type == distribute_none);
        CT_CONTINUE_IFTRUE(table_cur->table->remote_query == NULL);
        for (uint32 j = 0; j < table_cur->table->remote_query->tables.count; j++) {
            sql_table_t *sql_tab = (sql_table_t *)sql_array_get(&table_cur->table->remote_query->tables, j);
            if (tab_id == sql_tab->id) {
                *remote_id = sql_tab->remote_id;
                return CT_SUCCESS;
            }
        }
    }
    return CT_SUCCESS;
}
#endif

status_t sql_check_sub_select_pending(sql_cursor_t *parent_cursor, sql_select_t *select_context, bool32 *pending)
{
    uint32 table_id;
    parent_ref_t *parent_ref = NULL;

    if (select_context->parent_refs->count == 0) {
        return CT_SUCCESS;
    }

    for (uint32 i = 0; i < select_context->parent_refs->count; i++) {
        parent_ref = (parent_ref_t *)cm_galist_get(select_context->parent_refs, i);
        table_id = parent_ref->tab;
        CT_RETURN_IFERR(sql_check_node_pending(parent_cursor, table_id, pending));
        CT_BREAK_IF_TRUE(*pending);
    }
    return CT_SUCCESS;
}

status_t sql_fetch_cursor(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan_node, bool32 *eof)
{
    status_t status;
    CM_TRACE_BEGIN;
    if (cursor->eof) {
        *eof = CT_TRUE;
        return CT_SUCCESS;
    }
    CT_RETURN_IFERR(sql_stack_safe(stmt));

    switch (plan_node->type) {
        case PLAN_NODE_QUERY:
            status = sql_fetch_query(stmt, cursor, plan_node->query.next, eof);
            break;

        case PLAN_NODE_UNION:
            status = sql_fetch_hash_union(stmt, cursor, plan_node, eof);
            break;

        case PLAN_NODE_UNION_ALL:
            status = sql_fetch_union_all(stmt, cursor, plan_node, eof);
            break;

        case PLAN_NODE_MINUS:
            status = sql_fetch_minus(stmt, cursor, plan_node, eof);
            break;

        case PLAN_NODE_HASH_MINUS:
	        knl_panic(0);
            status = CT_ERROR;
            break;

        case PLAN_NODE_SELECT_SORT:
            status = sql_fetch_sort(stmt, cursor, plan_node, eof);
            break;

        case PLAN_NODE_SELECT_LIMIT:
            status = sql_fetch_limit(stmt, cursor, plan_node, eof);
            break;

        case PLAN_NODE_WITHAS_MTRL:
            status = sql_fetch_withas_mtrl(stmt, cursor, plan_node, eof);
            break;

        case PLAN_NODE_VM_VIEW_MTRL:
            status = sql_fetch_vm_view_mtrl(stmt, cursor, plan_node, eof);
            break;

        default:
            status = sql_fetch_query(stmt, cursor, plan_node, eof);
            SQL_CHECK_SESSION_VALID_FOR_RETURN(stmt);
            return status;
    }

    SQL_CHECK_SESSION_VALID_FOR_RETURN(stmt);
    CM_TRACE_END(stmt, plan_node->plan_id);
    return status;
}

status_t sql_fetch_join(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan_node, bool32 *eof)
{
    if (cursor->eof) {
        *eof = CT_TRUE;
        return CT_SUCCESS;
    }
    CM_TRACE_BEGIN;
    switch (plan_node->join_p.oper) {
        case JOIN_OPER_NL:
            CT_RETURN_IFERR(sql_fetch_nest_loop(stmt, cursor, plan_node, eof));
            break;

        case JOIN_OPER_NL_BATCH:
            CT_RETURN_IFERR(sql_fetch_nest_loop_batch(stmt, cursor, plan_node, eof));
            break;

        case JOIN_OPER_NL_LEFT:
            CT_RETURN_IFERR(sql_fetch_nest_loop_left(stmt, cursor, plan_node, eof));
            break;

        case JOIN_OPER_NL_FULL:
            CT_RETURN_IFERR(sql_fetch_nest_loop_full(stmt, cursor, plan_node, eof));
            break;

        case JOIN_OPER_HASH:
        case JOIN_OPER_HASH_PAR:
        case JOIN_OPER_HASH_LEFT:
        case JOIN_OPER_HASH_RIGHT_LEFT:
        case JOIN_OPER_HASH_SEMI:
        case JOIN_OPER_HASH_ANTI:
        case JOIN_OPER_HASH_ANTI_NA:
        case JOIN_OPER_HASH_RIGHT_SEMI:
        case JOIN_OPER_HASH_RIGHT_ANTI:
        case JOIN_OPER_HASH_RIGHT_ANTI_NA:
        case JOIN_OPER_HASH_FULL:
        case JOIN_OPER_MERGE:
        case JOIN_OPER_MERGE_LEFT:
        case JOIN_OPER_MERGE_FULL:
	    knl_panic(0);
            break;

        default:
            return CT_ERROR;
    }

    CM_TRACE_END(stmt, plan_node->plan_id);
    return CT_SUCCESS;
}

static void sql_set_cursor_cond(sql_cursor_t *cur, sql_query_t *query)
{
    if (query->connect_by_cond == NULL) {
        cur->cond = query->cond;
        return;
    }

    if (cur->connect_data.last_level_cursor == NULL) {
        cur->cond = query->start_with_cond;
    } else {
        cur->cond = query->connect_by_cond;
    }
}

static status_t sql_init_outer_join_exec_data(sql_stmt_t *stmt, sql_cursor_t *cur, uint32 count)
{
    uint32 i, mem_cost_size;

    mem_cost_size = count * sizeof(outer_join_data_t);
    CT_RETURN_IFERR(vmc_alloc(&cur->vmc, mem_cost_size, (void **)&cur->exec_data.outer_join));

    for (i = 0; i < count; ++i) {
        cur->exec_data.outer_join[i].need_reset_right = CT_TRUE;
        cur->exec_data.outer_join[i].right_matched = CT_FALSE;
        cur->exec_data.outer_join[i].need_swap_driver = CT_FALSE;
        cur->exec_data.outer_join[i].nl_full_opt_ctx = NULL;
    }
    return CT_SUCCESS;
}

static status_t sql_init_inner_join_exec_data(sql_stmt_t *stmt, sql_cursor_t *cursor, uint32 count)
{
    if (count == 0) {
        return CT_SUCCESS;
    }
    uint32 i, mem_cost_size;

    mem_cost_size = count * sizeof(inner_join_data_t);
    CT_RETURN_IFERR(vmc_alloc(&cursor->vmc, mem_cost_size, (void **)&cursor->exec_data.inner_join));

    for (i = 0; i < count; ++i) {
        cursor->exec_data.inner_join[i].right_fetched = CT_FALSE;
    }
    return CT_SUCCESS;
}

static status_t sql_init_aggr_dis_exec_data(sql_stmt_t *stmt, sql_cursor_t *cursor, uint32 count)
{
    uint32 i;
    uint32 mem_cost_size = sizeof(hash_segment_t) + count * sizeof(hash_table_entry_t);

    CT_RETURN_IFERR(vmc_alloc(&cursor->vmc, mem_cost_size, (void **)&cursor->exec_data.aggr_dis));

    hash_segment_t *hash_seg = (hash_segment_t *)cursor->exec_data.aggr_dis;
    vm_hash_segment_init(KNL_SESSION(stmt), stmt->mtrl.pool, hash_seg, PMA_POOL, HASH_PAGES_HOLD, HASH_AREA_SIZE);

    hash_table_entry_t *table_entry = (hash_table_entry_t *)(cursor->exec_data.aggr_dis + sizeof(hash_segment_t));
    for (i = 0; i < count; i++) {
        table_entry[i].vmid = CT_INVALID_ID32;
        table_entry[i].offset = CT_INVALID_ID32;
    }

    return CT_SUCCESS;
}

static status_t sql_init_rscol_defs_exec_data(sql_cursor_t *cursor, galist_t *rs_cols, char **buf)
{
    uint32 mem_cost_size, i;
    ct_type_t *types = NULL;
    rs_column_t *rs_col = NULL;

    if (*buf == NULL) {
        mem_cost_size = sizeof(uint32) + rs_cols->count * sizeof(ct_type_t);
        CT_RETURN_IFERR(vmc_alloc(&cursor->vmc, mem_cost_size, (void **)buf));
        *(uint32 *)*buf = mem_cost_size;
    }

    types = (ct_type_t *)(*buf + sizeof(uint32));

    for (i = 0; i < rs_cols->count; i++) {
        rs_col = (rs_column_t *)cm_galist_get(rs_cols, i);
        types[i] = rs_col->datatype;
    }

    return CT_SUCCESS;
}

static status_t sql_init_nl_batch_exec_data(sql_stmt_t *stmt, sql_cursor_t *cur, uint32 count)
{
    uint32 mem_cost_size = count * sizeof(nl_batch_data_t);
    CT_RETURN_IFERR(vmc_alloc(&cur->vmc, mem_cost_size, (void **)&cur->exec_data.nl_batch));

    for (uint32 i = 0; i < count; ++i) {
        cur->exec_data.nl_batch[i].cache_cur = NULL;
    }
    return CT_SUCCESS;
}

static status_t sql_init_merge_join_exec_data(sql_stmt_t *stmt, sql_cursor_t *cur, uint32 count)
{
    uint32 mem_cost_size = count * sizeof(join_data_t);
    CT_RETURN_IFERR(vmc_alloc(&cur->vmc, mem_cost_size, (void **)&cur->m_join));

    for (uint32 i = 0; i < count; i++) {
        cur->m_join[i].left = cur->m_join[i].right = NULL;
    }
    return CT_SUCCESS;
}

status_t sql_generate_cursor_exec_data(sql_stmt_t *stmt, sql_cursor_t *cur, sql_query_t *query)
{
    sql_query_t *s_query = query->s_query;

    if (query->join_assist.outer_node_count > 0 || (s_query != NULL && s_query->join_assist.outer_node_count > 0)) {
        uint32 outer_plan_count = query->join_assist.outer_plan_count;
        if (s_query != NULL) {
            outer_plan_count = MAX(outer_plan_count, s_query->join_assist.outer_plan_count);
        }
        CT_RETURN_IFERR(sql_init_outer_join_exec_data(stmt, cur, outer_plan_count));
    }

    // start-with clause may generated new join plan node
    if (query->tables.count > 1 || s_query != NULL) {
        uint32 inner_plan_count = query->join_assist.inner_plan_count;
        if (s_query != NULL) {
            inner_plan_count = MAX(inner_plan_count, s_query->join_assist.inner_plan_count);
        }
        CT_RETURN_IFERR(sql_init_inner_join_exec_data(stmt, cur, inner_plan_count));
    }

    if (query->aggr_dis_count > 0) {
        CT_RETURN_IFERR(sql_init_aggr_dis_exec_data(stmt, cur, query->aggr_dis_count));
    }

    if (cur->select_ctx != NULL && cur->select_ctx->pending_col_count > 0) {
        CT_RETURN_IFERR(sql_init_rscol_defs_exec_data(cur, query->rs_columns, &cur->mtrl.rs.buf));
    }

    if (stmt->context->nl_batch_cnt > 0) {
        CT_RETURN_IFERR(sql_init_nl_batch_exec_data(stmt, cur, stmt->context->nl_batch_cnt));
    }

    if (query->join_assist.mj_plan_count > 0 || (s_query != NULL && s_query->join_assist.mj_plan_count > 0)) {
        uint32 mj_plan_count = query->join_assist.mj_plan_count;
        if (s_query != NULL) {
            mj_plan_count = MAX(mj_plan_count, s_query->join_assist.mj_plan_count);
        }
        CT_RETURN_IFERR(sql_init_merge_join_exec_data(stmt, cur, mj_plan_count));
    }

    return CT_SUCCESS;
}

uint16 sql_get_decode_count(sql_table_t *table)
{
    bilist_node_t *node = NULL;
    query_field_t *query_field = NULL;

    if (table->query_fields.count == 0) {
        return 0;
    }
    node = cm_bilist_tail(&table->query_fields);
    query_field = BILIST_NODE_OF(query_field_t, node, bilist_node);
    return (uint16)(query_field->col_id + 1);
}

static inline status_t sql_calc_rownum_core(sql_stmt_t *stmt, cond_node_t *node, expr_node_t *var_expr,
    cmp_type_t cmp_type, uint32 *max_rownum)
{
    variant_t tmp_var;
    variant_t *var = NULL;

    if (var_expr->type != EXPR_NODE_CONST && var_expr->type != EXPR_NODE_PARAM) {
        return CT_SUCCESS;
    }

    if (NODE_IS_CONST(var_expr)) {
        var = &var_expr->value;
    } else {
        CT_RETURN_IFERR(sql_exec_expr_node(stmt, var_expr, &tmp_var));
        var = &tmp_var;
        if (var->is_null) {
            *max_rownum = 0U;
            return CT_SUCCESS;
        }
    }

    switch (cmp_type) {
        case CMP_TYPE_EQUAL:
            /* rownum=v, v<1 ==> false */
            /* rownum=v, v is real with non-zero tail (e.g., 2.3) */
            CT_RETURN_IFERR(var_as_real(var));
            if (var->v_real < 1 || (fabs(var->v_real - (uint32)(int32)var->v_real) >= CT_REAL_PRECISION)) {
                *max_rownum = 0U;
            } else {
                *max_rownum = (uint32)(int32)var->v_real;
            }
            break;

        case CMP_TYPE_LESS:
            /* rownum<v, v<=1  ==> false */
            CT_RETURN_IFERR(var_as_real(var));
            if (var->v_real <= 1) {
                *max_rownum = 0U;
            } else {
                *max_rownum = (uint32)(int32)ceil(var->v_real - 1.0);
            }
            break;

        case CMP_TYPE_LESS_EQUAL:
            /* rownum<=v, v<1  ==> false */
            CT_RETURN_IFERR(var_as_real(var));
            if (var->v_real < 1) {
                *max_rownum = 0U;
            } else {
                *max_rownum = (uint32)(int32)var->v_real;
            }
            break;

        default:
            *max_rownum = CT_INFINITE32;
            break;
    }

    return CT_SUCCESS;
}

static inline status_t sql_calc_rownum_right(sql_stmt_t *stmt, cond_node_t *node, uint32 *max_rownum)
{
    cmp_node_t *cmp_node = node->cmp;

    switch (cmp_node->type) {
        case CMP_TYPE_IS_NULL:
            *max_rownum = 0U;
            return CT_SUCCESS;

        case CMP_TYPE_IS_NOT_NULL:
            *max_rownum = CT_INFINITE32;
            return CT_SUCCESS;

        case CMP_TYPE_EQUAL:
        case CMP_TYPE_LESS:
        case CMP_TYPE_LESS_EQUAL:
        case CMP_TYPE_GREAT_EQUAL:
        case CMP_TYPE_GREAT:
        case CMP_TYPE_NOT_EQUAL:
            return sql_calc_rownum_core(stmt, node, cmp_node->right->root, cmp_node->type, max_rownum);

        default:
            break;
    }
    return CT_SUCCESS;
}

static inline status_t sql_calc_rownum_left(sql_stmt_t *stmt, cond_node_t *node, uint32 *max_row_num)
{
    cmp_node_t *cmp_node = node->cmp;

    switch (cmp_node->type) {
        case CMP_TYPE_GREAT_EQUAL:
            return sql_calc_rownum_core(stmt, node, cmp_node->left->root, CMP_TYPE_LESS_EQUAL, max_row_num);

        case CMP_TYPE_GREAT:
            return sql_calc_rownum_core(stmt, node, cmp_node->left->root, CMP_TYPE_LESS, max_row_num);

        case CMP_TYPE_EQUAL:
        case CMP_TYPE_LESS:
        case CMP_TYPE_LESS_EQUAL:
        case CMP_TYPE_NOT_EQUAL:
            return sql_calc_rownum_core(stmt, node, cmp_node->left->root, cmp_node->type, max_row_num);

        default:
            break;
    }
    return CT_SUCCESS;
}

static inline status_t sql_calc_cmp_rownum(sql_stmt_t *stmt, cond_node_t *node, uint32 *max_row_num)
{
    cmp_node_t *cmp_node = node->cmp;
    expr_node_t *left = NULL;
    expr_node_t *right = NULL;

    *max_row_num = CT_INFINITE32;

    /* already set rnum_pending flag in rbo_try_rownum_optmz */
    if (!cmp_node->rnum_pending) {
        return CT_SUCCESS;
    }

    left = cmp_node->left->root;
    if (NODE_IS_RES_ROWNUM(left)) {
        CT_RETURN_IFERR(sql_calc_rownum_right(stmt, node, max_row_num));
    }

    if (cmp_node->type == CMP_TYPE_IS_NULL || cmp_node->type == CMP_TYPE_IS_NOT_NULL) {
        return CT_SUCCESS;
    }

    right = cmp_node->right->root;
    if ((cmp_node->right->next == NULL) && NODE_IS_RES_ROWNUM(right)) {
        CT_RETURN_IFERR(sql_calc_rownum_left(stmt, node, max_row_num));
    }

    return CT_SUCCESS;
}

static inline status_t sql_calc_cond_rownum(sql_stmt_t *stmt, cond_node_t *node, uint32 *rnum_upper)
{
    uint32 l_upper, r_upper;

    CT_RETURN_IFERR(sql_stack_safe(stmt));

    switch (node->type) {
        case COND_NODE_COMPARE:
            CT_RETURN_IFERR(sql_calc_cmp_rownum(stmt, node, rnum_upper));
            break;

        case COND_NODE_OR:
            CT_RETURN_IFERR(sql_calc_cond_rownum(stmt, node->left, &l_upper));
            CT_RETURN_IFERR(sql_calc_cond_rownum(stmt, node->right, &r_upper));
            *rnum_upper = MAX(l_upper, r_upper);
            break;

        case COND_NODE_AND:
            CT_RETURN_IFERR(sql_calc_cond_rownum(stmt, node->left, &l_upper));
            CT_RETURN_IFERR(sql_calc_cond_rownum(stmt, node->right, &r_upper));
            *rnum_upper = MIN(l_upper, r_upper);
            break;

        default:
            *rnum_upper = CT_INFINITE32;
            break;
    }

    return CT_SUCCESS;
}

static void sql_set_cursor_max_rownum(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_query_t *query)
{
    cursor->max_rownum = CT_INFINITE32;
    if (cursor->connect_data.last_level_cursor != NULL) {
        return;
    }

    cond_tree_t *cond = NULL;
    if (query->join_assist.outer_node_count > 0 && query->filter_cond != NULL) { // only used for rownum filter
        cond = query->filter_cond;
        cursor->max_rownum = cond->rownum_upper;
    } else if (query->cond != NULL) { // used for rownum filter, also used for rownum count
        cond = query->cond;
        cursor->max_rownum = cond->rownum_upper;
    }

    if (cursor->max_rownum == CT_INFINITE32 && cond != NULL && cond->rownum_pending) {
        (void)sql_calc_cond_rownum(stmt, cond->root, &cursor->max_rownum);
    }
}

status_t sql_fetch_rownum(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof)
{
    if (cursor->rownum >= cursor->max_rownum) {
        cursor->connect_data.cur_level_cursor = NULL;
        *eof = CT_TRUE;
        return CT_SUCCESS;
    }
    cursor->rownum++;
    CT_RETURN_IFERR(sql_fetch_query(stmt, cursor, plan->rownum_p.next, eof));
    if (*eof) {
        return CT_SUCCESS;
    }
    return CT_SUCCESS;
}

static status_t sql_open_table_cursor(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_table_cursor_t *table_cur,
    knl_cursor_action_t cursor_action, bool32 is_select)
{
    sql_table_t *table = table_cur->table;
    sql_query_t *query = cursor->query;

    table_cur->scan_flag = table->tf_scan_flag;
    table_cur->hash_table = CT_FALSE;
    table_cur->action = cursor_action;
    sql_init_varea_set(stmt, table_cur);

    if (table->version.type == CURR_VERSION) {
        table_cur->scn = cursor->scn;
    } else {
        bool32 scn_type = (table->version.type == SCN_VERSION) ? CT_TRUE : CT_FALSE;
        CT_RETURN_IFERR(sql_convert_to_scn(stmt, table->version.expr, scn_type, &table_cur->scn));
    }

    if (CT_IS_SUBSELECT_TABLE(table->type)) {
        CT_RETURN_IFERR(sql_alloc_cursor(stmt, &table_cur->sql_cur));
        table_cur->sql_cur->scn = table_cur->scn;
        table_cur->sql_cur->select_ctx = table->select_ctx;
        table_cur->sql_cur->plan = table->select_ctx->plan;
        table_cur->sql_cur->global_cached = cursor->global_cached || table->global_cached;
        table_cur->sql_cur->ancestor_ref = cursor;
        table_cur->sql_cur->select_ctx->for_update_params.type =
            is_select ? cursor->select_ctx->for_update_params.type : ROWMARK_WAIT_BLOCK;
        table_cur->sql_cur->select_ctx->for_update_params.wait_seconds =
            is_select ? cursor->select_ctx->for_update_params.wait_seconds : 0;
        return CT_SUCCESS;
    }

    if (table->type == JSON_TABLE) {
        MEMS_RETURN_IFERR(
            memset_sp(&table_cur->json_table_exec, sizeof(json_table_exec_t), 0, sizeof(json_table_exec_t)));
    }

    CT_RETURN_IFERR(sql_alloc_knl_cursor(stmt, &table_cur->knl_cur));
    table_cur->knl_cur->action = (IF_LOCK_IN_FETCH(query) && table->for_update) ? CURSOR_ACTION_UPDATE : cursor_action;
    table_cur->knl_cur->for_update_fetch = table->for_update;
    table_cur->knl_cur->rowmark.type = is_select ? cursor->select_ctx->for_update_params.type : ROWMARK_WAIT_BLOCK;
    table_cur->knl_cur->rowmark.wait_seconds = is_select ? cursor->select_ctx->for_update_params.wait_seconds : 0;
    table_cur->knl_cur->update_info.count = 0;
    table_cur->knl_cur->global_cached = cursor->global_cached || table->global_cached;

    if (is_select) {
        table_cur->knl_cur->decode_count = sql_get_decode_count(table);
    }

    return CT_SUCCESS;
}

status_t sql_open_cursors(sql_stmt_t *stmt, sql_cursor_t *cur, sql_query_t *query, knl_cursor_action_t cursor_action,
    bool32 is_select)
{
    if (cur->is_open) {
        sql_close_cursor(stmt, cur);
    }

    cur->is_open = CT_TRUE;
    cur->select_ctx = query->owner;
    cur->query = query;
    cur->eof = CT_FALSE;
    cur->rownum = 0;

    sql_set_cursor_cond(cur, query);
    sql_set_cursor_max_rownum(stmt, cur, query);

    cur->columns = query->rs_columns;
    sql_reset_mtrl(stmt, cur);
    cur->table_count = 0;
    cur->winsort_ready = CT_FALSE;
    /*
     * @NOTE
     * "cur->table_count" is related to the sql_close_cursor() in dml_executor.c
     * if the counting method changed, check sql_close_cursor() too.
     */
    sql_array_t *tables = sql_get_query_tables(cur, query);
    CT_RETURN_IFERR(sql_alloc_table_cursors(cur, tables->count));

    for (uint32 i = 0; i < tables->count; i++) {
        sql_table_t *table = (sql_table_t *)sql_array_get(tables, i);
        cur->tables[i].table = table;
        cur->id_maps[i] = table->id;

        CT_RETURN_IFERR(sql_open_table_cursor(stmt, cur, &cur->tables[i], cursor_action, is_select));

        cur->table_count++;
    }

    sql_init_ssa_cursor_maps(cur, query->ssa.count);
    /* generate exec data for open cur, exec data contains:
       out join, aggr_distinct and etc.
    */
    return sql_generate_cursor_exec_data(stmt, cur, query);
}

static inline void sql_open_cursor_4_hash_mtrl(sql_stmt_t *stmt, sql_cursor_t *cur, sql_query_t *query)
{
    if (cur->is_open) {
        sql_close_cursor(stmt, cur);
    }
    sql_reset_mtrl(stmt, cur);
    cur->eof = CT_FALSE;
    cur->query = query;
    cur->rownum = 0;
    cur->is_open = CT_TRUE;
    cur->select_ctx = query->owner;
}

status_t sql_open_query_cursor(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_query_t *query)
{
    if (cursor->hash_mtrl_ctx != NULL) {
        sql_open_cursor_4_hash_mtrl(stmt, cursor, query);
        return CT_SUCCESS;
    }
    return sql_open_cursors(stmt, cursor, query, CURSOR_ACTION_SELECT, CT_TRUE);
}

status_t sql_fetch_query(sql_stmt_t *stmt, sql_cursor_t *cur, plan_node_t *plan, bool32 *eof)
{
    status_t status = CT_SUCCESS;

    if (cur->eof) {
        *eof = CT_TRUE;
        return CT_SUCCESS;
    }

    /* reset cached sequence */
    sql_reset_sequence(stmt);

    CM_TRACE_BEGIN;

    switch (plan->type) {
        case PLAN_NODE_SCAN:
            status = sql_fetch_scan(stmt, cur, plan, eof);
            break;

        case PLAN_NODE_CONCATE:
            status = sql_fetch_concate(stmt, cur, plan, eof);
            break;

        case PLAN_NODE_REMOTE_SCAN:
	    knl_panic(0);
            break;

        case PLAN_NODE_GROUP_MERGE:
	    knl_panic(0);
            break;
        case PLAN_NODE_JOIN:
            status = sql_fetch_join(stmt, cur, plan, eof);
            break;

        case PLAN_NODE_QUERY_SORT:
            status = sql_fetch_sort(stmt, cur, plan, eof);
            break;

        case PLAN_NODE_QUERY_SIBL_SORT:
            status = sql_fetch_sibl_sort(stmt, cur, plan, eof);
            break;

        case PLAN_NODE_SORT_GROUP:
            status = sql_fetch_sort_group(stmt, cur, plan, eof);
            break;

        case PLAN_NODE_MERGE_SORT_GROUP:
            status = sql_fetch_merge_sort_group(stmt, cur, plan, eof);
            break;

        case PLAN_NODE_HASH_GROUP:
        case PLAN_NODE_HASH_GROUP_PAR:
        case PLAN_NODE_HASH_GROUP_PIVOT:
            status = sql_fetch_hash_group_new(stmt, cur, plan, eof);
            break;

        case PLAN_NODE_INDEX_GROUP:
            status = sql_fetch_index_group(stmt, cur, plan, eof);
            break;

        case PLAN_NODE_AGGR:
        case PLAN_NODE_INDEX_AGGR:
            status = sql_fetch_aggr(stmt, cur, plan, eof);
            break;

        case PLAN_NODE_QUERY_LIMIT:
            status = sql_fetch_limit(stmt, cur, plan, eof);
            break;

        case PLAN_NODE_SORT_DISTINCT:
            status = sql_fetch_sort_distinct(stmt, cur, plan, eof);
            break;

        case PLAN_NODE_HASH_DISTINCT:
            status = sql_fetch_hash_distinct(stmt, cur, plan, eof);
            break;

        case PLAN_NODE_INDEX_DISTINCT:
            status = sql_fetch_index_distinct(stmt, cur, plan, eof);
            break;

        case PLAN_NODE_HAVING:
            status = sql_fetch_having(stmt, cur, plan, eof);
            break;

        case PLAN_NODE_CONNECT:
            // cur->connect_data.first_level_cursor is the same with cur
            if (cur->connect_data.cur_level_cursor == NULL || cur->connect_data.cur_level_cursor == cur) {
                cur->connect_data.first_level_rownum++;
            }
            status = sql_fetch_connect(stmt, cur, plan, eof);
            break;

        case PLAN_NODE_CONNECT_HASH:
            status = sql_fetch_connect_hash(stmt, cur, plan, eof);
            break;

        case PLAN_NODE_FILTER:
            status = sql_fetch_filter(stmt, cur, plan, eof);
            break;

        case PLAN_NODE_WINDOW_SORT:
            status = sql_fetch_winsort(stmt, cur, plan, eof);
            break;

        case PLAN_NODE_HASH_MTRL:
            status = sql_fetch_hash_mtrl(stmt, cur, plan, eof);
            break;

        case PLAN_NODE_GROUP_CUBE:
            status = sql_fetch_group_cube(stmt, cur, plan, eof);
            break;

        case PLAN_NODE_UNPIVOT:
            status = sql_fetch_unpivot(stmt, cur, plan, eof);
            break;

        case PLAN_NODE_ROWNUM:
            status = sql_fetch_rownum(stmt, cur, plan, eof);
            break;

        case PLAN_NODE_FOR_UPDATE:
            status = sql_fetch_for_update(stmt, cur, plan, eof);
            break;

        case PLAN_NODE_CONNECT_MTRL:
            status = sql_fetch_connect_mtrl(stmt, cur, plan, eof);
            break;

        case PLAN_NODE_WITHAS_MTRL:
            status = sql_fetch_withas_mtrl(stmt, cur, plan, eof);
            break;

        case PLAN_NODE_VM_VIEW_MTRL:
            status = sql_fetch_vm_view_mtrl(stmt, cur, plan, eof);
            break;

        default:
            status = sql_fetch_scan(stmt, cur, plan, eof);
            break;
    }

    SQL_CHECK_SESSION_VALID_FOR_RETURN(stmt);
    if (!IS_QUERY_SCAN_PLAN(plan->type)) {
        CM_TRACE_END(stmt, plan->plan_id);
    }
    return status;
}

status_t sql_execute_join(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof)
{
    CM_TRACE_BEGIN;
    switch (plan->join_p.oper) {
        case JOIN_OPER_NL:
            CT_RETURN_IFERR(sql_execute_nest_loop(stmt, cursor, plan, eof));
            break;

        case JOIN_OPER_NL_BATCH:
            CT_RETURN_IFERR(sql_execute_nest_loop_batch(stmt, cursor, plan, eof));
            break;

        case JOIN_OPER_NL_LEFT:
            CT_RETURN_IFERR(sql_execute_nest_loop_left(stmt, cursor, plan, eof));
            break;

        case JOIN_OPER_NL_FULL:
            CT_RETURN_IFERR(sql_execute_nest_loop_full(stmt, cursor, plan, eof));
            break;

        case JOIN_OPER_HASH:
        case JOIN_OPER_HASH_PAR:
        case JOIN_OPER_HASH_LEFT:
        case JOIN_OPER_HASH_RIGHT_LEFT:
        case JOIN_OPER_HASH_SEMI:
        case JOIN_OPER_HASH_ANTI:
        case JOIN_OPER_HASH_ANTI_NA:
        case JOIN_OPER_HASH_RIGHT_SEMI:
        case JOIN_OPER_HASH_RIGHT_ANTI:
        case JOIN_OPER_HASH_RIGHT_ANTI_NA:
        case JOIN_OPER_HASH_FULL:
        case JOIN_OPER_MERGE:
        case JOIN_OPER_MERGE_LEFT:
        case JOIN_OPER_MERGE_FULL:
	    knl_panic(0);
            break;

        default:
            return CT_ERROR;
    }
    CM_TRACE_END(stmt, plan->plan_id);
    return CT_SUCCESS;
}

status_t sql_execute_rownum(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    if (cursor->rownum >= cursor->max_rownum) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }
    cursor->rownum++;
    CT_RETURN_IFERR(sql_execute_query_plan(stmt, cursor, plan->rownum_p.next));
    cursor->rownum--;
    return CT_SUCCESS;
}

static status_t sql_make_mtrl_row_for_update(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_cursor_t *query_cur)
{
    row_assist_t ra;
    char *buf = NULL;
    mtrl_rowid_t rid;
    sql_table_cursor_t *table_cur = NULL;

    CT_RETURN_IFERR(sql_push(stmt, CT_MAX_ROW_SIZE, (void **)&buf));
    for (uint32 i = 0; i < query_cur->table_count; i++) {
        table_cur = &query_cur->tables[query_cur->id_maps[i]];
        if (table_cur->table->subslct_tab_usage != SUBSELECT_4_NORMAL_JOIN) {
            row_init(&ra, buf, CT_MAX_ROW_SIZE, 1);
        } else {
            CT_RETURN_IFERR(
                sql_make_mtrl_table_rs_row(stmt, query_cur, query_cur->tables, table_cur->table, buf, CT_MAX_ROW_SIZE));
        }
        CT_RETURN_IFERR(mtrl_insert_row(&stmt->mtrl, cursor->mtrl.for_update, buf, &rid));
    }
    CTSQL_POP(stmt);
    return CT_SUCCESS;
}

static status_t lock_row_for_update(sql_stmt_t *stmt, sql_cursor_t *cursor, for_update_plan_t *for_update_p,
    bool32 *retry)
{
    variant_t value;
    bool32 is_found = CT_FALSE;
    expr_tree_t *expr = NULL;
    sql_table_cursor_t *table_cur = NULL;

    for (uint32 i = 0; i < for_update_p->rowids->count; i++) {
        expr = (expr_tree_t *)cm_galist_get(for_update_p->rowids, i);
        CT_RETURN_IFERR(sql_exec_expr(stmt, expr, &value));
        if (value.is_null) {
            continue;
        }
        table_cur = &cursor->tables[ROWID_EXPR_TAB(expr)];
        CT_RETURN_IFERR(sql_var2rowid(&value, &table_cur->knl_cur->rowid, table_cur->knl_cur->dc_type));
        SQL_CURSOR_PUSH(stmt, cursor);
        CT_RETURN_IFERR(knl_fetch_by_rowid(KNL_SESSION(stmt), table_cur->knl_cur, &is_found));
        SQL_CURSOR_POP(stmt);
        if (!is_found || table_cur->knl_cur->scn > KNL_SESSION(stmt)->query_scn) {
            *retry = CT_TRUE;
            return CT_SUCCESS;
        }
    }
    return CT_SUCCESS;
}

static status_t sql_mtrl_for_update(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_cursor_t *query_cur, plan_node_t *plan,
    bool32 *retry)
{
    bool32 eof = CT_FALSE;
    status_t status = CT_ERROR;
    cond_tree_t *save_cond = cursor->cond;

    *retry = CT_FALSE;
    CT_RETURN_IFERR(sql_open_cursors(stmt, query_cur, cursor->query, CURSOR_ACTION_SELECT, CT_TRUE));
    CT_RETURN_IFERR(mtrl_create_segment(&stmt->mtrl, MTRL_SEGMENT_RS, NULL, &cursor->mtrl.for_update));
    CT_RETURN_IFERR(mtrl_open_segment(&stmt->mtrl, cursor->mtrl.for_update));

    SQL_CURSOR_PUSH(stmt, query_cur);
    if (sql_execute_query_plan(stmt, query_cur, plan->for_update.next) != CT_SUCCESS) {
        mtrl_close_segment(&stmt->mtrl, cursor->mtrl.for_update);
        return CT_ERROR;
    }

    cursor->cond = NULL;
    CTSQL_SAVE_STACK(stmt);

    for (;;) {
        CT_BREAK_IF_ERROR(sql_fetch_query(stmt, query_cur, plan->for_update.next, &eof));
        if (eof) {
            status = CT_SUCCESS;
            break;
        }

        CT_BREAK_IF_ERROR(lock_row_for_update(stmt, cursor, &plan->for_update, retry));
        if (*retry) {
            status = CT_SUCCESS;
            break;
        }
        CT_BREAK_IF_ERROR(sql_make_mtrl_row_for_update(stmt, cursor, query_cur));
        CTSQL_RESTORE_STACK(stmt);
    }
    CTSQL_RESTORE_STACK(stmt);
    SQL_CURSOR_POP(stmt);
    cursor->cond = save_cond;
    mtrl_close_segment(&stmt->mtrl, cursor->mtrl.for_update);
    return status;
}

static status_t sql_init_update_cursor(sql_stmt_t *stmt, sql_cursor_t *cursor)
{
    for (uint32 i = 0; i < cursor->table_count; i++) {
        sql_table_cursor_t *table_cur = &cursor->tables[cursor->id_maps[i]];
        if (CT_IS_SUBSELECT_TABLE(table_cur->table->type)) {
            sql_open_select_cursor(stmt, table_cur->sql_cur, table_cur->sql_cur->plan->select_p.rs_columns);
            continue;
        }
        if (table_cur->table->type == NORMAL_TABLE && table_cur->table->for_update) {
            table_cur->knl_cur->action = CURSOR_ACTION_UPDATE;
            table_cur->knl_cur->scan_mode = SCAN_MODE_ROWID;
            CT_RETURN_IFERR(knl_open_cursor(KNL_SESSION(stmt), table_cur->knl_cur, &table_cur->table->entry->dc));
        }
    }
    return CT_SUCCESS;
}

static status_t sql_reinit_update_cursor(sql_stmt_t *stmt, sql_cursor_t *cursor)
{
    CTSQL_RELEASE_SEGMENT(stmt, cursor->mtrl.for_update);
    for (uint32 i = 0; i < cursor->table_count; i++) {
        sql_table_cursor_t *table_cur = &cursor->tables[cursor->id_maps[i]];
        if (table_cur->table->type == NORMAL_TABLE && table_cur->table->for_update) {
            CT_RETURN_IFERR(knl_open_cursor(KNL_SESSION(stmt), table_cur->knl_cur, &table_cur->table->entry->dc));
        }
    }
    return CT_SUCCESS;
}

static inline void modify_scn_for_update(sql_stmt_t *stmt)
{
    knl_set_session_scn(KNL_SESSION(stmt), CT_INVALID_ID64);
    sql_set_scn(stmt);
}

status_t sql_execute_for_update(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    if (IF_LOCK_IN_FETCH(cursor->query)) {
        return sql_execute_query_plan(stmt, cursor, plan->for_update.next);
    }

    bool32 retry = CT_FALSE;
    status_t status = CT_ERROR;
    sql_cursor_t *query_cur = NULL;

    CT_RETURN_IFERR(sql_init_update_cursor(stmt, cursor));
    CT_RETURN_IFERR(sql_alloc_cursor(stmt, &query_cur));

    while (CT_TRUE) {
        SQL_CHECK_SESSION_VALID_FOR_RETURN(stmt);

        CT_BREAK_IF_ERROR(sql_mtrl_for_update(stmt, cursor, query_cur, plan, &retry));
        if (!retry) {
            status = CT_SUCCESS;
            break;
        }
        modify_scn_for_update(stmt);
        CT_BREAK_IF_ERROR(sql_reinit_update_cursor(stmt, cursor));
    };
    sql_free_cursor(stmt, query_cur);
    CT_RETURN_IFERR(status);
    cursor->last_table = CT_INVALID_ID32;
    return mtrl_open_rs_cursor(&stmt->mtrl, cursor->mtrl.for_update, &cursor->mtrl.cursor);
}

static void pad_cursor_row_for_update(sql_table_cursor_t *table_cur, mtrl_cursor_t *mtrl_cursor)
{
    if (CT_IS_SUBSELECT_TABLE(table_cur->table->type)) {
        mtrl_row_t *row = &table_cur->sql_cur->mtrl.cursor.row;
        row->data = mtrl_cursor->row.data;
        cm_decode_row(mtrl_cursor->row.data, row->offsets, row->lens, NULL);
        return;
    }

    knl_cursor_t *knl_cur = table_cur->knl_cur;
    knl_cur->row = (row_head_t *)mtrl_cursor->row.data;
    cm_decode_row(mtrl_cursor->row.data, knl_cur->offsets, knl_cur->lens, NULL);
    if (table_cur->table->type == NORMAL_TABLE) {
        uint32 rs_row_size = ((row_head_t *)knl_cur->row)->size;
        knl_cur->rowid = *(rowid_t *)(knl_cur->row + rs_row_size - KNL_ROWID_LEN);
    }
}

static status_t mtrl_move_cursor_for_update(mtrl_context_t *ctx, mtrl_cursor_t *mtrl_cursor)
{
    if (mtrl_cursor->slot < (uint32)mtrl_cursor->rs_page->rows) {
        mtrl_cursor->row.data = MTRL_GET_ROW(mtrl_cursor->rs_page, mtrl_cursor->slot);
        mtrl_cursor->slot++;
        return CT_SUCCESS;
    }

    mtrl_cursor->history[mtrl_cursor->count++] = mtrl_cursor->rs_vmid;
    vm_ctrl_t *ctrl = vm_get_ctrl(ctx->pool, mtrl_cursor->rs_vmid);
    mtrl_cursor->rs_vmid = ctrl->next;
    if (mtrl_cursor->rs_vmid == CT_INVALID_ID32) {
        CT_THROW_ERROR(ERR_VM, "invalid for update rs rows");
        return CT_ERROR;
    }
    vm_page_t *page = NULL;
    CT_RETURN_IFERR(mtrl_open_page(ctx, mtrl_cursor->rs_vmid, &page));
    mtrl_cursor->rs_page = (mtrl_page_t *)page->data;
    mtrl_cursor->row.data = MTRL_GET_ROW(mtrl_cursor->rs_page, 0);
    mtrl_cursor->slot = 1;
    return CT_SUCCESS;
}

static status_t sql_fetch_mtrl_row_for_update(mtrl_context_t *ctx, sql_cursor_t *cursor, bool32 *eof)
{
    sql_table_cursor_t *table_cur = NULL;
    mtrl_cursor_t *mtrl_cursor = &cursor->mtrl.cursor;

    mtrl_close_history_page(ctx, mtrl_cursor);

    for (uint32 i = 0; i < cursor->table_count; i++) {
        table_cur = &cursor->tables[cursor->id_maps[i]];
        if (i == 0) {
            CT_RETURN_IFERR(mtrl_move_rs_cursor(ctx, mtrl_cursor));
            if (mtrl_cursor->eof) {
                *eof = CT_TRUE;
                return CT_SUCCESS;
            }
        } else {
            CT_RETURN_IFERR(mtrl_move_cursor_for_update(ctx, mtrl_cursor));
        }
        pad_cursor_row_for_update(table_cur, mtrl_cursor);
    }
    return CT_SUCCESS;
}

status_t sql_fetch_for_update(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof)
{
    if (IF_LOCK_IN_FETCH(cursor->query)) {
        return sql_fetch_query(stmt, cursor, plan->for_update.next, eof);
    }

    return sql_fetch_mtrl_row_for_update(&stmt->mtrl, cursor, eof);
}

status_t sql_execute_query_plan(sql_stmt_t *stmt, sql_cursor_t *cur, plan_node_t *plan)
{
    CT_RETURN_IFERR(sql_stack_safe(stmt));
    CM_TRACE_BEGIN;
    status_t status;
    switch (plan->type) {
        case PLAN_NODE_SCAN:
            status = sql_execute_scan(stmt, cur, plan);
            break;

        case PLAN_NODE_CONCATE:
            status = sql_execute_concate(stmt, cur, plan);
            break;

        case PLAN_NODE_JOIN:
            status = sql_execute_join(stmt, cur, plan, &cur->eof);
            break;

        case PLAN_NODE_SORT_GROUP:
            status = sql_execute_sort_group(stmt, cur, plan);
            break;

        case PLAN_NODE_MERGE_SORT_GROUP:
            status = sql_execute_merge_sort_group(stmt, cur, plan);
            break;

        case PLAN_NODE_HASH_GROUP:
        case PLAN_NODE_HASH_GROUP_PAR:
        case PLAN_NODE_HASH_GROUP_PIVOT:
            status = sql_execute_hash_group_new(stmt, cur, plan);
            break;

        case PLAN_NODE_UNPIVOT:
            status = sql_execute_unpivot(stmt, cur, plan);
            break;

        case PLAN_NODE_QUERY_SORT:
        case PLAN_NODE_QUERY_SORT_PAR:
            status = sql_execute_query_sort(stmt, cur, plan);
            break;
        case PLAN_NODE_QUERY_SIBL_SORT:
            status = sql_execute_query_sibl_sort(stmt, cur, plan);
            break;
        case PLAN_NODE_INDEX_GROUP:
            status = sql_execute_index_group(stmt, cur, plan);
            break;

        case PLAN_NODE_AGGR:
            status = sql_execute_aggr(stmt, cur, plan);
            break;

        case PLAN_NODE_INDEX_AGGR:
            status = sql_execute_index_aggr(stmt, cur, plan);
            break;

        case PLAN_NODE_SORT_DISTINCT:
            status = sql_execute_sort_distinct(stmt, cur, plan);
            break;

        case PLAN_NODE_HASH_DISTINCT:
            status = sql_execute_hash_distinct(stmt, cur, plan);
            break;

        case PLAN_NODE_INDEX_DISTINCT:
            status = sql_execute_index_distinct(stmt, cur, plan);
            break;

        case PLAN_NODE_HAVING:
            status = sql_execute_query_plan(stmt, cur, plan->having.next);
            break;

        case PLAN_NODE_QUERY_LIMIT:
            status = sql_execute_query_limit(stmt, cur, plan);
            break;

        case PLAN_NODE_CONNECT:
            status = sql_execute_connect(stmt, cur, plan);
            break;

        case PLAN_NODE_CONNECT_HASH:
            status = sql_execute_connect_hash(stmt, cur, plan);
            break;

        case PLAN_NODE_FILTER:
            status = sql_execute_filter(stmt, cur, plan);
            break;

#ifdef Z_SHARDING
        case PLAN_NODE_REMOTE_SCAN:
	    knl_panic(0);
            break;

        case PLAN_NODE_GROUP_MERGE:
	    knl_panic(0);
            break;
#endif
        case PLAN_NODE_WINDOW_SORT:
            status = sql_execute_winsort(stmt, cur, plan);
            break;

        case PLAN_NODE_HASH_MTRL:
            status = sql_execute_hash_mtrl(stmt, cur, plan);
            break;

        case PLAN_NODE_GROUP_CUBE:
            status = sql_execute_group_cube(stmt, cur, plan);
            break;

        case PLAN_NODE_ROWNUM:
            status = sql_execute_rownum(stmt, cur, plan);
            break;

        case PLAN_NODE_FOR_UPDATE:
            status = sql_execute_for_update(stmt, cur, plan);
            break;

        case PLAN_NODE_CONNECT_MTRL:
            status = sql_execute_connect_mtrl(stmt, cur, plan);
            break;

        default:
            status = CT_ERROR;
            CT_THROW_ERROR(ERR_UNKNOWN_PLAN_TYPE, (int32)plan->type, "execute sql");
            break;
    }
    if (!IS_QUERY_SCAN_PLAN(plan->type)) {
        CM_TRACE_END(stmt, plan->plan_id);
    }
    return status;
}

status_t sql_execute_query(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    plan_node_t *next = plan->query.next;

    CT_RETURN_IFERR(sql_open_query_cursor(stmt, cursor, plan->query.ref));

    return sql_execute_query_plan(stmt, cursor, next);
}

status_t sql_make_normal_rs(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_fetch_func_t sql_fetch_func,
    sql_send_row_func_t sql_send_row_func)
{
    bool32 is_full = CT_FALSE;

    do {
        CTSQL_SAVE_STACK(stmt);
        if (sql_fetch_func(stmt, cursor, stmt->rs_plan, &cursor->eof) != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            return CT_ERROR;
        }

        if (cursor->eof) {
            my_sender(stmt)->send_column_def(stmt, cursor);
            sql_close_cursor(stmt, cursor);
            CTSQL_RESTORE_STACK(stmt);
            return CT_SUCCESS;
        }

        if (sql_send_row_func(stmt, cursor, &is_full) != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            return CT_ERROR;
        }
        CTSQL_RESTORE_STACK(stmt);

        SQL_CHECK_SESSION_VALID_FOR_RETURN(stmt);
    } while (!is_full);

    my_sender(stmt)->send_column_def(stmt, cursor);
    return CT_SUCCESS;
}

sql_send_row_func_t sql_get_send_row_func(sql_stmt_t *stmt, plan_node_t *plan)
{
    if (SECUREC_UNLIKELY(stmt->rs_type == RS_TYPE_ROW)) {
        return sql_send_ori_row;
    }
    switch (plan->type) {
        case PLAN_NODE_QUERY:
            return sql_get_send_row_func(stmt, plan->query.next);

        case PLAN_NODE_SORT_DISTINCT:
        case PLAN_NODE_SELECT_SORT:
        case PLAN_NODE_MINUS:
        case PLAN_NODE_HASH_MINUS:
            return sql_put_sort_row;
        case PLAN_NODE_QUERY_SORT_PAR:
	    knl_panic(0);
            return sql_send_row;

        case PLAN_NODE_QUERY_SIBL_SORT:
        case PLAN_NODE_QUERY_SORT:
            if (plan->query_sort.has_pending_rs) {
                return sql_send_sort_row_filter;
            }
            return sql_put_sort_row;

        case PLAN_NODE_SELECT_LIMIT:
        case PLAN_NODE_QUERY_LIMIT:
            return sql_get_send_row_func(stmt, plan->limit.next);

        case PLAN_NODE_REMOTE_SCAN:
	    knl_panic(0);

        case PLAN_NODE_WINDOW_SORT:
            return sql_send_sort_row_filter;

        default:
            return sql_send_row;
    }
}

void sql_open_select_cursor(sql_stmt_t *stmt, sql_cursor_t *cur, galist_t *rs_columns)
{
    if (cur->is_open) {
        sql_close_cursor(stmt, cur);
    }

    cur->eof = CT_FALSE;
    cur->rownum = 0;
    sql_reset_mtrl(stmt, cur);
    cur->columns = rs_columns;
    cur->is_open = CT_TRUE;
}

status_t sql_execute_select_plan(sql_stmt_t *stmt, sql_cursor_t *cur, plan_node_t *plan)
{
    status_t status;
    CT_RETURN_IFERR(sql_stack_safe(stmt));
    CT_RETURN_IFERR(SQL_CURSOR_PUSH(stmt, cur));
    CM_TRACE_BEGIN;

    switch (plan->type) {
        case PLAN_NODE_QUERY:
            status = sql_execute_query(stmt, cur, plan);
            break;

        case PLAN_NODE_UNION:
            status = sql_execute_hash_union(stmt, cur, plan);
            break;

        case PLAN_NODE_UNION_ALL:
            status = sql_execute_union_all(stmt, cur, plan);
            break;

        case PLAN_NODE_MINUS:
            status = sql_execute_minus(stmt, cur, plan);
            break;

        case PLAN_NODE_HASH_MINUS:
            knl_panic(0);
            status = CT_ERROR;
            break;

        case PLAN_NODE_SELECT_SORT:
            status = sql_execute_select_sort(stmt, cur, plan);
            break;

        case PLAN_NODE_SELECT_LIMIT:
            status = sql_execute_select_limit(stmt, cur, plan);
            break;

        case PLAN_NODE_WITHAS_MTRL:
            status = sql_execute_withas_mtrl(stmt, cur, plan);
            break;

        case PLAN_NODE_VM_VIEW_MTRL:
            status = sql_execute_vm_view_mtrl(stmt, cur, plan);
            break;

        default:
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "Don't support the plan type(%d)", plan->type);
            status = CT_ERROR;
            break;
    }
    CM_TRACE_END(stmt, plan->plan_id);
    SQL_CURSOR_POP(stmt);
    return status;
}

status_t sql_execute_select(sql_stmt_t *stmt)
{
    sql_select_t *select = NULL;
    sql_cursor_t *cursor = NULL;
    sql_set_ssn(stmt);
    CM_TRACE_BEGIN;

    select = (sql_select_t *)stmt->context->entry;

    cursor = CTSQL_ROOT_CURSOR(stmt);
    cursor->plan = select->plan;
    cursor->select_ctx = select;
    cursor->scn = CT_INVALID_ID64;
    cursor->found_rows.offset_skipcount = 0;
    cursor->found_rows.limit_skipcount = 0;
    cursor->total_rows = 0;

    stmt->need_send_ddm = CT_TRUE;
    if (sql_execute_select_plan(stmt, cursor, cursor->plan->select_p.next) != CT_SUCCESS) {
        return CT_ERROR;
    }
    stmt->need_send_ddm = CT_FALSE;
    stmt->rs_type = select->rs_type;
    stmt->rs_plan = select->rs_plan;

    if (stmt->plsql_mode == PLSQL_CURSOR && !stmt->cursor_info.is_forcur) {
        return CT_SUCCESS;
    }
    CT_RETURN_IFERR(sql_make_result_set(stmt, cursor));
    CM_TRACE_END(stmt, select->plan->plan_id);
    return CT_SUCCESS;
}

status_t sql_init_multi_update(sql_stmt_t *stmt, sql_cursor_t *cursor, knl_cursor_action_t action,
    knl_cursor_t **knl_curs)
{
    sql_table_cursor_t *table_cur = NULL;
    knl_cursor_t *knl_cur = NULL;

    for (uint32 i = 0; i < cursor->table_count; ++i) {
        table_cur = &cursor->tables[i];

        if (table_cur->table->type != NORMAL_TABLE || table_cur->knl_cur->table != NULL) {
            table_cur->hash_table = CT_FALSE;
            continue;
        }

        CT_RETURN_IFERR(sql_push(stmt, KNL_SESSION(stmt)->kernel->attr.cursor_size, (void **)&knl_cur));
        knl_curs[i] = knl_cur;
        KNL_INIT_CURSOR(knl_cur);
        knl_init_cursor_buf(KNL_SESSION(stmt), knl_cur);
        knl_cur->stmt = stmt;
        knl_cur->action = action;
        knl_cur->update_info.count = 0;
        knl_cur->scan_mode = SCAN_MODE_ROWID;
        if (knl_open_cursor(KNL_SESSION(stmt), knl_cur, &table_cur->table->entry->dc) != CT_SUCCESS) {
            return CT_ERROR;
        }
        SET_ROWID_PAGE(&knl_cur->link_rid, INVALID_PAGID);
        table_cur->hash_table = CT_TRUE;
        table_cur->knl_cur->table = knl_cur->table;
    }
    return CT_SUCCESS;
}

static inline void sql_free_scan(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    sql_table_t *table = plan->scan_p.table;
    sql_table_cursor_t *table_cur = &cursor->tables[table->id];

    if ((table_cur->sql_cur != NULL) && CT_IS_SUBSELECT_TABLE(table->type)) {
        sql_free_cursor(stmt, table_cur->sql_cur);
        table_cur->sql_cur = NULL;
    }
}

static status_t sql_free_join(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    switch (plan->join_p.oper) {
        case JOIN_OPER_HASH:
        case JOIN_OPER_HASH_LEFT:
        case JOIN_OPER_HASH_SEMI:
        case JOIN_OPER_HASH_ANTI:
        case JOIN_OPER_HASH_ANTI_NA:
        case JOIN_OPER_HASH_FULL:
        case JOIN_OPER_HASH_PAR:
        case JOIN_OPER_MERGE:
        case JOIN_OPER_MERGE_LEFT:
        case JOIN_OPER_MERGE_FULL:
            knl_panic(0);
        /* fall-through */
        default:
            break;
    }

    CT_RETURN_IFERR(sql_free_query_mtrl(stmt, cursor, plan->join_p.left));
    CT_RETURN_IFERR(sql_free_query_mtrl(stmt, cursor, plan->join_p.right));

    return CT_SUCCESS;
}

status_t sql_free_query_mtrl(sql_stmt_t *stmt, sql_cursor_t *cur, plan_node_t *plan)
{
    status_t status = CT_SUCCESS;
    CT_RETURN_IFERR(sql_stack_safe(stmt));

    switch (plan->type) {
        case PLAN_NODE_SCAN:
            sql_free_scan(stmt, cur, plan);
            break;

        case PLAN_NODE_CONCATE:
            if (cur->cnct_ctx != NULL) {
                sql_free_concate_ctx(stmt, cur->cnct_ctx);
                cur->cnct_ctx = NULL;
            }
            break;

        case PLAN_NODE_JOIN:
            status = sql_free_join(stmt, cur, plan);
            break;

        case PLAN_NODE_QUERY_SORT:
            sql_sort_mtrl_release_segment(stmt, cur);
            break;

        case PLAN_NODE_QUERY_SIBL_SORT:
            sql_free_sibl_sort(stmt, cur);
            break;

        case PLAN_NODE_SORT_GROUP:
        case PLAN_NODE_HASH_GROUP:
        case PLAN_NODE_HASH_GROUP_PAR:
            if (cur->group_ctx != NULL) {
                sql_free_group_ctx(stmt, cur->group_ctx);
                cur->group_ctx = NULL;
            }
            break;

        case PLAN_NODE_HASH_GROUP_PIVOT:
            if (cur->pivot_ctx != NULL) {
                sql_free_group_ctx(stmt, cur->pivot_ctx);
                cur->pivot_ctx = NULL;
            }
            break;

        case PLAN_NODE_MERGE_SORT_GROUP:
            mtrl_close_cursor(&stmt->mtrl, &cur->mtrl.cursor);
            CTSQL_RELEASE_SEGMENT(stmt, cur->mtrl.group.sid);
            break;

        case PLAN_NODE_INDEX_GROUP:
            CTSQL_RELEASE_SEGMENT(stmt, cur->mtrl.group_index);
            break;

        case PLAN_NODE_SORT_DISTINCT:
        case PLAN_NODE_HASH_DISTINCT:
            if (cur->distinct_ctx != NULL) {
                sql_free_distinct_ctx(cur->distinct_ctx);
                cur->distinct_ctx = NULL;
            }
            break;

        case PLAN_NODE_INDEX_DISTINCT:
            CTSQL_RELEASE_SEGMENT(stmt, cur->mtrl.index_distinct);
            break;

        case PLAN_NODE_CONNECT:
        case PLAN_NODE_CONNECT_HASH:
            sql_free_connect_cursor(stmt, cur);
            break;

        case PLAN_NODE_HASH_MTRL:
            cur->hash_mtrl_ctx = NULL;
            break;

        case PLAN_NODE_GROUP_CUBE:
            if (cur->exec_data.group_cube != NULL) {
                sql_free_group_cube(stmt, cur);
                cur->exec_data.group_cube = NULL;
            }
            break;

        case PLAN_NODE_FOR_UPDATE:
            status = sql_free_query_mtrl(stmt, cur, plan->for_update.next);
            // fall through

        case PLAN_NODE_WINDOW_SORT:
        default:
            break;
    }
    return status;
}
