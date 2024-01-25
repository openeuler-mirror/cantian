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
 * ctsql_group.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/executor/ctsql_group.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_group.h"
#include "ctsql_aggr.h"
#include "ctsql_select.h"
#include "ctsql_mtrl.h"
#include "srv_instance.h"
#include "ctsql_sort.h"
#include "knl_mtrl.h"
#include "ctsql_scan.h"

typedef struct st_group_aggr_assist {
    aggr_assist_t aa;
    group_ctx_t *group_ctx;
    aggr_var_t *old_aggr_var;
    row_head_t *row_head;
    uint32 index;
    variant_t *value;
} group_aggr_assist_t;

#define GA_AGGR_NODE(ga) ((ga)->aa.aggr_node)
#define GA_AGGR_TYPE(ga) ((ga)->aa.aggr_type)
#define GA_AVG_COUNT(ga) ((ga)->aa.avg_count)
#define GA_STMT(ga) ((ga)->aa.stmt)
#define GA_CURSOR(ga) ((ga)->aa.cursor)
#define GA_AGGR_VAR(ga) ((ga)->old_aggr_var)

#define SQL_INIT_GROUP_AGGR_ASSIST(ga, agg_type, ctx, agg_node, agg_var, key_row, aggid, v, avg_cnt) \
    do {                                                                                             \
        (ga)->group_ctx = (ctx);                                                                     \
        (ga)->old_aggr_var = (agg_var);                                                              \
        (ga)->row_head = (key_row);                                                                  \
        (ga)->index = (aggid);                                                                       \
        (ga)->value = (v);                                                                           \
        (ga)->aa.stmt = (ctx)->stmt;                                                                 \
        (ga)->aa.cursor = (ctx)->cursor;                                                             \
        (ga)->aa.aggr_node = (agg_node);                                                             \
        (ga)->aa.aggr_type = (agg_type);                                                             \
        (ga)->aa.avg_count = (avg_cnt);                                                              \
    } while (0)


typedef status_t (*group_init_func_t)(group_aggr_assist_t *ga);
typedef status_t (*group_invoke_func_t)(group_aggr_assist_t *ga);
typedef status_t (*group_calc_func_t)(aggr_assist_t *aa, aggr_var_t *aggr_var, group_ctx_t *ctx);

typedef struct st_group_aggr_func {
    sql_aggr_type_t aggr_type;
    bool32 ignore_type; /* flags indicate whether convert type when value->type != aggr_node->datatype */
    group_init_func_t init;
    group_invoke_func_t invoke;
    group_calc_func_t calc;
} group_aggr_func_t;


// ///////////////////////////////////////////////////////////////////////////////////////////
#define HASH_GROUP_AGGR_STR_RESERVE_SIZE 32

static inline group_aggr_func_t *sql_group_aggr_func(sql_aggr_type_t type);
static status_t sql_hash_group_convert_rowid_to_str(group_ctx_t *group_ctx, sql_stmt_t *stmt, aggr_var_t *aggr_var,
                                                    bool32 keep_old_open);
static inline status_t sql_hash_group_copy_aggr_value(group_ctx_t *ctx, aggr_var_t *old_aggr_var, variant_t *value);
static status_t sql_hash_group_ensure_str_buf(group_ctx_t *ctx, aggr_var_t *old_aggr_var, uint32 ensure_size,
    bool32 keep_value);
static status_t sql_group_calc_pivot(group_ctx_t *ctx, const char *new_buf, const char *old_buf);
static status_t sql_group_init_aggrs_buf_pivot(group_ctx_t *group_ctx, const char *old_buf, uint32 old_size);
static status_t sql_group_init_aggrs_buf(group_ctx_t *ctx, const char *old_buf, uint32 old_size);
static status_t sql_group_insert_listagg_value(group_ctx_t *ctx, expr_node_t *aggr_node, aggr_var_t *aggr_var,
    variant_t *value);
static status_t sql_group_insert_median_value(group_ctx_t *ctx, expr_node_t *aggr_node, aggr_var_t *aggr_var,
    variant_t *value);
static status_t sql_group_calc_aggr(group_aggr_assist_t *ga, const sql_func_t *func, const char *new_buf);

status_t sql_init_group_exec_data(sql_stmt_t *stmt, sql_cursor_t *cursor, group_plan_t *group_p)
{
    group_data_t *gd = NULL;

    CT_RETURN_IFERR(vmc_alloc(&cursor->vmc, sizeof(group_data_t), (void **)&gd));
    gd->curr_group = 0;
    gd->group_count = group_p->sets->count;
    gd->group_p = group_p;
    cursor->exec_data.group = gd;
    return CT_SUCCESS;
}

static status_t sql_alloc_listagg_page(knl_session_t *knl_session, group_ctx_t *ctx)
{
    vm_page_t *page = NULL;

    if (ctx->listagg_page == CT_INVALID_ID32) {
        CT_RETURN_IFERR(vm_alloc(knl_session, knl_session->temp_pool, &ctx->listagg_page));
        CT_RETURN_IFERR(vm_open(knl_session, knl_session->temp_pool, ctx->listagg_page, &page));
        CM_INIT_TEXTBUF(&ctx->concat_data, CT_VMEM_PAGE_SIZE, page->data);
    }

    return CT_SUCCESS;
}

status_t sql_group_mtrl_record_types(sql_cursor_t *cursor, plan_node_t *plan, char **buf)
{
    uint32 i, mem_cost_size;
    ct_type_t *types = NULL;
    galist_t *group_exprs = NULL;
    galist_t *group_aggrs = NULL;
    galist_t *group_cntdis_columns = NULL;
    expr_tree_t *expr = NULL;
    expr_node_t *expr_node = NULL;
    expr_node_t *cndis_column = NULL;

    group_exprs = plan->group.exprs;
    group_aggrs = plan->group.aggrs;
    group_cntdis_columns = plan->group.cntdis_columns;

    if (*buf == NULL) {
        mem_cost_size = (group_exprs->count + group_aggrs->count + group_cntdis_columns->count) * sizeof(ct_type_t);
        mem_cost_size += PENDING_HEAD_SIZE;
        CT_RETURN_IFERR(vmc_alloc(&cursor->vmc, mem_cost_size, (void **)buf));
        *(uint32 *)*buf = mem_cost_size;
    }

    types = (ct_type_t *)(*buf + PENDING_HEAD_SIZE);

    for (i = 0; i < group_exprs->count; i++) {
        expr = (expr_tree_t *)cm_galist_get(group_exprs, i);
        types[i] = expr->root->datatype;
    }

    for (i = 0; i < group_aggrs->count; i++) {
        expr_node = (expr_node_t *)cm_galist_get(group_aggrs, i);
        types[group_exprs->count + i] = expr_node->datatype;
    }

    for (i = 0; i < group_cntdis_columns->count; i++) {
        cndis_column = (expr_node_t *)cm_galist_get(group_cntdis_columns, i);
        types[group_exprs->count + group_aggrs->count + i] = cndis_column->datatype;
    }

    return CT_SUCCESS;
}

static status_t sql_group_get_cntdis_value(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, uint32 group_id,
    variant_t *value)
{
    expr_node_t *cntdis_column = NULL;
    uint32 cntdis_cid;
    ct_type_t type;

    if (value->v_bigint == 0 || group_id == CT_INVALID_ID32) {
        value->is_null = CT_TRUE;
        return CT_SUCCESS;
    }

    cntdis_column = (expr_node_t *)cm_galist_get(plan->group.cntdis_columns, group_id);
    cntdis_cid = plan->group.exprs->count + plan->group.aggrs_args + group_id;

    if (cntdis_column->datatype == CT_TYPE_UNKNOWN) {
        type = sql_get_pending_type(cursor->mtrl.group.buf, cntdis_cid);
    } else {
        type = cntdis_column->datatype;
    }

    mtrl_row_assist_t row_assist;
    mtrl_row_init(&row_assist, &cursor->mtrl.cursor.row);
    return mtrl_get_column_value(&row_assist, cursor->mtrl.cursor.eof, cntdis_cid, type, cntdis_column->typmod.is_array,
        value);
}

status_t sql_aggregate_group(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    variant_t value[FO_VAL_MAX - 1];
    ct_type_t type;
    uint32 aggr_cid = plan->group.exprs->count;
    mtrl_cursor_t *mtrl_cursor = &cursor->mtrl.cursor;
    aggr_assist_t ass;
    SQL_INIT_AGGR_ASSIST(&ass, stmt, cursor);
    mtrl_row_assist_t row_assist;
    mtrl_row_init(&row_assist, &mtrl_cursor->row);

    for (uint32 i = 0; i < plan->group.aggrs->count; i++) {
        ass.aggr_node = (expr_node_t *)cm_galist_get(plan->group.aggrs, i);
        const sql_func_t *func = GET_AGGR_FUNC(ass.aggr_node);
        if (ass.aggr_node->datatype == CT_TYPE_UNKNOWN) {
            type = sql_get_pending_type(cursor->mtrl.group.buf, aggr_cid);
        } else {
            type = ass.aggr_node->datatype;
        }

        if (func->aggr_type != AGGR_TYPE_DENSE_RANK && func->aggr_type != AGGR_TYPE_RANK) {
            for (uint32 j = 0; j < func->value_cnt; j++) {
                CT_RETURN_IFERR(mtrl_get_column_value(&row_assist, mtrl_cursor->eof, aggr_cid++, type,
                    ass.aggr_node->typmod.is_array, &value[j]));
            }
        }

        if (ass.aggr_node->dis_info.need_distinct && func->aggr_type == AGGR_TYPE_COUNT) {
            CT_RETURN_IFERR(sql_group_get_cntdis_value(stmt, cursor, plan, ass.aggr_node->dis_info.group_id, value));
        }

        ass.aggr_type = func->aggr_type;
        ass.avg_count = 1;
        CT_RETURN_IFERR(sql_aggr_value(&ass, i, value));
    }
    return CT_SUCCESS;
}

status_t sql_fetch_having(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof)
{
    for (;;) {
        CTSQL_SAVE_STACK(stmt);
        if (sql_fetch_query(stmt, cursor, plan->having.next, eof) != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            return CT_ERROR;
        }

        if (*eof) {
            CTSQL_RESTORE_STACK(stmt);
            return CT_SUCCESS;
        }

        bool32 is_found = CT_FALSE;
        if (sql_match_cond_node(stmt, plan->having.cond->root, &is_found) != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            return CT_ERROR;
        }

        if (is_found) {
            return CT_SUCCESS; // should not invoke CTSQL_RESTORE_STACK
        }
        CTSQL_RESTORE_STACK(stmt);
    }
}

status_t sql_hash_group_save_aggr_str_value(group_ctx_t *ctx, aggr_var_t *old_aggr_var, variant_t *value)
{
    if (value->is_null) {
        return CT_SUCCESS;
    }

    if (value->v_text.len != 0) {
        aggr_str_t *aggr_str = GET_AGGR_VAR_STR_EX(old_aggr_var);
        CT_RETURN_IFERR(sql_hash_group_ensure_str_buf(ctx, old_aggr_var, value->v_text.len, CT_FALSE));
        CT_RETURN_IFERR(sql_hash_group_convert_rowid_to_str(ctx, ctx->stmt, old_aggr_var, CT_FALSE));
        MEMS_RETURN_IFERR(
            memcpy_s(old_aggr_var->var.v_text.str, aggr_str->aggr_bufsize, value->v_text.str, value->v_text.len));
    }

    old_aggr_var->var.v_text.len = value->v_text.len;
    old_aggr_var->var.is_null = CT_FALSE;

    return CT_SUCCESS;
}

static status_t sql_hash_group_mtrl_record_types(group_ctx_t *ctx, expr_node_t *aggr_node, uint32 aggr_id, char **buf)
{
    if (aggr_node->sort_items == NULL) {
        *buf = NULL;
        return CT_SUCCESS;
    }
    sql_cursor_t *cursor = (sql_cursor_t *)ctx->cursor;
    if (ctx->concat_typebuf == NULL) {
        uint32 alloc_size = ctx->group_p->aggrs->count * sizeof(char *);
        CT_RETURN_IFERR(vmc_alloc(&cursor->vmc, alloc_size, (void **)&ctx->concat_typebuf));
        MEMS_RETURN_IFERR(memset_sp(ctx->concat_typebuf, alloc_size, 0, alloc_size));
    }
    if (ctx->concat_typebuf[aggr_id] == NULL) {
        CT_RETURN_IFERR(sql_sort_mtrl_record_types(&cursor->vmc, MTRL_SEGMENT_CONCAT_SORT, aggr_node->sort_items,
            &ctx->concat_typebuf[aggr_id]));
    }
    *buf = ctx->concat_typebuf[aggr_id];
    return CT_SUCCESS;
}

static inline status_t sql_group_init_none(group_aggr_assist_t *ga)
{
    CT_THROW_ERROR(ERR_UNKNOWN_ARRG_OPER);
    return CT_ERROR;
}

static inline status_t sql_group_init_value(group_aggr_assist_t *ga)
{
    aggr_var_t *aggr_var = ga->old_aggr_var;

    if (SECUREC_UNLIKELY(ga->group_ctx->group_by_phase == GROUP_BY_COLLECT)) {
        if (CT_IS_VARLEN_TYPE(ga->value->type)) {
            // reset GROUP_BY_COLLECT aggr_buf when do init, ensure realloc string buffer in ctx.
            aggr_str_t *aggr_str = GET_AGGR_VAR_STR_EX(aggr_var);
            if (aggr_str != NULL) {
                aggr_str->aggr_bufsize = 0;
            }
        }
    }

    var_copy(ga->value, &aggr_var->var);
    if (CT_IS_VARLEN_TYPE(ga->value->type)) {
        return sql_hash_group_save_aggr_str_value(ga->group_ctx, aggr_var, ga->value);
    }
    return CT_SUCCESS;
}

static inline status_t sql_group_init_count(group_aggr_assist_t *ga)
{
    GA_AGGR_VAR(ga)->var.ctrl = ga->value->ctrl;
    GA_AGGR_VAR(ga)->var.v_bigint = ga->value->v_bigint;
    return CT_SUCCESS;
}

static inline status_t sql_group_init_median(group_aggr_assist_t *ga)
{
    GET_AGGR_VAR_MEDIAN(GA_AGGR_VAR(ga))->median_count = GA_AVG_COUNT(ga);
    CT_RETURN_IFERR(sql_hash_group_mtrl_record_types(ga->group_ctx, GA_AGGR_NODE(ga), ga->index,
        &GET_AGGR_VAR_MEDIAN(GA_AGGR_VAR(ga))->type_buf));
    return sql_group_init_value(ga);
}

static inline status_t sql_group_init_covar(group_aggr_assist_t *ga)
{
    aggr_var_t *var = ga->old_aggr_var;
    aggr_covar_t *covar = GET_AGGR_VAR_COVAR(var);

    MEMS_RETURN_IFERR(memset_s(&var->var, sizeof(variant_t), 0, sizeof(variant_t)));
    MEMS_RETURN_IFERR(memset_s(&covar->extra, sizeof(variant_t), 0, sizeof(variant_t)));
    MEMS_RETURN_IFERR(memset_s(&covar->extra_1, sizeof(variant_t), 0, sizeof(variant_t)));
    var->var.is_null = CT_TRUE;
    covar->extra.is_null = CT_TRUE;
    covar->extra_1.is_null = CT_TRUE;
    covar->ex_count = 0;
    return sql_aggr_invoke(&ga->aa, var, ga->value);
}

static inline status_t sql_group_init_corr(group_aggr_assist_t *ga)
{
    aggr_var_t *var = ga->old_aggr_var;
    MEMS_RETURN_IFERR(memset_s(&var->var, sizeof(variant_t), 0, sizeof(variant_t)));
    var->var.is_null = CT_TRUE;
    aggr_corr_t *aggr_corr = GET_AGGR_VAR_CORR(var);
    MEMS_RETURN_IFERR(memset_s(&aggr_corr->extra, sizeof(aggr_corr->extra), 0, sizeof(aggr_corr->extra)));
    aggr_corr->extra[CORR_VAR_SUM_X].is_null = CT_TRUE;
    aggr_corr->extra[CORR_VAR_SUM_Y].is_null = CT_TRUE;
    aggr_corr->extra[CORR_VAR_SUM_XX].is_null = CT_TRUE;
    aggr_corr->extra[CORR_VAR_SUM_YY].is_null = CT_TRUE;
    aggr_corr->ex_count = 0;
    return sql_aggr_invoke(&ga->aa, var, ga->value);
}

static inline status_t sql_group_init_stddev(group_aggr_assist_t *ga)
{
    aggr_var_t *var = ga->old_aggr_var;
    aggr_stddev_t *aggr_stddev = GET_AGGR_VAR_STDDEV(var);
    MEMS_RETURN_IFERR(memset_s(&var->var, sizeof(variant_t), 0, sizeof(variant_t)));
    MEMS_RETURN_IFERR(memset_s(&aggr_stddev->extra, sizeof(variant_t), 0, sizeof(variant_t)));
    var->var.is_null = CT_TRUE;
    aggr_stddev->extra.is_null = CT_TRUE;
    aggr_stddev->ex_count = 0;

    if (ga->value->is_null) {
        return CT_SUCCESS;
    }

    return sql_aggr_invoke(&ga->aa, var, ga->value);
}

static status_t sql_group_init_array_agg(group_aggr_assist_t *ga)
{
    array_assist_t ass;
    id_list_t *vm_list = sql_get_exec_lob_list(GA_STMT(ga));
    aggr_var_t *aggr_var = ga->old_aggr_var;

    aggr_var->var.is_null = CT_FALSE;
    aggr_var->var.type = CT_TYPE_ARRAY;
    aggr_var->var.v_array.count = 1;
    aggr_var->var.v_array.value.type = CT_LOB_FROM_VMPOOL;
    aggr_var->var.v_array.type = ga->value->type;

    CT_RETURN_IFERR(
        array_init(&ass, KNL_SESSION(GA_STMT(ga)), GA_STMT(ga)->mtrl.pool, vm_list, &aggr_var->var.v_array.value.vm_lob));
    CT_RETURN_IFERR(sql_exec_array_element(GA_STMT(ga), &ass, aggr_var->var.v_array.count, ga->value, CT_TRUE,
        &aggr_var->var.v_array.value.vm_lob));
    return array_update_head_datatype(&ass, &aggr_var->var.v_array.value.vm_lob, ga->value->type);
}

static inline status_t sql_group_init_dense_rank(group_aggr_assist_t *ga)
{
    aggr_var_t *aggr_var = ga->old_aggr_var;
    aggr_dense_rank_t *aggr_dense_rank = GET_AGGR_VAR_DENSE_RANK(aggr_var);
    vm_hash_segment_init(KNL_SESSION(GA_STMT(ga)), GA_STMT(ga)->mtrl.pool, &aggr_dense_rank->hash_segment, PMA_POOL,
        HASH_PAGES_HOLD, HASH_AREA_SIZE);
    aggr_dense_rank->table_entry.vmid = CT_INVALID_ID32;
    aggr_dense_rank->table_entry.offset = CT_INVALID_ID32;
    CT_RETURN_IFERR(vm_hash_table_alloc(&aggr_dense_rank->table_entry, &aggr_dense_rank->hash_segment, 0));
    CT_RETURN_IFERR(
        vm_hash_table_init(&aggr_dense_rank->hash_segment, &aggr_dense_rank->table_entry, NULL, NULL, NULL));
    return sql_aggr_invoke(&ga->aa, aggr_var, ga->value);
}

static inline status_t sql_group_init_rank(group_aggr_assist_t *ga)
{
    return sql_aggr_invoke(&ga->aa, GA_AGGR_VAR(ga), ga->value);
}

static inline status_t sql_group_init_listagg(group_aggr_assist_t *ga)
{
    CT_RETURN_IFERR(sql_alloc_listagg_page(KNL_SESSION(GA_STMT(ga)), ga->group_ctx));
    CT_RETURN_IFERR(sql_hash_group_mtrl_record_types(ga->group_ctx, GA_AGGR_NODE(ga), ga->index,
        &GET_AGGR_VAR_GROUPCONCAT(GA_AGGR_VAR(ga))->type_buf));
    if (!CT_IS_STRING_TYPE(ga->value->type)) {
        CT_RETURN_IFERR(sql_convert_variant(GA_STMT(ga), ga->value, CT_TYPE_STRING));
    }
    if (GA_AGGR_NODE(ga)->sort_items == NULL) {
        return sql_group_init_value(ga);
    }
    return sql_group_insert_listagg_value(ga->group_ctx, GA_AGGR_NODE(ga), GA_AGGR_VAR(ga), ga->value);
}

// for avg/cume_dist
static inline status_t sql_group_init_avg(group_aggr_assist_t *ga)
{
    GET_AGGR_VAR_AVG(GA_AGGR_VAR(ga))->ex_avg_count = GA_AVG_COUNT(ga);
    return sql_group_init_value(ga);
}

static inline status_t sql_group_aggr_none(group_aggr_assist_t *ga)
{
    CT_THROW_ERROR(ERR_UNKNOWN_ARRG_OPER);
    return CT_ERROR;
}

static inline status_t sql_group_aggr_count(group_aggr_assist_t *ga)
{
    VALUE(int64, &GA_AGGR_VAR(ga)->var) += VALUE(int64, ga->value);
    return CT_SUCCESS;
}

static inline status_t sql_group_aggr_sum(group_aggr_assist_t *ga)
{
    /* if the first value is NULL, avg/cume_dist should reset its count to avoid NULL value to be added in */
    if (SECUREC_UNLIKELY(GA_AGGR_VAR(ga)->var.is_null)) {
        var_copy(ga->value, &GA_AGGR_VAR(ga)->var);
        if (GA_AGGR_TYPE(ga) == AGGR_TYPE_AVG || GA_AGGR_TYPE(ga) == AGGR_TYPE_CUME_DIST) {
            aggr_avg_t *aggr_avg = GET_AGGR_VAR_AVG(GA_AGGR_VAR(ga));
            if (aggr_avg != NULL) {
                aggr_avg->ex_avg_count = 1;
            }
        }
        return CT_SUCCESS;
    }

    return sql_aggr_sum_value(GA_STMT(ga), &GA_AGGR_VAR(ga)->var, ga->value);
}

// for avg/cume_dist
static inline status_t sql_group_aggr_avg(group_aggr_assist_t *ga)
{
    GET_AGGR_VAR_AVG(GA_AGGR_VAR(ga))->ex_avg_count += GA_AVG_COUNT(ga);
    return sql_group_aggr_sum(ga);
}

static inline status_t sql_group_aggr_min_max(group_aggr_assist_t *ga)
{
    int32 cmp_result;

    if (GA_AGGR_VAR(ga)->var.is_null) {
        return sql_hash_group_copy_aggr_value(ga->group_ctx, GA_AGGR_VAR(ga), ga->value);
    }

    if (CT_IS_STRING_TYPE(GA_AGGR_VAR(ga)->var.type) || CT_IS_BINARY_TYPE(GA_AGGR_VAR(ga)->var.type)) {
        CT_RETURN_IFERR(sql_hash_group_convert_rowid_to_str(ga->group_ctx, GA_STMT(ga), GA_AGGR_VAR(ga), CT_FALSE));
    }

    CT_RETURN_IFERR(sql_compare_variant(GA_STMT(ga), &GA_AGGR_VAR(ga)->var, ga->value, &cmp_result));

    if ((GA_AGGR_TYPE(ga) == AGGR_TYPE_MIN && cmp_result > 0) || (GA_AGGR_TYPE(ga) == AGGR_TYPE_MAX && cmp_result < 0)) {
        return sql_hash_group_copy_aggr_value(ga->group_ctx, GA_AGGR_VAR(ga), ga->value);
    }

    return CT_SUCCESS;
}

static inline status_t sql_group_aggr_median(group_aggr_assist_t *ga)
{
    GET_AGGR_VAR_MEDIAN(GA_AGGR_VAR(ga))->median_count += GA_AVG_COUNT(ga);
    return sql_group_insert_median_value(ga->group_ctx, GA_AGGR_NODE(ga), GA_AGGR_VAR(ga), ga->value);
}

static inline status_t sql_group_exec_sepvar(sql_stmt_t *stmt, expr_node_t *aggr_node, variant_t *sep_var)
{
    expr_tree_t *sep = aggr_node->argument; /* get the optional argument "separator" */
    if (sep != NULL) {
        CT_RETURN_IFERR(sql_exec_expr_node(stmt, sep->root, sep_var));
        if (!CT_IS_STRING_TYPE(sep_var->type)) {
            CT_RETURN_IFERR(sql_convert_variant(stmt, sep_var, CT_TYPE_STRING));
        }
        sql_keep_stack_variant(stmt, sep_var);
    } else {
        sep_var->is_null = CT_TRUE;
        sep_var->type = CT_TYPE_STRING;
    }
    return CT_SUCCESS;
}

static status_t sql_group_aggr_listagg(group_aggr_assist_t *ga)
{
    if (GA_AGGR_NODE(ga)->sort_items != NULL) {
        return sql_group_insert_listagg_value(ga->group_ctx, GA_AGGR_NODE(ga), GA_AGGR_VAR(ga), ga->value);
    }

    variant_t sep_var;
    variant_t *value = ga->value;

    if (value->is_null) {
        return CT_SUCCESS;
    }

    if (GA_AGGR_VAR(ga)->var.is_null) {
        return sql_hash_group_save_aggr_str_value(ga->group_ctx, GA_AGGR_VAR(ga), value);
    }

    CT_RETURN_IFERR(sql_group_exec_sepvar(GA_STMT(ga), GA_AGGR_NODE(ga), &sep_var));

    uint32 len = GA_AGGR_VAR(ga)->var.v_text.len + value->v_text.len;
    if (!sep_var.is_null && sep_var.v_text.len > 0) {
        len += sep_var.v_text.len;
    }

    CT_RETURN_IFERR(sql_hash_group_ensure_str_buf(ga->group_ctx, GA_AGGR_VAR(ga), len, CT_TRUE));
    CT_RETURN_IFERR(sql_hash_group_convert_rowid_to_str(ga->group_ctx, GA_STMT(ga), GA_AGGR_VAR(ga), CT_FALSE));

    char *cur_buf = GA_AGGR_VAR(ga)->var.v_text.str + GA_AGGR_VAR(ga)->var.v_text.len;
    uint32 remain_len = len - GA_AGGR_VAR(ga)->var.v_text.len;
    if (!sep_var.is_null && sep_var.v_text.len > 0) {
        MEMS_RETURN_IFERR(memcpy_sp(cur_buf, remain_len, sep_var.v_text.str, sep_var.v_text.len));

        cur_buf += sep_var.v_text.len;
        remain_len -= sep_var.v_text.len;
    }
    /* hit scenario: group_concat '1,1,2,' aggr_node is zero len string */
    if (value->v_text.len != 0) {
        MEMS_RETURN_IFERR(memcpy_sp(cur_buf, remain_len, value->v_text.str, value->v_text.len));
    }

    GA_AGGR_VAR(ga)->var.v_text.len = len;
    return CT_SUCCESS;
}

static inline status_t sql_group_aggr_array_agg(group_aggr_assist_t *ga)
{
    array_assist_t aa;
    GA_AGGR_VAR(ga)->var.v_array.count++;
    ARRAY_INIT_ASSIST_INFO(&aa, GA_STMT(ga));

    return sql_exec_array_element(GA_STMT(ga), &aa, GA_AGGR_VAR(ga)->var.v_array.count, ga->value, CT_TRUE,
        &GA_AGGR_VAR(ga)->var.v_array.value.vm_lob);
}

static inline status_t sql_group_aggr_normal(group_aggr_assist_t *ga)
{
    return sql_aggr_invoke(&ga->aa, GA_AGGR_VAR(ga), ga->value);
}

// for avg/cume_dist
static status_t sql_group_calc_avg(aggr_assist_t *ass, aggr_var_t *aggr_var, group_ctx_t *ctx)
{
    variant_t v_rows;
    v_rows.type = CT_TYPE_BIGINT;
    v_rows.is_null = CT_FALSE;

    v_rows.v_bigint = (int64)GET_AGGR_VAR_AVG(aggr_var)->ex_avg_count;
    if (ctx == NULL || ctx->group_by_phase != GROUP_BY_COLLECT) {
        GET_AGGR_VAR_AVG(aggr_var)->ex_avg_count = 1; // for fetch again
    }
    if (v_rows.v_bigint <= 0) {
        CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "v_rows.v_bigint(%lld) > 0", v_rows.v_bigint);
        return CT_ERROR;
    }
    if (ctx == NULL || ctx->group_by_phase != GROUP_BY_COLLECT) {
        if (ass->aggr_type == AGGR_TYPE_CUME_DIST) {
            // as if this param is been inserted
            v_rows.v_bigint += 1;
            CT_RETURN_IFERR(var_as_bigint(&aggr_var->var));
            aggr_var->var.v_bigint += 1;
        }
        CT_RETURN_IFERR(opr_exec(OPER_TYPE_DIV, SESSION_NLS(ass->stmt), &aggr_var->var, &v_rows, &aggr_var->var));
    }
    return CT_SUCCESS;
}

static inline status_t sql_group_calc_listagg(aggr_assist_t *aa, aggr_var_t *aggr_var, group_ctx_t *ctx)
{
    if (aa->aggr_node->sort_items != NULL) {
        aggr_group_concat_t *group_concat = GET_AGGR_VAR_GROUPCONCAT(aggr_var);
        if (group_concat->sort_rid.vmid == CT_INVALID_ID32) {
            CT_RETURN_IFERR(sql_hash_group_convert_rowid_to_str(ctx, ctx->stmt, aggr_var, CT_FALSE));
        }
        CT_RETURN_IFERR(
            sql_hash_group_calc_listagg(ctx->stmt, ctx->cursor, aa->aggr_node, aggr_var, &ctx->concat_data));
    }
    return CT_SUCCESS;
}

static inline status_t sql_group_calc_dense_rank(aggr_assist_t *ass, aggr_var_t *aggr_var, group_ctx_t *ctx)
{
    CT_RETURN_IFERR(sql_aggr_calc_value(ass, aggr_var));
    aggr_dense_rank_t *aggr_dense_rank = GET_AGGR_VAR_DENSE_RANK(aggr_var);
    vm_hash_segment_deinit(&aggr_dense_rank->hash_segment);
    aggr_dense_rank->table_entry.vmid = CT_INVALID_ID32;
    aggr_dense_rank->table_entry.offset = CT_INVALID_ID32;
    return CT_SUCCESS;
}

static inline status_t sql_group_calc_median(aggr_assist_t *ass, aggr_var_t *aggr_var, group_ctx_t *ctx)
{
    return sql_hash_group_calc_median(ctx->stmt, ctx->cursor, ass->aggr_node, aggr_var);
}

static inline status_t sql_group_calc_normal(aggr_assist_t *ass, aggr_var_t *aggr_var, group_ctx_t *ctx)
{
    return sql_aggr_calc_value(ass, aggr_var);
}

static inline status_t sql_group_calc_none(aggr_assist_t *ass, aggr_var_t *aggr_var, group_ctx_t *ctx)
{
    return CT_SUCCESS;
}

status_t sql_group_re_calu_aggr(group_ctx_t *group_ctx, galist_t *aggrs)
{
    aggr_assist_t ass;
    SQL_INIT_AGGR_ASSIST(&ass, group_ctx->stmt, group_ctx->cursor);
    group_ctx->concat_data.len = 0;

    for (uint32 i = 0; i < aggrs->count; i++) {
        aggr_var_t *aggr_var = sql_get_aggr_addr(ass.cursor, i);
        if (aggr_var->var.is_null) {
            continue;
        }
        ass.aggr_node = group_ctx->aggr_node[i];
        ass.aggr_type = GET_AGGR_FUNC(ass.aggr_node)->aggr_type;
        CT_RETURN_IFERR(sql_group_aggr_func(ass.aggr_type)->calc(&ass, aggr_var, group_ctx));
    }
    return CT_SUCCESS;
}


static status_t sql_hash_group_convert_rowid_to_str(group_ctx_t *group_ctx, sql_stmt_t *stmt, aggr_var_t *aggr_var,
    bool32 keep_old_open)
{
    aggr_str_t *aggr_str = GET_AGGR_VAR_STR_EX(aggr_var);
    mtrl_rowid_t rowid = aggr_str->str_result;
    if (rowid.vmid != CT_INVALID_ID32) { // aggr string value's buffer is alloced from vm_page
        vm_page_t *curr_page = group_ctx->extra_data.curr_page;
        mtrl_page_t *mtrl_page = NULL;

        if (curr_page != NULL && curr_page->vmid != rowid.vmid) {
            // keep the old page open, should be closed by the caller
            if (!keep_old_open) {
                mtrl_close_page(&stmt->mtrl, curr_page->vmid);
            }
            curr_page = NULL;
            group_ctx->extra_data.curr_page = NULL;
        }

        if (curr_page == NULL) {
            if (mtrl_open_page(&stmt->mtrl, rowid.vmid, &curr_page) != CT_SUCCESS) {
                return CT_ERROR;
            }

            group_ctx->extra_data.curr_page = curr_page;
        }

        mtrl_page = (mtrl_page_t *)curr_page->data;
        aggr_var->var.v_text.str = MTRL_GET_ROW(mtrl_page, rowid.slot) + sizeof(row_head_t) + sizeof(uint16);
    } else {
        if (rowid.slot != CT_INVALID_ID32) { // aggr string value's buffer is reserved near group_key & aggr value
            aggr_var->var.v_text.str = ((char *)aggr_var) + rowid.slot;
        }
    }

    return CT_SUCCESS;
}

status_t sql_hash_group_convert_rowid_to_str_row(group_ctx_t *ctx, sql_stmt_t *stmt, sql_cursor_t *cursor,
    galist_t *aggrs)
{
    uint32 i, j;
    aggr_var_t *aggr_var = NULL;
    vm_page_t *page = NULL;

    // close all page saved string aggr values by pre row
    for (i = 0; i < ctx->str_aggr_page_count; i++) {
        mtrl_close_page(&stmt->mtrl, ctx->str_aggr_pages[i]);
    }
    ctx->str_aggr_page_count = 0;

    for (i = 0; i < aggrs->count; i++) {
        aggr_var = sql_get_aggr_addr(cursor, i);
        if (aggr_var->var.is_null) {
            continue;
        }

        if (CT_IS_STRING_TYPE(aggr_var->var.type) || CT_IS_BINARY_TYPE(aggr_var->var.type)) {
            aggr_str_t *aggr_str = GET_AGGR_VAR_STR_EX(aggr_var);
            if (aggr_str->str_result.vmid != CT_INVALID_ID32) {
                for (j = 0; j < ctx->str_aggr_page_count; j++) {
                    if (ctx->str_aggr_pages[j] == aggr_str->str_result.vmid) {
                        break;
                    }
                }

                if (j == ctx->str_aggr_page_count) {
                    CT_RETURN_IFERR(mtrl_open_page(&stmt->mtrl, aggr_str->str_result.vmid, &page));
                    ctx->str_aggr_pages[ctx->str_aggr_page_count] = aggr_str->str_result.vmid;
                    ctx->str_aggr_page_count++;
                }
            }

            CT_RETURN_IFERR(sql_hash_group_convert_rowid_to_str(ctx, stmt, aggr_var, CT_FALSE));
        }
    }

    return CT_SUCCESS;
}

status_t group_hash_q_oper_func(void *callback_ctx, const char *new_buf, uint32 new_size, const char *old_buf,
    uint32 old_size, bool32 found)
{
    if (found) {
        group_ctx_t *ctx = (group_ctx_t *)callback_ctx;
        MEMS_RETURN_IFERR(memcpy_sp(ctx->row_buf, CT_MAX_ROW_SIZE, old_buf, old_size));

        ctx->row_buf_len = old_size;

        mtrl_cursor_t *mtrl_cursor = &((sql_cursor_t *)(ctx->cursor))->mtrl.cursor;
        mtrl_cursor->eof = CT_FALSE;
        mtrl_cursor->type = MTRL_CURSOR_HASH_GROUP;
        mtrl_cursor->row.data = ctx->row_buf;
        cm_decode_row(mtrl_cursor->row.data, mtrl_cursor->row.offsets, mtrl_cursor->row.lens, NULL);
        mtrl_cursor->hash_group.aggrs = mtrl_cursor->row.data + ((row_head_t *)old_buf)->size;
        CT_RETURN_IFERR(sql_hash_group_convert_rowid_to_str_row(ctx, ctx->stmt, (sql_cursor_t *)(ctx->cursor),
            ctx->group_p->aggrs));
        // can not get group_ctx from cursor
        // both hash group and hash mtrl will invoke this function
        return sql_group_re_calu_aggr(ctx, ctx->group_p->aggrs);
    }

    return CT_SUCCESS;
}

static inline status_t group_pivot_i_oper_func(void *callback_ctx, const char *new_buf, uint32 new_size,
    const char *old_buf, uint32 old_size, bool32 found)
{
    group_ctx_t *ctx = (group_ctx_t *)callback_ctx;

    if (found) {
        return sql_group_calc_pivot(ctx, new_buf, old_buf);
    } else {
        return sql_group_init_aggrs_buf_pivot(ctx, old_buf, old_size);
    }
}

static status_t sql_group_calc_aggrs(group_ctx_t *ctx, const char *new_buf, const char *old_buf)
{
    uint32 aggr_cnt = ctx->group_p->aggrs->count;
    const sql_func_t *func = NULL;
    row_head_t *row_head = (row_head_t *)old_buf;
    aggr_var_t *old_aggr_var = (aggr_var_t *)(old_buf + row_head->size);
    group_aggr_assist_t gp_assist;
    group_aggr_assist_t *ga = &gp_assist;
    SQL_INIT_GROUP_AGGR_ASSIST(ga, AGGR_TYPE_NONE, ctx, NULL, NULL, row_head, 0, ctx->str_aggr_val, 1);

    CTSQL_SAVE_STACK(ctx->stmt);
    for (uint32 index = 0; index < aggr_cnt; index++) {
        ga->index = index;
        GA_AGGR_NODE(ga) = ctx->aggr_node[index];
        func = GET_AGGR_FUNC(GA_AGGR_NODE(ga));
        GA_AGGR_TYPE(ga) = func->aggr_type;
        GA_AGGR_VAR(ga) = &old_aggr_var[index];
        CT_RETURN_IFERR(sql_group_calc_aggr(ga, func, new_buf));
        CTSQL_RESTORE_STACK(ctx->stmt);
    }

    return CT_SUCCESS;
}

status_t group_hash_i_oper_func(void *callback_ctx, const char *new_buf, uint32 new_size, const char *old_buf,
    uint32 old_size, bool32 found)
{
    group_ctx_t *ctx = (group_ctx_t *)callback_ctx;

    if (found) {
        return sql_group_calc_aggrs(ctx, new_buf, old_buf);
    } else {
        return sql_group_init_aggrs_buf(ctx, old_buf, old_size);
    }
}

static status_t sql_hash_group_ensure_str_buf(group_ctx_t *ctx, aggr_var_t *old_aggr_var, uint32 ensure_size,
    bool32 keep_value)
{
    char *buf = NULL;
    row_head_t *head = NULL;
    mtrl_rowid_t rowid;
    sql_stmt_t *stmt = ctx->stmt;

    if (ensure_size > CT_MAX_ROW_SIZE) {
        CT_THROW_ERROR(ERR_EXCEED_MAX_ROW_SIZE, ensure_size, CT_MAX_ROW_SIZE);
        return CT_ERROR;
    }

    aggr_str_t *aggr_str = GET_AGGR_VAR_STR_EX(old_aggr_var);
    if (ensure_size <= aggr_str->aggr_bufsize) {
        return CT_SUCCESS;
    }

    uint32 reserve_size = MAX(HASH_GROUP_AGGR_STR_RESERVE_SIZE, aggr_str->aggr_bufsize * AGGR_BUF_SIZE_FACTOR);
    reserve_size = MAX(reserve_size, ensure_size);
    reserve_size = MIN(reserve_size, CT_MAX_ROW_SIZE);
    CT_RETURN_IFERR(sql_push(stmt, CT_MAX_ROW_SIZE + sizeof(row_head_t) + sizeof(uint16), (void **)&buf));

    head = (row_head_t *)buf;
    head->flags = 0;
    head->itl_id = CT_INVALID_ID8;
    head->column_count = (uint16)1;
    head->size = reserve_size + sizeof(row_head_t) + sizeof(uint16);

    if (ctx->extra_data.curr_page == NULL) {
        CT_RETURN_IFERR(mtrl_extend_segment(&stmt->mtrl, &ctx->extra_data));
        CT_RETURN_IFERR(mtrl_open_segment2(&stmt->mtrl, &ctx->extra_data));
    }
    if (mtrl_insert_row2(&stmt->mtrl, &ctx->extra_data, buf, &rowid) != CT_SUCCESS) {
        CTSQL_POP(stmt);
        return CT_ERROR;
    }

    CTSQL_POP(stmt);

    if (keep_value && old_aggr_var->var.v_text.len > 0 && old_aggr_var->var.is_null == CT_FALSE) {
        uint32 old_vmid = aggr_str->str_result.vmid;
        CT_RETURN_IFERR(sql_hash_group_convert_rowid_to_str(ctx, stmt, old_aggr_var, CT_FALSE));
        variant_t old_var = old_aggr_var->var;
        aggr_str->str_result = rowid;
        // open the new page, but keep the old page open
        CT_RETURN_IFERR(sql_hash_group_convert_rowid_to_str(ctx, stmt, old_aggr_var, CT_TRUE));
        MEMS_RETURN_IFERR(memcpy_s(old_aggr_var->var.v_text.str, reserve_size, old_var.v_text.str, old_var.v_text.len));
        // close the old page
        if (old_vmid != rowid.vmid && old_vmid != CT_INVALID_ID32) {
            mtrl_close_page(&stmt->mtrl, old_vmid);
        }
    } else {
        aggr_str->str_result = rowid;
    }
    aggr_str->aggr_bufsize = reserve_size;

    return CT_SUCCESS;
}

static status_t sql_init_hash_dist_tables(sql_stmt_t *stmt, sql_cursor_t *cursor, group_ctx_t *ctx)
{
    hash_segment_t *hash_seg = &ctx->hash_segment;
    hash_table_entry_t *hash_table = NULL;
    uint32 alloc_size = sizeof(hash_table_entry_t) * ctx->group_p->sets->count;
    CT_RETURN_IFERR(vmc_alloc(&cursor->vmc, alloc_size, (void **)&ctx->hash_dist_tables));

    for (uint32 i = 0; i < ctx->group_p->sets->count; i++) {
        hash_table = &ctx->hash_dist_tables[i];
        CT_RETURN_IFERR(vm_hash_table_alloc(hash_table, hash_seg, 0));
        CT_RETURN_IFERR(vm_hash_table_init(hash_seg, hash_table, NULL, NULL, ctx));
    }
    return CT_SUCCESS;
}

static status_t sql_hash_group_insert(group_ctx_t *ctx, hash_table_entry_t *table, row_head_t *key_row, uint32 aggr_id,
    variant_t *value, bool32 *found)
{
    char *buf = NULL;
    sql_stmt_t *stmt = ctx->stmt;
    variant_t var_aggr_id, var_key;

    var_aggr_id.is_null = CT_FALSE;
    var_aggr_id.type = CT_TYPE_INTEGER;
    var_aggr_id.v_int = (int32)aggr_id;

    var_key.is_null = CT_FALSE;
    var_key.type = CT_TYPE_BINARY;
    var_key.v_bin.bytes = (uint8 *)key_row;
    var_key.v_bin.size = key_row->size;
    var_key.v_bin.is_hex_const = CT_FALSE;

    CT_RETURN_IFERR(sql_push(stmt, CT_MAX_ROW_SIZE, (void **)&buf));
    row_assist_t ra;
    row_init(&ra, buf, CT_MAX_ROW_SIZE, HASH_GROUP_COL_COUNT);
    if (sql_put_row_value(stmt, NULL, &ra, value->type, value) != CT_SUCCESS) {
        CTSQL_POP(stmt);
        return CT_ERROR;
    }

    if (sql_put_row_value(stmt, NULL, &ra, var_aggr_id.type, &var_aggr_id) != CT_SUCCESS) {
        CTSQL_POP(stmt);
        return CT_ERROR;
    }

    if (sql_put_row_value(stmt, NULL, &ra, var_key.type, &var_key) != CT_SUCCESS) {
        CTSQL_POP(stmt);
        return CT_ERROR;
    }

    if (vm_hash_table_insert2(found, &ctx->hash_segment, table, buf, ra.head->size) != CT_SUCCESS) {
        CTSQL_POP(stmt);
        return CT_ERROR;
    }

    CTSQL_POP(stmt);
    return CT_SUCCESS;
}

static status_t sql_group_init_aggr_distinct(group_aggr_assist_t *ga)
{
    if (GA_AGGR_NODE(ga)->dis_info.need_distinct) {
        variant_t dis_value;
        group_data_t *group_data = GA_CURSOR(ga)->exec_data.group;
        group_ctx_t *ctx = ga->group_ctx;
        var_copy(ga->value, &dis_value);
        if (GA_AGGR_TYPE(ga) == AGGR_TYPE_COUNT) {
            CT_RETURN_IFERR(
                sql_aggr_get_cntdis_value(ctx->stmt, ctx->group_p->cntdis_columns, GA_AGGR_NODE(ga), &dis_value));
            sql_keep_stack_variant(ctx->stmt, &dis_value);
        }
        if (ctx->hash_dist_tables == NULL) {
            CT_RETURN_IFERR(sql_init_hash_dist_tables(ctx->stmt, ctx->cursor, ctx));
        }
        bool32 found = CT_FALSE;
        CT_RETURN_IFERR(sql_hash_group_insert(ctx, &ctx->hash_dist_tables[group_data->curr_group], ga->row_head,
            ga->index, &dis_value, &found));
    }
    return CT_SUCCESS;
}

static status_t sql_group_init_aggr_buf(group_ctx_t *group_ctx, const char *old_buf, uint32 index)
{
    variant_t *value = group_ctx->str_aggr_val;
    expr_node_t *aggr_node = group_ctx->aggr_node[index];
    const sql_func_t *func = GET_AGGR_FUNC(aggr_node);
    row_head_t *row_head = (row_head_t *)old_buf;
    aggr_var_t *aggr_var = (aggr_var_t *)(old_buf + row_head->size);
    uint64 avg_count = 1;
    uint32 vmid = CT_INVALID_ID32;

    if (SECUREC_UNLIKELY(group_ctx->group_by_phase == GROUP_BY_COLLECT)) { // for par group
        *value = aggr_var[index].var;
        if (func->aggr_type == AGGR_TYPE_AVG || func->aggr_type == AGGR_TYPE_CUME_DIST) {
            avg_count = GET_AGGR_VAR_AVG(&aggr_var[index])->ex_avg_count;
        }
        if (CT_IS_VARLEN_TYPE(value->type) && !value->is_null && value->v_text.len != 0) {
            mtrl_rowid_t rowid = GET_AGGR_VAR_STR_EX(&aggr_var[index])->str_result;
            vm_page_t *page = NULL;
            vmid = rowid.vmid;
            CT_RETURN_IFERR(vm_open(group_ctx->stmt->mtrl.session, group_ctx->stmt->mtrl.pool, vmid, &page));
            value->v_text.str =
                MTRL_GET_ROW((mtrl_page_t *)page->data, rowid.slot) + sizeof(row_head_t) + sizeof(uint16);
        }
    } else {
        if (sql_exec_expr_node(group_ctx->stmt, AGGR_VALUE_NODE(func, aggr_node), value) != CT_SUCCESS) {
            return CT_ERROR;
        }
        sql_keep_stack_variant(group_ctx->stmt, value);
    }

    if (value->type != aggr_node->datatype && aggr_node->datatype != CT_TYPE_UNKNOWN &&
        !sql_group_aggr_func(func->aggr_type)->ignore_type) {
        CT_RETURN_IFERR(sql_convert_variant(group_ctx->stmt, value, aggr_node->datatype));
    }

    group_aggr_assist_t ga;
    SQL_INIT_GROUP_AGGR_ASSIST(&ga, func->aggr_type, group_ctx, aggr_node, &aggr_var[index], row_head, index, value,
        avg_count);
    CT_RETURN_IFERR(sql_group_init_aggr_distinct(&ga));
    CT_RETURN_IFERR(sql_group_aggr_func(func->aggr_type)->init(&ga));
    if (SECUREC_UNLIKELY(vmid != CT_INVALID_ID32)) {
        vm_close(group_ctx->stmt->mtrl.session, group_ctx->stmt->mtrl.pool, vmid, VM_ENQUE_TAIL);
    }
    return CT_SUCCESS;
}

static status_t sql_group_init_aggrs_buf(group_ctx_t *ctx, const char *old_buf, uint32 old_size)
{
    uint32 i;
    galist_t *aggrs = ctx->group_p->aggrs;

    CTSQL_SAVE_STACK(ctx->stmt);
    for (i = 0; i < aggrs->count; i++) {
        if (sql_group_init_aggr_buf(ctx, old_buf, i) != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(ctx->stmt);
            return CT_ERROR;
        }

        CTSQL_RESTORE_STACK(ctx->stmt);
    }

    return CT_SUCCESS;
}

static status_t sql_group_init_aggrs_buf_pivot(group_ctx_t *group_ctx, const char *old_buf, uint32 old_size)
{
    row_head_t *row_head = (row_head_t *)old_buf;
    aggr_var_t *aggr_var = (aggr_var_t *)(old_buf + row_head->size);
    int32 index;
    aggr_assist_t aa;
    SQL_INIT_AGGR_ASSIST(&aa, group_ctx->stmt, group_ctx->cursor);

    CT_RETURN_IFERR(sql_match_pivot_list(group_ctx->stmt, group_ctx->group_p->pivot_assist->for_expr,
        group_ctx->group_p->pivot_assist->in_expr, &index));
    CTSQL_SAVE_STACK(group_ctx->stmt);
    if (index >= 0) {
        uint32 start_pos = (uint32)index * group_ctx->group_p->pivot_assist->aggr_count;
        for (uint32 i = 0; i < group_ctx->group_p->pivot_assist->aggr_count; i++) {
            if (sql_group_init_aggr_buf(group_ctx, old_buf, start_pos + i) != CT_SUCCESS) {
                CTSQL_RESTORE_STACK(group_ctx->stmt);
                return CT_ERROR;
            }
            CTSQL_RESTORE_STACK(group_ctx->stmt);
        }
    }
    for (uint32 i = 0; i < group_ctx->group_p->aggrs->count; i++) {
        if (group_ctx->group_p->pivot_assist->aggr_count == 0) {
            CT_THROW_ERROR(ERR_ZERO_DIVIDE);
            knl_panic(0);
        } else {
            if (i / group_ctx->group_p->pivot_assist->aggr_count != index) {
                aa.aggr_node = (expr_node_t *)cm_galist_get(group_ctx->group_p->aggrs, i);
                aa.aggr_type = GET_AGGR_FUNC(aa.aggr_node)->aggr_type;
                aggr_var[i].var.type = CT_TYPE_UNKNOWN;
                CT_RETURN_IFERR(sql_aggr_reset(&aa, &aggr_var[i]));
                CT_RETURN_IFERR(sql_aggr_init_var(&aa, &aggr_var[i]));
            }
        }
    }

    return CT_SUCCESS;
}

static inline status_t sql_hash_group_aggr_concat(group_ctx_t *group_ctx, expr_node_t *aggr_node, aggr_var_t *old_aggr_var,
    variant_t *value)
{
    variant_t sep_var;
    variant_t *p_sep_var = &sep_var;
    sql_stmt_t *stmt = group_ctx->stmt;

    if (value->is_null) {
        return CT_SUCCESS;
    }

    if (old_aggr_var->var.is_null) {
        return sql_hash_group_save_aggr_str_value(group_ctx, old_aggr_var, value);
    }

    CT_RETURN_IFERR(sql_group_exec_sepvar(stmt, aggr_node, p_sep_var));

    uint32 len = old_aggr_var->var.v_text.len + value->v_text.len;
    if (!sep_var.is_null && sep_var.v_text.len > 0) {
        len += sep_var.v_text.len;
    }

    CT_RETURN_IFERR(sql_hash_group_ensure_str_buf(group_ctx, old_aggr_var, len, CT_TRUE));
    CT_RETURN_IFERR(sql_hash_group_convert_rowid_to_str(group_ctx, stmt, old_aggr_var, CT_FALSE));

    char *cur_buffer = old_aggr_var->var.v_text.str + old_aggr_var->var.v_text.len;
    uint32 remain_len = len - old_aggr_var->var.v_text.len;
    if (!sep_var.is_null && sep_var.v_text.len > 0) {
        MEMS_RETURN_IFERR(memcpy_s(cur_buffer, remain_len, sep_var.v_text.str, sep_var.v_text.len));

        cur_buffer += sep_var.v_text.len;
        remain_len -= sep_var.v_text.len;
    }
    /* hit scenario: group_concat '1,1,2,' aggr_node is zero len string */
    if (value->v_text.len != 0) {
        MEMS_RETURN_IFERR(memcpy_s(cur_buffer, remain_len, value->v_text.str, value->v_text.len));
    }

    old_aggr_var->var.v_text.len = len;

    return CT_SUCCESS;
}

static status_t sql_hash_group_decode_concat_sort_row(sql_stmt_t *stmt, expr_node_t *aggr_node, aggr_var_t *aggr_var,
    text_buf_t *sort_concat)
{
    char *buf = NULL;
    uint32 size;
    uint32 col_id = aggr_node->sort_items->count;
    mtrl_row_t row;
    row.data = aggr_var->var.v_text.str;
    cm_decode_row(row.data, row.offsets, row.lens, NULL);

    if (row.lens[col_id] == 0) {
        aggr_var->var.v_text.len = 0;
        return CT_SUCCESS;
    }

    buf = sort_concat->str + sort_concat->len;
    size = sort_concat->max_size - sort_concat->len;
    sort_concat->len += row.lens[col_id];

    MEMS_RETURN_IFERR(memcpy_s(buf, size, row.data + row.offsets[col_id], row.lens[col_id]));
    aggr_var->var.v_text.str = buf;
    aggr_var->var.v_text.len = row.lens[col_id];

    return CT_SUCCESS;
}

static status_t sql_hash_group_aggr_concat_sort_value(sql_stmt_t *stmt, mtrl_segment_t *segment, expr_node_t *aggr_node,
    aggr_var_t *aggr_var)
{
    char *buf = NULL;
    char *cur_buf = NULL;
    mtrl_row_t row;
    variant_t sep_var;
    uint32 len, remain_len, col_id, slot;
    bool32 is_first = CT_TRUE;
    bool32 has_separator = CT_FALSE;
    mtrl_page_t *page = NULL;
    vm_page_t *temp_page = NULL;
    uint32 id, next;
    vm_ctrl_t *ctrl = NULL;
    errno_t err;

    CT_RETURN_IFERR(sql_push(stmt, CT_MAX_ROW_SIZE, (void **)&buf));

    len = 0;
    cur_buf = buf;
    remain_len = CT_MAX_ROW_SIZE;
    col_id = aggr_node->sort_items->count;

    CT_RETURN_IFERR(sql_group_exec_sepvar(stmt, aggr_node, &sep_var));
    has_separator = (bool32)(!sep_var.is_null && sep_var.v_text.len > 0);

    id = segment->vm_list.first;
    while (id != CT_INVALID_ID32) {
        ctrl = vm_get_ctrl(stmt->mtrl.pool, id);
        next = ctrl->next;

        CT_RETURN_IFERR(mtrl_open_page(&stmt->mtrl, id, &temp_page));
        page = (mtrl_page_t *)temp_page->data;

        // the first row is mtrl_part_t for merge sort
        slot = (segment->vm_list.count > 1 && id == segment->vm_list.first) ? 1 : 0;
        for (; slot < (uint32)page->rows; ++slot) {
            row.data = MTRL_GET_ROW(page, slot);
            cm_decode_row(row.data, row.offsets, row.lens, NULL);

            len += row.lens[col_id];

            if (!is_first && has_separator) {
                len += sep_var.v_text.len;
            }
            if (len > CT_MAX_ROW_SIZE) {
                mtrl_close_page(&stmt->mtrl, id);
                CT_THROW_ERROR(ERR_EXCEED_MAX_ROW_SIZE, len, CT_MAX_ROW_SIZE);
                return CT_ERROR;
            }
            if (!is_first && has_separator) {
                err = memcpy_s(cur_buf, remain_len, sep_var.v_text.str, sep_var.v_text.len);
                if (err != EOK) {
                    mtrl_close_page(&stmt->mtrl, id);
                    CT_THROW_ERROR(ERR_SYSTEM_CALL, err);
                    return CT_ERROR;
                }
                cur_buf += sep_var.v_text.len;
                remain_len -= sep_var.v_text.len;
            }
            err = memcpy_s(cur_buf, remain_len, row.data + row.offsets[col_id], row.lens[col_id]);
            if (err != EOK) {
                mtrl_close_page(&stmt->mtrl, id);
                CT_THROW_ERROR(ERR_SYSTEM_CALL, err);
                return CT_ERROR;
            }
            cur_buf += row.lens[col_id];
            remain_len -= row.lens[col_id];
            is_first = CT_FALSE;
        }
        mtrl_close_page(&stmt->mtrl, id);
        id = next;
    }

    // save result buf into first page
    vm_free_list(stmt->mtrl.session, stmt->mtrl.pool, &segment->vm_list);
    CT_RETURN_IFERR(mtrl_extend_segment(&stmt->mtrl, segment));
    CT_RETURN_IFERR(mtrl_open_page(&stmt->mtrl, segment->vm_list.first, &segment->curr_page));
    page = (mtrl_page_t *)segment->curr_page->data;
    mtrl_init_page(page, segment->vm_list.first);

    uint32 *dir = MTRL_GET_DIR(page, 0);
    *dir = page->free_begin;
    char *ptr = (char *)page + page->free_begin;
    *(uint32 *)ptr = len;
    if (len > 0) {
        MEMS_RETURN_IFERR(memcpy_s(ptr + sizeof(uint32), CT_MAX_ROW_SIZE, buf, len));
        page->free_begin += (len + sizeof(uint32));
    }
    return CT_SUCCESS;
}

status_t sql_hash_group_calc_listagg(sql_stmt_t *stmt, sql_cursor_t *cursor, expr_node_t *aggr_node,
    aggr_var_t *aggr_var, text_buf_t *sort_concat)
{
    char *buf = NULL;
    uint32 size;
    mtrl_page_t *page = NULL;
    mtrl_segment_t *segment = NULL;
    status_t status;

    uint32 seg_id = cursor->mtrl.sort_seg;
    aggr_group_concat_t *aggr_group_concat = GET_AGGR_VAR_GROUPCONCAT(aggr_var);
    aggr_var->var.type = CT_TYPE_STRING;

    if (aggr_group_concat->sort_rid.vmid == CT_INVALID_ID32) {
        return sql_hash_group_decode_concat_sort_row(stmt, aggr_node, aggr_var, sort_concat);
    }

    CT_RETURN_IFERR(sql_get_segment_in_vm(stmt, seg_id, &aggr_group_concat->sort_rid, &segment));
    CT_RETURN_IFERR(mtrl_open_page(&stmt->mtrl, segment->vm_list.first, &segment->curr_page));
    page = (mtrl_page_t *)segment->curr_page->data;

    if (page->rows > 0) {
        mtrl_close_segment2(&stmt->mtrl, segment);
        CT_RETURN_IFERR(mtrl_sort_segment2(&stmt->mtrl, segment));

        CTSQL_SAVE_STACK(stmt);
        status = sql_hash_group_aggr_concat_sort_value(stmt, segment, aggr_node, aggr_var);
        CTSQL_RESTORE_STACK(stmt);

        if (status != CT_SUCCESS) {
            return CT_ERROR;
        }
        page = (mtrl_page_t *)segment->curr_page->data;
    }

    char *row_buf = MTRL_GET_ROW(page, 0);
    aggr_var->var.v_text.len = *(uint32 *)row_buf;

    if (aggr_var->var.v_text.len == 0) {
        mtrl_close_segment2(&stmt->mtrl, segment);
        return CT_SUCCESS;
    }

    buf = sort_concat->str + sort_concat->len;
    size = sort_concat->max_size - sort_concat->len;
    sort_concat->len += aggr_var->var.v_text.len;
    errno_t errcode = memcpy_s(buf, size, row_buf + sizeof(uint32), aggr_var->var.v_text.len);
    if (errcode != EOK) {
        mtrl_close_segment2(&stmt->mtrl, segment);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return CT_ERROR;
    }
    aggr_var->var.v_text.str = buf;

    mtrl_close_segment2(&stmt->mtrl, segment);
    return CT_SUCCESS;
}

static status_t inline sql_get_value_in_page(sql_stmt_t *stmt, ct_type_t datatype, mtrl_page_t *page, uint32 slot,
    variant_t *value)
{
    mtrl_row_t row;
    var_column_t v_col;

    v_col.datatype = datatype;
    v_col.is_array = CT_FALSE;
    v_col.ss_end = v_col.ss_start = 0;

    row.data = MTRL_GET_ROW(page, slot);
    cm_decode_row(row.data, row.offsets, row.lens, NULL);
    return sql_get_row_value(stmt, MT_CDATA(&row, 0), MT_CSIZE(&row, 0), &v_col, value, CT_TRUE);
}

static status_t inline sql_calc_median_value(sql_stmt_t *stmt, variant_t *var1, variant_t *var2, variant_t *result)
{
    variant_t v_sub, v_rows, v_half;
    v_rows.type = CT_TYPE_INTEGER;
    v_rows.v_int = 2;
    v_rows.is_null = CT_FALSE;
    CT_RETURN_IFERR(opr_exec(OPER_TYPE_SUB, SESSION_NLS(stmt), var2, var1, &v_sub));
    CT_RETURN_IFERR(opr_exec(OPER_TYPE_DIV, SESSION_NLS(stmt), &v_sub, &v_rows, &v_half));
    CT_RETURN_IFERR(opr_exec(OPER_TYPE_ADD, SESSION_NLS(stmt), var1, &v_half, result));
    return CT_SUCCESS;
}

static status_t sql_hash_group_calc_median_value(sql_stmt_t *stmt, mtrl_segment_t *seg, expr_node_t *aggr_node,
    aggr_var_t *aggr_var)
{
    uint32 next, slot, begin_slot;
    uint32 offset = 0;
    uint32 id = seg->vm_list.first;
    mtrl_page_t *page = NULL;
    vm_ctrl_t *ctrl = NULL;
    aggr_median_t *aggr_median = GET_AGGR_VAR_MEDIAN(aggr_var);
    uint32 begin_pos = (uint32)(aggr_median->median_count + 1) / 2 - 1;
    uint32 end_pos = (uint32)aggr_median->median_count / 2;
    variant_t var1, var2;

    ct_type_t type = TREE_DATATYPE(aggr_node->argument);
    if (type == CT_TYPE_UNKNOWN) {
        type = aggr_var->var.type;
    }

    while (id != CT_INVALID_ID32) {
        ctrl = vm_get_ctrl(stmt->mtrl.pool, id);
        next = ctrl->next;

        CT_RETURN_IFERR(vm_open(stmt->mtrl.session, stmt->mtrl.pool, id, &seg->curr_page));
        page = (mtrl_page_t *)seg->curr_page->data;

        // the first row is mtrl_part_t for merge sort
        begin_slot = (seg->vm_list.count > 1 && id == seg->vm_list.first) ? 1 : 0;
        begin_pos += begin_slot;
        end_pos += begin_slot;

        if (begin_pos >= offset + page->rows) {
            offset += page->rows;
            vm_close(stmt->mtrl.session, stmt->mtrl.pool, id, VM_ENQUE_TAIL);
            seg->curr_page = NULL;
            id = next;
            continue;
        }

        slot = begin_pos - offset;
        CT_RETURN_IFERR(sql_get_value_in_page(stmt, type, page, slot, &var1));

        // read next row
        if (begin_pos == end_pos) {
            var_copy(&var1, &aggr_var->var);
            vm_close(stmt->mtrl.session, stmt->mtrl.pool, id, VM_ENQUE_TAIL);
            seg->curr_page = NULL;
            break;
        }

        // next middle value located in the next page
        if (end_pos >= offset + page->rows) {
            offset += page->rows;
            vm_close(stmt->mtrl.session, stmt->mtrl.pool, id, VM_ENQUE_TAIL);
            CT_RETURN_IFERR(vm_open(stmt->mtrl.session, stmt->mtrl.pool, next, &seg->curr_page));
            page = (mtrl_page_t *)seg->curr_page->data;
            id = next;
        }

        slot = end_pos - offset;
        CT_RETURN_IFERR(sql_get_value_in_page(stmt, type, page, slot, &var2));
        vm_close(stmt->mtrl.session, stmt->mtrl.pool, id, VM_ENQUE_TAIL);
        seg->curr_page = NULL;

        CT_RETURN_IFERR(sql_calc_median_value(stmt, &var1, &var2, &aggr_var->var));
        break;
    }

    // save result buf into first page
    vm_free_list(stmt->mtrl.session, stmt->mtrl.pool, &seg->vm_list);
    return CT_SUCCESS;
}

status_t sql_hash_group_calc_median(sql_stmt_t *stmt, sql_cursor_t *cursor, expr_node_t *aggr_node,
    aggr_var_t *aggr_var)
{
    mtrl_segment_t *segment = NULL;
    aggr_median_t *aggr_median = GET_AGGR_VAR_MEDIAN(aggr_var);

    if (aggr_median->sort_rid.vmid == CT_INVALID_ID32) {
        return CT_SUCCESS;
    }

    uint32 seg_id = cursor->mtrl.sort_seg;
    CT_RETURN_IFERR(sql_get_segment_in_vm(stmt, seg_id, &aggr_median->sort_rid, &segment));
    CT_RETURN_IFERR(mtrl_sort_segment2(&stmt->mtrl, segment));
    CT_RETURN_IFERR(sql_hash_group_calc_median_value(stmt, segment, aggr_node, aggr_var));
    aggr_median->sort_rid.vmid = CT_INVALID_ID32;
    return CT_SUCCESS;
}

status_t sql_hash_group_mtrl_insert_row(sql_stmt_t *stmt, uint32 sort_seg, expr_node_t *aggr_node, aggr_var_t *var,
    char *row)
{
    status_t status;
    mtrl_rowid_t rid;
    mtrl_rowid_t *sort_rid = NULL;
    mtrl_page_t *page = NULL;
    mtrl_segment_t *seg = NULL;
    char *type_buf = NULL;

    if (var->aggr_type == AGGR_TYPE_GROUP_CONCAT) {
        sort_rid = &GET_AGGR_VAR_GROUPCONCAT(var)->sort_rid;
        type_buf = GET_AGGR_VAR_GROUPCONCAT(var)->type_buf;
    } else if (var->aggr_type == AGGR_TYPE_MEDIAN) {
        sort_rid = &GET_AGGR_VAR_MEDIAN(var)->sort_rid;
        type_buf = GET_AGGR_VAR_MEDIAN(var)->type_buf;
    } else {
        CT_THROW_ERROR(ERR_ASSERT_ERROR, "var->aggr_type is AGGR_TYPE_GROUP_CONCAT or AGGR_TYPE_MEDIAN");
        return CT_ERROR;
    }

    if (sort_rid->vmid == CT_INVALID_ID32) {
        CT_RETURN_IFERR(sql_alloc_segment_in_vm(stmt, sort_seg, &seg, sort_rid));
        mtrl_init_segment(seg, MTRL_SEGMENT_CONCAT_SORT, aggr_node->sort_items);
        CT_RETURN_IFERR(mtrl_extend_segment(&stmt->mtrl, seg));
        CT_RETURN_IFERR(mtrl_open_page(&stmt->mtrl, seg->vm_list.last, &seg->curr_page));
        page = (mtrl_page_t *)seg->curr_page->data;
        mtrl_init_page(page, seg->vm_list.last);
        seg->pending_type_buf = type_buf;
        // update median pending buffer
        if (var->aggr_type == AGGR_TYPE_MEDIAN && aggr_node->datatype == CT_TYPE_UNKNOWN) {
            *(ct_type_t *)(seg->pending_type_buf + PENDING_HEAD_SIZE) = var->var.type;
        }
    } else {
        CT_RETURN_IFERR(sql_get_segment_in_vm(stmt, sort_seg, sort_rid, &seg));
        CT_RETURN_IFERR(mtrl_open_page(&stmt->mtrl, seg->vm_list.last, &seg->curr_page));
    }

    status = mtrl_insert_row2(&stmt->mtrl, seg, row, &rid);

    mtrl_close_page(&stmt->mtrl, seg->vm_list.last);
    seg->curr_page = NULL;

    return status;
}

status_t sql_hash_group_make_sort_row(sql_stmt_t *stmt, expr_node_t *aggr_node, row_assist_t *ra, variant_t *value)
{
    uint32 i;
    variant_t sort_var;
    sort_item_t *sort_item = NULL;

    // make sort rows
    for (i = 0; i < aggr_node->sort_items->count; ++i) {
        sort_item = (sort_item_t *)cm_galist_get(aggr_node->sort_items, i);
        CT_RETURN_IFERR(sql_exec_expr(stmt, sort_item->expr, &sort_var));
        CT_RETURN_IFERR(sql_put_row_value(stmt, NULL, ra, sort_var.type, &sort_var));
    }

    // add aggr value row
    return sql_put_row_value(stmt, NULL, ra, CT_TYPE_STRING, value);
}

static status_t sql_group_insert_listagg_value(group_ctx_t *ctx, expr_node_t *aggr_node, aggr_var_t *aggr_var,
    variant_t *value)
{
    status_t status = CT_ERROR;
    char *buf = NULL;
    row_assist_t ra;
    variant_t sort_var;
    sql_cursor_t *cursor = (sql_cursor_t *)ctx->cursor;
    mtrl_context_t *mtrl = &ctx->stmt->mtrl;

    if (value->is_null) {
        return CT_SUCCESS;
    }

    if (cursor->mtrl.sort_seg == CT_INVALID_ID32) {
        CT_RETURN_IFERR(mtrl_create_segment(mtrl, MTRL_SEGMENT_SORT_SEG, NULL, &cursor->mtrl.sort_seg));
        CT_RETURN_IFERR(mtrl_open_segment(mtrl, cursor->mtrl.sort_seg));
    }

    CTSQL_SAVE_STACK(ctx->stmt);

    CT_RETURN_IFERR(sql_push(ctx->stmt, CT_MAX_ROW_SIZE, (void **)&buf));
    row_init(&ra, buf, CT_MAX_ROW_SIZE, aggr_node->sort_items->count + 1);

    do {
        // make sort rows
        CT_BREAK_IF_ERROR(sql_hash_group_make_sort_row(ctx->stmt, aggr_node, &ra, value));
        aggr_group_concat_t *aggr_group_concat = GET_AGGR_VAR_GROUPCONCAT(aggr_var);
        if (aggr_var->var.is_null) {
            // insert the first row into extra page
            sort_var.v_text.str = ra.buf;
            sort_var.v_text.len = ra.head->size;
            sort_var.is_null = CT_FALSE;
            sort_var.type = CT_TYPE_STRING;
            CT_BREAK_IF_ERROR(sql_hash_group_save_aggr_str_value(ctx, aggr_var, &sort_var));
            aggr_group_concat->total_len = value->v_text.len;
        } else {
            if (aggr_var->var.v_text.len > 0) {
                // read old value from vm
                CT_BREAK_IF_ERROR(sql_hash_group_convert_rowid_to_str(ctx, ctx->stmt, aggr_var, CT_FALSE));
                // insert the first row into mtrl page
                CT_BREAK_IF_ERROR(sql_hash_group_mtrl_insert_row(ctx->stmt, cursor->mtrl.sort_seg, aggr_node, aggr_var,
                    aggr_var->var.v_text.str));
                aggr_var->var.v_text.len = 0;
            }
            // check row size
            aggr_group_concat->total_len += value->v_text.len;
            if (aggr_group_concat->total_len > CT_MAX_ROW_SIZE) {
                CT_THROW_ERROR(ERR_EXCEED_MAX_ROW_SIZE, aggr_group_concat->total_len, CT_MAX_ROW_SIZE);
                break;
            }
            CT_BREAK_IF_ERROR(
                sql_hash_group_mtrl_insert_row(ctx->stmt, cursor->mtrl.sort_seg, aggr_node, aggr_var, buf));
        }
        status = CT_SUCCESS;
    } while (0);

    CTSQL_RESTORE_STACK(ctx->stmt);

    return status;
}

static status_t sql_group_insert_median_first_row(sql_stmt_t *stmt, uint32 sort_seg, expr_node_t *aggr_node,
    aggr_var_t *aggr_var)
{
    char *buf = NULL;
    row_assist_t ra;
    status_t status;
    ct_type_t type = TREE_DATATYPE(aggr_node->argument);
    if (type == CT_TYPE_UNKNOWN) {
        type = aggr_var->var.type;
    }

    CTSQL_SAVE_STACK(stmt);
    CT_RETURN_IFERR(sql_push(stmt, CT_MAX_ROW_SIZE, (void **)&buf));
    row_init(&ra, buf, CT_MAX_ROW_SIZE, 1);

    if (sql_put_row_value(stmt, NULL, &ra, type, &aggr_var->var) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }
    status = sql_hash_group_mtrl_insert_row(stmt, sort_seg, aggr_node, aggr_var, buf);
    CTSQL_RESTORE_STACK(stmt);
    return status;
}

static status_t sql_group_insert_median_value(group_ctx_t *ctx, expr_node_t *aggr_node, aggr_var_t *aggr_var,
    variant_t *value)
{
    status_t status = CT_ERROR;
    char *buf = NULL;
    row_assist_t ra;
    sql_cursor_t *cursor = (sql_cursor_t *)ctx->cursor;
    mtrl_context_t *mtrl = &ctx->stmt->mtrl;
    aggr_median_t *aggr_median = NULL;
    ct_type_t type = TREE_DATATYPE(aggr_node->argument);

    if (value->is_null) {
        return CT_SUCCESS;
    }
    if (type == CT_TYPE_UNKNOWN) {
        type = value->type;
    }

    if (cursor->mtrl.sort_seg == CT_INVALID_ID32) {
        CT_RETURN_IFERR(mtrl_create_segment(mtrl, MTRL_SEGMENT_SORT_SEG, NULL, &cursor->mtrl.sort_seg));
        CT_RETURN_IFERR(mtrl_open_segment(mtrl, cursor->mtrl.sort_seg));
    }

    CTSQL_SAVE_STACK(ctx->stmt);

    CT_RETURN_IFERR(sql_push(ctx->stmt, CT_MAX_ROW_SIZE, (void **)&buf));
    row_init(&ra, buf, CT_MAX_ROW_SIZE, 1);

    do {
        // make sort rows
        CT_BREAK_IF_ERROR(sql_put_row_value(ctx->stmt, NULL, &ra, type, value));

        if (aggr_var->var.is_null) {
            if (!CT_IS_NUMERIC_TYPE(value->type) && !CT_IS_DATETIME_TYPE(value->type)) {
                CT_THROW_ERROR(ERR_TYPE_MISMATCH, "NUMERIC", get_datatype_name_str(value->type));
                break;
            }
            var_copy(value, &aggr_var->var);
        } else {
            aggr_median = GET_AGGR_VAR_MEDIAN(aggr_var);
            if (aggr_median->sort_rid.vmid == CT_INVALID_ID32) {
                // insert the first row into mtrl page
                CT_BREAK_IF_ERROR(
                    sql_group_insert_median_first_row(ctx->stmt, cursor->mtrl.sort_seg, aggr_node, aggr_var));
            }
            CT_BREAK_IF_ERROR(
                sql_hash_group_mtrl_insert_row(ctx->stmt, cursor->mtrl.sort_seg, aggr_node, aggr_var, buf));
        }
        status = CT_SUCCESS;
    } while (0);

    CTSQL_RESTORE_STACK(ctx->stmt);

    return status;
}

static inline status_t sql_hash_group_copy_aggr_value(group_ctx_t *ctx, aggr_var_t *old_aggr_var, variant_t *value)
{
    switch (old_aggr_var->var.type) {
        case CT_TYPE_UINT32:
        case CT_TYPE_INTEGER:
        case CT_TYPE_BIGINT:
        case CT_TYPE_REAL:
        case CT_TYPE_NUMBER:
        case CT_TYPE_NUMBER2:
        case CT_TYPE_DECIMAL:
        case CT_TYPE_DATE:
        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
        case CT_TYPE_TIMESTAMP_TZ:
        case CT_TYPE_TIMESTAMP_LTZ:
        case CT_TYPE_INTERVAL_DS:
        case CT_TYPE_INTERVAL_YM:
        case CT_TYPE_BOOLEAN:
            old_aggr_var->var = *value;
            break;

        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
        case CT_TYPE_STRING:
        case CT_TYPE_BINARY:
        case CT_TYPE_VARBINARY:
        case CT_TYPE_RAW:
            return sql_hash_group_save_aggr_str_value(ctx, old_aggr_var, value);

        default:
            CT_SET_ERROR_MISMATCH_EX(old_aggr_var->var.type);
            return CT_ERROR;
    }

    return CT_SUCCESS;
}

static inline status_t sql_group_aggr_distinct(group_aggr_assist_t *ga, bool32 *found)
{
    (*found) = CT_FALSE;
    if (GA_AGGR_NODE(ga)->dis_info.need_distinct) {
        variant_t dis_value;
        var_copy(ga->value, &dis_value);
        group_ctx_t *ctx = ga->group_ctx;
        if (GA_AGGR_TYPE(ga) == AGGR_TYPE_COUNT) {
            expr_node_t *dis_node =
                (expr_node_t *)cm_galist_get(ctx->group_p->cntdis_columns, GA_AGGR_NODE(ga)->dis_info.group_id);
            CT_RETURN_IFERR(sql_exec_expr_node(ctx->stmt, dis_node, &dis_value));
            sql_keep_stack_variant(ctx->stmt, &dis_value);
        }
        uint32 curr_group = ((sql_cursor_t *)ctx->cursor)->exec_data.group->curr_group;
        CT_RETURN_IFERR(
            sql_hash_group_insert(ctx, &ctx->hash_dist_tables[curr_group], ga->row_head, ga->index, &dis_value, found));
    }
    return CT_SUCCESS;
}

static status_t sql_group_calc_aggr(group_aggr_assist_t *ga, const sql_func_t *func, const char *new_buf)
{
    GA_AVG_COUNT(ga) = 1;
    uint32 vmid = CT_INVALID_ID32;
    mtrl_context_t *ctx = &ga->group_ctx->stmt->mtrl;
    if (SECUREC_UNLIKELY(ga->group_ctx->group_by_phase == GROUP_BY_COLLECT)) { // for par group
        row_head_t *new_head = ((row_head_t *)new_buf);
        aggr_var_t *new_aggr_var = (aggr_var_t *)(new_buf + new_head->size);
        var_copy(&new_aggr_var[ga->index].var, ga->value);
        if (GA_AGGR_TYPE(ga) == AGGR_TYPE_AVG || GA_AGGR_TYPE(ga) == AGGR_TYPE_CUME_DIST) {
            GA_AVG_COUNT(ga) = GET_AGGR_VAR_AVG(&new_aggr_var[ga->index])->ex_avg_count;
        }
        if (CT_IS_VARLEN_TYPE(ga->value->type) && !ga->value->is_null && ga->value->v_text.len != 0) {
            mtrl_rowid_t rowid = GET_AGGR_VAR_STR_EX(&new_aggr_var[ga->index])->str_result;
            vm_page_t *page = NULL;
            vmid = rowid.vmid;
            CT_RETURN_IFERR(vm_open(ctx->session, ctx->pool, vmid, &page));
            ga->value->v_text.str =
                MTRL_GET_ROW((mtrl_page_t *)page->data, rowid.slot) + sizeof(row_head_t) + sizeof(uint16);
        }
    } else {
        if (sql_exec_expr_node(GA_STMT(ga), AGGR_VALUE_NODE(func, GA_AGGR_NODE(ga)), ga->value) != CT_SUCCESS) {
            return CT_ERROR;
        }
        sql_keep_stack_variant(GA_STMT(ga), ga->value);
    }

    if (ga->value->type != GA_AGGR_NODE(ga)->datatype && GA_AGGR_NODE(ga)->datatype != CT_TYPE_UNKNOWN &&
        !sql_group_aggr_func(GA_AGGR_TYPE(ga))->ignore_type) {
        if (sql_convert_variant(GA_STMT(ga), ga->value, GA_AGGR_NODE(ga)->datatype) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (ga->value->is_null && GA_AGGR_TYPE(ga) != AGGR_TYPE_ARRAY_AGG && GA_AGGR_TYPE(ga) != AGGR_TYPE_DENSE_RANK &&
        GA_AGGR_TYPE(ga) != AGGR_TYPE_RANK) {
        return CT_SUCCESS;
    }

    bool32 found = CT_FALSE;
    CT_RETURN_IFERR(sql_group_aggr_distinct(ga, &found));
    if (found) {
        return CT_SUCCESS;
    }
    CT_RETURN_IFERR(sql_group_aggr_func(GA_AGGR_TYPE(ga))->invoke(ga));
    if (SECUREC_UNLIKELY(vmid != CT_INVALID_ID32)) {
        vm_close(ctx->session, ctx->pool, vmid, VM_ENQUE_TAIL);
    }
    return CT_SUCCESS;
}

static status_t sql_group_calc_pivot(group_ctx_t *ctx, const char *new_buf, const char *old_buf)
{
    int32 index;
    uint32 i, start_pos;
    group_aggr_assist_t gp_assist;
    group_aggr_assist_t *ga = &gp_assist;

    CT_RETURN_IFERR(sql_match_pivot_list(ctx->stmt, ctx->group_p->pivot_assist->for_expr,
        ctx->group_p->pivot_assist->in_expr, &index));
    if (index < 0) {
        return CT_SUCCESS;
    }

    const sql_func_t *func = NULL;
    row_head_t *row_head = (row_head_t *)old_buf;
    aggr_var_t *old_aggr_var = (aggr_var_t *)(old_buf + row_head->size);
    SQL_INIT_GROUP_AGGR_ASSIST(ga, AGGR_TYPE_NONE, ctx, NULL, NULL, row_head, 0, ctx->str_aggr_val, 1);

    CTSQL_SAVE_STACK(ctx->stmt);
    start_pos = (uint32)index * ctx->group_p->pivot_assist->aggr_count;
    for (i = 0; i < ctx->group_p->pivot_assist->aggr_count; i++) {
        ga->index = start_pos + i;
        GA_AGGR_NODE(ga) = ctx->aggr_node[ga->index];
        func = GET_AGGR_FUNC(GA_AGGR_NODE(ga));
        GA_AGGR_TYPE(ga) = func->aggr_type;
        GA_AGGR_VAR(ga) = &old_aggr_var[ga->index];
        CT_RETURN_IFERR(sql_group_calc_aggr(ga, func, new_buf));
        CTSQL_RESTORE_STACK(ctx->stmt);
    }
    return CT_SUCCESS;
}

#define CHECK_AGGR_RESERVE_SIZE(ra, sz)                                   \
    do {                                                                  \
        if (SECUREC_UNLIKELY((sz) + (ra)->head->size > (ra)->max_size)) { \
            CT_THROW_ERROR(ERR_TOO_MANY_ARRG);                            \
            return CT_ERROR;                                              \
        }                                                                 \
    } while (0)


status_t sql_calc_aggr_reserve_size(row_assist_t *ra, group_ctx_t *group_ctx, uint32 *size)
{
    uint32 i;
    expr_node_t *aggr_node = NULL;
    const sql_func_t *func = NULL;
    group_plan_t *group_p = group_ctx->group_p;

    uint32 reserve_count = group_p->aggrs->count;
    uint32 fix_size = ra->head->size + reserve_count * sizeof(aggr_var_t);
    *size = fix_size;

    if (SECUREC_UNLIKELY(fix_size > ra->max_size)) {
        CT_THROW_ERROR(ERR_TOO_MANY_ARRG);
        return CT_ERROR;
    }

    if (group_ctx->row_buf_len != 0) {
        if (SECUREC_UNLIKELY(group_ctx->row_buf_len > (uint32)(ra->max_size - ra->head->size))) {
            CT_THROW_ERROR(ERR_TOO_MANY_ARRG);
            return CT_ERROR;
        }
        MEMS_RETURN_IFERR(memcpy_sp(ra->buf + ra->head->size, (uint32)(ra->max_size - ra->head->size), group_ctx->row_buf,
            group_ctx->row_buf_len));
        *size = ra->head->size + group_ctx->row_buf_len;
        return CT_SUCCESS;
    }

    aggr_var_t *a_var = (aggr_var_t *)(ra->buf + ra->head->size);
    for (i = 0; i < reserve_count; i++, a_var++) {
        aggr_node = group_ctx->aggr_node[i];
        func = GET_AGGR_FUNC(aggr_node);

        a_var->var.is_null = CT_TRUE;
        a_var->aggr_type = func->aggr_type;
        switch (func->aggr_type) {
            case AGGR_TYPE_GROUP_CONCAT:
                a_var->extra_size = sizeof(aggr_group_concat_t);
                a_var->extra_offset = (uint32)((ra->buf + *size) - (char *)a_var);
                *size += sizeof(aggr_group_concat_t);
                CHECK_AGGR_RESERVE_SIZE(ra, *size);
                aggr_group_concat_t *group_concat = GET_AGGR_VAR_GROUPCONCAT(a_var);
                group_concat->aggr_str.aggr_bufsize = 0;
                group_concat->aggr_str.str_result.vmid = CT_INVALID_ID32;
                group_concat->aggr_str.str_result.slot =
                    (uint32)((char *)group_concat + sizeof(aggr_group_concat_t) - (char *)a_var);
                *size += HASH_GROUP_AGGR_STR_RESERVE_SIZE;
                group_concat->sort_rid.vmid = CT_INVALID_ID32;
                group_concat->sort_rid.slot = CT_INVALID_ID32;
                break;
            case AGGR_TYPE_MIN:
            case AGGR_TYPE_MAX:
                if (CT_IS_VARLEN_TYPE(aggr_node->datatype) || aggr_node->datatype == CT_TYPE_UNKNOWN) {
                    a_var->extra_offset = (uint32)((ra->buf + *size) - (char *)a_var);
                    a_var->extra_size = sizeof(aggr_str_t);
                    *size += sizeof(aggr_str_t);
                    CHECK_AGGR_RESERVE_SIZE(ra, *size);
                    aggr_str_t *aggr_str = GET_AGGR_VAR_STR(a_var);

                    aggr_str->aggr_bufsize = 0;
                    aggr_str->str_result.vmid = CT_INVALID_ID32;
                    aggr_str->str_result.slot = (uint32)((char *)aggr_str + sizeof(aggr_str_t) - (char *)a_var);
                    *size += HASH_GROUP_AGGR_STR_RESERVE_SIZE;
                } else {
                    a_var->extra_offset = 0;
                    a_var->extra_size = 0;
                }
                break;
            case AGGR_TYPE_STDDEV:
            case AGGR_TYPE_STDDEV_POP:
            case AGGR_TYPE_STDDEV_SAMP:
            case AGGR_TYPE_VARIANCE:
            case AGGR_TYPE_VAR_POP:
            case AGGR_TYPE_VAR_SAMP:
                a_var->extra_offset = (uint32)((ra->buf + *size) - (char *)a_var);
                a_var->extra_size = sizeof(aggr_stddev_t);
                *size += sizeof(aggr_stddev_t);
                CHECK_AGGR_RESERVE_SIZE(ra, *size);
                break;
            case AGGR_TYPE_COVAR_POP:
            case AGGR_TYPE_COVAR_SAMP:
                a_var->extra_offset = (uint32)((ra->buf + *size) - (char *)a_var);
                a_var->extra_size = sizeof(aggr_covar_t);
                *size += sizeof(aggr_covar_t);
                CHECK_AGGR_RESERVE_SIZE(ra, *size);
                break;
            case AGGR_TYPE_CORR:
                a_var->extra_offset = (uint32)((ra->buf + *size) - (char *)a_var);
                a_var->extra_size = sizeof(aggr_corr_t);
                *size += sizeof(aggr_corr_t);
                CHECK_AGGR_RESERVE_SIZE(ra, *size);
                break;
            case AGGR_TYPE_AVG:
            case AGGR_TYPE_CUME_DIST:
            case AGGR_TYPE_AVG_COLLECT:
                a_var->extra_offset = (uint32)((ra->buf + *size) - (char *)a_var);
                a_var->extra_size = sizeof(aggr_avg_t);
                *size += sizeof(aggr_avg_t);
                CHECK_AGGR_RESERVE_SIZE(ra, *size);
                aggr_avg_t *aggr_avg = GET_AGGR_VAR_AVG(a_var);
                aggr_avg->ex_avg_count = 0;
                break;
            case AGGR_TYPE_MEDIAN:
                a_var->extra_offset = (uint32)((ra->buf + *size) - (char *)a_var);
                a_var->extra_size = sizeof(aggr_median_t);
                *size += sizeof(aggr_median_t);
                CHECK_AGGR_RESERVE_SIZE(ra, *size);
                aggr_median_t *aggr_median = GET_AGGR_VAR_MEDIAN(a_var);
                aggr_median->median_count = 0;
                aggr_median->sort_rid.vmid = CT_INVALID_ID32;
                aggr_median->sort_rid.slot = CT_INVALID_ID32;
                break;
            case AGGR_TYPE_DENSE_RANK:
                a_var->extra_offset = (uint32)((ra->buf + *size) - (char *)a_var);
                a_var->extra_size = sizeof(aggr_dense_rank_t);
                *size += sizeof(aggr_dense_rank_t);
                CHECK_AGGR_RESERVE_SIZE(ra, *size);
                /* fall-through */
            case AGGR_TYPE_RANK:
                a_var->var.is_null = CT_TRUE;
                a_var->var.type = CT_TYPE_INTEGER;
                VALUE(uint32, &a_var->var) = 1;
                break;
            default:
                a_var->extra_offset = 0;
                a_var->extra_size = 0;
                // AGGR_TYPE_SUM
                // AGGR_TYPE_COUNT
                // AGGR_TYPE_LAG
                break;
        };
    }

    group_ctx->row_buf_len = *size - ra->head->size;
    MEMS_RETURN_IFERR(memcpy_sp(group_ctx->row_buf, CT_MAX_ROW_SIZE, ra->buf + ra->head->size, group_ctx->row_buf_len));
    return CT_SUCCESS;
}

status_t sql_make_hash_group_row_new(sql_stmt_t *stmt, group_ctx_t *group_ctx, uint32 group_id, char *buf, uint32 *size,
    uint32 *key_size, char *pending_buffer)
{
    expr_tree_t *expr = NULL;
    variant_t value;
    row_assist_t ra;
    group_plan_t *group_p = group_ctx->group_p;
    galist_t *group_exprs = NULL;
    stmt->need_send_ddm = CT_FALSE;
    if (group_id < group_p->sets->count) {
        group_set_t *group_set = (group_set_t *)cm_galist_get(group_p->sets, group_id);
        group_exprs = group_set->items;
    } else {
        group_exprs = group_p->exprs;
    }

    row_init(&ra, buf, CT_MAX_ROW_SIZE, group_exprs->count);

    for (uint32 i = 0; i < group_exprs->count; i++) {
        expr = (expr_tree_t *)cm_galist_get(group_exprs, i);

        CT_RETURN_IFERR(sql_exec_expr(stmt, expr, &value));
        CT_RETURN_IFERR(sql_put_row_value(stmt, pending_buffer, &ra, expr->root->datatype, &value));
    }

    *key_size = (uint32)ra.head->size;
    stmt->need_send_ddm = CT_TRUE;
    return sql_calc_aggr_reserve_size(&ra, group_ctx, size);
}

status_t sql_mtrl_hash_group_new(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    bool32 found = CT_FALSE;
    bool32 eof = CT_FALSE;
    char *buf = NULL;
    status_t status = CT_SUCCESS;
    bool32 exist_record = CT_FALSE;
    uint32 size, key_size;
    group_data_t *group_data = cursor->exec_data.group;
    group_ctx_t *group_ctx = plan->type == PLAN_NODE_HASH_GROUP_PIVOT ? cursor->pivot_ctx : cursor->group_ctx;
    hash_segment_t *hash_seg = &group_ctx->hash_segment;

    CT_RETURN_IFERR(SQL_CURSOR_PUSH(stmt, cursor));
    CT_RETURN_IFERR(sql_push(stmt, CT_MAX_ROW_SIZE, (void **)&buf));

    CTSQL_SAVE_STACK(stmt);
    for (;;) {
        if (sql_fetch_query(stmt, cursor, plan->group.next, &eof) != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            status = CT_ERROR;
            break;
        }

        if (eof) {
            CTSQL_RESTORE_STACK(stmt);
            status = CT_SUCCESS;
            break;
        }

        exist_record = CT_TRUE;

        for (uint32 i = 0; i < group_data->group_count; i++) {
            group_data->curr_group = i;

            if (sql_make_hash_group_row_new(stmt, group_ctx, i, buf, &size, &key_size, cursor->mtrl.group.buf) !=
                CT_SUCCESS) {
                CTSQL_RESTORE_STACK(stmt);
                status = CT_ERROR;
                break;
            }

            if (vm_hash_table_insert2(&found, hash_seg, &group_ctx->hash_tables[i], buf, size) != CT_SUCCESS) {
                CTSQL_RESTORE_STACK(stmt);
                status = CT_ERROR;
                break;
            }
        }
        CT_BREAK_IF_ERROR(status);
        CTSQL_RESTORE_STACK(stmt);
    }
    CTSQL_POP(stmt);
    SQL_CURSOR_POP(stmt);

    group_ctx->empty = !exist_record;

    // the mtrl resource can be freed when group is done
    CT_RETURN_IFERR(sql_free_query_mtrl(stmt, cursor, plan->group.next));

    return status;
}

status_t sql_hash_group_open_cursor(sql_stmt_t *stmt, sql_cursor_t *cursor, group_ctx_t *ctx, uint32 group_id)
{
    bool32 found = CT_FALSE;
    hash_table_entry_t *hash_table = NULL;
    mtrl_cursor_t *mtrl_cursor = &cursor->mtrl.cursor;
    hash_segment_t *seg =
        (ctx->type == HASH_GROUP_PAR_TYPE) ? &ctx->hash_segment_par[group_id] : &ctx->hash_segment;

    if (ctx->empty) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    hash_table = &ctx->hash_tables[group_id];

    mtrl_cursor->type = MTRL_CURSOR_HASH_GROUP;
    ctx->oper_type = OPER_TYPE_FETCH;
    ctx->group_hash_scan_assit.scan_mode = HASH_FULL_SCAN;
    ctx->group_hash_scan_assit.buf = NULL;
    ctx->group_hash_scan_assit.size = 0;
    cursor->exec_data.group->curr_group = group_id;

    return vm_hash_table_open(seg, hash_table, &ctx->group_hash_scan_assit, &found, &ctx->iters[group_id]);
}

static status_t sql_init_hash_group_tables(sql_stmt_t *stmt, group_ctx_t *group_ctx)
{
    if (group_ctx->type == HASH_GROUP_PAR_TYPE) {
        return CT_SUCCESS;
    }
    uint32 hash_bucket_size;
    hash_segment_t *hash_seg = &group_ctx->hash_segment;
    hash_table_entry_t *hash_table = NULL;
    hash_table_iter_t *iter = NULL;
    oper_func_t i_oper_func = (group_ctx->type == HASH_GROUP_PIVOT_TYPE) ? group_pivot_i_oper_func : group_hash_i_oper_func;

    hash_bucket_size = (stmt->context->hash_bucket_size == 0) ? group_ctx->key_card : stmt->context->hash_bucket_size;

    for (uint32 i = 0; i < group_ctx->group_p->sets->count; i++) {
        hash_table = &group_ctx->hash_tables[i];
        iter = &group_ctx->iters[i];

        CT_RETURN_IFERR(vm_hash_table_alloc(hash_table, hash_seg, hash_bucket_size));
        CT_RETURN_IFERR(vm_hash_table_init(hash_seg, hash_table, i_oper_func, group_hash_q_oper_func, group_ctx));

        sql_init_hash_iter(iter, NULL);
    }
    group_ctx->group_hash_table = group_ctx->hash_tables[0];
    return CT_SUCCESS;
}

static void sql_init_group_ctx(group_ctx_t **group_ctx, group_type_t type, group_plan_t *group_p, uint32 key_card)
{
    (*group_ctx)->type = type;
    (*group_ctx)->group_p = group_p;
    (*group_ctx)->empty = CT_TRUE;
    (*group_ctx)->str_aggr_page_count = 0;
    (*group_ctx)->oper_type = OPER_TYPE_INSERT;
    (*group_ctx)->group_by_phase = GROUP_BY_INIT;
    (*group_ctx)->iters = NULL;
    (*group_ctx)->hash_dist_tables = NULL;
    (*group_ctx)->listagg_page = CT_INVALID_ID32;
    CM_INIT_TEXTBUF(&(*group_ctx)->concat_data, 0, NULL);
    (*group_ctx)->concat_typebuf = NULL;
    (*group_ctx)->row_buf_len = 0;
    (*group_ctx)->key_card = key_card;
    (*group_ctx)->par_hash_tab_count = 0;
    (*group_ctx)->aggr_node = NULL;
    (*group_ctx)->hash_segment_par = NULL;
}

static void sql_set_par_group_param(sql_stmt_t *stmt, sql_cursor_t *cursor, group_ctx_t **group_ctx, vm_page_t *vm_page,
    uint32 *offset)
{
    uint32 par_cons_num = MIN(stmt->context->parallel, CT_MAX_PAR_COMSUMER_SESSIONS);

    (*group_ctx)->par_hash_tab_count = par_cons_num;
    // buf for hash_segment_par
    (*group_ctx)->hash_segment_par = (hash_segment_t *)(vm_page->data + *offset);
    *offset += sizeof(hash_segment_t) * par_cons_num;
    // buf for empty_par
    (*group_ctx)->empty_par = (bool32 *)(vm_page->data + *offset);
    *offset += sizeof(bool32) * par_cons_num;
    for (uint32 i = 0; i < par_cons_num; i++) {
        (*group_ctx)->hash_segment_par[i].vm_list.count = 0;
        (*group_ctx)->hash_segment_par[i].pm_pool = NULL;
        (*group_ctx)->empty_par[i] = CT_TRUE;
    }
    cursor->par_ctx.par_parallel = (*group_ctx)->group_p->multi_prod ? (par_cons_num + par_cons_num) : (par_cons_num + 1);
    cursor->exec_data.group->group_count = (*group_ctx)->par_hash_tab_count;
}

status_t sql_alloc_hash_group_ctx(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, group_type_t type,
    uint32 key_card)
{
    uint32 vmid;
    vm_page_t *vm_page = NULL;
    group_plan_t *group_p = (plan->type == PLAN_NODE_HASH_MTRL) ? &plan->hash_mtrl.group : &plan->group;
    vmc_t *vmc = (plan->type == PLAN_NODE_HASH_MTRL) ? &stmt->vmc : &cursor->vmc;
    uint32 offset = (plan->type == PLAN_NODE_HASH_MTRL) ? sizeof(hash_mtrl_ctx_t) : sizeof(group_ctx_t);
    group_ctx_t **group_ctx =
        (plan->type == PLAN_NODE_HASH_MTRL) ? (group_ctx_t **)(&cursor->hash_mtrl_ctx) : &cursor->group_ctx;

    CT_RETURN_IFERR(sql_init_group_exec_data(stmt, cursor, group_p));
    CT_RETURN_IFERR(vm_alloc(KNL_SESSION(stmt), KNL_SESSION(stmt)->temp_pool, &vmid));

    if (vm_open(KNL_SESSION(stmt), KNL_SESSION(stmt)->temp_pool, vmid, &vm_page) != CT_SUCCESS) {
        vm_free(KNL_SESSION(stmt), KNL_SESSION(stmt)->temp_pool, vmid);
        return CT_ERROR;
    }
    *group_ctx = (group_ctx_t *)vm_page->data;
    (*group_ctx)->vm_id = vmid;
    (*group_ctx)->cursor = cursor;
    (*group_ctx)->stmt = stmt;
    sql_init_group_ctx(group_ctx, type, group_p, key_card);

    // buf for aggr_pages
    (*group_ctx)->str_aggr_pages = (uint32 *)((char *)vm_page->data + offset);
    offset += sizeof(uint32) * group_p->aggrs->count;

    // buf for aggr_value
    (*group_ctx)->str_aggr_val = (variant_t *)(vm_page->data + offset);
    offset += sizeof(variant_t) * (FO_VAL_MAX - 1);
    mtrl_init_segment(&(*group_ctx)->extra_data, MTRL_SEGMENT_EXTRA_DATA, NULL);

    if (type == HASH_GROUP_PAR_TYPE) {
        sql_set_par_group_param(stmt, cursor, group_ctx, vm_page, &offset);
    } else {
        vm_hash_segment_init(KNL_SESSION(stmt), stmt->mtrl.pool, &(*group_ctx)->hash_segment, PMA_POOL, HASH_PAGES_HOLD,
            HASH_AREA_SIZE);
    }

    // buf for hash_tables
    (*group_ctx)->hash_tables = (hash_table_entry_t *)(vm_page->data + offset);
    offset += sizeof(hash_table_entry_t) * cursor->exec_data.group->group_count;

    // buf for iters
    (*group_ctx)->iters = (hash_table_iter_t *)(vm_page->data + offset);
    offset += sizeof(hash_table_iter_t) * cursor->exec_data.group->group_count;

    // buf for row_buf
    (*group_ctx)->row_buf = (char *)vm_page->data + offset;

    if (CT_VMEM_PAGE_SIZE - CT_MAX_ROW_SIZE < offset) {
        CT_THROW_ERROR(ERR_TOO_MANY_ARRG);
        return CT_ERROR;
    }
    CT_RETURN_IFERR(sql_cache_aggr_node(vmc, *group_ctx));
    return sql_init_hash_group_tables(stmt, *group_ctx);
}

void sql_free_group_ctx(sql_stmt_t *stmt, group_ctx_t *group_ctx)
{
    uint32 i = 0;

    for (i = 0; i < group_ctx->str_aggr_page_count; i++) {
        mtrl_close_page(&stmt->mtrl, group_ctx->str_aggr_pages[i]);
    }
    group_ctx->str_aggr_page_count = 0;

    if (group_ctx->extra_data.curr_page != NULL) {
        mtrl_close_page(&stmt->mtrl, group_ctx->extra_data.curr_page->vmid);
        group_ctx->extra_data.curr_page = NULL;
    }
    vm_free_list(KNL_SESSION(stmt), stmt->mtrl.pool, &group_ctx->extra_data.vm_list);

    sql_cursor_t *cursor = (sql_cursor_t *)group_ctx->cursor;
    if (cursor != NULL && cursor->mtrl.sort_seg != CT_INVALID_ID32) {
        mtrl_close_segment(&stmt->mtrl, cursor->mtrl.sort_seg);
        sql_free_segment_in_vm(stmt, cursor->mtrl.sort_seg);
        mtrl_release_segment(&stmt->mtrl, cursor->mtrl.sort_seg);
        cursor->mtrl.sort_seg = CT_INVALID_ID32;
    }

    if (group_ctx->type == SORT_GROUP_TYPE) {
        sql_btree_deinit(&group_ctx->btree_seg);
    } else if (group_ctx->type == HASH_GROUP_PAR_TYPE) {
	    knl_panic(0);
    } else {
        vm_hash_segment_deinit(&group_ctx->hash_segment);
    }

    if (group_ctx->listagg_page != CT_INVALID_ID32) {
        vm_free(&stmt->session->knl_session, stmt->session->knl_session.temp_pool, group_ctx->listagg_page);
        CM_INIT_TEXTBUF(&group_ctx->concat_data, 0, NULL);
    }
    group_ctx->concat_typebuf = NULL;
    vm_free(&stmt->session->knl_session, stmt->session->knl_session.temp_pool, group_ctx->vm_id);
}

status_t sql_execute_hash_group_new(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan_node)
{
    CT_RETURN_IFERR(sql_execute_query_plan(stmt, cursor, plan_node->group.next));
    if (cursor->eof) {
        return CT_SUCCESS;
    }

    uint32 key_card = sql_get_plan_hash_rows(stmt, plan_node);
    group_type_t type = (plan_node->type == PLAN_NODE_HASH_GROUP_PIVOT) ? HASH_GROUP_PIVOT_TYPE : HASH_GROUP_TYPE;
    CT_RETURN_IFERR(sql_alloc_hash_group_ctx(stmt, cursor, plan_node, type, key_card));
    cursor->mtrl.cursor.type = MTRL_CURSOR_HASH_GROUP;
    if (cursor->select_ctx != NULL && cursor->select_ctx->pending_col_count > 0) {
        CT_RETURN_IFERR(sql_group_mtrl_record_types(cursor, plan_node, &cursor->mtrl.group.buf));
    }

    if (sql_mtrl_hash_group_new(stmt, cursor, plan_node) != CT_SUCCESS) {
        mtrl_close_segment2(&stmt->mtrl, &cursor->group_ctx->extra_data);
        return CT_ERROR;
    }
    mtrl_close_segment2(&stmt->mtrl, &cursor->group_ctx->extra_data);
    return sql_hash_group_open_cursor(stmt, cursor, cursor->group_ctx, 0);
}

status_t sql_fetch_hash_group_new(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof)
{
    status_t ret = CT_SUCCESS;
    group_data_t *group_data = cursor->exec_data.group;
    uint32 curr_group = group_data->curr_group;
    uint32 group_count = group_data->group_count;
    hash_table_entry_t *hash_table = NULL;
    hash_table_iter_t *iter = NULL;
    group_ctx_t *ctx = plan->type == PLAN_NODE_HASH_GROUP_PIVOT ? cursor->pivot_ctx : cursor->group_ctx;
    hash_segment_t *hash_seg = &ctx->hash_segment;

    do {
        *eof = CT_FALSE;
        if (ctx->type == HASH_GROUP_PAR_TYPE) {
            hash_seg = &ctx->hash_segment_par[curr_group];
        }
        hash_table = &ctx->hash_tables[curr_group];
        iter = &ctx->iters[curr_group];

        ret = vm_hash_table_fetch(eof, hash_seg, hash_table, iter);
        if (ret != CT_SUCCESS) {
            iter->curr_match.vmid = CT_INVALID_ID32;
            return CT_ERROR;
        }
        if (!(*eof)) {
            return CT_SUCCESS;
        }
        iter->curr_match.vmid = CT_INVALID_ID32;

        curr_group++;
        if (ctx->type == HASH_GROUP_PAR_TYPE) {
            while (curr_group < group_count && ctx->empty_par[curr_group]) {
                curr_group++;
            }
        }

        CT_BREAK_IF_TRUE(curr_group >= group_count);

        if (sql_hash_group_open_cursor(stmt, cursor, cursor->group_ctx, curr_group) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } while (CT_TRUE);

    return ret;
}

/*
 * **NOTE:**
 * 1. The function must be arranged by alphabetical ascending order.
 * 2. An enum stands for function index was added in ctsql_func.h.
 * if any built-in function added or removed from the following array,
 * please modify the enum definition, too.
 * 3. add function should add the define id in en_sql_aggr_type at ctsql_func.h.
 */
/* **NOTE:** The function must be arranged as the same order of en_sql_aggr_type. */
group_aggr_func_t g_group_aggr_func_tab[] = {
    { AGGR_TYPE_NONE, CT_FALSE, sql_group_init_none, sql_group_aggr_none, sql_group_calc_none },
    { AGGR_TYPE_AVG, CT_FALSE, sql_group_init_avg, sql_group_aggr_avg, sql_group_calc_avg },
    { AGGR_TYPE_SUM, CT_FALSE, sql_group_init_value, sql_group_aggr_sum, sql_group_calc_none },
    { AGGR_TYPE_MIN, CT_FALSE, sql_group_init_value, sql_group_aggr_min_max, sql_group_calc_none },
    { AGGR_TYPE_MAX, CT_FALSE, sql_group_init_value, sql_group_aggr_min_max, sql_group_calc_none },
    { AGGR_TYPE_COUNT, CT_TRUE, sql_group_init_count, sql_group_aggr_count, sql_group_calc_none },
    { AGGR_TYPE_AVG_COLLECT, CT_FALSE, sql_group_init_none, sql_group_aggr_none, sql_group_calc_none },
    { AGGR_TYPE_GROUP_CONCAT, CT_FALSE, sql_group_init_listagg, sql_group_aggr_listagg, sql_group_calc_listagg },
    { AGGR_TYPE_STDDEV, CT_FALSE, sql_group_init_stddev, sql_group_aggr_normal, sql_group_calc_normal },
    { AGGR_TYPE_STDDEV_POP, CT_FALSE, sql_group_init_stddev, sql_group_aggr_normal, sql_group_calc_normal },
    { AGGR_TYPE_STDDEV_SAMP, CT_FALSE, sql_group_init_stddev, sql_group_aggr_normal, sql_group_calc_normal },
    { AGGR_TYPE_LAG, CT_FALSE, sql_group_init_none, sql_group_aggr_none, sql_group_calc_none },
    { AGGR_TYPE_ARRAY_AGG, CT_TRUE, sql_group_init_array_agg, sql_group_aggr_array_agg, sql_group_calc_none },
    { AGGR_TYPE_NTILE, CT_FALSE, sql_group_init_none, sql_group_aggr_none, sql_group_calc_none },
    { AGGR_TYPE_MEDIAN, CT_TRUE, sql_group_init_median, sql_group_aggr_median, sql_group_calc_median },
    { AGGR_TYPE_CUME_DIST, CT_FALSE, sql_group_init_avg, sql_group_aggr_avg, sql_group_calc_avg },
    { AGGR_TYPE_VARIANCE, CT_FALSE, sql_group_init_stddev, sql_group_aggr_normal, sql_group_calc_normal },
    { AGGR_TYPE_VAR_POP, CT_FALSE, sql_group_init_stddev, sql_group_aggr_normal, sql_group_calc_normal },
    { AGGR_TYPE_VAR_SAMP, CT_FALSE, sql_group_init_stddev, sql_group_aggr_normal, sql_group_calc_normal },
    { AGGR_TYPE_COVAR_POP, CT_FALSE, sql_group_init_covar, sql_group_aggr_normal, sql_group_calc_normal },
    { AGGR_TYPE_COVAR_SAMP, CT_FALSE, sql_group_init_covar, sql_group_aggr_normal, sql_group_calc_normal },
    { AGGR_TYPE_CORR, CT_FALSE, sql_group_init_corr, sql_group_aggr_normal, sql_group_calc_normal },
    { AGGR_TYPE_DENSE_RANK, CT_TRUE, sql_group_init_dense_rank, sql_group_aggr_normal, sql_group_calc_dense_rank },
    { AGGR_TYPE_FIRST_VALUE, CT_FALSE, sql_group_init_none, sql_group_aggr_none, sql_group_calc_none },
    { AGGR_TYPE_LAST_VALUE, CT_FALSE, sql_group_init_none, sql_group_aggr_none, sql_group_calc_none },
    { AGGR_TYPE_RANK, CT_TRUE, sql_group_init_rank, sql_group_aggr_normal, sql_group_calc_none },
    { AGGR_TYPE_APPX_CNTDIS, CT_TRUE, sql_group_init_none, sql_group_aggr_normal, sql_group_calc_none },
};

static inline group_aggr_func_t *sql_group_aggr_func(sql_aggr_type_t type)
{
    return &g_group_aggr_func_tab[type];
}
