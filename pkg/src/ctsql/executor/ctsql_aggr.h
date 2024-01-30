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
 * ctsql_aggr.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/executor/ctsql_aggr.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_AGGR_H__
#define __SQL_AGGR_H__

#include "ctsql_func.h"
#include "dml_executor.h"
#include "var_inc.h"
#include "func_aggr.h"
#include "opr_add.h"

typedef struct st_aggr_dense_rank {
    hash_segment_t hash_segment;
    hash_table_entry_t table_entry;
} aggr_dense_rank_t;

typedef struct st_aggr_assist {
    sql_stmt_t *stmt;
    sql_cursor_t *cursor;
    expr_node_t *aggr_node;
    sql_aggr_type_t aggr_type;
    uint64 avg_count;
} aggr_assist_t;

typedef status_t (*aggr_alloc_buf_func_t)(aggr_assist_t *ass, aggr_var_t *aggr_var);
typedef status_t (*aggr_init_var_func_t)(aggr_assist_t *ass, aggr_var_t *aggr_var);
typedef status_t (*aggr_reset_func_t)(aggr_var_t *aggr_var);
typedef status_t (*aggr_proc_func_t)(aggr_assist_t *ass, aggr_var_t *aggr_var, variant_t *value);
typedef status_t (*aggr_calc_func_t)(aggr_assist_t *ass, aggr_var_t *aggr_var);

typedef struct st_aggr_func {
    sql_aggr_type_t aggr_type;
    aggr_alloc_buf_func_t alloc;
    aggr_init_var_func_t init;
    aggr_reset_func_t reset;
    aggr_proc_func_t invoke;
    aggr_calc_func_t calc;
} aggr_func_t;

extern aggr_func_t g_aggr_func_tab[];

static inline aggr_func_t *sql_get_aggr_func(sql_aggr_type_t type)
{
    return &g_aggr_func_tab[type];
}

static inline status_t sql_aggr_alloc_buf(aggr_assist_t *ass, aggr_var_t *aggr_var)
{
    return (&g_aggr_func_tab[ass->aggr_type])->alloc(ass, aggr_var);
}

static inline status_t sql_aggr_init_var(aggr_assist_t *ass, aggr_var_t *aggr_var)
{
    return (&g_aggr_func_tab[ass->aggr_type])->init(ass, aggr_var);
}

static inline status_t sql_aggr_reset(aggr_assist_t *ass, aggr_var_t *aggr_var)
{
    return (&g_aggr_func_tab[ass->aggr_type])->reset(aggr_var);
}

static inline status_t sql_aggr_invoke(aggr_assist_t *ass, aggr_var_t *aggr_var, variant_t *value)
{
    return (&g_aggr_func_tab[ass->aggr_type])->invoke(ass, aggr_var, value);
}

static inline status_t sql_aggr_calc_value(aggr_assist_t *ass, aggr_var_t *aggr_var)
{
    return (&g_aggr_func_tab[ass->aggr_type])->calc(ass, aggr_var);
}

#define SQL_INIT_AGGR_ASSIST(ass, _stmt_, _cursor_) \
    do {                                           \
        (ass)->stmt = (sql_stmt_t *)(_stmt_);       \
        (ass)->cursor = (sql_cursor_t *)(_cursor_); \
        (ass)->aggr_node = NULL;                    \
        (ass)->aggr_type = AGGR_TYPE_NONE;          \
        (ass)->avg_count = 0;                       \
    } while (0)

void clean_mtrl_seg(sql_stmt_t *stmt, sql_cursor_t *cursor);
status_t sql_aggr_value(aggr_assist_t *ctsql_stmt, uint32 id, variant_t *value);
status_t sql_aggr_get_cntdis_value(sql_stmt_t *stmt, galist_t *cntdis_columns, expr_node_t *aggr_node,
    variant_t *value);
status_t sql_execute_aggr(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan);
status_t sql_execute_index_aggr(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan);
status_t sql_init_aggr_values(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, galist_t *aggrs, uint32 *avgs);
status_t sql_fetch_aggr(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof);
status_t sql_exec_aggr(sql_stmt_t *stmt, sql_cursor_t *cursor, galist_t *aggrs, plan_node_t *plan);
status_t sql_exec_aggr_extra(sql_stmt_t *stmt, sql_cursor_t *cursor, galist_t *aggrs, plan_node_t *plan);

static inline aggr_var_t *sql_get_aggr_addr(sql_cursor_t *cursor, uint32 id)
{
    mtrl_cursor_t *mtrl_cursor = &cursor->mtrl.cursor;

    if (mtrl_cursor->type == MTRL_CURSOR_HASH_GROUP || mtrl_cursor->type == MTRL_CURSOR_SORT_GROUP) {
        return (aggr_var_t *)(mtrl_cursor->hash_group.aggrs + id * sizeof(aggr_var_t));
    } else { // sort group plan
        aggr_var_t *vars = (aggr_var_t *)((char *)cursor->aggr_page + sizeof(mtrl_page_t));
        return &vars[id];
    }
}

/* aggregate function must be a built-in function */
#define GET_AGGR_FUNC(aggr_node) ((const sql_func_t *)&g_func_tab[(aggr_node)->value.v_func.func_id])

static inline expr_node_t *sql_get_aggr_node(const sql_func_t *func, expr_node_t *aggr_node)
{
    /* the aggregate functions that use sql_func_normal_aggr compute aggr value are
     * equivalent to compute aggr values by aggr_node->argument->root, which is more
     * efficient than directly starting from aggr_node */
    return (func->invoke == sql_func_normal_aggr) ? aggr_node->argument->root : aggr_node;
}

#define AGGR_VALUE_NODE(func, aggr_node) sql_get_aggr_node(func, aggr_node)

static inline char *sql_get_aggr_free_start_addr(sql_cursor_t *cursor)
{
    return (char *)((char *)cursor->aggr_page + cursor->aggr_page->free_begin);
}

static inline status_t sql_aggr_sum_value(sql_stmt_t *stmt, variant_t *v_aggr, variant_t *v_add)
{
    if (CT_IS_NUMBER_TYPE(v_aggr->type)) {
        if (CT_IS_NUMBER_TYPE(v_add->type)) {
            return cm_dec_add(&v_aggr->v_dec, &v_add->v_dec, &v_aggr->v_dec);
        }
    } else if (v_aggr->type == CT_TYPE_BIGINT) {
        if (v_add->type == CT_TYPE_INTEGER) {
            return opr_bigint_add(v_aggr->v_bigint, (int64)v_add->v_int, &v_aggr->v_bigint);
        }
    }

    return opr_exec(OPER_TYPE_ADD, SESSION_NLS(stmt), v_aggr, v_add, v_aggr);
}

static inline void sql_get_aggr_value(sql_stmt_t *stmt, uint32 id, variant_t *value)
{
    sql_cursor_t *cursor = CTSQL_CURR_CURSOR(stmt);
    cursor = sql_get_group_cursor(cursor);
    aggr_var_t *aggr_var = sql_get_aggr_addr(cursor, id);
    var_copy(&aggr_var->var, value);
}

status_t sql_init_aggr_page(sql_stmt_t *stmt, sql_cursor_t *cursor, galist_t *aggrs);
status_t sql_mtrl_aggr(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 par_exe_flag);

#endif
