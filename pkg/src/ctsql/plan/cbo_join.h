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
 * cbo_join.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/plan/cbo_join.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CBO_JOIN_H__
#define __CBO_JOIN_H__

#include "plan_join.h"

#ifdef __cplusplus
extern "C" {
#endif

#define START_NODE (uint32)0

#define CBO_HASH_TABLE_RATE (uint32)5
#define CBO_NL_COST_RATE (uint32)100

#define CBO_FUNC_JOIN_BASE_COST (double)1.5

#define CBO_BHT_MIN_RATE (double)1.0
#define CBO_BHT_MAX_RATE (double)5.0
#define CBO_BHT_ROWS(x) (uint32)(CT_VMEM_PAGE_SIZE * 128 / ((x) * sizeof(rowid_t))) // rows ~= 2097152 / (x)

#define CBO_NL_SCAN_TUPLE_COST(l_card, r_card)                                                      \
    (((l_card) >= CBO_JOIN_RATING_CARD) ?                                                           \
        ((l_card) + (r_card)) * (CBO_DEFAULT_CPU_SCAN_TUPLE_COST + CBO_DEFAULT_CPU_OPERATOR_COST) : \
        CBO_MIN_COST)
#define CBO_NL_SCAN_RATE(l_card)                          \
    ((l_card) < CBO_LARGE_TABLE_ROWS ? CBO_BHT_MIN_RATE : \
                                       MIN(CBO_BHT_MAX_RATE, (double)(l_card) / CBO_LARGE_TABLE_ROWS))

#define IS_CARTESIAN_COND(cond) (((cond) == NULL) || ((cond) == &g_fake_inner_join_cond))
#define IS_JOIN_TABLE(jnd) ((jnd)->type == JOIN_TYPE_NONE)
#define GET_JOIN_NODE_COND(join_root) (IS_INNER_JOIN(join_root) ? (join_root)->filter : (join_root)->join_cond);
#define TABLE_HAS_DEP_TABLES(table) (TABLE_CBO_DEP_TABLES(table) && (TABLE_CBO_DEP_TABLES(table)->count > 0))

typedef struct st_cbo_join_edge {
    bool32 has_index; // CT_TRUE means right table can index scan by join cond or filter cond
    join_oper_t oper;
    scan_info_t scan_info;
    uint32 org;
    uint32 dst;
    double value;
    int64 card;
    int64 drv_card;
    join_cond_t *cond;
} cbo_join_edge_t;

typedef struct st_cbo_dist_node {
    uint32 join_tab;
    cbo_join_edge_t join_edge;
} cbo_dist_node_t;

struct st_cbo_join_graph;
typedef struct st_cbo_join_path {
    bilist_node_t bilist_node;
    struct st_cbo_join_graph *graph;
    bool8 is_idle;
    bool8 has_hash_oper;
    uint32 count;
    uint32 deal_count;
    uint32 last_nid;
    int64 card;
    double total_cost;

    bool8 *book;
    cbo_dist_node_t *path;
    uint32 *opt_tablist;
} cbo_join_path_t;

typedef struct st_cbo_join_graph {
    bool32 is_init;
    uint32 count;
    uint32 spec_drive_flag;
    int64 card;
    double total_cost;

    sql_table_t **nodes;
    cbo_join_edge_t **edges; // side table adjacency matrix
    uint32 *node2tab;        // node id -> tab id

    uint32 max_cache_path;     // maximum path cached in queue
    uint32 max_alloc_path;     // number of allocated join paths
    cbo_join_path_t *paths;    // array for alloc join paths
    cbo_join_path_t *opt_path; // pointer to the final optimal path
    bilist_t join_paths;       // bilist for cached join paths
    struct st_cbo_join_graph *next;
} cbo_join_graph_t;

typedef struct st_cbo_card_info {
    uint64 map_id;
    int64 card;
} cbo_card_info_t;

// for inner join condition has no association tables
extern join_cond_t g_fake_inner_join_cond;

// //////////////////////////////////////////////////////////////////////////////////////
// function
void set_table_filter_cond(sql_table_t *table, sql_join_node_t *node, cond_tree_t *cond);
void reset_plan_table(sql_stmt_t *stmt, plan_assist_t *pa, uint32 drv_table, sql_join_node_t *join_root);
void set_join_node_oper_2_hash(join_oper_t *oper);
void reset_join_node_oper(join_oper_t *oper);

bool32 if_adjust_join_tree_4_order(plan_assist_t *pa, sql_join_node_t *join_root, cbo_cost_t *cost);
status_t choose_optimized_join_edge(plan_assist_t *pa, int64 l_card, sql_table_t *l_table, sql_table_t *r_table,
    cbo_join_edge_t *join_edge);
int64 cbo_get_join_node_card(sql_join_node_t *join_node);
double cbo_get_table_join_cost(plan_assist_t *pa, int64 tmp_l_card, sql_table_t *l_tab, sql_table_t *r_tab,
                               join_oper_t oper);
status_t cbo_get_graph_join_info(plan_assist_t *pa, sql_join_node_t *join_root, join_cond_t **join_cond);
status_t cbo_calc_join_node_card(sql_stmt_t *stmt, plan_assist_t *pa, galist_t *cmp_nodes, sql_join_node_t *join_node,
    int64 *ret_card);
double cbo_calc_join_node_cost(sql_join_node_t *root);
status_t cbo_calc_table_join_card(plan_assist_t *pa, int64 tmp_l_card, sql_table_t *l_table, sql_table_t *r_table,
    cbo_join_edge_t *join_edge);
status_t get_all_tables_card(sql_stmt_t *stmt, plan_assist_t *pa);
status_t set_subselect_cbo_info(sql_stmt_t *stmt, plan_assist_t *pa, sql_table_t *table);
bool32 sql_join_node_can_use_hash(bilist_t *join_conds);
status_t cbo_adjust_join_tree_4_order(plan_assist_t *pa, sql_join_node_t *join_root);
status_t cbo_create_join_tree(sql_stmt_t *stmt, plan_assist_t *pa, join_assist_t *ja, sql_join_node_t **join_root);
status_t cbo_get_merge_into_join_oper(sql_stmt_t *stmt, plan_assist_t *pa, sql_table_t *merge_tab,
    sql_table_t *using_tab, cond_tree_t *merge_cond, cond_tree_t *using_cond, join_oper_t *oper);

cbo_cost_t *cbo_get_join_node_cost(sql_join_node_t *join_node, bool32 *has_index, uint32 *scan_flag);
double get_table_join_output_cost(int64 l_card, int64 r_card, int64 out_card);

bool32 is_cond_belong_tables(plan_assist_t *pa, sql_join_node_t *join_root, cond_tree_t *join_cond);
bool32 is_node_belong_tables(plan_assist_t *pa, sql_join_node_t *join_root, cond_node_t *cond_node);
// //////////////////////////////////////////////////////////////////////////////////////////////////////////
// inline interface
static inline sql_table_t *get_pa_table_by_id(plan_assist_t *pa, uint32 drv_table)
{
    if (pa->top_pa != NULL) {
        return get_pa_table_by_id(pa->top_pa, drv_table);
    }
    return pa->tables[drv_table];
}

static inline sql_table_t *cbo_get_depend_table(plan_assist_t *pa, sql_table_t *deptab, uint32 idx)
{
    uint32 tab_no = *(uint32 *)cm_galist_get(TABLE_CBO_DEP_TABLES(deptab), idx);
    return get_pa_table_by_id(pa, tab_no);
}

static inline bool32 find_table_in_subgraph(sql_table_t *table, uint32 tab_no)
{
    if (tab_no == CT_INVALID_ID32) {
        return CT_FALSE;
    }

    if (TABLE_CBO_SUBGRP_TABLES(table) != NULL) {
        for (uint32 i = 0; i < TABLE_CBO_SUBGRP_TABLES(table)->count; i++) {
            uint32 tab_id = *(uint32 *)cm_galist_get(TABLE_CBO_SUBGRP_TABLES(table), i);
            if (tab_no == tab_id) {
                return CT_TRUE;
            }
        }
    }
    return CT_FALSE;
}

static inline void save_and_reset_plan_assist(plan_assist_t *pa, uint32 *plan2tab, uint32 *cbo_flags)
{
    for (uint32 i = 0; i < pa->table_count; i++) {
        plan2tab[i] = pa->tables[i]->plan_id;
        pa->tables[i]->plan_id = CT_INVALID_ID32;
    }
    *cbo_flags = pa->cbo_flags;
    CBO_SET_FLAGS(pa, CBO_CHECK_FILTER_IDX | CBO_CHECK_JOIN_IDX);
}

static inline void restore_plan_assist(plan_assist_t *pa, uint32 *plan2tab, uint32 cbo_flags)
{
    for (uint32 i = 0; i < pa->table_count; i++) {
        pa->tables[i]->plan_id = plan2tab[i];
    }
    pa->cbo_flags = cbo_flags;
}

static inline void save_pa_cbo_flag(plan_assist_t *pa, cbo_flag_t flg, cbo_flag_t *cur_flg, cbo_flag_t *top_flg)
{
    *cur_flg = pa->cbo_flags;
    pa->cbo_flags = flg;

    if (pa->top_pa != NULL) {
        pa = pa->top_pa;
    }
    *top_flg = pa->cbo_flags;
    pa->cbo_flags = flg;
}

static inline void restore_pa_cbo_flag(plan_assist_t *pa, cbo_flag_t cur_flg, cbo_flag_t top_flg)
{
    pa->cbo_flags = cur_flg;
    if (pa->top_pa != NULL) {
        pa = pa->top_pa;
    }
    pa->cbo_flags = top_flg;
}


#ifdef __cplusplus
}
#endif

#endif
