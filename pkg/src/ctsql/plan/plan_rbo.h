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
 * plan_rbo.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/plan/plan_rbo.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __PLAN_RBO_H__
#define __PLAN_RBO_H__

#include "cm_defs.h"
#include "ctsql_cond.h"
#include "ctsql_plan.h"
#include "knl_dc.h"

#ifdef __cplusplus
extern "c" {
#endif

// Rule base optimization, cost estimate referenced by RBO planner
#define RBO_COST_ROWID_SCAN (double)1
#define RBO_COST_SUB_QUERY_SCAN (double)0 // sub query

// heap table
#define RBO_COST_UNIQUE_POINT_SCAN (double)15 // unique index (or primary key) point scan
#define RBO_COST_UNIQUE_LIST_SCAN (double)30  // unique index (or primary key) list  scan
#define RBO_COST_INDEX_POINT_SCAN (double)50  // index point scan
#define RBO_COST_INDEX_LIST_SCAN (double)80   // index list  scan
#define RBO_COST_INDEX_RANGE_SCAN (double)400 // index range scan
#define RBO_COST_PRE_INDEX_SCAN (double)2000  // prefix index scan
#define RBO_COST_FULL_INDEX_SCAN (double)9000 // index specified by INDEX hint, but it not in condition
#define RBO_COST_FULL_TABLE_SCAN (double)10000
#define RBO_COST_INFINITE (double)0xFFFFFFFFFF

// temp table
#define RBO_TEMP_COST_UNIQUE_POINT_SCAN (double)5 // unique index (or primary key) point scan
#define RBO_TEMP_COST_UNIQUE_LIST_SCAN (double)20 // unique index (or primary key) list  scan
#define RBO_TEMP_COST_INDEX_POINT_SCAN (double)35 // index point scan
#define RBO_TEMP_COST_INDEX_LIST_SCAN (double)38  // index list  scan
#define RBO_TEMP_COST_INDEX_RANGE_SCAN (double)40 // index range scan
#define RBO_TEMP_COST_PRE_INDEX_SCAN (double)42   // prefix index scan
#define RBO_TEMP_COST_FULL_INDEX_SCAN (double)45  // index specified by INDEX hint, but it not in condition
#define RBO_TEMP_COST_FULL_TABLE_SCAN (double)48

#define RBO_INDEX_NONE_FLAG 0
#define RBO_INDEX_ONLY_FLAG 0x01
#define RBO_INDEX_GROUP_FLAG 0x02
#define RBO_INDEX_DISTINCT_FLAG 0x04
#define RBO_INDEX_SORT_FLAG 0x08
// all part fields in index and matched from beginning, like: part fields(f1,f2), index fields(f1,f2,f3)
#define RBO_INDEX_MATCH_PARTFIELD_FLAG 0x10
#define RBO_NL_PREFETCH_FLAG 0x20
#define INDEX_SORT_SCAN_MASK 0x0E
#define BETTER_INDEX_SCAN_MASK 0x0F

#define INDEX_MATCH_PARTFILED(scan_flag) ((scan_flag) & RBO_INDEX_MATCH_PARTFIELD_FLAG)
#define INDEX_ONLY_SCAN(scan_flag) ((scan_flag) & RBO_INDEX_ONLY_FLAG)
#define CAN_INDEX_SORT(scan_flag) ((scan_flag) & RBO_INDEX_SORT_FLAG)
#define CAN_INDEX_GROUP(scan_flag) ((scan_flag) & RBO_INDEX_GROUP_FLAG)
#define CAN_INDEX_DISTINCT(scan_flag) ((scan_flag) & RBO_INDEX_DISTINCT_FLAG)
#define INDEX_SORT_SCAN(scan_flag) ((scan_flag) & INDEX_SORT_SCAN_MASK)
#define INDEX_NL_PREFETCH(scan_flag) (((scan_flag) & RBO_NL_PREFETCH_FLAG) != 0)

#define SORT_DISTINCT_FACTOR 0.75
// has index_only, but no index_sort
#define INDEX_ONLY_SCAN_ONLY(scan_flag) (INDEX_ONLY_SCAN(scan_flag) && !(INDEX_SORT_SCAN(scan_flag)))
// index_sort better than index_only, index_sort&only better than index_sort or index_only
#define IS_BETTER_INDEX_SCAN(scan_flag1, scan_flag2) \
    (((scan_flag1) & BETTER_INDEX_SCAN_MASK) > ((scan_flag2) & BETTER_INDEX_SCAN_MASK))

#define IS_UNIDIRECTIONAL_CMP(node)                                                                        \
    ((node)->type == CMP_TYPE_IN || (node)->type == CMP_TYPE_EQUAL_ANY || (node)->type == CMP_TYPE_LIKE || \
        (node)->type == CMP_TYPE_IS_NULL || (node)->type == CMP_TYPE_EQUAL_ALL)

/* if table entry is null, table is remote table */
#define IS_TEMP_TABLE(table)                                                               \
    ((table)->entry != NULL && ((table)->entry->dc.type == DICT_TYPE_TEMP_TABLE_SESSION || \
        (table)->entry->dc.type == DICT_TYPE_TEMP_TABLE_TRANS))
#define IS_DYNAMIC_VIEW(table)                                                       \
    ((table)->entry != NULL && ((table)->entry->dc.type == DICT_TYPE_DYNAMIC_VIEW || \
        (table)->entry->dc.type == DICT_TYPE_GLOBAL_DYNAMIC_VIEW))
#define RBO_INDEX_FULL_SCAN_COST(table) \
    (IS_TEMP_TABLE(table) ? RBO_TEMP_COST_FULL_INDEX_SCAN : RBO_COST_FULL_INDEX_SCAN)
#define RBO_TABLE_FULL_SCAN_COST(table) \
    (IS_TEMP_TABLE(table) ? RBO_TEMP_COST_FULL_TABLE_SCAN : RBO_COST_FULL_TABLE_SCAN)

status_t rbo_try_rownum_optmz(sql_stmt_t *stmt, cond_node_t *node, uint32 *max_rownum, bool8 *rnum_pending);
bool32 rbo_sort_col_indexable(sql_stmt_t *stmt, sql_query_t *query, galist_t *sort_items, knl_index_desc_t *index,
    sql_table_t *table, uint16 equal_to, uint8 *index_dsc);
bool32 rbo_group_col_indexable(sql_stmt_t *stmt, sql_query_t *query, knl_index_desc_t *index, sql_table_t *table,
    uint16 equal_to);
status_t rbo_cond_node_indexable(plan_assist_t *pa, cond_node_t *root_node, cond_node_t *node, expr_node_t *column,
    column_match_mode_t *match_mode, bool32 *result);
void rbo_set_table_scan_index(sql_table_t *table, double cost, knl_index_desc_t *index, uint16 scan_flag,
    uint8 index_dsc, uint16 idx_equal_to, uint16 equal_cols, uint16 col_use_flag, uint32 match_count,
    column_match_mode_t match_mode);
void rbo_update_column_in_func(sql_stmt_t *stmt, expr_node_t **node, uint32 table_id);
status_t sql_table_choose_indexes(sql_stmt_t *stmt, plan_assist_t *pa, sql_table_t *table);
uint16 rbo_get_index_scan_flag(plan_assist_t *pa, sql_table_t *table, knl_index_desc_t *index, uint16 idx_equal_to,
    uint8 *index_dsc, bool32 chk_part_key);
uint16 rbo_find_column_in_index(uint16 col_id, knl_index_desc_t *index, uint16 column_count);
status_t sql_get_index_col_node(sql_stmt_t *stmt, knl_column_t *knl_col, expr_node_t *column_node, expr_node_t **node,
                                uint32 table_id, uint32 col_id);
bool32 chk_part_key_match_index(dc_entity_t *entity, uint32 part_key_count, knl_index_desc_t *index, uint16 equal_to);

static inline void sql_init_table_indexable(sql_table_t *table, sql_table_t *parent)
{
    if (parent != NULL) {
        *table = *parent;
    }
    table->cond = NULL;
    table->index = NULL;
    table->sub_tables = NULL;
    table->scan_flag = 0;
    table->index_dsc = 0;
    table->rowid_set = NULL;
    table->rowid_usable = CT_FALSE;
    table->scan_mode = SCAN_MODE_TABLE_FULL;
    table->col_use_flag = 0;
    table->index_ffs = CT_FALSE;
    table->index_full_scan = CT_FALSE;
    table->index_skip_scan = CT_FALSE;
    table->skip_index_match = CT_FALSE;
    table->opt_match_mode = COLUMN_MATCH_NONE;
    table->index_match_count = 0;
    table->idx_equal_to = 0;
    table->equal_cols = 0;
    table->idx_col_map = NULL;
    table->cost = RBO_TABLE_FULL_SCAN_COST(table);
}

static inline void init_join_root_table_scan_info(sql_join_node_t *join_node)
{
    sql_table_t *table = NULL;
    for (uint32 i = 0; i < join_node->tables.count; i++) {
        table = (sql_table_t *)sql_array_get(&join_node->tables, i);
        sql_init_table_indexable(table, NULL);
        table->is_join_driver = CT_FALSE;
        TABLE_CBO_FILTER(table) = NULL;
    }
}

#ifdef __cplusplus
}
#endif

#endif
