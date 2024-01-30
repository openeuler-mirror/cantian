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
 * ctsql_plan_defs.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/plan/ctsql_plan_defs.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_PLAN_DEFS_H__
#define __SQL_PLAN_DEFS_H__

#include "ctsql_context.h"
#include "ctsql_stmt.h"
#include "ctsql_cond.h"
#include "ctsql_expr.h"
#include "cm_chan.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CBO_ON (g_instance->kernel.attr.enable_cbo)
#define CBO_SET_FLAGS(_pa_, _flg_) (_pa_)->cbo_flags |= (uint32)(_flg_)
#define CBO_UNSET_FLAGS(_pa_, _flg_) (_pa_)->cbo_flags &= ~(uint32)(_flg_)
#define CBO_SET_INDEX_AST(_pa_, _flg_) (_pa_)->cbo_index_ast |= (uint32)(_flg_)
#define CBO_UNSET_INDEX_AST(_pa_, _flg_) (_pa_)->cbo_index_ast &= ~(uint32)(_flg_)
#define CBO_INDEX_HAS_FLAG(_pa_, _flg_) (((_pa_)->cbo_index_ast & (uint32)(_flg_)) != 0)

typedef enum en_plan_node_type {
    PLAN_NODE_QUERY = 1,
    PLAN_NODE_UNION,
    PLAN_NODE_UNION_ALL,
    PLAN_NODE_MINUS,
    PLAN_NODE_HASH_MINUS,
    PLAN_NODE_MERGE,
    PLAN_NODE_INSERT,
    PLAN_NODE_DELETE,
    PLAN_NODE_UPDATE,
    PLAN_NODE_SELECT,
    PLAN_NODE_JOIN,
    PLAN_NODE_SORT_GROUP,
    PLAN_NODE_MERGE_SORT_GROUP,
    PLAN_NODE_HASH_GROUP,
    PLAN_NODE_INDEX_GROUP,
    PLAN_NODE_QUERY_SORT,
    PLAN_NODE_SELECT_SORT,
    PLAN_NODE_AGGR,
    PLAN_NODE_INDEX_AGGR,
    PLAN_NODE_SORT_DISTINCT,
    PLAN_NODE_HASH_DISTINCT,
    PLAN_NODE_INDEX_DISTINCT,
    PLAN_NODE_HAVING,
    PLAN_NODE_SCAN,
    PLAN_NODE_QUERY_LIMIT,
    PLAN_NODE_SELECT_LIMIT,
    PLAN_NODE_CONNECT,
    PLAN_NODE_FILTER,
    PLAN_NODE_WINDOW_SORT,
    PLAN_NODE_REMOTE_SCAN,
    PLAN_NODE_GROUP_MERGE,
    PLAN_NODE_HASH_GROUP_PAR,
    PLAN_NODE_HASH_MTRL,
    PLAN_NODE_CONCATE,
    PLAN_NODE_QUERY_SORT_PAR,
    PLAN_NODE_QUERY_SIBL_SORT,
    PLAN_NODE_GROUP_CUBE,
    PLAN_NODE_HASH_GROUP_PIVOT,
    PLAN_NODE_UNPIVOT,
    PLAN_NODE_ROWNUM,
    PLAN_NODE_FOR_UPDATE,
    PLAN_NODE_WITHAS_MTRL,
    PLAN_NODE_CONNECT_MTRL,
    PLAN_NODE_CONNECT_HASH,
    PLAN_NODE_VM_VIEW_MTRL,
} plan_node_type_t;

typedef struct st_join_info {
    galist_t *key_items;
    sql_array_t rs_tables;
    cond_tree_t *filter_cond;
} join_info_t;

typedef struct st_join_plan {
    join_oper_t oper;
    uint32 exec_data_index;
    uint32 batch_size;
    union {
        uint32 mj_pos;
        uint32 hj_pos;
        uint32 nl_pos;
    };
    bool32 hash_left : 1;
    bool32 r_eof_flag : 1;      // for nl join, stop when right plan is eof
    bool32 nl_full_r_drive : 1; // check if this plan node is nl full opt r_drive_plan
    uint32 unused : 29;

    struct st_plan_node *left;
    struct st_plan_node *right;
    cond_tree_t *cond;
    cond_tree_t *filter;
    cond_tree_t *hash_filter; // for hash join filter

    galist_t *cmp_list;
    int64 rows;

    union {
        struct {
            join_info_t left_merge;
            join_info_t right_merge;
        };
        struct {
            join_info_t left_hash;
            join_info_t right_hash;
        };
        struct {
            struct st_plan_node *r_drive_plan;
            uint32 nl_full_mtrl_pos;
            nl_full_opt_type_t nl_full_opt_type;
        };
    };
    sql_table_t *cache_tab;
} join_plan_t;

typedef enum en_range_list_type {
    RANGE_LIST_EMPTY = 0,
    RANGE_LIST_FULL,
    RANGE_LIST_NORMAL,
} range_list_type_t;

typedef struct st_plan_rowid_set {
    range_list_type_t type;
    sql_array_t array; // rowid list
} plan_rowid_set_t;

typedef struct st_scan_plan {
    sql_table_t *table;
    sql_array_t index_array;     // for index scan
    sql_array_t part_array;      // for part scan
    sql_array_t subpart_array;   // for subpart scan
    plan_rowid_set_t *rowid_set; // store rowid expr_trees for rowid scan
    bool32 par_exec;
    galist_t *sort_items;
} scan_plan_t;

typedef struct st_limit_plan {
    limit_item_t item;
    struct st_plan_node *next;
    bool32 calc_found_rows; /* only the limit plan affected by "SQL_CALC_FOUND_ROWS" */
} limit_plan_t;

typedef struct st_for_update_plan {
    galist_t *rowids;
    struct st_plan_node *next;
} for_update_plan_t;

typedef struct st_winsort_plan {
    expr_node_t *winsort;
    galist_t *rs_columns;
    struct st_plan_node *next;
} winsort_plan_t;

typedef struct st_rownum_plan {
    struct st_plan_node *next;
} rownum_plan_t;

typedef struct st_query_sort_plan {
    galist_t *items; // order by items, the structure of items is sort_item_t
    struct st_plan_node *next;
    galist_t *select_columns; // columns before execute order by
    bool32 has_pending_rs;
    uint32 rownum_upper;
} query_sort_plan_t;

typedef struct st_select_sort_plan {
    galist_t *items; // order by items, the structure of items is sort_item_t
    struct st_plan_node *next;
    galist_t *rs_columns; // rs_column of select after execute order by
} select_sort_plan_t;

typedef struct st_sort_plan {
    galist_t *items; // order by items, the structure of items is sort_item_t
    struct st_plan_node *next;

    union {
        query_sort_plan_t union_p;
        select_sort_plan_t union_all_p;
    };
} sort_plan_t;

typedef struct st_pivot_assist {
    expr_tree_t *for_expr;
    expr_tree_t *in_expr;
    uint32 aggr_count;
} pivot_assist_t;

typedef struct st_group_plan {
    galist_t *sets;  // group by sets
    galist_t *exprs; // group by exprs
    galist_t *aggrs;
    galist_t *cntdis_columns;
    galist_t *sort_groups;
    galist_t *sort_items; // sort items in listagg
    uint32 aggrs_args;    // number of values in group aggrs
    uint32 aggrs_sorts;   // number of sort items in group aggrs
    struct st_plan_node *next;
    struct st_pivot_assist *pivot_assist; // for pivot
    bool32 multi_prod;                    // used to judge the parallel mode is single producer or multi producers
} group_plan_t;

typedef struct st_btree_sort {
    galist_t cmp_key;
    galist_t sort_key;
} btree_sort_t;

typedef struct st_unpivot_plan {
    galist_t *group_sets;
    bool32 include_nulls;
    uint32 alias_rs_count;
    uint32 rows;
    struct st_plan_node *next;
} unpivot_plan_t;

typedef struct st_cube_plan {
    galist_t *sets;  // list of group_set_t
    galist_t *nodes; // list of cube_node_t
    galist_t *plans; // list of plan_node_t, sub plans
    struct st_plan_node *next;
} cube_plan_t;

typedef struct st_distinct_plan {
    galist_t *columns;        // distinct columns
    btree_sort_t *btree_sort; // for sort distinct which can eliminate order by
    struct st_plan_node *next;
} distinct_plan_t;

typedef struct st_aggr_plan {
    galist_t *items;
    galist_t *cntdis_columns;
    struct st_plan_node *next;
} aggr_plan_t;

typedef struct st_having_plan {
    cond_tree_t *cond;
    struct st_plan_node *next;
} having_plan_t;

typedef struct st_connect_plan {
    cond_tree_t *connect_by_cond;
    cond_tree_t *start_with_cond;
    struct st_plan_node *next_start_with;
    struct st_plan_node *next_connect_by;
    sql_query_t *s_query;
    galist_t *path_func_nodes;
    galist_t *prior_exprs; // for is_cycle checking
} connect_plan_t;

typedef struct st_filter_plan {
    cond_tree_t *cond;
    struct st_plan_node *next;
} filter_plan_t;

typedef struct st_query_plan {
    sql_query_t *ref;          // reference sql query context
    struct st_plan_node *next; // mertialized result set / table scan ...
} query_plan_t;

typedef struct st_union_plan {
    galist_t *rs_columns;    // rs_column
    galist_t *union_columns; // rs_column
} union_plan_t;

typedef enum en_minus_type {
    MINUS = 0,
    INTERSECT = 1,
    INTERSECT_ALL = 2,
    EXCEPT_ALL = 3,
} minus_type_t;

typedef struct st_minus_plan {
    galist_t *rs_columns;
    galist_t *minus_columns;
    minus_type_t minus_type;
    bool32 minus_left; // // build hash table on minus/intersect left cursor
} minus_plan_t;

typedef struct st_union_all_plan {
    uint32 exec_id;
    bool32 par_exec;
} union_all_plan_t;

typedef struct st_set_plan { // union, union all, ...
    struct st_plan_node *left;
    struct st_plan_node *right;
    galist_t *list;
    union {
        union_plan_t union_p;
        union_all_plan_t union_all_p;
        minus_plan_t minus_p;
    };
} set_plan_t;

typedef struct st_select_plan {
    galist_t *rs_columns; // for materialize rs
    sql_select_t *select;
    struct st_plan_node *next;
} select_plan_t;

typedef struct st_update_plan {
    galist_t *objects;
    struct st_plan_node *next; // table scan / index scan ...
    bool32 check_self_update; // check self update for multiple table update
} update_plan_t;

typedef struct st_insert_plan {
    sql_table_t *table;
} insert_plan_t;

typedef struct st_delete_plan {
    galist_t *objects;
    galist_t *rowid;           // for order by
    struct st_plan_node *next; // table scan / index scan...
} delete_plan_t;

typedef struct st_merge_plan {
    sql_table_t *merge_into_table;
    sql_table_t *using_table;
    struct st_plan_node *merge_into_scan_p;
    struct st_plan_node *using_table_scan_p;

    // hash join
    galist_t *merge_keys;
    galist_t *using_keys;
    cond_tree_t *merge_table_filter_cond;
    cond_tree_t *remain_on_cond; // Exclude the key condition of hash join and filter condition of merge table
} merge_plan_t;

typedef struct st_gather_plan {
    struct st_plan_node *next;
    sql_query_t *query;
} gather_plan_t;

typedef struct st_hash_mtrl_plan {
    group_plan_t group;
    galist_t *remote_keys;
    uint32 hash_mtrl_id;
} hash_mtrl_plan_t;

typedef struct st_withas_mtrl_plan {
    uint32 id;
    text_t name; // for explain display
    galist_t *rs_columns;
    struct st_plan_node *next;
} withas_mtrl_plan_t;

typedef struct st_vm_view_mtrl_plan {
    uint32 id;
    galist_t *rs_columns;
    struct st_plan_node *next;
} vm_view_mtrl_plan_t;

typedef struct st_concate_plan {
    galist_t *keys;
    galist_t *plans;
} concate_plan_t;

typedef struct st_connect_by_mtrl_plan {
    struct st_plan_node *next;
    galist_t *prior_exprs; // exprs decorated by prior
    galist_t *key_exprs;
    sql_array_t *rs_tables;
    cond_tree_t *start_with_cond;
    cond_tree_t *connect_by_cond;
} cb_mtrl_plan_t;

typedef struct st_plan_node {
    plan_node_type_t type;
    double cost;
    int64 rows;
    uint32 plan_id;

    union {
        for_update_plan_t for_update;
        limit_plan_t limit;
        query_sort_plan_t query_sort;
        select_sort_plan_t select_sort;
        aggr_plan_t aggr;
        group_plan_t group;
        cube_plan_t cube;
        distinct_plan_t distinct;
        having_plan_t having;
        connect_plan_t connect;
        filter_plan_t filter;
        query_plan_t query;
        select_plan_t select_p;
        update_plan_t update_p;
        delete_plan_t delete_p;
        insert_plan_t insert_p;
        merge_plan_t merge_p;
        join_plan_t join_p;
        scan_plan_t scan_p;
        set_plan_t set_p; // union, union all, intersect, minus
        winsort_plan_t winsort_p;
        rownum_plan_t rownum_p;
        hash_mtrl_plan_t hash_mtrl;
        concate_plan_t cnct_p;
        gather_plan_t gather_p; // for parallel scan
        unpivot_plan_t unpivot_p;
        withas_mtrl_plan_t withas_p;
        vm_view_mtrl_plan_t vm_view_p;
        cb_mtrl_plan_t cb_mtrl;
    };
} plan_node_t;

typedef enum en_cbo_flag {
    CBO_NONE_FLAG = 0x0,
    CBO_CHECK_FILTER_IDX = 0x01,
    CBO_CHECK_JOIN_IDX = 0x02,
    CBO_CHECK_ANCESTOR_DRIVER = 0x04,
} cbo_flag_t;

typedef enum en_col_use_flag {
    USE_NONE_FLAG = 0,
    USE_ANCESTOR_COL = 0x01,
    USE_SELF_JOIN_COL = 0x02,
} col_use_flag_t;

typedef enum en_cbo_index_assist {
    NONE_INDEX = 0x00,
    IGNORE_INDEX = 0x01,
    CAN_USE_INDEX = 0x02,
    USE_MULTI_INDEX = 0x04,
} cbo_index_assist_t;

typedef enum en_spec_drive_flag {
    DRIVE_FOR_NONE = 0,
    DRIVE_FOR_SORT = 0x01,
    DRIVE_FOR_GROUP = 0x02,
    DRIVE_FOR_DISTINCT = 0x03,
} spec_drive_flag_t;

typedef struct st_plan_assist {
    uint32 table_count; // table count
    uint32 plan_count;  // count of planned table

    struct st_plan_assist *top_pa; // for CBO use
    struct st_plan_assist *parent; // for join cond push down
    uint32 save_plcnt;
    uint32 cbo_index_ast;
    uint16 cbo_flags; // for save pa->cbo_flags
    uint16 col_use_flag;
    uint16 max_ancestor;
    uint16 spec_drive_flag; // for special drive table index to eliminate sort/group/distinct etc.

    struct {
        bool32 has_parent_join : 1;
        bool32 has_bind_param : 1;
        bool32 no_nl_batch : 1;     // add for not choose batch_nl join plan
        bool32 resv_outer_join : 1; // flag indicates reserve old outer join table order
        bool32 ignore_hj : 1;       // flag indicates not calc hash join
        bool32 is_final_plan : 1;
        bool32 is_subqry_cost : 1; // flag for cbo_get_query_cost
        bool32 is_nl_full_opt : 1;
        bool32 vpeek_flag : 1;
        bool32 reserved : 23;
    };

    uint16 nlf_mtrl_cnt;      // count of nl full rowid mtrl
    uint16 nlf_dupl_plan_cnt; // count of nl full dupl plan
    cond_tree_t *cond;
    sql_query_t *query;
    galist_t *sort_items;                         // additional columns for index chosen
    sql_table_t *tables[CT_MAX_JOIN_TABLES];      // sorted by sequence in sql text
    sql_table_t *plan_tables[CT_MAX_JOIN_TABLES]; // sorted by planner
    sql_join_assist_t *join_assist;
    uint32 list_expr_count; // in/or condition expr list count
    sql_node_type_t type;
    uint32 hj_pos;
    uint8 *join_oper_map;
    sql_stmt_t *stmt;
    bilist_t join_conds;
    uint32 scan_part_cnt; // only use part table
    plan_node_t **filter_node_pptr;
    pointer_t join_card_map;
} plan_assist_t;

typedef enum en_column_match_mode {
    COLUMN_MATCH_NONE = 0,
    COLUMN_MATCH_POINT = 1,
    COLUMN_MATCH_LIST = 2,
    COLUMN_MATCH_2_BORDER_RANGE = 3,
    COLUMN_MATCH_1_BORDER_RANGE = 4,
    COLUMN_MATCH_MAX = 5,
} column_match_mode_t;

typedef enum en_check_index_for_type {
    CK_FOR_EXISTS,
    CK_FOR_NOT_EXISTS,
    CK_FOR_OR2UNION,
    CK_FOR_HASH_MTRL,
    CK_FOR_UPDATE,
} ck_type_t;

#ifdef __cplusplus
}
#endif

#endif
