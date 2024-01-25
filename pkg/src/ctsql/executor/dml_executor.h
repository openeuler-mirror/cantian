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
 * dml_executor.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/executor/dml_executor.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DML_EXECUTOR_H__
#define __DML_EXECUTOR_H__

#include "plan_range.h"
#include "ctsql_plan.h"
#include "ctsql_stmt.h"
#include "ctsql_cond.h"
#include "cm_bilist.h"
#include "ctsql_vm_hash_table.h"
#include "ctsql_table_func.h"
#include "ctsql_btree.h"

typedef enum en_key_set_type {
    KEY_SET_FULL,
    KEY_SET_EMPTY,
    KEY_SET_NORMAL,
} key_set_type_t;

typedef struct st_key_range_t {
    char *l_key;
    char *r_key;
    bool32 is_equal;
} key_range_t;

typedef struct st_key_set_t {
    void *key_data; // id of key data which restored in vma
    uint32 offset;
    key_set_type_t type;
} key_set_t;

#ifdef Z_SHARDING

typedef struct st_participant_node {
    uint16 stmt_index;
    bool8 eof;
    uint8 reserved[1];
    struct st_participant_node *next;
} participant_node_t;

typedef struct st_merge_group_property {
    participant_node_t need_fetch_head;
    participant_node_t head;
    uint16 need_fetch_stmt_index[M_SLOT_STMT_LIST_COUNT];
    uint16 stmt_index_count;
    participant_node_t *pnode; /* buf for storing the following object */
} merge_group_property_t;

/* @NOTE: never store the return value in a heap variable */
static inline participant_node_t *sql_remote_get_merge_group_participant_list(sql_stmt_t *ctsql_stmt,
    merge_group_property_t *mergegrp_property)
{
    if (mergegrp_property->pnode == NULL) {
        CT_THROW_ERROR(ERR_ASSERT_ERROR, "mergegrp_property->pnode == NULL");
    }
    return mergegrp_property->pnode;
}

typedef struct st_merge_fetch_property {
    uint16 participants_count;
    uint16 alive_count; /* when the alive count is zero, it means no more data can be retrieved */
    char *buf;          /* buf for storing the following object */
    /*
     * ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
     * |  participant_node_t array  |   loser tree(i.e., int32 array)   |
     * ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
     *
     * refer to sql_remote_get_merge_sort_losertree() and sql_remote_get_merge_sort_participant() for details
     */
} merge_fetch_property_t;

/* @NOTE: never store the return value in a heap variable */
static inline int32 *sql_remote_get_merge_sort_losertree(sql_stmt_t *ctsql_stmt, merge_fetch_property_t *mergesort_property)
{
    if (mergesort_property->buf == NULL) {
        CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "mergesort_property->buf == NULL");
    }
    return (int32 *)(mergesort_property->buf + mergesort_property->participants_count * sizeof(participant_node_t));
}

/* @NOTE: never store the return value in a heap variable */
static inline participant_node_t *sql_remote_get_merge_sort_participant(sql_stmt_t *ctsql_stmt,
    merge_fetch_property_t *mergesort_property, int32 index)
{
    participant_node_t *node_arr = NULL;
    if (mergesort_property->buf == NULL) {
        CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "mergesort_property->buf == NULL");
        return NULL;
    }
    if (index < 0 || index >= mergesort_property->participants_count) {
        return NULL;
    }
    node_arr = (participant_node_t *)mergesort_property->buf;
    return &node_arr[index];
}

typedef struct st_remote_cursor {
    bool32 eof;
    remote_fetcher_type_t method_type;
    struct {
        union {
            merge_fetch_property_t merge_sort_property;
            merge_group_property_t merge_group_property;
        };
    };

    uint16 stmt_count;
    uint16 current_stmt_index;
    node_slot_stmt_t *slot_stmt_list[M_SLOT_STMT_LIST_COUNT];
    group_list_t group_id_list;
    bool32 direct_fetch;
    bool32 is_group_changed; /* true:next record group changed; false: next record is same group */

    uint32 column_count; /* the columns count of the result fetched by the remote_scan */
    row_head_t *row;     // current row data, point to buf
    uint16 *offsets;     // for decoding row
    uint16 *lens;        // for decoding row
    rowid_t rowid;       // row id
    bool8 is_mtrl_data;
    uint16 rownodeid;
    char buf[0];
} remote_cursor_t;

#endif

typedef struct st_mps_knlcur {
    knl_cursor_t *knl_cursor;
    uint32 offset;
} mps_knlcur_t;

typedef struct st_mps_sort {
    uint32 count;
    uint32 sort_array_length;
    uint32 *sort_array;
} mps_sort_t;

typedef struct st_multi_parts_scan_ctx {
    galist_t *knlcur_list;
    mps_sort_t *sort_info;
    uint32 knlcur_id;
    bool32 stop_index_key;
} mps_ctx_t;


typedef struct st_sql_table_cursor {
    sql_table_t *table; // table/subselect description
    union {
        knl_cursor_t *knl_cur;         // for kernel table
        struct st_sql_cursor *sql_cur; // for subselect
    };
    knl_cursor_action_t action;
    knl_scan_mode_t scan_mode;
    union {
        struct {
            key_set_t key_set;            // for index scan, the id of first indexed column's range
            key_set_t part_set;           // for part scan
            part_scan_key_t curr_part;    // for part scan
            part_scan_key_t curr_subpart; // for subpart scan
            uint32 part_scan_index;       // curr compart index in scan range
            mps_ctx_t multi_parts_info;   // for multi parts fetch optim
        };
        json_table_exec_t json_table_exec;
    };

    bool32 hash_table;        // for multi delete/update, hash join table
    tf_scan_flag_t scan_flag; // Parallel Scan Indicator
    struct st_par_scan_range range;
    uint64 scn;
    vmc_t vmc;
} sql_table_cursor_t;

#define PENDING_HEAD_SIZE sizeof(uint32)

typedef struct st_mtrl_sibl_sort {
    uint32 sid; // cache rowid list of the sub-segments,each non-leaf node has a sub-segment
    uint32 cursor_sid;
} mtrl_sibl_sort_t;

typedef struct st_sql_mtrl_handler {
    mtrl_cursor_t cursor;
    mtrl_resource_t rs;
    mtrl_resource_t predicate;
    mtrl_resource_t query_block;
    mtrl_resource_t outline;
    mtrl_resource_t note;
    mtrl_resource_t sort;
    uint32 aggr;
    uint32 aggr_str;
    uint32 sort_seg;
    uint32 for_update;
    mtrl_resource_t group;
    uint32 group_index;
    uint32 distinct;
    uint32 index_distinct;
    bool32 aggr_fetched;
    mtrl_resource_t winsort_rs;
    mtrl_resource_t winsort_aggr;
    mtrl_resource_t winsort_aggr_ext;
    mtrl_resource_t winsort_sort;
    uint32 hash_table_rs;
    mtrl_savepoint_t save_point;
    mtrl_sibl_sort_t sibl_sort;
} sql_mtrl_handler_t;

typedef struct st_union_all_data {
    uint32 pos; /* flags pos of child plan to be execute in union all plan list */
} union_all_data_t;

typedef struct st_minus_data {
    bool32 r_continue_fetch;
    uint32 rs_vmid; // for hash minus row buf
    uint32 rnums;   // rows left in hash table
} minus_data_t;

typedef struct st_limit_data {
    uint64 fetch_row_count;
    uint64 limit_count;
    uint64 limit_offset;
} limit_data_t;

typedef struct st_connect_by_data {
    struct st_sql_cursor *next_level_cursor;
    struct st_sql_cursor *last_level_cursor;
    struct st_sql_cursor *first_level_cursor;
    struct st_sql_cursor *cur_level_cursor; // only first_level_cursor's cur_level_cursor is not null, others is null
    bool32 connect_by_isleaf;
    bool32 connect_by_iscycle;
    uint32 level;
    uint32 first_level_rownum;
    galist_t *path_func_nodes;
    galist_t *prior_exprs;  // used to determine if the records are the same
    cm_stack_t *path_stack; /* only save the path in the first level cursor, stack content : text_t + data */
} connect_by_data_t;

typedef struct st_join_data {
    struct st_sql_cursor *left;
    struct st_sql_cursor *right;
} join_data_t;

typedef struct st_group_data {
    uint32 curr_group;
    uint32 group_count;
    group_plan_t *group_p;
} group_data_t;

typedef struct st_cube_data {
    struct st_sql_cursor *fetch_cursor;
    struct st_sql_cursor *group_cursor;
    galist_t *sets;     // list of group_set_t
    galist_t *nodes;    // list of cube_node_t
    galist_t *plans;    // list of plan_node_t
    biqueue_t curs_que; // queue of sub-cursor
    cube_node_t **maps; // node maps by group_id
    plan_node_t *fetch_plan;
} cube_data_t;

typedef struct st_hash_join_anchor {
    uint32 slot;
    uint32 batch_cnt;
    bool32 eof;
} hash_join_anchor_t;

typedef struct st_merge_group_data {
    bool32 eof;
} merge_group_data_t;

typedef struct st_outer_join_data {
    bool8 need_reset_right;
    bool8 right_matched;
    bool8 need_swap_driver; // left plan is fetched over
    bool8 left_empty;
    plan_node_t *right_plan;
    plan_node_t *left_plan;
    cond_tree_t *cond;
    cond_tree_t *filter;
    struct st_nl_full_opt_ctx *nl_full_opt_ctx;
} outer_join_data_t;

typedef struct st_inner_join_data {
    bool32 right_fetched; // right plan is first fetched
} inner_join_data_t;

typedef struct st_nl_batch_data {
    bool32 last_batch;
    struct st_sql_cursor *cache_cur;
} nl_batch_data_t;

typedef struct st_hash_right_semi_data {
    uint32 total_rows;
    uint32 deleted_rows;
    bool32 is_first;
} hash_right_semi_t;

typedef struct st_plan_exec_data {
    limit_data_t *query_limit;
    limit_data_t *select_limit;
    union_all_data_t *union_all;
    minus_data_t minus;
    uint32 unpivot_row;
    uint32 *explain_col_max_size;
    uint32 *qb_col_max_size;
    outer_join_data_t *outer_join;
    inner_join_data_t *inner_join;
    row_addr_t *join;
    char *aggr_dis;
    char *select_view;
    char *tab_parallel;
    group_data_t *group;
    cube_data_t *group_cube;
    nl_batch_data_t *nl_batch;
    galist_t *index_scan_range_ar;
    galist_t *part_scan_range_ar;
    text_buf_t sort_concat;
    knl_cursor_t *ext_knl_cur;     // for on duplicate key update or replace delete
    hash_right_semi_t *right_semi; // for hash join right semi
    char *dv_plan_buf;             // for dv_sql_plan knl cursor
} plan_exec_data_t;

typedef enum e_hash_table_oper_type {
    OPER_TYPE_INSERT = 1,
    OPER_TYPE_FETCH = 2
} hash_table_opertype_t;


typedef enum en_group_type {
    HASH_GROUP_TYPE,
    SORT_GROUP_TYPE,
    HASH_GROUP_PIVOT_TYPE,
    HASH_GROUP_PAR_TYPE,
} group_type_t;

typedef struct st_concate_ctx {
    uint32 id;
    uint32 vmid;
    char *buf;
    galist_t *keys;
    galist_t *sub_plans;
    plan_node_t *curr_plan;
    hash_segment_t hash_segment;
    hash_table_entry_t hash_table;
    hash_table_iter_t iter;
} concate_ctx_t;

typedef enum en_group_by_phase {
    GROUP_BY_INIT,
    GROUP_BY_PARALLEL,
    GROUP_BY_COLLECT,
    GROUP_BY_END
} group_by_phase_t;

typedef struct st_group_ctx {
    group_type_t type;
    hash_table_opertype_t oper_type;
    sql_stmt_t *stmt;
    group_plan_t *group_p;
    expr_node_t **aggr_node;
    handle_t cursor;
    uint32 vm_id;
    uint32 listagg_page;
    text_buf_t concat_data;
    char **concat_typebuf;
    mtrl_segment_t extra_data;
    uint32 *str_aggr_pages;
    uint32 str_aggr_page_count;
    group_by_phase_t group_by_phase;
    uint32 key_card;
    variant_t *str_aggr_val;
    union {
        struct {
            // hash group
            bool32 empty;
            union {
                hash_segment_t hash_segment;
                // for hash group par
                struct {
                    hash_segment_t *hash_segment_par;
                    bool32 *empty_par;
                    uint32 par_hash_tab_count;
                };
            };
            hash_table_entry_t group_hash_table;
            hash_scan_assist_t group_hash_scan_assit;
            hash_table_entry_t *hash_tables;
            hash_table_entry_t *hash_dist_tables;
            hash_table_iter_t *iters;
        };

        struct {
            // sort group
            sql_btree_segment_t btree_seg;
            sql_btree_cursor_t btree_cursor;
        };
    };
    char *row_buf;
    uint32 row_buf_len;
} group_ctx_t;

typedef enum en_distinct_type {
    HASH_DISTINCT,
    SORT_DISTINCT,
    HASH_UNION
} distinct_type_t;

typedef struct st_distinct_ctx {
    distinct_type_t type;
    distinct_plan_t *distinct_p;
    union {
        struct {
            // hash distinct
            hash_segment_t hash_segment;
            hash_table_entry_t hash_table_entry;
        };

        struct {
            // sort distinct
            sql_btree_segment_t btree_seg;
            sql_btree_cursor_t btree_cursor;
        };
    };
} distinct_ctx_t;

typedef struct st_unpivot_ctx {
    uint32 row_buf_len;
    char *row_buf;
} unpivot_ctx_t;

typedef struct st_hash_mtrl_ctx {
    group_ctx_t group_ctx; // must be first member

    /* used for sub-select optimize, if can not find row from hash table */
    /* * aggr need output at least one row * */
    char *aggrs;
    uint32 aggr_id;
    /* ************************************* */
    bool32 fetched;
    ct_type_t *key_types;
} hash_mtrl_ctx_t;

typedef struct st_connect_by_mtrl_data {
    hash_entry_t level_entry; // It can be used to find the hash node of the current layer output data.
    hash_table_iter_t iter;
    mtrl_rowid_t prior_row; // for cycle checking
} cb_mtrl_data_t;

typedef struct st_connect_by_mtrl_ctx {
    cb_mtrl_plan_t *cb_mtrl_p;
    uint32 vmid;
    bool32 empty;
    uint32 curr_level;
    uint32 hash_table_rs; // segment id for hashmap rs rows
    hash_segment_t hash_segment;
    hash_table_entry_t hash_table;
    hash_table_iter_t iter;
    galist_t *cb_data; // each layer has a cb_mtrl_data_t to manage the current layer traversal.
    sql_cursor_t *last_cursor;
    sql_cursor_t *curr_cursor;
    sql_cursor_t *next_cursor;
    ct_type_t *key_types;
} cb_mtrl_ctx_t;

typedef struct st_query_mtrl_ctx {
    withas_mtrl_plan_t *withas_p;
    mtrl_resource_t rs;
    bool32 is_ready;
} withas_mtrl_ctx_t;

typedef struct st_vm_view_mtrl_ctx {
    vm_view_mtrl_plan_t *vm_view_p;
    mtrl_resource_t rs;
    bool32 is_ready;
} vm_view_mtrl_ctx_t;

typedef struct st_hash_view_ctx {
    bool8 initialized;
    bool8 unavailable;
    bool8 has_null_key;
    bool8 empty_table;
    uint32 key_count;
    ct_type_t types[SQL_MAX_HASH_OPTM_KEYS];
    hash_segment_t hash_seg;
    hash_table_entry_t hash_table;
} hash_view_ctx_t;

/* used to store the row count skipped by limit offset or limit count */
typedef struct st_found_rows_info {
    uint64 offset_skipcount;
    uint64 limit_skipcount;
} found_rows_info_t;

typedef struct st_hash_join_ctx {
    bool32 right_eof : 1;
    bool32 has_match : 1;
    bool32 need_match_cond : 1;
    bool32 need_swap_driver : 1;
    bool32 scan_hash_table : 1; // flag indicates full scan hash table
    bool32 unused : 27;
    bool32 is_find;
    cond_tree_t *join_cond;
    mtrl_context_t *mtrl_ctx; // clone from parent ctsql_stmt
    ct_type_t *key_types;
    hash_table_iter_t iter;
} hash_join_ctx_t;

typedef struct st_merge_into_hash_data {
    bool32 already_update;
} merge_into_hash_data_t;

typedef struct st_semi_flag {
    uint32 flag;
    bool32 eof;
} semi_flag_t;

typedef struct st_semi_anchor {
    semi_flag_t semi_flags[CT_MAX_JOIN_TABLES];
} semi_anchor_t;

typedef struct st_hash_material {
    struct st_sql_cursor *hj_tables[CT_MAX_JOIN_TABLES]; /* for build hash table */
} hash_material_t;

typedef struct st_nl_full_opt_ctx {
    uint32 id;
    hash_segment_t hash_seg;
    hash_entry_t hash_table_entry;
    hash_table_iter_t iter;
} nl_full_opt_ctx_t;

typedef struct st_sql_par_mgr sql_par_mgr_t;
typedef struct st_sql_cursor_par_ctx {
    sql_par_mgr_t *par_mgr; // used for parallel sql
    bool32 par_threads_inuse : 1;
    bool32 par_need_gather : 1; // if need to gather results from workers
    volatile bool32 par_fetch_st : 2;
    bool32 par_exe_flag : 1; // for parallel avg
    uint32 par_parallel : 8;
    uint32 unused : 19;
} sql_cursor_par_ctx_t;

typedef enum st_hash_table_status {
    HASH_TABLE_STATUS_NOINIT = 0,
    HASH_TABLE_STATUS_CREATE = 1,
    HASH_TABLE_STATUS_CLONE = 2,
} hash_table_status_t;

typedef struct st_idx_func_cache_t {
    expr_node_t *node; // key
    uint16 tab;
    uint16 col;
} idx_func_cache_t;

typedef struct st_sql_cursor {
    sql_stmt_t *stmt;
    plan_node_t *plan;
    union {
        sql_merge_t *merge_ctx;
        sql_update_t *update_ctx;
        sql_delete_t *delete_ctx;
        sql_insert_t *insert_ctx;
        sql_select_t *select_ctx;
    };

    cond_tree_t *cond;
    sql_query_t *query; // for select
    galist_t *columns;  // rs_column_t, for non materialized result set, from sql_query_t
    mtrl_page_t *aggr_page;
    uint32 total_rows;
    uint32 rownum;
    uint32 max_rownum;
    // don't change the definition order of prev and next
    // so sql_cursor_t can be change to biqueue_node_t by macro QUEUE_NODE_OF and be added to a bi-queue
    struct st_sql_cursor *prev;
    struct st_sql_cursor *next;
    struct st_sql_cursor *cursor_maps[CT_MAX_SUBSELECT_EXPRS]; // subselect exprs
    biqueue_t ssa_cursors;                                     // subselect exprs
    uint32 last_table;                                         // the plan_id of the last scanning table
    uint32 table_count;
    uint32 id_maps[CT_MAX_JOIN_TABLES];
    sql_table_cursor_t *tables;
    uint64 scn;
    sql_mtrl_handler_t mtrl;
    merge_into_hash_data_t merge_into_hash;
    connect_by_data_t connect_data;
    struct st_sql_cursor *left_cursor;
    struct st_sql_cursor *right_cursor;
    struct st_sql_cursor *ancestor_ref;

    join_data_t *m_join;
    found_rows_info_t found_rows; /* for the built-in "FOUND_ROWS()" */
    plan_exec_data_t exec_data;   // buffer in vma for union all/limit/group...
    vmc_t vmc;

    hash_segment_t hash_seg;
    hash_entry_t hash_table_entry;
    hash_join_ctx_t *hash_join_ctx;
    union {
        group_ctx_t *group_ctx;
        group_ctx_t *pivot_ctx;
    };
    galist_t *nl_full_ctx_list;
    unpivot_ctx_t *unpivot_ctx;
    hash_mtrl_ctx_t *hash_mtrl_ctx;
    hash_material_t hash_mtrl;
    semi_anchor_t semi_anchor;
    concate_ctx_t *cnct_ctx; // for concate plan execute
    uint32 not_cache : 1;    // 0:will cache,  1: will not cache ,default is cache
    uint32 is_open : 1;
    uint32 is_result_cached : 1;
    uint32 exists_result : 1;
    uint32 winsort_ready : 1;
    uint32 global_cached : 1; // cached scan pages into global CR pool or not
    uint32 hash_table_status : 2;
    bool32 is_mtrl_cursor : 1;
    uint32 reserved : 23;
    bool32 eof;

    sql_cursor_par_ctx_t par_ctx; // for parallel execute sql
    distinct_ctx_t *distinct_ctx;
    cb_mtrl_ctx_t *cb_mtrl_ctx;
    galist_t *idx_func_cache; /* cache for function indexed expression */
} sql_cursor_t;

#ifdef __cplusplus
extern "C" {
#endif

status_t sql_begin_dml(sql_stmt_t *ctsql_stmt);
status_t sql_try_execute_dml(sql_stmt_t *ctsql_stmt);
status_t sql_execute_single_dml(sql_stmt_t *ctsql_stmt, knl_savepoint_t *savepoint);
status_t sql_execute_fetch(sql_stmt_t *ctsql_stmt);
status_t sql_execute_fetch_medatata(sql_stmt_t *ctsql_stmt);
status_t sql_execute_fetch_cursor_medatata(sql_stmt_t *ctsql_stmt);
status_t sql_alloc_cursor(sql_stmt_t *ctsql_stmt, sql_cursor_t **cursor);
status_t sql_alloc_knl_cursor(sql_stmt_t *ctsql_stmt, knl_cursor_t **cursor);
void sql_close_cursor(sql_stmt_t *ctsql_stmt, sql_cursor_t *ctsql_cursor);
void sql_free_cursor(sql_stmt_t *ctsql_stmt, sql_cursor_t *ctsql_cursor);
status_t sql_make_result_set(sql_stmt_t *stmt, sql_cursor_t *cursor);
void sql_init_varea_set(sql_stmt_t *ctsql_stmt, sql_table_cursor_t *table_cursor);
void sql_free_varea_set(sql_table_cursor_t *table_cursor);
void sql_init_sql_cursor(sql_stmt_t *stmt, sql_cursor_t *ctsql_cursor);
void sql_free_cursors(sql_stmt_t *ctsql_stmt);
status_t sql_alloc_global_sql_cursor(object_t **object);
void sql_free_va_set(sql_stmt_t *ctsql_stmt, sql_cursor_t *ctsql_cursor);
status_t sql_parse_anonymous_soft(sql_stmt_t *ctsql_stmt, word_t *leader, sql_text_t *sql);
status_t sql_parse_anonymous_directly(sql_stmt_t *ctsql_stmt, word_t *leader, sql_text_t *sql);
void sql_free_merge_join_data(sql_stmt_t *ctsql_stmt, join_data_t *m_join);
void sql_free_knl_cursor(sql_stmt_t *ctsql_stmt, knl_cursor_t *ctsql_cursor);
ct_type_t sql_get_pending_type(char *pending_buf, uint32 id);
status_t sql_try_put_dml_batch_error(sql_stmt_t *ctsql_stmt, uint32 row, int32 error_code, const char *message);
void sql_release_json_table(sql_table_cursor_t *tab_cursor);
void sql_free_nl_full_opt_ctx(nl_full_opt_ctx_t *opt_ctx);

static inline sql_cursor_t *sql_get_proj_cursor(sql_cursor_t *cursor)
{
    return cursor;
}

static inline void sql_inc_rows(sql_stmt_t *ctsql_stmt, sql_cursor_t *cursor)
{
    ctsql_stmt->batch_rows++;
    cursor->total_rows++;
}

static inline void sql_cursor_cache_result(sql_cursor_t *cursor, bool32 result)
{
    cursor->exists_result = result;
    cursor->is_result_cached = CT_TRUE;
}

/*
 * Get the upper of rownum from a *cond_tree_t*, if the cond_tree is
 * null, then return CT_INFINITE32.
 */
#define GET_MAX_ROWNUM(cond) (((cond) != NULL) ? (cond)->rownum_upper : CT_INFINITE32)

static inline status_t sql_get_ancestor_cursor(sql_cursor_t *curr_cur, uint32 ancestor, sql_cursor_t **ancestor_cur)
{
    uint32 depth = 0;

    *ancestor_cur = curr_cur;

    if (curr_cur == NULL) {
        CT_THROW_ERROR(ERR_VALUE_ERROR, "no sql prepare cannot get column value");
        return CT_ERROR;
    }

    while (depth < (ancestor)) {
        if ((*ancestor_cur)->ancestor_ref == NULL) {
            CT_THROW_ERROR(ERR_ANCESTOR_LEVEL_MISMATCH);
            return CT_ERROR;
        }
        (*ancestor_cur) = (*ancestor_cur)->ancestor_ref;
        depth++;
    }
    return CT_SUCCESS;
}

static inline status_t sql_alloc_ssa_cursor(sql_cursor_t *cursor, sql_select_t *select_ctx, uint32 id,
    sql_cursor_t **sql_cur)
{
    // cursor should use same ctsql_stmt with ssa_cursor
    CT_RETURN_IFERR(sql_alloc_cursor(cursor->stmt, sql_cur));
    (*sql_cur)->select_ctx = select_ctx;
    (*sql_cur)->plan = select_ctx->plan;
    (*sql_cur)->scn = cursor->scn;
    (*sql_cur)->ancestor_ref = cursor;
    (*sql_cur)->global_cached = CT_TRUE;
    cursor->cursor_maps[id] = *sql_cur;
    biqueue_add_tail(&cursor->ssa_cursors, QUEUE_NODE_OF(*sql_cur));
    return CT_SUCCESS;
}

static inline status_t sql_get_ssa_cursor(sql_cursor_t *cursor, sql_select_t *select_ctx, uint32 id,
    sql_cursor_t **sql_cur)
{
    *sql_cur = cursor->cursor_maps[id];
    if (*sql_cur != NULL) {
        return CT_SUCCESS;
    }
    return sql_alloc_ssa_cursor(cursor, select_ctx, id, sql_cur);
}

static inline void sql_init_ssa_cursor_maps(sql_cursor_t *cursor, uint32 ssa_count)
{
    for (uint32 i = 0; i < ssa_count; i++) {
        cursor->cursor_maps[i] = NULL;
    }
}

static inline status_t sql_alloc_table_cursors(sql_cursor_t *cursor, uint32 table_cnt)
{
    return vmc_alloc_mem(&cursor->vmc, sizeof(sql_table_cursor_t) * table_cnt, (void **)&cursor->tables);
}

static inline void sql_cursor_hash_table_clone(sql_stmt_t *main_stmt, sql_cursor_t *src, sql_cursor_t *dest)
{
    dest->hash_seg = src->hash_seg;
    dest->hash_table_entry = src->hash_table_entry;
    dest->hash_join_ctx->right_eof = CT_TRUE;
    dest->hash_join_ctx->has_match = CT_FALSE;
    dest->hash_join_ctx->mtrl_ctx = &main_stmt->mtrl;
    dest->mtrl.hash_table_rs = src->mtrl.hash_table_rs;
}
static inline sql_cursor_t *sql_get_group_cursor(sql_cursor_t *cursor)
{
    if (cursor->mtrl.cursor.type != MTRL_CURSOR_HASH_GROUP || cursor->exec_data.group_cube == NULL ||
        cursor->exec_data.group_cube->fetch_cursor == NULL) {
        return cursor;
    }
    return cursor->exec_data.group_cube->fetch_cursor;
}

#ifdef __cplusplus
}
#endif

#endif
