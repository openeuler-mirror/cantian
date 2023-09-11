/* -------------------------------------------------------------------------
 *  This file is part of the Cantian project.
 * Copyright (c) 2023 Huawei Technologies Co.,Ltd.
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
 * srv_query.h
 *
 *
 * IDENTIFICATION
 * src/cmd/srv_query.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_SELECT_H__
#define __SQL_SELECT_H__

#include "cm_hash.h"
#include "cm_defs.h"
#include "cm_lex.h"
#include "cm_bilist.h"
#include "knl_privilege.h"
#include "srv_session.h"
#include "cm_chan.h"
#include "cm_list.h"
#include "knl_database.h"
#include "var_inc.h"
#include "cm_text.h"
#include "cm_uuid.h"
#include <math.h>
#include "cm_base.h"
#include "cm_stack.h"
#include "cm_date.h"
#include "cm_vma.h"
#include "cm_spinlock.h"
#include "cs_protocol.h"
#include "srv_agent.h"
#include "knl_interface.h"
#include "cm_partkey.h"
#include "cm_log.h"
#include "cm_error.h"
#include "cm_memory.h"
#include "cm_context_pool.h"
#include "cs_pipe.h"
#include "cm_word.h"

typedef enum en_sql_type {
    SQL_TYPE_NONE = 0,
    SQL_TYPE_SELECT = 1,
    SQL_TYPE_UPDATE,
    SQL_TYPE_INSERT,
    SQL_TYPE_DELETE,
    SQL_TYPE_MERGE,
    SQL_TYPE_REPLACE, /* replace into */

    SQL_TYPE_DML_CEIL, /* pseudo */
    SQL_TYPE_BEGIN,    /* ONLY FOR PGS */
    SQL_TYPE_COMMIT_PHASE1,
    SQL_TYPE_COMMIT_PHASE2,
    SQL_TYPE_COMMIT,
    SQL_TYPE_ROLLBACK_PHASE2,
    SQL_TYPE_ROLLBACK,
    SQL_TYPE_ROLLBACK_TO,
    SQL_TYPE_SAVEPOINT,
    SQL_TYPE_RELEASE_SAVEPOINT,
#ifdef DB_DEBUG_VERSION
    SQL_TYPE_SYNCPOINT,
#endif /* DB_DEBUG_VERSION */
    SQL_TYPE_SET_TRANS,
    SQL_TYPE_BACKUP,
    SQL_TYPE_RESTORE,
    SQL_TYPE_RECOVER,
    SQL_TYPE_SHUTDOWN,
    SQL_TYPE_LOCK_TABLE,
    SQL_TYPE_BUILD,
    SQL_TYPE_CHECKPOINT,
    SQL_TYPE_ROUTE,
    SQL_TYPE_VALIDATE,
    SQL_TYPE_ALTER_SYSTEM,
    SQL_TYPE_ALTER_SESSION,
    SQL_TYPE_LOCK_NODE,
    SQL_TYPE_UNLOCK_NODE,
    SQL_TYPE_DAAC,
    SQL_TYPE_DCL_CEIL, /* pseudo */

    SQL_TYPE_CREATE_DATABASE,
    SQL_TYPE_CREATE_CLUSTERED_DATABASE,
    SQL_TYPE_CREATE_DATABASE_LINK,
    SQL_TYPE_CREATE_DISTRIBUTE_RULE,
    SQL_TYPE_CREATE_SEQUENCE,
    SQL_TYPE_CREATE_TABLESPACE,
    SQL_TYPE_CREATE_TABLE,
    SQL_TYPE_CREATE_INDEX,
    SQL_TYPE_CREATE_USER,
    SQL_TYPE_CREATE_ROLE,
    SQL_TYPE_CREATE_TENANT,
    SQL_TYPE_CREATE_VIEW,
    SQL_TYPE_CREATE_NODE,
    SQL_TYPE_CREATE_SYNONYM,
    SQL_TYPE_CREATE_PROFILE,
    SQL_TYPE_CREATE_DIRECTORY,
    SQL_TYPE_CREATE_CTRLFILE,
    SQL_TYPE_CREATE_LIBRARY,
    SQL_TYPE_CREATE_INDEXES,

    SQL_TYPE_DROP_DATABASE_LINK,
    SQL_TYPE_DROP_DIRECTORY,
    SQL_TYPE_DROP_SEQUENCE,
    SQL_TYPE_DROP_TABLESPACE,
    SQL_TYPE_DROP_TABLE,
    SQL_TYPE_DROP_INDEX,
    SQL_TYPE_DROP_USER,
    SQL_TYPE_DROP_ROLE,
    SQL_TYPE_DROP_TENANT,
    SQL_TYPE_DROP_VIEW,
    SQL_TYPE_DROP_SYNONYM,
    SQL_TYPE_DROP_PROFILE,
    SQL_TYPE_DROP_NODE,
    SQL_TYPE_DROP_DISTRIBUTE_RULE,
    SQL_TYPE_DROP_SQL_MAP,
    SQL_TYPE_DROP_LIBRARY,
    SQL_TYPE_TRUNCATE_TABLE,
    SQL_TYPE_PURGE,
    SQL_TYPE_COMMENT,
    SQL_TYPE_FLASHBACK_TABLE,

    SQL_TYPE_ALTER_DATABASE_LINK,
    SQL_TYPE_ALTER_SEQUENCE,
    SQL_TYPE_ALTER_TABLESPACE,
    SQL_TYPE_ALTER_TABLE,
    SQL_TYPE_ALTER_INDEX,
    SQL_TYPE_ALTER_USER,
    SQL_TYPE_ALTER_TENANT,
    SQL_TYPE_ALTER_DATABASE,
    SQL_TYPE_ALTER_NODE,
    SQL_TYPE_ALTER_PROFILE,
    SQL_TYPE_ALTER_TRIGGER,
    SQL_TYPE_ALTER_SQL_MAP,
    SQL_TYPE_ANALYSE_TABLE,
    SQL_TYPE_ANALYZE_INDEX,
    SQL_TYPE_GRANT,
    SQL_TYPE_REVOKE,
    SQL_TYPE_CREATE_CHECK_FROM_TEXT,
    SQL_TYPE_CREATE_EXPR_FROM_TEXT,
    SQL_TYPE_INHERIT_PRIVILEGES,
    SQL_TYPE_CREATE_PROC,
    SQL_TYPE_CREATE_FUNC,
    SQL_TYPE_CREATE_TRIG,
    SQL_TYPE_CREATE_PACK_SPEC, /* package specification */
    SQL_TYPE_CREATE_PACK_BODY, /* package body */
    SQL_TYPE_CREATE_TYPE_SPEC, /* type specification */
    SQL_TYPE_CREATE_TYPE_BODY, /* type body */
    SQL_TYPE_DROP_PROC,
    SQL_TYPE_DROP_FUNC,
    SQL_TYPE_DROP_TRIG,

    SQL_TYPE_DROP_PACK_SPEC, /* package specification */
    SQL_TYPE_DROP_PACK_BODY, /* package body */
    SQL_TYPE_DROP_TYPE_SPEC, /* type specification */
    SQL_TYPE_DROP_TYPE_BODY, /* type body */
    SQL_TYPE_DDL_CEIL,       /* pseudo */
    SQL_TYPE_ANONYMOUS_BLOCK,
    SQL_TYPE_PL_CEIL_END, /* pl_pseudo_end */
} sql_type_t;

#define SQL_OPT_PWD_DDL_TYPE(type)                                                                                 \
    ((type) == SQL_TYPE_CREATE_USER || (type) == SQL_TYPE_ALTER_USER || (type) == SQL_TYPE_CREATE_DATABASE_LINK || \
     (type) == SQL_TYPE_ALTER_DATABASE_LINK || (type) == SQL_TYPE_CREATE_NODE || (type) == SQL_TYPE_ALTER_NODE)

typedef struct st_sql_param_mark {
    uint32 offset;
    uint16 len;
    uint16 pnid;  // paramter name id
} sql_param_mark_t;

typedef struct st_sql_table_entry {
    text_t user;
    text_t name;
    text_t dblink;  // user.tab[@dblink], user1.t1@link_name
    uint32 tab_hash_val;
    knl_dictionary_t dc;
} sql_table_entry_t;

typedef struct st_sql_package_user {
    text_t package;
    text_t user;
} sql_package_user_t;
typedef enum en_rs_type {
    RS_TYPE_NONE = 0,
    RS_TYPE_NORMAL,
    RS_TYPE_SORT,
    RS_TYPE_HASH_GROUP,
    RS_TYPE_AGGR,
    RS_TYPE_UNION,
    RS_TYPE_UNION_ALL,
    RS_TYPE_MINUS,
    RS_TYPE_LIMIT,
    RS_TYPE_WINSORT,
    RS_TYPE_ROW,
    RS_TYPE_ROWNUM,
    RS_TYPE_FOR_UPDATE,
} rs_type_t;

typedef enum en_sql_node_type {
    SQL_MERGE_NODE = 1,
    SQL_UPDATE_NODE = 2,
    SQL_DELETE_NODE = 3,
    SQL_QUERY_NODE = 4,
    SQL_SELECT_NODE = 5,
} sql_node_type_t;

typedef struct st_clause_info {
    uint32 union_all_count;
} clause_info_t;

typedef struct st_sql_withas {
    galist_t *withas_factors;  // list of with as(sql_withas_factor_t)
    uint32 cur_match_idx;      // for check with as can't reference later with as definition
    uint32 cur_level;
} sql_withas_t;

/* For parse result of hint expression */
typedef struct st_hint_item {
    hint_id_t id;
    struct st_expr_tree *args;
} hint_item_t;

typedef struct st_opt_param_bool {
    uint64 enable_cb_mtrl : 1;
    uint64 enable_aggr_placement : 1;
    uint64 enable_all_transform : 1;
    uint64 enable_any_transform : 1;
    uint64 enable_connect_by_placement : 1;
    uint64 enable_distinct_elimination : 1;
    uint64 enable_filter_pushdown : 1;
    uint64 enable_group_by_elimination : 1;
    uint64 enable_hash_mtrl : 1;
    uint64 enable_join_elimination : 1;
    uint64 enable_join_pred_pushdown : 1;
    uint64 enable_order_by_elimination : 1;
    uint64 enable_order_by_placement : 1;
    uint64 enable_or_expand : 1;
    uint64 enable_pred_move_around : 1;
    uint64 enable_pred_reorder : 1;
    uint64 enable_project_list_pruning : 1;
    uint64 enable_subquery_elimination : 1;
    uint64 enable_unnest_set_subq : 1;
    uint64 vm_view_enabled : 1;
    uint64 enable_winmagic_rewrite : 1;
    uint64 reserved : 43;
} opt_param_bool_t;

typedef struct st_opt_param_info {
    union {
        opt_param_bool_t bool_value;
        uint64 value;
    };
    union {
        opt_param_bool_t bool_status;
        uint64 status;
    };
    uint32 dynamic_sampling;
} opt_param_info_t;

typedef struct opt_estimate_info_t {
    double scale_rows;
    int64 rows;
    int64 min_rows;
    int64 max_rows;
} opt_estimate_info_t;

typedef enum en_unnamed_tab_type {
    TAB_TYPE_PIVOT = 0,
    TAB_TYPE_UNPIVOT,
    TAB_TYPE_TABLE_FUNC,
    TAB_TYPE_OR_EXPAND,
    TAB_TYPE_WINMAGIC,
    TAB_TYPE_SUBQRY_TO_TAB,
    TAB_TYPE_UPDATE_SET,
    TAB_TYPE_MAX
} unnamed_tab_type_t;

typedef struct st_unnamed_tab_info {
    unnamed_tab_type_t type;
    text_t prefix;
} unnamed_tab_info_t;

/*
    For original parse results and query-level hint information after verification
*/
typedef struct st_hint_info {
    text_t info;
    // parse result, used only in parse-verify
    galist_t *items;  // hint_item_t
    opt_param_info_t *opt_params;
    opt_estimate_info_t *opt_estimate;
    // hint info after verify
    uint64 mask[MAX_HINT_TYPE];
    void *args[MAX_HINT_WITH_TABLE_ARGS];  // galist *
    uint32 leading_id;
} hint_info_t;

typedef struct st_sql_context {
    context_ctrl_t ctrl;
    galist_t *params;      // parameter list
    galist_t *csr_params;  // cursor sharing parameter list
    galist_t *tables;      // all tables (not include subselect)
    galist_t *rs_columns;  // result set column list
    void *entry;           // sql entry
    void *withas_entry;    // with as clause entry
    sql_type_t type;
    uint32 pname_count;  // number of distinct parameter name
    galist_t *selects;   // all select context
    void *supplement;
    hint_info_t *hint_info;  // storage opt_param hint
    bool32 has_ltt : 1;      // sql has local temporary table
    bool32 cacheable : 1;    // sql context if is able to be cached, default TRUE
    bool32 in_sql_pool : 1;  // sql context if has been cached, default FALSE
    bool32 opt_by_rbo : 1;
    bool32 obj_belong_self : 1;  // if all the objects accessed belong to self, include base tables in views
    bool32 has_pl_objects : 1;   // sql has user func or sys package, need check privilege
    bool32 need_vpeek : 1;       // for bind variable peeking
    bool32 is_opt_ctx : 1;
    bool32 always_vpeek : 1;
    bool32 has_func_tab : 1;
    bool32 sql_whitelist : 1;
    bool32 shd_read_master : 1;
    bool32 policy_used : 1;
    bool32 has_func_index : 1;
    bool32 has_dblink : 1;
    bool32 in_spm : 1;  // means this context was created by spm
    bool32 unused : 13;
    uint32 sub_map_id;
    atomic32_t vpeek_count;
    atomic32_t readonly;
    struct st_sql_context *parent;
    text_t spm_sign;  // associated with sys_spm's signature
    text_t sql_sign;  // text_addr SQL text MD5 sign
    clause_info_t clause_info;

    galist_t *dc_lst;       // plm dc used in this context(include view)
    galist_t *ref_objects;  // direct ref objects (procedure, table, sequence)
    galist_t *sequences;    // sequences in used in this context
    galist_t *outlines;
    uint32 *unnamed_tab_counter;  // record the number of unnamed tables of different types, max size is TAB_TYPE_MAX
    uint32 large_page_id;
    uint32 fexec_vars_cnt;    /* Record the number of first executable variants */
    uint32 fexec_vars_bytes;  /* Record the memory size of first executable variants which return text type  */
    uint32 hash_optm_count;   /* Record the number of in condition list that can be optimized by hash table  */
    uint32 dynamic_sampling;  // the level of dynamic sampling
    uint32 module_kind;       // the application kind of the currently executing user
    uint32 hash_bucket_size;
    uint32 parallel;
    uint32 nl_batch_cnt;
    uint32 plan_count;
    uint32 vm_view_count;
    uint32 hash_mtrl_count;
    uint32 query_count;
} sql_context_t;

typedef struct st_sql_array {
    void *context;
    ga_alloc_func_t alloc_func;
    text_t name;
    uint32 count;
    uint32 capacity;
    pointer_t *items;
} sql_array_t;

typedef enum sql_clause {
    CLAUSE_SELECT = 0,
    CLAUSE_WHERE,
    CLAUSE_ORDER_BY,
    CLAUSE_GROUP_BY,
    CLAUSE_HAVING,
} sql_clause_t;

typedef struct {
    sort_direction_t direction; /* the ordering direction: ASC/DESC */
    sort_nulls_t nulls_pos;     /* position of NULLS: NULLS FIRST/NULLS LAST */
} order_mode_t;

typedef struct st_sort_item {
    struct st_expr_tree *expr;

    union {  // use union for compatibility previous usage
        struct {
            sort_direction_t direction; /* the ordering direction: ASC/DESC */
            sort_nulls_t nulls_pos;     /* position of NULLS: NULLS FIRST/NULLS LAST */
        };
        order_mode_t sort_mode;
    };
} sort_item_t;

/* NULLS LAST is the default for ascending order, and NULLS FIRST is the default for descending order. */
#define DEFAULT_NULLS_SORTING_POSITION(sort_dir) (((sort_dir) == SORT_MODE_ASC) ? SORT_NULLS_LAST : SORT_NULLS_FIRST)

typedef struct st_btree_sort_key {
    uint32 group_id;
    order_mode_t sort_mode;
} btree_sort_key_t;

typedef struct st_btree_cmp_key {
    uint32 group_id;
} btree_cmp_key_t;

typedef enum en_window_border_type {
    WB_TYPE_UNBOUNDED_PRECED = 0,
    WB_TYPE_VALUE_PRECED,
    WB_TYPE_CURRENT_ROW,
    WB_TYPE_VALUE_FOLLOW,
    WB_TYPE_UNBOUNDED_FOLLOW,
} window_border_type_t;

typedef struct st_windowing_args {
    struct st_expr_tree *l_expr;
    struct st_expr_tree *r_expr;
    uint32 l_type;
    uint32 r_type;
    bool32 is_range;
} windowing_args_t;

typedef struct st_winsort_args {
    galist_t *sort_items;
    galist_t *group_exprs;
    windowing_args_t *windowing;
    uint32 sort_columns;
    bool32 is_rs_node;
} winsort_args_t;

typedef struct st_select_sort_item {
    uint32 rs_columns_id;
    gs_type_t datatype;
    order_mode_t sort_mode;
} select_sort_item_t;

typedef struct st_limit_item {
    void *count;
    void *offset;
} limit_item_t;

typedef struct st_join_cond_map {
    uint32 table1_id;
    uint32 table2_id;
    galist_t cmp_list;
} join_cond_map_t;

#define EX_QUERY_SORT (uint32)0x00000001
#define EX_QUERY_AGGR (uint32)0x00000002
#define EX_QUERY_HAVING (uint32)0x00000004
#define EX_QUERY_DISTINCT (uint32)0x00000008
#define EX_QUERY_LIMIT (uint32)0x00000010
#define EX_QUERY_ONEROW (uint32)0x00000020
#define EX_QUERY_CONNECT (uint32)0x00000040
#define EX_QUERY_FILTER (uint32)0x00000080
#define EX_QUERY_WINSORT (uint32)0x00000100
#define EX_QUERY_SIBL_SORT (uint32)0x00000200
#define EX_QUERY_CUBE (uint32)0x00000400
#define EX_QUERY_PIVOT (uint32)0x00000800
#define EX_QUERY_UNPIVOT (uint32)0x00001000
#define EX_QUERY_ROWNUM (uint32)0x00002000
#define EX_QUERY_FOR_UPDATE (uint32)0x00004000

typedef enum en_sql_join_type {
    JOIN_TYPE_NONE = 0x00000000,
    JOIN_TYPE_COMMA = 0x00010000,
    JOIN_TYPE_CROSS = 0x00020000,
    JOIN_TYPE_INNER = 0x00040000,
    JOIN_TYPE_LEFT = 0x00080000,
    JOIN_TYPE_RIGHT = 0x00100000,
    JOIN_TYPE_FULL = 0x00200000,
} sql_join_type_t;

/* Remember to modify `g_join_oper_desc` synchronously when modify the following contents */
typedef enum en_join_oper {
    JOIN_OPER_NONE = 0,
    JOIN_OPER_NL = 1,
    JOIN_OPER_NL_BATCH = 2,
    JOIN_OPER_NL_LEFT = 3,
    JOIN_OPER_NL_FULL = 4,
    /* !!NOTICE!! Keep HASH join oper below */
    JOIN_OPER_HASH,
    JOIN_OPER_HASH_LEFT,
    JOIN_OPER_HASH_FULL,
    JOIN_OPER_HASH_RIGHT_LEFT,
    JOIN_OPER_MERGE,
    JOIN_OPER_MERGE_LEFT,
    JOIN_OPER_MERGE_FULL,
    /* Keep SEMI/ANTI join oper below */
    JOIN_OPER_HASH_SEMI,
    JOIN_OPER_HASH_ANTI,
    JOIN_OPER_HASH_ANTI_NA,
    JOIN_OPER_HASH_RIGHT_SEMI,
    JOIN_OPER_HASH_RIGHT_ANTI,
    JOIN_OPER_HASH_RIGHT_ANTI_NA,
    JOIN_OPER_HASH_PAR,
} join_oper_t;

typedef enum en_nl_full_opt_type {
    NL_FULL_OPT_NONE = 0,
    NL_FULL_ROWID_MTRL,
    NL_FULL_DUPL_DRIVE,
} nl_full_opt_type_t;

typedef struct st_nl_full_opt_info {
    nl_full_opt_type_t opt_type;
    union {
        struct st_sql_table *r_drive_table;
        struct st_sql_join_node *r_drive_tree;
    };
} nl_full_opt_info_t;

typedef struct st_sql_join_node {
    join_oper_t oper;
    sql_join_type_t type;
    struct st_cond_tree *join_cond;
    struct st_cond_tree *filter;
    sql_array_t tables;  // records tables belong to current join node, for verify join cond
    struct st_sql_join_node *left;
    struct st_sql_join_node *right;
    struct st_sql_join_node *prev;
    struct st_sql_join_node *next;
    uint32 plan_id_start;
    struct {
        bool32 hash_left : 1;
        bool32 is_cartesian_join : 1;  // join cond cannot choose join edge, like true or a.f1 + b.f1 = c.f1
        bool32 unused : 30;
    };
    nl_full_opt_info_t nl_full_opt_info;
} sql_join_node_t;
#define TABLE_OF_JOIN_LEAF(node) ((struct st_sql_table *)((node)->tables.items[0]))
#define SET_TABLE_OF_JOIN_LEAF(node, table) \
    do {                                    \
        (node)->tables.items[0] = (table);  \
        (node)->tables.count = 1;           \
    } while (0)

typedef struct st_sql_join_chain {
    uint32 count;
    sql_join_node_t *first;
    sql_join_node_t *last;
} sql_join_chain_t;

typedef struct st_sql_table_hint {
    void *table; /* sql_table_t * */
} sql_table_hint_t;

typedef struct st_sql_join_assist_t {
    sql_join_node_t *join_node;
    uint32 outer_plan_count;
    uint32 outer_node_count;
    uint32 inner_plan_count;
    uint32 mj_plan_count;
    bool32 has_hash_oper;
} sql_join_assist_t;

typedef struct st_group_set {
    uint32 group_id;
    uint32 count;  // valid expr count
    galist_t *items;
} group_set_t;

typedef struct st_cube_node {
    uint32 plan_id;
    group_set_t *group_set;
    galist_t *leafs;
} cube_node_t;

typedef struct st_connect_by_mtrl_info {
    galist_t *prior_exprs;
    galist_t *key_exprs;
    bool32 combine_sw;  // start with plan share cb mtrl data
} cb_mtrl_info_t;

typedef struct st_query_block_info {
    uint32 origin_id;
    bool32 transformed;
    text_t origin_name;
    text_t changed_name;
} query_block_info_t;

typedef struct st_vpeek_assist {
    struct st_cond_tree *vpeek_cond;  // all conditions which contain bind variables for binding peeking
    uint64 vpeek_tables;              // table's id bit mask with binding param condition
} vpeek_assist_t;

typedef struct st_sql_query {
    source_location_t loc;
    struct st_sql_select *owner;
    galist_t *columns;     // expression columns in select list
    galist_t *rs_columns;  // result set columns, '*' is extracted
    galist_t *winsort_rs_columns;
    sql_array_t tables;
    sql_array_t ssa;  // SubSelect Array for subselect expr
    galist_t *aggrs;
    galist_t *cntdis_columns;
    galist_t *sort_items;
    galist_t *group_sets;   // list of group_set_t, store local columns for hash mtrl optimized
    galist_t *group_cubes;  // list of cube_node_t, for group by cube optimization
    galist_t *sort_groups;
    galist_t *distinct_columns;
    galist_t *exists_dist_columns;  // list of expr_node_t
    galist_t *winsort_list;
    galist_t *join_symbol_cmps;
    galist_t *remote_keys;         // store parent columns for hash mtrl optimization
    cb_mtrl_info_t *cb_mtrl_info;  // store hash keys for connect by mtrl optimization
    vpeek_assist_t *vpeek_assist;
    struct st_cond_tree *cond;
    struct st_cond_tree *filter_cond;
    struct st_cond_tree *having_cond;
    struct st_cond_tree *start_with_cond;
    struct st_cond_tree *connect_by_cond;
    struct st_sql_query *s_query;  // sub-query for start with scan
    struct {
        uint16 for_update : 1;
        uint16 connect_by_nocycle : 1;
        uint16 connect_by_prior : 1;
        uint16 connect_by_iscycle : 1;
        uint16 calc_found_rows : 1; /* for the FOUND_ROWS() function, used by query limit plan */
        uint16 cond_has_acstor_col : 1;
        uint16 order_siblings : 1;
        uint16 is_exists_query : 1;
        uint16 exists_covar : 1;
        uint16 is_s_query : 1;  // indicates this is the duplicated sub-query for start with
        uint16 has_distinct : 1;
        uint16 has_filter_opt : 1;
        uint16 has_aggr_sort : 1;     // query has aggr func with sort items like listagg
        uint16 has_no_or_expand : 1;  // query already has no_or_expand flag or not
        uint16 reserved : 2;
    };
    uint16 incl_flags;
    uint32 extra_flags;  // for order by, having, group by ...
    limit_item_t limit;
    hint_info_t *hint_info;
    sql_join_assist_t join_assist;
    uint32 aggr_dis_count;
    sql_join_node_t *join_root;
    galist_t *path_func_nodes;  // recode the function node for connect by path.
    int64 join_card;            // only for eliminate sort and cut cost
    void *filter_infos;         // for recalc table cost, alloced from VMC, used in creating plan.
    vmc_t *vmc;                 // for temporary memory alloc in creating plan
    query_block_info_t *block_info;
} sql_query_t;

/* get the calc_found_rows flag from the sql_select_t to whom the query belongs */
#define QUERY_NEEDS_CALC_FOUNDROWS(query) (((query)->owner) ? ((query)->owner->calc_found_rows) : GS_FALSE)

typedef enum st_select_node_type {
    SELECT_NODE_UNION = 1,
    SELECT_NODE_UNION_ALL = 2,
    SELECT_NODE_INTERSECT = 4,
    SELECT_NODE_MINUS = 8,
    SELECT_NODE_QUERY = 16,
    SELECT_NODE_INTERSECT_ALL = 32,
    SELECT_NODE_EXCEPT = 64,
    SELECT_NODE_EXCEPT_ALL = 128,
} select_node_type_t;

typedef struct st_select_node {
    select_node_type_t type;
    sql_query_t *query;

    // for set tree
    struct st_select_node *left;
    struct st_select_node *right;

    // for set chain
    struct st_select_node *prev;
    struct st_select_node *next;
} select_node_t;

typedef struct st_select_chain {
    uint32 count;
    select_node_t *first;
    select_node_t *last;
} select_chain_t;

typedef enum en_rs_column_type {
    RS_COL_CALC = 1,
    RS_COL_COLUMN,
} rs_column_type_t;

#define RS_SINGLE_COL 0x01
#define RS_EXIST_ALIAS 0x02
#define RS_NULLABLE 0x04
#define RS_HAS_QUOTE 0x08
#define RS_COND_UNABLE 0x10
#define RS_HAS_ROWNUM 0x20
#define RS_HAS_AGGR 0x40
#define RS_HAS_GROUPING 0x80
#define RS_IS_SERIAL 0x0100

#define RS_SET_FLAG(_set_, _rs_col_, _flag_)         \
    if ((_set_)) {                                   \
        GS_BIT_SET((_rs_col_)->rs_flag, (_flag_));   \
    } else {                                         \
        GS_BIT_RESET((_rs_col_)->rs_flag, (_flag_)); \
    }

typedef struct st_rs_column {
    rs_column_type_t type;
    text_t name;     // if exist_alias is true, name is column alias
    text_t z_alias;  // auto generated alias, for SHARD decompile sql
    uint16 rs_flag;
    union {
        /* These definitions is same as the `typmode_t`, thus they should
             be replaced by typmode_t for unifying the definition of columns */
        struct {
            gs_type_t datatype;
            uint16 size;
            uint8 precision;
            int8 scale;
        };
        typmode_t typmod;
    };
    union {
        var_column_t v_col;         // table column
        struct st_expr_tree *expr;  // calc column
    };
    uint32 win_rs_refs;  // record window rs ref count
} rs_column_t;

#define RS_COLUMN_IS_RESERVED_NULL(rs_col) \
    ((rs_col)->size == 0 && (rs_col)->type == RS_COL_CALC && NODE_IS_RES_NULL((rs_col)->expr->root))

typedef enum en_select_type {
    SELECT_AS_RESULT = 1,
    SELECT_AS_SET,
    SELECT_AS_TABLE,
    SELECT_AS_VARIANT,
    SELECT_AS_MULTI_VARIANT,
    SELECT_AS_VALUES,
    SELECT_AS_LIST,  // in clause
} select_type_t;

/* definition of with as clause */
typedef struct st_sql_subquery_factor {
    uint32 depth;
    uint32 level;
    uint32 refs;    /* withas reference count */
    bool32 is_mtrl; /* materialize hint occurs */
    sql_text_t user;
    sql_text_t name;
    sql_text_t subquery_sql;
    void *subquery_ctx;
} sql_withas_factor_t;

typedef struct st_parent_ref {
    uint32 tab;
    galist_t *ref_columns;
} parent_ref_t;

typedef struct st_sql_select {
    galist_t *rs_columns;
    sql_query_t *parent;
    sql_query_t *first_query;  // the first query in select
    select_type_t type;
    double cost;
    int64 drive_card;
    struct st_plan_node *plan;
    select_chain_t chain;
    select_node_t *root;
    rowmark_t for_update_params;
    galist_t *for_update_cols;  // select...for update [of col_list]
    bool8 for_update;           // flag for "select...for update"
    bool8 calc_found_rows;      // flag for the FOUND_ROWS() function, used by select limit plan
    uint8 has_ancestor;     // flag records the levels of the ancestor refs, three levels above self recorded in detail
    bool8 is_update_value;  // flag indicates that the select is in update set clause
    bool8 is_withas;        // flag indicates that the select is withas
    bool8 can_sub_opt;      // flag indicates that the select is in update set clause can be optimized
    uint8 reserved[1];      // reserved flags, 8 bytes align
    rs_type_t rs_type;
    struct st_plan_node *rs_plan;
    void *cond_cursor;
    galist_t *sort_items;
    galist_t *select_sort_items;
    limit_item_t limit;
    struct st_sql_select *prev;
    struct st_sql_select *next;
    uint32 pending_col_count;
    galist_t *parent_refs;
    galist_t *withass;    // all withas context in current select clause
    galist_t *pl_dc_lst;  // record plsql objects in current select context, for check privilege
} sql_select_t;

typedef enum en_sql_snapshot_type {
    CURR_VERSION = 0,
    SCN_VERSION = 1,
    TIMESTAMP_VERSION = 2,
} sql_snapshot_type_t;

typedef struct st_table_version {
    sql_snapshot_type_t type;
    void *expr;
} sql_table_snapshot_t;

typedef enum en_sql_table_type {
    NORMAL_TABLE,
    VIEW_AS_TABLE,
    SUBSELECT_AS_TABLE,
    FUNC_AS_TABLE,
    JOIN_AS_TABLE,  // t1.join (t2 join t3 on ...) on ..., t2 join t3 is join_as_table, temporarily exists
    WITH_AS_TABLE,
    JSON_TABLE,
} sql_table_type_t;

extern bool8 g_subselect_flags[];

/* use it carefully !!! */
#define GS_IS_SUBSELECT_TABLE(type) (g_subselect_flags[type])

typedef enum en_subslct_table_usage {
    SUBSELECT_4_NORMAL_JOIN = 0,
    SUBSELECT_4_NL_JOIN,
    SUBSELECT_4_SEMI_JOIN,
    SUBSELECT_4_ANTI_JOIN,
    SUBSELECT_4_ANTI_JOIN_NA,
} subslct_table_usage_t;

typedef enum en_reserved_prj {
    COL_RESERVED_ROWNODEID = 0,
    COL_RESERVED_CEIL,
} reserved_prj_t;

typedef struct st_table_func {
    text_t user;
    text_t package;
    text_t name;
    struct st_table_func_desc *desc;
    struct st_expr_tree *args;
    source_location_t loc;
} table_func_t;

typedef struct st_project_col_info {
    uint32 project_id;
    text_t *col_name;
    text_t *tab_alias_name;
    text_t *tab_name;
    text_t *user_name;
    bool8 col_name_has_quote; /* origin col_name wrapped by double quotation or not */
    bool8 tab_name_has_quote; /* origin tab_name wrapped by double quotation or not */
    bool8 reserved[2];
} project_col_info_t;

#define PROJECT_COL_ARRAY_STEP 64

typedef struct st_project_col_array {
    uint32 count;
    project_col_info_t **base;
} project_col_array_t;

project_col_info_t *sql_get_project_info_col(project_col_array_t *project_col_array, uint32 col_id);

#define REMOTE_TYPE_LOCAL 0x00000000        // DN Local Table, need to be ZERO!
#define REMOTE_TYPE_REPL 0x00000001         // CN Replication Table
#define REMOTE_TYPE_PART 0x00000002         // CN Hash/Range/List Table
#define REMOTE_TYPE_MIX 0x00000003          // CN Replication + Hash/Range/List Table
#define REMOTE_TYPE_GLOBAL_VIEW 0x00000004  // CN global view

typedef enum en_remote_fetcher_type {
    REMOTE_FETCHER_NORMAL = 0,
    REMOTE_FETCHER_MERGE_SORT = 1,
    REMOTE_FETCHER_GROUP = 2,
} remote_fetcher_type_t;

typedef struct st_query_field {
    bilist_node_t bilist_node;
    uint32 pro_id;
    gs_type_t datatype;
    uint16 col_id;
    bool8 is_cond_col;
    uint8 is_array;
    int32 start;
    int32 end;
    uint32 ref_count;
} query_field_t;

typedef struct st_func_expr {
    bilist_node_t bilist_node;
    void *expr;
} func_expr_t;

#define SQL_SET_QUERY_FIELD_INFO(query_field, type, id, arr, ss_start, ss_end) \
    do {                                                                       \
        (query_field)->datatype = (type);                                      \
        (query_field)->col_id = (id);                                          \
        (query_field)->is_array = (arr);                                       \
        (query_field)->start = (ss_start);                                     \
        (query_field)->end = (ss_end);                                         \
    } while (0)
/*
    For specify partition query.
*/
typedef enum en_specify_part_type {
    SPECIFY_PART_NONE = 0,
    SPECIFY_PART_NAME = 1,
    SPECIFY_PART_VALUE = 2,
} specify_part_type_t;

typedef struct st_specify_part_info {
    bool32 is_subpart;
    specify_part_type_t type;
    union {
        text_t part_name;
        galist_t *values;
    };
} specify_part_info_t;

/*
For CBO table selection attribute.
*/
typedef enum en_table_seltion_type {
    SELTION_NONE = 0x0,
    SELTION_DEPD_TABLES = 0x0001,       // the table depend on other tables
    SELTION_NO_DRIVER = 0x0002,         // the table can't be used as driving table
    SELTION_NO_HASH_JOIN = 0x0004,      // the table can't used NL Join Method
    SELTION_SPEC_DRIVER = 0x0008,       // the table is designated as the driving table
    SELTION_PUSH_DOWN_JOIN = 0x0010,    // the table as sub-select has push down condition
    SELTION_PUSH_DOWN_TABLE = 0x0020,   // the table in sub-select has push down condition
    SELTION_NL_PRIORITY = 0x0040,       // the table prefer to use NL Join Method
    SELTION_LEFT_JOIN_DRIVER = 0x0080,  // the table is Left join driving table(left node with join-right-deep tree)
    SELTION_LEFT_JOIN_TABLE = 0x0100,   // the table is Left join right table
    SELTION_SUBGRAPH_DRIVER = 0x0200,   // the table is only designated as the sub-graph driving table
} table_seltion_type_t;

typedef struct st_cbo_extra_attribute {
    vmc_t *vmc;              // memory owner for the following list
    galist_t *save_tables;   // for save depend tables
    galist_t *sub_grp_tabs;  // for sub graph tables
    galist_t *idx_ref_cols;  // for index join referent columns (eg: ref_tab.col = tab.col)
    galist_t *filter_cols;   // for filter columns (eg: tab.col <= 1)
    galist_t *drv_infos;     // for driver table info
} cbo_extra_attr_t;

typedef struct st_cbo_attribute {
    uint16 type;  // table_seltion_type_t
    uint16 save_type;
    uint8 is_deal : 1;
    uint8 is_load : 1;
    uint8 has_filter : 1;
    uint8 can_use_idx : 1;
    uint8 null_filter : 1; /* determine whether `is null` can be used to calculate table's card
                               select * from t1 left join t2 where t2.f1 is null;
                               `t2.f1 is null` expr can't be used to calculate t2's card */
    uint8 is_nl_tab : 1;   /* means the table is nl right table without index */
    uint8 is_scaled : 1;   /* means the table is scaled by limit or rownum */
    uint8 reserved3 : 1;   // not used, for byte alignment
    uint8 vpeek_flags;     // flag for variant peek
    uint16 cbo_flags;
    uint64 idx_ss_flags;  // for index skip scan flags
    int64 out_card;
    int64 total_rows;
    galist_t *tables;        // for depend tables
    cbo_extra_attr_t extra;  // cbo extra attribute, memory allocated from stmt->vmc

    struct st_cond_tree *filter;  // for outer join filter condition
} cbo_attribute_t;

#define IS_DBLINK_TABLE(table) ((table)->dblink.len != 0)
#define TABLE_CBO_IS_NL(table) ((table)->cbo_attr.is_nl_tab)
#define TABLE_CBO_IS_DEAL(table) ((table)->cbo_attr.is_deal)
#define TABLE_CBO_IS_LOAD(table) ((table)->cbo_attr.is_load)
#define TABLE_CBO_IS_SCALED(table) ((table)->cbo_attr.is_scaled)
#define TABLE_CBO_HAS_FILTER(table) ((table)->cbo_attr.has_filter)
#define TABLE_CBO_FILTER(table) ((table)->cbo_attr.filter)
#define TABLE_CBO_OUT_CARD(table) ((table)->cbo_attr.out_card)
#define TABLE_CBO_FILTER_ROWS(table) ((table)->filter_rows)
#define TABLE_CBO_TOTAL_ROWS(table) ((table)->cbo_attr.total_rows)
#define TABLE_CBO_SET_FLAG(table, flg) ((table)->cbo_attr.type |= (flg))
#define TABLE_CBO_UNSET_FLAG(table, flg) ((table)->cbo_attr.type &= ~(flg))
#define TABLE_CBO_HAS_FLAG(table, flg) ((table)->cbo_attr.type & (flg))
// extra attribute
#define TABLE_CBO_ATTR_OWNER(table) ((table)->cbo_attr.extra.vmc)
#define TABLE_CBO_DEP_TABLES(table) ((table)->cbo_attr.tables)
#define TABLE_CBO_SAVE_TABLES(table) ((table)->cbo_attr.extra.save_tables)
#define TABLE_CBO_SUBGRP_TABLES(table) ((table)->cbo_attr.extra.sub_grp_tabs)
#define TABLE_CBO_IDX_REF_COLS(table) ((table)->cbo_attr.extra.idx_ref_cols)
#define TABLE_CBO_FILTER_COLS(table) ((table)->cbo_attr.extra.filter_cols)
#define TABLE_CBO_DRV_INFOS(table) ((table)->cbo_attr.extra.drv_infos)

#define TABLE_SET_DRIVE_CARD(table, card)             \
    do {                                              \
        if (GS_IS_SUBSELECT_TABLE((table)->type)) {   \
            (table)->select_ctx->drive_card = (card); \
        }                                             \
    } while (0)

typedef enum {
    SCAN_PART_ANY,  // one part to be scanned, but cannot be specified. max part used for calculation.
    // one or multiple specified parts to be scanned, part_no(s) saved in st_scan_part_info->part_no
    SCAN_PART_SPECIFIED,
    SCAN_PART_FULL,          // all parts to be scanned
    SCAN_PART_UNKNOWN,       // part to be scanned can not be decided. max part used for calculation.
    SCAN_PART_EMPTY,         // no part to be scanned
    SCAN_SUBPART_SPECIFIED,  // one or multiple specified parts to be scaned
    SCAN_SUBPART_ANY,        // one subpart to be scanned, but cannot be specified. max subpart used for calculation.
    SCAN_SUBPART_UNKNOWN     // subpart to be scanned can not be decided. max subpart used for calculation.
} scan_part_range_type_t;

// the max number of specified part_no to be saved in scan_part_info.
// if the number of specified parts greater than 64, only part count will be used.
#define MAX_CBO_CALU_PARTS_COUNT 64

typedef struct st_scan_part_info {
    scan_part_range_type_t scan_type;
    uint64 part_cnt;  // the number of all specified part_no saved in '*part_no'
    // in case the number is too great, at most MAX_CBO_CALU_PARTS_COUNT saved. check count before reading array!
    uint32 *part_no;
    uint32 *subpart_no;
} scan_part_info_t;

typedef enum en_json_error_type {
    JSON_RETURN_ERROR = 0,    // return error if json table data expr is invalid or path is invalid
    JSON_RETURN_NULL = 1,     // return null if json table data expr is invalid or path is invalid
    JSON_RETURN_DEFAULT = 2,  // return default value if json table data expr is invalid or path is invalid
} json_error_type_t;

typedef struct st_json_error_info {
    json_error_type_t type;
    struct st_expr_tree *default_value;
} json_error_info_t;

typedef struct st_json_table_info {
    uint32 depend_table_count;
    uint32 *depend_tables;                     // table_id of table which exists in data_expr
    struct st_expr_tree *data_expr;            // origin json data to generate json_table
    text_t basic_path_txt;                     // text of json basic path expression
    struct st_source_location basic_path_loc;  // current location of data_expr
    struct st_json_path *basic_path;           // complie result of json path expression
    json_error_info_t json_error_info;
    galist_t columns;
} json_table_info_t;

typedef enum en_tf_scan_flag {
    SEQ_SQL_SCAN = 0,  // default value,
    SEQ_TFM_SCAN = 1,  // table function sequential execution
    PAR_TFM_SCAN = 2,  // table function parallel scan
    PAR_SQL_SCAN = 3,  // sql parallel scan by hint
} tf_scan_flag_t;

typedef struct st_scan_info {
    knl_index_desc_t *index;     // for index scan
    uint16 scan_flag;            // index only/sort eliminate flag
    uint16 idx_equal_to;         // a = ? and b = ? and c > ? then idx_equal_to = 2
    uint16 equal_cols;           // include idx_equal_to and "a in (?,?) and b >?", for choose optimal index
    uint16 col_use_flag;         // indicate choose index with ancestor col or self join col
    uint32 index_dsc : 1;        // index scan direction,for sort eliminate
    uint32 rowid_usable : 1;     // flag for rowid scan
    uint32 index_full_scan : 1;  // flag for index full scan
    uint32 index_skip_scan : 1;  // flag for index skip scan
    uint32 is_push_down : 1;     // flag for push down
    uint32 opt_match_mode : 3;   // [0,7]
    uint32 skip_index_match : 1;
    uint32 multi_parts_scan : 1;  // optim flag for multi knlcurs scan parts
    uint32 bindpar_onepart : 1;   // only one part left after the cond of bind parameter trimming
    uint32 index_ffs : 1;         // flag for index fast full scan
    uint32 reserved2 : 20;
    uint16 index_match_count;  // for index match column count
    uint16 scan_mode;          // for table
    double cost;
    void *rowid_set;            // Use void* to point plan_rowid_set_t* for avoiding loop include;
    uint16 *idx_col_map;        // for index only scan, decode row by index defined sequence
    struct st_cond_tree *cond;  // for multi index scan, create scan range for each index;
    galist_t *sub_tables;       // for multi index scan with or condition
} scan_info_t;

typedef struct st_cbo_filter_info {
    cbo_attribute_t cbo_attr;
    scan_info_t scan_info;
    int64 card;
    bool32 is_ready;
} cbo_filter_info_t;

// ///////////////////////////////////////////////////////////////////////////////////
typedef struct st_sql_table {
    uint32 id;
    text_t qb_name;
    sql_table_entry_t *entry;
    struct st_table_func func;  // for table function
    union {
        sql_select_t *select_ctx;
        json_table_info_t *json_table_info;  // for json table
    };
    uint32 plan_id;  // for join order
    sql_table_type_t type;
    /* for CBO optimize */
    int64 card;
    int64 filter_rows;  // save the filter card of table
    cbo_attribute_t cbo_attr;

    sql_text_t user;
    sql_text_t name;
    sql_text_t alias;
    sql_text_t dblink;
    sql_table_snapshot_t version;
    sql_join_node_t *join_node;

    project_col_array_t *project_col_array;
    uint32 project_column_count;

    uint32 col_start_pos;
    uint32 project_start_pos;

    uint32 is_ancestor;        // 0: not is ancestor, 1: is parent, 2: is grandfather, ...
    bool8 tab_name_has_quote;  // table name wrapped double quotations or not
    bool8 user_has_quote;      // user wrapped double quotations or not
    bool8 is_public_synonym;   // 0: not a public synonym, 1:public synonym
                               //#endif

    bilist_t query_fields;
    bilist_t func_expr;
    hint_info_t *hint_info;
    specify_part_info_t part_info;
    subslct_table_usage_t subslct_tab_usage;  // sub-select used for semi/anti join

    bool32 rowid_exists : 1;        // rowid exist in where clause or not
    bool32 rownodeid_exists : 1;    // rownodeid exist in where clause or not
    bool32 rs_nullable : 1;         // record whether rs_columns in current table can be nullable or not
    bool32 has_hidden_columns : 1;  // indicates table has virtual, invisible column
    bool32 global_cached : 1;       // cached scan pages into global CR pool or not
    bool32 view_dml : 1;
    bool32 ret_full_fields : 1;  // return full fields of single table flag
    bool32 for_update : 1;
    bool32 ineliminable : 1;        // indicates the sub-select table/view cannot be eliminated
    bool32 is_join_driver : 1;      // indicates the table is join driver table
    bool32 is_sub_table : 1;        // indicates this table is sub table for multi index scan
    bool32 is_descartes : 1;        // indicates this table is cartesian join with other tables
    bool32 index_cond_pruning : 1;  // indicates index cond of this table has been pruned
    bool32 is_jsonb_table : 1;      // indicates index cond of this table has been pruned
    bool32 reserved : 18;

    tf_scan_flag_t tf_scan_flag;  // Parallel Scan Indicator
    scan_part_info_t *scan_part_info;
    galist_t *for_update_cols;
    union {
        struct {
            knl_index_desc_t *index;     // for index scan
            uint16 scan_flag;            // index only/sort eliminate flag
            uint16 idx_equal_to;         // a = ? and b = ? and c > ? then idx_equal_to = 2
            uint16 equal_cols;           // include idx_equal_to and "a in (?,?) and b >?", for choose optimal index
            uint16 col_use_flag;         // indicate choose index with ancestor col or self join col
            uint32 index_dsc : 1;        // index scan direction,for sort eliminate
            uint32 rowid_usable : 1;     // flag for rowid scan
            uint32 index_full_scan : 1;  // flag for index full scan
            uint32 index_skip_scan : 1;  // flag for index skip scan
            uint32 is_push_down : 1;     // flag for push down
            uint32 opt_match_mode : 3;   // [0,7]
            uint32 skip_index_match : 1;
            uint32 multi_parts_scan : 1;  // optim flag for multi knlcurs scan parts
            uint32 bindpar_onepart : 1;   // only one part left after the cond of bind parameter trimming
            uint32 index_ffs : 1;         // flag for index fast full scan
            uint32 reserved2 : 20;
            uint16 index_match_count;  // for index match column count
            uint16 scan_mode;          // for table
            double cost;
            void *rowid_set;            // Use void* to point plan_rowid_set_t* for avoiding loop include;
            uint16 *idx_col_map;        // for index only scan, decode row by index defined sequence
            struct st_cond_tree *cond;  // for multi index scan, create scan range for each index;
            galist_t *sub_tables;       // for multi index scan with or condition
        };
        scan_info_t scan_info;
    };
} sql_table_t;

typedef struct st_query_column {
    struct st_expr_tree *expr;
    text_t alias;
    bool32 exist_alias;
    text_t z_alias;  // auto generated alias for SHARD decompile sql
} query_column_t;

/* end: for select statement */
/* begin: for update / insert statement */
/* for multi delete */
typedef struct st_del_object {
    sql_text_t user;
    sql_text_t name;
    sql_text_t alias;
    sql_table_t *table;
} del_object_t;

/* for multi update */
typedef struct st_upd_object {
    galist_t *pairs;
    sql_table_t *table;
} upd_object_t;

typedef struct st_column_value_pair {
    sql_text_t column_name;        // for insert column
    bool32 column_name_has_quote;  // if column name wrapped with double quotation

    // for update column. like: update t_test t1 set t1.f1 = 1, for convenience, using expr for t1.f1
    struct st_expr_tree *column_expr;  // for update column
    uint32 column_id;
    knl_column_t *column;

    // list of right value
    // for insert, may be a list. like: insert into tab() values(),(),()
    // for update, just one element
    galist_t *exprs;  // list of st_expr_tree, supports insert some values
    uint32 rs_no;     // for update multi set, ref to subquery rs_column number, start with 1, 0 for non-multi set
    int32 ss_start;   // for array start subscript
    int32 ss_end;     // for array end subscript
} column_value_pair_t;

// for update multi set
#define PAIR_IN_MULTI_SET(pair) ((pair)->rs_no > 0)

typedef struct st_sql_update {
    galist_t *objects;
    galist_t *pairs;
    sql_query_t *query;
    struct st_plan_node *plan;
    hint_info_t *hint_info;
    struct st_cond_tree *cond;  // for multi table update
    galist_t *ret_columns;      // returning columns
    uint32 param_start_pos;     // INSERT ON DUPLICATE KEY UPDATE first bind param pos
    bool32 check_self_update;   // check self update for multiple table update
    galist_t *pl_dc_lst;        // record plsql objects in current update context, for check privilege
} sql_update_t;

typedef struct st_sql_delete {
    galist_t *objects;
    sql_query_t *query;
    struct st_plan_node *plan;
    hint_info_t *hint_info;
    struct st_cond_tree *cond;  // for multiple table delete
    galist_t *ret_columns;      // returning columns
    galist_t *pl_dc_lst;        // record plsql objects in current update context, for check privilege
} sql_delete_t;

/* end: for delete statement */
#define INSERT_SET_NONE 0x00000000
#define INSERT_COLS_SPECIFIED 0x00000001
#define INSERT_VALS_SPECIFIED 0x00000002

#define INSERT_IS_IGNORE 0x00000001
#define INSERT_IS_ALL 0x00000002

typedef struct st_insert_all_t {
    sql_table_t *table;
    galist_t *pairs;
    uint32 pairs_count;
    uint32 flags;
} insert_all_t;

typedef struct st_sql_insert {
    sql_table_t *table;
    sql_array_t *ref_tables;
    sql_array_t ssa;  // SubSelect Array for subselect expr
    galist_t *pairs;
    uint32 pairs_count;
    uint32 *col_map;           // Indicate which column is set or not
    uint16 *part_key_map;      // store column position in partition key definition
    sql_select_t *select_ctx;  // for insert ... select
    struct st_plan_node *plan;
    hint_info_t *hint_info;
    sql_update_t *update_ctx;  // for on duplicate key update
    uint32 flags;              // set of insert flags
    galist_t *ret_columns;     // returning columns
    uint32 batch_commit_cnt;   // for insert ... select, batch commit;
    galist_t *pl_dc_lst;       // record plsql objects in current insert context, for check privilege
    galist_t *into_list;
    uint32 syntax_flag;  // syntax flag for insert ignore, insert all etc
} sql_insert_t;

#define MAX_ROW_SIZE 32000

/* end: for insert statement */
typedef struct st_sql_merge {
    struct st_cond_tree *insert_filter_cond;
    struct st_cond_tree *update_filter_cond;
    sql_update_t *update_ctx;
    sql_insert_t *insert_ctx;
    struct st_plan_node *plan;
    sql_query_t *query;  // tables: 0:merge into table,  1:using table
    hint_info_t *hint_info;
    galist_t *pl_dc_lst;  // record plsql objects in current update context, for check privilege
} sql_merge_t;

typedef struct st_sql_replace {
    sql_insert_t insert_ctx;
} sql_replace_t;

typedef struct st_par_scan_range {
    knl_part_locate_t part_loc;
    union {
        struct {  // parallel heap scan range
            uint64 l_page;
            uint64 r_page;
        };
        knl_scan_range_t *idx_scan_range;  // parallel index scan range
    };
} par_scan_range_t;

status_t sql_instance_startup(void);
status_t sql_create_context_pool(void);
void sql_destroy_context_pool(void);
void sql_context_uncacheable(sql_context_t *ctx);
void sql_free_context(sql_context_t *ctx);

void sql_close_dc(context_ctrl_t *ctrl);
void sql_close_context_resource(context_ctrl_t *ctrl);
status_t sql_alloc_mem(void *context, uint32 size, void **buf);
void ctx_recycle_all(void);
void dc_recycle_external(void);
bool32 ctx_recycle_internal(void);
typedef status_t (*sql_copy_func_t)(sql_context_t *ctx, text_t *src, text_t *dst);

/* copy name and convert to upper case */
status_t sql_copy_name(sql_context_t *ctx, text_t *src, text_t *dst);
status_t sql_copy_name_loc(sql_context_t *ctx, sql_text_t *src, sql_text_t *dst);
/* copy name and convert by case sensitive */
status_t sql_copy_name_cs(sql_context_t *ctx, text_t *src, text_t *dst);
status_t sql_copy_str_safe(sql_context_t *ctx, char *src, uint32 len, text_t *dst);
status_t sql_copy_str(sql_context_t *ctx, char *src, text_t *dst);
status_t sql_copy_text(sql_context_t *ctx, text_t *src, text_t *dst);
status_t sql_copy_binary(sql_context_t *ctx, binary_t *src, binary_t *dst);
status_t sql_copy_text_upper(sql_context_t *ctx, text_t *src, text_t *dst);
status_t sql_copy_file_name(sql_context_t *ctx, text_t *src, text_t *dst);
/* copy object name and judge whether to convert it to upper case by USE_UPPER_CASE_NAMES */
status_t sql_copy_object_name(sql_context_t *ctx, word_type_t type, text_t *src, text_t *dst);
status_t sql_copy_object_name_loc(sql_context_t *ctx, word_type_t type, sql_text_t *src, sql_text_t *dst);
status_t sql_copy_object_name_ci(sql_context_t *ctx, word_type_t type, text_t *src, text_t *dst);
status_t sql_copy_prefix_tenant(void *stmt_in, text_t *src, text_t *dst, sql_copy_func_t sql_copy_func);
status_t sql_copy_object_name_prefix_tenant(void *stmt_in, word_type_t type, text_t *src, text_t *dst);
status_t sql_copy_name_prefix_tenant_loc(void *stmt_in, sql_text_t *src, sql_text_t *dst);
status_t sql_copy_object_name_prefix_tenant_loc(void *stmt_in, word_type_t type, sql_text_t *src, sql_text_t *dst);
status_t sql_user_prefix_tenant(void *session_in, char *username);
status_t sql_user_text_prefix_tenant(void *session_in, text_t *user, char *buf, uint32 buf_size);
status_t sql_generate_unnamed_table_name(void *stmt_in, sql_table_t *table, unnamed_tab_type_t type);

static inline status_t sql_array_init(sql_array_t *array, uint32 capacity, void *ctx, ga_alloc_func_t alloc_func)
{
    if (alloc_func(ctx, capacity * sizeof(pointer_t), (void **)&array->items) != GS_SUCCESS) {
        return GS_ERROR;
    }

    MEMS_RETURN_IFERR(memset_sp(array->items, capacity * sizeof(pointer_t), 0, capacity * sizeof(pointer_t)));

    array->capacity = capacity;
    array->count = 0;
    array->context = ctx;
    array->alloc_func = alloc_func;
    array->name.str = NULL;
    array->name.len = 0;
    return GS_SUCCESS;
}

static inline status_t sql_create_array(sql_context_t *ctx, sql_array_t *array, char *name, uint32 capacity)
{
    GS_RETURN_IFERR(sql_array_init(array, capacity, ctx, sql_alloc_mem));

    if (name != NULL) {
        return sql_copy_str(ctx, name, &array->name);
    }

    return GS_SUCCESS;
}

status_t sql_array_put(sql_array_t *array, pointer_t ptr);
status_t sql_array_concat(sql_array_t *array1, sql_array_t *array2);
status_t sql_array_delete(sql_array_t *array, uint32 index);

static inline status_t sql_array_new(sql_array_t *array, uint32 size, pointer_t *ptr)
{
    if (array->alloc_func(array->context, size, ptr) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return sql_array_put(array, *ptr);
}

status_t sql_array_set(sql_array_t *array, uint32 index, pointer_t ptr);

static void inline sql_remove_quota(text_t *src)
{
    if (src->len > 1 && src->str[0] == '\'' && src->str[src->len - 1] == '\'') {
        src->str++;
        src->len -= 2;
    }
    return;
}

#define sql_array_get(arr, id) ((arr)->items[id])

#define SAVE_REFERENCES_LIST(stmt) galist_t *ref_obj = (stmt)->context->ref_objects;

#define RESTORE_REFERENCES_LIST(stmt) (stmt)->context->ref_objects = ref_obj;

ack_sender_t *sql_get_pl_sender(void);

static inline void sql_typmod_from_knl_column(typmode_t *tm, const knl_column_t *kcol)
{
    tm->datatype = kcol->datatype;
    tm->size = kcol->size;
    tm->precision = (uint8)kcol->precision;
    tm->scale = (int8)kcol->scale;
    tm->is_array = KNL_COLUMN_IS_ARRAY(kcol);
    if (GS_IS_STRING_TYPE(tm->datatype)) {
        tm->is_char = KNL_COLUMN_IS_CHARACTER(kcol);
    }
}

status_t sql_check_datafile_path(text_t *name);

bool32 sql_if_all_comma_join(sql_join_node_t *join_node);
status_t sql_get_real_path(text_t *name, char *real_path);
void sql_context_inc_exec(sql_context_t *context);
void sql_context_dec_exec(sql_context_t *context);
bool32 sql_upper_case_name(sql_context_t *ctx);
#define MAX_ANCESTOR_LEVEL 3

#define SET_ANCESTOR_LEVEL(select_ctx, level)                                        \
    do {                                                                             \
        if ((level) > 0 && (level) <= MAX_ANCESTOR_LEVEL) {                          \
            GS_BIT_SET((select_ctx)->has_ancestor, GS_GET_MASK((level)-1));          \
        } else if ((level) > MAX_ANCESTOR_LEVEL) {                                   \
            GS_BIT_SET((select_ctx)->has_ancestor, GS_GET_MASK(MAX_ANCESTOR_LEVEL)); \
        }                                                                            \
    } while (0)

#define RESET_ANCESTOR_LEVEL(select_ctx, level)                               \
    do {                                                                      \
        if ((level) > 0 && (level) <= MAX_ANCESTOR_LEVEL) {                   \
            GS_BIT_RESET((select_ctx)->has_ancestor, GS_GET_MASK((level)-1)); \
        }                                                                     \
    } while (0)

status_t do_commit(session_t *session);
void do_rollback(session_t *session, knl_savepoint_t *savepoint);

typedef enum en_stmt_status {
    STMT_STATUS_FREE = 0,
    STMT_STATUS_IDLE,
    STMT_STATUS_PREPARED,
    STMT_STATUS_EXECUTING,
    STMT_STATUS_EXECUTED,
    STMT_STATUS_FETCHING,
    STMT_STATUS_FETCHED,
} stmt_status_t;

typedef enum en_lang_type {
    LANG_INVALID = 0,
    LANG_DML = 1,
    LANG_DCL = 2,
    LANG_DDL = 3,
    LANG_PL = 4,
    LANG_EXPLAIN = 5,
} lang_type_t;

typedef struct st_sql_lob_info {
    id_list_t list;      // virtual memory page list for lob
    uint32 inuse_count;  // only lob_inuse_count is 0 can do free lob_list when
                         // sql_release_resource with force(false)
} sql_lob_info_t;

typedef struct st_sql_lob_info1 {
    id_list_t pre_list;   // virtual memory page list for prepare lob this time in lob write
    id_list_t exec_list;  // virtual memory page list for execute lob this time in sql process
    bool8 pre_expired;    // pre_list of lob is used in sql process and then it is expired
    uint8 reversed[3];
} sql_lob_info_ex_t;

typedef struct st_sql_param {
    uint8 direction;
    uint8 unused[3];
    variant_t *out_value;
    variant_t value;
} sql_param_t;

typedef struct st_sql_seq {
    var_seq_t seq;
    uint32 flags;
    bool32 processed;
    int64 value;
} sql_seq_t;

typedef struct st_cursor_attr {
    uint64 rrs_sn;  // dedicate a return cursor unique
    bool8 is_returned;
    bool8 is_forcur;
    uint8 type;
    bool8 sql_executed;
    bool8 has_fetched;
    bool8 reverify_in_fetch;  // true in fetch sys_refcursor(DBE_SQL.RETURN_CURSOR), it's important
                              // to send a parsed stmt that UNKNOWN TYPE-PARAMs have been specified.
    uint16 unused2;
    char *param_types;  // points to param types of cursor's pl-variant in vmc
    char *param_buf;    // points to param data of cursor's pl-variant in vmc
} cursor_info_t;

typedef struct st_default_info {
    bool32 default_on;
    variant_t *default_values;
} default_info_t;

typedef struct st_param_info {
    sql_param_t *params;     // stmt params from cm_push and points to received packet or kept vmc memory
    char *param_types;       // points to param types of received packet or kept vmc memory
    char *param_buf;         // points to param data of received packet or kept vmc memory
    uint32 outparam_cnt;     // count of outparams
    uint16 paramset_size;    // count of batch
    uint16 paramset_offset;  // offset of row in batch
    uint32 param_offset;     // record offset to decode params data of param_buf
    uint32 param_strsize;    // record total size of string type in params for read kept params
} param_info_t;

typedef struct st_first_exec_info {
    char *first_exec_buf;
    variant_t *first_exec_vars;   // count of first execution vars depends on context->fexec_vars_cnt
    uint32 fexec_buff_offset;     // used to alloca memory for var-length datatypes
    variant_t **first_exec_subs;  // record first execution subquery results for multiple executions
} first_exec_info_t;

#define GET_VM_CTX(stmt) ((stmt)->vm_ctx)
#define F_EXEC_VARS(stmt) ((stmt)->fexec_info.first_exec_vars)
#define F_EXEC_VALUE(stmt, node) (&(stmt)->fexec_info.first_exec_vars[NODE_OPTMZ_IDX(node)])

typedef struct st_sql_stmt {
    session_t *session;      // owner session
    spinlock_t stmt_lock;    // for modify context
    uint8 rs_type;           // rs_type_t
    uint8 plsql_mode;        // PLSQL_NONE
    uint8 lang_type;         // lang_type_t
    uint8 merge_type;        // merge_type_t
    sql_context_t *context;  // current sql memory
    void *pl_context;        // only for pl create
    vmc_t vmc;
    struct st_plan_node *rs_plan;
    cs_execute_ack_t *exec_ack;
    uint32 exec_ack_offset;
    uint32 fetch_ack_offset;

    date_t last_sql_active_time;  // last execute sql return result time of stmt
    knl_scn_t query_scn;          // query scn for current stmt
    uint64 ssn;                   // sql sequence number in session used for temporary table visibility judgment.
    uint32 xact_ssn;              // sql sequence number in transaction, in sub-stmt we force increase this whether
    knl_scn_t gts_scn;
    knl_scn_t sync_scn;

    // we are in transaction or not in order to distinguish stmt and its sub-stmt.
    object_list_t sql_curs;
    object_list_t knl_curs;

    /* object_stack */
    object_stack_t cursor_stack;  // for executing
    object_stack_t ssa_stack;     // for parsing, sub-select array
    object_stack_t node_stack;

    galist_t vmc_list;  // record all vmc allocated for query
    uint16 status;      // stmt status(free/idle/prepared/executed/fetch/pre_params)
    uint16 id;          // stmt id

    mtrl_context_t mtrl;
    row_assist_t ra;
    uint64 serial_value;  // for GS_TYPE_SERIAL
    uint32 batch_rows;    // number of rows in a batch
    uint32 total_rows;
    uint32 prefetch_rows;
    uint32 allowed_batch_errs;
    uint32 actual_batch_errs;
    union {
        sql_lob_info_t lob_info;
        sql_lob_info_ex_t lob_info_ex;
    };
    knl_column_t *default_column;  // for default key word, insert into values(default), update set = default
    uint32 gts_offset;
    uint32 pairs_pos;  // for insert some values or update pairs(0)

    /* for procedure */
    void *pl_compiler;
    void *pl_exec;
    galist_t *pl_ref_entry;                   // dependent PL objects dc during actual execution
    galist_t *trigger_list;                   // check trigger if has been checked privilege before
    void *parent_stmt;                        // parent stmt of current stmt in pl
    char pl_set_schema[GS_NAME_BUFFER_SIZE];  // saved schema value that set in procedure.

    /* flags */
    bool32 eof : 1;  // query result fetch over or dml execute over
    bool32 return_generated_key : 1;
    bool32 is_sub_stmt : 1;
    bool32 in_parse_query : 1;
    bool32 chk_priv : 1;
    bool32 mark_pending_done : 1;
    bool32 is_check : 1;
    bool32 resource_inuse : 1;
    bool32 need_send_ddm : 1;
    bool32 is_success : 1;  // stmt execute result
    bool32 is_batch_insert : 1;
    bool32 is_explain : 1;
    bool32 auto_commit : 1;
    bool32 is_srvoutput_on : 1;
    bool32 pl_failed : 1;
    bool32 params_ready : 1;  // flags whether stmt->param_info.params is ready, for print
    bool32 dc_invalid : 1;    // flags whether dc is invalid when execute
    bool32 is_reform_call : 1;
    bool32 is_verifying : 1;
    bool32 is_temp_alloc : 1;
    bool32 trace_disabled : 1;  // when exists serveroutput/returnresult, don't support autotrace
    bool32 context_refered : 1;
    bool32 is_var_peek : 1;
    bool32 has_pl_ref_dc : 1;
    bool32 hide_plan_extras : 1;  // if hide plan extra information for printing, such as cost/rows/pridicate/outline
    bool32 reversed : 7;

    /* record sysdate/systimestamp/sequence of stmt */
    date_t v_sysdate;
    date_t v_systimestamp;
    int32 tz_offset_utc;
    sql_seq_t *v_sequences;

    cursor_info_t cursor_info;

    default_info_t default_info;
    first_exec_info_t fexec_info;  // for first execution optimized
    param_info_t param_info;
    knl_cursor_t *direct_knl_cursor;  // kernel cursor to calculate function index column and check
    int32 text_shift;                 // if is_reform_call is true, param offset need text_shift
    void *sort_par;
    date_t *plan_time;  // record execution time of each plan
    uint32 plan_cnt;
    void *into;
    galist_t *outlines;  // record applied outlines
    pvm_context_t vm_ctx;
    vm_context_data_t vm_ctx_data;
    struct st_hash_mtrl_ctx **hash_mtrl_ctx_list;
    uint16 gdv_mode;    // for gdv: in sql_execute_select, do not return the ruslt set.
    uint16 gdv_unused;  // for gdv
} sql_stmt_t;

typedef enum en_cursor_type {
    USER_CURSOR = 0,
    PL_FORK_CURSOR = 1,
    PL_EXPLICIT_CURSOR = 2,
    PL_IMPLICIT_CURSOR = 3,
} cursor_type_t;

#define SQL_UNINITIALIZED_DATE GS_INVALID_INT64
#define SQL_UNINITIALIZED_TSTAMP GS_INVALID_INT64

#define SQL_CURSOR_STACK_DEPTH(stmt) ((stmt)->cursor_stack.depth)

#define SQL_ROOT_CURSOR(stmt) ((struct st_sql_cursor *)(stmt)->cursor_stack.items[0])
#define SQL_CURR_CURSOR(stmt)                                                                               \
    (((struct st_sql_cursor *)OBJ_STACK_CURR(&(stmt)->cursor_stack))->connect_data.cur_level_cursor == NULL \
         ? (struct st_sql_cursor *)OBJ_STACK_CURR(&(stmt)->cursor_stack)                                    \
         : ((struct st_sql_cursor *)OBJ_STACK_CURR(&(stmt)->cursor_stack))->connect_data.cur_level_cursor)
#define SQL_CURSOR_PUSH(stmt, cursor) obj_stack_push(&(stmt)->cursor_stack, cursor)
#define SQL_CURSOR_POP(stmt) (void)obj_stack_pop(&(stmt)->cursor_stack)

// SSA subselect array
#define SQL_CURR_SSA(stmt) ((sql_array_t *)OBJ_STACK_CURR(&(stmt)->ssa_stack))
#define SQL_SSA_PUSH(stmt, ar) obj_stack_push(&(stmt)->ssa_stack, ar)
#define SQL_SSA_POP(stmt) (void)obj_stack_pop(&(stmt)->ssa_stack)

// parent query
#define SQL_CURR_NODE(stmt) (stmt)->node_stack.depth > 0 ? ((sql_query_t *)OBJ_STACK_CURR(&(stmt)->node_stack)) : NULL
#define SQL_NODE_PUSH(stmt, node) obj_stack_push(&(stmt)->node_stack, (node))
#define SQL_NODE_POP(stmt) (void)obj_stack_pop(&(stmt)->node_stack)

#define SET_NODE_STACK_CURR_QUERY(stmt, query)                                                  \
    sql_query_t *__save_query__ = (stmt)->node_stack.depth == 0 ? NULL : SQL_CURR_NODE((stmt)); \
    do {                                                                                        \
        if ((stmt)->node_stack.depth == 0) {                                                    \
            GS_RETURN_IFERR(SQL_NODE_PUSH((stmt), (query)));                                    \
        } else {                                                                                \
            (stmt)->node_stack.items[(stmt)->node_stack.depth - 1] = (query);                   \
        }                                                                                       \
    } while (0)
#define SQL_RESTORE_NODE_STACK(stmt)                      \
    do {                                                  \
        if (__save_query__ == NULL) {                     \
            (stmt)->node_stack.depth = 0;                 \
        } else {                                          \
            (stmt)->node_stack.items[0] = __save_query__; \
            (stmt)->node_stack.depth = 1;                 \
        }                                                 \
    } while (0)

#define SAVE_AND_RESET_NODE_STACK(stmt)                                                         \
    sql_query_t *__save_query__ = (stmt)->node_stack.depth == 0 ? NULL : SQL_CURR_NODE((stmt)); \
    do {                                                                                        \
        (stmt)->node_stack.depth = 0;                                                           \
    } while (0)

#define SRV_SESSION(stmt) ((stmt)->session)
#define KNL_SESSION(stmt) (&(stmt)->session->knl_session)
#define LEX(stmt) ((stmt)->session->lex)

#define AUTOTRACE_ON(stmt) ((stmt)->session->knl_session.autotrace)
#define NEED_TRACE(stmt) (AUTOTRACE_ON(stmt) && (stmt)->context->type < SQL_TYPE_DML_CEIL && !(stmt)->is_explain)

static inline status_t sql_push(sql_stmt_t *stmt, uint32 size, void **ptr)
{
    uint32 actual_size, last_offset;
    cm_stack_t *stack = stmt->session->stack;

    actual_size = CM_ALIGN8(size) + GS_PUSH_RESERVE_SIZE;
    *ptr = stack->buf + stack->push_offset - actual_size + GS_PUSH_RESERVE_SIZE;

    if (stack->push_offset < (uint64)stack->heap_offset + GS_MIN_KERNEL_RESERVE_SIZE + actual_size) {
        *ptr = NULL;
        GS_THROW_ERROR(ERR_STACK_OVERFLOW);
        return GS_ERROR;
    }
    last_offset = stack->push_offset;
    stack->push_offset -= actual_size;
    *(uint32 *)(stack->buf + stack->push_offset + GS_PUSH_OFFSET_POS) = last_offset;

#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
    /* set magic number */
    *(uint32 *)(stack->buf + stack->push_offset) = STACK_MAGIC_NUM;
#endif

    return GS_SUCCESS;
}

static inline status_t sql_push_textbuf(sql_stmt_t *stmt, uint32 size, text_buf_t *txtbuf)
{
    if (sql_push(stmt, size, (void **)&txtbuf->str) != GS_SUCCESS) {
        return GS_ERROR;
    }

    txtbuf->len = 0;
    txtbuf->max_size = size;

    return GS_SUCCESS;
}

static inline const nlsparams_t *sql_get_session_nlsparams(const sql_stmt_t *stmt)
{
    return &(stmt->session->nls_params);
}

#define SESSION_NLS(stmt) sql_get_session_nlsparams(stmt)

static inline const timezone_info_t sql_get_session_timezone(const sql_stmt_t *stmt)
{
    return cm_get_session_time_zone(SESSION_NLS(stmt));
}

static inline void sql_session_nlsparam_geter(const sql_stmt_t *stmt, nlsparam_id_t id, text_t *text)
{
    const nlsparams_t *nls = SESSION_NLS(stmt);
    nls->param_geter(nls, id, text);
}

status_t sql_stack_alloc(void *sql_stmt, uint32 size, void **ptr);  // with memset_s
status_t sql_get_serial_cached_value(sql_stmt_t *stmt, text_t *username, text_t *tbl_name, int64 *val);

#define SQL_SAVE_STACK(stmt) CM_SAVE_STACK((stmt)->session->stack)
#define SQL_RESTORE_STACK(stmt) CM_RESTORE_STACK((stmt)->session->stack)
#define SQL_POP(stmt) cm_pop((stmt)->session->stack)

static inline void sql_keep_stack_variant(sql_stmt_t *stmt, variant_t *var)
{
    cm_keep_stack_variant(stmt->session->stack, var_get_buf(var));
}

static inline void sql_keep_stack_var(void *stmt, variant_t *var)
{
    sql_keep_stack_variant((sql_stmt_t *)stmt, var);
}

void sql_init_stmt(session_t *session, sql_stmt_t *stmt, uint32 stmt_id);
status_t sql_alloc_stmt(session_t *session, sql_stmt_t **statement);
void sql_free_stmt(sql_stmt_t *stmt);
void sql_set_scn(sql_stmt_t *stmt);
void sql_set_ssn(sql_stmt_t *stmt);  // SSN = SQL SEQUENCE NUMBER
status_t sql_parse_job(sql_stmt_t *stmt, text_t *sql, source_location_t *loc);
status_t sql_reparse(sql_stmt_t *stmt);
status_t sql_prepare(sql_stmt_t *stmt);
status_t sql_init_pl_ref_dc(sql_stmt_t *stmt);
status_t sql_init_trigger_list(sql_stmt_t *stmt);
status_t sql_execute(sql_stmt_t *stmt);
status_t sql_execute_directly(session_t *session, text_t *sql, sql_type_t *type, bool32 chk_priv);
status_t sql_execute_directly2(session_t *session, text_t *sql);
void sql_release_context(sql_stmt_t *stmt);
status_t sql_get_table_value(sql_stmt_t *stmt, var_column_t *v_col, variant_t *value);
status_t sql_check_ltt_dc(sql_stmt_t *stmt);
void sql_free_vmemory(sql_stmt_t *stmt);
void sql_log_param_change(sql_stmt_t *stmt, text_t sql);
void sql_unlock_lnk_tabs(sql_stmt_t *stmt);

status_t sql_prepare_for_multi_sql(sql_stmt_t *stmt, text_t *sql);
static inline bool32 sql_is_invalid_rowid(const rowid_t *rid, knl_dict_type_t dc_type)
{
    if (dc_type == DICT_TYPE_TABLE || dc_type == DICT_TYPE_TABLE_NOLOGGING) {
        return IS_INVALID_ROWID(*rid);
    }

    return IS_INVALID_TEMP_TABLE_ROWID(rid);
}

status_t sql_init_sequence(sql_stmt_t *stmt);
void *sql_get_plan(sql_stmt_t *stmt);
status_t sql_get_rowid(sql_stmt_t *stmt, var_rowid_t *rowid, variant_t *value);
status_t sql_get_rownodeid(sql_stmt_t *stmt, var_rowid_t *rowid, variant_t *value);
status_t sql_get_rowscn(sql_stmt_t *stmt, var_rowid_t *rowid, variant_t *value);
status_t sql_get_rownum(sql_stmt_t *stmt, variant_t *value);
void sql_release_resource(sql_stmt_t *stmt, bool32 is_force);
void sql_release_lob_info(sql_stmt_t *stmt);
void sql_mark_lob_info(sql_stmt_t *stmt);
void sql_prewrite_lob_info(sql_stmt_t *stmt);
void sql_preread_lob_info(sql_stmt_t *stmt);
void sql_convert_column_t(knl_column_t *column, knl_column_def_t *column_def);
id_list_t *sql_get_exec_lob_list(sql_stmt_t *stmt);
id_list_t *sql_get_pre_lob_list(sql_stmt_t *stmt);
status_t sql_keep_params(sql_stmt_t *stmt);
status_t sql_read_kept_params(sql_stmt_t *stmt);
status_t sql_read_dynblk_params(sql_stmt_t *stmt);
status_t sql_keep_first_exec_vars(sql_stmt_t *stmt);
status_t sql_load_first_exec_vars(sql_stmt_t *stmt);
status_t sql_read_params(sql_stmt_t *stmt);
status_t sql_fill_null_params(sql_stmt_t *stmt);
status_t sql_prepare_params(sql_stmt_t *stmt);
status_t sql_load_scripts(knl_handle_t handle, const char *file_name, bool8 is_necessary);
void sql_init_session(session_t *session);
status_t sql_write_lob(sql_stmt_t *stmt, lob_write_req_t *req);
status_t sql_read_lob(sql_stmt_t *stmt, void *locator, uint32 offset, void *buf, uint32 size, uint32 *read_size);
status_t sql_check_lob_vmid(id_list_t *vm_list, vm_pool_t *vm_pool, uint32 vmid);
status_t sql_alloc_object_id(sql_stmt_t *stmt, int64 *id);
status_t sql_extend_lob_vmem(sql_stmt_t *stmt, id_list_t *list, vm_lob_t *vlob);
status_t sql_row_put_lob(sql_stmt_t *stmt, row_assist_t *ra, uint32 lob_locator_size, var_lob_t *lob);
status_t sql_row_set_lob(sql_stmt_t *stmt, row_assist_t *ra, uint32 lob_locator_size, var_lob_t *lob, uint32 col_id);
status_t sql_row_set_array(sql_stmt_t *stmt, row_assist_t *ra, variant_t *value, uint16 col_id);
bool32 sql_send_check_is_full(sql_stmt_t *stmt);
void sql_init_sender(session_t *session);
status_t sql_send_result_success(session_t *session);
status_t sql_send_result_error(session_t *session);
void sql_init_sender_row(sql_stmt_t *stmt, char *buffer, uint32 size, uint32 column_count);  // for materialize
status_t sql_send_parsed_stmt(sql_stmt_t *stmt);
status_t sql_send_exec_begin(sql_stmt_t *stmt);
void sql_send_exec_end(sql_stmt_t *stmt);
status_t sql_send_import_rows(sql_stmt_t *stmt);
status_t sql_send_fetch_begin(sql_stmt_t *stmt);
void sql_send_fetch_end(sql_stmt_t *stmt);
status_t sql_send_row_entire(sql_stmt_t *stmt, char *row, bool32 *is_full);
status_t sql_send_row_begin(sql_stmt_t *stmt, uint32 column_count);
status_t sql_send_row_end(sql_stmt_t *stmt, bool32 *is_full);
status_t sql_send_column_null(sql_stmt_t *stmt, uint32 type);
status_t sql_send_column_uint32(sql_stmt_t *stmt, uint32 v);
status_t sql_send_column_int32(sql_stmt_t *stmt, int32 v);
status_t sql_send_column_int64(sql_stmt_t *stmt, int64 v);
status_t sql_send_column_real(sql_stmt_t *stmt, double v);
status_t sql_send_column_date(sql_stmt_t *stmt, date_t v);
status_t sql_send_column_ts(sql_stmt_t *stmt, date_t v);
status_t sql_send_column_tstz(sql_stmt_t *stmt, timestamp_tz_t *v);
status_t sql_send_column_tsltz(sql_stmt_t *stmt, timestamp_ltz_t v);
status_t sql_send_column_str(sql_stmt_t *stmt, char *str);
status_t sql_send_column_text(sql_stmt_t *stmt, text_t *text);
status_t sql_send_column_bin(sql_stmt_t *stmt, binary_t *bin);
status_t sql_send_column_decimal(sql_stmt_t *stmt, dec8_t *dec);
status_t sql_send_column_decimal2(sql_stmt_t *stmt, dec8_t *dec);
status_t sql_send_column_array(sql_stmt_t *stmt, var_array_t *v);
status_t sql_send_column_lob(sql_stmt_t *stmt, var_lob_t *v);
#define sql_send_column_ysintvl sql_send_column_int32
#define sql_send_column_dsintvl sql_send_column_int64
status_t sql_send_serveroutput(sql_stmt_t *stmt, text_t *output);
status_t sql_send_outparams(sql_stmt_t *stmt);
status_t sql_send_return_result(sql_stmt_t *stmt, uint32 stmt_id);
status_t sql_send_column_cursor(sql_stmt_t *stmt, cursor_t *cursor);
status_t sql_send_return_values(sql_stmt_t *stmt, gs_type_t type, typmode_t *typmod, variant_t *v);
void sql_send_column_def(sql_stmt_t *stmt, void *sql_cursor);
status_t sql_remap(sql_stmt_t *stmt, text_t *sql);
void sql_release_sql_map(sql_stmt_t *stmt);

status_t sql_send_nls_feedback(sql_stmt_t *stmt, nlsparam_id_t id, text_t *value);
status_t sql_send_session_tz_feedback(sql_stmt_t *stmt, timezone_info_t client_timezone);

status_t sql_stack_safe(sql_stmt_t *stmt);
status_t sql_execute_check(knl_handle_t handle, text_t *sql, bool32 *exist);
status_t sql_check_exist_cols_type(sql_stmt_t *stmt, uint32 col_type, bool32 *exist);
status_t sql_get_array_from_knl_lob(sql_stmt_t *stmt, knl_handle_t locator, vm_lob_t *vlob);
status_t sql_get_array_vm_lob(sql_stmt_t *stmt, var_lob_t *var_lob, vm_lob_t *vm_lob);
void sql_free_array_vm(sql_stmt_t *stmt, uint32 entry_vmid, uint32 last_vmid);
status_t sql_row_put_inline_array(sql_stmt_t *stmt, row_assist_t *ra, var_array_t *v, uint32 real_size);
status_t sql_convert_to_array(sql_stmt_t *stmt, variant_t *v, typmode_t *mode, bool32 apply_mode);
status_t sql_convert_to_collection(sql_stmt_t *stmt, variant_t *v, void *pl_coll);
status_t sql_compare_array(sql_stmt_t *stmt, variant_t *v1, variant_t *v2, int32 *result);
status_t sql_row_put_array(sql_stmt_t *stmt, row_assist_t *ra, var_array_t *v);
status_t sql_var_as_array(sql_stmt_t *stmt, variant_t *v, typmode_t *mode);
status_t var_get_value_in_row(variant_t *var, char *buf, uint32 size, uint16 *len);
status_t add_to_trans_table_list(sql_stmt_t *stmt);
status_t sql_parse_check_from_text(knl_handle_t handle, text_t *cond_text, knl_handle_t entity,
                                   memory_context_t *memory, void **cond_tree);
status_t sql_parse_default_from_text(knl_handle_t handle, knl_handle_t dc_entity, knl_handle_t column,
                                     memory_context_t *memory, void **expr_tree, void **expr_update_tree,
                                     text_t parse_text);
status_t sql_verify_default_from_text(knl_handle_t handle, knl_handle_t column_handle, text_t parse_text);
status_t sql_alloc_mem_from_dc(void *mem, uint32 size, void **buf);
status_t sql_trace_dml_and_send(sql_stmt_t *stmt);
status_t sql_init_stmt_plan_time(sql_stmt_t *stmt);
void srv_increase_session_shard_dml_id(sql_stmt_t *stmt);
void srv_unlock_session_shard_dml_id(sql_stmt_t *stmt);
status_t sql_alloc_for_longsql_stat(sql_stmt_t *stmt);
status_t sql_alloc_context(sql_stmt_t *stmt);
status_t sql_send_parsed_stmt_normal(sql_stmt_t *stmt, uint16 columnCount);

#define my_sender(stmt) ((stmt)->session->sender)
#define SET_STMT_CONTEXT(stmt, ctx)             \
    do {                                        \
        cm_spin_lock(&(stmt)->stmt_lock, NULL); \
        (stmt)->context = (ctx);                \
        cm_spin_unlock(&(stmt)->stmt_lock);     \
    } while (0)

#define SET_STMT_PL_CONTEXT(stmt, pl_ctx)       \
    do {                                        \
        cm_spin_lock(&(stmt)->stmt_lock, NULL); \
        (stmt)->pl_context = (void *)(pl_ctx);  \
        cm_spin_unlock(&(stmt)->stmt_lock);     \
    } while (0)

static inline void sql_reset_sequence(sql_stmt_t *stmt)
{
    knl_panic(stmt->v_sequences == NULL);
}

static inline status_t sql_compare_variant(sql_stmt_t *stmt, variant_t *v1, variant_t *v2, int32 *result)
{
    if (v1->is_null) {
        *result = 1;
        return GS_SUCCESS;
    } else if (v2->is_null) {
        *result = -1;
        return GS_SUCCESS;
    }

    if (v1->type == v2->type) {
        return var_compare_same_type(v1, v2, result);
    }

    if (v1->type == GS_TYPE_ARRAY || v2->type == GS_TYPE_ARRAY) {
        return sql_compare_array(stmt, v1, v1, result);
    }

    cmp_rule_t *rule = get_cmp_rule((gs_type_t)v1->type, (gs_type_t)v2->type);
    if (rule->cmp_type == INVALID_CMP_DATATYPE) {
        GS_SET_ERROR_MISMATCH(v1->type, v2->type);
        return GS_ERROR;
    }

    if (rule->same_type) {
        return var_compare_same_type(v1, v2, result);
    }
    return GS_ERROR;
}

static inline status_t sql_convert_variant(sql_stmt_t *stmt, variant_t *v, gs_type_t type)
{
    if (v->is_null) {
        v->type = type;
        return GS_SUCCESS;
    }

    GS_RETVALUE_IFTRUE((v->type == type), GS_SUCCESS);

    if (!GS_IS_BUFF_CONSUMING_TYPE(type) || GS_IS_BINSTR_TYPE2(v->type, type)) {
        return var_convert(SESSION_NLS(stmt), v, type, NULL);
    }

    // only buffer consuming datatype needs to alloc memory
    text_buf_t buffer;

    SQL_SAVE_STACK(stmt);

    sql_keep_stack_variant(stmt, v);
    if (sql_push_textbuf(stmt, GS_CONVERT_BUFFER_SIZE, &buffer) != GS_SUCCESS) {
        SQL_RESTORE_STACK(stmt);
        return GS_ERROR;
    }

    if (var_convert(SESSION_NLS(stmt), v, type, &buffer) != GS_SUCCESS) {
        SQL_RESTORE_STACK(stmt);
        return GS_ERROR;
    }

    SQL_RESTORE_STACK(stmt);
    return GS_SUCCESS;
}

static inline status_t sql_convert_variant2(sql_stmt_t *stmt, variant_t *v1, variant_t *v2)
{
    if (v1->is_null) {
        v1->type = v2->type;
        return GS_SUCCESS;
    }

    GS_RETVALUE_IFTRUE((v1->type == v2->type), GS_SUCCESS);

    if (!GS_IS_BUFF_CONSUMING_TYPE(v2->type) || GS_IS_BINSTR_TYPE2(v1->type, v2->type)) {
        return var_convert(SESSION_NLS(stmt), v1, v2->type, NULL);
    }

    // only buffer consuming datatype needs to alloc memory
    text_buf_t buffer;

    SQL_SAVE_STACK(stmt);

    sql_keep_stack_variant(stmt, v1);
    sql_keep_stack_variant(stmt, v2);
    if (sql_push_textbuf(stmt, GS_CONVERT_BUFFER_SIZE, &buffer) != GS_SUCCESS) {
        SQL_RESTORE_STACK(stmt);
        return GS_ERROR;
    }

    if (var_convert(SESSION_NLS(stmt), v1, v2->type, &buffer) != GS_SUCCESS) {
        SQL_RESTORE_STACK(stmt);
        return GS_ERROR;
    }

    SQL_RESTORE_STACK(stmt);
    return GS_SUCCESS;
}

static inline status_t sql_get_unnamed_stmt(session_t *session, sql_stmt_t **stmt)
{
    if (session->unnamed_stmt == NULL) {
        if (sql_alloc_stmt(session, &session->unnamed_stmt) != GS_SUCCESS) {
            return GS_ERROR;
        }
        session->unnamed_stmt->sync_scn = (*stmt)->sync_scn;
        session->unnamed_stmt->pl_exec = (*stmt)->pl_exec;
    }

    *stmt = session->unnamed_stmt;
    return GS_SUCCESS;
}
status_t sql_apply_typmode(variant_t *var, const typmode_t *typmod, char *buf, bool32 is_truc);
// this function like sql_apply_typmode_bin(), can merge to one function ?
status_t sql_convert_bin(sql_stmt_t *stmt, variant_t *v, uint32 def_size);
status_t sql_convert_char(knl_session_t *session, variant_t *v, uint32 def_size, bool32 is_character);
status_t sql_part_put_number_key(variant_t *value, gs_type_t data_type, part_key_t *partkey, uint32 precision);
status_t sql_part_put_scan_key(sql_stmt_t *stmt, variant_t *value, gs_type_t data_type, part_key_t *partkey);
status_t sql_part_put_key(sql_stmt_t *stmt, variant_t *value, gs_type_t data_type, uint32 def_size, bool32 is_character,
                          uint32 precision, int32 scale, part_key_t *partkey);
status_t sql_get_char_length(text_t *text, uint32 *characters, uint32 def_size);

// callback func for convert char
status_t sql_convert_char_cb(knl_handle_t session, text_t *text, uint32 def_size, bool32 is_char);

static inline void sql_rowid2str(const rowid_t *rowid, variant_t *result, knl_dict_type_t dc_type)
{
    uint32 offset;
    char *buf = result->v_text.str;

    if (dc_type == DICT_TYPE_TABLE || dc_type == DICT_TYPE_TABLE_NOLOGGING) {
        PRTS_RETVOID_IFERR(snprintf_s(buf, GS_MAX_ROWID_BUFLEN, GS_MAX_ROWID_STRLEN, "%04u", (uint32)rowid->file));
        offset = 4;

        PRTS_RETVOID_IFERR(
            snprintf_s(buf + offset, GS_MAX_ROWID_BUFLEN - offset, GS_MAX_ROWID_STRLEN, "%010u", (uint32)rowid->page));
        offset += 10;

        PRTS_RETVOID_IFERR(
            snprintf_s(buf + offset, GS_MAX_ROWID_BUFLEN - offset, GS_MAX_ROWID_STRLEN, "%04u", (uint32)rowid->slot));
        offset += 4;
        result->v_text.len = offset;
    } else {
        result->v_text.len = 0;
        cm_concat_fmt(&result->v_text, GS_MAX_ROWID_BUFLEN, "%010u", (uint32)rowid->vmid);
        cm_concat_fmt(&result->v_text, GS_MAX_ROWID_BUFLEN - result->v_text.len, "%08u", (uint32)rowid->vm_slot);
    }
}

#define SQL_TYPE(stmt) (stmt)->context->type
#define IS_DDL(stmt) (SQL_TYPE(stmt) > SQL_TYPE_DCL_CEIL && SQL_TYPE(stmt) < SQL_TYPE_DDL_CEIL)
#define IS_DCL(stmt) (SQL_TYPE(stmt) > SQL_TYPE_DML_CEIL && SQL_TYPE(stmt) < SQL_TYPE_DCL_CEIL)

status_t sql_check_trig_commit(sql_stmt_t *stmt);
status_t shd_check_route_flag(sql_stmt_t *stmt);
status_t sql_check_tables(sql_stmt_t *stmt, sql_context_t *ctx);
status_t check_table_in_trans(session_t *session);
bool32 shd_find_table_in_trans(session_t *session);
static inline void sql_inc_active_stmts(sql_stmt_t *stmt)
{
    if (stmt->cursor_info.type != PL_FORK_CURSOR) {
        stmt->session->active_stmts_cnt++;
    }
}

static inline void sql_dec_active_stmts(sql_stmt_t *stmt)
{
    if (stmt->cursor_info.type != PL_FORK_CURSOR) {
#if defined(DEBUG)
        CM_ASSERT(stmt->session->active_stmts_cnt > 0);
#endif
        stmt->query_scn = GS_INVALID_ID64;
        stmt->gts_scn = GS_INVALID_ID64;
        stmt->session->active_stmts_cnt--;
    }
}

static inline void sql_reset_first_exec_vars(sql_stmt_t *stmt)
{
    uint32 cnt = stmt->context->fexec_vars_cnt;

    stmt->fexec_info.fexec_buff_offset = 0;

    if (cnt == 0 || stmt->fexec_info.first_exec_vars == NULL) {
        return;
    }

    while (cnt-- > 0) {
        stmt->fexec_info.first_exec_vars[cnt].type = GS_TYPE_UNINITIALIZED;
        stmt->fexec_info.first_exec_vars[cnt].is_null = GS_TRUE;
    }
}

static inline void sql_set_stmt_check(void *stmt, knl_cursor_t *cursor, bool32 is_check)
{
    ((sql_stmt_t *)stmt)->is_check = (bool8)is_check;
    ((sql_stmt_t *)stmt)->direct_knl_cursor = cursor;
}

static inline void sql_init_mtrl_vmc(handle_t *mtrl)
{
    mtrl_context_t *ctx = (mtrl_context_t *)mtrl;
    session_t *session = (session_t *)ctx->session;
    vmc_init(&session->vmp, &ctx->vmc);
}

status_t sql_init_first_exec_info(sql_stmt_t *stmt);
status_t sql_stmt_clone(sql_stmt_t *src, sql_stmt_t *dest);

// 120000000us = 120s * 1000 * 1000, OPTINFO log only valid for 120s, in case some user forgets to turn it off.
#define LOG_OPTINFO_ON(stmt) \
    ((stmt)->session->optinfo_enable && LOG_ON && (cm_monotonic_now() - (stmt)->session->optinfo_start < 120000000))

#define SQL_LOG_OPTINFO(stmt, format, ...)     \
    if (LOG_OPTINFO_ON(stmt)) {                \
        GS_LOG_OPTINFO(format, ##__VA_ARGS__); \
    }

static inline status_t sql_switch_schema_by_uid(sql_stmt_t *stmt, uint32 switch_uid, saved_schema_t *schema)
{
    uint32 curr_schema_id = stmt->session->curr_schema_id;
    text_t name;

    schema->switched_flag = stmt->session->switched_schema;
    stmt->session->switched_schema = GS_TRUE;
    schema->user_id = GS_INVALID_ID32;
    if (curr_schema_id == switch_uid) {
        return GS_SUCCESS;
    }
    if (knl_get_user_name(KNL_SESSION(stmt), switch_uid, &name) != GS_SUCCESS) {
        return GS_ERROR;
    }
    MEMS_RETURN_IFERR(
        strncpy_s(schema->user, GS_NAME_BUFFER_SIZE, stmt->session->curr_schema, strlen(stmt->session->curr_schema)));
    schema->user_id = stmt->session->curr_schema_id;

    GS_RETURN_IFERR(cm_text2str(&name, stmt->session->curr_schema, GS_NAME_BUFFER_SIZE));
    stmt->session->curr_schema_id = switch_uid;

    return GS_SUCCESS;
}

static inline void sql_restore_schema(sql_stmt_t *stmt, saved_schema_t *schema)
{
    stmt->session->switched_schema = schema->switched_flag;
    if (schema->user_id == GS_INVALID_ID32) {
        return;
    }

    errno_t errcode = strncpy_s(stmt->session->curr_schema, GS_NAME_BUFFER_SIZE, schema->user, strlen(schema->user));
    MEMS_RETVOID_IFERR(errcode);

    stmt->session->curr_schema_id = schema->user_id;
    return;
}

#define SQL_CHECK_SESSION_VALID_FOR_RETURN(stmt)                          \
    do {                                                                  \
        sql_stmt_t *root_stmt = (stmt);                                   \
        while (root_stmt->parent_stmt != NULL) {                          \
            root_stmt = root_stmt->parent_stmt;                           \
        }                                                                 \
        CHECK_SESSION_VALID_FOR_RETURN(&root_stmt->session->knl_session); \
    } while (0)

static inline status_t sql_alloc_params_buf(sql_stmt_t *stmt)
{
    uint32 max_params = stmt->context->params->count;

    if (max_params == 0) {
        stmt->param_info.params = NULL;
        return GS_SUCCESS;
    }

    return sql_push(stmt, max_params * sizeof(sql_param_t), (void **)&stmt->param_info.params);
}

static inline bool32 sql_table_in_list(sql_array_t *table_list, uint32 table_id)
{
    sql_table_t *table = NULL;
    for (uint32 i = 0; i < table_list->count; ++i) {
        table = (sql_table_t *)sql_array_get(table_list, i);
        if (table->id == table_id) {
            return GS_TRUE;
        }
    }
    return GS_FALSE;
}

static inline void sql_inc_ctx_ref(sql_stmt_t *stmt, sql_context_t *context)
{
    if (context == NULL || stmt->context_refered) {
        return;
    }
    sql_context_inc_exec(context);
    stmt->context_refered = GS_TRUE;
}

static inline void sql_dec_ctx_ref(sql_stmt_t *stmt, sql_context_t *context)
{
    if (!stmt->context_refered) {
        return;
    }
    sql_context_dec_exec(context);
    stmt->context_refered = GS_FALSE;
}
typedef enum en_mutate_table_type { SINGLE_TABLE, ALL_TABLES, UPD_TABLES, DEL_TABLES } mutate_table_type_t;

typedef struct st_mutate_table_assist {
    mutate_table_type_t type;
    uint32 table_count;
    union {
        sql_table_t *table;
        galist_t *tables;
    };
} mutate_table_assist_t;
void sql_reset_plsql_resource(sql_stmt_t *stmt);

/*
CAUTION!!!: don't change the value of expr_node_type
in column default value / check constraint, the id is stored in system table COLUMN$
*/
typedef enum en_expr_node_type {
    EXPR_NODE_PRIOR = OPER_TYPE_PRIOR,  // for prior flag of connect by clause
    EXPR_NODE_ADD = OPER_TYPE_ADD,
    EXPR_NODE_SUB = OPER_TYPE_SUB,
    EXPR_NODE_MUL = OPER_TYPE_MUL,
    EXPR_NODE_DIV = OPER_TYPE_DIV,
    EXPR_NODE_BITAND = OPER_TYPE_BITAND,
    EXPR_NODE_BITOR = OPER_TYPE_BITOR,
    EXPR_NODE_BITXOR = OPER_TYPE_BITXOR,
    EXPR_NODE_CAT = OPER_TYPE_CAT, /* character string joint */
    EXPR_NODE_MOD = OPER_TYPE_MOD,
    EXPR_NODE_LSHIFT = OPER_TYPE_LSHIFT,
    EXPR_NODE_RSHIFT = OPER_TYPE_RSHIFT,
    EXPR_NODE_UNION = OPER_TYPE_SET_UNION,
    EXPR_NODE_UNION_ALL = OPER_TYPE_SET_UNION_ALL,
    EXPR_NODE_INTERSECT = OPER_TYPE_SET_INTERSECT,
    EXPR_NODE_INTERSECT_ALL = OPER_TYPE_SET_INTERSECT_ALL,
    EXPR_NODE_EXCEPT = OPER_TYPE_SET_EXCEPT,
    EXPR_NODE_EXCEPT_ALL = OPER_TYPE_SET_EXCEPT_ALL,
    EXPR_NODE_OPCEIL = OPER_TYPE_CEIL,

    EXPR_NODE_CONST = 65536,
    EXPR_NODE_FUNC = EXPR_NODE_CONST + 1,
    EXPR_NODE_JOIN = EXPR_NODE_CONST + 2,
    EXPR_NODE_PARAM = EXPR_NODE_CONST + 3,
    EXPR_NODE_COLUMN = EXPR_NODE_CONST + 4,
    EXPR_NODE_RS_COLUMN = EXPR_NODE_CONST + 5,
    EXPR_NODE_STAR = EXPR_NODE_CONST + 6,
    EXPR_NODE_RESERVED = EXPR_NODE_CONST + 7,
    EXPR_NODE_SELECT = EXPR_NODE_CONST + 8,
    EXPR_NODE_SEQUENCE = EXPR_NODE_CONST + 9,
    EXPR_NODE_CASE = EXPR_NODE_CONST + 10,
    EXPR_NODE_GROUP = EXPR_NODE_CONST + 11,
    EXPR_NODE_AGGR = EXPR_NODE_CONST + 12,
    EXPR_NODE_USER_FUNC = EXPR_NODE_CONST + 13,  // stored procedure or user defined function
    EXPR_NODE_USER_PROC = EXPR_NODE_CONST + 14,  // stored procedure
    EXPR_NODE_PROC = EXPR_NODE_CONST + 15,       // stored procedure
    EXPR_NODE_NEW_COL = EXPR_NODE_CONST + 16,    // ':NEW.F1' IN TRIGGER
    EXPR_NODE_OLD_COL = EXPR_NODE_CONST + 17,    // ':OLD.F1' IN TRIGGER
    EXPR_NODE_PL_ATTR = EXPR_NODE_CONST + 18,
    EXPR_NODE_OVER = EXPR_NODE_CONST + 19,          // Analytic Func
    EXPR_NODE_TRANS_COLUMN = EXPR_NODE_CONST + 20,  // for transform column
    EXPR_NODE_NEGATIVE = EXPR_NODE_CONST + 21,
    EXPR_NODE_DIRECT_COLUMN = EXPR_NODE_CONST + 22,  // for function based index column
    EXPR_NODE_ARRAY = EXPR_NODE_CONST + 23,          // array
    EXPR_NODE_V_METHOD = EXPR_NODE_CONST + 24,
    EXPR_NODE_V_ADDR = EXPR_NODE_CONST + 25,
    EXPR_NODE_V_CONSTRUCT = EXPR_NODE_CONST + 26,
    EXPR_NODE_CSR_PARAM = EXPR_NODE_CONST + 27,
    EXPR_NODE_UNKNOWN = 0xFFFFFFFF,
} expr_node_type_t;

#define IS_UDT_EXPR(type) \
    ((type) == EXPR_NODE_V_METHOD || (type) == EXPR_NODE_V_ADDR || (type) == EXPR_NODE_V_CONSTRUCT)

#define IS_OPER_NODE(node) ((node)->type > 0 && (node)->type < EXPR_NODE_OPCEIL)

typedef struct nodetype_mapped {
    expr_node_type_t id;
    text_t name;
} nodetype_mapped_t;

static const nodetype_mapped_t g_nodetype_names[] = {
    // type_id             type_name
    { EXPR_NODE_PRIOR, { (char *)"PRIOR", 5 } },
    { EXPR_NODE_ADD, { (char *)"ADD", 3 } },
    { EXPR_NODE_SUB, { (char *)"SUB", 3 } },
    { EXPR_NODE_MUL, { (char *)"MUL", 3 } },
    { EXPR_NODE_DIV, { (char *)"DIV", 3 } },
    { EXPR_NODE_BITAND, { (char *)"BITAND", 6 } },
    { EXPR_NODE_BITOR, { (char *)"BITOR", 5 } },
    { EXPR_NODE_BITXOR, { (char *)"BITXOR", 6 } },
    { EXPR_NODE_CAT, { (char *)"CAT", 3 } },
    { EXPR_NODE_MOD, { (char *)"MOD", 3 } },
    { EXPR_NODE_LSHIFT, { (char *)"LSHIFT", 6 } },
    { EXPR_NODE_RSHIFT, { (char *)"RSHIFT", 6 } },
    { EXPR_NODE_UNION, { (char *)"UNION", 5 } },
    { EXPR_NODE_UNION_ALL, { (char *)"UNION_ALL", 9 } },
    { EXPR_NODE_INTERSECT, { (char *)"INTERSECT", 9 } },
    { EXPR_NODE_INTERSECT_ALL, { (char *)"INTERSECT_ALL", 13 } },
    { EXPR_NODE_EXCEPT, { (char *)"EXCEPT", 6 } },
    { EXPR_NODE_EXCEPT_ALL, { (char *)"EXCEPT_ALL", 10 } },
    { EXPR_NODE_OPCEIL, { (char *)"OPCEIL", 6 } },
    { EXPR_NODE_CONST, { (char *)"CONST", 5 } },
    { EXPR_NODE_FUNC, { (char *)"FUNC", 4 } },
    { EXPR_NODE_JOIN, { (char *)"JOIN", 4 } },
    { EXPR_NODE_PARAM, { (char *)"PARAM", 5 } },
    { EXPR_NODE_COLUMN, { (char *)"COLUMN", 6 } },
    { EXPR_NODE_RS_COLUMN, { (char *)"RS_COLUMN", 9 } },
    { EXPR_NODE_STAR, { (char *)"STAR", 4 } },
    { EXPR_NODE_RESERVED, { (char *)"RESERVED", 8 } },
    { EXPR_NODE_SELECT, { (char *)"SELECT", 6 } },
    { EXPR_NODE_SEQUENCE, { (char *)"SEQUENCE", 8 } },
    { EXPR_NODE_CASE, { (char *)"CASE", 4 } },
    { EXPR_NODE_GROUP, { (char *)"GROUP", 5 } },
    { EXPR_NODE_AGGR, { (char *)"AGGR", 4 } },
    { EXPR_NODE_USER_FUNC, { (char *)"USER_FUNC", 9 } },
    { EXPR_NODE_USER_PROC, { (char *)"USER_PROC", 9 } },
    { EXPR_NODE_PROC, { (char *)"PROC", 4 } },
    { EXPR_NODE_NEW_COL, { (char *)"NEW_COL", 7 } },
    { EXPR_NODE_OLD_COL, { (char *)"OLD_COL", 7 } },
    { EXPR_NODE_PL_ATTR, { (char *)"PL_ATTR", 7 } },
    { EXPR_NODE_OVER, { (char *)"OVER", 4 } },
    { EXPR_NODE_TRANS_COLUMN, { (char *)"TRANS_COLUMN", 12 } },
    { EXPR_NODE_NEGATIVE, { (char *)"NEGATIVE", 8 } },
    { EXPR_NODE_DIRECT_COLUMN, { (char *)"DIRECT_COLUMN", 13 } },
    { EXPR_NODE_ARRAY, { (char *)"ARRAY", 5 } },
    { EXPR_NODE_V_METHOD, { (char *)"V_METHOD", 8 } },
    { EXPR_NODE_V_ADDR, { (char *)"V_ADDR", 6 } },
    { EXPR_NODE_V_CONSTRUCT, { (char *)"V_CONSTRUCT", 11 } },
    { EXPR_NODE_UNKNOWN, { (char *)"UNKNOWN_TYPE", 12 } },
};

typedef struct st_expr_profile {
    uint32 xflags;  // exclusive flags
    bool32 is_aggr;
    bool32 is_cond;
    sql_context_t *context;
    sql_clause_t curr_clause;  // current verify operation identify
} expr_profile_t;

typedef enum en_unary_oper {
    UNARY_OPER_NONE = 0,
    UNARY_OPER_POSITIVE = 1,
    UNARY_OPER_NEGATIVE = -1,
    UNARY_OPER_ROOT = 2,
    UNARY_OPER_ROOT_NEGATIVE = -2 /* combine UNARY_OPER_ROOT and UNARY_OPER_NEGATIVE */
} unary_oper_t;

#define NODE_TYPE_SIZE ELEMENT_COUNT(g_nodetype_names)
#define UNARY_INCLUDE_ROOT(node) (abs((int32)(node)->unary) == (int32)UNARY_OPER_ROOT)
#define UNARY_INCLUDE_NEGATIVE(node) ((int32)(node)->unary < UNARY_OPER_NONE)
#define UNARY_INCLUDE_NON_NEGATIVE(node) ((int32)(node)->unary >= UNARY_OPER_NONE)
#define UNARY_REDUCE_NEST(out_expr, sub_node)                          \
    do {                                                               \
        if ((out_expr)->unary != UNARY_OPER_NONE) {                    \
            if ((sub_node)->unary == UNARY_OPER_NONE) {                \
                (sub_node)->unary = (out_expr)->unary;                 \
                break;                                                 \
            }                                                          \
            (sub_node)->unary *= (out_expr)->unary;                    \
            if ((sub_node)->unary > UNARY_OPER_ROOT) {                 \
                (sub_node)->unary = UNARY_OPER_ROOT;                   \
            } else if ((sub_node)->unary < UNARY_OPER_ROOT_NEGATIVE) { \
                (sub_node)->unary = UNARY_OPER_ROOT_NEGATIVE;          \
            }                                                          \
        }                                                              \
    } while (0);

#define SQL_SET_OPTMZ_MODE(node, _mode_)            \
    do {                                            \
        (node)->optmz_info.mode = (uint16)(_mode_); \
    } while (0)

#define SQL_MAX_FEXEC_VAR_BYTES SIZE_K(64)
#define SQL_MAX_FEXEC_VARS 128
#define SQL_HASH_OPTM_THRESHOLD 10
#define SQL_MAX_HASH_OPTM_KEYS 64
#define SQL_MAX_HASH_OPTM_COUNT 256

/* * When CONCAT (||) two const variants, if length of the final length is
less than this Marco, we do the constant optimization in verification phase;
since concatenating two long string may consume too must context memory.
Then the optimization is done in first execution */
#define SQL_MAX_OPTMZ_CONCAT_LEN 512

#define JSON_FUNC_ATTR_EQUAL(att1, att2) (((att1)->ids == (att2)->ids) && ((att1)->return_size == (att2)->return_size))

/* Get the datatype of an expr node and tree */
#define NODE_DATATYPE(node) ((node)->datatype)
/* TREE_DATATYPE cannot use in executing, can use sql_get_tree_datetype */
#define TREE_DATATYPE(tree) (NODE_DATATYPE((tree)->root))

#define NODE_TYPMODE(node) ((node)->typmod)
#define TREE_TYPMODE(tree) (NODE_TYPMODE((tree)->root))

/* Get the expr type of an expr node and tree */
#define NODE_EXPR_TYPE(node) ((node)->type)
#define TREE_EXPR_TYPE(tree) (NODE_EXPR_TYPE((tree)->root))

/* Get the location info of an expr node and tree */
#define NODE_LOC(node) ((node)->loc)
#define TREE_LOC(tree) (NODE_LOC((tree)->root))

#define NODE_VALUE(T, node) VALUE(T, &(node)->value)
#define NODE_VALUE_PTR(T, node) VALUE_PTR(T, &(node)->value)

#define EXPR_VALUE(T, expr) NODE_VALUE(T, (expr)->root)
#define EXPR_VALUE_PTR(T, expr) NODE_VALUE_PTR(T, (expr)->root)

/* Get table id of an column expr node and tree */
#define NODE_TAB(node) VAR_TAB(&(node)->value)
#define EXPR_TAB(expr) VAR_TAB(&(expr)->root->value)
/* Get table id of an rowid expr node and tree */
#define ROWID_NODE_TAB(node) ((node)->value.v_rid.tab_id)
#define ROWID_EXPR_TAB(expr) ((expr)->root->value.v_rid.tab_id)
/* Get column id of an column expr node and tree */
#define NODE_COL(node) VAR_COL(&(node)->value)
#define EXPR_COL(expr) VAR_COL(&(expr)->root->value)
/* Get NODE_ANCESTOR of an column expr node and tree */
#define NODE_ANCESTOR(node) VAR_ANCESTOR(&(node)->value)
#define EXPR_ANCESTOR(expr) VAR_ANCESTOR(&(expr)->root->value)
/* Get NODE_ANCESTOR of an column expr node and tree */
#define ROWID_NODE_ANCESTOR(node) ((node)->value.v_rid.ancestor)
/* Get NODE_VM_ID of an column expr node */
#define NODE_VM_ID(node) VAR_VM_ID(&(node)->value)
/* Get NODE_VM_ANCESTOR of an column expr node */
#define NODE_VM_ANCESTOR(node) VAR_VM_ANCESTOR(&(node)->value)
/* Get group id of an vm column expr node */
#define NODE_VM_GROUP(node) VAR_VM_GROUP(&(node)->value)

#define TAB_OF_NODE(node)                                                                         \
    ((NODE_EXPR_TYPE(node) == EXPR_NODE_COLUMN || NODE_EXPR_TYPE(node) == EXPR_NODE_TRANS_COLUMN) \
         ? NODE_TAB(node)                                                                         \
         : ROWID_NODE_TAB(node))
#define COL_OF_NODE(node)                                                                                          \
    ((NODE_EXPR_TYPE(node) == EXPR_NODE_COLUMN || NODE_EXPR_TYPE(node) == EXPR_NODE_TRANS_COLUMN) ? NODE_COL(node) \
                                                                                                  : GS_INVALID_ID16)
#define ANCESTOR_OF_NODE(node) \
    (NODE_EXPR_TYPE(node) == EXPR_NODE_COLUMN ? NODE_ANCESTOR(node) : ROWID_NODE_ANCESTOR(node))

/* To check whether an expr_tree or expr_node is a reserved NULL,
 * @see sql_verify_reserved_value */
#define NODE_IS_RES_NULL(node) ((NODE_EXPR_TYPE(node) == EXPR_NODE_RESERVED) && ((node)->value.v_int == RES_WORD_NULL))
#define NODE_IS_RES_ROWNUM(node) \
    ((NODE_EXPR_TYPE(node) == EXPR_NODE_RESERVED) && ((node)->value.v_int == RES_WORD_ROWNUM))
#define NODE_IS_RES_ROWSCN(node) \
    ((NODE_EXPR_TYPE(node) == EXPR_NODE_RESERVED) && ((node)->value.v_int == RES_WORD_ROWSCN))
#define NODE_IS_RES_ROWID(node) \
    ((NODE_EXPR_TYPE(node) == EXPR_NODE_RESERVED) && ((node)->value.v_int == RES_WORD_ROWID))
#define NODE_IS_RES_ROWNODEID(node) \
    ((NODE_EXPR_TYPE(node) == EXPR_NODE_RESERVED) && ((node)->value.v_int == RES_WORD_ROWNODEID))
#define NODE_IS_RES_DUMMY(node) \
    ((NODE_EXPR_TYPE(node) == EXPR_NODE_RESERVED) && ((node)->value.v_int == RES_WORD_DUMMY))
#define NODE_IS_RES_TRUE(node) ((NODE_EXPR_TYPE(node) == EXPR_NODE_RESERVED) && ((node)->value.v_int == RES_WORD_TRUE))
#define NODE_IS_RES_FALSE(node) \
    ((NODE_EXPR_TYPE(node) == EXPR_NODE_RESERVED) && ((node)->value.v_int == RES_WORD_FALSE))

/* select rowid from view may generate a column-type rowid, see function @sql_verify_rowid */
#define NODE_IS_COLUMN_ROWID(node) \
    ((NODE_EXPR_TYPE(node) == EXPR_NODE_COLUMN) && ((node)->value.v_col.is_rowid == GS_TRUE))
/* select rownodeid from view may generate a column-type rownodeid, see function @sql_verify_rownodeid */
#define NODE_IS_COLUMN_ROWNODEID(node) \
    ((NODE_EXPR_TYPE(node) == EXPR_NODE_COLUMN) && ((node)->value.v_col.is_rownodeid == GS_TRUE))

#define TREE_IS_RES_NULL(expr) NODE_IS_RES_NULL((expr)->root)
#define TREE_IS_RES_ROWID(expr) NODE_IS_RES_ROWID((expr)->root)

#define NODE_IS_VALUE_NULL(node) (node)->value.is_null
#define TREE_IS_VALUE_NULL(tree) NODE_IS_VALUE_NULL((tree)->root)

#define NODE_IS_CONST(expr) ((expr)->type == EXPR_NODE_CONST)
#define TREE_IS_CONST(tree) (NODE_IS_CONST((tree)->root))

#define NODE_IS_PARAM(expr) ((expr)->type == EXPR_NODE_PARAM)
#define NODE_IS_CSR_PARAM(expr) ((expr)->type == EXPR_NODE_CSR_PARAM)

#define NODE_IS_NEGATIVE(expr) ((expr)->type == EXPR_NODE_NEGATIVE)
#define TREE_IS_NEGATIVE(tree) (NODE_IS_NEGATIVE((tree)->root))

#define NODE_OPTMZ_MODE(node) ((node)->optmz_info.mode)
#define NODE_OPTMZ_IDX(node) ((node)->optmz_info.idx)
#define NODE_OPTMZ_COUNT(node) ((node)->optmz_info.count)

#define NODE_IS_OPTMZ_CONST(node) (NODE_OPTMZ_MODE(node) == OPTMZ_AS_CONST)
#define NODE_IS_FIRST_EXECUTABLE(node) (NODE_OPTMZ_MODE(node) == OPTMZ_FIRST_EXEC_ROOT)
#define NODE_IS_OPTMZ_ALL(node) (NODE_OPTMZ_MODE(node) == OPTMZ_FIRST_EXEC_ALL)

/* To check whether an expr_tree or expr_node is a reserved DEFAULT,
 * @see sql_verify_reserved_value */
#define TREE_IS_RES_DEFAULT(expr) \
    ((TREE_EXPR_TYPE(expr) == EXPR_NODE_RESERVED) && (EXPR_VALUE(int32, expr) == RES_WORD_DEFAULT))

/* To check whether an expr_tree or expr_node is a binding parameter,
 * @see sql_verify_reserved_value */
#define TREE_IS_BINDING_PARAM(expr) (TREE_EXPR_TYPE(expr) == EXPR_NODE_PARAM)

#define IS_NORMAL_COLUMN(expr) ((expr)->root->type == EXPR_NODE_COLUMN && (expr)->root->unary == UNARY_OPER_NONE)
#define IS_FAKE_COLUMN_NODE(node) (NODE_IS_RES_ROWNUM(node) || NODE_IS_RES_ROWSCN(node) || NODE_IS_RES_ROWID(node))
#define IS_LOCAL_COLUMN(expr) (IS_NORMAL_COLUMN(expr) && EXPR_ANCESTOR(expr) == 0)
#define IS_ANCESTOR_COLUMN(expr) (IS_NORMAL_COLUMN(expr) && EXPR_ANCESTOR(expr) > 0)

/* trim type for the argument expression of TRIM() */
typedef enum en_func_trim_type {
    FUNC_RTRIM = 0, /* also stands for unnamable keyword "TRAILING" */
    FUNC_LTRIM = 1, /* also stands for unnamable keyword "LEADING" */
    FUNC_BOTH = 2,  /* also stands for unnamable keyword "BOTH" */
} func_trim_type_t;

typedef enum en_any_type { ANY_MIN, ANY_MAX } any_type_t;

/**
 * 1. `select * from tableX where date_col < to_date('2018-09-10 12:12:12');`
 * The format of TO_DATE relies on NLS_DATE_FORMAT, which is dependent on
 * the session parameter.
 * If NLS_DATE_FORMAT = 'YYYY-MM-DD HH24:MI:SS', the parsed date is 2018/09/10.
 * However, if NLS_DATE_FORMAT = 'YYYY-DD-MM HH24:MI:SS', the parsed date is 2018/10/09.
 * Due to soft parse, TO_DATE with one constant argument can not be optimized
 * in verify phase. In practice, it can be computed in advance on the first execution.
 *
 * Similar scenes include SYSDATE, SYSTIMESTAMP, SESSIONTIMEZONE;
 * @author Added 2018/10/06 */
typedef enum en_optmz_mode {
    OPTMZ_NONE = 0,
    OPTMZ_FIRST_EXEC_ROOT,
    OPTMZ_FIRST_EXEC_NODE,
    OPTMZ_FIRST_EXEC_ALL,
    OPTMZ_AS_PARAM,
    OPTMZ_AS_CONST,
    OPTMZ_AS_HASH_TABLE,
    OPTMZ_INVAILD = 100
} optmz_mode_t;

typedef struct st_expr_optmz_info {
    uint16 mode;  // @optmz_mode_t
    uint16 idx;
} expr_optmz_info_t;

typedef struct st_distinct_t {
    bool32 need_distinct;
    uint32 idx;
    uint32 group_id;
} distinct_t;

typedef struct st_json_func_attr {
    uint64 ids;          // json_func_attr_t
    uint16 return_size;  // for JFUNC_ATT_RETURNING_VARCHAR2
    struct {
        bool8 ignore_returning : 1;
        bool8 unused : 7;
    };
    uint8 unused2;
} json_func_attr_t;

#pragma pack(4)
typedef struct st_expr_node {
    struct st_expr_tree *owner;
    struct st_expr_tree *argument;  // for function node & array node
    expr_node_type_t type;
    var_word_t word;  // for column, function
    unary_oper_t unary;
    expr_optmz_info_t optmz_info;
    variant_t value;
    source_location_t loc;

    union {
        struct {
            gs_type_t datatype;  // data type, set by verifier
            union {
                struct {
                    uint16 size;  // data size, set by verifier
                    uint8 precision;
                    int8 scale;
                };
                void *udt_type;  // udt type meta, as plv_record_t or plv_collection_t
            };
        };
        typmode_t typmod;
    };

    union {
        struct st_cond_tree *cond_arg;  // for if function
        winsort_args_t *win_args;       // for winsort-func
        uint32 ext_args;                // for trim func
        galist_t *sort_items;           // for group_concat(... order by expr) or median
    };

    bool8 nullaware : 1;       // for all/any optimized min/max aggr node
    bool8 exec_default : 1;    // execute default expr cast
    bool8 format_json : 1;     // for json expr
    bool8 has_verified : 1;    // for order by 1,2 or order by alias
    bool8 is_median_expr : 1;  // expr for sharding median
    bool8 ignore_nulls : 1;    // for first_value/last_value
    bool8 parent_ref : 1;      // true means is already added to parent refs
    bool8 is_pkg : 1;          // if in user defined pkg
    uint8 lang_type;           // for proc/func lang type
    uint8 unused[2];

    json_func_attr_t json_func_attr;  // for json_value/json_query/json_mergepatch
    distinct_t dis_info;

    // for expression tree
    struct st_expr_node *left;
    struct st_expr_node *right;

    // for expr-node chain
    // don't change the definition order of prev and next
    // so cond_node_t can be change to biqueue_node_t by macro QUEUE_NODE_OF
    // and be added to a bi-queue
    struct st_expr_node *prev;
    struct st_expr_node *next;
} expr_node_t;
#pragma pack()

typedef struct st_expr_chain {
    uint32 count;
    expr_node_t *first;
    expr_node_t *last;
} expr_chain_t;

typedef struct st_star_location {
    uint32 begin;
    uint32 end;
} star_location_t;

typedef struct st_expr_tree {
    sql_context_t *owner;
    expr_node_t *root;
    struct st_expr_tree *next;  // for expr list
    source_location_t loc;
    uint32 expecting;
    unary_oper_t unary;
    bool32 generated;
    expr_chain_t chain;
    text_t arg_name;
    star_location_t star_loc;
    uint32 subscript;
} expr_tree_t;

typedef struct st_sql_walker {
    sql_stmt_t *stmt;
    sql_context_t *context;
    galist_t *columns;
} sql_walker_t;

typedef enum en_pivot_type {
    PIVOT_TYPE,
    UNPIVOT_TYPE,
    NOPIVOT_TYPE,
} pivot_type_t;

typedef status_t (*expr_calc_func_t)(sql_stmt_t *stmt, expr_node_t *node, variant_t *result);

typedef struct st_node_func_tab {
    expr_node_type_t type;
    expr_calc_func_t invoke;
} node_func_tab_t;

typedef struct st_case_pair {
    struct st_cond_tree *when_cond;
    expr_tree_t *when_expr;
    expr_tree_t *value;
} case_pair_t;

typedef struct st_case_expr {
    bool32 is_cond; /* FALSE: CASE expr WHEN expr THEN expr ... END , TRUE: CASE WHEN condition THEN expr ... END */
    expr_tree_t *expr;
    galist_t pairs;
    expr_tree_t *default_expr;
} case_expr_t;

typedef struct st_visit_assist {
    sql_stmt_t *stmt;
    sql_query_t *query;
    uint32 excl_flags;
    void *param0;
    void *param1;
    void *param2;
    void *param3;
    uint32 result0;
    uint32 result1;
    uint32 result2;
    date_t time;
} visit_assist_t;

#define RELATION_LEVELS 3

typedef struct st_cols_used {
    biqueue_t cols_que[RELATION_LEVELS];  // list for ancestor, parent and self column expression
    uint16 count[RELATION_LEVELS];        // count for ancestor, parent and self column expression
    uint8 level_flags[RELATION_LEVELS];   // flags of each level
    uint8 flags;
    uint8 subslct_flag;
    uint8 inc_flags;
    uint8 level;
    uint8 func_maxlev;  // the max level of column expression in functions
    uint32 ancestor;    // the max ancestor of column
    bool8 collect_sub_select : 1;
    bool8 unused : 7;
} cols_used_t;

#define APPEND_CHAIN(chain, node)         \
    do {                                  \
        (node)->next = NULL;              \
        if ((chain)->count == 0) {        \
            (chain)->first = node;        \
            (chain)->last = node;         \
            (node)->prev = NULL;          \
        } else {                          \
            (chain)->last->next = node;   \
            (node)->prev = (chain)->last; \
            (chain)->last = node;         \
        }                                 \
        (chain)->count++;                 \
    } while (0)

#define SQL_GET_STMT_SYSTIMESTAMP(stmt, result)                   \
    do {                                                          \
        if ((stmt)->v_systimestamp == SQL_UNINITIALIZED_TSTAMP) { \
            (stmt)->v_systimestamp = cm_now();                    \
        }                                                         \
        (result)->v_tstamp = (stmt)->v_systimestamp;              \
    } while (0)

#define SQL_GET_STMT_SYSDATE(stmt, result)                 \
    do {                                                   \
        if ((stmt)->v_sysdate == SQL_UNINITIALIZED_DATE) { \
            (stmt)->v_sysdate = cm_date_now();             \
        }                                                  \
        (result)->v_date = (stmt)->v_sysdate;              \
    } while (0)

#define VA_EXCL_NONE 0x00000000
#define VA_EXCL_PRIOR 0x00000001
#define VA_EXCL_WIN_SORT 0x00000002
#define VA_EXCL_FUNC 0x00000004
#define VA_EXCL_PROC 0x00000008

#define ANCESTOR_IDX 0
#define PARENT_IDX 1
#define SELF_IDX 2

#define FLAG_HAS_ANCESTOR_COLS 0x01
#define FLAG_HAS_PARENT_COLS 0x02
#define FLAG_HAS_SELF_COLS 0x04

#define FLAG_INC_ROWNUM 0x01
#define FLAG_INC_PRIOR 0x02
#define FLAG_INC_PARAM 0x04

#define LEVEL_HAS_DIFF_COLS 0x01
#define LEVEL_HAS_DIFF_TABS 0x02
#define LEVEL_HAS_ROWID 0x04
#define LEVEL_HAS_ROWNODEID 0x08

#define STATIC_SUB_SELECT 0x01
#define DYNAMIC_SUB_SELECT 0x02

#define HAS_PARENT_COLS(flags) ((flags)&FLAG_HAS_PARENT_COLS)
#define HAS_ANCESTOR_COLS(flags) ((flags)&FLAG_HAS_ANCESTOR_COLS)
#define HAS_SELF_COLS(flags) ((flags)&FLAG_HAS_SELF_COLS)
#define HAS_NO_COLS(flags) ((flags) == 0)
#define HAS_ONLY_SELF_COLS(flags) ((flags) == FLAG_HAS_SELF_COLS)
#define HAS_ONLY_PARENT_COLS(flags) ((flags) == FLAG_HAS_PARENT_COLS)
#define HAS_PRNT_OR_ANCSTR_COLS(flags) (HAS_PARENT_COLS(flags) || HAS_ANCESTOR_COLS(flags))
#define HAS_PRNT_AND_ANCSTR_COLS(flags) (HAS_PARENT_COLS(flags) && HAS_ANCESTOR_COLS(flags))
#define HAS_NOT_ONLY_SELF_COLS(flags) (HAS_SELF_COLS(flags) && (HAS_ANCESTOR_COLS(flags) || HAS_PARENT_COLS(flags)))

#define HAS_DIFF_TABS(cols_used, idx) ((cols_used)->level_flags[idx] & LEVEL_HAS_DIFF_TABS)
#define HAS_ROWID_COLUMN(cols_used, idx) ((cols_used)->level_flags[idx] & LEVEL_HAS_ROWID)
#define HAS_ROWNODEID_COLUMN(cols_used, idx) ((cols_used)->level_flags[idx] & LEVEL_HAS_ROWNODEID)

#define HAS_SUBSLCT(cols_used) ((cols_used)->subslct_flag > 0)
#define HAS_STATIC_SUBSLCT(cols_used) ((cols_used)->subslct_flag & STATIC_SUB_SELECT)
#define HAS_DYNAMIC_SUBSLCT(cols_used) ((cols_used)->subslct_flag & DYNAMIC_SUB_SELECT)

#define HAS_ROWNUM(cols_used) ((cols_used)->inc_flags & FLAG_INC_ROWNUM)
#define HAS_PRIOR(cols_used) ((cols_used)->inc_flags & FLAG_INC_PRIOR)
#define HAS_PARAM(cols_used) ((cols_used)->inc_flags & FLAG_INC_PARAM)

#define VAR_IS_NUMBERIC_ZERO(var) \
    ((var)->is_null == GS_FALSE && GS_IS_NUMERIC_TYPE((var)->type) && (var)->v_bigint == 0)

static inline gs_type_t sql_get_func_arg1_datatype(const expr_node_t *func_node)
{
    CM_POINTER3(func_node, func_node->argument, func_node->argument->root);
    return func_node->argument->root->datatype;
}

static inline gs_type_t sql_get_func_arg2_datatype(const expr_node_t *func_node)
{
    CM_POINTER2(func_node, func_node->argument);
    CM_POINTER2(func_node->argument->root, func_node->argument->next->root);
    return func_node->argument->next->root->datatype;
}

void sql_init_visit_assist(visit_assist_t *va, sql_stmt_t *stmt, sql_query_t *query);
const text_t *sql_get_nodetype_text(expr_node_type_t type);
typedef status_t (*visit_func_t)(visit_assist_t *va, expr_node_t **node);
status_t visit_expr_node(visit_assist_t *va, expr_node_t **node, visit_func_t visit_func);
status_t visit_expr_tree(visit_assist_t *va, expr_tree_t *tree, visit_func_t visit_func);
status_t visit_func_node(visit_assist_t *va, expr_node_t *node, visit_func_t visit_func);

bool32 sql_expr_tree_equal(sql_stmt_t *stmt, expr_tree_t *tree1, expr_tree_t *tree2, uint32 *tab_map);
status_t sql_get_reserved_value(sql_stmt_t *stmt, expr_node_t *node, variant_t *value);
status_t sql_convert_to_scn(sql_stmt_t *stmt, void *expr, bool32 scn_type, uint64 *scn);
status_t sql_exec_expr_node(sql_stmt_t *stmt, expr_node_t *node, variant_t *result);
bool32 sql_expr_node_exist_table(expr_node_t *node, uint32 table_id);
bool32 sql_expr_node_exist_ancestor_table(expr_node_t *node, uint32 table_id, uint32 is_ancestor);
#define sql_expr_exist_table(expr, table_id) sql_expr_node_exist_table((expr)->root, table_id)
#define sql_expr_exist_ancestor_table(expr, table_id, is_ancestor) \
    sql_expr_node_exist_ancestor_table((expr)->root, table_id, is_ancestor)

bool32 sql_is_const_expr_node(const expr_node_t *node);
bool32 sql_is_const_expr_tree(expr_tree_t *expr);
bool32 sql_expr_tree_in_tab_list(sql_array_t *tables, expr_tree_t *expr_tree, bool32 use_remote_id, bool32 *exist_col);
status_t sql_try_optimize_const_expr(sql_stmt_t *stmt, expr_node_t *node);
status_t sql_get_serial_value(sql_stmt_t *stmt, knl_dictionary_t *dc, variant_t *value);
status_t sql_expr_tree_walker(sql_stmt_t *stmt, expr_tree_t *expr_tree,
                              status_t (*fetch)(sql_stmt_t *stmt, expr_node_t *node, void *context), void *context);
status_t sql_expr_node_walker(sql_stmt_t *stmt, expr_node_t *node,
                              status_t (*fetch)(sql_stmt_t *stmt, expr_node_t *node, void *context), void *context);
status_t sql_exec_oper(sql_stmt_t *stmt, expr_node_t *node, variant_t *result);
void sql_copy_first_exec_var(sql_stmt_t *stmt, variant_t *src, variant_t *dst);

static status_t inline sql_exec_expr(sql_stmt_t *stmt, expr_tree_t *expr, variant_t *result)
{
    return sql_exec_expr_node(stmt, expr->root, result);
}

static inline uint32 sql_expr_list_len(expr_tree_t *list)
{
    uint32 len = 1;
    while (list->next != NULL) {
        len++;
        list = list->next;
    }

    return len;
}

status_t sql_exec_default(void *stmt, void *default_expr, variant_t *value);
status_t sql_get_func_index_expr_size(knl_handle_t session, text_t *default_text, typmode_t *typmode);
bool32 sql_compare_index_expr(knl_handle_t session, text_t *func_text1, text_t *func_text2);
status_t sql_exec_index_col_func(knl_handle_t sess, knl_handle_t knl_cursor, gs_type_t datatype, void *expr,
                                 variant_t *result, bool32 is_new);
/* The following rules describe the skipped expr type, that do not make
 * static-checking */
static inline bool32 sql_is_skipped_expr(const expr_tree_t *expr)
{
    if (TREE_IS_RES_NULL(expr) || TREE_IS_RES_DEFAULT(expr)) {
        return GS_TRUE;
    }

    if (TREE_IS_BINDING_PARAM(expr)) {
        return GS_TRUE;
    }

    if (GS_TYPE_UNKNOWN == TREE_DATATYPE(expr)) {
        return GS_TRUE;
    }

    return GS_FALSE;
}

status_t sql_exec_concat(sql_stmt_t *stmt, variant_t *l_var, variant_t *r_var, variant_t *result);
status_t sql_exec_unary(expr_node_t *node, variant_t *var);

static inline bool32 sql_is_single_const_or_param(expr_node_t *expr_node)
{
    return (bool32)(NODE_IS_CONST(expr_node) || NODE_IS_PARAM(expr_node) || NODE_IS_CSR_PARAM(expr_node));
}

static inline void sql_convert_lob_type(expr_node_t *node, gs_type_t datatype)
{
    if (datatype == GS_TYPE_CLOB || datatype == GS_TYPE_IMAGE) {
        node->typmod.datatype = GS_TYPE_STRING;
    } else if (datatype == GS_TYPE_BLOB) {
        node->typmod.datatype = GS_TYPE_RAW;
    }
}

status_t sql_clone_expr_tree(void *ctx, expr_tree_t *src_expr_tree, expr_tree_t **dest_expr_tree,
                             ga_alloc_func_t alloc_mem_func);
status_t sql_clone_expr_node(void *ctx, expr_node_t *src_expr_node, expr_node_t **dest_expr_node,
                             ga_alloc_func_t alloc_mem_func);
status_t sql_clone_var_column(void *ctx, var_column_t *src, var_column_t *dest, ga_alloc_func_t alloc_mem_func);
bool32 sql_expr_node_equal(sql_stmt_t *stmt, expr_node_t *node1, expr_node_t *node2, uint32 *tab_map);
status_t sql_get_lob_value_from_knl(sql_stmt_t *stmt, variant_t *result);
status_t sql_get_lob_value_from_vm(sql_stmt_t *stmt, variant_t *result);
status_t sql_get_lob_value(sql_stmt_t *stmt, variant_t *result);
status_t sql_get_lob_value_from_normal(sql_stmt_t *stmt, variant_t *result);
status_t sql_get_expr_datatype(sql_stmt_t *stmt, expr_tree_t *expr, gs_type_t *type);
status_t sql_get_param_value(sql_stmt_t *stmt, uint32 id, variant_t *result);
status_t sql_get_expr_unique_table(sql_stmt_t *stmt, expr_node_t *node, uint16 *tab, uint32 *ancestor);
status_t sql_get_subarray_to_value(array_assist_t *aa, vm_lob_t *src, int32 start, int32 end, gs_type_t type,
                                   variant_t *value);
status_t sql_get_element_to_value(sql_stmt_t *stmt, array_assist_t *aa, vm_lob_t *src, int32 start, int32 end,
                                  gs_type_t type, variant_t *value);
status_t sql_exec_array_element(sql_stmt_t *stmt, array_assist_t *aa, uint32 subscript, variant_t *ele_value,
                                bool32 last, vm_lob_t *vlob);
expr_node_t *sql_find_column_in_func(expr_node_t *node);

extern cols_used_t g_cols_used_init;

static inline void init_cols_used(cols_used_t *cols_used)
{
    uint32 loop;

    *cols_used = g_cols_used_init;
    cols_used->collect_sub_select = GS_TRUE;
    for (loop = 0; loop < RELATION_LEVELS; ++loop) {
        biqueue_init(&cols_used->cols_que[loop]);
    }
}

void sql_collect_cols_in_expr_tree(expr_tree_t *tree, cols_used_t *cols_used);
void sql_collect_cols_in_expr_node(expr_node_t *node, cols_used_t *cols_used);
status_t add_node_2_parent_ref_core(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *node, uint32 tab,
                                    uint32 temp_ancestor);

// in case include sql_cond.h
void sql_collect_cols_in_cond(void *cond_node, cols_used_t *cols_used);

status_t sql_check_not_support_reserved_value_shard(reserved_wid_t type);

static inline expr_node_t *sql_get_origin_ref(expr_node_t *expr_node)
{
    if (expr_node->type != EXPR_NODE_GROUP) {
        return expr_node;
    }
    return sql_get_origin_ref((expr_node_t *)expr_node->value.v_vm_col.origin_ref);
}

status_t sql_exec_concat_lob_value(sql_stmt_t *stmt, const char *buf, uint32 size, vm_lob_t *vlob);
status_t sql_get_sequence_value(sql_stmt_t *stmt, var_seq_t *seq, variant_t *value);
status_t sql_create_rowid_expr(sql_stmt_t *stmt, uint32 tab, expr_tree_t **expr);

extern node_func_tab_t *g_expr_calc_funcs[];
static inline node_func_tab_t *sql_get_node_func(sql_node_type_t type)
{
    return &g_expr_calc_funcs[(type / EXPR_NODE_CONST)][(type % EXPR_NODE_CONST)];
}

static inline status_t sql_get_expr_node_value(sql_stmt_t *stmt, expr_node_t *node, variant_t *result)
{
    return sql_get_node_func((sql_node_type_t)node->type)->invoke(stmt, node, result);
}

static inline bool32 sql_pair_type_is_plvar(expr_node_t *node)
{
    CM_ASSERT(node->type == EXPR_NODE_V_ADDR);
    return (node->value.v_address.pairs->count == 1);
}

bool32 chk_has_sharding_tab(sql_stmt_t *stmt);
status_t sql_clone_text(void *ctx, text_t *src, text_t *dest, ga_alloc_func_t alloc_mem_func);
status_t sql_set_pl_dc_for_user_func(void *verify_in, expr_node_t *node, pointer_t pl_dc_in);
var_udo_t *sql_node_get_obj(expr_node_t *node);
status_t sql_task_get_nextdate(sql_stmt_t *stmt, expr_node_t *interval, variant_t *result);

/*
CAUTION!!!: don't change the value of cond_node_type
in column default value / check constraint, the id is stored in system table COLUMN$
*/
typedef enum en_cond_node_type {
    COND_NODE_UNKNOWN = 0, /* init status */
    COND_NODE_COMPARE = 1,
    COND_NODE_OR = 2,    /* logic OR  */
    COND_NODE_AND = 3,   /* logic AND */
    COND_NODE_NOT = 4,   /* logic NOT, it will be converted to COND_NODE_COMPARE in parsing phase */
    COND_NODE_TRUE = 5,  /* logic NOT, it will be converted to COND_NODE_COMPARE in parsing phase */
    COND_NODE_FALSE = 6, /* logic NOT, it will be converted to COND_NODE_COMPARE in parsing phase */
} cond_node_type_t;

typedef struct st_cmp_node {
    int32 join_type;
    cmp_type_t type;    /* = <>, >, <, like, in, is, is not, not like, not in, */
    expr_tree_t *left;  /* expr of left variant */
    expr_tree_t *right; /* expr of right variant */
    bool8 rnum_pending;
    bool8 has_conflict_chain;  // f1 = f2 and f1 = 10
    bool8 anti_join_cond;      // anti join cond can not eliminate outer join
    bool8 unused;
} cmp_node_t;

typedef struct st_join_symbol_cmp {
    cmp_node_t *cmp_node; /* t1.f1 = t3.f1(+) */
    uint32 right_tab;     /* t1 */
    uint32 left_tab;      /* t3 */
} join_symbol_cmp_t;

typedef struct st_cond_node {
    cond_node_type_t type;
    bool32 processed;
    struct st_cond_node *left;
    struct st_cond_node *right;
    cmp_node_t *cmp; /* only used for node type is COND_NODE_COMPARE */

    // don't change the definition order of prev and next
    // so cond_node_t can be change to biqueue_node_t by macro QUEUE_NODE_OF
    // and be added to a biqueue
    struct st_cond_node *prev;
    struct st_cond_node *next;
} cond_node_t;

#define CONSTRUCT_COND_TREE(cond_node, add_left, cond_ori_child, cond_new_child) \
    if (add_left) {                                                              \
        (cond_node)->left = (cond_new_child);                                    \
        (cond_node)->right = (cond_ori_child);                                   \
    } else {                                                                     \
        (cond_node)->left = (cond_ori_child);                                    \
        (cond_node)->right = (cond_new_child);                                   \
    }

typedef struct st_cond_chain {
    cond_node_t *first;
    cond_node_t *last;
    uint32 count;
} cond_chain_t;

typedef struct st_cond_tree {
    void *owner;
    ga_alloc_func_t alloc_func;
    cond_node_t *root;
    uint32 incl_flags;
    source_location_t loc;
    cond_chain_t chain;
    /* max_rownum records the upper rownum in the condition tree.
     * It can be used for ROWNUM optimization
     * The default value of max_rownum is infinity
     */
    uint32 rownum_upper;
    bool8 rownum_pending;
    bool8 unused[3];
    struct st_cond_tree *clone_src;
} cond_tree_t;

typedef struct st_join_cond {
    bilist_node_t bilist_node;
    uint32 table1;
    uint32 table2;
    galist_t cmp_nodes;

    // below for outer join
    bool8 is_new_add;
    sql_join_type_t join_type;
    cond_tree_t *filter;
    cond_tree_t *join_cond;
} join_cond_t;
/* * Evaluate an expression tree of a compare node */

#define SQL_EXEC_CMP_OPERAND(expr, var, res, pending, stmt)       \
    do {                                                          \
        if (sql_exec_expr((stmt), (expr), (var)) != GS_SUCCESS) { \
            return GS_ERROR;                                      \
        }                                                         \
        if ((var)->type == GS_TYPE_COLUMN) {                      \
            (*(res)) = COND_TRUE;                                 \
            (*(pending)) = GS_TRUE;                               \
            return GS_SUCCESS;                                    \
        }                                                         \
        if (GS_IS_LOB_TYPE((var)->type)) {                        \
            GS_RETURN_IFERR(sql_get_lob_value((stmt), (var)));    \
        }                                                         \
    } while (0)

/* * Evaluate an expression tree of a compare node, and filter NULL value.
 * * Additionally, the result variant is kept in stack for later using.  */
#define SQL_EXEC_CMP_OPERAND_EX(expr, var, res, pending, stmt)         \
    do {                                                               \
        SQL_EXEC_CMP_OPERAND((expr), (var), (res), (pending), (stmt)); \
        sql_keep_stack_variant((stmt), (var));                         \
    } while (0)

/* for dml cond check, unknown means false */
status_t sql_match_cond(void *arg, bool32 *result);
status_t sql_match_cond_node(sql_stmt_t *stmt, cond_node_t *node, bool32 *result);
status_t sql_match_cond_argument(sql_stmt_t *stmt, cond_node_t *node, bool32 *pending, cond_result_t *result);
status_t sql_match_cond_tree(void *stmt, void *node, cond_result_t *result);
status_t sql_split_filter_cond(sql_stmt_t *stmt, cond_node_t *src, cond_tree_t **dst_tree);
status_t sql_create_cond_tree(sql_context_t *context, cond_tree_t **cond);
status_t sql_merge_cond_tree(cond_tree_t *ori_cond, cond_node_t *from_node);
status_t sql_clone_cond_tree(void *ctx, cond_tree_t *src, cond_tree_t **dst, ga_alloc_func_t alloc_mem_func);
status_t sql_clone_cond_node(void *ctx, cond_node_t *src, cond_node_t **dst, ga_alloc_func_t alloc_mem_func);
status_t sql_clone_cmp_node(void *ctx, cmp_node_t *src, cmp_node_t **dst, ga_alloc_func_t alloc_mem_func);
status_t sql_add_cond_node_left(cond_tree_t *ori_cond, cond_node_t *node);
status_t sql_add_cond_node(cond_tree_t *ori_cond, cond_node_t *node);
status_t sql_add_cond_node_core(cond_tree_t *ori_cond, cond_node_t *node, bool8 add_left);
status_t sql_get_cond_node_pos(cond_node_t *root_cond, cmp_node_t *cmp, cond_node_t **node_pos);
bool32 sql_cond_node_in_tab_list(sql_array_t *tables, cond_node_t *cond_node, bool32 use_remote_id, bool32 *exist_col);
bool32 sql_cond_node_exist_table(cond_node_t *cond_node, uint32 table_id);
bool32 sql_cond_node_has_prior(cond_node_t *cond_node);
status_t sql_extract_join_from_cond(cond_node_t *cond_node, uint32 table1, uint32 table2, galist_t *join_nodes,
                                    bool32 *has_join_cond);
status_t sql_cond_tree_walker(sql_stmt_t *stmt, cond_tree_t *cond_tree,
                              status_t (*fetch)(sql_stmt_t *stmt, expr_node_t *node, void *context), void *context);
void sql_convert_match_result(cmp_type_t cmp_type, int32 cmp_result, bool32 *result);
status_t sql_exec_expr_list(sql_stmt_t *stmt, expr_tree_t *list, uint32 count, variant_t *vars, bool32 *pending,
                            expr_tree_t **last);
status_t try_eval_compare_node(sql_stmt_t *stmt, cond_node_t *node, uint32 *rnum_upper, bool8 *rnum_pending);
void try_eval_logic_and(cond_node_t *node);
void try_eval_logic_or(cond_node_t *node);

extern status_t rbo_try_rownum_optmz(sql_stmt_t *stmt, cond_node_t *node, uint32 *max_rownum, bool8 *rnum_pending);

status_t sql_split_cond(sql_stmt_t *stmt, sql_array_t *tables, cond_tree_t **cond_tree_result, cond_tree_t *cond_tree,
                        bool32 use_remote_id);
status_t sql_rebuild_cond(sql_stmt_t *stmt, cond_tree_t **cond_tree_result, cond_tree_t *cond_tree, bool32 *ignore);
status_t sql_extract_filter_cond(sql_stmt_t *stmt, sql_array_t *tables, cond_tree_t **dst_tree, cond_node_t *cond_node);
bool32 sql_chk_cond_degrade_join(cond_node_t *cond, sql_join_node_t *join_node, bool32 is_right_node,
                                 bool32 is_outer_right, bool32 *not_null);
status_t sql_adjust_inner_join_cond(sql_stmt_t *stmt, sql_join_node_t *join_node, cond_tree_t **cond_tree);
status_t sql_merge_cond_tree_shallow(cond_tree_t *ori_cond, cond_node_t *from_node);
status_t sql_union_cond_node(sql_context_t *context, cond_tree_t **dst, cond_node_t *from_node);
bool32 sql_cond_node_equal(sql_stmt_t *stmt, cond_node_t *cond1, cond_node_t *cond2, uint32 *tab_map);
bool32 sql_cmp_node_equal(sql_stmt_t *stmt, cmp_node_t *cmp1, cmp_node_t *cmp2, uint32 *tab_map);
void sql_set_exists_query_flag(sql_stmt_t *stmt, select_node_t *select_node);
status_t sql_match_pivot_list(sql_stmt_t *stmt, expr_tree_t *for_expr, expr_tree_t *in_expr, int32 *index);
status_t visit_cond_node(visit_assist_t *va, cond_node_t *cond, visit_func_t visit_func);
bool32 sql_cond_has_acstor_col(sql_stmt_t *stmt, cond_tree_t *cond, sql_query_t *subqry);
status_t visit_join_node_cond(visit_assist_t *va, sql_join_node_t *join_node, visit_func_t visit_func);
bool32 sql_is_join_node(cond_node_t *cond_node, uint32 table1, uint32 table2);
status_t sql_exec_escape_character(expr_tree_t *expr, variant_t *var, char *escape);
status_t sql_try_simplify_new_cond(sql_stmt_t *stmt, cond_node_t *cond);

static inline void sql_init_cond_tree(void *owner, cond_tree_t *cond, ga_alloc_func_t alloc_func)
{
    CM_POINTER2(owner, cond);
    MEMS_RETVOID_IFERR(memset_s(cond, sizeof(cond_tree_t), 0, sizeof(cond_tree_t)));
    cond->owner = owner;
    cond->alloc_func = alloc_func;
    cond->rownum_upper = GS_INFINITE32;
    cond->rownum_pending = GS_FALSE;
}

#define SQL_EXCL_NONE 0x00000000
#define SQL_EXCL_AGGR 0x00000001
#define SQL_EXCL_COLUMN 0x00000002
#define SQL_EXCL_STAR 0x00000004
#define SQL_EXCL_SEQUENCE 0x00000008
#define SQL_EXCL_SUBSELECT 0x00000010
#define SQL_EXCL_JOIN 0x00000020
#define SQL_EXCL_ROWNUM 0x00000040
#define SQL_EXCL_ROWID 0x00000080
#define SQL_EXCL_DEFAULT 0x00000100
#define SQL_EXCL_PRIOR 0x00000200
#define SQL_EXCL_LOB_COL 0x00000400
#define SQL_EXCL_BIND_PARAM 0x00000800
#define SQL_EXCL_CASE 0x00001000
#define SQL_EXCL_ROOT 0x00002000
#define SQL_EXCL_WIN_SORT 0x00004000
#define SQL_EXCL_ROWSCN 0x00008000
#define SQL_EXCL_PARENT 0x00010000
#define SQL_EXCL_UNNEST 0x00020000
#define SQL_EXCL_ARRAY 0x00040000
#define SQL_EXCL_GROUPING 0x00080000
#define SQL_EXCL_COLL 0x00100000
#define SQL_EXCL_PATH_FUNC 0x00200000
#define SQL_EXCL_ROWNODEID 0x00400000
#define SQL_EXCL_METH_PROC 0x00800000
#define SQL_EXCL_METH_FUNC 0x01000000
#define SQL_EXCL_CONNECTBY_ATTR 0x02000000
#define SQL_EXCL_LEVEL 0x04000000
#define SQL_EXCL_PL_PROC 0x08000000
#define ROWNODEID_LENGTH 18 /* rownodeid for outer users is a string with a fixed length ROWNODEID_LENGTH. */

#define SQL_WHERE_EXCL                                                                                          \
    (SQL_EXCL_AGGR | SQL_EXCL_SEQUENCE | SQL_EXCL_STAR | SQL_EXCL_PRIOR | SQL_EXCL_WIN_SORT | SQL_EXCL_UNNEST | \
     SQL_EXCL_GROUPING | SQL_EXCL_PATH_FUNC)

#define SQL_HAVING_EXCL                                                                                          \
    (SQL_EXCL_JOIN | SQL_EXCL_STAR | SQL_EXCL_SEQUENCE | SQL_EXCL_PRIOR | SQL_EXCL_LOB_COL | SQL_EXCL_WIN_SORT | \
     SQL_EXCL_UNNEST | SQL_EXCL_ARRAY | SQL_EXCL_PATH_FUNC)

#define SQL_CONNECT_BY_EXCL                                                                                     \
    (SQL_EXCL_AGGR | SQL_EXCL_SEQUENCE | SQL_EXCL_STAR | SQL_EXCL_LOB_COL | SQL_EXCL_ROOT | SQL_EXCL_WIN_SORT | \
     SQL_EXCL_JOIN | SQL_EXCL_UNNEST | SQL_EXCL_ARRAY | SQL_EXCL_GROUPING | SQL_EXCL_PATH_FUNC |                \
     SQL_EXCL_CONNECTBY_ATTR)

#define SQL_START_WITH_EXCL                                                                                          \
    (SQL_EXCL_AGGR | SQL_EXCL_SEQUENCE | SQL_EXCL_STAR | SQL_EXCL_PRIOR | SQL_EXCL_LOB_COL | SQL_EXCL_ROOT |         \
     SQL_EXCL_JOIN | SQL_EXCL_WIN_SORT | SQL_EXCL_UNNEST | SQL_EXCL_ARRAY | SQL_EXCL_GROUPING | SQL_EXCL_PATH_FUNC | \
     SQL_EXCL_CONNECTBY_ATTR)

#define SQL_ORDER_EXCL \
    (SQL_EXCL_STAR | SQL_EXCL_SEQUENCE | SQL_EXCL_JOIN | SQL_EXCL_UNNEST | SQL_EXCL_ARRAY | SQL_EXCL_WIN_SORT)

#define SQL_GROUP_BY_EXCL                                                                                            \
    (SQL_EXCL_STAR | SQL_EXCL_SEQUENCE | SQL_EXCL_SUBSELECT | SQL_EXCL_LOB_COL | SQL_EXCL_AGGR | SQL_EXCL_WIN_SORT | \
     SQL_EXCL_UNNEST | SQL_EXCL_ARRAY | SQL_EXCL_GROUPING | SQL_EXCL_PATH_FUNC)

#define SQL_FOR_UPDATE_EXCL (SQL_EXCL_STAR | SQL_EXCL_SEQUENCE | SQL_EXCL_JOIN)

#define SQL_PRIOR_EXCL                                                                          \
    (SQL_EXCL_AGGR | SQL_EXCL_WIN_SORT | SQL_EXCL_SEQUENCE | SQL_EXCL_ROWNUM | SQL_EXCL_PRIOR | \
     SQL_EXCL_CONNECTBY_ATTR | SQL_EXCL_LEVEL)

#define SQL_MERGE_EXCL                                                                                        \
    (SQL_EXCL_AGGR | SQL_EXCL_SEQUENCE | SQL_EXCL_STAR | SQL_EXCL_PRIOR | SQL_EXCL_ROWNUM | SQL_EXCL_ROWSCN | \
     SQL_EXCL_JOIN | SQL_EXCL_GROUPING | SQL_EXCL_WIN_SORT | SQL_EXCL_PATH_FUNC | SQL_EXCL_ROWNODEID)

#define SQL_DEFAULT_EXCL                                                                                      \
    (SQL_EXCL_AGGR | SQL_EXCL_COLUMN | SQL_EXCL_STAR | SQL_EXCL_SUBSELECT | SQL_EXCL_JOIN | SQL_EXCL_ROWNUM | \
     SQL_EXCL_ROWID | SQL_EXCL_DEFAULT | SQL_EXCL_ROWSCN | SQL_EXCL_LOB_COL | SQL_EXCL_BIND_PARAM |           \
     SQL_EXCL_WIN_SORT | SQL_EXCL_ROWSCN | SQL_EXCL_ARRAY | SQL_EXCL_WIN_SORT | SQL_EXCL_GROUPING |           \
     SQL_EXCL_PATH_FUNC | SQL_EXCL_ROWNODEID)

#define SQL_LIMIT_EXCL                                                                                                 \
    (SQL_EXCL_AGGR | SQL_EXCL_COLUMN | SQL_EXCL_STAR | SQL_EXCL_SUBSELECT | SQL_EXCL_JOIN | SQL_EXCL_ROWNUM |          \
     SQL_EXCL_ROWID | SQL_EXCL_DEFAULT | SQL_EXCL_ROWSCN | SQL_EXCL_WIN_SORT | SQL_EXCL_GROUPING | SQL_EXCL_SEQUENCE | \
     SQL_EXCL_PATH_FUNC | SQL_EXCL_ROWNODEID)

#define SQL_CHECK_EXCL                                                                                           \
    (SQL_EXCL_AGGR | SQL_EXCL_STAR | SQL_EXCL_PRIOR | SQL_EXCL_SUBSELECT | SQL_EXCL_JOIN | SQL_EXCL_BIND_PARAM | \
     SQL_EXCL_ROWNUM | SQL_EXCL_ROWID | SQL_EXCL_LOB_COL | SQL_EXCL_SEQUENCE | SQL_EXCL_CASE | SQL_EXCL_ROWSCN | \
     SQL_EXCL_WIN_SORT | SQL_EXCL_ROWNODEID)

#define SQL_AGGR_EXCL (SQL_EXCL_AGGR | SQL_EXCL_WIN_SORT | SQL_EXCL_GROUPING | SQL_EXCL_SEQUENCE)

#define SQL_JSON_TABLE_EXCL                                                                                       \
    (SQL_EXCL_AGGR | SQL_EXCL_STAR | SQL_EXCL_SEQUENCE | SQL_EXCL_WIN_SORT | SQL_EXCL_PATH_FUNC | SQL_EXCL_JOIN | \
     SQL_EXCL_PRIOR | SQL_EXCL_ROWNUM | SQL_EXCL_ROWSCN | SQL_EXCL_ROOT | SQL_EXCL_DEFAULT | SQL_EXCL_LEVEL |     \
     SQL_EXCL_CONNECTBY_ATTR | SQL_EXCL_METH_PROC | SQL_EXCL_METH_FUNC | SQL_EXCL_GROUPING | SQL_EXCL_COLL |      \
     SQL_EXCL_ARRAY | SQL_EXCL_PL_PROC)

#define SQL_NON_NUMERIC_FLAGS                                                                                        \
    (SQL_EXCL_AGGR | SQL_EXCL_COLUMN | SQL_EXCL_STAR | SQL_EXCL_SEQUENCE | SQL_EXCL_SUBSELECT | SQL_EXCL_JOIN |      \
     SQL_EXCL_ROWNUM | SQL_EXCL_ROWID | SQL_EXCL_DEFAULT | SQL_EXCL_PRIOR | SQL_EXCL_LOB_COL | SQL_EXCL_BIND_PARAM | \
     SQL_EXCL_CASE | SQL_EXCL_ROWSCN | SQL_EXCL_GROUPING | SQL_EXCL_ROWNODEID)

#define PL_EXPR_EXCL                                                                                       \
    (SQL_EXCL_AGGR | SQL_EXCL_STAR | SQL_EXCL_JOIN | SQL_EXCL_ROWNUM | SQL_EXCL_ROWID | SQL_EXCL_DEFAULT | \
     SQL_EXCL_SUBSELECT | SQL_EXCL_COLUMN | SQL_EXCL_ROWSCN | SQL_EXCL_ROWNODEID | SQL_EXCL_METH_PROC |    \
     SQL_EXCL_PL_PROC)

#define PL_UDT_EXCL                                                                                                   \
    (SQL_EXCL_AGGR | SQL_EXCL_STAR | SQL_EXCL_JOIN | SQL_EXCL_ROWNUM | SQL_EXCL_ROWID | SQL_EXCL_DEFAULT |            \
     SQL_EXCL_SUBSELECT | SQL_EXCL_COLUMN | SQL_EXCL_ROWSCN | SQL_EXCL_ROWNODEID | SQL_EXCL_METH_PROC |               \
     SQL_EXCL_WIN_SORT | SQL_EXCL_PRIOR | SQL_EXCL_GROUPING | SQL_EXCL_PATH_FUNC | SQL_EXCL_LEVEL | SQL_EXCL_PARENT | \
     SQL_EXCL_CONNECTBY_ATTR | SQL_EXCL_LOB_COL | SQL_EXCL_ROOT | SQL_EXCL_PL_PROC)

#define SQL_INCL_AGGR 0x00000001
#define SQL_INCL_ROWNUM 0x00000002
#define SQL_INCL_JOIN 0x00000004
#define SQL_INCL_ROWID 0x00000008
#define SQL_INCL_PRNT_OR_ANCSTR 0x00000010
#define SQL_INCL_SUBSLCT 0x00000020
#define SQL_INCL_COND_COL 0x00000040
#define SQL_INCL_GROUPING 0x00000080
#define SQL_INCL_WINSORT 0x00000100
#define SQL_INCL_ARRAY 0x00000200
#define SQL_INCL_CONNECTBY_ATTR 0x00000400
#define SQL_INCL_JSON_TABLE 0x00000800

#define SQL_COND_UNABLE_INCL \
    (SQL_INCL_ROWNUM | SQL_INCL_AGGR | SQL_INCL_WINSORT | SQL_INCL_SUBSLCT | SQL_INCL_GROUPING | SQL_INCL_ARRAY)

#define SQL_DEFAULT_COLUMN_WIDTH 20

#define SQL_GEN_AGGR_FROM_COLUMN 0x00000001
#define SQL_GEN_AGGR_FROM_HAVING 0x00000002
#define SQL_GEN_AGGR_FROM_ORDER 0x00000004

#define SQL_MERGE_INSERT_NONE 0
#define SQL_MERGE_INSERT_COLUMNS 1
#define SQL_MERGE_INSERT_VALUES 2
#define SQL_MERGE_INSERT_COND 3

#define EXPR_INCL_ROWNUM 0x0001
#define COND_INCL_ROWNUM 0x0002
#define RS_INCL_PRNT_OR_ANCSTR 0x0004
#define RS_INCL_SUBSLCT 0x0008
#define RS_INCL_GROUPING 0x0010
#define RS_INCL_ARRAY 0x0020
#define EXPR_INCL_ROWNODEID 0x0040
#define COND_INCL_ROWNODEID 0x0080

#define SQL_POLICY_FUNC_STR_LEN (uint32)(GS_MAX_NAME_LEN * 4 + 8)
#define ROWNUM_COND_OCCUR(cond) ((cond) != NULL && ((cond)->incl_flags & SQL_INCL_ROWNUM))
#define RS_ARRAY_OCCUR(query) ((query)->incl_flags & RS_INCL_ARRAY)
#define QUERY_HAS_ROWNUM(query) ((query)->incl_flags & (EXPR_INCL_ROWNUM | COND_INCL_ROWNUM))
#define QUERY_HAS_ROWNODEID(query) ((query)->incl_flags & (EXPR_INCL_ROWNODEID | COND_INCL_ROWNODEID))
#define IS_COND_FALSE(cond) ((cond) != NULL && (cond)->root->type == COND_NODE_FALSE)
#define IS_ANALYZED_TABLE(table) (((table)->entry != NULL) && ((dc_entity_t *)(table)->entry->dc.handle)->stat_exists)

typedef struct st_sql_verifier sql_verifier_t;

typedef status_t (*verifier_func)(sql_verifier_t *, expr_node_t *);

struct st_sql_verifier {
    sql_stmt_t *stmt;
    sql_context_t *context;
    sql_select_t *select_ctx;
    galist_t *pl_dc_lst;
    void *line;
    struct {
        bool32 has_union : 1;
        bool32 has_minus : 1;
        bool32 for_update : 1;
        bool32 is_proc : 1;
        bool32 has_acstor_col : 1;
        bool32 has_excl_const : 1;
        bool32 do_expr_optmz : 1;
        bool32 verify_tables : 1;  // for global view
        bool32 is_check_cons : 1;
        bool32 has_except_intersect : 1;
        bool32 same_join_tab : 1;
        bool32 has_ddm_col : 1;
        bool32 from_table_define : 1;
        bool32 unused : 19;
    };

    uint32 aggr_flags;  // insert aggr into query columns list flags
    uint32 excl_flags;  // exclusive flags
    uint32 incl_flags;  // included  flags

    // for expr join node, t1.f1 = t2.f1(+)
    uint32 join_tab_id;

    galist_t *join_symbol_cmps;

    // for merge
    galist_t *merge_update_pairs;
    uint32 merge_insert_status;

    // for select
    sql_array_t *tables;
    galist_t *aggrs;
    galist_t *cntdis_columns;
    sql_query_t *curr_query;  // for only index scan

    // for nonselect
    sql_table_t *table;
    knl_column_def_t *column;
    knl_table_def_t *table_def;

    struct st_sql_verifier *parent;
    var_udo_t *obj;      // the verifier in package object
    typmode_t *typmode;  // for modify columns in function index
    knl_handle_t dc_entity;
};

typedef struct st_hint_conflict_t {
    union {
        opt_param_bool_t bool_conflict;
        uint64 opt_param_bool;
    };
    bool32 scale_rows : 1;
    bool32 rows : 1;
    bool32 min_rows : 1;
    bool32 max_rows : 1;
    bool32 ordered : 1;
    bool32 dynamic_sampling : 1;
    bool32 reserved2 : 26;
} sql_hint_conflict_t;

typedef struct st_sql_hint_verifier {
    sql_stmt_t *stmt;
    sql_array_t *tables;  // for select/update/delete
    sql_table_t *table;   // for insert
    sql_hint_conflict_t conflicts;
} sql_hint_verifier_t;

hint_id_t get_hint_id_4_index(index_hint_key_wid_t access_hint);
bool32 index_intercepted_in_hints(sql_table_t *table, uint32 index_id);
bool32 index_specified_in_hint(sql_table_t *t, hint_id_t hint_id, uint32 idx_id);
bool32 if_index_in_hint(sql_table_t *t, hint_id_t hint_id, uint32 idx_id);

void set_ddm_attr(sql_verifier_t *verf, var_column_t *v_col, knl_column_t *knl_col);

void sql_add_first_exec_node(sql_verifier_t *verf, expr_node_t *node);

void sql_infer_func_optmz_mode(sql_verifier_t *verf, expr_node_t *func);
void sql_infer_oper_optmz_mode(sql_verifier_t *verf, expr_node_t *node);
void sql_infer_unary_oper_optmz_mode(sql_verifier_t *verf, expr_node_t *node);

status_t sql_verify(sql_stmt_t *stmt);
status_t sql_verify_expr_node(sql_verifier_t *verf, expr_node_t *node);
status_t sql_verify_current_expr(sql_verifier_t *verf, expr_tree_t *verf_expr);
status_t sql_verify_expr(sql_verifier_t *verf, expr_tree_t *expr);
status_t sql_verify_cond(sql_verifier_t *verf, cond_tree_t *cond);
status_t sql_verify_select(sql_stmt_t *stmt, sql_select_t *select_ctx);
status_t sql_verify_sub_select(sql_stmt_t *stmt, sql_select_t *select_ctx, sql_verifier_t *parent);
status_t sql_verify_select_context(sql_verifier_t *verf, sql_select_t *select_ctx);
status_t sql_verify_query_order(sql_verifier_t *verf, sql_query_t *query, galist_t *sort_items, bool32 is_query);
status_t sql_verify_query_distinct(sql_verifier_t *verf, sql_query_t *query);
status_t sql_verify_query_pivot(sql_verifier_t *verf, sql_query_t *query);
status_t sql_match_distinct_expr(sql_stmt_t *stmt, sql_query_t *query, expr_tree_t **expr, bool32 need_clone);
status_t sql_verify_group_concat_order(sql_verifier_t *verf, expr_node_t *func, galist_t *sort_items);
status_t sql_verify_listagg_order(sql_verifier_t *verf, galist_t *sort_items);

void sql_init_aggr_node(expr_node_t *aggr_node, uint32 fun_id, uint32 ofun_id);
status_t sql_adjust_oper_node(sql_verifier_t *verf, expr_node_t *node);
status_t sql_table_cache_query_field(sql_stmt_t *stmt, sql_table_t *table, query_field_t *src_query_field);
status_t sql_table_cache_cond_query_field(sql_stmt_t *stmt, sql_table_t *table, query_field_t *src_query_field);
status_t sql_add_parent_refs(sql_stmt_t *stmt, galist_t *parent_refs, uint32 tab, expr_node_t *node);
void sql_del_parent_refs(galist_t *parent_refs, uint32 tab, expr_node_t *node);
status_t sql_init_table_dc(sql_stmt_t *stmt, sql_table_t *sql_table);
status_t sql_verify_expr_array_attr(expr_node_t *node, expr_tree_t *expr);
void sql_init_udo(var_udo_t *obj);
void sql_init_udo_with_str(var_udo_t *obj, char *user, char *pack, char *name);
void sql_init_udo_with_text(var_udo_t *obj, text_t *user, text_t *pack, text_t *name);
uint32 sql_get_any_priv_id(sql_stmt_t *stmt);
void sql_check_user_priv(sql_stmt_t *stmt, text_t *obj_user);
void sql_join_set_default_oper(sql_join_node_t *join_node);
status_t sql_gen_winsort_rs_columns(sql_stmt_t *stmt, sql_query_t *query);
bool32 sql_check_user_exists(knl_handle_t session, text_t *name);
status_t sql_match_group_expr(sql_stmt_t *stmt, sql_query_t *query, expr_tree_t *expr);
bool32 sql_check_reserved_is_const(expr_node_t *node);

status_t sql_gen_winsort_rs_col_by_expr(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *node);
status_t sql_gen_winsort_rs_col_by_expr_tree(sql_stmt_t *stmt, sql_query_t *query, expr_tree_t *expr);
void set_winsort_rs_node_flag(sql_query_t *query);
bool32 if_unqiue_idx_in_list(sql_query_t *query, sql_table_t *table, galist_t *list);
bool32 if_query_distinct_can_eliminate(sql_verifier_t *verf, sql_query_t *query);
status_t sql_add_sequence_node(sql_stmt_t *stmt, expr_node_t *node);
status_t sql_static_check_dml_pair(sql_verifier_t *verf, const column_value_pair_t *pair);
status_t sql_verify_table_dml_object(knl_handle_t session, sql_stmt_t *stmt, source_location_t loc, knl_dictionary_t dc,
                                     bool32 is_delete);
bool32 is_array_subscript_correct(int32 start, int32 end);
status_t sql_gen_group_rs_col_by_subselect(sql_stmt_t *stmt, galist_t *columns, expr_node_t *node);
status_t sql_gen_group_rs_by_expr(sql_stmt_t *stmt, galist_t *columns, expr_node_t *node);
status_t sql_add_ref_func_node(sql_verifier_t *verf, expr_node_t *node);
void sql_set_ancestor_level(sql_select_t *select_ctx, uint32 temp_level);
status_t sql_create_project_columns(sql_stmt_t *stmt, sql_table_t *table);
status_t sql_verify_func(sql_verifier_t *verf, expr_node_t *node);
status_t sql_try_verify_noarg_func(sql_verifier_t *verf, expr_node_t *node, bool32 *is_found);

bool32 sql_check_has_single_column(sql_verifier_t *verf, expr_node_t *node);

bool32 sql_check_table_column_exists(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *node);

status_t sql_try_verify_dbmsconst(sql_verifier_t *verf, expr_node_t *node, bool32 *result);
status_t sql_try_verify_sequence(sql_verifier_t *verf, expr_node_t *node, bool32 *result);
status_t sql_try_verify_rowid(sql_verifier_t *verf, expr_node_t *node, bool32 *result);
status_t sql_try_verify_rowscn(sql_verifier_t *verf, expr_node_t *node, bool32 *result);
status_t sql_try_verify_rownodeid(sql_verifier_t *verf, expr_node_t *node, bool32 *result);
status_t sql_verify_pl_var(sql_verifier_t *verf, plv_id_t vid, expr_node_t *node);
gs_type_t sql_get_case_expr_compatible_datatype(gs_type_t case_datatype, gs_type_t expr_datatype);
status_t sql_verify_column_expr(sql_verifier_t *verf, expr_node_t *node);
status_t sql_verify_return_columns(sql_verifier_t *verf, galist_t *ret_columns);
status_t sql_verify_query_columns(sql_verifier_t *verf, sql_query_t *query);

status_t sql_verify_query_joins(sql_verifier_t *verf, sql_query_t *query);
status_t sql_verify_query_unpivot(sql_verifier_t *verf, sql_query_t *query);
status_t sql_normalize_group_sets(sql_stmt_t *stmt, sql_query_t *query);
status_t sql_verify_query_group(sql_verifier_t *verf, sql_query_t *query);
status_t sql_verify_query_having(sql_verifier_t *verf, sql_query_t *query);
status_t sql_verify_query_where(sql_verifier_t *verf, sql_query_t *query);
status_t sql_verify_query_connect(sql_verifier_t *verf, sql_query_t *query);
status_t sql_verify_query_limit(sql_verifier_t *verf, sql_query_t *query);
status_t sql_get_table_policies(sql_verifier_t *verf, sql_table_t *table, text_t *clause_text, bool32 *exists);
status_t sql_verify_tables(sql_verifier_t *verf, sql_query_t *query);
status_t sql_search_table(sql_verifier_t *verf, expr_node_t *node, text_t *user, text_t *alias, sql_table_t **table,
                          uint32 *level);
bool32 sql_search_table_name(sql_table_t *query_table, text_t *user, text_t *alias);
status_t sql_search_table_local(sql_verifier_t *verf, expr_node_t *node, text_t *user, text_t *alias,
                                sql_table_t **table, bool32 *is_found);
status_t sql_search_table_parent(sql_verifier_t *verf, expr_node_t *node, text_t *user, text_t *alias,
                                 sql_table_t **table, uint32 *level, bool32 *is_found);
status_t sql_init_normal_table_dc(sql_stmt_t *stmt, sql_table_t *sql_table, sql_query_t *parent_query);
status_t sql_create_project_columns(sql_stmt_t *stmt, sql_table_t *table);
status_t sql_append_reference_knl_dc(galist_t *dest, knl_dictionary_t *dc);
status_t sql_apend_dependency_table(sql_stmt_t *stmt, sql_table_t *sql_table);

typedef enum en_sql_aggr_type {
    AGGR_TYPE_NONE = 0,
    AGGR_TYPE_AVG = 1,
    AGGR_TYPE_SUM = 2,
    AGGR_TYPE_MIN = 3,
    AGGR_TYPE_MAX = 4,
    AGGR_TYPE_COUNT = 5,
    AGGR_TYPE_AVG_COLLECT = 6,  // Z-Sharding
    AGGR_TYPE_GROUP_CONCAT = 7,
    AGGR_TYPE_STDDEV = 8,
    AGGR_TYPE_STDDEV_POP = 9,
    AGGR_TYPE_STDDEV_SAMP = 10,
    AGGR_TYPE_LAG = 11,
    AGGR_TYPE_ARRAY_AGG = 12,
    AGGR_TYPE_NTILE = 13,
    // ///////////////////aggr_type count//////////////
    AGGR_TYPE_MEDIAN,
    AGGR_TYPE_CUME_DIST,
    AGGR_TYPE_VARIANCE,
    AGGR_TYPE_VAR_POP,
    AGGR_TYPE_VAR_SAMP,
    AGGR_TYPE_COVAR_POP,
    AGGR_TYPE_COVAR_SAMP,
    AGGR_TYPE_CORR,
    AGGR_TYPE_DENSE_RANK,
    AGGR_TYPE_FIRST_VALUE,
    AGGR_TYPE_LAST_VALUE,
    AGGR_TYPE_RANK,
    AGGR_TYPE_APPX_CNTDIS
} sql_aggr_type_t;

#define SQL_MIN_HEX_STR_LEN 2
#define SQL_GROUP_CONCAT_STR_LEN 1024
#define SQL_USERENV_VALUE_DEFAULT_LEN 256
#define SQL_VERSION_VALUE_DEFAULT_LEN 50
#define SQL_ASCII_COUNT 256
#define UTF8_MAX_BYTE 6

typedef enum en_bit_operation {
    BIT_OPER_AND = 1,
    BIT_OPER_OR = 2,
    BIT_OPER_XOR = 3,
} bit_operation_t;

/* **NOTE:**
 * 1. The function item id should be the same order as function name.
 * 2. The function item id is equal to function id.
 */
typedef enum en_function_item_id {
    ID_FUNC_ITEM_ABS = 0,
    ID_FUNC_ITEM_ACOS,
    ID_FUNC_ITEM_ADD_MONTHS,
    ID_FUNC_ITEM_APPX_CNTDIS,
    ID_FUNC_ITEM_ARRAY_AGG,
    ID_FUNC_ITEM_ARRAY_LENGTH,
    ID_FUNC_ITEM_ASCII,
    ID_FUNC_ITEM_ASCIISTR,
    ID_FUNC_ITEM_ASIN,
    ID_FUNC_ITEM_ATAN,
    ID_FUNC_ITEM_ATAN2,
    ID_FUNC_ITEM_AVG,
    ID_FUNC_ITEM_AVG_COLLECT,
    ID_FUNC_ITEM_BIN2HEX,
    ID_FUNC_ITEM_BITAND,
    ID_FUNC_ITEM_BITOR,
    ID_FUNC_ITEM_BITXOR,
    ID_FUNC_ITEM_CAST,
    ID_FUNC_ITEM_CEIL,
    ID_FUNC_ITEM_CHAR,
    ID_FUNC_ITEM_CHAR_LENGTH,
    ID_FUNC_ITEM_CHR,
    ID_FUNC_ITEM_COALESCE,
    ID_FUNC_ITEM_CONCAT,
    ID_FUNC_ITEM_CONCAT_WS,
    ID_FUNC_ITEM_CONNECTION_ID,
    ID_FUNC_ITEM_CONVERT,
    ID_FUNC_ITEM_CORR,
    ID_FUNC_ITEM_COS,
    ID_FUNC_ITEM_COUNT,
    ID_FUNC_ITEM_COVAR_POP,
    ID_FUNC_ITEM_COVAR_SAMP,
    ID_FUNC_ITEM_CUME_DIST,
    ID_FUNC_ITEM_CURRENT_TIMESTAMP,
    ID_FUNC_ITEM_DBA_CLN_DDL,
    ID_FUNC_ITEM_DBA_EXEC_DDL,
    ID_FUNC_ITEM_DECODE,
    ID_FUNC_ITEM_DENSE_RANK,
    ID_FUNC_ITEM_EMPTY_BLOB,
    ID_FUNC_ITEM_EMPTY_CLOB,
    ID_FUNC_ITEM_EXP,
    ID_FUNC_ITEM_EXTRACT,
    ID_FUNC_ITEM_FIND_IN_SET,
    ID_FUNC_ITEM_FLOOR,
    ID_FUNC_ITEM_FOUND_ROWS,
    ID_FUNC_ITEM_FROM_TZ,
    ID_FUNC_ITEM_FROM_UNIXTIME,
    ID_FUNC_ITEM_GETUTCDATE,
    ID_FUNC_ITEM_GET_LOCK,
    ID_FUNC_ITEM_GET_SHARED_LOCK,
    ID_FUNC_ITEM_GET_XACT_LOCK,
    ID_FUNC_ITEM_GET_XACT_SHARED_LOCK,
    ID_FUNC_ITEM_GREATEST,
    ID_FUNC_ITEM_GROUPING,
    ID_FUNC_ITEM_GROUPING_ID,
    ID_FUNC_ITEM_GROUP_CONCAT,
    ID_FUNC_ITEM_GSCN2DATE,
    ID_FUNC_ITEM_GS_HASH,
    ID_FUNC_ITEM_HASH,
    ID_FUNC_ITEM_HEX,
    ID_FUNC_ITEM_HEX2BIN,
    ID_FUNC_ITEM_HEXTORAW,
    ID_FUNC_ITEM_IF,
    ID_FUNC_ITEM_IFNULL,
    ID_FUNC_ITEM_INET_ATON,
    ID_FUNC_ITEM_INET_NTOA,
    ID_FUNC_ITEM_INSERT,
    ID_FUNC_ITEM_INSTR,
    ID_FUNC_ITEM_INSTRB,
    ID_FUNC_ITEM_ISNUMERIC,
    ID_FUNC_ITEM_JSONB_ARRAY_LENGTH,
    ID_FUNC_ITEM_JSONB_EXISTS,
    ID_FUNC_ITEM_JSONB_MERGEPATCH,
    ID_FUNC_ITEM_JSONB_QUERY,
    ID_FUNC_ITEM_JSONB_SET,
    ID_FUNC_ITEM_JSONB_VALUE,
    ID_FUNC_ITEM_JSON_ARRAY,
    ID_FUNC_ITEM_JSON_ARRAY_LENGTH,
    ID_FUNC_ITEM_JSON_EXISTS,
    ID_FUNC_ITEM_JSON_MERGEPATCH,
    ID_FUNC_ITEM_JSON_OBJECT,
    ID_FUNC_ITEM_JSON_QUERY,
    ID_FUNC_ITEM_JSON_SET,
    ID_FUNC_ITEM_JSON_VALUE,
    ID_FUNC_ITEM_LAST_DAY,
    ID_FUNC_ITEM_LAST_INSERT_ID,
    ID_FUNC_ITEM_LEAST,
    ID_FUNC_ITEM_LEFT,
    ID_FUNC_ITEM_LENGTH,
    ID_FUNC_ITEM_LENGTHB,
    ID_FUNC_ITEM_LISTAGG,
    ID_FUNC_ITEM_LN,
    ID_FUNC_ITEM_LNNVL,
    ID_FUNC_ITEM_LOCALTIMESTAMP,
    ID_FUNC_ITEM_LOCATE,
    ID_FUNC_ITEM_LOG,
    ID_FUNC_ITEM_LOWER,
    ID_FUNC_ITEM_LPAD,
    ID_FUNC_ITEM_LTRIM,
    ID_FUNC_ITEM_MAX,
    ID_FUNC_ITEM_MD5,
    ID_FUNC_ITEM_MEDIAN,
    ID_FUNC_ITEM_MIN,
    ID_FUNC_ITEM_MOD,
    ID_FUNC_ITEM_MONTHS_BETWEEN,
    ID_FUNC_ITEM_NEXT_DAY,
    ID_FUNC_ITEM_NOW,
    ID_FUNC_ITEM_NULLIF,
    ID_FUNC_ITEM_NUMTODSINTERVAL,
    ID_FUNC_ITEM_NUMTOYMINTERVAL,
    ID_FUNC_ITEM_NVL,
    ID_FUNC_ITEM_NVL2,
    ID_FUNC_ITEM_OBJECT_ID,
    ID_FUNC_ITEM_PAGE_MASTERID,
    ID_FUNC_ITEM_PI,
    ID_FUNC_ITEM_POWER,
    ID_FUNC_ITEM_RADIANS,
    ID_FUNC_ITEM_RAND,
    ID_FUNC_ITEM_RANK,
    ID_FUNC_ITEM_RAWTOHEX,
    ID_FUNC_ITEM_REGEXP_COUNT,
    ID_FUNC_ITEM_REGEXP_INSTR,
    ID_FUNC_ITEM_REGEXP_REPLACE,
    ID_FUNC_ITEM_REGEXP_SUBSTR,
    ID_FUNC_ITEM_RELEASE_LOCK,
    ID_FUNC_ITEM_RELEASE_SHARED_LOCK,
    ID_FUNC_ITEM_PEPEAT,
    ID_FUNC_ITEM_REPLACE,
    ID_FUNC_ITEM_REVERSE,
    ID_FUNC_ITEM_RIGHT,
    ID_FUNC_ITEM_ROUND,
    ID_FUNC_ITEM_RPAD,
    ID_FUNC_ITEM_RTRIM,
    ID_FUNC_ITEM_SCN2DATE,
    ID_FUNC_ITEM_SERIAL_LASTVAL,
    ID_FUNC_ITEM_SHA,
    ID_FUNC_ITEM_SHA1,
    ID_FUNC_ITEM_SIGN,
    ID_FUNC_ITEM_SIN,
    ID_FUNC_ITEM_SOUNDEX,
    ID_FUNC_ITEM_SPACE,
    ID_FUNC_ITEM_SQRT,
    ID_FUNC_ITEM_STDDEV,
    ID_FUNC_ITEM_STDDEV_POP,
    ID_FUNC_ITEM_STDDEV_SAMP,
    ID_FUNC_ITEM_SUBSTR,
    ID_FUNC_ITEM_SUBSTRB,
    ID_FUNC_ITEM_SUBSTRING,
    ID_FUNC_ITEM_SUBSTRING_INDEX,
    ID_FUNC_ITEM_SUM,
    ID_FUNC_ITEM_SYSTIMESTAMP,
    ID_FUNC_ITEM_SYS_CONNECT_BY_PATH,
    ID_FUNC_ITEM_SYS_CONTEXT,
    ID_FUNC_ITEM_SYS_EXTRACT_UTC,
    ID_FUNC_ITEM_SYS_GUID,
    ID_FUNC_ITEM_TAN,
    ID_FUNC_ITEM_TANH,
    ID_FUNC_ITEM_TIMESTAMPADD,
    ID_FUNC_ITEM_TIMESTAMPDIFF,
    ID_FUNC_ITEM_TO_BIGINT,
    ID_FUNC_ITEM_TO_BLOB,
    ID_FUNC_ITEM_TO_CHAR,
    ID_FUNC_ITEM_TO_CLOB,
    ID_FUNC_ITEM_TO_DATE,
    ID_FUNC_ITEM_TO_DSINTERVAL,
    ID_FUNC_ITEM_TO_INT,
    ID_FUNC_ITEM_TO_MULTI_BYTE,
    ID_FUNC_ITEM_TO_NCHAR,
    ID_FUNC_ITEM_TO_NUMBER,
    ID_FUNC_ITEM_TO_SINGLE_BYTE,
    ID_FUNC_ITEM_TO_TIMESTAMP,
    ID_FUNC_ITEM_TO_YMINTERVAL,
    ID_FUNC_ITEM_TRANSLATE,
    ID_FUNC_ITEM_TRIM,
    ID_FUNC_ITEM_TRUNC,
    ID_FUNC_ITEM_TRY_GET_LOCK,
    ID_FUNC_ITEM_TRY_GET_SHARED_LOCK,
    ID_FUNC_ITEM_TRY_GET_XACT_LOCK,
    ID_FUNC_ITEM_TRY_GET_XACT_SHARED_LOCK,
    ID_FUNC_ITEM_TYPE_ID2NAME,
    ID_FUNC_ITEM_UNHEX,
    ID_FUNC_ITEM_UNIX_TIMESTAMP,
    ID_FUNC_ITEM_UPDATE_DN_MIN_SCN,
    ID_FUNC_ITEM_UPDATING,
    ID_FUNC_ITEM_UPPER,
    ID_FUNC_ITEM_USERENV,
    ID_FUNC_ITEM_UTCDATE,
    ID_FUNC_ITEM_UTCTIMESTAMP,
    ID_FUNC_ITEM_UUID,
    ID_FUNC_ITEM_VALUES,
    ID_FUNC_ITEM_VARIANCE,
    ID_FUNC_ITEM_VAR_POP,
    ID_FUNC_ITEM_VAR_SAMP,
    ID_FUNC_ITEM_VERSION,
    ID_FUNC_ITEM_VSIZE,
} function_item_id_t;

#define IS_BUILDIN_FUNCTION(node, id) \
    ((node)->value.v_func.pack_id == GS_INVALID_ID32 && (node)->value.v_func.func_id == (id))

typedef status_t (*sql_invoke_func_t)(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
typedef status_t (*sql_verify_func_t)(sql_verifier_t *verifier, expr_node_t *func);
typedef enum en_func_value_cnt { FO_USUAL = 1, FO_COVAR = 2, FO_VAL_MAX } func_value_cnt_t;
typedef enum en_func_option {
    /* no optimal methods */
    FO_NONE = 0,
    /* Using the normal method to infer its optimal inferring method,
     * see sql_infer_func_optmz_mode */
    FO_NORMAL = 1,
    // as procedure
    FO_PROC = 2,
    /* The function has its special optimal inferring method.
     * Generally, its inferring is in its verification function */
    FO_SPECIAL = 3,
} func_option_t;

typedef struct st_sql_func {
    text_t name;
    sql_invoke_func_t invoke;
    sql_verify_func_t verify;
    sql_aggr_type_t aggr_type;
    uint32 options;         /* need to const function reduce */
    uint32 builtin_func_id; /* only use for built-in function, other is set to GS_INVALID_ID32 */
    uint32 value_cnt;
    bool32 indexable; /* true: the function can be used as index column */
} sql_func_t;

typedef struct st_fmt_dot_pos {
    bool32 fill_mode;
    uint32 start_pos;
    uint32 dot_pos;
    uint32 fmt_dot_pos;
    uint32 last_zero_pos;
    uint32 int_len;
} fmt_dot_pos_t;
#define GS_CONST_FOUR (uint32)(4)
#define SQL_SET_NULL_VAR(var) VAR_SET_NULL((var), GS_DATATYPE_OF_NULL)
#define SQL_SET_COLUMN_VAR(var)       \
    do {                              \
        (var)->type = GS_TYPE_COLUMN; \
        (var)->is_null = GS_FALSE;    \
    } while (0)

#define SQL_CHECK_COLUMN_VAR(arg, res)         \
    do {                                       \
        if (((arg)->type) == GS_TYPE_COLUMN) { \
            SQL_SET_COLUMN_VAR(res);           \
            return GS_SUCCESS;                 \
        }                                      \
    } while (0)

#define SQL_CHECK_COND_PANDING(pending, res) \
    do {                                     \
        if ((pending)) {                     \
            SQL_SET_COLUMN_VAR(res);         \
            return GS_SUCCESS;               \
        }                                    \
    } while (0)

#define SQL_EXEC_FUNC_ARG(arg_expr, arg_var, res_var, stmt)               \
    do {                                                                  \
        if (sql_exec_expr((stmt), (arg_expr), (arg_var)) != GS_SUCCESS) { \
            return GS_ERROR;                                              \
        }                                                                 \
        SQL_CHECK_COLUMN_VAR((arg_var), (res_var));                       \
        if (GS_IS_LOB_TYPE((arg_var)->type) && !(arg_var)->is_null) {     \
            GS_RETURN_IFERR(sql_get_lob_value((stmt), (arg_var)));        \
        }                                                                 \
    } while (0)

#define SQL_EXEC_FUNC_ARG_EX(arg_expr, arg_var, res_var)           \
    do {                                                           \
        SQL_EXEC_FUNC_ARG((arg_expr), (arg_var), (res_var), stmt); \
        if ((arg_var)->is_null) {                                  \
            SQL_SET_NULL_VAR(res_var);                             \
            return GS_SUCCESS;                                     \
        }                                                          \
    } while (0)

#define SQL_EXEC_FUNC_ARG_EX2(arg_expr, arg_var, res_var)          \
    do {                                                           \
        SQL_EXEC_FUNC_ARG((arg_expr), (arg_var), (res_var), stmt); \
        if ((arg_var)->is_null) {                                  \
            SQL_SET_NULL_VAR(res_var);                             \
        }                                                          \
    } while (0)

#define SQL_EXEC_LENGTH_FUNC_ARG(arg_expr, arg_var, res_var, stmt)        \
    do {                                                                  \
        if (sql_exec_expr((stmt), (arg_expr), (arg_var)) != GS_SUCCESS) { \
            return GS_ERROR;                                              \
        }                                                                 \
        SQL_CHECK_COLUMN_VAR((arg_var), (res_var));                       \
        if ((arg_var)->is_null) {                                         \
            SQL_SET_NULL_VAR(res_var);                                    \
            return GS_SUCCESS;                                            \
        }                                                                 \
    } while (0)

#define SQL_INIT_TYPEMOD(typemod)         \
    do {                                  \
        (typemod).size = GS_INVALID_ID16; \
        (typemod).mode = GS_INVALID_ID16; \
        (typemod).is_array = 0;           \
        (typemod).reserve[0] = 0;         \
        (typemod).reserve[1] = 0;         \
        (typemod).reserve[2] = 0;         \
    } while (0)

/**
 * Used to static check the datatype for TO_XXXX functions, such as *to_date*,
 * *to_timestamp*, *to_yminterval* and *to_dsinterval*. These functions require the
 * source argument must be a STRING type, as well as binding argument with UNKNOWN type.
 * @author Added, 2018/04/10
 */
static inline bool32 sql_match_string_type(gs_type_t src_type)
{
    return (bool32)(GS_IS_STRING_TYPE(src_type) || GS_IS_UNKNOWN_TYPE(src_type));
}

static inline bool32 sql_match_numeric_type(gs_type_t src_type)
{
    return (bool32)(GS_IS_WEAK_NUMERIC_TYPE(src_type) || GS_IS_UNKNOWN_TYPE(src_type));
}

static inline bool32 sql_match_num_and_str_type(gs_type_t src_type)
{
    return (bool32)(GS_IS_WEAK_NUMERIC_TYPE(src_type) || GS_IS_UNKNOWN_TYPE(src_type));
}

static inline bool32 sql_match_datetime_type(gs_type_t src_type)
{
    return (bool32)(GS_IS_WEAK_DATETIME_TYPE(src_type) || GS_IS_UNKNOWN_TYPE(src_type));
}

static inline bool32 sql_match_timestamp(gs_type_t src_type)
{
    return (bool32)(GS_IS_TIMESTAMP(src_type) || GS_IS_TIMESTAMP_TZ_TYPE(src_type) ||
                    GS_IS_TIMESTAMP_LTZ_TYPE(src_type) || GS_IS_UNKNOWN_TYPE(src_type));
}

static inline bool32 sql_match_num_and_datetime_type(gs_type_t src_type)
{
    return (bool32)(sql_match_numeric_type(src_type) || sql_match_datetime_type(src_type));
}

static inline bool32 sql_match_interval_type(gs_type_t src_type)
{
    return (bool32)(src_type == GS_TYPE_INTERVAL_DS || src_type == GS_TYPE_INTERVAL_YM);
}

static inline bool32 sql_match_bool_type(gs_type_t src_type)
{
    return (bool32)(GS_IS_WEAK_BOOLEAN_TYPE(src_type) || GS_IS_UNKNOWN_TYPE(src_type));
}

static inline status_t sql_var_as_string(sql_stmt_t *stmt, variant_t *var)
{
    char *buf = NULL;
    text_buf_t buffer;

    uint32 size = cm_get_datatype_strlen(var->type, GS_STRING_BUFFER_SIZE) + 1;
    GS_RETURN_IFERR(sql_push(stmt, size, (void **)&buf));
    CM_INIT_TEXTBUF(&buffer, size, buf);
    GS_RETURN_IFERR(var_as_string(SESSION_NLS(stmt), var, &buffer));
    return GS_SUCCESS;
}

/* Set error for function: string argument is required */
#define GS_SRC_ERROR_REQUIRE_STRING(loc, got_type)                                        \
    GS_SRC_THROW_ERROR_EX((loc), ERR_INVALID_FUNC_PARAMS,                                 \
                          "illegal function argument: string argument expected - got %s", \
                          get_datatype_name_str((int32)(got_type)));

/* Set error for function: INTEGER argument is required */
#define GS_SRC_ERROR_REQUIRE_INTEGER(loc, got_type)                                        \
    GS_SRC_THROW_ERROR_EX((loc), ERR_INVALID_FUNC_PARAMS,                                  \
                          "illegal function argument: integer argument expected - got %s", \
                          get_datatype_name_str((int32)(got_type)));

/* Set error for function: NUMERIC argument is required */
#define GS_SRC_ERROR_REQUIRE_NUMERIC(loc, got_type)                                        \
    GS_SRC_THROW_ERROR_EX((loc), ERR_INVALID_FUNC_PARAMS,                                  \
                          "illegal function argument: NUMERIC argument expected - got %s", \
                          get_datatype_name_str((int32)(got_type)));

/* Set error for function: NUMERIC or string argument is required */
#define GS_SRC_ERROR_REQUIRE_NUM_OR_STR(loc, got_type)                                               \
    GS_SRC_THROW_ERROR_EX((loc), ERR_INVALID_FUNC_PARAMS,                                            \
                          "illegal function argument: NUMERIC or string argument expected - got %s", \
                          get_datatype_name_str((int32)(got_type)));

/* Set error for function: NUMERIC or DATETIME argument is required */
#define GS_SRC_ERROR_REQUIRE_NUM_OR_DATETIME(loc, got_type)                                            \
    GS_SRC_THROW_ERROR_EX((loc), ERR_INVALID_FUNC_PARAMS,                                              \
                          "illegal function argument: NUMERIC or DATETIME argument expected - got %s", \
                          get_datatype_name_str((int32)(got_type)));

/* Set error for function: DATETIME argument is required */
#define GS_SRC_ERROR_REQUIRE_DATETIME(loc, got_type)                                        \
    GS_SRC_THROW_ERROR_EX((loc), ERR_INVALID_FUNC_PARAMS,                                   \
                          "illegal function argument: DATETIME argument expected - got %s", \
                          get_datatype_name_str((int32)(got_type)));

#define GS_BLANK_CHAR_SET " \t"

typedef text_t *(*sql_func_item_t)(void *set, uint32 id);
extern sql_func_t g_func_tab[];
extern sql_func_t *sql_get_pack_func(var_func_t *v);

static inline sql_func_t *sql_get_func(var_func_t *v)
{
    if (v->pack_id == GS_INVALID_ID32) {
        return &g_func_tab[v->func_id];
    }

    knl_panic(0);
    return NULL;
}

static inline uint32 sql_hash_func(const char *buf)
{
    return cm_hash_func((uint8 *)buf, ((row_head_t *)buf)->size);
}

status_t sql_invoke_func(sql_stmt_t *stmt, expr_node_t *node, variant_t *result);
status_t sql_verify_func_node(sql_verifier_t *verf, expr_node_t *func, uint16 min_args, uint16 max_args,
                              uint32 type_arg_no);
status_t sql_exec_expr_as_string(sql_stmt_t *stmt, expr_tree_t *arg, variant_t *var, text_t **text);
status_t sql_get_utf8_clob_char_len(sql_stmt_t *stmt, variant_t *var, uint32 *len);
uint32 sql_func_binsearch(const text_t *name, sql_func_item_t get_item, void *set, uint32 count);
uint32 sql_get_func_id(const text_t *func_name);
uint32 sql_get_lob_var_length(variant_t *var);
bool32 sql_verify_lob_func_args(gs_type_t datatype);
status_t sql_func_page2masterid(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_page2masterid(sql_verifier_t *verifier, expr_node_t *func);
status_t pl_try_verify_builtin_func(sql_verifier_t *verf, expr_node_t *node, var_udo_t *obj, bool32 *is_found);
void pl_revert_last_error(status_t status);

typedef struct st_sql_parser {
    memory_context_t *context;
    text_t user;
    lex_t lex;
} sql_parser_t;

status_t sql_parse(sql_stmt_t *stmt, text_t *sql, source_location_t *loc);
lang_type_t sql_diag_lang_type(sql_stmt_t *stmt, sql_text_t *sql, word_t *leader_word);
#define IS_COMPARE_COND_TYPE(type) ((type) <= CMP_TYPE_NOT_EQUAL_ANY || (type) >= CMP_TYPE_GREAT_EQUAL_ANY)

#define IS_MEMBERSHIP_COND_TYPE(type) ((type) == CMP_TYPE_IN || (type) == CMP_TYPE_NOT_IN)

#define IS_LOGICAL_NODE(node) \
    ((node)->type == COND_NODE_OR || (node)->type == COND_NODE_NOT || (node)->type == COND_NODE_AND)

#define IS_LOGICAL_WORD(word) ((word)->id == KEY_WORD_OR || (word)->id == KEY_WORD_NOT || (word)->id == KEY_WORD_AND)

#define IS_OBVIOUS_CMP(word)                                                                                   \
    (word)->type == WORD_TYPE_COMPARE &&                                                                       \
        ((word)->id == CMP_TYPE_EQUAL || (word)->id == CMP_TYPE_GREAT_EQUAL || (word)->id == CMP_TYPE_GREAT || \
         (word)->id == CMP_TYPE_LESS || (word)->id == CMP_TYPE_LESS_EQUAL || (word)->id == CMP_TYPE_NOT_EQUAL)

#define IS_CSR_WHERE_END_WORD(id)                                                                                   \
    ((id) == KEY_WORD_FOR || (id) == KEY_WORD_GROUP || (id) == KEY_WORD_ORDER || (id) == KEY_WORD_WHERE ||          \
     (id) == KEY_WORD_HAVING || (id) == KEY_WORD_UNION || (id) == KEY_WORD_MINUS || (id) == KEY_WORD_LIMIT ||       \
     (id) == KEY_WORD_FULL || (id) == KEY_WORD_INNER || (id) == KEY_WORD_JOIN || (id) == KEY_WORD_START ||          \
     (id) == KEY_WORD_CONNECT || (id) == KEY_WORD_LOOP || (id) == KEY_WORD_SET || (id) == KEY_WORD_ON ||            \
     (id) == KEY_WORD_OFFSET || (id) == KEY_WORD_EXCEPT || (id) == KEY_WORD_RETURN || (id) == KEY_WORD_RETURNING || \
     (id) == KEY_WORD_INTERSECT || (id) == KEY_WORD_PIVOT || (id) == KEY_WORD_UNPIVOT)

#define IS_CLAUSE_WORD(id) (IS_CSR_WHERE_END_WORD(id) || (id) == KEY_WORD_WHEN || (id) == KEY_WORD_THEN)

#define MAX_COND_TREE_DEPTH 16

status_t sql_create_cond_until(sql_stmt_t *stmt, cond_tree_t **cond, word_t *word);
status_t sql_create_cond_from_text(sql_stmt_t *stmt, sql_text_t *text, cond_tree_t **cond, bool32 *is_expr);
status_t sql_create_const_expr_false(sql_stmt_t *stmt, expr_tree_t **expr, word_t *word, int32 val);
status_t sql_check_select_expr(sql_stmt_t *stmt, sql_text_t *text, bool32 *is_select);
status_t sql_parse_in_subselect(sql_stmt_t *stmt, expr_tree_t **expr, word_t *word);
cmp_node_t *sql_get_last_comp_node(sql_stmt_t *stmt, cond_tree_t *cond, word_t *word);
status_t sql_parse_dcl_alter(sql_stmt_t *stmt);
status_t sql_parse_backup(sql_stmt_t *stmt);
status_t sql_parse_restore(sql_stmt_t *stmt);
status_t sql_parse_recover(sql_stmt_t *stmt);
status_t sql_parse_shutdown(sql_stmt_t *stmt);
status_t sql_parse_backup_tag(sql_stmt_t *stmt, word_t *word, char *tag);
status_t sql_parse_daac(sql_stmt_t *stmt);
status_t sql_parse_dcl(sql_stmt_t *stmt, key_wid_t wid);
#define SEL_QUERY_BLOCK_PREFIX "SEL$"
#define SEL_QUERY_BLOCK_PREFIX_LEN (uint32)4

/* by Liu Liang on XXXX.XX.XX */
#ifndef LIMIT_CLAUSE_OCCUR
#define LIMIT_CLAUSE_OCCUR(limit) ((limit)->count != NULL || (limit)->offset != NULL)
#endif

typedef enum en_sql_special_word {
    SQL_HAS_NONE = 0,
    SQL_HAS_LTT = 0x00000001,
    SQL_HAS_DBLINK = 0x00000002
} sql_special_word_t;

status_t sql_create_list(sql_stmt_t *stmt, galist_t **list);
status_t sql_parse_dml(sql_stmt_t *stmt, key_wid_t wid);
status_t sql_parse_view_subselect(sql_stmt_t *stmt, text_t *sql, sql_select_t **select_ctx, source_location_t *loc);
bool32 sql_has_ltt(sql_stmt_t *stmt, text_t *sql);
bool32 sql_check_ctx(sql_stmt_t *stmt, sql_context_t *ctx);
bool32 sql_check_procedures(sql_stmt_t *stmt, galist_t *dc_lst);
status_t sql_compile_synonym_by_user(sql_stmt_t *stmt, text_t *schema_name, bool32 compile_all);
status_t sql_compile_view_by_user(sql_stmt_t *stmt, text_t *schema_name, bool32 compile_all);
status_t sql_parse_dml_directly(sql_stmt_t *stmt, key_wid_t wid, sql_text_t *sql);
bool32 sql_compile_view_sql(sql_stmt_t *stmt, knl_dictionary_t *view_dc, text_t *owner);
bool32 sql_check_equal_join_cond(join_cond_t *join_cond);

#define SQL_SAVE_PARSER(stmt)                     \
    SQL_SAVE_STACK(stmt);                         \
    sql_context_t *__context__ = (stmt)->context; \
    void *__pl_context__ = (stmt)->pl_context;    \
    lang_type_t __lang_type__ = (stmt)->lang_type;

#define SQL_RESTORE_PARSER(stmt)                   \
    do {                                           \
        SET_STMT_CONTEXT(stmt, __context__);       \
        SET_STMT_PL_CONTEXT(stmt, __pl_context__); \
        (stmt)->lang_type = __lang_type__;         \
        SQL_RESTORE_STACK(stmt);                   \
    } while (0)

status_t sql_create_rowid_rs_column(sql_stmt_t *stmt, uint32 id, sql_table_type_t type, galist_t *list);

status_t sql_create_dml_currently(sql_stmt_t *stmt, sql_text_t *sql, key_wid_t wid);
void sql_prepare_context_ctrl(sql_stmt_t *stmt, uint32 hash_value, context_bucket_t *bucket);
void sql_parse_set_context_procinfo(sql_stmt_t *stmt);
uint32 sql_has_special_word(sql_stmt_t *stmt, text_t *sql);
status_t sql_parse_table(sql_stmt_t *stmt, sql_table_t *table, word_t *word);
status_t sql_parse_query_tables(sql_stmt_t *stmt, sql_query_t *query, word_t *word);
status_t sql_parse_join_entry(sql_stmt_t *stmt, sql_query_t *query, word_t *word);
status_t sql_generate_join_node(sql_stmt_t *stmt, sql_join_chain_t *join_chain, sql_join_type_t join_type,
                                sql_table_t *table, cond_tree_t *cond);
status_t sql_decode_object_name(sql_stmt_t *stmt, word_t *word, sql_text_t *user, sql_text_t *name);
status_t sql_try_parse_table_alias(sql_stmt_t *stmt, sql_text_t *alias, word_t *word);
status_t sql_regist_table(sql_stmt_t *stmt, sql_table_t *table);
status_t sql_create_join_node(sql_stmt_t *stmt, sql_join_type_t join_type, sql_table_t *table, cond_tree_t *cond,
                              sql_join_node_t *left, sql_join_node_t *right, sql_join_node_t **join_node);
status_t sql_parse_comma_join(sql_stmt_t *stmt, sql_array_t *tables, sql_join_assist_t *join_assist,
                              sql_join_chain_t *join_chain, sql_table_t **table, word_t *word);
status_t sql_form_table_join_with_opers(sql_join_chain_t *chain, uint32 opers);
status_t sql_set_table_qb_name(sql_stmt_t *stmt, sql_query_t *query);
status_t sql_try_parse_alias(sql_stmt_t *stmt, text_t *alias, word_t *word);
status_t sql_init_query(sql_stmt_t *stmt, sql_select_t *select_ctx, source_location_t loc, sql_query_t *query);
status_t sql_parse_column(sql_stmt_t *stmt, galist_t *columns, word_t *word);
status_t sql_parse_order_by_items(sql_stmt_t *stmt, galist_t *sort_items, word_t *word);
status_t sql_parse_order_by(sql_stmt_t *stmt, sql_query_t *query, word_t *word);
status_t sql_verify_limit_offset(sql_stmt_t *stmt, limit_item_t *limit);
status_t sql_parse_limit_offset(sql_stmt_t *stmt, limit_item_t *limit, word_t *word);
status_t sql_init_join_assist(sql_stmt_t *stmt, sql_join_assist_t *join_assist);
status_t sql_parse_select_context(sql_stmt_t *stmt, select_type_t type, word_t *word, sql_select_t **select_ctx);
status_t sql_create_select_context(sql_stmt_t *stmt, sql_text_t *sql, select_type_t type, sql_select_t **select_ctx);
status_t sql_alloc_select_context(sql_stmt_t *stmt, select_type_t type, sql_select_t **select_ctx);
status_t sql_set_origin_query_block_name(sql_stmt_t *stmt, sql_query_t *query);
status_t dtc_parse_create_database(sql_stmt_t *stmt);
status_t dtc_verify_database_def(sql_stmt_t *stmt, knl_database_def_t *def);
status_t dtc_parse_instance(sql_stmt_t *stmt, knl_database_def_t *def, word_t *word);
status_t dtc_parse_maxinstance(sql_stmt_t *stmt, knl_database_def_t *def, word_t *word);

status_t sql_convert_to_cast(sql_stmt_t *stmt, expr_tree_t *expr, word_t *word);
status_t sql_build_func_node(sql_stmt_t *stmt, word_t *word, expr_node_t *node);
status_t sql_build_func_over(sql_stmt_t *stmt, expr_tree_t *expr, word_t *word, expr_node_t **node);
status_t sql_try_fetch_func_arg(sql_stmt_t *stmt, text_t *arg_name);
status_t sql_create_const_string_expr(sql_stmt_t *stmt, expr_tree_t **new_expr, const char *cstring);
status_t sql_build_cast_expr(sql_stmt_t *stmt, source_location_t loc, expr_tree_t *expr, typmode_t *type,
                             expr_tree_t **r_result);
#define IS_DUAL_TABLE_NAME(tab_name) \
    (cm_text_str_equal_ins(tab_name, "DUAL") || cm_text_str_equal(tab_name, "SYS_DUMMY"))

static inline status_t sql_word_as_table(sql_stmt_t *stmt, word_t *word, var_word_t *var)
{
    if (word->ex_count == 0) {
        if (sql_copy_object_name_loc(stmt->context, word->type, &word->text, &var->table.name) != GS_SUCCESS) {
            return GS_ERROR;
        }
        var->table.user.loc = word->text.loc;
        var->table.user.implicit = GS_TRUE;
        text_t user_name = { stmt->session->curr_schema, (uint32)strlen(stmt->session->curr_schema) };
        if (IS_DUAL_TABLE_NAME(&var->table.name.value)) {
            cm_text_upper(&var->table.name.value);
        }

        if (sql_copy_name(stmt->context, &user_name, (text_t *)&var->table.user) != GS_SUCCESS) {
            return GS_ERROR;
        }
    } else if (word->ex_count == 1) {
        if (sql_copy_object_name_loc(stmt->context, word->ex_words[0].type, &word->ex_words[0].text,
                                     &var->table.name) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (sql_copy_name_prefix_tenant_loc(stmt, &word->text, &var->table.user) != GS_SUCCESS) {
            return GS_ERROR;
        }
        var->table.user.implicit = GS_FALSE;
        if (cm_text_str_equal_ins(&var->table.user.value, "SYS") && IS_DUAL_TABLE_NAME(&var->table.name.value)) {
            cm_text_upper(&var->table.name.value);
        }
    } else {
        GS_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR, "invalid table name");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static inline status_t sql_word_as_column(sql_stmt_t *stmt, word_t *word, var_word_t *var)
{
    if (word->ex_count == 0) {
        GS_RETURN_IFERR(sql_copy_object_name_loc(stmt->context, word->type, &word->text, &var->column.name));

        var->column.table.value = CM_NULL_TEXT;
        var->column.table.loc = word->text.loc;

        var->column.user.value = CM_NULL_TEXT;
        var->column.user.loc = word->text.loc;
    } else if (word->ex_count == 1) {
        GS_RETURN_IFERR(sql_copy_object_name_loc(stmt->context, word->ex_words[0].type, &word->ex_words[0].text,
                                                 &var->column.name));

        GS_RETURN_IFERR(
            sql_copy_object_name_loc(stmt->context, word->type | word->ori_type, &word->text, &var->column.table));

        GS_RETURN_IFERR(sql_copy_name_prefix_tenant_loc(stmt, &word->text, &var->column.user_ex));

        var->column.user.value = CM_NULL_TEXT;
        var->column.user.loc = word->text.loc;
    } else if (word->ex_count == 2) {
        GS_RETURN_IFERR(sql_copy_object_name_loc(stmt->context, word->ex_words[1].type, &word->ex_words[1].text,
                                                 &var->column.name));

        GS_RETURN_IFERR(sql_copy_object_name_loc(stmt->context, word->ex_words[0].type, &word->ex_words[0].text,
                                                 &var->column.table));

        GS_RETURN_IFERR(sql_copy_name_prefix_tenant_loc(stmt, &word->text, &var->column.user));
    } else {
        GS_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR, "invalid column name is found");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static inline status_t sql_word_as_func(sql_stmt_t *stmt, word_t *word, var_word_t *var)
{
    if (word->ex_count == 0) {
        GS_RETURN_IFERR(
            sql_copy_object_name_loc(stmt->context, word->type | word->ori_type, &word->text, &var->func.name));

        var->func.args.value = CM_NULL_TEXT;
        var->func.args.loc = word->text.loc;
        var->func.pack.value = CM_NULL_TEXT;
        var->func.pack.loc = word->text.loc;
        var->func.user.value = CM_NULL_TEXT;
        var->func.user.loc = word->text.loc;
    } else if (word->ex_count == 1) {
        GS_RETURN_IFERR(
            sql_copy_object_name_loc(stmt->context, word->type | word->ori_type, &word->text, &var->func.name));

        var->func.args = word->ex_words[0].text;
        var->func.pack.value = CM_NULL_TEXT;
        var->func.pack.loc = word->text.loc;
        var->func.user.value = CM_NULL_TEXT;
        var->func.user.loc = word->text.loc;
    } else if (word->ex_count == 2) {
        GS_RETURN_IFERR(sql_copy_object_name_loc(stmt->context, word->ori_type, &word->text, &var->func.org_user));
        GS_RETURN_IFERR(sql_copy_object_name_prefix_tenant_loc(stmt, word->ori_type, &word->text, &var->func.user));
        GS_RETURN_IFERR(
            sql_copy_object_name_loc(stmt->context, word->ex_words[0].type, &word->ex_words[0].text, &var->func.name));

        var->func.args = word->ex_words[1].text;
        var->func.pack.value = CM_NULL_TEXT;
        var->func.pack.loc = word->text.loc;
    } else if (word->ex_count == 3) {
        GS_RETURN_IFERR(
            sql_copy_object_name_loc(stmt->context, word->ex_words[1].type, &word->ex_words[1].text, &var->func.name));

        GS_RETURN_IFERR(
            sql_copy_object_name_loc(stmt->context, word->ex_words[0].type, &word->ex_words[0].text, &var->func.pack));

        GS_RETURN_IFERR(sql_copy_name_prefix_tenant_loc(stmt, &word->text, &var->func.user));

        var->func.args = word->ex_words[2].text;
    } else {
        GS_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR, "invalid function or procedure name is found");
        return GS_ERROR;
    }

    var->func.count = word->ex_count;

    return GS_SUCCESS;
}

#define EXPR_EXPECT_NONE 0x00000000
#define EXPR_EXPECT_UNARY_OP 0x00000001
#define EXPR_EXPECT_OPER 0x00000002
#define EXPR_EXPECT_VAR 0x00000004
#define EXPR_EXPECT_UNARY 0x00000008
#define EXPR_EXPECT_STAR 0x00000010
#define EXPR_EXPECT_ALPHA 0x00000020

/* The modes of datatype parsing */
typedef enum en_parsing_mode {
    PM_NORMAL, /* parsing SQL column datatype or cast function  */
    PM_PL_VAR, /* parsing for procedure variables */
    PM_PL_ARG, /* parsing for procedure argument, no type attr is allowed */
} pmode_t;

status_t sql_create_expr_until(sql_stmt_t *stmt, expr_tree_t **expr, word_t *word);
status_t sql_create_expr_from_text(sql_stmt_t *stmt, sql_text_t *text, expr_tree_t **expr, word_flag_t flag_type);
status_t sql_create_expr_list(sql_stmt_t *stmt, sql_text_t *text, expr_tree_t **expr);
status_t sql_create_expr(sql_stmt_t *stmt, expr_tree_t **expr);
status_t sql_add_expr_word(sql_stmt_t *stmt, expr_tree_t *expr, word_t *word);
status_t sql_create_expr_from_word(sql_stmt_t *stmt, word_t *word, expr_tree_t **expr);
status_t sql_generate_expr(expr_tree_t *expr);
status_t sql_parse_typmode(lex_t *lex, pmode_t pmod, typmode_t *typmod, word_t *typword);
status_t sql_parse_datatype(lex_t *lex, pmode_t pmod, typmode_t *typmod, word_t *typword);
status_t sql_parse_datatype_typemode(lex_t *lex, pmode_t pmod, typmode_t *typmod, word_t *typword, word_t *tword);
status_t sql_parse_case_expr(sql_stmt_t *stmt, word_t *word, expr_node_t *node);
status_t sql_build_default_reserved_expr(sql_stmt_t *stmt, expr_tree_t **r_result);
status_t sql_build_column_expr(sql_stmt_t *stmt, knl_column_t *column, expr_tree_t **r_result);
status_t sql_copy_text_remove_quotes(sql_context_t *ctx, text_t *src, text_t *dst);
status_t sql_word2text(sql_stmt_t *stmt, word_t *word, expr_node_t *node);
status_t sql_word2number(word_t *word, expr_node_t *node);

#define EXPR_VAR_WORDS                                                                                                \
    (WORD_TYPE_VARIANT | WORD_TYPE_FUNCTION | WORD_TYPE_STRING | WORD_TYPE_PARAM | WORD_TYPE_NUMBER |                 \
     WORD_TYPE_RESERVED | WORD_TYPE_DATATYPE | WORD_TYPE_BRACKET | WORD_TYPE_KEYWORD | WORD_TYPE_PL_ATTR |            \
     WORD_TYPE_PL_NEW_COL | WORD_TYPE_PL_OLD_COL | WORD_TYPE_DQ_STRING | WORD_TYPE_HEXADECIMAL | WORD_TYPE_JOIN_COL | \
     WORD_TYPE_ARRAY)

#define EXPR_IS_UNARY_OP(word)                                                      \
    ((word)->type == (uint32)WORD_TYPE_OPERATOR &&                                  \
     ((word)->id == (uint32)OPER_TYPE_SUB || (word)->id == (uint32)OPER_TYPE_ADD || \
      (word)->id == (uint32)OPER_TYPE_PRIOR))

#define EXPR_IS_UNARY_OP_ROOT(word) \
    ((word)->type == (uint32)WORD_TYPE_OPERATOR && ((word)->id == (uint32)OPER_TYPE_ROOT))

#define EXPR_IS_OPER(word) ((word)->type == (uint32)WORD_TYPE_OPERATOR)

#define EXPR_IS_STAR(word)                                                                                             \
    ((word)->text.len > 0 && CM_TEXT_END(&(word)->text) == '*' && (word)->type != WORD_TYPE_DQ_STRING) /* the last     \
                                                                                                          char of word \
                                                                                                          is * */
status_t sql_add_param_mark(sql_stmt_t *stmt, word_t *word, bool32 *is_repeated, uint32 *pnid);

#define TEMP_TBL_ATTR_PARSED 0x00000002
#define TBLOPTS_EX_AUTO_INCREMENT 0x00000001
#define DDL_MAX_COMMENT_LEN 4000
#define KNL_MAX_DEF_LEN 64
#define DDL_MIN_PWD_LEN 6
#define DDL_MIN_SYS_PWD_LEN 8
#define DDL_MAX_PWD_LEN 32
#define DDL_MAX_INT32_LEN 10 /* do not include sign */
#define DDL_MAX_INT64_LEN 19 /* do not include sign */
#define DDL_MAX_REAL_LEN 40
#define DDL_MAX_NUMERIC_LEN 38

#define DDL_USER_TABLE (DDL_USER_PWD | DDL_USER_AUDIT | DDL_USER_READONLY | DDL_USER_STATUS)

#define COLUMN_EX_NULLABLE 0x00000001
#define COLUMN_EX_KEY 0x00000002
#define COLUMN_EX_DEFAULT 0x00000004
#define COLUMN_EX_REF 0x00000008
#define COLUMN_EX_INL_CONSTR 0x00000010
#define COLUMN_EX_CHECK 0x00000020
#define COLUMN_EX_COMMENT 0x00000040
#define COLUMN_EX_UPDATE_DEFAULT 0x00000080
#define COLUMN_EX_AUTO_INCREMENT 0x00000100
#define COLUMN_EX_COLLATE 0x00000200
#define ALTAB_AUTO_INCREMENT_COLUMN 0x00000001

#define IS_CONSTRAINT_KEYWORD(id)                                                                                      \
    ((id) == KEY_WORD_CONSTRAINT || (id) == KEY_WORD_PRIMARY || (id) == KEY_WORD_UNIQUE || (id) == KEY_WORD_FOREIGN || \
     (id) == KEY_WORD_CHECK || (id) == KEY_WORD_PARTITION || (id) == KEY_WORD_LOGICAL)

#define DDL_MAX_CONSTR_NAME_LEN 128
#define DEFAULT_CTRL_FILE_COUNT 3
#define DEFAULT_SYSTEM_SPACE_SIZE ((int64)(128 * 1048576))
#define DEFAULT_UNDO_SPACE_SIZE ((int64)(128 * 1048576))
#define DEFAULT_TEMP_SPACE_SIZE ((int64)(128 * 1048576))
#define DEFAULT_USER_SPACE_SIZE ((int64)(128 * 1048576))
#define DEFAULT_SYSAUX_SPACE_SIZE ((int64)(128 * 1048576))
#define DEFAULT_LOGFILE_SIZE ((int64)(64 * 1048576))
#define DEFAULT_AUTOEXTEND_SIZE ((int64)(16 * 1048576))

/* default values for sequence parameters */
#define DDL_SEQUENCE_DEFAULT_INCREMENT 1
#define DDL_SEQUENCE_DEFAULT_CACHE 20
#define DDL_ASC_SEQUENCE_DEFAULT_MIN_VALUE 1
#define DDL_DESC_SEQUENCE_DEFAULT_MAX_VALUE ((int64)(-1))

#define DDL_ASC_SEQUENCE_DEFAULT_MAX_VALUE ((int64)GS_MAX_INT64)
#define DDL_DESC_SEQUENCE_DEFAULT_MIN_VALUE ((int64)GS_MIN_INT64)
#define DDL_SEQUENCE_MAX_CACHE ((int64)GS_MAX_INT64)

status_t sql_parse_create_sequence(sql_stmt_t *stmt);
status_t sql_parse_alter_sequence(sql_stmt_t *stmt);
status_t sql_parse_drop_sequence(sql_stmt_t *stmt);
status_t sql_parse_create_synonym(sql_stmt_t *stmt, uint32 flags);
status_t sql_parse_drop_synonym(sql_stmt_t *stmt, uint32 flags);

#define DB_MAX_NAME_LEN 32
#define SYSTEM_FILE_MIN_SIZE SIZE_M(80)
typedef enum en_program_type_def {
    PROGRAM_TYPE_FUNCTION,
    PROGRAM_TYPE_PROCEDURE,
    PROGRAM_TYPE_PACKAGE
} program_type_def;

typedef struct st_knl_program_unit_def {
    program_type_def prog_type; /* 0: function, 1: procedure, 2: package */
    text_t schema;              /* the program's owner */
    text_t prog_name;           /* the program's name */
} knl_program_unit_def;

/* check object type */
#define OBJ_IS_TABLE_TYPE(objtype) ((objtype) == OBJ_TYPE_TABLE)
#define OBJ_IS_VIEW_TYPE(objtype) ((objtype) == OBJ_TYPE_VIEW)
#define OBJ_IS_SEQUENCE_TYPE(objtype) ((objtype) == OBJ_TYPE_SEQUENCE)
#define OBJ_IS_PACKAGE_TYPE(objtype) ((objtype) == OBJ_TYPE_PACKAGE_SPEC)
#define OBJ_IS_TYPE_TYPE(objtype) ((objtype) == OBJ_TYPE_TYPE_SPEC)
#define OBJ_IS_PROCEDURE_TYPE(objtype) ((objtype) == OBJ_TYPE_PROCEDURE)
#define OBJ_IS_FUNCTION_TYPE(objtype) ((objtype) == OBJ_TYPE_FUNCTION)
#define OBJ_IS_DIRECTORY_TYPE(objtype) ((objtype) == OBJ_TYPE_DIRECTORY)
#define OBJ_IS_LIBRARY_TYPE(objtype) ((objtype) == OBJ_TYPE_LIBRARY)
#define OBJ_IS_TRIGGER_TYPE(objtype) ((objtype) == OBJ_TYPE_TRIGGER)
#define OBJ_IS_INVALID_TYPE(objtype) ((objtype) == OBJ_TYPE_INVALID)
#define OBJ_IS_USER_TYPE(objtype) ((objtype) == OBJ_TYPE_USER)

#define MAX_SAMPLE_RATIO 100

status_t sql_parse_space(sql_stmt_t *stmt, lex_t *lex, word_t *word, text_t *space);
status_t sql_verify_check_constraint(sql_stmt_t *stmt, knl_table_def_t *def);
status_t sql_regist_ddl_table(sql_stmt_t *stmt, text_t *user, text_t *name);

status_t sql_parse_create_table(sql_stmt_t *stmt, bool32 is_temp, bool32 has_global);
status_t sql_parse_drop_table(sql_stmt_t *stmt, bool32 is_temp);
status_t sql_parse_alter_table(sql_stmt_t *stmt);
status_t sql_verify_alter_table(sql_stmt_t *stmt);
status_t sql_parse_analyze_table(sql_stmt_t *stmt);
status_t sql_parse_truncate_table(sql_stmt_t *stmt);
status_t sql_parse_flashback_table(sql_stmt_t *stmt);
status_t sql_parse_purge_table(sql_stmt_t *stmt, knl_purge_def_t *def);
status_t sql_parse_comment_table(sql_stmt_t *stmt, key_wid_t id);
status_t sql_create_temporary_lead(sql_stmt_t *stmt);
status_t sql_parse_drop_temporary_lead(sql_stmt_t *stmt);
status_t sql_create_global_lead(sql_stmt_t *stmt);

typedef struct st_priv_info {
    text_t priv_name;
    source_location_t start_loc;
} priv_info;

status_t sql_parse_grant_objprivs_def(sql_stmt_t *stmt, lex_t *lex, knl_grant_def_t *def);
status_t sql_parse_revoke_objprivs_def(sql_stmt_t *stmt, lex_t *lex, knl_revoke_def_t *def);
status_t sql_check_dir_priv(galist_t *privs, bool32 *dire_priv);
status_t sql_check_user_privileges(galist_t *privs);
status_t sql_parse_grant_privs(sql_stmt_t *stmt, knl_grant_def_t *def);
status_t sql_parse_revokee_def(sql_stmt_t *stmt, lex_t *lex, knl_revoke_def_t *def);
status_t sql_parse_grantee_def(sql_stmt_t *stmt, lex_t *lex, knl_grant_def_t *def);
status_t sql_check_obj_owner(lex_t *lex, const text_t *curr_user, galist_t *holders);
status_t sql_check_obj_schema(lex_t *lex, text_t *schema, galist_t *holders);
status_t sql_check_privs_type(sql_stmt_t *stmt, galist_t *privs, priv_type_def priv_type, object_type_t objtype,
                              text_t *typename);
status_t sql_parse_revoke_privs(sql_stmt_t *stmt, knl_revoke_def_t *def);

typedef struct st_index_column_def {
    text_t index_column_name;
    bool32 is_in_function_mode;
    bool32 is_in_expression_mode;
    char expression_operator;
    char *function_name;
} index_knl_column_def_t;

status_t sql_parse_using_index(sql_stmt_t *stmt, lex_t *lex, knl_constraint_def_t *def);
status_t sql_parse_column_list(sql_stmt_t *stmt, lex_t *lex, galist_t *column_list, bool32 have_sort,
                               bool32 *have_func);
status_t sql_parse_index_attrs(sql_stmt_t *stmt, lex_t *lex, knl_index_def_t *def);

status_t sql_parse_create_index(sql_stmt_t *stmt, bool32 is_unique);
status_t sql_parse_alter_index(sql_stmt_t *stmt);
status_t sql_parse_drop_index(sql_stmt_t *stmt);
status_t sql_parse_analyze_index(sql_stmt_t *stmt);
status_t sql_parse_purge_index(sql_stmt_t *stmt, knl_purge_def_t *def);
status_t sql_parse_create_indexes(sql_stmt_t *stmt);
status_t sql_parse_create_database(sql_stmt_t *stmt, bool32 clustered);
status_t sql_create_database_lead(sql_stmt_t *stmt);
status_t sql_parse_alter_database_lead(sql_stmt_t *stmt);
status_t sql_parse_drop_tablespace(sql_stmt_t *stmt);
status_t sql_drop_database_lead(sql_stmt_t *stmt);
status_t sql_parse_password(sql_stmt_t *stmt, char *password, word_t *word);

status_t sql_parse_dbca_datafile_spec(sql_stmt_t *stmt, lex_t *lex, word_t *word, knl_space_def_t *space_def);
status_t sql_parse_dbca_logfiles(sql_stmt_t *stmt, galist_t *logfiles, word_t *word);

status_t sql_try_parse_if_not_exists(lex_t *lex, uint32 *options);

status_t sql_parse_references_clause(sql_stmt_t *stmt, lex_t *lex, text_t *ref_user, text_t *ref_table,
                                     knl_refactor_t *refactor, galist_t *ref_columns);
status_t sql_parse_primary_unique_cons(sql_stmt_t *stmt, lex_t *lex, constraint_type_t type, knl_constraint_def_t *def);
status_t sql_parse_foreign_key(sql_stmt_t *stmt, lex_t *lex, knl_constraint_def_t *def);
status_t sql_parse_add_check(sql_stmt_t *stmt, lex_t *lex, knl_altable_def_t *def, knl_constraint_def_t *cons);
status_t sql_parse_constraint(sql_stmt_t *stmt, lex_t *lex, knl_altable_def_t *def);
status_t sql_try_parse_cons(sql_stmt_t *stmt, lex_t *lex, knl_table_def_t *def, word_t *word, bool32 *result);
status_t sql_create_altable_inline_cons(sql_stmt_t *stmt, knl_column_def_t *column, knl_alt_column_prop_t *column_def);
status_t sql_parse_auto_primary_key_constr_name(sql_stmt_t *stmt, text_t *constr_name, text_t *sch_name,
                                                text_t *tab_name);
status_t sql_parse_inline_constraint(sql_stmt_t *stmt, lex_t *lex, knl_column_def_t *column, word_t *word,
                                     uint32 *ex_flags);
status_t sql_parse_inline_constraint_elemt(sql_stmt_t *stmt, lex_t *lex, knl_column_def_t *column, word_t *word,
                                           uint32 *ex_flags, text_t *cons_name);
status_t sql_parse_altable_constraint_rename(sql_stmt_t *stmt, lex_t *lex, knl_altable_def_t *def);
typedef enum en_add_column_type {
    CREATE_TABLE_ADD_COLUMN = 0,
    ALTER_TABLE_ADD_COLUMN = 1,
} def_column_action_t;

status_t sql_parse_lob_store(sql_stmt_t *stmt, lex_t *lex, word_t *word, galist_t *defs);
status_t sql_parse_modify_lob(sql_stmt_t *stmt, lex_t *lex, knl_altable_def_t *tab_def);
status_t sql_parse_charset(sql_stmt_t *stmt, lex_t *lex, uint8 *charset);
status_t sql_parse_collate(sql_stmt_t *stmt, lex_t *lex, uint8 *collate);

status_t sql_verify_columns(sql_stmt_t *stmt, knl_table_def_t *def);
status_t sql_verify_column_default_expr(sql_verifier_t *verf, expr_tree_t *cast_expr, knl_column_def_t *def);
status_t sql_verify_auto_increment(sql_stmt_t *stmt, knl_table_def_t *def);
status_t sql_verify_array_columns(table_type_t type, galist_t *columns);
status_t sql_verify_cons_def(knl_table_def_t *def);
status_t sql_check_duplicate_column(galist_t *columns, const text_t *name);
status_t sql_create_inline_cons(sql_stmt_t *stmt, knl_table_def_t *def);
status_t sql_parse_column_property(sql_stmt_t *stmt, lex_t *lex, word_t *word, knl_altable_def_t *def, uint32 *flags);
status_t sql_delay_verify_default(sql_stmt_t *stmt, knl_table_def_t *def);
status_t sql_parse_altable_add_brackets_recurse(sql_stmt_t *stmt, lex_t *lex, bool32 enclosed, knl_altable_def_t *def);
status_t sql_parse_altable_modify_brackets_recurse(sql_stmt_t *stmt, lex_t *lex, bool32 enclosed,
                                                   knl_altable_def_t *def);
status_t sql_parse_altable_column_rename(sql_stmt_t *stmt, lex_t *lex, knl_altable_def_t *def);
status_t sql_parse_column_defs(sql_stmt_t *stmt, lex_t *lex, knl_table_def_t *def, bool32 *expect_as);
status_t sql_check_duplicate_column_name(galist_t *columns, const text_t *name);

#define JSON_MAX_SIZE (g_instance->sql.json_mpool.max_json_dyn_buf)
#define JSON_MAX_FUN_ARGS 128
#define JSON_MAX_STRING_LEN (GS_STRING_BUFFER_SIZE - 1)

typedef struct st_json_mem_pool {
    spinlock_t lock;
    uint64 max_json_dyn_buf;
    uint64 used_json_dyn_buf;  // memory used size
} sql_json_mem_pool_t;

status_t sql_build_func_args_json_array(sql_stmt_t *stmt, word_t *word, expr_node_t *func_node, sql_text_t *arg_text);
status_t sql_build_func_args_json_object(sql_stmt_t *stmt, word_t *word, expr_node_t *func_node, sql_text_t *arg_text);
status_t sql_build_func_args_json_retrieve(sql_stmt_t *stmt, word_t *word, expr_node_t *func_node,
                                           sql_text_t *arg_text);
status_t sql_build_func_args_json_query(sql_stmt_t *stmt, word_t *word, expr_node_t *func_node, sql_text_t *arg_text);
status_t sql_build_func_args_json_set(sql_stmt_t *stmt, word_t *word, expr_node_t *func_node, sql_text_t *arg_text);

status_t sql_func_is_json(sql_stmt_t *stmt, expr_tree_t *node, variant_t *result);

status_t sql_verify_json_value(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_json_value(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);

status_t sql_verify_json_query(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_json_query(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);

status_t sql_verify_json_mergepatch(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_json_mergepatch(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);

status_t sql_verify_json_array(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_json_array(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);

status_t sql_verify_json_array_length(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_json_array_length(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);

status_t sql_verify_json_object(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_json_object(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);

status_t sql_verify_json_exists(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_json_exists(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);

status_t sql_verify_json_set(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_json_set(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);

typedef struct st_seqence_info {
    bool32 start_flag;
    bool32 cache_flag;
    bool32 inc_flag;
    bool32 cyc_flag;
    bool32 nomin_flag;
    bool32 nomax_flag;
    bool32 nocache_flag;
    bool32 nocyc_flag;
} sql_seqence_info_t;

status_t sql_parse_ddl(sql_stmt_t *stmt, key_wid_t wid);
status_t sql_parse_drop(sql_stmt_t *stmt);
status_t sql_parse_truncate(sql_stmt_t *stmt);
status_t sql_parse_flashback(sql_stmt_t *stmt);
status_t sql_parse_create(sql_stmt_t *stmt);
status_t sql_parse_create_directory(sql_stmt_t *stmt, bool32 is_replace);
status_t sql_parse_create_library(sql_stmt_t *stmt, bool32 is_replace);
status_t sql_parse_drop_library(sql_stmt_t *stmt);
status_t sql_parse_drop_table(sql_stmt_t *stmt, bool32 is_temp);
status_t sql_parse_drop_tablespace(sql_stmt_t *stmt);
status_t sql_parse_truncate_table(sql_stmt_t *stmt);
status_t sql_parse_flashback_table(sql_stmt_t *stmt);
status_t sql_parse_create_unique_lead(sql_stmt_t *stmt);
status_t sql_check_duplicate_column(galist_t *columns, const text_t *name);
status_t sql_verify_view_def(sql_stmt_t *stmt, knl_view_def_t *def, lex_t *lex, bool32 is_force);
status_t sql_verify_default_column(sql_stmt_t *stmt, knl_table_def_t *def);
status_t sql_verify_check_constraint(sql_stmt_t *stmt, knl_table_def_t *def);
status_t sql_verify_table_storage(sql_stmt_t *stmt, knl_table_def_t *def);
status_t sql_parse_column_defs(sql_stmt_t *stmt, lex_t *lex, knl_table_def_t *def, bool32 *expect_as);
status_t sql_convert_object_name(sql_stmt_t *stmt, word_t *word, text_t *owner, bool32 *owner_explict, text_t *name);
status_t sql_parse_drop_object(sql_stmt_t *stmt, knl_drop_def_t *def);
status_t sql_verify_array_columns(table_type_t type, galist_t *columns);
status_t sql_verify_auto_increment(sql_stmt_t *stmt, knl_table_def_t *def);
status_t sql_part_verify_key_type(typmode_t *typmod);
status_t sql_list_store_define_key(part_key_t *curr_key, knl_part_def_t *parent_part_def, knl_part_obj_def_t *obj_def,
                                   const text_t *part_name);
void sql_unregist_ddl_table(sql_stmt_t *stmt, const text_t *user, const text_t *name);
status_t sql_parse_scope_clause_inner(knl_alter_sys_def_t *def, lex_t *lex, bool32 force);
status_t sql_parse_expected_scope_clause(knl_alter_sys_def_t *def, lex_t *lex);
status_t sql_parse_scope_clause(knl_alter_sys_def_t *def, lex_t *lex);
status_t sql_parse_dc_info(sql_stmt_t *stmt, text_t *schema, text_t *objname, bool32 owner_explict,
                           object_type_t *objtype, text_t *typename);
status_t sql_parse_sequence_info(sql_stmt_t *stmt, text_t *schema, text_t *objname, object_type_t *objtype,
                                 text_t *typename);
status_t sql_parse_pl_info(sql_stmt_t *stmt, text_t *schema, text_t *objname, bool32 owner_explict,
                           object_type_t *objtype, text_t *typename);
status_t sql_parse_directory_info(sql_stmt_t *stmt, text_t *schema, object_type_t *objtype, text_t *typename);
status_t sql_parse_lib_info(sql_stmt_t *stmt, text_t *schema, text_t *objname, object_type_t *objtype,
                            text_t *typename);
status_t sql_check_object_type(sql_stmt_t *stmt, object_type_t *expected_objtype, text_t *typename, text_t *schema,
                               text_t *objname);
status_t sql_parse_auto_primary_key_constr_name(sql_stmt_t *stmt, text_t *constr_name, text_t *sch_name,
                                                text_t *tab_name);
status_t sql_parse_purge_partition(sql_stmt_t *stmt, knl_purge_def_t *def);
status_t sql_list_store_define_key(part_key_t *curr_key, knl_part_def_t *parent_part_def, knl_part_obj_def_t *obj_def,
                                   const text_t *part_name);
status_t sql_part_verify_key_type(typmode_t *typmod);
status_t sql_parse_datafile(sql_stmt_t *stmt, knl_device_def_t *dev_def, word_t *word, bool32 *isRelative);
status_t sql_parse_autoextend_clause_core(device_type_t type, sql_stmt_t *stmt, knl_autoextend_def_t *autoextend_def,
                                          word_t *next_word);
status_t sql_try_parse_if_exists(lex_t *lex, uint32 *options);
status_t sql_try_parse_if_not_exists(lex_t *lex, uint32 *options);
status_t sql_parse_drop_object(sql_stmt_t *stmt, knl_drop_def_t *def);
status_t sql_convert_object_name(sql_stmt_t *stmt, word_t *word, text_t *owner, bool32 *owner_explict, text_t *name);
status_t sql_parse_space(sql_stmt_t *stmt, lex_t *lex, word_t *word, text_t *space);
status_t sql_parse_trans(lex_t *lex, word_t *word, uint32 *trans);
status_t sql_parse_crmode(lex_t *lex, word_t *word, uint8 *cr_mode);
status_t sql_parse_pctfree(lex_t *lex, word_t *word, uint32 *pct_free);
status_t sql_parse_storage(lex_t *lex, word_t *word, knl_storage_def_t *storage_def, bool32 alter);
status_t sql_parse_parallelism(lex_t *lex, word_t *word, uint32 *parallelism, int32 max_parallelism);
status_t sql_parse_reverse(word_t *word, bool32 *is_reverse);
static inline status_t sql_replace_password(sql_stmt_t *stmt, text_t *password)
{
    if (stmt->pl_exec == NULL && stmt->pl_compiler == NULL) {  // can't modify sql in pl
        if (password->len != 0) {
            MEMS_RETURN_IFERR(memset_s(password->str, password->len, '*', password->len));
        }
    }
    return GS_SUCCESS;
}

#define CHECK_CONS_TZ_TYPE_RETURN(col_type)                                                                  \
    do {                                                                                                     \
        if ((col_type) == GS_TYPE_TIMESTAMP_TZ) {                                                            \
            GS_THROW_ERROR(ERR_SQL_SYNTAX_ERROR,                                                             \
                           "column of datatype TIMESTAMP WITH TIME ZONE cannot be unique or a primary key"); \
            return GS_ERROR;                                                                                 \
        }                                                                                                    \
    } while (0)

status_t sql_parse_init_auto_increment(sql_stmt_t *stmt, lex_t *lex, int64 *serial_start);
status_t sql_check_organization_column(knl_table_def_t *def);
status_t sql_parse_coalesce_partition(sql_stmt_t *stmt, lex_t *lex, knl_altable_def_t *def);
status_t sql_parse_check_auto_increment(sql_stmt_t *stmt, word_t *word, knl_altable_def_t *def);
status_t sql_parse_appendonly(lex_t *lex, word_t *word, bool32 *appendonly);
status_t sql_parse_organization(sql_stmt_t *stmt, lex_t *lex, word_t *word, knl_ext_def_t *def);
status_t sql_parse_table_attrs(sql_stmt_t *stmt, lex_t *lex, knl_table_def_t *def, bool32 *expect_as, word_t *word);
status_t sql_parse_row_format(lex_t *lex, word_t *word, bool8 *csf);
status_t sql_parse_table_compress(sql_stmt_t *stmt, lex_t *lex, uint8 *type, uint8 *algo);

/* user update types */
#define DDL_USER_NULL 0
#define DDL_USER_PWD 1
#define DDL_USER_AUDIT 2
#define DDL_USER_READONLY 4
#define DDL_USER_STATUS 8
#define DDL_USER_FAILCOUNT 16
#define DDL_USER_PWD_EXPIRE 32
#define DDL_USER_ACCOUNT_LOCK 64
#define DDL_USER_PROFILE 128
#define DDL_USER_DEFALT_SPACE 256
#define DDL_USER_TMP_SPACE 512
#define DDL_USER_PERMANENT 1024

typedef status_t (*func_check_profile)(knl_profile_def_t *def, variant_t *value, lex_t *lex, uint32 id,
                                       dec8_t *unlimit);

typedef struct st_check_profile {
    func_check_profile func;
} check_profile_t;

status_t sql_parse_create_user(sql_stmt_t *stmt);
status_t sql_parse_drop_user(sql_stmt_t *stmt);
status_t sql_parse_alter_user(sql_stmt_t *stmt);
status_t sql_parse_create_role(sql_stmt_t *stmt);
status_t sql_parse_drop_role(sql_stmt_t *stmt);
status_t sql_parse_create_tenant(sql_stmt_t *stmt);
status_t sql_parse_create_profile(sql_stmt_t *stmt, bool32 is_replace);
status_t sql_parse_alter_profile(sql_stmt_t *stmt);
status_t sql_parse_drop_profile(sql_stmt_t *stmt);
status_t sql_parse_alter_tenant(sql_stmt_t *stmt);
status_t sql_parse_drop_tenant(sql_stmt_t *stmt);

// cbo
#define CBO_MIN_COST (double)0
#define CBO_MAX_COST (double)0xFFFFFFFFFFFF
#define CBO_DUMMY_COST (double)0.003
#define CBO_MAX_ROWS (int64)0xFFFFFFFFF
#define CBO_DEFAULT_NDV (uint32)1
#define CBO_DEFAULT_MAX_NDV (uint32)100000000
#define CBO_SCALE_MIN_ROWNUM (uint32)25
#define TABLE_NAME(table) (((table)->alias.len > 0) ? T2S(&(table)->alias.value) : T2S(&(table)->name.value))
#define INDEX_NAME(table) (((table)->index != NULL) ? (table)->index->name : "NULL")
#define TABLE_COST(table) (TABLE_CBO_IS_LOAD(table) ? CBO_MIN_COST : (table)->cost)
#define IS_INDEX_UNIQUE(index) (((index)->primary || (index)->unique))
#define IS_WITHAS_QUERY(query) (bool32)((query)->owner != NULL && (query)->owner->is_withas)
#define IS_NL_OPER(oper) (bool32)((oper) == JOIN_OPER_NL || (oper) == JOIN_OPER_NL_LEFT || (oper) == JOIN_OPER_NL_FULL)
#define IS_HASH_OPER(oper)                                                                                 \
    (bool32)((oper) == JOIN_OPER_HASH || (oper) == JOIN_OPER_HASH_LEFT || (oper) == JOIN_OPER_HASH_FULL || \
             (oper) == JOIN_OPER_HASH_RIGHT_LEFT)
#define IS_SEMI_OPER(oper) (bool32)((oper) >= JOIN_OPER_HASH_SEMI)
#define IS_CARTESIAN_COND(cond) (((cond) == NULL) || ((cond) == &g_fake_inner_join_cond))
#define IS_JOIN_TABLE(jnd) ((jnd)->type == JOIN_TYPE_NONE)
#define GET_JOIN_NODE_COND(join_root) (IS_INNER_JOIN(join_root) ? (join_root)->filter : (join_root)->join_cond);
#define TABLE_HAS_DEP_TABLES(table) (TABLE_CBO_DEP_TABLES(table) && (TABLE_CBO_DEP_TABLES(table)->count > 0))

// Rule base optimization, cost estimate referenced by RBO planner
#define RBO_COST_ROWID_SCAN (double)1
#define RBO_COST_SUB_QUERY_SCAN (double)0  // sub query

// heap table
#define RBO_COST_UNIQUE_POINT_SCAN (double)15  // unique index (or primary key) point scan
#define RBO_COST_UNIQUE_LIST_SCAN (double)30   // unique index (or primary key) list  scan
#define RBO_COST_INDEX_POINT_SCAN (double)50   // index point scan
#define RBO_COST_INDEX_LIST_SCAN (double)80    // index list  scan
#define RBO_COST_INDEX_RANGE_SCAN (double)400  // index range scan
#define RBO_COST_PRE_INDEX_SCAN (double)2000   // prefix index scan
#define RBO_COST_FULL_INDEX_SCAN (double)9000  // index specified by INDEX hint, but it not in condition
#define RBO_COST_FULL_TABLE_SCAN (double)10000
#define RBO_COST_INFINITE (double)0xFFFFFFFFFF

// temp table
#define RBO_TEMP_COST_UNIQUE_POINT_SCAN (double)5  // unique index (or primary key) point scan
#define RBO_TEMP_COST_UNIQUE_LIST_SCAN (double)20  // unique index (or primary key) list  scan
#define RBO_TEMP_COST_INDEX_POINT_SCAN (double)35  // index point scan
#define RBO_TEMP_COST_INDEX_LIST_SCAN (double)38   // index list  scan
#define RBO_TEMP_COST_INDEX_RANGE_SCAN (double)40  // index range scan
#define RBO_TEMP_COST_PRE_INDEX_SCAN (double)42    // prefix index scan
#define RBO_TEMP_COST_FULL_INDEX_SCAN (double)45   // index specified by INDEX hint, but it not in condition
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

#define INDEX_MATCH_PARTFILED(scan_flag) ((scan_flag)&RBO_INDEX_MATCH_PARTFIELD_FLAG)
#define INDEX_ONLY_SCAN(scan_flag) ((scan_flag)&RBO_INDEX_ONLY_FLAG)
#define CAN_INDEX_SORT(scan_flag) ((scan_flag)&RBO_INDEX_SORT_FLAG)
#define CAN_INDEX_GROUP(scan_flag) ((scan_flag)&RBO_INDEX_GROUP_FLAG)
#define CAN_INDEX_DISTINCT(scan_flag) ((scan_flag)&RBO_INDEX_DISTINCT_FLAG)
#define INDEX_SORT_SCAN(scan_flag) ((scan_flag)&INDEX_SORT_SCAN_MASK)
#define INDEX_NL_PREFETCH(scan_flag) (((scan_flag)&RBO_NL_PREFETCH_FLAG) != 0)
#define SORT_DISTINCT_FACTOR 0.75
// has index_only, but no index_sort
#define INDEX_ONLY_SCAN_ONLY(scan_flag) (INDEX_ONLY_SCAN(scan_flag) && !(INDEX_SORT_SCAN(scan_flag)))
// index_sort better than index_only, index_sort&only better than index_sort or index_only
#define IS_BETTER_INDEX_SCAN(scan_flag1, scan_flag2) \
    (((scan_flag1)&BETTER_INDEX_SCAN_MASK) > ((scan_flag2)&BETTER_INDEX_SCAN_MASK))

/* if table entry is null, table is remote table */
#define IS_TEMP_TABLE(table)                                                               \
    ((table)->entry != NULL && ((table)->entry->dc.type == DICT_TYPE_TEMP_TABLE_SESSION || \
                                (table)->entry->dc.type == DICT_TYPE_TEMP_TABLE_TRANS))
#define IS_DYNAMIC_VIEW(table) \
    ((table)->entry != NULL && \
     ((table)->entry->dc.type == DICT_TYPE_DYNAMIC_VIEW || (table)->entry->dc.type == DICT_TYPE_GLOBAL_DYNAMIC_VIEW))
#define RBO_INDEX_FULL_SCAN_COST(table) \
    (IS_TEMP_TABLE(table) ? RBO_TEMP_COST_FULL_INDEX_SCAN : RBO_COST_FULL_INDEX_SCAN)
#define RBO_TABLE_FULL_SCAN_COST(table) \
    (IS_TEMP_TABLE(table) ? RBO_TEMP_COST_FULL_TABLE_SCAN : RBO_COST_FULL_TABLE_SCAN)

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

typedef enum en_range_list_type {
    RANGE_LIST_EMPTY = 0,
    RANGE_LIST_FULL,
    RANGE_LIST_NORMAL,
} range_list_type_t;

typedef struct st_plan_rowid_set {
    range_list_type_t type;
    sql_array_t array;  // rowid list
} plan_rowid_set_t;

typedef struct st_scan_plan {
    sql_table_t *table;
    sql_array_t index_array;      // for index scan
    sql_array_t part_array;       // for part scan
    sql_array_t subpart_array;    // for subpart scan
    plan_rowid_set_t *rowid_set;  // store rowid expr_trees for rowid scan
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
    galist_t *items;  // order by items, the structure of items is sort_item_t
    struct st_plan_node *next;
    galist_t *select_columns;  // columns before execute order by
    bool32 has_pending_rs;
    uint32 rownum_upper;
} query_sort_plan_t;

typedef struct st_select_sort_plan {
    galist_t *items;  // order by items, the structure of items is sort_item_t
    struct st_plan_node *next;
    galist_t *rs_columns;  // rs_column of select after execute order by
} select_sort_plan_t;

typedef struct st_sort_plan {
    galist_t *items;  // order by items, the structure of items is sort_item_t
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
    galist_t *sets;   // group by sets
    galist_t *exprs;  // group by exprs
    galist_t *aggrs;
    galist_t *cntdis_columns;
    galist_t *sort_groups;
    galist_t *sort_items;  // sort items in listagg
    uint32 aggrs_args;     // number of values in group aggrs
    uint32 aggrs_sorts;    // number of sort items in group aggrs
    struct st_plan_node *next;
    struct st_pivot_assist *pivot_assist;  // for pivot
    bool32 multi_prod;                     // used to judge the parallel mode is single producer or multi producers
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
    galist_t *sets;   // list of group_set_t
    galist_t *nodes;  // list of cube_node_t
    galist_t *plans;  // list of plan_node_t, sub plans
    struct st_plan_node *next;
} cube_plan_t;

typedef struct st_distinct_plan {
    galist_t *columns;         // distinct columns
    btree_sort_t *btree_sort;  // for sort distinct which can eliminate order by
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
    galist_t *prior_exprs;  // for is_cycle checking
} connect_plan_t;

typedef struct st_filter_plan {
    cond_tree_t *cond;
    struct st_plan_node *next;
} filter_plan_t;

typedef struct st_query_plan {
    sql_query_t *ref;           // reference sql query context
    struct st_plan_node *next;  // mertialized result set / table scan ...
} query_plan_t;

typedef struct st_union_plan {
    galist_t *rs_columns;     // rs_column
    galist_t *union_columns;  // rs_column
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
    bool32 minus_left;  // // build hash table on minus/intersect left cursor
} minus_plan_t;

typedef struct st_union_all_plan {
    uint32 exec_id;
    bool32 par_exec;
} union_all_plan_t;

typedef struct st_set_plan {  // union, union all, ...
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
    galist_t *rs_columns;  // for materialize rs
    sql_select_t *select;
    struct st_plan_node *next;
} select_plan_t;

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
        distinct_plan_t distinct;
        filter_plan_t filter;
        query_plan_t query;
        select_plan_t select_p;
        scan_plan_t scan_p;
        set_plan_t set_p;  // union, union all, intersect, minus
        rownum_plan_t rownum_p;
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
    uint32 table_count;  // table count
    uint32 plan_count;   // count of planned table

    struct st_plan_assist *top_pa;  // for CBO use
    struct st_plan_assist *parent;  // for join cond push down
    uint32 save_plcnt;
    uint32 cbo_index_ast;
    uint16 cbo_flags;  // for save pa->cbo_flags
    uint16 col_use_flag;
    uint16 max_ancestor;
    uint16 spec_drive_flag;  // for special drive table index to eliminate sort/group/distinct etc.

    struct {
        bool32 has_parent_join : 1;
        bool32 has_bind_param : 1;
        bool32 no_nl_batch : 1;      // add for not choose batch_nl join plan
        bool32 resv_outer_join : 1;  // flag indicates reserve old outer join table order
        bool32 ignore_hj : 1;        // flag indicates not calc hash join
        bool32 is_final_plan : 1;
        bool32 is_subqry_cost : 1;  // flag for cbo_get_query_cost
        bool32 is_nl_full_opt : 1;
        bool32 vpeek_flag : 1;
        bool32 reserved : 23;
    };

    uint16 nlf_mtrl_cnt;       // count of nl full rowid mtrl
    uint16 nlf_dupl_plan_cnt;  // count of nl full dupl plan
    cond_tree_t *cond;
    sql_query_t *query;
    galist_t *sort_items;                          // additional columns for index chosen
    sql_table_t *tables[GS_MAX_JOIN_TABLES];       // sorted by sequence in sql text
    sql_table_t *plan_tables[GS_MAX_JOIN_TABLES];  // sorted by planner
    sql_join_assist_t *join_assist;
    uint32 list_expr_count;  // in/or condition expr list count
    sql_node_type_t type;
    uint32 hj_pos;
    uint8 *join_oper_map;
    sql_stmt_t *stmt;
    bilist_t join_conds;
    uint32 scan_part_cnt;  // only use part table
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
    table->rowid_usable = GS_FALSE;
    table->scan_mode = SCAN_MODE_TABLE_FULL;
    table->col_use_flag = 0;
    table->index_ffs = GS_FALSE;
    table->index_full_scan = GS_FALSE;
    table->index_skip_scan = GS_FALSE;
    table->skip_index_match = GS_FALSE;
    table->opt_match_mode = COLUMN_MATCH_NONE;
    table->index_match_count = 0;
    table->idx_equal_to = 0;
    table->equal_cols = 0;
    table->idx_col_map = NULL;
    table->cost = RBO_TABLE_FULL_SCAN_COST(table);
}

bool32 sql_like_indexable(sql_stmt_t *stmt, cmp_node_t *node, column_match_mode_t *match_mode);

#define HAS_ONLY_NL_OPER(flag) \
    (((flag) == JOIN_OPER_NL) || ((flag) == JOIN_OPER_NL_LEFT) || ((flag) == JOIN_OPER_NL_BATCH))

status_t sql_create_dml_plan(sql_stmt_t *stmt);
status_t sql_check_table_indexable(sql_stmt_t *stmt, plan_assist_t *pa, sql_table_t *table, cond_tree_t *cond);
status_t sql_create_table_scan_plan(sql_stmt_t *stmt, plan_assist_t *pa, cond_tree_t *cond, sql_table_t *table,
                                    plan_node_t **plan);
status_t sql_get_rowid_cost(sql_stmt_t *stmt, plan_assist_t *pa, cond_node_t *cond, sql_table_t *table, bool32 is_temp);
status_t sql_make_index_col_map(plan_assist_t *pa, sql_stmt_t *stmt, sql_table_t *table);

status_t sql_generate_insert_plan(sql_stmt_t *stmt, sql_insert_t *insert_ctx, plan_assist_t *parent);
status_t sql_generate_merge_into_plan(sql_stmt_t *stmt, sql_merge_t *merge_ctx, plan_assist_t *parent);
status_t sql_generate_delete_plan(sql_stmt_t *stmt, sql_delete_t *delete_ctx, plan_assist_t *parent);
status_t sql_generate_select_plan(sql_stmt_t *stmt, sql_select_t *select_ctx, plan_assist_t *parent);
status_t sql_generate_update_plan(sql_stmt_t *stmt, sql_update_t *update_ctx, plan_assist_t *parent);
status_t sql_create_subselect_plan(sql_stmt_t *stmt, sql_query_t *query, plan_assist_t *pa);
void check_table_stats(sql_stmt_t *stmt);
void cbo_unset_select_node_table_flag(select_node_t *select_node, uint32 cbo_flag, bool32 recurs);
void cbo_set_select_node_table_flag(select_node_t *select_node, uint32 cbo_flag, bool32 recurs);

// RBO|CBO interface declare
status_t rbo_table_indexable(sql_stmt_t *stmt, plan_assist_t *pa, sql_table_t *table, cond_node_t *cond,
                             bool32 *result);
status_t rbo_choose_full_scan_index(sql_stmt_t *stmt, plan_assist_t *pa, sql_table_t *table, bool32 chk_sort);

void sql_prepare_query_plan(sql_stmt_t *stmt, plan_assist_t *pa, sql_query_t *query, sql_node_type_t type,
                            plan_assist_t *parent);

/* the following functions means CBO open or close */
bool32 sql_match_cbo_cond(sql_stmt_t *stmt, sql_table_t *table, sql_query_t *query);
void reset_select_node_cbo_status(select_node_t *node);
void sql_collect_select_nodes(biqueue_t *que, select_node_t *node);
typedef status_t (*query_visit_func_t)(sql_stmt_t *stmt, sql_query_t *query);
status_t visit_select_node(sql_stmt_t *stmt, select_node_t *node, query_visit_func_t visit_func);
bool32 sql_expr_is_certain(plan_assist_t *pa, expr_tree_t *expr, var_column_t *v_col);
void sql_init_plan_assist(sql_stmt_t *stmt, plan_assist_t *pa, sql_query_t *query, sql_node_type_t type,
                          plan_assist_t *parent);
uint32 get_query_plan_flag(sql_query_t *query);
plan_assist_t *sql_get_ancestor_pa(plan_assist_t *curr_pa, uint32 temp_ancestor);
sql_query_t *sql_get_ancestor_query(sql_query_t *query, uint32 ancestor);
status_t can_rewrite_by_check_index(sql_stmt_t *stmt, sql_query_t *query, ck_type_t cktype, bool32 *result);
status_t rbo_check_index_4_rewrite(sql_stmt_t *stmt, sql_query_t *query, bool32 *result);
plan_node_type_t sql_get_group_plan_type(sql_stmt_t *stmt, sql_query_t *query);
status_t add_cbo_depend_tab(sql_stmt_t *stmt, sql_table_t *table, uint32 tab_no);
uint32 sql_get_plan_hash_rows(sql_stmt_t *stmt, plan_node_t *plan);
status_t sql_create_query_plan_ex(sql_stmt_t *stmt, sql_query_t *query, plan_assist_t *pa, plan_node_t **plan);
bool32 sql_can_hash_mtrl_support_aggtype(sql_stmt_t *stmt, sql_query_t *query);
status_t sql_clone_join_root(sql_stmt_t *stmt, void *ctx, sql_join_node_t *src_join_root,
                             sql_join_node_t **dst_join_root, sql_array_t *tables, ga_alloc_func_t alloc_mem_func);
void swap_join_tree_child_node(plan_assist_t *pa, sql_join_node_t *join_root);
bool32 if_is_drive_table(sql_join_node_t *join_node, uint16 tab);
void clear_query_cbo_status(sql_query_t *query);
status_t build_query_join_tree(sql_stmt_t *stmt, sql_query_t *query, plan_assist_t *parent, sql_join_node_t **ret_root,
                               uint32 driver_table_count);
uint32 sql_calc_rownum(sql_stmt_t *stmt, sql_query_t *query);
status_t perfect_tree_and_gen_oper_map(plan_assist_t *pa, uint32 step, sql_join_node_t *join_node);
status_t sql_dynamic_sampling_table_stats(sql_stmt_t *stmt, plan_assist_t *pa);
bool32 sql_query_has_hash_join(sql_query_t *query);
status_t clone_tables_4_subqry(sql_stmt_t *stmt, sql_query_t *query, sql_query_t *subqry);
void sql_init_plan_assist_impl(sql_stmt_t *stmt, plan_assist_t *pa, sql_query_t *query, sql_node_type_t type,
                               plan_assist_t *parent);
sql_table_t *sql_get_driver_table(plan_assist_t *pa);
status_t remove_pushed_down_join_cond(sql_stmt_t *stmt, plan_assist_t *pa, sql_array_t *tables);

#define IS_REVERSE_INDEX_AVAILABLE(match_mode, idx_col_id) \
    ((match_mode) == COLUMN_MATCH_POINT || ((match_mode) == COLUMN_MATCH_LIST && (idx_col_id) == 0))
#define SCALE_BY_LIMIT_EXCL                                                                                           \
    (EX_QUERY_WINSORT | EX_QUERY_HAVING | EX_QUERY_CUBE | EX_QUERY_PIVOT | EX_QUERY_FOR_UPDATE | EX_QUERY_SIBL_SORT | \
     EX_QUERY_CONNECT)

#define SCALE_BY_ROWNUM_EXCL (EX_QUERY_SIBL_SORT | EX_QUERY_CONNECT)
#define MAX_NL_FULL_DUPL_PLAN_COUNT 4
#define IS_EQUAL_TYPE(join_type)                                                                           \
    ((join_type) == JOIN_TYPE_INNER || (join_type) == JOIN_TYPE_COMMA || (join_type) == JOIN_TYPE_CROSS || \
     (join_type) == JOIN_TYPE_FULL)
#define IS_INNER_TYPE(join_type) \
    ((join_type) == JOIN_TYPE_INNER || (join_type) == JOIN_TYPE_COMMA || (join_type) == JOIN_TYPE_CROSS)
#define IS_INNER_JOIN(join_root) IS_INNER_TYPE((join_root)->type)
#define IS_LEFT_JOIN(join_root) ((join_root)->type == JOIN_TYPE_LEFT)
#define IS_FULL_JOIN(join_root) ((join_root)->type == JOIN_TYPE_FULL)
#define IS_SEMI_JOIN(join_root)                                                                 \
    ((join_root)->oper == JOIN_OPER_HASH_ANTI || (join_root)->oper == JOIN_OPER_HASH_ANTI_NA || \
     (join_root)->oper == JOIN_OPER_HASH_SEMI)
static inline void sql_plan_assist_set_table(plan_assist_t *pa, sql_table_t *table)
{
    table->plan_id = pa->plan_count;
    pa->plan_tables[pa->plan_count++] = table;

    if (table->sub_tables != NULL) {
        for (uint32 i = 0; i < table->sub_tables->count; i++) {
            sql_table_t *sub_table = (sql_table_t *)cm_galist_get(table->sub_tables, i);
            sub_table->plan_id = table->plan_id;
        }
    }
}

#define IF_LOCK_IN_FETCH(query) \
    ((query)->tables.count == 1 || (query)->connect_by_cond != NULL || (query)->incl_flags & (EXPR_INCL_ROWNUM))

status_t sql_extract_prior_cond_node(sql_stmt_t *stmt, cond_node_t *cond_node, cond_tree_t **dst_tree);
bool32 sql_sort_index_matched(sql_query_t *query, galist_t *sortitems, plan_node_t *nextplan);
bool32 if_parent_changes_rows_count(sql_query_t *query, uint32 *rownum_upper);
status_t get_limit_total_value(sql_stmt_t *stmt, sql_query_t *query, uint32 *rownum_upper);
status_t sql_create_mtrl_plan_rs_columns(sql_stmt_t *stmt, sql_query_t *query, galist_t **plan_rs_columns);
status_t sql_create_query_plan(sql_stmt_t *stmt, sql_query_t *query, sql_node_type_t type, plan_node_t **query_plan,
                               plan_assist_t *parent);
cond_tree_t *sql_get_rownum_cond(sql_stmt_t *stmt, sql_query_t *query);

typedef enum en_range_type {
    RANGE_EMPTY = 0,
    RANGE_FULL,
    RANGE_SECTION,
    RANGE_POINT,
    RANGE_LIST,
    RANGE_LIKE,
    RANGE_ANY,
    RANGE_UNKNOWN
} range_type_t;

typedef enum en_border_wise_t {
    WISE_LEFT,
    WISE_RIGHT,
} border_wise_t;

typedef enum en_border_type {
    BORDER_INFINITE_LEFT,
    BORDER_INFINITE_RIGHT,
    BORDER_CONST,
    BORDER_CALC,
    BORDER_IS_NULL,
} border_type_t;

typedef struct st_plan_border {
    expr_tree_t *expr;
    border_type_t type;
    bool32 closed;
} plan_border_t;

typedef struct st_plan_range {
    range_type_t type;
    gs_type_t datatype;
    plan_border_t left;
    plan_border_t right;
} plan_range_t;

typedef struct st_plan_range_list {
    range_list_type_t type;
    typmode_t typmode;
    galist_t *items;  // range list
} plan_range_list_t;

#define LIST_EXIST_LIST_EMPTY 0x0001
#define LIST_EXIST_LIST_FULL 0x0002
#define LIST_EXIST_RANGE_UNEQUAL 0x0004
#define LIST_EXIST_LIST_UNKNOWN 0X0008
#define LIST_EXIST_LIST_ANY 0X0010
#define LIST_EXIST_MULTI_RANGES 0X0020

#define MAX_CACHE_COUNT 5

typedef struct st_scan_border {
    variant_t var;
    border_type_t type;
    bool32 closed;
} scan_border_t;

typedef struct st_scan_range {
    scan_border_t left;
    scan_border_t right;
    range_type_t type;
} scan_range_t;

typedef struct st_scan_range_list {
    range_list_type_t type;
    gs_type_t datatype;
    scan_range_t **ranges;
    uint32 count;
    uint32 rid;
} scan_range_list_t;

typedef struct st_scan_list_info {
    scan_range_list_t *scan_list;
    uint32 tab_id;
    uint32 index_id;
    uint32 ar_countid;
    uint32 flags;
} scan_list_info;

typedef struct st_scan_list_array {
    scan_range_list_t *items;
    uint32 count;
    uint32 flags;
    uint32 total_ranges;
} scan_list_array_t;

typedef struct st_part_scan_key {
    uint32 left;
    uint32 right;
    uint32 parent_partno;
    galist_t *sub_scan_key;  // if sub_scan_key != null is sub part
} part_scan_key_t;

typedef struct st_part_assist {
    uint32 count;
    part_scan_key_t *scan_key;
} part_assist_t;

typedef enum e_calc_mode {
    CALC_IN_PLAN,
    CALC_IN_EXEC,
    CALC_IN_EXEC_PART_KEY,
} calc_mode_t;

typedef status_t (*sql_convert_border_t)(sql_stmt_t *stmt, knl_index_desc_t *index, scan_border_t *border,
                                         gs_type_t datatype, uint32 cid, void *key);

#define SQL_GET_BORDER_TYPE(expr_type) (expr_type) == EXPR_NODE_CONST ? BORDER_CONST : BORDER_CALC

status_t sql_create_scan_ranges(sql_stmt_t *stmt, plan_assist_t *pa, sql_table_t *table, scan_plan_t *scan_plan);
status_t sql_create_rowid_set(sql_stmt_t *stmt, plan_assist_t *pa, sql_table_t *table, cond_node_t *node,
                              plan_rowid_set_t **plan_rid_set, bool32 is_temp);
status_t sql_create_part_scan_ranges(sql_stmt_t *stmt, plan_assist_t *pa, sql_table_t *table, sql_array_t *array);
status_t sql_create_subpart_scan_ranges(sql_stmt_t *stmt, plan_assist_t *pa, sql_table_t *table,
                                        sql_array_t *subpart_array);

status_t sql_check_border_variant(sql_stmt_t *stmt, variant_t *var, gs_type_t datatype, uint32 size);
status_t sql_generate_part_scan_key(sql_stmt_t *stmt, knl_handle_t handle, scan_list_array_t *ar, part_assist_t *pa,
                                    uint32 parent_partno, bool32 *full_scan);
status_t sql_make_border_l(sql_stmt_t *stmt, knl_index_desc_t *index_desc, scan_list_array_t *ar, uint32 rid, void *key,
                           bool32 *closed, sql_convert_border_t sql_convert_border_func);
status_t sql_make_border_r(sql_stmt_t *stmt, knl_index_desc_t *index_desc, scan_list_array_t *ar, uint32 rid, void *key,
                           bool32 *closed, bool32 *equal, sql_convert_border_t sql_convert_border_func);
status_t clone_buff_consuming_type(vmc_t *vmc, scan_border_t *dest, scan_border_t *src);
status_t sql_clone_scan_list_ranges(vmc_t *vmc, scan_range_t **list_range, scan_range_t *src_range);
status_t sql_clone_scan_list(vmc_t *vmc, scan_range_list_t *src_scan_list, scan_range_list_t **dest_scan_list);
status_t sql_init_index_scan_range_ar(vmc_t *vmc, galist_t **range_ar);
status_t sql_cache_range(galist_t **list, scan_list_array_t *ar, scan_range_list_t *src_scan_list, vmc_t *vmc,
                         sql_table_t *table, uint32 ar_countid, calc_mode_t calc_mode);
status_t sql_finalize_scan_range(sql_stmt_t *stmt, sql_array_t *plan_ranges, scan_list_array_t *ar, sql_table_t *table,
                                 sql_cursor_t *cursor, galist_t **list, calc_mode_t calc_mode);
void sql_make_range(cmp_type_t cmp_type, expr_tree_t *expr, plan_range_t *range);
bool32 sql_inter_const_range(sql_stmt_t *stmt, plan_border_t *border1, plan_border_t *border2, bool32 is_left,
                             plan_border_t *result);
status_t sql_verify_const_range(sql_stmt_t *stmt, plan_range_t *result);
status_t sql_create_range_list(sql_stmt_t *stmt, plan_assist_t *pa, expr_node_t *match_node, knl_column_t *knl_col,
                               cond_node_t *node, plan_range_list_t **list, bool32 index_reverse,
                               bool32 index_first_col);
status_t sql_finalize_range_list(sql_stmt_t *stmt, plan_range_list_t *plan_list, scan_range_list_t *scan_list,
                                 uint32 *list_flag, calc_mode_t calc_mode, uint32 *is_optm);
bool32 sql_cmp_range_usable(plan_assist_t *pa, cmp_node_t *node, expr_node_t *match_node);
#define GS_MAX_VM_VIEW_ROWS 1000000
#define GS_MAX_VM_VIEW_MTRL_COUNT 5

status_t sql_create_subselect_expr_plan(sql_stmt_t *stmt, sql_array_t *ssa, plan_assist_t *parent);
status_t sql_create_subselect_plan(sql_stmt_t *stmt, sql_query_t *query, plan_assist_t *pa);
#define FUNC_TABLE_COST 512
status_t sql_create_query_scan_plan(sql_stmt_t *stmt, plan_assist_t *pa, plan_node_t **plan);
bool32 sql_has_hash_join_oper(sql_join_node_t *join_node);

typedef status_t (*sys_privs_chk_func)(sql_stmt_t *stmt, sys_privs_id base_privid, sys_privs_id any_privid);

typedef struct st_priv_tab_def {
    sys_privs_id base_privid;
    sys_privs_id any_privid;
    sys_privs_chk_func proc;
} priv_tab_def;

typedef struct st_sql_priv_check_t {
    priv_type_def priv_type;
    galist_t *priv_list;
    text_t *objowner;
    text_t *objname;
    object_type_t objtype;
} sql_priv_check_t;

status_t sql_check_trigger_priv(sql_stmt_t *stmt, void *entity_in);
status_t sql_check_privilege(sql_stmt_t *stmt, bool32 need_lock_ctrl);
status_t sql_check_seq_priv(sql_stmt_t *stmt, text_t *user, text_t *seqname);
status_t sql_check_library_priv_core(sql_stmt_t *stmt, text_t *obj_owner, text_t *obj_name, text_t *curr_user);
status_t sql_check_proc_priv_core(sql_stmt_t *stmt, text_t *obj_owner, text_t *obj_name, text_t *curr_user);
status_t sql_check_type_priv_core(sql_stmt_t *stmt, text_t *obj_owner, text_t *obj_name, text_t *curr_user);
status_t sql_check_inherit_priv(sql_stmt_t *stmt, text_t *obj_user);
status_t sql_check_exec_type_priv(sql_stmt_t *stmt, text_t *obj_owner, text_t *obj_name);
status_t sql_check_grant_revoke_priv(sql_stmt_t *stmt, sql_priv_check_t *priv_check);
status_t sql_check_user_select_priv(knl_session_t *session, text_t *checked_user, text_t *owner, text_t *objname,
                                    object_type_t objtype, bool32 for_update);

bool32 sql_user_is_dba(session_t *session);
bool32 sql_check_schema_priv(session_t *session, text_t *obj_schema);
bool32 sql_check_stats_priv(session_t *session, text_t *obj_schema);
bool32 sql_check_policy_exempt(session_t *session);
status_t sql_check_profile_priv(sql_stmt_t *stmt, sys_privs_id base_privid, sys_privs_id any_privid);
status_t sql_check_priv(sql_stmt_t *stmt, text_t *curr_user, text_t *object_user, sys_privs_id base_privid,
                        sys_privs_id any_privid);
status_t sql_check_table_priv_by_name(sql_stmt_t *stmt, text_t *curr_user, text_t *owner, text_t *objname,
                                      uint32 priv_id);
status_t sql_check_user_tenant(knl_session_t *session);
status_t sql_check_xa_priv(knl_session_t *se, xa_xid_t *xa_xid);
status_t sql_check_dump_priv(sql_stmt_t *stmt, knl_alter_sys_def_t *def);
status_t sql_check_pl_dc_lst_priv(sql_stmt_t *stmt, galist_t *pl_dc_lst, text_t *checked_user);
status_t sql_check_create_trig_priv(sql_stmt_t *stmt, text_t *obj_owner, text_t *table_user);
status_t sql_check_ple_dc_priv(sql_stmt_t *stmt, void *pl_dc_in);
status_t sql_check_dml_privs(sql_stmt_t *stmt, bool32 need_lock_ctrl);
status_t sql_check_single_select_priv(sql_stmt_t *stmt, sql_select_t *select, text_t *checked_user);

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
    void *key_data;  // id of key data which restored in vma
    uint32 offset;
    key_set_type_t type;
} key_set_t;

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
    sql_table_t *table;  // table/subselect description
    union {
        knl_cursor_t *knl_cur;          // for kernel table
        struct st_sql_cursor *sql_cur;  // for subselect
    };
    knl_cursor_action_t action;
    knl_scan_mode_t scan_mode;
    union {
        struct {
            key_set_t key_set;             // for index scan, the id of first indexed column's range
            key_set_t part_set;            // for part scan
            part_scan_key_t curr_part;     // for part scan
            part_scan_key_t curr_subpart;  // for subpart scan
            uint32 part_scan_index;        // curr compart index in scan range
            mps_ctx_t multi_parts_info;    // for multi parts fetch optim
        };
        json_table_exec_t json_table_exec;
    };

    bool32 hash_table;         // for multi delete/update, hash join table
    tf_scan_flag_t scan_flag;  // Parallel Scan Indicator
    struct st_par_scan_range range;
    uint64 scn;
    vmc_t vmc;
} sql_table_cursor_t;

#define PENDING_HEAD_SIZE sizeof(uint32)

typedef struct st_mtrl_sibl_sort {
    uint32 sid;  // cache rowid list of the sub-segments,each non-leaf node has a sub-segment
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
    uint32 rs_vmid;  // for hash minus row buf
    uint32 rnums;    // rows left in hash table
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
    struct st_sql_cursor *cur_level_cursor;  // only first_level_cursor's cur_level_cursor is not null, others is null
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
    galist_t *sets;      // list of group_set_t
    galist_t *nodes;     // list of cube_node_t
    galist_t *plans;     // list of plan_node_t
    biqueue_t curs_que;  // queue of sub-cursor
    cube_node_t **maps;  // node maps by group_id
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
    bool8 need_swap_driver;  // left plan is fetched over
    bool8 left_empty;
    plan_node_t *right_plan;
    plan_node_t *left_plan;
    cond_tree_t *cond;
    cond_tree_t *filter;
    struct st_nl_full_opt_ctx *nl_full_opt_ctx;
} outer_join_data_t;

typedef struct st_inner_join_data {
    bool32 right_fetched;  // right plan is first fetched
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
    knl_cursor_t *ext_knl_cur;      // for on duplicate key update or replace delete
    hash_right_semi_t *right_semi;  // for hash join right semi
    char *dv_plan_buf;              // for dv_sql_plan knl cursor
} plan_exec_data_t;

typedef enum e_hash_table_oper_type { OPER_TYPE_INSERT = 1, OPER_TYPE_FETCH = 2 } hash_table_opertype_t;

typedef enum en_group_type {
    HASH_GROUP_TYPE,
    SORT_GROUP_TYPE,
    HASH_GROUP_PIVOT_TYPE,
    HASH_GROUP_PAR_TYPE,
} group_type_t;

typedef enum en_group_by_phase { GROUP_BY_INIT, GROUP_BY_PARALLEL, GROUP_BY_COLLECT, GROUP_BY_END } group_by_phase_t;

typedef enum en_distinct_type { HASH_DISTINCT, SORT_DISTINCT, HASH_UNION } distinct_type_t;

typedef struct st_unpivot_ctx {
    uint32 row_buf_len;
    char *row_buf;
} unpivot_ctx_t;

/* used to store the row count skipped by limit offset or limit count */
typedef struct st_found_rows_info {
    uint64 offset_skipcount;
    uint64 limit_skipcount;
} found_rows_info_t;

typedef struct st_merge_into_hash_data {
    bool32 already_update;
} merge_into_hash_data_t;

typedef struct st_semi_flag {
    uint32 flag;
    bool32 eof;
} semi_flag_t;

typedef struct st_semi_anchor {
    semi_flag_t semi_flags[GS_MAX_JOIN_TABLES];
} semi_anchor_t;

typedef struct st_hash_material {
    struct st_sql_cursor *hj_tables[GS_MAX_JOIN_TABLES]; /* for build hash table */
} hash_material_t;

typedef struct st_sql_par_mgr sql_par_mgr_t;
typedef struct st_sql_cursor_par_ctx {
    sql_par_mgr_t *par_mgr;  // used for parallel sql
    bool32 par_threads_inuse : 1;
    bool32 par_need_gather : 1;  // if need to gather results from workers
    volatile bool32 par_fetch_st : 2;
    bool32 par_exe_flag : 1;  // for parallel avg
    uint32 par_parallel : 8;
    uint32 unused : 19;
} sql_cursor_par_ctx_t;

typedef enum st_hash_table_status {
    HASH_TABLE_STATUS_NOINIT = 0,
    HASH_TABLE_STATUS_CREATE = 1,
    HASH_TABLE_STATUS_CLONE = 2,
} hash_table_status_t;

typedef struct st_idx_func_cache_t {
    expr_node_t *node;  // key
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
    sql_query_t *query;  // for select
    galist_t *columns;   // rs_column_t, for non materialized result set, from sql_query_t
    mtrl_page_t *aggr_page;
    uint32 total_rows;
    uint32 rownum;
    uint32 max_rownum;
    // don't change the definition order of prev and next
    // so sql_cursor_t can be change to biqueue_node_t by macro QUEUE_NODE_OF and be added to a bi-queue
    struct st_sql_cursor *prev;
    struct st_sql_cursor *next;
    struct st_sql_cursor *cursor_maps[GS_MAX_SUBSELECT_EXPRS];  // subselect exprs
    biqueue_t ssa_cursors;                                      // subselect exprs
    uint32 last_table;                                          // the plan_id of the last scanning table
    uint32 table_count;
    uint32 id_maps[GS_MAX_JOIN_TABLES];
    sql_table_cursor_t *tables;
    uint64 scn;
    merge_into_hash_data_t merge_into_hash;
    connect_by_data_t connect_data;
    struct st_sql_cursor *left_cursor;
    struct st_sql_cursor *right_cursor;
    struct st_sql_cursor *ancestor_ref;

    join_data_t *m_join;
    found_rows_info_t found_rows; /* for the built-in "FOUND_ROWS()" */
    plan_exec_data_t exec_data;   // buffer in vma for union all/limit/group...
    vmc_t vmc;

    galist_t *nl_full_ctx_list;
    unpivot_ctx_t *unpivot_ctx;
    hash_material_t hash_mtrl;
    semi_anchor_t semi_anchor;
    uint32 not_cache : 1;  // 0:will cache,  1: will not cache ,default is cache
    uint32 is_open : 1;
    uint32 is_result_cached : 1;
    uint32 exists_result : 1;
    uint32 winsort_ready : 1;
    uint32 global_cached : 1;  // cached scan pages into global CR pool or not
    uint32 hash_table_status : 2;
    bool32 is_mtrl_cursor : 1;
    uint32 reserved : 23;
    bool32 eof;

    sql_cursor_par_ctx_t par_ctx;  // for parallel execute sql
    galist_t *idx_func_cache;      /* cache for function indexed expression */
} sql_cursor_t;

status_t sql_begin_dml(sql_stmt_t *stmt);
status_t sql_try_execute_dml(sql_stmt_t *stmt);
status_t sql_execute_single_dml(sql_stmt_t *stmt, knl_savepoint_t *savepoint);
status_t sql_execute_fetch(sql_stmt_t *stmt);
status_t sql_execute_fetch_medatata(sql_stmt_t *stmt);
status_t sql_execute_fetch_cursor_medatata(sql_stmt_t *stmt);
status_t sql_alloc_cursor(sql_stmt_t *stmt, sql_cursor_t **cursor);
status_t sql_alloc_knl_cursor(sql_stmt_t *stmt, knl_cursor_t **cursor);
void sql_close_cursor(sql_stmt_t *stmt, sql_cursor_t *cursor);
void sql_free_cursor(sql_stmt_t *stmt, sql_cursor_t *cursor);
status_t sql_make_result_set(sql_stmt_t *stmt, sql_cursor_t *cursor);
void sql_init_varea_set(sql_stmt_t *stmt, sql_table_cursor_t *cursor);
void sql_free_varea_set(sql_table_cursor_t *cursor);
void sql_init_sql_cursor(sql_stmt_t *stmt, sql_cursor_t *cursor);
void sql_free_cursors(sql_stmt_t *stmt);
status_t sql_alloc_global_sql_cursor(object_t **object);
void sql_free_va_set(sql_stmt_t *stmt, sql_cursor_t *cursor);
status_t sql_parse_anonymous_soft(sql_stmt_t *stmt, word_t *leader, sql_text_t *sql);
status_t sql_parse_anonymous_directly(sql_stmt_t *stmt, word_t *leader, sql_text_t *sql);
void sql_free_merge_join_data(sql_stmt_t *stmt, join_data_t *m_join);
void sql_free_knl_cursor(sql_stmt_t *stmt, knl_cursor_t *cursor);
gs_type_t sql_get_pending_type(char *pending_buf, uint32 id);
status_t sql_try_put_dml_batch_error(sql_stmt_t *stmt, uint32 row, int32 error_code, const char *message);
void sql_release_json_table(sql_table_cursor_t *tab_cur);

static inline sql_cursor_t *sql_get_proj_cursor(sql_cursor_t *cursor)
{
    if (cursor->par_ctx.par_mgr == NULL) {
        return cursor;
    }

    knl_panic(0);
    sql_cursor_t *proj_cursor = cursor;

    return proj_cursor;
}

static inline void sql_inc_rows(sql_stmt_t *stmt, sql_cursor_t *cursor)
{
    stmt->batch_rows++;
    cursor->total_rows++;
}

/*
 * Get the upper of rownum from a *cond_tree_t*, if the cond_tree is
 * null, then return GS_INFINITE32.
 */
#define GET_MAX_ROWNUM(cond) (((cond) != NULL) ? (cond)->rownum_upper : GS_INFINITE32)

static inline status_t sql_get_ancestor_cursor(sql_cursor_t *curr_cur, uint32 ancestor, sql_cursor_t **ancestor_cur)
{
    uint32 depth = 0;

    *ancestor_cur = curr_cur;

    if (curr_cur == NULL) {
        GS_THROW_ERROR(ERR_VALUE_ERROR, "no sql prepare cannot get column value");
        return GS_ERROR;
    }

    while (depth < (ancestor)) {
        if ((*ancestor_cur)->ancestor_ref == NULL) {
            GS_THROW_ERROR(ERR_ANCESTOR_LEVEL_MISMATCH);
            return GS_ERROR;
        }
        (*ancestor_cur) = (*ancestor_cur)->ancestor_ref;
        depth++;
    }
    return GS_SUCCESS;
}

static inline status_t sql_alloc_ssa_cursor(sql_cursor_t *cursor, sql_select_t *select_ctx, uint32 id,
                                            sql_cursor_t **sql_cur)
{
    // cursor should use same stmt with ssa_cursor
    GS_RETURN_IFERR(sql_alloc_cursor(cursor->stmt, sql_cur));
    (*sql_cur)->select_ctx = select_ctx;
    (*sql_cur)->plan = select_ctx->plan;
    (*sql_cur)->scn = cursor->scn;
    (*sql_cur)->ancestor_ref = cursor;
    (*sql_cur)->global_cached = GS_TRUE;
    cursor->cursor_maps[id] = *sql_cur;
    biqueue_add_tail(&cursor->ssa_cursors, QUEUE_NODE_OF(*sql_cur));
    return GS_SUCCESS;
}

static inline status_t sql_get_ssa_cursor(sql_cursor_t *cursor, sql_select_t *select_ctx, uint32 id,
                                          sql_cursor_t **sql_cur)
{
    *sql_cur = cursor->cursor_maps[id];
    if (*sql_cur != NULL) {
        return GS_SUCCESS;
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

static inline sql_cursor_t *sql_get_group_cursor(sql_cursor_t *cursor)
{
    return cursor;
}

static inline sql_array_t *sql_get_query_tables(sql_cursor_t *cursor, sql_query_t *query)
{
    if (cursor->connect_data.last_level_cursor != NULL || query->s_query == NULL) {
        return &query->tables;
    }
    return &query->s_query->tables;
}

status_t sql_init_multi_update(sql_stmt_t *stmt, sql_cursor_t *cursor, knl_cursor_action_t action,
                               knl_cursor_t **knl_curs);

typedef status_t (*sql_fetch_func_t)(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof);
typedef status_t (*sql_send_row_func_t)(sql_stmt_t *stmt, sql_cursor_t *cursor, bool32 *is_full);

typedef struct st_rs_fetch_func_tab {
    uint8 rs_type;
    sql_fetch_func_t sql_fetch_func;
} rs_fetch_func_tab_t;

status_t sql_execute_select(sql_stmt_t *stmt);
status_t sql_open_query_cursor(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_query_t *query);
status_t sql_fetch_cursor(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof);
status_t sql_fetch_query(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof);
status_t sql_execute_query(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan);
status_t sql_execute_query_plan(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan);
status_t sql_execute_select_plan(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan);
void sql_open_select_cursor(sql_stmt_t *stmt, sql_cursor_t *cursor, galist_t *rs_columns);
status_t shd_refuse_sql(sql_stmt_t *stmt);
status_t sql_execute_join(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof);
status_t sql_fetch_join(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof);
status_t sql_make_normal_rs(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_fetch_func_t sql_fetch_func,
                            sql_send_row_func_t sql_send_row_func);
sql_send_row_func_t sql_get_send_row_func(sql_stmt_t *stmt, plan_node_t *plan);
status_t sql_open_cursors(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_query_t *query, knl_cursor_action_t cursor_action,
                          bool32 is_select);
uint16 sql_get_decode_count(sql_table_t *table);
status_t sql_check_sub_select_pending(sql_cursor_t *parent_cursor, sql_select_t *select_ctx, bool32 *pending);
status_t sql_generate_cursor_exec_data(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_query_t *query);
status_t sql_free_query_mtrl(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan);
status_t sql_fetch_rownum(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof);
status_t sql_fetch_for_update(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof);
status_t sql_get_parent_remote_table_id(sql_cursor_t *parent_cursor, uint32 tab_id, uint32 *remote_id);

#define CHECK_SESSION_VALID_IN_FETCH(stmt, cursor)  \
    do {                                            \
        if (KNL_SESSION(stmt)->killed) {            \
            sql_close_cursor((stmt), (cursor));     \
            GS_THROW_ERROR(ERR_OPERATION_KILLED);   \
            return GS_ERROR;                        \
        }                                           \
        if (KNL_SESSION(stmt)->canceled) {          \
            sql_close_cursor((stmt), (cursor));     \
            GS_THROW_ERROR(ERR_OPERATION_CANCELED); \
            return GS_ERROR;                        \
        }                                           \
    } while (0)

#define CM_TRACE_BEGIN                              \
    date_t __starttime__ = 0;                       \
    do {                                            \
        if (SECUREC_UNLIKELY(AUTOTRACE_ON(stmt))) { \
            __starttime__ = cm_now();               \
        }                                           \
    } while (0)

#define CM_TRACE_END(stmt, plan_id)                                                \
    do {                                                                           \
        if (SECUREC_UNLIKELY(AUTOTRACE_ON(stmt) && ((stmt)->plan_time != NULL))) { \
            (stmt)->plan_time[(plan_id)] += (cm_now() - __starttime__);            \
        }                                                                          \
    } while (0)

#define IS_QUERY_SCAN_PLAN(type) (type == PLAN_NODE_JOIN || type == PLAN_NODE_SCAN || type == PLAN_NODE_CONCATE)

status_t sql_execute_dcl(sql_stmt_t *stmt);
bool32 sql_check_effective_in_shard(uint32 id);
status_t sql_execute_commit_phase1(sql_stmt_t *stmt);
status_t sql_execute_end_phase2(sql_stmt_t *stmt);
status_t sql_execute_commit(sql_stmt_t *stmt);
status_t sql_execute_rollback(sql_stmt_t *stmt);
status_t sql_execute_rollback_to(sql_stmt_t *stmt);
status_t sql_execute_savepoint(sql_stmt_t *stmt);
status_t sql_execute_ddl(sql_stmt_t *stmt);
status_t sql_execute_ddl_with_count(sql_stmt_t *stmt);
status_t sql_try_import_rows(void *sql_stmt, uint32 count);
status_t sql_get_ddl_sql(void *sql_stmt, text_t *sql, vmc_t *vmc, bool8 *need_free);

status_t sql_execute_alter_index(sql_stmt_t *stmt);
status_t sql_execute_create_index(sql_stmt_t *stmt);
status_t sql_execute_drop_index(sql_stmt_t *stmt);

status_t sql_send_row(sql_stmt_t *stmt, sql_cursor_t *cursor, bool32 *is_full);
status_t sql_send_value(sql_stmt_t *stmt, char *pending_buf, gs_type_t temp_type, typmode_t *typmod, variant_t *value);
status_t sql_get_rs_value(sql_stmt_t *stmt, sql_cursor_t *cursor, uint32 id, variant_t *value);
status_t sql_get_col_rs_value(sql_stmt_t *stmt, sql_cursor_t *cursor, uint16 col, var_column_t *v_col,
                              variant_t *value);
status_t sql_send_generated_key_row(sql_stmt_t *stmt, int64 *serial_val);
gs_type_t sql_make_pending_column_def(sql_stmt_t *stmt, char *pending_buf, gs_type_t type, uint32 col_id,
                                      variant_t *value);
status_t sql_send_ori_row(sql_stmt_t *stmt, sql_cursor_t *cursor, bool32 *is_full);
status_t sql_send_return_row(sql_stmt_t *stmt, galist_t *ret_columns, bool8 gen_null);
status_t sql_send_column(sql_stmt_t *stmt, sql_cursor_t *cursor, rs_column_t *rs_col, variant_t *value);
status_t sql_send_calc_column(sql_stmt_t *stmt, rs_column_t *rs_col, variant_t *value);
status_t sql_var2rowid(const variant_t *var, rowid_t *rid, knl_dict_type_t dc_type);
status_t sql_execute_scan(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan);
status_t sql_fetch_scan(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof);
status_t sql_fetch_scan_subselect(sql_stmt_t *stmt, struct st_sql_cursor *sql_cur, bool32 *eof);
status_t sql_get_row_value(sql_stmt_t *stmt, char *ptr, uint32 len, var_column_t *v_col, variant_t *value,
                           bool8 set_lob_nodeid);
status_t sql_get_kernel_value(sql_stmt_t *stmt, sql_table_t *table, knl_cursor_t *knl_cur, var_column_t *v_col,
                              variant_t *value);
status_t sql_get_ddm_kernel_value(sql_stmt_t *stmt, sql_table_t *table, knl_cursor_t *knl_cur, var_column_t *v_col,
                                  variant_t *value);
status_t sql_get_trig_kernel_value(sql_stmt_t *stmt, row_head_t *row, uint16 *offsets, uint16 *lens,
                                   var_column_t *v_col, variant_t *value);
void sql_part_get_print(sql_stmt_t *stmt, scan_plan_t *plan, char *buf, uint32 size);
void sql_prepare_scan(sql_stmt_t *stmt, knl_dictionary_t *dc, knl_cursor_t *cursor);
status_t sql_execute_table_scan(sql_stmt_t *stmt, sql_table_cursor_t *cursor);
status_t sql_scan_normal_table(sql_stmt_t *stmt, sql_table_t *table, sql_table_cursor_t *tab_cur, plan_node_t *plan,
                               sql_cursor_t *cursor);
status_t sql_make_part_scan_keys(sql_stmt_t *stmt, scan_plan_t *plan, sql_table_cursor_t *cursor,
                                 sql_cursor_t *sql_cursor, calc_mode_t calc_mode);
bool32 sql_try_fetch_next_part(sql_table_cursor_t *cursor);
knl_part_locate_t sql_fetch_next_part(sql_table_cursor_t *cursor);
status_t sql_fetch_one_part(sql_stmt_t *stmt, sql_table_cursor_t *tab_cur, sql_table_t *table);
status_t sql_try_switch_part(sql_stmt_t *stmt, sql_table_cursor_t *tab_cur, sql_table_t *table, bool32 *result);
status_t sql_get_subarray_by_col(sql_stmt_t *stmt, var_column_t *v_col, variant_t *value, variant_t *result);
status_t sql_make_index_scan_keys(sql_stmt_t *stmt, scan_plan_t *plan, sql_cursor_t *sql_cursor,
                                  sql_table_cursor_t *cursor);
bool32 sql_load_index_scan_key(sql_table_cursor_t *cursor);
status_t sql_make_subpart_scan_keys(sql_stmt_t *stmt, sql_array_t *subpart, sql_table_t *table, vmc_t *vmc,
                                    part_scan_key_t *part_scan_key, calc_mode_t calc_mode);
status_t sql_try_get_value_from_index(sql_stmt_t *stmt, expr_node_t *node, variant_t *result, bool32 *ready);
bool32 sql_match_func_index_col(sql_stmt_t *stmt, expr_node_t *node, knl_index_desc_t *index, sql_table_t *table,
                                uint32 *index_col);
/* 1.all scan ranges are point range (include RANGE_FULL type)
 * 2.At least one column has multi scan ranges
 * 3.index columns must match condition or has RANGE_FULL scan type.
 * 4.total ranges of Cartesian product not greater than GS_MAX_POINT_RANGE_COUNT
 */
static inline bool32 can_use_point_scan(scan_list_array_t *ar)
{
    if (!GS_BIT_TEST(ar->flags, LIST_EXIST_RANGE_UNEQUAL) && GS_BIT_TEST(ar->flags, LIST_EXIST_MULTI_RANGES) &&
        ar->total_ranges <= GS_MAX_POINT_RANGE_COUNT) {
        return GS_TRUE;
    }

    return GS_FALSE;
}
status_t sql_row_put_value(sql_stmt_t *stmt, row_assist_t *ra, variant_t *value);
status_t sql_put_row_value(sql_stmt_t *stmt, char *pending_buf, row_assist_t *ra, gs_type_t temp_type,
                           variant_t *value);
void sql_reset_mtrl(sql_stmt_t *stmt, sql_cursor_t *cursor);
status_t sql_process_free_stmt(session_t *session);
status_t sql_process_prepare(session_t *session);
status_t sql_process_execute(session_t *session);
status_t sql_process_fetch(session_t *session);
status_t sql_process_commit(session_t *session);
status_t sql_process_rollback(session_t *session);

status_t sql_process_query(session_t *session);
status_t sql_process_prep_and_exec(session_t *session);
status_t sql_process_lob_read(session_t *session);
status_t sql_process_lob_write(session_t *session);
status_t sql_process_lob_read_local(session_t *session, lob_read_req_t *req, lob_read_ack_t *ack);

status_t sql_process_xa_start(session_t *session);
status_t sql_process_xa_end(session_t *session);
status_t sql_process_xa_prepare(session_t *session);
status_t sql_process_xa_commit(session_t *session);
status_t sql_process_xa_rollback(session_t *session);
status_t sql_process_xa_status(session_t *session);
status_t sql_get_stmt(session_t *session, uint32 stmt_id);

status_t sql_process_stmt_rollback(session_t *session); /* added for z_sharding */
status_t sql_process_sequence(session_t *session);      /* added for z_sharding */

status_t sql_process_load(session_t *session);
status_t check_version_and_local_infile(void);
status_t generate_load_full_file_name(session_t *session, char *full_file_name);
status_t sql_load_try_remove_file(char *file_name);

status_t sql_process_pre_exec_multi_sql(session_t *session);

typedef struct st_sql_type_map {
    bool32 do_typemap;
    char file_name[GS_FILE_NAME_BUFFER_SIZE];
    list_t type_maps; /* sql_user_typemap_t */
} sql_type_map_t;

typedef enum en_load_data_local_phase {
    LOAD_DATA_LOCAL_GET_SQL = 1,
    LOAD_DATA_LOCAL_GET_DATA = 2,
    LOAD_DATA_LOCAL_EXE_ZSQL = 3
} load_data_local_t;
#define POPEN_GET_BUF_MAX_LEN (uint32)1024
#define LOAD_MAX_FULL_FILE_NAME_LEN (uint32)512  // path + file_name
#define LOAD_FEATURE_INNER_VERSION 1
#define MAX_DEL_RETRY_TIMES 5
#define LOAD_BY_ZSQL_MAX_STR_LEN (uint32)32768
#define LOAD_MAX_SQL_SUFFIX_LEN (uint32)10000
#define LOAD_MAX_RAW_SQL_LEN (uint32)20000

typedef struct st_sql_instance {
    context_pool_t *pool;
    bool32 enable_stat;
    bool32 commit_on_disconn;
    ack_sender_t pl_sender;
    ack_sender_t sender;
    ack_sender_t gdv_sender;
    uint32 interactive_timeout;
    uint32 sql_lob_locator_size;
    bool32 enable_empty_string_null; /* String: '' as null like oracle, as '' like MYSQL */
    bool32 string_as_hex_binary;     /* String: '' as null like oracle, as '' like MYSQL */
    list_t self_func_list;           // high priority user function.
    sql_type_map_t type_map;
    uint32 max_connect_by_level;
    uint32 index_scan_range_cache;
    uint32 prefetch_rows;
    uint32 max_sql_map_per_user;
    bool32 enable_predicate;
    uint32 plan_display_format;
    bool32 enable_outer_join_opt;
    uint32 cbo_index_caching;   // parameter CBO_INDEX_CACHING
    uint32 cbo_index_cost_adj;  // parameter CBO_INDEX_COST_ADJ
    uint32 cbo_path_caching;    // parameter CBO_PATH_CACHING
    uint32 cbo_dyn_sampling;
    bool32 enable_distinct_pruning;  // parameter _DISTINCT_PRUNING
    uint32 topn_threshold;
    uint32 withas_subquery;  // 0: optimizer(default), 1: materialize, 2: inline
    bool32 enable_cb_mtrl;
    bool32 enable_aggr_placement;
    bool32 enable_or_expand;
    bool32 enable_project_list_pruning;
    bool32 enable_pred_move_around;
    bool32 enable_hash_mtrl;
    bool32 enable_winmagic_rewrite;
    bool32 enable_pred_reorder;
    bool32 enable_order_by_placement;
    bool32 enable_subquery_elimination;
    bool32 enable_join_elimination;
    bool32 enable_connect_by_placement;
    bool32 enable_group_by_elimination;
    bool32 enable_distinct_elimination;
    bool32 enable_multi_index_scan;
    bool32 enable_join_pred_pushdown;
    bool32 enable_filter_pushdown;
    uint32 optim_index_scan_max_parts;
    bool32 enable_order_by_elimination;
    bool32 enable_any_transform;
    bool32 enable_all_transform;
    bool32 enable_unnest_set_subq;
    bool32 enable_right_semijoin;
    bool32 enable_right_antijoin;
    bool32 enable_right_leftjoin;
    bool32 vm_view_enabled;
    bool32 enable_password_cipher;
    bool32 enable_cbo_hint;
    uint32 segment_pages_hold;
    uint32 hash_pages_hold;
    uint64 hash_area_size;
    bool32 enable_func_idx_only;
    bool32 enable_index_cond_pruning;
    bool32 enable_nl_full_opt;
    bool32 enable_arr_store_opt;  // default value is FALSE, and when set to TRUE, forbidden to set back to FALSE
    bool32 enable_exists_transform;
    bool32 parallel_policy;
    bool32 strict_case_datatype;
    sql_json_mem_pool_t json_mpool;
} sql_instance_t;

#endif
