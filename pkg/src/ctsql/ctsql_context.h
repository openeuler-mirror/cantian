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
 * ctsql_context.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/ctsql_context.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_CONTEXT_H__
#define __SQL_CONTEXT_H__
#include "cm_defs.h"
#include "cm_memory.h"
#include "cm_context_pool.h"
#include "cm_list.h"
#include "var_inc.h"
#include "cs_pipe.h"
#include "cm_word.h"
#include "knl_interface.h"
#include "ctsql_statistics.h"
#include "cm_lex.h"
#include "cm_bilist.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum en_sql_type {
    CTSQL_TYPE_NONE = 0,
    CTSQL_TYPE_SELECT = 1,
    CTSQL_TYPE_UPDATE,
    CTSQL_TYPE_INSERT,
    CTSQL_TYPE_DELETE,
    CTSQL_TYPE_MERGE,
    CTSQL_TYPE_REPLACE, /* replace into */

    CTSQL_TYPE_DML_CEIL, /* pseudo */
    CTSQL_TYPE_BEGIN,    /* ONLY FOR PGS */
    CTSQL_TYPE_COMMIT_PHASE1,
    CTSQL_TYPE_COMMIT_PHASE2,
    CTSQL_TYPE_COMMIT,
    CTSQL_TYPE_ROLLBACK_PHASE2,
    CTSQL_TYPE_ROLLBACK,
    CTSQL_TYPE_ROLLBACK_TO,
    CTSQL_TYPE_SAVEPOINT,
    CTSQL_TYPE_RELEASE_SAVEPOINT,
#ifdef DB_DEBUG_VERSION
    CTSQL_TYPE_SYNCPOINT,
#endif /* DB_DEBUG_VERSION */
    CTSQL_TYPE_SET_TRANS,
    CTSQL_TYPE_BACKUP,
    CTSQL_TYPE_RESTORE,
    CTSQL_TYPE_RECOVER,
    CTSQL_TYPE_SHUTDOWN,
    CTSQL_TYPE_LOCK_TABLE,
    CTSQL_TYPE_BUILD,
    CTSQL_TYPE_CHECKPOINT,
    CTSQL_TYPE_ROUTE,
    CTSQL_TYPE_VALIDATE,
    CTSQL_TYPE_ALTER_SYSTEM,
    CTSQL_TYPE_ALTER_SESSION,
    CTSQL_TYPE_LOCK_NODE,
    CTSQL_TYPE_UNLOCK_NODE,
    CTSQL_TYPE_DAAC,
    CTSQL_TYPE_DCL_CEIL, /* pseudo */

    CTSQL_TYPE_CREATE_DATABASE,
    CTSQL_TYPE_CREATE_CLUSTERED_DATABASE,
    CTSQL_TYPE_CREATE_DATABASE_LINK,
    CTSQL_TYPE_CREATE_DISTRIBUTE_RULE,
    CTSQL_TYPE_CREATE_SEQUENCE,
    CTSQL_TYPE_CREATE_TABLESPACE,
    CTSQL_TYPE_CREATE_TABLE,
    CTSQL_TYPE_CREATE_INDEX,
    CTSQL_TYPE_CREATE_USER,
    CTSQL_TYPE_CREATE_ROLE,
    CTSQL_TYPE_CREATE_TENANT,
    CTSQL_TYPE_CREATE_VIEW,
    CTSQL_TYPE_CREATE_NODE,
    CTSQL_TYPE_CREATE_SYNONYM,
    CTSQL_TYPE_CREATE_PROFILE,
    CTSQL_TYPE_CREATE_DIRECTORY,
    CTSQL_TYPE_CREATE_CTRLFILE,
    CTSQL_TYPE_CREATE_LIBRARY,
    CTSQL_TYPE_CREATE_INDEXES,

    CTSQL_TYPE_DROP_DATABASE_LINK,
    CTSQL_TYPE_DROP_DIRECTORY,
    CTSQL_TYPE_DROP_SEQUENCE,
    CTSQL_TYPE_DROP_TABLESPACE,
    CTSQL_TYPE_DROP_TABLE,
    CTSQL_TYPE_DROP_INDEX,
    CTSQL_TYPE_DROP_USER,
    CTSQL_TYPE_DROP_ROLE,
    CTSQL_TYPE_DROP_TENANT,
    CTSQL_TYPE_DROP_VIEW,
    CTSQL_TYPE_DROP_SYNONYM,
    CTSQL_TYPE_DROP_PROFILE,
    CTSQL_TYPE_DROP_NODE,
    CTSQL_TYPE_DROP_DISTRIBUTE_RULE,
    CTSQL_TYPE_DROP_SQL_MAP,
    CTSQL_TYPE_DROP_LIBRARY,
    CTSQL_TYPE_TRUNCATE_TABLE,
    CTSQL_TYPE_PURGE,
    CTSQL_TYPE_COMMENT,
    CTSQL_TYPE_FLASHBACK_TABLE,

    CTSQL_TYPE_ALTER_DATABASE_LINK,
    CTSQL_TYPE_ALTER_SEQUENCE,
    CTSQL_TYPE_ALTER_TABLESPACE,
    CTSQL_TYPE_ALTER_TABLE,
    CTSQL_TYPE_ALTER_INDEX,
    CTSQL_TYPE_ALTER_USER,
    CTSQL_TYPE_ALTER_TENANT,
    CTSQL_TYPE_ALTER_DATABASE,
    CTSQL_TYPE_ALTER_NODE,
    CTSQL_TYPE_ALTER_PROFILE,
    CTSQL_TYPE_ALTER_TRIGGER,
    CTSQL_TYPE_ALTER_SQL_MAP,
    CTSQL_TYPE_ANALYSE_TABLE,
    CTSQL_TYPE_ANALYZE_INDEX,
    CTSQL_TYPE_GRANT,
    CTSQL_TYPE_REVOKE,
    CTSQL_TYPE_CREATE_CHECK_FROM_TEXT,
    CTSQL_TYPE_CREATE_EXPR_FROM_TEXT,
    CTSQL_TYPE_INHERIT_PRIVILEGES,
    CTSQL_TYPE_CREATE_PROC,
    CTSQL_TYPE_CREATE_FUNC,
    CTSQL_TYPE_CREATE_TRIG,
    CTSQL_TYPE_CREATE_PACK_SPEC, /* package specification */
    CTSQL_TYPE_CREATE_PACK_BODY, /* package body */
    CTSQL_TYPE_CREATE_TYPE_SPEC, /* type specification */
    CTSQL_TYPE_CREATE_TYPE_BODY, /* type body */
    CTSQL_TYPE_DROP_PROC,
    CTSQL_TYPE_DROP_FUNC,
    CTSQL_TYPE_DROP_TRIG,

    CTSQL_TYPE_DROP_PACK_SPEC, /* package specification */
    CTSQL_TYPE_DROP_PACK_BODY, /* package body */
    CTSQL_TYPE_DROP_TYPE_SPEC, /* type specification */
    CTSQL_TYPE_DROP_TYPE_BODY, /* type body */
    CTSQL_TYPE_DDL_CEIL,       /* pseudo */
    CTSQL_TYPE_ANONYMOUS_BLOCK,
    CTSQL_TYPE_PL_CEIL_END, /* pl_pseudo_end */
} sql_type_t;

#define SQL_OPT_PWD_DDL_TYPE(type)                                                                                 \
    ((type) == CTSQL_TYPE_CREATE_USER || (type) == CTSQL_TYPE_ALTER_USER || (type) == CTSQL_TYPE_CREATE_DATABASE_LINK || \
        (type) == CTSQL_TYPE_ALTER_DATABASE_LINK || (type) == CTSQL_TYPE_CREATE_NODE || (type) == CTSQL_TYPE_ALTER_NODE)

typedef enum en_sql_logic_op {
    RD_PLM_CREATE = 0,
    RD_PLM_REPLACE,
    RD_PLM_DROP,
    RD_PLM_UPDATE_TRIG_TAB,
    RD_PLM_UPDATE_TRIG_STATUS,
    RD_PLM_FREE_TRIG_ENTITY,
} sql_logic_op_t;

typedef enum en_merge_type {
    MERGE_TYPE_INSERT = 0,
    MERGE_TYPE_UPDATE
} merge_type_t;

typedef struct st_sql_param_mark {
    uint32 offset;
    uint16 len;
    uint16 pnid; // paramter name id
} sql_param_mark_t;

typedef struct st_sql_table_entry {
    text_t user;
    text_t name;
    text_t dblink; // user.tab[@dblink], user1.t1@link_name
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
    RS_TYPE_SORT_GROUP,
    RS_TYPE_MERGE_SORT_GROUP,
    RS_TYPE_HASH_GROUP,
    RS_TYPE_PAR_HASH_GROUP,
    RS_TYPE_INDEX_GROUP,
    RS_TYPE_AGGR,
    RS_TYPE_SORT_DISTINCT,
    RS_TYPE_HASH_DISTINCT,
    RS_TYPE_INDEX_DISTINCT,
    RS_TYPE_UNION,
    RS_TYPE_UNION_ALL,
    RS_TYPE_MINUS,
    RS_TYPE_HASH_MINUS,
    RS_TYPE_LIMIT,
    RS_TYPE_HAVING,
    RS_TYPE_REMOTE,
    RS_TYPE_GROUP_MERGE,
    RS_TYPE_WINSORT,
    RS_TYPE_HASH_MTRL,
    RS_TYPE_ROW,
    RS_TYPE_SORT_PAR,
    RS_TYPE_SIBL_SORT,
    RS_TYPE_PAR_QUERY_JOIN,
    RS_TYPE_GROUP_CUBE,
    RS_TYPE_ROWNUM,
    RS_TYPE_FOR_UPDATE,
    RS_TYPE_WITHAS_MTRL,
} rs_type_t;

typedef enum en_sql_node_type {
    SQL_MERGE_NODE = 1,
    SQL_UPDATE_NODE = 2,
    SQL_DELETE_NODE = 3,
    SQL_QUERY_NODE = 4,
    SQL_SELECT_NODE = 5,
} sql_node_type_t;

#ifdef TEST_MEM
#define CT_MAX_TEST_MEM_COUNT 8192
#endif

typedef struct st_clause_info {
    uint32 union_all_count;
} clause_info_t;

typedef struct st_sql_withas {
    galist_t *withas_factors; // list of with as(sql_withas_factor_t)
    uint32 cur_match_idx;     // for check with as can't reference later with as definition
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
    galist_t *items; // hint_item_t
    opt_param_info_t *opt_params;
    opt_estimate_info_t *opt_estimate;
    // hint info after verify
    uint64 mask[MAX_HINT_TYPE];
    void *args[MAX_HINT_WITH_TABLE_ARGS]; // galist *
    uint32 leading_id;
} hint_info_t;

typedef struct st_sql_context {
    context_ctrl_t ctrl;
    galist_t *params;     // parameter list
    galist_t *csr_params; // cursor sharing parameter list
    galist_t *tables;     // all tables (not include subselect)
    galist_t *rs_columns; // result set column list
    void *entry;          // sql entry
    void *withas_entry;   // with as clause entry
    sql_type_t type;
    uint32 pname_count; // number of distinct parameter name
    ctx_stat_t stat;    // statistics
    galist_t *selects;  // all select context
    void *supplement;
    hint_info_t *hint_info; // storage opt_param hint
    bool32 has_ltt : 1;     // sql has local temporary table
    bool32 cacheable : 1;   // sql context if is able to be cached, default TRUE
    bool32 in_sql_pool : 1; // sql context if has been cached, default FALSE
    bool32 opt_by_rbo : 1;
    bool32 obj_belong_self : 1; // if all the objects accessed belong to self, include base tables in views
    bool32 has_pl_objects : 1;  // sql has user func or sys package, need check privilege
    bool32 need_vpeek : 1;      // for bind variable peeking
    bool32 is_opt_ctx : 1;
    bool32 always_vpeek : 1;
    bool32 has_sharding_tab : 1;
    bool32 repl_sink_all : 1; // replication sink all
    bool32 unsinkable : 1;
    bool32 has_func_tab : 1;
    bool32 sql_whitelist : 1;
    bool32 shd_read_master : 1;
    bool32 policy_used : 1;
    bool32 has_func_index : 1;
    bool32 has_dblink : 1;
    bool32 in_spm : 1; // means this context was created by spm
    bool32 unused : 13;
    uint32 sub_map_id;
    atomic32_t vpeek_count;
    atomic32_t readonly;
    struct st_sql_context *parent;
    text_t spm_sign; // associated with sys_spm's signature
    text_t sql_sign; // text_addr SQL text MD5 sign
    clause_info_t clause_info;
#ifdef Z_SHARDING
    uint32 max_remote_params; // copy of param MAX_CACHE_ROWS
    galist_t *rules;
    void *old_entry;
    void *sinkall_entry;
    long_text_t origin_sql;   // only DDL in CN, origin sql copy from receive buffer for CN to distribute sql to DN.
    galist_t *shd_params_map; // shd adapter record all params and sequences, exclude remote-scan
#endif
    galist_t *in_ssa;         // sub-select list for in sub-select clause
    galist_t *in_params;      // in subquery parameter list

#ifdef TEST_MEM
    void **test_mem;
    uint32 test_mem_count;
#endif
    galist_t *dc_lst;      // plm dc used in this context(include view)
    galist_t *ref_objects; // direct ref objects (procedure, table, sequence)
    galist_t *sequences;   // sequences in used in this context
    galist_t *outlines;
    uint32 *unnamed_tab_counter; // record the number of unnamed tables of different types, max size is TAB_TYPE_MAX
    uint32 large_page_id;
    uint32 fexec_vars_cnt;   /* Record the number of first executable variants */
    uint32 fexec_vars_bytes; /* Record the memory size of first executable variants which return text type  */
    uint32 hash_optm_count;  /* Record the number of in condition list that can be optimized by hash table  */
    uint32 dynamic_sampling; // the level of dynamic sampling
    uint32 module_kind;      // the application kind of the currently executing user
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

/* begin: for select statement */
#ifdef Z_SHARDING
#define ITEM_NOT_IN_TARGET_LIST (-1)
#define SQL_HAS_GLOBAL_SEQUENCE(stmt) ((stmt)->context->sequences != NULL && (stmt)->context->sequences->count > 0)
#define SHD_IS_UNSINKABLE(context) ((context)->unsinkable)
#endif

typedef struct {
    sort_direction_t direction; /* the ordering direction: ASC/DESC */
    sort_nulls_t nulls_pos;     /* position of NULLS: NULLS FIRST/NULLS LAST */
} order_mode_t;

typedef struct st_sort_item {
    struct st_expr_tree *expr;

    union { // use union for compatibility previous usage
        struct {
            sort_direction_t direction; /* the ordering direction: ASC/DESC */
            sort_nulls_t nulls_pos;     /* position of NULLS: NULLS FIRST/NULLS LAST */
        };
        order_mode_t sort_mode;
    };
} sort_item_t;

/* NULLS LAST is the default for ascending order, and NULLS FIRST is the default for descending order. */
#define DEFAULT_NULLS_SORTING_POSITION(sort_dir) (((sort_dir) == SORT_MODE_ASC) ? SORT_NULLS_LAST : SORT_NULLS_FIRST)

static inline bool32 sql_nulls_pos_is_default(const order_mode_t *om)
{
    return om->nulls_pos == DEFAULT_NULLS_SORTING_POSITION(om->direction);
}

static inline bool32 sql_is_same_order_mode(const order_mode_t *om1, const order_mode_t *om2)
{
    return om1->direction == om2->direction && om1->nulls_pos == om2->nulls_pos;
}

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

#ifdef Z_SHARDING
#define COPY_SORT_ITEM_SHALLOW(dest, org)     \
    do {                                      \
        (dest)->expr = (org)->expr;           \
        (dest)->sort_mode = (org)->sort_mode; \
    } while (0)
#endif

typedef struct st_select_sort_item {
    uint32 rs_columns_id;
    ct_type_t datatype;
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
    cbo_cost_t cost;
    struct st_cond_tree *join_cond;
    struct st_cond_tree *filter;
    sql_array_t tables; // records tables belong to current join node, for verify join cond
    struct st_sql_join_node *left;
    struct st_sql_join_node *right;
    struct st_sql_join_node *prev;
    struct st_sql_join_node *next;
    uint32 plan_id_start;
    struct {
        bool32 hash_left : 1;
        bool32 is_cartesian_join : 1; // join cond cannot choose join edge, like true or a.f1 + b.f1 = c.f1
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
    uint32 count; // valid expr count
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
    bool32 combine_sw; // start with plan share cb mtrl data
} cb_mtrl_info_t;

typedef struct st_query_block_info {
    uint32 origin_id;
    bool32 transformed;
    text_t origin_name;
    text_t changed_name;
} query_block_info_t;

typedef struct st_vpeek_assist {
    struct st_cond_tree *vpeek_cond; // all conditions which contain bind variables for binding peeking
    uint64 vpeek_tables;             // table's id bit mask with binding param condition
} vpeek_assist_t;

typedef struct st_sql_query {
    source_location_t loc;
    struct st_sql_select *owner;
    galist_t *columns;    // expression columns in select list
    galist_t *rs_columns; // result set columns, '*' is extracted
    galist_t *winsort_rs_columns;
    sql_array_t tables;
    sql_array_t ssa; // SubSelect Array for subselect expr
    galist_t *aggrs;
    galist_t *cntdis_columns;
    galist_t *sort_items;
    galist_t *group_sets;  // list of group_set_t, store local columns for hash mtrl optimized
    galist_t *group_cubes; // list of cube_node_t, for group by cube optimization
    galist_t *sort_groups;
    galist_t *distinct_columns;
    galist_t *exists_dist_columns; // list of expr_node_t
    galist_t *winsort_list;
    galist_t *join_symbol_cmps;
    galist_t *remote_keys;        // store parent columns for hash mtrl optimization
    cb_mtrl_info_t *cb_mtrl_info; // store hash keys for connect by mtrl optimization
    vpeek_assist_t *vpeek_assist;
    struct st_pivot_items *pivot_items;
    struct st_cond_tree *cond;
    struct st_cond_tree *filter_cond;
    struct st_cond_tree *having_cond;
    struct st_cond_tree *start_with_cond;
    struct st_cond_tree *connect_by_cond;
    struct st_sql_query *s_query; // sub-query for start with scan
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
        uint16 is_s_query : 1; // indicates this is the duplicated sub-query for start with
        uint16 has_distinct : 1;
        uint16 has_filter_opt : 1;
        uint16 has_aggr_sort : 1;    // query has aggr func with sort items like listagg
        uint16 has_no_or_expand : 1; // query already has no_or_expand flag or not
        uint16 reserved : 2;
    };
    uint16 incl_flags;
    uint32 extra_flags; // for order by, having, group by ...
    limit_item_t limit;
    hint_info_t *hint_info;
    sql_join_assist_t join_assist;
    uint32 aggr_dis_count;
    sql_join_node_t *join_root;
    galist_t *path_func_nodes; // recode the function node for connect by path.
    cbo_cost_t cost;
    int64 join_card;    // only for eliminate sort and cut cost
    void *filter_infos; // for recalc table cost, alloced from VMC, used in creating plan.
    vmc_t *vmc;         // for temporary memory alloc in creating plan
    query_block_info_t *block_info;
} sql_query_t;

/* get the calc_found_rows flag from the sql_select_t to whom the query belongs */
#define QUERY_NEEDS_CALC_FOUNDROWS(query) (((query)->owner) ? ((query)->owner->calc_found_rows) : CT_FALSE)

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
        CT_BIT_SET((_rs_col_)->rs_flag, (_flag_));   \
    } else {                                         \
        CT_BIT_RESET((_rs_col_)->rs_flag, (_flag_)); \
    }

typedef struct st_rs_column {
    rs_column_type_t type;
    text_t name;    // if exist_alias is true, name is column alias
    text_t z_alias; // auto generated alias, for SHARD decompile sql
    uint16 rs_flag;
    union {
        /* These definitions is same as the `typmode_t`, thus they should
             be replaced by typmode_t for unifying the definition of columns */
        struct {
            ct_type_t datatype;
            uint16 size;
            uint8 precision;
            int8 scale;
        };
        typmode_t typmod;
    };
    union {
        var_column_t v_col;        // table column
        struct st_expr_tree *expr; // calc column
    };
    uint32 win_rs_refs; // record window rs ref count
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
    SELECT_AS_LIST, // in clause
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
    sql_query_t *first_query; // the first query in select
    select_type_t type;
    double cost;
    int64 drive_card;
    struct st_plan_node *plan;
    select_chain_t chain;
    select_node_t *root;
    rowmark_t for_update_params;
    galist_t *for_update_cols; // select...for update [of col_list]
    galist_t *ref_nodes;      // store all expr_node_t that referenced by v_obj.ptr
    bool8 sub_select_sinkall; // flag for subselect
    bool8 for_update;      // flag for "select...for update"
    bool8 calc_found_rows; // flag for the FOUND_ROWS() function, used by select limit plan
    uint8 has_ancestor;    // flag records the levels of the ancestor refs, three levels above self recorded in detail
    bool8 is_update_value; // flag indicates that the select is in update set clause
    bool8 is_withas;       // flag indicates that the select is withas
    bool8 can_sub_opt;     // flag indicates that the select is in update set clause can be optimized
    uint8 reserved[1];     // reserved flags, 8 bytes align
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
    galist_t *withass;   // all withas context in current select clause
    galist_t *pl_dc_lst; // record plsql objects in current select context, for check privilege
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
    JOIN_AS_TABLE, // t1.join (t2 join t3 on ...) on ..., t2 join t3 is join_as_table, temporarily exists
    WITH_AS_TABLE,
    JSON_TABLE,
} sql_table_type_t;

extern bool8 g_subselect_flags[];

/* use it carefully !!! */
#define CT_IS_SUBSELECT_TABLE(type) (g_subselect_flags[type])

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

#define REMOTE_TYPE_LOCAL 0x00000000       // DN Local Table, need to be ZERO!
#define REMOTE_TYPE_REPL 0x00000001        // CN Replication Table
#define REMOTE_TYPE_PART 0x00000002        // CN Hash/Range/List Table
#define REMOTE_TYPE_MIX 0x00000003         // CN Replication + Hash/Range/List Table
#define REMOTE_TYPE_GLOBAL_VIEW 0x00000004 // CN global view

typedef enum en_remote_fetcher_type {
    REMOTE_FETCHER_NORMAL = 0,
    REMOTE_FETCHER_MERGE_SORT = 1,
    REMOTE_FETCHER_GROUP = 2,
} remote_fetcher_type_t;

typedef struct st_query_field {
    bilist_node_t bilist_node;
    uint32 pro_id;
    ct_type_t datatype;
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
    SELTION_DEPD_TABLES = 0x0001,      // the table depend on other tables
    SELTION_NO_DRIVER = 0x0002,        // the table can't be used as driving table
    SELTION_NO_HASH_JOIN = 0x0004,     // the table can't used NL Join Method
    SELTION_SPEC_DRIVER = 0x0008,      // the table is designated as the driving table
    SELTION_PUSH_DOWN_JOIN = 0x0010,   // the table as sub-select has push down condition
    SELTION_PUSH_DOWN_TABLE = 0x0020,  // the table in sub-select has push down condition
    SELTION_NL_PRIORITY = 0x0040,      // the table prefer to use NL Join Method
    SELTION_LEFT_JOIN_DRIVER = 0x0080, // the table is Left join driving table(left node with join-right-deep tree)
    SELTION_LEFT_JOIN_TABLE = 0x0100,  // the table is Left join right table
    SELTION_SUBGRAPH_DRIVER = 0x0200,  // the table is only designated as the sub-graph driving table
} table_seltion_type_t;

typedef struct st_cbo_extra_attribute {
    vmc_t *vmc;             // memory owner for the following list
    galist_t *save_tables;  // for save depend tables
    galist_t *sub_grp_tabs; // for sub graph tables
    galist_t *idx_ref_cols; // for index join referent columns (eg: ref_tab.col = tab.col)
    galist_t *filter_cols;  // for filter columns (eg: tab.col <= 1)
    galist_t *drv_infos;    // for driver table info
} cbo_extra_attr_t;

typedef struct st_cbo_attribute {
    uint16 type; // table_seltion_type_t
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
    uint64 idx_ss_flags; // for index skip scan flags
    int64 out_card;
    int64 total_rows;
    galist_t *tables;       // for depend tables
    cbo_extra_attr_t extra; // cbo extra attribute, memory allocated from stmt->vmc

    struct st_cond_tree *filter; // for outer join filter condition
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
        if (CT_IS_SUBSELECT_TABLE((table)->type)) {   \
            (table)->select_ctx->drive_card = (card); \
        }                                             \
    } while (0)

typedef enum {
    SCAN_PART_ANY, // one part to be scanned, but cannot be specified. max part used for calculation.
    // one or multiple specified parts to be scanned, part_no(s) saved in st_scan_part_info->part_no
    SCAN_PART_SPECIFIED,
    SCAN_PART_FULL,         // all parts to be scanned
    SCAN_PART_UNKNOWN,      // part to be scanned can not be decided. max part used for calculation.
    SCAN_PART_EMPTY,        // no part to be scanned
    SCAN_SUBPART_SPECIFIED, // one or multiple specified parts to be scaned
    SCAN_SUBPART_ANY,       // one subpart to be scanned, but cannot be specified. max subpart used for calculation.
    SCAN_SUBPART_UNKNOWN    // subpart to be scanned can not be decided. max subpart used for calculation.
} scan_part_range_type_t;

// the max number of specified part_no to be saved in scan_part_info.
// if the number of specified parts greater than 64, only part count will be used.
#define MAX_CBO_CALU_PARTS_COUNT 64

typedef struct st_scan_part_info {
    scan_part_range_type_t scan_type;
    uint64 part_cnt; // the number of all specified part_no saved in '*part_no'
    // in case the number is too great, at most MAX_CBO_CALU_PARTS_COUNT saved. check count before reading array!
    uint32 *part_no;
    uint32 *subpart_no;
} scan_part_info_t;

typedef enum en_json_error_type {
    JSON_RETURN_ERROR = 0,   // return error if json table data expr is invalid or path is invalid
    JSON_RETURN_NULL = 1,    // return null if json table data expr is invalid or path is invalid
    JSON_RETURN_DEFAULT = 2, // return default value if json table data expr is invalid or path is invalid
} json_error_type_t;

typedef struct st_json_error_info {
    json_error_type_t type;
    struct st_expr_tree *default_value;
} json_error_info_t;

typedef struct st_json_table_info {
    uint32 depend_table_count;
    uint32 *depend_tables;                    // table_id of table which exists in data_expr
    struct st_expr_tree *data_expr;           // origin json data to generate json_table
    text_t basic_path_txt;                    // text of json basic path expression
    struct st_source_location basic_path_loc; // current location of data_expr
    struct st_json_path *basic_path;          // complie result of json path expression
    json_error_info_t json_error_info;
    galist_t columns;
} json_table_info_t;

typedef enum en_tf_scan_flag {
    SEQ_SQL_SCAN = 0, // default value,
    SEQ_TFM_SCAN = 1, // table function sequential execution
    PAR_TFM_SCAN = 2, // table function parallel scan
    PAR_SQL_SCAN = 3, // sql parallel scan by hint
} tf_scan_flag_t;

typedef struct st_scan_info {
    knl_index_desc_t *index;    // for index scan
    uint16 scan_flag;           // index only/sort eliminate flag
    uint16 idx_equal_to;        // a = ? and b = ? and c > ? then idx_equal_to = 2
    uint16 equal_cols;          // include idx_equal_to and "a in (?,?) and b >?", for choose optimal index
    uint16 col_use_flag;        // indicate choose index with ancestor col or self join col
    uint32 index_dsc : 1;       // index scan direction,for sort eliminate
    uint32 rowid_usable : 1;    // flag for rowid scan
    uint32 index_full_scan : 1; // flag for index full scan
    uint32 index_skip_scan : 1; // flag for index skip scan
    uint32 is_push_down : 1;    // flag for push down
    uint32 opt_match_mode : 3;  // [0,7]
    uint32 skip_index_match : 1;
    uint32 multi_parts_scan : 1; // optim flag for multi knlcurs scan parts
    uint32 bindpar_onepart : 1;  // only one part left after the cond of bind parameter trimming
    uint32 index_ffs : 1;        // flag for index fast full scan
    uint32 reserved2 : 20;
    uint16 index_match_count; // for index match column count
    uint16 scan_mode;         // for table
    double cost;
    void *rowid_set;           // Use void* to point plan_rowid_set_t* for avoiding loop include;
    uint16 *idx_col_map;       // for index only scan, decode row by index defined sequence
    struct st_cond_tree *cond; // for multi index scan, create scan range for each index;
    galist_t *sub_tables;      // for multi index scan with or condition
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
    struct st_table_func func; // for table function
    union {
        sql_select_t *select_ctx;
        json_table_info_t *json_table_info; // for json table
    };
    uint32 plan_id; // for join order
    sql_table_type_t type;
    /* for CBO optimize */
    int64 card;
    int64 filter_rows; // save the filter card of table
    cbo_attribute_t cbo_attr;

    sql_text_t user;
    sql_text_t name;
    sql_text_t alias;
    sql_text_t dblink;
    sql_table_snapshot_t version;
    sql_join_node_t *join_node;

    project_col_array_t *project_col_array;
    galist_t *pushdown_columns;
    uint32 project_column_count;
    uint32 remote_id;
    uint32 col_start_pos;
    uint32 project_start_pos;
    sql_query_t *remote_query;
    join_cond_map_t *join_map;
    void *sink_all_list;
    uint32 remote_type;
    remote_fetcher_type_t fetch_type; /* the type of fetch data */
    uint32 is_ancestor;               // 0: not is ancestor, 1: is parent, 2: is grandfather, ...
    bool8 is_distribute_rule;
    bool8 tab_name_has_quote; // table name wrapped double quotations or not
    bool8 user_has_quote;     // user wrapped double quotations or not
    bool8 is_public_synonym;  // 0: not a public synonym, 1:public synonym

    bilist_t query_fields;
    bilist_t func_expr;
    hint_info_t *hint_info;
    specify_part_info_t part_info;
    subslct_table_usage_t subslct_tab_usage; // sub-select used for semi/anti join

    bool32 rowid_exists : 1;       // rowid exist in where clause or not
    bool32 rownodeid_exists : 1;   // rownodeid exist in where clause or not
    bool32 rs_nullable : 1;        // record whether rs_columns in current table can be nullable or not
    bool32 has_hidden_columns : 1; // indicates table has virtual, invisible column
    bool32 global_cached : 1;      // cached scan pages into global CR pool or not
    bool32 view_dml : 1;
    bool32 ret_full_fields : 1; // return full fields of single table flag
    bool32 for_update : 1;
    bool32 ineliminable : 1;       // indicates the sub-select table/view cannot be eliminated
    bool32 is_join_driver : 1;     // indicates the table is join driver table
    bool32 is_sub_table : 1;       // indicates this table is sub table for multi index scan
    bool32 is_descartes : 1;       // indicates this table is cartesian join with other tables
    bool32 index_cond_pruning : 1; // indicates index cond of this table has been pruned
    bool32 is_jsonb_table : 1;     // indicates index cond of this table has been pruned
    bool32 reserved : 18;

    tf_scan_flag_t tf_scan_flag; // Parallel Scan Indicator
    scan_part_info_t *scan_part_info;
    galist_t *for_update_cols;
    union {
        struct {
            knl_index_desc_t *index;    // for index scan
            uint16 scan_flag;           // index only/sort eliminate flag
            uint16 idx_equal_to;        // a = ? and b = ? and c > ? then idx_equal_to = 2
            uint16 equal_cols;          // include idx_equal_to and "a in (?,?) and b >?", for choose optimal index
            uint16 col_use_flag;        // indicate choose index with ancestor col or self join col
            uint32 index_dsc : 1;       // index scan direction,for sort eliminate
            uint32 rowid_usable : 1;    // flag for rowid scan
            uint32 index_full_scan : 1; // flag for index full scan
            uint32 index_skip_scan : 1; // flag for index skip scan
            uint32 is_push_down : 1;    // flag for push down
            uint32 opt_match_mode : 3;  // [0,7]
            uint32 skip_index_match : 1;
            uint32 multi_parts_scan : 1; // optim flag for multi knlcurs scan parts
            uint32 bindpar_onepart : 1;  // only one part left after the cond of bind parameter trimming
            uint32 index_ffs : 1;        // flag for index fast full scan
            uint32 reserved2 : 20;
            uint16 index_match_count; // for index match column count
            uint16 scan_mode;         // for table
            double cost;
            void *rowid_set;           // Use void* to point plan_rowid_set_t* for avoiding loop include;
            uint16 *idx_col_map;       // for index only scan, decode row by index defined sequence
            struct st_cond_tree *cond; // for multi index scan, create scan range for each index;
            galist_t *sub_tables;      // for multi index scan with or condition
        };
        scan_info_t scan_info;
    };
} sql_table_t;

typedef struct st_query_column {
    struct st_expr_tree *expr;
    text_t alias;
    bool32 exist_alias;
    text_t z_alias; // auto generated alias for SHARD decompile sql
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
    sql_text_t column_name;       // for insert column
    bool32 column_name_has_quote; // if column name wrapped with double quotation

    // for update column. like: update t_test t1 set t1.f1 = 1, for convenience, using expr for t1.f1
    struct st_expr_tree *column_expr; // for update column
    uint32 column_id;
    knl_column_t *column;

    // list of right value
    // for insert, may be a list. like: insert into tab() values(),(),()
    // for update, just one element
    galist_t *exprs; // list of st_expr_tree, supports insert some values
    uint32 rs_no;    // for update multi set, ref to subquery rs_column number, start with 1, 0 for non-multi set
    int32 ss_start;  // for array start subscript
    int32 ss_end;    // for array end subscript
} column_value_pair_t;

// for update multi set
#define PAIR_IN_MULTI_SET(pair) ((pair)->rs_no > 0)

typedef struct st_sql_update {
    galist_t *objects;
    galist_t *pairs;
    sql_query_t *query;
    struct st_plan_node *plan;
    hint_info_t *hint_info;
    struct st_cond_tree *cond; // for multi table update
    galist_t *ret_columns;     // returning columns
    uint32 param_start_pos;    // INSERT ON DUPLICATE KEY UPDATE first bind param pos
    bool32 check_self_update;  // check self update for multiple table update
    galist_t *pl_dc_lst;       // record plsql objects in current update context, for check privilege
} sql_update_t;

/* end: for update statement */
#ifdef Z_SHARDING

typedef enum {
    SHD_ROUTE_BY_RULE = 0,
    SHD_ROUTE_BY_NODE = 1,
    SHD_ROUTE_BY_NULL = 2,
} shd_route_by_t;

typedef struct st_sql_route {
    sql_table_t *rule;
    galist_t *pairs;
    uint32 pairs_count;
    uint32 *col_map;          // Indicate which column is set or not
    sql_select_t *select_ctx; // for insert ... select
    struct st_plan_node *plan;
    sql_update_t *update_ctx; // for on duplicate key update
    shd_route_by_t type;
    uint16 group_id;
    bool8 cols_specified;
    bool8 unused;
} sql_route_t;

#endif

typedef struct st_sql_delete {
    galist_t *objects;
    sql_query_t *query;
    struct st_plan_node *plan;
    hint_info_t *hint_info;
    struct st_cond_tree *cond; // for multiple table delete
    galist_t *ret_columns;     // returning columns
    galist_t *pl_dc_lst;       // record plsql objects in current update context, for check privilege
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
    sql_array_t ssa; // SubSelect Array for subselect expr
    galist_t *pairs;
    uint32 pairs_count;
    uint32 *col_map;          // Indicate which column is set or not
    uint16 *part_key_map;     // store column position in partition key definition
    sql_select_t *select_ctx; // for insert ... select
    struct st_plan_node *plan;
    hint_info_t *hint_info;
    sql_update_t *update_ctx; // for on duplicate key update
    uint32 flags;             // set of insert flags
    galist_t *ret_columns;    // returning columns
    uint32 batch_commit_cnt;  // for insert ... select, batch commit;
    galist_t *pl_dc_lst;      // record plsql objects in current insert context, for check privilege
    galist_t *into_list;
    uint32 syntax_flag; // syntax flag for insert ignore, insert all etc
} sql_insert_t;

#define MAX_ROW_SIZE 32000

/* end: for insert statement */
typedef struct st_sql_merge {
    struct st_cond_tree *insert_filter_cond;
    struct st_cond_tree *update_filter_cond;
    sql_update_t *update_ctx;
    sql_insert_t *insert_ctx;
    struct st_plan_node *plan;
    sql_query_t *query; // tables: 0:merge into table,  1:using table
    hint_info_t *hint_info;
    galist_t *pl_dc_lst; // record plsql objects in current update context, for check privilege
} sql_merge_t;

typedef struct st_sql_replace {
    sql_insert_t insert_ctx;
} sql_replace_t;

typedef struct st_par_scan_range {
    knl_part_locate_t part_loc;
    union {
        struct { // parallel heap scan range
            uint64 l_page;
            uint64 r_page;
        };
        knl_scan_range_t *idx_scan_range; // parallel index scan range
    };
} par_scan_range_t;

/* end: for merge statement */
#ifdef Z_SHARDING
// for online update
typedef enum en_shd_lock_unlock_type_t {
    SHD_LOCK_UNLOCK_TYPE_TALBE = 0,
    SHD_LOCK_UNLOCK_TYPE_NODE = 1,
} shd_lock_unlock_type_t;

typedef enum en_shd_lock_node_mode {
    SHD_LOCK_MODE_NO_LOCK = 0,
    SHD_LOCK_MODE_SHARE = 1,     /* SHARE */
    SHD_LOCK_MODE_EXCLUSIVE = 2, /* EXCLUSIVE */
} shd_lock_node_mode_t;

#define SHD_LOCK_CHK_INTERVAL (uint32)1000 // ms

typedef enum en_shd_wait_mode {
    SHD_WAIT_MODE_NO_WAIT = 0, /* NO WAIT */
    SHD_WAIT_MODE_WAIT,        /* WAIT */
} shd_wait_mode_t;

typedef struct st_shd_lock_node_def {
    shd_lock_node_mode_t lock_mode;
    shd_wait_mode_t wait_mode;
    uint32 wait_time; // unit second, only wait_mode = SHD_WAIT_MODE_WAIT,
    // the value is meaning
    // (wait_mode = SHD_WAIT_MODE_WAIT, value = 0) equal (wait_mode = SHD_WAIT_MODE_NO_WAIT)
} shd_lock_node_def_t;
#endif

status_t sql_instance_startup(void);
status_t sql_create_context_pool(void);
void sql_destroy_context_pool(void);
void sql_context_uncacheable(sql_context_t *sql_ctx);
void sql_free_context(sql_context_t *sql_ctx);

void sql_close_dc(context_ctrl_t *ctrl_ctx);
void sql_close_context_resource(context_ctrl_t *ctrl_ctx);
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
status_t sql_copy_str_safe(sql_context_t *sql_ctx, char *src, uint32 len, text_t *dst);
status_t sql_copy_str(sql_context_t *sql_ctx, char *src, text_t *dst);
status_t sql_copy_text(sql_context_t *sql_ctx, text_t *src, text_t *dst);
status_t sql_copy_binary(sql_context_t *sql_ctx, binary_t *src, binary_t *dst);
status_t sql_copy_text_upper(sql_context_t *sql_ctx, text_t *src, text_t *dst);
status_t sql_copy_file_name(sql_context_t *sql_ctx, text_t *src, text_t *dst);
/* copy object name and judge whether to convert it to upper case by USE_UPPER_CASE_NAMES */
status_t sql_copy_object_name(sql_context_t *ctx, word_type_t word_type, text_t *src, text_t *dst);
status_t sql_copy_object_name_loc(sql_context_t *ctx, word_type_t word_type, sql_text_t *src, sql_text_t *dst);
status_t sql_copy_object_name_ci(sql_context_t *ctx, word_type_t word_type, text_t *src, text_t *dst);
status_t sql_copy_prefix_tenant(void *stmt_in, text_t *src, text_t *dst, sql_copy_func_t sql_copy_func);
status_t sql_copy_object_name_prefix_tenant(void *stmt_in, word_type_t word_type, text_t *src, text_t *dst);
status_t sql_copy_name_prefix_tenant_loc(void *stmt_in, sql_text_t *src, sql_text_t *dst);
status_t sql_copy_object_name_prefix_tenant_loc(void *stmt_in, word_type_t word_type, sql_text_t *src, sql_text_t *dst);
status_t sql_user_prefix_tenant(void *session, char *username);
status_t sql_user_text_prefix_tenant(void *session_in, text_t *user, char *buf, uint32 buf_size);
status_t sql_generate_unnamed_table_name(void *stmt_in, sql_table_t *table, unnamed_tab_type_t type);
status_t sql_get_sort_item_project_id(sql_query_t *remote_query, sort_item_t *sort_item, uint32 *project_id);

static inline status_t sql_array_init(sql_array_t *array, uint32 capacity, void *ctx, ga_alloc_func_t alloc_func)
{
    if (alloc_func(ctx, capacity * sizeof(pointer_t), (void **)&array->items) != CT_SUCCESS) {
        return CT_ERROR;
    }

    MEMS_RETURN_IFERR(memset_sp(array->items, capacity * sizeof(pointer_t), 0, capacity * sizeof(pointer_t)));

    array->capacity = capacity;
    array->count = 0;
    array->context = ctx;
    array->alloc_func = alloc_func;
    array->name.str = NULL;
    array->name.len = 0;
    return CT_SUCCESS;
}

static inline status_t sql_create_array(sql_context_t *ctx, sql_array_t *array, char *name, uint32 capacity)
{
    CT_RETURN_IFERR(sql_array_init(array, capacity, ctx, sql_alloc_mem));

    if (name != NULL) {
        return sql_copy_str(ctx, name, &array->name);
    }

    return CT_SUCCESS;
}

status_t sql_array_put(sql_array_t *array, pointer_t ptr);
status_t sql_array_concat(sql_array_t *array1, sql_array_t *array2);
status_t sql_array_delete(sql_array_t *array, uint32 index);

static inline status_t sql_array_new(sql_array_t *array, uint32 size, pointer_t *ptr)
{
    if (array->alloc_func(array->context, size, ptr) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return sql_array_put(array, *ptr);
}

static inline void sql_array_reset(sql_array_t *array)
{
    array->count = 0;
}

status_t sql_array_set(sql_array_t *array, uint32 index, pointer_t ptr);

static inline void sql_init_context_stat(ctx_stat_t *stat)
{
    MEMS_RETVOID_IFERR(memset_s(stat, sizeof(ctx_stat_t), 0, sizeof(ctx_stat_t)));
}

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
    if (CT_IS_STRING_TYPE(tm->datatype)) {
        tm->is_char = KNL_COLUMN_IS_CHARACTER(kcol);
    }
}

status_t sql_check_datafile_path(text_t *name);

bool32 sql_if_all_comma_join(sql_join_node_t *join_node);
status_t sql_get_real_path(text_t *name, char *real_path);
void sql_context_inc_exec(sql_context_t *sql_ctx);
void sql_context_dec_exec(sql_context_t *sql_ctx);
bool32 sql_upper_case_name(sql_context_t *ctx);
#define MAX_ANCESTOR_LEVEL 3

#define SET_ANCESTOR_LEVEL(select_ctx, level)                                          \
    do {                                                                               \
        if ((level) > 0 && (level) <= MAX_ANCESTOR_LEVEL) {                            \
            CT_BIT_SET((select_ctx)->has_ancestor, CT_GET_MASK((level) - 1));          \
        } else if ((level) > MAX_ANCESTOR_LEVEL) {                                     \
            CT_BIT_SET((select_ctx)->has_ancestor, CT_GET_MASK(MAX_ANCESTOR_LEVEL));   \
        }                                                                              \
    } while (0)

#define RESET_ANCESTOR_LEVEL(select_ctx, level)                                 \
    do {                                                                        \
        if ((level) > 0 && (level) <= MAX_ANCESTOR_LEVEL) {                     \
            CT_BIT_RESET((select_ctx)->has_ancestor, CT_GET_MASK((level) - 1)); \
        }                                                                       \
    } while (0)

#ifdef __cplusplus
}
#endif

#endif
