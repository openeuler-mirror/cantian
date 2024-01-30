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
 * ctsql_verifier.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/verifier/ctsql_verifier.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_VERIFIER_H__
#define __SQL_VERIFIER_H__

#include "cm_defs.h"
#include "cm_list.h"
#include "ctsql_stmt.h"
#include "ctsql_cond.h"

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

#define SQL_WHERE_EXCL                                                                                          \
    (SQL_EXCL_AGGR | SQL_EXCL_SEQUENCE | SQL_EXCL_STAR | SQL_EXCL_PRIOR | SQL_EXCL_WIN_SORT | SQL_EXCL_UNNEST | \
        SQL_EXCL_GROUPING | SQL_EXCL_PATH_FUNC)

#define SQL_HAVING_EXCL                                                                                          \
    (SQL_EXCL_JOIN | SQL_EXCL_STAR | SQL_EXCL_SEQUENCE | SQL_EXCL_PRIOR | SQL_EXCL_LOB_COL | SQL_EXCL_WIN_SORT | \
        SQL_EXCL_UNNEST | SQL_EXCL_ARRAY | SQL_EXCL_PATH_FUNC)

#define SQL_CONNECT_BY_EXCL                                                                                     \
    (SQL_EXCL_AGGR | SQL_EXCL_SEQUENCE | SQL_EXCL_STAR | SQL_EXCL_LOB_COL | SQL_EXCL_ROOT | SQL_EXCL_WIN_SORT | \
        SQL_EXCL_JOIN | SQL_EXCL_UNNEST | SQL_EXCL_ARRAY | SQL_EXCL_GROUPING | SQL_EXCL_PATH_FUNC |             \
        SQL_EXCL_CONNECTBY_ATTR)

#define SQL_START_WITH_EXCL                                                                                  \
    (SQL_EXCL_AGGR | SQL_EXCL_SEQUENCE | SQL_EXCL_STAR | SQL_EXCL_PRIOR | SQL_EXCL_LOB_COL | SQL_EXCL_ROOT | \
        SQL_EXCL_JOIN | SQL_EXCL_WIN_SORT | SQL_EXCL_UNNEST | SQL_EXCL_ARRAY | SQL_EXCL_GROUPING |           \
        SQL_EXCL_PATH_FUNC | SQL_EXCL_CONNECTBY_ATTR)

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
        SQL_EXCL_ROWID | SQL_EXCL_DEFAULT | SQL_EXCL_ROWSCN | SQL_EXCL_LOB_COL | SQL_EXCL_BIND_PARAM |        \
        SQL_EXCL_WIN_SORT | SQL_EXCL_ROWSCN | SQL_EXCL_ARRAY | SQL_EXCL_WIN_SORT | SQL_EXCL_GROUPING |        \
        SQL_EXCL_PATH_FUNC | SQL_EXCL_ROWNODEID)

#define SQL_LIMIT_EXCL                                                                                        \
    (SQL_EXCL_AGGR | SQL_EXCL_COLUMN | SQL_EXCL_STAR | SQL_EXCL_SUBSELECT | SQL_EXCL_JOIN | SQL_EXCL_ROWNUM | \
        SQL_EXCL_ROWID | SQL_EXCL_DEFAULT | SQL_EXCL_ROWSCN | SQL_EXCL_WIN_SORT | SQL_EXCL_GROUPING |         \
        SQL_EXCL_SEQUENCE | SQL_EXCL_PATH_FUNC | SQL_EXCL_ROWNODEID)

#define SQL_CHECK_EXCL                                                                                              \
    (SQL_EXCL_AGGR | SQL_EXCL_STAR | SQL_EXCL_PRIOR | SQL_EXCL_SUBSELECT | SQL_EXCL_JOIN | SQL_EXCL_BIND_PARAM |    \
        SQL_EXCL_ROWNUM | SQL_EXCL_ROWID | SQL_EXCL_LOB_COL | SQL_EXCL_SEQUENCE | SQL_EXCL_CASE | SQL_EXCL_ROWSCN | \
        SQL_EXCL_WIN_SORT | SQL_EXCL_ROWNODEID)

#define SQL_AGGR_EXCL (SQL_EXCL_AGGR | SQL_EXCL_WIN_SORT | SQL_EXCL_GROUPING | SQL_EXCL_SEQUENCE)

#define SQL_JSON_TABLE_EXCL                                                                                       \
    (SQL_EXCL_AGGR | SQL_EXCL_STAR | SQL_EXCL_SEQUENCE | SQL_EXCL_WIN_SORT | SQL_EXCL_PATH_FUNC | SQL_EXCL_JOIN | \
        SQL_EXCL_PRIOR | SQL_EXCL_ROWNUM | SQL_EXCL_ROWSCN | SQL_EXCL_ROOT | SQL_EXCL_DEFAULT | SQL_EXCL_LEVEL |  \
        SQL_EXCL_CONNECTBY_ATTR | SQL_EXCL_METH_PROC | SQL_EXCL_METH_FUNC | SQL_EXCL_GROUPING | SQL_EXCL_COLL |   \
        SQL_EXCL_ARRAY | SQL_EXCL_PL_PROC)

#define SQL_NON_NUMERIC_FLAGS                                                                                   \
    (SQL_EXCL_AGGR | SQL_EXCL_COLUMN | SQL_EXCL_STAR | SQL_EXCL_SEQUENCE | SQL_EXCL_SUBSELECT | SQL_EXCL_JOIN | \
        SQL_EXCL_ROWNUM | SQL_EXCL_ROWID | SQL_EXCL_DEFAULT | SQL_EXCL_PRIOR | SQL_EXCL_LOB_COL |               \
        SQL_EXCL_BIND_PARAM | SQL_EXCL_CASE | SQL_EXCL_ROWSCN | SQL_EXCL_GROUPING | SQL_EXCL_ROWNODEID)

#define PL_EXPR_EXCL                                                                                       \
    (SQL_EXCL_AGGR | SQL_EXCL_STAR | SQL_EXCL_JOIN | SQL_EXCL_ROWNUM | SQL_EXCL_ROWID | SQL_EXCL_DEFAULT | \
        SQL_EXCL_SUBSELECT | SQL_EXCL_COLUMN | SQL_EXCL_ROWSCN | SQL_EXCL_ROWNODEID | SQL_EXCL_METH_PROC | \
        SQL_EXCL_PL_PROC)

#define PL_UDT_EXCL                                                                                        \
    (SQL_EXCL_AGGR | SQL_EXCL_STAR | SQL_EXCL_JOIN | SQL_EXCL_ROWNUM | SQL_EXCL_ROWID | SQL_EXCL_DEFAULT | \
        SQL_EXCL_SUBSELECT | SQL_EXCL_COLUMN | SQL_EXCL_ROWSCN | SQL_EXCL_ROWNODEID | SQL_EXCL_METH_PROC | \
        SQL_EXCL_WIN_SORT | SQL_EXCL_PRIOR | SQL_EXCL_GROUPING | SQL_EXCL_PATH_FUNC | SQL_EXCL_LEVEL |     \
        SQL_EXCL_PARENT | SQL_EXCL_CONNECTBY_ATTR | SQL_EXCL_LOB_COL | SQL_EXCL_ROOT | SQL_EXCL_PL_PROC)

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

#define SQL_POLICY_FUNC_STR_LEN (uint32)(CT_MAX_NAME_LEN * 4 + 8)
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
        bool32 verify_tables : 1; // for global view
        bool32 is_check_cons : 1;
        bool32 has_except_intersect : 1;
        bool32 same_join_tab : 1;
        bool32 has_ddm_col : 1;
        bool32 from_table_define : 1;
        bool32 unused : 19;
    };

    uint32 aggr_flags; // insert aggr into query columns list flags
    uint32 excl_flags; // exclusive flags
    uint32 incl_flags; // included  flags

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
    sql_query_t *curr_query; // for only index scan

    // for nonselect
    sql_table_t *table;
    knl_column_def_t *column;
    knl_table_def_t *table_def;

#ifdef Z_SHARDING
    verifier_func excl_func;
#endif
    struct st_sql_verifier *parent;
    var_udo_t *obj;     // the verifier in package object
    typmode_t *typmode; // for modify columns in function index
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
    sql_array_t *tables; // for select/update/delete
    sql_table_t *table;  // for insert
    sql_hint_conflict_t conflicts;
} sql_hint_verifier_t;

hint_id_t get_hint_id_4_index(index_hint_key_wid_t access_hint);
bool32 index_intercepted_in_hints(sql_table_t *table, uint32 index_id);
bool32 index_specified_in_hint(sql_table_t *t, hint_id_t hint_id, uint32 idx_id);
bool32 if_index_in_hint(sql_table_t *t, hint_id_t hint_id, uint32 idx_id);

void set_ddm_attr(sql_verifier_t *verif, var_column_t *v_col, knl_column_t *knl_col);

void sql_add_first_exec_node(sql_verifier_t *verif, expr_node_t *node);

void sql_infer_func_optmz_mode(sql_verifier_t *verif, expr_node_t *func);
void sql_infer_oper_optmz_mode(sql_verifier_t *verif, expr_node_t *node);
void sql_infer_unary_oper_optmz_mode(sql_verifier_t *verif, expr_node_t *node);
#ifdef __cplusplus
extern "C" {
#endif

status_t sql_verify(sql_stmt_t *stmt);
status_t sql_verify_expr_node(sql_verifier_t *verif, expr_node_t *node);
status_t sql_verify_current_expr(sql_verifier_t *verif, expr_tree_t *verf_expr);
status_t sql_verify_expr(sql_verifier_t *verif, expr_tree_t *expr);
status_t sql_verify_cond(sql_verifier_t *verif, cond_tree_t *cond);
status_t sql_verify_select(sql_stmt_t *stmt, sql_select_t *select_ctx);
status_t sql_verify_sub_select(sql_stmt_t *stmt, sql_select_t *select_ctx, sql_verifier_t *parent);
status_t sql_verify_select_context(sql_verifier_t *verif, sql_select_t *select_ctx);
status_t sql_verify_query_order(sql_verifier_t *verif, sql_query_t *query, galist_t *sort_items, bool32 is_query);
status_t sql_verify_query_distinct(sql_verifier_t *verif, sql_query_t *query);
status_t sql_verify_query_pivot(sql_verifier_t *verif, sql_query_t *query);
status_t sql_match_distinct_expr(sql_stmt_t *stmt, sql_query_t *query, expr_tree_t **expr, bool32 need_clone);
status_t sql_verify_group_concat_order(sql_verifier_t *verif, expr_node_t *func, galist_t *sort_items);
status_t sql_verify_listagg_order(sql_verifier_t *verif, galist_t *sort_items);

void sql_init_aggr_node(expr_node_t *node, uint32 fun_id, uint32 ofun_id);
status_t sql_adjust_oper_node(sql_verifier_t *verif, expr_node_t *node);
status_t sql_table_cache_query_field(sql_stmt_t *stmt, sql_table_t *table, query_field_t *src_query_fld);
status_t sql_table_cache_cond_query_field(sql_stmt_t *stmt, sql_table_t *table, query_field_t *src_query_fld);
status_t sql_add_parent_refs(sql_stmt_t *stmt, galist_t *parent_refs, uint32 tab, expr_node_t *node);
void sql_del_parent_refs(galist_t *parent_refs, uint32 tab, expr_node_t *node);
status_t sql_init_table_dc(sql_stmt_t *stmt, sql_table_t *sql_table);
status_t sql_verify_expr_array_attr(expr_node_t *node, expr_tree_t *expr);
void sql_init_udo(var_udo_t *udo_obj);
void sql_init_udo_with_str(var_udo_t *udo_obj, char *user, char *pack, char *name);
void sql_init_udo_with_text(var_udo_t *udo_obj, text_t *user, text_t *pack, text_t *name);
uint32 sql_get_any_priv_id(sql_stmt_t *stmt);
void sql_check_user_priv(sql_stmt_t *stmt, text_t *obj_user);
void sql_join_set_default_oper(sql_join_node_t *node);
status_t sql_gen_winsort_rs_columns(sql_stmt_t *stmt, sql_query_t *query);
bool32 sql_check_user_exists(knl_handle_t session, text_t *name);
status_t sql_match_group_expr(sql_stmt_t *stmt, sql_query_t *query, expr_tree_t *expr);
bool32 sql_check_reserved_is_const(expr_node_t *node);
#ifdef Z_SHARDING
status_t sql_verify_route(sql_stmt_t *stmt, sql_route_t *route_ctx);
status_t sql_verify_route(sql_stmt_t *stmt, sql_route_t *route_ctx);
status_t shd_verfity_excl_user_function(sql_verifier_t *verif, sql_stmt_t *stmt);
status_t shd_verify_user_function(sql_verifier_t *verif, expr_node_t *node);
#endif

status_t sql_gen_winsort_rs_col_by_expr(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *node);
status_t sql_gen_winsort_rs_col_by_expr_tree(sql_stmt_t *stmt, sql_query_t *query, expr_tree_t *expr);
void set_winsort_rs_node_flag(sql_query_t *query);
bool32 if_unqiue_idx_in_list(sql_query_t *query, sql_table_t *table, galist_t *list);
bool32 if_query_distinct_can_eliminate(sql_verifier_t *verif, sql_query_t *query);
status_t sql_add_sequence_node(sql_stmt_t *stmt, expr_node_t *node);
status_t sql_static_check_dml_pair(sql_verifier_t *verif, const column_value_pair_t *pair);
status_t sql_verify_table_dml_object(knl_handle_t session, sql_stmt_t *stmt, source_location_t loc, knl_dictionary_t dc,
    bool32 is_delete);
bool32 is_array_subscript_correct(int32 start, int32 end);
status_t sql_gen_group_rs_col_by_subselect(sql_stmt_t *stmt, galist_t *rs_col, expr_node_t *node);
status_t sql_gen_group_rs_by_expr(sql_stmt_t *stmt, galist_t *rs_col, expr_node_t *node);
status_t sql_add_ref_func_node(sql_verifier_t *verif, expr_node_t *node);
void sql_set_ancestor_level(sql_select_t *select_ctx, uint32 temp_level);

#ifdef __cplusplus
}
#endif

#endif
