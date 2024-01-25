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
 * ctsql_package.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/node/ctsql_package.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_PACKAGE_H__
#define __SQL_PACKAGE_H__

#include "ctsql_context.h"
#include "ctsql_func.h"

#define STANDARD_PACK_NAME "DBE_STD"
extern status_t sql_verify_column_expr_tree(sql_verifier_t *verf, knl_column_t *column, expr_tree_t *expr_tree_src,
    expr_tree_t *expr_update_tree_src);
// built-in package
typedef struct st_sql_package {
    text_t name;
    uint32 var_count;
    variant_t *vars;
    uint32 func_count;
    sql_func_t *funcs;
    uint32 pack_id;
} sql_package_t;

typedef enum en_package_item_id {
    DBE_AC_ROW_PACK_ID = 0,
    DBE_DEBUG_PACK_ID,
    DBE_DIAGNOSE_PACK_ID,
    DBE_LOB_PACK_ID,
    DBE_MASK_DATA_PACK_ID,
    DBE_OUTPUT_PACK_ID,
    DBE_RANDOM_PACK_ID,
    DBE_RSRC_MGR_PACK_ID,
    DBE_SQL_PACK_ID,
    DBE_STATS_PACK_ID,
    DBE_STD_PACK_ID,
    DBE_TASK_PACK_ID,
    DBE_UTIL_PACK_ID,
} package_item_id_t;

typedef struct st_dbe_func_param {
    uint32 id;            // column id
    char *name;           // column name
    uint32 datatype;      // datatype of the parameter
    bool32 nullable;      // null or not null
    uint32 param_max_len; // parameter len
} dbe_func_param_t;

typedef struct st_obj_type_id_def {
    text_t obj_type;
    object_type_t type_id;
} obj_type_id;

// local struct type for partitioned function
typedef struct sql_func_part_arg {
    variant_t arg1; // calc size type
    variant_t arg2; // user name
    variant_t arg3; // table name
    variant_t arg4; // index name or column id or part name
    bool32 is_pending;
} sql_func_part_arg_t;

status_t sql_get_dbe_param_value_loc(sql_stmt_t *stmt, expr_node_t *func, dbe_func_param_t *dbe_param,
                                     uint32 param_pos, variant_t *result, source_location_t *node_loc);
status_t sql_get_dbe_param_value(sql_stmt_t *stmt, expr_node_t *func, dbe_func_param_t *dbe_param, uint32 param_pos,
                                 variant_t *result);
status_t sql_check_object_name(text_t *name, const char *object_type, source_location_t loc);
status_t sql_has_table_select_privs(knl_session_t *session, text_t *check_user, text_t *owner, text_t *obj,
    object_type_t objtype, obj_privs_id opid);
status_t sql_invoke_pack_func(sql_stmt_t *stmt, expr_node_t *node, variant_t *result);
void sql_convert_standard_pack_func(text_t *func_name, var_func_t *v);
void sql_convert_pack_func(text_t *pack_name, text_t *func_name, var_func_t *v);
void pl_convert_pack_func(uint32 pack_id, text_t *func_name, uint8 *func_id);
text_t *sql_pack_name(void *set, uint32 id);
sql_func_t *sql_get_pack_func(var_func_t *v);
sql_package_t *sql_get_pack(uint32 id);
uint32 sql_get_pack_num(void);
bool32 sql_pack_exists(text_t *pack_name);
void process_word_case_sensitive(word_t *word);
status_t sql_task_get_nextdate(sql_stmt_t *stmt, expr_node_t *interval, variant_t *result);
bool32 sql_transform_task_content(char *dest, uint32 max_dest, const char *src, uint32 temp_src_len);
status_t sql_verify_dbe_func(sql_verifier_t *verf, expr_node_t *func, dbe_func_param_t *dbe_param, uint32 param_count);

status_t sql_func_get_table_name(sql_stmt_t *stmt, expr_node_t *func, variant_t *res);
status_t sql_verify_get_table_name(sql_verifier_t *verifier, expr_node_t *func);
status_t sql_func_ind_pos(sql_stmt_t *stmt, expr_node_t *func, variant_t *res);
status_t sql_verify_ind_pos(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_partitioned_lobsize(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_func_partitioned_tabsize(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_func_table_partsize(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_func_partitioned_indsize(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_func_table_indsize(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_partitioned_lobsize(sql_verifier_t *verf, expr_node_t *func);
status_t sql_verify_partitioned_tabsize(sql_verifier_t *verf, expr_node_t *func);
status_t sql_verify_partitioned_indsize(sql_verifier_t *verf, expr_node_t *func);
status_t sql_verify_table_indsize(sql_verifier_t *verf, expr_node_t *func);
status_t sql_verify_table_partsize(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_has_obj_privs(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_has_obj_privs(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_tenant_check(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_tenant_check(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_list_cols(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_list_cols(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_raft_add_member(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_raft_add_member(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_raft_del_member(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_raft_del_member(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_raft_query_info(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_raft_query_info(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_raft_version(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_raft_version(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_raft_monitor_info(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_raft_monitor_info(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_raft_set_param(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_raft_set_param(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_segment_size(sql_stmt_t *stmt, expr_node_t *func, variant_t *res);
status_t sql_verify_segment_size(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_sleep(sql_stmt_t *stmt, expr_node_t *func, variant_t *res);
status_t sql_verify_sleep(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_space_size(sql_stmt_t *stmt, expr_node_t *func, variant_t *res);
status_t sql_verify_space_size(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_tab_type(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_func_to_tablespace_name(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_to_tablespace_name(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_to_username(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_to_username(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_lob_segment_free_size(sql_stmt_t *stmt, expr_node_t *func, variant_t *res);
status_t sql_verify_lob_segment_free_size(sql_verifier_t *verf, expr_node_t *func);

#endif
