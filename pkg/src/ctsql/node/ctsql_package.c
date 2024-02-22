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
 * ctsql_package.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/node/ctsql_package.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_package.h"
#include "cm_utils.h"
#include "srv_instance.h"
#include "pl_compiler.h"
#include "pl_executor.h"
#include "pl_debugger.h"
#include "dml_parser.h"
#include "ctsql_parser.h"
#include "func_parser.h"
#include "ctsql_privilege.h"
#include "knl_interface.h"
#include "knl_table.h"
#include "ddl_parser.h"
#include "func_others.h"
#include "func_string.h"
#include "ctsql_privilege.h"
#include "decl.h"
#include "pl_dbg_pack.h"

#define pl_sender (&g_instance->sql.pl_sender)

static dbe_func_param_t g_collect_table_stats_params[] = {
    // id, name                ,datatype,      nullable    parameter len
    { 0,  "schema",          CT_TYPE_VARCHAR, CT_FALSE,   CT_MAX_NAME_LEN },
    { 1,  "name",            CT_TYPE_VARCHAR, CT_FALSE,   CT_MAX_NAME_LEN },
    { 2,  "part_name",       CT_TYPE_VARCHAR, CT_TRUE,    CT_MAX_NAME_LEN },
    { 3,  "sample_ratio",    CT_TYPE_NUMBER,  CT_TRUE,    CT_INVALID_ID32 },
    { 4,  "block_sample",    CT_TYPE_BOOLEAN, CT_TRUE,    CT_INVALID_ID32 },
    { 5,  "method_opt",      CT_TYPE_VARCHAR, CT_TRUE,    CT_INVALID_ID32 },
};

static dbe_func_param_t g_collect_schema_stats_params[] = {
    // id, name                ,datatype,      nullable      parameter len
    { 0,  "schema",          CT_TYPE_VARCHAR, CT_FALSE,    CT_MAX_NAME_LEN },
    { 1,  "sample_ratio",    CT_TYPE_NUMBER,  CT_TRUE,    CT_INVALID_ID32 },
    { 2,  "block_sample",    CT_TYPE_BOOLEAN, CT_TRUE,    CT_INVALID_ID32 },
    { 3,  "method_opt",      CT_TYPE_VARCHAR, CT_TRUE,    CT_INVALID_ID32 },
};

static dbe_func_param_t g_collect_index_stats_params[] = {
    // id, name                ,datatype,      nullable      parameter len
    { 0,  "table_schema",      CT_TYPE_VARCHAR, CT_FALSE,    CT_MAX_NAME_LEN },
    { 1,  "index_name",        CT_TYPE_VARCHAR, CT_FALSE,   CT_MAX_NAME_LEN },
    { 2,  "table_name",        CT_TYPE_VARCHAR, CT_FALSE,   CT_MAX_NAME_LEN },
    { 3,  "sample_ratio",      CT_TYPE_NUMBER,  CT_TRUE,    CT_INVALID_ID32 },
};

static dbe_func_param_t g_delete_table_stats_params[] = {
    // id, name                ,datatype,         nullable      parameter len
    { 0,  "schema",         CT_TYPE_VARCHAR, CT_FALSE,    CT_MAX_NAME_LEN },
    { 1,  "name",           CT_TYPE_VARCHAR, CT_FALSE,    CT_MAX_NAME_LEN },
    { 2,  "part_name",      CT_TYPE_VARCHAR, CT_TRUE,     CT_MAX_NAME_LEN },
};

static dbe_func_param_t g_ddm_add_rule_params[] = {
    // id, name                    ,datatype,         nullable      parameter len
    { 0,  "object_schema",         CT_TYPE_VARCHAR, CT_FALSE,    CT_MAX_NAME_LEN },
    { 1,  "object_name",           CT_TYPE_VARCHAR, CT_FALSE,    CT_MAX_NAME_LEN },
    { 2,  "column_name",           CT_TYPE_VARCHAR, CT_TRUE,     CT_MAX_NAME_LEN },
    { 3,  "policy_name",           CT_TYPE_VARCHAR, CT_TRUE,     CT_MAX_NAME_LEN },
    { 4,  "policy_type",           CT_TYPE_VARCHAR, CT_TRUE,     CT_MAX_NAME_LEN },
    { 5,  "mask_value",            CT_TYPE_VARCHAR, CT_TRUE,     CT_MAX_DDM_LEN },
};

static dbe_func_param_t g_ddm_del_rule_params[] = {
    // id, name                ,datatype,         nullable      parameter len
    { 0,  "object_schema",     CT_TYPE_VARCHAR, CT_FALSE,    CT_MAX_NAME_LEN },
    { 1,  "object_name",       CT_TYPE_VARCHAR, CT_FALSE,    CT_MAX_NAME_LEN },
    { 2,  "policy_name",       CT_TYPE_VARCHAR, CT_TRUE,     CT_MAX_NAME_LEN },
};

static dbe_func_param_t g_delete_schema_stats_params[] = {
    // id, name                ,datatype,   nullable      parameter len
    { 0, "name",       CT_TYPE_VARCHAR, CT_FALSE,    CT_MAX_NAME_LEN },
};

static dbe_func_param_t g_purge_stats_params[] = {
    // id, name                ,datatype,         nullable      parameter len
    { 0, "before",              CT_TYPE_TIMESTAMP, CT_FALSE,    CT_INVALID_ID32 },
};

static dbe_func_param_t g_compile_schema_params[] = {
    // id, name                ,datatype,      nullable      parameter len
    { 0, "schema",         CT_TYPE_VARCHAR, CT_FALSE,   CT_MAX_NAME_LEN },
    { 1, "all",            CT_TYPE_BOOLEAN, CT_TRUE,    CT_INVALID_ID32 },
};

static dbe_func_param_t g_submit_task_params[] = {
    // id, name        ,datatype,         nullable      parameter len
    { 0, "id",        CT_TYPE_NUMBER,  CT_FALSE,   CT_INVALID_ID32 },
    { 1, "content",   CT_TYPE_VARCHAR, CT_FALSE,   CT_INVALID_ID32 },
    { 2, "next_time", CT_TYPE_DATE,    CT_TRUE,    CT_INVALID_ID32 },
    { 3, "interval",  CT_TYPE_VARCHAR, CT_TRUE,    CT_INVALID_ID32 },
    { 4, "no_check",  CT_TYPE_BOOLEAN, CT_TRUE,    CT_INVALID_ID32 },
};

static dbe_func_param_t g_run_task_params[] = {
    // id, name        ,datatype,         nullable      parameter len
    { 0, "id",        CT_TYPE_NUMBER,    CT_FALSE,     CT_INVALID_ID32 },
    { 1, "force",     CT_TYPE_BOOLEAN,   CT_TRUE,      CT_INVALID_ID32 },
};

static dbe_func_param_t g_cancel_task_params[] = {
    // id, name   ,datatype,     nullable      parameter len
    { 0, "id",   CT_TYPE_NUMBER, CT_FALSE,    CT_INVALID_ID32 },
};

static dbe_func_param_t g_suspend_job_params[] = {
    // id, name     ,datatype,         nullable      parameter len
    { 0, "id",        CT_TYPE_NUMBER,  CT_FALSE,    CT_INVALID_ID32 },
    { 1, "broken",    CT_TYPE_BOOLEAN, CT_FALSE,    CT_INVALID_ID32 },
    { 2, "next_time", CT_TYPE_DATE,    CT_TRUE,    CT_INVALID_ID32 },
};

static dbe_func_param_t g_create_cgroup_params[] = {
    // id, name,             datatype,         nullable      parameter len
    { 0, "name",            CT_TYPE_VARCHAR,  CT_FALSE,    CT_INVALID_ID32 },
    { 1, "comment",         CT_TYPE_VARCHAR,  CT_TRUE,    CT_INVALID_ID32 },
};

static dbe_func_param_t g_delete_cgroup_params[] = {
    // id, name,           datatype,         nullable      parameter len
    { 0, "name",   CT_TYPE_VARCHAR,  CT_FALSE,    CT_INVALID_ID32 },
};

static dbe_func_param_t g_update_cgroup_params[] = {
    // id, name,        datatype,         nullable      parameter len
    { 0, "name",       CT_TYPE_VARCHAR,  CT_FALSE,    CT_INVALID_ID32 },
    { 1, "comment",    CT_TYPE_VARCHAR,  CT_TRUE,    CT_INVALID_ID32 },
};

static dbe_func_param_t g_create_plan_params[] = {
    // id, name,    datatype,         nullable      parameter len
    { 0, "name",    CT_TYPE_VARCHAR,  CT_FALSE,    CT_INVALID_ID32 },
    { 1, "comment", CT_TYPE_VARCHAR,  CT_TRUE,    CT_INVALID_ID32 },
    { 2, "type",    CT_TYPE_NUMBER,   CT_TRUE,    CT_INVALID_ID32 },
};

static dbe_func_param_t g_validate_plan_params[] = {
    // id, name,    datatype,         nullable      parameter len
    { 0, "name",   CT_TYPE_VARCHAR,  CT_FALSE,    CT_INVALID_ID32 },
};

static dbe_func_param_t g_delete_plan_params[] = {
    // id, name,    datatype,         nullable      parameter len
    { 0, "name",   CT_TYPE_VARCHAR,  CT_FALSE,    CT_INVALID_ID32 },
};

static dbe_func_param_t g_update_plan_params[] = {
    // id, name,         datatype,         nullable      parameter len
    { 0, "name",         CT_TYPE_VARCHAR,  CT_FALSE,    CT_INVALID_ID32 },
    { 1, "comment",      CT_TYPE_VARCHAR,  CT_TRUE,     CT_INVALID_ID32 },
};

static dbe_func_param_t g_add_user_to_group_params[] = {
    // id, name,         datatype,         nullable      parameter len
    { 0, "name",          CT_TYPE_VARCHAR,  CT_FALSE,    CT_INVALID_ID32 },
    { 1, "control_group", CT_TYPE_VARCHAR,  CT_TRUE,     CT_INVALID_ID32 },
};

static dbe_func_param_t g_create_plan_rule_params[] = {
    // id, name,               datatype,         nullable      parameter len
    { 0,  "plan_name",         CT_TYPE_VARCHAR,  CT_FALSE,    CT_INVALID_ID32 },
    { 1,  "control_group",     CT_TYPE_VARCHAR,  CT_FALSE,    CT_INVALID_ID32 },
    { 2,  "comment",           CT_TYPE_VARCHAR,  CT_TRUE,    CT_INVALID_ID32 },
    { 3,  "cpu",               CT_TYPE_NUMBER,  CT_TRUE,    CT_INVALID_ID32 },
    { 4,  "sessions",          CT_TYPE_NUMBER,  CT_TRUE,    CT_INVALID_ID32 },
    { 5,  "active_sess",       CT_TYPE_NUMBER,  CT_TRUE,    CT_INVALID_ID32 },
    { 6,  "queue_time",        CT_TYPE_NUMBER,  CT_TRUE,    CT_INVALID_ID32 },
    { 7,  "max_exec_time",     CT_TYPE_NUMBER,  CT_TRUE,    CT_INVALID_ID32 },
    { 8,  "temp_pool",         CT_TYPE_NUMBER,  CT_TRUE,    CT_INVALID_ID32 },
    { 9,  "max_iops",          CT_TYPE_NUMBER,  CT_TRUE,    CT_INVALID_ID32 },
    { 10, "max_commits",       CT_TYPE_NUMBER,  CT_TRUE,    CT_INVALID_ID32 },
};

static dbe_func_param_t g_remove_plan_rule_params[] = {
    // id, name,               datatype,         nullable      parameter len
    { 0,  "plan_name",         CT_TYPE_VARCHAR,  CT_FALSE,    CT_INVALID_ID32 },
    { 1,  "control_group",     CT_TYPE_VARCHAR,  CT_FALSE,    CT_INVALID_ID32 },
};

static dbe_func_param_t g_update_plan_rule_params[] = {
    // id, name,                datatype,         nullable      parameter len
    { 0,  "plan_name",     CT_TYPE_VARCHAR, CT_FALSE,    CT_INVALID_ID32 },
    { 1,  "control_group", CT_TYPE_VARCHAR, CT_FALSE,    CT_INVALID_ID32 },
    { 2,  "comment",       CT_TYPE_VARCHAR, CT_TRUE,    CT_INVALID_ID32 },
    { 3,  "cpu",           CT_TYPE_NUMBER,  CT_TRUE,    CT_INVALID_ID32 },
    { 4,  "sessions",      CT_TYPE_NUMBER,  CT_TRUE,    CT_INVALID_ID32 },
    { 5,  "active_sess",   CT_TYPE_NUMBER,  CT_TRUE,    CT_INVALID_ID32 },
    { 6,  "queue_time",    CT_TYPE_NUMBER,  CT_TRUE,    CT_INVALID_ID32 },
    { 7,  "max_exec_time", CT_TYPE_NUMBER,  CT_TRUE,    CT_INVALID_ID32 },
    { 8,  "temp_pool",     CT_TYPE_NUMBER,  CT_TRUE,    CT_INVALID_ID32 },
    { 9,  "max_iops",      CT_TYPE_NUMBER,  CT_TRUE,    CT_INVALID_ID32 },
    { 10, "max_commits",   CT_TYPE_NUMBER,  CT_TRUE,    CT_INVALID_ID32 },
};

static dbe_func_param_t g_mod_column_stats_params[] = {
    // id, name,                datatype,         nullable   parameter len
    { 0,  "table_schema",    CT_TYPE_VARCHAR, CT_FALSE,     CT_MAX_NAME_LEN },
    { 1,  "table_name",      CT_TYPE_VARCHAR, CT_FALSE,     CT_MAX_NAME_LEN },
    { 2,  "column_name",     CT_TYPE_VARCHAR, CT_FALSE,     CT_MAX_NAME_LEN },
    { 3,  "part_name",       CT_TYPE_VARCHAR, CT_TRUE,      CT_MAX_NAME_LEN },
    { 4,  "dist_nums",       CT_TYPE_NUMBER,  CT_TRUE,      CT_INVALID_ID32 },
    { 5,  "density",         CT_TYPE_NUMBER,  CT_TRUE,      CT_INVALID_ID32 },
    { 6,  "null_cnt",        CT_TYPE_NUMBER,  CT_TRUE,      CT_INVALID_ID32 },
    { 7,  "max_value",       CT_TYPE_VARCHAR, CT_TRUE,      CT_MAX_MIN_VALUE_SIZE },
    { 8,  "min_value",       CT_TYPE_VARCHAR, CT_TRUE,      CT_MAX_MIN_VALUE_SIZE },
    { 9,  "force",           CT_TYPE_BOOLEAN, CT_TRUE,      CT_INVALID_ID32 },
};

static dbe_func_param_t g_set_index_stats_params[] = {
    // id, name,                datatype,         nullable   parameter len
    { 0,  "table_schema",          CT_TYPE_VARCHAR, CT_FALSE,     CT_MAX_NAME_LEN },
    { 1,  "index_name",            CT_TYPE_VARCHAR, CT_FALSE,     CT_MAX_NAME_LEN },
    { 2,  "part_name",             CT_TYPE_VARCHAR, CT_TRUE,      CT_MAX_NAME_LEN },
    { 3,  "leaf_blk_nums",         CT_TYPE_NUMBER,  CT_TRUE,      CT_INVALID_ID32 },
    { 4,  "dist_key_nums",         CT_TYPE_NUMBER,  CT_TRUE,      CT_INVALID_ID32 },
    { 5,  "avg_leaf_per_key",      CT_TYPE_NUMBER,  CT_TRUE,      CT_INVALID_ID32 },
    { 6,  "avg_data_blk_per_key",  CT_TYPE_NUMBER,  CT_TRUE,      CT_INVALID_ID32 },
    { 7,  "cluster_factor",        CT_TYPE_NUMBER,  CT_TRUE,      CT_INVALID_ID32 },
    { 8,  "index_height",          CT_TYPE_NUMBER,  CT_TRUE,      CT_INVALID_ID32 },
    { 9,  "combndv2",              CT_TYPE_NUMBER,  CT_TRUE,      CT_INVALID_ID32 },
    { 10, "combndv3",              CT_TYPE_NUMBER,  CT_TRUE,      CT_INVALID_ID32 },
    { 11, "combndv4",              CT_TYPE_NUMBER,  CT_TRUE,      CT_INVALID_ID32 },
    { 12, "force",                 CT_TYPE_BOOLEAN, CT_TRUE,      CT_INVALID_ID32 },
};

static dbe_func_param_t g_set_table_stats_params[] = {
    // id, name,                datatype,         nullable   parameter len
    { 0,  "schema",         CT_TYPE_VARCHAR, CT_FALSE,     CT_MAX_NAME_LEN },
    { 1,  "name",           CT_TYPE_VARCHAR, CT_FALSE,     CT_MAX_NAME_LEN },
    { 2,  "part_name",      CT_TYPE_VARCHAR, CT_TRUE,      CT_MAX_NAME_LEN },
    { 3,  "row_nums",       CT_TYPE_NUMBER,  CT_TRUE,      CT_INVALID_ID32 },
    { 4,  "blk_nums",       CT_TYPE_NUMBER,  CT_TRUE,      CT_INVALID_ID32 },
    { 5,  "avgr_len",       CT_TYPE_NUMBER,  CT_TRUE,      CT_INVALID_ID32 },
    { 6,  "samplesize",     CT_TYPE_NUMBER,  CT_TRUE,      CT_INVALID_ID32 },
    { 7,  "force",          CT_TYPE_BOOLEAN, CT_TRUE,      CT_INVALID_ID32 },
};

static dbe_func_param_t g_lock_table_stats_params[] = {
    // id, name,        datatype,       nullable   parameter len
    { 0,  "schema", CT_TYPE_VARCHAR, CT_FALSE,   CT_MAX_NAME_LEN },
    { 1,  "name",   CT_TYPE_VARCHAR, CT_FALSE,   CT_MAX_NAME_LEN },
};

static dbe_func_param_t g_unlock_table_stats_params[] = {
    // id, name,        datatype,       nullable   parameter len
    { 0,  "schema", CT_TYPE_VARCHAR, CT_FALSE,   CT_MAX_NAME_LEN },
    { 1,  "name",   CT_TYPE_VARCHAR, CT_FALSE,   CT_MAX_NAME_LEN },
};

static dbe_func_param_t g_add_policy_params[] = {
    // id, name,                datatype,       nullable      parameter len
    { 0,  "object_schema",     CT_TYPE_VARCHAR, CT_FALSE,    CT_MAX_NAME_LEN },
    { 1,  "object_name",       CT_TYPE_VARCHAR, CT_FALSE,    CT_MAX_NAME_LEN },
    { 2,  "policy_name",       CT_TYPE_VARCHAR, CT_FALSE,    CT_MAX_NAME_LEN },
    { 3,  "function_schema",   CT_TYPE_VARCHAR, CT_FALSE,    CT_MAX_NAME_LEN },
    { 4,  "policy_function",   CT_TYPE_VARCHAR, CT_FALSE,    CT_MAX_NAME_LEN },
    { 5,  "types",             CT_TYPE_VARCHAR, CT_TRUE,     CT_INVALID_ID32 },
    { 6,  "enable",            CT_TYPE_BOOLEAN, CT_TRUE,     CT_INVALID_ID32 },
};

static dbe_func_param_t g_drop_policy_params[] = {
    // id, name,                datatype,       nullable      parameter len
    { 0,  "object_schema",     CT_TYPE_VARCHAR, CT_FALSE,    CT_MAX_NAME_LEN },
    { 1,  "object_name",       CT_TYPE_VARCHAR, CT_FALSE,    CT_MAX_NAME_LEN },
    { 2,  "policy_name",       CT_TYPE_VARCHAR, CT_FALSE,    CT_MAX_NAME_LEN },
};

static dbe_func_param_t g_enable_policy_params[] = {
    // id, name,                datatype,       nullable      parameter len
    { 0,  "object_schema",     CT_TYPE_VARCHAR, CT_FALSE,    CT_MAX_NAME_LEN },
    { 1,  "object_name",       CT_TYPE_VARCHAR, CT_FALSE,    CT_MAX_NAME_LEN },
    { 2,  "policy_name",       CT_TYPE_VARCHAR, CT_FALSE,    CT_MAX_NAME_LEN },
    { 3,  "enable",            CT_TYPE_BOOLEAN, CT_TRUE,     CT_INVALID_ID32 },
};

static dbe_func_param_t g_diag_partab_tabsize[] = {
    // id, name,                datatype,       nullable      parameter len
    { 0,  "size_type",       CT_TYPE_INTEGER, CT_FALSE,    CT_INVALID_INT32 },
    { 1,  "user_name",       CT_TYPE_VARCHAR, CT_FALSE,    CT_MAX_NAME_LEN  },
    { 2,  "table_name",      CT_TYPE_VARCHAR, CT_FALSE,    CT_MAX_NAME_LEN  },
};

static dbe_func_param_t g_diag_partab_indsize[] = {
    // id, name,                datatype,       nullable      parameter len
    { 0,  "size_type",       CT_TYPE_INTEGER, CT_FALSE,    CT_INVALID_INT32 },
    { 1,  "user_name",       CT_TYPE_VARCHAR, CT_FALSE,    CT_MAX_NAME_LEN  },
    { 2,  "table_name",      CT_TYPE_VARCHAR, CT_FALSE,    CT_MAX_NAME_LEN  },
    { 3,  "index_name",      CT_TYPE_VARCHAR, CT_TRUE,     CT_MAX_NAME_LEN  },
};

static dbe_func_param_t g_diag_tab_indsize[] = {
    // id, name,                datatype,       nullable      parameter len
    { 0,  "size_type",       CT_TYPE_INTEGER, CT_FALSE,    CT_INVALID_INT32 },
    { 1,  "user_name",       CT_TYPE_VARCHAR, CT_FALSE,    CT_MAX_NAME_LEN  },
    { 2,  "table_name",      CT_TYPE_VARCHAR, CT_FALSE,    CT_MAX_NAME_LEN  },
    { 3,  "index_name",      CT_TYPE_VARCHAR, CT_TRUE,     CT_MAX_NAME_LEN  },
};

static dbe_func_param_t g_diag_partab_lobsize[] = {
    // id, name,                datatype,       nullable      parameter len
    { 0,  "size_type",       CT_TYPE_INTEGER, CT_FALSE,    CT_INVALID_INT32 },
    { 1,  "user_name",       CT_TYPE_VARCHAR, CT_FALSE,    CT_MAX_NAME_LEN  },
    { 2,  "table_name",      CT_TYPE_VARCHAR, CT_FALSE,    CT_MAX_NAME_LEN  },
    { 3,  "column_id",       CT_TYPE_INTEGER, CT_TRUE,     CT_INVALID_ID32  },
};

static dbe_func_param_t g_diag_table_partsize[] = {
    // id, name,                datatype,       nullable      parameter len
    { 0,  "size_type",       CT_TYPE_INTEGER, CT_FALSE,    CT_INVALID_INT32},
    { 1,  "user_name",       CT_TYPE_VARCHAR, CT_FALSE,    CT_MAX_NAME_LEN },
    { 2,  "table_name",      CT_TYPE_VARCHAR, CT_FALSE,    CT_MAX_NAME_LEN },
    { 3,  "part_name",       CT_TYPE_VARCHAR, CT_FALSE,    CT_MAX_NAME_LEN },
};

static dbe_func_param_t g_diag_table_size[] = {
    // id, name,                datatype,       nullable      parameter len
    { 0,  "size_type",       CT_TYPE_INTEGER, CT_FALSE,    CT_INVALID_INT32},
    { 1,  "user_name",       CT_TYPE_VARCHAR, CT_FALSE,    CT_MAX_NAME_LEN },
    { 2,  "table_name",      CT_TYPE_VARCHAR, CT_FALSE,    CT_MAX_NAME_LEN },
};

static inline uint32 sql_get_dbe_func_min_args(dbe_func_param_t *dbe_params, uint32 param_count)
{
    uint32 res = 0;
    for (uint32 i = 0; i < param_count; i++) {
        if (!dbe_params[i].nullable) {
            res++;
        }
    }
    return res;
}

#define DBE_FUNC_PARAM_MAX(g_func_tab_params) ((sizeof(g_func_tab_params)) / (sizeof(dbe_func_param_t)))
#define DBE_FUNC_PARAM_MIN(g_func_tab_params) \
    (sql_get_dbe_func_min_args(g_func_tab_params, DBE_FUNC_PARAM_MAX(g_func_tab_params)))

status_t sql_func_get_table_name(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    expr_tree_t *arg1 = NULL;
    expr_tree_t *arg2 = NULL;
    variant_t var1, var2;

    CM_POINTER3(stmt, func, res);

    arg1 = func->argument;
    CM_POINTER(arg1);
    if (sql_exec_expr(stmt, arg1, &var1) != CT_SUCCESS) {
        return CT_ERROR;
    }

    SQL_CHECK_COLUMN_VAR(&var1, &var1);

    if (var1.is_null) {
        CT_SRC_THROW_ERROR(arg1->loc, ERR_INVALID_FUNC_PARAMS, "integer argument expected");
        return CT_ERROR;
    } else {
        if (var_as_integer(&var1) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    arg2 = arg1->next;
    CM_POINTER(arg2);
    if (sql_exec_expr(stmt, arg2, &var2) != CT_SUCCESS) {
        return CT_ERROR;
    }

    SQL_CHECK_COLUMN_VAR(&var2, &var2);

    if (var2.is_null) {
        CT_SRC_THROW_ERROR(arg2->loc, ERR_INVALID_FUNC_PARAMS, "integer argument expected");
        return CT_ERROR;
    } else {
        if (var_as_integer(&var2) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (sql_push(stmt, CT_NAME_BUFFER_SIZE * 2, (void **)&res->v_text.str) != CT_SUCCESS) {
        CTSQL_POP(stmt);
        return CT_ERROR;
    }

    res->v_text.len = CT_NAME_BUFFER_SIZE * 2;
    CT_RETURN_IFERR(knl_get_table_name(stmt->session, var1.v_int, var2.v_int, &res->v_text));
    res->is_null = CT_FALSE;
    res->type = CT_TYPE_STRING;
    return CT_SUCCESS;
}

status_t sql_verify_get_table_name(sql_verifier_t *verifier, expr_node_t *func)
{
    ct_type_t arg_type;
    CM_POINTER2(verifier, func);

    CT_RETURN_IFERR(sql_verify_func_node(verifier, func, 2, 2, CT_INVALID_ID32));

    arg_type = sql_get_func_arg1_datatype(func);
    if (!sql_match_numeric_type(arg_type)) {
        CT_SRC_THROW_ERROR(func->argument->loc, ERR_INVALID_FUNC_PARAMS, "integer argument expected");
        return CT_ERROR;
    }

    arg_type = sql_get_func_arg2_datatype(func);
    if (!sql_match_numeric_type(arg_type)) {
        CT_SRC_THROW_ERROR(func->argument->loc, ERR_INVALID_FUNC_PARAMS, "integer argument expected");
        return CT_ERROR;
    }

    func->datatype = CT_TYPE_STRING;
    func->size = CT_NAME_BUFFER_SIZE * 2; // for scheme.name
    return CT_SUCCESS;
}

status_t sql_verify_ind_pos(sql_verifier_t *verf, expr_node_t *func)
{
    ct_type_t arg_type1, arg_type2;

    CM_POINTER2(verf, func);

    CT_RETURN_IFERR(sql_verify_func_node(verf, func, 2, 2, CT_INVALID_ID32));

    arg_type1 = sql_get_func_arg1_datatype(func);
    if (!sql_match_string_type(arg_type1)) {
        CT_SRC_THROW_ERROR(func->argument->loc, ERR_INVALID_FUNC_PARAMS, "string argument expected");
        return CT_ERROR;
    }

    arg_type2 = sql_get_func_arg2_datatype(func);
    if (!sql_match_string_type(arg_type2)) {
        CT_SRC_THROW_ERROR(func->argument->loc, ERR_INVALID_FUNC_PARAMS, "string argument expected");
        return CT_ERROR;
    }

    func->datatype = CT_TYPE_INTEGER;
    func->size = CT_INTEGER_SIZE;
    return CT_SUCCESS;
}

status_t sql_func_ind_pos(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    uint32 pos = 0;
    text_t splitchar = { ",", 1 };
    expr_tree_t *arg1 = func->argument;
    expr_tree_t *arg2 = arg1->next;
    variant_t var1, var2;

    CM_POINTER3(stmt, func, res);

    SQL_EXEC_FUNC_ARG_EX(arg1, &var1, res);
    sql_keep_stack_variant(stmt, &var1);
    if (sql_var_as_string(stmt, &var1) != CT_SUCCESS) {
        cm_set_error_loc(arg1->loc);
        return CT_ERROR;
    }

    if (var1.v_text.len == 0) {
        SQL_SET_NULL_VAR(res);
        return CT_SUCCESS;
    }

    SQL_EXEC_FUNC_ARG_EX(arg2, &var2, res);
    sql_keep_stack_variant(stmt, &var2);
    if (sql_var_as_string(stmt, &var2) != CT_SUCCESS) {
        cm_set_error_loc(arg2->loc);
        return CT_ERROR;
    }

    if (var2.v_text.len == 0) {
        SQL_SET_NULL_VAR(res);
        return CT_SUCCESS;
    }

    if (GET_DATABASE_CHARSET->num_instr(&var1.v_text, &var2.v_text, &splitchar, &pos) != CT_SUCCESS) {
        cm_reset_error();
        CT_SRC_THROW_ERROR(func->argument->loc, ERR_INVALID_FUNC_PARAMS, "number argument expected");
        return CT_ERROR;
    }

    res->v_int = (int)pos;
    res->type = CT_TYPE_INTEGER;
    res->is_null = CT_FALSE;
    return CT_SUCCESS;
}

status_t sql_func_tabsize_argexpr(sql_stmt_t *stmt, expr_node_t *func, sql_func_part_arg_t *args)
{
    expr_tree_t *arg1 = NULL;
    expr_tree_t *arg2 = NULL;
    expr_tree_t *arg3 = NULL;
    expr_tree_t *arg4 = NULL;

    args->is_pending = CT_TRUE;
    arg1 = func->argument;
    SQL_EXEC_FUNC_ARG(arg1, &args->arg1, &args->arg1, stmt);
    sql_keep_stack_variant(stmt, &args->arg1);

    arg2 = arg1->next;
    SQL_EXEC_FUNC_ARG(arg2, &args->arg2, &args->arg2, stmt);
    sql_keep_stack_variant(stmt, &args->arg2);

    arg3 = arg2->next;
    SQL_EXEC_FUNC_ARG(arg3, &args->arg3, &args->arg3, stmt);
    sql_keep_stack_variant(stmt, &args->arg3);

    arg4 = arg3->next;
    if (arg4 == NULL) {
        args->arg4.is_null = CT_TRUE;
    } else {
        SQL_EXEC_FUNC_ARG(arg4, &args->arg4, &args->arg4, stmt);
        sql_keep_stack_variant(stmt, &args->arg4);
    }

    if (args->arg1.is_null || args->arg2.is_null || args->arg3.is_null) {
        CT_THROW_ERROR(ERR_FUNC_NULL_ARGUMENT);
        return CT_ERROR;
    }

    if (!CT_IS_INTEGER_TYPE(args->arg1.type)) {
        CT_RETURN_IFERR(var_as_decimal(&args->arg1));
        if (!cm_dec_is_integer(&args->arg1.v_dec)) {
            CT_THROW_ERROR(ERR_FUNC_ARGUMENT_WRONG_TYPE, 1, "integer");
            return CT_ERROR;
        }
    }

    CT_RETURN_IFERR(var_as_integer(&args->arg1));
    if (args->arg1.v_int < 0 || args->arg1.v_int > 2) {
        CT_SRC_THROW_ERROR(func->loc, ERR_FUNC_ARGUMENT_OUT_OF_RANGE);
        return CT_ERROR;
    }

    if (!CT_IS_STRING_TYPE(args->arg2.type)) {
        CT_THROW_ERROR(ERR_FUNC_ARGUMENT_WRONG_TYPE, 2, "string");
        return CT_ERROR;
    }

    if (!CT_IS_STRING_TYPE(args->arg3.type)) {
        CT_THROW_ERROR(ERR_FUNC_ARGUMENT_WRONG_TYPE, 3, "string");
        return CT_ERROR;
    }

    args->is_pending = CT_FALSE;
    return CT_SUCCESS;
}

status_t sql_func_partitioned_lobsize(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    knl_dictionary_t dc;
    sql_func_part_arg_t args;
    int32 col_id = -1;
    text_t user, table;
    char buf[CT_NAME_BUFFER_SIZE];

    if (sql_func_tabsize_argexpr(stmt, func, &args) != CT_SUCCESS) {
        cm_set_error_loc(func->loc);
        return CT_ERROR;
    }

    if (args.is_pending) {
        result->type = CT_TYPE_COLUMN;
        result->is_null = CT_FALSE;
        return CT_SUCCESS;
    }

    user = args.arg2.v_text;
    table = args.arg3.v_text;
    cm_text_upper(&user);
    if (sql_user_text_prefix_tenant(stmt->session, &user, buf, CT_NAME_BUFFER_SIZE) != CT_SUCCESS) {
        cm_set_error_loc(func->loc);
        return CT_ERROR;
    }
    process_name_case_sensitive(&table);

    if (!args.arg4.is_null) {
        if (!CT_IS_INTEGER_TYPE(args.arg4.type)) {
            CT_SRC_THROW_ERROR(func->loc, ERR_FUNC_ARGUMENT_WRONG_TYPE, 4, "integer");
            return CT_ERROR;
        }
        col_id = args.arg4.v_int;
    }

    if (knl_open_dc(stmt->session, &user, &table, &dc) != CT_SUCCESS) {
        cm_set_error_loc(func->loc);
        return CT_ERROR;
    }

    if (knl_get_partitioned_lobsize((knl_handle_t)KNL_SESSION(stmt), &dc, args.arg1.v_int, col_id, &result->v_bigint) !=
        CT_SUCCESS) {
        knl_close_dc(&dc);
        cm_set_error_loc(func->loc);
        return CT_ERROR;
    }

    result->type = CT_TYPE_BIGINT;
    result->is_null = CT_FALSE;
    knl_close_dc(&dc);
    return CT_SUCCESS;
}

status_t sql_func_partitioned_tabsize(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    knl_dictionary_t dc;
    sql_func_part_arg_t args;
    text_t user, table;
    char buf[CT_NAME_BUFFER_SIZE];

    if (sql_func_tabsize_argexpr(stmt, func, &args) != CT_SUCCESS) {
        cm_set_error_loc(func->loc);
        return CT_ERROR;
    }

    if (args.is_pending) {
        result->type = CT_TYPE_COLUMN;
        result->is_null = CT_FALSE;
        return CT_SUCCESS;
    }

    user = args.arg2.v_text;
    table = args.arg3.v_text;
    cm_text_upper(&user);
    if (sql_user_text_prefix_tenant(stmt->session, &user, buf, CT_NAME_BUFFER_SIZE) != CT_SUCCESS) {
        cm_set_error_loc(func->loc);
        return CT_ERROR;
    }
    process_name_case_sensitive(&table);

    if (knl_open_dc(stmt->session, &user, &table, &dc) != CT_SUCCESS) {
        cm_set_error_loc(func->loc);
        return CT_ERROR;
    }

    if (knl_get_partitioned_tabsize((knl_handle_t)KNL_SESSION(stmt), &dc, args.arg1.v_int, &result->v_bigint) !=
        CT_SUCCESS) {
        knl_close_dc(&dc);
        cm_set_error_loc(func->loc);
        return CT_ERROR;
    }

    result->type = CT_TYPE_BIGINT;
    result->is_null = CT_FALSE;
    knl_close_dc(&dc);
    return CT_SUCCESS;
}

status_t sql_func_table_partsize(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    knl_dictionary_t dc;
    sql_func_part_arg_t args;
    text_t user, table, part;
    char buf[CT_NAME_BUFFER_SIZE];

    if (sql_func_tabsize_argexpr(stmt, func, &args) != CT_SUCCESS) {
        cm_set_error_loc(func->loc);
        return CT_ERROR;
    }

    if (args.is_pending) {
        result->type = CT_TYPE_COLUMN;
        result->is_null = CT_FALSE;
        return CT_SUCCESS;
    }

    user = args.arg2.v_text;
    table = args.arg3.v_text;
    part = args.arg4.v_text;
    cm_text_upper(&user);

    if (sql_user_text_prefix_tenant(stmt->session, &user, buf, CT_NAME_BUFFER_SIZE) != CT_SUCCESS) {
        cm_set_error_loc(func->loc);
        return CT_ERROR;
    }

    process_name_case_sensitive(&table);
    if (args.arg4.is_null || args.arg4.type < CT_TYPE_CHAR || args.arg4.type > CT_TYPE_STRING ||
        args.arg4.v_text.len == 0) {
        CT_SRC_THROW_ERROR(func->loc, ERR_FUNC_ARGUMENT_WRONG_TYPE, 4, "string");
        return CT_ERROR;
    }
    part = args.arg4.v_text;
    process_name_case_sensitive(&part);
    if (knl_open_dc(stmt->session, &user, &table, &dc) != CT_SUCCESS) {
        cm_set_error_loc(func->loc);
        return CT_ERROR;
    }

    if (knl_get_table_partsize((knl_handle_t)KNL_SESSION(stmt), &dc, args.arg1.v_int, &part, &result->v_bigint) !=
        CT_SUCCESS) {
        knl_close_dc(&dc);
        cm_set_error_loc(func->loc);
        return CT_ERROR;
    }

    result->type = CT_TYPE_BIGINT;
    result->is_null = CT_FALSE;
    knl_close_dc(&dc);
    return CT_SUCCESS;
}


status_t sql_func_table_size(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    knl_dictionary_t dc;
    sql_func_part_arg_t args;
    text_t user, table;
    char buf[CT_NAME_BUFFER_SIZE];

    if (sql_func_tabsize_argexpr(stmt, func, &args) != CT_SUCCESS) {
        cm_set_error_loc(func->loc);
        return CT_ERROR;
    }

    if (args.is_pending) {
        result->type = CT_TYPE_COLUMN;
        result->is_null = CT_FALSE;
        return CT_SUCCESS;
    }

    user = args.arg2.v_text;
    table = args.arg3.v_text;
    cm_text_upper(&user);

    if (sql_user_text_prefix_tenant(stmt->session, &user, buf, CT_NAME_BUFFER_SIZE) != CT_SUCCESS) {
        cm_set_error_loc(func->loc);
        return CT_ERROR;
    }
    process_name_case_sensitive(&table);

    if (knl_open_dc(stmt->session, &user, &table, &dc) != CT_SUCCESS) {
        cm_set_error_loc(func->loc);
        return CT_ERROR;
    }

    if (knl_get_table_size((knl_handle_t)KNL_SESSION(stmt), &dc, args.arg1.v_int, &result->v_bigint) != CT_SUCCESS) {
        knl_close_dc(&dc);
        cm_set_error_loc(func->loc);
        return CT_ERROR;
    }

    result->type = CT_TYPE_BIGINT;
    result->is_null = CT_FALSE;
    knl_close_dc(&dc);
    return CT_SUCCESS;
}

status_t sql_func_partitioned_indsize(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    knl_dictionary_t dc;
    sql_func_part_arg_t args;
    text_t user, table;
    text_t *index_name = NULL;
    char buf[CT_NAME_BUFFER_SIZE];

    if (sql_func_tabsize_argexpr(stmt, func, &args) != CT_SUCCESS) {
        cm_set_error_loc(func->loc);
        return CT_ERROR;
    }

    if (args.is_pending) {
        result->type = CT_TYPE_COLUMN;
        result->is_null = CT_FALSE;
        return CT_SUCCESS;
    }

    user = args.arg2.v_text;
    table = args.arg3.v_text;
    cm_text_upper(&user);
    CT_RETURN_IFERR(sql_user_text_prefix_tenant(stmt->session, &user, buf, CT_NAME_BUFFER_SIZE));
    process_name_case_sensitive(&table);

    if (!args.arg4.is_null) {
        if ((args.arg4.type < CT_TYPE_CHAR) || (args.arg4.type > CT_TYPE_STRING)) {
            CT_SRC_THROW_ERROR(func->loc, ERR_FUNC_ARGUMENT_WRONG_TYPE, 4, "string");
            return CT_ERROR;
        }

        index_name = &args.arg4.v_text;
        process_name_case_sensitive(index_name);
    }

    if (knl_open_dc(stmt->session, &user, &table, &dc) != CT_SUCCESS) {
        cm_set_error_loc(func->loc);
        return CT_ERROR;
    }

    if (knl_get_partitioned_indsize((knl_handle_t)KNL_SESSION(stmt), &dc, args.arg1.v_int, index_name,
        &result->v_bigint) != CT_SUCCESS) {
        knl_close_dc(&dc);
        cm_set_error_loc(func->loc);
        return CT_ERROR;
    }

    result->type = CT_TYPE_BIGINT;
    result->is_null = CT_FALSE;
    knl_close_dc(&dc);
    return CT_SUCCESS;
}

status_t sql_func_table_indsize(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    knl_dictionary_t dc;
    sql_func_part_arg_t args;
    text_t user, table;
    text_t *index_name = NULL;
    char buf[CT_NAME_BUFFER_SIZE];

    if (sql_func_tabsize_argexpr(stmt, func, &args) != CT_SUCCESS) {
        cm_set_error_loc(func->loc);
        return CT_ERROR;
    }

    if (args.is_pending) {
        result->type = CT_TYPE_COLUMN;
        result->is_null = CT_FALSE;
        return CT_SUCCESS;
    }

    user = args.arg2.v_text;
    table = args.arg3.v_text;
    cm_text_upper(&user);
    CT_RETURN_IFERR(sql_user_text_prefix_tenant(stmt->session, &user, buf, CT_NAME_BUFFER_SIZE));
    process_name_case_sensitive(&table);

    if (!args.arg4.is_null) {
        if ((args.arg4.type < CT_TYPE_CHAR) || (args.arg4.type > CT_TYPE_STRING)) {
            CT_SRC_THROW_ERROR(func->loc, ERR_FUNC_ARGUMENT_WRONG_TYPE, 4, "string");
            return CT_ERROR;
        }

        index_name = &args.arg4.v_text;
        process_name_case_sensitive(index_name);
    }

    if (knl_open_dc(stmt->session, &user, &table, &dc) != CT_SUCCESS) {
        cm_set_error_loc(func->loc);
        return CT_ERROR;
    }

    if (knl_get_table_idx_size((knl_handle_t)KNL_SESSION(stmt), &dc, args.arg1.v_int, index_name, &result->v_bigint) !=
        CT_SUCCESS) {
        knl_close_dc(&dc);
        cm_set_error_loc(func->loc);
        return CT_ERROR;
    }

    result->type = CT_TYPE_BIGINT;
    result->is_null = CT_FALSE;
    knl_close_dc(&dc);
    return CT_SUCCESS;
}

status_t sql_verify_partitioned_tabsize(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);
    if (sql_verify_func_node(verf, func, DBE_FUNC_PARAM_MIN(g_diag_partab_tabsize),
        DBE_FUNC_PARAM_MAX(g_diag_partab_tabsize), CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    func->datatype = CT_TYPE_BIGINT;
    func->size = CT_BIGINT_SIZE;

    return sql_verify_dbe_func(verf, func, g_diag_partab_tabsize,
        sizeof(g_diag_partab_tabsize) / sizeof(dbe_func_param_t));
}

status_t sql_verify_partitioned_lobsize(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);
    if (sql_verify_func_node(verf, func, DBE_FUNC_PARAM_MIN(g_diag_partab_lobsize),
        DBE_FUNC_PARAM_MAX(g_diag_partab_lobsize), CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    func->datatype = CT_TYPE_BIGINT;
    func->size = CT_BIGINT_SIZE;

    return sql_verify_dbe_func(verf, func, g_diag_partab_lobsize,
        sizeof(g_diag_partab_lobsize) / sizeof(dbe_func_param_t));
}

status_t sql_verify_partitioned_indsize(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);
    if (sql_verify_func_node(verf, func, DBE_FUNC_PARAM_MIN(g_diag_partab_indsize),
        DBE_FUNC_PARAM_MAX(g_diag_partab_indsize), CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    func->datatype = CT_TYPE_BIGINT;
    func->size = CT_BIGINT_SIZE;

    return sql_verify_dbe_func(verf, func, g_diag_partab_indsize,
        sizeof(g_diag_partab_indsize) / sizeof(dbe_func_param_t));
}

status_t sql_verify_table_indsize(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);
    if (sql_verify_func_node(verf, func, DBE_FUNC_PARAM_MIN(g_diag_tab_indsize), DBE_FUNC_PARAM_MAX(g_diag_tab_indsize),
        CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    func->datatype = CT_TYPE_BIGINT;
    func->size = CT_BIGINT_SIZE;

    return sql_verify_dbe_func(verf, func, g_diag_tab_indsize, sizeof(g_diag_tab_indsize) / sizeof(dbe_func_param_t));
}

status_t sql_verify_table_partsize(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);
    if (sql_verify_func_node(verf, func, DBE_FUNC_PARAM_MIN(g_diag_table_partsize),
        DBE_FUNC_PARAM_MAX(g_diag_table_partsize), CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    func->datatype = CT_TYPE_BIGINT;
    func->size = CT_BIGINT_SIZE;

    return sql_verify_dbe_func(verf, func, g_diag_table_partsize,
        sizeof(g_diag_table_partsize) / sizeof(dbe_func_param_t));
}
status_t sql_verify_table_size(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);
    if (sql_verify_func_node(verf, func, DBE_FUNC_PARAM_MIN(g_diag_table_size), DBE_FUNC_PARAM_MAX(g_diag_table_size),
        CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    func->datatype = CT_TYPE_BIGINT;
    func->size = CT_BIGINT_SIZE;

    return sql_verify_dbe_func(verf, func, g_diag_table_size, sizeof(g_diag_table_size) / sizeof(dbe_func_param_t));
}


status_t sql_has_obj_privs(knl_session_t *se, text_t *check_user, text_t *owner, text_t *obj, object_type_t objtype)
{
    uint32 count = 0;
    obj_privs_id *set = NULL;
    uint32 i;

    knl_get_objprivs_set(objtype, &set, &count);
    if (set == NULL || count == 0) {
        CT_LOG_RUN_ERR("[PRIV] failed to get objprivs set");
        return CT_ERROR;
    }
    for (i = 0; i < count; i++) {
        /* check user has obj privs */
        if (knl_check_obj_priv_by_name(se, check_user, owner, obj, objtype, (uint32)set[i])) {
            return CT_SUCCESS;
        }
    }
    return CT_ERROR;
}
status_t sql_has_table_select_privs(knl_session_t *session, text_t *check_user, text_t *owner, text_t *obj,
    object_type_t objtype, obj_privs_id opid)
{
    uint32 check_user_id;
    text_t role = { DBA_ROLE, 3 };
    text_t sys_user_name = {
        .str = SYS_USER_NAME,
        .len = SYS_USER_NAME_LEN
    };

    if (!dc_get_user_id(session, check_user, &check_user_id)) {
        CT_THROW_ERROR(ERR_INVALID_OPERATION, "invalid check_user");
        return CT_ERROR;
    }
    bool32 has_any_dictionary = knl_check_sys_priv_by_name(session, check_user, SELECT_ANY_DICTIONARY);
    bool32 has_any_priv = knl_check_sys_priv_by_uid(session, check_user_id, SELECT_ANY_TABLE) ?
        CT_TRUE :
        knl_check_sys_priv_by_uid(session, check_user_id, READ_ANY_TABLE);
    bool32 dba_curr_user = knl_grant_role_with_option(session, check_user, &role, CT_FALSE);
    if (!dba_curr_user && (cm_compare_text(check_user, &sys_user_name) != 0) &&
        (cm_compare_text(owner, &sys_user_name) == 0)) {
        if (((g_instance->attr.access_dc_enable == CT_TRUE) && has_any_priv) || (has_any_dictionary == CT_TRUE)) {
            has_any_priv = CT_TRUE;
        } else {
            has_any_priv = CT_FALSE;
        }
    }
    if (!has_any_priv) {
        CT_RETURN_IFERR(sql_check_user_select_priv(session, check_user, owner, obj, objtype, CT_FALSE));
    }
    return CT_SUCCESS;
}
uint32 sql_get_proc_any_priv_id(object_type_t obj_type)
{
    switch (obj_type) {
        case OBJ_TYPE_PROCEDURE:
        case OBJ_TYPE_FUNCTION:
        case OBJ_TYPE_PACKAGE_BODY:
        case OBJ_TYPE_PACKAGE_SPEC:
            return EXECUTE_ANY_PROCEDURE;
        case OBJ_TYPE_LIBRARY:
            return EXECUTE_ANY_LIBRARY;
        case OBJ_TYPE_TYPE_BODY:
        case OBJ_TYPE_TYPE_SPEC:
            return EXECUTE_ANY_TYPE;
        case OBJ_TYPE_TRIGGER:
            return CREATE_ANY_TRIGGER;
        default:
            return CT_SYS_PRIVS_COUNT;
    }
}

status_t sql_has_table_privs(knl_session_t *se, text_t *check_user, text_t *owner, text_t *obj, object_type_t objtype)
{
    uint32 check_user_id, owner_id;
    if (!dc_get_user_id(se, check_user, &check_user_id)) {
        return CT_ERROR;
    }
    if (!dc_get_user_id(se, owner, &owner_id)) {
        return CT_ERROR;
    }
    bool32 has_any_dictionary = knl_check_sys_priv_by_uid(se, check_user_id, SELECT_ANY_DICTIONARY);
    bool32 has_any_priv = knl_check_sys_priv_by_uid(se, check_user_id, SELECT_ANY_TABLE) ?
        CT_TRUE :
        knl_check_sys_priv_by_uid(se, check_user_id, READ_ANY_TABLE);
    // comman user check sys object
    if ((owner_id == 0) && (check_user_id != 0)) {
        if (((g_instance->attr.access_dc_enable == CT_TRUE) && has_any_priv) || (has_any_dictionary == CT_TRUE)) {
            return CT_SUCCESS;
        }
    } else { // comman user check others' object
        if (has_any_priv || knl_check_sys_priv_by_uid(se, check_user_id, INSERT_ANY_TABLE) ||
            knl_check_sys_priv_by_uid(se, check_user_id, UPDATE_ANY_TABLE) ||
            knl_check_sys_priv_by_uid(se, check_user_id, DELETE_ANY_TABLE) ||
            knl_check_sys_priv_by_uid(se, check_user_id, LOCK_ANY_TABLE)) {
            return CT_SUCCESS;
        }
    }
    if (sql_has_obj_privs(se, check_user, owner, obj, objtype) == CT_SUCCESS) {
        return CT_SUCCESS;
    }
    if (check_user_id == owner_id) {
        return CT_SUCCESS;
    }
    return CT_ERROR;
}
status_t sql_has_sequence_privs(knl_session_t *se, text_t *check_user, text_t *owner, text_t *obj,
    object_type_t objtype)
{
    uint32 check_user_id, owner_id;
    if (!dc_get_user_id(se, check_user, &check_user_id)) {
        return CT_ERROR;
    }
    if (!dc_get_user_id(se, owner, &owner_id)) {
        return CT_ERROR;
    }
    if (knl_check_sys_priv_by_uid(se, check_user_id, SELECT_ANY_SEQUENCE) ||
        knl_check_sys_priv_by_uid(se, check_user_id, ALTER_ANY_SEQUENCE)) {
        if ((owner_id != 0) || (check_user_id == 0)) {
            return CT_SUCCESS;
        }
    }
    if (sql_has_obj_privs(se, check_user, owner, obj, objtype) == CT_SUCCESS) {
        return CT_SUCCESS;
    }
    if (check_user_id == owner_id) {
        return CT_SUCCESS;
    }
    return CT_ERROR;
}

status_t sql_has_procedure_privs(knl_session_t *se, text_t *check_user, text_t *owner, text_t *obj,
    object_type_t expected_objtype)
{
    uint32 check_user_id, owner_id;
    uint32 any_priv_id = sql_get_proc_any_priv_id(expected_objtype);
    if (any_priv_id == CT_SYS_PRIVS_COUNT) {
        CT_THROW_ERROR(ERR_INVALID_OPERATION, ", invalid privilage");
        return CT_ERROR;
    }
    if (!dc_get_user_id(se, check_user, &check_user_id)) {
        return CT_ERROR;
    }
    if (!dc_get_user_id(se, owner, &owner_id)) {
        return CT_ERROR;
    }
    if (knl_check_sys_priv_by_uid(se, check_user_id, any_priv_id)) {
        if ((owner_id != 0) || (check_user_id == 0)) {
            return CT_SUCCESS;
        }
    }
    if (sql_has_obj_privs(se, check_user, owner, obj, OBJ_TYPE_PROCEDURE) == CT_SUCCESS) {
        return CT_SUCCESS;
    }
    if (check_user_id == owner_id) {
        return CT_SUCCESS;
    }
    return CT_ERROR;
}
status_t sql_has_library_privs(knl_session_t *se, text_t *check_user, text_t *owner, text_t *obj, object_type_t objtype)
{
    uint32 check_user_id, owner_id;
    if (!dc_get_user_id(se, check_user, &check_user_id)) {
        return CT_ERROR;
    }
    if (!dc_get_user_id(se, owner, &owner_id)) {
        return CT_ERROR;
    }
    if (knl_check_sys_priv_by_uid(se, check_user_id, EXECUTE_ANY_LIBRARY)) {
        if ((owner_id != 0) || (check_user_id == 0)) {
            return CT_SUCCESS;
        }
    }
    if (sql_has_obj_privs(se, check_user, owner, obj, objtype) == CT_SUCCESS) {
        return CT_SUCCESS;
    }
    if (check_user_id == owner_id) {
        return CT_SUCCESS;
    }
    return CT_ERROR;
}

status_t sql_has_directory_privs(knl_session_t *se, text_t *check_user, text_t *owner, text_t *obj,
    object_type_t objtype)
{
    uint32 owner_id, check_user_id;
    if (!dc_get_user_id(se, check_user, &check_user_id)) {
        return CT_ERROR;
    }
    if (!dc_get_user_id(se, owner, &owner_id)) {
        return CT_ERROR;
    }
    if (owner_id != 0) {
        CT_THROW_ERROR_EX(ERR_INVALID_OPERATION, ",owner must be sys");
        return CT_ERROR;
    }
    if (sql_has_obj_privs(se, check_user, owner, obj, objtype) == CT_SUCCESS) {
        return CT_SUCCESS;
    }
    if (check_user_id == owner_id) {
        return CT_SUCCESS;
    }
    return CT_ERROR;
}

obj_type_id g_obj_type_def[] = {
    { { .str = "B", .len = 1 }, OBJ_TYPE_PACKAGE_SPEC },
    { { .str = "DIRECTORY", .len = 9 }, OBJ_TYPE_DIRECTORY },
    { { .str = "F", .len = 1 }, OBJ_TYPE_FUNCTION },
    { { .str = "FUNCTION", .len = 8 }, OBJ_TYPE_FUNCTION },
    { { .str = "LIBRARY", .len = 7 }, OBJ_TYPE_LIBRARY },
    { { .str = "O", .len = 1 }, OBJ_TYPE_TYPE_SPEC },
    { { .str = "P", .len = 1 }, OBJ_TYPE_PROCEDURE },
    { { .str = "PACKAGE", .len = 7 }, OBJ_TYPE_PACKAGE_SPEC },
    { { .str = "PACKAGE BODY", .len = 12 }, OBJ_TYPE_PACKAGE_BODY },
    { { .str = "PACKAGE SPEC", .len = 12 }, OBJ_TYPE_PACKAGE_SPEC },
    { { .str = "PROCEDURE", .len = 9 }, OBJ_TYPE_PROCEDURE },
    { { .str = "S", .len = 1 }, OBJ_TYPE_PACKAGE_SPEC },
    { { .str = "SEQUENCE", .len = 8 }, OBJ_TYPE_SEQUENCE },
    { { .str = "SYNONYM", .len = 7 }, OBJ_TYPE_SYNONYM },
    { { .str = "SYSPACKAGE", .len = 10 }, OBJ_TYPE_SYS_PACKAGE },
    { { .str = "T", .len = 1 }, OBJ_TYPE_TRIGGER },
    { { .str = "TABLE", .len = 5 }, OBJ_TYPE_TABLE },
    { { .str = "TRIGGER", .len = 7 }, OBJ_TYPE_TRIGGER },
    { { .str = "TYPE", .len = 4 }, OBJ_TYPE_TYPE_SPEC },
    { { .str = "TYPE BODY", .len = 9 }, OBJ_TYPE_TYPE_BODY },
    { { .str = "TYPE SPEC", .len = 9 }, OBJ_TYPE_TYPE_SPEC },
    { { .str = "VIEW", .len = 4 }, OBJ_TYPE_VIEW },
    { { .str = "Y", .len = 1 }, OBJ_TYPE_TYPE_SPEC },
};
bool32 sql_parse_object_type(text_t *objtype, object_type_t *expected_objtype)
{
    uint32 begin_pos = 0;
    uint32 end_pos = sizeof(g_obj_type_def) / sizeof(obj_type_id);
    uint32 mid_pos;
    int32 comp;
    while (end_pos >= begin_pos) {
        mid_pos = (begin_pos + end_pos) / 2;
        comp = cm_compare_text_ins(objtype, &g_obj_type_def[mid_pos].obj_type);
        if (comp == 0) {
            *expected_objtype = g_obj_type_def[mid_pos].type_id;
            return CT_TRUE;
        } else if (comp < 0) {
            end_pos = mid_pos - 1;
        } else {
            begin_pos = mid_pos + 1;
        }
    }
    *expected_objtype = OBJ_TYPE_INVALID;
    return CT_FALSE;
}

status_t sql_func_has_obj_privs(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    expr_tree_t *arg = NULL;
    variant_t check_user_var, owner_var, obj_var, objtype_var;
    text_t *check_user_text = NULL;
    text_t *owner_text = NULL;
    text_t *obj_text = NULL;
    text_t *obj_type_text = NULL;
    status_t ret;
    uint32 owner_id;
    object_type_t obj_type;
    knl_session_t *session = &stmt->session->knl_session;
    result->is_null = CT_FALSE;
    result->type = CT_TYPE_BOOLEAN;
    result->v_bool = CT_FALSE;

    arg = func->argument;
    CT_RETURN_IFERR(sql_exec_expr_as_string(stmt, arg, &check_user_var, &check_user_text));
    SQL_CHECK_COLUMN_VAR(&check_user_var, result);

    arg = arg->next;
    CT_RETURN_IFERR(sql_exec_expr_as_string(stmt, arg, &owner_var, &owner_text));
    SQL_CHECK_COLUMN_VAR(&owner_var, result);

    arg = arg->next;
    CT_RETURN_IFERR(sql_exec_expr_as_string(stmt, arg, &obj_var, &obj_text));
    SQL_CHECK_COLUMN_VAR(&obj_var, result);

    arg = arg->next;
    CT_RETURN_IFERR(sql_exec_expr_as_string(stmt, arg, &objtype_var, &obj_type_text));
    SQL_CHECK_COLUMN_VAR(&objtype_var, result);

    if (CM_IS_EMPTY(check_user_text) || CM_IS_EMPTY(owner_text) || CM_IS_EMPTY(obj_text) || CM_IS_EMPTY(obj_type_text)) {
        result->is_null = CT_TRUE;
        result->v_text.len = 0;
        CT_THROW_ERROR(ERR_INVALID_OPERATION, ", arg of function has_obj_privs must be effective word");
        return CT_ERROR;
    }
    cm_text_upper(check_user_text);
    cm_text_upper(owner_text);
    process_name_case_sensitive(obj_text);
    cm_text_upper(obj_type_text);

    if (!sql_parse_object_type(obj_type_text, &obj_type)) {
        CT_THROW_ERROR(ERR_INVALID_OPERATION, ", please check object type");
        return CT_ERROR;
    }
    // For compatibility, you can control the view at the beginning of ALL_/DB_
    // through parameters to see the objects of sys
    if (!dc_get_user_id(session, owner_text, &owner_id)) {
        CT_THROW_ERROR(ERR_USER_NOT_EXIST, T2S(owner_text));
        return CT_ERROR;
    }
    if (owner_id == 0 && g_instance->attr.view_access_dc == CT_TRUE) {
        result->v_bool = CT_TRUE;
        return CT_SUCCESS;
    }

    switch (obj_type) {
        case OBJ_TYPE_TABLE:
            ret = sql_has_table_privs(session, check_user_text, owner_text, obj_text, obj_type);
            break;
        case OBJ_TYPE_VIEW:
            ret = sql_has_table_privs(session, check_user_text, owner_text, obj_text, obj_type);
            break;
        case OBJ_TYPE_SEQUENCE:
            ret = sql_has_sequence_privs(session, check_user_text, owner_text, obj_text, obj_type);
            break;

        case OBJ_TYPE_PROCEDURE:
        case OBJ_TYPE_PACKAGE_SPEC:
        case OBJ_TYPE_FUNCTION:
        case OBJ_TYPE_TYPE_SPEC:
        case OBJ_TYPE_TRIGGER:
            ret = sql_has_procedure_privs(session, check_user_text, owner_text, obj_text, obj_type);
            break;

        case OBJ_TYPE_DIRECTORY:
            ret = sql_has_directory_privs(session, check_user_text, owner_text, obj_text, obj_type);
            break;
        case OBJ_TYPE_LIBRARY:
            ret = sql_has_library_privs(session, check_user_text, owner_text, obj_text, obj_type);
            break;
        default:
            ret = CT_ERROR;
            break;
    }
    result->type = CT_TYPE_BOOLEAN;
    result->v_bool = CT_FALSE;
    if (ret == CT_SUCCESS) {
        result->v_bool = CT_TRUE;
    }
    return CT_SUCCESS;
}

status_t sql_verify_has_obj_privs(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);
    if (sql_verify_func_node(verf, func, 4, 4, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }
    func->datatype = CT_TYPE_BOOLEAN;
    func->size = CT_BOOLEAN_SIZE;
    return CT_SUCCESS;
}

enum en_tenant_check_type {
    TENANT_CHECK_ID = 0,
    TENANT_CHECK_NAME,
    TENANT_CHECK_UID
};

status_t sql_func_tenant_check(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t var1, var2;
    text_buf_t buffer;
    bool32 flag = CT_FALSE;
    dc_user_t *user = NULL;

    CM_POINTER3(stmt, func, result);

    if (stmt->session->curr_tenant_id == SYS_TENANTROOT_ID) {
        result->is_null = CT_FALSE;
        result->v_bool = CT_TRUE;
        result->type = CT_TYPE_BOOLEAN;
        return CT_SUCCESS;
    }

    expr_tree_t *arg1 = func->argument;
    CM_POINTER(arg1);
    SQL_EXEC_FUNC_ARG_EX(arg1, &var1, result);
    CT_RETURN_IFERR(var_as_floor_integer(&var1));

    expr_tree_t *arg2 = arg1->next;
    CM_POINTER(arg2);
    SQL_EXEC_FUNC_ARG_EX(arg2, &var2, result);

    switch (var1.v_int) {
        case TENANT_CHECK_ID:
            CT_RETURN_IFERR(var_as_floor_integer(&var2));
            flag = (var2.v_int == stmt->session->curr_tenant_id);
            break;
        case TENANT_CHECK_NAME:
            CT_RETURN_IFERR(var_as_string(SESSION_NLS(stmt), &var2, &buffer));
            flag = cm_text_str_equal_ins(&var2.v_text, stmt->session->curr_tenant);
            break;
        case TENANT_CHECK_UID:
            CT_RETURN_IFERR(var_as_floor_integer(&var2));
            if ((uint32)var2.v_int >= CT_MAX_USERS) {
                CT_THROW_ERROR(ERR_TYPE_OVERFLOW, "the user id");
                return CT_ERROR;
            }
            CT_RETURN_IFERR(dc_open_user_by_id(&stmt->session->knl_session, (uint32)var2.v_int, &user));
            flag = (user->desc.tenant_id == stmt->session->curr_tenant_id);
            break;
        default:
            cm_set_error_loc(arg1->loc);
            return CT_ERROR;
    }

    result->v_bool = flag;
    result->is_null = CT_FALSE;
    result->type = CT_TYPE_BOOLEAN;
    return CT_SUCCESS;
}

status_t sql_verify_tenant_check(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 2, 2, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    // OPTIMIZE_AS_CONST
    if (verf->stmt->session->curr_tenant_id == SYS_TENANTROOT_ID) {
        func->optmz_info.mode = OPTIMIZE_AS_CONST;
    }

    func->datatype = CT_TYPE_BOOLEAN;
    func->size = CT_BOOLEAN_SIZE;
    return CT_SUCCESS;
}

static status_t sql_func_list_cols_core(sql_stmt_t *stmt, expr_node_t *func, variant_t *result, text_t *user,
    text_t *table, text_t *column_list)
{
    knl_dictionary_t dc;
    uint32 column_count, id;
    text_t column_text;
    status_t status = CT_SUCCESS;

    if (knl_open_dc(stmt->session, user, table, &dc) != CT_SUCCESS) {
        cm_set_error_loc(func->loc);
        return CT_ERROR;
    }

    column_count = knl_get_column_count(dc.handle);
    while (cm_fetch_text(column_list, ',', '\0', &column_text)) {
        if (!cm_is_short(&column_text)) {
            CT_SRC_THROW_ERROR(func->loc, ERR_INVALID_NUMBER, ":invalid column list");
            status = CT_ERROR;
            break;
        }

        if (cm_text2uint32(&column_text, &id) != CT_SUCCESS) {
            status = CT_ERROR;
            break;
        }

        if (id >= column_count && id < DC_VIRTUAL_COL_START) {
            CT_SRC_THROW_ERROR(func->loc, ERR_OUT_OF_INDEX, "column id", column_count);
            status = CT_ERROR;
            break;
        }

        if (result->v_text.len > 0) {
            if (cm_concat_string(&result->v_text, CT_NAME_BUFFER_SIZE * CT_MAX_INDEX_COLUMNS, ", ") != CT_SUCCESS) {
                status = CT_ERROR;
                break;
            }
        }

        knl_column_t *column = knl_get_column(dc.handle, id);
        if (column == NULL) {
            CT_SRC_THROW_ERROR_EX(func->loc, ERR_INVALID_NUMBER, "column id %u out of index, limits is %u", id,
                column_count);
            status = CT_ERROR;
            break;
        }

        if (id < DC_VIRTUAL_COL_START) {
            if (cm_concat_string(&result->v_text, CT_NAME_BUFFER_SIZE * CT_MAX_INDEX_COLUMNS, column->name) !=
                CT_SUCCESS) {
                status = CT_ERROR;
                break;
            }
        } else {
            cm_concat_text(&result->v_text, CT_NAME_BUFFER_SIZE * CT_MAX_INDEX_COLUMNS, &column->default_text);
        }
    }

    knl_close_dc(&dc);
    return status;
}

status_t sql_func_list_cols(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t var1, var2, var3;
    expr_tree_t *arg1 = NULL;
    expr_tree_t *arg2 = NULL;
    expr_tree_t *arg3 = NULL;
    status_t status;
    char buf[CT_NAME_BUFFER_SIZE];

    CM_POINTER3(stmt, func, result);

    result->type = CT_TYPE_STRING;
    result->is_null = CT_FALSE;

    arg1 = func->argument;
    arg2 = arg1->next;
    arg3 = arg2->next;

    CTSQL_SAVE_STACK(stmt);

    SQL_EXEC_FUNC_ARG(arg1, &var1, result, stmt);
    if (var1.is_null || !CT_IS_STRING_TYPE(var1.type)) {
        CTSQL_RESTORE_STACK(stmt);
        CT_SRC_THROW_ERROR(arg1->loc, ERR_KEY_EXPECTED, "user name");
        return CT_ERROR;
    }
    sql_keep_stack_variant(stmt, &var1);
    cm_text_upper(&var1.v_text);
    if (sql_user_text_prefix_tenant(stmt->session, &var1.v_text, buf, CT_NAME_BUFFER_SIZE) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }

    SQL_EXEC_FUNC_ARG(arg2, &var2, result, stmt);
    if (var2.is_null || !CT_IS_STRING_TYPE(var2.type)) {
        CTSQL_RESTORE_STACK(stmt);
        CT_SRC_THROW_ERROR(arg2->loc, ERR_KEY_EXPECTED, "table name");
        return CT_ERROR;
    }
    sql_keep_stack_variant(stmt, &var2);
    process_name_case_sensitive(&var2.v_text);

    SQL_EXEC_FUNC_ARG(arg3, &var3, result, stmt);
    if (var3.is_null || !CT_IS_STRING_TYPE(var3.type)) {
        CTSQL_RESTORE_STACK(stmt);
        CT_SRC_THROW_ERROR(arg3->loc, ERR_KEY_EXPECTED, "column list string");
        return CT_ERROR;
    }
    sql_keep_stack_variant(stmt, &var3);

    if (sql_push(stmt, CT_NAME_BUFFER_SIZE * CT_MAX_INDEX_COLUMNS, (void **)&result->v_text.str) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }
    result->v_text.len = 0;

    status = sql_func_list_cols_core(stmt, func, result, &var1.v_text, &var2.v_text, &var3.v_text);

    CTSQL_RESTORE_STACK(stmt);
    return status;
}

status_t sql_verify_list_cols(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 3, 3, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    func->datatype = CT_TYPE_STRING;
    func->size = CT_NAME_BUFFER_SIZE * CT_MAX_INDEX_COLUMNS;
    return CT_SUCCESS;
}

status_t sql_func_segment_size(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    variant_t var1, var2;
    expr_tree_t *arg1 = NULL;
    expr_tree_t *arg2 = NULL;

    CM_POINTER3(stmt, func, res);

    arg1 = func->argument;
    CM_POINTER(arg1);
    SQL_EXEC_FUNC_ARG_EX(arg1, &var1, res);
    if (var_as_integer(&var1) != CT_SUCCESS) {
        cm_set_error_loc(func->loc);
        return CT_ERROR;
    }

    if (var1.v_int < 0 || var1.v_int > 2) {
        CT_THROW_ERROR(ERR_FUNC_ARGUMENT_OUT_OF_RANGE);
        return CT_ERROR;
    }

    arg2 = arg1->next;
    CM_POINTER(arg2);
    SQL_EXEC_FUNC_ARG_EX(arg2, &var2, res);

    CT_RETURN_IFERR(sql_exec_expr(stmt, arg2, &var2));

    if (var_as_bigint(&var2) != CT_SUCCESS) {
        cm_set_error_loc(func->loc);
        return CT_ERROR;
    }

    res->type = CT_TYPE_BIGINT;
    res->is_null = CT_FALSE;

    uint32 pages, page_size, extents;
    page_id_t entry;

    entry = *(page_id_t *)&var2.v_bigint;
    if (IS_INVALID_PAGID(entry)) {
        res->v_bigint = 0;
        return CT_SUCCESS;
    }

    if (knl_get_segment_size(stmt->session, entry, &extents, &pages, &page_size) != CT_SUCCESS) {
        cm_reset_error();
        res->v_bigint = 0;
        return CT_SUCCESS;
    }

    (void)knl_calc_seg_size((seg_size_type_t)var1.v_int, pages, page_size, extents, &res->v_bigint);
    return CT_SUCCESS;
}

status_t sql_verify_segment_size(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 2, 2, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    func->datatype = CT_TYPE_BIGINT;
    func->size = CT_BIGINT_SIZE;

    return CT_SUCCESS;
}

status_t sql_func_lob_segment_free_size(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    variant_t var1, var2;

    expr_tree_t *arg1 = NULL;
    expr_tree_t *arg2 = NULL;

    CM_POINTER3(stmt, func, res);

    arg1 = func->argument;
    CM_POINTER(arg1);
    SQL_EXEC_FUNC_ARG_EX(arg1, &var1, res);
    if (var_as_integer(&var1) != CT_SUCCESS) {
        cm_set_error_loc(func->loc);
        return CT_ERROR;
    }

    if (var1.v_int < 0 || var1.v_int > 2) {
        CT_THROW_ERROR(ERR_FUNC_ARGUMENT_OUT_OF_RANGE);
        return CT_ERROR;
    }

    arg2 = arg1->next;
    CM_POINTER(arg2);
    SQL_EXEC_FUNC_ARG_EX(arg2, &var2, res);

    CT_RETURN_IFERR(sql_exec_expr(stmt, arg2, &var2));

    if (var_as_bigint(&var2) != CT_SUCCESS) {
        cm_set_error_loc(func->loc);
        return CT_ERROR;
    }

    res->type = CT_TYPE_BIGINT;
    res->is_null = CT_FALSE;

    uint32 pages, page_size, extents;
    page_id_t entry;

    entry = *(page_id_t *)&var2.v_bigint;
    if (IS_INVALID_PAGID(entry)) {
        res->v_bigint = 0;
        return CT_SUCCESS;
    }

    if (knl_get_lob_recycle_pages(stmt->session, entry, &extents, &pages, &page_size) != CT_SUCCESS) {
        cm_reset_error();
        res->v_bigint = 0;
        return CT_SUCCESS;
    }

    (void)knl_calc_seg_size((seg_size_type_t)var1.v_int, pages, page_size, extents, &res->v_bigint);
    return CT_SUCCESS;
}

status_t sql_verify_lob_segment_free_size(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 2, 2, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    func->datatype = CT_TYPE_BIGINT;
    func->size = CT_BIGINT_SIZE;

    return CT_SUCCESS;
}

#define CT_MAX_SLEEP_SECOND 999999999999

status_t sql_func_sleep(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    variant_t value;
    date_t start_time, sleep_time;

    CM_POINTER3(stmt, func, res);

    expr_node_t *arg_node = func->argument->root;
    CM_POINTER(arg_node);

    if (sql_exec_expr_node(stmt, arg_node, &value) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_CALC_EXPRESSION, "expression node");
        return CT_ERROR;
    }
    SQL_CHECK_COLUMN_VAR(&value, res);
    if (value.is_null) {
        SQL_SET_NULL_VAR(res);
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(var_as_real(&value));
    if (value.v_real <= 0) {
        CT_THROW_ERROR(ERR_INVALID_FUNC_PARAMS, "parameter can not be negative.");
        return CT_ERROR;
    }

    // in order to avoid the arrary overflow and avoid the PL stay sleep for a long time,
    // limit the value not greater than CT_MAX_SLEEP_SECOND
    if (value.v_real > CT_MAX_SLEEP_SECOND) {
        CT_THROW_ERROR(ERR_INVALID_FUNC_PARAMS, "the parameter can not exceed " CT_STR(CT_MAX_SLEEP_SECOND));
        return CT_ERROR;
    }

    start_time = cm_now();
    sleep_time = (date_t)(value.v_real * (double)MICROSECS_PER_SECOND);
    while (((cm_now() - start_time)) < sleep_time) {
        SQL_CHECK_SESSION_VALID_FOR_RETURN(stmt);
        cm_sleep(CT_CPU_TIME);
    }

    SQL_SET_NULL_VAR(res);
    return CT_SUCCESS;
}

status_t sql_verify_sleep(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 1, 1, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!sql_match_numeric_type(TREE_DATATYPE(func->argument))) {
        CT_SRC_ERROR_REQUIRE_NUMERIC(func->argument->loc, TREE_DATATYPE(func->argument));
        return CT_ERROR;
    }

    func->datatype = CT_TYPE_VARCHAR;
    func->size = 0;
    return CT_SUCCESS;
}

status_t sql_func_space_size(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    variant_t var1, var2;

    CM_POINTER3(stmt, func, res);

    expr_tree_t *arg1 = func->argument;
    expr_tree_t *arg2 = arg1->next;

    SQL_EXEC_FUNC_ARG(arg1, &var1, res, stmt);
    if (!CT_IS_INTEGER_TYPE(var1.type)) {
        CT_SRC_THROW_ERROR(arg1->loc, ERR_KEY_EXPECTED, "tablespace id");
        return CT_ERROR;
    }
    CT_RETURN_IFERR(sql_exec_expr(stmt, arg2, &var2));

    SQL_CHECK_COLUMN_VAR(&var2, res);

    if (!CT_IS_STRING_TYPE(var2.type)) {
        CT_SRC_THROW_ERROR(arg2->loc, ERR_KEY_EXPECTED, "attribute name");
        return CT_ERROR;
    }

    if (var1.is_null || var2.is_null) {
        CT_THROW_ERROR(ERR_FUNC_NULL_ARGUMENT);
        cm_set_error_loc(func->loc);
        return CT_ERROR;
    }

    sql_keep_stack_variant(stmt, &var2);

    knl_space_info_t spc_info;
    int32 page_size;

    if (knl_get_space_size(stmt->session, var1.v_int, &page_size, &spc_info) != CT_SUCCESS) {
        cm_set_error_loc(func->loc);
        return CT_ERROR;
    }

    if (cm_text_str_equal_ins(&var2.v_text, "PAGE")) {
        res->v_bigint = (int64)page_size;
    } else if (cm_text_str_equal_ins(&var2.v_text, "TOTAL")) {
        res->v_bigint = (int64)spc_info.total;
    } else if (cm_text_str_equal_ins(&var2.v_text, "USED")) {
        res->v_bigint = (int64)spc_info.used;
    } else if (cm_text_str_equal_ins(&var2.v_text, "NORMAL_TOTAL")) {
        res->v_bigint = (int64)spc_info.normal_total;
    } else if (cm_text_str_equal_ins(&var2.v_text, "NORMAL_USED")) {
        res->v_bigint = (int64)spc_info.normal_used;
    } else if (cm_text_str_equal_ins(&var2.v_text, "COMPRESS_TOTAL")) {
        res->v_bigint = (int64)spc_info.compress_total;
    } else if (cm_text_str_equal_ins(&var2.v_text, "COMPRESS_USED")) {
        res->v_bigint = (int64)spc_info.compress_used;
    } else {
        CT_SRC_THROW_ERROR(arg2->loc, ERR_INVALID_ATTR_NAME, T2S(&var2.v_text));
        return CT_ERROR;
    }

    res->type = CT_TYPE_BIGINT;
    res->is_null = CT_FALSE;
    return CT_SUCCESS;
}

status_t sql_verify_space_size(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 2, 2, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    func->datatype = CT_TYPE_BIGINT;
    func->size = CT_BIGINT_SIZE;
    return CT_SUCCESS;
}

static status_t sql_get_type_mapped(sql_stmt_t *stmt, expr_node_t *func, variant_t *result, bool32 is_col,
    type_desc_t *array, uint32 size)
{
    int32 id;
    variant_t var;
    expr_tree_t *arg = NULL;
    type_desc_t *desc = NULL;

    desc = &array[0]; // first item is unknown type
    arg = func->argument;
    SQL_EXEC_FUNC_ARG_EX(arg, &var, result);

    CT_RETURN_IFERR(var_as_integer(&var));

    id = is_col ? var.v_int - CT_TYPE_BASE : var.v_int + 1;

    if (id >= 0 && (uint32)id < size) {
        desc = &array[id];
    }

    result->is_null = CT_FALSE;
    result->v_text = desc->name;
    result->type = CT_TYPE_STRING;
    return CT_SUCCESS;
}

#define TAB_TYPE_SIZE ELEMENT_COUNT(g_table_type_names)

/* **NOTE:** The type must be arranged by id ascending order. */
type_desc_t g_table_type_names[] = {
    { -1, { (char *)"UNKNOWN_TYPE", 12 } },
    { TABLE_TYPE_HEAP, { (char *)"HEAP", 4 } },
    { TABLE_TYPE_IOT, { (char *)"IOT", 3 } },
    { TABLE_TYPE_TRANS_TEMP, { (char *)"TRANS_TEMP", 10 } },
    { TABLE_TYPE_SESSION_TEMP, { (char *)"SESSION_TEMP", 12 } },
    { TABLE_TYPE_NOLOGGING, { (char *)"NOLOGGING", 9 } },
    { TABLE_TYPE_EXTERNAL, { (char *)"EXTERNAL", 8 } },
};

status_t sql_func_tab_type(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    return sql_get_type_mapped(stmt, func, result, CT_FALSE, g_table_type_names, TAB_TYPE_SIZE);
}

status_t sql_func_to_tablespace_name(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    text_t space_name;

    if (sql_exec_expr(stmt, func->argument, result) != CT_SUCCESS) {
        return CT_ERROR;
    }

    SQL_CHECK_COLUMN_VAR(result, result);

    if (result->is_null) {
        CT_THROW_ERROR(ERR_SPACE_NOT_EXIST, "");
        return CT_ERROR;
    } else {
        if (var_as_integer(result) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (result->v_int < 0 || result->v_int >= CT_MAX_SPACES) {
            CT_THROW_ERROR(ERR_SPACE_NOT_EXIST, "");
            return CT_ERROR;
        }

        CT_RETURN_IFERR(knl_get_space_name(&stmt->session->knl_session, (uint32)result->v_int, &space_name));
    }

    result->is_null = CT_FALSE;
    result->v_text = space_name;
    result->type = CT_TYPE_STRING;
    return CT_SUCCESS;
}

status_t sql_verify_to_tablespace_name(sql_verifier_t *verf, expr_node_t *func)
{
    ct_type_t arg_type;

    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 1, 1, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    arg_type = sql_get_func_arg1_datatype(func);
    if (!sql_match_numeric_type(arg_type)) {
        CT_SRC_THROW_ERROR(func->argument->loc, ERR_INVALID_FUNC_PARAMS, "integer argument expected");
        return CT_ERROR;
    }

    func->datatype = CT_TYPE_STRING;
    func->size = CT_MAX_NAME_LEN;
    return CT_SUCCESS;
}

status_t sql_func_to_username(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    text_t user_name;

    if (sql_exec_expr(stmt, func->argument, result) != CT_SUCCESS) {
        return CT_ERROR;
    }

    SQL_CHECK_COLUMN_VAR(result, result);

    if (result->is_null) {
        CT_THROW_ERROR(ERR_USER_NOT_EXIST, "");
        return CT_ERROR;
    } else {
        if (var_as_integer(result) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (result->v_int < 0 || result->v_int >= CT_MAX_USERS) {
            CT_THROW_ERROR(ERR_USER_NOT_EXIST, "");
            return CT_ERROR;
        }

        CT_RETURN_IFERR(knl_get_user_name(&stmt->session->knl_session, (uint32)result->v_int, &user_name));
    }

    result->is_null = CT_FALSE;
    result->v_text = user_name;
    result->type = CT_TYPE_STRING;
    return CT_SUCCESS;
}

status_t sql_verify_to_username(sql_verifier_t *verf, expr_node_t *func)
{
    ct_type_t arg_type;

    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 1, 1, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    arg_type = sql_get_func_arg1_datatype(func);
    if (!sql_match_numeric_type(arg_type)) {
        CT_SRC_THROW_ERROR(func->argument->loc, ERR_INVALID_FUNC_PARAMS, "integer argument expected");
        return CT_ERROR;
    }

    func->datatype = CT_TYPE_STRING;
    func->size = CT_MAX_NAME_LEN;
    return CT_SUCCESS;
}

static status_t sql_verify_param_datatype(dbe_func_param_t *param, expr_tree_t *expr_pos)
{
    switch (param->datatype) {
        case CT_TYPE_NUMBER:
        case CT_TYPE_NUMBER2:
        case CT_TYPE_UINT32:
        case CT_TYPE_INTEGER:
        case CT_TYPE_DECIMAL:
            if (!sql_match_numeric_type(TREE_DATATYPE(expr_pos))) {
                CT_SRC_THROW_ERROR_EX(expr_pos->loc, ERR_INVALID_FUNC_PARAMS, "%s should be number", param->name);
                return CT_ERROR;
            }
            break;

        case CT_TYPE_DATE:
        case CT_TYPE_TIMESTAMP:
            if (!sql_match_datetime_type(TREE_DATATYPE(expr_pos))) {
                CT_SRC_THROW_ERROR_EX(expr_pos->loc, ERR_INVALID_FUNC_PARAMS, "%s should be date/datatime",
                    param->name);
                return CT_ERROR;
            }
            break;

        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
        case CT_TYPE_STRING:
            if (!sql_match_string_type(TREE_DATATYPE(expr_pos))) {
                CT_SRC_THROW_ERROR_EX(expr_pos->loc, ERR_INVALID_FUNC_PARAMS, "%s should be string", param->name);
                return CT_ERROR;
            }
            break;

        case CT_TYPE_BOOLEAN:
            if (!sql_match_bool_type(TREE_DATATYPE(expr_pos))) {
                CT_SRC_THROW_ERROR_EX(expr_pos->loc, ERR_INVALID_FUNC_PARAMS, "%s should be boolean", param->name);
                return CT_ERROR;
            }
            break;

        default:
            CT_SRC_THROW_ERROR(expr_pos->loc, ERR_UNSUPPORT_DATATYPE, get_datatype_name_str(param->datatype));
            return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t sql_verify_nofound_param(expr_node_t *func, dbe_func_param_t *dbe_param, uint32 param_count,
    uint32 found_count)
{
    uint32 i;
    text_t param_name;
    dbe_func_param_t param;
    expr_tree_t *expr = NULL;

    if (found_count != func->value.v_func.arg_cnt) {
        for (expr = func->argument; expr != NULL; expr = expr->next) {
            if (expr->arg_name.len == 0) {
                continue;
            }

            for (i = 0; i < param_count; i++) {
                param = dbe_param[i];
                param_name.str = param.name;
                param_name.len = (uint32)strlen(param.name);

                if (cm_compare_text_ins(&param_name, &expr->arg_name) == 0) {
                    break;
                }
            }

            if (i == param_count) {
                CT_SRC_THROW_ERROR_EX(expr->loc, ERR_INVALID_FUNC_PARAMS, "error params name '%s'",
                    T2S(&expr->arg_name));
                return CT_ERROR;
            }
        }
    }

    return CT_SUCCESS;
}

/*
 * verify the paramter of this function
 */
status_t sql_verify_dbe_func(sql_verifier_t *verf, expr_node_t *func, dbe_func_param_t *dbe_param, uint32 param_count)
{
    uint32 i, j;
    dbe_func_param_t param;
    expr_tree_t *expr = NULL;
    expr_tree_t *expr_pos = NULL;
    text_t param_name;
    uint32 found_count = 0;

    for (i = 0; i < param_count; i++) {
        param = dbe_param[i];
        param_name.str = param.name;
        param_name.len = (uint32)strlen(param.name);
        expr_pos = NULL;
        for (expr = func->argument, j = 0; expr != NULL; expr = expr->next, j++) {
            if (expr->arg_name.len > 0 && cm_compare_text_ins(&param_name, &expr->arg_name) == 0) {
                expr_pos = expr;
                break;
            }

            if (j == i && expr->arg_name.len == 0) {
                expr_pos = expr;
            }
        }

        if (expr_pos == NULL && param.nullable == CT_TRUE) {
            continue;
        }
        if (expr_pos == NULL && param.nullable == CT_FALSE) {
            CT_SRC_THROW_ERROR_EX(func->loc, ERR_INVALID_FUNC_PARAMS, "%s cannot be null", param.name);
            return CT_ERROR;
        }

        CT_RETURN_IFERR(sql_verify_param_datatype(&param, expr_pos));

        found_count++;
    }

    /* Some input parameters has not been found, should check is valid or not */
    return sql_verify_nofound_param(func, dbe_param, param_count, found_count);
}

static status_t check_dbe_param_type(dbe_func_param_t *param, const int16 type, expr_tree_t *expr_dest)
{
    switch (param->datatype) {
        case CT_TYPE_NUMBER:
        case CT_TYPE_NUMBER2:
        case CT_TYPE_DECIMAL:
        case CT_TYPE_UINT32:
        case CT_TYPE_INTEGER:
        case CT_TYPE_REAL:
            if (!CT_IS_NUMERIC_TYPE(type)) {
                CT_SRC_THROW_ERROR(expr_dest->root->loc, ERR_INVALID_FUNC_PARAMS, param->name);
                return CT_ERROR;
            }
            break;

        case CT_TYPE_DATE:
        case CT_TYPE_TIMESTAMP:
            if (!CT_IS_DATETIME_TYPE(type)) {
                CT_SRC_THROW_ERROR(expr_dest->root->loc, ERR_INVALID_FUNC_PARAMS, param->name);
                return CT_ERROR;
            }
            break;

        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
        case CT_TYPE_STRING:
            if (!CT_IS_STRING_TYPE(type)) {
                CT_SRC_THROW_ERROR(expr_dest->root->loc, ERR_INVALID_FUNC_PARAMS, param->name);
                return CT_ERROR;
            }
            break;

        case CT_TYPE_BOOLEAN:
            if (!CT_IS_BOOLEAN_TYPE(type)) {
                CT_SRC_THROW_ERROR(expr_dest->root->loc, ERR_INVALID_FUNC_PARAMS, param->name);
                return CT_ERROR;
            }
            break;

        default:
            CT_SRC_THROW_ERROR(expr_dest->root->loc, ERR_UNSUPPORT_DATATYPE, get_datatype_name_str(param->datatype));
            return CT_ERROR;
    }

    return CT_SUCCESS;
}

/*
 * Get the paramter of this function by parameter position.
 * The position starts from one.
 * note:
 * 1.get the expr by name of this parameter.
 * 2.then get the expr by the position.
 */
status_t sql_get_dbe_param_value_loc(sql_stmt_t *stmt, expr_node_t *func, dbe_func_param_t *dbe_param,
    uint32 param_pos, variant_t *result, source_location_t *node_loc)
{
    expr_tree_t *expr = func->argument;
    expr_tree_t *expr_pos = NULL;
    expr_tree_t *expr_dest = NULL;
    text_t param_name;
    SQL_SET_NULL_VAR(result);
    if (param_pos == 0) {
        CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "param_pos(%u) != 0(%u)", (uint32)param_pos, (uint32)0);
        return CT_ERROR;
    }

    dbe_func_param_t param = dbe_param[param_pos - 1];
    param_name.str = param.name;
    param_name.len = (uint32)strlen(param.name);
    uint32 param_max_len = param.param_max_len;
    for (uint32 i = 1; expr != NULL; expr = expr->next, i++) {
        if (expr->arg_name.len > 0 && cm_compare_text_ins(&param_name, &expr->arg_name) == 0) {
            expr_dest = expr;
            break;
        }
        if (i == param_pos && expr->arg_name.len == 0) {
            expr_pos = expr;
        }
    }
    if (expr_dest == NULL && expr_pos != NULL) {
        expr_dest = expr_pos;
    }

    source_location_t loc = (expr_dest != NULL) ? expr_dest->root->loc : func->argument->root->loc;

    /* compute the paramter value */
    if (expr_dest != NULL && param.datatype != CT_TYPE_UNKNOWN) {
        CT_RETURN_IFERR(sql_exec_expr(stmt, expr_dest, result));
    }

    if (node_loc != NULL) {
        *node_loc = loc;
    }
    if (result->is_null) {
        if (!param.nullable) {
            CT_SRC_THROW_ERROR(loc, ERR_INVALID_FUNC_PARAMS, param.name);
            return CT_ERROR;
        }
        return CT_SUCCESS;
    }

    CT_RETSUC_IFTRUE(expr_dest == NULL);
    if (param_max_len != CT_INVALID_ID32) {
        if (result->v_text.len > param_max_len) {
            CT_THROW_ERROR(ERR_INVALID_PARAMETER_NAME, param_name.str);
            return CT_ERROR;
        }
    }

    return check_dbe_param_type(&param, result->type, expr_dest);
}

status_t sql_get_dbe_param_value(sql_stmt_t *stmt, expr_node_t *func, dbe_func_param_t *dbe_param, uint32 param_pos,
    variant_t *result)
{
    return sql_get_dbe_param_value_loc(stmt, func, dbe_param, param_pos, result, NULL);
}

void process_word_case_sensitive(word_t *word)
{
    if (word->type == WORD_TYPE_DQ_STRING) {
        return;
    } else if (IS_CASE_INSENSITIVE) {
        cm_text_upper(&word->text.value);
    }
}

static bool32 sql_is_pl_func(sql_stmt_t *stmt)
{
    pl_entity_t *entity = NULL;
    do {
        entity = (pl_entity_t *)stmt->pl_context;
        if (entity != NULL && entity->pl_type == PL_FUNCTION) {
            return CT_TRUE;
        }
        if (stmt->parent_stmt != NULL) {
            stmt = (sql_stmt_t *)stmt->parent_stmt;
        } else {
            return CT_FALSE;
        }
    } while (CT_TRUE);
}

/*
 * sql_func_sqlcode
 *
 * This function returns the errcode of this statement.
 */
static status_t sql_func_sqlcode(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    pl_executor_t *exec = (pl_executor_t *)stmt->pl_exec;
    bool32 execpt_existed = CT_FALSE;
    pl_exec_exception_t *curr_except = NULL;

    if (sql_is_pl_exec(stmt) != CT_TRUE) {
        CT_SRC_THROW_ERROR(func->loc, ERR_PL_SYNTAX_ERROR_FMT, "sql_err_code must to be used in PL/SQL");
        return CT_ERROR;
    }

    result->type = CT_TYPE_INTEGER;
    execpt_existed = ple_get_curr_except(exec, &curr_except);
    if (execpt_existed) {
        result->is_null = CT_FALSE;
        result->v_int = curr_except->except.error_code;
    } else {
        result->is_null = CT_FALSE;
        result->v_int = 0;
    }

    return CT_SUCCESS;
}

static status_t sql_verify_sqlcode(sql_verifier_t *verf, expr_node_t *func)
{
    if (sql_verify_func_node(verf, func, 0, 0, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    func->type = EXPR_NODE_FUNC;
    func->datatype = CT_TYPE_INTEGER;
    func->size = sizeof(int32);
    return CT_SUCCESS;
}

/*
 * sql_func_sqlerrm
 *
 * This function returns the errmsg of this statement.
 */
static status_t sql_func_sqlerrm(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    const char *error_message = NULL;
    variant_t var_errcode;
    pl_exec_exception_t *curr_except = NULL;
    bool32 except_existed = CT_FALSE;
    pl_executor_t *exec = (pl_executor_t *)stmt->pl_exec;

    result->type = CT_TYPE_STRING;

    if (sql_is_pl_exec(stmt) != CT_TRUE) {
        CT_SRC_THROW_ERROR(func->loc, ERR_PL_SYNTAX_ERROR_FMT, "sql_err_msg must to be used in PL/SQL");
        return CT_ERROR;
    }

    except_existed = ple_get_curr_except(exec, &curr_except);

    if (func->argument == NULL) {
        if (except_existed) {
            result->is_null = CT_FALSE;
            result->v_text.str = (char *)curr_except->except.message;
            result->v_text.len = (uint32)strlen(curr_except->except.message);
        } else {
            result->is_null = CT_FALSE;
            result->v_text.str = (char *)cm_get_errormsg(ERR_ERRNO_BASE);
            result->v_text.len = (uint32)strlen(result->v_text.str);
        }
    } else {
        expr_tree_t *arg = func->argument;
        CT_RETURN_IFERR(sql_exec_expr(stmt, arg, &var_errcode));

        if (!(var_errcode.is_null == CT_FALSE && CT_IS_NUMERIC_TYPE(var_errcode.type))) {
            CT_SRC_THROW_ERROR(func->argument->root->loc, ERR_INVALID_FUNC_PARAMS,
                "the error code argument of sql_err_msg is incorrect");
            return CT_ERROR;
        }

        CT_RETURN_IFERR(var_as_floor_integer(&var_errcode));

        if (var_errcode.v_int >= ERR_MIN_USER_DEFINE_ERROR && var_errcode.v_int <= ERR_MAX_USER_DEFINE_ERROR &&
            except_existed && var_errcode.v_int == curr_except->except.error_code) {
            error_message = (char *)curr_except->except.message;
        } else {
            error_message = cm_get_errormsg(var_errcode.v_int);
        }

        if (error_message == NULL) {
            result->is_null = CT_TRUE;
        } else {
            result->is_null = CT_FALSE;
            result->v_text.str = (char *)error_message;
            result->v_text.len = (uint32)strlen(error_message);
        }
    }

    return CT_SUCCESS;
}

static status_t sql_verify_sqlerrm(sql_verifier_t *verf, expr_node_t *func)
{
    if (sql_verify_func_node(verf, func, 0, 1, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    func->type = EXPR_NODE_FUNC;
    func->datatype = CT_TYPE_STRING;

    return CT_SUCCESS;
}

static status_t sql_output_prepare(sql_stmt_t *stmt, expr_node_t *func, variant_t *value, variant_t *result)
{
    CM_POINTER3(stmt, func, result);

    expr_node_t *arg_node = func->argument->root;
    CM_POINTER(arg_node);

    if (sql_exec_expr_node(stmt, arg_node, value) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_CALC_EXPRESSION, "expression node");
        return CT_ERROR;
    }

    if (sql_convert_variant(stmt, value, CT_TYPE_STRING) != CT_SUCCESS) {
        return CT_ERROR;
    }

    result->type = CT_TYPE_INTEGER;
    if (value->is_null) {
        result->is_null = CT_TRUE;
        value->v_text.len = 0;
    } else {
        result->is_null = CT_FALSE;
        result->v_int = 0;
    }

    if (value->v_text.len > CT_MAX_PUTLINE_SIZE) {
        CT_THROW_ERROR(ERR_OUT_OF_INDEX, "line length", CT_MAX_PUTLINE_SIZE);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t sql_print_line(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t var;
    status_t status;

    CTSQL_SAVE_STACK(stmt);

    do {
        status = sql_output_prepare(stmt, func, &var, result);
        if (status != CT_SUCCESS) {
            break;
        }

        if (stmt->is_srvoutput_on) {
            /* the value keeped will be release at the end of sql_print_line */
            sql_keep_stack_var(stmt, &var);
            status = pl_sender->send_serveroutput(stmt, &var.v_text);
        }
    } while (0);

    CTSQL_RESTORE_STACK(stmt);

    return status;
}

static status_t sql_verify_print(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 1, 1, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    func->datatype = CT_TYPE_INTEGER;
    func->size = sizeof(uint32);
    return CT_SUCCESS;
}

static inline void sql_gen_random_string(int32 length, variant_t *var_mode, char *buffer)
{
    char mode = var_mode->is_null ? 'U' : var_mode->v_text.str[0];
    cm_rand_string(length, mode, buffer);
}

/*
 * dbe_random.sql_random_string()
 *
 * This function is used to generate a random string.
 */
static status_t sql_random_string(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    char *buf = NULL;
    variant_t var_mode, var_length;
    expr_tree_t *arg1 = func->argument;
    expr_tree_t *arg2 = arg1->next;
    status_t status = CT_ERROR;

    /* get the mode of result char */
    CT_RETURN_IFERR(sql_exec_expr(stmt, arg1, &var_mode));

    SQL_CHECK_COLUMN_VAR(&var_mode, result);
    if (var_mode.is_null == CT_FALSE && !(CT_IS_STRING_TYPE(var_mode.type) && var_mode.v_text.len < 2)) {
        CT_SRC_THROW_ERROR(func->argument->root->loc, ERR_INVALID_FUNC_PARAMS,
            "the flag of random get_string is incorrect");
        return CT_ERROR;
    }

    CTSQL_SAVE_STACK(stmt);

    /* the value kept will be release at the end of sql_random_string */
    sql_keep_stack_var(stmt, &var_mode);

    /* get the length of result char */
    do {
        CT_BREAK_IF_ERROR(sql_exec_expr(stmt, arg2, &var_length));

        if (var_length.type == CT_TYPE_COLUMN) {
            SQL_SET_COLUMN_VAR(result);
            status = CT_SUCCESS;
            break;
        }
        if (!(var_length.is_null == CT_FALSE && CT_IS_NUMERIC_TYPE(var_length.type))) {
            CT_SRC_THROW_ERROR(func->argument->root->loc, ERR_INVALID_FUNC_PARAMS,
                "the len of random get_string is incorrect");
            break;
        }

        CT_BREAK_IF_ERROR(var_as_floor_integer(&var_length));

        int32 length = var_length.v_int;
        if (length < 1) {
            result->is_null = CT_TRUE;
            result->type = CT_TYPE_CHAR;
            status = CT_SUCCESS;
            break;
        } else if (length > CT_MAX_COLUMN_SIZE) {
            length = CT_MAX_COLUMN_SIZE;
        }

        CT_BREAK_IF_ERROR(sql_push(stmt, length + 1, (void **)&buf));

        sql_gen_random_string(length, &var_mode, buf);

        result->is_null = CT_FALSE;
        result->type = CT_TYPE_CHAR;
        result->v_text.str = buf;
        result->v_text.len = length;
        status = CT_SUCCESS;
    } while (0);

    CTSQL_RESTORE_STACK(stmt);
    return status;
}

static status_t sql_verify_random_string(sql_verifier_t *verf, expr_node_t *func)
{
    /* check the number of the argument */
    if (sql_verify_func_node(verf, func, 2, 2, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    expr_tree_t *arg1 = func->argument;
    expr_tree_t *arg2 = arg1->next;

    /* param1 must be one char or null */
    if (!sql_match_string_type(TREE_DATATYPE(arg1))) {
        CT_SRC_THROW_ERROR(func->argument->root->loc, ERR_INVALID_FUNC_PARAMS,
            "the falg of random get_string is incorrect");
        return CT_ERROR;
    }

    /* param2 must be number */
    if (!sql_match_numeric_type(TREE_DATATYPE(arg2))) {
        CT_SRC_THROW_ERROR(func->argument->root->loc, ERR_INVALID_FUNC_PARAMS,
            "the len of random get_string is incorrect");
        return CT_ERROR;
    }

    func->datatype = CT_TYPE_CHAR;
    func->size = CT_MAX_COLUMN_SIZE;
    return CT_SUCCESS;
}

/*
 * dbe_random.get_value()
 *
 * This function is used to generate a random number.
 */
static status_t sql_random_value(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    expr_tree_t *arg1 = NULL;
    expr_tree_t *arg2 = NULL;
    uint32 rand_val;
    variant_t var_low, var_high;
    dec8_t delta;
    bool32 defined_range = CT_FALSE;

    result->is_null = CT_FALSE;
    result->type = CT_TYPE_NUMBER;

    if (func->argument != NULL) {
        arg1 = func->argument;
        arg2 = arg1->next;

        /* get the low value */
        if (sql_exec_expr(stmt, arg1, &var_low) != CT_SUCCESS) {
            return CT_ERROR;
        }
        SQL_CHECK_COLUMN_VAR(&var_low, result);
        if (!(var_low.is_null == CT_FALSE && CT_IS_NUMERIC_TYPE(var_low.type))) {
            CT_SRC_THROW_ERROR(func->argument->root->loc, ERR_INVALID_FUNC_PARAMS,
                "the first argument of random get_value is incorrect");
            return CT_ERROR;
        }

        /* get the high value */
        if (sql_exec_expr(stmt, arg2, &var_high) != CT_SUCCESS) {
            return CT_ERROR;
        }
        SQL_CHECK_COLUMN_VAR(&var_high, result);
        if (!(var_high.is_null == CT_FALSE && CT_IS_NUMERIC_TYPE(var_high.type))) {
            CT_SRC_THROW_ERROR(func->argument->root->loc, ERR_INVALID_FUNC_PARAMS,
                "the second argument of random get_value is incorrect");
            return CT_ERROR;
        }

        /* convert to decimal */
        CT_RETURN_IFERR(var_as_decimal(&var_low));
        CT_RETURN_IFERR(var_as_decimal(&var_high));
        if (cm_dec_cmp(&var_low.v_dec, &var_high.v_dec) == 0) {
            *result = var_low;
            return CT_SUCCESS;
        }

        defined_range = CT_TRUE;
    }

    rand_val = cm_random(CT_MAX_RAND_RANGE);

    cm_uint32_to_dec(rand_val, &result->v_dec);
    CT_RETURN_IFERR(cm_dec_div_int64(&result->v_dec, CT_MAX_RAND_RANGE, &result->v_dec));

    if (defined_range == CT_TRUE) {
        CT_RETURN_IFERR(cm_dec_subtract(&var_high.v_dec, &var_low.v_dec, &delta));
        CT_RETURN_IFERR(cm_dec_mul(&result->v_dec, &delta, &result->v_dec));
        CT_RETURN_IFERR(cm_dec_add(&result->v_dec, &var_low.v_dec, &result->v_dec));
    }

    return CT_SUCCESS;
}

static status_t sql_verify_random_value(sql_verifier_t *verf, expr_node_t *func)
{
    expr_tree_t *arg1 = NULL;
    expr_tree_t *arg2 = NULL;

    /* check the number of the argument */
    if (func->argument != NULL) {
        if (sql_verify_func_node(verf, func, 2, 2, CT_INVALID_ID32) != CT_SUCCESS) {
            return CT_ERROR;
        }

        arg1 = func->argument;
        arg2 = arg1->next;

        /* param1 must be one char or null */
        if (!sql_match_numeric_type(TREE_DATATYPE(arg1))) {
            CT_SRC_THROW_ERROR(func->argument->root->loc, ERR_INVALID_FUNC_PARAMS,
                "the first argument of random get_value is incorrect");
            return CT_ERROR;
        }

        /* param2 must be number */
        if (!sql_match_numeric_type(TREE_DATATYPE(arg2))) {
            CT_SRC_THROW_ERROR(func->argument->root->loc, ERR_INVALID_FUNC_PARAMS,
                "the second argument of get_random value is incorrect");
            return CT_ERROR;
        }
    }

    func->datatype = CT_TYPE_NUMBER;
    func->size = MAX_DEC_BYTE_SZ;
    func->scale = CT_UNSPECIFIED_NUM_SCALE;
    func->precision = CT_UNSPECIFIED_NUM_PREC;
    return CT_SUCCESS;
}

static status_t sql_throw_exception_core(sql_stmt_t *stmt, expr_node_t *func, variant_t *error_code,
    variant_t *error_message)
{
    expr_node_t *arg_node = NULL;

    arg_node = func->argument->root;

    if (sql_exec_expr_node(stmt, arg_node, error_code) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_CALC_EXPRESSION, "expression node");
        return CT_ERROR;
    }
    if (!(error_code->is_null == CT_FALSE && CT_IS_WEAK_NUMERIC_TYPE(error_code->type))) {
        CT_SRC_THROW_ERROR(func->argument->root->loc, ERR_INVALID_FUNC_PARAMS,
            "error number argument to throw_exception");
        return CT_ERROR;
    }
    if (var_as_bigint(error_code) != CT_SUCCESS) {
        CT_SRC_THROW_ERROR(func->argument->root->loc, ERR_INVALID_FUNC_PARAMS,
            "error number argument to throw_exception");
        return CT_ERROR;
    }

    /* The error_code is an integer in the range -20000..-20999. */
    if (!(error_code->v_bigint >= ERR_MIN_USER_DEFINE_ERROR && error_code->v_bigint <= ERR_MAX_USER_DEFINE_ERROR)) {
        CT_SRC_THROW_ERROR_EX(func->argument->root->loc, ERR_INVALID_FUNC_PARAMS,
            "error number argument to throw_exception is out of range(%d..%d)", ERR_MIN_USER_DEFINE_ERROR,
            ERR_MAX_USER_DEFINE_ERROR);
        return CT_ERROR;
    }

    arg_node = func->argument->next->root;

    if (sql_exec_expr_node(stmt, arg_node, error_message) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_CALC_EXPRESSION, "expression node");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(sql_convert_variant(stmt, error_message, CT_TYPE_STRING));

    /* The message is a character string of at most PLC_ERROR_BUFFER_SIZE bytes. */
    if (error_message->is_null) {
        CT_SRC_THROW_ERROR(func->argument->root->loc, ERR_INVALID_FUNC_PARAMS, "the message string can not be null");
        return CT_ERROR;
    }
    if (error_message->v_text.len > PLC_ERROR_BUFFER_SIZE) {
        CT_SRC_THROW_ERROR_EX(func->argument->root->loc, ERR_INVALID_FUNC_PARAMS,
            "message string is too large, the max length is %d", PLC_ERROR_BUFFER_SIZE);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t sql_throw_exception(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    CM_POINTER3(stmt, func, result);
    variant_t error_code;
    variant_t error_message;
    pl_executor_t *exec = NULL;
    pl_exec_exception_t *exec_except = NULL;

    CT_RETURN_IFERR(sql_throw_exception_core(stmt, func, &error_code, &error_message));

    cm_reset_error();
    cm_set_error((char *)__FILE__, (uint32)__LINE__, error_code.v_bigint, "%s", T2S(&error_message.v_text));
    cm_set_error_loc(func->argument->root->loc);

    if (stmt->pl_exec != NULL) {
        exec = (pl_executor_t *)stmt->pl_exec;
        exec_except = &(exec->exec_except);

        exec_except->has_exception = CT_TRUE;
        exec_except->except.is_userdef = CT_FALSE;
        exec_except->except.error_code = (int32)error_code.v_bigint;
        exec_except->except.loc = func->argument->root->loc;
        MEMS_RETURN_IFERR(strcpy_s(exec_except->except.message, CT_MESSAGE_BUFFER_SIZE, T2S(&error_message.v_text)));
    }
    return CT_ERROR;
}

static status_t sql_verify_throw_excption(sql_verifier_t *verf, expr_node_t *func)
{
    expr_tree_t *arg1 = NULL;
    expr_tree_t *arg2 = NULL;
    expr_tree_t *arg3 = NULL;

    if (sql_verify_func_node(verf, func, 2, 3, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    arg1 = func->argument;
    arg2 = arg1->next;

    if (!sql_match_numeric_type(TREE_DATATYPE(arg1))) {
        CT_SRC_ERROR_REQUIRE_INTEGER(arg1->loc, TREE_DATATYPE(arg1));
        return CT_ERROR;
    }

    if (!sql_match_string_type(TREE_DATATYPE(arg2))) {
        CT_SRC_ERROR_REQUIRE_STRING(arg2->loc, TREE_DATATYPE(arg2));
        return CT_ERROR;
    }

    /* The 3rd argument should be false or true. */
    if (arg2->next != NULL) {
        arg3 = arg2->next;
        if (!(arg3->root->type == EXPR_NODE_RESERVED && arg3->root->value.type == CT_TYPE_INTEGER &&
            (arg3->root->value.v_rid.res_id == RES_WORD_FALSE || arg3->root->value.v_rid.res_id == RES_WORD_TRUE))) {
            CT_SRC_THROW_ERROR(func->argument->root->loc, ERR_INVALID_FUNC_PARAMS, "error flag");
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t sql_auto_sample_size(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    result->type = CT_TYPE_NUMBER;
    result->is_null = CT_FALSE;
    cm_zero_dec(&result->v_dec);
    return CT_SUCCESS;
}

static status_t sql_verify_auto_sample_size(sql_verifier_t *verf, expr_node_t *func)
{
    if (sql_verify_func_node(verf, func, 0, 0, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    func->datatype = CT_TYPE_NUMBER;
    func->size = MAX_DEC_BYTE_SZ;
    func->scale = CT_UNSPECIFIED_NUM_SCALE;
    func->precision = CT_UNSPECIFIED_NUM_PREC;
    return CT_SUCCESS;
}

/*
 * sql_delete_table_stats
 *
 * This procedure deletes table-related statistics.
 * Syntax:
 * DBE-STATS.DELETE_TABLE_STATS ( * ownname          VARCHAR2,
 * tabname          VARCHAR2,
 * partname         VARCHAR2 DEFAULT NULL,--unsupported
 * stattab          VARCHAR2 DEFAULT NULL,--unsupported
 * statid           VARCHAR2 DEFAULT NULL,--unsupported
 * cascade_parts    BOOLEAN  DEFAULT TRUE,--unsupported
 * cascade_columns  BOOLEAN  DEFAULT TRUE,--unsupported
 * cascade_indexes  BOOLEAN  DEFAULT TRUE,--unsupported
 * statown          VARCHAR2 DEFAULT NULL,--unsupported
 * no_invalidate    BOOLEAN  DEFAULT to_no_invalidate_type ( get_param('NO_INVALIDATE')),--unsupported
 * force            BOOLEAN DEFAULT FALSE --unsupported
 * );
 */
static status_t sql_delete_table_stats(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t ownname, tabname, partname;
    status_t status = CT_ERROR;
    char buf[CT_NAME_BUFFER_SIZE];

    CM_POINTER3(stmt, func, result);
    CT_RETURN_IFERR(sql_check_trig_commit(stmt));

    CTSQL_SAVE_STACK(stmt);

    do {
        /* ownname */
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_delete_table_stats_params, 1, &ownname));
        /* the value kept will be release at the end of sql_delete_table_stats */
        sql_keep_stack_var(stmt, &ownname);
        CT_BREAK_IF_ERROR(sql_user_text_prefix_tenant(stmt->session, &ownname.v_text, buf, CT_NAME_BUFFER_SIZE));

        /* tabname */
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_delete_table_stats_params, 2, &tabname));
        /* the value kept will be release at the end of sql_delete_table_stats */
        sql_keep_stack_var(stmt, &tabname);

        /* partname */
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_delete_table_stats_params, 3, &partname));
        /* the value kept will be release at the end of sql_delete_table_stats */
        sql_keep_stack_var(stmt, &partname);

        /*
         * User name must be upper case.
         * Table name uses upper case or original mode depending on system setting.
         */
        cm_text_upper(&ownname.v_text);
        process_name_case_sensitive(&tabname.v_text);

        /* check privilege */
        if (!sql_check_stats_priv(stmt->session, &ownname.v_text)) {
            CT_SRC_THROW_ERROR(func->loc, ERR_INSUFFICIENT_PRIV);
            break;
        }

        SQL_SET_NULL_VAR(result);

        if (partname.is_null) {
            status = knl_delete_table_stats(KNL_SESSION(stmt), &ownname.v_text, &tabname.v_text, NULL);
        } else {
            process_name_case_sensitive(&partname.v_text);
            status = knl_delete_table_stats(KNL_SESSION(stmt), &ownname.v_text, &tabname.v_text, &partname.v_text);
        }
    } while (0);

    CTSQL_RESTORE_STACK(stmt);

    return status;
}

static status_t sql_verify_delete_table_stats(sql_verifier_t *verf, expr_node_t *func)
{
    if (sql_verify_func_node(verf, func, 2, 3, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return sql_verify_dbe_func(verf, func, g_delete_table_stats_params,
        sizeof(g_delete_table_stats_params) / sizeof(dbe_func_param_t));
}

/*
 * sql_delete_schema_stats
 *
 * This procedure deletes statistics for an entire schema.
 * Syntax:
 *
 * DBE-STATS.DELETE_SCHEMA_STATS ( *   ownname          VARCHAR2,
 * stattab          VARCHAR2 DEFAULT NULL, --unsupported
 * statid           VARCHAR2 DEFAULT NULL, --unsupported
 * statown          VARCHAR2 DEFAULT NULL, --unsupported
 * no_invalidate    BOOLEAN DEFAULT FALSE, --unsupported
 * force            BOOLEAN DEFAULT FALSE --unsupported
 * );
 */
static status_t sql_delete_schema_stats(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t ownname;
    status_t status;
    char buf[CT_NAME_BUFFER_SIZE];

    CM_POINTER3(stmt, func, result);
    CT_RETURN_IFERR(sql_check_trig_commit(stmt));

    CTSQL_SAVE_STACK(stmt);

    /* ownname */
    if (sql_get_dbe_param_value(stmt, func, g_delete_schema_stats_params, 1, &ownname) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }
    /* the value kept will be release at the end of this function */
    sql_keep_stack_var(stmt, &ownname);
    if (sql_user_text_prefix_tenant(stmt->session, &ownname.v_text, buf, CT_NAME_BUFFER_SIZE) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }

    /* User name must be upper case.  */
    cm_text_upper(&ownname.v_text);

    if (!sql_check_stats_priv(stmt->session, &ownname.v_text)) {
        CT_SRC_THROW_ERROR(func->loc, ERR_INSUFFICIENT_PRIV);
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }

    SQL_SET_NULL_VAR(result);

    status = knl_delete_schema_stats(&stmt->session->knl_session, &ownname.v_text);
    CTSQL_RESTORE_STACK(stmt);

    return status;
}

static status_t sql_verify_delete_schema_stats(sql_verifier_t *verf, expr_node_t *func)
{
    if (sql_verify_func_node(verf, func, 1, 1, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return sql_verify_dbe_func(verf, func, g_delete_schema_stats_params,
        sizeof(g_delete_schema_stats_params) / sizeof(dbe_func_param_t));
}

static status_t sql_compute_sample_ratio(sql_stmt_t *stmt, expr_node_t *func, dbe_func_param_t *dbe_param,
    uint32 param_pos, double *sample_ratio, bool32 *is_default)
{
    variant_t estimate_percent;

    CT_RETURN_IFERR(sql_get_dbe_param_value(stmt, func, dbe_param, param_pos, &estimate_percent));

    if (estimate_percent.is_null) {
        *is_default = CT_TRUE;
        *sample_ratio = STATS_DEFAULT_ESTIMATE_PERCENT;
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(var_as_real(&estimate_percent));
    if (fabs(estimate_percent.v_real) < CT_REAL_PRECISION) {
        *sample_ratio = 0;
        return CT_SUCCESS;
    }
    if (estimate_percent.v_real < STATS_MIN_ESTIMATE_PERCENT || estimate_percent.v_real > STATS_MAX_ESTIMATE_PERCENT) {
        CT_SRC_THROW_ERROR(func->argument->root->loc, ERR_INVALID_FUNC_PARAMS,
            "the valid range of sample_ratio is [0.000001,100]");
        return CT_ERROR;
    }

    *sample_ratio = estimate_percent.v_real;

    return CT_SUCCESS;
}

status_t sql_parser_schema_stats_opt(sql_stmt_t *stmt, text_t *method_opt, knl_analyze_schema_def_t *def,
    source_location_t loc)
{
    lex_t *lex = stmt->session->lex;
    sql_text_t sql_text;
    uint32 matched_id;
    bool32 result = CT_FALSE;
    status_t ret = CT_ERROR;

    sql_text.value = *method_opt;
    sql_text.loc = loc;
    lex_trim(&sql_text);
    if (sql_text.value.len == 0) {
        def->method_opt.option = FOR_ALL_COLUMNS;
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(sql_stack_safe(stmt));
    CT_RETURN_IFERR(lex_push(lex, &sql_text));

    do {
        CT_BREAK_IF_ERROR(lex_expected_fetch_word(lex, "for"));
        CT_BREAK_IF_ERROR(lex_expected_fetch_1of2(lex, "all", "columns", &matched_id));

        if (matched_id == 1) {
            CT_SRC_THROW_ERROR(loc, ERR_CAPABILITY_NOT_SUPPORT, "for column lists");
            break;
        }

        CT_BREAK_IF_ERROR(lex_expected_fetch_1of3(lex, "indexed", "hidden", "columns", &matched_id));

        if (matched_id == 1) {
            CT_SRC_THROW_ERROR(loc, ERR_CAPABILITY_NOT_SUPPORT, "for all hidden lists");
            break;
        }

        if (matched_id == 2) {
            def->method_opt.option = FOR_ALL_COLUMNS;
        } else {
            CT_BREAK_IF_ERROR(lex_expected_fetch_word(lex, "columns"));
            def->method_opt.option = FOR_ALL_INDEX_COLUMNS;
        }

        CT_BREAK_IF_ERROR(lex_try_fetch(lex, "size", &result));

        if (result == CT_TRUE) {
            CT_BREAK_IF_ERROR(lex_expected_fetch_1ofn(lex, &matched_id, 4, "interger", "repeat", "auto", "skewonly"));
        }

        ret = CT_SUCCESS;
    } while (0);

    lex_pop(lex);
    return ret;
}

status_t sql_parser_table_stats_opt(sql_stmt_t *stmt, text_t *method_opt, knl_analyze_tab_def_t *def,
    source_location_t loc)
{
    lex_t *lex = stmt->session->lex;
    sql_text_t sql_text;
    uint32 matched_id;
    bool32 result = CT_FALSE;
    status_t status = CT_ERROR;
    bool32 for_exec_ok = CT_TRUE;
    word_t word;
    knl_dictionary_t dc;
    uint16 col;

    dc.handle = NULL;
    sql_text.value = *method_opt;
    sql_text.loc = loc;
    lex_trim(&sql_text);
    if (sql_text.value.len == 0) {
        def->method_opt.option = FOR_ALL_COLUMNS;
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(sql_stack_safe(stmt));
    CT_RETURN_IFERR(lex_push(lex, &sql_text));

    uint32 flags_bak = lex->flags;
    lex->flags = LEX_SINGLE_WORD;

    do {
        CT_BREAK_IF_ERROR(lex_expected_fetch_word(lex, "for"));
        CT_BREAK_IF_ERROR(lex_expected_fetch_1of2(lex, "all", "columns", &matched_id));
        if (matched_id == 0) {
            CT_BREAK_IF_ERROR(lex_expected_fetch_1of3(lex, "indexed", "hidden", "columns", &matched_id));
            if (matched_id == 1) {
                CT_SRC_THROW_ERROR(loc, ERR_CAPABILITY_NOT_SUPPORT, "for all hidden lists");
                break;
            }
            if (matched_id == 2) {
                def->method_opt.option = FOR_ALL_COLUMNS;
            } else {
                CT_BREAK_IF_ERROR(lex_expected_fetch_word(lex, "columns"));
                def->method_opt.option = FOR_ALL_INDEX_COLUMNS;
            }
            CT_BREAK_IF_ERROR(lex_try_fetch(lex, "size", &result));
            if (result == CT_TRUE) {
                CT_BREAK_IF_ERROR(
                    lex_expected_fetch_1ofn(lex, &matched_id, 4, "interger", "repeat", "auto", "skewonly"));
                CT_SRC_THROW_ERROR(loc, ERR_CAPABILITY_NOT_SUPPORT, "for all .. size");
                break;
            }
            CT_BREAK_IF_ERROR(lex_fetch(lex, &word));
            if (word.type != WORD_TYPE_EOF) {
                CT_SRC_THROW_ERROR_EX(word.loc, ERR_SQL_SYNTAX_ERROR, "unexpected word '%s' found", W2S(&word));
                break;
            }
            status = CT_SUCCESS;
        } else {
            def->method_opt.option = FOR_SPECIFIED_COLUMNS;
            CT_BREAK_IF_ERROR(knl_open_dc(KNL_SESSION(stmt), &def->owner, &def->name, &dc));
            for (;;) {
                CT_BREAK_IF_ERROR(lex_fetch(lex, &word));
                if (word.type != WORD_TYPE_VARIANT && word.type != WORD_TYPE_DQ_STRING) {
                    CT_SRC_THROW_ERROR_EX(word.loc, ERR_SQL_SYNTAX_ERROR, "unexpected word '%s' found", W2S(&word));
                    break;
                }
                process_word_case_sensitive(&word);
                col = knl_get_column_id(&dc, &word.text.value);
                if (col == CT_INVALID_ID16 || KNL_COLUMN_INVISIBLE(knl_get_column(dc.handle, col))) {
                    CT_SRC_THROW_ERROR(word.loc, ERR_UNDEFINED_SYMBOL_FMT, W2S(&word));
                    break;
                }
                for (uint32 i = 0; i < def->specify_cols.cols_count; i++) {
                    if (def->specify_cols.specified_cols[i] == col) {
                        CT_SRC_THROW_ERROR(word.loc, ERR_DUPLICATE_NAME, "COLUMN", W2S(&word));
                        for_exec_ok = CT_FALSE;
                        break;
                    }
                }
                CT_BREAK_IF_TRUE(!for_exec_ok);
                def->specify_cols.specified_cols[def->specify_cols.cols_count++] = col;
                CT_BREAK_IF_ERROR(lex_fetch(lex, &word));

                if (word.id == KEY_WORD_WITH) {
                    CT_BREAK_IF_ERROR(lex_expected_fetch_word(lex, "indexed"));
                    CT_BREAK_IF_ERROR(lex_expected_fetch_word(lex, "columns"));
                    CT_BREAK_IF_ERROR(lex_fetch(lex, &word));
                    if (word.type != WORD_TYPE_EOF) {
                        CT_SRC_THROW_ERROR(word.loc, ERR_UNDEFINED_SYMBOL_FMT, W2S(&word));
                        break;
                    }
                    def->method_opt.option = FOR_SPECIFIED_INDEXED_COLUMNS;
                    status = CT_SUCCESS;
                    break;
                } else {
                    if (word.type != WORD_TYPE_EOF && word.type != WORD_TYPE_SPEC_CHAR) {
                        CT_SRC_THROW_ERROR(word.loc, ERR_UNDEFINED_SYMBOL_FMT, W2S(&word));
                        break;
                    }
                    if (word.type == WORD_TYPE_EOF) {
                        status = CT_SUCCESS;
                        break;
                    }
                }
            }
        }
    } while (0);

    lex_pop(lex);
    knl_close_dc((knl_handle_t)&dc);
    lex->flags = flags_bak;
    return status;
}

/*
 * sql_collect_table_stats
 *
 * This function is used to get the stats of one table.
 *
 * syntax:
 * DBE-STATS.COLLECT_TABLE_STATS ( *   ownname          VARCHAR2,
 * tabname          VARCHAR2,
 * partname         VARCHAR2 DEFAULT NULL,
 * estimate_percent NUMBER   DEFAULT (The valid range is [0.000001,100])
 * block_sample     BOOLEAN  DEFAULT TRUE,
 * method_opt       VARCHAR2 DEFAULT ,
 * degree           NUMBER   DEFAULT,
 * granularity      VARCHAR2 DEFAULT,
 * cascade          BOOLEAN  DEFAULT,
 * stattab          VARCHAR2 DEFAULT NULL,
 * statid           VARCHAR2 DEFAULT NULL,
 * statown          VARCHAR2 DEFAULT NULL,
 * no_invalidate    BOOLEAN  DEFAULT NULL,
 * stattype         VARCHAR2 DEFAULT NULL,
 * force            BOOLEAN  DEFAULT NULL);
 */
static status_t sql_collect_table_stats(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    knl_analyze_tab_def_t *def = NULL;
    variant_t ownname, tabname, partname, block_sample, method_opt;
    status_t status = CT_ERROR;
    errno_t ret;
    source_location_t loc;
    char buf[CT_NAME_BUFFER_SIZE];

    CM_POINTER3(stmt, func, result);
    CT_RETURN_IFERR(sql_check_trig_commit(stmt));

    CTSQL_SAVE_STACK(stmt);

    do {
        /* ownname */
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_collect_table_stats_params, 1, &ownname));
        /* the value kept will be release at the end of this function */
        sql_keep_stack_var(stmt, &ownname);
        CT_BREAK_IF_ERROR(sql_user_text_prefix_tenant(stmt->session, &ownname.v_text, buf, CT_NAME_BUFFER_SIZE));

        /* tabname */
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_collect_table_stats_params, 2, &tabname));
        /* the value kept will be release at the end of this function */
        sql_keep_stack_var(stmt, &tabname);

        /* partname */
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_collect_table_stats_params, 3, &partname));
        /* the value kept will be release at the end of this function */
        sql_keep_stack_var(stmt, &partname);

        CT_BREAK_IF_ERROR(sql_push(stmt, sizeof(knl_analyze_tab_def_t), (void **)&def));
        ret = memset_sp(def, sizeof(knl_analyze_tab_def_t), 0, sizeof(knl_analyze_tab_def_t));
        if (ret != EOK) {
            CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
            break;
        }

        def->owner = ownname.v_text;
        def->name = tabname.v_text;
        def->sample_ratio = STATS_MAX_ESTIMATE_PERCENT;
        def->sample_level = BLOCK_SAMPLE;
        def->sample_type = STATS_SPECIFIED_SAMPLE;
        def->is_default = CT_FALSE;
        def->part_name = partname.is_null ? CM_NULL_TEXT : partname.v_text;
        def->specify_cols.cols_count = 0;

        /* estimate_percent */
        CT_BREAK_IF_ERROR(sql_compute_sample_ratio(stmt, func, g_collect_table_stats_params, 4, &def->sample_ratio,
            &def->is_default));

        if (def->is_default) {
            def->sample_type = STATS_DEFAULT_SAMPLE;
        }

        if (fabs(def->sample_ratio) < CT_REAL_PRECISION) {
            def->sample_type = STATS_AUTO_SAMPLE;
        }

        /* block_sample */
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_collect_table_stats_params, 5, &block_sample));

        if (!block_sample.is_null) {
            def->sample_level = (block_sample.v_bool == CT_TRUE) ? BLOCK_SAMPLE : ROW_SAMPLE;
        }

        /*
         * User name must be upper case.
         * Table name uses upper case or original mode depending on system setting.
         */
        process_name_case_sensitive(&def->owner);
        process_name_case_sensitive(&def->name);
        process_name_case_sensitive(&def->part_name);

        /* method opt */
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value_loc(stmt, func, g_collect_table_stats_params, 6, &method_opt, &loc));

        if (!method_opt.is_null) {
            CT_BREAK_IF_ERROR(sql_parser_table_stats_opt(stmt, &method_opt.v_text, def, loc));
        } else {
            def->method_opt.option = FOR_ALL_COLUMNS;
        }

        /* check privilege */
        if (!sql_check_stats_priv(stmt->session, &def->owner)) {
            CT_SRC_THROW_ERROR(func->loc, ERR_INSUFFICIENT_PRIV);
            break;
        }

        sql_record_knl_stats_info(stmt);
        status = knl_analyze_table(&stmt->session->knl_session, def);
        sql_reset_knl_stats_info(stmt, status);
    } while (0);

    CTSQL_RESTORE_STACK(stmt);

    return status;
}

static status_t sql_verify_collect_table_stats(sql_verifier_t *verf, expr_node_t *func)
{
    if (sql_verify_func_node(verf, func, 2, 6, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return sql_verify_dbe_func(verf, func, g_collect_table_stats_params,
        sizeof(g_collect_table_stats_params) / sizeof(dbe_func_param_t));
}

/*
 * sql_collect_schema_stats
 *
 * This function is used to get the stats of one schema.
 * Syntax
 *
 * DBE-STATS.COLLECT_SCHEMA_STATS ( *   ownname          VARCHAR2,
 * estimate_percent NUMBER   DEFAULT ,
 * block_sample     BOOLEAN  DEFAULT FALSE,
 * method_opt       VARCHAR2 DEFAULT ,
 * degree           NUMBER   DEFAULT ,
 * granularity      VARCHAR2 DEFAULT ,
 * cascade          BOOLEAN  DEFAULT ,
 * stattab          VARCHAR2 DEFAULT NULL,
 * statid           VARCHAR2 DEFAULT NULL,
 * options          VARCHAR2 DEFAULT ,
 * objlist          OUT      ObjectTab,
 * statown          VARCHAR2 DEFAULT NULL,
 * no_invalidate    BOOLEAN  DEFAULT ,
 * force             BOOLEAN DEFAULT FALSE,
 * obj_filter_list  ObjectTab DEFAULT NULL);
 */
static status_t sql_collect_schema_stats(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    knl_analyze_schema_def_t *def = NULL;
    variant_t ownname, block_sample, method_opt;
    status_t status = CT_ERROR;
    source_location_t loc;
    char buf[CT_NAME_BUFFER_SIZE];

    CM_POINTER3(stmt, func, result);
    CT_RETURN_IFERR(sql_check_trig_commit(stmt));

    CTSQL_SAVE_STACK(stmt);

    do {
        /* ownname */
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_collect_schema_stats_params, 1, &ownname));
        CT_BREAK_IF_ERROR(sql_user_text_prefix_tenant(stmt->session, &ownname.v_text, buf, CT_NAME_BUFFER_SIZE));
        CT_BREAK_IF_ERROR(sql_push(stmt, sizeof(knl_analyze_schema_def_t), (void **)&def));

        def->owner = ownname.v_text;
        def->sample_level = BLOCK_SAMPLE;
        def->sample_ratio = STATS_MAX_ESTIMATE_PERCENT;
        def->sample_type = STATS_SPECIFIED_SAMPLE;
        def->is_default = CT_FALSE;

        CT_BREAK_IF_ERROR(sql_compute_sample_ratio(stmt, func, g_collect_schema_stats_params, 2, &def->sample_ratio,
            &def->is_default));

        if (def->is_default) {
            def->sample_type = STATS_DEFAULT_SAMPLE;
        }

        if (fabs(def->sample_ratio) < CT_REAL_PRECISION) {
            def->sample_type = STATS_AUTO_SAMPLE;
        }

        /* block_sample */
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_collect_schema_stats_params, 3, &block_sample));

        if (!block_sample.is_null) {
            def->sample_level = (block_sample.v_bool == CT_TRUE) ? BLOCK_SAMPLE : ROW_SAMPLE;
        }

        /* method_opt */
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value_loc(stmt, func, g_collect_schema_stats_params, 4, &method_opt, &loc));

        if (!method_opt.is_null) {
            CT_BREAK_IF_ERROR(sql_parser_schema_stats_opt(stmt, &method_opt.v_text, def, loc));
        } else {
            def->method_opt.option = FOR_ALL_COLUMNS;
        }

        /* User name must be upper case  */
        cm_text_upper(&def->owner);

        if (!sql_check_stats_priv(stmt->session, &def->owner)) {
            CT_SRC_THROW_ERROR(func->loc, ERR_INSUFFICIENT_PRIV);
            break;
        }

        sql_record_knl_stats_info(stmt);
        status = knl_analyze_schema(&stmt->session->knl_session, def);
        sql_reset_knl_stats_info(stmt, status);
    } while (0);

    CTSQL_RESTORE_STACK(stmt);

    return status;
}

static status_t sql_verify_collect_schema_stats(sql_verifier_t *verf, expr_node_t *func)
{
    if (sql_verify_func_node(verf, func, 1, 4, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return sql_verify_dbe_func(verf, func, g_collect_schema_stats_params,
        sizeof(g_collect_schema_stats_params) / sizeof(dbe_func_param_t));
}

static status_t sql_collect_index_stats(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    knl_analyze_index_def_t *def = NULL;
    variant_t ownname, indexname, tablename;
    status_t status = CT_ERROR;
    errno_t ret;
    bool32 is_default = CT_FALSE;
    char buf[CT_NAME_BUFFER_SIZE];

    CM_POINTER3(stmt, func, result);
    CT_RETURN_IFERR(sql_check_trig_commit(stmt));

    CTSQL_SAVE_STACK(stmt);

    do {
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_collect_index_stats_params, 1, &ownname));
        sql_keep_stack_var(stmt, &ownname);
        CT_BREAK_IF_ERROR(sql_user_text_prefix_tenant(stmt->session, &ownname.v_text, buf, CT_NAME_BUFFER_SIZE));

        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_collect_index_stats_params, 2, &indexname));
        sql_keep_stack_var(stmt, &indexname);

        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_collect_index_stats_params, 3, &tablename));
        sql_keep_stack_var(stmt, &tablename);

        CT_BREAK_IF_ERROR(sql_push(stmt, sizeof(knl_analyze_index_def_t), (void **)&def));
        ret = memset_sp(def, sizeof(knl_analyze_index_def_t), 0, sizeof(knl_analyze_index_def_t));
        if (ret != EOK) {
            CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
            break;
        }

        def->owner = ownname.v_text;
        def->name = indexname.v_text;
        def->sample_ratio = STATS_MAX_ESTIMATE_PERCENT;
        def->sample_level = BLOCK_SAMPLE;
        def->table_name = tablename.v_text;

        CT_BREAK_IF_ERROR(
            sql_compute_sample_ratio(stmt, func, g_collect_index_stats_params, 4, &def->sample_ratio, &is_default));
        def->sample_ratio = def->sample_ratio / 100; // sample ratio divided by 100
        cm_text_upper(&def->owner);
        process_name_case_sensitive(&def->name);

        if (!sql_check_stats_priv(stmt->session, &def->owner)) {
            CT_SRC_THROW_ERROR(func->loc, ERR_INSUFFICIENT_PRIV);
            break;
        }
        status = knl_analyze_index(&stmt->session->knl_session, def);
    } while (0);

    CTSQL_RESTORE_STACK(stmt);

    return status;
}

static status_t sql_verify_collect_index_stats(sql_verifier_t *verf, expr_node_t *func)
{
    if (sql_verify_func_node(verf, func, 3, 4, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return sql_verify_dbe_func(verf, func, g_collect_index_stats_params,
        sizeof(g_collect_index_stats_params) / sizeof(dbe_func_param_t));
}

static void sql_confirm_text_val(variant_t *var, text_t *text_var)
{
    if (var->is_null) {
        text_var->len = CT_NULL_VALUE_LEN;
        return;
    }

    text_var->str = var->v_text.str;
    text_var->len = var->v_text.len;
}

static status_t sql_confirm_uint32_val(variant_t *var, uint32 *uint32_var)
{
    if (var->is_null) {
        *uint32_var = CT_INVALID_ID32;
        return CT_SUCCESS;
    }
    CT_RETURN_IFERR(var_as_uint32(var));
    *uint32_var = var->v_uint32;
    return CT_SUCCESS;
}

static status_t sql_confirm_double_val(variant_t *var, double *double_var)
{
    if (var->is_null) {
        *double_var = CT_INVALID_ID64;
        return CT_SUCCESS;
    }
    CT_RETURN_IFERR(var_as_real(var));
    *double_var = var->v_real;
    return CT_SUCCESS;
}

static status_t sql_confirm_uint64_val(variant_t *var, uint64 *uint64_var)
{
    if (var->is_null) {
        *uint64_var = CT_INVALID_ID64;
        return CT_SUCCESS;
    }
    CT_RETURN_IFERR(var_as_decimal(var));
    CT_RETURN_IFERR(cm_dec_to_uint64(&var->v_dec, uint64_var, ROUND_HALF_UP));
    return CT_SUCCESS;
}

static status_t sql_set_column_stats_value(knl_column_set_stats_t *col_stats, variant_t *partname)
{
    if (SECUREC_UNLIKELY(col_stats == NULL || partname == NULL)) {
        return CT_ERROR;
    }

    if ((col_stats->density != CT_INVALID_ID64) && (col_stats->density > 1 || col_stats->density < 0)) {
        CT_THROW_ERROR_EX(ERR_INVALID_FUNC_PARAMS, "%s should between 0 and 1", g_mod_column_stats_params[5].name);
        return CT_ERROR;
    }

    col_stats->part_name = partname->is_null ? CM_NULL_TEXT : partname->v_text;
    col_stats->is_single_part = partname->is_null ? CT_FALSE : CT_TRUE;

    /*
     * User name must be upper case
     * Table name and column name use upper case or original mode depending on system setting.
     */
    cm_text_upper(&col_stats->owner);
    process_name_case_sensitive(&col_stats->tabname);
    process_name_case_sensitive(&col_stats->colname);
    process_name_case_sensitive(&col_stats->part_name);

    return CT_SUCCESS;
}

/*
 * sql_mod_column_stats
 *
 * This function is used to set the stats of column
 * Syntax
 *
 * DBE-STATS.MODIFY_COLUMN_STATS (
 * ownname       VARCHAR2,
 * tabname       VARCHAR2,
 * colname       VARCHAR2,
 * partname      VARCHAR2  DEFAULT NULL,
 * stattab       VARCHAR2  DEFAULT NULL,
 * statid        VARCHAR2  DEFAULT NULL,
 * distcnt       NUMBER    DEFAULT NULL,
 * density       NUMBER    DEFAULT NULL,
 * nullcnt       NUMBER    DEFAULT NULL,
 * max_value     VARCHAR2  DEFAULT NULL,
 * min_value     VARCHAR2  DEFAULT NULL,
 * srec          STATREC   DEFAULT NULL,
 * avgclen       NUMBER    DEFAULT NULL,
 * flags         NUMBER    DEFAULT NULL,
 * statown       VARCHAR2  DEFAULT NULL,
 * no_invalidate BOOLEAN   DEFAULT NULL,
 * force         BOOLEAN   DEFAULT FALSE
 * );
 */
static status_t sql_mod_column_stats(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    knl_column_set_stats_t *col_stats = NULL;
    variant_t ownname, tabname, colname, partname, distcnt, density, nullcnt, force, max_val, min_val;
    status_t status = CT_ERROR;
    char buf[CT_NAME_BUFFER_SIZE];

    CM_POINTER3(stmt, func, result);
    CT_RETURN_IFERR(sql_check_trig_commit(stmt));

    CTSQL_SAVE_STACK(stmt);

    do {
        /* ownname */
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_mod_column_stats_params, 1, &ownname));
        /* the value kept will be released at the end of this function */
        sql_keep_stack_var(stmt, &ownname);
        CT_BREAK_IF_ERROR(sql_user_text_prefix_tenant(stmt->session, &ownname.v_text, buf, CT_NAME_BUFFER_SIZE));

        /* tabname */
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_mod_column_stats_params, 2, &tabname));
        sql_keep_stack_var(stmt, &tabname);

        /* colname */
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_mod_column_stats_params, 3, &colname));
        sql_keep_stack_var(stmt, &colname);

        /* partname */
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_mod_column_stats_params, 4, &partname));
        sql_keep_stack_var(stmt, &partname);

        /* distcnt */
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_mod_column_stats_params, 5, &distcnt));

        /* density */
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_mod_column_stats_params, 6, &density));

        /* nullcnt */
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_mod_column_stats_params, 7, &nullcnt));

        /* max_val */
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_mod_column_stats_params, 8, &max_val));
        sql_keep_stack_var(stmt, &max_val);

        /* min_val */
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_mod_column_stats_params, 9, &min_val));
        sql_keep_stack_var(stmt, &min_val);

        /* force */
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_mod_column_stats_params, 10, &force));

        CT_BREAK_IF_ERROR(sql_push(stmt, sizeof(knl_column_set_stats_t), (void **)&col_stats));
        col_stats->owner = ownname.v_text;
        col_stats->tabname = tabname.v_text;
        col_stats->colname = colname.v_text;

        CT_BREAK_IF_ERROR(sql_confirm_uint32_val(&distcnt, &col_stats->distnum));
        CT_BREAK_IF_ERROR(sql_confirm_double_val(&density, &col_stats->density));
        CT_BREAK_IF_ERROR(sql_confirm_uint32_val(&nullcnt, &col_stats->nullnum));

        sql_confirm_text_val(&min_val, &col_stats->min_value);
        sql_confirm_text_val(&max_val, &col_stats->max_value);
        col_stats->is_forced = force.is_null ? CT_FALSE : force.v_bool;

        if (sql_set_column_stats_value(col_stats, &partname) != CT_SUCCESS) {
            break;
        }

        /* check privilege */
        if (!sql_check_stats_priv(stmt->session, &col_stats->owner)) {
            CT_SRC_THROW_ERROR(func->loc, ERR_INSUFFICIENT_PRIV);
            break;
        }

        status = knl_set_columns_stats(KNL_SESSION(stmt), col_stats);
    } while (0);

    CTSQL_RESTORE_STACK(stmt);

    return status;
}

static status_t sql_verify_mod_column_stats(sql_verifier_t *verf, expr_node_t *func)
{
    if (sql_verify_func_node(verf, func, 3, sizeof(g_mod_column_stats_params) / sizeof(dbe_func_param_t),
        CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return sql_verify_dbe_func(verf, func, g_mod_column_stats_params,
        sizeof(g_mod_column_stats_params) / sizeof(dbe_func_param_t));
}

/*
 * sql_mod_index_stats
 *
 * This function is used to set the stats of index
 * Syntax
 *
 * DBE-STATS.MODIFY_INDEX_STATS (
 * ownname       VARCHAR2,
 * indname       VARCHAR2,
 * partname      VARCHAR2  DEFAULT NULL,
 * stattab       VARCHAR2  DEFAULT NULL,
 * statid        VARCHAR2  DEFAULT NULL,
 * numrows       NUMBER    DEFAULT NULL,
 * numlblks      NUMBER    DEFAULT NULL,
 * numdist       NUMBER    DEFAULT NULL,
 * avglblk       NUMBER    DEFAULT NULL,
 * avgdblk       NUMBER    DEFAULT NULL,
 * clstfct       NUMBER    DEFAULT NULL,
 * indlevel      NUMBER    DEFAULT NULL,
 * combndv2      NUMBER    DEFAULT NULL,
 * combndv3      NUMBER    DEFAULT NULL,
 * combndv4      NUMBER    DEFAULT NULL,
 * flags         NUMBER    DEFAULT NULL,
 * statown       VARCHAR2  DEFAULT NULL,
 * no_invalidate BOOLEAN   DEFAULT NULL,
 * guessq        NUMBER    DEFAULT NULL,
 * cachedblk     NUMBER    DEFAULT NULL,
 * cachehit      NUMBER    DEFUALT NULL,
 * force         BOOLEAN   DEFAULT FALSE
 * );
 */
static status_t sql_mod_index_stats(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    knl_index_set_stats_t *ind_stats = NULL;
    variant_t ownname, indname, partname, numlblks, numdist, avglblk, avgdblk, clstfct, indlevel, combndv2, combndv3,
        combndv4, force;
    status_t status = CT_ERROR;
    char buf[CT_NAME_BUFFER_SIZE];

    CM_POINTER3(stmt, func, result);
    CT_RETURN_IFERR(sql_check_trig_commit(stmt));

    CTSQL_SAVE_STACK(stmt);

    do {
        /* ownname */
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_set_index_stats_params, 1, &ownname));
        /* the value kept will be released at the end of this function */
        sql_keep_stack_var(stmt, &ownname);
        CT_BREAK_IF_ERROR(sql_user_text_prefix_tenant(stmt->session, &ownname.v_text, buf, CT_NAME_BUFFER_SIZE));

        /* indname */
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_set_index_stats_params, 2, &indname));
        sql_keep_stack_var(stmt, &indname);

        /* partname */
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_set_index_stats_params, 3, &partname));
        sql_keep_stack_var(stmt, &partname);

        /* numlblks */
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_set_index_stats_params, 4, &numlblks));

        /* numdist */
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_set_index_stats_params, 5, &numdist));

        /* avglblk */
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_set_index_stats_params, 6, &avglblk));

        /* avgdblk */
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_set_index_stats_params, 7, &avgdblk));

        /* clstfct */
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_set_index_stats_params, 8, &clstfct));

        /* indlevel */
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_set_index_stats_params, 9, &indlevel));

        /* combndv2 */
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_set_index_stats_params, 10, &combndv2));

        /* combndv3 */
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_set_index_stats_params, 11, &combndv3));

        /* combndv4 */
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_set_index_stats_params, 12, &combndv4));

        /* force */
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_set_index_stats_params, 13, &force));

        CT_BREAK_IF_ERROR(sql_push(stmt, sizeof(knl_index_set_stats_t), (void **)&ind_stats));

        ind_stats->owner = ownname.v_text;
        ind_stats->name = indname.v_text;

        CT_BREAK_IF_ERROR(sql_confirm_uint32_val(&numlblks, &ind_stats->numlblks));
        CT_BREAK_IF_ERROR(sql_confirm_uint32_val(&numdist, &ind_stats->numdist));
        CT_BREAK_IF_ERROR(sql_confirm_double_val(&avglblk, &ind_stats->avglblk));

        if (ind_stats->avglblk != CT_INVALID_ID64 && ind_stats->avglblk < 0) {
            // the index of avglblk in g_set_index_stats_params is 5
            CT_THROW_ERROR_EX(ERR_INVALID_FUNC_PARAMS, "%s can not be negative.", g_set_index_stats_params[5].name);
            break;
        }

        CT_BREAK_IF_ERROR(sql_confirm_double_val(&avgdblk, &ind_stats->avgdblk));

        if (ind_stats->avgdblk != CT_INVALID_ID64 && ind_stats->avgdblk < 0) {
            // the index of avgdblk in g_set_index_stats_params is 6
            CT_THROW_ERROR_EX(ERR_INVALID_FUNC_PARAMS, "%s can not be negative.", g_set_index_stats_params[6].name);
            break;
        }

        CT_BREAK_IF_ERROR(sql_confirm_uint32_val(&clstfct, &ind_stats->clstfct));
        CT_BREAK_IF_ERROR(sql_confirm_uint32_val(&indlevel, &ind_stats->indlevel));
        CT_BREAK_IF_ERROR(sql_confirm_uint32_val(&combndv2, &ind_stats->combndv2));
        CT_BREAK_IF_ERROR(sql_confirm_uint32_val(&combndv3, &ind_stats->combndv3));
        CT_BREAK_IF_ERROR(sql_confirm_uint32_val(&combndv4, &ind_stats->combndv4));

        ind_stats->part_name = partname.is_null ? CM_NULL_TEXT : partname.v_text;
        ind_stats->is_single_part = partname.is_null ? CT_FALSE : CT_TRUE;
        ind_stats->is_forced = force.is_null ? CT_FALSE : force.v_bool;

        /*
         * User name must be upper case
         * Index name use upper case or original mode depending on system setting.
         */
        cm_text_upper(&ind_stats->owner);
        process_name_case_sensitive(&ind_stats->name);
        process_name_case_sensitive(&ind_stats->part_name);

        /* check privilege */
        if (!sql_check_stats_priv(stmt->session, &ind_stats->owner)) {
            CT_SRC_THROW_ERROR(func->loc, ERR_INSUFFICIENT_PRIV);
            break;
        }

        status = knl_set_index_stats(KNL_SESSION(stmt), ind_stats);
    } while (0);

    CTSQL_RESTORE_STACK(stmt);

    return status;
}

static status_t sql_verify_mod_index_stats(sql_verifier_t *verf, expr_node_t *func)
{
    if (sql_verify_func_node(verf, func, 2, sizeof(g_set_index_stats_params) / sizeof(dbe_func_param_t),
        CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return sql_verify_dbe_func(verf, func, g_set_index_stats_params,
        sizeof(g_set_index_stats_params) / sizeof(dbe_func_param_t));
}

static status_t sql_set_table_stats_value(knl_table_set_stats_t *tab_stats, variant_t *partname)
{
    if (SECUREC_UNLIKELY(tab_stats == NULL || partname == NULL)) {
        return CT_ERROR;
    }

    /*
     * rownums is smaller than CT_MAX_INT32, so is samplesize.
     * the default value of tab_stats->samplesize is 0 without samplesize.
     */
    if (tab_stats->samplesize != CT_INVALID_ID64 && tab_stats->samplesize > CT_MAX_INT32) {
        CT_THROW_ERROR(ERR_TYPE_OVERFLOW, "samplesize");
        return CT_ERROR;
    }

    tab_stats->part_name = partname->is_null ? CM_NULL_TEXT : partname->v_text;
    tab_stats->is_single_part = partname->is_null ? CT_FALSE : CT_TRUE;

    /*
     * User name must be upper case
     * Table name use upper case or original mode depending on system setting.
     */
    cm_text_upper(&tab_stats->owner);
    process_name_case_sensitive(&tab_stats->name);
    process_name_case_sensitive(&tab_stats->part_name);

    return CT_SUCCESS;
}

/*
 * sql_mod_table_stats
 *
 * This function is used to set the stats of table
 * Syntax
 *
 * DBE-STATS.MODIFY_TABLE_STATS (
 * ownname       VARCHAR2,
 * tabname       VARCHAR2,
 * partname      VARCHAR2  DEFAULT NULL,
 * stattab       VARCHAR2  DEFAULT NULL,
 * statid        VARCHAR2  DEFAULT NULL,
 * numrows       NUMBER    DEFAULT NULL,
 * numblks       NUMBER    DEFAULT NULL,
 * avgrlen       NUMBER    DEFAULT NULL,
 * flags         NUMBER    DEFAULT NULL,
 * statown       VARCHAR2  DEFAULT NULL,
 * no_invalidate BOOLEAN   DEFAULT NULL,
 * cachedblk     NUMBER    DEFAULT NULL,
 * cachehit      NUMBER    DEFUALT NULL,
 * samplesize    NUMBER    DEFUALT NULL,
 * force         BOOLEAN   DEFAULT FALSE,
 * );
 */
static status_t sql_mod_table_stats(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    knl_table_set_stats_t *tab_stats = NULL;
    variant_t ownname, tabname, partname, numrows, numblks, avgrlen, force, samplesize;
    status_t status = CT_ERROR;
    char buf[CT_NAME_BUFFER_SIZE];

    CM_POINTER3(stmt, func, result);
    CT_RETURN_IFERR(sql_check_trig_commit(stmt));

    CTSQL_SAVE_STACK(stmt);

    do {
        /* ownname */
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_set_table_stats_params, 1, &ownname));
        /* the value kept will be released at the end of this function */
        sql_keep_stack_var(stmt, &ownname);
        CT_BREAK_IF_ERROR(sql_user_text_prefix_tenant(stmt->session, &ownname.v_text, buf, CT_NAME_BUFFER_SIZE));

        /* tabname */
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_set_table_stats_params, 2, &tabname));
        sql_keep_stack_var(stmt, &tabname);

        /* partname */
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_set_table_stats_params, 3, &partname));
        sql_keep_stack_var(stmt, &partname);

        /* numrows */
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_set_table_stats_params, 4, &numrows));

        /* numblks */
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_set_table_stats_params, 5, &numblks));

        /* avgrlen */
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_set_table_stats_params, 6, &avgrlen));

        /* samplesize */
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_set_table_stats_params, 7, &samplesize));

        /* force */
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_set_table_stats_params, 8, &force));

        CT_BREAK_IF_ERROR(sql_push(stmt, sizeof(knl_table_set_stats_t), (void **)&tab_stats));
        tab_stats->owner = ownname.v_text;
        tab_stats->name = tabname.v_text;

        CT_BREAK_IF_ERROR(sql_confirm_uint32_val(&numrows, &tab_stats->rownums));
        CT_BREAK_IF_ERROR(sql_confirm_uint32_val(&numblks, &tab_stats->blknums));
        CT_BREAK_IF_ERROR(sql_confirm_uint64_val(&avgrlen, &tab_stats->avgrlen));
        CT_BREAK_IF_ERROR(sql_confirm_uint64_val(&samplesize, &tab_stats->samplesize));

        tab_stats->is_forced = force.is_null ? CT_FALSE : force.v_bool;

        if (sql_set_table_stats_value(tab_stats, &partname) != CT_SUCCESS) {
            break;
        }

        /* check privilege */
        if (!sql_check_stats_priv(stmt->session, &tab_stats->owner)) {
            CT_SRC_THROW_ERROR(func->loc, ERR_INSUFFICIENT_PRIV);
            break;
        }

        status = knl_set_table_stats(KNL_SESSION(stmt), tab_stats);
    } while (0);

    CTSQL_RESTORE_STACK(stmt);

    return status;
}

static status_t sql_verify_mod_table_stats(sql_verifier_t *verf, expr_node_t *func)
{
    if (sql_verify_func_node(verf, func, 2, sizeof(g_set_table_stats_params) / sizeof(dbe_func_param_t),
        CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return sql_verify_dbe_func(verf, func, g_set_table_stats_params,
        sizeof(g_set_table_stats_params) / sizeof(dbe_func_param_t));
}

/*
 * This function is used to lock the stats of table
 */
static status_t sql_lock_table_stats(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    knl_dictionary_t dc;
    variant_t ownname, tabname;
    text_t owner, table_name;
    status_t status = CT_ERROR;
    char buf[CT_NAME_BUFFER_SIZE];

    CM_POINTER3(stmt, func, result);
    CT_RETURN_IFERR(sql_check_trig_commit(stmt));

    CTSQL_SAVE_STACK(stmt);

    do {
        /* ownname */
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_lock_table_stats_params, 1, &ownname));
        /* the value kept will be released at the end of this function */
        sql_keep_stack_var(stmt, &ownname);
        CT_BREAK_IF_ERROR(sql_user_text_prefix_tenant(stmt->session, &ownname.v_text, buf, CT_NAME_BUFFER_SIZE));

        /* tabname */
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_lock_table_stats_params, 2, &tabname));
        sql_keep_stack_var(stmt, &tabname);

        owner = ownname.v_text;
        table_name = tabname.v_text;

        /*
         * User name must be upper case
         * Table name use upper case or original mode depending on system setting.
         */
        cm_text_upper(&owner);
        process_name_case_sensitive(&table_name);

        /* check privilege */
        if (!sql_check_stats_priv(stmt->session, &owner)) {
            CT_SRC_THROW_ERROR(func->loc, ERR_INSUFFICIENT_PRIV);
            break;
        }

        CT_BREAK_IF_ERROR(knl_open_dc(KNL_SESSION(stmt), &owner, &table_name, &dc));

        status = knl_lock_table_stats(KNL_SESSION(stmt), &dc);
        knl_close_dc(&dc);
    } while (0);

    CTSQL_RESTORE_STACK(stmt);

    return status;
}

static status_t sql_verify_lock_table_stats(sql_verifier_t *verf, expr_node_t *func)
{
    if (sql_verify_func_node(verf, func, 2, 2, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return sql_verify_dbe_func(verf, func, g_lock_table_stats_params,
        sizeof(g_lock_table_stats_params) / sizeof(dbe_func_param_t));
}

/* This function is used to unlock the stats of table */
static status_t sql_unlock_table_stats(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    knl_dictionary_t dc;
    variant_t ownname, tabname;
    text_t owner, table_name;
    status_t status = CT_ERROR;
    char buf[CT_NAME_BUFFER_SIZE];

    CM_POINTER3(stmt, func, result);
    CT_RETURN_IFERR(sql_check_trig_commit(stmt));

    CTSQL_SAVE_STACK(stmt);

    do {
        /* ownname */
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_unlock_table_stats_params, 1, &ownname));
        /* the value kept will be released at the end of this function */
        CT_BREAK_IF_ERROR(sql_user_text_prefix_tenant(stmt->session, &ownname.v_text, buf, CT_NAME_BUFFER_SIZE));

        /* tabname */
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_unlock_table_stats_params, 2, &tabname));
        sql_keep_stack_var(stmt, &tabname);

        owner = ownname.v_text;
        table_name = tabname.v_text;

        /*
         * User name must be upper case
         * Table name use upper case or original mode depending on system setting.
         */
        cm_text_upper(&owner);
        process_name_case_sensitive(&table_name);

        /* check privilege */
        if (!sql_check_stats_priv(stmt->session, &owner)) {
            CT_SRC_THROW_ERROR(func->loc, ERR_INSUFFICIENT_PRIV);
            break;
        }

        CT_BREAK_IF_ERROR(knl_open_dc(KNL_SESSION(stmt), &owner, &table_name, &dc));
        status = knl_unlock_table_stats(KNL_SESSION(stmt), &dc);

        knl_close_dc(&dc);
    } while (0);

    CTSQL_RESTORE_STACK(stmt);

    return status;
}

static status_t sql_verify_unlock_table_stats(sql_verifier_t *verf, expr_node_t *func)
{
    if (sql_verify_func_node(verf, func, 2, 2, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return sql_verify_dbe_func(verf, func, g_unlock_table_stats_params,
        sizeof(g_unlock_table_stats_params) / sizeof(dbe_func_param_t));
}

/*
 * FLUSH_DB_STATS_INFO Procedure
 * Syntax:
 *
 * DBE_STATS.FLUSH_DB_STATS_INFO;
 */
static status_t sql_flush_db_stats_info(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    CT_RETURN_IFERR(sql_check_trig_commit(stmt));

    /* Current user should be dba or has analyze_any privilage */
    if (!sql_user_is_dba(stmt->session) &&
        !knl_check_sys_priv_by_uid(KNL_SESSION(stmt), stmt->session->knl_session.uid, ANALYZE_ANY)) {
        CT_SRC_THROW_ERROR(func->loc, ERR_INSUFFICIENT_PRIV);
        return CT_ERROR;
    }

    return knl_flush_table_monitor(KNL_SESSION(stmt));
}

static status_t sql_verify_flush_db_stats_info(sql_verifier_t *verf, expr_node_t *func)
{
    if (func->argument != NULL) {
        CT_THROW_ERROR(ERR_INVALID_FUNC_PARAMS, "function FLUSH_DB_STATS_INFO doesn't support argument.");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

/*
 * sql_purge_stats
 *
 * This function is used to purge the stats before given time.
 *
 */
static status_t sql_purge_stats(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t before_time;

    CM_POINTER3(stmt, func, result);
    CT_RETURN_IFERR(sql_check_trig_commit(stmt));

    CT_RETURN_IFERR(sql_get_dbe_param_value(stmt, func, g_purge_stats_params, 1, &before_time));

    /* Current user should be dba */
    if (!sql_user_is_dba(stmt->session)) {
        CT_SRC_THROW_ERROR(func->loc, ERR_INSUFFICIENT_PRIV);
        return CT_ERROR;
    }

    return knl_purge_stats(&stmt->session->knl_session, (int64)before_time.v_tstamp);
}

static status_t sql_verify_purge_stats(sql_verifier_t *verf, expr_node_t *func)
{
    if (sql_verify_func_node(verf, func, 1, 1, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return sql_verify_dbe_func(verf, func, g_purge_stats_params,
        sizeof(g_purge_stats_params) / sizeof(dbe_func_param_t));
}

/*
 * func format_error_backtrace
 *
 * This function return error backtrace
 */
static status_t sql_func_get_error_backtrace(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    pl_exec_exception_t *curr_except = NULL;
    pl_executor_t *exec = (pl_executor_t *)stmt->pl_exec;

    result->type = CT_TYPE_STRING;
    result->is_null = CT_FALSE;

    if (sql_is_pl_exec(stmt) != CT_TRUE || (ple_get_curr_except(exec, &curr_except) == CT_FALSE) ||
        (curr_except->has_exception == CT_FALSE)) {
        result->is_null = CT_TRUE;
        return CT_SUCCESS;
    }

    result->v_text.len = exec->err_stack_pos;
    result->v_text.str = exec->err_stack;

    return CT_SUCCESS;
}

static status_t sql_verify_get_error_backtrace(sql_verifier_t *verf, expr_node_t *func)
{
    if (sql_verify_func_node(verf, func, 0, 0, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    func->datatype = CT_TYPE_STRING;
    return CT_SUCCESS;
}

/*
 * sql_func_get_time
 *
 * This function returns the current time in 100th's of a second.
 */
static status_t sql_func_get_time(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    struct timeval curr_time;

    result->type = CT_TYPE_BIGINT;
    result->is_null = CT_FALSE;

    (void)cm_gettimeofday(&curr_time);
    result->v_bigint = (int64)curr_time.tv_sec * 100 + (int64)curr_time.tv_usec / 10000;

    return CT_SUCCESS;
}

static status_t sql_verify_get_time(sql_verifier_t *verf, expr_node_t *func)
{
    if (sql_verify_func_node(verf, func, 0, 0, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    func->datatype = CT_TYPE_BIGINT;
    return CT_SUCCESS;
}

static status_t sql_func_lob_getlength(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    return sql_func_length_core(stmt, func, result, CT_TRUE);
}

/*
 * sql_func_substr
 *
 * This function is used to realize DBE_LOB.SUBSTR.
 */
static status_t sql_func_lob_substr(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t var1, var2, var3;
    char *buf = NULL;
    uint32 substr_len = 0;
    uint32 offset = 1;
    bool32 is_bin = CT_FALSE;
    status_t ret = CT_ERROR;

    CM_POINTER3(stmt, func, result);

    CTSQL_SAVE_STACK(stmt);

    result->type = CT_TYPE_STRING;

    expr_tree_t *arg1 = func->argument;
    CM_POINTER(arg1);
    SQL_EXEC_FUNC_ARG_EX(arg1, &var1, result);

    if (sql_verify_lob_func_args(var1.type) != CT_TRUE) {
        CT_SRC_THROW_ERROR(arg1->root->loc, ERR_UNSUPPORT_DATATYPE, get_datatype_name_str(var1.type));
        return CT_ERROR;
    }

    is_bin = CT_IS_BLOB_TYPE(var1.type) || CT_IS_BINARY_TYPE(var1.type) || CT_IS_RAW_TYPE(var1.type);

    do {
        /* the value kept will be release at the end of this function */
        sql_keep_stack_variant(stmt, &var1);
        CT_BREAK_IF_ERROR(sql_var_as_string(stmt, &var1));

        if (var1.v_text.len == 0 && g_instance->sql.enable_empty_string_null) {
            SQL_SET_NULL_VAR(result);
            CTSQL_RESTORE_STACK(stmt);
            return CT_SUCCESS;
        }

        result->is_null = CT_FALSE;

        expr_tree_t *arg2 = arg1->next;
        if (arg2 != NULL) {
            SQL_EXEC_FUNC_ARG_EX(arg2, &var2, result);
            CT_BREAK_IF_ERROR(var_as_floor_integer(&var2));

            if (var2.v_int <= 0) {
                result->v_text.len = 0;
                result->is_null = g_instance->sql.enable_empty_string_null;
                CTSQL_RESTORE_STACK(stmt);
                return CT_SUCCESS;
            }

            substr_len = (is_bin) ? ((uint32)var2.v_int * 2) : ((uint32)var2.v_int);

            expr_tree_t *arg3 = arg2->next;
            if (arg3 != NULL) {
                SQL_EXEC_FUNC_ARG_EX(arg3, &var3, result);
                CT_BREAK_IF_ERROR(var_as_floor_integer(&var3));

                if (var3.v_int <= 0) {
                    result->v_text.len = 0;
                    result->is_null = g_instance->sql.enable_empty_string_null;
                    CTSQL_RESTORE_STACK(stmt);
                    return CT_SUCCESS;
                }

                offset = (is_bin) ? ((uint32)var3.v_int * 2 - 1) : ((uint32)var3.v_int);
            }
        } else {
            substr_len = var1.v_text.len;
        }

        CT_BREAK_IF_ERROR(sql_push(stmt, substr_len + 1, (void **)&buf));

        result->v_text.str = buf;
        result->v_text.len = 0;

        ret = GET_DATABASE_CHARSET->substr_left(&var1.v_text, offset, substr_len, &result->v_text);
        if (ret == CT_ERROR) {
            SQL_SET_NULL_VAR(result);
            CTSQL_RESTORE_STACK(stmt);
            return CT_SUCCESS;
        }

        if (result->v_text.len == 0 && g_instance->sql.enable_empty_string_null) {
            SQL_SET_NULL_VAR(result);
        }

        ret = CT_SUCCESS;
    } while (0);

    CTSQL_RESTORE_STACK(stmt);

    return ret;
}

static status_t sql_verify_lob_getlength(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 1, 1, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    func->datatype = CT_TYPE_BIGINT;
    func->size = cm_get_datatype_strlen(func->argument->root->datatype, func->argument->root->size);

    return CT_SUCCESS;
}

static status_t sql_verify_lob_substr(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 1, 3, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    func->datatype = CT_TYPE_STRING;
    func->size = cm_get_datatype_strlen(func->argument->root->datatype, func->argument->root->size);

    return CT_SUCCESS;
}

static inline void reset_cursor_before_return(sql_stmt_t *stmt, sql_stmt_t *cursor_stmt)
{
    cursor_stmt->cursor_info.is_returned = CT_TRUE;
    cursor_stmt->cursor_info.rrs_sn = stmt->session->rrs_sn;
    cursor_stmt->is_sub_stmt = CT_FALSE;
    cursor_stmt->parent_stmt = NULL;
    cursor_stmt->pl_ref_entry = NULL;
}

/*
 * sql_func_return_cursor
 *
 * This procedure returns the result of an executed statement to the client application.
 * syntax:
 * PROCEDURE RETURN_RESULT (rc IN OUT SYS_REFCURSOR, to_client IN BOOLEAN DEFAULT TRUE);
 *
 */
static status_t sql_func_return_cursor(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    expr_tree_t *arg1 = NULL;
    expr_tree_t *arg2 = NULL;
    variant_t var_cursor;
    variant_t var_to_client;
    sql_stmt_t *sub_stmt = NULL;
    pl_cursor_slot_t *ref_cursor = NULL;
    pl_executor_t *exec = (pl_executor_t *)stmt->pl_exec;

    if (stmt->plsql_mode == PLSQL_DYNBLK) {
        CT_SRC_THROW_ERROR(func->argument->root->loc, ERR_ILEGAL_RETURN_RESULT);
        return CT_ERROR;
    }
    if (sql_is_pl_func(stmt) == CT_TRUE) {
        CT_SRC_THROW_ERROR(func->argument->root->loc, ERR_ILEGAL_RETURN_RESULT);
        return CT_ERROR;
    }

    arg1 = func->argument;
    if (sql_exec_expr_node(stmt, arg1->root, &var_cursor) != CT_SUCCESS) {
        CT_SRC_THROW_ERROR(func->argument->root->loc, ERR_INVALID_FUNC_PARAMS, "invalid cursor");
        return CT_ERROR;
    }

    if (var_cursor.type != CT_TYPE_CURSOR) {
        CT_SRC_THROW_ERROR(func->argument->root->loc, ERR_INVALID_FUNC_PARAMS, "invalid cursor");
        return CT_ERROR;
    }

    if (exec != NULL && exec->entity->is_auton_trans) {
        CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "in autonomous transaction pl,return result is not supported");
        return CT_ERROR;
    }

    sub_stmt = ple_ref_cursor_get(stmt, var_cursor.v_cursor.ref_cursor);
    if (sub_stmt == NULL || (sub_stmt->cursor_info.has_fetched && sub_stmt->eof)) {
        CT_SRC_THROW_ERROR(func->argument->root->loc, ERR_INVALID_CURSOR);
        return CT_ERROR;
    }

    /* the to_client flag should be NULL or CT_TRUE */
    arg2 = arg1->next;
    if (arg2 != NULL) {
        if (sql_exec_expr_node(stmt, arg2->root, &var_to_client) != CT_SUCCESS) {
            CT_SRC_THROW_ERROR(func->argument->root->loc, ERR_INVALID_FUNC_PARAMS, "error flag");
            return CT_ERROR;
        }
        if (!var_to_client.is_null) {
            if (var_as_bool(&var_to_client) != CT_SUCCESS) {
                CT_SRC_THROW_ERROR(func->argument->root->loc, ERR_INVALID_FUNC_PARAMS, "error flag");
                return CT_ERROR;
            }
            if (var_to_client.v_bool == CT_FALSE) {
                CT_SRC_THROW_ERROR(func->argument->root->loc, ERR_CAPABILITY_NOT_SUPPORT, "client flag ct_false");
                return CT_ERROR;
            }
        }
    }

    if (sub_stmt->cursor_info.param_buf == NULL && var_cursor.v_cursor.input != NULL) {
        if (ple_keep_input(sub_stmt, stmt->pl_exec, (void *)var_cursor.v_cursor.input,
            ((pl_executor_t *)stmt->pl_exec)->is_dyncur) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    /* send to client */
    reset_cursor_before_return(stmt, sub_stmt);

    ref_cursor = (pl_cursor_slot_t *)var_cursor.v_cursor.ref_cursor;
    ref_cursor->stmt_id = CT_INVALID_ID16;
    // no need to free cursor until stack pop
    return pl_sender->send_return_result(stmt, sub_stmt->id);
}

static status_t sql_verify_return_cursor(sql_verifier_t *verf, expr_node_t *func)
{
    expr_node_t *first_node = NULL;
    plv_decl_t *decl = NULL;
    pl_compiler_t *compiler = (pl_compiler_t *)verf->stmt->pl_compiler;

    if (compiler == NULL || (compiler->type != PL_PROCEDURE && compiler->type != PL_ANONYMOUS_BLOCK)) {
        CT_SRC_THROW_ERROR(func->loc, ERR_ILEGAL_RETURN_RESULT);
        return CT_ERROR;
    }

    if (sql_verify_func_node(verf, func, 1, 2, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    first_node = func->argument->root;

    if (first_node->type != EXPR_NODE_V_ADDR) {
        CT_SRC_THROW_ERROR(first_node->loc, ERR_PL_SYNTAX_ERROR_FMT, "1st argu type must be sys_refcursor");
        return CT_ERROR;
    }
    var_address_pair_t *pair = sql_get_last_addr_pair(first_node);
    if (pair == NULL || pair->type != UDT_STACK_ADDR) {
        CT_SRC_THROW_ERROR(first_node->loc, ERR_PL_SYNTAX_ERROR_FMT, "1st argu type must be sys_refcursor");
        return CT_ERROR;
    }

    decl = pair->stack->decl;
    if (decl == NULL) {
        CT_SRC_THROW_ERROR(first_node->loc, ERR_PL_SYNTAX_ERROR_FMT, "unexpected pl-variant occurs");
        return CT_ERROR;
    }
    bool32 verf_flag = (decl->type & PLV_CUR) && (decl->cursor.ctx != NULL) && (decl->cursor.ctx->is_sysref == CT_TRUE);
    if (verf_flag == CT_FALSE) {
        CT_SRC_THROW_ERROR(first_node->loc, ERR_PL_SYNTAX_ERROR_FMT, "1st argu type must be sys_refcursor");
        return CT_ERROR;
    }

    func->datatype = CT_TYPE_INTEGER;
    func->size = sizeof(uint32);

    return CT_SUCCESS;
}

static status_t sql_verify_compile_schema(sql_verifier_t *verf, expr_node_t *func)
{
    /* check the number of the argument */
    if (sql_verify_func_node(verf, func, 1, 2, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return sql_verify_dbe_func(verf, func, g_compile_schema_params,
        sizeof(g_compile_schema_params) / sizeof(dbe_func_param_t));
}

static status_t sql_compile_object_by_user(sql_stmt_t *stmt, text_t *schema_name, bool32 compile_all)
{
    /* compile pl object */
    CT_RETURN_IFERR(pl_compile_by_user(stmt, schema_name, compile_all));

    /* compile synonym object */
    CT_RETURN_IFERR(sql_compile_synonym_by_user(stmt, schema_name, compile_all));

    /* compile view object */
    CT_RETURN_IFERR(sql_compile_view_by_user(stmt, schema_name, compile_all));

    return CT_SUCCESS;
}

/*
 * sql_func_compile_schema
 *
 * compile the objects of specified schema.
 * syntax:
 * Syntax
 * DBE_UTIL.COMPILE_SCHEMA ( *   schema          IN VARCHAR2,
 * compile_all     IN BOOLEAN DEFAULT TRUE,
 * reuse_settings  IN BOOLEAN DEFAULT FALSE);
 */
static status_t sql_func_compile_schema(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t name, flag;
    status_t status;
    char buf[CT_NAME_BUFFER_SIZE];

    CM_POINTER3(stmt, func, result);
    CT_RETURN_IFERR(sql_check_trig_commit(stmt));

    CTSQL_SAVE_STACK(stmt);

    /* schema */
    if (sql_get_dbe_param_value(stmt, func, g_compile_schema_params, 1, &name) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }

    /* the value kept will be release at the end of this function */
    sql_keep_stack_var(stmt, &name);
    if (sql_user_text_prefix_tenant(stmt->session, &name.v_text, buf, CT_NAME_BUFFER_SIZE) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }

    /* compile_all */
    if (sql_get_dbe_param_value(stmt, func, g_compile_schema_params, 2, &flag) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }

    /* User name must be upper case.  */
    cm_text_upper(&name.v_text);

    if (flag.is_null) {
        flag.is_null = CT_FALSE;
        flag.v_bool = CT_TRUE;
    }
    if (cm_text_str_equal_ins(&name.v_text, SYS_USER_NAME)) {
        if (!cm_text_str_equal_ins(&stmt->session->curr_user, SYS_USER_NAME)) {
            CT_SRC_THROW_ERROR(func->loc, ERR_RECOMPILE_SYS_OBJECTS);
            CTSQL_RESTORE_STACK(stmt);
            return CT_ERROR;
        }
    }

    /* Schema only can be compiled by dba or itself. */
    if (!sql_check_schema_priv(stmt->session, &name.v_text)) {
        CT_SRC_THROW_ERROR(func->loc, ERR_INSUFFICIENT_PRIV);
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }

    SQL_SET_NULL_VAR(result);

    status = sql_compile_object_by_user(stmt, &name.v_text, flag.v_bool);
    CTSQL_RESTORE_STACK(stmt);

    return status;
}

/*
 * This procedure sets the broken flag. Broken jobs are never run.
 *
 * Syntax:
 * DBE_TASK.SUSPEND ( * job       IN  BINARY_INTEGER,
 * broken    IN  BOOLEAN,  true: broken, false:not broken
 * next_date IN  DATE DEFAULT SYSDATE);
 *
 * NOTE:
 * If the broken is true, the next_date will be ignored.
 */
static status_t sql_task_suspend(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    CM_POINTER3(stmt, func, result);
    variant_t jobno, broken_flag, next_date;
    knl_job_node_t job_info;
    pl_executor_t *exec = stmt->pl_exec;

    if (exec == NULL) {
        CT_SRC_THROW_ERROR(func->argument->root->loc, ERR_SQL_SYNTAX_ERROR,
            "DBE_TASK.SUSPEND can only be used in plsql");
        return CT_ERROR;
    }

    SQL_SET_NULL_VAR(result);

    /* job number */
    CT_RETURN_IFERR(sql_get_dbe_param_value(stmt, func, g_suspend_job_params, 1, &jobno));
    CT_RETURN_IFERR(var_as_bigint(&jobno));

    /* broken flag */
    CT_RETURN_IFERR(sql_get_dbe_param_value(stmt, func, g_suspend_job_params, 2, &broken_flag));

    /* next date */
    CT_RETURN_IFERR(sql_get_dbe_param_value(stmt, func, g_suspend_job_params, 3, &next_date));
    if (next_date.is_null) {
        next_date.is_null = CT_FALSE;
        next_date.type = CT_TYPE_DATE;
        next_date.v_bigint = cm_now();
    }

    job_info.node_type = JOB_TYPE_BROKEN;
    job_info.job_id = jobno.v_bigint;
    job_info.is_broken = broken_flag.v_bool;
    job_info.next_date = next_date.v_bigint;

    return knl_update_job(KNL_SESSION(stmt), &stmt->session->curr_user, &job_info, CT_TRUE);
}

static status_t sql_verify_task_suspend(sql_verifier_t *verf, expr_node_t *func)
{
    /* check the number of the argument */
    if (sql_verify_func_node(verf, func, 2, 3, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return sql_verify_dbe_func(verf, func, g_suspend_job_params,
        sizeof(g_suspend_job_params) / sizeof(dbe_func_param_t));
}

/*
 * sql_job_cancel
 *
 * This procedure removes an existing job from the job queue.This currently does not stop a running job.
 * Syntax:
 * DBE_TASK.CANCEL (job       IN  BINARY_INTEGER);
 */
static status_t sql_job_cancel(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    CM_POINTER3(stmt, func, result);
    variant_t jobno;
    pl_executor_t *exec = stmt->pl_exec;

    if (exec == NULL) {
        CT_SRC_THROW_ERROR(func->argument->root->loc, ERR_SQL_SYNTAX_ERROR,
            "DBE_TASK.CANCEL can only be used in plsql");
        return CT_ERROR;
    }

    SQL_SET_NULL_VAR(result);

    /* job number */
    CT_RETURN_IFERR(sql_get_dbe_param_value(stmt, func, g_cancel_task_params, 1, &jobno));
    CT_RETURN_IFERR(var_as_bigint(&jobno));

    return knl_delete_job(KNL_SESSION(stmt), &stmt->session->curr_user, jobno.v_bigint, CT_TRUE);
}

static status_t sql_verify_job_cancel(sql_verifier_t *verf, expr_node_t *func)
{
    /* check the number of the argument */
    if (sql_verify_func_node(verf, func, 1, 1, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return sql_verify_dbe_func(verf, func, g_cancel_task_params,
        sizeof(g_cancel_task_params) / sizeof(dbe_func_param_t));
}

/*
 * sql_task_run
 *
 * This procedure runs job JOB now.It runs it even if it is broken.
 * Running the job recomputes next_date.
 * Syntax:
 * DBE_TASK.RUN ( *    job       IN  BINARY_INTEGER,
 * force     IN  BOOLEAN DEFAULT FALSE  // not effective
 * );
 */
static status_t sql_task_run(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    CM_POINTER3(stmt, func, result);
    variant_t jobno, force_flag;
    knl_job_node_t job_info;
    pl_executor_t *exec = stmt->pl_exec;

    SQL_SET_NULL_VAR(result);

    if (exec == NULL) {
        CT_SRC_THROW_ERROR(func->argument->root->loc, ERR_SQL_SYNTAX_ERROR, "DBE_TASK.RUN can only be used in plsql");
        return CT_ERROR;
    }

    /* job number */
    CT_RETURN_IFERR(sql_get_dbe_param_value(stmt, func, g_run_task_params, 1, &jobno));
    CT_RETURN_IFERR(var_as_bigint(&jobno));

    /* force flag */
    CT_RETURN_IFERR(sql_get_dbe_param_value(stmt, func, g_run_task_params, 2, &force_flag));

    job_info.node_type = JOB_TYPE_RUN;
    job_info.job_id = jobno.v_bigint;
    job_info.next_date = cm_now();

    return knl_update_job(KNL_SESSION(stmt), &stmt->session->curr_user, &job_info, CT_TRUE);
}

static status_t sql_verify_task_run(sql_verifier_t *verf, expr_node_t *func)
{
    /* check the number of the argument */
    if (sql_verify_func_node(verf, func, 1, 2, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return sql_verify_dbe_func(verf, func, g_run_task_params, sizeof(g_run_task_params) / sizeof(dbe_func_param_t));
}

status_t sql_alloc_task_id(sql_stmt_t *stmt, int64 *id)
{
    text_t name;
    text_t sys = {
        .str = SYS_USER_NAME,
        .len = 3
    };
    cm_str2text("JOBSEQ", &name);

    CT_RETURN_IFERR(knl_seq_nextval(stmt->session, &sys, &name, id));

    if (*id == CT_INVALID_INT64) {
        CT_THROW_ERROR(ERR_JOB_UNSUPPORT, "ID reach the maximum value");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

/*
 * transform this sql to plsql block
 */
#define BEGIN_PREFIX 6
#define END_SUFFIX 5

bool32 sql_transform_task_content(char *dest, uint32 max_dest, const char *src, uint32 temp_src_len)
{
    uint32 buf_len;
    uint32 src_len = temp_src_len;
    errno_t errcode;

    /* check begin ...end exists or not */
    if (src_len <= BEGIN_PREFIX || (src_len > BEGIN_PREFIX && cm_strcmpni(src, "BEGIN ", BEGIN_PREFIX)) != 0) {
        errcode = memcpy_s(dest, max_dest, "BEGIN ", BEGIN_PREFIX);
        if (errcode != EOK) {
            return CT_FALSE;
        }
        buf_len = max_dest - BEGIN_PREFIX;
        errcode = memcpy_s(dest + BEGIN_PREFIX, buf_len, src, src_len);
        if (errcode != EOK) {
            return CT_FALSE;
        }
        buf_len = buf_len - src_len;
        errcode = memcpy_s(dest + BEGIN_PREFIX + src_len, buf_len, " END;", END_SUFFIX);
        if (errcode != EOK) {
            return CT_FALSE;
        }
        src_len = src_len + END_SUFFIX + BEGIN_PREFIX;
        dest[src_len] = '\0';
        return CT_TRUE;
    }

    return CT_FALSE;
}

status_t sql_parse_job_what(sql_stmt_t *stmt, text_t *sql, source_location_t *location)
{
    char what[WHAT_BUFFER_LENGTH];
    text_t what_txt;
    char *ptr = sql->str;
    uint32 len = sql->len;

    if (sql_transform_task_content(what, WHAT_BUFFER_LENGTH, ptr, len)) {
        what_txt.str = what;
        what_txt.len = (uint32)strlen(what);
    } else {
        what_txt = *sql;
    }

    return sql_parse_job(stmt, &what_txt, location);
}

static status_t sql_parse_job_interval(sql_stmt_t *stmt, knl_job_def_t *def, date_t now_date, source_location_t *loc)
{
    expr_tree_t *inter_calc_expr = NULL;
    sql_text_t sql_interval;
    variant_t var;

    /* verify interval */
    if (def->interval.len > 0) {
        sql_verifier_t verf = { 0 };
        sql_interval.value = def->interval;
        sql_interval.loc = *loc;
        stmt->session->lex->flags = LEX_WITH_OWNER | LEX_WITH_ARG;
        if (CT_SUCCESS != sql_create_expr_from_text(stmt, &sql_interval, &inter_calc_expr, WORD_FLAG_NONE)) {
            return CT_ERROR;
        }

        verf.stmt = stmt;
        verf.context = stmt->context;
        if (sql_verify_expr(&verf, inter_calc_expr) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (CT_SUCCESS != sql_task_get_nextdate(stmt, inter_calc_expr->root, &var)) {
            CT_SRC_THROW_ERROR(*loc, ERR_INVALID_EXPRESSION);
            return CT_ERROR;
        }

        if (var.v_bigint <= now_date) {
            CT_THROW_ERROR(ERR_INTERVAL_TOO_EARLY);
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t sql_get_job_interval(sql_stmt_t *stmt, expr_node_t *func, knl_job_def_t *def)
{
    variant_t interval;

    CT_RETURN_IFERR(sql_get_dbe_param_value(stmt, func, g_submit_task_params, 4, &interval));
    if (interval.is_null) {
        def->interval = CM_NULL_TEXT;
    } else {
        if (interval.v_text.len < 1 || interval.v_text.len > MAX_LENGTH_INTERVAL) {
            CT_SRC_THROW_ERROR(func->argument->root->loc, ERR_INVALID_FUNC_PARAMS,
                "error interval for DBE_TASK.SUBMIT");
            return CT_ERROR;
        }

        /* the value kept will be release at the end of sql_task_submit */
        sql_keep_stack_var(stmt, &interval);

        def->interval = interval.v_text;
    }

    return CT_SUCCESS;
}

static status_t sql_get_job_what(sql_stmt_t *stmt, expr_node_t *func, knl_job_def_t *def)
{
    variant_t what;

    CT_RETURN_IFERR(sql_get_dbe_param_value(stmt, func, g_submit_task_params, 2, &what));

    if (what.is_null || what.v_text.len < 1 || what.v_text.len > MAX_LENGTH_WHAT) {
        CT_SRC_THROW_ERROR(func->argument->root->loc, ERR_INVALID_FUNC_PARAMS, "error what for DBE_TASK.SUBMIT");
        return CT_ERROR;
    }

    /* the value kept will be release at the end of sql_task_submit */
    sql_keep_stack_var(stmt, &what);
    def->what = what.v_text;

    return CT_SUCCESS;
}

/*
 * verify the job' what and interval is valid or not
 */
static status_t sql_check_job_valid(sql_stmt_t *stmt, knl_job_def_t *def, date_t now_date, expr_node_t *func)
{
    sql_stmt_t *sub_stmt = NULL;
    status_t status;

    CTSQL_SAVE_STACK(stmt);

    if (sql_push(stmt, sizeof(sql_stmt_t), (void **)&sub_stmt) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }

    errno_t err = memset_s(sub_stmt, sizeof(sql_stmt_t), 0, sizeof(sql_stmt_t));
    if (err != EOK) {
        CTSQL_RESTORE_STACK(stmt);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return CT_ERROR;
    }
    sql_init_stmt(stmt->session, sub_stmt, stmt->id);
    sub_stmt->is_srvoutput_on = stmt->is_srvoutput_on;
    sub_stmt->is_sub_stmt = CT_TRUE;
    sub_stmt->pl_ref_entry = stmt->pl_ref_entry;
    sub_stmt->parent_stmt = stmt;
    sub_stmt->cursor_info.type = PL_FORK_CURSOR;

    if (sql_alloc_context(sub_stmt) != CT_SUCCESS) {
        sql_free_stmt(sub_stmt);
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }

    /* parse interval */
    if (sql_parse_job_interval(sub_stmt, def, now_date, &func->argument->root->loc) != CT_SUCCESS) {
        sql_free_stmt(sub_stmt);
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }

    /* parse what */
    sub_stmt->session->lex->flags = LEX_WITH_OWNER | LEX_WITH_ARG;
    status = sql_parse_job_what(sub_stmt, &def->what, &func->argument->root->loc);
    sql_free_stmt(sub_stmt);
    CTSQL_RESTORE_STACK(stmt);

    return status;
}

static status_t sql_task_submit_get_dst(pl_executor_t *exec, expr_tree_t *jobno_expr, ple_var_t **dst)
{
    if (jobno_expr->root->type != EXPR_NODE_V_ADDR) {
        CT_SRC_THROW_ERROR(jobno_expr->loc, ERR_PL_SYNTAX_ERROR_FMT, "unexpected pl-variant occurs");
        return CT_ERROR;
    }
    var_address_pair_t *pair = sql_get_last_addr_pair(jobno_expr->root);
    if (pair == NULL || pair->type != UDT_STACK_ADDR) {
        CT_SRC_THROW_ERROR(jobno_expr->loc, ERR_PL_SYNTAX_ERROR_FMT, "unexpected pl-variant occurs");
        return CT_ERROR;
    }
    *dst = ple_get_plvar(exec, pair->stack->decl->vid);
    return CT_SUCCESS;
}

/*
 * This procedure submits a new job.It chooses the job from the sequence sys.jobseq.
 *
 * Syntax:
 *
 * DBE_TASK.SUBMIT ( *     job       OUT BINARY_INTEGER,
 * what      IN  VARCHAR2,
 * next_date IN  DATE DEFAULT sysdate,
 * interval  IN  VARCHAR2 DEFAULT 'null',
 * no_parse  IN  BOOLEAN DEFAULT FALSE,
 * instance  IN  BINARY_INTEGER DEFAULT any_instance,   // current set to 0
 * force     IN  BOOLEAN DEFAULT FALSE,    // current set to true
 * );
 */
static status_t sql_task_submit(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    expr_tree_t *jobno_expr = NULL;
    variant_t next_date, no_parse, src;
    knl_job_def_t job_def;
    pl_executor_t *exec = NULL;
    ple_var_t *dst = NULL;
    date_t now_date;
    status_t status;

    CM_POINTER3(stmt, func, res);
    SQL_SET_NULL_VAR(res);

    now_date = cm_date_now();

    exec = stmt->pl_exec;
    if (exec == NULL) {
        CT_SRC_THROW_ERROR(func->argument->root->loc, ERR_SQL_SYNTAX_ERROR,
            "DBE_TASK.SUBMIT can only be used in plsql");
        return CT_ERROR;
    }

    CTSQL_SAVE_STACK(stmt);

    do {
        /* job number */
        jobno_expr = func->argument;

        /* what */
        status = sql_get_job_what(stmt, func, &job_def);
        CT_BREAK_IF_ERROR(status);

        /* next date */
        status = sql_get_dbe_param_value(stmt, func, g_submit_task_params, 3, &next_date);
        CT_BREAK_IF_ERROR(status);
        job_def.next_date = (next_date.is_null) ? now_date : next_date.v_bigint;

        /* interval */
        status = sql_get_job_interval(stmt, func, &job_def);
        CT_BREAK_IF_ERROR(status);

        /* If the no_parse is false or null, try verify the job */
        status = sql_get_dbe_param_value(stmt, func, g_submit_task_params, 5, &no_parse);
        CT_BREAK_IF_ERROR(status);
        job_def.no_parse = (no_parse.is_null || !no_parse.v_bool) ? CT_FALSE : CT_TRUE;

        job_def.instance = 0;
        if (!job_def.no_parse) {
            status = sql_check_job_valid(stmt, &job_def, now_date, func);
            CT_BREAK_IF_ERROR(status);
        }

        job_def.lowner = stmt->session->curr_user;

        status = sql_alloc_task_id(stmt, &job_def.job_id);
        CT_BREAK_IF_ERROR(status);
        status = knl_submit_job(KNL_SESSION(stmt), &job_def);
        CT_BREAK_IF_ERROR(status);

        /* return the job number as out argument */
        status = sql_task_submit_get_dst(exec, jobno_expr, &dst);
        CT_BREAK_IF_ERROR(status);
        src.type = CT_TYPE_BIGINT;
        src.v_bigint = job_def.job_id;
        src.is_null = CT_FALSE;

        status = ple_move_value(stmt, &src, dst);
    } while (0);

    CTSQL_RESTORE_STACK(stmt);

    return status;
}

static status_t sql_verify_task_submit(sql_verifier_t *verf, expr_node_t *func)
{
    expr_tree_t *jobno_expr = NULL;

    /* check the number of the argument */
    if (sql_verify_func_node(verf, func, 2, 5, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    /* make sure the first argument be variant */
    jobno_expr = func->argument;
    if (!(jobno_expr->root->type == EXPR_NODE_V_ADDR && CT_IS_NUMERIC_TYPE(TREE_DATATYPE(jobno_expr)))) {
        CT_SRC_THROW_ERROR(func->argument->root->loc, ERR_INVALID_FUNC_PARAMS,
            "argument id of DBE_TASK.SUBMIT should be numeric type");
        return CT_ERROR;
    }

    return sql_verify_dbe_func(verf, func, g_submit_task_params,
        sizeof(g_submit_task_params) / sizeof(dbe_func_param_t));
}

/*
 * sql_task_get_nextdate
 *
 * This procedure get the next date by interval.
 *
 */
status_t sql_task_get_nextdate(sql_stmt_t *stmt, expr_node_t *interval, variant_t *result)
{
    variant_t next_date;

    CM_POINTER2(stmt, result);
    result->is_null = CT_TRUE;

    if (sql_exec_expr_node(stmt, interval, &next_date) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_CALC_EXPRESSION, "interval expression node");
        return CT_ERROR;
    }
    if (!(next_date.is_null == CT_FALSE && CT_IS_DATETIME_TYPE(next_date.type))) {
        CT_THROW_ERROR(ERR_INVALID_FUNC_PARAMS, "error interval");
        return CT_ERROR;
    }

    *result = next_date;

    return CT_SUCCESS;
}

static status_t sql_create_ddm_expr_tree(sql_stmt_t *stmt, knl_column_t *knl_col, expr_tree_t **expr_tree,
    text_t ddm_text)
{
    typmode_t col_type;
    lex_t *lex = NULL;
    word_t word;
    status_t status;
    uint32 src_lex_flags;

    CM_POINTER3(stmt, knl_col, expr_tree);

    word.id = RES_WORD_DEFAULT;
    lex = stmt->session->lex;
    src_lex_flags = lex->flags;

    word.type = WORD_TYPE_RESERVED;
    word.begin_addr = ddm_text.str;
    word.loc.line = 1;
    word.loc.column = 1;
    word.text.value.str = ddm_text.str;
    word.text.value.len = ddm_text.len;
    word.text.loc.line = 1;
    word.text.loc.column = 1;

    if (lex_push(lex, &word.text) != CT_SUCCESS) {
        return CT_ERROR;
    }

    lex->flags = LEX_SINGLE_WORD;
    status = sql_create_expr_until(stmt, expr_tree, &word);
    if (status != CT_SUCCESS) {
        lex_pop(lex);
        lex->flags = src_lex_flags;
        return status;
    }
    col_type.datatype = knl_col->datatype;
    col_type.size = knl_col->size;
    col_type.precision = knl_col->precision;
    col_type.scale = knl_col->scale;
    col_type.is_array = KNL_COLUMN_IS_ARRAY(knl_col);
    if (sql_build_cast_expr(stmt, TREE_LOC(*expr_tree), *expr_tree, &col_type, expr_tree) != CT_SUCCESS) {
        lex_pop(lex);
        lex->flags = src_lex_flags;
        CT_SRC_THROW_ERROR(LEX_LOC, ERR_CAST_TO_COLUMN, "default value", T2S(&word.text.value));
        return CT_ERROR;
    }
    lex_pop(lex);
    lex->flags = src_lex_flags;
    if (word.type != WORD_TYPE_EOF) {
        CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "end of expression text expected but %s found",
            W2S(&word));
        return CT_ERROR;
    }
    return CT_SUCCESS;
}
static status_t sql_drop_ddm_policy(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t ownname, tabname, rulename;
    knl_session_t *session = KNL_SESSION(stmt);
    char buf[CT_NAME_BUFFER_SIZE];

    CM_POINTER3(stmt, func, result);
    CT_RETURN_IFERR(sql_check_trig_commit(stmt));

    /* ownname */
    CT_RETURN_IFERR(sql_get_dbe_param_value(stmt, func, g_ddm_del_rule_params, 1, &ownname));

    /* tabname */
    CT_RETURN_IFERR(sql_get_dbe_param_value(stmt, func, g_ddm_del_rule_params, 2, &tabname));

    /* colname */
    CT_RETURN_IFERR(sql_get_dbe_param_value(stmt, func, g_ddm_del_rule_params, 3, &rulename));

    cm_text_upper(&ownname.v_text);
    CT_RETURN_IFERR(sql_user_text_prefix_tenant(stmt->session, &ownname.v_text, buf, CT_NAME_BUFFER_SIZE));

    process_name_case_sensitive(&tabname.v_text);
    process_name_case_sensitive(&rulename.v_text);

    if (knl_check_ddm_rule((knl_handle_t *)session, ownname.v_text, tabname.v_text, rulename.v_text) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return knl_drop_ddm_rule_by_name((knl_handle_t *)session, ownname.v_text, tabname.v_text, rulename.v_text);
}
static status_t sql_verify_drop_ddm_policy(sql_verifier_t *verf, expr_node_t *func)
{
    if (sql_verify_func_node(verf, func, 3, 3, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return sql_verify_dbe_func(verf, func, g_ddm_del_rule_params,
        sizeof(g_ddm_del_rule_params) / sizeof(dbe_func_param_t));
}

static status_t sql_ddm_verify_text(sql_stmt_t *stmt, variant_t *param, knl_column_t *column)
{
    sql_stmt_t *sub_stmt = NULL;
    expr_tree_t *expr_tree = NULL;
    expr_tree_t *expr_update_tree_src = NULL;
    char tmpparam[CT_MAX_DDM_LEN] = { 0 };
    text_t ddm_text;

    if (cm_text2str_with_quato(&param->v_text, tmpparam, CT_MAX_DDM_LEN) != CT_SUCCESS) {
        return CT_ERROR;
    }
    ddm_text.str = tmpparam;
    ddm_text.len = (uint32)strlen(tmpparam);

    CTSQL_SAVE_STACK(stmt);

    if (sql_push(stmt, sizeof(sql_stmt_t), (void **)&sub_stmt) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }

    errno_t err = memset_s(sub_stmt, sizeof(sql_stmt_t), 0, sizeof(sql_stmt_t));
    if (err != EOK) {
        CTSQL_RESTORE_STACK(stmt);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return CT_ERROR;
    }
    sql_init_stmt(stmt->session, sub_stmt, stmt->id);
    sub_stmt->is_srvoutput_on = stmt->is_srvoutput_on;
    sub_stmt->is_sub_stmt = CT_TRUE;
    sub_stmt->parent_stmt = stmt;
    sub_stmt->cursor_info.type = PL_FORK_CURSOR;

    if (sql_alloc_context(sub_stmt) != CT_SUCCESS) {
        sql_free_stmt(sub_stmt);
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }
    if (sql_create_ddm_expr_tree(sub_stmt, column, &expr_tree, ddm_text) != CT_SUCCESS) {
        cm_reset_error();
        CT_THROW_ERROR(ERR_INVALID_OPERATION, ", param value can't match column");
        sql_free_stmt(sub_stmt);
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }

    sql_verifier_t verf = { 0 };
    verf.stmt = sub_stmt;
    verf.context = sub_stmt->context;
    verf.do_expr_optmz = CT_FALSE;
    verf.excl_flags = SQL_DEFAULT_EXCL;
    verf.obj = NULL;
    if (sql_verify_column_expr_tree(&verf, column, expr_tree, expr_update_tree_src) != CT_SUCCESS) {
        cm_reset_error();
        CT_THROW_ERROR(ERR_INVALID_OPERATION, ", param value can't match column");
        sql_free_stmt(sub_stmt);
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }

    if (expr_tree->root->argument->root->type != EXPR_NODE_CONST) {
        cm_reset_error();
        CT_THROW_ERROR(ERR_INVALID_OPERATION, ", param value must be const");
        sql_free_stmt(sub_stmt);
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }

    sql_free_stmt(sub_stmt);
    CTSQL_RESTORE_STACK(stmt);

    return CT_SUCCESS;
}


static status_t sql_ddm_policy_check_dc(sql_stmt_t *stmt, variant_t *colname, variant_t *ownname, variant_t *tabname,
    variant_t *param, knl_ddm_def_t *def)
{
    text_t user = ownname->v_text;
    text_t name = tabname->v_text;
    knl_column_t *column = NULL;
    knl_dictionary_t dc;
    status_t status = CT_ERROR;
    knl_session_t *session = KNL_SESSION(stmt);

    CT_RETURN_IFERR(dc_open(session, &user, &name, &dc));
    CTSQL_SAVE_STACK(stmt);
    do {
        dc_entity_t *entity = (dc_entity_t *)dc.handle;
        if (dc.type != DICT_TYPE_TABLE) {
            CT_THROW_ERROR(ERR_INVALID_OPERATION, ", please set rule on common table");
            break;
        }
        if (entity->table.desc.uid == 0) {
            CT_THROW_ERROR(ERR_INVALID_OPERATION, ", adding a policy to an object owned by SYS is not allowed");
            break;
        }
        if (IS_SYS_TABLE(&entity->table)) {
            CT_THROW_ERROR(ERR_INVALID_OPERATION, ", please set rule on common table");
            break;
        }
        column = knl_find_column(&colname->v_text, &dc);
        if (column == NULL) {
            CT_THROW_ERROR(ERR_COLUMN_NOT_EXIST, "column", T2S(&colname->v_text));
            break;
        }
        if (KNL_COLUMN_IS_VIRTUAL(column)) {
            CT_THROW_ERROR(ERR_INVALID_OPERATION, ", can't set rule on virtual column");
            break;
        }

        if (sql_ddm_verify_text(stmt, param, column) != CT_SUCCESS) {
            break;
        }
        def->oid = dc.oid;
        def->uid = dc.uid;
        def->column_id = column->id;

        status = CT_SUCCESS;
    } while (0);

    dc_close(&dc);
    CTSQL_RESTORE_STACK(stmt);
    return status;
}


static status_t sql_add_ddm_policy(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t ownname, tabname, colname, rulename, ddmtype, param;
    knl_ddm_def_t def;
    errno_t ret;
    status_t ret_stat;
    knl_session_t *session = KNL_SESSION(stmt);
    char buf[CT_NAME_BUFFER_SIZE];

    CM_POINTER3(stmt, func, result);
    CT_RETURN_IFERR(sql_check_trig_commit(stmt));
    /* ownname */
    CT_RETURN_IFERR(sql_get_dbe_param_value(stmt, func, g_ddm_add_rule_params, 1, &ownname));

    /* tabname */
    CT_RETURN_IFERR(sql_get_dbe_param_value(stmt, func, g_ddm_add_rule_params, 2, &tabname));

    /* colname */
    CT_RETURN_IFERR(sql_get_dbe_param_value(stmt, func, g_ddm_add_rule_params, 3, &colname));

    /* rulename */
    CT_RETURN_IFERR(sql_get_dbe_param_value(stmt, func, g_ddm_add_rule_params, 4, &rulename));

    /* ddmtype */
    CT_RETURN_IFERR(sql_get_dbe_param_value(stmt, func, g_ddm_add_rule_params, 5, &ddmtype));

    /* param */
    CT_RETURN_IFERR(sql_get_dbe_param_value(stmt, func, g_ddm_add_rule_params, 6, &param));
    /*
     * User name must be upper case.
     * Table name uses upper case or original mode depending on system setting.
     */
    cm_text_upper(&ownname.v_text);
    CT_RETURN_IFERR(sql_user_text_prefix_tenant(stmt->session, &ownname.v_text, buf, CT_NAME_BUFFER_SIZE));

    process_name_case_sensitive(&tabname.v_text);
    process_name_case_sensitive(&colname.v_text);
    process_name_case_sensitive(&rulename.v_text);
    process_name_case_sensitive(&ddmtype.v_text);
    process_name_case_sensitive(&param.v_text);

    if (rulename.v_text.len <= 0) {
        CT_THROW_ERROR(ERR_INVALID_OPERATION, ", rulename is too short");
        return CT_ERROR;
    }

    if (cm_compare_text_str_ins(&ddmtype.v_text, "FULL") != 0) {
        CT_THROW_ERROR(ERR_INVALID_OPERATION, ", policy_type only support full type");
        return CT_ERROR;
    }

    ret = memset_sp(&def, sizeof(knl_ddm_def_t), 0, sizeof(knl_ddm_def_t));
    if (ret != EOK) {
        CT_THROW_ERROR(ERR_RESET_MEMORY, "knl_ddm_def_t def");
        return CT_ERROR;
    }

    if (sql_ddm_policy_check_dc(stmt, &colname, &ownname, &tabname, &param, &def) != CT_SUCCESS) {
        return CT_ERROR;
    }

    CT_RETURN_IFERR(cm_text2str(&rulename.v_text, def.rulename, CT_NAME_BUFFER_SIZE));
    CT_RETURN_IFERR(cm_text2str(&ddmtype.v_text, def.ddmtype, CT_NAME_BUFFER_SIZE));
    CT_RETURN_IFERR(cm_text2str_with_quato(&param.v_text, def.param, CT_MAX_DDM_LEN));
    CM_SAVE_STACK(stmt->session->stack);
    ret_stat = knl_write_sysddm((knl_handle_t *)session, &def);
    CM_RESTORE_STACK(stmt->session->stack);
    return ret_stat;
}

static status_t sql_verify_add_ddm_policy(sql_verifier_t *verf, expr_node_t *func)
{
    if (sql_verify_func_node(verf, func, 6, 6, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return sql_verify_dbe_func(verf, func, g_ddm_add_rule_params,
        sizeof(g_ddm_add_rule_params) / sizeof(dbe_func_param_t));
}

static status_t sql_auto_degree(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    result->type = CT_TYPE_NUMBER;
    result->is_null = CT_FALSE;
    cm_zero_dec(&result->v_dec);

    return CT_SUCCESS;
}

static status_t sql_verify_auto_degree(sql_verifier_t *verf, expr_node_t *func)
{
    if (sql_verify_func_node(verf, func, 0, 0, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    func->datatype = CT_TYPE_NUMBER;
    func->size = MAX_DEC_BYTE_SZ;
    func->scale = CT_UNSPECIFIED_NUM_SCALE;
    func->precision = CT_UNSPECIFIED_NUM_PREC;
    return CT_SUCCESS;
}

status_t sql_convert_ids(text_t *t_ids, galist_t *id_list)
{
    if (t_ids->len == 0) {
        return CT_SUCCESS;
    }

    lex_t lex;
    word_t word;
    sql_text_t sql_text;
    sql_text.value = *t_ids;
    lex_trim(&sql_text);
    lex_init(&lex, &sql_text);
    uint32 *id = NULL;

    for (;;) {
        CT_RETURN_IFERR(lex_fetch(&lex, &word));
        if (word.type != WORD_TYPE_NUMBER) {
            CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "invalid id was found");
            return CT_ERROR;
        }
        CT_RETURN_IFERR(cm_galist_new(id_list, sizeof(uint32), (pointer_t *)&id));
        CT_RETURN_IFERR(cm_text2uint32(&word.text.value, id));
        CT_RETURN_IFERR(lex_fetch(&lex, &word));
        if (word.type == WORD_TYPE_EOF) {
            break;
        }
        if (!IS_SPEC_CHAR(&word, ',')) {
            CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, ", expected but %s found", W2S(&word));
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

static status_t sql_verify_edit_distance(sql_verifier_t *verf, expr_node_t *func)
{
    if (sql_verify_func_node(verf, func, 2, 2, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    func->datatype = CT_TYPE_INTEGER;
    func->size = CT_INTEGER_SIZE;
    return CT_SUCCESS;
}

static status_t sql_edit_distance_prepare_param(sql_stmt_t *stmt, expr_tree_t *arg_node, variant_t *value,
    variant_t *result)
{
    CM_POINTER(arg_node);
    SQL_EXEC_FUNC_ARG(arg_node, value, result, stmt);
    if (value->type == CT_TYPE_RAW || value->type == CT_TYPE_BLOB) {
        CT_THROW_ERROR(ERR_UNSUPPORT_DATATYPE, "BLOB");
        return CT_ERROR;
    }
    CT_RETSUC_IFTRUE(value->is_null || CT_IS_STRING_TYPE(value->type));

    sql_keep_stack_variant(stmt, value);
    if (sql_var_as_string(stmt, value) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t sql_func_edit_distance_core(sql_stmt_t *stmt, text_t *src, text_t *dst, variant_t *res)
{
    uint32 *distance = NULL;
    uint32 len_src = src->len;
    uint32 len_dst = dst->len;
    uint32 pre, temp;

    if (len_src == 0 || len_dst == 0) {
        res->v_int = len_src + len_dst;
        return CT_SUCCESS;
    }

    if (sql_push(stmt, sizeof(uint32) * (len_dst + 1), (void **)&distance) != CT_SUCCESS) {
        return CT_ERROR;
    }

    for (uint32 i = 0; i <= len_dst; i++) {
        distance[i] = i;
    }
    for (uint32 i = 1; i <= len_src; i++) {
        pre = distance[0];
        distance[0] = i;
        for (uint32 j = 1; j <= len_dst; j++) {
            temp = distance[j];
            if (src->str[i - 1] == dst->str[j - 1]) {
                distance[j] = pre;
            } else {
                distance[j] = MIN(MIN(pre, distance[j]), distance[j - 1]) + 1;
            }
            pre = temp;
        }
    }
    res->v_int = distance[len_dst];
    return CT_SUCCESS;
}

static status_t sql_func_edit_distance_and_similarity(sql_stmt_t *stmt, expr_node_t *func, variant_t *result,
    variant_t *similarity)
{
    variant_t src, dst;
    CM_POINTER3(stmt, func, result);

    CT_RETURN_IFERR(sql_edit_distance_prepare_param(stmt, func->argument, &src, result));

    sql_keep_stack_variant(stmt, &src);
    CT_RETURN_IFERR(sql_edit_distance_prepare_param(stmt, func->argument->next, &dst, result));

    if (src.is_null && dst.is_null && similarity != NULL) {
        similarity->v_int = (int32)CT_PERCENT;
        return CT_SUCCESS;
    }
    if (src.is_null || dst.is_null || src.type == CT_TYPE_COLUMN || dst.type == CT_TYPE_COLUMN) {
        return CT_SUCCESS;
    }

    if (src.v_text.len > CT_STRING_BUFFER_SIZE) {
        CT_THROW_ERROR(ERR_PL_ARG_FMT, 1, "function", "exceeds the length limit");
        return CT_ERROR;
    }

    if (dst.v_text.len > CT_STRING_BUFFER_SIZE) {
        CT_THROW_ERROR(ERR_PL_ARG_FMT, 2, "function", "exceeds the length limit");
        return CT_ERROR;
    }
    sql_keep_stack_variant(stmt, &dst);

    CT_RETURN_IFERR(sql_func_edit_distance_core(stmt, &src.v_text, &dst.v_text, result));
    if (similarity != NULL) {
        int max_len = MAX(src.v_text.len, dst.v_text.len);
        if (max_len > 0 && result->v_int >= 0) {
            similarity->v_int = (int32)((1 - (double)result->v_int / (double)max_len) * CT_PERCENT + 0.5);
        }
    }
    return CT_SUCCESS;
}

static status_t sql_func_edit_distance(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    result->is_null = CT_FALSE;
    result->type = CT_TYPE_INTEGER;
    result->v_int = -1;
    CTSQL_SAVE_STACK(stmt);
    status_t status = sql_func_edit_distance_and_similarity(stmt, func, result, NULL);
    CTSQL_RESTORE_STACK(stmt);
    return status;
}

static status_t sql_func_edit_distance_similarity(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    result->is_null = CT_FALSE;
    result->type = CT_TYPE_INTEGER;
    result->v_int = 0;
    variant_t distance;
    CTSQL_SAVE_STACK(stmt);
    status_t status = sql_func_edit_distance_and_similarity(stmt, func, &distance, result);
    if (status != CT_ERROR && distance.type == CT_TYPE_COLUMN) {
        result->type = CT_TYPE_COLUMN;
    }
    CTSQL_RESTORE_STACK(stmt);
    return status;
}

static status_t sql_func_rowid2pageid(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    expr_tree_t *arg1 = NULL;
    variant_t var1;

    CM_POINTER3(stmt, func, result);
    arg1 = func->argument;
    CM_POINTER(arg1);

    CTSQL_SAVE_STACK(stmt);
    SQL_EXEC_FUNC_ARG_EX(arg1, &var1, result);
    SQL_SET_NULL_VAR(result);

    if (var1.v_text.len >= CT_MAX_ROWID_STRLEN || var1.v_text.len <= 0) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_SUCCESS; /* ignore illegal input */
    }

    rowid_t rowid;
    rowid.value = 0;
    sql_str2rowid(var1.v_text.str, &rowid);

    page_id_t pageid = GET_ROWID_PAGE(rowid);
    char *buf = NULL;

    if (sql_push(stmt, CT_MAX_ROWID_STRLEN, (void **)&buf) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }

    int ret;
    ret = memset_sp(buf, CT_MAX_ROWID_STRLEN, 0, CT_MAX_ROWID_STRLEN);
    ret = snprintf_s(buf, CT_MAX_ROWID_STRLEN, CT_MAX_ROWID_STRLEN, "%u-%u", (uint32)pageid.file, (uint32)pageid.page);
    if (ret < 0) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }

    result->is_null = CT_FALSE;
    result->type = CT_TYPE_STRING;
    result->v_text.str = buf;
    result->v_text.len = strlen(buf);
    CTSQL_RESTORE_STACK(stmt);

    return CT_SUCCESS;
}

static status_t sql_verify_rowid2pageid(sql_verifier_t *verf, expr_node_t *func)
{
    if (sql_verify_func_node(verf, func, 1, 1, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    func->datatype = CT_TYPE_STRING;
    func->size = cm_get_datatype_strlen(func->argument->root->datatype, func->argument->root->size);

    return CT_SUCCESS;
}

#define SQL_FUNC_NAME_LEN(name) (sizeof(name) - 1)

static sql_func_t g_dbe_job_funcs[] = {
    { { (char *)"cancel", 6 }, sql_job_cancel, sql_verify_job_cancel, AGGR_TYPE_NONE, FO_PROC, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"run", 3 }, sql_task_run, sql_verify_task_run, AGGR_TYPE_NONE, FO_PROC, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"submit", 6 }, sql_task_submit, sql_verify_task_submit, AGGR_TYPE_NONE, FO_PROC, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"suspend", 7 }, sql_task_suspend, sql_verify_task_suspend, AGGR_TYPE_NONE, FO_PROC, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
};

static sql_func_t g_dbe_random_funcs[] = {
    { { (char *)"get_string", 10 }, sql_random_string, sql_verify_random_string, AGGR_TYPE_NONE, FO_NORMAL, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"get_value", 9 }, sql_random_value, sql_verify_random_value, AGGR_TYPE_NONE, FO_NORMAL, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
};

static sql_func_t g_dbe_output_funcs[] = {
    { { (char *)"print", 5 }, sql_print_line, sql_verify_print, AGGR_TYPE_NONE, FO_PROC, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"print_line", 10 }, sql_print_line, sql_verify_print, AGGR_TYPE_NONE, FO_PROC, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
};

static sql_func_t g_dbe_sql_funcs[] = {
    { { (char *)"return_cursor", 13 }, sql_func_return_cursor, sql_verify_return_cursor, AGGR_TYPE_NONE, FO_PROC, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
};

static sql_func_t g_dbe_standard_funcs[] = {
    { { (char *)"sleep", 5 }, sql_func_sleep, sql_verify_sleep, AGGR_TYPE_NONE, FO_PROC, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"sql_err_code", 12 }, sql_func_sqlcode, sql_verify_sqlcode, AGGR_TYPE_NONE, FO_NORMAL, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"sql_err_msg", 11 }, sql_func_sqlerrm, sql_verify_sqlerrm, AGGR_TYPE_NONE, FO_NORMAL, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"throw_exception", 15 }, sql_throw_exception, sql_verify_throw_excption, AGGR_TYPE_NONE, FO_PROC, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
};

static sql_func_t g_dbe_stats_funcs[] = {
    { { (char *)"auto_degree", 11 }, sql_auto_degree, sql_verify_auto_degree, AGGR_TYPE_NONE, FO_NORMAL, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"auto_sample_size", 16 }, sql_auto_sample_size, sql_verify_auto_sample_size, AGGR_TYPE_NONE, FO_NORMAL, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"collect_index_stats", 19 }, sql_collect_index_stats, sql_verify_collect_index_stats, AGGR_TYPE_NONE, FO_PROC, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"collect_schema_stats", 20 }, sql_collect_schema_stats, sql_verify_collect_schema_stats, AGGR_TYPE_NONE, FO_PROC, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"collect_table_stats", 19 }, sql_collect_table_stats, sql_verify_collect_table_stats, AGGR_TYPE_NONE, FO_PROC, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"delete_schema_stats", 19 }, sql_delete_schema_stats, sql_verify_delete_schema_stats, AGGR_TYPE_NONE, FO_PROC, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"delete_table_stats", 18 }, sql_delete_table_stats, sql_verify_delete_table_stats, AGGR_TYPE_NONE, FO_PROC, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"flush_db_stats_info", 19 }, sql_flush_db_stats_info, sql_verify_flush_db_stats_info, AGGR_TYPE_NONE, FO_PROC, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"lock_table_stats", 16 }, sql_lock_table_stats, sql_verify_lock_table_stats, AGGR_TYPE_NONE, FO_PROC, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"modify_column_stats", 19 }, sql_mod_column_stats, sql_verify_mod_column_stats, AGGR_TYPE_NONE, FO_PROC, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"modify_index_stats", 18 }, sql_mod_index_stats, sql_verify_mod_index_stats, AGGR_TYPE_NONE, FO_PROC, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"modify_table_stats", 18 }, sql_mod_table_stats, sql_verify_mod_table_stats, AGGR_TYPE_NONE, FO_PROC, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"purge_stats", 11 }, sql_purge_stats, sql_verify_purge_stats, AGGR_TYPE_NONE, FO_PROC, CT_INVALID_ID32, CT_INVALID_VALUE_CNT},
    { { (char *)"unlock_table_stats", 18 }, sql_unlock_table_stats, sql_verify_unlock_table_stats, AGGR_TYPE_NONE, FO_PROC, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
};

static sql_func_t g_dbe_utility_funcs[] = {
    { { (char *)"compile_schema", 14 },
      sql_func_compile_schema,
      sql_verify_compile_schema,
      AGGR_TYPE_NONE,
      FO_PROC,
      CT_INVALID_ID32,
      CT_INVALID_VALUE_CNT,
      CT_FALSE },
    { { (char *)"edit_distance", 13 },
      sql_func_edit_distance,
      sql_verify_edit_distance,
      AGGR_TYPE_NONE,
      FO_NORMAL,
      CT_INVALID_ID32,
      CT_INVALID_VALUE_CNT,
      CT_FALSE },
    { { (char *)"edit_distance_similarity", 24 },
      sql_func_edit_distance_similarity,
      sql_verify_edit_distance,
      AGGR_TYPE_NONE,
      FO_NORMAL,
      CT_INVALID_ID32,
      CT_INVALID_VALUE_CNT,
      CT_FALSE },
    { { (char *)"get_date_time", 13 },
      sql_func_get_time,
      sql_verify_get_time,
      AGGR_TYPE_NONE,
      FO_NORMAL,
      CT_INVALID_ID32,
      CT_INVALID_VALUE_CNT,
      CT_FALSE },
    { { (char *)"get_error_backtrace", 19 },
      sql_func_get_error_backtrace,
      sql_verify_get_error_backtrace,
      AGGR_TYPE_NONE,
      FO_NORMAL,
      CT_INVALID_ID32,
      CT_INVALID_VALUE_CNT,
      CT_FALSE },
    { { (char *)"rowid_block_number", 18 },
      sql_func_rowid2pageid,
      sql_verify_rowid2pageid,
      AGGR_TYPE_NONE,
      FO_NORMAL,
      CT_INVALID_ID32,
      CT_INVALID_VALUE_CNT,
      CT_FALSE },
};

static sql_func_t g_dbe_lob_funcs[] = {
    { { (char *)"get_length", 10 }, sql_func_lob_getlength, sql_verify_lob_getlength, AGGR_TYPE_NONE, FO_NORMAL, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"substr", 6 }, sql_func_lob_substr, sql_verify_lob_substr, AGGR_TYPE_NONE, FO_NORMAL, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
};

static sql_func_t g_dbe_diagnose_funcs[] = {
    { { (char *)"dba_index_size", 14 }, sql_func_table_indsize, sql_verify_table_indsize, AGGR_TYPE_NONE, FO_NORMAL, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"dba_ind_pos", 11 }, sql_func_ind_pos, sql_verify_ind_pos, AGGR_TYPE_NONE, FO_NORMAL, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"dba_listcols", 12 }, sql_func_list_cols, sql_verify_list_cols, AGGR_TYPE_NONE, FO_NORMAL, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"dba_lob_recycle_pages", 21 }, sql_func_lob_segment_free_size, sql_verify_lob_segment_free_size, AGGR_TYPE_NONE, FO_NORMAL, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"dba_partitioned_indsize", 23 }, sql_func_partitioned_indsize, sql_verify_partitioned_indsize, AGGR_TYPE_NONE, FO_NORMAL, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"dba_partitioned_lobsize", 23 }, sql_func_partitioned_lobsize, sql_verify_partitioned_lobsize, AGGR_TYPE_NONE, FO_NORMAL, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"dba_partitioned_tabsize", 23 }, sql_func_partitioned_tabsize, sql_verify_partitioned_tabsize, AGGR_TYPE_NONE, FO_NORMAL, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"dba_segsize", 11 }, sql_func_segment_size, sql_verify_segment_size, AGGR_TYPE_NONE, FO_NORMAL, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"dba_space_name", 14 }, sql_func_to_tablespace_name, sql_verify_to_tablespace_name, AGGR_TYPE_NONE, FO_NORMAL, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"dba_spcsize", 11 }, sql_func_space_size, sql_verify_space_size, AGGR_TYPE_NONE, FO_NORMAL, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"dba_table_name", 14}, sql_func_get_table_name, sql_verify_get_table_name, AGGR_TYPE_NONE, FO_NORMAL, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"dba_table_partsize", 18 }, sql_func_table_partsize, sql_verify_table_partsize, AGGR_TYPE_NONE, FO_NORMAL, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"dba_table_size", 14 }, sql_func_table_size, sql_verify_table_size, AGGR_TYPE_NONE, FO_NORMAL, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"dba_tabtype", 11 }, sql_func_tab_type, sql_verify_to_type_mapped, AGGR_TYPE_NONE, FO_NORMAL, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"dba_user_name", 13 }, sql_func_to_username, sql_verify_to_username, AGGR_TYPE_NONE, FO_NORMAL, CT_INVALID_ID32, CT_INVALID_VALUE_CNT},
    { { (char *)"has_obj_privs", 13 }, sql_func_has_obj_privs, sql_verify_has_obj_privs, AGGR_TYPE_NONE, FO_NORMAL, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"tenant_check", 12 }, sql_func_tenant_check, sql_verify_tenant_check, AGGR_TYPE_NONE, FO_NORMAL, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
};
static sql_func_t g_dbe_redact_funcs[] = {
    { { (char *)"add_policy", 10 }, sql_add_ddm_policy, sql_verify_add_ddm_policy, AGGR_TYPE_NONE, FO_PROC, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"drop_policy", 11 }, sql_drop_ddm_policy, sql_verify_drop_ddm_policy, AGGR_TYPE_NONE, FO_PROC, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
};

static sql_func_t g_dbe_debug_funcs[] = {
    { { (char *)"add_break", 9 }, sql_debug_add_break, sql_verify_debug_add_break, AGGR_TYPE_NONE, FO_NORMAL, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"attach", 6 }, sql_debug_attach, sql_verify_debug_attach, AGGR_TYPE_NONE, FO_PROC, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"delete_break", 12 }, sql_debug_del_break, sql_verify_debug_del_break, AGGR_TYPE_NONE, FO_PROC, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"delete_break_by_name", 20 }, sql_debug_del_break_by_name, sql_verify_debug_del_break_by_name, AGGR_TYPE_NONE, FO_PROC, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"detach", 6 }, sql_debug_detach, sql_verify_debug_detach, AGGR_TYPE_NONE, FO_PROC, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"get_status", 10 }, sql_debug_get_status, sql_verify_debug_get_status, AGGR_TYPE_NONE, FO_NORMAL, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"get_value", 9 }, sql_debug_get_value, sql_verify_debug_get_value, AGGR_TYPE_NONE, FO_NORMAL, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"get_version", 11 }, sql_debug_get_version, sql_verify_debug_get_version, AGGR_TYPE_NONE, FO_NORMAL, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"init", 4 }, sql_debug_init, sql_verify_debug_init, AGGR_TYPE_NONE, FO_NORMAL, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"pause", 5 }, sql_debug_pause, sql_verify_no_argument, AGGR_TYPE_NONE, FO_PROC, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"resume", 6 }, sql_debug_resume, sql_verify_debug_resume, AGGR_TYPE_NONE, FO_PROC, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"set_break", 9 }, sql_debug_set_break, sql_verify_debug_set_break, AGGR_TYPE_NONE, FO_PROC, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"set_curr_count", 14 }, sql_debug_set_curr_count, sql_verify_debug_set_curr_count, AGGR_TYPE_NONE, FO_PROC, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"set_value", 9 }, sql_debug_set_value, sql_verify_debug_set_value, AGGR_TYPE_NONE, FO_PROC, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"terminate", 9 }, sql_debug_terminate, sql_verify_no_argument, AGGR_TYPE_NONE, FO_PROC, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"uninit", 6 }, sql_debug_uninit, sql_verify_no_argument, AGGR_TYPE_NONE, FO_PROC, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"update_break", 12 }, sql_debug_update_break, sql_verify_debug_update_break, AGGR_TYPE_NONE, FO_PROC, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },

};

status_t sql_check_object_name(text_t *name, const char *object_type, source_location_t loc)
{
    if (name->len == 0 || !is_variant_head(name->str[0])) {
        CT_SRC_THROW_ERROR(loc, ERR_SQL_SYNTAX_ERROR, "invalid identifier");
        return CT_ERROR;
    }
    for (uint32 i = 1; i < name->len; i++) {
        if (!is_nameble(name->str[i])) {
            CT_SRC_THROW_ERROR(loc, ERR_SQL_SYNTAX_ERROR, "invalid identifier");
            return CT_ERROR;
        }
    }
    if (name->len > CT_MAX_NAME_LEN) {
        CT_SRC_THROW_ERROR(loc, ERR_NAME_TOO_LONG, object_type, name->len, CT_MAX_NAME_LEN);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t sql_check_tenant_name(text_t *name, source_location_t loc)
{
    if (name->len == 0 || !is_variant_head(name->str[0])) {
        CT_SRC_THROW_ERROR(loc, ERR_SQL_SYNTAX_ERROR, "invalid identifier");
        return CT_ERROR;
    }
    for (uint32 i = 1; i < name->len; i++) {
        if (!is_nameble(name->str[i])) {
            CT_SRC_THROW_ERROR(loc, ERR_SQL_SYNTAX_ERROR, "invalid identifier");
            return CT_ERROR;
        }
    }
    if (name->len > CT_TENANT_NAME_LEN) {
        CT_SRC_THROW_ERROR(loc, ERR_NAME_TOO_LONG, "tenant", name->len, CT_TENANT_NAME_LEN);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static inline status_t sql_pre_exec_resource_manager(sql_stmt_t *stmt)
{
    stmt->session->sql_audit.audit_type = SQL_AUDIT_DDL;
    if (!knl_is_dist_ddl(KNL_SESSION(stmt))) {
        (void)do_commit(stmt->session);
    }
    sql_set_scn(stmt);
    sql_set_ssn(stmt);

#ifdef Z_SHARDING
    CT_RETURN_IFERR(shd_pre_execute_ddl(stmt, CT_FALSE, CT_FALSE));
#endif // Z_SHARDING

    return CT_SUCCESS;
}

static inline status_t sql_after_exec_resource_manager(sql_stmt_t *stmt, status_t temp_result)
{
    status_t result = temp_result;
    if (result == CT_SUCCESS) {
        result = do_commit(stmt->session);
    } else {
        do_rollback(stmt->session, NULL);
    }
    return result;
}

static inline status_t sql_verify_dbe_resmgr(sql_stmt_t *stmt)
{
    if (sql_check_user_tenant(&stmt->session->knl_session) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

#define SQL_BUFFER_SIZE 2048

static inline status_t sql_pre_exec_create_cgroup(sql_stmt_t *stmt, knl_rsrc_group_t *rsrc_group)
{
    char ddl_sql[SQL_BUFFER_SIZE];

    PRTS_RETURN_IFERR(snprintf_s(ddl_sql, SQL_BUFFER_SIZE, SQL_BUFFER_SIZE - 1,
        "BEGIN\n DBE_RSRC_MGR.CREATE_CONTROL_GROUP("
        "name=>'%s', comment=>'%s');\nEND;\n/",
        rsrc_group->name, rsrc_group->description));
    CT_LOG_DEBUG_INF("generated distribute ddl: [%s]", ddl_sql);
    CT_RETURN_IFERR(sql_pre_exec_resource_manager(stmt));
    return CT_SUCCESS;
}

static inline status_t sql_pre_exec_update_cgroup(sql_stmt_t *stmt, knl_rsrc_group_t *rsrc_group)
{
    char ddl_sql[SQL_BUFFER_SIZE];

    PRTS_RETURN_IFERR(snprintf_s(ddl_sql, SQL_BUFFER_SIZE, SQL_BUFFER_SIZE - 1,
        "BEGIN\n DBE_RSRC_MGR.UPDATE_CONTROL_GROUP("
        "name=>'%s', comment=>'%s');\nEND;\n/",
        rsrc_group->name, rsrc_group->description));
    CT_LOG_DEBUG_INF("generated distribute ddl: [%s]", ddl_sql);
    CT_RETURN_IFERR(sql_pre_exec_resource_manager(stmt));
    return CT_SUCCESS;
}

static inline status_t sql_pre_exec_delete_cgroup(sql_stmt_t *stmt, text_t *group_name)
{
    char ddl_sql[SQL_BUFFER_SIZE];

    PRTS_RETURN_IFERR(snprintf_s(ddl_sql, SQL_BUFFER_SIZE, SQL_BUFFER_SIZE - 1,
        "BEGIN\n DBE_RSRC_MGR.DELETE_CONTROL_GROUP(name=>'%s');\nEND;\n/", T2S(group_name)));
    CT_LOG_DEBUG_INF("generated distribute ddl: [%s]", ddl_sql);
    CT_RETURN_IFERR(sql_pre_exec_resource_manager(stmt));
    return CT_SUCCESS;
}

static status_t sql_create_cgroup(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    status_t status;
    knl_rsrc_group_t rsrc_group;
    variant_t name, comment;
    source_location_t loc;

    /* group_name */
    CT_RETURN_IFERR(sql_get_dbe_param_value_loc(stmt, func, g_create_cgroup_params, 1, &name, &loc));
    CT_RETURN_IFERR(sql_check_object_name(&name.v_text, "control group", loc));
    process_name_case_sensitive(&name.v_text);
    /* case insensitive */
    cm_text_upper(&name.v_text);
    CT_RETURN_IFERR(cm_text2str(&name.v_text, rsrc_group.name, CT_NAME_BUFFER_SIZE));

    /* comment */
    CT_RETURN_IFERR(sql_get_dbe_param_value(stmt, func, g_create_cgroup_params, 2, &comment));
    if (!comment.is_null && comment.v_text.len > 0) {
        CT_RETURN_IFERR(cm_text2str(&comment.v_text, rsrc_group.description, CT_COMMENT_SIZE + 1));
    } else {
        rsrc_group.description[0] = '\0';
    }
    SQL_SET_NULL_VAR(result);

#ifdef Z_SHARDING
    if (IS_COORDINATOR && IS_APP_CONN(stmt->session)) {
        CT_RETURN_IFERR(sql_pre_exec_create_cgroup(stmt, &rsrc_group));
    }
#endif // Z_SHARDING
    status = knl_create_control_group(KNL_SESSION(stmt), &rsrc_group);
    return sql_after_exec_resource_manager(stmt, status);
}

static status_t sql_verify_create_cgroup(sql_verifier_t *verf, expr_node_t *func)
{
    if (sql_verify_func_node(verf, func, 1, 2, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (sql_verify_dbe_func(verf, func, g_create_cgroup_params,
        sizeof(g_create_cgroup_params) / sizeof(dbe_func_param_t)) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return sql_verify_dbe_resmgr(verf->stmt);
}

static bool32 sql_check_cgroup_referenced(text_t *group_name)
{
    rsrc_group_t *group = NULL;
    rsrc_plan_t *plan = GET_RSRC_MGR->plan;
    if (plan == NULL) {
        return CT_FALSE;
    }
    for (uint32 i = 0; i < plan->group_count; i++) {
        group = plan->groups[i];
        if (cm_text_str_equal(group_name, group->knl_group.name)) {
            return CT_TRUE;
        }
    }
    return CT_FALSE;
}

static inline bool32 sql_check_rsrc_plan_referenced(text_t *plan_name)
{
    rsrc_plan_t *plan = GET_RSRC_MGR->plan;
    if (plan != NULL && cm_text_str_equal(plan_name, plan->knl_plan.name)) {
        return CT_TRUE;
    }
    return CT_FALSE;
}

static status_t sql_delete_cgroup(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    status_t status;
    variant_t name;
    source_location_t loc;

    /* group_name */
    CT_RETURN_IFERR(sql_get_dbe_param_value_loc(stmt, func, g_delete_cgroup_params, 1, &name, &loc));
    CT_RETURN_IFERR(sql_check_object_name(&name.v_text, "control group", loc));
    process_name_case_sensitive(&name.v_text);
    cm_text_upper(&name.v_text);
    sql_keep_stack_variant(stmt, &name);

    if (sql_check_cgroup_referenced(&name.v_text)) {
        CT_THROW_ERROR(ERR_USER_IS_REFERENCED, "control group", T2S(&name.v_text), "being used");
        return CT_ERROR;
    }
    SQL_SET_NULL_VAR(result);

#ifdef Z_SHARDING
    if (IS_COORDINATOR && IS_APP_CONN(stmt->session)) {
        CT_RETURN_IFERR(sql_pre_exec_delete_cgroup(stmt, &name.v_text));
    }
#endif // Z_SHARDING
    status = knl_delete_control_group(KNL_SESSION(stmt), &name.v_text);
    return sql_after_exec_resource_manager(stmt, status);
}

static status_t sql_verify_delete_cgroup(sql_verifier_t *verf, expr_node_t *func)
{
    if (sql_verify_func_node(verf, func, 1, 1, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (sql_verify_dbe_func(verf, func, g_delete_cgroup_params,
        sizeof(g_delete_cgroup_params) / sizeof(dbe_func_param_t)) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return sql_verify_dbe_resmgr(verf->stmt);
}

static status_t sql_update_cgroup(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    status_t status;
    knl_rsrc_group_t rsrc_group;
    variant_t name, comment;
    source_location_t loc;

    /* group_name */
    CT_RETURN_IFERR(sql_get_dbe_param_value_loc(stmt, func, g_update_cgroup_params, 1, &name, &loc));
    CT_RETURN_IFERR(sql_check_object_name(&name.v_text, "control group", loc));
    process_name_case_sensitive(&name.v_text);
    cm_text_upper(&name.v_text);
    CT_RETURN_IFERR(cm_text2str(&name.v_text, rsrc_group.name, CT_NAME_BUFFER_SIZE));

    /* comment */
    CT_RETURN_IFERR(sql_get_dbe_param_value(stmt, func, g_create_cgroup_params, 2, &comment));
    if (!comment.is_null && comment.v_text.len > 0) {
        CT_RETURN_IFERR(cm_text2str(&comment.v_text, rsrc_group.description, CT_COMMENT_SIZE + 1));
    } else {
        rsrc_group.description[0] = '\0';
    }
    SQL_SET_NULL_VAR(result);

#ifdef Z_SHARDING
    if (IS_COORDINATOR && IS_APP_CONN(stmt->session)) {
        CT_RETURN_IFERR(sql_pre_exec_update_cgroup(stmt, &rsrc_group));
    }
#endif // Z_SHARDING
    status = knl_update_control_group(KNL_SESSION(stmt), &rsrc_group);
    return sql_after_exec_resource_manager(stmt, status);
}

static status_t sql_verify_update_cgroup(sql_verifier_t *verf, expr_node_t *func)
{
    if (sql_verify_func_node(verf, func, 1, 2, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (sql_verify_dbe_func(verf, func, g_update_cgroup_params,
        sizeof(g_update_cgroup_params) / sizeof(dbe_func_param_t)) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return sql_verify_dbe_resmgr(verf->stmt);
}

static inline status_t sql_pre_exec_create_rsrc_plan(sql_stmt_t *stmt, knl_rsrc_plan_t *knl_plan)
{
    char ddl_sql[SQL_BUFFER_SIZE];

    PRTS_RETURN_IFERR(snprintf_s(ddl_sql, SQL_BUFFER_SIZE, SQL_BUFFER_SIZE - 1,
        "BEGIN\n DBE_RSRC_MGR.CREATE_PLAN(name=>'%s', comment=>'%s');\nEND;\n/", knl_plan->name,
        knl_plan->description));
    CT_LOG_DEBUG_INF("generated distribute ddl: [%s]", ddl_sql);
    CT_RETURN_IFERR(sql_pre_exec_resource_manager(stmt));
    return CT_SUCCESS;
}

static inline status_t sql_pre_exec_update_rsrc_plan(sql_stmt_t *stmt, knl_rsrc_plan_t *knl_plan)
{
    char ddl_sql[SQL_BUFFER_SIZE];
    PRTS_RETURN_IFERR(snprintf_s(ddl_sql, SQL_BUFFER_SIZE, SQL_BUFFER_SIZE - 1,
        "BEGIN\n DBE_RSRC_MGR.UPDATE_PLAN(name=>'%s', comment=>'%s');\nEND;\n/", knl_plan->name,
        knl_plan->description));
    CT_LOG_DEBUG_INF("generated distribute ddl: [%s]", ddl_sql);
    CT_RETURN_IFERR(sql_pre_exec_resource_manager(stmt));
    return CT_SUCCESS;
}

static status_t sql_create_rsrc_plan(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    status_t status;
    knl_rsrc_plan_t knl_plan;
    variant_t name, comment;
    source_location_t loc;
    variant_t value;

    /* plan_name */
    CT_RETURN_IFERR(sql_get_dbe_param_value_loc(stmt, func, g_create_plan_params, 1, &name, &loc));
    CT_RETURN_IFERR(sql_check_object_name(&name.v_text, "resource plan", loc));
    process_name_case_sensitive(&name.v_text);
    /* case insensitive */
    cm_text_upper(&name.v_text);
    CT_RETURN_IFERR(cm_text2str(&name.v_text, knl_plan.name, CT_NAME_BUFFER_SIZE));

    /* comment */
    CT_RETURN_IFERR(sql_get_dbe_param_value(stmt, func, g_create_plan_params, 2, &comment));
    if (!comment.is_null && comment.v_text.len > 0) {
        CT_RETURN_IFERR(cm_text2str(&comment.v_text, knl_plan.description, CT_COMMENT_SIZE + 1));
    } else {
        knl_plan.description[0] = '\0';
    }

    /* type */
    CT_RETURN_IFERR(sql_get_dbe_param_value_loc(stmt, func, g_create_plan_params, 3, &value, &loc));
    if (!value.is_null) {
        if (value.v_int != PLAN_TYPE_USER && value.v_int != PLAN_TYPE_TENANT) {
            CT_SRC_THROW_ERROR(loc, ERR_FUNC_ARGUMENT_OUT_OF_RANGE);
            return CT_ERROR;
        }
        knl_plan.type = value.v_int;
    } else {
        knl_plan.type = PLAN_TYPE_USER;
    }

    SQL_SET_NULL_VAR(result);
    knl_plan.num_rules = 0;

#ifdef Z_SHARDING
    if (IS_COORDINATOR && IS_APP_CONN(stmt->session)) {
        CT_RETURN_IFERR(sql_pre_exec_create_rsrc_plan(stmt, &knl_plan));
    }
#endif // Z_SHARDING

    status = knl_create_rsrc_plan(KNL_SESSION(stmt), &knl_plan);
    return sql_after_exec_resource_manager(stmt, status);
}

static status_t sql_verify_create_rsrc_plan(sql_verifier_t *verf, expr_node_t *func)
{
    if (sql_verify_func_node(verf, func, 1, 3, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (sql_verify_dbe_func(verf, func, g_create_plan_params,
        sizeof(g_create_plan_params) / sizeof(dbe_func_param_t)) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return sql_verify_dbe_resmgr(verf->stmt);
}

static status_t sql_delete_rsrc_plan(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    status_t status;
    variant_t name;
    source_location_t loc;

    /* plan_name */
    CT_RETURN_IFERR(sql_get_dbe_param_value_loc(stmt, func, g_delete_plan_params, 1, &name, &loc));
    CT_RETURN_IFERR(sql_check_object_name(&name.v_text, "resource plan", loc));
    process_name_case_sensitive(&name.v_text);
    cm_text_upper(&name.v_text);
    sql_keep_stack_variant(stmt, &name);

    if (sql_check_rsrc_plan_referenced(&name.v_text)) {
        CT_THROW_ERROR(ERR_USER_IS_REFERENCED, "resource plan", T2S(&name.v_text), "being used");
        return CT_ERROR;
    }
    SQL_SET_NULL_VAR(result);

    status = knl_delete_rsrc_plan(KNL_SESSION(stmt), &name.v_text);
    return sql_after_exec_resource_manager(stmt, status);
}

static status_t sql_verify_delete_rsrc_plan(sql_verifier_t *verf, expr_node_t *func)
{
    if (sql_verify_func_node(verf, func, 1, 1, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (sql_verify_dbe_func(verf, func, g_delete_plan_params,
        sizeof(g_delete_plan_params) / sizeof(dbe_func_param_t)) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return sql_verify_dbe_resmgr(verf->stmt);
}

static status_t sql_update_rsrc_plan(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    status_t status;
    knl_rsrc_plan_t knl_plan;
    variant_t name, comment;
    source_location_t loc;

    /* plan_name */
    CT_RETURN_IFERR(sql_get_dbe_param_value_loc(stmt, func, g_update_plan_params, 1, &name, &loc));
    CT_RETURN_IFERR(sql_check_object_name(&name.v_text, "resource plan", loc));
    process_name_case_sensitive(&name.v_text);
    cm_text_upper(&name.v_text);
    CT_RETURN_IFERR(cm_text2str(&name.v_text, knl_plan.name, CT_NAME_BUFFER_SIZE));

    /* comment */
    CT_RETURN_IFERR(sql_get_dbe_param_value(stmt, func, g_update_plan_params, 2, &comment));
    if (!comment.is_null && comment.v_text.len > 0) {
        CT_RETURN_IFERR(cm_text2str(&comment.v_text, knl_plan.description, CT_COMMENT_SIZE + 1));
    } else {
        knl_plan.description[0] = '\0';
    }
    SQL_SET_NULL_VAR(result);

#ifdef Z_SHARDING
    if (IS_COORDINATOR && IS_APP_CONN(stmt->session)) {
        CT_RETURN_IFERR(sql_pre_exec_update_rsrc_plan(stmt, &knl_plan));
    }
#endif // Z_SHARDING
    status = knl_update_rsrc_plan(KNL_SESSION(stmt), &knl_plan);
    return sql_after_exec_resource_manager(stmt, status);
}

static status_t sql_verify_update_rsrc_plan(sql_verifier_t *verf, expr_node_t *func)
{
    if (sql_verify_func_node(verf, func, 1, 2, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (sql_verify_dbe_func(verf, func, g_update_plan_params,
        sizeof(g_update_plan_params) / sizeof(dbe_func_param_t)) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return sql_verify_dbe_resmgr(verf->stmt);
}

static status_t sql_validate_rsrc_plan(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t name;
    char plan_name[CT_NAME_BUFFER_SIZE];
    source_location_t loc;
    rsrc_plan_t *rsrc_plan = NULL;

    /* plan_name */
    CT_RETURN_IFERR(sql_get_dbe_param_value_loc(stmt, func, g_delete_plan_params, 1, &name, &loc));
    CT_RETURN_IFERR(sql_check_object_name(&name.v_text, "resource plan", loc));
    process_name_case_sensitive(&name.v_text);
    cm_text_upper(&name.v_text);
    CT_RETURN_IFERR(cm_text2str(&name.v_text, plan_name, CT_NAME_BUFFER_SIZE));
    SQL_SET_NULL_VAR(result);

    if (rsrc_load_plan(KNL_SESSION(stmt), plan_name, &rsrc_plan) != CT_SUCCESS) {
        return CT_ERROR;
    }
    mctx_destroy(rsrc_plan->memory);
    return CT_SUCCESS;
}

static status_t sql_verify_validate_rsrc_plan(sql_verifier_t *verf, expr_node_t *func)
{
    if (sql_verify_func_node(verf, func, 1, 1, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (sql_verify_dbe_func(verf, func, g_validate_plan_params,
        sizeof(g_validate_plan_params) / sizeof(dbe_func_param_t)) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static inline status_t sql_verify_plan_rule_value(variant_t *value, uint32 max_value, source_location_t loc)
{
    if (var_as_integer(value) != CT_SUCCESS) {
        cm_set_error_loc(loc);
        return CT_ERROR;
    }
    if (value->v_int < 0 && value->v_int != -1) {
        CT_SRC_THROW_ERROR(loc, ERR_FUNC_ARGUMENT_OUT_OF_RANGE);
        return CT_ERROR;
    }
    if ((uint32)value->v_int > max_value) {
        CT_SRC_THROW_ERROR(loc, ERR_FUNC_ARGUMENT_OUT_OF_RANGE);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t sql_prepare_plan_rule_def(sql_stmt_t *stmt, expr_node_t *func, dbe_func_param_t *dbe_param,
    knl_rsrc_plan_rule_def_t *def)
{
    variant_t value;
    source_location_t loc;
    def->is_option_set = CT_FALSE;

    /* plan_name */
    CT_RETURN_IFERR(sql_get_dbe_param_value_loc(stmt, func, dbe_param, 1, &value, &loc));
    CT_RETURN_IFERR(sql_check_object_name(&value.v_text, "resource plan", loc));
    process_name_case_sensitive(&value.v_text);
    cm_text_upper(&value.v_text);
    CT_RETURN_IFERR(cm_text2str(&value.v_text, def->rule.plan_name, CT_NAME_BUFFER_SIZE));

    /* group_name */
    CT_RETURN_IFERR(sql_get_dbe_param_value_loc(stmt, func, dbe_param, 2, &value, &loc));
    CT_RETURN_IFERR(sql_check_object_name(&value.v_text, "control group", loc));
    process_name_case_sensitive(&value.v_text);
    cm_text_upper(&value.v_text);
    CT_RETURN_IFERR(cm_text2str(&value.v_text, def->rule.group_name, CT_NAME_BUFFER_SIZE));

    /* description */
    CT_RETURN_IFERR(sql_get_dbe_param_value(stmt, func, dbe_param, 3, &value));
    if (!value.is_null) {
        CT_RETURN_IFERR(cm_text2str(&value.v_text, def->rule.description, CT_COMMENT_SIZE + 1));
        def->is_comment_set = CT_TRUE;
    }

    /* cpu */
    CT_RETURN_IFERR(sql_get_dbe_param_value_loc(stmt, func, dbe_param, 4, &value, &loc));
    if (!value.is_null) {
        CT_RETURN_IFERR(sql_verify_plan_rule_value(&value, 100, loc));
        def->rule.max_cpu_limit = (uint32)value.v_int;
        def->is_cpu_set = CT_TRUE;
    }

    /* sessions */
    CT_RETURN_IFERR(sql_get_dbe_param_value_loc(stmt, func, dbe_param, 5, &value, &loc));
    if (!value.is_null) {
        CT_RETURN_IFERR(sql_verify_plan_rule_value(&value, CT_MAX_UINT32, loc));
        def->rule.max_sessions = (uint32)value.v_int;
        def->is_sessions_set = CT_TRUE;
    }

    /* active session */
    CT_RETURN_IFERR(sql_get_dbe_param_value_loc(stmt, func, dbe_param, 6, &value, &loc));
    if (!value.is_null) {
        CT_RETURN_IFERR(sql_verify_plan_rule_value(&value, CT_MAX_UINT32, loc));
        def->rule.max_active_sess = (uint32)value.v_int;
        def->is_active_sess_set = CT_TRUE;
    }

    /* queue time */
    CT_RETURN_IFERR(sql_get_dbe_param_value_loc(stmt, func, dbe_param, 7, &value, &loc));
    if (!value.is_null) {
        CT_RETURN_IFERR(sql_verify_plan_rule_value(&value, CT_MAX_UINT32, loc));
        def->rule.max_queue_time = (uint32)value.v_int;
        def->is_queue_time_set = CT_TRUE;
    }

    /* max estimate exec time */
    CT_RETURN_IFERR(sql_get_dbe_param_value_loc(stmt, func, dbe_param, 8, &value, &loc));
    if (!value.is_null) {
        CT_RETURN_IFERR(sql_verify_plan_rule_value(&value, CT_MAX_UINT32, loc));
        def->rule.max_exec_time = (uint32)value.v_int;
        def->is_exec_time_set = CT_TRUE;
    }

    /* temp pool */
    CT_RETURN_IFERR(sql_get_dbe_param_value_loc(stmt, func, dbe_param, 9, &value, &loc));
    if (!value.is_null) {
        if (var_as_integer(&value) != CT_SUCCESS) {
            cm_set_error_loc(loc);
            return CT_ERROR;
        }
        if (value.v_int != -1) {
            int64 bytes = (int64)((uint64)value.v_uint32 << 20);
            if (bytes < CT_MIN_TEMP_BUFFER_SIZE || bytes > CT_MAX_TEMP_BUFFER_SIZE) {
                CT_SRC_THROW_ERROR(loc, ERR_FUNC_ARGUMENT_OUT_OF_RANGE);
                return CT_ERROR;
            }
        }
        def->rule.max_temp_pool = (uint32)value.v_int;
        def->is_temp_pool_set = CT_TRUE;
    }

    /* iops */
    CT_RETURN_IFERR(sql_get_dbe_param_value_loc(stmt, func, dbe_param, 10, &value, &loc));
    if (!value.is_null) {
        CT_RETURN_IFERR(sql_verify_plan_rule_value(&value, CT_MAX_UINT32, loc));
        def->rule.max_iops = (uint32)value.v_int;
        def->is_iops_set = CT_TRUE;
    }

    /* commits */
    CT_RETURN_IFERR(sql_get_dbe_param_value_loc(stmt, func, dbe_param, 11, &value, &loc));
    if (!value.is_null) {
        CT_RETURN_IFERR(sql_verify_plan_rule_value(&value, CT_MAX_UINT32, loc));
        def->rule.max_commits = (uint32)value.v_int;
        def->is_commits_set = CT_TRUE;
    }
    return CT_SUCCESS;
}

static inline status_t sql_pre_exec_remove_plan_rule(sql_stmt_t *stmt, text_t *plan_name, text_t *group_name)
{
    char ddl_sql[SQL_BUFFER_SIZE];

    PRTS_RETURN_IFERR(snprintf_s(ddl_sql, SQL_BUFFER_SIZE, SQL_BUFFER_SIZE - 1,
        "BEGIN\n DBE_RSRC_MGR.REMOVE_PLAN_RULE(plan_name=>'%s', control_group=>'%s');\nEND;\n/", T2S(plan_name),
        T2S_EX(group_name)));
    CT_LOG_DEBUG_INF("generated distribute ddl: [%s]", ddl_sql);
    CT_RETURN_IFERR(sql_pre_exec_resource_manager(stmt));
    return CT_SUCCESS;
}

static status_t sql_create_plan_rule(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    status_t status;
    knl_rsrc_plan_rule_def_t def;

    CT_RETURN_IFERR(sql_prepare_plan_rule_def(stmt, func, g_create_plan_rule_params, &def));
    def.is_update = CT_FALSE;
    SQL_SET_NULL_VAR(result);

    status = knl_create_rsrc_plan_rule(KNL_SESSION(stmt), &def);
    return sql_after_exec_resource_manager(stmt, status);
}

static status_t sql_verify_create_plan_rule(sql_verifier_t *verf, expr_node_t *func)
{
    if (sql_verify_func_node(verf, func, 2, ELEMENT_COUNT(g_create_plan_rule_params), CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (sql_verify_dbe_func(verf, func, g_create_plan_rule_params, ELEMENT_COUNT(g_create_plan_rule_params)) !=
        CT_SUCCESS) {
        return CT_ERROR;
    }
    return sql_verify_dbe_resmgr(verf->stmt);
}

static status_t sql_remove_plan_rule(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    status_t status;
    variant_t plan_name, group_name;
    source_location_t loc;

    /* plan_name */
    CT_RETURN_IFERR(sql_get_dbe_param_value_loc(stmt, func, g_remove_plan_rule_params, 1, &plan_name, &loc));
    CT_RETURN_IFERR(sql_check_object_name(&plan_name.v_text, "resource plan", loc));
    process_name_case_sensitive(&plan_name.v_text);
    cm_text_upper(&plan_name.v_text);
    sql_keep_stack_variant(stmt, &plan_name);

    /* group_name */
    CT_RETURN_IFERR(sql_get_dbe_param_value_loc(stmt, func, g_remove_plan_rule_params, 2, &group_name, &loc));
    CT_RETURN_IFERR(sql_check_object_name(&group_name.v_text, "control group", loc));
    process_name_case_sensitive(&group_name.v_text);
    cm_text_upper(&group_name.v_text);
    sql_keep_stack_variant(stmt, &group_name);
    SQL_SET_NULL_VAR(result);

#ifdef Z_SHARDING
    if (IS_COORDINATOR && IS_APP_CONN(stmt->session)) {
        CT_RETURN_IFERR(sql_pre_exec_remove_plan_rule(stmt, &plan_name.v_text, &group_name.v_text));
    }
#endif // Z_SHARDING

    status = knl_delete_rsrc_plan_rule(KNL_SESSION(stmt), &plan_name.v_text, &group_name.v_text);
    return sql_after_exec_resource_manager(stmt, status);
}

static status_t sql_verify_remove_plan_rule(sql_verifier_t *verf, expr_node_t *func)
{
    if (sql_verify_func_node(verf, func, 2, 2, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (sql_verify_dbe_func(verf, func, g_remove_plan_rule_params, 2) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return sql_verify_dbe_resmgr(verf->stmt);
}

static status_t sql_update_plan_rule(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    status_t status;
    knl_rsrc_plan_rule_def_t def;
    CT_RETURN_IFERR(sql_prepare_plan_rule_def(stmt, func, g_update_plan_rule_params, &def));
    def.is_update = CT_TRUE;
    SQL_SET_NULL_VAR(result);

    status = knl_update_rsrc_plan_rule(KNL_SESSION(stmt), &def);
    return sql_after_exec_resource_manager(stmt, status);
}

static status_t sql_verify_update_plan_rule(sql_verifier_t *verf, expr_node_t *func)
{
    if (sql_verify_func_node(verf, func, 2, ELEMENT_COUNT(g_update_plan_rule_params), CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (sql_verify_dbe_func(verf, func, g_update_plan_rule_params, ELEMENT_COUNT(g_update_plan_rule_params)) !=
        CT_SUCCESS) {
        return CT_ERROR;
    }
    return sql_verify_dbe_resmgr(verf->stmt);
}

static inline status_t sql_verify_map_attribte(text_t *attr, source_location_t loc)
{
    if (!cm_text_str_equal_ins(attr, "db_user") && !cm_text_str_equal_ins(attr, "tenant")) {
        CT_SRC_THROW_ERROR(loc, ERR_INVALID_FUNC_PARAMS, "invalid ATTRIBUTE argument specified");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static inline status_t sql_pre_exec_add_user_to_cgroup(sql_stmt_t *stmt, knl_rsrc_group_mapping_t *knl_map)
{
    char ddl_sql[SQL_BUFFER_SIZE];

    PRTS_RETURN_IFERR(snprintf_s(ddl_sql, SQL_BUFFER_SIZE, SQL_BUFFER_SIZE - 1,
        "BEGIN\n DBE_RSRC_MGR.ADD_USER_TO_CONTROL_GROUP(name=>'%s', control_group=>'%s');\nEND;\n/", knl_map->value,
        knl_map->group_name));
    CT_LOG_DEBUG_INF("generated distribute ddl: [%s]", ddl_sql);
    CT_RETURN_IFERR(sql_pre_exec_resource_manager(stmt));
    return CT_SUCCESS;
}

static status_t sql_add_user_to_cgroup(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    status_t status;
    knl_rsrc_group_mapping_t knl_map;
    variant_t value, group;
    source_location_t loc;
    char buf[CT_NAME_BUFFER_SIZE];

    /* attribute */
    text_t attr_txt = { "DB_USER", 7 };
    CT_RETURN_IFERR(cm_text2str(&attr_txt, knl_map.attribute, CT_NAME_BUFFER_SIZE));

    /* value */
    CT_RETURN_IFERR(sql_get_dbe_param_value_loc(stmt, func, g_add_user_to_group_params, 1, &value, &loc));
    CT_RETURN_IFERR(sql_check_object_name(&value.v_text, "user", loc));
    process_name_case_sensitive(&value.v_text);

    CT_RETURN_IFERR(sql_user_text_prefix_tenant(stmt->session, &value.v_text, buf, CT_NAME_BUFFER_SIZE));
    CT_RETURN_IFERR(cm_text2str(&value.v_text, knl_map.value, CT_VALUE_BUFFER_SIZE));

    /* control_group */
    CT_RETURN_IFERR(sql_get_dbe_param_value_loc(stmt, func, g_add_user_to_group_params, 2, &group, &loc));
    if (group.is_null) {
        knl_map.group_name[0] = '\0';
    } else {
        CT_RETURN_IFERR(sql_check_object_name(&group.v_text, "control_group", loc));
        process_name_case_sensitive(&group.v_text);
        cm_text_upper(&group.v_text);
        CT_RETURN_IFERR(cm_text2str(&group.v_text, knl_map.group_name, CT_NAME_BUFFER_SIZE));
    }
    SQL_SET_NULL_VAR(result);

    status = knl_set_cgroup_mapping(KNL_SESSION(stmt), &knl_map);
    return sql_after_exec_resource_manager(stmt, status);
}

static status_t sql_add_tenant_to_cgroup(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    status_t status;
    knl_rsrc_group_mapping_t knl_map;
    variant_t value, group;
    source_location_t loc;

    /* attribute */
    text_t attr_txt = { "TENANT", 6 };
    CT_RETURN_IFERR(cm_text2str(&attr_txt, knl_map.attribute, CT_NAME_BUFFER_SIZE));

    /* value */
    CT_RETURN_IFERR(sql_get_dbe_param_value_loc(stmt, func, g_add_user_to_group_params, 1, &value, &loc));
    CT_RETURN_IFERR(sql_check_tenant_name(&value.v_text, loc));
    process_name_case_sensitive(&value.v_text);
    cm_text_upper(&value.v_text);
    CT_RETURN_IFERR(cm_text2str(&value.v_text, knl_map.value, CT_VALUE_BUFFER_SIZE));

    /* control_group */
    CT_RETURN_IFERR(sql_get_dbe_param_value_loc(stmt, func, g_add_user_to_group_params, 2, &group, &loc));
    if (group.is_null) {
        knl_map.group_name[0] = '\0';
    } else {
        CT_RETURN_IFERR(sql_check_object_name(&group.v_text, "control_group", loc));
        process_name_case_sensitive(&group.v_text);
        cm_text_upper(&group.v_text);
        CT_RETURN_IFERR(cm_text2str(&group.v_text, knl_map.group_name, CT_NAME_BUFFER_SIZE));
    }
    SQL_SET_NULL_VAR(result);

    status = knl_set_cgroup_mapping(KNL_SESSION(stmt), &knl_map);
    return sql_after_exec_resource_manager(stmt, status);
}

static status_t sql_verify_add_user_to_cgroup(sql_verifier_t *verf, expr_node_t *func)
{
    if (sql_verify_func_node(verf, func, 1, 2, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (sql_verify_dbe_func(verf, func, g_add_user_to_group_params,
        sizeof(g_add_user_to_group_params) / sizeof(dbe_func_param_t)) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return sql_verify_dbe_resmgr(verf->stmt);
}

static status_t set_policy_stmt_type(text_t *split_text, policy_def_t *def)
{
    text_t left, right;
    text_t select = { "select", 6 };
    text_t insert = { "insert", 6 };
    text_t update = { "update", 6 };
    text_t delete = { "delete", 6 };

    do {
        cm_split_text(split_text, ',', '\0', &left, &right);
        split_text = &right;
        if (cm_text_equal_ins(&left, &select)) {
            def->stmt_types |= (uint8)STMT_SELECT;
        } else if (cm_text_equal_ins(&left, &insert)) {
            def->stmt_types |= (uint8)STMT_INSERT;
        } else if (cm_text_equal_ins(&left, &update)) {
            def->stmt_types |= (uint8)STMT_UPDATE;
        } else if (cm_text_equal_ins(&left, &delete)) {
            def->stmt_types |= (uint8)STMT_DELETE;
        } else {
            CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "invalid parameters");
            return CT_ERROR;
        }
    } while (split_text->len != 0 && split_text->str != NULL);

    return CT_SUCCESS;
}

static status_t sql_write_sys_policies(sql_stmt_t *stmt, policy_def_t *def)
{
    knl_session_t *session = &stmt->session->knl_session;
    var_udo_t obj;
    bool32 exists = CT_FALSE;

    /* verify function_owner and function */
    obj.user = def->function_owner;
    obj.pack = CM_NULL_TEXT;
    obj.name = def->function;
    obj.name_sensitive = CT_TRUE;

    if (pl_find_entry(KNL_SESSION(stmt), &obj.user, &obj.name, PL_FUNCTION, NULL, &exists) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!exists) {
        CT_THROW_ERROR(ERR_USER_OBJECT_NOT_EXISTS, "function", T2S(&def->function_owner), T2S_EX(&def->function));
        return CT_ERROR;
    }

    CT_RETURN_IFERR(knl_write_sys_policy(session, def));
    return CT_SUCCESS;
}

static status_t sql_add_policy(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    policy_def_t def;
    text_t split_text;
    variant_t object_owner, object_name, policy_name, function_owner, function, statement_types, enable;
    char buf[CT_NAME_BUFFER_SIZE];
    status_t ret = CT_ERROR;

    CM_POINTER3(stmt, func, result);
    SQL_SET_NULL_VAR(result);

    CTSQL_SAVE_STACK(stmt);

    do {
        CT_BREAK_IF_ERROR(pl_check_trig_and_udf(stmt));

        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_add_policy_params, 1, &object_owner));
        sql_keep_stack_var(stmt, &object_owner);
        CT_BREAK_IF_ERROR(sql_user_text_prefix_tenant(stmt->session, &object_owner.v_text, buf, CT_NAME_BUFFER_SIZE));

        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_add_policy_params, 2, &object_name));
        sql_keep_stack_var(stmt, &object_name);

        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_add_policy_params, 3, &policy_name));
        sql_keep_stack_var(stmt, &policy_name);

        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_add_policy_params, 4, &function_owner));
        sql_keep_stack_var(stmt, &function_owner);

        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_add_policy_params, 5, &function));
        sql_keep_stack_var(stmt, &function);

        def.object_owner = object_owner.v_text;
        cm_text_upper(&def.object_owner);
        def.object_name = object_name.v_text;
        process_name_case_sensitive(&def.object_name);
        def.policy_name = policy_name.v_text;
        process_name_case_sensitive(&def.policy_name);
        def.function_owner = function_owner.v_text;
        cm_text_upper(&def.function_owner);
        def.function = function.v_text;
        process_name_case_sensitive(&def.function);

        /* statement_types */
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_add_policy_params, 6, &statement_types));
        sql_keep_stack_var(stmt, &statement_types);
        def.stmt_types = 0;
        def.ptype = 0; // ptype reserved

        if (statement_types.is_null) {
            def.stmt_types = STMT_SELECT; // default: select
        } else {
            split_text = statement_types.v_text;
            if (set_policy_stmt_type(&split_text, &def) != CT_SUCCESS) {
                break;
            }
        }

        /* update_check */
        def.check_option = CT_FALSE;

        /* enable */
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_add_policy_params, 7, &enable));
        def.enable = enable.is_null ? CT_TRUE : enable.v_bool ? CT_TRUE : CT_FALSE;

        /* long_predicate */
        def.long_predicate = CT_FALSE;

        CT_BREAK_IF_ERROR(sql_write_sys_policies(stmt, &def));
        ret = CT_SUCCESS;
    } while (0);

    CTSQL_RESTORE_STACK(stmt);
    return ret;
}

static status_t sql_verify_add_policy(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);
    if (sql_verify_func_node(verf, func, 5, 7, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return sql_verify_dbe_func(verf, func, g_add_policy_params, sizeof(g_add_policy_params) / sizeof(dbe_func_param_t));
}

static status_t sql_drop_policy(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    policy_def_t def;
    variant_t object_owner, object_name, policy_name;
    char buf[CT_NAME_BUFFER_SIZE];
    status_t ret = CT_ERROR;

    CM_POINTER3(stmt, func, result);
    SQL_SET_NULL_VAR(result);

    CTSQL_SAVE_STACK(stmt);

    do {
        CT_BREAK_IF_ERROR(pl_check_trig_and_udf(stmt));

        /* object_owner */
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_drop_policy_params, 1, &object_owner));
        /* the value kept will be release at the end of this function */
        sql_keep_stack_var(stmt, &object_owner);
        CT_BREAK_IF_ERROR(sql_user_text_prefix_tenant(stmt->session, &object_owner.v_text, buf, CT_NAME_BUFFER_SIZE));

        /* object_name */
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_drop_policy_params, 2, &object_name));
        /* the value kept will be release at the end of this function */
        sql_keep_stack_var(stmt, &object_name);
        /* policy_name */
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_drop_policy_params, 3, &policy_name));
        /* the value kept will be release at the end of this function */
        sql_keep_stack_var(stmt, &policy_name);

        def.object_owner = object_owner.v_text;
        cm_text_upper(&def.object_owner);
        def.object_name = object_name.v_text;
        process_name_case_sensitive(&def.object_name);
        def.policy_name = policy_name.v_text;
        process_name_case_sensitive(&def.policy_name);

        /* delete from sys_policies */
        CT_BREAK_IF_ERROR(knl_modify_sys_policy(&stmt->session->knl_session, &def, CURSOR_ACTION_DELETE));
        ret = CT_SUCCESS;
    } while (0);

    CTSQL_RESTORE_STACK(stmt);
    return ret;
}

static status_t sql_verify_drop_policy(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);
    if (sql_verify_func_node(verf, func, 3, 3, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return sql_verify_dbe_func(verf, func, g_drop_policy_params,
        sizeof(g_drop_policy_params) / sizeof(dbe_func_param_t));
}

static status_t sql_enable_policy(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    policy_def_t def;
    variant_t object_owner, object_name, policy_name, enable;
    char buf[CT_NAME_BUFFER_SIZE];
    status_t ret = CT_ERROR;

    CM_POINTER3(stmt, func, result);
    SQL_SET_NULL_VAR(result);

    CTSQL_SAVE_STACK(stmt);

    do {
        CT_BREAK_IF_ERROR(pl_check_trig_and_udf(stmt));

        /* object_owner */
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_enable_policy_params, 1, &object_owner));
        /* the value kept will be release at the end of this function */
        sql_keep_stack_var(stmt, &object_owner);
        CT_BREAK_IF_ERROR(sql_user_text_prefix_tenant(stmt->session, &object_owner.v_text, buf, CT_NAME_BUFFER_SIZE));

        /* object_name */
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_enable_policy_params, 2, &object_name));
        /* the value kept will be release at the end of this function */
        sql_keep_stack_var(stmt, &object_name);
        /* policy_name */
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_enable_policy_params, 3, &policy_name));
        /* the value kept will be release at the end of this function */
        sql_keep_stack_var(stmt, &policy_name);
        /* enable */
        CT_BREAK_IF_ERROR(sql_get_dbe_param_value(stmt, func, g_enable_policy_params, 4, &enable));
        /* the value kept will be release at the end of this function */
        sql_keep_stack_var(stmt, &enable);

        def.object_owner = object_owner.v_text;
        cm_text_upper(&def.object_owner);
        def.object_name = object_name.v_text;
        process_name_case_sensitive(&def.object_name);
        def.policy_name = policy_name.v_text;
        process_name_case_sensitive(&def.policy_name);
        def.enable = enable.v_bool ? CT_TRUE : CT_FALSE;

        /* update sys_policies */
        CT_BREAK_IF_ERROR(knl_modify_sys_policy(&stmt->session->knl_session, &def, CURSOR_ACTION_UPDATE));
        ret = CT_SUCCESS;
    } while (0);

    CTSQL_RESTORE_STACK(stmt);
    return ret;
}

static status_t sql_verify_enable_policy(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);
    if (sql_verify_func_node(verf, func, 4, 4, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return sql_verify_dbe_func(verf, func, g_enable_policy_params,
        sizeof(g_enable_policy_params) / sizeof(dbe_func_param_t));
}

static sql_func_t g_dbe_rls_funcs[] = {
    { { (char *)"add_policy", 10 }, sql_add_policy, sql_verify_add_policy, AGGR_TYPE_NONE, FO_PROC, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"drop_policy", 11 }, sql_drop_policy, sql_verify_drop_policy, AGGR_TYPE_NONE, FO_PROC, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"enable_policy", 13 }, sql_enable_policy, sql_verify_enable_policy, AGGR_TYPE_NONE, FO_PROC, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
};

static sql_func_t g_dbe_resmgr_funcs[] = {
    { { (char *)"add_tenant_to_control_group", 27 }, sql_add_tenant_to_cgroup, sql_verify_add_user_to_cgroup, AGGR_TYPE_NONE, FO_PROC, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"add_user_to_control_group", 25 }, sql_add_user_to_cgroup, sql_verify_add_user_to_cgroup, AGGR_TYPE_NONE, FO_PROC, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"create_control_group", 20 }, sql_create_cgroup, sql_verify_create_cgroup, AGGR_TYPE_NONE, FO_PROC, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"create_plan", 11 }, sql_create_rsrc_plan, sql_verify_create_rsrc_plan, AGGR_TYPE_NONE, FO_PROC, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"create_plan_rule", 16 }, sql_create_plan_rule, sql_verify_create_plan_rule, AGGR_TYPE_NONE, FO_PROC, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"delete_control_group", 20 }, sql_delete_cgroup, sql_verify_delete_cgroup, AGGR_TYPE_NONE, FO_PROC, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"delete_plan", 11 }, sql_delete_rsrc_plan, sql_verify_delete_rsrc_plan, AGGR_TYPE_NONE, FO_PROC, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"remove_plan_rule", 16 }, sql_remove_plan_rule, sql_verify_remove_plan_rule, AGGR_TYPE_NONE, FO_PROC, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"update_control_group", 20 }, sql_update_cgroup, sql_verify_update_cgroup, AGGR_TYPE_NONE, FO_PROC, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"update_plan", 11 }, sql_update_rsrc_plan, sql_verify_update_rsrc_plan, AGGR_TYPE_NONE, FO_PROC, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"update_plan_rule", 16 }, sql_update_plan_rule, sql_verify_update_plan_rule, AGGR_TYPE_NONE, FO_PROC, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
    { { (char *)"validate_plan", 13 }, sql_validate_rsrc_plan, sql_verify_validate_rsrc_plan, AGGR_TYPE_NONE, FO_PROC, CT_INVALID_ID32, CT_INVALID_VALUE_CNT, CT_FALSE },
};
#define DBE_JOB_FUNC_COUNT (sizeof(g_dbe_job_funcs) / sizeof(sql_func_t))
#define DBE_RANDOM_FUNC_COUNT (sizeof(g_dbe_random_funcs) / sizeof(sql_func_t))
#define DBE_OUTPUT_FUNC_COUNT (sizeof(g_dbe_output_funcs) / sizeof(sql_func_t))
#define DBE_SQL_FUNC_COUNT (sizeof(g_dbe_sql_funcs) / sizeof(sql_func_t))
#define DBE_STANDARD_FUNC_COUNT (sizeof(g_dbe_standard_funcs) / sizeof(sql_func_t))
#define DBE_STATS_FUNC_COUNT (sizeof(g_dbe_stats_funcs) / sizeof(sql_func_t))
#define DBE_UTILITY_FUNC_COUNT (sizeof(g_dbe_utility_funcs) / sizeof(sql_func_t))
#define DBE_LOB_FUNC_COUNT (sizeof(g_dbe_lob_funcs) / sizeof(sql_func_t))
#define DBE_DIAGNOSE_FUNC_COUNT (sizeof(g_dbe_diagnose_funcs) / sizeof(sql_func_t))
#define DBE_DEBUG_FUNC_COUNT (sizeof(g_dbe_debug_funcs) / sizeof(sql_func_t))
#define DBE_REDACT_COUNT (sizeof(g_dbe_redact_funcs) / sizeof(sql_func_t))
#define DBE_RESMGR_FUNC_COUNT (sizeof(g_dbe_resmgr_funcs) / sizeof(sql_func_t))
#define DBE_RLS_FUNC_COUNT (sizeof(g_dbe_rls_funcs) / sizeof(sql_func_t))

static sql_package_t g_builtin_packs[] = {
    { { "DBE_AC_ROW", 10 }, 0, NULL, DBE_RLS_FUNC_COUNT, g_dbe_rls_funcs, DBE_AC_ROW_PACK_ID },
    { { "DBE_DEBUG", 9 }, 0, NULL, DBE_DEBUG_FUNC_COUNT, g_dbe_debug_funcs, DBE_DEBUG_PACK_ID },
    { { "DBE_DIAGNOSE", 12 }, 0, NULL, DBE_DIAGNOSE_FUNC_COUNT, g_dbe_diagnose_funcs, DBE_DIAGNOSE_PACK_ID },
    { { "DBE_LOB", 7 }, 0, NULL, DBE_LOB_FUNC_COUNT, g_dbe_lob_funcs, DBE_LOB_PACK_ID },
    { { "DBE_MASK_DATA", 13 }, 0, NULL, DBE_REDACT_COUNT, g_dbe_redact_funcs, DBE_MASK_DATA_PACK_ID },
    { { "DBE_OUTPUT", 10 }, 0, NULL, DBE_OUTPUT_FUNC_COUNT, g_dbe_output_funcs, DBE_OUTPUT_PACK_ID },
    { { "DBE_RANDOM", 10 }, 0, NULL, DBE_RANDOM_FUNC_COUNT, g_dbe_random_funcs, DBE_RANDOM_PACK_ID },
    { { "DBE_RSRC_MGR", 12 }, 0, NULL, DBE_RESMGR_FUNC_COUNT, g_dbe_resmgr_funcs, DBE_RSRC_MGR_PACK_ID },
    { { "DBE_SQL", 7 }, 0, NULL, DBE_SQL_FUNC_COUNT, g_dbe_sql_funcs, DBE_SQL_PACK_ID },
    { { "DBE_STATS", 9 }, 0, NULL, DBE_STATS_FUNC_COUNT, g_dbe_stats_funcs, DBE_STATS_PACK_ID },
    { { "DBE_STD", 7 }, 0, NULL, DBE_STANDARD_FUNC_COUNT, g_dbe_standard_funcs, DBE_STD_PACK_ID },
    { { "DBE_TASK", 8 }, 0, NULL, DBE_JOB_FUNC_COUNT, g_dbe_job_funcs, DBE_TASK_PACK_ID },
    { { "DBE_UTIL", 8 }, 0, NULL, DBE_UTILITY_FUNC_COUNT, g_dbe_utility_funcs, DBE_UTIL_PACK_ID },
};

#define SQL_PACKAGE_COUNT (sizeof(g_builtin_packs) / sizeof(sql_package_t))

text_t *sql_pack_name(void *set, uint32 id)
{
    return &g_builtin_packs[id].name;
}

static text_t *sql_pack_func_name(void *set, uint32 id)
{
    sql_package_t *pack = (sql_package_t *)set;
    return &pack->funcs[id].name;
}

/*
 * package: DBE_STD
 */
void sql_convert_standard_pack_func(text_t *func_name, var_func_t *v)
{
    sql_package_t *pack = &g_builtin_packs[DBE_STD_PACK_ID];
    v->pack_id = DBE_STD_PACK_ID;
    v->func_id = sql_func_binsearch(func_name, sql_pack_func_name, pack, pack->func_count);
}

void sql_convert_pack_func(text_t *pack_name, text_t *func_name, var_func_t *v)
{
    v->pack_id = sql_func_binsearch(pack_name, sql_pack_name, NULL, SQL_PACKAGE_COUNT);

    if (v->pack_id == CT_INVALID_ID32) {
        v->func_id = CT_INVALID_ID32;
        v->orig_func_id = CT_INVALID_ID32;
        return;
    }

    sql_package_t *pack = &g_builtin_packs[v->pack_id];
    v->func_id = sql_func_binsearch(func_name, sql_pack_func_name, pack, pack->func_count);
}

void pl_convert_pack_func(uint32 pack_id, text_t *func_name, uint8 *func_id)
{
    sql_package_t *pack = &g_builtin_packs[pack_id];
    *func_id = (uint8)sql_func_binsearch(func_name, sql_pack_func_name, pack, pack->func_count);
}

sql_func_t *sql_get_pack_func(var_func_t *v)
{
    sql_package_t *pack = &g_builtin_packs[v->pack_id];
    return &pack->funcs[v->func_id];
}

status_t sql_invoke_pack_func(sql_stmt_t *stmt, expr_node_t *node, variant_t *result)
{
    uint32 pack_id, func_id;
    status_t status;

    CT_RETURN_IFERR(sql_stack_safe(stmt));

    pack_id = node->value.v_func.pack_id;
    func_id = node->value.v_func.func_id;

    if (pack_id >= SQL_PACKAGE_COUNT) {
        // only if some built-in functions been removed
        CT_THROW_ERROR(ERR_INVALID_PACKAGE, pack_id);
        return CT_ERROR;
    }
    sql_package_t *pack = &g_builtin_packs[pack_id];
    sql_func_t *func = &pack->funcs[func_id];
    CTSQL_SAVE_STACK(stmt);
    status = func->invoke(stmt, node, result);
    CTSQL_RESTORE_STACK(stmt);
    return status;
}

sql_package_t *sql_get_pack(uint32 id)
{
    return &g_builtin_packs[id];
}

uint32 sql_get_pack_num(void)
{
    return SQL_PACKAGE_COUNT;
}

bool32 sql_pack_exists(text_t *pack_name)
{
    if (sql_func_binsearch(pack_name, sql_pack_name, NULL, SQL_PACKAGE_COUNT) != CT_INVALID_ID32) {
        return CT_TRUE;
    } else {
        return CT_FALSE;
    }
}
