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
 * func_others.h
 *
 *
 * IDENTIFICATION
 * src/cmd/function/func_others.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __FUNC_OTHERS_H__
#define __FUNC_OTHERS_H__
#include "srv_query.h"

extern char *cantiand_get_dbversion(void);

status_t sql_func_md5(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_md5(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_hash(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_hash(sql_verifier_t *verifier, expr_node_t *func);
status_t sql_func_gs_hash(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_gs_hash(sql_verifier_t *verifier, expr_node_t *func);
status_t sql_func_connection_id(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_connection_id(sql_verifier_t *verf, expr_node_t *func);
status_t sql_verify_found_rows(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_found_rows(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_func_dba_exec_ddl(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_dba_exec_ddl(sql_verifier_t *verifier, expr_node_t *func);
status_t sql_func_dba_cln_ddl(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_dba_cln_ddl(sql_verifier_t *verifier, expr_node_t *func);
status_t sql_func_updating(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_updating(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_least(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_func_greatest(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_least_greatest(sql_verifier_t *verifier, expr_node_t *func);
status_t sql_func_sys_context(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_sys_context(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_userenv(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_userenv(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_version(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_version(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_type_name(sql_stmt_t *stmt, expr_node_t *func, variant_t *res);
status_t sql_verify_to_type_mapped(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_scn2date(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_scn2date(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_gscn2date(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_gscn2date(sql_verifier_t *verf, expr_node_t *func);
status_t sql_verify_coalesce(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_coalesce(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_func_sys_guid(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_sys_guid(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_object_id(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_object_id(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_sha1(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_sha1(sql_verifier_t *verifier, expr_node_t *func);
status_t sql_func_soundex(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_soundex(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_serial_lastval(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_serial_lastval(sql_verifier_t *verifier, expr_node_t *func);
status_t sql_func_vsize(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_vsize(sql_verifier_t *verifier, expr_node_t *func);
status_t sql_verify_last_insert_id(sql_verifier_t *verifier, expr_node_t *func);
status_t sql_func_last_insert_id(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_func_is_numeric(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_is_numeric(sql_verifier_t *verifier, expr_node_t *func);
status_t sql_verify_alck_name(sql_verifier_t *verf, expr_node_t *func);
status_t sql_verify_alck_nm_and_to(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_get_lock(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_func_try_get_lock(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_func_release_lock(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_func_get_shared_lock(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_func_try_get_shared_lock(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_func_release_shared_lock(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_func_get_xact_lock(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_func_try_get_xact_lock(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_func_get_xact_shared_lock(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_func_try_get_xact_shared_lock(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_func_array_length(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_array_length(sql_verifier_t *verifier, expr_node_t *func);
status_t sql_verify_values(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_values(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);

/* *************************************************************************** */
/*           type declarations for internal use within sql_others.c            */
/* *************************************************************************** */
/* for SYS_CONTEXT */
typedef status_t (*sql_func_arg_processor)(sql_stmt_t *stmt, expr_tree_t *arg, variant_t *arg_var);
typedef status_t (*sql_func_sysctx_option_handler)(sql_stmt_t *stmt, int32 option_id, variant_t *result);

/* the possible object type which can be searched from system view USER_OBJECTS */
typedef enum en_funcoi_object_type {
    FUNC_OBJ_ID_TABLE = 0,
    FUNC_OBJ_ID_VIEW = 1,
    FUNC_OBJ_ID_DYNVIEW = 2,
    FUNC_OBJ_ID_PROCEDURE = 3,
    FUNC_OBJ_ID_FUNCTION = 4,
    FUNC_OBJ_ID_TRIGGER = 5,
    FUNC_OBJ_ID_TYPE_COUNT, /* @Note: DO NOT add new type below the "FUNC_OBJ_ID_TYPE_COUNT" */
} funcoi_object_type_t;

typedef struct st_funcoi_support_type {
    funcoi_object_type_t typeid;
    const char *typename;
} funcoi_support_type_t;

typedef struct st_funcctx_support_type {
    const char *namespc;
    sql_func_arg_processor option_processor;
    sql_func_sysctx_option_handler option_handler;
} funcctx_support_type_t;

typedef enum en_funcctx_option {
    FUNC_SYS_CTX_SID = 0,
    FUNC_SYS_CTX_TERMINAL = 1,
    FUNC_SYS_CTX_CURR_SCHEMA = 2,
    FUNC_SYS_CTX_CURR_SCHEMA_ID = 3,
    FUNC_SYS_CTX_DB_NAME = 4,
    FUNC_SYS_CTX_OS_USER = 5,
    FUNC_SYS_CTX_TENANT_NAME = 6,
    FUNC_SYS_CTX_TENANT_ID = 7,
    FUNC_SYS_CTX_OPTIONS_COUNT, /* @Note: DO NOT add new type below the "FUNC_SYS_CTX_OPTIONS_COUNT" */
} funcctx_option_t;

typedef struct st_funcctx_support_option {
    funcctx_option_t opid;
    const char *opname;
} funcctx_support_option_t;


#define ADVLCK_INIT_WITH_NAME_TIMEOUT(func, timeout, result)                                    \
    do {                                                                                        \
        CM_POINTER3(stmt, (func), (result));                                                      \
        GS_RETURN_IFERR(sql_func_alck_get_name(stmt, (func)->argument, &name));                   \
        SQL_CHECK_COLUMN_VAR(&name, (result));                                                  \
        if ((func)->argument->next) {                                                             \
            GS_RETURN_IFERR(sql_func_alck_get_timeout(stmt, (func)->argument->next, &(timeout))); \
            SQL_CHECK_COLUMN_VAR(&(timeout), (result));                                         \
        } else {                                                                                \
            (timeout).v_int = 0;                                                                \
        }                                                                                       \
        (result)->type = (func)->datatype;                                                        \
        (result)->is_null = GS_FALSE;                                                           \
    } while (0)

#define ADVLCK_INIT_WITH_NAME(result, func)                                     \
    do {                                                                        \
        CM_POINTER3(stmt, (func), (result));                                    \
        GS_RETURN_IFERR(sql_func_alck_get_name(stmt, (func)->argument, &name)); \
        SQL_CHECK_COLUMN_VAR(&name, (result));                                  \
        (result)->type = (func)->datatype;                                      \
        (result)->is_null = GS_FALSE;                                           \
    } while (0)

#endif
