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
 * pl_procedure.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/meta/pl_procedure.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __PL_PROCEDURE_H__
#define __PL_PROCEDURE_H__


#include "knl_session.h"
#include "ctsql_stmt.h"
#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_procedure_desc_t procedure_desc_t;
typedef struct st_procedure procedure_t;
typedef struct st_procedure function_t;

struct st_procedure_desc_t {
    uint64 oid;
    char name[CT_NAME_BUFFER_SIZE];
    uint32 uid;
    uint32 proc_id;
    uint8 mods;            // modifier_t
    uint8 pl_type;         // pl_class_type_t
    uint16 arg_count;      // argument count
    uint16 outparam_count; // outparam count
    uint16 overload;
    galist_t *params;
    union {
        uint32 flags;
        struct {
            uint32 is_aggr : 1;
            uint32 pipelined : 1;
            uint32 is_synonym : 1;
            uint32 lang_type : 2; /* is plsql or clang */
            uint32 is_auton_trans : 1;
            uint32 is_function : 1;
            uint32 is_recursion : 1;
            uint32 unused_flag : 24;
        };
    };
    source_location_t loc; // in package or type sce
    uint32 option;
    uint64 lib_obj;
    knl_scn_t org_scn; // original scn
    knl_scn_t chg_scn; // scn when changed by DDL(alter)
};

struct st_procedure {
    void *body; // pl_body
    procedure_desc_t desc;
};

status_t pl_delete_sys_argument(knl_session_t *session, void *desc_in);
status_t pl_insert_proc_arg(knl_session_t *session, void *desc_in, void *pl_ctx_in);
status_t pl_insert_package_proc_args(knl_session_t *session, void *desc_in, void *pl_ctx_in);
status_t pl_load_entity_update_proc_table(knl_session_t *session, void *desc_in, void *entity_in);
status_t pl_get_proc_id_by_name(sql_stmt_t *stmt, text_t *user, text_t *object, uint32 *uid, uint64 *oid);
#ifdef __cplusplus
}
#endif

#endif