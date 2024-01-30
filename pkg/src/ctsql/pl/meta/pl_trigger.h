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
 * pl_trigger.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/meta/pl_trigger.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __PL_TRIGGER_H__
#define __PL_TRIGGER_H__

#include "ast.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum e_trig_dml_type {
    TRIG_EVENT_INSERT = 0x00000001,
    TRIG_EVENT_DELETE = 0x00000002,
    TRIG_EVENT_UPDATE = 0x00000004,
} trig_dml_type_t;

typedef struct st_trigger_column {
    char col_name[CT_NAME_BUFFER_SIZE];
    source_location_t loc;
    uint16 id;
    uint16 type;
} trigger_column_t;

typedef struct st_trig_pseudo_column {
    uint16 col_id;
    text_t name;
} trig_pseudo_column_t;

typedef enum en_trigger_type_t {
    TRIG_AFTER_STATEMENT,
    TRIG_AFTER_EACH_ROW,
    TRIG_BEFORE_STATEMENT,
    TRIG_BEFORE_EACH_ROW,
    TRIG_INSTEAD_OF,
} trigger_type_t;


typedef struct st_trig_col_t {
    uint32 col_id;
    uint32 type;
} trig_col_t;

typedef struct st_trig_desc_t {
    char name[CT_NAME_BUFFER_SIZE];
    uint32 uid;
    trigger_type_t type;
    uint16 events;
    uint16 enable;
    uint16 col_count;
    uint16 action_line;
    uint16 action_col;
    uint32 flags;
    uint32 obj_uid;
    uint64 base_obj;
    text_t real_user;
    text_t real_table;
    galist_t columns;
} trig_desc_t;

typedef struct st_trigger {
    pl_line_begin_t *body; // body statement, pl_line_body_t
    trig_desc_t desc;      // trigger desc
    galist_t *modified_new_cols;
} trigger_t;

void pl_free_trig_entity_by_tab(knl_handle_t knl_session, knl_dictionary_t *dc);
bool32 plc_trigger_verify_row_pesudo(const text_t *name, uint16 *col, text_t *decl_name);
status_t pl_load_sys_trigger(knl_session_t *session, uint64 oid, trig_desc_t *trig);
status_t pl_delete_systriger(knl_session_t *session, uint64 oid);
status_t pl_write_systrigger(knl_session_t *session, uint64 oid, trig_desc_t *trig_desc);
status_t pl_get_table_trigger_count(knl_session_t *session, void *trig_def, uint32 *trig_count);
status_t pl_update_trigger_enable_status(knl_session_t *session, uint64 oid, bool32 enable);
status_t pl_update_source_for_trigs(knl_handle_t knl_session, knl_dictionary_t *dc, text_t *name, text_t *new_name);
status_t pl_execute_alter_trigger(sql_stmt_t *stmt);
status_t pl_load_entity_update_trigger_table(knl_session_t *session, void *desc_in, void *entity_in);
status_t pl_update_sysproc_trigger_enable(knl_session_t *knl_session, void *desc_in, bool32 enable);
#ifdef __cplusplus
}
#endif

#endif
