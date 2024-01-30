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
 * pl_debugger.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/debug/pl_debugger.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __PL_DEBUGGER_H__
#define __PL_DEBUGGER_H__

#include "pl_dc.h"
#include "pl_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PLD_CURSOR_VALUE_LEN 128
#define PLD_INVALID_M_OFFSET 0

typedef enum en_pl_debug_version {
    PLD_VERSION_0 = 0, /* the first version */
} pl_debug_version_t;

typedef struct st_pld_exec_info {
    uint32 stack_id;
    pl_line_ctrl_t *curr_line;
} pld_exec_info_t;

typedef struct st_pld_block_info {
    uint32 stack_id;
    uint16 curr_stack_start;
    uint16 next_stack_start;
    uint32 *var_count;
    uint32 max_depth;
} pld_block_info_t;

typedef struct st_pld_cursor_info {
    bool8 is_open;
    bool8 has_fetched;
    bool8 is_found;
    uint8 res;
    uint32 rows;
} pld_cursor_info_t;

typedef struct st_pld_var_info {
    uint32 stack_id;
    int16 block_id;
    uint16 id;
    uint16 m_offset;
    bool8 is_attr_in_vm;
    bool8 is_obj;
    text_t name;
    text_t parent_name;
    text_t block_name;
    union {
        struct {
            variant_t get_value;
            variant_t *set_value;
            typmode_t type;
            pld_cursor_info_t cur_info;
        };
        struct {
            udt_mtrl_record_field_t field;
            plv_record_attr_t *attr;
            sql_stmt_t *curr_stmt;
        };
        struct {
            udt_mtrl_object_field_t obj_field;
            plv_object_attr_t *obj_attr;
            sql_stmt_t *obj_curr_stmt;
        };
    };
    union {
        struct {
            udt_mtrl_record_field_t *total_field;
            plv_record_attr_t **total_attr;
        };
        struct {
            udt_mtrl_object_field_t *obj_total_field;
            plv_object_attr_t **obj_total_attr;
        };
    };
    text_t *total_parent_name;
} pld_var_info_t;

typedef struct st_pld_set_var {
    variant_t *src;
    variant_t *dst;
    typmode_t type;
} pld_set_var_t;

typedef struct st_plm_find_pldesc {
    var_udo_t v_udo;
    uint32 type;
    sql_context_t *context;
    bool32 is_recursive;
} plm_find_pldesc_t;

void process_name_case_sensitive(text_t *name);
status_t pld_parse_block_info(const debug_control_t *debug_ctl, pld_block_info_t *block_info);
status_t pld_get_var_info(sql_stmt_t *stmt, debug_control_t *debug_ctl, pld_var_info_t *pld_var_info, bool32 *is_found,
                          bool32 *eof);
status_t pld_set_var(sql_stmt_t *stmt, const pld_set_var_t *set_var);
status_t pld_parse_exec_info(const debug_control_t *debug_ctl, pld_exec_info_t *exec_info);
void pld_register_debug_callbacks(dbg_callback_t *dbg_callback);
bool32 pld_has_privilege(session_t *session, text_t *debug_user, const void *exec);
status_t pld_open_proc_dc(sql_stmt_t *stmt, debug_control_t *debug_ctl, plm_find_pldesc_t *plm_find_pldesc,
    pl_dc_t *pl_dc);
status_t pld_get_cursor_buf(char *cursor_buf, uint32 buf_len, uint32 *using_len, const pld_cursor_info_t *cursor_info);
status_t pld_record_field_read(sql_stmt_t *stmt, sql_stmt_t *vm_stmt, plv_record_attr_t *attr,
    udt_mtrl_record_field_t *field, variant_t *result);
status_t pld_record_field_write(sql_stmt_t *stmt, debug_control_t *debug_ctl, pld_var_info_t *var_info, variant_t *right);
status_t pld_object_field_read(sql_stmt_t *stmt, sql_stmt_t *vm_stmt, plv_object_attr_t *attr,
    udt_mtrl_object_field_t *field, variant_t *result);
status_t pld_object_field_write(sql_stmt_t *stmt, debug_control_t *debug_ctl,
                                pld_var_info_t *var_info, variant_t *right);
status_t pld_get_pl_type(text_t *type, uint32 *pl_type);
status_t pld_get_pl_type_text(uint32 temp_pl_type, text_t *type);
status_t pld_get_target_session_debug_info(sql_stmt_t *stmt, uint32 session_id, debug_control_t **debug_ctl,
                                           spinlock_t **dbg_ctl_lock);
#ifdef __cplusplus
}
#endif

#endif
