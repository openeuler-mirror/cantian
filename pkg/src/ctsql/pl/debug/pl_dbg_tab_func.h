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
 * pl_dbg_tab_func.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/debug/pl_dbg_tab_func.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __PL_DBG_TAB_FUNC_H__
#define __PL_DBG_TAB_FUNC_H__

#include "pl_debugger.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CONTROL_ITEM_NAME_MAXLEN 32
#define LINE_TYPE_NAME_MAXLEN 32
#define LINE_TYPE_NUM (LINE_END_EXCEPTION + 1)

typedef struct dba_proc_decode {
    uint32 line_num;
    char type_name[LINE_TYPE_NAME_MAXLEN];
    uint32 loc_line;
    text_t sp_instruction;
} dba_proc_decode_t;

typedef struct dba_proc_buf_info {
    char *buf;
    uint32 max_size;
    uint32 offset;
    bool32 is_full;
} dba_proc_buf_info_t;

typedef struct dba_proc_line_record {
    uint32 used_pos;
    uint32 line_num;
} dba_proc_line_record_t;

typedef struct dba_proc_line_info {
    pl_line_ctrl_t *line;
    char *name;
} dba_proc_line_info_t;

typedef struct st_dbg_breakpoint_info {
    uint32 break_id;
    text_t owner;
    text_t object;
    uint32 pl_type;
    uint16 loc_line;
    bool8 is_valid;
    bool8 is_enabled;
    text_t cond;
    uint32 max_skip;
} dbg_breakpoint_info_t;

typedef struct st_dbg_control_info {
    char name[CONTROL_ITEM_NAME_MAXLEN];
    uint32 value;
} dbg_control_info_t;

typedef struct st_dbg_proc_callstack {
    uint32 stack_id;
    uint32 uid;
    uint64 oid;
    text_t owner;
    text_t object;
    uint32 loc_line;
    text_t type_name;
} dbg_proc_callstack_t;

typedef struct st_dbg_show_values {
    uint32 stack_id;
    text_t name;
    text_t parent_name;
    text_t block_name;
    int16 block;
    uint16 id;
    uint16 m_offset;
    bool8 is_attr_in_vm;
    bool8 is_obj;
    union {
        struct {
            variant_t value;
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
} dbg_show_values_t;

#define TBL_FUNC_RETURN_IF_NOT_DBG_SESSION(session)                                             \
    do {                                                                                        \
        if ((session)->dbg_ctl == NULL || (session)->dbg_ctl->type == TARGET_SESSION) {         \
            CT_THROW_ERROR(ERR_DEBUG_SESSION_TYPE, "debug session", (session)->knl_session.id); \
            return CT_ERROR;                                                                    \
        }                                                                                       \
    } while (0)

#define TBL_FUNC_RETURN_IF_INT_NEGATIVE(var)                                           \
    do {                                                                               \
        if ((var).v_int < 0) {                                                         \
            CT_THROW_ERROR(ERR_INVALID_FUNC_PARAMS, "parameter can not be negative."); \
            return CT_ERROR;                                                           \
        }                                                                              \
    } while (0)

#define TBL_FUNC_RETURN_IF_NOT_INTEGER(loc, type)                     \
    do {                                                              \
        if (!CT_IS_INTEGER_TYPE(type) && !CT_IS_UNKNOWN_TYPE(type)) { \
            CT_SRC_ERROR_REQUIRE_INTEGER((loc), (type));              \
            return CT_ERROR;                                          \
        }                                                             \
    } while (0)


void proc_decode_get_max_line_num(pl_line_ctrl_t *entry, uint32 *max_line_num);
void proc_decode_default_sp(pl_line_ctrl_t *line, dba_proc_decode_t *decode_item, dba_proc_buf_info_t *buf_info);
void proc_decode_begin_sp(pl_line_ctrl_t *entry, pl_line_ctrl_t *line, dba_proc_decode_t *decode_item,
                          dba_proc_buf_info_t *buf_info);
void proc_decode_if_sp(pl_line_ctrl_t *entry, pl_line_ctrl_t *line, dba_proc_decode_t *decode_item,
                       dba_proc_buf_info_t *buf_info);
void proc_decode_else_sp(pl_line_ctrl_t *entry, pl_line_ctrl_t *line, dba_proc_decode_t *decode_item,
                         dba_proc_buf_info_t *buf_info);
void proc_decode_elsif_sp(pl_line_ctrl_t *entry, pl_line_ctrl_t *line, dba_proc_decode_t *decode_item,
                          dba_proc_buf_info_t *buf_info);
void proc_decode_when_case_sp(pl_line_ctrl_t *entry, pl_line_ctrl_t *line, dba_proc_decode_t *decode_item,
                              dba_proc_buf_info_t *buf_info);
void proc_decode_end_loop_sp(pl_line_ctrl_t *entry, pl_line_ctrl_t *line, dba_proc_decode_t *decode_item,
                             dba_proc_buf_info_t *buf_info);
void proc_decode_exit_sp(pl_line_ctrl_t *entry, pl_line_ctrl_t *line, dba_proc_decode_t *decode_item,
                         dba_proc_buf_info_t *buf_info);
void proc_decode_goto_sp(pl_line_ctrl_t *entry, pl_line_ctrl_t *line, dba_proc_decode_t *decode_item,
                         dba_proc_buf_info_t *buf_info);
void proc_decode_continue_sp(pl_line_ctrl_t *entry, pl_line_ctrl_t *line, dba_proc_decode_t *decode_item,
                             dba_proc_buf_info_t *buf_info);
void proc_decode_while_sp(pl_line_ctrl_t *entry, pl_line_ctrl_t *line, dba_proc_decode_t *decode_item,
                          dba_proc_buf_info_t *buf_info);
void proc_decode_for_sp(pl_line_ctrl_t *entry, pl_line_ctrl_t *line, dba_proc_decode_t *decode_item,
                        dba_proc_buf_info_t *buf_info);
void proc_decode_except_sp(pl_line_ctrl_t *entry, pl_line_ctrl_t *line, dba_proc_decode_t *decode_item,
                           dba_proc_buf_info_t *buf_info);
void dba_proc_line_add_head(char *buf, uint32 buf_len, char type, text_t *object, uint16 *used_len);

status_t get_break_info_by_id(sql_stmt_t *stmt, uint32 id, debug_control_t *ctl, dbg_breakpoint_info_t *break_info);
status_t dbg_proc_callstack_prepare(sql_stmt_t *stmt, debug_control_t *debug_ctl, dbg_proc_callstack_t *stats,
                                    uint32 stack_id);
status_t dbg_show_values_prepare(sql_stmt_t *stmt, debug_control_t *debug_ctl, dbg_show_values_t *stats,
                                 uint32 *using_index, uint32 stack_id);
#ifdef __cplusplus
}
#endif

#endif
