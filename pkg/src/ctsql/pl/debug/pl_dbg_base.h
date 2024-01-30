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
 * pl_dbg_base.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/debug/pl_dbg_base.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __PL_DBG_BASE_H__
#define __PL_DBG_BASE_H__

#include "cm_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*dbg_callback_func_t)(void *session, void *exec, status_t *status);

typedef enum en_dbg_session_type {
    TARGET_SESSION = 0,
    DEBUG_SESSION = 1,
} dbg_session_type_t;

typedef struct st_dbg_callback {
    dbg_callback_func_t proc_start;
    dbg_callback_func_t proc_end;
    dbg_callback_func_t stmt_start;
    dbg_callback_func_t stmt_end;
} dbg_callback_t;

typedef struct st_dbg_callstack_info {
    char owner[CT_NAME_BUFFER_SIZE];
    uint32 owner_len;
    char object[CT_NAME_BUFFER_SIZE];
    uint32 object_len;
    void *exec;
    void *stmt;
} dbg_callstack_info_t;

typedef enum en_dbg_status {
    DBG_IDLE = 0,
    DBG_EXECUTING = 1,
    DBG_WAITING = 2,
    DBG_PRE_WAIT = 3,
} dbg_status_t;

typedef struct st_dbg_break_info {
    bool8 is_using;
    bool8 is_enabled;
    knl_scn_t scn;
    char owner[CT_NAME_BUFFER_SIZE];
    uint32 owner_len;
    char object[CT_NAME_BUFFER_SIZE];
    uint32 object_len;
    uint32 pl_type;
    source_location_t loc;
    void *cond_tree;
    char cond_str[CT_NAME_BUFFER_SIZE];
    uint32 cond_str_len;
    uint32 max_skip_times;
    uint32 skipped_times;
} dbg_break_info_t;

typedef enum en_dbg_break_flag {
    BRK_NEXT_LINE = 0, // Break at next source line (step over calls)
    BRK_ANY_CALL = 1,  // Break at next source line (step into calls)
    // Break after returning from current entrypoint (skip over any entrypoints called from the current routine)
    BRK_ANY_RETURN = 2,
    BRK_RETURN = 3,    // Break the next time an entrypoint gets ready to return.
    BRK_EXCEPTION = 4, // Break when an exception is raised
    BRK_HANDLER = 5,   // Break when an exception handler is executed
    BRK_ABORT = 6,     // Stop execution and force an 'exit' event as soon as DBE_DEBUG.CONTINUE is called.
    BRK_NEVER = 7,     // Do not break, unless breakpoint matched.
    BRK_END
} dbg_break_flag_t;

typedef struct st_debug_control {
    dbg_session_type_t type;
    dbg_callstack_info_t *callstack_info;
    dbg_break_info_t *brk_info;
    union {
        // TARGET_SESSION
        struct {
            dbg_callback_t dbg_calls;
            uint32 timeout;
            // Target and debug WR
            uint32 curr_count;
            dbg_status_t status;
            bool8 is_force_pause;
            bool8 is_force_terminate;
            // Target RO
            bool8 is_attached;
            uint8 unused1;
            uint32 debug_id;
            spinlock_t *debug_lock;
            dbg_break_flag_t brk_flag;
            uint32 brk_flag_stack_id;
            uint32 max_stack_id;
            uint32 max_break_id;
            text_t target_user;
            text_t debug_user;
            galist_t *pl_ref_entry;
            list_t *stmts;
        };

        // DEBUG_SESSION
        struct {
            bool8 is_attaching;
            uint8 unused2[3];
            uint32 target_id;
            spinlock_t *target_lock;
        };
    };
} debug_control_t;

#ifdef __cplusplus
}
#endif

#endif
