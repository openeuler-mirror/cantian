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
 * session_defs.h
 *
 *
 * IDENTIFICATION
 * src/kernel/include/session_defs.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_SESSION_DEFS_H__
#define __KNL_SESSION_DEFS_H__

#include "knl_defs.h"

#ifdef __cplusplus
extern "C" {
#endif


// Internal work session ID
typedef enum en_sys_session {
    SESSION_ID_KERNEL = 0,
    SESSION_ID_LOGWR = 1,
    SESSION_ID_DBWR = 2,
    SESSION_ID_SMON = 3,
    SESSION_ID_SEQ = 4,
    SESSION_ID_UNDO = 5,
    SESSION_ID_ARCH = 6,
    SESSION_ID_BRU = 7,

    SESSION_ID_LSND = 8,
    SESSION_ID_REPLAY = 9,

    SESSION_ID_LFTC_CLIENT = 11,
    SESSION_ID_TIMER = 12,
    SESSION_ID_ROLLBACK = 13,
    SESSION_ID_ROLLBACK_EDN = 14,
    SESSION_ID_LOGWR_ASYNC = 15,
    SESSION_ID_TRANS_CLEAN = 16,
    SESSION_ID_GTS_TMS = 17,
    SESSION_ID_STATS = 18,
    SESSION_ID_TMP_STAT = 19,
    SESSION_ID_LOAD_NODE = 20,
    SESSION_ID_JOB = 21,
    SESSION_ID_IDX_RECYCLE = 22,
    SESSION_ID_SEG_RCYCLE = 23,
    SESSION_ID_SYNC_TIME = 24,
    SESSION_ID_RMON = 25,
    SESSION_ID_AIO = 26,
    SESSION_ID_ASHRINK = 27,
    SESSION_ID_IDX_REBUILD = 28,
    SESSION_ID_DTC_PROCESS = 29,
    SESSION_ID_DRC_REMASTER = 30,
    SESSION_ID_RES_PROCESS = 31,
    SESSION_ID_START = CT_SYS_SESSIONS,
} sys_session_t;

typedef enum en_wait_event {
    IDLE_WAIT = 0,
    MESSAGE_FROM_CLIENT = 1,
    MESSAGE_TO_CLIENT,
    LARGE_POOL_ALLOC,
    BUFFER_POOL_ALLOC,
    CACHE_BUFFER_CHAINS,
    CURSOR_MUTEX,
    LIBRARY_MUTEX,
    LOG_FILE_SYNC,
    BUFFER_BUSY_WAIT,
    ENQ_TX_ROW,
    ENQ_TX_ITL,
    ENQ_TX_KEY,
    ENQ_TX_TABLE_S,
    ENQ_TX_TABLE_X,
    ENQ_TX_READ_WAIT,
    DB_FILE_SCATTERED_READ,
    DB_FILE_SEQUENTIAL_READ,
    DB_FILE_GBP_READ,
    MTRL_SEGMENT_SORT,
    LOG_FILE_SWITCH_CKPT,
    LOG_FILE_SWITCH_ARCH,
    READ_BY_OTHER_SESSION,
    ATTACH_AGENT,
    ENQ_HEAP_MAP,
    ENQ_SEGMENT_EXTEND,
    RES_IO_QUANTUM,
    DIRECT_PATH_READ_TEMP,
    DIRECT_PATH_WRITE_TEMP,
    ENQ_ADVISORY_LOCK,
    CN_COMMIT,
    CN_EXECUTE_REQ,
    CN_EXECUTE_ACK,
    TEMP_ENTER_PAGE,
    LOG_RECYCLE,
    UNDO_EXTEND_SEGMENT,
    ENQ_PLSQL_LOCK,
    TEMP_POOL_ALLOC,
    PARALLEL_FINISH,

    GC_BUFFER_BUSY,
    DCS_REQ_MASTER4PAGE_1WAY,
    DCS_REQ_MASTER4PAGE_2WAY,
    DCS_REQ_MASTER4PAGE_3WAY,
    DCS_REQ_MASTER4PAGE_TRY,
    DCS_REQ_OWNER4PAGE,
    DCS_CLAIM_OWNER,
    DCS_RECYCLE_OWNER,
    DCS_INVLDT_READONLY_REQ,
    DCS_INVLDT_READONLY_PROCESS,
    DCS_TRANSFER_PAGE_LATCH,
    DCS_TRANSFER_PAGE_READONLY2X,
    DCS_TRANSFER_PAGE_FLUSHLOG,
    DCS_TRANSFER_PAGE,
    DCS_TRANSFER_LATEST_EDP_PAGE,
    DCS_TRANSFER_LATEST_EDP_PAGE_LATCH,
    PCR_REQ_BTREE_PAGE,
    PCR_REQ_HEAP_PAGE,
    PCR_REQ_MASTER,
    PCR_REQ_OWNER,
    PCR_CHECK_CURR_VISIBLE,
    TXN_REQ_INFO,
    TXN_REQ_SNAPSHOT,
    DLS_REQ_LOCK,
    DLS_REQ_TABLE,
    DLS_WAIT_TXN,
    DEAD_LOCK_TXN,
    DEAD_LOCK_TABLE,
    DEAD_LOCK_ITL,
    BROADCAST_BTREE_SPLIT,
    BROADCAST_ROOT_PAGE,
    CKPT_DISABLE_WAIT,
    WAIT_EVENT_COUNT,
} wait_event_t;

typedef struct st_wait_event_desc {
    char name[CT_MAX_NAME_LEN];
    char p1[CT_MAX_NAME_LEN];
    char wait_class[CT_MAX_NAME_LEN];
} wait_event_desc_t;

const wait_event_desc_t* knl_get_event_desc(const uint16 id);

// SESSION
void knl_init_session(knl_handle_t kernel, knl_handle_t knl_session, uint32 uid, char *plog_buf,
    cm_stack_t *stack);
void knl_init_sess_ex(knl_handle_t kernel, knl_handle_t sess);

void knl_init_rm(knl_handle_t handle, uint16 rmid);
void knl_set_session_rm(knl_handle_t handle, uint16 rmid);
EXTER_ATTACK uint16 knl_get_rm_sid(knl_handle_t session, uint16 rmid);
status_t knl_begin_auton_rm(knl_handle_t session);
void knl_end_auton_rm(knl_handle_t handle, status_t status);

void knl_set_curr_sess2tls(void *sess);
void *knl_get_curr_sess(void);
status_t knl_check_sessions_per_user(knl_handle_t session, text_t *username, uint32 count);
status_t knl_begin_itl_waits(knl_handle_t se, uint32 *itl_waits);
void knl_end_itl_waits(knl_handle_t se);
bool32 knl_exist_session_wait(knl_handle_t se);
bool32 knl_hang_session_wait(knl_handle_t se);
void knl_begin_session_wait(knl_handle_t se, wait_event_t event, bool32 immediate);
void knl_end_session_wait(knl_handle_t se, wait_event_t event);
void knl_end_session_waits(knl_handle_t se);
void knl_destroy_session(knl_handle_t kernel, uint32 sid);
void knl_set_session_scn(knl_handle_t handle, uint64 scn);
void knl_inc_session_ssn(knl_handle_t handle);
void knl_end_session_wait_ex(knl_handle_t se, wait_event_t old_event,wait_event_t new_event);

#ifdef __cplusplus
}
#endif

#endif