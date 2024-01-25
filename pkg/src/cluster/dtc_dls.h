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
 * dtc_dls.h
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_dls.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef DTC_DLS_H
#define DTC_DLS_H

#include "cm_defs.h"
#include "cm_types.h"
#include "knl_session.h"
#include "mes_queue.h"
#include "dtc_drc.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DLS_WAIT_TIMEOUT MES_WAIT_MAX_TIME //ms,now set forever to find hang issues
#define DLS_TABLE_WAIT_TIMEOUT (10)        // ms

typedef struct st_msg_lock_table_request {
    mes_message_head_t head;
    status_t lock_status;
    knl_scn_t scn;
} msg_lock_table_request_t;
typedef struct st_msg_lock_req {
    mes_message_head_t head;
    drid_t lock_id;
    uint64 req_version;
    uint8 req_mode;
    uint32 release_timeout_ticks;
} msg_lock_req_t;
typedef struct st_msg_lock_ack {
    mes_message_head_t head;
    status_t lock_status;
    uint64 req_version;
} msg_lock_ack_t;

EXTER_ATTACK status_t dls_process_ask_master_for_lock(knl_session_t *session, mes_message_t *receive_msg);
EXTER_ATTACK status_t dls_process_ask_master_for_latch(knl_session_t *session, mes_message_t *receive_msg);
EXTER_ATTACK status_t dls_process_try_ask_master_for_lock(knl_session_t *session, mes_message_t *receive_msg);
EXTER_ATTACK void dls_process_lock_msg(void *sess, mes_message_t *receive_msg);
EXTER_ATTACK status_t dls_process_clean_granted_map(knl_session_t *session, mes_message_t *receive_msg);
//if type + id can uniquely identifies lock resource, you can ignore uid
#define DLS_INIT_DR_RES(drid, _type, _id, _uid, _idx, _part, _parentpart, _is_shadow) \
    do {                                                               \
        CM_ASSERT((drid)->type == DR_TYPE_INVALID);                    \
        (drid)->type = _type;                                          \
        (drid)->id = _id;                                              \
        (drid)->uid = _uid;                                            \
        (drid)->idx = _idx;                                            \
        (drid)->part = _part;                                          \
        (drid)->parentpart = _parentpart;                                    \
        (drid)->is_shadow = _is_shadow;                                \
    } while (0)

static inline void dls_init_spinlock(drlock_t* lock, dr_type_t type, uint32 id, uint16 uid)
{
    DLS_INIT_DR_RES(&lock->drid, type, id, uid, CT_INVALID_ID32, CT_INVALID_ID32, CT_INVALID_ID32, 0);
    lock->lock = 0;
}

static inline void dls_init_spinlock2(drlock_t *lock, dr_type_t type, uint32 id, uint16 uid, uint32 idx, uint32 part,
                                      uint32 parentpart)
{
    DLS_INIT_DR_RES(&lock->drid, type, id, uid, idx, part, parentpart, 0);
    lock->lock = 0;
}

void dls_spin_lock(knl_session_t *session, drlock_t *dlock, spin_statis_t *stat);
bool32 dls_spin_try_lock(knl_session_t *session, drlock_t *dlock);
bool32 dls_spin_timed_lock(knl_session_t *session, drlock_t *dlock, uint32 timeout_ticks, wait_event_t event);
bool32 dls_spin_lock_by_self(knl_session_t *session, drlock_t *dlock);
void dls_spin_unlock(knl_session_t *session, drlock_t *dlock);
void dls_spin_add(knl_session_t *session, drlock_t *dlock);
void dls_spin_dec(knl_session_t *session, drlock_t *dlock);
void dls_spin_dec_unlock(knl_session_t *session, drlock_t *dlock);


static inline void dls_init_latch(drlatch_t* dlatch, dr_type_t type, uint32 id, uint16 uid)
{
    DLS_INIT_DR_RES(&dlatch->drid, type, id, uid, CT_INVALID_ID32, CT_INVALID_ID32, CT_INVALID_ID32, 0);
    dlatch->latch.lock = 0;
    dlatch->latch.shared_count = 0;
    dlatch->latch.sid = 0;
    dlatch->latch.stat = 0;
}

static inline void dls_init_latch2(drlatch_t *dlatch, dr_type_t type, uint32 id, uint16 uid, uint32 idx, uint32 part,
                                   uint32 parentpart, bool8 is_shadow)
{
    DLS_INIT_DR_RES(&dlatch->drid, type, id, uid, idx, part, parentpart, is_shadow);
    dlatch->latch.lock = 0;
    dlatch->latch.shared_count = 0;
    dlatch->latch.sid = 0;
    dlatch->latch.stat = 0;
}

bool32 dls_request_latch_x(knl_session_t *session, drid_t *lock_id, bool32 timeout, uint32 timeout_ticks,
    uint32 release_timeout_ticks);
bool32 dls_request_latch_s(knl_session_t *session, drid_t *lock_id, bool32 timeout, uint32 timeout_ticks,
    uint32 release_timeout_ticks);
void dls_latch_s(knl_session_t *session, drlatch_t *dlatch, uint32 sid, bool32 is_force, latch_statis_t *stat);
bool32 dls_latch_timed_s(knl_session_t *session, drlatch_t *dlatch, uint32 ticks_for_wait, bool32 is_force,
                         latch_statis_t *stat, uint32 release_timeout_ticks);
void dls_latch_x(knl_session_t *session, drlatch_t *dlatch, uint32 sid, latch_statis_t *stat);
bool32 dls_latch_timed_x(knl_session_t *session, drlatch_t *dlatch, uint32 ticks_for_wait, bool32 is_force,
                         latch_statis_t *stat, uint32 release_timeout_ticks);
void dls_unlatch(knl_session_t *session, drlatch_t *dlatch, latch_statis_t *stat);

status_t dtc_is_inst_fault(uint32 inst_id);

EXTER_ATTACK void dls_process_txn_msg(void *sess, mes_message_t *receive_msg);
bool32 dls_wait_txn(knl_session_t *session, uint16 rmid);
void dls_release_txn(knl_session_t *session, knl_rm_t *rm);
void dls_wait_txn_recyle(knl_session_t *session);
status_t dls_request_txn_msg(knl_session_t *session, xid_t* xid, uint8 dst_inst, uint32 cmd);
void dls_process_txn_wait(knl_session_t *session, mes_message_t *receive_msg);
status_t dls_clean_granted_map(knl_session_t *session, drid_t *lock_id, uint8 inst_id);
void dls_request_clean_granted_map(knl_session_t *session, drid_t *lock_id);
#ifdef __cplusplus
}
#endif

#endif
