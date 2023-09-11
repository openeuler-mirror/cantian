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
 * dtc_smon.h
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_smon.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef DTC_SMON_H
#define DTC_SMON_H

#include "cm_types.h"
#include "cm_defs.h"
#include "cm_thread.h"
#include "knl_session.h"
#include "knl_dlock_stack.h"
#include "mes_func.h"

#ifdef __cplusplus
extern "C" {
#endif

// dtc txn lock check
#pragma pack(4)
typedef struct st_dtc_dead_lock {
    uint64 curr_lsn;
    xid_t wxid;
    uint16 wsid;
    uint16 wrmid;
} dtc_dlock;
#pragma pack()

// dtc table lock check
#pragma pack(4)
typedef struct st_dtc_table_lock_wait {
    uint8 inst_id; // wait table lock instance id
    uint8 unused;
    uint16 sid;
    uint16 rmid;
    uint16 wrmid;
    lock_twait_t wtid;
} dtc_tlock;
#pragma pack()

// dtc itl lock check
#pragma pack(4)
typedef struct st_dtc_itl_lock_wait {
    uint16 sid;
    uint8 unused[2];
    xid_t xid;
    xid_t wxid;     // wait node id in transaction table
    page_id_t wpid; // wait on page itls
    knl_session_status_t status;
} dtc_ilock;
#pragma pack()

status_t dtc_smon_init_lock_stack(knl_session_t *session);
void dtc_smon_uninit_lock_stack(knl_session_t *session);

EXTER_ATTACK void dtc_smon_process_get_sid(void *sess, mes_message_t *receive_msg);
EXTER_ATTACK void dtc_smon_process_txn_dlock(void *sess, mes_message_t *receive_msg);
EXTER_ATTACK void dtc_smon_process_get_wrid(void *sess, mes_message_t *receive_msg);
EXTER_ATTACK void dtc_smon_process_wait_tlocks_msg(void *sess, mes_message_t *receive_msg);
EXTER_ATTACK void dtc_smon_process_wait_tlock_msg(void *sess, mes_message_t *receive_msg);
EXTER_ATTACK void dtc_smon_process_check_tlock_msg(void *sess, mes_message_t *receive_msg);
EXTER_ATTACK void dtc_smon_process_get_tlock_msg(void *sess, mes_message_t *receive_msg);
EXTER_ATTACK void dtc_smon_process_wait_event_msg(void *sess, mes_message_t *receive_msg);
EXTER_ATTACK void dtc_smon_process_get_ilock_msg(void *sess, mes_message_t *receive_msg);
EXTER_ATTACK void dtc_smon_process_check_se_msg(void *sess, mes_message_t *receive_msg);
EXTER_ATTACK void dtc_smon_process_deadlock_sql(void *sess, mes_message_t *receive_msg);

void dtc_smon_detect_dead_lock_in_cluster(knl_session_t *session, uint8 *wait_marks, uint16 session_id,
    bool32 record_sql);
bool32 dtc_smon_check_lock_waits_in_cluster(knl_session_t *session, knl_session_t *se, bool32 record_sql);
bool32 dtc_smon_check_itl_waits_in_cluster(knl_session_t *session, knl_session_t *start_session, bool32 record_sql);


#ifdef __cplusplus
}
#endif

#endif
