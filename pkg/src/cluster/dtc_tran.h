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
 * dtc_tran.h
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_tran.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DTC_TRAN_H__
#define __DTC_TRAN_H__
#include "knl_tran.h"
#include "mes_func.h"

#ifdef __cplusplus
extern "C" {
#endif
#define TXN_REQ_TIMEOUT (100) //ms

typedef struct st_msg_txn_info {
    mes_message_head_t head;
    xid_t xid;
    knl_scn_t curr_scn;
    bool32 is_can;
} msg_txn_info_t;

typedef struct st_msg_txn_snapshot {
    mes_message_head_t head;
    xmap_t xmap;
} msg_txn_snapshot_t;

typedef struct st_msg_txn_wait {
    mes_message_head_t head;
    xid_t wxid;
}msg_txn_wait_t;

EXTER_ATTACK void dtc_process_txn_info_req(void *sess, mes_message_t *msg);
status_t dtc_get_remote_txn_snapshot(knl_session_t *session, xmap_t xmap, uint32 dst_id, txn_snapshot_t *snapshot);
EXTER_ATTACK void dtc_process_txn_snapshot_req(void *sess, mes_message_t *msg);
EXTER_ATTACK void dtc_flush_log(knl_session_t *session, page_id_t page_id);

status_t dtc_get_remote_txn_info(knl_session_t *session, bool32 is_scan, xid_t xid, uint8 dst_id,
                                 txn_info_t *txn_info);
void dtc_get_txn_info(knl_session_t *session, bool32 is_scan, xid_t xid, txn_info_t *txn_info);

void dtc_undo_init(knl_session_t *session, uint8 inst_id);
void dtc_undo_release(knl_session_t *session, uint8 inst_id);

status_t dtc_tx_area_init(knl_session_t *session, uint8 inst_id);
status_t dtc_tx_area_load(knl_session_t *session, uint8 inst_id);
void dtc_rollback_close(knl_session_t *session, uint8 inst_id);

status_t dtc_tx_rollback_start(knl_session_t *session, uint8 inst_id);
void dtc_tx_rollback_close(knl_session_t *session, uint8 inst_id);
page_id_t dtc_get_txn_page_id(knl_session_t *session, xmap_t xmap);
#ifdef __cplusplus
}
#endif

#endif
