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
 * dtc_smon.c
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_smon.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_cluster_module.h"
#include "knl_smon.h"
#include "knl_context.h"
#include "pcr_heap.h"
#include "pcr_btree.h"
#include "knl_table.h"
#include "dtc_dls.h"
#include "dtc_trace.h"
#include "dtc_context.h"
#include "dtc_smon.h"
#include "cm_malloc.h"

static dtc_dlock_stack_t g_tlock_stack;
static dtc_dlock_stack_t g_ilock_stack;

#define DTC_SMON_TRACE_SQL_LEN (1024)
#define DTC_SMON_WAIT_TIMEOUTMS (10000)

void dtc_smon_process_deadlock_sql(void *sess, mes_message_t *receive_msg)
{
    status_t ret = CT_SUCCESS;
    uint8 *send_msg = NULL;
    mes_message_head_t* head = NULL;
    knl_session_t *session = (knl_session_t *)sess;
    if (sizeof(mes_message_head_t) + sizeof(uint16) != receive_msg->head->size) {
        CT_LOG_RUN_ERR("smon process deadlock sql mes size is invalid, msg size %u.", receive_msg->head->size);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    uint16 sid = *(uint16*)(receive_msg->buffer + sizeof(mes_message_head_t));
    if (sid >= CT_MAX_SESSIONS) {
        CT_LOG_RUN_ERR("smon_process_deadlock_sql failed, invalid sid %u", sid);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    uint32 mes_size = sizeof(mes_message_head_t) + DTC_SMON_TRACE_SQL_LEN;
    text_t sql_text;

    send_msg = (uint8*)cm_push(session->stack, mes_size);
    if (send_msg == NULL) {
        CT_LOG_RUN_ERR("msg failed to malloc memory");
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    head = (mes_message_head_t*)send_msg;

    sql_text.len = CM_ALIGN8(DTC_SMON_TRACE_SQL_LEN  - CT_PUSH_RESERVE_SIZE);
    sql_text.str = (char*)(send_msg + sizeof(mes_message_head_t));
    if (g_knl_callback.get_sql_text(sid, &sql_text) != CT_SUCCESS) {
        int check = snprintf_s(sql_text.str, sql_text.len, sql_text.len - 1, "%s", "sql statement not found");
        PRTS_RETVOID_IFERR(check);
        sql_text.len = strlen(sql_text.str);
    }
    //CT_LOG_TRACE("wait sql: %s \n", sql_text.str);
    mes_init_ack_head(receive_msg->head, head, MES_CMD_DEAD_LOCK_SQL_ACK, sizeof(mes_message_head_t) + sql_text.len,
                      CT_INVALID_ID16);

    ret = mes_send_data(send_msg);
    if (ret != CT_SUCCESS) {
        DTC_DLS_DEBUG_ERR("[SMON] process dead lock sql message from instance(%u), sid(%u) failed", receive_msg->head->src_inst, sid);
    }
    cm_pop(session->stack);
    DTC_DLS_DEBUG_INF("[SMON] process dead lock sql message from instance(%u), sid(%u)", receive_msg->head->src_inst, sid);
    mes_release_message_buf(receive_msg->buffer);
    return;
}

status_t dtc_smon_request_deadlock_sql(knl_session_t *session, wait_event_t event, uint8 dst_inst, uint16 sid)
{
    errno_t ret;
    uint8 *send_msg = NULL;
    uint16 msg_size = sizeof(mes_message_head_t) + sizeof(uint16);
    mes_message_head_t* head = NULL;
    mes_message_t    recv_msg = {0};
    uint32   rsn = 0;
    uint8    src_inst = session->kernel->dtc_attr.inst_id;
    char* sql_content;

    send_msg = (uint8*)cm_push(session->stack, msg_size);
    head = (mes_message_head_t*)send_msg;
    mes_init_send_head(head, MES_CMD_DEAD_LOCK_SQL, msg_size, CT_INVALID_ID32, src_inst, dst_inst, session->id,
                       CT_INVALID_ID16);
    *((uint16*)(send_msg + sizeof(mes_message_head_t))) = sid;

    knl_begin_session_wait(session, event, CT_TRUE);
    ret = mes_send_data(send_msg);
    if (ret != CT_SUCCESS) {
        knl_end_session_wait(session, event);
        cm_pop(session->stack);
        DTC_DLS_DEBUG_ERR("[SMON] request dead lock sql message to instance(%u) failed, event(%u) sid(%u) errcode(%u)", dst_inst, event, sid, ret);
        return ret;
    }
    cm_pop(session->stack);

    ret = mes_recv(session->id, &recv_msg, CT_FALSE, rsn, DTC_SMON_WAIT_TIMEOUTMS);
    if (ret != CT_SUCCESS) {
        knl_end_session_wait(session, event);
        DTC_DLS_DEBUG_ERR("[SMON] receive dead lock sql message to instance(%u) failed, event(%u) sid(%u) errcode(%u)", dst_inst, event, sid, ret);
        return ret;
    }

    knl_end_session_wait(session, event);
    sql_content = (char*)(recv_msg.buffer + sizeof(mes_message_head_t));
    CT_LOG_TRACE("wait sql: %s \n", sql_content);

    mes_release_message_buf(recv_msg.buffer);
    DTC_DLS_DEBUG_INF("[SMON] request dead lock sql message to instance(%u), event(%u) sid(%u)", dst_inst, event, sid);
    return ret;
}

static void dtc_smon_record_deadlock_sql(knl_session_t *session, wait_event_t event, uint8 inst_id, uint16 sid)
{
    text_t sql_text;

    if (session->kernel->dtc_attr.inst_id == inst_id) {
        smon_sql_init(session, &sql_text);
        if (g_knl_callback.get_sql_text(sid, &sql_text) == CT_SUCCESS) {
            CT_LOG_TRACE("wait sql: %s \n", sql_text.str);
        }
        return;
    }
    dtc_smon_request_deadlock_sql(session, event, inst_id, sid);
    return;
}

//dtc txn lock
void dtc_smon_process_txn_dlock(void *sess, mes_message_t * receive_msg)
{
    status_t ret = CT_SUCCESS;
    uint8 *send_msg = NULL;
    mes_message_head_t* head = NULL;
    knl_session_t *session = (knl_session_t *)sess;
    if (sizeof(mes_message_head_t) + sizeof(uint16) != receive_msg->head->size) {
        CT_LOG_RUN_ERR("smon process txn dlock mes size is invalid, msg size %u.", receive_msg->head->size);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    uint16 rmid = *(uint16*)(receive_msg->buffer + sizeof(mes_message_head_t));
    uint32 mes_size = sizeof(mes_message_head_t) + sizeof(dtc_dlock);
    dtc_dlock* dlock;

    send_msg = (uint8*)cm_push(session->stack, mes_size);
    if (send_msg == NULL) {
        CT_LOG_RUN_ERR("msg failed to malloc memory");
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    head = (mes_message_head_t*)send_msg;
    mes_init_ack_head(receive_msg->head, head, MES_CMD_DEAD_LOCK_TXN_ACK, mes_size, CT_INVALID_ID16);

    dlock = (dtc_dlock*)(send_msg + sizeof(mes_message_head_t));
    dlock->wsid = CT_INVALID_ID16;
    //must be local rmid
    dtc_smon_get_txn_dlock(session, session->kernel->id, rmid, dlock);

    ret = mes_send_data(send_msg);
    if (ret != CT_SUCCESS) {
        DTC_DLS_DEBUG_ERR("[SMON] process txn dead lock message from instance(%u), type(%u) rmid(%u) instid(%u) wsid(%u) failed",
            receive_msg->head->src_inst, MES_CMD_DEAD_LOCK_TXN, rmid, xid_get_inst_id(session, dlock->wxid), dlock->wsid);
    }
    cm_pop(session->stack);
    DTC_DLS_DEBUG_INF("[SMON] process txn dead lock message from instance(%u), type(%u) rmid(%u) instid(%u) wsid(%u)",
        receive_msg->head->src_inst, MES_CMD_DEAD_LOCK_TXN, rmid, xid_get_inst_id(session, dlock->wxid), dlock->wsid);
    mes_release_message_buf(receive_msg->buffer);
    return;
}

void dtc_smon_process_get_sid(void *sess, mes_message_t * receive_msg)
{
    status_t ret = CT_SUCCESS;
    uint8 *send_msg = NULL;
    mes_message_head_t* head = NULL;
    knl_session_t *session = (knl_session_t *)sess;
    if (sizeof(mes_message_head_t) + sizeof(uint16) != receive_msg->head->size) {
        CT_LOG_RUN_ERR("smon process get sid mes size is invalid, msg size %u.", receive_msg->head->size);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    uint16 rmid = *(uint16*)(receive_msg->buffer + sizeof(mes_message_head_t));
    uint32 mes_size = sizeof(mes_message_head_t) + sizeof(uint16);
    uint16 sid;

    send_msg = (uint8*)cm_push(session->stack, mes_size);
    if (send_msg == NULL) {
        CT_LOG_RUN_ERR("msg failed to malloc memory");
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    head = (mes_message_head_t*)send_msg;

    mes_init_ack_head(receive_msg->head, head, MES_CMD_DEAD_LOCK_SID_ACK, mes_size, CT_INVALID_ID16);
    //must be local rmid
    sid = knl_get_rm_sid(session, rmid);
    *((uint16*)(send_msg + sizeof(mes_message_head_t))) = sid;

    ret = mes_send_data(send_msg);
    if (ret != CT_SUCCESS) {
        DTC_DLS_DEBUG_ERR("[SMON] process sid message from instance(%u), type(%u) rmid(%u) sid(%u) failed",
            receive_msg->head->src_inst, MES_CMD_DEAD_LOCK_SID, rmid, sid);
    }
    cm_pop(session->stack);
    DTC_DLS_DEBUG_INF("[SMON] process sid message from instance(%u), type(%u) rmid(%u) sid(%u)",
        receive_msg->head->src_inst, MES_CMD_DEAD_LOCK_SID, rmid, sid);
    mes_release_message_buf(receive_msg->buffer);
    return;
}

void dtc_smon_process_get_wrid(void *sess, mes_message_t * receive_msg)
{
    status_t ret = CT_SUCCESS;
    uint8 *send_msg = NULL;
    mes_message_head_t* head = NULL;
    knl_session_t *session = (knl_session_t *)sess;
    if (sizeof(mes_message_head_t) + sizeof(uint16) != receive_msg->head->size) {
        CT_LOG_RUN_ERR("smon process get wrid msg size is invalid, msg size %u.", receive_msg->head->size);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    uint16 rmid = *(uint16*)(receive_msg->buffer + sizeof(mes_message_head_t));
    uint32 mes_size = sizeof(mes_message_head_t) + sizeof(rowid_t);
    rowid_t rowid;

    send_msg = (uint8*)cm_push(session->stack, mes_size);
    if (send_msg == NULL) {
        CT_LOG_RUN_ERR("msg failed to malloc memory");
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    head = (mes_message_head_t*)send_msg;

    mes_init_ack_head(receive_msg->head, head, MES_CMD_DEAD_LOCK_ROWID_ACK, mes_size, CT_INVALID_ID16);
    //must be local rmid
    rowid = dtc_smon_get_rm_wrid(session, session->kernel->id, rmid);
    *((rowid_t*)(send_msg + sizeof(mes_message_head_t))) = rowid;

    ret = mes_send_data(send_msg);
    if (ret != CT_SUCCESS) {
        DTC_DLS_DEBUG_ERR("[SMON] process sid message from instance(%u), type(%u) rmid(%u) rowid(%u-%u-%u) failed",
            receive_msg->head->src_inst, MES_CMD_DEAD_LOCK_ROWID, rmid, rowid.file, rowid.page, rowid.slot);
    }
    cm_pop(session->stack);
    DTC_DLS_DEBUG_ERR("[SMON] process row id message from instance(%u), type(%u) rmid(%u) rowid(%u-%u-%u)",
        receive_msg->head->src_inst, MES_CMD_DEAD_LOCK_ROWID, rmid, rowid.file, rowid.page, rowid.slot);
    mes_release_message_buf(receive_msg->buffer);
    return;
}

status_t dtc_smon_request_dlock_msg(knl_session_t *session, uint8 cmd, uint8 dst_inst, uint16 rmid, void* rsp_content, uint32 rsp_size)
{
    errno_t ret;
    uint8 *send_msg = NULL;
    uint16 msg_size = sizeof(mes_message_head_t) + sizeof(uint16);
    mes_message_head_t* head = NULL;
    mes_message_t    recv_msg = {0};
    uint32   rsn = 0;
    uint8    src_inst = session->kernel->dtc_attr.inst_id;

    send_msg = (uint8*)cm_push(session->stack, msg_size);
    if (send_msg == NULL) {
        CT_LOG_RUN_ERR("send_msg failed to malloc memory, send_msg size %u.", msg_size);
        return CT_ERROR;
    }
    head = (mes_message_head_t*)send_msg;
    mes_init_send_head(head, cmd, msg_size, CT_INVALID_ID32, src_inst, dst_inst, session->id, CT_INVALID_ID16);
    *((uint16*)(send_msg + sizeof(mes_message_head_t))) = rmid;

    knl_begin_session_wait(session, DEAD_LOCK_TXN, CT_TRUE);
    ret = mes_send_data(send_msg);
    if (ret != CT_SUCCESS) {
        knl_end_session_wait(session, DEAD_LOCK_TXN);
        cm_pop(session->stack);
        DTC_DLS_DEBUG_ERR("[SMON] request dead lock message to instance(%u) failed, type(%u) rmid(%u) errcode(%u)", dst_inst, cmd, rmid, ret);
        return ret;
    }
    cm_pop(session->stack);

    ret = mes_recv(session->id, &recv_msg, CT_FALSE, rsn, DTC_SMON_WAIT_TIMEOUTMS);
    if (ret != CT_SUCCESS) {
        knl_end_session_wait(session, DEAD_LOCK_TXN);
        DTC_DLS_DEBUG_ERR("[SMON] receive dead lock message to instance(%u) failed, type(%u) rmid(%u) errcode(%u)", dst_inst, cmd, rmid, ret);
        return ret;
    }

    knl_end_session_wait(session, DEAD_LOCK_TXN);
    ret = memcpy_s((char*)rsp_content, rsp_size, recv_msg.buffer + sizeof(mes_message_head_t), rsp_size);
    MEMS_RETURN_IFERR(ret);
    mes_release_message_buf(recv_msg.buffer);
    DTC_DLS_DEBUG_INF("[SMON] request dead lock message to instance(%u), type(%u) rmid(%u)", dst_inst, cmd, rmid);
    return ret;
}

status_t dtc_smon_request_txn_dlock(knl_session_t *session, uint8 dst_inst, uint16 rmid, dtc_dlock* dlock)
{
    status_t status;
    SYNC_POINT_GLOBAL_START(CANTIAN_SMON_REQUEST_TXN_DLOCK_TIMEOUT_AND_FAIL, &status, CT_ERROR);
    status = dtc_smon_request_dlock_msg(session, MES_CMD_DEAD_LOCK_TXN, dst_inst, rmid, dlock, sizeof(dtc_dlock));
    SYNC_POINT_GLOBAL_END;
    return status;
}

status_t dtc_smon_request_sid(knl_session_t *session,  uint8 dst_inst, uint16 rmid, uint16* sid)
{
    status_t status;
    SYNC_POINT_GLOBAL_START(CANTIAN_SMON_REQUEST_SID_TIMEOUT_AND_FAIL, &status, CT_ERROR);
    status = dtc_smon_request_dlock_msg(session, MES_CMD_DEAD_LOCK_SID, dst_inst, rmid, sid, sizeof(uint16));
    SYNC_POINT_GLOBAL_END;
    return status;
}

status_t dtc_smon_request_wrid(knl_session_t *session,  uint8 dst_inst, uint16 rmid, rowid_t* rowid)
{
    status_t status;
    SYNC_POINT_GLOBAL_START(CANTIAN_SMON_REQUEST_WSID_TIMEOUT_AND_FAIL, &status, CT_ERROR);
    status = dtc_smon_request_dlock_msg(session, MES_CMD_DEAD_LOCK_ROWID, dst_inst, rmid, rowid, sizeof(rowid_t));
    SYNC_POINT_GLOBAL_END;
    return status;
}

uint16 dtc_smon_get_rm_sid(knl_session_t *session,  uint8 dst_inst, uint16 rmid)
{
    uint16 sid = CT_INVALID_ID16;

    if (rmid == CT_INVALID_ID16) {
        return CT_INVALID_ID16;
    }

    if (dst_inst == session->kernel->dtc_attr.inst_id) {
        sid = knl_get_rm_sid(session, rmid);
    } else {
        dtc_smon_request_sid(session, dst_inst, rmid, &sid);
    }
    return sid;
}

rowid_t dtc_smon_get_rm_wrid(knl_session_t *session,  uint8 dst_inst, uint16 rmid)
{
    knl_session_t *knl_session = (knl_session_t *)session;
    knl_rm_t *rm = NULL;
    knl_session_t *se;
    rowid_t wrid;

    if (rmid >= CT_MAX_RMS) {
        return g_invalid_rowid;
    }

    if (dst_inst == session->kernel->id) {
        rm = knl_session->kernel->rms[rmid];
        if (rm != NULL && rm->sid < CT_MAX_SESSIONS) {
            se = knl_session->kernel->sessions[rm->sid];
            wrid = se->wrid;
        } else {
            wrid = g_invalid_rowid;
        }
    } else {
        dtc_smon_request_wrid(session, dst_inst, rmid, &wrid);
    }
    return wrid;
}

status_t dtc_smon_get_txn_dlock(knl_handle_t session, uint8 instid, uint16 rmid, dtc_dlock* dlock)
{
    knl_session_t *knl_session = (knl_session_t *)session;
    knl_rm_t *rm = NULL;
    knl_session_t *se;

    if (rmid >= CT_MAX_RMS) {
        dlock->wsid = CT_INVALID_ID16;
        return CT_SUCCESS;
    }

    if (instid == knl_session->kernel->id) {
        rm = knl_session->kernel->rms[rmid];
        if (rm != NULL && rm->sid < CT_MAX_SESSIONS) {
            se = knl_session->kernel->sessions[rm->sid];
            dlock->curr_lsn = se->curr_lsn;
            dlock->wxid = se->wxid;
            dlock->wrmid = se->wrmid;
            dlock->wsid = dtc_smon_get_rm_sid(session, xid_get_inst_id(se, se->wxid), se->wrmid);
        } else {
            dlock->wsid = CT_INVALID_ID16;
        }
        return CT_SUCCESS;
    }

    //remote
    return dtc_smon_request_txn_dlock(session, instid, rmid, dlock);
}

static uint16 dtc_smon_find_first_local_sid(knl_session_t *session, dtc_dlock *dlockshot,
    uint32 inst_id, uint16 id)
{
    if (id == CT_INVALID_ID16) {
        return CT_INVALID_ID16;
    }

    uint32 tmp_instid = inst_id;
    uint32 id_of_inst = inst_id;
    uint16 tmp_id = id;
    while (dlockshot[tmp_instid * CT_MAX_SESSIONS + tmp_id].wsid != id) {
        id_of_inst = tmp_instid;
        tmp_instid = xid_get_inst_id(session, dlockshot[id_of_inst * CT_MAX_SESSIONS + tmp_id].wxid);
        tmp_id = dlockshot[id_of_inst * CT_MAX_SESSIONS + tmp_id].wsid;
        // find it, then return
        if (tmp_instid == session->kernel->id) {
            return tmp_id;
        }
    }

    return CT_INVALID_ID16;
}

void dtc_smon_detect_dead_lock_in_cluster(knl_session_t *session, uint8 *wait_marks, uint16 session_id,
    bool32 record_sql)
{
    knl_session_t *current = NULL;
    dtc_dlock *dlockshot = NULL;
    dtc_dlock dlock;
    txn_snapshot_t snapshot;
    xid_t wait_xid;
    uint16 rmid;
    uint16 begin;
    uint32 count;
    errno_t ret;
    uint32 inst_id;
    uint32 tmp_instid;
    uint16 id = session_id;

    count = CT_MAX_INSTANCES * CT_MAX_SESSIONS * sizeof(dtc_dlock);
    dlockshot = (dtc_dlock *)malloc(count);
    if (dlockshot == NULL) {
        CT_LOG_RUN_ERR("dtc transaction deadlock malloc size(%u) failed", count);
        return;
    }
    ret = memset_sp((char*)dlockshot, count, CT_INVALID_ID8, count);
    knl_securec_check(ret);

    // suspended session should not be killed
    current = session->kernel->sessions[id];
    if (current->status == SESSION_INACTIVE) {
        wait_marks[id] = 0;
        free(dlockshot);
        return;
    }
    rmid = current->rmid;
    inst_id = session->kernel->dtc_attr.inst_id;
    //check from current instance and given id(sid)
    while (id != CT_INVALID_ID16 && dlockshot[inst_id * CT_MAX_SESSIONS + id].wsid == CT_INVALID_ID16) {
        //get wait xid,  lsn
        if (dtc_smon_get_txn_dlock(session, inst_id, rmid, &dlockshot[inst_id * CT_MAX_SESSIONS + id]) != CT_SUCCESS) {
            free(dlockshot);
            return;
        }
        if (inst_id == session->kernel->dtc_attr.inst_id) {
            wait_marks[id] = 1;
        }
        tmp_instid = inst_id;
        inst_id = xid_get_inst_id(session, dlockshot[tmp_instid * CT_MAX_SESSIONS + id].wxid);
        rmid = dlockshot[tmp_instid * CT_MAX_SESSIONS + id].wrmid;
        id = dlockshot[tmp_instid * CT_MAX_SESSIONS + id].wsid;
    }

    // not belong to myself, need find first session belong to me.
    if (inst_id != session->kernel->id) {
        id = dtc_smon_find_first_local_sid(session, dlockshot, inst_id, id);
        CT_LOG_DEBUG_INF("[SMON] find first local sid[%u] inst_id[%u]", id, inst_id);
    }

    // no deadlock was detected
    if (id == CT_INVALID_ID16) {
        free(dlockshot);
        return;
    }

    // suspended session should not be killed
    current = session->kernel->sessions[id];
    if (current->status == SESSION_INACTIVE) {
        wait_marks[id] = 0;
        free(dlockshot);
        return;
    }
    rmid = current->rmid;
    inst_id = current->kernel->id;
    begin = id;

    for (;;) {
        dlock.wsid = CT_INVALID_ID16;
        if (dtc_smon_get_txn_dlock(session, inst_id, rmid, &dlock) != CT_SUCCESS) {
            break;
        }
        if (dlock.wsid == CT_INVALID_ID16) {
            break;
        }
        if (dlockshot[inst_id * CT_MAX_SESSIONS + id].wsid != dlock.wsid ||
            dlockshot[inst_id * CT_MAX_SESSIONS + id].curr_lsn != dlock.curr_lsn ||
            dlockshot[inst_id * CT_MAX_SESSIONS + id].wrmid != dlock.wrmid ||
            dlockshot[inst_id * CT_MAX_SESSIONS + id].wxid.xnum != dlock.wxid.xnum) {
            break;
        }

        wait_xid = dlock.wxid;
        if (wait_xid.value == CT_INVALID_ID64) {
            break;
        }

        tx_get_snapshot(session, wait_xid.xmap, &snapshot);
        if (snapshot.rmid != dlockshot[inst_id * CT_MAX_SESSIONS + id].wrmid ||
            snapshot.xnum != dlockshot[inst_id * CT_MAX_SESSIONS + id].wxid.xnum ||
            snapshot.status == (uint8)XACT_END) {
            break;
        }

        if (record_sql) {
            //record current session info if needed
            rowid_t wrid = dtc_smon_get_rm_wrid(session, inst_id, rmid);
            CT_LOG_TRACE("session id: (%u/%u), wait session: (%u/%u), wait rowid: %u-%u-%u",
                         inst_id, id, xid_get_inst_id(session, dlock.wxid), dlock.wsid, wrid.file, wrid.page, wrid.slot);
            dtc_smon_record_deadlock_sql(session, DEAD_LOCK_TXN, inst_id, id);
        }

        //switch next
        tmp_instid = inst_id;
        inst_id = xid_get_inst_id(session, dlockshot[tmp_instid * CT_MAX_SESSIONS + id].wxid);
        rmid = dlockshot[tmp_instid * CT_MAX_SESSIONS + id].wrmid;
        id = dlockshot[tmp_instid * CT_MAX_SESSIONS + id].wsid;

        if (begin == id) {
            free(dlockshot);
            if (!record_sql) {
                smon_record_deadlock_time();
                CT_LOG_TRACE("[Transaction Deadlock]");
                dtc_smon_detect_dead_lock_in_cluster(session, wait_marks, id, CT_TRUE);
                CT_LOG_TRACE("-----------------END OF WAIT INFORMATION-----------------\n");
                //set initiate session dead locked
                current->dead_locked = CT_TRUE;
            }
            CT_LOG_RUN_ERR("found transaction deadlock in instance %u session %d", session->kernel->dtc_attr.inst_id, begin);
            return;
        }
    }

    free(dlockshot);
    return;
}

//dtc table lock
status_t dtc_smon_init_stack(knl_session_t *session, dtc_dlock_stack_t* stack, uint32 unit_size)
{
    if (session->kernel->attr.clustered) {
        stack->top = 0;
        stack->count =  CT_MAX_SESSIONS * CT_MAX_INSTANCES;
        stack->size = unit_size;
        stack->values = (void *)malloc(stack->count * stack->size);
        if (stack->values == NULL) {
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

void dtc_smon_uninit_stack(knl_session_t *session, dtc_dlock_stack_t* stack)
{
    if (session->kernel->attr.clustered) {
        stack->top = 0;
        stack->count =  0;
        free(stack->values);
    }
}

status_t dtc_smon_init_lock_stack(knl_session_t *session)
{
    if (dtc_smon_init_stack(session, &g_tlock_stack, sizeof(dtc_tlock)) != CT_SUCCESS) {
        CT_LOG_RUN_INF("smon thread init tlock failed");
        return CT_ERROR;
    }

    if (dtc_smon_init_stack(session, &g_ilock_stack, sizeof(dtc_ilock)) != CT_SUCCESS) {
        CT_LOG_RUN_INF("smon thread init ilock failed");
        dtc_smon_uninit_stack(session, &g_tlock_stack);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

void dtc_smon_uninit_lock_stack(knl_session_t *session)
{
    dtc_smon_uninit_stack(session, &g_tlock_stack);
    dtc_smon_uninit_stack(session, &g_ilock_stack);
}


void dtc_smon_process_wait_tlocks_msg(void *sess, mes_message_t * receive_msg)
{
    status_t ret = CT_SUCCESS;
    uint8 *w_marks = NULL;
    uint32 count = 0;
    uint8 *send_msg = NULL;
    mes_message_head_t* head = NULL;
    knl_session_t *session = (knl_session_t *)sess;
    if (sizeof(mes_message_head_t) + sizeof(uint64) != receive_msg->head->size) {
        CT_LOG_RUN_ERR("msg is invalid, msg size %u.", receive_msg->head->size);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    uint64 table_id = *(uint64*)(receive_msg->buffer + sizeof(mes_message_head_t));
    dtc_dlock_stack_t stack_lock;
    uint32 mes_size = 0;
    dtc_tlock* tlock;

    count = CT_MAX_SESSIONS * CT_MAX_INSTANCES * sizeof(uint8);
    w_marks = (void *)malloc(count);
    if (w_marks == NULL) {
        CT_LOG_RUN_ERR("dtc process table deadlock malloc size(%u) failed", count);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    ret = memset_sp(w_marks, count, 0, count);
    knl_securec_check(ret);

    if (dtc_smon_init_stack(session, &stack_lock, sizeof(dtc_tlock)) != CT_SUCCESS) {
        free(w_marks);
        CT_LOG_RUN_ERR("dtc process table deadlock init stack failed");
        mes_release_message_buf(receive_msg->buffer);
        return;
    }

    DTC_DLS_DEBUG_INF("[SMON] process wait tlocks message from instance(%u) table_id(%llu) cmd(%u)",
                      receive_msg->head->src_inst, table_id, receive_msg->head->cmd);

    //must be local sid
    count = 0;
    if (receive_msg->head->cmd == MES_CMD_DEAD_LOCK_WAIT_SHARED_TABLES) {
        //check table lock is shared
        if (lock_table_is_shared_mode(session, table_id)) {
            if (dtc_smon_push_tlock(session, w_marks, &stack_lock, session->kernel->dtc_attr.inst_id, table_id)) {
                count = stack_lock.top;
            }
        }
    } else {
        if (dtc_smon_push_tlock(session, w_marks, &stack_lock, session->kernel->dtc_attr.inst_id, table_id)) {
            count = stack_lock.top;
        }
    }

    mes_size = sizeof(mes_message_head_t) + sizeof(uint32) + sizeof(dtc_tlock) * count;
    //need malloc
    send_msg = (uint8*)cm_malloc(mes_size);
    if (send_msg == NULL) {
        free(w_marks);
        CT_LOG_RUN_ERR("dtc process table deadlock malloc size(%u) failed", mes_size);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    head = (mes_message_head_t*)send_msg;
    mes_init_ack_head(receive_msg->head, head, MES_CMD_DEAD_LOCK_TABLES_ACK, mes_size, CT_INVALID_ID16);
    *(uint32*)(send_msg + sizeof(mes_message_head_t)) = count;
    if (count != 0) {
        tlock = (dtc_tlock*)(send_msg + sizeof(mes_message_head_t) + sizeof(uint32));
        ret = memcpy_s((char*)tlock, count * sizeof(dtc_tlock), stack_lock.values, count * sizeof(dtc_tlock));
        knl_securec_check(ret);
    }

    ret = mes_send_data(send_msg);
    if (ret != CT_SUCCESS) {
        DTC_DLS_DEBUG_INF("[SMON] process wait tlocks msg from instance(%u) table_id(%llu) count(%u) failed, ret(%u)",
            receive_msg->head->src_inst, table_id, count, ret);
    }
    cm_free(send_msg);
    free(w_marks);
    dtc_smon_uninit_stack(session, &stack_lock);

    DTC_DLS_DEBUG_INF("[SMON] process wait tlocks message from instance(%u) table_id(%llu) count(%u)",
        receive_msg->head->src_inst, table_id, count);
    mes_release_message_buf(receive_msg->buffer);
    return;
}

status_t dtc_smon_request_wait_tlocks_msg(knl_session_t *session, uint8 *w_marks, dtc_dlock_stack_t *stack_lock,
                                          uint8 dst_inst, uint64 table_id, uint32 cmd)
{
    uint16 msg_size = sizeof(mes_message_head_t) + sizeof(uint64);
    uint32   rsn = 0;
    uint8    src_inst = session->kernel->dtc_attr.inst_id;
    mes_message_t recv_msg = { 0 };
    dtc_tlock* tlock;
    uint8 *send_msg = NULL;

    DTC_DLS_DEBUG_INF("[SMON] request wait table locks send message to instance(%u) table_id(%llu)", dst_inst, table_id);

    send_msg = (uint8*)cm_push(session->stack, msg_size);
    mes_message_head_t *head = (mes_message_head_t*)send_msg;
    mes_init_send_head(head, cmd, msg_size, CT_INVALID_ID32, src_inst, dst_inst, session->id, CT_INVALID_ID16);
    *((uint64*)(send_msg + sizeof(mes_message_head_t))) = table_id;

    knl_begin_session_wait(session, DEAD_LOCK_TABLE, CT_TRUE);
    errno_t ret = mes_send_data(send_msg);
    if (ret != CT_SUCCESS) {
        if (dtc_is_inst_fault(dst_inst) == CT_SUCCESS) {
            knl_end_session_wait(session, DEAD_LOCK_TABLE);
            cm_pop(session->stack);
            return CT_SUCCESS;
        }
        knl_end_session_wait(session, DEAD_LOCK_TABLE);
        cm_pop(session->stack);
        DTC_DLS_DEBUG_ERR("[SMON] request wait table locks message to instance(%u) failed, table_id(%llu) errcode(%u)", dst_inst, table_id, ret);
        return ret;
    }
    cm_pop(session->stack);

    ret = mes_recv(session->id, &recv_msg, CT_FALSE, rsn, DTC_SMON_WAIT_TIMEOUTMS);
    if (ret != CT_SUCCESS) {
        if (dtc_is_inst_fault(dst_inst) == CT_SUCCESS) {
            knl_end_session_wait(session, DEAD_LOCK_TABLE);
            return CT_SUCCESS;
        }
        knl_end_session_wait(session, DEAD_LOCK_TABLE);
        DTC_DLS_DEBUG_ERR("[SMON] receive wait table locks message to instance(%u) failed, table_id(%llu) errcode(%u)", dst_inst, table_id, ret);
        return ret;
    }

    knl_end_session_wait(session, DEAD_LOCK_TABLE);

    uint32 count = *(uint32*)(recv_msg.buffer + sizeof(mes_message_head_t));
    for (uint32 i = 0; i < count; i++) {
        tlock = (dtc_tlock*)(recv_msg.buffer + sizeof(mes_message_head_t) + sizeof(uint32) + sizeof(dtc_tlock) * i);
        if (tlock->sid == CT_INVALID_ID16) {
            continue;
        }
        if (w_marks[tlock->inst_id * CT_MAX_SESSIONS + tlock->sid] == 0) {
                if (dtc_dlock_push_with_check(stack_lock, tlock, sizeof(dtc_tlock))) {
                    w_marks[tlock->inst_id * CT_MAX_SESSIONS + tlock->sid] = 1;
                }
        }
    }
    mes_release_message_buf(recv_msg.buffer);
    DTC_DLS_DEBUG_INF("[SMON] request wait table locks message to instance(%u), table_id(%llu) count(%u)", dst_inst, table_id, count);
    return ret;
}


void dtc_smon_process_wait_tlock_msg(void *sess, mes_message_t * receive_msg)
{
    status_t ret = CT_SUCCESS;
    uint8 *send_msg = NULL;
    mes_message_head_t* head = NULL;
    knl_session_t *session = (knl_session_t *)sess;
    if (sizeof(mes_message_head_t) + sizeof(uint64) != receive_msg->head->size) {
        CT_LOG_RUN_ERR("msg is invalid, msg size %u.", receive_msg->head->size);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    uint64 table_id = *(uint64*)(receive_msg->buffer + sizeof(mes_message_head_t));
    uint32 mes_size = sizeof(mes_message_head_t) + sizeof(dtc_tlock);
    dtc_tlock* tlock;
    lock_twait_t wtid;
    schema_lock_t *lock = NULL;
    dc_entry_t *entry = NULL;
    dc_user_t *user = NULL;
    knl_session_t *lock_session = NULL;

    DTC_DLS_DEBUG_INF("[SMON] process wait tlock message from instance(%u) table_id(%llu) cmd(%u)",
                      receive_msg->head->src_inst, table_id, receive_msg->head->cmd);

    send_msg = (uint8*)cm_push(session->stack, mes_size);
    if (send_msg == NULL) {
        CT_LOG_RUN_ERR("send_msg failed to malloc memory, send_msg size %u.", mes_size);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    head = (mes_message_head_t*)send_msg;
    mes_init_ack_head(receive_msg->head, head, MES_CMD_DEAD_LOCK_TABLE_ACK, mes_size, CT_INVALID_ID16);
    tlock = (dtc_tlock*)(send_msg + sizeof(mes_message_head_t));
    tlock->sid = CT_INVALID_ID16;

    wtid.value = table_id;
    ret = dc_open_user_by_id(session, wtid.uid, &user);
    if (ret == CT_SUCCESS) {
        entry = DC_GET_ENTRY(user, wtid.oid);
        if (entry != NULL) {
            cm_spin_lock(&entry->lock, &session->stat->spin_stat.stat_dc_entry);
            if ((entry->ready) && (!entry->recycled)) {
                lock = entry->sch_lock;
                if (lock != NULL && lock->mode == LOCK_MODE_X) {
                    for (uint32 i = 0; i < session->kernel->rm_count; i++) {
                        if (lock->map[i] != 0) {
                            uint16 id = knl_get_rm_sid(session, i);
                            if (id == CT_INVALID_ID16) {
                                continue;
                            }
                            
                            lock_session = session->kernel->sessions[id];
                            if (lock_session != NULL && !lock_session->lock_dead_locked) {
                                tlock->inst_id = lock->inst_id;
                                tlock->sid = id;
                                tlock->rmid = lock_session->rmid;
                                tlock->wrmid = lock_session->wrmid;
                                tlock->wtid = lock_session->wtid;
                                break;
                            }
                        }
                    }
                }
            }
            cm_spin_unlock(&entry->lock);
        }
    }

    ret = mes_send_data(send_msg);
    if (ret != CT_SUCCESS) {
        DTC_DLS_DEBUG_INF("[SMON] process wait tlock message from instance(%u) table_id(%llu) failed, ret(%u)",
            receive_msg->head->src_inst, table_id, ret);
    }
    cm_pop(session->stack);
    DTC_DLS_DEBUG_INF("[SMON] process wait tlock message from instance(%u) table_id(%llu)", receive_msg->head->src_inst, table_id);
    mes_release_message_buf(receive_msg->buffer);
    return;
}

status_t dtc_smon_request_wait_tlock_msg(knl_session_t *session, dtc_tlock* tlock, uint8 dst_inst, uint64 table_id)
{
    errno_t ret;
    uint8 *send_msg = NULL;
    uint16 msg_size = sizeof(mes_message_head_t) + sizeof(uint64);
    mes_message_head_t* head = NULL;
    mes_message_t recv_msg = {0};
    uint32 rsn = 0;
    uint8 src_inst = session->kernel->dtc_attr.inst_id;

    send_msg = (uint8*)cm_push(session->stack, msg_size);
    head = (mes_message_head_t*)send_msg;
    mes_init_send_head(head, MES_CMD_DEAD_LOCK_GET_TABLE, msg_size, CT_INVALID_ID32, src_inst, dst_inst, session->id,
                       CT_INVALID_ID16);
    *((uint64*)(send_msg + sizeof(mes_message_head_t))) = table_id;

    knl_begin_session_wait(session, DEAD_LOCK_TABLE, CT_TRUE);
    ret = mes_send_data(send_msg);
    if (ret != CT_SUCCESS) {
        knl_end_session_wait(session, DEAD_LOCK_TABLE);
        cm_pop(session->stack);
        DTC_DLS_DEBUG_ERR("[SMON] request get table lock message to instance(%u) failed, table_id(%llu) errcode(%u)", dst_inst, table_id, ret);
        return ret;
    }
    cm_pop(session->stack);

    ret = mes_recv(session->id, &recv_msg, CT_FALSE, rsn, DTC_SMON_WAIT_TIMEOUTMS);
    if (ret != CT_SUCCESS) {
        knl_end_session_wait(session, DEAD_LOCK_TABLE);
        DTC_DLS_DEBUG_ERR("[SMON] receive get table lock message to instance(%u) failed, table_id(%llu) errcode(%u)", dst_inst, table_id, ret);
        return ret;
    }

    knl_end_session_wait(session, DEAD_LOCK_TABLE);
    ret = memcpy_s((char*)tlock, sizeof(dtc_tlock), recv_msg.buffer + sizeof(mes_message_head_t), sizeof(dtc_tlock));
    knl_securec_check(ret);

    mes_release_message_buf(recv_msg.buffer);
    DTC_DLS_DEBUG_INF("[SMON] request get table lock message to instance(%u), table_id(%llu)", dst_inst, table_id);
    return ret;
}

status_t dtc_smon_request_itl_tlock_msg(knl_session_t *session, dtc_tlock *tlock, uint8 dst_inst, uint8 sid, uint8 rmid,
                                        uint32 cmd)
{
    errno_t ret;
    uint8 *send_msg = NULL;
    uint16 msg_size = sizeof(mes_message_head_t) + sizeof(uint16) + sizeof(uint16);
    mes_message_head_t *head = NULL;
    mes_message_t recv_msg = { 0 };
    uint32 rsn = 0;
    uint8 src_inst = session->kernel->dtc_attr.inst_id;

    send_msg = (uint8 *)cm_push(session->stack, msg_size);
    if (send_msg == NULL) {
        CT_LOG_RUN_ERR("send_msg failed to malloc memory, send_msg size %u.", msg_size);
        return CT_ERROR;
    }
    head = (mes_message_head_t *)send_msg;
    mes_init_send_head(head, cmd, msg_size, CT_INVALID_ID32, src_inst, dst_inst, session->id, CT_INVALID_ID16);
    *((uint16 *)(send_msg + sizeof(mes_message_head_t))) = sid;
    *((uint16 *)(send_msg + sizeof(mes_message_head_t) + sizeof(uint16))) = rmid;

    knl_begin_session_wait(session, DEAD_LOCK_TABLE, CT_TRUE);
    ret = mes_send_data(send_msg);
    if (ret != CT_SUCCESS) {
        knl_end_session_wait(session, DEAD_LOCK_TABLE);
        cm_pop(session->stack);
        DTC_DLS_DEBUG_ERR("[SMON] request get table lock message to instance(%u) failed, sid(%u) rmid(%u) errcode(%u)",
                          dst_inst, sid, rmid, ret);
        return ret;
    }
    cm_pop(session->stack);

    ret = mes_recv(session->id, &recv_msg, CT_FALSE, rsn, DTC_SMON_WAIT_TIMEOUTMS);
    if (ret != CT_SUCCESS) {
        knl_end_session_wait(session, DEAD_LOCK_TABLE);
        DTC_DLS_DEBUG_ERR("[SMON] receive get table lock message to instance(%u) failed, sid(%u) rmid(%u) errcode(%u)",
                          dst_inst, sid, rmid, ret);
        return ret;
    }

    knl_end_session_wait(session, DEAD_LOCK_TABLE);
    ret = memcpy_s((char *)tlock, sizeof(dtc_tlock), recv_msg.buffer + sizeof(mes_message_head_t), sizeof(dtc_tlock));
    knl_securec_check(ret);

    mes_release_message_buf(recv_msg.buffer);
    DTC_DLS_DEBUG_INF("[SMON] request get table lock message to instance(%u), sid(%u) rmid(%u)", dst_inst, sid, rmid);
    return ret;
}

bool32 dtc_smon_request_remote_shared_wait_table(knl_session_t *session, uint8 *w_marks, dtc_dlock_stack_t *stack_lock, uint64 table_id)
{
    for (uint32 i = 0; i < g_dtc->profile.node_count; i++) {
        if (i == g_dtc->profile.inst_id) {
            continue;
        }
        if (dtc_smon_request_wait_tlocks_msg(session, w_marks, stack_lock, i, table_id,
                                             MES_CMD_DEAD_LOCK_WAIT_SHARED_TABLES) != CT_SUCCESS) {
            return CT_FALSE;
        }
    }
    return CT_TRUE;
}

bool32 dtc_smon_push_tlock(knl_session_t *session, uint8 *w_marks, dtc_dlock_stack_t *stack_lock,
                           uint32 inst_id, uint64 table_id)
{
    knl_session_t *lock_session = NULL;
    dtc_tlock tlock;
    lock_twait_t wtid;
    schema_lock_t *lock = NULL;
    dc_entry_t *entry = NULL;
    dc_user_t *user = NULL;
    uint32 winstid;
    uint16 wsid;

    if (session->kernel->dtc_attr.inst_id != inst_id) {
        if (dtc_smon_request_wait_tlocks_msg(session, w_marks, stack_lock, inst_id, table_id, MES_CMD_DEAD_LOCK_WAIT_TABLES) != CT_SUCCESS) {
            return CT_FALSE;
        }
        return CT_TRUE;
    }

    wtid.value = table_id;
    if (dc_open_user_by_id(session, wtid.uid, &user) != CT_SUCCESS) {
        return CT_FALSE;
    }

    entry = DC_GET_ENTRY(user, wtid.oid);
    if (entry == NULL) {
        return CT_FALSE;
    }

    cm_spin_lock(&entry->lock, &session->stat->spin_stat.stat_dc_entry);
    if ((!entry->ready) || (entry->recycled)) {
        cm_spin_unlock(&entry->lock);
        return CT_FALSE;
    }
    lock = entry->sch_lock;
    cm_spin_unlock(&entry->lock);

    if (lock == NULL) {
        return CT_FALSE;
    }
    winstid = lock->inst_id;
    if (winstid == CT_INVALID_ID8) {
        return CT_FALSE;
    }

    for (uint32 i = 0; i < session->kernel->rm_count; i++) {
        if (lock->map[i] != 0) {
            uint16 id = knl_get_rm_sid(session, i);
            if (id == CT_INVALID_ID16) {
                continue;
            }

            lock_session = session->kernel->sessions[id];
            if (lock_session == NULL) {
                return CT_FALSE;
            }

            if (lock_session->lock_dead_locked) {
                return CT_FALSE;
            }

            if (lock->mode == LOCK_MODE_X) {
                if (session->kernel->dtc_attr.inst_id == winstid) {
                    if (lock->dls_tbllock_done != CT_TRUE) {
                        continue;
                    }
                    //get local table wait
                    wsid = dtc_smon_get_rm_sid(session, winstid, i);
                    if (wsid == CT_INVALID_ID16) {
                        return CT_FALSE;
                    }
                    if (w_marks[winstid * CT_MAX_SESSIONS + wsid] == 0) {
                        tlock.inst_id = winstid;
                        tlock.sid = wsid;
                        tlock.wtid = lock_session->wtid;
                        tlock.rmid = lock_session->rmid;
                        tlock.wrmid = lock_session->wrmid;
                        if (dtc_dlock_push_with_check(stack_lock, &tlock, sizeof(dtc_tlock))) {
                            w_marks[winstid * CT_MAX_SESSIONS + wsid] = 1;
                        }
                    }

                    //lock by local instance, maybe wait for remote shared table lock
                    if (dtc_smon_request_remote_shared_wait_table(session, w_marks, stack_lock, table_id) == CT_FALSE) {
                        return CT_FALSE;
                    }
                } else {
                    // lock by remote instance, get remote session wait table info
                    if (dtc_smon_request_wait_tlock_msg(session, &tlock, winstid, table_id) != CT_SUCCESS) {
                        return CT_FALSE;
                    }
                    if (tlock.sid != CT_INVALID_ID16 && w_marks[tlock.inst_id * CT_MAX_SESSIONS + tlock.sid] == 0) {
                        if (tlock.inst_id != winstid) {
                            return CT_FALSE;
                        }
                        if (dtc_dlock_push_with_check(stack_lock, &tlock, sizeof(dtc_tlock))) {
                            w_marks[tlock.inst_id * CT_MAX_SESSIONS + tlock.sid] = 1;
                        }
                    }
                }
            } else {
                wsid = dtc_smon_get_rm_sid(session, winstid, i);
                if (wsid == CT_INVALID_ID16) {
                    return CT_FALSE;
                }
                //shared table lock , can get session wait info localily
                if (w_marks[winstid * CT_MAX_SESSIONS + wsid] == 0) {
                    tlock.inst_id = winstid;
                    tlock.sid = wsid;
                    tlock.wtid = lock_session->wtid;
                    tlock.rmid = lock_session->rmid;
                    tlock.wrmid = lock_session->wrmid;
                    if (dtc_dlock_push_with_check(stack_lock, &tlock, sizeof(dtc_tlock))) {
                        w_marks[winstid * CT_MAX_SESSIONS + wsid] = 1;
                    }
                }
            }
        }
    }

    if (lock_session == NULL) {
        return CT_FALSE;
    }
    return CT_TRUE;
}

void dtc_smon_process_check_tlock_msg(void *sess, mes_message_t * receive_msg)
{
    status_t ret = CT_SUCCESS;
    uint8 *send_msg = NULL;
    mes_message_head_t* head = NULL;
    knl_session_t *session = (knl_session_t *)sess;
    uint32 mes_size = sizeof(mes_message_head_t) + sizeof(bool32);
    bool32 in_use = CT_FALSE;
    dtc_tlock tlock;
    if (sizeof(mes_message_head_t) + sizeof(uint64) != receive_msg->head->size) {
        CT_LOG_RUN_ERR("msg is invalid, msg size %u.", receive_msg->head->size);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    tlock.wtid.value = *(uint64*)(receive_msg->buffer + sizeof(mes_message_head_t));
    tlock.inst_id = session->kernel->dtc_attr.inst_id;

    send_msg = (uint8*)cm_push(session->stack, mes_size);
    if (send_msg == NULL) {
        CT_LOG_RUN_ERR("send_msg failed to malloc memory, send_msg size %u.", mes_size);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    head = (mes_message_head_t*)send_msg;
    mes_init_ack_head(receive_msg->head, head, MES_CMD_DEAD_LOCK_CHECK_TABLE_ACK, mes_size, CT_INVALID_ID16);
    //must be local table id
    in_use = dtc_smon_check_table_status(session, &tlock);
     *((bool32*)(send_msg + sizeof(mes_message_head_t))) = in_use;

    ret = mes_send_data(send_msg);
    if (ret != CT_SUCCESS) {
        DTC_DLS_DEBUG_ERR("[SMON] process check tlock message from instance(%u) table_id(%llu) failed, ret(%u)",
            receive_msg->head->src_inst, tlock.wtid.value, ret);
    }
    cm_pop(session->stack);
    DTC_DLS_DEBUG_ERR("[SMON] process check tlock message from instance(%u) table_id(%llu) in_use(%u)",
        receive_msg->head->src_inst, tlock.wtid.value, in_use);
    mes_release_message_buf(receive_msg->buffer);
    return;
}

status_t dtc_smon_request_check_tlock_msg(knl_session_t *session, uint8 dst_inst, uint64 table_id, bool32* in_use)
{
    errno_t ret;
    uint8 *send_msg = NULL;
    uint16 msg_size = sizeof(mes_message_head_t) + sizeof(uint64);
    mes_message_head_t* head = NULL;
    mes_message_t    recv_msg = {0};
    uint32   rsn = 0;
    uint8    src_inst = session->kernel->dtc_attr.inst_id;

    send_msg = (uint8*)cm_push(session->stack, msg_size);
    head = (mes_message_head_t*)send_msg;
    mes_init_send_head(head, MES_CMD_DEAD_LOCK_CHECK_TABLE, msg_size, CT_INVALID_ID32, src_inst, dst_inst, session->id,
                       CT_INVALID_ID16);
    *((uint64*)(send_msg + sizeof(mes_message_head_t))) = table_id;

    knl_begin_session_wait(session, DEAD_LOCK_TABLE, CT_TRUE);
    ret = mes_send_data(send_msg);
    if (ret != CT_SUCCESS) {
        knl_end_session_wait(session, DEAD_LOCK_TABLE);
        cm_pop(session->stack);
        DTC_DLS_DEBUG_ERR("[SMON] request check table lock message to instance(%u) failed, table_id(%llu) errcode(%u)", dst_inst, table_id, ret);
        return ret;
    }
    cm_pop(session->stack);

    ret = mes_recv(session->id, &recv_msg, CT_FALSE, rsn, DTC_SMON_WAIT_TIMEOUTMS);
    if (ret != CT_SUCCESS) {
        knl_end_session_wait(session, DEAD_LOCK_TABLE);
        DTC_DLS_DEBUG_ERR("[SMON] receive check table lock message to instance(%u) failed, table_id(%llu) errcode(%u)", dst_inst, table_id, ret);
        return ret;
    }

    knl_end_session_wait(session, DEAD_LOCK_TABLE);
    *in_use = *(bool32*)(recv_msg.buffer + sizeof(mes_message_head_t));
    mes_release_message_buf(recv_msg.buffer);

    DTC_DLS_DEBUG_INF("[SMON] request check table lock message to instance(%u), table_id(%llu) status(%u)", dst_inst, table_id, *in_use);
    return ret;
}

bool32 dtc_smon_check_table_status(knl_session_t *session, dtc_tlock* tlock)
{
    schema_lock_t *lock = NULL;
    dc_entry_t *entry = NULL;
    dc_user_t *user = NULL;
    lock_twait_t curr_wtid;
    bool32 in_use = CT_FALSE;

    if (session->kernel->dtc_attr.inst_id == tlock->inst_id) {
        curr_wtid.value = tlock->wtid.value;
        if (dc_open_user_by_id(session, curr_wtid.uid, &user) != CT_SUCCESS) {
            return CT_FALSE;
        }

        entry = DC_GET_ENTRY(user, curr_wtid.oid);
        if (entry == NULL) {
            return CT_FALSE;
        }

        cm_spin_lock(&entry->lock, &session->stat->spin_stat.stat_dc_entry);
        if ((!entry->ready) || (entry->recycled)) {
            cm_spin_unlock(&entry->lock);
            return CT_FALSE;
        }
        lock = entry->sch_lock;
        cm_spin_unlock(&entry->lock);
        if (lock == NULL) {
            return CT_FALSE;
        }
        return CT_TRUE;
    }

    if (dtc_smon_request_check_tlock_msg(session, tlock->inst_id, tlock->wtid.value, &in_use) != CT_SUCCESS) {
        return CT_FALSE;
    }
    return in_use;
}

void dtc_smon_get_tlock_from_wait_session(knl_session_t *session, uint16 wsid, uint16 rmid, dtc_tlock *tlock)
{
    knl_session_t *wait_session = session->kernel->sessions[wsid];
    if (wait_session != NULL && wait_session->rmid == rmid) {
        // resource not changed
        tlock->inst_id = session->kernel->dtc_attr.inst_id;
        tlock->sid = wsid;
        tlock->rmid = wait_session->rmid;
        tlock->wrmid = wait_session->wrmid;
        tlock->wtid = wait_session->wtid;
    }
}

void dtc_smon_wait_rm_msg(knl_session_t *session, uint16 wsid, uint16 rmid, dtc_tlock *tlock)
{
    knl_session_t *lock_session = session->kernel->sessions[wsid];
    // resource not changed
    if (lock_session != NULL && lock_session->wrmid != CT_INVALID_ID16 && lock_session->wrmid == rmid) {
        uint32 instid = xid_get_inst_id(lock_session, lock_session->wxid);
        uint16 sid = dtc_smon_get_rm_sid(session, instid, lock_session->wrmid);
        if (sid == CT_INVALID_ID16) {
            return;
        }
        if (session->kernel->dtc_attr.inst_id == instid) {
            dtc_smon_get_tlock_from_wait_session(session, sid, rmid, tlock);
        } else {
            (void)dtc_smon_request_itl_tlock_msg(session, tlock, instid, sid, rmid, MES_CMD_DEAD_LOCK_GET_RM);
        }
    }
}

void dtc_smon_process_get_tlock_msg(void *sess, mes_message_t *receive_msg)
{
    status_t ret = CT_SUCCESS;
    uint8 *send_msg = NULL;
    mes_message_head_t* head = NULL;
    knl_session_t *session = (knl_session_t *)sess;
    if (sizeof(mes_message_head_t) + sizeof(uint16) + sizeof(uint16) != receive_msg->head->size) {
        CT_LOG_RUN_ERR("msg is invalid, msg size %u.", receive_msg->head->size);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    uint16 wsid = *(uint16*)(receive_msg->buffer + sizeof(mes_message_head_t));
    uint16 rmid = *(uint16*)(receive_msg->buffer + sizeof(mes_message_head_t) + sizeof(uint16));
    uint32 mes_size = sizeof(mes_message_head_t) + sizeof(dtc_tlock);
    dtc_tlock* tlock;

    send_msg = (uint8*)cm_push(session->stack, mes_size);
    if (send_msg == NULL) {
        CT_LOG_RUN_ERR("send_msg failed to malloc memory, send_msg size %u.", mes_size);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    head = (mes_message_head_t*)send_msg;
    mes_init_ack_head(receive_msg->head, head, MES_CMD_DEAD_LOCK_TABLE_ACK, mes_size, CT_INVALID_ID16);
    tlock = (dtc_tlock*)(send_msg + sizeof(mes_message_head_t));
    tlock->sid = CT_INVALID_ID16;

    if (wsid != CT_INVALID_ID16 && wsid < CT_MAX_SESSIONS) {
        if (receive_msg->head->cmd  == MES_CMD_DEAD_LOCK_WAIT_RM) {
            dtc_smon_wait_rm_msg(session, wsid, rmid, tlock);
        } else if (receive_msg->head->cmd == MES_CMD_DEAD_LOCK_GET_RM) {
            dtc_smon_get_tlock_from_wait_session(session, wsid, rmid, tlock);
        } else {
        }
    }

    ret = mes_send_data(send_msg);
    if (ret != CT_SUCCESS) {
        DTC_DLS_DEBUG_INF("[SMON] process get tlock message from instance(%u) rmid(%u) failed, ret(%u)", receive_msg->head->src_inst, rmid, ret);
    }
    cm_pop(session->stack);
    DTC_DLS_DEBUG_INF("[SMON] process get tlock message from instance(%u) rmid(%u)", receive_msg->head->src_inst, rmid);
    mes_release_message_buf(receive_msg->buffer);
    return;
}

void dtc_smon_push_itl_to_tlock(knl_session_t *session, uint8 *w_marks, dtc_dlock_stack_t *stack_lock, uint32 inst_id,
                                uint16 wsid, uint16 wrmid)
{
    knl_session_t *lock_session = NULL;
    knl_session_t *wait_session = NULL;
    dtc_tlock* tlock;

    if (wrmid == CT_INVALID_ID16 || wsid == CT_INVALID_ID16) {
        return;
    }

    if (session->kernel->dtc_attr.inst_id == inst_id) {
        lock_session = session->kernel->sessions[wsid];
        if (lock_session == NULL || lock_session->status == SESSION_INACTIVE ||
            lock_session->wrmid == CT_INVALID_ID16 || lock_session->wrmid != wrmid) {
            //resource changed
            return;
        }

        uint32 instid = xid_get_inst_id(lock_session, lock_session->wxid);
        uint16 sid = dtc_smon_get_rm_sid(session, instid, lock_session->wrmid);
        if (sid == CT_INVALID_ID16) {
            return;
        }
        if (session->kernel->dtc_attr.inst_id == instid) {
            wait_session = session->kernel->sessions[sid];
            if (wait_session == NULL || wait_session->status == SESSION_INACTIVE ||
                wait_session->id == CT_INVALID_ID16 || wait_session->rmid != wrmid) {
                //resource changed
                return;
            }
            //wait local resource
            if (w_marks[instid * CT_MAX_SESSIONS + sid] == 0) {
                tlock = (dtc_tlock*)cm_push(session->stack, sizeof(dtc_tlock));
                tlock->inst_id = instid;
                tlock->sid = sid;
                tlock->rmid = wait_session->rmid;
                tlock->wrmid = wait_session->wrmid;
                tlock->wtid = wait_session->wtid;
                if (dtc_dlock_push_with_check(stack_lock, tlock, sizeof(dtc_tlock))) {
                    w_marks[instid * CT_MAX_SESSIONS + sid] = 1;
                }
                cm_pop(session->stack);
            }
        } else {
            tlock = (dtc_tlock*)cm_push(session->stack, sizeof(dtc_tlock));
            tlock->sid = CT_INVALID_ID16;
            (void)dtc_smon_request_itl_tlock_msg(session, tlock, instid, sid, wrmid, MES_CMD_DEAD_LOCK_GET_RM);
            if (tlock->sid != CT_INVALID_ID16 && w_marks[tlock->inst_id * CT_MAX_SESSIONS + tlock->sid] == 0) {
                knl_panic(tlock->inst_id == instid);
                knl_panic(tlock->sid == sid);
                if (dtc_dlock_push_with_check(stack_lock, tlock, sizeof(dtc_tlock))) {
                    w_marks[tlock->inst_id * CT_MAX_SESSIONS + tlock->sid] = 1;
                }
            }
            cm_pop(session->stack);
        }
    } else {
        //remote
        tlock = (dtc_tlock*)cm_push(session->stack, sizeof(dtc_tlock));
        tlock->sid = CT_INVALID_ID16;
        (void)dtc_smon_request_itl_tlock_msg(session, tlock, inst_id, wsid, wrmid, MES_CMD_DEAD_LOCK_WAIT_RM);
        //tlock->sid == CT_INVALID_ID16 means no table
        if (tlock->sid != CT_INVALID_ID16 && w_marks[tlock->inst_id * CT_MAX_SESSIONS + tlock->sid] == 0) {
            if (dtc_dlock_push_with_check(stack_lock, tlock, sizeof(dtc_tlock))) {
                w_marks[tlock->inst_id * CT_MAX_SESSIONS + tlock->sid] = 1;
            }
        }
        cm_pop(session->stack);
    }

    return;
}

void dtc_smon_process_wait_event_msg(void *sess, mes_message_t * receive_msg)
{
    status_t ret = CT_SUCCESS;
    uint8 *send_msg = NULL;
    mes_message_head_t* head = NULL;
    knl_session_t *session = (knl_session_t *)sess;
    uint32 mes_size = sizeof(mes_message_head_t) + sizeof(bool32);
    bool32 in_use = CT_FALSE;
    if (sizeof(mes_message_head_t) + sizeof(uint16) != receive_msg->head->size) {
        CT_LOG_RUN_ERR("msg is invalid, msg size %u.", receive_msg->head->size);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    uint16 sid = *(uint16 *)(receive_msg->buffer + sizeof(mes_message_head_t));

    send_msg = (uint8*)cm_push(session->stack, mes_size);
    if (send_msg == NULL) {
        CT_LOG_RUN_ERR("send_msg failed to malloc memory, send_msg size %u.", mes_size);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    head = (mes_message_head_t*)send_msg;
    mes_init_ack_head(receive_msg->head, head, MES_CMD_DEAD_LOCK_WAIT_EVENT_ACK, mes_size, CT_INVALID_ID16);
    //must be local sid
    in_use = dtc_smon_check_wait_event(session, session->kernel->dtc_attr.inst_id, sid);
     *((bool32*)(send_msg + sizeof(mes_message_head_t))) = in_use;

    ret = mes_send_data(send_msg);
    if (ret != CT_SUCCESS) {
        DTC_DLS_DEBUG_ERR("[SMON] process wait event message from instance(%u) sid(%u) failed, ret(%u)",
            receive_msg->head->src_inst, sid, ret);
    }
    cm_pop(session->stack);
    DTC_DLS_DEBUG_ERR("[SMON] process wait event message from instance(%u) sid(%u) in_use(%u)",
        receive_msg->head->src_inst, sid, in_use);
    mes_release_message_buf(receive_msg->buffer);
    return;
}

status_t dtc_smon_request_wait_event(knl_session_t *session, uint8 dst_inst, uint16 sid, bool32 *in_use)
{
    errno_t ret;
    uint8 *send_msg = NULL;
    uint16 msg_size = sizeof(mes_message_head_t) + sizeof(uint16);
    mes_message_head_t* head = NULL;
    mes_message_t recv_msg = {0};
    uint32   rsn = 0;
    uint8    src_inst = session->kernel->dtc_attr.inst_id;

    send_msg = (uint8*)cm_push(session->stack, msg_size);
    if (send_msg == NULL) {
        CT_LOG_RUN_ERR("send_msg failed to malloc memory, send_msg size %u.", msg_size);
        return CT_ERROR;
    }
    head = (mes_message_head_t*)send_msg;
    mes_init_send_head(head, MES_CMD_DEAD_LOCK_WAIT_EVENT, msg_size, CT_INVALID_ID32, src_inst, dst_inst, session->id,
                       CT_INVALID_ID16);
    *((uint16*)(send_msg + sizeof(mes_message_head_t))) = sid;

    knl_begin_session_wait(session, DEAD_LOCK_TABLE, CT_TRUE);
    ret = mes_send_data(send_msg);
    if (ret != CT_SUCCESS) {
        knl_end_session_wait(session, DEAD_LOCK_TABLE);
        cm_pop(session->stack);
        DTC_DLS_DEBUG_ERR("[SMON] request check session wait event message to instance(%u) failed, sid(%u) errcode(%u)", dst_inst, sid, ret);
        return ret;
    }
    cm_pop(session->stack);

    ret = mes_recv(session->id, &recv_msg, CT_FALSE, rsn, DTC_SMON_WAIT_TIMEOUTMS);
    if (ret != CT_SUCCESS) {
        knl_end_session_wait(session, DEAD_LOCK_TABLE);
        DTC_DLS_DEBUG_ERR("[SMON] receive check session wait event message to instance(%u) failed, sid(%u) errcode(%u)", dst_inst, sid, ret);
        return ret;
    }

    knl_end_session_wait(session, DEAD_LOCK_TABLE);
    *in_use = *(bool32*)(recv_msg.buffer + sizeof(mes_message_head_t));
    mes_release_message_buf(recv_msg.buffer);

    DTC_DLS_DEBUG_INF("[SMON] request check session wait event message to instance(%u), sid(%u) status(%u)", dst_inst, sid, *in_use);
    return ret;
}

bool32 dtc_smon_check_wait_event(knl_session_t *session, uint8 inst_id, uint16 sid)
{
    knl_session_t *se;
    bool32 in_use = CT_FALSE;
    if (sid == CT_INVALID_ID16 || sid >= CT_MAX_SESSIONS) {
        return CT_FALSE;
    }

    if (session->kernel->dtc_attr.inst_id == inst_id) {
        se = session->kernel->sessions[sid];
        if (se == NULL || se->status != SESSION_ACTIVE) {
            return CT_FALSE;
        }
        if (se->wait_pool[ENQ_TX_TABLE_S].is_waiting || se->wait_pool[ENQ_TX_TABLE_X].is_waiting) {
            return CT_TRUE;
        }
        return CT_FALSE;
    }

    if (dtc_smon_request_wait_event(session, inst_id, sid, &in_use) != CT_SUCCESS) {
        return CT_FALSE;
    }
    return in_use;
}

bool32 dtc_smon_check_lock_waits_in_cluster(knl_session_t *session, knl_session_t *se, bool32 record_sql)
{
    errno_t ret;
    dtc_dlock_stack_t *stack_lock = NULL;
    uint8 *w_marks = NULL;
    dtc_tlock* tlock;
    lock_twait_t wtid;
    uint32 count;

    if (se == NULL || se->status != SESSION_ACTIVE || !se->wtid.is_locking) {
        return CT_FALSE;
    }

    stack_lock = &g_tlock_stack;
    dtc_dlock_reset(stack_lock);
    count = CT_MAX_SESSIONS * CT_MAX_INSTANCES * sizeof(uint8);
    w_marks = (void *)cm_malloc(count);
    if (w_marks == NULL) {
        CT_LOG_RUN_ERR("dtc table deadlock malloc size(%u) failed", count);
        return CT_FALSE;
    }
    ret = memset_sp(w_marks, count, 0, count);
    knl_securec_check(ret);

    wtid.value = cm_atomic_get(&se->wtid.value);
    if (!dtc_smon_push_tlock(session, w_marks, stack_lock, se->kernel->dtc_attr.inst_id, wtid.value)) {
        cm_free(w_marks);
        return CT_FALSE;
    }

    if (record_sql) {
        CT_LOG_TRACE("session id: %u-%u, wait object id: %u-%u", se->kernel->dtc_attr.inst_id, se->id, se->wtid.uid, se->wtid.oid);
        dtc_smon_record_deadlock_sql(session, DEAD_LOCK_TABLE, se->kernel->dtc_attr.inst_id, se->id);
    }

    if (dtc_dlock_is_empty(stack_lock)) {
        cm_free(w_marks);
        DTC_DLS_DEBUG_INF("[SMON] no table wait found, sid(%u)", se->id);
        return CT_FALSE;
    }

    while (!dtc_dlock_is_empty(stack_lock)) {
        tlock = (dtc_tlock *)dtc_dlock_top(stack_lock);
        dtc_dlock_pop(stack_lock);

        if (se->kernel->dtc_attr.inst_id == tlock->inst_id && se->rmid == tlock->rmid) {
            continue;
        }

        if (dtc_smon_check_wait_event(session, tlock->inst_id, tlock->sid)) {
            if (!dtc_smon_check_table_status(session, tlock)) {
                cm_free(w_marks);
                return CT_FALSE;
            }
            if (record_sql) {
                CT_LOG_TRACE("session id: %u-%u, wait object id: %u-%u", tlock->inst_id, tlock->sid, tlock->wtid.uid, tlock->wtid.oid);
                dtc_smon_record_deadlock_sql(session, DEAD_LOCK_TABLE, tlock->inst_id, tlock->sid);
            }

            if (!dtc_smon_push_tlock(session, w_marks, stack_lock, tlock->inst_id, tlock->wtid.value)) {
                cm_free(w_marks);
                return CT_FALSE;
            }
        } else if (tlock->wrmid != CT_INVALID_ID16) {
            if (record_sql) {
                CT_LOG_TRACE("session id: %u-%u, wait rm id: %u", tlock->inst_id, tlock->sid, tlock->wrmid);
                dtc_smon_record_deadlock_sql(session, DEAD_LOCK_TABLE, tlock->inst_id, tlock->sid);
            }
            dtc_smon_push_itl_to_tlock(session, w_marks, stack_lock, tlock->inst_id, tlock->sid, tlock->wrmid);
        } else {
            cm_free(w_marks);
            return CT_FALSE;
        }
    }

    cm_free(w_marks);
    if (se->wtid.oid != wtid.oid || se->wtid.uid != wtid.uid || !se->wtid.is_locking) {
        return CT_FALSE;
    }
    // re-check deadlock and record SQL text
    if (!record_sql) {
        smon_record_deadlock_time();
        CT_LOG_TRACE("[Table Deadlock]");
        return dtc_smon_check_lock_waits_in_cluster(session, se, CT_TRUE);
    }
    CT_LOG_TRACE("-----------------END OF WAIT INFORMATION-----------------\n");
    return CT_TRUE;
}


void dtc_smon_process_get_ilock_msg(void *sess, mes_message_t * receive_msg)
{
    status_t ret = CT_SUCCESS;
    uint8 *send_msg = NULL;
    mes_message_head_t* head = NULL;
    knl_session_t *session = (knl_session_t *)sess;
    if (sizeof(mes_message_head_t) + sizeof(xid_t) != receive_msg->head->size) {
        CT_LOG_RUN_ERR("msg is invalid, msg size %u.", receive_msg->head->size);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    xid_t xid = *(xid_t*)(receive_msg->buffer + sizeof(mes_message_head_t));
    uint32 mes_size = sizeof(mes_message_head_t) + sizeof(dtc_ilock);
    dtc_ilock* ilock;
    knl_session_t *se = NULL;

    send_msg = (uint8*)cm_push(session->stack, mes_size);
    if (send_msg == NULL) {
        CT_LOG_RUN_ERR("send_msg failed to malloc memory, send_msg size %u.", mes_size);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    head = (mes_message_head_t*)send_msg;
    mes_init_ack_head(receive_msg->head, head, MES_CMD_DEAD_LOCK_GET_ITL_ACK, mes_size, CT_INVALID_ID16);
    ilock = (dtc_ilock*)(send_msg + sizeof(mes_message_head_t));

    ilock->sid = CT_INVALID_ID16;
    if (xid.xmap.slot / TXN_PER_PAGE(session) >= UNDO_MAX_TXN_PAGE) {
        CT_LOG_RUN_ERR("[SMON] process get ilock message xmap slot invalid slot(%u).", xid.xmap.slot);
    } else {
        se = get_xid_session(session, xid);
    }
    if (se != NULL && se->id != CT_INVALID_ID16) {
        ilock->status = se->status;
        ilock->wpid = se->wpid;
        ilock->wxid = se->wxid;
        ilock->sid = se->id;
        ilock->xid = xid;
    }

    ret = mes_send_data(send_msg);
    if (ret != CT_SUCCESS) {
        DTC_DLS_DEBUG_INF("[SMON] process get ilock message from instance(%u) xid(%llu) failed, ret(%u)", receive_msg->head->src_inst, xid.value, ret);
    }
    cm_pop(session->stack);
    DTC_DLS_DEBUG_INF("[SMON] process get ilock message from instance(%u) xid(%llu)", receive_msg->head->src_inst, xid.value);
    mes_release_message_buf(receive_msg->buffer);
    return;
}


status_t dtc_smon_request_get_ilock_msg(knl_session_t *session, uint8 *w_marks, dtc_dlock_stack_t *stack_lock, xid_t xid)
{
    errno_t ret;
    uint8 *send_msg = NULL;
    uint16 msg_size = sizeof(mes_message_head_t) + sizeof(xid_t);
    mes_message_head_t* head = NULL;
    mes_message_t    recv_msg = {0};
    uint32   rsn = 0;
    uint8    src_inst = session->kernel->dtc_attr.inst_id;
    uint8 dst_inst = xid_get_inst_id(session, xid);
    dtc_ilock* ilock;

    send_msg = (uint8*)cm_push(session->stack, msg_size);
    head = (mes_message_head_t*)send_msg;
    mes_init_send_head(head, MES_CMD_DEAD_LOCK_GET_ITL, msg_size, CT_INVALID_ID32, src_inst, dst_inst, session->id,
                       CT_INVALID_ID16);
    *((xid_t*)(send_msg + sizeof(mes_message_head_t))) = xid;

    knl_begin_session_wait(session, DEAD_LOCK_ITL, CT_TRUE);
    ret = mes_send_data(send_msg);
    if (ret != CT_SUCCESS) {
        knl_end_session_wait(session, DEAD_LOCK_ITL);
        cm_pop(session->stack);
        DTC_DLS_DEBUG_ERR("[SMON] request get itl lock message to instance(%u) failed, xid(%llu) errcode(%u)", dst_inst, xid.value, ret);
        return ret;
    }
    cm_pop(session->stack);

    ret = mes_recv(session->id, &recv_msg, CT_FALSE, rsn, DTC_SMON_WAIT_TIMEOUTMS);
    if (ret != CT_SUCCESS) {
        knl_end_session_wait(session, DEAD_LOCK_ITL);
        DTC_DLS_DEBUG_ERR("[SMON] receive get itl lock message to instance(%u) failed, xid(%llu) errcode(%u)", dst_inst, xid.value, ret);
        return ret;
    }

    knl_end_session_wait(session, DEAD_LOCK_ITL);
    ilock = (dtc_ilock*)(recv_msg.buffer + sizeof(mes_message_head_t));
    //ilock->sid == CT_INVALID_ID16 means no itl
    if (ilock->sid != CT_INVALID_ID16 && w_marks[dst_inst * CT_MAX_SESSIONS + ilock->sid] == 0) {
        if (dtc_dlock_push_with_check(stack_lock, ilock, sizeof(dtc_ilock))) {
            w_marks[dst_inst * CT_MAX_SESSIONS + ilock->sid] = 1;
        }
    }
    mes_release_message_buf(recv_msg.buffer);
    DTC_DLS_DEBUG_INF("[SMON] request get itl lock message to instance(%u), xid(%llu)", dst_inst, xid.value);
    return ret;
}


static bool32 dtc_smon_push_xid_ilock(knl_session_t *session, uint8 *w_marks, dtc_dlock_stack_t *dlock_stack, xid_t xid)
{
    knl_session_t *next_session = NULL;
    uint8 inst_id;
    dtc_ilock ilock;

    inst_id = xid_get_inst_id(session, xid);
    if (session->kernel->dtc_attr.inst_id == inst_id) {
        next_session = get_xid_session(session, xid);
        if (next_session == NULL) {
            CT_LOG_DEBUG_INF("put itl sessions in cluster, the session being waited by start session (%u) is ended.", session->id);
            return CT_FALSE;
        }

        ilock.status = next_session->status;
        ilock.wpid = next_session->wpid;
        ilock.wxid = next_session->wxid;
        ilock.sid = next_session->id;
        ilock.xid = xid;
        if (w_marks[inst_id * CT_MAX_SESSIONS + next_session->id] == 0) {
            if (dtc_dlock_push_with_check(dlock_stack, &ilock, sizeof(dtc_ilock))) {
                w_marks[inst_id * CT_MAX_SESSIONS + next_session->id] = 1;
            }
        }
    } else {
        //remote fetch back
        if (dtc_smon_request_get_ilock_msg(session, w_marks, dlock_stack, xid) != CT_SUCCESS) {
            return CT_FALSE;
        }
    }

    return CT_TRUE;
}

static bool32 dtc_smon_push_itl_sessions_ilock(knl_session_t *session, dtc_ilock *assist, page_head_t *head,
                                               dtc_dlock_stack_t *stack_ptr, uint8 *w_marks)
{
    pcr_itl_t *pcr_item = NULL;
    uint8 i;
    heap_page_t *heap_page = NULL;
    btree_page_t *btree_page = NULL;

    if (assist->status == SESSION_INACTIVE) {
        CT_LOG_RUN_INF("push itl sessions in cluster, start session(%u) is inactive.", assist->sid);
        return CT_FALSE;
    }

    switch (head->type) {
        case PAGE_TYPE_HEAP_DATA:
        case PAGE_TYPE_BTREE_NODE:
            CT_LOG_RUN_INF("push itl sessions in cluster not support in RCR mode.");
            break;

        case PAGE_TYPE_PCRH_DATA:
            heap_page = (heap_page_t *)head;
            for (i = 0; i < heap_page->itls; i++) {
                pcr_item = pcrh_get_itl(heap_page, i);
                if (!pcr_item->is_active) {
                    CT_LOG_RUN_INF("put itl sessions in cluster, found inactive itl in session (%u).", session->id);
                    return CT_FALSE;
                }
                if (pcr_item->xid.value == assist->xid.value) {
                    CT_LOG_RUN_INF("put itl sessions in cluster, start session (%u) already has an itl.", session->id);
                    return CT_FALSE;
                }
                if (!dtc_smon_push_xid_ilock(session, w_marks, stack_ptr, pcr_item->xid)) {
                    return CT_FALSE;
                }
            }
            break;

        case PAGE_TYPE_PCRB_NODE:
        default:
            btree_page = (btree_page_t *)head;
            for (i = 0; i < btree_page->itls; i++) {
                pcr_item = pcrb_get_itl(btree_page, i);
                if (!pcr_item->is_active) {
                    CT_LOG_RUN_INF("put itl sessions in cluster, found inactive itl in session (%u).", session->id);
                    return CT_FALSE;
                }
                if (pcr_item->xid.value == assist->xid.value) {
                    CT_LOG_RUN_INF("put itl sessions in cluster, start session (%u) already has an itl.", session->id);
                    return CT_FALSE;
                }
                if (!dtc_smon_push_xid_ilock(session, w_marks, stack_ptr, pcr_item->xid)) {
                    return CT_FALSE;
                }
            }
            break;
    }

    return CT_TRUE;
}

void dtc_smon_process_check_se_msg(void *sess, mes_message_t * receive_msg)
{
    status_t ret = CT_SUCCESS;
    uint8 *send_msg = NULL;
    mes_message_head_t* head = NULL;
    knl_session_t *session = (knl_session_t *)sess;
    uint32 mes_size = sizeof(mes_message_head_t) + sizeof(bool32);
    bool32 in_use = CT_FALSE;
    if (sizeof(mes_message_head_t) + sizeof(xid_t) != receive_msg->head->size) {
        CT_LOG_RUN_ERR("msg is invalid, msg size %u.", receive_msg->head->size);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    xid_t xid = *(xid_t*)(receive_msg->buffer + sizeof(mes_message_head_t));
    knl_session_t *curr_session = NULL;
    knl_rm_t *curr_rm = NULL;

    send_msg = (uint8*)cm_push(session->stack, mes_size);
    if (send_msg == NULL) {
        CT_LOG_RUN_ERR("send_msg failed to malloc memory, send_msg size %u.", mes_size);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    head = (mes_message_head_t*)send_msg;
    mes_init_ack_head(receive_msg->head, head, MES_CMD_DEAD_LOCK_CHECK_ITL_ACK, mes_size, CT_INVALID_ID16);
    if (xid.xmap.slot / TXN_PER_PAGE(session) >= UNDO_MAX_TXN_PAGE) {
        CT_LOG_RUN_ERR("[SMON] process check se message xmap slot invalid slot(%u).", xid.xmap.slot);
    } else {
        curr_session = get_xid_session(session, xid);
    }
    if (curr_session != NULL) {
        curr_rm = curr_session->rm;
        if (curr_session->status != SESSION_INACTIVE && curr_rm != NULL) {
            in_use = CT_TRUE;
        }
    }
    *((bool32*)(send_msg + sizeof(mes_message_head_t))) = in_use;

    ret = mes_send_data(send_msg);
    if (ret != CT_SUCCESS) {
        DTC_DLS_DEBUG_ERR("[SMON] process check ilock message from instance(%u) xid(%llu) failed, ret(%u)",
            receive_msg->head->src_inst, xid.value, ret);
    }
    cm_pop(session->stack);
    DTC_DLS_DEBUG_ERR("[SMON] process check ilock message from instance(%u) xid(%llu) in_use(%u)",
        receive_msg->head->src_inst, xid.value, in_use);
    mes_release_message_buf(receive_msg->buffer);
    return;
}


status_t dtc_smon_request_check_se_msg(knl_session_t *session, uint8 dst_inst, xid_t xid, bool32* in_use)
{
    errno_t ret;
    uint8 *send_msg = NULL;
    uint16 msg_size = sizeof(mes_message_head_t) + sizeof(xid_t);
    mes_message_head_t* head = NULL;
    mes_message_t recv_msg = {0};
    uint32 rsn = 0;
    uint8 src_inst = session->kernel->dtc_attr.inst_id;

    send_msg = (uint8*)cm_push(session->stack, msg_size);
    head = (mes_message_head_t*)send_msg;
    mes_init_send_head(head, MES_CMD_DEAD_LOCK_CHECK_ITL, msg_size, CT_INVALID_ID32, src_inst, dst_inst, session->id,
                       CT_INVALID_ID16);
    *((xid_t*)(send_msg + sizeof(mes_message_head_t))) = xid;

    knl_begin_session_wait(session, DEAD_LOCK_ITL, CT_TRUE);
    ret = mes_send_data(send_msg);
    if (ret != CT_SUCCESS) {
        knl_end_session_wait(session, DEAD_LOCK_ITL);
        cm_pop(session->stack);
        DTC_DLS_DEBUG_ERR("[SMON] request check itl lock message to instance(%u) failed, xid(%llu) errcode(%u)", dst_inst, xid.value, ret);
        return ret;
    }
    cm_pop(session->stack);

    ret = mes_recv(session->id, &recv_msg, CT_FALSE, rsn, DTC_SMON_WAIT_TIMEOUTMS);
    if (ret != CT_SUCCESS) {
        knl_end_session_wait(session, DEAD_LOCK_ITL);
        DTC_DLS_DEBUG_ERR("[SMON] receive check itl lock message to instance(%u) failed, xid(%llu) errcode(%u)", dst_inst, xid.value, ret);
        return ret;
    }

    knl_end_session_wait(session, DEAD_LOCK_ITL);
    *in_use = *(bool32*)(recv_msg.buffer + sizeof(mes_message_head_t));
    mes_release_message_buf(recv_msg.buffer);

    DTC_DLS_DEBUG_INF("[SMON] request check itl lock message to instance(%u), xid(%llu) status(%u)", dst_inst, xid.value, *in_use);
    return ret;
}


bool32 dtc_smon_check_se_status(knl_session_t *session, knl_session_t *start_session, dtc_ilock* ilock)
{
    bool32 in_use = CT_FALSE;
    knl_session_t *curr_session = NULL;
    knl_rm_t *curr_rm = NULL;
    knl_rm_t *start_rm = NULL;
    uint8 inst_id = xid_get_inst_id(session, ilock->xid);

    start_rm = start_session->rm;
    if (start_session->status == SESSION_INACTIVE ||  start_rm == NULL) {
        return CT_FALSE;
    }

    if (session->kernel->dtc_attr.inst_id == inst_id) {
        curr_session = get_xid_session(session, ilock->xid);
        if (curr_session == NULL) {
            CT_LOG_RUN_INF("put itl sessions in cluster, the session being waited by xid (%llu) is ended.", ilock->xid.value);
            return CT_FALSE;
        }
        curr_rm = curr_session->rm;
        if (curr_session->status == SESSION_INACTIVE || curr_rm == NULL) {
            return CT_FALSE;
        }
        return CT_TRUE;
    }

    if (dtc_smon_request_check_se_msg(session, inst_id, ilock->xid, &in_use) != CT_SUCCESS) {
        return CT_FALSE;
    }
    return in_use;
}

bool32 dtc_smon_check_itl_waits_in_cluster(knl_session_t *session, knl_session_t *start_session, bool32 record_sql)
{
    page_head_t *curr_page = NULL;
    uint8 *w_marks = NULL;
    xid_t curr_wxid;
    page_id_t start_wpid, curr_wpid;
    dtc_dlock_stack_t *stack_ptr;
    knl_rm_t *start_rm = NULL;
    uint32 max_sessions;
    errno_t ret;
    dtc_ilock *ilock;
    dtc_ilock assist;

    max_sessions = CT_MAX_SESSIONS * CT_MAX_INSTANCES;
    stack_ptr = &g_ilock_stack;
    dtc_dlock_reset(stack_ptr);
    w_marks = (uint8 *)malloc(max_sessions * sizeof(uint8));
    if (w_marks == NULL) {
        CT_LOG_RUN_ERR("dtc itl deadlock malloc size(%u) failed", max_sessions);
    }
    ret = memset_sp(w_marks, max_sessions, 0, max_sessions);
    knl_securec_check(ret);

    if (start_session->status == SESSION_INACTIVE) {
        free(w_marks);
        return CT_FALSE;
    }

    start_wpid = start_session->wpid;
    if (IS_INVALID_PAGID(start_wpid)) {
        free(w_marks);
        return CT_FALSE;
    }

    if (buf_read_page(session, start_wpid, LATCH_MODE_S, ENTER_PAGE_NORMAL) != CT_SUCCESS) {
        cm_reset_error();
        free(w_marks);
        return CT_FALSE;
    }
    curr_page = (page_head_t *)CURR_PAGE(session);

    if (record_sql) {
        CT_LOG_TRACE("session id: %u-%u, wait page_id: %u-%u", start_session->kernel->dtc_attr.inst_id, start_session->id, start_wpid.file, start_wpid.page);
        dtc_smon_record_deadlock_sql(session, DEAD_LOCK_ITL, start_session->kernel->dtc_attr.inst_id, start_session->id);
    }

    assist.status = start_session->status;
    assist.xid = start_session->rm->xid;
    assist.sid = start_session->id;
    if (!dtc_smon_push_itl_sessions_ilock(session, &assist, curr_page, stack_ptr, w_marks)) {
        buf_leave_page(session, CT_FALSE);
        free(w_marks);
        return CT_FALSE;
    }
    buf_leave_page(session, CT_FALSE);

    while (!dtc_dlock_is_empty(stack_ptr)) {
        ilock = (dtc_ilock *)dtc_dlock_top(stack_ptr);
        dtc_dlock_pop(stack_ptr);

        start_rm = start_session->rm;
        if (ilock->xid.value == start_rm->xid.value) {
            continue;
        }
        if (!dtc_smon_check_se_status(session, start_session, ilock)) {
            free(w_marks);
            return CT_FALSE;
        }

        curr_wpid = ilock->wpid;
        curr_wxid = ilock->wxid;
        if (curr_wxid.value == CT_INVALID_ID64 && IS_INVALID_PAGID(curr_wpid)) {
            free(w_marks);
            return CT_FALSE;
        } else if (curr_wxid.value != CT_INVALID_ID64) {
            if (!dtc_smon_push_xid_ilock(session, w_marks, stack_ptr, curr_wxid)) {
                free(w_marks);
                return CT_FALSE;
            }
            if (record_sql) {
                CT_LOG_TRACE("session id: %u-%u, wait instance id: %u", xid_get_inst_id(session, ilock->xid),
                             ilock->sid, xid_get_inst_id(session, curr_wxid));
                dtc_smon_record_deadlock_sql(session, DEAD_LOCK_ITL, xid_get_inst_id(session, ilock->xid), ilock->sid);
            }
        } else {
            if (IS_SAME_PAGID(curr_wpid, start_wpid)) {
                continue;
            }

            if (record_sql) {
                CT_LOG_TRACE("session id: %u-%u, wait page_id: %u-%u", xid_get_inst_id(session, ilock->xid), ilock->sid,
                             curr_wpid.file, curr_wpid.page);
                dtc_smon_record_deadlock_sql(session, DEAD_LOCK_ITL, xid_get_inst_id(session, ilock->xid), ilock->sid);
            }

            if (buf_read_page(session, curr_wpid, LATCH_MODE_S, ENTER_PAGE_NORMAL) != CT_SUCCESS) {
                cm_reset_error();
                free(w_marks);
                return CT_FALSE;
            }
            curr_page = (page_head_t *)CURR_PAGE(session);
            if (!dtc_smon_push_itl_sessions_ilock(session, ilock, curr_page, stack_ptr, w_marks)) {
                buf_leave_page(session, CT_FALSE);
                free(w_marks);
                return CT_FALSE;
            }
            buf_leave_page(session, CT_FALSE);
        }
    }
    free(w_marks);

    // re-check deadlock and record SQL text
    if (!record_sql) {
        smon_record_deadlock_time();
        CT_LOG_TRACE("[ITL Deadlock]");
        return dtc_smon_check_itl_waits_in_cluster(session, start_session, CT_TRUE);
    }
    CT_LOG_TRACE("-----------------END OF WAIT INFORMATION-----------------\n");
    return CT_TRUE;
}
