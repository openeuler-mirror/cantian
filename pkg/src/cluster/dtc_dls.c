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
 * dtc_dls.c
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_dls.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_cluster_module.h"
#include "mes_func.h"
#include "dtc_dls.h"
#include "dtc_context.h"
#include "dtc_database.h"
#include "dtc_drc.h"
#include "dtc_tran.h"
#include "dtc_trace.h"
#include "dtc_dcs.h"
#include "dtc_dc.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CT_DLS_SPIN_COUNT   (3)

static status_t dls_request_msg(knl_session_t *session, drid_t *id, uint8 dst_inst, uint32 cmd,
    drc_req_info_t *req_info, uint64 req_version)
{
    msg_lock_req_t lock_req;
    status_t ret = CT_SUCCESS;
    mes_message_t recv_msg = {0};
    uint8 src_inst = session->kernel->dtc_attr.inst_id;
    uint8 mode = req_info->req_mode;
    DTC_DRC_DEBUG_INF(
        "[DRC][%u/%u/%u/%u/%u][request remote lock action]: cmd=%u, from sid:%d, to node %d, to satisfied mode:%d,",
        id->type, id->uid, id->id, id->idx, id->part, cmd, session->id, dst_inst, mode);

    mes_init_send_head(&lock_req.head, cmd, sizeof(msg_lock_req_t), CT_INVALID_ID32, src_inst, dst_inst,
                       session->id, CT_INVALID_ID16);
    lock_req.req_version = req_version;
    lock_req.lock_id = *id;
    lock_req.req_mode = mode;
    lock_req.release_timeout_ticks = req_info->release_timeout_ticks;
    ret = dcs_send_data_retry(&lock_req);
    if (ret != CT_SUCCESS) {
        DTC_DLS_DEBUG_ERR(
            "[DLS] send message to instance(%u) failed, type(%u) resource(%llu/%llu/%u) rsn(%u) errcode(%u)", dst_inst,
            cmd, id->key1, id->key2, id->key3, lock_req.head.rsn, ret);
        return ret;
    }

    ret = mes_recv(session->id, &recv_msg, CT_FALSE, lock_req.head.rsn, DLS_WAIT_TIMEOUT);
    if (ret != CT_SUCCESS || recv_msg.head->cmd == MES_CMD_ERROR_MSG) {
        DTC_DLS_DEBUG_ERR(
            "[DLS] receive message to instance(%u) failed, type(%u) resource(%llu/%llu/%u) rsn(%u) errcode(%u)",
            dst_inst, cmd, id->key1, id->key2, id->key3, lock_req.head.rsn, ret);
        return ret;
    }

    msg_lock_ack_t *lock_ack = (msg_lock_ack_t *)(recv_msg.buffer);
    uint64 req_version_ack = lock_ack->req_version;

    if (DRC_STOP_DLS_REQ_FOR_REFORMING(req_version_ack, session)) {
        DTC_DLS_DEBUG_ERR("[DLS]reforming, request lock owner failed, req_version_ack=%llu, cur_version=%llu",
            req_version_ack, DRC_GET_CURR_REFORM_VERSION);
        mes_release_message_buf(recv_msg.buffer);
        return CT_ERROR;
    }

    ret = lock_ack->lock_status;
    mes_release_message_buf(recv_msg.buffer);

    return ret;
}


static status_t dls_send_msg(knl_session_t *session, drid_t *id, uint32 dst_inst, uint32 cmd)
{
    status_t ret = CT_SUCCESS;
    uint8 *send_msg = NULL;
    mes_message_head_t* head = NULL;
    uint8    src_inst = session->kernel->dtc_attr.inst_id;

    send_msg = (uint8*)cm_push(session->stack, sizeof(mes_message_head_t) + sizeof(drid_t));
    knl_panic(send_msg != NULL);
    head = (mes_message_head_t*)send_msg;

    mes_init_send_head(head, cmd, sizeof(mes_message_head_t) + sizeof(drid_t), CT_INVALID_ID32, src_inst, dst_inst,
                       session->id, CT_INVALID_ID16);
    *((drid_t*)(send_msg + sizeof(mes_message_head_t))) = *id;

    ret = mes_send_data(send_msg);
    if (ret != CT_SUCCESS) {
        cm_pop(session->stack);
        DTC_DLS_DEBUG_ERR(
            "[DLS] single way send message to instance(%u) failed, type(%u) resource(%llu/%llu/%u) rsn(%u) errcode(%u)",
            dst_inst, cmd, id->key1, id->key2, id->key3, head->rsn, ret);
        return ret;
    }
    cm_pop(session->stack);

    return ret;
}

status_t dls_request_lock_msg(knl_session_t *session, drid_t *lock_id, uint8 dst_inst, uint32 cmd,
    drc_req_info_t *req_info, wait_event_t event, uint64 req_version)
{
    status_t ret = CT_SUCCESS;
    knl_begin_session_wait(session, event, CT_TRUE);
    ret = dls_request_msg(session, lock_id, dst_inst, cmd, req_info, req_version);
    knl_end_session_wait(session, event);

    return ret;
}

status_t dls_send_lock_msg(knl_session_t *session, drid_t *lock_id, uint32 dst_inst, uint32 cmd)
{
    return dls_send_msg(session, lock_id, dst_inst, cmd);
}

status_t dls_process_unlock_table(knl_session_t *session, drid_t *lock_id, drc_lock_mode_e mode)
{
    drc_local_latch *latch_stat;
    drc_local_lock_res_t *lock_res;

    DTC_DLS_DEBUG_INF("[DLS] unlock table(%u/%u/%u/%u/%u) for req:%d", lock_id->type, lock_id->uid, lock_id->id,
                      lock_id->idx, lock_id->part, mode);
    knl_dictionary_t dc;
    dc_entity_t *entity;
    dc_entry_t *entry;
    status_t status;
    uint32 timeout = session->kernel->attr.ddl_lock_timeout;

    if (knl_open_dc_by_id(session, lock_id->uid, lock_id->id, &dc, CT_FALSE) != CT_SUCCESS) {
        // for table lock, master lock res not recycle, so master records grand_map is not correct,
        // would let table which is not owner to release lock

        if (drc_get_local_resx_without_create(lock_id) == NULL) {
            CT_LOG_RUN_WAR("[DLS] process unlock table lock(%u/%u/%u/%u/%u) success, local lock res is been recycled",
                lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part);
            return CT_SUCCESS;
        }

        CT_LOG_RUN_ERR("[DLS] process table lock(%u/%u/%u/%u/%u) failed, dc not found", lock_id->type, lock_id->uid,
            lock_id->id, lock_id->idx, lock_id->part);
        return CT_ERROR;
    }
    entity = (dc_entity_t *)(dc.handle);
    entry = entity->entry;

    DTC_DLS_DEBUG_INF("[DLS] process release table lock(%u/%u/%u/%u/%u) table name %s", lock_id->type, lock_id->uid,
                      lock_id->id, lock_id->idx, lock_id->part, entry->name);
    if (mode == DRC_LOCK_EXCLUSIVE) {
        status = lock_table_exclusive_mode(session, entity, entry, timeout, session->kernel->dtc_attr.inst_id);
    } else {
        lock_item_t item;
        status = lock_try_lock_table_shared_local(session, entity, timeout, &item);
    }
    if (status != CT_SUCCESS) {
        dc_close(&dc);
        CT_LOG_RUN_ERR("[DLS] process release table lock(%u/%u/%u/%u/%u) table name %s, but lock local table failed.",
            lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part, entry->name);
        return status;
    }

    lock_res = drc_get_local_resx_without_create(lock_id);
    // for table lock, master lock res not recycle, so master records grand_map is not correct,
    // would let table which is not owner to release lock
    if (lock_res == NULL) {
        unlock_table_local(session, entry, session->kernel->dtc_attr.inst_id);
        dc_close(&dc);
        CT_LOG_RUN_WAR("[DLS] process unlock table lock(%u/%u/%u/%u/%u) success, local lock res is been recycled",
            lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part);
        return CT_SUCCESS;
    }
    drc_lock_local_resx(lock_res);
    drc_get_local_latch_statx(lock_res, &latch_stat);

    knl_panic(latch_stat->lock_mode != DRC_LOCK_NULL);
    if (mode == DRC_LOCK_EXCLUSIVE) {
        latch_stat->lock_mode = DRC_LOCK_NULL;
    } else {
        knl_panic(mode == DRC_LOCK_SHARE);
        knl_panic(latch_stat->lock_mode == DRC_LOCK_EXCLUSIVE);
        latch_stat->lock_mode = DRC_LOCK_SHARE;
    }
    drc_unlock_local_resx(lock_res);
    unlock_table_local(session, entry, session->kernel->dtc_attr.inst_id);
    dc_close(&dc);
    DTC_DLS_DEBUG_INF(
        "[DLS] release successfully table lock(%u/%u/%u/%u/%u) table name %s, local mode:%d, for remote mode:%d",
        lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part, entry->name, latch_stat->lock_mode,
        mode);
    return CT_SUCCESS;
}

status_t dls_broadcast_btree_split(knl_session_t *session, drid_t *lock_id, drc_lock_mode_e mode)
{
    // when split, it must req X model, if req S, it must not split, not to broadcast
    // shadow_index not broadcast
    if (mode == DRC_LOCK_SHARE || lock_id->is_shadow) {
        return CT_SUCCESS;
    }
    if (lock_id->type != DR_TYPE_BTREE_LATCH && lock_id->type != DR_TYPE_BRTEE_PART_LATCH) {
        return CT_SUCCESS;
    }
    knl_dictionary_t dc;
    if (knl_try_open_dc_by_id(session, lock_id->uid, lock_id->id, &dc) != CT_SUCCESS) {
        cm_reset_error();
        DTC_DLS_DEBUG_ERR("[DLS] dc not found, failed to open dc user id %u, table id %u, index id %u", lock_id->uid,
            lock_id->id, lock_id->idx);
        return CT_SUCCESS;
    }

    dc_entity_t *entity = DC_ENTITY(&dc);
    if (entity == NULL) {
        cm_reset_error();
        DTC_DLS_DEBUG_ERR("[DTC] btree entity is null, uid/table_id/index_id/part/parentpart:[%d-%d-%d-%u-%u-%d]",
            lock_id->uid, lock_id->id, lock_id->idx, lock_id->part, lock_id->parentpart, lock_id->is_shadow);
        dc_close(&dc);
        return CT_SUCCESS;
    }
    knl_part_locate_t part_loc;
    part_loc.part_no = (lock_id->parentpart != CT_INVALID_ID32) ? lock_id->parentpart : lock_id->part;
    part_loc.subpart_no = (lock_id->parentpart != CT_INVALID_ID32) ? lock_id->part : lock_id->parentpart;
    btree_t *btree = dc_get_btree_by_id(session, entity, lock_id->idx, part_loc, lock_id->is_shadow);
    if (btree != NULL && btree->is_splitting == CT_TRUE) {
        DTC_DLS_DEBUG_ERR("[DLS] btree is spliting, owner release lock(%u/%u/%u/%u/%u) failed, ", lock_id->type,
            lock_id->uid, lock_id->id, lock_id->idx, lock_id->part);
        dc_close(&dc);
        return CT_ERROR;
    }
    if (btree != NULL && btree->is_splitting == CT_FALSE) {
        if (btree->pre_struct_ver != btree->struct_ver) {
            dtc_broadcast_btree_split(session, btree, part_loc, CT_TRUE);
            btree->pre_struct_ver = btree->struct_ver;
        }
    }
    dc_close(&dc);
    return CT_SUCCESS;
}

status_t dls_process_release_ownership(knl_session_t *session, drid_t *lock_id, drc_lock_mode_e mode,
                                       uint64 req_version, uint32 release_timeout_ticks)
{
    bool8  is_locked = CT_TRUE;
    bool8  is_owner = CT_FALSE;
    drc_local_latch* latch_stat;
    drc_local_lock_res_t* lock_res;
    uint32 times = 0;

    DTC_DLS_DEBUG_INF("[DLS] release lock(%u/%u/%u/%u/%u)", lock_id->type, lock_id->uid, lock_id->id, lock_id->idx,
                      lock_id->part);

    if (DRC_STOP_DLS_REQ_FOR_REFORMING(req_version, session)) {
        CT_LOG_RUN_ERR("[DLS]reforming, owner release lock(%u/%u/%u/%u/%u) failed, req_version=%llu, cur_version=%llu",
            lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part, req_version,
            DRC_GET_CURR_REFORM_VERSION);
        return CT_ERROR;
    }

    if (mode != DRC_LOCK_EXCLUSIVE && mode != DRC_LOCK_SHARE) {
        CT_LOG_RUN_ERR("[DLS] invalid mode %d", mode);
        return CT_ERROR;
    }

    if (lock_id->type == DR_TYPE_TABLE) {
        return dls_process_unlock_table(session, lock_id, mode);
    }

    for (;;) {
        lock_res = drc_get_local_resx_without_create(lock_id);
        if (lock_res == NULL) {
            CT_LOG_RUN_WAR("[DLS] process unlock table lock(%u/%u/%u/%u/%u) success, local lock res is been recycled",
                lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part);
            return CT_SUCCESS;
        }
        drc_lock_local_resx(lock_res);
        drc_get_local_lock_statx(lock_res, &is_locked, &is_owner);
        if (is_locked && (lock_id->type == DR_TYPE_SHUTDOWN)) {
            drc_unlock_local_resx(lock_res);
            CT_LOG_RUN_WAR("[DLS] lock type is DR_TYPE_SHUTDOWN, do not wait for release");
            return CT_ERROR;
        }

        if (release_timeout_ticks != CT_INVALID_ID32 && times >= release_timeout_ticks) {
            drc_unlock_local_resx(lock_res);
            CT_LOG_DEBUG_WAR("[DLS] release latch(%u/%u/%u/%u/%u) timeout", lock_id->type, lock_id->uid, lock_id->id,
                lock_id->idx, lock_id->part);
            return CT_ERROR;
        }

        if (is_locked) {
            drc_unlock_local_resx(lock_res);
            //multi-times lock release ownership when cluster in fault env
            //knl_panic(is_owner);
            cm_spin_sleep();
            times++;
            continue;
        }

        if (DRC_STOP_DLS_REQ_FOR_REFORMING(req_version, session)) {
            CT_LOG_RUN_ERR("[DLS] reforming, owner release lock(%u/%u/%u/%u/%u) failed, req_version=%llu,"
                "cur_version=%llu", lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part, req_version,
                DRC_GET_CURR_REFORM_VERSION);
            drc_unlock_local_resx(lock_res);
            return CT_ERROR;
        }
        drc_get_local_latch_statx(lock_res, &latch_stat);
        drc_get_local_lock_statx(lock_res, &is_locked, &is_owner);
        if ((!is_locked && latch_stat->stat == LATCH_STATUS_IDLE) ||
            (latch_stat->stat == LATCH_STATUS_IX && latch_stat->shared_count == 0)) {
            if (latch_stat->lock_mode == DRC_LOCK_NULL) {
                CT_LOG_RUN_ERR("[DLS] release lock(%u/%u/%u/%u/%u) failed, invalid lock mode",
                    lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part);
                drc_unlock_local_resx(lock_res);
                return CT_ERROR;
            }
            if (dls_broadcast_btree_split(session, lock_id, mode) != CT_SUCCESS) {
                drc_unlock_local_resx(lock_res);
                return CT_ERROR;
            }
            if (mode == DRC_LOCK_EXCLUSIVE) {
                latch_stat->lock_mode = DRC_LOCK_NULL;
                drc_set_local_lock_statx(lock_res, CT_FALSE, CT_FALSE);
            } else {
                knl_panic(mode == DRC_LOCK_SHARE);
                // knl_panic is unreasonable in this scenario, claim failed (only syncpoint trigger)
                // requester req S mode, owner X mode, master will send owner release message,
                // then, owner Lock Degradation to S mode,
                // then, claim failed, requester will retry, master will send owner release message again,
                // but, owner Lock mode has already S mode
                // knl_panic(latch_stat->lock_mode == DRC_LOCK_EXCLUSIVE);
                latch_stat->lock_mode = DRC_LOCK_SHARE;
                drc_set_local_lock_statx(lock_res, CT_FALSE, CT_TRUE);
            }
            drc_unlock_local_resx(lock_res);
            DTC_DLS_DEBUG_INF("[DLS] release spinlock(%u/%u/%u/%u/%u) successfully, curr mode:%d", lock_id->type,
                              lock_id->uid, lock_id->id, lock_id->idx, lock_id->part, latch_stat->lock_mode);
            break;
        }
        drc_unlock_local_resx(lock_res);
        cm_spin_sleep();
    }

    return CT_SUCCESS;
}

status_t dls_process_try_release_ownership(knl_session_t *session, drid_t *lock_id, drc_lock_mode_e mode,
                                           uint64 req_version)
{
    bool8  is_locked = CT_TRUE;
    bool8  is_owner = CT_FALSE;
    uint32 times = 0;
    drc_local_latch *latch_stat;
    drc_local_lock_res_t *lock_res;

    DTC_DLS_DEBUG_INF("[DLS] release spinlock(%u/%u/%u/%u/%u)", lock_id->type, lock_id->uid, lock_id->id, lock_id->idx,
                      lock_id->part);

    if (DRC_STOP_DLS_REQ_FOR_REFORMING(req_version, session)) {
        CT_LOG_RUN_ERR(
            "[DLS]reforming, owner try release lock(%u/%u/%u/%u/%u) failed, req_version=%llu, cur_version=%llu",
            lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part, req_version,
            DRC_GET_CURR_REFORM_VERSION);
        return CT_ERROR;
    }

    if (mode != DRC_LOCK_EXCLUSIVE && mode != DRC_LOCK_SHARE) {
        CT_LOG_RUN_ERR("[DLS] invalid mode %d", mode);
        return CT_ERROR;
    }

    if (lock_id->type == DR_TYPE_TABLE) {
        return dls_process_unlock_table(session, lock_id, mode);
    }

    lock_res = drc_get_local_resx(lock_id);
    while (is_locked && times < 3) {
        drc_get_local_lock_statx(lock_res, &is_locked, &is_owner);
        cm_spin_sleep();
        times++;
    }

    if (times >= 3) {
        CT_LOG_DEBUG_WAR("[DLS] release spinlock(%u/%u/%u/%u/%u) timeout", lock_id->type, lock_id->uid, lock_id->id,
                         lock_id->idx, lock_id->part);
        return ERR_DLS_LOCK_TIMEOUT;
    }

    drc_lock_local_resx(lock_res);
    drc_get_local_latch_statx(lock_res, &latch_stat);
    if (latch_stat->lock_mode == DRC_LOCK_NULL) {
        CT_LOG_RUN_ERR("[DLS] release lock(%u/%u/%u/%u/%u) failed, invalid lock mode",
            lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part);
        drc_unlock_local_resx(lock_res);
        return CT_ERROR;
    }
    if (mode == DRC_LOCK_EXCLUSIVE) {
        latch_stat->lock_mode = DRC_LOCK_NULL;
        drc_set_local_lock_statx(lock_res, CT_FALSE, CT_FALSE);
    } else {
        knl_panic(mode == DRC_LOCK_SHARE);
        knl_panic(latch_stat->lock_mode == DRC_LOCK_EXCLUSIVE);
        latch_stat->lock_mode = DRC_LOCK_SHARE;
        drc_set_local_lock_statx(lock_res, CT_FALSE, CT_TRUE);
    }
    drc_unlock_local_resx(lock_res);
    DTC_DLS_DEBUG_INF("[DLS] release spinlock(%u/%u/%u/%u/%u) successfully", lock_id->type, lock_id->uid, lock_id->id,
                      lock_id->idx, lock_id->part);

    return CT_SUCCESS;
}

status_t dls_process_ask_master_for_lock(knl_session_t * session, mes_message_t * receive_msg)
{
    status_t ret = CT_SUCCESS;
    uint8 owner_id = CT_INVALID_ID8;
    bool32 is_granted = CT_FALSE;
    uint8    self_id = g_dtc->kernel->dtc_attr.inst_id;
    msg_lock_req_t lock_req = *(msg_lock_req_t *)(receive_msg->buffer);
    drid_t  *lock_id = &lock_req.lock_id;
    uint64 req_version = lock_req.req_version;
    uint64 old_owner_map = 0;
    if (lock_req.req_mode != DRC_LOCK_EXCLUSIVE || lock_req.head.src_inst >= CT_MAX_INSTANCES) {
        CT_LOG_RUN_ERR("invalid reqmode %d or invalid src_inst %u", lock_req.req_mode, lock_req.head.src_inst);
        return CT_ERROR;
    }
    // knl_panic(lock_req.req_mode == DRC_LOCK_EXCLUSIVE);
    drc_req_info_t req_info;
    req_info.inst_id = lock_req.head.src_inst;
    req_info.inst_sid = lock_req.head.src_sid;
    req_info.req_mode = lock_req.req_mode;
    req_info.curr_mode = DRC_LOCK_MODE_MAX;
    req_info.rsn = lock_req.head.rsn;
    req_info.req_time = lock_req.head.req_start_time;
    req_info.req_version = req_version;
    req_info.lsn = CT_INVALID_ID64;
    req_info.release_timeout_ticks = lock_req.release_timeout_ticks;

    ret = drc_request_lock_owner(session, lock_id, &req_info, &is_granted, &old_owner_map, req_version);
    if (ret != CT_SUCCESS) {
        DTC_DRC_DEBUG_ERR("[DLS] process drc request lock(%u/%u/%u/%u/%u) owner failed",
            lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part);
        return ret;
    }

    // if granted, we get the lock directly
    if (is_granted) {
        return ret;
    } else {
        if (drc_bitmap64_exist(&old_owner_map, req_info.inst_id)) {
            //when guest not recieve ack, but master already claimed.
            //multi-times lock request send ack failed when cluster in fault env
            DTC_DLS_DEBUG_INF(
                "[DLS] process drc request lock(%u/%u/%u/%u/%u) owner already exist, old_owner_map(%llu), self_id(%u)",
                lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part, old_owner_map, req_info.inst_id);
            return CT_SUCCESS;
        }

        //spinlock only have one owner
        for (int32 i = 0; i < g_mes.profile.inst_count; i++) {
            if (drc_bitmap64_exist(&old_owner_map, i)) {
                owner_id = i;
                break;
            }
        }

        if (self_id == owner_id) {
            //master is the owner
            ret = dls_process_release_ownership(session, lock_id, lock_req.req_mode, req_version,
                lock_req.release_timeout_ticks);
        } else {
            //somebody is the owner
            ret = dls_request_lock_msg(session, lock_id, owner_id, MES_CMD_RELEASE_LOCK, &req_info,
                DLS_REQ_LOCK, req_version);
        }
        if (ret != CT_SUCCESS) {
            //not claimed
            if (DRC_STOP_DLS_REQ_FOR_REFORMING(req_version, session)) {
                CT_LOG_RUN_ERR("[DLS]reforming, process dls request master ask owner(%u) for"
                    "lock(%u/%u/%u/%u/%u) failed, req_version=%llu, cur_version=%llu",
                    owner_id, lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part, req_version,
                    DRC_GET_CURR_REFORM_VERSION);
                return ret;
            }
            drc_cancel_lock_owner_request(req_info.inst_id, lock_id);
            CT_LOG_RUN_ERR("[DLS] process dls request master ask owner(%u) to release lock(%u/%u/%u/%u/%u) failed",
                owner_id, lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part);
            return ret;
        }
    }

    return ret;
}

status_t dls_process_ask_master_for_latch(knl_session_t * session, mes_message_t * receive_msg)
{
    status_t ret = CT_SUCCESS;
    bool32 is_granted = CT_FALSE;
    uint8    self_id = g_dtc->kernel->dtc_attr.inst_id;
    msg_lock_req_t lock_req = *(msg_lock_req_t *)(receive_msg->buffer);
    drid_t  *lock_id = &lock_req.lock_id;
    uint64 req_version = lock_req.req_version;
    uint64 old_owner_map = 0;
    drc_lock_mode_e mode = (receive_msg->head->cmd == MES_CMD_REQUEST_LATCH_S) ? DRC_LOCK_SHARE : DRC_LOCK_EXCLUSIVE;
    if (lock_req.req_mode != mode || lock_req.head.src_inst >= CT_MAX_INSTANCES) {
        CT_LOG_RUN_ERR("req_mode dismatch or invalid src_inst %u, req_mode %d, proc mode %d", lock_req.head.src_inst,
            lock_req.req_mode, mode);
        return CT_ERROR;
    }
    // knl_panic(lock_req.req_mode == mode);
    drc_req_info_t req_info;
    req_info.inst_id = lock_req.head.src_inst;
    req_info.inst_sid = lock_req.head.src_sid;
    req_info.req_mode = lock_req.req_mode;
    req_info.curr_mode = DRC_LOCK_MODE_MAX;
    req_info.rsn = lock_req.head.rsn;
    req_info.req_time = lock_req.head.req_start_time;
    req_info.req_version = req_version;
    req_info.lsn = CT_INVALID_ID64;
    req_info.release_timeout_ticks = lock_req.release_timeout_ticks;

    ret = drc_request_lock_owner(session, lock_id, &req_info, &is_granted, &old_owner_map, req_version);
    if (ret != CT_SUCCESS) {
        DTC_DRC_DEBUG_ERR("[DLS] process drc request latch(%u/%u/%u/%u/%u) owner failed",
            lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part);
        return ret;
    }

    // if granted, we get the lock directly
    if (is_granted) {
        return ret;
    }
    //spinlock only have one owner
    for (uint8 i = 0; i < g_mes.profile.inst_count; i++) {
        if (drc_bitmap64_exist(&old_owner_map, i)) {
            if (req_info.inst_id == i) {
                continue; // if latch s->x or x->s, we have get owner yet
            }
            //master is the owner
            if (self_id == i) {
                ret = dls_process_release_ownership(session, lock_id, req_info.req_mode, req_version,
                    lock_req.release_timeout_ticks);
            } else {
                //somebody is the owner,
                //todo: batch operate need for performmance
                ret = dls_request_lock_msg(session, lock_id, i, MES_CMD_RELEASE_LOCK, &req_info,
                    DLS_REQ_LOCK, req_version);
            }
            if (ret != CT_SUCCESS) {
                //not claimed
                if (DRC_STOP_DLS_REQ_FOR_REFORMING(req_version, session)) {
                    CT_LOG_RUN_ERR("[DLS]reforming, process dls request master ask owner(%u) for"
                        "latch(%u/%u/%u/%u/%u) failed, req_version=%llu, cur_version=%llu",
                        i, lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part, req_version,
                        DRC_GET_CURR_REFORM_VERSION);
                    return CT_ERROR;
                }
                drc_cancel_lock_owner_request(req_info.inst_id, lock_id);
                CT_LOG_RUN_ERR("[DLS] process dls request master ask owner(%u) to release latch(%u/%u/%u/%u/%u) failed",
                    i, lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part);
                return ret;
            }
            if (req_info.req_mode == DRC_LOCK_EXCLUSIVE) {
                // in case x->s, no need to clear granted map
                dls_clear_granted_map_for_inst(lock_id, i);
            }
        }
    }

    return ret;
}

status_t dls_process_try_ask_master_for_lock(knl_session_t * session, mes_message_t * receive_msg)
{
    status_t ret = CT_SUCCESS;
    uint8 owner_id = CT_INVALID_ID8;
    bool32 is_granted = CT_FALSE;
    uint8    self_id = g_dtc->kernel->dtc_attr.inst_id;
    msg_lock_req_t lock_req = *(msg_lock_req_t *)(receive_msg->buffer);
    drid_t  *lock_id = &lock_req.lock_id;
    uint64 req_version = lock_req.req_version;
    uint64 old_owner_map = 0;
    if (lock_req.req_mode != DRC_LOCK_EXCLUSIVE || lock_req.head.src_inst >= CT_MAX_INSTANCES) {
        CT_LOG_RUN_ERR("invalid reqmode %d or invalid src_inst %u", lock_req.req_mode, lock_req.head.src_inst);
        return CT_ERROR;
    }
    // knl_panic(lock_req.req_mode == DRC_LOCK_EXCLUSIVE);
    drc_req_info_t req_info;
    req_info.inst_id = lock_req.head.src_inst;
    req_info.inst_sid = lock_req.head.src_sid;
    req_info.req_mode = lock_req.req_mode;
    req_info.curr_mode = DRC_LOCK_MODE_MAX;
    req_info.rsn = lock_req.head.rsn;
    req_info.req_time = lock_req.head.req_start_time;
    req_info.req_version = req_version;
    req_info.lsn = CT_INVALID_ID64;
    req_info.release_timeout_ticks = lock_req.release_timeout_ticks;
    DTC_DLS_DEBUG_INF("[DLS] process drc try request lock (%u/%u/%u/%u/%u)",
        lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part);
    ret = drc_try_request_lock_owner(session, lock_id, &req_info, &is_granted, &old_owner_map, req_version);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR_LIMIT(LOG_PRINT_INTERVAL_SECOND_20,
            "[DLS] process drc try request lock(%u/%u/%u/%u/%u) owner failed",
            lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part);
        return ret;
    }

    // if granted, we get the lock directly
    if (is_granted) {
        DTC_DLS_DEBUG_INF("[DLS] process drc try request lock (%u/%u/%u/%u/%u) successfully",
            lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part);
        return ret;
    } else {
        // here can check source instance not the owner
        if (drc_bitmap64_exist(&old_owner_map, req_info.inst_id)) {
            // multi-times lock request send ack failed when cluster in fault env
            DTC_DLS_DEBUG_INF(
                "[DLS] process drc try request lock (%u/%u/%u/%u/%u) owner already exist, old_owner_map(%llu), self_id(%u)",
                lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part, old_owner_map, req_info.inst_id);
            return CT_SUCCESS;
        }

        //spinlock only have one owner
        for (int32 i = 0; i < g_mes.profile.inst_count; i++) {
            if (drc_bitmap64_exist(&old_owner_map, i)) {
                owner_id = i;
                break;
            }
        }

        //master is the owner
        if (self_id == owner_id) {
            ret = dls_process_try_release_ownership(session, lock_id, req_info.req_mode, req_version);
        } else {
            // somebody is the owner
            ret = dls_request_lock_msg(session, lock_id, owner_id, MES_CMD_TRY_RELEASE_LOCK, &req_info,
                                       DLS_REQ_LOCK, req_version);
        }
        if (ret != CT_SUCCESS) {
            if (DRC_STOP_DLS_REQ_FOR_REFORMING(req_version, session)) {
                CT_LOG_RUN_ERR("[DLS]reforming, process dls request master ask owner(%u) for"
                    "lock(%u/%u/%u/%u/%u) failed, req_version=%llu, cur_version=%llu",
                    owner_id, lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part, req_version,
                    DRC_GET_CURR_REFORM_VERSION);
                return ret;
            }
            drc_cancel_lock_owner_request(req_info.inst_id, lock_id);
            CT_LOG_DEBUG_WAR("[DLS] process dls master try ask owner(%u) to release lock(%u/%u/%u/%u/%u) failed",
                             owner_id, lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part);
            return ret;
        }
    }
    DTC_DLS_DEBUG_INF("[DLS] process drc try request lock (%u/%u/%u/%u/%u) successfully",
        lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part);

    return ret;
}


static status_t dls_process_claim_ownership(knl_session_t *session, mes_message_t * receive_msg)
{
    msg_lock_req_t lock_req = *(msg_lock_req_t *)(receive_msg->buffer);
    drid_t  *lock_id = &lock_req.lock_id;

    lock_claim_info_t claim_info;
    claim_info.new_id = lock_req.head.src_inst;
    claim_info.inst_sid = lock_req.head.src_sid;
    claim_info.mode = lock_req.req_mode;

    return drc_claim_lock_owner(session, lock_id, &claim_info, lock_req.req_version, CT_FALSE);
}

status_t dls_process_clean_granted_map(knl_session_t * session, mes_message_t * receive_msg)
{
    msg_lock_req_t lock_req = *(msg_lock_req_t *)(receive_msg->buffer);
    drid_t  *lock_id = &lock_req.lock_id;
    uint8 inst_id = lock_req.head.src_inst;
    uint64 req_version = lock_req.req_version;
    if (DRC_STOP_DLS_REQ_FOR_REFORMING(req_version, session)) {
        CT_LOG_DEBUG_ERR("[DLS]reforming, clean granted map failed, req_version=%llu, cur_version=%llu",
            req_version, DRC_GET_CURR_REFORM_VERSION);
        return CT_ERROR;
    }
    if (inst_id >= CT_MAX_INSTANCES) {
        CT_LOG_DEBUG_ERR("[DLS]invalid src_inst %u", inst_id);
        return CT_ERROR;
    }
    return dls_clean_granted_map(session, lock_id, inst_id);
}

// static status_t dls_process_cancle_ownership(knl_session_t *session, mes_message_t * receive_msg)
// {
//     msg_lock_req_t lock_req = *(msg_lock_req_t *)(receive_msg->buffer);
//     uint8    dest_id = receive_msg->head->src_inst;
//     drid_t  *lock_id = &lock_req.lock_id;

//     return drc_cancel_lock_owner_request(dest_id, lock_id);
// }

void dls_process_lock_msg(void *sess, mes_message_t * receive_msg)
{
    status_t ret = CT_SUCCESS;
    if (sizeof(msg_lock_req_t) != receive_msg->head->size) {
        CT_LOG_RUN_ERR("process lock msg size is invalid, msg size %u.", receive_msg->head->size);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    msg_lock_req_t lock_req = *(msg_lock_req_t *)(receive_msg->buffer);
    drid_t  *lock_id = &lock_req.lock_id;
    uint64 req_version = lock_req.req_version;
    bool32 claim = CT_FALSE;
    uint8   cmd = MES_CMD_LOCK_ACK;
    knl_session_t *session = (knl_session_t *)sess;

    DTC_DLS_DEBUG_INF("[DLS] process message type(%u),resource id(%u/%u/%u/%u/%u), from %d, sid:%d, req mode:%d ",
                      receive_msg->head->cmd, lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part,
                      lock_req.head.src_inst, lock_req.head.src_sid, lock_req.req_mode);

    switch (receive_msg->head->cmd) {
        case MES_CMD_REQUEST_LOCK:
            //master receive message, so need to grant the lock to caller
            ret = dls_process_ask_master_for_lock(session, receive_msg);
            claim = CT_TRUE;
            break;
        case MES_CMD_REQUEST_LATCH_S:
            // go through
        case MES_CMD_REQUEST_LATCH_X:
            ret = dls_process_ask_master_for_latch(session, receive_msg);
            claim = CT_TRUE;
            break;
        case MES_CMD_TRY_REQUEST_LOCK:
            //master receive message, so need to grant the lock to caller
            ret = dls_process_try_ask_master_for_lock(session, receive_msg);
            claim = CT_TRUE;
            break;
        case MES_CMD_RELEASE_LOCK:
            //owner receive message, others want the spinlock ownership, so i should release the ownership
            ret = dls_process_release_ownership(session, lock_id, lock_req.req_mode, req_version,
                lock_req.release_timeout_ticks);
            break;
        case MES_CMD_TRY_RELEASE_LOCK:
            ret = dls_process_try_release_ownership(session, lock_id, lock_req.req_mode, req_version);
            break;
        case MES_CMD_CLEAN_GRANTED_MAP:
            ret = dls_process_clean_granted_map(session, receive_msg);
            break;
        // case MES_CMD_CLAIM_LOCK:
        //     //no claim message now
        //     ret =  dls_process_claim_ownership(session, receive_msg);
        //     break;
        // case MES_CMD_CANCLE_LOCK:
        //     //no cancle message now
        //     ret = dls_process_cancle_ownership(session, receive_msg);
        //     mes_release_message_buf(receive_msg->buffer);
        //     return;
        default:
            //temp errorcode
            CT_LOG_RUN_ERR("invalidate lock command(%d)", receive_msg->head->cmd);
            ret = ERR_DLS_INVALID_CMD;
    }

    if (claim && ret == CT_SUCCESS) {
        ret = dls_process_claim_ownership(session, receive_msg);
        if (ret != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[DLS] process drc claim lock(%u/%u/%u/%u/%u) owner failed, ins_id(%u)",
                lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part, receive_msg->head->src_inst);
        }
    }

    msg_lock_ack_t lock_ack;

    mes_init_ack_head(&lock_req.head, &lock_ack.head, cmd, sizeof(msg_lock_ack_t), CT_INVALID_ID16);
    lock_ack.lock_status = ret;
    lock_ack.req_version = req_version;
    mes_release_message_buf(receive_msg->buffer);

    ret = dcs_send_data_retry(&lock_ack);
    if (ret != CT_SUCCESS) {
        //log or abort
        //knl_panic(0);
        DTC_DLS_DEBUG_ERR("[DLS] process ack message send back failed, msg type(%u),resource id(%u/%u/%u/%u/%u), errorcode(%u)",
            cmd, lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part, ret);
    }

    return;
}

status_t dls_request_lock(knl_session_t *session, drid_t *lock_id, drc_req_info_t *req_info, uint32 cmd)
{
    status_t ret = CT_SUCCESS;
    uint8    master_id = CT_INVALID_ID8;
    uint8    self_id = session->kernel->dtc_attr.inst_id;
    bool32 is_granted = CT_FALSE;
    uint64 old_owner_map = 0;

    drc_get_lock_master_id(lock_id, &master_id);
    uint64 req_version = req_info->req_version;
    DTC_DRC_DEBUG_INF("[DRC][%u/%u/%u/%u/%u][start request lock res]: req mode=%u, from %d, sid:%d", lock_id->type,
                      lock_id->uid, lock_id->id, lock_id->idx, lock_id->part, req_info->req_mode, req_info->inst_id,
                      req_info->inst_sid);
    if (master_id == self_id) {
        SYNC_POINT_GLOBAL_START(CANTIAN_DLS_REQUEST_LOCK_OWNER_FAIL, &ret, CT_ERROR);
        ret = drc_request_lock_owner(session, lock_id, req_info, &is_granted, &old_owner_map, req_version);
        SYNC_POINT_GLOBAL_END;
        if (ret != CT_SUCCESS) {
            DTC_DRC_DEBUG_ERR("[DLS] drc request lock(%u/%u/%u/%u/%u) owner failed",
                lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part);
            return ret;
        }
        SYNC_POINT_GLOBAL_START(CANTIAN_DLS_REQUEST_LOCK_OWNER_SUCC_ABORT, NULL, 0);
        SYNC_POINT_GLOBAL_END;

        // if granted, we get the lock directly; if not, send a request to the lock owner
        if (!is_granted) {
            //spinlock only have one owner
            for (int32 i = 0; i < g_mes.profile.inst_count; i++) {
                if (drc_bitmap64_exist(&old_owner_map, i)) {
                    if (self_id == i) {
                        continue; //latch condition, if latch s->i->x or x->i->s, we have get owner yet
                    }
                    SYNC_POINT_GLOBAL_START(CANTIAN_DLS_REQUEST_LOCK_MSG_SEND_FAIL, &ret, CT_ERROR);
                    ret = dls_request_lock_msg(session, lock_id, i, MES_CMD_RELEASE_LOCK, req_info,
                                               DLS_REQ_LOCK, req_version);
                    SYNC_POINT_GLOBAL_END;
                    if (ret != CT_SUCCESS) {
                        // todo: tell master lock failed and go next, not claim
                        drc_cancel_lock_owner_request(self_id, lock_id);
                        DTC_DRC_DEBUG_ERR(
                            "[DLS] dls request master ask owner(%u) to release lock(%u/%u/%u/%u/%u) failed", i,
                            lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part);
                        return ret;
                    }
                    if (req_info->req_mode == DRC_LOCK_EXCLUSIVE) {
                        // in case x->s, no need to clear granted map
                        dls_clear_granted_map_for_inst(lock_id, i);
                    }
                    SYNC_POINT_GLOBAL_START(CANTIAN_DLS_REQUEST_LOCK_MSG_SEND_SUCC_ABORT, NULL, 0);
                    SYNC_POINT_GLOBAL_END;
                }
            }
        }

        SYNC_POINT_GLOBAL_START(CANTIAN_DLS_CLAIM_LOCK_OWNER_BEFORE_ABORT, NULL, 0);
        SYNC_POINT_GLOBAL_END;

        lock_claim_info_t claim_info;
        claim_info.new_id = req_info->inst_id;
        claim_info.inst_sid = req_info->inst_sid;
        claim_info.mode = req_info->req_mode;

        SYNC_POINT_GLOBAL_START(CANTIAN_DLS_CLAIM_LOCK_OWNER_BEFORE_ABORT, NULL, 0);
        SYNC_POINT_GLOBAL_END;

        SYNC_POINT_GLOBAL_START(CANTIAN_DLS_CLAIM_LOCK_OWNER_FAIL, &ret, CT_ERROR);
        ret = drc_claim_lock_owner(session, lock_id, &claim_info, req_version, CT_FALSE);
        SYNC_POINT_GLOBAL_END;
        if (ret != CT_SUCCESS) {
            drc_cancel_lock_owner_request(self_id, lock_id);
            CT_LOG_RUN_ERR("[DLS] drc claim lock(%u/%u/%u/%u/%u) owner failed, ins_id(%u)",
                lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part, self_id);
        }
        SYNC_POINT_GLOBAL_START(CANTIAN_DLS_CLAIM_LOCK_OWNER_SUCC_ABORT, NULL, 0);
        SYNC_POINT_GLOBAL_END;
    } else {
        SYNC_POINT_GLOBAL_START(CANTIAN_DLS_REQUEST_LOCK_MSG_SEND_FAIL, &ret, CT_ERROR);
        ret = dls_request_lock_msg(session, lock_id, master_id, cmd, req_info, DLS_REQ_LOCK, req_version);
        SYNC_POINT_GLOBAL_END;
        if (ret != CT_SUCCESS) {
            CT_LOG_DEBUG_ERR("[DLS] dls request lock(%u/%u/%u/%u/%u) owner from master(%u) failed", lock_id->type,
                lock_id->uid, lock_id->id, lock_id->idx, lock_id->part, master_id);
            return ret;
        }
        SYNC_POINT_GLOBAL_START(CANTIAN_DLS_REQUEST_LOCK_MSG_SEND_SUCC_ABORT, NULL, 0);
        SYNC_POINT_GLOBAL_END;
    }

    DTC_DRC_DEBUG_INF("[DRC][%u/%u/%u/%u/%u][finish lock res]: req mode=%u, from %d, sid:%d", lock_id->type,
                      lock_id->uid, lock_id->id, lock_id->idx, lock_id->part, req_info->req_mode, req_info->inst_id,
                      req_info->inst_sid);
    return ret;
}

static void dls_request_spin_lock(knl_session_t *session, drid_t *lock_id)
{
    status_t ret = CT_SUCCESS;
    uint32 spin_times = 0;
    drc_req_info_t req_info;

    do {
        req_info.inst_id = session->kernel->id;
        req_info.inst_sid = session->id;
        req_info.req_mode = DRC_LOCK_EXCLUSIVE;
        req_info.curr_mode = DRC_LOCK_MODE_MAX;
        req_info.rsn = mes_get_rsn(session->id);
        req_info.req_time = KNL_NOW(session);
        req_info.req_version = DRC_GET_CURR_REFORM_VERSION;
        req_info.lsn = CT_INVALID_ID64;
        req_info.release_timeout_ticks = CT_INVALID_ID32;
        ret = dls_request_lock(session, lock_id, &req_info, MES_CMD_REQUEST_LOCK);
        if (ret == CT_SUCCESS) {
            break;
        }
#ifndef WIN32
        fas_cpu_pause();
#endif  // !WIN32
        spin_times++;
        if (SECUREC_UNLIKELY(spin_times == CT_DLS_SPIN_COUNT)) {
            cm_spin_sleep();
            spin_times = 0;
        }
    } while (CT_TRUE);

    return;
}

void dls_spin_lock(knl_session_t *session, drlock_t * dlock, spin_statis_t *stat)
{
    database_t *db = &session->kernel->db;
    bool8  is_locked = CT_FALSE;
    bool8  is_owner = CT_FALSE;
    drc_local_lock_res_t *lock_res;
    drc_local_latch *latch_stat = NULL;

    /* CODE_REVIEW muting 00198166 2019-8-17: is this status really fine ?? */
    if (session->kernel->attr.clustered && !DAAC_REPLAY_NODE(session) && db->status >= DB_STATUS_MOUNT) {
        knl_panic(dlock->drid.type != DR_TYPE_INVALID);
        lock_res = drc_get_local_resx(&dlock->drid);
        drc_lock_local_resx(lock_res);
        drc_get_local_latch_statx(lock_res, &latch_stat);
        drc_get_local_lock_statx(lock_res, &is_locked, &is_owner);

        DTC_DLS_DEBUG_INF("[DLS] add spinlock(%u/%u/%u/%u/%u), owner(%u)",
            dlock->drid.type, dlock->drid.uid, dlock->drid.id, dlock->drid.idx, dlock->drid.part, is_owner);
        //i am not owner or latch mode change
        if (!is_owner) {
            dls_request_spin_lock(session, &dlock->drid);
        }
        latch_stat->lock_mode = DRC_LOCK_EXCLUSIVE;
        drc_set_local_lock_statx(lock_res, CT_TRUE, CT_TRUE);
    } else {
        cm_spin_lock(&dlock->lock, stat);
    }

    return;
}

status_t dls_try_request_lock(knl_session_t *session, drid_t *lock_id, wait_event_t event)
{
    status_t ret = CT_SUCCESS;
    uint8    master_id = CT_INVALID_ID8;
    uint8    self_id = session->kernel->dtc_attr.inst_id;
    bool32 is_granted = CT_FALSE;
    uint64 old_owner_map = 0;
    uint64 req_version = DRC_GET_CURR_REFORM_VERSION;
    drc_get_lock_master_id(lock_id, &master_id);

    drc_req_info_t req_info;
    req_info.inst_id = self_id;
    req_info.inst_sid = session->id;
    req_info.req_mode = DRC_LOCK_EXCLUSIVE;
    req_info.curr_mode = DRC_LOCK_MODE_MAX;
    req_info.rsn = mes_get_rsn(session->id);
    req_info.req_time = KNL_NOW(session);
    req_info.req_version = DRC_GET_CURR_REFORM_VERSION;
    req_info.lsn = CT_INVALID_ID64;
    req_info.release_timeout_ticks = CT_INVALID_ID32;

    if (master_id == self_id) {
        ret = drc_try_request_lock_owner(session, lock_id, &req_info, &is_granted, &old_owner_map, req_version);
        if (ret != CT_SUCCESS) {
            DTC_DLS_DEBUG_ERR("[DLS] drc try request lock(%u/%u/%u/%u/%u) owner failed",
                lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part);
            return ret;
        }

        // if granted, we get the lock directly; if not, send a request to the lock owner
        if (!is_granted) {
             //here can check self instance not the owner
            if (drc_bitmap64_exist(&old_owner_map, self_id)) {
                //knl_panic(0);
                drc_cancel_lock_owner_request(self_id, lock_id);
                DTC_DLS_DEBUG_ERR("[DLS] drc try request lock(%u/%u/%u/%u/%u) owner error, old_owner_map(%llu), self_id(%u)",
                    lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part, old_owner_map, self_id);
                return CT_ERROR;
            }
            //spinlock only have one owner
            for (int32 i = 0; i < g_mes.profile.inst_count; i++) {
                if (drc_bitmap64_exist(&old_owner_map, i)) {
                    ret = dls_request_lock_msg(session, lock_id, i, MES_CMD_TRY_RELEASE_LOCK, &req_info, event,
                                               req_version);
                    if (ret != CT_SUCCESS) {
                        //lock failed
                        //CT_THROW_ERROR(ret, lock_id->type, lock_id->id);
                        DTC_DLS_DEBUG_ERR("[DLS] dls request master ask owner(%u) to release lock(%u/%u/%u/%u/%u) failed, errcode(%u)",
                            i, lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part, ret);
                        // todo: tell master lock failed and go next
                        drc_cancel_lock_owner_request(self_id, lock_id);
                        return ret;
                    }
                }
            }
        }

        lock_claim_info_t claim_info;
        claim_info.new_id = self_id;
        claim_info.inst_sid = session->id;
        claim_info.mode = req_info.req_mode;

        ret = drc_claim_lock_owner(session, lock_id, &claim_info, req_version, CT_FALSE);
        if (ret != CT_SUCCESS) {
            drc_cancel_lock_owner_request(self_id, lock_id);
            DTC_DLS_DEBUG_ERR("[DLS] drc claim lock(%u/%u/%u/%u/%u) owner failed, ins_id(%u)",
                lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part, self_id);
        }
    } else {
        ret = dls_request_lock_msg(session, lock_id, master_id, MES_CMD_TRY_REQUEST_LOCK, &req_info, event,
                                   req_version);
        if (ret != CT_SUCCESS) {
            //lock failed
            //CT_THROW_ERROR(ret, lock_id->type, lock_id->id);
            DTC_DLS_DEBUG_ERR("[DLS] dls request lock(%u/%u/%u/%u/%u) owner from master(%u) failed, errcode(%u)",
                lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part, master_id, ret);
            //todo: if the cancle message failed, master will always do converting, maybe master should suppory re-enter
            //(void)dls_send_lock_msg(session, lock_id, master_id, MES_CMD_CANCLE_LOCK);
        }
    }

    return ret;
}

bool32 dls_do_spin_try_lock(knl_session_t *session, drlock_t * dlock, wait_event_t event)
{
    status_t ret = CT_SUCCESS;
    database_t *db = &session->kernel->db;
    bool8  is_locked = CT_FALSE;
    bool8 is_owner = CT_FALSE;
    drc_local_lock_res_t *lock_res;
    drc_local_latch *latch_stat = NULL;

    if (session->kernel->attr.clustered && !DAAC_REPLAY_NODE(session) && db->status >= DB_STATUS_MOUNT) {
        knl_panic(dlock->drid.type != DR_TYPE_INVALID);
        lock_res = drc_get_local_resx(&dlock->drid);
        drc_get_local_lock_statx(lock_res, &is_locked, &is_owner);
        drc_get_local_latch_statx(lock_res, &latch_stat);
        if (is_locked) {
            DTC_DLS_DEBUG_INF("[DLS] try add spinlock(%u/%u/%u/%u/%u), owner(%u) is locked",
                dlock->drid.type, dlock->drid.uid, dlock->drid.id, dlock->drid.idx, dlock->drid.part, is_owner);
            return CT_FALSE;
        }

        if (drc_try_lock_local_resx(lock_res)) {
            drc_get_local_lock_statx(lock_res, &is_locked, &is_owner);
            knl_panic(!is_locked);
            DTC_DLS_DEBUG_INF("[DLS] try add spinlock(%u/%u/%u/%u/%u), owner(%u)",
                dlock->drid.type, dlock->drid.uid, dlock->drid.id, dlock->drid.idx, dlock->drid.part, is_owner);
            if (!is_owner) {
                ret = dls_try_request_lock(session, &dlock->drid, event);
                if (ret != CT_SUCCESS) {
                    latch_stat->lock_mode = DRC_LOCK_NULL;
                    drc_set_local_lock_statx(lock_res, CT_FALSE, CT_FALSE);
                    drc_unlock_local_resx(lock_res);
                    DTC_DLS_DEBUG_INF("[DLS] try add spinlock(%u/%u/%u/%u/%u) failed, ret(%u)",
                        dlock->drid.type, dlock->drid.uid, dlock->drid.id, dlock->drid.idx, dlock->drid.part, ret);
                    return CT_FALSE;
                }
            }
            latch_stat->lock_mode = DRC_LOCK_EXCLUSIVE;
            drc_set_local_lock_statx(lock_res, CT_TRUE, CT_TRUE);
            return CT_TRUE;
        } else {
            DTC_DLS_DEBUG_INF("[DLS] try add spinlock(%u/%u/%u/%u/%u), local resource is locked",
                dlock->drid.type, dlock->drid.uid, dlock->drid.id, dlock->drid.idx, dlock->drid.part);
            return CT_FALSE;
        }
    } else {
        return cm_spin_try_lock(&dlock->lock);
    }
}

bool32 dls_spin_try_lock(knl_session_t *session, drlock_t * dlock)
{
    return dls_do_spin_try_lock(session, dlock, DLS_REQ_LOCK);
}

static void dls_request_spin_unlock(knl_session_t *session, drc_local_lock_res_t *lock_res)
{
#ifdef DB_DEBUG_VERSION
    bool8  is_locked = CT_FALSE;
    bool8  is_owner = CT_FALSE;
    drc_local_latch *latch_stat = NULL;
    //check dls spinlock valid in debug

    drc_get_local_latch_statx(lock_res, &latch_stat);
    drc_get_local_lock_statx(lock_res, &is_locked, &is_owner);
    knl_panic(is_owner);
    knl_panic(latch_stat->lock_mode == DRC_LOCK_EXCLUSIVE);
#endif
    drc_set_local_lock_statx(lock_res, CT_FALSE, CT_TRUE);
    return;
}


bool32 dls_spin_timed_lock(knl_session_t *session, drlock_t * dlock, uint32 timeout_ticks, wait_event_t event)
{
    database_t *db = &session->kernel->db;
    uint32 spin_times = 0;
    uint32 wait_ticks = 0;

    if (session->kernel->attr.clustered && !DAAC_REPLAY_NODE(session)  && db->status >= DB_STATUS_MOUNT) {
        knl_panic(dlock->drid.type != DR_TYPE_INVALID);
        DTC_DLS_DEBUG_INF("[DLS] add timed spinlock(%u/%u/%u/%u/%u)",
            dlock->drid.type, dlock->drid.uid, dlock->drid.id, dlock->drid.idx, dlock->drid.part);
        for (;;) {
            if (dls_do_spin_try_lock(session, dlock, event)) {
                return CT_TRUE;
            }
            if (SECUREC_UNLIKELY(wait_ticks >= timeout_ticks)) {
                DTC_DLS_DEBUG_INF("[DLS] add timed spinlock(%u/%u/%u/%u/%u) timeout",
                    dlock->drid.type, dlock->drid.uid, dlock->drid.id, dlock->drid.idx, dlock->drid.part);
                return CT_FALSE;
            }
#ifndef WIN32
            fas_cpu_pause();
#endif  // !WIN32

            spin_times++;
            if (SECUREC_UNLIKELY(spin_times == CT_SPIN_COUNT)) {
                cm_spin_sleep();
                spin_times = 0;
                wait_ticks++;
            }
        }
    } else {
        return cm_spin_timed_lock(&dlock->lock, timeout_ticks);
    }
}

bool32 dls_spin_lock_by_self(knl_session_t *session, drlock_t * dlock)
{
    bool8  is_locked = CT_FALSE;
    bool8  is_owner = CT_FALSE;
    drc_local_lock_res_t *lock_res;

    knl_panic(session->kernel->attr.clustered);

    lock_res = drc_get_local_resx(&dlock->drid);
    drc_lock_local_res_count(lock_res);
    DTC_DLS_DEBUG_INF("[DLS] begin dls spin lock by self (%u/%u/%u/%u/%u), lock count %d", dlock->drid.type,
                      dlock->drid.uid, dlock->drid.id, dlock->drid.idx, dlock->drid.part, lock_res->count);
    drc_get_local_lock_statx(lock_res, &is_locked, &is_owner);
    if (is_locked && is_owner) {
        lock_res->count++;
    }
    DTC_DLS_DEBUG_INF("[DLS] end dls spin lock by self (%u/%u/%u/%u/%u), lock count %d", dlock->drid.type,
                      dlock->drid.uid, dlock->drid.id, dlock->drid.idx, dlock->drid.part, lock_res->count);
    drc_unlock_local_res_count(lock_res);
    return (is_locked && is_owner);
}

void dls_spin_unlock(knl_session_t *session, drlock_t *dlock)
{
    database_t *db = &session->kernel->db;
    drc_local_lock_res_t *lock_res;

    if (session->kernel->attr.clustered && !DAAC_REPLAY_NODE(session) && db->status >= DB_STATUS_MOUNT) {
        knl_panic(dlock->drid.type != DR_TYPE_INVALID);
        lock_res = drc_get_local_resx(&dlock->drid);
        dls_request_spin_unlock(session, lock_res);
        drc_unlock_local_resx(lock_res);
        DTC_DLS_DEBUG_INF("[DLS] release spinlock(%u/%u/%u/%u/%u) successfully", dlock->drid.type, dlock->drid.uid,
                          dlock->drid.id, dlock->drid.idx, dlock->drid.part);
    } else {
        cm_spin_unlock(&dlock->lock);
    }

    return;
}

void dls_spin_add(knl_session_t *session, drlock_t *dlock)
{
    database_t *db = &session->kernel->db;
    drc_local_lock_res_t *lock_res;

    if (session->kernel->attr.clustered && !DAAC_REPLAY_NODE(session) && db->status >= DB_STATUS_MOUNT) {
        knl_panic(dlock->drid.type != DR_TYPE_INVALID);
        lock_res = drc_get_local_resx(&dlock->drid);
        drc_lock_local_res_count(lock_res);
        lock_res->count++;
        DTC_DLS_DEBUG_INF("[DLS] end spin add (%u/%u/%u/%u/%u), lock count %d",
            dlock->drid.type, dlock->drid.uid, dlock->drid.id, dlock->drid.idx, dlock->drid.part, lock_res->count);
        drc_unlock_local_res_count(lock_res);
    }
}

void dls_spin_dec(knl_session_t *session, drlock_t *dlock)
{
    database_t *db = &session->kernel->db;
    drc_local_lock_res_t *lock_res;

    if (session->kernel->attr.clustered && !DAAC_REPLAY_NODE(session) && db->status >= DB_STATUS_MOUNT) {
        knl_panic(dlock->drid.type != DR_TYPE_INVALID);
        lock_res = drc_get_local_resx(&dlock->drid);
        drc_lock_local_res_count(lock_res);
        if (lock_res->count > 0) {
            lock_res->count--;
        }
        drc_unlock_local_res_count(lock_res);
    }
}

void dls_spin_dec_unlock(knl_session_t *session, drlock_t *dlock)
{
    database_t *db = &session->kernel->db;
    drc_local_lock_res_t *lock_res;

    if (session->kernel->attr.clustered && !DAAC_REPLAY_NODE(session) && db->status >= DB_STATUS_MOUNT) {
        knl_panic(dlock->drid.type != DR_TYPE_INVALID);
        lock_res = drc_get_local_resx(&dlock->drid);
        drc_lock_local_res_count(lock_res);
        DTC_DLS_DEBUG_INF("[DLS] spin dec unlock (%u/%u/%u/%u/%u), lock count %d", dlock->drid.type, dlock->drid.uid,
                          dlock->drid.id, dlock->drid.idx, dlock->drid.part, lock_res->count);
        if (lock_res->count > 0) {
            lock_res->count--;
        }
        if (lock_res->count == 0) {
            dls_spin_unlock(session, dlock);
        }
        drc_unlock_local_res_count(lock_res);
    }
}

status_t dls_clean_granted_map(knl_session_t *session, drid_t *lock_id, uint8 inst_id)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_master_res_t *lock_res;
    drc_res_bucket_t *bucket;
    uint32 part_id;
    spinlock_t *res_part_stat_lock = NULL;
    bucket = drc_get_res_map_bucket(&ctx->global_lock_res.res_map, (char *)lock_id, sizeof(drid_t));
    part_id = drc_resource_id_hash((char *)lock_id, sizeof(drid_t), DRC_MAX_PART_NUM);
    res_part_stat_lock = &ctx->global_lock_res.res_part_stat_lock[part_id];
    cm_spin_lock(res_part_stat_lock, NULL);
    cm_spin_lock(&bucket->lock, NULL);

    DTC_DRC_DEBUG_INF("[DRC][%u/%u/%u/%u/%u][clean granted map]", lock_id->type, lock_id->uid, lock_id->id,
        lock_id->idx, lock_id->part);

    lock_res = (drc_master_res_t *)drc_res_map_lookup(&ctx->global_lock_res.res_map, bucket, (char *)lock_id);
    if (NULL == lock_res) {
        DTC_DRC_DEBUG_INF("[DRC][%u/%u/%u/%u/%u][clean granted map]: global lock res is null, no need to clean",
            lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part);
    } else {
        drc_bitmap64_clear(&lock_res->granted_map, inst_id);
        if (lock_res->granted_map == 0) {
            lock_res->mode = DRC_LOCK_NULL;
        }
    }
    cm_spin_unlock(&bucket->lock);
    cm_spin_unlock(res_part_stat_lock);
    DTC_DRC_DEBUG_INF("[DRC][%u/%u/%u/%u/%u][clean granted map]: successed",
        lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part);
    return CT_SUCCESS;
}

void dls_request_clean_granted_map(knl_session_t *session, drid_t *lock_id)
{
    uint8 master_id = CT_INVALID_ID8;
    uint8 self_id = session->kernel->dtc_attr.inst_id;
    drc_req_info_t req_info = {0};
    req_info.release_timeout_ticks = CT_INVALID_ID32;
    req_info.req_mode = DRC_LOCK_MODE_MAX;
    drc_get_lock_master_id(lock_id, &master_id);
    if (master_id == self_id) {
        dls_clean_granted_map(session, lock_id, self_id);
    } else {
        dls_request_msg(session, lock_id, master_id, MES_CMD_CLEAN_GRANTED_MAP, &req_info,
            DRC_GET_CURR_REFORM_VERSION);
    }
    return;
}

bool32 dls_request_latch_s(knl_session_t *session, drid_t *lock_id, bool32 timeout, uint32 timeout_ticks,
    uint32 release_timeout_ticks)
{
    uint32 spin_times = 0;
    uint32 wait_ticks = 0;
    drc_req_info_t req_info;

    do {
        req_info.inst_id = session->kernel->id;
        req_info.inst_sid = session->id;
        req_info.req_mode = DRC_LOCK_SHARE;
        req_info.curr_mode = DRC_LOCK_MODE_MAX;
        req_info.rsn = mes_get_rsn(session->id);
        req_info.req_time = KNL_NOW(session);
        req_info.req_version = DRC_GET_CURR_REFORM_VERSION;
        req_info.lsn = CT_INVALID_ID64;
        req_info.release_timeout_ticks = release_timeout_ticks;
        if (dls_request_lock(session, lock_id, &req_info, MES_CMD_REQUEST_LATCH_S) == CT_SUCCESS) {
            return  CT_TRUE;
        }

        if (timeout && SECUREC_UNLIKELY(wait_ticks >= timeout_ticks)) {
            DTC_DLS_DEBUG_INF("[DLS] add timed latch_s(%u/%u/%u/%u/%u) timeout",
                lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part);
            return CT_FALSE;
        }

#ifndef WIN32
        fas_cpu_pause();
#endif  // !WIN32
        spin_times++;
        if (SECUREC_UNLIKELY(spin_times == CT_DLS_SPIN_COUNT)) {
            cm_spin_sleep();
            spin_times = 0;
            wait_ticks++;
        }
    } while (CT_TRUE);
}

bool32 dls_request_latch_x(knl_session_t *session, drid_t *lock_id, bool32 timeout, uint32 timeout_ticks,
    uint32 release_timeout_ticks)
{
    status_t ret = CT_SUCCESS;
    uint32 spin_times = 0;
    uint32 wait_ticks = 0;
    drc_req_info_t req_info;

    do {
        req_info.inst_id = session->kernel->id;
        req_info.inst_sid = session->id;
        req_info.req_mode = DRC_LOCK_EXCLUSIVE;
        req_info.curr_mode = DRC_LOCK_MODE_MAX;
        req_info.rsn = mes_get_rsn(session->id);
        req_info.req_time = KNL_NOW(session);
        req_info.req_version = DRC_GET_CURR_REFORM_VERSION;
        req_info.lsn = CT_INVALID_ID64;
        req_info.release_timeout_ticks = release_timeout_ticks;
        ret = dls_request_lock(session, lock_id, &req_info, MES_CMD_REQUEST_LATCH_X);
        if (ret == CT_SUCCESS) {
            return  CT_TRUE;
        }

        if (timeout && SECUREC_UNLIKELY(wait_ticks >= timeout_ticks)) {
            DTC_DLS_DEBUG_INF("[DLS] add timed latch_x(%u/%u/%u/%u/%u) timeout",
                lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part);
            return CT_FALSE;
        }

#ifndef WIN32
        fas_cpu_pause();
#endif  // !WIN32
        spin_times++;
        if (SECUREC_UNLIKELY(spin_times == CT_DLS_SPIN_COUNT)) {
            cm_spin_sleep();
            spin_times = 0;
            wait_ticks++;
        }
    } while (CT_TRUE);

    return CT_TRUE;
}

static void dls_latch_ix2x(knl_session_t *session, drid_t *lock_id, drc_local_latch *latch_stat, uint32 sid, latch_statis_t *stat)
{
    uint32 count = 0;
    bool32 locked = CT_FALSE;
    drc_local_lock_res_t *lock_res;

    for (;;) {
        if (stat != NULL) {
            stat->misses++;
        }
        
        while (latch_stat->shared_count > 0) {
            count++;
            if (count >= CT_SPIN_COUNT) {
                SPIN_STAT_INC(stat, ix_sleeps);
                cm_spin_sleep();
                count = 0;
            }
        }
        
        lock_res = drc_get_local_resx(lock_id);
        drc_lock_local_resx(lock_res);
        if (latch_stat->shared_count == 0) {
            locked = dls_request_latch_x(session, lock_id, CT_TRUE, 1, CT_INVALID_ID32);
            if (locked) {
                latch_stat->sid = sid;
                latch_stat->stat = LATCH_STATUS_X;
                latch_stat->lock_mode = DRC_LOCK_EXCLUSIVE;
                drc_set_local_lock_statx(lock_res, CT_TRUE, CT_TRUE);
                drc_unlock_local_resx(lock_res);
                break;
            }
        }
        drc_unlock_local_resx(lock_res);
        cm_spin_sleep();
    }
}

static bool32 dls_latch_timed_ix2x(knl_session_t *session, drid_t *lock_id, drc_local_latch *latch_stat, uint32 sid,
                                   uint32 wait_ticks, latch_statis_t *stat, uint32 release_timeout_ticks)
{
    uint32 count = 0;
    bool32 locked = CT_FALSE;
    drc_local_lock_res_t *lock_res;
    uint32 ticks = 0;

    for (;;) {
        if (stat != NULL) {
            stat->misses++;
        }

        while (latch_stat->shared_count > 0) {
            if (ticks >= wait_ticks) {
                return CT_FALSE;
            }

            count++;
            if (count >= CT_SPIN_COUNT) {
                SPIN_STAT_INC(stat, ix_sleeps);
                cm_spin_sleep();
                count = 0;
                ticks++;
            }
        }

        lock_res = drc_get_local_resx(lock_id);
        drc_lock_local_resx(lock_res);
        if (latch_stat->shared_count == 0) {
            locked = dls_request_latch_x(session, lock_id, CT_TRUE, 1, release_timeout_ticks);
            if (locked) {
                latch_stat->sid = sid;
                latch_stat->stat = LATCH_STATUS_X;
                latch_stat->lock_mode = DRC_LOCK_EXCLUSIVE;
                drc_set_local_lock_statx(lock_res, CT_TRUE, CT_TRUE);
                drc_unlock_local_resx(lock_res);
                return CT_TRUE;
            }
        }
        drc_unlock_local_resx(lock_res);
        cm_spin_sleep();
    }
}

void dls_latch_x(knl_session_t *session, drlatch_t *dlatch, uint32 sid, latch_statis_t *stat)
{
    database_t *db = &session->kernel->db;
    uint32 count = 0;
    drc_local_latch* latch_stat = NULL;
    bool32 locked = CT_FALSE;
    drc_local_lock_res_t *lock_res;

    if (session->kernel->attr.clustered && !DAAC_REPLAY_NODE(session) && db->status >= DB_STATUS_MOUNT) {
        knl_panic(dlatch->drid.type != DR_TYPE_INVALID);
        for (;;) {
            lock_res = drc_get_local_resx(&dlatch->drid);
            drc_lock_local_resx(lock_res);
            drc_get_local_latch_statx(lock_res, &latch_stat);
            DTC_DLS_DEBUG_INF("[DLS] add latch_x(%u/%u/%u/%u/%u), state=%d, lock_mode=%d", dlatch->drid.type,
                              dlatch->drid.uid, dlatch->drid.id, dlatch->drid.idx, dlatch->drid.part, latch_stat->stat,
                              latch_stat->lock_mode);
            if (latch_stat->stat == LATCH_STATUS_IDLE) {
                //x->i->x not need lock for local latch
                if (latch_stat->lock_mode != DRC_LOCK_EXCLUSIVE) {
                    locked = dls_request_latch_x(session, &dlatch->drid,  CT_TRUE, 1, CT_INVALID_ID32);
                    if (!locked) {
                        drc_unlock_local_resx(lock_res);
                        cm_spin_sleep();
                        continue;
                    }
                    latch_stat->lock_mode = DRC_LOCK_EXCLUSIVE;
                }
                latch_stat->sid = sid;
                latch_stat->stat = LATCH_STATUS_X;
                drc_set_local_lock_statx(lock_res, CT_TRUE, CT_TRUE);
                drc_unlock_local_resx(lock_res);
                cm_latch_stat_inc(stat, count);
                return;
            } else if (latch_stat->stat == LATCH_STATUS_S) {
                latch_stat->stat = LATCH_STATUS_IX;
                drc_unlock_local_resx(lock_res);
                dls_latch_ix2x(session, &dlatch->drid, latch_stat, sid, stat);
                return;
            } else {
                drc_unlock_local_resx(lock_res);
                if (stat != NULL) {
                    stat->misses++;
                }
                while (latch_stat->stat != LATCH_STATUS_IDLE && latch_stat->stat != LATCH_STATUS_S) {
                    count++;
                    if (count >= CT_SPIN_COUNT) {
                        SPIN_STAT_INC(stat, x_sleeps);
                        cm_spin_sleep();
                        count = 0;
                    }
                }
            }
        }
    } else {
        cm_latch_x(&dlatch->latch, sid, stat);
    }
}

void dls_latch_s(knl_session_t *session, drlatch_t *dlatch, uint32 sid, bool32 is_force, latch_statis_t *stat)
{
    database_t *db = &session->kernel->db;
    uint32 count = 0;
    drc_local_latch* latch_stat = NULL;
    bool32 locked = CT_FALSE;
    drc_local_lock_res_t *lock_res;

    if (session->kernel->attr.clustered && !DAAC_REPLAY_NODE(session) && db->status >= DB_STATUS_MOUNT) {
        knl_panic(dlatch->drid.type != DR_TYPE_INVALID);
        for (;;) {
            lock_res = drc_get_local_resx(&dlatch->drid);
            drc_lock_local_resx(lock_res);
            drc_get_local_latch_statx(lock_res, &latch_stat);
            DTC_DLS_DEBUG_INF("[DLS] add latch_s(%u/%u/%u/%u/%u), state=%d, lock_mode=%d", dlatch->drid.type,
                              dlatch->drid.uid, dlatch->drid.id, dlatch->drid.idx, dlatch->drid.part, latch_stat->stat,
                              latch_stat->lock_mode);
            if (latch_stat->stat == LATCH_STATUS_IDLE) {
                //s->i->s no need for local latch
                if (latch_stat->lock_mode == DRC_LOCK_NULL) {
                    locked = dls_request_latch_s(session, &dlatch->drid, CT_TRUE, 1, CT_INVALID_ID32);
                    if (!locked) {
                        drc_unlock_local_resx(lock_res);
                        cm_spin_sleep();
                        continue;
                    }
                    latch_stat->lock_mode = DRC_LOCK_SHARE;
                }
                latch_stat->stat = LATCH_STATUS_S;
                latch_stat->shared_count = 1;
                latch_stat->sid = sid;
                drc_set_local_lock_statx(lock_res, CT_TRUE, CT_TRUE);
                drc_unlock_local_resx(lock_res);
                cm_latch_stat_inc(stat, count);
                return;
            } else if ((latch_stat->stat == LATCH_STATUS_S) || (latch_stat->stat == LATCH_STATUS_IX && is_force)) {
                latch_stat->shared_count++;
                drc_set_local_lock_statx(lock_res, CT_TRUE, CT_TRUE);
                drc_unlock_local_resx(lock_res);
                cm_latch_stat_inc(stat, count);
                return;
            } else {
                drc_unlock_local_resx(lock_res);
                if (stat != NULL) {
                    stat->misses++;
                }
                while (latch_stat->stat != LATCH_STATUS_IDLE && latch_stat->stat != LATCH_STATUS_S) {
                    count++;
                    if (count >= CT_SPIN_COUNT) {
                        SPIN_STAT_INC(stat, s_sleeps);
                        cm_spin_sleep();
                        count = 0;
                    }
                }
            }
        }
    } else {
        cm_latch_s(&dlatch->latch, sid, is_force, stat);
    }

    return;
}

bool32 dls_latch_timed_s(knl_session_t *session, drlatch_t *dlatch, uint32 ticks_for_wait, bool32 is_force,
                         latch_statis_t *stat, uint32 release_timeout_ticks)
{
    uint32 count = 0;
    uint32 ticks = 0;
    database_t *db = &session->kernel->db;
    drc_local_latch* latch_stat = NULL;
    drc_local_lock_res_t *lock_res;
    uint32 wait_ticks = ticks_for_wait;

    if (session->kernel->attr.clustered && !DAAC_REPLAY_NODE(session) && db->status >= DB_STATUS_MOUNT) {
        knl_panic(dlatch->drid.type != DR_TYPE_INVALID);
        DTC_DLS_DEBUG_INF("[DLS] add timed latch_s(%u/%u/%u/%u/%u)",
            dlatch->drid.type, dlatch->drid.uid, dlatch->drid.id, dlatch->drid.idx, dlatch->drid.part);
        for (;;) {
            lock_res = drc_get_local_resx(&dlatch->drid);
            drc_lock_local_resx(lock_res);
            drc_get_local_latch_statx(lock_res, &latch_stat);
            if (latch_stat->stat == LATCH_STATUS_IDLE) {
                if (latch_stat->lock_mode == DRC_LOCK_NULL) {
                    wait_ticks = (wait_ticks - ticks > 0) ? (wait_ticks - ticks) : 0;
                    if (!dls_request_latch_s(session, &dlatch->drid, CT_TRUE, wait_ticks, release_timeout_ticks)) {
                        drc_set_local_lock_statx(lock_res, CT_FALSE, CT_FALSE);
                        drc_unlock_local_resx(lock_res);
                        return CT_FALSE;
                    }
                    latch_stat->lock_mode = DRC_LOCK_SHARE;
                }
                latch_stat->stat = LATCH_STATUS_S;
                latch_stat->shared_count = 1;
                drc_set_local_lock_statx(lock_res, CT_TRUE, CT_TRUE);
                drc_unlock_local_resx(lock_res);
                return CT_TRUE;
            } else if ((latch_stat->stat == LATCH_STATUS_S) || (latch_stat->stat == LATCH_STATUS_IX && is_force)) {
                latch_stat->shared_count++;
                drc_set_local_lock_statx(lock_res, CT_TRUE, CT_TRUE);
                drc_unlock_local_resx(lock_res);
                return CT_TRUE;
            } else {
                drc_unlock_local_resx(lock_res);
                while (latch_stat->stat != LATCH_STATUS_IDLE && latch_stat->stat != LATCH_STATUS_S) {
                    if (ticks >= wait_ticks) {
                        DTC_DLS_DEBUG_INF("[DLS] add timed latch_s(%u/%u/%u/%u/%u) timeout",
                            dlatch->drid.type, dlatch->drid.uid, dlatch->drid.id, dlatch->drid.idx, dlatch->drid.part);
                        return CT_FALSE;
                    }
                    count++;
                    if (count >= CT_SPIN_COUNT) {
                        SPIN_STAT_INC(stat, s_sleeps);
                        cm_spin_sleep();
                        count = 0;
                        ticks++;
                    }
                }
            }
        }
    } else {
        return cm_latch_timed_s(&dlatch->latch, wait_ticks, is_force, stat);
    }
}

bool32 dls_latch_timed_x(knl_session_t *session, drlatch_t *dlatch, uint32 ticks_for_wait, bool32 is_force,
                         latch_statis_t *stat, uint32 release_timeout_ticks)
{
    uint32 count = 0;
    uint32 ticks = 0;
    database_t *db = &session->kernel->db;
    drc_local_latch *latch_stat = NULL;
    drc_local_lock_res_t *lock_res;
    uint32 wait_ticks = ticks_for_wait;

    if (session->kernel->attr.clustered && !DAAC_REPLAY_NODE(session) && db->status >= DB_STATUS_MOUNT) {
        knl_panic(dlatch->drid.type != DR_TYPE_INVALID);
        DTC_DLS_DEBUG_INF("[DLS] add timed latch_x(%u/%u/%u/%u/%u)", dlatch->drid.type, dlatch->drid.uid,
                          dlatch->drid.id, dlatch->drid.idx, dlatch->drid.part);
        for (;;) {
            lock_res = drc_get_local_resx(&dlatch->drid);
            drc_lock_local_resx(lock_res);
            drc_get_local_latch_statx(lock_res, &latch_stat);
            if (latch_stat->stat == LATCH_STATUS_IDLE) {
                if (latch_stat->lock_mode != DRC_LOCK_EXCLUSIVE) {
                    wait_ticks = (wait_ticks - ticks > 0) ? (wait_ticks - ticks) : 0;
                    if (!dls_request_latch_x(session, &dlatch->drid, CT_TRUE, wait_ticks, release_timeout_ticks)) {
                        drc_set_local_lock_statx(lock_res, CT_FALSE, CT_FALSE);
                        drc_unlock_local_resx(lock_res);
                        return CT_FALSE;
                    }
                    latch_stat->lock_mode = DRC_LOCK_EXCLUSIVE;
                }
                latch_stat->sid = session->id;
                latch_stat->stat = LATCH_STATUS_X;
                drc_set_local_lock_statx(lock_res, CT_TRUE, CT_TRUE);
                drc_unlock_local_resx(lock_res);
                cm_latch_stat_inc(stat, count);
                return CT_TRUE;
            } else if (latch_stat->stat == LATCH_STATUS_S) {
                latch_stat->stat = LATCH_STATUS_IX;
                drc_unlock_local_resx(lock_res);
                if (!dls_latch_timed_ix2x(session, &dlatch->drid, latch_stat, session->id, wait_ticks, stat,
                    release_timeout_ticks)) {
                    drc_lock_local_resx(lock_res);
                    latch_stat->stat = latch_stat->shared_count > 0 ? LATCH_STATUS_S : LATCH_STATUS_IDLE;
                    drc_unlock_local_resx(lock_res);
                    return CT_FALSE;
                }
                return CT_TRUE;
            } else {
                drc_unlock_local_resx(lock_res);
                if (stat != NULL) {
                    stat->misses++;
                }
                while (latch_stat->stat != LATCH_STATUS_IDLE && latch_stat->stat != LATCH_STATUS_S) {
                    if (ticks >= wait_ticks) {
                        DTC_DLS_DEBUG_INF("[DLS] add timed latch_x(%u/%u/%u/%u/%u) timeout", dlatch->drid.type,
                                          dlatch->drid.uid, dlatch->drid.id, dlatch->drid.idx, dlatch->drid.part);
                        return CT_FALSE;
                    }
                    count++;
                    if (count >= CT_SPIN_COUNT) {
                        SPIN_STAT_INC(stat, x_sleeps);
                        cm_spin_sleep();
                        count = 0;
                        ticks++;
                    }
                }
            }
        }
    } else {
        return cm_latch_timed_x(&dlatch->latch, wait_ticks, is_force, stat);
    }
}

void dls_unlatch(knl_session_t *session, drlatch_t *dlatch, latch_statis_t *stat)
{
    database_t *db = &session->kernel->db;
    drc_local_latch* latch_stat = NULL;
    drc_local_lock_res_t *lock_res;

    //check dls spinlock valid in debug
    if (session->kernel->attr.clustered && !DAAC_REPLAY_NODE(session) && db->status >= DB_STATUS_MOUNT) {
        knl_panic(dlatch->drid.type != DR_TYPE_INVALID);
        DTC_DLS_DEBUG_INF("[DLS] release latch(%u/%u/%u/%u/%u)",
            dlatch->drid.type, dlatch->drid.uid, dlatch->drid.id, dlatch->drid.idx, dlatch->drid.part);
        lock_res = drc_get_local_resx(&dlatch->drid);
        drc_lock_local_resx(lock_res);
        drc_get_local_latch_statx(lock_res, &latch_stat);
        DTC_DLS_DEBUG_INF("[DLS] release latch(%u/%u/%u/%u/%u), stat=%d, shared_count:%d, lock_mode:%d",
                          dlatch->drid.type, dlatch->drid.uid, dlatch->drid.id, dlatch->drid.idx, dlatch->drid.part,
                          latch_stat->stat, latch_stat->shared_count, latch_stat->lock_mode);
        if (latch_stat->shared_count > 0) {
            latch_stat->shared_count--;
        }
        if ((latch_stat->stat == LATCH_STATUS_S || latch_stat->stat == LATCH_STATUS_X) && (latch_stat->shared_count == 0)) {
            latch_stat->stat = LATCH_STATUS_IDLE;
        }
        drc_set_local_lock_statx(lock_res, CT_FALSE, CT_TRUE);
        drc_unlock_local_resx(lock_res);
    } else {
        cm_unlatch(&dlatch->latch, stat);
    }
    return;
}

status_t dtc_is_inst_fault(uint32 inst_id)
{
    cluster_view_t view;
    rc_get_cluster_view(&view, CT_FALSE);
    if (!rc_bitmap64_exist(&view.bitmap, inst_id)) {
        return CT_SUCCESS;
    }
    return CT_ERROR;
}

#define DLS_REMOTE_TXN_WAIT  (0)
#define DLS_REMOTE_TXN_END  (1)

status_t dls_request_txn_msg(knl_session_t *session, xid_t* xid, uint8 dst_inst, uint32 cmd)
{
    status_t ret = CT_SUCCESS;
    uint8 *send_msg = NULL;
    mes_message_head_t* head = NULL;
    mes_message_t    recv_msg = {0};
    uint8    src_inst = session->kernel->dtc_attr.inst_id;

    send_msg = (uint8*)cm_push(session->stack, sizeof(mes_message_head_t) + sizeof(xid_t));
    head = (mes_message_head_t*)send_msg;
    mes_init_send_head(head, cmd, sizeof(mes_message_head_t) + sizeof(uint64), CT_INVALID_ID32, src_inst, dst_inst,
                       session->id, CT_INVALID_ID16);
    *((uint64*)(send_msg + sizeof(mes_message_head_t))) = xid->value;

    knl_begin_session_wait(session, DLS_WAIT_TXN, CT_TRUE);
    SYNC_POINT_GLOBAL_START(CANTIAN_DLS_WAIT_TXN_SEND_FAIL, &ret, CT_ERROR);
    ret = mes_send_data(send_msg);
    SYNC_POINT_GLOBAL_END;
    if (ret != CT_SUCCESS) {
        knl_end_session_wait(session, DLS_WAIT_TXN);
        cm_pop(session->stack);
        DTC_DLS_DEBUG_ERR("[DLS] request txn message to instance(%u) failed, type(%u) xid(%llu) rsn(%u) errcode(%u)",
                          dst_inst, cmd, xid->value, head->rsn, ret);
        return ret;
    }
    cm_pop(session->stack);

    ret = mes_recv(session->id, &recv_msg, CT_FALSE, head->rsn, DLS_WAIT_TIMEOUT);
    if (ret != CT_SUCCESS) {
        knl_end_session_wait(session, DLS_WAIT_TXN);
        DTC_DLS_DEBUG_ERR("[DLS] receive message to instance(%u) failed, type(%u) xid(%llu) rsn(%u) errcode(%u)",
                          dst_inst, cmd, xid->value, head->rsn, ret);
        return ret;
    }
    knl_end_session_wait(session, DLS_WAIT_TXN);
    ret = *(status_t*)(recv_msg.buffer + sizeof(mes_message_head_t));
    if (ret == DLS_REMOTE_TXN_END) {
        knl_scn_t scn = *(knl_scn_t*)(recv_msg.buffer + sizeof(mes_message_head_t) + sizeof(status_t));
        dtc_update_scn(session, scn);
    }
    mes_release_message_buf(recv_msg.buffer);
    return ret;
}

static void  dls_send_txn_msg(knl_session_t *session, xid_t*  xid, knl_scn_t scn, uint32 dst_inst, uint32 cmd)
{
    status_t ret = CT_SUCCESS;
    uint8 *send_msg = NULL;
    mes_message_head_t* head = NULL;
    uint8    src_inst = session->kernel->dtc_attr.inst_id;
    uint32 mes_size = sizeof(mes_message_head_t) + sizeof(xid_t) + sizeof(knl_scn_t);

    send_msg = (uint8*)cm_push(session->stack, mes_size);
    head = (mes_message_head_t*)send_msg;

    mes_init_send_head(head, cmd, mes_size, CT_INVALID_ID32, src_inst, dst_inst, session->id, CT_INVALID_ID16);
    *((uint64*)(send_msg + sizeof(mes_message_head_t))) = xid->value;
    *((knl_scn_t*)(send_msg + sizeof(mes_message_head_t) + sizeof(xid_t))) = scn;

    ret = mes_send_data(send_msg);
    if (ret != CT_SUCCESS) {
        cm_pop(session->stack);
        DTC_DLS_DEBUG_ERR(
            "[DLS] send txn message to instance(%u) failed, type(%u) xid(%llu) scn(%llu) rsn(%u) errcode(%u)", dst_inst,
            cmd, xid->value, scn, head->rsn, ret);
        return;
    }
    cm_pop(session->stack);

    return;
}

void dls_process_txn_wait(knl_session_t *session, mes_message_t * receive_msg)
{
    status_t ret = CT_SUCCESS;
    uint8 *send_msg = NULL;
    mes_message_head_t* head = NULL;
    txn_info_t txn_info;
    knl_scn_t scn = CT_INVALID_ID64;
    if (sizeof(mes_message_head_t) + sizeof(uint64) != receive_msg->head->size) {
        CT_LOG_RUN_ERR("process txn awake msg is invalid, msg size %u.", receive_msg->head->size);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    xid_t  *xid = (xid_t*)(receive_msg->buffer + sizeof(mes_message_head_t));
    uint32 mes_size = sizeof(mes_message_head_t) + sizeof(status_t) + sizeof(knl_scn_t);
    if ((xid->xmap.slot / TXN_PER_PAGE(session)) >= UNDO_MAX_TXN_PAGE) {
        CT_LOG_RUN_ERR("txn xmap slot is invalid, slot %u.", xid->xmap.slot);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }

    uint8 inst_id = xid_get_inst_id(session, *xid);
    if (inst_id != session->kernel->id || receive_msg->head->src_inst >= CT_MAX_INSTANCES) {
        CT_LOG_RUN_ERR("xid %llu or src_inst %u error, inst_id by xid %u, self_id %u", xid->value,
            receive_msg->head->src_inst, inst_id, session->kernel->id);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    // knl_panic(xid_get_inst_id(session, *xid) == session->kernel->id);
    tx_get_info(session, CT_FALSE, *xid, &txn_info);
    if (txn_info.status == (uint8)XACT_END) {
        ret = DLS_REMOTE_TXN_END;
        scn = txn_info.scn;
    } else {
        drc_enqueue_txn(xid, receive_msg->head->src_inst);
        ret = DLS_REMOTE_TXN_WAIT;

        tx_get_info(session, CT_FALSE, *xid, &txn_info);
        if (txn_info.status == (uint8)XACT_END) {
            ret = DLS_REMOTE_TXN_END;
            scn = txn_info.scn;
            drc_release_txn(session, xid, DB_CURR_SCN(session), dls_send_txn_msg);
        }
    }

    send_msg = (uint8*)cm_push(session->stack, mes_size);
    if (send_msg == NULL) {
        CT_LOG_RUN_ERR("msg failed to malloc memory");
        return;
    }
    head = (mes_message_head_t*)send_msg;

    mes_init_ack_head(receive_msg->head, head, MES_CMD_TXN_ACK, mes_size, CT_INVALID_ID16);
    *((status_t*)(send_msg + sizeof(mes_message_head_t))) = ret;
    *((knl_scn_t*)(send_msg + sizeof(mes_message_head_t) + sizeof(status_t))) = scn;

    DTC_DLS_DEBUG_INF("[DLS] process wait txn %llu scn %llu status %u from instance %u", xid->value, scn, ret, receive_msg->head->src_inst);
    SYNC_POINT_GLOBAL_START(CANTIAN_DLS_WAIT_TXN_ACK_SEND_FAIL, &ret, CT_ERROR);
    ret = mes_send_data(send_msg);
    SYNC_POINT_GLOBAL_END;
    if (ret != CT_SUCCESS) {
        DTC_DLS_DEBUG_ERR("[DLS] process wait txn %llu from instance %u failed", xid->value, receive_msg->head->src_inst);
    }
    mes_release_message_buf(receive_msg->buffer);
    cm_pop(session->stack);
    return;
}

static void dls_process_txn_awake(knl_session_t *session, mes_message_t * receive_msg)
{
    uint32 mes_size = sizeof(mes_message_head_t) + sizeof(xid_t) + sizeof(knl_scn_t);
    if (mes_size != receive_msg->head->size) {
        CT_LOG_RUN_ERR("process txn awake msg is invalid, msg size %u.", receive_msg->head->size);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    xid_t  *xid = (xid_t*)(receive_msg->buffer + sizeof(mes_message_head_t));
    knl_scn_t scn = *(knl_scn_t*)(receive_msg->buffer + sizeof(mes_message_head_t) + sizeof(xid_t));

    drc_local_txn_awake(xid);
    dtc_update_scn(session, scn);
    DTC_DLS_DEBUG_INF("[DLS] process wake up txn %llu scn %llu from instance %u", xid->value, scn, receive_msg->head->src_inst);
    mes_release_message_buf(receive_msg->buffer);
    return;
}

void dls_process_txn_msg(void *sess, mes_message_t * receive_msg)
{
    knl_session_t *session = (knl_session_t *)sess;

    if (MES_CMD_WAIT_TXN == receive_msg->head->cmd) {
        dls_process_txn_wait(session, receive_msg);
    } else if (MES_CMD_AWAKE_TXN == receive_msg->head->cmd) {
        dls_process_txn_awake(session, receive_msg);
    } else {
        CT_LOG_RUN_ERR("[DLS] invalid cmd %u, not process", receive_msg->head->cmd);
    }
    return;
}

bool32 dls_wait_txn(knl_session_t *session, uint16 rmid)
{
    status_t ret = CT_SUCCESS;
    knl_rm_t *wait_rm = NULL;
    txn_snapshot_t snapshot;
    uint8 inst_id;

    inst_id = XID_INST_ID(session->wxid);
    if (inst_id == session->kernel->id) {
        wait_rm = session->kernel->rms[rmid];
        if (cm_wait_cond(&wait_rm->cond, TX_WAIT_INTERVEL)) {
            tx_get_snapshot(session, session->wxid.xmap, &snapshot);
            if (snapshot.xnum != session->wxid.xnum || snapshot.status == (uint8)XACT_END) {
                return CT_TRUE;
            }
        }
        return CT_FALSE;
    }

    inst_id = xid_get_inst_id(session, session->wxid);
    DTC_DLS_DEBUG_INF("[DLS] wait txn %llu from instance %u", session->wxid.value, inst_id);
    // send message to owner (check txn status and record in wait hash queue)
    ret = dls_request_txn_msg(session, (xid_t *)(&session->wxid), inst_id, MES_CMD_WAIT_TXN);
    if (ret == DLS_REMOTE_TXN_END) {
        return CT_TRUE;
    }

    if (ret == DLS_REMOTE_TXN_WAIT) {
        if (drc_local_txn_wait((xid_t *)(&session->wxid))) {
            tx_get_snapshot(session, session->wxid.xmap, &snapshot);
            if (snapshot.xnum != session->wxid.xnum || snapshot.status == (uint8)XACT_END) {
                return CT_TRUE;
            }
        }
    }

    return CT_FALSE;
}

void dls_wait_txn_recyle(knl_session_t *session)
{
    uint8 inst_id = xid_get_inst_id(session, session->wxid);
    if (inst_id == session->kernel->id) {
        return;
    }
    drc_local_txn_recyle((xid_t *)(&session->wxid));
    return;
}

void dls_release_txn(knl_session_t *session, knl_rm_t *rm)
{
    cm_release_cond(&rm->cond);

    //remote
    if (DB_ATTR_CLUSTER(session)) {
        drc_release_txn(session, (xid_t *)(&rm->xid), rm->txn->scn, dls_send_txn_msg);
    }
    return;
}

#ifdef __cplusplus
}
#endif
