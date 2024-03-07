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
 * dtc_dc.c
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_dc.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_cluster_module.h"
#include "dtc_dc.h"
#include "dtc_dcs.h"
#include "dtc_context.h"
#include "knl_datafile.h"
#include "knl_buflatch.h"

logic_op_t g_ignore_logic_lmgrs[] = {
    RD_ADD_LOGFILE,
    RD_DROP_LOGFILE,
    RD_REGISTER_LOGFLIE,
};

#define DTC_WAIT_MES_TIMEOUT 10000
#define DTC_WAIT_MES_TIMEOUT_HIGH ((DTC_WAIT_MES_TIMEOUT) * 30)
#define DTC_MAX_RETRY_TIEMS (0xFFFFFFFF)
#define DTC_GET_BITMAP_TIME_INTERVAL (1000)
#define DTC_GET_BITMAP_RETRY_TIEMS (10)
#define IGNORE_LOGIC_LMGR_COUNT (uint32)(sizeof(g_ignore_logic_lmgrs) / sizeof(logic_op_t))
#define BTREE_WAIT_ACK_TIMEOUT (10000)  // ms
#define BTREE_WAIT_ACK_RETRY_THRESHOLD  (0xFFFFFFFF)
#define HEAP_WAIT_ACK_TIMEOUT (10000) // ms
#define HEAP_WAIT_ACK_RETRY_THRESHOLD  (0xFFFFFFFF)
#define UPGRADE_VERSION_WAIT_MES_TIMEOUT 10000
#define UPGRADE_VERSION_MAX_RETRY_TIEMS (0xFFFFFFFF)

bool32 can_ignore(logic_op_t type)
{
    for (uint32 i = 0; i < IGNORE_LOGIC_LMGR_COUNT; i++) {
        if (type == g_ignore_logic_lmgrs[i]) {
            return CT_TRUE;
        }
    }
    return CT_FALSE;
}

static status_t dtc_get_alive_bitmap(uint64 *target_bits)
{
    cluster_view_t view;
    rc_get_cluster_view(&view, CT_FALSE);
    *target_bits = view.bitmap;
    return CT_SUCCESS;
}

status_t dtc_send_sync_ddl_msg(knl_handle_t knl_session, char *logic_log_buf, uint32 logic_log_size)
{
    knl_session_t *session = (knl_session_t *)knl_session;
    msg_ddl_info_t info;
    info.scn = KNL_GET_SCN(&session->kernel->scn);
    info.log_len = logic_log_size;
    mes_init_send_head(&info.head, MES_CMD_DDL_BROADCAST, (uint16)(sizeof(msg_ddl_info_t) + logic_log_size),
        CT_INVALID_ID32, session->kernel->dtc_attr.inst_id, 0, session->id, CT_INVALID_ID16);
    uint64 target_bits = 0;
    status_t status = dtc_get_alive_bitmap(&target_bits);
    if (status != CT_SUCCESS) {
        CT_LOG_RUN_ERR("dtc sync ddl get alive bitmap failed");
        return status;
    }
    status = mes_broadcast_bufflist_and_wait_with_retry(session->id, target_bits, &info.head, sizeof(msg_ddl_info_t),
        logic_log_buf, DTC_WAIT_MES_TIMEOUT_HIGH, DTC_MAX_RETRY_TIEMS);
    return status;
}

status_t dtc_sync_ddl_internal(knl_handle_t knl_session, char * logic_log_buf, uint32 logic_log_size)
{
    knl_session_t *session = (knl_session_t *)knl_session;

    if (!DB_IS_CLUSTER(session) || session->bootstrap || (DB_STATUS(session) != DB_STATUS_OPEN)) {
        return CT_SUCCESS;
    }

    if (logic_log_size == 0) {
        return CT_SUCCESS;
    }

    SYNC_POINT_GLOBAL_START(CANTIAN_SYNC_DDL_BEFORE_BCAST_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;

    log_entry_t *log = (log_entry_t*)logic_log_buf;
    logic_op_t *op_type = (logic_op_t *)log->data;
    bool32 should_ignore = can_ignore(*op_type);

    CT_LOG_DEBUG_INF("dtc sync ddl type=%d, op_type=%d, size=%u, logic_log_size %u can ignore=%d", log->type, *op_type,
        log->size, logic_log_size, should_ignore);

    if (should_ignore) {
        return CT_SUCCESS;
    }
    char *syn_log_buf = (char *)cm_push(session->stack, (uint32)CT_DFLT_CTRL_BLOCK_SIZE);
    uint32 syn_log_size = 0;
    uint32_t offset = 0;
    uint32_t total_log_size = 0;
    while (offset < logic_log_size) {
        log_entry_t *tmplog = (log_entry_t *)((char*)logic_log_buf + offset);
        offset += tmplog->size;
        knl_panic(tmplog->size > 0);
        total_log_size += tmplog->size;
        CT_LOG_DEBUG_INF("dtc sync ddl log type=%d op_type=%d, size=%d , total size %dcan ignore=%d", tmplog->type,
            *(logic_op_t *)tmplog->data, tmplog->size, total_log_size, can_ignore(tmplog->type));
        knl_panic(total_log_size <= logic_log_size);
        logic_op_t tmp_op_type = *(logic_op_t *)tmplog->data;
        if (DB_IS_PRIMARY(&session->kernel->db) && (tmp_op_type == RD_LOCK_TABLE_FOR_MYSQL_DDL ||
            tmp_op_type == RD_UNLOCK_TABLE_FOR_MYSQL_DDL || tmp_op_type == RD_INVALID_DD_FOR_MYSQL_DDL)) {
            continue;
        }
        if (tmplog->size + syn_log_size > CT_DFLT_CTRL_BLOCK_SIZE) {
            status_t status = dtc_send_sync_ddl_msg(knl_session, syn_log_buf, syn_log_size);
            if (status != CT_SUCCESS) {
                cm_pop(session->stack);
                CT_LOG_RUN_ERR("dtc sync ddl failed, log type=%d op_type=%d, size=%d , logic_log_size size %d sync size %u can ignore=%d",
                    log->type, *op_type, log->size, logic_log_size, syn_log_size, should_ignore);
                return status;
            }
            syn_log_size = 0;
        }
        int32 ret = memcpy_sp(syn_log_buf + syn_log_size, CT_DFLT_CTRL_BLOCK_SIZE - syn_log_size, tmplog, tmplog->size);
        knl_securec_check(ret);
        syn_log_size += tmplog->size;
    }

    if (syn_log_size == 0) {
        cm_pop(session->stack);
        return CT_SUCCESS;
    }
    status_t status = dtc_send_sync_ddl_msg(knl_session, syn_log_buf, syn_log_size);
    if (status != CT_SUCCESS) {
        cm_pop(session->stack);
        CT_LOG_RUN_ERR("dtc sync ddl failed, log type=%d op_type=%d, size=%d , logic_log_size size %d sync size %u can ignore=%d",
            log->type, *op_type, log->size, logic_log_size, syn_log_size, should_ignore);
        return status;
    }
    cm_pop(session->stack);
    return status;
}

/*
* when call this interface, need to add CM_SAVE_STACK and CM_RESTORE_STACK around it
*/
char *dtc_push_ddl_redo(knl_handle_t knl_session, char *redo, uint32 redo_size)
{
    knl_session_t *session = (knl_session_t *)knl_session;
    uint32 logic_log_buf_size = LOG_ENTRY_SIZE + CM_ALIGN4(redo_size);
    char *buf = (char *)cm_push(session->stack, logic_log_buf_size);
    log_entry_t *entry = (log_entry_t *)buf;
    errno_t ret;

    entry->type = RD_LOGIC_OPERATION;
    entry->size = logic_log_buf_size;
    entry->flag = LOG_ENTRY_FLAG_NONE;

    ret = memcpy_sp((char *)entry->data, redo_size, redo, redo_size);
    knl_securec_check(ret);

    return buf;
}

status_t dtc_sync_ddl_redo(knl_handle_t knl_session, char * redo, uint32 redo_size)
{
    knl_session_t *session = (knl_session_t *)knl_session;
    char *buf = NULL;
    status_t status;

    CM_SAVE_STACK(session->stack);
    buf = dtc_push_ddl_redo(knl_session, redo, redo_size);
    status = dtc_sync_ddl_internal(session, buf, ((log_entry_t *)buf)->size);
    CM_RESTORE_STACK(session->stack);

    return status;
}

status_t dtc_sync_ddl(knl_handle_t knl_session)
{
    knl_session_t *session = (knl_session_t *)knl_session;

    knl_panic(session->logic_log_size > 0);

    knl_rm_t *rm = session->rm;
    char *logic_log_buf = NULL;
    if (session->logic_log_size <= KNL_LOGIC_LOG_BUF_SIZE) {
        logic_log_buf = rm->logic_log_buf;
    } else {
        logic_log_buf = mpool_page_addr(session->kernel->attr.large_pool, rm->large_page_id);
    }
    (void)dtc_sync_ddl_internal(session, logic_log_buf, session->logic_log_size);
    if (rm->large_page_id != CT_INVALID_ID32) {
        mpool_free_page(session->kernel->attr.large_pool, rm->large_page_id);
        rm->large_page_id = CT_INVALID_ID32;
    }

    session->logic_log_size = 0;
    knl_panic(!session->atomic_op);

    return CT_SUCCESS;
}


status_t dtc_refresh_ddl(knl_session_t *session, log_entry_t *log)
{
    logic_op_t *op_type = (logic_op_t *)log->data;
    bool32 should_ignore = can_ignore(*op_type);
    logic_log_manager_t *logic_lmgr = NULL;
    uint32 count;

    while (DB_STATUS(session) != DB_STATUS_OPEN) {
        cm_sleep(100);
    }

    knl_panic(DB_STATUS(session) == DB_STATUS_OPEN);

    if (should_ignore) {
        CT_LOG_RUN_WAR("dtc refresh ddl, ignore redo log,  type=%d, op_type=%d, size=%d", log->type, *op_type, log->size);
        return CT_SUCCESS;
    }

    CT_LOG_DEBUG_INF("dtc refresh ddl type=%d, op_type=%d, size=%d", log->type, *op_type, log->size);

    log_get_logic_manager(&logic_lmgr, &count);

    // replay logical log need update session query_scn
    session->query_scn = DB_CURR_SCN(session);

    for (uint32 id = 0; id < count; id++) {
        if (logic_lmgr[id].type == *op_type) {
            logic_lmgr[id].replay_proc(session, log);
            return CT_SUCCESS;
        }
    }

    if (*op_type >= RD_SQL_LOG_BEGIN && *op_type < RD_SQL_LOG_END) {
        if (g_knl_callback.pl_logic_log_replay(session, *op_type - RD_SQL_LOG_BEGIN,
            (void *)(log->data + CM_ALIGN4(sizeof(logic_op_t)))) != CT_SUCCESS) {
            int32 error_code;
            const char *error_message = NULL;
            cm_get_error(&error_code, &error_message, NULL);
            CT_LOG_RUN_ERR("sql logic log replay fail, error code:%u, error message:%s",
                           error_code, error_message);
            cm_reset_error();
            return CT_ERROR;
        }
        return CT_SUCCESS;
    }
    CT_LOG_RUN_ERR("[DTC] invalid op_type: %d", *op_type);
    return CT_ERROR;
}

status_t dtc_broadcast_btree_split(knl_session_t *session, btree_t *btree, knl_part_locate_t part_loc,
                                   bool32 is_splitted)
{
    status_t ret = CT_SUCCESS;
    msg_broadcast_data_t bcast;
    msg_broadcast_btree_data_t btree_data;

    btree_data.uid = btree->index->desc.uid;
    btree_data.table_id = btree->index->desc.table_id;
    btree_data.index_id = btree->index->desc.id;
    btree_data.part_loc = part_loc;
    btree_data.is_shadow = btree->is_shadow;
    if (is_splitted) {
        btree_data.split_status = BTREE_IS_SPLITTED;
        SYNC_POINT_GLOBAL_START(CANTIAN_BTREE_SPLIT_BEFORE_BCAST_SPLITTED_ABORT, NULL, 0);
        SYNC_POINT_GLOBAL_END;
    } else if (btree->is_splitting) {
        btree_data.split_status = BTREE_IS_SPLITTING;
    } else {
        btree_data.split_status = BTREE_ABORT_SPLIT;
        SYNC_POINT_GLOBAL_START(CANTIAN_BTREE_SPLIT_BEFORE_BCAST_ABORT_SPLIT_ABORT, NULL, 0);
        SYNC_POINT_GLOBAL_END;
    }

    uint16 msg_size = sizeof(msg_broadcast_data_t) + sizeof(msg_broadcast_btree_data_t);
    mes_init_send_head(&bcast.head, MES_CMD_BROADCAST_DATA, msg_size, CT_INVALID_ID32, session->kernel->id,
                       CT_INVALID_ID8, session->id, CT_INVALID_ID16);
    bcast.type = BTREE_SPLITTING;

    knl_begin_session_wait(session, BROADCAST_BTREE_SPLIT, CT_TRUE);
    ret = mes_broadcast_bufflist_and_wait_with_retry(session->id, MES_BROADCAST_ALL_INST, &bcast.head,
        sizeof(msg_broadcast_data_t), (char *)&btree_data, BTREE_WAIT_ACK_TIMEOUT, BTREE_WAIT_ACK_RETRY_THRESHOLD);
        knl_end_session_wait(session, BROADCAST_BTREE_SPLIT);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR(
            "[DTC][dtc_broadcast_btree_split]: the other node is doing btree split, split status:%d, split owner:%u, "
            "wait ticks:%u, struct verion:%llu, uid/table_id/index_id/part/subpart:[%d-%d-%d-%u-%u]",
            btree_data.split_status, btree->split_owner, btree->wait_ticks, btree->struct_ver, btree_data.uid,
            btree_data.table_id, btree_data.index_id, btree_data.part_loc.part_no, btree_data.part_loc.subpart_no);
        return ret;
    }
    if (ret == CT_SUCCESS && btree->is_splitting) {
        SYNC_POINT_GLOBAL_START(CANTIAN_BTREE_SPLIT_AFTER_BCAST_SPLITTING_ABORT, NULL, 0);
        SYNC_POINT_GLOBAL_END;
    }
    btree->split_owner = btree->is_splitting ? session->kernel->id : CT_INVALID_ID8;

    CT_LOG_RUN_RET_INFO(
        ret,
        "[DTC][dtc_broadcast_btree_split]: split status:%d, split owner:%u, wait ticks:%u, struct version:%llu, ret=%d,"
        " uid/table_id/index_id/part/subpart:[%d-%d-%d-%u-%u]", btree_data.split_status, btree->split_owner,
        btree->wait_ticks, btree->struct_ver, ret, btree_data.uid, btree_data.table_id, btree_data.index_id,
        btree_data.part_loc.part_no, btree_data.part_loc.subpart_no);
    return ret;
}

status_t dtc_process_btree_splitting(knl_session_t *session, char *data, uint8 src_inst)
{
    msg_broadcast_btree_data_t *bcast = (msg_broadcast_btree_data_t *)data;
    knl_dictionary_t dc;

    if (knl_try_open_dc_by_id(session, bcast->uid, bcast->table_id, &dc) != CT_SUCCESS) {
        cm_reset_error();
        CT_LOG_RUN_ERR("[DTC] failed to open dc user id %u, table id %u, index id %u", bcast->uid, bcast->table_id,
                       bcast->index_id);
        return CT_ERROR;
    }

    dc_entity_t *entity = DC_ENTITY(&dc);
    if (entity == NULL) {
        cm_reset_error();
        CT_LOG_DEBUG_INF("[DTC] broadcast btree entity is null, uid/table_id/index_id/part/subpart:[%d-%d-%d-%u-%u]",
            bcast->uid, bcast->table_id, bcast->index_id, bcast->part_loc.part_no, bcast->part_loc.subpart_no);
        return CT_SUCCESS;
    }

    btree_t *btree = dc_get_btree_by_id(session, entity, bcast->index_id, bcast->part_loc, bcast->is_shadow);
    if (btree == NULL) {
        CT_LOG_RUN_ERR("[DTC] failed to get btree by id, part_no %u is_shadow %u, index id %u",
                       bcast->part_loc.part_no, bcast->is_shadow, bcast->index_id);
        dc_close(&dc);
        return CT_ERROR;
    }
    switch (bcast->split_status) {
        case BTREE_IS_SPLITTING:
            if (btree->is_splitting) {
                CT_LOG_RUN_ERR("[DTC] btree is splitting, split status:%d, split_owner:%u, wait ticks:%u, "
                               "struct version:%llu, uid/table_id/index_id/part/subpart:[%d-%d-%d-%u-%u]",
                               btree->is_splitting, btree->split_owner, btree->wait_ticks, btree->struct_ver,
                               bcast->uid, bcast->table_id, bcast->index_id, bcast->part_loc.part_no,
                               bcast->part_loc.subpart_no);
                dc_close(&dc);
                return CT_ERROR;
            }
            btree->is_splitting = CT_TRUE;
            btree->split_owner = src_inst;
            break;
        case BTREE_ABORT_SPLIT:
            btree->is_splitting = CT_FALSE;
            btree->split_owner = CT_INVALID_ID8;
            btree->wait_ticks = 0;
            break;
        case BTREE_IS_SPLITTED:
            btree->is_splitting = CT_FALSE;
            btree->split_owner = CT_INVALID_ID8;
            btree->wait_ticks = 0;
            int64 struct_ver = btree->struct_ver + 1;
            (void)cm_atomic_set(&btree->struct_ver, struct_ver);
            break;
        default:
            break;
    }

    dc_close(&dc);
    CT_LOG_DEBUG_WAR(
        "[DTC][dtc_process_btree_splitting]: uid/table_id/index_id/part/subpart:[%d-%d-%d-%u-%u], split status:%d, "
        "struct version:%llu, split_owner: %u", bcast->uid, bcast->table_id, bcast->index_id, bcast->part_loc.part_no,
        bcast->part_loc.subpart_no, bcast->split_status, btree->struct_ver, btree->split_owner);

    return CT_SUCCESS;
}

#define DTC_GET_BTREE_SPLIT_STATUS_TIMEOUT (1000)
status_t dtc_get_btree_split_status(knl_session_t *session, btree_t *btree, knl_part_locate_t part_loc,
                                    bool8 *is_splitting)
{
    msg_broadcast_data_t bcast;
    msg_broadcast_btree_data_t btree_data;

    btree_data.uid = btree->index->desc.uid;
    btree_data.table_id = btree->index->desc.table_id;
    btree_data.index_id = btree->index->desc.id;
    btree_data.part_loc = part_loc;
    btree_data.is_shadow = btree->is_shadow;
    btree_data.split_status = btree->is_splitting;

    uint16 msg_size = sizeof(msg_broadcast_data_t) + sizeof(msg_broadcast_btree_data_t);
    mes_init_send_head(&bcast.head, MES_CMD_BROADCAST_DATA, msg_size, CT_INVALID_ID32, session->kernel->id,
                       btree->split_owner, session->id, CT_INVALID_ID16);
    bcast.type = BTREE_SPLIT_STATUS;

    mes_message_t msg;
    if (mes_send_data3(&bcast.head, sizeof(msg_broadcast_data_t), (void *)&btree_data) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DTC] dtc_get_btree_split_status send message failed");
        return CT_ERROR;
    }

    if (mes_recv(session->id, &msg, CT_FALSE, CT_INVALID_ID32, DTC_GET_BTREE_SPLIT_STATUS_TIMEOUT) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DTC] dtc_get_btree_split_status get result timeout");
        return CT_ERROR;
    }

    if (SECUREC_UNLIKELY(msg.head->cmd != MES_CMD_BROADCAST_DATA_ACK)) {
        mes_release_message_buf(msg.buffer);
        return CT_ERROR;
    }

    msg_btree_split_status_t *split_ack = (msg_btree_split_status_t *)(msg.buffer);
    *is_splitting = split_ack->is_splitting;
    mes_release_message_buf(msg.buffer);

    CT_LOG_DEBUG_INF("[DTC][get btree split status]: uid/table_id/part/subpart:[%d-%d-%u-%u], split_owner:%d, "
        "split_status:%d, struct version:%llu, result split status:%d", btree_data.uid, btree_data.table_id,
        btree_data.index_id, btree_data.part_loc.part_no, btree->split_owner, btree->is_splitting, btree->struct_ver,
        *is_splitting);
    return CT_SUCCESS;
}

void dtc_process_btree_split_status(knl_session_t *session, mes_message_t *req_msg, char *data)
{
    msg_broadcast_btree_data_t *bcast = (msg_broadcast_btree_data_t *)data;
    msg_btree_split_status_t msg;
    knl_dictionary_t dc;
    if (knl_try_open_dc_by_id(session, bcast->uid, bcast->table_id, &dc) != CT_SUCCESS) {
        cm_reset_error();
        CT_LOG_RUN_ERR("[DTC] failed to open dc user id %u, table id %u, index id %u", bcast->uid, bcast->table_id,
                       bcast->index_id);
        CM_ASSERT(0);
        mes_release_message_buf(req_msg->buffer);
        return;
    }

    dc_entity_t *entity = DC_ENTITY(&dc);
    if (entity == NULL) {
        cm_reset_error();
        CT_LOG_RUN_WAR("[DTC] broadcast btree entity is null, uid/table_id/index_id/part/subpart:[%d-%d-%d-%u-%u]",
                       bcast->uid, bcast->table_id, bcast->index_id, bcast->part_loc.part_no,
                       bcast->part_loc.subpart_no);
        msg.split_owner = CT_INVALID_ID8;
        msg.is_splitting = CT_FALSE;
    } else {
        btree_t *btree = dc_get_btree_by_id(session, entity, bcast->index_id, bcast->part_loc, bcast->is_shadow);
        if (btree == NULL) {
            CT_LOG_RUN_ERR("[DTC] failed to get btree by id, part_no %u is_shadow %u, index id %u",
                           bcast->part_loc.part_no, bcast->is_shadow, bcast->index_id);
            dc_close(&dc);
            mes_release_message_buf(req_msg->buffer);
            return;
        }
        msg.split_owner = btree->split_owner;
        msg.is_splitting = btree->is_splitting;
        dc_close(&dc);
    }
    mes_init_ack_head(req_msg->head, &msg.head, MES_CMD_BROADCAST_DATA_ACK,
                      sizeof(msg_btree_split_status_t), session->id);
    mes_release_message_buf(req_msg->buffer);
    if (mes_send_data(&msg) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DTC DC] failed to send split btree status,");
        return;
    }
}

void dtc_broadcast_data_send_status_ack(knl_session_t *session, mes_message_t *msg)
{
    mes_message_head_t ack_head = {0};

    mes_init_ack_head(msg->head, &ack_head, MES_CMD_BROADCAST_ACK, sizeof(mes_message_head_t), session->id);

    mes_release_message_buf(msg->buffer);

    status_t ret = CT_SUCCESS;
    SYNC_POINT_GLOBAL_START(CANTIAN_DTC_BCAST_ACK_FAIL, &ret, CT_ERROR);
    ret = mes_send_data(&ack_head);
    SYNC_POINT_GLOBAL_END;
    if (ret != CT_SUCCESS) {
        CT_LOG_DEBUG_ERR("[DTC] failed to send broadcast ack msg: cmd=%u, dest_id=%u, dest_sid=%u",
                         ack_head.cmd, ack_head.dst_inst, ack_head.dst_sid);
    }
}
status_t dtc_broadcast_heap_extend(knl_session_t *session, heap_t *heap, knl_part_locate_t part_loc)
{
    status_t ret = CT_SUCCESS;
    msg_broadcast_data_t bcast;
    msg_broadcast_heap_data_t heap_data;

    heap_data.uid = heap->table->desc.uid;
    heap_data.table_id = heap->table->desc.id;
    heap_data.part_loc = part_loc;
    heap_data.extending = heap->extending;
    heap_data.compacting = heap->compacting;

    uint16 msg_size = sizeof(msg_broadcast_data_t) + sizeof(msg_broadcast_heap_data_t);
    mes_init_send_head(&bcast.head, MES_CMD_BROADCAST_DATA, msg_size, CT_INVALID_ID32, session->kernel->id,
                       CT_INVALID_ID8, session->id, CT_INVALID_ID16);
    bcast.type = HEAP_EXTEND;

    ret = mes_broadcast_bufflist_and_wait_with_retry(session->id, MES_BROADCAST_ALL_INST, &bcast.head,
        sizeof(msg_broadcast_data_t), (char *)&heap_data, HEAP_WAIT_ACK_TIMEOUT, HEAP_WAIT_ACK_RETRY_THRESHOLD);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR(
            "[DTC][broadcast heap extend] the other node is doing heap extend, extend status:%d, compacting:%d, "
            "extend owner:%d, wait tickes:%u, uid/table_id/part/subpart:[%d-%d-%u-%u]", heap_data.extending,
            heap_data.compacting, heap->extend_owner, heap->wait_ticks, heap_data.uid, heap_data.table_id,
            part_loc.part_no, part_loc.subpart_no);
        return ret;
    }

    heap->extend_owner = heap->extending ? session->kernel->id : CT_INVALID_ID8;
    CT_LOG_RUN_RET_INFO(
        ret,
        "[DTC][broadcast heap extend] extend status:%d, compacting:%d, extend owner:%d, wait tickes:%u, ret:%d, "
        "uid/table_id/part/subpart:[%d-%d-%u-%u]", heap_data.extending, heap_data.compacting, heap->extend_owner,
        heap->wait_ticks, ret, heap_data.uid, heap_data.table_id, part_loc.part_no, part_loc.subpart_no);
    return ret;
}

status_t dtc_process_heap_extend(knl_session_t *session, char *data, uint8 src_inst)
{
    msg_broadcast_heap_data_t *bcast = (msg_broadcast_heap_data_t *)data;
    knl_dictionary_t dc;
    dc_entity_t *entity = NULL;
    heap_t *heap = NULL;

    SYNC_POINT_GLOBAL_START(CANTIAN_HEAP_EXTEND_PROC_BCAST_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;

    if (knl_try_open_dc_by_id(session, bcast->uid, bcast->table_id, &dc) != CT_SUCCESS) {
        cm_reset_error();
        CT_LOG_RUN_ERR("[DTC] process heap extend, failed to open dc user id %u, table id %u",
                       bcast->uid, bcast->table_id);
        CM_ASSERT(0);
        return CT_SUCCESS;
    }

    entity = DC_ENTITY(&dc);
    if (entity == NULL) {
        cm_reset_error();
        CT_LOG_DEBUG_INF("[DTC] broadcast heap extend entity is null, uid/table_id/part/subpart:[%d-%d-%u-%u]",
            bcast->uid, bcast->table_id, bcast->part_loc.part_no, bcast->part_loc.subpart_no);
        return CT_SUCCESS;
    }

    heap = dc_get_heap_by_entity(session, bcast->part_loc, entity);
    if (heap == NULL) {
        CT_LOG_RUN_ERR("[DTC] process heap extend failed to get heap, uid/table_id/part/subpart:[%d-%d-%u-%u]",
                       bcast->uid, bcast->table_id, bcast->part_loc.part_no, bcast->part_loc.subpart_no);
        dc_close(&dc);
        return CT_ERROR;
    }
    if (bcast->extending == CT_TRUE && heap->extending) {
        CT_LOG_RUN_ERR(
            "[DTC][process_heap_extend] current node is doing heap extend, uid/table_id/part/subpart:[%d-%d-%u-%u], "
            "extending:%d, compacting:%d, extend owner:%d, wait ticks:%u", bcast->uid, bcast->table_id,
            bcast->part_loc.part_no, bcast->part_loc.subpart_no, bcast->extending, bcast->compacting,
            heap->extend_owner, heap->wait_ticks);
        dc_close(&dc);
        return CT_ERROR;
    }
    heap->extending = bcast->extending;
    heap->compacting = bcast->compacting;
    heap->extend_owner = heap->extending ? src_inst : CT_INVALID_ID8;
    heap->wait_ticks = heap->extending ? 0 : heap->wait_ticks;
    dc_close(&dc);
    CT_LOG_DEBUG_INF(
        "[DTC][process_heap_extend]: uid/table_id/part/subpart:[%d-%d-%u-%u], extending:%d, compacting:%d, owner:%d",
        bcast->uid, bcast->table_id, bcast->part_loc.part_no, bcast->part_loc.subpart_no, bcast->extending,
        bcast->compacting, heap->extend_owner);
    return CT_SUCCESS;
}

#define DTC_GET_HEAP_EXTEND_STATUS_TIMEOUT (1000)
status_t dtc_get_heap_extend_status(knl_session_t *session, heap_t *heap, knl_part_locate_t part_loc, bool8 *extending)
{
    msg_broadcast_data_t bcast;
    msg_broadcast_heap_data_t heap_data;

    heap_data.uid = heap->table->desc.uid;
    heap_data.table_id = heap->table->desc.id;
    heap_data.part_loc = part_loc;
    heap_data.extending = heap->extending;
    heap_data.compacting = heap->compacting;

    uint16 msg_size = sizeof(msg_broadcast_data_t) + sizeof(msg_broadcast_heap_data_t);
    mes_init_send_head(&bcast.head, MES_CMD_BROADCAST_DATA, msg_size, CT_INVALID_ID32, session->kernel->id,
                       heap->extend_owner, session->id, CT_INVALID_ID16);
    bcast.type = HEAP_EXTEND_STATUS;

    mes_message_t  msg;

    if (mes_send_data3(&bcast.head, sizeof(msg_broadcast_data_t), (void *)&heap_data) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DTC] dtc_get_heap_extend_status failed");
        return CT_ERROR;
    }

    if (mes_recv(session->id, &msg, CT_FALSE, CT_INVALID_ID32, DTC_GET_HEAP_EXTEND_STATUS_TIMEOUT) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DTC] dtc_get_heap_extend_status get result timeout");
        return CT_ERROR;
    }

    if (SECUREC_UNLIKELY(msg.head->cmd != MES_CMD_BROADCAST_DATA_ACK)) {
        mes_release_message_buf(msg.buffer);
        return CT_ERROR;
    }

    msg_heap_extend_status_t *extend_ack = (msg_heap_extend_status_t *)(msg.buffer);
    *extending = extend_ack->is_extending;
    mes_release_message_buf(msg.buffer);

    CT_LOG_DEBUG_INF("[DTC][get heap extend status]: uid/table_id/part/subpart:[%d-%d-%u-%u], "
        "exend owner=%d, result extending:%d",
        heap_data.uid, heap_data.table_id, part_loc.part_no, part_loc.subpart_no, heap->extend_owner, *extending);
    return CT_SUCCESS;
}

void dtc_process_heap_extend_status(knl_session_t *session, mes_message_t *req_msg, char *data)
{
    msg_broadcast_heap_data_t *bcast = (msg_broadcast_heap_data_t *)data;
    knl_dictionary_t dc;
    if (knl_try_open_dc_by_id(session, bcast->uid, bcast->table_id, &dc) != CT_SUCCESS) {
        cm_reset_error();
        CT_LOG_RUN_ERR("[DTC] process heap extend, failed to open dc user id %u, table id %u",
                       bcast->uid, bcast->table_id);
        mes_release_message_buf(req_msg->buffer);
        return;
    }

    msg_heap_extend_status_t msg;
    dc_entity_t *entity = DC_ENTITY(&dc);
    if (entity == NULL) {
        cm_reset_error();
        CT_LOG_RUN_WAR("[DTC] broadcast heap extend entity is null, uid/table_id/part/subpart:[%d-%d-%u-%u]",
                       bcast->uid, bcast->table_id, bcast->part_loc.part_no, bcast->part_loc.subpart_no);
        msg.is_extending = CT_FALSE;
        msg.extend_owner = CT_INVALID_ID8;
    } else {
        heap_t *heap = dc_get_heap_by_entity(session, bcast->part_loc, entity);
        if (heap == NULL) {
            CT_LOG_RUN_ERR("[DTC] process heap extend failed to get heap, uid/table_id/part/subpart:[%d-%d-%u-%u]",
                           bcast->uid, bcast->table_id, bcast->part_loc.part_no, bcast->part_loc.subpart_no);
            dc_close(&dc);
            mes_release_message_buf(req_msg->buffer);
            return;
        }
        msg.is_extending = heap->extending;
        msg.extend_owner = heap->extend_owner;
        CT_LOG_DEBUG_INF(
            "[DTC][heap_extend_status]: uid/table_id/part/subpart:[%d-%d-%u-%u], extending:%d, compacting:%d, owner:%d",
            bcast->uid, bcast->table_id, bcast->part_loc.part_no, bcast->part_loc.subpart_no, bcast->extending,
            bcast->compacting, heap->extend_owner);
        dc_close(&dc);
    }
    mes_init_ack_head(req_msg->head, &msg.head, MES_CMD_BROADCAST_DATA_ACK,
                      sizeof(msg_heap_extend_status_t), session->id);
    mes_release_message_buf(req_msg->buffer);
    if (mes_send_data(&msg) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DTC DC] failed to send heap extend status,");
        return;
    }
}


void dtc_broadcast_user_status(knl_session_t *session, uint32 uid, user_status_t status)
{
    if (!DB_IS_CLUSTER(session)) {
        return;
    }

    msg_broadcast_data_t bcast;
    msg_broadcast_user_data_t user_data;

    bcast.type = USER_STATUS;
    user_data.uid = uid;
    user_data.status = status;
    if (status == USER_STATUS_LOCKED) {
        user_data.user_locked_owner = session->kernel->id;
    } else {
        user_data.user_locked_owner = CT_INVALID_ID32;
    }

    mes_init_send_head(&bcast.head, MES_CMD_BROADCAST_USER,
                       sizeof(msg_broadcast_data_t) + sizeof(msg_broadcast_user_data_t), CT_INVALID_ID32,
                       session->kernel->id, CT_INVALID_ID8, session->id, CT_INVALID_ID16);

    mes_broadcast_data3(session->id, &bcast.head, sizeof(msg_broadcast_data_t), (char *)&user_data);
    mes_wait_acks(session->id, MES_WAIT_MAX_TIME);
    return;
}


void dtc_process_user_status(knl_session_t * session, char *data)
{
    msg_broadcast_user_data_t *user_data = (msg_broadcast_user_data_t*)data;
    dc_user_t* user = NULL;

    if (dtc_modify_drop_uid(session, user_data->uid) != CT_SUCCESS ||
        dc_open_user_by_id(session, user_data->uid, &user) != CT_SUCCESS) {
        cm_reset_error();
        CT_LOG_RUN_ERR("[DDL] failed to open user id %u", user_data->uid);
        CM_ASSERT(0);
        return;
    }

    user->status = user_data->status;
    if (user->status == USER_STATUS_NORMAL) {
        session->drop_uid = CT_INVALID_ID32;
        user->user_locked_owner = CT_INVALID_ID32;
        SYNC_POINT_GLOBAL_START(CANTIAN_DROP_USER_LOCK_PROC_BCAST_ABORT, NULL, 0);
        SYNC_POINT_GLOBAL_END;
    } else {
        session->drop_uid = user_data->uid;
        user->user_locked_owner = user_data->user_locked_owner;
        SYNC_POINT_GLOBAL_START(CANTIAN_DROP_USER_REVERT_NORMAL_PROC_BCAST_ABORT, NULL, 0);
        SYNC_POINT_GLOBAL_END;
    }
    SYNC_POINT_GLOBAL_START(CANTIAN_SET_USER_STATS_ACK_TIMEOUT, NULL, 5000); // delay 5000ms
    SYNC_POINT_GLOBAL_END;
}

void dtc_broadcast_invalidate_dc(knl_session_t * session, uint32 uid, uint32 oid)
{
    SYNC_POINT_GLOBAL_START(CANTIAN_INVALID_DC_BEFORE_BCAST_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;

    msg_broadcast_data_t bcast;
    msg_broadcast_invalidate_dc_t dc_info;
    bcast.type = INVALIDATE_DC;
    dc_info.uid = uid;
    dc_info.oid = oid;
    mes_init_send_head(&bcast.head, MES_CMD_BROADCAST_INVALIDATE_DC,
                       sizeof(msg_broadcast_data_t) + sizeof(msg_broadcast_invalidate_dc_t), CT_INVALID_ID32,
                       session->kernel->id, CT_INVALID_ID8, session->id, CT_INVALID_ID16);

    mes_broadcast_data3(session->id, &bcast.head, sizeof(msg_broadcast_data_t), (char*)&dc_info);
    mes_wait_acks(session->id, MES_WAIT_MAX_TIME);
    return;
}

void dtc_process_invalidate_dc(knl_session_t* session, char* data)
{
    msg_broadcast_invalidate_dc_t* dc_info = (msg_broadcast_invalidate_dc_t*)data;
    knl_dictionary_t dc;

    if (knl_try_open_dc_by_id(session, dc_info->uid, dc_info->oid, &dc) != CT_SUCCESS) {
        cm_reset_error();
        CT_LOG_RUN_ERR("[DC] failed to open dc user id %u, table id %u for invalidate dc", dc_info->uid, dc_info->oid);
        return;
    }
    dc_entity_t *entity = DC_ENTITY(&dc);
    if (entity == NULL) {
        cm_reset_error();
        CT_LOG_RUN_WAR("[DC] process dtc invalidate dc, dc not loaded, dc user id %u, table id %u",
            dc_info->uid, dc_info->oid);
        return;
    }
    CT_LOG_DEBUG_INF("invalidate dc: uid: %u, tid: %u, valid: %u", dc_info->uid, dc_info->oid, DC_ENTITY(&dc)->valid);
    dc_invalidate(session, entity);
    dc_close(&dc);
}

status_t dtc_remove_df_watch(knl_session_t *session, uint32 df_id)
{
    status_t ret = CT_SUCCESS;
    msg_broadcast_data_t bcast;

    uint16 msg_size = sizeof(msg_broadcast_data_t) + sizeof(uint32);
    mes_init_send_head(&bcast.head, MES_CMD_BROADCAST_DATA, msg_size, CT_INVALID_ID32, session->kernel->id,
                       CT_INVALID_ID8, session->id, CT_INVALID_ID16);
    bcast.type = REMOVE_DF_WATCH;

    ret = mes_broadcast_bufflist_and_wait_with_retry(session->id, MES_BROADCAST_ALL_INST, &bcast.head,
        sizeof(msg_broadcast_data_t), (char *)&df_id,
        DTC_WAIT_MES_TIMEOUT, DTC_MAX_RETRY_TIEMS);
    CT_LOG_RUN_INF("[DTC][dtc_remove_df_watch]: the other node returns ret: %u", ret);
    return ret;
}

status_t dtc_process_remove_df_watch(knl_session_t* session, char* data)
{
    uint32* df_id = (uint32*)data;
    CT_LOG_RUN_INF("[DTC][dtc_process_remove_df_watch]: remove device watch for df %u", *df_id);
    rmon_t *rmon_ctx = &(session->kernel->rmon_ctx);
    datafile_t *df = DATAFILE_GET(session, *df_id);
    if (cm_exist_device(df->ctrl->type, df->ctrl->name)) {
        if (cm_rm_device_watch(df->ctrl->type, rmon_ctx->watch_fd, &df->wd) != CT_SUCCESS) {
            CT_LOG_RUN_WAR("[RMON]: failed to remove monitor of datafile %s on remote node", df->ctrl->name);
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

void dtc_broadcast_data_send_ack(knl_session_t *session, mes_message_t *msg, status_t process_ret)
{
    mes_message_head_t ack_head = {0};

    mes_init_ack_head(msg->head, &ack_head, MES_CMD_BROADCAST_ACK, sizeof(mes_message_head_t), session->id);
    ack_head.status = process_ret;

    mes_release_message_buf(msg->buffer);

    status_t ret = CT_SUCCESS;
    SYNC_POINT_GLOBAL_START(CANTIAN_DTC_BCAST_ACK_FAIL, &ret, CT_ERROR);
    ret = mes_send_data(&ack_head);
    SYNC_POINT_GLOBAL_END;
    if (ret != CT_SUCCESS) {
        CT_LOG_DEBUG_ERR("[DTC] failed to send broadcast ack msg: cmd=%u, dest_id=%u, dest_sid=%u",
                         ack_head.cmd, ack_head.dst_inst, ack_head.dst_sid);
    }
}

void dtc_process_broadcast_data(void *sess, mes_message_t * msg)
{
    if (sizeof(msg_broadcast_data_t) > msg->head->size) {
        CT_LOG_RUN_ERR("[DTC] process broadcast data, msg size is invalid, size=%u", msg->head->size);
        mes_release_message_buf(msg->buffer);
        return;
    }
    msg_broadcast_data_t *bcast = (msg_broadcast_data_t *)msg->buffer;
    knl_session_t *session = (knl_session_t *)sess;
    status_t ret = CT_SUCCESS;

    if (!DC_IS_READY(session)) {
        CT_LOG_RUN_INF("[DTC] process broadcast data, dc not ready, status=%d", DB_STATUS(session));
        dtc_broadcast_data_send_ack(session, msg, ret);
        return;
    }

    switch (bcast->type) {
        case BTREE_SPLITTING:
            if (sizeof(msg_broadcast_data_t) + sizeof(msg_broadcast_btree_data_t) != msg->head->size) {
                CT_LOG_RUN_ERR("[DTC] btree splitting, msg size is invalid, size=%u", msg->head->size);
                return;
            }
            ret = dtc_process_btree_splitting(session, (char*)bcast + sizeof(msg_broadcast_data_t),
                                              bcast->head.src_inst);
            break;
        case BTREE_SPLIT_STATUS:
            if (sizeof(msg_broadcast_data_t) + sizeof(msg_broadcast_btree_data_t) != msg->head->size) {
                CT_LOG_RUN_ERR("[DTC] btree split status, msg size is invalid, size=%u", msg->head->size);
                return;
            }
            dtc_process_btree_split_status(session, msg, (char*)bcast + sizeof(msg_broadcast_data_t));
            return;
        case HEAP_EXTEND:
            if (sizeof(msg_broadcast_data_t) + sizeof(msg_broadcast_heap_data_t) != msg->head->size) {
                CT_LOG_RUN_ERR("[DTC] heap extend, msg size is invalid, size=%u", msg->head->size);
                return;
            }
            ret = dtc_process_heap_extend(session, (char*)bcast + sizeof(msg_broadcast_data_t), bcast->head.src_inst);
            break;
        case HEAP_EXTEND_STATUS:
            if (sizeof(msg_broadcast_data_t) + sizeof(msg_broadcast_heap_data_t) != msg->head->size) {
                CT_LOG_RUN_ERR("[DTC] heap extend status, msg size is invalid, size=%u", msg->head->size);
                return;
            }
            dtc_process_heap_extend_status(session, msg, (char*)bcast + sizeof(msg_broadcast_data_t));
            return;
        case USER_STATUS:
            if (sizeof(msg_broadcast_data_t) + sizeof(msg_broadcast_user_data_t) != msg->head->size) {
                CT_LOG_RUN_ERR("[DTC] user status, msg size is invalid, size=%u", msg->head->size);
                return;
            }
            dtc_process_user_status(session, (char*)bcast + sizeof(msg_broadcast_data_t));
            break;
        case INVALIDATE_DC:
            if (sizeof(msg_broadcast_data_t) + sizeof(msg_broadcast_invalidate_dc_t) != msg->head->size) {
                CT_LOG_RUN_ERR("[DTC] invalidate dc, msg size is invalid, size=%u", msg->head->size);
                return;
            }
            dtc_process_invalidate_dc(session, (char*)bcast + sizeof(msg_broadcast_data_t));
            break;
        case USER_LOCK_STATUS:
            if (sizeof(msg_broadcast_data_t) + sizeof(msg_broadcast_user_data_t) != msg->head->size) {
                CT_LOG_RUN_ERR("[DTC] btree splitting, msg size is invalid, size=%u", msg->head->size);
                return;
            }
            dtc_process_get_user_lock_status(session, msg, (char*)bcast + sizeof(msg_broadcast_data_t));
            return;
        case REMOVE_DF_WATCH:
            if (sizeof(msg_broadcast_data_t) + sizeof(uint32) != msg->head->size) {
                CT_LOG_RUN_ERR("[DTC] remove datafile device watch, msg size is invalid, size=%u", msg->head->size);
                return;
            }
            ret = dtc_process_remove_df_watch(session, (char*)bcast + sizeof(msg_broadcast_data_t));
            break;
        default:
            CT_LOG_RUN_ERR("[DTC] process broadcast data, type is invalid, type=%d", bcast->type);
            return;
    }

    dtc_broadcast_data_send_ack(session, msg, ret);
}

status_t dtc_sync_upgrade_ctrl_version(knl_handle_t knl_session)
{
    knl_session_t *session = (knl_session_t *)knl_session;
    msg_broadcast_upgrade_version_t msg;
    msg.version = DB_CORE_CTRL(session)->version;

    mes_init_send_head(&msg.head, MES_CMD_UPGRADE_CTRL_VERSION,
        (uint16)(sizeof(msg_broadcast_upgrade_version_t) + sizeof(ctrl_version_t)),
        CT_INVALID_ID32, session->kernel->dtc_attr.inst_id, 0, session->id, CT_INVALID_ID16);

    uint64 target_bits = 0;
    status_t status = dtc_get_alive_bitmap(&target_bits);
    if (status != CT_SUCCESS) {
        return status;
    }
    SYNC_POINT_GLOBAL_START(CANTIAN_UPGRADE_CTRL_VERSION_SEND_SYNC_FAIL, &status, CT_ERROR);
    status = mes_broadcast_bufflist_and_wait_with_retry(session->id, target_bits, &msg.head,
        sizeof(msg_broadcast_upgrade_version_t), (char *)&(msg.version), UPGRADE_VERSION_WAIT_MES_TIMEOUT,
        UPGRADE_VERSION_MAX_RETRY_TIEMS);
    SYNC_POINT_GLOBAL_END;
    return status;
}

void dtc_process_upgrade_ctrl_version(void *sess, mes_message_t * msg)
{
    msg_broadcast_upgrade_version_t *bcast = (msg_broadcast_upgrade_version_t *)msg->buffer;
    knl_session_t *session = (knl_session_t *)sess;
    status_t process_ret = CT_SUCCESS;
    ctrl_version_t version = bcast->version;
    if (db_cur_ctrl_version_is_higher(session, version)) {
        CT_LOG_RUN_ERR("[SYNC UPGARDE] current version is higher than %hu-%hu-%hu-%hu",
                       version.main, version.major, version.revision, version.inner);
        process_ret = CT_ERROR;
    } else {
        if (db_equal_to_cur_ctrl_version(session, version)) {
            CT_LOG_RUN_WAR("[SYNC UPGARDE] current version is equal to %hu-%hu-%hu-%hu, no need to upgrade",
                           version.main, version.major, version.revision, version.inner);
        } else {
            DB_CORE_CTRL(session)->version = version;
        }
    }

    mes_message_head_t ack_head = {0};
    mes_init_ack_head(msg->head, &ack_head, MES_CMD_UPGRADE_CTRL_VERSION_ACK, sizeof(mes_message_head_t), session->id);
    ack_head.status = process_ret;
    mes_release_message_buf(msg->buffer);

    status_t ret = CT_SUCCESS;
    SYNC_POINT_GLOBAL_START(CANTIAN_UPGRADE_CTRL_VERSION_SEND_ACK_FAIL, &ret, CT_ERROR);
    ret = mes_send_data(&ack_head);
    SYNC_POINT_GLOBAL_END;
    if (ret != CT_SUCCESS) {
        CT_LOG_DEBUG_ERR("[SYNC UPGARDE] failed to send broadcast ack msg: cmd=%u, dest_id=%u, dest_sid=%u",
                         ack_head.cmd, ack_head.dst_inst, ack_head.dst_sid);
    } else {
        CT_LOG_RUN_INF("[SYNC UPGARDE] Success to upgrade ctrl version to %hu-%hu-%hu-%hu",
                       version.main, version.major, version.revision, version.inner);
    }
}

status_t dtc_ddl_enabled(knl_handle_t knl_session, bool32 forbid_in_rollback)
{
    knl_session_t *session = (knl_session_t *)knl_session;
    if (!DB_IS_CLUSTER(session) || session->bootstrap) {
        return CT_SUCCESS;
    }
    if (RC_REFORM_IN_PROGRESS) {
        CT_LOG_RUN_WAR("reform is preparing, refuse to ddl operation");
        CT_THROW_ERROR(ERR_CLUSTER_DDL_DISABLED, "reform is preparing");
        return CT_ERROR;
    }
    CT_LOG_DEBUG_INF("dtc check ddl enabled");
    mes_message_head_t head;
    mes_init_send_head(&head, MES_CMD_CHECK_DDL_ENABLED, sizeof(mes_message_head_t) + sizeof(bool32), CT_INVALID_ID32,
        session->kernel->dtc_attr.inst_id, 0, session->id, CT_INVALID_ID16);
    uint64 target_bits = 0;
    status_t status = dtc_get_alive_bitmap(&target_bits);
    if (status != CT_SUCCESS) {
        return status;
    }
    mes_broadcast_bufflist_with_retry(session->id, target_bits, &head, sizeof(mes_message_head_t), log);
    status = mes_wait_acks(session->id, MES_WAIT_MAX_TIME);
    if (status != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DDL] recv check ddl enabled failed from instance");
    }
    return status;
}

void dtc_process_check_ddl_enabled(void *sess, mes_message_t *msg)
{
    knl_session_t *session = (knl_session_t *)sess;
    mes_message_head_t ack_head;
    if (sizeof(mes_message_head_t) + sizeof(bool32) != msg->head->size) {
        CT_LOG_RUN_ERR("msg is invalid, msg size %u.", msg->head->size);
        mes_release_message_buf(msg->buffer);
        return;
    }
    bool32 forbid_in_rollback = *(bool32 *)(msg->buffer + sizeof(mes_message_head_t));
    ddl_exec_status_t ddl_exec_stat;
    status_t ddl_status = knl_ddl_execute_status(session, forbid_in_rollback, &ddl_exec_stat);

    mes_init_ack_head(msg->head, &ack_head, MES_CMD_CHECK_DDL_ENABLED_ACK, (sizeof(mes_message_head_t) + sizeof(status_t)), session->id);

    mes_release_message_buf(msg->buffer);
    if (mes_send_data2(&ack_head, &ddl_status) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DDL] send check ddl enabled ack failed");
        return;
    }
}

inline status_t db_write_ddl_op(knl_session_t *session)
{
    // Before sync ddl will write system table, used for recover sync ddl when node crashed.
    // Maybe extend data file during this process, will rewrite the logic log buf.
    return CT_SUCCESS;
}

status_t db_write_ddl_op_internal(knl_session_t* session, char *log, uint32 log_size)
{
    knl_cursor_t* cursor = NULL;
    row_assist_t ra;
    uint32 max_size = session->kernel->attr.max_row_size;
    knl_column_t* lob_column = NULL;
    binary_t log_bin;

    if (!DB_IS_CLUSTER(session) || (DB_STATUS(session) != DB_STATUS_OPEN)) {
        cm_reset_error();
        return CT_SUCCESS;
    }

    knl_panic(log_size < KNL_LOGIC_LOG_BUF_SIZE && log_size > LOG_ENTRY_SIZE);

    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_CLUSTER_DDL_TABLE, IX_SYS_CLUSTER_DDL_TABLE_001_ID);
    row_init(&ra, (char*)cursor->row, max_size, SYS_CLUSTER_DDL_OP_COLS);
    (void)row_put_int32(&ra, session->id);
    (void)row_put_int64(&ra, DB_CURR_LSN(session));

    lob_column = knl_get_column(cursor->dc_entity, SYS_CLUSTER_DDL_TABLE_LOB_ID);
    log_bin.bytes = (uint8 *)log;
    log_bin.size = log_size;
    if (knl_row_put_lob(session, cursor, lob_column, &log_bin, &ra) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (knl_internal_insert(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    session->logic_log_num++;
    return CT_SUCCESS;
}


status_t db_write_ddl_op_for_parents(knl_session_t* session, table_t* table)
{
    char* buf = NULL;
    ref_cons_t* ref = NULL;
    uint32 i;

    if (!DB_IS_CLUSTER(session) || (DB_STATUS(session) != DB_STATUS_OPEN)) {
        cm_reset_error();
        return CT_SUCCESS;
    }

    for (i = 0; i < table->cons_set.ref_count; i++) {
        ref = table->cons_set.ref_cons[i];

        if (ref->ref_uid == table->desc.uid && ref->ref_oid == table->desc.id) {
            continue;
        }

        CM_SAVE_STACK(session->stack);
        rd_table_t rd_altable;
        rd_altable.op_type = RD_ALTER_TABLE;
        rd_altable.uid = table->desc.uid;
        rd_altable.oid = table->desc.id;
        buf = dtc_push_ddl_redo(session, (char*)&rd_altable, sizeof(rd_altable));
        if (db_write_ddl_op_internal(session, buf, ((log_entry_t*)buf)->size) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            CT_LOG_DEBUG_ERR("[DDL]failed to write cluster ddl op for parent table (%d:%d).", ref->ref_uid, ref->ref_oid);
            return CT_ERROR;
        }
        CM_RESTORE_STACK(session->stack);
    }
    return CT_SUCCESS;
}

status_t db_write_ddl_op_for_constraints(knl_session_t* session, uint32 uid, uint32 id, galist_t* constraints)
{
    knl_constraint_def_t* cons = NULL;
    knl_reference_def_t *ref = NULL;
    uint32 i;

    if (!DB_IS_CLUSTER(session) || (DB_STATUS(session) != DB_STATUS_OPEN)) {
        cm_reset_error();
        return CT_SUCCESS;
    }

    for (i = 0; i < constraints->count; i++) {
        cons = (knl_constraint_def_t*)cm_galist_get(constraints, i);
        if (cons->type != CONS_TYPE_REFERENCE) {
            continue;
        }

        ref = &cons->ref;
        knl_dictionary_t* dc = &ref->ref_dc;
        if (dc->handle != NULL) {
            CM_SAVE_STACK(session->stack);
            rd_table_t rd_altable;
            rd_altable.op_type = RD_ALTER_TABLE;
            rd_altable.uid = dc->uid;
            rd_altable.oid = dc->oid;
            char* buf = dtc_push_ddl_redo(session, (char*)&rd_altable, sizeof(rd_altable));
            if (db_write_ddl_op_internal(session, buf, ((log_entry_t*)buf)->size) != CT_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                CT_LOG_DEBUG_ERR("[DDL]failed to write cluster ddl op for cons table (%d:%d).", dc->uid, dc->oid);
                knl_panic(0);
            }
            CM_RESTORE_STACK(session->stack);
        }
    }
    return CT_SUCCESS;
}


status_t db_write_ddl_op_for_children(knl_session_t* session, table_t* table)
{
    index_t* index = NULL;
    cons_dep_t* dep = NULL;
    uint32 i;

    if (!DB_IS_CLUSTER(session) || (DB_STATUS(session) != DB_STATUS_OPEN)) {
        cm_reset_error();
        return CT_SUCCESS;
    }

    if (table->index_set.count == 0) {
        return CT_SUCCESS;
    }

    for (i = 0; i < table->index_set.count; i++) {
        index = table->index_set.items[i];
        if (index->dep_set.count == 0) {
            continue;
        }

        /* if table is referenced by another table */
        dep = index->dep_set.first;
        while (dep != NULL) {
            if (dep->uid == table->desc.uid && dep->oid == table->desc.id) {
                dep = dep->next;
                continue;
            }

            CM_SAVE_STACK(session->stack);
            rd_table_t rd_altable;
            rd_altable.op_type = RD_ALTER_TABLE;
            rd_altable.uid = dep->uid;
            rd_altable.oid = dep->oid;
            char *buf = dtc_push_ddl_redo(session, (char*)&rd_altable, sizeof(rd_altable));
            if (db_write_ddl_op_internal(session, buf, ((log_entry_t*)buf)->size) != CT_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                CT_LOG_DEBUG_ERR("[DDL]failed to write cluster ddl op for child table (%d:%d).", dep->uid, dep->oid);
                knl_panic(0);
            }
            CM_RESTORE_STACK(session->stack);

            dep = dep->next;
        }
    }
    return CT_SUCCESS;
}

static inline void db_convert_ddl_op_desc(knl_session_t *session, knl_cursor_t* cursor, ddl_op_desc_t* desc)
{
    char* lob = NULL;

    desc->sid = *(uint32*)CURSOR_COLUMN_DATA(cursor, 0);
    desc->lsn = *(uint32*)CURSOR_COLUMN_DATA(cursor, 1);
    desc->logic_log = (char*)cm_push(session->stack, KNL_LOGIC_LOG_BUF_SIZE);
    lob = CURSOR_COLUMN_DATA(cursor, SYS_CLUSTER_DDL_TABLE_LOB_ID);
    if (knl_read_lob(session, lob, 0, desc->logic_log, KNL_LOGIC_LOG_BUF_SIZE, &desc->log_size, NULL) != CT_SUCCESS) {
        knl_panic(0);
    }
    knl_panic(desc->log_size < KNL_LOGIC_LOG_BUF_SIZE);
}

status_t db_clean_ddl_op(knl_session_t *session, clean_ddl_op_t clean_op)
{
    while (!DB_IS_OPEN(session) && clean_op == DDL_REFORM_REPLAY) {
        CT_RETVALUE_IFTRUE(rc_reform_cancled(), CT_ERROR);
        cm_sleep(10); // 10ms
        CT_LOG_RUN_WAR("[DDL] wait db open current status %d", (session)->kernel->db.status);
    }
    knl_cursor_t* cursor = NULL;
    uint32 id = session->id;
    ddl_op_desc_t desc;

    if (!DB_IS_CLUSTER(session) || (session->logic_log_num == 0 && (clean_op == DDL_CLEAN_SESSION))) {
        cm_reset_error();
        return CT_SUCCESS;
    }

    session->logic_log_num = 0;
    knl_set_session_scn(session, CT_INVALID_ID64);

    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);

    if (clean_op != DDL_CLEAN_SESSION) {
        knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_CLUSTER_DDL_TABLE, CT_INVALID_ID32);
    } else {
        knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_CLUSTER_DDL_TABLE, IX_SYS_CLUSTER_DDL_TABLE_001_ID);
        knl_init_index_scan(cursor, CT_TRUE);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &id, sizeof(uint32),
            IX_SYS_CLUSTER_DDL_TABLE_001_ID);
    }

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (cursor->eof) {
        CM_RESTORE_STACK(session->stack);
        CT_LOG_DEBUG_WAR("[DDL]clean ddl op record, found no record for session(%d), op(%d).", id, clean_op);
        return CT_SUCCESS;
    }

    while (!cursor->eof) {
        if (clean_op == DDL_REFORM_REPLAY) {
            db_convert_ddl_op_desc(session, cursor, &desc);
            uint32 offset = 0;
            log_entry_t* log = NULL;
            while (offset < desc.log_size) {
                log = (log_entry_t*)((char*)desc.logic_log + offset);
                if (dtc_refresh_ddl(session, log) != CT_SUCCESS) {
                    CM_RESTORE_STACK(session->stack);
                    return CT_ERROR;
                }
                offset += log->size;
            }
        }

        if (knl_internal_delete(session, cursor) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }

        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

void db_clean_ddl_op_garbage(knl_session_t *session)
{
    if (!DB_IS_CLUSTER(session)) {
        return;
    }

    status_t status = db_clean_ddl_op(session, DDL_CLEAN_ALL);
    if (status != CT_SUCCESS) {
        CT_LOG_DEBUG_WAR("[DDL]failed to clean ddl op garbage.");
    }
    knl_commit(session);
}

status_t dtc_modify_drop_uid(knl_session_t *knl_session, uint32 uid)
{
    dc_context_t *ctx = &knl_session->kernel->dc_ctx;
    if (uid >= CT_MAX_USERS) {
        CT_LOG_RUN_ERR("dtc_modify_drop_uid failed, invalid uid %u", uid);
        CT_THROW_ERROR(ERR_USER_ID_NOT_EXIST, uid);
        return CT_ERROR;
    }
    dc_user_t *dc_user = ctx->users[uid];
    if (dc_user == NULL) {
        CT_THROW_ERROR(ERR_USER_ID_NOT_EXIST, uid);
        return CT_ERROR;
    }
    if (dc_user->status == USER_STATUS_LOCKED) {
        knl_session->drop_uid = uid;
    }
    return CT_SUCCESS;
}

status_t dtc_get_user_status(knl_session_t *session, dc_user_t *dc_user, bool8 *is_user_normal)
{
    msg_broadcast_data_t bcast;
    msg_broadcast_user_data_t user_data;
    user_data.uid = dc_user->desc.id;
    uint16 msg_size = sizeof(msg_broadcast_data_t) + sizeof(msg_broadcast_user_data_t);

    mes_init_send_head(&bcast.head, MES_CMD_BROADCAST_DATA, msg_size, CT_INVALID_ID32, session->kernel->id,
        dc_user->user_locked_owner, session->id, CT_INVALID_ID16);
    bcast.type = USER_LOCK_STATUS;
    mes_message_t msg;
    if (mes_send_data3(&bcast.head, sizeof(msg_broadcast_data_t), (void *)&user_data) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (mes_recv(session->id, &msg, CT_FALSE, CT_INVALID_ID32, DTC_GET_BTREE_SPLIT_STATUS_TIMEOUT) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DTC DC] dtc_get_user_lock_status get result timeout");
        return CT_ERROR;
    }

    if (SECUREC_UNLIKELY(msg.head->cmd != MES_CMD_BROADCAST_DATA_ACK)) {
        CT_LOG_RUN_ERR("[DTC DC] Recive unmatched message expect %d real %d", MES_CMD_BROADCAST_DATA_ACK,
            msg.head->cmd);
        mes_release_message_buf(msg.buffer);
        return CT_ERROR;
    }

    msg_user_stat_t *user_data_ack = (msg_user_stat_t *)(msg.buffer);
    *is_user_normal = (user_data_ack->status == USER_STATUS_NORMAL) ? CT_TRUE : CT_FALSE;
    CT_LOG_RUN_INF("[DTC DC] Get user lock status uid %d user status %d", dc_user->desc.id, user_data_ack->status);
    mes_release_message_buf(msg.buffer);
    return CT_SUCCESS;
}

void dtc_process_get_user_lock_status(knl_session_t *session, mes_message_t *req_msg, char *data)
{
    msg_broadcast_user_data_t *bcast = (msg_broadcast_user_data_t *)data;
    msg_user_stat_t msg;
    dc_context_t *ctx = &session->kernel->dc_ctx;
    uint32 uid = bcast->uid;
    if (uid >= CT_MAX_USERS) {
        CT_LOG_RUN_ERR("process_get_user_lock_status failed, invalid uid %u", uid);
        mes_release_message_buf(req_msg->buffer);
        return;
    }
    dc_user_t *dc_user = ctx->users[uid];

    if (dc_user) {
        msg.user_locked_owner = dc_user->user_locked_owner;
        msg.status = dc_user->status;
    } else {
        msg.user_locked_owner = CT_INVALID_ID32;
        msg.status = USER_STATUS_DROPPED;
    }

    mes_init_ack_head(req_msg->head, &msg.head, MES_CMD_BROADCAST_DATA_ACK, sizeof(msg_user_stat_t), session->id);
    mes_release_message_buf(req_msg->buffer);
    SYNC_POINT_GLOBAL_START(CANTIAN_GET_USER_STATS_ACK_TIMEOUT, NULL, 5000); // delay 5000ms
    SYNC_POINT_GLOBAL_END;
    if (mes_send_data(&msg) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DTC DC] failed to send lock user status");
        return;
    }
    CT_LOG_RUN_INF("[DTC DC] owner return user(%d) lock status %d", uid, msg.status);
}

status_t dtc_try_clean_user_lock(knl_session_t *knl_session, dc_user_t *dc_user)
{
    status_t ret = CT_SUCCESS;
    if (dc_user->user_locked_owner == knl_session->kernel->id) {
        return ret;
    }
    cluster_view_t view;
    rc_get_cluster_view(&view, CT_FALSE);
    uint64 alive_inst = view.bitmap;
    bool8 need_clean = CT_FALSE;
    if (!rc_bitmap64_exist(&alive_inst, dc_user->user_locked_owner)) {
        need_clean = dc_user->status == USER_STATUS_LOCKED ? CT_TRUE : CT_FALSE;
    } else {
        bool8 is_user_normal = CT_FALSE;
        ret = dtc_get_user_status(knl_session, dc_user, &is_user_normal);
        need_clean = (ret == CT_SUCCESS) && (is_user_normal == CT_TRUE);
    }
    if (need_clean) {
        text_t username;
        cm_str2text(dc_user->desc.name, &username);
        CT_LOG_RUN_WAR("[DTC DC] Need clean user lock uid %d, lock owner %d, current status %d, alive inst %llu",
            dc_user->desc.id, dc_user->user_locked_owner, dc_user->status, alive_inst);
        dc_set_user_status(knl_session, &username, USER_STATUS_NORMAL);
    }

    CT_LOG_RUN_INF("[DTC DC] Clean lock status uid %d, lock owner %d, current status %d, alive inst %llu need clean %d",
        dc_user->desc.id, dc_user->user_locked_owner, dc_user->status, alive_inst, need_clean);
    return ret;
}
