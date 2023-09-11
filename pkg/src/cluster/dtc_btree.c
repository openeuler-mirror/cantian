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
 * dtc_btree.c
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_btree.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_tran.h"
#include "knl_dc.h"
#include "index_common.h"
#include "pcr_btree_scan.h"
#include "dtc_btree.h"
#include "dtc_context.h"
#include "dtc_dcs.h"

status_t dtc_btree_construct_cr_page(knl_session_t *session, cr_cursor_t *cursor, btree_page_t *page)
{
    uint8 inst_id;

    if (g_dtc->profile.enable_rmo_cr) {
        /* in RMO mode, we force to do local consistent read */
        cursor->local_cr = GS_TRUE;
    }

    for (;;) {
        if (pcrb_get_invisible_itl(session, cursor, page) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (cursor->itl == NULL || cursor->wxid.value != GS_INVALID_ID64) {
            return GS_SUCCESS;
        }

        inst_id = xid_get_inst_id(session, cursor->itl->xid);
        if (inst_id == session->kernel->id || cursor->local_cr) {
            if (pcrb_reorganize_with_undo_list(session, cursor, page) != GS_SUCCESS) {
                return GS_ERROR;
            }
        } else {
            if (dcs_btree_request_cr_page(session, cursor, (char *)page, inst_id) != GS_SUCCESS) {
                return GS_ERROR;
            }

            if (cursor->itl == NULL || cursor->wxid.value != GS_INVALID_ID64) {
                return GS_SUCCESS;
            }
        }
    }
}

void dtc_btree_broadcast_root_page(knl_session_t *session, btree_t *btree, btree_page_t *page,
                                   knl_part_locate_t part_loc)
{
    msg_btree_broadcast_t bcast;
    page_id_t page_id = AS_PAGID(page->head.id);
    uint16 size = sizeof(msg_btree_broadcast_t) + DEFAULT_PAGE_SIZE(session);
    mes_init_send_head(&bcast.head, MES_CMD_BTREE_ROOT_PAGE, size, GS_INVALID_ID32, session->kernel->id, GS_INVALID_ID8,
                       session->id, GS_INVALID_ID16);
    bcast.table_id = btree->index->desc.table_id;
    bcast.uid = btree->index->desc.uid;
    bcast.index_id = btree->index->desc.id;
    bcast.part_loc = part_loc;
    bcast.is_shadow = btree->is_shadow;

    GS_LOG_DEBUG_INF(
        "[DTC] session %u broadcast root page[%u-%u], rsn %u, pcn %u, table-uid-index-part-subpart[%u-%u-%u-%u-%u]",
        session->id, page_id.file, page_id.page, bcast.head.rsn, page->head.pcn, btree->index->desc.table_id,
        btree->index->desc.uid, btree->index->desc.id, part_loc.part_no, part_loc.subpart_no);

    SYNC_POINT_GLOBAL_START(CANTIAN_BTREE_BEFORE_BCAST_ROOT_PAGE_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;

    mes_broadcast_bufflist_with_retry(session->id, MES_BROADCAST_ALL_INST, &bcast.head,
        sizeof(msg_btree_broadcast_t), (char *)page);

    SYNC_POINT_GLOBAL_START(CANTIAN_BTREE_AFTER_BCAST_ROOT_PAGE_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
}

void dtc_btree_send_ack(knl_session_t *session, mes_message_t *msg)
{
    mes_message_head_t ack_head = {0};

    mes_init_ack_head(msg->head, &ack_head, MES_CMD_BROADCAST_ACK, sizeof(mes_message_head_t), session->id);

    mes_release_message_buf(msg->buffer);

    SYNC_POINT_GLOBAL_START(CANTIAN_BTREE_PROC_BCAST_ROOT_PAGE_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;

    status_t ret = GS_SUCCESS;
    SYNC_POINT_GLOBAL_START(CANTIAN_BTREE_PROC_BCAST_ROOT_PAGE_FAIL, &ret, GS_ERROR);
    ret = mes_send_data(&ack_head);
    SYNC_POINT_GLOBAL_END;
    if (ret != GS_SUCCESS) {
        GS_LOG_DEBUG_ERR("[DTC] failed to send msg: cmd=%u, dest_id=%u, dest_sid=%u, rsn=%u",
                         ack_head.cmd, ack_head.dst_inst, ack_head.dst_sid, ack_head.rsn);
    }
}

void dtc_btree_process_root_page(void *sess, mes_message_t *msg)
{
    msg_btree_broadcast_t *bcast = (msg_btree_broadcast_t *)msg->buffer;
    btree_page_t *root = (btree_page_t *)((char *)bcast + sizeof(msg_btree_broadcast_t));
    knl_dictionary_t dc;
    btree_t *btree = NULL;
    knl_session_t *session = (knl_session_t *)sess;
    page_id_t page_id = AS_PAGID(root->head.id);

    if (!DC_IS_READY(session)) {
        GS_LOG_DEBUG_INF(
            "[DTC] process btree root page[%u-%u], rsn %u, part-subpart[%u-%u], dc not ready, status=%dtable-uid-index[%u-%u-%u]",
            page_id.file, page_id.page, bcast->head.rsn, bcast->part_loc.part_no, bcast->part_loc.subpart_no,
            DB_STATUS(session), bcast->table_id, bcast->uid, bcast->index_id);
        dtc_btree_send_ack(session, msg);
        return;
    }
    if (knl_try_open_dc_by_id(session, bcast->uid, bcast->table_id, &dc) != GS_SUCCESS) {
        cm_reset_error();
        knl_panic_log(
            0,
            "[DTC] process btree root page[%u-%u], part-subpart[%u-%u], failed to open dc, table-uid-index[%u-%u-%u]",
            page_id.file, page_id.page, bcast->part_loc.part_no, bcast->part_loc.subpart_no, bcast->table_id,
            bcast->uid, bcast->index_id);
        return;
    }

    dc_entity_t *entity = DC_ENTITY(&dc);
    if (entity == NULL) {
        GS_LOG_DEBUG_INF(
            "[DTC] process btree root page[%u-%u], entity is null, part-subpart[%u-%u], table-uid-index[%u-%u-%u]",
            page_id.file, page_id.page, bcast->part_loc.part_no, bcast->part_loc.subpart_no, bcast->table_id,
            bcast->uid, bcast->index_id);
        dtc_btree_send_ack(session, msg);
        return;
    }

    btree = dc_get_btree_by_id(session, entity, bcast->index_id, bcast->part_loc, bcast->is_shadow);
    btree_copy_root_page(session, btree, root);

    GS_LOG_DEBUG_INF("[DTC] process btree root page[%u-%u], part-subpart[%u-%u],table-uid-index[%u-%u-%u]",
                     page_id.file, page_id.page, bcast->part_loc.part_no, bcast->part_loc.subpart_no, bcast->table_id,
                     bcast->uid, bcast->index_id);

    dtc_btree_send_ack(session, msg);

    dc_close(&dc);
}
