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
 * dtc_ckpt.c
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_ckpt.c
 *
 * -------------------------------------------------------------------------
 */
#include "dtc_ckpt.h"
#include "dtc_dcs.h"
#include "dtc_buffer.h"
#include "dtc_trace.h"
#include "knl_ckpt.h"
#include "cm_device.h"

static int32 cmp_page_id(const void *pa, const void *pb)
{
    const page_id_t *a = (const page_id_t *) pa;
    const page_id_t *b = (const page_id_t *) pb;
    int32 result;

    result = a->file > b->file ? 1 : (a->file < b->file ? -1 : 0);
    if (result != 0) {
        return result;
    }

    result = a->page > b->page ? 1 : (a->page < b->page ? -1 : 0);
    return result;
}

static int32 cmp_edp_page_info_t(const void* pa, const void* pb)
{
    const edp_page_info_t* a = (const edp_page_info_t*)pa;
    const edp_page_info_t* b = (const edp_page_info_t*)pb;

    return cmp_page_id(&a->page, &b->page);
}

static inline void sanity_check_sorted_page_id_array(edp_page_info_t* pages, uint32 count)
{
#ifdef LOG_DIAG
    for (uint32 i = 0; i < count - 1; i++) {
        knl_panic(!(pages[i].page.page == 0 && pages[i].page.file == 0));
        knl_panic(pages[i].page.file != INVALID_FILE_ID);
        knl_panic(cmp_edp_page_info_t(&pages[i], &pages[i + 1]) <= 0);
    }
#endif
}

void ckpt_sort_page_id_array(edp_page_info_t *pages, uint32 count)
{
    if (count <= 1) {
        return;
    }

    qsort(pages, count, sizeof(edp_page_info_t), cmp_edp_page_info_t);
    sanity_check_sorted_page_id_array(pages, count);
}

uint32 ckpt_merge_to_array(edp_page_info_t* src_pages, uint32 start, uint32 src_count, edp_page_info_t *dst_pages, uint32 * dst_count, uint32 dst_capacity)
{
    uint32 i = start;
    uint32 j = 0;
    uint32 tmp_dst_count = *dst_count;
    errno_t ret;
    int32 result;
    uint32 is_same = 0;

    ckpt_sort_page_id_array(dst_pages, tmp_dst_count);
    while (i - start < src_count && j < tmp_dst_count && tmp_dst_count < dst_capacity) {
        knl_panic(!(src_pages[i].page.page == 0 && src_pages[i].page.file == 0));
        knl_panic(src_pages[i].page.file != INVALID_FILE_ID);
        result = cmp_edp_page_info_t(&src_pages[i], &dst_pages[j]);
        if (result == 0) {
            i++;
            j++;
            is_same++;
        } else if (result < 0) {
            ret = memmove_s((char*)dst_pages + (j + 1) * sizeof(edp_page_info_t), (tmp_dst_count - j) * sizeof(edp_page_info_t),
                (char*)dst_pages + j * sizeof(edp_page_info_t), (tmp_dst_count - j) * sizeof(edp_page_info_t));
            knl_securec_check(ret);
            dst_pages[j] = src_pages[i];
            tmp_dst_count++;
            i++;
            j++;
        } else {
            j++;
        }
    }
    if (i - start >= src_count || j >= dst_capacity - 1 || tmp_dst_count >= dst_capacity) {
        GS_LOG_DEBUG_INF("[CKPT] merge src array(%d) to dst array(%d), found duplicated (%d), new dst size(%d)", src_count, *dst_count, is_same, tmp_dst_count);
        *dst_count = tmp_dst_count;
        sanity_check_sorted_page_id_array(dst_pages, tmp_dst_count);
        return i;
    }

    uint32 left = MIN(dst_capacity - j, src_count - (i - start));
    left = MIN(left, dst_capacity - tmp_dst_count);
    ret = memmove_s((char*)dst_pages + j * sizeof(edp_page_info_t), left * sizeof(edp_page_info_t),
        (char*)src_pages + i * sizeof(edp_page_info_t), left * sizeof(edp_page_info_t));
    knl_securec_check(ret);
    i += left;
    tmp_dst_count += left;
    GS_LOG_DEBUG_INF("[CKPT] merge src array(%d) to dst array(%d), found duplicated (%d), new dst size(%d)", src_count, *dst_count, is_same, tmp_dst_count);
    *dst_count = tmp_dst_count;
    knl_panic(*dst_count <= dst_capacity);
    sanity_check_sorted_page_id_array(dst_pages, tmp_dst_count);
    return i;
}

bool32 dtc_need_empty_ckpt(knl_session_t* session)
{
    if (!DB_IS_CLUSTER(session)) {
        return GS_FALSE;
    }

    /* The ckpt queue may be cleared by clean edp msg from edp page's owner node. */
    ckpt_context_t* ckpt_ctx = &session->kernel->ckpt_ctx;
    dtc_node_ctrl_t *node_ctrl = dtc_my_ctrl(session);
    return log_cmp_point(&node_ctrl->rcy_point, &ckpt_ctx->lrp_point) < 0;
}

bool32 dtc_add_to_edp_group(knl_session_t *session, ckpt_edp_group_t *dst, uint32 count, page_id_t page, uint64 lsn)
{
    GS_LOG_DEBUG_INF("[CKPT]add edp [%u-%u], count(%u), max count(%u)", page.file, page.page, dst->count, count);
    if (dst->count >= count) {
        return GS_FALSE;
    }

    dst->pages[dst->count].page = page;
    dst->pages[dst->count].lsn = lsn;
    dst->count++;
    return GS_TRUE;
}

status_t dtc_ckpt_trigger(knl_session_t *session, msg_ckpt_trigger_point_t *point, bool32 wait,
                          ckpt_mode_t trigger, uint32 target_id, bool32 update, bool32 force_switch)
{
    knl_instance_t *kernel = session->kernel;
    bak_context_t *ctx = &kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    mes_message_head_t head;
    mes_message_t  msg;

    mes_init_send_head(&head, MES_CMD_CKPT_TRIGGER, sizeof(mes_message_head_t) + sizeof(msg_ckpt_trigger_t),
                       GS_INVALID_ID32, session->kernel->dtc_attr.inst_id, target_id, session->id, GS_INVALID_ID16);

    msg_ckpt_trigger_t ckpt;
    ckpt.wait = wait;
    ckpt.update = update;
    ckpt.force_switch = (BAK_IS_DBSOTR(bak) && force_switch);
    ckpt.trigger = trigger;
    ckpt.lsn = DB_CURR_LSN(session);

    if (mes_send_data2(&head, &ckpt) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[BACKUP] %s failed", "send ckpt trigger mes ");
        return GS_ERROR;
    }

    if (mes_recv(session->id, &msg, GS_FALSE, GS_INVALID_ID32, MES_WAIT_MAX_TIME) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[BACKUP] %s failed", "receive ckpt trigger mes ");
        return GS_ERROR;
    }

    if (SECUREC_UNLIKELY(msg.head->cmd != MES_CMD_CKPT_TRIGGER_ACK)) {
        mes_release_message_buf(msg.buffer);
        return GS_ERROR;
    }

    msg_ckpt_trigger_point_t *trigger_info = (msg_ckpt_trigger_point_t *)(msg.buffer + sizeof(mes_message_head_t));
    uint32 ret = trigger_info->result;
    if (point != NULL) {
        *point = *trigger_info;
    }
    mes_release_message_buf(msg.buffer);
    if (ret != DTC_BAK_SUCCESS) {
        GS_LOG_RUN_ERR("[BACKUP] ckpt trigger failed, instid %u, result %u", target_id, ret);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

void dtc_process_ckpt_trigger(void *sess, mes_message_t * receive_msg)
{
    mes_message_head_t head;
    msg_ckpt_trigger_t *ckpt = (msg_ckpt_trigger_t *)(receive_msg->buffer + sizeof(mes_message_head_t));
    knl_session_t *session = (knl_session_t *)sess;
    // todo trigger arch file
    status_t s = GS_SUCCESS;
    uint32 ret = DTC_BAK_SUCCESS;
    dtc_update_lsn(session, ckpt->lsn);
    if (ckpt->force_switch) {
        s = arch_switch_archfile_trigger(session, GS_FALSE);
        if (s != GS_SUCCESS) {
            ret = DTC_BAK_ERROR;
        }
    }
    ckpt_trigger(session, ckpt->wait, ckpt->trigger);
    msg_ckpt_trigger_point_t return_info;
    if (!ckpt->update) {
        SYNC_POINT_GLOBAL_START(CANTIAN_BACKUP_REV_RCY_REQ_ABORT, NULL, 0);
        SYNC_POINT_GLOBAL_END;
        return_info.point = dtc_my_ctrl(session)->rcy_point;
        GS_LOG_DEBUG_INF("[BACKUP] set rcy log point: [%llu/%llu/%llu/%u]",
                         (uint64)return_info.point.rst_id, return_info.point.lsn,
                         (uint64)return_info.point.lfn, return_info.point.asn);
    } else {
        SYNC_POINT_GLOBAL_START(CANTIAN_BACKUP_REV_LRP_REQ_ABORT, NULL, 0);
        SYNC_POINT_GLOBAL_END;
        return_info.point = dtc_my_ctrl(session)->lrp_point;
    }
    SYNC_POINT_GLOBAL_START(CANTIAN_BACKUP_REV_CKPT_REQ_FAIL, (int32*)&ret, DTC_BAK_ERROR);
    return_info.result = ret;
    SYNC_POINT_GLOBAL_END;
    return_info.lsn = DB_CURR_LSN(session);
    mes_init_ack_head(receive_msg->head, &head, MES_CMD_CKPT_TRIGGER_ACK,
                      sizeof(mes_message_head_t) + sizeof(msg_ckpt_trigger_point_t), session->id);
    mes_release_message_buf(receive_msg->buffer);
    if (mes_send_data2((void*)&head, &return_info) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[BACKUP] %s failed", "send ckpt trigger mes ack ");
        return;
    }
}

void dcs_process_ckpt_edp_local(knl_session_t *session, edp_page_info_t *pages, uint32 page_count, bool32 wait)
{
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;
    uint32 i = 0;
    uint32 times = 0;
    ckpt_clean_edp_group_t *group = &ctx->remote_edp_group;

    if (page_count == 0) {
        return;
    }

    GS_LOG_DEBUG_INF("[CKPT] process remote request to write (%d) edp pages", page_count);

    ckpt_sort_page_id_array(pages, page_count);
    cm_spin_lock(&group->lock, NULL);
    while (i < page_count && !CKPT_CLOSED(session)) {
        i = ckpt_merge_to_array(pages, i, page_count - i, group->pages, &group->count, GS_CLEAN_EDP_GROUP_SIZE);
        if (i == page_count || DAAC_CKPT_SESSION(session)) {
            break;
        }
        cm_spin_unlock(&group->lock);
        ckpt_trigger(session, wait, CKPT_TRIGGER_INC);
        if (times++ > CKPT_TRY_ADD_TO_GROUP_TIMES || !ctx->ckpt_enabled) {
            GS_LOG_DEBUG_WAR("[CKPT] remote edp group is full when process remote request to write (%d) edp pages"
                             "or ckpt is disabled %d", page_count, ctx->ckpt_enabled);
            return;
        }
        cm_sleep(300);
        cm_spin_lock(&group->lock, NULL);
    }
    cm_spin_unlock(&group->lock);
    ckpt_trigger(session, wait, CKPT_TRIGGER_INC);
}

static inline status_t dcs_notify_owner_for_ckpt_l(knl_session_t *session, edp_page_info_t *pages, uint32 start,
                                                   uint32 end)
{
    msg_ckpt_edp_request_t msg;
    ckpt_edp_group_t edp_group;
    uint32 page_left;
    uint32 page_sent;
    errno_t ret;
    status_t status;

    uint8 cur_owner_id;
    cluster_view_t view;

    GS_LOG_DEBUG_INF("[CKPT][master try to notify page owner to write edp pages]: master src_id=%u, count=%d", DCS_SELF_INSTID(session), end - start);

    if (start >= end) {
        return GS_SUCCESS;
    }

    for (uint32 i = 0; i < g_dtc->profile.node_count; i++) {
        rc_get_cluster_view(&view, GS_FALSE);
        if (!rc_bitmap64_exist(&view.bitmap, i)) {
            GS_LOG_RUN_INF("[CKPT] inst id (%u) is not alive, alive bitmap: %llu", i, view.bitmap);
            continue;
        }
        edp_group.count = 0;
        for (uint32 j = start; j < end; j++) {
            page_id_t page_id = pages[j].page;
            drc_res_action_e action;

            if (SECUREC_UNLIKELY(drc_get_page_owner_id(session, page_id, &cur_owner_id, &action) != GS_SUCCESS)) {
                GS_LOG_RUN_WAR(
                    "[CKPT][%u-%u][notify page owner for ckpt page]: master src_id=%u, get owner failed, clean edp msg may be lost, node id=%d, index=%d, start=%d, end=%d, curr owner=%d",
                    page_id.file, page_id.page, DCS_SELF_INSTID(session), i, j, start, end, cur_owner_id);
                action = DRC_RES_CLEAN_EDP_ACTION;
                cur_owner_id = i; /* broadcast to all node to clean edp from ckpt because buf res is null and local
                                     clean edp msg may be lost. */
            }

            if ((cur_owner_id == GS_INVALID_ID8) || (cur_owner_id != i)) {
                continue;
            }
            pages[j].action = action;
            edp_group.pages[edp_group.count++] = pages[j];
        }

        if (i == DCS_SELF_INSTID(session)) {
            if (edp_group.count > 0) {
                dcs_process_ckpt_edp_local(session, edp_group.pages, edp_group.count, GS_FALSE);
            }
            continue;
        }
        page_sent = 0;
        page_left = edp_group.count;

        while (page_left > 0) {
            msg.count = MIN(GS_CKPT_EDP_GROUP_SIZE, page_left);
            ret = memcpy_sp((char*)msg.edp_pages, msg.count * sizeof(edp_page_info_t),
                            (char*)edp_group.pages + page_sent * sizeof(edp_page_info_t), msg.count * sizeof(edp_page_info_t));
            knl_securec_check(ret);

            mes_init_send_head(&msg.head, MES_CMD_CKPT_EDP_BROADCAST_TO_OWNER, sizeof(msg_ckpt_edp_request_t),
                               GS_INVALID_ID32, DCS_SELF_INSTID(session), i, DCS_SELF_SID(session), GS_INVALID_ID16);
            status = dcs_send_data_retry((void *)&msg);
            if (status != GS_SUCCESS) {
                GS_LOG_RUN_ERR("[CKPT][notify page owner for ckpt page]: master src_id=%u, send message failed, dest node id=%d, start=%d, end=%d",
                    DCS_SELF_INSTID(session), i, start, end);
                break;
            }

            page_sent += msg.count;
            page_left -= msg.count;
        }
        GS_LOG_DEBUG_INF("[CKPT] broadcast request to write (%d) edp pages to page owner %d", edp_group.count, i);
    }
    return GS_SUCCESS;
}

status_t dcs_master_process_ckpt_request(knl_session_t *session, edp_page_info_t *pages, uint32 count, bool32 broadcast_to_others)
{
    msg_ckpt_edp_request_t msg;
    uint64 success_inst;
    uint32 page_left;
    uint32 page_sent;
    uint8 master_id;
    uint32 notify_master_idx = 0;
    errno_t ret;
    status_t status;

    GS_LOG_DEBUG_INF("[CKPT] master start to process request to write (%d) edp pages", count);

    for (uint32 i = 0; i < count; i++) {
        knl_panic(!(pages[i].page.page == 0 && pages[i].page.file));
        if (drc_get_page_master_id(pages[i].page, &master_id) != GS_SUCCESS) {
            return GS_ERROR;
        }

        // move page whose master is on current node to the end of the array
        if (master_id != DCS_SELF_INSTID(session)) {
            SWAP(edp_page_info_t, pages[i], pages[notify_master_idx]);
            notify_master_idx++;
        }
    }

    status = dcs_notify_owner_for_ckpt_l(session, pages, notify_master_idx, count);
    if (status != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[CKPT] master process local owner ckpt failed, notify_master_idx=%d, count=%d", notify_master_idx, count);
        return GS_ERROR;
    }

    if (!broadcast_to_others || notify_master_idx == 0) {
        return GS_SUCCESS;
    }

    page_left = notify_master_idx;
    page_sent = 0;

    while (page_left > 0) {
        msg.count = MIN(GS_CKPT_EDP_GROUP_SIZE, page_left);
        ret = memcpy_sp((char*)msg.edp_pages, msg.count * sizeof(edp_page_info_t),
                        (char*)pages + page_sent * sizeof(edp_page_info_t), msg.count * sizeof(edp_page_info_t));
        knl_securec_check(ret);

        mes_init_send_head(&msg.head, MES_CMD_CKPT_EDP_BROADCAST_TO_MASTER, sizeof(msg_ckpt_edp_request_t),
                           GS_INVALID_ID32, g_dtc->profile.inst_id, GS_INVALID_ID8, session->id, GS_INVALID_ID16);
        mes_broadcast(session->id, MES_BROADCAST_ALL_INST, &msg, &success_inst);

        page_sent += msg.count;
        page_left -= msg.count;
    }

    GS_LOG_DEBUG_INF("[CKPT] broadcast request to write (%d) edp pages to master", notify_master_idx);

    return GS_SUCCESS;
}

status_t dcs_notify_owner_for_ckpt(knl_session_t * session, ckpt_context_t *ctx)
{
    if (!DB_IS_CLUSTER(session) || ctx->edp_group.count == 0) {
        return GS_SUCCESS;
    }

    knl_panic(ctx->edp_group.count <= GS_CKPT_GROUP_SIZE);
    return dcs_master_process_ckpt_request(session, ctx->edp_group.pages, ctx->edp_group.count, GS_TRUE);
}

void dcs_process_ckpt_edp_broadcast_to_master_req(void *sess, mes_message_t * msg)
{
    msg_ckpt_edp_request_t *request = (msg_ckpt_edp_request_t *)msg->buffer;
    knl_session_t *session = (knl_session_t *)sess;
    uint32 page_count = request->count;

    if (page_count > GS_CKPT_EDP_GROUP_SIZE) {
        GS_LOG_RUN_ERR("[%u] edp request page count invalid,", page_count);
        mes_release_message_buf(msg->buffer);
        return;
    }

    (void)dcs_master_process_ckpt_request(session, request->edp_pages, page_count, GS_FALSE);

    GS_LOG_DEBUG_INF("[CKPT] master process request to write (%d) edp pages", page_count);
    mes_release_message_buf(msg->buffer);
}

void dcs_process_ckpt_edp_broadcast_to_owner_req(void *sess, mes_message_t * msg)
{
    msg_ckpt_edp_request_t *request = (msg_ckpt_edp_request_t *)msg->buffer;
    knl_session_t *session = (knl_session_t *)sess;
    uint32 page_count = request->count;
    if (page_count > GS_CKPT_EDP_GROUP_SIZE) {
        GS_LOG_RUN_ERR("[%u] edp request page count invalid,", page_count);
        mes_release_message_buf(msg->buffer);
        return;
    }

    GS_LOG_DEBUG_INF("[CKPT] owner process request to write (%d) edp pages", page_count);
    dcs_process_ckpt_edp_local(session, request->edp_pages, page_count, GS_FALSE);
    mes_release_message_buf(msg->buffer);
}

status_t dcs_ckpt_remote_edp_prepare(knl_session_t *session, ckpt_context_t *ctx)
{
    buf_ctrl_t *ctrl = NULL;
    uint32 i;
    page_id_t page_id;
    uint8 action;
    uint64 clean_lsn;
    bool32 latched;
    errno_t ret;
    uint32 count;

    ctx->remote_edp_clean_group.count = 0;
    ckpt_clean_edp_group_t *group = &ctx->remote_edp_group;
    cm_spin_lock(&group->lock, NULL);
    if (group->count == 0) {
        cm_spin_unlock(&group->lock);
        return GS_SUCCESS;
    }

    knl_panic(group->count <= GS_CLEAN_EDP_GROUP_SIZE);
    i = 0;
    count = group->count;

    while (i < count) {
        page_id = group->pages[i].page;
        action = group->pages[i].action;
        clean_lsn = group->pages[i].lsn;

        ctrl = buf_try_latch_ckpt_page(session, page_id, &latched);
        if (ctrl == NULL) {
            /* if it's local clean shared copy from remote dirty page, it may be swapped out of memory. Notify requester
               with invalid lsn, and requester need to load from disk and check.
            */
            i++;
            (void)dtc_add_to_edp_group(session, &ctx->remote_edp_clean_group, GS_CKPT_GROUP_SIZE, page_id, clean_lsn);
            GS_LOG_RUN_WAR("[CKPT][%u-%u][ckpt remote prepare]: not found in memory, page is clean, and resend clean "
                "edp message, requester needs to double check disk page, clean_lsn:%llu, current_lsn:%llu",
                page_id.file, page_id.page, clean_lsn, DB_CURR_LSN(session));
            continue;
        }

        if (!latched) {
            buf_dec_ref(session, ctrl);
            SWAP(edp_page_info_t, group->pages[i], group->pages[count - 1]);
            count--;
            GS_LOG_DEBUG_WAR("[CKPT][%u-%u][ckpt remote prepare]: can't latch page", page_id.file, page_id.page);
            continue;
        }

        i++;

        DTC_DCS_DEBUG_INF(
            "[CKPT][%u-%u][ckpt write page]:ctrl_dirty=%u, ctrl_remote_dirty=%u, ctrl_readonly=%u, ctrl_marked=%u, ctrl_lock_mode=%u, edp=%d",
            ctrl->page_id.file, ctrl->page_id.page, ctrl->is_dirty, ctrl->is_remote_dirty, ctrl->is_readonly,
            ctrl->is_marked, ctrl->lock_mode, ctrl->is_edp);

        if (action != DRC_RES_INVALID_ACTION && ctrl->is_edp && g_rc_ctx->status >= REFORM_RECOVER_DONE) {
            dcs_clean_local_ctrl(session, ctrl, action, clean_lsn);
        }

        if (ctrl->is_marked || ctrl->is_readonly || ctrl->is_edp || !DCS_BUF_CTRL_IS_OWNER(session, ctrl) ||
            !IS_SAME_PAGID(page_id, ctrl->page_id)) {
            buf_unlatch_page(session, ctrl);
            DTC_DCS_DEBUG_INF("[CKPT][%u-%u][ckpt remote prepare]: not edp owner page", page_id.file, page_id.page);
            continue;
        }

        /* Both ctrl->is_remote_dirty and ctrl->is_dirty may be 0. It has to flush page to disk and send ack again, in
           case: 1) previous clean edp msg is lost, and other edp ctrl resends ckpt request. Or ctrl ownership changed
           after this request. 2) this ctrl is a local clean shared copy from remote dirty ctrl owner, it's newer than
           page on disk.
        */
        knl_panic_log(clean_lsn <= ctrl->page->lsn || g_rc_ctx->status < REFORM_RECOVER_DONE, "page_id %u-%u, i %u",
            ctrl->page_id.file, ctrl->page_id.page, i);
        (void)dtc_add_to_edp_group(session, &ctx->remote_edp_clean_group, GS_CKPT_GROUP_SIZE, ctrl->page_id,
                                   ctrl->page->lsn);
        knl_panic_log(!ctrl->is_edp, "page_id %u-%u, i %u", ctrl->page_id.file, ctrl->page_id.page, i);
        knl_panic_log(DCS_BUF_CTRL_IS_OWNER(session, ctrl), "page_id %u-%u, i %u", ctrl->page_id.file,
            ctrl->page_id.page, i);
        knl_panic_log(CHECK_PAGE_PCN(ctrl->page), "page_id %u-%u, i %u", ctrl->page_id.file, ctrl->page_id.page, i);
        knl_panic_log(IS_SAME_PAGID(ctrl->page_id, AS_PAGID(ctrl->page->id)),
                      "ctrl's page_id and ctrl page's id are not same, panic info: page_id %u-%u type %u, "
                      "page id %u-%u type %u",
                      ctrl->page_id.file, ctrl->page_id.page, ctrl->page->type, AS_PAGID(ctrl->page->id).file,
                      AS_PAGID(ctrl->page->id).page, ctrl->page->type);

        /* DEFAULT_PAGE_SIZE is 8192,  ctx->group.count <= GS_CKPT_GROUP_SIZE(4096), integers cannot cross bounds */
        ret = memcpy_sp(ctx->group.buf + DEFAULT_PAGE_SIZE(session) * ctx->group.count,
                        DEFAULT_PAGE_SIZE(session), ctrl->page, DEFAULT_PAGE_SIZE(session));
        knl_securec_check(ret);

        if (ctrl == ctx->batch_end) {
            ctx->batch_end = ctx->batch_end->ckpt_prev;
        }
        if (ctrl->in_ckpt) {
            ckpt_pop_page(session, ctx, ctrl);
        }

        if (ctx->consistent_lfn < ctrl->lastest_lfn) {
            ctx->consistent_lfn = ctrl->lastest_lfn;
        }

        ctrl->is_marked = 1;
        CM_MFENCE;
        ctrl->is_dirty = 0;
        ctrl->is_remote_dirty = 0;

        buf_unlatch_page(session, ctrl);
        ctx->group.items[ctx->group.count].ctrl = ctrl;
        ctx->group.items[ctx->group.count].buf_id = ctx->group.count;
        ctx->group.items[ctx->group.count].need_punch = GS_FALSE;

        if (ckpt_encrypt(session, ctx) != GS_SUCCESS) {
            cm_spin_unlock(&group->lock);
            return GS_ERROR;
        }
        if (ckpt_checksum(session, ctx) != GS_SUCCESS) {
            cm_spin_unlock(&group->lock);
            return GS_ERROR;
        }
        ckpt_put_to_part_group(session, ctx, ctrl);
        ctx->group.count++;

        if (ctx->group.count >= GS_CKPT_GROUP_SIZE) {
            break;
        }
    }

    group->count -= count;
    if (group->count > 0) {
        ret = memmove_s((char*)group->pages, group->count * sizeof(edp_page_info_t),
                        (char*)group->pages + count * sizeof(edp_page_info_t), group->count * sizeof(edp_page_info_t));
        knl_securec_check(ret);
    }

    cm_spin_unlock(&group->lock);
    return GS_SUCCESS;
}

status_t dcs_ckpt_clean_local_edp(knl_session_t *session, ckpt_context_t *ctx)
{
    uint32 i = 0;
    edp_page_info_t page;
    bool32 succeed;
    uint32 count;
    errno_t ret;

    ckpt_clean_edp_group_t *group = &ctx->local_edp_clean_group;
    cm_spin_lock(&group->lock, NULL);
    if (group->count == 0) {
        cm_spin_unlock(&group->lock);
        return GS_SUCCESS;
    }

    count = group->count;

    GS_LOG_DEBUG_INF("[CKPT] ckpt clean local (%d) edp pages", count);
    knl_panic(count <= GS_CLEAN_EDP_GROUP_SIZE);

    while (i < count) {
        page = group->pages[i];
        succeed = buf_clean_edp(session, page);
        if (!succeed) {
            SWAP(edp_page_info_t, group->pages[i], group->pages[count - 1]);
            count--;
            continue;
        }
        i++;
    }
    if (ctx->timed_task == CKPT_MODE_IDLE) {
        ctx->stat.clean_edp_count[ctx->trigger_task] += count;
    } else {
        ctx->stat.clean_edp_count[ctx->timed_task] += count;
    }
    group->count -= count;
    if (group->count > 0) {
        ret = memmove_s((char*)group->pages, group->count * sizeof(edp_page_info_t),
                        (char*)group->pages + count * sizeof(edp_page_info_t), group->count * sizeof(edp_page_info_t));
        knl_securec_check(ret);
    }
    cm_spin_unlock(&group->lock);
    return GS_SUCCESS;
}


void dcs_ckpt_trigger(knl_session_t *session, bool32 wait, ckpt_mode_t trigger)
{
    if (DB_NOT_READY(session)) {
        return;
    }

    ckpt_trigger(session, wait, trigger);
    if (!DB_IS_CLUSTER(session)) {
        return;
    }

    msg_ckpt_request_t req;
    req.trigger = trigger;
    req.wait = wait;

    mes_init_send_head(&req.head, MES_CMD_CKPT_REQ, sizeof(msg_ckpt_request_t), GS_INVALID_ID32,
        DCS_SELF_INSTID(session), 0, session->id, GS_INVALID_ID16);
    mes_broadcast_and_wait(session->id, MES_BROADCAST_ALL_INST, (void *)&req, MES_WAIT_MAX_TIME, NULL);
}

// called by drop tablespace or drop file
#define MAX_DCS_CHECKPOINT_TIMEOUT 300000
#define DCS_CHECKPOINT_SLEEP_TIME 2000
#define DCS_CHECKPOINT_RETRY_SLEEP_TIME 1000
void dcs_broadcast_retry(knl_session_t *session, cluster_view_t *view, msg_ckpt_request_t *req)
{
    uint64 bitmap = 0;
    uint64 suc_inst = 0;
    status_t ret;

    bitmap = view->bitmap;
    for (;;) {
        GS_LOG_DEBUG_INF("[CKPT] broadcast , bitmap = %llu.", bitmap);
        ret = mes_broadcast_and_wait(session->id, bitmap, (void *)req, MAX_DCS_CHECKPOINT_TIMEOUT, &suc_inst);
        if (ret != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[CKPT] failed to broadcast cluster, ret = %d, bitmap = %llu, success instance = %llu.", ret,
                           bitmap, suc_inst);
            if (rc_is_cluster_changed(view)) {
                GS_LOG_DEBUG_INF("[CKPT] cluster is changed.");
                break;
            }
            bitmap = bitmap & (~suc_inst);
            cm_sleep(DCS_CHECKPOINT_RETRY_SLEEP_TIME);
            continue;
        }
        break;
    }
}

void dcs_ckpt_trigger4drop(knl_session_t *session, bool32 wait, ckpt_mode_t trigger)
{
    if (DB_NOT_READY(session)) {
        return;
    }
    
    if (!DB_IS_CLUSTER(session)) {
        ckpt_trigger(session, wait, trigger);
        return;
    }

    cluster_view_t view;
    do {
        rc_get_cluster_view(&view, GS_FALSE);
        if (!view.is_stable) {
            GS_LOG_RUN_INF("[CKPT] failed to get stable cluster view, is_stable = %d.", view.is_stable);
            cm_sleep(DCS_CHECKPOINT_SLEEP_TIME);
            continue;
        }
        GS_LOG_RUN_INF("[CKPT] begin to checkpoint once.");
        ckpt_trigger(session, wait, trigger);

        msg_ckpt_request_t req;
        req.trigger = trigger;
        req.wait = wait;

        mes_init_send_head(&req.head, MES_CMD_CKPT_REQ, sizeof(msg_ckpt_request_t), GS_INVALID_ID32,
            DCS_SELF_INSTID(session), 0, session->id, GS_INVALID_ID16);
        dcs_broadcast_retry(session, &view, &req);

        GS_LOG_RUN_INF("[CKPT] succeed to finish checkpoint once.");
    } while (rc_is_cluster_changed(&view));
}

void dcs_process_ckpt_request(void *sess, mes_message_t * msg)
{
    knl_session_t *session = (knl_session_t*)sess;
    msg_ckpt_request_t *req = (msg_ckpt_request_t*)msg->buffer;
    mes_message_head_t head = {0};

    GS_LOG_DEBUG_INF("[CKPT] process request to trigger checkpoint, type = %d, wait=%d", req->trigger, req->wait);
    if (req->trigger < CKPT_TRIGGER_INC && req->trigger > CKPT_TRIGGER_CLEAN) {
        GS_LOG_RUN_ERR("[%u] ckpt request trigger invalid,", req->trigger);
        mes_release_message_buf(msg->buffer);
        return;
    }
    ckpt_trigger(session, req->wait, req->trigger);

    mes_init_ack_head(msg->head, &head, MES_CMD_BROADCAST_ACK, sizeof(mes_message_head_t), GS_INVALID_ID16);
    mes_release_message_buf(msg->buffer);
    if (mes_send_data(&head) != GS_SUCCESS) {
        CM_ASSERT(0);
    }
    GS_LOG_RUN_INF("[CKPT] done request to trigger checkpoint, type = %d", req->trigger);

    return;
}

status_t dtc_cal_redo_size(knl_session_t *session, log_point_t pre_lrp_point, log_point_t pre_rcy_point,
                           rc_redo_stat_list_t *redo_stat_list)
{
    log_context_t *log_ctx = &session->kernel->redo_ctx;
    log_file_t *log_file = &log_ctx->files[log_ctx->curr_file];
    dtc_node_ctrl_t *node_ctrl = dtc_my_ctrl(session);
    uint64 recovery_log_size = 0;
    uint64 io_generate_log_size = 0;
    uint64 recycle_log_size = 0;
    uint32 rcy_log_size = 0;

    if (cm_dbs_is_enable_dbs() == GS_TRUE) {
        if (cm_device_get_used_cap(log_file->ctrl->type, log_file->handle, node_ctrl->rcy_point.lsn, &rcy_log_size) !=
            GS_SUCCESS) {
            GS_LOG_RUN_ERR("[DTC CKPT] failed to fetch rcy redo log size of rcy point lsn(%llu) from DBStor",
                           node_ctrl->lrp_point.lsn);
            return GS_ERROR;
        }
        redo_stat_list->redo_recovery_size = ((uint64)rcy_log_size * SIZE_K(1)) / SIZE_M(1);
    } else {
        recovery_log_size = log_file->ctrl->size * (node_ctrl->lrp_point.asn - node_ctrl->rcy_point.asn) +
                            1ULL * node_ctrl->lrp_point.block_id * log_file->ctrl->block_size -
                            1ULL * node_ctrl->rcy_point.block_id * log_file->ctrl->block_size;
        redo_stat_list->redo_recovery_size = recovery_log_size / SIZE_M(1);
    }

    io_generate_log_size = log_file->ctrl->size * (node_ctrl->lrp_point.asn - pre_lrp_point.asn) +
                           1ULL * node_ctrl->lrp_point.block_id * log_file->ctrl->block_size -
                           1ULL * pre_lrp_point.block_id * log_file->ctrl->block_size;
    redo_stat_list->redo_generate_size = io_generate_log_size / SIZE_M(1);

    recycle_log_size = log_file->ctrl->size * (node_ctrl->rcy_point.asn - pre_rcy_point.asn) +
                       1ULL * node_ctrl->rcy_point.block_id * log_file->ctrl->block_size -
                       1ULL * pre_rcy_point.block_id * log_file->ctrl->block_size;
    redo_stat_list->redo_recycle_size = recycle_log_size / SIZE_M(1);

    return GS_SUCCESS;
}

void dtc_calculate_rcy_redo_size(knl_session_t *session, buf_ctrl_t *ckpt_first_ctrl)
{
    rc_redo_stat_t *redo_stat = &g_rc_ctx->redo_stat;
    static timeval_t update_time = { 0 };
    static log_point_t pre_rcy_point = { 0 };
    static log_point_t pre_lrp_point = { 0 };
    page_id_t page_id_tmp = { 0 };
    
    cm_spin_lock(&redo_stat->lock, NULL);
    redo_stat->ckpt_num++;
    if (redo_stat->ckpt_num == CKPT_CAL_REDO_TIMES) {
        dtc_node_ctrl_t *node_ctrl = dtc_my_ctrl(session);
        timeval_t now_time;
        rc_redo_stat_list_t redo_stat_list;
        uint32 redo_stat_insert_ind = 0;

        if (dtc_cal_redo_size(session, pre_lrp_point, pre_rcy_point, &redo_stat_list) != GS_SUCCESS) {
            redo_stat->ckpt_num--;
            cm_spin_unlock(&redo_stat->lock);
            GS_LOG_RUN_WAR("[DTC] update dtc rcy redo stat failed, try next time");
            return;
        }

        redo_stat_insert_ind = redo_stat->redo_stat_cnt < CKPT_LOG_REDO_STAT_COUNT ?
                               redo_stat->redo_stat_cnt : redo_stat->redo_stat_start_ind;

        (void)cm_gettimeofday(&now_time);
        uint64 time_interval = TIMEVAL_DIFF_S(&update_time, &now_time);
        redo_stat_list.time_interval = time_interval;
        redo_stat_list.redo_generate_speed = (double)redo_stat_list.redo_generate_size / (double)time_interval;
        redo_stat_list.redo_recycle_speed = (double)redo_stat_list.redo_recycle_size / (double)time_interval;
        redo_stat_list.ckpt_queue_first_page = ckpt_first_ctrl == NULL ? page_id_tmp : ckpt_first_ctrl->page_id;
        redo_stat_list.end_time = cm_now();

        redo_stat->stat_list[redo_stat_insert_ind] = redo_stat_list;
        redo_stat->redo_stat_cnt = redo_stat->redo_stat_cnt < CKPT_LOG_REDO_STAT_COUNT ?
                                   redo_stat->redo_stat_cnt + 1 : redo_stat->redo_stat_cnt;
        redo_stat->redo_stat_start_ind = (redo_stat_insert_ind + 1) % CKPT_LOG_REDO_STAT_COUNT;

        pre_lrp_point = node_ctrl->lrp_point;
        pre_rcy_point = node_ctrl->rcy_point;
        update_time = now_time;

        redo_stat->ckpt_num = 0;
    }
    cm_spin_unlock(&redo_stat->lock);
    return;
}
