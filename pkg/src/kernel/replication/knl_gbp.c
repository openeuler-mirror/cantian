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
 * knl_gbp.c
 *
 *
 * IDENTIFICATION
 * src/kernel/replication/knl_gbp.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_replication_module.h"
#include "cm_log.h"
#include "cm_thread.h"
#include "cm_hash.h"
#include "cm_debug.h"
#include "cm_file.h"
#include "knl_buflatch.h"
#include "knl_gbp.h"
#include "knl_database.h"
#include "knl_recovery.h"
#include "dtc_database.h"

#ifdef __cplusplus
extern "C"{
#endif

static buf_ctrl_t *gbp_pop_queue(knl_session_t *session, gbp_queue_t *queue, buf_ctrl_t *ctrl);
void gbp_refresh_gbp_window(knl_session_t *session, uint32 gbp_proc_id);

static cs_pipe_t *gbp_get_client_pipe(gbp_context_t *gbp_context, uint32 gbp_proc_id, bool32 is_temp)
{
    gbp_buf_manager_t *manager = &gbp_context->gbp_buf_manager[gbp_proc_id];

    return (is_temp) ? &manager->pipe_temp : &manager->pipe_const;
}

/* database send request to GBP */
static status_t gbp_knl_send_request(cs_pipe_t *pipe, char *req_buf, gbp_buf_manager_t *manager)
{
    gbp_msg_hdr_t *request = (gbp_msg_hdr_t *)req_buf;

    if (cs_write_stream(pipe, req_buf, request->msg_length, 0) == CT_SUCCESS) {
        return CT_SUCCESS;
    }

    CT_LOG_RUN_WAR("[GBP] failed to send request, type %u, fd %d", request->msg_type, cs_get_socket_fd(pipe));
    if (manager != NULL) {
        cs_disconnect(pipe); // just close const pipe here, temp pipes are closed at gbp_stop_temp_connection
        manager->is_connected = CT_FALSE;
    }
    return CT_ERROR;
}

/* database get reponse from GBP */
static status_t gbp_knl_wait_response(cs_pipe_t *pipe, char *resp_buf, int32 buf_size)
{
    int32 recv_size;
    int32 remain_size;
    gbp_msg_hdr_t msg;

    if (cs_read_stream(pipe, (char *)&msg, GBP_MAX_READ_WAIT_TIME, sizeof(gbp_msg_hdr_t), &recv_size) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[GBP] failed to receive message from GBP instance");
        return CT_ERROR;
    }

    if (sizeof(gbp_msg_hdr_t) != recv_size) {
        CT_LOG_RUN_ERR("[GBP] invalid recv_size %u received, expected size is %u",
                       recv_size, (int32)sizeof(gbp_msg_hdr_t));
        return CT_ERROR;
    }

    if (msg.msg_length < recv_size) {
        CT_LOG_RUN_ERR("[GBP] invalid message size %u received, which is smaller than %u",
                       msg.msg_length, recv_size);
        return CT_ERROR;
    }

    remain_size = msg.msg_length - recv_size;

    if (remain_size > (buf_size - sizeof(gbp_msg_hdr_t))) {
        CT_LOG_RUN_ERR("[GBP] invalid msg length size %u received", msg.msg_length);
        return CT_ERROR;
    }

    if (remain_size > 0) {
        if (cs_read_stream(pipe, resp_buf + sizeof(gbp_msg_hdr_t), GBP_MAX_READ_WAIT_TIME, remain_size,
                           &recv_size) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[GBP] failed to receive message type %u from GBP with size %u", msg.msg_type, remain_size);
            return CT_ERROR;
        }

        if (recv_size != (buf_size - sizeof(gbp_msg_hdr_t))) {
            CT_LOG_RUN_ERR("[GBP] invalid recv_size %u received, expected size is %u",
                           (uint32)recv_size, (uint32)(buf_size - sizeof(gbp_msg_hdr_t)));
            return CT_ERROR;
        }

        if (recv_size == 0) {
            CT_LOG_RUN_ERR("[GBP] peer close the connetion when read message body");
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t gbp_notify_msg(knl_session_t *session, gbp_notify_msg_e msg, uint32 gbp_proc_id, gbp_msg_ack_t *ack)
{
    gbp_context_t *gbp_context = &session->kernel->gbp_context;
    gbp_attr_t *gbp_attr = &session->kernel->gbp_attr;
    database_t *db = &session->kernel->db;
    bool32 temp_pipe = (msg == MSG_GBP_READ_BEGIN);
    cs_pipe_t *pipe = gbp_get_client_pipe(gbp_context, gbp_proc_id, temp_pipe);
    gbp_notify_req_t request;
    errno_t ret;

    // set msg header
    GBP_SET_MSG_HEADER(&request, GBP_REQ_NOTIFY_MSG, sizeof(gbp_notify_req_t), cs_get_socket_fd(pipe));
    // set msg body
    request.msg = msg;
    request.db_stat.db_role = db->ctrl.core.db_role;
    request.db_stat.db_open = db->status;
    ret = memcpy_sp(request.db_stat.local_host, CM_MAX_IP_LEN, gbp_attr->local_gbp_host, CM_MAX_IP_LEN);
    knl_securec_check(ret);

    if (gbp_knl_send_request(pipe, (char *)&request, &gbp_context->gbp_buf_manager[gbp_proc_id]) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (ack == NULL) {
        return CT_SUCCESS;
    }
    return gbp_knl_wait_response(pipe, (char *)ack, sizeof(gbp_msg_ack_t));
}

/* primary or statndy send heart beat to GBP */
static void gbp_timed_heart_beat(knl_session_t *session)
{
    gbp_context_t *gbp_context = &session->kernel->gbp_context;
    uint32 gbp_proc_id = session->gbp_queue_index - 1;
    gbp_buf_manager_t *gbp_buf_manager = &gbp_context->gbp_buf_manager[gbp_proc_id];

    if (!KNL_GBP_ENABLE(session->kernel) || !gbp_buf_manager->is_connected) {
        return;
    }

    if (g_timer()->now - gbp_buf_manager->last_hb_time < GBP_HEARTBEAT_INTERVAL) {
        return;
    }

    cm_spin_lock(&gbp_buf_manager->fisrt_pipe_lock, NULL);
    if (gbp_notify_msg(session, MSG_GBP_HEART_BEAT, gbp_proc_id, NULL) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[GBP] heart beat with gbp failed");
    }
    cm_spin_unlock(&gbp_buf_manager->fisrt_pipe_lock);
    gbp_buf_manager->last_hb_time = g_timer()->now;
}

/* get page lsn record on disk */
static uint64 gbp_get_disk_lsn(knl_session_t *session, page_id_t page_id, bool32 ignore_crc)
{
    buf_ctrl_t ctrl;
    uint64 lsn;
    char *buf = (char *)cm_push(session->stack, DEFAULT_PAGE_SIZE(session) + CT_MAX_ALIGN_SIZE_4K);

    ctrl.page_id = page_id;
    ctrl.page = (page_head_t *)cm_aligned_buf(buf);

    if (buf_load_page_from_disk(session, &ctrl, page_id) != CT_SUCCESS) {
        if (ignore_crc) {
            /* Only verify disk lsn at gbp_replace_local_page in DEBUG mode, may be concurrent with ckpt */
            CT_LOG_RUN_WAR("[GBP] verify disk lsn failed because CRC failed");
            ctrl.page->lsn = CT_INVALID_LSN;
        } else {
            CM_ABORT(0, "[GBP] ABORT INFO: failed to load page %u-%u", page_id.file, page_id.page);
        }
    }

    lsn = ctrl.page->lsn;
    cm_pop(session->stack);
    return lsn;
}

/* replace database buffer page using GBP's page */
static void gbp_replace_local_page(knl_session_t *session, buf_ctrl_t *ctrl, page_head_t *gbp_page)
{
    errno_t ret;

#ifdef LOG_DIAG
    uint64 disk_page_lsn = gbp_get_disk_lsn(session, ctrl->page_id, CT_TRUE);
    uint64 gbp_page_lsn = PAGE_GET_LSN(gbp_page);
    knl_panic_log(disk_page_lsn <= gbp_page_lsn, "disk_page_lsn is bigger than gbp_page_lsn, panic info: "
                  "ctrl_page %u-%u type %u, gbp_page %u-%u type %u disk_page_lsn %llu gbp_page_lsn %llu",
                  ctrl->page_id.file, ctrl->page_id.page, ctrl->page->type, AS_PAGID(gbp_page->id).file,
                  AS_PAGID(gbp_page->id).page, gbp_page->type, disk_page_lsn, gbp_page_lsn);
#endif
    ret = memcpy_sp(ctrl->page, DEFAULT_PAGE_SIZE(session), gbp_page, DEFAULT_PAGE_SIZE(session));
    knl_securec_check(ret);

    knl_panic_log(IS_SAME_PAGID(AS_PAGID(ctrl->page->id), ctrl->page_id), "ctrl page's id and ctrl's page_id are not "
                  "same, panic info: ctrl page's id %u-%u ctrl's page_id %u-%u type %u", AS_PAGID(ctrl->page->id).file,
                  AS_PAGID(ctrl->page->id).page, ctrl->page_id.file, ctrl->page_id.page, ctrl->page->type);
    knl_panic_log(CHECK_PAGE_PCN(ctrl->page), "page pcn is abnormal, panic info: page %u-%u type %u",
                  ctrl->page_id.file, ctrl->page_id.page, ctrl->page->type);

    ctrl->gbp_ctrl->is_from_gbp = CT_TRUE;
    if (!ctrl->is_dirty) {
        ctrl->is_dirty = CT_TRUE;
        ckpt_enque_one_page(session, ctrl);
    }
}

/*
 * process response for database read one page from GBP
 * if gbp page can be used, replace local page as gbp page
 */
static gbp_page_status_e gbp_process_read_resp(knl_session_t *session, gbp_read_resp_t *response, buf_ctrl_t *ctrl)
{
    uint64 gbp_page_lsn;
    uint64 curr_page_lsn;
    gbp_page_status_e page_status = GBP_PAGE_MISS;
    char *gbp_page = response->block;

    if (response->result == GBP_READ_RESULT_OK) {
        gbp_page_lsn = PAGE_GET_LSN(gbp_page);
        curr_page_lsn = PAGE_GET_LSN(ctrl->page);
        page_status = gbp_page_verify(session, response->pageid, gbp_page_lsn, curr_page_lsn);
        if (gbp_page_lsn > curr_page_lsn && (page_status == GBP_PAGE_HIT || page_status == GBP_PAGE_USABLE)) {
            gbp_replace_local_page(session, ctrl, (page_head_t *)gbp_page);
            ctrl->gbp_ctrl->gbp_read_version = KNL_GBP_READ_VER(session->kernel);
        }
    }

    if (response->result == GBP_READ_RESULT_ERROR) {
        gbp_page[GBP_MSG_LEN] = '\0'; // Write at most 64 byte of page head to run log
        page_status = GBP_PAGE_ERROR;
        CT_LOG_RUN_WAR("[GBP] failed to read page(%u, %u) from GBP, error: %s",
                       ctrl->page_id.file, ctrl->page_id.page, gbp_page);
    }

    return page_status;
}

/*
 * some gbp page can not be repalced as local page, inlcude
 * 1. gbp page is not in standby redo, mostly this gbp page too old and page lfn < standby rcy point
 * 2. gbp page has been verifyed, mostly means that has been relapced as local page
 * 3. space or datafile is not online
 * 4. page is nologging page, except space head page
 */
static bool32 gbp_need_skip(knl_session_t *session, gbp_page_item_t *page_item)
{
    datafile_t *df = NULL;
    space_t *space = NULL;
    gbp_analyse_item_t *item = NULL;

    item = gbp_aly_get_page_item(session, page_item->page_id);
    /* no redo log for the page, page can be discard */
    if (item == NULL) {
        return CT_TRUE;
    }
    knl_panic_log(item->lsn != CT_INVALID_LSN, "lsn is NULL.");
    if (item->is_verified == CT_TRUE) {
        return CT_TRUE;
    }

    df = DATAFILE_GET(session, page_item->page_id.file);
    space = SPACE_GET(session, df->space_id);
    if (!SPACE_IS_ONLINE(space) || !DATAFILE_IS_ONLINE(df) || !df->ctrl->used) {
        item->is_verified = CT_TRUE;
        return CT_TRUE;
    }

    if (SPACE_IS_NOLOGGING(space)) {
        item->is_verified = CT_TRUE;
        return CT_TRUE;
    }

    return CT_FALSE;
}

/* process response for background thread read page batch from GBP */
static void gbp_process_batch_read_resp(knl_session_t *session, gbp_batch_read_resp_t *resp)
{
    gbp_page_item_t *gbp_batch = resp->pages;
    gbp_page_item_t *gbp_page = NULL;
    buf_ctrl_t *ctrl = NULL;
    page_id_t page_id;
    uint64 gbp_page_lsn;
    uint64 curr_page_lsn;

    if (resp->result == GBP_READ_RESULT_ERROR) {
        resp->msg[GBP_MSG_LEN - 1] = '\0';
        CT_LOG_RUN_WAR("[GBP] kernel batch read gbp pages error: %s", resp->msg);
        return;
    }

    for (uint32 i = 0; i < resp->count; i++) {
        gbp_page = &gbp_batch[i];

        if (gbp_need_skip(session, gbp_page)) {
            continue;
        }

        page_id = AS_PAGID(((page_head_t *)gbp_page->block)->id);
        knl_panic_log(IS_SAME_PAGID(gbp_page->page_id, page_id), "gbp_page's page_id and gbp_page block's id are not "
                      "same, panic info: gbp_page %u-%u, gbp_page block %u-%u", gbp_page->page_id.file,
                      gbp_page->page_id.page, page_id.file, page_id.page);

        /* use ENTER_PAGE_NO_READ to indicate it will not load page from local disk */
        buf_enter_page(session, gbp_page->page_id, LATCH_MODE_X, ENTER_PAGE_NO_READ);
        ctrl = session->curr_page_ctrl;
        gbp_page_lsn = PAGE_GET_LSN(gbp_page->block);
        curr_page_lsn = ctrl->page->lsn;

        ctrl->gbp_ctrl->page_status = gbp_page_verify(session, page_id, gbp_page_lsn, curr_page_lsn);

        if ((gbp_page_lsn > curr_page_lsn) &&
            (ctrl->gbp_ctrl->page_status == GBP_PAGE_HIT || ctrl->gbp_ctrl->page_status == GBP_PAGE_USABLE)) {
            gbp_replace_local_page(session, ctrl, (page_head_t *)gbp_page->block);
        } else if (curr_page_lsn == CT_INVALID_LSN) {
            /* page is not load from disk or replace by gbp page, page in buffer is invalid, need load disk page */
            ctrl->gbp_ctrl->is_from_gbp = CT_FALSE;
            if (buf_load_page_from_disk(session, ctrl, page_id) != CT_SUCCESS) {
                CM_ABORT(0, "[GBP] ABORT INFO: GBP background thread failed to load %u-%u", page_id.file, page_id.page);
            }
            CT_LOG_RUN_INF("[GBP] kernel load page from disk %u-%u when read batch page", page_id.file, page_id.page);
        }

        ctrl->gbp_ctrl->gbp_read_version = KNL_GBP_READ_VER(session->kernel);

        if (PAGE_SIZE(*ctrl->page) == 0 && ctrl->page->lsn == 0) {
            /* extended page, must be load from disk */
            knl_panic_log(!ctrl->gbp_ctrl->is_from_gbp, "page is read from gbp, panic info: page %u-%u type %u",
                          ctrl->page_id.file, ctrl->page_id.page, ctrl->page->type);
        }

        /* treat page as loaded from disk, do not change it, do not generate redo */
        buf_leave_page(session, CT_FALSE);
    }
}

/* background worker read pages from GBP, mostly running when standby failover */
static uint32 gbp_knl_read_pages(knl_session_t *session)
{
    gbp_context_t *gbp_context = &session->kernel->gbp_context;
    log_context_t *redo_ctx = &session->kernel->redo_ctx;
    gbp_batch_read_req_t request;
    gbp_batch_read_resp_t *response = NULL;
    uint32 gbp_proc_id = session->gbp_queue_index - 1;
    date_t begin_time = g_timer()->now;
    cs_pipe_t *pipe = gbp_get_client_pipe(gbp_context, gbp_proc_id, CT_FALSE);

    /* set message header */
    GBP_SET_MSG_HEADER(&request, GBP_REQ_BATCH_PAGE_READ, sizeof(gbp_batch_read_req_t), cs_get_socket_fd(pipe));
    /* set message body */
    request.gbp_skip_point = redo_ctx->gbp_skip_point; // only read pages after gbp_skip_point

    if (gbp_knl_send_request(pipe, (char *)&request, &gbp_context->gbp_buf_manager[gbp_proc_id]) != CT_SUCCESS) {
        return GBP_READ_RESULT_ERROR;
    }

    response = (gbp_batch_read_resp_t *)gbp_context->batch_buf[gbp_proc_id];
    if (gbp_knl_wait_response(pipe, (char *)response, sizeof(gbp_batch_read_resp_t)) != CT_SUCCESS) {
        gbp_context->gbp_buf_manager[gbp_proc_id].is_connected = CT_FALSE;
        cs_disconnect(pipe);
        return GBP_READ_RESULT_ERROR;
    }

    gbp_process_batch_read_resp(session, response);
    session->stat->gbp_bg_read += response->count;
    session->stat->gbp_bg_read_time += (g_timer()->now - begin_time) / MICROSECS_PER_MILLISEC;

    return response->result;
}

static status_t gbp_buf_latch_s(knl_session_t *session, buf_ctrl_t *ctrl)
{
    buf_gbp_ctrl_t *gbp_ctrl = ctrl->gbp_ctrl;
    date_t timeout = GBP_MAX_READ_WAIT_TIME * MICROSECS_PER_MILLISEC;
    date_t start_time = KNL_NOW(session);
    date_t wait_time = 0;

    while (gbp_ctrl == NULL) {
        cm_spin_sleep();
        gbp_ctrl = ctrl->gbp_ctrl;
    }

    cm_spin_lock(&gbp_ctrl->init_lock, NULL);
    /* need wait page loaded, beacuse this page may be doing recycle */
    while (ctrl->load_status == BUF_NEED_LOAD && wait_time <= timeout) {
        cm_spin_unlock(&gbp_ctrl->init_lock);
        cm_spin_sleep();
        wait_time = KNL_NOW(session) - start_time;
        cm_spin_lock(&gbp_ctrl->init_lock, NULL);
    }

    if (wait_time > timeout) {
        cm_spin_unlock(&gbp_ctrl->init_lock);
        CT_LOG_RUN_ERR("[GBP] latch ctrl timeout, load_status %u, page id [%u-%u]",
                       ctrl->load_status, ctrl->page_id.file, ctrl->page_id.page);
        return CT_ERROR;
    }
    buf_latch_s(session, ctrl, CT_FALSE, CT_TRUE);
    cm_spin_unlock(&gbp_ctrl->init_lock);
    return CT_SUCCESS;
}

static status_t gbp_try_buf_latch_ctrl(knl_session_t *session, thread_t *thread, buf_ctrl_t *ctrl,
                                       bool32 wait_readonly)
{
    if (gbp_buf_latch_s(session, ctrl) != CT_SUCCESS) {
        return CT_ERROR;
    }
    /* like ckpt, we can not put readonly page to gbp */
    /* need wait page loaded, beacuse this page may be doing recycle */
    while ((wait_readonly && ctrl->is_readonly) || ctrl->load_status == BUF_NEED_LOAD) {
        buf_unlatch(session, ctrl, CT_FALSE);
        cm_spin_sleep();
        if (session->killed || thread->closed) {
            return CT_ERROR;
        }
        if (gbp_buf_latch_s(session, ctrl) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

/*
 * when gbp queue page not send to GBP, but it has been recycled. gbp queue will has gap, we need remove queue pages
 * that trunc point is less than gap_end_point
 */
static uint32 gbp_queue_remove_gap_pages(knl_session_t *session, thread_t *thread, gbp_queue_t *gbp_queue,
                                         log_point_t gap_end_point)
{
    buf_ctrl_t *ctrl = NULL;
    buf_ctrl_t *ctrl_next = NULL;
    uint32 remove_num = 0;

    ctrl = gbp_queue->first;

    while (ctrl != NULL && !session->killed && !thread->closed) {
        if (gbp_try_buf_latch_ctrl(session, thread, ctrl, CT_FALSE) != CT_SUCCESS) {
            return remove_num;
        }

        /*
         * If page gbp trunc point less than gap end point, the page ctrl may be recycled.
         * Tnd origin dirty page will be never send to GBP, so we give up all pages before gap_end_point
         */
        if (LOG_LFN_LT(ctrl->gbp_ctrl->gbp_trunc_point, gap_end_point)) {
            ctrl_next = gbp_pop_queue(session, gbp_queue, ctrl);
            ctrl->gbp_ctrl->is_gbpdirty = CT_FALSE;
            buf_unlatch(session, ctrl, CT_FALSE);
            ctrl = ctrl_next;
        } else {
            buf_unlatch(session, ctrl, CT_FALSE);
            break;
        }
        remove_num++;
    }
    return remove_num;
}

/* copy 100 dirty pages to write request, record pages max lsn and max lastest lfn */
static void gbp_assemble_write_request(knl_session_t *session, thread_t *thread, gbp_write_req_t *request,
                                       gbp_queue_t *gbp_queue, uint64 *max_lsn, uint64 *max_lfn)
{
    buf_ctrl_t *ctrl = NULL;
    buf_ctrl_t *ctrl_next = NULL;
    uint32 pop_num = 0;
    errno_t ret;

    ctrl = gbp_queue->first;

    while (ctrl != NULL && pop_num < GBP_BATCH_PAGE_NUM && !session->killed && !thread->closed) {
        if (gbp_try_buf_latch_ctrl(session, thread, ctrl, CT_TRUE) != CT_SUCCESS) {
            gbp_queue->has_gap = CT_TRUE;
            return;
        }

        if (ctrl->page->size_units != 0) {
            knl_panic_log(IS_SAME_PAGID(ctrl->page_id, AS_PAGID(ctrl->page->id)), "ctrl's page id and ctrl page's id "
                          "are not same, panic info: ctrl_page %u-%u type %u, ctrl page %u-%u type %u",
                          ctrl->page_id.file, ctrl->page_id.page, ctrl->page->type, AS_PAGID(ctrl->page->id).file,
                          AS_PAGID(ctrl->page->id).page, ctrl->page->type);
            knl_panic_log(CHECK_PAGE_PCN(ctrl->page), "pcn of the page is abnormal, panic info: page %u-%u type %u",
                          ctrl->page_id.file, ctrl->page_id.page, ctrl->page->type);
        }

        /* set page info */
        request->pages[pop_num].page_id = ctrl->page_id;
        request->pages[pop_num].gbp_trunc_point = ctrl->gbp_ctrl->gbp_trunc_point;
        request->pages[pop_num].gbp_lrp_point.lfn = ctrl->lastest_lfn;
        ret = memcpy_sp(request->pages[pop_num].block, DEFAULT_PAGE_SIZE(session),
                        ctrl->page, DEFAULT_PAGE_SIZE(session));
        knl_securec_check(ret);
        PAGE_CHECKSUM(request->pages[pop_num].block, DEFAULT_PAGE_SIZE(session)) =
            CT_INVALID_CHECKSUM; // set checksum to 0
        pop_num++;

        /* page in queue should obey gbp_trunc_point asc order */
        knl_panic_log(LOG_LFN_LE(request->batch_trunc_point, ctrl->gbp_ctrl->gbp_trunc_point),
                      "panic info: page %u-%u type %u", ctrl->page_id.file, ctrl->page_id.page, ctrl->page->type);
        request->batch_trunc_point = ctrl->gbp_ctrl->gbp_trunc_point;
        *max_lsn = MAX(*max_lsn, ctrl->page->lsn);
        *max_lfn = MAX(*max_lfn, ctrl->lastest_lfn);

        ctrl_next = gbp_pop_queue(session, gbp_queue, ctrl);
        ctrl->gbp_ctrl->is_gbpdirty = CT_FALSE;
        buf_unlatch(session, ctrl, CT_FALSE);
        ctrl = ctrl_next;
    }

    request->page_num = pop_num;
    request->page_num_tail = pop_num;
}

/*
 * return min{local_flush_point, max{peer_flush_point}}
 * make sure log is flushed to local disk and at least one peer standby.
 */
static void gbp_log_min_flush_point(knl_session_t *session, log_point_t *min_flush_point)
{
    log_point_t peer_max_point = { 0, 0, 0, 0 };

    *min_flush_point = session->kernel->redo_ctx.curr_point;  /* local flush point */

    if (DB_IS_RAFT_ENABLED(session->kernel)) {
        return; // log must flushed to peer in raft mode
    }

    if (session->kernel->lsnd_ctx.standby_num > 0) {
        lsnd_get_max_flush_point(session, &peer_max_point, CT_FALSE);
        if (min_flush_point->asn == CT_INVALID_ASN || log_cmp_point(&peer_max_point, min_flush_point) < 0) {
            *min_flush_point = peer_max_point;
        }
    }
}

/*
 * Wait log flushed to local disk and at least one standy before write page to GBP
 * set request->lrp_point as min (local_flush_point, max(peer_flush_points))
 * make sure GBP pages satisfy WAL principle for at least one standy, let this standby can use GBP
 */
static status_t gbp_wait_log_flush(knl_session_t *session, thread_t *thread, uint64 max_page_lsn, uint64 max_page_lfn,
                                   log_point_t *gbp_lrp_point)
{
    gbp_context_t *gbp_context = &session->kernel->gbp_context;
    log_context_t *redo_ctx = &session->kernel->redo_ctx;
    log_point_t curr_point = { 0, 0, 0, 0 };
    log_point_t min_flush_point;

    /* make sure log is flushed to local disk(primary DN disk) */
    if (max_page_lfn > redo_ctx->flushed_lfn && !gbp_context->log_flushing) {
        gbp_context->log_flushing = CT_TRUE;
        if (log_flush(session, &curr_point, NULL, NULL) != CT_SUCCESS) {
            return CT_ERROR;
        }

        /* wait log flushed to standby */
        if ((curr_point.asn != CT_INVALID_ASN) && !DB_IS_RAFT_ENABLED(session->kernel)) {
            lsnd_wait(session, curr_point.lfn, NULL);
        }

        gbp_context->log_flushing = CT_FALSE;
    }

    /* make sure log is flushed to at least one peer(standby DN) */
    gbp_log_min_flush_point(session, &min_flush_point);
    while (max_page_lfn > min_flush_point.lfn && !session->killed && !thread->closed) {
        cm_sleep(10);
        CT_LOG_DEBUG_INF("[GBP] wait log flushed before write page to GBP. "
                         "max_page_lfn[%llu], min_flush_lfn[%llu], max_page_lsn[%llu]",
                         max_page_lfn, (uint64)min_flush_point.lfn, max_page_lsn);
        gbp_log_min_flush_point(session, &min_flush_point);
    }
    *gbp_lrp_point = min_flush_point;
    return CT_SUCCESS;
}

/* if has gap, remove pages and just update begin_point, lrp_point */
static void gbp_knl_reset_queue(knl_session_t *session, thread_t *thread, gbp_write_req_t *request, gbp_queue_t *gbp_queue)
{
    log_context_t *redo_ctx = &session->kernel->redo_ctx;
    uint32 throw_num = request->page_num;

    while (gbp_queue->has_gap) {
        gbp_queue->has_gap = CT_FALSE;
        throw_num += gbp_queue_remove_gap_pages(session, thread, gbp_queue, redo_ctx->curr_point);
    }

    request->page_num = 0;
    request->page_num_tail = 0;

    /* we read curr_point without lock */
    request->batch_begin_point = redo_ctx->curr_point;
    request->batch_trunc_point = request->batch_begin_point;
    request->batch_lrp_point = request->batch_begin_point;
    CT_LOG_RUN_WAR("[GBP] queue id %u, throw %u gap pages and reset gbp begin lfn: %llu",
                   gbp_queue->id, throw_num, (uint64)request->batch_begin_point.lfn);
}

/* background write pages to GBP */
static status_t gbp_knl_write_to_gbp(knl_session_t *session, thread_t *thread)
{
    gbp_context_t *gbp_context = &session->kernel->gbp_context;
    uint32 gbp_proc_id = session->gbp_queue_index - 1;
    gbp_write_req_t *request = (gbp_write_req_t *)gbp_context->batch_buf[gbp_proc_id];
    gbp_queue_t *gbp_queue = &gbp_context->queue[gbp_proc_id];
    cs_pipe_t *pipe = gbp_get_client_pipe(gbp_context, gbp_proc_id, CT_FALSE);
    date_t begin_time = g_timer()->now;
    uint64 max_page_lsn = CT_INVALID_LSN;
    uint64 max_page_lfn = CT_INVALID_LSN;
    log_point_t init_point = { 0, 0, 0, 0 };

    knl_panic(SESSION_IS_GBP_BG(session));
    if (gbp_queue->count == 0) {
        cm_spin_sleep();
    }

    while (gbp_queue->count > 0) {
        if (session->killed || thread->closed) {
            return CT_ERROR;
        }

        request->batch_trunc_point = init_point; // set to 0
        request->batch_begin_point = init_point; // set to 0

        /* set msg header */
        GBP_SET_MSG_HEADER(request, GBP_REQ_PAGE_WRITE, sizeof(gbp_write_req_t), cs_get_socket_fd(pipe));
        /* set msg body */
        gbp_assemble_write_request(session, thread, request, gbp_queue, &max_page_lsn, &max_page_lfn);

        if (gbp_wait_log_flush(session, thread, max_page_lsn, max_page_lfn, &request->batch_lrp_point) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (session->killed || thread->closed) {
            return CT_ERROR;
        }

        if (gbp_queue->has_gap) {
            gbp_knl_reset_queue(session, thread, request, gbp_queue);
        }

        if (gbp_knl_send_request(pipe, (char *)request, &gbp_context->gbp_buf_manager[gbp_proc_id]) != CT_SUCCESS) {
            return CT_ERROR;
        }

        session->stat->gbp_page_write_time += (g_timer()->now - begin_time) / MICROSECS_PER_MILLISEC;
        session->stat->gbp_page_write += request->page_num;
    }
    return CT_SUCCESS;
}

/* check if pages on gbp satisfy WAL, gbp lrp point can not large than standby redo end point */
static void gbp_page_check_wal(knl_session_t *session, gbp_read_ckpt_resp_t *resp)
{
    log_context_t *redo_ctx = &session->kernel->redo_ctx;
    log_point_t redo_end_point = redo_ctx->redo_end_point;

    /* if end_point < gbp_lrp_point, it does not satisfy WAL */
    if (LOG_LFN_LT(redo_end_point, resp->lrp_point) || redo_ctx->gbp_aly_lsn < resp->max_lsn) {
        gbp_set_unsafe(session, RD_TYPE_END);

        CT_LOG_RUN_WAR("[GBP] gbp unsafe, redo end_point[%u-%u-%llu] less than gbp_lrp_point[%u-%u-%llu]"
                       "or redo max lsn[%llu] less than gbp page max lsn[%llu]",
                       redo_end_point.rst_id, redo_end_point.asn, (uint64)redo_end_point.lfn,
                       resp->lrp_point.rst_id, resp->lrp_point.asn, (uint64)resp->lrp_point.lfn,
                       redo_ctx->gbp_aly_lsn, resp->max_lsn);
    }
}

static void gbp_process_read_ckpt_resp(knl_session_t *session, gbp_read_ckpt_resp_t *resp, log_context_t *redo_ctx)
{
    // gbp_begin_point: Min trunc point for GBP pages, pages less than gbp_begin_point may be eliminated in GBP buffer.
    // If we use GBP page to repalce local page, make sure the current repaly point is not less than gbp_begin_point
    redo_ctx->gbp_begin_point = resp->begin_point;
    // gbp_rcy_point: Just think GBP is disk, it is same as rcy_point. All GBP pages have been repalyed to at least
    // gbp_rcy_point. When we pulled all GBP pages to local, we just need replay redo from gbp_rcy_point
    redo_ctx->gbp_rcy_point = resp->rcy_point;
    // gbp_lrp_point: Max trunc point for GBP pages. Just think GBP is disk, it is same as lrp_point. Some GBP pages
    // have already been repalyed to gbp_lrp_point and some GBP pages have been only repalyed to gbp_rcy_point.
    // After pull GBP pages, we must repaly redo at least to gbp_lrp_point. Otherwise, data consistency is broken.
    redo_ctx->gbp_lrp_point = resp->lrp_point;
    if (resp->gbp_unsafe) {
        gbp_set_unsafe(session, RD_TYPE_END);
        CT_LOG_RUN_WAR("[GBP] gbp unsafe reason: %s", resp->unsafe_reason);
    }

    CT_LOG_RUN_INF("[GBP] gbp_begin_point[%u-%u-%llu], gbp_lrp_point[%u-%u-%llu], format: [rst_id-asn-lfn]",
                   resp->begin_point.rst_id, resp->begin_point.asn, (uint64)resp->begin_point.lfn,
                   resp->lrp_point.rst_id, resp->lrp_point.asn, (uint64)resp->lrp_point.lfn);

    gbp_page_check_wal(session, resp);
}

/* crash recovery or failover, read page from gbp */
static void gbp_try_pull_page_batch(knl_session_t *session, uint32 *last_result)
{
    gbp_context_t *gbp_context = &session->kernel->gbp_context;
    uint32 gbp_proc_id = session->gbp_queue_index - 1;
    uint32 result = *last_result;

    knl_panic(SESSION_IS_GBP_BG(session));
    /* last read status is GBP_READ_RESULT_OK, it means some gbp pages are not read, need continue read from GBP */
    if (result == GBP_READ_RESULT_OK) {
        result = gbp_knl_read_pages(session);
    }

    if (result == GBP_READ_RESULT_ERROR) {
        CM_ABORT(0, "[GBP] ABORT INFO: instance must exit beacause failed to read pages from GBP");
    }

    /* no pages can read from GBP for current gbp_bg_proc, means all GBP pages in queue[gbp_proc_id] have been read */
    if (result == GBP_READ_RESULT_NOPAGE) {
        if (gbp_context->gbp_buf_manager[gbp_proc_id].gbp_reading) {
            gbp_context->gbp_buf_manager[gbp_proc_id].gbp_reading = CT_FALSE;
            (void)cm_atomic_dec(&gbp_context->gbp_read_thread_num);
        }

        if (gbp_context->gbp_read_thread_num == 0 && // all gbp_bg_proc read completed
            gbp_proc_id == 0 && // gbp_knl_end_read need only be called once, so just let gbp_bg_proc 0 call it
            DB_IS_OPEN(session) &&
            DB_IS_PRIMARY(&session->kernel->db)) { // need wait failover completed
            gbp_knl_end_read(session);
        }
        cm_sleep(1);
    }

    *last_result = result;
}

status_t gbp_alloc_bg_session(uint8 queue_index, knl_session_t **session)
{
    if (g_knl_callback.alloc_knl_session(CT_TRUE, (knl_handle_t *)session) != CT_SUCCESS) {
        return CT_ERROR;
    }
    (*session)->gbp_queue_index = queue_index; // for gbp bg session, gbp_queue_index > 0
    return CT_SUCCESS;
}

void gbp_release_bg_session(knl_session_t *session)
{
    session->gbp_queue_index = 0;
    g_knl_callback.release_knl_session(session);
}

/*
 * background worker in kernel which is used to transform pages with GBP in background
 * number of gbp_bg_proc is gbp_buf_manager_count
 * 1. On primary, write dirty pages to GBP and send heart beat
 * 2. On standby, send heart beat or read pages from GBP
 */
static void gbp_bg_proc(thread_t *thread)
{
    knl_session_t *session = (knl_session_t *)thread->argument;
    gbp_context_t *gbp_context = &session->kernel->gbp_context;
    gbp_buf_manager_t *gbp_buf_manager = gbp_context->gbp_buf_manager;
    uint32 gbp_proc_id = session->gbp_queue_index - 1;
    uint32 pull_result = GBP_READ_RESULT_OK;

    cm_set_thread_name("gbp_bg");
    CT_LOG_RUN_INF("gbp_bg_%u thread started", gbp_proc_id);
    knl_panic(SESSION_IS_GBP_BG(session));

    /* first start, treat it has gap, so that gbp begin point refresh as redo->curr_point */
    gbp_context->queue[gbp_proc_id].id = gbp_proc_id;
    gbp_context->queue[gbp_proc_id].has_gap = CT_TRUE;
    gbp_buf_manager[gbp_proc_id].gbp_reading = CT_FALSE;
    gbp_buf_manager[gbp_proc_id].last_hb_time = g_timer()->now;

    /* loop forever when USE_GBP is TRUE */
    while (!thread->closed) {
        if (!gbp_buf_manager[gbp_proc_id].is_connected) {
            cm_sleep(100);
            continue;
        }

        /* only works during recover from GBP */
        if (KNL_RECOVERY_WITH_GBP(session->kernel)) {
            gbp_try_pull_page_batch(session, &pull_result);
            continue;
        }
        pull_result = GBP_READ_RESULT_OK; /* reset pull page result after recover end */

        if (!DB_IS_OPEN(session)) {
            cm_sleep(10);
            continue;
        }

        if (DB_IS_PRIMARY(&session->kernel->db)) {
            if (gbp_knl_write_to_gbp(session, thread) != CT_SUCCESS) {
                /* write page to gbp failed, set has gap, the GBP pages will be cleared */
                gbp_context->queue[gbp_proc_id].has_gap = CT_TRUE;
            }
        } else {
            /* standby do not write dirty pages to GBP, when it become new primary, has_gap will reset GBP's page */
            gbp_context->queue[gbp_proc_id].has_gap = CT_TRUE;
            gbp_refresh_gbp_window(session, gbp_proc_id);
            cm_sleep(200);
        }

        gbp_timed_heart_beat(session); /* both primary and standby send heart beat to GBP */
    }
    CT_LOG_RUN_INF("gbp_bg_%u thread stopped", gbp_proc_id);
    gbp_release_bg_session(session);
    KNL_SESSION_CLEAR_THREADID(session);
}

static void gbp_init_connect_pipe(gbp_buf_manager_t *gbp_buf_manager)
{
    gbp_buf_manager->is_connected = CT_FALSE;
    gbp_buf_manager->pipe_const.link.tcp.sock = CS_INVALID_SOCKET;
    gbp_buf_manager->pipe_const.link.tcp.closed = CT_TRUE;
    gbp_buf_manager->pipe_temp.link.tcp.sock = CS_INVALID_SOCKET;
    gbp_buf_manager->pipe_temp.link.tcp.closed = CT_TRUE;

    gbp_buf_manager->pipe_const.link.rdma.sock = CS_INVALID_SOCKET;
    gbp_buf_manager->pipe_const.link.rdma.closed = CT_TRUE;
    gbp_buf_manager->pipe_temp.link.rdma.sock = CS_INVALID_SOCKET;
    gbp_buf_manager->pipe_temp.link.rdma.closed = CT_TRUE;
}

/* start kernel's background workers in kernel */
status_t gbp_agent_start_client(knl_session_t *session)
{
    gbp_context_t *gbp_context = &session->kernel->gbp_context;
    gbp_buf_manager_t *gbp_buf_manager = gbp_context->gbp_buf_manager;
    knl_session_t **gbp_bg_sessions = gbp_context->gbp_bg_sessions;
    uint32 id;
    uint32 buf_size = MAX(GBP_MAX_REQ_BUF_SIZE, GBP_MAX_RESP_BUF_SIZE);

    for (id = 0; id < CT_GBP_SESSION_COUNT; id++) {
        gbp_init_connect_pipe(&gbp_buf_manager[id]);
        gbp_buf_manager[id].queue_id = id;
        gbp_bg_sessions[id] = NULL;
        gbp_context->batch_buf[id] = gbp_context->pipe_buf.aligned_buf + id * buf_size;
    }

    /* start gbp background threads */
    for (id = 0; id < CT_GBP_SESSION_COUNT; id++) {
        if (gbp_alloc_bg_session(id + 1, &gbp_bg_sessions[id]) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[GBP] failed to alloc gbp background session for index %u", id);
            return CT_ERROR;
        }

        if (cm_create_thread(gbp_bg_proc, 0, gbp_bg_sessions[id], &gbp_buf_manager[id].thread) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[GBP] failed to create background thread for index %u", id);
            gbp_release_bg_session(gbp_bg_sessions[id]); // other sessions are closed when gbp_bg_proc closed
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

void gbp_agent_stop_client(knl_session_t *session)
{
    gbp_context_t *gbp_context = &session->kernel->gbp_context;
    knl_session_t **gbp_bg_sessions = gbp_context->gbp_bg_sessions;

    /* stop gbp bg proc threads */
    for (uint32 id = 0; id < CT_GBP_SESSION_COUNT; id++) {
        gbp_bg_sessions[id]->killed = CT_TRUE;
        cm_close_thread(&gbp_context->gbp_buf_manager[id].thread);
        cs_disconnect(&gbp_context->gbp_buf_manager[id].pipe_const);
        gbp_context->gbp_buf_manager[id].is_connected = CT_FALSE;
        gbp_context->batch_buf[id] = NULL;
        CT_LOG_RUN_INF("[GBP] gbp bg proc %u closed", id);
    }
}

static status_t gbp_send_shake_hand(cs_pipe_t *pipe, uint32 queue_id, bool32 is_temp, bool32 is_standby)
{
    gbp_shake_hand_req_t req;
    gbp_shake_hand_resp_t resp;
    int32 recv_size;

    req.header.msg_type = GBP_REQ_SHAKE_HAND;

    req.is_standby = is_standby;
    req.is_temp = is_temp;
    req.queue_id = queue_id;

    if (cs_write_stream(pipe, (char *)&req, sizeof(req), 0) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (cs_read_stream(pipe, (char *)&resp, CT_MAX_WAIT_TIME, sizeof(resp), &recv_size) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (recv_size != sizeof(resp) ||
        GBP_MSG_TYPE(&resp.header) != GBP_REQ_SHAKE_HAND ||
        req.queue_id != resp.queue_id) {
        CT_LOG_RUN_ERR("[GBP] invalid shake hand response, type %u, recieve size %u",
                       GBP_MSG_TYPE(&resp.header), recv_size);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t gbp_init_connection(knl_session_t *session, gbp_buf_manager_t *gbp_buf_manager, const char *host,
                                    uint16 port, bool32 is_temp)
{
    char url[RDMA_HOST_PREFIX_LEN + CT_HOST_NAME_BUFFER_SIZE + CT_TCP_PORT_MAX_LENGTH] = { 0 };
    uint32 queue_id = gbp_buf_manager->queue_id;
    bool32 is_standby = DB_IS_PRIMARY(&session->kernel->db) ? CT_FALSE : CT_TRUE;
    cs_pipe_t *pipe = (is_temp) ? &gbp_buf_manager->pipe_temp : &gbp_buf_manager->pipe_const;
    errno_t ret;

    ret = memset_sp(pipe, sizeof(cs_pipe_t), 0, sizeof(cs_pipe_t));
    knl_securec_check(ret);
    ret = snprintf_s(url, sizeof(url), sizeof(url) - 1, "%s:%u", host, port);
    if (ret >= sizeof(url) || ret == -1) {
        CT_LOG_RUN_ERR("[GBP] Url %s is truncated", url);
        return CT_ERROR;
    }

    pipe->connect_timeout = GBP_CONNECT_TIMEOUT;
    if (cs_connect((const char *)url, pipe, NULL, NULL, NULL) != CT_SUCCESS) {
        CT_LOG_DEBUG_ERR("[GBP] failed to connect %s", url);
        return CT_ERROR;
    }

    if (gbp_send_shake_hand(pipe, queue_id, is_temp, is_standby) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[GBP] failed to send shake hand to %s", url);
        cs_disconnect(pipe);
        return CT_ERROR;
    }

    cm_reset_error();
    CT_LOG_RUN_INF("[GBP] connected to %s, queue id %u, is temp %d", url, queue_id, is_temp);
    return CT_SUCCESS;
}

static void gbp_get_server_host(knl_session_t *session, char *host, uint32 buf_size, uint32 addr_id)
{
    gbp_attr_t *gbp_attr = &session->kernel->gbp_attr;
    char* ip_addr = gbp_attr->server_addr[addr_id];
    errno_t ret;

    if (cm_str_equal_ins(gbp_attr->trans_type, "rdma")) {
        ret = snprintf_s(host, buf_size, buf_size - 1, RDMA_HOST_PREFIX"%s", ip_addr);
    } else {
        ret = snprintf_s(host, buf_size, buf_size - 1, "%s", ip_addr);
    }
    knl_securec_check_ss(ret);
}

bool32 gbp_promote_triggered(knl_handle_t knl_handle)
{
    knl_instance_t *kernel = (knl_instance_t *)knl_handle;

    if (knl_failover_triggered(kernel)) {
        return CT_TRUE;
    }
    return CT_FALSE;
}

void gbp_reset_server_hosts(knl_instance_t *kernel)
{
    gbp_attr_t *gbp_attr = &kernel->gbp_attr;
    errno_t ret;

    cm_spin_lock(&gbp_attr->addr_lock, NULL);
    if (!gbp_attr->server_addr_changed) {
        cm_spin_unlock(&gbp_attr->addr_lock);
        return;
    }

    for (uint32 i = 0; i < CT_MAX_LSNR_HOST_COUNT; i++) {
        ret = memcpy_sp(gbp_attr->server_addr[i], CM_MAX_IP_LEN,
                        gbp_attr->server_addr2[i], CM_MAX_IP_LEN);
        knl_securec_check(ret);
    }
    gbp_attr->server_count = gbp_attr->server_count2;
    gbp_attr->server_addr_changed = CT_FALSE;
    cm_spin_unlock(&gbp_attr->addr_lock);
}

/* Maintaining the connections between gbp backupground threads and GBP */
static void gbp_agent_proc(thread_t *thread)
{
    knl_session_t *session = (knl_session_t *)thread->argument;
    knl_instance_t *kernel = session->kernel;
    gbp_context_t *gbp_context = &kernel->gbp_context;
    gbp_buf_manager_t *managers = gbp_context->gbp_buf_manager;
    uint32 err_conn_num = 0;
    uint16 port = kernel->gbp_attr.lsnr_port;
    uint32 addr_id = 0;
    char host[RDMA_HOST_PREFIX_LEN + CT_HOST_NAME_BUFFER_SIZE] = { 0 };

    cm_set_thread_name("gbp_agent");
    CT_LOG_RUN_INF("[GBP] gbp_agent thread started");
    gbp_get_server_host(session, host, RDMA_HOST_PREFIX_LEN + CT_HOST_NAME_BUFFER_SIZE, addr_id);

    while (!thread->closed) {
        /*
         * if alter system set USE_GBP = FALSE, we just set GBP_OFF_TRIGGERED = TRUE
         * after failover running end, exit all GBP threads, then set USE_GBP = TRUE
         */
        if (KNL_GBP_OFF_TRIGGERED(kernel) && !KNL_RECOVERY_WITH_GBP(kernel) && !gbp_promote_triggered(kernel)) {
            kernel->gbp_aly_ctx.is_closing = CT_TRUE;
            thread->closed = CT_TRUE;
            break;
        }

        /* get gbp buffer manager communication channel */
        for (uint32 id = 0; id < CT_GBP_SESSION_COUNT; id++) {
            if (managers[id].is_connected) {
                continue;
            }
            gbp_reset_server_hosts(kernel);

            if (gbp_init_connection(session, &managers[id], host, port, CT_FALSE) != CT_SUCCESS) {
                managers[id].is_connected = CT_FALSE;
                if (err_conn_num < kernel->gbp_attr.server_count) {
                    err_conn_num++;
                    CT_LOG_RUN_ERR("[GBP] gbp connect failed, host %s", host);
                }
                if (kernel->gbp_attr.server_count != 0) {
                    addr_id = (addr_id + 1) % kernel->gbp_attr.server_count;
                }
                gbp_get_server_host(session, host, RDMA_HOST_PREFIX_LEN + CT_HOST_NAME_BUFFER_SIZE, addr_id);
                break; // switch server ip, retry next loop
            }
            managers[id].is_connected = CT_TRUE;
            managers[id].connected_id = addr_id;
            err_conn_num = 0;
        }
        cm_sleep(500);
    }

    gbp_agent_stop_client(session);
    cm_aligned_free(&gbp_context->pipe_buf);
    gbp_aly_mem_free(session);
    if (KNL_GBP_OFF_TRIGGERED(kernel)) {
        kernel->gbp_attr.use_gbp = CT_FALSE; // after exit all GBP threads, then set USE_GBP to FALSE
    }
}

bool32 gbp_page_is_usable(knl_session_t *session, page_id_t page_id, uint64 curr_page_lsn, uint64 gbp_page_lsn,
                          uint64 expect_lsn)
{
    knl_session_t *redo_session = session->kernel->sessions[SESSION_ID_KERNEL];
    bool32 use_gbp_page = CT_FALSE;
    uint64 disk_page_lsn = CT_INVALID_LSN;
    uint64 redo_curr_lsn = redo_session->curr_lsn;

    if (curr_page_lsn != CT_INVALID_LSN) { /* page is loaded from disk */
        if (gbp_page_lsn > curr_page_lsn) {
            /* gbp page can be used if gbp_page_lsn > curr_page_lsn */
            use_gbp_page = CT_TRUE;
        }
    } else { /* page not loaded from disk */
        if (!DB_NOT_READY(session) && gbp_page_lsn > redo_curr_lsn) {
            /* before failover done, redo_curr_lsn always >= page's lsn,
             * gbp_page_lsn > page lsn, gbp page can be used. after failover done, redo_curr_lsn == lrpl_end_lsn
             * when failover done, redo_curr_lsn will not increase, gbp_page_lsn must <= redo_curr_lsn
             */
            use_gbp_page = CT_TRUE;
        } else {
            /* need compare with page disk lsn, gbp page can be used if gbp_page_lsn >= disk_page_lsn */
            disk_page_lsn = gbp_get_disk_lsn(session, page_id, CT_FALSE);
            use_gbp_page = (gbp_page_lsn >= disk_page_lsn);
        }
    }

    CT_LOG_DEBUG_WAR("[GBP] %s page:%u-%u expected LSN:%llu, gbp LSN:%llu,"
                     "redo current LSN:%llu, page current LSN:%llu, page disk LSN:%llu",
                     (use_gbp_page ? "usable" : "old"), page_id.file, page_id.page, expect_lsn, gbp_page_lsn,
                     redo_curr_lsn, curr_page_lsn, disk_page_lsn);

    return use_gbp_page;
}

gbp_page_status_e gbp_page_verify(knl_session_t *session, page_id_t page_id, uint64 gbp_page_lsn,
                                  uint64 curr_page_lsn)
{
    gbp_analyse_item_t *item = gbp_aly_get_page_item(session, page_id);
    uint64 expect_lsn;

    /* page is not in aly_items, that means between gbp_skip_point and lrpl_end_point, no redo about this page */
    if (item == NULL) {
        session->stat->gbp_miss++;
        return GBP_PAGE_MISS;
    }

    if (item->is_verified == CT_TRUE) {
        session->stat->gbp_old++; // ensure that page refreshed as gbp page at most once.
        return GBP_PAGE_OLD;
    }
    item->is_verified = CT_TRUE;

    expect_lsn = item->lsn;
    knl_panic_log(expect_lsn > 0, "expect_lsn is abnormal, panic info: page %u-%u expect_lsn %llu", page_id.file,
                  page_id.page, expect_lsn);

    if (gbp_page_lsn == expect_lsn) {
        session->stat->gbp_hit++;
        return GBP_PAGE_HIT;
    }

    if (gbp_page_lsn < expect_lsn) {
        if (gbp_page_is_usable(session, page_id, curr_page_lsn, gbp_page_lsn, expect_lsn)) {
            session->stat->gbp_usable++;
            return GBP_PAGE_USABLE;
        } else {
            session->stat->gbp_old++;
            return GBP_PAGE_OLD;
        }
    }

    // will not happen, because gbp WAL, gbp_page_lsn must <= expect_lsn
    knl_panic_log(0, "[GBP] ahead page:%u-%u expected LSN:%llu, gbp LSN:%llu, page current LSN:%llu",
                  page_id.file, page_id.page, expect_lsn, gbp_page_lsn, curr_page_lsn);
    return GBP_PAGE_AHEAD;
}

/* in recover or failover lrpl, if this page has not been pulled by gbp background thread, we pull it immediately */
static gbp_page_status_e gbp_knl_pull_one_page(knl_session_t *session, buf_ctrl_t *ctrl)
{
    gbp_context_t *gbp_context = &session->kernel->gbp_context;
    gbp_read_req_t request;
    gbp_read_resp_t *response = NULL;
    uint32 gbp_proc_id = ctrl->page_id.page % CT_GBP_SESSION_COUNT;
    cs_pipe_t *pipe = gbp_get_client_pipe(gbp_context, gbp_proc_id, CT_TRUE);
    gbp_page_status_e page_status;

    GBP_SET_MSG_HEADER(&request, GBP_REQ_PAGE_READ, sizeof(gbp_read_req_t), cs_get_socket_fd(pipe));
    /* set message body */
    request.page_id = ctrl->page_id;
    request.buf_pool_id = ctrl->buf_pool_id;

    if (gbp_knl_send_request(pipe, (char *)&request, NULL) != CT_SUCCESS) {
        return GBP_PAGE_ERROR;
    }

    CM_SAVE_STACK(session->stack);
    response = (gbp_read_resp_t *)cm_push(session->stack, sizeof(gbp_read_resp_t));
    knl_panic(response != NULL);
    if (gbp_knl_wait_response(pipe, (char *)response, sizeof(gbp_read_resp_t)) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[GBP] gbp wait response failed while send request gbp_read_req");
        CM_RESTORE_STACK(session->stack);
        return GBP_PAGE_ERROR;
    }
    page_status = gbp_process_read_resp(session, response, ctrl);

    CM_RESTORE_STACK(session->stack);
    return page_status;
}

/*
 * temp connections with GBP, which are used to pull a few pages for user sessions
 * create when failover begine, and will be closed after all GBP pages are pulled to local buffer
 */
static status_t gbp_start_temp_connection(knl_session_t *session, gbp_context_t *gbp_context)
{
    knl_instance_t *kernel = session->kernel;
    gbp_buf_manager_t *manager = NULL;
    uint16 port = kernel->gbp_attr.lsnr_port;
    uint32 addr_id = gbp_context->gbp_buf_manager[0].connected_id;
    char host[RDMA_HOST_PREFIX_LEN + CT_HOST_NAME_BUFFER_SIZE] = { 0 };

    gbp_get_server_host(session, host, RDMA_HOST_PREFIX_LEN + CT_HOST_NAME_BUFFER_SIZE, addr_id);

    for (uint32 id = 0; id < CT_GBP_SESSION_COUNT; id++) {
        manager = &gbp_context->gbp_buf_manager[id];

        if (gbp_init_connection(session, manager, host, port, CT_TRUE) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static void gbp_stop_temp_connection(knl_session_t *session, gbp_context_t *gbp_context)
{
    gbp_buf_manager_t *manager = NULL;
    gbp_msg_hdr_t request;

    for (uint32 id = 0; id < CT_GBP_SESSION_COUNT; id++) {
        manager = &gbp_context->gbp_buf_manager[id];
        if ((manager->pipe_temp.type == CS_TYPE_NONE) ||
            (manager->pipe_temp.type == CS_TYPE_TCP && manager->pipe_temp.link.tcp.sock == CS_INVALID_SOCKET) ||
            (manager->pipe_temp.type == CS_TYPE_RSOCKET && manager->pipe_temp.link.rdma.sock == CS_INVALID_SOCKET)) {
            continue;
        }

        GBP_SET_MSG_HEADER(&request, GBP_REQ_CLOSE_CONN, sizeof(gbp_msg_hdr_t), cs_get_socket_fd(&manager->pipe_temp));

        if (cs_write_stream(&manager->pipe_temp, (char *)&request, request.msg_length, 0) != CT_SUCCESS) {
            CT_LOG_RUN_WAR("[GBP] failed to send connection close request, fd %d", request.msg_fd);
        }
        cm_sleep(1);
        cs_disconnect(&manager->pipe_temp);
    }

    CT_LOG_RUN_INF("[GBP] gbp temp connections are closed");
}

void gbp_enque_one_page(knl_session_t *session, buf_ctrl_t *ctrl)
{
    gbp_context_t *gbp_ctx = &session->kernel->gbp_context;
    uint32 queue_id = ctrl->page_id.page % CT_GBP_SESSION_COUNT;
    gbp_queue_t *queue = &gbp_ctx->queue[queue_id];

    cm_spin_lock(&queue->lock, &session->stat->spin_stat.stat_gbp_queue);

    ctrl->gbp_ctrl->gbp_trunc_point = queue->trunc_point;
    knl_panic_log(ctrl->gbp_ctrl->gbp_next == NULL, "the next gbp dirty page is valid, panic info: page %u-%u type %u",
                  ctrl->page_id.file, ctrl->page_id.page, ctrl->page->type);

    if (queue->first == NULL) {
        queue->first = ctrl;
        queue->last = ctrl;
    } else {
        queue->last->gbp_ctrl->gbp_next = ctrl;
        queue->last = ctrl;
    }
    queue->count++;

    cm_spin_unlock(&queue->lock);
}

void gbp_enque_pages(knl_session_t *session)
{
    for (uint32 i = 0; i < session->gbp_dirty_count; i++) {
        gbp_enque_one_page(session, session->gbp_dirty_pages[i]);
    }

    session->gbp_dirty_count = 0;
}

/* pop first and return the new first */
static buf_ctrl_t *gbp_pop_queue(knl_session_t *session, gbp_queue_t *queue, buf_ctrl_t *ctrl)
{
    cm_spin_lock(&queue->lock, &session->stat->spin_stat.stat_gbp_queue);
    queue->count--;

    knl_panic_log(queue->first == ctrl, "the first of gbp queue and ctrl are not same, panic info: page %u-%u type %u",
                  ctrl->page_id.file, ctrl->page_id.page, ctrl->page->type);
    if (queue->count == 0) {
        queue->first = NULL;
        queue->last = NULL;
    } else {
        queue->first = queue->first->gbp_ctrl->gbp_next;
    }
    ctrl->gbp_ctrl->gbp_next = NULL;

    cm_spin_unlock(&queue->lock);
    return queue->first;
}

void gbp_queue_set_gap(knl_session_t *session, buf_ctrl_t *ctrl)
{
    gbp_context_t *gbp_ctx = &session->kernel->gbp_context;
    uint32 queue_id = ctrl->page_id.page % CT_GBP_SESSION_COUNT;
    gbp_queue_t *queue = &gbp_ctx->queue[queue_id];

    if (queue->has_gap) {
        return;
    }

    queue->has_gap = CT_TRUE;
    CT_LOG_RUN_WAR("[GBP] gbp send queue: [%d] set gap", queue_id);
}

void gbp_queue_set_trunc_point(knl_session_t *session, log_point_t *point)
{
    log_context_t *redo_ctx = &session->kernel->redo_ctx;
    gbp_context_t *gbp_ctx = &session->kernel->gbp_context;
    gbp_queue_t *queue = NULL;

    if (!KNL_GBP_ENABLE(session->kernel)) {
        return;
    }

    /* this is possible during recovery if we set _GBP_DEBUG_MODE=RCYCHK */
    if (!DB_IS_OPEN(session)) {
        if (log_cmp_point(point, &redo_ctx->gbp_rcy_point) < 0) {
            return;
        }
    }

    for (uint32 id = 0; id < CT_GBP_SESSION_COUNT; id++) {
        queue = &gbp_ctx->queue[id];
        cm_spin_lock(&queue->lock, &session->stat->spin_stat.stat_gbp_queue);
        if (LOG_LFN_LT(queue->trunc_point, *point)) {
            queue->trunc_point = *point;
        }
        cm_spin_unlock(&queue->lock);
    }
}

uint64 gbp_queue_get_page_count(knl_session_t *session)
{
    gbp_context_t *gbp_ctx = &session->kernel->gbp_context;
    gbp_queue_t *queue = NULL;
    uint64 page_count = 0;

    for (uint32 id = 0; id < CT_GBP_SESSION_COUNT; id++) {
        queue = &gbp_ctx->queue[id];
        page_count += queue->count;
    }

    return page_count;
}

log_point_t gbp_queue_get_trunc_point(knl_session_t *session)
{
    gbp_context_t *gbp_ctx = &session->kernel->gbp_context;
    gbp_queue_t *queue = NULL;
    log_point_t trunc_point = gbp_ctx->queue[0].trunc_point;

    for (uint32 id = 0; id < CT_GBP_SESSION_COUNT; id++) {
        queue = &gbp_ctx->queue[id];
        cm_spin_lock(&queue->lock, &session->stat->spin_stat.stat_gbp_queue);
        if (queue->count != 0) {
            if (log_cmp_point(&queue->first->gbp_ctrl->gbp_trunc_point, &trunc_point) < 0) {
                trunc_point = queue->first->gbp_ctrl->gbp_trunc_point;
            }
        }
        cm_spin_unlock(&queue->lock);
    }

    return trunc_point;
}

void gbp_set_unsafe(knl_session_t *session, log_type_t type)
{
    log_context_t *redo_ctx = &session->kernel->redo_ctx;

    redo_ctx->gbp_aly_result.gbp_unsafe = CT_TRUE;
    redo_ctx->gbp_aly_result.unsafe_type = type;
}

void gbp_reset_unsafe(knl_session_t *session)
{
    log_context_t *redo_ctx = &session->kernel->redo_ctx;

    redo_ctx->gbp_aly_result.gbp_unsafe = CT_FALSE;
    CT_LOG_RUN_INF("[GBP] gbp reset to safe successfully");
}

/*
 * check if gbp can reset from unsafe to safe.
 * if replay beyond the unsafe redo and unsafe is caused by logic or space redo, gbp can reset to safe.
 */
void gbp_unsafe_redo_check(knl_session_t *session)
{
    log_context_t *redo_ctx = &session->kernel->redo_ctx;
    rcy_context_t *rcy_ctx = &session->kernel->rcy_ctx;
    uint64 rcy_curr_lsn = session->kernel->sessions[SESSION_ID_KERNEL]->curr_lsn;

    if (!KNL_GBP_ENABLE(session->kernel)) {
        return;
    }

    // in paral recovery, each repaly session has its lsn, redo current lsn is the max lsn
    // paralle recover must be compeleted here
    if (rcy_ctx->paral_rcy) {
        rcy_curr_lsn = 0;
        for (uint32 i = 0; i < rcy_ctx->capacity; i++) {
            rcy_curr_lsn = MAX(rcy_ctx->bucket[i].session->curr_lsn, rcy_curr_lsn);
        }
    }

    /* if gbp unsafe caused by unsafe redo log, can reset gbp status to safe */
    if (redo_ctx->gbp_aly_result.gbp_unsafe && redo_ctx->gbp_aly_result.unsafe_type < RD_TYPE_END) {
        /* if replay beyond the unsafe redo, gbp can reset to safe */
        if (rcy_curr_lsn > redo_ctx->gbp_aly_result.unsafe_max_lsn) {
            CT_LOG_RUN_INF("[GBP] gbp reset to safe because of replay lsn [%llu] beyond max unsafe redo lsn[%llu]",
                           rcy_curr_lsn, redo_ctx->gbp_aly_result.unsafe_max_lsn);
            gbp_reset_unsafe(session);
        }
    }
}

/* check if gbp is safe, retrun true if gbp can be used for failover */
bool32 gbp_pre_check(knl_session_t *session, log_point_t aly_end_point)
{
    log_context_t *redo_ctx = &session->kernel->redo_ctx;
    log_point_t init_point = { 0, 0, 0, 0 };

    if (DB_IS_CASCADED_PHYSICAL_STANDBY(&session->kernel->db)) {
        CT_LOG_RUN_WAR("[GBP] gbp is unsafe because database is cascaded standby");
        return CT_FALSE;
    }

    redo_ctx->gbp_begin_point = init_point;
    redo_ctx->gbp_rcy_point = init_point;
    redo_ctx->gbp_lrp_point = init_point;

    gbp_unsafe_redo_check(session);
    if (!KNL_GBP_SAFE(session->kernel)) {
        CT_LOG_RUN_WAR("[GBP] gbp is unsafe");
        return CT_FALSE;
    }

    if (aly_end_point.rst_id != dtc_my_ctrl(session)->rcy_point.rst_id) {
        gbp_set_unsafe(session, RD_TYPE_END);
        CT_LOG_RUN_WAR("[GBP] gbp unsafe because of redo end_point rst_id[%u] is not equal to rcy_point rst_id[%u]",
                       aly_end_point.rst_id, dtc_my_ctrl(session)->rcy_point.rst_id);
        return CT_FALSE;
    }

    CT_LOG_RUN_INF("[GBP] gbp is safe");
    return CT_TRUE;
}

/*
 * GBP window [A, B] means that GBP only contine all pages between log point A and log point B.
 * only LRPL replay current point is in [A, B], we can pull GBP pages and replace local pages
 */
bool32 gbp_replay_in_window(knl_session_t *session, log_point_t curr_point)
{
    log_context_t *redo = &session->kernel->redo_ctx;

    if (redo->gbp_begin_point.lfn == 0 || redo->gbp_rcy_point.lfn == 0) {
        return CT_FALSE; // point is invalid
    }

    if (LOG_LFN_GT(curr_point, redo->gbp_begin_point) && LOG_LFN_LT(curr_point, redo->gbp_rcy_point)) {
        return CT_TRUE;
    } else {
        CT_LOG_RUN_WAR("[GBP] replay current point %llu not in gbp window[%llu, %llu], continue replay redo log",
                       (uint64)curr_point.lfn, (uint64)redo->gbp_begin_point.lfn, (uint64)redo->gbp_rcy_point.lfn);
        return CT_FALSE;
    }
}

/* kernel read GBP checkpoints */
status_t gbp_knl_query_gbp_point(knl_session_t *session, gbp_read_ckpt_resp_t *response, bool32 check_end_point)
{
    gbp_context_t *gbp_context = &session->kernel->gbp_context;
    log_context_t *redo_ctx = &session->kernel->redo_ctx;
    gbp_read_ckpt_req_t request;
    gbp_buf_manager_t *manager = &gbp_context->gbp_buf_manager[0];
    cs_pipe_t *pipe = gbp_get_client_pipe(gbp_context, 0, CT_FALSE);

    cm_spin_lock(&manager->fisrt_pipe_lock, NULL); // concurrency with heart beat
    if (!manager->is_connected) {
        cm_spin_unlock(&manager->fisrt_pipe_lock);
        return CT_ERROR;
    }

    GBP_SET_MSG_HEADER(&request, GBP_REQ_READ_CKPT, sizeof(gbp_read_ckpt_req_t), cs_get_socket_fd(pipe));
    request.check_end_point = check_end_point;
    request.aly_end_point = redo_ctx->redo_end_point;

    if (gbp_knl_send_request(pipe, (char *)&request, manager) != CT_SUCCESS) {
        cm_spin_unlock(&manager->fisrt_pipe_lock);
        return CT_ERROR;
    }

    if (gbp_knl_wait_response(pipe, (char *)response, sizeof(gbp_read_ckpt_resp_t)) != CT_SUCCESS) {
        cs_disconnect(pipe);
        manager->is_connected = CT_FALSE;
        cm_spin_unlock(&manager->fisrt_pipe_lock);
        return CT_ERROR;
    }

    cm_spin_unlock(&manager->fisrt_pipe_lock);

    if (response->gbp_unsafe) {
        gbp_context->gbp_window_start = 0;
        gbp_context->gbp_window_end = 0;
    } else {
        gbp_context->gbp_window_start = response->begin_point.lfn;
        gbp_context->gbp_window_end = response->rcy_point.lfn;
    }

    return CT_SUCCESS;
}

/* kernel notify GBP check redo end point */
void gbp_knl_check_end_point(knl_session_t *session)
{
    log_context_t *redo_ctx = &session->kernel->redo_ctx;
    gbp_read_ckpt_resp_t response;

    if (gbp_knl_query_gbp_point(session, &response, CT_TRUE) != CT_SUCCESS) {
        gbp_set_unsafe(session, RD_TYPE_END);
        CT_LOG_RUN_WAR("[GBP] gbp unsafe because failed to query gbp point");
        return;
    }

    gbp_process_read_ckpt_resp(session, &response, redo_ctx);
}

void gbp_refresh_gbp_window(knl_session_t *session, uint32 gbp_proc_id)
{
    gbp_context_t *gbp_context = &session->kernel->gbp_context;
    gbp_read_ckpt_resp_t response;

    if (gbp_proc_id != 0) {
        return;
    }

    if (gbp_knl_query_gbp_point(session, &response, CT_FALSE) != CT_SUCCESS) {
        gbp_context->gbp_window_start = 0;
        gbp_context->gbp_window_end = 0;
    }
}

/* kernel try read one page from GBP */
gbp_page_status_e knl_read_page_from_gbp(knl_session_t *session, buf_ctrl_t *ctrl)
{
    gbp_page_status_e page_status;
    datafile_t *df = DATAFILE_GET(session, ctrl->page_id.file);
    space_t *space = SPACE_GET(session, df->space_id);

    /* no redo log for the page, page would not exists on GBP */
    if (gbp_aly_get_page_lsn(session, ctrl->page_id) == CT_INVALID_LSN) {
        return GBP_PAGE_MISS;
    }
    if (SPACE_IS_NOLOGGING(space)) {
        return GBP_PAGE_MISS;
    }

    session->stat->gbp_knl_read++;
    page_status = gbp_knl_pull_one_page(session, ctrl);
    if (page_status == GBP_PAGE_ERROR) {
        CM_ABORT(0, "[GBP] ABORT INFO: instance must exit beacause of failed to read page from GBP");
    }

    if (page_status == GBP_PAGE_MISS) {
        CT_LOG_DEBUG_INF("[GBP] kernel read page from GBP: page: %u-%u not found on GBP",
                         ctrl->page_id.file, ctrl->page_id.page);
        session->stat->gbp_miss++;
        return GBP_PAGE_MISS;
    }

    return page_status;
}

/*
 * when failover is triggered, and GBP log analysis status is safe, we can use GBP to accelerate LRPL speed
 * let kernel's background worker start to read page from gbp, move forward lrpl point and update gbp_read_version
 */
void gbp_knl_begin_read(knl_session_t *session, log_point_t *curr_point)
{
    gbp_context_t *gbp_context = &session->kernel->gbp_context;
    log_context_t *redo = &session->kernel->redo_ctx;
    gbp_msg_ack_t ack;

    if (gbp_start_temp_connection(session, gbp_context) != CT_SUCCESS) {
        gbp_set_unsafe(session, RD_TYPE_END);
        gbp_stop_temp_connection(session, gbp_context); // close temp connections which have been created
        CT_LOG_RUN_WAR("[GBP] gbp unsafe because can not start temp connection");
        return;
    }

    if (gbp_notify_msg(session, MSG_GBP_READ_BEGIN, 0, &ack) != CT_SUCCESS) {
        gbp_set_unsafe(session, RD_TYPE_END);
        gbp_stop_temp_connection(session, gbp_context);
        CT_LOG_RUN_WAR("[GBP] gbp unsafe because can not notify GBP");
        return;
    }

    gbp_context->gbp_read_completed = CT_FALSE;
    gbp_context->gbp_read_thread_num = CT_GBP_SESSION_COUNT;
    gbp_context->gbp_read_version++;

    for (uint32 id = 0; id < gbp_context->gbp_read_thread_num; id++) {
        gbp_context->gbp_buf_manager[id].gbp_reading = CT_TRUE;
    }

    CT_LOG_RUN_INF("[GBP] recover use gbp, lfn gap: %llu. curr_point:[%llu-%u-%llu],"
                   "gbp begin point:[%llu-%u-%llu], gbp rcy point:[%llu-%u-%llu]",
                   (uint64)(redo->redo_end_point.lfn - redo->gbp_rcy_point.lfn),
                   (uint64)curr_point->rst_id, curr_point->asn, (uint64)curr_point->lfn,
                   (uint64)redo->gbp_begin_point.rst_id, redo->gbp_begin_point.asn, (uint64)redo->gbp_begin_point.lfn,
                   (uint64)redo->gbp_rcy_point.rst_id, redo->gbp_rcy_point.asn, (uint64)redo->gbp_rcy_point.lfn);
    CT_LOG_RUN_INF("[GBP] current gbp page version %u", gbp_context->gbp_read_version);

    gbp_context->gbp_begin_read_time = cm_now();

    redo->last_rcy_with_gbp = CT_TRUE;
    redo->gbp_rcy_lfn = redo->gbp_rcy_point.lfn;
    redo->gbp_skip_point = *curr_point; // when use gbp, we skip some redo after gbp_skip_point
#ifdef LOG_DIAG
    if (session->kernel->gbp_attr.gbp_debug_rcy_check) {
        redo->rcy_with_gbp = CT_TRUE;
        CT_LOG_RUN_WAR("[GBP DEBUG] curr_point is not move forward");
        return; // if debug check enable, do not move forward curr_point, the GBP pages will checked when redo replay
    }
#endif
    /* set gbp_trunc_point, skip replaying redo between curr_point point and redo->gbp_rcy_point */
    *curr_point = redo->gbp_rcy_point;  // move forward lrpl current point, skip [gbp_skip_point, gbp_rcy_point]
    gbp_queue_set_trunc_point(session, &redo->gbp_rcy_point);
    log_reset_point(session, &redo->gbp_rcy_point);

    redo->lfn = redo->gbp_rcy_point.lfn;
    CM_MFENCE;
    redo->rcy_with_gbp = CT_TRUE; // after set to TRUE, DN start pull pages from GBP
    CT_LOG_RUN_INF("[GBP] begin read GBP pages");
}

static void gbp_verify_skiped_redo_pages(knl_session_t *session)
{
    log_context_t *ctx = &session->kernel->redo_ctx;
    gbp_analyse_item_t *aly_items = ctx->gbp_aly_items;
    uint64 skip_start = ctx->gbp_skip_point.lfn;
    uint64 skip_end = ctx->gbp_rcy_point.lfn;

    CT_LOG_RUN_INF("[GBP] begin to verify pages that belong to skiped redo logs");
    for (uint32 i = 0; i < GBP_ALY_MAX_ITEM; i++) {
        if (aly_items[i].lfn >= skip_start && aly_items[i].lfn < skip_end) {
            knl_panic_log(aly_items[i].is_verified > 0, "[GBP] page %u-%u is not pulled, instance must exit",
                          aly_items[i].page_id.file, aly_items[i].page_id.page);
        }
    }
    CT_LOG_RUN_INF("[GBP] end to verify pages that belong to skiped redo logs");
}

/*
 * after pull all GBP pages to local buffer or db start, kernel notify GBP server to stop send page.
 * then close all temp connections with GBP
 */
void gbp_knl_end_read(knl_session_t *session)
{
    gbp_context_t *gbp_context = &session->kernel->gbp_context;
    log_context_t *redo = &session->kernel->redo_ctx;
    uint32 gbp_proc_id = session->gbp_queue_index - 1;
    int32 lock_id;

    gbp_context->gbp_read_completed = CT_TRUE;
    gbp_context->gbp_end_read_time = cm_now();
    CT_LOG_RUN_INF("[GBP] read page from gbp completed, used time %llums",
                   (cm_now() - gbp_context->gbp_begin_read_time) / MICROSECS_PER_MILLISEC);

    for (lock_id = 0; lock_id < CT_GBP_RD_LOCK_COUNT; lock_id++) {
        cm_spin_lock(&gbp_context->buf_read_lock[lock_id], NULL); // lock 8 gbp read locks
    }

    if (gbp_notify_msg(session, MSG_GBP_READ_END, gbp_proc_id, NULL) != CT_SUCCESS) {
        CT_LOG_RUN_WAR("[GBP] failed to notify GBP read page end");
    }
    gbp_verify_skiped_redo_pages(session);

    /* concurrency with buf_load_page_from_GBP */
    redo->rcy_with_gbp = CT_FALSE;

    for (lock_id = CT_GBP_RD_LOCK_COUNT - 1; lock_id >= 0; lock_id--) {
        cm_spin_unlock(&gbp_context->buf_read_lock[lock_id]); // unlock 8 gbp read locks
    }

    /* when read from GBP end, stop temp connections */
    gbp_stop_temp_connection(session, gbp_context);
}

/*
 * init gbp process when db start
 * 1. start gbp background workers, which process dirty pages between kernel and GBP
 * 2. start gbp_agent_proc, which maintains the connections with GBP
 */
status_t gbp_agent_start(knl_session_t *session)
{
    gbp_context_t *gbp_context = &session->kernel->gbp_context;
    uint32 buf_size = MAX(GBP_MAX_REQ_BUF_SIZE, GBP_MAX_RESP_BUF_SIZE) * CT_GBP_SESSION_COUNT;
    errno_t ret;

    ret = memset_sp(gbp_context, sizeof(gbp_context_t), 0, sizeof(gbp_context_t));
    knl_securec_check(ret);

    gbp_context->gbp_read_completed = CT_TRUE;

    if (cm_aligned_malloc((int64)buf_size, "gbp pipe buffer", &gbp_context->pipe_buf) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (gbp_aly_mem_init(session) != CT_SUCCESS) { // redo analysis memory, free when gbp_agent_proc quit
        cm_aligned_free(&gbp_context->pipe_buf);
        return CT_ERROR;
    }

    if (gbp_agent_start_client(session) != CT_SUCCESS) {
        gbp_agent_stop_client(session); // release gbp_bg_procs which have been created
        cm_aligned_free(&gbp_context->pipe_buf);
        gbp_aly_mem_free(session);
        return CT_ERROR;
    }

    if (cm_create_thread(gbp_agent_proc, 0, session, &gbp_context->gbp_agent_thread) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[GBP] gbp agent thread create failed");
        gbp_agent_stop_client(session);
        cm_aligned_free(&gbp_context->pipe_buf);
        gbp_aly_mem_free(session);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

void gbp_agent_close(knl_session_t *session)
{
    gbp_context_t *gbp_context = &session->kernel->gbp_context;

    cm_close_thread(&gbp_context->gbp_agent_thread);
}

/* ------------------------ Log analysis fuctions  ------------------------------- */
status_t gbp_aly_mem_init(knl_session_t *session)
{
    log_context_t *ctx = &session->kernel->redo_ctx;
    gbp_analyse_bucket_t *free_list = &ctx->gbp_aly_free_list;
    int64 buf_size = GBP_ALY_MAX_ITEM_SIZE + GBP_ALY_MAX_BUCKET_SIZE; // 176M
    errno_t ret;

    if (!KNL_GBP_ENABLE(session->kernel)) {
        CT_LOG_RUN_INF("gbp is off, log analysis memory will not malloc");
        return CT_SUCCESS;
    }

    if (ctx->gbp_aly_items == NULL) { // fisrt alloc memory at db_mount, free memory at db_close
        if (cm_aligned_malloc(buf_size, "log analysis", &ctx->gbp_aly_mem) != CT_SUCCESS) {
            return CT_ERROR;
        }
        ctx->gbp_aly_items = (gbp_analyse_item_t *)ctx->gbp_aly_mem.aligned_buf;
        ctx->gbp_aly_buckets = (gbp_analyse_bucket_t *)(ctx->gbp_aly_mem.aligned_buf + GBP_ALY_MAX_ITEM_SIZE);
    }

    ret = memset_sp(ctx->gbp_aly_items, GBP_ALY_MAX_ITEM_SIZE, 0, GBP_ALY_MAX_ITEM_SIZE); // 160M
    knl_securec_check(ret);
    ret = memset_sp(ctx->gbp_aly_buckets, GBP_ALY_MAX_BUCKET_SIZE, 0, GBP_ALY_MAX_BUCKET_SIZE); // 16M
    knl_securec_check(ret);

    free_list->count = GBP_ALY_MAX_ITEM;
    free_list->first = &ctx->gbp_aly_items[0];
    for (uint32 i = 0; i < GBP_ALY_MAX_ITEM - 1; i++) {
        ctx->gbp_aly_items[i].next = &ctx->gbp_aly_items[i + 1]; // init free list
    }

    return CT_SUCCESS;
}

/* free memory at db_close or alter system set USE_GBP = FALSE */
void gbp_aly_mem_free(knl_session_t *session)
{
    log_context_t *ctx = &session->kernel->redo_ctx;
    gbp_aly_ctx_t *aly = &session->kernel->gbp_aly_ctx;

    while (aly->is_started && !aly->is_done) {
        cm_sleep(1); // wait gbp_aly_proc exit
    }

    aly->is_started = CT_FALSE;
    cm_aligned_free(&ctx->gbp_aly_mem);
    ctx->gbp_aly_items = NULL;
    ctx->gbp_aly_buckets = NULL;
}

gbp_analyse_item_t *gbp_aly_pop_free_item(knl_session_t *session)
{
    log_context_t *ctx = &session->kernel->redo_ctx;
    gbp_analyse_bucket_t *free_list = &ctx->gbp_aly_free_list;
    gbp_analyse_item_t *item = NULL;

    if (free_list->first == NULL) {
        return NULL;
    }

    item = free_list->first;
    free_list->first = item->next;
    free_list->count--;
    item->next = NULL;

    return item;
}

/* if item.lfn < rcy_point.lfn, this item can be recycled, because this item page has been flush to disk */
void gbp_aly_recycle_old_item(knl_session_t *session, gbp_analyse_bucket_t *bucket)
{
    gbp_analyse_bucket_t *free_list = &session->kernel->redo_ctx.gbp_aly_free_list;
    gbp_analyse_item_t *item = NULL;
    gbp_analyse_item_t *prev = NULL;
    gbp_analyse_item_t *next = NULL;

    item = bucket->first;
    while (item != NULL) {
        next = item->next;
        if ((uint64)item->lfn < dtc_my_ctrl(session)->rcy_point.lfn) { /* if this item can be reused */
            if (prev == NULL) {
                bucket->first = next;
            } else {
                prev->next = next;
            }
            item->is_verified = 0;
            item->page_id.file = 0;
            item->page_id.page = 0;
            item->lsn = 0;
            item->lfn = 0;

            item->next = free_list->first;
            free_list->first = item;
            free_list->count++;
            bucket->count--;
        } else {
            prev = item;
        }

        item = next;
    }
}

void gbp_aly_do_recycle(knl_session_t *session, gbp_analyse_item_t **new_item)
{
    log_context_t *ctx = &session->kernel->redo_ctx;
    gbp_aly_ctx_t *aly = &session->kernel->gbp_aly_ctx;
    date_t now_time = g_timer()->now;
    date_t last_time = MIN(aly->last_recycle_time, now_time);
    if ((now_time - last_time) < GBP_RECYCLE_TIMEOUT) {
        return;
    }

    for (uint32 i = 0; i < GBP_ALY_MAX_FILE * GBP_ALY_MAX_BUCKET_PER_FILE; i++) {
        gbp_aly_recycle_old_item(session, &ctx->gbp_aly_buckets[i]); // try recycle all gbp aly buckets
    }
    aly->last_recycle_time = now_time;
    *new_item = gbp_aly_pop_free_item(session);
    CT_LOG_DEBUG_WAR("[GBP] free all gbp aly buckets");
}

static inline void gbp_aly_set_item(gbp_analyse_item_t *item, uint64 lsn, uint64 lfn)
{
    item->lsn = lsn;
    item->lfn = lfn;
}

void gbp_aly_set_page_lsn(knl_session_t *session, page_id_t page_id, uint64 lsn, uint64 lfn)
{
    log_context_t *ctx = &session->kernel->redo_ctx;
    gbp_analyse_item_t *item = NULL;
    gbp_analyse_item_t *reuse_item = NULL;
    gbp_analyse_item_t *new_item = NULL;
    uint32 file_hash = page_id.file % GBP_ALY_MAX_FILE;
    uint32 page_hash = page_id.page % GBP_ALY_MAX_BUCKET_PER_FILE;
    gbp_analyse_bucket_t *bucket = &ctx->gbp_aly_buckets[file_hash * GBP_ALY_MAX_BUCKET_PER_FILE + page_hash];

    item = bucket->first;
    while (item != NULL) {
        knl_panic_log(item->lsn != CT_INVALID_LSN, "lsn is invalid, panic info: page %u-%u lsn %llu", page_id.file,
                      page_id.page, item->lsn);
        if (IS_SAME_PAGID(item->page_id, page_id)) {
            gbp_aly_set_item(item, lsn, lfn);
            return;
        }

        if (reuse_item == NULL && (uint64)item->lfn < dtc_my_ctrl(session)->rcy_point.lfn) { /* if this item can be
                                                                                                reused */
            reuse_item = item;
        }
        item = item->next;
    }

    /* if same page id item is not found, try reuse one item */
    if (reuse_item != NULL) {
        gbp_aly_set_item(reuse_item, lsn, lfn);
        reuse_item->page_id = page_id;
        ctx->replay_stat.analyze_new_pages++;
        return;
    }

    /* if same page id item or reuse item is not found, add one free item */
    new_item = gbp_aly_pop_free_item(session);
    if (new_item == NULL) {
        gbp_aly_do_recycle(session, &new_item);
    }

    if (new_item != NULL) {
        new_item->next = bucket->first;
        bucket->first = new_item;
        bucket->count++;
        gbp_aly_set_item(new_item, lsn, lfn);
        new_item->page_id = page_id;
        ctx->replay_stat.analyze_new_pages++;
        return;
    }

    if (!ctx->gbp_aly_result.gbp_unsafe) {
        CT_LOG_RUN_WAR("[GBP] gbp unsafe because of analyze overflow, page %u-%u", page_id.file, page_id.page);
    }
    gbp_set_unsafe(session, RD_TYPE_END);
}

uint32 gbp_aly_free_space_percent(knl_session_t *session)
{
    log_context_t *ctx = &session->kernel->redo_ctx;

    if (ctx->gbp_aly_items == NULL) {
        return 0;
    }

    return (ctx->gbp_aly_free_list.count * 100 / GBP_ALY_MAX_ITEM); // calculate percent
}

gbp_analyse_item_t *gbp_aly_get_page_item(knl_session_t *session, page_id_t page_id)
{
    log_context_t *ctx = &session->kernel->redo_ctx;
    gbp_analyse_item_t *item = NULL;
    uint32 file_hash = page_id.file % GBP_ALY_MAX_FILE;
    uint32 page_hash = page_id.page % GBP_ALY_MAX_BUCKET_PER_FILE;
    gbp_analyse_bucket_t *bucket = &ctx->gbp_aly_buckets[file_hash * GBP_ALY_MAX_BUCKET_PER_FILE + page_hash];

    item = bucket->first;
    while (item != NULL) {
        if (IS_SAME_PAGID(item->page_id, page_id)) {
            return item;
        }

        item = item->next;
    }

    return NULL;
}

uint64 gbp_aly_get_page_lsn(knl_session_t *session, page_id_t page_id)
{
    gbp_analyse_item_t *item = NULL;

    if (session->kernel->gbp_context.gbp_agent_thread.closed) {
        return CT_INVALID_LSN;
    }

    item = gbp_aly_get_page_item(session, page_id);
    return (item == NULL) ? CT_INVALID_LSN : item->lsn;
}

/*
 * analyze redo log, only running when GBP is enabled. it dose not replay redo expect txn page
 * it will record all page's latest lsn
 */
static status_t gbp_aly_analyze(knl_session_t *session, log_point_t *point, uint32 data_size, log_batch_t *batch,
                                uint32 block_size)
{
    bool32 need_more = CT_FALSE;

    if (rcy_analysis(session, point, data_size, batch, block_size, &need_more) != CT_SUCCESS) {
        CT_LOG_RUN_INF("[GBP] failed to analyze log at point [%u-%u/%u/%llu]",
                       point->rst_id, point->asn, point->block_id, (uint64)point->lfn);
        return CT_ERROR;
    }

    if (!need_more) {
        CT_LOG_RUN_INF("[GBP] failed to analyze log at point [%u-%u/%u/%llu], no more log needed",
                       point->rst_id, point->asn, point->block_id, (uint64)point->lfn);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

/* like lrpl, gbp analyze proc will read and analyze all standby redo log */
status_t gbp_aly_perform(knl_session_t *session, log_point_t *point)
{
    gbp_aly_ctx_t *aly_ctx = &session->kernel->gbp_aly_ctx;
    log_context_t *log = &session->kernel->redo_ctx;
    uint32 data_size = 0;
    uint32 file_id;
    uint32 block_size;

    log_lock_logfile(session);
    file_id = log_get_id_by_asn(session, (uint32)point->rst_id, point->asn, &aly_ctx->loading_curr_file);
    log_unlock_logfile(session);

    if (file_id == CT_INVALID_ID32) {
        bool32 reset = CT_FALSE;
        if (lrpl_prepare_archfile(session, point, &reset) != CT_SUCCESS) {
            CT_LOG_RUN_INF("[GBP] failed to prepare archive log at point [%u-%u/%u/%llu]",
                           point->rst_id, point->asn, point->block_id, (uint64)point->lfn);
            return CT_ERROR;
        }
        if (reset) {
            return CT_SUCCESS;
        }

        if (rcy_load_from_arch(session, point, &data_size, &aly_ctx->arch_file, &aly_ctx->read_buf) != CT_SUCCESS) {
            CT_LOG_RUN_INF("[GBP] failed to load archive log at point [%u-%u/%u/%llu]",
                           point->rst_id, point->asn, point->block_id, (uint64)point->lfn);
            return CT_ERROR;
        }
        block_size = (uint32)aly_ctx->arch_file.head.block_size;
    } else {
        if (rcy_load_from_online(session, file_id, point, &data_size, aly_ctx->log_handle + file_id,
                                 &aly_ctx->read_buf) != CT_SUCCESS) {
            CT_LOG_RUN_INF("[GBP] failed to load online log[%u] at point [%u-%u/%u/%llu]",
                           file_id, point->rst_id, point->asn, point->block_id, (uint64)point->lfn);
            return CT_ERROR;
        }
        block_size = log->files[file_id].ctrl->block_size;
    }

    log_batch_t *batch = (log_batch_t *)aly_ctx->read_buf.aligned_buf;
    if (gbp_aly_analyze(session, point, data_size, batch, block_size) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static void gbp_free_aly_proc_context(knl_session_t *aly_session, gbp_aly_ctx_t *aly_ctx)
{
    cm_close_file(aly_ctx->arch_file.handle);
    aly_ctx->arch_file.handle = INVALID_FILE_HANDLE;

    for (uint32 i = 0; i < CT_MAX_LOG_FILES; i++) {
        cm_close_file(aly_ctx->log_handle[i]);
        aly_ctx->log_handle[i] = INVALID_FILE_HANDLE;
    }

    cm_aligned_free(&aly_ctx->read_buf);
    cm_aligned_free(&aly_ctx->log_decrypt_buf);
    cm_aligned_free(&aly_ctx->bucket_buf);
    gbp_release_bg_session(aly_session);
    aly_ctx->sid = CT_INVALID_ID32;
}

/*
 * log analysis thread, run when gbp enabled on standby
 * like lrpl, it read and analyze redo log to get page latest lsn
 */
static void gbp_aly_proc(thread_t *thread)
{
    knl_session_t *session = (knl_session_t *)thread->argument;
    gbp_aly_ctx_t *aly = &session->kernel->gbp_aly_ctx;
    log_context_t *redo_ctx = &session->kernel->redo_ctx;
    bool32 sleep_needed = CT_FALSE;

    cm_set_thread_name("gbp_aly");
    CT_LOG_RUN_INF("gbp aly thread started");
    KNL_SESSION_SET_CURR_THREADID(session, thread->id);

    aly->curr_point = redo_ctx->curr_point;
    aly->begin_point = aly->curr_point;
    aly->is_started = CT_TRUE;
    aly->is_done = CT_FALSE;
    redo_ctx->analysis_lfn = aly->curr_point.lfn;

    while (!thread->closed) {
        if (aly->is_closing) {
            break;
        }

        if (sleep_needed && gbp_promote_triggered(session->kernel)) {
            CT_LOG_RUN_INF("[GBP] log analysis failover triggered");

            redo_ctx->redo_end_point = aly->curr_point;
            if (gbp_pre_check(session, redo_ctx->redo_end_point)) {
                gbp_knl_check_end_point(session);
            }
            break;
        }
        if (sleep_needed) {
            cm_sleep(10);
        }

        if (!lrpl_need_replay(session, &aly->curr_point)) {
            sleep_needed = CT_TRUE;
            continue;
        }

        if (gbp_aly_perform(session, &aly->curr_point) != CT_SUCCESS) {
            redo_ctx->redo_end_point = aly->curr_point;
            aly->has_gap = CT_TRUE;
            CT_LOG_RUN_WAR("[GBP] gbp analysis failed");
            break;
        }

        sleep_needed = CT_FALSE;
    }

    cm_close_thread(&aly->page_bucket.thread);
    aly->is_done = CT_TRUE;
    aly->end_time = cm_now();
    CT_LOG_RUN_INF("[GBP] log analysis end with log point: rst_id %u asn %u lfn %llu block_id %u",
                   aly->curr_point.rst_id, aly->curr_point.asn, (uint64)aly->curr_point.lfn,
                   aly->curr_point.block_id);

    gbp_free_aly_proc_context(session, aly);
    KNL_SESSION_CLEAR_THREADID(session);
    thread->closed = CT_TRUE;
}

void gbp_aly_page_proc(thread_t *thread)
{
    knl_session_t *session = (knl_session_t *)thread->argument;
    gbp_aly_ctx_t *aly = &session->kernel->gbp_aly_ctx;
    gbp_page_bucket_t *bucket = &aly->page_bucket;
    date_t last_time = g_timer()->now;
    gbp_aly_page_t ctrl;
    uint32 tail;

    cm_set_thread_name("gbp_page_proc");
    CT_LOG_RUN_INF("gbp page thread started");
    for (;;) {
        if (bucket->head == bucket->tail) {
            if (thread->closed) {
                break;
            }

            if (g_timer()->now - last_time > RCY_SLEEP_TIME_THRESHOLD) {
                cm_sleep(10);
            } else {
                cm_spin_sleep();
            }
            continue;
        }

        cm_spin_lock(&bucket->lock, NULL);
        tail = bucket->tail;
        cm_spin_unlock(&bucket->lock);

        if (bucket->head == tail) {
            cm_spin_sleep();
            continue;
        }
        last_time = g_timer()->now;

        while (bucket->head != tail) {
            ctrl = bucket->first[bucket->head];
            gbp_aly_set_page_lsn(session, ctrl.page_id, ctrl.lsn, ctrl.lfn);
            bucket->head = (bucket->head + 1) % bucket->count;
        }
    }
    CT_LOG_RUN_INF("gbp page thread closed");
}

/* init gbp analyze memory and start gbp analyze proc */
status_t gbp_aly_init(knl_session_t *session)
{
    gbp_aly_ctx_t *aly_ctx = &session->kernel->gbp_aly_ctx;
    knl_session_t *aly_session = NULL;

    errno_t ret = memset_sp(aly_ctx, sizeof(gbp_aly_ctx_t), 0, sizeof(gbp_aly_ctx_t));
    knl_securec_check(ret);

    aly_ctx->arch_file.handle = INVALID_FILE_HANDLE;
    for (uint32 i = 0; i < CT_MAX_LOG_FILES; i++) {
        aly_ctx->log_handle[i] = INVALID_FILE_HANDLE;
    }

    if (gbp_alloc_bg_session(0, &aly_session) != CT_SUCCESS) {
        return CT_ERROR;
    }

    /* redo analysis memory is alloced in gbp_agent_start when db_mount, if switchover as standby, need reset memory */
    if (gbp_aly_mem_init(session) != CT_SUCCESS) {
        gbp_free_aly_proc_context(aly_session, aly_ctx);
        return CT_ERROR;
    }

    if (cm_aligned_malloc(CT_MAX_BATCH_SIZE, "log analysis read buffer", &aly_ctx->read_buf) != CT_SUCCESS) {
        gbp_free_aly_proc_context(aly_session, aly_ctx);
        return CT_ERROR;
    }

    if (cm_aligned_malloc((int64)session->kernel->attr.lgwr_cipher_buf_size, "log analysis decrypt buffer",
                          &aly_ctx->log_decrypt_buf) != CT_SUCCESS) {
        gbp_free_aly_proc_context(aly_session, aly_ctx);
        return CT_ERROR;
    }

    if (cm_aligned_malloc((int64)GBP_ALY_PAGE_BUCKET_SIZE, "log analysis bucket buffer",
                          &aly_ctx->bucket_buf) != CT_SUCCESS) {
        gbp_free_aly_proc_context(aly_session, aly_ctx);
        return CT_ERROR;
    }

    aly_ctx->sid = aly_session->id;
    aly_ctx->page_bucket.first = (gbp_aly_page_t *)aly_ctx->bucket_buf.aligned_buf;
    aly_ctx->page_bucket.count = GBP_ALY_PAGE_COUNT;
    aly_ctx->page_bucket.head = 0;
    aly_ctx->page_bucket.tail = 0;
    aly_ctx->page_bucket.lock = 0;
    aly_ctx->begin_time = cm_now();

    if (cm_create_thread(gbp_aly_page_proc, 0, aly_session, &aly_ctx->page_bucket.thread) != CT_SUCCESS) {
        gbp_free_aly_proc_context(aly_session, aly_ctx);
        return CT_ERROR;
    }

    if (cm_create_thread(gbp_aly_proc, 0, aly_session, &aly_ctx->thread) != CT_SUCCESS) {
        cm_close_thread(&aly_ctx->page_bucket.thread);
        gbp_free_aly_proc_context(aly_session, aly_ctx);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

void gbp_aly_close(knl_session_t *session)
{
    gbp_aly_ctx_t *aly_ctx = &session->kernel->gbp_aly_ctx;

    aly_ctx->is_closing = CT_TRUE;
    cm_close_thread(&aly_ctx->thread);
    CT_LOG_RUN_INF("[GBP] gbp aly thread is closed successfully");
}

/* some redo type is unsafe to gbp, when find these redo, set gbp unsafe status and max unsafe lsn */
void gbp_aly_unsafe_entry(knl_session_t *session, log_entry_t *log, uint64 lsn)
{
    log_context_t *ctx = &session->kernel->redo_ctx;

    ctx->gbp_aly_result.unsafe_max_lsn = lsn;

    if (!ctx->gbp_aly_result.gbp_unsafe) {
        CT_LOG_RUN_WAR("[GBP] gbp unsafe because of redo log type: %u, lsn: %llu", log->type, lsn);
        if (log->type == RD_LOGIC_OPERATION) {
            CT_LOG_RUN_WAR("[GBP] unsafe logic type: %u", *((logic_op_t *)log->data));
        }
    }
    gbp_set_unsafe(session, log->type);
}

void gbp_aly_safe_entry(knl_session_t *session, log_entry_t *log, uint64 lsn)
{
    knl_panic(session->curr_page_ctrl == NULL || !BUF_IS_RESIDENT(session->curr_page_ctrl));
}

/* get last point of online redo */
status_t gbp_aly_get_file_end_point(knl_session_t *session, log_point_t *point, uint16 file_id)
{
    log_context_t *redo_ctx = &session->kernel->redo_ctx;
    log_file_t *file = NULL;

    if (file_id == CT_INVALID_ID16) {
        return CT_ERROR;
    }
    file = &redo_ctx->files[file_id];

    point->asn = file->head.asn;
    point->rst_id = file->head.rst_id;
    point->block_id = (uint32)(file->head.write_pos / file->head.block_size);
    point->lfn = 0; // do not need show lfn in gbp view dv_gbp_analyze_info
    return CT_SUCCESS;
}

void gbp_record_promote_time(knl_session_t *session, const char *stage, const char *promote_type)
{
    log_context_t *log = &session->kernel->redo_ctx;
    lrpl_context_t *lrpl = &session->kernel->lrpl_ctx;

    if (cm_str_equal_ins(stage, "log analyze")) {
        CT_LOG_RUN_INF("[GBP] [%s] Log analyze time %llums, end point: rst_id:[%llu], asn[%u], lfn[%llu]",
                       promote_type, (KNL_NOW(session) - log->promote_temp_time) / MILLISECS_PER_SECOND,
                       (uint64)log->redo_end_point.rst_id, log->redo_end_point.asn,
                       (uint64)log->redo_end_point.lfn);
    } else {
        CT_LOG_RUN_INF("[GBP] [%s] LRPL replay used time %llums, end point: rst_id:[%llu], asn[%u], lfn[%llu]",
                       promote_type, (KNL_NOW(session) - log->promote_temp_time) / MILLISECS_PER_SECOND,
                       (uint64)lrpl->curr_point.rst_id, lrpl->curr_point.asn, (uint64)lrpl->curr_point.lfn);
    }

    log->promote_temp_time = KNL_NOW(session);
}

#ifdef __cplusplus
}
#endif
