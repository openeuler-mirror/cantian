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
 * dtc_dmon.c
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_dmon.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_cluster_module.h"
#include "dtc_dmon.h"
#include "dtc_database.h"
#include "dtc_tran.h"

#define SCN_BROADCAST_CLOCK 5  // broadcast scn per 5ms
#define TIME_BROADCAST_CLOCK (10 * SECONDS_PER_MIN * MILLISECS_PER_SECOND)  // broadcast time per 10 mins

static g_cluster_time_interval_t g_cluster_time_interval_instance = { 0 };
g_cluster_time_interval_t  *g_cluster_time_interval_pitr = &g_cluster_time_interval_instance;

static void dmon_scn_broadcast(knl_session_t *session)
{
    mes_scn_bcast_t bcast;
    uint64 success_inst;

    mes_init_send_head(&bcast.head, MES_CMD_SCN_BROADCAST, sizeof(mes_scn_bcast_t), CT_INVALID_ID32,
                       g_dtc->profile.inst_id, CT_INVALID_ID8, session->id, CT_INVALID_ID16);
    bcast.scn = KNL_GET_SCN(&g_dtc->kernel->scn);
    bcast.min_scn = KNL_GET_SCN(&g_dtc->kernel->local_min_scn);
    bcast.lsn = cm_atomic_get(&g_dtc->kernel->lsn);
    (void)cm_gettimeofday(&(bcast.cur_time));
    
    mes_broadcast(session->id, MES_BROADCAST_ALL_INST, &bcast, &success_inst);
}

void dmon_time_broadcast(knl_session_t *session)
{
    mes_time_bcast_t bcast;
    uint64 success_inst;

    mes_init_send_head(&bcast.head, MES_CMD_TIME_BROADCAST, sizeof(mes_time_bcast_t), CT_INVALID_ID32,
                       g_dtc->profile.inst_id, CT_INVALID_ID8, session->id, CT_INVALID_ID16);
    (void)cm_gettimeofday(&(bcast.cur_time));
    
    mes_broadcast(session->id, MES_BROADCAST_ALL_INST, &bcast, &success_inst);
}

void dmon_proc(thread_t *thread)
{
    knl_session_t *session = (knl_session_t *)thread->argument;
    dmon_context_t *ctx = &g_dtc->dmon_ctx;
    uint32 ticks = 0;

    ctx->session = session;

    cm_set_thread_name("dmon");
    CT_LOG_RUN_INF("dmon thread started");
    KNL_SESSION_SET_CURR_THREADID(session, cm_get_current_thread_id());

    while (!thread->closed) {
        // try broadcast scn per seconds
        if (ticks % SCN_BROADCAST_CLOCK == 0) {
            dmon_scn_broadcast(session);
        }

        if (ticks % TIME_BROADCAST_CLOCK == 0) {
            dmon_time_broadcast(session);
        }

        cm_sleep(1);
        ticks++;
    }
}

status_t dmon_startup(void)
{
    knl_session_t *session = NULL;

    if (g_knl_callback.alloc_knl_session(CT_TRUE, (knl_handle_t *)&session) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (cm_create_thread(dmon_proc, 0, session, &g_dtc->dmon_ctx.thread) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

void dmon_close(void)
{
    dmon_context_t *ctx = &g_dtc->dmon_ctx;

    cm_close_thread(&ctx->thread);

    if (ctx->session != NULL) {
        g_knl_callback.release_knl_session(ctx->session);
        ctx->session = NULL;
    }
}

void dtc_process_scn_req(void *sess, mes_message_t *msg)
{
    mes_scn_bcast_t bcast;
    knl_session_t *session = (knl_session_t *)sess;

    mes_init_send_head(&bcast.head, MES_CMD_SCN_BROADCAST, sizeof(mes_scn_bcast_t), msg->head->rsn, msg->head->dst_inst,
                       msg->head->src_inst, session->id, msg->head->src_sid);

    bcast.scn = DB_CURR_SCN(session);

    mes_release_message_buf(msg->buffer);
    mes_send_data((void *)&bcast);
}

void dtc_keep_time_interval(uint64 time_interval_us)
{
    date_t date_now = cm_now();
    if (!cm_spin_try_lock(&g_cluster_time_interval_pitr->lock)) {
        return;
    }
    uint16 number = g_cluster_time_interval_pitr->number;
    if (number >= CLUSTER_TIME_INTERVAL_ARRAY_SIZE) {
        cm_spin_unlock(&g_cluster_time_interval_pitr->lock);
        return;
    }
    g_cluster_time_interval_pitr->date_record[number] = date_now;
    g_cluster_time_interval_pitr->interval_record[number] = time_interval_us;
    g_cluster_time_interval_pitr->number++;
    cm_spin_unlock(&g_cluster_time_interval_pitr->lock);
}

void dtc_check_time_interval(timeval_t db_time)
{
    timeval_t p_now;
    (void)cm_gettimeofday(&p_now);
    int64 time_interval_us = (int64)(1000000 * (p_now.tv_sec - db_time.tv_sec) + p_now.tv_usec - db_time.tv_usec);
    dtc_keep_time_interval(abs(time_interval_us));
}

void dtc_process_scn_broadcast(void *sess, mes_message_t *msg)
{
    if (sizeof(mes_scn_bcast_t) != msg->head->size) {
        CT_LOG_RUN_ERR("scn broadcast is invalid, msg size %u.", msg->head->size);
        mes_release_message_buf(msg->buffer);
        return;
    }
    mes_scn_bcast_t *bcast = (mes_scn_bcast_t *)msg->buffer;
    knl_scn_t lamport_scn = bcast->scn;
    int64 lamport_lsn = bcast->lsn;
    knl_session_t *session = (knl_session_t *)sess;
    if (msg->head->src_inst >= CT_MAX_INSTANCES) {
        mes_release_message_buf(msg->buffer);
        CT_LOG_RUN_ERR("Do not process scn broadcast, because src_inst is invalid: %u", msg->head->src_inst);
        return;
    }
    KNL_SET_SCN(&g_dtc->profile.min_scn[msg->head->src_inst], bcast->min_scn);
    mes_release_message_buf(msg->buffer);

    dtc_update_scn(session, lamport_scn);
    dtc_update_lsn(session, lamport_lsn);
}

void dtc_process_lsn_broadcast(void *sess, mes_message_t *msg)
{
    if (sizeof(mes_lsn_bcast_t) != msg->head->size) {
        CT_LOG_RUN_ERR("msg is invalid, msg size %u.", msg->head->size);
        mes_release_message_buf(msg->buffer);
        return;
    }
    mes_lsn_bcast_t *bcast = (mes_lsn_bcast_t *)msg->buffer;
    int64 lamport_lsn = bcast->lsn;
    knl_session_t *session = (knl_session_t *)sess;

    mes_release_message_buf(msg->buffer);
    dtc_update_lsn(session, lamport_lsn);
}

void dtc_process_time_broadcast(void *sess, mes_message_t *msg)
{
    if (sizeof(mes_time_bcast_t) != msg->head->size) {
        CT_LOG_RUN_ERR("time broadcast is invalid, msg size %u.", msg->head->size);
        mes_release_message_buf(msg->buffer);
        return;
    }
    mes_time_bcast_t *bcast = (mes_time_bcast_t *)msg->buffer;

    timeval_t db_time = bcast->cur_time;
    if (msg->head->src_inst >= CT_MAX_INSTANCES) {
        mes_release_message_buf(msg->buffer);
        CT_LOG_RUN_ERR("Do not process time broadcast, because src_inst is invalid: %u", msg->head->src_inst);
        return;
    }
    mes_release_message_buf(msg->buffer);
    dtc_check_time_interval(db_time);
}

/*
 * get the cluster min_scn as current instance min_scn
 */
knl_scn_t dtc_get_min_scn(knl_scn_t cur_min_scn)
{
    dtc_profile_t *profile = &g_dtc->profile;
    cluster_view_t view;
    rc_get_cluster_view(&view, CT_FALSE);
    knl_scn_t min_scn = cur_min_scn;

    for (uint32 i = 0; i < profile->node_count; i++) {
        if (i == profile->inst_id) {
            continue;
        }

        if (!rc_bitmap64_exist(&view.bitmap, i)) {
            continue;
        }

        if (profile->min_scn[i] != 0 && profile->min_scn[i] < min_scn) {
            min_scn = profile->min_scn[i];
        }
    }

    return min_scn;
}
