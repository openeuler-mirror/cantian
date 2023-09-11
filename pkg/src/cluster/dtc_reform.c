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
 * dtc_reform.c
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_reform.c
 *
 * -------------------------------------------------------------------------
 */
#include "dtc_reform.h"
#include "dtc_context.h"
#include "dtc_drc.h"
#include "dtc_recovery.h"
#include "dtc_tran.h"
#include "dtc_dls.h"
#include "dtc_dc.h"
#include "dtc_database.h"
#include "dtc_ckpt.h"
#include "cm_malloc.h"
#include "knl_ckpt.h"
#include "dtc_dcs.h"
#include "tse_srv_util.h"
#include "rc_reform.h"

status_t init_dtc_rc(void)
{
    knl_session_t *session;
    GS_RETURN_IFERR(g_knl_callback.alloc_knl_session(GS_TRUE, (knl_handle_t *)&session));

    reform_init_t init_st;
    init_st.session = (void*)session;
    init_st.self_id = session->kernel->dtc_attr.inst_id;
    errno_t ret;
    ret = sprintf_s((char*)(&init_st.res_type), CMS_MAX_RES_TYPE_LEN, CMS_RES_TYPE_DB);
    PRTS_RETURN_IFERR(ret);
    init_st.callback.start_new_reform = (rc_cb_start_new_reform)rc_start_new_reform;
    init_st.callback.lock = NULL;
    init_st.callback.unlock = NULL;
    init_st.callback.build_channel = (rc_cb_build_channel)rc_build_channel;
    init_st.callback.release_channel = (rc_cb_release_channel)rc_release_channel;
    init_st.callback.finished = (rc_cb_finished)rc_finished;
    init_st.callback.stop_cur_reform = (rc_cb_stop_cur_reform)rc_stop_cur_reform;
    init_st.callback.rc_reform_cancled = (rc_cb_reform_canceled)rc_reform_cancled;

    return init_cms_rc(&g_dtc->rf_ctx, &init_st);
}

void free_dtc_rc(void)
{
    // TODO: complete shutdown normal function later
    // shutdown_context_t *ctx = &g_instance->shutdown_ctx;
    // bool32 is_shutdown_abort = (ctx->phase == SHUTDOWN_PHASE_INPROGRESS && ctx->mode == SHUTDOWN_MODE_ABORT);

    cm_close_thread(&g_drc_res_ctx.gc_thread);

    if (g_rc_ctx == NULL || g_rc_ctx->started == GS_FALSE) {
        return;
    }

    // free_cms_rc(is_shutdown_abort);
    free_cms_rc(GS_TRUE);

    g_knl_callback.release_knl_session(g_rc_ctx->session);

    // release all pages owned by self, should be do this after remaster is done
    // release edp, notify owner do page clean
    // clean DDL resource
}

bool32 rc_instance_accessible(uint8 id)
{
    reform_role_t role;

    if (g_rc_ctx->status >= REFORM_OPEN) {
        return GS_TRUE;
    }

    /** instance in reform list */
    role = rc_get_role(&g_rc_ctx->info, id);
    return (role == REFORM_ROLE_STAY);
}

void rc_get_tx_deposit_inst_list(instance_list_t * deposit_list, instance_list_t * deposit_free_list)
{
    rc_init_inst_list(deposit_list);
    rc_init_inst_list(deposit_free_list);

    uint64 inst_count = ((knl_session_t*)g_rc_ctx->session)->kernel->db.ctrl.core.node_count;
    CM_ASSERT(inst_count <= GS_MAX_INSTANCES);

    if (g_rc_ctx->info.master_changed) {
        instance_list_t *after = &RC_REFORM_LIST(&g_rc_ctx->info, REFORM_LIST_AFTER);
        for (uint8 inst_id = 0; inst_id < inst_count; inst_id++) {
                if (!check_id_in_list(inst_id, after)) {
                add_id_to_list(inst_id, deposit_list);
            }
        }
    } else {
        instance_list_t *abort = &RC_REFORM_LIST(&g_rc_ctx->info, REFORM_LIST_ABORT);
        for (uint8 i = 0; i < abort->inst_id_count; i++) {
            add_id_to_list(abort->inst_id_list[i], deposit_list);
        }

        instance_list_t *leave = &RC_REFORM_LIST(&g_rc_ctx->info, REFORM_LIST_LEAVE);
        for (uint8 i = 0; i < leave->inst_id_count; i++) {
            add_id_to_list(leave->inst_id_list[i], deposit_list);
        }

        instance_list_t *fail = &RC_REFORM_LIST(&g_rc_ctx->info, REFORM_LIST_FAIL);
        for (uint8 i = 0; i < fail->inst_id_count; i++) {
            add_id_to_list(fail->inst_id_list[i], deposit_list);
        }

        // do abort first, join next time
        instance_list_t *join = &RC_REFORM_LIST(&g_rc_ctx->info, REFORM_LIST_JOIN);
        for (uint8 i = 0; i < join->inst_id_count; i++) {
            if (!check_id_in_list(join->inst_id_list[i], abort)) {
                add_id_to_list(join->inst_id_list[i], deposit_free_list);
            }
        }
    }
}

status_t rc_tx_area_init(instance_list_t *list)
{
    for (uint8 i = 0; i < list->inst_id_count; i++) {
        if (dtc_tx_area_init(g_rc_ctx->session, list->inst_id_list[i]) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[DTC RCY] failed to init tx area");
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t rc_undo_init(instance_list_t *list)
{
    for (uint8 i = 0; i < list->inst_id_count; i++) {
        dtc_undo_init(g_rc_ctx->session, list->inst_id_list[i]);
    }

    return GS_SUCCESS;
}

status_t rc_tx_area_load(instance_list_t *list)
{
    for (uint8 i = 0; i < list->inst_id_count; i++) {
        dtc_tx_area_load(g_rc_ctx->session, list->inst_id_list[i]);
    }

    return GS_SUCCESS;
}

status_t rc_rollback_close(instance_list_t *list)
{
    for (uint8 i = 0; i < list->inst_id_count; i++) {
        dtc_rollback_close(g_rc_ctx->session, list->inst_id_list[i]);
    }

    return GS_SUCCESS;
}

status_t rc_undo_release(instance_list_t * list)
{
    for (uint8 i = 0; i < list->inst_id_count; i++) {
        dtc_undo_release(g_rc_ctx->session, list->inst_id_list[i]);
    }

    return GS_SUCCESS;
}

static void accumulate_recovery_stat(void)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_rcy_stat_t *stat = &dtc_rcy->rcy_stat;
    reform_detail_t *rf_detail = &g_rc_ctx->reform_detail;

    stat->accum_rcy_log_size += stat->last_rcy_log_size;
    stat->accum_rcy_set_num += stat->last_rcy_set_num;
    stat->accum_rcy_set_create_elapsed += rf_detail->recovery_set_create_elapsed.cost_time;
    stat->accum_rcy_set_revise_elapsed += rf_detail->recovery_set_revise_elapsed.cost_time;
    stat->accum_rcy_replay_elapsed += rf_detail->recovery_replay_elapsed.cost_time;
    stat->accum_rcy_elapsed += rf_detail->recovery_elapsed.cost_time;
    stat->accum_rcy_times++;
}

void rc_release_tse_resources(reform_info_t * info)
{
    uint8  inst_id;
    switch (info->role)  {
        case REFORM_ROLE_STAY:
            for (uint8 i = 0; i < info->reform_list[REFORM_LIST_LEAVE].inst_id_count; i++) {
                inst_id = info->reform_list[REFORM_LIST_LEAVE].inst_id_list[i];
                if (g_rc_ctx->self_id != inst_id) {
                    GS_LOG_RUN_INF("[RC]REFORM_LIST_LEAVE cantian_ist_id:%u.", inst_id);
                    clean_up_for_bad_cantian((uint32_t)inst_id);
                }
            }

            for (uint8 i = 0; i < info->reform_list[REFORM_LIST_ABORT].inst_id_count; i++) {
                inst_id = info->reform_list[REFORM_LIST_ABORT].inst_id_list[i];
                if (g_rc_ctx->self_id != inst_id) {
                    GS_LOG_RUN_INF("[RC]REFORM_LIST_ABORT cantian_ist_id:%u.", inst_id);
                    clean_up_for_bad_cantian((uint32_t)inst_id);
                }
            }
            break;

        default:
            break;
    }
    return;
}

status_t dtc_partial_recovery(void)
{
    GS_LOG_RUN_INF("[RC][partial restart] start redo replay, session->kernel->lsn=%llu,"
                   " g_rc_ctx->status=%u",
                   ((knl_session_t *)g_rc_ctx->session)->kernel->lsn, g_rc_ctx->status);
    if (dtc_start_recovery(g_rc_ctx->session, &g_rc_ctx->info.reform_list[REFORM_LIST_ABORT], GS_FALSE) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[RC][partial restart] failed to start dtc recovery, session->kernel->lsn=%llu,"
                       "g_rc_ctx->status=%u",
                       ((knl_session_t *)g_rc_ctx->session)->kernel->lsn, g_rc_ctx->status);
        g_rc_ctx->status = REFORM_PREPARE;
        return GS_ERROR;
    }

    // wait recovery finish here
    while (dtc_recovery_in_progress()) {
        cm_sleep(DTC_REFORM_WAIT_TIME);
    }
    GS_LOG_RUN_INF("[RC][partial restart] finish redo replay, session->kernel->lsn=%llu,"
                   "g_rc_ctx->status=%u",
                   ((knl_session_t *)g_rc_ctx->session)->kernel->lsn, g_rc_ctx->status);

    if (dtc_recovery_failed()) {
        GS_LOG_RUN_ERR("[RC][partial restart] failed to do dtc recovery, session->kernel->lsn=%llu,"
                       " g_rc_ctx->status=%u",
                       ((knl_session_t *)g_rc_ctx->session)->kernel->lsn, g_rc_ctx->status);
        CM_ABORT(0, "[RC] DTC RCY failed");
    }
    return GS_SUCCESS;
}

status_t dtc_rollback_node(void)
{
    // init deposit undo && transaction for abort or leave instances
    GS_LOG_RUN_INF("[RC] start process undo, session->kernel->lsn=%llu, g_rc_ctx->status=%u",
                   ((knl_session_t *)g_rc_ctx->session)->kernel->lsn, g_rc_ctx->status);

    // init deposit transaction for abort or leave instances
    instance_list_t deposit_list;
    instance_list_t deposit_free_list;
    rc_get_tx_deposit_inst_list(&deposit_list, &deposit_free_list);
    rc_log_instance_list(&deposit_list, "deposit");
    rc_log_instance_list(&deposit_free_list, "deposit free");

    if (rc_undo_init(&deposit_list) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[RC] failed to rc_undo_init");
        return GS_ERROR;
    }

    if (rc_tx_area_init(&deposit_list) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[RC][partial restart] failed to do tx area init, g_rc_ctx->status=%u", g_rc_ctx->status);
        return GS_ERROR;
    }

    if (rc_tx_area_load(&deposit_list) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[RC][partial restart] failed to do tx area load, session->kernel->lsn=%llu, "
                       "g_rc_ctx->status=%u",
                       ((knl_session_t *)g_rc_ctx->session)->kernel->lsn, g_rc_ctx->status);
        return GS_ERROR;
    }

    g_rc_ctx->status = REFORM_OPEN;

    while (DB_IN_BG_ROLLBACK((knl_session_t *)g_rc_ctx->session)) {
        cm_sleep(DTC_REFORM_WAIT_TIME);
    }
    GS_LOG_RUN_INF("[RC] finish undo_rollback, session->kernel->lsn=%llu, g_rc_ctx->status=%u",
                   ((knl_session_t *)g_rc_ctx->session)->kernel->lsn, g_rc_ctx->status);

    if (rc_rollback_close(&deposit_list) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[RC][partial restart] failed to rc_tx_area_release, session->kernel->lsn=%llu, "
                       "g_rc_ctx->status=%u",
                       ((knl_session_t *)g_rc_ctx->session)->kernel->lsn, g_rc_ctx->status);
        return GS_ERROR;
    }

    /*            if (rc_undo_release(&deposit_free_list) != GS_SUCCESS) {
                    GS_LOG_RUN_ERR("[RC] failed to rc_undo_release");
                    g_rc_ctx->status = REFORM_DONE;
                    return GS_ERROR;
                }
    */
    return GS_SUCCESS;
}

void rc_reform_init(reform_info_t *reform_info)
{
    dtc_remaster_init(reform_info);
}

status_t rc_follower_reform(reform_mode_t mode, reform_detail_t *detail)
{
    GS_LOG_RUN_INF("[RC] reform for partial restart as follower.");

    // step 2 drc_remaster
    RC_STEP_BEGIN(detail->remaster_elapsed);
    drc_start_remaster(&g_rc_ctx->info);
   // wait remaster finish here
    while (drc_remaster_in_progress()) {
        cm_sleep(DTC_REFORM_WAIT_TIME);
    }
    if (drc_get_remaster_status() == REMASTER_FAIL) {
        GS_LOG_RUN_ERR("[RC][partial restart] failed to partial restart as follower, session->kernel->lsn=%llu,"
                       " g_rc_ctx->status=%u", ((knl_session_t *)g_rc_ctx->session)->kernel->lsn, g_rc_ctx->status);
        g_rc_ctx->info.failed_reform_status = g_rc_ctx->status;
        g_rc_ctx->status = REFORM_PREPARE;
        RC_STEP_END(detail->remaster_elapsed, RC_STEP_FAILED);
        return GS_ERROR;
    }
    RC_STEP_END(detail->remaster_elapsed, RC_STEP_FINISH);

    // wait redo finish here
    RC_STEP_BEGIN(detail->recovery_elapsed);
    while (g_rc_ctx->status < REFORM_RECOVER_DONE) {
        GS_RETVALUE_IFTRUE(rc_reform_cancled(), GS_ERROR);
        cm_sleep(DTC_REFORM_WAIT_TIME);
    }
    RC_STEP_END(detail->recovery_elapsed, RC_STEP_FINISH);

    drc_clean_remaster_res();
    return GS_SUCCESS;
}

status_t rc_master_clean_ddl_op(reform_detail_t *detail)
{
    RC_STEP_BEGIN(detail->clean_ddp_elapsed);
    if (knl_begin_auton_rm(g_rc_ctx->session) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[RC] failed to begin kernel auto rm, session->kernel->lsn=%llu, "
                       "g_rc_ctx->status=%u",
                       ((knl_session_t *)g_rc_ctx->session)->kernel->lsn, g_rc_ctx->status);
        g_rc_ctx->info.failed_reform_status = g_rc_ctx->status;
        g_rc_ctx->status = REFORM_PREPARE;
        RC_STEP_END(detail->clean_ddp_elapsed, RC_STEP_FAILED);
        return GS_ERROR;
    }
    status_t status = db_clean_ddl_op(g_rc_ctx->session, DDL_REFORM_REPLAY);
    if (status != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[RC] failed to do clean ddl operation, session->kernel->lsn=%llu, "
                       "g_rc_ctx->status=%u",
                       ((knl_session_t *)g_rc_ctx->session)->kernel->lsn, g_rc_ctx->status);
        g_rc_ctx->info.failed_reform_status = g_rc_ctx->status;
        g_rc_ctx->status = REFORM_PREPARE;
        knl_end_auton_rm(g_rc_ctx->session, status);
        RC_STEP_END(detail->clean_ddp_elapsed, RC_STEP_FAILED);
        return GS_ERROR;
    }
    knl_end_auton_rm(g_rc_ctx->session, status);
    GS_LOG_RUN_INF("[RC] finish to complete ddl operations, session->kernel->lsn=%llu, "
                   "g_rc_ctx->status=%u",
                   ((knl_session_t *)g_rc_ctx->session)->kernel->lsn, g_rc_ctx->status);
    RC_STEP_END(detail->clean_ddp_elapsed, RC_STEP_FINISH);
    return GS_SUCCESS;
}

status_t rc_master_start_remaster(reform_detail_t *detail)
{
    RC_STEP_BEGIN(detail->remaster_elapsed);
    drc_start_remaster(&g_rc_ctx->info);
    GS_LOG_RUN_INF("[RC] reform for partial restart as master, g_rc_ctx->status=%u", g_rc_ctx->status);
    // wait remaster finish here
    while (drc_remaster_in_progress()) {
        cm_sleep(DTC_REFORM_WAIT_TIME);
    }
    if (drc_get_remaster_status() == REMASTER_FAIL) {
        GS_LOG_RUN_ERR("[RC][partial restart] failed to partial restart as master, session->kernel->lsn=%llu,"
                       " g_rc_ctx->status=%u", ((knl_session_t *)g_rc_ctx->session)->kernel->lsn, g_rc_ctx->status);
        g_rc_ctx->info.failed_reform_status = g_rc_ctx->status;
        g_rc_ctx->status = REFORM_PREPARE;
        RC_STEP_END(detail->remaster_elapsed, RC_STEP_FAILED);
        return GS_ERROR;
    }
    RC_STEP_END(detail->remaster_elapsed, RC_STEP_FINISH);
    GS_LOG_RUN_INF("[RC][partial restart] finish remaster, g_rc_ctx->status=%u", g_rc_ctx->status);
    return GS_SUCCESS;
}

status_t rc_master_partial_recovery(reform_mode_t mode, reform_detail_t *detail)
{
    RC_STEP_BEGIN(detail->recovery_elapsed);
    if (mode == REFORM_MODE_OUT_OF_PLAN) {
        if (dtc_partial_recovery() != GS_SUCCESS) {
            g_rc_ctx->info.failed_reform_status = g_rc_ctx->status;
            g_rc_ctx->status = REFORM_PREPARE;
            RC_STEP_END(detail->recovery_elapsed, RC_STEP_FAILED);
            GS_LOG_RUN_ERR("[RC] failed to do partial recovery");
            return GS_ERROR;
        }
    } else {
        if (rc_set_redo_replay_done(g_rc_ctx->session, &(g_rc_ctx->info)) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[RC][partial restart] failed to broadcast reform status g_rc_ctx->status=%u",
                           g_rc_ctx->status);
            g_rc_ctx->info.failed_reform_status = g_rc_ctx->status;
            g_rc_ctx->status = REFORM_PREPARE;
            RC_STEP_END(detail->recovery_elapsed, RC_STEP_FAILED);
            return GS_ERROR;
        }
    }
    RC_STEP_END(detail->recovery_elapsed, RC_STEP_FINISH);
    return GS_SUCCESS;
}

status_t rc_master_rollback_node(reform_detail_t *detail)
{
    RC_STEP_BEGIN(detail->deposit_elapsed);
    if (dtc_rollback_node() != GS_SUCCESS) {
        g_rc_ctx->info.failed_reform_status = g_rc_ctx->status;
        g_rc_ctx->status = REFORM_PREPARE;
        RC_STEP_END(detail->deposit_elapsed, RC_STEP_FAILED);
        GS_LOG_RUN_ERR("[RC] failed to do undo rollback");
        return GS_ERROR;
    }
    RC_STEP_END(detail->deposit_elapsed, RC_STEP_FINISH);
    return GS_SUCCESS;
}

status_t rc_master_wait_ckpt_finish(reform_mode_t mode)
{
    if (mode == REFORM_MODE_OUT_OF_PLAN && dtc_update_ckpt_log_point()) {
        g_rc_ctx->info.failed_reform_status = g_rc_ctx->status;
        g_rc_ctx->status = REFORM_PREPARE;
        GS_LOG_RUN_ERR("[RC] failed to do ckpt in reform");
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t rc_reform_build_channel(reform_detail_t *detail)
{
    status_t ret;
    RC_STEP_BEGIN(detail->build_channel_elapsed);
    SYNC_POINT_GLOBAL_START(CANTIAN_REFORM_BUILD_CHANNEL_FAIL, &ret, GS_ERROR);
    ret = rc_build_channel(&g_rc_ctx->info);
    SYNC_POINT_GLOBAL_END;
    if (ret != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[RC] failed to rc_build_channel, g_rc_ctx->status=%u", g_rc_ctx->status);
        g_rc_ctx->info.failed_reform_status = g_rc_ctx->status;
        g_rc_ctx->status = REFORM_PREPARE;
        RC_STEP_END(detail->build_channel_elapsed, RC_STEP_FAILED);
        return GS_ERROR;
    }
    GS_LOG_RUN_INF("[RC] build channel successfully, g_rc_ctx->status=%u", g_rc_ctx->status);

    rc_release_abort_channel(&g_rc_ctx->info);
    GS_LOG_RUN_INF("[RC] release channel successfully, g_rc_ctx->status=%u", g_rc_ctx->status);
    RC_STEP_END(detail->build_channel_elapsed, RC_STEP_FINISH);
    return GS_SUCCESS;
}

status_t rc_master_reform(reform_mode_t mode, reform_detail_t *detail)
{
    bool32 is_full_restart = rc_is_full_restart();
    if (is_full_restart) {
        GS_LOG_RUN_INF("[RC] reform for full restart as master, g_rc_ctx->status=%u", g_rc_ctx->status);

        drc_start_one_master();
        g_rc_ctx->status = REFORM_MOUNTING;

        // in case of full restart, recover in main thread, wait recovery finish here
        while (((knl_session_t*)g_rc_ctx->session)->kernel->db.status <= DB_STATUS_RECOVERY || dtc_recovery_in_progress()) {
            GS_RETVALUE_IFTRUE(rc_reform_cancled(), GS_ERROR);
            cm_sleep(DTC_REFORM_WAIT_TIME);
        }
    } else {
        GS_LOG_RUN_INF("[RC] reform for partial restart as master, g_rc_ctx->status=%u", g_rc_ctx->status);
        g_rc_ctx->status = REFORM_RECOVERING;

        // step 2 drc_remaster
        if (rc_master_start_remaster(detail) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[RC][partial restart] remaster failed");
            return GS_ERROR;
        }

        // step 3 roll forward
        if (rc_master_partial_recovery(mode, detail) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[RC][partial restart] recovery failed");
            return GS_ERROR;
        }
    }
    // recovery finish, trigger ckpt
    RC_STEP_BEGIN(detail->ckpt_elapsed);

    drc_clean_remaster_res();

    // step 4 rollback
    if (rc_master_rollback_node(detail) != GS_SUCCESS) {
        RC_STEP_END(detail->ckpt_elapsed, RC_STEP_FAILED);
        GS_LOG_RUN_ERR("[RC][partial restart] rollback failed");
        return GS_ERROR;
    }

    rc_release_tse_resources(&g_rc_ctx->info);

    /* checkpoint and update log point after reform_open, in order for dtc_get_txn_info to move on and release ctrl */
    /* latch */
    if (rc_master_wait_ckpt_finish(mode) != GS_SUCCESS) {
        RC_STEP_END(detail->ckpt_elapsed, RC_STEP_FAILED);
        GS_LOG_RUN_ERR("[RC][partial restart] wait ckpt finish failed");
        return GS_ERROR;
    }
    RC_STEP_END(detail->ckpt_elapsed, RC_STEP_FINISH);

    if (!is_full_restart) {
        if (rc_master_clean_ddl_op(detail) != GS_SUCCESS) {
            GS_LOG_RUN_INF("[RC][partial restart] master clean ddl op failed");
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

status_t rc_start_new_reform(reform_mode_t mode)
{
    reform_detail_t *detail = &g_rc_ctx->reform_detail;

    // step 0 freeze reform cluster
    GS_LOG_RUN_INF("[RC] change g_rc_ctx->status=%u", g_rc_ctx->status);
    g_rc_ctx->status = REFORM_FROZEN;
    rc_reform_init(&g_rc_ctx->info);
    GS_LOG_RUN_INF("[RC] new reform init successfully, g_rc_ctx->status=%u", g_rc_ctx->status);

    // step 1 rebuild mes channel
    if (rc_reform_build_channel(detail) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[RC] build channel step failed");
        return GS_ERROR;
    }

    if (rc_is_master() == GS_TRUE) {
        if (rc_master_reform(mode, detail) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[RC] master reform failed");
            return GS_ERROR;
        }
    } else {
        if (rc_follower_reform(mode, detail) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[RC][partial restart] follower reform failed");
            return GS_ERROR;
        }
    }
    GS_LOG_RUN_INF("[RC] finish reform, g_rc_ctx->status=%u", g_rc_ctx->status);
    GS_LOG_RUN_INF("[RC] there are (%d) flying page request", page_req_count);
    page_req_count = 0;
    accumulate_recovery_stat();

    return GS_SUCCESS;
}

status_t rc_mes_connect(uint8 inst_id)
{
    int32 err_code;
    const char *error_msg = NULL;
    if (mes_connect(inst_id, g_dtc->profile.nodes[inst_id], g_dtc->profile.ports[inst_id]) != GS_SUCCESS) {
        cm_get_error(&err_code, &error_msg, NULL);
        if (err_code != ERR_MES_ALREADY_CONNECT) {
            GS_LOG_RUN_ERR("[RC] failed to create mes channel to instance %u", inst_id);
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

status_t rc_mes_connection_ready(uint8 inst_id)
{
    uint32 wait_time = 0;
    while (!mes_connection_ready(inst_id)) {
        cm_sleep(DTC_REFORM_WAIT_TIME);
        wait_time += DTC_REFORM_WAIT_TIME;
        if (wait_time > DTC_REFORM_MES_CONNECT_TIMEOUT) {
            GS_LOG_RUN_ERR("[RC] connect to instance %u time out, wait_time %u.", inst_id, wait_time);
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

status_t rc_build_channel_join(reform_info_t *info)
{
    uint8 inst_id;
    for (uint8 i = 0; i < info->reform_list[REFORM_LIST_AFTER].inst_id_count; i++) {
        inst_id = info->reform_list[REFORM_LIST_AFTER].inst_id_list[i];
        if (g_rc_ctx->self_id != inst_id && rc_mes_connect(inst_id) != GS_SUCCESS) {
                return GS_ERROR;
            }
    }

    for (uint8 i = 0; i < info->reform_list[REFORM_LIST_AFTER].inst_id_count; i++) {
        inst_id = info->reform_list[REFORM_LIST_AFTER].inst_id_list[i];
        if (g_rc_ctx->self_id != inst_id && rc_mes_connection_ready(inst_id) != GS_SUCCESS) {
                return GS_ERROR;
            }
    }
    return GS_SUCCESS;
}

status_t rc_build_channel_stay(reform_info_t *info)
{
    uint8 inst_id;
    for (uint8 i = 0; i < info->reform_list[REFORM_LIST_JOIN].inst_id_count; i++) {
        inst_id = info->reform_list[REFORM_LIST_JOIN].inst_id_list[i];
        if (g_rc_ctx->self_id != inst_id && rc_mes_connect(inst_id) != GS_SUCCESS) {
                return GS_ERROR;
        }
    }

    for (uint8 i = 0; i < info->reform_list[REFORM_LIST_JOIN].inst_id_count; i++) {
        inst_id = info->reform_list[REFORM_LIST_JOIN].inst_id_list[i];
        if (g_rc_ctx->self_id != inst_id && rc_mes_connection_ready(inst_id) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

status_t rc_build_channel(reform_info_t *info)
{
    switch (info->role) {
        case REFORM_ROLE_JOIN:
            if (rc_build_channel_join(info) != GS_SUCCESS) {
                return GS_ERROR;
            }
            break;

        case REFORM_ROLE_STAY:
            if (rc_build_channel_stay(info) != GS_SUCCESS) {
                return GS_ERROR;
            }
            break;

        default:
            break;
    }
    return GS_SUCCESS;
}


void rc_release_abort_channel(reform_info_t *info)
{
    uint8  inst_id;
    uint32 released = 0;

    switch (info->role) {
        case REFORM_ROLE_STAY:
            for (uint8 i = 0; i < info->reform_list[REFORM_LIST_ABORT].inst_id_count; i++) {
                inst_id = info->reform_list[REFORM_LIST_ABORT].inst_id_list[i];
                if (g_rc_ctx->self_id != inst_id) {
                    mes_disconnect(inst_id, GS_FALSE);
                    released++;
                }
            }
            break;

        default:
            break;
    }

    if (released > 0) {
        mes_wakeup_rooms();
    }

    return;
}


void rc_release_channel(reform_info_t *info)
{
    uint8  inst_id;
    uint32 released = 0;

    switch (info->role) {
        case REFORM_ROLE_LEAVE:
            for (uint8 i = 0; i < info->reform_list[REFORM_LIST_BEFORE].inst_id_count; i++) {
                inst_id = info->reform_list[REFORM_LIST_BEFORE].inst_id_list[i];
                if (g_rc_ctx->self_id != inst_id) {
                    mes_disconnect(inst_id, GS_TRUE);
                    released++;
                }
            }
            break;

        case REFORM_ROLE_STAY:
            for (uint8 i = 0; i < info->reform_list[REFORM_LIST_LEAVE].inst_id_count; i++) {
                inst_id = info->reform_list[REFORM_LIST_LEAVE].inst_id_list[i];
                if (g_rc_ctx->self_id != inst_id) {
                    mes_disconnect(inst_id, GS_TRUE);
                    released++;
                }
            }

            for (uint8 i = 0; i < info->reform_list[REFORM_LIST_ABORT].inst_id_count; i++) {
                inst_id = info->reform_list[REFORM_LIST_ABORT].inst_id_list[i];
                if (g_rc_ctx->self_id != inst_id) {
                    mes_disconnect(inst_id, GS_TRUE);
                    released++;
                }
            }

            for (uint8 i = 0; i < info->reform_list[REFORM_LIST_FAIL].inst_id_count; i++) {
                inst_id = info->reform_list[REFORM_LIST_FAIL].inst_id_list[i];
                if (g_rc_ctx->self_id != inst_id) {
                    mes_disconnect(inst_id, GS_TRUE);
                    released++;
                }
            }
            break;

        default:
            break;
    }

    if (released > 0) {
        mes_wakeup_rooms();
    }

    return;
}

bool32 rc_finished(void)
{
    if (drc_remaster_in_progress()) {
        return GS_FALSE;
    }

    if (dtc_recovery_in_progress()) {
        return GS_FALSE;
    }
    return GS_TRUE;
}

void rc_stop_cur_reform(void)
{
    GS_LOG_RUN_INF("[RC] start stop current reform, reform failed status(%u), remaster need stop(%u), recovery need "
                   "stop(%u), recovery failed(%u)", g_rc_ctx->info.failed_reform_status, drc_remaster_need_stop(),
                   dtc_recovery_need_stop(), dtc_recovery_failed());
    if (drc_remaster_need_stop()) {
        if (drc_stop_remaster() != GS_SUCCESS) {
            CM_ABORT_REASONABLE(0, "ABORT INFO: stop remaster failed");
        }
    }
 
    if (dtc_recovery_need_stop()) {
        dtc_stop_recovery();
    }
    // current reform failed after remaster done, exit
    if (g_rc_ctx->info.failed_reform_status > REFORM_RECOVERING && g_rc_ctx->info.failed_reform_status < REFORM_DONE) {
        CM_ABORT_REASONABLE(0, "ABORT INFO: current reform failed and cannot reentrant, exit");
    }
    GS_LOG_RUN_INF("[RC] finish stop current reform");
}

bool32 rc_reform_cancled(void)
{
    if (g_instance->shutdown_ctx.mode == SHUTDOWN_MODE_ABORT || g_instance->shutdown_ctx.mode == SHUTDOWN_MODE_SIGNAL) {
        return GS_TRUE;
    }
    return GS_FALSE;
}