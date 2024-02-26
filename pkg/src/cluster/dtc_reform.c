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
 * dtc_reform.c
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_reform.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_cluster_module.h"
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
#include "dtc_backup.h"
#include "repl_log_replay.h"

status_t init_dtc_rc(void)
{
    knl_session_t *session;
    CT_RETURN_IFERR(g_knl_callback.alloc_knl_session(CT_TRUE, (knl_handle_t *)&session));

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
    init_st.callback.rc_promote_role = (rc_cb_promote_role)rc_promote_role;
    init_st.callback.rc_start_lrpl_proc = (rc_cb_start_lrpl_proc)rc_start_lrpl_proc;

    return init_cms_rc(&g_dtc->rf_ctx, &init_st);
}

void free_dtc_rc(void)
{
    // TODO: complete shutdown normal function later
    // shutdown_context_t *ctx = &g_instance->shutdown_ctx;
    // bool32 is_shutdown_abort = (ctx->phase == SHUTDOWN_PHASE_INPROGRESS && ctx->mode == SHUTDOWN_MODE_ABORT);

    cm_close_thread(&g_drc_res_ctx.gc_thread);

    if (g_rc_ctx == NULL || g_rc_ctx->started == CT_FALSE) {
        return;
    }

    // free_cms_rc(is_shutdown_abort);
    free_cms_rc(CT_TRUE);

    g_knl_callback.release_knl_session(g_rc_ctx->session);

    // release all pages owned by self, should be do this after remaster is done
    // release edp, notify owner do page clean
    // clean DDL resource
}

bool32 rc_instance_accessible(uint8 id)
{
    reform_role_t role;

    if (g_rc_ctx->status >= REFORM_OPEN) {
        return CT_TRUE;
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
    CM_ASSERT(inst_count <= CT_MAX_INSTANCES);

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
        if (dtc_tx_area_init(g_rc_ctx->session, list->inst_id_list[i]) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[DTC RCY] failed to init tx area");
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t rc_undo_init(instance_list_t *list)
{
    for (uint8 i = 0; i < list->inst_id_count; i++) {
        dtc_undo_init(g_rc_ctx->session, list->inst_id_list[i]);
    }

    return CT_SUCCESS;
}

status_t rc_tx_area_load(instance_list_t *list)
{
    for (uint8 i = 0; i < list->inst_id_count; i++) {
        dtc_tx_area_load(g_rc_ctx->session, list->inst_id_list[i]);
    }

    return CT_SUCCESS;
}

status_t rc_rollback_close(instance_list_t *list)
{
    for (uint8 i = 0; i < list->inst_id_count; i++) {
        dtc_rollback_close(g_rc_ctx->session, list->inst_id_list[i]);
    }

    return CT_SUCCESS;
}

status_t rc_undo_release(instance_list_t * list)
{
    for (uint8 i = 0; i < list->inst_id_count; i++) {
        dtc_undo_release(g_rc_ctx->session, list->inst_id_list[i]);
    }

    return CT_SUCCESS;
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
                    CT_LOG_RUN_INF("[RC]REFORM_LIST_LEAVE cantian_ist_id:%u.", inst_id);
                    clean_up_for_bad_cantian((uint32_t)inst_id);
                }
            }

            for (uint8 i = 0; i < info->reform_list[REFORM_LIST_ABORT].inst_id_count; i++) {
                inst_id = info->reform_list[REFORM_LIST_ABORT].inst_id_list[i];
                if (g_rc_ctx->self_id != inst_id) {
                    CT_LOG_RUN_INF("[RC]REFORM_LIST_ABORT cantian_ist_id:%u.", inst_id);
                    clean_up_for_bad_cantian((uint32_t)inst_id);
                }
            }
            break;

        default:
            break;
    }
    return;
}

status_t dtc_partial_recovery(instance_list_t *recover_list)
{
    CT_LOG_RUN_INF("[RC][partial restart] start redo replay, session->kernel->lsn=%llu,"
                   " g_rc_ctx->status=%u",
                   ((knl_session_t *)g_rc_ctx->session)->kernel->lsn, g_rc_ctx->status);
    if (dtc_start_recovery(g_rc_ctx->session, recover_list, CT_FALSE) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RC][partial restart] failed to start dtc recovery, session->kernel->lsn=%llu,"
                       "g_rc_ctx->status=%u",
                       ((knl_session_t *)g_rc_ctx->session)->kernel->lsn, g_rc_ctx->status);
        g_rc_ctx->status = REFORM_PREPARE;
        return CT_ERROR;
    }

    // wait recovery finish here
    while (dtc_recovery_in_progress()) {
        cm_sleep(DTC_REFORM_WAIT_TIME);
    }
    CT_LOG_RUN_INF("[RC][partial restart] finish redo replay, session->kernel->lsn=%llu,"
                   "g_rc_ctx->status=%u",
                   ((knl_session_t *)g_rc_ctx->session)->kernel->lsn, g_rc_ctx->status);

    if (dtc_recovery_failed()) {
        CT_LOG_RUN_ERR("[RC][partial restart] failed to do dtc recovery, session->kernel->lsn=%llu,"
                       " g_rc_ctx->status=%u",
                       ((knl_session_t *)g_rc_ctx->session)->kernel->lsn, g_rc_ctx->status);
        CM_ABORT(0, "[RC] DTC RCY failed");
    }
    return CT_SUCCESS;
}

status_t dtc_slave_load_my_undo(void)
{
    knl_session_t *session = (knl_session_t *)g_rc_ctx->session;
    core_ctrl_t *core_ctrl = DB_CORE_CTRL(session);
    undo_set_t *undo_set = MY_UNDO_SET(session);
    undo_init_impl(session, undo_set, 0, core_ctrl->undo_segments);

    if (tx_area_init_impl(session, undo_set, 0, core_ctrl->undo_segments, CT_FALSE) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RC][partial restart] failed to do tx area init, g_rc_ctx->status=%u", g_rc_ctx->status);
        return CT_ERROR;
    }

    tx_area_release_impl(session, 0, core_ctrl->undo_segments, session->kernel->id);

    return CT_SUCCESS;
}

status_t dtc_standby_partial_recovery(void)
{
    if (g_rc_ctx->info.master_changed) {
        knl_session_t *session = (knl_session_t *)g_rc_ctx->session;
        instance_list_t *rcy_list = (instance_list_t *)cm_push(session->stack, sizeof(instance_list_t));
        rcy_list->inst_id_count = session->kernel->db.ctrl.core.node_count;
        for (uint8 i = 0; i < rcy_list->inst_id_count; i++) {
            rcy_list->inst_id_list[i] = i;
        }
        CT_LOG_RUN_INF("standby start to partial recovery");
        if (dtc_partial_recovery(rcy_list) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[RC] failed to do partial recovery");
            return CT_ERROR;
        }
    } else {
        if (rc_set_redo_replay_done(g_rc_ctx->session, &(g_rc_ctx->info), CT_FALSE) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[RC][partial restart] failed to broadcast reform status g_rc_ctx->status=%u",
                           g_rc_ctx->status);
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

status_t dtc_rollback_node(void)
{
    // init deposit undo && transaction for abort or leave instances
    knl_session_t *session = (knl_session_t *)g_rc_ctx->session;
    CT_LOG_RUN_INF("[RC] start process undo, session->kernel->lsn=%llu, g_rc_ctx->status=%u",
        session->kernel->lsn, g_rc_ctx->status);

    // init deposit transaction for abort or leave instances
    instance_list_t deposit_list;
    instance_list_t deposit_free_list;
    rc_get_tx_deposit_inst_list(&deposit_list, &deposit_free_list);
    rc_log_instance_list(&deposit_list, "deposit");
    rc_log_instance_list(&deposit_free_list, "deposit free");

    if (rc_undo_init(&deposit_list) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RC] failed to rc_undo_init");
        return CT_ERROR;
    }

    if (rc_tx_area_init(&deposit_list) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RC][partial restart] failed to do tx area init, g_rc_ctx->status=%u", g_rc_ctx->status);
        return CT_ERROR;
    }

    if (!DB_IS_PRIMARY(&session->kernel->db)) {
        core_ctrl_t *core_ctrl = DB_CORE_CTRL(session);
        for (uint8 i = 0; i < deposit_list.inst_id_count; i++) {
            tx_area_release_impl(session, 0, core_ctrl->undo_segments, deposit_list.inst_id_list[i]);
        }
        g_rc_ctx->status = REFORM_OPEN;
        return CT_SUCCESS;
    }

    if (g_instance->kernel.db.open_status == DB_OPEN_STATUS_MAX_FIX) {
        g_instance->kernel.db.is_readonly = CT_TRUE;
    }

    if (rc_tx_area_load(&deposit_list) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RC][partial restart] failed to do tx area load, session->kernel->lsn=%llu, "
                       "g_rc_ctx->status=%u",
                       ((knl_session_t *)g_rc_ctx->session)->kernel->lsn, g_rc_ctx->status);
        return CT_ERROR;
    }

    g_rc_ctx->status = REFORM_OPEN;

    while (DB_IN_BG_ROLLBACK((knl_session_t *)g_rc_ctx->session)) {
        cm_sleep(DTC_REFORM_WAIT_TIME);
    }
    CT_LOG_RUN_INF("[RC] finish undo_rollback, session->kernel->lsn=%llu, g_rc_ctx->status=%u",
                   ((knl_session_t *)g_rc_ctx->session)->kernel->lsn, g_rc_ctx->status);

    if (rc_rollback_close(&deposit_list) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RC][partial restart] failed to rc_tx_area_release, session->kernel->lsn=%llu, "
                       "g_rc_ctx->status=%u",
                       ((knl_session_t *)g_rc_ctx->session)->kernel->lsn, g_rc_ctx->status);
        return CT_ERROR;
    }

    /*            if (rc_undo_release(&deposit_free_list) != CT_SUCCESS) {
                    CT_LOG_RUN_ERR("[RC] failed to rc_undo_release");
                    g_rc_ctx->status = REFORM_DONE;
                    return CT_ERROR;
                }
    */
    return CT_SUCCESS;
}

void rc_reform_init(reform_info_t *reform_info)
{
    dtc_remaster_init(reform_info);
}

status_t rc_follower_reform(reform_mode_t mode, reform_detail_t *detail)
{
    CT_LOG_RUN_INF("[RC] reform for partial restart as follower.");

    // step 2 drc_remaster
    RC_STEP_BEGIN(detail->remaster_elapsed);
    drc_start_remaster(&g_rc_ctx->info);
   // wait remaster finish here
    while (drc_remaster_in_progress()) {
        cm_sleep(DTC_REFORM_WAIT_TIME);
    }
    if (drc_get_remaster_status() == REMASTER_FAIL) {
        CT_LOG_RUN_ERR("[RC][partial restart] failed to partial restart as follower, session->kernel->lsn=%llu,"
                       " g_rc_ctx->status=%u", ((knl_session_t *)g_rc_ctx->session)->kernel->lsn, g_rc_ctx->status);
        g_rc_ctx->info.failed_reform_status = g_rc_ctx->status;
        g_rc_ctx->status = REFORM_PREPARE;
        RC_STEP_END(detail->remaster_elapsed, RC_STEP_FAILED);
        return CT_ERROR;
    }
    RC_STEP_END(detail->remaster_elapsed, RC_STEP_FINISH);

    // wait redo finish here
    RC_STEP_BEGIN(detail->recovery_elapsed);
    while (g_rc_ctx->status < REFORM_RECOVER_DONE) {
        CT_RETVALUE_IFTRUE(rc_reform_cancled(), CT_ERROR);
        cm_sleep(DTC_REFORM_WAIT_TIME);
    }
    RC_STEP_END(detail->recovery_elapsed, RC_STEP_FINISH);

    drc_clean_remaster_res();

    arch_proc_context_t arch_proc_ctx[DTC_MAX_NODE_COUNT] = { 0 };
    if (rc_archive_log(arch_proc_ctx) != CT_SUCCESS) {
        rc_end_archive_log(arch_proc_ctx);
        CT_LOG_RUN_WAR("[RC][partial restart] arch in reform failed");
        return CT_SUCCESS;
    }
    if (rc_wait_archive_log_finish(arch_proc_ctx) != CT_SUCCESS) {
        CT_LOG_RUN_WAR("[RC][partial restart] wait arch finish in reform failed");
    }
    return CT_SUCCESS;
}

status_t rc_master_clean_ddl_op(reform_detail_t *detail)
{
    RC_STEP_BEGIN(detail->clean_ddp_elapsed);
    if (knl_begin_auton_rm(g_rc_ctx->session) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RC] failed to begin kernel auto rm, session->kernel->lsn=%llu, "
                       "g_rc_ctx->status=%u",
                       ((knl_session_t *)g_rc_ctx->session)->kernel->lsn, g_rc_ctx->status);
        g_rc_ctx->info.failed_reform_status = g_rc_ctx->status;
        g_rc_ctx->status = REFORM_PREPARE;
        RC_STEP_END(detail->clean_ddp_elapsed, RC_STEP_FAILED);
        CT_LOG_RUN_INF("[RC][partial restart] master clean ddl op failed");
        return CT_ERROR;
    }
    status_t status = db_clean_ddl_op(g_rc_ctx->session, DDL_REFORM_REPLAY);
    if (status != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RC] failed to do clean ddl operation, session->kernel->lsn=%llu, "
                       "g_rc_ctx->status=%u",
                       ((knl_session_t *)g_rc_ctx->session)->kernel->lsn, g_rc_ctx->status);
        g_rc_ctx->info.failed_reform_status = g_rc_ctx->status;
        g_rc_ctx->status = REFORM_PREPARE;
        knl_end_auton_rm(g_rc_ctx->session, status);
        RC_STEP_END(detail->clean_ddp_elapsed, RC_STEP_FAILED);
        CT_LOG_RUN_INF("[RC][partial restart] master clean ddl op failed");
        return CT_ERROR;
    }
    knl_end_auton_rm(g_rc_ctx->session, status);
    CT_LOG_RUN_INF("[RC] finish to complete ddl operations, session->kernel->lsn=%llu, "
                   "g_rc_ctx->status=%u",
                   ((knl_session_t *)g_rc_ctx->session)->kernel->lsn, g_rc_ctx->status);
    RC_STEP_END(detail->clean_ddp_elapsed, RC_STEP_FINISH);
    return CT_SUCCESS;
}

status_t rc_master_start_remaster(reform_detail_t *detail)
{
    RC_STEP_BEGIN(detail->remaster_elapsed);
    drc_start_remaster(&g_rc_ctx->info);
    CT_LOG_RUN_INF("[RC] reform for partial restart as master, g_rc_ctx->status=%u", g_rc_ctx->status);
    // wait remaster finish here
    while (drc_remaster_in_progress()) {
        cm_sleep(DTC_REFORM_WAIT_TIME);
    }
    if (drc_get_remaster_status() == REMASTER_FAIL) {
        CT_LOG_RUN_ERR("[RC][partial restart] failed to partial restart as master, session->kernel->lsn=%llu,"
                       " g_rc_ctx->status=%u", ((knl_session_t *)g_rc_ctx->session)->kernel->lsn, g_rc_ctx->status);
        g_rc_ctx->info.failed_reform_status = g_rc_ctx->status;
        g_rc_ctx->status = REFORM_PREPARE;
        RC_STEP_END(detail->remaster_elapsed, RC_STEP_FAILED);
        CT_LOG_RUN_ERR("[RC][partial restart] remaster failed");
        return CT_ERROR;
    }
    RC_STEP_END(detail->remaster_elapsed, RC_STEP_FINISH);
    CT_LOG_RUN_INF("[RC][partial restart] finish remaster, g_rc_ctx->status=%u", g_rc_ctx->status);
    return CT_SUCCESS;
}

status_t rc_master_partial_recovery(reform_mode_t mode, reform_detail_t *detail)
{
    RC_STEP_BEGIN(detail->recovery_elapsed);
    knl_session_t *session = (knl_session_t *)g_rc_ctx->session;
    if (mode == REFORM_MODE_OUT_OF_PLAN) {
        if (!DB_IS_PRIMARY(&session->kernel->db)) {
            if (dtc_standby_partial_recovery() != CT_SUCCESS) {
                g_rc_ctx->info.failed_reform_status = g_rc_ctx->status;
                g_rc_ctx->status = REFORM_PREPARE;
                RC_STEP_END(detail->recovery_elapsed, RC_STEP_FAILED);
                CT_LOG_RUN_ERR("[RC][partial restart] recovery failed");
                return CT_ERROR;
            }
            RC_STEP_END(detail->recovery_elapsed, RC_STEP_FINISH);
            return CT_SUCCESS;
        }
        if (dtc_partial_recovery(&g_rc_ctx->info.reform_list[REFORM_LIST_ABORT]) != CT_SUCCESS) {
            g_rc_ctx->info.failed_reform_status = g_rc_ctx->status;
            g_rc_ctx->status = REFORM_PREPARE;
            RC_STEP_END(detail->recovery_elapsed, RC_STEP_FAILED);
            CT_LOG_RUN_ERR("[RC] failed to do partial recovery");
            CT_LOG_RUN_ERR("[RC][partial restart] recovery failed");
            return CT_ERROR;
        }
    } else {
        if (rc_set_redo_replay_done(g_rc_ctx->session, &(g_rc_ctx->info), CT_FALSE) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[RC][partial restart] failed to broadcast reform status g_rc_ctx->status=%u",
                           g_rc_ctx->status);
            g_rc_ctx->info.failed_reform_status = g_rc_ctx->status;
            g_rc_ctx->status = REFORM_PREPARE;
            RC_STEP_END(detail->recovery_elapsed, RC_STEP_FAILED);
            CT_LOG_RUN_ERR("[RC][partial restart] recovery failed");
            return CT_ERROR;
        }
    }
    RC_STEP_END(detail->recovery_elapsed, RC_STEP_FINISH);
    return CT_SUCCESS;
}

status_t rc_master_rollback_node(reform_detail_t *detail)
{
    RC_STEP_BEGIN(detail->deposit_elapsed);
    reform_mode_t mode = rc_get_change_mode();
    if (!DB_IS_PRIMARY(&((knl_session_t*)g_rc_ctx->session)->kernel->db) && mode == REFORM_MODE_OUT_OF_PLAN &&
        g_rc_ctx->info.master_changed == CT_FALSE) {
        RC_STEP_END(detail->deposit_elapsed, RC_STEP_FINISH);
        return CT_SUCCESS;
    }
    if (!DB_IS_PRIMARY(&((knl_session_t*)g_rc_ctx->session)->kernel->db) && mode == REFORM_MODE_OUT_OF_PLAN &&
        g_rc_ctx->info.master_changed) {
        if (dtc_slave_load_my_undo() != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[RC] slave load undo failed g_rc_ctx->status=%u", g_rc_ctx->status);
            return CT_ERROR;
        }
    }
    if (dtc_rollback_node() != CT_SUCCESS) {
        g_rc_ctx->info.failed_reform_status = g_rc_ctx->status;
        g_rc_ctx->status = REFORM_PREPARE;
        RC_STEP_END(detail->deposit_elapsed, RC_STEP_FAILED);
        CT_LOG_RUN_ERR("[RC] failed to do undo rollback");
        CT_LOG_RUN_ERR("[RC][partial restart] rollback failed");
        return CT_ERROR;
    }
    RC_STEP_END(detail->deposit_elapsed, RC_STEP_FINISH);
    return CT_SUCCESS;
}

status_t rc_master_wait_ckpt_finish(reform_mode_t mode)
{
    knl_session_t *session = (knl_session_t *)g_rc_ctx->session;
    if (mode == REFORM_MODE_OUT_OF_PLAN && DB_IS_PRIMARY(&session->kernel->db) && dtc_update_ckpt_log_point()) {
        g_rc_ctx->info.failed_reform_status = g_rc_ctx->status;
        g_rc_ctx->status = REFORM_PREPARE;
        CT_LOG_RUN_ERR("[RC] failed to do ckpt in reform");
        CT_LOG_RUN_ERR("[RC][partial restart] wait ckpt finish failed");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t rc_reform_build_channel(reform_detail_t *detail)
{
    status_t ret;
    RC_STEP_BEGIN(detail->build_channel_elapsed);
    SYNC_POINT_GLOBAL_START(CANTIAN_REFORM_BUILD_CHANNEL_FAIL, &ret, CT_ERROR);
    ret = rc_build_channel(&g_rc_ctx->info);
    SYNC_POINT_GLOBAL_END;
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RC] failed to rc_build_channel, g_rc_ctx->status=%u", g_rc_ctx->status);
        g_rc_ctx->info.failed_reform_status = g_rc_ctx->status;
        g_rc_ctx->status = REFORM_PREPARE;
        RC_STEP_END(detail->build_channel_elapsed, RC_STEP_FAILED);
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("[RC] build channel successfully, g_rc_ctx->status=%u", g_rc_ctx->status);
    SYNC_POINT_GLOBAL_START(CANTIAN_REFORM_BUILD_CHANNEL_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    rc_release_abort_channel(&g_rc_ctx->info);
    CT_LOG_RUN_INF("[RC] release channel successfully, g_rc_ctx->status=%u", g_rc_ctx->status);
    RC_STEP_END(detail->build_channel_elapsed, RC_STEP_FINISH);
    return CT_SUCCESS;
}

status_t rc_arch_handle_tmp_file(arch_proc_context_t *proc_ctx, uint32 node_id)
{
    knl_session_t *session = proc_ctx->session;
    device_type_t arch_file_type = cm_device_type(proc_ctx->arch_dest);
    log_file_t *logfile = &proc_ctx->logfile;
    arch_set_tmp_filename(proc_ctx->tmp_file_name, proc_ctx, node_id);
    CT_LOG_RUN_INF("[RC_ARCH] rc handle tmp arch file %s", proc_ctx->tmp_file_name);
    if (arch_clear_tmp_file(arch_file_type, proc_ctx->tmp_file_name) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (cm_create_device_retry_when_eexist(proc_ctx->tmp_file_name, arch_file_type,
                                           knl_io_flag(session), &proc_ctx->tmp_file_handle) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RC_ARCH] failed to create temp archive log file %s", proc_ctx->tmp_file_name);
        return CT_ERROR;
    }

    if (cm_dbs_is_enable_dbs() == true) {
        if (arch_tmp_flush_head(arch_file_type, proc_ctx->tmp_file_name,
                                proc_ctx, logfile, proc_ctx->tmp_file_handle) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

void rc_init_redo_ctx(arch_proc_context_t *proc_ctx, dtc_node_ctrl_t *node_ctrl, log_file_t *logfile, uint32 node_id)
{
    logfile_set_t *file_set = LOGFILE_SET(proc_ctx->session, node_id);
    log_context_t *redo_ctx = &proc_ctx->session->kernel->redo_ctx;
    redo_ctx->logfile_hwm = file_set->logfile_hwm;
    redo_ctx->files = &file_set->items[0];
    redo_ctx->curr_file = node_ctrl->log_last;
    redo_ctx->active_file = node_ctrl->log_first;

    int32 size = CM_CALC_ALIGN(sizeof(log_file_head_t), logfile->ctrl->block_size);
    redo_ctx->logwr_head_buf = (char *)cm_malloc(size);
    if (redo_ctx->logwr_head_buf == NULL) {
        CM_ABORT(0, "[LOG] ABORT INFO: flush redo file:%s, offset:%u, size:%lu failed.", logfile->ctrl->name, 0,
            sizeof(log_file_head_t));
    }

    errno_t ret = memset_sp(redo_ctx->logwr_head_buf, logfile->ctrl->block_size, 0, logfile->ctrl->block_size);
    knl_securec_check(ret);

    for (int i = 0; i < file_set->log_count; ++i) {
        file_set->items[i].handle = CT_INVALID_HANDLE;
        status_t ret = cm_open_device(file_set->items[i].ctrl->name, file_set->items[i].ctrl->type,
                                      knl_redo_io_flag(proc_ctx->session), &file_set->items[i].handle);
        if (ret != CT_SUCCESS || file_set->items[i].handle == -1) {
            CT_LOG_RUN_ERR("[BACKUP] failed to open %s ", logfile->ctrl->name);
            return;
        }
    }
    CT_LOG_RUN_INF("[RC_ARCH] arch init redo ctx success");
}

status_t rc_arch_init_session(arch_proc_context_t *proc_ctx, knl_session_t *session, uint32 node_id)
{
    errno_t ret;
    proc_ctx->session = (knl_session_t *)cm_malloc(sizeof(knl_session_t));
    ret = memcpy_s((char*)proc_ctx->session, sizeof(knl_session_t), (char*)session, sizeof(knl_session_t));
    knl_securec_check(ret);

    proc_ctx->session->kernel = (knl_instance_t *)cm_malloc(sizeof(knl_instance_t));
    ret = memcpy_s((char*)proc_ctx->session->kernel, sizeof(knl_instance_t), (char*)session->kernel,
                   sizeof(knl_instance_t));
    knl_securec_check(ret);

    proc_ctx->session->kernel->id = node_id;
    return CT_SUCCESS;
}

void rc_arch_set_last_file_id(arch_proc_context_t *proc_ctx, uint32 node_id)
{
    logfile_set_t *file_set = LOGFILE_SET(proc_ctx->session, node_id);
    log_context_t *redo_ctx = &proc_ctx->session->kernel->redo_ctx;
    uint32 last_file_id = CT_INVALID_ID32;
    if (redo_ctx->active_file == 0) {
        last_file_id = file_set->log_count - 1;
    } else {
        last_file_id = redo_ctx->active_file - 1;
    }
    proc_ctx->last_file_id = last_file_id;
}

void rc_init_arch_proc_ctx(arch_proc_context_t *proc_ctx, log_file_t *logfile, dtc_node_ctrl_t *node_ctrl,
                           uint32 arch_num, uint32 node_id)
{
    knl_session_t *session = proc_ctx->session;
    proc_ctx->arch_id = node_id;
    proc_ctx->last_archived_log_record.rst_id = session->kernel->db.ctrl.core.resetlogs.rst_id;
    proc_ctx->last_archived_log_record.offset = CM_CALC_ALIGN(sizeof(log_file_head_t), logfile->ctrl->block_size);
    proc_ctx->write_failed = CT_FALSE;
    proc_ctx->read_failed = CT_FALSE;
    proc_ctx->enabled = CT_TRUE;
    proc_ctx->tmp_file_handle = CT_INVALID_HANDLE;
    proc_ctx->data_type = cm_dbs_is_enable_dbs() == CT_TRUE ? ARCH_DATA_TYPE_DBSTOR : ARCH_DATA_TYPE_FILE;
    
    if (cm_dbs_is_enable_dbs() != CT_TRUE) {
        log_context_t *ctx = &proc_ctx->session->kernel->redo_ctx;
        rc_init_redo_ctx(proc_ctx, node_ctrl, logfile, node_id);
        log_switch_file(proc_ctx->session);
        free(ctx->logwr_head_buf);
        rc_arch_set_last_file_id(proc_ctx, node_id);
    }

    arch_ctrl_t *arch_ctrl = NULL;
    if (arch_num != 0) {
        arch_ctrl = db_get_arch_ctrl(session, node_ctrl->archived_end - 1, node_id);
        proc_ctx->last_archived_log_record.asn = arch_ctrl->asn + 1;
        proc_ctx->last_archived_log_record.start_lsn = arch_ctrl->end_lsn;
        proc_ctx->last_archived_log_record.end_lsn = arch_ctrl->end_lsn;
        proc_ctx->last_archived_log_record.cur_lsn = arch_ctrl->end_lsn;
    } else {
        proc_ctx->last_archived_log_record.asn = 1;
    }
}

status_t rc_arch_init_proc_ctx(arch_proc_context_t *proc_ctx, uint32 node_id)
{
    CT_LOG_RUN_INF("[RC_ARCH] rc init arch proc ctx params and resource, node id %u", node_id);
    knl_session_t *session = (knl_session_t *)g_rc_ctx->session;
    dtc_node_ctrl_t *node_ctrl = dtc_get_ctrl(session, node_id);
    log_file_t *logfile = &proc_ctx->logfile;
    logfile->handle = CT_INVALID_HANDLE;
    status_t ret = CT_ERROR;
    SYNC_POINT_GLOBAL_START(CANTIAN_REFORM_ARCHIVE_INIT_ARCH_CTX_FAIL, &ret, CT_ERROR);
    ret = bak_open_logfile_dbstor(session, logfile, node_id);
    SYNC_POINT_GLOBAL_END;
    if (ret != CT_SUCCESS) {
        return CT_ERROR;
    }

    uint32 arch_num = (node_ctrl->archived_end - node_ctrl->archived_start + CT_MAX_ARCH_NUM) % CT_MAX_ARCH_NUM;
    ret = strcpy_s(proc_ctx->arch_dest, CT_FILE_NAME_BUFFER_SIZE,
                   session->kernel->arch_ctx.arch_proc[ARCH_DEFAULT_DEST - 1].arch_dest);
    knl_securec_check(ret);
 
    proc_ctx->session = session;
    if (cm_dbs_is_enable_dbs() != CT_TRUE && rc_arch_init_session(proc_ctx, session, node_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    rc_init_arch_proc_ctx(proc_ctx, logfile, node_ctrl, arch_num, node_id);
    CT_LOG_RUN_INF("[RC_ARCH] cur arch num %u, next asn %u, next start lsn %llu", arch_num,
                   proc_ctx->last_archived_log_record.asn, proc_ctx->last_archived_log_record.end_lsn);

    uint32 redo_log_filesize = 0;
    if (cm_dbs_is_enable_dbs() == CT_TRUE) {
        status_t status = cm_device_get_used_cap(logfile->ctrl->type, logfile->handle,
                                                 proc_ctx->last_archived_log_record.start_lsn + 1, &redo_log_filesize);
        if (status != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[RC_ARCH] failed to fetch redolog size from DBStor");
            return CT_ERROR;
        }
        proc_ctx->redo_log_filesize = SIZE_K_U64(redo_log_filesize);
    }
   
    CT_LOG_RUN_INF("[RC_ARCH] finish to init proc ctx, redo left size %llu", proc_ctx->redo_log_filesize);
    return CT_SUCCESS;
}

status_t rc_arch_update_node_ctrl(uint32 node_id)
{
    CT_LOG_RUN_INF("[RC_ARCH] update offline node %u arch ctrl from device", node_id);
    knl_session_t *session = (knl_session_t *)g_rc_ctx->session;
    database_t *db = &session->kernel->db;
    uint32 count = CTRL_MAX_BUF_SIZE / sizeof(arch_ctrl_t);
    uint32 pages_per_inst = (CT_MAX_ARCH_NUM - 1) / count + 1;
    ctrl_page_t *pages = &db->ctrl.pages[db->ctrl.arch_segment + pages_per_inst * node_id];
    bool32 loaded = CT_FALSE;
    for (int i = 0; i < db->ctrlfiles.count; i++) {
        ctrlfile_t *ctrlfile = &db->ctrlfiles.items[i];
        int64 offset = (db->ctrl.arch_segment + pages_per_inst * node_id) * ctrlfile->block_size;
        if (cm_open_device(ctrlfile->name, ctrlfile->type, knl_io_flag(session), &ctrlfile->handle) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[RC_ARCH] failed to open ctrlfile[%d], filename[%s], instid[%u]",
                           i, ctrlfile->name, node_id);
            continue;
        }
        if (cm_read_device(ctrlfile->type, ctrlfile->handle, offset,
                           pages, pages_per_inst * ctrlfile->block_size) != CT_SUCCESS) {
            cm_close_device(ctrlfile->type, &ctrlfile->handle);
            CT_LOG_RUN_ERR("[RC_ARCH] fail to read offline node arch ctrl from ctrlfile[%d], instid[%u]", i, node_id);
            continue;
        }
        CT_LOG_RUN_INF("[RC_ARCH] succ to get offline node arch ctrl, ctrlfile[%d], instid[%u]", i, node_id);
        loaded = CT_TRUE;
        break;
    }
    if (!loaded) {
        CT_THROW_ERROR(ERR_LOAD_CONTROL_FILE, "no usable control file");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t rc_archive_log_offline_node(arch_proc_context_t *proc_ctx, uint32 node_id)
{
    if (rc_arch_update_node_ctrl(node_id) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (rc_arch_init_proc_ctx(proc_ctx, node_id) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (cm_dbs_is_enable_dbs() == CT_TRUE && proc_ctx->redo_log_filesize == 0) {
        CT_LOG_RUN_INF("[RC_ARCH] no left redo log to fetch from DBStor, node id %u", node_id);
        return CT_SUCCESS;
    }

    uint32 buffer_size = proc_ctx->session->kernel->attr.lgwr_buf_size;
    uint32 arch_rw_buf_num = cm_dbs_is_enable_dbs() == true ? DBSTOR_ARCH_RW_BUF_NUM : ARCH_RW_BUF_NUM;
    if (arch_init_rw_buf(&proc_ctx->arch_rw_buf, buffer_size * arch_rw_buf_num, "ARCH") != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (cm_dbs_is_enable_dbs() == true) {
        if (rc_arch_handle_tmp_file(proc_ctx, node_id) != CT_SUCCESS) {
            return CT_ERROR;
        }
        if (cm_create_thread(rc_arch_dbstor_read_proc, 0, proc_ctx, &proc_ctx->read_thread) != CT_SUCCESS) {
            return CT_ERROR;
        }
        if (cm_create_thread(arch_write_proc_dbstor, 0, proc_ctx, &proc_ctx->write_thread) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        if (cm_create_thread(rc_arch_proc, 0, proc_ctx, &proc_ctx->write_thread) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

bool32 rc_need_archive_log(void)
{
    knl_session_t *session = (knl_session_t *)g_rc_ctx->session;
    if (session->kernel->db.ctrl.core.log_mode != ARCHIVE_LOG_ON) {
        return CT_FALSE;
    }
    knl_panic_log(g_dtc->profile.node_count < DTC_MAX_NODE_COUNT, "not support node count");
    return CT_TRUE;
}

status_t rc_archive_log(arch_proc_context_t *arch_proc_ctx)
{
    if (rc_need_archive_log() != CT_TRUE) {
        return CT_SUCCESS;
    }
    CT_LOG_RUN_INF("[RC_ARCH] start to archive redo log for all offline nodes");
    for (uint32 i = 0; i < g_dtc->profile.node_count; i++) {
        if (i == g_dtc->profile.inst_id) {
            continue;
        }
        if (rc_get_current_stat()->inst_list[i].stat == CMS_RES_ONLINE &&
            rc_get_target_stat()->inst_list[i].stat == CMS_RES_OFFLINE) {
            if (rc_archive_log_offline_node(arch_proc_ctx + i, i) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }
    }
    return CT_SUCCESS;
}

void rc_end_archive_log(arch_proc_context_t *arch_proc_ctx)
{
    if (rc_need_archive_log() != CT_TRUE) {
        return;
    }
    CT_LOG_RUN_INF("[RC_ARCH] release all arch proc ctx resource");
    for (uint32 i = 0; i < DTC_MAX_NODE_COUNT; i++) {
        cm_close_thread(&arch_proc_ctx[i].write_thread);
        if (cm_dbs_is_enable_dbs() == CT_TRUE) {
            cm_close_thread(&arch_proc_ctx[i].read_thread);
        }

        if (arch_proc_ctx[i].arch_rw_buf.aligned_buf.alloc_buf != NULL) {
            arch_release_rw_buf(&arch_proc_ctx[i].arch_rw_buf, "RC_ARCH");
        }

        if (arch_proc_ctx[i].tmp_file_name[0] != '\0' && arch_proc_ctx[i].tmp_file_handle != CT_INVALID_HANDLE) {
            cm_close_device(cm_device_type(arch_proc_ctx[i].tmp_file_name), &arch_proc_ctx[i].tmp_file_handle);
        }
        if (arch_proc_ctx[i].logfile.ctrl != NULL && arch_proc_ctx[i].logfile.handle != CT_INVALID_HANDLE) {
            cm_close_device(arch_proc_ctx[i].logfile.ctrl->type, &arch_proc_ctx[i].logfile.handle);
        }
    }
}

status_t rc_wait_archive_log_finish(arch_proc_context_t *arch_proc_ctx)
{
    status_t arch_stat = CT_SUCCESS;
    if (rc_need_archive_log() != CT_TRUE) {
        return arch_stat;
    }
    CT_LOG_RUN_INF("[RC_ARCH] wait all arch procs to complete");
    for (uint32 i = 0; i < DTC_MAX_NODE_COUNT;) {
        if (arch_proc_ctx[i].read_failed || arch_proc_ctx[i].write_failed) {
            arch_stat = CT_ERROR;
            break;
        }
        if (arch_proc_ctx[i].arch_execute == CT_TRUE) {
            sleep(DTC_REFORM_WAIT_ARCH_LOG);
            continue;
        }
        i++;
    }
    CT_LOG_RUN_INF("[RC_ARCH] end all arch procs, arch stat: %s", arch_stat == CT_SUCCESS ? "SUCCESS" : "ERROR");
    rc_end_archive_log(arch_proc_ctx);
    return arch_stat;
}

status_t rc_master_reform(reform_mode_t mode, reform_detail_t *detail)
{
    bool32 is_full_restart = rc_is_full_restart();
    if (is_full_restart) {
        CT_LOG_RUN_INF("[RC] reform for full restart as master, g_rc_ctx->status=%u", g_rc_ctx->status);

        drc_start_one_master();
        g_rc_ctx->status = REFORM_MOUNTING;

        // in case of full restart, recover in main thread, wait recovery finish here
        while (((knl_session_t*)g_rc_ctx->session)->kernel->db.status <= DB_STATUS_RECOVERY || dtc_recovery_in_progress()) {
            CT_RETVALUE_IFTRUE(rc_reform_cancled(), CT_ERROR);
            cm_sleep(DTC_REFORM_WAIT_TIME);
        }
    } else {
        CT_LOG_RUN_INF("[RC] reform for partial restart as master, g_rc_ctx->status=%u", g_rc_ctx->status);
        g_rc_ctx->status = REFORM_RECOVERING;

        // step 2 drc_remaster
        if (rc_master_start_remaster(detail) != CT_SUCCESS) {
            return CT_ERROR;
        }

        // step 3 roll forward
        if (rc_master_partial_recovery(mode, detail) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    // recovery finish, trigger ckpt
    RC_STEP_BEGIN(detail->ckpt_elapsed);

    drc_clean_remaster_res();

    arch_proc_context_t arch_proc_ctx[DTC_MAX_NODE_COUNT] = { 0 };
    if (rc_archive_log(arch_proc_ctx) != CT_SUCCESS) {
        rc_end_archive_log(arch_proc_ctx);
        return CT_ERROR;
    }

    // step 4 rollback
    if (rc_master_rollback_node(detail) != CT_SUCCESS) {
        RC_STEP_END(detail->ckpt_elapsed, RC_STEP_FAILED);
        rc_end_archive_log(arch_proc_ctx);
        return CT_ERROR;
    }

    rc_release_tse_resources(&g_rc_ctx->info);

    /* checkpoint and update log point after reform_open, in order for dtc_get_txn_info to move on and release ctrl */
    /* latch */
    if (rc_master_wait_ckpt_finish(mode) != CT_SUCCESS) {
        RC_STEP_END(detail->ckpt_elapsed, RC_STEP_FAILED);
        rc_end_archive_log(arch_proc_ctx);
        return CT_ERROR;
    }
    RC_STEP_END(detail->ckpt_elapsed, RC_STEP_FINISH);

    if (rc_wait_archive_log_finish(arch_proc_ctx) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t rc_start_new_reform(reform_mode_t mode)
{
    reform_detail_t *detail = &g_rc_ctx->reform_detail;

    // step 0 freeze reform cluster
    CT_LOG_RUN_INF("[RC] change g_rc_ctx->status=%u", g_rc_ctx->status);
    g_rc_ctx->status = REFORM_FROZEN;
    rc_reform_init(&g_rc_ctx->info);
    CT_LOG_RUN_INF("[RC] new reform init successfully, g_rc_ctx->status=%u", g_rc_ctx->status);
    SYNC_POINT_GLOBAL_START(CANTIAN_REFORM_BUILD_CHANNEL_DELAY, NULL, 1000); // delay 1000ms
    SYNC_POINT_GLOBAL_END;
    // step 1 rebuild mes channel
    if (rc_reform_build_channel(detail) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RC] build channel step failed");
        return CT_ERROR;
    }

    if (rc_is_master() == CT_TRUE) {
        if (rc_master_reform(mode, detail) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[RC] master reform failed");
            return CT_ERROR;
        }
    } else {
        if (rc_follower_reform(mode, detail) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[RC][partial restart] follower reform failed");
            return CT_ERROR;
        }
    }
    CT_LOG_RUN_INF("[RC] finish reform, g_rc_ctx->status=%u", g_rc_ctx->status);
    CT_LOG_RUN_INF("[RC] there are (%d) flying page request", page_req_count);
    page_req_count = 0;
    accumulate_recovery_stat();

    return CT_SUCCESS;
}

status_t rc_mes_connect(uint8 inst_id)
{
    int32 err_code;
    const char *error_msg = NULL;
    if (mes_connect(inst_id, g_dtc->profile.nodes[inst_id], g_dtc->profile.ports[inst_id]) != CT_SUCCESS) {
        cm_get_error(&err_code, &error_msg, NULL);
        if (err_code != ERR_MES_ALREADY_CONNECT) {
            CT_LOG_RUN_ERR("[RC] failed to create mes channel to instance %u", inst_id);
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

status_t rc_mes_connection_ready(uint8 inst_id)
{
    uint32 wait_time = 0;
    while (!mes_connection_ready(inst_id)) {
        cm_sleep(DTC_REFORM_WAIT_TIME);
        wait_time += DTC_REFORM_WAIT_TIME;
        if (wait_time > DTC_REFORM_MES_CONNECT_TIMEOUT) {
            CT_LOG_RUN_ERR("[RC] connect to instance %u time out, wait_time %u.", inst_id, wait_time);
            return CT_ERROR;
        }
    }
    
    if (drc_mes_check_full_connection(inst_id) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RC] connect to instance %u failed, full connection not ready.", inst_id);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t rc_build_channel_join(reform_info_t *info)
{
    uint8 inst_id;
    for (uint8 i = 0; i < info->reform_list[REFORM_LIST_AFTER].inst_id_count; i++) {
        inst_id = info->reform_list[REFORM_LIST_AFTER].inst_id_list[i];
        if (g_rc_ctx->self_id != inst_id && rc_mes_connect(inst_id) != CT_SUCCESS) {
                return CT_ERROR;
            }
    }

    for (uint8 i = 0; i < info->reform_list[REFORM_LIST_AFTER].inst_id_count; i++) {
        inst_id = info->reform_list[REFORM_LIST_AFTER].inst_id_list[i];
        if (g_rc_ctx->self_id != inst_id && rc_mes_connection_ready(inst_id) != CT_SUCCESS) {
                return CT_ERROR;
            }
    }
    return CT_SUCCESS;
}

status_t rc_build_channel_stay(reform_info_t *info)
{
    uint8 inst_id;
    for (uint8 i = 0; i < info->reform_list[REFORM_LIST_JOIN].inst_id_count; i++) {
        inst_id = info->reform_list[REFORM_LIST_JOIN].inst_id_list[i];
        if (g_rc_ctx->self_id != inst_id && rc_mes_connect(inst_id) != CT_SUCCESS) {
                return CT_ERROR;
        }
    }

    for (uint8 i = 0; i < info->reform_list[REFORM_LIST_JOIN].inst_id_count; i++) {
        inst_id = info->reform_list[REFORM_LIST_JOIN].inst_id_list[i];
        if (g_rc_ctx->self_id != inst_id && rc_mes_connection_ready(inst_id) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

status_t rc_build_channel(reform_info_t *info)
{
    switch (info->role) {
        case REFORM_ROLE_JOIN:
            if (rc_build_channel_join(info) != CT_SUCCESS) {
                return CT_ERROR;
            }
            break;

        case REFORM_ROLE_STAY:
            if (rc_build_channel_stay(info) != CT_SUCCESS) {
                return CT_ERROR;
            }
            break;

        default:
            break;
    }
    return CT_SUCCESS;
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
                    mes_disconnect(inst_id, CT_FALSE);
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
                    mes_disconnect(inst_id, CT_TRUE);
                    released++;
                }
            }
            break;

        case REFORM_ROLE_STAY:
            for (uint8 i = 0; i < info->reform_list[REFORM_LIST_LEAVE].inst_id_count; i++) {
                inst_id = info->reform_list[REFORM_LIST_LEAVE].inst_id_list[i];
                if (g_rc_ctx->self_id != inst_id) {
                    mes_disconnect(inst_id, CT_TRUE);
                    released++;
                }
            }

            for (uint8 i = 0; i < info->reform_list[REFORM_LIST_ABORT].inst_id_count; i++) {
                inst_id = info->reform_list[REFORM_LIST_ABORT].inst_id_list[i];
                if (g_rc_ctx->self_id != inst_id) {
                    mes_disconnect(inst_id, CT_TRUE);
                    released++;
                }
            }

            for (uint8 i = 0; i < info->reform_list[REFORM_LIST_FAIL].inst_id_count; i++) {
                inst_id = info->reform_list[REFORM_LIST_FAIL].inst_id_list[i];
                if (g_rc_ctx->self_id != inst_id) {
                    mes_disconnect(inst_id, CT_TRUE);
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
        return CT_FALSE;
    }

    knl_session_t *session = (knl_session_t *)g_rc_ctx->session;
    if (!DB_IS_PRIMARY(&session->kernel->db)) {
        CT_LOG_RUN_INF("standby cluster no need check recovery");
        return CT_TRUE;
    }

    if (dtc_recovery_in_progress()) {
        return CT_FALSE;
    }
    return CT_TRUE;
}

void rc_stop_cur_reform(void)
{
    CT_LOG_RUN_INF("[RC] start stop current reform, reform failed status(%u), remaster need stop(%u), recovery need "
                   "stop(%u), recovery failed(%u)", g_rc_ctx->info.failed_reform_status, drc_remaster_need_stop(),
                   dtc_recovery_need_stop(), dtc_recovery_failed());
    if (drc_remaster_need_stop()) {
        if (drc_stop_remaster() != CT_SUCCESS) {
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
    CT_LOG_RUN_INF("[RC] finish stop current reform");
}

bool32 rc_reform_cancled(void)
{
    if (g_instance->shutdown_ctx.mode == SHUTDOWN_MODE_ABORT || g_instance->shutdown_ctx.mode == SHUTDOWN_MODE_SIGNAL) {
        return CT_TRUE;
    }
    return CT_FALSE;
}

status_t rc_promote_role(knl_session_t *session)
{
    lrpl_context_t *lrpl = &session->kernel->lrpl_ctx;
    status_t status = CT_SUCCESS;

    if (g_rc_ctx->info.master_changed && rc_is_master() && lrpl->is_promoting) {
        DbsRoleInfo info;
        info.lastRole = DBS_DISASTER_RECOVERY_SLAVE;
        info.curRole = DBS_DISASTER_RECOVERY_MASTER;
        status_t status = db_switch_role(info);
        if (status != CT_SUCCESS) {
            CM_ABORT_REASONABLE(0, "[RC] refomer promote failed");
        }
    }
    return status;
}

status_t rc_start_lrpl_proc(knl_session_t *session)
{
    lrpl_context_t *lrpl = &session->kernel->lrpl_ctx;
    if (g_rc_ctx->mode == REFORM_MODE_OUT_OF_PLAN && g_rc_ctx->info.master_changed && rc_is_master()) {
        if (cm_create_thread(lrpl_proc, 0, session, &lrpl->thread) != CT_SUCCESS) {
            CM_ABORT_REASONABLE(0, "[RC] refomer start lrpl proc failed");
        }
    }
    return CT_SUCCESS;
}
