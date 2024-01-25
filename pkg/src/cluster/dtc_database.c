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
 * dtc_database.c
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_database.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_cluster_module.h"
#include "dtc_database.h"
#include "dtc_context.h"
#include "dtc_dls.h"
#include "dtc_log.h"
#include "knl_db_create.h"
#include "knl_create_space.h"
#include "cm_dbs_intf.h"
#include "rc_reform.h"

//build logfiles for each instance
status_t dtc_build_logfiles(knl_session_t *session, knl_database_def_t *def)
{
    dtc_node_def_t *inst = NULL;
    uint32 i;
    uint32 total_log_count = 0;

    for (i = 0; i < def->nodes.count; i++) {
        inst = cm_galist_get(&def->nodes, i);
        total_log_count += inst->logfiles.count;
        if (total_log_count >= CT_MAX_LOG_FILES) {
            CT_THROW_ERROR(ERR_TOO_MANY_OBJECTS, CT_MAX_LOG_FILES, "logfiles");
            return CT_ERROR;
        }

        if (dbc_build_logfiles(session, &inst->logfiles, i) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

/*
 * build undo tablespace, swap and temporary undo tablespace for each instance
 */
status_t dtc_build_node_spaces(knl_session_t *session, knl_database_def_t *def)
{
    dtc_node_def_t *node = NULL;
    dtc_node_ctrl_t *ctrl = NULL;
    uint32 i;

    for (i = 0; i < def->nodes.count; i++) {
        node = (dtc_node_def_t *)cm_galist_get(&def->nodes, i);
        ctrl = dtc_get_ctrl(session, i);

        node->undo_space.extent_size = UNDO_EXTENT_SIZE;
        node->undo_space.is_for_create_db = CT_FALSE;
        if (spc_create_space(session, &node->undo_space, &ctrl->undo_space) != CT_SUCCESS) {
            return CT_ERROR;
        }
        node->swap_space.is_for_create_db = CT_FALSE;
        if (spc_create_space(session, &node->swap_space, &ctrl->swap_space) != CT_SUCCESS) {
            return CT_ERROR;
        }
        node->temp_undo_space.is_for_create_db = CT_FALSE;
        if (spc_create_space(session, &node->temp_undo_space, &ctrl->temp_undo_space) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

//initialize undo tablespace
status_t dtc_init_undo_spaces(knl_session_t *session, knl_database_def_t *def)
{
    dtc_node_def_t *node;
    dtc_node_ctrl_t *ctrl;
    undo_context_t *ctx = &session->kernel->undo_ctx;
    undo_set_t *undo_set = MY_UNDO_SET(session);
    undo_set_t *temp_undo_set = MY_TEMP_UNDO_SET(session);

    for (uint32 i = 0; i < def->nodes.count; i++) {
        node = (dtc_node_def_t *)cm_galist_get(&def->nodes, i);
        ctrl = dtc_get_ctrl(session, i);
        if (spc_get_space_id(session, &node->undo_space.name, CT_FALSE, &ctrl->undo_space) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (undo_create(session, i, ctrl->undo_space, 0, UNDO_SEGMENT_COUNT(session)) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (spc_get_space_id(session, &node->temp_undo_space.name, CT_FALSE, &ctrl->temp_undo_space) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (temp_undo_create(session, i, ctrl->temp_undo_space, 0, UNDO_SEGMENT_COUNT(session)) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    ctx->space = undo_set->space;
    ctx->undos = undo_set->undos;

    ctx->temp_space = temp_undo_set->space;
    ctx->temp_undos = temp_undo_set->undos;

    return CT_SUCCESS;
}

status_t dtc_save_all_ctrls(knl_session_t *session, uint32 count)
{
    uint32 i;
    for (i = 0; i < count; i++) {
        if (dtc_save_ctrl(session, i) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t dtc_build_completed(knl_session_t *session)
{
    core_ctrl_t *core_ctrl = &session->kernel->db.ctrl.core;
    dtc_node_ctrl_t *node_ctrl = NULL;
    uint32 i;

    for (i = 0; i < core_ctrl->node_count; i++) {
        node_ctrl = dtc_get_ctrl(session, i);
        node_ctrl->scn = DB_CURR_SCN(session);

        if (dtc_save_ctrl(session, i) != CT_SUCCESS) {
            CM_ABORT(0, "[DC] ABORT INFO: save node control file failed when load ex_systables");
            return CT_ERROR;
        }
    }

    core_ctrl->build_completed = CT_TRUE;

    if (db_save_core_ctrl(session) != CT_SUCCESS) {
        CM_ABORT(0, "[DC] ABORT INFO: save core control file failed when load ex_systables");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t dtc_save_ctrl(knl_session_t *session, uint32 id)
{
    ctrlfile_t *ctrlfile = NULL;
    database_t *db = &session->kernel->db;

    cm_spin_lock(&db->ctrl_lock, NULL);

    for (uint32 i = 0; i < db->ctrlfiles.count; i++) {
        ctrlfile = &db->ctrlfiles.items[i];

        /* ctrlfile can be opened for a long time, closed in db_close_ctrl_files */
        if (cm_open_device(ctrlfile->name, ctrlfile->type, knl_io_flag(session), &ctrlfile->handle) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[DB] failed to open %s ", ctrlfile->name);
            cm_spin_unlock(&db->ctrl_lock);
            CM_ABORT_REASONABLE(0, "[DB] ABORT INFO: save core control file failed when open device");
            return CT_ERROR;
        }

        if (db_save_ctrl_page(session, ctrlfile, CTRL_LOG_SEGMENT + id) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[DB] failed to write %s ", ctrlfile->name);
            cm_spin_unlock(&db->ctrl_lock);
            CM_ABORT_REASONABLE(0, "[DB] ABORT INFO: save core control file failed");
            return CT_ERROR;
        }
    }

    cm_spin_unlock(&db->ctrl_lock);
    return CT_SUCCESS;
}

status_t dtc_read_node_ctrl(knl_session_t *session, uint8 node_id)
{
    ctrlfile_t *ctrlfile = NULL;
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;

    cm_spin_lock(&db->ctrl_lock, NULL);

    for (uint32 i = 0; i < db->ctrlfiles.count; i++) {
        ctrlfile = &db->ctrlfiles.items[i];

        /* ctrlfile can be opened for a long time, closed in db_close_ctrl_files */
        if (cm_open_device(ctrlfile->name, ctrlfile->type, knl_io_flag(session), &ctrlfile->handle) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[DB] failed to open %s ", ctrlfile->name);
            continue;
        }

        if (db_read_ctrl_page(session, ctrlfile, CTRL_LOG_SEGMENT + node_id) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[DB] failed to read %s ", ctrlfile->name);
            continue;
        }

        dtc_node_ctrl_t *ctrl = dtc_get_ctrl(session, node_id);
        uint32 start = db_get_log_ctrl_pageid(0, db->ctrl.log_segment, node_id);
        uint32 end = db_get_log_ctrl_pageid(ctrl->log_hwm, db->ctrl.log_segment, node_id);
        if (db_read_log_page(session, ctrlfile, start, end) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[DB] failed to read %s ", ctrlfile->name);
            continue;
        }
        // read ctrl successfully
        cm_spin_unlock(&db->ctrl_lock);
        return CT_SUCCESS;
    }

    cm_spin_unlock(&db->ctrl_lock);
    CT_LOG_RUN_ERR("[DB] failed to read ctrl file for node %u ", node_id);
    return CT_ERROR;
}

void dtc_update_scn(knl_session_t *session, knl_scn_t lamport_scn)
{
    tx_area_t *area = &session->kernel->tran_ctx;

    if (DB_CURR_SCN(session) >= lamport_scn) {
        return;
    }

    cm_spin_lock(&area->scn_lock, &session->stat->spin_stat.stat_inc_scn);
    if (DB_CURR_SCN(session) >= lamport_scn) {
        cm_spin_unlock(&area->scn_lock);
        return;
    }

    KNL_SET_SCN(&session->kernel->scn, lamport_scn);
    cm_spin_unlock(&area->scn_lock);
}

void dtc_update_lsn(knl_session_t *session, atomic_t lamport_lsn)
{
    int64 delta = lamport_lsn - DB_CURR_LSN(session);
    if (delta <= 0) {
        return;
    }

    cm_atomic_add(&session->kernel->lsn, delta);
}

void dtc_wait_reform_util(knl_session_t *session, bool8 is_master, reform_status_t stat)
{
#ifndef DTC_RUN_WITH_REFORM
    return;
#endif

    if (!DB_IS_CLUSTER(session)) {
        return;
    }
    if (rc_is_master() != is_master) {
        return;
    }
    for (;;) {
        if (g_rc_ctx->status >= stat) {
            return;
        }
        cm_sleep(10);
    }
}

void dtc_wait_reform(void)
{
#ifndef DTC_RUN_WITH_REFORM
    return;
#endif
    for (;;) {
        if (rc_is_master() && g_rc_ctx->status >= REFORM_MOUNTING) { /* wait for remaster to finish when full restart on
                                                                        master node. */
            return;
        }

        if (!rc_is_master() && g_rc_ctx->status >= REFORM_DONE) { /* wait for reform to finish as redo and undo is done
                                                                     on master node. */
            return;
        }
        cm_sleep(10);
    }
}

void dtc_wait_reform_open(void)
{
#ifndef DTC_RUN_WITH_REFORM
    return;
#endif
    if (!rc_is_master()) {
        return;
    }

    // wait CMS to reform done to enable ddl in dc_init
    for (;;) {
        if (g_rc_ctx->status >= REFORM_OPEN) {
            return;
        }
        cm_sleep(10);
    }
}

status_t dtc_reset_log(knl_session_t *session, bool32 reset_recover, bool32 reset_archive)
{
    database_t *db = &session->kernel->db;
    core_ctrl_t *core = &db->ctrl.core;
    reset_log_t *reset_log = &core->resetlogs;
    logfile_set_t *file_set = NULL;
    log_file_t *logfile = NULL;
    dtc_node_ctrl_t *node_ctrl = NULL;
    errno_t err;

    reset_log->rst_id++;

    for (uint32 i = 0; i < g_dtc->profile.node_count; i++) {
        node_ctrl = dtc_get_ctrl(session, i);
        if (!LOG_POINT_LFN_EQUAL(&node_ctrl->rcy_point, &node_ctrl->lrp_point)) {
            CT_THROW_ERROR(ERR_OPEN_RESETLOGS, node_ctrl->rcy_point.lfn, node_ctrl->lrp_point.lfn);
            return CT_ERROR;
        }

        file_set = LOGFILE_SET(session, i);
        for (uint32 j = 0; j < file_set->logfile_hwm; j++) {
            logfile = &file_set->items[j];
            if (logfile->ctrl->status == LOG_FILE_CURRENT) {
                break;
            }
        }
        logfile->head.rst_id = reset_log->rst_id;

        if (SECUREC_UNLIKELY(i == g_dtc->profile.inst_id)) {
            log_flush_head(session, logfile);
        } else {
            dtc_log_flush_head(session, logfile);
        }

        if (reset_recover) {
            node_ctrl->rcy_point.rst_id = logfile->head.rst_id;
            node_ctrl->consistent_lfn = node_ctrl->rcy_point.lfn;
            node_ctrl->last_asn = node_ctrl->rcy_point.asn;
            node_ctrl->last_lfn = node_ctrl->rcy_point.lfn;
            if (cm_dbs_is_enable_dbs() == CT_TRUE) {
                node_ctrl->rcy_point.block_id = 0;
            } else {
                // write_pos is calcaulated by CM_CALC_ALIGN use sizeof(log_file_head_t) and block_size,
                // block_size is 512 or 4096, so value is smaller than uint32.
                node_ctrl->rcy_point.asn = logfile->head.asn;
                node_ctrl->rcy_point.block_id = (uint32)(logfile->head.write_pos / (uint32)logfile->head.block_size);
            }
            node_ctrl->lrp_point = node_ctrl->rcy_point;
        }

        CT_LOG_RUN_INF("[DTC RCY] reset log instance %u from point [%u][%u/%u/%llu/%llu][%llu][%u]",
                       i, node_ctrl->rcy_point.rst_id, node_ctrl->rcy_point.asn, node_ctrl->rcy_point.block_id,
                       (uint64)node_ctrl->rcy_point.lfn, node_ctrl->rcy_point.lsn, node_ctrl->lsn,
                       logfile->head.asn);

        if (reset_archive) {
            err = memset_sp(core->archived_log, sizeof(arch_log_id_t) * CT_MAX_ARCH_DEST, 0,
                            sizeof(arch_log_id_t) * CT_MAX_ARCH_DEST);
            knl_securec_check(err);
        }

        if (dtc_save_ctrl(session, i) != CT_SUCCESS) {
                CM_ABORT(0, "[DB] ABORT INFO: save core control file failed when reset log.");
        }
    }

    return CT_SUCCESS;
}
