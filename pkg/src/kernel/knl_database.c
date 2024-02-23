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
 * knl_database.c
 *
 *
 * IDENTIFICATION
 * src/kernel/knl_database.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_common_module.h"
#include "knl_database.h"
#include "cm_file.h"
#include "knl_context.h"
#include "knl_db_create.h"
#include "index_common.h"
#include "knl_ctrl_restore.h"
#include "knl_space_ddl.h"
#include "dtc_database.h"
#include "dtc_dls.h"
#include "dtc_drc.h"
#include "cm_dbs_intf.h"
#include "cm_file_iofence.h"
#include "srv_view.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BACKGROUD_LOG_INTERVAL 300 /* 5min */

static status_t db_start_daemon(knl_session_t *session);
static char *db_get_role(database_t *db);

uint32 g_local_inst_id = CT_INVALID_ID32;

bool32 g_get_role_from_dbs = CT_FALSE;

/*
 * Initialize member of database
 * @param    kernel handle of the open kernel
 * @return
 * - CT_SUCCESS
 * - CT_ERROR
 * @note must call after instance is startup

 * @since 2017/4/26
 */
status_t db_init(knl_session_t *session)
{
    uint32 i;
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    uint32 size = CTRL_MAX_PAGES(session) * CT_DFLT_CTRL_BLOCK_SIZE;
    uint32 offset = kernel->attr.clustered ? (CT_MAX_INSTANCES + CTRL_LOG_SEGMENT) : (1 + CTRL_LOG_SEGMENT);
    errno_t err;

    dls_init_spinlock(&(db->df_ctrl_lock), DR_TYPE_DATABASE, DR_ID_DATABASE_CTRL, 0);
    dls_init_latch(&(db->ddl_latch), DR_TYPE_DDL, DR_ID_DDL_OP, 0);
    dls_init_latch(&(db->ctrl_latch), DR_TYPE_DDL, DR_ID_DATABASE_CTRL, 0);

    CT_LOG_RUN_INF("[DB INIT] db init start.");
    if (cm_aligned_malloc((int64)size, "ctrl", &db->ctrl.buf) != CT_SUCCESS) {
        return CT_ERROR;
    }
    db->ctrl.pages = (ctrl_page_t *)db->ctrl.buf.aligned_buf;
    err = memset_sp(db->ctrl.pages, size, 0, size);
    knl_securec_check(err);

    for (i = 0; i < CT_MAX_CTRL_FILES; i++) {
        db->ctrlfiles.items[i].handle = CT_INVALID_HANDLE;
    }

    db->ctrl.log_segment = offset;
    db_init_logfile_ctrl(session, &offset);
    db->ctrl.space_segment = offset;
    db_init_space_ctrl(session, &offset);
    db->ctrl.datafile_segment = offset;
    db_init_datafile_ctrl(session, &offset);
    db->ctrl.arch_segment = offset;

    err = memset_sp(&db->ctrl.core, sizeof(core_ctrl_t), 0, sizeof(core_ctrl_t));
    knl_securec_check(err);

    if (buf_init(session) != CT_SUCCESS) {
        return CT_ERROR;
    }
    pcrp_init(session);
    CT_LOG_RUN_INF("[DB INIT] init buf & pcrp finish.");

    if (pcb_init_ctx(session) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (db_start_daemon(session) != CT_SUCCESS) {
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("[DB INIT] start daemon finish.");

    if (dc_preload(session, DB_STATUS_NOMOUNT) != CT_SUCCESS) {
        return CT_ERROR;
    }

    lsnd_eventfd_init(&kernel->lsnd_ctx);
    CT_LOG_RUN_INF("[DB INIT] db init finish.");
    return CT_SUCCESS;
}

knl_scn_t db_inc_scn(knl_session_t *session)
{
    tx_area_t *area;
    timeval_t now;
    time_t init_time;
    knl_scn_t scn;
    uint64 seq = 1;

    area = &session->kernel->tran_ctx;
    init_time = DB_INIT_TIME(session);

#ifdef Z_SHARDING
    if (TX_XA_CONSISTENCY(session)) {
        knl_scn_t gts_scn;
        status_t status = gts_get_lcl_timestamp(&gts_scn);
        KNL_SCN_TO_TIMESEQ(gts_scn, &now, seq, CM_GTS_BASETIME);
        seq++;
        knl_panic(status == CT_SUCCESS);
        CM_ABORT(status == CT_SUCCESS, "[DB] ABORT INFO: increase scn failed");
    } else
#endif
    {
        (void)cm_gettimeofday(&now);
    }

    cm_spin_lock(&area->scn_lock, &session->stat->spin_stat.stat_inc_scn);
    scn = knl_inc_scn(init_time, &now, seq, &session->kernel->scn, session->kernel->attr.systime_inc_threshold);
    cm_spin_unlock(&area->scn_lock);

    return scn;
}

knl_scn_t db_next_scn(knl_session_t *session)
{
    atomic_t curr_scn;
    timeval_t now;
    time_t init_time;
    uint64 seq = 1;

    init_time = DB_INIT_TIME(session);
    curr_scn = (int64)DB_CURR_SCN(session);

#ifdef Z_SHARDING
    knl_scn_t gts_scn;
    if (TX_XA_CONSISTENCY(session)) {
        status_t status = gts_get_lcl_timestamp(&gts_scn);
        KNL_SCN_TO_TIMESEQ(gts_scn, &now, seq, CM_GTS_BASETIME);
        seq++;
        knl_panic(status == CT_SUCCESS);
        CM_ABORT(status == CT_SUCCESS, "[DB] ABORT INFO: get next scn failed");
    } else 
#endif
    {
        (void)cm_gettimeofday(&now);
    }
    return knl_inc_scn(init_time, &now, seq, &curr_scn, session->kernel->attr.systime_inc_threshold);
}

knl_scn_t db_time_scn(knl_session_t *session, uint32 second, uint32 msecond)
{
    timeval_t time;
    time_t init_time = KNL_INVALID_SCN;
    time.tv_sec = second + msecond / MILLISECS_PER_SECOND;
    time.tv_usec = (msecond % MILLISECS_PER_SECOND) * MICROSECS_PER_MILLISEC;
    return KNL_TIME_TO_SCN(&time, init_time);
}
void db_init_max_instance(knl_session_t *session, uint32 max_instance)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;

    db->ctrl.core.max_nodes = max_instance;
}

status_t db_load_logfiles(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    database_t *db = &kernel->db;
    log_file_t *logfile = NULL;
    logfile_set_t *file_set = MY_LOGFILE_SET(session);
    uint32 i;
    status_t ret;

    // mount redo files
    file_set->logfile_hwm = dtc_my_ctrl(session)->log_hwm;
    file_set->log_count = dtc_my_ctrl(session)->log_count;

    for (i = 0; i < file_set->logfile_hwm; i++) {
        logfile = &file_set->items[i];
        logfile->ctrl = (log_file_ctrl_t *)db_get_log_ctrl_item(db->ctrl.pages, i, sizeof(log_file_ctrl_t),
                                                                db->ctrl.log_segment, kernel->id);
        if (LOG_IS_DROPPED(logfile->ctrl->flg)) {
            continue;
        }
        SYNC_POINT_GLOBAL_START(CANTIAN_OPEN_DEVICE_FAIL, &ret, CT_ERROR);
        /* logfile can be opened for a long time, closed in db_close_log_files */
        ret = cm_open_device(logfile->ctrl->name, logfile->ctrl->type, knl_redo_io_flag(session), &logfile->handle);
        SYNC_POINT_GLOBAL_END;
        if (ret != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[DB] failed to open %s ", logfile->ctrl->name);
            return CT_ERROR;
        }
    }
    CT_LOG_RUN_INF("[DB] load logfiles finish");
    return CT_SUCCESS;
}

static void db_upgrade_original_space(core_ctrl_t *core_ctrl, dtc_node_ctrl_t *node_ctrl, space_t *space,
                                      bool32 *is_upgrade)
{
    switch (space->ctrl->id) {
        case SYS_SPACE_ID:
            if (core_ctrl->system_space == 0) {
                space->ctrl->type = SPACE_TYPE_SYSTEM | SPACE_TYPE_DEFAULT;
                core_ctrl->system_space = space->ctrl->id;
            }
            return;
        case FIXED_TEMP_SPACE_ID:
            if (node_ctrl->swap_space == 0) {
                space->ctrl->type = SPACE_TYPE_TEMP | SPACE_TYPE_SWAP | SPACE_TYPE_DEFAULT;
                node_ctrl->swap_space = space->ctrl->id;
            }
            return;
        case FIXED_UNDO_SPACE_ID:
            if (node_ctrl->undo_space == 0) {
                space->ctrl->type = SPACE_TYPE_UNDO | SPACE_TYPE_DEFAULT;
                node_ctrl->undo_space = space->ctrl->id;
            }
            return;
        case FIXED_USER_SPACE_ID:
            if (core_ctrl->user_space == 0) {
                space->ctrl->type = SPACE_TYPE_USERS | SPACE_TYPE_DEFAULT;
                core_ctrl->user_space = space->ctrl->id;
            }
            return;
        default:
            if (!SPACE_IS_DEFAULT(space)) {
                // 'typed' version will not hit this
                if (SPACE_IS_USER_NOLOGGING(space)) {
                    space->ctrl->type = SPACE_TYPE_TEMP;
                }
                space->ctrl->type |= SPACE_TYPE_USERS;
                return;
            }
    }

    *is_upgrade = CT_FALSE;
}

/*
 * for old version compatibility issue
 */
static void db_try_upgrade_space(knl_session_t *session, space_t *space, bool32 *is_upgrade)
{
    core_ctrl_t *core_ctrl = DB_CORE_CTRL(session);
    dtc_node_ctrl_t *node_ctrl = dtc_my_ctrl(session);

    *is_upgrade = CT_TRUE;

    // if it is default space, need verify ****_space in core ctrl
    if (space->ctrl->type != SPACE_TYPE_UNDEFINED && !SPACE_IS_DEFAULT(space)) {
        *is_upgrade = CT_FALSE;
        return;
    }

    /* old version default space cannot be off-lined */
    if (!SPACE_IS_ONLINE(space) && SPACE_TYPE_IS_UNDEFINED(space)) {
        space->ctrl->type = SPACE_TYPE_USERS;
        return;
    }

    if (cm_text_str_equal(&g_temp2, space->ctrl->name) && (core_ctrl->temp_space == 0)) {
        space->ctrl->type = SPACE_TYPE_TEMP | SPACE_TYPE_USERS | SPACE_TYPE_DEFAULT;
        core_ctrl->temp_space = space->ctrl->id;
        return;
    }

    if (cm_text_str_equal(&g_temp2_undo, space->ctrl->name) && (core_ctrl->temp_undo_space == 0)) {
        space->ctrl->type = SPACE_TYPE_UNDO | SPACE_TYPE_TEMP | SPACE_TYPE_DEFAULT ;
        core_ctrl->temp_undo_space = space->ctrl->id;
        return;
    }

    // for spc200 version compatibility
    if (cm_text_str_equal(&g_sysaux, space->ctrl->name) && (core_ctrl->sysaux_space == 0)) {
        space->ctrl->type = SPACE_TYPE_SYSAUX | SPACE_TYPE_DEFAULT;
        core_ctrl->sysaux_space = space->ctrl->id;
        return;
    }

    db_upgrade_original_space(core_ctrl, node_ctrl, space, is_upgrade);
}

static status_t db_save_tablespace_ctrl(knl_session_t *session, space_t *space, bool32 is_upgrade)
{
    if (is_upgrade) {
        if (SPACE_IS_DEFAULT(space)) {
            if (db_save_core_ctrl(session) != CT_SUCCESS) {
                CM_ABORT(0, "[DB] ABORT INFO: failed to save core ctrl file when load tablespace");
                return CT_ERROR;
            }
        }

        if (db_save_space_ctrl(session, space->ctrl->id) != CT_SUCCESS) {
            CM_ABORT(0, "[DB] ABORT INFO: failed to save space ctrl file when load tablespace %s",
                space->ctrl->name);
            return CT_ERROR;
        }
    } else {
        if (!SPACE_IS_ONLINE(space)) {
            if (db_save_space_ctrl(session, space->ctrl->id) != CT_SUCCESS) {
                CM_ABORT(0, "[DB] ABORT INFO: failed to save space ctrl file when load tablespace %s",
                    space->ctrl->name);
                return CT_ERROR;
            }
        }
    }

    return CT_SUCCESS;
}

static status_t db_load_tablespaces(knl_session_t *session, bool32 *has_offline)
{
    space_t *space = NULL;
    bool32 is_upgrade = CT_FALSE;
    bool32 swap_encrypt = CT_FALSE;
    uint32 i;

    *has_offline = CT_FALSE;

    // mount spaces
    for (i = 0; i < CT_MAX_SPACES; i++) {
        space = SPACE_GET(session, i);
        if (space->ctrl->file_hwm == 0) {
            continue;
        }

        /* skip mount off-lined space,
        but mount creating spaces which have finished space & datafile creating but not mount */
        if (!SPACE_IS_ONLINE(space) && !space->ctrl->used) {
            continue;
        }

        if (spc_mount_space(session, space, CT_TRUE) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (SPACE_IS_ENCRYPT(space)) {
            swap_encrypt = CT_TRUE;
        }

        db_try_upgrade_space(session, space, &is_upgrade);
        if (db_save_tablespace_ctrl(session, space, is_upgrade) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (!SPACE_IS_ONLINE(space)) {
            *has_offline = CT_TRUE;
        }
    }

    if (swap_encrypt) {
        if (spc_active_swap_encrypt(session) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

static void db_close_ctrl_files(knl_session_t *session)
{
    ctrlfile_t *ctrlfile = NULL;
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    uint32 i;

    for (i = 0; i < db->ctrlfiles.count; i++) {
        ctrlfile = &db->ctrlfiles.items[i];
        cm_close_device(ctrlfile->type, &ctrlfile->handle);
    }
}

void db_close_log_files(knl_session_t *session)
{
    log_file_t *file = NULL;
    logfile_set_t *logfile_set = MY_LOGFILE_SET(session);

    for (uint32 i = 0; i < logfile_set->logfile_hwm; i++) {
        file = &logfile_set->items[i];

        if (LOG_IS_DROPPED(file->ctrl->flg)) {
            continue;
        }

        cm_close_device(file->ctrl->type, &file->handle);
    }
}

void db_close(knl_session_t *session, bool32 need_ckpt)
{
    log_point_t *rcy_point = &dtc_my_ctrl(session)->rcy_point;
    log_point_t *lrp_point = &dtc_my_ctrl(session)->lrp_point;

    if (!DB_IS_PRIMARY(&session->kernel->db)) {
        gbp_aly_close(session);
        lrpl_close(session);
        lftc_clt_close(session);
    }

    rcy_close(session);
    gbp_agent_close(session);
    bak_close(session);
    undo_close(session);
    arch_close(session);
    tx_shutdown(session);
    smon_close(session);
    rmon_close(session);
    ashrink_close(session);
    auto_rebuild_close(session);
    stats_close(session);
    job_close(session);
    idx_recycle_close(session);
    synctimer_close(session);

    if (need_ckpt) {
        CT_LOG_RUN_INF("begin to save table monitor stats");
        (void)knl_flush_table_monitor(session->kernel->sessions[SESSION_ID_STATS]);
        CT_LOG_RUN_INF("finished to save table monitor stats");
    }

    if (DB_IS_RAFT_ENABLED(session->kernel)) {
        if (log_flush(session, NULL, NULL, NULL) != CT_SUCCESS) {
            CM_ABORT(0, "[LOG] ABORT INFO: redo log task flush redo file failed.");
        }
        if (session->kernel->raft_ctx.status == RAFT_STATUS_INITED) {
            session->kernel->raft_ctx.status = RAFT_STATUS_CLOSING;
        }
        CT_LOG_RUN_INF("commit_lfn : %llu, flushed_lfn : %llu",
            session->kernel->raft_ctx.commit_lfn, session->kernel->redo_ctx.flushed_lfn);
        raft_wait_for_log_flush(session, session->kernel->redo_ctx.flushed_lfn);
        cm_close_thread(&session->kernel->redo_ctx.async_thread);
        CT_LOG_RUN_INF("commit_lfn : %llu, flushed_lfn : %llu",
            session->kernel->raft_ctx.commit_lfn, session->kernel->redo_ctx.flushed_lfn);
    }

    if (DB_TO_RECOVERY(session) && need_ckpt) {
        CT_LOG_RUN_INF("begin full checkpoint");
        ckpt_trigger(session, CT_TRUE, CKPT_TRIGGER_FULL);
        CT_LOG_RUN_INF("full checkpoint completed: file:%u,point:%u,lfn:%llu", rcy_point->asn, rcy_point->block_id,
                       (uint64)rcy_point->lfn);
        CT_LOG_RUN_INF("full checkpoint completed: file:%u,point:%u,lfn:%llu", lrp_point->asn, lrp_point->block_id,
                       (uint64)lrp_point->lfn);
        knl_panic(log_cmp_point(rcy_point, lrp_point) == 0 && LOG_POINT_LFN_EQUAL(rcy_point, lrp_point));
        dtc_my_ctrl(session)->shutdown_consistency = CT_TRUE;
        if (db_save_core_ctrl(session) != CT_SUCCESS) {
            CM_ABORT(0, "[DB] ABORT INFO: save core control file failed when consistent shutdown");
        }
    }
    ckpt_close(session);
    log_close(session);
    lsnd_close_all_thread(session);

    if (DB_IS_CLUSTER(session)) {
        dtc_shutdown(session, need_ckpt);
    }

    if (DB_IS_RAFT_ENABLED((knl_instance_t *)session->kernel)
        && ((knl_instance_t *)session->kernel)->raft_ctx.status == RAFT_STATUS_CLOSING) {
        raft_stop_consistency(session);
    }

    undo_context_t *ctx = &session->kernel->undo_ctx;
    if (ctx->extend_cnt != 0) {
        tx_extend_deinit(session);
    }

    if (DB_TO_RECOVERY(session)) {
        db_close_ctrl_files(session);
        db_close_log_files(session);
    }

    if (session->kernel->attr.enable_asynch) {
        cm_close_thread(&session->kernel->buf_aio_ctx.thread);
    }

    cm_close_timer(g_timer());
    // status must set to close otherwise audit_log will core when shutdown.
    session->kernel->db.status = DB_STATUS_CLOSED;
}

static void db_load_systable(knl_session_t *session, uint32 table_id, page_id_t entry)
{
    table_t *table;

    table = db_sys_table(table_id);
    if (DB_IS_CLUSTER(session)) {
        table->desc.cr_mode = CR_PAGE;
    }

    dc_set_table_accessor(table);

    table->desc.entry = entry;
    table->heap.entry = table->desc.entry;

    buf_enter_page(session, table->heap.entry, LATCH_MODE_S, ENTER_PAGE_RESIDENT);
    table->heap.segment = HEAP_SEG_HEAD(session);
    buf_leave_page(session, CT_FALSE);

    table->desc.seg_scn = table->heap.segment->seg_scn;
}

static void db_load_sysindex_entry(knl_session_t *session, uint32 index_id, page_id_t entry)
{
    index_t *index;

    index = db_sys_index(index_id);
    index->desc.entry = entry;

    if (DB_IS_CLUSTER(session)) {
        index->desc.cr_mode = CR_PAGE;
    }
}

static void db_load_systables(knl_session_t *session)
{
    database_t *db = &session->kernel->db;
    core_ctrl_t *ctrl = &db->ctrl.core;

    db_load_systable(session, SYS_TABLE_ID, ctrl->sys_table_entry);
    db_load_systable(session, SYS_COLUMN_ID, ctrl->sys_column_entry);
    db_load_systable(session, SYS_INDEX_ID, ctrl->sys_index_entry);
    db_load_systable(session, SYS_USER_ID, ctrl->sys_user_entry);

    db_load_sysindex_entry(session, IX_SYS_TABLE1_ID, ctrl->ix_sys_table1_entry);
    db_load_sysindex_entry(session, IX_SYS_TABLE2_ID, ctrl->ix_sys_table2_entry);

    db_load_sysindex_entry(session, IX_SYS_COLUMN_ID, ctrl->ix_sys_column_entry);
    db_load_sysindex_entry(session, IX_SYS_INDEX1_ID, ctrl->ix_sys_index1_entry);
    db_load_sysindex_entry(session, IX_SYS_INDEX2_ID, ctrl->ix_sys_index2_entry);
    db_load_sysindex_entry(session, IX_SYS_USER1_ID, ctrl->ix_sys_user1_entry);
    db_load_sysindex_entry(session, IX_SYS_USER2_ID, ctrl->ix_sys_user2_entry);
}

static status_t db_verify_systime(knl_session_t *session, bool32 ignore_systime)
{
    time_t init_time = DB_INIT_TIME(session);
    knl_scn_t curr_scn = (uint64)session->kernel->scn;
    int64 threshold = session->kernel->attr.systime_inc_threshold;
    timeval_t sys_time, db_time;

    (void)cm_gettimeofday(&sys_time);
    KNL_SCN_TO_TIME(curr_scn, &db_time, init_time);

    if (threshold == 0 || (int64)(sys_time.tv_sec - db_time.tv_sec) <= threshold) {
        return CT_SUCCESS;
    }

    if (!ignore_systime) {
        CT_THROW_ERROR(ERR_SYSTEM_TIME, db_time.tv_sec, sys_time.tv_sec);
        return CT_ERROR;
    }

    curr_scn = KNL_TIMESEQ_TO_SCN(&sys_time, init_time, 0);
    KNL_SET_SCN(&session->kernel->scn, curr_scn);

    return CT_SUCCESS;
}

status_t db_mount_ctrl(knl_session_t *session)
{
    text_t ctrlfiles;
    bool32 is_found = CT_FALSE;

    if (db_check(session, &ctrlfiles, &is_found) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!is_found) {
        CT_THROW_ERROR(ERR_LOAD_CONTROL_FILE, "ctrl file does not exist!");
        return CT_ERROR;
    }

    if (db_load_ctrlspace(session, &ctrlfiles) != CT_SUCCESS) {
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("mount ctrl finish, memory usage=%lu", cm_print_memory_usage());

    return CT_SUCCESS;
}

status_t db_register_iof(knl_instance_t *kernel)
{
    if (knl_dbs_is_enable_dbs()) {
        if (cm_dbs_open_all_ns() != CT_SUCCESS) {
            CT_LOG_RUN_ERR("failed to open dbstore namespace.");
            return CT_ERROR;
        }

        if (cm_dbs_iof_reg_all_ns(kernel->id) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("failed to iof reg dbstore namespace, inst id %u", kernel->id);
            return CT_ERROR;
        }
    } else {
        if (kernel->file_iof_thd.id == 0) {
            if (cm_file_iof_register(kernel->id, &kernel->file_iof_thd) != CT_SUCCESS) {
                CT_LOG_RUN_ERR("failed to iof reg file, inst id %u", kernel->id);
                return CT_ERROR;
            }
        }
    }
    return CT_SUCCESS;
}

status_t db_mount(knl_session_t *session)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;

    CT_LOG_RUN_INF("start to alter database MOUNT, memory usage=%lu", cm_print_memory_usage());

    if (!cm_spin_try_lock(&kernel->lock)) {
        CT_THROW_ERROR(ERR_DB_START_IN_PROGRESS);
        return CT_ERROR;
    }

    knl_panic(db->status == DB_STATUS_NOMOUNT || db->status == DB_STATUS_CREATING);
    kernel->undo_segid = 0;

    if (db_register_iof(kernel) != CT_SUCCESS) {
        cm_spin_unlock(&kernel->lock);
        return CT_ERROR;
    }

    if (db_mount_ctrl(session) != CT_SUCCESS) {
        cm_spin_unlock(&kernel->lock);
        return CT_ERROR;
    }

    if (DB_ATTR_CLUSTER(session)) {
        if (dtc_startup() != CT_SUCCESS) {
            cm_spin_unlock(&kernel->lock);
            return CT_ERROR;
        }
    }

    if (ckpt_recover_partial_write(session) != CT_SUCCESS) {
        cm_spin_unlock(&kernel->lock);
        return CT_ERROR;
    }

    if (arch_init(session) != CT_SUCCESS) {
        cm_spin_unlock(&kernel->lock);
        return CT_ERROR;
    }

    if (db_load_logfiles(session) != CT_SUCCESS) {
        cm_spin_unlock(&kernel->lock);
        return CT_ERROR;
    }

    if (dc_preload(session, DB_STATUS_MOUNT) != CT_SUCCESS) {
        cm_spin_unlock(&kernel->lock);
        return CT_ERROR;
    }

    if (KNL_GBP_ENABLE(session->kernel) && (gbp_agent_start(session) != CT_SUCCESS)) {
        cm_spin_unlock(&kernel->lock);
        return CT_ERROR;
    }

    if (rcy_init(session) != CT_SUCCESS) {
        cm_spin_unlock(&kernel->lock);
        return CT_ERROR;
    }

    rmon_load(session);

    db->status = DB_STATUS_MOUNT;

    cm_spin_unlock(&kernel->lock);
    CT_LOG_RUN_INF("sucessfully alter database MOUNT, memory usage=%lu", cm_print_memory_usage());
    return CT_SUCCESS;
}

static status_t db_start_writer(knl_instance_t *kernel, ckpt_context_t *ckpt)
{
    // start log writer thread
    if (cm_create_thread(log_proc, 0, kernel->sessions[SESSION_ID_LOGWR], &kernel->redo_ctx.thread) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (DB_IS_RAFT_ENABLED(kernel)) {
        if (cm_create_thread(log_async_proc, 0, kernel->sessions[SESSION_ID_LOGWR_ASYNC],
            &kernel->redo_ctx.async_thread) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    // start db writer threads
    for (uint32 i = 0; i < ckpt->dbwr_count; i++) {
        if (cm_create_thread(dbwr_proc, 0, &ckpt->dbwr[i], &ckpt->dbwr[i].thread) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    // start checkpoint thread
    if (cm_create_thread(ckpt_proc, 0, kernel->sessions[SESSION_ID_DBWR], &kernel->ckpt_ctx.thread) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t db_start_daemon(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    ckpt_context_t *ckpt = &kernel->ckpt_ctx;

    if (log_init(session) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (ckpt_init(session) != CT_SUCCESS) {
        return CT_ERROR;
    }

    bak_init(session);

    CT_LOG_RUN_INF("int log & ckpt & bak finish.");
    if (db_start_writer(kernel, ckpt) != CT_SUCCESS) {
        return CT_ERROR;
    }

    // start smon thread
    if (cm_create_thread(smon_proc, 0, kernel->sessions[SESSION_ID_SMON], &kernel->smon_ctx.thread) != CT_SUCCESS) {
        return CT_ERROR;
    }

    // start stats thread
    if (cm_create_thread(stats_proc, 0, kernel->sessions[SESSION_ID_STATS], &kernel->stats_ctx.thread) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (cm_create_thread(idx_recycle_proc, 0, kernel->sessions[SESSION_ID_IDX_RECYCLE],
        &kernel->index_ctx.recycle_ctx.thread) != CT_SUCCESS) {
            return CT_ERROR;
    }

    if (DB_IS_PRIMARY(&session->kernel->db) && !DB_IS_RAFT_ENABLED(kernel)) {
        if (tx_rollback_start(session) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (kernel->attr.enable_asynch) {
        if (cm_create_thread(buf_aio_proc, 0, kernel, &kernel->buf_aio_ctx.thread) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (cm_create_thread(rmon_proc, 0, kernel->sessions[SESSION_ID_RMON], &kernel->rmon_ctx.thread) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (ashrink_init(session) != CT_SUCCESS) {
        return CT_ERROR;
    }

    knl_session_t *ashrink_se = kernel->sessions[SESSION_ID_ASHRINK];
    if (cm_create_thread(ashrink_proc, 0, ashrink_se, &kernel->ashrink_ctx.thread) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (cm_create_thread(idx_auto_rebuild_proc, 0, kernel->sessions[SESSION_ID_IDX_REBUILD],
        &kernel->auto_rebuild_ctx.thread) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t db_switchover_proc_init(knl_session_t *session)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;

    if (!DB_IS_PRIMARY(db) || DB_IS_RAFT_ENABLED(kernel)) {
        if (DB_IS_CLUSTER(session)) {
            if (lrpl_init(session) != CT_SUCCESS) {
                return CT_ERROR;
            }
            return CT_SUCCESS;
        }
        if (KNL_GBP_ENABLE(kernel)) {
            if (gbp_aly_init(session) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }

        rcy_init_proc(session);
        if (lrpl_init(session) != CT_SUCCESS) {
            return CT_ERROR;
        }
        CT_LOG_RUN_INF("The lrpl has been initialized.");
    }

    if (DB_IS_PRIMARY(db) || DB_IS_PHYSICAL_STANDBY(db)) {
        if (lsnd_init(session) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    CT_LOG_RUN_INF("[DB]: db switchover proc init finish.");
    return CT_SUCCESS;
}

/**
 * When redo log is corrupted and database cannot recover, we can use recover database until cancel
 * Then need open database with resetlogs or force ignore logs
 * If force ignore logs and current point less than consistent point, database can also open
 */
static status_t db_reset_ignore_log(knl_session_t *session,  bool32 resetlogs, bool32 force_ignore_logs)
{
    rcy_context_t *rcy = &session->kernel->rcy_ctx;
    log_point_t lrp_point = dtc_my_ctrl(session)->lrp_point;
    uint64 consistent_lfn = dtc_my_ctrl(session)->consistent_lfn;

    if (!resetlogs && !force_ignore_logs && RCY_IGNORE_CORRUPTED_LOG(rcy)) {
        CT_THROW_ERROR(ERR_CANNOT_OPEN_DATABASE, "after recover until cancel",
                       "open resetlog or open force ignore log");
        return CT_ERROR;
    }

    if (consistent_lfn == 0) { // for database version downward compatibility
        consistent_lfn = lrp_point.lfn;
    }

    CT_LOG_RUN_INF("[DB] db is recover until cancel, rcy point lfn %llu, consistent point %llu",
                   (uint64)dtc_my_ctrl(session)->rcy_point.lfn, (uint64)consistent_lfn);

    if (dtc_my_ctrl(session)->rcy_point.lfn < consistent_lfn) {
        if (force_ignore_logs) {
            dtc_my_ctrl(session)->open_inconsistency = CT_TRUE;
            CT_LOG_RUN_WAR("[DB] force ignore redo log, database may not be in consistency");
        } else {
            CT_THROW_ERROR(ERR_OPEN_RESETLOGS, dtc_my_ctrl(session)->rcy_point.lfn, consistent_lfn);
            return CT_ERROR;
        }
    }

    db_reset_log(session, CT_INVALID_ASN, CT_TRUE, CT_TRUE);

    if (db_save_core_ctrl(session) != CT_SUCCESS) {
        CM_ABORT(0, "[DB] ABORT INFO: save core control file failed when reset log.");
    }

    return CT_SUCCESS;
}

static status_t db_mode_set(knl_session_t *session, db_open_opt_t *options)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    rcy_context_t *rcy = &session->kernel->rcy_ctx;
    database_t *db = &kernel->db;

    if (options->open_status >= DB_OPEN_STATUS_RESTRICT) {
        if (session->uid != DB_SYS_USER_ID) {
            CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "of opening for restrict or upgrade mode", "non-system user");
            return CT_ERROR;
        }
        db->open_status = options->open_status;
    }
    db->terminate_lfn = options->lfn;
    db->has_load_role = CT_FALSE;

    if (options->readonly || !DB_IS_PRIMARY(db)) {
        CT_LOG_RUN_INF("The db is set as readonly");
        db->is_readonly = CT_TRUE;
        db->readonly_reason = DB_IS_PRIMARY(db) ? MANUALLY_SET : PHYSICAL_STANDBY_SET;
        //        tx_rollback_close(session);
    }

    if (options->resetlogs && !RCY_IGNORE_CORRUPTED_LOG(rcy)) {
        if (session->kernel->attr.clustered) {
            if (dtc_reset_log(session, CT_TRUE, CT_TRUE) != CT_SUCCESS) {
                return CT_ERROR;
            }
        } else {
            if (!LOG_POINT_LFN_EQUAL(&dtc_my_ctrl(session)->rcy_point, &dtc_my_ctrl(session)->lrp_point)) {
                CT_THROW_ERROR(ERR_OPEN_RESETLOGS, dtc_my_ctrl(session)->rcy_point.lfn,
                               dtc_my_ctrl(session)->lrp_point.lfn);
                return CT_ERROR;
            }

            db_reset_log(session, CT_INVALID_ASN, CT_TRUE, CT_TRUE);

            if (db_save_core_ctrl(session) != CT_SUCCESS) {
                CM_ABORT(0, "[DB] ABORT INFO: save core control file failed when reset log.");
            }
        }
    }

    if (RCY_IGNORE_CORRUPTED_LOG(rcy)) {
        if (db_reset_ignore_log(session, options->resetlogs, options->ignore_logs) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    rcy->action = RECOVER_NORMAL;
    return CT_SUCCESS;
}

status_t db_callback_function(knl_session_t *session)
{
    if (g_knl_callback.pl_init(session) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DB]: callback function pl init failed.");
        return CT_ERROR;
    }

#ifdef Z_SHARDING
    if (g_knl_callback.init_shard_resource(session) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DB]: callback function init shard resource failed.");
        return CT_ERROR;
    }
#endif

    if (g_knl_callback.init_sql_maps(session) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DB]: callback function init sql maps failed.");
        return CT_ERROR;
    }

    if (g_knl_callback.init_resmgr(session) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DB]: callback function init resmgr failed.");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t db_mount_to_recovery(knl_session_t *session, db_open_opt_t *options, bool32 *has_offline)
{
    core_ctrl_t *core_ctrl = DB_CORE_CTRL(session);
    bool32 is_upgrade = (options->open_status >= DB_OPEN_STATUS_UPGRADE) ? CT_TRUE : CT_FALSE;
    drlatch_t *ctrl_latch = &session->kernel->db.ctrl_latch;

    mes_set_message_timeout_check_func(dtc_is_in_rcy);
    
    if (log_load(session) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DB OPEN] log_load failed");
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("[DB OPEN] log_load finished");

    dtc_wait_reform_util(session, CT_FALSE, REFORM_RECOVER_DONE);

    if (knl_ddl_latch_s(ctrl_latch, session, NULL) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DB OPEN] latch ddl failed");
        return CT_ERROR;
    }

    if (DB_IS_CLUSTER(session)) {
        // full recovery do not need mount ctrl again
        if (!rc_is_master() && db_mount_ctrl(session) != CT_SUCCESS) {
            dls_unlatch(session, ctrl_latch, NULL);
            CT_LOG_RUN_ERR("[DB OPEN] mount ctrl failed");
            return CT_ERROR;
        }
        rc_allow_reform_finish();
        dtc_wait_reform();
        CT_LOG_RUN_INF("[DB OPEN] dtc_wait_reform finished");
    }

    if (log_check_asn(session, options->ignore_logs) != CT_SUCCESS) {
        dls_unlatch(session, ctrl_latch, NULL);
        CT_THROW_ERROR(ERR_INVALID_OPERATION, ", check log asn failed when open database");
        CT_LOG_RUN_ERR("[DB OPEN] log_check_asn failed");
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("[DB OPEN] log_check_asn finished");

    if (!db_sysdata_version_is_equal(session, is_upgrade)) {
        dls_unlatch(session, ctrl_latch, NULL);
        CT_LOG_RUN_ERR("[DB OPEN] db_sysdata_version_is_equal failed");
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("[DB OPEN] db_sysdata_version_is_equal finished");

    if (db_mode_set(session, options) != CT_SUCCESS) {
        dls_unlatch(session, ctrl_latch, NULL);
        CT_LOG_RUN_ERR("[DB OPEN] db_mode_set failed");
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("[DB OPEN] db_mode_set finished");

    if (raft_load(session) != CT_SUCCESS) {
        dls_unlatch(session, ctrl_latch, NULL);
        CT_LOG_RUN_ERR("[DB OPEN] raft_load failed");
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("[DB OPEN] raft_load finished");

    if (db_load_tablespaces(session, has_offline) != CT_SUCCESS) {
        knl_panic_log(0, "[DB OPEN] db_load_tablespaces failed");
        dls_unlatch(session, ctrl_latch, NULL);
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("[DB OPEN] db_load_tablespaces finished");

    db_load_systables(session);
    CT_LOG_RUN_INF("[DB OPEN] db_load_systables finished");

    undo_init(session, 0, core_ctrl->undo_segments);
    CT_LOG_RUN_INF("[DB OPEN] undo_init finished");

    if (lock_area_init(session) != CT_SUCCESS) {
        knl_panic_log(0, "[DB OPEN] lock_area_init failed");
        dls_unlatch(session, ctrl_latch, NULL);
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("[DB OPEN] lock_area_init finished");

    btree_area_init(session);
    CT_LOG_RUN_INF("[DB OPEN] btree_area_init finished");

    lob_area_init(session);
    CT_LOG_RUN_INF("[DB OPEN] lob_area_init finished");

    if (tx_area_init(session, 0, core_ctrl->undo_segments) != CT_SUCCESS) {
        knl_panic_log(0, "[DB OPEN] tx_area_init failed");
        dls_unlatch(session, ctrl_latch, NULL);
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("[DB OPEN] tx_area_init finished");

    ckpt_load(session);
    CT_LOG_RUN_INF("[DB OPEN] ckpt_load finished");

    if (arch_start(session) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DB OPEN] arch_start failed");
        dls_unlatch(session, ctrl_latch, NULL);
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("[DB OPEN] arch_start finished");
    dls_unlatch(session, ctrl_latch, NULL);

    return CT_SUCCESS;
}

static status_t db_check_terminate_lfn(knl_session_t *session, uint64 lfn)
{
    database_t *db = &session->kernel->db;

    if (lfn == CT_INVALID_LFN) {
        return CT_SUCCESS;
    }

    if (DB_IS_PRIMARY(db)) {
        CT_LOG_RUN_ERR("[UPGRADE] The operation entering terminated lfn for primary role was not allowed");
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "entering terminated lfn for primary role");
        return CT_ERROR;
    }

    if (lfn < (uint64)dtc_my_ctrl(session)->lrp_point.lfn) {
        CT_LOG_RUN_ERR("[UPGRADE] terminated lfn [%llu] is less than lrp point's lfn [%llu]", lfn,
                       (uint64)dtc_my_ctrl(session)->lrp_point.lfn);
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "entering terminated lfn less than lrp point");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t db_recovery_to_initphase2(knl_session_t *session, bool32 has_offline)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    undo_set_t *undo_set = MY_UNDO_SET(session);

    if (dtc_my_ctrl(session)->shutdown_consistency) {
        CT_LOG_RUN_INF("The last shutdown is consistent");
        if (!DB_IS_RAFT_ENABLED(kernel)) {
        knl_panic(log_cmp_point(&dtc_my_ctrl(session)->rcy_point, &dtc_my_ctrl(session)->lrp_point) == 0 &&
                  LOG_POINT_LFN_EQUAL(&dtc_my_ctrl(session)->rcy_point, &dtc_my_ctrl(session)->lrp_point));
        }
    } else {
        CT_LOG_RUN_INF("The last shutdown is inconsistent");
    }

    if (rcy_recover(session) != CT_SUCCESS) {
        session->kernel->rcy_ctx.is_working = CT_FALSE;
        return CT_ERROR;
    }

    if (kernel->lrcv_ctx.is_building) {
        if (rst_truncate_datafile(session) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    ckpt_trigger(session, has_offline, CKPT_TRIGGER_FULL);
    dtc_my_ctrl(session)->shutdown_consistency = CT_FALSE;
    if (db_save_core_ctrl(session) != CT_SUCCESS) {
        CM_ABORT(0, "[DB] ABORT INFO: save core control file failed after ckpt is completed");
    }

    if (DB_IS_PRIMARY(db)) {
        tx_area_release(session, undo_set);
        if (spc_clean_garbage_space(session) != CT_SUCCESS) {
            CT_LOG_RUN_WAR("[SPACE] failed to clean garbage tablespace");
        }
    } else {
        core_ctrl_t *core_ctrl = DB_CORE_CTRL(session);
        tx_area_release_impl(session, 0, core_ctrl->undo_segments, session->kernel->id);
    }

    return CT_SUCCESS;
}

static status_t db_initphase2_to_open(knl_session_t *session)
{
    repl_role_t old_role = REPL_ROLE_PRIMARY;
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;

    if (!DB_IS_MAINTENANCE(session) && !DB_IS_READONLY(session)) {
        undo_shrink_inactive_segments(session);
    }

    db_garbage_segment_init(session);

    if (DB_IS_CLUSTER(session)) {
        dtc_wait_reform_open();
    }

    if (dc_init(session) != CT_SUCCESS) {
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("[DB]: dc init finish.");

    if (!DB_IS_UPGRADE(session)) {
        if (db_callback_function(session) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    db->ctrl.core.open_count++;
    if (db_save_core_ctrl(session) != CT_SUCCESS) {
        CM_ABORT(0, "[DB] ABORT INFO: failed to save core control file when open database");
    }

    if (db_switchover_proc_init(session) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (raft_db_start_follower(session, old_role) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("RAFT: db start follower failed.");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t db_open_precheck(knl_session_t *session, db_open_opt_t *options)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;

    if (!options->is_creating && !db->ctrl.core.build_completed) {
        CT_THROW_ERROR(ERR_DATABASE_NOT_COMPLETED);
        return CT_ERROR;
    }

    if (db_check_terminate_lfn(session, options->lfn) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (db_verify_systime(session, options->ignore_systime) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DB OPEN] db_verify_systime failed");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t db_open_check_nolog(knl_session_t *session, db_open_opt_t *options)
{
    bool32 has_nolog = CT_FALSE;
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;

    if (!DB_IS_PRIMARY(&kernel->db)) {
        return CT_SUCCESS;
    }

    if (options->open_status >= DB_OPEN_STATUS_RESTRICT || options->is_creating) {
        return CT_SUCCESS;
    }
    
    if (knl_database_has_nolog_object(session, &has_nolog) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!has_nolog) {
        return CT_SUCCESS;
    }
    
    if (!DB_IS_SINGLE(session)) {
        CT_LOG_RUN_ERR("[DB] can not open database in HA mode with nolog object exists.");
        return CT_ERROR;
    }

    if (kernel->db.ctrl.core.lrep_mode == LOG_REPLICATION_ON) {
        CT_LOG_RUN_ERR("[DB] can not open database with replication on while nolog object exists.");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t db_open(knl_session_t *session, db_open_opt_t *options)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    bool32 has_offline = CT_FALSE;

    mes_set_message_timeout_check_func(dtc_is_in_rcy);

    CT_LOG_RUN_INF("[DB OPEN] start to alter database OPEN, memory usage=%lu", cm_print_memory_usage());
    if (!cm_spin_try_lock(&kernel->lock)) {
        CT_THROW_ERROR(ERR_DB_START_IN_PROGRESS);
        return CT_ERROR;
    }

    if (db_open_precheck(session, options) != CT_SUCCESS) {
        cm_spin_unlock(&kernel->lock);
        CT_LOG_RUN_ERR("[DB OPEN] db_open_precheck failed");
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("[DB OPEN] db_open_precheck finished");

    if (db_mount_to_recovery(session, options, &has_offline) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DB OPEN] db_mount_to_recovery failed");
        cm_spin_unlock(&kernel->lock);
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("[DB OPEN] db_mount_to_recovery finished");

    db->status = DB_STATUS_RECOVERY;
    CT_LOG_RUN_INF("[DB OPEN] db status is RECOVRY.");
    if (db_recovery_to_initphase2(session, has_offline) != CT_SUCCESS) {
        cm_spin_unlock(&kernel->lock);
        CT_LOG_RUN_ERR("[DB OPEN] db_recovery_to_initphase2 failed");
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("[DB OPEN] db_recovery_to_initphase2 finished");

    // temp space may extra replay create datafile after rebuild
    spc_init_swap_space(session, SPACE_GET(session, dtc_my_ctrl(session)->swap_space));
    CT_LOG_RUN_INF("[DB OPEN] spc_init_swap_space finished");
    if (cm_dbs_is_enable_dbs() == CT_TRUE && CTRL_LOG_BACKUP_LEVEL(session) != CTRLLOG_BACKUP_LEVEL_NONE) {
        if (ctrl_backup_ctrl_info(session) != CT_SUCCESS) {
            cm_spin_unlock(&kernel->lock);
            CT_LOG_RUN_ERR("[DB OPEN] ctrl_backup_ctrl_info failed");
            return CT_ERROR;
        }
        CT_LOG_RUN_INF("[DB OPEN] ctrl_backup_ctrl_info finished");
    }

    db->status = DB_STATUS_INIT_PHASE2;
    CT_LOG_RUN_INF("[DB OPEN] db status is INIT PHASE2.");

    if (db_initphase2_to_open(session) != CT_SUCCESS) {
        cm_spin_unlock(&kernel->lock);
        CT_LOG_RUN_ERR("[DB OPEN] db_initphase2_to_open failed");
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("[DB OPEN] db_initphase2_to_open finished");

    if (db_open_check_nolog(session, options) != CT_SUCCESS) {
        CM_ABORT(0, "[DB] ABORT INFO: The database cannot be opened because of the nolog object.");
    }
    CT_LOG_RUN_INF("[DB OPEN] db_open_check_nolog finished");

    cm_spin_unlock(&kernel->lock);
    db->status = DB_STATUS_OPEN;

    if (DB_IS_PRIMARY(db) && db->ctrl.core.is_restored) {
        db_set_ctrl_restored(session, CT_FALSE);
    }
    CT_LOG_RUN_INF("[DB OPEN] db status is OPEN, memory usage=%lu.", cm_print_memory_usage());
    
    CT_LOG_RUN_INF("[DB OPEN] sse42 available %d", cm_crc32c_sse42_available());
    CT_LOG_RUN_INF("[DB OPEN] successfully alter database OPEN, running as %s role", db_get_role(db));
    return CT_SUCCESS;
}

status_t db_clean_record_arch(knl_session_t *session)
{
    // This operation is performed only during recovery for restore.
    uint32 archived_start;
    uint32 archived_end;
    arch_ctrl_t *arch_ctrl = NULL;
    for (uint32 node_id = 0; node_id < g_dtc->profile.node_count; node_id++) {
        archived_start = arch_get_arch_start(session, node_id);
        archived_end = arch_get_arch_end(session, node_id);
        if ((archived_end - archived_start + CT_MAX_ARCH_NUM) % CT_MAX_ARCH_NUM <= 0) {
            continue;
        }
        for (uint32 arch_locator = archived_start; arch_locator < archived_end; arch_locator++) {
            arch_ctrl = db_get_arch_ctrl(session, arch_locator, node_id);
            arch_ctrl->recid = 0;
            if (db_save_arch_ctrl(session, arch_locator, node_id) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }
        arch_set_arch_start(session, 0, node_id);
        arch_set_arch_end(session, 0, node_id);
        if (arch_save_ctrl(session, node_id) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    CT_LOG_RUN_INF("[RECOVER] success to clean record archive files");
    return CT_SUCCESS;
}

status_t db_recover(knl_session_t *session, knl_scn_t max_recover_scn, uint64 max_recover_lrp_lsn)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    bool32 has_offline = CT_FALSE;

    if (!cm_spin_try_lock(&kernel->lock)) {
        CT_THROW_ERROR(ERR_DB_START_IN_PROGRESS);
        return CT_ERROR;
    }

    if (db_load_tablespaces(session, &has_offline) != CT_SUCCESS) {
        cm_spin_unlock(&kernel->lock);
        return CT_ERROR;
    }

    if (log_load(session) != CT_SUCCESS) {
        cm_spin_unlock(&kernel->lock);
        return CT_ERROR;
    }

    ckpt_load(session);

    db->status = DB_STATUS_RECOVERY;
    session->kernel->rcy_ctx.max_scn = max_recover_scn;
    session->kernel->rcy_ctx.max_lrp_lsn = max_recover_lrp_lsn;
    if (rcy_recover(session) != CT_SUCCESS) {
        session->kernel->rcy_ctx.is_working = CT_FALSE;
        cm_spin_unlock(&kernel->lock);
        return CT_ERROR;
    }

    session->kernel->rcy_ctx.max_scn = CT_INVALID_ID64;
    session->kernel->rcy_ctx.max_lrp_lsn = CT_INVALID_ID64;
    ckpt_trigger(session, CT_TRUE, CKPT_TRIGGER_FULL);
    db->ctrl.core.build_completed = CT_TRUE;

    if (db_clean_record_arch(session) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RECOVER] failed to clean record archive files");
        cm_spin_unlock(&kernel->lock);
        return CT_ERROR;
    }

    if (db_save_core_ctrl(session) != CT_SUCCESS) {
        cm_spin_unlock(&kernel->lock);
        return CT_ERROR;
    }
    db->status = DB_STATUS_MOUNT;
    cm_spin_unlock(&kernel->lock);
    return CT_SUCCESS;
}

static bool32 db_build_need_retry(knl_session_t *session, status_t status)
{
    bak_t *bak = &session->kernel->backup_ctx.bak;
    int32 err_code;
    const char *error_msg = NULL;

    if (status == CT_SUCCESS) {
        return CT_FALSE;
    }

    bak_get_error(session, &err_code, &error_msg);
    CT_LOG_DEBUG_ERR("build failed, error code:%d, msg:%s", err_code, error_msg);
    if (err_code == ERR_BUILD_CANCELLED) {
        return CT_FALSE;
    }
    if (err_code == ERR_BACKUP_IN_PROGRESS) {
        bak->build_retry_time = 0;
        return CT_TRUE;
    }
    if (bak->need_retry) {
        return CT_TRUE;
    }
    return CT_FALSE;
}

static void db_build_set_role(database_t *db, build_type_t build_type)
{
    if (build_type == BUILD_AUTO) {
        if (!DB_IS_CASCADED_PHYSICAL_STANDBY(db)) {
            db->ctrl.core.db_role = REPL_ROLE_PHYSICAL_STANDBY;
        }
    } else if (build_type == BUILD_STANDBY) {
        db->ctrl.core.db_role = REPL_ROLE_PHYSICAL_STANDBY;
    } else {
        db->ctrl.core.db_role = REPL_ROLE_CASCADED_PHYSICAL_STANDBY;
    }
}

static bool32 db_build_check_peer_role(knl_session_t *session, build_type_t build_type)
{
    lrcv_context_t *lrcv = &session->kernel->lrcv_ctx;
    uint32 retry_count = CT_BACKUP_RETRY_COUNT;

    while (lrcv->peer_role == PEER_UNKNOWN) {
        if (retry_count == 0) {
            CT_THROW_ERROR(ERR_PRI_NOT_CONNECT, "peer role");
            return CT_FALSE;
        }

        cm_sleep(5);

        if (retry_count > 0) {
            retry_count--;
        }
    }

    if (lrcv->peer_role == PEER_STANDBY && build_type == BUILD_STANDBY) {
        CT_THROW_ERROR(ERR_INVALID_OPERATION, ",build standby not connect to primary database");
        return CT_FALSE;
    }

    return CT_TRUE;
}

static status_t db_build_restore_precheck(knl_session_t *session, knl_build_def_t *def)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    if (DB_IS_RAFT_ENABLED(session->kernel)) {
        CT_THROW_ERROR(ERR_INVALID_OPERATION,
            ",RAFT: build not supported when raft is enabled, please use builddb.sh instead.");
        return CT_ERROR;
    }

    if (def->param_ctrl.is_increment || def->param_ctrl.is_repair) {
        if (db->status != DB_STATUS_MOUNT) {
            CT_THROW_ERROR(ERR_INVALID_OPERATION, ",increment or repair build can only be executed on MOUNT status");
            return CT_ERROR;
        }

        if (!session->kernel->db.ctrl.core.build_completed) {
            CT_THROW_ERROR(ERR_DATABASE_NOT_COMPLETED);
            return CT_ERROR;
        }
    } else {
        if (db->status != DB_STATUS_NOMOUNT) {
            CT_THROW_ERROR(ERR_INVALID_OPERATION, ",operation can only be executed on NOMOUNT status");
            return CT_ERROR;
        }
    }

    if (def->param_ctrl.is_repair) {
        if (DB_IS_PRIMARY(db)) {
            CT_THROW_ERROR(ERR_INVALID_OPERATION, ",repair build can not be executed on primary");
            return CT_ERROR;
        }

        if (!knl_brain_repair_check(session)) {
            return CT_ERROR;
        }
    }

    if (!db_build_check_peer_role(session, def->build_type)) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t db_build_restore(knl_session_t *session, knl_build_def_t *def)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    status_t status = CT_ERROR;
    bak_t *bak = &kernel->backup_ctx.bak;

    if (db_build_restore_precheck(session, def) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (def->build_type != BUILD_AUTO) {
        session->kernel->lrcv_ctx.role_spec_building = CT_TRUE;
    }

    kernel->lrcv_ctx.is_building = CT_TRUE;
    db->status = def->param_ctrl.is_increment || def->param_ctrl.is_repair ? db->status : DB_STATUS_CREATING;
    db->ctrl.core.db_role = REPL_ROLE_PHYSICAL_STANDBY;
    bak->build_retry_time = BAK_BUILD_INIT_RETRY_TIME;
    def->param_ctrl.base_lsn = CT_INVALID_LSN;
    do {
        cm_reset_error();
        status = bak_build_restore(session, &def->param_ctrl);
        cm_sleep(1000);
    } while (db_build_need_retry(session, status));

    if (status != CT_SUCCESS) {
        db->status = DB_STATUS_NOMOUNT;
        kernel->lrcv_ctx.is_building = CT_FALSE;
        CT_LOG_RUN_ERR("[DB] failed to backup database");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t db_build_baseline(knl_session_t *session, knl_build_def_t *def)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    bool32 no_wait = CT_FALSE;
    errno_t err;

    if (db_build_restore(session, def) != CT_SUCCESS) {
        return CT_ERROR;
    }

    CT_LOG_RUN_INF("[DB] database backup successfully");

    db->ctrl.core.build_completed = CT_TRUE;
    err = memset_sp(db->ctrl.core.archived_log, sizeof(arch_log_id_t) * CT_MAX_ARCH_DEST, 0,
                    sizeof(arch_log_id_t) * CT_MAX_ARCH_DEST);
    knl_securec_check(err);

    db_build_set_role(db, def->build_type);

    if (db_save_core_ctrl(session) != CT_SUCCESS) {
        CM_ABORT(0, "[DB] ABORT INFO: failed to save core control file when build baseline");
    }

    if (!def->param_ctrl.is_increment && !def->param_ctrl.is_repair) {
        if (db_mount(session) != CT_SUCCESS) {
            kernel->lrcv_ctx.is_building = CT_FALSE;
            return CT_ERROR;
        }
    }

    kernel->lrcv_ctx.reconnected = CT_FALSE;

    /*
     * If one node connects to primary and wants to build a cascaded standby, the primary will disconnect
     * with it after build successfully. So in this scenario, there is no need to wait log receiver to become prepared.
     */
    no_wait = (bool32)(DB_IS_CASCADED_PHYSICAL_STANDBY(db) && kernel->lrcv_ctx.role_spec_building &&
                       kernel->lrcv_ctx.peer_role == PEER_PRIMARY);

    db_open_opt_t open_options = {
        CT_FALSE, CT_FALSE, CT_FALSE, CT_FALSE, CT_TRUE, DB_OPEN_STATUS_NORMAL, CT_INVALID_LFN
    };
    if (db_open(session, &open_options) != CT_SUCCESS) {
        kernel->lrcv_ctx.is_building = CT_FALSE;
        return CT_ERROR;
    }

    if (!no_wait) {
        lrcv_wait_status_prepared(session);
    }

    kernel->lrcv_ctx.is_building = CT_FALSE;
    CT_LOG_RUN_INF("database build successfully");
    return CT_SUCCESS;
}

static char *db_get_role(database_t *db)
{
    if (DB_IS_PRIMARY(db)) {
        return "primary";
    } else if (DB_IS_PHYSICAL_STANDBY(db)) {
        return "physical standby";
    } else if (DB_IS_CASCADED_PHYSICAL_STANDBY(db)) {
        return "cascaded physical standby";
    } else {
        return "unknown";
    }
}

char *db_get_switchover_status(knl_session_t *session)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;

    if (DB_IS_PHYSICAL_STANDBY(&kernel->db)) {
        return "TO PRIMARY";
    } else {
        return "NOT ALLOWED";
    }
}

char *db_get_failover_status(knl_session_t *session)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;

    if (!DB_IS_PRIMARY(&kernel->db)) {
        return "TO PRIMARY";
    } else {
        return "NOT ALLOWED";
    }
}

char *db_get_condition(knl_session_t *session)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    switch_ctrl_t *ctrl = &kernel->switch_ctrl;
    lrcv_context_t *lrcv = &kernel->lrcv_ctx;
    lftc_clt_ctx_t *lftc_clt = &kernel->lftc_client_ctx;

    switch (ctrl->request) {
        case SWITCH_REQ_DEMOTE:
            return "DEMOTING";
        case SWITCH_REQ_PROMOTE:
            return "PROMOTING";
        case SWITCH_REQ_FAILOVER_PROMOTE:
        case SWITCH_REQ_FORCE_FAILOVER_PROMOTE:
            return "FAILOVER PROMOTING";
        case SWITCH_REQ_RAFT_PROMOTE:
            return "RAFT FAILOVER";
        default:
            break;
    }

    // for other scenarios, just return normal in primary role
    if (DB_IS_PRIMARY(&kernel->db)) {
        return "NORMAL";
    }

    // for other scenarios, check log receiver in standby role
    if (lrcv->status == LRCV_NEED_REPAIR || lftc_clt->arch_lost ||
        kernel->rcy_ctx.log_decrypt_failed || lrpl_replay_blocked(session)) {
        return "NEED REPAIR";
    } else if (lrcv->state == REP_STATE_WAITING_DEMOTE) {
        return "WAIT TO PROMOTE";
    } else if (lrcv->status < LRCV_PREPARE) {
        return "DISCONNECTED";
    } else {
        return "NORMAL";
    }
}

char *db_get_needrepair_reason(knl_session_t *session)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    lrcv_context_t *lrcv = &kernel->lrcv_ctx;
    lftc_clt_ctx_t *lftc_clt = &kernel->lftc_client_ctx;

    if (DB_IS_PRIMARY(&kernel->db)) {
        return "NONE";
    }

    if (lrpl_replay_blocked(session)) {
        return "REPLAY BLOCKED";
    }

    if (lftc_clt->arch_lost) {
        return "ARCHIVE LOG LOST";
    }

    if (kernel->rcy_ctx.log_decrypt_failed) {
        return "LOG DECRYPT FAILED";
    }

    if (lrcv->status == LRCV_NEED_REPAIR) {
        return "OTHER REASONS";
    }

    return "NONE";
}

char *db_get_readonly_reason(knl_session_t *session)
{
    database_t *db = &session->kernel->db;

    switch (db->readonly_reason) {
        case PRIMARY_SET:
            return "NONE";
        case PHYSICAL_STANDBY_SET:
            return "PHYSICAL STANDBY";
        case MANUALLY_SET:
            return "MANUALLY SET";
        case RMON_SET:
            return "RMON SET";
        default:
            return "OTHER REASONS";
    }
}

char *db_get_status(knl_session_t *session)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;

    switch (db->status) {
        case DB_STATUS_CLOSED:
            return "CLOSED";
        case DB_STATUS_NOMOUNT:
            return "NOMOUNT";
        case DB_STATUS_CREATING:
            return "CREATING";
        case DB_STATUS_MOUNT:
            return "MOUNT";
        case DB_STATUS_RECOVERY:
            return "RECOVERY";
        case DB_STATUS_INIT_PHASE2:
            return "INIT PHASE2";
        case DB_STATUS_WAIT_CLEAN:
            return "WAIT CLEAN";
        case DB_STATUS_OPEN:
            return "OPEN";
        default:
            CT_LOG_RUN_ERR("[DB] unexpected database status %d", db->status);
            return "INVALID STATUS";
    }
}

uint64 knl_current_scn(knl_handle_t session)
{
    return (uint64)DB_CURR_SCN((knl_session_t *)session);
}

uint64 knl_next_scn(knl_handle_t session)
{
    return (uint64)db_next_scn((knl_session_t *)session);
}

time_t knl_init_time(knl_handle_t session)
{
    return DB_INIT_TIME((knl_session_t *)session);
}

/*
 * reset logfile to a new time line, we set update rst_id of the
 * current logfile, skip recovery if requested.
 * @param kernel session, reset recover, reset archive
 */
void db_reset_log(knl_session_t *session, uint32 switch_asn, bool32 reset_recover, bool32 reset_archive)
{
    database_t *db = &session->kernel->db;
    core_ctrl_t *core = &db->ctrl.core;
    reset_log_t *reset_log = &core->resetlogs;
    log_context_t *log = &session->kernel->redo_ctx;
    log_file_t *logfile = &log->files[log->curr_file];
    uint32 last_asn;
    errno_t err;

    last_asn = (switch_asn != CT_INVALID_ASN) ? (switch_asn - 1) : (logfile->head.asn - 1);
    CT_LOG_RUN_INF("reset log from rst_id %u asn %u lfn %llu, reset_log_scn %llu, curr_scn %llu",
                   log->curr_point.rst_id, last_asn, (uint64)log->curr_point.lfn, core->reset_log_scn, log->curr_scn);

    reset_log->last_asn = last_asn;
    reset_log->last_lfn = log->curr_point.lfn;
    reset_log->rst_id = (uint32)log->curr_point.rst_id + 1;
    bool32 is_stor = knl_dbs_is_enable_dbs();
    if (is_stor) {
        reset_log->last_lsn = log->curr_point.lsn;
    }
    if (!CT_INVALID_SCN(log->curr_scn)) {
        core->reset_log_scn = log->curr_scn;
    }

    logfile->head.rst_id = reset_log->rst_id;
    log_flush_head(session, logfile);

    if (reset_recover) {
        log_point_t point;
        point.asn = logfile->head.asn;
        point.rst_id = logfile->head.rst_id;
        point.lfn = dtc_my_ctrl(session)->rcy_point.lfn;
        if (cm_dbs_is_enable_dbs() == CT_TRUE) {
            (void)cm_dbs_ulog_get_maxLsn(logfile->ctrl->name, &point.lsn);
            point.block_id = 0;
        } else {
            /*
            * write_pos is calculated by CM_CALC_ALIGN use sizeof(log_file_head_t) and block_size,
            * block_size is 512 or 4096, so value is smaller than uint32.
            */
            point.block_id = (uint32)(logfile->head.write_pos / (uint32)logfile->head.block_size);
        }
        ckpt_reset_point(session, &point);
    }

    if (reset_archive) {
        err = memset_sp(core->archived_log, sizeof(arch_log_id_t) * CT_MAX_ARCH_DEST, 0,
                        sizeof(arch_log_id_t) * CT_MAX_ARCH_DEST);
        knl_securec_check(err);
    }
    if (DB_ATTR_CLUSTER(session) && CTRL_LOG_BACKUP_LEVEL(session) != CTRLLOG_BACKUP_LEVEL_NONE &&
        cm_dbs_is_enable_dbs() == CT_TRUE) {
        if (dbs_ctrl_backup_reset_logs(session) != CT_SUCCESS) {
            CM_ABORT(0, "[DB] ABORT INFO: Failed to backup reset logs when reset logs");
        }
    } else if (!DB_ATTR_CLUSTER(session)){
        if (ctrl_backup_reset_logs(session) != CT_SUCCESS) {
            CM_ABORT(0, "[DB] ABORT INFO: Failed to backup reset logs when reset logs");
        }
    }
}

status_t db_change_storage_path(file_convert_t *convert, char *name, uint32 name_size)
{
    file_name_convert_t *list = NULL;
    text_t left;
    text_t right;
    text_t text;
    char right_str[CT_FILE_NAME_BUFFER_SIZE];
    uint32 i;
    errno_t err;

    if (!convert->is_convert) {
        return CT_SUCCESS;
    }

    cm_str2text(name, &text);
    (void)cm_split_rtext(&text, SLASH, '\0', &left, &right);
    cm_delete_text_end_slash(&left);
    (void)cm_text2str(&right, right_str, CT_FILE_NAME_BUFFER_SIZE);

    for (i = 0; i < convert->count; i++) {
        list = &convert->convert_list[i];
        if (cm_check_exist_special_char(list->primry_path, (uint32)strlen(list->primry_path))) {
            CT_THROW_ERROR(ERR_INVALID_DIR, list->primry_path);
            return CT_ERROR;
        }
        if (cm_check_exist_special_char(list->standby_path, (uint32)strlen(list->standby_path))) {
            CT_THROW_ERROR(ERR_INVALID_DIR, list->standby_path);
            return CT_ERROR;
        }
    }

    for (i = 0; i < convert->count; i++) {
        list = &convert->convert_list[i];
        cm_try_delete_end_slash(list->primry_path);
        if (cm_text_str_equal_ins(&left, list->primry_path)) {
            cm_try_delete_end_slash(list->standby_path);
            err = snprintf_s(name, name_size, name_size - 1, "%s/%s", list->standby_path,
                             right_str);
            knl_securec_check_ss(err);

            return CT_SUCCESS;
        }
    }

    return CT_SUCCESS;
}

uint64 db_get_datafiles_used_size(knl_session_t *session)
{
    space_t *space = NULL;
    uint64 total_pages = 0;
    uint32 i;

    for (i = 0; i < CT_MAX_SPACES; i++) {
        space = SPACE_GET(session, i);
        if (!SPACE_IS_ONLINE(space) || !space->ctrl->used) {
            continue;
        }

        if (IS_SWAP_SPACE(space)) {
            total_pages++;
        } else {
            total_pages += spc_count_backup_pages(session, space);
        }
    }
    cm_reset_error();
    return total_pages * DEFAULT_PAGE_SIZE(session);
}

uint64 db_get_datafiles_size(knl_session_t *session)
{
    datafile_ctrl_t *ctrl = NULL;
    uint64 total_size = 0;
    uint32 i;

    for (i = 0; i < CT_MAX_DATA_FILES; i++) {
        ctrl = session->kernel->db.datafiles[i].ctrl;
        if (!ctrl->used) {
            continue;
        }

        total_size += (uint64)ctrl->size;
    }

    return total_size;
}

uint64 db_get_logfiles_size(knl_session_t *session)
{
    log_file_ctrl_t *ctrl = NULL;
    uint64 total_size = 0;
    uint32 i;
    logfile_set_t *logfile_set = MY_LOGFILE_SET(session);

    for (i = 0; i < logfile_set->logfile_hwm; i++) {
        ctrl = logfile_set->items[i].ctrl;
        if (LOG_IS_DROPPED(ctrl->flg)) {
            continue;
        }

        total_size += (uint64)ctrl->size;
    }

    return total_size;
}

/*
 * clean nologging data, called when:
 * 1. db restart, no matter restart as primary or standby;
 * 2. db failover/switchover;
 */
static void db_clean_nologging_data(knl_session_t *session)
{
    stats_clean_nologging_stats(session);
    CT_LOG_RUN_INF("[DB] Clean nologging data start.");

    /* 1. make in-memory nologging dc as empty */
    dc_invalidate_nologging(session);

    /* 2. make on-disk nologging space as empty */
    spc_clean_nologging_data(session);
    CT_LOG_RUN_INF("[DB] Clean nologging data end.");
}

/*
 * drop nologging tables if needed, call when:
 * 1. db restart to primary;
 * 2. db failover/switchover;
 */
static status_t db_drop_nologging_table(knl_session_t *session)
{
    status_t status = CT_SUCCESS;

    if (session->kernel->attr.drop_nologging) {
        status = spc_drop_nologging_table(session);
        CT_LOG_RUN_INF("[DB] Drop nologging table status:%d", status);
    }

    return status;
}

status_t db_clean_nologging_all(knl_session_t *session)
{
    if (DB_IS_CLUSTER(session) || DB_IS_MAINTENANCE(session)) {
        return CT_SUCCESS;
    }

    CT_LOG_RUN_INF("[DB] Clean nologging tables start.");
    /* 1. clean nologging table data */
    db_clean_nologging_data(session);

    /* 2. drop nologging table if needed */
    if (db_drop_nologging_table(session) != CT_SUCCESS) {
        return CT_ERROR;
    }

    /* 3. make on-disk nologging space as empty again */
    spc_clean_nologging_data(session);

    /* 4. reset nologging space head */
    spc_rebuild_temp2_undo(session, NULL);

    /* 5. init temp free page list */
    temp2_undo_init(session);
    CT_LOG_RUN_INF("[DB] Clean nologging tables end.");

    return CT_SUCCESS;
}

void db_convert_temp_path(knl_session_t *session, const char* path)
{
    knl_instance_t *kernel = session->kernel;
    datafile_ctrl_t *datafile = NULL;
    log_file_ctrl_t *logfile = NULL;
    errno_t err;
    uint32 i;
    logfile_set_t *logfile_set = MY_LOGFILE_SET(session);

    for (i = 0; i < CT_MAX_DATA_FILES; i++) {
        datafile = kernel->db.datafiles[i].ctrl;
        err = snprintf_s(datafile->name, CT_FILE_NAME_BUFFER_SIZE, CT_FILE_NAME_BUFFER_SIZE - 1, "%s/%s_%u",
                         path, "data", i);
        knl_securec_check_ss(err);
    }
    bool32 is_dbstor = knl_dbs_is_enable_dbs();
    for (i = 0; i < logfile_set->logfile_hwm; i++) {
        logfile = logfile_set->items[i].ctrl;
        err = snprintf_s(logfile->name, CT_FILE_NAME_BUFFER_SIZE, CT_FILE_NAME_BUFFER_SIZE - 1, "%s/%s_%u",
                         path, "log", i);
        knl_securec_check_ss(err);
        if (is_dbstor) {
            break;
        }
    }
}

void db_set_with_switchctrl_lock(switch_ctrl_t *ctrl, volatile bool32 *working)
{
    if (!cm_spin_try_lock(&ctrl->lock)) {
        return;
    }

    if (ctrl->request != SWITCH_REQ_NONE) {
        cm_spin_unlock(&ctrl->lock);
        return;
    }

    *working = CT_TRUE;
    cm_spin_unlock(&ctrl->lock);
}

static void db_update_lobs_seg_scn(knl_session_t *session, knl_dictionary_t *dc)
{
    lob_t *lob = NULL;
    knl_column_t *column = NULL;
    lob_part_t *lob_part = NULL;
    lob_part_t *lob_subpart = NULL;
    table_part_t *table_part = NULL;
    dc_entity_t *entity = DC_ENTITY(dc);
    table_t *table = DC_TABLE(dc);

    for (uint32 i = 0; i < entity->column_count; i++) {
        column = dc_get_column(entity, i);
        if (!COLUMN_IS_LOB(column)) {
            continue;
        }

        lob = (lob_t *)column->lob;
        if (!IS_PART_TABLE(table)) {
            if (lob->lob_entity.segment != NULL) {
                lob->desc.seg_scn = LOB_SEGMENT(session, lob->lob_entity.entry, lob->lob_entity.segment)->seg_scn;
            }

            continue;
        }

        for (uint32 j = 0; j < table->part_table->desc.partcnt; j++) {
            table_part = TABLE_GET_PART(table, j);
            lob_part = LOB_GET_PART(lob, j);
            if (!IS_READY_PART(table_part) || lob_part == NULL) {
                continue;
            }
            
            if (!IS_PARENT_LOBPART(&lob_part->desc)) {
                if (lob_part->lob_entity.segment != NULL) {
                    lob_part->desc.seg_scn = LOB_SEGMENT(session, lob_part->lob_entity.entry,
                        lob_part->lob_entity.segment)->seg_scn;
                }

                continue;
            }

            for (uint32 k = 0; k < lob_part->desc.subpart_cnt; k++) {
                lob_subpart = PART_GET_SUBENTITY(lob->part_lob, lob_part->subparts[k]);
                if (lob_subpart == NULL) {
                    continue;
                }

                if (lob_subpart->lob_entity.segment != NULL) {
                    lob_subpart->desc.seg_scn = LOB_SEGMENT(session, lob_subpart->lob_entity.entry,
                        lob_subpart->lob_entity.segment)->seg_scn;
                }
            }
        }
    }
}

static void db_update_index_seg_scn(knl_session_t *session, table_t *table, index_t *index)
{
    index_part_t *index_part = NULL;
    table_part_t *table_part = NULL;
    index_part_t *index_subpart = NULL;

    if (!IS_PART_INDEX(index)) {
        if (index->btree.segment != NULL) {
            index->desc.seg_scn = BTREE_SEGMENT(session, index->btree.entry, index->btree.segment)->seg_scn;
        }

        return;
    }

    for (uint32 i = 0; i < index->part_index->desc.partcnt; i++) {
        table_part = TABLE_GET_PART(table, i);
        index_part = INDEX_GET_PART(index, i);
        if (!IS_READY_PART(table_part) || index_part == NULL) {
            continue;
        }
        
        if (!IS_PARENT_IDXPART(&index_part->desc)) {
            if (index_part->btree.segment != NULL) {
                index_part->desc.seg_scn = BTREE_SEGMENT(session, index_part->btree.entry,
                    index_part->btree.segment)->seg_scn;
            }

            continue;
        }

        for (uint32 j = 0; j < index_part->desc.subpart_cnt; j++) {
            index_subpart = PART_GET_SUBENTITY(index->part_index, index_part->subparts[j]);
            if (index_subpart == NULL) {
                continue;
            }

            if (index_subpart->btree.segment != NULL) {
                index_subpart->desc.seg_scn = BTREE_SEGMENT(session, index_subpart->btree.entry,
                    index_subpart->btree.segment)->seg_scn;
            }
        }
    }
}

void db_update_seg_scn(knl_session_t *session, knl_dictionary_t *dc)
{
    index_t *index = NULL;
    table_part_t *table_part = NULL;
    table_part_t *table_subpart = NULL;
    dc_entity_t *entity = DC_ENTITY(dc);
    table_t *table = DC_TABLE(dc);

    if (entity->contain_lob) {
        db_update_lobs_seg_scn(session, dc);
    }

    if (table->desc.type == TABLE_TYPE_TRANS_TEMP || table->desc.type == TABLE_TYPE_SESSION_TEMP) {
        return;
    }

    for (uint32 i = 0; i < table->index_set.total_count; i++) {
        index = table->index_set.items[i];
        db_update_index_seg_scn(session, table, index);
    }

    if (!IS_PART_TABLE(table)) {
        table->desc.seg_scn = HEAP_SEGMENT(session, table->heap.entry, table->heap.segment)->seg_scn;
        return;
    }
    
    for (uint32 i = 0; i < table->part_table->desc.partcnt; i++) {
        table_part = TABLE_GET_PART(table, i);
        if (!IS_READY_PART(table_part)) {
            continue;
        }

        if (!IS_PARENT_TABPART(&table_part->desc)) {
            if (table_part->heap.segment != NULL) {
                table_part->desc.seg_scn = HEAP_SEGMENT(session, table_part->heap.entry,
                                                        table_part->heap.segment)->seg_scn;
            }

            continue;
        }

        for (uint32 j = 0; j < table_part->desc.subpart_cnt; j++) {
            table_subpart = PART_GET_SUBENTITY(table->part_table, table_part->subparts[j]);
            if (table_subpart == NULL) {
                continue;
            }

            if (table_subpart->heap.segment != NULL) {
                table_subpart->desc.seg_scn = HEAP_SEGMENT(session, table_subpart->heap.entry,
                    table_subpart->heap.segment)->seg_scn;
            }
        }
    }
}

void db_segments_stats_record(knl_session_t *session, seg_stat_t temp_stat, seg_stat_t *seg_stat)
{
    seg_stat_t stat;

    stat.logic_reads = session->stat->buffer_gets - temp_stat.logic_reads;
    stat.physical_reads = session->stat->disk_reads - temp_stat.physical_reads;
    stat.physical_writes = session->stat->disk_writes - temp_stat.physical_writes;
    stat.buf_busy_waits = session->stat_page.misses - temp_stat.buf_busy_waits;

    if (stat.logic_reads == 0 && stat.physical_reads == 0 && stat.physical_writes == 0 && stat.buf_busy_waits == 0) {
        return;
    }

    seg_stat->logic_reads += stat.logic_reads;
    seg_stat->physical_reads += stat.physical_reads;
    seg_stat->physical_writes += stat.physical_writes;
    seg_stat->buf_busy_waits += stat.buf_busy_waits;
}

void db_segment_stats_init(knl_session_t *session, seg_stat_t *temp_stat)
{
    temp_stat->physical_reads = session->stat->disk_reads;
    temp_stat->physical_writes = session->stat->disk_writes;
    temp_stat->logic_reads = session->stat->buffer_gets;
    temp_stat->buf_busy_waits = session->stat_page.misses;
}

static void db_record_runing_job(knl_session_t *session, bool32 demote, bool32 sync)
{
    knl_instance_t *kernel = session->kernel;

    if (kernel->stats_ctx.stats_gathering) {
        CT_LOG_RUN_INF("[DB] [%s] Stats gather is working", demote ? "SWITCHOVER" : "RAEDONLY");
    }

    if (kernel->smon_ctx.undo_shrinking) {
        CT_LOG_RUN_INF("[DB] [%s] Smon undo shrink is working", demote ? "SWITCHOVER" : "RAEDONLY");
    }

    if (kernel->index_ctx.recycle_ctx.is_working) {
        CT_LOG_RUN_INF("[DB] [%s] Index recycle is working", demote ? "SWITCHOVER" : "RAEDONLY");
    }

    if (sync) {
        CT_LOG_RUN_INF("[DB] [%s] Time sync is working", demote ? "SWITCHOVER" : "RAEDONLY");
    }

    if (kernel->rmon_ctx.working) {
        CT_LOG_RUN_INF("[DB] [%s] Rmon thread is working", demote ? "SWITCHOVER" : "RAEDONLY");
    }

    if (kernel->ashrink_ctx.working) {
        CT_LOG_RUN_INF("[DB] [%s] Ashrink thread is working", demote ? "SWITCHOVER" : "RAEDONLY");
    }

    if (kernel->auto_rebuild_ctx.working) {
        CT_LOG_RUN_INF("[DB] [%s] Auto rebuild thread is working", demote ? "SWITCHOVER" : "RAEDONLY");
    }
}

bool32 db_check_backgroud_blocked(knl_session_t *session, bool32 demote, bool32 sync)
{
    knl_instance_t *kernel = session->kernel;
    switch_ctrl_t *ctrl = &kernel->switch_ctrl;

    if (!kernel->stats_ctx.stats_gathering && !kernel->smon_ctx.undo_shrinking &&
        !kernel->index_ctx.recycle_ctx.is_working && !sync && !kernel->rmon_ctx.working &&
        !kernel->ashrink_ctx.working && !kernel->auto_rebuild_ctx.working) {
        ctrl->has_logged = CT_FALSE;
        ctrl->last_log_time = 0;
        return CT_FALSE;
    }

    if (ctrl->has_logged && (g_timer()->now - ctrl->last_log_time) / MICROSECS_PER_SECOND < BACKGROUD_LOG_INTERVAL) {
        return CT_TRUE;
    }

    db_record_runing_job(session, demote, sync);

    ctrl->has_logged = CT_TRUE;
    ctrl->last_log_time = g_timer()->now;

    return CT_TRUE;
}

static status_t dump_ctrl_space_item(cm_dump_t *dump, space_ctrl_t *space, uint32 space_no)
{
    cm_dump(dump, "\t#%-2u", space_no);
    cm_dump(dump, "\t%u", space->id);
    cm_dump(dump, "\t%u", (uint32)space->used);
    cm_dump(dump, "\t%-*s", (int)strlen(space->name), NULL_2_STR(space->name));
    cm_dump(dump, "\t%u", (uint32)space->flag);
    cm_dump(dump, "\t%u", (uint32)space->block_size);
    cm_dump(dump, "\t%u", space->extent_size);
    cm_dump(dump, "\t%u", space->file_hwm);
    cm_dump(dump, "\t%llu", space->org_scn);
    cm_dump(dump, "\t%u", (uint32)space->encrypt_version);
    cm_dump(dump, "\t%u", (uint32)space->cipher_reserve_size);
    cm_dump(dump, "\t%u", space->files[0]);
    for (uint32 j = 1; j < space->file_hwm; j++) {
        cm_dump(dump, ", %u", space->files[j]);
        CM_DUMP_WRITE_FILE(dump);
    }
    cm_dump(dump, "\n");
    CM_DUMP_WRITE_FILE(dump);

    return CT_SUCCESS;
}

static status_t dump_ctrl_datafile_item(cm_dump_t *dump, datafile_ctrl_t *datafile, uint32 datfile_no)
{
    cm_dump(dump, "\t#%-2u", datfile_no);
    cm_dump(dump, "\t%u", datafile->id);
    cm_dump(dump, "\t%u", (uint32)datafile->used);
    cm_dump(dump, "\t%-*s", (int)strlen(datafile->name), NULL_2_STR(datafile->name));
    cm_dump(dump, "\t%lld", datafile->size);
    cm_dump(dump, "\t%u", (uint32)datafile->block_size);
    cm_dump(dump, "\t%u", (uint32)datafile->flag);
    cm_dump(dump, "\t%u", (uint32)datafile->type);
    cm_dump(dump, "\t%lld", datafile->auto_extend_size);
    cm_dump(dump, "\t%lld\n", datafile->auto_extend_maxsize);
    CM_DUMP_WRITE_FILE(dump);

    return CT_SUCCESS;
}

static status_t dump_ctrl_arch_item(cm_dump_t *dump, arch_ctrl_t *arch_ctrl, uint32 arch_no)
{
    cm_dump(dump, "\t#%-2u", arch_no);
    cm_dump(dump, "\t%u", arch_ctrl->recid);
    cm_dump(dump, "\t%u", arch_ctrl->dest_id);
    cm_dump(dump, "\t%u", arch_ctrl->rst_id);
    cm_dump(dump, "\t%u", arch_ctrl->asn);
    cm_dump(dump, "\t%llu", arch_ctrl->stamp);
    cm_dump(dump, "\t%d", arch_ctrl->blocks);
    cm_dump(dump, "\t%d", arch_ctrl->block_size);
    cm_dump(dump, "\t%lld", (int64)arch_ctrl->blocks * arch_ctrl->block_size);
    cm_dump(dump, "\t%lld", arch_get_ctrl_real_size(arch_ctrl));
    cm_dump(dump, "\t%llu", arch_ctrl->first);
    cm_dump(dump, "\t%llu", arch_ctrl->last);
    cm_dump(dump, "\t%-*s\n",
        (int)strlen(arch_ctrl->name), NULL_2_STR(arch_ctrl->name));
    CM_DUMP_WRITE_FILE(dump);

    return CT_SUCCESS;
}

status_t dump_ctrl_internal_page(database_ctrl_t *page, cm_dump_t *dump)
{
    space_ctrl_t *space = NULL;
    datafile_ctrl_t *datafile = NULL;
    arch_ctrl_t *arch_ctrl = NULL;
    database_ctrl_t *ctrl = page;

    cm_dump(dump, "\tspaces information:\n");
    cm_dump(dump, "\tid\tspaceid\tused\tname\tflg\tblock_size\textent_size\tfile_hwm\torg_scn\tfiles\n");
    CM_DUMP_WRITE_FILE(dump);
    for (uint32 i = 0; i < CT_MAX_SPACES; i++) {
        space = (space_ctrl_t *)db_get_ctrl_item(ctrl->pages, i, sizeof(space_ctrl_t), ctrl->space_segment);
        if (space->name != NULL && (*(char *)(space->name)) != '\0') {
            if (dump_ctrl_space_item(dump, space, i) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }
    }
    cm_dump(dump, "\tdatafiles information:\n");
    cm_dump(dump, "\tid\tdfileid\tused\tname\tsize\tblock_size\tflg\ttype\tauto_extend_size\tauto_extend_maxsize\n");
    CM_DUMP_WRITE_FILE(dump);
    for (uint32 i = 0; i < CT_MAX_DATA_FILES; i++) {
        datafile = (datafile_ctrl_t *)db_get_ctrl_item(ctrl->pages, i, sizeof(datafile_ctrl_t), ctrl->datafile_segment);
        if (datafile->name != NULL && (*(char *)(datafile->name)) != '\0') {
            if (dump_ctrl_datafile_item(dump, datafile, i) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }
    }
    cm_dump(dump, "\tarchive log information:\n");
    cm_dump(dump, "\tid\trecid\tdest_id\trst_id\tasn\tstamp"
        "\tblocks\tblock_size\tlogic_size\treal_size\tfirst\tlast\tname\n");
    CM_DUMP_WRITE_FILE(dump);
    for (uint32 i = 0; i < CT_MAX_ARCH_NUM; i++) {
        arch_ctrl = (arch_ctrl_t *)db_get_ctrl_item(ctrl->pages, i, sizeof(arch_ctrl_t), ctrl->arch_segment);
        if (arch_ctrl->name != NULL && (*(char *)(arch_ctrl->name)) != '\0') {
            if (dump_ctrl_arch_item(dump, arch_ctrl, i) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }
    }

    return CT_SUCCESS;
}

static status_t ctrl_time2str(time_t time, char *str, uint16 size)
{
    text_t fmt_text, time_text;
    if (strlen("YYYY-MM-DD HH24:MI:SS") >= size) {
        CT_THROW_ERROR(ERR_BUFFER_UNDERFLOW, size, strlen("YYYY-MM-DD HH24:MI:SS"));
        return CT_ERROR;
    }

    cm_str2text("YYYY-MM-DD HH24:MI:SS", &fmt_text);
    time_text.str = str;
    time_text.len = 0;

    return cm_time2text(time, &fmt_text, &time_text, size);
}

static status_t dump_db_core(database_ctrl_t *ctrl, cm_dump_t *dump, char *str, uint32 strlen)
{
    cm_dump(dump, "core information:\n");
    cm_dump(dump, "\tversion:                %u-%u-%u-%u\n",
        ctrl->core.version.main, ctrl->core.version.major,
        ctrl->core.version.revision, ctrl->core.version.inner);
    cm_dump(dump, "\tstartup times:        %u\n", ctrl->core.open_count);
    cm_dump(dump, "\tdbid times:           %u\n", ctrl->core.dbid);
    cm_dump(dump, "\tdatabase name:        %s\n", NULL_2_STR(ctrl->core.name));
    if (ctrl_time2str(ctrl->core.init_time, str, strlen) != CT_SUCCESS) {
        cm_dump(dump, "\tinit time:            %s\n", "null");
    } else {
        cm_dump(dump, "\tinit time:            %s\n", NULL_2_STR(str));
    }
    CM_DUMP_WRITE_FILE(dump);
    return CT_SUCCESS;
}

static void dump_systable_core(database_ctrl_t *ctrl, cm_dump_t *dump)
{
    cm_dump(dump, "\ttable$ entry:         %llu\n", *(uint64 *)&ctrl->core.sys_table_entry);
    cm_dump(dump, "\tix_table$1 entry:     %llu\n",
        *(uint64 *)&ctrl->core.ix_sys_table1_entry);
    cm_dump(dump, "\tix_table$2 entry:     %llu\n",
        *(uint64 *)&ctrl->core.ix_sys_table2_entry);
    cm_dump(dump, "\tcolumn$ entry:        %llu\n", *(uint64 *)&ctrl->core.sys_column_entry);
    cm_dump(dump, "\tix_column$ entry:     %llu\n",
        *(uint64 *)&ctrl->core.ix_sys_column_entry);
    cm_dump(dump, "\tindex$ entry:         %llu\n", *(uint64 *)&ctrl->core.sys_index_entry);
    cm_dump(dump, "\tix_index$1 entry:     %llu\n",
        *(uint64 *)&ctrl->core.ix_sys_index1_entry);
    cm_dump(dump, "\tix_index$2 entry:     %llu\n",
        *(uint64 *)&ctrl->core.ix_sys_index2_entry);
    cm_dump(dump, "\tuser$_entry:          %llu\n", *(uint64 *)&ctrl->core.sys_user_entry);
    cm_dump(dump, "\tix_user$1 entry:      %llu\n",
        *(uint64 *)&ctrl->core.ix_sys_user1_entry);
    cm_dump(dump, "\tix_user$2 entry:      %llu\n",
        *(uint64 *)&ctrl->core.ix_sys_user2_entry);
}

static status_t dump_log_core(database_ctrl_t *ctrl, cm_dump_t *dump)
{
    //    cm_dump(dump, "\trcy point:            %u-%u-%u-%llu\n",
    //        (uint32)ctrl->core.rcy_point.rst_id, ctrl->core.rcy_point.asn, ctrl->core.rcy_point.block_id,
    //        (uint64)ctrl->core.rcy_point.lfn);
    //    cm_dump(dump, "\tlrp point:            %u-%u-%u-%llu\n",
    //        (uint32)ctrl->core.lrp_point.rst_id, ctrl->core.lrp_point.asn, ctrl->core.lrp_point.block_id,
    //        (uint64)ctrl->core.lrp_point.lfn);
    cm_dump(dump, "\traft flush point:     scn(%llu)-lfn(%llu)-raft_index(%llu)\n",
        ctrl->core.raft_flush_point.scn, ctrl->core.raft_flush_point.lfn,
        ctrl->core.raft_flush_point.raft_index);
    //    cm_dump(dump, "\tckpt_id:              %llu\n", ctrl->core.ckpt_id);
    //  cm_dump(dump, "\tdw_start:             %u\n", ctrl->core.dw_start);
    //  cm_dump(dump, "\tdw_end:               %u\n", ctrl->core.dw_end);
    //    cm_dump(dump, "\tlsn:                  %llu\n", ctrl->core.lsn);
    //    cm_dump(dump, "\tlfn:                  %llu\n", ctrl->core.lfn);
    cm_dump(dump, "\tbuild completed:      %u\n", (uint32)ctrl->core.build_completed);
    //    cm_dump(dump, "\tlog count:            %u\n", ctrl->core.log_count);
    //    cm_dump(dump, "\tlog hwm:              %u\n", ctrl->core.log_hwm);
    //    cm_dump(dump, "\tlog first:            %u\n", ctrl->core.log_first);
    //    cm_dump(dump, "\tlog last:             %u\n", ctrl->core.log_last);
    CM_DUMP_WRITE_FILE(dump);
    cm_dump(dump, "\tarchive mode:         %u\n", (uint32)ctrl->core.log_mode);
    cm_dump(dump, "\tarchive logs:         %llu", ctrl->core.archived_log[0].arch_log);
    CM_DUMP_WRITE_FILE(dump);
    
    for (uint32 i = 1; i < CT_MAX_ARCH_DEST; i++) {
        cm_dump(dump, "-%llu", ctrl->core.archived_log[i].arch_log);
        CM_DUMP_WRITE_FILE(dump);
    }

    return CT_SUCCESS;
}

static void dump_logfile_item(cm_dump_t *dump, log_file_ctrl_t *logfile, uint32 logfile_no)
{
    cm_dump(dump, "\t#%-2u", logfile_no);
    cm_dump(dump, "\t%-*s", (int)strlen(logfile->name), NULL_2_STR(logfile->name));
    cm_dump(dump, "\t%lld", logfile->size);
    cm_dump(dump, "\t%lld", logfile->hwm);
    cm_dump(dump, "\t%u", logfile->seq);
    cm_dump(dump, "\t%u", logfile->block_size);
    cm_dump(dump, "\t%u", (uint32)logfile->flg);
    cm_dump(dump, "\t%u", (uint32)logfile->type);
    cm_dump(dump, "\t%u", (uint32)logfile->status);
    cm_dump(dump, "\t%u", (uint32)logfile->forward);
    cm_dump(dump, "\t%u\n", (uint32)logfile->backward);
}

static status_t dump_rebuild_ctrl_datafile_list(database_ctrl_t *ctrl, cm_dump_t *dump)
{
    datafile_ctrl_t *datafile = NULL;
    
    for (uint32 i = 0; i < ctrl->core.device_count; i++) {
        datafile = (datafile_ctrl_t *)db_get_ctrl_item(ctrl->pages, i, sizeof(datafile_ctrl_t), ctrl->datafile_segment);
        if (datafile->used && (datafile->flag & DATAFILE_FLAG_ONLINE) && !(datafile->flag & DATAFILE_FLAG_ALARMED)) {
            if (i == ctrl->core.device_count - 1) {
                cm_dump(dump, "'%s'\n", datafile->name);
            } else {
                cm_dump(dump, "'%s',\n", datafile->name);
            }
            CM_DUMP_WRITE_FILE(dump);
        }
    }

    return CT_SUCCESS;
}

static status_t dump_rebuild_ctrl_logfile_list(database_ctrl_t *ctrl, cm_dump_t *dump)
{
    knl_panic(0);  // todo: design to print new log ctrl
    /*
        log_file_ctrl_t *logfile = NULL;

        for (uint32 i = 0; i < ctrl->core.log_count; i++) {
            logfile = (log_file_ctrl_t *)db_get_ctrl_item(ctrl->pages, i, sizeof(log_file_ctrl_t), ctrl->log_segment);
            if (!LOG_IS_DROPPED(logfile->flg) && !LOG_IS_ALARMED(logfile->flg)) {
                if (i == ctrl->core.log_count - 1) {
                    cm_dump(dump, "'%s'\n", logfile->name);
                } else {
                    cm_dump(dump, "'%s',\n", logfile->name);
                }
                CM_DUMP_WRITE_FILE(dump);
            }
        }
    */

    return CT_SUCCESS;
}


status_t dump_rebuild_ctrl_statement(database_ctrl_t *ctrl, cm_dump_t *dump)
{
    cm_dump(dump, "\n");
    cm_dump(dump, "create ctrlfile datafile(\n");
    CM_DUMP_WRITE_FILE(dump);
    (void)dump_rebuild_ctrl_datafile_list(ctrl, dump);
    cm_dump(dump, ") logfile(\n");
    (void)dump_rebuild_ctrl_logfile_list(ctrl, dump);
    cm_dump(dump, ") charset set ");
    if (ctrl->core.charset_id == CHARSET_GBK) {
        cm_dump(dump, "GBK ");
    } else {
        cm_dump(dump, "UTF8 ");
    }

    if (ctrl->core.log_mode == ARCHIVE_LOG_ON) {
        cm_dump(dump, "archivelog;\n");
    } else {
        cm_dump(dump, "noarchivelog;\n");
    }

    cm_dump(dump, "\n");
    cm_dump(dump, "Tips: You can change the character set and log mode in the SQL statement above based on your needs.");
    cm_dump(dump, "\n");
    
    CM_DUMP_WRITE_FILE(dump);
    return CT_SUCCESS;
}

status_t dump_ctrl_page(database_ctrl_t *page, cm_dump_t *dump)
{
    log_file_ctrl_t *logfile = NULL;
    char *str = NULL;
    uint32 i;
    database_ctrl_t *ctrl = page;
    
    str = (char *)malloc(CT_MAX_TIME_STRLEN);
    if (str == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)CT_MAX_TIME_STRLEN, "core init time");
        return CT_ERROR;
    }
    str[0] = '\0';

    if (dump_db_core(ctrl, dump, str, CT_MAX_TIME_STRLEN) != CT_SUCCESS) {
        free(str);
        return CT_ERROR;
    }

    free(str);
    dump_systable_core(ctrl, dump);
    if (dump_log_core(ctrl, dump) != CT_SUCCESS) {
        return CT_ERROR;
    }

    cm_dump(dump, "\n");
    cm_dump(dump, "\tdb_role:              %u\n", (uint32)ctrl->core.db_role);
    cm_dump(dump, "\tprotect mode:         %u\n", (uint32)ctrl->core.protect_mode);
    cm_dump(dump, "\tspace count:          %u\n", ctrl->core.space_count);
    cm_dump(dump, "\tdevice count:         %u\n", ctrl->core.device_count);
    cm_dump(dump, "\tpage size:            %u\n", ctrl->core.page_size);
    cm_dump(dump, "\tundo segments:        %u\n", ctrl->core.undo_segments);
    cm_dump(dump, "\tundo segments extend: %u\n", ctrl->core.undo_segments_extended);
    cm_dump(dump, "\treset logs:           %u-%u-%llu\n",
        ctrl->core.resetlogs.rst_id, ctrl->core.resetlogs.last_asn, ctrl->core.resetlogs.last_lfn);
    cm_dump(dump, "\tlogic replication mode:  %u\n", (uint32)ctrl->core.lrep_mode);
    //    cm_dump(dump, "\tshutdown consistency:    %u\n", ctrl->core.shutdown_consistency);
    cm_dump(dump, "\topen inconsistency:      %u\n", ctrl->core.open_inconsistency);
    //    cm_dump(dump, "\tconsistent lfn:          %llu\n", (uint64)ctrl->core.consistent_lfn);
    cm_dump(dump, "storage information:\n");
    cm_dump(dump, "\tlogfiles information:\n");
    cm_dump(dump, "\tid\tname\tsize\thwm\tseq\tblock_size\tflg\ttype\tstatus\tforward\tbackward\n");
    CM_DUMP_WRITE_FILE(dump);
    for (i = 0; i < CT_MAX_LOG_FILES; i++) {
        logfile = (log_file_ctrl_t *)db_get_ctrl_item(ctrl->pages, i, sizeof(log_file_ctrl_t), ctrl->log_segment);
        if (logfile->name != NULL && (*(char *)(logfile->name)) != '\0') {
            dump_logfile_item(dump, logfile, i);
            CM_DUMP_WRITE_FILE(dump);
        }
    }

    return dump_ctrl_internal_page(page, dump);
}

status_t knl_create_database(knl_handle_t session, knl_database_def_t *def, bool32 clustered)
{
    return dbc_create_database(session, def, clustered);
}

void db_save_corrupt_info(knl_session_t *session, page_id_t page_id, knl_corrupt_info_t *info)
{
    errno_t ret;

    info->page_id = page_id;
    datafile_t *df = DATAFILE_GET(session, page_id.file);
    ret = strncpy_s(info->datafile_name, CT_FILE_NAME_BUFFER_SIZE, df->ctrl->name, CT_FILE_NAME_BUFFER_SIZE - 1);
    knl_securec_check(ret);
    space_t *space = SPACE_GET(session, df->space_id);
    ret = strncpy_s(info->space_name, CT_NAME_BUFFER_SIZE, space->ctrl->name, CT_NAME_BUFFER_SIZE - 1);
    knl_securec_check(ret);
}

void db_set_ctrl_restored(knl_session_t *session, bool32 is_restored)
{
    session->kernel->db.ctrl.core.is_restored = is_restored;
    if (db_save_core_ctrl(session) != CT_SUCCESS) {
        CM_ABORT(0, "ABORT INFO: failed to save core ctrlfile");
    }
}

void db_get_cantiand_version(ctrl_version_t *cantiand_version)
{
    text_t db_version, left, right, right2, version_main, version_major, version_revision;
    uint32 main_n, major_n, revision_n;
    char *version = (char *)cantiand_get_dbversion();
    cm_str2text(version, &db_version);
    // for release package the dbversion is like "Cantian Release 2.0.0"
    // for debug package the dbversion is like "Cantian Debug 2.0.0 c11fdca072"
    (void)cm_split_text(&db_version, ' ', 0, &left, &right);
    (void)cm_split_text(&right, ' ', 0, &left, &right2);
    (void)cm_split_text(&right2, ' ', 0, &left, &right);
    (void)cm_split_text(&left, '.', 0, &version_main, &right);
    (void)cm_split_text(&right, '.', 0, &version_major, &version_revision);
    (void)cm_text2int(&version_main, (int32 *)&main_n);
    (void)cm_text2int(&version_major, (int32 *)&major_n);
    (void)cm_text2int(&version_revision, (int32 *)&revision_n);
    cantiand_version->main = (uint16)main_n;
    cantiand_version->major = (uint16)major_n;
    cantiand_version->revision = (uint16)revision_n;
}

static status_t db_slave_update_ctrl_file(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;

    kernel->db.is_readonly = CT_FALSE;
    kernel->db.readonly_reason = PRIMARY_SET;
    kernel->db.ctrl.core.db_role = REPL_ROLE_PRIMARY;

    if (db_save_core_ctrl(session) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[INST] [SWITCHOVER] ABORT INFO: save core control file failed when switch role");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t db_promote_undo_rollback(knl_session_t *session)
{
    instance_list_t rollback_list = {0};
    rc_init_inst_list(&rollback_list);

    uint64 inst_count = session->kernel->db.ctrl.core.node_count;
    for (uint8 i = 0; i < inst_count; i++) {
        add_id_to_list(i, &rollback_list);
    }
    
    if (rc_tx_area_load(&rollback_list) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[INST] [SWITCHOVER] failed to do tx area load");
        return CT_ERROR;
    }

    while (DB_IN_BG_ROLLBACK(session)) {
        cm_sleep(DTC_REFORM_WAIT_TIME);
    }
    CT_LOG_RUN_INF("[INST] [SWITCHOVER]finish undo_rollback");

    if (rc_rollback_close(&rollback_list) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RC][partial restart] failed to rc_rollback_close");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static void db_promote_update_deposit_map(knl_session_t *session)
{
    uint64 inst_count = session->kernel->db.ctrl.core.node_count;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    for (uint32 inst_id = 0; inst_id < inst_count; inst_id++) {
        cm_spin_lock(&ctx->drc_deposit_map[inst_id].lock, NULL);
        ctx->drc_deposit_map[inst_id].deposit_id = inst_id;
        cm_spin_unlock(&ctx->drc_deposit_map[inst_id].lock);
    }
}

void db_process_broadcast_cluster_role(void *sess, mes_message_t *msg)
{
    knl_session_t *session = (knl_session_t *)sess;
    knl_instance_t *kernel = session->kernel;
    lrpl_context_t *lrpl = &session->kernel->lrpl_ctx;

    if (sizeof(msg_cluster_role_request) != msg->head->size) {
        CT_LOG_RUN_ERR("[INST] [SWITCHOVER] msg is invalid, msg size %u.", msg->head->size);
        mes_release_message_buf(msg->buffer);
        return;
    }
    msg_cluster_role_request *req = (msg_cluster_role_request*)msg->buffer;
    mes_message_head_t head = {0};
    DbsDisasterRecoveryRole last_role = req->role_info.lastRole;
    DbsDisasterRecoveryRole cur_role =  req->role_info.curRole;

    if (last_role == DBS_DISASTER_RECOVERY_SLAVE && cur_role == DBS_DISASTER_RECOVERY_MASTER) {
        if (kernel->db.ctrl.core.db_role == REPL_ROLE_PRIMARY) {
            CT_LOG_RUN_ERR("[INST] [SWITCHOVER] db_role is invalid:%u.", kernel->db.ctrl.core.db_role);
            mes_release_message_buf(msg->buffer);
            return;
        }

        // update undo set
        if (dtc_slave_load_my_undo() != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[INST] [SWITCHOVER] failed to update undo");
            mes_release_message_buf(msg->buffer);
            return;
        }
        db_promote_update_deposit_map(session);
        CT_LOG_RUN_INF("[INST] [SWITCHOVER] update undo is done");

        if (dtc_read_node_ctrl(session, session->kernel->id) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[INST] [SWITCHOVER] failed to read ctrl page for node=%u", session->kernel->id);
            mes_release_message_buf(msg->buffer);
            return;
        }

        // set disaster cluster role, readonly -> readwrite
        kernel->db.is_readonly = CT_FALSE;
        kernel->db.readonly_reason = PRIMARY_SET;
        kernel->db.ctrl.core.db_role = REPL_ROLE_PRIMARY;

        log_context_t *redo_ctx = &session->kernel->redo_ctx;
        dtc_node_ctrl_t *ctrl = dtc_get_ctrl(session, session->kernel->id);
        DB_SET_LFN(&redo_ctx->lfn, ctrl->rcy_point.lfn);
        redo_ctx->buf_lfn[0] = redo_ctx->lfn + 1;
        redo_ctx->buf_lfn[1] = redo_ctx->lfn + 2;

        // cloese lrpl
        lrpl_close(session);

        CT_LOG_RUN_INF("[INST] [SWITCHOVER] promote completed, running as primary");

        mes_init_ack_head(msg->head, &head, MES_CMD_BROADCAST_ACK, sizeof(mes_message_head_t), CT_INVALID_ID16);
        mes_release_message_buf(msg->buffer);
        if (mes_send_data(&head) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[INST] [SWITCHOVER] mes send ack failed.");
            return;
        }
        lrpl->is_promoting = CT_FALSE;
    }
}

static void db_wait_lrpl_done(knl_session_t *session)
{
    lrpl_context_t *lrpl = &session->kernel->lrpl_ctx;
    if (lrpl->is_closing) {
        CM_ABORT_REASONABLE(0, "[INST] [SWITCHOVER] lrpl is closing");
    } else {
        lrpl_close(session);
        lrpl->is_closing = CT_TRUE;
        while (lrpl->is_done != CT_TRUE) {
            cm_sleep(STANDBY_WAIT_SLEEP_TIME);
        }
        CT_LOG_RUN_INF("[INST] [SWITCHOVER] lrpl is done");
    }
}

void db_promote_cluster_role(thread_t* thread)
{
    knl_instance_t *kernel = &g_instance->kernel;
    knl_session_t *session = kernel->sessions[SESSION_ID_KERNEL];
    lrpl_context_t *lrpl = &session->kernel->lrpl_ctx;
    DbsRoleInfo role_info;
    role_info.lastRole = DBS_DISASTER_RECOVERY_SLAVE;
    role_info.curRole = DBS_DISASTER_RECOVERY_MASTER;

    while (!DB_IS_OPEN(session)) {
        cm_sleep(RC_WAIT_DB_OPEN_TIME);
    }
    if (!rc_is_master()) {
        lrpl->is_promoting = CT_TRUE;
        CT_LOG_RUN_INF("[INST] [SWITCHOVER] follower inst start promote");
        return;
    }
    
    lrpl->is_promoting = CT_TRUE;
    CT_LOG_RUN_INF("[INST] [SWITCHOVER] reformer inst start promote");

    if (kernel->db.ctrl.core.db_role == REPL_ROLE_PRIMARY) {
        CM_ABORT_REASONABLE(0, "[INST] [SWITCHOVER] db_role is invalid: %u.", kernel->db.ctrl.core.db_role);
    }

    // step1 wait redo replay
    db_wait_lrpl_done(session);

    // step2 undo rollback
    if (db_promote_undo_rollback(session) != CT_SUCCESS) {
        CM_ABORT_REASONABLE(0, "[INST] [SWITCHOVER] failed to do undo rollback");
    }
    CT_LOG_RUN_INF("[INST] [SWITCHOVER] undo rollback is done");

    // step3 set disaster cluster role, readonly -> readwrite
    if (db_slave_update_ctrl_file(session) != CT_SUCCESS) {
        CM_ABORT_REASONABLE(0, "[INST] [SWITCHOVER] update control file failed when switch role");
    }

    // step4 broadcast to other nodes
    msg_cluster_role_request req;
    req.role_info = role_info;
    mes_init_send_head(&req.head, MES_CMD_BROADCAST_CLUSTER_ROLE, sizeof(msg_cluster_role_request), CT_INVALID_ID32,
        session->kernel->id, 0, session->id, CT_INVALID_ID16);
    status_t ret = mes_broadcast_and_wait(session->id, MES_BROADCAST_ALL_INST, (void *)&req, BROADCAST_PROMOTE_WAIT_INTERVEL, NULL);
    if (ret == CT_ERROR) {
        CM_ABORT_REASONABLE(0, "[INST] [SWITCHOVER] broadcast cluster role failed, switch primary failed.");
    }
    CT_LOG_RUN_INF("[INST] [SWITCHOVER] MES_CMD_BROADCAST_CLUSTER_ROLE succ");

    // step5 cloese lrpl
    db_promote_update_deposit_map(session);
    lrpl->is_promoting = CT_FALSE;
    CT_LOG_RUN_INF("[INST] [SWITCHOVER] promote completed, running as primary");
}

status_t db_switch_role(DbsRoleInfo role_info)
{
    knl_instance_t *kernel = &g_instance->kernel;
    knl_session_t *session = kernel->sessions[SESSION_ID_KERNEL];
    DbsDisasterRecoveryRole last_role = role_info.lastRole;
    DbsDisasterRecoveryRole cur_role =  role_info.curRole;
    lrpl_context_t *lrpl = &session->kernel->lrpl_ctx;
    database_t *db = &g_instance->kernel.db;

    if (last_role == DBS_DISASTER_RECOVERY_SLAVE && cur_role == DBS_DISASTER_RECOVERY_MASTER) {
        status_t status = cm_create_thread(db_promote_cluster_role, 0, NULL, &lrpl->promote_thread);
        if (status != CT_SUCCESS) {
            CM_ABORT_REASONABLE(0, "[INST] [SWITCHOVER] promote cm_create_thread failed");
            return CT_ERROR;
        }
    } else if (last_role == DBS_DISASTER_RECOVERY_MASTER && cur_role == DBS_DISASTER_RECOVERY_SLAVE) {
        // 主降备退出
        if (kernel->db.ctrl.core.db_role == REPL_ROLE_PHYSICAL_STANDBY) {
            CT_LOG_RUN_ERR("[INST] [SWITCHOVER] db_role is invalid:%u.", kernel->db.ctrl.core.db_role);
            return CT_ERROR;
        }
        kernel->db.ctrl.core.db_role = REPL_ROLE_PHYSICAL_STANDBY;

        if (db_save_core_ctrl(session) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[INST] [SWITCHOVER] ABORT INFO: save core control file failed when switch role");
            return CT_ERROR;
        }
        CM_ABORT_REASONABLE(0, "[INST] [SWITCHOVER] demote completed");
    } else if (last_role == DBS_DISASTER_RECOVERY_INVAILD && cur_role == DBS_DISASTER_RECOVERY_SLAVE) {
        db->ctrl.core.db_role = REPL_ROLE_PHYSICAL_STANDBY;
    } else if (last_role == DBS_DISASTER_RECOVERY_INVAILD && cur_role == DBS_DISASTER_RECOVERY_MASTER) {
        db->ctrl.core.db_role = REPL_ROLE_PRIMARY;
    } else {
        CT_LOG_RUN_ERR("The disaster cluster role is invalid.");
        return CT_ERROR;
    }
    g_get_role_from_dbs = CT_TRUE;
    return CT_SUCCESS;
}

int32_t set_disaster_cluster_role(DbsRoleInfo info)
{
    CT_LOG_RUN_INF("Trying to start set_disaster_cluster_role, the input lastStatus is %d, curStatus is %d.",
        info.lastRole, info.curRole);
    status_t ret = db_switch_role(info);
    if (ret == CT_ERROR) {
        CM_ABORT_REASONABLE(0, "switch role failed");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

#ifdef __cplusplus
}
#endif
