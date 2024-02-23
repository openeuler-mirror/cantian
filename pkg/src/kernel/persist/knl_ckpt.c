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
 * knl_ckpt.c
 *
 *
 * IDENTIFICATION
 * src/kernel/persist/knl_ckpt.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_persist_module.h"
#include "knl_ckpt.h"
#include "cm_log.h"
#include "cm_file.h"
#include "knl_buflatch.h"
#include "knl_ctrl_restore.h"
#include "zstd.h"
#include "knl_space_ddl.h"
#include "dtc_database.h"
#include "dtc_dls.h"
#include "dtc_dcs.h"
#include "dtc_ckpt.h"

#define NEED_SYNC_LOG_INFO(ctx) ((ctx)->timed_task != CKPT_MODE_IDLE || (ctx)->trigger_task == CKPT_TRIGGER_FULL)

#define CKPT_WAIT_ENABLE_MS 2
#define CKPT_FLUSH_WAIT_MS 10

static uint8 g_page_clean_finish_flag[PAGE_CLEAN_MAX_BYTES] = {0};
bool32 g_crc_verify = 0;

void ckpt_proc(thread_t *thread);
void dbwr_proc(thread_t *thread);
static status_t ckpt_perform(knl_session_t *session);
static void ckpt_page_clean(knl_session_t *session);

static inline void init_ckpt_part_group(knl_session_t *session)
{
    if (cm_dbs_is_enable_dbs() == CT_FALSE || cm_dbs_is_enable_batch_flush() == CT_FALSE) {
        return;
    }
    knl_instance_t *kernel = session->kernel;
    ckpt_context_t *ctx = &kernel->ckpt_ctx;
    for (uint32 i = 0; i < cm_dbs_get_part_num(); i++) {
        ctx->ckpt_part_group[i].count = 0;
    }
}

static inline void ckpt_param_init(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    ckpt_context_t *ctx = &kernel->ckpt_ctx;

    ctx->dbwr_count = kernel->attr.dbwr_processes;
    ctx->double_write = kernel->attr.enable_double_write;
}

status_t dbwr_aio_init(knl_session_t *session, dbwr_context_t *dbwr)
{
    knl_instance_t *kernel = session->kernel;
    errno_t ret;

    if (!session->kernel->attr.enable_asynch) {
        return CT_SUCCESS;
    }

    ret = memset_sp(&dbwr->async_ctx.aio_ctx, sizeof(cm_io_context_t), 0, sizeof(cm_io_context_t));
    knl_securec_check(ret);

    if (cm_aio_setup(&kernel->aio_lib, CT_CKPT_GROUP_SIZE(session), &dbwr->async_ctx.aio_ctx) != CT_SUCCESS) {
        CT_LOG_RUN_WAR("[CKPT]: setup asynchronous I/O context failed, errno %d", errno);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t dbwr_init(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    ckpt_context_t *ctx = &kernel->ckpt_ctx;
    dbwr_context_t *dbwr = NULL;
    errno_t ret;

    for (uint32 i = 0; i < ctx->dbwr_count; i++) {
        dbwr = &ctx->dbwr[i];
        dbwr->dbwr_trigger = CT_FALSE;
        dbwr->session = kernel->sessions[SESSION_ID_DBWR];
        ret = memset_sp(&dbwr->datafiles, CT_MAX_DATA_FILES * sizeof(int32), 0xFF, CT_MAX_DATA_FILES * sizeof(int32));
        knl_securec_check(ret);
#ifdef WIN32
        dbwr->sem = CreateSemaphore(NULL, 0, 1, NULL);
#else
        sem_init(&dbwr->sem, 0, 0);

        if (dbwr_aio_init(session, dbwr) != CT_SUCCESS) {
            return CT_ERROR;
        }
#endif  // WIN32
    }

    return CT_SUCCESS;
}

status_t ckpt_init(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    ckpt_context_t *ctx = &kernel->ckpt_ctx;
    errno_t ret;

    ret = memset_sp(ctx, sizeof(ckpt_context_t), 0, sizeof(ckpt_context_t));
    knl_securec_check(ret);

    ckpt_param_init(session);

    cm_init_cond(&ctx->ckpt_cond);

    ctx->group.buf = kernel->attr.ckpt_buf;
    ctx->ckpt_enabled = CT_TRUE;
    ctx->trigger_task = CKPT_MODE_IDLE;
    ctx->timed_task = CKPT_MODE_IDLE;
    ctx->trigger_finish_num = 0;
    ctx->stat.proc_wait_cnt = 0;
    ctx->full_trigger_active_num = 0;
    ctx->dw_file = -1;
    ctx->batch_end = NULL;
    ctx->clean_end = NULL;
    ctx->ckpt_blocked = CT_FALSE;
    CT_INIT_SPIN_LOCK(ctx->disable_lock);
    ctx->disable_cnt = 0;

    if (dbwr_init(session) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (kernel->attr.enable_asynch) {
        ctx->group.iocbs_buf = (char *)malloc(CT_CKPT_GROUP_SIZE(session) * CM_IOCB_LENTH);
        if (ctx->group.iocbs_buf == NULL) {
            CT_LOG_RUN_ERR("[CKPT] iocb malloc fail");
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

void ckpt_load(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    ckpt_context_t *ctx = &kernel->ckpt_ctx;

    ctx->lrp_point = dtc_my_ctrl(session)->lrp_point;

    ctx->edp_group.count = 0;
    ctx->remote_edp_group.count = 0;
    ctx->remote_edp_clean_group.count = 0;
    ctx->local_edp_clean_group.count = 0;
    ctx->edp_group.lock = 0;
    ctx->remote_edp_group.lock = 0;
    ctx->remote_edp_clean_group.lock = 0;
    ctx->local_edp_clean_group.lock = 0;
}

void ckpt_close(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    ckpt_context_t *ctx = &kernel->ckpt_ctx;

#ifndef WIN32
    ctx->thread.closed = CT_TRUE;
#endif

    cm_close_thread(&ctx->thread);
    for (uint32 i = 0; i < ctx->dbwr_count; i++) {
#ifndef WIN32
        ctx->dbwr[i].thread.closed = CT_TRUE;
        ctx->dbwr[i].dbwr_trigger = CT_TRUE;
        (void)sem_post(&ctx->dbwr[i].sem);
#endif
        cm_close_thread(&ctx->dbwr[i].thread);
    }
    cm_close_file(ctx->dw_file);
    ctx->dw_file = CT_INVALID_HANDLE;
#ifndef WIN32
    if (ctx->group.iocbs_buf != NULL) {
        free(ctx->group.iocbs_buf);
        ctx->group.iocbs_buf = NULL;
    }
#endif
}

static void ckpt_update_log_point(knl_session_t *session)
{
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;
    rcy_context_t *rcy = &session->kernel->rcy_ctx;
    log_point_t last_point = session->kernel->redo_ctx.curr_point;

    /*
     * when recovering file in mount status, ckpt can't update log point because there are only dirty pages
     * of the file to recover in queue.
     */
    if (IS_FILE_RECOVER(session)) {
        return;
    }

    if (ctx->queue.count != 0) {
        dtc_node_ctrl_t *ctrl = dtc_my_ctrl(session);
        cm_spin_lock(&ctx->queue.lock, &session->stat->spin_stat.stat_ckpt_queue);
        ctrl->rcy_point = ctx->queue.first->trunc_point;
        if (DB_IS_CLUSTER(session) && log_cmp_point(&ctx->lrp_point, &ctrl->rcy_point) < 0) {
            ctx->lrp_point = ctrl->rcy_point;
            ctrl->lrp_point = ctrl->rcy_point;
        }
        cm_spin_unlock(&ctx->queue.lock);
        return;
    }

    /*
     * We can not directly set rcy_point to lrp_point when ckpt queue is empty.
     * Because it doesn't mean all dirty pages have been flushed to disk.
     * Only after database has finished recovery job can we set rcy_point to lrp_point,
     * which means database status is ready or recover_for_restore has been set to true.
     */
    if (!DB_NOT_READY(session) || session->kernel->db.recover_for_restore) {
        if (RCY_IGNORE_CORRUPTED_LOG(rcy) && last_point.lfn < ctx->lrp_point.lfn) {
            dtc_my_ctrl(session)->rcy_point = last_point;
            return;
        }

        /*
         * Logical logs do not generate dirty pages, so lfn of lrp_point could be less than trunc_point_snapshot_lfn
         * probablely. In this scenario, we should set rcy_point to lrp_point still.
         */
        if (DB_IS_READONLY(session) && ctx->trunc_point_snapshot.lfn < ctx->lrp_point.lfn) {
            dtc_my_ctrl(session)->rcy_point = ctx->trunc_point_snapshot;
            return;
        }

        if (log_cmp_point(&(dtc_my_ctrl(session)->rcy_point), &(ctx->lrp_point)) <= 0) {
            dtc_my_ctrl(session)->rcy_point = ctx->lrp_point;
            dtc_my_ctrl(session)->consistent_lfn = ctx->lrp_point.lfn;
        }
    }
}

void ckpt_update_log_point_slave_role(knl_session_t *session)
{
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;
    uint32 curr_node_idx = 0;
 
    /*
     * when recovering file in mount status, ckpt can't update log point because there are only dirty pages
     * of the file to recover in queue.
     */
    if (IS_FILE_RECOVER(session)) {
        return;
    }
 
    if (ctx->queue.count != 0) {
        cm_spin_lock(&ctx->queue.lock, &session->stat->spin_stat.stat_ckpt_queue);
        curr_node_idx = ctx->queue.first->curr_node_idx;
        dtc_node_ctrl_t *ctrl = dtc_get_ctrl(session, curr_node_idx);
        ctrl->rcy_point = ctx->queue.first->trunc_point;
        cm_spin_unlock(&ctx->queue.lock);

        if (dtc_save_ctrl(session, curr_node_idx) != CT_SUCCESS) {
            KNL_SESSION_CLEAR_THREADID(session);
            CM_ABORT(0, "ABORT INFO: save core control file failed when ckpt update log point");
        }
    }
}

void ckpt_reset_point(knl_session_t *session, log_point_t *point)
{
    knl_instance_t *kernel = session->kernel;
    ckpt_context_t *ctx = &kernel->ckpt_ctx;

    dtc_my_ctrl(session)->rcy_point = *point;
    ctx->lrp_point = *point;
    dtc_my_ctrl(session)->lrp_point = *point;

    dtc_my_ctrl(session)->consistent_lfn = point->lfn;
}

static status_t ckpt_save_ctrl(knl_session_t *session)
{
    if (session->kernel->attr.clustered) {
        return dtc_save_ctrl(session, session->kernel->id);
    }

    if (db_save_core_ctrl(session) != CT_SUCCESS) {
        KNL_SESSION_CLEAR_THREADID(session);
        CM_ABORT(0, "[CKPT] ABORT INFO: save core control file failed when perform checkpoint");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

void ckpt_block_and_wait_enable(ckpt_context_t *ctx)
{
    while (!ctx->ckpt_enabled) {
        ctx->ckpt_blocked = CT_TRUE;
        cm_sleep(CKPT_WAIT_ENABLE_MS);
    }

    ctx->ckpt_blocked = CT_FALSE;
}
/*
 * trigger full checkpoint to promote rcy point to current point
 */
static void ckpt_full_checkpoint(knl_session_t *session)
{
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;
    ctx->batch_end = NULL;
    CT_LOG_RUN_INF("start trigger full checkpoint, expect process pages %d", ctx->queue.count);
    uint64 curr_flush_count = ctx->stat.flush_pages[ctx->trigger_task];
    uint64 curr_clean_edp_count = ctx->stat.clean_edp_count[ctx->trigger_task];
    uint64 task_begin = KNL_NOW(session);
    for (;;) {
        if (ctx->thread.closed || (!DB_IS_PRIMARY(&session->kernel->db) && rc_is_master() == CT_FALSE)) {
            break;
        }

        buf_ctrl_t *ckpt_first = ctx->queue.first;
        if (ctx->batch_end == NULL) {
            ctx->batch_end = ctx->queue.last;
        }

        if (ckpt_perform(session) != CT_SUCCESS) {
            KNL_SESSION_CLEAR_THREADID(session);
            CM_ABORT(0, "[CKPT] ABORT INFO: redo log task flush redo file failed.");
        }

        ckpt_block_and_wait_enable(ctx);

        if (!DB_IS_PRIMARY(&session->kernel->db)) {
            ckpt_update_log_point_slave_role(session);
        } else {
            ckpt_update_log_point(session);
            // Save log point
            if (ckpt_save_ctrl(session) != CT_SUCCESS) {
                KNL_SESSION_CLEAR_THREADID(session);
                CM_ABORT(0, "[CKPT] ABORT INFO: save core control file failed when perform checkpoint");
            }
        }
        
        log_recycle_file(session, &dtc_my_ctrl(session)->rcy_point);
        CT_LOG_DEBUG_INF("[CKPT] Set rcy point to [%u-%u/%u/%llu] in ctrl for instance %u",
                         dtc_my_ctrl(session)->rcy_point.rst_id, dtc_my_ctrl(session)->rcy_point.asn,
                         dtc_my_ctrl(session)->rcy_point.block_id, (uint64)dtc_my_ctrl(session)->rcy_point.lfn,
                         session->kernel->id);

        /* backup some core ctrl info on datafile head */
        if (ctrl_backup_core_log_info(session) != CT_SUCCESS) {
            KNL_SESSION_CLEAR_THREADID(session);
            CM_ABORT(0, "[CKPT] ABORT INFO: backup core control info failed when perform checkpoint");
        }

        /* maybe someone has been blocked by full ckpt when alloc buffer ctrl */
        if (ckpt_first == ctx->queue.first) {
            ckpt_page_clean(session);
        }

        if (ctx->batch_end != NULL) {
            if (ctx->edp_group.count != 0) {
                uint32 sleep_time = (ctx->edp_group.count / (CT_CKPT_GROUP_SIZE(session) / 2 + 1) + 1) * 3 * CKPT_WAIT_MS;
                cm_sleep(sleep_time);
            }
            continue;
        }

        if (ckpt_save_ctrl(session) != CT_SUCCESS) {
            KNL_SESSION_CLEAR_THREADID(session);
            CM_ABORT(0, "[CKPT] ABORT INFO: save core control file failed when perform checkpoint");
        }

        break;
    }
    uint64 task_end = KNL_NOW(session);
    CT_LOG_RUN_INF("Finish trigger full checkpoint, Flush pages %llu, Clean edp count %llu, cost time(us) %llu",
        ctx->stat.flush_pages[ctx->trigger_task] - curr_flush_count,
        ctx->stat.clean_edp_count[ctx->trigger_task] - curr_clean_edp_count, task_end - task_begin);
}

/*
 * trigger inc checkpoint to flush page on ckpt-q as soon as possible
 */
static void ckpt_inc_checkpoint(knl_session_t *session)
{
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;
    if (!DB_IS_PRIMARY(&session->kernel->db) && rc_is_master() == CT_FALSE) {
        return;
    }
    if (ckpt_perform(session) != CT_SUCCESS) {
        KNL_SESSION_CLEAR_THREADID(session);
        CM_ABORT(0, "[CKPT] ABORT INFO: redo log task flush redo file failed.");
    }

    ckpt_block_and_wait_enable(ctx);

    if (!DB_IS_PRIMARY(&session->kernel->db)) {
        ckpt_update_log_point_slave_role(session);
    } else {
        ckpt_update_log_point(session);
        // save log point first
        if (ckpt_save_ctrl(session) != CT_SUCCESS) {
            KNL_SESSION_CLEAR_THREADID(session);
            CM_ABORT(0, "[CKPT] ABORT INFO: save core control file failed when perform checkpoint");
        }
    }
    
    log_recycle_file(session, &dtc_my_ctrl(session)->rcy_point);
    CT_LOG_DEBUG_INF("[CKPT] Set rcy point to [%u-%u/%u/%llu] in ctrl for instance %u",
                     dtc_my_ctrl(session)->rcy_point.rst_id, dtc_my_ctrl(session)->rcy_point.asn,
                     dtc_my_ctrl(session)->rcy_point.block_id, (uint64)dtc_my_ctrl(session)->rcy_point.lfn,
                     session->kernel->id);

    /* backup some core info on datafile head: only back up core log info for full ckpt and timed task */
    if (NEED_SYNC_LOG_INFO(ctx) && ctrl_backup_core_log_info(session) != CT_SUCCESS) {
        KNL_SESSION_CLEAR_THREADID(session);
        CM_ABORT(0, "[CKPT] ABORT INFO: backup core control info failed when perform checkpoint");
    }

    if (ckpt_save_ctrl(session) != CT_SUCCESS) {
        KNL_SESSION_CLEAR_THREADID(session);
        CM_ABORT(0, "[CKPT] ABORT INFO: save core control file failed when perform checkpoint");
    }
}

void ckpt_pop_page(knl_session_t *session, ckpt_context_t *ctx, buf_ctrl_t *ctrl)
{
    cm_spin_lock(&ctx->queue.lock, &session->stat->spin_stat.stat_ckpt_queue);
    ctx->queue.count--;

    if (ctx->queue.count == 0) {
        ctx->queue.first = NULL;
        ctx->queue.last = NULL;
    } else {
        if (ctrl->ckpt_prev != NULL) {
            ctrl->ckpt_prev->ckpt_next = ctrl->ckpt_next;
        }

        if (ctrl->ckpt_next != NULL) {
            ctrl->ckpt_next->ckpt_prev = ctrl->ckpt_prev;
        }

        if (ctx->queue.last == ctrl) {
            ctx->queue.last = ctrl->ckpt_prev;
        }

        if (ctx->queue.first == ctrl) {
            ctx->queue.first = ctrl->ckpt_next;
        }
    }

    knl_panic_log(ctrl->in_ckpt == CT_TRUE, "ctrl is not in ckpt, panic info: page %u-%u type %u", ctrl->page_id.file,
                  ctrl->page_id.page, ctrl->page->type);
    ctrl->ckpt_prev = NULL;
    ctrl->ckpt_next = NULL;
    ctrl->in_ckpt = CT_FALSE;

    cm_spin_unlock(&ctx->queue.lock);
}

static void ckpt_assign_trigger_task(knl_session_t *session, trigger_task_t *task_desc)
{
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;
    uint64_t snap_num = 0;
    
    /* To ensure the trigger_task action is valid, we use white list for debugging */
    for (;;) {
        cm_spin_lock(&ctx->lock, &session->stat->spin_stat.stat_ckpt);
        if (ctx->trigger_task == CKPT_MODE_IDLE && ctx->ckpt_enabled) {
            /* We don not assign inc trigger if there is full_trigger running or waiting */
            if (task_desc->mode != CKPT_TRIGGER_INC || ctx->full_trigger_active_num == 0) {
                snap_num = ctx->trigger_finish_num;
                ctx->trigger_task = task_desc->mode;
                cm_spin_unlock(&ctx->lock);
                break; // sucess
            }
        }
        cm_spin_unlock(&ctx->lock);

        if (!task_desc->guarantee) {
            return;
        }

        if (task_desc->join && task_desc->mode == ctx->trigger_task) {
             /* task with join should not be set with wait, so directly return. */
            return;
        }
        
        /* We will try again until sucess.
         * Doing the next try when contition satisfied to decrease lock competition.
         */
        while (ctx->trigger_task != CKPT_MODE_IDLE || !ctx->ckpt_enabled) {
            cm_sleep(1);
        }
    }

    cm_release_cond_signal(&ctx->ckpt_cond); /* send a signal whatever */

    /* Wait for task finished.
     * Note that this is only meaningful for inc and full ckpt task,
     * while clean task always comes with no wait.
     */
    while (task_desc->wait && snap_num == ctx->trigger_finish_num) {
        cm_release_cond_signal(&ctx->ckpt_cond);
        cm_sleep(1);
    }
}

static inline status_t ckpt_assign_timed_task(knl_session_t *session, ckpt_context_t *ctx, ckpt_mode_t mode)
{
    knl_panic (mode == CKPT_TIMED_CLEAN || mode == CKPT_TIMED_INC);

    cm_spin_lock(&ctx->lock, &session->stat->spin_stat.stat_ckpt);
    /* Using lock to ensure corretness in case another
     * thread doing somthing with ckpt_enabled flag.
     */
    if (SECUREC_UNLIKELY(!ctx->ckpt_enabled)) {
        cm_spin_unlock(&ctx->lock);
        return CT_ERROR;
    }
    ctx->timed_task = mode;
    cm_spin_unlock(&ctx->lock);
    return CT_SUCCESS;
}

void ckpt_trigger(knl_session_t *session, bool32 wait, ckpt_mode_t mode)
{
    if (!DB_TO_RECOVERY(session)) {
        return;
    }

    /*
     * The task flags are set to achieve the effects of legacy use.
     * With guarantee flag, we will keep trying until successfully assign the task.
     */
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;
    trigger_task_t task;
    task.guarantee = CT_FALSE;
    task.join = CT_TRUE;
    task.wait = wait;

    if (mode == CKPT_TRIGGER_FULL) {
        task.guarantee = CT_TRUE;
        task.join = CT_FALSE;
        (void)cm_atomic_inc(&ctx->full_trigger_active_num);
    }
    
    task.mode = mode;
    ckpt_assign_trigger_task(session, &task);
}

static void ckpt_do_trigger_task(knl_session_t *session, ckpt_context_t *ctx, date_t *clean_time, date_t *ckpt_time)
{
    if (ctx->trigger_task == CKPT_MODE_IDLE) {
        return;
    }

    uint64 task_begin = KNL_NOW(session);
    ctx->stat.ckpt_begin_time[ctx->trigger_task] = (date_t)task_begin;
    knl_panic (CKPT_IS_TRIGGER(ctx->trigger_task));
    
    switch (ctx->trigger_task) {
        case CKPT_TRIGGER_FULL:
            ckpt_full_checkpoint(session);

            (void)cm_atomic_dec(&ctx->full_trigger_active_num);
            *ckpt_time = KNL_NOW(session);
            break;
        case CKPT_TRIGGER_INC:
            ckpt_inc_checkpoint(session);
            *ckpt_time = KNL_NOW(session);
            break;
        case CKPT_TRIGGER_CLEAN:
            ckpt_page_clean(session);
            *clean_time = KNL_NOW(session);
            break;
        default:
            /* Not possible, for grammar compliance with switch clause */
            break;
    }

    uint64 task_end = KNL_NOW(session);
    ctx->stat.task_count[ctx->trigger_task]++;
    ctx->stat.task_us[ctx->trigger_task] += task_end - task_begin;

    cm_spin_lock(&ctx->lock, &session->stat->spin_stat.stat_ckpt);
    ctx->trigger_finish_num++;
    ctx->trigger_task = CKPT_MODE_IDLE;
    cm_spin_unlock(&ctx->lock);
}


static void ckpt_do_timed_task(knl_session_t *session, ckpt_context_t *ctx, date_t *clean_time, date_t *ckpt_time)
{
    if (!DB_IS_PRIMARY(&session->kernel->db) && rc_is_master() == CT_FALSE) {
        return;
    }
    knl_attr_t *attr = &session->kernel->attr;

    if (attr->page_clean_period != 0 &&
        KNL_NOW(session) - (*clean_time) >= (date_t)attr->page_clean_period * MILLISECS_PER_SECOND) {
        if (ckpt_assign_timed_task(session, ctx, CKPT_TIMED_CLEAN) == CT_SUCCESS) {
            date_t task_begin = KNL_NOW(session);
            ctx->stat.ckpt_begin_time[CKPT_TIMED_CLEAN] = task_begin;
            ckpt_page_clean(session);
            *clean_time = KNL_NOW(session);
            ctx->timed_task = CKPT_MODE_IDLE;

            date_t task_end = KNL_NOW(session);
            ctx->stat.task_count[CKPT_TIMED_CLEAN]++;
            ctx->stat.task_us[CKPT_TIMED_CLEAN] += task_end - task_begin;
        }
    }

    if (ctx->queue.count + ctx->remote_edp_group.count >= attr->ckpt_interval ||
        ctx->remote_edp_group.count + ctx->local_edp_clean_group.count >= CT_CKPT_EDP_GROUP_SIZE(session) ||
        KNL_NOW(session) - (*ckpt_time) >= (date_t)attr->ckpt_timeout * MICROSECS_PER_SECOND) {
        if (ckpt_assign_timed_task(session, ctx, CKPT_TIMED_INC) == CT_SUCCESS) {
            date_t task_begin = KNL_NOW(session);
            ctx->stat.ckpt_begin_time[CKPT_TIMED_INC] = task_begin;
            ckpt_inc_checkpoint(session);
            *ckpt_time = KNL_NOW(session);
            ctx->timed_task = CKPT_MODE_IDLE;

            date_t task_end = KNL_NOW(session);
            ctx->stat.task_count[CKPT_TIMED_INC]++;
            ctx->stat.task_us[CKPT_TIMED_INC] += task_end - task_begin;
        }
    }
}

/*
 * ckpt thread handles buffer page clean and full/inc ckpt on following condition:
 * 1.trigger of page clean, inc/full ckpt.
 * 2.page clean or inc ckpt timeout.
 * 3.count of dirty pages on ckpt queue is up to threshold.
 */
void ckpt_proc(thread_t *thread)
{
    knl_session_t *session = (knl_session_t *)thread->argument;
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;
    knl_attr_t *attr = &session->kernel->attr;
    date_t ckpt_time = 0;
    date_t clean_time = 0;

    cm_set_thread_name("ckpt");
    CT_LOG_RUN_INF("ckpt thread started");
    KNL_SESSION_SET_CURR_THREADID(session, cm_get_current_thread_id());
    
    while (!thread->closed) {
        /* If the database has come to recovery stage, we will break and go to normal schedul once
         * a trigger task is received.
         */
        if (DB_TO_RECOVERY(session) && ctx->trigger_task != CKPT_MODE_IDLE) {
            break;
        }
        cm_sleep(CKPT_WAIT_MS);
    }

    while (!thread->closed) {
        ckpt_do_trigger_task(session, ctx, &clean_time, &ckpt_time);
        ckpt_do_timed_task(session, ctx, &clean_time, &ckpt_time);

        /* quickly go to the next schdule if there is trigger task */
        if (ctx->trigger_task != CKPT_MODE_IDLE) {
            continue;
        }

        /* Quicly go the next schedul if dirty queue satisfies timed schedule */
        if (ctx->queue.count >= attr->ckpt_interval && ctx->ckpt_enabled) {
            continue;
        }

         /* For performance consideration,  we may don't want the timed task runing too frequently
          * in large-memory environment.
          * So we wait for a short time (default to 100ms with parameter), in which we can still
          * respond trigger task.
          * If one want the time task scheduled timely, he can set the parameter to 0.
          */
        uint32 timed_task_delay_ms = session->kernel->attr.ckpt_timed_task_delay;
        (void)cm_wait_cond(&ctx->ckpt_cond, timed_task_delay_ms);
        if (ctx->trigger_task != CKPT_MODE_IDLE) {
            continue;
        }

        /*
         * Using condition wait may missing the singal, but can avoid stucking with
         * disordered system time and always return on time out.
         * Besides, we can keep on releasing signal after triggering to make sure
         * the signal is not missed.
         */
        (void)cm_wait_cond(&ctx->ckpt_cond, CKPT_WAIT_MS);
        ctx->stat.proc_wait_cnt++;
    }

    CT_LOG_RUN_INF("ckpt thread closed");
    KNL_SESSION_CLEAR_THREADID(session);
}

bool32 ckpt_try_latch_ctrl(knl_session_t *session, buf_ctrl_t *ctrl)
{
    uint32 times = 0;
    uint32 wait_ticks = 0;
    knl_instance_t *kernel = session->kernel;
    ckpt_context_t *ctx = &kernel->ckpt_ctx;
    
    for (;;) {
        if (ctx->ckpt_enabled == CT_FALSE) {
            return CT_FALSE;
        }
        while (ctrl->is_readonly) {
            if (ctx->ckpt_enabled == CT_FALSE) {
                return CT_FALSE;
            }
            if (wait_ticks >= CKPT_LATCH_WAIT) {
                return CT_FALSE;
            }
            times++;
            if (times > CT_SPIN_COUNT) {
                cm_spin_sleep();
                times = 0;
                wait_ticks++;
                continue;
            }
        }

        // in checkpoint, we don't increase the ref_num.
        if (!buf_latch_timed_s(session, ctrl, CKPT_LATCH_TIMEOUT, CT_FALSE, CT_TRUE)) {
            return CT_FALSE;
        }

        if (!ctrl->is_readonly) {
            return CT_TRUE;
        }
        buf_unlatch(session, ctrl, CT_FALSE);
    }
}

status_t ckpt_checksum(knl_session_t *session, ckpt_context_t *ctx)
{
    uint32 cks_level = session->kernel->attr.db_block_checksum;
    page_head_t *page = (page_head_t *)(ctx->group.buf + DEFAULT_PAGE_SIZE(session) * ctx->group.count);

    if (cks_level == (uint32)CKS_FULL) {
        if (PAGE_CHECKSUM(page, DEFAULT_PAGE_SIZE(session)) != CT_INVALID_CHECKSUM
            && !page_verify_checksum(page, DEFAULT_PAGE_SIZE(session))) {
            CT_LOG_RUN_ERR("[CKPT] page corrupted(file %u, page %u).checksum level %s, page size %u, cks %u",
                AS_PAGID_PTR(page->id)->file, AS_PAGID_PTR(page->id)->page, knl_checksum_level(cks_level),
                PAGE_SIZE(*page), PAGE_CHECKSUM(page, DEFAULT_PAGE_SIZE(session)));
            return CT_ERROR;
        }
    } else if (cks_level == (uint32)CKS_OFF) {
        PAGE_CHECKSUM(page, DEFAULT_PAGE_SIZE(session)) = CT_INVALID_CHECKSUM;
    } else if (g_crc_verify == CT_TRUE && cks_level == (uint32)CKS_TYPICAL) {
        datafile_t *df = DATAFILE_GET(session, AS_PAGID(page->id).file);
        space_t *space = SPACE_GET(session, df->space_id);
        if (IS_SYSTEM_SPACE(space) || IS_SYSAUX_SPACE(space)) {
            status_t ret = CT_SUCCESS;
            SYNC_POINT_GLOBAL_START(CANTIAN_CKPT_CHECKSUM_VERIFY_FAIL, &ret, CT_ERROR);
            ret = !page_verify_checksum(page, DEFAULT_PAGE_SIZE(session));
            SYNC_POINT_GLOBAL_END;
            if (ret != CT_SUCCESS) {
                knl_panic_log(0, "sys or sysaux page checksum verify invalid, panic info: page %u-%u type %u",
                              AS_PAGID(page->id).file, AS_PAGID(page->id).page, page->type);
            }
        }
    } else {
        page_calc_checksum(page, DEFAULT_PAGE_SIZE(session));
    }

    return CT_SUCCESS;
}

static uint32 ckpt_get_neighbors(knl_session_t *session, buf_ctrl_t *ctrl, page_id_t *first)
{
    knl_attr_t *attr = &session->kernel->attr;
    datafile_t *df = NULL;
    space_t *space = NULL;
    page_id_t page_id;
    uint32 start_id, load_count;

    *first = ctrl->page_id;

    if (!attr->ckpt_flush_neighbors) {
        return 1;
    }

    if (ctrl->page->type == PAGE_TYPE_UNDO) {
        return session->kernel->attr.undo_prefetch_page_num;
    }

    page_id = ctrl->page_id;
    df = DATAFILE_GET(session, page_id.file);
    space = SPACE_GET(session, df->space_id);
    start_id = spc_first_extent_id(session, space, page_id);
    if (page_id.page >= start_id) {
        first->page = page_id.page - ((page_id.page - start_id) % space->ctrl->extent_size);
        first->aligned = 0;
        load_count = MAX(space->ctrl->extent_size, BUF_MAX_PREFETCH_NUM / 2);
    } else {
        load_count = 1;
    }

    return load_count;
}

static inline bool32 page_encrypt_enable(knl_session_t *session, space_t *space, page_head_t *page)
{
    if (page->type == PAGE_TYPE_UNDO) {
        return undo_valid_encrypt(session, page);
    }

    if (SPACE_IS_ENCRYPT(space) && page_type_suport_encrypt(page->type)) {
        return CT_TRUE;
    }

    return CT_FALSE;
}

status_t ckpt_encrypt(knl_session_t *session, ckpt_context_t *ctx)
{
    page_head_t *page = (page_head_t *)(ctx->group.buf + DEFAULT_PAGE_SIZE(session) * ctx->group.count);
    space_t *space = SPACE_GET(session, DATAFILE_GET(session, AS_PAGID_PTR(page->id)->file)->space_id);
    if (!page_encrypt_enable(session, space, page)) {
        return CT_SUCCESS;
    }

    if (page_encrypt(session, page, space->ctrl->encrypt_version, space->ctrl->cipher_reserve_size) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

#ifdef LOG_DIAG
static status_t ckpt_verify_decrypt(knl_session_t *session, ckpt_context_t *ctx)
{
    page_head_t *page = (page_head_t *)(ctx->group.buf + DEFAULT_PAGE_SIZE(session) * ctx->group.count);
    page_id_t page_id = AS_PAGID(page->id);
    space_t *space = SPACE_GET(session, DATAFILE_GET(session, page_id.file)->space_id);

    char *copy_page = (char *)cm_push(session->stack, DEFAULT_PAGE_SIZE(session));
    errno_t ret = memcpy_sp(copy_page, DEFAULT_PAGE_SIZE(session), page, DEFAULT_PAGE_SIZE(session));
    knl_securec_check(ret);

    if (((page_head_t *)copy_page)->encrypted) {
        if (page_decrypt(session, (page_head_t *)copy_page) != CT_SUCCESS) {
            knl_panic_log(0, "decrypt verify failed![AFTER ENCRYPT]AFTER CKPT CHECKSUM! ,DECRYPT IMMEDEATLY ERROR: "
                "page_info: page %u, file %u, page_type %u, encrypted %u,"
                "space->ctrl->cipher_reserve_size: %u ",
                page_id.page, page_id.file, page->type, page->encrypted, space->ctrl->cipher_reserve_size);
        }
    }
    cm_pop(session->stack);
    return CT_SUCCESS;
}
#endif

void ckpt_unlatch_group(knl_session_t *session, page_id_t first, uint32 start, uint32 end)
{
    page_id_t page_id;
    buf_ctrl_t *to_flush_ctrl = NULL;

    page_id.file = first.file;

    for (uint32 i = start; i < end; i++) {
        page_id.page = first.page + i;
        to_flush_ctrl = buf_find_by_pageid(session, page_id);
        knl_panic_log(to_flush_ctrl != NULL, "ctrl missed in buffer, panic info: group head %u-%u, missed %u-%u",
            first.file, first.page, first.file, first.page + i);
        buf_unlatch(session, to_flush_ctrl, CT_FALSE);
    }
}

page_id_t page_first_group_id(knl_session_t *session, page_id_t page_id)
{
    datafile_t *df = DATAFILE_GET(session, page_id.file);
    space_t *space = SPACE_GET(session, df->space_id);
    page_id_t first;
    uint32 start_id;

    start_id = spc_first_extent_id(session, space, page_id);

    knl_panic_log(page_id.page >= start_id, "page %u-%u before space first extent %u-%u", page_id.file, page_id.page,
        page_id.file, start_id);
    first.page = page_id.page - ((page_id.page - start_id) % PAGE_GROUP_COUNT);
    first.file = page_id.file;
    first.aligned = 0;

    return first;
}

bool32 buf_group_compressible(knl_session_t *session, buf_ctrl_t *ctrl)
{
    buf_ctrl_t *to_compress_ctrl = NULL;
    page_id_t first, page_id;

    first = page_first_group_id(session, ctrl->page_id);
    if (!IS_SAME_PAGID(first, ctrl->page_id)) {
        CT_LOG_RUN_ERR("group incompressible, first: %d-%d != current: %d-%d", first.file, first.page,
            ctrl->page_id.file, ctrl->page_id.page);
        return CT_FALSE;
    }

    page_id.file = first.file;
    for (uint16 i = 0; i < PAGE_GROUP_COUNT; i++) {
        page_id.page = first.page + i;
        to_compress_ctrl = buf_find_by_pageid(session, page_id);
        /* as a page group is alloc and release as a whole, so we consider a page group
         * which members are not all in buffer is incompressible */
        if (to_compress_ctrl == NULL || !page_compress(session, to_compress_ctrl->page_id)) {
            CT_LOG_RUN_ERR("group incompressible, member: %d, current: %d-%d", i,
                ctrl->page_id.file, ctrl->page_id.page);
            return CT_FALSE;
        }
    }

    return CT_TRUE;
}

bool32 ckpt_try_latch_group(knl_session_t *session, buf_ctrl_t *ctrl)
{
    buf_ctrl_t *to_compress_ctrl = NULL;
    page_id_t first, page_id;

    first = page_first_group_id(session, ctrl->page_id);
    page_id.file = first.file;

    for (uint16 i = 0; i < PAGE_GROUP_COUNT; i++) {
        page_id.page = first.page + i;
        to_compress_ctrl = buf_find_by_pageid(session, page_id);
        /* in the following scenario, ctrl may be null
         * 1.for noread, PAGE_GROUP_COUNT's pages are added to segment in log_atomic_op
         * 2.page is reused, PAGE_GROUP_COUNT's pages are formatted in log_atomic_op
         * so we consider group has NULL member as an exception */
        knl_panic_log(to_compress_ctrl != NULL, "ctrl missed in buffer, panic info: group head %u-%u, missed %u-%u",
            first.file, first.page, first.file, first.page + i);
        if (!ckpt_try_latch_ctrl(session, to_compress_ctrl)) {
            ckpt_unlatch_group(session, first, 0, i);
            return CT_FALSE;
        }
    }

    return CT_TRUE;
}
 
static void ckpt_copy_item(knl_session_t *session, buf_ctrl_t *ctrl, buf_ctrl_t *to_flush_ctrl)
{
    gbp_context_t *gbp_ctx = &session->kernel->gbp_context;
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;
    uint32 gbp_lock_id = CT_INVALID_ID32;
    errno_t ret;

    /* concurrent with knl_read_page_from_gbp when buf_enter_page with LATCH_S lock */
    if (SECUREC_UNLIKELY(KNL_RECOVERY_WITH_GBP(session->kernel))) {
        gbp_lock_id = ctrl->page_id.page % CT_GBP_RD_LOCK_COUNT;
        cm_spin_lock(&gbp_ctx->buf_read_lock[gbp_lock_id], NULL);
    }

    knl_panic_log(IS_SAME_PAGID(to_flush_ctrl->page_id, AS_PAGID(to_flush_ctrl->page->id)),
        "to_flush_ctrl's page_id and to_flush_ctrl page's id are not same, panic info: page_id %u-%u type %u, "
        "page id %u-%u type %u", to_flush_ctrl->page_id.file, to_flush_ctrl->page_id.page,
        to_flush_ctrl->page->type, AS_PAGID(to_flush_ctrl->page->id).file,
        AS_PAGID(to_flush_ctrl->page->id).page, to_flush_ctrl->page->type);
    knl_panic_log(CHECK_PAGE_PCN(to_flush_ctrl->page), "page pcn is abnormal, panic info: page %u-%u type %u",
        to_flush_ctrl->page_id.file, to_flush_ctrl->page_id.page, to_flush_ctrl->page->type);

    /* this is not accurate, does not matter */
    if (ctx->trunc_lsn < to_flush_ctrl->page->lsn) {
        ctx->trunc_lsn = to_flush_ctrl->page->lsn;
    }

    if (ctx->consistent_lfn < to_flush_ctrl->lastest_lfn) {
        ctx->consistent_lfn = to_flush_ctrl->lastest_lfn;
    }

    /* DEFAULT_PAGE_SIZE is 8192,  ctx->group.count <= CT_CKPT_GROUP_SIZE(4096), integers cannot cross bounds */
    ret = memcpy_sp(ctx->group.buf + DEFAULT_PAGE_SIZE(session) * ctx->group.count, DEFAULT_PAGE_SIZE(session),
        to_flush_ctrl->page, DEFAULT_PAGE_SIZE(session));
    knl_securec_check(ret);

    if (SECUREC_UNLIKELY(gbp_lock_id != CT_INVALID_ID32)) {
        cm_spin_unlock(&gbp_ctx->buf_read_lock[gbp_lock_id]);
        gbp_lock_id = CT_INVALID_ID32;
    }

    if (to_flush_ctrl == ctx->batch_end) {
        ctx->batch_end = to_flush_ctrl->ckpt_prev;
    }

    if (to_flush_ctrl->in_ckpt) {
        ckpt_pop_page(session, ctx, to_flush_ctrl);
    }

    to_flush_ctrl->is_marked = 1;
    CM_MFENCE;
    to_flush_ctrl->is_dirty = 0;
    to_flush_ctrl->is_remote_dirty = 0;

    ctx->group.items[ctx->group.count].ctrl = to_flush_ctrl;
    ctx->group.items[ctx->group.count].buf_id = ctx->group.count;
    ctx->group.items[ctx->group.count].need_punch = CT_FALSE;

    ckpt_put_to_part_group(session, ctx, to_flush_ctrl);
}

static status_t ckpt_ending_prepare(knl_session_t *session, ckpt_context_t *ctx)
{
    /* must before checksum calc */
    if (ckpt_encrypt(session, ctx) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (ckpt_checksum(session, ctx) != CT_SUCCESS) {
        return CT_ERROR;
    }
#ifdef LOG_DIAG
    if (ckpt_verify_decrypt(session, ctx) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("ERROR: ckpt verify decrypt failed. ");
        return CT_ERROR;
    }
#endif

    return CT_SUCCESS;
}

status_t ckpt_prepare_compress(knl_session_t *session, ckpt_context_t *ctx, buf_ctrl_t *curr_ctrl,
    buf_ctrl_t *ctrl_next, bool8 *ctrl_next_is_flushed, bool8 *need_exit)
{
    page_id_t first_page_id, to_flush_pageid;
    buf_ctrl_t *to_flush_ctrl = NULL;

    ctx->has_compressed = CT_TRUE;

    if (ctx->group.count + PAGE_GROUP_COUNT > CT_CKPT_GROUP_SIZE(session)) {
        *need_exit = CT_TRUE;
        return CT_SUCCESS;
    }

    if (!ckpt_try_latch_group(session, curr_ctrl)) {
        return CT_SUCCESS;
    }

    first_page_id = page_first_group_id(session, curr_ctrl->page_id);
    to_flush_pageid = first_page_id;
    for (uint16 i = 0; i < PAGE_GROUP_COUNT; i++) {
        to_flush_pageid.page = first_page_id.page + i;

        /* get ctrl */
        if (IS_SAME_PAGID(to_flush_pageid, curr_ctrl->page_id)) {
            to_flush_ctrl = curr_ctrl;
        } else {
            to_flush_ctrl = buf_find_by_pageid(session, to_flush_pageid);
        }

        /* not a flushable page */
        if (to_flush_ctrl == NULL) {
            continue;
        }

        /* we should retain items for clean pages in page group, as a result, it may lead to lower io capacity */
        if (to_flush_ctrl->is_marked) {
            /* this ctrl has been added to ckpt group, so skip it */
            if (to_flush_ctrl->in_ckpt == CT_FALSE) {
                buf_unlatch(session, to_flush_ctrl, CT_FALSE);
                continue;
            }
            ckpt_unlatch_group(session, first_page_id, i, PAGE_GROUP_COUNT);
            *need_exit = CT_TRUE;
            return CT_SUCCESS;
        }

        ckpt_copy_item(session, curr_ctrl, to_flush_ctrl);

        if (to_flush_ctrl == ctrl_next) {
            *ctrl_next_is_flushed = CT_TRUE;
        }

        buf_unlatch(session, to_flush_ctrl, CT_FALSE);

        if (ckpt_ending_prepare(session, ctx) != CT_SUCCESS) {
            ckpt_unlatch_group(session, first_page_id, i + 1, PAGE_GROUP_COUNT);
            return CT_ERROR;
        }

        ctx->group.count++;

        if (ctx->group.count >= CT_CKPT_GROUP_SIZE(session)) {
            *need_exit = CT_TRUE;
            return CT_SUCCESS;
        }
    }

    return CT_SUCCESS;
}

static status_t ckpt_prepare_normal(knl_session_t *session, ckpt_context_t *ctx, buf_ctrl_t *curr_ctrl,
    buf_ctrl_t *ctrl_next, bool8 *ctrl_next_is_flushed, bool8 *need_exit)
{
    page_id_t first_page_id, to_flush_pageid;
    buf_ctrl_t *to_flush_ctrl = NULL;
    uint32 count;

    ctx->stat.ckpt_total_neighbors_times++;
    ctx->stat.ckpt_curr_neighbors_times++;

    count = ckpt_get_neighbors(session, curr_ctrl, &first_page_id);
    to_flush_pageid = first_page_id;
    for (uint32 i = 0; i < count; i++) {
        to_flush_pageid.page = first_page_id.page + i;

        /* get ctrl */
        if (IS_SAME_PAGID(to_flush_pageid, curr_ctrl->page_id)) {
            to_flush_ctrl = curr_ctrl;
        } else {
            to_flush_ctrl = buf_find_by_pageid(session, to_flush_pageid);
        }

        /* not a flushable page */
        if (to_flush_ctrl == NULL || to_flush_ctrl->in_ckpt == CT_FALSE) {
            continue;
        }

        /* skip compress page when flush non-compress page's neighbors */
        if (page_compress(session, to_flush_ctrl->page_id)) {
            continue;
        }

        if (!ckpt_try_latch_ctrl(session, to_flush_ctrl)) {
            continue;
        }

        if (DB_IS_CLUSTER(session)) {
            if (to_flush_ctrl->is_edp) {
                CT_LOG_DEBUG_INF("[CKPT]checkpoint find edp [%u-%u], count(%d)", to_flush_ctrl->page_id.file,
                                 to_flush_ctrl->page_id.page, ctx->edp_group.count);
                knl_panic(DCS_BUF_CTRL_NOT_OWNER(session, to_flush_ctrl));
                buf_unlatch(session, to_flush_ctrl, CT_FALSE);
                if (!dtc_add_to_edp_group(session, &ctx->edp_group, CT_CKPT_GROUP_SIZE(session), to_flush_ctrl->page_id,
                                          to_flush_ctrl->page->lsn)) {
                    *need_exit = CT_TRUE;
                    break;
                }
                continue;
            }

            if (to_flush_ctrl->in_ckpt == CT_FALSE) {
                buf_unlatch(session, to_flush_ctrl, CT_FALSE);
                continue;
            }

            knl_panic(DCS_BUF_CTRL_IS_OWNER(session, to_flush_ctrl));
            if (to_flush_ctrl->is_remote_dirty &&
                !dtc_add_to_edp_group(session, &ctx->remote_edp_clean_group, CT_CKPT_GROUP_SIZE(session), to_flush_ctrl->page_id,
                                      to_flush_ctrl->page->lsn)) {
                buf_unlatch(session, to_flush_ctrl, CT_FALSE);
                *need_exit = CT_TRUE;
                break;
            }
        }

        /*
        * added to ckpt->queue again during we flush it,
        * end this prepare, we can not handle two copies of same page
        */
        if (to_flush_ctrl->is_marked) {
            buf_unlatch(session, to_flush_ctrl, CT_FALSE);
            *need_exit = CT_TRUE;
            return CT_SUCCESS;
        }

        ckpt_copy_item(session, curr_ctrl, to_flush_ctrl);

        if (to_flush_ctrl == ctrl_next) {
            *ctrl_next_is_flushed = CT_TRUE;
        }

        buf_unlatch(session, to_flush_ctrl, CT_FALSE);

        if (ckpt_ending_prepare(session, ctx) != CT_SUCCESS) {
            return CT_ERROR;
        }

        ctx->stat.ckpt_total_neighbors_len++;
        ctx->stat.ckpt_curr_neighbors_len++;
        ctx->group.count++;

        if (ctx->group.count >= CT_CKPT_GROUP_SIZE(session)) {
            *need_exit = CT_TRUE;
            return CT_SUCCESS;
        }
    }

    return CT_SUCCESS;
}

status_t ckpt_prepare_pages(knl_session_t *session, ckpt_context_t *ctx)
{
    buf_ctrl_t *ctrl_next = NULL;
    buf_ctrl_t *ctrl = ctx->queue.first;
    bool8 ctrl_next_is_flushed = CT_FALSE;
    bool8 need_exit = CT_FALSE;

    ctx->group.count = 0;
    ctx->edp_group.count = 0;
    init_ckpt_part_group(session);
    if (DB_IS_CLUSTER(session)) {
        dcs_ckpt_remote_edp_prepare(session, ctx);
        dcs_ckpt_clean_local_edp(session, ctx);
        dtc_calculate_rcy_redo_size(session, ctrl);
    }

    if (ctx->queue.count == 0 || ctx->group.count >= CT_CKPT_GROUP_SIZE(session)) {
        return CT_SUCCESS;
    }

    ctx->trunc_lsn = 0;
    ctx->consistent_lfn = 0;
    ctx->has_compressed = CT_FALSE;
    ctx->stat.ckpt_curr_neighbors_times = 0;
    ctx->stat.ckpt_curr_neighbors_len = 0;

    while (ctrl != NULL) {
        ctrl_next = ctrl->ckpt_next;
        ctrl_next_is_flushed = CT_FALSE;
        if (page_compress(session, ctrl->page_id)) {
            knl_panic(!DB_IS_CLUSTER(session));  // not support compress in cluster for now
            if (ckpt_prepare_compress(session, ctx, ctrl, ctrl_next, &ctrl_next_is_flushed, &need_exit) != CT_SUCCESS) {
                return CT_ERROR;
            }
        } else {
            if (ckpt_prepare_normal(session, ctx, ctrl, ctrl_next, &ctrl_next_is_flushed, &need_exit) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }

        if (need_exit) {
            break;
        }

        ctrl = ctrl_next_is_flushed ? ctx->queue.first : ctrl_next;
        /* prevent that dirty page count is less than CT_CKPT_GROUP_SIZE,
           in the same time there is one page is latched. */
        if (!ctx->ckpt_enabled) {
            break;
        }
    }

    if (ctx->stat.ckpt_curr_neighbors_times != 0) {
        ctx->stat.ckpt_last_neighbors_len = (ctx->stat.ckpt_curr_neighbors_len / ctx->stat.ckpt_curr_neighbors_times);
    }

    return CT_SUCCESS;
}

static inline void ckpt_unlatch_datafiles(datafile_t **df, uint32 count, int32 size)
{
    if (cm_dbs_is_enable_dbs() == CT_TRUE && size == CT_UDFLT_VALUE_BUFFER_SIZE) {
        return;
    }

    for (uint32 i = 0; i < count; i++) {
        cm_unlatch(&df[i]->block_latch, NULL);
    }
}

static void ckpt_latch_datafiles(knl_session_t *session, datafile_t **df, uint64 *offset, int32 size, uint32 count)
{
    // dbstor can ensure that atomicity of read and write when page size is smaller than 8K
    if (cm_dbs_is_enable_dbs() == CT_TRUE && size == CT_UDFLT_VALUE_BUFFER_SIZE) {
        return;
    }

    uint64 end_pos = 0;
    uint32 i = 0;
    for (;;) {
        for (i = 0; i < count; i++) {
            end_pos = offset[i] + (uint64)size;

            if (!cm_latch_timed_s(&df[i]->block_latch, 1, CT_FALSE, NULL)) {
                /* latch fail need release them and try again from first page */
                ckpt_unlatch_datafiles(df, i, size);
                cm_sleep(1);
                break;
            }
            if (spc_datafile_is_blocked(session, df[i], (uint64)offset[i], end_pos)) {
                /* one page is backing up, need try again from fisrt page */
                ckpt_unlatch_datafiles(df, i + 1, size);
                cm_sleep(1);
                break;
            }
        }
        if (i == count) {
            return;
        }
    }
}

void dbwr_compress_checksum(knl_session_t *session, page_head_t *page)
{
    uint32 cks_level = session->kernel->attr.db_block_checksum;

    if (cks_level == (uint32)CKS_OFF) {
        COMPRESS_PAGE_HEAD(page)->checksum = CT_INVALID_CHECKSUM;
    } else {
        page_compress_calc_checksum(page, DEFAULT_PAGE_SIZE(session));
    }
}

static void dbwr_construct_group(knl_session_t *session, dbwr_context_t *dbwr, uint32 begin,
    uint32 compressed_size, const char *zbuf)
{
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;
    uint32 remaining_size, actual_size, zsize;
    page_head_t *page = NULL;
    buf_ctrl_t *ctrl = NULL;
    uint32 buf_id;
    uint32 offset;
    uint32 slot;
    errno_t ret;

    remaining_size = compressed_size;
    
    /* +---------+----------+---------------------+
    *  |page_head|group_head| zip data            |
    *  +---------+----------+---------------------+
    *  */
    slot = begin;
    zsize = COMPRESS_PAGE_VALID_SIZE(session);
    offset = 0;
    do {
        if (remaining_size > zsize) {
            actual_size = zsize;
        } else {
            actual_size = remaining_size;
        }

        ctrl = ctx->group.items[slot].ctrl;
        buf_id = ctx->group.items[slot].buf_id;
        page = (page_head_t *)(ctx->group.buf + ((uint64)buf_id) * DEFAULT_PAGE_SIZE(session));
        ret = memcpy_sp((char *)page + DEFAULT_PAGE_SIZE(session) - zsize, actual_size,
                        (char *)zbuf + offset, actual_size);
        knl_securec_check(ret);
        knl_panic_log(IS_SAME_PAGID(ctrl->page_id, AS_PAGID(page->id)), "the ctrl's page_id and page->id are not same, "
            "panic info: ctrl page %u-%u type %u curr page %u-%u", ctrl->page_id.file, ctrl->page_id.page, page->type,
            AS_PAGID(page->id).file, AS_PAGID(page->id).page);
        knl_panic_log(page_compress(session, AS_PAGID(page->id)), "the page is incompressible, panic info: "
            "type %u curr page %u-%u", page->type, AS_PAGID(page->id).file, AS_PAGID(page->id).page);
        COMPRESS_PAGE_HEAD(page)->compressed_size = compressed_size;
        COMPRESS_PAGE_HEAD(page)->compress_algo = COMPRESS_ZSTD;
        COMPRESS_PAGE_HEAD(page)->group_cnt = GROUP_COUNT_8;
        COMPRESS_PAGE_HEAD(page)->unused = 0;
        page->compressed = 1;
        dbwr_compress_checksum(session, page);
        remaining_size -= actual_size;
        offset += actual_size;
        slot++;
    } while (remaining_size != 0);

    while (slot <= begin + PAGE_GROUP_COUNT - 1) {
        ctx->group.items[slot].need_punch = CT_TRUE;
        ctrl = ctx->group.items[slot].ctrl;
        knl_panic_log(page_compress(session, ctrl->page_id), "the page is incompressible, panic info: "
            "curr page %u-%u", ctrl->page_id.file, ctrl->page_id.page);
        slot++;
    }
}

static status_t dbwr_compress_group(knl_session_t *session, dbwr_context_t *dbwr, uint32 begin, char *zbuf, char *src)
{
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;
    page_head_t *page = NULL;
    uint32 buf_id;
    uint32 compressed_size;
    errno_t ret;

    for (uint16 i = 0; i < PAGE_GROUP_COUNT; i++) {
        buf_id = ctx->group.items[i + begin].buf_id;
        page = (page_head_t *)(ctx->group.buf + ((uint64)buf_id) * DEFAULT_PAGE_SIZE(session));
        ret = memcpy_sp(src + DEFAULT_PAGE_SIZE(session) * i, DEFAULT_PAGE_SIZE(session), page,
                        DEFAULT_PAGE_SIZE(session));
        knl_securec_check(ret);
    }
    compressed_size = ZSTD_compress((char *)zbuf, DEFAULT_PAGE_SIZE(session) * PAGE_GROUP_COUNT, src,
        DEFAULT_PAGE_SIZE(session) * PAGE_GROUP_COUNT, ZSTD_DEFAULT_COMPRESS_LEVEL);
    if (ZSTD_isError(compressed_size)) {
        CT_THROW_ERROR(ERR_COMPRESS_ERROR, "zstd", compressed_size, ZSTD_getErrorName(compressed_size));
        return CT_ERROR;
    }

    if (SECUREC_LIKELY(compressed_size <= COMPRESS_GROUP_VALID_SIZE(session))) {
        dbwr_construct_group(session, dbwr, begin, compressed_size, zbuf);
    }

    return CT_SUCCESS;
}

/* we devide ckpt group into two groups,one is pages which would be punched,the other is pages wihch would be submit */
static status_t dbwr_compress_prepare(knl_session_t *session, dbwr_context_t *dbwr)
{
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;
    page_head_t *page = NULL;
    uint32 buf_id;
    uint32 skip_cnt;
    errno_t ret;
    pcb_assist_t src_pcb_assist;
    pcb_assist_t zbuf_pcb_assist;
    uint16 i;

    if (pcb_get_buf(session, &src_pcb_assist) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (pcb_get_buf(session, &zbuf_pcb_assist) != CT_SUCCESS) {
        pcb_release_buf(session, &src_pcb_assist);
        return CT_ERROR;
    }

    ret = memset_sp(zbuf_pcb_assist.aligned_buf, DEFAULT_PAGE_SIZE(session) * PAGE_GROUP_COUNT, 0,
        DEFAULT_PAGE_SIZE(session) * PAGE_GROUP_COUNT);
    knl_securec_check(ret);

    for (i = dbwr->begin; i <= dbwr->end; i = i + skip_cnt) {
        buf_id = ctx->group.items[i].buf_id;
        page = (page_head_t *)(ctx->group.buf + ((uint64)buf_id) * DEFAULT_PAGE_SIZE(session));
        skip_cnt = 1;
        if (!page_compress(session, AS_PAGID(page->id))) {
            continue;
        }
        knl_panic(AS_PAGID(page->id).page % PAGE_GROUP_COUNT == 0);
        if (dbwr_compress_group(session, dbwr, i, zbuf_pcb_assist.aligned_buf,
            src_pcb_assist.aligned_buf) != CT_SUCCESS) {
            pcb_release_buf(session, &src_pcb_assist);
            pcb_release_buf(session, &zbuf_pcb_assist);
            return CT_ERROR;
        }
        skip_cnt = PAGE_GROUP_COUNT;
    }

    pcb_release_buf(session, &src_pcb_assist);
    pcb_release_buf(session, &zbuf_pcb_assist);
    return CT_SUCCESS;
}

static status_t dbwr_async_io_write(knl_session_t *session, cm_aio_iocbs_t *aio_cbs, ckpt_context_t *ctx,
                                    dbwr_context_t *dbwr, uint32 size)
{
    struct timespec timeout = { 0, 200 };
    int32 aio_ret;
    uint32 buf_id, cb_id;
    page_head_t *page = NULL;
    ckpt_asyncio_ctx_t *asyncio_ctx = &dbwr->async_ctx;
    cm_aio_lib_t *lib_ctx = &session->kernel->aio_lib;
    int32 event_num = (int32)dbwr->io_cnt;
    ckpt_sort_item *item = NULL;
    cb_id = 0;
    uint32 idx = 0;
    errno_t ret;
    datafile_t *df = NULL;

    ret = memset_sp(dbwr->flags, sizeof(dbwr->flags), 0, sizeof(dbwr->flags));
    knl_securec_check(ret);

    for (uint16 i = dbwr->begin; i <= dbwr->end; i++) {
        item = &ctx->group.items[i];
        if (item->need_punch) {
            if (cm_file_punch_hole(*asyncio_ctx->handles[idx], (int64)asyncio_ctx->offsets[idx], size) != CT_SUCCESS) {
                CT_LOG_RUN_ERR("[CKPT] failed to punch datafile %s", asyncio_ctx->datafiles[idx]->ctrl->name);
                return CT_ERROR;
            }
        } else {
            buf_id = ctx->group.items[i].buf_id;
            page = (page_head_t *)(ctx->group.buf + ((uint64)buf_id) * size);
            knl_panic(item->ctrl != NULL);
            knl_panic(IS_SAME_PAGID(item->ctrl->page_id, AS_PAGID(page->id)));
            aio_cbs->iocb_ptrs[cb_id] = &aio_cbs->iocbs[cb_id];
            cm_aio_prep_write(aio_cbs->iocb_ptrs[cb_id], *asyncio_ctx->handles[idx], (void *)page, size,
                              (int64)asyncio_ctx->offsets[idx]);
            knl_panic(asyncio_ctx->offsets[idx] == (uint64)item->ctrl->page_id.page * PAGE_SIZE(*page));
            cb_id++;

            df = asyncio_ctx->datafiles[idx];
            dbwr->flags[df->ctrl->id] = CT_TRUE;
        }
        idx++;
    }
    knl_panic(cb_id == dbwr->io_cnt);
    aio_ret = lib_ctx->io_submit(dbwr->async_ctx.aio_ctx, (long)event_num, aio_cbs->iocb_ptrs);
    if (aio_ret != event_num) {
        CT_LOG_RUN_ERR("[CKPT] failed to submit by async io, error code: %d, aio_ret: %d", errno, aio_ret);
        return CT_ERROR;
    }

    while (event_num > 0) {
        ret = memset_sp(aio_cbs->events, sizeof(cm_io_event_t) * event_num, 0, sizeof(cm_io_event_t) * event_num);
        knl_securec_check(ret);
        aio_ret = lib_ctx->io_getevents(dbwr->async_ctx.aio_ctx, 1, event_num, aio_cbs->events, &timeout);
        if (aio_ret < 0) {
            if (errno == EINTR || aio_ret == -EINTR) {
                continue;
            }
            CT_LOG_RUN_ERR("[CKPT] failed to getevent by async io, error code: %d, aio_ret: %d", errno, aio_ret);
            return CT_ERROR;
        }
        for (int32 i = 0; i < aio_ret; i++) {
            if (aio_cbs->events[i].res != size) {
                CT_LOG_RUN_ERR("[CKPT] failed to write by event, error code: %ld", aio_cbs->events[i].res);
                return CT_ERROR;
            }
        }
        event_num = event_num - aio_ret;
    }

    return dbwr_fdatasync(session, dbwr);
}

static status_t dbwr_flush_async_io(knl_session_t *session, dbwr_context_t *dbwr)
{
    ckpt_asyncio_ctx_t *asyncio_ctx = &dbwr->async_ctx;
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;
    page_id_t *page_id = NULL;
    page_head_t *page = NULL;
    uint32 buf_offset, buf_id;
    cm_aio_iocbs_t aio_cbs;
    ckpt_sort_item *item = NULL;

    if (ctx->has_compressed) {
        if (dbwr_compress_prepare(session, dbwr) != CT_SUCCESS) {
            int32 err_code = cm_get_error_code();
            if (err_code != ERR_ALLOC_MEMORY) {
                return CT_ERROR;
            }
            /* if there is not enough memory, no compression is performed */
            cm_reset_error();
        }
    }

    dbwr->io_cnt = dbwr->end - dbwr->begin + 1; // page count need to io ,init by all page count first.
    uint32 latch_cnt = 0; // to recode page count need to latch.
    for (uint16 i = dbwr->begin; i <= dbwr->end; i++) {
        buf_id = ctx->group.items[i].buf_id;
        page = (page_head_t *)(ctx->group.buf + ((uint64)buf_id) * DEFAULT_PAGE_SIZE(session));
        item = &ctx->group.items[i];
        if (item->need_punch) {
            dbwr->io_cnt--; // remove punch hole page count from all page count.
        }
        knl_panic(item->ctrl != NULL);
        knl_panic(IS_SAME_PAGID(item->ctrl->page_id, AS_PAGID(page->id)));

        page_id = AS_PAGID_PTR(page->id);
        asyncio_ctx->datafiles[latch_cnt] = DATAFILE_GET(session, page_id->file);
        asyncio_ctx->handles[latch_cnt] = &dbwr->datafiles[page_id->file];
        asyncio_ctx->offsets[latch_cnt] = (uint64)page_id->page * DEFAULT_PAGE_SIZE(session);
        knl_panic(page_compress(session, AS_PAGID(page)) || CHECK_PAGE_PCN(page));

        if (spc_open_datafile(session, asyncio_ctx->datafiles[latch_cnt],
            asyncio_ctx->handles[latch_cnt]) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[CKPT] failed to open datafile %s", asyncio_ctx->datafiles[latch_cnt]->ctrl->name);
            return CT_ERROR;
        }
        latch_cnt++;
    }

    buf_offset = dbwr->begin * CM_IOCB_LENTH;
    aio_cbs.iocbs = (cm_iocb_t *)(ctx->group.iocbs_buf + buf_offset);
    buf_offset += sizeof(cm_iocb_t) * dbwr->io_cnt;
    aio_cbs.events = (cm_io_event_t*)(ctx->group.iocbs_buf + buf_offset);
    buf_offset += sizeof(cm_io_event_t) * dbwr->io_cnt;
    aio_cbs.iocb_ptrs = (cm_iocb_t**)(ctx->group.iocbs_buf + buf_offset);

    ckpt_latch_datafiles(session, asyncio_ctx->datafiles, asyncio_ctx->offsets, DEFAULT_PAGE_SIZE(session), latch_cnt);
    if (dbwr_async_io_write(session, &aio_cbs, ctx, dbwr, DEFAULT_PAGE_SIZE(session)) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CKPT] failed to write datafile by async io");
        ckpt_unlatch_datafiles(asyncio_ctx->datafiles, latch_cnt, DEFAULT_PAGE_SIZE(session));
        return CT_ERROR;
    }
    ckpt_unlatch_datafiles(asyncio_ctx->datafiles, latch_cnt, DEFAULT_PAGE_SIZE(session));

    for (uint16 i = dbwr->begin; i <= dbwr->end; i++) {
        ctx->group.items[i].ctrl->is_marked = 0;
    }

    return CT_SUCCESS;
}

static status_t dbwr_sync_pg_pool(knl_session_t *session, dbwr_context_t *dbwr, uint32 part_id)
{
    database_t *db = &session->kernel->db;

    for (uint32 i = 0; i < CT_MAX_DATA_FILES; i++) {
        if (dbwr->flags[i]) {
            if (cm_sync_device_by_part(dbwr->datafiles[i], part_id) != CT_SUCCESS) {
                CT_LOG_RUN_ERR("failed to fdatasync datafile %s, part_id %d", db->datafiles[i].ctrl->name, part_id);
                return CT_ERROR;
            }
        }
    }
    return CT_SUCCESS;
}

status_t dbwr_async_io_write_dbs(knl_session_t *session, ckpt_context_t *ctx, dbwr_context_t *dbwr, uint32 size)
{
    uint32 buf_id;
    page_head_t *page = NULL;
    ckpt_asyncio_ctx_t *asyncio_ctx = &dbwr->async_ctx;
    errno_t ret;
    datafile_t *df = NULL;
    uint32 begin = 0;
    uint32 end = 0;

    ret = memset_sp(dbwr->flags, sizeof(dbwr->flags), 0, sizeof(dbwr->flags));
    knl_securec_check(ret);
    while (begin < dbwr->io_cnt) {
        end = MIN(begin + session->kernel->attr.batch_flush_capacity, dbwr->io_cnt);
        for (uint16 i = begin; i < end; i++) {
            uint32 group_idx = ctx->ckpt_part_group[dbwr->id].item_index[i];
            buf_id = ctx->group.items[group_idx].buf_id;
            page = (page_head_t *)(ctx->group.buf + ((uint64)buf_id) * size);
            if (cm_aio_prep_write_by_part(*asyncio_ctx->handles[i], (int64)asyncio_ctx->offsets[i], page, size,
                dbwr->id)) {
                return CT_ERROR;
            }

            df = asyncio_ctx->datafiles[i];
            dbwr->flags[df->ctrl->id] = CT_TRUE;
        }
        if (dbwr_sync_pg_pool(session, dbwr, dbwr->id) != CT_SUCCESS) {
            return CT_ERROR;
        }
        for (uint16 i = begin; i < end; i++) {
            uint32 group_index = ctx->ckpt_part_group[dbwr->id].item_index[i];
            ctx->group.items[group_index].ctrl->is_marked = 0;
        }
        begin = end;
    }

    return CT_SUCCESS;
}

status_t dbwr_flush_async_dbs(knl_session_t *session, dbwr_context_t *dbwr)
{
    ckpt_asyncio_ctx_t *asyncio_ctx = &dbwr->async_ctx;
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;
    page_id_t *page_id = NULL;
    page_head_t *page = NULL;
    uint32 buf_id, group_index;
    if (ctx->has_compressed) {
        knl_panic_log(0, "not support page compressed when flush dbs");
    }

    dbwr->io_cnt = ctx->ckpt_part_group[dbwr->id].count; // page count need to io ,init by all page count first.
    uint32 latch_cnt = 0;                                // to recode page count need to latch.
    for (uint16 i = 0; i < dbwr->io_cnt; i++) {
        group_index = ctx->ckpt_part_group[dbwr->id].item_index[i];
        buf_id = ctx->group.items[group_index].buf_id;
        page = (page_head_t *)(ctx->group.buf + ((uint64)buf_id) * DEFAULT_PAGE_SIZE(session));

        page_id = AS_PAGID_PTR(page->id);
        asyncio_ctx->datafiles[latch_cnt] = DATAFILE_GET(session, page_id->file);
        asyncio_ctx->handles[latch_cnt] = &dbwr->datafiles[page_id->file];
        asyncio_ctx->offsets[latch_cnt] = (uint64)page_id->page * DEFAULT_PAGE_SIZE(session);
        knl_panic(CHECK_PAGE_PCN(page));

        if (spc_open_datafile(session, asyncio_ctx->datafiles[latch_cnt], asyncio_ctx->handles[latch_cnt]) !=
            CT_SUCCESS) {
            CT_LOG_RUN_ERR("[CKPT] failed to open datafile %s", asyncio_ctx->datafiles[latch_cnt]->ctrl->name);
            return CT_ERROR;
        }
        latch_cnt++;
    }

    ckpt_latch_datafiles(session, asyncio_ctx->datafiles, asyncio_ctx->offsets, DEFAULT_PAGE_SIZE(session), latch_cnt);
    if (dbwr_async_io_write_dbs(session, ctx, dbwr, DEFAULT_PAGE_SIZE(session)) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CKPT] failed to write datafile by async io");
        ckpt_unlatch_datafiles(asyncio_ctx->datafiles, latch_cnt, DEFAULT_PAGE_SIZE(session));
        return CT_ERROR;
    }
    ckpt_unlatch_datafiles(asyncio_ctx->datafiles, latch_cnt, DEFAULT_PAGE_SIZE(session));
    return CT_SUCCESS;
}

static status_t ckpt_double_write(knl_session_t *session, ckpt_context_t *ctx)
{
    database_t *db = &session->kernel->db;
    datafile_t *df = DATAFILE_GET(session, db->ctrl.core.dw_file_id);
    timeval_t tv_begin, tv_end;
    int64 offset;
    dtc_node_ctrl_t *node = dtc_my_ctrl(session);

    (void)cm_gettimeofday(&tv_begin);

    if (ctx->dw_ckpt_start + ctx->group.count > DW_DISTRICT_END(session->kernel->id)) {
        ctx->dw_ckpt_start = DW_DISTRICT_BEGIN(session->kernel->id);
    }

    ctx->dw_ckpt_end = ctx->dw_ckpt_start + ctx->group.count;
    knl_panic(ctx->dw_ckpt_start >= DW_DISTRICT_BEGIN(session->kernel->id));
    knl_panic(ctx->dw_ckpt_end <= DW_DISTRICT_END(session->kernel->id));
    knl_panic(df->file_no == 0);  // first sysaux file

    offset = (uint64)ctx->dw_ckpt_start * DEFAULT_PAGE_SIZE(session);
    /* DEFAULT_PAGE_SIZE is 8192, ctx->group.count <= CT_CKPT_GROUP_SIZE(4096), can not cross bounds */
    if (spc_write_datafile(session, df, &ctx->dw_file, offset, ctx->group.buf,
                           ctx->group.count * DEFAULT_PAGE_SIZE(session)) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CKPT] failed to write datafile %s", df->ctrl->name);
        return CT_ERROR;
    }

    if (db_fdatasync_file(session, ctx->dw_file) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CKPT] failed to fdatasync datafile %s", (char *)DATAFILE_GET(session, 0));
        return CT_ERROR;
    }

    cm_spin_lock(&db->ctrl_lock, NULL);
    node->dw_start = ctx->dw_ckpt_start;
    node->dw_end = ctx->dw_ckpt_end;
    cm_spin_unlock(&db->ctrl_lock);

    (void)cm_gettimeofday(&tv_end);
    ctx->stat.double_writes++;
    ctx->stat.double_write_time += (uint64)TIMEVAL_DIFF_US(&tv_begin, &tv_end);

    return CT_SUCCESS;
}

static int32 ckpt_buforder_comparator(const void *pa, const void *pb)
{
    const ckpt_sort_item *a = (const ckpt_sort_item *) pa;
    const ckpt_sort_item *b = (const ckpt_sort_item *) pb;

    /* compare fileid */
    if (a->ctrl->page_id.file < b->ctrl->page_id.file) {
        return -1;
    } else if (a->ctrl->page_id.file > b->ctrl->page_id.file) {
        return 1;
    }

    /* compare page */
    if (a->ctrl->page_id.page < b->ctrl->page_id.page) {
        return -1;
    } else if (a->ctrl->page_id.page > b->ctrl->page_id.page) {
        return 1;
    }

    /* equal pageid is impossible */
    return 0;
}

static inline void ckpt_flush_sort(knl_session_t *session, ckpt_context_t *ctx)
{
    qsort(ctx->group.items, ctx->group.count, sizeof(ckpt_sort_item), ckpt_buforder_comparator);
}


static uint32 ckpt_adjust_dbwr(knl_session_t *session, buf_ctrl_t *ctrl)
{
    page_id_t first;

    first = page_first_group_id(session, ctrl->page_id);

    return (PAGE_GROUP_COUNT - (ctrl->page_id.page - first.page + 1));
}

/* flush [begin, end - 1] */
static inline status_t ckpt_flush(knl_session_t *session, ckpt_context_t *ctx, uint32 begin, uint32 end)
{
    uint32 pages_each_wr = (end - begin - 1) / ctx->dbwr_count + 1;
    uint32 curr_page = begin;
    uint32 i;
    uint32 trigger_count = 0;
    buf_ctrl_t *ctrl = NULL;
    uint32 cnt;
    for (i = 0; i < ctx->dbwr_count; i++) {
        ctx->dbwr[i].begin = curr_page;
        curr_page += pages_each_wr;
        if (curr_page >= end) {
            curr_page = end;
        }
        
        /* if the last page is compressed page, take all its grouped pages to this dbwr  */
        ctrl = ctx->group.items[curr_page - 1].ctrl;
        if (page_compress(session, ctrl->page_id)) {
            cnt = ckpt_adjust_dbwr(session, ctrl);
            curr_page += cnt;
            knl_panic(curr_page <= end);
        }

        ctx->dbwr[i].end = curr_page - 1;
        ctx->dbwr[i].dbwr_trigger = CT_TRUE;
        trigger_count++;
#ifdef WIN32
        ReleaseSemaphore(ctx->dbwr[i].sem, 1, NULL);
#else
        (void)sem_post(&ctx->dbwr[i].sem);
#endif  // WIN32

        if (curr_page >= end) {
            break;
        }
    }

    for (i = 0; i < trigger_count; i++) {
        while (ctx->dbwr[i].dbwr_trigger) {
            cm_sleep(1);
        }
    }
    return CT_SUCCESS;
}

static inline void ckpt_delay(knl_session_t *session, uint32 ckpt_io_capacity)
{
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;

    /* max capacity, skip sleep */
    if (ctx->group.count == ckpt_io_capacity) {
        return;
    }

    cm_sleep(1000); /* 1000ms */
}

static uint32 ckpt_get_dirty_ratio(knl_session_t *session)
{
    ckpt_context_t *ckpt_ctx = &session->kernel->ckpt_ctx;
    buf_context_t *buf_ctx = &session->kernel->buf_ctx;
    buf_set_t *set = NULL;
    uint64 total_pages;

    set = &buf_ctx->buf_set[0];
    total_pages = (uint64)set->capacity * buf_ctx->buf_set_count;

    return (uint32)ceil((double)ckpt_ctx->queue.count / ((double)total_pages) * CT_PERCENT);
}

static uint32 ckpt_adjust_io_capacity(knl_session_t *session)
{
    knl_attr_t *attr = &session->kernel->attr;
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;
    uint32 ckpt_io_capacity = attr->ckpt_io_capacity;
    atomic_t curr_io_read = cm_atomic_get(&session->kernel->total_io_read);

    /* adjust io capacity */
    if (ctx->trigger_task != CKPT_MODE_IDLE) {
        /* triggered, max capacity */
        ckpt_io_capacity = ctx->group.count;
    } else if (ctx->prev_io_read == curr_io_read || /* no read, max capacity */
               ckpt_get_dirty_ratio(session) > CT_MAX_BUF_DIRTY_PCT) {
        ckpt_io_capacity = ctx->group.count;
    } else {
        /* normal case */
        ckpt_io_capacity = attr->ckpt_io_capacity;
    }

    ctx->prev_io_read = curr_io_read;

    return ckpt_io_capacity;
}

static status_t ckpt_flush_by_part(knl_session_t *session, ckpt_context_t *ctx)
{
    for (uint32 i = 0; i < cm_dbs_get_part_num(); i++) {
        if (ctx->ckpt_part_group[i].count == 0) {
            continue;
        }
        ctx->dbwr[i].dbwr_trigger = CT_TRUE;
        ctx->dbwr[i].id = i;
        (void)sem_post(&ctx->dbwr[i].sem);
    }

    for (uint32 i = 0; i < cm_dbs_get_part_num(); i++) {
        ctx->stat.part_stat[i].cur_flush_pages = ctx->ckpt_part_group[i].count;
        ctx->stat.part_stat[i].flush_pagaes += ctx->ckpt_part_group[i].count;
        if (ctx->ckpt_part_group[i].count > ctx->stat.part_stat[i].max_flush_pages) {
            ctx->stat.part_stat[i].max_flush_pages = ctx->ckpt_part_group[i].count;
        } else if (ctx->ckpt_part_group[i].count < ctx->stat.part_stat[i].max_flush_pages) {
            ctx->stat.part_stat[i].min_flush_pages = ctx->ckpt_part_group[i].count;
        }
        if (ctx->ckpt_part_group[i].count == 0) {
            ctx->stat.part_stat[i].zero_flush_times += 1;
            continue;
        }
        while (ctx->dbwr[i].dbwr_trigger) {
            cm_sleep(1);
        }
        ctx->stat.part_stat[i].flush_times++;
    }
    return CT_SUCCESS;
}

static status_t ckpt_flush_pages(knl_session_t *session)
{
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;
    uint32 ckpt_io_capacity;
    uint32 begin;
    uint32 end;
    timeval_t tv_begin, tv_end;
    buf_ctrl_t *ctrl_border = NULL;

    if (cm_dbs_is_enable_dbs() && cm_dbs_is_enable_batch_flush()) {
        (void)cm_gettimeofday(&tv_begin);
        status_t ret = ckpt_flush_by_part(session, ctx);
        ctx->stat.disk_writes += ctx->group.count;
        (void)cm_gettimeofday(&tv_end);
        ctx->stat.disk_write_time += (uint64)TIMEVAL_DIFF_US(&tv_begin, &tv_end);
        return ret;
    }

    ckpt_io_capacity = ckpt_adjust_io_capacity(session);
    ckpt_flush_sort(session, ctx);

    begin = 0;
    while (begin < ctx->group.count) {
        end = MIN(begin + ckpt_io_capacity, ctx->group.count);
 
        ctrl_border = ctx->group.items[end - 1].ctrl; // if compressed, taking all the group
        if (page_compress(session, ctrl_border->page_id)) {
            end += ckpt_adjust_dbwr(session, ctrl_border);
            knl_panic(end <= ctx->group.count);
        }

        (void)cm_gettimeofday(&tv_begin);
        if (ckpt_flush(session, ctx, begin, end) != CT_SUCCESS) {
            return CT_ERROR;
        }

        (void)cm_gettimeofday(&tv_end);
        ctx->stat.disk_writes += end - begin;
        ctx->stat.disk_write_time += (uint64)TIMEVAL_DIFF_US(&tv_begin, &tv_end);
        ckpt_delay(session, ckpt_io_capacity);
        
        begin  = end;
    }

    /* check */
#ifdef LOG_DIAG
    buf_ctrl_t *ctrl = NULL;

    for (uint32 i = 0; i < ctx->group.count; i++) {
        ctrl = ctx->group.items[i].ctrl;
        knl_panic_log(ctrl->is_marked == 0, "ctrl is marked, panic info: page %u-%u type %u", ctrl->page_id.file,
                      ctrl->page_id.page, ctrl->page->type);
    }
#endif

    return CT_SUCCESS;
}

/*
 * we need to do following jobs before flushing pages:
 * 1.flush redo log to update lrp point.
 * 2.double write pages to be flushed if need.
 * 3.back up log info in core ctrl to log file.
 */
static status_t ckpt_flush_prepare(knl_session_t *session, ckpt_context_t *ctx)
{
    core_ctrl_t *core = &session->kernel->db.ctrl.core;

    if (log_flush(session, &ctx->lrp_point, &ctx->lrp_scn, NULL) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!DB_NOT_READY(session) && !DB_IS_READONLY(session)) {
        if (DB_IS_RAFT_ENABLED(session->kernel)) {
            raft_wait_for_log_flush(session, (uint64)ctx->lrp_point.lfn);
        } else if (session->kernel->lsnd_ctx.standby_num > 0) {
            lsnd_wait(session, (uint64)ctx->lrp_point.lfn, NULL);
        }
    }

    if ((ctx->group.count != 0) && ctx->double_write) {
        if (ckpt_double_write(session, ctx) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (DB_IS_PRIMARY(&session->kernel->db)) {
        dtc_node_ctrl_t *ctrl = dtc_my_ctrl(session);
        ctrl->lrp_point = ctx->lrp_point;
        ctrl->scn = ctx->lrp_scn;
        ctrl->lsn = DB_CURR_LSN(session);
        ctrl->lfn = session->kernel->lfn;
        if (ctrl->consistent_lfn < ctx->consistent_lfn) {
            ctrl->consistent_lfn = ctx->consistent_lfn;
        }

        if (DB_IS_RAFT_ENABLED(session->kernel) && (session->kernel->raft_ctx.status >= RAFT_STATUS_INITED)) {
            raft_context_t *raft_ctx = &session->kernel->raft_ctx;
            cm_spin_lock(&raft_ctx->raft_write_disk_lock, NULL);
            core->raft_flush_point = raft_ctx->raft_flush_point;
            cm_spin_unlock(&raft_ctx->raft_write_disk_lock);

            if (db_save_core_ctrl(session) != CT_SUCCESS) {
                return CT_ERROR;
            }

            knl_panic(session->kernel->raft_ctx.saved_raft_flush_point.lfn <= core->raft_flush_point.lfn &&
                session->kernel->raft_ctx.saved_raft_flush_point.raft_index <= core->raft_flush_point.raft_index);
                session->kernel->raft_ctx.saved_raft_flush_point = core->raft_flush_point;
        } else {
            if (dtc_save_ctrl(session, session->kernel->id) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }

        /* backup some core info on datafile head: only back up core log info for full ckpt & timed task */
        if (NEED_SYNC_LOG_INFO(ctx) && ctrl_backup_core_log_info(session) != CT_SUCCESS) {
            KNL_SESSION_CLEAR_THREADID(session);
            CM_ABORT(0, "[CKPT] ABORT INFO: backup core control info failed when perform checkpoint");
        }
    }
    
    return CT_SUCCESS;
}

/*
 * steps to perform checkpoint:
 * 1.prepare dirty pages and copy to ckpt group.
 * 2.flush redo log and double write dirty pages.
 * 3.flush pages to disk.
 */
static status_t ckpt_perform(knl_session_t *session)
{
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;

    if (ckpt_prepare_pages(session, ctx) != CT_SUCCESS) {
        return CT_ERROR;
    }

    dcs_notify_owner_for_ckpt(session, ctx);

    if (ctx->timed_task == CKPT_MODE_IDLE) {
        ctx->stat.flush_pages[ctx->trigger_task] += ctx->group.count;
    } else {
        ctx->stat.flush_pages[ctx->timed_task] += ctx->group.count;
    }

    if (DB_IS_PRIMARY(&session->kernel->db)) {
        ckpt_get_trunc_point(session, &ctx->trunc_point_snapshot);
    } else {
        ckpt_get_trunc_point_slave_role(session, &ctx->trunc_point_snapshot, &ctx->curr_node_idx);
    }

    if ((ctx->group.count == 0) && !dtc_need_empty_ckpt(session)) {
        dcs_clean_edp(session, ctx);
        return CT_SUCCESS;
    }

    if (ckpt_flush_prepare(session, ctx) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (ctx->group.count != 0) {
        if (ckpt_flush_pages(session) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    dcs_clean_edp(session, ctx);

    ctx->group.count = 0;
    ctx->dw_ckpt_start = ctx->dw_ckpt_end;
    dtc_my_ctrl(session)->ckpt_id++;
    dtc_my_ctrl(session)->dw_start = ctx->dw_ckpt_start;

    if (dtc_save_ctrl(session, session->kernel->id) != CT_SUCCESS) {
        KNL_SESSION_CLEAR_THREADID(session);
        CM_ABORT(0, "[CKPT] ABORT INFO: save core control file failed when perform checkpoint");
    }

    return CT_SUCCESS;
}

void ckpt_enque_page(knl_session_t *session)
{
    ckpt_context_t *ckpt = &session->kernel->ckpt_ctx;
    ckpt_queue_t *queue = &ckpt->queue;
    uint32 i;

    cm_spin_lock(&queue->lock, &session->stat->spin_stat.stat_ckpt_queue);

    if (queue->count == 0) {
        queue->first = session->dirty_pages[0];
        session->dirty_pages[0]->ckpt_prev = NULL;
    } else {
        queue->last->ckpt_next = session->dirty_pages[0];
        session->dirty_pages[0]->ckpt_prev = queue->last;
    }

    queue->last = session->dirty_pages[session->dirty_count - 1];
    queue->last->ckpt_next = NULL;
    queue->count += session->dirty_count;

    /** set log truncate point for every dirty page in current session */
    for (i = 0; i < session->dirty_count; i++) {
        knl_panic(session->dirty_pages[i]->in_ckpt == CT_FALSE);
        if (!DB_IS_PRIMARY(&session->kernel->db)) {
            session->dirty_pages[i]->curr_node_idx = queue->curr_node_idx;
        }
        session->dirty_pages[i]->trunc_point = queue->trunc_point;
        session->dirty_pages[i]->in_ckpt = CT_TRUE;
    }

    cm_spin_unlock(&queue->lock);

    session->stat->disk_writes += session->dirty_count;
    session->dirty_count = 0;
}

void ckpt_enque_one_page(knl_session_t *session, buf_ctrl_t *ctrl)
{
    ckpt_context_t *ckpt = &session->kernel->ckpt_ctx;
    ckpt_queue_t *queue = &ckpt->queue;

    cm_spin_lock(&queue->lock, &session->stat->spin_stat.stat_ckpt_queue);

    if (queue->count == 0) {
        queue->first = ctrl;
        ctrl->ckpt_prev = NULL;
    } else {
        queue->last->ckpt_next = ctrl;
        ctrl->ckpt_prev = queue->last;
    }

    queue->last = ctrl;
    queue->last->ckpt_next = NULL;
    queue->count++;

    if (!DB_IS_PRIMARY(&session->kernel->db)) {
        ctrl->curr_node_idx = queue->curr_node_idx;
    }
    ctrl->trunc_point = queue->trunc_point;
    ctrl->in_ckpt = CT_TRUE;
    cm_spin_unlock(&queue->lock);
}

bool32 ckpt_check(knl_session_t *session)
{
    ckpt_context_t *ckpt_ctx = &session->kernel->ckpt_ctx;

    if (ckpt_ctx->trigger_task == CKPT_MODE_IDLE && ckpt_ctx->queue.count == 0) {
        return CT_TRUE;
    } else {
        return CT_FALSE;
    }
}

void ckpt_set_trunc_point(knl_session_t *session, log_point_t *point)
{
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;

    /* do not move forward trunc point if GBP_RECOVERY is not completed */
    if (KNL_RECOVERY_WITH_GBP(session->kernel)) {
        return;
    }
    cm_spin_lock(&ctx->queue.lock, &session->stat->spin_stat.stat_ckpt_queue);
    ctx->queue.trunc_point = *point;
    cm_spin_unlock(&ctx->queue.lock);
}

void ckpt_set_trunc_point_slave_role(knl_session_t *session, log_point_t *point, uint32 curr_node_idx)
{
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;
 
    /* do not move forward trunc point if GBP_RECOVERY is not completed */
    if (KNL_RECOVERY_WITH_GBP(session->kernel)) {
        return;
    }
    cm_spin_lock(&ctx->queue.lock, &session->stat->spin_stat.stat_ckpt_queue);
    ctx->queue.trunc_point = *point;
    ctx->queue.curr_node_idx = curr_node_idx;
    cm_spin_unlock(&ctx->queue.lock);
}

void ckpt_get_trunc_point(knl_session_t *session, log_point_t *point)
{
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;

    cm_spin_lock(&ctx->queue.lock, &session->stat->spin_stat.stat_ckpt_queue);
    *point = ctx->queue.trunc_point;
    cm_spin_unlock(&ctx->queue.lock);
}

void ckpt_get_trunc_point_slave_role(knl_session_t *session, log_point_t *point, uint32 *curr_node_idx)
{
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;
 
    cm_spin_lock(&ctx->queue.lock, &session->stat->spin_stat.stat_ckpt_queue);
    *point = ctx->queue.trunc_point;
    *curr_node_idx = ctx->queue.curr_node_idx;
    cm_spin_unlock(&ctx->queue.lock);
}

status_t dbwr_save_page(knl_session_t *session, dbwr_context_t *dbwr, page_head_t *page)
{
    page_id_t *page_id = AS_PAGID_PTR(page->id);
    datafile_t *df = DATAFILE_GET(session, page_id->file);
    int32 *handle = &dbwr->datafiles[page_id->file];
    int64 offset = (int64)page_id->page * PAGE_SIZE(*page);

    knl_panic (!page_compress(session, *page_id));
    knl_panic (page->type != PAGE_TYPE_PUNCH_PAGE);
    knl_panic_log(CHECK_PAGE_PCN(page), "page pcn is abnormal, panic info: page %u-%u type %u", page_id->file,
        page_id->page, page->type);

    if (spc_write_datafile(session, df, handle, offset, page, PAGE_SIZE(*page)) != CT_SUCCESS) {
        spc_close_datafile(df, handle);
        CT_LOG_RUN_ERR("[CKPT] failed to write datafile %s", df->ctrl->name);
        return CT_ERROR;
    }

    if (!dbwr->flags[page_id->file]) {
        dbwr->flags[page_id->file] = CT_TRUE;
    }

    return CT_SUCCESS;
}

status_t dbwr_fdatasync(knl_session_t *session, dbwr_context_t *dbwr)
{
    database_t *db = &session->kernel->db;

    for (uint32 i = 0; i < CT_MAX_DATA_FILES; i++) {
        if (dbwr->flags[i]) {
            if (cm_fdatasync_file(dbwr->datafiles[i]) != CT_SUCCESS) {
                CT_LOG_RUN_ERR("failed to fdatasync datafile %s", db->datafiles[i].ctrl->name);
                return CT_ERROR;
            }
        }
    }

    return CT_SUCCESS;
}

static status_t dbwr_write_or_punch(knl_session_t *session, ckpt_sort_item *item, int32 *handle, datafile_t *df,
    page_head_t *page)
{
    page_id_t *page_id = AS_PAGID_PTR(page->id);
    int64 offset = (int64)page_id->page * PAGE_SIZE(*page);

    if (!page_compress(session, *page_id)) {
        knl_panic_log(CHECK_PAGE_PCN(page), "page pcn is abnormal, panic info: page %u-%u type %u", page_id->file,
            page_id->page, page->type);
    }

    if (item->need_punch) {
        knl_panic(page_compress(session, *page_id));
        if (cm_file_punch_hole(*handle, (uint64)offset, PAGE_SIZE(*page)) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[CKPT] failed to punch datafile compress %s", df->ctrl->name);
            return CT_ERROR;
        }
    } else if (page->type == PAGE_TYPE_PUNCH_PAGE) {
        knl_panic(!page_compress(session, *page_id));
        if (cm_file_punch_hole(*handle, (uint64)offset, PAGE_SIZE(*page)) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[CKPT] failed to punch datafile normal %s", df->ctrl->name);
            return CT_ERROR;
        }
    } else {
        if (cm_write_device(df->ctrl->type, *handle, offset, page, PAGE_SIZE(*page)) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[CKPT] failed to write datafile %s", df->ctrl->name);
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}
    
static status_t dbwr_save_page_by_id(knl_session_t *session, dbwr_context_t *dbwr, uint16 begin, uint16 *saved_cnt)
{
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;
    uint32 buf_id = ctx->group.items[begin].buf_id;
    page_head_t *page = (page_head_t *)(ctx->group.buf + ((uint64)buf_id) * DEFAULT_PAGE_SIZE(session));

    page_id_t *page_id = AS_PAGID_PTR(page->id);
    datafile_t *df = DATAFILE_GET(session, page_id->file);
    int32 *handle = &dbwr->datafiles[page_id->file];
    int64 offset = (int64)page_id->page * DEFAULT_PAGE_SIZE(session);
    uint16 sequent_cnt = page_compress(session, *page_id) ? PAGE_GROUP_COUNT : 1;
    uint64 end_pos = (uint64)offset + sequent_cnt * DEFAULT_PAGE_SIZE(session);
    *saved_cnt = 0;

    if (*handle == -1) {
        if (spc_open_datafile(session, df, handle) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[SPACE] failed to open datafile %s", df->ctrl->name);
            return CT_ERROR;
        }
    }

    for (;;) {
        cm_latch_s(&df->block_latch, CT_INVALID_ID32, CT_FALSE, NULL);
        if (!spc_datafile_is_blocked(session, df, (uint64)offset, end_pos)) {
            break;
        }
        cm_unlatch(&df->block_latch, NULL);
        cm_sleep(1);
    }

    for (uint16 i = begin; i < begin + sequent_cnt; i++) {
        buf_ctrl_t *ctrl = ctx->group.items[i].ctrl;
        buf_id = ctx->group.items[i].buf_id;
        page = (page_head_t *)(ctx->group.buf + ((uint64)buf_id) * DEFAULT_PAGE_SIZE(session));
        knl_panic_log(ctrl != NULL, "ctrl is NULL, panic info: page %u-%u type %u", AS_PAGID(page->id).file,
            AS_PAGID(page->id).page, page->type);
        knl_panic_log(IS_SAME_PAGID(ctrl->page_id, AS_PAGID(page->id)), "ctrl's page_id and page's id are not same, "
            "panic info: ctrl_page %u-%u type %u, page %u-%u type %u", ctrl->page_id.file,
            ctrl->page_id.page, ctrl->page->type, AS_PAGID(page->id).file, AS_PAGID(page->id).page, page->type);

        if (dbwr_write_or_punch(session, &ctx->group.items[i], handle, df, page) != CT_SUCCESS) {
            cm_unlatch(&df->block_latch, NULL);
            spc_close_datafile(df, handle);
            return CT_ERROR;
        }

        ctrl->is_marked = 0;
    }

    if (!dbwr->flags[page_id->file]) {
        dbwr->flags[page_id->file] = CT_TRUE;
    }

    cm_unlatch(&df->block_latch, NULL);
    *saved_cnt = sequent_cnt;
    return CT_SUCCESS;
}

static status_t dbwr_flush_sync_io(knl_session_t *session, dbwr_context_t *dbwr)
{
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;
    uint16 saved_cnt;

    errno_t ret = memset_sp(dbwr->flags, sizeof(dbwr->flags), 0, sizeof(dbwr->flags));
    knl_securec_check(ret);

    if (ctx->has_compressed) {
        if (dbwr_compress_prepare(session, dbwr) != CT_SUCCESS) {
            int32 err_code = cm_get_error_code();
            if (err_code != ERR_ALLOC_MEMORY) {
                return CT_ERROR;
            }
            /* if there is not enough memory, no compression is performed */
            cm_reset_error();
        }
    }

    for (uint16 i = dbwr->begin; i <= dbwr->end; i += saved_cnt) {
        if (dbwr_save_page_by_id(session, dbwr, i, &saved_cnt) != CT_SUCCESS) {
            return CT_ERROR;
        }
        knl_panic(saved_cnt == 1 || saved_cnt == PAGE_GROUP_COUNT);
    }

    if (session->kernel->attr.enable_fdatasync) {
        return dbwr_fdatasync(session, dbwr);
    }
    return CT_SUCCESS;
}

static status_t dbwr_flush(knl_session_t *session, dbwr_context_t *dbwr)
{
    if (cm_dbs_is_enable_dbs() && cm_dbs_is_enable_batch_flush()) {
        if (dbwr_flush_async_dbs(session, dbwr) != CT_SUCCESS) {
            return CT_ERROR;
        }
        return CT_SUCCESS;
    }
#ifndef WIN32
    if (session->kernel->attr.enable_asynch) {
        if (dbwr_flush_async_io(session, dbwr) != CT_SUCCESS) {
            return CT_ERROR;
        }
        return CT_SUCCESS;
    }
#endif

    if (dbwr_flush_sync_io(session, dbwr) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

void dbwr_end(knl_session_t *session, dbwr_context_t *dbwr)
{
    for (uint32 i = 0; i < CT_MAX_DATA_FILES; i++) {
        datafile_t *df = DATAFILE_GET(session, i);
        cm_close_device(df->ctrl->type, &dbwr->datafiles[i]);
        dbwr->datafiles[i] = CT_INVALID_HANDLE;
    }
}

static void dbwr_aio_destroy(knl_session_t *session, dbwr_context_t *dbwr)
{
#ifndef WIN32
    knl_instance_t *kernel = session->kernel;

    if (!session->kernel->attr.enable_asynch) {
        return;
    }

    (void)cm_aio_destroy(&kernel->aio_lib, dbwr->async_ctx.aio_ctx);
#endif
}

void dbwr_proc(thread_t *thread)
{
    dbwr_context_t *dbwr = (dbwr_context_t *)thread->argument;
    knl_session_t *session = dbwr->session;
    status_t status;

    cm_set_thread_name("dbwr");
    CT_LOG_RUN_INF("dbwr thread started");
    KNL_SESSION_SET_CURR_THREADID(session, cm_get_current_thread_id());
    while (!thread->closed) {
#ifdef WIN32
        if (WaitForSingleObject(dbwr->sem, 5000) == WAIT_TIMEOUT) {
            continue;
        }
#else
        struct timespec wait_time;
        long nsecs;
        (void)clock_gettime(CLOCK_REALTIME, &wait_time);
        nsecs = wait_time.tv_nsec + 500 * NANOSECS_PER_MILLISEC; // 500ms
        wait_time.tv_sec += nsecs / (int32)NANOSECS_PER_SECOND;
        wait_time.tv_nsec = nsecs % (int32)NANOSECS_PER_SECOND;

        if (sem_timedwait(&dbwr->sem, &wait_time) == -1) {
            continue;
        }
#endif  // WIN32
        if (thread->closed) {
            break;
        }
        // if enable dbstore batch flush, dbwr->begin and dbwr->end will unuse
        knl_panic(dbwr->end >= dbwr->begin || (cm_dbs_is_enable_dbs() && cm_dbs_is_enable_batch_flush()));
        knl_panic(dbwr->dbwr_trigger);

        status = dbwr_flush(session, dbwr);
        if (status != CT_SUCCESS) {
            CT_LOG_ALARM(WARN_FLUSHBUFFER, "'instance-name':'%s'}", session->kernel->instance_name);
            KNL_SESSION_CLEAR_THREADID(session);
            CM_ABORT_REASONABLE(0, "[CKPT] ABORT INFO: db flush fail");
        }
        dbwr->dbwr_trigger = CT_FALSE;
    }

    dbwr_end(session, dbwr);
    dbwr_aio_destroy(session, dbwr);
    CT_LOG_RUN_INF("dbwr thread closed");
    KNL_SESSION_CLEAR_THREADID(session);
}

static status_t ckpt_read_doublewrite_pages(knl_session_t *session, uint32 node_id)
{
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;
    int64 offset;
    datafile_t *df;
    uint32 dw_file_id = knl_get_dbwrite_file_id(session);

    offset = (int64)ctx->dw_ckpt_start * DEFAULT_PAGE_SIZE(session);
    df = DATAFILE_GET(session, dw_file_id);

    knl_panic(ctx->dw_ckpt_start >= DW_DISTRICT_BEGIN(node_id));
    knl_panic(ctx->dw_ckpt_end <= DW_DISTRICT_END(node_id));
    knl_panic(df->ctrl->id == dw_file_id);  // first sysware file

    ctx->group.count = ctx->dw_ckpt_end - ctx->dw_ckpt_start;
    /* DEFAULT_PAGE_SIZE is 8192, ctx->group.count <= CT_CKPT_GROUP_SIZE(4096), can not cross bounds */
    if (spc_read_datafile(session, df, &ctx->dw_file, offset, ctx->group.buf,
        ctx->group.count * DEFAULT_PAGE_SIZE(session)) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CKPT] failed to open datafile %s", df->ctrl->name);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t ckpt_recover_decompress(knl_session_t *session, int32 *handle, page_head_t *page,
    const char *read_buf, char *org_group)
{
    const uint32 group_size = DEFAULT_PAGE_SIZE(session) * PAGE_GROUP_COUNT;
    page_id_t *page_id = AS_PAGID_PTR(page->id);
    datafile_t *df = DATAFILE_GET(session, page_id->file);
    status_t status = CT_SUCCESS;
    page_head_t *org_page = NULL;
    uint32 size;
    errno_t ret;

    if (((page_head_t *)read_buf)->compressed) {
        if (buf_check_load_compress_group(session, *page_id, read_buf) != CT_SUCCESS) {
            return CT_ERROR;
        }
        if (buf_decompress_group(session, org_group, read_buf, &size) != CT_SUCCESS) {
            return CT_ERROR;
        }
        if (size != group_size) {
            return CT_ERROR;
        }
    } else {
        ret = memcpy_s(org_group, group_size, read_buf, group_size);
        knl_securec_check(ret);
    }

    for (uint32 i = 0; i < PAGE_GROUP_COUNT; i++) {
        org_page = (page_head_t *)((char *)org_group + i * DEFAULT_PAGE_SIZE(session));
        if (!CHECK_PAGE_PCN(org_page) || (PAGE_CHECKSUM(org_page, DEFAULT_PAGE_SIZE(session)) == CT_INVALID_CHECKSUM) ||
            !page_verify_checksum(org_page, DEFAULT_PAGE_SIZE(session))) {
            CT_LOG_RUN_INF("[CKPT] datafile %s page corrupted(file %u, page %u), recover from doublewrite page",
                df->ctrl->name, page_id->file, page_id->page + i);
            status = CT_ERROR;
        }
    }

    return status;
}

static status_t ckpt_recover_one(knl_session_t *session, int32 *handle, page_head_t *page, page_head_t *org_page,
    bool32 force_recover)
{
    page_id_t *page_id = AS_PAGID_PTR(page->id);
    int64 offset = (int64)page_id->page * PAGE_SIZE(*page);
    datafile_t *df = DATAFILE_GET(session, page_id->file);
    space_t *space = SPACE_GET(session, df->space_id);
    status_t status;

    if (!force_recover) {
        if (CHECK_PAGE_PCN(org_page) && (PAGE_CHECKSUM(org_page, DEFAULT_PAGE_SIZE(session)) != CT_INVALID_CHECKSUM) &&
            page_verify_checksum(org_page, DEFAULT_PAGE_SIZE(session))) {
            if (org_page->lsn >= page->lsn) {
                return CT_SUCCESS;
            }
            CT_LOG_RUN_INF(
                "[CKPT] datafile %s page (file %u, page %u) found older data with lsn %llu than doublewrite %llu",
                df->ctrl->name, page_id->file, page_id->page, org_page->lsn, page->lsn);

            if (!(CHECK_PAGE_PCN(page) && (PAGE_CHECKSUM(page, DEFAULT_PAGE_SIZE(session)) != CT_INVALID_CHECKSUM) &&
                  page_verify_checksum(page, DEFAULT_PAGE_SIZE(session)))) {
                CT_LOG_RUN_INF("[CKPT] datafile %s page (file %u, page %u) is newer in dbwr but is corrupted.",
                               df->ctrl->name, page_id->file, page_id->page);
                return CT_SUCCESS;
            }
        }
        CT_LOG_RUN_INF("[CKPT] datafile %s page corrupted(file %u, page %u), recover from doublewrite page",
            df->ctrl->name, page_id->file, page_id->page);
    }

    knl_panic_log(CHECK_PAGE_PCN(page), "page pcn is abnormal, panic info: page %u-%u type %u", page_id->file,
        page_id->page, page->type);
    knl_panic_log((PAGE_CHECKSUM(page, DEFAULT_PAGE_SIZE(session)) == CT_INVALID_CHECKSUM) ||
        page_verify_checksum(page, DEFAULT_PAGE_SIZE(session)), "checksum is wrong, panic info: page %u-%u type %u",
        page_id->file, page_id->page, page->type);

    status = spc_write_datafile(session, df, handle, offset, page, DEFAULT_PAGE_SIZE(session));
    if (status != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CKPT] failed to write datafile %s, file %u, page %u", df->ctrl->name, page_id->file,
            page_id->page);
    } else {
        status = db_fdatasync_file(session, *handle);
        if (status != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[CKPT] failed to fdatasync datafile %s", df->ctrl->name);
        }
    }

    if (status != CT_SUCCESS) {
        if (spc_auto_offline_space(session, space, df)) {
            status = CT_SUCCESS;
        }
    }

    return status;
}

static status_t ckpt_recover_compress_group(knl_session_t *session, ckpt_context_t *ctx, uint32 slot)
{
    rcy_sort_item_t *item = &ctx->rcy_items[slot];
    page_head_t *page = item->page;
    page_id_t *page_id = AS_PAGID_PTR(page->id);
    int64 offset = (int64)page_id->page * PAGE_SIZE(*page);
    datafile_t *df = DATAFILE_GET(session, page_id->file);
    space_t *space = SPACE_GET(session, df->space_id);
    int32 handle = -1;
    char *read_buf = NULL;
    char *src = NULL;
    char *org_group = NULL;
    uint32 size;
    status_t status = CT_SUCCESS;

    knl_panic_log(page_id->page % PAGE_GROUP_COUNT == 0, "panic info: page %u-%u not the group head", page_id->file,
        page_id->page);
    size = DEFAULT_PAGE_SIZE(session) * PAGE_GROUP_COUNT;
    src = (char *)malloc(size + CT_MAX_ALIGN_SIZE_4K);
    if (src == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, size + CT_MAX_ALIGN_SIZE_4K, "recover compress group");
        return CT_ERROR;
    }
    org_group = (char *)malloc(size);
    if (org_group == NULL) {
        free(src);
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, size, "recover compress group");
        return CT_ERROR;
    }
    read_buf = (char *)cm_aligned_buf(src);
    if (spc_read_datafile(session, df, &handle, offset, read_buf, size) != CT_SUCCESS) {
        spc_close_datafile(df, &handle);
        CT_LOG_RUN_ERR("[CKPT] failed to read datafile %s, file %u, page %u", df->ctrl->name, page_id->file,
            page_id->page);

        if (spc_auto_offline_space(session, space, df)) {
            CT_LOG_RUN_INF("[CKPT] skip recover offline space %s and datafile %s", space->ctrl->name, df->ctrl->name);
            free(org_group);
            free(src);
            return CT_SUCCESS;
        }

        free(org_group);
        free(src);
        return CT_ERROR;
    }

    if (ckpt_recover_decompress(session, &handle, page, read_buf, org_group) != CT_SUCCESS) {
        CT_LOG_RUN_INF("[CKPT] datafile %s decompress group failed(file %u, page %u), recover from doublewrite",
            df->ctrl->name, page_id->file, page_id->page);
        /* we need to recover the compress group as a whole */
        for (uint32 i = 0; i < PAGE_GROUP_COUNT; i++) {
            if (ckpt_recover_one(session, &handle, ctx->rcy_items[slot + i].page,
                (page_head_t *)((char *)org_group + i * DEFAULT_PAGE_SIZE(session)), CT_TRUE) != CT_SUCCESS) {
                status = CT_ERROR;
                break;
            }
        }
    }

    free(org_group);
    free(src);
    spc_close_datafile(df, &handle);
    return status;
}

static status_t ckpt_recover_normal(knl_session_t *session, ckpt_context_t *ctx, uint32 slot, page_head_t *org_page)
{
    rcy_sort_item_t *item = &ctx->rcy_items[slot];
    page_head_t *page = item->page;
    page_id_t *page_id = AS_PAGID_PTR(page->id);
    int64 offset = (int64)page_id->page * PAGE_SIZE(*page);
    datafile_t *df = DATAFILE_GET(session, page_id->file);
    space_t *space = SPACE_GET(session, df->space_id);
    int32 handle = -1;
    status_t status;

    if (spc_read_datafile(session, df, &handle, offset, org_page, DEFAULT_PAGE_SIZE(session)) != CT_SUCCESS) {
        spc_close_datafile(df, &handle);
        CT_LOG_RUN_ERR("[CKPT] failed to read datafile %s, file %u, page %u", df->ctrl->name, page_id->file,
            page_id->page);

        if (spc_auto_offline_space(session, space, df)) {
            CT_LOG_RUN_INF("[CKPT] skip recover offline space %s and datafile %s", space->ctrl->name, df->ctrl->name);
            return CT_SUCCESS;
        }

        return CT_ERROR;
    }

    status = ckpt_recover_one(session, &handle, page, org_page, CT_FALSE);
    spc_close_datafile(df, &handle);
    return status;
}

status_t ckpt_recover_page(knl_session_t *session, ckpt_context_t *ctx, uint32 slot, page_head_t *org_page,
    uint32 *skip_cnt)
{
    rcy_sort_item_t *item = &ctx->rcy_items[slot];
    page_head_t *page = item->page;
    page_id_t *page_id = AS_PAGID_PTR(page->id);
    datafile_t *df = DATAFILE_GET(session, page_id->file);
    space_t *space = SPACE_GET(session, df->space_id);
    status_t status;

    if (!SPACE_IS_ONLINE(space) || !DATAFILE_IS_ONLINE(df)) {
        CT_LOG_RUN_INF("[CKPT] skip recover offline space %s and datafile %s", space->ctrl->name, df->ctrl->name);
        return CT_SUCCESS;
    }

    if (page_compress(session, *page_id)) {
        *skip_cnt = PAGE_GROUP_COUNT;
        status = ckpt_recover_compress_group(session, ctx, slot);
    } else {
        *skip_cnt = 1;
        status = ckpt_recover_normal(session, ctx, slot, org_page);
    }

    return status;
}

static int32 ckpt_rcyorder_comparator(const void *pa, const void *pb)
{
    const rcy_sort_item_t *a = (const rcy_sort_item_t *)pa;
    const rcy_sort_item_t *b = (const rcy_sort_item_t *)pb;

    /* compare fileid */
    if (AS_PAGID(a->page->id).file < AS_PAGID(b->page->id).file) {
        return -1;
    } else if (AS_PAGID(a->page->id).file > AS_PAGID(b->page->id).file) {
        return 1;
    }

    /* compare page */
    if (AS_PAGID(a->page->id).page < AS_PAGID(b->page->id).page) {
        return -1;
    } else if (AS_PAGID(a->page->id).page > AS_PAGID(b->page->id).page) {
        return 1;
    }

    /* equal pageid is impossible */
    return 0;
}

static void ckpt_recover_prepare(knl_session_t *session, ckpt_context_t *ctx)
{
    page_head_t *page = NULL;

    for (uint32 i = 0; i < ctx->group.count; i++) {
        page = (page_head_t *)(ctx->group.buf + i * DEFAULT_PAGE_SIZE(session));
        ctx->rcy_items[i].page = page;
        ctx->rcy_items[i].buf_id = i;
    }
    qsort(ctx->rcy_items, ctx->group.count, sizeof(rcy_sort_item_t), ckpt_rcyorder_comparator);
}

static status_t ckpt_recover_pages(knl_session_t *session, ckpt_context_t *ctx, uint32 node_id)
{
    uint32 i;
    page_head_t *page = NULL;
    char *page_buf = (char *)cm_push(session->stack, DEFAULT_PAGE_SIZE(session) + CT_MAX_ALIGN_SIZE_4K);
    char *head = (char *)cm_aligned_buf(page_buf);
    dtc_node_ctrl_t *node = dtc_get_ctrl(session, node_id);
    uint16 swap_file_head = SPACE_GET(session, node->swap_space)->ctrl->files[0];
    uint32 skip_cnt;

    ckpt_recover_prepare(session, ctx);
    for (i = 0; i < ctx->group.count; i = i + skip_cnt) {
        page = ctx->rcy_items[i].page;
        page_id_t *page_id = AS_PAGID_PTR(page->id);
        skip_cnt = 1;

        if (page_id->file == swap_file_head) {
            CT_LOG_RUN_INF("[CKPT] skip recover swap datafile %s", DATAFILE_GET(session, swap_file_head)->ctrl->name);
            continue;
        }

        if (ckpt_recover_page(session, ctx, i, (page_head_t *)head, &skip_cnt) != CT_SUCCESS) {
            cm_pop(session->stack);
            return CT_ERROR;
        }
    }

    cm_pop(session->stack);
    ctx->group.count = 0;
    ctx->dw_ckpt_start = ctx->dw_ckpt_end;
    node->dw_start = ctx->dw_ckpt_end;

    if (dtc_save_ctrl(session, node_id) != CT_SUCCESS) {
        CM_ABORT(0, "[CKPT] ABORT INFO: save core control file failed when checkpoint recover pages");
    }

    return CT_SUCCESS;
}

status_t ckpt_recover_partial_write_node(knl_session_t *session, uint32 node_id)
{
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;
    dtc_node_ctrl_t *node = dtc_get_ctrl(session, node_id);

    ctx->dw_ckpt_start = node->dw_start;
    ctx->dw_ckpt_end = node->dw_end;

    if (ctx->dw_ckpt_start == ctx->dw_ckpt_end) {
        return CT_SUCCESS;
    }

    if (ckpt_read_doublewrite_pages(session, node_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (ckpt_recover_pages(session, ctx, node_id) != CT_SUCCESS) {
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("[CKPT] ckpt recover doublewrite finish for node %u", node_id);
    return CT_SUCCESS;
}

status_t ckpt_recover_partial_write(knl_session_t *session)
{
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;
    dtc_node_ctrl_t *node = dtc_my_ctrl(session);
    uint32 node_count = session->kernel->db.ctrl.core.node_count;

    if (DB_ATTR_CLUSTER(session) && !rc_is_master()) {
        ctx->dw_ckpt_start = node->dw_start;
        ctx->dw_ckpt_end = node->dw_start;
        CT_LOG_RUN_INF("[CKPT] ckpt doublewrite recover has been done on master node.");
        return CT_SUCCESS;
    }

    for (uint32 i = 0; i < node_count; i++) {
        ckpt_recover_partial_write_node(session, i);
    }

    ctx->dw_ckpt_start = node->dw_start;
    ctx->dw_ckpt_end = node->dw_start;

    CT_LOG_RUN_INF("[CKPT] ckpt recover finish, memory usage=%lu", cm_print_memory_usage());
    return CT_SUCCESS;
}

/* Forbidden others to set new task, and then wait the running task to finish */
void ckpt_disable(knl_session_t *session)
{
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;
    cm_spin_lock(&ctx->disable_lock, NULL);
    ctx->disable_cnt++;
    ctx->ckpt_enabled = CT_FALSE;
    cm_spin_unlock(&ctx->disable_lock);
    while ((ctx->trigger_task != CKPT_MODE_IDLE || ctx->timed_task != CKPT_MODE_IDLE) && !ctx->ckpt_blocked) {
        cm_sleep(10);
    }
}

void ckpt_enable(knl_session_t *session)
{
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;
    cm_spin_lock(&ctx->disable_lock, NULL);
    if (ctx->disable_cnt > 0) {
        ctx->disable_cnt--;
    }
    if (ctx->disable_cnt == 0) {
        ctx->ckpt_enabled = CT_TRUE;
    }
    cm_spin_unlock(&ctx->disable_lock);
}

/*
 * disable ckpt and remove page of df to be removed from ckpt queue
 */
void ckpt_remove_df_page(knl_session_t *session, datafile_t *df, bool32 need_disable)
{
    knl_instance_t *kernel = session->kernel;
    ckpt_context_t *ctx = &kernel->ckpt_ctx;
    uint32 pop_count = 0;

    if (need_disable) {
        ckpt_disable(session);
    }

    /* remove page from queue base on file id */
    cm_spin_lock(&ctx->queue.lock, &session->stat->spin_stat.stat_ckpt_queue);
    buf_ctrl_t *curr = ctx->queue.first;
    buf_ctrl_t *last = ctx->queue.last;
    cm_spin_unlock(&ctx->queue.lock);

    buf_ctrl_t *next = NULL;
    while (ctx->queue.count != 0 && curr != NULL && curr != last->ckpt_next) {
        next = curr->ckpt_next;
        if (curr->page_id.file == df->ctrl->id) {
            ckpt_pop_page(session, ctx, curr);
            curr->is_dirty = 0;  // todo: notify other nodes
            curr->is_remote_dirty = 0;
            curr->is_edp = 0;
            buf_expire_page(session, curr->page_id);
            pop_count++;
        }
        curr = next;
    }

    if (need_disable) {
        ckpt_enable(session);
    }

    CT_LOG_RUN_INF("[CKPT] remove df page, count=%u, df=%s.", pop_count, df->ctrl->name);
}

static status_t ckpt_clean_try_latch_group(knl_session_t *session, buf_ctrl_t *ctrl, buf_ctrl_t **ctrl_group)
{
    page_id_t page_id;
    uint32  i, j;
    buf_ctrl_t *cur_ctrl = NULL;

    page_id = page_first_group_id(session, ctrl->page_id);
    
    for (i = 0; i < PAGE_GROUP_COUNT; i++, page_id.page++) {
        cur_ctrl = buf_find_by_pageid(session, page_id);
        knl_panic(cur_ctrl != NULL);
        if (!ckpt_try_latch_ctrl(session, cur_ctrl)) {
            for (j = 0; j < i; j++) {
                buf_unlatch(session, ctrl_group[j], CT_FALSE);
            }
            return CT_ERROR;
        }
        ctrl_group[i] = cur_ctrl;
    }

    return CT_SUCCESS;
}

status_t ckpt_clean_prepare_compress(knl_session_t *session, ckpt_context_t *ctx, buf_ctrl_t *head)
{
    ctx->has_compressed = CT_TRUE;
    buf_ctrl_t *ctrl_group[PAGE_GROUP_COUNT];
    int32 i, j;

    if (ctx->group.count + PAGE_GROUP_COUNT > CT_CKPT_GROUP_SIZE(session)) {
        return CT_SUCCESS; // continue the next
    }

    if (ckpt_clean_try_latch_group(session, head, ctrl_group) != CT_SUCCESS) {
        return CT_SUCCESS; // continue the next
    }

    knl_panic(!head->is_marked);
    knl_panic(head->in_ckpt);

    /* Copy all the compression group pages to ckpt group.
     * If a page is dirty (in ckpt queue), we will pop it and update its flags.
     */
    for (i = 0; i < PAGE_GROUP_COUNT; i++) {
        knl_panic_log(IS_SAME_PAGID(ctrl_group[i]->page_id, AS_PAGID(ctrl_group[i]->page->id)),
            "ctrl_group[%d]'s page_id and page's id are not same, panic info: page_id %u-%u type %u, page id %u-%u "
            "type %u", i, ctrl_group[i]->page_id.file, ctrl_group[i]->page_id.page, ctrl_group[i]->page->type,
            AS_PAGID(ctrl_group[i]->page->id).file, AS_PAGID(ctrl_group[i]->page->id).page, ctrl_group[i]->page->type);

        errno_t ret = memcpy_sp(ctx->group.buf + DEFAULT_PAGE_SIZE(session) * ctx->group.count,
            DEFAULT_PAGE_SIZE(session), ctrl_group[i]->page, DEFAULT_PAGE_SIZE(session));
        knl_securec_check(ret);

        if (ctrl_group[i]->is_dirty) {
            knl_panic(ctrl_group[i]->in_ckpt);
            ckpt_pop_page(session, ctx, ctrl_group[i]);
            if (ctx->consistent_lfn < ctrl_group[i]->lastest_lfn) {
                ctx->consistent_lfn = ctrl_group[i]->lastest_lfn;
            }
            ctrl_group[i]->is_marked = 1;
            CM_MFENCE;
            ctrl_group[i]->is_dirty = 0;
        }

        buf_unlatch(session, ctrl_group[i], CT_FALSE);

        ctx->group.items[ctx->group.count].ctrl = ctrl_group[i];
        ctx->group.items[ctx->group.count].buf_id = ctx->group.count;
        ctx->group.items[ctx->group.count].need_punch = CT_FALSE;

        if (ckpt_encrypt(session, ctx) != CT_SUCCESS) {
            for (j = i + 1; j < PAGE_GROUP_COUNT; j++) {
                buf_unlatch(session, ctrl_group[j], CT_FALSE);
            }
            return CT_ERROR;
        }
        if (ckpt_checksum(session, ctx) != CT_SUCCESS) {
            for (j = i + 1; j < PAGE_GROUP_COUNT; j++) {
                buf_unlatch(session, ctrl_group[j], CT_FALSE);
            }
            return CT_ERROR;
        }

        ctx->group.count++;
    }

    return CT_SUCCESS;
}

status_t ckpt_clean_prepare_normal(knl_session_t *session, ckpt_context_t *ctx, buf_ctrl_t *shift)
{
    if (!ckpt_try_latch_ctrl(session, shift)) {
        return CT_SUCCESS; // continue the next
    }

    if (DB_IS_CLUSTER(session)) {
        if (shift->is_edp) {
            CT_LOG_DEBUG_INF("[CKPT]checkpoint find edp [%u-%u], count(%d)", shift->page_id.file, shift->page_id.page,
                             ctx->edp_group.count);
            knl_panic(DCS_BUF_CTRL_NOT_OWNER(session, shift));
            buf_unlatch(session, shift, CT_FALSE);
            (void)(dtc_add_to_edp_group(session, &ctx->edp_group, CT_CKPT_GROUP_SIZE(session), shift->page_id,
                                        shift->page->lsn));
            return CT_SUCCESS;
        }

        if (shift->in_ckpt == CT_FALSE) {
            buf_unlatch(session, shift, CT_FALSE);
            return CT_SUCCESS;
        }

        knl_panic(DCS_BUF_CTRL_IS_OWNER(session, shift));
        if (shift->is_remote_dirty && !dtc_add_to_edp_group(session, &ctx->remote_edp_clean_group, CT_CKPT_GROUP_SIZE(session),
                                                            shift->page_id, shift->page->lsn)) {
            buf_unlatch(session, shift, CT_FALSE);
            return CT_SUCCESS;
        }
    }

    knl_panic(!shift->is_marked);
    knl_panic(shift->in_ckpt);

    knl_panic_log(IS_SAME_PAGID(shift->page_id, AS_PAGID(shift->page->id)),
        "shift's page_id and shift page's id are not same, panic info: page_id %u-%u type %u, "
        "page id %u-%u type %u", shift->page_id.file, shift->page_id.page,
        shift->page->type, AS_PAGID(shift->page->id).file,
        AS_PAGID(shift->page->id).page, shift->page->type);

    /* copy page from buffer to ckpt group */
    errno_t ret = memcpy_sp(ctx->group.buf + DEFAULT_PAGE_SIZE(session) * ctx->group.count,
        DEFAULT_PAGE_SIZE(session), shift->page, DEFAULT_PAGE_SIZE(session));
    knl_securec_check(ret);
    
    ckpt_pop_page(session, ctx, shift);
    
    if (ctx->consistent_lfn < shift->lastest_lfn) {
        ctx->consistent_lfn = shift->lastest_lfn;
    }

    shift->is_marked = 1;
    CM_MFENCE;
    shift->is_dirty = 0;
    shift->is_remote_dirty = 0;
    buf_unlatch(session, shift, CT_FALSE);

    ctx->group.items[ctx->group.count].ctrl = shift;
    ctx->group.items[ctx->group.count].buf_id = ctx->group.count;
    ctx->group.items[ctx->group.count].need_punch = CT_FALSE;

    if (ckpt_encrypt(session, ctx) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (ckpt_checksum(session, ctx) != CT_SUCCESS) {
        return CT_ERROR;
    }
    ckpt_put_to_part_group(session, ctx, shift);
    ctx->group.count++;
    return CT_SUCCESS;
}

/*
 * prepare pages to be cleaned
 * 1.search dirty page from write list of buffer set and copy to ckpt group
 * 2.stash dirty pages for releasing after flushing.
 */
static status_t ckpt_clean_prepare_pages(knl_session_t *session, ckpt_context_t *ctx, buf_set_t *set,
    buf_lru_list_t *page_list)
{
    ctx->has_compressed = CT_FALSE;
    buf_ctrl_t *ctrl = NULL;
    buf_ctrl_t *shift = NULL;
    if (ctx->clean_end != NULL) {
        ctrl = ctx->clean_end;
    } else {
        cm_spin_lock(&set->write_list.lock, NULL);
        ctrl = set->write_list.lru_last;
        cm_spin_unlock(&set->write_list.lock);
    }
    init_ckpt_part_group(session);
    ctx->group.count = 0;
    ctx->edp_group.count = 0;
    if (DB_IS_CLUSTER(session)) {
        dcs_ckpt_remote_edp_prepare(session, ctx);
        dcs_ckpt_clean_local_edp(session, ctx);
    }

    if (ctx->group.count >= CT_CKPT_GROUP_SIZE(session)) {
        return CT_SUCCESS;
    }

    while (ctrl != NULL) {
        shift = ctrl;
        ctrl = ctrl->prev;
    
        /* page has been expired */
        if (shift->bucket_id == CT_INVALID_ID32) {
            buf_stash_marked_page(set, page_list, shift);
            continue;
        }
        /* page has alreay add to group by dcs_ckpt_remote_edp_prepare */
        if (DB_IS_CLUSTER(session) && shift->is_marked) {
            continue;
        }

        /* page has already been flushed by checkpoint.
         * We need not hold lock to the ctrl when tesing dirty, since there is no harm
         * if it is set to dirty by others again after we get a not-dirty result.
         */
        if (!shift->is_dirty) {
            buf_stash_marked_page(set, page_list, shift);
            continue;
        }

        /* because page clean doesn't modify batch_end, therefore we skip ctrl which equals batch_end,
         * otherwise checkpoint full will not end */
        if (shift == ctx->batch_end) {
            buf_stash_marked_page(set, page_list, shift);
            continue;
        }
    
        status_t status;
        if (page_compress(session, shift->page_id)) {
            status = ckpt_clean_prepare_compress(session, ctx, shift);
        } else {
            status = ckpt_clean_prepare_normal(session, ctx, shift);
        }
        if (status != CT_SUCCESS) {
            return CT_ERROR;
        }

        buf_stash_marked_page(set, page_list, shift);

        if (ctx->group.count >= CT_CKPT_GROUP_SIZE(session) || ctx->edp_group.count >= CT_CKPT_GROUP_SIZE(session) ||
            ctx->remote_edp_clean_group.count >= CT_CKPT_GROUP_SIZE(session)) {
            ctx->clean_end = ctrl;
            return CT_SUCCESS;
        }
    }

    ctx->clean_end = NULL;
    return CT_SUCCESS;
}

/*
 * clean dirty page on write list of given buffer set.
 * 1.only flush a part of dirty page to release clean page of other buffer set.
 * 2.need to flush one more time because of ckpt group size limitation.
 */
static status_t ckpt_clean_single_set(knl_session_t *session, ckpt_context_t *ckpt_ctx, buf_set_t *set)
{
    buf_lru_list_t page_list;
    int64 clean_cnt = (int64)(set->write_list.count * CKPT_PAGE_CLEAN_RATIO(session));
    ckpt_ctx->clean_end = NULL;

    for (;;) {
        page_list = g_init_list_t;
        if (ckpt_clean_prepare_pages(session, ckpt_ctx, set, &page_list) != CT_SUCCESS) {
            return CT_ERROR;
        }

        dcs_notify_owner_for_ckpt(session, ckpt_ctx);

        if (ckpt_ctx->timed_task == CKPT_MODE_IDLE) {
            ckpt_ctx->stat.flush_pages[CKPT_TRIGGER_CLEAN] += ckpt_ctx->group.count;
        } else {
            ckpt_ctx->stat.flush_pages[CKPT_TIMED_CLEAN] += ckpt_ctx->group.count;
        }

        if (ckpt_ctx->group.count == 0) {
            dcs_clean_edp(session, ckpt_ctx);
            buf_reset_cleaned_pages(set, &page_list);
            return CT_SUCCESS;
        }

        if (ckpt_flush_prepare(session, ckpt_ctx) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (ckpt_flush_pages(session) != CT_SUCCESS) {
            CM_ABORT(0, "[CKPT] ABORT INFO: flush page failed when clean page.");
        }

        dcs_clean_edp(session, ckpt_ctx);
        buf_reset_cleaned_pages(set, &page_list);

        clean_cnt -= ckpt_ctx->group.count;
        ckpt_ctx->group.count = 0;
        ckpt_ctx->dw_ckpt_start = ckpt_ctx->dw_ckpt_end;
        dtc_my_ctrl(session)->dw_start = ckpt_ctx->dw_ckpt_end;

        if (dtc_save_ctrl(session, session->kernel->id) != CT_SUCCESS) {
            KNL_SESSION_CLEAR_THREADID(session);
            CM_ABORT(0, "[CKPT] ABORT INFO: save core control file failed when perform checkpoint");
        }

        /* only clean a part of pages when generate by trigger */
        if (clean_cnt <= 0 || ckpt_ctx->clean_end == NULL) {
            return CT_SUCCESS;
        }
    }
    return CT_SUCCESS;
}

static inline void ckpt_bitmap_set(uint8 *bitmap, uint8 num)
{
    uint8 position;
    position = (uint8)1 << (num % CKPT_BITS_PER_BYTE);

    bitmap[num / CKPT_BITS_PER_BYTE] |= position;
}

static inline void ckpt_bitmap_clear(uint8 *bitmap, uint8 num)
{
    uint8 position;
    position = ~((uint8)1 << (num % CKPT_BITS_PER_BYTE));

    bitmap[num / CKPT_BITS_PER_BYTE] &= position;
}

static inline bool32 ckpt_bitmap_exist(uint8 *bitmap, uint8 num)
{
    uint8 position;
    position = (uint8)1 << (num % CKPT_BITS_PER_BYTE);
    position = bitmap[num / CKPT_BITS_PER_BYTE] & position;

    return 0 != position;
}

status_t ckpt_clean_prepare_pages_all_set(knl_session_t *session, ckpt_context_t *ctx, buf_lru_list_t *page_list,
    ckpt_clean_ctx_t *page_clean_ctx)
{
    ctx->has_compressed = CT_FALSE;
    buf_context_t *buf_ctx = &session->kernel->buf_ctx;
    buf_ctrl_t *shift = NULL;
    ctx->group.count = 0;
    ctx->edp_group.count = 0;
    init_ckpt_part_group(session);
    if (DB_IS_CLUSTER(session)) {
        dcs_ckpt_remote_edp_prepare(session, ctx);
        dcs_ckpt_clean_local_edp(session, ctx);
    }

    if (ctx->group.count >= CT_CKPT_GROUP_SIZE(session)) {
        return CT_SUCCESS;
    }

    uint32 index = page_clean_ctx->next_index;
    while (memcmp(page_clean_ctx->bitmap, g_page_clean_finish_flag, PAGE_CLEAN_MAX_BYTES) != 0) {
        index = page_clean_ctx->next_index;
        page_clean_ctx->next_index = (index + 1) % buf_ctx->buf_set_count;
        if (!ckpt_bitmap_exist(page_clean_ctx->bitmap, index)) {
            continue;
        }
        shift = page_clean_ctx->ctrl[index];
        if (shift == NULL) {
            ckpt_bitmap_clear(page_clean_ctx->bitmap, index);
            continue;
        }
        page_clean_ctx->ctrl[index] = shift->prev;
        page_clean_ctx->clean_count[index] -= 1;
        if (page_clean_ctx->clean_count[index] == 0) {
            ckpt_bitmap_clear(page_clean_ctx->bitmap, index);
        }
        /* page has been expired */
        if (shift->bucket_id == CT_INVALID_ID32) {
            buf_stash_marked_page(&buf_ctx->buf_set[index], page_list, shift);
            continue;
        }

        /* page has alreay add to group by dcs_ckpt_remote_edp_prepare */
        if (DB_IS_CLUSTER(session) && shift->is_marked) {
            continue;
        }
        /* page has already been flushed by checkpoint.
         * We need not hold lock to the ctrl when tesing dirty, since there is no harm
         * if it is set to dirty by others again after we get a not-dirty result.
         */
        if (!shift->is_dirty) {
            buf_stash_marked_page(&buf_ctx->buf_set[index], page_list, shift);
            continue;
        }

        /* because page clean doesn't modify batch_end, therefore we skip ctrl which equals batch_end,
         * otherwise checkpoint full will not end */
        if (shift == ctx->batch_end) {
            buf_stash_marked_page(&buf_ctx->buf_set[index], page_list, shift);
            continue;
        }

        status_t status;
        if (page_compress(session, shift->page_id)) {
            status = ckpt_clean_prepare_compress(session, ctx, shift);
        } else {
            status = ckpt_clean_prepare_normal(session, ctx, shift);
        }
        if (status != CT_SUCCESS) {
            return CT_ERROR;
        }

        buf_stash_marked_page(&buf_ctx->buf_set[index], page_list, shift);
        if (ctx->group.count >= CT_CKPT_GROUP_SIZE(session) || ctx->edp_group.count >= CT_CKPT_GROUP_SIZE(session) ||
            ctx->remote_edp_clean_group.count >= CT_CKPT_GROUP_SIZE(session)) {
            return CT_SUCCESS;
        }
    }
    return CT_SUCCESS;
}

void ckpt_clean_prepare_buf_list(buf_context_t *buf_ctx, ckpt_clean_ctx_t *page_clean_ctx, double clean_ratio)
{
    for (uint32 i = 0; i < buf_ctx->buf_set_count; i++) {
        page_clean_ctx->clean_count[i] = buf_ctx->buf_set[i].write_list.count * clean_ratio;
        cm_spin_lock(&buf_ctx->buf_set[i].write_list.lock, NULL);
        page_clean_ctx->ctrl[i] = buf_ctx->buf_set[i].write_list.lru_last;
        cm_spin_unlock(&buf_ctx->buf_set[i].write_list.lock);
        ckpt_bitmap_set(page_clean_ctx->bitmap, i);
    }
}

/*
 * clean dirty page on write list of all buffer set.
 * 1.only flush a part of dirty page to release clean page of buffer set.
 * 2.need to flush one more time because of ckpt group size limitation.
 * 3.when flush once will get page from all off the buffer set
 */
status_t ckpt_clean_all_set(knl_session_t *session)
{
    buf_context_t *buf_ctx = &session->kernel->buf_ctx;
    ckpt_context_t *ckpt_ctx = &session->kernel->ckpt_ctx;
    ckpt_clean_ctx_t page_clean_ctx = {0};
    ckpt_clean_prepare_buf_list(buf_ctx, &page_clean_ctx, CKPT_PAGE_CLEAN_RATIO(session));
    buf_lru_list_t page_list;
    for (;;) {
        page_list = g_init_list_t;
        if (ckpt_clean_prepare_pages_all_set(session, ckpt_ctx, &page_list, &page_clean_ctx) != CT_SUCCESS) {
            return CT_ERROR;
        }

        dcs_notify_owner_for_ckpt(session, ckpt_ctx);

        if (ckpt_ctx->timed_task == CKPT_MODE_IDLE) {
            ckpt_ctx->stat.flush_pages[CKPT_TRIGGER_CLEAN] += ckpt_ctx->group.count;
        } else {
            ckpt_ctx->stat.flush_pages[CKPT_TIMED_CLEAN] += ckpt_ctx->group.count;
        }

        if (ckpt_ctx->group.count == 0) {
            dcs_clean_edp(session, ckpt_ctx);
            buf_reset_cleaned_pages_all_bufset(buf_ctx, &page_list);
            return CT_SUCCESS;
        }

        if (ckpt_flush_prepare(session, ckpt_ctx) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (ckpt_flush_pages(session) != CT_SUCCESS) {
            CM_ABORT(0, "[CKPT] ABORT INFO: flush page failed when clean page.");
        }

        dcs_clean_edp(session, ckpt_ctx);
        buf_reset_cleaned_pages_all_bufset(buf_ctx, &page_list);

        ckpt_ctx->group.count = 0;
        ckpt_ctx->dw_ckpt_start = ckpt_ctx->dw_ckpt_end;
        dtc_my_ctrl(session)->dw_start = ckpt_ctx->dw_ckpt_end;

        if (dtc_save_ctrl(session, session->kernel->id) != CT_SUCCESS) {
            KNL_SESSION_CLEAR_THREADID(session);
            CM_ABORT(0, "[CKPT] ABORT INFO: save core control file failed when perform checkpoint");
        }

        /* only clean a part of pages when generate by trigger */
        if (memcmp(page_clean_ctx.bitmap, g_page_clean_finish_flag, PAGE_CLEAN_MAX_BYTES) == 0) {
            return CT_SUCCESS;
        }
    }
    return CT_SUCCESS;
}

/*
 * clean dirty page on buffer write list of each buffer set
 */
static void ckpt_page_clean(knl_session_t *session)
{
    buf_context_t *buf_ctx = &session->kernel->buf_ctx;
    ckpt_context_t *ckpt_ctx = &session->kernel->ckpt_ctx;
    page_clean_t clean_mode = session->kernel->attr.page_clean_mode;
    if (!DB_IS_PRIMARY(&session->kernel->db) && rc_is_master() == CT_FALSE) {
        return;
    }

    if (clean_mode == PAGE_CLEAN_MODE_ALLSET) {
        ckpt_block_and_wait_enable(&session->kernel->ckpt_ctx);
        if (ckpt_clean_all_set(session) != CT_SUCCESS) {
            KNL_SESSION_CLEAR_THREADID(session);
            CM_ABORT(0, "[CKPT] ABORT INFO: flush page failed when clean dirty page");
        }
    } else if (clean_mode == PAGE_CLEAN_MODE_SINGLESET) {
        for (uint32 i = 0; i < buf_ctx->buf_set_count; i++) {
            ckpt_block_and_wait_enable(&session->kernel->ckpt_ctx);

            if (ckpt_clean_single_set(session, ckpt_ctx, &buf_ctx->buf_set[i]) != CT_SUCCESS) {
                KNL_SESSION_CLEAR_THREADID(session);
                CM_ABORT(0, "[CKPT] ABORT INFO: flush page failed when clean dirty page");
            }
        }
    } else {
        CM_ABORT(0, "[CKPT] ABORT INFO: Not support this mode %d", session->kernel->attr.page_clean_mode);
    }
}

void ckpt_put_to_part_group(knl_session_t *session, ckpt_context_t *ctx, buf_ctrl_t *to_flush_ctrl)
{
    if (cm_dbs_is_enable_dbs() == CT_FALSE || cm_dbs_is_enable_batch_flush() == CT_FALSE) {
        return;
    }
    uint32 part_id = 0;
    (void)cm_cal_partid_by_pageid(to_flush_ctrl->page_id.page, DEFAULT_PAGE_SIZE(session), &part_id);
    uint32 index = ctx->ckpt_part_group[part_id].count;
    ctx->ckpt_part_group[part_id].count++;
    ctx->ckpt_part_group[part_id].item_index[index] = ctx->group.count;
}
