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
 * knl_rmon.c
 *
 *
 * IDENTIFICATION
 * src/kernel/daemon/knl_rmon.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_common_module.h"
#include "knl_rmon.h"
#include "cm_file.h"
#include "knl_context.h"

void rmon_init(knl_session_t *session)
{
    rmon_t *ctx = &session->kernel->rmon_ctx;
    errno_t ret;

    ret = memset_sp(ctx, sizeof(rmon_t), 0, sizeof(rmon_t));
    knl_securec_check(ret);

    ctx->epoll_fd = CT_INVALID_HANDLE;
    ctx->watch_fd = CT_INVALID_HANDLE;
    ctx->working = CT_FALSE;
}

static void rmon_notify_convert_to_readonly(knl_session_t *session)
{
    switch_ctrl_t *ctrl = &session->kernel->switch_ctrl;

    cm_spin_lock(&ctrl->lock, NULL);
    if (ctrl->request != SWITCH_REQ_NONE) {
        cm_spin_unlock(&ctrl->lock);
        return;
    }

    ctrl->is_rmon_set = CT_TRUE;
    ctrl->keep_sid = session->id;
    ctrl->request = SWITCH_REQ_READONLY;
    cm_spin_unlock(&ctrl->lock);

    CT_LOG_RUN_INF("[DB] notify server to set %s", "READONLY");
}

/*
 * check whether exists file that has been removed or moved.
 * the only thing we know is watch descriptor, so we need to search both datafiles and
 * logfiles to find out which file has gone.
 */
static void rmon_watch_files(knl_session_t *session)
{
    rmon_t *ctx = &session->kernel->rmon_ctx;
    int32 wd;
    uint32 i;
    datafile_t *df = NULL;
    log_file_t *logfile = NULL;
    logfile_set_t *logfile_set = MY_LOGFILE_SET(session);

    /* catch inotify event */
    if (cm_watch_file_event(ctx->watch_fd, ctx->epoll_fd, &wd) != CT_SUCCESS) {
        return;
    }

    /* search datafile */
    for (i = 0; i < CT_MAX_DATA_FILES; i++) {
        df = DATAFILE_GET(session, i);
        if (!df->ctrl->used || df->wd != wd) {
            continue;
        }

        if (cm_access_device(df->ctrl->type, df->ctrl->name, R_OK | W_OK) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[RMON]: datafile %s has been removed, moved or modified on disk unexpectedly",
                           df->ctrl->name);
            CT_LOG_ALARM(WARN_FILEMONITOR, "'file-name':'%s'}", df->ctrl->name);

            DATAFILE_SET_ALARMED(df);
            if (db_save_datafile_ctrl(session, df->ctrl->id) != CT_SUCCESS) {
                CM_ABORT(0, "[SPACE] ABORT INFO: failed to save control file when set datafile flag");
            }

            rmon_notify_convert_to_readonly(session);
            return;
        }
    }

    /* search logfile */
    for (i = 0; i < logfile_set->logfile_hwm; i++) {
        logfile = &logfile_set->items[i];
        if (LOG_IS_DROPPED(logfile->ctrl->flg) || logfile->wd != wd) {
            continue;
        }

        if (cm_access_device(logfile->ctrl->type, logfile->ctrl->name, R_OK | W_OK) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[RMON]: logfile %s has been removed, moved or modified on disk unexpectedly",
                           logfile->ctrl->name);
            CT_LOG_ALARM(WARN_FILEMONITOR, "'file-name':'%s'}", logfile->ctrl->name);

            LOG_SET_ALARMED(logfile->ctrl->flg);
            if (db_save_log_ctrl(session, (uint32)logfile->ctrl->file_id, logfile->ctrl->node_id) != CT_SUCCESS) {
                CM_ABORT(0, "[DB] ABORT INFO: failed to save whole control file when set logfile flag");
            }

            rmon_notify_convert_to_readonly(session);
            return;
        }
    }
}

static void rmon_try_clean_df_alarm(knl_session_t *session, datafile_t *df)
{
    if (!DATAFILE_IS_ALARMED(df) || cm_access_file(df->ctrl->name, W_OK | R_OK) != CT_SUCCESS) {
        return;
    }

    CT_LOG_ALARM_RECOVER(WARN_FILEMONITOR, "'file-name':'%s'}", df->ctrl->name);
    DATAFILE_UNSET_ALARMED(df);

    if (db_save_datafile_ctrl(session, df->ctrl->id) != CT_SUCCESS) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save control file when set datafile flag");
    }
}

static void rmon_try_clean_log_alarm(knl_session_t *session, log_file_t *logfile)
{
    if (!LOG_IS_ALARMED(logfile->ctrl->flg) ||
        cm_access_device(logfile->ctrl->type, logfile->ctrl->name, W_OK | R_OK) != CT_SUCCESS) {
        return;
    }

    CT_LOG_ALARM_RECOVER(WARN_FILEMONITOR, "'file-name':'%s'}", logfile->ctrl->name);

    LOG_UNSET_ALARMED(logfile->ctrl->flg);
    if (db_save_log_ctrl(session, (uint32)logfile->ctrl->file_id, logfile->ctrl->node_id) != CT_SUCCESS) {
        CM_ABORT(0, "[DB] ABORT INFO: failed to save whole control file when set logfile flag");
    }
}

/*
 * intialize inotify to monitor file, adding datafiles and logfiles to monitor list
 */
void rmon_load(knl_session_t *session)
{
    rmon_t *rmon_ctx = NULL;
    datafile_t *df = NULL;
    log_file_t *logfile = NULL;
    uint32 i;
    logfile_set_t *logfile_set = MY_LOGFILE_SET(session);

    rmon_ctx = &session->kernel->rmon_ctx;

    /* monitor datafiles */
    for (i = 0; i < CT_MAX_DATA_FILES; i++) {
        df = DATAFILE_GET(session, i);
        if (!df->ctrl->used || !DATAFILE_IS_ONLINE(df)) {
            continue;
        }

        rmon_try_clean_df_alarm(session, df);

        if (cm_add_device_watch(df->ctrl->type, rmon_ctx->watch_fd, df->ctrl->name, &df->wd) != CT_SUCCESS) {
            CT_LOG_RUN_WAR("[RMON]: failed to add monitor of datafile %s", df->ctrl->name);
        }
    }

    /* monitor logfiles */
    for (i = 0; i < logfile_set->logfile_hwm; i++) {
        logfile = &logfile_set->items[i];
        if (LOG_IS_DROPPED(logfile->ctrl->flg)) {
            continue;
        }

        rmon_try_clean_log_alarm(session, logfile);

        if (cm_add_device_watch(df->ctrl->type, rmon_ctx->watch_fd, logfile->ctrl->name, &logfile->wd) != CT_SUCCESS) {
            CT_LOG_RUN_WAR("[RMON]: failed to add monitor of logfile %s", logfile->ctrl->name);
        }
    }
    CT_LOG_RUN_INF("[RMON]: rmon load finish.");
}

static inline void rmon_file_watch_close(knl_session_t *session)
{
    rmon_t *ctx = &session->kernel->rmon_ctx;

    cm_close_file(ctx->epoll_fd);
    cm_close_file(ctx->watch_fd);
}

/*
 * free extents on space free list back to bitmap
 */
void rmon_free_spc_extents(knl_session_t *session, rmon_t *rmon_ctx)
{
    switch_ctrl_t *ctrl = &session->kernel->switch_ctrl;
    space_t *space = NULL;
    space_head_t *head = NULL;

    for (uint32 i = 0; i < CT_MAX_SPACES; i++) {
        space = SPACE_GET(session, i);
        if (!space->ctrl->used || !SPACE_IS_ONLINE(space) || !SPACE_IS_BITMAPMANAGED(space)) {
            continue;
        }

        head = SPACE_HEAD_RESIDENT(session, space);
        if (head == NULL || head->free_extents.count == 0) {
            continue;
        }

        db_set_with_switchctrl_lock(ctrl, &rmon_ctx->working);
        if (!rmon_ctx->working) {
            return;
        }

        while (head->free_extents.count != 0) {
            /* space has been dropped when return error */
            if (spc_free_extent_from_list(session, space, NULL) != CT_SUCCESS) {
                break;
            }
            head = SPACE_HEAD_RESIDENT(session, space);
        }
        rmon_ctx->working = CT_FALSE;
    }
}

/* move cold page from main list to aux list periodically */
void rmon_monitor_buffer_set(knl_session_t *session, uint32 count)
{
    buf_context_t *ctx = &session->kernel->buf_ctx;
    buf_set_t *set = NULL;

    for (uint32 i = 0; i < ctx->buf_set_count; i++) {
        set = &ctx->buf_set[i];

        if (count % RMON_MONITOR_BUFFER_CLOCK == 0 || BUF_NEED_BALANCE(set)) {
            buf_balance_set_list(set);
        }
    }
}

static void rmon_delay_clean_segments(knl_session_t *session, rmon_t *rmon_ctx)
{
    switch_ctrl_t *ctrl = &session->kernel->switch_ctrl;

    cm_spin_lock(&rmon_ctx->mark_mutex, NULL);
    if (rmon_ctx->delay_clean_segments) {
        rmon_ctx->delay_clean_segments = CT_FALSE;
        cm_spin_unlock(&rmon_ctx->mark_mutex);

        db_set_with_switchctrl_lock(ctrl, &rmon_ctx->working);
        if (!rmon_ctx->working) {
            return;
        }
        db_delay_clean_segments(session);
        rmon_ctx->working = CT_FALSE;
    } else {
        cm_spin_unlock(&rmon_ctx->mark_mutex);
    }
}

/*
 * resource monitor thread including following works:
 * 1.monitor datafiles and logfiles by inotify
 * 2.monitor free list on bitmap space and return to map if possible
 * 3.move cold page on main list of buffer set to aux list
 */
void rmon_proc(thread_t *thread)
{
    knl_session_t *session = (knl_session_t *)thread->argument;
    rmon_t *rmon_ctx = &session->kernel->rmon_ctx;
    switch_ctrl_t *ctrl = &session->kernel->switch_ctrl;
    uint32 count = 0;

    cm_set_thread_name("rmon");
    CT_LOG_RUN_INF("rmon thread started");
    KNL_SESSION_SET_CURR_THREADID(session, cm_get_current_thread_id());

    cm_watch_file_init(&rmon_ctx->watch_fd, &rmon_ctx->epoll_fd);

    while (!thread->closed) {
        rmon_monitor_buffer_set(session, count);

        if (session->kernel->db.status != DB_STATUS_OPEN) {
            session->status = SESSION_INACTIVE;
            count++;
            cm_sleep(200);
            continue;
        }

        if (DB_IS_MAINTENANCE(session) || DB_IS_READONLY(session) || ctrl->request != SWITCH_REQ_NONE) {
            session->status = SESSION_INACTIVE;
            count++;
            cm_sleep(200);
            continue;
        }

        if (session->status == SESSION_INACTIVE) {
            session->status = SESSION_ACTIVE;
        }

        rmon_watch_files(session);
        rmon_free_spc_extents(session, rmon_ctx);
        rmon_delay_clean_segments(session, rmon_ctx);

        count++;
        cm_sleep(200);
    }

    rmon_file_watch_close(session);
    CT_LOG_RUN_INF("rmon thread closed");
    KNL_SESSION_CLEAR_THREADID(session);
}

void rmon_close(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    rmon_t *ctx = &kernel->rmon_ctx;
    cm_close_thread(&ctx->thread);
}

void rmon_clean_alarm(knl_session_t *session)
{
    datafile_t *df = NULL;
    log_file_t *logfile = NULL;
    uint32 i;
    logfile_set_t *logfile_set = MY_LOGFILE_SET(session);

    for (i = 0; i < CT_MAX_DATA_FILES; i++) {
        df = DATAFILE_GET(session, i);
        if (!df->ctrl->used || !DATAFILE_IS_ONLINE(df)) {
            continue;
        }
        rmon_try_clean_df_alarm(session, df);
    }

    for (i = 0; i < logfile_set->logfile_hwm; i++) {
        logfile = &logfile_set->items[i];
        if (LOG_IS_DROPPED(logfile->ctrl->flg)) {
            continue;
        }
        rmon_try_clean_log_alarm(session, logfile);
    }
}

status_t rmon_start(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    if (cm_create_thread(rmon_proc, 0, kernel->sessions[SESSION_ID_RMON], &kernel->rmon_ctx.thread) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

void job_close(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    job_t *ctx = &kernel->job_ctx;

    cm_close_thread(&ctx->thread);
}

void synctimer_close(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    synctimer_t *ctx = &kernel->synctimer_ctx;

    if (ctx->thread != NULL) {
        cm_close_thread(ctx->thread);
    }
}
