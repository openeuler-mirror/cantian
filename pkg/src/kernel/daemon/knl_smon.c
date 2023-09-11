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
 * knl_smon.c
 *
 *
 * IDENTIFICATION
 * src/kernel/daemon/knl_smon.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_smon.h"
#include "knl_context.h"
#include "pcr_heap.h"
#include "pcr_btree.h"
#include "knl_table.h"
#include "knl_dlock_stack.h"
#include "index_common.h"
#include "srv_instance.h"
#include "dtc_dls.h"
#include "dtc_dmon.h"
#include "dtc_dc.h"
#include "dtc_smon.h"
#include "dtc_database.h"

static knl_dlock_stack_t g_dlock_stack;
static bool32 smon_check_itl_waits(knl_session_t *session, knl_session_t *start_session,
                                   bool32 record_sql);
static bool32 smon_check_lock_waits(knl_session_t *session, knl_session_t *se, bool32 record_sql);

#define MAX_UNDO_HIST 10
#define MIN_UNDO_RETENTION 3
#define AUTO_UNDO_RETENTION_CLOCK 1000
typedef struct st_knl_undo_hist {
    uint32 undo_hist[MAX_UNDO_HIST];
    uint32 last;
} knl_undo_hist;
static knl_undo_hist g_undo_hist;
static void smon_init_undo_hist(knl_session_t *session);
static void smon_set_undo_retention(knl_session_t *session);


/*
 * must init sql text first before get sql text
 */
void smon_sql_init(knl_session_t *session, text_t *sql_text)
{
    sql_text->str = (char *)(session->stack->buf + session->stack->heap_offset);
    sql_text->len = CM_ALIGN8(session->stack->push_offset - session->stack->heap_offset - GS_PUSH_RESERVE_SIZE);
}

static void smon_record_deadlock(knl_session_t *session, knl_session_t *dead_session)
{
    text_t sql_text;

    smon_sql_init(session, &sql_text);
    if (g_knl_callback.get_sql_text(dead_session->id, &sql_text) == GS_SUCCESS) {
        GS_LOG_TRACE("wait sql: %s \n", sql_text.str);
    }
}

void smon_record_deadlock_time()
{
    char date[GS_MAX_TIME_STRLEN] = {0};

    (void)cm_date2str(cm_now(), "yyyy-mm-dd hh24:mi:ss", date, GS_MAX_TIME_STRLEN);
    GS_LOG_TRACE("**************%s DEADLOCK DETECTED*****************", date);
    GS_LOG_TRACE("\nThe following deadlock is not a ZENITH error. \nIt is due to user error in the design of SQL.");
    GS_LOG_TRACE("The following information may aid in determining the deadlock : \n");
    GS_LOG_TRACE("----------------------WAIT INFORMATION---------------------\n");
}

/*
 * detect deadlock event
 * We use coloring algorithm to detect the deadlock ring by record the wsid
 * and current lsn of the detected session.
 * If deadlock founded, causing the session is dynamic and active, we need
 * to recheck all session in ring by checking the transaction it waiting for.
 * @param SMON session, wait marks, detecting session id.
 */
void smon_detect_dead_lock(knl_session_t *session, uint8 *wait_marks, uint16 id_input, bool32 record_sql)
{
    uint16 id = id_input;
    knl_session_t *current = NULL;
    uint64 *curr_lsn = NULL;
    uint16 *wait_sid = NULL;
    txn_snapshot_t snapshot;
    xid_t wait_xid;
    uint16 begin;
    uint32 count;
    errno_t ret;

    CM_SAVE_STACK(session->stack);
    curr_lsn = (uint64 *)cm_push(session->stack, GS_MAX_SESSIONS * sizeof(uint64));
    wait_sid = (uint16 *)cm_push(session->stack, GS_MAX_SESSIONS * sizeof(uint16));
    count = GS_MAX_SESSIONS * sizeof(uint16);
    ret = memset_sp(wait_sid, count, GS_INVALID_ID16, count);
    knl_securec_check(ret);

    while (id != GS_INVALID_ID16 && wait_sid[id] == GS_INVALID_ID16) {
        current = session->kernel->sessions[id];
        wait_sid[id] = knl_get_rm_sid(session, current->wrmid);
        curr_lsn[id] = current->curr_lsn;
        wait_marks[id] = 1;

        id = wait_sid[id];
    }

    // no deadlock was detected
    if (id == GS_INVALID_ID16) {
        CM_RESTORE_STACK(session->stack);
        return;
    }

    // suspended session should not be killed
    current = session->kernel->sessions[id];
    if (current->status == SESSION_INACTIVE) {
        wait_marks[id] = 0;
        CM_RESTORE_STACK(session->stack);
        return;
    }

    begin = id;

    for (;;) {
        if (wait_sid[id] != knl_get_rm_sid(session, current->wrmid) ||
            curr_lsn[id] != current->curr_lsn) {
            CM_RESTORE_STACK(session->stack);
            return;
        }

        wait_xid = current->wxid;
        if (wait_xid.value == GS_INVALID_ID64) {
            CM_RESTORE_STACK(session->stack);
            return;
        }

        tx_get_snapshot(session, wait_xid.xmap, &snapshot);
        if (snapshot.rmid != current->wrmid ||
            snapshot.xnum != current->wxid.xnum ||
            snapshot.status == (uint8)XACT_END) {
            CM_RESTORE_STACK(session->stack);
            return;
        }

        id = wait_sid[id];
        current = session->kernel->sessions[id];

        if (record_sql) {
            GS_LOG_TRACE("session id: %u, wait session: %u, wait rowid: %u-%u-%u",
                         current->id, knl_get_rm_sid(session, current->wrmid),
                         current->wrid.file, current->wrid.page, current->wrid.slot);
            smon_record_deadlock(session, current);
        }

        if (begin == id) {
            CM_RESTORE_STACK(session->stack);
            if (!record_sql) {
                smon_record_deadlock_time();
                GS_LOG_TRACE("[Transaction Deadlock]");
                smon_detect_dead_lock(session, wait_marks, id, GS_TRUE);
                GS_LOG_TRACE("-----------------END OF WAIT INFORMATION-----------------\n");
                current->dead_locked = GS_TRUE;
            }
            GS_LOG_RUN_ERR("found transaction deadlock in session %d", begin);
            return;
        }
    }
}

void smon_check_active_sessions(knl_session_t *session)
{
    uint32 i;
    knl_session_t *se = NULL;
    uint8 w_marks[GS_MAX_SESSIONS];
    uint32 max_sessions;
    errno_t ret;
    bool32 dead_lock = GS_FALSE;

    max_sessions = GS_MAX_SESSIONS;
    ret = memset_sp(w_marks, max_sessions, 0, max_sessions);
    knl_securec_check(ret);

    for (i = GS_SYS_SESSIONS; i < GS_MAX_SESSIONS; i++) {
        se = session->kernel->sessions[i];

        if (se == NULL || se->status != SESSION_ACTIVE || se->dtc_session_type == DTC_WORKER) {
            continue;
        }

        // The marked session is no longer detected
        if (se->wrmid != GS_INVALID_ID16 && w_marks[i] != 1) {
            if (session->kernel->attr.clustered) {
                dtc_smon_detect_dead_lock_in_cluster(session, w_marks, i, GS_FALSE);
            } else {
                smon_detect_dead_lock(session, w_marks, i, GS_FALSE);
            }
        } else if (!IS_INVALID_PAGID(se->wpid)) {
            if (session->kernel->attr.clustered) {
                dead_lock = dtc_smon_check_itl_waits_in_cluster(session, se, GS_FALSE);
            } else {
                dead_lock = smon_check_itl_waits(session, se, GS_FALSE);
            }
            if (dead_lock) {
                se->itl_dead_locked = GS_TRUE;
                GS_LOG_RUN_ERR("smon found itl deadlock in session(%u), page_id : %u-%u",
                               se->id, se->wpid.file, se->wpid.page);
                GS_LOG_ALARM(WARN_DEADLOCK, "'instance-name':'%s'}", se->kernel->instance_name);
            }
        } else if (se->wtid.is_locking) {
            if (session->kernel->attr.clustered) {
                dead_lock = dtc_smon_check_lock_waits_in_cluster(session, se, GS_FALSE);
            } else {
                dead_lock = smon_check_lock_waits(session, se, GS_FALSE);
            }
            if (dead_lock) {
                se->lock_dead_locked = GS_TRUE;
                GS_LOG_RUN_ERR("smon found table deadlock in session(%u)", se->id);
                GS_LOG_ALARM(WARN_DEADLOCK, "'instance-name':'%s'}", se->kernel->instance_name);
            }
        }
    }
}

/*
 * smon_set_min_scn :Calculate the minimum SCN
 * Detect the minimum SCN  of all active session. min SCN use for MVCC
 */
static void smon_set_min_scn(knl_session_t *session)
{
    g_knl_callback.set_min_scn(session);
}

static void smon_calculate_space_size(knl_session_t *session, space_t *space, uint64 *max_size, uint64 *used_pages)
{
    datafile_t *df = NULL;
    *max_size = 0;
    *used_pages = 0;

    for (uint32 j = 0; j < space->ctrl->file_hwm; j++) {
        if (space->ctrl->files[j] == GS_INVALID_ID32) {
            continue;
        }

        df = DATAFILE_GET(session, space->ctrl->files[j]);
        if (!DATAFILE_IS_ONLINE(df)) {
            continue;
        }

        /* calculate space max size by maxsize with autoextend on or size with autoextend off of each datafile */
        if (DATAFILE_IS_AUTO_EXTEND(df)) {
            *max_size += (uint64)df->ctrl->auto_extend_maxsize;
        } else {
            *max_size += (uint64)df->ctrl->size;
        }

        *used_pages += spc_get_df_used_pages(session, space, j);
    }

    /*
    * compared threshold size that calculated by space max size and threshold
    * with used size to decide whether throw alarm or not.
    */

    if (!SPACE_IS_BITMAPMANAGED(space)) {
        *used_pages -= SPACE_HEAD_RESIDENT(session, space)->free_extents.count * space->ctrl->extent_size;
    }
}

static void smon_check_undo_usage(knl_session_t *session, space_t *space, uint64 *used_pages, uint32 *usage_alarm_threshold, warn_name_t *warn_name)
{
    if (space->ctrl->id != dtc_my_ctrl(session)->undo_space &&
        space->ctrl->id != DB_CORE_CTRL(session)->temp_undo_space) {
        return;
    }

    uint64 segment_free_page_count = 0;
    undo_t *undo = NULL;
    for (uint32 vm_slot_index = 0; vm_slot_index < session->kernel->attr.undo_segments; vm_slot_index++) {
        undo = &session->kernel->undo_ctx.undos[vm_slot_index];
        if (IS_TEMP_SPACE(space)) {
            segment_free_page_count += undo->temp_free_page_list.count;
        } else {
            segment_free_page_count += undo->segment->page_list.count;
        }
    }
    if (*used_pages >= segment_free_page_count) {
        *used_pages -= segment_free_page_count;
    }
    
    *usage_alarm_threshold = session->kernel->attr.undo_usage_alarm_threshold;
    *warn_name = WARN_UNDO_USAGE;
}

static inline void smon_usage_alarm_log(knl_session_t *session, space_t *space, uint32 usage_alarm_threshold, warn_name_t warn_name)
{
#ifdef Z_SHARDING
    if (session->kernel->is_coordinator) {
        GS_LOG_ALARM_CN(warn_name, "'space-name':'%s', 'alarm-threshold':'%d'}",
            space->ctrl->name, usage_alarm_threshold);
        space->alarm_enabled = GS_FALSE;
        return;
    }
#endif

    GS_LOG_ALARM(warn_name, "'space-name':'%s', 'alarm-threshold':'%d'}", space->ctrl->name, usage_alarm_threshold);
    space->alarm_enabled = GS_FALSE;
}

static inline void smon_usage_recovery_log(knl_session_t *session, space_t *space, uint32 usage_alarm_threshold, warn_name_t warn_name)
{
#ifdef Z_SHARDING
        if (session->kernel->is_coordinator) {
            GS_LOG_ALARM_RECOVER_CN(warn_name, "'space-name':'%s', 'alarm-threshold':'%d'}",
                space->ctrl->name, usage_alarm_threshold);
            space->alarm_enabled = GS_TRUE;
            return;
        }
#endif

    GS_LOG_ALARM_RECOVER(warn_name, "'space-name':'%s', 'alarm-threshold':'%d'}",
        space->ctrl->name, usage_alarm_threshold);
    space->alarm_enabled = GS_TRUE;
}

/*
 * if usage of space is up to threshold, throw a alarm
 */
static void smon_check_space_usage(knl_session_t *session)
{
    return;  // todo: renable
    space_t *space = NULL;
    uint64 max_size;
    uint64 used_pages;
    uint64 threshold_size;

    for (uint32 i = 0; i < GS_MAX_SPACES; i++) {
        space = SPACE_GET(session, i);
        cm_spin_lock(&space->lock.lock, NULL);
        /* for undo tablespace, it is not necessary to check the usage status */
        if (!space->ctrl->used || !SPACE_IS_ONLINE(space)) {
            cm_spin_unlock(&space->lock.lock);
            continue;
        }

        smon_calculate_space_size(session, space, &max_size, &used_pages);

        warn_name_t warn_name = WARN_SPACEUSAGE;
        uint32 usage_alarm_threshold = session->kernel->attr.spc_usage_alarm_threshold;
        
        if (IS_UNDO_SPACE(space)) {
            if (session->kernel->attr.undo_usage_alarm_threshold == 0) {
                cm_spin_unlock(&space->lock.lock);
                continue;
            }
            smon_check_undo_usage(session, space, &used_pages, &usage_alarm_threshold, &warn_name);
        }

        threshold_size = max_size * usage_alarm_threshold / GS_PERCENT;
        if (used_pages * DEFAULT_PAGE_SIZE(session) >= threshold_size) {
            if (space->alarm_enabled) {
                smon_usage_alarm_log(session, space, usage_alarm_threshold, warn_name);
            }
        } else {
            if (!space->alarm_enabled) {
                smon_usage_recovery_log(session, space, usage_alarm_threshold, warn_name);
            }
        }

        cm_spin_unlock(&space->lock.lock);
    }
}

static void smon_set_dc_completed(knl_session_t *session)
{
    bool32 is_found = GS_FALSE;

    if (!session->kernel->dc_ctx.completed && !DB_IN_BG_ROLLBACK(session)) {
        GS_LOG_RUN_INF("set dc completed in clean_all_shadow_indexes.");
        session->kernel->set_dc_complete_status = DDL_PART_DISABLE_CLEAN_SHADOW_IDX;
        (void)db_clean_all_shadow_indexes(session);

        GS_LOG_RUN_INF("set dc completed in purge_garbage_segment.");
        session->kernel->set_dc_complete_status = DDL_PART_DISABLE_PURGE_GARBAGE_SEG;
        (void)db_purge_garbage_segment(session);

        GS_LOG_RUN_INF("set dc completed in clean_garbage_partition.");
        session->kernel->set_dc_complete_status = DDL_PART_DISABLE_CLEAN_GARBAGE_PART;
        (void)db_clean_garbage_partition(session);  // clean those partitions that with flag = 1

        GS_LOG_RUN_INF("set dc completed in clean_garbage_subpartition.");
        session->kernel->set_dc_complete_status = DDL_PART_DISABLE_CLEAN_GARBAGE_SUBPART;
        (void)db_clean_garbage_subpartition(session);

        GS_LOG_RUN_INF("set dc completed in delete_ptrans_remained.");
        session->kernel->set_dc_complete_status = DDL_PART_DISABLE_DEL_PENDING_TRANS;
        (void)db_delete_ptrans_remained(session, NULL, NULL, &is_found);

        GS_LOG_RUN_INF("set dc completed when clean cluster ddl ops.");
        (void)db_clean_ddl_op_garbage(session);

        session->kernel->dc_ctx.completed = GS_TRUE;
        GS_LOG_RUN_INF("set dc completed.");
        session->kernel->set_dc_complete_status = DDL_ENABLE;
    }
}

static void smon_check_nologging(knl_session_t *session, smon_t *ctx)
{
    bool32 has_nolog = GS_FALSE;
    if (knl_database_has_nolog_object(session, &has_nolog) != GS_SUCCESS) {
        return;
    }

    if (has_nolog && !ctx->nolog_alarm) {
        GS_LOG_ALARM(WARN_NOLOG_OBJ, "'instance-name':'%s'}", session->kernel->instance_name);
        ctx->nolog_alarm = GS_TRUE;
    }

    if (!has_nolog && ctx->nolog_alarm) {
        GS_LOG_ALARM_RECOVER(WARN_NOLOG_OBJ, "'instance-name':'%s'}", session->kernel->instance_name);
        ctx->nolog_alarm = GS_FALSE;
    }
}

static void undo_try_shrink_inactive(knl_session_t *session, smon_t *ctx, switch_ctrl_t *ctrl)
{
    db_set_with_switchctrl_lock(ctrl, &ctx->undo_shrinking);
    if (ctx->undo_shrinking) {
        undo_shrink_inactive_segments(session);
        ctx->shrink_inactive = GS_FALSE;
        ctx->undo_shrinking = GS_FALSE;
    }

    return;
}

static void smon_timed_task(knl_session_t *session, uint32 count, smon_t *ctx, switch_ctrl_t *ctrl)
{
    // dead lock detect per [1,10,100,1000]ms, 1s as default
    uint32 deadlock_detect_interval = g_instance->kernel.attr.deadlock_detect_interval;
    if (count % deadlock_detect_interval == 0) {
        smon_check_active_sessions(session);
    }
    
    if (count % SMON_CHECK_SPC_USAGE_CLOCK == 0 && session->kernel->attr.spc_usage_alarm_threshold) {
        smon_check_space_usage(session);
    }

    if (count % AUTO_UNDO_RETENTION_CLOCK == 0 && session->kernel->attr.auto_undo_retention) {
        // undo retention per 1s
        smon_set_undo_retention(session);
    }
    
    if (count % SMON_UNDO_SHRINK_CLOCK == 0 && session->kernel->attr.undo_auto_shrink) {
        // undo shrink per minute
        db_set_with_switchctrl_lock(ctrl, &ctx->undo_shrinking);
        if (ctx->undo_shrinking) {
            undo_shrink_segments(session);
            ctx->undo_shrinking = GS_FALSE;
        }
    }
    
    if (count % SMON_INDEX_RECY_CLOCK == 0) {
        // recycle index root copy every 100 second
        btree_release_root_copy(session);
    }
    
    if (count % SMON_CHECK_XA_CLOCK == 0) {
        g_knl_callback.shrink_xa_rms(session, GS_FALSE);
    }

    if (count % SMON_CHECK_NOLOGGING == 0) {
        smon_check_nologging(session, ctx);
    }

    if (count % UNDO_STAT_SNAP_INTERVAL == 0) {
        undo_timed_task(session);
    }

    if (ctx->shrink_inactive) {
        undo_try_shrink_inactive(session, ctx, ctrl);
    }
}

static inline void smon_undo_stat_init(knl_handle_t session)
{
    knl_session_t *se = (knl_session_t *)session;
    undo_context_t *ctx = &se->kernel->undo_ctx;

    ctx->stat_cnt = 0;
    ctx->longest_sql_time = 0;
    return;
}

void smon_proc(thread_t *thread)
{
    knl_session_t *session = (knl_session_t *)thread->argument;
    smon_t *ctx = &session->kernel->smon_ctx;
    switch_ctrl_t *ctrl = &session->kernel->switch_ctrl;
    uint32 count = 0;

    cm_set_thread_name("smon");
    GS_LOG_RUN_INF("smon thread started");
    KNL_SESSION_SET_CURR_THREADID(session, cm_get_current_thread_id());

    ctx->undo_shrinking = GS_FALSE;
    ctx->shrink_inactive = GS_FALSE;
    smon_init_undo_hist(session);
    if (dtc_smon_init_lock_stack(session) != GS_SUCCESS) {
        knl_panic(0);
        return;
    }

    smon_undo_stat_init(session);
    while (!thread->closed) {
        if (session->kernel->db.status != DB_STATUS_OPEN) {
            session->status = SESSION_INACTIVE;
            cm_sleep(200);
            continue;
        }

        if (DB_IS_MAINTENANCE(session) || DB_IS_READONLY(session) || ctrl->request != SWITCH_REQ_NONE) {
            session->status = SESSION_INACTIVE;
            cm_sleep(100);
            continue;
        }

        if (session->status == SESSION_INACTIVE) {
            session->status = SESSION_ACTIVE;
        }

        smon_set_dc_completed(session);
        smon_set_min_scn(session);
        smon_timed_task(session, count, ctx, ctrl);

        // dead lock detect per [1,10,100,1000]ms, 1s as default
        uint32 deadlock_detect_interval = g_instance->kernel.attr.deadlock_detect_interval;

        // sleep time range [1,10,100]ms, 100ms as default
        uint32 smon_sleep_time = MIN(deadlock_detect_interval, 100);
        if (count % smon_sleep_time != 0) {
            count = 0;
        }
        cm_sleep(smon_sleep_time);
        count += smon_sleep_time;
    }

    dtc_smon_uninit_lock_stack(session);
    GS_LOG_RUN_INF("smon thread closed");
    KNL_SESSION_CLEAR_THREADID(session);
}

void smon_close(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    smon_t *ctx = &kernel->smon_ctx;
    cm_close_thread(&ctx->thread);
}

knl_session_t *get_xid_session(knl_session_t *session, xid_t xid)
{
    txn_snapshot_t snapshot;
    uint16 sid;

    tx_get_snapshot(session, xid.xmap, &snapshot);
    if (snapshot.xnum != xid.xnum || snapshot.status == (uint8)XACT_END) {
        return NULL;
    }

    sid = knl_get_rm_sid(session, snapshot.rmid);

    return (sid != GS_INVALID_ID16) ? session->kernel->sessions[sid] : NULL;
}

static bool32 smon_push_itl(knl_session_t *start_session, itl_t *item, knl_dlock_stack_t *stack_ptr,
                            uint8 *w_marks)
{
    knl_session_t *next_session = NULL;
    if (!item->is_active) {
        return GS_FALSE;
    }
    if (item->xid.value == start_session->rm->xid.value) {
        return GS_FALSE;
    }

    next_session = get_xid_session(start_session, item->xid);
    if (next_session == NULL) {
        return GS_FALSE;
    }

    if (w_marks[next_session->id] == 0) {
        if (dlock_push_with_check(stack_ptr, next_session)) {
            w_marks[next_session->id] = 1;
        }
    }
    return GS_TRUE;
}

static bool32 smon_push_pcr_itl(knl_session_t *session, pcr_itl_t *itl, knl_dlock_stack_t *dlock_stack,
                                uint8 *w_marks)
{
    knl_session_t *next_session = NULL;

    if (!itl->is_active) {
        return GS_FALSE;
    }

    if (itl->xid.value == session->rm->xid.value) {
        return GS_FALSE;
    }

    next_session = get_xid_session(session, itl->xid);
    if (next_session == NULL) {
        return GS_FALSE;
    }

    if (w_marks[next_session->id] == 0) {
        if (dlock_push_with_check(dlock_stack, next_session)) {
            w_marks[next_session->id] = 1;
        }
    }

    return GS_TRUE;
}

// return FALSE means no deadlock and break check
static bool32 smon_push_itl_sessions(knl_session_t *start_session, page_head_t *head, knl_dlock_stack_t *stack_ptr,
                                     uint8 *w_marks)
{
    itl_t *item = NULL;
    pcr_itl_t *pcr_item = NULL;
    heap_page_t *heap_page = NULL;
    btree_page_t *btree_page = NULL;

    if (start_session->status == SESSION_INACTIVE) {
        return GS_FALSE;
    }

    switch (head->type) {
        case PAGE_TYPE_HEAP_DATA:
            heap_page = (heap_page_t *)head;
            for (uint8 i = 0; i < heap_page->itls; i++) {
                item = heap_get_itl(heap_page, i);
                if (!smon_push_itl(start_session, item, stack_ptr, w_marks)) {
                    return GS_FALSE;
                }
            }
            break;

        case PAGE_TYPE_BTREE_NODE:
            btree_page = (btree_page_t *)head;
            for (uint8 i = 0; i < btree_page->itls; i++) {
                item = BTREE_GET_ITL(btree_page, i);
                if (!smon_push_itl(start_session, item, stack_ptr, w_marks)) {
                    return GS_FALSE;
                }
            }
            break;

        case PAGE_TYPE_PCRH_DATA:
            heap_page = (heap_page_t *)head;
            for (uint8 i = 0; i < heap_page->itls; i++) {
                pcr_item = pcrh_get_itl(heap_page, i);
                if (!smon_push_pcr_itl(start_session, pcr_item, stack_ptr, w_marks)) {
                    return GS_FALSE;
                }
            }
            break;

        case PAGE_TYPE_PCRB_NODE:
        default:
            btree_page = (btree_page_t *)head;
            for (uint8 i = 0; i < btree_page->itls; i++) {
                pcr_item = pcrb_get_itl(btree_page, i);
                if (!smon_push_pcr_itl(start_session, pcr_item, stack_ptr, w_marks)) {
                    return GS_FALSE;
                }
            }
            break;
    }

    return GS_TRUE;
}

// check if all pathes end in a circle or to session itself
static bool32 smon_check_itl_waits(knl_session_t *session, knl_session_t *start_session, bool32 record_sql)
{
    knl_session_t *curr_session = NULL;
    knl_session_t *next_session = NULL;
    page_head_t *curr_page = NULL;
    uint8 *w_marks = NULL;
    xid_t curr_wxid;
    page_id_t start_wpid, curr_wpid;
    knl_dlock_stack_t *stack_ptr;
    knl_rm_t *curr_rm = NULL;
    knl_rm_t *start_rm = NULL;
    uint32 max_sessions;
    errno_t ret;

    max_sessions = GS_MAX_SESSIONS;
    stack_ptr = &g_dlock_stack;
    stack_ptr->top = 0;
    w_marks = (uint8 *)cm_push(session->stack, max_sessions * sizeof(uint8));
    ret = memset_sp(w_marks, max_sessions, 0, max_sessions);
    knl_securec_check(ret);

    if (start_session->status == SESSION_INACTIVE) {
        cm_pop(session->stack);
        return GS_FALSE;
    }

    start_wpid = start_session->wpid;
    if (IS_INVALID_PAGID(start_wpid)) {
        cm_pop(session->stack);
        return GS_FALSE;
    }

    if (buf_read_page(session, start_wpid, LATCH_MODE_S, ENTER_PAGE_NORMAL) != GS_SUCCESS) {
        cm_reset_error();
        cm_pop(session->stack);
        return GS_FALSE;
    }
    curr_page = (page_head_t *)CURR_PAGE(session);

    if (record_sql) {
        GS_LOG_TRACE("session id: %u, wait page_id: %u-%u", start_session->id, start_wpid.file, start_wpid.page);
        smon_record_deadlock(session, start_session);
    }

    if (!smon_push_itl_sessions(start_session, curr_page, stack_ptr, w_marks)) {
        buf_leave_page(session, GS_FALSE);
        cm_pop(session->stack);
        return GS_FALSE;
    }
    buf_leave_page(session, GS_FALSE);

    while (!dlock_is_empty(stack_ptr)) {
        curr_session = (knl_session_t *)dlock_top(stack_ptr);
        dlock_pop(stack_ptr);

        start_rm = start_session->rm;
        curr_rm = curr_session->rm;

        if (curr_session->status == SESSION_INACTIVE || start_session->status == SESSION_INACTIVE ||
            curr_rm == NULL || start_rm == NULL) {
            cm_pop(session->stack);
            return GS_FALSE;
        }

        if (curr_rm->xid.value == start_rm->xid.value) {
            if (record_sql) {
                GS_LOG_TRACE("session id: %u, wait page_id: %u-%u", curr_session->id, curr_wpid.file, curr_wpid.page);
                smon_record_deadlock(session, curr_session);
            }
            continue;
        }

        curr_wpid = curr_session->wpid;
        curr_wxid = curr_session->wxid;
        if (curr_wxid.value == GS_INVALID_ID64 && IS_INVALID_PAGID(curr_wpid)) {
            cm_pop(session->stack);
            return GS_FALSE;
        } else if (curr_wxid.value != GS_INVALID_ID64) {
            next_session = get_xid_session(session, curr_wxid);
            if (next_session == NULL) {
                cm_pop(session->stack);
                return GS_FALSE;
            }

            if (record_sql) {
                GS_LOG_TRACE("session id: %u, wait session id: %u", curr_session->id, next_session->id);
                smon_record_deadlock(session, curr_session);
            }

            if (w_marks[next_session->id] == 0) {
                if (dlock_push_with_check(stack_ptr, next_session)) {
                    w_marks[next_session->id] = 1;
                }
            }
        } else {
            if (IS_SAME_PAGID(curr_wpid, start_wpid)) {
                if (record_sql) {
                    GS_LOG_TRACE("session id: %u, wait page_id: %u-%u", curr_session->id, curr_wpid.file, curr_wpid.page);
                    smon_record_deadlock(session, curr_session);
                }
                continue;
            }

            if (record_sql) {
                GS_LOG_TRACE("session id: %u, wait page_id: %u-%u", curr_session->id, curr_wpid.file, curr_wpid.page);
                smon_record_deadlock(session, curr_session);
            }

            if (buf_read_page(session, curr_wpid, LATCH_MODE_S, ENTER_PAGE_NORMAL) != GS_SUCCESS) {
                cm_reset_error();
                cm_pop(session->stack);
                return GS_FALSE;
            }
            curr_page = (page_head_t *)CURR_PAGE(session);
            if (!smon_push_itl_sessions(curr_session, curr_page, stack_ptr, w_marks)) {
                buf_leave_page(session, GS_FALSE);
                cm_pop(session->stack);
                return GS_FALSE;
            }
            buf_leave_page(session, GS_FALSE);
        }
    }
    cm_pop(session->stack);

    // re-check deadlock and record SQL text
    if (!record_sql) {
        smon_record_deadlock_time();
        GS_LOG_TRACE("[ITL Deadlock]");
        return smon_check_itl_waits(session, start_session, GS_TRUE);
    }
    GS_LOG_TRACE("-----------------END OF WAIT INFORMATION-----------------\n");
    return GS_TRUE;
}

static void smon_push_itl_to_lock(knl_session_t *session, uint8 *w_marks, knl_dlock_stack_t *stack_lock)
{
    knl_session_t *lock_session = NULL;
    uint16 wsid, wrmid;

    wrmid = session->wrmid;
    if (wrmid == GS_INVALID_ID16) {
        return;
    }

    wsid = knl_get_rm_sid(session, wrmid);
    if (wsid == GS_INVALID_ID16) {
        return;
    }

    if (w_marks[wsid] == 0) {
        lock_session = session->kernel->sessions[wsid];
        if (dlock_push_with_check(stack_lock, lock_session)) {
            w_marks[wsid] = 1;
        }
    }
}

static bool32 smon_push_lock(knl_session_t *session, uint8 *w_marks, knl_dlock_stack_t *stack_lock,
                             schema_lock_t *lock)
{
    knl_session_t *lock_session = NULL;
    uint16 sid;
    uint32 count = 0;

    if (lock == NULL) {
        return GS_FALSE;
    }

    for (uint32 i = 0; i < session->kernel->rm_count; i++) {
        if (lock->map[i] != 0) {
            sid = knl_get_rm_sid(session, i);
            if (sid == GS_INVALID_ID16) {
                continue;
            }

            lock_session = session->kernel->sessions[sid];
            if (lock_session == NULL) {
                return GS_FALSE;
            }

            if (lock_session->lock_dead_locked) {
                return GS_FALSE;
            }

            if (i != session->rmid) {
                count++;
            }

            if (w_marks[sid] == 0) {
                if (dlock_push_with_check(stack_lock, lock_session)) {
                    w_marks[sid] = 1;
                }
            }
        }
    }
    // current session has no available locked_session
    if (count == 0) {
        return GS_FALSE;
    }

    if (lock_session == NULL) {
        return GS_FALSE;
    }

    return GS_TRUE;
}

static bool32 smon_check_lock_waits(knl_session_t *session, knl_session_t *se, bool32 record_sql)
{
    knl_dlock_stack_t *stack_lock = NULL;
    uint8 *w_marks = NULL;
    knl_session_t *curr_session = NULL;
    schema_lock_t *lock = NULL;
    dc_entry_t *entry = NULL;
    dc_user_t *user = NULL;
    page_head_t *curr_page = NULL;
    uint32 max_sessions;
    lock_twait_t wtid, curr_wtid;
    errno_t ret;
    page_id_t curr_wpid;
    uint16 curr_wrmid;

    if (se == NULL) {
        return GS_FALSE;
    }

    wtid.value = cm_atomic_get(&se->wtid.value);
    if (dc_open_user_by_id(session, wtid.uid, &user) != GS_SUCCESS) {
        return GS_FALSE;
    }

    entry = DC_GET_ENTRY(user, wtid.oid);
    if (entry == NULL) {
        return GS_FALSE;
    }

    cm_spin_lock(&entry->lock, &session->stat->spin_stat.stat_dc_entry);
    if ((!entry->ready) || (entry->recycled)) {
        cm_spin_unlock(&entry->lock);
        return GS_FALSE;
    }
    lock = entry->sch_lock;
    cm_spin_unlock(&entry->lock);

    if (lock == NULL) {
        return GS_FALSE;
    }

    if (!se->wtid.is_locking) {
        return GS_FALSE;
    }
    max_sessions = GS_MAX_SESSIONS;
    stack_lock = &g_dlock_stack;
    stack_lock->top = 0;
    w_marks = (uint8 *)cm_push(session->stack, max_sessions * sizeof(uint8));
    ret = memset_sp(w_marks, max_sessions, 0, max_sessions);
    knl_securec_check(ret);

    if (record_sql) {
        GS_LOG_TRACE("session id: %u, wait object id: %u-%u", se->id, se->wtid.uid, se->wtid.oid);
        smon_record_deadlock(session, se);
    }

    if (!smon_push_lock(se, w_marks, stack_lock, lock)) {
        cm_pop(session->stack);
        return GS_FALSE;
    }

    while (!dlock_is_empty(stack_lock)) {
        curr_session = (knl_session_t *)dlock_top(stack_lock);
        dlock_pop(stack_lock);

        if (curr_session == NULL) {
            cm_pop(session->stack);
            return GS_FALSE;
        }

        if (se->rmid == curr_session->rmid) {
            continue;
        }

        curr_wpid = curr_session->wpid;
        curr_wrmid = curr_session->wrmid;

        if ((curr_session->wait.event == ENQ_TX_TABLE_S || curr_session->wait.event == ENQ_TX_TABLE_X) &&
            curr_session->is_waiting) {
            curr_wtid.value = cm_atomic_get(&curr_session->wtid.value);
            if (dc_open_user_by_id(session, curr_wtid.uid, &user) != GS_SUCCESS) {
                cm_pop(session->stack);
                return GS_FALSE;
            }

            entry = DC_GET_ENTRY(user, curr_wtid.oid);
            if (entry == NULL) {
                cm_pop(session->stack);
                return GS_FALSE;
            }

            cm_spin_lock(&entry->lock, &session->stat->spin_stat.stat_dc_entry);
            if ((!entry->ready) || (entry->recycled)) {
                cm_spin_unlock(&entry->lock);
                cm_pop(session->stack);
                return GS_FALSE;
            }
            lock = entry->sch_lock;
            cm_spin_unlock(&entry->lock);

            if (record_sql) {
                GS_LOG_TRACE("session id: %u, wait object id: %u-%u",
                             curr_session->id, curr_session->wtid.uid, curr_session->wtid.oid);
                smon_record_deadlock(session, curr_session);
            }

            if (!smon_push_lock(curr_session, w_marks, stack_lock, lock)) {
                cm_pop(session->stack);
                return GS_FALSE;
            }
        } else if (curr_wrmid != GS_INVALID_ID16 && curr_session->status != SESSION_INACTIVE) {
            if (record_sql) {
                GS_LOG_TRACE("session id: %u, wait session id: %u",
                             curr_session->id, knl_get_rm_sid(session, curr_wrmid));
                smon_record_deadlock(session, curr_session);
            }

            smon_push_itl_to_lock(curr_session, w_marks, stack_lock);
        } else if (!IS_INVALID_PAGID(curr_wpid) && curr_session->status != SESSION_INACTIVE) {
            if (buf_read_page(session, curr_wpid, LATCH_MODE_S, ENTER_PAGE_NORMAL) != GS_SUCCESS) {
                cm_reset_error();
                cm_pop(session->stack);
                return GS_FALSE;
            }
            curr_page = (page_head_t *)CURR_PAGE(session);

            if (record_sql) {
                GS_LOG_TRACE("session id: %u, wait page_id: %u-%u", curr_session->id, curr_wpid.file, curr_wpid.page);
                smon_record_deadlock(session, curr_session);
            }

            if (!smon_push_itl_sessions(curr_session, curr_page, stack_lock, w_marks)) {
                buf_leave_page(session, GS_FALSE);
                cm_pop(session->stack);
                return GS_FALSE;
            }
            buf_leave_page(session, GS_FALSE);
        } else {
            cm_pop(session->stack);
            return GS_FALSE;
        }
    }

    if (se->wtid.oid != wtid.oid || se->wtid.uid != wtid.uid || !se->wtid.is_locking) {
        cm_pop(session->stack);
        return GS_FALSE;
    }
    cm_pop(session->stack);

    // re-check deadlock and record SQL text
    if (!record_sql) {
        smon_record_deadlock_time();
        GS_LOG_TRACE("[Table Deadlock]");
        return smon_check_lock_waits(session, se, GS_TRUE);
    }
    GS_LOG_TRACE("-----------------END OF WAIT INFORMATION-----------------\n");
    return GS_TRUE;
}

status_t smon_start(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;

    if (cm_create_thread(smon_proc, 0, kernel->sessions[SESSION_ID_SMON], &kernel->smon_ctx.thread) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static void smon_init_undo_hist(knl_session_t *session)
{
    for (int i = 0; i < MAX_UNDO_HIST; i++) {
        g_undo_hist.undo_hist[i] = MIN_UNDO_RETENTION;
    }
    g_undo_hist.last = 0;
}

/*
 * get_scn_diff_time : get scn1 - scn2 time diff
 */
static inline uint32 get_scn_diff_time(knl_scn_t scn1, knl_scn_t scn2)
{
    timeval_t time1, time2;
    KNL_SCN_TO_TIME(scn1, &time1, 0);
    KNL_SCN_TO_TIME(scn2, &time2, 0);
    return time1.tv_sec - time2.tv_sec;
}
/*
 * smon_get_min_undo_retention :Calculate the minimum undo_rentention
 */
static uint32 smon_get_min_undo_retention(knl_session_t *session)
{
    knl_scn_t cur_local_scn = db_inc_scn(session); // force inc scn
    knl_scn_t min_local_scn = cur_local_scn;
    uint32 min_undo_retention = 0;

    smon_set_min_scn(session);
    min_local_scn = KNL_GET_SCN(&session->kernel->min_scn);
    if (min_local_scn < cur_local_scn) {
        min_undo_retention = get_scn_diff_time(cur_local_scn, min_local_scn);
    }
    if (min_undo_retention >= g_instance->kernel.attr.undo_retention_time) {
        GS_LOG_DEBUG_INF("min > undo_retention %llu - %llu = %u ", cur_local_scn, min_local_scn, min_undo_retention);
    }
    return min_undo_retention;
}

static void smon_set_undo_retention(knl_session_t *session)
{
    uint32 min_undo_retenion ;
    min_undo_retenion = smon_get_min_undo_retention(session);
    min_undo_retenion++; // round up
    min_undo_retenion++; // round up

    // for flashback min_retention
    if (min_undo_retenion < g_instance->kernel.attr.auto_undo_retention) {
        min_undo_retenion = g_instance->kernel.attr.auto_undo_retention;
    }

    if (min_undo_retenion < MIN_UNDO_RETENTION) {
        min_undo_retenion = MIN_UNDO_RETENTION;
    }
    // for undo_retention_time parameter
    if (min_undo_retenion > g_instance->kernel.attr.undo_retention_time) {
        min_undo_retenion = g_instance->kernel.attr.undo_retention_time;
    }

    ++g_undo_hist.last;
    g_undo_hist.undo_hist[g_undo_hist.last % MAX_UNDO_HIST] = min_undo_retenion;

    for (int i = 0; i < MAX_UNDO_HIST; i++) {
        if (g_undo_hist.undo_hist[i] > min_undo_retenion) {
            min_undo_retenion = g_undo_hist.undo_hist[i];
        }
    }
    if (min_undo_retenion != g_instance->kernel.undo_ctx.retention) {
        GS_LOG_DEBUG_INF("smon_set_undo_retention %u -> %u \n", g_instance->kernel.undo_ctx.retention,
            min_undo_retenion);
        g_instance->kernel.undo_ctx.retention = min_undo_retenion;
    }
}
