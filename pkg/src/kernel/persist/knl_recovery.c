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
 * knl_recovery.c
 *
 *
 * IDENTIFICATION
 * src/kernel/persist/knl_recovery.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_persist_module.h"
#include "knl_recovery.h"
#include "knl_log_mgr.h"
#include "cm_log.h"
#include "cm_checksum.h"
#include "cm_file.h"
#include "knl_context.h"
#include "knl_ctlg.h"
#include "knl_xa_persist.h"
#include "dtc_dc.h"

void log_get_manager(log_manager_t **lmgr, uint32 *count)
{
    *lmgr = g_lmgrs;
    *count = LMGR_COUNT;
}

void log_get_logic_manager(logic_log_manager_t **lmgr, uint32 *count)
{
    *lmgr = g_logic_lmgrs;
    *count = LOGIC_LMGR_COUNT;
}

static bool32 abr_supported_redo_type(log_type_t type)
{
    switch (type) {
        /* following space redo do not modify page context */
        case RD_SPC_CREATE_SPACE:
        case RD_SPC_REMOVE_SPACE:
        case RD_SPC_EXTEND_DATAFILE:
        case RD_SPC_TRUNCATE_DATAFILE:
            return CT_FALSE;
        default:
            break;
    }

    if (type >= LOG_TYPE_LREP && type <= LOG_TYPE_LOGIC) {
        return CT_FALSE;
    }

    return CT_TRUE;
}

static bool32 rcy_contain_spc_log(uint8 type)
{
    switch (type) {
        case RD_SPC_CREATE_SPACE:
        case RD_SPC_REMOVE_SPACE:
        case RD_SPC_CREATE_DATAFILE:
        case RD_SPC_REMOVE_DATAFILE:
        case RD_SPC_EXTEND_DATAFILE:
        case RD_SPC_TRUNCATE_DATAFILE:
        case RD_SPC_EXTEND_UNDO_SEGMENTS:
            return CT_TRUE;
        default:
            return CT_FALSE;
    }
}

void print_rcy_skip_page_limit(knl_session_t *session)
{
    page_head_t *head = (page_head_t *)session->curr_page;
    static page_id_t damage_pages[DAMAGE_PAGE_CACHE_COUNT] = {0};
    static uint64 count = 0;
    bool not_found = CT_TRUE;
    uint64 num = (count > DAMAGE_PAGE_CACHE_COUNT) ? DAMAGE_PAGE_CACHE_COUNT : count;
    for (uint64 i = 0; i < num; i++) {
        if (damage_pages[i].page == AS_PAGID(head->id).page && damage_pages[i].file == AS_PAGID(head->id).file) {
            not_found = CT_FALSE;
        }
    }
    if (not_found) {
        damage_pages[count % DAMAGE_PAGE_CACHE_COUNT] = AS_PAGID(head->id);
        count++;
        CT_LOG_RUN_WAR("[RCY] page: %u-%u is damaged, skip redo for this page, current count: %llu",
            AS_PAGID(head->id).file, AS_PAGID(head->id).page, count);
    }
    return;
}

static bool32 rcy_is_skip(knl_session_t *session, log_type_t type)
{
    if ((session->kernel->rcy_ctx.abr_rcy_flag || session->kernel->rcy_ctx.is_file_repair) &&
        !abr_supported_redo_type(type)) {
        return CT_TRUE;
    }

    if (RD_TYPE_IS_ENTER_PAGE(type) || RD_TYPE_IS_LEAVE_PAGE(type) || session->page_stack.depth == 0) {
        return CT_FALSE;
    }

    if (!DB_IS_CLUSTER(session) && DB_IS_OPEN(session) && (type == RD_TX_END || type == RD_XA_PHASE1)) {
        /*
        * gbp log analyze proc will replay txn redo, and maintain txn area, but it can not forward scn
        * only lrpl proc can forward scn, so we do not skip RD_TX_END and RD_XA_PHASE1 in rcy_is_skip
        * is_skip will been judged in rd_tx_end and rd_xa_phase1
        */
        return CT_FALSE;
    }

    bool32 is_skip = session->page_stack.is_skip[session->page_stack.depth - 1];
    if (is_skip) {
        return is_skip;
    }
    is_skip = ((session->curr_page != NULL) && PAGE_IS_HARD_DAMAGE((page_head_t *)session->curr_page));
    if (is_skip) {
        print_rcy_skip_page_limit(session);
    }
    return is_skip;
}

static inline bool32 rcy_pcn_verifiable(knl_session_t *session, log_entry_t *log)
{
    return (bool32)(DB_IS_RCY_CHECK_PCN(session) &&
        !RD_TYPE_IS_ENTER_PAGE(log->type) &&
        !RD_TYPE_IS_LEAVE_PAGE(log->type) &&
        log->type != RD_LOGIC_OPERATION &&
        session->page_stack.depth > 0 &&
        session->curr_page_ctrl &&
        session->curr_page_ctrl->page->pcn != 0 &&
        !format_page_redo_type(log->type)) &&
        !(session->rm->nolog_type == TABLE_LEVEL) &&
        !session->curr_page_ctrl->page->soft_damage;
}

void rcy_page_set_damage(knl_session_t *session, pcn_verify_t *log_pcns)
{
    if (DB_IS_MAXFIX(session)) {
        log_context_t *ctx = &session->kernel->redo_ctx;
        session->curr_page_ctrl->page->hard_damage = CT_TRUE;
        CT_LOG_RUN_WAR(
            "set hard_damage, log entry pcn %u not equal page pcn %u.page_id: %u-%u, lsn: %llu, curr_file: %s",
            log_pcns[session->page_stack.depth - 1].pcn, session->curr_page_ctrl->page->pcn,
            session->curr_page_ctrl->page_id.file, session->curr_page_ctrl->page_id.page, session->curr_lsn,
            ctx->files[ctx->curr_file].ctrl->name);
    }
    return;
}

void rcy_replay_pcn_verify(knl_session_t *session, log_entry_t *log, pcn_verify_t *log_pcns, uint32 log_pcns_size)
{
    log_context_t *ctx = &session->kernel->redo_ctx;
    rd_enter_page_t *rd  = NULL;
    datafile_t *df = NULL;
    bool32 changed = CT_FALSE;

    if (RD_TYPE_IS_ENTER_PAGE(log->type)) {
        rd = (rd_enter_page_t *)log->data;
        df = DATAFILE_GET(session, rd->file);
        knl_panic_log(session->page_stack.depth < log_pcns_size, "the page_stack's depth is more than log_pcns_size, "
                      "panic info: log_pcns_size %u log_pcns_size %u", session->page_stack.depth, log_pcns_size);
        log_pcns[session->page_stack.depth].failed = CT_FALSE;
        if (SPACE_IS_NOLOGGING(SPACE_GET(session, df->space_id)) || (rd->options & ENTER_PAGE_NO_READ)) {
            log_pcns[session->page_stack.depth].skip = CT_TRUE;
            return;
        }
        log_pcns[session->page_stack.depth].pcn = rd->pcn;
        log_pcns[session->page_stack.depth].skip = CT_FALSE;
        return;
    }

    if (RD_TYPE_IS_LEAVE_PAGE(log->type)) {
        if (!log_pcns[session->page_stack.depth - 1].failed) {
            return;
        }
        
        changed = *(bool32 *)log->data;
        if (changed && (!DB_IS_MAXFIX(session))) {
            knl_panic_log(CT_FALSE, "log entry pcn %u not equal page pcn %u.page_id: %u-%u, lsn: %llu, curr_file: %s",
                          log_pcns[session->page_stack.depth - 1].pcn, session->curr_page_ctrl->page->pcn,
                          session->curr_page_ctrl->page_id.file, session->curr_page_ctrl->page_id.page,
                          session->curr_lsn, ctx->files[ctx->curr_file].ctrl->name);
        }
        log_pcns[session->page_stack.depth - 1].failed = CT_FALSE;
        return;
    }

    if (rcy_pcn_verifiable(session, log)) {
        if (log_pcns[session->page_stack.depth - 1].skip) {
            return;
        }
        // RD_TX_END and RD_XA_PHASE1 will not set to skip in rcy_is_skip when lrpl perform
        if (DB_IS_OPEN(session) && (log->type == RD_TX_END || log->type == RD_XA_PHASE1) &&
            session->page_stack.is_skip[session->page_stack.depth - 1]) {
            return;
        }

        if (log_pcns[session->page_stack.depth - 1].pcn != session->curr_page_ctrl->page->pcn) {
            log_pcns[session->page_stack.depth - 1].failed = CT_TRUE;
            rcy_page_set_damage(session, log_pcns);
        }
    }
}

void rcy_flexible_sleep(knl_session_t *session, rcy_context_t *rcy, rcy_bucket_t *bucket)
{
    if (!DB_IS_OPEN(session) || rcy->last_lrpl_time == 0) {
        cm_spin_sleep(); // when db is in recover, just sleep 100ns
        return;
    }
    if (g_timer()->now - rcy->last_lrpl_time > RCY_SLEEP_TIME_THRESHOLD) {
        cm_sleep(100);
        return;
    }

    if (bucket != NULL && (g_timer()->now - bucket->last_replay_time > RCY_SLEEP_TIME_THRESHOLD)) {
        cm_sleep(100);
        return;
    }

    if (rcy->replay_no_lag) {
        cm_sleep(1);
    } else {
        cm_spin_sleep();
    }
}

static void rcy_set_soft_damage_page(knl_session_t *session, log_entry_t *log)
{
    if (RD_TYPE_IS_ENTER_PAGE(log->type) && session->page_stack.depth != 0 && session->curr_page != NULL) {
        if (session->rm->nolog_type != TABLE_LEVEL) {
            return;
        }

        page_head_t *page = (page_head_t *)CURR_PAGE(session);

        if (page->soft_damage) {
            return;
        }

        if (page_type_suport_nolog_insert(page->type)) {
            page->soft_damage = CT_TRUE;
            return;
        }

        page_id_t *page_id = NULL;
        if (session->kernel->backup_ctx.block_repairing) {
            page_id = session->kernel->rcy_ctx.abr_ctrl == NULL ? NULL : &session->kernel->rcy_ctx.abr_ctrl->page_id;
        } else {
            page_id = session->curr_page_ctrl == NULL ? NULL : &session->curr_page_ctrl->page_id;
        }

        if (page_id == NULL) {
            return;
        }

        datafile_t *df = DATAFILE_GET(session, page_id->file);

        // df has punched and page is inited and page was nolog inserted, the page may be punched so we need skip entry.
        if (df->ctrl->punched && page->size_units == 0) {
            session->page_stack.is_skip[session->page_stack.depth - 1] = CT_TRUE;
        }
    }

    return;
}

static void rcy_unblock_backup(knl_session_t *session, log_entry_t *log, bool32 need_unblock_backup)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    if (need_unblock_backup) {
        ctx->bak.rcy_stop_backup = CT_FALSE;
    }
}

atomic_t rcy_replay_entry_num;
atomic_t rcy_total_entry_num;
static inline void rcy_replay_entry(knl_session_t *session, log_entry_t *log, pcn_verify_t *log_pcns,
                                    uint32 log_pcns_size)
{
    log_context_t *ctx = &session->kernel->redo_ctx;
    bool32 need_replay = CT_TRUE;
    bool32 need_unblock_backup = CT_FALSE;

    if (!rcy_is_skip(session, log->type)) {
        rcy_replay_pcn_verify(session, log, log_pcns, log_pcns_size);
        if (DB_IS_MAXFIX(session) && rcy_is_skip(session, log->type)) {
            return;
        }
        /*
         * checking page was safe format or punch format,skip punch format situation
         */
        ctx->verify_page_format_proc[log->type](session, log, &need_replay);
        
        if (need_replay) {
            /*
             * checking page was nologging inserted, we need skip most logs of nolog_insert pages
             * just some specified logs must be rcy (eg: nolog_page_allow_redo_type).
             */
            ctx->verify_nolog_insert_proc[log->type](session, log, &need_replay);
            if (need_replay) {
                ctx->stop_backup_proc[log->type](session, log, &need_unblock_backup);
                ctx->replay_procs[log->type](session, log);
                rcy_unblock_backup(session, log, need_unblock_backup);
                rcy_set_soft_damage_page(session, log);
            }
        }
    }
}

static void rcy_analysis_entry(knl_session_t *session, log_entry_t *log)
{
    log_context_t *ctx = &session->kernel->redo_ctx;

    knl_panic_log(ctx->analysis_procs[log->type] != NULL, "current analysis_procs is NULL.");
    /* always analysis it if this log is gbp_unsafe or gbp_safe */
    if (ctx->analysis_procs[log->type] == gbp_aly_unsafe_entry ||
        ctx->analysis_procs[log->type] == gbp_aly_safe_entry) {
        ctx->analysis_procs[log->type](session, log, session->curr_lsn);
    } else {
        /* because we may replay log during log analysis, so we must follow `skip' logical */
        if (!rcy_is_skip(session, log->type)) {
            ctx->analysis_procs[log->type](session, log, session->curr_lsn);
        }
    }
}

void rcy_wait_preload_complete(knl_session_t *session)
{
    rcy_context_t *rcy = &session->kernel->rcy_ctx;

    if (!rcy->paral_rcy) {
        return;
    }
    for (uint32 i = 0; i < rcy->preload_proc_num; i++) {
        while (rcy->preload_info[i].curr < (uint32)rcy->preload_hwm) {
            cm_spin_sleep();
        }
    }
}

void rcy_wait_replay_complete(knl_session_t *session)
{
    rcy_context_t *rcy = &session->kernel->rcy_ctx;
    errno_t ret;

    if (!rcy->paral_rcy) {
        return;
    }

    rcy_wait_preload_complete(session);
    ret = memset_sp(rcy->page_bitmap, sizeof(uint16) * CT_RCY_MAX_PAGE_BITMAP_LEN, 0,
                    sizeof(uint16) * CT_RCY_MAX_PAGE_BITMAP_LEN);
    knl_securec_check(ret);
    for (uint32 i = 0; i < rcy->capacity; i++) {
        while (rcy->bucket[i].head != rcy->bucket[i].tail) {
            cm_spin_sleep();
        }
    }
    rcy->wait_stats_view[WAIT_RELAPY_COUNT]++;

    rcy->page_list_count = 0;
    rcy->tx_end_count = 0;
    rcy->current_tid = 0;
    rcy->preload_hwm = 0;
    for (uint32 i = 0; i < rcy->preload_proc_num; i++) {
        rcy->preload_info[i].group_id = 0;
        rcy->preload_info[i].curr = i;
    }
    gbp_unsafe_redo_check(session);
}

static void rcy_wait_cond(knl_session_t *session, rcy_bucket_t *bucket, uint32 index, volatile uint32 *curr,
    uint32 target, uint32 *wait_count)
{
    uint32 sleep_times = 0;

    if (bucket != NULL) {
        bucket->waiting_index = index;
        while (*curr + 1 < target) {
            cm_timedwait_eventfd(&bucket->eventfd, 1);
        }
        bucket->waiting_index = CT_INVALID_ID32;
    }

    for (;;) {
        if (*curr == target) {
            break;
        }

        sleep_times++;
        if (SECUREC_UNLIKELY(sleep_times == session->kernel->attr.rcy_sleep_interval)) {
            (*wait_count)++;
            cm_spin_sleep();
            sleep_times = 0;
            continue;
        }
#ifndef WIN32
        for (uint32 i = 0; i < sleep_times; i++) {
            fas_cpu_pause();
        }
#endif
    }
}

static void rcy_wakeup_next(rcy_context_t *rcy, uint8 next_bucket_id, uint32 waiting_index)
{
    if (next_bucket_id == CT_INVALID_ID8) {
        return;
    }

    if (rcy->bucket[next_bucket_id].waiting_index == waiting_index) {
        cm_wakeup_eventfd(&rcy->bucket[next_bucket_id].eventfd);
    }
}

static void rcy_record_time(rcy_bucket_t *bucket, uint64 wait_time)
{
    if (bucket != NULL) {
        rcy_paral_stat_t *rcy_stat = &bucket->rcy_stat;
        rcy_stat->wait_cond_time += wait_time;
    }
    return;
}

static status_t rcy_paral_replay_entry(knl_session_t *session, rcy_bucket_t *bucket, log_entry_t *log,
                                       rcy_paral_group_t *paral_group, pcn_verify_list_t pcn_list)
{
    rcy_context_t *rcy = &session->kernel->rcy_ctx;
    pcn_verify_t *log_pcns = pcn_list.list;
    uint32 log_pcns_size = pcn_list.count;
    uint32 wait_count = 0;
    timeval_t rcy_wait_time_begin;
    uint64 rcy_wait_time_end = 0;

    if (RD_TYPE_IS_ENTER_PAGE(log->type)) {
        rd_enter_page_t *redo = (rd_enter_page_t *)log->data;
        uint32 index = paral_group->items[paral_group->curr_enter_id].page_index;
        rcy_page_t *page = &rcy->page_list[index >> RCY_PAGE_LIST_MOD_BITLEN][index & PCY_PAGE_LIST_MOD_MASK];
        knl_panic_log(redo->file == page->file && redo->page == page->page, "the redo is not match to page, "
                      "panic info: page %u-%u redo %u-%u", page->page, page->file, redo->file, redo->page);
        uint32 group_slot = paral_group->items[paral_group->curr_enter_id].slot;
        uint8 next_bucket_id = paral_group->items[paral_group->curr_enter_id].next_bucket_id;

        ELAPSED_BEGIN(rcy_wait_time_begin);
        rcy_wait_cond(session, bucket, index, &page->current_group, group_slot, &wait_count);
        ELAPSED_END(rcy_wait_time_begin, rcy_wait_time_end);
        rcy_record_time(bucket, rcy_wait_time_end);
        rcy_replay_entry(session, log, log_pcns, log_pcns_size);

        page_head_t *page_head = (page_head_t *)CURR_PAGE(session);
        if (SECUREC_LIKELY(page_head != NULL)) {
            rcy->wait_stats_view[page_head->type] += wait_count;
        }
        paral_group->curr_enter_id++;
        rcy_wakeup_next(rcy, next_bucket_id, index);
        return CT_SUCCESS;
    }

    if (log->type == RD_TX_END || log->type == RD_XA_PHASE1) {
        if (!DB_IS_CLUSTER(session)) {
            rcy_wait_cond(session, bucket, paral_group->tx_id, &rcy->current_tid, paral_group->tx_id, &wait_count);
        }
        rcy_replay_entry(session, log, log_pcns, log_pcns_size);
        rcy->wait_stats_view[TXN_END_WAIT_COUNT] += wait_count;
        rcy->current_tid++;
        if (!DB_IS_CLUSTER(session)) {
            rcy_wakeup_next(rcy, paral_group->tx_next_bid, paral_group->tx_id + 1);
        }
        return CT_SUCCESS;
    }

    rcy_replay_entry(session, log, log_pcns, log_pcns_size);
    return CT_SUCCESS;
}

static void rcy_replay_group_end(knl_session_t *session)
{
    if (session->dirty_count > 0) {
        ckpt_enque_page(session);
    }

    if (SECUREC_UNLIKELY(session->gbp_dirty_count > 0)) {
        gbp_enque_pages(session);
    }

    if (session->changed_count > 0) {
        log_set_page_lsn(session, session->curr_lsn, session->curr_lfn);
    }
}

static status_t rcy_paral_replay_group(knl_session_t *session, rcy_bucket_t *bucket, log_context_t *ctx,
                                       rcy_paral_group_t *paral_group)
{
    uint32 offset;
    log_entry_t *log = NULL;
    log_group_t *group = paral_group->group;
    pcn_verify_t log_pcns[KNL_MAX_PAGE_STACK_DEPTH] = {0};
    pcn_verify_list_t pcn_list;

    pcn_list.list = log_pcns;
    pcn_list.count = KNL_MAX_PAGE_STACK_DEPTH;

    session->curr_lsn = group->lsn;
    session->ddl_lsn_pitr = paral_group->ddl_lsn_pitr;
    offset = sizeof(log_group_t);
    session->rm->nolog_type = group->nologging_insert ? TABLE_LEVEL : LOGGING_LEVEL;
    while (offset < LOG_GROUP_ACTUAL_SIZE(group)) {
        log = (log_entry_t *)((char *)group + offset);
        if (rcy_paral_replay_entry(session, bucket, log, paral_group, pcn_list) != CT_SUCCESS) {
            session->rm->nolog_type = LOGGING_LEVEL;
            return CT_ERROR;
        }
        if (!DB_IS_PRIMARY(&session->kernel->db) && DB_IS_CLUSTER(session) && log->type == RD_LOGIC_OPERATION) {
            if (dtc_sync_ddl_redo(session, log->data, log->size - LOG_ENTRY_SIZE) != CT_SUCCESS) {
                logic_op_t *op_type = (logic_op_t *)log->data;
                CT_LOG_RUN_ERR("dtc sync ddl failed, type=%d, op_type=%d, size=%u", log->type, *op_type,
                    log->size);
                knl_panic(0);
            }
        }
        offset += log->size;
    }
    session->rm->nolog_type = LOGGING_LEVEL;
    rcy_replay_group_end(session);
    return CT_SUCCESS;
}

void rcy_replay_group(knl_session_t *session, log_context_t *ctx, log_group_t *group)
{
    uint32 offset;
    log_entry_t *log = NULL;
    knl_session_t *se  = session->kernel->sessions[SESSION_ID_KERNEL];
    pcn_verify_t log_pcns[KNL_MAX_PAGE_STACK_DEPTH] = { 0 };

    se->dtc_session_type = session->dtc_session_type;
    se->curr_lsn = group->lsn;
    offset = sizeof(log_group_t);
    se->rm->nolog_type = group->nologging_insert ? TABLE_LEVEL : LOGGING_LEVEL;
    while (offset < LOG_GROUP_ACTUAL_SIZE(group)) {
        log = (log_entry_t *)((char *)group + offset);
        rcy_replay_entry(se, log, log_pcns, KNL_MAX_PAGE_STACK_DEPTH);
        offset += log->size;
    }
    se->rm->nolog_type = LOGGING_LEVEL;
    rcy_replay_group_end(se);
}

/* when GBP enabled, analyze standby redo log group, set page latest lsn to gbp aly item */
static void rcy_analysis_group(knl_session_t *session, log_context_t *ctx, log_group_t *group)
{
    uint32 offset;
    log_entry_t *log = NULL;
    knl_session_t *se = session->kernel->sessions[SESSION_ID_KERNEL];

    if (SESSION_IS_LOG_ANALYZE(session)) {
        se = session; // use aly session for log analysis
    }

    ctx->gbp_aly_lsn = group->lsn;
    se->curr_lsn = group->lsn;
    offset = sizeof(log_group_t);

    while (offset < LOG_GROUP_ACTUAL_SIZE(group)) {
        log = (log_entry_t *)((char *)group + offset);
        rcy_analysis_entry(se, log);
        offset += log->size;
    }
    rcy_replay_group_end(se);
}

bool32 rcy_page_already_added(rcy_paral_group_t *paral_group, uint32 page_index, uint32* inpage_slot)
{
    for (uint32 i = 0; i < paral_group->enter_count; i++) {
        if (page_index == paral_group->items[i].page_index) {
            *inpage_slot = paral_group->items[i].slot;
            return CT_TRUE;
        }
    }
    return CT_FALSE;
}

bool32 rcy_get_page_index(rcy_context_t *rcy_ctx, uint32 page, uint32 file, uint32 *index)
{
    uint32 page_index;
    uint32 page_list_idx;
    rcy_page_t *page_info = NULL;
    uint32 bucket_id = (file + HASH_SEED * page) * HASH_SEED % CT_RCY_MAX_PAGE_COUNT;
    rcy_page_bucket_t *bucket = &rcy_ctx->page_bucket[bucket_id];
    uint16 *bitmap = &rcy_ctx->page_bitmap[bucket_id / UINT16_BITS];
    uint16 map_idx = bucket_id % UINT16_BITS;

    if (!btree_get_bitmap(bitmap, map_idx)) {
        bucket->first = 0;
        bucket->count = 0;
        btree_set_bitmap(bitmap, map_idx);
    }

    page_index = bucket->first;
    for (uint32 i = 0; i < bucket->count; i++) {
        page_info = &rcy_ctx->page_list[page_index >> RCY_PAGE_LIST_MOD_BITLEN][page_index & PCY_PAGE_LIST_MOD_MASK];
        if (page_info->file == file && page_info->page == page) {
            *index = page_index;
            return CT_TRUE;
        }
        page_index = page_info->hash_next;
    }
    
    if (rcy_ctx->page_list_count >= RCY_PAGE_MAX_COUNT) {
            // __TODO__: try hold more page
            CT_LOG_RUN_ERR("rcy paral replay error, page list if full! page_limit:%u", RCY_PAGE_MAX_COUNT);
            knl_panic(0);
    }
    
    *index = rcy_ctx->page_list_count;
    page_list_idx = (*index) >> RCY_PAGE_LIST_MOD_BITLEN;
    if (!CT_BIT_TEST(rcy_ctx->page_list_bitmap, 1ULL << page_list_idx)) {
        rcy_ctx->page_list[page_list_idx] = (rcy_page_t *)malloc(sizeof(rcy_page_t) * RCY_PAGE_LIST_NUM_MAX);
        knl_panic_log(rcy_ctx->page_list[page_list_idx] != NULL, "alloc page_list failed.");
        CT_BIT_SET(rcy_ctx->page_list_bitmap, 1ULL << page_list_idx);
    }
    page_info = &rcy_ctx->page_list[(*index) >> RCY_PAGE_LIST_MOD_BITLEN][(*index) & PCY_PAGE_LIST_MOD_MASK];
    page_info->hash_next = bucket->first;
    bucket->count++;
    bucket->first = *index;
    rcy_ctx->page_list_count++;
    return CT_FALSE;
}

void rcy_add_page(rcy_page_t **pages, rcy_paral_group_t *paral_group, rd_enter_page_t *rd, rcy_context_t *rcy)
{
    bool32 is_exist;
    uint32 index = 0;
    uint32 group_count = 0;
    uint32 page = rd->page;
    uint32 file = rd->file;
    uint32 slot = 0;
    rcy_page_t *now_page;

    is_exist = rcy_get_page_index(rcy, page, file, &index);
    now_page = &pages[index >> RCY_PAGE_LIST_MOD_BITLEN][index & PCY_PAGE_LIST_MOD_MASK];
    if (is_exist) {
        group_count = now_page->group_count;
        if (!rcy_page_already_added(paral_group, index, &slot)) {
            now_page->group_count++;
            slot = group_count;
        }
        // let previous RD_ENTER_PAGE entry know the bucket id which replay next RD_ENTER_PAGE entry
        // TODO in cluster mode, this will cause invalid write;
        // pages[index].prev_enter->next_bucket_id = (uint8)(paral_group->group->rmid % rcy->capacity);

        // reset prev_enter to current RD_ENTER_PAGE entry
        now_page->prev_enter = &paral_group->items[paral_group->enter_count];

        paral_group->items[paral_group->enter_count].page_index = index;
        paral_group->items[paral_group->enter_count].slot = slot;
        paral_group->items[paral_group->enter_count].next_bucket_id = CT_INVALID_ID8;
        paral_group->enter_count++;
    } else {
        now_page->page = page;
        now_page->file = file;
        now_page->group_count = 1;
        now_page->current_group = 0;
        now_page->option = rd->options;
        now_page->gid = paral_group->id;
        now_page->prev_enter = &paral_group->items[paral_group->enter_count];

        paral_group->items[paral_group->enter_count].page_index = index;
        paral_group->items[paral_group->enter_count].slot = 0;
        paral_group->items[paral_group->enter_count].next_bucket_id = CT_INVALID_ID8;
        paral_group->enter_count++;
    }
}

void rcy_record_batch_scn(log_entry_t *log, rcy_paral_group_t *paral_group)
{
    if (log->type == RD_TX_END) {
        rd_tx_end_t *rd_tx = (rd_tx_end_t *)log->data;
        paral_group->group_scn = MAX(paral_group->group_scn, rd_tx->scn);
        CT_LOG_DEBUG_INF("update scn %llu, rd_tx->scn %llu", paral_group->group_scn, rd_tx->scn);
    }

    if (log->type == RD_XA_PHASE1) {
        rd_xa_phase1_t *rd_xa = (rd_xa_phase1_t *)log->data;
        paral_group->group_scn = MAX(paral_group->group_scn, rd_xa->scn);
        CT_LOG_DEBUG_INF("update scn %llu, rd_tx->scn %llu", paral_group->group_scn, rd_xa->scn);
    }
    return;
}

void rcy_add_pages(rcy_paral_group_t *paral_group, log_group_t *group, uint32 group_slot, rcy_context_t *rcy,
                   bool32 *logic, rcy_paral_group_t **next_group)
{
    rcy_page_t **pages = rcy->page_list;
    uint32 offset = sizeof(log_group_t);
    log_entry_t *log = NULL;
    rd_enter_page_t *rd = NULL;
    uint32 page_count = 0;

    paral_group->group = group;
    paral_group->curr_enter_id = 0;
    paral_group->enter_count = 0;
    paral_group->tx_id = 0;
    paral_group->id = group_slot;
    paral_group->group_scn = 0;
    *logic = CT_FALSE;

    while (offset < LOG_GROUP_ACTUAL_SIZE(group)) {
        log = (log_entry_t *)((char *)group + offset);
        if (RD_TYPE_IS_ENTER_PAGE(log->type)) {
            rd = (rd_enter_page_t *)log->data;
            rcy_add_page(pages, paral_group, rd, rcy);
            page_count++;
        }
        if (log->type == RD_TX_END || log->type == RD_XA_PHASE1) {
            paral_group->tx_id = rcy->tx_end_count;
            paral_group->tx_next_bid = CT_INVALID_ID8;
            rcy->tx_end_count++;
            rcy_record_batch_scn(log, paral_group);

            // TODO in cluster mode, this will cause invalid write;
            // if (paral_group->tx_id > 0) {
            //     // let previous tx group know the bucket id which replay next tx group
            //     rcy->prev_tx_group->tx_next_bid = (uint8)(paral_group->group->rmid % rcy->capacity);
            // }
            // rcy->prev_tx_group = paral_group; // reset prev_tx_group to current tx group
        }
        if (log->type == RD_LOGIC_OPERATION || log->type == RD_LOGIC_REP_ALL_DDL  || rcy_contain_spc_log(log->type)) {
            *logic = CT_TRUE;
        }
        offset += log->size;
    }

    knl_panic_log(page_count == paral_group->enter_count, "the page_count is not equal to paral_group's enter_count, "
                  "panic info: page_count %u enter_count %u.", page_count, paral_group->enter_count);
    *next_group = (rcy_paral_group_t *)(&paral_group->items[page_count]);
}

void rcy_add_replay_bucket(rcy_paral_group_t *paral_group, rcy_context_t *rcy)
{
    rcy_bucket_t *bucket = NULL;
    uint32 id;
    uint32 ctrl_id;
    timeval_t begin_time;
    uint64 sleep_time = 0;

    id = paral_group->group->rmid % rcy->capacity;
    bucket = &rcy->bucket[id];

    ctrl_id = (bucket->tail + 1) % bucket->count;
    ELAPSED_BEGIN(begin_time);
    for (;;) {
        if (SECUREC_UNLIKELY(ctrl_id == bucket->head)) {
            rcy->wait_stats_view[BUCKET_OVERFLOW_COUNT]++;
            cm_spin_sleep();
        } else {
            break;
        }
    }
    ELAPSED_END(begin_time, sleep_time);
    bucket->rcy_stat.sleep_time_in_log_add_bucket += sleep_time;
    bucket->rcy_stat.session_replay_log_group_count += 1;

    cm_spin_lock(&bucket->lock, NULL);
    bucket->first[bucket->tail] = paral_group;
    bucket->tail = ctrl_id;
    cm_spin_unlock(&bucket->lock);
}

void rcy_release_lock_pages(knl_session_t *session, rcy_paral_group_t *paral_group)
{
    rcy_context_t *rcy = &session->kernel->rcy_ctx;
    rcy_page_t *page = NULL;
    uint32 i = 0;
    uint32 index = 0;

    for (i = 0; i < paral_group->enter_count; i++) {
        index = paral_group->items[i].page_index;
        page = &rcy->page_list[index >> RCY_PAGE_LIST_MOD_BITLEN][index & PCY_PAGE_LIST_MOD_MASK];
        knl_panic_log(page->group_count >= page->current_group, "the page's group_count is smaller than current_group,"
                      " panic info: page %u-%u group_count %u current_group %u",
                      page->page, page->file, page->group_count, page->current_group);
        if (page->current_group > paral_group->items[i].slot) {
            continue;
        }
        knl_panic_log(page->current_group == paral_group->items[i].slot,
            "page's current_group is not equal to paral_group's slot, panic info: page %u-%u current_group %u slot %u",
            page->page, page->file, page->current_group, paral_group->items[i].slot);
        page->current_group++;
    }
    paral_group->enter_count = 0;
}

void rcy_replay_logic_group(knl_session_t *session, rcy_paral_group_t *paral_group)
{
    knl_instance_t *kernel = session->kernel;
    log_context_t *ctx = &kernel->redo_ctx;
    rcy_context_t *rcy = &kernel->rcy_ctx;
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_rcy_stat_t *stat = &dtc_rcy->rcy_stat;

    timeval_t begin_time;
    uint64 used_time;
    ELAPSED_BEGIN(begin_time);
    for (uint32 j = 0; j < rcy->capacity; j++) {
        while (rcy->bucket[j].head != rcy->bucket[j].tail) {
            cm_spin_sleep();
        }
    }
    ELAPSED_END(begin_time, used_time);
    stat->latc_rcy_logic_log_wait_time += used_time;
 
    ELAPSED_BEGIN(begin_time);
    if (rcy_paral_replay_group(session, NULL, ctx, paral_group) == CT_SUCCESS) {
        rcy_release_lock_pages(session, paral_group);
    }
    ELAPSED_END(begin_time, used_time);
    stat->last_rcy_logic_log_elapsed += used_time;
    stat->last_rcy_logic_log_group_count += 1;
}

static void rcy_paral_replay_batch(knl_session_t *session, log_cursor_t *cursor, log_batch_t *batch)
{
    knl_instance_t *kernel = session->kernel;
    log_context_t *ctx = &kernel->redo_ctx;
    rcy_context_t *rcy = &kernel->rcy_ctx;
    log_group_t *group = NULL;
    bool32 logic = CT_FALSE;
    rcy_paral_group_t *next_paral_group = NULL;
    uint32 group_slot = rcy->curr_group_id;
    knl_session_t *redo_ssesion = session->kernel->sessions[SESSION_ID_KERNEL];
    redo_ssesion->dtc_session_type = session->dtc_session_type;

    for (;;) {
        group = log_fetch_group(ctx, cursor);
        if (SECUREC_UNLIKELY(group == NULL)) {
            break;
        }
        // record curr replay lsn in redo_ssesion when paral recovery, it will be used in gbp_page_verify
        // because redo_curr_lsn must >= page lsn during lrpl, if gbp_page_lsn > redo_curr_lsn, means gbp page can used
        redo_ssesion->curr_lsn = group->lsn;
        rcy_add_pages(rcy->curr_group, group, group_slot, rcy, &logic, &next_paral_group);
        group_slot++;
        rcy->curr_group_id = group_slot;
        cm_atomic_set(&rcy->preload_hwm, (int64)rcy->page_list_count);
        if (logic) {
            // redo log has logic log, must replay by order
            rcy->wait_stats_view[LOGIC_GROUP_COUNT]++;
            rcy_replay_logic_group(session, rcy->curr_group);
        } else {
            rcy_add_replay_bucket(rcy->curr_group, rcy);
        }
        DB_SET_LSN(session->kernel->lsn, group->lsn);
        rcy->curr_group = next_paral_group;
    }

    DB_SET_LFN(&ctx->lfn, batch->head.point.lfn);
    return;
}

void rcy_init_log_cursor(log_cursor_t *cursor, log_batch_t *batch)
{
    char *ptr = (char *)batch + sizeof(log_batch_t);
    cursor->part_count = batch->part_count;
    knl_panic_log(batch->part_count > 0, "the batch's part_count is abnormal, panic info: part_count %u",
                  batch->part_count);
    knl_panic_log(batch->part_count <= CT_MAX_LOG_BUFFERS,
                  "the batch's part_count is more than max limit, panic info: part_count %u", batch->part_count);

    for (uint32 i = 0; i < batch->part_count; i++) {
        cursor->parts[i] = (log_part_t *)ptr;
        cursor->offsets[i] = sizeof(log_part_t);
        ptr = (ptr + cursor->parts[i]->size) + sizeof(log_part_t);
    }
}

void rcy_replay_batch(knl_session_t *session, log_batch_t *batch)
{
    knl_instance_t *kernel = session->kernel;
    log_context_t *ctx = &kernel->redo_ctx;
    rcy_context_t *rcy = &kernel->rcy_ctx;
    log_cursor_t cursor;

    rcy_init_log_cursor(&cursor, batch);
    if (rcy->paral_rcy) {
        rcy_paral_replay_batch(session, &cursor, batch);
    } else {
        log_group_t *group = log_fetch_group(ctx, &cursor);
        while (group != NULL) {
            rcy_replay_group(session, ctx, group);
            DB_SET_LSN(session->kernel->lsn, group->lsn);
            group = log_fetch_group(ctx, &cursor);
        }
        DB_SET_LFN(&ctx->lfn, batch->head.point.lfn);
        gbp_unsafe_redo_check(session);
    }
}

/* when GBP enabled, analyze standby redo log batch */
void rcy_analysis_batch(knl_session_t *session, log_batch_t *batch)
{
    knl_instance_t *kernel = session->kernel;
    log_context_t *ctx = &kernel->redo_ctx;
    gbp_aly_ctx_t *aly = &kernel->gbp_aly_ctx;
    log_cursor_t cursor;

    rcy_init_log_cursor(&cursor, batch);

    /* need set analysis lfn before analysis groups */
    DB_SET_LFN(&ctx->analysis_lfn, batch->head.point.lfn);

    log_group_t *group = log_fetch_group(ctx, &cursor);
    while (group != NULL) {
        rcy_analysis_group(session, ctx, group);

        if (aly->is_closing) {
            return;
        }
        group = log_fetch_group(ctx, &cursor);
    }
}

uint64 rcy_fetch_batch_lsn(knl_session_t *session, log_batch_t *batch)
{
    knl_instance_t *kernel = session->kernel;
    log_context_t *ctx = &kernel->redo_ctx;
    log_cursor_t cursor;

    rcy_init_log_cursor(&cursor, batch);

    log_group_t *group = log_fetch_group(ctx, &cursor);

    knl_panic_log(group != NULL, "the group is NULL.");
    return group->lsn;
}

bool32 rcy_validate_batch(log_batch_t *batch, log_batch_tail_t *tail)
{
    if (batch->head.magic_num == LOG_MAGIC_NUMBER && tail->magic_num == LOG_MAGIC_NUMBER &&
        batch->head.point.lfn == tail->point.lfn && batch->size != 0 &&
        batch->raft_index != CT_INVALID_ID64) {
        return CT_TRUE;
    }
    return CT_FALSE;
}

static inline void rcy_next_file(knl_session_t *session, log_point_t *point, bool32 *need_more_log)
{
    log_context_t *ctx = &session->kernel->redo_ctx;
    reset_log_t *reset_log = &session->kernel->db.ctrl.core.resetlogs;
    database_t *db = &session->kernel->db;
    lrcv_context_t *lrcv = &session->kernel->lrcv_ctx;

    if (!lrcv->wait_info.waiting && LOG_POINT_FILE_EQUAL(*point, ctx->files[ctx->curr_file].head)) {
        *need_more_log = (db->status != DB_STATUS_RECOVERY) && db->status != DB_STATUS_REDO_ANALYSIS;
    } else if (point->rst_id < reset_log->rst_id &&
               point->asn == reset_log->last_asn &&
               (uint64)point->lfn == reset_log->last_lfn) {
        point->rst_id++;
        point->asn++;
        point->block_id = 0;
        *need_more_log = CT_TRUE;
    } else if (!SESSION_IS_LOG_ANALYZE(session) && session->kernel->rcy_ctx.loading_curr_file) {
        *need_more_log = CT_TRUE;
    } else if (SESSION_IS_LOG_ANALYZE(session) && session->kernel->gbp_aly_ctx.loading_curr_file) {
        *need_more_log = CT_TRUE;
    } else {
        point->asn++;
        point->block_id = 0;
        *need_more_log = CT_TRUE;
        CT_LOG_RUN_INF("[RCY] Move log point to [%u-%u/%u/%llu]",
                       (uint32)point->rst_id, point->asn, point->block_id, (uint64)point->lfn);
    }
}

static bool32 rcy_prepare_standby_batch(knl_session_t *session, log_point_t *point, log_batch_t *batch,
                                        bool32 *need_more_log)
{
    uint32 file_id;
    log_file_t *file = NULL;
    database_t *db = &session->kernel->db;
    reset_log_t *rst_log = &db->ctrl.core.resetlogs;

    if (point->rst_id >= rst_log->rst_id || batch->head.point.lfn <= rst_log->last_lfn) {
        return CT_TRUE;
    }

    /*
     * point->rst_id < rst_log->rst_id && batch->head.point.lfn > rst_log->last_lfn
     * We should reset file write_pos and update next batch point.
     */
    CT_LOG_RUN_INF("[RCY] find useless batch at point [%u-%u/%u/%llu] in %s recovery, rstlog [%u-%u/%llu]",
                   point->rst_id, point->asn, point->block_id, (uint64)point->lfn,
                   (db->status == DB_STATUS_RECOVERY) ? "rcy" : "lrpl",
                   rst_log->rst_id, rst_log->last_asn, rst_log->last_lfn);

    /* maxrst_id <= 2^18, cannot oveflow */
    file_id = log_get_id_by_asn(session, (uint32)point->rst_id, point->asn, NULL);
    if (file_id != CT_INVALID_ID32) {
        file = session->kernel->redo_ctx.files + file_id;
        file->head.write_pos = (uint64)point->block_id * file->ctrl->block_size;
        log_flush_head(session, file);
        log_unlatch_file(session, file_id);
    }

    rcy_next_file(session, point, need_more_log);

    return CT_FALSE;
}

static bool32 rcy_prepare_batch(knl_session_t *session, log_point_t *point, log_batch_t *batch,
                                bool32 *need_more_log, bool32 is_analysis)
{
    database_t *db = &session->kernel->db;
    log_context_t *ctx = &session->kernel->redo_ctx;
    rcy_context_t *rcy_ctx = &session->kernel->rcy_ctx;
    log_point_t max_lrp_point;
    uint64 valid_lfn;

    if (!DB_IS_PRIMARY(db) && db->status == DB_STATUS_RECOVERY && !DB_IS_RAFT_ENABLED(session->kernel)) {
        max_lrp_point = dtc_my_ctrl(session)->lrp_point;
        if (KNL_GBP_SAFE(session->kernel) && log_cmp_point(&max_lrp_point, &ctx->gbp_lrp_point) < 0) {
            max_lrp_point = ctx->gbp_lrp_point;
        }

        /* if use gbp, it should at least recover to max{local_lrp_point, gbp_lrp_point} */
        if (!rcy_ctx->is_demoting && log_cmp_point(&max_lrp_point, point) == 0) {
            *need_more_log = CT_FALSE;
            CT_LOG_RUN_INF("standby recover no need more log.core_lrp_point[%u-%u-%u-%llu],gbp_lrp_point[%u-%u-%u-%llu]",
                           dtc_my_ctrl(session)->lrp_point.rst_id, dtc_my_ctrl(session)->lrp_point.asn,
                           dtc_my_ctrl(session)->lrp_point.block_id, (uint64)dtc_my_ctrl(session)->lrp_point.lfn,
                           ctx->gbp_lrp_point.rst_id, ctx->gbp_lrp_point.asn, ctx->gbp_lrp_point.block_id,
                           (uint64)ctx->gbp_lrp_point.lfn);
            return CT_FALSE;
        } else {
            if (batch->head.magic_num != LOG_MAGIC_NUMBER || !LFN_IS_CONTINUOUS(batch->head.point.lfn, ctx->lfn)) {
                rcy_next_file(session, point, need_more_log);
                return CT_FALSE;
            }
            return rcy_prepare_standby_batch(session, point, batch, need_more_log);
        }
    }

    valid_lfn = is_analysis ? ctx->analysis_lfn : ctx->lfn;
    if (batch->head.magic_num != LOG_MAGIC_NUMBER || !LFN_IS_CONTINUOUS(batch->head.point.lfn, valid_lfn)) {
        rcy_next_file(session, point, need_more_log);
        return CT_FALSE;
    }

    if (DB_IS_PRIMARY(db)) {
        return CT_TRUE;
    }

    return rcy_prepare_standby_batch(session, point, batch, need_more_log);
}

status_t rcy_verify_checksum(knl_session_t *session, log_batch_t *batch)
{
    uint32 cks_level = session->kernel->attr.db_block_checksum;
    uint16 org_cks;
    uint32 new_cks;
    uint64 raft_index = 0;

    if (DB_IS_CHECKSUM_OFF(session) || batch->checksum == CT_INVALID_CHECKSUM) {
        return CT_SUCCESS;
    }

    if (DB_IS_RAFT_ENABLED(session->kernel)) {
        raft_index = batch->raft_index;
        batch->raft_index = CT_INVALID_ID64;
    }

    org_cks = batch->checksum;
    batch->checksum = CT_INVALID_CHECKSUM;
    new_cks = cm_get_checksum(batch, batch->size);
    batch->checksum = org_cks;
    if (org_cks != REDUCE_CKS2UINT16(new_cks)) {
        CT_LOG_RUN_ERR("invalid batch checksum.asn %u block_id %u lfn %llu rst_id %llu "
                       "size %u org_cks %u new_cks %u checksum level %s",
                       batch->head.point.asn, batch->head.point.block_id, (uint64)batch->head.point.lfn,
                       (uint64)batch->head.point.rst_id, batch->size, org_cks, REDUCE_CKS2UINT16(new_cks),
                       knl_checksum_level(cks_level));
        CT_THROW_ERROR(ERR_CHECKSUM_FAILED, "");
        return CT_ERROR;
    }
    if (DB_IS_RAFT_ENABLED(session->kernel)) {
        batch->raft_index = raft_index;
    }

    return CT_SUCCESS;
}

/* GBP failover triggered, need skip remain redo log batchs */
static inline bool32 rcy_gbp_triggered(knl_session_t *session, bool32 *need_more_log)
{
    gbp_aly_ctx_t *aly_ctx = &session->kernel->gbp_aly_ctx;

    if (!KNL_RECOVERY_WITH_GBP(session->kernel) && knl_failover_triggered(session->kernel) &&
        aly_ctx->is_done && !aly_ctx->has_return_replay) {
        aly_ctx->has_return_replay = CT_TRUE;
        *need_more_log = CT_TRUE;
        return CT_TRUE;
    }
    return CT_FALSE;
}

static bool32 rcy_pitr_replay_end(rcy_context_t *rcy, log_batch_t *batch, log_point_t *point, bool32 *need_more_log)
{
    if (batch->scn <= rcy->max_scn) {
        return CT_FALSE;
    }

    CT_LOG_RUN_INF("[RCY] pitr replay end at point [%u-%u/%u/%llu]",
                   (uint32)point->rst_id, point->asn, point->block_id, (uint64)point->lfn);
    if (point->block_id > 1) {
        point->asn = point->asn + 1; // if block_id > 1, it means the half of current file has been replayed
    }
    *need_more_log = CT_FALSE;
    return CT_TRUE;
}

static status_t rcy_try_decrypt(knl_session_t *session, log_batch_t *batch, bool32 is_analysis)
{
    if (!batch->encrypted) {
        return CT_SUCCESS;
    }

    if (!is_analysis) {
        log_context_t *ctx = &session->kernel->redo_ctx;
        return log_decrypt(session, batch, ctx->logwr_cipher_buf, ctx->logwr_cipher_buf_size);
    } else {
        gbp_aly_ctx_t *aly_ctx = &session->kernel->gbp_aly_ctx;
        return log_decrypt(session, batch, aly_ctx->log_decrypt_buf.aligned_buf, (uint32)aly_ctx->log_decrypt_buf.buf_size);
    }
}

void rcy_set_points(knl_session_t *session, log_point_t *point, bool32 is_analysis, bool32 paral_rcy)
{
    if (!is_analysis) {
        if (!paral_rcy) {
            ckpt_set_trunc_point(session, point);
            gbp_queue_set_trunc_point(session, point);
        }
        log_reset_point(session, point);
    } else {
        log_reset_analysis_point(session, point);
    }
}

status_t rcy_replay(knl_session_t *session, log_point_t *point, uint32 data_size_input, log_batch_t *batch,
    uint32 block_size, bool32 *need_more_log, bool32 *replay_fail, bool32 is_analysis)
{
    rcy_context_t *rcy = &session->kernel->rcy_ctx;
    log_batch_tail_t *tail = (log_batch_tail_t *)((char *)batch + batch->size - sizeof(log_batch_tail_t));
    uint32 data_size = data_size_input;
    bool32 first_batch = CT_TRUE;
    bool32 thread_closing = CT_FALSE;

    CM_SET_VALUE_IF_NOTNULL(replay_fail, CT_FALSE);

    if (data_size == 0) {
        rcy_next_file(session, point, need_more_log);
        return CT_SUCCESS;
    }

    while (data_size >= sizeof(log_batch_t)) {
        if (!rcy_prepare_batch(session, point, batch, need_more_log, is_analysis)) {
            CM_SET_VALUE_IF_NOTNULL(replay_fail, CT_TRUE);
            return CT_SUCCESS;
        }

        if (data_size < batch->space_size) {
            if (first_batch) {
                *need_more_log = CT_FALSE;
                CM_SET_VALUE_IF_NOTNULL(replay_fail, CT_TRUE);
                CT_LOG_RUN_ERR("recovery failed, invalid batch(%u,%u).", point->asn, point->block_id);
                return CT_SUCCESS;
            }
            *need_more_log = CT_TRUE;
            return CT_SUCCESS;
        }

        if (rcy_gbp_triggered(session, need_more_log)) {
            return CT_SUCCESS;
        }

        if (!LFN_IS_CONTINUOUS(batch->head.point.lfn, point->lfn)) {
            *need_more_log = CT_FALSE;
            CM_SET_VALUE_IF_NOTNULL(replay_fail, CT_TRUE);
            CT_LOG_RUN_ERR("recovery failed, invalid batch lfn(%llu:%llu).", (uint64)batch->head.point.lfn,
                           (uint64)point->lfn);
            return CT_SUCCESS;
        }

        if (rcy_pitr_replay_end(rcy, batch, point, need_more_log)) {
            return CT_SUCCESS;
        }

        if (db_terminate_lfn_reached(session, point->lfn)) {
            *need_more_log = CT_FALSE;
            CT_LOG_RUN_INF("[UPGRADE] recovery finished while lfn reach %llu", (uint64)point->lfn);
            return CT_SUCCESS;
        }

        if (!rcy_validate_batch(batch, tail)) {
            *need_more_log = CT_FALSE;
            CM_SET_VALUE_IF_NOTNULL(replay_fail, CT_TRUE);
            CT_LOG_RUN_ERR("recovery failed, invalid batch[%u-%u/%u] size %u head [%llu/%llu/%llu] tail [%llu/%llu]",
                           point->rst_id, point->asn, point->block_id, batch->size, batch->head.magic_num,
                           (uint64)batch->head.point.lfn, batch->raft_index, tail->magic_num, (uint64)tail->point.lfn);
            return CT_SUCCESS;
        }
        first_batch = CT_FALSE;
        if (rcy_verify_checksum(session, batch) != CT_SUCCESS) {
            *need_more_log = CT_FALSE;
            CM_SET_VALUE_IF_NOTNULL(replay_fail, CT_TRUE);
            CT_LOG_RUN_ERR("[RCY] recovery failed");
            return CT_SUCCESS;
        }
        if (rcy_try_decrypt(session, batch, is_analysis) != CT_SUCCESS) {
            *need_more_log = CT_FALSE;
            rcy->log_decrypt_failed = CT_TRUE;
            CM_SET_VALUE_IF_NOTNULL(replay_fail, CT_TRUE);
            CT_LOG_RUN_ERR("[RCY] recovery failed");
            return CT_SUCCESS;
        }

        point->lfn = batch->head.point.lfn;
        point->block_id += batch->space_size / block_size;
        rcy->cur_pos += batch->space_size;
        session->kernel->redo_ctx.curr_scn = batch->scn;
        if (!DB_IS_PRIMARY(&session->kernel->db)) {
            if (!is_analysis) {
                log_reset_point(session, point);
            } else {
                log_reset_analysis_point(session, point);
            }
        }

        if (!is_analysis) {
            rcy_replay_batch(session, batch);
            thread_closing = session->kernel->lrpl_ctx.is_closing;
        } else {
            rcy_analysis_batch(session, batch);
            thread_closing = session->kernel->gbp_aly_ctx.is_closing;
        }

        if (thread_closing) {
            rcy_wait_replay_complete(session);
            ckpt_set_trunc_point(session, point);
            gbp_queue_set_trunc_point(session, point);
            return CT_SUCCESS;
        }
        data_size -= batch->space_size;
        CT_LOG_DEBUG_INF("[RCY] Replay log to [%u-%u/%u/%llu], scn %llu", (uint32)point->rst_id, point->asn,
                         point->block_id, (uint64)point->lfn, session->kernel->redo_ctx.curr_scn);

        rcy_set_points(session, point, is_analysis, rcy->paral_rcy);
        session->kernel->redo_ctx.curr_replay_point = *point;

        batch = (log_batch_t *)((char *)batch + batch->space_size);
        tail = (log_batch_tail_t *)((char *)batch + batch->size - sizeof(log_batch_tail_t));
    }

    *need_more_log = CT_TRUE;
    return CT_SUCCESS;
}

status_t rcy_analysis(knl_session_t *session, log_point_t *point, uint32 data_size, log_batch_t *batch,
                      uint32 block_size, bool32 *need_more_log)
{
    return rcy_replay(session, point, data_size, batch, block_size, need_more_log, NULL, CT_TRUE);
}

/* Only when doing auto block recover(page repair), we try to find archive log from backup */
static bool32 rcy_load_backup_arch(knl_session_t *session, uint32 asn, char *buf, uint32 buf_size)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    char *path = bak->record.path;
    char file_name[CT_FILE_NAME_BUFFER_SIZE] = { 0 };
    errno_t ret;

    if (!(IS_BLOCK_RECOVER(session) || IS_FILE_RECOVER(session))) {
        return CT_FALSE;
    }

     /* when repairing data file to load arch from backupset, backupset with compress or enctyption is not supported */
    if (IS_FILE_RECOVER(session) && IS_ENCTYPT_OR_COMPRESS_BACKUPSET(bak)) {
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "replaying log in backupset to repairing file",
            "backupset with compress or enctyption");
        return CT_FALSE;
    }

    bak_generate_bak_file(session, path, BACKUP_ARCH_FILE, 0, asn, 0, file_name);

    if (cm_exist_device(cm_device_type(file_name), file_name)) {
        ret = strcpy_sp(buf, buf_size, file_name);
        knl_securec_check(ret);
        CT_LOG_DEBUG_INF("[ABR] find backup archive log %s", file_name);
        return CT_TRUE;
    }

    for (uint32 i = 0; i < bak->depend_num; i++) {
        path = bak->depends[i].file_dest;
        bak_generate_bak_file(session, path, BACKUP_ARCH_FILE, 0, asn, 0, file_name);
        if (cm_exist_device(cm_device_type(file_name), file_name)) {
            ret = strcpy_sp(buf, buf_size, file_name);
            knl_securec_check(ret);
            CT_LOG_DEBUG_INF("[ABR] find backup archive log %s", file_name);
            return CT_TRUE;
        }
    }

    return CT_FALSE;
}

static status_t rcy_init_compress(knl_session_t *session, arch_file_t *file)
{
    CT_LOG_RUN_INF("[RCY] arc compressed log %s", file->name);
    rcy_context_t *rcy_ctx = &session->kernel->rcy_ctx;
    rcy_ctx->cur_pos = 0;
    rcy_ctx->write_len = 0;
    rcy_ctx->cmp_file_offset = (int64)file->head.block_size;
    if (knl_compress_alloc(file->head.cmp_algorithm, &rcy_ctx->cmp_ctx, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (knl_compress_init(file->head.cmp_algorithm, &rcy_ctx->cmp_ctx, CT_FALSE) != CT_SUCCESS) {
        knl_compress_free(file->head.cmp_algorithm, &rcy_ctx->cmp_ctx, CT_FALSE);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t rcy_is_arch_compressed(arch_file_t *file, bool32 *is_compress)
{
    *is_compress = CT_FALSE;
    if (file->head.cmp_algorithm == COMPRESS_NONE) {
        return CT_SUCCESS;
    }
    if (file->head.cmp_algorithm != COMPRESS_ZSTD) {
        CT_LOG_RUN_ERR("arch compressed mode expected compress algorithm is zstd, actual is %s",
            bak_compress_algorithm_name(file->head.cmp_algorithm));
        CT_THROW_ERROR(ERR_BACKUP_RESTORE, "recovery check arch compress algorithm",
            "arch compressed mode expected compress algorithm is zstd, actual is zlib or lz4");
        return CT_ERROR;
    }
    *is_compress = CT_TRUE;
    return CT_SUCCESS;
}

status_t rcy_load_arch(knl_session_t *session, uint32 rst_id, uint32 asn, arch_file_t *file, bool32 *is_compress)
{
    char file_name[CT_FILE_NAME_BUFFER_SIZE];
    bak_t *bak = &session->kernel->backup_ctx.bak;
    device_type_t type = cm_device_type(file->name);
    bool32 is_dbstor = cm_dbs_is_enable_dbs();

    if (!arch_get_archived_log_name(session, rst_id, asn, ARCH_DEFAULT_DEST, file_name, CT_FILE_NAME_BUFFER_SIZE,
                                    session->kernel->id)) {
        if (is_dbstor) {
            if (arch_switch_archfile_trigger(session, CT_TRUE) != CT_SUCCESS) {
                CT_LOG_RUN_ERR("[BACKUP] faile switch archfile");
                return CT_ERROR;
            }
            if (!arch_get_archived_log_name(session, rst_id, asn, ARCH_DEFAULT_DEST, file_name,
                                            CT_FILE_NAME_BUFFER_SIZE, session->kernel->id)) {
                CT_LOG_RUN_ERR("[RECOVERY] failed to get archived log file[%u-%u]", rst_id, asn);
                return CT_ERROR;
            }
        } else {
            arch_set_archive_log_name(session, rst_id, asn, ARCH_DEFAULT_DEST, file_name, CT_FILE_NAME_BUFFER_SIZE,
                                      session->kernel->id);
            if (!cm_exist_device(type, file_name)) {
                if (BAK_IS_UDS_DEVICE(bak)) {
                    CT_LOG_RUN_ERR("[RECOVERY] failed to get archived log file[%u-%u]", rst_id, asn);
                    CT_THROW_ERROR(ERR_BACKUP_RESTORE, "repair", "because the lost of rcy point log");
                    return CT_ERROR;
                } else if (!rcy_load_backup_arch(session, asn, file_name, CT_FILE_NAME_BUFFER_SIZE)) {
                    CT_LOG_RUN_ERR("[RECOVERY] failed to get archived log file[%u-%u]", rst_id, asn);
                    return CT_ERROR;
                }
            }
        }
    }

    if (strcmp(file->name, file_name) == 0) {
        return rcy_is_arch_compressed(file, is_compress);
    }

    if (file->handle != CT_INVALID_HANDLE) {
        cm_close_device(type, &file->handle);
    }

    errno_t ret = strcpy_sp(file->name, CT_FILE_NAME_BUFFER_SIZE, file_name);
    knl_securec_check(ret);
    /* file->handle is closed in rcy_close_file */
    if (log_get_file_head(file->name, &file->head) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (log_verify_head_checksum(session, &file->head, file->name) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (rcy_is_arch_compressed(file, is_compress) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (cm_open_device(file->name, type, knl_arch_io_flag(session, *is_compress), &file->handle) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RECOVERY] failed to open %s", file->name);
        return CT_ERROR;
    }

    if (!*is_compress) {
        return CT_SUCCESS;
    }

    return rcy_init_compress(session, file);
}

static void rcy_move_buf_data(rcy_context_t *rcy_ctx)
{
    if (rcy_ctx->cur_pos == 0) {
        return;
    }
    char *buf = rcy_ctx->read_buf.aligned_buf;
    uint32 data_len = rcy_ctx->write_len - rcy_ctx->cur_pos;
    if (data_len != 0) {
        errno_t ret = memmove_s(buf, (size_t)rcy_ctx->read_buf.buf_size, buf + rcy_ctx->cur_pos, data_len);
        knl_securec_check(ret);
    }
    rcy_ctx->cur_pos = 0;
    rcy_ctx->write_len = data_len;
}

static status_t rcy_deal_first_arch_file(rcy_context_t *rcy_ctx, log_point_t *point,
    knl_compress_t *cmp_ctx, arch_file_t *file)
{
    int64 targe_pos = point->block_id * file->head.block_size - file->head.block_size;
    aligned_buf_t *cmp_read_buf = &rcy_ctx->cmp_read_buf;
    aligned_buf_t *batch_buf = &rcy_ctx->read_buf;
    rcy_ctx->cur_arc_read_pos = 0;
    int32 read_size;
    for (;;) {
        CT_LOG_DEBUG_INF("[RECOVERY] seek log file %s to %lld", file->name, rcy_ctx->cmp_file_offset);
        if (cm_read_device_nocheck(cm_device_type(file->name), file->handle, rcy_ctx->cmp_file_offset,
                                   cmp_read_buf->aligned_buf, (int32)CT_ARC_COMPRESS_BUFFER_SIZE,
                                   &read_size) != CT_SUCCESS) {
            return CT_ERROR;
        }
        CT_LOG_DEBUG_INF("[RECOVERY] read log file %s with %d", file->name, read_size);

        if (read_size == 0) {
            knl_compress_free(file->head.cmp_algorithm, cmp_ctx, CT_FALSE);
            rcy_ctx->is_first_arch_file = CT_FALSE;
            rcy_ctx->write_len = 0;
            return CT_SUCCESS;
        }
        rcy_ctx->cmp_file_offset += read_size;
        knl_compress_set_input(file->head.cmp_algorithm, cmp_ctx, cmp_read_buf->aligned_buf, (uint32)read_size);
        CT_LOG_DEBUG_INF("[RECOVERY] read log file %s set input with %d", file->name, read_size);
        cmp_ctx->finished = CT_FALSE;
        while (!cmp_ctx->finished) {
            if (knl_decompress(file->head.cmp_algorithm, cmp_ctx, CT_FALSE, batch_buf->aligned_buf,
                (uint32)batch_buf->buf_size) != CT_SUCCESS) {
                return CT_ERROR;
            }
            rcy_ctx->cur_arc_read_pos += cmp_ctx->write_len;
            CT_LOG_DEBUG_INF("[RECOVERY] decompress log file %s with %d to %u read %lld target pos %lld",
                file->name, read_size, cmp_ctx->write_len, rcy_ctx->cur_arc_read_pos, targe_pos);
            if (rcy_ctx->cur_arc_read_pos >= targe_pos) {
                rcy_ctx->cmp_file_offset = rcy_ctx->cmp_file_offset - read_size + cmp_ctx->zstd_in_buf.pos;
                break;
            }
        }
        if (rcy_ctx->cur_arc_read_pos >= targe_pos) {
            break;
        }
    }
    /* len <= 64M, (uint32)size cannot overflow */
    uint32 len = (uint32)(rcy_ctx->cur_arc_read_pos - targe_pos);
    uint32 start = rcy_ctx->cmp_ctx.write_len - len;
    char *buf = rcy_ctx->read_buf.aligned_buf;
    errno_t ret = memmove_s(buf, (size_t)rcy_ctx->read_buf.buf_size, buf + start, len);
    rcy_ctx->write_len = len;
    knl_securec_check(ret);

    rcy_ctx->is_first_arch_file = CT_FALSE;
    return CT_SUCCESS;
}

static status_t rcy_load_arch_compressed_file(knl_session_t *session, log_point_t *point,
    uint32 *data_size, arch_file_t *arch_file)
{
    rcy_context_t *rcy_ctx = &session->kernel->rcy_ctx;
    knl_compress_t *cmp_ctx = &rcy_ctx->cmp_ctx;
    arch_file_t *file = &rcy_ctx->arch_file;
    aligned_buf_t *cmp_read_buf = &rcy_ctx->cmp_read_buf;
    aligned_buf_t *batch_buf = &rcy_ctx->read_buf;
    log_batch_t *batch = NULL;
    int32 read_size;

    if (rcy_ctx->is_first_arch_file) {
        if (cm_aligned_realloc(CT_MAX_BATCH_SIZE, "rcy", batch_buf) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)CT_MAX_BATCH_SIZE, "rcy");
            return CT_ERROR;
        }
        if (rcy_deal_first_arch_file(rcy_ctx, point, cmp_ctx, file) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    rcy_move_buf_data(rcy_ctx);

    do {
        CT_LOG_DEBUG_INF("[RECOVERY] seek log file %s to %lld", file->name, rcy_ctx->cmp_file_offset);
        if (cm_read_device_nocheck(cm_device_type(file->name), file->handle, rcy_ctx->cmp_file_offset,
                                   cmp_read_buf->aligned_buf, (int32)CT_ARC_COMPRESS_BUFFER_SIZE,
                                   &read_size) != CT_SUCCESS) {
            return CT_ERROR;
        }
        CT_LOG_DEBUG_INF("[RECOVERY] read log file %s with %d", file->name, read_size);
        if (read_size == 0) {
            knl_compress_free(file->head.cmp_algorithm, cmp_ctx, CT_FALSE);
            *data_size = rcy_ctx->write_len;
            return CT_SUCCESS;
        }
        knl_compress_set_input(file->head.cmp_algorithm, cmp_ctx, cmp_read_buf->aligned_buf, (uint32)read_size);
        CT_LOG_DEBUG_INF("[RECOVERY] read log file %s set input with %d", file->name, read_size);
        if (knl_decompress(file->head.cmp_algorithm, cmp_ctx, CT_FALSE, batch_buf->aligned_buf + rcy_ctx->write_len,
            (uint32)batch_buf->buf_size - rcy_ctx->write_len) != CT_SUCCESS) {
            return CT_ERROR;
        }
        CT_LOG_DEBUG_INF("[RECOVERY] decompress log file %s with %d to %u", file->name, read_size, cmp_ctx->write_len);
        rcy_ctx->cmp_file_offset = rcy_ctx->cmp_file_offset + cmp_ctx->zstd_in_buf.pos;
        rcy_ctx->write_len += cmp_ctx->write_len;
        *data_size = rcy_ctx->write_len;
        batch = (log_batch_t *)rcy_ctx->read_buf.aligned_buf;
    } while (*data_size < batch->space_size);
    return CT_SUCCESS;
}

status_t rcy_load_arch_file(knl_session_t *session, log_point_t *point, uint32 *data_size,
    arch_file_t *file, aligned_buf_t *align_buf)
{
    uint64 buf_size = (uint64)align_buf->buf_size;
    char *buf = align_buf->aligned_buf;

    if (file->head.write_pos < (uint64)point->block_id * file->head.block_size) {
        *data_size = 0;
        return CT_SUCCESS;
    }

    uint64 size = file->head.write_pos - (uint64)point->block_id * file->head.block_size;
    if (size > buf_size) {
        size = buf_size;
    }

    int64 offset = (int64)point->block_id * file->head.block_size;
    /* size <= buf_size, (int32)size cannot overflow */
    if (cm_read_device(cm_device_type(file->name), file->handle, offset, buf, (int32)size) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RECOVERY] failed to read %s, offset %llu", file->name,
                       (uint64)point->block_id * file->head.block_size);
        rcy_close_file(session);
        return CT_ERROR;
    }

    *data_size = (uint32)size;

    return CT_SUCCESS;
}

status_t rcy_load_from_arch(knl_session_t *session, log_point_t *point, uint32 *data_size,
    arch_file_t *file, aligned_buf_t *align_buf)
{
    rcy_context_t *rcy_ctx = &session->kernel->rcy_ctx;
    
    bool32 is_compress = CT_FALSE;
    if (rcy_load_arch(session, (uint32)point->rst_id, point->asn, file, &is_compress) != CT_SUCCESS)  { /* max rst_id <= 2^18, cannot overflow */
        rcy_close_file(session);
        return CT_ERROR;
    }

    if (point->block_id == 0) {
        point->block_id = 1;
    }

    if (is_compress) {
        if (rcy_load_arch_compressed_file(session, point, data_size, file) != CT_SUCCESS) {
            knl_compress_free(file->head.cmp_algorithm, &rcy_ctx->cmp_ctx, CT_FALSE);
            rcy_close_file(session);
            return CT_ERROR;
        }
    } else {
        if (rcy_load_arch_file(session, point, data_size, file, align_buf) != CT_SUCCESS) {
            rcy_close_file(session);
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

status_t rcy_load_from_online(knl_session_t *session, uint32 file_id, log_point_t *point, uint32 *data_size,
                              int32 *handle, aligned_buf_t *align_buf)
{
    uint64 size;
    uint64 buf_size = (uint64)align_buf->buf_size;
    log_context_t *ctx = &session->kernel->redo_ctx;
    log_file_t *file = &ctx->files[file_id];
    bak_t *bak = &session->kernel->backup_ctx.bak;
    char *buf = align_buf->aligned_buf;

    if (point->block_id == 0) {
        point->block_id = 1;
    }

    if (session->kernel->db.status == DB_STATUS_RECOVERY || session->kernel->db.status == DB_STATUS_REDO_ANALYSIS ||
        (bak->is_building && bak->record.attr.level == 1) || bak->record.is_repair) {
        size = (uint64)file->ctrl->size;
        if ((int64)point->block_id * file->ctrl->block_size + (int64)buf_size > file->ctrl->size) {
            size = (uint64)file->ctrl->size - (uint64)point->block_id * file->ctrl->block_size;
        }
    } else {
        size = file->head.write_pos - (uint64)point->block_id * file->ctrl->block_size;
    }

    if (size == 0) {
        *data_size = 0;
        log_unlatch_file(session, file_id);
        return CT_SUCCESS;
    }

    if (size > buf_size) {
        size = buf_size;
    }

    if (cm_open_device(file->ctrl->name, file->ctrl->type, knl_redo_io_flag(session), handle) != CT_SUCCESS) {
        log_unlatch_file(session, file_id);
        CT_LOG_RUN_ERR("[RECOVERY] failed to open %s", file->ctrl->name);
        return CT_ERROR;
    }
    /* size <= buf_size, (uint32)size cannot overflow */
    if (cm_read_device(file->ctrl->type, *handle, (int64)point->block_id * file->ctrl->block_size, buf,
                       (uint32)size) != CT_SUCCESS) {
        log_unlatch_file(session, file_id);
        CT_LOG_RUN_ERR("[RECOVERY] failed to read %s, offset %u", file->ctrl->name, point->block_id);
        cm_close_device(file->ctrl->type, handle);
        return CT_ERROR;
    }

    *data_size = (uint32)size;
    log_unlatch_file(session, file_id);
    return CT_SUCCESS;
}

static inline bool32 rcy_group_pages_preloaded(rcy_context_t *rcy, uint32 group_id)
{
    if (rcy->preload_proc_num == 0) {
        return CT_TRUE;
    }

    uint32 min = rcy->preload_info[0].group_id;
    for (uint32 i = 1; i < rcy->preload_proc_num; i++) {
        min = (min < rcy->preload_info[i].group_id) ? min : rcy->preload_info[i].group_id;
    }
    return (min > group_id);
}

void rcy_perform(knl_session_t *session, rcy_bucket_t *bucket, uint64 *rcy_perform_work_time)
{
    log_context_t *ctx = &session->kernel->redo_ctx;
    rcy_context_t *rcy = &session->kernel->rcy_ctx;
    rcy_paral_group_t *ctrl = NULL;

    if (bucket->head == bucket->tail) {
        rcy_flexible_sleep(session, rcy, bucket);
        return;
    }

    cm_spin_lock(&bucket->lock, NULL);
    if (SECUREC_UNLIKELY(bucket->head == bucket->tail)) {
        cm_spin_unlock(&bucket->lock);
        return;
    }
    ctrl = bucket->first[bucket->head];
    cm_spin_unlock(&bucket->lock);

    bucket->last_replay_time = g_timer()->now;
    if (!rcy_group_pages_preloaded(rcy, ctrl->id)) {
        rcy_flexible_sleep(session, rcy, NULL);
        return;
    }

    timeval_t calc_work_time;
    ELAPSED_BEGIN(calc_work_time);

    if (rcy_paral_replay_group(session, bucket, ctx, ctrl) != CT_SUCCESS) {
        return;
    }
    rcy_release_lock_pages(session, ctrl);

    if (session->kernel->attr.clustered) {
        dtc_rcy_atomic_dec_group_num(session, ctrl->group_list_idx, 1);
    }

    if (bucket->head != bucket->tail) {
        bucket->head = (bucket->head + 1) % bucket->count;
    }
    ELAPSED_END(calc_work_time, *rcy_perform_work_time);
}

static void rcy_release_session(knl_session_t *session)
{
    g_knl_callback.release_knl_session(session);
}

static void rcy_bucket_stat_update(rcy_bucket_t *bucket, uint64 rcy_disk_read, uint64 rcy_disk_read_time,
                                   uint64 work_time, uint64 used_time)
{
    bucket->rcy_stat.rcy_read_disk_page_num = rcy_disk_read;
    bucket->rcy_stat.rcy_read_disk_total_time = rcy_disk_read_time;
    bucket->rcy_stat.rcy_read_disk_avg_time = (rcy_disk_read == 0 ? 0 : rcy_disk_read_time / rcy_disk_read);
    bucket->rcy_stat.session_work_time = work_time;
    bucket->rcy_stat.session_used_time = used_time;
    bucket->rcy_stat.session_util_rate = (100.0 * work_time / (used_time + 1));
}

void rcy_proc(thread_t *thread)
{
    rcy_bucket_t *bucket = (rcy_bucket_t *)thread->argument;
    knl_session_t *session = bucket->session;
    rcy_context_t *rcy = &session->kernel->rcy_ctx;
    uint32 sid = session->id;
    uint64 used_time;
    uint64 work_time = 0;
    uint64 rcy_disk_read_time = session->stat->disk_read_time;
    uint64 rcy_disk_read = session->stat->disk_reads;

    CT_LOG_DEBUG_INF("[DTC RCY] rcy_paral_proc start. session_id:%u", sid);

    cm_set_thread_name("rcy_proc");
    KNL_SESSION_SET_CURR_THREADID(session, cm_get_current_thread_id());
    for (;;) {
        uint64 rcy_perform_work_time = 0;
        if (thread->closed && bucket->head == bucket->tail) {
            break;
        }
        if (session->kernel->rcy_ctx.rcy_end) {
            rcy_replay_group_end(session);
            break;
        }
        rcy_perform(session, bucket, &rcy_perform_work_time);
        work_time += rcy_perform_work_time;
    }

    rcy_disk_read_time = session->stat->disk_read_time - rcy_disk_read_time;
    rcy_disk_read = session->stat->disk_reads - rcy_disk_read;
    ELAPSED_END(rcy->paral_rcy_thread_start_work_time, used_time);

    rcy_bucket_stat_update(bucket, rcy_disk_read, rcy_disk_read_time, work_time, used_time);
    rcy_release_session(session);
    KNL_SESSION_CLEAR_THREADID(session);

    CT_LOG_RUN_INF("[DTC RCY] rcy_paral_proc end. session_id:%u, work_time(us):%llu, life_cycle(us):%llu,"
        " rate of utilization:%u%%, read_page_num:%llu, total_time(us):%llu, ave_time(us):%llu, "
        "sleep_time_in_log_add_bucket=%llu, session_replay_log_group_count=%llu,wait_cond_time=%llu",
        sid, work_time, used_time, bucket->rcy_stat.session_util_rate, rcy_disk_read, rcy_disk_read_time,
        bucket->rcy_stat.rcy_read_disk_avg_time, bucket->rcy_stat.sleep_time_in_log_add_bucket,
        bucket->rcy_stat.session_replay_log_group_count, bucket->rcy_stat.wait_cond_time);
}

static status_t rcy_alloc_buffer(rcy_context_t *rcy)
{
    rcy->buf = (char *)malloc(CT_RCY_BUF_SIZE); // 4M
    if (rcy->buf == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)CT_RCY_BUF_SIZE, "bucket");
        return CT_ERROR;
    }
    errno_t ret = memset_sp(rcy->buf, CT_RCY_BUF_SIZE, 0, CT_RCY_BUF_SIZE);
    knl_securec_check(ret);

    rcy->group_list = (rcy_paral_group_t *)malloc(CT_MAX_BATCH_SIZE); // 64M
    if (rcy->group_list == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, CT_MAX_BATCH_SIZE, "group list");
        CM_FREE_PTR(rcy->buf);
        return CT_ERROR;
    }
    ret = memset_sp(rcy->group_list, CT_MAX_BATCH_SIZE, 0, CT_MAX_BATCH_SIZE);
    knl_securec_check(ret);

    rcy->page_bucket = (rcy_page_bucket_t *)malloc(sizeof(rcy_page_bucket_t) * CT_RCY_MAX_PAGE_COUNT); // 32M
    if (rcy->page_bucket == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, sizeof(rcy_page_bucket_t) * CT_RCY_MAX_PAGE_COUNT, "page bucket");
        CM_FREE_PTR(rcy->buf);
        CM_FREE_PTR(rcy->group_list);
        return CT_ERROR;
    }
    ret = memset_sp(rcy->page_bucket, CT_RCY_MAX_PAGE_COUNT * sizeof(rcy_page_bucket_t), 0,
                    sizeof(rcy_page_bucket_t) * CT_RCY_MAX_PAGE_COUNT);
    knl_securec_check(ret);

    rcy->page_bitmap = (uint16 *)malloc(sizeof(uint16) * CT_RCY_MAX_PAGE_BITMAP_LEN); // 512K
    if (rcy->page_bitmap == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, sizeof(uint16) * CT_RCY_MAX_PAGE_BITMAP_LEN, "page bucket");
        CM_FREE_PTR(rcy->buf);
        CM_FREE_PTR(rcy->group_list);
        CM_FREE_PTR(rcy->page_bucket);
        return CT_ERROR;
    }
    ret = memset_sp(rcy->page_bitmap, sizeof(uint16) * CT_RCY_MAX_PAGE_BITMAP_LEN, 0,
                    sizeof(uint16) * CT_RCY_MAX_PAGE_BITMAP_LEN);
    knl_securec_check(ret);

    ret = memset_sp(rcy->page_list, RCY_PAGE_LIST_BITMAP_LEN * sizeof(rcy_page_t *),
                    0, RCY_PAGE_LIST_BITMAP_LEN * sizeof(rcy_page_t *));
    knl_securec_check(ret);
    return CT_SUCCESS;
}

void rcy_free_buffer(rcy_context_t *rcy)
{
    CM_FREE_PTR(rcy->buf);
    CM_FREE_PTR(rcy->group_list);
    CM_FREE_PTR(rcy->page_bucket);
    CM_FREE_PTR(rcy->page_bitmap);
    for (uint32 i = 0; i < RCY_PAGE_LIST_BITMAP_LEN; i++) {
        CM_FREE_PTR(rcy->page_list[i]);
    }
}

status_t rcy_init_context(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    rcy_context_t *rcy = &kernel->rcy_ctx;
    if (!rcy->paral_rcy) {
        return CT_SUCCESS;
    }

    if (rcy_alloc_buffer(rcy) != CT_SUCCESS) {
        return CT_ERROR;
    }
    rcy->page_list_bitmap = 0;
    rcy->abr_rcy_flag = CT_FALSE;
    rcy->abr_pagid = INVALID_PAGID;
    CT_LOG_RUN_INF("[RCY] init context finish");
    return CT_SUCCESS;
}

// load redo log from log files from the given recovery point offset.
status_t rcy_load(knl_session_t *session, log_point_t *point, uint32 *data_size, uint32 *block_size)
{
    uint32 file_id;
    rcy_context_t *rcy_ctx = &session->kernel->rcy_ctx;
    log_context_t *ctx = &session->kernel->redo_ctx;
    status_t status;

    if (session->kernel->rcy_ctx.paral_rcy) {
        rcy_wait_replay_complete(session);
    }

    if (IS_BLOCK_RECOVER(session) && rcy_ctx->abr_db_status == DB_STATUS_OPEN) {
        status = rcy_load_from_arch(session, point, data_size, &rcy_ctx->arch_file, &rcy_ctx->read_buf);
        *block_size = (uint32)rcy_ctx->arch_file.head.block_size;
        return status;
    }

    log_lock_logfile(session);
    file_id = log_get_id_by_asn(session, (uint32)point->rst_id, point->asn,
                                &rcy_ctx->loading_curr_file); /* max rst_id <= 2^18, cannot oveflow */
    log_unlock_logfile(session);
    if (file_id != CT_INVALID_ID32) {
        /* rcy_ctx->read_buf.buf_size <= 64M, cannot oveflow */
        status = rcy_load_from_online(session, file_id, point, data_size, rcy_ctx->handle + file_id,
                                      &rcy_ctx->read_buf);
        *block_size = ctx->files[file_id].ctrl->block_size;
    } else {
        status = rcy_load_from_arch(session, point, data_size, &rcy_ctx->arch_file, &rcy_ctx->read_buf);
        *block_size = (uint32)rcy_ctx->arch_file.head.block_size;
    }
    return status;
}
void rcy_init_callback_proc(log_context_t *ctx)
{
    for (uint32 i = 0; i < LMGR_COUNT; i++) {
        ctx->replay_procs[g_lmgrs[i].type] = g_lmgrs[i].replay_proc;
        ctx->analysis_procs[g_lmgrs[i].type] = g_lmgrs[i].analysis_proc;
        ctx->verify_page_format_proc[g_lmgrs[i].type] = g_lmgrs[i].verify_page_format_proc;
        ctx->verify_nolog_insert_proc[g_lmgrs[i].type] = g_lmgrs[i].verify_nolog_insert_proc;
        ctx->stop_backup_proc[g_lmgrs[i].type] = g_lmgrs[i].stop_backup_proc;
        knl_panic_log(g_lmgrs[i].analysis_proc != NULL, "current analysis_proc is NULL.");
    }
}

status_t rcy_init(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    log_context_t *ctx = &kernel->redo_ctx;
    rcy_context_t *rcy = &kernel->rcy_ctx;

    errno_t ret = memset_sp(rcy, sizeof(rcy_context_t), 0, sizeof(rcy_context_t));
    knl_securec_check(ret);

    rcy_eventfd_init(rcy);

    rcy->capacity = CT_DEFAULT_PARAL_RCY;
    for (uint32 i = 0; i < RCY_WAIT_STATS_COUNT; i++) {
        rcy->wait_stats_view[i] = 0;
    }

    rcy_init_callback_proc(ctx);
    rcy->paral_rcy = CT_FALSE;
    if (kernel->attr.log_replay_processes > CT_DEFAULT_PARAL_RCY) {
        rcy->paral_rcy = CT_TRUE;
        rcy->capacity = kernel->attr.log_replay_processes;
    }
    if (rcy->read_buf.alloc_buf == NULL) {
        int64 size = (int64)LOG_LGWR_BUF_SIZE(session);
        if (cm_aligned_malloc(size, "rcy", &rcy->read_buf) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    if (rcy->paral_rcy) {
        if (rcy->read_buf2.alloc_buf == NULL) {
            int64 size = (int64)LOG_LGWR_BUF_SIZE(session);
            if (cm_aligned_malloc(size, "rcy second buf", &rcy->read_buf2) != CT_SUCCESS) {
                cm_aligned_free(&rcy->read_buf);
                return CT_ERROR;
            }
        }
        rcy->swich_buf = CT_FALSE;
    }
    if (cm_aligned_malloc((int64)CT_ARC_COMPRESS_BUFFER_SIZE, "rcy process", &rcy->cmp_read_buf) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)CT_ARC_COMPRESS_BUFFER_SIZE, "rcy process");
        return CT_ERROR;
    }

    rcy->arch_file.handle = CT_INVALID_HANDLE;
    for (uint32 i = 0; i < CT_MAX_LOG_FILES; i++) {
        rcy->handle[i] = CT_INVALID_HANDLE;
    }

    rcy->max_scn = CT_INVALID_ID64;
    rcy->max_lrp_lsn = CT_INVALID_ID64;
    rcy->action = RECOVER_NORMAL;

    if (!rcy->paral_rcy || kernel->attr.clustered) {
        return CT_SUCCESS;
    }

    return rcy_init_context(session);
}

void rcy_close(knl_session_t *session)
{
    rcy_context_t *rcy = &session->kernel->rcy_ctx;

    if (session->kernel->attr.clustered) {  // TODO: double check
        // dtc_recovery_close(session);
        return;
    }

    rcy->is_closing = CT_TRUE;
    rcy_close_proc(session);
    for (;;) {
        if (!rcy->is_working) {
            break;
        }
    }
    cm_aligned_free(&rcy->cmp_read_buf);
    cm_aligned_free(&rcy->read_buf);
    cm_aligned_free(&rcy->read_buf2);
    rcy_free_buffer(rcy);
}

void rcy_close_file(knl_session_t *session)
{
    rcy_context_t *rcy_ctx = &session->kernel->rcy_ctx;
    log_context_t *redo_ctx = &session->kernel->redo_ctx;
    log_file_t *files = redo_ctx->files;
    uint32 i;

    if (SESSION_IS_LOG_ANALYZE(session)) {
        return; // gbp aly session's log file handle is closed in gbp_aly_proc
    }
    cm_close_device(cm_device_type(rcy_ctx->arch_file.name), &rcy_ctx->arch_file.handle);
    rcy_ctx->arch_file.handle = CT_INVALID_HANDLE;
    rcy_ctx->arch_file.name[0] = '\0';

    for (i = 0; i < CT_MAX_LOG_FILES; i++) {
        cm_close_device(files[i].ctrl->type, &rcy_ctx->handle[i]);
    }
}

static status_t rcy_reset_file(knl_session_t *session, log_point_t *point)
{
    knl_instance_t *kernel = session->kernel;
    log_context_t *ctx = &kernel->redo_ctx;
    log_file_t *file = NULL;

    if (log_set_file_asn(session, point->asn, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    file = &ctx->files[dtc_my_ctrl(session)->log_first];
    /* file->head.write_pos / file->head.block_size < max int32, cannot overflow */
    point->block_id = (uint32)(file->head.write_pos / (uint32)file->head.block_size);
    ctx->free_size += log_file_freesize(file);
    return CT_SUCCESS;
}

/*
 * if curr_point resides in the window (gbp_begin_point, gbp_rcy_point), we can speed up recovery by
 * moving curr_point forward to gbp_rcy_point.
 */
static void rcy_try_use_gbp(knl_session_t *session, log_point_t *curr_point)
{
    if (KNL_GBP_SAFE(session->kernel) &&
        KNL_GBP_FOR_RECOVERY(session->kernel) &&
        !KNL_RECOVERY_WITH_GBP(session->kernel) &&
        gbp_replay_in_window(session, *curr_point)) {
        if (session->kernel->rcy_ctx.paral_rcy) {
            rcy_wait_replay_complete(session);
        }

        if (KNL_GBP_SAFE(session->kernel)) { // recheck again, gbp status may set unsafe when rcy_wait_replay_complete
            gbp_knl_begin_read(session, curr_point);
        }
    }
}

static status_t rcy_analysis_all_redo(knl_session_t *session, log_point_t *curr_point)
{
    rcy_context_t *rcy = &session->kernel->rcy_ctx;
    log_batch_t *batch = NULL;
    bool32 need_more_log = CT_FALSE;
    uint32 data_size = 0;
    uint32 block_size;
    rcy->is_first_arch_file = CT_TRUE;

    while (rcy_load(session, curr_point, &data_size, &block_size) == CT_SUCCESS) {
        batch = (log_batch_t*)rcy->read_buf.aligned_buf;
        if (log_need_realloc_buf(batch, &rcy->read_buf, "rcy", CT_MAX_BATCH_SIZE)) {
            continue;
        }

        if (rcy_analysis(session, curr_point, data_size, batch, block_size, &need_more_log) != CT_SUCCESS) {
            return CT_ERROR;
        }
        if (!need_more_log) {
            break;
        }
    }

    return CT_SUCCESS;
}

/*
 * For _GBP_FOR_RECOVERY == TRUE, analyze redo log when database restart
 * then use GBP at recover stage to accelerate DB open speed
 * Notice: standby redo analysis process is gbp_aly_proc, not use this function
 */
static status_t rcy_redo_analysis(knl_session_t *session, log_point_t *curr_point)
{
    knl_instance_t *kernel = session->kernel;
    log_context_t *redo_ctx = &kernel->redo_ctx;
    log_point_t rcy_begin_point = *curr_point;
    errno_t ret;

    redo_ctx->rcy_with_gbp = CT_FALSE;
    redo_ctx->last_rcy_with_gbp = CT_FALSE;
    ret = memset_sp(&redo_ctx->redo_end_point, sizeof(log_point_t), 0, sizeof(log_point_t));
    knl_securec_check(ret);

    if (!kernel->db.recover_for_restore && KNL_GBP_ENABLE(kernel) && KNL_GBP_FOR_RECOVERY(kernel)) {
        log_reset_analysis_point(session, curr_point);
        gbp_reset_unsafe(session);
        kernel->db.status = DB_STATUS_REDO_ANALYSIS;

        CT_LOG_RUN_INF("[GBP] log analysis: from file:%u,point:%u,lfn:%llu\n",
                       curr_point->asn, curr_point->block_id, (uint64)curr_point->lfn);
        (void)cm_gettimeofday(&redo_ctx->replay_stat.analyze_begin);

        if (rcy_analysis_all_redo(session, curr_point) != CT_SUCCESS) {
            return CT_ERROR;
        }

        redo_ctx->redo_end_point = *curr_point;
        (void)cm_gettimeofday(&redo_ctx->replay_stat.analyze_end);
        redo_ctx->replay_stat.analyze_elapsed = TIMEVAL_DIFF_US(&redo_ctx->replay_stat.analyze_begin,
                                                                &redo_ctx->replay_stat.analyze_end);

        CT_LOG_RUN_INF("[GBP] log analysis: end with file:%u,point:%u,lfn:%llu\n",
                       curr_point->asn, curr_point->block_id, (uint64)curr_point->lfn);

        cm_sleep(200); // wait gbp background process connected
        if (gbp_pre_check(session, redo_ctx->redo_end_point)) {
            gbp_knl_check_end_point(session);

            CT_LOG_RUN_INF("[GBP] gbp_rcy_point: rst_id:%u,file:%u,point:%u,lfn:%llu\n",
                           (uint32)redo_ctx->gbp_rcy_point.rst_id, redo_ctx->gbp_rcy_point.asn,
                           redo_ctx->gbp_rcy_point.block_id, (uint64)redo_ctx->gbp_rcy_point.lfn);
            CT_LOG_RUN_INF("[GBP] gbp lfn gap:%llu, gbp_rcy_lfn:%llu\n",
                           (uint64)(curr_point->lfn - redo_ctx->gbp_rcy_point.lfn),
                           (uint64)redo_ctx->gbp_rcy_point.lfn);
        }
    } else {
        gbp_set_unsafe(session, RD_TYPE_END);
    }

    rcy_try_use_gbp(session, &rcy_begin_point);
    *curr_point = rcy_begin_point;
    return CT_SUCCESS;
}

status_t rcy_recover_check(knl_session_t *session, log_point_t curr_point, log_point_t lrp_point)
{
    rcy_context_t *rcy = &session->kernel->rcy_ctx;
    uint64 consistent_lfn = dtc_my_ctrl(session)->consistent_lfn;
    uint64 rcy_point_lfn = dtc_my_ctrl(session)->rcy_point.lfn;

    CT_LOG_RUN_INF("[RCY] recovery real end with file:%u,point:%u,lfn:%llu", curr_point.asn, curr_point.block_id,
        (uint64)curr_point.lfn);
    CT_LOG_RUN_INF("[RCY] current lfn %llu, rcy point lfn %llu, consistent point %llu, lrp point lfn %llu",
                   (uint64)curr_point.lfn, (uint64)rcy_point_lfn, (uint64)consistent_lfn, (uint64)lrp_point.lfn);
    if (curr_point.lfn >= lrp_point.lfn) {
        return CT_SUCCESS;
    }

    if (RCY_IGNORE_CORRUPTED_LOG(rcy)) {
        CT_LOG_RUN_WAR("[RCY] database can not recover to lrp point");
        return CT_SUCCESS;
    }

    CT_THROW_ERROR(ERR_INVALID_RCV_END_POINT,
        curr_point.asn, curr_point.block_id, lrp_point.asn, lrp_point.block_id);
    knl_panic(0);
    return CT_ERROR;
}

bool32 db_terminate_lfn_reached(knl_session_t *session, uint64 curr_lfn)
{
    database_t *db = &session->kernel->db;

    if (DB_IS_PRIMARY(db) || db->terminate_lfn == CT_INVALID_LFN) {
        return CT_FALSE;
    }
    knl_panic(curr_lfn <= db->terminate_lfn);

    return ((curr_lfn == db->terminate_lfn) ? CT_TRUE : CT_FALSE);
}

status_t rcy_recover(knl_session_t *session)
{
    log_point_t curr_point = dtc_my_ctrl(session)->rcy_point;
    log_point_t lrp_point = dtc_my_ctrl(session)->lrp_point;
    rcy_context_t *rcy = &session->kernel->rcy_ctx;
    log_context_t *log = &session->kernel->redo_ctx;
    log_batch_t *batch = NULL;
    bool32 need_more_log = CT_FALSE;
    uint32 data_size = 0;
    uint32 block_size;

    log_reset_point(session, &lrp_point);
    log_reset_analysis_point(session, &lrp_point);
    ckpt_set_trunc_point(session, &curr_point);
    gbp_queue_set_trunc_point(session, &curr_point);
    session->kernel->redo_ctx.lfn = curr_point.lfn;
    session->kernel->redo_ctx.analysis_lfn = curr_point.lfn;
    session->kernel->redo_ctx.curr_replay_point = curr_point;
    session->kernel->ckpt_ctx.trunc_lsn = (uint64)session->kernel->lsn;
    session->kernel->rcy_ctx.rcy_end = CT_FALSE;

    /* TODO: support cluster recover */
    if (session->kernel->attr.clustered) {
        return dtc_recover(session);
    }

    /* redo log analysis, if GBP is usable, move curr_point forward to gbp_rcy_point, skip some redo log */
    if (rcy_redo_analysis(session, &curr_point) != CT_SUCCESS) {
        rcy_close_file(session);
        CT_LOG_RUN_ERR("[RCY] database redo analysis failed");
        return CT_ERROR;
    }
    /* after log analysis, reset redo context */
    session->kernel->redo_ctx.lfn = curr_point.lfn;
    session->kernel->db.status = DB_STATUS_RECOVERY;
    (void)cm_gettimeofday(&log->replay_stat.replay_begin);

    CT_LOG_RUN_INF("[RCY] database start recovery");
    CT_LOG_RUN_INF("[RCY] recovery from file:%u,point:%u,lfn:%llu", curr_point.asn, curr_point.block_id,
                   (uint64)curr_point.lfn);
    CT_LOG_RUN_INF("[RCY] recovery expected least end with file:%u,point:%u,lfn:%llu", lrp_point.asn, lrp_point.block_id,
                   (uint64)lrp_point.lfn);

    rcy_init_proc(session);

    rcy->replay_no_lag = CT_FALSE;
    rcy->is_working = CT_TRUE;
    rcy->is_first_arch_file = CT_TRUE;
    while (rcy_load(session, &curr_point, &data_size, &block_size) == CT_SUCCESS) {
        if (rcy->is_closing) {
            rcy_close_file(session);
            CT_LOG_RUN_ERR("database recovery aborted");
            return CT_ERROR;
        }

        batch = (log_batch_t *)rcy->read_buf.aligned_buf;
        if (log_need_realloc_buf(batch, &rcy->read_buf, "rcy", CT_MAX_BATCH_SIZE)) {
            continue;
        }
        rcy->curr_group = rcy->group_list;
        rcy->curr_group_id = 0;
        if (rcy_replay(session, &curr_point, data_size, batch, block_size, &need_more_log, NULL, CT_FALSE) != CT_SUCCESS) {
            rcy_close_file(session);
            return CT_ERROR;
        }
        rcy_try_use_gbp(session, &curr_point);

        if (!need_more_log) {
            break;
        }
    }

    cm_spin_lock(&rcy->lock, NULL);
    rcy->is_working = CT_FALSE;

    if (rcy->is_closing) {
        cm_spin_unlock(&rcy->lock);
        rcy_close_file(session);
        CT_LOG_RUN_ERR("database recovery aborted");
        return CT_ERROR;
    }

    cm_spin_unlock(&rcy->lock);
    (void)cm_gettimeofday(&log->replay_stat.replay_end);
    log->replay_stat.replay_elapsed = TIMEVAL_DIFF_US(&log->replay_stat.replay_begin, &log->replay_stat.replay_end);

    rcy_wait_replay_complete(session);
    rcy_close_proc(session);
    rcy->rcy_end = CT_TRUE;
    rcy_close_file(session);

    /* set next generate lfn equal to the previous lfn plus 1 */
    log->buf_lfn[0] = log->lfn + 1;
    log->buf_lfn[1] = log->lfn + 2;

    if (rcy_recover_check(session, curr_point, lrp_point) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (session->kernel->db.recover_for_restore && !RCY_IGNORE_CORRUPTED_LOG(rcy)) {
        if (rcy_reset_file(session, &curr_point) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (IS_PITR_RECOVER(rcy)) {
            CT_LOG_RUN_INF("[RCY] pitr clear useless archive logs");
            arch_reset_archfile(session, curr_point.asn - 1);
        }
    } else {
        log_reset_file(session, &curr_point);
    }

    log_reset_analysis_point(session, &curr_point);
    if (KNL_GBP_ENABLE(session->kernel)) {
        gbp_reset_unsafe(session);
    }

    if (DB_IS_RAFT_ENABLED(session->kernel)) {
        session->kernel->raft_ctx.flush_point = curr_point;
        session->kernel->db.is_readonly = CT_TRUE;
        session->kernel->db.ctrl.core.db_role = REPL_ROLE_PHYSICAL_STANDBY;
    }

    ckpt_set_trunc_point(session, &log->curr_point);
    return CT_SUCCESS;
}

static status_t rcy_alloc_session(knl_instance_t *kernel, knl_session_t **session)
{
    if (g_knl_callback.alloc_knl_session(CT_TRUE, (knl_handle_t *)session) != CT_SUCCESS) {
        return CT_ERROR;
    }
    (*session)->curr_lsn = CT_INVALID_LSN;

    return CT_SUCCESS;
}

void rcy_update_preload_info(rcy_preload_info_t *info, rcy_context_t *rcy, rcy_wait_stats_e rcy_event)
{
    info->curr += rcy->preload_proc_num;
    rcy->wait_stats_view[rcy_event]++;
}

void rcy_preload_proc(thread_t *thread)
{
    rcy_preload_info_t *info = (rcy_preload_info_t *)thread->argument;
    knl_session_t *session = info->session;
    rcy_context_t *rcy = &session->kernel->rcy_ctx;
    page_id_t page_id;
    buf_ctrl_t *ctrl = NULL;
    status_t status;
    rcy_page_t *page = NULL;
    cm_set_thread_name("rcy_preload");
    KNL_SESSION_SET_CURR_THREADID(session, cm_get_current_thread_id());
    for (;;) {
        if (thread->closed) {
            break;
        }

        uint32 preload_hwm = (uint32)cm_atomic_get(&rcy->preload_hwm);
        if (preload_hwm <= info->curr) {
            info->group_id = rcy->curr_group_id;
            rcy_flexible_sleep(session, rcy, NULL);
            continue;
        }
        page = &rcy->page_list[info->curr >> RCY_PAGE_LIST_MOD_BITLEN][info->curr & PCY_PAGE_LIST_MOD_MASK];
        info->group_id = page->gid;
        if (session->kernel->db.status == DB_STATUS_OPEN && page->option & ENTER_PAGE_NO_READ) {
            rcy_update_preload_info(info, rcy, ENTER_PAGE_NO_READ);
            continue;
        }

        page_id.file = page->file;
        page_id.page = page->page;

        /* RTO = 0, disable prefetch when db is recovery from GBP */
        if (SECUREC_UNLIKELY(KNL_RECOVERY_WITH_GBP(session->kernel) || IS_INVALID_PAGID(page_id))) {
            ctrl = NULL;
            rcy_update_preload_info(info, rcy, PRELOAD_BUFFER_PAGES);
            continue;
        }

        if (page_compress(session, page_id)) {
            ctrl = buf_try_alloc_compress(session, page_id, LATCH_MODE_S, ENTER_PAGE_NORMAL, BUF_ADD_HOT);
        } else {
            ctrl = buf_try_alloc_ctrl(session, page_id, LATCH_MODE_S, ENTER_PAGE_NORMAL, BUF_ADD_HOT);
        }

        if (ctrl == NULL) {
            rcy_update_preload_info(info, rcy, PRELOAD_BUFFER_PAGES);
            continue;
        }
        knl_panic(ctrl->load_status == (uint8)BUF_NEED_LOAD);

        if (page_compress(session, page_id)) {
            status = buf_load_group(session, ctrl);
        } else {
            status = buf_load_page(session, ctrl, page_id);
        }

        if (status != CT_SUCCESS) {
            rcy_update_preload_info(info, rcy, PRELOAD_BUFFER_PAGES);
            buf_unlatch(session, ctrl, CT_TRUE);
            continue;
        }
        rcy->wait_stats_view[PRELOAD_DISK_PAGES]++;

        buf_unlatch(session, ctrl, CT_TRUE);
        info->curr += rcy->preload_proc_num;
    }

    rcy_release_session(session);
    KNL_SESSION_CLEAR_THREADID(session);
}

void rcy_init_proc(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    rcy_context_t *rcy = &kernel->rcy_ctx;
    rcy_bucket_t *bucket = NULL;
    uint32 bucket_count;
    errno_t ret;
    uint32 i = 0;
    ELAPSED_BEGIN(rcy->paral_rcy_thread_start_work_time);
    
    if (kernel->attr.log_replay_processes > CT_DEFAULT_PARAL_RCY) {
        rcy->paral_rcy = CT_TRUE;
        rcy->capacity = kernel->attr.log_replay_processes;
        rcy->preload_proc_num = kernel->attr.rcy_preload_processes;
    } else {
        rcy->paral_rcy = CT_FALSE;
        rcy->preload_proc_num = 0;
    }

    if (!rcy->paral_rcy) {
        return;
    }

    rcy->replay_no_lag = CT_FALSE;
    rcy->swich_buf = CT_FALSE;
    bucket_count = CT_RCY_BUF_SIZE / sizeof(rcy_paral_group_t *);
    rcy->page_list_count = 0;
    rcy->preload_hwm = 0;
    rcy->rcy_end = CT_FALSE;
    ret = memset_s(rcy->page_bucket, (uint32)(CT_RCY_MAX_PAGE_COUNT * sizeof(rcy_page_bucket_t)), 0,
                   sizeof(rcy_page_bucket_t) * CT_RCY_MAX_PAGE_COUNT);
    knl_securec_check(ret);

    for (i = 0; i < rcy->capacity; i++) {
        bucket = &rcy->bucket[i];
        bucket->count = bucket_count / rcy->capacity;
        bucket->lock = 0;
        bucket->head = 0;
        bucket->tail = 0;
        bucket->first = (rcy_paral_group_t **)(rcy->buf + i * bucket->count * sizeof(rcy_paral_group_t *));
        bucket->last_replay_time = g_timer()->now;
        bucket->id = i;

        cm_init_eventfd(&bucket->eventfd);
        if (rcy_alloc_session(kernel, &bucket->session) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("rcy proc init failed as alloc session failed now=%u, capacity=%u", i, rcy->capacity);
            break;
        }

        bucket->session->dtc_session_type = session->dtc_session_type;

        if (cm_create_thread(rcy_proc, 0, bucket, &bucket->thread) != CT_SUCCESS) {
            rcy_release_session(bucket->session);
            CT_LOG_RUN_ERR("rcy proc init failed as create thread failed now=%u, capacity=%u", i, rcy->capacity);
            break;
        }
 
        rcy_paral_stat_t *rcy_stat = &bucket->rcy_stat;
        rcy_stat->session_id = bucket->session->id;
        rcy_stat->rcy_read_disk_page_num = 0;
        rcy_stat->rcy_read_disk_total_time = 0;
        rcy_stat->rcy_read_disk_avg_time = 0;
        rcy_stat->session_work_time = 0;
        rcy_stat->session_used_time = 0;
        rcy_stat->session_util_rate = 0;
        rcy_stat->sleep_time_in_log_add_bucket = 0;
        rcy_stat->session_replay_log_group_count = 0;
 
        CT_LOG_DEBUG_INF("[DTC RCY] init rcy_paral_proc,rcy->capacity=%u, session_id=%u, "
            "sleep_time_in_log_add_bucket=%llu, session_replay_log_group_count=%llu", rcy->capacity,
            rcy_stat->session_id, rcy_stat->sleep_time_in_log_add_bucket, rcy_stat->session_replay_log_group_count);
    }

    if (i < rcy->capacity) {
        if (i > CT_DEFAULT_PARAL_RCY) {
            rcy->capacity = i;
            rcy->paral_rcy = CT_TRUE;
        } else {
            rcy->paral_rcy = CT_FALSE;
        }
    }

    for (i = 0; i < rcy->preload_proc_num; i++) {
        rcy->preload_info[i].group_id = 0;
        rcy->preload_info->curr = i;

        if (rcy_alloc_session(kernel, &rcy->preload_info[i].session) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("rcy preload proc as alloc session failed now=%u, capacity=%u", i, rcy->preload_proc_num);
            break;
        }

        if (cm_create_thread(rcy_preload_proc, 0, &rcy->preload_info[i], &rcy->preload_thread[i]) != CT_SUCCESS) {
            rcy_release_session(rcy->preload_info[i].session);
            CT_LOG_RUN_ERR("rcy preload proc as create thread failed now=%u, capacity=%u", i, rcy->preload_proc_num);
            break;
        }
    }

    rcy->preload_proc_num = (i < rcy->preload_proc_num) ? i : rcy->preload_proc_num;

    return;
}

void rcy_close_proc(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    rcy_context_t *rcy = &kernel->rcy_ctx;
    rcy_bucket_t *bucket = NULL;
    uint32 i;

    if (!rcy->paral_rcy) {
        return;
    }

    rcy->last_lrpl_time = 0;  // make sure parallel threads close immediately
    for (i = 0; i < rcy->capacity; i++) {
        bucket = &rcy->bucket[i];
        cm_close_thread(&bucket->thread);
        cm_release_eventfd(&bucket->eventfd);
    }

    for (i = 0; i < rcy->preload_proc_num; i++) {
        cm_close_thread(&rcy->preload_thread[i]);
    }
    rcy->swich_buf = CT_FALSE;
    CT_LOG_RUN_INF("[RCY] replay processes closed");
}

#ifdef LOG_DIAG
static inline void log_diag_entry(knl_session_t *session, log_entry_t *log)
{
    log_context_t *ctx = &session->kernel->redo_ctx;
    char *page = NULL;

    if (ctx->replay_procs[log->type] == NULL) {
        CT_LOG_RUN_WAR("undefined replay function for log type: %d\n", log->type);
        knl_panic(0);
        return;
    }

    page = session->curr_page;
    session->curr_page = session->log_diag_page[session->page_stack.depth - 1];

    ctx->replay_procs[log->type](session, log);
    session->curr_page = page;
}

void log_diag_page(knl_session_t *session)
{
    log_entry_t *entry = NULL;
    uint32 offset;
    uint32 group_pages = 0;

    session->log_diag = CT_TRUE;
    offset = session->page_stack.log_begin[session->page_stack.depth - 1];

    // only replay those logs which belong to current page
    while (offset < ((log_group_t *)session->log_buf)->size) {
        entry = (log_entry_t *)(session->log_buf + offset);
        offset += entry->size;
        if (RD_TYPE_IS_ENTER_PAGE(entry->type)) {
            group_pages++;
            continue;
        } else if (RD_TYPE_IS_LEAVE_PAGE(entry->type)) {
            knl_panic_log(group_pages != 0, "the group_pages is zero.");
            group_pages--;
            continue;
        }

        if (group_pages == 1) {
            log_diag_entry(session, entry);
        }
    }
    session->log_diag = CT_FALSE;
}
#endif

static bool32 need_replay_in_partial_restart(knl_session_t *session, log_entry_t *log)
{
    logic_op_t *op_type = (logic_op_t *)log->data;
    if (!DAAC_PARTIAL_RECOVER_SESSION(session)) {
        return CT_FALSE;
    }
    if (*op_type != RD_CREATE_INDEX && *op_type != RD_ALTER_INDEX && *op_type != RD_DROP_INDEX &&
        *op_type != RD_RENAME_TABLE && *op_type != RD_ALTER_TABLE && *op_type != RD_DROP_TABLE &&
        *op_type != RD_CREATE_TABLE && *op_type != RD_TRUNCATE_TABLE && *op_type != RD_ALTER_DB_LOGICREP &&
        *op_type != RD_CREATE_USER && *op_type != RD_DROP_USER) {
        return CT_FALSE;
    }
    return CT_TRUE;
}

void rcy_replay_logic(knl_session_t *session, log_entry_t *log)
{
    logic_op_t *op_type = (logic_op_t *)log->data;
    if (DB_IS_PRIMARY(&session->kernel->db) &&
        (*op_type == RD_LOCK_TABLE_FOR_MYSQL_DDL ||
        *op_type == RD_UNLOCK_TABLE_FOR_MYSQL_DDL ||
        *op_type == RD_INVALID_DD_FOR_MYSQL_DDL)) {
        return;
    }

    if (DB_NOT_READY(session) || (DB_IS_PRIMARY(&session->kernel->db)) || DB_IS_UPGRADE(session)) {
        if (*op_type != RD_CREATE_MK_BEGIN &&
            *op_type != RD_CREATE_MK_END &&
            *op_type != RD_CREATE_MK_DATA &&
            *op_type != RD_UPDATE_SYSDATA_VERSION &&
            !need_replay_in_partial_restart(session, log)) {
            return;
        }
    }

    // replay logical log need update session query_scn
    session->query_scn = DB_CURR_SCN(session);

    for (uint32 id = 0; id < LOGIC_LMGR_COUNT; id++) {
        if (g_logic_lmgrs[id].type == *op_type) {
            g_logic_lmgrs[id].replay_proc(session, log);
            return;
        }
    }

    if (*op_type >= RD_SQL_LOG_BEGIN && *op_type < RD_SQL_LOG_END) {
        if (g_knl_callback.pl_logic_log_replay(session, *op_type - RD_SQL_LOG_BEGIN,
            (void *)(log->data + CM_ALIGN4(sizeof(logic_op_t)))) != CT_SUCCESS) {
            int32 error_code;
            const char *error_message = NULL;
            cm_get_error(&error_code, &error_message, NULL);
            CT_LOG_RUN_ERR("sql logic log replay fail, error code:%u, error message:%s",
                           error_code, error_message);
            cm_reset_error();
        }
    }
}

void print_replay_logic(log_entry_t *log)
{
    logic_op_t *op_type = (logic_op_t *)log->data;

    for (uint32 id = 0; id < LOGIC_LMGR_COUNT; id++) {
        if (g_logic_lmgrs[id].type == *op_type) {
            g_logic_lmgrs[id].desc_proc(log);
            return;
        }
    }
}

void gbp_aly_gbp_logic(knl_session_t *session, log_entry_t *log, uint64 lsn)
{
    logic_op_t *op_type = (logic_op_t *)log->data;

    if (DB_NOT_READY(session) || DB_IS_PRIMARY(&session->kernel->db)) {
        return;
    }

    switch (*op_type) {
        case RD_ADD_LOGFILE:
            rd_alter_add_logfile(session, log);
            break;
        case RD_DROP_LOGFILE:
            rd_alter_drop_logfile(session, log);
            break;
        default:
            gbp_aly_unsafe_entry(session, log, lsn);
            break;
    }
}

void backup_logic_entry(knl_session_t *session, log_entry_t *log, bool32 *need_unblock_backup)
{
    logic_op_t *op_type = (logic_op_t *)log->data;

    for (uint32 id = 0; id < LOGIC_LMGR_COUNT; id++) {
        if (g_logic_lmgrs[id].type == *op_type) {
            g_logic_lmgrs[id].stop_backup_proc(session, log, need_unblock_backup);
            return;
        }
    }
}

const char* rcy_logic_name(log_entry_t *log)
{
    logic_op_t *op_type = (logic_op_t *)log->data;

    for (uint32 id = 0; id < LOGIC_LMGR_COUNT; id++) {
        if (g_logic_lmgrs[id].type == *op_type) {
            return g_logic_lmgrs[id].name;
        }
    }
    return NULL;
}

const char* rcy_redo_name(log_entry_t *log)
{
    if (log->type == RD_LOGIC_OPERATION) {
        return rcy_logic_name(log);
    }

    for (uint32 id = 0; id < LMGR_COUNT; id++) {
        if (g_lmgrs[id].type == log->type) {
            return g_lmgrs[id].name;
        }
    }
    return NULL;
}
