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
 * dtc_recovery.c
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_recovery.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_recovery.h"
#include "dtc_database.h"
#include "dtc_drc.h"
#include "dtc_reform.h"
#include "cm_dbs_intf.h"
#include "dirent.h"
#include "knl_space_log.h"
#include "knl_map.h"
#include "rcr_btree.h"
#include "knl_create_space.h"
#include "knl_buffer.h"
#include "knl_page.h"
#include "knl_undo.h"
#include "knl_punch_space.h"
#include "cm_io_record.h"


dtc_rcy_analyze_paral_node_t g_analyze_paral_mgr;
dtc_rcy_replay_paral_node_t g_replay_paral_mgr;

page_stack_t g_dtc_rcy_page_id_stack;

void dtc_rcy_inc_need_analysis_leave_page_cnt(bool32 recover_flag)
{
    if (recover_flag) {
        dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
        dtc_rcy->need_analysis_leave_page_cnt++;
    }
}

void dtc_rcy_dec_need_analysis_leave_page_cnt(bool32 recover_flag)
{
    if (recover_flag) {
        dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
        dtc_rcy->need_analysis_leave_page_cnt--;
    }
}

void dtc_rcy_reset_need_analysis_leave_page_cnt(bool32 recover_flag)
{
    if (recover_flag) {
        dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
        dtc_rcy->need_analysis_leave_page_cnt = 0;
    }
}

bool8 dtc_rcy_is_need_analysis_leave_page(bool32 recover_flag)
{
    if (recover_flag) {
        dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
        return (dtc_rcy->need_analysis_leave_page_cnt > 0);
    }
    return GS_FALSE;
}

bool8 dtc_rcy_set_pitr_end_analysis(bool32 recover_flag)
{
    if (recover_flag) {
        dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
        dtc_rcy->is_end_restore_recover = GS_TRUE;
        return GS_TRUE;
    }
    return GS_FALSE;
}

static bool8 dtc_rcy_check_is_end_restore_recovery(void)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    return dtc_rcy->is_end_restore_recover;
}

bool8 dtc_rcy_set_pitr_end_replay(bool32 recover_flag, uint64 lsn)
{
    if (recover_flag) {
        dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
        if (lsn >= dtc_rcy->end_lsn_restore_recovery) {
            dtc_rcy->is_end_restore_recover = GS_TRUE;
            return GS_TRUE;
        }
        return GS_FALSE;
    }
    return GS_FALSE;
}

static inline uint32 dtc_rcy_bucket_hash(page_id_t page_id, uint32 range)
{
    /* after mod range, the result is less than 0xffffffff */
    return (HASH_SEED * page_id.page + page_id.file) * HASH_SEED % range;
}

rcy_set_item_t *dtc_rcy_get_item(rcy_set_bucket_t *bucket, page_id_t page_id)
{
    rcy_set_item_t *item = bucket->first;

    while (item != NULL) {
        if (IS_SAME_PAGID(item->page_id, page_id)) {
            return item;
        }

        item = item->next_item;
    }

    return NULL;
}

static inline void dtc_rcy_add_to_bucket(rcy_set_bucket_t *bucket, rcy_set_item_t *item)
{
    item->next_item = bucket->first;
    bucket->first = item;
    bucket->count++;
}

status_t dtc_rcy_set_item_update_need_replay(rcy_set_bucket_t *bucket, page_id_t page_id, bool8 need_replay)
{
    rcy_set_item_t *item = bucket->first;
    while (item != NULL) {
        if (IS_SAME_PAGID(item->page_id, page_id)) {
            item->need_replay = need_replay;
            return GS_SUCCESS;
        }
        item = item->next_item;
    }
    return GS_ERROR;
}

rcy_set_item_t *dtc_rcy_get_item_internal(page_id_t page_id)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    rcy_set_t *rcy_set = &dtc_rcy->rcy_set;
    rcy_set_bucket_t *bucket = NULL;
    uint32 hash_id;
    hash_id = dtc_rcy_bucket_hash(page_id, rcy_set->bucket_num);
    bucket = &rcy_set->buckets[hash_id];
    return(dtc_rcy_get_item(bucket, page_id));
}

static void dtc_rcy_init_last_recovery_stat(instance_list_t *recover_list)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_rcy_stat_t *stat = &dtc_rcy->rcy_stat;

    stat->last_rcy_log_size = 0;
    stat->last_rcy_set_num = 0;
    stat->last_rcy_analyze_elapsed = 0;
    stat->last_rcy_set_revise_elapsed = 0;
    stat->last_rcy_replay_elapsed = 0;
    stat->last_rcy_elapsed = 0;
    stat->last_rcy_is_full_recovery = GS_FALSE;
    stat->last_rcy_logic_log_group_count = 0;
    stat->last_rcy_logic_log_elapsed = 0;
    stat->latc_rcy_logic_log_wait_time = 0;
    MEMS_RETVOID_IFERR(memset_sp(&stat->rcy_log_points, sizeof(rcy_node_stat_t) * GS_MAX_INSTANCES,
                                 0, sizeof(rcy_node_stat_t) * GS_MAX_INSTANCES));

    MEMS_RETVOID_IFERR(memcpy_s(&stat->last_rcy_inst_list, sizeof(instance_list_t),
                                recover_list, sizeof(instance_list_t)));
}

rcy_set_item_pool_t* dtc_rcy_alloc_itempool(rcy_set_t *rcy_set)
{
    rcy_set_item_pool_t *item_pool = NULL;
    uint64 item_pool_size = sizeof(rcy_set_item_t) * rcy_set->capacity + sizeof(rcy_set_item_pool_t);

    // free in dtc_recovery_close
    item_pool = (rcy_set_item_pool_t *)malloc(item_pool_size);
    if (item_pool == NULL) {
        GS_LOG_RUN_ERR("[DTC RCY] failed to alloc rcy set itempool");
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, item_pool_size, "dtc recovery set itempool");
        return NULL;
    }
    errno_t ret = memset_sp(item_pool, item_pool_size, 0, item_pool_size);
    knl_securec_check(ret);
    item_pool->items = (rcy_set_item_t *)((char *)item_pool + sizeof(rcy_set_item_pool_t));
    item_pool->hwm = 0;
    item_pool->next = NULL;

    GS_LOG_RUN_INF("[DTC RCY] alloc rcy_set itempool successfully, recovery set capacity=%llu, itempool size=%llu",
                   rcy_set->capacity, item_pool_size);
    return item_pool;
}

status_t dtc_rcy_try_alloc_itempool(rcy_set_t *rcy_set, rcy_set_item_pool_t *old_pool)
{
    static atomic32_t count = 0;
    int32 times = cm_atomic32_inc(&count);
    if (times == 1 && rcy_set->curr_item_pools == old_pool) {
        rcy_set_item_pool_t *item_pool = dtc_rcy_alloc_itempool(rcy_set);
        if (item_pool == NULL) {
            cm_atomic32_dec(&count);
            GS_LOG_RUN_ERR("[DTC RCY] failed to alloc itempool");
            return GS_ERROR;
        }
        rcy_set->curr_item_pools->next = item_pool;
        rcy_set->curr_item_pools = item_pool;
        cm_atomic32_dec(&count);
    } else {
        cm_atomic32_dec(&count);
        while (rcy_set->curr_item_pools == old_pool) {
            cm_sleep(1);
        }
    }
    return GS_SUCCESS;
}

void dtc_rcy_handle_pcn_discon(knl_session_t *session, rcy_set_item_t *item, page_id_t page_id, uint32 pcn, uint64 lsn)
{
    if (pcn == (uint32)(item->pcn + 1)) {
        item->pcn = pcn;
        return;
    }
    if (pcn == (uint32)(item->pcn)) {
        dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
        dtc_rcy->pcn_is_equal_num++;
        return;
    }
    if (pcn < item->pcn) {
        GS_LOG_RUN_INF("[DTC RCY] analyze update page [%u-%u], first_dirty_lsn: %llu,"
            "last_dirty_lsn: %llu, curr_dirty_lsn: %llu, pcn[%u-%u]",
            page_id.file, page_id.page, item->first_dirty_lsn, item->last_dirty_lsn, lsn, pcn, item->pcn);
        item->need_check_leave_changed = GS_TRUE;
        dtc_rcy_inc_need_analysis_leave_page_cnt(session->kernel->db.recover_for_restore);
        return;
    }
    
    buf_enter_page(session, page_id, LATCH_MODE_S, ENTER_PAGE_NORMAL);
    if (item->pcn < ((page_head_t *)session->curr_page)->pcn) {
        item->pcn = pcn;
    } else {
        GS_LOG_RUN_ERR("[DTC RCY] analyze update page [%u-%u], first_dirty_lsn: %llu,"
                       "last_dirty_lsn: %llu, curr_dirty_lsn: %llu, pcn[%u-%u]",
                       page_id.file, page_id.page, item->first_dirty_lsn,
                       item->last_dirty_lsn, lsn, pcn, item->pcn);
        dtc_rcy_set_pitr_end_analysis(session->kernel->db.recover_for_restore);
    }
    buf_leave_page(session, GS_FALSE);
}

void dtc_rcy_init_page_id_stack(bool32 recover_flag)
{
    if (recover_flag) {
        g_dtc_rcy_page_id_stack.depth = 0;
    }
}

void dtc_rcy_push_page_id(bool32 recover_flag, page_id_t page_id)
{
    if (recover_flag) {
        knl_panic(g_dtc_rcy_page_id_stack.depth < KNL_MAX_PAGE_STACK_DEPTH);
        g_dtc_rcy_page_id_stack.gbp_aly_page_id[g_dtc_rcy_page_id_stack.depth] = page_id;
        g_dtc_rcy_page_id_stack.depth++;
    }
}

void dtc_rcy_pop_page_id(bool32 recover_flag, page_id_t *page_id)
{
    if (recover_flag) {
        knl_panic(g_dtc_rcy_page_id_stack.depth > 0);
        g_dtc_rcy_page_id_stack.depth--;
        *page_id = g_dtc_rcy_page_id_stack.gbp_aly_page_id[g_dtc_rcy_page_id_stack.depth];
    }
}

status_t dtc_rcy_record_page(knl_session_t *session, page_id_t page_id, uint64 lsn, uint32 pcn)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    rcy_set_t *rcy_set = &dtc_rcy->rcy_set;
    rcy_set_item_pool_t *item_pool;
    uint32 hash_id = dtc_rcy_bucket_hash(page_id, rcy_set->bucket_num);
    rcy_set_bucket_t *bucket = &rcy_set->buckets[hash_id];
    int64 idx;

    dtc_rcy_push_page_id(session->kernel->db.recover_for_restore, page_id);

    cm_spin_lock(&bucket->lock, NULL);
    rcy_set_item_t *item = dtc_rcy_get_item(bucket, page_id);
    if (item != NULL) {
        GS_LOG_DEBUG_INF("[DTC RCY] analyze update page [%u-%u], hash id=%u, first_dirty_lsn=%llu, last_dirty_lsn=%llu"
            ", curr_dirty_lsn=%llu", page_id.file, page_id.page, hash_id, item->first_dirty_lsn,
            item->last_dirty_lsn, lsn);
        if (lsn > item->last_dirty_lsn) {
            item->last_dirty_lsn = lsn;
        }
        if (session->kernel->db.recover_for_restore) {
            dtc_rcy_handle_pcn_discon(session, item, page_id, pcn, lsn);
        }
        cm_spin_unlock(&bucket->lock);
        return GS_SUCCESS;
    }

    status_t ret = GS_SUCCESS;
    do {
        item_pool = rcy_set->curr_item_pools;
        idx = item_pool->hwm;
        if (idx >= rcy_set->capacity) {
            SYNC_POINT_GLOBAL_START(CANTIAN_RECOVERY_RCY_SET_ALLOC_ITEMPOOL_FAIL, &ret, GS_ERROR);
            ret = dtc_rcy_try_alloc_itempool(rcy_set, item_pool);
            SYNC_POINT_GLOBAL_END;
            if (ret != GS_SUCCESS) {
                GS_LOG_RUN_ERR("[DTC RCY] failed to alloc itmepool for recovery set");
                return GS_ERROR;
            }
            item_pool = rcy_set->curr_item_pools;
            idx = item_pool->hwm;
            continue;
        }
    } while (!cm_atomic_cas(&item_pool->hwm, idx, idx + 1));

    item = &item_pool->items[idx];
    item->page_id = page_id;
    item->first_dirty_lsn = lsn;
    item->last_dirty_lsn = lsn;
    item->pcn = pcn;
    item->need_replay = GS_TRUE;

    GS_LOG_DEBUG_INF("[DTC RCY] analyze record page [%u-%u], hash id=%u, first_dirty_lsn=%llu, last_dirty_lsn=%llu"
                     ", curr_dirty_lsn=%llui, pcn=%u, need replay=%u", page_id.file, page_id.page, hash_id,
                     item->first_dirty_lsn, item->last_dirty_lsn, lsn, item->pcn, item->need_replay);
    if (drc_get_page_master_id(page_id, &item->master_id) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[DTC RCY] failed to get master id of page [%u-%u]", page_id.file, page_id.page);
        cm_spin_unlock(&bucket->lock);
        return GS_ERROR;
    }

    dtc_rcy_add_to_bucket(bucket, item);
    cm_spin_unlock(&bucket->lock);
    return GS_SUCCESS;
}

#define DTC_GET_PAGE_ID_REDO(ptr, type, member, page_id)     \
    ({                                                  \
        type *__redo = (type *)(ptr);                   \
        page_id = __redo->member;                       \
    })

bool8 dtc_get_page_id_by_redo(log_entry_t *log, page_id_t *page_id_value)
{
    switch (log->type) {
        case RD_HEAP_FORMAT_PAGE:
        case RD_HEAP_FORMAT_MAP:
        case RD_HEAP_FORMAT_ENTRY:
            DTC_GET_PAGE_ID_REDO(log->data, rd_heap_format_page_t, page_id, *page_id_value);
            break;
        case RD_BTREE_FORMAT_PAGE:
            DTC_GET_PAGE_ID_REDO(log->data, rd_btree_page_init_t, page_id, *page_id_value);
            break;
        case RD_BTREE_INIT_ENTRY:
            DTC_GET_PAGE_ID_REDO(log->data, rd_btree_init_entry_t, page_id, *page_id_value);
            break;
        case RD_SPC_UPDATE_HEAD:
            DTC_GET_PAGE_ID_REDO(log->data, rd_update_head_t, entry, *page_id_value);
            break;
        case RD_SPC_INIT_MAP_HEAD:
        case RD_SPC_INIT_MAP_PAGE:
            *page_id_value = AS_PAGID(log->data);
            break;
        case RD_UNDO_CREATE_SEGMENT:
        case RD_UNDO_FORMAT_TXN:
        case RD_LOB_PAGE_INIT:
        case RD_LOB_PAGE_EXT_INIT:
            {
                page_head_t *redo = (page_head_t *)log->data;
                *page_id_value = AS_PAGID(redo->id);
                break;
            }
        case RD_UNDO_FORMAT_PAGE:
            {
                rd_undo_fmt_page_t *undo_fmt = (rd_undo_fmt_page_t *)log->data;
                *page_id_value = MAKE_PAGID(undo_fmt->page_id.file, undo_fmt->page_id.page);
                break;
            }
        case RD_PUNCH_FORMAT_PAGE:
            DTC_GET_PAGE_ID_REDO(log->data, rd_punch_page_t, page_id, *page_id_value);
            break;
        case RD_LEAVE_PAGE:
        case RD_LEAVE_TXN_PAGE:
            {
                dtc_rcy_pop_page_id(GS_TRUE, page_id_value);
                return dtc_rcy_is_need_analysis_leave_page(GS_TRUE);
            }
        default:
            return GS_FALSE;
    }
    return GS_TRUE;
}

void dtc_rcy_try_set_pitr_end_analysis(bool32 recover_flag, page_id_t *page_id, rcy_set_item_t *item, bool32 changed)
{
    if (recover_flag) {
        if (item->need_check_leave_changed) {
            dtc_rcy_dec_need_analysis_leave_page_cnt(recover_flag);
            if (changed) {
                GS_LOG_RUN_ERR("[DTC RCY] analyze update page [%u-%u], first_dirty_lsn: %llu, "
                    "last_dirty_lsn: %llu, pcn %u",
                    page_id->file, page_id->page, item->first_dirty_lsn, item->last_dirty_lsn, item->pcn);
                (void)dtc_rcy_set_pitr_end_analysis(recover_flag);
            }
        }
        item->need_check_leave_changed = GS_FALSE;
    }
    return;
}

status_t dtc_rcy_reset_page_pcn(knl_session_t *session, log_entry_t *log)
{
    page_id_t page_id;
    if (!dtc_get_page_id_by_redo(log, &page_id)) {
        return GS_SUCCESS;
    }
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    rcy_set_t *rcy_set = &dtc_rcy->rcy_set;
    uint32 hash_id = dtc_rcy_bucket_hash(page_id, rcy_set->bucket_num);
    rcy_set_bucket_t *bucket = &rcy_set->buckets[hash_id];

    cm_spin_lock(&bucket->lock, NULL);
    rcy_set_item_t *item = dtc_rcy_get_item(bucket, page_id);
    if (item != NULL) {
        GS_LOG_DEBUG_INF("[DTC RCY] analyze update page [%u-%u], hash: %u, first_dirty_lsn: %llu,"
                         "last_dirty_lsn: %llu",
                         page_id.file, page_id.page, hash_id, item->first_dirty_lsn, item->last_dirty_lsn);

        if (RD_TYPE_IS_LEAVE_PAGE(log->type)) {
            dtc_rcy_try_set_pitr_end_analysis(session->kernel->db.recover_for_restore,
                &page_id, item, *(bool32 *)log->data);
        } else {
            item->pcn = 0;
        }
        cm_spin_unlock(&bucket->lock);
        return GS_SUCCESS;
    }
    cm_spin_unlock(&bucket->lock);
    GS_LOG_DEBUG_INF("[DTC RCY] analyze record page [%u-%u], now is format, but no page enter",
                     page_id.file, page_id.page);
    return GS_SUCCESS;
}

status_t dtc_rcy_analyze_entry(knl_session_t *session, log_entry_t *log, uint64 lsn, bool32 is_create_df)
{
    knl_panic(log->type >= RD_ENTER_PAGE);
    if (!(log->type == RD_ENTER_PAGE || log->type == RD_ENTER_TXN_PAGE)) {
        if (!session->kernel->db.recover_for_restore) {
            return GS_SUCCESS;
        }
        return dtc_rcy_reset_page_pcn(session, log);
    }

    rd_enter_page_t *redo = (rd_enter_page_t *)log->data;
    page_id_t page_id = MAKE_PAGID(redo->file, redo->page);
    if (session->kernel->db.recover_for_restore) {
        return dtc_rcy_record_page(session, page_id, lsn, redo->pcn);
    }

    datafile_t *df = DATAFILE_GET(session, redo->file);
    if (!is_create_df && (!DATAFILE_IS_ONLINE(df) || !df->ctrl->used || df->file_no == GS_INVALID_ID32)) {
        GS_LOG_RUN_ERR("[DTC RCY] failed to verify df");
        knl_panic(0);
        return GS_ERROR;
    }

    space_t *space = SPACE_GET(session, df->space_id);
    if (!is_create_df && (!SPACE_IS_ONLINE(space) || !space->ctrl->used)) {
        GS_LOG_RUN_ERR("[DTC RCY] failed to verify space cfg");
        knl_panic(0);
        return GS_ERROR;
    }

    if (dtc_rcy_record_page(session, page_id, lsn, redo->pcn) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[DTC RCY] failed to record page [%u-%u] in recovery_set", page_id.file, page_id.page);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t dtc_rcy_analyze_group(knl_session_t *session, log_group_t *group)
{
    uint32 offset = sizeof(log_group_t);
    log_entry_t *log = NULL;
    knl_session_t *knl_ss = session->kernel->sessions[SESSION_ID_KERNEL];
    knl_ss->dtc_session_type = session->dtc_session_type;
    bool32 is_create_df = GS_FALSE;
    dtc_rcy_init_page_id_stack(session->kernel->db.recover_for_restore);
    dtc_rcy_reset_need_analysis_leave_page_cnt(session->kernel->db.recover_for_restore);
    while (offset < group->size) {
        log = (log_entry_t *)((char *)group + offset);
        knl_panic(log->size > 0);
        if (!is_create_df && log->type == RD_SPC_CREATE_DATAFILE) {
            is_create_df = GS_TRUE;
        }
        if (dtc_rcy_analyze_entry(knl_ss, log, group->lsn, is_create_df) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[DTC RCY] failed to analyze redo entry");
            return GS_ERROR;
        }
        if (dtc_rcy_check_is_end_restore_recovery()) {
            break;
        }
        offset += log->size;
    }
    return GS_SUCCESS;
}

static inline void dtc_rcy_inc_rcy_set_ref_num(void)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    cm_spin_lock(&dtc_rcy->lock, NULL);
    dtc_rcy->rcy_set_ref_num++;
    cm_spin_unlock(&dtc_rcy->lock);
}

static inline void dtc_rcy_dec_rcy_set_ref_num(void)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    cm_spin_lock(&dtc_rcy->lock, NULL);
    dtc_rcy->rcy_set_ref_num--;
    cm_spin_unlock(&dtc_rcy->lock);
}

static inline void dtc_rcy_inc_msg_sent(void)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    cm_spin_lock(&dtc_rcy->lock, NULL);
    dtc_rcy->msg_sent++;
    cm_spin_unlock(&dtc_rcy->lock);
}

static inline void dtc_rcy_inc_msg_recv(void)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    cm_spin_lock(&dtc_rcy->lock, NULL);
    dtc_rcy->msg_recv++;
    cm_spin_unlock(&dtc_rcy->lock);
}

status_t dtc_rcy_check_rcyset_msg(knl_session_t *session)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    cm_spin_lock(&dtc_rcy->lock, NULL);
    // check if reformer rev ack msg from alive nodes timeout
    date_t time_now = KNL_NOW(session);
    if (time_now - dtc_rcy->rcy_set_send_time >= dtc_rcy->msg_sent * DTC_RCY_RECV_RCY_SET_ACK_TIMEOUT) {
        GS_LOG_RUN_WAR("[DTC RCY] wait nodes collects page info in rcy_set timeout, %u msg_sent, %u msg_recv, "
            "time spend=%lld", dtc_rcy->msg_sent, dtc_rcy->msg_recv, time_now - dtc_rcy->rcy_set_send_time);
        dtc_rcy->failed = GS_TRUE;
        return GS_ERROR;
    }
    if (dtc_rcy->msg_recv == dtc_rcy->msg_sent) {
        dtc_rcy->phase = PHASE_HANDLE_RCYSET_DONE;
    }
    cm_spin_unlock(&dtc_rcy->lock);
    return GS_SUCCESS;
}

status_t dtc_send_page_to_node(knl_session_t *session, page_id_t *pages, uint32 count, bool32 finished,
    uint8 node_id, uint8 cmd)
{
    dtc_rcy_set_msg_t req;
    status_t status;
    drc_remaster_mngr_t *remaster_mngr = &g_drc_res_ctx.part_mngr.remaster_mngr;

    mes_init_send_head(&req.head, cmd, sizeof(dtc_rcy_set_msg_t), GS_INVALID_ID32, session->kernel->id, node_id,
                       session->id, GS_INVALID_ID16);

    req.count = count;
    req.finished = finished;
    req.buffer_len = req.count * sizeof(page_id_t);
    req.head.size = (uint16)(sizeof(dtc_rcy_set_msg_t) + req.count * sizeof(page_id_t));
    req.reform_trigger_version = remaster_mngr->reform_info.trigger_version;

    if (count > 0) {
        status = mes_send_data3(&req.head, sizeof(dtc_rcy_set_msg_t), pages);
    } else {
        status = mes_send_data(&req.head);
    }

    if (cmd == MES_CMD_SEND_RCY_SET) {
        dtc_rcy_inc_msg_sent();
    }
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    GS_LOG_RUN_INF("[DTC RCY] send num=%u pages size=%u to instance=%u with status=%d, rcy_set ref num=%u",
        count, req.head.size, node_id, status, dtc_rcy->rcy_set_ref_num);

    return status;
}

static page_id_t* dtc_rcy_alloc_page_space(uint32 size)
{
    if (size == 0) {
        GS_LOG_RUN_ERR("[DTC RCY] failed to alloc page space, size=%u", size);
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, size, "dtc recovery page space");
        return NULL;
    }
    page_id_t *pages = (page_id_t *)malloc(size);
    if (pages == NULL) {
        GS_LOG_RUN_ERR("[DTC RCY] failed to alloc page space, size=%u", size);
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, size, "dtc recovery page space");
        return NULL;
    }

    errno_t ret = memset_sp(pages, size, 0, size);
    knl_securec_check(ret);
    return pages;
}

status_t dtc_send_rcy_set_by_pool(knl_session_t *session, rcy_set_item_pool_t *pool, rcy_set_t *rcy_set)
{
    uint32 size = DTC_RCY_SET_SEND_MSG_MAX_PAGE_NUM * sizeof(page_id_t);
    rcy_set_item_t *item = NULL;
    page_id_t *pages = NULL;
    uint32 *page_count = NULL;
    uint8 node_id;

    for (uint32 i = 0; i < pool->hwm; i++) {
        item = &pool->items[i];
        node_id = item->master_id;
        knl_panic(node_id < GS_MAX_INSTANCES);

        pages = rcy_set->pages[node_id];
        page_count = &rcy_set->page_count[node_id];
        // malloc memory for the first time
        if (pages == NULL) {
            pages = dtc_rcy_alloc_page_space(size);
            if (pages == NULL) {
                GS_LOG_RUN_ERR("[DTC RCY] failed to malloc %u bytes for sending rcyset to instance=%u", size, node_id);
                return GS_ERROR;
            }
            *page_count = 0;
            rcy_set->pages[node_id] = pages;
        }

        pages[*page_count] = item->page_id;
        (*page_count)++;

        // send to master if message buffer is full
        if (*page_count >= DTC_RCY_SET_SEND_MSG_MAX_PAGE_NUM) {
            if (dtc_send_page_to_node(session, pages, *page_count, GS_FALSE,
                node_id, MES_CMD_SEND_RCY_SET) != GS_SUCCESS) {
                GS_LOG_RUN_ERR("[DTC RCY] failed to send num=%u pages from rcy set to node=%u, max_page_count=%lu",
                    *page_count, node_id, DTC_RCY_SET_SEND_MSG_MAX_PAGE_NUM);
                return GS_ERROR;
            }

            *page_count = 0;
        }
    }
    return GS_SUCCESS;
}

status_t dtc_send_rcy_set(knl_session_t *session)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    rcy_set_item_pool_t *pool = dtc_rcy->rcy_set.item_pools;
    status_t ret = GS_SUCCESS;

    // set recovery phase to PHASE_HANDLE_RCYSET
    dtc_rcy->phase = PHASE_HANDLE_RCYSET;
    GS_LOG_RUN_INF("[DTC RCY] start send rcy set to each master, dtc_rcy->phase=%u", dtc_rcy->phase);
    while (pool != NULL) {
        dtc_rcy_inc_rcy_set_ref_num();
        SYNC_POINT_GLOBAL_START(CANTIAN_RECOVERY_SEND_RCY_SET_FAIL, &ret, GS_ERROR);
        ret = dtc_send_rcy_set_by_pool(session, pool, &dtc_rcy->rcy_set);
        SYNC_POINT_GLOBAL_END;
        if (ret != GS_SUCCESS) {
            dtc_rcy_dec_rcy_set_ref_num();
            GS_LOG_RUN_ERR("[DTC RCY] failed to send rcy set by pool, pool capacity=%llu, dtc_rcy->phase=%u, "
                "rcy_set ref num=%u", pool->hwm, dtc_rcy->phase, dtc_rcy->rcy_set_ref_num);
            return GS_ERROR;
        }
        dtc_rcy_dec_rcy_set_ref_num();
        GS_LOG_RUN_INF("[DTC RCY] send rcy set by pool, dtc_rcy->phase=%u, rcy_set ref num=%u",
            dtc_rcy->phase, dtc_rcy->rcy_set_ref_num);
        pool = pool->next;
    }

    page_id_t *pages = NULL;
    uint32 *page_count = NULL;
    for (uint32 i = 0; i < GS_MAX_INSTANCES; i++) {
        dtc_rcy_inc_rcy_set_ref_num();
        pages = dtc_rcy->rcy_set.pages[i];
        page_count = &dtc_rcy->rcy_set.page_count[i];
        if (pages == NULL) {
            dtc_rcy_dec_rcy_set_ref_num();
            continue;
        }

        // send the rest page to each master if successful
        if (dtc_send_page_to_node(session, pages, *page_count, GS_TRUE, i, MES_CMD_SEND_RCY_SET) != GS_SUCCESS) {
            dtc_rcy_dec_rcy_set_ref_num();
            GS_LOG_RUN_ERR("[DTC RCY] failed to send rcy set to node=%u, page_count=%u, rcy_set ref num=%u",
                i, *page_count, dtc_rcy->rcy_set_ref_num);
            return GS_ERROR;
        }
        *page_count = 0;
        dtc_rcy_dec_rcy_set_ref_num();
        GS_LOG_RUN_INF("[DTC RCY] send rcy set to node=%u, page_count=%u, rcy_set ref num=%u",
            i, *page_count, dtc_rcy->rcy_set_ref_num);
    }

    if (dtc_rcy->msg_sent == 0) {
        dtc_rcy->phase = PHASE_HANDLE_RCYSET_DONE;
    }

    dtc_rcy->rcy_set_send_time = KNL_NOW(session);  // record time when all pages in rcy_set have sent successfully
    GS_LOG_RUN_INF("[DTC RCY] send %u rcy set messages, dtc_rcy->phase=%u, send time=%lld",
        dtc_rcy->msg_sent, dtc_rcy->phase, dtc_rcy->rcy_set_send_time);
    return GS_SUCCESS;
}

void dtc_process_rcy_set_err_ack(void *sess, mes_message_t *msg)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_rcy_set_msg_t *ack = (dtc_rcy_set_msg_t *)msg->buffer;
    bool32 finished = ack->finished;
    drc_remaster_mngr_t *remaster_mngr = &g_drc_res_ctx.part_mngr.remaster_mngr;
 
    if (g_rc_ctx->status > REFORM_RECOVER_DONE || g_rc_ctx->status < REFORM_FROZEN ||
        ack->reform_trigger_version < remaster_mngr->reform_info.trigger_version) {
        GS_LOG_RUN_ERR("[DTC RCY] process rcy set err ack from master=%u, finished=%u, reform status(%u), msg reform "
                       "trigger version(%llu), local reform trigger version(%llu)", ack->head.src_inst, finished,
                       g_rc_ctx->status, ack->reform_trigger_version, remaster_mngr->reform_info.trigger_version);
        mes_release_message_buf(msg->buffer);
        return;
    }

    GS_LOG_RUN_INF("[DTC RCY] process rcy set err ack from master=%u, finished=%u", ack->head.src_inst, finished);
    if (!finished) {
        dtc_rcy->failed = GS_TRUE;
    }
    dtc_rcy_inc_msg_recv();
    mes_release_message_buf(msg->buffer);
    return;
}

status_t dtc_rcy_set_update_no_need_replay_batch(rcy_set_t *rcy_set, page_id_t *no_rcy_pages, uint32 count)
{
    rcy_set_bucket_t *bucket = NULL;
    uint32 hash_id;
    page_id_t *page_id = NULL;
    status_t ret = GS_SUCCESS;
    bool8 need_replay = GS_TRUE;
    for (uint32 i = 0; i < count; i++) {
        page_id = no_rcy_pages + i;
        hash_id = dtc_rcy_bucket_hash(*page_id, rcy_set->bucket_num);
        bucket = &rcy_set->buckets[hash_id];
        cm_spin_lock(&bucket->lock, NULL);
        need_replay = GS_FALSE;
        ret = dtc_rcy_set_item_update_need_replay(bucket, *page_id, need_replay);
        GS_LOG_RUN_RET_INFO(ret, "[DTC RCY][%u-%u] update need replay(%u) in rcy set",
                            page_id->file, page_id->page, need_replay);
        if (ret != GS_SUCCESS) {
            cm_spin_unlock(&bucket->lock);
            return ret;
        }
        cm_spin_unlock(&bucket->lock);
    }
    return ret;
}

void dtc_process_rcy_set_ack(void *sess, mes_message_t *msg)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    drc_remaster_mngr_t *remaster_mngr = &g_drc_res_ctx.part_mngr.remaster_mngr;
    dtc_rcy_set_msg_t *ack = (dtc_rcy_set_msg_t *)msg->buffer;

    uint32 count = ack->count;
    uint32 buffer_len = ack->buffer_len;
    if (buffer_len != count * sizeof(page_id_t) || g_rc_ctx->status >= REFORM_RECOVER_DONE ||
        g_rc_ctx->status < REFORM_FROZEN ||
        ack->reform_trigger_version != remaster_mngr->reform_info.trigger_version ||
        count > DTC_RCY_SET_SEND_MSG_MAX_PAGE_NUM || ack->head.size != sizeof(dtc_rcy_set_msg_t) + buffer_len) {
        GS_LOG_RUN_ERR("[DTC RCY] receive page count=%u, max_page_count=%lu, no_rcy_pages buffer len=%u, reform "
            "status(%u), msg reform trigger version(%llu), local reform trigger version(%llu), msg size(%u)",
            count, DTC_RCY_SET_SEND_MSG_MAX_PAGE_NUM, buffer_len, g_rc_ctx->status,
            ack->reform_trigger_version, remaster_mngr->reform_info.trigger_version, ack->head.size);
        mes_release_message_buf(msg->buffer);
        return;
    }

    page_id_t *no_rcy_pages = (page_id_t *)(msg->buffer + sizeof(dtc_rcy_set_msg_t));
    bool32 finished = ack->finished;
    GS_LOG_RUN_INF("[DTC RCY] process rcy set with edp from master=%u, no_rcy page count=%u, finished=%u",
        ack->head.src_inst, count, finished);
    if (!finished) {
        dtc_rcy->failed = GS_TRUE;
        dtc_rcy_inc_msg_recv();
        mes_release_message_buf(msg->buffer);
        GS_LOG_RUN_ERR("[DTC RCY] collect page info from inst=%u, finished=%u", ack->head.src_inst, finished);
        return;
    }
    if (dtc_rcy->failed) {
        mes_release_message_buf(msg->buffer);
        return;
    }
    
    rcy_set_t *rcy_set = &dtc_rcy->rcy_set;
    dtc_rcy_inc_rcy_set_ref_num();

    if (dtc_rcy_set_update_no_need_replay_batch(rcy_set, no_rcy_pages, count) != GS_SUCCESS) {
        dtc_rcy->failed = GS_TRUE;
    }
    GS_LOG_RUN_INF("[DTC RCY] finish delete no_rcy page count=%u, rcy_set ref num=%u", count, dtc_rcy->rcy_set_ref_num);

    dtc_rcy_inc_msg_recv();
    dtc_rcy_dec_rcy_set_ref_num();
    GS_LOG_RUN_INF("[DTC RCY] finish process rcy set with edp ack, rcy_set ref num=%u", dtc_rcy->rcy_set_ref_num);
    mes_release_message_buf(msg->buffer);
}

bool32 dtc_rcy_page_need_recover(knl_session_t *session, page_id_t *page_id)
{
    return drc_page_need_recover(session, page_id);
}

status_t dtc_send_page_back_to_node(knl_session_t *session, page_id_t *pages, uint32 count, bool32 finished,
    uint8 node_id, uint8 cmd)
{
    dtc_rcy_set_msg_t req;
    status_t status;
    drc_remaster_mngr_t *remaster_mngr = &g_drc_res_ctx.part_mngr.remaster_mngr;

    mes_init_send_head(&req.head, cmd, sizeof(dtc_rcy_set_msg_t), GS_INVALID_ID32, session->kernel->id, node_id,
                       session->id, GS_INVALID_ID16);

    req.count = count;
    req.finished = finished;
    req.buffer_len = req.count * sizeof(page_id_t);
    req.head.size = (uint16)(sizeof(dtc_rcy_set_msg_t) + req.buffer_len);
    req.reform_trigger_version = remaster_mngr->reform_info.trigger_version;

    if (count > 0) {
        status = mes_send_data3(&req.head, sizeof(dtc_rcy_set_msg_t), pages);
    } else {
        status = mes_send_data(&req.head);
    }
    GS_LOG_RUN_INF("[DTC RCY] send %u pages no need to rcy to instance=%u with cmd=%d, status=%d",
        count, node_id, cmd, status);

    return status;
}

status_t dtc_process_rcy_set_parameter_check(dtc_rcy_set_msg_t *req, uint32 size)
{
    drc_remaster_mngr_t *remaster_mngr = &g_drc_res_ctx.part_mngr.remaster_mngr;
    uint32 buffer_len = req->buffer_len;
    if (g_rc_ctx->status >= REFORM_RECOVER_DONE || g_rc_ctx->status < REFORM_FROZEN || req->count == 0 ||
        req->count > DTC_RCY_SET_SEND_MSG_MAX_PAGE_NUM || buffer_len != size ||
        buffer_len > DTC_RCY_SET_SEND_MSG_MAX_PAGE_NUM * sizeof(page_id_t) ||
        req->reform_trigger_version != remaster_mngr->reform_info.trigger_version ||
        sizeof(dtc_rcy_set_msg_t) + size != req->head.size) {
        GS_LOG_RUN_ERR("[DTC RCY] receive page count=%u, max_page_count=%lu, buffer len=%u, max buffer len=%lu, reform"
            " status(%u), msg reform trigger version(%llu), local reform trigger version(%llu), msgsize(%u)",
            req->count, DTC_RCY_SET_SEND_MSG_MAX_PAGE_NUM, buffer_len,
            DTC_RCY_SET_SEND_MSG_MAX_PAGE_NUM * sizeof(page_id_t), g_rc_ctx->status,
            req->reform_trigger_version, remaster_mngr->reform_info.trigger_version, req->head.size);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

void dtc_process_rcy_set(void *sess, mes_message_t *receive_msg)
{
    knl_session_t *session = (knl_session_t *)sess;
    dtc_rcy_set_msg_t *req = (dtc_rcy_set_msg_t *)receive_msg->buffer;
    page_id_t *pages_recv = (page_id_t *)(receive_msg->buffer + sizeof(dtc_rcy_set_msg_t));
    uint8 src_inst = receive_msg->head->src_inst;
    uint32 size = req->count * sizeof(page_id_t);
    uint32 count = 0;
    bool32 need_recover = GS_FALSE;

    if (dtc_process_rcy_set_parameter_check(req, size) != GS_SUCCESS) {
        mes_release_message_buf(receive_msg->buffer);
        return;
    }

    page_id_t *page_id = NULL;
    page_id_t *pages = NULL;
    pages = dtc_rcy_alloc_page_space(size);
    if (pages == NULL) {
        GS_LOG_RUN_ERR("[DTC RCY] failed to malloc %u bytes to collect do not need rcy page info from instance=%u",
            size, receive_msg->head->src_inst);
        mes_release_message_buf(receive_msg->buffer);
        if (dtc_send_page_back_to_node(session, pages, count, GS_FALSE, src_inst, MES_CMD_SEND_RCY_SET_ERR_ACK) !=
                                       GS_SUCCESS) {
            GS_LOG_RUN_ERR("[DTC RCY] failed to send error msg to instance=%u", src_inst);
        }
        return;
    }
    GS_LOG_RUN_INF("[DTC RCY] process recovery set of %u pages size=%u from instance=%u",
                   req->count, size, receive_msg->head->src_inst);

    for (uint32 i = 0; i < req->count; i++) {
        page_id = pages_recv + i;
        need_recover = dtc_rcy_page_need_recover(session, page_id);
        if (!need_recover) {
            pages[count++] = *page_id;
            GS_LOG_DEBUG_INF("[DTC RCY] process recovery set, page [%u-%u] no need to rcy in instance=%u",
                page_id->file, page_id->page, session->inst_id);
        }
    }
    GS_LOG_RUN_INF("[DTC RCY] master process rcy set, total check page count=%u, collect no_rcy page count=%u",
                   req->count, count);

    mes_release_message_buf(receive_msg->buffer);
    // send the no_rcy pages to reformer
    if (dtc_send_page_back_to_node(session, pages, count, GS_TRUE, src_inst, MES_CMD_SEND_RCY_SET_ACK) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[DTC RCY] failed to send rcy set result to instance=%u", src_inst);
        CM_FREE_PTR(pages);
        return;
    }
    CM_FREE_PTR(pages);
}

bool8 dtc_rcy_page_in_rcyset(page_id_t page_id)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;

    if (dtc_rcy->full_recovery) {
        return GS_TRUE;
    }

    rcy_set_t *rcy_set = &dtc_rcy->rcy_set;
    uint32 hash_id = dtc_rcy_bucket_hash(page_id, rcy_set->bucket_num);
    rcy_set_bucket_t *bucket = &rcy_set->buckets[hash_id];
    rcy_set_item_t *item = dtc_rcy_get_item(bucket, page_id);
    knl_panic_log(item != NULL, "rcy set item is NULL, panic info: page[%u-%u] is not in rcy set, but appears in "
                  "replay", page_id.file, page_id.page);
    return item->need_replay;
}

void dtc_rcy_page_update_need_replay(page_id_t page_id)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    rcy_set_t *rcy_set = &dtc_rcy->rcy_set;
    uint32 hash_id = dtc_rcy_bucket_hash(page_id, rcy_set->bucket_num);
    rcy_set_bucket_t *bucket = &rcy_set->buckets[hash_id];
    rcy_set_item_t *item = dtc_rcy_get_item(bucket, page_id);
    knl_panic_log(item != NULL, "rcy set item is NULL, panic info: page[%u-%u] is not in rcy set, but appears in "
                  "replay", page_id.file, page_id.page);
    item->need_replay = GS_TRUE;
}

void dtc_print_batch(log_batch_t *batch, uint8 node_id)
{
    GS_LOG_DEBUG_INF("[DTC RCY] Log Batch lfn=%llu, lsn=%llu, scn=%llu, head magic=%llx. point [%u-%u/%u], "
        "size=%u, space size=%u for instance=%u",
        (uint64)batch->head.point.lfn, batch->lsn, batch->scn, batch->head.magic_num,
        batch->head.point.rst_id, batch->head.point.asn, batch->head.point.block_id,
        batch->size, batch->space_size, node_id);
}

void dtc_rcy_close_logfile(knl_session_t *session)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;

    if (dtc_rcy->rcy_nodes == NULL) {
        return;
    }

    for (uint32 i = 0; i < dtc_rcy->node_count; i++) {
        dtc_rcy_node_t *rcy_node = &dtc_rcy->rcy_nodes[i];

        if (rcy_node == NULL) {
            continue;
        }

        if (rcy_node->arch_file.handle != GS_INVALID_HANDLE) {
            cm_close_device(cm_device_type(rcy_node->arch_file.name), &rcy_node->arch_file.handle);
            rcy_node->arch_file.handle = GS_INVALID_HANDLE;
            rcy_node->arch_file.name[0] = '\0';
            rcy_node->arch_file.head.rst_id = 0;
            rcy_node->arch_file.head.asn = 0;
        }

        logfile_set_t *log_set = LOGFILE_SET(session, rcy_node->node_id);
        for (uint32 j = 0; j < log_set->logfile_hwm; j++) {
            if (rcy_node->handle[j] != GS_INVALID_HANDLE) {
                cm_close_device(log_set->items[j].ctrl->type, &rcy_node->handle[j]);
            }
        }
    }
}

void dtc_recovery_close(knl_session_t *session)
{
    GS_LOG_RUN_INF("[DTC RCY] start dtc recovery close");
    if (rc_is_master() == GS_FALSE) {
        return;
    }

    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;

    // [reformer] close logfile handle
    dtc_rcy_close_logfile(session);

    // [reformer] release memory malloced in dtc_rcy_init_rcyset
    while (dtc_rcy->rcy_set_ref_num != 0) {
        GS_LOG_RUN_INF("[DTC RCY] wait rcy_set ref num=%u", dtc_rcy->rcy_set_ref_num);
        cm_sleep(DTC_RCY_WAIT_REF_NUM_CLEAN_SLEEP_TIME);
    }

    // [reformer] release memory malloced in paral analyze
    for (uint32 i = 0; i < GS_MAX_INSTANCES; i++) {
        if (dtc_rcy->rcy_set.pages[i] != NULL) {
            CM_FREE_PTR(dtc_rcy->rcy_set.pages[i]);
        }
    }

    rcy_set_item_pool_t *pool = dtc_rcy->rcy_set.item_pools;
    rcy_set_item_pool_t *next = NULL;
    while (pool != NULL) {
        next = pool->next;
        CM_FREE_PTR(pool);
        pool = next;
    }

    // [reformer] release memory malloced in dtc_rcy_init_rcynode
    if (dtc_rcy->rcy_nodes != NULL) {
        for (uint32 i = 0; i < dtc_rcy->node_count; i++) {
            if (&dtc_rcy->rcy_nodes[i].read_buf != NULL) {
                cm_aligned_free(&dtc_rcy->rcy_nodes[i].read_buf);
            }
        }
    }
    // [reformer] release memroy malloced in dtc_rcy_init_context
    CM_FREE_PTR(dtc_rcy->rcy_nodes);
    
    rcy_set_t *rcy_set = &dtc_rcy->rcy_set;
    if (rcy_set->buckets != NULL) {
        CM_FREE_PTR(rcy_set->buckets);
    }

    // [reformer][paral_rcy] release memory and session malloced in dtc_rcy_init_replay_proc
    if (dtc_rcy->paral_rcy) {
        rcy_close_proc(session);
        rcy_free_buffer(&session->kernel->rcy_ctx);
    }

    // [reformer][partial_recovery]
    if (!dtc_rcy->full_recovery) {
        g_knl_callback.release_knl_session(session);
    }

    dtc_rcy->in_progress = GS_FALSE;
    dtc_rcy->ss->dtc_session_type = DTC_TYPE_NONE;
    GS_LOG_RUN_INF("[DTC RCY] finish dtc recovery close");
}

static inline bool32 dtc_log_file_not_used(dtc_node_ctrl_t *ctrl, uint32 file)
{
    bool32 not_used = GS_FALSE;

    if (ctrl->log_first <= ctrl->log_last) {
        not_used = file < ctrl->log_first || file > ctrl->log_last;
    } else {
        not_used = file < ctrl->log_first && file > ctrl->log_last;
    }
    return not_used;
}

static inline void dtc_init_not_used_log_file(log_file_t *file, database_t *db)
{
    file->head.rst_id = db->ctrl.core.resetlogs.rst_id;
    file->head.write_pos = CM_CALC_ALIGN(sizeof(log_file_head_t), file->ctrl->block_size);
    file->head.block_size = file->ctrl->block_size;
    file->head.asn = GS_INVALID_ASN;
}

static inline void dtc_init_dbs_log_file(log_file_t *file, database_t *db)
{
    file->head.rst_id = db->ctrl.core.resetlogs.rst_id;
    file->head.write_pos = 0;
}

status_t dtc_init_node_logset(knl_session_t *session, uint8 idx)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_rcy_node_t *rcy_node = &dtc_rcy->rcy_nodes[idx];
    logfile_set_t *file_set = LOGFILE_SET(session, rcy_node->node_id);
    dtc_node_ctrl_t *ctrl = dtc_get_ctrl(session, rcy_node->node_id);
    database_t *db = &session->kernel->db;
    log_file_t *file = NULL;
    char *buf = rcy_node->read_buf.aligned_buf;

    if (session->kernel->id == rcy_node->node_id) {
        return GS_SUCCESS;
    }
    
    file_set->logfile_hwm = ctrl->log_hwm;
    file_set->log_count = ctrl->log_count;

    for (uint32 i = 0; i < file_set->logfile_hwm; i++) {
        file = &file_set->items[i];
        file->ctrl = (log_file_ctrl_t *)db_get_log_ctrl_item(db->ctrl.pages, i, sizeof(log_file_ctrl_t),
                                                             db->ctrl.log_segment, rcy_node->node_id);
        if (LOG_IS_DROPPED(file->ctrl->flg)) {
            continue;
        }

        if (dtc_log_file_not_used(ctrl, i)) {
            dtc_init_not_used_log_file(file, db);
            continue;
        }

        // logfile can be opened for a long time, closed in db_close_log_files
        if (cm_open_device(file->ctrl->name, file->ctrl->type, knl_io_flag(session), &rcy_node->handle[i]) !=
            GS_SUCCESS) {
            GS_LOG_RUN_ERR("[DB] failed to open redo log file=%s ", file->ctrl->name);
            return GS_ERROR;
        }
        // The log header does not need to be written.
        if (cm_dbs_is_enable_dbs() == GS_TRUE) {
            dtc_init_dbs_log_file(file, db);
            GS_LOG_RUN_INF("[DTC RCY] Init logfile=%s, handle=%d, point=[%u-%u] write_pos=%llu for instance=%u",
                           file->ctrl->name, rcy_node->handle[i],
                           file->head.rst_id, file->head.asn, file->head.write_pos, rcy_node->node_id);
            break;
        }
        if (cm_read_device(file->ctrl->type, rcy_node->handle[i], 0, buf,
                           CM_CALC_ALIGN(sizeof(log_file_head_t), file->ctrl->block_size)) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[DB] failed to open redo log file=%s ", file->ctrl->name);
            // close file in dtc_rcy_close
            return GS_ERROR;
        }

        if (log_verify_head_checksum(session, (log_file_head_t *)buf, file->ctrl->name) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[DTC RCY] failed to verify head checksum of log file=%s", file->ctrl->name);
            // close file in dtc_rcy_close
            return GS_ERROR;
        }

        errno_t ret = memcpy_sp(&file->head, sizeof(log_file_head_t), buf, sizeof(log_file_head_t));
        knl_securec_check(ret);
        GS_LOG_RUN_INF("[DTC RCY] Init logfile=%s, handle=%d, point=[%u-%u] write_pos=%llu for instance=%u",
                       file->ctrl->name, rcy_node->handle[i],
                       file->head.rst_id, file->head.asn, file->head.write_pos, rcy_node->node_id);
    }

    return GS_SUCCESS;
}

static inline void dtc_rcy_next_file(knl_session_t *session, uint32 idx, bool32 *need_more_log)
{
    reset_log_t *reset_log = &session->kernel->db.ctrl.core.resetlogs;
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    reform_rcy_node_t *rcy_log_point = &dtc_rcy->rcy_log_points[idx];
    dtc_rcy_node_t *rcy_node = &dtc_rcy->rcy_nodes[idx];
    log_point_t *point = &rcy_log_point->rcy_point;
    dtc_node_ctrl_t *ctrl = dtc_get_ctrl(session, rcy_log_point->node_id);

    if (cm_dbs_is_enable_dbs() == GS_FALSE) {
        logfile_set_t *log_set = LOGFILE_SET(session, rcy_log_point->node_id);
        uint32 curr_file = ctrl->log_last;
        if (LOG_POINT_FILE_EQUAL(*point, log_set->items[curr_file].head)) {
            *need_more_log = GS_FALSE;
            return;
        }
    }
    if (point->rst_id < reset_log->rst_id && point->asn == ctrl->last_asn &&
        (uint64)point->lfn == ctrl->last_lfn) {
        point->rst_id++;
        point->asn++;
        point->block_id = 0;
        *need_more_log = GS_TRUE;
        GS_LOG_RUN_INF("[DTC RCY] Move log point to [%u-%u/%u/%llu]",
            (uint32)point->rst_id, point->asn, point->block_id, (uint64)point->lfn);
    } else {
        point->asn++;
        point->block_id = 0;
        *need_more_log = GS_TRUE;
        GS_LOG_RUN_INF("[DTC RCY] Move log point to [%u-%u/%u/%llu]",
            (uint32)point->rst_id, point->asn, point->block_id, (uint64)point->lfn);
    }
    rcy_node->curr_file_length = 0;
}

// only call in dbstor opened
static bool32 dtc_rcy_check_ulog(knl_session_t *session, uint32 idx)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_rcy_node_t *rcy_node = &dtc_rcy->rcy_nodes[idx];
    reform_rcy_node_t *rcy_log_point = &dtc_rcy->rcy_log_points[idx];
    log_point_t *point = &rcy_log_point->rcy_point;
    uint64 start_lsn = point->lsn + 1;
    int32 *handle = &rcy_node->handle[0];
    logfile_set_t *log_set = LOGFILE_SET(session, rcy_log_point->node_id);
    log_file_t *file = &log_set->items[0];
    device_type_t type = cm_device_type(file->ctrl->name);
    // logfile can be opened for a long time, closed in db_close_log_files
    if (cm_open_device(file->ctrl->name, type, knl_io_flag(session), handle) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[DB] failed to open redo log file %s ", file->ctrl->name);
        return GS_ERROR;
    }

    bool32 ulog_is_valid = cm_check_device_offset_valid(type, *handle, start_lsn);
    GS_LOG_RUN_INF("[DTC RCY] check ulog lsn %lld from %s, handle %d, inst_id %u result  %d", start_lsn,
                   file->ctrl->name, *handle, rcy_log_point->node_id, ulog_is_valid);
    return ulog_is_valid;
}

// only call in dbstor opened
static bool32 dtc_rcy_check_log_is_exist(knl_session_t *session, uint32 idx)
{
    return dtc_rcy_check_ulog(session, idx);
}

uint32 dtc_rcy_get_logfile_by_node(knl_session_t *session, uint32 idx)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_rcy_node_t *rcy_node = &dtc_rcy->rcy_nodes[idx];
    reform_rcy_node_t *rcy_log_point = &dtc_rcy->rcy_log_points[idx];
    logfile_set_t *log_set = LOGFILE_SET(session, rcy_log_point->node_id);
    log_point_t *point = &rcy_log_point->rcy_point;
    log_file_t *file = NULL;

    for (uint32 i = 0; i < log_set->logfile_hwm; i++) {
        file = &log_set->items[i];

        if (LOG_IS_DROPPED(file->ctrl->flg)) {
            continue;
        }
        // Only one log file is required for DBStor.
        if (cm_dbs_is_enable_dbs() == GS_TRUE) {
            if (rcy_node->ulog_exist_data) {
                return i;
            }
            return GS_INVALID_ID32;
        }

        if (file->head.rst_id != point->rst_id || file->head.asn != point->asn) {
            continue;
        }

        cm_latch_s(&file->latch, session->id, GS_FALSE, NULL);
        if (file->head.rst_id != point->rst_id || file->head.asn != point->asn) {
            cm_unlatch(&file->latch, NULL);
            continue;
        }

        return i;
    }

    return GS_INVALID_ID32;
}

status_t dtc_rcy_set_batch_invalidate(knl_session_t *session, log_batch_t *batch)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_rcy_node_t *rcy_node = &dtc_rcy->rcy_nodes[dtc_rcy->curr_node_idx];
    if (rcy_node->curr_file_length < batch->space_size) {
        return GS_SUCCESS;
    }
    rcy_node->curr_file_length -= batch->space_size;
    arch_file_t *file = &rcy_node->arch_file;
    device_type_t type = cm_device_type(file->name);
    batch->head.magic_num = LOG_INVALIDATE_MAGIC_NUMBER;
    int64 offset = (int64)(rcy_node->curr_file_length + rcy_node->blk_size);
    if (cm_write_device(type, file->handle, offset, (void *)batch, (int32)batch->space_size) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[DTC RCY] ABORT INFO: flush batch:%s, offset:%lld, size:%d failed.",
                       file->name, offset, (int32)batch->space_size);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t dtc_rcy_read_log(knl_session_t *session, int32 *handle, const char *name, int64 offset,
                          void *buf, int64 buf_size, int64 size_need_read, uint32 *size_read)
{
    int64 size = size_need_read;
    *size_read = 0;
    if (size_need_read == 0) {
        return GS_SUCCESS;
    }
    if (size_need_read > buf_size) {
        size = buf_size;
    }
    device_type_t type = cm_device_type(name);
    if (cm_open_device(name, type, knl_io_flag(session), handle) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[DTC RCY] failed to open redo log, filename=%s", name);
        return GS_ERROR;
    }
    /* size <= buf_size, (uint32)size cannot overflow */
    if (cm_dbs_is_enable_dbs() == GS_TRUE) {
        int32 return_size = 0;
        if (cm_read_device_nocheck(type, *handle, offset, buf, (int32)size, &return_size) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[DTC RCY] failed to read redo log size_need_read=%lld, offet=%lld, logfile handle=%d "
                "from file=%s", size_need_read, offset, *handle, name);
            return GS_ERROR;
        }
        *size_read = return_size;
    } else {
        if (cm_read_device(type, *handle, offset, buf, (int32)size) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[DTC RCY] failed to read redo log size_need_read=%lld, offet=%lld, logfile handle=%d "
                "from file=%s", size_need_read, offset, *handle, name);
            return GS_ERROR;
        }
        *size_read = (int32)size;
    }
    GS_LOG_DEBUG_INF("[DTC RCY] read redo log size=%lld, offset=%lld from=%s, size_need_read=%lld", size, offset, name,
                     size_need_read);
    return GS_SUCCESS;
}

status_t dtc_rcy_read_online_log(knl_session_t *session, uint32 file_id, uint32 idx, uint32 *size_read)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_rcy_node_t *rcy_node = &dtc_rcy->rcy_nodes[idx];
    reform_rcy_node_t *rcy_log_point = &dtc_rcy->rcy_log_points[idx];
    logfile_set_t *log_set = LOGFILE_SET(session, rcy_log_point->node_id);
    log_file_t *file = &log_set->items[file_id];
    int32 *handle = &rcy_node->handle[file_id];
    char *buf = rcy_node->read_buf.aligned_buf;
    int64 buf_size = rcy_node->read_buf.buf_size;
    log_point_t *point = &rcy_log_point->rcy_point;

    if (point->block_id == 0) {
        point->block_id = 1;
    }

    if (rcy_node->blk_size == 0) {
        rcy_node->blk_size = file->ctrl->block_size;
    }

    int64 file_size = file->head.write_pos;
    if (file->ctrl->status == LOG_FILE_CURRENT) {
        // the write_pos of current log file is not accurate
        file_size = file->ctrl->size;
    }

    int64 offset = (int64)point->block_id * file->ctrl->block_size;
    int64 size_need_read = file_size - offset;
    // Obtain logs based on the LSN for DBStor.
    if (cm_dbs_is_enable_dbs() == GS_TRUE) {
        offset = point->lsn + 1;   // read redo data after rcy_point.
        size_need_read = buf_size; // read as much data as possible.
    }
    GS_LOG_RUN_INF("[DTC RCY] start read online redo log point %u/%u from %s", point->asn, point->block_id, file->ctrl->name);
    return dtc_rcy_read_log(session, handle, file->ctrl->name, offset, buf, buf_size, size_need_read, size_read);
}

static status_t dtc_rcy_load_archfile(knl_session_t *session, uint32 idx, arch_file_t *file, log_point_t *point)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_rcy_node_t *rcy_node = &dtc_rcy->rcy_nodes[idx];
    bool32 is_dbstor = cm_dbs_is_enable_dbs();
    if (!is_dbstor && file->head.rst_id == point->rst_id && file->head.asn == point->asn) {
        // already load the need archived logfile.
        return GS_SUCCESS;
    }

    if (file->handle != GS_INVALID_HANDLE) {
        cm_close_device(cm_device_type(file->name), &file->handle);
        file->handle = GS_INVALID_HANDLE;
    }

    if (is_dbstor) {
        arch_ctrl_t *arch_ctrl = arch_get_archived_log_info_for_recovery(session, (uint32)point->rst_id, point->asn,
                                                                         ARCH_DEFAULT_DEST, point->lsn,
                                                                         rcy_node->node_id);
        if (arch_ctrl == NULL) {
            GS_LOG_RUN_ERR("[RECOVERY] failed to get archived log for [%u-%u-%u-%llu]",
                           rcy_node->node_id, point->rst_id, point->asn, point->lsn);
            return GS_ERROR;
        }
        point->asn = arch_ctrl->asn;
        arch_set_archive_log_name_with_lsn(session, arch_ctrl->rst_id, arch_ctrl->asn, ARCH_DEFAULT_DEST,
            file->name, GS_FILE_NAME_BUFFER_SIZE, rcy_node->node_id, arch_ctrl->start_lsn, arch_ctrl->end_lsn);
        if (!cm_exist_device(cm_device_type(file->name), file->name)) {
            GS_LOG_RUN_ERR("[DTC RCY] failed to get archived redo log file[%u-%u] for instance %u",
                           (uint32)point->rst_id, point->asn, rcy_node->node_id);
            return GS_ERROR;
        }
    } else {
        if (!arch_get_archived_log_name(session, (uint32)point->rst_id, point->asn, ARCH_DEFAULT_DEST, file->name,
                                        GS_FILE_NAME_BUFFER_SIZE, rcy_node->node_id)) {
            // TODO: Need to use the archive dest of corresponding node
            arch_set_archive_log_name(session, (uint32)point->rst_id, point->asn, ARCH_DEFAULT_DEST,
                                      file->name, GS_FILE_NAME_BUFFER_SIZE, rcy_node->node_id);
            if (!cm_exist_device(cm_device_type(file->name), file->name)) {
                GS_LOG_RUN_ERR("[DTC RCY] failed to get archived redo log file[%u-%u] for instance %u",
                               (uint32)point->rst_id, point->asn, rcy_node->node_id);
                return GS_ERROR;
            }
        }
    }

    if (cm_open_device(file->name, cm_device_type(file->name), knl_io_flag(session), &file->handle) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[DTC RCY] failed to open archived redo log file %s", file->name);
        return GS_ERROR;
    }

    /* size <= buf_size, (uint32)size cannot overflow */
    if (cm_read_device(cm_device_type(file->name), file->handle, 0, rcy_node->read_buf.aligned_buf,
                       CM_CALC_ALIGN((uint32)sizeof(log_file_head_t), 512)) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[DTC RCY] failed to read %s, offset 0 handle %d", file->name, file->handle);
        return GS_ERROR;
    }

    errno_t errcode;
    errcode = memcpy_s(&file->head, (int32)sizeof(log_file_head_t), rcy_node->read_buf.aligned_buf,
                       (int32)sizeof(log_file_head_t));
    knl_securec_check(errcode);

    return log_verify_head_checksum(session, &file->head, file->name);
}

bool32 dtc_rcy_validate_batch(log_batch_t *batch)
{
    log_batch_tail_t *tail = (log_batch_tail_t *)((char *)batch + batch->size - sizeof(log_batch_tail_t));
    if (batch->head.magic_num == LOG_MAGIC_NUMBER &&
        tail->magic_num == LOG_MAGIC_NUMBER &&
        batch->head.point.lfn == tail->point.lfn &&
        batch->size != 0) {
        return GS_TRUE;
    }

    if (batch->head.magic_num == LOG_INVALIDATE_MAGIC_NUMBER &&
        tail->magic_num == LOG_MAGIC_NUMBER &&
        batch->head.point.lfn == tail->point.lfn &&
        batch->size != 0) {
        return GS_FALSE;
    }
    GS_LOG_RUN_ERR("[DTC RCY] head magic_num:%llx, lsn:%llu, lfn:%llu, tail magic_num:%llx, lsn:%llu, "
        "lfn:%llu, size:%u", batch->head.magic_num, batch->head.point.lsn, (uint64)batch->head.point.lfn,
        tail->magic_num, tail->point.lsn, (uint64)tail->point.lfn, batch->size);
    if (cm_dbs_is_enable_dbs() == GS_TRUE) {
        knl_panic(0);
    }
    return GS_FALSE;
}

status_t dtc_rcy_find_batch_by_lsn(char *buf, dtc_rcy_node_t *rcy_node, log_point_t *point,
                                   int32 size_read, bool8 *is_find_start)
{
    int32 buffer_size = size_read;
    uint32 invalide_size = 0;
    log_batch_t *batch = NULL;
    if (buf == NULL) {
        GS_LOG_RUN_ERR("[DTC RCY] batch is null, read_size[%d], invalide_size[%u], point[%u/%u/%u%llu/%llu]",
                       size_read, invalide_size, point->rst_id, point->asn,
                       point->block_id, point->lsn, (uint64)point->lfn);
        return GS_ERROR;
    }
    while (buffer_size >= sizeof(log_batch_t)) {
        batch = (log_batch_t *)(buf + invalide_size);
        if (buffer_size < batch->size) {
            break;
        }
        if (!dtc_rcy_validate_batch(batch)) {
            GS_LOG_RUN_ERR("[DTC RCY] batch is invalidate, read_size[%d], invalide_size[%u], point[%u/%u/%u%llu/%llu]",
                           size_read, invalide_size, point->rst_id, point->asn,
                           point->block_id, point->lsn, (uint64)point->lfn);
            rcy_node->recover_done = GS_TRUE;
            *is_find_start = GS_TRUE;
            rcy_node->read_pos += invalide_size;
            return GS_ERROR;
        }
        if (batch->head.point.lsn > point->lsn) {
            break;
        }
        invalide_size += batch->space_size;
        buffer_size -= batch->space_size;
    }
    point->block_id += invalide_size / rcy_node->blk_size;
    rcy_node->curr_file_length += invalide_size;
    if (batch->head.point.lsn > point->lsn) {
        *is_find_start = GS_TRUE;
        rcy_node->read_pos += invalide_size;
        return GS_SUCCESS;
    }
    return GS_SUCCESS;
}

status_t dtc_rcy_read_archived_log(knl_session_t *session, uint32 idx, uint32 *size_read)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_rcy_node_t *rcy_node = &dtc_rcy->rcy_nodes[idx];
    reform_rcy_node_t *rcy_log_point = &dtc_rcy->rcy_log_points[idx];
    arch_file_t *file = &rcy_node->arch_file;
    char *buf = rcy_node->read_buf.aligned_buf;
    int64 buf_size = rcy_node->read_buf.buf_size;
    log_point_t *point = &rcy_log_point->rcy_point;
    bool8 is_find_start = GS_TRUE;

    if (dtc_rcy_load_archfile(session, idx, file, point) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (point->block_id == 0) {
        point->block_id = 1;
    }

    if (point->block_id == GS_INFINITE32) {
        is_find_start = GS_FALSE;
        point->block_id = 1;
    }

    if (rcy_node->blk_size == 0) {
        rcy_node->blk_size = file->head.block_size;
    }

    do {
        int64 offset = (int64)point->block_id * file->head.block_size;
        int64 size_need_read = file->head.write_pos - offset;
        status_t status = dtc_rcy_read_log(session, &file->handle, file->name,
                                           offset, buf, buf_size, size_need_read, size_read);
        if (status != GS_SUCCESS) {
            return status;
        }
        if (*size_read == 0) {
            return status;
        }
        if (is_find_start) {
            break;
        }
        // seek batch pos by lsn, only recovery for restore and opened dbstor
        // other by blockid
        if (dtc_rcy_find_batch_by_lsn(buf, rcy_node, point, (int32)(*size_read), &is_find_start) != GS_SUCCESS) {
            return GS_ERROR;
        }
    } while (*size_read != 0 && !is_find_start);
    return GS_SUCCESS;
}

status_t dtc_recover_check_assign_nodeid(knl_session_t *session, uint32_t node_id)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    reform_rcy_node_t *rcy_log_point = NULL;
    dtc_node_ctrl_t *ctrl = NULL;

    knl_panic(node_id <= dtc_rcy->node_count);

    rcy_log_point = &dtc_rcy->rcy_log_points[node_id];
    ctrl = dtc_get_ctrl(session, rcy_log_point->node_id);

    GS_LOG_RUN_INF("[DTC RCY] node:%u, recovery real end with file: %u, point: %u, lfn: %llu", rcy_log_point->node_id,
                   rcy_log_point->rcy_point.asn, rcy_log_point->rcy_point.block_id,
                   (uint64)rcy_log_point->rcy_point.lfn);
    GS_LOG_RUN_INF("[DTC RCY] node:%u, current lfn: %llu, rcy point lfn: %llu, lrp point lfn: %llu",
                   rcy_log_point->node_id, (uint64)rcy_log_point->rcy_point.lfn, (uint64)ctrl->rcy_point.lfn,
                   (uint64)(uint64)ctrl->lrp_point.lfn);

    if (rcy_log_point->rcy_point.lfn >= ctrl->lrp_point.lfn) {
        return GS_SUCCESS;
    }

    cm_reset_error();
    GS_THROW_ERROR(ERR_INVALID_RCV_END_POINT, rcy_log_point->rcy_point.asn, rcy_log_point->rcy_point.block_id,
                   rcy_log_point->rcy_point.asn, rcy_log_point->rcy_point.block_id);
    return GS_ERROR;
}

bool8 dtc_rcy_check_recovery_is_done(knl_session_t *session, uint32 idx)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_rcy_node_t *rcy_node = &dtc_rcy->rcy_nodes[idx];
    if ((cm_dbs_is_enable_dbs() == GS_TRUE) &&
        (session->kernel->db.recover_for_restore == GS_FALSE) &&
        (rcy_node->ulog_exist_data == GS_FALSE)) {
        rcy_node->recover_done = GS_TRUE;
        return GS_TRUE;
    }
    return GS_FALSE;
}

status_t dtc_rcy_read_node_log(knl_session_t *session, uint32 idx, uint32 *size_read)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_rcy_node_t *rcy_node = &dtc_rcy->rcy_nodes[idx];
    status_t status;
    timeval_t tv_begin;

    rcy_node->read_pos = 0;
    rcy_node->write_pos = 0;

    if (rcy_node->recover_done) {
        // current instance has nothing to recover.
        return GS_SUCCESS;
    }

    if (dtc_rcy_check_recovery_is_done(session, idx)) {
        return GS_SUCCESS;
    }
    uint32 logfile_id = dtc_rcy_get_logfile_by_node(session, idx);
    if (logfile_id != GS_INVALID_ID32) {
        cantian_record_io_stat_begin(IO_RECORD_EVENT_RECOVERY_READ_ONLINE_LOG, &tv_begin);
        status = dtc_rcy_read_online_log(session, logfile_id, idx, size_read);
        log_unlatch_file(session, logfile_id);
        cantian_record_io_stat_end(IO_RECORD_EVENT_RECOVERY_READ_ONLINE_LOG, &tv_begin,
            status == GS_SUCCESS ? IO_STAT_SUCCESS : IO_STAT_FAILED);
        GS_LOG_RUN_INF("[DTC RCY] finish read online redo log of crashed node=%u, logfile_id=%u, size_read=%u",
                       rcy_node->node_id, logfile_id, *size_read);
    } else {
        status = dtc_rcy_read_archived_log(session, idx, size_read);
        GS_LOG_DEBUG_INF("[DTC RCY] dtc rcy read archived redo log of crashed node=%u, logfile_id=%u, size_read=%u",
            rcy_node->node_id, logfile_id, *size_read);
        if ((status != GS_SUCCESS) && (dtc_recover_check_assign_nodeid(session, idx) == GS_SUCCESS)) {
            return GS_SUCCESS;
        }
    }

    if (status == GS_ERROR) {
        GS_LOG_RUN_ERR("[DTC RCY] failed to load redo log of crashed node=%u", rcy_node->node_id);
        return GS_ERROR;
    }

    rcy_node->write_pos += *size_read;
    rcy_node->recover_done = GS_FALSE;

    if (dtc_rcy->rcy_stat.last_rcy_set_num <= 0) {
        dtc_rcy->rcy_stat.last_rcy_log_size += *size_read;
    }

    return GS_SUCCESS;
}

status_t dtc_read_all_logs(knl_session_t *session)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;

    // load redo log into buffer
    for (uint32 i = 0; i < dtc_rcy->node_count; i++) {
        if (dtc_init_node_logset(session, i) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[DTC RCY] failed to init logset for crashed node=%u", dtc_rcy->rcy_nodes[i].node_id);
            return GS_ERROR;
        }

        if (cm_dbs_is_enable_dbs() == GS_TRUE) {
            dtc_rcy->rcy_nodes[i].ulog_exist_data = dtc_rcy_check_log_is_exist(session, i);
        }
        uint32 size_read = 0;
        if (dtc_rcy_read_node_log(session, i, &size_read) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[DTC RCY] failed to load redo log of crashed node=%u", dtc_rcy->rcy_nodes[i].node_id);
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t dtc_rcy_verify_analysis_and_recovery_log_point(log_point_t analysis_read_end_point,
    log_point_t recovery_read_end_point)
{
    if (analysis_read_end_point.asn != recovery_read_end_point.asn) {
        return GS_ERROR;
    }
    if (analysis_read_end_point.block_id != recovery_read_end_point.block_id) {
        return GS_ERROR;
    }
    if (analysis_read_end_point.lfn != recovery_read_end_point.lfn) {
        return GS_ERROR;
    }
    if (analysis_read_end_point.lsn != recovery_read_end_point.lsn) {
        return GS_ERROR;
    }
    if (analysis_read_end_point.rst_id != recovery_read_end_point.rst_id) {
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

uint64 dtc_rcy_get_ddl_pitr_lsn(knl_session_t *session, uint64 curr_batch_lsn)
{
    if (session->kernel->db.recover_for_restore && session->kernel->db.ctrl.core.ddl_pitr_lsn != 0) {
        return session->kernel->db.ctrl.core.ddl_pitr_lsn;
    } else {
        return curr_batch_lsn;
    }
}

status_t dtc_rcy_fetch_log_batch(knl_session_t *session, log_batch_t **batch_out)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    log_batch_t *batch = NULL;
    uint32 left_size;
    bool32 batch_loaded = GS_FALSE;
    dtc_rcy_node_t *rcy_node = NULL;
    reform_rcy_node_t *rcy_log_point = NULL;
    uint64 curr_batch_lsn = GS_INVALID_ID64;
    uint32 curr_node_idx;
    uint8 curr_node;

    *batch_out = NULL;
    for (uint32 i = 0; i < dtc_rcy->node_count; i++) {
        rcy_node = &dtc_rcy->rcy_nodes[i];
        rcy_log_point = &dtc_rcy->rcy_log_points[i];
        if (rcy_node->recover_done) {
            if (dtc_rcy->phase == PHASE_ANALYSIS) {
                GS_LOG_RUN_INF(
                    "[DTC RCY] analysis read end point[asn(%u)-block_id(%u)-rst_id(%llu)-lfn(%llu)-lsn(%llu)]",
                    rcy_node->analysis_read_end_point.asn, rcy_node->analysis_read_end_point.block_id,
                    (uint64)rcy_node->analysis_read_end_point.rst_id, (uint64)rcy_node->analysis_read_end_point.lfn,
                    rcy_node->analysis_read_end_point.lsn);
            } else if (dtc_rcy->phase == PHASE_RECOVERY) {
                GS_LOG_RUN_INF(
                    "[DTC RCY] recovery read end point[asn(%u)-block_id(%u)-rst_id(%llu)-lfn(%llu)-lsn(%llu)]",
                    rcy_node->recovery_read_end_point.asn, rcy_node->recovery_read_end_point.block_id,
                    (uint64)rcy_node->recovery_read_end_point.rst_id, (uint64)rcy_node->recovery_read_end_point.lfn,
                    rcy_node->recovery_read_end_point.lsn);
            }
            if (!dtc_rcy->full_recovery && dtc_rcy->phase == PHASE_RECOVERY &&
                dtc_rcy_verify_analysis_and_recovery_log_point(rcy_node->analysis_read_end_point,
                rcy_node->recovery_read_end_point) != GS_SUCCESS) {
                knl_panic_log(0,
                    "[DTC RCY] analysis read end point[asn(%u)-block_id(%u)-rst_id(%llu)-lfn(%llu)-lsn(%llu)] is not "
                    "equal recovery read end point[asn(%u)-block_id(%u)-rst_id(%llu)-lfn(%llu)-lsn(%llu)]",
                    rcy_node->analysis_read_end_point.asn, rcy_node->analysis_read_end_point.block_id,
                    (uint64)rcy_node->analysis_read_end_point.rst_id, (uint64)rcy_node->analysis_read_end_point.lfn,
                    rcy_node->analysis_read_end_point.lsn, rcy_node->recovery_read_end_point.asn,
                    rcy_node->recovery_read_end_point.block_id, (uint64)rcy_node->recovery_read_end_point.rst_id,
                    (uint64)rcy_node->recovery_read_end_point.lfn, rcy_node->recovery_read_end_point.lsn);
            }
            continue;
        }

        // get batch from log buffer
        batch = DTC_RCY_GET_CURR_BATCH(dtc_rcy, i);
        left_size = rcy_node->write_pos - rcy_node->read_pos;
        if (left_size < sizeof(log_batch_t) || left_size < batch->space_size) {
            uint32 read_size = 0;
            // need to read log
            if (dtc_rcy_read_node_log(session, i, &read_size) != GS_SUCCESS) {
                GS_LOG_RUN_ERR("[DTC RCY] failed to load redo log of crashed node=%u", rcy_node->node_id);
                return GS_ERROR;
            }

            if (read_size == 0) {
                // try to advance log point to next file
                bool32 not_finished;
                dtc_rcy_next_file(session, i, &not_finished);
                if (not_finished) {
                    // read log again after advancing the log point
                    if (dtc_rcy_read_node_log(session, i, &read_size) != GS_SUCCESS) {
                        GS_LOG_RUN_ERR("[DTC RCY] failed to load redo log of instance=%u", rcy_node->node_id);
                        return GS_ERROR;
                    }
                }

                // if no more log, set recover done
                if (!not_finished || read_size == 0) {
                    rcy_node->recover_done = GS_TRUE;
                    continue;
                }
            }
        }

        batch = DTC_RCY_GET_CURR_BATCH(dtc_rcy, i);
        if (!dtc_rcy_validate_batch(batch)) {
            // Batch is invalid
            rcy_node->recover_done = GS_TRUE;
            GS_LOG_RUN_INF(
                "[DTC RCY] Invalid batch from instance %u, recovery done with point [%u-%u/%u/%llu],"
                " head lfn:%llu, batch writepos:%u, readpos:%u, space_size:%u, current lsn:%llu, start lsn:%llu",
                rcy_log_point->node_id, rcy_log_point->rcy_point.rst_id, rcy_log_point->rcy_point.asn,
                rcy_log_point->rcy_point.block_id, (uint64)rcy_log_point->rcy_point.lfn, (uint64)batch->head.point.lfn,
                rcy_node->write_pos, rcy_node->read_pos, batch->space_size, rcy_log_point->rcy_point.lsn,
                rcy_log_point->rcy_point_saved.lsn);
            continue;
        }

        if (!LFN_IS_CONTINUOUS(batch->head.point.lfn, rcy_log_point->rcy_point.lfn)) {
            // batch is not continuous
            rcy_node->recover_done = GS_TRUE;
            GS_LOG_RUN_INF("[DTC RCY] not continuous batch from instance %u, "
                "recovery done with point [%u-%u/%u/%llu/%llu],current point [%u-%u/%u/%llu/%llu]",
                rcy_log_point->node_id, batch->head.point.rst_id, batch->head.point.asn,
                batch->head.point.block_id, (uint64)batch->head.point.lfn, batch->head.point.lsn,
                rcy_log_point->rcy_point.rst_id, rcy_log_point->rcy_point.asn, rcy_log_point->rcy_point.block_id,
                (uint64)rcy_log_point->rcy_point.lfn, rcy_log_point->rcy_point.lsn);
            continue;
        }

        if (rcy_verify_checksum(session, batch) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[DTC RCY] failed to verify log batch checksum of instance %u with rcy point"
                           " [%u-%u/%u%llu], betch_lsn=%llu",
                           rcy_log_point->node_id, rcy_log_point->rcy_point.rst_id, rcy_log_point->rcy_point.asn,
                           rcy_log_point->rcy_point.block_id, (uint64)rcy_log_point->rcy_point.lfn, batch->lsn);
            return GS_ERROR;
        }

        if (batch->lsn < curr_batch_lsn) {
            curr_node_idx = (uint8)i;
            curr_node = rcy_node->node_id;
            curr_batch_lsn = batch->lsn;
            batch_loaded = GS_TRUE;
        }
    }

    if (batch_loaded) {
        *batch_out = DTC_RCY_GET_CURR_BATCH(dtc_rcy, curr_node_idx);
        dtc_print_batch(*batch_out, curr_node);
        dtc_rcy->curr_node_idx = curr_node_idx;
        dtc_rcy->curr_node = curr_node;
        dtc_rcy->curr_batch_lsn = curr_batch_lsn;
        rcy_node = &dtc_rcy->rcy_nodes[curr_node_idx];
        rcy_log_point = &dtc_rcy->rcy_log_points[curr_node_idx];

        // move rcy point to log point of read batch
        rcy_log_point->lsn = curr_batch_lsn;
        rcy_log_point->rcy_point.lfn = (*batch_out)->head.point.lfn;
        rcy_log_point->rcy_point.block_id += (*batch_out)->space_size / rcy_node->blk_size;
        rcy_node->read_pos += (*batch_out)->space_size;
        rcy_node->curr_file_length += (*batch_out)->space_size;
        if (cm_dbs_is_enable_dbs() == GS_TRUE) {
            rcy_log_point->rcy_point.lsn = curr_batch_lsn;
        }

        if ((*batch_out)->head.point.lfn >= rcy_node->pitr_lfn && rcy_node->ddl_lsn_pitr == GS_INVALID_ID64) {
            rcy_node->ddl_lsn_pitr = dtc_rcy_get_ddl_pitr_lsn(session, curr_batch_lsn);
            GS_LOG_RUN_INF("[DTC RCY] batch lfn %llu, pitr_lfn %llu, rcy ddl lsn pitr[core %llu/curr %llu], node id %u",
                           (uint64)(*batch_out)->head.point.lfn, rcy_node->pitr_lfn,
                           session->kernel->db.ctrl.core.ddl_pitr_lsn, rcy_node->ddl_lsn_pitr, curr_node_idx);
        }
        if (dtc_rcy->phase == PHASE_ANALYSIS) {
            rcy_node->analysis_read_end_point = (*batch_out)->head.point;
        } else if (dtc_rcy->phase == PHASE_RECOVERY) {
            rcy_node->recovery_read_end_point = (*batch_out)->head.point;
        }
        GS_LOG_DEBUG_INF("[DTC RCY] Move log point to [%u-%u/%u/%llu] with read pos %u write pos %u for instance %u,"
                         " curr_batch_lsn=%llu",
                         rcy_log_point->rcy_point.rst_id, rcy_log_point->rcy_point.asn,
                         rcy_log_point->rcy_point.block_id, (uint64)rcy_log_point->rcy_point.lfn, rcy_node->read_pos,
                         rcy_node->write_pos, rcy_node->node_id, curr_batch_lsn);
    }

    return GS_SUCCESS;
}

static uint64 dtc_rcy_get_ddl_lsn_pitr(void)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_rcy_node_t *rcy_node = NULL;
    rcy_node = &dtc_rcy->rcy_nodes[dtc_rcy->curr_node_idx];
    return rcy_node->ddl_lsn_pitr;
}

status_t dtc_rcy_process_batch(knl_session_t *session, log_batch_t *batch)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    log_cursor_t cursor;
    log_group_t *group = NULL;
    log_context_t *ctx = &session->kernel->redo_ctx;

    rcy_init_log_cursor(&cursor, batch);
    group = log_fetch_group(ctx, &cursor);
    if (group == NULL) {
        GS_LOG_RUN_ERR("[DTC RCY] the group is NULL.");
        return GS_ERROR;
    }
    uint64 batch_start_lsn = group->lsn;
    while (group != NULL) {
        if (dtc_rcy->phase == PHASE_RECOVERY) {
            if (dtc_rcy_set_pitr_end_replay(session->kernel->db.recover_for_restore, group->lsn)) {
                GS_LOG_RUN_INF("[DTC RCY] pcn is invalide, lsn=%llu, rmid=%u, batch_start_lsn=%llu",
                               group->lsn, group->rmid, batch_start_lsn);
                break;
            }
            session->ddl_lsn_pitr = dtc_rcy_get_ddl_lsn_pitr();
            rcy_replay_group(session, ctx, group);
            GS_LOG_DEBUG_INF("[DTC RCY] before redo replay log group, lsn=%llu, rmid=%u, session->kernel->lsn=%llu",
                group->lsn, group->rmid, session->kernel->lsn);
            // set kernel lsn after replaying one log group
            //DB_SET_LSN(session->kernel->lsn, group->lsn);
            dtc_update_lsn(session, group->lsn);
            GS_LOG_DEBUG_INF("[DTC RCY] after redo replay log group, lsn=%llu, rmid=%u, session->kernel->lsn=%llu",
                group->lsn, group->rmid, session->kernel->lsn);
        } else {
            if (dtc_rcy_analyze_group(session, group) != GS_SUCCESS) {
                GS_LOG_RUN_ERR("[DTC RCY] failed to analyze redo log group, lsn %llu, rmid=%u",
                    group->lsn, group->rmid);
                return GS_ERROR;
            }
            if (dtc_rcy_check_is_end_restore_recovery()) {
                GS_LOG_RUN_INF("[DTC RCY] pcn is invalide, lsn=%llu, rmid=%u, batch_start_lsn=%llu",
                               group->lsn, group->rmid, batch_start_lsn);
                dtc_rcy->end_lsn_restore_recovery = batch_start_lsn;
                GS_RETURN_IFERR(dtc_rcy_set_batch_invalidate(session, batch));
                break;
            }
        }

        group = log_fetch_group(ctx, &cursor);
    }

    GS_LOG_DEBUG_INF("[DTC RCY] Log batch lfn=%llu, lsn=%llu, point [%u-%u/%u] has been processed for instance=%u",
        (uint64)batch->head.point.lfn, batch->lsn, batch->head.point.rst_id, batch->head.point.asn,
        batch->head.point.block_id, dtc_rcy->curr_node);
    return GS_SUCCESS;
}

status_t dtc_recover_check(knl_session_t *session)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    reform_rcy_node_t *rcy_log_point = NULL;
    dtc_node_ctrl_t *ctrl = NULL;
    status_t status = GS_SUCCESS;

    for (uint32 i = 0; i < dtc_rcy->node_count; i++) {
        rcy_log_point = &dtc_rcy->rcy_log_points[i];
        ctrl = dtc_get_ctrl(session, rcy_log_point->node_id);

        GS_LOG_RUN_INF("[DTC RCY] node:%u, recovery real end with file:%u,point:%u,lfn:%llu", rcy_log_point->node_id,
                       rcy_log_point->rcy_point.asn, rcy_log_point->rcy_point.block_id,
                       (uint64)rcy_log_point->rcy_point.lfn);
        GS_LOG_RUN_INF("[DTC RCY] node:%u, current lfn %llu, rcy point lfn %llu, lrp point lfn %llu",
                       rcy_log_point->node_id, (uint64)rcy_log_point->rcy_point.lfn, (uint64)ctrl->rcy_point.lfn,
                       (uint64)(uint64)ctrl->lrp_point.lfn);

        if (rcy_log_point->rcy_point.lfn >= ctrl->lrp_point.lfn) {
            continue;
        }

        GS_LOG_RUN_ERR("[DTC RCY] failed to check dtc recovery rcy point");
        cm_reset_error();
        GS_THROW_ERROR(ERR_INVALID_RCV_END_POINT, rcy_log_point->rcy_point.asn, rcy_log_point->rcy_point.block_id,
                       ctrl->lrp_point.asn, ctrl->lrp_point.block_id);
        status = GS_ERROR;
    }
    return status;
}

status_t dtc_rcy_update_node_info(knl_session_t *session, reform_rcy_node_t *rcy_log_point)
{
    dtc_node_ctrl_t *ctrl = NULL;

    ctrl = dtc_get_ctrl(session, rcy_log_point->node_id);
    knl_panic(log_cmp_point(&ctrl->rcy_point, &rcy_log_point->rcy_point) <= 0);
    knl_panic(ctrl->rcy_point.lfn <= rcy_log_point->rcy_point.lfn);
    ctrl->rcy_point = rcy_log_point->rcy_point;
    ctrl->lrp_point = rcy_log_point->rcy_point;
    ctrl->consistent_lfn = rcy_log_point->rcy_point.lfn;
    ctrl->lsn = rcy_log_point->lsn;
    ctrl->lfn = rcy_log_point->rcy_point.lfn;

    GS_LOG_RUN_INF("[DTC RCY] Update ctrl rcy point to [%u-%u/%u/%llu] for instance %u", ctrl->rcy_point.rst_id,
                   ctrl->rcy_point.asn, ctrl->rcy_point.block_id, (uint64)ctrl->rcy_point.lfn, rcy_log_point->node_id);

    if (dtc_save_ctrl(session, rcy_log_point->node_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t dtc_rcy_update_ckpt_log_point(knl_session_t *session)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    reform_rcy_node_t *rcy_log_point = NULL;

    for (uint32 i = 0; i < dtc_rcy->node_count; i++) {
        rcy_log_point = &dtc_rcy->rcy_log_points[i];
        if (dtc_rcy_update_node_info(session, rcy_log_point) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[DTC RCY] failed to update node info");
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

void dtc_rcy_update_ckpt_prcy_info(knl_session_t *session)
{
    ckpt_context_t* ctx = &session->kernel->ckpt_ctx;

    GS_LOG_RUN_INF("[DTC RCY] save ckpt end point, prcy_trunc_point.asn=%u, prcy_trunc_point.block_id=%u"
                   "prcy_trunc_point.rst_id=%d, prcy_trunc_point.lfn=%llu",
                   g_rc_ctx->prcy_trunc_point.asn, g_rc_ctx->prcy_trunc_point.block_id,
                   g_rc_ctx->prcy_trunc_point.rst_id, (uint64)g_rc_ctx->prcy_trunc_point.lfn);

    cm_spin_lock(&ctx->queue.lock, &session->stat->spin_stat.stat_ckpt_queue);
    g_rc_ctx->prcy_trunc_point = ctx->queue.trunc_point;
    cm_spin_unlock(&ctx->queue.lock);
}

static bool32 ckpt_prcy_flush_check(knl_session_t *session)
{
    if (!DB_IS_CLUSTER(session)) {
        return GS_TRUE;
    }

    if (rc_is_master() == GS_FALSE) {
        return GS_TRUE;
    }
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;

    if (ctx->queue.first != NULL && log_cmp_point(&ctx->queue.first->trunc_point, &g_rc_ctx->prcy_trunc_point) <= 0) {
        return GS_FALSE;
    }

    GS_LOG_DEBUG_INF("[CKPT] finish checkpoint");
    return GS_TRUE;
}

#define CHECK_INTERVAL 100
status_t dtc_update_ckpt_log_point(void)
{
    // wait prcy ckpt finish
    GS_LOG_RUN_INF("[RC][partial start] start waiting prcy ckpt done, session->kernel->lsn=%llu, "
                   "g_rc_ctx->status=%u",
                   ((knl_session_t *)g_rc_ctx->session)->kernel->lsn, g_rc_ctx->status);
    uint32 loop = 0;
    for (;;) {
        GS_RETVALUE_IFTRUE(rc_reform_cancled(), GS_ERROR);
        if (loop % CHECK_INTERVAL == 0) {
            ckpt_trigger(g_rc_ctx->session, GS_FALSE, CKPT_TRIGGER_INC);
            if (ckpt_prcy_flush_check(g_rc_ctx->session)) {
                break;
            }
        }
        cm_sleep(DTC_REFORM_WAIT_TIME);
        loop++;
    }
    GS_LOG_RUN_INF("[RC][partial start] finish waiting prcy ckpt done, session->kernel->lsn=%llu, "
                   "g_rc_ctx->status=%u",
                   ((knl_session_t *)g_rc_ctx->session)->kernel->lsn, g_rc_ctx->status);

    // TODO: multi node crash
    return dtc_rcy_update_ckpt_log_point(g_rc_ctx->session);
}

static void dtc_rcy_set_num_stat(void)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    rcy_set_item_pool_t *pool = dtc_rcy->rcy_set.item_pools;

    while (pool != NULL) {
        dtc_rcy->rcy_stat.last_rcy_set_num += pool->hwm;
        pool = pool->next;
    }
}

static void dtc_rcy_wait_paral_replay_end(knl_session_t *session)
{
    rcy_context_t *rcy = &session->kernel->rcy_ctx;
    rcy_wait_replay_complete(session);
    rcy->rcy_end = GS_TRUE;
}

static bool32 dtc_rcy_pitr_replay_end(rcy_context_t *rcy, log_batch_t *batch)
{
    if (batch->scn <= rcy->max_scn) {
        return GS_FALSE;
    }
    GS_LOG_RUN_INF("[DTC RCY] until time recover done");
    return GS_TRUE;
}

bool32 dtc_rcy_full_recovery_replay_end(rcy_context_t *rcy, log_batch_t *batch)
{
    if (batch->lsn <= rcy->max_lrp_lsn) {
        return GS_FALSE;
    }
    GS_LOG_RUN_INF("[DTC RCY] until lrp[%llu] full_recover done", batch->lsn);
    return GS_TRUE;
}

status_t dtc_rcy_process_batches(knl_session_t *session)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    log_batch_t *batch = NULL;
    status_t status = GS_SUCCESS;
    rcy_context_t *rcy = &session->kernel->rcy_ctx;
    timeval_t elapsed_begin;
    uint64 used_time;
    uint64 fetch_log_time = 0;
    uint64 replay_log_time = 0;

    ELAPSED_BEGIN(elapsed_begin);
    if (dtc_read_all_logs(session) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[DTC RCY] failed to load log files");
        return GS_ERROR;
    }
    ELAPSED_END(elapsed_begin, used_time);
    GS_LOG_RUN_INF("[DTC RCY] dtc_read_all_logs used %llu", used_time);

    ELAPSED_BEGIN(elapsed_begin);
    if (dtc_rcy_fetch_log_batch(session, &batch) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[DTC RCY] failed to extract log batch");
        return GS_ERROR;
    }
    ELAPSED_END(elapsed_begin, fetch_log_time);

    while (batch != NULL) {
        if (session->canceled) {
            GS_THROW_ERROR(ERR_OPERATION_CANCELED);
            status = GS_ERROR;
            break;
        }

        if (session->killed) {
            GS_THROW_ERROR(ERR_OPERATION_KILLED);
            status = GS_ERROR;
            break;
        }

        // check whether need to cancel this task
        if (dtc_rcy->canceled) {
            GS_LOG_RUN_ERR("[DTC RCY] required to cancel this dtc recovery task");
            break;
        }

        if (dtc_rcy_pitr_replay_end(rcy, batch)) {
            break;
        }

        if (dtc_rcy_full_recovery_replay_end(rcy, batch)) {
            break;
        }

        // call batch process function
        ELAPSED_BEGIN(elapsed_begin);
        if (dtc_rcy_process_batch(session, batch) != GS_SUCCESS) {
            status = GS_ERROR;
            ELAPSED_END(elapsed_begin, used_time);
            break;
        }
        ELAPSED_END(elapsed_begin, used_time);
        replay_log_time += used_time;
        // fetch next batch
        ELAPSED_BEGIN(elapsed_begin);
        if (dtc_rcy_check_is_end_restore_recovery()) {
            break;
        }
        if (dtc_rcy_fetch_log_batch(session, &batch) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[DTC RCY] failed to extract log batch");
            status = GS_ERROR;
            break;
        }
        ELAPSED_END(elapsed_begin, used_time);
        fetch_log_time += used_time;
    }

    GS_LOG_RUN_INF("[DTC RCY] dtc_rcy_fetch_log_batch used=%llu", fetch_log_time);
    GS_LOG_RUN_INF("[DTC RCY] dtc_rcy_process_batch used=%llu", replay_log_time);
    return status;
}

static void dtc_rcy_atomic_list_init(dtc_rcy_atomic_list *list)
{
    list->begin      = 0;
    list->end        = 0;
    list->writed_end = 0;
    list->lock       = 0;
}

static uint32 dtc_rcy_atomic_list_pop(dtc_rcy_atomic_list *list)
{
    int64 begin, end;
    uint32 val;
    cm_spin_lock(&list->lock, NULL);
    do {
        begin = list->begin;
        end   = list->writed_end;
        if (begin == end) { // list is empty
            cm_spin_unlock(&list->lock);
            return GS_INVALID_INT32;
        }
        val = list->array[begin % DTC_RCY_PARAL_BUF_LIST_SIZE];
    } while (!cm_atomic_cas(&list->begin, begin, begin + 1));
    cm_spin_unlock(&list->lock);
    return val;
}

static bool8 dtc_rcy_atomic_list_push(dtc_rcy_atomic_list *list, uint32 val)
{
    int64 begin, end;
    cm_spin_lock(&list->lock, NULL);
    do {
        begin = list->begin;
        end   = list->end;
        if (begin + DTC_RCY_PARAL_BUF_LIST_SIZE == end) { // list is full
            cm_spin_unlock(&list->lock);
            return GS_FALSE;
        }
    } while (!cm_atomic_cas(&list->end, end, end + 1)); // placeholder
    list->array[end % DTC_RCY_PARAL_BUF_LIST_SIZE] = val;
    while (!cm_atomic_cas(&list->writed_end, end, end + 1)) { // update end
        // yield
        continue;
    }
    cm_spin_unlock(&list->lock);
    return GS_TRUE;
}

static void dtc_rcy_free_list_in_analyze_paral(aligned_buf_t *list, uint32 num)
{
    for (uint32 i = 0; i < num; i++) {
        cm_aligned_free(&list[i]);
    }
}

static void dtc_rcy_analyze_paral_proc(thread_t *thread)
{
    knl_session_t *session = (knl_session_t *)thread->argument;
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    log_cursor_t cursor;
    log_group_t *group = NULL;
    log_batch_t *batch = NULL;
    status_t ret;
    uint32 idx;
    log_context_t *ctx = &session->kernel->redo_ctx;
    dtc_rcy_inc_rcy_set_ref_num();

    while (!g_analyze_paral_mgr.killed_flag) {
        idx = dtc_rcy_atomic_list_pop(&g_analyze_paral_mgr.used_list);
        if (idx == GS_INVALID_INT32) {
            if (g_analyze_paral_mgr.read_log_end_flag) {
                break;
            }
            cm_sleep(1);
            continue;
        }
        batch = (log_batch_t *)g_analyze_paral_mgr.buf_list[idx].aligned_buf;
        GS_LOG_DEBUG_INF("[DTC RCY] log batch with lsn=%llu, lfn=%llu, rst_id=%u, asn=%u, block_id=%u, idx=%u, start "
            "process for instance=%u", batch->lsn, (uint64)batch->head.point.lfn, batch->head.point.rst_id,
            batch->head.point.asn, batch->head.point.block_id, idx, dtc_rcy->curr_node);
        rcy_init_log_cursor(&cursor, batch);
        group = log_fetch_group(ctx, &cursor);
        while (group != NULL) {
            if (dtc_rcy_analyze_group(session, group) != GS_SUCCESS) {
                GS_LOG_RUN_ERR("[DTC RCY] failed to analyze redo log group, lsn=%llu, rmid=%u",
                    group->lsn, group->rmid);
                dtc_rcy->failed = GS_TRUE;
                break;
            }
            group = log_fetch_group(ctx, &cursor);
        }
        
        ret = dtc_rcy_atomic_list_push(&g_analyze_paral_mgr.free_list, idx);
        GS_LOG_DEBUG_INF("[DTC RCY] log batch with lsn=%llu, lfn=%llu, rst_id=%u, asn=%u, block_id=%u, idx=%u has been"
            " processed for instance=%u", batch->lsn, (uint64)batch->head.point.lfn, batch->head.point.rst_id,
            batch->head.point.asn, batch->head.point.block_id, idx, dtc_rcy->curr_node);
        knl_panic_log(ret == GS_TRUE, "[DTC RCY] paral redo log analyze, push used buffer=%u into free list error",
            idx);
    }
    cm_atomic32_dec(&g_analyze_paral_mgr.running_thread_num);
    dtc_rcy_dec_rcy_set_ref_num();
    GS_LOG_RUN_INF("[DTC RCY] dtc_rcy_analyze_paral_proc finish, rcy_set ref num=%u", dtc_rcy->rcy_set_ref_num);
}

void dtc_rcy_atomic_dec_group_num(uint32 idx, int32 val)
{
    status_t ret;
    if (cm_atomic32_add(&g_replay_paral_mgr.group_num[idx], -val) == 0) {
        ret = dtc_rcy_atomic_list_push(&g_replay_paral_mgr.free_list, idx);
        knl_panic_log(ret == GS_TRUE, "[DTC RCY] push into free list error");
    }
}

static void dtc_rcy_paral_replay_batch(knl_session_t *session, log_cursor_t *cursor, uint32 idx)
{
    knl_instance_t *kernel = session->kernel;
    rcy_context_t *rcy = &kernel->rcy_ctx;
    log_group_t *group = NULL;
    bool32 logic = GS_FALSE;
    rcy_paral_group_t *next_paral_group = NULL;
    log_context_t *ctx = &session->kernel->redo_ctx;
    uint32 group_slot = rcy->curr_group_id;
    knl_session_t *redo_ssesion = session->kernel->sessions[SESSION_ID_KERNEL];
    redo_ssesion->dtc_session_type = session->dtc_session_type;

    rcy->curr_group = (rcy_paral_group_t *)g_replay_paral_mgr.group_list[idx].aligned_buf;
    g_replay_paral_mgr.group_num[idx] = DTC_RCY_GROUP_NUM_BASE;
    for (;;) {
        group = log_fetch_group(ctx, cursor);
        if (group == NULL) {
            GS_LOG_DEBUG_INF("paral redo replay, fetch current log group is NULL");
            break;
        }

        if (dtc_rcy_set_pitr_end_replay(session->kernel->db.recover_for_restore, group->lsn)) {
            GS_LOG_RUN_INF("[DTC RCY] pcn is invalide, lsn=%llu, rmid=%u", group->lsn, group->rmid);
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
            rcy->curr_group->ddl_lsn_pitr = dtc_rcy_get_ddl_lsn_pitr();
            rcy_replay_logic_group(session, rcy->curr_group);
        } else {
            cm_atomic32_inc(&g_replay_paral_mgr.group_num[idx]);
            rcy->curr_group->group_list_idx = idx;
            rcy_add_replay_bucket(rcy->curr_group, rcy);
        }

        GS_LOG_DEBUG_INF("[DTC RCY] redo replay log group lsn=%llu, rmid=%u, kernel lsn=%llu, "
            "id=%u, group_tid=%u, inc_idx=%u, enter_cnt=%u",
            group->lsn, group->rmid, session->kernel->lsn, rcy->curr_group->id,
            rcy->curr_group->tx_id, rcy->curr_group->group_list_idx, rcy->curr_group->enter_count);

        dtc_update_lsn(session, group->lsn);
        GS_LOG_DEBUG_INF("[DTC RCY] updated kernel->session->lsn=%llu", session->kernel->lsn);
        rcy->curr_group = next_paral_group;
    }

    dtc_rcy_atomic_dec_group_num(idx, DTC_RCY_GROUP_NUM_BASE);
    GS_LOG_DEBUG_INF("[DTC RCY] finish paral redo replay of log batch=%u", idx);
    return;
}

static status_t dtc_rcy_analyze_batches_paral(knl_session_t *session)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_rcy_stat_t *stat = &dtc_rcy->rcy_stat;
    int64 lgwr_buf_size = (int64)LOG_LGWR_BUF_SIZE(session);
    rcy_context_t *rcy = &session->kernel->rcy_ctx;
    log_batch_t *batch = NULL;
    status_t status = GS_SUCCESS;
    errno_t ret;
    uint32 idx;
    g_analyze_paral_mgr.killed_flag         = GS_FALSE;
    g_analyze_paral_mgr.read_log_end_flag     = GS_FALSE;
    g_analyze_paral_mgr.running_thread_num  = 0;

    GS_LOG_RUN_INF("[DTC RCY] paral redo log analyze start, dtc_rcy->phase=%u, session->id=%u",
        dtc_rcy->phase, session->id);

    dtc_rcy_atomic_list_init(&g_analyze_paral_mgr.free_list);
    dtc_rcy_atomic_list_init(&g_analyze_paral_mgr.used_list);
    for (uint32 i = 0; i < DTC_RCY_PARAL_BUF_LIST_SIZE; i++) {
        g_analyze_paral_mgr.free_list.array[i] = i;

        if (cm_aligned_malloc(lgwr_buf_size, "dtc rcy read buffer", &g_analyze_paral_mgr.buf_list[i]) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[DTC RCY] failed to alloc log read buffer in paral analyze, buffer list id=%u, "
                "lgwr_buf_size=%llu", i, lgwr_buf_size);
            dtc_rcy_free_list_in_analyze_paral(g_analyze_paral_mgr.buf_list, i);
            return GS_ERROR;
        }
    }
    g_analyze_paral_mgr.free_list.end = DTC_RCY_PARAL_BUF_LIST_SIZE;
    g_analyze_paral_mgr.free_list.writed_end = DTC_RCY_PARAL_BUF_LIST_SIZE;

    SYNC_POINT_GLOBAL_START(CANTIAN_RECOVERY_ANAL_READ_LOG_FAIL, &status, GS_ERROR);
    status = dtc_read_all_logs(session);
    SYNC_POINT_GLOBAL_END;
    if (status != GS_SUCCESS) {
        dtc_rcy_free_list_in_analyze_paral(g_analyze_paral_mgr.buf_list, DTC_RCY_PARAL_BUF_LIST_SIZE);
        session->canceled = GS_TRUE;
        GS_LOG_RUN_ERR("[DTC RCY] failed to load first log file in paral analyze, dtc_rcy->failed=%u. "
            "session->canceled=%u", dtc_rcy->failed, session->canceled);
        return GS_ERROR;
    }

    if (dtc_rcy_fetch_log_batch(session, &batch) != GS_SUCCESS) {
        dtc_rcy_free_list_in_analyze_paral(g_analyze_paral_mgr.buf_list, DTC_RCY_PARAL_BUF_LIST_SIZE);
        GS_LOG_RUN_ERR("[DTC RCY] failed to extract first log batch in paral analyze, dtc_rcy->failed=%u. "
            "session->canceled=%u", dtc_rcy->failed, session->canceled);
        return GS_ERROR;
    }
    for (uint32 i = 0; i < PARAL_ANALYZE_THREAD_NUM; i++) {
        //cpu_set_t cpuset;
        //CPU_ZERO(&cpuset);
        //CPU_SET(i + 20, &cpuset); // start from 20

        status = cm_create_thread(dtc_rcy_analyze_paral_proc, 0, (void *)session, &g_analyze_paral_mgr.thread[i]);
        if (status == GS_SUCCESS) {
            //pthread_setaffinity_np(g_analyze_paral_mgr.thread[i].id, sizeof(cpu_set_t), &cpuset);
            g_analyze_paral_mgr.running_thread_num++;
        } else {
            GS_LOG_RUN_ERR("[DTC RCY] failed to create paral analyze thread=%u", i);
            batch = NULL;
            g_analyze_paral_mgr.killed_flag = GS_TRUE;
            break;
        }
    }
    while (batch != NULL) {
        if (session->canceled) {
            GS_LOG_RUN_ERR("[DTC RCY] rcy session is canceled, session->id=%u", session->id);
            GS_THROW_ERROR(ERR_OPERATION_CANCELED);
            status = GS_ERROR;
            g_analyze_paral_mgr.killed_flag = GS_TRUE;
            break;
        }
        if (session->killed) {
            GS_LOG_RUN_ERR("[DTC RCY] rcy session is canceled, session->id=%u", session->id);
            GS_THROW_ERROR(ERR_OPERATION_KILLED);
            status = GS_ERROR;
            g_analyze_paral_mgr.killed_flag = GS_TRUE;
            break;
        }
        // check whether need to cancel this task
        if (dtc_rcy->canceled) {
            GS_LOG_RUN_ERR("[DTC RCY] required to cancel this dtc recovery task");
            g_analyze_paral_mgr.killed_flag = GS_TRUE;
            break;
        }
        if (batch->scn > rcy->max_scn) {
            GS_LOG_RUN_INF("[DTC RCY] log batch->scn=%llu is larger than rcy->max_scn=%llu, recovery done", batch->scn,
                           rcy->max_scn);
            break;
        }
        idx = dtc_rcy_atomic_list_pop(&g_analyze_paral_mgr.free_list);
        if (idx == GS_INVALID_INT32) { // free list is empty
            continue;
        }

        ret = memcpy_sp(g_analyze_paral_mgr.buf_list[idx].aligned_buf, lgwr_buf_size, (char*)batch, batch->space_size);
        knl_securec_check(ret);
        knl_panic_log(dtc_rcy_atomic_list_push(&g_analyze_paral_mgr.used_list, idx),
                      "[DTC RCY] push buffer of idx %u from free list into used list error", idx);
        GS_LOG_DEBUG_INF("log batch [%llu/%llu/%u] push to idx=%u", batch->lsn, (uint64)batch->head.point.lfn,
            batch->head.point.block_id, idx);
        if (dtc_rcy_fetch_log_batch(session, &batch) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[DTC RCY] failed to extract log batch in paral analyze");
            status = GS_ERROR;
            g_analyze_paral_mgr.killed_flag = GS_TRUE;
            break;
        }
    }
    if (g_analyze_paral_mgr.killed_flag == GS_FALSE) {
        g_analyze_paral_mgr.read_log_end_flag = GS_TRUE;
    }
    while (cm_atomic32_get(&g_analyze_paral_mgr.running_thread_num) > 0) {
        cm_sleep(1);
    }
    dtc_rcy_free_list_in_analyze_paral(g_analyze_paral_mgr.buf_list, DTC_RCY_PARAL_BUF_LIST_SIZE);
    session->canceled = dtc_rcy->canceled ? GS_TRUE : GS_FALSE;

    GS_LOG_RUN_INF("[DTC RCY] paral redo log analyze finish, dtc_rcy->phase=%u, session->id=%u, "
        "need replay redo size total(M)=%llu", dtc_rcy->phase, session->id, stat->last_rcy_log_size / SIZE_M(1));
    GS_LOG_RUN_INF("[DTC RCY] dtc_rcy canceled=%u, session canceled=%u", dtc_rcy->canceled, session->canceled);
    return status;
}

static status_t dtc_rcy_replay_batches_paral(knl_session_t *session)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    int64 lgwr_buf_size = (int64)LOG_LGWR_BUF_SIZE(session);
    log_batch_t *batch = NULL;
    log_cursor_t cursor;
    status_t status = GS_SUCCESS;
    errno_t ret;
    rcy_context_t *rcy = &session->kernel->rcy_ctx;
    timeval_t elapsed_begin;
    uint32 idx;
    uint64 used_time;
    uint64 fetch_log_time = 0;

    GS_LOG_RUN_INF("[DTC RCY] start paral redo replay, dtc_rcy->phase=%u, session->kernel->lsn=%llu",
        dtc_rcy->phase, session->kernel->lsn);

    dtc_rcy_atomic_list_init(&g_replay_paral_mgr.free_list);
    for (uint32 i = 0; i < DTC_RCY_PARAL_BUF_LIST_SIZE; i++) {
        g_replay_paral_mgr.free_list.array[i] = i;

        if (cm_aligned_malloc(lgwr_buf_size, "dtc rcy read buffer", &g_replay_paral_mgr.buf_list[i]) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[DTC RCY] failed to alloc log read buffer in paral replay for buf_list id=%u", i);
            dtc_rcy_free_list_in_analyze_paral(g_replay_paral_mgr.buf_list, i);
            return GS_ERROR;
        }
    }

    for (uint32 i = 0; i < DTC_RCY_PARAL_BUF_LIST_SIZE; i++) {
        if (cm_aligned_malloc(lgwr_buf_size, "dtc rcy paral group buffer", &g_replay_paral_mgr.group_list[i]) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[DTC RCY] failed to alloc paral group buffer in paral replay for group=%u", i);
            dtc_rcy_free_list_in_analyze_paral(g_replay_paral_mgr.group_list, i);
            dtc_rcy_free_list_in_analyze_paral(g_replay_paral_mgr.buf_list, DTC_RCY_PARAL_BUF_LIST_SIZE);
            return GS_ERROR;
        }
    }
    g_replay_paral_mgr.free_list.end         = DTC_RCY_PARAL_BUF_LIST_SIZE;
    g_replay_paral_mgr.free_list.writed_end  = DTC_RCY_PARAL_BUF_LIST_SIZE;

    ELAPSED_BEGIN(elapsed_begin);
    SYNC_POINT_GLOBAL_START(CANTIAN_PARAL_REPLAY_READ_LOG_FAIL, &status, GS_ERROR);
    status = dtc_read_all_logs(session);
    SYNC_POINT_GLOBAL_END;
    if (status != GS_SUCCESS) {
        dtc_rcy_free_list_in_analyze_paral(g_replay_paral_mgr.buf_list, DTC_RCY_PARAL_BUF_LIST_SIZE);
        dtc_rcy_free_list_in_analyze_paral(g_replay_paral_mgr.group_list, DTC_RCY_PARAL_BUF_LIST_SIZE);
        GS_LOG_RUN_ERR("[DTC RCY] failed to read redo log files in paral replay");
        return GS_ERROR;
    }
    ELAPSED_END(elapsed_begin, used_time);
    GS_LOG_RUN_INF("[DTC RCY] read redo logs in paral replay used=%llu", used_time);

    ELAPSED_BEGIN(elapsed_begin);
    if (dtc_rcy_fetch_log_batch(session, &batch) != GS_SUCCESS) {
        dtc_rcy_free_list_in_analyze_paral(g_replay_paral_mgr.buf_list, DTC_RCY_PARAL_BUF_LIST_SIZE);
        dtc_rcy_free_list_in_analyze_paral(g_replay_paral_mgr.group_list, DTC_RCY_PARAL_BUF_LIST_SIZE);
        GS_LOG_RUN_ERR("[DTC RCY] failed to extract log batch in paral replay");
        return GS_ERROR;
    }
    ELAPSED_END(elapsed_begin, fetch_log_time);
    ELAPSED_BEGIN(rcy->paral_rcy_thread_start_work_time);
    while (batch != NULL) {
        if (session->canceled) {
            GS_LOG_RUN_ERR("[DTC RCY] session is canceled, session->id=%u", session->id);
            GS_THROW_ERROR(ERR_OPERATION_CANCELED);
            status = GS_ERROR;
            break;
        }

        if (session->killed) {
            GS_LOG_RUN_ERR("[DTC RCY] session is killed, session->id=%u", session->id);
            GS_THROW_ERROR(ERR_OPERATION_KILLED);
            status = GS_ERROR;
            break;
        }

        // check whether need to cancel this task
        if (dtc_rcy->canceled) {
            GS_LOG_RUN_ERR("[DTC RCY] required to cancel this dtc recovery task");
            break;
        }

        if (dtc_rcy_pitr_replay_end(rcy, batch)) {
            break;
        }

        if (dtc_rcy_full_recovery_replay_end(rcy, batch)) {
            break;
        }

        idx = dtc_rcy_atomic_list_pop(&g_replay_paral_mgr.free_list);
        if (idx == GS_INVALID_INT32) { // free list is empty
            cm_spin_sleep(); // 100ns
            continue;
        }

        ret = memcpy_sp(g_replay_paral_mgr.buf_list[idx].aligned_buf, lgwr_buf_size, (char*)batch, batch->space_size);
        knl_securec_check(ret);

        // call batch process function
        rcy_init_log_cursor(&cursor, (log_batch_t *)g_replay_paral_mgr.buf_list[idx].aligned_buf);
        dtc_rcy_paral_replay_batch(session, &cursor, idx);
        GS_LOG_DEBUG_INF("[DTC RCY] paral replay redo log batch lfn=%llu, lsn=%llu, point [%u-%u/%u] has been"
            " processed for instance=%u, session lsn=%llu", (uint64)batch->head.point.lfn, batch->lsn,
            batch->head.point.rst_id, batch->head.point.asn, batch->head.point.block_id, dtc_rcy->curr_node,
            session->kernel->lsn);
         
        // fetch next batch
        ELAPSED_BEGIN(elapsed_begin);

        if (dtc_rcy_check_is_end_restore_recovery()) {
            break;
        }
        if (dtc_rcy_fetch_log_batch(session, &batch) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[DTC RCY] failed to extract log batch in paral replay");
            status = GS_ERROR;
            break;
        }
        ELAPSED_END(elapsed_begin, used_time);
        fetch_log_time += used_time;
    }

    dtc_rcy_wait_paral_replay_end(session);
    dtc_rcy_free_list_in_analyze_paral(g_replay_paral_mgr.buf_list, DTC_RCY_PARAL_BUF_LIST_SIZE);
    dtc_rcy_free_list_in_analyze_paral(g_replay_paral_mgr.group_list, DTC_RCY_PARAL_BUF_LIST_SIZE);

    session->canceled = dtc_rcy->canceled ? GS_TRUE : GS_FALSE;
    GS_LOG_RUN_INF("[DTC RCY] dtc_rcy canceled=%u, session canceled=%u", dtc_rcy->canceled, session->canceled);

    GS_LOG_RUN_INF("[DTC RCY] finish paral redo replay, dtc_rcy->phase=%u, session->kernel->lsn=%llu, "
        "fetch redo log used time=%llu", dtc_rcy->phase, session->kernel->lsn, fetch_log_time);
    return status;
}

static inline void dtc_rcy_next_phase(knl_session_t *session)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_rcy->phase = PHASE_RECOVERY;
    dtc_rcy->curr_node_idx = GS_INVALID_ID8;
    dtc_rcy->curr_node = GS_INVALID_ID8;
    dtc_rcy->curr_blk_size = GS_INVALID_ID16;
    dtc_rcy->curr_batch_lsn = GS_INVALID_ID64;
    dtc_rcy->is_end_restore_recover = GS_FALSE;
    dtc_rcy->recovery_status = RECOVERY_REPLAY;

    for (uint32 i = 0; i < dtc_rcy->node_count; i++) {
        dtc_rcy->rcy_log_points[i].rcy_point = dtc_rcy->rcy_log_points[i].rcy_point_saved;
        dtc_rcy->rcy_nodes[i].recover_done = GS_FALSE;
        dtc_rcy->rcy_nodes[i].ulog_exist_data = GS_TRUE;
        dtc_rcy->rcy_nodes[i].read_pos = 0;
        dtc_rcy->rcy_nodes[i].write_pos = 0;
        if (cm_dbs_is_enable_dbs() && session->kernel->db.recover_for_restore) {
            dtc_rcy->rcy_log_points[i].rcy_point.asn = 0;
            dtc_rcy->rcy_log_points[i].rcy_point.block_id = GS_INFINITE32;
        }
    }
}

status_t dtc_rcy_full_recovery_replay(knl_session_t *session, dtc_rcy_stat_t *stat)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    timeval_t begin_time;
    ELAPSED_BEGIN(begin_time);
    if (dtc_rcy->paral_rcy) {
        if (dtc_rcy_replay_batches_paral(session) != GS_SUCCESS) {
            return GS_ERROR;
        }
    } else {
        if (dtc_rcy_process_batches(session) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }
    ELAPSED_END(begin_time, stat->last_rcy_replay_elapsed);
    return GS_SUCCESS;
}

static status_t dtc_rcy_full_recovery(knl_session_t *session)
{
    timeval_t begin_time;
    knl_session_t *se  = session->kernel->sessions[SESSION_ID_KERNEL];
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_rcy_stat_t *stat = &dtc_rcy->rcy_stat;
    stat->last_rcy_is_full_recovery = GS_TRUE;
    reform_detail_t *rf_detail = &g_rc_ctx->reform_detail;
    uint64 rcy_disk_read_time = se->stat->disk_read_time;
    uint64 rcy_disk_read = se->stat->disk_reads;
    
    if (dtc_rcy->phase == PHASE_ANALYSIS) {
        ELAPSED_BEGIN(begin_time);
        if (dtc_rcy_process_batches(session) != GS_SUCCESS) {
            return GS_ERROR;
        }
        dtc_rcy_next_phase(session);
        ELAPSED_END(begin_time, stat->last_rcy_analyze_elapsed);
        GS_LOG_RUN_INF("[DTC RCY] finish redo analyze, pcn is equal num=%u", dtc_rcy->pcn_is_equal_num);
    }

    RC_STEP_BEGIN(rf_detail->recovery_replay_elapsed);
    dtc_rcy->recovery_status = RECOVERY_REPLAY;
    if (dtc_rcy_full_recovery_replay(session, stat) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[DTC RCY] redo replay failed");
        RC_STEP_END(rf_detail->recovery_replay_elapsed, RC_STEP_FAILED);
        return GS_ERROR;
    }

    if (dtc_recover_check(session) != GS_SUCCESS) {
        RC_STEP_END(rf_detail->recovery_replay_elapsed, RC_STEP_FAILED);
        return GS_ERROR;
    }
    RC_STEP_END(rf_detail->recovery_replay_elapsed, RC_STEP_FINISH);

    GS_LOG_RUN_INF("[DTC RCY] finish redo replay, session lsn=%llu", ((knl_session_t *)g_rc_ctx->session)->kernel->lsn);
    if (rc_set_redo_replay_done(g_rc_ctx->session, &(g_rc_ctx->info)) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[DTC RCY] failed to broadcast reform status g_rc_ctx->status=%u", g_rc_ctx->status);
    }

    if (log_ddl_write_buffer(session) != GS_SUCCESS) {
        return GS_ERROR;
    }
    rcy_disk_read_time = se->stat->disk_read_time - rcy_disk_read_time;
    rcy_disk_read = se->stat->disk_reads - rcy_disk_read;

    GS_LOG_RUN_INF("[DTC RCY] kernel session read_page_num=%llu, total_time(us)=%llu, ave_time(us)=%llu", rcy_disk_read,
        rcy_disk_read_time, (rcy_disk_read == 0 ? 0 : rcy_disk_read_time / rcy_disk_read));
    GS_LOG_RUN_INF("[DTC RCY] last_rcy_replay_elapsed_time=%llu", stat->last_rcy_replay_elapsed);
    GS_LOG_RUN_INF("[DTC RCY] last_rcy_replay_log_size=%llu", stat->last_rcy_log_size);

    // wait for all dirty pages to be flushed to disk
    ckpt_trigger(session, GS_TRUE, CKPT_TRIGGER_FULL);

    return dtc_rcy_update_ckpt_log_point(session);
}

static status_t dtc_rcy_partial_recovery(knl_session_t *session)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_rcy_stat_t *stat = &dtc_rcy->rcy_stat;
    reform_detail_t *rf_detail = &g_dtc->rf_ctx.reform_detail;
    stat->last_rcy_is_full_recovery = GS_FALSE;
    knl_session_t *se  = session->kernel->sessions[SESSION_ID_KERNEL];

    dtc_rcy->recovery_status = RECOVERY_ANALYSIS;
    RC_STEP_BEGIN(rf_detail->recovery_set_create_elapsed);
    if (dtc_rcy_analyze_batches_paral(session) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[DTC RCY][partial recovery] failed to paral analyze redo logs, dtc_rcy->failed=%u, "
            "dtc_rcy->ss->canceled=%u", dtc_rcy->failed, dtc_rcy->ss->canceled);
        RC_STEP_END(rf_detail->recovery_set_create_elapsed, RC_STEP_FAILED);
        return GS_ERROR;
    }
    RC_STEP_END(rf_detail->recovery_set_create_elapsed, RC_STEP_FINISH);

    dtc_rcy_set_num_stat();

    // send recovery set to each alive node and wait for response
    RC_STEP_BEGIN(rf_detail->recovery_set_revise_elapsed);
    if (dtc_send_rcy_set(session) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[DTC RCY][partial recovery] failed to send rcy set to each master");
        RC_STEP_END(rf_detail->recovery_set_revise_elapsed, RC_STEP_FAILED);
        return GS_ERROR;
    }

    // wait for response from alive nodes
    while (dtc_rcy->phase != PHASE_HANDLE_RCYSET_DONE) {
        if (dtc_rcy_check_rcyset_msg(session) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("DTC RCY] failed to check rcyset msg");
            RC_STEP_END(rf_detail->recovery_set_revise_elapsed, RC_STEP_FAILED);
            return GS_ERROR;
        }
        cm_sleep(10);
        if (session->canceled) {
            GS_LOG_RUN_ERR("[DTC RCY] rcy session is cancled, session->id=%u", session->id);
            RC_STEP_END(rf_detail->recovery_set_revise_elapsed, RC_STEP_FAILED);
            GS_THROW_ERROR(ERR_OPERATION_CANCELED);
            return GS_ERROR;
        }

        if (session->killed) {
            GS_LOG_RUN_ERR("[DTC RCY] rcy session is cancled, session->id=%u", session->id);
            RC_STEP_END(rf_detail->recovery_set_revise_elapsed, RC_STEP_FAILED);
            GS_THROW_ERROR(ERR_OPERATION_KILLED);
            return GS_ERROR;
        }

        // check whether need to cancel this task
        if (dtc_rcy->canceled) {
            session->canceled = GS_TRUE;
            GS_LOG_RUN_ERR("[DTC RCY] required to cancel this dtc recovery task, session canceled=%u", session->canceled);
            RC_STEP_END(rf_detail->recovery_set_revise_elapsed, RC_STEP_FAILED);
            return GS_ERROR;
        }

        if (dtc_rcy->failed == GS_TRUE) {
            GS_LOG_RUN_ERR("[DTC RCY] check dtc_rcy->failed=%u", dtc_rcy->failed);
            RC_STEP_END(rf_detail->recovery_set_revise_elapsed, RC_STEP_FAILED);
            return GS_ERROR;
        }
    }
    RC_STEP_END(rf_detail->recovery_set_revise_elapsed, RC_STEP_FINISH);
    GS_LOG_RUN_INF("[DTC RCY][partial recovery] wait masters send rcy set results successfully, msg_sent=%u, "
        "msg_recv=%u, dtc_rcy->phase=%u", dtc_rcy->msg_sent, dtc_rcy->msg_recv, dtc_rcy->phase);

    // move partial recovery to next phase
    dtc_rcy_next_phase(session);

    uint64 rcy_disk_read_time = se->stat->disk_read_time;
    uint64 rcy_disk_read = se->stat->disk_reads;
    uint64 rcy_record_page = 0;
    rcy_set_t *rcy_set = &dtc_rcy->rcy_set;
    for (uint32 i = 0; i < rcy_set->bucket_num; i++) {
        rcy_record_page += rcy_set->buckets[i].count;
    }

    // start real recovery task using recovery set
    RC_STEP_BEGIN(rf_detail->recovery_replay_elapsed);
    if (dtc_rcy->paral_rcy) {
        if (dtc_rcy_replay_batches_paral(session) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[DTC RCY] failed to do redo log batch replay in parallel");
            RC_STEP_END(rf_detail->recovery_replay_elapsed, RC_STEP_FAILED);
            return GS_ERROR;
        }
    } else {
        if (dtc_rcy_process_batches(session) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[DTC RCY] failed to do redo log batch replay");
            RC_STEP_END(rf_detail->recovery_replay_elapsed, RC_STEP_FAILED);
            return GS_ERROR;
        }
    }
    RC_STEP_END(rf_detail->recovery_replay_elapsed, RC_STEP_FINISH);

    if (dtc_recover_check(session) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[DTC RCY][partial recovery] failed to check dtc recovery rcy point");
        return GS_ERROR;
    }

    GS_LOG_RUN_INF("[DTC RCY] finish redo replay, session lsn=%llu", ((knl_session_t *)g_rc_ctx->session)->kernel->lsn);

    if (rc_set_redo_replay_done(g_rc_ctx->session, &(g_rc_ctx->info)) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[DTC RCY] failed to broadcast reform status g_rc_ctx->status=%u", g_rc_ctx->status);
    }

    rcy_disk_read_time = se->stat->disk_read_time - rcy_disk_read_time;
    rcy_disk_read = se->stat->disk_reads - rcy_disk_read;

    GS_LOG_RUN_INF("[DTC RCY] kernel session read page num=%llu, total time(s)=%llu, ave_time(us)=%llu",
                   rcy_disk_read, rcy_disk_read_time / MICROSECS_PER_SECOND,
                   (rcy_disk_read == 0 ? 0 : rcy_disk_read_time / rcy_disk_read));
    GS_LOG_RUN_INF("[DTC RCY] recovery set create time(us)=%llu, recovery set revise time(s)=%llu. recovery replay "
                   "time(s)=%llu", (rf_detail->recovery_set_create_elapsed.cost_time) / MICROSECS_PER_SECOND_LL,
                   (rf_detail->recovery_set_revise_elapsed.cost_time) / MICROSECS_PER_SECOND_LL,
                   (rf_detail->recovery_replay_elapsed.cost_time) / MICROSECS_PER_SECOND_LL);
    GS_LOG_RUN_INF("[DTC RCY] recovery set record page=%llu, recovery redo log size(M)=%llu", rcy_record_page,
                   stat->last_rcy_log_size / SIZE_M(1));

    ckpt_trigger(session, GS_FALSE, CKPT_TRIGGER_INC);
    GS_LOG_RUN_INF("[DTC RCY][partial recovery] trigger inc ckpt");

    dtc_rcy_update_ckpt_prcy_info(session);

    return GS_SUCCESS;
}

status_t dtc_rcy_proc(knl_session_t *session)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    status_t status;
    if (dtc_rcy->full_recovery) {
        status = dtc_rcy_full_recovery(session);
    } else {
        status = dtc_rcy_partial_recovery(session);
    }

    GS_LOG_RUN_INF("[DTC RCY] dtc_rcy_proc, dtc_rcy->failed=%u, dtc_rcy->ss->canceled=%u, dtc_rcy->recovery_status=%u,"
        "memory usage in bytes=%lu", dtc_rcy->failed, dtc_rcy->ss->canceled, dtc_rcy->recovery_status,
        cm_print_memory_usage());
    dtc_rcy->failed = (bool32)(status == GS_ERROR);
    dtc_rcy->recovery_status = status == GS_ERROR ? dtc_rcy->recovery_status : RECOVERY_FINISH;
    dtc_rcy->ss->canceled = dtc_rcy->failed ? GS_TRUE : GS_FALSE;
    dtc_recovery_close(session);
    GS_LOG_RUN_INF("[DTC RCY] dtc_rcy_proc, dtc_rcy->failed=%u, dtc_rcy->ss->canceled=%u, dtc_rcy->recovery_status=%u,"
        "memory usage in bytes=%lu", dtc_rcy->failed, dtc_rcy->ss->canceled, dtc_rcy->recovery_status,
        cm_print_memory_usage());
    return status;
}

static void dtc_rcy_thread_proc(thread_t *thread)
{
    knl_session_t *session = (knl_session_t *)thread->argument;
    if (dtc_rcy_proc(session) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[DTC RCY] dtc_rcy_proc failed");
    }
}

dtc_rcy_phase_e dtc_rcy_get_recover_phase(knl_session_t *session, bool32 full_recovery)
{
    if (full_recovery) {
        if (session->kernel->db.recover_for_restore) {
            return PHASE_ANALYSIS;
        } else {
            return PHASE_RECOVERY;
        }
    } else {
        return PHASE_ANALYSIS;
    }
}

status_t dtc_rcy_init_context(knl_session_t *session, dtc_rcy_context_t *dtc_rcy, uint32 count, bool32 full_recovery)
{
    knl_panic(count <= GS_MAX_INSTANCES);
    dtc_rcy->curr_node_idx = GS_INVALID_ID8;
    dtc_rcy->curr_node = GS_INVALID_ID8;
    dtc_rcy->curr_blk_size = GS_INVALID_ID16;
    dtc_rcy->curr_batch_lsn = GS_INVALID_ID64;
    dtc_rcy->end_lsn_restore_recovery = GS_INVALID_ID64;
    dtc_rcy->full_recovery = full_recovery;
    dtc_rcy->phase = dtc_rcy_get_recover_phase(session, full_recovery);
    dtc_rcy->replay_thread_num = session->kernel->attr.log_replay_processes;
    dtc_rcy->canceled = GS_FALSE;
    dtc_rcy->failed = GS_FALSE;
    dtc_rcy->is_end_restore_recover = GS_FALSE;
    dtc_rcy->need_analysis_leave_page_cnt = 0;
    dtc_rcy->node_count = count;
    dtc_rcy->msg_sent = 0;
    dtc_rcy->msg_recv = 0;
    dtc_rcy->paral_rcy_size = 0;
    dtc_rcy->paral_rcy = (dtc_rcy->replay_thread_num > 1);
    dtc_rcy->rcy_set_ref_num = 0;
    dtc_rcy->pcn_is_equal_num = 0;
    dtc_rcy->rcy_nodes = (dtc_rcy_node_t *)malloc(count * sizeof(dtc_rcy_node_t));
    if (dtc_rcy->rcy_nodes == NULL) {
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, count * sizeof(dtc_rcy_node_t), "dtc recovery nodes");
        GS_LOG_RUN_ERR("[DTC RCY] failed to alloc memory for crashed nodes");
        // free memory in dtc_recovery_close
        return GS_ERROR;
    }
    errno_t ret = memset_sp(dtc_rcy->rcy_nodes, count * sizeof(dtc_rcy_node_t), 0, count * sizeof(dtc_rcy_node_t));
    knl_securec_check(ret);

    if (full_recovery) {
        session->dtc_session_type = dtc_rcy->paral_rcy ? DTC_FULL_RCY_PARAL : DTC_FULL_RCY;
    } else {
        session->dtc_session_type = dtc_rcy->paral_rcy ? DTC_PART_RCY_PARAL : DTC_PART_RCY;
    }

    return GS_SUCCESS;
}

void dtc_rcy_update_rcy_stat(knl_session_t *session, instance_list_t *recover_list, uint32 idx,
                             uint8 node_id, dtc_node_ctrl_t *node_ctrl)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_rcy_stat_t *rcy_stat = &dtc_rcy->rcy_stat;

    rcy_stat->rcy_log_points[idx].node_id = node_id;
    rcy_stat->rcy_log_points[idx].rcy_point = node_ctrl->rcy_point;
    rcy_stat->rcy_log_points[idx].lrp_point = node_ctrl->lrp_point;
    rcy_stat->rcy_log_points[idx].curr_read_rcy_point = node_ctrl->rcy_point;
    return;
}

status_t dtc_rcy_init_rcynode(knl_session_t *session, instance_list_t *recover_list, uint32 idx)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_node_ctrl_t *ctrl = NULL;
    dtc_rcy_node_t *rcy_node = NULL;
    reform_rcy_node_t *rcy_log_point = NULL;
    uint8 node_id = recover_list->inst_id_list[idx];

    if (dtc_read_node_ctrl(session, node_id) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[DTC RCY] failed to read ctrl page for crashed node=%u", node_id);
        return GS_ERROR;
    }
    bool32 is_dbstor = cm_dbs_is_enable_dbs();
    ctrl = dtc_get_ctrl(session, node_id);
    rcy_log_point = &dtc_rcy->rcy_log_points[idx];
    rcy_node = &dtc_rcy->rcy_nodes[idx];
    rcy_node->node_id = node_id;
    rcy_node->pitr_lfn = ctrl->lrp_point.lfn;
    rcy_node->ddl_lsn_pitr = GS_INVALID_ID64;
    rcy_node->arch_file.handle = GS_INVALID_HANDLE;
    rcy_node->ulog_exist_data = GS_TRUE;
    rcy_node->write_pos = 0;
    rcy_node->read_pos = 0;
    rcy_node->curr_file_length = 0;

    rcy_log_point->node_id = node_id;
    rcy_log_point->lsn = ctrl->lsn;
    rcy_log_point->rcy_point = ctrl->rcy_point;
    rcy_log_point->rcy_point_saved = ctrl->rcy_point;

    dtc_update_scn(session, ctrl->scn);
    dtc_update_lsn(session, ctrl->lsn);

    if (is_dbstor && session->kernel->db.recover_for_restore) {
        rcy_log_point->rcy_point.asn = 0;
        rcy_log_point->rcy_point.block_id = GS_INFINITE32;
    }

    int64 size = (int64)LOG_LGWR_BUF_SIZE(session);
    if (cm_aligned_malloc(size, "dtc rcy read buffer", &rcy_node->read_buf) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[DTC RCY] failed to alloc log read buffer for crashed node=%u", node_id);
        // free memory in dtc_recovery_close
        return GS_ERROR;
    }

    errno_t ret = memset_sp(rcy_node->handle, sizeof(rcy_node->handle), GS_INVALID_HANDLE, sizeof(rcy_node->handle));
    knl_securec_check(ret);

    dtc_rcy_update_rcy_stat(session, recover_list, idx, node_id, ctrl);
    GS_LOG_RUN_INF("[DTC RCY] Recover instance=%u from point [%u-%u/%u/%llu/%llu/%llu][%u/%u/%llu/%llu]", node_id,
        ctrl->rcy_point.rst_id, ctrl->rcy_point.asn, ctrl->rcy_point.block_id, (uint64)ctrl->rcy_point.lfn,
        ctrl->rcy_point.lsn, ctrl->lsn, ctrl->lrp_point.asn, ctrl->lrp_point.block_id, (uint64)ctrl->lrp_point.lfn,
        ctrl->lrp_point.lsn);
    return GS_SUCCESS;
}

status_t dtc_rcy_init_rcyset(rcy_set_t *rcy_set)
{
    rcy_set->bucket_num = GS_RCY_SET_BUCKET;
    rcy_set->capacity = GS_RCY_SET_BUCKET * RCY_SET_BUCKET_TIMES;

    uint64 bucket_size = sizeof(rcy_set_bucket_t) * rcy_set->bucket_num;
    // free in dtc_rcy_close
    rcy_set->buckets = (rcy_set_bucket_t *)malloc(bucket_size);
    if (rcy_set->buckets == NULL) {
        GS_LOG_RUN_ERR("[DTC RCY] failed to alloc dtc recovery rcyset bucket");
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, bucket_size, "dtc recovery set bucket");
        return GS_ERROR;
    }
    errno_t ret = memset_sp(rcy_set->buckets, bucket_size, 0, bucket_size);
    knl_securec_check(ret);

    // free in dtc_rcy_close
    rcy_set->item_pools = dtc_rcy_alloc_itempool(rcy_set);
    if (rcy_set->item_pools == NULL) {
        CM_FREE_PTR(rcy_set->buckets);
        GS_LOG_RUN_ERR("[DTC RCY] failed to alloc dtc recovery rcyset itmepool");
        return GS_ERROR;
    }
    rcy_set->curr_item_pools = rcy_set->item_pools;
    return GS_SUCCESS;
}

status_t dtc_rcy_init_replay_proc(knl_session_t *session, dtc_rcy_context_t *dtc_rcy)
{
    rcy_context_t *rcy = &session->kernel->rcy_ctx;

    if (!dtc_rcy->paral_rcy) {
        GS_LOG_RUN_INF("[DTC RCY] use single thread to replay.");
        return GS_SUCCESS;
    }

    if (rcy_init_context(session) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[DTC RCY] failed to init rcy context");
        return GS_ERROR;
    }

    rcy_init_proc(session);

    rcy->curr_group = rcy->group_list;
    if (rcy->paral_rcy == GS_FALSE) {
        GS_LOG_RUN_ERR("[DTC RCY] failed to create paral replay thread");
        return GS_ERROR;
    } else {
        GS_LOG_RUN_INF("[DTC RCY] expected number of created threads=%u, actual number of created threads=%u",
            dtc_rcy->replay_thread_num, rcy->capacity);
        dtc_rcy->replay_thread_num = rcy->capacity;
        return GS_SUCCESS;
    }
}

status_t dtc_recovery_init(knl_session_t *session, instance_list_t *recover_list, bool32 full_recovery)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    uint32 count = recover_list->inst_id_count;

    dtc_rcy_init_last_recovery_stat(recover_list);
    cm_reset_error();
    if (dtc_rcy_init_context(session, dtc_rcy, count, full_recovery) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[DTC RCY] failed to init dtc recovery context");
        return GS_ERROR;
    }

    if (dtc_rcy_init_replay_proc(session, dtc_rcy) != GS_SUCCESS) {
        CM_FREE_PTR(dtc_rcy->rcy_nodes);  // free memory malloced in dtc_rcy_init_context
        GS_LOG_RUN_ERR("[DTC RCY] failed to init dtc recovery replay proc");
        return GS_ERROR;
    }

    for (uint32 i = 0; i < count; i++) {
        if (dtc_rcy_init_rcynode(session, recover_list, i) != GS_SUCCESS) {
            // release memory malloced in dtc_rcy_init_rcynode
            for (uint32 j = 0; j < i; j++) {
                if (&dtc_rcy->rcy_nodes[j].read_buf != NULL) {
                    cm_aligned_free(&dtc_rcy->rcy_nodes[j].read_buf);
                }
            }
            CM_FREE_PTR(dtc_rcy->rcy_nodes);  // free memory malloced in dtc_rcy_init_context
            // free memory and session malloced in dtc_rcy_init_replay_proc
            if (dtc_rcy->paral_rcy) {
                rcy_close_proc(session);
                rcy_free_buffer(&session->kernel->rcy_ctx);
            }

            GS_LOG_RUN_ERR("[DTC RCY] failed to init rcynode");
            return GS_ERROR;
        }
    }

    // init the recovery set
    if (dtc_rcy_init_rcyset(&dtc_rcy->rcy_set) != GS_SUCCESS) {
        // release memory malloced in dtc_rcy_init_rcynode
        for (uint32 i = 0; i < count; i++) {
            if (&dtc_rcy->rcy_nodes[i].read_buf != NULL) {
                cm_aligned_free(&dtc_rcy->rcy_nodes[i].read_buf);
            }
        }
        CM_FREE_PTR(dtc_rcy->rcy_nodes);  // free memory malloced in dtc_rcy_init_context
        // free memory and session malloced in dtc_rcy_init_replay_proc
        if (dtc_rcy->paral_rcy) {
            rcy_close_proc(session);
            rcy_free_buffer(&session->kernel->rcy_ctx);
        }

        GS_LOG_RUN_ERR("[DTC RCY] failed to init recovery set");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

void dtc_recovery_from_double_write_area(knl_session_t *session, reform_info_t *reform_info)
{
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;
    if (ctx->double_write != GS_TRUE) {
        GS_LOG_RUN_INF("Double write is disabled(%u), do NOT recovery from double write area.", ctx->double_write);
        return;
    }
    ckpt_disable(session);
    for (uint32 i = 0; i < reform_info->reform_list[REFORM_LIST_ABORT].inst_id_count; i++) {
        ckpt_recover_partial_write_node(session, reform_info->reform_list[REFORM_LIST_ABORT].inst_id_list[i]);
    }
    ctx->dw_ckpt_start = dtc_my_ctrl(session)->dw_start;
    ctx->dw_ckpt_end = dtc_my_ctrl(session)->dw_end;
    ckpt_enable(session);
}

status_t dtc_recover_crashed_nodes(knl_session_t *session, instance_list_t *recover_list, bool32 full_recovery)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_rcy->ss = session;
    dtc_rcy->recovery_status = RECOVERY_INIT;
    if (!full_recovery) {
        if (g_knl_callback.alloc_knl_session(GS_TRUE, (knl_handle_t *)&dtc_rcy->ss) != GS_SUCCESS) {
            dtc_rcy->in_progress = GS_FALSE;
            dtc_rcy->failed = GS_TRUE;
            GS_LOG_RUN_ERR("[DTC RCY] failed to alloc knernel session for partial recovery, "
                "dtc_rcy->recovery_status=%u, dtc_rcy->failed=%u, dtc_rcy->in_progress=%u",
                dtc_rcy->recovery_status, dtc_rcy->failed, dtc_rcy->in_progress);
            return GS_ERROR;
        }
    }

    status_t status = GS_SUCCESS;
    SYNC_POINT_GLOBAL_START(CANTIAN_RECOVERY_INIT_FAIL, &status, GS_ERROR);
    status = dtc_recovery_init(dtc_rcy->ss, recover_list, full_recovery);
    SYNC_POINT_GLOBAL_END;
    if (status != GS_SUCCESS) {
        dtc_rcy->in_progress = GS_FALSE;
        dtc_rcy->failed = GS_TRUE;
        dtc_rcy->ss->dtc_session_type = DTC_TYPE_NONE;
        GS_LOG_RUN_ERR("[DTC RCY] failed to init dtc recovery. dtc_rcy->recovery_status=%u, dtc_rcy->failed=%u, "
            "dtc_rcy->in_progress=%u", dtc_rcy->recovery_status, dtc_rcy->failed, dtc_rcy->in_progress);
        return GS_ERROR;
    }

    if (dtc_rcy->canceled) {
        dtc_recovery_close(session);
        dtc_rcy->failed = GS_TRUE;
        GS_LOG_RUN_INF("[DTC RCY] dtc_rcy canceled=%u, dtc_rcy->recovery_status=%u, dtc_rcy->failed=%u, "
            "dtc_rcy->in_progress=%u", dtc_rcy->canceled, dtc_rcy->recovery_status, dtc_rcy->failed,
            dtc_rcy->in_progress);
    }

    // recovery from doublewrite
    dtc_recovery_from_double_write_area(g_rc_ctx->session, &g_rc_ctx->info);

    if (dtc_rcy->canceled) {
        dtc_recovery_close(session);
        dtc_rcy->failed = GS_TRUE;
        GS_LOG_RUN_INF("[DTC RCY] dtc_rcy canceled=%u, dtc_rcy->recovery_status=%u, dtc_rcy->failed=%u, "
            "dtc_rcy->in_progress=%u", dtc_rcy->canceled, dtc_rcy->recovery_status, dtc_rcy->failed,
            dtc_rcy->in_progress);
    }

    if (full_recovery) {
        // No need to start thread to execute the recovery task.
        status = dtc_rcy_proc(dtc_rcy->ss);
        if (status != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[DTC RCY] failed to do full recovery");
        }
    } else {
        GS_LOG_RUN_INF("[DTC RCY][partial recovery] start paral redo replay, session->kernel->lsn=%llu",
            session->kernel->lsn);
        status = cm_create_thread(dtc_rcy_thread_proc, 0, dtc_rcy->ss, &DTC_RCY_CONTEXT->thread);
        if (status != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[DTC RCY][partial recovery], failed to create rcy_thread_proc");
            dtc_rcy->failed = GS_TRUE;
            dtc_recovery_close(session);
        }
    }

    return status;
}

status_t dtc_start_recovery(knl_session_t *session, instance_list_t *recover_list, bool32 full_recovery)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    cm_spin_lock(&dtc_rcy->lock, NULL);
    if (dtc_rcy->in_progress) {
        GS_LOG_RUN_ERR("[DTC RCY] failed to start recovery task because another one is already in progress");
        cm_spin_unlock(&dtc_rcy->lock);
        return GS_ERROR;
    }
    dtc_rcy->in_progress = GS_TRUE;
    cm_spin_unlock(&dtc_rcy->lock);

    return dtc_recover_crashed_nodes(session, recover_list, full_recovery);
}

bool32 dtc_recovery_in_progress(void)
{
    if (DTC_RCY_CONTEXT->failed) {
        return GS_FALSE;
    }
    return DTC_RCY_CONTEXT->in_progress;
}

bool32 dtc_recovery_need_stop(void)
{
    if (DTC_RCY_CONTEXT->failed || DTC_RCY_CONTEXT->in_progress) {
        return GS_TRUE;
    }
    return GS_FALSE;
}

bool32 dtc_recovery_failed(void)
{
    return DTC_RCY_CONTEXT->failed;
}

void dtc_stop_recovery(void)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    GS_LOG_RUN_INF("[DTC RCY] last recovery status=%u, dtc_rcy->failed=%u, dtc_rcy->in_progress=%u, "
        "dtc_rcy->canceled=%u, dtc_rcy->ss->canceled=%u, dtc_rcy->ss->killed=%u", dtc_rcy->recovery_status,
        dtc_rcy->failed, dtc_rcy->in_progress, dtc_rcy->canceled, dtc_rcy->ss->canceled, dtc_rcy->ss->killed);

    if (dtc_rcy->failed) {
        CM_ABORT(0, "[DTC RCY] DTC RCY failed");
    }
    
    dtc_rcy->canceled = GS_TRUE;
    GS_LOG_RUN_INF("[DTC RCY] stop current running thread, dtc_rcy->in_progress %u", dtc_rcy->in_progress);
    while (dtc_recovery_in_progress()) {
        cm_sleep(DTC_RCY_WAIT_STOP_SLEEP_TIME);
        if (dtc_rcy->ss->canceled || dtc_rcy->ss->killed) {
            if (rc_is_master() && !dtc_rcy->full_recovery) {
                g_knl_callback.release_knl_session(dtc_rcy->ss);  // release partial recovery alloc session
            }
            return;
        }
    }
}

status_t dtc_recover(knl_session_t *session)
{
    dtc_node_ctrl_t *curr_ctrl = dtc_my_ctrl(session);
    log_point_t curr_point = curr_ctrl->rcy_point;
    log_point_t lrp_point = curr_ctrl->lrp_point;
    log_context_t *log = &session->kernel->redo_ctx;
    reform_detail_t *rf_detail = &g_rc_ctx->reform_detail;
    status_t status = GS_SUCCESS;

    log_reset_point(session, &lrp_point);
    ckpt_set_trunc_point(session, &curr_point);
    session->kernel->redo_ctx.lfn = curr_point.lfn;
    session->kernel->ckpt_ctx.trunc_lsn = (uint64)session->kernel->lsn;

    if (rc_is_master() == GS_TRUE) {
        // only master node is allowed to execute dtc recovery
        g_rc_ctx->status = REFORM_RECOVERING;
        instance_list_t *rcy_list = (instance_list_t *)cm_push(session->stack, sizeof(instance_list_t));
        rcy_list->inst_id_count = session->kernel->db.ctrl.core.node_count;
        for (uint8 i = 0; i < rcy_list->inst_id_count; i++) {
            rcy_list->inst_id_list[i] = i;
        }
        RC_STEP_BEGIN(rf_detail->recovery_elapsed);
        status = dtc_start_recovery(session, rcy_list, GS_TRUE);
        RC_STEP_END(rf_detail->recovery_elapsed, RC_STEP_FINISH);
    }

    /* update current trunc point and current point */
    log_reset_point(session, &curr_ctrl->rcy_point);
    ckpt_set_trunc_point(session, &curr_ctrl->rcy_point);
    log_reset_file(session, &curr_ctrl->rcy_point);

    //    DB_SET_LSN(session->kernel->db.ctrl.core.lsn, curr_ctrl->lsn);
    DB_SET_LFN(&log->lfn, curr_ctrl->rcy_point.lfn);

    // set next generate lfn equal to the previous lfn plus 1
    log->buf_lfn[0] = log->lfn + 1;
    log->buf_lfn[1] = log->lfn + 2;

    if (rc_is_master() == GS_TRUE) {
        cm_pop(session->stack);
    }

    return status;
}

status_t dtc_add_dirtypage_for_recovery(knl_session_t *session, page_id_t page_id)
{
    /* if a shared copy is chosen as owner during recovery, it has to be marked dirty and be flushed to disk,
       otherwise the shared copy page can't be recovered in below scenario:
        1) the shared copy page is removed from recovery set
        2) after recovery the redo log of crashed node is truncated
        3) later the partial recovery node crash afterwards.
    */
    buf_bucket_t *bucket = buf_find_bucket(session, page_id);
    cm_spin_lock(&bucket->lock, &session->stat->spin_stat.stat_bucket);
    buf_ctrl_t *ctrl = buf_find_from_bucket(bucket, page_id);
    if (!ctrl || ctrl->lock_mode == DRC_LOCK_NULL) {
        /* If the page is not in memory or lock mode is null, the partial recovery for that page can't be skipped,
           as the page on disk may be not the latest one. */
        cm_spin_unlock(&bucket->lock);
        GS_LOG_RUN_WAR("[DTC RCY] can't skip enter page [%u-%u] due to it's not in memory or not usable",
                       page_id.file, page_id.page);
        return GS_ERROR;
    }

    if (!ctrl->is_dirty) {
        ctrl->is_dirty = GS_TRUE;
        ckpt_enque_one_page(session, ctrl);
    }
    cm_spin_unlock(&bucket->lock);
    return GS_SUCCESS;
}
