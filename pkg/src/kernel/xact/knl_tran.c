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
 * knl_tran.c
 *
 *
 * IDENTIFICATION
 * src/kernel/xact/knl_tran.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_xact_module.h"
#include "knl_tran.h"
#include "knl_lob.h"
#include "rcr_btree.h"
#include "pcr_btree.h"
#include "knl_context.h"
#include "temp_btree.h"
#include "pcr_heap.h"
#include "pcr_heap_undo.h"
#include "knl_table.h"
#include "knl_xa.h"
#include "index_common.h"
#include "dtc_dls.h"
#include "dtc_tran.h"
#include "dtc_dc.h"
#include "dtc_drc.h"
#include "dtc_context.h"
#include "cantian_fdsa.h"

pcr_itl_t g_init_pcr_itl = { .scn = 0, .xid.value = 0, .undo_page.value = 0, .undo_slot = 0, .flags = 0 };

static inline void tx_reset_rm(knl_rm_t *rm)
{
    lock_reset(rm);
    lob_items_reset(rm);
    rm->tx_id.value = CT_INVALID_ID64;
    rm->txn = NULL;
    rm->xid.value = CT_INVALID_ID64;
    rm->svpt_count = 0;
    rm->ssn = 0;
    rm->begin_lsn = CT_INVALID_ID64;
    rm->temp_has_undo = CT_FALSE;
    rm->noredo_undo_pages.count = 0;
    rm->noredo_undo_pages.first = INVALID_UNDO_PAGID;
    rm->noredo_undo_pages.last = INVALID_UNDO_PAGID;
}

void knl_tx_reset_rm(void *rm)
{
    tx_reset_rm((knl_rm_t *)rm);
}

status_t tx_area_init_impl(knl_session_t *session, undo_set_t *undo_set, uint32 lseg_no, uint32 rseg_no,
                           bool32 is_extend)
{
    undo_context_t *ctx = &session->kernel->undo_ctx;
    undo_t *undo = NULL;
    tx_item_t *item = NULL;
    uint32 txn_no, page_no, seg_no;
    uint32 id;

    if (is_extend && ctx->extend_cnt == 0) {
        ctx->extend_segno = lseg_no;
        knl_panic(session->kernel->id == undo_set->inst_id);
    }

    /* init each undo segment transaction area info */
    for (seg_no = lseg_no; seg_no < rseg_no; seg_no++) {
        undo = &undo_set->undos[seg_no];
        undo->lock = 0;
        undo->ow_scn = DB_CURR_SCN(session);
        undo->capacity = UNDO_DEF_TXN_PAGE(session) * TXN_PER_PAGE(session);
        if (is_extend) {
            uint64 buf_size = knl_txn_buffer_size(session->kernel->attr.page_size, 1);
            undo->items = (tx_item_t *)malloc((size_t)buf_size);
            if (undo->items == NULL) {
                CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)buf_size, "extend undo segments");
                return CT_ERROR;
            }
            ctx->extend_cnt++;
        } else {
            undo->items = (tx_item_t *)(undo_set->tx_buf + seg_no * undo->capacity * sizeof(tx_item_t));
        }
        
        undo->free_items.count = 0;
        undo->free_items.first = CT_INVALID_ID32;
        undo->free_items.last = CT_INVALID_ID32;

        id = 0;
        for (txn_no = 0; txn_no < TXN_PER_PAGE(session); txn_no++) {
            for (page_no = 0; page_no < UNDO_DEF_TXN_PAGE(session); page_no++) {
                item = &undo->items[id];
                item->xmap.seg_id = seg_no + CT_MAX_UNDO_SEGMENT * undo_set->inst_id;
                item->xmap.slot = (uint16)(page_no * TXN_PER_PAGE(session) + txn_no);
                item->lock = 0;
                item->prev = CT_INVALID_ID32;
                item->next = CT_INVALID_ID32;
                item->rmid = CT_INVALID_ID16;
                item->in_progress = CT_FALSE;
                item->systime = KNL_NOW(session);
                id++;
            }
        }
    }

    return CT_SUCCESS;
}

status_t tx_area_init(knl_session_t *session, uint32 lseg_no, uint32 rseg_no)
{
    tx_area_t *area = &session->kernel->tran_ctx;
    undo_set_t *undo_set = MY_UNDO_SET(session);
    undo_context_t *undo_ctx = &session->kernel->undo_ctx;

    /* global area info */
    area->scn_lock = 0;
    area->seri_lock = 0;
    area->rollback_num = 0;
    undo_set->active_workers = 0;

    undo_set->tx_buf = session->kernel->attr.tran_buf;

    undo_set->assign_workers = session->kernel->attr.tx_rollback_proc_num;
    /* the real worker is allocated in tx_rollback_start, no need to allocate here. */
    undo_ctx->active_workers = 0;

    return tx_area_init_impl(session, undo_set, lseg_no, rseg_no, CT_FALSE);
}

void tx_extend_deinit(knl_session_t *session)
{
    undo_context_t *ctx = &session->kernel->undo_ctx;
    undo_t *undo = NULL;

    for (uint32 i = ctx->extend_segno; i < ctx->extend_segno + ctx->extend_cnt; i++) {
        undo = &ctx->undos[i];
        CM_FREE_PTR(undo->items);
    }
}

static inline tx_id_t xmap_get_txid(knl_session_t *session, xmap_t xmap)
{
    tx_id_t tx_id;
    tx_id.seg_id = XMAP_SEG_ID(xmap);
    tx_id.item_id = xmap.slot % TXN_PER_PAGE(session) * UNDO_DEF_TXN_PAGE(session) + xmap.slot / TXN_PER_PAGE(session);
    return tx_id;
}

tx_id_t tx_xmap_get_txid(knl_session_t *session, xmap_t xmap)
{
    return xmap_get_txid(session, xmap);
}

static inline tx_item_t *xmap_get_item(knl_session_t *session, xmap_t xmap)
{
    tx_id_t tx_id = xmap_get_txid(session, xmap);
    undo_set_t *undo_set = UNDO_SET(session, XMAP_INST_ID(xmap));
    undo_t *undo = &undo_set->undos[tx_id.seg_id];
    return &undo->items[tx_id.item_id];
}

uint8 xid_get_inst_id(knl_session_t *session, xid_t xid)
{
    uint8 inst_id = XID_INST_ID(xid);
    if (inst_id == session->kernel->id) {
        return inst_id;
    }

    return drc_get_deposit_id(inst_id);
}

uint8 xmap_get_inst_id(knl_session_t *session, xmap_t xmap)
{
    uint8 inst_id = XMAP_INST_ID(xmap);
    if (inst_id == session->kernel->id) {
        return inst_id;
    }

    return drc_get_deposit_id(inst_id);
}

static inline void tx_bind_segid(knl_session_t *session, knl_rm_t *rm, uint64 global_segid)
{
    uint32 active_undo_segments = UNDO_ACTIVE_SEGMENT_COUNT(session);
    uint32 auton_trans_segments = UNDO_AUTON_TRANS_SEGMENT_COUNT(session);
    if (!UNDO_IS_AUTON_BIND_OWN(session) || active_undo_segments <= auton_trans_segments) {
        rm->undo_segid = (uint32)(global_segid % active_undo_segments);
    } else {
        rm->undo_segid = (uint32)(global_segid % (active_undo_segments - auton_trans_segments) + auton_trans_segments);
    }

    rm->tx_id.seg_id = (uint32)(global_segid % (UNDO_SEGMENT_COUNT(session) - auton_trans_segments) +
                                auton_trans_segments);
}

static inline void tx_bind_auton_segid(knl_session_t *session, knl_rm_t *rm, uint64 global_segid)
{
    uint32 active_undo_segments = UNDO_ACTIVE_SEGMENT_COUNT(session);
    uint32 auton_trans_segments = UNDO_AUTON_TRANS_SEGMENT_COUNT(session);
    if (!UNDO_IS_AUTON_BIND_OWN(session) || active_undo_segments <= auton_trans_segments) {
        rm->undo_segid = (uint32)(global_segid % active_undo_segments);
    } else {
        rm->undo_segid = (uint32)(global_segid % auton_trans_segments);
    }

    rm->tx_id.seg_id = (uint32)(global_segid % auton_trans_segments);
}

static inline undo_t *tx_bind_undo(knl_session_t *session, knl_rm_t *rm)
{
    undo_context_t *ctx = &session->kernel->undo_ctx;
    uint64 global_segid;

    rm->undo_page_info.undo_rid = g_invalid_undo_rowid;
    rm->undo_page_info.undo_fs = 0;
    rm->undo_page_info.encrypt_enable = CT_FALSE;
    rm->undo_page_info.undo_log_encrypt = CT_FALSE;

    rm->noredo_undo_page_info.undo_rid = g_invalid_undo_rowid;
    rm->noredo_undo_page_info.undo_fs = 0;
    rm->noredo_undo_page_info.encrypt_enable = CT_FALSE;
    rm->noredo_undo_page_info.undo_log_encrypt = CT_FALSE;

    global_segid = (uint64)cm_atomic_inc(&session->kernel->undo_segid);

    if (rm->prev == CT_INVALID_ID16) {
        tx_bind_segid(session, rm, global_segid);
    } else {
        tx_bind_auton_segid(session, rm, global_segid);
    }

    return &ctx->undos[rm->tx_id.seg_id];
}

static status_t txn_alloc(knl_session_t *session, knl_rm_t *rm)
{
    undo_t *undo = tx_bind_undo(session, rm);

    cm_spin_lock(&undo->lock, &session->stat->spin_stat.stat_txn_list);
    if (undo->free_items.count == 0) {
        cm_spin_unlock(&undo->lock);
        CT_THROW_ERROR(ERR_TOO_MANY_PENDING_TRANS);
        return CT_ERROR;
    }

    rm->tx_id.item_id = undo->free_items.first;
    undo->stat.txn_cnts++;
    undo->free_items.count--;
    if (undo->free_items.count == 0) {
        undo->free_items.first = CT_INVALID_ID32;
        undo->free_items.last = CT_INVALID_ID32;
    } else {
        undo->free_items.first = undo->items[rm->tx_id.item_id].next;
        knl_panic(undo->free_items.first != CT_INVALID_ID32);
        undo->items[undo->free_items.first].prev = CT_INVALID_ID32;
    }
    cm_spin_unlock(&undo->lock);

    return CT_SUCCESS;
}

static void txn_release(knl_session_t *session, undo_set_t *undo_set, tx_id_t tx_id)
{
    CM_ASSERT(tx_id.seg_id < CT_MAX_UNDO_SEGMENT);
    undo_t *undo = &undo_set->undos[tx_id.seg_id];

    if (tx_id.item_id >= undo->capacity) {
        return;
    }

    /* release temp table hold_rmid */
    knl_temp_cache_t *temp_table_ptr = NULL;
    for (uint32 i = 0; i < session->temp_table_count; i++) {
        temp_table_ptr = &session->temp_table_cache[i];
        if (temp_table_ptr->hold_rmid == session->rmid) {
            temp_table_ptr->hold_rmid = CT_INVALID_ID32;
        }
    }
    
    cm_spin_lock(&undo->lock, &session->stat->spin_stat.stat_txn_list);
    if (undo->free_items.count == 0) {
        undo->free_items.count = 1;
        undo->free_items.first = tx_id.item_id;
        undo->free_items.last = tx_id.item_id;
        undo->items[tx_id.item_id].prev = CT_INVALID_ID32;
    } else {
        undo->items[undo->free_items.last].next = tx_id.item_id;
        undo->items[tx_id.item_id].prev = undo->free_items.last;
        undo->free_items.last = tx_id.item_id;
        undo->free_items.count++;
    }
    undo->items[tx_id.item_id].next = CT_INVALID_ID32;
    cm_spin_unlock(&undo->lock);
}

void tx_area_release_impl(knl_session_t *session, uint32 lseg_no, uint32 rseg_no)
{
    undo_context_t *ctx = &session->kernel->undo_ctx;
    tx_item_t *item = NULL;
    undo_t *undo = NULL;
    txn_t *txn = NULL;
    uint32 i, seg_no;
    tx_id_t tx_id;
    undo_set_t *undo_set = MY_UNDO_SET(session);

    for (seg_no = lseg_no; seg_no < rseg_no; seg_no++) {
        undo = &ctx->undos[seg_no];

        for (i = 0; i < undo->capacity; i++) {
            item = &undo->items[i];
            txn = txn_addr(session, item->xmap);
            if (txn->status == (uint8)XACT_END) {
                tx_id.seg_id = XMAP_SEG_ID(item->xmap);
                tx_id.item_id = i;
                txn_release(session, undo_set, tx_id);
            }
        }
    }
}

void tx_area_release(knl_session_t *session, undo_set_t *undo_set)
{
    undo_context_t *ctx = &session->kernel->undo_ctx;
    core_ctrl_t *core_ctrl = DB_CORE_CTRL(session);
    uint32 rcy_rm_id = 0;
    bool32 need_rcy = CT_FALSE;
    undo_t *undo = NULL;
    tx_item_t *item = NULL;
    txn_t *txn = NULL;
    uint32 i, seg_no;
    tx_id_t tx_id;

    for (seg_no = 0; seg_no < core_ctrl->undo_segments; seg_no++) {
        undo = &undo_set->undos[seg_no];

        for (i = 0; i < undo->capacity; i++) {
            item = &undo->items[i];
            txn = txn_addr(session, item->xmap);
            if (txn->status == (uint8)XACT_END) {
                tx_id.seg_id = XMAP_SEG_ID(item->xmap);
                tx_id.item_id = i;
                txn_release(session, undo_set, tx_id);
            } else {
                item->rmid = undo_set->rb_ctx[rcy_rm_id % undo_set->assign_workers].session->rmid;
                rcy_rm_id++;
                need_rcy = CT_TRUE;
            }
        }
    }

    CT_LOG_RUN_INF("[tx_area_release] undo_set->active_workers=%lld, undo_ctx->active_workers=%lld",
        undo_set->active_workers, ctx->active_workers);
    undo_set->active_workers = rcy_rm_id > 0 ? undo_set->assign_workers : 0;
    cm_atomic_add(&ctx->active_workers, undo_set->active_workers);
    CT_LOG_RUN_INF("[tx_area_release] add active_workers in undo_ctx,  undo_set->active_workers=%lld, "
        "undo_ctx->active_workers=%lld", undo_set->active_workers, ctx->active_workers);

    if (session->kernel->id == undo_set->inst_id) {
        tx_area_t *area = &session->kernel->tran_ctx;
        area->rollback_num = need_rcy ? session->kernel->attr.tx_rollback_proc_num : 0;
    }
}

void tx_rollback_items(knl_session_t *session, thread_t *thread, undo_t *undo)
{
    knl_rm_t *rm = session->rm;
    tx_item_t *item = NULL;
    txn_t *txn = NULL;
    uint32 id;
    status_t status;

    for (id = 0; id < undo->capacity; id++) {
        if (thread->closed) {
            break;
        }

        item = &undo->items[id];
        if (item->rmid != session->rmid) {
            continue;
        }

        txn = txn_addr(session, item->xmap);

        switch (txn->status) {
            case XACT_PHASE1:
                status = xa_recover(session, item, txn, id);
                knl_panic(status == CT_SUCCESS);
                break;
            case XACT_PHASE2:
            case XACT_BEGIN:
                tx_rm_attach_trans(rm, item, txn, id);
                knl_rollback(session, NULL);
                break;
            case XACT_END:
            default:
                break;
        }
    }
}

void tx_area_rollback(knl_session_t *session, thread_t *thread, undo_set_t *undo_set)
{
    tx_area_t *area = &session->kernel->tran_ctx;
    uint32 seg_no;

    if ((!DB_IS_READONLY(session) || DB_IS_MAXFIX(session) ||
        (!DB_IS_PRIMARY(&session->kernel->db) && session->kernel->lrpl_ctx.is_promoting == CT_TRUE)) &&
        DB_IS_BG_ROLLBACK_SE(session) && DB_IN_BG_ROLLBACK(session)) {
        for (seg_no = 0; seg_no < UNDO_SEGMENT_COUNT(session); seg_no++) {
            if (thread->closed) {
                break;
            }

            tx_rollback_items(session, thread, &undo_set->undos[seg_no]);
        }

        (void)cm_atomic_dec(&area->rollback_num);
    }
}

inline txn_t *txn_addr(knl_session_t *session, xmap_t xmap)
{
    uint32 page_capacity = TXN_PER_PAGE(session);
    uint8 deposit_id = xmap_get_inst_id(session, xmap);
    knl_panic(deposit_id == (uint8)session->kernel->id);

    undo_set_t *undo_set = UNDO_SET(session, XMAP_INST_ID(xmap));
    undo_t *undo = &undo_set->undos[XMAP_SEG_ID(xmap)];
    txn_page_t *txn_page = undo->txn_pages[xmap.slot / page_capacity];
    return &txn_page->items[xmap.slot % page_capacity];
}

status_t tx_begin(knl_session_t *session)
{
    knl_rm_t *rm = session->rm;
    undo_t *undo = NULL;
    tx_item_t *tx_item = NULL;
    txn_t *txn = NULL;
    undo_page_id_t page_id;

    if (session->kernel->undo_ctx.is_switching) {
        CT_THROW_ERROR(ERR_INVALID_OPERATION, ",when swithching undo space");
        return CT_ERROR;
    }

    uint64 begin_time = KNL_NOW(session);

    if (txn_alloc(session, rm) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (KNL_IS_AUTON_SE(session)) {
        session->kernel->stat.auto_txn_alloc_times += KNL_NOW(session) - begin_time;
    } else {
        session->kernel->stat.txn_alloc_times += KNL_NOW(session) - begin_time;
    }

    undo = &session->kernel->undo_ctx.undos[rm->tx_id.seg_id];
    tx_item = &undo->items[rm->tx_id.item_id];
    page_id = undo->segment->txn_page[tx_item->xmap.slot / TXN_PER_PAGE(session)];
    rm->xid.xmap = tx_item->xmap;

    log_atomic_op_begin(session);

    begin_time = KNL_NOW(session);

    buf_enter_page(session, PAGID_U2N(page_id), LATCH_MODE_X, ENTER_PAGE_RESIDENT);

    txn = txn_addr(session, tx_item->xmap);
    cm_spin_lock(&tx_item->lock, &session->stat->spin_stat.stat_txn);
    txn->xnum++;
    txn->status = (uint8)XACT_BEGIN;
    txn->undo_pages.count = 0;
    txn->undo_pages.first = INVALID_UNDO_PAGID;
    txn->undo_pages.last = INVALID_UNDO_PAGID;
    tx_item->rmid = session->rmid;
    rm->xid.xnum = txn->xnum;
    cm_spin_unlock(&tx_item->lock);

    rm->txn = txn;
    log_put(session, RD_TX_BEGIN, &rm->xid, sizeof(xid_t), LOG_ENTRY_FLAG_NONE);
    buf_leave_page(session, CT_TRUE);

    if (KNL_IS_AUTON_SE(session)) {
        session->kernel->stat.auto_txn_page_waits += KNL_NOW(session) - begin_time;
    } else {
        session->kernel->stat.txn_page_waits += KNL_NOW(session) - begin_time;
    }

    log_atomic_op_end(session);

    knl_panic(XID_INST_ID(rm->xid) == session->kernel->id);
    rm->begin_lsn = session->curr_lsn;
    tx_item->systime = KNL_NOW(session);
    return CT_SUCCESS;
}

/*
 * if call this function, must lock scn_lock first
 */
knl_scn_t tx_inc_scn(knl_session_t *session, uint32 seg_id, txn_t *txn, knl_scn_t xa_scn)
{
    undo_context_t *ctx = &session->kernel->undo_ctx;
    tx_area_t *area = &session->kernel->tran_ctx;
    knl_scn_t scn;
    timeval_t now;
    time_t init_time;
    uint64 seq = 1;
    undo_t *undo = &ctx->undos[seg_id];

    init_time = DB_INIT_TIME(session);

#ifdef Z_SHARDING
    knl_scn_t gts_scn;
    if (TX_XA_CONSISTENCY(session)) {
        status_t status = gts_get_lcl_timestamp(&gts_scn);
        KNL_SCN_TO_TIMESEQ(gts_scn, &now, seq, CM_GTS_BASETIME);
        seq++;
        knl_panic(status == CT_SUCCESS);
    } else
#endif
    {
        (void)cm_gettimeofday(&now);
    }

    cm_spin_lock(&area->scn_lock, &session->stat->spin_stat.stat_inc_scn);

    if (xa_scn != CT_INVALID_ID64) {
        scn = xa_scn;
        if (scn > KNL_GET_SCN(&session->kernel->scn)) {
            KNL_SET_SCN(&session->kernel->scn, scn);
        }
    } else {
        scn = knl_inc_scn(init_time, &now, seq, &session->kernel->scn, session->kernel->attr.systime_inc_threshold);
    }

    if (undo->ow_scn < txn->scn && txn->status != (uint8)XACT_PHASE1) {
        undo->ow_scn = txn->scn;
    }

    cm_spin_unlock(&area->scn_lock);

    return scn;
}

static inline void tx_end_stat(knl_session_t *session, txn_t *txn, tx_item_t *item)
{
    if (txn->status == (uint8)XACT_BEGIN) {
        session->stat->local_txn_times += (KNL_NOW(session) - item->systime);
    } else if (txn->status == (uint8)XACT_PHASE1 || txn->status == (uint8)XACT_PHASE2) {
        session->stat->xa_txn_times += (KNL_NOW(session) - item->systime);
    } else {
        // Never happened until error.
        knl_panic(0);
    }
}

/*
 * end transaction
 * From now on, we are going to overwrite commit scn to transaction,
 * save the max overwritten scn to global transaction area. If we are
 * in rollback process, overwrite 0 to transaction, so the following
 * allocation of itl can reuse itl related to current transaction
 * immediately 'causing no rows or keys are related with the itl.
 */
static void tx_end(knl_session_t *session, bool32 is_commit, knl_scn_t xa_scn, bool32 dis_ckpt)
{
    undo_context_t *ctx = &session->kernel->undo_ctx;
    tx_area_t *area = &session->kernel->tran_ctx;
    knl_rm_t *rm = session->rm;
    undo_set_t *undo_set = UNDO_SET(session, XID_INST_ID(rm->xid));
    txn_t *txn = rm->txn;
    undo_t *tx_undo = &undo_set->undos[rm->tx_id.seg_id];
    tx_item_t *tx_item = &tx_undo->items[rm->tx_id.item_id];
    undo_page_id_t page_id = tx_undo->segment->txn_page[tx_item->xmap.slot / TXN_PER_PAGE(session)];
    bool32 has_logic = (session->kernel->db.ctrl.core.lrep_mode == LOG_REPLICATION_ON);
    rd_tx_end_t redo;

    knl_panic((XID_INST_ID(rm->xid) == session->kernel->id) || DB_IS_BG_ROLLBACK_SE(session));
    rm->need_copy_logic_log = LOG_HAS_LOGIC_DATA(session);
    rm->nolog_insert = CT_FALSE;
    rm->nolog_type = LOGGING_LEVEL;
    rm->logging = CT_TRUE;
    undo_t *undo = &ctx->undos[UNDO_GET_SESSION_UNDO_SEGID(session)];

    redo.xmap = rm->xid.xmap;
    redo.is_auton = 0;
    redo.is_commit = (uint8)is_commit;
    tx_end_stat(session, txn, tx_item);

    /* from now on, we are entering transaction end progress */
    tx_item->in_progress = CT_TRUE;

    if (session->kernel->attr.serialized_commit) {
        cm_spin_lock(&area->seri_lock, &session->stat->spin_stat.stat_seri_commit);
    }

    uint64 begin_time = KNL_NOW(session);
    log_atomic_op_begin(session);
    buf_enter_page(session, PAGID_U2N(page_id), LATCH_MODE_X, ENTER_PAGE_RESIDENT);

    cm_spin_lock(&tx_item->lock, &session->stat->spin_stat.stat_txn);
    txn->scn = tx_inc_scn(session, rm->tx_id.seg_id, txn, xa_scn);
    tx_item->rmid = CT_INVALID_ID16;
    txn->status = (uint8)XACT_END;
    cm_spin_unlock(&tx_item->lock);
    cm_atomic_set(&session->kernel->commit_scn, (int64)txn->scn);

    redo.scn = txn->scn;
    redo.aligned = 0;
    log_put(session, RD_TX_END, &redo, sizeof(rd_tx_end_t), LOG_ENTRY_FLAG_NONE);
    if (has_logic && knl_xa_xid_valid(&rm->xa_xid)) {
        log_append_data(session, &rm->xa_xid, sizeof(knl_xa_xid_t));
    }
    buf_leave_page(session, CT_TRUE);

    if (KNL_IS_AUTON_SE(session)) {
        session->kernel->stat.auto_txn_page_end_waits += KNL_NOW(session) - begin_time;
    } else {
        session->kernel->stat.txn_page_end_waits += KNL_NOW(session) - begin_time;
    }

    if (txn->undo_pages.count > 0) {
        undo_release_pages(session, undo, &txn->undo_pages, CT_TRUE);
        session->rm->txn_alarm_enable = CT_TRUE;
    }

    if (session->rm->noredo_undo_pages.count > 0) {
        undo_release_pages(session, undo, &rm->noredo_undo_pages, CT_FALSE);
    }

    if (dis_ckpt) {
        knl_begin_session_wait(session, CKPT_DISABLE_WAIT, CT_TRUE);
        ckpt_disable(session);
        knl_end_session_wait(session, CKPT_DISABLE_WAIT);
    }
    log_atomic_op_end(session);

    if (session->kernel->attr.serialized_commit) {
        cm_spin_unlock(&area->seri_lock);
    }

    tx_item->in_progress = CT_FALSE;
    // cm_release_cond(&rm->cond);
    dls_release_txn(session, rm);
}

static inline void tx_release(knl_session_t *session)
{
    knl_rm_t *rm = session->rm;
    undo_set_t *undo_set = UNDO_SET(session, XID_INST_ID(rm->xid));

    lock_free(session, rm);
    txn_release(session, undo_set, rm->tx_id);

    tx_reset_rm(rm);

    session->tx_fpl.count = 0;
    session->tx_fpl.index = 0;
}

void tx_copy_logic_log(knl_session_t *session)
{
    knl_rm_t *rm = session->rm;

    rm->need_copy_logic_log = LOG_HAS_LOGIC_DATA(session);
    if (rm->need_copy_logic_log) {
        log_atomic_op_begin(session);
        log_atomic_op_end(session);
        log_commit(session);
    }
}

static inline void tx_delete_xa_xid(knl_session_t *session)
{
    if (knl_xa_xid_valid(&session->rm->xa_xid)) {
        g_knl_callback.delete_xa_xid(&session->rm->xa_xid);
    }
}

void tx_commit(knl_session_t *session, knl_scn_t xa_scn)
{
    knl_rm_t *rm = session->rm;

    rm->isolevel = session->kernel->attr.db_isolevel;
    rm->query_scn = CT_INVALID_ID64;
    bool32 has_logic = session->logic_log_size > 0 || session->rm->logic_log_size > 0;
    if (session->temp_table_count != 0) {
        knl_close_temp_tables(session, DICT_TYPE_TEMP_TABLE_TRANS);
    }

    if (rm->txn == NULL || rm->txn->status == (uint8)XACT_END) {
        tx_copy_logic_log(session);
        if (has_logic) {
            if (db_write_ddl_op(session) != CT_SUCCESS) {
                knl_panic_log(0, "[DDL]can't record logical log for session(%d)", session->id);
            }
            dtc_sync_ddl(session);
        }
        rm->svpt_count = 0;
        return;
    }

    if (has_logic) {
        if (db_write_ddl_op(session) != CT_SUCCESS) {
            knl_panic_log(0, "[DDL]can't record logical log for session(%d)", session->id);
        }
    }

    // to recycle lob deleted pages
    if (rm->lob_items.count != 0) {
        lob_free_delete_pages(session);
        lob_items_free(session);
    }

    tx_end(session, CT_TRUE, xa_scn, has_logic);
    log_commit(session);
    
    if (has_logic) {
        SYNC_POINT_GLOBAL_START(CANTIAN_DDL_BEFORE_SYNC_DDL_ABORT, NULL, 0);
        SYNC_POINT_GLOBAL_END;
        dtc_sync_ddl(session);
        ckpt_enable(session);
    }

    tx_release(session);
    g_knl_callback.accumate_io(session, IO_TYPE_COMMIT);
}

static inline status_t tx_is_invalid_xid(knl_session_t *session, xid_t xid)
{
    if ((xid.xmap.seg_id >= UNDO_SEGMENT_COUNT(session) && !DB_ATTR_CLUSTER(session)) ||
        (xid.xmap.slot / TXN_PER_PAGE(session)) >= UNDO_DEF_TXN_PAGE(session)) {
        CT_THROW_ERROR(ERR_INVALID_DATABASE_DEF, "invalid xid , exceed max segment count or def txn pages");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t knl_commit_force(knl_handle_t handle, knl_xid_t *xid)
{
    knl_session_t *session = (knl_session_t *)handle;
    knl_rm_t *rm = session->rm;
    tx_item_t *item = NULL;
    txn_t *txn = NULL;
    xid_t force_xid;
    tx_id_t tx_id;
    uint32 i;

    if (!DB_IS_RESTRICT(session)) {
        CT_THROW_ERROR(ERR_INVALID_OPERATION, ",operation only supported in restrict mode");
        return CT_ERROR;
    }

    if (rm->txn != NULL) {
        CT_THROW_ERROR(ERR_TXN_IN_PROGRESS, "cur session is in transaction,can't commit force transaction.");
        return CT_ERROR;
    }

    force_xid.xmap.seg_id = xid->seg_id;
    force_xid.xmap.slot = xid->slot;
    force_xid.xnum = xid->xnum;

    if (tx_is_invalid_xid(session, force_xid) != CT_SUCCESS) {
        return CT_ERROR;
    }

    item = xmap_get_item(session, force_xid.xmap);
    txn = txn_addr(session, force_xid.xmap);

    for (i = SESSION_ID_ROLLBACK; i <= SESSION_ID_ROLLBACK_EDN; i++) {
        if (item->rmid == session->kernel->sessions[i]->rmid) {
            break;
        }
    }

    if (i > SESSION_ID_ROLLBACK_EDN ||
        txn->status == (uint8)XACT_END ||
        txn->xnum != xid->xnum) {
        CT_THROW_ERROR(ERR_INVALID_DATABASE_DEF, "invalid xid , not found residual transaction");
        return CT_ERROR;
    }

    /* if the xa trans status is XACT_PHASE2, force commit it as normal residual transaction */
    if (txn->status == (uint8)XACT_PHASE1) {
        CT_THROW_ERROR(ERR_XATXN_IN_PROGRESS, "can't commit force residual XA transaction.");
        return CT_ERROR;
    }

    tx_id = xmap_get_txid(session, force_xid.xmap);
    tx_rm_attach_trans(rm, item, txn, tx_id.item_id);
    knl_commit(handle);
    return CT_SUCCESS;
}

void knl_commit(knl_handle_t handle)
{
    status_t ret = CT_ERROR;
    io_id_t io_id = {0};
    if (cm_dbs_is_enable_dbs()) {
        io_id.io_no = GetFdsaIoNo();
        io_id.fdsa_type = FDSA_KNL_COMMIT;
        ret = AddIo2FdsaHashTable(io_id);
    }
    SYNC_POINT_GLOBAL_START(CANTIAN_KNL_COMMIT_DELAY, NULL, 200000); // delay 200S
    SYNC_POINT_GLOBAL_END;
    SYNC_POINT_GLOBAL_START(CANTIAN_KNL_COMMIT_DELAY_ONCE, NULL, 660000); // delay 660s
    SYNC_POINT_GLOBAL_END;
    knl_session_t *session = (knl_session_t *)handle;
    g_knl_callback.before_commit(handle);
    tx_commit(session, CT_INVALID_ID64);
    session->stat->commits++;
    tx_delete_xa_xid(session);

    if (cm_dbs_is_enable_dbs() && ret == CT_SUCCESS) {
        RemovetIoFromFdsaHashtable(io_id);
    }

    if (!DB_IS_CLUSTER(session) || session->logic_log_num == 0) {
        return;
    }

    if (knl_begin_auton_rm(session) != CT_SUCCESS) {
        return;
    }
    status_t status = db_clean_ddl_op(session, DDL_CLEAN_SESSION);
    knl_end_auton_rm(session, status);
}

static void tx_undo_one_row(knl_session_t *session, undo_row_t *row, undo_page_t *page, int32 slot,
    knl_dictionary_t *dc, heap_undo_assist_t *heap_assist)
{
    switch (row->type) {
        case UNDO_HEAP_INSERT:
            heap_undo_insert(session, row, page, slot, dc, heap_assist);
            break;
        case UNDO_HEAP_DELETE:
        case UNDO_HEAP_DELETE_ORG:
        case UNDO_HEAP_COMPACT_DELETE:
        case UNDO_HEAP_COMPACT_DELETE_ORG:
            heap_undo_delete(session, row, page, slot);
            break;
        case UNDO_HEAP_UPDATE:
        case UNDO_HEAP_UPDATE_FULL:
            heap_undo_update(session, row, page, slot, dc, heap_assist);
            break;
        case UNDO_BTREE_INSERT:
            btree_undo_insert(session, row, page, slot, dc);
            break;
        case UNDO_BTREE_DELETE:
            btree_undo_delete(session, row, page, slot, dc);
            break;
        case UNDO_CREATE_INDEX:
            btree_undo_create(session, row, page, slot);
            break;
        case UNDO_LOB_INSERT:
            lob_undo_insert(session, row, page, slot, dc);
            break;
        case UNDO_LOB_DELETE_COMMIT:
            lob_undo_delete_commit(session, row, page, slot);
            break;
        case UNDO_TEMP_HEAP_INSERT:
            temp_heap_undo_insert(session, row, page, slot);
            break;
        case UNDO_TEMP_HEAP_BINSERT:
            temp_heap_undo_batch_insert(session, row, page, slot);
            break;
        case UNDO_TEMP_HEAP_DELETE:
            temp_heap_undo_delete(session, row, page, slot);
            break;
        case UNDO_TEMP_HEAP_UPDATE:
        case UNDO_TEMP_HEAP_UPDATE_FULL:
            temp_heap_undo_update(session, row, page, slot);
            break;
        case UNDO_TEMP_BTREE_INSERT:
            temp_btree_undo_insert(session, row, page, slot, dc);
            break;
        case UNDO_TEMP_BTREE_BINSERT:
            temp_btree_undo_batch_insert(session, row, page, slot, dc);
            break;
        case UNDO_TEMP_BTREE_DELETE:
            temp_btree_undo_delete(session, row, page, slot, dc);
            break;
        case UNDO_LOB_DELETE:
            lob_undo_delete(session, row, page, slot);
            break;
        case UNDO_HEAP_INSERT_MIGR:
            heap_undo_insert_migr(session, row, page, slot, dc, heap_assist);
            break;
        case UNDO_HEAP_UPDATE_LINKRID:
            heap_undo_update_linkrid(session, row, page, slot);
            break;
        case UNDO_HEAP_DELETE_MIGR:
            heap_undo_delete_migr(session, row, page, slot, dc, heap_assist);
            break;
        case UNDO_PCRH_ITL:
            pcrh_ud_itl(session, row, page, slot, dc, heap_assist);
            break;
        case UNDO_PCRH_INSERT:
            pcrh_undo_ins(session, row, page, slot);
            break;
        case UNDO_PCRH_DELETE:
        case UNDO_PCRH_COMPACT_DELETE:
            pcrh_undo_del(session, row, page, slot);
            break;
        case UNDO_PCRH_UPDATE:
        case UNDO_PCRH_UPDATE_FULL:
            pcrh_undo_upd(session, row, page, slot);
            break;
        case UNDO_PCRH_UPDATE_LINK_SSN:
            pcrh_undo_upd_link_ssn(session, row, page, slot);
            break;
        case UNDO_PCRH_UPDATE_NEXT_RID:
            pcrh_undo_upd_next_rowid(session, row, page, slot);
            break;
        case UNDO_PCRH_BATCH_INSERT:
            pcrh_undo_batch_ins(session, row, page, slot);
            break;
        case UNDO_PCRB_ITL:
            pcrb_undo_itl(session, row, page, slot);
            break;
        case UNDO_PCRB_INSERT:
            pcrb_undo_insert(session, row, page, slot, dc);
            break;
        case UNDO_PCRB_DELETE:
            pcrb_undo_delete(session, row, page, slot, dc);
            break;
        case UNDO_PCRB_BATCH_INSERT:
            pcrb_undo_batch_insert(session, row, page, slot, dc);
            break;
        case UNDO_LOB_DELETE_COMMIT_RECYCLE:
            lob_undo_delete_commit_recycle(session, row, page, slot);
            break;
        case UNDO_LOB_ALLOC_PAGE:
            lob_undo_write_page(session, row, page, slot);
            break;
        case UNDO_CREATE_HEAP:
            heap_undo_create_part(session, row, page, slot);
            break;
        case UNDO_CREATE_LOB:
            lob_undo_create_part(session, row, page, slot);
            break;
        case UNDO_LOB_TEMP_ALLOC_PAGE:
            lob_temp_undo_write_page(session, row, page, slot);
            break;
        case UNDO_LOB_TEMP_DELETE:
            lob_temp_undo_delete(session, row, page, slot);
            break;
        default:
            knl_panic_log(0, "row type is unknown, panic info: page %u-%u type %u row type %u",
                          AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type, row->type);
            break;
    }
}

void tx_rollback_one_row(knl_session_t *session, undo_row_t *row, undo_page_t *page, int32 slot)
{
    knl_dictionary_t dc;
    heap_undo_assist_t heap_assist;
    page_id_t page_id;
    uint32 i;

    heap_assist.rows = 0;
    heap_assist.heap = NULL;
    heap_assist.need_latch = CT_FALSE;
    dc.handle = NULL;
    page_id = AS_PAGID(page->head.id);

    log_atomic_op_begin(session);

    tx_undo_one_row(session, row, page, slot, &dc, &heap_assist);

    if (heap_assist.need_latch) {
        dls_latch_x(session, &heap_assist.heap->latch, session->id, &session->stat_heap);
        tx_undo_one_row(session, row, page, slot, &dc, &heap_assist);
        dls_unlatch(session, &heap_assist.heap->latch, &session->stat_heap);
    }

    // The cleanup of undo row should be in the same atomic operation
    // with rollback to avoid log partial write which would cause
    // rollback a roll-backed row after recovery.
    buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_PINNED);
    row->is_cleaned = 1;
    if (SPC_IS_LOGGING_BY_PAGEID(session, page_id)) {
        log_put(session, RD_UNDO_CLEAN, &slot, sizeof(int32), LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, CT_TRUE);

    log_atomic_op_end(session);

    for (i = 0; i < heap_assist.rows; i++) {
        session->change_list = heap_assist.change_list[i];
        heap_try_change_map(session, heap_assist.heap, heap_assist.page_id[i]);
    }

    if (dc.handle != NULL) {
        dc_close(&dc);
    }
}

static void tx_free_undo_pages(knl_session_t *session, undo_page_list_t *free_list, page_id_t last_page_id,
                               bool32 need_redo)
{
    knl_rm_t *rm = session->rm;
    undo_set_t *undo_set = UNDO_SET(session, XID_INST_ID(rm->xid));
    undo_t *undo = &undo_set->undos[UNDO_GET_SESSION_UNDO_SEGID(session)];
    txn_t *txn = rm->txn;
    undo_page_id_t txn_page_id;
    undo_page_list_t *tx_undo_page_list = NULL;
    rd_undo_chg_txn_t redo;

    txn_get_owner(session, rm->xid.xmap, &txn_page_id);

    log_atomic_op_begin(session);
    buf_enter_page(session, PAGID_U2N(txn_page_id), LATCH_MODE_X, ENTER_PAGE_RESIDENT);

    if (need_redo) {
        tx_undo_page_list = &txn->undo_pages;
    } else {
        tx_undo_page_list = &rm->noredo_undo_pages;
    }

    knl_panic_log(tx_undo_page_list->count >= free_list->count, "undo page count is smaller than free count, "
                  "panic info: page %u-%u type %u undo page count %u free count %u", txn_page_id.file,
                  txn_page_id.page, ((page_head_t *)CURR_PAGE(session))->type,
                  tx_undo_page_list->count, free_list->count);
    tx_undo_page_list->count -= free_list->count;
    if (tx_undo_page_list->count == 0) {
        tx_undo_page_list->first = INVALID_UNDO_PAGID;
        tx_undo_page_list->last = INVALID_UNDO_PAGID;
    } else {
        knl_panic_log(!IS_INVALID_PAGID(last_page_id), "last page id is invalid, panic info: txn_page %u-%u type %u",
                      txn_page_id.file, txn_page_id.page, ((page_head_t *)CURR_PAGE(session))->type);
        tx_undo_page_list->last = PAGID_N2U(last_page_id);
    }

    if (need_redo) {
        redo.xmap = rm->xid.xmap;
        redo.undo_pages = *tx_undo_page_list;
        log_put(session, RD_UNDO_CHANGE_TXN, &redo, sizeof(rd_undo_chg_txn_t), LOG_ENTRY_FLAG_NONE);
    }

    buf_leave_page(session, need_redo);

    undo_release_pages(session, undo, free_list, need_redo);
    log_atomic_op_end(session);
}

/*
 * rollback undo record on undo pages
 * rollback from current_slot in begin page to target_slot in end page,
 * if end page is a invalid page_id, rollback all undo-chained-pages generated by current transaction
 * only in end transaction scenario could we free undo pages in rollback
 */
static void tx_rollback_pages(knl_session_t *session, undo_page_id_t undo_page_id, undo_rowid_t *svpt_urid,
                              bool32 need_redo)
{
    knl_rm_t *rm = session->rm;
    int32 slot, min_slot;
    uint16 end_slot;
    undo_page_t *page = NULL;
    undo_row_t *row = NULL;
    buf_ctrl_t *ctrl = NULL;
    page_id_t page_id, prev;
    undo_page_list_t free_list;
    bool32 need_release = (svpt_urid == NULL && rm->svpt_count == 0);
    free_list.count = 0;
    page_id = PAGID_U2N(undo_page_id);

    while (!IS_INVALID_PAGID(page_id)) {
        if (buf_read_page(session, page_id, LATCH_MODE_S, ENTER_PAGE_PINNED) != CT_SUCCESS) {
            CM_ABORT(DB_IS_CLUSTER(session) && DB_IS_MAXFIX(session), "[BUFFER] ABORT INFO: failed to read page %u-%u", page_id.file, page_id.page);
            CT_LOG_RUN_WAR("page: %u-%u can't be loaded, ignore rollback the reset undo pages of this tx.",
                           AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page);
            break;
        }
        page = (undo_page_t *)CURR_PAGE(session);
        if (page_is_damaged(&page->head)) {
            CM_ABORT(DB_IS_CLUSTER(session) && DB_IS_MAXFIX(session), "[BUFFER] ABORT INFO: page damaged %u-%u",
                     page_id.file, page_id.page);
            CT_LOG_RUN_WAR("page: %u-%u was damaged, ignore rollback the reset undo pages of this tx.",
                           AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page);
            buf_leave_page(session, CT_FALSE);
            break;
        }

        end_slot = page->begin_slot;
        prev = PAGID_U2N(page->prev);
        ctrl = session->curr_page_ctrl;
        buf_leave_page(session, CT_FALSE);

        if (svpt_urid != NULL && IS_SAME_PAGID(svpt_urid->page_id, page_id)) {
            knl_panic_log(svpt_urid->slot >= end_slot, "slot abnormal, panic info: page %u-%u type %u "
                          "svpt_urid slot %u end_slot %u", AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page,
                          page->head.type, svpt_urid->slot, end_slot);
            end_slot = svpt_urid->slot;
        }

        min_slot = (int32)end_slot;
        for (slot = (int32)page->rows - 1; slot >= min_slot; slot--) {
            row = UNDO_ROW(session, page, slot);
            // the database does not replay redo log generated by nologging insert undo, just marking undo row
            // is invalid.
            if (row->xid.value == CT_INVALID_ID64) {
                continue;
            }

            knl_panic_log(row->xid.value == rm->xid.value, "the xid of row and rm are not equal, panic info: "
                          "page %u-%u type %u row xid %llu rm xid %llu", AS_PAGID(page->head.id).file,
                          AS_PAGID(page->head.id).page, page->head.type, row->xid.value, rm->xid.value);

            if (!row->is_cleaned) {
                tx_rollback_one_row(session, row, page, slot);
            }
        }

        BUF_UNPIN(ctrl);

        if (svpt_urid != NULL && IS_SAME_PAGID(svpt_urid->page_id, page_id)) {
            break;  // rollback to savepoint
        }

        if (need_release) {
            if (free_list.count == 0) {
                free_list.first = as_undo_page_id(page_id);
                free_list.last = as_undo_page_id(page_id);
            } else {
                free_list.first = as_undo_page_id(page_id);
            }
            free_list.count++;

            if (free_list.count == CT_EXTENT_SIZE) {
                tx_free_undo_pages(session, &free_list, prev, need_redo);
                free_list.count = 0;
            }
        }
        
        page_id = prev;
    }
}

/*
 * release savepoint whose lsn bigger than the parameter lsn on rm when rollback.
 */
static void tx_release_named_savepoint(knl_session_t *session, knl_savepoint_t *savepoint)
{
    int i;
    knl_rm_t *rm = session->rm;

    if (savepoint == NULL) {
        rm->svpt_count = 0;
        return;
    }
    
    if (rm->svpt_count == 0) {
        return;
    }

    if (savepoint->name[0] != '\0') {
        for (i = rm->svpt_count - 1; i >= 0; i--) {
            if (cm_str_equal_ins(savepoint->name, rm->save_points[i].name)) {
                break;
            }
        }
    } else {
        for (i = rm->svpt_count - 1; i >= 0; i--) {
            if (rm->save_points[i].lsn <= savepoint->lsn) {
                break;
            }
        }
    }

    if (i < 0) {
        rm->svpt_count = 0;
    } else {
        rm->svpt_count = i + 1;
    }
}

void tx_rollback(knl_session_t *session, knl_savepoint_t *savepoint)
{
    knl_rm_t *rm = session->rm;

    /* release savepoint on the rm */
    tx_release_named_savepoint(session, savepoint);

    if (rm->txn == NULL || rm->txn->status == (uint8)XACT_END) {
        if (savepoint == NULL) {
            rm->isolevel = session->kernel->attr.db_isolevel;
            rm->query_scn = CT_INVALID_ID64;
        }
        return;
    }

    /* Only the savepoint in current transaction is valid. */
    if (savepoint != NULL && savepoint->xid == rm->xid.value) {
        knl_panic(savepoint->lsn != CT_INVALID_ID64 || DB_IS_BG_ROLLBACK_SE(session)
                  || IS_INVALID_PAGID(savepoint->urid.page_id) || knl_xa_xid_valid(&rm->xa_xid));
        tx_rollback_pages(session, rm->undo_page_info.undo_rid.page_id, &savepoint->urid, CT_TRUE);
        tx_rollback_pages(session, rm->noredo_undo_page_info.undo_rid.page_id, &savepoint->noredo_urid, CT_FALSE);

        g_knl_callback.invalidate_cursor(session, savepoint->lsn);
    } else {
        knl_panic(rm->begin_lsn != CT_INVALID_ID64 || DB_IS_BG_ROLLBACK_SE(session) || knl_xa_xid_valid(&rm->xa_xid));
        tx_rollback_pages(session, rm->undo_page_info.undo_rid.page_id, NULL, CT_TRUE);
        tx_rollback_pages(session, rm->noredo_undo_page_info.undo_rid.page_id, NULL, CT_FALSE);

        g_knl_callback.invalidate_cursor(session, rm->begin_lsn);
    }

    /* Current savepoint is valid or rm has named savepoint, don't end transaction */
    if (savepoint != NULL && (savepoint->xid == rm->xid.value || rm->svpt_count > 0)) {
        lob_reset_svpt(session, savepoint);
        lock_free_to_svpt(session, savepoint);
        lock_reset_to_svpt(session, savepoint);
    } else {
        if (rm->lob_items.count != 0) {
            lob_items_free(session);
        }

        tx_end(session, CT_FALSE, CT_INVALID_ID64, CT_FALSE);
        tx_release(session);
        if (session->temp_table_count != 0) {
            knl_close_temp_tables(session, DICT_TYPE_TEMP_TABLE_TRANS);
        }
    }
    session->logic_log_size = 0;
    if (savepoint == NULL) {
        rm->isolevel = session->kernel->attr.db_isolevel;
        rm->query_scn = CT_INVALID_ID64;

        if (!DB_IS_CLUSTER(session) || session->logic_log_num == 0) {
            return;
        }

        if (knl_begin_auton_rm(session) != CT_SUCCESS) {
            return;
        }

        status_t status = db_clean_ddl_op(session, DDL_CLEAN_SESSION);
        knl_end_auton_rm(session, status);
    }
}

void knl_rollback(knl_handle_t handle, knl_savepoint_t *savepoint)
{
    knl_session_t *session = (knl_session_t *)handle;
    knl_rm_t *rm = session->rm;

    if (session->rm->nolog_insert && session->rm->nolog_type == SESSION_LEVEL) {
        CT_LOG_RUN_WAR("The rollback does not take effect because the transaction has executed "
            "session level nologging insert, rmid: %d, xid(%d, %d, %d).",
            session->rmid, rm->xid.xmap.seg_id, rm->xid.xmap.slot, rm->xid.xnum);
        return;
    }

    tx_rollback(session, savepoint);
    if (savepoint == NULL) {
        tx_delete_xa_xid(session);
    }

    session->dist_ddl_id = NULL;

    session->stat->rollbacks++;
}

/*
 * get transaction info
 * get transaction info by transaction xid
 * @param kernel session, is_scan, xid, trans info
 */
void tx_get_info(knl_session_t *session, bool32 is_scan, xid_t xid, txn_info_t *txn_info)
{
    txn_snapshot_t snapshot;

    tx_get_local_snapshot(session, xid.xmap, &snapshot);
    txn_info->xid.xmap = xid.xmap;
    txn_info->xid.xnum = snapshot.xnum;

    if (xid.xnum == snapshot.xnum) {
        /*
         * Transaction version is same with us, we get trans info directly from
         * current transaction. If transaction is in XACT_END status, we just return it.
         * If transaction is active or transaction is ending in progress and current
         * behavior is itl-reuse, we will read history version or reuse other itl.
         */
        txn_info->is_owscn = CT_FALSE;

        if (snapshot.status == (uint8)XACT_PHASE1 || snapshot.status == (uint8)XACT_PHASE2) {
            txn_info->scn = snapshot.scn;
            txn_info->status = (uint8)snapshot.status;
        } else if (snapshot.status != (uint8)XACT_END || (snapshot.in_progress && !is_scan)) {
            txn_info->scn = DB_CURR_SCN(session);
            txn_info->status = (uint8)XACT_BEGIN;
        } else {
            txn_info->scn = snapshot.scn;
            txn_info->status = (uint8)XACT_END;
        }
    } else if (xid.xnum + 1 == snapshot.xnum && snapshot.status == (uint8)XACT_BEGIN) {
        /*
         * To increase transaction info retention time, we would not overwrite
         * transaction scn when we are reusing a committed transaction. So, we
         * can get commit version from current transaction directly.
         */
        txn_info->scn = snapshot.scn;
        txn_info->is_owscn = CT_FALSE;
        txn_info->status = (uint8)XACT_END;
    } else {
        /* commit info has been overwritten, get from undo global overwrite area */
        undo_set_t *undo_set = UNDO_SET(session, XID_INST_ID(xid));
        undo_t *undo = &undo_set->undos[XID_SEG_ID(xid)];
        txn_info->status = (uint8)XACT_END;
        txn_info->is_owscn = CT_TRUE;
        txn_info->scn = undo->ow_scn;
    }
}

void tx_get_itl_info(knl_session_t *session, bool32 is_scan, itl_t *itl, txn_info_t *txn_info)
{
    if (itl->is_active) {
        tx_get_info(session, is_scan, itl->xid, txn_info);
    } else {
        txn_info->scn = itl->scn;
        txn_info->is_owscn = (bool8)itl->is_owscn;
        txn_info->status = (uint8)XACT_END;
    }
}

void tx_get_pcr_itl_info(knl_session_t *session, bool32 is_scan, pcr_itl_t *itl, txn_info_t *txn_info)
{
    if (itl->is_active) {
        if (!itl->is_hist) {
            if (DB_IS_CLUSTER(session)) {
                dtc_get_txn_info(session, is_scan, itl->xid, txn_info);
            } else {
                tx_get_info(session, is_scan, itl->xid, txn_info);
            }
        } else {
            txn_info->scn = DB_CURR_SCN(session);
            txn_info->is_owscn = CT_FALSE;
            txn_info->status = (uint8)XACT_BEGIN;
        }
    } else {
        txn_info->scn = itl->scn;
        txn_info->is_owscn = (bool8)itl->is_owscn;
        txn_info->status = (uint8)XACT_END;
    }
}

static status_t tx_check_wait_valid(knl_session_t *session)
{
    if (session->dead_locked) {
        CT_THROW_ERROR(ERR_DEAD_LOCK, "transaction", session->id);
        CT_LOG_ALARM(WARN_DEADLOCK, "'instance-name':'%s'}", session->kernel->instance_name);
        return CT_ERROR;
    }

    if (session->itl_dead_locked) {
        CT_THROW_ERROR(ERR_DEAD_LOCK, "itl", session->id);
        CT_LOG_ALARM(WARN_DEADLOCK, "'instance-name':'%s'}", session->kernel->instance_name);
        return CT_ERROR;
    }

    if (session->lock_dead_locked) {
        CT_THROW_ERROR(ERR_DEAD_LOCK, "table", session->id);
        CT_LOG_ALARM(WARN_DEADLOCK, "'instance-name':'%s'}", session->kernel->instance_name);
        return CT_ERROR;
    }

    if (session->canceled) {
        CT_THROW_ERROR(ERR_OPERATION_CANCELED);
        return CT_ERROR;
    }

    if (session->killed) {
        CT_THROW_ERROR(ERR_OPERATION_KILLED);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static inline void tx_reset_deadlock_flag(knl_session_t *session)
{
    session->itl_dead_locked = CT_FALSE;
    session->dead_locked = CT_FALSE;
    session->lock_dead_locked = CT_FALSE;
}

/*
 * transaction wait
 * transaction concurrency control interface
 * Wait for the end of the transaction which hold the heap row or btree key.
 * @param kernel session, timeout(in milliseconds)
 */
status_t tx_wait(knl_session_t *session, uint32 timeout, wait_event_t event)
{
    txn_snapshot_t snapshot;
    date_t begin_time;
    status_t status;

    tx_get_snapshot(session, session->wxid.xmap, &snapshot);
    if (snapshot.xnum != session->wxid.xnum || snapshot.status == (uint8)XACT_END) {
        session->wxid.value = CT_INVALID_ID64;
        return CT_SUCCESS;
    }

    begin_time = KNL_NOW(session);
    tx_reset_deadlock_flag(session);
    session->wrmid = snapshot.rmid;

    knl_begin_session_wait(session, event, CT_TRUE);

    for (;;) {
        if (dls_wait_txn(session, snapshot.rmid)) {
            status = CT_SUCCESS;
            break;
        }

        if (timeout != 0 && (KNL_NOW(session) - begin_time) / (date_t)MICROSECS_PER_MILLISEC > (date_t)timeout) {
            CT_THROW_ERROR(ERR_LOCK_TIMEOUT);
            status = CT_ERROR;
            break;
        }

        if (tx_check_wait_valid(session) != CT_SUCCESS) {
            status = CT_ERROR;
            break;
        }

        tx_get_snapshot(session, session->wxid.xmap, &snapshot);
        if (snapshot.xnum != session->wxid.xnum || snapshot.status == (uint8)XACT_END) {
            status = CT_SUCCESS;
            break;
        }
    }

    dls_wait_txn_recyle(session);

    knl_end_session_wait(session, event);
    session->stat->con_wait_time += session->wait_pool[event].usecs;
    tx_reset_deadlock_flag(session);
    session->wrmid = CT_INVALID_ID16;
    session->wxid.value = CT_INVALID_ID64;

    return status;
}

inline void tx_get_local_snapshot(knl_session_t *session, xmap_t xmap, txn_snapshot_t *snapshot)
{
    tx_item_t *tx_item = xmap_get_item(session, xmap);
    txn_t *txn = txn_addr(session, xmap);

    cm_spin_lock(&tx_item->lock, &session->stat->spin_stat.stat_txn);
    snapshot->xnum = txn->xnum;
    snapshot->scn = txn->scn;
    snapshot->rmid = tx_item->rmid;
    snapshot->status = txn->status;
    snapshot->in_progress = tx_item->in_progress;
    cm_spin_unlock(&tx_item->lock);
}

inline void tx_get_snapshot(knl_session_t *session, xmap_t xmap, txn_snapshot_t *snapshot)
{
    uint8 inst_id, curr_id;

    inst_id = XMAP_INST_ID(xmap);
    if (inst_id == session->kernel->id) {
        tx_get_local_snapshot(session, xmap, snapshot);
        return;
    }

    for (;;) {
        curr_id = xmap_get_inst_id(session, xmap);
        if (curr_id == session->kernel->id) {
            if (rc_instance_accessible(inst_id)) {
                tx_get_local_snapshot(session, xmap, snapshot);
            } else {
                cm_sleep(MES_MSG_RETRY_TIME);
                continue;
            }
        } else {
            if (g_dtc->profile.node_count <= curr_id) {
                CT_LOG_RUN_ERR("current id get from xmap is invalid, curr_id(%u)", curr_id);
                break;
            }
            if (dtc_get_remote_txn_snapshot(session, xmap, curr_id, snapshot) != CT_SUCCESS) {
                cm_reset_error();
                cm_sleep(MES_MSG_RETRY_TIME);
                continue;
            }
        }
        return;
    }
}

void txn_get_owner(knl_session_t *session, xmap_t xmap, undo_page_id_t *page_id)
{
    undo_set_t *undo_set = UNDO_SET(session, XMAP_INST_ID(xmap));
    undo_t *undo = &undo_set->undos[XMAP_SEG_ID(xmap)];

    *page_id = undo->segment->txn_page[xmap.slot / TXN_PER_PAGE(session)];
}

void tx_rollback_proc(thread_t *thread)
{
    rollback_ctx_t *rb_ctx = (rollback_ctx_t *)thread->argument;
    knl_session_t *session = rb_ctx->session;
    undo_set_t *undo_set = UNDO_SET(session, rb_ctx->inst_id);
    undo_context_t *ctx = &session->kernel->undo_ctx;

    session->bg_rollback = CT_TRUE;

    cm_set_thread_name("rollback");
    CT_LOG_RUN_INF("rollback %u thread started", rb_ctx->inst_id);
    KNL_SESSION_SET_CURR_THREADID(session, cm_get_current_thread_id());
    while (!thread->closed) {
        /*
         * make it works when it reach to WAIT_CLEAN,
         * because we will drop nologging tables during `db_drop_nologging_table',
         * if we want to lock a row which is locked by a running transaction,
         * we can wait tx_rollback_proc to undo it,
         * otherwise, deadlock maybe occurred, example(1->2->3->1):
         * 1. tx_rollback_proc wait db_open;
         * 2. db_open wait db_drop_nologging_table;
         * 3. db_clean_nologging_guts wait tx_rollback_proc to rollback a running transaction;
         */
        if (session->kernel->db.status >= DB_STATUS_WAIT_CLEAN) {
            if (DB_IS_MAXFIX(session)) {
                break;
            }
            if (!DB_IS_READONLY(session) && !DB_IS_MAINTENANCE(session)) {
                break;
            }
            if (!DB_IS_PRIMARY(&session->kernel->db) && session->kernel->lrpl_ctx.is_promoting == CT_TRUE) {
                break;
            }
        }
        cm_sleep(200);
    }

    if (!thread->closed) {
        tx_area_rollback(session, thread, undo_set);

        CT_LOG_RUN_INF("[tx_rollback_proc] undo_set->active_workers=%lld, undo_ctx->active_workers=%lld",
            undo_set->active_workers, ctx->active_workers);
        if (undo_set->active_workers > 0) {
            (void)cm_atomic_dec(&ctx->active_workers);
            CT_LOG_RUN_INF("[tx_rollback_proc] dec active_workers in undo ctx, undo_set->active_workers=%lld, "
                "undo_ctx->active_workers=%lld", undo_set->active_workers, ctx->active_workers);
        }
    }

    session->bg_rollback = CT_FALSE;

    CT_LOG_RUN_INF("rollback thread closed");
    KNL_SESSION_CLEAR_THREADID(session);
}

status_t tx_rollback_start(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    undo_set_t *undo_set = MY_UNDO_SET(session);
    uint32 i;
    // undoset and rb_ctx in undo_set is allocated in tx_area_init just before recovery

    for (i = 0; i < session->kernel->attr.tx_rollback_proc_num; i++) {
        undo_set->rb_ctx[i].session = kernel->sessions[SESSION_ID_ROLLBACK + i];
        undo_set->rb_ctx[i].inst_id = session->kernel->id;
        if (cm_create_thread(tx_rollback_proc, 0, &undo_set->rb_ctx[i], &kernel->tran_ctx.rollback_proc[i]) !=
            CT_SUCCESS) {
            return CT_ERROR;
        }
        undo_set->rb_ctx[i].thread = kernel->tran_ctx.rollback_proc[i];
    }

    return CT_SUCCESS;
}

void tx_rollback_close(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    tx_area_t *ctx = &kernel->tran_ctx;
    undo_set_t *undo_set = MY_UNDO_SET(session);

    for (uint32 i = 0; i < session->kernel->attr.tx_rollback_proc_num; i++) {
        knl_panic(undo_set->rb_ctx[i].session == kernel->sessions[SESSION_ID_ROLLBACK + i]);
        cm_close_thread(&ctx->rollback_proc[i]);
    }

    knl_panic(undo_set->active_workers == 0);
}

status_t txn_dump_page(knl_session_t *session, page_head_t *page_head, cm_dump_t *dump)
{
    txn_page_t *page = (txn_page_t *)page_head;
    txn_t *txn = NULL;
    page_id_t first, last;

    /* page size if 8192, bigger than sizeof(page_head_t) + sizeof(page_tail_t) */
    uint32 count = (PAGE_SIZE(page->head) - sizeof(page_head_t) - sizeof(page_tail_t)) / sizeof(txn_t);
    cm_dump(dump, "txn page information\n");
    CM_DUMP_WRITE_FILE(dump);
    for (uint32 slot = 0; slot < count; slot++) {
        txn = &page->items[slot];

        first = PAGID_U2N(txn->undo_pages.first);
        last = PAGID_U2N(txn->undo_pages.last);

        cm_dump(dump, "\titems[%u] ", slot);
        cm_dump(dump, "\txnum: %-3u", txn->xnum);
        cm_dump(dump, "\tstatus: %s", txn_status((xact_status_t)txn->status));
        cm_dump(dump, "\tscn: %llu", txn->scn);
        cm_dump(dump, "\tundo_pages: count %u first %u-%u last %u-%u\n", txn->undo_pages.count,
                (uint32)first.file, (uint32)first.page, (uint32)last.file, (uint32)last.page);
        CM_DUMP_WRITE_FILE(dump);
    }

    return CT_SUCCESS;
}

void tx_record_sql(knl_session_t *session)
{
    text_t sql_text;

    sql_text.str = (char *)cm_push(session->stack, RECORD_SQL_SIZE);
    sql_text.len = RECORD_SQL_SIZE;
    if (sql_text.str == NULL || g_knl_callback.get_sql_text(session->id, &sql_text) != CT_SUCCESS) {
        cm_reset_error();
    } else {
        CT_LOG_RUN_ERR("sql detail: %s", T2S(&sql_text));
    }
    cm_pop(session->stack);
}

void tx_shutdown(knl_session_t *session)
{
    for (uint8 id = 0; id < CT_MAX_INSTANCES; id++) {
        undo_set_t *undo_set = UNDO_SET(session, id);
        if (undo_set->assign_workers == 0) {
            continue;
        }

        if (id == session->kernel->id) {
            /* release local transaction area */
            tx_rollback_close(session);
        } else {
            /* release deposit transaction area */
            dtc_rollback_close(session, id);
        }
    }
}
