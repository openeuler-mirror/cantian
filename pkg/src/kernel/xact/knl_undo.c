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
 * knl_undo.c
 *
 *
 * IDENTIFICATION
 * src/kernel/xact/knl_undo.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_xact_module.h"
#include "knl_undo.h"
#include "knl_buffer_access.h"
#include "knl_context.h"
#include "knl_space_manage.h"
#include "dtc_database.h"

undo_type_descriptor_t g_undo_type_desc[] = {
    { UNDO_HEAP_INSERT, "heap_insert" },
    { UNDO_HEAP_DELETE, "heap_delete" },
    { UNDO_HEAP_COMPACT_DELETE, "heap_compact_delete" },
    { UNDO_HEAP_UPDATE, "heap_update" },
    { UNDO_HEAP_UPDATE_FULL, "heap_update_full" },
    { UNDO_BTREE_INSERT, "btree_insert" },
    { UNDO_BTREE_DELETE, "btree_delete" },
    { UNDO_CREATE_INDEX, "create_index"},
    { UNDO_LOB_INSERT, "lob_insert" },
    { UNDO_LOB_DELETE_COMMIT, "lob_delete_commit"},
    { UNDO_TEMP_HEAP_INSERT, "temp_heap_insert" },
    { UNDO_TEMP_HEAP_BINSERT, "temp_heap_batch_insert" },
    { UNDO_TEMP_HEAP_DELETE, "temp_heap_delete" },
    { UNDO_TEMP_HEAP_UPDATE, "temp_heap_delete" },
    { UNDO_TEMP_HEAP_UPDATE_FULL, "temp_heap_update_full"},
    { UNDO_TEMP_BTREE_INSERT, "temp_btree_insert" },
    { UNDO_TEMP_BTREE_DELETE, "temp_btree_delete" },
    { UNDO_TEMP_BTREE_BINSERT, "temp_btree_batch_insert" },
    { UNDO_LOB_DELETE, "lob_delete" },
    { UNDO_HEAP_INSERT_MIGR, "heap_insert_migr" },
    { UNDO_HEAP_UPDATE_LINKRID, "heap_update_linkrid" },
    { UNDO_HEAP_DELETE_MIGR, "heap_delete_migr" },
    { UNDO_HEAP_DELETE_ORG, "heap_delete_org" },
    { UNDO_HEAP_COMPACT_DELETE_ORG, "heap_compact_delete_org" },
    { UNDO_PCRH_ITL, "pcrh_itl" },
    { UNDO_PCRH_INSERT, "pcrh_insert" },
    { UNDO_PCRH_DELETE, "pcrh_delete" },
    { UNDO_PCRH_COMPACT_DELETE, "pcrh_compact_delete" },
    { UNDO_PCRH_UPDATE, "pcrh_update" },
    { UNDO_PCRH_UPDATE_FULL, "pcrh_update_full" },
    { UNDO_PCRH_UPDATE_LINK_SSN, "pcrh_update_link_ssn" },
    { UNDO_PCRH_UPDATE_NEXT_RID, "pcrh_update_next_rid" },
    { UNDO_PCRH_BATCH_INSERT, "pcrh_batch_insert"},
    { UNDO_PCRB_ITL, "pcrb_itl" },
    { UNDO_PCRB_INSERT, "pcrb_insert" },
    { UNDO_PCRB_DELETE, "pcrb_delete"},
    { UNDO_PCRB_BATCH_INSERT, "pcrb_batch_insert" },
    { UNDO_LOB_DELETE_COMMIT_RECYCLE, "lob_delete_commit_recycle"},
    { UNDO_LOB_ALLOC_PAGE, "lob_alloc_page" },
    { UNDO_CREATE_HEAP, "create hash partition heap entry"},
    { UNDO_CREATE_LOB, "create hash partition lob entry"},
};

const char *undo_type(uint8 type)
{
    uint32 undo_count = sizeof(g_undo_type_desc) / sizeof(undo_type_descriptor_t);
    for (uint32 i = 0; i < undo_count; i++) {
        if (type == g_undo_type_desc[i].undo_type) {
            return g_undo_type_desc[i].type_desc;
        }
    }

    return "invalid";
}

/*
 * print the given undo page for debug
 * @note caller should hold the undo page
 */
status_t undo_dump_page(knl_session_t *session, page_head_t *page_head, cm_dump_t *dump)
{
    undo_page_t *page = (undo_page_t *)page_head;
    undo_row_t *row = NULL;
    undo_page_id_t seg_id;

    cm_dump(dump, "undo page information\n");
    cm_dump(dump, "\tprev: %u-%u", page->prev.file, page->prev.page);
    cm_dump(dump, "\tss_time: %lld", page->ss_time);
    cm_dump(dump, "\trows: %u", page->rows);
    cm_dump(dump, "\tfree_size: %u", page->free_size);
    cm_dump(dump, "\tfree_begin: %u", page->free_begin);
    cm_dump(dump, "\tbegin_slot: %u\n", page->begin_slot);

    cm_dump(dump, "row information on this page\n");
    cm_dump(dump, "slot\trow_type\tis_cleaned\tis_xfirst\tscn\tis_owscn\txmap\txnum\tssn");
    cm_dump(dump, "\tseg_id\tis_shadow\tuser_id\ttable_id\tindex_id\trow_page\trow_slot\tprev_undo\tprev_slot\n");

    CM_DUMP_WRITE_FILE(dump);

    for (uint32 slot = 0; slot < page->rows; slot++) {
        row = UNDO_ROW(session, page, slot);

        cm_dump(dump, "#%u\t%s", slot, undo_type((uint8)row->type));
        cm_dump(dump, "\t%u\t%u\t%llu\t%u\t%u-%u\t%u\t%u", row->is_cleaned, row->is_xfirst, row->scn, row->is_owscn,
                row->xid.xmap.seg_id, row->xid.xmap.slot, row->xid.xnum, row->ssn);

        if (row->type == UNDO_BTREE_INSERT || row->type == UNDO_BTREE_DELETE) {
            seg_id.value = row->prev_page.value;
            cm_dump(dump, "\t%u-%u\t%u", seg_id.file, seg_id.page, (row->index_id == CT_SHADOW_INDEX_ID ? 1 : 0));
        } else if (row->type == UNDO_TEMP_BTREE_INSERT || row->type == UNDO_TEMP_BTREE_DELETE) {
            cm_dump(dump, "\t%u\t%u\t%u", row->user_id, (uint32)row->seg_page, (uint32)row->index_id);
        } else {
            cm_dump(dump, "\t%u-%u\t%u", (uint32)row->rowid.file, (uint32)row->rowid.page, (uint32)row->rowid.slot);
        }

        cm_dump(dump, "\t%u-%u\t%u\n", row->prev_page.file, row->prev_page.page, row->prev_slot);

        CM_DUMP_WRITE_FILE(dump);
    }
    return CT_SUCCESS;
}

static inline bool32 undo_cipher_reserve_valid(knl_session_t *session, undo_page_t *page, uint8 cipher_reserve_size)
{
    uint16 cipher_offset = sizeof(undo_page_t) + cipher_reserve_size;

    if (page->free_begin < cipher_offset) {
        return CT_FALSE;
    } else if (page->rows > 0 && *UNDO_SLOT(session, page, 0) < cipher_offset) {
        return CT_FALSE;
    }

    return CT_TRUE;
}

static inline bool32 undo_is_formated_page(knl_session_t *session, undo_page_t *page)
{
    if (page->rows == 0 && page->begin_slot == 0 &&
        page->free_size == (uint16)(DEFAULT_PAGE_SIZE(session) - sizeof(undo_page_t) - sizeof(page_tail_t)) &&
        page->free_begin == sizeof(undo_page_t)) {
        return CT_TRUE;
    }

    return CT_FALSE;
}

bool32 undo_valid_encrypt(knl_session_t *session, page_head_t *page)
{
    space_t *space = SPACE_GET(session, DATAFILE_GET(session, AS_PAGID_PTR(page->id)->file)->space_id);
    if (space->ctrl->cipher_reserve_size == 0) {
        return CT_FALSE;
    }
    return undo_cipher_reserve_valid(session, (undo_page_t *)page, space->ctrl->cipher_reserve_size);
}

void temp2_undo_init(knl_session_t *session)
{
    undo_context_t *ctx = &session->kernel->undo_ctx;
    uint32 i;

    for (i = 0; i < UNDO_SEGMENT_COUNT(session); i++) {
        ctx->undos[i].temp_free_page_list.count = 0;
        ctx->undos[i].temp_free_page_list.first = INVALID_UNDO_PAGID;
        ctx->undos[i].temp_free_page_list.last = INVALID_UNDO_PAGID;
    }
}

void undo_init_proc(thread_t *thread)
{
    knl_session_t *session = NULL;
    if (g_knl_callback.alloc_knl_session(CT_TRUE, (knl_handle_t *)&session) != CT_SUCCESS) {
        knl_panic(0);
    }
    undo_init_worker_t *worker = (undo_init_worker_t *)thread->argument;
    undo_init_ctx_t *undo_ctx = worker->undo_ctx;
    undo_page_id_t *entry = worker->entry;
    uint32 lseg_no = worker->lseg_no;
    uint32 rseg_no = worker->rseg_no;
    undo_set_t *undo_set = worker->undo_set;
    CT_LOG_RUN_INF("prefetch start thread %u", lseg_no);
    if (!thread->closed) {
        for(uint32 i = lseg_no; i < rseg_no; i += UNDO_INIT_THREAD_NUMS) {
            undo_set->undos[i].entry = entry[i];
            
            buf_enter_page(session, PAGID_U2N(entry[i]), LATCH_MODE_S, ENTER_PAGE_RESIDENT);
            undo_set->undos[i].segment = (undo_segment_t *)(CURR_PAGE(session) + PAGE_HEAD_SIZE);
            buf_leave_page(session, CT_FALSE);

            for (uint32 j = 0; j < undo_set->undos[i].segment->txn_page_count; j++) {
                buf_enter_page(session, PAGID_U2N(undo_set->undos[i].segment->txn_page[j]), LATCH_MODE_S,
                            ENTER_PAGE_RESIDENT);
                undo_set->undos[i].txn_pages[j] = (txn_page_t *)CURR_PAGE(session);
                buf_leave_page(session, CT_FALSE);
            }
        }
    }
    thread->closed = CT_TRUE;
    if (undo_ctx->undo_init_active_workers > 0) {
        (void)cm_atomic_dec(&undo_ctx->undo_init_active_workers);
    }
    g_knl_callback.release_knl_session(session);
    CT_LOG_RUN_INF("prefetch end thread %u", lseg_no);
    return;    
}


void undo_init_impl(knl_session_t *session, undo_set_t *undo_set, uint32 lseg_no, uint32 rseg_no)
{
    undo_page_id_t *entry = NULL;
    undo_init_ctx_t undo_ctx = {0};
    undo_ctx.undo_init_active_workers = UNDO_INIT_THREAD_NUMS;

    undo_set->used = CT_TRUE;
    buf_enter_page(session, undo_set->space->entry, LATCH_MODE_S, ENTER_PAGE_RESIDENT);
    entry = (undo_page_id_t *)(CURR_PAGE(session) + PAGE_HEAD_SIZE + sizeof(space_head_t));
    for (int k = 0; k < UNDO_INIT_THREAD_NUMS; k++) {
        undo_init_worker_t *undo_init_worker = &undo_ctx.workers[k];
        undo_init_worker->entry = entry;
        undo_init_worker->lseg_no = lseg_no + k;
        undo_init_worker->rseg_no = rseg_no;
        undo_init_worker->undo_ctx = &undo_ctx;
        undo_init_worker->undo_set = undo_set;
        if (cm_create_thread(undo_init_proc, 0, undo_init_worker, &undo_init_worker->thread) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("failed to create tx_rollback_proc %u", k);
            return;
        }
    }

    while (undo_ctx.undo_init_active_workers > 0) {
        CT_LOG_RUN_INF("wait for prefetch end");
        cm_sleep(5);
    }

    buf_leave_page(session, CT_FALSE);
}

void undo_set_release(knl_session_t *session, undo_set_t *undo_set)
{
    undo_t *undo = NULL;
    buf_ctrl_t *ctrl = NULL;

    for (uint32 i = 0; i < UNDO_SEGMENT_COUNT(session); i++) {
        undo = &undo_set->undos[i];

        for (uint32 j = 0; j < undo->segment->txn_page_count; j++) {
            buf_enter_page(session, PAGID_U2N(undo->segment->txn_page[j]), LATCH_MODE_S, ENTER_PAGE_RESIDENT);
            ctrl = session->curr_page_ctrl;
            buf_leave_page(session, CT_FALSE);

            buf_unreside(session, ctrl);
            undo->txn_pages[j] = NULL;
        }

        buf_enter_page(session, PAGID_U2N(undo->entry), LATCH_MODE_S, ENTER_PAGE_RESIDENT);
        ctrl = session->curr_page_ctrl;
        buf_leave_page(session, CT_FALSE);

        buf_unreside(session, ctrl);
        undo->segment = NULL;
    }

    undo_set->inst_id = CT_INVALID_ID32;
    undo_set->space = NULL;
    undo_set->used = CT_FALSE;
}

/*
 * init the undo context
 */
void undo_init(knl_session_t *session, uint32 lseg_no, uint32 rseg_no)
{
    undo_context_t *ctx = &session->kernel->undo_ctx;
    core_ctrl_t *core_ctrl = DB_CORE_CTRL(session);
    undo_set_t *undo_set = MY_UNDO_SET(session);

    ctx->retention = session->kernel->attr.undo_retention_time;
    ctx->space = spc_get_undo_space(session, session->kernel->id);
    ctx->temp_space = SPACE_GET(session, core_ctrl->temp_undo_space);
    ctx->is_switching = CT_FALSE;
    ctx->extend_segno = 0;
    ctx->extend_cnt = 0;
    ctx->undos = undo_set->undos;
    undo_set->space = ctx->space;
    undo_set->inst_id = session->kernel->id;

    undo_init_impl(session, undo_set, lseg_no, rseg_no);

    temp2_undo_init(session);
}

/*
 * close the undo pre-loading thread
 */
void undo_close(knl_session_t *session)
{
    undo_context_t *ctx = &session->kernel->undo_ctx;

    cm_close_thread(&ctx->thread);
}

/*
 * format the specified txn page during undo create
 * @param kernel session, txn page, page id
 */
static inline void undo_format_txn(knl_session_t *session, page_head_t *page, page_id_t page_id)
{
    page_init(session, page, page_id, PAGE_TYPE_TXN);
    log_put(session, RD_UNDO_FORMAT_TXN, page, sizeof(page_head_t), LOG_ENTRY_FLAG_NONE);
}

/*
 * format the specified undo page
 * @param kernel session, undo page, page id, prev undo page, next undo page
 * @note as undo page management is page level rather than extent level, we
 * link formated undo page to the specified undo page list.
 */
void undo_format_page(knl_session_t *session, undo_page_t *page, page_id_t page_id,
                      undo_page_id_t prev, undo_page_id_t next)
{
    page_init(session, (page_head_t *)page, page_id, PAGE_TYPE_UNDO);
    AS_PAGID_PTR(page->head.next_ext)->file = next.file;
    AS_PAGID_PTR(page->head.next_ext)->page = next.page;
    page->ss_time = 0;
    page->rows = 0;
    page->begin_slot = 0;
    page->prev = prev;
    page->free_size = (uint16)(DEFAULT_PAGE_SIZE(session) - sizeof(undo_page_t) - sizeof(page_tail_t));
    page->free_begin = sizeof(undo_page_t);
}

static void undo_extend_txn_impl(knl_session_t *session, space_t *space, undo_t *undo, page_id_t *extent)
{
    rd_undo_alloc_txn_page_t rd;

    buf_enter_page(session, PAGID_U2N(undo->entry), LATCH_MODE_X, ENTER_PAGE_RESIDENT);

    buf_enter_page(session, *extent, LATCH_MODE_X, ENTER_PAGE_RESIDENT | ENTER_PAGE_NO_READ);
    undo_format_txn(session, (page_head_t *)CURR_PAGE(session), *extent);
    rd.slot = undo->segment->txn_page_count;
    rd.txn_extent = *extent;
    undo->segment->txn_page[undo->segment->txn_page_count++] = PAGID_N2U(*extent);

    buf_leave_page(session, CT_TRUE);

    log_put(session, RD_UNDO_EXTEND_TXN, &rd, sizeof(rd_undo_alloc_txn_page_t), LOG_ENTRY_FLAG_NONE);
    buf_leave_page(session, CT_TRUE);
}

/*
 * extend a txn page for the specified undo segment
 * @param kernel session, undo segment id
 * @note we use space alloc extent interface to catch error
 */
static status_t undo_extend_txn(knl_session_t *session, space_t *space, undo_t *undo)
{
    page_id_t extent;

    log_atomic_op_begin(session);

    if (CT_SUCCESS != spc_alloc_extent(session, space, space->ctrl->extent_size, &extent, CT_FALSE)) {
        CT_THROW_ERROR(ERR_ALLOC_EXTENT, space->ctrl->name);
        log_atomic_op_end(session);
        return CT_ERROR;
    }

    undo_extend_txn_impl(session, space, undo, &extent);

    log_atomic_op_end(session);

    return CT_SUCCESS;
}

status_t undo_df_extend_txn(knl_session_t *session, space_t *space, undo_t *undo, datafile_t *df)
{
    page_id_t extent;

    log_atomic_op_begin(session);

    if (CT_SUCCESS != spc_df_alloc_extent(session, space, space->ctrl->extent_size, &extent, df)) {
        CT_THROW_ERROR(ERR_ALLOC_EXTENT, space->ctrl->name);
        log_atomic_op_end(session);
        return CT_ERROR;
    }

    undo_extend_txn_impl(session, space, undo, &extent);

    log_atomic_op_end(session);

    return CT_SUCCESS;
}

void undo_create_segment_impl(knl_session_t *session, space_t *space, undo_t *undo, uint32 id, page_id_t *extent)
{
    undo_page_id_t *undo_entry = NULL;
    rd_undo_alloc_seg_t redo;

    undo->entry = PAGID_N2U(*extent);

    buf_enter_page(session, space->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    undo_entry = (undo_page_id_t *)(CURR_PAGE(session) + PAGE_HEAD_SIZE + sizeof(space_head_t));
    undo_entry[id] = undo->entry;

    redo.entry = undo->entry;
    redo.id = id;
    log_put(session, RD_UNDO_ALLOC_SEGMENT, &redo, sizeof(rd_undo_alloc_seg_t), LOG_ENTRY_FLAG_NONE);
    buf_leave_page(session, CT_TRUE);

    buf_enter_page(session, PAGID_U2N(undo->entry), LATCH_MODE_X, ENTER_PAGE_RESIDENT | ENTER_PAGE_NO_READ);
    page_init(session, (page_head_t *)CURR_PAGE(session), PAGID_U2N(undo->entry), PAGE_TYPE_UNDO_HEAD);

    undo->segment = UNDO_GET_SEGMENT(session);
    undo->segment->page_list.count = 0;
    undo->segment->page_list.first = INVALID_UNDO_PAGID;
    undo->segment->page_list.last = INVALID_UNDO_PAGID;
    undo->segment->txn_page_count = 0;

    log_put(session, RD_UNDO_CREATE_SEGMENT, CURR_PAGE(session), sizeof(page_head_t), LOG_ENTRY_FLAG_NONE);
    log_append_data(session, undo->segment, sizeof(undo_segment_t));
    buf_leave_page(session, CT_TRUE);
}

/*
 * create and init an undo segment during undo create
 * @param kernel session, undo segment id
 * @note we use space alloc extent interface to catch error
 */
static status_t undo_create_segment(knl_session_t *session, space_t *space, undo_t *undo, uint32 id)
{
    page_id_t page_id;

    log_atomic_op_begin(session);

    if (CT_SUCCESS != spc_alloc_extent(session, space, space->ctrl->extent_size, &page_id, CT_FALSE)) {
        CT_THROW_ERROR(ERR_ALLOC_EXTENT, space->ctrl->name);
        log_atomic_op_end(session);
        return CT_ERROR;
    }

    undo_create_segment_impl(session, space, undo, id, &page_id);

    log_atomic_op_end(session);

    return CT_SUCCESS;
}

static status_t undo_df_create_segment(knl_session_t *session, space_t *space, undo_t *undo, uint32 id, datafile_t *df)
{
    page_id_t page_id;

    log_atomic_op_begin(session);

    if (CT_SUCCESS != spc_df_alloc_extent(session, space, space->ctrl->extent_size, &page_id, df)) {
        CT_THROW_ERROR(ERR_ALLOC_EXTENT, space->ctrl->name);
        log_atomic_op_end(session);
        return CT_ERROR;
    }

    undo_create_segment_impl(session, space, undo, id, &page_id);

    log_atomic_op_end(session);

    return CT_SUCCESS;
}

static void undo_get_stat_records(knl_session_t *session, undo_context_t *ctx, undo_stat_t *undo_stat)
{
    uint32 i;
    undo_t *undo = NULL;
    uint64 buf_busy_wait = 0;
    uint32 page_list_cnt = 0;
    uint32 stat_cnt = ctx->stat_cnt % CT_MAX_UNDO_STAT_RECORDS;

    if (ctx->stat_cnt == 0) {
        undo_stat->begin_time = cm_now();
    } else if (stat_cnt == 0) {
        undo_stat->begin_time = ctx->stat[CT_MAX_UNDO_STAT_RECORDS - 1].end_time;
    } else {
        undo_stat->begin_time = ctx->stat[stat_cnt - 1].end_time;
    }

    undo_stat->end_time = cm_now();
    for (i = 0; i < UNDO_SEGMENT_COUNT(session); i++) {
        undo = &ctx->undos[i];
        undo_stat->total_undo_pages += undo->segment->page_list.count;
        undo_stat->reuse_expire_pages += undo->stat.reuse_expire_pages;
        undo_stat->reuse_unexpire_pages += undo->stat.reuse_unexpire_pages;
        undo_stat->use_space_pages += undo->stat.use_space_pages;
        undo_stat->steal_expire_pages += undo->stat.steal_expire_pages;
        undo_stat->steal_unexpire_pages += undo->stat.steal_unexpire_pages;
        undo_stat->txn_cnts += undo->stat.txn_cnts;
        undo_stat->total_buf_busy_waits += undo->stat.buf_busy_waits;
        if ((undo->stat.buf_busy_waits > buf_busy_wait) || (undo->segment->page_list.count > page_list_cnt)) {
            buf_busy_wait = undo->stat.buf_busy_waits;
            page_list_cnt = undo->segment->page_list.count;
            undo_stat->busy_wait_segment = i;
        }
    }

    undo = &ctx->undos[undo_stat->busy_wait_segment];
    undo_stat->busy_seg_pages = undo->segment->page_list.count;
    undo_stat->longest_sql_time = ctx->longest_sql_time;

    return;
}

static void undo_set_stat_records(undo_context_t *ctx, undo_stat_t undo_stat)
{
    uint32 stat_cnt = ctx->stat_cnt % CT_MAX_UNDO_STAT_RECORDS;

    ctx->stat[stat_cnt].begin_time = undo_stat.begin_time;
    ctx->stat[stat_cnt].end_time = undo_stat.end_time;
    ctx->stat[stat_cnt].total_undo_pages = undo_stat.total_undo_pages;
    ctx->stat[stat_cnt].reuse_expire_pages = undo_stat.reuse_expire_pages;
    ctx->stat[stat_cnt].reuse_unexpire_pages = undo_stat.reuse_unexpire_pages;
    ctx->stat[stat_cnt].use_space_pages = undo_stat.use_space_pages;
    ctx->stat[stat_cnt].steal_expire_pages = undo_stat.steal_expire_pages;
    ctx->stat[stat_cnt].steal_unexpire_pages = undo_stat.steal_unexpire_pages;
    ctx->stat[stat_cnt].txn_cnts = undo_stat.txn_cnts;
    ctx->stat[stat_cnt].longest_sql_time = undo_stat.longest_sql_time;
    ctx->stat[stat_cnt].total_buf_busy_waits = undo_stat.total_buf_busy_waits;
    ctx->stat[stat_cnt].busy_wait_segment = undo_stat.busy_wait_segment;
    ctx->stat[stat_cnt].busy_seg_pages = undo_stat.busy_seg_pages;

    ctx->stat_cnt++;
    if (ctx->stat_cnt >= CT_MAX_UNDO_STAT_RECORDS) {
        ctx->stat_cnt = ctx->stat_cnt % CT_MAX_UNDO_STAT_RECORDS + CT_MAX_UNDO_STAT_RECORDS;
    }

    return;
}

void undo_timed_task(knl_session_t *session)
{
    uint32 i;
    undo_context_t *ctx = &session->kernel->undo_ctx;
    uint32 stat_cnt = ctx->stat_cnt % CT_MAX_UNDO_STAT_RECORDS;
    undo_stat_t stat = {0};

    /* undo statistics snap every 10 minutes */
    undo_get_stat_records(session, ctx, &stat);
    cm_spin_lock(&ctx->stat[stat_cnt].lock, NULL);
    undo_set_stat_records(ctx, stat);
    cm_spin_unlock(&ctx->stat[stat_cnt].lock);

    ctx->longest_sql_time = 0;
    for (i = 0; i < UNDO_SEGMENT_COUNT(session); i++) {
        undo_t *undo = &ctx->undos[i];
        MEMS_RETVOID_IFERR(memset_sp(&undo->stat, sizeof(undo_seg_stat_t), 0, sizeof(undo_seg_stat_t)));
        undo->stat.begin_time = cm_now();
    }

    return;
}

/*
 * init undo pages for the specified undo segment during undo pre-load
 * @param kernel session, undo segment id, number of init pages
 */
static void undo_init_segment(knl_session_t *session, uint32 id, uint32 init_pages)
{
    undo_context_t *ctx = &session->kernel->undo_ctx;
    undo_t *undo = &ctx->undos[id];

    rd_undo_fmt_page_t redo;
    page_id_t page_id;
    uint32 extent_size;
    uint32 i;

    for (;;) {
        log_atomic_op_begin(session);

        buf_enter_page(session, PAGID_U2N(undo->entry), LATCH_MODE_X, ENTER_PAGE_RESIDENT);

        if (undo->segment->page_list.count >= init_pages) {
            buf_leave_page(session, CT_FALSE);
            log_atomic_op_end(session);
            return;
        }

        if (!spc_alloc_undo_extent(session, ctx->space, &page_id, &extent_size)) {
            buf_leave_page(session, CT_FALSE);
            log_atomic_op_end(session);
            return;
        }

        for (i = 0; i < extent_size; i++) {
            buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_NO_READ);
            undo_format_page(session, (undo_page_t *)CURR_PAGE(session), page_id, INVALID_UNDO_PAGID,
                             undo->segment->page_list.first);
            redo.page_id = PAGID_N2U(page_id);
            redo.prev = g_invalid_undo_pagid;
            redo.next = undo->segment->page_list.first;
            log_put(session, RD_UNDO_FORMAT_PAGE, &redo, sizeof(rd_undo_fmt_page_t), LOG_ENTRY_FLAG_NONE);
            buf_leave_page(session, CT_TRUE);

            undo->segment->page_list.first = PAGID_N2U(page_id);
            if (undo->segment->page_list.count == 0) {
                undo->segment->page_list.last = undo->segment->page_list.first;
            }
            undo->segment->page_list.count++;
            page_id.page++;
        }

        log_put(session, RD_UNDO_CHANGE_SEGMENT, &undo->segment->page_list, sizeof(undo_page_list_t),
            LOG_ENTRY_FLAG_NONE);
        buf_leave_page(session, CT_TRUE);

        log_atomic_op_end(session);
    }

    MEMS_RETVOID_IFERR(memset_sp(&undo->stat, sizeof(undo_seg_stat_t), 0, sizeof(undo_seg_stat_t)));
    undo->stat.begin_time = cm_now();

    return;
}

/*
 * warm up the undo space by init some undo pages for each undo segment
 */
void undo_preload_proc(thread_t *thread)
{
    knl_session_t *session = (knl_session_t *)thread->argument;
    undo_context_t *ctx = &session->kernel->undo_ctx;
    uint64 total_pages;
    uint32 init_pages;
    uint32 i;

    cm_set_thread_name("undo preload");
    CT_LOG_RUN_INF("undo preload thread started");
    KNL_SESSION_SET_CURR_THREADID(session, cm_get_current_thread_id());
    knl_qos_begin(session);

    total_pages = spc_count_pages(session, ctx->space, CT_FALSE);
    init_pages = UNDO_INIT_PAGES(session, total_pages);

    for (i = 0; i < UNDO_SEGMENT_COUNT(session); i++) {
        undo_init_segment(session, i, init_pages);
    }

    knl_qos_end(session);

    CT_LOG_RUN_INF("undo preload thread closed");
    KNL_SESSION_CLEAR_THREADID(session);
}

/*
 * undo pre-load thread
 * @note only called after the first startup after database create
 */
status_t undo_preload(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    undo_context_t *ctx = &kernel->undo_ctx;

    if (CT_SUCCESS != cm_create_thread(undo_preload_proc, 0, kernel->sessions[SESSION_ID_UNDO], &ctx->thread)) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

/*
 * undo create interface
 */
status_t undo_create(knl_session_t *session, uint32 inst_id, uint32 space_id, uint32 lseg_no, uint32 count)
{
    undo_set_t *undo_set = UNDO_SET(session, inst_id);
    undo_t *undo = NULL;
    uint32 i;
    uint32 j;
    space_t *space = SPACE_GET(session, space_id);

    for (i = lseg_no; i < count; i++) {
        undo = &undo_set->undos[i];
        if (CT_SUCCESS != undo_create_segment(session, space, undo, i)) {
            return CT_ERROR;
        }

        for (j = 0; j < UNDO_DEF_TXN_PAGE(session); j++) {
            if (CT_SUCCESS != undo_extend_txn(session, space, undo)) {
                return CT_ERROR;
            }
        }
    }

    return CT_SUCCESS;
}

status_t temp_undo_create(knl_session_t *session, uint32 inst_id, uint32 space_id, uint32 lseg_no, uint32 count)
{
    undo_set_t *temp_undo_set = TEMP_UNDO_SET(session, inst_id);
    undo_t *undo = NULL;
    uint32 i;
    uint32 j;
    space_t *space = SPACE_GET(session, space_id);

    for (i = lseg_no; i < count; i++) {
        undo = &temp_undo_set->undos[i];
        if (CT_SUCCESS != undo_create_segment(session, space, undo, i)) {
            return CT_ERROR;
        }

        for (j = 0; j < UNDO_DEF_TXN_PAGE(session); j++) {
            if (CT_SUCCESS != undo_extend_txn(session, space, undo)) {
                return CT_ERROR;
            }
        }
    }

    return CT_SUCCESS;
}

status_t undo_df_create(knl_session_t *session, uint32 space_id, uint32 lseg_no, uint32 count, datafile_t *df)
{
    undo_context_t *ctx = &session->kernel->undo_ctx;
    undo_t *undo = NULL;
    uint32 i;
    uint32 j;
    ctx->space = SPACE_GET(session, space_id);

    for (i = lseg_no; i < count; i++) {
        undo = &ctx->undos[i];
        if (CT_SUCCESS != undo_df_create_segment(session, ctx->space, undo, i, df)) {
            return CT_ERROR;
        }

        for (j = 0; j < UNDO_DEF_TXN_PAGE(session); j++) {
            if (CT_SUCCESS != undo_df_extend_txn(session, ctx->space, undo, df)) {
                return CT_ERROR;
            }
        }
    }

    return CT_SUCCESS;
}

/*
 * extend undo pages for the specified undo segment
 * As we use space alloc undo extent, we may get a normal extent allocated from space hwm
 * or an undo page allocated from space free undo page lists. Here, we skip the last
 * allocated page which would be inited by the caller, and format the rest undo pages and
 * link the rest undo pages to undo segment.
 * @param kernel session, undo, allocated undo page id (output param), extent size (output param)
 * @note when extend segment failed, we don't throw an error, the caller would take other
 * undo strategies into consideration.
 */
static bool32 undo_extend_segment(knl_session_t *session, undo_page_list_t *page_list, space_t *space,
    page_id_t *page_id, uint32 *extent_size)
{
    uint32 i;

    knl_begin_session_wait(session, UNDO_EXTEND_SEGMENT, CT_FALSE);
    if (!spc_alloc_undo_extent(session, space, page_id, extent_size)) {
        knl_end_session_wait(session, UNDO_EXTEND_SEGMENT);
        return CT_FALSE;
    }
    knl_end_session_wait(session, UNDO_EXTEND_SEGMENT);

    for (i = 0; i < *extent_size - 1; i++) {
        buf_enter_page(session, *page_id, LATCH_MODE_X, ENTER_PAGE_NO_READ);
        undo_format_page(session, (undo_page_t *)CURR_PAGE(session), *page_id, INVALID_UNDO_PAGID, page_list->first);

        if (SPACE_IS_LOGGING(space)) {
            rd_undo_fmt_page_t redo;

            redo.page_id = PAGID_N2U(*page_id);
            redo.prev = INVALID_UNDO_PAGID;
            redo.next = page_list->first;
            log_put(session, RD_UNDO_FORMAT_PAGE, &redo, sizeof(rd_undo_fmt_page_t), LOG_ENTRY_FLAG_NONE);
        }

        buf_leave_page(session, CT_TRUE);

        page_list->first = PAGID_N2U(*page_id);
        if (page_list->count == 0) {
            page_list->last = page_list->first;
        }
        page_list->count++;
        page_id->page++;
    }

    if (*extent_size > 1) {
        if (SPACE_IS_LOGGING(space)) {
            log_put(session, RD_UNDO_CHANGE_SEGMENT, page_list, sizeof(undo_page_list_t), LOG_ENTRY_FLAG_NONE);
        }

        /*
         * while extent_size > 1 means it is extended from datafile, for temp2_undo,
         * because of it has no recovery when restart,
         * and undo page in temp2_undo is not latest, so, it must be formated.
         */
        if (SPACE_IS_NOLOGGING(space)) {
            undo_page_t *page = NULL;

            buf_enter_page(session, *page_id, LATCH_MODE_X, ENTER_PAGE_NO_READ);
            page = (undo_page_t *)CURR_PAGE(session);
            undo_format_page(session, page, *page_id, INVALID_UNDO_PAGID, INVALID_UNDO_PAGID);
            buf_leave_page(session, CT_TRUE);
        }
    }

    return CT_TRUE;
}

static inline bool32 undo_shrink_need_suspend(knl_session_t *session)
{
    return db_in_switch(&session->kernel->switch_ctrl);
}

/*
 * shrink the specified undo segment
 * Shrink extra undo pages of the undo segment to undo space one by one.
 * If undo page count is less than reserve pages, just skip shrink.
 * During shrinking, we only shrink undo pages which exceed undo retention time.
 * @param kernel session, undo, reserved undo pages
 */
void undo_shrink_segment(knl_session_t *session, undo_t *undo, bool32 need_redo, uint32 reserve_pages)
{
    undo_context_t *ctx = &session->kernel->undo_ctx;
    undo_page_t *page = NULL;
    undo_page_list_t *page_list = NULL;
    space_t *space = NULL;
    undo_page_id_t first;
    undo_page_id_t next;
    uint32 i;
    uint64 begin_time = KNL_NOW(session);

    space = need_redo ? ctx->space : ctx->temp_space;

    if (space == NULL) {
        page_list = UNDO_GET_FREE_PAGELIST(undo, need_redo);
        knl_panic_log(page_list->count == 0, "undo shrink segment has free %llu pages, time consuming: %llu",
                      session->kernel->stat.undo_free_pages, session->kernel->stat.undo_shrink_times);
        return;
    }

    for (i = 0; i < UNDO_SHRINK_PAGES; i++) {
        if (undo_shrink_need_suspend(session)) {
            break;
        }

        log_atomic_op_begin(session);

        buf_enter_page(session, PAGID_U2N(undo->entry), LATCH_MODE_X, ENTER_PAGE_RESIDENT);
        page_list = UNDO_GET_FREE_PAGELIST(undo, need_redo);
        if (page_list->count <= reserve_pages) {
            buf_leave_page(session, CT_FALSE);
            log_atomic_op_end(session);
            return;
        }

        first = page_list->first;

        buf_enter_page(session, PAGID_U2N(first), LATCH_MODE_S, ENTER_PAGE_NORMAL);
        page = (undo_page_t *)CURR_PAGE(session);
        if (KNL_NOW(session) - page->ss_time < (date_t)ctx->retention * MICROSECS_PER_SECOND) {
            buf_leave_page(session, CT_FALSE);  // release undo page
            buf_leave_page(session, CT_FALSE);  // release entry page
            log_atomic_op_end(session);
            return;
        }

        next = PAGID_N2U(AS_PAGID(page->head.next_ext));
        buf_leave_page(session, CT_FALSE);

        page_list->count--;
        if (page_list->count > 0) {
            knl_panic_log(!IS_INVALID_PAGID(next), "undo shrink segment has free %llu pages, time consuming: %llu",
                          session->kernel->stat.undo_free_pages, session->kernel->stat.undo_shrink_times);
        }
        page_list->first = next;

        if (need_redo) {
            log_put(session, RD_UNDO_CHANGE_SEGMENT, page_list, sizeof(undo_page_list_t), LOG_ENTRY_FLAG_NONE);
        }

        buf_leave_page(session, CT_TRUE && need_redo);

        spc_free_extent(session, space, PAGID_U2N(first));

        log_atomic_op_end(session);

        session->kernel->stat.undo_free_pages++;
        session->kernel->stat.undo_shrink_times += (KNL_NOW(session) - begin_time);
    }
}

/*
 * shrink page_list of all undo segment
 */
void undo_shrink_inactive_segments(knl_session_t *session)
{
    undo_context_t *ctx = &session->kernel->undo_ctx;
    undo_t *undo = NULL;
    uint32 i;
    uint32 active_segment = session->kernel->attr.undo_active_segments;
    uint64 begin_time = KNL_NOW(session);

    for (i = active_segment; i < UNDO_SEGMENT_COUNT(session); i++) {
        undo = &ctx->undos[i];

        log_atomic_op_begin(session);
        buf_enter_page(session, PAGID_U2N(undo->entry), LATCH_MODE_X, ENTER_PAGE_RESIDENT);

        if (undo->segment->page_list.count == 0) {
            buf_leave_page(session, CT_FALSE);
            log_atomic_op_end(session);
            continue;
        }

        spc_free_undo_extents(session, ctx->space, &undo->segment->page_list);

        undo->segment->page_list.count = 0;
        undo->segment->page_list.first = g_invalid_undo_pagid;
        undo->segment->page_list.last = g_invalid_undo_pagid;

        log_put(session, RD_UNDO_CHANGE_SEGMENT, &undo->segment->page_list,
            sizeof(undo_page_list_t), LOG_ENTRY_FLAG_NONE);
        buf_leave_page(session, CT_TRUE);

        log_atomic_op_end(session);

        session->kernel->stat.undo_free_pages++;
        session->kernel->stat.undo_shrink_times += (KNL_NOW(session) - begin_time);
    }
}

/*
 * undo shrink interface
 * @note only cyclically caller by SMON thread
 */
void undo_shrink_segments(knl_session_t *session)
{
    undo_context_t *ctx = &session->kernel->undo_ctx;
    undo_t *undo = NULL;
    uint64 undo1_total_pages;  // for UNDO tablespace
    uint32 undo1_reserve_pages;
    uint64 undo2_total_pages;  // for UNDO2 tablespace
    uint32 undo2_reserve_pages;
    uint32 i;

    undo1_total_pages = spc_count_pages(session, ctx->space, CT_FALSE);
    undo1_reserve_pages = UNDO_RESERVE_PAGES(session, undo1_total_pages);

    undo2_total_pages = (ctx->temp_space == NULL) ? 0 : spc_count_pages(session, ctx->temp_space, CT_FALSE);
    undo2_reserve_pages = UNDO_RESERVE_TEMP_PAGES(session, undo2_total_pages);

    for (i = 0; i < UNDO_SEGMENT_COUNT(session); i++) {
        undo = &ctx->undos[i];
        undo_shrink_segment(session, undo, CT_TRUE, undo1_reserve_pages);
        undo_shrink_segment(session, undo, CT_FALSE, undo2_reserve_pages);
    }
}

/*
 * find the undo segment which holds the most undo pages
 * @param kernel session, undo pointer
 */
bool32 undo_find_free_segment(knl_session_t *session, bool32 need_redo, undo_t **undo)
{
    undo_context_t *ctx = &session->kernel->undo_ctx;
    uint32 page_count = 0;
    undo_t *curr = NULL;
    uint32 i;
    undo_page_list_t *page_list = NULL;

    for (i = 0; i < UNDO_SEGMENT_COUNT(session); i++) {
        if (i == UNDO_GET_SESSION_UNDO_SEGID(session)) {
            continue;  // skip current session
        }

        curr = &ctx->undos[i];
        buf_enter_page(session, PAGID_U2N(curr->entry), LATCH_MODE_S, ENTER_PAGE_RESIDENT);

        page_list = UNDO_GET_FREE_PAGELIST(curr, need_redo);
        if (page_count < page_list->count) {
            page_count = page_list->count;
            *undo = curr;
        }

        buf_leave_page(session, CT_FALSE);
    }

    if (page_count == 0) {
        return CT_FALSE;
    }

    return CT_TRUE;
}

static void undo_force_shrink_pages(knl_session_t *session, undo_page_list_t *page_list,
    undo_page_list_t *shrink_pages, undo_t *undo_need_shrink, bool32 need_redo)
{
    uint32 i;
    undo_page_t *page = NULL;
    undo_page_id_t last;
    undo_page_id_t next;
    uint32 page_count;
    undo_context_t *ctx = &session->kernel->undo_ctx;
    undo_t *undo = UNDO_GET_SESSION_UNDO_SEGMENT(session);

    page_count = MIN(page_list->count, CT_EXTENT_SIZE);
    next = page_list->first;
    for (i = 0; i < page_count; i++) {
        last = next;
        buf_enter_page(session, PAGID_U2N(last), LATCH_MODE_S, ENTER_PAGE_NORMAL);
        page = (undo_page_t *)CURR_PAGE(session);
        if (KNL_NOW(session) - page->ss_time < (date_t)ctx->retention * MICROSECS_PER_SECOND) {
            undo->stat.steal_unexpire_pages++;
            undo_need_shrink->stat.stealed_unexpire_pages++;
        } else {
            undo->stat.steal_expire_pages++;
            undo_need_shrink->stat.stealed_expire_pages++;
        }
        next = PAGID_N2U(AS_PAGID(((page_head_t *)CURR_PAGE(session))->next_ext));
        buf_leave_page(session, CT_FALSE);
    }

    shrink_pages->count = page_count;
    shrink_pages->first = page_list->first;
    shrink_pages->last = last;

    page_list->count -= page_count;
    page_list->first = next;

    if (need_redo) {
        log_put(session, RD_UNDO_CHANGE_SEGMENT, page_list, sizeof(undo_page_list_t), LOG_ENTRY_FLAG_NONE);
    }

    return;
}

/*
 * force to shrink undo pages from other undo segment to ours
 * In force mode, it means that we don't care about the undo retention time,
 * we don't care about the reserved pages. The only thing we care is that
 * we should shrink a normal extent from the undo segment which holds the
 * most free undo pages to our undo segment *directly*.
 */
static bool32 undo_force_shrink_segment(knl_session_t *session, undo_context_t *ctx, bool32 need_redo)
{
    undo_t *undo_need_shrink = NULL;
    undo_t *undo = UNDO_GET_SESSION_UNDO_SEGMENT(session);
    undo_page_list_t shrink_pages;
    uint32 page_count;
    undo_page_list_t *page_list = NULL;
    uint64 begin_time = KNL_NOW(session);

    if (!undo_find_free_segment(session, need_redo, &undo_need_shrink)) {
        // All segments are busy, failed to force shrink.
        return CT_FALSE;
    }

    if (!cm_latch_timed_x(&ctx->latch, session->id, 100, NULL)) {
        return CT_TRUE;
    }

    log_atomic_op_begin(session);

    buf_enter_page(session, PAGID_U2N(undo_need_shrink->entry), LATCH_MODE_X, ENTER_PAGE_RESIDENT);

    page_list = UNDO_GET_FREE_PAGELIST(undo_need_shrink, need_redo);
    if (page_list->count == 0) {
        // All segments are busy, failed to force shrink.
        buf_leave_page(session, CT_FALSE);
        log_atomic_op_end(session);
        cm_unlatch(&ctx->latch, NULL);
        return CT_FALSE;
    }

    page_count = MIN(page_list->count, CT_EXTENT_SIZE);
    undo_force_shrink_pages(session, page_list, &shrink_pages, undo_need_shrink, need_redo);
    buf_leave_page(session, CT_TRUE && need_redo);

    undo_release_pages(session, undo, &shrink_pages, need_redo);
    log_atomic_op_end(session);

    cm_unlatch(&ctx->latch, NULL);

    session->kernel->stat.undo_free_pages += page_count;
    session->kernel->stat.undo_shrink_times += (KNL_NOW(session) - begin_time);

    return CT_TRUE;
}

bool32 undo_check_active_transaction(knl_session_t *session)
{
    undo_context_t *ctx = &session->kernel->undo_ctx;
    undo_t *undo = NULL;
    uint32 seg_no;

    for (seg_no = 0; seg_no < UNDO_SEGMENT_COUNT(session); seg_no++) {
        undo = &ctx->undos[seg_no];

        if (undo->free_items.count != TXN_PER_PAGE(session) * UNDO_DEF_TXN_PAGE(session)) {
            return CT_TRUE;
        }
    }

    return CT_FALSE;
}

void undo_get_txn_hwms(knl_session_t *session, space_t *space, uint32 *hwms)
{
    undo_context_t *ctx = &session->kernel->undo_ctx;
    undo_t *undo = NULL;
    uint32 i, j;
    undo_page_id_t ud_pageid;
    datafile_t  *df = NULL;

    for (i = 0; i < UNDO_SEGMENT_COUNT(session); i++) {
        undo = &ctx->undos[i];
        for (j = 0; j < undo->segment->txn_page_count; j++) {
            ud_pageid = undo->segment->txn_page[j];
            df = DATAFILE_GET(session, ud_pageid.file);
            if (ud_pageid.page >= hwms[df->file_no]) {
                hwms[df->file_no] = ud_pageid.page + 1;
            }
        }
    }
}

void undo_clean_segment_pagelist(knl_session_t *session, space_t *space)
{
    undo_context_t *ctx = &session->kernel->undo_ctx;
    undo_t *undo = NULL;
    undo_page_list_t *page_list = NULL;
    uint32 i;
    bool32 need_redo = SPACE_IS_LOGGING(space);
    
    for (i = 0; i < UNDO_SEGMENT_COUNT(session); i++) {
        undo = &ctx->undos[i];
        log_atomic_op_begin(session);

        buf_enter_page(session, PAGID_U2N(undo->entry), LATCH_MODE_X, ENTER_PAGE_RESIDENT);
        page_list = UNDO_GET_FREE_PAGELIST(undo, need_redo);
        page_list->count = 0;
        page_list->first = INVALID_UNDO_PAGID;
        page_list->last = INVALID_UNDO_PAGID;
        if (need_redo) {
            log_put(session, RD_UNDO_CHANGE_SEGMENT, page_list, sizeof(undo_page_list_t), LOG_ENTRY_FLAG_NONE);
        }

        buf_leave_page(session, CT_TRUE && need_redo);
        log_atomic_op_end(session);
    }
}

static inline bool32 undo_need_alloc_from_space(knl_session_t *session, undo_context_t *ctx, undo_page_t *page,
    uint32 reserved_size, uint8 cipher_reserve_size)
{
    if (page->free_size < reserved_size &&
        KNL_NOW(session) - page->ss_time < (date_t)ctx->retention * MICROSECS_PER_SECOND) {
        return CT_TRUE;
    }

     // if alloc normal undo page, cipher_reserve_size is 0,
     // if alloc undo page enable to encrypt, undo page should reserve cipher size behind undo_page_t,
    if (undo_cipher_reserve_valid(session, page, cipher_reserve_size)) {
        return CT_FALSE;
    }

    // if page has been formated, it still can be used for encryption, cipher reserve size will be added before use.
    if (undo_is_formated_page(session, page)) {
        return CT_FALSE;
    }

    return CT_TRUE;
}

static void undo_alloc_from_free_list(knl_session_t *session, space_t *space, undo_page_list_t *page_list,
    undo_page_t *page, undo_page_id_t next_page)
{
    undo_context_t *ctx = &session->kernel->undo_ctx;
    undo_t *undo = &ctx->undos[UNDO_GET_SESSION_UNDO_SEGID(session)];
    bool32 need_redo = SPACE_IS_LOGGING(space);

    if (KNL_NOW(session) - page->ss_time < (date_t)ctx->retention * MICROSECS_PER_SECOND) {
        undo->stat.reuse_unexpire_pages++;
    } else {
        undo->stat.reuse_expire_pages++;
    }

    page_list->count--;
    if (page_list->count == 0) {
        page_list->first = INVALID_UNDO_PAGID;
        page_list->last = INVALID_UNDO_PAGID;
    } else {
        knl_panic(!IS_INVALID_PAGID(next_page));
        page_list->first = next_page;
    }

    if (need_redo) {
        log_put(session, RD_UNDO_CHANGE_SEGMENT, page_list, sizeof(undo_page_list_t), LOG_ENTRY_FLAG_NONE);
    }

    return;
}

/*
 * alloc undo page interface
 * In undo alloc page, we use three hierarchical allocation strategies:
 * 1. Alloc page from undo segment page list which exceeds retention time.
 * 2. Alloc page from undo space.
 * 3. Alloc page from undo segment page list which does not exceed undo retention time.
 * @param kernel session, undo page reserved size, undo page id (output)
 */
bool32 undo_alloc_page(knl_session_t *session, space_t *space, uint32 reserved_size,
    uint8 cipher_reserve_size, page_id_t *page_id, bool32 *new_extent)
{
    undo_context_t *ctx = &session->kernel->undo_ctx;
    undo_t *undo = &ctx->undos[UNDO_GET_SESSION_UNDO_SEGID(session)];
    undo_page_t *page = NULL;
    undo_page_id_t next_page;
    uint32 extent_size;
    bool32 from_space = CT_FALSE;
    undo_page_list_t *page_list = NULL;
    bool32 need_redo = SPACE_IS_LOGGING(space);
    uint64 buf_busy_waits = 0;

    next_page = INVALID_UNDO_PAGID;
    if (STATS_ENABLE_MONITOR_TABLE(session)) {
        buf_busy_waits = session->stat_page.misses;
    }

    buf_enter_page(session, PAGID_U2N(undo->entry), LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    page_list = UNDO_GET_FREE_PAGELIST(undo, need_redo);
    if (page_list->count == 0) {
        from_space = CT_TRUE;
    } else {
        buf_enter_prefetch_page_num(session, PAGID_U2N(page_list->first), session->kernel->attr.undo_prefetch_page_num,
            LATCH_MODE_S, ENTER_PAGE_HIGH_AGE);
        page = (undo_page_t *)CURR_PAGE(session);
        next_page = PAGID_N2U(AS_PAGID(page->head.next_ext));
        from_space = undo_need_alloc_from_space(session, ctx, page, reserved_size, cipher_reserve_size);
        buf_leave_page(session, CT_FALSE);
    }

    if (from_space) {
        if (undo_extend_segment(session, page_list, space, page_id, &extent_size)) {
            *new_extent = extent_size > 1 ? CT_TRUE : CT_FALSE;
            buf_leave_page(session, *new_extent && need_redo);
            undo->stat.use_space_pages++;
            return CT_TRUE;
        }
    }

    if (STATS_ENABLE_MONITOR_TABLE(session)) {
        buf_busy_waits = session->stat_page.misses - buf_busy_waits;
        undo->stat.buf_busy_waits += buf_busy_waits;
    }

    if (page_list->count == 0) {
        buf_leave_page(session, CT_FALSE);
        return CT_FALSE;
    }

    *page_id = PAGID_U2N(page_list->first);
    undo_alloc_from_free_list(session, space, page_list, page, next_page);
    buf_leave_page(session, CT_TRUE && need_redo);

    return CT_TRUE;
}

/*
 * release undo pages to undo segment free page list
 * @param kernel session, undo, free undo page list
 */
void undo_release_pages(knl_session_t *session, undo_t *undo, undo_page_list_t *undo_pages, bool32 need_redo)
{
    undo_page_list_t *page_list = NULL;

    buf_enter_page(session, PAGID_U2N(undo->entry), LATCH_MODE_X, ENTER_PAGE_RESIDENT);

    page_list = UNDO_GET_FREE_PAGELIST(undo, need_redo);
    if (page_list->count == 0) {
        *page_list = *undo_pages;
    } else {
        spc_concat_extent(session, PAGID_U2N(page_list->last), PAGID_U2N(undo_pages->first));
        page_list->last = undo_pages->last;
        page_list->count += undo_pages->count;
    }

    if (need_redo) {
        log_put(session, RD_UNDO_CHANGE_SEGMENT, page_list, sizeof(undo_page_list_t), LOG_ENTRY_FLAG_NONE);
    }

    buf_leave_page(session, CT_TRUE && need_redo);
}

static inline void undo_page_encrypt_format(knl_session_t *session, undo_page_t *page, uint8 cipher_reserve_size,
    bool32 need_redo)
{
    page->free_size -= cipher_reserve_size;
    page->free_begin += cipher_reserve_size;
    if (need_redo) {
        rd_undo_cipher_reserve_t reserve_redo;

        reserve_redo.cipher_reserve_size = cipher_reserve_size;
        reserve_redo.unused = 0;
        reserve_redo.aligned = 0;
        log_put(session, RD_UNDO_CIPHER_RESERVE, &reserve_redo, sizeof(rd_undo_cipher_reserve_t), LOG_ENTRY_FLAG_NONE);
    }
}

static void trigger_undo_usage_alram_log(knl_session_t *session)
{
    xid_t xid = session->rm->xid;
    text_t sql_text;
    CM_SAVE_STACK(session->stack);
    sql_text.str = (char *)cm_push(session->stack, RECORD_SQL_SIZE);
    sql_text.len = RECORD_SQL_SIZE;
    if (sql_text.str == NULL || g_knl_callback.get_sql_text(session->id, &sql_text) != CT_SUCCESS) {
        CT_LOG_RUN_WAR("[TxnUndospaceUsage] session-id: %u, rmid: %u, transaction-id: %u.%u.%u, txn-alarm-threshold: %u%%, sql-detail: [fail to record sql]",
            session->id, session->rm->id, xid.xmap.seg_id, xid.xmap.slot, xid.xnum,
            session->kernel->attr.txn_undo_usage_alarm_threshold);
        cm_reset_error();
    } else {
        CT_LOG_RUN_WAR("[TxnUndospaceUsage] session-id: %u, rmid: %u, transaction-id: %u.%u.%u, txn-alarm-threshold: %u%%, sql-detail: [%s]",
            session->id, session->rm->id, xid.xmap.seg_id, xid.xmap.slot, xid.xnum,
            session->kernel->attr.txn_undo_usage_alarm_threshold, T2S(&sql_text));
    }
    CM_RESTORE_STACK(session->stack);
}

static inline void txn_undo_page_check(knl_session_t *session, uint32 undo_page_count)
{
    uint64 undo_total_pages = spc_count_pages_with_ext(session, session->kernel->undo_ctx.space, CT_FALSE);
    if (undo_page_count >= undo_total_pages * session->kernel->attr.txn_undo_usage_alarm_threshold / CT_MAX_TXN_UNDO_ALARM_THRESHOLD) {
        trigger_undo_usage_alram_log(session);
        session->rm->txn_alarm_enable = CT_FALSE;
    }
}

/*
 * allocate undo page for txn
 * Here, we use four hierarchical allocation strategies:
 * 1. Alloc undo page whose page free size satisfies with request size or
 *    page last change time exceed undo retention time from our undo segment.
 * 2. Alloc undo page from undo space, append the extra pages to undo segment.
 * 3. Force to alloc undo page from undo segment free page list if any.
 * 4. Try to shrink undo page from other undo segment directly if any.
 * After allocation, format the undo page, append it to txn undo page list.
 * @param kernel session, txn, txn reserved size
 * @note we may not format the undo page we just alloc if its free size
 * is over reserve size to keep the undo data as much as possible to avoid
 * snapshot too old error.
 */
status_t undo_alloc_page_for_txn(knl_session_t *session, txn_t *txn, uint32 reserve_size_input, bool32 need_redo,
    uint8 cipher_reserve_size)
{
    undo_context_t *ctx = &session->kernel->undo_ctx;
    knl_rm_t *rm = session->rm;
    undo_page_list_t *tx_undo_page_list = NULL;
    undo_page_info_t *curr_undo_page = NULL;
    undo_page_t *page = NULL;
    uint32 reserve_size = reserve_size_input;
    page_id_t page_id;
    undo_page_id_t txn_page_id;
    rd_undo_fmt_page_t fmt_redo;
    rd_undo_chg_page_t chg_redo;
    rd_undo_chg_txn_t redo;
    bool32 new_extent = CT_FALSE;
    space_t *space = need_redo ? ctx->space : ctx->temp_space;

    reserve_size = MAX(reserve_size, session->kernel->attr.undo_reserve_size);
    txn_get_owner(session, rm->xid.xmap, &txn_page_id);

    log_atomic_op_begin(session);

    buf_enter_page(session, PAGID_U2N(txn_page_id), LATCH_MODE_X, ENTER_PAGE_RESIDENT);

    for (;;) {
        if (undo_alloc_page(session, space, reserve_size, cipher_reserve_size, &page_id, &new_extent)) {
            break;
        }

        buf_leave_page(session, CT_FALSE);

        log_atomic_op_end(session);

        if (!undo_force_shrink_segment(session, ctx, need_redo)) {
            CT_THROW_ERROR(ERR_NO_FREE_UNDO_PAGE);
            return CT_ERROR;
        }

        log_atomic_op_begin(session);

        buf_enter_page(session, PAGID_U2N(txn_page_id), LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    }

    buf_enter_page(session, page_id, LATCH_MODE_X, new_extent ? ENTER_PAGE_NO_READ : ENTER_PAGE_NORMAL);
    page = (undo_page_t *)CURR_PAGE(session);

    if (need_redo) {
        tx_undo_page_list = &txn->undo_pages;
        curr_undo_page = &rm->undo_page_info;
    } else {
        tx_undo_page_list = &rm->noredo_undo_pages;
        curr_undo_page = &rm->noredo_undo_page_info;
    }

    if (!new_extent && page->free_size >= reserve_size &&
        undo_cipher_reserve_valid(session, page, cipher_reserve_size)) {
        TO_PAGID_DATA(INVALID_PAGID, page->head.next_ext);
        page->prev = tx_undo_page_list->last;
        page->begin_slot = page->rows;

        if (need_redo) {
            chg_redo.prev = page->prev;
            chg_redo.slot = page->begin_slot;
            chg_redo.aligned = 0;
            log_put(session, RD_UNDO_CHANGE_PAGE, &chg_redo, sizeof(rd_undo_chg_page_t), LOG_ENTRY_FLAG_NONE);
        }
    } else {
        undo_format_page(session, page, page_id, tx_undo_page_list->last, INVALID_UNDO_PAGID);
        if (need_redo) {
            fmt_redo.page_id = PAGID_N2U(page_id);
            fmt_redo.prev = tx_undo_page_list->last;
            fmt_redo.next = INVALID_UNDO_PAGID;
            log_put(session, RD_UNDO_FORMAT_PAGE, &fmt_redo, sizeof(rd_undo_fmt_page_t), LOG_ENTRY_FLAG_NONE);
        }

        if (cipher_reserve_size > 0) {
            undo_page_encrypt_format(session, page, cipher_reserve_size, need_redo);
        }
    }

    curr_undo_page->undo_rid.page_id = PAGID_N2U(page_id);
    curr_undo_page->undo_rid.slot = page->begin_slot;
    curr_undo_page->undo_fs = page->free_size;
    curr_undo_page->encrypt_enable = undo_valid_encrypt(session, (page_head_t *)page);

    buf_leave_page(session, CT_TRUE);

    if (tx_undo_page_list->count == 0) {
        tx_undo_page_list->first = PAGID_N2U(page_id);
        tx_undo_page_list->last = PAGID_N2U(page_id);
    } else {
        spc_concat_extent(session, PAGID_U2N(tx_undo_page_list->last), page_id);
        tx_undo_page_list->last = PAGID_N2U(page_id);
    }

    tx_undo_page_list->count++;

    if (need_redo) {
        redo.xmap = rm->xid.xmap;
        redo.undo_pages = *tx_undo_page_list;
        log_put(session, RD_UNDO_CHANGE_TXN, &redo, sizeof(rd_undo_chg_txn_t), LOG_ENTRY_FLAG_NONE);
    }

    buf_leave_page(session, CT_TRUE && need_redo);

    log_atomic_op_end(session);

    if (session->kernel->attr.txn_undo_usage_alarm_threshold != 0 && session->rm->txn_alarm_enable) {
        txn_undo_page_check(session, txn->undo_pages.count);
    }

    return CT_SUCCESS;
}

/*
 * prepare the undo page and begin transaction if necessary
 * If current undo page free size is enough, return success.
 * @param kernel session, undo count, total undo request size
 * need_redo flags if generate redo for undo
 */
status_t undo_multi_prepare(knl_session_t *session, uint32 count, uint32 size, bool32 need_redo, bool32 need_encrypt)
{
    undo_context_t *ctx = &session->kernel->undo_ctx;
    knl_rm_t *rm = session->rm;
    uint32 cost_size;
    uint32 undo_freespace;
    space_t *space = need_redo ? ctx->space : ctx->temp_space;
    bool32 encrypt_enable = CT_FALSE;
    uint8 cipher_reserve_size = need_encrypt ? space->ctrl->cipher_reserve_size : 0;

    if (DB_NOT_READY(session)) {
        return CT_SUCCESS;
    }

    if (!need_redo && ctx->temp_space == NULL) {
        CT_THROW_ERROR(ERR_NOLOGGING_SPACE, "TEMP2_UNDO");
        return CT_ERROR;
    }

    knl_panic_log(!DB_IS_READONLY(session), "current DB is readonly!");

    if (rm->txn == NULL) {
        if (tx_begin(session) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    cost_size = size + count * (UNDO_ROW_HEAD_SIZE + sizeof(uint16));
    if (cost_size > (uint32)(UNDO_PAGE_MAX_FREE_SIZE(session) - (uint16)cipher_reserve_size)) {
        CT_THROW_ERROR(ERR_RECORD_SIZE_OVERFLOW, "undo cost", cost_size,
            UNDO_PAGE_MAX_FREE_SIZE(session) - cipher_reserve_size);
        return CT_ERROR;
    }

    if (need_redo) {
        undo_freespace = rm->undo_page_info.undo_fs;
        encrypt_enable = rm->undo_page_info.encrypt_enable;
        rm->undo_page_info.undo_log_encrypt = need_encrypt;
    } else {
        undo_freespace = rm->noredo_undo_page_info.undo_fs;
        encrypt_enable = rm->noredo_undo_page_info.encrypt_enable;
        rm->noredo_undo_page_info.undo_log_encrypt = CT_FALSE;
    }

    if (encrypt_enable || !need_encrypt) {
        if (undo_freespace >= cost_size) {
            return CT_SUCCESS;
        }
    }
    knl_panic_log(rm->txn != NULL, "rm's txn is NULL.");
    return undo_alloc_page_for_txn(session, rm->txn, cost_size, need_redo, cipher_reserve_size);
}

static void undo_check_log_encrypt(knl_session_t *session, undo_page_t *page, space_t *space, bool32 need_redo)
{
    undo_page_info_t *undo_info = NULL;
    if (session->log_encrypt) {
        return;
    }

    if (need_redo) {
        undo_info = &session->rm->undo_page_info;
    } else {
        undo_info = &session->rm->noredo_undo_page_info;
    }

#ifdef LOG_DIAG
    knl_panic_log(undo_info->encrypt_enable == undo_valid_encrypt(session, (page_head_t *)page),
                  "undo's encrypt status is abnormal, panic info: page %u-%u type %u",
                  AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type);
#endif

    if (undo_info->undo_log_encrypt) {
        knl_panic_log(undo_info->encrypt_enable, "curr undo page must encryptable");
        session->log_encrypt = CT_TRUE;
    }
}

/*
 * undo write interface
 * Organize undo row with undo data, write undo row to current undo page.
 * @param kernel session, undo data
 */
void undo_write(knl_session_t *session, undo_data_t *undo_data, bool32 need_redo, bool32 nolog_insert)
{
    undo_page_t *page = NULL;
    undo_row_t *row = NULL;
    uint16 *slot = NULL;
    uint16 actual_size;
    undo_rowid_t undo_rid;
    undo_page_info_t *undo_page_info = UNDO_GET_PAGE_INFO(session, need_redo);
    errno_t ret;

    if (DB_NOT_READY(session)) {
        return;
    }
    knl_panic_log(!DB_IS_READONLY(session), "current DB is readonly!");

    undo_rid = undo_page_info->undo_rid;
    space_t *space = SPACE_GET(session, DATAFILE_GET(session, undo_rid.page_id.file)->space_id);

    buf_enter_page(session, PAGID_U2N(undo_rid.page_id), LATCH_MODE_X, ENTER_PAGE_NORMAL);
    page = (undo_page_t *)CURR_PAGE(session);

    undo_check_log_encrypt(session, page, space, need_redo);

    knl_panic_log(page->free_begin + page->free_size == UNDO_PAGE_FREE_END(session, page),
                  "the page's free size is abnormal, "
                  "panic info: page %u-%u type %u free_begin %u free_size %u free_end %u",
                  AS_PAGID(page->head.id).file,
                  AS_PAGID(page->head.id).page, page->head.type, page->free_begin, page->free_size,
                  UNDO_PAGE_FREE_END(session, page));
    knl_panic_log(undo_data->size + UNDO_ROW_HEAD_SIZE + sizeof(uint16) <= page->free_size,
        "the undo_data is abnormal, panic info: page %u-%u type %u undo_data size %u page's free_size %u",
        AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type, undo_data->size, page->free_size);
    
    row = (undo_row_t *)((char *)page + page->free_begin);
    row->type = undo_data->type;
    row->rowid = undo_data->rowid;
    row->data_size = undo_data->size;
    row->prev_page = undo_data->snapshot.undo_page;
    row->prev_slot = undo_data->snapshot.undo_slot;
    row->scn = undo_data->snapshot.scn;
    row->ssn = undo_data->ssn;
    row->xid = session->rm->xid;
    row->is_owscn = undo_data->snapshot.is_owscn;
    row->is_xfirst = undo_data->snapshot.is_xfirst;
    row->is_cleaned = 0;
    if (undo_data->snapshot.contain_subpartno) {
        row->contain_subpartno = CT_TRUE;
    }

    knl_panic_log(row->xid.value != CT_INVALID_ID64,
                  "the xid of row is invalid, panic info: page %u-%u type %u row xid %llu",
                  AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type, row->xid.value);
    knl_panic_log(undo_rid.slot == page->rows, "the undo_rid's slot is not match to page's rows, panic info: "
                  "page %u-%u type %u undo_rid slot %u page rows %u", AS_PAGID(page->head.id).file,
                  AS_PAGID(page->head.id).page, page->head.type, undo_rid.slot, page->rows);

    /* undo_data->size is less than page size(8192), the sum will not exceed max value of uint16 */
    actual_size = (uint16)(UNDO_ROW_HEAD_SIZE + undo_data->size);

    if (undo_data->size > 0) {
        ret = memcpy_sp(row->data, page->free_size, undo_data->data, undo_data->size);
        knl_securec_check(ret);
        if (session->delete_ptrans) {
            if (row->type == UNDO_HEAP_DELETE || row->type == UNDO_PCRH_DELETE) {
                row_head_t *ptrans_row = (row_head_t *)row->data;
                *(uint64 *)((char *)ptrans_row + ptrans_row->size - sizeof(uint64)) = session->xa_scn;
            }
        }
    }

    slot = UNDO_SLOT(session, page, page->rows);
    *slot = page->free_begin;

    /*
     * free_size less than DEFAULT_PAGE_SIZE(8192),
     * actual_size is less than page size(8192) + UNDO_ROW_HEAD_SIZE,
     * the sum is less than max value(65535) of uint16
     */
    page->free_begin += actual_size;
    page->free_size -= (actual_size + sizeof(uint16));
    page->ss_time = KNL_NOW(session);
    page->rows++;

    undo_page_info->undo_fs = page->free_size;
    undo_page_info->undo_rid.slot = page->rows;

    if (need_redo) {
        if (nolog_insert) {
            log_put(session, RD_UNDO_NOLOG_WRITE, &undo_data->size, sizeof(uint16), LOG_ENTRY_FLAG_NONE);
        } else {
            log_put(session, RD_UNDO_WRITE, &page->ss_time, sizeof(date_t), LOG_ENTRY_FLAG_NONE);
            log_append_data(session, row, actual_size);
        }
    }

    buf_leave_page(session, CT_TRUE);
}

status_t undo_segment_dump(knl_session_t *session, page_head_t *page_head, cm_dump_t *dump)
{
    undo_segment_t *segment = UNDO_GET_SEGMENT(session);

    cm_dump(dump, "undo segment information\n");
    cm_dump(dump, "\tpage lists: count %u first %u-%u last %u-%u\n", segment->page_list.count,
        segment->page_list.first.file, segment->page_list.first.page,
        segment->page_list.last.file, segment->page_list.last.page);
    cm_dump(dump, "\ttxn_page_count: %u\n", segment->txn_page_count);
    cm_dump(dump, "txn_page information on this page");
    CM_DUMP_WRITE_FILE(dump);

    for (uint32 slot = 0; slot < segment->txn_page_count; slot++) {
        if (slot % UNDO_PAGE_PER_LINE == 0) {
            cm_dump(dump, "\n\t");
        }
        cm_dump(dump, "%u-%u ", segment->txn_page[slot].file, segment->txn_page[slot].page);
        CM_DUMP_WRITE_FILE(dump);
    }

    return CT_SUCCESS;
}

void undo_invalid_segments(knl_session_t *session)
{
    undo_context_t *ctx = &session->kernel->undo_ctx;
    uint32 i, j;
    undo_t *undo = NULL;

    for (i = 0; i < UNDO_SEGMENT_COUNT(session); i++) {
        undo = &ctx->undos[i];
      
        for (j = 0; j < UNDO_DEF_TXN_PAGE(session); j++) {
            buf_unreside_page(session, PAGID_U2N(undo->segment->txn_page[j]));
        }
        buf_unreside_page(session, PAGID_U2N(undo->entry));
    }
}

void undo_move_txn(knl_session_t *session, undo_t *undo, uint32 id)
{
    txn_t *old_txn = NULL;
    txn_t *new_txn = NULL;
    txn_page_t *new_txnpage = NULL;
    txn_page_t *old_txnpage = NULL;

    log_atomic_op_begin(session);
    buf_enter_page(session, PAGID_U2N(undo->segment->txn_page[id]), LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    new_txnpage = (txn_page_t *)CURR_PAGE(session);
    old_txnpage = undo->txn_pages[id];

    for (uint32 i = 0; i < TXN_PER_PAGE(session); i++) {
        old_txn = &old_txnpage->items[i];
        new_txn = &new_txnpage->items[i];
        new_txn->scn = old_txn->scn;
        new_txn->xnum = old_txn->xnum;
    }

    log_put(session, RD_UNDO_MOVE_TXN, CURR_PAGE(session), sizeof(page_head_t), LOG_ENTRY_FLAG_NONE);
    log_append_data(session, new_txnpage->items, DEFAULT_PAGE_SIZE(session) - sizeof(page_head_t));
    buf_leave_page(session, CT_TRUE);
    log_atomic_op_end(session);
}

void undo_reload_segment(knl_session_t *session, page_id_t entry)
{
    undo_context_t *ctx = &session->kernel->undo_ctx;
    undo_page_id_t *undo_entry = NULL;
    undo_t *undo = NULL;

    buf_enter_page(session, entry, LATCH_MODE_S, ENTER_PAGE_RESIDENT);
    undo_entry = (undo_page_id_t *)(CURR_PAGE(session) + PAGE_HEAD_SIZE + sizeof(space_head_t));
    buf_leave_page(session, CT_FALSE);

    for (uint32 i = 0; i < UNDO_SEGMENT_COUNT(session); i++) {
        buf_enter_page(session, PAGID_U2N(undo_entry[i]), LATCH_MODE_S, ENTER_PAGE_RESIDENT | ENTER_PAGE_NO_READ);
        undo = &ctx->undos[i];
        undo->entry = undo_entry[i];
        undo->segment = UNDO_GET_SEGMENT(session);
        buf_leave_page(session, CT_FALSE);
    }
}

/*
* 1. create segment and alloc txn pages for new undo space
* 2. change undo segments of undo context in memory
* 3. move txn from old undo to new undo
* @param kernel session, undo, new undo space id
*/
static status_t undo_switch(knl_session_t *session, uint32 space_id)
{
    undo_context_t *ctx = &session->kernel->undo_ctx;
    undo_t *undos = ctx->undos;
    undo_t undo;
    space_t *space = SPACE_GET(session, space_id);
    uint32 i;
    uint32 j;

    for (i = 0; i < UNDO_SEGMENT_COUNT(session); i++) {
        if (CT_SUCCESS != undo_create_segment(session, space, &undo, i)) {
            return CT_ERROR;
        }

        for (j = 0; j < UNDO_DEF_TXN_PAGE(session); j++) {
            if (CT_SUCCESS != undo_extend_txn(session, space, &undo)) {
                return CT_ERROR;
            }
        }
    }

    undo_reload_segment(session, space->entry);

    for (i = 0; i < UNDO_SEGMENT_COUNT(session); i++) {
        for (j = 0; j < UNDO_DEF_TXN_PAGE(session); j++) {
            undo_move_txn(session, &undos[i], j);
        }
    }
    
    ctx->space = space;
    return CT_SUCCESS;
}

status_t undo_switch_space(knl_session_t *session, uint32 space_id)
{
    core_ctrl_t *core_ctrl = DB_CORE_CTRL(session);
    rd_switch_undo_space_t rd;
    space_t *space = NULL;
    space_t *old_undo_space = SPACE_GET(session, dtc_my_ctrl(session)->undo_space);
    space_t *new_undo_space = NULL;
    undo_set_t *undo_set = MY_UNDO_SET(session);

    knl_panic(0);  // TODO: need to design

    session->kernel->undo_ctx.is_switching = CT_TRUE;
    undo_invalid_segments(session);

    if (undo_switch(session, space_id) != CT_SUCCESS) {
        session->kernel->undo_ctx.space = old_undo_space;
        session->kernel->undo_ctx.is_switching = CT_FALSE;
        return CT_ERROR;
    }

    dtc_my_ctrl(session)->undo_space = space_id;

    undo_init(session, 0, core_ctrl->undo_segments);

    if (tx_area_init(session, 0, core_ctrl->undo_segments) != CT_SUCCESS) {
        session->kernel->undo_ctx.is_switching = CT_FALSE;
        return CT_ERROR;
    }

    tx_area_release(session, undo_set);

    space = SPACE_GET(session, space_id);
    
    new_undo_space = SPACE_GET(session, space_id);
    new_undo_space->ctrl->type = SPACE_TYPE_UNDO | SPACE_TYPE_DEFAULT;
    old_undo_space->ctrl->type = SPACE_TYPE_UNDO;
    new_undo_space->ctrl->cipher_reserve_size = old_undo_space->ctrl->cipher_reserve_size;
    new_undo_space->ctrl->encrypt_version = old_undo_space->ctrl->encrypt_version;
    session->kernel->undo_ctx.is_switching = CT_FALSE;

    rd.op_type = RD_SWITCH_UNDO_SPACE;
    rd.space_id = space_id;
    rd.space_entry = space->entry;
    log_put(session, RD_LOGIC_OPERATION, &rd, sizeof(rd_switch_undo_space_t), LOG_ENTRY_FLAG_NONE);
    knl_commit(session);
    ckpt_trigger(session, CT_TRUE, CKPT_TRIGGER_FULL);

    if (db_save_space_ctrl(session, old_undo_space->ctrl->id) != CT_SUCCESS) {
        CM_ABORT(0, "[DB] ABORT INFO: failed to save space ctrl file when load tablespace %s",
                 old_undo_space->ctrl->name);
    }

    if (db_save_space_ctrl(session, new_undo_space->ctrl->id) != CT_SUCCESS) {
        CM_ABORT(0, "[DB] ABORT INFO: failed to save space ctrl file when load tablespace %s",
                 new_undo_space->ctrl->name);
    }

    if (db_save_core_ctrl(session) != CT_SUCCESS) {
        CM_ABORT(0, "[DB] ABORT INFO: failed to save core ctrl file when load tablespace");
    }

    CT_LOG_RUN_INF("[UNDO] succeed to switch undo tablespace %s", new_undo_space->ctrl->name);
    return CT_SUCCESS;
}

uint32 undo_max_prepare_size(knl_session_t *session, uint32 count)
{
    return UNDO_PAGE_MAX_FREE_SIZE(session) - count * (UNDO_ROW_HEAD_SIZE + sizeof(uint16));
}

uint32 undo_part_locate_size(knl_handle_t knl_table)
{
    table_t *table = (table_t *)knl_table;

    if (!IS_PART_TABLE(table)) {
        return sizeof(uint32);
    }

    if (IS_COMPART_TABLE(table->part_table)) {
        return sizeof(knl_part_locate_t);
    } else {
        return sizeof(uint32);
    }
}
