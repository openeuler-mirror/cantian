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
 * pcr_heap_undo.c
 *
 *
 * IDENTIFICATION
 * src/kernel/table/pcr_heap_undo.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_log.h"
#include "knl_context.h"
#include "pcr_heap_scan.h"

static void pcrh_revert_r_ins(knl_session_t *session, rowid_t rid, bool32 is_xfirst, heap_page_t *cr_page)
{
    pcr_row_dir_t *dir = pcrh_get_dir(cr_page, (uint16)rid.slot);
    row_head_t *row = PCRH_GET_ROW(cr_page, dir);

    /* free directly if is last row */
    if (cr_page->free_begin == *dir + row->size) {
        cr_page->free_begin = *dir;
    }

    /* free directly if is last and new allocated dir */
    if (is_xfirst) {
        if ((uint16)rid.slot + 1 == cr_page->dirs) {
            /*
             * free_size and free_end both within DEFAULT_PAGE_SIZE,
             * sizeof(pcr_row_dir_t) is 2, so the sum less than max value(65535) of uint16.
             */
            cr_page->free_end += sizeof(pcr_row_dir_t);
            cr_page->free_size += sizeof(pcr_row_dir_t);
            cr_page->dirs--;
        } else {
            /* set dir to new dir with free mask, so that we can recycle later */
            *dir = PCRH_DIR_NEW_MASK | PCRH_DIR_FREE_MASK;
        }
    } else {
        *dir = PCRH_DIR_FREE_MASK;
    }

    /*
     * free_size less than DEFAULT_PAGE_SIZE, row size PCRH_MAX_ROW_SIZE,
     * the sum is less than max value(65535) of uint16
     */
    cr_page->free_size += row->size;
    cr_page->rows--;
}

/*
 * CR rollback function
 * revert an insert operation from undo
 * @param kernel session, CR page, itl, undo row
 */
static void pcrh_revert_ins(knl_session_t *session, heap_page_t *cr_page, pcr_itl_t *itl, undo_row_t *ud_row)
{
    rowid_t rid = ud_row->rowid;
    knl_panic_log(itl->xid.value == ud_row->xid.value, "the xid of itl and ud_row are not equal, panic info: "
                  "page %u-%u type %u itl xid %llu ud_row xid %llu", AS_PAGID(cr_page->head.id).file,
                  AS_PAGID(cr_page->head.id).page, cr_page->head.type, itl->xid.value, ud_row->xid.value);
    pcrh_revert_r_ins(session, rid, ud_row->is_xfirst, cr_page);
    itl->ssn = ud_row->ssn;
    itl->undo_page = ud_row->prev_page;
    itl->undo_slot = ud_row->prev_slot;
}

/*
 * CR rollback function
 * revert batch insert operation from undo
 * @param kernel session, CR page, itl, undo row
 */
static void pcrh_revert_batch_ins(knl_session_t *session, heap_page_t *cr_page, pcr_itl_t *itl,
    undo_row_t *ud_row)
{
    rowid_t rid;
    uint16 is_xfirst;
    pcrh_undo_batch_insert_t *batch_undo = (pcrh_undo_batch_insert_t *)ud_row->data;

    rid = ud_row->rowid;
    for (int32 i = batch_undo->count - 1; i >= 0; i--) {
        rid.slot = batch_undo->undos[i].slot;
        /* For compatibility reasons, we need to use ud_row->is_xfirst to decide which xfirst to use */
        is_xfirst = ud_row->is_xfirst ? ud_row->is_xfirst : batch_undo->undos[i].is_xfirst;
        pcrh_revert_r_ins(session, rid, is_xfirst, cr_page);
    }

    itl->ssn = ud_row->ssn;
    itl->undo_page = ud_row->prev_page;
    itl->undo_slot = ud_row->prev_slot;
}
    
/*
 * CR rollback function
 * reorganize a heap row by current row and undo update info
 * @param kernel session, current row, undo update info, origin row
 */
static void pcrh_reorganize_ud_upd(knl_session_t *session, row_head_t *row,
                                        heap_undo_update_info_t *undo_info, row_head_t *ori_row)
{
    knl_update_info_t info;
    row_assist_t ra;
    uint16 *offsets = NULL;
    uint16 *lens = NULL;
    rowid_t next_rid;
    uint16 col_size;
    errno_t ret;
    ra.is_csf = row->is_csf;

    CM_SAVE_STACK(session->stack);

    CM_PUSH_UPDATE_INFO(session, info);
    /* max value of max_column_count is GS_MAX_COLUMNS(4096) */
    offsets = (uint16 *)cm_push(session->stack, session->kernel->attr.max_column_count * sizeof(uint16));
    lens = (uint16 *)cm_push(session->stack, session->kernel->attr.max_column_count * sizeof(uint16));

    info.count = undo_info->count;
    /* info.count will not exceed GS_MAX_COLUMNS(4096), so col_size less than max value(65535) of uint16  */
    col_size = info.count * sizeof(uint16);
    if (col_size != 0) {
        ret = memcpy_sp(info.columns, (session)->kernel->attr.max_column_count * sizeof(uint16),
            undo_info->columns, col_size);
        knl_securec_check(ret);
    }

    info.data = (char *)undo_info + HEAP_UNDO_UPDATE_INFO_SIZE(info.count);
    cm_decode_row(info.data, info.offsets, info.lens, NULL);
    cm_decode_row((char *)row, offsets, lens, NULL);

    if (!row->is_migr) {
        pcrh_init_row(session, &ra, (char *)ori_row, undo_info->old_cols, ROW_ITL_ID(row), row->flags);
    } else {
        next_rid = *PCRH_NEXT_ROWID(row);
        pcrh_init_migr_row(session, &ra, (char *)ori_row, undo_info->old_cols, ROW_ITL_ID(row), row->flags, next_rid);
    }

    heap_reorganize_with_update(row, offsets, lens, &info, &ra);

    CM_RESTORE_STACK(session->stack);
}

/*
 * CR rollback function
 * We try to revert alloc itl and dir to free more space for revert update/delete.
 * Theoretically, it's safe to remove those dirs and itls now.
 * @param kernel session, CR page
 */
void pcrh_revert_alloc_space(knl_session_t *session, heap_page_t *page)
{
    pcr_row_dir_t *dir = NULL;
    pcr_itl_t *itl = NULL;
    char *src = NULL;
    char *dst = NULL;
    int16 slot;
    int8 id, count;
    errno_t ret;

    for (slot = (int16)(page->dirs - 1); slot >= 0; slot--) {
        dir = pcrh_get_dir(page, slot);
        if (!PCRH_DIR_IS_FREE(dir)) {
            break;
        }

        if (PCRH_DIR_IS_NEW(dir)) {
            /*
             * free_size and free_end both within DEFAULT_PAGE_SIZE, sizeof(pcr_row_dir_t) is 2,
             * so the sum less than max value(65535) of uint16
             */
            page->free_end += sizeof(pcr_row_dir_t);
            page->free_size += sizeof(pcr_row_dir_t);
            page->dirs--;
        }
    }

    count = 0;
    for (id = page->itls - 1; id >= 0; id--) {
        itl = pcrh_get_itl(page, id);
        if (itl->is_active || itl->scn != 0) {
            break;
        }
        count++;
    }

    if (count > 0) {
        if (page->dirs > 0) {
            src = (char *)page + page->free_end;
            dst = src + count * sizeof(pcr_itl_t);

            ret = memmove_s(dst, page->dirs * sizeof(pcr_row_dir_t), src, page->dirs * sizeof(pcr_row_dir_t));
            knl_securec_check(ret);
        }

        /*
         * free_size and free_end both within DEFAULT_PAGE_SIZE, sizeof(pcr_row_dir_t) is 2,
         * so the sum less than max value(65535) of uint16
         */
        page->free_end += count * sizeof(pcr_itl_t);
        page->free_size += count * sizeof(pcr_itl_t);
        page->itls -= (uint8)count;
    }
}

/*
 * CR rollback function
 * revert an update operation from undo
 * @note during rollback update, we may be need to compact current CR page to get an enough page space
 * to insert old row, if there is any space in itl fsc, just use it.
 * @param kernel session, CR page, itl, undo row
 */
static void pcrh_revert_upd(knl_session_t *session, heap_page_t *cr_page, pcr_itl_t *itl, undo_row_t *ud_row)
{
    rowid_t rid;
    pcr_row_dir_t *dir;
    row_head_t *row;
    row_head_t *ori_row = NULL;
    int16 inc_size;
    errno_t ret;

    rid = ud_row->rowid;

    dir = pcrh_get_dir(cr_page, (uint16)rid.slot);
    row = PCRH_GET_ROW(cr_page, dir);

    CM_SAVE_STACK(session->stack);

    if (ud_row->type == UNDO_PCRH_UPDATE_FULL) {
        ori_row = (row_head_t *)ud_row->data;
    } else {
        knl_panic_log(!row->is_link, "row is link, panic info: page %u-%u type %u", AS_PAGID(cr_page->head.id).file,
                      AS_PAGID(cr_page->head.id).page, cr_page->head.type);
        ori_row = (row_head_t *)cm_push(session->stack, PCRH_MAX_MIGR_SIZE(session));
        pcrh_reorganize_ud_upd(session, row, (heap_undo_update_info_t *)ud_row->data, ori_row);
    }

    inc_size = ori_row->size - row->size;

    if (inc_size > 0) {
        if (cr_page->free_size < inc_size) {
            pcrh_revert_alloc_space(session, cr_page);
            dir = pcrh_get_dir(cr_page, (uint16)rid.slot);
            row = PCRH_GET_ROW(cr_page, dir);
        }

        if (cr_page->free_end - cr_page->free_begin < ori_row->size) {
            *dir |= PCRH_DIR_FREE_MASK;
            pcrh_compact_page(session, cr_page);
        }

        *dir = cr_page->free_begin;
        /*
         * free_begin less than DEFAULT_PAGE_SIZE, row size less than PCRH_MAX_ROW_SIZE,
         * the sum is less than max value(65535) of uint16
         */
        cr_page->free_begin += ori_row->size;
        cr_page->free_size -= inc_size;
        knl_panic_log(cr_page->free_begin <= cr_page->free_end, "cr_page's free size begin is bigger than end, panic "
                      "info: free_begin %u free_end %u page %u-%u type %u", cr_page->free_begin, cr_page->free_end,
                      AS_PAGID(cr_page->head.id).file, AS_PAGID(cr_page->head.id).page, cr_page->head.type);

        /* relocate the row position */
        row = PCRH_GET_ROW(cr_page, dir);
    } else {
        /* inc_size is negative and the ads value of inc_size is less than page size(8192) */
        cr_page->free_size -= inc_size;
    }

    ret = memcpy_sp(row, DEFAULT_PAGE_SIZE(session) - *dir, (char *)ori_row, ori_row->size);
    knl_securec_check(ret);

    if (ud_row->is_xfirst) {
        ROW_SET_ITL_ID(row, GS_INVALID_ID8);
    }

    CM_RESTORE_STACK(session->stack);

    itl->ssn = ud_row->ssn;
    itl->undo_page = ud_row->prev_page;
    itl->undo_slot = ud_row->prev_slot;
}

/*
 * CR rollback function
 * revert an delete operation from undo
 * @note delete rollback update, we may be need to compact current CR page, because the deleted space would
 * be used after the delete operation, if there is any space in itl fsc, just use it.
 * @param kernel session, CR page, itl, undo row
 */
static void pcrh_revert_del(knl_session_t *session, heap_page_t *cr_page, pcr_itl_t *itl, undo_row_t *ud_row)
{
    row_head_t *row = NULL;

    rowid_t rid = ud_row->rowid;
    row_head_t *ori_row = (row_head_t *)ud_row->data;

    pcr_row_dir_t *dir = pcrh_get_dir(cr_page, (uint16)rid.slot);
    if (!PCRH_DIR_IS_FREE(dir)) {
        row = PCRH_GET_ROW(cr_page, dir);
        if (row->size == ori_row->size) {
            /* deleted row has not been compacted, we can rollback directly */
            row->is_deleted = 0;
        } else {
            /* row has been compact, we should find a new space in page to revert delete */
            knl_panic_log(row->size == sizeof(row_head_t),
                "row size is abnormal, panic info: page %u-%u type %u row_size %u", AS_PAGID(cr_page->head.id).file,
                AS_PAGID(cr_page->head.id).page, cr_page->head.type, row->size);

            row = NULL;
        }

        /* current row is deleted, the remained size can free to CR page */
        cr_page->free_size += sizeof(row_head_t);
    }

    if (row == NULL) {
        if (cr_page->free_size < ori_row->size) {
            pcrh_revert_alloc_space(session, cr_page);
            dir = pcrh_get_dir(cr_page, (uint16)rid.slot);
            row = PCRH_GET_ROW(cr_page, dir);
        }

        if (cr_page->free_end - cr_page->free_begin < ori_row->size) {
            *dir |= PCRH_DIR_FREE_MASK;
            pcrh_compact_page(session, cr_page);
        }

        *dir = cr_page->free_begin;
        /*
         * free_begin less than DEFAULT_PAGE_SIZE, row size PCRH_MAX_ROW_SIZE,
         * the sum is less than max value(65535) of uint16
         */
        cr_page->free_begin += ori_row->size;
        knl_panic_log(cr_page->free_begin <= cr_page->free_end, "cr_page's free size begin is bigger than end, panic "
                      "info: free_begin %u free_end %u page %u-%u type %u", cr_page->free_begin, cr_page->free_end,
                      AS_PAGID(cr_page->head.id).file, AS_PAGID(cr_page->head.id).page, cr_page->head.type);

        /* relocate the row position */
        row = PCRH_GET_ROW(cr_page, dir);
        errno_t ret = memcpy_sp(row, DEFAULT_PAGE_SIZE(session) - *dir, ori_row, ori_row->size);
        knl_securec_check(ret);
    }

    if (ud_row->is_xfirst) {
        ROW_SET_ITL_ID(row, GS_INVALID_ID8);
    }

    knl_panic_log(cr_page->free_size >= row->size, "cr_page's free_size is smaller than row's size, panic info: "
                  "page %u-%u type %u free_size %u row size %u", AS_PAGID(cr_page->head.id).file,
                  AS_PAGID(cr_page->head.id).page, cr_page->head.type, cr_page->free_size, row->size);
    cr_page->free_size -= row->size;
    cr_page->rows++;

    itl->ssn = ud_row->ssn;
    itl->undo_page = ud_row->prev_page;
    itl->undo_slot = ud_row->prev_slot;
}

/*
 * CR rollback function
 * revert an update next rowid operation from undo
 * @param kernel session, CR page, itl, undo row
 */
static void pcrh_revert_upd_next_rowid(knl_session_t *session, heap_page_t *cr_page,
    pcr_itl_t *itl, undo_row_t *ud_row)
{
    pcr_row_dir_t *dir = pcrh_get_dir(cr_page, (uint16)ud_row->rowid.slot);
    knl_panic(!PCRH_DIR_IS_FREE(dir));
    row_head_t *row = PCRH_GET_ROW(cr_page, dir);
    knl_panic(row->is_link || row->is_migr);

    /* revert link rowid */
    *PCRH_NEXT_ROWID(row) = *(rowid_t *)ud_row->data;

    if (ud_row->is_xfirst) {
        ROW_SET_ITL_ID(row, GS_INVALID_ID8);
    }

    itl->ssn = ud_row->ssn;
    itl->undo_page = ud_row->prev_page;
    itl->undo_slot = ud_row->prev_slot;
}

/*
 * CR rollback function
 * revert an lock link row operation
 * @param kernel session, itl, undo row
 */
static inline void pcrh_revert_upd_link_ssn(knl_session_t *session, heap_page_t *cr_page,
                                               pcr_itl_t *itl, undo_row_t *ud_row)
{
    pcr_row_dir_t *dir = pcrh_get_dir(cr_page, (uint16)ud_row->rowid.slot);
    knl_panic(!PCRH_DIR_IS_FREE(dir));
    row_head_t *row = PCRH_GET_ROW(cr_page, dir);

    if (ud_row->is_xfirst) {
        ROW_SET_ITL_ID(row, GS_INVALID_ID8);
    }

    itl->ssn = ud_row->ssn;
    itl->undo_page = ud_row->prev_page;
    itl->undo_slot = ud_row->prev_slot;
}

/*
 * CR rollback interface
 * @param kernel session, CR page, itl_id, undo row
 */
static void pcrh_reorganize_with_ud(knl_session_t *session, heap_page_t *cr_page,
    pcr_itl_t *itl, undo_row_t *ud_row)
{
    switch (ud_row->type) {
        case UNDO_PCRH_ITL:
            pcrh_revert_itl(session, cr_page, itl, ud_row);
            break;

        case UNDO_PCRH_INSERT:
            pcrh_revert_ins(session, cr_page, itl, ud_row);
            break;

        case UNDO_PCRH_DELETE:
        case UNDO_PCRH_COMPACT_DELETE:
            pcrh_revert_del(session, cr_page, itl, ud_row);
            break;

        case UNDO_PCRH_UPDATE:
        case UNDO_PCRH_UPDATE_FULL:
            pcrh_revert_upd(session, cr_page, itl, ud_row);
            break;

        case UNDO_PCRH_UPDATE_LINK_SSN:
            pcrh_revert_upd_link_ssn(session, cr_page, itl, ud_row);
            break;

        case UNDO_PCRH_UPDATE_NEXT_RID:
            pcrh_revert_upd_next_rowid(session, cr_page, itl, ud_row);
            break;

        case UNDO_PCRH_BATCH_INSERT:
            pcrh_revert_batch_ins(session, cr_page, itl, ud_row);
            break;

        default:
            break;
    }
}


/*
 * PCR reorganize with undo list
 * @note rollback from the specified itl undo snapshot, as we know,
 * different rows in same page changed by the same transaction, there undos
 * are in the same undo list, so we don't check rowid here, just check xid.
 * We keep statement level read consistency when visit undo snapshot.
 * @param kernel session, kernel cursor, CR page, itl_id, flashback mark
 */
status_t pcrh_reorganize_with_ud_list(knl_session_t *session, cr_cursor_t *cursor, heap_page_t *cr_page,
                                        bool8 *fb_mark)
{
    pcr_itl_t *itl = cursor->itl;

    /*
     * When we are going to revert an itl, we take over the free space management
     * for the whole page revert to keep enough free space for every itl.
     * And if itl is inactive, set to active before revert.
     */
    if (!itl->is_active) {
        itl->is_active = GS_TRUE;
    } else {
        /* free_size and itl->fsc both within DEFAULT_PAGE_SIZE, so the sum less than max value(65535) of uint16 */
        cr_page->free_size += itl->fsc;
    }

    itl->is_hist = GS_TRUE;
    itl->fsc = 0;

    uint8 options = cursor->is_remote ? ENTER_PAGE_TRY : ENTER_PAGE_NORMAL;

    for (;;) {
        /* on condition of nologging, no undo page */
        if (IS_INVALID_PAGID(PAGID_U2N(itl->undo_page))) {
            tx_record_sql(session);
            GS_LOG_RUN_ERR("snapshot too old: invalid undo page_id, itl scn %llu", itl->scn);
            GS_THROW_ERROR(ERR_SNAPSHOT_TOO_OLD);
            return GS_ERROR;
        }

        if (buf_read_page(session, PAGID_U2N(itl->undo_page), LATCH_MODE_S, options) != GS_SUCCESS) {
            return GS_ERROR;
        }

        undo_page_t *ud_page = (undo_page_t *)CURR_PAGE(session);
        if (ud_page == NULL) {
            /* only in remote CR request, force the requester to do local read */
            cursor->local_cr = GS_TRUE;
            return GS_SUCCESS;
        }

        if (itl->undo_slot >= ud_page->rows) {
            buf_leave_page(session, GS_FALSE);
            tx_record_sql(session);
            GS_LOG_RUN_ERR("snapshot too old, detail: snapshot slot %u, undo rows %u, query scn %llu",
                           (uint32)itl->undo_slot, (uint32)ud_page->rows, cursor->query_scn);
            GS_THROW_ERROR(ERR_SNAPSHOT_TOO_OLD);
            return GS_ERROR;
        }

        undo_row_t *ud_row = UNDO_ROW(session, ud_page, itl->undo_slot);

        if (itl->xid.value != ud_row->xid.value) {
            buf_leave_page(session, GS_FALSE);
            tx_record_sql(session);
            GS_LOG_RUN_ERR("snapshot too old, detail: snapshot xid %llu, undo row xid %llu, query scn %llu",
                           itl->xid.value, ud_row->xid.value, cursor->query_scn);
            GS_THROW_ERROR(ERR_SNAPSHOT_TOO_OLD);
            return GS_ERROR;
        }

        /* support statement level read consistency */
        if (ud_row->xid.value == cursor->xid.value && ud_row->ssn < cursor->ssn) {
            itl->ssn = ud_row->ssn;
            buf_leave_page(session, GS_FALSE);
            return GS_SUCCESS;
        }

        pcrh_reorganize_with_ud(session, cr_page, itl, ud_row);

        /* current itl is done, caller should find a new recent itl to do CR rollback */
        if (ud_row->type == UNDO_PCRH_ITL) {
            buf_leave_page(session, GS_FALSE);
            return GS_SUCCESS;
        }

        /* for flashback, we mark row has been roll backed in flashback buffer */
        if (fb_mark != NULL) {
            if (ud_row->type == UNDO_PCRH_BATCH_INSERT) {
                /* for batch insert, we need mark every row */
                pcrh_undo_batch_insert_t *batch_undo = (pcrh_undo_batch_insert_t *)ud_row->data;
                for (uint32 i = 0; i < batch_undo->count; i++) {
                    fb_mark[batch_undo->undos[i].slot] = 1;
                }
            } else {
                fb_mark[ud_row->rowid.slot] = 1;
            }
        }

        buf_leave_page(session, GS_FALSE);
    }
}

void pcrh_undo_ins_r(knl_session_t *session, bool32 is_xfirst, uint16 slot, pcr_row_dir_t *dir, row_head_t *row)
{
    heap_page_t *page = (heap_page_t *)CURR_PAGE(session);
    if (page->free_begin == *dir + row->size) {
        page->free_begin = *dir;
    }

    /* free directly if is last and new allocated dir */
    if (is_xfirst) {
        if (slot + 1 == page->dirs) {
            /*
             * free_size and free_end both within DEFAULT_PAGE_SIZE,
             * sizeof(pcr_row_dir_t) is 2, so the sum less than max value(65535) of uint16.
             */
            page->free_end += sizeof(pcr_row_dir_t);
            page->free_size += sizeof(pcr_row_dir_t);
            page->dirs--;
        } else {
            *dir = page->first_free_dir | PCRH_DIR_NEW_MASK | PCRH_DIR_FREE_MASK;
            page->first_free_dir = (uint16)slot;
        }
    } else {
        *dir = page->first_free_dir | PCRH_DIR_FREE_MASK;
        page->first_free_dir = slot;
    }

    row->is_deleted = 1;
    page->rows--;
}
/*
 * PCR heap undo insert
 * @param kernel session, undo row, undo page, undo slot
 */
void pcrh_undo_ins(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot)
{
    rowid_t rowid = ud_row->rowid;
    page_id_t page_id = GET_ROWID_PAGE(rowid);
    rd_pcrh_undo_t redo;

    if (!spc_validate_page_id(session, page_id)) {
        return;
    }

    /* first of all, verify undo information on itl of target row */
    buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    heap_page_t *page = (heap_page_t *)CURR_PAGE(session);
    if (page_is_damaged(&page->head)) {
        GS_LOG_RUN_WAR("[NOLOG INSERT] page: %u-%u was loaded using the NOLOGGING option.",
            AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page);
        buf_leave_page(session, GS_FALSE);
        return;
    }

    pcr_row_dir_t *dir = pcrh_get_dir(page, (uint16)rowid.slot);
    row_head_t *row = PCRH_GET_ROW(page, dir);
    pcr_itl_t *itl = pcrh_get_itl(page, ROW_ITL_ID(row));
    knl_panic_log(IS_SAME_PAGID(itl->undo_page, AS_PAGID(ud_page->head.id)), "itl's undo_page and ud_page are not "
                  "same page, panic info: ud_page %u-%u type %u, page %u-%u type %u", AS_PAGID(ud_page->head.id).file,
                  AS_PAGID(ud_page->head.id).page, ud_page->head.type, page_id.file, page_id.page, page->head.type);
    knl_panic_log(itl->undo_slot == ud_slot, "itl's undo_slot and ud_slot are not equal, panic info: ud_page %u-%u "
                  "type %u page %u-%u type %u itl undo_slot %u ud_slot %u", AS_PAGID(ud_page->head.id).file,
                  AS_PAGID(ud_page->head.id).page, ud_page->head.type, page_id.file,
                  page_id.page, page->head.type, itl->undo_slot, ud_slot);
    knl_panic_log(itl->xid.value == session->rm->xid.value, "the xid of itl and rm are not equal, panic info: ud_page "
                  "%u-%u type %u page %u-%u type %u itl xid %llu rm xid %llu", AS_PAGID(ud_page->head.id).file,
                  AS_PAGID(ud_page->head.id).page, ud_page->head.type, page_id.file,
                  page_id.page, page->head.type, itl->xid.value, session->rm->xid.value);

    pcrh_undo_ins_r(session, ud_row->is_xfirst, (uint16)rowid.slot, dir, row);

    /*
     * rollback itl information from undo
     * 1.we only need to set ssn until undo itl
     * 2.we just return row space to fsc and release all space when undo itl.
     */
    itl->fsc += row->size;
    itl->ssn = ud_row->ssn;
    itl->undo_page = ud_row->prev_page;
    itl->undo_slot = ud_row->prev_slot;

    redo.slot = (uint16)rowid.slot;
    redo.ssn = ud_row->ssn;
    redo.undo_page = ud_row->prev_page;
    redo.undo_slot = ud_row->prev_slot;
    redo.is_xfirst = ud_row->is_xfirst;
    if (SPC_IS_LOGGING_BY_PAGEID(session, page_id)) {
        log_put(session, RD_PCRH_UNDO_INSERT, &redo, sizeof(rd_pcrh_undo_t), LOG_ENTRY_FLAG_NONE);
    }

    buf_leave_page(session, GS_TRUE);
}

/*
 * PCR heap undo batch insert
 * @param kernel session, undo row, undo page, undo slot
 */
void pcrh_undo_batch_ins(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot)
{
    heap_page_t *page = NULL;
    pcr_row_dir_t *dir = NULL;
    pcr_itl_t *itl = NULL;
    row_head_t *row = NULL;
    rowid_t rowid;
    rd_pcrh_undo_t redo;
    page_id_t page_id;
    pcrh_undo_batch_insert_t *batch_undo = (pcrh_undo_batch_insert_t *)ud_row->data;

    rowid = ud_row->rowid;
    page_id = GET_ROWID_PAGE(rowid);
    if (!spc_validate_page_id(session, page_id)) {
        return;
    }

    /* first of all, verify undo information on itl of target row */
    buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    page = (heap_page_t *)CURR_PAGE(session);
    if (page_is_damaged(&page->head)) {
        buf_leave_page(session, GS_FALSE);
        return;
    }

    dir = pcrh_get_dir(page, (uint16)batch_undo->undos[0].slot);
    row = PCRH_GET_ROW(page, dir);
    itl = pcrh_get_itl(page, ROW_ITL_ID(row));
    knl_panic_log(IS_SAME_PAGID(itl->undo_page, AS_PAGID(ud_page->head.id)), "itl's undo_page and ud_page are not "
                  "same page, panic info: ud_page %u-%u type %u, page %u-%u type %u", AS_PAGID(ud_page->head.id).file,
                  AS_PAGID(ud_page->head.id).page, ud_page->head.type, page_id.file, page_id.page, page->head.type);
    knl_panic_log(itl->undo_slot == ud_slot, "itl's undo_slot and ud_slot are not equal, panic info: ud_page %u-%u "
                  "type %u page %u-%u type %u itl undo_slot %u ud_slot %u", AS_PAGID(ud_page->head.id).file,
                  AS_PAGID(ud_page->head.id).page, ud_page->head.type, page_id.file,
                  page_id.page, page->head.type, itl->undo_slot, ud_slot);
    knl_panic_log(itl->xid.value == session->rm->xid.value, "the xid of itl and rm are not equal, panic info: ud_page "
                  "%u-%u type %u page %u-%u type %u itl xid %llu rm xid %llu", AS_PAGID(ud_page->head.id).file,
                  AS_PAGID(ud_page->head.id).page, ud_page->head.type, page_id.file,
                  page_id.page, page->head.type, itl->xid.value, session->rm->xid.value);
    redo.ssn = itl->ssn;
    redo.undo_page = itl->undo_page;
    redo.undo_slot = itl->undo_slot;

    for (int32 i = batch_undo->count - 1; i >= 0; i--) {
        dir = pcrh_get_dir(page, batch_undo->undos[i].slot);
        row = PCRH_GET_ROW(page, dir);
        redo.is_xfirst = ud_row->is_xfirst ? ud_row->is_xfirst : batch_undo->undos[i].is_xfirst;
        pcrh_undo_ins_r(session, redo.is_xfirst, batch_undo->undos[i].slot, dir, row);

        itl->fsc += row->size;
        redo.slot = batch_undo->undos[i].slot;
        if (i == 0) {
            redo.ssn = ud_row->ssn;
            redo.undo_page = ud_row->prev_page;
            redo.undo_slot = ud_row->prev_slot;
            /*
             * rollback itl information from undo
             * 1.we only need to set ssn until undo itl
             * 2.we just return row space to fsc and release all space when undo itl.
             */
            itl->ssn = ud_row->ssn;
            itl->undo_page = ud_row->prev_page;
            itl->undo_slot = ud_row->prev_slot;
        }
        if (SPC_IS_LOGGING_BY_PAGEID(session, page_id)) {
            log_put(session, RD_PCRH_UNDO_INSERT, &redo, sizeof(rd_pcrh_undo_t), LOG_ENTRY_FLAG_NONE);
        }
    }

    buf_leave_page(session, GS_TRUE);
}

/*
 * PCR heap undo delete
 * @param kernel session, undo row, undo page, undo slot
 */
void pcrh_undo_del(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot)
{
    heap_page_t *page = NULL;
    pcr_row_dir_t *dir = NULL;
    row_head_t *row = NULL;
    row_head_t *org_row = NULL;
    pcr_itl_t *itl = NULL;
    rd_pcrh_undo_t redo;
    rowid_t rowid = ud_row->rowid;
    page_id_t page_id = GET_ROWID_PAGE(rowid);
    errno_t ret;

    if (!spc_validate_page_id(session, page_id)) {
        return;
    }

    org_row = (row_head_t *)ud_row->data;

    /* first of all, verify undo information on itl of target row */
    buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    page = (heap_page_t *)CURR_PAGE(session);
    if (page_is_damaged(&page->head)) {
        buf_leave_page(session, GS_FALSE);
        return;
    }

    dir = pcrh_get_dir(page, (uint16)rowid.slot);
    row = PCRH_GET_ROW(page, dir);
    knl_panic_log(row->is_deleted, "row is not deleted, panic info: ud_page %u-%u type %u, page %u-%u type %u",
                  AS_PAGID(ud_page->head.id).file, AS_PAGID(ud_page->head.id).page, ud_page->head.type, page_id.file,
                  page_id.page, page->head.type);
    itl = pcrh_get_itl(page, ROW_ITL_ID(row));
    knl_panic_log(IS_SAME_PAGID(itl->undo_page, AS_PAGID(ud_page->head.id)), "itl's undo_page and ud_page are not "
                  "same page, panic info: ud_page %u-%u type %u, page %u-%u type %u", AS_PAGID(ud_page->head.id).file,
                  AS_PAGID(ud_page->head.id).page, ud_page->head.type, page_id.file, page_id.page, page->head.type);
    knl_panic_log(itl->undo_slot == ud_slot, "itl's undo_slot and ud_slot are not equal, panic info: ud_page %u-%u "
                  "type %u page %u-%u type %u itl undo_slot %u ud_slot %u", AS_PAGID(ud_page->head.id).file,
                  AS_PAGID(ud_page->head.id).page, ud_page->head.type, page_id.file,
                  page_id.page, page->head.type, itl->undo_slot, ud_slot);
    knl_panic_log(itl->xid.value == session->rm->xid.value, "the xid of itl and rm are not equal, panic info: ud_page "
                  "%u-%u type %u page %u-%u type %u itl xid %llu rm xid %llu", AS_PAGID(ud_page->head.id).file,
                  AS_PAGID(ud_page->head.id).page, ud_page->head.type, page_id.file,
                  page_id.page, page->head.type, itl->xid.value, session->rm->xid.value);

    if (row->size == org_row->size) {
        /* deleted row has not been compacted, we can rollback directly */
        row->is_deleted = 0;
    } else {
        /* row has been compact, we should find a new space in page to revert delete */
        knl_panic_log(row->size == sizeof(row_head_t),
                      "row's size is abnormal, panic info: ud_page %u-%u type %u, page %u-%u type %u row size %u",
                      AS_PAGID(ud_page->head.id).file, AS_PAGID(ud_page->head.id).page, ud_page->head.type,
                      page_id.file, page_id.page, page->head.type, row->size);

        if (page->free_end - page->free_begin < org_row->size) {
            *dir |= PCRH_DIR_FREE_MASK;
            pcrh_compact_page(session, page);
        }

        *dir = page->free_begin;
        /*
         * free_begin less than DEFAULT_PAGE_SIZE, row size PCRH_MAX_ROW_SIZE,
         * the sum is less than max value(65535) of uint16.
         */
        page->free_begin += org_row->size;
        knl_panic_log(page->free_begin <= page->free_end, "page's free size begin is more than end, panic info: "
                      "ud_page %u-%u type %u, page %u-%u type %u free_begin %u free_end %u",
                      AS_PAGID(ud_page->head.id).file, AS_PAGID(ud_page->head.id).page, ud_page->head.type,
                      page_id.file, page_id.page, page->head.type, page->free_begin, page->free_end);

        /* relocate the row position */
        row = PCRH_GET_ROW(page, dir);
        ret = memcpy_sp(row, page->free_end - *dir, org_row, org_row->size);
        knl_securec_check(ret);
    }

    knl_panic_log(itl->fsc >= row->size - sizeof(row_head_t),
        "itl's fsc is abnormal, panic info: ud_page %u-%u type %u, page %u-%u type %u itl fsc %u row size %u",
        AS_PAGID(ud_page->head.id).file, AS_PAGID(ud_page->head.id).page, ud_page->head.type, page_id.file,
        page_id.page, page->head.type, itl->fsc, row->size);
    itl->fsc -= row->size - sizeof(row_head_t);
    page->rows++;

    itl->undo_page = ud_row->prev_page;
    itl->undo_slot = ud_row->prev_slot;
    itl->ssn = ud_row->ssn;
    if (ud_row->is_xfirst) {
        ROW_SET_ITL_ID(row, GS_INVALID_ID8);
    }

    redo.slot = (uint16)rowid.slot;
    redo.is_xfirst = (uint8)ud_row->is_xfirst;
    redo.ssn = ud_row->ssn;
    redo.undo_page = ud_row->prev_page;
    redo.undo_slot = ud_row->prev_slot;
    if (SPC_IS_LOGGING_BY_PAGEID(session, page_id)) {
        log_put(session, RD_PCRH_UNDO_DELETE, &redo, sizeof(rd_pcrh_undo_t), LOG_ENTRY_FLAG_NONE);
        log_append_data(session, org_row, org_row->size);
    }
    buf_leave_page(session, GS_TRUE);
}

/*
 * PCR heap undo update
 * @param kernel session, undo row, undo page, undo slot
 */
void pcrh_undo_upd(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot)
{
    rd_pcrh_undo_update_t redo;
    heap_page_t *page = NULL;
    pcr_row_dir_t *dir = NULL;
    row_head_t *row = NULL;
    row_head_t *org_row = NULL;
    pcr_itl_t *itl = NULL;
    rowid_t rowid = ud_row->rowid;
    page_id_t page_id = GET_ROWID_PAGE(rowid);
    int16 inc_size;
    errno_t ret;

    if (!spc_validate_page_id(session, page_id)) {
        return;
    }

    /* first of all, verify undo information on itl of target row */
    buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    page = (heap_page_t *)CURR_PAGE(session);
    if (page_is_damaged(&page->head)) {
        buf_leave_page(session, GS_FALSE);
        return;
    }

    dir = pcrh_get_dir(page, (uint16)rowid.slot);
    row = PCRH_GET_ROW(page, dir);
    itl = pcrh_get_itl(page, ROW_ITL_ID(row));
    knl_panic_log(IS_SAME_PAGID(itl->undo_page, AS_PAGID(ud_page->head.id)), "itl's undo_page and ud_page are not "
                  "same page, panic info: ud_page %u-%u type %u, page %u-%u type %u", AS_PAGID(ud_page->head.id).file,
                  AS_PAGID(ud_page->head.id).page, ud_page->head.type, page_id.file, page_id.page, page->head.type);
    knl_panic_log(itl->undo_slot == ud_slot, "itl's undo_slot and ud_slot are not equal, panic info: ud_page %u-%u "
                  "type %u page %u-%u type %u itl undo_slot %u ud_slot %u", AS_PAGID(ud_page->head.id).file,
                  AS_PAGID(ud_page->head.id).page, ud_page->head.type, page_id.file, page_id.page, page->head.type,
                  itl->undo_slot, ud_slot);
    knl_panic_log(itl->xid.value == session->rm->xid.value, "the xid of itl and rm are not equal, panic info: ud_page "
                  "%u-%u type %u page %u-%u type %u itl xid %llu rm xid %llu", AS_PAGID(ud_page->head.id).file,
                  AS_PAGID(ud_page->head.id).page, ud_page->head.type, page_id.file,
                  page_id.page, page->head.type, itl->xid.value, session->rm->xid.value);

    /*
     * UNDO_PCRH_UPDATE need to reorganize row
     */
    if (ud_row->type == UNDO_PCRH_UPDATE_FULL) {
        org_row = (row_head_t *)ud_row->data;
    } else {
        knl_panic_log(!row->is_link, "row is link, panic info: ud_page %u-%u type %u, page %u-%u type %u",
                      AS_PAGID(ud_page->head.id).file, AS_PAGID(ud_page->head.id).page, ud_page->head.type,
                      page_id.file, page_id.page, page->head.type);
        org_row = (row_head_t *)cm_push(session->stack, PCRH_MAX_MIGR_SIZE(session));
        pcrh_reorganize_ud_upd(session, row, (heap_undo_update_info_t *)ud_row->data, org_row);
    }

    inc_size = org_row->size - row->size;

    /*
     * if need more space to rollback row, insert the origin row into free
     * begin directly and release older space
     */
    if (inc_size > 0) {
        if (page->free_end - page->free_begin < org_row->size) {
            *dir |= PCRH_DIR_FREE_MASK;
            pcrh_compact_page(session, page);
        }

        *dir = page->free_begin;
        /*
         * free_begin less than DEFAULT_PAGE_SIZE(8192), row size PCRH_MAX_ROW_SIZE(session),
         * the sum is less than max value(65535) of uint16
         */
        page->free_begin += org_row->size;
        knl_panic_log(page->free_begin <= page->free_end, "page's free size begin is more than end, panic info: "
                      "ud_page %u-%u type %u, page %u-%u type %u free_begin %u free_end %u",
                      AS_PAGID(ud_page->head.id).file, AS_PAGID(ud_page->head.id).page, ud_page->head.type,
                      page_id.file, page_id.page, page->head.type, page->free_begin, page->free_end);

        if (itl->fsc >= inc_size) {
            itl->fsc -= inc_size;
        } else {
            page->free_size -= (inc_size - itl->fsc);
            itl->fsc = 0;
        }

        row = PCRH_GET_ROW(page, dir);
    } else {
        /* inc_size is negative, itl->fsc and  abs(inc_size) is less than page size 8192 */
        itl->fsc -= inc_size;
    }

    ret = memcpy_sp(row, page->free_end - *dir, (char *)org_row, org_row->size);
    knl_securec_check(ret);

    if (ud_row->is_xfirst) {
        ROW_SET_ITL_ID(row, GS_INVALID_ID8);
    }
    itl->ssn = ud_row->ssn;
    itl->undo_page = ud_row->prev_page;
    itl->undo_slot = ud_row->prev_slot;

    redo.slot = (uint16)rowid.slot;
    redo.is_xfirst = (uint8)ud_row->is_xfirst;
    redo.ssn = ud_row->ssn;
    redo.undo_page = ud_row->prev_page;
    redo.undo_slot = ud_row->prev_slot;
    redo.type = (uint8)ud_row->type;
    redo.aligned = 0;
    if (SPC_IS_LOGGING_BY_PAGEID(session, page_id)) {
        log_put(session, RD_PCRH_UNDO_UPDATE, &redo, sizeof(rd_pcrh_undo_update_t), LOG_ENTRY_FLAG_NONE);
        log_append_data(session, org_row, org_row->size);
    }
    buf_leave_page(session, GS_TRUE);

    if (ud_row->type == UNDO_PCRH_UPDATE) {
        cm_pop(session->stack);
    }
}

/*
 * PCR heap undo update next row id
 * @param kernel session, undo row, undo page, undo slot
 */
void pcrh_undo_upd_next_rowid(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot)
{
    pcr_itl_t *itl = NULL;
    rd_pcrh_undo_t redo;
    rowid_t rowid = ud_row->rowid;
    page_id_t page_id = GET_ROWID_PAGE(rowid);
    if (!spc_validate_page_id(session, page_id)) {
        return;
    }

    buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    heap_page_t *page = (heap_page_t *)CURR_PAGE(session);
    if (page_is_damaged(&page->head)) {
        buf_leave_page(session, GS_FALSE);
        return;
    }

    pcr_row_dir_t *dir = pcrh_get_dir(page, (uint16)rowid.slot);
    row_head_t *row = PCRH_GET_ROW(page, dir);
    knl_panic_log(row->is_link || row->is_migr, "row is neither link nor migr, panic info: ud_page %u-%u type %u, "
                  "page %u-%u type %u", AS_PAGID(ud_page->head.id).file, AS_PAGID(ud_page->head.id).page,
                  ud_page->head.type, page_id.file, page_id.page, page->head.type);
    itl = pcrh_get_itl(page, ROW_ITL_ID(row));
    knl_panic_log(IS_SAME_PAGID(itl->undo_page, AS_PAGID(ud_page->head.id)), "itl's undo_page and ud_page are not "
                  "same page, panic info: ud_page %u-%u type %u, page %u-%u type %u", AS_PAGID(ud_page->head.id).file,
                  AS_PAGID(ud_page->head.id).page, ud_page->head.type, page_id.file, page_id.page, page->head.type);
    knl_panic_log(itl->undo_slot == ud_slot, "itl's undo_slot and ud_slot are not equal, panic info: ud_page %u-%u "
                  "type %u page %u-%u type %u itl undo_slot %u ud_slot %u", AS_PAGID(ud_page->head.id).file,
                  AS_PAGID(ud_page->head.id).page, ud_page->head.type, page_id.file, page_id.page, page->head.type,
                  itl->undo_slot, ud_slot);
    knl_panic_log(itl->xid.value == session->rm->xid.value, "the xid of itl and rm are not equal, panic info: ud_page "
                  "%u-%u type %u page %u-%u type %u itl xid %llu rm xid %llu", AS_PAGID(ud_page->head.id).file,
                  AS_PAGID(ud_page->head.id).page, ud_page->head.type, page_id.file,
                  page_id.page, page->head.type, itl->xid.value, session->rm->xid.value);

    /* rollback next rowid */
    *PCRH_NEXT_ROWID(row) = *(rowid_t *)ud_row->data;

    if (ud_row->is_xfirst) {
        ROW_SET_ITL_ID(row, GS_INVALID_ID8);
    }

    itl->ssn = ud_row->ssn;
    itl->undo_page = ud_row->prev_page;
    itl->undo_slot = ud_row->prev_slot;

    redo.slot = (uint16)rowid.slot;
    redo.undo_page = itl->undo_page;
    redo.undo_slot = itl->undo_slot;
    redo.ssn = itl->ssn;
    redo.is_xfirst = ud_row->is_xfirst;
    if (SPC_IS_LOGGING_BY_PAGEID(session, page_id)) {
        log_put(session, RD_PCRH_UNDO_NEXT_RID, &redo, sizeof(rd_pcrh_undo_t), LOG_ENTRY_FLAG_NONE);
        log_append_data(session, ud_row->data, sizeof(rowid_t));
    }
    buf_leave_page(session, GS_TRUE);
}

/*
 * PCR heap undo lock link
 * @param kernel session, undo row, undo page, undo slot
 */
void pcrh_undo_upd_link_ssn(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot)
{
    heap_page_t *page = NULL;
    pcr_row_dir_t *dir = NULL;
    row_head_t *row = NULL;
    pcr_itl_t *itl = NULL;
    rd_pcrh_undo_t redo;
    rowid_t rowid = ud_row->rowid;
    page_id_t page_id = GET_ROWID_PAGE(rowid);
    if (!spc_validate_page_id(session, page_id)) {
        return;
    }

    buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    page = (heap_page_t *)CURR_PAGE(session);
    if (page_is_damaged(&page->head)) {
        buf_leave_page(session, GS_FALSE);
        return;
    }

    dir = pcrh_get_dir(page, (uint16)rowid.slot);
    row = PCRH_GET_ROW(page, dir);
    knl_panic_log(row->is_link, "row is not link, panic info: ud_page %u-%u type %u, page %u-%u type %u",
                  AS_PAGID(ud_page->head.id).file, AS_PAGID(ud_page->head.id).page,
                  ud_page->head.type, page_id.file, page_id.page, page->head.type);

    itl = pcrh_get_itl(page, ROW_ITL_ID(row));
    knl_panic_log(IS_SAME_PAGID(itl->undo_page, AS_PAGID(ud_page->head.id)), "itl's undo_page and ud_page are not "
                  "same page, panic info: ud_page %u-%u type %u, page %u-%u type %u", AS_PAGID(ud_page->head.id).file,
                  AS_PAGID(ud_page->head.id).page, ud_page->head.type, page_id.file, page_id.page, page->head.type);
    knl_panic_log(itl->undo_slot == ud_slot, "itl's undo_slot and ud_slot are not equal, panic info: ud_page %u-%u "
                  "type %u page %u-%u type %u itl undo_slot %u ud_slot %u", AS_PAGID(ud_page->head.id).file,
                  AS_PAGID(ud_page->head.id).page, ud_page->head.type, page_id.file, page_id.page, page->head.type,
                  itl->undo_slot, ud_slot);
    knl_panic_log(itl->xid.value == session->rm->xid.value, "the xid of itl and rm are not equal, panic info: ud_page "
                  "%u-%u type %u page %u-%u type %u itl xid %llu rm xid %llu", AS_PAGID(ud_page->head.id).file,
                  AS_PAGID(ud_page->head.id).page, ud_page->head.type, page_id.file, page_id.page, page->head.type,
                  itl->xid.value, session->rm->xid.value);

    if (ud_row->is_xfirst) {
        ROW_SET_ITL_ID(row, GS_INVALID_ID8);
    }

    itl->ssn = ud_row->ssn;
    itl->undo_page = ud_row->prev_page;
    itl->undo_slot = ud_row->prev_slot;

    redo.slot = (uint16)rowid.slot;
    redo.undo_page = itl->undo_page;
    redo.undo_slot = itl->undo_slot;
    redo.ssn = itl->ssn;
    redo.is_xfirst = ud_row->is_xfirst;
    if (SPC_IS_LOGGING_BY_PAGEID(session, page_id)) {
        log_put(session, RD_PCRH_UNDO_UPDATE_LINK_SSN, &redo, sizeof(rd_pcrh_undo_t), LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, GS_TRUE);
}

/*
 * PCR heap undo update
 * @param kernel session, undo row, undo page, undo slot
 */
void pcrh_ud_itl(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot,
                   knl_dictionary_t *dc, heap_undo_assist_t *heap_assist)
{
    heap_page_t *page = NULL;
    pcr_itl_t *itl = NULL;
    heap_t *heap = NULL;
    uint8 itl_id;
    uint8 owner_list;
    rowid_t rowid = ud_row->rowid;
    page_id_t page_id = GET_ROWID_PAGE(rowid);
    if (!spc_validate_page_id(session, page_id)) {
        return;
    }

    /* first of all, verify undo information on itl of target row */
    itl_id = (uint8)rowid.slot;
    buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    page = (heap_page_t *)CURR_PAGE(session);
    if (page_is_damaged(&page->head)) {
        buf_leave_page(session, GS_FALSE);
        return;
    }

    itl = pcrh_get_itl(page, itl_id);
    knl_panic_log(IS_SAME_PAGID(itl->undo_page, AS_PAGID(ud_page->head.id)), "itl's undo_page and ud_page are not "
        "same page, panic info: ud_page %u-%u type %u, page %u-%u type %u", AS_PAGID(ud_page->head.id).file,
        AS_PAGID(ud_page->head.id).page, ud_page->head.type, page_id.file, page_id.page, page->head.type);
    knl_panic_log(itl->undo_slot == ud_slot, "itl's undo_slot and ud_slot are not equal, panic info: ud_page %u-%u "
        "type %u page %u-%u type %u itl undo_slot %u ud_slot %u", AS_PAGID(ud_page->head.id).file,
        AS_PAGID(ud_page->head.id).page, ud_page->head.type, page_id.file, page_id.page, page->head.type,
        itl->undo_slot, ud_slot);
    knl_panic_log(itl->xid.value == session->rm->xid.value, "the xid of itl and rm are not equal, panic info: "
        "ud_page %u-%u type %u page %u-%u type %u itl xid %llu rm xid %llu", AS_PAGID(ud_page->head.id).file,
        AS_PAGID(ud_page->head.id).page, ud_page->head.type, page_id.file, page_id.page, page->head.type,
        itl->xid.value, session->rm->xid.value);

    /* undo itl means rollback to last transaction, so we need to recover scn and xid on itl */
    page->free_size += itl->fsc;  // itl->fsc and free_size is both less than page size(8192)

    itl->xid = *(xid_t *)ud_row->data;
    itl->scn = ud_row->scn;
    itl->is_owscn = ud_row->is_owscn;
    itl->undo_page = ud_row->prev_page;
    itl->undo_slot = ud_row->prev_slot;
    itl->is_active = GS_FALSE;

    if (SPC_IS_LOGGING_BY_PAGEID(session, page_id)) {
        log_put(session, RD_PCRH_UNDO_ITL, itl, sizeof(pcr_itl_t), LOG_ENTRY_FLAG_NONE);
        log_append_data(session, &itl_id, sizeof(uint8));
    }

    knl_part_locate_t part_loc = ((pcrh_undo_itl_t *)ud_row->data)->part_loc;

    heap = dc_get_heap(session, page->uid, page->oid, part_loc, dc);
    owner_list = heap_get_owner_list(session, (heap_segment_t *)heap->segment, page->free_size);
    heap_assist->change_list[0] = owner_list - (uint8)page->map.list_id;
    heap_assist->page_id[0] = page_id;

    heap_assist->heap = heap;
    heap_assist->rows = 1;

    buf_leave_page(session, GS_TRUE);
}

