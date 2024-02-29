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
 * pcr_heap_log.c
 *
 *
 * IDENTIFICATION
 * src/kernel/table/pcr_heap_log.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_table_module.h"
#include "pcr_heap_log.h"
#include "knl_context.h"
#include "srv_mq_msg.h"

#define REFORM_LOG_DDL_TERM_SIZE (1)
#define REFORM_LOG_DDL_TERM_DATA ";"

/*
 * redo function
 * @param kernel session, log entry
 */
void rd_pcrh_init_itls(knl_session_t *session, log_entry_t *log)
{
    uint8 itls;
    heap_page_t *page;

    itls = (uint8)(*(uint32 *)log->data);
    page = (heap_page_t *)CURR_PAGE(session);

    page->itls = itls;
    /* free_end and free_size larger than itls * sizeof(pcr_itl_t) */
    page->free_end -= (uint16)(itls * sizeof(pcr_itl_t));
    page->free_size -= (uint16)(itls * sizeof(pcr_itl_t));
}

/*
 * redo function
 * @param kernel session, log entry
 */
void rd_pcrh_new_itl(knl_session_t *session, log_entry_t *log)
{
    rd_pcrh_new_itl_t *redo;
    heap_page_t *page;
    uint8 itl_id;
    pcr_itl_t *itl;

    redo = (rd_pcrh_new_itl_t *)log->data;
    page = (heap_page_t *)CURR_PAGE(session);

    itl_id = pcrh_new_itl(session, page);
    itl = pcrh_get_itl(page, itl_id);
    tx_init_pcr_itl(session, itl, &redo->undo_rid, redo->xid, redo->ssn);
}

/*
 * redo function
 * @param kernel session, log entry
 */
void rd_pcrh_reuse_itl(knl_session_t *session, log_entry_t *log)
{
    rd_pcrh_reuse_itl_t *redo;
    heap_page_t *page;
    pcr_itl_t *itl;

    redo = (rd_pcrh_reuse_itl_t *)log->data;
    page = (heap_page_t *)CURR_PAGE(session);
    itl = pcrh_get_itl(page, (uint8)redo->itl_id);

    pcrh_reuse_itl(session, page, itl, (uint8)redo->itl_id);
    tx_init_pcr_itl(session, itl, &redo->undo_rid, redo->xid, redo->ssn);
}

/*
 * redo function
 * @param kernel session, log entry
 */
void rd_pcrh_clean_itl(knl_session_t *session, log_entry_t *log)
{
    rd_pcrh_clean_itl_t *redo;
    heap_page_t *page;

    redo = (rd_pcrh_clean_itl_t *)log->data;
    page = (heap_page_t *)CURR_PAGE(session);
    if (page->itls == 0) {
        return;
    }

    pcrh_clean_itl(session, page, redo);
}

/*
 * redo function
 * @param kernel session, log entry
 */
void rd_pcrh_lock_row(knl_session_t *session, log_entry_t *log)
{
    rd_pcrh_lock_row_t *redo;
    heap_page_t *page;
    pcr_row_dir_t *dir;
    row_head_t *row;

    redo = (rd_pcrh_lock_row_t *)log->data;
    page = (heap_page_t *)CURR_PAGE(session);
    dir = pcrh_get_dir(page, redo->slot);
    row = PCRH_GET_ROW(page, dir);

    ROW_SET_ITL_ID(row, redo->itl_id);
    row->is_changed = 0;
    row->self_chg = 0;
}

/*
 * redo function
 * @param kernel session, log entry
 */
void rd_pcrh_update_link_ssn(knl_session_t *session, log_entry_t *log)
{
    pcrh_update_link_ssn_t *redo = (pcrh_update_link_ssn_t *)log->data;
    heap_page_t *page = (heap_page_t *)CURR_PAGE(session);

    pcr_row_dir_t *dir = pcrh_get_dir(page, redo->slot);
    knl_panic_log(!PCRH_DIR_IS_FREE(dir), "the dir is free, panic info: page %u-%u type %u",
                  AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type);

    row_head_t *row = PCRH_GET_ROW(page, dir);
    knl_panic_log(row->is_link, "row is not link, panic info: page %u-%u type %u", AS_PAGID(page->head.id).file,
                  AS_PAGID(page->head.id).page, page->head.type);

    pcr_itl_t *itl = pcrh_get_itl(page, ROW_ITL_ID(row));
    itl->undo_page = redo->undo_page;
    itl->undo_slot = redo->undo_slot;
    itl->ssn = redo->ssn;

    row->is_changed = 1;
    row->self_chg = 1;
}

/*
 * redo function
 * @param kernel session, log entry
 */
void rd_pcrh_insert(knl_session_t *session, log_entry_t *log)
{
    rd_pcrh_insert_t *redo;
    row_head_t *row = NULL;
    heap_page_t *page;
    undo_data_t undo;
    uint16 slot;

    redo = (rd_pcrh_insert_t *)log->data;
    row = (row_head_t *)redo->data;
    page = (heap_page_t *)CURR_PAGE(session);

    pcrh_insert_into_page(session, page, row, &undo, redo, &slot);
}

/*
 * redo function
 * @param kernel session, log entry
 */
void rd_pcrh_update_inplace(knl_session_t *session, log_entry_t *log)
{
    rd_pcrh_update_inplace_t *redo;
    heap_page_t *page;
    pcr_row_dir_t *dir = NULL;
    row_head_t *row = NULL;
    pcr_itl_t *itl;
    knl_update_info_t info;
    uint16 *offsets = NULL;
    uint16 *lens = NULL;
    uint16 col_size;
    errno_t ret;

    redo = (rd_pcrh_update_inplace_t *)log->data;
    page = (heap_page_t *)CURR_PAGE(session);
    dir = pcrh_get_dir(page, redo->slot);
    row = PCRH_GET_ROW(page, dir);
    itl = pcrh_get_itl(page, ROW_ITL_ID(row));

    itl->undo_page = redo->undo_page;
    itl->undo_slot = redo->undo_slot;
    itl->ssn = redo->ssn;

    CM_SAVE_STACK(session->stack);
    CM_PUSH_UPDATE_INFO(session, info);

    info.count = redo->count;
    info.data = (log->data + (sizeof(rd_pcrh_update_inplace_t)) + CM_ALIGN4(sizeof(uint16) * redo->count));
    /* max value of redo->count is CT_MAX_COLUMNS(4096) */
    col_size = sizeof(uint16) * redo->count;
    ret = memcpy_sp(info.columns, (session)->kernel->attr.max_column_count * sizeof(uint16), redo->columns, col_size);
    knl_securec_check(ret);

    /* max column count of table is CT_MAX_COLUMNS(4096) */
    offsets = (uint16 *)cm_push(session->stack, sizeof(uint16) * session->kernel->attr.max_column_count * 2);
    lens = (uint16 *)((char *)offsets + sizeof(uint16) * session->kernel->attr.max_column_count);

    cm_decode_row((char *)row, offsets, lens, NULL);
    cm_decode_row(info.data, info.offsets, info.lens, NULL);

    row->self_chg = 1;
    heap_update_inplace(session, offsets, lens, &info, row);

    CM_RESTORE_STACK(session->stack);
}

/*
 * redo function
 * @param kernel session, log entry
 */
void rd_pcrh_update_inpage(knl_session_t *session, log_entry_t *log)
{
    rd_pcrh_update_inpage_t *redo = (rd_pcrh_update_inpage_t *)log->data;
    heap_page_t *page = (heap_page_t *)CURR_PAGE(session);
    pcr_row_dir_t *dir = NULL;
    row_head_t *row = NULL;
    pcr_itl_t *itl = NULL;
    heap_update_assist_t ua;
    knl_update_info_t info;
    uint16 offsets[CT_MAX_COLUMNS];
    uint16 lens[CT_MAX_COLUMNS];
    uint16 data_size, col_size;
    errno_t ret;

    dir = pcrh_get_dir(page, redo->slot);
    row = PCRH_GET_ROW(page, dir);
    itl = pcrh_get_itl(page, ROW_ITL_ID(row));

    itl->undo_page = redo->undo_page;
    itl->undo_slot = redo->undo_slot;
    itl->ssn = redo->ssn;

    CM_SAVE_STACK(session->stack);
    ua.row = (row_head_t *)cm_push(session->stack, PCRH_MAX_MIGR_SIZE(session));
    CM_PUSH_UPDATE_INFO(session, info);

    ua.rowid.file = (uint16)AS_PAGID(page->head.id).file;
    ua.rowid.page = (uint32)AS_PAGID(page->head.id).page;
    ua.rowid.slot = redo->slot;
    ua.offsets = offsets;
    ua.lens = lens;

    info.count = redo->count;
    ua.new_cols = redo->new_cols;
    ua.inc_size = redo->inc_size;
    /* row->size and ua.inc_size is less than page size(8192) for update inpage mode */
    ua.new_size = row->size + ua.inc_size;
    ua.info = &info;

    info.data = log->data + PCRH_UPDATE_INPAGE_SIZE(redo->count);
    col_size = sizeof(uint16) * redo->count;
    ret = memcpy_sp(info.columns, (session)->kernel->attr.max_column_count * sizeof(uint16), redo->columns, col_size);
    knl_securec_check(ret);
    ret = memcpy_sp(ua.row, PCRH_MAX_MIGR_SIZE(session), row, row->size);
    knl_securec_check(ret);

    cm_decode_row((char *)ua.row, ua.offsets, ua.lens, &data_size);
    cm_decode_row(info.data, info.offsets, info.lens, NULL);

    pcrh_update_inpage(session, page, &ua);

    CM_RESTORE_STACK(session->stack);
}

/*
 * redo function
 * @param kernel session, log entry
 */
void rd_pcrh_delete(knl_session_t *session, log_entry_t *log)
{
    rd_pcrh_delete_t *redo;
    heap_page_t *page;
    pcr_row_dir_t *dir = NULL;
    row_head_t *row = NULL;
    pcr_itl_t *itl;

    redo = (rd_pcrh_delete_t *)log->data;
    page = (heap_page_t *)CURR_PAGE(session);
    dir = pcrh_get_dir(page, redo->slot);
    row = PCRH_GET_ROW(page, dir);
    itl = pcrh_get_itl(page, ROW_ITL_ID(row));

    itl->undo_page = redo->undo_page;
    itl->undo_slot = redo->undo_slot;
    itl->ssn = redo->ssn;
    /* itl->fsc and row->size is less than page size(8192) */
    itl->fsc += row->size - sizeof(row_head_t);

    knl_panic_log(!row->is_deleted, "the row is deleted, panic info: page %u-%u type %u", AS_PAGID(page->head.id).file,
                  AS_PAGID(page->head.id).page, page->head.type);
    row->is_deleted = 1;
    row->is_changed = 1;
    row->self_chg = 1;

    page->rows--;
}

/*
 * redo function
 * @param kernel session, log entry
 */
void rd_pcrh_convert_link(knl_session_t *session, log_entry_t *log)
{
    pcrh_set_next_rid_t *redo;
    heap_page_t *page;
    pcr_row_dir_t *dir = NULL;
    row_head_t *row = NULL;
    pcr_itl_t *itl;

    redo = (pcrh_set_next_rid_t *)log->data;
    page = (heap_page_t *)CURR_PAGE(session);
    dir = pcrh_get_dir(page, redo->slot);
    row = PCRH_GET_ROW(page, dir);
    itl = pcrh_get_itl(page, ROW_ITL_ID(row));

    itl->undo_page = redo->undo_page;
    itl->undo_slot = redo->undo_slot;
    itl->ssn = redo->ssn;
    /* itl->fsc and row->size is less than page size(8192) */
    itl->fsc += row->size - PCRH_MIN_ROW_SIZE;

    row->is_link = 1;
    row->is_changed = 1;
    row->self_chg = 1;
    *PCRH_NEXT_ROWID(row) = redo->next_rid;
    row->size = PCRH_MIN_ROW_SIZE;
}

/*
 * redo function
 * @param kernel session, log entry
 */
void rd_pcrh_update_next_rid(knl_session_t *session, log_entry_t *log)
{
    pcrh_set_next_rid_t *redo;
    heap_page_t *page;
    pcr_row_dir_t *dir = NULL;
    row_head_t *row = NULL;
    pcr_itl_t *itl;

    redo = (pcrh_set_next_rid_t *)log->data;
    page = (heap_page_t *)CURR_PAGE(session);
    dir = pcrh_get_dir(page, redo->slot);
    row = PCRH_GET_ROW(page, dir);
    itl = pcrh_get_itl(page, ROW_ITL_ID(row));

    itl->undo_page = redo->undo_page;
    itl->undo_slot = redo->undo_slot;
    itl->ssn = redo->ssn;

    row->is_changed = 1;
    row->self_chg = 1;
    *PCRH_NEXT_ROWID(row) = redo->next_rid;
}

/*
 * redo function
 * @param kernel session, log entry
 */
void rd_pcrh_undo_itl(knl_session_t *session, log_entry_t *log)
{
    heap_page_t *page;
    pcr_itl_t *itl;
    pcr_itl_t *redo;
    uint8 itl_id;

    page = (heap_page_t *)CURR_PAGE(session);
    redo = (pcr_itl_t *)log->data;
    itl_id = *(uint8 *)(log->data + sizeof(pcr_itl_t));

    itl = pcrh_get_itl(page, itl_id);
    /* itl->fsc and free_size is less than page size(8192) */
    page->free_size += itl->fsc;
    *itl = *redo;
}

/*
 * redo function
 * @param kernel session, log entry
 */
void rd_pcrh_undo_insert(knl_session_t *session, log_entry_t *log)
{
    rd_pcrh_undo_t *redo = (rd_pcrh_undo_t *)log->data;
    heap_page_t *page = (heap_page_t *)CURR_PAGE(session);
    pcr_row_dir_t *dir = pcrh_get_dir(page, (uint16)redo->slot);
    row_head_t *row = PCRH_GET_ROW(page, dir);
    pcr_itl_t *itl = pcrh_get_itl(page, ROW_ITL_ID(row));

    /* free directly if is last row */
    if (page->free_begin == *dir + row->size) {
        page->free_begin = *dir;
    }

    /* free directly if is last and new allocated dir */
    if (redo->is_xfirst) {
        if ((uint16)redo->slot + 1 == page->dirs) {
            /*
             * free_size and free_end both within DEFAULT_PAGE_SIZE(8192), sizeof(pcr_row_dir_t) is 2,
             * so the sum less than max value(65535) of uint16.
             */
            page->free_end += sizeof(pcr_row_dir_t);
            page->free_size += sizeof(pcr_row_dir_t);
            page->dirs--;
        } else {
            *dir = page->first_free_dir | PCRH_DIR_NEW_MASK | PCRH_DIR_FREE_MASK;
            page->first_free_dir = (uint16)redo->slot;
        }
    } else {
        *dir = page->first_free_dir | PCRH_DIR_FREE_MASK;
        page->first_free_dir = (uint16)redo->slot;
    }

    row->is_deleted = 1;
    page->rows--;
    /* itl->fsc and row->size are both less than page size(8192) */
    itl->fsc += row->size;
    itl->ssn = redo->ssn;
    itl->undo_page = redo->undo_page;
    itl->undo_slot = redo->undo_slot;
}

/*
 * redo function
 * @param kernel session, log entry
 */
void rd_pcrh_undo_delete(knl_session_t *session, log_entry_t *log)
{
    rd_pcrh_undo_t *redo = (rd_pcrh_undo_t *)log->data;
    heap_page_t *page = (heap_page_t *)CURR_PAGE(session);
    pcr_row_dir_t *dir = pcrh_get_dir(page, (uint16)redo->slot);
    row_head_t *row = PCRH_GET_ROW(page, dir);
    pcr_itl_t *itl = pcrh_get_itl(page, ROW_ITL_ID(row));
    row_head_t *org_row = (row_head_t *)((char *)redo + sizeof(rd_pcrh_undo_t));
    errno_t ret;

    if (row->size == org_row->size) {
        /* deleted row has not been compacted, we can rollback directly */
        row->is_deleted = 0;
    } else {
        /* row has been compact, we should find a new space in page to revert delete */
        knl_panic_log(row->size == sizeof(row_head_t),
                      "row's size is abnormal, panic info: page %u-%u type %u row size %u",
                      AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type, row->size);

        if (page->free_end - page->free_begin < org_row->size) {
            *dir |= PCRH_DIR_FREE_MASK;
            pcrh_compact_page(session, page);
        }

        *dir = page->free_begin;
        /*
         * free_begin less than DEFAULT_PAGE_SIZE, row size PCRH_MAX_ROW_SIZE,
         * the sum is less than max value(65535) of uint16
         */
        page->free_begin += org_row->size;
        knl_panic_log(page->free_begin <= page->free_end, "page's free size begin is more than end, panic info: "
                      "page %u-%u type %u free_begin %u free_end %u", AS_PAGID(page->head.id).file,
                      AS_PAGID(page->head.id).page, page->head.type, page->free_begin, page->free_end);

        /* relocate the row position */
        row = PCRH_GET_ROW(page, dir);
        ret = memcpy_sp(row, page->free_end - *dir, org_row, org_row->size);
        knl_securec_check(ret);
    }

    knl_panic_log(itl->fsc >= row->size - sizeof(row_head_t),
                  "itl's fsc is abnormal, panic info: page %u-%u type %u itl fsc %u row size %u",
                  AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type, itl->fsc, row->size);
    itl->fsc -= row->size - sizeof(row_head_t);
    page->rows++;

    itl->undo_page = redo->undo_page;
    itl->undo_slot = redo->undo_slot;
    itl->ssn = redo->ssn;
    if (redo->is_xfirst) {
        ROW_SET_ITL_ID(row, CT_INVALID_ID8);
    }
}

/*
 * redo function
 * @param kernel session, log entry
 */
void rd_pcrh_undo_update(knl_session_t *session, log_entry_t *log)
{
    rd_pcrh_undo_update_t *redo = (rd_pcrh_undo_update_t *)log->data;
    heap_page_t *page = (heap_page_t *)CURR_PAGE(session);
    pcr_row_dir_t *dir = pcrh_get_dir(page, (uint16)redo->slot);
    row_head_t *row = PCRH_GET_ROW(page, dir);
    pcr_itl_t *itl = pcrh_get_itl(page, ROW_ITL_ID(row));
    row_head_t *org_row = (row_head_t *)((char *)redo + sizeof(rd_pcrh_undo_update_t));
    errno_t ret;
    int16 inc_size;

    inc_size = org_row->size - row->size;

    if (inc_size > 0) {
        if (page->free_end - page->free_begin < org_row->size) {
            *dir |= PCRH_DIR_FREE_MASK;
            pcrh_compact_page(session, page);
        }

        *dir = page->free_begin;
        /*
         * free_begin is less than DEFAULT_PAGE_SIZE, row size is less than PCRH_MAX_ROW_SIZE,
         * the sum is less than max value(65535) of uint16
         */
        page->free_begin += org_row->size;
        knl_panic_log(page->free_begin <= page->free_end, "page's free size begin is more than end, panic info: "
                      "page %u-%u type %u free_begin %u free_end %u", AS_PAGID(page->head.id).file,
                      AS_PAGID(page->head.id).page, page->head.type, page->free_begin, page->free_end);

        if (itl->fsc >= inc_size) {
            itl->fsc -= inc_size;
        } else {
            page->free_size -= (inc_size - itl->fsc);
            itl->fsc = 0;
        }

        row = PCRH_GET_ROW(page, dir);
    } else {
        itl->fsc -= inc_size;
    }

    ret = memcpy_sp(row, page->free_end - *dir, (char *)org_row, org_row->size);
    knl_securec_check(ret);

    if (redo->is_xfirst) {
        ROW_SET_ITL_ID(row, CT_INVALID_ID8);
    }
    itl->ssn = redo->ssn;
    itl->undo_page = redo->undo_page;
    itl->undo_slot = redo->undo_slot;
}

/*
 * redo function
 * @param kernel session, log entry
 */
void rd_pcrh_undo_update_next_rid(knl_session_t *session, log_entry_t *log)
{
    rd_pcrh_undo_t *redo = (rd_pcrh_undo_t *)log->data;
    heap_page_t *page = (heap_page_t *)CURR_PAGE(session);
    pcr_row_dir_t *dir = pcrh_get_dir(page, (uint16)redo->slot);
    row_head_t *row = PCRH_GET_ROW(page, dir);
    pcr_itl_t *itl = pcrh_get_itl(page, ROW_ITL_ID(row));
    rowid_t *next_rid = (rowid_t *)((char *)redo + sizeof(rd_pcrh_undo_t));

    *PCRH_NEXT_ROWID(row) = *next_rid;

    if (redo->is_xfirst) {
        ROW_SET_ITL_ID(row, CT_INVALID_ID8);
    }

    itl->ssn = redo->ssn;
    itl->undo_page = redo->undo_page;
    itl->undo_slot = redo->undo_slot;
}

/*
 * redo function
 * @param kernel session, log entry
 */
void rd_pcrh_reset_self_change(knl_session_t *session, log_entry_t *log)
{
    uint8 itl_id = *(uint8 *)log->data;
    heap_page_t *page = (heap_page_t *)CURR_PAGE(session);

    pcrh_reset_self_changed(session, page, itl_id);
}

void rd_logic_rep_head_log(knl_session_t *session, log_entry_t *log)
{
    logic_rep_ddl_head_t *redo = (logic_rep_ddl_head_t *)log->data;
    uint32 sql_len = *(uint32 *)(log->data + sizeof(logic_rep_ddl_head_t));
    char *sql_text = (char *)(log->data + sizeof(logic_rep_ddl_head_t) + sizeof(uint32));
    CT_LOG_RUN_INF("[Disaster Recovery] In the rd_logic_rep_head_log, len:%d, ddl:%s", sql_len, sql_text);
    /*
        In the no_meta_normalized mode, the ddl should also be replayed for sync the dd cache in MySQL.
    */
    if (!knl_db_is_primary(session) && !DB_ATTR_MYSQL_META_IN_DACC(session)) {
        g_knl_callback.cc_execute_replay_ddl((knl_handle_t)session, sql_text, sql_len);
        return;
    }
    log_ddl_write_file(session, redo, sql_text, sql_len);
    return;
}

/*
 * redo function
 * @param kernel session, log entry
 */
void rd_pcrh_undo_lock_link(knl_session_t *session, log_entry_t *log)
{
    rd_pcrh_undo_t *redo = (rd_pcrh_undo_t *)log->data;
    heap_page_t *page = (heap_page_t *)CURR_PAGE(session);
    pcr_row_dir_t *dir = pcrh_get_dir(page, (uint16)redo->slot);
    row_head_t *row = PCRH_GET_ROW(page, dir);
    pcr_itl_t *itl = pcrh_get_itl(page, ROW_ITL_ID(row));

    ROW_SET_ITL_ID(row, CT_INVALID_ID8);

    itl->ssn = redo->ssn;
    itl->undo_page = redo->undo_page;
    itl->undo_slot = redo->undo_slot;
}

void rd_pcrh_undo_update_link_ssn(knl_session_t *session, log_entry_t *log)
{
    rd_pcrh_undo_t *redo = (rd_pcrh_undo_t *)log->data;
    heap_page_t *page = (heap_page_t *)CURR_PAGE(session);
    pcr_row_dir_t *dir = pcrh_get_dir(page, (uint16)redo->slot);
    row_head_t *row = PCRH_GET_ROW(page, dir);
    pcr_itl_t *itl = pcrh_get_itl(page, ROW_ITL_ID(row));

    if (redo->is_xfirst) {
        ROW_SET_ITL_ID(row, CT_INVALID_ID8);
    }

    itl->ssn = redo->ssn;
    itl->undo_page = redo->undo_page;
    itl->undo_slot = redo->undo_slot;
}

void print_pcrh_init_itls(log_entry_t *log)
{
    uint32 itls = *(uint32 *)log->data;

    printf("itls %u\n", itls);
}

void print_pcrh_new_itl(log_entry_t *log)
{
    rd_pcrh_new_itl_t *redo = (rd_pcrh_new_itl_t *)log->data;

    printf("ssn %u, xid %u-%u-%u, undo_rowid %u-%u-%u\n",
           redo->ssn, (uint32)redo->xid.xmap.seg_id, (uint32)redo->xid.xmap.slot, redo->xid.xnum,
           (uint32)redo->undo_rid.page_id.file, (uint32)redo->undo_rid.page_id.page, (uint32)redo->undo_rid.slot);
}

void print_pcrh_reuse_itl(log_entry_t *log)
{
    rd_pcrh_reuse_itl_t *redo = (rd_pcrh_reuse_itl_t *)log->data;

    printf("itl_id %u, ssn %u, xid %u-%u-%u, undo_rowid %u-%u-%u\n", (uint16)redo->itl_id, redo->ssn,
           (uint32)redo->xid.xmap.seg_id, (uint32)redo->xid.xmap.slot, (uint32)redo->xid.xnum,
           (uint32)redo->undo_rid.page_id.file, (uint32)redo->undo_rid.page_id.page, (uint32)redo->undo_rid.slot);
}

void print_pcrh_clean_itl(log_entry_t *log)
{
    rd_pcrh_clean_itl_t *redo = (rd_pcrh_clean_itl_t *)log->data;

    printf("itl_id %u, scn %llu, is_owscn %u\n", (uint8)redo->itl_id, (uint64)redo->scn, (uint8)redo->is_owscn);
}

void print_pcrh_lock_row(log_entry_t *log)
{
    rd_pcrh_lock_row_t *redo = (rd_pcrh_lock_row_t *)log->data;

    printf("slot %u, itl_id %u\n", (uint32)redo->slot, (uint32)redo->itl_id);
}

void print_pcrh_update_link_ssn(log_entry_t *log)
{
    pcrh_update_link_ssn_t *redo = (pcrh_update_link_ssn_t *)log->data;

    printf("slot %u, ssn %u, undo_page: %u-%u, undo_slot %u\n", (uint32)redo->slot, redo->ssn,
           (uint32)redo->undo_page.file, (uint32)redo->undo_page.page, (uint32)redo->undo_slot);
}

void print_pcrh_insert(log_entry_t *log)
{
    rd_pcrh_insert_t *redo = (rd_pcrh_insert_t *)log->data;
    row_head_t *row = (row_head_t *)redo->data;

    printf("ssn %u, undo_page %u-%u, undo_slot %u, itl_id %u ",
           redo->ssn, (uint32)redo->undo_page.file, (uint32)redo->undo_page.page,
           (uint32)redo->undo_slot, (uint32)ROW_ITL_ID(row));
    printf("size %u, cols %u, deleted/link/migr/changed/self_chg %u/%u/%u/%u/%u\n",
           (uint32)row->size, (uint32)ROW_COLUMN_COUNT(row),
           (uint32)row->is_deleted, (uint32)row->is_link, (uint32)row->is_migr,
           (uint32)row->is_changed, (uint32)row->self_chg);
}

void print_pcrh_update_inplace(log_entry_t *log)
{
    rd_pcrh_update_inplace_t *rd = (rd_pcrh_update_inplace_t *)log->data;
    uint16 *columns = (uint16 *)rd->columns;
    uint16 i;

    printf("slot %u, count %u, columns %u", (uint32)rd->slot, (uint32)rd->count, (uint32)rd->columns[0]);
    for (i = 1; i < rd->count; i++) {
        printf(", %u", (uint32)columns[i]);
    }
    printf("\n");
}

void print_pcrh_update_inpage(log_entry_t *log)
{
    rd_pcrh_update_inpage_t *rd = (rd_pcrh_update_inpage_t *)log->data;
    uint16 *columns = (uint16 *)rd->columns;
    uint16 i;

    printf("slot %u, count %u, cols %u, inc_size %d, columns %u",
           (uint32)rd->slot, (uint32)rd->count, (uint32)rd->new_cols, (int32)rd->inc_size, (uint32)columns[0]);
    for (i = 1; i < rd->count; i++) {
        printf(", %u", (uint32)columns[i]);
    }
    printf("\n");
}

void print_pcrh_delete(log_entry_t *log)
{
    rd_pcrh_delete_t *redo = (rd_pcrh_delete_t *)log->data;

    printf("slot %u, ssn %u, undo_page: %u-%u, undo_slot %u\n", (uint32)redo->slot, redo->ssn,
           (uint32)redo->undo_page.file, (uint32)redo->undo_page.page, (uint32)redo->undo_slot);
}

void print_pcrh_convert_link(log_entry_t *log)
{
    pcrh_set_next_rid_t *redo = (pcrh_set_next_rid_t *)log->data;

    printf("slot %u, ssn %u, undo_page: %u-%u, undo_slot %u, next rowid %u-%u-%u\n", (uint32)redo->slot,
           redo->ssn, (uint32)redo->undo_page.file, (uint32)redo->undo_page.page, (uint32)redo->undo_slot,
           (uint32)redo->next_rid.file, (uint32)redo->next_rid.page, (uint32)redo->next_rid.slot);
}

void print_pcrh_update_next_rid(log_entry_t *log)
{
    pcrh_set_next_rid_t *redo = (pcrh_set_next_rid_t *)log->data;

    printf("slot %u, ssn %u, undo_page: %u-%u, undo_slot %u, next rowid %u-%u-%u\n", (uint32)redo->slot,
           redo->ssn, (uint32)redo->undo_page.file, (uint32)redo->undo_page.page, (uint32)redo->undo_slot,
           (uint32)redo->next_rid.file, (uint32)redo->next_rid.page, (uint32)redo->next_rid.slot);
}

void print_pcrh_undo_itl(log_entry_t *log)
{
    pcr_itl_t *redo = (pcr_itl_t *)log->data;
    uint8 itl_id = *(uint8 *)(log->data + sizeof(pcr_itl_t));

    printf("itl_id %u, scn %llu, is_owscn %u, xid: %u-%u-%u, undo_page %u-%u, undo_slot %u\n",
           itl_id, redo->scn, (uint32)redo->is_owscn,
           (uint32)redo->xid.xmap.seg_id, (uint32)redo->xid.xmap.slot, redo->xid.xnum,
           (uint32)redo->undo_page.file, (uint32)redo->undo_page.page, (uint32)redo->undo_slot);
}

void print_pcrh_undo_insert(log_entry_t *log)
{
    rd_pcrh_undo_t *redo = (rd_pcrh_undo_t *)log->data;

    printf("slot %u, ssn %u, undo_page: %u-%u, undo_slot %u, is_xfirst %u\n",
           (uint32)redo->slot, redo->ssn, (uint32)redo->undo_page.file,
           (uint32)redo->undo_page.page, (uint16)redo->undo_slot, (uint16)redo->is_xfirst);
}

void print_pcrh_undo_delete(log_entry_t *log)
{
    rd_pcrh_undo_t *redo = (rd_pcrh_undo_t *)log->data;

    printf("slot %u, ssn %u, undo_page: %u-%u, undo_slot %u, is_xfirst %u\n",
           (uint32)redo->slot, redo->ssn, (uint32)redo->undo_page.file, (uint32)redo->undo_page.page,
           (uint16)redo->undo_slot, (uint16)redo->is_xfirst);
}

void print_pcrh_undo_update(log_entry_t *log)
{
    rd_pcrh_undo_update_t *redo = (rd_pcrh_undo_update_t *)log->data;

    printf("slot %u, ssn %u, undo_page: %u-%u, undo_slot %u, is_xfirst %u\n",
           (uint32)redo->slot, redo->ssn, (uint32)redo->undo_page.file, (uint32)redo->undo_page.page,
           (uint16)redo->undo_slot, redo->is_xfirst);
}

void print_pcrh_undo_lock_link(log_entry_t *log)
{
    rd_pcrh_undo_t *redo = (rd_pcrh_undo_t *)log->data;

    printf("slot %u, ssn %u, undo_page: %u-%u, undo_slot %u, is_xfirst %u\n",
           (uint32)redo->slot, redo->ssn, (uint32)redo->undo_page.file, (uint32)redo->undo_page.page,
           (uint32)redo->undo_slot, (uint32)redo->is_xfirst);
}

void print_pcrh_undo_update_link_ssn(log_entry_t *log)
{
    rd_pcrh_undo_t *redo = (rd_pcrh_undo_t *)log->data;

    printf("slot %u, ssn %u, undo_page: %u-%u, undo_slot %u, is_xfirst %u\n",
           (uint32)redo->slot, redo->ssn, (uint32)redo->undo_page.file, (uint32)redo->undo_page.page,
           (uint32)redo->undo_slot, (uint32)redo->is_xfirst);
}

void print_pcrh_undo_update_next_rid(log_entry_t *log)
{
    rd_pcrh_undo_t *redo = (rd_pcrh_undo_t *)log->data;
    rowid_t *next_rid = (rowid_t *)((char *)redo + sizeof(rd_pcrh_undo_t));

    printf("slot %u, ssn %u, undo_page: %u-%u, undo_slot %u, is_xfirst %u, next rowid %u-%u-%u\n",
           (uint32)redo->slot, redo->ssn, (uint32)redo->undo_page.file,
           (uint32)redo->undo_page.page, (uint32)redo->undo_slot, (uint32)redo->is_xfirst,
           (uint32)next_rid->file, (uint32)next_rid->page, (uint32)next_rid->slot);
}

void print_pcrh_reset_self_change(log_entry_t *log)
{
    uint8 itl_id = *(uint8 *)log->data;

    printf("itl_id %u\n", (uint32)itl_id);
}

