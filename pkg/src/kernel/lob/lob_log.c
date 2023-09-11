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
 * lob_log.c
 *
 *
 * IDENTIFICATION
 * src/kernel/lob/lob_log.c
 *
 * -------------------------------------------------------------------------
 */
#include "lob_log.h"
#include "knl_lob.h"
#include "knl_context.h"

void rd_lob_put_chunk(knl_session_t *session, log_entry_t *log)
{
    lob_chunk_t *chunk = (lob_chunk_t *)log->data;
    lob_chunk_t *dst_chunk = LOB_GET_CHUNK(session);
    errno_t ret;

    ret = memcpy_sp(dst_chunk, OFFSET_OF(lob_chunk_t, data) + chunk->size, chunk,
        OFFSET_OF(lob_chunk_t, data) + chunk->size);
    knl_securec_check(ret);
}

void rd_lob_page_init(knl_session_t *session, log_entry_t *log)
{
    page_head_t *head = (page_head_t *)log->data;
    page_head_t *curr_head = (page_head_t *)CURR_PAGE(session);
    page_tail_t *tail = NULL;
    errno_t ret;

    ret = memset_sp(curr_head, DEFAULT_PAGE_SIZE(session), 0, DEFAULT_PAGE_SIZE(session));
    knl_securec_check(ret);
    ret = memcpy_sp(curr_head, DEFAULT_PAGE_SIZE(session), head, sizeof(page_head_t));
    knl_securec_check(ret);
    tail = PAGE_TAIL(curr_head);
    tail->pcn = curr_head->pcn;
    lob_init_page(session, AS_PAGID(head->id), head->type, GS_FALSE);
}

void rd_lob_page_ext_init(knl_session_t *session, log_entry_t *log)
{
    page_head_t *head = (page_head_t *)log->data;
    page_head_t *curr_head = (page_head_t *)CURR_PAGE(session);
    page_tail_t *tail = NULL;
    errno_t ret;

    ret = memcpy_sp(curr_head, DEFAULT_PAGE_SIZE(session), head, sizeof(page_head_t));
    knl_securec_check(ret);
    tail = PAGE_TAIL(curr_head);
    tail->pcn = curr_head->pcn;
    lob_init_page(session, AS_PAGID(head->id), head->type, GS_FALSE);
}

void rd_lob_change_seg(knl_session_t *session, log_entry_t *log)
{
    lob_segment_t *seg = (lob_segment_t *)log->data;
    uint16 size = log->size - LOG_ENTRY_SIZE;
    errno_t ret;

    ret = memcpy_sp(LOB_SEG_HEAD(session), sizeof(lob_segment_t), seg, size);
    knl_securec_check(ret);
}

void rd_lob_change_chunk(knl_session_t *session, log_entry_t *log)
{
    lob_chunk_t *chunk = (lob_chunk_t *)log->data;
    lob_chunk_t *dst_chunk = LOB_GET_CHUNK(session);
    errno_t ret;

    ret = memcpy_sp(dst_chunk, LOB_MAX_CHUNK_SIZE(session), chunk, sizeof(lob_chunk_t));
    knl_securec_check(ret);
}

void redo_lob_change_page_free(knl_session_t *session, log_entry_t *log_entry)
{
    page_id_t *page_id = (page_id_t *)log_entry->data;
    lob_data_page_t *dst_data = LOB_CURR_DATA_PAGE(session);

    dst_data->pre_free_page = *page_id;
}

void print_lob_put_chunk(log_entry_t *log)
{
    lob_chunk_t *chunk = (lob_chunk_t *)log->data;
    printf("insert_xid: xmap %u-%u, xnum %u, ",
           (uint32)chunk->ins_xid.xmap.seg_id, (uint32)chunk->ins_xid.xmap.slot, chunk->ins_xid.xnum);
    printf("delete_xid: xmap %u-%u, xnum %u, ",
           (uint32)chunk->del_xid.xmap.seg_id, (uint32)chunk->del_xid.xmap.slot, chunk->del_xid.xnum);
    printf("org_scn %llu, ", chunk->org_scn);
    printf("size %u, ", chunk->size);
    printf("next %u-%u, ", (uint32)chunk->next.file, (uint32)chunk->next.page);
    printf("free_next %u-%u, ", (uint32)chunk->free_next.file, (uint32)chunk->free_next.page);
    printf("is_recycled: %u\n", (uint32)chunk->is_recycled);
}

void print_lob_page_init(log_entry_t *log)
{
    page_head_t *head = (page_head_t *)log->data;
    printf("next_ext %u-%u\n", (uint32)AS_PAGID_PTR(head->next_ext)->file,
           (uint32)AS_PAGID_PTR(head->next_ext)->page);
}

void print_lob_change_seg(log_entry_t *log)
{
    lob_segment_t *seg = (lob_segment_t *)log->data;
    printf("uid %u, table_id %u, column_id %u, space_id %u, ", seg->uid, seg->table_id, seg->column_id, seg->space_id);
    printf("extents(count %u, first %u-%u, last %u-%u), free_list(count %u, first %u-%u, last %u-%u), ",
           seg->extents.count,
           (uint32)seg->extents.first.file, (uint32)seg->extents.first.page, (uint32)seg->extents.last.file,
           (uint32)seg->extents.last.page,
           seg->free_list.count, (uint32)seg->free_list.first.file, (uint32)seg->free_list.first.page,
           (uint32)seg->free_list.last.file, (uint32)seg->free_list.last.page);
    printf("ufp_count %u, ufp_first %u-%u, ufp_extent %u-%u\n", seg->ufp_count,
           (uint32)seg->ufp_first.file, (uint32)seg->ufp_first.page, (uint32)seg->ufp_extent.file,
           (uint32)seg->ufp_extent.page);
}

void print_lob_change_chunk(log_entry_t *log)
{
    lob_chunk_t *chunk = (lob_chunk_t *)log->data;
    printf("insert_xid: xmap %u-%u, xnum %u, ",
           (uint32)chunk->ins_xid.xmap.seg_id, (uint32)chunk->ins_xid.xmap.slot, chunk->ins_xid.xnum);
    printf("delete_xid: xmap %u-%u, xnum %u, ",
           (uint32)chunk->del_xid.xmap.seg_id, (uint32)chunk->del_xid.xmap.slot, chunk->del_xid.xnum);
    printf("org_scn %llu, ", chunk->org_scn);
    printf("size %u, ", chunk->size);
    printf("next %u-%u, ", (uint32)chunk->next.file, (uint32)chunk->next.page);
    printf("free_next %u-%u, ", (uint32)chunk->free_next.file, (uint32)chunk->free_next.page);
    printf("is_recycled: %u\n", (uint32)chunk->is_recycled);
}

void print_lob_changed_page_unused(log_entry_t *log)
{
    page_id_t *page_id = (page_id_t *)log->data;
    printf("pre_free page: %u-%u\n", page_id->file, page_id->page);
}

void print_lob_page_ext_init(log_entry_t *log)
{
    page_head_t *head = (page_head_t *)log->data;
    printf("next_ext %u-%u\n", (uint32)AS_PAGID_PTR(head->next_ext)->file,
           (uint32)AS_PAGID_PTR(head->next_ext)->page);
}
