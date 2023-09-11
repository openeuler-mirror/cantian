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
 * knl_map_log.c
 *
 *
 * IDENTIFICATION
 * src/kernel/table/knl_map_log.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_map_log.h"
#include "knl_context.h"
#include "knl_heap.h"


void rd_heap_format_page(knl_session_t *session, log_entry_t *log)
{
    heap_page_t *page = (heap_page_t *)CURR_PAGE(session);
    int32 ret;

    ret = memset_sp(page, DEFAULT_PAGE_SIZE(session), 0, DEFAULT_PAGE_SIZE(session));
    knl_securec_check(ret);
    ret = memcpy_sp(page, DEFAULT_PAGE_SIZE(session), log->data, (uint32)OFFSET_OF(heap_page_t, reserved));
    knl_securec_check(ret);
}

void print_heap_format_page(log_entry_t *log)
{
    heap_page_t *page = (heap_page_t *)log->data;
    printf("uid %u, oid %u, seg_scn %llu, org_scn %llu, free_begin %u, free_end %u, free_size %u,free_dir %u\n",
        page->uid, page->oid, page->seg_scn, page->org_scn,
        (uint32)page->free_begin, (uint32)page->free_end, (uint32)page->free_size, (uint32)page->first_free_dir);
}

void rd_heap_concat_page(knl_session_t *session, log_entry_t *log)
{
    page_id_t *page_id = (page_id_t *)log->data;
    heap_page_t *page = (heap_page_t *)CURR_PAGE(session);
    TO_PAGID_DATA(*page_id, page->next);
}

void print_heap_concat_page(log_entry_t *log)
{
    page_id_t *page_id = (page_id_t *)log->data;
    printf("page %u-%u\n", (uint32)page_id->file, (uint32)page_id->page);
}

void rd_heap_format_map(knl_session_t *session, log_entry_t *log)
{
    map_page_t *page = (map_page_t *)CURR_PAGE(session);
    rd_heap_format_page_t *redo = (rd_heap_format_page_t *)log->data;

    heap_format_map(session, page, redo->page_id, redo->extent_size);
}

void print_heap_format_map(log_entry_t *log)
{
    page_id_t page_id = *(page_id_t *)log->data;
    printf("map %u-%u\n", (uint32)page_id.file, (uint32)page_id.page);
}

void rd_heap_format_entry(knl_session_t *session, log_entry_t *log)
{
    rd_heap_format_page_t *redo = (rd_heap_format_page_t *)log->data;
    page_head_t *page = (page_head_t *)CURR_PAGE(session);

    page_init(session, page, redo->page_id, PAGE_TYPE_HEAP_HEAD);
    page->ext_size = spc_ext_id_by_size(redo->extent_size);
}

void print_heap_format_entry(log_entry_t *log)
{
    page_id_t *page_id = (page_id_t *)log->data;
    printf("entry %u-%u\n", (uint32)page_id->file, (uint32)page_id->page);
}

void rd_heap_alloc_map_node(knl_session_t *session, log_entry_t *log)
{
    rd_alloc_map_node_t *redo = (rd_alloc_map_node_t *)log->data;
    map_page_t *page = (map_page_t *)CURR_PAGE(session);
    map_node_t *node = NULL;

    heap_insert_into_list(page, &page->lists[redo->lid], page->hwm);
    node = heap_get_map_node(CURR_PAGE(session), page->hwm);
    node->file = redo->file;
    node->page = redo->page;
    page->hwm++;
}

void print_heap_alloc_map_node(log_entry_t *log)
{
    rd_alloc_map_node_t *redo = (rd_alloc_map_node_t *)log->data;
    printf("node page %u-%u, lid %u\n", (uint32)redo->file, (uint32)redo->page, redo->lid);
}

void rd_heap_change_seg(knl_session_t *session, log_entry_t *log)
{
    heap_segment_t *segment = (heap_segment_t *)(CURR_PAGE(session) + PAGE_HEAD_SIZE);
    errno_t ret;
    uint16 size = log->size - LOG_ENTRY_SIZE;
    ret = memcpy_sp(segment, sizeof(heap_segment_t), log->data, size);
    knl_securec_check(ret);
}

void print_heap_change_seg(log_entry_t *log)
{
    heap_segment_t *seg = (heap_segment_t *)log->data;
    knl_tree_info_t *tree_info = &seg->tree_info;

    printf("uid %u, oid %u, space %u, initrans %u, org_scn %llu, seg_scn %llu, crmode %u, serial %llu ",
        seg->uid, seg->oid, seg->space_id, seg->initrans, seg->org_scn, seg->seg_scn, seg->cr_mode, seg->serial);
    printf("map(root %u-%u, level %u), extents(count %u, first %u-%u, last %u-%u), "
        "free_extents(count %u, first %u-%u, last %u-%u), data_first %u-%u, data_last %u-%u, "
        "ufp_count %u, free_ufp %u-%u, cmp_hwm %u-%u\n, shrinkable_scn %llu, page_count %u,"
        " free_page_count %u, last_ext_size %u ",
        (uint32)AS_PAGID(tree_info->root).file, (uint32)AS_PAGID(tree_info->root).page, (uint32)tree_info->level,
        seg->extents.count, (uint32)seg->extents.first.file, (uint32)seg->extents.first.page,
        (uint32)seg->extents.last.file, (uint32)seg->extents.last.page,
        seg->free_extents.count, (uint32)seg->free_extents.first.file, (uint32)seg->free_extents.first.page,
        (uint32)seg->free_extents.last.file, (uint32)seg->free_extents.last.page,
        (uint32)seg->data_first.file, (uint32)seg->data_first.page,
        (uint32)seg->data_last.file, (uint32)seg->data_last.page,
        (uint32)seg->ufp_count, (uint32)seg->free_ufp.file, (uint32)seg->free_ufp.page,
        (uint32)seg->cmp_hwm.file, (uint32)seg->cmp_hwm.page,
        (uint64)seg->shrinkable_scn,
        seg->page_count, seg->free_page_count, (uint32)seg->last_ext_size);
}

void rd_heap_set_map(knl_session_t *session, log_entry_t *log)
{
    map_page_t *page = (map_page_t *)CURR_PAGE(session);
    errno_t ret;
    ret = memcpy_sp(&page->map, sizeof(map_index_t), log->data, sizeof(map_index_t));
    knl_securec_check(ret);
}

void print_heap_set_map(log_entry_t *log)
{
    map_index_t *index = (map_index_t *)log->data;
    printf("map %u-%u, slot %u, lid %u\n",
        (uint32)index->file, (uint32)index->page, (uint32)index->slot, (uint32)index->list_id);
}

void rd_heap_change_map(knl_session_t *session, log_entry_t *log)
{
    rd_change_map_t *redo = (rd_change_map_t *)log->data;
    map_page_t *page = (map_page_t *)CURR_PAGE(session);

    heap_remove_from_list(page, &page->lists[redo->old_lid], redo->slot);
    heap_insert_into_list(page, &page->lists[redo->new_lid], redo->slot);
}

void print_heap_change_map(log_entry_t *log)
{
    rd_change_map_t *redo = (rd_change_map_t *)log->data;
    printf("slot %u, old_lid %u new_lid %u\n", (uint32)redo->slot, (uint32)redo->old_lid, (uint32)redo->new_lid);
}

void rd_heap_shrink_map(knl_session_t *session, log_entry_t *log)
{
    uint16 slot = *(uint16 *)log->data;
    map_page_t *page = (map_page_t *)CURR_PAGE(session);

    heap_shrink_mappage(page, slot);
}

void print_heap_shrink_map(log_entry_t *log)
{
    uint16 slot = *(uint16 *)log->data;
    printf("slot %u\n", (uint32)slot);
}

void rd_heap_change_list(knl_session_t *session, log_entry_t *log)
{
    heap_page_t *page = (heap_page_t *)CURR_PAGE(session);
    page->map.list_id = *(uint8 *)log->data;
}

void print_heap_change_list(log_entry_t *log)
{
    uint8 lid = *(uint8 *)log->data;
    printf("lid %u\n", (uint32)lid);
}

