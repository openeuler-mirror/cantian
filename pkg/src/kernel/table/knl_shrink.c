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
 * knl_shrink.c
 *
 *
 * IDENTIFICATION
 * src/kernel/table/knl_shrink.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_table_module.h"
#include "knl_table.h"
#include "temp_btree.h"
#include "knl_map.h"
#include "knl_space_manage.h"

static inline bool32 heap_try_reset_seg_page_cnt(heap_segment_t *segment)
{
    // if only 1 extent left, recover calc logic (now, free extent also empty)
    if (segment->extents.count <= 1 && segment->free_extents.count == 0) {
        heap_reset_page_count(segment);
        return CT_TRUE;
    }
    return CT_FALSE;
}

static void heap_try_shrink_seg_page_cnt(space_t *space, heap_segment_t *segment,
    uint32 shrink_page_count, uint32 curr_ext_size)
{
    // if it is bitmap space, try to update page_count
    if (SPACE_IS_AUTOALLOCATE(space) && HEAP_SEG_BITMAP_IS_DEGRADE(segment)) {
        // if segment reset succeed, return.
        if (heap_try_reset_seg_page_cnt(segment)) {
            return;
        }

        // shrink can not shrink all pages, at least keep 1 extent
        knl_panic(segment->page_count > shrink_page_count);
        segment->page_count -= shrink_page_count;
        segment->free_page_count = 0;
        segment->last_ext_size = curr_ext_size;
    }
}

/*
 * heap get shrink extents
 * @param session, segment, new extent hwm, shrink extent list
 */
static uint32 heap_fetch_shrink_extents(knl_session_t *session, space_t *space, heap_segment_t *segment,
    page_id_t ext_hwm, page_list_t *extents)
{
    page_id_t page_id;
    uint32 ext_size;
    uint32 page_count = 0;  // page_count is only use in BIT MAP and alloc extent degraded
    extents->count = 0;

    if (IS_SAME_PAGID(ext_hwm, segment->extents.last)) {
        return page_count;
    }

    page_id = ext_hwm;

    while (!IS_SAME_PAGID(page_id, segment->extents.last)) {
        page_id = spc_get_size_next_ext(session, space, page_id, &ext_size);
        // if not bitmap or alloc extent degraded, just count, no use
        page_count += ext_size;
        if (extents->count == 0) {
            page_count = 0;
            extents->first = page_id;
        }

        extents->last = page_id;
        extents->count++;
    }

    // page_count is only use in BIT MAP and alloc extent degraded
    if (SPACE_IS_AUTOALLOCATE(space) && segment->page_count != 0) {
        (void)spc_get_size_next_ext(session, space, page_id, &ext_size);
        page_count += ext_size;
    }

    knl_panic_log(extents->count < segment->extents.count, "shrink's extent counts is more than segment's, "
                  "panic info: page %u-%u shrink's extent counts %u segment's %u",
                  page_id.file, page_id.page, extents->count, segment->extents.count);

    return page_count;
}

/*
 * heap init traversal map for shrink
 * @note function must be called before traversal map
 * @param heap, map path
 */
void heap_shrink_initialize_map_path(knl_session_t *session, knl_handle_t heap_handle, map_path_t *path)
{
    heap_t *heap = (heap_t *)heap_handle;
    knl_tree_info_t tree_info;
    map_index_t *index = NULL;
    page_id_t map_id;
    int32 ret;

    ret = memset_sp(path, sizeof(map_path_t), 0, sizeof(map_path_t));
    knl_securec_check(ret);

    tree_info.value = cm_atomic_get(&HEAP_SEGMENT(session, heap->entry, heap->segment)->tree_info.value);
    map_id = AS_PAGID(tree_info.root);
    path->level = tree_info.level;

    // init root map path
    index = &path->index[path->level];
    index->file = map_id.file;
    index->page = map_id.page;
    index->slot = INVALID_SLOT;
}

/*
 * heap shrink map page
 * Shrink the current map page from the given map node slot.
 * @param map page, map node slot
 */
void heap_shrink_mappage(map_page_t *page, uint16 slot)
{
    map_node_t *node = NULL;
    uint16 curr, next;
    uint8 i;

    knl_panic_log(slot < page->hwm, "curr page slot is more than hwm, panic info: page %u-%u type %u slot %u hwm %u",
                  AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type, slot, page->hwm);

    for (i = 0; i < HEAP_FREE_LIST_COUNT; i++) {
        curr = page->lists[i].first;

        while (curr != INVALID_SLOT) {
            node = heap_get_map_node((char *)page, curr);
            next = (uint16)node->next;

            if (curr > slot) {
                heap_remove_from_list(page, &page->lists[i], curr);
            }

            curr = next;
        }
    }

    page->hwm = slot + 1;
}

/*
 * heap get shrink hwm
 * @param session, compact hwm, shrink hwm
 */
void heap_fetch_shrink_hwm(knl_session_t *session, page_id_t cmp_hwm, page_id_t *hwm)
{
    heap_page_t *page = NULL;
    page_id_t page_id;

    *hwm = cmp_hwm;
    page_id = cmp_hwm;

    while (!IS_INVALID_PAGID(page_id)) {
        buf_enter_page(session, page_id, LATCH_MODE_S, ENTER_PAGE_NORMAL);
        page = (heap_page_t *)CURR_PAGE(session);
        if (page->rows > 0) {
            *hwm = page_id;
        }

        page_id = AS_PAGID(page->next);
        buf_leave_page(session, CT_FALSE);
    }
}

/*
 * we need to search the extent list of segment to find out first and last page in
 * extent on bitmap management space.
 */
static void heap_get_extent_range(knl_session_t *session, heap_segment_t *segment, page_id_t page_id,
    page_id_t *first, page_id_t *last)
{
    page_id_t extent;
    page_head_t *page = NULL;
    uint32 extent_size;

    extent = segment->extents.first;
    for (;;) {
        buf_enter_page(session, extent, LATCH_MODE_S, ENTER_PAGE_NORMAL);
        page = (page_head_t *)CURR_PAGE(session);
        extent_size = spc_ext_size_by_id((uint8)page->ext_size);

        if (IS_SAME_PAGID(extent, segment->extents.last)) {
            buf_leave_page(session, CT_FALSE);
            break;
        }

        if (page_id.file == extent.file && page_id.page >= extent.page && page_id.page < extent.page + extent_size) {
            buf_leave_page(session, CT_FALSE);
            break;
        }

        extent = AS_PAGID(page->next_ext);
        buf_leave_page(session, CT_FALSE);
    }

    *first = extent;
    extent.page += extent_size - 1;
    *last = extent;
}

static uint32 heap_get_page_extent_size(knl_session_t *session, space_t *space, page_id_t extent)
{
    buf_enter_page(session, extent, LATCH_MODE_S, ENTER_PAGE_NORMAL);
    page_head_t *page = (page_head_t *)session->curr_page;
    uint32 ext_size = spc_get_page_ext_size(space, page->ext_size);
    buf_leave_page(session, CT_FALSE);
    return ext_size;
}

static void heap_replace_map_root(knl_session_t *session, heap_segment_t *segment, map_path_t *path)
{
    uint16 new_level;
    page_id_t page_id = INVALID_PAGID;
    knl_tree_info_t tree_info;

    tree_info.value = cm_atomic_get(&segment->tree_info.value);

    /* get new root map page id */
    knl_panic_log(tree_info.level > HEAP_MAP_LEVEL1, "map tree's level incorrect, panic info: level %u",
                  tree_info.level);
    if (tree_info.level == HEAP_MAP_LEVEL3) {
        knl_panic_log(path->index[HEAP_MAP_LEVEL3].slot == 0, "map slot is abnormal, panic info: map slot %u",
                      path->index[HEAP_MAP_LEVEL3].slot);
        /* change map tree from three level to one level */
        if (path->index[HEAP_MAP_LEVEL2].slot == 0) {
            new_level = HEAP_MAP_LEVEL1;
        } else {
            /* change map tree from three level to two level */
            new_level = HEAP_MAP_LEVEL2;
        }
    } else {
        /* change map tree from two level to one level */
        new_level = HEAP_MAP_LEVEL1;
    }

    page_id.file = (uint16)path->index[new_level].file;
    page_id.page = (uint32)path->index[new_level].page;
    page_id.aligned = 0;
    
    knl_panic_log(!IS_INVALID_PAGID(page_id), "current page is invalid, panic info: page %u-%u", page_id.file,
                  page_id.page);
    /* set new map tree root */
    buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    map_page_t *page = (map_page_t *)CURR_PAGE(session);
    page->map.file = INVALID_FILE_ID;
    page->map.page = 0;
    page->map.slot = INVALID_SLOT;
    page->map.list_id = 0;
    if (SPACE_IS_LOGGING(SPACE_GET(session, segment->space_id))) {
        log_put(session, RD_HEAP_SET_MAP, &page->map, sizeof(map_index_t), LOG_ENTRY_FLAG_NONE);
    }

    buf_leave_page(session, CT_TRUE);
    tree_info.level = new_level;
    AS_PAGID_PTR(tree_info.root)->file = page_id.file;
    AS_PAGID_PTR(tree_info.root)->page = page_id.page;
    (void)cm_atomic_set(&segment->tree_info.value, tree_info.value);
}

/*
 * heap shrink map
 * Shrink the heap map tree from the given map path:
 * 1. Map pages after the page in map path in the same level are removed directly.
 * 2. Map nodes after the node in the same page in map path are removed one by one.
 * @note if the shrink slot is the max node of the page, we set the current map to
 * invalid page id so the following segment extension would alloc new map.
 * @param kernel session, heap segment, map path
 */
static void heap_shrink_map_tree(knl_session_t *session, heap_segment_t *segment, map_path_t *path)
{
    knl_tree_info_t tree_info;
    map_page_t *page = NULL;
    page_id_t page_id;
    uint16 slot, max_nodes;
    uint16 i, level;
    uint8 last_lid;

    level = 0;
    max_nodes = (uint16)session->kernel->attr.max_map_nodes;  // the max value of max_map_nodes is 1014

    tree_info.value = cm_atomic_get(&segment->tree_info.value);

    for (i = 0; i <= tree_info.level; i++) {
        slot = (uint16)path->index[i].slot;
        page_id.file = (uint16)path->index[i].file;
        page_id.page = (uint32)path->index[i].page;
        page_id.aligned = 0;

        if (i > 0) {
            segment->map_count[i - 1] = slot + 1;
        }

        /* only when the root page to be free, it can not shrink the map page */
        if (tree_info.level > 0 && slot == 0 && i == tree_info.level) {
            segment->map_count[i] = 0;
            segment->curr_map[i] = INVALID_PAGID;
            continue;
        } else if (slot + 1 == max_nodes) {
            segment->curr_map[i] = INVALID_PAGID;
        } else {
            segment->curr_map[i] = page_id;

            buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_NORMAL);
            page = (map_page_t *)CURR_PAGE(session);
            if (slot + 1 == page->hwm) {
                buf_leave_page(session, CT_FALSE);
            } else {
                // Remove map node from map page
                heap_shrink_mappage(page, slot);
                if (SPACE_IS_LOGGING(SPACE_GET(session, segment->space_id))) {
                    log_put(session, RD_HEAP_SHRINK_MAP, &slot, sizeof(uint16), LOG_ENTRY_FLAG_NONE);
                }

                // Change Current Map List ID and upper level map
                // Previous action may cause changes of map list
                last_lid = heap_find_last_list(page);
                if (last_lid != page->map.list_id && i < tree_info.level) {
                    heap_change_map(session, segment, &page->map, last_lid, i + 1);
                }

                buf_leave_page(session, CT_TRUE);
            }
        }

        level = i;
    }

    // shrink root map
    if (tree_info.level > level) {
        heap_replace_map_root(session, segment, path);
    }
}

/*
 * get the last page id in format unit of given page
 */
static inline void heap_get_format_unit_last(knl_session_t *session, page_id_t page_id, page_id_t *fmt_last)
{
    datafile_t *df = DATAFILE_GET(session, page_id.file);
    space_t *space = SPACE_GET(session, df->space_id);
    uint32 start_id = spc_first_extent_id(session, space, page_id);
    uint32 offset;

    offset = HEAP_PAGE_FORMAT_UNIT - (page_id.page - start_id) % HEAP_PAGE_FORMAT_UNIT - 1;
    *fmt_last = page_id;
    fmt_last->page += offset;
}

/*
 * heap shrink hwm
 * Shrink the current heap segment, we do this work when holding the table
 * exclusive lock. No concurrent modify operation on it, and query may return
 * page reused error.
 * We detect the accurate hwm by checking all pages from the compact hwm, shrink
 * all map page after the accurate hwm, update the segment info.
 * @param kernel session, heap handle
 */
void heap_shrink_hwm(knl_session_t *session, knl_handle_t heap_handle, bool32 async_shrink)
{
    map_path_t path;
    page_list_t extents;
    page_id_t hwm, next;
    page_id_t last_ext, ext_last, fmt_last;
    uint32 ufp_count;

    heap_t *heap = (heap_t *)heap_handle;
    heap_segment_t *segment = HEAP_SEGMENT(session, heap->entry, heap->segment);

    heap_fetch_shrink_hwm(session, segment->cmp_hwm, &hwm);
    heap_get_map_path(session, heap, hwm, &path);

    if (async_shrink && !IS_SAME_PAGID(segment->cmp_hwm, hwm)) {
#ifdef LOG_DIAG
        knl_panic_log(CT_FALSE, "asyn shrink compcat hwm is not credible.curr hwm %u-%u, new hwm %u-%u, "
            "uid %u, oid %u, entry %u-%u", segment->cmp_hwm.file,
            segment->cmp_hwm.page, hwm.file, hwm.page, segment->uid,
            segment->oid, heap->entry.file, heap->entry.page);
#endif
        CT_LOG_RUN_WAR("asyn shrink compcat hwm is not credible.curr hwm %u-%u, "
            "new hwm %u-%u, uid %u, oid %u, entry %u-%u", segment->cmp_hwm.file,
            segment->cmp_hwm.page, hwm.file, hwm.page, segment->uid,
            segment->oid, heap->entry.file, heap->entry.page);
    }

    space_t *space = SPACE_GET(session, segment->space_id);

    if (SPACE_IS_BITMAPMANAGED(space)) {
        heap_get_extent_range(session, segment, hwm, &last_ext, &ext_last);
    } else {
        last_ext = spc_get_extent_first(session, space, hwm);
        ext_last.file = last_ext.file;
        ext_last.page = last_ext.page + space->ctrl->extent_size - 1;
        ext_last.aligned = 0;
    }

    if (ext_last.page != hwm.page) {
        next.file = hwm.file;
        next.page = hwm.page + 1;
        next.aligned = 0;
        ufp_count = ext_last.page - hwm.page;  // ext_last.page is GE hwm.page
    } else {
        next = INVALID_PAGID;
        ufp_count = 0;
    }

    // page count for shrinked page count
    uint32 page_count = heap_fetch_shrink_extents(session, space, segment, last_ext, &extents);
    // the ext size of hwm belonged
    uint32 hwm_ext_size = heap_get_page_extent_size(session, space, last_ext);

    log_atomic_op_begin(session);

    if (!IS_SAME_PAGID(hwm, segment->data_last)) {
        buf_enter_page(session, hwm, LATCH_MODE_X, ENTER_PAGE_NORMAL);
        TO_PAGID_DATA(INVALID_PAGID, ((heap_page_t *)CURR_PAGE(session))->next);
        if (SPACE_IS_LOGGING(space)) {
            log_put(session, RD_HEAP_CONCAT_PAGE, &INVALID_PAGID, sizeof(page_id_t), LOG_ENTRY_FLAG_NONE);
        }
        buf_leave_page(session, CT_TRUE);
    }

    buf_enter_page(session, heap->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    segment = HEAP_SEG_HEAD(session);
    heap_format_free_ufp(session, segment);

    heap_shrink_map_tree(session, segment, &path);

    knl_panic(segment->extents.count > extents.count);
    segment->extents.count -= extents.count;
    segment->extents.last = last_ext;
    segment->cmp_hwm = INVALID_PAGID;
    segment->data_last = hwm;

    if (ufp_count > 0) {
        heap_get_format_unit_last(session, next, &fmt_last);
        if (fmt_last.page >= ext_last.page) {
            heap_add_ufp(session, segment, next, ufp_count, !segment->compress);
            segment->free_ufp = INVALID_PAGID;
            segment->ufp_count = 0;
        } else {
            uint32 fmt_count = fmt_last.page - next.page + 1;
            heap_add_ufp(session, segment, next, fmt_count, !segment->compress);
            segment->ufp_count = ufp_count - fmt_count;
            fmt_last.page++;
            segment->free_ufp = fmt_last;
        }
    } else {
        segment->free_ufp = INVALID_PAGID;
        segment->ufp_count = 0;
    }

    if (segment->free_extents.count > 0) {
        if (extents.count == 0) {
            extents = segment->free_extents;
        } else {
            spc_concat_extents(session, &extents, &segment->free_extents);
        }

        segment->free_extents.count = 0;
        segment->free_extents.first = INVALID_PAGID;
        segment->free_extents.last = INVALID_PAGID;
    }

    // free extent will be freed to spc, do not need to record free page count herer
    heap_try_shrink_seg_page_cnt(space, segment, page_count, hwm_ext_size);

    if (extents.count > 0) {
        spc_free_extents(session, space, &extents);
    } else {
        CT_LOG_RUN_INF("no extents be shrinked. uid %u oid %u ashrink %u",
            segment->uid, segment->oid, (uint32)async_shrink);
    }

    if (SPACE_IS_LOGGING(space)) {
        log_put(session, RD_HEAP_CHANGE_SEG, segment, HEAP_SEG_SIZE, LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, CT_TRUE);

    log_atomic_op_end(session);
}

/*
 * heap traversal map for shrink
 * @param kernel session, map path, traversal page id
 */
void heap_traversal_map_for_shrink(knl_session_t *session, map_path_t *path, page_id_t *page_id)
{
    uint32 level = 0;
    map_index_t *index = NULL;
    map_page_t *page = NULL;
    map_node_t *node = NULL;
    page_id_t map_id;

    for (;;) {
        index = &path->index[level];

        if (index->slot == 0) {
            if (level == path->level) {
                *page_id = INVALID_PAGID;
                return;
            }

            level++;
            continue;
        } else if (index->slot != INVALID_SLOT) {
            index->slot--;
        }

        map_id.file = (uint16)index->file;
        map_id.page = (uint32)index->page;
        map_id.aligned = 0;

        buf_enter_page(session, map_id, LATCH_MODE_S, ENTER_PAGE_NORMAL);
        page = (map_page_t *)CURR_PAGE(session);

        knl_panic_log(page->head.type == PAGE_TYPE_HEAP_MAP, "page type is abnormal, panic info: page %u-%u type %u",
                      AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type);

        // there is no heap page on map page, scan previous map of the same layer
        if (page->hwm == 0) {
            level++;
            buf_leave_page(session, CT_FALSE);
            continue;
        }

        if (index->slot == INVALID_SLOT) {
            index->slot = page->hwm - 1;
        }

        node = heap_get_map_node((char *)page, (uint16)index->slot);

        if (level > 0) {
            level--;
            index = &path->index[level];
            index->file = node->file;
            index->page = node->page;
            index->slot = INVALID_SLOT;
            buf_leave_page(session, CT_FALSE);
            continue;
        }

        page_id->file = (uint16)node->file;
        page_id->page = (uint32)node->page;
        page_id->aligned = 0;
        buf_leave_page(session, CT_FALSE);
        return;
    }
}

