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
 * ctsql_btree.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/executor/ctsql_btree.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_btree.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BTREE_PAGES_HOLD 128
#define BTREE_GET_SLOT(page, id, slot_size) (uint32 *)((char *)(page) + CT_VMEM_PAGE_SIZE - ((id) + 1) * (slot_size))
#define BTREE_GET_ROW(page, id, slot_size) \
    (sql_btree_row_t *)((char *)(page) + *BTREE_GET_SLOT((page), (id), (slot_size)))

#define CT_MAX_NEW_PAGES 2

typedef struct st_sql_btree_pages {
    vm_page_t *item[CT_MAX_NEW_PAGES];
    uint32 count;
} sql_btree_pages_t;

typedef struct st_sql_btree_assit {
    sql_btree_segment_t *seg;
    char *buf;
    uint32 buf_size;
    uint32 key_size;
    sql_btree_pages_t new_pages;
} sql_btree_assit_t;

static inline status_t sql_btree_vm_alloc_and_append(sql_btree_segment_t *seg)
{
    vm_page_t *page = NULL;

    CT_RETURN_IFERR(vm_alloc_and_append(seg->sess, seg->pool, &seg->vm_list));

    // if pages hold threshold not reached, do an extra open for hold purpose
    if (seg->vm_list.count <= seg->pages_hold) {
        return vm_open(seg->sess, seg->pool, seg->vm_list.last, &page);
    }

    return CT_SUCCESS;
}

static inline void sql_btree_init_page(vm_page_t *page, bool32 is_leaf)
{
    sql_btree_page_head_t *btree_page_head = (sql_btree_page_head_t *)page->data;
    btree_page_head->is_leaf = is_leaf;
    btree_page_head->row_count = 0;
    btree_page_head->free_begin = sizeof(sql_btree_page_head_t);
    btree_page_head->last_vmid = CT_INVALID_ID32;
    btree_page_head->next_vmid = CT_INVALID_ID32;
}

status_t sql_btree_init(sql_btree_segment_t *segment, handle_t sess, vm_pool_t *pool, void *callback_ctx,
                        cmp_func_t cmp, oper_func_t insert_oper)
{
    vm_page_t *page = NULL;

    segment->callback_ctx = callback_ctx;
    segment->sess = sess;
    segment->pool = pool;
    segment->pages_hold = BTREE_PAGES_HOLD;
    segment->vm_list.count = 0;
    segment->cmp = cmp;
    segment->insert_oper = insert_oper;

    if (sql_btree_vm_alloc_and_append(segment) != CT_SUCCESS) {
        sql_btree_deinit(segment);
        return CT_ERROR;
    }

    if (vm_open(segment->sess, segment->pool, segment->vm_list.last, &page) != CT_SUCCESS) {
        sql_btree_deinit(segment);
        return CT_ERROR;
    }

    sql_btree_init_page(page, CT_TRUE);
    segment->root_node_vmid = page->vmid;
    segment->first_data_vmid = page->vmid;
    vm_close(segment->sess, segment->pool, segment->vm_list.last, VM_ENQUE_TAIL);

    return CT_SUCCESS;
}

void sql_btree_deinit(sql_btree_segment_t *segment)
{
    uint32 loop;
    vm_ctrl_t *ctrl = NULL;
    uint32 curr_id, next_id;

    curr_id = segment->vm_list.first;
    for (loop = 0; loop < segment->vm_list.count; ++loop) {
        ctrl = vm_get_ctrl(segment->pool, curr_id);
        next_id = ctrl->next;
        vm_free(segment->sess, segment->pool, curr_id);
        curr_id = next_id;
    }
    segment->vm_list.count = 0;
}

static status_t sql_btree_leaf_node_binsearch(sql_btree_assit_t *assit, vm_page_t *page, uint32 *slot_id,
    sql_btree_row_t **btree_row)
{
    sql_btree_page_head_t *page_head = (sql_btree_page_head_t *)page->data;
    int32 result;
    uint32 begin, end, current;

    if (page_head->row_count == 0) {
        *slot_id = 0;
        *btree_row = NULL;
        return CT_SUCCESS;
    }

    // if >= the last row, put at the end directly
    *btree_row = BTREE_GET_ROW(page_head, page_head->row_count - 1, sizeof(sql_btree_page_leaf_slot_t));
    CT_RETURN_IFERR(assit->seg->cmp(&result, assit->seg->callback_ctx, assit->buf, assit->buf_size, (*btree_row)->data,
        (*btree_row)->size));

    if (result > 0) {
        *slot_id = page_head->row_count;
        *btree_row = NULL;
        return CT_SUCCESS;
    } else if (result == 0) {
        *slot_id = page_head->row_count - 1;
        return CT_SUCCESS;
    }

    // search the correct position
    current = 0;
    begin = 0;
    end = page_head->row_count - 1;

    while (begin < end) {
        current = (end + begin) >> 1;
        *btree_row = BTREE_GET_ROW(page_head, current, sizeof(sql_btree_page_leaf_slot_t));

        CT_RETURN_IFERR(assit->seg->cmp(&result, assit->seg->callback_ctx, assit->buf, assit->key_size,
            (*btree_row)->data, (*btree_row)->key_size));

        if (0 == result) {
            *slot_id = current;
            return CT_SUCCESS;
        }

        if (result < 0) {
            end = current;
        } else {
            begin = current + 1;
        }
    }

    *slot_id = begin;
    *btree_row = NULL;
    return CT_SUCCESS;
}

static status_t sql_btree_non_leaf_node_binsearch(sql_btree_assit_t *assit, vm_page_t *page, uint32 *slot_id,
    sql_btree_row_t **btree_row)
{
    sql_btree_page_head_t *page_head = (sql_btree_page_head_t *)page->data;
    int32 result;
    uint32 begin, end, current;

    CM_ASSERT(page_head->row_count > 1);

    *btree_row = BTREE_GET_ROW(page_head, 1, sizeof(sql_btree_page_slot_t));
    CT_RETURN_IFERR(assit->seg->cmp(&result, assit->seg->callback_ctx, assit->buf, assit->key_size, (*btree_row)->data,
        (*btree_row)->key_size));

    if (result < 0) {
        *slot_id = 0;
        *btree_row = NULL;
        return CT_SUCCESS;
    } else if (result == 0) {
        *slot_id = 1;
        return CT_SUCCESS;
    }

    // search the correct position
    begin = 1;
    end = page_head->row_count - 1;

    while (begin < end) {
        current = (end + begin + 1) >> 1;
        *btree_row = BTREE_GET_ROW(page_head, current, sizeof(sql_btree_page_slot_t));

        CT_RETURN_IFERR(assit->seg->cmp(&result, assit->seg->callback_ctx, assit->buf, assit->key_size,
            (*btree_row)->data, (*btree_row)->key_size));

        if (0 == result) {
            *slot_id = current;
            return CT_SUCCESS;
        }

        if (result < 0) {
            end = current - 1;
        } else {
            begin = current;
        }
    }

    *slot_id = begin;
    *btree_row = NULL;
    return CT_SUCCESS;
}

static inline status_t sql_btree_shift_slots(sql_btree_page_head_t *page_head, uint32 slot_id, size_t slot_size)
{
    char *src = NULL;

    if (slot_id >= page_head->row_count) {
        return CT_SUCCESS;
    }

    char *dst = (char *)BTREE_GET_SLOT(page_head, page_head->row_count, slot_size);
    src = dst + slot_size;
    MEMS_RETURN_IFERR(memmove_s(dst, CT_VMEM_PAGE_SIZE, src, (page_head->row_count - slot_id) * slot_size));
    return CT_SUCCESS;
}

static inline status_t btree_insert_oper(sql_btree_segment_t *seg, const char *new_buf, uint32 new_size,
    const char *old_buf, uint32 old_size, bool32 found)
{
    if (seg->insert_oper == NULL) {
        return CT_SUCCESS;
    }
    return seg->insert_oper(seg->callback_ctx, new_buf, new_size, old_buf, old_size, found);
}

static status_t sql_btree_move_data(sql_btree_assit_t *assit, sql_btree_page_head_t *page,
    sql_btree_page_head_t *new_page, uint32 *already_move_rows, uint32 slot_id, uint32 slot_size,
    uint32 child_node_vmid, bool32 *already_insert)
{
    uint32 *offset_src = NULL;
    uint32 *offset_dst = NULL;
    sql_btree_row_t *btree_row = NULL;
    uint32 need_copy_size;
    // The second page needs to store all the remaining data
    uint32 reserved_mem_size = (*already_move_rows == 0) ? (CT_VMEM_PAGE_SIZE * 2 / 5) : 0;
    uint32 remain_mem_size = CT_VMEM_PAGE_SIZE;

    offset_src = BTREE_GET_SLOT(page, *already_move_rows, slot_size);
    offset_dst = BTREE_GET_SLOT(new_page, 0, slot_size);

    while ((*already_move_rows < page->row_count || !*already_insert) && remain_mem_size > reserved_mem_size) {
        // if *already_move_rows == page->row_count and !*already_insert == true,
        // then *already_move_rows must be equal to slot_id
        if (*already_move_rows == slot_id && !*already_insert) {
            remain_mem_size = (uint32)((char *)offset_dst - (char *)new_page - new_page->free_begin);
            if (assit->buf_size + sizeof(sql_btree_row_t) + slot_size > remain_mem_size) {
                // not enough memory
                break;
            }

            *already_insert = CT_TRUE;

            btree_row = (sql_btree_row_t *)((char *)new_page + new_page->free_begin);
            btree_row->size = assit->buf_size;
            btree_row->key_size = assit->key_size;
            MEMS_RETURN_IFERR(memcpy_s(btree_row->data, (remain_mem_size - sizeof(sql_btree_row_t) - slot_size),
                assit->buf, assit->buf_size));

            if (child_node_vmid != CT_INVALID_ID32) {
                ((sql_btree_page_slot_t *)offset_dst)->child_node_vmid = child_node_vmid;
            }

            *offset_dst = new_page->free_begin;
            offset_dst = (uint32 *)((char *)offset_dst - slot_size);
            new_page->free_begin += btree_row->size + sizeof(sql_btree_row_t);
            new_page->row_count++;

            if (page->is_leaf) {
                CT_RETURN_IFERR(btree_insert_oper(assit->seg, btree_row->data, btree_row->size, btree_row->data,
                    btree_row->size, CT_FALSE));
            }

            remain_mem_size = (uint32)((char *)offset_dst - (char *)new_page - new_page->free_begin);
            continue;
        }

        MEMS_RETURN_IFERR(memcpy_s(offset_dst, slot_size, offset_src, slot_size));

        btree_row = (sql_btree_row_t *)((char *)page + *offset_src);
        offset_src = (uint32 *)((char *)offset_src - slot_size);

        need_copy_size = btree_row->size + sizeof(sql_btree_row_t);
        remain_mem_size = (uint32)((char *)offset_dst - (char *)new_page - new_page->free_begin);
        if (need_copy_size + slot_size > remain_mem_size) {
            // not enough memory
            break;
        }

        MEMS_RETURN_IFERR(memcpy_s((char *)new_page + new_page->free_begin, (remain_mem_size - slot_size),
            (char *)btree_row, need_copy_size));

        *offset_dst = new_page->free_begin;
        offset_dst = (uint32 *)((char *)offset_dst - slot_size);
        new_page->free_begin += need_copy_size;
        new_page->row_count++;
        (*already_move_rows)++;
        remain_mem_size = (uint32)((char *)offset_dst - (char *)new_page - new_page->free_begin);
    }

    return CT_SUCCESS;
}

static status_t sql_btree_split(sql_btree_assit_t *assit, sql_btree_page_head_t *page_head, uint32 slot_id,
    uint32 slot_size, uint32 child_node_vmid)
{
    uint32 remain_rows;
    uint32 already_move_rows = 0;
    bool32 already_insert = CT_FALSE;
    sql_btree_segment_t *segment = assit->seg;
    vm_page_t *new_page = NULL;
    sql_btree_page_head_t *new_page_head = NULL;
    sql_btree_page_head_t *new_page1 = NULL;
    sql_btree_page_head_t *new_page2 = NULL;

    remain_rows = page_head->row_count + 1;
    assit->new_pages.count = 0;

    while (remain_rows > 0) {
        if (assit->new_pages.count >= CT_MAX_NEW_PAGES) {
            CT_THROW_ERROR(ERR_NO_FREE_VMEM, "one page size of virtual memory is too small");
            return CT_ERROR;
        }

        CT_RETURN_IFERR(sql_btree_vm_alloc_and_append(assit->seg));
        CT_RETURN_IFERR(vm_open(segment->sess, segment->pool, segment->vm_list.last, &new_page));
        sql_btree_init_page(new_page, page_head->is_leaf);
        assit->new_pages.item[assit->new_pages.count] = new_page;
        assit->new_pages.count++;
        new_page_head = (sql_btree_page_head_t *)(new_page->data);
        CT_RETURN_IFERR(sql_btree_move_data(assit, page_head, new_page_head, &already_move_rows, slot_id, slot_size,
            child_node_vmid, &already_insert));
        remain_rows -= new_page_head->row_count;
    }

    if (!page_head->is_leaf) {
        return CT_SUCCESS;
    }

    // Leaf nodes need to maintain data linked lists
    new_page1 = (sql_btree_page_head_t *)assit->new_pages.item[0]->data;
    new_page2 = (sql_btree_page_head_t *)assit->new_pages.item[1]->data;

    new_page1->last_vmid = page_head->last_vmid;
    new_page1->next_vmid = assit->new_pages.item[1]->vmid;
    new_page2->last_vmid = assit->new_pages.item[0]->vmid;
    new_page2->next_vmid = page_head->next_vmid;

    if (page_head->last_vmid != CT_INVALID_ID32) {
        CT_RETURN_IFERR(vm_open(segment->sess, segment->pool, page_head->last_vmid, &new_page));
        ((sql_btree_page_head_t *)new_page->data)->next_vmid = assit->new_pages.item[0]->vmid;
        vm_close(segment->sess, segment->pool, page_head->last_vmid, VM_ENQUE_TAIL);
    }

    if (page_head->next_vmid != CT_INVALID_ID32) {
        CT_RETURN_IFERR(vm_open(segment->sess, segment->pool, page_head->next_vmid, &new_page));
        ((sql_btree_page_head_t *)new_page->data)->last_vmid = assit->new_pages.item[1]->vmid;
        vm_close(segment->sess, segment->pool, page_head->next_vmid, VM_ENQUE_TAIL);
    }

    return CT_SUCCESS;
}

static status_t sql_btree_insert_leaf_node(sql_btree_assit_t *assit, vm_page_t *page, bool32 already_found)
{
    sql_btree_page_head_t *page_head = (sql_btree_page_head_t *)page->data;
    uint32 slot_id;
    sql_btree_row_t *btree_row = NULL;
    uint32 *slot = NULL;

    if (already_found) {
        btree_row = BTREE_GET_ROW(page_head, 0, sizeof(sql_btree_page_leaf_slot_t));
        return btree_insert_oper(assit->seg, assit->buf, assit->buf_size, btree_row->data, btree_row->size, CT_TRUE);
    } else {
        // binary search
        CT_RETURN_IFERR(sql_btree_leaf_node_binsearch(assit, page, &slot_id, &btree_row));
        if (btree_row != NULL) { // find same data
            return btree_insert_oper(assit->seg, assit->buf, assit->buf_size, btree_row->data, btree_row->size,
                CT_TRUE);
        }
    }

    if (page_head->free_begin + assit->buf_size + sizeof(sql_btree_row_t) + sizeof(sql_btree_page_leaf_slot_t) >
        CT_VMEM_PAGE_SIZE - page_head->row_count * sizeof(sql_btree_page_leaf_slot_t)) {
        // split one page to two pages
        return sql_btree_split(assit, (sql_btree_page_head_t *)page->data, slot_id, sizeof(sql_btree_page_leaf_slot_t),
            CT_INVALID_ID32);
    }

    // insert data
    CT_RETURN_IFERR(sql_btree_shift_slots(page_head, slot_id, sizeof(sql_btree_page_leaf_slot_t)));
    btree_row = (sql_btree_row_t *)((char *)page_head + page_head->free_begin);
    btree_row->size = assit->buf_size;
    btree_row->key_size = assit->key_size;
    MEMS_RETURN_IFERR(memcpy_s(btree_row->data, assit->buf_size, assit->buf, assit->buf_size));

    slot = BTREE_GET_SLOT(page_head, slot_id, sizeof(sql_btree_page_leaf_slot_t));
    *slot = page_head->free_begin;

    page_head->free_begin += sizeof(sql_btree_row_t) + assit->buf_size;
    page_head->row_count++;

    return btree_insert_oper(assit->seg, btree_row->data, btree_row->size, btree_row->data, btree_row->size, CT_FALSE);
}

static status_t sql_btree_add_boundary(sql_btree_assit_t *assit, sql_btree_page_head_t *page_head, uint32 slot_id,
    vm_page_t *new_child_vm_page)
{
    sql_btree_row_t *btree_row = NULL;
    sql_btree_row_t *new_btree_row = NULL;
    uint32 need_size;
    sql_btree_page_slot_t *slot = NULL;
    sql_btree_page_head_t *new_child_page = (sql_btree_page_head_t *)new_child_vm_page->data;
    uint32 child_node_vmid = new_child_vm_page->vmid;

    if (new_child_page->is_leaf) {
        btree_row = BTREE_GET_ROW(new_child_page, 0, sizeof(sql_btree_page_leaf_slot_t));
    } else {
        btree_row = BTREE_GET_ROW(new_child_page, 0, sizeof(sql_btree_page_slot_t));
    }

    need_size = btree_row->key_size + sizeof(sql_btree_row_t);
    if (page_head->free_begin + need_size + sizeof(sql_btree_page_slot_t) >
        CT_VMEM_PAGE_SIZE - page_head->row_count * sizeof(sql_btree_page_slot_t)) {
        // split one page to two pages
        assit->buf = btree_row->data;
        assit->buf_size = btree_row->key_size;
        assit->key_size = btree_row->key_size;
        return sql_btree_split(assit, page_head, slot_id, sizeof(sql_btree_page_slot_t), child_node_vmid);
    }

    // insert data
    CT_RETURN_IFERR(sql_btree_shift_slots(page_head, slot_id, sizeof(sql_btree_page_slot_t)));
    new_btree_row = (sql_btree_row_t *)((char *)page_head + page_head->free_begin);
    new_btree_row->size = new_btree_row->key_size = btree_row->key_size;
    MEMS_RETURN_IFERR(memcpy_s(new_btree_row->data, btree_row->key_size, btree_row->data, btree_row->key_size));

    slot = (sql_btree_page_slot_t *)BTREE_GET_SLOT(page_head, slot_id, sizeof(sql_btree_page_slot_t));
    slot->offset = page_head->free_begin;
    slot->child_node_vmid = child_node_vmid;

    page_head->free_begin += need_size;
    page_head->row_count++;
    return CT_SUCCESS;
}

static inline void sql_btree_close_pages(sql_btree_segment_t *segment, sql_btree_pages_t *pages)
{
    for (uint32 i = 0; i < pages->count; i++) {
        vm_close(segment->sess, segment->pool, pages->item[i]->vmid, VM_ENQUE_TAIL);
    }
}

static inline void sql_btree_free_page(sql_btree_segment_t *segment, uint32 vmid)
{
    vm_remove(segment->pool, &segment->vm_list, vmid);
    vm_free(segment->sess, segment->pool, vmid);
}

static inline void sql_btree_close_or_free_page(sql_btree_assit_t *btree_assit, uint32 *vmid)
{
    if (btree_assit->new_pages.count > 0) {
        sql_btree_free_page(btree_assit->seg, *vmid);

        if (btree_assit->seg->first_data_vmid == *vmid) {
            btree_assit->seg->first_data_vmid = btree_assit->new_pages.item[0]->vmid;
        }

        *vmid = btree_assit->new_pages.item[0]->vmid;
    } else {
        vm_close(btree_assit->seg->sess, btree_assit->seg->pool, *vmid, VM_ENQUE_TAIL);
    }
}

static status_t sql_btree_insert_node(sql_btree_assit_t *assit, uint32 *vmid, bool32 already_found);
static status_t sql_btree_insert_non_leaf_node(sql_btree_assit_t *assit, vm_page_t *page, bool32 temp_already_found)
{
    uint32 slot_id;
    sql_btree_row_t *btree_row = NULL;
    sql_btree_page_slot_t *slot = NULL;
    sql_btree_segment_t *seg = assit->seg;
    bool32 already_found = temp_already_found;

    if (already_found) {
        slot_id = 0;
    } else {
        // binary search
        CT_RETURN_IFERR(sql_btree_non_leaf_node_binsearch(assit, page, &slot_id, &btree_row));
        already_found = (btree_row != NULL);
    }

    slot = (sql_btree_page_slot_t *)BTREE_GET_SLOT(page->data, slot_id, sizeof(sql_btree_page_slot_t));
    CT_RETURN_IFERR(sql_btree_insert_node(assit, &slot->child_node_vmid, already_found));

    if (assit->new_pages.count > 0) {
        CM_ASSERT(assit->new_pages.count > 1);
        // add boundary value in non-leaf node
        // if a boundary value is added and this node needs to split, then new page is equal to the new split page
        sql_btree_pages_t new_pages = assit->new_pages;
        assit->new_pages.count = 0;
        CT_RETURN_IFERR(
            sql_btree_add_boundary(assit, (sql_btree_page_head_t *)page->data, slot_id + 1, new_pages.item[1]));
        sql_btree_close_pages(seg, &new_pages);
    }

    return CT_SUCCESS;
}

static status_t sql_btree_insert_node(sql_btree_assit_t *assit, uint32 *vmid, bool32 already_found)
{
    vm_page_t *page = NULL;
    sql_btree_page_head_t *page_head = NULL;
    sql_btree_segment_t *seg = assit->seg;

    CT_RETURN_IFERR(vm_open(seg->sess, seg->pool, *vmid, &page));

    page_head = (sql_btree_page_head_t *)page->data;
    if (page_head->is_leaf) {
        CT_RETURN_IFERR(sql_btree_insert_leaf_node(assit, page, already_found));
    } else {
        CT_RETURN_IFERR(sql_btree_insert_non_leaf_node(assit, page, already_found));
    }

    sql_btree_close_or_free_page(assit, vmid);
    return CT_SUCCESS;
}

static status_t sql_btree_split_root_node(sql_btree_assit_t *assit)
{
    vm_page_t *new_page = NULL;
    vm_page_t *root_node_page = NULL;
    sql_btree_page_head_t *page = NULL;
    sql_btree_page_head_t *new_page_head = NULL;
    sql_btree_page_slot_t *slot = NULL;
    errno_t ret;
    sql_btree_row_t *row_src = NULL;
    sql_btree_row_t *row_dst = NULL;
    sql_btree_segment_t *seg = assit->seg;

    new_page = assit->new_pages.item[1];
    CT_RETURN_IFERR(sql_btree_vm_alloc_and_append(seg));

    CT_RETURN_IFERR(vm_open(seg->sess, seg->pool, seg->vm_list.last, &root_node_page));
    sql_btree_init_page(root_node_page, CT_FALSE);

    page = (sql_btree_page_head_t *)root_node_page->data;

    // slot 0
    row_dst = (sql_btree_row_t *)((char *)page + page->free_begin);
    row_dst->key_size = row_dst->size = 0;

    slot = (sql_btree_page_slot_t *)BTREE_GET_SLOT(page, 0, sizeof(sql_btree_page_slot_t));
    slot->offset = page->free_begin;
    slot->child_node_vmid = seg->root_node_vmid;
    page->free_begin += sizeof(sql_btree_row_t);
    page->row_count++;

    // slot 1
    new_page_head = (sql_btree_page_head_t *)new_page->data;
    if (new_page_head->is_leaf) {
        row_src = BTREE_GET_ROW(new_page_head, 0, sizeof(sql_btree_page_leaf_slot_t));
    } else {
        row_src = BTREE_GET_ROW(new_page_head, 0, sizeof(sql_btree_page_slot_t));
    }

    row_dst = (sql_btree_row_t *)((char *)page + page->free_begin);
    row_dst->key_size = row_dst->size = row_src->key_size;
    ret = memcpy_s(row_dst->data, row_src->key_size, (char *)row_src->data, row_src->key_size);
    if (ret != EOK) {
        vm_close(seg->sess, seg->pool, root_node_page->vmid, VM_ENQUE_TAIL);
        sql_btree_close_pages(seg, &assit->new_pages);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CT_ERROR;
    }

    slot = (sql_btree_page_slot_t *)BTREE_GET_SLOT(page, 1, sizeof(sql_btree_page_slot_t));
    slot->offset = page->free_begin;
    slot->child_node_vmid = new_page->vmid;
    page->free_begin += row_src->key_size + sizeof(sql_btree_row_t);
    page->row_count++;

    seg->root_node_vmid = root_node_page->vmid;
    vm_close(seg->sess, seg->pool, root_node_page->vmid, VM_ENQUE_TAIL);
    sql_btree_close_pages(seg, &assit->new_pages);
    return CT_SUCCESS;
}

status_t sql_btree_insert(sql_btree_segment_t *seg, char *buf, uint32 size, uint32 key_size)
{
    sql_btree_assit_t assit;
    bool32 already_found = CT_FALSE;

    assit.seg = seg;
    assit.buf = buf;
    assit.buf_size = size;
    assit.key_size = key_size;
    assit.new_pages.count = 0;

    CT_RETURN_IFERR(sql_btree_insert_node(&assit, &seg->root_node_vmid, already_found));

    // root node need split
    if (assit.new_pages.count > 0) {
        CT_RETURN_IFERR(sql_btree_split_root_node(&assit));
    }

    return CT_SUCCESS;
}

status_t sql_btree_open(sql_btree_segment_t *segment, sql_btree_cursor_t *cursor)
{
    cursor->cur_rows = 0;
    cursor->btree_row = NULL;
    return vm_open(segment->sess, segment->pool, segment->first_data_vmid, &cursor->cur_page);
}

status_t sql_btree_fetch(sql_btree_segment_t *segment, sql_btree_cursor_t *cursor, bool32 *eof)
{
    sql_btree_page_head_t *page = (sql_btree_page_head_t *)cursor->cur_page->data;
    uint32 next_data_vmid;

    *eof = CT_FALSE;

    if (cursor->cur_rows < page->row_count) {
        cursor->btree_row = BTREE_GET_ROW(page, cursor->cur_rows, sizeof(sql_btree_page_leaf_slot_t));
        cursor->cur_rows++;
        return CT_SUCCESS;
    }

    if (page->next_vmid == CT_INVALID_ID32) {
        *eof = CT_TRUE;
        cursor->btree_row = NULL;
        return CT_SUCCESS;
    }

    next_data_vmid = page->next_vmid;
    vm_close(segment->sess, segment->pool, cursor->cur_page->vmid, VM_ENQUE_TAIL);
    CT_RETURN_IFERR(vm_open(segment->sess, segment->pool, next_data_vmid, &cursor->cur_page));
    cursor->btree_row = BTREE_GET_ROW(cursor->cur_page->data, 0, sizeof(sql_btree_page_leaf_slot_t));
    cursor->cur_rows = 1;
    return CT_SUCCESS;
}

#ifdef __cplusplus
}
#endif
