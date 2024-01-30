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
 * temp_btree.c
 *
 *
 * IDENTIFICATION
 * src/kernel/index/temp_btree.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_index_module.h"
#include "temp_btree.h"
#include "index_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TEMP_KEY_EXTRA_UNDO sizeof(knl_scn_t) // seg scn
#define TEMP_INSERT_UNDO_COUNT 1

static status_t temp_btree_split_page(knl_session_t *session, index_t *index, temp_btree_segment_t *seg,
                                      btree_path_info_t *path_info, uint32 level);
static status_t temp_btree_alloc_page(knl_session_t *session, index_t *index, uint32 index_segid,
                                      uint32 *curr_vmid, uint32 level, bool32 insert_minimum_key);

static inline void temp_btree_format_page(knl_session_t *session, index_t *index, temp_btree_page_t *page,
                                          uint32 level)
{
    AS_PAGID_PTR(page->prev)->vmid = CT_INVALID_ID32;
    AS_PAGID_PTR(page->next)->vmid = CT_INVALID_ID32;
    page->level = (uint8)level;
    page->keys = 0;
    page->seg_scn = index->desc.seg_scn;
    page->itls = 0;
    page->free_begin = sizeof(temp_btree_page_t);
    page->free_end = PAGE_SIZE(page->head) - sizeof(temp_page_tail_t);
    page->free_size = page->free_end - page->free_begin;
    page->is_recycled = 0;
}

void temp_btree_init_page(knl_session_t *session, index_t *index, temp_btree_page_t *page, uint32 vmid,
                          uint32 level)
{
    temp_page_init(session, &page->head, vmid, PAGE_TYPE_TEMP_INDEX);
    temp_btree_format_page(session, index, page, level);
}

static void temp_btree_insert_minimum_key(knl_session_t *session, temp_btree_page_t *page)
{
    btree_key_t *key;
    temp_btree_dir_t *dir;

    key = (btree_key_t *)((char *)page + page->free_begin);
    dir = TEMP_BTREE_GET_DIR(page, 0);

    btree_init_key(key, NULL);
    key->is_infinite = CT_TRUE;
    MINIMIZE_ROWID(key->rowid);
    key->undo_page = INVALID_UNDO_PAGID;
    key->undo_slot = INVALID_SLOT;
    key->scn = CT_INVALID_ID64;

    dir->offset = page->free_begin;
    dir->itl_id = CT_INVALID_ID8;
    page->free_begin += (uint32)key->size;
    page->free_end -= sizeof(temp_btree_dir_t);
    page->free_size -= ((uint32)key->size + sizeof(temp_btree_dir_t));
    page->keys++;
    knl_panic_log(page->free_begin <= page->free_end, "page's free size begin is more than end, panic info: "
                  "page %u-%u type %u free_begin %u free_end %u", AS_PAGID(page->head.id).file,
                  AS_PAGID(page->head.id).page, page->head.type, page->free_begin, page->free_end);
}

static void temp_btree_generate_undo(knl_session_t *session, knl_cursor_t *cursor, btree_path_info_t *path_info,
                                     bool32 is_same, undo_type_t type)
{
    index_t *index = (index_t *)cursor->index;
    btree_key_t *key = (btree_key_t *)cursor->key;
    btree_key_t *old_key = NULL;
    temp_btree_dir_t *dir = NULL;
    undo_data_t undo;
    vm_page_t *vm_page = NULL;
    temp_btree_page_t *page;
    errno_t ret;

    vm_page = buf_curr_temp_page(session);
    page = (temp_btree_page_t *)vm_page->data;
    undo.size = (uint32)key->size + TEMP_KEY_EXTRA_UNDO;
    undo.data = (char *)cm_push(session->stack, undo.size);

    if (is_same) {
        dir = TEMP_BTREE_GET_DIR(page, path_info->path[0].vm_slot);
        old_key = TEMP_BTREE_GET_KEY(page, dir);

        if (type == UNDO_TEMP_BTREE_INSERT) {
            knl_panic_log(old_key->is_deleted,
                "old_key is not deleted, panic info: page %u-%u type %u table %s index %s", cursor->rowid.file,
                cursor->rowid.page, page->head.type, ((table_t *)cursor->table)->desc.name, index->desc.name);
            CM_ABORT(old_key->is_deleted, "[BTREE] ABORT INFO: insert key has not been deleted");
        }

        if (type == UNDO_TEMP_BTREE_DELETE) {
            knl_panic_log(!old_key->is_deleted,
                "old_key is deleted, panic info: page %u-%u type %u table %s index %s", cursor->rowid.file,
                cursor->rowid.page, page->head.type, ((table_t *)cursor->table)->desc.name, index->desc.name);
            CM_ABORT(!old_key->is_deleted, "[BTREE] ABORT INFO: delete key has been deleted");
        }

        undo.snapshot.undo_page = old_key->undo_page;
        undo.snapshot.undo_slot = old_key->undo_slot;
        undo.snapshot.scn = old_key->scn;
        ret = memcpy_sp(undo.data, undo.size, old_key, (size_t)old_key->size);
        knl_securec_check(ret);
    } else {
        knl_panic_log((uint32)(page->free_end - page->free_begin) >= TEMP_BTREE_COST_SIZE(key), "page's free size is "
            "abnormal, panic info: page %u-%u type %u free_begin %u free_end %u table %s index %s temp btree cost "
            "size %u", cursor->rowid.file, cursor->rowid.page, page->head.type, page->free_begin, page->free_end,
            ((table_t *)cursor->table)->desc.name, index->desc.name, (uint32)TEMP_BTREE_COST_SIZE(key));
        undo.snapshot.undo_page = INVALID_UNDO_PAGID;
        undo.snapshot.undo_slot = INVALID_SLOT;
        undo.snapshot.scn = 0;
        ret = memcpy_sp(undo.data, undo.size, key, (size_t)key->size);
        knl_securec_check(ret);
    }

    undo.snapshot.is_xfirst = cursor->is_xfirst;
    undo.snapshot.is_owscn = 0;
    undo.user_id = index->desc.uid;
    undo.seg_page = index->desc.table_id;
    undo.index_id = index->desc.id;
    undo.type = type;
    undo.ssn = 0;
    *(uint64 *)((char *)undo.data + undo.size - TEMP_KEY_EXTRA_UNDO) = CURSOR_TEMP_CACHE(cursor)->seg_scn;

    log_atomic_op_begin(session);
    undo_write(session, &undo, IS_TEMPTABLE_HAS_REDO(session), CT_FALSE);
    log_atomic_op_end(session);
    cm_pop(session->stack);
}

status_t temp_btree_create_segment(knl_session_t *session, index_t *index, knl_temp_cache_t *temp_table)
{
    uint32 index_segid;
    mtrl_segment_t *segment = NULL;
    uint32 vmid;

    knl_panic_log(index->desc.table_id == temp_table->table_id, "the table id record on index and temp_table are not "
                  "same, panic info: index %s index_tid %u temp_tid %u",
                  index->desc.name, index->desc.table_id, temp_table->table_id);
    knl_panic_log(temp_table->table_segid != CT_INVALID_ID32,
                  "the temp_table's table_segid is invalid, panic info: index %s", index->desc.name);

    index_segid = temp_table->index_segid;
    if (index_segid == CT_INVALID_ID32) {
        if (temp_create_segment(session, &index_segid) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("Fail to create btree segment in btree create segment.");
            return CT_ERROR;
        }
        temp_table->index_segid = index_segid;
        segment = session->temp_mtrl->segments[index_segid];
    } else {
        segment = session->temp_mtrl->segments[index_segid];
    }

    if (temp_btree_alloc_page(session, index, index_segid, &vmid, 0, CT_TRUE) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Fail to alloc btree page in btree create segment.");
        return CT_ERROR;
    }

    temp_table->index_root[index->desc.id].org_scn = index->desc.org_scn;
    temp_table->index_root[index->desc.id].index_segid = index_segid;
    temp_table->index_root[index->desc.id].root_vmid = vmid;
    temp_table->index_root[index->desc.id].level = 1;

    index->desc.entry.vmid = CT_INVALID_ID32;
    index->temp_btree = NULL;

    knl_panic_log(segment->vm_list.last == vmid, "the vm_list's last id is not equal to vmid, panic info: index %s "
                  "last id %u vmid %u", index->desc.name, segment->vm_list.last, vmid);
    knl_panic_log(segment->vm_list.count > 0, "the vm_list's count is not bigger than zero, panic info: index %s "
                  "vm count %u", index->desc.name, segment->vm_list.count);
    return CT_SUCCESS;
}

status_t temp_btree_construct(btree_mt_context_t *ctx)
{
    mtrl_cursor_t cursor;
    index_t *index = NULL;
    btree_t *btree = NULL;
    btree_key_t *key = NULL;
    knl_session_t *session = (knl_session_t *)ctx->mtrl_ctx.session;
    knl_cursor_t *knl_cursor = NULL;
    errno_t ret;

    CM_SAVE_STACK(session->stack);

    btree = (btree_t *)ctx->mtrl_ctx.segments[ctx->seg_id]->cmp_items;
    index = btree->index;
    knl_cursor = knl_push_cursor(session);
    knl_cursor->index = index;
    knl_cursor->index_slot = index->desc.slot;
    knl_cursor->temp_cache = knl_get_temp_cache(session, index->desc.uid, index->desc.table_id);
    knl_cursor->ssn = session->ssn;

    if (knl_cursor->temp_cache == NULL) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    knl_cursor->dc_type = CURSOR_TEMP_CACHE(knl_cursor)->table_type;
    knl_cursor->dc_entity = index->entity;

    if (mtrl_open_cursor(&ctx->mtrl_ctx, ctx->seg_id, &cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (mtrl_fetch_sort_key(&ctx->mtrl_ctx, &cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    while (!cursor.eof) {
        key = (btree_key_t *)cursor.sort.row;
        ret = memcpy_sp(knl_cursor->key, CT_KEY_BUF_SIZE, key, (size_t)key->size);
        knl_securec_check(ret);

        if (temp_btree_insert(session, knl_cursor) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }

        if (mtrl_fetch_sort_key(&ctx->mtrl_ctx, &cursor) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }
    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}


static status_t temp_db_fill_index_entity(knl_session_t *session, knl_cursor_t *cursor, knl_dictionary_t *dc,
                                          index_t *index)
{
    btree_mt_context_t ctx;
    mtrl_rowid_t rid;
    dc_entity_t *entity = DC_ENTITY(dc);
    status_t status = CT_SUCCESS;

    errno_t err = memset_sp(&ctx, sizeof(btree_mt_context_t), 0, sizeof(btree_mt_context_t));
    knl_securec_check(err);
    index->entity = entity;
    index->btree.index = index;
    cursor->action = CURSOR_ACTION_SELECT;
    cursor->scan_mode = SCAN_MODE_TABLE_FULL;
    if (CT_SUCCESS != knl_open_cursor(session, cursor, dc)) {
        return CT_ERROR;
    }

    if (CT_SUCCESS != knl_fetch(session, cursor)) {
        knl_close_cursor(session, cursor);
        return CT_ERROR;
    }

    if (cursor->eof) {
        knl_close_cursor(session, cursor);
        return CT_SUCCESS;
    }

    if (CT_SUCCESS != btree_constructor_init(session, &ctx, &index->btree)) {
        knl_close_cursor(session, cursor);
        return CT_ERROR;
    }

    char *key = (char *)cm_push(session->stack, CT_KEY_BUF_SIZE);
    do {
        if (session->canceled) {
            CT_THROW_ERROR(ERR_OPERATION_CANCELED);
            status = CT_ERROR;
            break;
        }

        if (session->killed) {
            CT_THROW_ERROR(ERR_OPERATION_KILLED);
            status = CT_ERROR;
            break;
        }

        if (knl_make_key(session, cursor, index, key) != CT_SUCCESS) {
            status = CT_ERROR;
            break;
        }

        ((btree_key_t *)key)->scn = CT_INVALID_ID64;

        if (CT_SUCCESS != mtrl_insert_row(&ctx.mtrl_ctx, 0, key, &rid)) {
            status = CT_ERROR;
            break;
        }

        if (CT_SUCCESS != knl_fetch(session, cursor)) {
            status = CT_ERROR;
            break;
        }
    } while (!cursor->eof);

    knl_close_cursor(session, cursor);
    cm_pop(session->stack);
    if (status != CT_SUCCESS) {
        mtrl_release_context(&ctx.mtrl_ctx);
        return CT_ERROR;
    }

    mtrl_close_segment(&ctx.mtrl_ctx, ctx.seg_id);
    if (mtrl_sort_segment(&ctx.mtrl_ctx, ctx.seg_id) != CT_SUCCESS) {
        mtrl_release_context(&ctx.mtrl_ctx);
        return CT_ERROR;
    }
    if (temp_btree_construct(&ctx) != CT_SUCCESS) {
        mtrl_release_context(&ctx.mtrl_ctx);
        return CT_ERROR;
    }

    mtrl_release_context(&ctx.mtrl_ctx);
    ctx.initialized = CT_FALSE;
    return CT_SUCCESS;
}

status_t temp_db_fill_index(knl_session_t *session, knl_cursor_t *cursor, index_t *index, uint32 paral_count)
{
    knl_temp_cache_t *temp_table = NULL;
    knl_dictionary_t dc;

    if (paral_count != 0) {
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "create index parallel", "temp table");
        return CT_ERROR;
    }

    if (dc_open_table_private(session, index->desc.uid, index->desc.table_id, &dc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (knl_ensure_temp_cache(session, dc.handle, &temp_table) != CT_SUCCESS) {
        dc_close_table_private(&dc);
        return CT_ERROR;
    }
    
    if (knl_ensure_temp_index(session, cursor, &dc, temp_table) != CT_SUCCESS) {
        dc_close_table_private(&dc);
        return CT_ERROR;
    }
    
    temp_table->index_root[index->desc.id].org_scn = index->desc.org_scn;

    if (temp_db_fill_index_entity(session, cursor, &dc, index) != CT_SUCCESS) {
        if (temp_table->index_segid != CT_INVALID_ID32) {
            temp_table->index_root[index->desc.id].root_vmid = CT_INVALID_ID32;
        }
        temp_table->index_root[index->desc.id].org_scn = CT_INVALID_ID64;
        dc_close_table_private(&dc);
        return CT_ERROR;
    }

    dc_close_table_private(&dc);

    return CT_SUCCESS;
}

static inline void temp_btree_clean_dir(knl_session_t *session, temp_btree_page_t *page, uint16 dir_id)
{
    uint16 j;
    errno_t ret;

    for (j = dir_id; j < page->keys - 1; j++) {
        *TEMP_BTREE_GET_DIR(page, j) = *TEMP_BTREE_GET_DIR(page, j + 1);
    }

    ret = memset_sp(TEMP_BTREE_GET_DIR(page, page->keys - 1), sizeof(temp_btree_dir_t), 0, sizeof(temp_btree_dir_t));
    knl_securec_check(ret);
    page->keys--;
}

static void temp_btree_compact_page(knl_session_t *session, temp_btree_page_t *page)
{
    temp_btree_dir_t *dir = NULL;
    btree_key_t *key = NULL;
    btree_key_t *free_addr = NULL;
    uint16 key_size;
    errno_t ret;

    for (int16 i = 0; i < page->keys; i++) {
        if (page->keys == 1) {
            dir = TEMP_BTREE_GET_DIR(page, 0);
            key = TEMP_BTREE_GET_KEY(page, dir);

            dir->offset = key->bitmap;
            if (key->is_cleaned) {
                key->is_cleaned = (uint16)CT_FALSE;
            }
            key->bitmap = 0;
            break;
        }

        dir = TEMP_BTREE_GET_DIR(page, i);
        key = TEMP_BTREE_GET_KEY(page, dir);
        if (key->is_cleaned) {
            temp_btree_clean_dir(session, page, i);
            i--;
            continue;
        }

        dir->offset = key->bitmap;
        key->bitmap = i;
    }

    key = (btree_key_t *)((char *)page + sizeof(temp_btree_page_t));
    free_addr = key;

    while ((char *)key < (char *)page + page->free_begin) {
        knl_panic_log(key->size > 0, "key's size is not bigger than zero, panic info: page %u-%u type %u key size %u",
                      AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type, key->size);
        if (key->is_cleaned) {
            key = (btree_key_t *)((char *)key + key->size);
            continue;
        }

        knl_panic(key->bitmap < page->keys);
        key_size = (uint16)key->size;
        if (key != free_addr) {
            ret = memmove_s(free_addr, key_size, key, key_size);
            knl_securec_check(ret);
        }

        dir = TEMP_BTREE_GET_DIR(page, free_addr->bitmap);
        free_addr->bitmap = dir->offset;
        dir->offset = (uint32)((char *)free_addr - (char *)page);

        free_addr = (btree_key_t *)((char *)free_addr + free_addr->size);
        key = (btree_key_t *)((char *)key + key_size);
    }

    page->free_begin = (uint32)((char *)free_addr - (char *)page);
    page->free_end = (uint32)((char *)TEMP_BTREE_GET_DIR(page, page->keys - 1) - (char *)page);
    page->free_size = page->free_end - page->free_begin;
    knl_panic_log(page->free_end >= page->free_begin, "page's free size begin is more than end, panic info: "
                  "page %u-%u type %u free_begin %u free_end %u", AS_PAGID(page->head.id).file,
                  AS_PAGID(page->head.id).page, page->head.type, page->free_begin, page->free_end);
}

int32 temp_btree_cmp_rowid(btree_key_t *key1, btree_key_t *key2)
{
    int32 result;

    result = (key1->rowid.vmid > key2->rowid.vmid ? 1 : (key1->rowid.vmid < key2->rowid.vmid ? (-1) : 0));
    if (result != 0) {
        return result;
    }

    result = (key1->rowid.vm_slot > key2->rowid.vm_slot ? 1 : (key1->rowid.vm_slot < key2->rowid.vm_slot ? (-1) : 0));
    return result;
}

void temp_btree_binary_search(index_t *index, temp_btree_page_t *page, knl_scan_key_t *scan_key,
                              btree_path_info_t *path_info, bool32 cmp_rowid, bool32 *is_same)
{
    int32 result;
    uint16 begin, end, curr;
    temp_btree_dir_t *dir = NULL;
    btree_key_t *cmp_key = NULL;

    curr = 0;
    begin = 0;
    result = 0;
    end = page->keys;
    /* branch node should have at least one key */
    knl_panic_log(page->level == 0 || page->keys > 0, "page level is not equal to zero and the keys is not more than "
        "zero, panic info: page %u-%u type %u index %s page_level %u page_keys %u", AS_PAGID(page->head.id).file,
        AS_PAGID(page->head.id).page, page->head.type, index->desc.name, page->level, page->keys);
    if (page->keys == 0) {
        *is_same = CT_FALSE;
    }

    while (begin < end) {
        curr = (end + begin) >> 1;
        dir = TEMP_BTREE_GET_DIR(page, curr);
        cmp_key = TEMP_BTREE_GET_KEY(page, dir);

        result = btree_compare_key(index, scan_key, cmp_key, cmp_rowid, is_same);
        if (result == 0) {
            break;
        }

        if (result < 0) {
            end = curr;
        } else {
            begin = curr + 1;
        }
    }

    if (result > 0) {
        path_info->path[page->level].vm_slot = curr + ((0 == page->level) ? 1 : 0);
        result = -1;
    } else {
        path_info->path[page->level].vm_slot = curr - ((0 == page->level) ? 0 : ((0 == result) ? 0 : 1));
    }
}

static status_t temp_btree_find_leaf(knl_session_t *session, index_t *index, temp_btree_segment_t *seg,
                                     bool32 desc_scan, knl_scan_key_t *scan_key,
                                     bool32 is_equal, btree_path_info_t *path_info, bool32 *is_found)
{
    temp_btree_dir_t *dir = NULL;
    btree_key_t *curr_key = NULL;
    temp_btree_page_t *page = NULL;
    vm_page_t *vm_page = NULL;
    uint32 vmid = seg->root_vmid;
    bool32 cmp_rowid;
    bool32 is_same = CT_FALSE;

    cmp_rowid = desc_scan ? CT_TRUE : ((index->desc.primary || index->desc.unique) ? CT_FALSE : CT_TRUE);
    for (;;) {
        if (buf_enter_temp_page_nolock(session, vmid) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("Fail to open vm page (%d) in btree find leaf page.", vmid);
            return CT_ERROR;
        }
        vm_page = buf_curr_temp_page(session);

        page = (temp_btree_page_t *)vm_page->data;
        path_info->path[page->level].vmid = vmid;
        knl_panic_log(page->head.type == PAGE_TYPE_TEMP_INDEX,
                      "page type is abnormal, panic info: page %u-%u type %u index %s",
                      AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type, index->desc.name);

        temp_btree_binary_search(index, page, scan_key, path_info, cmp_rowid, &is_same);

        if (path_info->path[page->level].vm_slot >= page->keys) {
            if (desc_scan) {
                knl_panic_log(page->level == 0, "the page level is not equal to zero, panic info: page %u-%u type %u "
                              "page level %u index %s", AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page,
                              page->head.type, page->level, index->desc.name);
                break;
            }

            vmid = AS_PAGID_PTR(page->next)->vmid;
            if (vmid != CT_INVALID_ID32) {
                buf_leave_temp_page_nolock(session, CT_FALSE);
                continue;
            }

            buf_leave_temp_page_nolock(session, CT_FALSE);
            *is_found = CT_FALSE;
            return CT_SUCCESS;
        }

        if (page->level == 0) {
            if (is_equal && !is_same) {
                buf_leave_temp_page_nolock(session, CT_FALSE);
                *is_found = CT_FALSE;
                return CT_SUCCESS;
            }
            break;
        }

        dir = TEMP_BTREE_GET_DIR(page, path_info->path[page->level].vm_slot);
        curr_key = TEMP_BTREE_GET_KEY(page, dir);
        vmid = curr_key->child.vmid;
        buf_leave_temp_page_nolock(session, CT_FALSE);
    }

    *is_found = CT_TRUE;
    return CT_SUCCESS;
}

static status_t temp_get_sibling_key(knl_session_t *session, btree_path_info_t *path_info)
{
    temp_btree_page_t *page = TEMP_BTREE_CURR_PAGE(session);
    CM_ASSERT(page->level == 1);
    uint32 vm_slot = (uint32)path_info->path[1].vm_slot + 1;
    if (vm_slot == page->keys) {
        uint32 next_vmid = AS_PAGID_PTR(page->next)->vmid;
        if (next_vmid == CT_INVALID_ID32) {
            return CT_SUCCESS;
        }
        buf_leave_temp_page_nolock(session, CT_FALSE);
        if (buf_enter_temp_page_nolock(session, next_vmid) != CT_SUCCESS) {
            return CT_ERROR;
        }
        page = TEMP_BTREE_CURR_PAGE(session);
        vm_slot = 0;
    }

    temp_btree_dir_t *dir = TEMP_BTREE_GET_DIR(page, vm_slot);
    btree_key_t *key = TEMP_BTREE_GET_KEY(page, dir);
    errno_t ret = memcpy_sp(path_info->sibling_key, CT_KEY_BUF_SIZE, key, (size_t)key->size);
    knl_securec_check(ret);

    return CT_SUCCESS;
}

static status_t temp_btree_find_update_pos(knl_session_t *session, index_t *index, temp_btree_segment_t *seg,
                                           knl_scan_key_t *scan_key, btree_path_info_t *path_info, bool32 *is_same,
                                           btree_find_type type, bool32 *is_found)
{
    temp_btree_dir_t *dir = NULL;
    btree_key_t *curr_key = NULL;
    temp_btree_page_t *page = NULL;
    vm_page_t *vm_page = NULL;
    uint32 vmid = seg->root_vmid;
    uint32 level = seg->level - 1;

    bool32 cmp_rowid = !IS_UNIQUE_PRIMARY_INDEX(index);

    for (;;) {
        if (buf_enter_temp_page_nolock(session, vmid) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("Fail to open vm page (%d) in btree find update pos.", vmid);
            return CT_ERROR;
        }

        vm_page = buf_curr_temp_page(session);
        page = (temp_btree_page_t *)vm_page->data;
        knl_panic_log(level == page->level, "curr level is not equal to page level, panic info: page %u-%u type %u "
                      "level %u page level %u index %s", AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page,
                      page->head.type, level, page->level, index->desc.name);

        path_info->path[page->level].vmid = vmid;
        knl_panic_log(page->head.type == PAGE_TYPE_TEMP_INDEX,
                      "page type is abnormal, panic info: page %u-%u type %u index %s",
                      AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type, index->desc.name);

        temp_btree_binary_search(index, page, scan_key, path_info, cmp_rowid, is_same);

        if (type != BTREE_FIND_INSERT && path_info->path[page->level].vm_slot >= page->keys) {
            vmid = AS_PAGID_PTR(page->next)->vmid;
            buf_leave_temp_page_nolock(session, CT_FALSE);

            if (vmid == CT_INVALID_ID32) {
                *is_found = CT_FALSE;
                return CT_SUCCESS;
            }
            continue;
        }

        if (page->level == 0) {
            break;
        }

        dir = TEMP_BTREE_GET_DIR(page, path_info->path[page->level].vm_slot);
        curr_key = TEMP_BTREE_GET_KEY(page, dir);
        vmid = curr_key->child.vmid;
        level = page->level - 1;
        if (path_info->get_sibling && level == 0) {
            if (temp_get_sibling_key(session, path_info) != CT_SUCCESS) {
                CT_LOG_RUN_ERR("Fail to get temp btree sibling key.");
                return CT_ERROR;
            }
        }

        buf_leave_temp_page_nolock(session, CT_FALSE);
    }
    *is_found = CT_TRUE;
    return CT_SUCCESS;
}

static status_t temp_btree_locate_prev_page(knl_session_t *session, knl_cursor_t *cursor)
{
    uint32 page_id;
    temp_btree_page_t *page;
    vm_page_t *vm_page;

    vm_page = buf_curr_temp_page(session);
    page = (temp_btree_page_t *)vm_page->data;
    page_id = AS_PAGID_PTR(page->next)->vmid;

    for (;;) {
        // no pages plit
        if (page_id == cursor->key_loc.page_id.vmid) {
            break;
        }
        buf_leave_temp_page_nolock(session, CT_FALSE);
        if (buf_enter_temp_page_nolock(session, page_id) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("Fail to open vm page (%d) in btree locate prev page.", page_id);
            return CT_ERROR;
        }
        vm_page = buf_curr_temp_page(session);
        page = (temp_btree_page_t *)vm_page->data;
        page_id = AS_PAGID_PTR(page->next)->vmid;
    }
    return CT_SUCCESS;
}

static status_t temp_btree_locate_with_find(knl_session_t *session, knl_cursor_t *cursor, knl_scan_key_t *scan_key)
{
    temp_btree_page_t *page = NULL;
    index_t *index;
    btree_path_info_t path_info;
    bool32 desc_scan;
    uint32 prev_id;
    bool32 is_found = CT_FALSE;
    knl_temp_cache_t *temp_table;
    temp_btree_segment_t *seg;

    index = (index_t *)cursor->index;
    desc_scan = (bool32)cursor->index_dsc;
    bool32 is_equal = cursor->scan_range.is_equal && IS_UNIQUE_PRIMARY_INDEX(index);

    temp_table = cursor->temp_cache;
    seg = &temp_table->index_root[index->desc.id];
    knl_panic_log(temp_table != NULL, "the temp_table is NULL, panic info: page %u-%u type %u table %s index %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                  ((table_t *)cursor->table)->desc.name, index->desc.name);
    knl_panic_log(seg->root_vmid != CT_INVALID_ID32, "the root_vmid is invalid, panic info: page %u-%u type %u "
                  "table %s index %s", cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                  ((table_t *)cursor->table)->desc.name, index->desc.name);

    if (temp_btree_find_leaf(session, index, seg, desc_scan, scan_key, is_equal,
        &path_info, &is_found) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Fail to open vm page in btree locate with find.");
        return CT_ERROR;
    }

    if (!is_found) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    page = TEMP_BTREE_CURR_PAGE(session);

    if (desc_scan) {
        if (path_info.path[0].vm_slot == 0) {
            prev_id = AS_PAGID_PTR(page->prev)->vmid;
            buf_leave_temp_page_nolock(session, CT_FALSE);
            if (buf_enter_temp_page_nolock(session, prev_id) != CT_SUCCESS) {
                CT_LOG_RUN_ERR("Fail to open vm page (%d) in btree locate with find.", prev_id);
                return CT_ERROR;
            }

            page = TEMP_BTREE_CURR_PAGE(session);
            path_info.path[0].vm_slot = page->keys - 1;
            path_info.path[0].vmid = AS_PAGID_PTR(page->head.id)->vmid;
        } else {
            path_info.path[0].vm_slot--;
        }
    }
    cursor->key_loc.seg_scn = CT_INVALID_ID64;
    cursor->key_loc.lsn = CT_INVALID_ID64;
    cursor->key_loc.slot = (uint16)path_info.path[0].vm_slot;
    cursor->key_loc.page_id.vmid = (uint32)path_info.path[0].vmid;
    cursor->key_loc.next_page_id.vmid = AS_PAGID_PTR(page->next)->vmid;
    cursor->key_loc.prev_page_id.vmid = AS_PAGID_PTR(page->prev)->vmid;
    cursor->key_loc.is_located = CT_TRUE;
    cursor->key_loc.pcn = page->head.pcn;
    cursor->key_loc.index_ver = CT_INVALID_ID64;
    cursor->key_loc.page_cache = NO_PAGE_CACHE;
    cursor->key_loc.slot_end = INVALID_SLOT;
    return CT_SUCCESS;
}

static status_t temp_btree_locate_next_page(knl_session_t *session, knl_cursor_t *cursor)
{
    temp_btree_page_t *page = NULL;
    uint32 next_page;

    next_page = cursor->index_dsc ? cursor->key_loc.prev_page_id.vmid : cursor->key_loc.next_page_id.vmid;

    if (next_page == CT_INVALID_ID32) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    if (buf_enter_temp_page_nolock(session, next_page) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Fail to open vm page (%d) in btree locate next page.", next_page);
        return CT_ERROR;
    }

    page = TEMP_BTREE_CURR_PAGE(session);

    if (cursor->index_dsc) {
        if (temp_btree_locate_prev_page(session, cursor) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("Fail to prev open vm page (%d) in btree locate next page.", cursor->key_loc.page_id.vmid);
            return CT_ERROR;
        }
        page = TEMP_BTREE_CURR_PAGE(session);
        cursor->key_loc.slot = page->keys - 1;
        cursor->key_loc.page_id.vmid = AS_PAGID_PTR(page->head.id)->vmid;
    } else {
        cursor->key_loc.slot = 0;
        cursor->key_loc.page_id.vmid = AS_PAGID_PTR(page->head.id)->vmid;
    }

    cursor->key_loc.lsn = CT_INVALID_ID64;
    cursor->key_loc.pcn = page->head.pcn;
    cursor->key_loc.slot_end = INVALID_SLOT;
    cursor->key_loc.next_page_id.vmid = AS_PAGID_PTR(page->next)->vmid;
    cursor->key_loc.prev_page_id.vmid = AS_PAGID_PTR(page->prev)->vmid;
    return CT_SUCCESS;
}

static status_t temp_btree_relocate_curr_page(knl_session_t *session, knl_cursor_t *cursor,
                                              knl_scan_key_t *scan_key)
{
    bool32 is_same = CT_FALSE;
    btree_path_info_t path_info;
    index_t *index = (index_t *)cursor->index;
    bool32 cmp_rowid;
    temp_btree_page_t *page = NULL;

    cmp_rowid = IS_UNIQUE_PRIMARY_INDEX(index) ? CT_FALSE : CT_TRUE;

    if (cursor->index_dsc) {
        /* if split happened on this page, re-search from root */
        buf_leave_temp_page_nolock(session, CT_FALSE);
        cursor->key_loc.is_located = CT_FALSE;
        return temp_btree_locate_with_find(session, cursor, scan_key);
    }

    page = TEMP_BTREE_CURR_PAGE(session);
    knl_panic_log(page->head.type == PAGE_TYPE_TEMP_INDEX,
                  "page type is abnormal, panic info: page %u-%u type %u table %s",
                  cursor->rowid.file, cursor->rowid.page, page->head.type, ((table_t *)cursor->table)->desc.name);

    for (;;) {
        temp_btree_binary_search(index, page, scan_key, &path_info, cmp_rowid, &is_same);

        if (path_info.path[0].vm_slot < page->keys - 1) {
            /* if key is still on current page, then move on to next slot */
            cursor->key_loc.slot = (uint16)path_info.path[0].vm_slot + 1;
            break;
        }

        cursor->key_loc.page_id.vmid = AS_PAGID_PTR(page->next)->vmid;
        buf_leave_temp_page_nolock(session, CT_FALSE);

        if (cursor->key_loc.page_id.vmid == CT_INVALID_ID32) {
            cursor->eof = CT_TRUE;
            return CT_SUCCESS;
        }

        if (buf_enter_temp_page_nolock(session, cursor->key_loc.page_id.vmid) != CT_SUCCESS) {
            return CT_ERROR;
        }

        page = TEMP_BTREE_CURR_PAGE(session);
        /* if scan key is last key of prev page, no need to binary search on curr page */
        if (is_same) {
            cursor->key_loc.slot = 0;
            break;
        }
    }

    cursor->key_loc.lsn = CT_INVALID_ID64;
    cursor->key_loc.pcn = page->head.pcn;
    cursor->key_loc.next_page_id.vmid = AS_PAGID_PTR(page->next)->vmid;
    cursor->key_loc.prev_page_id.vmid = AS_PAGID_PTR(page->prev)->vmid;

    return CT_SUCCESS;
}

static status_t temp_btree_locate_curr_page(knl_session_t *session, knl_cursor_t *cursor, knl_scan_key_t *scan_key)
{
    temp_btree_page_t *page = NULL;

    if (buf_enter_temp_page_nolock(session, cursor->key_loc.page_id.vmid) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Fail to open vm page (%d) in btree locate curr page.", cursor->key_loc.page_id.vmid);
        return CT_ERROR;
    }
    page = TEMP_BTREE_CURR_PAGE(session);
    knl_panic_log(page->head.type == PAGE_TYPE_TEMP_INDEX,
                  "page type is abnormal, panic info: page %u-%u type %u table %s",
                  cursor->rowid.file, cursor->rowid.page, page->head.type, ((table_t *)cursor->table)->desc.name);

    if (page->head.pcn == cursor->key_loc.pcn) {
        if (cursor->index_dsc) {
            cursor->key_loc.slot--;
        } else {
            cursor->key_loc.slot++;
        }

        if (cursor->key_loc.slot >= page->keys) {
            knl_panic_log(0, "the key's slot is bigger than page keys, panic info: key's slot %u page %u-%u type %u "
                          "keys %u table %s", cursor->key_loc.slot, cursor->rowid.file, cursor->rowid.page,
                          page->head.type, page->keys, ((table_t *)cursor->table)->desc.name);
        }
        return CT_SUCCESS;
    }

    if (temp_btree_relocate_curr_page(session, cursor, scan_key) != CT_SUCCESS) {
        buf_leave_temp_page_nolock(session, CT_FALSE);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t temp_btree_find_key(knl_session_t *session, knl_cursor_t *cursor, knl_scan_key_t *scan_key,
    bool32 *is_found)
{
    if (!cursor->key_loc.is_located) {
        if (temp_btree_locate_with_find(session, cursor, scan_key) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else if (cursor->key_loc.is_last_key) {
        if (temp_btree_locate_next_page(session, cursor) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        if (temp_btree_locate_curr_page(session, cursor, scan_key) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    *is_found = !cursor->eof;
    return CT_SUCCESS;
}

static void temp_btree_decode_scan_key(knl_session_t *session, knl_cursor_t *cursor, btree_key_t *key)
{
    cursor->rowid.vmid = key->rowid.vmid;
    cursor->rowid.vm_slot = key->rowid.vm_slot;

    if (cursor->index_dsc) {
        errno_t ret = memcpy_sp(cursor->scan_range.r_buf, CT_KEY_BUF_SIZE, key, (size_t)key->size);
        knl_securec_check(ret);
        key = (btree_key_t *)cursor->scan_range.r_buf;
        btree_decode_key(cursor->index, key, &cursor->scan_range.r_key);
    } else {
        errno_t ret = memcpy_sp(cursor->scan_range.l_buf, CT_KEY_BUF_SIZE, key, (size_t)key->size);
        knl_securec_check(ret);
        key = (btree_key_t *)cursor->scan_range.l_buf;
        btree_decode_key(cursor->index, key, &cursor->scan_range.l_key);
    }
}

static status_t temp_btree_get_visible_key(knl_session_t *session, knl_cursor_t *cursor, btree_key_t *key,
    btree_key_t **ud_key, bool32 *is_found)
{
    page_id_t ud_page_id = PAGID_U2N(key->undo_page);
    uint16 ud_slot = key->undo_slot;

    *is_found = CT_FALSE;
    for (;;) {
        if (IS_INVALID_PAGID(ud_page_id) || ud_slot == CT_INVALID_ID16) {
            return CT_SUCCESS;
        }

        if (buf_read_page(session, ud_page_id, LATCH_MODE_S, ENTER_PAGE_NORMAL) != CT_SUCCESS) {
            return CT_ERROR;
        }

        undo_page_t *ud_page = (undo_page_t *)CURR_PAGE(session);
        undo_row_t *ud_row = UNDO_ROW(session, ud_page, ud_slot);

        if (cursor->ssn <= ud_row->scn) {
            ud_page_id = PAGID_U2N(ud_row->prev_page);
            ud_slot = ud_row->prev_slot;
            buf_leave_page(session, CT_FALSE);
            continue;
        }

        if (ud_row->type != UNDO_TEMP_BTREE_DELETE) {
            buf_leave_page(session, CT_FALSE);
            return CT_SUCCESS;
        }

        *ud_key = (btree_key_t *)ud_row->data;
        *is_found = CT_TRUE;
        return CT_SUCCESS;
    }
}

static status_t temp_btree_check_with_undo(knl_session_t *session, knl_cursor_t *cursor, btree_key_t *key,
    bool32 *is_found)
{
    btree_key_t *ud_key = NULL;

    if (session->rm->idx_conflicts == 0) {
        return CT_SUCCESS;
    }
    
    if (temp_btree_get_visible_key(session, cursor, key, &ud_key, is_found) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!*is_found) {
        return CT_SUCCESS;
    }

    temp_btree_decode_scan_key(session, cursor, ud_key);
    buf_leave_page(session, CT_FALSE);
    return CT_SUCCESS;
}

static status_t temp_btree_fetch_key_asc(knl_session_t *session, knl_cursor_t *cursor, bool32 *first_get,
                                         bool32 *is_found)
{
    int32 result;
    btree_key_t *key = NULL;
    temp_btree_dir_t *dir = NULL;
    index_t *index = (index_t *)cursor->index;
    bool32 is_same = CT_FALSE;
    temp_btree_page_t *page = TEMP_BTREE_CURR_PAGE(session);
    bool32 is_equal = cursor->scan_range.is_equal && IS_UNIQUE_PRIMARY_INDEX(index);
    bool32 cmp_rowid = (!cursor->scan_range.is_equal && !IS_UNIQUE_PRIMARY_INDEX(index));
    knl_scan_key_t *filter_key = cursor->scan_range.is_equal ? &cursor->scan_range.l_key : &cursor->scan_range.r_key;

    *is_found = CT_FALSE;
    while (cursor->key_loc.slot < page->keys) {
        dir = TEMP_BTREE_GET_DIR(page, cursor->key_loc.slot);
        key = TEMP_BTREE_GET_KEY(page, dir);
        if (is_equal && *first_get) {
            *first_get = CT_FALSE;
        } else {
            result = btree_compare_key(index, filter_key, key, cmp_rowid, &is_same);
            if (result < 0) {
                cursor->eof = CT_TRUE;
                return CT_SUCCESS;
            }
        }

        if (cursor->ssn <= key->scn) {
            if (temp_btree_check_with_undo(session, cursor, key, is_found)) {
                return CT_ERROR;
            }
        } else if (!key->is_deleted) {
            *is_found = CT_TRUE;
            temp_btree_decode_scan_key(session, cursor, key);
        }

        if (*is_found) {
            cursor->key_loc.is_last_key = (cursor->key_loc.slot == page->keys - 1);
            return CT_SUCCESS;
        }
        cursor->key_loc.slot++;
    }

    cursor->key_loc.is_last_key = CT_TRUE;
    return CT_SUCCESS;
}

static status_t temp_btree_fetch_key_dsc(knl_session_t *session, knl_cursor_t *cursor, bool32 *is_found)
{
    int32 result;
    bool32 is_same = CT_FALSE;
    btree_key_t *scan_key = NULL;
    temp_btree_dir_t *dir = NULL;
    index_t *index = (index_t *)cursor->index;
    knl_scan_key_t *filter_key = &cursor->scan_range.l_key;
    temp_btree_page_t *page = TEMP_BTREE_CURR_PAGE(session);
    bool32 cmp_rowid = ((index->desc.primary || index->desc.unique) ? CT_FALSE : CT_TRUE);

    *is_found = CT_FALSE;
    for (;;) {
        dir = TEMP_BTREE_GET_DIR(page, cursor->key_loc.slot);
        scan_key = TEMP_BTREE_GET_KEY(page, dir);
        result = btree_compare_key(index, filter_key, scan_key, cmp_rowid, &is_same);
        if (result > 0) {
            cursor->eof = CT_TRUE;
            return CT_SUCCESS;
        }

        if (cursor->ssn <= scan_key->scn) {
            if (temp_btree_check_with_undo(session, cursor, scan_key, is_found)) {
                return CT_ERROR;
            }
        } else if (!scan_key->is_deleted) {
            *is_found = CT_TRUE;
            temp_btree_decode_scan_key(session, cursor, scan_key);
        }

        if (*is_found) {
            cursor->key_loc.is_last_key = (cursor->key_loc.slot == 0);
            return CT_SUCCESS;
        }

        if (cursor->key_loc.slot > 0) {
            cursor->key_loc.slot--;
        } else {
            break;
        }
    }

    cursor->key_loc.is_last_key = CT_TRUE;
    return CT_SUCCESS;
}

status_t temp_btree_fetch(knl_handle_t handle, knl_cursor_t *cursor)
{
    knl_session_t *session = (knl_session_t *)handle;
    index_t *index = (index_t *)cursor->index;
    knl_scan_key_t *scan_key = NULL;
    bool32 first_get;

    if (cursor->temp_cache == NULL || CURSOR_TEMP_CACHE(cursor)->table_segid == CT_INVALID_ID32) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    knl_temp_cache_t *temp_table = (knl_temp_cache_t *)cursor->temp_cache;
    if (temp_table->table_type == DICT_TYPE_TEMP_TABLE_TRANS &&
        temp_table->hold_rmid != CT_INVALID_ID32 && session->rmid != temp_table->hold_rmid) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }
        
    if (!cursor->key_loc.is_initialized) {
        cursor->key_loc.is_initialized = CT_TRUE;
        cursor->key_loc.is_located = CT_FALSE;
        cursor->key_loc.is_last_key = CT_FALSE;
        first_get = CT_TRUE;
    } else {
        if (cursor->scan_range.is_equal && IS_UNIQUE_PRIMARY_INDEX(index)) {
            cursor->eof = CT_TRUE;
            return CT_SUCCESS;
        }

        first_get = CT_FALSE;
    }

    scan_key = cursor->index_dsc ? &cursor->scan_range.r_key : &cursor->scan_range.l_key;

    for (;;) {
        if (temp_btree_find_key(session, cursor, scan_key, &cursor->is_found) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (!cursor->is_found) {
            return CT_SUCCESS;
        }

        if (cursor->index_dsc) {
            (void)temp_btree_fetch_key_dsc(session, cursor, &cursor->is_found);
        } else {
            (void)temp_btree_fetch_key_asc(session, cursor, &first_get, &cursor->is_found);
        }
        buf_leave_temp_page_nolock(session, CT_FALSE);

        if (cursor->eof) {
            return CT_SUCCESS;
        }

        if (!cursor->is_found) {
            continue;
        }

        if (IS_INDEX_ONLY_SCAN(cursor)) {
            if (knl_match_cond(session, cursor, &cursor->is_found) != CT_SUCCESS) {
                return CT_ERROR;
            }
        } else {
            if (temp_heap_fetch_by_rowid(session, cursor) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }

        if (cursor->is_found) {
            return CT_SUCCESS;
        }
    }

    return CT_SUCCESS;
}

static status_t temp_btree_alloc_page(knl_session_t *session, index_t *index, uint32 index_segid,
                                      uint32 *curr_vmid,
                                      uint32 level, bool32 insert_minimum_key)
{
    temp_btree_page_t *page = NULL;
    mtrl_segment_t *segment = NULL;
    mtrl_context_t *ctx = session->temp_mtrl;
    uint32 vmid;

    segment = session->temp_mtrl->segments[index_segid];

    if (vm_alloc(ctx->session, ctx->pool, &vmid) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Fail to extend segment in btree alloc page.");
        return CT_ERROR;
    }

    if (buf_enter_temp_page_nolock(session, vmid) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Fail to open extend vm (%d) in btree alloc page.", vmid);
        return CT_ERROR;
    }
    page = TEMP_BTREE_CURR_PAGE(session);
    temp_btree_init_page(session, index, page, vmid, level);
    if (insert_minimum_key) {
        temp_btree_insert_minimum_key(session, page);
    }
    buf_leave_temp_page_nolock(session, CT_TRUE);
    vm_append(ctx->pool, &segment->vm_list, vmid);

    *curr_vmid = vmid;

    knl_panic_log(segment->vm_list.last == vmid, "the vm_list's last id is not equal to vmid, panic info: "
                  "page %u-%u type %u index %s last id %u vmid %u", AS_PAGID(page->head.id).file,
                  AS_PAGID(page->head.id).page, page->head.type, index->desc.name, segment->vm_list.last, vmid);
    return CT_SUCCESS;
}

static void temp_btree_move_keys(knl_session_t *session, temp_btree_page_t *src_page, temp_btree_page_t *dst_page,
                                 uint32 pos, uint32 level)
{
    temp_btree_dir_t *dir = NULL;
    btree_key_t *src_key = NULL;
    btree_key_t *new_key = NULL;
    errno_t ret;

    for (uint32 i = pos; i < src_page->keys; i++) {
        dir = TEMP_BTREE_GET_DIR(src_page, i);
        new_key = (btree_key_t *)((char *)dst_page + dst_page->free_begin);
        src_key = TEMP_BTREE_GET_KEY(src_page, dir);
        ret = memcpy_sp(new_key, CT_KEY_BUF_SIZE, src_key, (size_t)src_key->size);
        knl_securec_check(ret);
        dir = TEMP_BTREE_GET_DIR(dst_page, dst_page->keys);
        dir->offset = dst_page->free_begin;
        dir->itl_id = CT_INVALID_ID8;

        dst_page->free_begin += (uint32)src_key->size;
        dst_page->free_end -= sizeof(temp_btree_dir_t);
        dst_page->free_size -= ((uint32)src_key->size + sizeof(temp_btree_dir_t));
        dst_page->keys++;

        if (!src_key->is_cleaned) {
            src_page->free_size += ((uint32)src_key->size + sizeof(temp_btree_dir_t));
            src_key->is_cleaned = (uint16)CT_TRUE;
        }
    }

    src_page->keys = pos;
    src_page->free_end = (uint32)((char *)TEMP_BTREE_GET_DIR(src_page,
                                                             src_page->keys - 1) - (char *)src_page);
}

static void temp_btree_insert_into_page(knl_session_t *session, temp_btree_page_t *page, btree_key_t *key,
                                        rd_btree_insert_t *redo)
{
    temp_btree_dir_t *dir = NULL;
    btree_key_t *curr_key = NULL;
    errno_t ret;
    uint16 i;

    if (redo->is_reuse) {
        dir = TEMP_BTREE_GET_DIR(page, redo->slot);
        curr_key = TEMP_BTREE_GET_KEY(page, dir);
        if (curr_key->is_cleaned) {
            page->free_size -= (uint32)curr_key->size + sizeof(temp_btree_dir_t);
        }
        ret = memcpy_sp(curr_key, CT_KEY_BUF_SIZE, key, (size_t)key->size);
        knl_securec_check(ret);
    } else {
        curr_key = (btree_key_t *)((char *)page + page->free_begin);
        dir = TEMP_BTREE_GET_DIR(page, redo->slot);
        if (redo->slot < page->keys) {
            for (i = page->keys; i > redo->slot; i--) {
                *TEMP_BTREE_GET_DIR(page, i) = *TEMP_BTREE_GET_DIR(page, i - 1);
            }
        }
        dir->offset = page->free_begin;
        dir->itl_id = CT_INVALID_ID8;
        ret = memcpy_sp(curr_key, (size_t)key->size, key, (size_t)key->size);
        knl_securec_check(ret);

        page->free_begin += (uint32)key->size;
        page->free_end -= sizeof(temp_btree_dir_t);
        page->free_size -= ((uint32)key->size + sizeof(temp_btree_dir_t));
        page->keys++;
        knl_panic_log(page->free_begin <= page->free_end, "page's free size begin is more than end, panic info: "
                      "page %u-%u type %u free_begin %u free_end %u", AS_PAGID(page->head.id).file,
                      AS_PAGID(page->head.id).page, page->head.type, page->free_begin, page->free_end);
    }
}

static status_t temp_btree_increase_level(knl_session_t *session, index_t *index, temp_btree_segment_t *seg,
                                          btree_key_t *key1, btree_key_t *key2)
{
    btree_key_t *key = NULL;
    temp_btree_dir_t *dir = NULL;
    temp_btree_page_t *page = NULL;
    uint32 new_page_id;
    errno_t ret;

    if (temp_btree_alloc_page(session, index, seg->index_segid, &new_page_id, seg->level, CT_FALSE) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("failed to find free temp buffer page to increase level.");
        return CT_ERROR;
    }
    if (buf_enter_temp_page_nolock(session, new_page_id) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Fail to open vm page (%d) to increase level.", new_page_id);
        return CT_ERROR;
    }

    page = TEMP_BTREE_CURR_PAGE(session);

    key = (btree_key_t *)((char *)page + page->free_begin);
    ret = memcpy_sp(key, (size_t)key1->size, key1, (size_t)key1->size);
    knl_securec_check(ret);
    dir = TEMP_BTREE_GET_DIR(page, page->keys);
    dir->offset = page->free_begin;
    dir->itl_id = CT_INVALID_ID8;

    page->free_begin += (uint32)key->size;
    page->free_end -= sizeof(temp_btree_dir_t);
    page->free_size -= ((uint32)key->size + sizeof(temp_btree_dir_t));
    page->keys++;

    key = (btree_key_t *)((char *)page + page->free_begin);
    ret = memcpy_sp(key, (size_t)key2->size, key2, (size_t)key2->size);
    knl_securec_check(ret);
    dir = TEMP_BTREE_GET_DIR(page, page->keys);
    dir->offset = page->free_begin;
    dir->itl_id = CT_INVALID_ID8;

    page->free_begin += (uint32)key->size;
    page->free_end -= sizeof(temp_btree_dir_t);
    page->free_size -= ((uint32)key->size + sizeof(temp_btree_dir_t));
    page->keys++;
    knl_panic_log(page->free_begin <= page->free_end, "page's free size begin is more than end, panic info: "
                  "page %u-%u type %u free_begin %u free_end %u index %s", AS_PAGID(page->head.id).file,
                  AS_PAGID(page->head.id).page, page->head.type, page->free_begin, page->free_end, index->desc.name);

    buf_leave_temp_page_nolock(session, CT_TRUE);

    seg->level++;
    seg->root_vmid = new_page_id;
    return CT_SUCCESS;
}

static status_t temp_btree_insert_into_parent(knl_session_t *session, index_t *index, temp_btree_segment_t *seg,
                                              btree_key_t *key, btree_path_info_t *path_info, uint32 level)
{
    temp_btree_page_t *page = NULL;
    rd_btree_insert_t redo;

    if (buf_enter_temp_page_nolock(session, (uint32)path_info->path[level].vmid) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Fail to open vm page (%u) in insert into parent.", path_info->path[level].vmid);
        return CT_ERROR;
    }
    page = TEMP_BTREE_CURR_PAGE(session);

    path_info->path[level].vm_slot++;

    if ((uint32)(page->free_end - page->free_begin) <= TEMP_BTREE_COST_SIZE(key)) {
        buf_leave_temp_page_nolock(session, CT_FALSE);
        if (temp_btree_split_page(session, index, seg, path_info, level) != CT_SUCCESS) {
            return CT_ERROR;
        }
        if (buf_enter_temp_page_nolock(session, (uint32)path_info->path[level].vmid) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("Fail to open splitted vm page (%u) in insert into parent.", path_info->path[level].vmid);
            return CT_ERROR;
        }
        page = TEMP_BTREE_CURR_PAGE(session);
    }

    redo.slot = (uint16)path_info->path[level].vm_slot;
    redo.is_reuse = CT_FALSE;
    redo.itl_id = CT_INVALID_ID8;

    knl_panic_log((uint32)(page->free_end - page->free_begin) >= TEMP_BTREE_COST_SIZE(key), "page's free sieze is "
        "abnormal, panic info: page %u-%u type %u free_end %u free_begin %u index %s", AS_PAGID(page->head.id).file,
        AS_PAGID(page->head.id).page, page->head.type, page->free_end, page->free_begin, index->desc.name);

    temp_btree_insert_into_page(session, page, key, &redo);
    buf_leave_temp_page_nolock(session, CT_TRUE);
    return CT_SUCCESS;
}

static status_t temp_btree_split_page(knl_session_t *session, index_t *index, temp_btree_segment_t *seg,
                                      btree_path_info_t *path_info, uint32 level)
{
    uint16 pos;
    uint32 sum_key_byte;
    uint32 sum_tmp_key_byte;
    btree_key_t *key = NULL;
    btree_key_t *src_tmp_key = NULL;
    temp_btree_dir_t *dir = NULL;
    temp_btree_page_t *src_page = NULL;
    temp_btree_page_t *dst_page = NULL;
    temp_btree_page_t *next_page = NULL;
    uint32 src_page_id, new_page_id, next_page_id;
    // push two key memory space, one for src_key, another one for new_key
    btree_key_t *src_key = (btree_key_t *)cm_push(session->stack, CT_KEY_BUF_SIZE * 2);
    btree_key_t *new_key = (btree_key_t *)((char *)src_key + CT_KEY_BUF_SIZE);
    errno_t ret;

    sum_tmp_key_byte = 0;
    src_page_id = (uint32)path_info->path[level].vmid;

    if (temp_btree_alloc_page(session, index, seg->index_segid, &new_page_id, level, CT_FALSE) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("failed to find free temp buffer page to split.");
        cm_pop(session->stack);
        return CT_ERROR;
    }
    if (buf_enter_temp_page_nolock(session, src_page_id) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Fail to open src vm page (%d) in split page.", src_page_id);
        cm_pop(session->stack);
        return CT_ERROR;
    }
    src_page = TEMP_BTREE_CURR_PAGE(session);
    next_page_id = AS_PAGID_PTR(src_page->next)->vmid;
    if (next_page_id != CT_INVALID_ID32) {
        if (buf_enter_temp_page_nolock(session, next_page_id) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("Fail to open next_page_id vm page (%d) in split page.", next_page_id);
            cm_pop(session->stack);
            return CT_ERROR;
        }
        next_page = TEMP_BTREE_CURR_PAGE(session);
        AS_PAGID_PTR(next_page->prev)->vmid = new_page_id;
        buf_leave_temp_page_nolock(session, CT_TRUE);
    }

    if (buf_enter_temp_page_nolock(session, new_page_id) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Fail to open new_page_id vm page (%d) in split page.", new_page_id);
        cm_pop(session->stack);
        return CT_ERROR;
    }
    dst_page = TEMP_BTREE_CURR_PAGE(session);
    AS_PAGID_PTR(dst_page->prev)->vmid = src_page_id;
    AS_PAGID_PTR(dst_page->next)->vmid = next_page_id;

    knl_panic(src_page->itls == 0);
    sum_key_byte = PAGE_SIZE(src_page->head) - sizeof(page_head_t) - sizeof(temp_page_tail_t) -
                   sizeof(itl_t) * src_page->itls - src_page->free_size;
    pos = 0;
    for (uint32 i = 0; i < src_page->keys; i++) {
        dir = TEMP_BTREE_GET_DIR(src_page, i);
        src_tmp_key = TEMP_BTREE_GET_KEY(src_page, dir);
        sum_tmp_key_byte += (uint32)src_tmp_key->size + sizeof(temp_btree_dir_t);
        /* Move half of the keys to a page when splitting */
        if (sum_tmp_key_byte >= sum_key_byte / 2) {
            pos = i;
            break;
        }
    }
    knl_panic(pos != 0);
    temp_btree_move_keys(session, src_page, dst_page, pos, level);
    temp_btree_compact_page(session, src_page);

    if (path_info->path[level].vm_slot > pos) {
        path_info->path[level].vm_slot -= pos;
        path_info->path[level].vmid = new_page_id;
    }

    key = TEMP_BTREE_GET_KEY(dst_page, TEMP_BTREE_GET_DIR(dst_page, 0));
    ret = memcpy_sp(new_key, CT_KEY_BUF_SIZE, key, (size_t)key->size);
    knl_securec_check(ret);
    buf_leave_temp_page_nolock(session, CT_TRUE);

    AS_PAGID_PTR(src_page->next)->vmid = new_page_id;

    key = TEMP_BTREE_GET_KEY(src_page, TEMP_BTREE_GET_DIR(src_page, 0));
    ret = memcpy_sp(src_key, CT_KEY_BUF_SIZE, key, (size_t)key->size);
    knl_securec_check(ret);
    buf_leave_temp_page_nolock(session, CT_TRUE);

    new_key->is_cleaned = CT_FALSE;
    new_key->is_deleted = CT_FALSE;

    if (level == seg->level - 1) {
        src_key->is_cleaned = CT_FALSE;
        src_key->is_deleted = CT_FALSE;
        src_key->child.vmid = src_page_id;
        new_key->child.vmid = new_page_id;
        if (temp_btree_increase_level(session, index, seg, src_key, new_key) != CT_SUCCESS) {
            cm_pop(session->stack);
            return CT_ERROR;
        }
    } else {
        new_key->child.vmid = new_page_id;
        if (temp_btree_insert_into_parent(session, index, seg, new_key, path_info, level + 1) != CT_SUCCESS) {
            cm_pop(session->stack);
            return CT_ERROR;
        }
    }

    cm_pop(session->stack);
    return CT_SUCCESS;
}

static status_t temp_btree_check_unique(knl_session_t *session, knl_cursor_t *cursor, btree_path_info_t *path_info,
                                        temp_btree_page_t *page, bool32 is_same, bool32 *conflict)
{
    index_t *index = (index_t *)cursor->index;
    btree_key_t *key = NULL;
    temp_btree_dir_t *dir = NULL;

    if ((!index->desc.primary && !index->desc.unique) || !is_same) {
        return CT_SUCCESS;
    }

    dir = TEMP_BTREE_GET_DIR(page, path_info->path[0].vm_slot);
    key = TEMP_BTREE_GET_KEY(page, dir);
    if (!key->is_deleted) {
        cursor->conflict_rid.vmid = key->rowid.vmid;
        cursor->conflict_rid.vm_slot = key->rowid.vm_slot;

        if (cursor->action == CURSOR_ACTION_INSERT || cursor->disable_pk_update) {
            cursor->conflict_idx_slot = cursor->index_slot;
            *conflict = CT_TRUE;
            return idx_generate_dupkey_error(session, index, (char *)key);
        } else if (key->scn == cursor->ssn) {
            *conflict = CT_TRUE;
        }

        CT_THROW_ERROR(ERR_DUPLICATE_KEY, "");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t temp_btree_enter_insert(knl_session_t *session, knl_cursor_t *cursor, temp_btree_segment_t *root_seg,
                                        btree_path_info_t *path_info, bool32 *is_same, bool32 *conflict)
{
    index_t *index = (index_t *)cursor->index;
    btree_key_t *key = (btree_key_t *)cursor->key;
    temp_btree_page_t *page = NULL;
    knl_scan_key_t scan_key;
    bool32 is_found = CT_FALSE;

    btree_decode_key(index, key, &scan_key);
    for (;;) {
        if (temp_btree_find_update_pos(session, index, root_seg, &scan_key, path_info, is_same,
            BTREE_FIND_INSERT, &is_found) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("Fail to open vm page in btree enter insert.");
            return CT_ERROR;
        }
        knl_panic_log(is_found, "scan_key is not found, panic info: page %u-%u type %u table %s inde %s",
                      cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                      ((table_t *)cursor->table)->desc.name, index->desc.name);
        page = TEMP_BTREE_CURR_PAGE(session);
        if ((uint32)(page->free_end - page->free_begin) <= TEMP_BTREE_COST_SIZE(key)) {
            buf_leave_temp_page_nolock(session, CT_FALSE);
            if (temp_btree_split_page(session, index, root_seg, path_info, 0) != CT_SUCCESS) {
                return CT_ERROR;
            }
            continue;
        }

        if (temp_btree_check_unique(session, cursor, path_info, page, *is_same, conflict) != CT_SUCCESS) {
            buf_leave_temp_page_nolock(session, CT_FALSE);
            return CT_ERROR;
        }
        break;
    }
    return CT_SUCCESS;
}

static status_t temp_btree_internal_insert(knl_session_t *session, knl_cursor_t *cursor, bool32 *conflict)
{
    bool32 is_same = CT_FALSE;
    rd_btree_insert_t redo;
    btree_path_info_t path_info;
    index_t *index = (index_t *)cursor->index;
    btree_key_t *key = (btree_key_t *)cursor->key;
    knl_temp_cache_t *temp_table;
    temp_btree_segment_t *root_seg;
    temp_btree_page_t *page = NULL;
    uint32 count;
    errno_t ret;
    bool32 need_redo = IS_TEMPTABLE_HAS_REDO(session);
    undo_page_info_t *undo_page_info = UNDO_GET_PAGE_INFO(session, need_redo);

    temp_table = cursor->temp_cache;
    root_seg = &temp_table->index_root[index->desc.id];
    if (root_seg->root_vmid == CT_INVALID_ID32) {
        // index has been dropped and recreated.
        if (root_seg->org_scn != index->desc.org_scn) {
            return CT_SUCCESS;
        }

        if (CT_SUCCESS != temp_btree_create_segment(session, index, temp_table)) {
            CT_LOG_RUN_ERR("Fail to create btree segment in btree insert.");
            return CT_ERROR;
        }
    }
    index->desc.entry.vmid = 0;
    index->temp_btree = NULL;
    count = sizeof(rowid_t) * CT_MAX_BTREE_LEVEL;
    ret = memset_sp(path_info.path, count, 0, count);
    knl_securec_check(ret);
    path_info.get_sibling = CT_FALSE;
    path_info.sibling_key = NULL;

    // prepare undo which contains btree key and seg_scn
    if (undo_prepare(session, (uint32)key->size + TEMP_KEY_EXTRA_UNDO, need_redo, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    session->rm->temp_has_undo = CT_TRUE;

    if (temp_btree_enter_insert(session, cursor, root_seg, &path_info, &is_same, conflict) != CT_SUCCESS) {
        return CT_ERROR;
    }

    redo.slot = (uint16)path_info.path[0].vm_slot;
    redo.is_reuse = (uint8)is_same;
    redo.itl_id = CT_INVALID_ID8;

    key->is_deleted = CT_FALSE;
    key->undo_page = undo_page_info->undo_rid.page_id;
    key->undo_slot = undo_page_info->undo_rid.slot;
    key->scn = cursor->ssn;

    page = TEMP_BTREE_CURR_PAGE(session);

    knl_panic_log(page->head.type == PAGE_TYPE_TEMP_INDEX,
                  "page type is abnormal, panic info: page %u-%u type %u table %s",
                  cursor->rowid.file, cursor->rowid.page, page->head.type, ((table_t *)cursor->table)->desc.name);

    temp_btree_generate_undo(session, cursor, &path_info, is_same, UNDO_TEMP_BTREE_INSERT);

    temp_btree_insert_into_page(session, page, key, &redo);

    buf_leave_temp_page_nolock(session, CT_TRUE);

    return CT_SUCCESS;
}

static status_t temp_btree_force_update_dupkey(knl_session_t *session, knl_cursor_t *cursor)
{
    btree_key_t *key = (btree_key_t *)cursor->key;
    rowid_t rid;
    bool32 conflict = CT_FALSE;

    ROWID_COPY(rid, key->rowid);
    ROWID_COPY(key->rowid, cursor->conflict_rid);
    ROWID_COPY(cursor->rowid, cursor->conflict_rid); /* to keep cursor->rowid == key->rowid while deleting keys */

    if (temp_btree_delete(session, cursor) != CT_SUCCESS) {
        return CT_ERROR;
    }

    ROWID_COPY(key->rowid, rid);
    ROWID_COPY(cursor->rowid, rid);

    return temp_btree_internal_insert(session, cursor, &conflict);
}

status_t temp_btree_insert(knl_session_t *session, knl_cursor_t *cursor)
{
    bool32 conflict = CT_FALSE;

    if (temp_btree_internal_insert(session, cursor, &conflict) != CT_SUCCESS) {
        int32 err_code = cm_get_error_code();
        if (err_code != ERR_DUPLICATE_KEY || conflict) {
            return CT_ERROR;
        }
        cm_reset_error();
        session->rm->idx_conflicts++;
        return temp_btree_force_update_dupkey(session, cursor);
    }

    return CT_SUCCESS;
}

static status_t temp_btree_batch_insert_prepare(knl_session_t *session, knl_cursor_t *cursor)
{
    index_t *index = (index_t *)cursor->index;

    knl_temp_cache_t *temp_table = cursor->temp_cache;
    temp_btree_segment_t *root_seg = &temp_table->index_root[index->desc.id];
    if (root_seg->root_vmid == CT_INVALID_ID32) {
        // index has been dropped and recreated.
        if (root_seg->org_scn != index->desc.org_scn) {
            return CT_SUCCESS;
        }

        if (temp_btree_create_segment(session, index, temp_table) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("Fail to create temp btree segment in batch insert.");
            return CT_ERROR;
        }
    }

    if (knl_cursor_use_vm(session, cursor, CT_FALSE) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Fail to alloc vm page in temp btree batch insert.");
        return CT_ERROR;
    }

    temp_btree_page_t *page = (temp_btree_page_t *)cursor->vm_page->data;
    temp_btree_init_page(session, index, page, cursor->vm_page->vmid, 0);
    temp_btree_insert_minimum_key(session, page);

    index->desc.entry.vmid = 0;
    index->temp_btree = NULL;

    return CT_SUCCESS;
}

static status_t temp_btree_enter_batch_insert(knl_session_t *session, knl_cursor_t *cursor, bool32 need_redo,
    bool32 *page_changed, btree_key_t *sibling_key)
{
    bool32 is_same = CT_FALSE;
    bool32 conflict = CT_FALSE;
    btree_path_info_t path_info;
    index_t *index = (index_t *)cursor->index;
    knl_temp_cache_t *temp_table = cursor->temp_cache;
    temp_btree_segment_t *root_seg = &temp_table->index_root[index->desc.id];

    uint32 count = sizeof(rowid_t) * CT_MAX_BTREE_LEVEL;
    errno_t ret = memset_sp(path_info.path, count, 0, count);
    knl_securec_check(ret);
    path_info.get_sibling = CT_TRUE;
    path_info.sibling_key = (char *)sibling_key;

    if (temp_btree_enter_insert(session, cursor, root_seg, &path_info, &is_same, &conflict) != CT_SUCCESS) {
        return CT_ERROR;
    }

    temp_btree_page_t *page = TEMP_BTREE_CURR_PAGE(session);
    if (page->free_size > page->free_end - page->free_begin) {
        temp_btree_compact_page(session, page);
    }

    return CT_SUCCESS;
}

static bool32 temp_btree_batch_insert_enable(knl_session_t *session, knl_cursor_t *cursor, btree_key_t *sibling_key,
    btree_key_t *src_key, rd_btree_insert_t *rd_insert)
{
    index_t *index = (index_t *)cursor->index;
    temp_btree_page_t *page = TEMP_BTREE_CURR_PAGE(session);
    knl_scan_key_t scan_key;
    bool32 cmp_rowid = !IS_UNIQUE_PRIMARY_INDEX(index);
    btree_path_info_t path_info;
    bool32 is_same = CT_FALSE;

    rd_insert->slot = INVALID_SLOT;
    rd_insert->is_reuse = CT_FALSE;

    btree_decode_key(index, src_key, &scan_key);
    if (sibling_key != NULL) {
        if (btree_compare_key(index, &scan_key, sibling_key, cmp_rowid, NULL) >= 0) {
            return CT_FALSE;
        }
    }

    temp_btree_binary_search(index, page, &scan_key, &path_info, cmp_rowid, &is_same);

    if (!is_same && page->free_end - page->free_begin < TEMP_BTREE_COST_SIZE(src_key)) {
        return CT_FALSE;
    }

    rd_insert->is_reuse = (uint16)is_same;
    rd_insert->slot = (uint16)path_info.path[0].vm_slot;

    if (is_same) {
        return CT_FALSE;
    }

    return CT_TRUE;
}

static void temp_generate_batch_insert_undo(knl_session_t *session, knl_cursor_t *cursor,
    temp_undo_btreeb_insert_t *undo_insert, uint32 key_count, uint32 key_size)
{
    index_t *index = (index_t *)cursor->index;
    undo_data_t undo;

    undo.size = CM_ALIGN4(OFFSET_OF(temp_undo_btreeb_insert_t, keys) + key_size);
    undo_insert->seg_scn = CURSOR_TEMP_CACHE(cursor)->seg_scn;
    undo_insert->count = key_count;
    undo_insert->aligned = 0;

    undo.snapshot.is_xfirst = cursor->is_xfirst;
    undo.snapshot.is_owscn = 0;
    undo.snapshot.undo_page = INVALID_UNDO_PAGID;
    undo.snapshot.undo_slot = INVALID_SLOT;
    undo.snapshot.scn = 0;
    undo.user_id = index->desc.uid;
    undo.seg_page = index->desc.table_id;
    undo.seg_file = 0;
    undo.index_id = index->desc.id;
    undo.ssn = 0;
    undo.type = UNDO_TEMP_BTREE_BINSERT;
    undo.data = (char *)undo_insert;

    log_atomic_op_begin(session);
    undo_write(session, &undo, IS_TEMPTABLE_HAS_REDO(session), CT_FALSE);
    log_atomic_op_end(session);
}


static uint32 temp_batch_insert_keys(knl_session_t *session, knl_cursor_t *cursor, uint16 *batch_size,
                                     btree_key_t *sibling_key, bool32 *single_insert)
{
    temp_btree_page_t *src_page = (temp_btree_page_t *)cursor->vm_page->data;
    uint32 undo_size = CM_ALIGN4(OFFSET_OF(temp_undo_btreeb_insert_t, keys) + *batch_size);
    temp_btree_page_t *page = TEMP_BTREE_CURR_PAGE(session);
    rd_btree_insert_t redo;
    bool32 need_redo = IS_TEMPTABLE_HAS_REDO(session);
    undo_page_info_t *undo_page_info = UNDO_GET_PAGE_INFO(session, need_redo);
    uint16 key_size = 0;
    uint32 keys = 0;

    CM_SAVE_STACK(session->stack);
    temp_undo_btreeb_insert_t *undo_insert = (temp_undo_btreeb_insert_t *)cm_push(session->stack, undo_size);
    char *undo_keys = ((char *)undo_insert + OFFSET_OF(temp_undo_btreeb_insert_t, keys));
    *single_insert = CT_FALSE;
    undo_insert->count = 0;

    for (uint32 i = 1; i < src_page->keys; i++) {
        temp_btree_dir_t *src_dir = TEMP_BTREE_GET_DIR(src_page, i);
        btree_key_t *src_key = TEMP_BTREE_GET_KEY(src_page, src_dir);
        if (src_key->is_cleaned) {
            continue;
        }

        if (!temp_btree_batch_insert_enable(session, cursor, sibling_key, src_key, &redo)) {
            *single_insert = redo.is_reuse;
            break;
        }

        src_key->is_deleted = CT_FALSE;
        src_key->undo_page = undo_page_info->undo_rid.page_id;
        src_key->undo_slot = undo_page_info->undo_rid.slot;
        src_key->scn = cursor->ssn;

        btree_key_t *ud_key = (btree_key_t *)(undo_keys + key_size);
        errno_t ret = memcpy_sp((void *)ud_key, *batch_size - key_size, src_key, (size_t)src_key->size);
        knl_securec_check(ret);
        temp_btree_insert_into_page(session, page, src_key, &redo);

        key_size += (uint16)src_key->size;
        src_key->is_cleaned = CT_TRUE;
        keys++;
    }

    if (keys > 0) {
        temp_generate_batch_insert_undo(session, cursor, undo_insert, keys, key_size);
        *batch_size -= key_size;
    }
    CM_RESTORE_STACK(session->stack);
    return keys;
}


static status_t temp_btree_do_batch_insert(knl_session_t *session, knl_cursor_t *cursor, temp_btree_page_t *src_page,
                                           bool32 *single_insert, uint16 *batch_size)
{
    bool32 page_changed = CT_FALSE;
    bool32 need_redo = IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type);
    uint32 undo_size = CM_ALIGN4(OFFSET_OF(temp_undo_btreeb_insert_t, keys) + *batch_size);
    if (undo_prepare(session, undo_size, need_redo, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    session->rm->temp_has_undo = CT_TRUE;
    CM_SAVE_STACK(session->stack);
    btree_key_t *sibling_key = cm_push(session->stack, CT_KEY_BUF_SIZE);
    if (temp_btree_enter_batch_insert(session, cursor, need_redo, &page_changed, sibling_key) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    temp_btree_page_t *page = TEMP_BTREE_CURR_PAGE(session);
    uint32 next_vmid = AS_PAGID_PTR(page->next)->vmid;
    if (temp_batch_insert_keys(session, cursor, batch_size,
                               ((next_vmid == CT_INVALID_ID32) ? NULL : sibling_key), single_insert) > 0) {
        page_changed = CT_TRUE;
    }

    buf_leave_temp_page_nolock(session, page_changed);
    CM_RESTORE_STACK(session->stack);

    return CT_SUCCESS;
}

static status_t temp_try_btree_batch_insert(knl_session_t *session, knl_cursor_t *cursor,
                                            temp_btree_page_t *src_page, uint16 *batch_size)
{
    bool32 single_insert = CT_FALSE;
    uint16 rest_size;

    if (*batch_size == 0) {
        return CT_SUCCESS;
    }

    while (*batch_size > 0) {
        rest_size = *batch_size;
        temp_btree_dir_t *dir = TEMP_BTREE_GET_DIR(src_page, 1);
        btree_key_t *key = TEMP_BTREE_GET_KEY(src_page, dir);
        errno_t ret = memcpy_sp(cursor->key, CT_KEY_BUF_SIZE, key, (size_t)key->size);
        knl_securec_check(ret);

        if (temp_btree_do_batch_insert(session, cursor, src_page, &single_insert, &rest_size) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (*batch_size > rest_size) {
            *batch_size = rest_size;
            temp_btree_compact_page(session, src_page);
            if (rest_size == 0) {
                break;
            }
        } else {
            knl_panic_log(single_insert, "temp btree batch insert failed.must insert one key at least.");
        }

        if (single_insert) {
            bool32 conflict = CT_FALSE;
            temp_btree_dir_t *dir1 = TEMP_BTREE_GET_DIR(src_page, 1);
            btree_key_t *key1 = TEMP_BTREE_GET_KEY(src_page, dir1);
            ret = memcpy_sp(cursor->key, CT_KEY_BUF_SIZE, key1, (size_t)key1->size);
            knl_securec_check(ret);

            if (temp_btree_internal_insert(session, cursor, &conflict) != CT_SUCCESS) {
                return CT_ERROR;
            }

            key1->is_cleaned = 1;
            (*batch_size) -= (uint16)key1->size;
            temp_btree_compact_page(session, src_page);
        }
    }

    knl_panic_log(src_page->free_size == src_page->free_end - src_page->free_begin,
                  "temp btree batch insert failed.free size %u, free end %u, free begin %u.",
                  (uint32)src_page->free_size, (uint32)src_page->free_end, (uint32)src_page->free_begin);
    return CT_SUCCESS;
}

static status_t temp_insert_btree_sort_page(knl_session_t *session, index_t *index,
                                            temp_btree_page_t *page, btree_key_t *key)
{
    rd_btree_insert_t redo;
    btree_path_info_t path_info;
    knl_scan_key_t scan_key;
    bool32 cmp_rid = !IS_UNIQUE_PRIMARY_INDEX(index);
    bool32 is_same = CT_FALSE;

    btree_decode_key(index, key, &scan_key);
    temp_btree_binary_search(index, page, &scan_key, &path_info, cmp_rid, &is_same);
    if (is_same) {
        return idx_generate_dupkey_error(session, index, (char *)key);
    }

    redo.is_reuse = CT_FALSE;
    redo.slot = (uint16)path_info.path[0].vm_slot;
    temp_btree_insert_into_page(session, page, key, &redo);

    return CT_SUCCESS;
}

status_t temp_btree_batch_insert(knl_session_t *session, knl_cursor_t *cursor)
{
    if (temp_btree_batch_insert_prepare(session, cursor) != CT_SUCCESS) {
        return CT_ERROR;
    }

    status_t status;
    uint16 batch_size = 0;
    index_t *index = (index_t *)cursor->index;
    row_head_t *org_row = cursor->row;
    temp_btree_page_t *sort_page = (temp_btree_page_t *)cursor->vm_page->data;
    uint32 max_undo_size = undo_max_prepare_size(session, TEMP_INSERT_UNDO_COUNT);
    uint32 max_batch_size = max_undo_size - OFFSET_OF(temp_undo_btreeb_insert_t, keys);

    CM_SAVE_STACK(session->stack);
    btree_key_t *key = (btree_key_t *)cm_push(session->stack, CT_KEY_BUF_SIZE);
    for (uint32 i = 0; i < cursor->rowid_count; i++) {
        cursor->rowid = cursor->rowid_array[i];
        cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, NULL);
        if (knl_make_key(session, cursor, index, (char *)key) != CT_SUCCESS) {
            status = CT_ERROR;
            break;
        }

        if (batch_size + key->size > max_batch_size || sort_page->free_size < TEMP_BTREE_COST_SIZE(key)) {
            if (temp_try_btree_batch_insert(session, cursor, sort_page, &batch_size) != CT_SUCCESS) {
                status = CT_ERROR;
                break;
            }

            CM_ASSERT(sort_page->free_size >= TEMP_BTREE_COST_SIZE(key));
        }

        status = temp_insert_btree_sort_page(session, index, sort_page, key);
        if (status != CT_SUCCESS) {
            break;
        }

        cursor->row = (row_head_t *)((char *)cursor->row + cursor->row->size);
        batch_size += (uint16)key->size;
    }

    if (status == CT_SUCCESS) {
        status = temp_try_btree_batch_insert(session, cursor, sort_page, &batch_size);
    }

    cursor->row = org_row;
    knl_panic_log(status != CT_SUCCESS || batch_size == 0, "temp btree batch insert invalid."
                  "status %u, batch_size %u", (uint32)status, (uint32)batch_size);
    CM_RESTORE_STACK(session->stack);

    return status;
}

static void temp_btree_delete_key(knl_session_t *session, temp_btree_page_t *page, rd_temp_btree_delete_t *redo)
{
    temp_btree_dir_t *dir = TEMP_BTREE_GET_DIR(page, redo->slot);
    btree_key_t *key = TEMP_BTREE_GET_KEY(page, dir);

    key->is_deleted = CT_TRUE;
    dir->itl_id = redo->itl_id;
    key->scn = redo->ssn;
    key->undo_page = redo->undo_page;
    key->undo_slot = redo->undo_slot;
    key->is_owscn = CT_FALSE;
}

status_t temp_btree_delete(knl_session_t *session, knl_cursor_t *cursor)
{
    bool32 is_same = CT_FALSE;
    btree_path_info_t path_info;
    btree_key_t *key = (btree_key_t *)cursor->key;
    knl_scan_key_t scan_key;
    bool32 is_found = CT_FALSE;
    rd_temp_btree_delete_t redo;
    knl_temp_cache_t *temp_table = cursor->temp_cache;
    bool32 need_redo = IS_TEMPTABLE_HAS_REDO(session);
    undo_page_info_t *undo_page_info = UNDO_GET_PAGE_INFO(session, need_redo);

    knl_panic_log(temp_table != NULL, "the temp_table is NULL, panic info: page %u-%u type %u table %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                  ((table_t *)cursor->table)->desc.name);

    temp_btree_segment_t *seg = &temp_table->index_root[((index_t *)cursor->index)->desc.id];
    if (seg->root_vmid == CT_INVALID_ID32) {
        return CT_SUCCESS;
    }

    // prepare undo for btree key and seg_scn
    if (undo_prepare(session, (uint32)key->size + TEMP_KEY_EXTRA_UNDO, need_redo, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    session->rm->temp_has_undo = CT_TRUE;
    path_info.get_sibling = CT_FALSE;
    path_info.sibling_key = NULL;

    btree_decode_key(cursor->index, key, &scan_key);
    if (temp_btree_find_update_pos(session, cursor->index, seg, &scan_key, &path_info, &is_same,
        BTREE_FIND_DELETE, &is_found) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Fail to open vm page in btree delete.");
        return CT_ERROR;
    }
    knl_panic_log(is_found, "scan_key is not found, panic info: page %u-%u type %u table %s", cursor->rowid.file,
        cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name);
    temp_btree_page_t *page = TEMP_BTREE_CURR_PAGE(session);

    if (!is_same) {
        buf_leave_temp_page_nolock(session, CT_FALSE);
        knl_panic_log(is_same, "scan_key is not found, panic info: page %u-%u type %u table %s", cursor->rowid.file,
            cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name);
    }

    if (session->rm->idx_conflicts > 0) {
        temp_btree_dir_t *dir = TEMP_BTREE_GET_DIR(page, (uint32)path_info.path[0].vm_slot);
        btree_key_t *curr_key = TEMP_BTREE_GET_KEY(page, dir);

        if (!IS_SAME_ROWID(curr_key->rowid, cursor->rowid)) {
            buf_leave_temp_page_nolock(session, CT_FALSE);
            session->rm->idx_conflicts--;
            return CT_SUCCESS;
        }
    }

    redo.slot = (uint16)path_info.path[0].vm_slot;

    redo.undo_page = undo_page_info->undo_rid.page_id;
    redo.undo_slot = undo_page_info->undo_rid.slot;
    redo.ssn = cursor->ssn;
    redo.itl_id = CT_INVALID_ID8;

    temp_btree_generate_undo(session, cursor, &path_info, CT_TRUE, UNDO_TEMP_BTREE_DELETE);

    temp_btree_delete_key(session, page, &redo);
    buf_leave_temp_page_nolock(session, CT_TRUE);

    return CT_SUCCESS;
}

void temp_btree_undo_insert(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot,
                            knl_dictionary_t *dc)
{
    temp_btree_page_t *page = NULL;
    temp_btree_dir_t *dir = NULL;
    btree_path_info_t path_info;
    btree_key_t *ud_key = (btree_key_t *)ud_row->data;
    btree_key_t *key = NULL;
    bool32 is_same = CT_FALSE;
    bool32 is_found = CT_FALSE;
    knl_scan_key_t scan_key;
    knl_temp_cache_t *temp_table = NULL;
    temp_btree_segment_t *seg = NULL;
    uint32 count;
    errno_t ret;
    index_t *index = NULL;
    uint64 seg_scn;

    if (DB_IS_BG_ROLLBACK_SE(session)) {
        return;
    }

    index = dc_get_index(session, (uint32)ud_row->user_id, (uint32)ud_row->seg_page, (uint32)ud_row->index_id, dc);
    CT_RETVOID_IFTRUE(index == NULL); /* in case of temp btree construct, if failed, the index will be NULL. */

    temp_table = knl_get_temp_cache(session, index->entity->table.desc.uid, index->entity->table.desc.id);
    seg_scn = *(uint64 *)((char *)ud_row->data + ud_row->data_size - sizeof(knl_scn_t));

    if (temp_table == NULL || temp_table->seg_scn != seg_scn) {
        return;
    }

    knl_panic_log((uint32)ud_row->seg_page == temp_table->table_id, "btree segment page id is not equal to "
                  "temp_table's table id, panic info: ud_page %u-%u type %u index %s seg_page %u table_id %u",
                  AS_PAGID(ud_page->head.id).file, AS_PAGID(ud_page->head.id).page, ud_page->head.type,
                  index->desc.name, (uint32)ud_row->seg_page, temp_table->table_id);
    knl_panic_log(temp_table->org_scn == index->entity->table.desc.org_scn, "the temp_table's org_scn is not equal "
                  "to table, panic info: ud_page %u-%u type %u, index %s", AS_PAGID(ud_page->head.id).file,
                  AS_PAGID(ud_page->head.id).page, ud_page->head.type, index->desc.name);
    seg = &temp_table->index_root[ud_row->index_id];
    knl_panic_log(seg->root_vmid != CT_INVALID_ID32,
        "the root_vmid is invalid, panic info: ud_page %u-%u type %u index %s", AS_PAGID(ud_page->head.id).file,
        AS_PAGID(ud_page->head.id).page, ud_page->head.type, index->desc.name);
    count = sizeof(rowid_t) * CT_MAX_BTREE_LEVEL;
    ret = memset_sp(path_info.path, count, 0, count);
    knl_securec_check(ret);
    path_info.get_sibling = CT_FALSE;
    path_info.sibling_key = NULL;

    btree_decode_key(index, ud_key, &scan_key);
    if (temp_btree_find_update_pos(session, index, seg, &scan_key, &path_info, &is_same,
        BTREE_FIND_DELETE, &is_found) != CT_SUCCESS) {
        CM_ABORT(0, "[TEMP] ABORT INFO: Fail to open vm page in btree undo insert.");
        return;
    }
    knl_panic_log(is_found, "scan_key is not found, panic info: ud_page %u-%u type %u index %s",
        AS_PAGID(ud_page->head.id).file, AS_PAGID(ud_page->head.id).page, ud_page->head.type, index->desc.name);
    knl_panic_log(is_same, "scan_key is not found, panic info: ud_page %u-%u type %u index %s",
        AS_PAGID(ud_page->head.id).file, AS_PAGID(ud_page->head.id).page, ud_page->head.type, index->desc.name);
    CM_ABORT((is_found && is_same), "[TEMP] ABORT INFO: cannot find the key for undo insert");

    page = TEMP_BTREE_CURR_PAGE(session);
    knl_panic_log(page->head.type == PAGE_TYPE_TEMP_INDEX, "curr page type is abnormal, panic info: "
                  "curr page %u-%u type %u, ud_page %u-%u type %u, index %s", AS_PAGID(page->head.id).file,
                  AS_PAGID(page->head.id).page, page->head.type, AS_PAGID(ud_page->head.id).file,
                  AS_PAGID(ud_page->head.id).page, ud_page->head.type, index->desc.name);
    dir = TEMP_BTREE_GET_DIR(page, path_info.path[0].vm_slot);
    key = TEMP_BTREE_GET_KEY(page, dir);

    knl_panic_log(IS_SAME_PAGID(key->undo_page, AS_PAGID(ud_page->head.id)), "key's undo_page and ud_page are not "
        "same, panic info: undo_page %u-%u ud_page %u-%u type %u cur_page %u-%u type %u index %s", key->undo_page.file,
        key->undo_page.page, AS_PAGID(ud_page->head.id).file, AS_PAGID(ud_page->head.id).page, ud_page->head.type,
        AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type, index->desc.name);
    knl_panic_log(key->undo_slot == ud_slot, "key's undo_slot is not equal to ud_slot, panic info: page %u-%u type %u "
                  "ud_page %u-%u type %u undo_slot %u ud_slot %u index %s", AS_PAGID(page->head.id).file,
                  AS_PAGID(page->head.id).page, page->head.type, AS_PAGID(ud_page->head.id).file,
                  AS_PAGID(ud_page->head.id).page, ud_page->head.type, key->undo_slot, ud_slot, index->desc.name);
    knl_panic_log(dir->itl_id == CT_INVALID_ID8, "dir's itl id is valid, panic info: page %u-%u type %u ud_page %u-%u "
                  "type %u itl_id %u index %s", AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page,
                  page->head.type, AS_PAGID(ud_page->head.id).file, AS_PAGID(ud_page->head.id).page,
                  ud_page->head.type, dir->itl_id, index->desc.name);

    key->undo_page = ud_row->prev_page;
    key->undo_slot = ud_row->prev_slot;
    key->is_owscn = 0;
    key->scn = ud_row->scn;
    knl_panic_log(key->is_deleted == CT_FALSE, "the key is deleted, panic info: page %u-%u type %u ud_page %u-%u "
        "type %u index %s", AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type,
        AS_PAGID(ud_page->head.id).file, AS_PAGID(ud_page->head.id).page, ud_page->head.type, index->desc.name);
    key->is_deleted = CT_TRUE;
    dir->itl_id = CT_INVALID_ID8;

    key->rowid = ud_key->rowid;
    buf_leave_temp_page_nolock(session, CT_TRUE);
}

static void temp_btree_undo_batch_key(undo_page_t *ud_page, undo_row_t *ud_row, int32 ud_slot, btree_key_t *ud_key,
                                      temp_btree_page_t *page, btree_path_info_t *path_info)
{
    temp_btree_dir_t *dir = TEMP_BTREE_GET_DIR(page, path_info->path[0].vm_slot);
    btree_key_t *key = TEMP_BTREE_GET_KEY(page, dir);

    knl_panic_log(IS_SAME_PAGID(key->undo_page, AS_PAGID(ud_page->head.id)) && key->undo_slot == ud_slot &&
                  dir->itl_id == CT_INVALID_ID8, "temp btree undo batch key failed.key_undo_page %u-%u"
                  " ud_page %u-%u type %u key_undo_slot %u ud_slot %u itl_id %u", key->undo_page.file,
                  key->undo_page.page, AS_PAGID(ud_page->head.id).file, AS_PAGID(ud_page->head.id).page,
                  ud_page->head.type, (uint32)key->undo_slot, (uint32)ud_slot, (uint32)dir->itl_id);
    key->undo_page = ud_row->prev_page;
    key->undo_slot = ud_row->prev_slot;
    key->is_owscn = 0;
    key->scn = ud_row->scn;
    knl_panic_log(!key->is_deleted, "temp btree undo batch key failed.key is deleted.");
    key->is_deleted = CT_TRUE;
    dir->itl_id = CT_INVALID_ID8;

    key->rowid = ud_key->rowid;
    key->is_cleaned = CT_TRUE;
}

static bool32 temp_btree_undo_binsert_anable(knl_session_t *session, undo_row_t *ud_row, knl_dictionary_t *dc)
{
    temp_undo_btreeb_insert_t *ud_batch = (temp_undo_btreeb_insert_t *)ud_row->data;

    if (DB_IS_BG_ROLLBACK_SE(session)) {
        return CT_FALSE;
    }

    index_t *index = dc_get_index(session, (uint32)ud_row->user_id, (uint32)ud_row->seg_page,
                                  (uint32)ud_row->index_id, dc);
    if (index == NULL) { /* in case of temp btree construct, if failed, the index will be NULL. */
        return CT_FALSE;
    }

    knl_temp_cache_t *temp_table = knl_get_temp_cache(session, index->entity->table.desc.uid,
                                                      index->entity->table.desc.id);
    uint64 seg_scn = ud_batch->seg_scn;
    if (temp_table == NULL || temp_table->seg_scn != seg_scn) {
        return CT_FALSE;
    }

    return CT_TRUE;
}

void temp_btree_undo_batch_insert(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot,
                                  knl_dictionary_t *dc)
{
    if (!temp_btree_undo_binsert_anable(session, ud_row, dc)) {
        return;
    }

    temp_undo_btreeb_insert_t *ud_batch = (temp_undo_btreeb_insert_t *)ud_row->data;
    index_t *index = dc_get_index(session, (uint32)ud_row->user_id, (uint32)ud_row->seg_page,
                                  (uint32)ud_row->index_id, dc);
    CT_RETVOID_IFTRUE(index == NULL); /* in case of temp btree construct, if failed, the index will be NULL. */
    knl_temp_cache_t *temp_table = knl_get_temp_cache(session, index->entity->table.desc.uid,
                                                      index->entity->table.desc.id);
    bool32 cmp_rowid = !IS_UNIQUE_PRIMARY_INDEX(index);
    temp_btree_page_t *page = NULL;
    btree_path_info_t path_info;
    knl_scan_key_t scan_key;
    bool32 is_same = CT_FALSE;
    bool32 is_found = CT_FALSE;
    bool32 find_page = CT_FALSE;
    uint16 keys = 0;
    uint16 offset = 0;
    path_info.get_sibling = CT_FALSE;

    while (keys < ud_batch->count) {
        btree_key_t *ud_key = (btree_key_t *)((char *)ud_batch->keys + offset);
        btree_decode_key(index, ud_key, &scan_key);
        if (find_page) {
            temp_btree_binary_search(index, page, &scan_key, &path_info, cmp_rowid, &is_same);
            if (path_info.path[0].vm_slot >= page->keys) {
                temp_btree_compact_page(session, page);
                buf_leave_temp_page_nolock(session, CT_TRUE);
                find_page = CT_FALSE;
                continue;
            }
        } else {
            if (temp_btree_find_update_pos(session, index, &temp_table->index_root[ud_row->index_id],
                &scan_key, &path_info, &is_same, BTREE_FIND_DELETE, &is_found) != CT_SUCCESS) {
                knl_panic_log(0, "[TEMP] ABORT INFO: Fail to open vm page in btree undo insert.");
                return;
            }
            knl_panic_log(is_found && is_same, "temp btree undo batch insert did't find key."
                          "is_found %u, is_same %u", is_found, is_same);
            page = TEMP_BTREE_CURR_PAGE(session);
            find_page = CT_TRUE;
        }

        temp_btree_undo_batch_key(ud_page, ud_row, ud_slot, ud_key, page, &path_info);
        offset += (uint16)ud_key->size;
        keys++;
    }

    temp_btree_compact_page(session, page);
    buf_leave_temp_page_nolock(session, CT_TRUE);
}

void temp_btree_undo_delete(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot,
                            knl_dictionary_t *dc)
{
    temp_btree_page_t *page = NULL;
    temp_btree_dir_t *dir = NULL;
    btree_path_info_t path_info;
    btree_key_t *key = NULL;
    knl_scan_key_t scan_key;
    bool32 is_same = CT_FALSE;
    bool32 is_found = CT_FALSE;
    knl_temp_cache_t *temp_table = NULL;
    temp_btree_segment_t *seg = NULL;
    uint32 count;
    errno_t ret;
    index_t *index = NULL;

    if (DB_IS_BG_ROLLBACK_SE(session)) {
        return;
    }

    index = dc_get_index(session, (uint32)ud_row->user_id, (uint32)ud_row->seg_page, (uint32)ud_row->index_id, dc);
    CT_RETVOID_IFTRUE(index == NULL); /* in case of temp btree construct, if failed, the index will be NULL. */
    temp_table = knl_get_temp_cache(session, index->entity->table.desc.uid, index->entity->table.desc.id);
    uint64 seg_scn = *(uint64 *)((char *)ud_row->data + ud_row->data_size - TEMP_KEY_EXTRA_UNDO);

    if (temp_table == NULL || temp_table->seg_scn != seg_scn) {
        return;
    }
    knl_panic_log((uint32)ud_row->seg_page == temp_table->table_id, "btree segment page id is not equal to "
                  "temp_table's table id, panic info: ud_page %u-%u type %u index %s seg_page id %u table_id %u",
                  AS_PAGID(ud_page->head.id).file, AS_PAGID(ud_page->head.id).page, ud_page->head.type,
                  index->desc.name, (uint32)ud_row->seg_page, temp_table->table_id);
    knl_panic_log(temp_table->org_scn == index->entity->table.desc.org_scn, "the temp_table's org_scn is not equal to "
                  "table's, panic info: ud_page %u-%u type %u index %s temp_table's org_scn %llu table's org_scn %llu",
                  AS_PAGID(ud_page->head.id).file, AS_PAGID(ud_page->head.id).page, ud_page->head.type,
                  index->desc.name, temp_table->org_scn, index->entity->table.desc.org_scn);
    seg = &temp_table->index_root[ud_row->index_id];
    knl_panic_log(seg->root_vmid != CT_INVALID_ID32, "the root_vmid is invalid, panic info: "
                  "ud_page %u-%u type %u index %s", AS_PAGID(ud_page->head.id).file,
                  AS_PAGID(ud_page->head.id).page, ud_page->head.type, index->desc.name);
    count = sizeof(rowid_t) * CT_MAX_BTREE_LEVEL;
    ret = memset_sp(path_info.path, count, 0, count);
    knl_securec_check(ret);
    path_info.get_sibling = CT_FALSE;
    path_info.sibling_key = NULL;

    key = (btree_key_t *)ud_row->data;

    btree_decode_key(index, key, &scan_key);
    if (temp_btree_find_update_pos(session, index, seg, &scan_key, &path_info, &is_same,
        BTREE_FIND_DELETE, &is_found) != CT_SUCCESS) {
        CM_ABORT(0, "[TEMP] ABORT INFO: Fail to open vm page in btree undo delete.");
        return;
    }
    knl_panic_log(is_found, "scan_key is not found, panic info: ud_page %u-%u type %u index %s",
        AS_PAGID(ud_page->head.id).file, AS_PAGID(ud_page->head.id).page, ud_page->head.type, index->desc.name);
    knl_panic_log(is_same, "scan_key is not found, panic info: ud_page %u-%u type %u index %s",
        AS_PAGID(ud_page->head.id).file, AS_PAGID(ud_page->head.id).page, ud_page->head.type, index->desc.name);

    page = TEMP_BTREE_CURR_PAGE(session);
    knl_panic_log(page->head.type == PAGE_TYPE_TEMP_INDEX, "page type is abnormal, panic info: page %u-%u type %u "
        "ud_page %u-%u type %u index %s", AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type,
        AS_PAGID(ud_page->head.id).file, AS_PAGID(ud_page->head.id).page, ud_page->head.type, index->desc.name);
    dir = TEMP_BTREE_GET_DIR(page, path_info.path[0].vm_slot);
    key = TEMP_BTREE_GET_KEY(page, dir);
    knl_panic_log(IS_SAME_PAGID(key->undo_page, AS_PAGID(ud_page->head.id)), "key's undo_page and ud_page are not "
        "same, panic info: undo_page %u-%u ud_page %u-%u type %u page %u-%u type %u index %s", key->undo_page.file,
        key->undo_page.page, AS_PAGID(ud_page->head.id).file, AS_PAGID(ud_page->head.id).page, ud_page->head.type,
        AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type, index->desc.name);
    knl_panic_log(key->undo_slot == ud_slot, "key's undo_slot is not equal to ud_slot, panic info: page %u-%u type %u "
                  "ud_page %u-%u type %u undo_slot %u ud_slot %u index %s", AS_PAGID(page->head.id).file,
                  AS_PAGID(page->head.id).page, page->head.type, AS_PAGID(ud_page->head.id).file,
                  AS_PAGID(ud_page->head.id).page, ud_page->head.type, key->undo_slot, ud_slot, index->desc.name);
    knl_panic_log(dir->itl_id == CT_INVALID_ID8, "dir's itl id is valid, panic info: page %u-%u type %u, "
                  "ud_page %u-%u type %u,itl_id %u index %s", AS_PAGID(page->head.id).file,
                  AS_PAGID(page->head.id).page, page->head.type, AS_PAGID(ud_page->head.id).file,
                  AS_PAGID(ud_page->head.id).page, ud_page->head.type, dir->itl_id, index->desc.name);

    key->undo_page = ud_row->prev_page;
    key->undo_slot = ud_row->prev_slot;
    key->is_owscn = 0;
    key->scn = ud_row->scn;
    knl_panic_log(key->is_deleted == CT_TRUE, "the key is not deleted, panic info: page %u-%u type %u, ud_page %u-%u "
        "type %u, index %s", AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type,
        AS_PAGID(ud_page->head.id).file, AS_PAGID(ud_page->head.id).page, ud_page->head.type, index->desc.name);
    key->is_deleted = CT_FALSE;
    dir->itl_id = CT_INVALID_ID8;

    buf_leave_temp_page_nolock(session, CT_TRUE);
}

#ifdef __cplusplus
}
#endif
