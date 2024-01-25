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
 * rcr_btree.c
 *
 *
 * IDENTIFICATION
 * src/kernel/index/rcr_btree.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_index_module.h"
#include "rcr_btree.h"
#include "rcr_btree_scan.h"
#include "cm_utils.h"
#include "knl_dc.h"
#include "knl_context.h"
#include "knl_table.h"
#include "temp_btree.h"
#include "pcr_btree.h"
#include "index_common.h"
#include "knl_space_manage.h"
#include "dtc_dls.h"
#include "dtc_dc.h"

#define BTREE_MIN_COALESCE_LEVEL 2

typedef bool32 (*btree_recycle_check_t)(knl_session_t *session, btree_page_t *page,
    knl_scn_t interval_scn, btree_recycle_desc_t *desc);
typedef void (*btree_recycle_t)(knl_session_t *session, btree_t *btree,
    knl_part_locate_t part_loc, btree_recycle_desc_t *desc);

typedef struct st_btree_coalesce_assist {
    btree_recycle_check_t checker;
    btree_recycle_t recycler;
    bool32 need_suspend;
} btree_coalesce_assist_t;

static void btree_split_page(knl_session_t *session, btree_t *btree, btree_key_t *insert_key,
                             btree_path_info_t *path_info, uint32 level, bool32 use_pct);

void btree_cache_reset(knl_session_t *session)
{
    index_cache_ctx_t *ctx = &session->kernel->index_ctx.cache_ctx;
    index_page_item_t *item = NULL;
    uint32 i;

    for (i = 0; i < ctx->hwm; i++) {
        item = BTREE_GET_ITEM(session, ctx, i);
        item->is_invalid = CT_TRUE;
    }
}

static inline void btree_minimize_unique_parent(index_t *index, btree_key_t *key)
{
    if (IS_UNIQUE_PRIMARY_INDEX(index) && !BTREE_KEY_IS_NULL(key)) {
        MINIMIZE_ROWID(key->rowid);
    }
}
status_t btree_dump_page(knl_session_t *session, page_head_t *page_head, cm_dump_t *dump)
{
    btree_page_t *page = (btree_page_t *)page_head;

    cm_dump(dump, "btree page information\n");
    cm_dump(dump, "\tseg_scn: %llu", page->seg_scn);
    cm_dump(dump, "\tprev: %u-%u", AS_PAGID_PTR(page->prev)->file, AS_PAGID_PTR(page->prev)->page);
    cm_dump(dump, "\tnext: %u-%u\n", AS_PAGID_PTR(page->next)->file, AS_PAGID_PTR(page->next)->page);
    cm_dump(dump, "\tlevel: %u", page->level);
    cm_dump(dump, "\tkeys: %u", page->keys);
    cm_dump(dump, "\titls: %u", page->itls);
    cm_dump(dump, "\tfree_begin: %u", page->free_begin);
    cm_dump(dump, "\tfree_end: %u", page->free_end);
    cm_dump(dump, "\tfree_size: %u\n", page->free_size);

    cm_dump(dump, "itl information on this page\n");

    CM_DUMP_WRITE_FILE(dump);

    itl_t *itl = NULL;
    for (uint32 slot = 0; slot < page->itls; slot++) {
        itl = BTREE_GET_ITL(page, slot);

        cm_dump(dump, "\tslot: #%-3u", slot);
        cm_dump(dump, "\tscn: %llu", itl->scn);
        cm_dump(dump, "\txmap: %u-%u", itl->xid.xmap.seg_id, itl->xid.xmap.slot);
        cm_dump(dump, "\txnum: %u", itl->xid.xnum);
        cm_dump(dump, "\tfsc: %u", itl->fsc);
        cm_dump(dump, "\tis_active: %u", itl->is_active);
        cm_dump(dump, "\tis_owscn: %u\n", itl->is_owscn);
    
        CM_DUMP_WRITE_FILE(dump);
    }

    cm_dump(dump, "key information on this page\n");
    btree_dir_t *dir = NULL;
    btree_key_t *key = NULL;
    for (uint32 slot = 0; slot < page->keys; slot++) {
        dir = BTREE_GET_DIR(page, slot);
        key = BTREE_GET_KEY(page, dir);

        cm_dump(dump, "\tslot: #%-3u", slot);
        cm_dump(dump, "\toffset: %-5u", dir->offset);
        cm_dump(dump, "\titl_id: %u", dir->itl_id);
        cm_dump(dump, "\tscn: %llu", key->scn);
        cm_dump(dump, "\towscn/infinite/deleted/cleaned: %u/%u/%u/%u",
            key->is_owscn, key->is_infinite, key->is_deleted, key->is_cleaned);
        cm_dump(dump, "\theap_page: %u-%u", key->rowid.file, key->rowid.page);
        cm_dump(dump, "\theap_slot: %u", key->rowid.slot);
        cm_dump(dump, "\tundo_page: %u-%u", key->undo_page.file, key->undo_page.page);
        cm_dump(dump, "\tundo_slot: %u", key->undo_slot);
        cm_dump(dump, "\tsize: %u\n", key->size);

        CM_DUMP_WRITE_FILE(dump);
    }
    return CT_SUCCESS;
}

/*
 * Description     : Initialize a btree key with given heap row id
 * Input           : rid : heap row id
 * Output          : NA
 * Return Value    : void
 * History         : 1.2017/4/26,  add description
 */
void btree_init_key(btree_key_t *key, rowid_t *rid)
{
    int32 ret;

    ret = memset_sp(key, sizeof(btree_key_t), 0, sizeof(btree_key_t));
    knl_securec_check(ret);

    if (rid != NULL) {
        ROWID_COPY(key->rowid, *rid);
    } else {
        MINIMIZE_ROWID(key->rowid);
    }

    key->size = sizeof(btree_key_t);
}

/*
 * Description     : Set one column data of btree
 * Input           : type : data type of this column
 * Input           : data : pointer of column data
 * Input           : len  : data length of column data
 * Input           : id   : id of this column in btree index
 * Output          : NA
 * Return Value    : void
 * History         : 1.2017/4/26,  add description
 */
void btree_put_key_data(char *key_buf, ct_type_t type, const char *data, uint16 len, uint16 id)
{
    btree_key_t *key = (btree_key_t *)key_buf;
    uint32 align_size;
    uint32 buf_size;
    errno_t err;

    if (data == NULL || len == CT_NULL_VALUE_LEN) {
        return;
    }

    btree_set_bitmap(&key->bitmap, id);

    switch (type) {
        case CT_TYPE_UINT64:
            *(uint64 *)CURR_KEY_PTR(key) = *(uint64 *)data;
            key->size += sizeof(uint64);
            break;
        case CT_TYPE_BIGINT:
            if (len == sizeof(int32)) {
                *(int64 *)CURR_KEY_PTR(key) = (int64)(*(int32 *)data);
                key->size += sizeof(int64);
                break;
            }
        // fall-through
        case CT_TYPE_UINT32:
        case CT_TYPE_INTEGER:
        case CT_TYPE_REAL:
        case CT_TYPE_DATE:
        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_BOOLEAN:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
        case CT_TYPE_TIMESTAMP_TZ:
        case CT_TYPE_TIMESTAMP_LTZ:
        case CT_TYPE_INTERVAL_DS:
        case CT_TYPE_INTERVAL_YM:
        case CT_TYPE_DATETIME_MYSQL:
        case CT_TYPE_TIME_MYSQL:
        case CT_TYPE_DATE_MYSQL:
            buf_size = CT_KEY_BUF_SIZE - (uint32)key->size;
            err = memcpy_sp(CURR_KEY_PTR(key), buf_size, data, len);
            knl_securec_check(err);
            key->size += len;
            break;
        case CT_TYPE_NUMBER2:
            if (SECUREC_UNLIKELY(len == 0)) {
                *(uint8 *)CURR_KEY_PTR(key) = 1;
                *(uint8 *)(CURR_KEY_PTR(key) + sizeof(uint8)) = ZERO_EXPN;
                key->size += 1 + sizeof(uint8);
                break;
            }
            buf_size = CT_KEY_BUF_SIZE - (uint32)key->size - sizeof(uint8);
            *(uint8 *)CURR_KEY_PTR(key) = (uint8)len;
            err = memcpy_sp(CURR_KEY_PTR(key) + sizeof(uint8), buf_size, data, len);
            knl_securec_check(err);
            key->size += (len + sizeof(uint8));
            break;
        case CT_TYPE_DECIMAL:
        case CT_TYPE_NUMBER3:
        case CT_TYPE_NUMBER:
            if (SECUREC_UNLIKELY(len == 0)) {
                buf_size = CT_KEY_BUF_SIZE - (uint32)key->size - sizeof(uint16);
                *(uint16 *)CURR_KEY_PTR(key) = CSF_NUMBER_INDEX_LEN;
                err = memcpy_sp(CURR_KEY_PTR(key) + sizeof(uint16), buf_size, "\0\0\0\0", CSF_NUMBER_INDEX_LEN);
                knl_securec_check(err);
                key->size += CM_ALIGN4(CSF_NUMBER_INDEX_LEN + sizeof(uint16));
                break;
            }
        // fall-through
        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
        case CT_TYPE_STRING:
        case CT_TYPE_BINARY:
        case CT_TYPE_VARBINARY:
        case CT_TYPE_RAW:
            *(uint16 *)CURR_KEY_PTR(key) = len;
            buf_size = CT_KEY_BUF_SIZE - (uint32)key->size - sizeof(uint16);
            if (len != 0) {
                err = memcpy_sp(CURR_KEY_PTR(key) + sizeof(uint16), buf_size, data, len);
                knl_securec_check(err);
            }

            align_size = CM_ALIGN4(len + sizeof(uint16)) - (len + sizeof(uint16));
            if (align_size != 0) {
                buf_size -= len;
                err = memset_sp(CURR_KEY_PTR(key) + (len + sizeof(uint16)), buf_size, 0, align_size);
                knl_securec_check(err);
            }
            key->size += CM_ALIGN4(len + sizeof(uint16));
            break;
        default:
            CT_LOG_RUN_WAR("[BTREE] unknown datatype %u when generate key data", type);
            knl_panic(0);
    }
}

static inline void btree_clean_dir(knl_session_t *session, btree_page_t *page, uint16 slot)
{
    uint16 j;

    for (j = slot; j < page->keys - 1; j++) {
        *BTREE_GET_DIR(page, j) = *BTREE_GET_DIR(page, j + 1);
    }

    page->keys--;
}

void btree_convert_row(knl_session_t *session, knl_index_desc_t *desc, char *key_buf, row_head_t *row, uint16 *bitmap)
{
    btree_key_t *key = NULL;
    uint32 copy_size;
    errno_t ret;

    key = (btree_key_t *)key_buf;
    row->size = sizeof(row_head_t) + (uint16)key->size - sizeof(btree_key_t);
    row->column_count = desc->column_count;

    copy_size = (uint32)key->size - (uint32)sizeof(btree_key_t);
    if (copy_size != 0) {
        ret = memcpy_sp((char *)row + sizeof(row_head_t), DEFAULT_PAGE_SIZE(session) - sizeof(row_head_t),
            (char *)key + sizeof(btree_key_t), copy_size);
        knl_securec_check(ret);
    }

    *bitmap = key->bitmap;
}

void btree_compact_page(knl_session_t *session, btree_page_t *page, knl_scn_t min_scn)
{
    btree_dir_t *dir = NULL;
    btree_key_t *key = NULL;
    btree_key_t *free_addr = NULL;
    itl_t *itl = NULL;
    uint16 key_size;
    int32 ret;
    space_t *space = SPACE_GET(session, DATAFILE_GET(session, AS_PAGID_PTR(page->head.id)->file)->space_id);

    for (int16 i = 0; i < page->keys; i++) {
        // keep a non-deleted min key in page to prevent parent delete
        if (page->keys == 1) {
            dir = BTREE_GET_DIR(page, 0);
            key = BTREE_GET_KEY(page, dir);

            dir->offset = key->bitmap;
            if (key->is_cleaned) {
                key->is_cleaned = (uint16)CT_FALSE;
            }
            key->bitmap = 0;
            break;
        }

        dir = BTREE_GET_DIR(page, (uint16)i);
        key = BTREE_GET_KEY(page, dir);
        if (key->is_cleaned) {
            btree_clean_dir(session, page, (uint16)i);
            i--;
            continue;
        }

        if (key->is_deleted && page->level == 0) {
            if (dir->itl_id == CT_INVALID_ID8) {
                if (key->scn <= min_scn) {
                    key->is_cleaned = (uint16)CT_TRUE;
                    btree_clean_dir(session, page, (uint16)i);
                    i--;
                    continue;
                }
            } else {
                itl = BTREE_GET_ITL(page, dir->itl_id);
                if (!itl->is_active && itl->scn <= min_scn) {
                    key->is_cleaned = (uint16)CT_TRUE;
                    btree_clean_dir(session, page, (uint16)i);
                    i--;
                    continue;
                }
            }
        }

        dir->offset = key->bitmap;
        key->bitmap = (uint16)i;
    }

    key = (btree_key_t *)((char *)page + sizeof(btree_page_t) + space->ctrl->cipher_reserve_size);
    free_addr = key;

    while ((char *)key < (char *)page + page->free_begin) {
        knl_panic_log(key->size > 0, "size in key is invalid, panic info: page %u-%u type %u key size %u",
                      AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type, key->size);
        if (key->is_cleaned) {
            key = (btree_key_t *)((char *)key + key->size);
            continue;
        }

        knl_panic_log(key->bitmap < page->keys, "bitmap is more than page's keys, panic info: page %u-%u type %u "
                      "bitmap %u page keys %u", AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page,
                      page->head.type, key->bitmap, page->keys);

        key_size = (uint16)key->size;

        if (key != free_addr) {
            ret = memmove_s(free_addr, key_size, key, key_size);
            knl_securec_check(ret);
        }

        dir = BTREE_GET_DIR(page, free_addr->bitmap);
        free_addr->bitmap = dir->offset;
        dir->offset = (uint16)((char *)free_addr - (char *)page);

        free_addr = (btree_key_t *)((char *)free_addr + free_addr->size);
        key = (btree_key_t *)((char *)key + key_size);
    }

    page->free_begin = (uint16)((char *)free_addr - (char *)page);
    page->free_end = (uint16)((char *)BTREE_GET_DIR(page, page->keys - 1) - (char *)page);
    page->free_size = page->free_end - page->free_begin;
}

/*
 * Description     : decode every column of a btree key
 * Input           : index : index handle
 * Input           : key : btree key
 * Output          : key_data : structure which contains every pointer to every column
 * Return Value    : void
 * History         : 1. 2017/4/26,  add description
 */
void btree_decode_key(index_t *index, btree_key_t *key, knl_scan_key_t *scan_key)
{
    dc_entity_t *entity = index->entity;
    knl_column_t *column = NULL;
    uint32 id;
    uint16 offset;

    scan_key->buf = (char *)key;
    offset = sizeof(btree_key_t);

    for (id = 0; id < index->desc.column_count; id++) {
        column = dc_get_column(entity, index->desc.columns[id]);

        btree_decode_key_column(scan_key, &key->bitmap, &offset, column->datatype, id, CT_FALSE);
    }
}

// CAUTION! value of 'root_page' must set before 'level'
#define BTREE_SET_STRUCT_INFO(st, root_pid, tree_level) \
    do {                                                \
        (st).file = (root_pid).file;                    \
        (st).page = (root_pid).page;                    \
        (st).level = (tree_level);                      \
    } while (0)

static void btree_increase_level(knl_session_t *session, btree_t *btree, btree_key_t *key1, btree_key_t *key2)
{
    btree_segment_t *segment = BTREE_SEGMENT(session, btree->entry, btree->segment);
    knl_tree_info_t tree_info;
    btree_key_t *key = NULL;
    btree_dir_t *dir = NULL;
    btree_page_t *page = NULL;
    uint32 itl_id = CT_INVALID_ID32;
    errno_t err;
    bool32 need_encrypt = SPACE_NEED_ENCRYPT(btree->cipher_reserve_size);
    btree_alloc_assist_t alloc_assist;
    tree_info = segment->tree_info;

    bt_all_pageid(session, btree, &alloc_assist);
    bt_all_page(session, btree, &alloc_assist);
    buf_enter_page(session, alloc_assist.new_pageid, LATCH_MODE_X,
        alloc_assist.type == BTREE_ALLOC_NEW_PAGE ? ENTER_PAGE_NO_READ : ENTER_PAGE_NORMAL);
    page = BTREE_CURR_PAGE(session);
    btree_format_page(session, segment, alloc_assist.new_pageid, (uint32)tree_info.level, (uint8)page->head.ext_size,
        alloc_assist.type == BTREE_ALLOC_NEW_PAGE ? CT_FALSE : CT_TRUE);
    key = (btree_key_t *)((char *)page + page->free_begin);
    err = memcpy_sp(key, CT_KEY_BUF_SIZE, key1, (size_t)key1->size);
    knl_securec_check(err);
    dir = BTREE_GET_DIR(page, page->keys);
    dir->offset = page->free_begin;
    dir->itl_id = CT_INVALID_ID8;
    dir->unused = 0;

    page->free_begin += (uint16)key->size;
    page->free_end -= sizeof(btree_dir_t);
    page->free_size -= ((uint16)key->size + sizeof(btree_dir_t));
    page->keys++;
    if (SPACE_IS_LOGGING(SPACE_GET(session, segment->space_id))) {
        log_encrypt_prepare(session, page->head.type, need_encrypt);
        log_put(session, RD_BTREE_COPY_KEY, key1, (uint32)key1->size, LOG_ENTRY_FLAG_NONE);
        log_append_data(session, &itl_id, sizeof(uint32));
    }
    key = (btree_key_t *)((char *)page + page->free_begin);
    err = memcpy_sp(key, CT_KEY_BUF_SIZE, key2, (size_t)key2->size);
    knl_securec_check(err);
    dir = BTREE_GET_DIR(page, page->keys);
    dir->offset = page->free_begin;
    dir->itl_id = CT_INVALID_ID8;
    dir->unused = 0;

    page->free_begin += (uint16)key->size;
    page->free_end -= sizeof(btree_dir_t);
    page->free_size -= ((uint16)key->size + sizeof(btree_dir_t));
    page->keys++;
    if (SPACE_IS_LOGGING(SPACE_GET(session, segment->space_id))) {
        log_encrypt_prepare(session, page->head.type, need_encrypt);
        log_put(session, RD_BTREE_COPY_KEY, key2, (uint32)key2->size, LOG_ENTRY_FLAG_NONE);
        log_append_data(session, &itl_id, sizeof(uint32));
    }
    btree_copy_root_page(session, btree, page);
    buf_leave_page(session, CT_TRUE);

    buf_enter_page(session, btree->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);

    TO_PAGID_DATA(alloc_assist.new_pageid, tree_info.root);
    tree_info.level++;

    (void)cm_atomic_set(&segment->tree_info.value, tree_info.value);
    if (SPACE_IS_LOGGING(SPACE_GET(session, segment->space_id))) {
        log_put(session, RD_BTREE_CHANGE_SEG, segment, sizeof(btree_segment_t), LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, CT_TRUE);
}

uint8 btree_copy_itl(knl_session_t *session, itl_t *src_itl, btree_page_t *dst_page)
{
    uint8 i, id;
    itl_t *dst_itl = NULL;

    for (i = 0; i < dst_page->itls; i++) {
        dst_itl = BTREE_GET_ITL(dst_page, i);
        if (!dst_itl->is_active) {
            *dst_itl = *src_itl;
            return i;
        }
    }

    id = btree_new_itl(session, dst_page);
    knl_panic_log(id != CT_INVALID_ID8, "current btree itl id is invalid, panic info: page %u-%u type %u",
                  AS_PAGID(dst_page->head.id).file, AS_PAGID(dst_page->head.id).page, dst_page->head.type);
    dst_itl = BTREE_GET_ITL(dst_page, id);
    *dst_itl = *src_itl;
    dst_itl->is_copied = CT_FALSE;

    return id;
}

static void btree_insert_new_node(knl_session_t *session, btree_path_info_t *path_info, btree_key_t *insert_key, btree_key_t *new_key)
{
    rd_btree_insert_t redo;
    errno_t ret;
    btree_page_t *dst_page = BTREE_CURR_PAGE(session);
    page_id_t pageid = AS_PAGID(dst_page->head.id);
    space_t *space = SPACE_GET(session, (DATAFILE_GET(session, (pageid).file))->space_id);
    bool32 need_redo = SPACE_IS_LOGGING(space);
    bool32 need_encrypt = SPACE_NEED_ENCRYPT(space->ctrl->cipher_reserve_size);
    int level = dst_page->level;
    rowid_t *path = &path_info->path[level];

    path->slot = 0;
    SET_ROWID_PAGE(path, AS_PAGID(dst_page->head.id));
    /* get dst_page's first key to insert into high level branch */
    ret = memcpy_sp(new_key, CT_KEY_BUF_SIZE, insert_key, (size_t)insert_key->size);
    knl_securec_check(ret);

    if (level == 0) {
        if (!path_info->is_empty_newnode || path_info->is_rebuild) {
            return;
        }

        insert_key->is_deleted = CT_TRUE;
    }

    redo.slot = (uint16)path->slot;
    redo.is_reuse = CT_FALSE;
    redo.itl_id = CT_INVALID_ID8;

    btree_insert_into_page(session, dst_page, insert_key, &redo);
    if (need_redo) {
        log_encrypt_prepare(session, ((page_head_t *)session->curr_page)->type, need_encrypt);
        log_put(session, RD_BTREE_INSERT, &redo, (uint32)OFFSET_OF(rd_btree_insert_t, key),
            LOG_ENTRY_FLAG_NONE);
        log_append_data(session, insert_key, (uint32)insert_key->size);
    }

    insert_key->is_deleted = CT_FALSE;
}

static void btree_move_keys(knl_session_t *session, btree_page_t *src_page, btree_page_t *dst_page, uint32 pos,
                            uint32 level, uint8 *itl_map)
{
    btree_dir_t *dir = NULL;
    btree_key_t *new_key = NULL;
    btree_key_t *src_key = NULL;
    errno_t err;
    itl_t *itl = NULL;
    txn_info_t txn_info;
    uint32 new_itl_id = 0;
    page_id_t page_id = AS_PAGID(src_page->head.id);
    bool32 need_redo = SPC_IS_LOGGING_BY_PAGEID(session, page_id);
    bool32 need_encrypt = SPACE_IS_ENCRYPT(SPACE_GET(session, DATAFILE_GET(session, page_id.file)->space_id));

    for (uint32 i = pos; i < src_page->keys; i++) {
        dir = BTREE_GET_DIR(src_page, i);
        new_key = (btree_key_t *)((char *)dst_page + dst_page->free_begin);
        src_key = BTREE_GET_KEY(src_page, dir);
        err = memcpy_sp(new_key, CT_KEY_BUF_SIZE, src_key, (size_t)src_key->size);
        knl_securec_check(err);

        if (level == 0) {
            btree_get_txn_info(session, CT_FALSE, src_page, dir, src_key, &txn_info);
            if (txn_info.status == (uint8)XACT_END) {
                new_itl_id = CT_INVALID_ID8;
                new_key->scn = txn_info.scn;
                new_key->is_owscn = txn_info.is_owscn;
            } else if (CT_INVALID_ID8 != itl_map[dir->itl_id]) {
                new_itl_id = itl_map[dir->itl_id];
            } else {
                itl = BTREE_GET_ITL(src_page, dir->itl_id);
                new_itl_id = btree_copy_itl(session, itl, dst_page);
                itl_map[dir->itl_id] = (uint8)new_itl_id; // itl id is less than 255
                if (need_redo) {
                    log_put(session, RD_BTREE_COPY_ITL, itl, sizeof(itl_t), LOG_ENTRY_FLAG_NONE);
                }
            }
        }

        dir = BTREE_GET_DIR(dst_page, dst_page->keys);
        dir->offset = dst_page->free_begin;
        dir->itl_id = (uint8)new_itl_id;
        dir->unused = 0;

        dst_page->free_begin += (uint16)src_key->size;
        dst_page->free_end -= sizeof(btree_dir_t);
        dst_page->free_size -= ((uint16)src_key->size + sizeof(btree_dir_t));
        dst_page->keys++;
        if (need_redo) {
            log_encrypt_prepare(session, ((page_head_t *)session->curr_page)->type, need_encrypt);
            log_put(session, RD_BTREE_COPY_KEY, new_key, (uint32)new_key->size, LOG_ENTRY_FLAG_NONE);
            log_append_data(session, &new_itl_id, sizeof(uint32));
        }

        if (!src_key->is_cleaned) {
            src_page->free_size += ((uint16)src_key->size + sizeof(btree_dir_t));
            src_key->is_cleaned = (uint16)CT_TRUE;
        }
    }

    src_page->keys = pos;
    src_page->free_end = (uint16)((char *)BTREE_GET_DIR(src_page, src_page->keys - 1) - (char *)src_page);
}

void btree_insert_into_page(knl_session_t *session, btree_page_t *page, btree_key_t *key,
                            rd_btree_insert_t *redo)
{
    btree_dir_t *dir = NULL;
    btree_key_t *curr_key = NULL;
    errno_t err;
    uint32 i;

    if (redo->is_reuse) {
        dir = BTREE_GET_DIR(page, redo->slot);
        curr_key = BTREE_GET_KEY(page, dir);
        dir->itl_id = redo->itl_id;
        if (curr_key->is_cleaned) {
            page->free_size -= (uint16)curr_key->size + sizeof(btree_dir_t);
        }

        err = memcpy_sp(curr_key, CT_KEY_BUF_SIZE, key, (size_t)key->size);
        knl_securec_check(err);
    } else {
        curr_key = (btree_key_t *)((char *)page + page->free_begin);
        dir = BTREE_GET_DIR(page, redo->slot);
        if (redo->slot < page->keys) {
            for (i = page->keys; i > redo->slot; i--) {
                *BTREE_GET_DIR(page, i) = *BTREE_GET_DIR(page, i - 1);
            }
        }
        dir->unused = 0;
        dir->offset = page->free_begin;
        dir->itl_id = redo->itl_id;
        err = memcpy_sp(curr_key, CT_KEY_BUF_SIZE, key, (size_t)key->size);
        knl_securec_check(err);

        page->free_begin += (uint16)key->size;
        page->free_end -= sizeof(btree_dir_t);
        page->free_size -= ((uint16)key->size + sizeof(btree_dir_t));
        page->keys++;
    }
}

static void btree_insert_into_parent(knl_session_t *session, btree_t *btree, btree_key_t *key,
                                     btree_path_info_t *path_info, uint32 level)
{
    rd_btree_insert_t redo;
    rowid_t *path = path_info->path;
    bool32 need_encrypt = SPACE_NEED_ENCRYPT(btree->cipher_reserve_size);

    path[level].slot++;

    buf_enter_page(session, GET_ROWID_PAGE(path[level]), LATCH_MODE_X, ENTER_PAGE_NORMAL);
    btree_page_t *page = BTREE_CURR_PAGE(session);

    if (page->free_size < BTREE_COST_SIZE(key)) {
        buf_leave_page(session, CT_FALSE);
        btree_split_page(session, btree, key, path_info, level, CT_FALSE);
        // insert the key in btree move new node
        if (path[level].slot == 0) {
            return;
        }

        buf_enter_page(session, GET_ROWID_PAGE(path[level]), LATCH_MODE_X, ENTER_PAGE_NORMAL);
        page = BTREE_CURR_PAGE(session);
    }

    redo.slot = (uint16)path[level].slot;
    redo.is_reuse = CT_FALSE;
    redo.itl_id = CT_INVALID_ID8;

    if ((uint16)(page->free_end - page->free_begin) < BTREE_COST_SIZE(key)) {
        knl_scn_t scn = btree_get_recycle_min_scn(session);
        btree->min_scn = scn;
        btree_compact_page(session, page, scn);
        if (SPC_IS_LOGGING_BY_PAGEID(session, btree->entry)) {
            rd_btree_info_t btree_info;
            btree_info.min_scn = scn;
            btree_info.uid = btree->index->desc.uid;
            btree_info.oid = btree->index->desc.table_id;
            btree_info.idx_id = btree->index->desc.id;
            btree_info.part_loc = path_info->part_loc;
            log_put(session, RD_BTREE_COMPACT_PAGE, &btree_info, sizeof(rd_btree_info_t), LOG_ENTRY_FLAG_NONE);
        }
    }

    knl_panic_log((uint16)(page->free_end - page->free_begin) >= BTREE_COST_SIZE(key),
                  "page's free size is abnormal, panic info: page %u-%u type %u free_end %u free_begin %u, index %s",
                  AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type, page->free_end,
                  page->free_begin, ((index_t *)btree->index)->desc.name);

    btree_insert_into_page(session, page, key, &redo);

    if (SPC_IS_LOGGING_BY_PAGEID(session, btree->entry)) {
        log_encrypt_prepare(session, page->head.type, need_encrypt);
        log_put(session, RD_BTREE_INSERT, &redo, sizeof(rd_btree_insert_t), LOG_ENTRY_FLAG_NONE);
        log_append_data(session, key, (uint32)key->size);
    }

    page_id_t root = AS_PAGID(BTREE_SEGMENT(session, btree->entry, btree->segment)->tree_info.root);
    if (IS_SAME_PAGID(AS_PAGID(page->head.id), root)) {
        btree_copy_root_page(session, btree, page);
    }
    buf_leave_page(session, CT_TRUE);
}

static void btree_split_normal(knl_session_t *session, btree_page_t *src_page, btree_path_info_t *path_info,
                               btree_key_t *insert_key, uint8 *itl_map, btree_key_t *new_key,
                               bool32 use_pct, btree_t *btree)
{
    rowid_t *path = path_info->path;
    uint16 pos = 0;
    btree_dir_t *dir = NULL;
    btree_key_t *key = NULL;
    btree_page_t *dst_page = BTREE_CURR_PAGE(session);
    rd_btree_clean_keys_t redo;
    uint16 cost_size, src_size, dst_size;
    uint16 dst_capacity;
    bool32 new_node = CT_FALSE;
    uint8 level = src_page->level;
    page_id_t page_id = AS_PAGID(src_page->head.id);
    uint8 cipher_reserve_size = btree->cipher_reserve_size;
    path_info->is_empty_newnode = CT_FALSE;

    dst_capacity = BTREE_SPLIT_PAGE_SIZE - sizeof(btree_page_t) - sizeof(page_tail_t) -
        cipher_reserve_size - sizeof(itl_t) * src_page->itls;
    if (use_pct) {
        /* transform pctfree to ratio and calculate page capacity */
        dst_capacity -= BTREE_SPLIT_PAGE_SIZE * BTREE_SEGMENT(session, btree->entry, btree->segment)->pctfree / 100;
    }

    src_size = PAGE_SIZE(src_page->head) - src_page->free_size - sizeof(btree_page_t) - sizeof(page_tail_t) -
        cipher_reserve_size - sizeof(itl_t) * src_page->itls + BTREE_MAX_COST_SIZE(insert_key);
    dst_size = 0;

    /* if insert key is max of btree, just split one key to new page */
    bool32 is_max_key = (path[level].slot == src_page->keys && IS_INVALID_PAGID(AS_PAGID(src_page->next)));
    if (is_max_key) {
        dir = BTREE_GET_DIR(src_page, src_page->keys - 1);
        key = BTREE_GET_KEY(src_page, dir);
        pos = (((BTREE_COST_SIZE(key) + BTREE_MAX_COST_SIZE(insert_key)) > dst_capacity) ||
              (key->size > BTREE_RESERVE_SIZE)) ? src_page->keys : (src_page->keys - 1);
        new_node = (pos == src_page->keys);
        path_info->is_empty_newnode = (pos == src_page->keys);
    } else {
        for (uint32 i = src_page->keys; i >= 0; i--) {
            if (i > path[level].slot) {
                dir = BTREE_GET_DIR(src_page, i - 1);
                key = BTREE_GET_KEY(src_page, dir);
                cost_size = BTREE_COST_SIZE(key);
            } else if (i == path[level].slot) {
                cost_size = BTREE_MAX_COST_SIZE(insert_key);
            } else {
                dir = BTREE_GET_DIR(src_page, i);
                key = BTREE_GET_KEY(src_page, dir);
                cost_size = BTREE_COST_SIZE(key);
            }

            src_size -= cost_size;
            dst_size += cost_size;
            /*
             *  if dst page exceeds its capacity, move 1 key less to dst page
             */
            if (dst_size > dst_capacity) {
                pos = i + 1;
                break;
            }

            /* make sure src page does not exceed its capacity */
            if (src_size > dst_capacity) {
                continue;
            }

            /*
             * here dst_size <= dst_capacity && src_size <= dst_capacity, we can split here. However
             * we need to seed for a better split position.
             */
            if (dst_size > src_size) {
                pos = (src_size + cost_size) > dst_capacity ? i : (i + 1);
                break;
            }
            knl_panic_log(i != 0, "page[%u-%u] has been damaged.", AS_PAGID(src_page->head.id).file,
                AS_PAGID(src_page->head.id).page);
        }

        if (pos == path[level].slot) {
            new_node = CT_TRUE;
        } else {
            pos = ((path[level].slot > pos) ? pos : (pos - 1));
        }
    }

    btree_move_keys(session, src_page, dst_page, pos, level, itl_map);

    if (new_node) {
        btree_insert_new_node(session, path_info, insert_key, new_key);
    } else {
        if (path[level].slot > pos) {
            path[level].slot -= pos;
            SET_ROWID_PAGE(&path[level], AS_PAGID(dst_page->head.id));
        }
        key = BTREE_GET_KEY(dst_page, BTREE_GET_DIR(dst_page, 0));
        errno_t err = memcpy_sp(new_key, CT_KEY_BUF_SIZE, key, (size_t)key->size);
        knl_securec_check(err);
    }
    buf_leave_page(session, CT_TRUE);  // dst_page

    if (SPC_IS_LOGGING_BY_PAGEID(session, page_id)) {
        redo.keys = src_page->keys;
        redo.free_size = src_page->free_size;
        log_put(session, RD_BTREE_CLEAN_KEYS, &redo, sizeof(rd_btree_clean_keys_t), LOG_ENTRY_FLAG_NONE);
    }
}

void bt_upd_ow_recycle_scn(knl_session_t *session, btree_t *btree, btree_alloc_assist_t *assist)
{
    if (assist->type == BTREE_RECYCLE_DELETED || assist->type == BTREE_ALLOC_RECYCLED) {
        btree_segment_t *segment = BTREE_SEGMENT(session, btree->entry, btree->segment);
        buf_enter_page(session, btree->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
        KNL_SET_SCN(&segment->ow_recycle_scn, assist->ow_recycle_scn);
        if (SPACE_IS_LOGGING(SPACE_GET(session, segment->space_id))) {
            log_put(session, RD_BTREE_CHANGE_SEG, segment, sizeof(btree_segment_t), LOG_ENTRY_FLAG_NONE);
        }
        buf_leave_page(session, CT_TRUE);
    }
}

void bt_upd_recycle_ver_scn(knl_session_t *session, btree_t *btree)
{
    btree_segment_t *segment = BTREE_SEGMENT(session, btree->entry, btree->segment);
    log_atomic_op_begin(session);
    buf_enter_page(session, btree->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    knl_scn_t curr_scn = KNL_GET_SCN(&segment->recycle_ver_scn);
    knl_scn_t next_scn = MAX(DB_NOW_TO_SCN(session), curr_scn + 1);
    knl_panic_log(next_scn > curr_scn, "invaid next version scn %llu, curr version scn %llu",
        next_scn, curr_scn);
    KNL_SET_SCN(&segment->recycle_ver_scn, next_scn);
    if (SPACE_IS_LOGGING(SPACE_GET(session, segment->space_id))) {
        log_put(session, RD_BTREE_CHANGE_SEG, segment, sizeof(btree_segment_t), LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, CT_TRUE);
    log_atomic_op_end(session);
}

static void btree_split_page(knl_session_t *session, btree_t *btree, btree_key_t *insert_key,
                             btree_path_info_t *path_info, uint32 level, bool32 use_pct)
{
    rowid_t *path = path_info->path;
    btree_key_t *key = NULL;
    btree_page_t *src_page = NULL;
    btree_page_t *dst_page = NULL;
    btree_page_t *next_page = NULL;
    btree_segment_t *seg = BTREE_SEGMENT(session, btree->entry, btree->segment);
    page_id_t src_page_id, next_page_id;
    btree_key_t *src_key = NULL;
    btree_key_t *new_key = NULL;
    uint8 *itl_map = NULL;
    itl_t *copy_itl = NULL;
    uint32 max_trans = CT_MAX_TRANS;
    uint32 i;
    errno_t err;
    btree_alloc_assist_t alloc_assist;

    CM_SAVE_STACK(session->stack);

    src_key = (btree_key_t *)cm_push(session->stack, CT_KEY_BUF_SIZE * 2); // double key buf size
    new_key = (btree_key_t *)((char *)src_key + CT_KEY_BUF_SIZE);
    itl_map = (uint8 *)cm_push(session->stack, max_trans * sizeof(uint8));

    if (level == 0) {
        err = memset_sp(itl_map, max_trans, CT_INVALID_ID8, max_trans);
        knl_securec_check(err);
    }

    src_page_id = GET_ROWID_PAGE(path[level]);
    bt_all_pageid(session, btree, &alloc_assist);
    bt_upd_ow_recycle_scn(session, btree, &alloc_assist);

    buf_enter_page(session, src_page_id, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    src_page = BTREE_CURR_PAGE(session);
    if (level == 0 && src_page->head.lsn != path_info->leaf_lsn) {
        buf_leave_page(session, CT_FALSE);
        CM_RESTORE_STACK(session->stack);
        return;
    }

    next_page_id = AS_PAGID(src_page->next);
    if (!IS_INVALID_PAGID(next_page_id)) {
        buf_enter_page(session, next_page_id, LATCH_MODE_X, ENTER_PAGE_NORMAL);
        next_page = BTREE_CURR_PAGE(session);
        TO_PAGID_DATA(alloc_assist.new_pageid, next_page->prev);
        if (SPACE_IS_LOGGING(SPACE_GET(session, seg->space_id))) {
            /* log the prev and next page */
            log_put(session, RD_BTREE_CHANGE_CHAIN, &next_page->prev, sizeof(page_id_t) * 2, LOG_ENTRY_FLAG_NONE);
        }
        buf_leave_page(session, CT_TRUE);
    }

    buf_enter_page(session, alloc_assist.new_pageid, LATCH_MODE_X,
                   (alloc_assist.type == BTREE_ALLOC_NEW_PAGE) ? ENTER_PAGE_NO_READ : ENTER_PAGE_NORMAL);
    dst_page = BTREE_CURR_PAGE(session);
    btree_format_page(session, seg, alloc_assist.new_pageid, level, (uint8)dst_page->head.ext_size,
                      (alloc_assist.type == BTREE_ALLOC_NEW_PAGE) ? CT_FALSE : CT_TRUE);
    TO_PAGID_DATA(src_page_id, dst_page->prev);
    TO_PAGID_DATA(next_page_id, dst_page->next);
    if (SPACE_IS_LOGGING(SPACE_GET(session, seg->space_id))) {
        /* log the prev and next page */
        log_put(session, RD_BTREE_CHANGE_CHAIN, &dst_page->prev, sizeof(page_id_t) * 2, LOG_ENTRY_FLAG_NONE);
    }

    btree_split_normal(session, src_page, path_info, insert_key, itl_map, new_key, use_pct, btree);

    if (level == 0) {
        for (i = 0; i < src_page->itls; i++) {
            if (itl_map[i] != CT_INVALID_ID8) {
                copy_itl = BTREE_GET_ITL(src_page, i);
                copy_itl->is_copied = 1;
            }
        }
        if (SPACE_IS_LOGGING(SPACE_GET(session, seg->space_id))) {
            log_put(session, RD_BTREE_CHANGE_ITL_COPIED, itl_map, src_page->itls, LOG_ENTRY_FLAG_NONE);
        }
    }

    TO_PAGID_DATA(alloc_assist.new_pageid, src_page->next);
    if (SPACE_IS_LOGGING(SPACE_GET(session, seg->space_id))) {
        /* log the prev and next page */
        log_put(session, RD_BTREE_CHANGE_CHAIN, &src_page->prev, sizeof(page_id_t) * 2, LOG_ENTRY_FLAG_NONE);
    }

    key = BTREE_GET_KEY(src_page, BTREE_GET_DIR(src_page, 0));
    err = memcpy_sp(src_key, CT_KEY_BUF_SIZE, key, (size_t)key->size);
    knl_securec_check(err);
    buf_leave_page(session, CT_TRUE);  // src_page

    bt_all_page(session, btree, &alloc_assist);

    if (KNL_IDX_RECYCLE_ENABLED(session->kernel)) {
        btree->chg_stats.alloc_pages++;
    }

    new_key->is_cleaned = CT_FALSE;
    new_key->is_deleted = CT_FALSE;
    /* if index is unique and not null, parent node does not need to hold heap rowid, null keys have compared rowid */
    if (IS_UNIQUE_PRIMARY_INDEX(btree->index) && level == 0 && !BTREE_KEY_IS_NULL(new_key)) {
        MINIMIZE_ROWID(new_key->rowid);
        if ((level == seg->tree_info.level - 1) && !BTREE_KEY_IS_NULL(src_key)) {
            MINIMIZE_ROWID(src_key->rowid);
        }
    }

    if (level == seg->tree_info.level - 1) {
        src_key->is_cleaned = CT_FALSE;
        src_key->is_deleted = CT_FALSE;
        src_key->child = src_page_id;
        new_key->child = alloc_assist.new_pageid;
        btree_increase_level(session, btree, src_key, new_key);
    } else {
        new_key->child = alloc_assist.new_pageid;
        btree_insert_into_parent(session, btree, new_key, path_info, level + 1);
    }

    CM_RESTORE_STACK(session->stack);
}

void btree_reuse_itl(knl_session_t *session, btree_page_t *page, itl_t *itl, uint8 itl_id,
                     knl_scn_t min_scn)
{
    uint16 i;
    btree_key_t *key = NULL;
    btree_dir_t *dir = NULL;

    if (page->level != 0) {
        return;
    }

    for (i = 0; i < page->keys; i++) {
        dir = BTREE_GET_DIR(page, i);
        key = BTREE_GET_KEY(page, dir);

        if (dir->itl_id != itl_id) {
            continue;
        }

        if (key->is_cleaned) {
            continue;
        }

        dir->itl_id = CT_INVALID_ID8;
        key->scn = itl->scn;
        key->is_owscn = (uint16)itl->is_owscn;
        if (key->is_deleted && itl->scn <= min_scn) {
            key->is_cleaned = (uint16)CT_TRUE;
            page->free_size += ((uint16)key->size + sizeof(btree_dir_t));
        }
    }
}

static void btree_init_itl(knl_session_t *session, knl_cursor_t *cursor, btree_page_t *page, itl_t **itl)
{
    rd_btree_reuse_itl_t redo;

    if (*itl == NULL) {
        *itl = BTREE_GET_ITL(page, session->itl_id);
        tx_init_itl(session, *itl, session->rm->xid);
        if (IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type) && cursor->logging) {
            log_put(session, RD_BTREE_NEW_ITL, &session->rm->xid, sizeof(xid_t), LOG_ENTRY_FLAG_NONE);
        }
    } else {
        if ((*itl)->is_copied) {
            cursor->reused_xid = (*itl)->xid.value;
        }

        redo.min_scn = btree_get_recycle_min_scn(session);
        redo.xid = session->rm->xid;
        redo.itl_id = session->itl_id;
        redo.unused1 = (uint8)0;
        redo.unused2 = (uint16)0;

        btree_reuse_itl(session, page, *itl, session->itl_id, redo.min_scn);
        tx_init_itl(session, *itl, session->rm->xid);
        if (IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type) && cursor->logging) {
            log_put(session, RD_BTREE_REUSE_ITL, &redo, sizeof(rd_btree_reuse_itl_t), LOG_ENTRY_FLAG_NONE);
        }
    }
}

static bool32 btree_find_free_itl(knl_session_t *session, knl_cursor_t *cursor, btree_page_t *page, itl_t **itl)
{
    uint8 i;
    txn_info_t txn_info;
    itl_t *item = NULL;
    rd_btree_clean_itl_t rd_clean;

    session->itl_id = CT_INVALID_ID8;
    *itl = NULL;

    for (i = 0; i < page->itls; i++) {
        item = BTREE_GET_ITL(page, i);
        if (item->xid.value == session->rm->xid.value) {
            session->itl_id = i;  // itl already exists
            *itl = item;
            return CT_TRUE;
        }

        if (!item->is_active) {
            if (*itl == NULL) {
                session->itl_id = i;
                *itl = item;
            }
            continue;
        }

        tx_get_itl_info(session, CT_FALSE, item, &txn_info);
        if (txn_info.status != (uint8)XACT_END) {
            continue;
        }

        item->is_active = 0;
        item->scn = txn_info.scn;
        item->is_owscn = (uint16)txn_info.is_owscn;
        item->xid.value = CT_INVALID_ID64;

        if (*itl == NULL) {
            session->itl_id = i;
            *itl = item;
        }

        rd_clean.scn = item->scn;
        rd_clean.itl_id = i;
        rd_clean.is_owscn = (uint8)item->is_owscn;
        rd_clean.is_copied = (uint8)item->is_copied;
        rd_clean.aligned = (uint8)0;
        if (IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type) && cursor->logging) {
            log_put(session, RD_BTREE_CLEAN_ITL, &rd_clean, sizeof(rd_btree_clean_itl_t), LOG_ENTRY_FLAG_NONE);
        }
    }

    return CT_FALSE;
}

static status_t btree_alloc_itl(knl_session_t *session, knl_cursor_t *cursor, btree_page_t *page, itl_t **itl)
{
    btree_t *btree = CURSOR_BTREE(cursor);

    cursor->reused_xid = CT_INVALID_ID64;
    if (btree_find_free_itl(session, cursor, page, itl)) {
        return CT_SUCCESS;
    }

    if (*itl == NULL) {
        if (page->free_size < sizeof(itl_t)) {
            return CT_SUCCESS;
        }

        if (page->itls >= btree->index->desc.maxtrans - 1) {
            session->itl_id = CT_INVALID_ID8;
            return CT_SUCCESS;
        }

        session->itl_id = btree_new_itl(session, page);
        if (session->itl_id == CT_INVALID_ID8) {
            return CT_SUCCESS;
        }
    }

    btree_init_itl(session, cursor, page, itl);

    if (DB_NOT_READY(session)) {
        (*itl)->is_active = 0;
        return CT_SUCCESS;
    }

    knl_panic_log(!DB_IS_READONLY(session), "current DB is readonly, panic info: page %u-%u type %u table %s index %s",
                  cursor->rowid.file, cursor->rowid.page, page->head.type, ((table_t *)cursor->table)->desc.name,
                  ((index_t *)btree->index)->desc.name);

    knl_part_locate_t part_loc;
    if (IS_PART_INDEX(cursor->index)) {
        part_loc.part_no = cursor->part_loc.part_no;
        part_loc.subpart_no = cursor->part_loc.subpart_no;
    } else {
        part_loc.part_no = CT_INVALID_ID24;
        part_loc.subpart_no = CT_INVALID_ID32;
    }
    
    if (lock_itl(session, AS_PAGID(page->head.id), session->itl_id, part_loc, AS_PAGID(page->next),
        LOCK_TYPE_RCR_KX) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t btree_check_unique(knl_session_t *session, knl_cursor_t *cursor, rowid_t *path, bool32 is_same,
                                   bool32 *is_wait, idx_conflict_info_t *conflict_info)
{
    index_t *index = (index_t *)cursor->index;
    itl_t *itl = NULL;
    btree_key_t *key = NULL;
    btree_dir_t *dir = NULL;
    txn_info_t txn_info;
    btree_page_t *page = BTREE_CURR_PAGE(session);
    bool32 is_same_stmt = CT_FALSE;

    *is_wait = CT_FALSE;

    if ((!index->desc.primary && !index->desc.unique) || !is_same) {
        return CT_SUCCESS;
    }

    dir = BTREE_GET_DIR(page, path[0].slot);
    key = BTREE_GET_KEY(page, dir);

    if (CT_INVALID_ID8 == dir->itl_id) {
        txn_info.status = (uint8)XACT_END;
        txn_info.scn = key->scn;
    } else {
        itl = BTREE_GET_ITL(page, dir->itl_id);
        tx_get_itl_info(session, CT_FALSE, itl, &txn_info);

        if (txn_info.status != (uint8)XACT_END) {
            is_same_stmt = (key->scn == cursor->ssn);

            if (itl->xid.value != session->rm->xid.value) {
                session->wxid = itl->xid;
                ROWID_COPY(session->wrid, key->rowid);
                *is_wait = CT_TRUE;

                return CT_SUCCESS;
            }
        }
    }

    /* transaction has committed, we need to check if it is visible for serializible isolation */
    if (cursor->isolevel == (uint8)ISOLATION_SERIALIZABLE &&
        txn_info.status == (uint8)XACT_END && cursor->query_scn < txn_info.scn) {
        CT_THROW_ERROR(ERR_SERIALIZE_ACCESS);
        return CT_ERROR;
    }

    if (!key->is_deleted) {
        cursor->conflict_rid = key->rowid;
        conflict_info->is_duplicate = CT_TRUE;
        if (cursor->action == CURSOR_ACTION_INSERT || cursor->disable_pk_update) {
            conflict_info->conflict = CT_TRUE;
            /* print index name and key for insert */
            return idx_generate_dupkey_error(session, index, (char *)key);
        } else if (is_same_stmt) {
            conflict_info->conflict = CT_TRUE;
        }

        CT_THROW_ERROR(ERR_DUPLICATE_KEY, "");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static void btree_generate_undo(knl_session_t *session, knl_cursor_t *cursor, rowid_t *path, bool32 is_same,
                                undo_type_t type)
{
    btree_t *btree = CURSOR_BTREE(cursor);
    btree_key_t *key = (btree_key_t *)cursor->key;
    btree_page_t *page = BTREE_CURR_PAGE(session);
    table_t *table = (table_t *)cursor->table;
    undo_data_t undo;
    errno_t ret;
    index_t *index = (index_t *)cursor->index;
    bool32 need_redo = IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type);

    knl_part_locate_t part_loc;
    if (IS_PART_INDEX(index)) {
        part_loc = cursor->part_loc;
    } else {
        part_loc.part_no = CT_INVALID_ID32;
        part_loc.subpart_no = CT_INVALID_ID32;
    }

    uint32 partloc_size = undo_part_locate_size(table);
    undo.size = (uint32)key->size + partloc_size;
    undo.data = (char *)cm_push(session->stack, undo.size);
    undo.snapshot.contain_subpartno = CT_FALSE;

    if (is_same) {
        btree_dir_t *dir = BTREE_GET_DIR(page, path[0].slot);
        btree_key_t *old_key = BTREE_GET_KEY(page, dir);
        if (btree->is_shadow && type == UNDO_BTREE_INSERT && !old_key->is_deleted) {
            undo.snapshot.is_xfirst = CT_TRUE;
            undo.snapshot.undo_page = INVALID_UNDO_PAGID;
            undo.snapshot.scn = 0;
            undo.snapshot.is_owscn = 0;
            ret = memcpy_sp(undo.data, undo.size, key, (size_t)key->size);
            knl_securec_check(ret);
        } else {
            if (type == UNDO_BTREE_INSERT) {
                knl_panic_log(old_key->is_deleted, "[BTREE] index %s try to insert an existed key",
                              btree->index->desc.name);
            }

            if (type == UNDO_BTREE_DELETE) {
                knl_panic_log(IS_SAME_ROWID(old_key->rowid, cursor->rowid),
                              "[BTREE]index %s try to delete a wrong key %u-%u-%u, cursor rid %u-%u-%u",
                              btree->index->desc.name, (uint32)old_key->rowid.file, (uint32)old_key->rowid.page,
                              (uint32)old_key->rowid.slot, (uint32)cursor->rowid.file, (uint32)cursor->rowid.page,
                              (uint32)cursor->rowid.slot);
                knl_panic_log(!old_key->is_deleted,
                    "the old_key is deleted, panic info: page %u-%u type %u table %s index %s", cursor->rowid.file,
                    cursor->rowid.page, page->head.type, table->desc.name, index->desc.name);
            }

            if (dir->itl_id == session->itl_id) {
                undo.snapshot.is_xfirst = CT_FALSE;
                undo.snapshot.scn = DB_CURR_SCN(session);
            } else if (dir->itl_id == CT_INVALID_ID8) {
                undo.snapshot.is_xfirst = CT_TRUE;
                undo.snapshot.scn = old_key->scn;
            } else {
                undo.snapshot.is_xfirst = CT_TRUE;
                itl_t *itl = BTREE_GET_ITL(page, dir->itl_id);
                undo.snapshot.scn = itl->scn;
            }

            undo.snapshot.undo_page = old_key->undo_page;
            undo.snapshot.undo_slot = old_key->undo_slot;
            undo.snapshot.is_owscn = old_key->is_owscn;
            ret = memcpy_sp(undo.data, undo.size, old_key, (size_t)old_key->size);
            knl_securec_check(ret);
        }
    } else {
        knl_panic_log(page->free_size >= BTREE_COST_SIZE(key), "page's free_size is abnormal, panic info: page %u-%u "
            "type %u free_size %u, table %s, index %s btree cost size %lu", cursor->rowid.file, cursor->rowid.page,
            page->head.type, page->free_size, table->desc.name, index->desc.name, BTREE_COST_SIZE(key));
        undo.snapshot.is_xfirst = CT_TRUE;
        undo.snapshot.undo_page = INVALID_UNDO_PAGID;
        undo.snapshot.scn = 0;
        undo.snapshot.is_owscn = 0;
        ret = memcpy_sp(undo.data, undo.size, key, (size_t)key->size);
        knl_securec_check(ret);
    }
    
    if (IS_PART_INDEX(index) && IS_COMPART_INDEX(index->part_index)) {
        undo.snapshot.contain_subpartno = CT_TRUE;
    }
    
    ret = memcpy_sp(undo.data + key->size, partloc_size, &part_loc, partloc_size);
    knl_securec_check(ret);
    undo.seg_page = btree->entry.page;
    undo.seg_file = btree->entry.file;
    undo.index_id = (btree->is_shadow) ? CT_SHADOW_INDEX_ID : btree->index->desc.id;
    undo.type = type;
    undo.ssn = (uint32)cursor->ssn;

    if (cursor->nologging_type != SESSION_LEVEL) {
        undo_write(session, &undo, need_redo, !cursor->logging);
    }
    cm_pop(session->stack);
}

static status_t btree_try_split_page(knl_session_t *session, knl_cursor_t *cursor, btree_path_info_t *path_info,
                                     int64 version, bool32 use_pct)
{
    btree_t *btree = CURSOR_BTREE(cursor);
    btree_segment_t *seg = BTREE_SEGMENT(session, btree->entry, btree->segment);
    page_id_t extent;
    int64 struct_ver;

    cm_latch_x(&btree->struct_latch.latch, session->id, &session->stat_btree);

    /*
     * In case of struct version is the same but btree is splitting,
     * which means the version might be changed soon btree->is_splitting
     * makes sure there is only one thread doing split.
     */
    struct_ver = cm_atomic_get(&btree->struct_ver);
    if (struct_ver != version || btree->is_splitting) {
        cm_unlatch(&btree->struct_latch.latch, &session->stat_btree);
        cm_spin_sleep();
        return CT_SUCCESS;
    }

    btree->is_splitting = CT_TRUE;
    if (btree_need_extend(session, seg)) {
        cm_unlatch(&btree->struct_latch.latch, &session->stat_btree);
        log_atomic_op_begin(session);

        space_t *space = SPACE_GET(session, seg->space_id);
        uint32 extent_size = spc_get_ext_size(SPACE_GET(session, seg->space_id), seg->extents.count);
        bool32 is_degrade = CT_FALSE;
        if (spc_try_alloc_extent(session, space, &extent, &extent_size, &is_degrade, CT_FALSE) != CT_SUCCESS) {
            btree->is_splitting = CT_FALSE;
            CT_THROW_ERROR(ERR_ALLOC_EXTENT, space->ctrl->name);
            log_atomic_op_end(session);
            return CT_ERROR;
        }

        cm_latch_x(&btree->struct_latch.latch, session->id, &session->stat_btree);
        btree_concat_extent(session, btree, extent, extent_size, is_degrade);
        log_atomic_op_end(session);
    }

    log_atomic_op_begin(session);
    path_info->part_loc = cursor->part_loc;
    btree_split_page(session, btree, (btree_key_t *)cursor->key, path_info, 0, use_pct);
    struct_ver = btree->struct_ver + 1;
    (void)cm_atomic_set(&btree->struct_ver, struct_ver);
    btree->is_splitting = CT_FALSE;
    log_atomic_op_end(session);

    cm_unlatch(&btree->struct_latch.latch, &session->stat_btree);

    return CT_SUCCESS;
}

static status_t btree_check_level(knl_session_t *session, btree_t *btree, rowid_t *path, uint32 level)
{
    uint16 max_key_size;
    btree_page_t *page = NULL;

    if (level < CT_MAX_ROOT_LEVEL) {
        return CT_SUCCESS;
    }

    max_key_size = btree_max_key_size(btree->index) + sizeof(knl_part_locate_t) + sizeof(page_id_t);
    /* max_btree_level - 1 is root, root - 1 is the child of root */
    if (buf_read_page(session, GET_ROWID_PAGE(path[CT_MAX_ROOT_LEVEL - 1]),
                      LATCH_MODE_S, ENTER_PAGE_NORMAL) != CT_SUCCESS) {
        return CT_ERROR;
    }
    page = BTREE_CURR_PAGE(session);
    if (max_key_size > page->free_size) {
        buf_leave_page(session, CT_FALSE);
        CT_THROW_ERROR(ERR_BTREE_LEVEL_EXCEEDED, CT_MAX_ROOT_LEVEL);
        return CT_ERROR;
    }
    buf_leave_page(session, CT_FALSE);

    return CT_SUCCESS;
}

static bool32 btree_find_update_pos(knl_session_t *session, btree_find_assist_t *find_assist, bool32 *is_same,
    bool32 *compact_leaf, bool32 logging)
{
    btree_t *btree = find_assist->btree;
    btree_segment_t *seg = BTREE_SEGMENT(session, btree->entry, btree->segment);
    knl_tree_info_t tree_info;
    index_t *index = btree->index;
    knl_scn_t scn;
    btree_dir_t *dir = NULL;
    btree_key_t *curr_key = NULL;
    btree_page_t *page = NULL;
    uint16 cost_size = (find_assist->find_type == BTREE_FIND_DELETE ?
        sizeof(itl_t) : BTREE_COST_SIZE((btree_key_t *)find_assist->scan_key->buf) + sizeof(itl_t));
    bool32 need_redo = SPACE_IS_LOGGING(SPACE_GET(session, seg->space_id)) && logging;
    knl_scn_t snap_scn = DB_CURR_SCN(session);
    btree_find_type org_type = find_assist->find_type;
    bool32 org_compact_leaf = *compact_leaf;

    tree_info.value = cm_atomic_get(&seg->tree_info.value);
    uint32 level = (uint32)tree_info.level - 1;
    page_id_t page_id = AS_PAGID(tree_info.root);
    bool32 cmp_rowid = (index->desc.primary || index->desc.unique) ? CT_FALSE : CT_TRUE;
    for (;;) {
        buf_enter_page(session, page_id, (level == 0) ? LATCH_MODE_X : LATCH_MODE_S,
            (level > 0) ? (ENTER_PAGE_NORMAL | ENTER_PAGE_HIGH_AGE) : ENTER_PAGE_NORMAL);
        page = BTREE_CURR_PAGE(session);
        if (page_soft_damaged(&page->head)) {
            buf_leave_page(session, CT_FALSE);
            find_assist->page_id = page_id;
            find_assist->page_damage = CT_TRUE;
            return CT_FALSE;
        }

        knl_panic_log(level == page->level, "the btree's level is abnormal, panic info: page %u-%u type %u level %u "
                      "page level %u, index %s", AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page,
                      page->head.type, level, page->level, index->desc.name);

        if (page->level > 0) {
            snap_scn = KNL_GET_SCN(&seg->recycle_ver_scn);
        }

        if (bt_chk_leaf_recycled(session, btree, page, snap_scn)) {
            buf_leave_page(session, CT_FALSE);
            level = (uint32)tree_info.level - 1;
            page_id = AS_PAGID(tree_info.root);
            find_assist->find_type = org_type;
            *compact_leaf = org_compact_leaf;
            continue;
        }

        SET_ROWID_PAGE(&find_assist->path_info->path[page->level], page_id);
        if (page->level == 0 && find_assist->find_type != BTREE_FIND_DELETE_NEXT &&
            BTREE_NEED_COMPACT(page, cost_size)) {
            if (compact_leaf != NULL) {
                *compact_leaf = CT_TRUE;
            }
            scn = btree_get_recycle_min_scn(session);
            btree->min_scn = scn;
            btree_compact_page(session, page, scn);
            if (need_redo) {
                rd_btree_info_t btree_info;
                btree_info.min_scn = scn;
                btree_info.uid = index->desc.uid;
                btree_info.oid = index->desc.table_id;
                btree_info.idx_id = index->desc.id;
                btree_info.part_loc = find_assist->path_info->part_loc;
                log_put(session, RD_BTREE_COMPACT_PAGE, &btree_info, sizeof(rd_btree_info_t), LOG_ENTRY_FLAG_NONE);
            }
        }

        knl_panic_log(page->head.type == PAGE_TYPE_BTREE_NODE, "page type is abnormal, panic info: page %u-%u type %u "
            "index %s", AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type, index->desc.name);
        knl_panic_log(page->seg_scn == seg->seg_scn, "seg_scn of page and segment are not same, panic info: "
                      "page %u-%u type %u, index %s page seg_scn %llu seg_scn %llu", AS_PAGID(page->head.id).file,
                      AS_PAGID(page->head.id).page, page->head.type, index->desc.name, page->seg_scn, seg->seg_scn);

        btree_binary_search(index, page, find_assist->scan_key, find_assist->path_info, cmp_rowid, is_same);

        if (find_assist->path_info->path[page->level].slot >= page->keys) {
            if (find_assist->find_type == BTREE_FIND_DELETE || find_assist->find_type == BTREE_FIND_DELETE_NEXT) {
                page_id = AS_PAGID(page->next);
                snap_scn = KNL_GET_SCN(&seg->recycle_ver_scn);
                if (IS_INVALID_PAGID(page_id)) {
                    return CT_FALSE;
                }

                buf_leave_page(session, page->level == 0 ? (*compact_leaf) : CT_FALSE);
                *compact_leaf = CT_FALSE;
                find_assist->find_type = BTREE_FIND_DELETE_NEXT;
                continue;
            } else if (find_assist->find_type == BTREE_FIND_INSERT) {
                /*
                * for insert, if located at the last slot, insert key could be the largest key of this page,
                * or it could located on next page.
                */
                buf_leave_page(session, page->level == 0 ? (*compact_leaf) : CT_FALSE);
                *compact_leaf = CT_FALSE;
                return CT_FALSE;
            }
        }

        if (page->level == 0) {
            break;
        }

        dir = BTREE_GET_DIR(page, find_assist->path_info->path[page->level].slot);
        curr_key = BTREE_GET_KEY(page, dir);
        page_id = curr_key->child;
        level = page->level - 1;
        buf_leave_page(session, CT_FALSE);
    }

    return CT_TRUE;
}

static status_t btree_enter_insert(knl_session_t *session, knl_cursor_t *cursor, btree_path_info_t *path_info,
    bool32 is_rebuild, bool32 *is_same, bool32 *compact_leaf, idx_conflict_info_t *conflict_info)
{
    btree_key_t *key = (btree_key_t *)cursor->key;
    btree_t *btree = CURSOR_BTREE(cursor);
    btree_page_t *page = NULL;
    itl_t *itl = NULL;
    bool32 is_wait = CT_FALSE;
    knl_scan_key_t scan_key;
    int64 version;
    uint16 pct_size;
    btree_find_assist_t find_assist;
    uint32 level;

    btree_decode_key(btree->index, key, &scan_key);
    path_info->part_loc = cursor->part_loc;
    for (;;) {
        *compact_leaf = CT_FALSE;
        log_atomic_op_begin(session);
        log_set_group_nolog_insert(session, cursor->logging);
        version = cm_atomic_get(&btree->struct_ver);
        level = BTREE_SEGMENT(session, btree->entry, btree->segment)->tree_info.level;
        btree_init_find_assist(btree, path_info, &scan_key, BTREE_FIND_INSERT, &find_assist);
        if (!btree_find_update_pos(session, &find_assist, is_same, compact_leaf, cursor->logging)) {
            log_atomic_op_end(session);
            if (find_assist.page_damage) {
                CT_THROW_ERROR(ERR_PAGE_SOFT_DAMAGED, find_assist.page_id.file, find_assist.page_id.page);
                return CT_ERROR;
            }

            log_atomic_op_begin(session);
            log_set_group_nolog_insert(session, cursor->logging);
            cm_latch_s(&btree->struct_latch.latch, session->id, CT_FALSE, &session->stat_btree);
            version = cm_atomic_get(&btree->struct_ver);
            level = BTREE_SEGMENT(session, btree->entry, btree->segment)->tree_info.level;
            btree_init_find_assist(btree, path_info, &scan_key, BTREE_FIND_INSERT_LOCKED, &find_assist);
            (void)btree_find_update_pos(session, &find_assist, is_same, compact_leaf, cursor->logging);
            if (find_assist.page_damage) {
                log_atomic_op_end(session);
                CT_THROW_ERROR(ERR_PAGE_SOFT_DAMAGED, find_assist.page_id.file, find_assist.page_id.page);
                return CT_ERROR;
            }
            cm_unlatch(&btree->struct_latch.latch, &session->stat_btree);
        }

        page = BTREE_CURR_PAGE(session);
        pct_size = ((is_rebuild || btree->is_shadow) &&
                    BTREE_MAX_COST_SIZE(key) <= DEFAULT_PAGE_SIZE(session) - BTREE_PCT_SIZE(btree))
                   ? BTREE_PCT_SIZE(btree)
                   : (uint16)0;
        if (page->free_size < BTREE_MAX_COST_SIZE(key) + pct_size) {
            path_info->leaf_lsn = page->head.lsn;
            buf_leave_page(session, *compact_leaf);
            if (btree_check_level(session, btree, path_info->path, level) != CT_SUCCESS) {
                log_atomic_op_end(session);
                knl_end_itl_waits(session);
                return CT_ERROR;
            }

            log_atomic_op_end(session);

            if (*compact_leaf) {
                path_info->leaf_lsn = session->curr_lsn;
            }

            path_info->is_rebuild = is_rebuild;
            if (btree_try_split_page(session, cursor, path_info, version, (pct_size != 0)) != CT_SUCCESS) {
                knl_end_itl_waits(session);
                return CT_ERROR;
            }
            continue;
        }

        if (btree_check_unique(session, cursor, path_info->path, *is_same, &is_wait, conflict_info) != CT_SUCCESS) {
            buf_leave_page(session, *compact_leaf);
            log_atomic_op_end(session);
            knl_end_itl_waits(session);
            return CT_ERROR;
        }

        if (is_wait) {
            buf_leave_page(session, *compact_leaf);
            log_atomic_op_end(session);
            knl_end_itl_waits(session);
            btree->stat.row_lock_waits++;

            if (tx_wait(session, session->lock_wait_timeout, ENQ_TX_KEY) != CT_SUCCESS) {
                tx_record_rowid(session->wrid);
                return CT_ERROR;
            }
            continue;
        }

        if (is_rebuild) {
            knl_end_itl_waits(session);
            return CT_SUCCESS;
        }

        if (btree_alloc_itl(session, cursor, page, &itl) != CT_SUCCESS) {
            buf_leave_page(session, CT_TRUE);
            log_atomic_op_end(session);
            knl_end_itl_waits(session);
            return CT_ERROR;
        }

        if (itl == NULL) {
            session->wpid = AS_PAGID(page->head.id);
            buf_leave_page(session, *compact_leaf);
            log_atomic_op_end(session);
            if (knl_begin_itl_waits(session, &btree->stat.itl_waits) != CT_SUCCESS) {
                knl_end_itl_waits(session);
                return CT_ERROR;
            }
            continue;
        }
        knl_end_itl_waits(session);
        break;
    }

    return CT_SUCCESS;
}

static status_t btree_do_insert(knl_session_t *session, knl_cursor_t *cursor, idx_conflict_info_t *conflict_info)
{
    btree_page_t *page = NULL;
    rd_btree_insert_t redo;
    btree_path_info_t path_info;
    bool32 is_same = CT_FALSE;
    bool32 compact_leaf = CT_FALSE;
    btree_t *btree = CURSOR_BTREE(cursor);
    btree_key_t *key = (btree_key_t *)cursor->key;
    page_id_t next_page_id;
    bool32 need_redo = IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type);

    if (btree->segment == NULL) {
        if (IS_PART_INDEX(btree->index)) {
            knl_panic_log(cursor->index_part != NULL, "the index_part is NULL, panic info: page %u-%u type %u "
                "table %s index %s", cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                ((table_t *)cursor->table)->desc.name, ((index_t *)btree->index)->desc.name);
            if (btree_create_part_entry(session, btree, cursor->index_part, cursor->part_loc) != CT_SUCCESS) {
                return CT_ERROR;
            }
        } else {
            if (btree_create_entry(session, btree) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }
    }
    bool32 need_encrypt = SPACE_NEED_ENCRYPT(btree->cipher_reserve_size);

    // prepare key and part number
    table_t *table = (table_t *)cursor->table;
    if (cursor->nologging_type != SESSION_LEVEL) {
        if (undo_prepare(session, (uint32)key->size + undo_part_locate_size(table),
            need_redo, need_encrypt) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (btree_enter_insert(session, cursor, &path_info, CT_FALSE,
        &is_same, &compact_leaf, conflict_info) != CT_SUCCESS) {
        return CT_ERROR;
    }

    page = BTREE_CURR_PAGE(session);

    next_page_id = AS_PAGID(page->next);

    redo.slot = (uint16)path_info.path[0].slot;
    redo.is_reuse = (uint8)is_same;
    redo.itl_id = session->itl_id;

    key->is_deleted = CT_FALSE;
    key->scn = cursor->ssn;

    if (need_redo) {
        key->undo_page = session->rm->undo_page_info.undo_rid.page_id;
        key->undo_slot = session->rm->undo_page_info.undo_rid.slot;
    } else {
        key->undo_page = session->rm->noredo_undo_page_info.undo_rid.page_id;
        key->undo_slot = session->rm->noredo_undo_page_info.undo_rid.slot;
    }

    btree_generate_undo(session, cursor, path_info.path, is_same, UNDO_BTREE_INSERT);
    btree_insert_into_page(session, page, key, &redo);

    if (need_redo) {
        log_encrypt_prepare(session, page->head.type, need_encrypt);
        log_put(session, RD_BTREE_INSERT, &redo, sizeof(rd_btree_insert_t), LOG_ENTRY_FLAG_NONE);
        log_append_data(session, key, (uint32)key->size);
    }

    buf_leave_page(session, CT_TRUE);
    log_atomic_op_end(session);

    if (cursor->reused_xid != CT_INVALID_ID64 && !IS_INVALID_PAGID(next_page_id)) {
        (void)btree_clean_copied_itl(session, cursor->reused_xid, next_page_id, need_redo);
    }

    if (KNL_IDX_RECYCLE_ENABLED(session->kernel)) {
        btree->chg_stats.insert_size += BTREE_COST_SIZE(key);
    }

    return CT_SUCCESS;
}

static status_t btree_force_update_dupkey(knl_session_t *session, knl_cursor_t *cursor)
{
    btree_key_t *key = (btree_key_t *)cursor->key;
    rowid_t curr_rid;
    knl_handle_t index = (index_t *)cursor->index;
    knl_handle_t part = cursor->index_part;
    shadow_index_t *shadow_entity = ((table_t *)cursor->table)->shadow_index;
    idx_conflict_info_t conflict_info = { CT_FALSE, CT_FALSE };
    status_t status = CT_SUCCESS;

    session->rm->idx_conflicts++; /* could not overflow, we won't have a table with 2^64 rows */
    ROWID_COPY(curr_rid, key->rowid);
    /* Note : cursor->conflict_rid is rowid which duplicated with current row */
    ROWID_COPY(key->rowid, cursor->conflict_rid);
    ROWID_COPY(cursor->rowid, cursor->conflict_rid); /* to keep cursor->rowid == key->rowid while deleting keys */

    do {
        if (btree_delete(session, cursor) != CT_SUCCESS) {
            status = CT_ERROR;
            break;
        }

        if (shadow_entity != NULL) {
            /*
             * this only happened while rebuild index online,
             * if there is a conflict on original index, there must be a same conflict on shadow index
             * pcrb_delete will try to insert and delete a key which conflicts with exist keys, so
             * session->idx_conflicts should +1 and do same operations on shadow index,
             */
            if (!btree_get_index_shadow(session, cursor, shadow_entity)) {
                status = CT_SUCCESS;
                break;
            }

            session->rm->idx_conflicts++;
            if (btree_delete(session, cursor) != CT_SUCCESS) {
                status = CT_ERROR;
                break;
            }
        }
    } while (0);

    // revert cursor variable
    cursor->index = index;
    cursor->index_part = part;
    ROWID_COPY(cursor->rowid, curr_rid);
    ROWID_COPY(key->rowid, curr_rid);

    if (status != CT_SUCCESS) {
        return status;
    }

    return btree_do_insert(session, cursor, &conflict_info);
}

status_t btree_insert(knl_session_t *session, knl_cursor_t *cursor)
{
    idx_conflict_info_t conflict_info = { CT_FALSE, CT_FALSE };

    if (btree_do_insert(session, cursor, &conflict_info) != CT_SUCCESS) {
        if (!conflict_info.is_duplicate || conflict_info.conflict) {
            cursor->query_scn = DB_CURR_SCN(session);
            return CT_ERROR;
        }

        cm_reset_error();
        return btree_force_update_dupkey(session, cursor);
    }

    return CT_SUCCESS;
}

status_t btree_insert_into_shadow(knl_session_t *session, knl_cursor_t *cursor)
{
    btree_path_info_t path_info;
    bool32 is_same = CT_FALSE;
    btree_page_t *page = NULL;
    rd_btree_insert_t redo;
    btree_key_t *key = (btree_key_t *)cursor->key;
    idx_conflict_info_t conflict_info = { CT_FALSE, CT_FALSE };
    bool32 compact_leaf = CT_FALSE;
    btree_t *btree = CURSOR_BTREE(cursor);
    bool32 need_encrypt = SPACE_NEED_ENCRYPT(btree->cipher_reserve_size);

    if (btree_enter_insert(session, cursor, &path_info, CT_TRUE,
        &is_same, &compact_leaf, &conflict_info) != CT_SUCCESS) {
        return CT_ERROR;
    }

    page = BTREE_CURR_PAGE(session);
    if (is_same) {
        btree_dir_t *dir = BTREE_GET_DIR(page, path_info.path[0].slot);
        btree_key_t *same_key = BTREE_GET_KEY(page, dir);

        if (IS_SAME_ROWID(same_key->rowid, key->rowid)) {
            buf_leave_page(session, compact_leaf);
            log_atomic_op_end(session);
            return CT_SUCCESS;
        }
    }

    redo.slot = (uint16)path_info.path[0].slot;
    redo.is_reuse = (uint8)is_same;
    redo.itl_id = CT_INVALID_ID8;

    key->is_deleted = CT_FALSE;
    key->undo_page = INVALID_UNDO_PAGID;
    key->undo_slot = INVALID_SLOT;
    btree_insert_into_page(session, page, key, &redo);
    if (IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type)) {
        log_encrypt_prepare(session, page->head.type, need_encrypt);
        log_put(session, RD_BTREE_INSERT, &redo, sizeof(rd_btree_insert_t), LOG_ENTRY_FLAG_NONE);
        log_append_data(session, key, (uint32)key->size);
    }

    buf_leave_page(session, CT_TRUE);

    log_atomic_op_end(session);

    return CT_SUCCESS;
}

static status_t btree_need_wait(knl_session_t *session, knl_cursor_t *cursor, btree_page_t *page,
    btree_dir_t *dir, bool32 *need_wait)
{
    itl_t *itl = NULL;
    txn_info_t txn_info;

    if (dir->itl_id == CT_INVALID_ID8) {
        return CT_SUCCESS;
    }

    itl = BTREE_GET_ITL(page, dir->itl_id);
    if (itl->xid.value == session->rm->xid.value) {
        return CT_SUCCESS;
    }

    tx_get_itl_info(session, CT_FALSE, itl, &txn_info);
    if (txn_info.status != (uint8)XACT_END) {
        btree_key_t *key = BTREE_GET_KEY(page, dir);
        session->wxid = itl->xid;
        ROWID_COPY(session->wrid, key->rowid);
        *need_wait = CT_TRUE;
        return CT_SUCCESS;
    }

    /* transaction has committed, we need to check if it is visible for serializible isolation */
    if (cursor->isolevel == (uint8)ISOLATION_SERIALIZABLE && cursor->query_scn < txn_info.scn) {
        CT_THROW_ERROR(ERR_SERIALIZE_ACCESS);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t btree_enter_delete(knl_session_t *session, knl_cursor_t *cursor, btree_path_info_t *path_info,
                                   bool32 *is_same)
{
    itl_t *itl = NULL;
    btree_dir_t *dir = NULL;
    btree_page_t *page = NULL;
    knl_scan_key_t scan_key;
    bool32 compact_leaf = CT_FALSE;
    bool32 need_wait = CT_FALSE;
    btree_find_assist_t find_assist;

    btree_t *btree = CURSOR_BTREE(cursor);
    btree_key_t *key = (btree_key_t *)cursor->key;
    btree_decode_key(btree->index, key, &scan_key);
    path_info->part_loc = cursor->part_loc;
    for (;;) {
        compact_leaf = CT_FALSE;
        log_atomic_op_begin(session);
        btree_init_find_assist(btree, path_info, &scan_key, BTREE_FIND_DELETE, &find_assist);
        (void)btree_find_update_pos(session, &find_assist, is_same, &compact_leaf, cursor->logging);
        if (find_assist.page_damage) {
            log_atomic_op_end(session);
            CT_THROW_ERROR(ERR_PAGE_SOFT_DAMAGED, find_assist.page_id.file, find_assist.page_id.page);
            return CT_ERROR;
        }

        page = BTREE_CURR_PAGE(session);
        dir = BTREE_GET_DIR(page, path_info->path[0].slot);
        btree_key_t *old_key = BTREE_GET_KEY(page, dir);
        if (!(*is_same)) {
            if (btree->is_shadow) {
                buf_leave_page(session, compact_leaf);
                log_atomic_op_end(session);
                knl_end_itl_waits(session);
                return CT_ERROR;
            }
            /* this will not happen */
            knl_panic_log(0, "[BTREE] index %s cannot find the key %u-%u-%u to be deleted in page %u-%u",
                          btree->index->desc.name, (uint32)key->rowid.file, (uint32)key->rowid.page,
                          (uint32)key->rowid.slot, (uint32)AS_PAGID(page->head.id).file,
                          (uint32)AS_PAGID(page->head.id).page);
        }

        /*
         * in case of update primary key, we need force delete old key,
         * which has on lock on heap row, so we need to check itl status here
         */
        if (btree_need_wait(session, cursor, page, dir, &need_wait) != CT_SUCCESS) {
            buf_leave_page(session, compact_leaf);
            log_atomic_op_end(session);
            knl_end_itl_waits(session);
            return CT_ERROR;
        }

        if (need_wait) {
            buf_leave_page(session, compact_leaf);
            log_atomic_op_end(session);
            knl_end_itl_waits(session);
            btree->stat.row_lock_waits++;
            need_wait = CT_FALSE;

            if (tx_wait(session, session->lock_wait_timeout, ENQ_TX_KEY) != CT_SUCCESS) {
                tx_record_rowid(session->wrid);
                return CT_ERROR;
            }
            continue;
        }

        if (session->rm->idx_conflicts > 0) {
            if (!IS_SAME_ROWID(old_key->rowid, cursor->rowid) || old_key->is_deleted) {
                buf_leave_page(session, compact_leaf);
                log_atomic_op_end(session);
                knl_end_itl_waits(session);
                session->rm->idx_conflicts--;
                *is_same = CT_FALSE;
                return CT_SUCCESS;
            }
        }

        if (btree->is_shadow) {
            if (!IS_SAME_ROWID(old_key->rowid, cursor->rowid)) {
                *is_same = CT_FALSE;
                buf_leave_page(session, compact_leaf);
                log_atomic_op_end(session);
                return CT_SUCCESS;
            }
        }

        if (btree_alloc_itl(session, cursor, page, &itl) != CT_SUCCESS) {
            buf_leave_page(session, CT_TRUE);
            log_atomic_op_end(session);
            knl_end_itl_waits(session);
            return CT_ERROR;
        }

        if (itl == NULL) {
            session->wpid = AS_PAGID(page->head.id);
            buf_leave_page(session, compact_leaf);
            log_atomic_op_end(session);
            if (knl_begin_itl_waits(session, &btree->stat.itl_waits) != CT_SUCCESS) {
                knl_end_itl_waits(session);
                return CT_ERROR;
            }
            continue;
        }

        knl_end_itl_waits(session);
        break;
    }

    return CT_SUCCESS;
}

uint16 bt_alloc_page_size(knl_session_t *session, btree_t *btree)
{
    uint16 page_size;

    /*
    * the min value of session->kernel->attr.page_size and page_size is 8192
    * the max value of desc.initrans is 255
    */
    if (btree->index->desc.cr_mode == CR_PAGE) {
        page_size = (uint16)(DEFAULT_PAGE_SIZE(session) - sizeof(btree_page_t) - sizeof(page_tail_t) -
            btree->segment->initrans * sizeof(pcr_itl_t));
    } else {
        page_size = (uint16)(DEFAULT_PAGE_SIZE(session) - sizeof(btree_page_t) - sizeof(page_tail_t) -
            btree->segment->initrans * sizeof(itl_t));
    }

    return page_size;
}

static inline uint64 bt_calculate_garbage_size(knl_session_t *session, btree_t *btree)
{
    uint16 page_size = bt_alloc_page_size(session, btree);
    idx_chg_stats_t *stats = &btree->chg_stats;

    /* the max value of page_size is 32768 and stats->alloc_pages is no larger than 2^40 */
    int64 extended_size = (int64)page_size * stats->alloc_pages;
    int64 garbage_size = (extended_size + stats->delete_size) - stats->insert_size;
    return garbage_size < 0 ? 0 : (uint64)garbage_size;
}

static void bt_put_garbage_size(knl_session_t *session, btree_t *btree)
{
    if (IS_INVALID_PAGID(btree->entry)) {
        return;
    }

    btree_segment_t *segment = BTREE_SEGMENT(session, btree->entry, btree->segment);
    if (segment == NULL) {
        return;
    }

    knl_scn_t seg_scn = segment->seg_scn;
    uint64 garbage_size = bt_calculate_garbage_size(session, btree);
    uint64 empty_size = btree->chg_stats.empty_size;
    garbage_size = MAX(garbage_size, empty_size);
    if (segment->garbage_size == garbage_size || session->atomic_op) {
        return;
    }

    log_atomic_op_begin(session);
    buf_enter_page(session, btree->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    page_head_t *head = (page_head_t *)CURR_PAGE(session);
    segment = BTREE_GET_SEGMENT(session);
    if (head->type != PAGE_TYPE_BTREE_HEAD || segment->seg_scn != seg_scn) {
        buf_leave_page(session, CT_FALSE);
        log_atomic_op_end(session);
        return;
    }

    segment->garbage_size = garbage_size;
    CT_LOG_DEBUG_INF("btree flush garbage size: entry %d-%d empty_size %llu garbage_size %llu.",
        btree->entry.file, btree->entry.page, empty_size, garbage_size);
    if (SPC_IS_LOGGING_BY_PAGEID(session, btree->entry)) {
        log_put(session, RD_BTREE_CHANGE_SEG, segment, sizeof(btree_segment_t), LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, CT_TRUE);
    log_atomic_op_end(session);
}

void bt_flush_partition_garbage_size(knl_session_t *session, index_t *index, table_t *table)
{
    part_index_t *part_index = index->part_index;
    for (uint32 i = 0; i < part_index->desc.partcnt; i++) {
        index_part_t *index_part = INDEX_GET_PART(index, i);
        table_part_t *table_part = TABLE_GET_PART(table, i);
        if (index_part == NULL || !IS_READY_PART(table_part)) {
            continue;
        }

        if (!IS_PARENT_IDXPART(&index_part->desc)) {
            bt_put_garbage_size(session, &index_part->btree);
            continue;
        }

        for (uint32 j = 0; j < index_part->desc.subpart_cnt; j++) {
            index_part_t *index_subpart = PART_GET_SUBENTITY(part_index, index_part->subparts[j]);
            if (index_subpart == NULL) {
                continue;
            }

            bt_put_garbage_size(session, &index_subpart->btree);
        }
    }
}

void btree_flush_garbage_size(knl_session_t *session, dc_entity_t *entity)
{
    table_t *table = &entity->table;
    uint32 valid_count = table->index_set.count;
    index_t *index = NULL;

    if (DB_IS_MAINTENANCE(session) || session->bootstrap ||
        (session->kernel->db.status != DB_STATUS_OPEN) || DB_IS_READONLY(session)) {
        return;
    }

    for (uint32 i = 0; i < valid_count; i++) {
        index = table->index_set.items[i];
        if (index == NULL) {
            continue;
        }

        if (!IS_PART_INDEX(index)) {
            bt_put_garbage_size(session, &index->btree);
            continue;
        }

        bt_flush_partition_garbage_size(session, index, table);
    }
}

bool32 btree_need_recycle(knl_session_t *session, btree_t *btree, idx_recycle_info_t *recycle_info)
{
    uint16 page_size = bt_alloc_page_size(session, btree);
    space_t *space = SPACE_GET(session, btree->segment->space_id);
    uint32 seg_pages_cnt = btree_get_segment_page_count(space, BTREE_SEGMENT(session, btree->entry, btree->segment));
    uint64 segment_size = (uint64)page_size * seg_pages_cnt;

    uint32 recycled_cnt = btree->segment->del_pages.count + btree->segment->recycled_pages.count;
    uint64 recycled_size = (uint64)page_size * recycled_cnt;
    uint64 using_size = segment_size - recycled_size;
    uint64 ratio_size = using_size * INDEX_NEED_RECY_RATIO(session);
    uint64 recycle_threshold = session->kernel->attr.idx_recycle_size;

    uint64 garbage_size = bt_calculate_garbage_size(session, btree);
    uint64 recyclable_empty_size = btree->chg_stats.empty_size;
    if (btree->chg_stats.empty_size >= btree->chg_stats.first_empty_size) {
        recyclable_empty_size = btree->chg_stats.empty_size - btree->chg_stats.first_empty_size;
    }

    if (recycle_info != NULL) {
        knl_scn_t min_scn = btree_get_recycle_min_scn(session);
        recycle_info->segment_scn = btree->segment->seg_scn;
        recycle_info->segment_size = segment_size;
        recycle_info->recycled_size = recycled_size;
        recycle_info->first_recycle_scn = btree->segment->first_recycle_scn;
        knl_scn_t last_rscn = btree->segment->last_recycle_scn;
        if (btree->segment->del_pages.count > 0) {
            if (btree->segment->recycled_pages.count > 0) {
                last_rscn = MAX(btree->segment->del_scn, last_rscn);
            } else {
                last_rscn = btree->segment->del_scn;
            }
        }
        recycle_info->last_recycle_scn = last_rscn;
        recycle_info->recycled_reusable = bt_recycle_leaf_reusable(session, last_rscn, min_scn);
        recycle_info->empty_ratio = (uint64)((double)recyclable_empty_size / using_size * CT_PERCENT);
        recycle_info->garbage_size = garbage_size;
        recycle_info->garbage_ratio = (uint64)((double)garbage_size / using_size * CT_PERCENT);
        recycle_info->btree_level = btree->segment->tree_info.level;
    }

    if (segment_size < CT_MIN_INDEX_RECYCLE_SIZE
        || using_size < CT_MIN_INDEX_RECYCLE_SIZE
        || btree->segment->tree_info.level < BTREE_MIN_COALESCE_LEVEL) {
        return CT_FALSE;
    }

    if (recyclable_empty_size > ratio_size || recyclable_empty_size >= recycle_threshold ||
        garbage_size > ratio_size || garbage_size >= recycle_threshold) {
        return CT_TRUE;
    }

    return CT_FALSE;
}

static void btree_get_recycle_part_orgscn(index_t *index, knl_part_locate_t part_loc, index_recycle_item_t *item)
{
    if (IS_PART_INDEX(index)) {
        table_t *table = &index->entity->table;
        part_table_t *part_table = table->part_table;
        table_part_t *part = TABLE_GET_PART(table, part_loc.part_no);
        if (IS_PARENT_TABPART(&part->desc)) {
            knl_panic_log(part_loc.subpart_no != CT_INVALID_ID32, "the subpart_no is invalid, panic info: table %s "
                          "table_part %s index %s", table->desc.name, part->desc.name, index->desc.name);
            table_part_t *subpart = PART_GET_SUBENTITY(part_table, part->subparts[part_loc.subpart_no]);
            item->part_org_scn = subpart->desc.org_scn;
        } else {
            item->part_org_scn = part->desc.org_scn;
        }
    } else {
        item->part_org_scn = CT_INVALID_ID64;
    }
}

static void btree_notify_recycle(knl_session_t *session, btree_t *btree, knl_part_locate_t part_loc)
{
    index_recycle_ctx_t *ctx = &session->kernel->index_ctx.recycle_ctx;
    index_t *index = btree->index;

    cm_spin_lock(&ctx->lock, NULL);
    if (btree->wait_recycle) {
        cm_spin_unlock(&ctx->lock);
        CT_LOG_DEBUG_INF("skip recycle index %s,is wait recycle", index->desc.name);
        return;
    }

    if (ctx->idx_list.count == CT_MAX_RECYCLE_INDEXES) {
        cm_spin_unlock(&ctx->lock);
        CT_LOG_DEBUG_INF("skip recycle index %s, the recycle list is full", index->desc.name);
        return;
    }

    uint32 id = ctx->free_list.first;
    index_recycle_item_t *item = &ctx->items[id];
    item->xid = session->rm->xid;
    item->is_tx_active = CT_TRUE;
    item->scn = DB_CURR_SCN(session);
    item->uid = index->desc.uid;

    btree_get_recycle_part_orgscn(index, part_loc, item);

    item->table_id = index->desc.table_id;
    item->index_id = index->desc.id;
    ctx->free_list.count--;
    ctx->free_list.first = item->next;
    item->next = CT_INVALID_ID32;

    if (ctx->free_list.count == 0) {
        ctx->free_list.last = CT_INVALID_ID32;
    }

    if (ctx->idx_list.count == 0) {
        ctx->idx_list.first = id;
    } else {
        /* the max value of id is 255 */
        ctx->items[ctx->idx_list.last].next = id;
    }

    ctx->idx_list.last = id;
    ctx->idx_list.count++;

    btree->wait_recycle = CT_TRUE;
    cm_spin_unlock(&ctx->lock);
    bt_put_garbage_size(session, &index->btree);

    if (IS_PART_INDEX(index)) {
        CT_LOG_DEBUG_INF("prepare to recycle pages of index %s, partition (%d, %d), %d indexes are waiting "
            "for recycling", index->desc.name, part_loc.part_no, part_loc.subpart_no, ctx->idx_list.count);
    } else {
        CT_LOG_DEBUG_INF("prepare to recycle pages of index %s, %d indexes are waiting for recycling", index->desc.name,
            ctx->idx_list.count);
    }
}

void btree_try_notify_recycle(knl_session_t *session, btree_t *btree, knl_part_locate_t part_loc)
{
    if (btree->wait_recycle) {
        return;
    }

    if (!btree_need_recycle(session, btree, NULL)) {
        return;
    }

    if (btree->index->desc.type == INDEX_TYPE_BTREE) {
        btree_notify_recycle(session, btree, part_loc);
    }
}

static status_t btree_do_delete(knl_session_t *session, knl_cursor_t *cursor, bool32 *is_found)
{
    btree_page_t *page = NULL;
    rd_btree_delete_t redo;
    btree_path_info_t path_info;
    btree_t *btree = CURSOR_BTREE(cursor);
    btree_key_t *key = (btree_key_t *)cursor->key;
    page_id_t next_page_id;
    bool32 need_encrypt = SPACE_NEED_ENCRYPT(btree->cipher_reserve_size);

    // prepare key and part number
    table_t *table = (table_t *)cursor->table;
    if (undo_prepare(session, (uint32)key->size + undo_part_locate_size(table),
                     IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type), need_encrypt) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (btree_enter_delete(session, cursor, &path_info, is_found) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!(*is_found)) {
        return CT_SUCCESS;
    }

    page = BTREE_CURR_PAGE(session);
    next_page_id = AS_PAGID(page->next);

    redo.slot = (uint16)path_info.path[0].slot;

    if (IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type)) {
        redo.undo_page = session->rm->undo_page_info.undo_rid.page_id;
        redo.undo_slot = session->rm->undo_page_info.undo_rid.slot;
    } else {
        redo.undo_page = session->rm->noredo_undo_page_info.undo_rid.page_id;
        redo.undo_slot = session->rm->noredo_undo_page_info.undo_rid.slot;
    }
    redo.ssn = (uint32)cursor->ssn;
    redo.itl_id = session->itl_id;
    redo.unused1 = (uint8)0;
    redo.unused2 = (uint16)0;

    btree_generate_undo(session, cursor, path_info.path, CT_TRUE, UNDO_BTREE_DELETE);

    btree_delete_key(session, page, &redo);
    if (IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type)) {
        log_put(session, RD_BTREE_DELETE, &redo, sizeof(rd_btree_delete_t), LOG_ENTRY_FLAG_NONE);
    }

    buf_leave_page(session, CT_TRUE);
    log_atomic_op_end(session);

    if (cursor->reused_xid != CT_INVALID_ID64 && !IS_INVALID_PAGID(next_page_id)) {
        (void)btree_clean_copied_itl(session, cursor->reused_xid, next_page_id,
            IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type));
    }

    if (KNL_IDX_RECYCLE_ENABLED(session->kernel)) {
        btree->chg_stats.delete_size += BTREE_COST_SIZE((btree_key_t *)cursor->key);
        btree_try_notify_recycle(session, btree, cursor->part_loc);
    }

    return CT_SUCCESS;
}

status_t btree_delete(knl_session_t *session, knl_cursor_t *cursor)
{
    btree_t *btree = NULL;
    bool32 is_found = CT_FALSE;

    if (btree_do_delete(session, cursor, &is_found) != CT_SUCCESS) {
        btree = CURSOR_BTREE(cursor);
        if (!btree->is_shadow || is_found) {
            return CT_ERROR;
        }

        if (btree_insert_into_shadow(session, cursor) != CT_SUCCESS) {
            int32 code = cm_get_error_code();
            if (code != ERR_DUPLICATE_KEY) {
                return CT_ERROR;
            }

            cm_reset_error();
        }

        if (btree_do_delete(session, cursor, &is_found) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

void btree_clean_lock(knl_session_t *session, lock_item_t *lock)
{
    rd_btree_clean_itl_t redo;
    uint64 itl_xid = CT_INVALID_ID64;
    uint8 option = !session->kernel->attr.delay_cleanout ? ENTER_PAGE_NORMAL : (ENTER_PAGE_NORMAL | ENTER_PAGE_TRY);

    log_atomic_op_begin(session);
    buf_enter_page(session, MAKE_PAGID(lock->file, lock->page), LATCH_MODE_X, option);

    if (session->curr_page == NULL) {
        log_atomic_op_end(session);
        return;
    }

    btree_page_t *page = BTREE_CURR_PAGE(session);
    page_id_t page_id = AS_PAGID(page->head.id);
    page_id_t next_page_id = AS_PAGID(page->next);

    if (lock->itl >= page->itls) {
        buf_leave_page(session, CT_FALSE);
        log_atomic_op_end(session);
        return;
    }

    itl_t *itl = BTREE_GET_ITL(page, lock->itl);
    if (!itl->is_active || itl->xid.value != session->rm->xid.value) {
        buf_leave_page(session, CT_FALSE);
        log_atomic_op_end(session);
        return;
    }

    if (itl->is_copied) {
        itl->is_copied = CT_FALSE;
        itl_xid = itl->xid.value;
    }

    itl->is_active = CT_FALSE;
    itl->scn = session->rm->txn->scn;
    itl->xid.value = CT_INVALID_ID64;

    redo.itl_id = lock->itl;
    redo.scn = itl->scn;
    redo.is_owscn = CT_FALSE;
    redo.is_copied = CT_FALSE;
    redo.aligned = (uint8)0;
    if (SPC_IS_LOGGING_BY_PAGEID(session, page_id)) {
        log_put(session, RD_BTREE_CLEAN_ITL, &redo, sizeof(rd_btree_clean_itl_t), LOG_ENTRY_FLAG_NONE);
    }

    buf_leave_page(session, CT_TRUE);
    log_atomic_op_end(session);

    if (itl_xid == CT_INVALID_ID64) {
        return;
    }

    while (!IS_INVALID_PAGID(next_page_id) && !IS_SAME_PAGID(next_page_id, AS_PAGID(lock->next_pagid))) {
        next_page_id = btree_clean_copied_itl(session, itl_xid, next_page_id,
                                              SPC_IS_LOGGING_BY_PAGEID(session, page_id));
    }
}

void btree_undo_insert(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot,
                       knl_dictionary_t *dc)
{
    btree_page_t *page = NULL;
    btree_dir_t *dir = NULL;
    itl_t *itl = NULL;
    rd_btree_undo_t redo;
    btree_key_t *key = NULL;
    bool32 compact_leaf = CT_FALSE;
    bool32 is_same = CT_FALSE;
    knl_scan_key_t scan_key;
    btree_path_info_t path_info;
    knl_part_locate_t part_loc;
    btree_find_assist_t find_assist;

    btree_key_t *ud_key = (btree_key_t *)ud_row->data;
    if (ud_row->contain_subpartno) {
        part_loc = *(knl_part_locate_t *)(ud_row->data + ud_key->size);
    } else {
        part_loc.part_no = *(uint32 *)(ud_row->data + ud_key->size);
        part_loc.subpart_no = CT_INVALID_ID32;
    }

    btree_t *btree = btree_get_handle_by_undo(session, dc, part_loc, (char *)ud_row);
    if (btree == NULL) {
        return;
    }
    path_info.part_loc = part_loc;
    btree_decode_key(btree->index, ud_key, &scan_key);
    btree_init_find_assist(btree, &path_info, &scan_key, BTREE_FIND_DELETE, &find_assist);
    (void)btree_find_update_pos(session, &find_assist, &is_same, &compact_leaf, CT_TRUE);
    if (find_assist.page_damage) {
        return;
    }

    page = BTREE_CURR_PAGE(session);
    knl_panic_log(is_same, "[BTREE] index %s cannot find the key %u-%u-%u for undo insert in page %u-%u",
                  btree->index->desc.name, (uint32)ud_key->rowid.file, (uint32)ud_key->rowid.page,
                  (uint32)ud_key->rowid.slot, (uint32)AS_PAGID(page->head.id).file,
                  (uint32)AS_PAGID(page->head.id).page);

    dir = BTREE_GET_DIR(page, path_info.path[0].slot);
    key = BTREE_GET_KEY(page, dir);
    knl_panic_log(IS_SAME_PAGID(key->undo_page, AS_PAGID(ud_page->head.id)), "key's undo_page and ud_page are not "
                  "same, panic info: page %u-%u type %u, ud_page %u-%u type %u index %s", AS_PAGID(page->head.id).file,
                  AS_PAGID(page->head.id).page, page->head.type, AS_PAGID(ud_page->head.id).file,
                  AS_PAGID(ud_page->head.id).page, ud_page->head.type, ((index_t *)btree->index)->desc.name);
    knl_panic_log(key->undo_slot == ud_slot, "undo_slot is abnormal, panic info: page %u-%u type %u undo_slot %u, "
                  "ud_page %u-%u type %u ud_slot %u, index %s", AS_PAGID(page->head.id).file,
                  AS_PAGID(page->head.id).page, page->head.type, key->undo_slot, AS_PAGID(ud_page->head.id).file,
                  AS_PAGID(ud_page->head.id).page, ud_page->head.type, ud_slot, ((index_t *)btree->index)->desc.name);
    knl_panic_log(dir->itl_id != CT_INVALID_ID8, "itl_id is invalid, panic info: page %u-%u type %u itl_id %u, "
                  "ud_page %u-%u type %u, index %s", AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page,
                  page->head.type, dir->itl_id, AS_PAGID(ud_page->head.id).file, AS_PAGID(ud_page->head.id).page,
                  ud_page->head.type, ((index_t *)btree->index)->desc.name);
    itl = BTREE_GET_ITL(page, dir->itl_id);
    knl_panic_log(itl->xid.value == session->rm->xid.value, "the xid of itl and rm are not equal, panic info: "
        "page %u-%u type %u ud_page %u-%u type %u index %s itl xid %llu rm xid %llu", AS_PAGID(page->head.id).file,
        AS_PAGID(page->head.id).page, page->head.type, AS_PAGID(ud_page->head.id).file,
        AS_PAGID(ud_page->head.id).page, ud_page->head.type, ((index_t *)btree->index)->desc.name, itl->xid.value,
        session->rm->xid.value);

    key->undo_page = ud_row->prev_page;
    key->undo_slot = ud_row->prev_slot;
    key->is_owscn = ud_row->is_owscn;
    key->is_deleted = CT_TRUE;
    /*
     * rollback heap_page and heap_slot to old version, because for unique index
     * old and new is same just means they have same index column value, however
     * old and new key may not point to the same heap row
     */
    key->rowid = ud_key->rowid;

    if (ud_row->is_xfirst) {
        key->scn = ud_row->scn;
        dir->itl_id = CT_INVALID_ID8;
    } else {
        key->scn = ud_row->ssn;
    }

    if (SPC_IS_LOGGING_BY_PAGEID(session, btree->entry)) {
        redo.slot = (uint16)path_info.path[0].slot;
        redo.scn = key->scn;
        redo.is_owscn = ud_row->is_owscn;
        redo.is_xfirst = ud_row->is_xfirst;
        redo.undo_page = ud_row->prev_page;
        redo.undo_slot = ud_row->prev_slot;
        redo.rowid = ud_key->rowid;
        redo.unused = 0;
        log_put(session, RD_BTREE_UNDO_INSERT, &redo, sizeof(rd_btree_undo_t), LOG_ENTRY_FLAG_NONE);
    }

    buf_leave_page(session, CT_TRUE);

    if (KNL_IDX_RECYCLE_ENABLED(session->kernel)) {
        btree->chg_stats.delete_size += BTREE_COST_SIZE(ud_key);
        btree_try_notify_recycle(session, btree, part_loc);
    }
}

static void btree_undo_delete_update_partid(knl_session_t *session, btree_t *btree, btree_key_t *ud_key,
    btree_key_t *key, uint16 slot)
{
    index_t *index = btree->index;
    table_t *table = &index->entity->table;

    if (!IS_PART_TABLE(table) || IS_PART_INDEX(index)) {
        return;
    }

    rd_update_btree_partid_t redo;
    redo.slot = slot;
    redo.unused = 0;
    if (IS_COMPART_TABLE(table->part_table)) {
        uint32 old_parent_partid = *(uint32 *)((char *)ud_key + ud_key->size - sizeof(uint32));
        uint32 old_part_id = *(uint32 *)((char *)ud_key + ud_key->size - sizeof(uint32) - sizeof(uint32));
        uint32 new_parent_partid = *(uint32 *)((char *)key + key->size - sizeof(uint32));
        uint32 new_part_id = *(uint32 *)((char *)key + key->size - sizeof(uint32) - sizeof(uint32));

        if (!(old_parent_partid == new_parent_partid && old_part_id == new_part_id)) {
            *(uint32 *)((char *)key + key->size - sizeof(uint32)) = old_parent_partid;
            *(uint32 *)((char *)key + key->size - sizeof(uint32) - sizeof(uint32)) = old_part_id;

            if (SPC_IS_LOGGING_BY_PAGEID(session, btree->entry)) {
                redo.parent_partid = old_parent_partid;
                redo.part_id = old_part_id;
                redo.is_compart_table = CT_TRUE;
                log_put(session, RD_BTREE_UPDATE_PARTID, &redo, sizeof(rd_update_btree_partid_t), LOG_ENTRY_FLAG_NONE);
            }
        }
    } else {
        uint32 old_part_id = *(uint32 *)((char *)ud_key + ud_key->size - sizeof(uint32));
        uint32 new_part_id = *(uint32 *)((char *)key + key->size - sizeof(uint32));
        if (old_part_id != new_part_id) {
            *(uint32 *)((char *)key + key->size - sizeof(uint32)) = old_part_id;
            if (SPC_IS_LOGGING_BY_PAGEID(session, btree->entry)) {
                redo.parent_partid = CT_INVALID_ID32;
                redo.part_id = old_part_id;
                redo.is_compart_table = CT_FALSE;
                log_put(session, RD_BTREE_UPDATE_PARTID, &redo, sizeof(rd_update_btree_partid_t), LOG_ENTRY_FLAG_NONE);
            }
        }
    }
}

void btree_undo_delete(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot,
                       knl_dictionary_t *dc)
{
    rd_btree_undo_t redo = { 0 };
    knl_scan_key_t scan_key;
    bool32 compact_leaf = CT_FALSE;
    bool32 is_same = CT_FALSE;
    btree_path_info_t path_info;
    btree_find_assist_t find_assist;

    btree_key_t *ud_key = (btree_key_t *)ud_row->data;
    if (ud_row->contain_subpartno) {
        path_info.part_loc = *(knl_part_locate_t *)(ud_row->data + ud_key->size);
    } else {
        path_info.part_loc.part_no = *(uint32 *)(ud_row->data + ud_key->size);
        path_info.part_loc.subpart_no = CT_INVALID_ID32;
    }
    
    btree_t *btree = btree_get_handle_by_undo(session, dc, path_info.part_loc, (char *)ud_row);
    if (btree == NULL) {
        return;
    }

    btree_decode_key(btree->index, ud_key, &scan_key);
    btree_init_find_assist(btree, &path_info, &scan_key, BTREE_FIND_DELETE, &find_assist);
    (void)btree_find_update_pos(session, &find_assist, &is_same, &compact_leaf, CT_TRUE);
    if (find_assist.page_damage) {
        return;
    }

    btree_page_t *page = BTREE_CURR_PAGE(session);
    btree_dir_t *dir = BTREE_GET_DIR(page, path_info.path[0].slot);
    btree_key_t *key = BTREE_GET_KEY(page, dir);
    knl_panic_log(IS_SAME_PAGID(key->undo_page, AS_PAGID(ud_page->head.id)),
        "key's undo_page and ud_page are not same, panic info: page %u-%u type %u, ud_page %u-%u type %u, index %s",
        AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type, AS_PAGID(ud_page->head.id).file,
        AS_PAGID(ud_page->head.id).page, ud_page->head.type, ((index_t *)btree->index)->desc.name);
    knl_panic_log(key->undo_slot == ud_slot, "undo_slot is abnormal, panic info: page %u-%u type %u undo_slot %u, "
        "ud_page %u-%u type %u ud_slot %u, index %s", AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page,
        page->head.type, key->undo_slot, AS_PAGID(ud_page->head.id).file, AS_PAGID(ud_page->head.id).page,
        ud_page->head.type, ud_slot, ((index_t *)btree->index)->desc.name);
    knl_panic_log(dir->itl_id != CT_INVALID_ID8,
        "itl_id is invalid, panic info: page %u-%u type %u, ud_page %u-%u type %u, index %s itl_id %u",
        AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type, AS_PAGID(ud_page->head.id).file,
        AS_PAGID(ud_page->head.id).page, ud_page->head.type, ((index_t *)btree->index)->desc.name, dir->itl_id);
    itl_t *itl = BTREE_GET_ITL(page, dir->itl_id);
    knl_panic_log(itl->xid.value == session->rm->xid.value, "the xid of itl and rm are not equal, panic info: "
        "page %u-%u type %u ud_page %u-%u type %u index %s itl xid %llu rm xid %llu", AS_PAGID(page->head.id).file,
        AS_PAGID(page->head.id).page, page->head.type, AS_PAGID(ud_page->head.id).file,
        AS_PAGID(ud_page->head.id).page, ud_page->head.type, ((index_t *)btree->index)->desc.name, itl->xid.value,
        session->rm->xid.value);

    key->undo_page = ud_row->prev_page;
    key->undo_slot = ud_row->prev_slot;
    key->is_owscn = ud_row->is_owscn;
    key->is_deleted = CT_FALSE;

    if (ud_row->is_xfirst) {
        key->scn = ud_row->scn;
        dir->itl_id = CT_INVALID_ID8;
    } else {
        key->scn = ud_row->ssn;
    }

    redo.slot = (uint16)path_info.path[0].slot;
    redo.is_xfirst = ud_row->is_xfirst;
    redo.is_owscn = ud_row->is_owscn;
    redo.scn = key->scn;
    redo.undo_page = ud_row->prev_page;
    redo.undo_slot = ud_row->prev_slot;
    if (SPC_IS_LOGGING_BY_PAGEID(session, btree->entry)) {
        log_put(session, RD_BTREE_UNDO_DELETE, &redo, sizeof(rd_btree_undo_t), LOG_ENTRY_FLAG_NONE);
    }

    btree_undo_delete_update_partid(session, btree, ud_key, key, redo.slot);
    buf_leave_page(session, CT_TRUE);

    if (KNL_IDX_RECYCLE_ENABLED(session->kernel)) {
        btree->chg_stats.delete_size -= BTREE_COST_SIZE(ud_key);
    }
}

void btree_append_to_page(knl_session_t *session, btree_page_t *page, btree_key_t *key, uint8 itl_id)
{
    btree_dir_t *dir = NULL;
    errno_t err;

    knl_panic_log(page->free_end - page->free_begin >= (uint16)(key->size + sizeof(btree_dir_t)),
        "page free size is abnormal, panic info: key size %u page %u-%u type %u free_end %u free_begin %u", key->size,
        AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type, page->free_end, page->free_begin);
    dir = BTREE_GET_DIR(page, page->keys);
    dir->offset = page->free_begin;
    dir->itl_id = itl_id;
    err = memcpy_sp((char *)page + page->free_begin, BTREE_PAGE_FREE_SIZE(page) - sizeof(btree_dir_t),
        key, (size_t)key->size);
    knl_securec_check(err);
    page->free_begin += (uint16)key->size;
    page->free_end -= sizeof(btree_dir_t);
    page->free_size -= (uint16)key->size + sizeof(btree_dir_t);
    page->keys++;
}

static status_t btree_construct_ancestors(knl_session_t *session, btree_t *btree, btree_page_t **parent_page,
    char **key_buf, btree_key_t *key, uint32 level, bool32 nologging)
{
    page_id_t page_id, prev_page_id;
    btree_page_t *page = NULL;
    bool32 is_ext_first = CT_FALSE;

    if (level >= CT_MAX_ROOT_LEVEL - 1) {
        CT_THROW_ERROR(ERR_BTREE_LEVEL_EXCEEDED, CT_MAX_ROOT_LEVEL);
        return CT_ERROR;
    }

    if (key_buf[level] == NULL) {
        key_buf[level] = (char *)cm_push(session->stack, CT_KEY_BUF_SIZE);
    }

    char *min_key = key_buf[level];
    if (parent_page[level] == NULL) {
        parent_page[level] = (btree_page_t *)cm_push(session->stack, session->kernel->attr.page_size);
        if (btree_prepare_pages(session, btree) != CT_SUCCESS) {
            return CT_ERROR;
        }

        log_atomic_op_begin(session);
        btree_alloc_from_ufp(session, btree, &page_id, &is_ext_first);
        buf_enter_page(session, page_id, LATCH_MODE_X, is_ext_first ? ENTER_PAGE_NORMAL : ENTER_PAGE_NO_READ);
        page = BTREE_CURR_PAGE(session);
        btree_format_page(session, BTREE_SEGMENT(session, btree->entry, btree->segment), page_id, level + 1,
                          (uint8)page->head.ext_size, is_ext_first ? CT_TRUE : CT_FALSE);
        buf_leave_page(session, CT_TRUE);

        log_atomic_op_end(session);

        btree_format_vm_page(session, BTREE_SEGMENT(session, btree->entry, btree->segment),
                             parent_page[level], page_id, level + 1);
        TO_PAGID_DATA(INVALID_PAGID, parent_page[level]->prev);
        TO_PAGID_DATA(INVALID_PAGID, parent_page[level]->next);
    }

    btree_page_t *vm_page = parent_page[level];
    uint16 pct_size = (BTREE_COST_SIZE(key) > DEFAULT_PAGE_SIZE(session) - BTREE_PCT_SIZE(btree) ||
        vm_page->level > 0) ? (uint16)0 : BTREE_PCT_SIZE(btree);
    if (vm_page->free_begin + BTREE_COST_SIZE(key) + pct_size > vm_page->free_end) {
        if (btree_prepare_pages(session, btree) != CT_SUCCESS) {
            return CT_ERROR;
        }

        log_atomic_op_begin(session);
        btree_alloc_from_ufp(session, btree, &page_id, &is_ext_first);
        page = BTREE_CURR_PAGE(session);
        buf_enter_page(session, page_id, LATCH_MODE_X, is_ext_first ? ENTER_PAGE_NORMAL : ENTER_PAGE_NO_READ);
        btree_format_page(session, BTREE_SEGMENT(session, btree->entry, btree->segment), page_id, level + 1,
                          (uint8)page->head.ext_size, is_ext_first ? CT_TRUE : CT_FALSE);
        buf_leave_page(session, CT_TRUE);

        log_atomic_op_end(session);

        TO_PAGID_DATA(page_id, vm_page->next);

        log_atomic_op_begin(session);
        log_set_group_nolog_insert(session, !nologging);
        buf_enter_page(session, AS_PAGID(vm_page->head.id), LATCH_MODE_X, ENTER_PAGE_NORMAL);
        page = BTREE_CURR_PAGE(session);
        errno_t err = memcpy_sp(BTREE_PAGE_BODY(page), BTREE_PAGE_BODY_SIZE(page), BTREE_PAGE_BODY(vm_page),
            BTREE_PAGE_BODY_SIZE(page));
        knl_securec_check(err);
        if (SPC_IS_LOGGING_BY_PAGEID(session, btree->entry) && !nologging) {
            log_put(session, RD_BTREE_CONSTRUCT_PAGE, BTREE_PAGE_BODY(page), BTREE_PAGE_BODY_SIZE(page),
                LOG_ENTRY_FLAG_NONE);
        }

        if (parent_page[level + 1] != NULL) {
            buf_leave_page(session, CT_TRUE);
            log_atomic_op_end(session);
        } else {
            btree_key_t *mkey = BTREE_GET_KEY(page, BTREE_GET_DIR(page, 0));
            err = memcpy_sp(min_key, CT_KEY_BUF_SIZE, mkey, (size_t)mkey->size);
            knl_securec_check(err);
            ((btree_key_t *)min_key)->child = AS_PAGID(parent_page[level]->head.id);
            buf_leave_page(session, CT_TRUE);
            log_atomic_op_end(session);
            if (btree_construct_ancestors(session, btree, parent_page, key_buf, (btree_key_t *)min_key, level + 1,
                nologging) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }
        prev_page_id = AS_PAGID(vm_page->head.id);
        btree_format_vm_page(session, BTREE_SEGMENT(session, btree->entry, btree->segment),
                             vm_page, page_id, level + 1);
        TO_PAGID_DATA(prev_page_id, vm_page->prev);
        err = memcpy_sp(min_key, CT_KEY_BUF_SIZE, key, (size_t)key->size);
        knl_securec_check(err);
        ((btree_key_t *)min_key)->child = page_id;
        if (btree_construct_ancestors(session, btree, parent_page, key_buf, (btree_key_t *)min_key, level + 1,
            nologging) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    btree_append_to_page(session, vm_page, key, CT_INVALID_ID8);
    return CT_SUCCESS;
}

void btree_construct_ancestors_finish(knl_session_t *session, btree_t *btree, btree_page_t **parent_page,
    bool32 nologging)
{
    btree_segment_t *segment = BTREE_SEGMENT(session, btree->entry, btree->segment);
    btree_page_t *page = NULL;
    errno_t err;

    if (parent_page[0] == NULL) {
        return;
    }

    for (uint32 i = 0; i < CT_MAX_ROOT_LEVEL; i++) {
        log_atomic_op_begin(session);
        log_set_group_nolog_insert(session, !nologging);
        buf_enter_page(session, AS_PAGID(parent_page[i]->head.id), LATCH_MODE_X, ENTER_PAGE_NORMAL);
        page = BTREE_CURR_PAGE(session);
        err = memcpy_sp(BTREE_PAGE_BODY(page), BTREE_PAGE_BODY_SIZE(page), BTREE_PAGE_BODY(parent_page[i]),
                        BTREE_PAGE_BODY_SIZE(page));
        knl_securec_check(err);
        if (SPACE_IS_LOGGING(SPACE_GET(session, segment->space_id)) && !nologging) {
            log_put(session, RD_BTREE_CONSTRUCT_PAGE, BTREE_PAGE_BODY(page), BTREE_PAGE_BODY_SIZE(page),
                LOG_ENTRY_FLAG_NONE);
        }

        buf_leave_page(session, CT_TRUE);

        if (parent_page[i + 1] == NULL) {
            buf_enter_page(session, btree->entry, LATCH_MODE_X, ENTER_PAGE_NORMAL);

            /*
             * tree level is count from 1, i is count from 0
             * and i + 1 is the level of parent page, so tree level is i + 2
             */
            segment->tree_info.level = i + 2;
            TO_PAGID_DATA(AS_PAGID(parent_page[i]->head.id), segment->tree_info.root);
            if (SPACE_IS_LOGGING(SPACE_GET(session, segment->space_id))) {
                log_put(session, RD_BTREE_CHANGE_SEG, (btree_segment_t *)btree->segment, sizeof(btree_segment_t),
                    LOG_ENTRY_FLAG_NONE);
            }
            buf_leave_page(session, CT_TRUE);
            log_atomic_op_end(session);
            break;
        }
        log_atomic_op_end(session);
    }
}

/*
 * Description     : Build btree with sorted keys
 * Input           : ctx : context of btree materials
 * Output          : NA
 * Return Value    : status_t
 * History         : 1. 2017/4/26,  add description
 */
status_t btree_construct(btree_mt_context_t *ctx)
{
    mtrl_cursor_t cursor;
    mtrl_sort_cursor_t cur1, cur2;
    btree_page_t *parent_page[CT_MAX_BTREE_LEVEL];
    btree_key_t *key = NULL;
    btree_key_t *mkey = NULL;
    knl_session_t *session = (knl_session_t *)ctx->mtrl_ctx.session;
    page_id_t prev_page_id;
    char *key_buf[CT_MAX_BTREE_LEVEL];
    status_t status = CT_SUCCESS;
    uint16 pct_size;
    bool32 is_ext_first = CT_FALSE;

    CM_SAVE_STACK(session->stack);

    btree_t *btree = (btree_t *)ctx->mtrl_ctx.segments[ctx->seg_id]->cmp_items;
    btree_segment_t *segment = BTREE_SEGMENT(session, btree->entry, btree->segment);
    page_id_t page_id = AS_PAGID(segment->tree_info.root);
    bool32 need_redo = SPACE_IS_LOGGING(SPACE_GET(session, segment->space_id));
    uint8 cipher_reserve_size = btree->cipher_reserve_size;

    log_atomic_op_begin(session);
    log_set_group_nolog_insert(session, !ctx->nologging);
    session->rm->logging = !ctx->nologging;
    session->rm->nolog_type = TABLE_LEVEL;
    if (btree_open_mtrl_cursor(ctx, &cur1, &cur2, &cursor) != CT_SUCCESS) {
        log_atomic_op_end(session);
        return CT_ERROR;
    }

    if (btree_fetch_mtrl_sort_key(ctx, &cur1, &cur2, &cursor) != CT_SUCCESS) {
        log_atomic_op_end(session);
        return CT_ERROR;
    }

    bool32 changed = !cursor.eof;
    char *src_mkey = (char *)cm_push(session->stack, CT_KEY_BUF_SIZE);
    char *dst_mkey = (char *)cm_push(session->stack, CT_KEY_BUF_SIZE);

    uint32 mem_size = sizeof(char *) * CT_MAX_BTREE_LEVEL;
    errno_t err = memset_sp(parent_page, mem_size, 0, mem_size);
    knl_securec_check(err);
    err = memset_sp(key_buf, mem_size, 0, mem_size);
    knl_securec_check(err);

    buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    btree_page_t *page = BTREE_CURR_PAGE(session);
    int16 free_size = (int16)(DEFAULT_PAGE_SIZE(session) - sizeof(btree_page_t) - sizeof(page_tail_t) -
        cipher_reserve_size - page->itls * sizeof(itl_t) - BTREE_RESERVE_SIZE);

    while (!cursor.eof) {
        key = (btree_key_t *)cursor.sort.row;
        pct_size = (BTREE_COST_SIZE(key) > DEFAULT_PAGE_SIZE(session) - BTREE_PCT_SIZE(btree))
                   ? (uint16)0
                   : BTREE_PCT_SIZE(btree);
        if (free_size - (int16)pct_size - (int16)BTREE_COST_SIZE(key) < 0) { // key->size is 3900 at most now
            if (need_redo && !ctx->nologging) {
                log_put(session, RD_BTREE_CONSTRUCT_PAGE, BTREE_PAGE_BODY(page),
                    BTREE_PAGE_BODY_SIZE(page), LOG_ENTRY_FLAG_NONE);
            }

            prev_page_id = AS_PAGID(page->head.id);
            buf_leave_page(session, CT_TRUE);
            log_atomic_op_end(session);

            // page is full, we need move on to next page
            if (btree_prepare_pages(session, btree) != CT_SUCCESS) {
                status = CT_ERROR;
                break;
            }

            log_atomic_op_begin(session);

            is_ext_first = CT_FALSE;
            btree_alloc_from_ufp(session, btree, &page_id, &is_ext_first);

            buf_enter_page(session, page_id, LATCH_MODE_X, is_ext_first ? ENTER_PAGE_NORMAL : ENTER_PAGE_NO_READ);
            page = BTREE_CURR_PAGE(session);
            btree_format_page(session, segment, page_id, 0, (uint8)page->head.ext_size,
                              is_ext_first ? CT_TRUE : CT_FALSE);
            buf_leave_page(session, CT_TRUE);

            buf_enter_page(session, prev_page_id, LATCH_MODE_X, ENTER_PAGE_NORMAL);
            page = BTREE_CURR_PAGE(session);
            TO_PAGID_DATA(page_id, page->next);

            if (need_redo) {
                /* log the prev and next page */
                log_put(session, RD_BTREE_CHANGE_CHAIN, &page->prev, sizeof(page_id_t) * 2, LOG_ENTRY_FLAG_NONE);
            }

            if (parent_page[0] == NULL) {
                mkey = BTREE_GET_KEY(page, BTREE_GET_DIR(page, 0));
                err = memcpy_sp(src_mkey, CT_KEY_BUF_SIZE, (void *)mkey, (size_t)mkey->size);
                knl_securec_check(err);
                ((btree_key_t *)src_mkey)->child = AS_PAGID(page->head.id);
                btree_minimize_unique_parent(btree->index, (btree_key_t *)src_mkey);
            }

            buf_leave_page(session, CT_TRUE);
            log_atomic_op_end(session);

            if (parent_page[0] == NULL && btree_construct_ancestors(session, btree, parent_page, key_buf,
                (btree_key_t *)src_mkey, 0, ctx->nologging) != CT_SUCCESS) {
                status = CT_ERROR;
                break;
            }

            err = memcpy_sp(dst_mkey, CT_KEY_BUF_SIZE, (void *)key, (size_t)key->size);
            knl_securec_check(err);
            ((btree_key_t *)dst_mkey)->child = page_id;
            btree_minimize_unique_parent(btree->index, (btree_key_t *)dst_mkey);
            if (btree_construct_ancestors(session, btree, parent_page, key_buf,
                (btree_key_t *)dst_mkey, 0, ctx->nologging) != CT_SUCCESS) {
                status = CT_ERROR;
                break;
            }

            log_atomic_op_begin(session);
            log_set_group_nolog_insert(session, !ctx->nologging);
            buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_NORMAL);
            page = BTREE_CURR_PAGE(session);
            TO_PAGID_DATA(prev_page_id, page->prev);
            free_size = (int16)(DEFAULT_PAGE_SIZE(session) - sizeof(btree_page_t) - sizeof(page_tail_t) -
                cipher_reserve_size - page->itls * sizeof(itl_t) - BTREE_RESERVE_SIZE);
        }

        btree_append_to_page(session, page, key, CT_INVALID_ID8);
        free_size -= (int16)key->size + sizeof(btree_dir_t);

        if (btree_fetch_mtrl_sort_key(ctx, &cur1, &cur2, &cursor) != CT_SUCCESS) {
            log_atomic_op_end(session);
            status = CT_ERROR;
            break;
        }
    }

    if (status == CT_SUCCESS) {
        if (need_redo) {
            log_put(session, RD_BTREE_CONSTRUCT_PAGE, BTREE_PAGE_BODY(page),
                BTREE_PAGE_BODY_SIZE(page), LOG_ENTRY_FLAG_NONE);
        }

        buf_leave_page(session, changed);
        log_atomic_op_end(session);
        btree_construct_ancestors_finish(session, btree, parent_page, ctx->nologging);
    }

    btree_close_mtrl_cursor(ctx, &cur1, &cur2, &cursor);
    CM_RESTORE_STACK(session->stack);
    return status;
}

static void btree_get_parent_page(knl_session_t *session, btree_t *btree, knl_scan_key_t *scan_key,
                                  uint32 child_level, btree_path_info_t *path_info)
{
    btree_segment_t *seg = BTREE_SEGMENT(session, btree->entry, btree->segment);
    knl_tree_info_t tree_info;
    index_t *index = btree->index;
    btree_dir_t *dir = NULL;
    btree_key_t *curr_key = NULL;
    btree_page_t *page = NULL;
    page_id_t page_id;
    bool32 cmp_rowid;
    bool32 is_same = CT_FALSE;
    uint32 level;

    tree_info.value = cm_atomic_get(&seg->tree_info.value);
    level = (uint32)tree_info.level - 1;
    page_id = AS_PAGID(tree_info.root);
    cmp_rowid = (index->desc.primary || index->desc.unique) ? CT_FALSE : CT_TRUE;
    for (;;) {
        buf_enter_page(session, page_id, (child_level + 1 == level) ? LATCH_MODE_X : LATCH_MODE_S, ENTER_PAGE_NORMAL);
        page = BTREE_CURR_PAGE(session);
        SET_ROWID_PAGE(&path_info->path[page->level], page_id);
        btree_binary_search(index, page, scan_key, path_info, cmp_rowid, &is_same);

        if (child_level + 1 == page->level) {
            break;
        }

        dir = BTREE_GET_DIR(page, path_info->path[page->level].slot);
        curr_key = BTREE_GET_KEY(page, dir);
        page_id = curr_key->child;
        level = page->level - 1;
        buf_leave_page(session, CT_FALSE);
    }
}

bool32 bt_recycle_page(knl_session_t *session, btree_t *btree, btree_recycle_desc_t *recycle_desc,
    knl_part_locate_t part_locate)
{
    space_t *space = SPACE_GET(session, DATAFILE_GET(session, recycle_desc->leaf_id.file)->space_id);
    uint8 cipher_size = space->ctrl->cipher_reserve_size;

    buf_enter_page(session, recycle_desc->leaf_id, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    btree_page_t *page = BTREE_CURR_PAGE(session);
    if (page->head.lsn != recycle_desc->snapshot_lsn || page->is_recycled) {
        buf_leave_page(session, CT_FALSE);  // leaf page
        recycle_desc->is_sparse = CT_TRUE;
        return CT_FALSE;
    }

    page->is_recycled = 1;
    page_id_t *next_del_page = BTREE_NEXT_DEL_PAGE(session, cipher_size);
    *next_del_page = INVALID_PAGID;
    knl_scn_t *next_recycle_scn = BTREE_NEXT_RECYCLE_SCN(session, cipher_size);
    *next_recycle_scn = 0;
    knl_scn_t ow_del_scn = MAX(btree->chg_stats.ow_del_scn, recycle_desc->max_del_scn);
    KNL_SET_SCN(&btree->chg_stats.ow_del_scn, ow_del_scn);

    if (SPC_IS_LOGGING_BY_PAGEID(session, btree->entry)) {
        rd_btree_set_recycle_t rd;
        rd.btree_info.min_scn = btree_get_recycle_min_scn(session);
        rd.btree_info.uid = btree->index->desc.uid;
        rd.btree_info.oid = btree->index->desc.table_id;
        rd.btree_info.idx_id = btree->index->desc.id;
        rd.btree_info.part_loc = part_locate;
        rd.ow_del_scn = ow_del_scn;
        btree->min_scn = rd.btree_info.min_scn;
        log_put(session, RD_BTREE_RECYCLE_PAGE, &rd, sizeof(rd_btree_set_recycle_t), LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, CT_TRUE);
    return CT_TRUE;
}

void btree_concat_del_pages(knl_session_t *session, btree_t *btree, btree_recycle_desc_t *desc)
{
    space_t *space = SPACE_GET(session, DATAFILE_GET(session, desc->leaf_id.file)->space_id);
    uint8 cipher_size = space->ctrl->cipher_reserve_size;

    buf_enter_page(session, btree->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    knl_scn_t curr_scn = KNL_GET_SCN(&btree->segment->recycle_ver_scn);
    if (btree->segment->recycled_pages.count == 0) {
        btree->segment->recycled_pages.first = desc->leaf_id;
        btree->segment->first_recycle_scn = curr_scn;
    } else {
        buf_enter_page(session, btree->segment->recycled_pages.last, LATCH_MODE_X, ENTER_PAGE_NORMAL);
        page_id_t *next_del_page = BTREE_NEXT_DEL_PAGE(session, cipher_size);
        knl_scn_t *next_recycle_scn = BTREE_NEXT_RECYCLE_SCN(session, cipher_size);
        *next_del_page = desc->leaf_id;
        *next_recycle_scn = curr_scn;
        if (SPC_IS_LOGGING_BY_PAGEID(session, btree->entry)) {
            rd_btree_concat_dels_t rd = {desc->leaf_id, curr_scn};
            log_put(session, RD_BTREE_CONCAT_DEL_PAGE, &rd, sizeof(rd_btree_concat_dels_t), LOG_ENTRY_FLAG_NONE);
        }
        buf_leave_page(session, CT_TRUE);
    }

    btree->segment->recycled_pages.last = desc->leaf_id;
    btree->segment->recycled_pages.count++;
    knl_panic_log(curr_scn > btree->segment->last_recycle_scn,
        "invalid new last recycle scn %llu, old last recycle scn %llu", curr_scn, btree->segment->last_recycle_scn);
    btree->segment->last_recycle_scn = curr_scn;
    btree->segment->ow_del_scn = KNL_GET_SCN(&btree->chg_stats.ow_del_scn);
    knl_scn_t next_version = MAX(DB_NOW_TO_SCN(session), curr_scn + 1);
    knl_panic_log(next_version > curr_scn, "invalid next version scn %llu, curr version scn %llu",
        next_version, curr_scn);
    KNL_SET_SCN(&btree->segment->recycle_ver_scn, next_version);
    if (SPC_IS_LOGGING_BY_PAGEID(session, btree->entry)) {
        log_put(session, RD_BTREE_CHANGE_SEG, (btree_segment_t *)btree->segment, sizeof(btree_segment_t),
            LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, CT_TRUE);
}

void btree_concat_next_to_prev(knl_session_t *session, page_id_t next_page_id, page_id_t prev_page_id)
{
    btree_page_t *next_page = NULL;
    btree_page_t *prev_page = NULL;

    // concat prev->next
    if (!IS_INVALID_PAGID(next_page_id)) {
        buf_enter_page(session, next_page_id, LATCH_MODE_X, ENTER_PAGE_NORMAL);
        next_page = BTREE_CURR_PAGE(session);
        TO_PAGID_DATA(prev_page_id, next_page->prev);
        if (SPC_IS_LOGGING_BY_PAGEID(session, next_page_id)) {
            /* log the prev and next page */
            log_put(session, RD_BTREE_CHANGE_CHAIN, &next_page->prev, sizeof(page_id_t) * 2, LOG_ENTRY_FLAG_NONE);
        }
        buf_leave_page(session, CT_TRUE);
    }

    buf_enter_page(session, prev_page_id, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    prev_page = BTREE_CURR_PAGE(session);
    TO_PAGID_DATA(next_page_id, prev_page->next);
    if (SPC_IS_LOGGING_BY_PAGEID(session, prev_page_id)) {
        /* log the prev and next page */
        log_put(session, RD_BTREE_CHANGE_CHAIN, &prev_page->prev, sizeof(page_id_t) * 2, LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, CT_TRUE);
}

static bool32 bt_recycle_delete_leaf(knl_session_t *session, btree_t *btree, knl_scan_key_t *scan_key,
    btree_recycle_desc_t *recycle_desc, knl_part_locate_t part_locate)
{
    btree_path_info_t path_info;

    // remove parent key
    btree_get_parent_page(session, btree, scan_key, 0, &path_info);
    btree_page_t *parent_page = BTREE_CURR_PAGE(session);
    if (path_info.path[1].slot == 0) {
        buf_leave_page(session, CT_FALSE);
        recycle_desc->is_first_child = CT_TRUE;
        return CT_FALSE;
    }

    if (!bt_recycle_page(session, btree, recycle_desc, part_locate)) {
        buf_leave_page(session, CT_FALSE);  // parent page
        recycle_desc->is_sparse = CT_TRUE;
        return CT_FALSE;
    }

    recycle_desc->is_recycled = CT_TRUE;
    btree_clean_key(session, parent_page, (uint16)path_info.path[1].slot);
    uint16 key_slot = (uint16)path_info.path[1].slot;

    if (SPC_IS_LOGGING_BY_PAGEID(session, btree->entry)) {
        log_put(session, RD_BTREE_CLEAN_KEY, &key_slot, sizeof(uint16), LOG_ENTRY_FLAG_NONE);
    }
    page_id_t root = AS_PAGID(BTREE_SEGMENT(session, btree->entry, btree->segment)->tree_info.root);
    if (IS_SAME_PAGID(AS_PAGID(parent_page->head.id), root)) {
        btree_copy_root_page(session, btree, parent_page);
    }
    buf_leave_page(session, CT_TRUE);

    return CT_TRUE;
}

/*
 * Description     : recycle leaf page to deleted pages list
 * Input           : leaf_id: the page id can be recycled
 * Input           : lsn & pcn: to make sure leaf_page never be changed
 * Output          : NA
 * ReturnValue     : void
 */
static void btree_recycle_leaf(knl_session_t *session, btree_t *btree, knl_part_locate_t part_loc,
    btree_recycle_desc_t *desc)
{
    knl_scan_key_t scan_key;
    int64 version;

    CM_SAVE_STACK(session->stack);
    char *key_buf = (char *)cm_push(session->stack, CT_KEY_BUF_SIZE);

    log_atomic_op_begin(session);
    for (;;) {
        cm_latch_x(&btree->struct_latch.latch, session->id, &session->stat_btree);
        if (!btree->is_splitting) {
            break;
        }
        cm_unlatch(&btree->struct_latch.latch, &session->stat_btree);
        cm_spin_sleep();
        CT_LOG_DEBUG_INF("index %s recycle page %u-%u try latch btree struct latch.",
            btree->index->desc.name, (uint32)desc->leaf_id.file, (uint32)desc->leaf_id.page);
        continue;
    }

    buf_enter_page(session, desc->leaf_id, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    btree_page_t *page = BTREE_CURR_PAGE(session);
    if (page->head.lsn != desc->snapshot_lsn || page->is_recycled) {
        buf_leave_page(session, CT_FALSE);
        cm_unlatch(&btree->struct_latch.latch, &session->stat_btree);
        log_atomic_op_end(session);
        CM_RESTORE_STACK(session->stack);
        desc->is_sparse = CT_TRUE;
        return;
    }
    page_id_t prev_page_id = AS_PAGID(page->prev);
    page_id_t next_page_id = AS_PAGID(page->next);
    btree_dir_t *dir = BTREE_GET_DIR(page, 0);
    btree_key_t *key = BTREE_GET_KEY(page, dir);
    errno_t err = memcpy_sp(key_buf, CT_KEY_BUF_SIZE, key, (size_t)key->size);
    knl_securec_check(err);
    btree_decode_key(btree->index, (btree_key_t *)key_buf, &scan_key);
    buf_leave_page(session, CT_FALSE);

    if (!bt_recycle_delete_leaf(session, btree, &scan_key, desc, part_loc)) {
        cm_unlatch(&btree->struct_latch.latch, &session->stat_btree);
        log_atomic_op_end(session);
        CM_RESTORE_STACK(session->stack);
        return;
    }

    btree_concat_next_to_prev(session, next_page_id, prev_page_id);
    btree_concat_del_pages(session, btree, desc);

    version = btree->struct_ver + 1;
    (void)cm_atomic_set(&btree->struct_ver, version);

    cm_unlatch(&btree->struct_latch.latch, &session->stat_btree);
    log_atomic_op_end(session);
    CM_RESTORE_STACK(session->stack);
}

knl_scn_t btree_get_recycle_min_scn(knl_session_t *session)
{
    knl_scn_t current_scn = DB_CURR_SCN(session);
    knl_scn_t min_scn = KNL_GET_SCN(&session->kernel->min_scn);
    uint32 defer_recycle_time = DB_DEFER_RECYLE_TIME(session);

    timeval_t time;
    time_t init_time = KNL_INVALID_SCN;
    time.tv_sec = defer_recycle_time;
    time.tv_usec = 0;

    knl_scn_t defer_recycle_scn = KNL_TIME_TO_SCN(&time, init_time);
    if (defer_recycle_scn >= current_scn) {
        return KNL_INVALID_SCN;
    }

    return MIN(min_scn, (current_scn - defer_recycle_scn));
}

bool32 bt_recycle_time_expire(knl_session_t *session, knl_scn_t interval_scn, knl_scn_t min_scn,
    knl_scn_t commit_scn)
{
    if (min_scn >= commit_scn) {
        return CT_TRUE;
    }

    if (CT_INVALID_SCN(interval_scn)) {
        return CT_FALSE;
    }

    if (DB_NOW_TO_SCN(session) >= commit_scn) {
        if (DB_NOW_TO_SCN(session) - commit_scn >= interval_scn) {
            return CT_TRUE;
        }
    }

    return CT_FALSE;
}

static inline uint16 btree_body_size(knl_session_t *session, btree_page_t *page, space_t *space)
{
    return (uint16)(DEFAULT_PAGE_SIZE(session) - sizeof(itl_t) * page->itls -
        sizeof(page_tail_t) - sizeof(btree_page_t) - space->ctrl->cipher_reserve_size);
}

#define BTREE_MIN_PAGE_USED_RATIO  0.4
static bool32 btree_is_recycled_page(knl_session_t *session, btree_page_t *page,
    knl_scn_t interval_scn, btree_recycle_desc_t *desc)
{
    txn_info_t txn_info;
    bool32 is_recyclable = CT_TRUE;
    uint16 used_size = 0;
    space_t *space = SPACE_GET(session, DATAFILE_GET(session, AS_PAGID_PTR(page->head.id)->file)->space_id);
    knl_scn_t min_scn = btree_get_recycle_min_scn(session);

    desc->is_empty = CT_TRUE;
    desc->max_del_scn = 0;
    for (uint32 i = 0; i < page->keys; i++) {
        /*
        * if key is not deleted or transaction has not committed, page cannot be recycled
        */
        btree_dir_t *dir = BTREE_GET_DIR(page, i);
        btree_key_t *key = BTREE_GET_KEY(page, dir);
        if (!key->is_deleted) {
            desc->is_empty = CT_FALSE;
            is_recyclable = CT_FALSE;
            used_size += BTREE_COST_SIZE(key);
            continue;
        }

        txn_info.xid.value = CT_INVALID_ID64;
        btree_get_txn_info(session, CT_FALSE, page, dir, key, &txn_info);
        if (txn_info.status != (uint8)XACT_END) {
            is_recyclable = CT_FALSE;
            desc->active_txn = CT_TRUE;
            desc->xid = (txn_info.xid.value == CT_INVALID_ID64) ? desc->xid : txn_info.xid;
            continue;
        }

        if (!bt_recycle_time_expire(session, interval_scn, min_scn, txn_info.scn)) {
            is_recyclable = CT_FALSE;
            desc->unexpire = CT_TRUE;
            continue;
        }
        desc->force_recycle = (min_scn >= txn_info.scn) ? desc->force_recycle : CT_TRUE;
        desc->max_del_scn = MAX(txn_info.scn, desc->max_del_scn);
    }

    for (uint8 i = 0; i < page->itls; i++) {
        itl_t *itl = BTREE_GET_ITL(page, i);
        tx_get_itl_info(session, CT_FALSE, itl, &txn_info);
        if (txn_info.status != (uint8)XACT_END) {
            is_recyclable = CT_FALSE;
            desc->active_txn = CT_TRUE;
            continue;
        }
        desc->max_del_scn = MAX(txn_info.scn, desc->max_del_scn);
    }

    if (is_recyclable) {
        return CT_TRUE;
    }

    uint16 total_size = btree_body_size(session, page, space);
    desc->is_sparse = (bool8)(!(desc->is_empty) && used_size < total_size * BTREE_MIN_PAGE_USED_RATIO);
    return CT_FALSE;
}

#define BTREE_COALESCE_CHECK_INTERVAL 100
static inline bool32 btree_coalesce_need_suspend(knl_session_t *session, dc_entry_t *entry, uint32 scan_pages)
{
    schema_lock_t *lock = entry->sch_lock;

    /* backstage coalesce should not block user's DDL */
    if (session->id == SESSION_ID_IDX_RECYCLE && scan_pages % BTREE_COALESCE_CHECK_INTERVAL == 0) {
        if (lock->mode == LOCK_MODE_IX) {
            return CT_TRUE;
        }
    }

    return db_in_switch(&session->kernel->switch_ctrl);
}

static void bt_put_recycle_stats(idx_recycle_stats_t *recycle_stats, btree_recycle_desc_t *recycle_desc)
{
    if (recycle_desc->is_empty) {
        if (recycle_desc->is_recycled) {
            recycle_stats->recycled_pages++;
            recycle_stats->force_recycled_pages += recycle_desc->force_recycle ? 1 : 0;
        } else {
            recycle_stats->unrecycled_empty_leafs++;
            recycle_stats->active_txn_pages += recycle_desc->active_txn ? 1 : 0;
            recycle_stats->parent_first_leafs += recycle_desc->is_first_child ? 1 : 0;
            recycle_stats->unexpire_pages += recycle_desc->unexpire ? 1 : 0;
            recycle_stats->xid_val = (recycle_desc->xid.value == CT_INVALID_ID64) ? recycle_stats->xid_val : recycle_desc->xid.value;
        }
    } else if (recycle_desc->is_sparse) {
        recycle_stats->sparse_pages++;
    } else {
        recycle_stats->normal_leafs++;
    }
    recycle_stats->total_leafs++;
}

static status_t btree_coalesce_by_extents(knl_session_t *session, btree_t *btree,
    btree_coalesce_assist_t *assist, idx_recycle_stats_t *stats, knl_part_locate_t part_loc)
{
    space_t *space = SPACE_GET(session, btree->segment->space_id);
    // No.0 extents can not degrade, here should calc, because the page have not been read
    uint32 extent_size = spc_get_ext_size(space, 0) - 1;
    page_type_t page_type = (btree->index->desc.cr_mode == CR_PAGE) ? PAGE_TYPE_PCRB_NODE : PAGE_TYPE_BTREE_NODE;
    uint64 disk_reads = session->stat->disk_reads;
    uint64 disk_read_time = session->stat->disk_read_time;
    uint32 extents = 1;
    uint32 total_pages = btree_get_segment_page_count(space, BTREE_SEGMENT(session, btree->entry, btree->segment));
    uint32 scan_pages = 0;

    buf_enter_page(session, btree->entry, LATCH_MODE_S, ENTER_PAGE_RESIDENT);
    page_head_t *head = (page_head_t *)CURR_PAGE(session);
    page_id_t next_ext = AS_PAGID(head->next_ext);
    uint32 extent_count = btree->segment->extents.count;
    page_id_t last_pagid = (btree->segment->ufp_count > 0) ? btree->segment->ufp_first : btree->segment->ufp_extent;
    buf_leave_page(session, CT_FALSE);

    page_id_t leaf_id = btree->segment->extents.first;
    leaf_id.page++;

    for (;;) {
        btree_recycle_desc_t desc = {
            CT_INVALID_ID64, CT_INVALID_ID64, leaf_id, CT_FALSE, CT_FALSE,
            CT_FALSE, CT_FALSE, CT_FALSE, CT_FALSE, CT_FALSE, .xid.value = CT_INVALID_ID64
                                    };

        if (IS_INVALID_PAGID(leaf_id) || IS_SAME_PAGID(last_pagid, leaf_id)) {
            break;
        }

        if (btree_coalesce_need_suspend(session, btree->index->entity->entry, scan_pages)) {
            CT_LOG_RUN_INF("coalesce index %s interrupted by table ix lock", btree->index->desc.name);
            assist->need_suspend = CT_TRUE;
            break;
        }

        if (session->killed) {
            CT_LOG_RUN_INF("coalesce index %s has been interrupted, total pages %d, recycled pages %d",
                           btree->index->desc.name, total_pages, stats->recycled_pages);
            CT_THROW_ERROR(ERR_OPERATION_KILLED);
            return CT_ERROR;
        }

        if (session->canceled) {
            CT_LOG_RUN_INF("coalesce index %s has been interrupted, total pages %d, recycled pages %d",
                           btree->index->desc.name, total_pages, stats->recycled_pages);
            CT_THROW_ERROR(ERR_OPERATION_CANCELED);
            return CT_ERROR;
        }

        buf_enter_prefetch_page(session, leaf_id, LATCH_MODE_S, ENTER_PAGE_NORMAL | ENTER_PAGE_SEQUENTIAL);
        btree_page_t *page = BTREE_CURR_PAGE(session);

        if (btree_check_segment_scn(page, page_type, btree->segment->seg_scn) != CT_SUCCESS) {
            buf_leave_page(session, CT_FALSE);
            CT_LOG_RUN_INF("cancel index %s because of segment scn changed", btree->index->desc.name);
            return CT_ERROR;
        }

        if (extent_size == 0) {
            extent_size = spc_get_page_ext_size(space, page->head.ext_size);
            next_ext = (extent_count == extents) ? INVALID_PAGID : AS_PAGID(page->head.next_ext);
            extents++;
        }

        extent_size--;

        if (page->level == 0) {
            if (page->is_recycled) {
                buf_leave_page(session, CT_FALSE);
                stats->free_pages++;
            } else if (((*assist->checker)(session, page, stats->initerval_scn, &desc))) {
                desc.snapshot_lsn = page->head.lsn;
                buf_leave_page(session, CT_FALSE);
                (*assist->recycler)(session, btree, part_loc, &desc);
            } else {
                buf_leave_page(session, CT_FALSE);
            }
            bt_put_recycle_stats(stats, &desc);
        } else {
            buf_leave_page(session, CT_FALSE);
        }

        if (extent_size == 0) {
            leaf_id = next_ext;
            if (session->id == SESSION_ID_IDX_RECYCLE && session->stat->disk_reads > disk_reads) {
                /* Modifying the system time may result in unusually large sleep_msecs, so we set
                 * sleep time <= 1000ms to avoid unusually large sleep time
                 */
                uint32 sleep_msecs = (uint32)((session->stat->disk_read_time - disk_read_time) /
                    MICROSECS_PER_MILLISEC);
                cm_sleep(MIN(sleep_msecs, MILLISECS_PER_SECOND));
                disk_reads = session->stat->disk_reads;
                disk_read_time = session->stat->disk_read_time;
                stats->total_sleep_msecs += (uint64)MIN(sleep_msecs, MILLISECS_PER_SECOND);
            }
        } else {
            leaf_id.page++;
        }

        scan_pages++;
    }

    return CT_SUCCESS;
}

static bool32 bt_coalesce_prepare(knl_session_t *session, btree_t *btree, btree_coalesce_assist_t *assist,
    idx_recycle_stats_t *recycle_stats)
{
    if (btree->index->desc.cr_mode == CR_PAGE) {
        assist->checker = pcrb_is_recycled_page;
        assist->recycler = pcrb_recycle_leaf;
    } else {
        assist->checker = btree_is_recycled_page;
        assist->recycler = btree_recycle_leaf;
    }
    assist->need_suspend = CT_FALSE;

    errno_t ret = memset_sp(recycle_stats, sizeof(idx_recycle_stats_t), 0, sizeof(idx_recycle_stats_t));
    knl_securec_check(ret);
    recycle_stats->initerval_scn = db_time_scn(session, session->kernel->attr.idx_force_recycle_time, 0);
    recycle_stats->xid_val = CT_INVALID_ID64;

    if (btree->segment->tree_info.level < BTREE_MIN_COALESCE_LEVEL) {
        btree->wait_recycle = CT_FALSE;
        recycle_stats->need_coalesce = CT_FALSE;
        CT_LOG_RUN_INF("cancel %s index coalesce, tree level too low", btree->index->desc.name);
        return CT_FALSE;
    }

    bt_upd_recycle_ver_scn(session, btree);
    return CT_TRUE;
}

status_t btree_coalesce(knl_session_t *session, btree_t *btree, idx_recycle_stats_t *stats,
    knl_part_locate_t part_loc, bool32 is_auto)
{
    space_t *space = SPACE_GET(session, btree->index->desc.space_id);
    uint32 total_pages = btree_get_segment_page_count(space, BTREE_SEGMENT(session, btree->entry, btree->segment));
    char *coa_type = is_auto ? "auto coalesce" : "coalesce";
    btree_coalesce_assist_t assist;
    bool32 wait_recycle = CT_FALSE;

    if (!bt_coalesce_prepare(session, btree, &assist, stats)) {
        return CT_SUCCESS;
    }

    int64 deleted_size = btree->chg_stats.delete_size;
    int64 insert_size = btree->chg_stats.insert_size;
    int64 alloc_pages = btree->chg_stats.alloc_pages;
    timeval_t tv_begin, tv_end;

    (void)cm_gettimeofday(&tv_begin);

    btree->is_recycling = CT_TRUE;
    status_t status = btree_coalesce_by_extents(session, btree, &assist, stats, part_loc);
    btree->is_recycling = CT_FALSE;

    bool32 finish_coalesce = (status == CT_SUCCESS && !assist.need_suspend);
    if (finish_coalesce) {
        btree->chg_stats.delete_size = btree->chg_stats.delete_size - deleted_size;
        btree->chg_stats.insert_size = btree->chg_stats.insert_size - insert_size;
        /* set alloc_pages to empty_pages we didn't recycled this time */
        btree->chg_stats.alloc_pages = btree->chg_stats.alloc_pages - alloc_pages;
        btree->chg_stats.empty_size = stats->unrecycled_empty_leafs * DEFAULT_PAGE_SIZE(session);
        btree->chg_stats.first_empty_size = stats->parent_first_leafs * DEFAULT_PAGE_SIZE(session);
    }

    if ((stats->active_txn_pages + stats->unexpire_pages) > stats->recycled_pages ||
        btree_need_recycle(session, btree, NULL)) {
        wait_recycle = is_auto ? CT_TRUE : CT_FALSE;
        stats->need_coalesce = CT_TRUE;
    } else {
        stats->need_coalesce = CT_FALSE;
    }
    char *need_coa_again = stats->need_coalesce ? "need coalesce again" : "no need coalesce again";

    bt_put_garbage_size(session, btree);
    (void)cm_gettimeofday(&tv_end);

    CT_LOG_RUN_INF("%s index %s %s, %s,part(%d, %d),level %u, total pages %u, total leafs %u,"
        "normal leafs %u, unrecycled empty leafs %u[active tx leafs %u,unexpire leafs %u,parent first leafs %u],"
        "sparse leafs %u, recycled leafs %u[force recycled leafs %u], free pages %u, time used %llu ms, "
        "sleep %llu ms, ow_del_scn %llu",
        coa_type, btree->index->desc.name, finish_coalesce ? "finished" : "interrupted",
        need_coa_again, part_loc.part_no, part_loc.subpart_no,
        btree->segment->tree_info.level, total_pages, stats->total_leafs, stats->normal_leafs,
        stats->unrecycled_empty_leafs, stats->active_txn_pages, stats->unexpire_pages,
        stats->parent_first_leafs, stats->sparse_pages, stats->recycled_pages, stats->force_recycled_pages,
        stats->free_pages, (uint64)TIMEVAL_DIFF_US(&tv_begin, &tv_end) / MICROSECS_PER_MILLISEC,
        stats->total_sleep_msecs, btree->chg_stats.ow_del_scn);

    btree->wait_recycle = wait_recycle;

    return status;
}

#ifdef LOG_DIAG
void btree_validate_page(knl_session_t *session, page_head_t *page)
{
    itl_t *itl = NULL;
    btree_dir_t *dir = NULL;
    btree_key_t *key = NULL;
    space_t *space = SPACE_GET(session, DATAFILE_GET(session, AS_PAGID_PTR(page->id)->file)->space_id);

    CM_SAVE_STACK(session->stack);
    btree_page_t *copy_page = (btree_page_t *)cm_push(session->stack, DEFAULT_PAGE_SIZE(session));
    errno_t ret = memcpy_sp(copy_page, DEFAULT_PAGE_SIZE(session), page, DEFAULT_PAGE_SIZE(session));
    knl_securec_check(ret);

    // if btree page recycled, no need to check
    if (copy_page->is_recycled) {
        CM_RESTORE_STACK(session->stack);
        return;
    }
    // check page itl
    for (uint8 j = 0; j < copy_page->itls; j++) {
        itl = BTREE_GET_ITL(copy_page, j);
        if (itl->is_active) {
            knl_panic_log(itl->scn == 0, "commit scn is abnormal, panic info: page %u-%u type %u, copy_page %u-%u "
                          "type %u", AS_PAGID(page->id).file, AS_PAGID(page->id).page, page->type,
                          AS_PAGID(copy_page->head.id).file, AS_PAGID(copy_page->head.id).page, copy_page->head.type);
            knl_panic_log(itl->xid.value != CT_INVALID_ID64, "itl xid is invalid, panic info: page %u-%u type %u, "
                          "copy_page %u-%u type %u", AS_PAGID(page->id).file, AS_PAGID(page->id).page, page->type,
                          AS_PAGID(copy_page->head.id).file, AS_PAGID(copy_page->head.id).page, copy_page->head.type);
        }
    }

    // check dir and itl
    for (uint16 i = 0; i < copy_page->keys; i++) {
        dir = BTREE_GET_DIR(copy_page, i);
        knl_panic_log(dir->offset < copy_page->free_begin, "offset in dir is more than page's free_begin, panic info: "
            "page %u-%u type %u, copy_page %u-%u type %u dir offset %u free_begin %u", AS_PAGID(page->id).file,
            AS_PAGID(page->id).page, page->type, AS_PAGID(copy_page->head.id).file, AS_PAGID(copy_page->head.id).page,
            copy_page->head.type, dir->offset, copy_page->free_begin);
        knl_panic_log(dir->offset >= sizeof(btree_page_t) + space->ctrl->cipher_reserve_size,
            "offset in dir is abnormal, panic info: page %u-%u type %u, copy_page %u-%u type %u dir offset %u "
            "cipher_reserve_size %u", AS_PAGID(page->id).file, AS_PAGID(page->id).page, page->type,
            AS_PAGID(copy_page->head.id).file, AS_PAGID(copy_page->head.id).page, copy_page->head.type, dir->offset,
            space->ctrl->cipher_reserve_size);

        uint8 itl_id = dir->itl_id;
        knl_panic_log(itl_id == CT_INVALID_ID8 || itl_id <= copy_page->itls, "itl_id is abnormal, panic info: "
            "page %u-%u type %u, copy_page %u-%u type %u itl_id %u copy_page's itls %u", AS_PAGID(page->id).file,
            AS_PAGID(page->id).page, page->type, AS_PAGID(copy_page->head.id).file, AS_PAGID(copy_page->head.id).page,
            copy_page->head.type, itl_id, copy_page->itls);
    }

    // check key size
    uint64 total_size = sizeof(btree_page_t) + space->ctrl->cipher_reserve_size;
    for (uint16 i = 0; i < copy_page->keys; i++) {
        key = (btree_key_t *)((char *)copy_page + total_size);
        knl_panic_log(key->size <= CT_MAX_KEY_SIZE - space->ctrl->cipher_reserve_size, "the key's size is abnormal, "
            "panic info: page %u-%u type %u, copy_page %u-%u type %u key size %u cipher_reserve_size %u",
            AS_PAGID(page->id).file, AS_PAGID(page->id).page, page->type, AS_PAGID(copy_page->head.id).file,
            AS_PAGID(copy_page->head.id).page, copy_page->head.type, key->size, space->ctrl->cipher_reserve_size);
        total_size += key->size;
        knl_panic_log(total_size <= copy_page->free_begin, "total_size is more than page's free_begin, panic info: "
            "page %u-%u type %u, copy_page %u-%u type %u free_begin %u total_size %llu", AS_PAGID(page->id).file,
            AS_PAGID(page->id).page, page->type, AS_PAGID(copy_page->head.id).file, AS_PAGID(copy_page->head.id).page,
            copy_page->head.type, copy_page->free_begin, total_size);
    };

    // check page size
    knl_scn_t scn = btree_get_recycle_min_scn(session);
    btree_compact_page(session, copy_page, scn);
    knl_panic_log(copy_page->free_begin + copy_page->free_size == copy_page->free_end, "copy_page's free size is "
        "abnormal, panic info: page %u-%u type %u, copy_page %u-%u type %u free_begin %u free_size %u free_end %u",
        AS_PAGID(page->id).file, AS_PAGID(page->id).page, page->type, AS_PAGID(copy_page->head.id).file,
        AS_PAGID(copy_page->head.id).page, copy_page->head.type, copy_page->free_begin, copy_page->free_size,
        copy_page->free_end);
    CM_RESTORE_STACK(session->stack);
}
#endif

status_t btree_compare_mtrl_key(mtrl_segment_t *segment, char *data1, char *data2, int32 *result)
{
    btree_t *btree = (btree_t *)segment->cmp_items;
    knl_scan_key_t scan_key;
    bool32 cmp_rowid = IS_UNIQUE_PRIMARY_INDEX(btree->index) ? CT_FALSE : CT_TRUE;

    btree_decode_key(btree->index, (btree_key_t *)data1, &scan_key);

    *result = btree_compare_key(btree->index, &scan_key, (btree_key_t *)data2, cmp_rowid, NULL);
    if (!cmp_rowid && *result == 0) {
        CT_THROW_ERROR(ERR_DUPLICATE_KEY, "");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

char *btree_get_column(knl_scan_key_t *key, ct_type_t type, uint32 id, uint16 *len, bool32 is_pcr)
{
    if (key->flags[id] == SCAN_KEY_IS_NULL) {
        *len = CT_NULL_VALUE_LEN;
        return NULL;
    }

    knl_panic(key->flags[id] == SCAN_KEY_NORMAL);

    switch (type) {
        case CT_TYPE_UINT32:
        case CT_TYPE_INTEGER:
        case CT_TYPE_BOOLEAN:
            *len = sizeof(int32);
            return (char *)key->buf + key->offsets[id];
        case CT_TYPE_UINT64:
        case CT_TYPE_BIGINT:
        case CT_TYPE_REAL:
        case CT_TYPE_DATE:
        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
        case CT_TYPE_TIMESTAMP_LTZ:
        case CT_TYPE_DATETIME_MYSQL:
        case CT_TYPE_TIME_MYSQL:
        case CT_TYPE_DATE_MYSQL:
            *len = sizeof(int64);
            return (char *)key->buf + key->offsets[id];

        case CT_TYPE_TIMESTAMP_TZ:
            *len = sizeof(timestamp_tz_t);
            return (char *)key->buf + key->offsets[id];

        case CT_TYPE_INTERVAL_YM:
            *len = sizeof(interval_ym_t);
            return (char *)key->buf + key->offsets[id];

        case CT_TYPE_INTERVAL_DS:
            *len = sizeof(interval_ds_t);
            return (char *)key->buf + key->offsets[id];

        case CT_TYPE_NUMBER2:
            if (is_pcr) {
                *len = DECIMAL2_LEN(((char *)key->buf + key->offsets[id]));
                return (char *)key->buf + key->offsets[id];
            }
            *len = *(uint16 *)((char *)key->buf + key->offsets[id]);
            return (char *)key->buf + key->offsets[id] + sizeof(uint16);

        case CT_TYPE_NUMBER:
        case CT_TYPE_NUMBER3:
        case CT_TYPE_DECIMAL:
            if (is_pcr) {
                *len = DECIMAL_LEN(((char *)key->buf + key->offsets[id]));
                return (char *)key->buf + key->offsets[id];
            }
            // fall-through
        default:
            *len = *(uint16 *)((char *)key->buf + key->offsets[id]);
            return (char *)key->buf + key->offsets[id] + sizeof(uint16);
    }
}

uint16 btree_max_column_size(ct_type_t type, uint16 size, bool32 is_pcr)
{
    switch (type) {
        case CT_TYPE_UINT32:
        case CT_TYPE_INTEGER:
            return sizeof(int32);

        case CT_TYPE_BOOLEAN:
            return sizeof(bool32);

        case CT_TYPE_UINT64:
        case CT_TYPE_BIGINT:
            return sizeof(int64);

        case CT_TYPE_DATE:
        case CT_TYPE_DATETIME_MYSQL:
        case CT_TYPE_TIME_MYSQL:
        case CT_TYPE_DATE_MYSQL:
            return sizeof(date_t);

        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_LTZ:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
            return sizeof(timestamp_t);

        case CT_TYPE_TIMESTAMP_TZ:
            return sizeof(timestamp_tz_t);

        case CT_TYPE_REAL:
            return sizeof(double);

        case CT_TYPE_INTERVAL_YM:
            return sizeof(interval_ym_t);

        case CT_TYPE_INTERVAL_DS:
            return sizeof(interval_ds_t);

        case CT_TYPE_NUMBER:
        case CT_TYPE_DECIMAL:
        case CT_TYPE_NUMBER2:
        case CT_TYPE_NUMBER3:
            if (is_pcr) {
                return (uint16)CM_ALIGN4(size);
            }
            // fall-through
        default:
            return CM_ALIGN4(sizeof(uint16) + size);
    }
}

void btree_get_txn_info(knl_session_t *session, bool32 is_scan, btree_page_t *page, btree_dir_t *dir,
    btree_key_t *key, txn_info_t *txn_info)
{
    itl_t *itl = NULL;

    if (dir->itl_id == CT_INVALID_ID8) {
        txn_info->status = (uint8)XACT_END;
        txn_info->scn = key->scn;
        txn_info->is_owscn = (bool8)key->is_owscn;
    } else {
        knl_panic_log(dir->itl_id < page->itls, "dir's itl id is more than page's itls, panic info: page %u-%u "
                      "type %u itl id %u itls %u", AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page,
                      page->head.type, dir->itl_id, page->itls);
        itl = BTREE_GET_ITL(page, dir->itl_id);

        tx_get_itl_info(session, is_scan, itl, txn_info);
    }
}

void btree_close_mtrl_cursor(btree_mt_context_t *ctx, mtrl_sort_cursor_t *cur1,
    mtrl_sort_cursor_t *cur2, mtrl_cursor_t *cursor)
{
    if (ctx->is_parallel) {
        mtrl_close_sort_cursor(&ctx->mtrl_ctx, cur1);
        mtrl_close_sort_cursor(&ctx->mtrl_ctx_paral, cur2);
    }
}

status_t btree_open_mtrl_cursor(btree_mt_context_t *ctx, mtrl_sort_cursor_t *cur1,
    mtrl_sort_cursor_t *cur2, mtrl_cursor_t *cursor)
{
    if (!ctx->is_parallel) {
        return mtrl_open_cursor(&ctx->mtrl_ctx, ctx->seg_id, cursor);
    }

    mtrl_segment_t *seg1 = ctx->mtrl_ctx.segments[0];
    mtrl_segment_t *seg2 = ctx->mtrl_ctx_paral.segments[0];
    mtrl_rowid_t rid1 = { 0, 0 };
    mtrl_rowid_t rid2 = { 0, 0 };

    rid1.vmid = seg1->vm_list.first;
    rid2.vmid = seg2->vm_list.first;

    if (mtrl_init_cursor(cursor) != CT_SUCCESS) {
        return CT_ERROR;
    }
    cursor->result_cur = NULL;
    if (mtrl_open_sort_cursor(&ctx->mtrl_ctx, seg1, &rid1, seg1->level, cur1) != CT_SUCCESS) {
        return CT_ERROR;
    }

    cur1->ctx = &ctx->mtrl_ctx;
    if (mtrl_open_sort_cursor(&ctx->mtrl_ctx_paral, seg2, &rid2, seg2->level, cur2) != CT_SUCCESS) {
        mtrl_close_sort_cursor(&ctx->mtrl_ctx, cur1);
        return CT_ERROR;
    }
    cur2->ctx = &ctx->mtrl_ctx_paral;
    ctx->rows = 0;
    return CT_SUCCESS;
}

status_t btree_fetch_mtrl_sort_key(btree_mt_context_t *ctx, mtrl_sort_cursor_t *cur1,
    mtrl_sort_cursor_t *cur2, mtrl_cursor_t *cursor)
{
    if (!ctx->is_parallel) {
        return mtrl_fetch_sort_key(&ctx->mtrl_ctx, cursor);
    }

    mtrl_sort_cursor_t *result_sort_cur = cursor->result_cur;
    
    if (ctx->rows == cur1->part.rows + cur2->part.rows) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    if (ctx->rows > 0) {
        if (mtrl_move_sort_cursor(result_sort_cur->ctx, result_sort_cur, mtrl_close_sorted_page) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (mtrl_merge_compare(&ctx->mtrl_ctx, ctx->mtrl_ctx.segments[0], cur1, cur2, &result_sort_cur) != CT_SUCCESS) {
        return CT_ERROR;
    }

    result_sort_cur->rownum++;
    ctx->rows++;
    cursor->sort = *result_sort_cur;
    cursor->result_cur = result_sort_cur;
    return CT_SUCCESS;
}
