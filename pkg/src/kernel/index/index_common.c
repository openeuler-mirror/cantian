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
 * index_common.c
 *
 *
 * IDENTIFICATION
 * src/kernel/index/index_common.c
 *
 * -------------------------------------------------------------------------
 */

#include "index_common.h"
#include "rcr_btree.h"
#include "pcr_btree.h"
#include "cm_utils.h"
#include "knl_dc.h"
#include "knl_context.h"
#include "knl_table.h"
#include "temp_btree.h"
#include "knl_space_manage.h"
#include "dtc_dc.h"
#include "dtc_dls.h"
#include "dtc_recovery.h"
#include "dtc_context.h"

void btree_area_init(knl_session_t *session)
{
    index_cache_ctx_t *cache_ctx = &session->kernel->index_ctx.cache_ctx;
    index_recycle_ctx_t *recycle_ctx = &session->kernel->index_ctx.recycle_ctx;
    index_recycle_item_t *item = NULL;
    uint32 id;

    cache_ctx->lock = 0;
    cache_ctx->capacity = (uint32)(session->kernel->attr.index_buf_size / BTREE_ROOT_COPY_SIZE(session));
    cache_ctx->hwm = 0;
    cache_ctx->free_items.count = 0;
    cache_ctx->free_items.first = GS_INVALID_ID32;
    cache_ctx->free_items.last = GS_INVALID_ID32;
    cache_ctx->expired_items.count = 0;
    cache_ctx->expired_items.first = GS_INVALID_ID32;
    cache_ctx->expired_items.last = GS_INVALID_ID32;
    cache_ctx->items = (index_page_item_t *)session->kernel->attr.index_buf;

    recycle_ctx->lock = 0;
    recycle_ctx->idx_list.count = 0;
    recycle_ctx->idx_list.first = GS_INVALID_ID32;
    recycle_ctx->idx_list.last = GS_INVALID_ID32;

    for (id = 0; id < GS_MAX_RECYCLE_INDEXES; id++) {
        item = &recycle_ctx->items[id];
        item->index_id = GS_INVALID_ID32;
        item->next = (id == (GS_MAX_RECYCLE_INDEXES - 1)) ? GS_INVALID_ID32 : (id + 1);
        item->scn = 0;
    }

    recycle_ctx->free_list.count = GS_MAX_RECYCLE_INDEXES;
    recycle_ctx->free_list.first = 0;
    recycle_ctx->free_list.last = GS_MAX_RECYCLE_INDEXES - 1;
}

void btree_release_root_copy(knl_session_t *session)
{
    index_cache_ctx_t *ctx = &session->kernel->index_ctx.cache_ctx;
    index_page_item_t *prev_item = NULL;
    index_page_item_t *item = NULL;
    knl_session_t *se = NULL;
    uint32 i, id;
    id_list_t expired_items;
    id_list_t release_items;
    id_list_t new_expired_items;
    bool32 is_used = GS_FALSE;
    int32 ret;

    cm_spin_lock(&ctx->lock, NULL);
    ret = memcpy_sp(&expired_items, sizeof(id_list_t), &ctx->expired_items, sizeof(id_list_t));
    knl_securec_check(ret);
    cm_spin_unlock(&ctx->lock);

    if (expired_items.count <= 1) {
        return;
    }

    release_items.count = 0;
    new_expired_items.count = 0;
    new_expired_items.first = new_expired_items.last = GS_INVALID_ID32;
    knl_panic(expired_items.first != GS_INVALID_ID32);

    id = expired_items.first;
    while (id != expired_items.last) {
        item = BTREE_GET_ITEM(session, ctx, id);
        is_used = GS_FALSE;

        for (i = GS_SYS_SESSIONS; i < GS_MAX_SESSIONS; i++) {
            se = session->kernel->sessions[i];
            if (se == NULL) {
                continue;
            }

            if (se->status == SESSION_INACTIVE) {
                continue;
            }

            if (se->index_root == (char *)item) {
                is_used = GS_TRUE;
                break;
            }
        }

        if (is_used) {
            if (new_expired_items.count == 0) {
                new_expired_items.first = id;
            } else {
                prev_item = BTREE_GET_ITEM(session, ctx, new_expired_items.last);
                prev_item->next = id;
            }

            new_expired_items.last = id;
            new_expired_items.count++;
            id = item->next;
            continue;
        }

        if (release_items.count == 0) {
            release_items.first = id;
        } else {
            prev_item = BTREE_GET_ITEM(session, ctx, release_items.last);
            prev_item->next = id;
        }

        release_items.last = id;
        release_items.count++;
        id = item->next;
    }

    if (release_items.count == 0) {
        return;
    }

    cm_spin_lock(&ctx->lock, NULL);
    if (ctx->free_items.count == 0) {
        ctx->free_items.first = release_items.first;
    } else {
        prev_item = BTREE_GET_ITEM(session, ctx, ctx->free_items.last);
        prev_item->next = release_items.first;
    }
    ctx->free_items.count += release_items.count;
    ctx->free_items.last = release_items.last;

    if (new_expired_items.count == 0) {
        ctx->expired_items.first = expired_items.last;
    } else {
        ctx->expired_items.first = new_expired_items.first;
        item = BTREE_GET_ITEM(session, ctx, new_expired_items.last);
        item->next = expired_items.last;
    }
    ctx->expired_items.count -= release_items.count;

    cm_spin_unlock(&ctx->lock);
}

void btree_copy_root_page_base(knl_session_t *session, btree_t *btree, btree_page_t *root, knl_scn_t recycle_ver_scn)
{
    index_cache_ctx_t *ctx = &session->kernel->index_ctx.cache_ctx;
    index_page_item_t *item = NULL;
    index_page_item_t *prev = NULL;
    uint32 id;
    uint32 old_id;

    cm_spin_lock(&ctx->lock, NULL);

    if (ctx->hwm < ctx->capacity) {
        id = ctx->hwm++;
        item = BTREE_GET_ITEM(session, ctx, id);
    } else {
        if (ctx->free_items.count == 0) {
            cm_spin_unlock(&ctx->lock);
            btree->root_copy = NULL;
            return;
        }

        id = ctx->free_items.first;
        item = BTREE_GET_ITEM(session, ctx, id);
        ctx->free_items.count--;
        if (ctx->free_items.count == 0) {
            ctx->free_items.first = GS_INVALID_ID32;
            ctx->free_items.last = GS_INVALID_ID32;
        } else {
            knl_panic_log(item->next != GS_INVALID_ID32,
                          "the next page is invalid, panic info: index %s", ((index_t *)btree->index)->desc.name);
            ctx->free_items.first = item->next;
        }
    }

    if (btree->root_copy != NULL) {
        index_page_item_t *old_item = (index_page_item_t *)btree->root_copy;
        old_id = (uint32)(((char *)old_item - (char *)ctx->items) / BTREE_ROOT_COPY_SIZE(session));
        old_item->next = GS_INVALID_ID32;
        if (ctx->expired_items.count == 0) {
            ctx->expired_items.first = old_id;
            ctx->expired_items.last = old_id;
        } else {
            prev = (index_page_item_t *)((char *)ctx->items + ctx->expired_items.last *
                BTREE_ROOT_COPY_SIZE(session));
            prev->next = old_id;
            ctx->expired_items.last = old_id;
        }
        ctx->expired_items.count++;
    }

    cm_spin_unlock(&ctx->lock);

    int32 ret = memcpy_sp(item->page, DEFAULT_PAGE_SIZE(session), root, (size_t)PAGE_SIZE(root->head));
    knl_securec_check(ret);
    item->cache_scn = recycle_ver_scn;
    item->is_invalid = GS_FALSE;
    btree->root_copy = (volatile char *)item;
}

void btree_copy_root_page(knl_session_t *session, btree_t *btree, btree_page_t *root)
{
    btree_segment_t *seg = BTREE_SEGMENT(session, btree->entry, btree->segment);
    btree_copy_root_page_base(session, btree, root, KNL_GET_SCN(&seg->recycle_ver_scn));
}

bool32 btree_get_index_shadow(knl_session_t *session, knl_cursor_t *cursor, knl_handle_t shadow_handle)
{
    shadow_index_t *shadow_entity = (shadow_index_t *)shadow_handle;
    index_t *shadow_index = NULL;
    index_part_t *shadow_idx_part = NULL;

    if (!shadow_entity->is_valid) {
        return GS_FALSE;
    }

    if (shadow_entity->part_loc.part_no != GS_INVALID_ID32) {
        if (shadow_entity->part_loc.part_no != cursor->part_loc.part_no ||
            shadow_entity->part_loc.subpart_no != cursor->part_loc.subpart_no) {
            return GS_FALSE;
        }

        shadow_index = SHADOW_INDEX_ENTITY(shadow_entity);
        shadow_idx_part = &shadow_entity->index_part;
    } else {
        shadow_index = &shadow_entity->index;
        if (IS_PART_INDEX(shadow_index)) {
            shadow_idx_part = INDEX_GET_PART(shadow_index, cursor->part_loc.part_no);
            if (IS_PARENT_IDXPART(&shadow_idx_part->desc)) {
                uint32 subpart_no = cursor->part_loc.subpart_no;
                shadow_idx_part = PART_GET_SUBENTITY(shadow_index->part_index, shadow_idx_part->subparts[subpart_no]);
            }
        }
    }

    /* we only replace current index by its shadow index */
    if (shadow_index->desc.id != ((index_t *)cursor->index)->desc.id) {
        return GS_FALSE;
    }

    cursor->index = shadow_index;
    cursor->index_part = shadow_idx_part;

    return GS_TRUE;
}

void btree_decode_key_column(knl_scan_key_t *scan_key, uint16 *bitmap, uint16 *offset, gs_type_t type, uint32 id,
    bool32 is_pcr)
{
    if (!btree_get_bitmap(bitmap, id)) {
        scan_key->flags[id] = SCAN_KEY_IS_NULL;
        return;
    }

    scan_key->flags[id] = SCAN_KEY_NORMAL;

    switch (type) {
        case GS_TYPE_UINT32:
        case GS_TYPE_INTEGER:
        case GS_TYPE_BOOLEAN:
            scan_key->offsets[id] = *offset;
            *offset += sizeof(uint32);
            break;
        case GS_TYPE_UINT64:
        case GS_TYPE_BIGINT:
        case GS_TYPE_REAL:
        case GS_TYPE_DATE:
        case GS_TYPE_TIMESTAMP:
        case GS_TYPE_TIMESTAMP_TZ_FAKE:
        case GS_TYPE_TIMESTAMP_LTZ:
            scan_key->offsets[id] = *offset;
            *offset += sizeof(int64);
            break;
        case GS_TYPE_TIMESTAMP_TZ:
            scan_key->offsets[id] = *offset;
            *offset += sizeof(timestamp_tz_t);
            break;
        case GS_TYPE_INTERVAL_DS:
            scan_key->offsets[id] = *offset;
            *offset += sizeof(interval_ds_t);
            break;
        case GS_TYPE_INTERVAL_YM:
            scan_key->offsets[id] = *offset;
            *offset += sizeof(interval_ym_t);
            break;
        case GS_TYPE_NUMBER2:
            scan_key->offsets[id] = *offset;
            *offset += *(uint8 *)(scan_key->buf + *offset) + sizeof(uint8);
            break;
        case GS_TYPE_NUMBER:
        case GS_TYPE_NUMBER3:
        case GS_TYPE_DECIMAL:
            if (is_pcr) {
                scan_key->offsets[id] = *offset;
                *offset += DECIMAL_FORMAT_LEN((char *)scan_key->buf + *offset);
                break;
            }

        // fall-through
        case GS_TYPE_CHAR:
        case GS_TYPE_VARCHAR:
        case GS_TYPE_STRING:
        case GS_TYPE_BINARY:
        case GS_TYPE_VARBINARY:
        case GS_TYPE_RAW:
            scan_key->offsets[id] = *offset;
            *offset += CM_ALIGN4(*(uint16 *)(scan_key->buf + *offset) + sizeof(uint16));
            break;
        default:
            knl_panic(0);
    }
}

uint16 btree_max_key_size(index_t *index)
{
    dc_entity_t *entity = index->entity;
    knl_column_t *column = NULL;
    bool32 is_pcr = (index->desc.cr_mode == CR_PAGE);
    uint16 max_size = is_pcr ? (sizeof(pcrb_key_t) + sizeof(pcrb_dir_t)) :
        (sizeof(btree_key_t) + sizeof(btree_dir_t));
    uint32 id;

    for (id = 0; id < index->desc.column_count; id++) {
        column = dc_get_column(entity, index->desc.columns[id]);
        max_size += btree_max_column_size(column->datatype, column->size, is_pcr);
    }

    return max_size;
}

#define BTREE_PARENT_MINIMUM_KEYS 2
uint16 btree_max_allowed_size(knl_session_t *session, knl_index_desc_t *index_desc)
{
    bool32 is_pcr = (index_desc->cr_mode == CR_PAGE);
    size_t itl_size;
    uint32 initrans = index_desc->initrans;
    uint16 leaf_key_size;
    uint16 parent_key_size;
    space_t *space = SPACE_GET(session, index_desc->space_id);
    uint8 cipher_reserve_size = space->ctrl->cipher_reserve_size;

    if (is_pcr) {
        itl_size = (initrans == 0) ? sizeof(pcr_itl_t) : sizeof(pcr_itl_t) * initrans;
    } else {
        itl_size = (initrans == 0) ? sizeof(itl_t) : sizeof(itl_t) * initrans;
    }

    leaf_key_size = (uint16)((session->kernel->attr.page_size - sizeof(btree_page_t) - cipher_reserve_size -
        sizeof(page_tail_t) - itl_size));
    parent_key_size = (uint16)((session->kernel->attr.page_size - sizeof(btree_page_t) - cipher_reserve_size -
        sizeof(page_tail_t)) / BTREE_PARENT_MINIMUM_KEYS); // parent node has at least two keys
    leaf_key_size = MIN(leaf_key_size, GS_MAX_KEY_SIZE - cipher_reserve_size);
    parent_key_size = MIN(parent_key_size, GS_MAX_KEY_SIZE - cipher_reserve_size);

    return MIN(leaf_key_size, parent_key_size);
}

status_t btree_constructor_init(knl_session_t *session, btree_mt_context_t *ctx, btree_t *btree)
{
    mtrl_segment_type_t type;
    bool32 nologging = ctx->nologging;
    errno_t err = memset_sp(ctx, sizeof(btree_mt_context_t), 0, sizeof(btree_mt_context_t));
    knl_securec_check(err);
    session->thread_shared = GS_FALSE;
    mtrl_init_context(&ctx->mtrl_ctx, session);
    if (btree->index->desc.cr_mode == CR_PAGE) {
        type = MTRL_SEGMENT_PCR_BTREE;
        ctx->mtrl_ctx.sort_cmp = pcrb_compare_mtrl_key;
    } else {
        type = MTRL_SEGMENT_RCR_BTREE;
        ctx->mtrl_ctx.sort_cmp = btree_compare_mtrl_key;
    }

    if (GS_SUCCESS != mtrl_create_segment(&ctx->mtrl_ctx, type, (handle_t)btree, &ctx->seg_id)) {
        mtrl_release_context(&ctx->mtrl_ctx);
        return GS_ERROR;
    }

    if (GS_SUCCESS != mtrl_open_segment(&ctx->mtrl_ctx, ctx->seg_id)) {
        mtrl_release_context(&ctx->mtrl_ctx);
        return GS_ERROR;
    }

    ctx->nologging = nologging;
    ctx->initialized = GS_TRUE;
    return GS_SUCCESS;
}

static void btree_insert_minimum_key(knl_session_t *session)
{
    btree_page_t *page;
    page_id_t page_id;
    btree_key_t *key = NULL;
    btree_dir_t *dir = NULL;

    page = BTREE_CURR_PAGE(session);
    if (page->head.type == PAGE_TYPE_PCRB_NODE) {
        pcrb_insert_minimum_key(session);
        return;
    }

    page_id = AS_PAGID(page->head.id);
    space_t *space = SPACE_GET(session, DATAFILE_GET(session, page_id.file)->space_id);
    bool32 need_encrypt = SPACE_IS_ENCRYPT(space);
    key = (btree_key_t *)((char *)page + page->free_begin);
    dir = BTREE_GET_DIR(page, 0);

    btree_init_key(key, NULL);
    key->is_infinite = GS_TRUE;
    key->undo_page = INVALID_UNDO_PAGID;
    key->scn = DB_CURR_SCN(session);

    dir->offset = page->free_begin;
    dir->itl_id = GS_INVALID_ID8;
    dir->unused = 0;
    page->free_begin += (uint16)key->size;
    page->free_end -= sizeof(btree_dir_t);
    page->free_size -= ((uint16)key->size + sizeof(btree_dir_t));
    page->keys++;

    rd_btree_insert_t redo;
    redo.slot = 0;
    redo.is_reuse = GS_FALSE;
    redo.itl_id = dir->itl_id;
    if (SPC_IS_LOGGING_BY_PAGEID(session, page_id)) {
        log_encrypt_prepare(session, page->head.type, need_encrypt);
        log_put(session, RD_BTREE_INSERT, &redo, sizeof(rd_btree_insert_t), LOG_ENTRY_FLAG_NONE);
        log_append_data(session, key, (uint32)key->size);
    }
}

static inline void btree_try_reset_segment_pagecount(space_t *space, btree_segment_t *segment,
    uint32 origin_page_count)
{
    if (!SPACE_IS_AUTOALLOCATE(space)) {
        return;
    }

    // 0 or 1 means it is firstly init or truncate without reuse,
    // so, whether degrade happened or not, it will be reset.
    if (segment->extents.count <= 1) {
        segment->page_count = 0;
        return;
    }
    segment->page_count = origin_page_count;
}

static void btree_init_segment(knl_session_t *session, knl_index_desc_t *desc, page_list_t *extents,
    page_id_t ufp_extent)
{
    space_t *space = SPACE_GET(session, desc->space_id);
    knl_tree_info_t *tree_info = NULL;
    page_id_t page_id;
    rd_btree_init_entry_t redo;
    uint32 extent_size = space->ctrl->extent_size;

    btree_segment_t *segment = BTREE_GET_SEGMENT(session);
    // used by update page count
    uint32 origin_page_count = segment->page_count;

    page_head_t *page = (page_head_t *)CURR_PAGE(session);
    page_init(session, page, desc->entry, PAGE_TYPE_BTREE_HEAD);
    TO_PAGID_DATA(ufp_extent, page->next_ext);
    page->ext_size = spc_ext_id_by_size(extent_size);
    if (SPACE_IS_LOGGING(space)) {
        redo.page_id = desc->entry;
        redo.extent_size = extent_size;
        log_put(session, RD_BTREE_INIT_ENTRY, &redo, sizeof(rd_btree_init_entry_t), LOG_ENTRY_FLAG_NONE);
        log_put(session, RD_SPC_CONCAT_EXTENT, &ufp_extent, sizeof(page_head_t), LOG_ENTRY_FLAG_NONE);
    }

    segment->uid = (uint16)desc->uid;
    segment->table_id = desc->table_id;
    segment->index_id = (uint16)desc->id;
    segment->space_id = (uint16)desc->space_id;
    segment->initrans = (uint8)desc->initrans;
    segment->org_scn = desc->org_scn;
    segment->seg_scn = db_inc_scn(session);
    segment->pctfree = desc->pctfree;
    segment->cr_mode = desc->cr_mode;
    knl_panic_log(desc->cr_mode == CR_PAGE || desc->cr_mode == CR_ROW,
                  "cr_mode is abnormal, panic info: index_part %s", desc->name);

    page_id = desc->entry;
    page_id.page++;

    tree_info = &segment->tree_info;
    TO_PAGID_DATA(page_id, tree_info->root);
    tree_info->level = 1;

    segment->extents = *extents;
    segment->ufp_first = page_id;
    segment->ufp_first.page++;
    /* btree use 2 pages, one is for entry, one is for minimum key */
    segment->ufp_count = extent_size - 2;
    segment->ufp_extent = ufp_extent;

    btree_try_reset_segment_pagecount(space, segment, origin_page_count);

    if (SPACE_IS_LOGGING(space)) {
        log_put(session, RD_BTREE_INIT_SEG, segment, sizeof(btree_segment_t), LOG_ENTRY_FLAG_NONE);
    }
}

void btree_init_part_segment(knl_session_t *session, knl_index_part_desc_t *desc, page_list_t *extents,
    page_id_t ufp_extent)
{
    knl_tree_info_t *tree_info = NULL;
    space_t *space = SPACE_GET(session, desc->space_id);
    page_id_t page_id;
    uint32 extent_size;
    rd_btree_init_entry_t redo;
    extent_size = space->ctrl->extent_size;

    btree_segment_t *segment = BTREE_GET_SEGMENT(session);
    // used by update page count
    uint32 origin_page_count = segment->page_count;

    page_head_t *page = (page_head_t *)CURR_PAGE(session);
    page_init(session, page, desc->entry, PAGE_TYPE_BTREE_HEAD);
    TO_PAGID_DATA(ufp_extent, page->next_ext);
    page->ext_size = spc_ext_id_by_size(extent_size);

    if (SPACE_IS_LOGGING(space)) {
        redo.page_id = desc->entry;
        redo.extent_size = extent_size;
        log_put(session, RD_BTREE_INIT_ENTRY, &redo, sizeof(rd_btree_init_entry_t), LOG_ENTRY_FLAG_NONE);
        log_put(session, RD_SPC_CONCAT_EXTENT, &ufp_extent, sizeof(page_head_t), LOG_ENTRY_FLAG_NONE);
    }

    segment->uid = (uint16)desc->uid;  // uid is less than 65536(2^16)
    segment->table_id = desc->table_id;
    segment->index_id = (uint16)desc->index_id;  // index_id is less than 65536(2^16)
    segment->space_id = (uint16)desc->space_id;  // space_id is less than 65536(2^16)
    segment->initrans = (uint8)desc->initrans;   // initrans is less than 65536(2^16)
    segment->org_scn = desc->org_scn;
    segment->seg_scn = db_inc_scn(session);
    segment->pctfree = desc->pctfree;
    segment->cr_mode = desc->cr_mode;
    knl_panic_log(desc->cr_mode == CR_PAGE || desc->cr_mode == CR_ROW,
                  "cr_mode is abnormal, panic info: index_part %s", desc->name);

    page_id = desc->entry;
    page_id.page++;

    tree_info = &segment->tree_info;
    TO_PAGID_DATA(page_id, tree_info->root);
    tree_info->level = 1;

    segment->extents = *extents;
    segment->ufp_first = page_id;
    segment->ufp_first.page++;
    /* btree use 2 pages, one is for entry, one is for minimum key */
    segment->ufp_count = extent_size - 2;
    segment->ufp_extent = ufp_extent;

    btree_try_reset_segment_pagecount(space, segment, origin_page_count);

    if (SPACE_IS_LOGGING(space)) {
        log_put(session, RD_BTREE_INIT_SEG, segment, sizeof(btree_segment_t), LOG_ENTRY_FLAG_NONE);
    }
}


void btree_drop_segment(knl_session_t *session, index_t *index)
{
    space_t *space;
    btree_segment_t *segment = NULL;
    page_list_t extents;
    page_head_t *head = NULL;
    buf_ctrl_t *ctrl = NULL;

    space = SPACE_GET(session, index->desc.space_id);
    if (!SPACE_IS_ONLINE(space) || !space->ctrl->used) {
        return;
    }

    if (IS_INVALID_PAGID(index->desc.entry)) {
        return;
    }

    log_atomic_op_begin(session);

    buf_enter_page(session, index->desc.entry, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    head = (page_head_t *)CURR_PAGE(session);
    segment = BTREE_GET_SEGMENT(session);
    index->desc.entry = INVALID_PAGID;
    index->btree.segment = NULL;
    index->btree.chg_stats.ow_del_scn = 0;

    if (head->type != PAGE_TYPE_BTREE_HEAD || segment->org_scn != index->desc.org_scn) {
        // btree segment has been released
        buf_leave_page(session, GS_FALSE);
        log_atomic_op_end(session);
        return;
    }

    ctrl = session->curr_page_ctrl;
    extents = segment->extents;

    page_free(session, head);
    if (SPACE_IS_LOGGING(space)) {
        log_put(session, RD_SPC_FREE_PAGE, NULL, 0, LOG_ENTRY_FLAG_NONE);
    }

    buf_leave_page(session, GS_TRUE);

    buf_unreside(session, ctrl);

    spc_free_extents(session, space, &extents);
    spc_drop_segment(session, space);

    log_atomic_op_end(session);
}

void btree_drop_garbage_segment(knl_session_t *session, knl_seg_desc_t *seg)
{
    space_t *space = NULL;
    btree_segment_t *segment = NULL;
    page_list_t extents;
    page_head_t *head = NULL;
    buf_ctrl_t *ctrl = NULL;

    if (!db_valid_seg_tablespace(session, seg->space_id, seg->entry)) {
        return;
    }

    space = SPACE_GET(session, seg->space_id);
    log_atomic_op_begin(session);

    buf_enter_page(session, seg->entry, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    head = (page_head_t *)CURR_PAGE(session);
    segment = BTREE_GET_SEGMENT(session);
    if (head->type != PAGE_TYPE_BTREE_HEAD || segment->seg_scn != seg->seg_scn) {
        // btree segment has been released
        buf_leave_page(session, GS_FALSE);
        log_atomic_op_end(session);
        return;
    }

    ctrl = session->curr_page_ctrl;
    extents = segment->extents;

    page_free(session, head);
    if (SPACE_IS_LOGGING(space)) {
        log_put(session, RD_SPC_FREE_PAGE, NULL, 0, LOG_ENTRY_FLAG_NONE);
    }

    buf_leave_page(session, GS_TRUE);

    buf_unreside(session, ctrl);

    spc_free_extents(session, space, &extents);
    spc_drop_segment(session, space);

    log_atomic_op_end(session);
}

void btree_drop_part_segment(knl_session_t *session, index_part_t *index_part)
{
    space_t *space;
    btree_segment_t *segment = NULL;
    page_list_t extents;
    page_head_t *head = NULL;
    buf_ctrl_t *ctrl = NULL;

    space = SPACE_GET(session, index_part->desc.space_id);
    if (!SPACE_IS_ONLINE(space) || !space->ctrl->used) {
        return;
    }

    if (IS_INVALID_PAGID(index_part->desc.entry)) {
        return;
    }

    log_atomic_op_begin(session);

    buf_enter_page(session, index_part->desc.entry, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    head = (page_head_t *)CURR_PAGE(session);
    segment = BTREE_GET_SEGMENT(session);
    index_part->desc.entry = INVALID_PAGID;
    index_part->btree.segment = NULL;
    index_part->btree.chg_stats.ow_del_scn = 0;

    if (head->type != PAGE_TYPE_BTREE_HEAD || segment->org_scn != index_part->desc.org_scn) {
        // btree segment has been released
        buf_leave_page(session, GS_FALSE);
        log_atomic_op_end(session);
        return;
    }

    ctrl = session->curr_page_ctrl;
    extents = segment->extents;

    page_free(session, head);
    if (SPACE_IS_LOGGING(space)) {
        log_put(session, RD_SPC_FREE_PAGE, NULL, 0, LOG_ENTRY_FLAG_NONE);
    }

    buf_leave_page(session, GS_TRUE);

    buf_unreside(session, ctrl);

    spc_free_extents(session, space, &extents);
    spc_drop_segment(session, space);

    log_atomic_op_end(session);
}

void btree_drop_part_garbage_segment(knl_session_t *session, knl_seg_desc_t *seg)
{
    space_t *space = NULL;
    btree_segment_t *segment = NULL;
    page_list_t extents;
    page_head_t *head = NULL;
    buf_ctrl_t *ctrl = NULL;

    if (!db_valid_seg_tablespace(session, seg->space_id, seg->entry)) {
        return;
    }

    space = SPACE_GET(session, seg->space_id);
    log_atomic_op_begin(session);

    buf_enter_page(session, seg->entry, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    head = (page_head_t *)CURR_PAGE(session);
    segment = BTREE_GET_SEGMENT(session);
    if (head->type != PAGE_TYPE_BTREE_HEAD || segment->seg_scn != seg->seg_scn) {
        // btree segment has been released
        buf_leave_page(session, GS_FALSE);
        log_atomic_op_end(session);
        return;
    }

    ctrl = session->curr_page_ctrl;
    extents = segment->extents;

    page_free(session, head);
    if (SPACE_IS_LOGGING(space)) {
        log_put(session, RD_SPC_FREE_PAGE, NULL, 0, LOG_ENTRY_FLAG_NONE);
    }

    buf_leave_page(session, GS_TRUE);

    buf_unreside(session, ctrl);

    spc_free_extents(session, space, &extents);
    spc_drop_segment(session, space);

    log_atomic_op_end(session);
}

status_t btree_purge_prepare(knl_session_t *session, knl_rb_desc_t *desc)
{
    space_t *space = SPACE_GET(session, desc->space_id);
    if (!SPACE_IS_ONLINE(space) || !space->ctrl->used) {
        return GS_SUCCESS;
    }

    if (IS_INVALID_PAGID(desc->entry)) {
        return GS_SUCCESS;
    }

    buf_enter_page(session, desc->entry, LATCH_MODE_S, ENTER_PAGE_NORMAL);
    btree_segment_t *segment = BTREE_GET_SEGMENT(session);
    knl_seg_desc_t seg;
    seg.uid = segment->uid;
    seg.oid = segment->table_id;
    seg.index_id = GS_INVALID_ID32;
    seg.column_id = GS_INVALID_ID32;
    seg.space_id = segment->space_id;
    seg.entry = desc->entry;
    seg.org_scn = segment->org_scn;
    seg.seg_scn = segment->seg_scn;
    seg.initrans = segment->initrans;
    seg.pctfree = 0;
    seg.op_type = BTREE_PURGE_SEGMENT;
    seg.reuse = GS_FALSE;
    seg.serial = 0;
    buf_leave_page(session, GS_FALSE);

    if (db_write_garbage_segment(session, &seg) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

void btree_purge_segment(knl_session_t *session, knl_seg_desc_t *desc)
{
    btree_segment_t *segment = NULL;
    page_list_t extents;
    page_head_t *head = NULL;

    if (!db_valid_seg_tablespace(session, desc->space_id, desc->entry)) {
        return;
    }

    space_t *space = SPACE_GET(session, desc->space_id);
    log_atomic_op_begin(session);

    buf_enter_page(session, desc->entry, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    head = (page_head_t *)CURR_PAGE(session);
    segment = BTREE_GET_SEGMENT(session);
    if (head->type != PAGE_TYPE_BTREE_HEAD || segment->seg_scn != desc->seg_scn) {
        // btree segment has been released
        buf_leave_page(session, GS_FALSE);
        log_atomic_op_end(session);
        return;
    }

    extents = segment->extents;
    page_free(session, head);
    if (SPACE_IS_LOGGING(space)) {
        log_put(session, RD_SPC_FREE_PAGE, NULL, 0, LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, GS_TRUE);

    buf_unreside(session, session->curr_page_ctrl);

    spc_free_extents(session, space, &extents);
    spc_drop_segment(session, space);

    log_atomic_op_end(session);
}

void btree_truncate_segment(knl_session_t *session, knl_index_desc_t *desc, bool32 reuse_storage)
{
    btree_segment_t *segment = NULL;
    page_head_t *page = NULL;
    page_id_t page_id, ufp_extent;
    page_list_t extents;

    if (!db_valid_seg_tablespace(session, desc->space_id, desc->entry)) {
        return;
    }

    space_t *space = SPACE_GET(session, desc->space_id);
    page_id = desc->entry;
    log_atomic_op_begin(session);

    buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    page = (page_head_t *)CURR_PAGE(session);
    segment = BTREE_GET_SEGMENT(session);
    if (page->type != PAGE_TYPE_BTREE_HEAD || segment->seg_scn != desc->seg_scn) {
        // btree segment has been released
        buf_leave_page(session, GS_FALSE);
        log_atomic_op_end(session);
        return;
    }

    if (!reuse_storage) {
        if (segment->extents.count > 1) {
            extents.count = segment->extents.count - 1;
            extents.first = AS_PAGID(page->next_ext);
            extents.last = segment->extents.last;
            spc_free_extents(session, space, &extents);
        }

        extents.count = 1;
        extents.first = page_id;
        extents.last = page_id;
        ufp_extent = INVALID_PAGID;
    } else {
        extents = segment->extents;
        ufp_extent = AS_PAGID(page->next_ext);
    }

    desc->cr_mode = segment->cr_mode;
    btree_init_segment(session, desc, &extents, ufp_extent);
    buf_leave_page(session, GS_TRUE);

    page_id.page++;
    buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_NO_READ);
    btree_format_page(session, segment, page_id, 0, spc_ext_id_by_size(space->ctrl->extent_size), GS_FALSE);
    btree_insert_minimum_key(session);
    buf_leave_page(session, GS_TRUE);

    log_atomic_op_end(session);
}

void btree_truncate_garbage_segment(knl_session_t *session, knl_seg_desc_t *seg)
{
    knl_index_desc_t desc;

    desc.uid = seg->uid;
    desc.table_id = seg->oid;
    desc.id = seg->index_id;
    desc.space_id = seg->space_id;
    desc.org_scn = seg->org_scn;
    desc.seg_scn = seg->seg_scn;
    desc.entry = seg->entry;
    desc.pctfree = seg->pctfree;
    desc.initrans = seg->initrans;

    btree_truncate_segment(session, &desc, seg->reuse);
}

void btree_truncate_part_segment(knl_session_t *session, knl_index_part_desc_t *desc, bool32 reuse_storage)
{
    btree_segment_t *segment = NULL;
    page_head_t *page = NULL;
    page_id_t page_id, ufp_extent;
    page_list_t extents;

    if (!db_valid_seg_tablespace(session, desc->space_id, desc->entry)) {
        return;
    }

    space_t *space = SPACE_GET(session, desc->space_id);
    page_id = desc->entry;
    log_atomic_op_begin(session);

    buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    page = (page_head_t *)CURR_PAGE(session);
    segment = BTREE_GET_SEGMENT(session);
    if (page->type != PAGE_TYPE_BTREE_HEAD || segment->seg_scn != desc->seg_scn) {
        // btree segment has been released
        buf_leave_page(session, GS_FALSE);
        log_atomic_op_end(session);
        return;
    }

    if (!reuse_storage) {
        if (segment->extents.count > 1) {
            extents.count = segment->extents.count - 1;
            extents.first = AS_PAGID(page->next_ext);
            extents.last = segment->extents.last;
            spc_free_extents(session, space, &extents);
        }

        extents.count = 1;
        extents.first = page_id;
        extents.last = page_id;
        ufp_extent = INVALID_PAGID;
    } else {
        extents = segment->extents;
        ufp_extent = AS_PAGID(page->next_ext);
    }

    desc->cr_mode = segment->cr_mode;
    btree_init_part_segment(session, desc, &extents, ufp_extent);
    buf_leave_page(session, GS_TRUE);

    page_id.page++;
    buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_NO_READ);
    btree_format_page(session, segment, page_id, 0, spc_ext_id_by_size(space->ctrl->extent_size), GS_FALSE);
    btree_insert_minimum_key(session);
    buf_leave_page(session, GS_TRUE);

    log_atomic_op_end(session);
}

void btree_truncate_part_garbage_segment(knl_session_t *session, knl_seg_desc_t *seg)
{
    knl_index_part_desc_t desc;

    desc.uid = seg->uid;
    desc.table_id = seg->oid;
    desc.index_id = seg->index_id;
    desc.space_id = seg->space_id;
    desc.org_scn = seg->org_scn;
    desc.seg_scn = seg->seg_scn;
    desc.entry = seg->entry;
    desc.pctfree = seg->pctfree;
    desc.initrans = seg->initrans;

    btree_truncate_part_segment(session, &desc, seg->reuse);
}

bool32 bt_recycle_leaf_reusable(knl_session_t *session, knl_scn_t rec_scn, knl_scn_t min_scn)
{
    if (GS_INVALID_SCN(rec_scn)) {
        return GS_FALSE;
    }

    if (min_scn > rec_scn) {
        return GS_TRUE;
    }

    uint64 msec = session->kernel->attr.idx_recycle_reuse_time;
    knl_scn_t recycle_reuse_scn = db_time_scn(session, 0, msec);
    if (GS_INVALID_SCN(recycle_reuse_scn)) {
        return GS_FALSE;
    }

    if (DB_NOW_TO_SCN(session) >= rec_scn) {
        if (DB_NOW_TO_SCN(session) - rec_scn >= recycle_reuse_scn) {
            return GS_TRUE;
        }
    }

    return GS_FALSE;
}

bool32 btree_need_extend(knl_session_t *session, btree_segment_t *segment)
{
    if (segment->ufp_count > segment->tree_info.level || !IS_INVALID_PAGID(segment->ufp_extent)) {
        return GS_FALSE;
    }

    uint32 recycled_count = segment->del_pages.count + segment->recycled_pages.count;
    if (recycled_count + segment->ufp_count <= segment->tree_info.level) {
        return GS_TRUE;
    }

    knl_scn_t min_scn = btree_get_recycle_min_scn(session);
    knl_scn_t recycle_scn = segment->last_recycle_scn;
    if (segment->del_pages.count > 0) {
        recycle_scn = (segment->recycled_pages.count > 0) ? MAX(segment->del_scn, recycle_scn) : segment->del_scn;
    }

    if (bt_recycle_leaf_reusable(session, recycle_scn, min_scn)) {
        return GS_FALSE;
    }

    return GS_TRUE;
}

void btree_format_vm_page(knl_session_t *session, btree_segment_t *segment, btree_page_t *page, page_id_t page_id,
    uint32 level)
{
    space_t *space = SPACE_GET(session, segment->space_id);
    page_init(session, &page->head, page_id,
        ((segment->cr_mode == CR_PAGE) ? PAGE_TYPE_PCRB_NODE : PAGE_TYPE_BTREE_NODE));
    TO_PAGID_DATA(INVALID_PAGID, page->prev);
    TO_PAGID_DATA(INVALID_PAGID, page->next);
    page->level = (uint8)level;
    page->keys = 0;
    page->seg_scn = segment->seg_scn;
    page->itls = (level == 0 ? segment->initrans : 0);
    page->free_begin = sizeof(btree_page_t) + space->ctrl->cipher_reserve_size;
    if (segment->cr_mode == CR_PAGE) {
        page->free_end = PAGE_SIZE(page->head) - sizeof(pcr_itl_t) * page->itls - sizeof(page_tail_t);
    } else {
        page->free_end = PAGE_SIZE(page->head) - sizeof(itl_t) * page->itls - sizeof(page_tail_t);
    }
    page->free_size = page->free_end - page->free_begin;
}

void btree_init_page(knl_session_t *session, btree_page_t *page, rd_btree_page_init_t *redo)
{
    page_id_t next_ext;

    next_ext = AS_PAGID(page->head.next_ext);
    page_init(session, &page->head, redo->page_id,
        ((redo->cr_mode == CR_PAGE) ? PAGE_TYPE_PCRB_NODE : PAGE_TYPE_BTREE_NODE));
    space_t *space = SPACE_GET(session, DATAFILE_GET(session, AS_PAGID_PTR(page->head.id)->file)->space_id);

    if (redo->reserve_ext) {
        TO_PAGID_DATA(next_ext, page->head.next_ext);
    }
    TO_PAGID_DATA(INVALID_PAGID, page->prev);
    TO_PAGID_DATA(INVALID_PAGID, page->next);
    page->head.ext_size = redo->extent_size;
    page->level = (uint32)redo->level;
    page->keys = 0;
    page->seg_scn = redo->seg_scn;
    page->itls = redo->itls;
    page->is_recycled = 0;
    page->free_begin = sizeof(btree_page_t) + space->ctrl->cipher_reserve_size;
    if (redo->cr_mode == CR_PAGE) {
        page->free_end = PAGE_SIZE(page->head) - sizeof(pcr_itl_t) * page->itls - sizeof(page_tail_t);
    } else {
        page->free_end = PAGE_SIZE(page->head) - sizeof(itl_t) * page->itls - sizeof(page_tail_t);
    }
    page->free_size = page->free_end - page->free_begin;
}

void btree_format_page(knl_session_t *session, btree_segment_t *segment, page_id_t page_id,
    uint32 level, uint8 extent_size, bool8 reserve_ext)
{
    rd_btree_page_init_t redo;
    btree_page_t *page = BTREE_CURR_PAGE(session);

    redo.cr_mode = segment->cr_mode;
    redo.seg_scn = segment->seg_scn;
    redo.level = (uint8)level;
    redo.page_id = page_id;
    redo.itls = (level == 0 ? segment->initrans : 0);
    redo.extent_size = extent_size;
    redo.reserve_ext = reserve_ext;
    redo.aligned = 0;
    redo.unused = 0;
    btree_init_page(session, page, &redo);
    if (SPACE_IS_LOGGING(SPACE_GET(session, segment->space_id))) {
        log_put(session, RD_BTREE_FORMAT_PAGE, &redo, sizeof(rd_btree_page_init_t), LOG_ENTRY_FLAG_NONE);
    }
}

void btree_concat_extent(knl_session_t *session, btree_t *btree, page_id_t extent, uint32 extent_size,
    bool32 is_degrade)
{
    btree_segment_t *segment = BTREE_SEGMENT(session, btree->entry, btree->segment);

    buf_enter_page(session, extent, LATCH_MODE_X, ENTER_PAGE_NO_READ);
    btree_format_page(session, segment, extent, 0, spc_ext_id_by_size(extent_size), GS_FALSE);
    buf_leave_page(session, GS_TRUE);

    buf_enter_page(session, btree->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);

    if (!IS_SAME_PAGID(btree->entry, segment->extents.last)) {
        buf_enter_page(session, segment->extents.last, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    }

    page_head_t *head = (page_head_t *)CURR_PAGE(session);
    TO_PAGID_DATA(extent, head->next_ext);
    space_t *space = SPACE_GET(session, segment->space_id);
    if (SPACE_IS_LOGGING(space)) {
        log_put(session, RD_SPC_CONCAT_EXTENT, &extent, sizeof(page_id_t), LOG_ENTRY_FLAG_NONE);
    }

    if (!IS_SAME_PAGID(btree->entry, segment->extents.last)) {
        buf_leave_page(session, GS_TRUE);
    }

    // try to init & update btree segment page count
    if (is_degrade) {
        btree_try_init_segment_pagecount(space, segment);
    }
    btree_try_update_segment_pagecount(segment, extent_size);

    segment->extents.last = extent;
    segment->extents.count++;
    segment->ufp_extent = extent;

    if (SPACE_IS_LOGGING(space)) {
        log_put(session, RD_BTREE_CHANGE_SEG, segment, sizeof(btree_segment_t), LOG_ENTRY_FLAG_NONE);
    }

    buf_leave_page(session, GS_TRUE);
}

void bt_all_pageid(knl_session_t *session, btree_t *btree, btree_alloc_assist_t *assist)
{
    btree_segment_t *segment = BTREE_SEGMENT(session, btree->entry, btree->segment);
    uint8 cipher_size = btree->cipher_reserve_size;

    if (segment->del_pages.count > 0) {
        knl_scn_t min_scn = btree_get_recycle_min_scn(session);
        if (bt_recycle_leaf_reusable(session, segment->del_scn, min_scn)) {
            assist->new_pageid = segment->del_pages.first;
            buf_enter_page(session, segment->del_pages.first, LATCH_MODE_S, ENTER_PAGE_NORMAL);
            assist->next_pageid = *(page_id_t *)BTREE_NEXT_DEL_PAGE(session, cipher_size);
            assist->ow_recycle_scn = segment->del_scn;
            buf_leave_page(session, GS_FALSE);
            assist->type = BTREE_RECYCLE_DELETED;
            return;
        }
    }

    if (segment->recycled_pages.count > 0) {
        knl_scn_t min_scn = btree_get_recycle_min_scn(session);
        if (bt_recycle_leaf_reusable(session, segment->first_recycle_scn, min_scn)) {
            assist->new_pageid = segment->recycled_pages.first;
            buf_enter_page(session, segment->recycled_pages.first, LATCH_MODE_S, ENTER_PAGE_NORMAL);
            assist->next_pageid = *(page_id_t *)BTREE_NEXT_DEL_PAGE(session, cipher_size);
            assist->next_recycle_scn = *BTREE_NEXT_RECYCLE_SCN(session, cipher_size);
            assist->ow_recycle_scn = segment->first_recycle_scn;
#ifdef DB_DEBUG_VERSION
            if (!GS_INVALID_SCN(assist->next_recycle_scn)) {
                knl_panic_log(assist->ow_recycle_scn < assist->next_recycle_scn,
                    "invalid ow_recycle_scn %llu, next_recycle_scn %llu",
                    assist->ow_recycle_scn, assist->next_recycle_scn);
            }
#endif
            buf_leave_page(session, GS_FALSE);
            assist->type = BTREE_ALLOC_RECYCLED;
            return;
        }
    }

    if (segment->ufp_count == 0 && !IS_INVALID_PAGID(segment->ufp_extent)) {
        assist->new_pageid = segment->ufp_extent;

        if (!IS_SAME_PAGID(segment->ufp_extent, segment->extents.last)) {
            assist->type = BTREE_REUSE_STORAGE;
        } else {
            assist->type = BTREE_ALLOC_NEW_EXTENT;
        }

        return;
    }

    assist->type = BTREE_ALLOC_NEW_PAGE;
    assist->new_pageid = segment->ufp_first;
    return;
}

void btree_alloc_from_ufp(knl_session_t *session, btree_t *btree, page_id_t *page_id, bool32 *is_ext_first)
{
    btree_segment_t *segment = BTREE_SEGMENT(session, btree->entry, btree->segment);
    space_t *space = NULL;
    page_head_t *page_head = NULL;

    buf_enter_page(session, btree->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    space = SPACE_GET(session, segment->space_id);

    if (segment->ufp_count == 0 && !IS_INVALID_PAGID(segment->ufp_extent)) {
        segment->ufp_first = segment->ufp_extent;
        buf_enter_page(session, segment->ufp_first, LATCH_MODE_S, ENTER_PAGE_NORMAL);
        page_head = (page_head_t *)session->curr_page;

        if (SPACE_IS_BITMAPMANAGED(space)) {
            segment->ufp_count = spc_ext_size_by_id(page_head->ext_size);
        } else {
            segment->ufp_count = space->ctrl->extent_size;
        }

        if (!IS_SAME_PAGID(segment->ufp_first, segment->extents.last)) {
            segment->ufp_extent = AS_PAGID(page_head->next_ext);
        } else {
            segment->ufp_extent = INVALID_PAGID;
        }

        buf_leave_page(session, GS_FALSE);

        /*
        * notice the caller that the page allocated is whether the first page of extent or not.
        * so that, the caller can determine the enter page mode because of extent size storing
        * in the first page of extent.
        */
        if (is_ext_first != NULL) {
            *is_ext_first = GS_TRUE;
        }
    }

    knl_panic_log(segment->ufp_count > 0, "the unformat page count of segment is abnormal, panic info: index %s "
                  "segment's ufp_count %u", ((index_t *)btree->index)->desc.name, segment->ufp_count);

    *page_id = segment->ufp_first;
    if (segment->ufp_count == 1) {
        segment->ufp_first = INVALID_PAGID;
    } else {
        segment->ufp_first.page++;
    }

    segment->ufp_count--;
    if (SPACE_IS_LOGGING(space)) {
        log_put(session, RD_BTREE_CHANGE_SEG, segment, sizeof(btree_segment_t), LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, GS_TRUE);
}

void bt_all_page(knl_session_t *session, btree_t *btree, btree_alloc_assist_t *assist)
{
    btree_segment_t *segment = BTREE_SEGMENT(session, btree->entry, btree->segment);

    if (assist->type == BTREE_RECYCLE_DELETED) {
        buf_enter_page(session, btree->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
        KNL_SET_SCN(&segment->ow_recycle_scn, assist->ow_recycle_scn);
        segment->del_pages.count--;
        if (segment->del_pages.count == 0) {
            segment->del_pages.first = INVALID_PAGID;
            segment->del_pages.last = INVALID_PAGID;
        } else {
            segment->del_pages.first = assist->next_pageid;
        }

        if (SPACE_IS_LOGGING(SPACE_GET(session, segment->space_id))) {
            log_put(session, RD_BTREE_CHANGE_SEG, segment, sizeof(btree_segment_t), LOG_ENTRY_FLAG_NONE);
        }
        buf_leave_page(session, GS_TRUE);
        return;
    }

    if (assist->type == BTREE_ALLOC_RECYCLED) {
        buf_enter_page(session, btree->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
        KNL_SET_SCN(&segment->ow_recycle_scn, assist->ow_recycle_scn);
        segment->recycled_pages.count--;
        if (segment->recycled_pages.count == 0) {
            segment->recycled_pages.first = INVALID_PAGID;
            segment->recycled_pages.last = INVALID_PAGID;
            segment->last_recycle_scn = 0;
            segment->first_recycle_scn = 0;
        } else {
            segment->recycled_pages.first = assist->next_pageid;
            segment->first_recycle_scn = assist->next_recycle_scn;
        }

        if (SPACE_IS_LOGGING(SPACE_GET(session, segment->space_id))) {
            log_put(session, RD_BTREE_CHANGE_SEG, segment, sizeof(btree_segment_t), LOG_ENTRY_FLAG_NONE);
        }
        buf_leave_page(session, GS_TRUE);
        return;
    }

    /* page has already formatted so that called need't to know extent size */
    btree_alloc_from_ufp(session, btree, &assist->new_pageid, NULL);
}

status_t btree_build_segment(knl_session_t *session, index_t *index)
{
    space_t *space = SPACE_GET(session, index->desc.space_id);
    btree_segment_t *segment = NULL;
    page_list_t extents;
    page_id_t page_id;

    log_atomic_op_begin(session);

    if (GS_SUCCESS != spc_alloc_extent(session, space, space->ctrl->extent_size, &page_id, GS_FALSE)) {
        GS_THROW_ERROR(ERR_ALLOC_EXTENT, space->ctrl->name);
        log_atomic_op_end(session);
        return GS_ERROR;
    }

    spc_create_segment(session, space);

    index->desc.entry = page_id;
    index->btree.entry = page_id;
    index->btree.cipher_reserve_size = space->ctrl->cipher_reserve_size;

    extents.count = 1;
    extents.first = page_id;
    extents.last = page_id;

    buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_RESIDENT | ENTER_PAGE_NO_READ);
    segment = BTREE_GET_SEGMENT(session);
    btree_init_segment(session, &index->desc, &extents, INVALID_PAGID);
    buf_leave_page(session, GS_TRUE);

    page_id.page++;
    buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_NO_READ);
    btree_format_page(session, segment, page_id, 0, spc_ext_id_by_size(space->ctrl->extent_size), GS_FALSE);
    btree_insert_minimum_key(session);
    buf_leave_page(session, GS_TRUE);

    index->desc.seg_scn = segment->seg_scn;

    log_atomic_op_end(session);

    return GS_SUCCESS;
}

status_t btree_create_segment(knl_session_t *session, index_t *index)
{
    space_t *space = SPACE_GET(session, index->desc.space_id);

    if (!spc_valid_space_object(session, space->ctrl->id)) {
        GS_THROW_ERROR(ERR_SPACE_HAS_REPLACED, space->ctrl->name, space->ctrl->name);
        return GS_ERROR;
    }

    return btree_build_segment(session, index);
}

status_t btree_create_part_segment(knl_session_t *session, index_part_t *index_part)
{
    space_t *space = SPACE_GET(session, index_part->desc.space_id);
    btree_segment_t *segment = NULL;
    page_list_t extents;
    page_id_t page_id;

    if (!spc_valid_space_object(session, space->ctrl->id)) {
        GS_THROW_ERROR(ERR_SPACE_HAS_REPLACED, space->ctrl->name, space->ctrl->name);
        return GS_ERROR;
    }

    log_atomic_op_begin(session);

    if (GS_SUCCESS != spc_alloc_extent(session, space, space->ctrl->extent_size, &page_id, GS_FALSE)) {
        GS_THROW_ERROR(ERR_ALLOC_EXTENT, space->ctrl->name);
        log_atomic_op_end(session);
        return GS_ERROR;
    }

    spc_create_segment(session, space);

    index_part->desc.entry = page_id;
    index_part->btree.entry = page_id;
    index_part->btree.cipher_reserve_size = space->ctrl->cipher_reserve_size;

    extents.count = 1;
    extents.first = page_id;
    extents.last = page_id;

    buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_RESIDENT | ENTER_PAGE_NO_READ);
    segment = BTREE_GET_SEGMENT(session);
    btree_init_part_segment(session, &index_part->desc, &extents, INVALID_PAGID);
    buf_leave_page(session, GS_TRUE);

    page_id.page++;
    buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_NO_READ);
    btree_format_page(session, segment, page_id, 0, spc_ext_id_by_size(space->ctrl->extent_size), GS_FALSE);
    btree_insert_minimum_key(session);
    buf_leave_page(session, GS_TRUE);

    index_part->desc.seg_scn = segment->seg_scn;

    log_atomic_op_end(session);

    if (DB_IS_CLUSTER(session) && (session->rm->logic_log_size >= KNL_LOGIC_LOG_FLUSH_SIZE)) {
        tx_copy_logic_log(session);
        if (db_write_ddl_op(session) != GS_SUCCESS) {
            knl_panic_log(0, "[DDL]can't record logical log for session(%d)", session->id);
        }
        dtc_sync_ddl(session);
    }

    return GS_SUCCESS;
}

status_t btree_create_part_entry(knl_session_t *session, btree_t *btree, index_part_t *index_part,
                                 knl_part_locate_t part_loc)
{
    dls_latch_x(session, &btree->struct_latch, session->id, &session->stat_btree);

    if (btree->segment != NULL) {
        dls_unlatch(session, &btree->struct_latch, &session->stat_btree);
        return GS_SUCCESS;
    }

    if (btree_create_part_segment(session, index_part) != GS_SUCCESS) {
        dls_unlatch(session, &btree->struct_latch, &session->stat_btree);
        return GS_ERROR;
    }

    if (knl_begin_auton_rm(session) != GS_SUCCESS) {
        btree_drop_part_segment(session, index_part);
        dls_unlatch(session, &btree->struct_latch, &session->stat_btree);
        return GS_ERROR;
    }

    status_t status = GS_SUCCESS;
    if (IS_SUB_IDXPART(&index_part->desc)) {
        status = db_upd_sub_idx_part_entry(session, &index_part->desc, index_part->desc.entry);
    } else {
        status = db_upd_idx_part_entry(session, &index_part->desc, index_part->desc.entry);
    }
    
    if (status != GS_SUCCESS) {
        knl_end_auton_rm(session, GS_ERROR);
        btree_drop_part_segment(session, index_part);
        dls_unlatch(session, &btree->struct_latch, &session->stat_btree);
        return GS_ERROR;
    }

    rd_create_btree_entry_t redo;
    redo.tab_op.op_type = RD_CREATE_BTREE_ENTRY;
    redo.tab_op.uid = index_part->desc.uid;
    redo.tab_op.oid = index_part->desc.table_id;
    redo.part_loc = part_loc;
    redo.entry = index_part->desc.entry;
    redo.index_id = index_part->desc.index_id;
    redo.is_shadow = btree->is_shadow;
    if (SPACE_IS_LOGGING(SPACE_GET(session, index_part->desc.space_id))) {
        log_put(session, RD_LOGIC_OPERATION, &redo, sizeof(rd_create_btree_entry_t), LOG_ENTRY_FLAG_NONE);
    }

    knl_end_auton_rm(session, GS_SUCCESS);

    buf_enter_page(session, index_part->desc.entry, LATCH_MODE_S, ENTER_PAGE_RESIDENT);
    btree->segment = BTREE_GET_SEGMENT(session);
    bt_put_change_stats(btree);
    buf_leave_page(session, GS_FALSE);

    dls_unlatch(session, &btree->struct_latch, &session->stat_btree);

    return GS_SUCCESS;
}

status_t btree_create_entry(knl_session_t *session, btree_t *btree)
{
    index_t *index = btree->index;

    dls_latch_x(session, &btree->struct_latch, session->id, &session->stat_btree);

    if (btree->segment != NULL) {
        dls_unlatch(session, &btree->struct_latch, &session->stat_btree);
        return GS_SUCCESS;
    }

    if (btree_create_segment(session, index) != GS_SUCCESS) {
        dls_unlatch(session, &btree->struct_latch, &session->stat_btree);
        return GS_ERROR;
    }

    if (knl_begin_auton_rm(session) != GS_SUCCESS) {
        btree_drop_segment(session, index);
        dls_unlatch(session, &btree->struct_latch, &session->stat_btree);
        return GS_ERROR;
    }

    if (db_update_index_entry(session, &index->desc, index->desc.entry) != GS_SUCCESS) {
        knl_end_auton_rm(session, GS_ERROR);
        btree_drop_segment(session, index);
        dls_unlatch(session, &btree->struct_latch, &session->stat_btree);
        return GS_ERROR;
    }

    rd_create_btree_entry_t redo;
    redo.tab_op.op_type = RD_CREATE_BTREE_ENTRY;
    redo.tab_op.uid = index->desc.uid;
    redo.tab_op.oid = index->desc.table_id;
    redo.part_loc.part_no = GS_INVALID_ID32;
    redo.entry = index->desc.entry;
    redo.index_id = index->desc.id;
    redo.is_shadow = btree->is_shadow;

    if (SPACE_IS_LOGGING(SPACE_GET(session, index->desc.space_id))) {
        log_put(session, RD_LOGIC_OPERATION, &redo, sizeof(rd_create_btree_entry_t), LOG_ENTRY_FLAG_NONE);
    }

    knl_end_auton_rm(session, GS_SUCCESS);

    buf_enter_page(session, index->desc.entry, LATCH_MODE_S, ENTER_PAGE_RESIDENT);
    btree->segment = BTREE_GET_SEGMENT(session);
    bt_put_change_stats(btree);
    buf_leave_page(session, GS_FALSE);

    dls_unlatch(session, &btree->struct_latch, &session->stat_btree);

    return GS_SUCCESS;
}

status_t btree_segment_dump(knl_session_t *session, page_head_t *page_head, cm_dump_t *dump)
{
    btree_segment_t *segment = BTREE_GET_SEGMENT(session);
    cm_dump(dump, "btree segment information\n");
    cm_dump(dump, "\tindex info:\n \t\tuid: %u \ttable_id: %u \tindex_id: %u \tspace_id: %u\n",
        segment->uid, segment->table_id, segment->index_id, segment->space_id);
    cm_dump(dump, "\t\ttree_info.root: %u-%u \ttree_info.level: %u\n",
        (uint32)AS_PAGID(segment->tree_info.root).file,
        (uint32)AS_PAGID(segment->tree_info.root).page, (uint32)segment->tree_info.level);
    CM_DUMP_WRITE_FILE(dump);
    cm_dump(dump, "\t\tinitrans: %u", segment->initrans);
    cm_dump(dump, "\torg_scn: %llu", segment->org_scn);
    cm_dump(dump, "\tseg_scn: %llu\n", segment->seg_scn);
    cm_dump(dump, "\tfirst_recycle_scn: %llu", segment->first_recycle_scn);
    cm_dump(dump, "\tlast_recycle_scn: %llu\n", segment->last_recycle_scn);
    cm_dump(dump, "\tow_del_scn: %llu\n", segment->ow_del_scn);
    cm_dump(dump, "\tow_recycle_scn: %llu\n", segment->ow_recycle_scn);
    cm_dump(dump, "\tow_recycle_scn: %llu\n", segment->recycle_ver_scn);
    cm_dump(dump, "btree storage information\n");
    CM_DUMP_WRITE_FILE(dump);

    cm_dump(dump, "\textents:\tcount %u, \tfirst %u-%u, \tlast %u-%u\n",
        segment->extents.count,
        segment->extents.first.file, segment->extents.first.page,
        segment->extents.last.file, segment->extents.last.page);
    cm_dump(dump, "\tufp_count: %u\n", segment->ufp_count);
    cm_dump(dump, "\tufp_first: %u-%u\n", segment->ufp_first.file, segment->ufp_first.page);
    cm_dump(dump, "\tufp_extent: %u-%u\n", segment->ufp_extent.file, segment->ufp_extent.page);
    cm_dump(dump, "\tgarbage_size: %llu\n", segment->garbage_size);
    CM_DUMP_WRITE_FILE(dump);

    return GS_SUCCESS;
}

void btree_undo_create(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot)
{
    btree_segment_t *segment = NULL;
    undo_btree_create_t *undo;
    page_list_t extents;
    page_head_t *head = NULL;
    buf_ctrl_t *ctrl = NULL;
    space_t *space = NULL;

    undo = (undo_btree_create_t *)ud_row->data;
    if (!spc_validate_page_id(session, undo->entry)) {
        return;
    }

    if (DB_IS_BG_ROLLBACK_SE(session) && !SPC_IS_LOGGING_BY_PAGEID(session, undo->entry)) {
        return;
    }

    space = SPACE_GET(session, undo->space_id);
    buf_enter_page(session, undo->entry, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    head = (page_head_t *)CURR_PAGE(session);
    ctrl = session->curr_page_ctrl;
    segment = BTREE_GET_SEGMENT(session);
    extents = segment->extents;
    page_free(session, head);
    if (SPACE_IS_LOGGING(space)) {
        log_put(session, RD_SPC_FREE_PAGE, NULL, 0, LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, GS_TRUE);
    buf_unreside(session, ctrl);

    spc_free_extents(session, space, &extents);
    spc_drop_segment(session, space);
}

status_t btree_generate_create_undo(knl_session_t *session, page_id_t entry, uint32 space_id, bool32 need_redo)
{
    undo_data_t undo;
    undo_btree_create_t ud_create;

    if (undo_prepare(session, sizeof(undo_btree_create_t), need_redo, GS_FALSE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    log_atomic_op_begin(session);
    ud_create.entry = entry;
    ud_create.space_id = space_id;

    undo.snapshot.is_xfirst = GS_TRUE;
    undo.snapshot.scn = 0;
    undo.data = (char *)&ud_create;
    undo.size = sizeof(undo_btree_create_t);
    undo.ssn = session->rm->ssn;
    undo.type = UNDO_CREATE_INDEX;
    undo_write(session, &undo, need_redo, GS_FALSE);
    log_atomic_op_end(session);

    return GS_SUCCESS;
}

status_t btree_prepare_pages(knl_session_t *session, btree_t *btree)
{
    btree_segment_t *segment = BTREE_SEGMENT(session, btree->entry, btree->segment);
    page_id_t extent;

    if (segment->ufp_count == 0 && IS_INVALID_PAGID(segment->ufp_extent)) {
        log_atomic_op_begin(session);

        space_t *space = SPACE_GET(session, segment->space_id);
        uint32 extent_size = spc_get_ext_size(SPACE_GET(session, segment->space_id), segment->extents.count);

        bool32 is_degrade = GS_FALSE;
        if (spc_try_alloc_extent(session, space, &extent, &extent_size, &is_degrade, GS_FALSE) != GS_SUCCESS) {
            GS_THROW_ERROR(ERR_ALLOC_EXTENT, space->ctrl->name);
            log_atomic_op_end(session);
            return GS_ERROR;
        }

        btree_concat_extent(session, btree, extent, extent_size, is_degrade);
        log_atomic_op_end(session);
    }

    if (DB_IS_CLUSTER(session) && (session->rm->logic_log_size >= KNL_LOGIC_LOG_FLUSH_SIZE)) {
        tx_copy_logic_log(session);
        if (db_write_ddl_op(session) != GS_SUCCESS) {
            knl_panic_log(0, "[DDL]can't record logical log for session(%d)", session->id);
        }
        dtc_sync_ddl(session);
    }

    return GS_SUCCESS;
}

static void btree_set_scns(knl_session_t *session, btree_t *btree, rd_btree_info_t btree_info,
    rd_btree_set_recycle_t *recycle_info)
{
        btree->min_scn = btree_info.min_scn;
        if (recycle_info != NULL) {
            knl_scn_t ow_del_scn = MAX(KNL_GET_SCN(&btree->chg_stats.ow_del_scn), recycle_info->ow_del_scn);
#ifdef DB_DEBUG_VERSION
            knl_scn_t old_scn = KNL_GET_SCN(&btree->chg_stats.ow_del_scn);
            knl_panic_log(ow_del_scn >= old_scn, "invalid new ow del scn %llu, old ow del scn %llu",
                ow_del_scn, old_scn);
#endif
            KNL_SET_SCN(&btree->chg_stats.ow_del_scn, ow_del_scn);
        }
}

void btree_rd_set_scn(knl_session_t *session, rd_btree_info_t btree_info, rd_btree_set_recycle_t *recycle_info)
{
    if (DB_IS_MAINTENANCE(session) || DB_NOT_READY(session) || DAAC_PARTIAL_RECOVER_SESSION(session)) {
        return;
    }

    dc_user_t *user = NULL;

    if (dc_open_user_by_id(session, btree_info.uid, &user) != GS_SUCCESS) {
        return;
    }

    dc_entry_t *entry = DC_GET_ENTRY(user, btree_info.oid);
    if (entry == NULL) {
        return;
    }

    cm_spin_lock(&entry->lock, &session->stat->spin_stat.stat_dc_entry);
    if (entry->entity == NULL) {
        cm_spin_unlock(&entry->lock);
        return;
    }
    cm_spin_lock(&entry->entity->ref_lock, NULL);
    entry->entity->ref_count++;
    cm_spin_unlock(&entry->entity->ref_lock);

    index_t *index = dc_find_index_by_id(entry->entity, btree_info.idx_id);
    if (index == NULL) {
        cm_spin_unlock(&entry->lock);
        dc_close_entity(session->kernel, entry->entity, GS_TRUE);
        return;
    }

    btree_t *btree = NULL;
    if (IS_PART_INDEX(index)) {
        index_part_t *index_part = INDEX_GET_PART(index, btree_info.part_loc.part_no);
        if (IS_PARENT_IDXPART(&index_part->desc)) {
            index_part = PART_GET_SUBENTITY(index->part_index, index_part->subparts[btree_info.part_loc.subpart_no]);
        }
        btree = &index_part->btree;
    } else {
        btree = &index->btree;
    }
    btree_set_scns(session, btree, btree_info, recycle_info);

    cm_spin_unlock(&entry->lock);
    if (entry->entity != NULL) {
        dc_close_entity(session->kernel, entry->entity, GS_TRUE);
    }
}

btree_t *btree_get_handle_by_undo(knl_session_t *session, knl_dictionary_t *dc, knl_part_locate_t part_loc,
    char *undo_row)
{
    undo_row_t *ud_row = (undo_row_t *)undo_row;
    page_id_t entry;

    entry.file = (uint16)ud_row->seg_file;
    entry.page = (uint32)ud_row->seg_page;
    if (!spc_validate_page_id(session, entry)) {
        return NULL;
    }

    return dc_get_btree(session, entry, part_loc, ud_row->index_id == GS_SHADOW_INDEX_ID, dc);
}

void btree_set_initrans(knl_session_t *session, btree_t *btree, uint32 initrans)
{
    btree_segment_t *segment = (btree_segment_t *)btree->segment;

    if (segment == NULL) {
        return;
    }

    log_atomic_op_begin(session);

    buf_enter_page(session, btree->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    segment->initrans = initrans;
    if (SPC_IS_LOGGING_BY_PAGEID(session, btree->entry)) {
        log_put(session, RD_BTREE_CHANGE_SEG, segment, sizeof(btree_segment_t), LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, GS_TRUE);

    log_atomic_op_end(session);
}

void bt_put_change_stats(btree_t *btree)
{
    btree->chg_stats.empty_size = MAX(btree->chg_stats.empty_size, btree->segment->garbage_size);
    btree->chg_stats.first_empty_size = 0;
    KNL_SET_SCN(&btree->chg_stats.ow_del_scn, btree->segment->ow_del_scn);
}
