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
 * knl_part_index.c
 *
 *
 * IDENTIFICATION
 * src/kernel/table/knl_part_index.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_table_module.h"
#include "knl_part_output.h"
#include "cm_hash.h"
#include "cm_log.h"
#include "knl_table.h"
#include "ostat_load.h"
#include "dc_part.h"
#include "knl_lob.h"
#include "knl_heap.h"
#include "knl_sys_part_defs.h"
#include "knl_part_inner.h"

bool32 subpart_idx_find_by_name(part_index_t *part_index, text_t *name, index_part_t **idx_subpart)
{
    if (!IS_COMPART_INDEX(part_index)) {
        return CT_FALSE;
    }
    
    index_part_t *entity = NULL;
    uint32 hash = dc_cal_part_name_hash(name);
    part_bucket_t *bucket = &part_index->sub_pbuckets[hash];
    uint32 part_no = bucket->first;

    while (part_no != CT_INVALID_ID32) {
        entity = PART_GET_SUBENTITY(part_index, part_no);
        if (cm_text_str_equal(name, entity->desc.name)) {
            break;
        }

        part_no = entity->pnext;
    }
    
    *idx_subpart = entity;
    if (part_no == CT_INVALID_ID32) {
        return CT_FALSE;
    }
    
    return CT_TRUE;
}

bool32 part_idx_find_by_name(part_index_t *part_index, text_t *name, index_part_t **idx_part)
{
    index_part_t *entity = NULL;
    uint32 hash = dc_cal_part_name_hash(name);
    part_bucket_t *bucket = &part_index->pbuckets[hash];
    uint32 part_no = bucket->first;

    while (part_no != CT_INVALID_ID32) {
        entity = PART_GET_ENTITY(part_index, part_no);
        if (cm_text_str_equal(name, entity->desc.name)) {
            break;
        }

        part_no = entity->pnext;
    }
    
    *idx_part = entity;
    if (part_no == CT_INVALID_ID32) {
        return CT_FALSE;
    }
    
    return CT_TRUE;
}

status_t db_upd_idx_part(knl_session_t *session, knl_index_part_desc_t *desc)
{
    knl_cursor_t *cursor = NULL;
    row_assist_t ra;
    uint16 size;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_INDEXPART_ID, IX_SYS_INDEXPART001_ID);

    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&desc->uid,
                     sizeof(uint32), IX_COL_SYS_INDEXPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&desc->table_id,
                     sizeof(uint32), IX_COL_SYS_INDEXPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&desc->index_id,
                     sizeof(uint32), IX_COL_SYS_INDEXPART001_INDEX_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&desc->part_id,
                     sizeof(uint32), IX_COL_SYS_INDEXPART001_PART_ID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s", cursor->rowid.file,
                  cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name);

    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), UPDATE_COLUMN_COUNT_SIX);
    (void)row_put_int32(&ra, desc->space_id);
    (void)row_put_int64(&ra, desc->org_scn);
    (void)row_put_int64(&ra, *(int64 *)&desc->entry);
    (void)row_put_int32(&ra, desc->initrans);
    (void)row_put_int32(&ra, desc->pctfree);
    (void)row_put_int32(&ra, desc->flags);
    cursor->update_info.count = UPDATE_COLUMN_COUNT_SIX;
    cursor->update_info.columns[0] = SYS_INDEXPART_COL_SPACE_ID;   // index part space id
    cursor->update_info.columns[1] = SYS_INDEXPART_COL_ORG_SCN;   // index part org scn
    cursor->update_info.columns[2] = SYS_INDEXPART_COL_ENTRY;   // index part entry
    cursor->update_info.columns[3] = SYS_INDEXPART_COL_INITRANS;  // index part initrans
    cursor->update_info.columns[4] = SYS_INDEXPART_COL_PCTFREE;  // index part pctfree
    cursor->update_info.columns[5] = SYS_INDEXPART_COL_FLAGS;  // index part pctfree

    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

    if (knl_internal_update(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    CM_RESTORE_STACK(session->stack);

    return CT_SUCCESS;
}

status_t db_upd_idx_part_entry(knl_session_t *session, knl_index_part_desc_t *desc, page_id_t entry)
{
    knl_cursor_t *cursor = NULL;
    row_assist_t ra;
    uint16 size;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_INDEXPART_ID, IX_SYS_INDEXPART001_ID);

    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&desc->uid,
                     sizeof(uint32), IX_COL_SYS_INDEXPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&desc->table_id,
                     sizeof(uint32), IX_COL_SYS_INDEXPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&desc->index_id,
                     sizeof(uint32), IX_COL_SYS_INDEXPART001_INDEX_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&desc->part_id,
                     sizeof(uint32), IX_COL_SYS_INDEXPART001_PART_ID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s", cursor->rowid.file,
                  cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name);

    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), UPDATE_COLUMN_COUNT_TWO);
    (void)row_put_int32(&ra, *(uint32 *)&desc->space_id);
    (void)row_put_int64(&ra, *(int64 *)&entry);
    cursor->update_info.count = UPDATE_COLUMN_COUNT_TWO;
    cursor->update_info.columns[0] = SYS_INDEXPART_COL_SPACE_ID;
    cursor->update_info.columns[1] = SYS_INDEXPART_COL_ENTRY;  // index part entry
    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

    if (knl_internal_update(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

status_t db_upd_shadow_idx_part_entry(knl_session_t *session, knl_index_part_desc_t *desc, page_id_t entry,
    bool32 is_sub)
{
    uint16 size;
    row_assist_t ra;
    uint32 parent_partid = is_sub ? desc->parent_partid : 0;

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_SHADOW_INDEXPART_ID, IX_SYS_SHW_INDEXPART001_ID);

    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&desc->uid,
        sizeof(uint32), IX_COL_SYS_SHW_INDEXPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&desc->table_id,
        sizeof(uint32), IX_COL_SYS_SHW_INDEXPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&desc->index_id,
        sizeof(uint32), IX_COL_SYS_SHW_INDEXPART001_INDEX_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&desc->part_id,
        sizeof(uint32), IX_COL_SYS_SHW_INDEXPART001_PART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&parent_partid,
        sizeof(uint32), IX_COL_SYS_SHW_INDEXPART001_PARENTPART_ID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (!cursor->eof) {
        row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), UPDATE_COLUMN_COUNT_ONE);
        (void)row_put_int64(&ra, *(int64 *)&entry);
        cursor->update_info.count = UPDATE_COLUMN_COUNT_ONE;
        cursor->update_info.columns[0] = SYS_SHADOW_INDEXPART_COL_ENTRY;  // index part entry
        cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

        if (knl_internal_update(session, cursor) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

status_t db_switch_shadow_idx_partition(knl_session_t *session, knl_cursor_t *cursor,
    knl_index_part_desc_t *part_desc)
{
    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, NULL);
    part_desc->part_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SHADOW_INDEXPART_COL_PART_ID);
    part_desc->space_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SHADOW_INDEXPART_COL_SPACE_ID);
    part_desc->org_scn = *(knl_scn_t *)CURSOR_COLUMN_DATA(cursor, SYS_SHADOW_INDEXPART_COL_ORG_SCN);
    part_desc->entry = *(page_id_t *)CURSOR_COLUMN_DATA(cursor, SYS_SHADOW_INDEXPART_COL_ENTRY);
    part_desc->initrans = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SHADOW_INDEXPART_COL_INITRANS);
    part_desc->pctfree = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SHADOW_INDEXPART_COL_PCTFREE);
    part_desc->flags = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SHADOW_INDEXPART_COL_FLAGS);
    part_desc->subpart_cnt = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SHADOW_INDEXPART_COL_SUBPART_CNT);
    
    if (IS_SUB_IDXPART(part_desc)) {
        if (db_upd_idx_subpart(session, part_desc) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        if (db_upd_idx_part(session, part_desc) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t db_switch_shadow_idx_partitions(knl_session_t *session, knl_cursor_t *cursor, index_t *index)
{
    knl_index_desc_t *idesc = &index->desc;
    knl_index_part_desc_t part_desc;

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_SHADOW_INDEXPART_ID, IX_SYS_SHW_INDEXPART001_ID);
    knl_init_index_scan(cursor, CT_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &idesc->uid,
                     sizeof(uint32), IX_COL_SYS_SHW_INDEXPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &idesc->table_id,
                     sizeof(uint32), IX_COL_SYS_SHW_INDEXPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &idesc->id, sizeof(uint32),
                     IX_COL_SYS_SHW_INDEXPART001_INDEX_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_SHW_INDEXPART001_PART_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_SHW_INDEXPART001_PARENTPART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, &idesc->uid,
                     sizeof(uint32), IX_COL_SYS_SHW_INDEXPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, &idesc->table_id,
                     sizeof(uint32), IX_COL_SYS_SHW_INDEXPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, &idesc->id, sizeof(uint32),
                     IX_COL_SYS_SHW_INDEXPART001_INDEX_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_SHW_INDEXPART001_PART_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_SHW_INDEXPART001_PARENTPART_ID);

    part_desc.uid = idesc->uid;
    part_desc.table_id = idesc->table_id;
    part_desc.index_id = idesc->id;

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        return CT_ERROR;
    }

    while (!cursor->eof) {
        if (db_switch_shadow_idx_partition(session, cursor, &part_desc) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (db_delete_from_shadow_sysindexpart(session, cursor, index->desc.uid, index->desc.table_id,
        index->desc.id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t db_upd_idx_part_initrans(knl_session_t *session, knl_index_part_desc_t *desc, uint32 initrans)
{
    row_assist_t ra;
    uint16 size;

    CM_SAVE_STACK(session->stack);

    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_INDEXPART_ID, IX_SYS_INDEXPART001_ID);

    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER,
        (void *)&desc->uid, sizeof(uint32), IX_COL_SYS_INDEXPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER,
        (void *)&desc->table_id, sizeof(uint32), IX_COL_SYS_INDEXPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER,
        (void *)&desc->index_id, sizeof(uint32), IX_COL_SYS_INDEXPART001_INDEX_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER,
        (void *)&desc->part_id, sizeof(uint32), IX_COL_SYS_INDEXPART001_PART_ID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s", cursor->rowid.file,
                  cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name);

    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), UPDATE_COLUMN_COUNT_ONE);
    (void)row_put_int32(&ra, (int32)initrans);
    cursor->update_info.count = UPDATE_COLUMN_COUNT_ONE;
    cursor->update_info.columns[0] = SYS_INDEXPART_COL_INITRANS;  // index part initrans
    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);
    if (knl_internal_update(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

status_t db_upd_idx_subpart_initrans(knl_session_t *session, knl_index_part_desc_t *desc, uint32 initrans)
{
    row_assist_t ra;
    uint16 size;

    CM_SAVE_STACK(session->stack);

    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_SUB_INDEX_PARTS_ID, IX_SYS_INDEXSUBPART001_ID);

    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER,
        (void *)&desc->uid, sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER,
        (void *)&desc->table_id, sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER,
        (void *)&desc->index_id, sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_INDEX_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER,
        (void *)&desc->parent_partid, sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_PARENT_PART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER,
        (void *)&desc->part_id, sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_SUB_PART_ID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s", cursor->rowid.file,
                  cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name);
    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), UPDATE_COLUMN_COUNT_ONE);
    (void)row_put_int32(&ra, (uint32)initrans);
    cursor->update_info.count = UPDATE_COLUMN_COUNT_ONE;
    cursor->update_info.columns[0] = SYS_INDEXSUBPART_COL_INITRANS;  // index subpart initrans
    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);
    if (knl_internal_update(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

status_t part_get_btree_sub_seg_size(knl_session_t *session, knl_handle_t index, index_part_t *index_part,
    part_segment_desc_t part_segment_desc, int64 *result)
{
    page_id_t entry;
    int64 segment_size;
    uint32 pages, page_size, extents;
    index_t *idx = (index_t *)index;
    dc_entity_t *entity = idx->entity;
    table_t *table = &entity->table;
    int64 part_size = 0;
    uint32 part_no = part_segment_desc.part_start;
    uint32 part_cnt = part_segment_desc.part_end;

    index_part_t *index_subpart = NULL;
    for (uint32 i = part_no; i < part_cnt; i++) {
        index_subpart = PART_GET_SUBENTITY(idx->part_index, index_part->subparts[i]);
        if (index_subpart == NULL) {
            continue;
        }

        if (index_subpart->btree.segment == NULL) {
            table_part_t *table_part = TABLE_GET_PART(table, index_part->part_no);
            table_part_t *table_subpart = PART_GET_SUBENTITY(table->part_table, table_part->subparts[i]);
            if (dc_load_table_part_segment(session, entity, (table_part_t *)table_subpart) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }

        if (index_subpart->btree.segment == NULL) {
            continue;
        }

        entry = BTREE_SEGMENT(session, index_subpart->btree.entry, index_subpart->btree.segment)->extents.first;
        if (knl_get_segment_size(session, entry, &extents, &pages, &page_size) != CT_SUCCESS) {
            return CT_ERROR;
        }

        knl_calc_seg_size(part_segment_desc.type, pages, page_size, extents, &segment_size);
        part_size += segment_size;
    }
    *result = part_size;
    return CT_SUCCESS;
}

status_t part_get_btree_seg_size(knl_session_t *session, knl_handle_t index, index_part_t *index_part,
    seg_size_type_t type, int64 *part_size)
{
    page_id_t entry;
    int64 segment_size;
    uint32 pages, page_size, extents;
    index_t *idx = (index_t *)index;
    dc_entity_t *entity = idx->entity;
    table_t *table = &entity->table;
    *part_size = 0;
    if (!IS_PARENT_IDXPART(&index_part->desc)) {
        if (index_part->btree.segment == NULL) {
            table_part_t *table_part = TABLE_GET_PART(table, index_part->part_no);
            if (dc_load_table_part_segment(session, entity, table_part) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }

        if (index_part->btree.segment == NULL) {
            return CT_SUCCESS;
        }

        entry = BTREE_SEGMENT(session, index_part->btree.entry, index_part->btree.segment)->extents.first;
        if (knl_get_segment_size(session, entry, &extents, &pages, &page_size) != CT_SUCCESS) {
            return CT_ERROR;
        }

        knl_calc_seg_size(type, pages, page_size, extents, &segment_size);
        *part_size += segment_size;

        return CT_SUCCESS;
    }

    part_segment_desc_t part_segment_desc = {
        .type = type,
        .part_start = 0,
        .part_end = index_part->desc.subpart_cnt
    };

    return part_get_btree_sub_seg_size(session, index, index_part, part_segment_desc, part_size);
}

bool32 db_idx_part_has_seg(part_index_t *part_index, index_part_t *index_part)
{
    if (!IS_PARENT_IDXPART(&index_part->desc)) {
        bool32 has_segment = ((index_part->btree.segment == NULL) ? CT_FALSE : CT_TRUE);
        return has_segment;
    } else {
        index_part_t *index_subpart = NULL;
        for (uint32 i = 0; i < index_part->desc.subpart_cnt; i++) {
            index_subpart = PART_GET_SUBENTITY(part_index, index_part->subparts[i]);
            if (index_subpart == NULL) {
                continue;
            }

            if (index_subpart->btree.segment != NULL) {
                return CT_TRUE;
            }
        }
    }

    return CT_FALSE;
}

status_t db_upd_sub_idx_part_entry(knl_session_t *session, knl_index_part_desc_t *desc, page_id_t entry)
{
    row_assist_t ra;
    uint16 size;

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_SUB_INDEX_PARTS_ID, IX_SYS_INDEXSUBPART001_ID);
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&desc->uid,
        sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&desc->table_id,
        sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&desc->index_id,
        sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_INDEX_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER,
        (void *)&desc->parent_partid, sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_PARENT_PART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&desc->part_id,
        sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_SUB_PART_ID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s", cursor->rowid.file,
                  cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name);

    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), UPDATE_COLUMN_COUNT_TWO);
    (void)row_put_uint32(&ra, desc->space_id);
    (void)row_put_int64(&ra, *(int64 *)&entry);
    cursor->update_info.count = UPDATE_COLUMN_COUNT_TWO;
    cursor->update_info.columns[0] = SYS_INDEXSUBPART_COL_SPACE_ID;
    cursor->update_info.columns[1] = SYS_INDEXSUBPART_COL_ENTRY;  // index subpart entry
    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

    if (knl_internal_update(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

status_t db_upd_idx_subpart(knl_session_t *session, knl_index_part_desc_t *desc)
{
    row_assist_t ra;
    uint16 size;
    
    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_SUB_INDEX_PARTS_ID, IX_SYS_INDEXSUBPART001_ID);
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&desc->uid,
                     sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&desc->table_id,
                     sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&desc->index_id,
                     sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_INDEX_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER,
        (void *)&desc->parent_partid, sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_PARENT_PART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&desc->part_id,
                     sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_SUB_PART_ID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s", cursor->rowid.file,
                  cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name);

    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), UPDATE_COLUMN_COUNT_SIX);
    (void)row_put_int32(&ra, desc->space_id);
    (void)row_put_int64(&ra, desc->org_scn);
    (void)row_put_int64(&ra, *(int64 *)&desc->entry);
    (void)row_put_int32(&ra, desc->initrans);
    (void)row_put_int32(&ra, desc->pctfree);
    (void)row_put_int32(&ra, desc->flags);
    cursor->update_info.count = UPDATE_COLUMN_COUNT_SIX;
    cursor->update_info.columns[0] = SYS_INDEXSUBPART_COL_SPACE_ID;   // index part space id
    cursor->update_info.columns[1] = SYS_INDEXSUBPART_COL_ORG_SCN;   // index part org scn
    cursor->update_info.columns[2] = SYS_INDEXSUBPART_COL_ENTRY;   // index part entry
    cursor->update_info.columns[3] = SYS_INDEXSUBPART_COL_INITRANS;  // index part initrans
    cursor->update_info.columns[4] = SYS_INDEXSUBPART_COL_PCTFREE;  // index part pctfree
    cursor->update_info.columns[5] = SYS_INDEXSUBPART_COL_FLAGS;
    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

    if (knl_internal_update(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

status_t db_upd_parent_idx_partid(knl_session_t *session, knl_index_desc_t *desc, uint32 old_partid,
    uint32 new_partid)
{
    row_assist_t ra;

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_SUB_INDEX_PARTS_ID, IX_SYS_INDEXSUBPART001_ID);
    knl_init_index_scan(cursor, CT_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&desc->uid,
        sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&desc->table_id,
        sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&desc->id,
        sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_INDEX_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&old_partid,
        sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_PARENT_PART_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_INDEXSUBPART001_SUB_PART_ID);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, (void *)&desc->uid,
        sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, (void *)&desc->table_id,
        sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, (void *)&desc->id,
        sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_INDEX_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, (void *)&old_partid,
        sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_PARENT_PART_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_INDEXSUBPART001_SUB_PART_ID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    while (!cursor->eof) {
        row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), UPDATE_COLUMN_COUNT_ONE);
        (void)row_put_int32(&ra, (int32)new_partid);
        cursor->update_info.count = UPDATE_COLUMN_COUNT_ONE;
        cursor->update_info.columns[0] = SYS_INDEXSUBPART_COL_PPART_ID;  // parent part id
        cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, NULL);

        if (knl_internal_update(session, cursor) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }

        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

status_t db_upd_idx_part_id(knl_session_t *session, knl_cursor_t *cursor, table_part_t *table_part,
    uint32 index_id, uint32 new_partid)
{
    uint16 size;
    row_assist_t ra;

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_INDEXPART_ID, IX_SYS_INDEXPART001_ID);
    knl_init_index_scan(cursor, CT_TRUE);
    knl_scan_key_t *key = &cursor->scan_range.l_key;
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &table_part->desc.uid,
                     sizeof(uint32), IX_COL_SYS_INDEXPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &table_part->desc.table_id,
                     sizeof(uint32), IX_COL_SYS_INDEXPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &index_id,
                     sizeof(uint32), IX_COL_SYS_INDEXPART001_INDEX_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &table_part->desc.part_id,
                     sizeof(uint32), IX_COL_SYS_INDEXPART001_PART_ID);
    
    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        return CT_ERROR;
    }
    
    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s", cursor->rowid.file,
                  cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name);
    
    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), UPDATE_COLUMN_COUNT_ONE);
    (void)row_put_int32(&ra, (int32)new_partid);
    cursor->update_info.count = UPDATE_COLUMN_COUNT_ONE;
    cursor->update_info.columns[0] = SYS_INDEXPART_COL_PART_ID;
    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);
    if (knl_internal_update(session, cursor) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t db_upd_idx_part_ids(knl_session_t *session, knl_cursor_t *cursor, table_part_t *table_part,
    knl_dictionary_t *dc, uint32 new_partid)
{
    index_t *index = NULL;
    table_t *table = DC_TABLE(dc);

    for (uint32 i = 0; i < table->index_set.total_count; i++) {
        index = table->index_set.items[i];
        if (!IS_PART_INDEX(index)) {
            continue;
        }

        if (db_upd_idx_part_id(session, cursor, table_part, index->desc.id, new_partid) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (IS_PARENT_TABPART(&table_part->desc)) {
            if (db_upd_parent_idx_partid(session, &index->desc, table_part->desc.part_id, new_partid) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }
    }

    return CT_SUCCESS;
}

index_part_t* subpart_get_parent_idx_part(knl_handle_t idx, uint32 parent_partid)
{
    index_part_t *index_part = NULL;
    index_t *index = (index_t *)idx;
    table_t *table = &index->entity->table;
    table_part_t *table_part = NULL;
    part_index_t *part_index = index->part_index;
    uint32 partcnt = part_index->desc.partcnt;

    for (uint32 i = 0; i < partcnt; i++) {
        index_part = PART_GET_ENTITY(part_index, i);
        table_part = TABLE_GET_PART(table, i);
        if (!IS_READY_PART(table_part) || index_part == NULL) {
            continue;
        }
        
        if (parent_partid == index_part->desc.part_id) {
            return index_part;
        }
    }

    return NULL;
}

status_t subpart_delete_sub_idx_part(knl_session_t *session, knl_dictionary_t *dc, uint32 compart_no,
    uint32 subpart_no, bool32 reuse_storage)
{
    table_t *table = DC_TABLE(dc);
    index_t *index = NULL;
    index_part_t *index_part = NULL;
    index_part_t *index_subpart = NULL;
    bool32 is_changed = CT_FALSE;
    bool32 invalidate_index = CT_FALSE;

    table_part_t *table_part = TABLE_GET_PART(table, compart_no);
    table_part_t *table_subpart = PART_GET_SUBENTITY(table->part_table, table_part->subparts[subpart_no]);
    if (db_need_invalidate_index(session, dc, table, (table_part_t *)table_subpart, &invalidate_index) != CT_SUCCESS) {
        return CT_ERROR;
    }
    
    for (uint32 i = 0; i < table->index_set.total_count; i++) {
        index = table->index_set.items[i];
        if (index->desc.parted) {
            index_part = INDEX_GET_PART(index, compart_no);
            index_subpart = PART_GET_SUBENTITY(index->part_index, index_part->subparts[subpart_no]);
            if (db_update_sub_idxpart_status(session, index_subpart, CT_FALSE, &is_changed) != CT_SUCCESS) {
                return CT_ERROR;
            }

            if (btree_part_segment_prepare(session, (index_part_t *)index_subpart, reuse_storage,
                BTREE_TRUNCATE_PART_SEGMENT) != CT_SUCCESS) {
                return CT_ERROR;
            }
        } else {
            if (!invalidate_index) {
                continue;
            }
            
            if (db_update_index_status(session, index, CT_TRUE, &is_changed) != CT_SUCCESS) {
                return CT_ERROR;
            }
            if (btree_segment_prepare(session, index, CT_INVALID_ID32, BTREE_DROP_SEGMENT) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }
    }

    return CT_SUCCESS;
}
