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
 * knl_part_split.c
 *
 *
 * IDENTIFICATION
 * src/kernel/table/knl_part_split.c
 *
 * -------------------------------------------------------------------------
 */
 
#include "knl_part_output.h"
#include "cm_hash.h"
#include "cm_log.h"
#include "knl_table.h"
#include "ostat_load.h"
#include "knl_lob.h"
#include "knl_heap.h"
#include "knl_sys_part_defs.h"
#include "knl_part_inner.h"

static bool32 part_is_id_conflict(table_t *table, uint32 part_id)
{
    uint32 i;
    table_part_t *table_part = NULL;

    for (i = 0; i < table->part_table->desc.partcnt; i++) {
        table_part = TABLE_GET_PART(table, i);
        if (!IS_READY_PART(table_part)) {
            continue;
        }
        
        if (table_part->desc.part_id == part_id) {
            return GS_TRUE;
        }
    }

    return GS_FALSE;
}

static bool32 part_generate_split_id(table_t *table, uint32 split_id, uint32 *new_id1, uint32 *new_id2)
{
    table_part_t *table_part = TABLE_GET_PART(table, table->part_table->desc.partcnt - 1);
    uint32 last_part_id = table_part->desc.part_id;

    /* split from the first partition, find an non-conflict part id */
    if (split_id == 1) {
        *new_id1 = split_id + GS_DFT_PARTID_STEP;

        while (*new_id1 < split_id + GS_MAX_PART_ID_GAP) {
            if (part_is_id_conflict(table, *new_id1)) {
                *new_id1 += GS_DFT_PARTID_STEP;
                continue;
            }
            break;
        }

        /* if the new_id is much bigger than split part id, then adjust it to be smaller */
        if (*new_id1 - split_id >= GS_MAX_PART_ID_GAP) {
            *new_id1 = split_id + GS_DFT_PARTID_STEP + 1;
            for (;;) {
                if (!part_is_id_conflict(table, *new_id1)) {
                    break;
                }
                (*new_id1)++;
            }
        }

        *new_id2 = *new_id1 + GS_DFT_PARTID_STEP;
        return GS_TRUE;
    } else if (split_id == last_part_id) {
        /* split from the last partition */
        *new_id1 = last_part_id + 1;
        *new_id2 = last_part_id + 1 + GS_DFT_PARTID_STEP;
        return GS_FALSE;
    } else {
        /* split from other (non-first, non-last) partition */
        *new_id1 = split_id - 1;
        *new_id2 = split_id + 1;
        if (part_is_id_conflict(table, *new_id1)) {
            *new_id1 = split_id + GS_DFT_PARTID_STEP;
            for (;;) {
                if (!part_is_id_conflict(table, *new_id1)) {
                    break;
                }
                (*new_id1)++;
            }
            *new_id2 = *new_id1 + GS_DFT_PARTID_STEP;
            return GS_TRUE;
        } else if (part_is_id_conflict(table, *new_id2)) {
            *new_id1 += GS_DFT_PARTID_STEP;
            *new_id2 = *new_id1 + GS_DFT_PARTID_STEP;
            return GS_TRUE;
        } else {
            return GS_FALSE;
        }
    }
}

static uint32 part_split_get_update_pos(uint32 partcnt, table_t *table, uint32 split_id)
{
    uint32 split_pos = 0;
    table_part_t *table_part = NULL;

    for (uint32 i = 0; i < partcnt; i++) {
        table_part = TABLE_GET_PART(table, i);
        if (table_part->desc.part_id == split_id) {
            split_pos = i;
            break;
        }
    }

    return split_pos;
}

static status_t part_split_update_idx_rpids(knl_session_t *session, knl_cursor_t *cursor, index_t *index,
    uint32 split_pos, uint32 new_partid)
{
    row_assist_t ra;
    uint32 new_rpid;
    knl_index_part_desc_t desc;
    part_index_t *part_index = index->part_index;
    uint32 idx = part_index->desc.partcnt - 1;
    index_part_t *index_part = INDEX_GET_PART(index, split_pos + 1);
    uint32 old_partid = index_part->desc.part_id;

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_INDEXPART_ID, IX_SYS_INDEXPART001_ID);
    cursor->index_dsc = GS_TRUE;
    knl_init_index_scan(cursor, GS_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
        (void *)&part_index->desc.uid, sizeof(uint32), IX_COL_SYS_INDEXPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
        (void *)&part_index->desc.table_id, sizeof(uint32), IX_COL_SYS_INDEXPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
        (void *)&part_index->desc.index_id, sizeof(uint32), IX_COL_SYS_INDEXPART001_INDEX_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&old_partid,
        sizeof(uint32), IX_COL_SYS_INDEXPART001_PART_ID);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER,
        (void *)&part_index->desc.uid, sizeof(uint32), IX_COL_SYS_INDEXPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER,
        (void *)&part_index->desc.table_id, sizeof(uint32), IX_COL_SYS_INDEXPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER,
        (void *)&part_index->desc.index_id, sizeof(uint32), IX_COL_SYS_INDEXPART001_INDEX_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_INDEXPART001_PART_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    while (!cursor->eof) {
        new_rpid = new_partid + (idx - split_pos) * GS_DFT_PARTID_STEP;
        row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), UPDATE_COLUMN_COUNT_ONE);
        (void)row_put_int32(&ra, new_rpid);
        cursor->update_info.count = UPDATE_COLUMN_COUNT_ONE;
        cursor->update_info.columns[0] = SYS_INDEXPART_COL_PART_ID;  // index part id
        cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, NULL);

        if (knl_internal_update(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }

        dc_convert_index_part_desc(cursor, &desc);
        if (IS_PARENT_IDXPART(&desc)) {
            if (db_upd_parent_idx_partid(session, &index->desc, desc.part_id, new_rpid) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        idx--;
        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t part_split_update_idxs_rpids(knl_session_t *session, table_t *table, knl_cursor_t *cursor,
    uint32 org_partid, uint32 new_partid)
{
    index_t *index = NULL;
    index_set_t *index_set = &table->index_set;
    uint32 split_pos = part_split_get_update_pos(table->part_table->desc.partcnt, table, org_partid);

    for (uint32 i = 0; i < index_set->total_count; i++) {
        index = index_set->items[i];
        if (!IS_PART_INDEX(index)) {
            continue;
        }
        
        if (part_split_update_idx_rpids(session, cursor, index, split_pos, new_partid) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t part_split_update_lob_rpids(knl_session_t *session, knl_cursor_t *cursor, table_t *table, lob_t *lob,
    uint32 split_pos, uint32 new_partid)
{
    row_assist_t ra;
    uint32 idx = table->part_table->desc.partcnt - 1;
    knl_lob_part_desc_t desc;
    lob_part_t *lob_part = LOB_GET_PART(lob, split_pos + 1);
    uint32 old_partid = lob_part->desc.part_id;
    
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_LOBPART_ID, IX_SYS_LOBPART001_ID);
    cursor->index_dsc = GS_TRUE;
    knl_init_index_scan(cursor, GS_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
        (void *)&lob->desc.uid, sizeof(uint32), IX_COL_SYS_LOBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
        (void *)&lob->desc.table_id, sizeof(uint32), IX_COL_SYS_LOBPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
        (void *)&lob->desc.column_id, sizeof(uint32), IX_COL_SYS_LOBPART001_COLUMN_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
        (void *)&old_partid, sizeof(uint32), IX_COL_SYS_LOBPART001_PART_ID);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER,
        (void *)&lob->desc.uid, sizeof(uint32), IX_COL_SYS_LOBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER,
        (void *)&lob->desc.table_id, sizeof(uint32), IX_COL_SYS_LOBPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER,
        (void *)&lob->desc.column_id, sizeof(uint32), IX_COL_SYS_LOBPART001_COLUMN_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_LOBPART001_PART_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    while (!cursor->eof) {
        uint32 new_rpid = new_partid + (idx - split_pos) * GS_DFT_PARTID_STEP;
        row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), UPDATE_COLUMN_COUNT_ONE);
        (void)row_put_int32(&ra, *(int32 *)&new_rpid);
        cursor->update_info.count = UPDATE_COLUMN_COUNT_ONE;
        cursor->update_info.columns[0] = SYS_LOBPART_COL_PART_ID;
        cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, NULL);

        if (knl_internal_update(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }

        dc_convert_lob_part_desc(cursor, &desc);
        if (IS_PARENT_LOBPART(&desc)) {
            if (db_update_parent_lobpartid(session, &lob->desc, desc.part_id, new_rpid) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        idx--;
        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t part_split_update_lobs_rpids(knl_session_t *session, knl_dictionary_t *dc, knl_cursor_t *cursor,
    uint32 org_partid, uint32 new_partid)
{
    dc_entity_t *entity = DC_ENTITY(dc);
    table_t *table = &entity->table;
    knl_column_t *column = NULL;
    lob_t *lob = NULL;
    uint32 partcnt = table->part_table->desc.partcnt;
    uint32 split_pos = part_split_get_update_pos(partcnt, table, org_partid);

    for (uint32 i = 0; i < table->desc.column_count; i++) {
        column = dc_get_column(entity, i);
        if (!COLUMN_IS_LOB(column)) {
            continue;
        }

        lob = (lob_t *)column->lob;
        if (part_split_update_lob_rpids(session, cursor, table, lob, split_pos, new_partid) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t part_split_update_table_rpids(knl_session_t *session, knl_cursor_t *cursor, table_t *table,
    uint32 org_partid, uint32 new_partid)
{
    row_assist_t ra;
    uint32 new_rpid;
    knl_table_part_desc_t desc;
    uint32 partcnt = table->part_table->desc.partcnt;
    uint32 split_pos = part_split_get_update_pos(partcnt, table, org_partid);
    table_part_t *table_part = TABLE_GET_PART(table, split_pos + 1);
    uint32 old_partid = table_part->desc.part_id;
    uint32 idx = partcnt - 1;

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_TABLEPART_ID, IX_SYS_TABLEPART001_ID);
    cursor->index_dsc = GS_TRUE;
    knl_init_index_scan(cursor, GS_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&table->desc.uid,
        sizeof(uint32), IX_COL_SYS_TABLEPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&table->desc.id,
        sizeof(uint32), IX_COL_SYS_TABLEPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&old_partid,
        sizeof(uint32), IX_COL_SYS_TABLEPART001_PART_ID);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, (void *)&table->desc.uid,
        sizeof(uint32), IX_COL_SYS_TABLEPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, (void *)&table->desc.id,
        sizeof(uint32), IX_COL_SYS_TABLEPART001_TABLE_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_TABLEPART001_PART_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    while (!cursor->eof) {
        new_rpid = new_partid + (idx - split_pos) * GS_DFT_PARTID_STEP;
        row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), UPDATE_COLUMN_COUNT_ONE);
        (void)row_put_int32(&ra, (int32)new_rpid);
        cursor->update_info.count = UPDATE_COLUMN_COUNT_ONE;
        cursor->update_info.columns[0] = SYS_TABLEPART_COL_PART_ID;  // table part id
        cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, NULL);
        if (knl_internal_update(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }

        dc_convert_table_part_desc(cursor, &desc);
        if (IS_PARENT_TABPART(&desc)) {
            if (db_update_parent_tabpartid(session, desc.uid, desc.table_id, desc.part_id, new_rpid) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        idx--;
        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    knl_panic_log(idx == split_pos, "the idx is not equal to split_pos, panic info: page %u-%u type %u table %s "
                  "table_part %s idx %u split_pos %u", cursor->rowid.file, cursor->rowid.page,
                  ((page_head_t *)cursor->page_buf)->type, table->desc.name, table_part->desc.name, idx, split_pos);
    return GS_SUCCESS;
}

static int32 part_compare_split_border(part_key_t *key, part_table_t *part_table, uint32 new_pno)
{
    knl_part_key_t part_key;
    table_part_t *table_part = NULL;
    int32 result;

    knl_decode_part_key(key, &part_key);

    table_part = PART_GET_ENTITY(part_table, new_pno);
    knl_panic_log(table_part->desc.groupcnt == 1,
                  "table_part's groupcnt is abnormal, panic info: table_part %s groupcnt %u",
                  table_part->desc.name, table_part->desc.groupcnt);
    result = part_compare_range_key(part_table->keycols, table_part->desc.groups, &part_key.decoder);

    return result;
}

static status_t part_split_compare_range_key(knl_session_t *session, part_table_t *part_table,
                                             knl_cursor_t *cursor_delete, uint32 left_pno, int32 *result)
{
    part_key_t *key = NULL;

    key = (part_key_t *)cm_push(session->stack, GS_MAX_COLUMN_SIZE);
    errno_t ret = memset_sp(key, GS_MAX_COLUMN_SIZE, 0, GS_MAX_COLUMN_SIZE);
    knl_securec_check(ret);
    if (part_generate_part_key(session, cursor_delete->row, cursor_delete->offsets, cursor_delete->lens,
        part_table, key) != GS_SUCCESS) {
        cm_pop(session->stack);
        return GS_ERROR;
    }

    *result = part_compare_split_border(key, part_table, left_pno);

    cm_pop(session->stack);

    return GS_SUCCESS;
}

static status_t part_split_drop_newpart(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def,
    bool32 reuse_orgpart)
{
    knl_part_def_t *new_part = (knl_part_def_t *)cm_galist_get(&def->part_def.obj_def->parts, 0);

    def->options |= DROP_IF_EXISTS;
    def->part_def.name = new_part->name;
    if (db_altable_drop_part(session, dc, def, GS_FALSE) != GS_SUCCESS) {
        return GS_ERROR;
    }
    GS_LOG_DEBUG_INF("drop the left spliting part %s", T2S(&def->part_def.name));

    if (reuse_orgpart) {
        return GS_SUCCESS;
    }

    new_part = (knl_part_def_t *)cm_galist_get(&def->part_def.obj_def->parts, 1);
    def->options |= DROP_IF_EXISTS;
    def->part_def.name = new_part->name;
    if (db_altable_drop_part(session, dc, def, GS_FALSE) != GS_SUCCESS) {
        return GS_ERROR;
    }
    GS_LOG_DEBUG_INF("drop the right spliting part %s", T2S(&def->part_def.name));
    return GS_SUCCESS;
}

static status_t part_split_invalidate_global_index(knl_session_t *session, knl_handle_t knl_table)
{
    index_t *index = NULL;
    bool32 is_changed = GS_FALSE;
    table_t *table = (table_t *)knl_table;
    
    for (uint32 i = 0; i < table->index_set.total_count; i++) {
        index = table->index_set.items[i];

        if (!IS_PART_INDEX(index)) {
            if (db_update_index_status(session, index, GS_TRUE, &is_changed) != GS_SUCCESS) {
                return GS_ERROR;
            }

            if (btree_segment_prepare(session, index, GS_INVALID_ID32, BTREE_DROP_SEGMENT) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }

    return GS_SUCCESS;
}

static status_t part_split_rebuild_global_index(knl_session_t *session, knl_dictionary_t *dc, knl_handle_t knl_table)
{
    knl_alindex_def_t def;
    index_t *index = NULL;
    table_t *table = (table_t *)knl_table;

    for (uint32 i = 0; i < table->index_set.total_count; i++) {
        index = table->index_set.items[i];
      
        if (!IS_PART_INDEX(index) && index->desc.is_invalid) {
            cm_str2text(index->desc.name, &def.name);
            def.rebuild.space.str = NULL;
            def.rebuild.build_stats = GS_FALSE;
            def.rebuild.pctfree = GS_INVALID_ID32;
            def.rebuild.cr_mode = index->desc.cr_mode;
            def.rebuild.is_online = GS_FALSE;
            def.rebuild.parallelism = 0;
            def.rebuild.specified_parts = 0;
            def.rebuild.lock_timeout = LOCK_INF_WAIT;
            if (db_alter_index_rebuild(session, &def, dc, index) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }

    return GS_SUCCESS;
}

static status_t part_split_precheck(knl_session_t *session, table_t *table,
    knl_altable_def_t *def, table_part_t *split_part)
{
    part_table_t *part_table = table->part_table;
    knl_part_obj_def_t *obj_def = def->part_def.obj_def;
    uint32 split_partno = split_part->part_no;

    if (part_table->desc.parttype != PART_TYPE_RANGE || part_table->desc.interval_key != NULL) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "split partition", "non-range partitioned table");
        return GS_ERROR;
    }
    
    /* if specify update global index clause, need to rebuild the global index, no need to check reference */
    if (!def->part_def.global_index_option) {
        if (db_table_is_referenced(session, table, GS_TRUE)) {
            GS_THROW_ERROR(ERR_TABLE_IS_REFERENCED);
            return GS_ERROR;
        }
    }

    if (table->part_table->desc.partcnt + GS_SPLIT_PART_COUNT - 1 > GS_MAX_PART_COUNT) {
        GS_THROW_ERROR(ERR_EXCEED_MAX_PARTCNT, (uint32)GS_MAX_PART_COUNT);
        return GS_ERROR;
    }

    table_part_t *table_part = NULL;
    knl_part_def_t *left_def = (knl_part_def_t *)cm_galist_get(&obj_def->parts, 0);
    knl_part_def_t *right_def = (knl_part_def_t *)cm_galist_get(&obj_def->parts, 1);

    /* last split failed, the sys_table_parts table has one entry which is not ready.
     * the name of this not ready part can be reused
     */
    if ((part_table_find_by_name(part_table, &left_def->name, &table_part) && !table_part->desc.not_ready) ||
        (part_table_find_by_name(part_table, &right_def->name, &table_part) && !table_part->desc.not_ready &&
        table_part->part_no != split_partno)) {
        GS_THROW_ERROR(ERR_DUPLICATE_PART_NAME);
        return GS_ERROR;
    }

    table_part_t *table_subpart = NULL;
    if (subpart_table_find_by_name(part_table, &left_def->name, &table_part, &table_subpart) ||
        subpart_table_find_by_name(part_table, &right_def->name, &table_part, &table_subpart)) {
        GS_THROW_ERROR(ERR_DUPLICATE_PART_NAME);
        return GS_ERROR;
    }

    if (split_partno == 0) { // split the first part, no need to check the left bound of spliting partition
        return GS_SUCCESS;
    }
    
    knl_part_key_t part_key;
    uint32 pre_partno = split_partno - 1;
    table_part = TABLE_GET_PART(table, pre_partno);
    knl_part_column_desc_t *column_desc = part_table->keycols;
    knl_decode_part_key(left_def->partkey, &part_key);
    if (part_compare_range_key(column_desc, &part_key.decoder, table_part->desc.groups) <= 0) {
        GS_THROW_ERROR(ERR_INVALID_PART_KEY, "split partition bound must collate higher than its previous partition.");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

/* for spliting partition, we will spilt the orignal part id into two new part ids. the new part ids may be conflict
 * with the id of the right partitions of the spltting partition, so it's need to update the ids of these right parts.
 * rpids: right part ids
 */
static status_t part_split_update_rpids(knl_session_t *session, knl_dictionary_t *dc, uint32 org_partid,
    uint32 new_partid)
{
    table_t *table = DC_TABLE(dc);

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    if (part_split_update_table_rpids(session, cursor, table, org_partid, new_partid) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (part_split_update_idxs_rpids(session, table, cursor, org_partid, new_partid) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (part_split_update_lobs_rpids(session, dc, cursor, org_partid, new_partid) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static status_t part_split_create_new_subparts(knl_session_t *session, knl_cursor_t *cursor, table_t *table,
    table_part_t *split_part, knl_table_part_desc_t *parent_desc)
{
    errno_t ret;
    table_part_t *subpart = NULL;
    knl_table_part_desc_t desc = { 0 };

    for (uint32 i = 0; i < split_part->desc.subpart_cnt; i++) {
        subpart = PART_GET_SUBENTITY(table->part_table, split_part->subparts[i]);
        if (subpart == NULL) {
            continue;
        }

        ret = memcpy_sp(&desc, sizeof(knl_table_part_desc_t), &subpart->desc, sizeof(knl_table_part_desc_t));
        knl_securec_check(ret);

        /* update the new left subpart's desc */
        desc.entry = INVALID_PAGID;
        desc.parent_partid = parent_desc->part_id;
        desc.org_scn = db_inc_scn(session);
        desc.seg_scn = desc.org_scn;
        desc.space_id = parent_desc->space_id;
        desc.is_nologging = GS_FALSE;
        
        int64 object_id;
        text_t name;
        text_t sys;
        
        cm_str2text("OBJECT_ID$", &name);
        cm_str2text("SYS", &sys);
        if (knl_seq_nextval(session, &sys, &name, &object_id) != GS_SUCCESS) {
            return GS_ERROR;
        }
        
        ret = snprintf_s(desc.name, GS_NAME_BUFFER_SIZE, GS_NAME_BUFFER_SIZE - 1, "SYS_SUBP%llX", object_id);
        knl_securec_check_ss(ret);

        if (db_write_sys_tablesubpart(session, cursor, &desc) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t part_split_create_new_tabpart(knl_session_t *session, knl_dictionary_t *dc, table_part_t *split_part,
    knl_table_part_desc_t *desc)
{
    table_t *table = DC_TABLE(dc);
    bool32 is_encrypt_table = SPACE_IS_ENCRYPT(SPACE_GET(session, table->desc.space_id));
    if (!check_part_encrypt_allowed(session, is_encrypt_table, desc->space_id)) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "add partiton", "cases: add encrypt partition to non-encrypt \
part table or add non-encrypt partition to encrypt part table.");
        return GS_ERROR;
    }

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    if (db_write_sys_tablepart(session, cursor, &table->desc, desc) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (desc->storaged && db_write_sysstorage(session, cursor, desc->org_scn, &desc->storage_desc) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (desc->compress) {
        if (db_write_syscompress(session, cursor, desc->space_id, desc->org_scn, desc->compress_algo,
            COMPRESS_OBJ_TYPE_TABLE_PART) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    if (desc->is_parent) {
        if (part_split_create_new_subparts(session, cursor, table, split_part, desc) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    if (db_update_part_count(session, table->desc.uid, table->desc.id, GS_INVALID_ID32, GS_TRUE) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static status_t part_split_create_new_subidxpart(knl_session_t *session, knl_cursor_t *cursor, table_t *table,
    table_part_t *split_part, knl_table_part_desc_t *part_desc)
{
    errno_t ret;
    index_t *index = NULL;
    index_part_t *index_part = NULL;
    index_part_t *index_subpart = NULL;
    knl_index_part_desc_t desc = { 0 };

    for (uint32 i = 0; i < table->index_set.total_count; i++) {
        index = table->index_set.items[i];
        if (!IS_PART_INDEX(index)) {
            continue;
        }

        index_part = INDEX_GET_PART(index, split_part->part_no);
        knl_panic_log(IS_PARENT_IDXPART(&index_part->desc), "current index_part is not parent idxpart, panic info: "
            "table %s split_part %s index %s index_part %s index_part %s", table->desc.name,
            split_part->desc.name, index->desc.name, index_part->desc.name, index_subpart->desc.name);
        for (uint32 j = 0; j < index_part->desc.subpart_cnt; j++) {
            index_subpart = PART_GET_SUBENTITY(index->part_index, index_part->subparts[j]);
            if (index_subpart == NULL) {
                continue;
            }

            ret = memcpy_sp(&desc, sizeof(knl_index_part_desc_t), &index_subpart->desc, sizeof(knl_index_part_desc_t));
            knl_securec_check(ret);

            desc.entry = INVALID_PAGID;
            desc.parent_partid = part_desc->part_id;
            desc.org_scn = db_inc_scn(session);
            desc.seg_scn = desc.org_scn;
            ret = snprintf_s(desc.name, GS_NAME_BUFFER_SIZE, GS_NAME_BUFFER_SIZE - 1, "SYS_P%llX", desc.org_scn);
            knl_securec_check_ss(ret);

            if (db_write_sys_indsubpart(session, cursor, &desc) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }
    return GS_SUCCESS;
}

static status_t part_split_create_new_index_part(knl_session_t *session, table_t *table, table_part_t *split_part,
    knl_table_part_desc_t *part_desc)
{
    index_part_t *index_part = NULL;
    index_part_t *index_subpart = NULL;
    knl_index_part_desc_t desc;
    text_t text;

    CM_SAVE_STACK(session->stack);
    cm_str2text(part_desc->name, &text);
    knl_cursor_t *cursor = knl_push_cursor(session);

    for (uint32 i = 0; i < table->index_set.total_count; i++) {
        index_t *index = table->index_set.items[i];
        if (!IS_PART_INDEX(index)) {
            continue;
        }

        if (db_update_part_count(session, index->desc.uid, index->desc.table_id,
            index->desc.id, GS_TRUE) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        index_part = INDEX_GET_PART(index, split_part->part_no);
        errno_t ret = memcpy_sp(&desc, sizeof(knl_index_part_desc_t), &index_part->desc, sizeof(knl_index_part_desc_t));
        knl_securec_check(ret);
        ret = memcpy_sp(desc.name, GS_NAME_BUFFER_SIZE, part_desc->name, GS_NAME_BUFFER_SIZE);
        knl_securec_check(ret);
        desc.entry = INVALID_PAGID;
        desc.org_scn = db_inc_scn(session);
        desc.seg_scn = desc.org_scn;
        desc.part_id = part_desc->part_id;
        desc.is_not_ready = part_desc->not_ready;

        // If part index name has duplicated, use sys generated name instead.
        if (part_idx_find_by_name(index->part_index, &text, &index_part) ||
            subpart_idx_find_by_name(index->part_index, &text, &index_subpart)) {
            ret = snprintf_s(desc.name, GS_NAME_BUFFER_SIZE, GS_NAME_BUFFER_SIZE - 1, "SYS_P%llX", desc.org_scn);
            knl_securec_check_ss(ret);
        }

        if (db_write_sys_indexpart(session, cursor, &desc) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    if (!part_desc->is_parent) {
        CM_RESTORE_STACK(session->stack);
        return GS_SUCCESS;
    }

    if (part_split_create_new_subidxpart(session, cursor, table, split_part, part_desc) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static status_t part_split_create_new_lobpart(knl_session_t *session, knl_dictionary_t *dc, knl_part_def_t *def,
    knl_table_part_desc_t *part_desc, table_part_t *split_part)
{
    errno_t ret;
    uint32 space_id;
    table_t *table = DC_TABLE(dc);
    dc_entity_t *entity = DC_ENTITY(dc);
    knl_lob_part_desc_t lob_desc = { 0 };

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    cursor->row = (row_head_t *)cursor->buf;

    for (uint32 i = 0; i < table->desc.column_count; i++) {
        knl_column_t *column = dc_get_column(entity, i);
        if (!COLUMN_IS_LOB(column)) {
            continue;
        }

        lob_t *lob = (lob_t *)column->lob;
        if (part_lob_get_space_id(session, lob, def, &space_id) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        part_init_lob_part_desc(session, &lob->desc, part_desc->part_id, space_id, &lob_desc);
        if (part_desc->is_parent) {
            lob_desc.subpart_cnt = part_desc->subpart_cnt;
            lob_desc.is_parent = GS_TRUE;
        }

        if (part_write_sys_lobpart(session, cursor, &lob_desc) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        if (part_desc->is_parent) {
            lob_part_t *part = LOB_GET_PART(lob, split_part->part_no);
            for (uint32 j = 0; j < part->desc.subpart_cnt; j++) {
                lob_part_t *subpart = PART_GET_SUBENTITY(lob->part_lob, part->subparts[j]);
                ret = memcpy_sp(&lob_desc, sizeof(knl_lob_part_desc_t), &subpart->desc, sizeof(knl_lob_part_desc_t));
                knl_securec_check(ret);

                lob_desc.entry = INVALID_PAGID;
                lob_desc.parent_partid = part_desc->part_id;
                lob_desc.org_scn = db_inc_scn(session);
                lob_desc.seg_scn = lob_desc.org_scn;

                if (subpart_write_syslob(session, &lob_desc) != GS_SUCCESS) {
                    CM_RESTORE_STACK(session->stack);
                    return GS_ERROR;
                }
            }
        }
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

/* generate new part desc: we can optionally specify new attributes for the partitions resulting from the split.
 * any attributes that do not specified are inherited from the original partition.
 */
static status_t part_split_get_partdesc(knl_session_t *session, knl_part_def_t *part_def, table_part_t *split_part,
                                        uint32 part_id, knl_table_part_desc_t *desc)
{
    errno_t ret = memcpy_sp(desc, sizeof(knl_table_part_desc_t), &split_part->desc, sizeof(knl_table_part_desc_t));
    knl_securec_check(ret);

    /* org_scn must be update */
    desc->org_scn = db_inc_scn(session);
    
    ret = memcpy_sp(desc->name, GS_NAME_BUFFER_SIZE, part_def->name.str, part_def->name.len);
    knl_securec_check(ret);
    desc->name[part_def->name.len] = '\0';
    
    if (part_def->space.len != 0) {
        if (spc_get_space_id(session, &part_def->space, part_def->is_for_create_db, &desc->space_id) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (part_def->initrans > 0) {
        desc->initrans = part_def->initrans;
    }

    if (part_def->pctfree != GS_INVALID_ID32) {
        desc->pctfree = part_def->pctfree;
    }

    space_t *space = SPACE_GET(session, desc->space_id);
    if (part_def->storage_def.initial > 0 && !dc_is_reserved_entry(split_part->desc.uid, split_part->desc.table_id)) {
        desc->storaged = GS_TRUE;
        desc->storage_desc.initial = CM_CALC_ALIGN((uint64)part_def->storage_def.initial, space->ctrl->block_size) /
            space->ctrl->block_size;
    }

    if (part_def->storage_def.maxsize > 0 && !dc_is_reserved_entry(split_part->desc.uid, split_part->desc.table_id)) {
        desc->storaged = GS_TRUE;
        desc->storage_desc.max_pages = CM_CALC_ALIGN((uint64)part_def->storage_def.maxsize, space->ctrl->block_size) /
            space->ctrl->block_size;
    }

    desc->part_id = part_id;
    desc->not_ready = GS_TRUE;
    desc->entry = INVALID_PAGID;
    if (desc->compress_algo > COMPRESS_NONE) {
        if (!IS_SPACE_COMPRESSIBLE(space)) {
            GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "split part table",
                "non user bitmap tablespace");
            return GS_ERROR;
        }
    }
    desc->compress = (desc->compress_algo > COMPRESS_NONE) ? GS_TRUE : GS_FALSE;

    return GS_SUCCESS;
}

static status_t part_split_create_newpart(knl_session_t *session, knl_dictionary_t *dc, knl_part_def_t *part_def,
    knl_table_part_desc_t *desc, table_part_t *split_part)
{
    table_t *table = DC_TABLE(dc);

    if (IS_PARENT_TABPART(&split_part->desc)) {
        part_def->is_parent = GS_TRUE;
    }

    if (part_split_create_new_tabpart(session, dc, split_part, desc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (part_split_create_new_index_part(session, table, split_part, desc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (part_split_create_new_lobpart(session, dc, part_def, desc, split_part) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t part_split_create_newparts(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def,
    table_part_t *split_part, bool32 reuse_orgpart, uint32 *new_partid)
{
    knl_table_part_desc_t desc;
    table_t *table = DC_TABLE(dc);
    
    /* generate part id for new partition.
     * if the new part id is conflict with the right parts, it's need to update the part id of all right parts
     */
    uint32 left_partid, right_partid;
    bool32 update_part_ids = part_generate_split_id(table, split_part->desc.part_id, &left_partid, &right_partid);
    if (update_part_ids) {
        if (part_split_update_rpids(session, dc, split_part->desc.part_id, right_partid) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    *new_partid = right_partid;
    knl_part_def_t *part_def = (knl_part_def_t *)cm_galist_get(&def->part_def.obj_def->parts, 0);
    if (part_split_get_partdesc(session, part_def, split_part, left_partid, &desc) != GS_SUCCESS) {
        return GS_ERROR;
    }
    
    desc.hiboundval = part_def->hiboundval;
    desc.bhiboundval.bytes = (uint8 *)part_def->partkey;
    desc.bhiboundval.size = part_def->partkey->size;
    desc.is_nologging = GS_FALSE;
    if (part_split_create_newpart(session, dc, part_def, &desc, split_part) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (reuse_orgpart) {
        return GS_SUCCESS;
    }

    part_def = (knl_part_def_t *)cm_galist_get(&def->part_def.obj_def->parts, 1);
    if (part_split_get_partdesc(session, part_def, split_part, right_partid, &desc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    desc.is_nologging = GS_FALSE;
    if (part_split_create_newpart(session, dc, part_def, &desc, split_part) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t part_split_redisdata_open_cursor(knl_session_t *session, knl_dictionary_t *dc,
    knl_cursor_t *cursor_delete, knl_cursor_t *cursor_insert)
{
    cursor_delete->scan_mode = SCAN_MODE_TABLE_FULL;
    cursor_delete->action = CURSOR_ACTION_DELETE;
    cursor_delete->is_splitting = GS_TRUE;
    if (knl_open_cursor(session, cursor_delete, dc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    cursor_insert->scan_mode = SCAN_MODE_TABLE_FULL;
    cursor_insert->action = CURSOR_ACTION_INSERT;
    cursor_insert->is_splitting = GS_TRUE;
    if (knl_open_cursor(session, cursor_insert, dc) != GS_SUCCESS) {
        knl_close_cursor(session, cursor_delete);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static void part_split_redisdata_close_cursor(knl_session_t *session, knl_cursor_t *cursor_delete,
    knl_cursor_t *cursor_insert)
{
    knl_close_cursor(session, cursor_delete);
    knl_close_cursor(session, cursor_insert);
}

static status_t part_split_redis_get_newparts(table_t *table, knl_altable_def_t *def, table_part_t **left_part,
    table_part_t **right_part, bool32 reuse_orgpart)
{
    part_table_t *part_table = table->part_table;
    table_part_t *table_part = NULL;
    knl_part_def_t *left_part_def = (knl_part_def_t *)cm_galist_get(&def->part_def.obj_def->parts, 0);
    knl_part_def_t *right_part_def = (knl_part_def_t *)cm_galist_get(&def->part_def.obj_def->parts, 1);
    
    for (uint32 i = 0; i < part_table->desc.partcnt + part_table->desc.not_ready_partcnt; i++) {
        table_part = TABLE_GET_PART(table, i);
        if (!IS_READY_PART(table_part)) {
            continue;
        }
        
        if (cm_compare_text_str(&left_part_def->name, table_part->desc.name) == 0 && table_part->desc.not_ready) {
            *left_part = table_part;
        }

        if (cm_compare_text_str(&right_part_def->name, table_part->desc.name) == 0 && table_part->desc.not_ready) {
            *right_part = table_part;
        }
    }
    
    if (*left_part == NULL) {
        GS_LOG_DEBUG_INF("could not find the part, name is %s", T2S(&left_part_def->name));
        GS_THROW_ERROR(ERR_PARTITION_NOT_EXIST, "table", T2S(&left_part_def->name));
        return GS_ERROR;
    }

    if (*right_part == NULL && !reuse_orgpart) {
        GS_LOG_DEBUG_INF("could not find the part, name is %s", T2S(&right_part_def->name));
        GS_THROW_ERROR(ERR_PARTITION_NOT_EXIST, "table", T2S(&right_part_def->name));
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t part_split_match_redis_pno(void *handle, bool32 *matched)
{
    int32 result;
    split_redistribute_t *redistribute_cond = (split_redistribute_t *)handle;
    part_table_t *part_table = redistribute_cond->part_table;
    knl_cursor_t *cursor_delete = redistribute_cond->cursor_delete;
    uint32 left_pno = redistribute_cond->left_pno;

    if (part_split_compare_range_key(redistribute_cond->session, part_table, cursor_delete,
        left_pno, &result) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (result > 0) {
        *matched = GS_TRUE;
        return GS_SUCCESS;
    }

    *matched = GS_FALSE;
    return GS_SUCCESS;
}

static status_t part_split_redis_entity_reuse(knl_session_t *session, knl_dictionary_t *dc, knl_cursor_t *cursor_delete,
    knl_cursor_t *cursor_insert, knl_altable_def_t *def)
{
    status_t status = GS_SUCCESS;
    table_t *table = DC_TABLE(dc);
    table_part_t *left_part = NULL;
    table_part_t *right_part = NULL;
    knl_match_cond_t org_match_cond = session->match_cond;

    if (part_split_redis_get_newparts(table, def, &left_part, &right_part, GS_TRUE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    CM_SAVE_STACK(session->stack);
    cursor_delete->stmt = cm_push(session->stack, sizeof(split_redistribute_t));
    session->match_cond = part_split_match_redis_pno;
    split_redistribute_t *redistribute_cond = (split_redistribute_t *)cursor_delete->stmt;
    
    // initialize the match condition structure
    redistribute_cond->session = session;
    redistribute_cond->cursor_delete = cursor_delete;
    redistribute_cond->left_pno = left_part->part_no;
    redistribute_cond->part_table = table->part_table;
    if (knl_fetch(session, cursor_delete) != GS_SUCCESS) {
        session->match_cond = org_match_cond;
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    while (!cursor_delete->eof) {
        cursor_insert->part_loc.part_no = left_part->part_no;
        if (IS_SUB_TABPART(&((table_part_t *)cursor_delete->table_part)->desc)) {
            if (part_redis_get_subpartno(session, dc, cursor_delete, cursor_insert) != GS_SUCCESS) {
                status = GS_ERROR;
                break;
            }
        } else {
            cursor_insert->part_loc.subpart_no = GS_INVALID_ID32;
            knl_set_table_part(cursor_insert, cursor_insert->part_loc);
        }

        if (knl_copy_row(session, cursor_delete, cursor_insert) != GS_SUCCESS) {
            status = GS_ERROR;
            break;
        }

        if (knl_internal_delete(session, cursor_delete) != GS_SUCCESS) {
            status = GS_ERROR;
            break;
        }

        if (knl_internal_insert(session, cursor_insert) != GS_SUCCESS) {
            status = GS_ERROR;
            break;
        }

        if (knl_fetch(session, cursor_delete) != GS_SUCCESS) {
            status = GS_ERROR;
            break;
        }
    }

    session->match_cond = org_match_cond;
    CM_RESTORE_STACK(session->stack);
    return status;
}

static status_t part_split_redis_entity(knl_session_t *session, knl_dictionary_t *dc, knl_cursor_t *cursor_delete,
    knl_cursor_t *cursor_insert, knl_altable_def_t *def, bool32 reuse_orgpart)
{
    int32 result;
    table_t *table = DC_TABLE(dc);
    table_part_t *left_part = NULL;
    table_part_t *right_part = NULL;

    if (reuse_orgpart) {
        return part_split_redis_entity_reuse(session, dc, cursor_delete, cursor_insert, def);
    }
    
    if (part_split_redis_get_newparts(table, def, &left_part, &right_part, GS_FALSE) != GS_SUCCESS) {
        return GS_ERROR;
    }
    
    if (knl_fetch(session, cursor_delete) != GS_SUCCESS) {
        return GS_ERROR;
    }

    while (!cursor_delete->eof) {
        if (part_split_compare_range_key(session, table->part_table, cursor_delete, left_part->part_no,
            &result) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (result > 0) {
            cursor_insert->part_loc.part_no = left_part->part_no;
        } else {
            cursor_insert->part_loc.part_no = right_part->part_no;
        }

        if (IS_SUB_TABPART(&((table_part_t *)cursor_delete->table_part)->desc)) {
            if (part_redis_get_subpartno(session, dc, cursor_delete, cursor_insert) != GS_SUCCESS) {
                return GS_ERROR;
            }
        } else {
            cursor_insert->part_loc.subpart_no = GS_INVALID_ID32;
            knl_set_table_part(cursor_insert, cursor_insert->part_loc);
        }

        if (knl_copy_row(session, cursor_delete, cursor_insert) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (knl_internal_delete(session, cursor_delete) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (knl_internal_insert(session, cursor_insert) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (knl_fetch(session, cursor_delete) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t part_split_redis_rows(knl_session_t *session, knl_dictionary_t *dc, knl_cursor_t *cursor_delete,
    knl_cursor_t *cursor_insert, knl_altable_def_t *def, bool32 reuse_orgpart)
{
    table_t *table = DC_TABLE(dc);
    table_part_t *split_part = TABLE_GET_PART(table, cursor_delete->part_loc.part_no);

    if (IS_PARENT_TABPART(&split_part->desc)) {
        for (uint32 i = 0; i < split_part->desc.subpart_cnt; i++) {
            cursor_delete->part_loc.subpart_no = i;
            knl_set_table_part(cursor_delete, cursor_delete->part_loc);
            if (knl_reopen_cursor(session, cursor_delete, dc) != GS_SUCCESS) {
                return GS_ERROR;
            }
            
            if (part_split_redis_entity(session, dc, cursor_delete, cursor_insert, def, reuse_orgpart) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    } else {
        cursor_delete->part_loc.subpart_no = GS_INVALID_ID32;
        knl_set_table_part(cursor_delete, cursor_delete->part_loc);
        if (knl_reopen_cursor(session, cursor_delete, dc) != GS_SUCCESS) {
            return GS_ERROR;
        }
        
        if (part_split_redis_entity(session, dc, cursor_delete, cursor_insert, def, reuse_orgpart) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t part_split_redis_data(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def,
    table_part_t *split_part, bool32 reuse_orgpart)
{
    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor_delete = knl_push_cursor(session);
    knl_cursor_t *cursor_insert = knl_push_cursor(session);
    if (part_split_redisdata_open_cursor(session, dc, cursor_delete, cursor_insert) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    cursor_insert->row = (row_head_t *)cm_push(session->stack, GS_MAX_ROW_SIZE);
    cursor_delete->part_loc.part_no = split_part->part_no;
    if (part_split_redis_rows(session, dc, cursor_delete, cursor_insert, def, reuse_orgpart) != GS_SUCCESS) {
        part_split_redisdata_close_cursor(session, cursor_delete, cursor_insert);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }
    
    part_split_redisdata_close_cursor(session, cursor_delete, cursor_insert);
    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static status_t part_split_refresh_tabpart(knl_session_t *session, knl_cursor_t *cursor, table_part_t *split_part,
    const char *new_name)
{
    uint16 size;
    row_assist_t ra;

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_TABLEPART_ID, IX_SYS_TABLEPART001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_scan_key_t *key = &cursor->scan_range.l_key;
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_INTEGER, &split_part->desc.uid,
                     sizeof(uint32), IX_COL_SYS_TABLEPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_INTEGER, &split_part->desc.table_id,
                     sizeof(uint32), IX_COL_SYS_TABLEPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_INTEGER, &split_part->desc.part_id,
                     sizeof(uint32), IX_COL_SYS_TABLEPART001_PART_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s", cursor->rowid.file,
                  cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name);
    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), UPDATE_COLUMN_COUNT_SEVEN);
    (void)row_put_str(&ra, new_name);
    cursor->update_info.count = UPDATE_COLUMN_COUNT_SEVEN;
    cursor->update_info.columns[0] = SYS_TABLEPART_COL_NAME;

    /* clean stats info */
    for (uint32 i = 0; i < UPDATE_COLUMN_COUNT_SEVEN - 1; i++) {
        (void)row_put_null(&ra);
        cursor->update_info.columns[i + UPDATE_COLUMN_COUNT_ONE] = i + STATS_SYS_TABLEPART_COLUMN_NUM;
    }

    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);
    if (knl_internal_update(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t part_split_refresh_idxpart(knl_session_t *session, knl_cursor_t *cursor, table_part_t *split_part,
    const char *new_name, uint32 index_id)
{
    uint16 size;
    row_assist_t ra;

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_INDEXPART_ID, IX_SYS_INDEXPART001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_scan_key_t *key = &cursor->scan_range.l_key;
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_INTEGER, &split_part->desc.uid,
                     sizeof(uint32), IX_COL_SYS_INDEXPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_INTEGER, &split_part->desc.table_id,
                     sizeof(uint32), IX_COL_SYS_INDEXPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_INTEGER, &index_id,
                     sizeof(uint32), IX_COL_SYS_INDEXPART001_INDEX_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_INTEGER, &split_part->desc.part_id,
                     sizeof(uint32), IX_COL_SYS_INDEXPART001_PART_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s", cursor->rowid.file,
                  cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name);
    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), UPDATE_COLUMN_COUNT_TWELVE);
    (void)row_put_str(&ra, new_name);
    cursor->update_info.count = UPDATE_COLUMN_COUNT_TWELVE;
    cursor->update_info.columns[0] = SYS_INDEXPART_COL_NAME;

    /* clean stats info */
    for (uint32 i = 0; i < UPDATE_COLUMN_COUNT_TWELVE - 1; i++) {
        (void)row_put_null(&ra);
        cursor->update_info.columns[i + UPDATE_COLUMN_COUNT_ONE] = i + STATS_SYS_INDEXPART_COLUMN_NUM;
    }

    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);
    if (knl_internal_update(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t part_split_refresh_idxparts(knl_session_t *session, knl_dictionary_t *dc, knl_cursor_t *cursor,
    table_part_t *split_part, const char *new_name)
{
    index_t *index = NULL;
    table_t *table = DC_TABLE(dc);

    for (uint32 i = 0; i < table->index_set.total_count; i++) {
        index = table->index_set.items[i];
        if (!IS_PART_INDEX(index)) {
            continue;
        }

        if (part_split_refresh_idxpart(session, cursor, split_part, new_name, index->desc.id) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t part_split_refresh_orgpart(knl_session_t *session, knl_dictionary_t *dc, table_part_t *split_part,
    text_t *new_name)
{
    char name_buffer[GS_NAME_BUFFER_SIZE] = { 0 };

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    (void)cm_text2str(new_name, name_buffer, GS_NAME_BUFFER_SIZE);
    if (part_split_refresh_tabpart(session, cursor, split_part, name_buffer) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (part_split_refresh_idxparts(session, dc, cursor, split_part, name_buffer) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

/* interface of finishing last work of spliting part
 * 1. update new part flag
 * 2. rebuild index if need
 * 3. drop original part
 */
static status_t part_split_finish_lastwork(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def,
    table_part_t *split_part, bool32 reuse_orgpart, uint32 new_partid)
{
    table_t *table = DC_TABLE(dc);
    table_part_t *left_part = NULL;
    table_part_t *right_part = NULL;

    /* update the partition flag as ready */
    if (part_split_redis_get_newparts(table, def, &left_part, &right_part, reuse_orgpart) != GS_SUCCESS) {
        return GS_ERROR;
    }
    
    if (db_update_part_flag(session, dc, table->part_table, left_part->desc.part_id,
        PART_FLAG_TYPE_NOTREADY) != GS_SUCCESS) {
        return GS_ERROR;
    }
    
    if (!reuse_orgpart) {
        if (db_update_part_flag(session, dc, table->part_table, right_part->desc.part_id,
            PART_FLAG_TYPE_NOTREADY) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (!reuse_orgpart) {
        if (db_drop_part(session, dc, split_part, GS_TRUE) != GS_SUCCESS) {
            return GS_ERROR;
        }
    } else {
        knl_part_def_t *part_def = (knl_part_def_t *)cm_galist_get(&def->part_def.obj_def->parts, 1);
        if (part_split_refresh_orgpart(session, dc, split_part, &part_def->name) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (db_update_part_id(session, dc, split_part, new_partid) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (db_update_table_chgscn(session, &table->desc) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    /* if specify update global index clause, need to rebuild the global index */
    if (def->part_def.global_index_option) {
        if (part_split_rebuild_global_index(session, dc, table) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static void part_split_handle_error(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def,
    bool32 reuse_orgpart)
{
    knl_rollback(session, NULL);
    if (part_split_drop_newpart(session, dc, def, reuse_orgpart) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[PART] Failed to drop the newly created partition when split the partition %s failed",
            T2S(&def->part_def.name));
        knl_rollback(session, NULL);
    } else {
        knl_commit(session);
    }
}

static status_t part_split_refresh_dc(knl_session_t *session, knl_dictionary_t *dc, text_t *part_name,
    table_part_t **org_part)
{
    uint32 i;
    table_part_t *table_part = NULL;
    part_put_logic_log(session, dc);
    knl_commit(session);
    dc_invalidate(session, (dc_entity_t *)dc->handle);

    knl_dictionary_t new_dc;
    if (knl_open_dc_by_id(session, dc->uid, dc->oid, &new_dc, GS_TRUE) != GS_SUCCESS) {
        return GS_ERROR;
    }
    
    dc_close(dc);
    errno_t ret = memcpy_sp(dc, sizeof(knl_dictionary_t), &new_dc, sizeof(knl_dictionary_t));
    knl_securec_check(ret);
    table_t *table = DC_TABLE(dc);
    part_table_t *part_table = table->part_table;
    
    for (i = 0; i < part_table->desc.partcnt + part_table->desc.not_ready_partcnt; i++) {
        table_part = PART_GET_ENTITY(part_table, i);
        if (!IS_READY_PART(table_part)) {
            continue;
        }
        
        if (cm_compare_text_str_ins(part_name, table_part->desc.name) == 0 && !table_part->desc.not_ready) {
            *org_part = table_part;
            return GS_SUCCESS;
        }
    }

    if (i == part_table->desc.partcnt + part_table->desc.not_ready_partcnt) {
        GS_THROW_ERROR(ERR_OBJECT_NOT_EXISTS, "partition", T2S(part_name));
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t part_split_reuse_orgpart(knl_session_t *session, knl_altable_def_t *def, table_part_t *split_part,
    bool32 *reuse)
{
    uint32 space_id = split_part->desc.space_id;
    knl_part_def_t *part_def = (knl_part_def_t *)cm_galist_get(&def->part_def.obj_def->parts, 1);
    if (part_def->space.len != 0) {
        if (spc_get_space_id(session, &part_def->space, def->is_for_create_db, &space_id) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (space_id == split_part->desc.space_id) {
        *reuse = GS_TRUE;
    } else {
        *reuse = GS_FALSE;
    }

    return GS_SUCCESS;
}

/*
 * split part interface. split a part in following steps:
 * 1. check input for splitting a part
 * 2. clean garbage partition
 * 3. add a new part
 * 4. invalidate global index
 * 5. redistribute data of original partition
 * 6. rebuild global index if need
 */
status_t db_altable_split_part(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def)
{
    uint32 new_partid = GS_INVALID_ID32;
    table_part_t *split_part = NULL;
    table_t *table = DC_TABLE(dc);
    part_table_t *part_table = table->part_table;

    GS_LOG_DEBUG_INF("begin to split partition %s", T2S(&def->part_def.name));

    if (!part_table_find_by_name(part_table, &def->part_def.name, &split_part) || split_part->desc.not_ready) {
        GS_THROW_ERROR(ERR_OBJECT_NOT_EXISTS, "normal partition", T2S(&def->part_def.name));
        return GS_ERROR;
    }

    /* check input for splitting a part */
    if (part_split_precheck(session, table, def, split_part) != GS_SUCCESS) {
        return GS_ERROR;
    }

    /* clean not ready parts which created by a failed split sql */
    if (part_clean_garbage_partition(session, dc) != GS_SUCCESS) {
        return GS_ERROR;
    }
    
    /* refresh the dc since the parts has been changed */
    if (part_split_refresh_dc(session, dc, &def->part_def.name, &split_part) != GS_SUCCESS) {
        return GS_ERROR;
    }

    bool32 reuse_orgpart = GS_FALSE;
    if (part_split_reuse_orgpart(session, def, split_part, &reuse_orgpart) != GS_SUCCESS) {
        return GS_ERROR;
    }
    
    if (part_split_create_newparts(session, dc, def, split_part, reuse_orgpart, &new_partid) != GS_SUCCESS) {
        return GS_ERROR;
    }

    table = DC_TABLE(dc);
    if (part_split_invalidate_global_index(session, table) != GS_SUCCESS) {
        return GS_ERROR;
    }

    /* refresh the dc since the parts has been changed */
    if (part_split_refresh_dc(session, dc, &def->part_def.name, &split_part) != GS_SUCCESS) {
        part_split_handle_error(session, dc, def, reuse_orgpart);
        return GS_ERROR;
    }
    
    /* redistribute the data of original part */
    if (part_split_redis_data(session, dc, def, split_part, reuse_orgpart) != GS_SUCCESS) {
        part_split_handle_error(session, dc, def, reuse_orgpart);
        return GS_ERROR;
    }
    
    if (part_split_finish_lastwork(session, dc, def, split_part, reuse_orgpart, new_partid) != GS_SUCCESS) {
        part_split_handle_error(session, dc, def, reuse_orgpart);
        return GS_ERROR;
    }

    GS_LOG_DEBUG_INF("successfully to split partition %s", T2S(&def->part_def.name));
    return GS_SUCCESS;
}

static status_t subpart_split_precheck(knl_session_t *session, table_t *table, knl_altable_def_t *def,
    table_part_t *compart, uint32 split_partno)
{
    part_table_t *part_table = table->part_table;
    knl_part_obj_def_t *obj_def = def->part_def.obj_def;

    /* if specify update global index clause, need to rebuild the global index, no need to check reference */
    if (!def->part_def.global_index_option) {
        if (db_table_is_referenced(session, table, GS_TRUE)) {
            GS_THROW_ERROR(ERR_TABLE_IS_REFERENCED);
            return GS_ERROR;
        }
    }

    if (compart->desc.subpart_cnt + GS_SPLIT_PART_COUNT - 1 > GS_MAX_SUBPART_COUNT) {
        GS_THROW_ERROR(ERR_EXCEED_MAX_SUBPARTCNT, (uint32)GS_MAX_SUBPART_COUNT);
        return GS_ERROR;
    }

    table_part_t *table_compart = NULL;
    table_part_t *table_subpart = NULL;
    knl_part_def_t *parent_part = (knl_part_def_t *)cm_galist_get(&obj_def->parts, 0);
    knl_part_def_t *left_def = (knl_part_def_t *)cm_galist_get(&parent_part->subparts, 0);
    knl_part_def_t *right_def = (knl_part_def_t *)cm_galist_get(&parent_part->subparts, 1);

    /* last split failed, the sys_sub_table_parts table has one entry which is not ready.
    * the name of this not ready part can be reused
    */
    if (subpart_table_find_by_name(part_table, &left_def->name, &table_compart, &table_subpart) &&
        !table_subpart->desc.not_ready) {
        GS_THROW_ERROR(ERR_DUPLICATE_PART_NAME);
        return GS_ERROR;
    }

    if (subpart_table_find_by_name(part_table, &right_def->name, &table_compart, &table_subpart) &&
        !table_subpart->desc.not_ready) {
        if (!(table_compart->part_no == compart->part_no && table_subpart->part_no == split_partno)) {
            GS_THROW_ERROR(ERR_DUPLICATE_PART_NAME);
            return GS_ERROR;
        }
    }

    if (part_table_find_by_name(part_table, &left_def->name, &table_compart) ||
        part_table_find_by_name(part_table, &right_def->name, &table_compart)) {
        GS_THROW_ERROR(ERR_DUPLICATE_PART_NAME);
        return GS_ERROR;
    }

    if (split_partno == 0) { // split the first part, no need to check the left bound of spliting partition
        return GS_SUCCESS;
    }

    knl_part_key_t part_key;
    uint32 pre_partno = split_partno - 1;
    table_subpart = PART_GET_SUBENTITY(part_table, compart->subparts[pre_partno]);
    knl_part_column_desc_t *column_desc = part_table->sub_keycols;
    knl_decode_part_key(left_def->partkey, &part_key);
    if (part_compare_range_key(column_desc, &part_key.decoder, table_subpart->desc.groups) <= 0) {
        GS_THROW_ERROR(ERR_INVALID_PART_KEY, "split partition bound must collate higher than its previous partition.");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static bool32 subpart_is_id_conflict(part_table_t *part_table, table_part_t *compart, uint32 part_id)
{
    table_part_t *table_subpart = NULL;

    for (uint32 i = 0; i < compart->desc.subpart_cnt; i++) {
        table_subpart = PART_GET_SUBENTITY(part_table, compart->subparts[i]);
        if (table_subpart->desc.part_id == part_id) {
            return GS_TRUE;
        }
    }

    return GS_FALSE;
}

static bool32 subpart_generate_split_id(part_table_t *part_table, table_part_t *compart, uint32 split_id,
    uint32 *new_id1, uint32 *new_id2)
{
    table_part_t *table_subpart = PART_GET_SUBENTITY(part_table, compart->subparts[compart->desc.subpart_cnt - 1]);
    uint32 last_part_id = table_subpart->desc.part_id;

    /* split from the first partition, find an non-conflict part id */
    if (split_id == 1) {
        *new_id1 = split_id + GS_DFT_PARTID_STEP;

        while (*new_id1 < split_id + GS_MAX_PART_ID_GAP) {
            if (subpart_is_id_conflict(part_table, compart, *new_id1)) {
                *new_id1 += GS_DFT_PARTID_STEP;
                continue;
            }
            break;
        }

        /* if the new_id is much bigger than split part id, then adjust it to be smaller */
        if (*new_id1 - split_id >= GS_MAX_PART_ID_GAP) {
            *new_id1 = split_id + GS_DFT_PARTID_STEP + 1;
            for (;;) {
                if (!subpart_is_id_conflict(part_table, compart, *new_id1)) {
                    break;
                }
                (*new_id1)++;
            }
        }

        *new_id2 = *new_id1 + GS_DFT_PARTID_STEP;
        return GS_TRUE;
    } else if (split_id == last_part_id) {
        /* split from the last partition */
        *new_id1 = last_part_id + 1;
        *new_id2 = last_part_id + 1 + GS_DFT_PARTID_STEP;
        return GS_FALSE;
    } else {
        /* split from other (non-first, non-last) partition */
        *new_id1 = split_id - 1;
        *new_id2 = split_id + 1;
        if (subpart_is_id_conflict(part_table, compart, *new_id1)) {
            *new_id1 = split_id + GS_DFT_PARTID_STEP;
            for (;;) {
                if (!subpart_is_id_conflict(part_table, compart, *new_id1)) {
                    break;
                }
                (*new_id1)++;
            }
            *new_id2 = *new_id1 + GS_DFT_PARTID_STEP;
            return GS_TRUE;
        } else if (subpart_is_id_conflict(part_table, compart, *new_id2)) {
            *new_id1 += GS_DFT_PARTID_STEP;
            *new_id2 = *new_id1 + GS_DFT_PARTID_STEP;
            return GS_TRUE;
        } else {
            return GS_FALSE;
        }
    }
}

static uint32 subpart_split_get_update_pos(part_table_t *part_table, table_part_t *compart, uint32 org_partid)
{
    uint32 split_pos = 0;
    table_part_t *subpart = NULL;

    for (uint32 i = 0; i < compart->desc.subpart_cnt; i++) {
        subpart = PART_GET_SUBENTITY(part_table, compart->subparts[i]);
        if (subpart->desc.part_id == org_partid) {
            split_pos = i;
            break;
        }
    }

    return split_pos;
}

static status_t subpart_split_update_idx_rpids(knl_session_t *session, knl_cursor_t *cursor, index_t *index,
    table_part_t *compart, uint32 split_pos, uint32 new_partid)
{
    row_assist_t ra;
    uint32 new_rpid;
    uint32 update_cnt = compart->desc.subpart_cnt - 1;
    part_index_t *part_index = index->part_index;
    index_part_t *subpart = PART_GET_SUBENTITY(index->part_index, compart->subparts[split_pos + 1]);
    uint32 old_partid = subpart->desc.part_id;

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_SUB_INDEX_PARTS_ID, IX_SYS_INDEXSUBPART001_ID);
    cursor->index_dsc = GS_TRUE;
    knl_init_index_scan(cursor, GS_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &part_index->desc.uid,
        sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &part_index->desc.table_id,
        sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &part_index->desc.index_id,
        sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_INDEX_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &compart->desc.part_id,
        sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_PARENT_PART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &old_partid,
        sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_SUB_PART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &part_index->desc.uid,
        sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &part_index->desc.table_id,
        sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &part_index->desc.index_id,
        sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_INDEX_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &compart->desc.part_id,
        sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_PARENT_PART_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_INDEXSUBPART001_SUB_PART_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    while (!cursor->eof) {
        new_rpid = new_partid + (update_cnt - split_pos) * GS_DFT_PARTID_STEP;
        row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), UPDATE_COLUMN_COUNT_ONE);
        (void)row_put_int32(&ra, new_rpid);
        cursor->update_info.count = UPDATE_COLUMN_COUNT_ONE;
        cursor->update_info.columns[0] = SYS_INDEXSUBPART_COL_SUB_PART_ID;  // index part id
        cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, NULL);

        if (knl_internal_update(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }

        update_cnt--;
        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t subpart_split_update_idxs_rpids(knl_session_t *session, table_t *table, table_part_t *compart,
    uint32 org_partid, uint32 new_partid)
{
    index_t *index = NULL;
    index_set_t *index_set = &table->index_set;
    uint32 split_pos = subpart_split_get_update_pos(table->part_table, compart, org_partid);

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);

    for (uint32 i = 0; i < index_set->total_count; i++) {
        index = index_set->items[i];
        if (!IS_PART_INDEX(index) || !IS_COMPART_INDEX(&index->part_index->desc)) {
            continue;
        }

        if (subpart_split_update_idx_rpids(session, cursor, index, compart, split_pos, new_partid) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static status_t subpart_split_update_lob_rpids(knl_session_t *session, knl_cursor_t *cursor, lob_t *lob,
    table_part_t *compart, uint32 split_pos, uint32 new_partid)
{
    row_assist_t ra;
    uint32 new_rpid;
    uint32 update_cnt = compart->desc.subpart_cnt - 1;
    lob_part_t *subpart = PART_GET_SUBENTITY(lob->part_lob, compart->subparts[split_pos + 1]);
    uint32 old_partid = subpart->desc.part_id;
    
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_SUB_LOB_PARTS_ID, IX_SYS_LOBSUBPART001_ID);
    cursor->index_dsc = GS_TRUE;
    knl_init_index_scan(cursor, GS_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &lob->desc.uid,
        sizeof(uint32), IX_COL_SYS_LOBSUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &lob->desc.table_id,
        sizeof(uint32), IX_COL_SYS_LOBSUBPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &compart->desc.part_id,
        sizeof(uint32), IX_COL_SYS_LOBSUBPART001_PARENT_PART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &lob->desc.column_id,
        sizeof(uint32), IX_COL_SYS_LOBSUBPART001_COLUMN_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &old_partid,
        sizeof(uint32), IX_COL_SYS_LOBSUBPART001_SUB_PART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &lob->desc.uid,
        sizeof(uint32), IX_COL_SYS_LOBSUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &lob->desc.table_id,
        sizeof(uint32), IX_COL_SYS_LOBSUBPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &compart->desc.part_id,
        sizeof(uint32), IX_COL_SYS_LOBSUBPART001_PARENT_PART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &lob->desc.column_id,
        sizeof(uint32), IX_COL_SYS_LOBSUBPART001_COLUMN_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_LOBSUBPART001_SUB_PART_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    while (!cursor->eof) {
        new_rpid = new_partid + (update_cnt - split_pos) * GS_DFT_PARTID_STEP;
        row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), UPDATE_COLUMN_COUNT_ONE);
        (void)row_put_int32(&ra, new_rpid);
        cursor->update_info.count = UPDATE_COLUMN_COUNT_ONE;
        cursor->update_info.columns[0] = SYS_LOBSUBPART_COL_PART_ID;
        cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, NULL);

        if (knl_internal_update(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }

        update_cnt--;
        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t subpart_split_update_lobs_rpids(knl_session_t *session, knl_dictionary_t *dc, table_part_t *compart,
    uint32 org_partid, uint32 new_partid)
{
    lob_t *lob = NULL;
    knl_column_t *column = NULL;
    table_t *table = DC_TABLE(dc);
    dc_entity_t *entity = DC_ENTITY(dc);
    uint32 split_pos = subpart_split_get_update_pos(table->part_table, compart, org_partid);

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);

    for (uint32 i = 0; i < table->desc.column_count; i++) {
        column = dc_get_column(entity, i);
        if (!COLUMN_IS_LOB(column)) {
            continue;
        }

        lob = (lob_t *)column->lob;
        if (subpart_split_update_lob_rpids(session, cursor, lob, compart, split_pos, new_partid) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static status_t subpart_split_update_table_rpids(knl_session_t *session, table_t *table, table_part_t *compart,
    uint32 org_partid, uint32 new_partid)
{
    row_assist_t ra;
    uint32 update_cnt = compart->desc.subpart_cnt - 1;
    uint32 split_pos = subpart_split_get_update_pos(table->part_table, compart, org_partid);
    table_part_t *subpart = PART_GET_SUBENTITY(table->part_table, compart->subparts[split_pos + 1]);
    uint32 old_partid = subpart->desc.part_id;

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_SUB_TABLE_PARTS_ID, IX_SYS_TABLESUBPART001_ID);
    cursor->index_dsc = GS_TRUE;
    knl_init_index_scan(cursor, GS_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &compart->desc.uid,
        sizeof(uint32), IX_COL_SYS_TABLESUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &compart->desc.table_id,
        sizeof(uint32), IX_COL_SYS_TABLESUBPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &compart->desc.part_id,
        sizeof(uint32), IX_COL_SYS_TABLESUBPART001_PARENT_PART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &old_partid,
        sizeof(uint32), IX_COL_SYS_TABLESUBPART001_SUB_PART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &compart->desc.uid,
        sizeof(uint32), IX_COL_SYS_TABLESUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &compart->desc.table_id,
        sizeof(uint32), IX_COL_SYS_TABLESUBPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &compart->desc.part_id,
        sizeof(uint32), IX_COL_SYS_TABLESUBPART001_PARENT_PART_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_TABLESUBPART001_SUB_PART_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    while (!cursor->eof) {
        uint32 new_rpid = new_partid + (update_cnt - split_pos) * GS_DFT_PARTID_STEP;
        row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), UPDATE_COLUMN_COUNT_ONE);
        (void)row_put_int32(&ra, (int32)new_rpid);
        cursor->update_info.count = UPDATE_COLUMN_COUNT_ONE;
        cursor->update_info.columns[0] = SYS_TABLESUBPART_COL_SUB_PART_ID;  // table part id
        cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, NULL);
        if (knl_internal_update(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        update_cnt--;
        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    knl_panic_log(update_cnt == split_pos, "the update_cnt is not equal to split_pos, panic info: "
                  "table %s subpart %s compart %s update_cnt %u split_pos %u",
                  table->desc.name, subpart->desc.name, compart->desc.name, update_cnt, split_pos);
    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

/* for spiting partition, we will split the original part id into two new part ids. the new part ids may be conflict
 * with the id of the right partitions of the spliting partition, so it's need to update the ids of these right parts.
 * rpids: right part ids
 */
static status_t subpart_split_update_rpids(knl_session_t *session, knl_dictionary_t *dc, table_part_t *compart,
    uint32 org_partid, uint32 new_partid)
{
    table_t *table = DC_TABLE(dc);

    if (subpart_split_update_table_rpids(session, table, compart, org_partid, new_partid) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (subpart_split_update_idxs_rpids(session, table, compart, org_partid, new_partid) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (subpart_split_update_lobs_rpids(session, dc, compart, org_partid, new_partid) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t subpart_split_create_new_tabpart(knl_session_t *session, knl_dictionary_t *dc,
    knl_table_part_desc_t *desc)
{
    table_t *table = DC_TABLE(dc);
    bool32 is_encrypt_table = SPACE_IS_ENCRYPT(SPACE_GET(session, table->desc.space_id));
    if (!check_part_encrypt_allowed(session, is_encrypt_table, desc->space_id)) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "add partiton", "cases: add encrypt partition to non-encrypt \
part table or add non-encrypt partition to encrypt part table.");
        return GS_ERROR;
    }

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);

    if (db_write_sys_tablesubpart(session, cursor, desc) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (db_update_subtabpart_count(session, desc->uid, desc->table_id, desc->parent_partid, GS_TRUE) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static status_t subpart_split_create_new_idxpart(knl_session_t *session, knl_dictionary_t *dc,
    knl_table_part_desc_t *new_part_desc, table_part_t *org_part)
{
    table_t *table = DC_TABLE(dc);
    text_t text;
    errno_t ret;
    index_part_t *index_part = NULL;
    index_part_t *index_subpart = NULL;
    knl_index_part_desc_t new_idx_desc = { 0 };

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    index_t *index = NULL;
    for (uint32 i = 0; i < table->index_set.total_count; i++) {
        index = table->index_set.items[i];
        if (!IS_PART_INDEX(index) || !IS_COMPART_INDEX(index->part_index)) {
            continue;
        }

        index_part = INDEX_GET_PART(index, org_part->parent_partno);
        index_subpart = PART_GET_SUBENTITY(index->part_index, index_part->subparts[org_part->part_no]);
        ret = memcpy_sp(&new_idx_desc, sizeof(knl_index_part_desc_t),
            &index_subpart->desc, sizeof(knl_index_part_desc_t));
        knl_securec_check(ret);
        ret = memcpy_sp(&new_idx_desc.name, GS_NAME_BUFFER_SIZE, new_part_desc->name, GS_NAME_BUFFER_SIZE);
        knl_securec_check(ret);
        new_idx_desc.entry = INVALID_PAGID;
        new_idx_desc.org_scn = db_inc_scn(session);
        new_idx_desc.seg_scn = new_idx_desc.org_scn;
        new_idx_desc.part_id = new_part_desc->part_id;
        new_idx_desc.is_not_ready = new_part_desc->not_ready;

        /* if part index name has duplicated, use sys generated name instead. */
        cm_str2text(new_idx_desc.name, &text);
        if (part_idx_find_by_name(index->part_index, &text, &index_part) ||
            subpart_idx_find_by_name(index->part_index, &text, &index_subpart)) {
            ret = snprintf_s(new_idx_desc.name, GS_NAME_BUFFER_SIZE,
                GS_NAME_BUFFER_SIZE - 1, "SYS_P%llX", new_idx_desc.org_scn);
            knl_securec_check_ss(ret);
        }

        if (db_write_sys_indsubpart(session, cursor, &new_idx_desc) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        if (db_update_subidxpart_count(session, &index->desc, new_part_desc->parent_partid, GS_TRUE) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}
    
static status_t subpart_split_create_new_lobpart(knl_session_t *session, knl_dictionary_t *dc,
    knl_table_part_desc_t *desc)
{
    uint32 space_id;
    lob_t *lob = NULL;
    knl_column_t *column = NULL;
    table_t *table = DC_TABLE(dc);
    dc_entity_t *entity = DC_ENTITY(dc);
    knl_lob_part_desc_t lob_desc = { 0 };

    for (uint32 i = 0; i < table->desc.column_count; i++) {
        column = dc_get_column(entity, i);
        if (!COLUMN_IS_LOB(column)) {
            continue;
        }

        lob = (lob_t *)column->lob;
        space_id = lob->desc.is_stored ? lob->desc.space_id : desc->space_id;
        part_init_lob_part_desc(session, &lob->desc, desc->part_id, space_id, &lob_desc);
        lob_desc.is_not_ready = desc->not_ready;
        lob_desc.parent_partid = desc->parent_partid;

        if (subpart_write_syslob(session, &lob_desc) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t subpart_split_create_newpart(knl_session_t *session, knl_dictionary_t *dc,
    knl_table_part_desc_t *desc, table_part_t *org_part)
{
    if (subpart_split_create_new_tabpart(session, dc, desc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (subpart_split_create_new_idxpart(session, dc, desc, org_part) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (subpart_split_create_new_lobpart(session, dc, desc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t subpart_split_create_newparts(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def,
    table_part_t *split_compart, table_part_t *split_subpart)
{
    table_t *table = DC_TABLE(dc);
    
    /* generate part id for new partition.
     * if the new part id is conflict with the right parts, it's need to update the part id of all right parts
     */
    uint32 left_partid, right_partid;
    bool32 update_part_ids = subpart_generate_split_id(table->part_table, split_compart, split_subpart->desc.part_id,
        &left_partid, &right_partid);
    if (update_part_ids) {
        if (subpart_split_update_rpids(session, dc, split_compart, split_subpart->desc.part_id,
            right_partid) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    knl_table_part_desc_t desc;
    knl_part_def_t *parent_def = (knl_part_def_t *)cm_galist_get(&def->part_def.obj_def->parts, 0);
    knl_part_def_t *part_def = (knl_part_def_t *)cm_galist_get(&parent_def->subparts, 0);
    if (part_split_get_partdesc(session, part_def, (table_part_t *)split_subpart, left_partid, &desc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    desc.hiboundval = part_def->hiboundval;
    desc.bhiboundval.bytes = (uint8 *)part_def->partkey;
    desc.bhiboundval.size = part_def->partkey->size;
    desc.is_nologging = GS_FALSE;
    if (subpart_split_create_newpart(session, dc, &desc, split_subpart) != GS_SUCCESS) {
        return GS_ERROR;
    }

    part_def = (knl_part_def_t *)cm_galist_get(&parent_def->subparts, 1);
    if (part_split_get_partdesc(session, part_def, (table_part_t *)split_subpart, right_partid, &desc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    desc.is_nologging = GS_FALSE;
    if (subpart_split_create_newpart(session, dc, &desc, split_subpart) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t subpart_split_redis_get_newparts(table_t *table, knl_altable_def_t *def, uint32 compart_no,
    table_part_t **left_part, table_part_t **right_part)
{
    table_part_t *compart = TABLE_GET_PART(table, compart_no);
    knl_part_def_t *parent_part = (knl_part_def_t *)cm_galist_get(&def->part_def.obj_def->parts, 0);
    knl_part_def_t *left_part_def = (knl_part_def_t *)cm_galist_get(&parent_part->subparts, 0);
    knl_part_def_t *right_part_def = (knl_part_def_t *)cm_galist_get(&parent_part->subparts, 1);

    uint32 start_pos = 0;
    table_part_t *subpart = PART_GET_SUBENTITY(table->part_table, compart->subparts[start_pos]);
    while (subpart != NULL && start_pos < compart->desc.subpart_cnt) {
        if (cm_compare_text_str(&left_part_def->name, subpart->desc.name) == 0 && subpart->desc.not_ready) {
            *left_part = subpart;
        }

        if (cm_compare_text_str(&right_part_def->name, subpart->desc.name) == 0 && subpart->desc.not_ready) {
            *right_part = subpart;
        }

        if (*left_part != NULL && *right_part != NULL) {
            break;
        }

        start_pos++;
        subpart = PART_GET_SUBENTITY(table->part_table, compart->subparts[start_pos]);
    }
    
    if (*left_part == NULL) {
        GS_LOG_DEBUG_INF("could not find the part, name is %s", T2S(&left_part_def->name));
        GS_THROW_ERROR(ERR_PARTITION_NOT_EXIST, "table", T2S(&left_part_def->name));
        return GS_ERROR;
    }

    if (*right_part == NULL) {
        GS_LOG_DEBUG_INF("could not find the part, name is %s", T2S(&right_part_def->name));
        GS_THROW_ERROR(ERR_PARTITION_NOT_EXIST, "table", T2S(&right_part_def->name));
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t subpart_split_compare_range_key(knl_session_t *session, part_table_t *part_table,
    knl_cursor_t *cursor_delete, uint32 left_pno, int32 *result)
{
    part_key_t *key = (part_key_t *)cm_push(session->stack, GS_MAX_COLUMN_SIZE);
    errno_t ret = memset_sp(key, GS_MAX_COLUMN_SIZE, 0, GS_MAX_COLUMN_SIZE);
    knl_securec_check(ret);
    if (subpart_generate_part_key(cursor_delete->row, cursor_delete->offsets, cursor_delete->lens,
        part_table, key) != GS_SUCCESS) {
        cm_pop(session->stack);
        return GS_ERROR;
    }

    knl_part_key_t part_key;
    knl_decode_part_key(key, &part_key);
    table_part_t *compart = PART_GET_ENTITY(part_table, cursor_delete->part_loc.part_no);
    table_part_t *subpart = PART_GET_SUBENTITY(part_table, compart->subparts[left_pno]);
    *result = part_compare_range_key(part_table->sub_keycols, subpart->desc.groups, &part_key.decoder);

    cm_pop(session->stack);
    return GS_SUCCESS;
}

static status_t subpart_split_redis_entity(knl_session_t *session, knl_dictionary_t *dc, knl_cursor_t *cursor_delete,
    knl_cursor_t *cursor_insert, knl_altable_def_t *def)
{
    int32 result;
    table_t *table = DC_TABLE(dc);
    table_part_t *left_part = NULL;
    table_part_t *right_part = NULL;
    if (subpart_split_redis_get_newparts(table, def, cursor_delete->part_loc.part_no, &left_part,
        &right_part) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (knl_fetch(session, cursor_delete) != GS_SUCCESS) {
        return GS_ERROR;
    }

    while (!cursor_delete->eof) {
        if (subpart_split_compare_range_key(session, table->part_table, cursor_delete, left_part->part_no,
            &result) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (result > 0) {
            cursor_insert->part_loc.subpart_no = left_part->part_no;
        } else {
            cursor_insert->part_loc.subpart_no = right_part->part_no;
        }

        knl_set_table_part(cursor_insert, cursor_insert->part_loc);
        if (knl_copy_row(session, cursor_delete, cursor_insert) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (knl_internal_delete(session, cursor_delete) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (knl_internal_insert(session, cursor_insert) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (knl_fetch(session, cursor_delete) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t subpart_split_redis_rows(knl_session_t *session, knl_dictionary_t *dc, knl_cursor_t *cursor_delete,
    knl_cursor_t *cursor_insert, knl_altable_def_t *def)
{
    table_t *table = DC_TABLE(dc);
    table_part_t *split_compart = TABLE_GET_PART(table, cursor_delete->part_loc.part_no);

    cursor_insert->part_loc.part_no = split_compart->part_no;
    knl_set_table_part(cursor_delete, cursor_delete->part_loc);
    if (knl_reopen_cursor(session, cursor_delete, dc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (subpart_split_redis_entity(session, dc, cursor_delete, cursor_insert, def) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t subpart_split_redis_data(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def,
    table_part_t *split_compart, table_part_t *split_subpart)
{
    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor_delete = knl_push_cursor(session);
    knl_cursor_t *cursor_insert = knl_push_cursor(session);
    if (part_split_redisdata_open_cursor(session, dc, cursor_delete, cursor_insert) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    cursor_insert->row = (row_head_t *)cm_push(session->stack, GS_MAX_ROW_SIZE);
    cursor_delete->part_loc.part_no = split_compart->part_no;
    cursor_delete->part_loc.subpart_no = split_subpart->part_no;
    if (subpart_split_redis_rows(session, dc, cursor_delete, cursor_insert, def) != GS_SUCCESS) {
        part_split_redisdata_close_cursor(session, cursor_delete, cursor_insert);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    part_split_redisdata_close_cursor(session, cursor_delete, cursor_insert);
    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static status_t subpart_split_drop_newpart(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def)
{
    knl_part_def_t *parent_part = (knl_part_def_t *)cm_galist_get(&def->part_def.obj_def->parts, 0);

    knl_part_def_t *part_def = (knl_part_def_t *)cm_galist_get(&parent_part->subparts, 0);
    def->options |= DROP_IF_EXISTS;
    def->part_def.name = part_def->name;
    if (db_altable_drop_subpartition(session, dc, def, GS_FALSE) != GS_SUCCESS) {
        return GS_ERROR;
    }
    GS_LOG_DEBUG_INF("drop the left spliting part %s", T2S(&def->part_def.name));

    part_def = (knl_part_def_t *)cm_galist_get(&parent_part->subparts, 1);
    def->options |= DROP_IF_EXISTS;
    def->part_def.name = part_def->name;
    if (db_altable_drop_subpartition(session, dc, def, GS_FALSE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    GS_LOG_DEBUG_INF("drop the right spliting part %s", T2S(&def->part_def.name));
    return GS_SUCCESS;
}

/* interface of finishing last work of spliting part
 * 1. update new part flag
 * 2. rebuild index if need
 * 3. drop original part
 */
static status_t subpart_split_finish_lastwork(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def,
    table_part_t *compart, table_part_t *subpart)
{
    table_t *table = DC_TABLE(dc);
    table_part_t *left_part = NULL;
    table_part_t *right_part = NULL;

    if (subpart_split_redis_get_newparts(table, def, compart->part_no, &left_part, &right_part) != GS_SUCCESS) {
        return GS_ERROR;
    }
        
    /* update the partition flag as ready */
    if (db_update_subpart_flag(session, dc, compart, left_part->desc.part_id, PART_FLAG_TYPE_NOTREADY) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (db_update_subpart_flag(session, dc, compart, right_part->desc.part_id, PART_FLAG_TYPE_NOTREADY) != GS_SUCCESS) {
        return GS_ERROR;
    }

    /* if specify update global index clause, need to rebuild the global index */
    if (def->part_def.global_index_option) {
        if (part_split_rebuild_global_index(session, dc, table) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (db_drop_subpartition(session, dc, subpart) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static void subpart_handle_split_error(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def)
{
    knl_rollback(session, NULL);
    if (subpart_split_drop_newpart(session, dc, def) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[PART] Failed to drop the newly created subpartition when split the subpartition %s failed",
            T2S(&def->part_def.name));
        knl_rollback(session, NULL);
    } else {
        knl_commit(session);
    }
}

static status_t subpart_split_refresh_dc(knl_session_t *session, knl_dictionary_t *dc, text_t *part_name,
    table_part_t **compart, table_part_t **subpart)
{
    part_put_logic_log(session, dc);
    knl_commit(session);
    dc_invalidate(session, (dc_entity_t *)dc->handle);

    knl_dictionary_t new_dc;
    if (knl_open_dc_by_id(session, dc->uid, dc->oid, &new_dc, GS_TRUE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    dc_close(dc);
    errno_t ret = memcpy_sp(dc, sizeof(knl_dictionary_t), &new_dc, sizeof(knl_dictionary_t));
    knl_securec_check(ret);

    table_t *table = DC_TABLE(dc);
    if (!subpart_table_find_by_name(table->part_table, part_name, compart, subpart)) {
        GS_THROW_ERROR(ERR_PARTITION_NOT_EXIST, "table", T2S(part_name));
        return GS_ERROR;
    }

    if (!(*subpart)->desc.not_ready) {
        return GS_SUCCESS;
    }

    uint32 i;
    table_part_t *table_subpart = NULL;
    for (i = 0; i < (*compart)->desc.subpart_cnt; i++) {
        table_subpart = PART_GET_SUBENTITY(table->part_table, (*compart)->subparts[i]);
        if (table_subpart == NULL) {
            continue;
        }

        if (cm_compare_text_str_ins(part_name, table_subpart->desc.name) == 0 && !table_subpart->desc.not_ready) {
            break;
        }
    }

    if (i == (*compart)->desc.subpart_cnt) {
        GS_THROW_ERROR(ERR_OBJECT_NOT_EXISTS, "subpartition", T2S(part_name));
        return GS_ERROR;
    }
    
    *subpart = table_subpart;
    return GS_SUCCESS;
}

/*
 * split part interface. split a part in following steps:
 * 1. check input for spliting a part
 * 2. clean garbage partition
 * 3. add a new part
 * 4. invalidate global index
 * 5. redistribute data of original partition
 * 6. rebuild global index if need
 */
status_t db_altable_split_subpart(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def)
{
    table_t *table = DC_TABLE(dc);
    table_part_t *compart = NULL;
    table_part_t *subpart = NULL;
    part_table_t *part_table = table->part_table;

    GS_LOG_DEBUG_INF("begin to split subpartition %s", T2S(&def->part_def.name));

    if (!subpart_table_find_by_name(part_table, &def->part_def.name, &compart, &subpart) || subpart->desc.not_ready) {
        GS_THROW_ERROR(ERR_OBJECT_NOT_EXISTS, "normal partition", T2S(&def->part_def.name));
        return GS_ERROR;
    }

    /* check input for splitting a part */
    if (subpart_split_precheck(session, table, def, compart, subpart->part_no) != GS_SUCCESS) {
        return GS_ERROR;
    }

    /* clean not ready subparts */
    if (subpart_clean_garbage_partition(session, dc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    /* refresh the split part since the old dc has changed */
    if (subpart_split_refresh_dc(session, dc, &def->part_def.name, &compart, &subpart) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (subpart_split_create_newparts(session, dc, def, compart, subpart) != GS_SUCCESS) {
        return GS_ERROR;
    }

    table = DC_TABLE(dc);
    if (part_split_invalidate_global_index(session, table) != GS_SUCCESS) {
        return GS_ERROR;
    }

    /* refresh the split part since the old dc has changed */
    if (subpart_split_refresh_dc(session, dc, &def->part_def.name, &compart, &subpart) != GS_SUCCESS) {
        subpart_handle_split_error(session, dc, def);
        return GS_ERROR;
    }
    
    /* redistribute the data of original part */
    if (subpart_split_redis_data(session, dc, def, compart, subpart) != GS_SUCCESS) {
        subpart_handle_split_error(session, dc, def);
        return GS_ERROR;
    }

    if (subpart_split_finish_lastwork(session, dc, def, compart, subpart) != GS_SUCCESS) {
        subpart_handle_split_error(session, dc, def);
        return GS_ERROR;
    }

    GS_LOG_DEBUG_INF("successfully to split subpartition %s", T2S(&def->part_def.name));
    return GS_SUCCESS;
}

