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
 * knl_part_comm.c
 *
 *
 * IDENTIFICATION
 * src/kernel/table/knl_part_comm.c
 *
 * -------------------------------------------------------------------------
 */
 
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

bool32 part_table_find_by_name(part_table_t *part_table, text_t *name, table_part_t **table_part)
{
    uint32 hash;
    uint32 part_no;
    part_bucket_t *bucket;
    table_part_t *entity = NULL;

    hash = dc_cal_part_name_hash(name);
    bucket = &part_table->pbuckets[hash];

    part_no = bucket->first;

    while (part_no != GS_INVALID_ID32) {
        entity = PART_GET_ENTITY(part_table, part_no);
        if (cm_text_str_equal(name, entity->desc.name)) {
            break;
        }

        part_no = entity->pnext;
    }

    *table_part = entity;

    if (part_no == GS_INVALID_ID32) {
        return GS_FALSE;
    }

    return GS_TRUE;
}

uint32 part_generate_interval_partno(part_table_t *part_table, uint32 part_id)
{
    uint32 part_no;
    part_no = (part_id - PART_INTERVAL_BASE_ID) + part_table->desc.transition_no + 1;
    return part_no;
}

status_t db_update_table_part_entry(knl_session_t *session, knl_table_part_desc_t *desc, page_id_t entry)
{
    knl_cursor_t *cursor = NULL;
    row_assist_t ra;
    uint16 size;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_TABLEPART_ID, IX_SYS_TABLEPART001_ID);

    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&desc->uid,
                     sizeof(uint32), IX_COL_SYS_TABLEPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&desc->table_id,
                     sizeof(uint32), IX_COL_SYS_TABLEPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&desc->part_id,
                     sizeof(uint32), IX_COL_SYS_TABLEPART001_PART_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s", cursor->rowid.file,
                  cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name);

    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), UPDATE_COLUMN_COUNT_ONE);
    (void)row_put_int64(&ra, *(int64 *)&entry);
    cursor->update_info.count = UPDATE_COLUMN_COUNT_ONE;
    cursor->update_info.columns[0] = SYS_TABLEPART_COL_ENTRY;  // table part entry
    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

    if (knl_internal_update(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t db_update_lob_part_entry(knl_session_t *session, knl_lob_part_desc_t *desc, page_id_t entry)
{
    knl_cursor_t *cursor = NULL;
    row_assist_t ra;
    uint16 size;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_LOBPART_ID, IX_SYS_LOBPART001_ID);

    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&desc->uid,
                     sizeof(uint32), IX_COL_SYS_LOBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&desc->table_id,
                     sizeof(uint32), IX_COL_SYS_LOBPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&desc->column_id,
                     sizeof(uint32), IX_COL_SYS_LOBPART001_COLUMN_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&desc->part_id,
                     sizeof(uint32), IX_COL_SYS_LOBPART001_PART_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s", cursor->rowid.file,
                  cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name);

    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), UPDATE_COLUMN_COUNT_ONE);
    (void)row_put_int64(&ra, *(int64 *)&entry);
    cursor->update_info.count = UPDATE_COLUMN_COUNT_ONE;
    cursor->update_info.columns[0] = SYS_LOBPART_COL_ENTRY;  // lob part entry
    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

    if (knl_internal_update(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static bool32 part_column_in_update(part_table_t *part_table, knl_update_info_t *info)
{
    uint16 i;
    uint32 j;

    for (i = 0; i < info->count; i++) {
        for (j = 0; j < part_table->desc.partkeys; j++) {
            if ((uint32)info->columns[i] == part_table->keycols[j].column_id) {
                return GS_TRUE;
            }
        }
    }

    if (!IS_COMPART_TABLE(part_table)) {
        return GS_FALSE;
    }
    
    for (i = 0; i < info->count; i++) {
        for (j = 0; j < part_table->desc.subpartkeys; j++) {
            if ((uint32)info->columns[i] == part_table->sub_keycols[j].column_id) {
                return GS_TRUE;
            }
        }
    }

    return GS_FALSE;
}

uint32 part_generate_part_id(table_t *table, uint32 number)
{
    uint32 num = number;
    table_part_t *table_part = NULL;

    if (table->part_table != NULL) {
        table_part = TABLE_GET_PART(table, table->part_table->desc.partcnt - 1);
        num = table_part->desc.part_id;
        num /= GS_DFT_PARTID_STEP;
    } else {
        knl_panic_log(num != GS_INVALID_ID32, "the num is invalid, panic info: table %s", table->desc.name);
    }

    return GS_DFT_PARTID_STEP * (num + 1);
}

status_t part_generate_part_key(knl_session_t *session, row_head_t *row, uint16 *offsets, uint16 *lens,
                                part_table_t *part_table, part_key_t *key)
{
    uint32 i;
    uint16 col_id;
    uint16 column_count;

    column_count = ROW_COLUMN_COUNT(row);
    part_key_init(key, part_table->desc.partkeys);
    for (i = 0; i < part_table->desc.partkeys; i++) {
        col_id = part_table->keycols[i].column_id;
        knl_panic(col_id < column_count);

        if (lens[col_id] != GS_NULL_VALUE_LEN) {
            gs_type_t type = part_table->keycols[i].datatype;
            char temp[NUMBER_ZERO_STORAGR_LEN] = {0};
            uint32 org_len = 0;
            if (CSF_IS_DECIMAL_ZERO(row->is_csf, lens[col_id], type)) {
                part_get_number_zero(type, temp, NUMBER_ZERO_STORAGR_LEN, &org_len);
                if (part_put_data(key, temp, org_len, type) != GS_SUCCESS) {
                    return GS_ERROR;
                }
            } else {
                if (part_put_data(key, (char *)row + offsets[col_id], lens[col_id], type) != GS_SUCCESS) {
                    return GS_ERROR;
                }
            }
        } else {
            part_put_null(key);
        }
    }

    return GS_SUCCESS;
}
                                
static status_t part_get_new_part_loc(knl_session_t *session, knl_cursor_t *cursor, knl_part_locate_t *part_loc)
{
    row_assist_t ra;
    dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;
    part_table_t *part_table = entity->table.part_table;
    
    CM_SAVE_STACK(session->stack);
    row_head_t *new_row = (row_head_t *)cm_push(session->stack, GS_MAX_ROW_SIZE);
    
    /* push space for offsets and lens at once, so it is multiplied by 2 */
    uint16 *offsets = (uint16 *)cm_push(session->stack, sizeof(uint16) * session->kernel->attr.max_column_count * 2);
    uint16 *lens = (uint16 *)((char *)offsets + sizeof(uint16) * session->kernel->attr.max_column_count);
    cm_row_init(&ra, (char *)new_row, GS_MAX_ROW_SIZE, entity->column_count, cursor->row->is_csf);
    heap_reorganize_with_update(cursor->row, cursor->offsets, cursor->lens, &cursor->update_info, &ra);
    cm_decode_row((char *)new_row, offsets, lens, NULL);

    part_key_t *key = (part_key_t *)cm_push(session->stack, GS_MAX_COLUMN_SIZE);
    errno_t ret = memset_sp(key, GS_MAX_COLUMN_SIZE, 0, GS_MAX_COLUMN_SIZE);
    knl_securec_check(ret);
    if (part_generate_part_key(session, new_row, offsets, lens, part_table, key) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    part_loc->part_no = knl_locate_part_key(entity, key);
    if (part_loc->part_no == GS_INVALID_ID32) {
        CM_RESTORE_STACK(session->stack);
        GS_THROW_ERROR(ERR_INVALID_PART_KEY, "updated partition key does not map to any partition");
        return GS_ERROR;
    }

    /* update into interval part and the interval part will be created next */
    if (knl_verify_interval_part(entity, part_loc->part_no)) {
        part_loc->subpart_no = (IS_COMPART_TABLE(part_table) ? 0 : GS_INVALID_ID32);
        CM_RESTORE_STACK(session->stack);
        return GS_SUCCESS;
    }
    
    table_part_t *table_part = PART_GET_ENTITY(part_table, part_loc->part_no);
    if (IS_PARENT_TABPART(&table_part->desc)) {
        ret = memset_sp(key, GS_MAX_COLUMN_SIZE, 0, GS_MAX_COLUMN_SIZE);
        knl_securec_check(ret);
        if (subpart_generate_part_key(new_row, offsets, lens, part_table, key) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
        
        part_loc->subpart_no = knl_locate_subpart_key(entity, part_loc->part_no, key);
        if (part_loc->subpart_no == GS_INVALID_ID32) {
            CM_RESTORE_STACK(session->stack);
            GS_THROW_ERROR(ERR_INVALID_PART_KEY, "updated partition key does not map to any subpartition");
            return GS_ERROR;
        }
    }
    
    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t part_prepare_crosspart_update(knl_session_t *session, knl_cursor_t *cursor, knl_part_locate_t *part_loc)
{
    dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;
    part_table_t *part_table = entity->table.part_table;
    if (!part_column_in_update(part_table, &cursor->update_info)) {
        *part_loc = cursor->part_loc;
        return GS_SUCCESS;
    }

    uint32 max_row_len = heap_table_max_row_len(cursor->table, GS_MAX_ROW_SIZE, cursor->part_loc);
    knl_panic_log(cursor->row->is_csf == ((row_head_t *)cursor->update_info.data)->is_csf,
        "the CSF format of the row on the page is different from that in the update information");
    heap_update_assist_t ua;
    ua.old_cols = ROW_COLUMN_COUNT(cursor->row);
    ua.new_cols = entity->column_count;
    ua.info = &cursor->update_info;
    heap_update_prepare(session, cursor->row, cursor->offsets, cursor->lens, cursor->data_size, &ua);
    
    if (ua.new_size > max_row_len && entity->contain_lob) {
        knl_update_info_t *lob_info = NULL;
        bool32 is_reorg = GS_FALSE;
        CM_SAVE_STACK(session->stack);
        lob_info = (knl_update_info_t *)cm_push(session->stack, sizeof(knl_update_info_t) + GS_MAX_ROW_SIZE);
        lob_info->data = (char *)lob_info + sizeof(knl_update_info_t);
        CM_PUSH_UPDATE_INFO(session, *lob_info);

        /*
         * lob_reorganize_update_info will check new size and throw ERR_RECORD_SIZE_OVERFLOW when row size overflow
         */
        if (lob_reorganize_columns(session, cursor, &ua, lob_info, &is_reorg) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        if (is_reorg) {
            errno_t ret = memcpy_sp(ua.info->data, GS_MAX_ROW_SIZE, lob_info->data, GS_MAX_ROW_SIZE);
            knl_securec_check(ret);
            uint32 copy_size = session->kernel->attr.max_column_count * sizeof(uint16);
            ret = memcpy_sp(ua.info->columns, copy_size, lob_info->columns, copy_size);
            knl_securec_check(ret);
            ret = memcpy_sp(ua.info->offsets, copy_size, lob_info->offsets, copy_size);
            knl_securec_check(ret);
            ret = memcpy_sp(ua.info->lens, copy_size, lob_info->lens, copy_size);
            knl_securec_check(ret);
            heap_update_prepare(session, cursor->row, cursor->offsets, cursor->lens, cursor->data_size, &ua);
        }
        CM_RESTORE_STACK(session->stack);
    }

    if (ua.new_size > max_row_len) {
        GS_THROW_ERROR(ERR_RECORD_SIZE_OVERFLOW, "update row", ua.new_size, max_row_len);
        return GS_ERROR;
    }
    
    if (part_get_new_part_loc(session, cursor, part_loc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

bool32 part_check_update_crosspart(knl_part_locate_t *new_loc, knl_part_locate_t *old_loc)
{
    if (new_loc->part_no == GS_INVALID_ID32) {
        return GS_FALSE;
    }
    
    if (new_loc->part_no != old_loc->part_no) {
        return GS_TRUE;
    }

    if (new_loc->subpart_no == GS_INVALID_ID32) {
        return GS_FALSE;
    }

    if (new_loc->subpart_no != old_loc->subpart_no) {
        return GS_TRUE;
    }

    return GS_FALSE;
}

void db_set_part_flag(knl_table_part_desc_t *desc, part_flag_type_e part_flag)
{
    switch (part_flag) {
        case PART_FLAG_TYPE_NOTREADY:
            desc->not_ready = 0;
            break;
        case PART_FLAG_TYPE_STORAGED:
            desc->storaged = GS_TRUE;
            break;
        case PART_FLAG_TYPE_ENABLE_NOLOGGING:
            desc->is_nologging = GS_TRUE;
            break;
        case PART_FLAG_TYPE_DISABLE_NOLOGGING:
            desc->is_nologging = GS_FALSE;
            break;

        default:
            knl_panic_log(0, "update part's flag to unsupport flag type");
    }
}

// to set the flag to ready
status_t db_update_part_flag(knl_session_t *session, knl_dictionary_t *dc, part_table_t *part_table,
    uint32 pid, part_flag_type_e part_flag)
{
    uint16 size;
    row_assist_t ra;
    knl_table_part_desc_t desc;

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_TABLEPART_ID, IX_SYS_TABLEPART001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_scan_key_t *key = &cursor->scan_range.l_key;
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_INTEGER, &part_table->desc.uid,
                     sizeof(uint32), IX_COL_SYS_TABLEPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_INTEGER, &part_table->desc.table_id,
                     sizeof(uint32), IX_COL_SYS_TABLEPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_INTEGER, &pid,
                     sizeof(uint32), IX_COL_SYS_TABLEPART001_PART_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    knl_panic_log(!cursor->eof, "the specified partition cannot be found");

    dc_convert_table_part_desc(cursor, &desc);
    db_set_part_flag(&desc, part_flag);

    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), UPDATE_COLUMN_COUNT_ONE);
    (void)row_put_int32(&ra, (int32)desc.flags);
    cursor->update_info.count = UPDATE_COLUMN_COUNT_ONE;
    cursor->update_info.columns[0] = SYS_TABLEPART_COL_FLAGS;

    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

    if (knl_internal_update(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);

    return GS_SUCCESS;
}

status_t db_update_table_part_initrans(knl_session_t *session, knl_table_part_desc_t *desc, uint32 initrans)
{
    row_assist_t ra;
    uint16 size;

    CM_SAVE_STACK(session->stack);

    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_TABLEPART_ID, IX_SYS_TABLEPART001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_scan_key_t *key = &cursor->scan_range.l_key;
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_INTEGER, (void *)&desc->uid,
        sizeof(uint32), IX_COL_SYS_TABLEPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_INTEGER, (void *)&desc->table_id,
        sizeof(uint32), IX_COL_SYS_TABLEPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_INTEGER, (void *)&desc->part_id,
        sizeof(uint32), IX_COL_SYS_TABLEPART001_PART_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s", cursor->rowid.file,
                  cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name);

    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), UPDATE_COLUMN_COUNT_ONE);
    (void)row_put_int32(&ra, (int32)initrans);
    cursor->update_info.count = UPDATE_COLUMN_COUNT_ONE;
    cursor->update_info.columns[0] = SYS_TABLEPART_COL_INITRANS; // table part initrans
    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

    if (knl_internal_update(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t db_update_table_subpart_initrans(knl_session_t *session, knl_table_part_desc_t *desc, uint32 initrans)
{
    row_assist_t ra;
    uint16 size;

    CM_SAVE_STACK(session->stack);

    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_SUB_TABLE_PARTS_ID, IX_SYS_TABLESUBPART001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_scan_key_t *key = &cursor->scan_range.l_key;
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_INTEGER, (void *)&desc->uid,
        sizeof(uint32), IX_COL_SYS_TABLESUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_INTEGER, (void *)&desc->table_id,
        sizeof(uint32), IX_COL_SYS_TABLESUBPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_INTEGER,
        (void *)&desc->parent_partid, sizeof(uint32), IX_COL_SYS_TABLESUBPART001_PARENT_PART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_INTEGER, (void *)&desc->part_id,
        sizeof(uint32), IX_COL_SYS_TABLESUBPART001_SUB_PART_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s", cursor->rowid.file,
                  cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name);

    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), UPDATE_COLUMN_COUNT_ONE);
    (void)row_put_int32(&ra, (int32)initrans);
    cursor->update_info.count = UPDATE_COLUMN_COUNT_ONE;
    cursor->update_info.columns[0] = SYS_TABLESUBPART_COL_INITRANS; // table subpart initrans
    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

    if (knl_internal_update(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t db_update_part_count(knl_session_t *session, uint32 uid, uint32 tid, uint32 iid, bool32 is_add)
{
    knl_cursor_t *cursor = NULL;
    knl_scan_key_t *key = NULL;
    uint16 size;
    row_assist_t ra;
    uint32 partcnt;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_PARTOBJECT_ID, IX_SYS_PARTOBJECT001_ID);

    knl_init_index_scan(cursor, GS_TRUE);
    key = &cursor->scan_range.l_key;
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_INTEGER, &uid,
                     sizeof(uint32), IX_COL_SYS_PARTOBJECT001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_INTEGER, &tid,
                     sizeof(uint32), IX_COL_SYS_PARTOBJECT001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_INTEGER, &iid,
                     sizeof(uint32), IX_COL_SYS_PARTOBJECT001_INDEX_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s", cursor->rowid.file,
                  cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name);

    partcnt = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_PARTOBJECT_COL_PARTCNT) + (is_add ? 1 : -1);
    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), UPDATE_COLUMN_COUNT_ONE);
    (void)row_put_int32(&ra, partcnt);
    cursor->update_info.count = UPDATE_COLUMN_COUNT_ONE;
    cursor->update_info.columns[0] = SYS_PARTOBJECT_COL_PARTCNT;  // partcnt
    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

    if (knl_internal_update(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    GS_LOG_DEBUG_INF("update count: uid: %d, tid: %d, iid: %d", uid, tid, iid);
    GS_LOG_DEBUG_INF("update count: partcnt after update is: %d, the operation is(1:add, 0:drop): %d",
                     partcnt, is_add);

    CM_RESTORE_STACK(session->stack);

    return GS_SUCCESS;
}

status_t part_update_interval_part_count(knl_session_t *session, table_t *table, uint32 part_no, uint32 iid,
    bool32 is_add)
{
    row_assist_t ra;
    uint32 partcnt = 0;
    part_table_t *part_table = table->part_table;
    table_part_t *entity = NULL;

    /* part_no locate in (transition_no, last_part_no) */
    if (part_no > part_table->desc.transition_no && part_no < part_table->desc.partcnt - 1) {
        return GS_SUCCESS;
    }

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_PARTOBJECT_ID, IX_SYS_PARTOBJECT001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &table->desc.uid,
        sizeof(uint32), IX_COL_SYS_PARTOBJECT001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &table->desc.id,
        sizeof(uint32), IX_COL_SYS_PARTOBJECT001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &iid, sizeof(uint32),
        IX_COL_SYS_PARTOBJECT001_INDEX_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s", cursor->rowid.file,
                  cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, table->desc.name);

    if (is_add) {
        partcnt = part_no + 1;
    } else {
        // for drop last part ,this must be interval part, find first no-null part before last part
        if (part_no == part_table->desc.partcnt - 1) {
            for (uint32 i = part_no - 1; i >= part_table->desc.transition_no; i--) {
                entity = PART_GET_ENTITY(part_table, i);
                if (entity != NULL && entity->is_ready) {
                    partcnt = entity->part_no + 1;
                    break;
                }
                // i = 0 ,could not continue since i will be a negative number and i >= 0 will always true
                if (i == 0) {
                    break;
                }
            }
        } else {
            // for drop part before transition part
            knl_panic_log(part_no < part_table->desc.transition_no,
                          "part_no is abnormal, panic info: page %u-%u type %u table %s part_no %u transition_no %u",
                          cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                          table->desc.name, part_no, part_table->desc.transition_no);
            partcnt = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_PARTOBJECT_COL_PARTCNT) - 1;
        }
    }

    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), UPDATE_COLUMN_COUNT_ONE);
    (void)row_put_int32(&ra, partcnt);
    cursor->update_info.count = UPDATE_COLUMN_COUNT_ONE;
    cursor->update_info.columns[0] = SYS_PARTOBJECT_COL_PARTCNT;  // partcnt
    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, NULL);

    if (knl_internal_update(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    GS_LOG_DEBUG_INF("update interval count: uid: %d, tid: %d, iid: %d, partno: %d", table->desc.uid,
                     table->desc.id, iid, part_no);
    GS_LOG_DEBUG_INF("update interval count: partcnt after update is: %d, the operation is(1:add, 0:drop): %d",
                     partcnt, is_add);

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t part_table_corruption_verify(knl_session_t *session, knl_dictionary_t *dc, knl_corrupt_info_t *corrupt_info)
{
    dc_entity_t *entity = DC_ENTITY(dc);
    table_t *table = (table_t *)&entity->table;
    for (uint32 i = 0; i < table->part_table->desc.partcnt; i++) {
        table_part_t *table_part = TABLE_GET_PART(table, i);
        if (!IS_READY_PART(table_part)) {
            continue;
        }
        if (!table_part->heap.loaded) {
            if (dc_load_table_part_segment(session, entity, table_part) != GS_SUCCESS) {
                GS_LOG_RUN_WAR("[DC] could not load table partition %s of table %s.%s, segment corrupted",
                    table_part->desc.name, session->kernel->dc_ctx.users[table->desc.uid]->desc.name,
                    table->desc.name);
                return GS_ERROR;
            }
        }
        heap_segment_t *segment = (heap_segment_t *)table_part->heap.segment;
        if (segment != NULL) {
            if (heap_page_corruption_scan(session, segment, corrupt_info) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }

    if (!entity->contain_lob) {
        return GS_SUCCESS;
    }

    for (uint32 i = 0; i < table->desc.column_count; i++) {
        knl_column_t *column = dc_get_column(entity, i);
        if (!COLUMN_IS_LOB(column)) {
            continue;
        }

        lob_t *lob = (lob_t *)column->lob;
        for (uint32 j = 0; j < table->part_table->desc.partcnt; j++) {
            table_part_t *table_part = TABLE_GET_PART(table, j);
            lob_part_t *lob_part = LOB_GET_PART(lob, j);
            if (!IS_READY_PART(table_part) || lob_part == NULL) {
                continue;
            }
            lob_segment_t *lob_segment = (lob_segment_t *)lob_part->lob_entity.segment;
            if (lob_segment != NULL) {
                if (lob_corruption_scan(session, lob_segment, corrupt_info) != GS_SUCCESS) {
                    return GS_ERROR;
                }
            }
        }
    }

    return GS_SUCCESS;
}

static status_t part_get_lob_entity_size(knl_session_t *session, lob_part_t *lob_part, seg_size_type_t type,
    int64* size)
{
    page_id_t entry;
    int64 segment_size;
    uint32 pages, page_size, extents;

    entry = LOB_SEGMENT(session, lob_part->lob_entity.entry, lob_part->lob_entity.segment)->extents.first;
    if (knl_get_segment_size(session, entry, &extents, &pages, &page_size) != GS_SUCCESS) {
        return GS_ERROR;
    }

    knl_calc_seg_size(type, pages, page_size, extents, &segment_size);
    *size += segment_size;

    return GS_SUCCESS;
}

status_t part_get_lob_segment_size(knl_session_t *session, knl_dictionary_t *dc, knl_handle_t lob_handle,
    seg_size_type_t type, int64 *size)
{
    lob_t *lob = (lob_t *)lob_handle;
    lob_part_t *lob_part = NULL;
    lob_part_t *lob_subpart = NULL;
    table_part_t *table_part = NULL;
    table_t *table = DC_TABLE(dc);

    for (uint32 i = 0; i < table->part_table->desc.partcnt; i++) {
        table_part = TABLE_GET_PART(table, i);
        if (!IS_READY_PART(table_part)) {
            continue;
        }

        lob_part = LOB_GET_PART(lob, i);
        if (!IS_PARENT_LOBPART(&lob_part->desc)) {
            if (lob_part->lob_entity.segment == NULL) {
                table_part = TABLE_GET_PART(table, lob_part->part_no);
                if (dc_load_table_part_segment(session, dc->handle, table_part) != GS_SUCCESS) {
                    return GS_ERROR;
                }
            }

            if (lob_part->lob_entity.segment == NULL) {
                continue;
            }
            
            if (part_get_lob_entity_size(session, lob_part, type, size) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        for (uint32 j = 0; j < lob_part->desc.subpart_cnt; j++) {
            lob_subpart = PART_GET_SUBENTITY(lob->part_lob, lob_part->subparts[j]);
            if (lob_subpart == NULL) {
                continue;
            }

            if (lob_subpart->lob_entity.segment == NULL) {
                table_part = TABLE_GET_PART(table, i);
                table_part_t *table_subpart = PART_GET_SUBENTITY(table->part_table, table_part->subparts[j]);
                if (dc_load_table_part_segment(session, dc->handle, (table_part_t *)table_subpart) != GS_SUCCESS) {
                    return GS_ERROR;
                }
            }

            if (lob_subpart->lob_entity.segment == NULL) {
                continue;
            }
            
            if (part_get_lob_entity_size(session, (lob_part_t *)lob_subpart, type, size) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }
    return GS_SUCCESS;
}

int64 part_get_heap_subsegment_size(knl_session_t *session, knl_dictionary_t *dc, table_part_t *table_part,
    part_segment_desc_t part_segment_desc)
{
    page_id_t entry;
    int64 segment_size;
    uint32 pages, page_size, extents;
    table_t *table = DC_TABLE(dc);
    seg_size_type_t type = part_segment_desc.type;
    uint32 part_start = part_segment_desc.part_start;
    uint32 part_end = part_segment_desc.part_end;
    int64 part_size = 0;

    table_part_t *table_subpart = NULL;
    for (uint32 i = part_start; i < part_end; i++) {
        table_subpart = PART_GET_SUBENTITY(table->part_table, table_part->subparts[i]);
        if (table_subpart == NULL) {
            continue;
        }

        if (!table_subpart->heap.loaded) {
            if (dc_load_table_part_segment(session, dc->handle, (table_part_t *)table_subpart) != GS_SUCCESS) {
                return -1;
            }
        }

        if (table_subpart->heap.segment == NULL) {
            continue;
        }

        entry = HEAP_SEGMENT(session, table_subpart->heap.entry, table_subpart->heap.segment)->extents.first;
        if (knl_get_segment_size(session, entry, &extents, &pages, &page_size) != GS_SUCCESS) {
            return -1;
        }

        knl_calc_seg_size(type, pages, page_size, extents, &segment_size);
        part_size += segment_size;
    }

    return part_size;
}

status_t part_get_heap_segment_size(knl_session_t *session, knl_dictionary_t *dc, table_part_t *table_part,
    seg_size_type_t type, int64 *part_size)
{
    page_id_t entry;
    int64 segment_size;
    uint32 pages, page_size, extents;
    *part_size = 0;

    if (!IS_PARENT_TABPART(&table_part->desc)) {
        if (!table_part->heap.loaded) {
            if (dc_load_table_part_segment(session, dc->handle, table_part) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        if (table_part->heap.segment == NULL) {
            return GS_SUCCESS;
        }

        entry = HEAP_SEGMENT(session, table_part->heap.entry, table_part->heap.segment)->extents.first;
        if (knl_get_segment_size(session, entry, &extents, &pages, &page_size) != GS_SUCCESS) {
            return GS_ERROR;
        }

        knl_calc_seg_size(type, pages, page_size, extents, &segment_size);
        *part_size += segment_size;

        return GS_SUCCESS;
    }

    part_segment_desc_t part_segment_desc = {
        .type = type,
        .part_start = 0,
        .part_end = table_part->desc.subpart_cnt
    };

    *part_size = part_get_heap_subsegment_size(session, dc, table_part, part_segment_desc);

    if (*part_size < 0) {
        *part_size = 0;
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

bool32 db_tabpart_has_segment(part_table_t *part_table, table_part_t *table_part)
{
    if (!IS_PARENT_TABPART(&table_part->desc)) {
        bool32 has_segment = ((table_part->heap.segment == NULL) ? GS_FALSE : GS_TRUE);
        return has_segment;
    } else {
        table_part_t *table_subpart = NULL;
        for (uint32 i = 0; i < table_part->desc.subpart_cnt; i++) {
            table_subpart = PART_GET_SUBENTITY(part_table, table_part->subparts[i]);
            if (table_subpart == NULL) {
                continue;
            }

            if (table_subpart->heap.segment != NULL) {
                return GS_TRUE;
            }
        }
    }

    return GS_FALSE;
}

bool32 db_lobpart_has_segment(part_lob_t *part_lob, lob_part_t *lob_part)
{
    if (!IS_PARENT_LOBPART(&lob_part->desc)) {
        bool32 has_segment = ((lob_part->lob_entity.segment == NULL) ? GS_FALSE : GS_TRUE);
        return has_segment;
    } else {
        lob_part_t *lob_subpart = NULL;
        for (uint32 i = 0; i < lob_part->desc.subpart_cnt; i++) {
            lob_subpart = PART_GET_SUBENTITY(part_lob, lob_part->subparts[i]);
            if (lob_subpart == NULL) {
                continue;
            }

            if (lob_subpart->lob_entity.segment != NULL) {
                return GS_TRUE;
            }
        }
    }

    return GS_FALSE;
}

status_t db_update_subtabpart_entry(knl_session_t *session, knl_table_part_desc_t *desc, page_id_t entry)
{
    row_assist_t ra;
    uint16 size;

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_SUB_TABLE_PARTS_ID, IX_SYS_TABLESUBPART001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&desc->uid,
        sizeof(uint32), IX_COL_SYS_TABLESUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&desc->table_id,
        sizeof(uint32), IX_COL_SYS_TABLESUBPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
        (void *)&desc->parent_partid, sizeof(uint32), IX_COL_SYS_TABLESUBPART001_PARENT_PART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&desc->part_id,
        sizeof(uint32), IX_COL_SYS_TABLESUBPART001_SUB_PART_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s", cursor->rowid.file,
                  cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name);

    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), UPDATE_COLUMN_COUNT_ONE);
    (void)row_put_int64(&ra, *(int64 *)&entry);
    cursor->update_info.count = UPDATE_COLUMN_COUNT_ONE;
    cursor->update_info.columns[0] = SYS_TABLESUBPART_COL_ENTRY;  // table part entry
    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

    if (knl_internal_update(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t db_update_sublobpart_entry(knl_session_t *session, knl_lob_part_desc_t *desc, page_id_t entry)
{
    row_assist_t ra;
    uint16 size;
    
    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_SUB_LOB_PARTS_ID, IX_SYS_LOBSUBPART001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&desc->uid,
                     sizeof(uint32), IX_COL_SYS_LOBSUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&desc->table_id,
                     sizeof(uint32), IX_COL_SYS_LOBSUBPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
        (void *)&desc->parent_partid, sizeof(uint32), IX_COL_SYS_LOBSUBPART001_PARENT_PART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&desc->column_id,
                     sizeof(uint32), IX_COL_SYS_LOBSUBPART001_COLUMN_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&desc->part_id,
                     sizeof(uint32), IX_COL_SYS_LOBSUBPART001_SUB_PART_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s", cursor->rowid.file,
                  cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name);

    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), UPDATE_COLUMN_COUNT_ONE);
    (void)row_put_int64(&ra, *(int64 *)&entry);
    cursor->update_info.count = UPDATE_COLUMN_COUNT_ONE;
    cursor->update_info.columns[0] = SYS_LOBSUBPART_COL_ENTRY;  // lob subpart entry
    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

    if (knl_internal_update(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t db_update_parent_tabpartid(knl_session_t *session, uint32 uid, uint32 table_id, uint32 old_partid,
    uint32 new_partid)
{
    row_assist_t ra;

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_SUB_TABLE_PARTS_ID, IX_SYS_TABLESUBPART001_ID);
    knl_init_index_scan(cursor, GS_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&uid,
        sizeof(uint32), IX_COL_SYS_TABLESUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&table_id,
        sizeof(uint32), IX_COL_SYS_TABLESUBPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&old_partid,
        sizeof(uint32), IX_COL_SYS_TABLESUBPART001_PARENT_PART_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_TABLESUBPART001_SUB_PART_ID);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, (void *)&uid,
        sizeof(uint32), IX_COL_SYS_TABLESUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, (void *)&table_id,
        sizeof(uint32), IX_COL_SYS_TABLESUBPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, (void *)&old_partid,
        sizeof(uint32), IX_COL_SYS_TABLESUBPART001_PARENT_PART_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_TABLESUBPART001_SUB_PART_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    while (!cursor->eof) {
        row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), UPDATE_COLUMN_COUNT_ONE);
        (void)row_put_int32(&ra, (int32)new_partid);
        cursor->update_info.count = UPDATE_COLUMN_COUNT_ONE;
        cursor->update_info.columns[0] = SYS_TABLESUBPART_COL_PARENT_PART_ID;  // parent part id
        cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, NULL);

        if (knl_internal_update(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t db_update_parent_lobpartid(knl_session_t *session, knl_lob_desc_t *desc, uint32 old_partid, uint32 new_partid)
{
    row_assist_t ra;

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_SUB_LOB_PARTS_ID, IX_SYS_LOBSUBPART001_ID);
    knl_init_index_scan(cursor, GS_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&desc->uid,
        sizeof(uint32), IX_COL_SYS_LOBSUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&desc->table_id,
        sizeof(uint32), IX_COL_SYS_LOBSUBPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&old_partid,
        sizeof(uint32), IX_COL_SYS_LOBSUBPART001_PARENT_PART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&desc->column_id,
        sizeof(uint32), IX_COL_SYS_LOBSUBPART001_COLUMN_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_LOBSUBPART001_SUB_PART_ID);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, (void *)&desc->uid,
        sizeof(uint32), IX_COL_SYS_LOBSUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, (void *)&desc->table_id,
        sizeof(uint32), IX_COL_SYS_LOBSUBPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, (void *)&old_partid,
        sizeof(uint32), IX_COL_SYS_LOBSUBPART001_PARENT_PART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, (void *)&desc->column_id,
        sizeof(uint32), IX_COL_SYS_LOBSUBPART001_COLUMN_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_LOBSUBPART001_SUB_PART_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    while (!cursor->eof) {
        row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), UPDATE_COLUMN_COUNT_ONE);
        (void)row_put_int32(&ra, (int32)new_partid);
        cursor->update_info.count = UPDATE_COLUMN_COUNT_ONE;
        cursor->update_info.columns[0] = SYS_LOBSUBPART_COL_PARENT_PART_ID;  // parent part id
        cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, NULL);

        if (knl_internal_update(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

table_part_t* subpart_get_parent_tabpart(part_table_t *part_table, uint32 parent_partid)
{
    table_part_t *table_part = NULL;
    uint32 partcnt = part_table->desc.partcnt + part_table->desc.not_ready_partcnt;

    for (uint32 i = 0; i < partcnt; i++) {
        table_part = PART_GET_ENTITY(part_table, i);
        if (!IS_READY_PART(table_part)) {
            continue;
        }
        
        if (parent_partid == table_part->desc.part_id) {
            return table_part;
        }
    }

    return NULL;
}

status_t subpart_generate_part_key(row_head_t *row, uint16 *offsets, uint16 *lens, part_table_t *part_table,
    part_key_t *key)
{
    uint16 col_id;
    uint16 column_count;

    column_count = ROW_COLUMN_COUNT(row);
    part_key_init(key, part_table->desc.subpartkeys);
    for (uint32 i = 0; i < part_table->desc.subpartkeys; i++) {
        col_id = part_table->sub_keycols[i].column_id;
        knl_panic(col_id < column_count);

        if (lens[col_id] == GS_NULL_VALUE_LEN) {
            part_put_null(key);
            continue;
        }
        
        gs_type_t type = part_table->sub_keycols[i].datatype;
        char temp[NUMBER_ZERO_STORAGR_LEN] = {0};
        uint32 org_len = 0;
        if (CSF_IS_DECIMAL_ZERO(row->is_csf, lens[col_id], type)) {
            part_get_number_zero(type, temp, NUMBER_ZERO_STORAGR_LEN, &org_len);
            if (part_put_data(key, temp, org_len, type) != GS_SUCCESS) {
                return GS_ERROR;
            }
        } else {
            if (part_put_data(key, (char *)row + offsets[col_id], lens[col_id], type) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }

    return GS_SUCCESS;
}

bool32 knl_is_parent_part(knl_handle_t dc_entity, uint32 part_no)
{
    dc_entity_t *entity = (dc_entity_t *)dc_entity;
    part_table_t *part_table = entity->table.part_table;
    table_part_t *table_part = PART_GET_ENTITY(part_table, part_no);
    if (!IS_READY_PART(table_part)) {
        return GS_FALSE;
    }
    
    return IS_PARENT_TABPART(&table_part->desc);
}

knl_handle_t knl_get_parent_part(knl_handle_t dc_entity, uint32 part_no)
{
    dc_entity_t *entity = (dc_entity_t *)dc_entity;
    part_table_t *part_table = entity->table.part_table;
    table_part_t *table_part = PART_GET_ENTITY(part_table, part_no);
    if (!IS_READY_PART(table_part)) {
        return NULL;
    } else {
        return table_part;
    }
}

uint16 knl_subpart_key_count(knl_handle_t dc_entity)
{
    dc_entity_t *entity = (dc_entity_t *)dc_entity;
    part_table_t *part_table = entity->table.part_table;
    return (uint16)part_table->desc.subpartkeys;
}

uint16 knl_subpart_key_column_id(knl_handle_t dc_entity, uint16 id)
{
    dc_entity_t *entity = (dc_entity_t *)dc_entity;
    part_table_t *part_table = entity->table.part_table;
    return part_table->sub_keycols[id].column_id;
}

uint32 knl_locate_subpart_border(knl_handle_t session, knl_handle_t dc_entity, knl_part_key_t *locate_key,
    uint32 compart_no, bool32 is_left)
{
    int32 result;
    int32 curr = 0;
    int32 begin = 0;
    uint32 subpart_no = GS_INVALID_ID32;
    part_key_t *key = locate_key->key;
    table_part_t *table_subpart = NULL;
    dc_entity_t *entity = (dc_entity_t *)dc_entity;
    table_t *table = &entity->table;
    part_table_t *part_table = table->part_table;
    
    knl_decode_part_key(key, locate_key);
    knl_panic_log(key->column_count == part_table->desc.subpartkeys, "the column_count is not equal to part_table's "
                  "subpartkeys, panic info: table %s column_count %u subpartkeys %u", table->desc.name,
                  key->column_count, part_table->desc.subpartkeys);

    table_part_t *table_compart = TABLE_GET_PART(table, compart_no);
    int32 end = table_compart->desc.subpart_cnt - 1;
    
    while (begin <= end) {
        curr = ((uint32)(end + begin)) >> 1;
        table_subpart = PART_GET_SUBENTITY(part_table, table_compart->subparts[(uint32)curr]);
        result = part_compare_border(part_table->sub_keycols, locate_key, table_subpart->desc.groups, is_left);
        if (result <= 0) {
            subpart_no = (uint32)curr;
            end = curr - 1;
        } else {
            begin = curr + 1;
        }
    }

    return subpart_no;
}

bool32 subpart_table_find_by_name(part_table_t *part_table, text_t *name, table_part_t **table_compart,
    table_part_t **table_subpart)
{
    if (!IS_COMPART_TABLE(part_table)) {
        return GS_FALSE;
    }
    
    table_part_t *subpart = NULL;
    uint32 hash = dc_cal_part_name_hash(name);
    part_bucket_t *bucket = &part_table->sub_pbuckets[hash];
    uint32 subpart_no = bucket->first;
    
    while (subpart_no != GS_INVALID_ID32) {
        subpart = PART_GET_SUBENTITY(part_table, subpart_no);
        if (cm_text_str_equal(name, subpart->desc.name)) {
            *(table_subpart) = subpart;
            *(table_compart) = PART_GET_ENTITY(part_table, subpart->parent_partno);
            break;
        }

        subpart_no = subpart->pnext;
    }

    if (subpart_no == GS_INVALID_ID32) {
        return GS_FALSE;
    }

    return GS_TRUE;
}

status_t knl_find_subpart_by_name(knl_handle_t dc_entity, text_t *name, uint32 *compart_no, uint32 *subpart_no)
{
    table_part_t *compart = NULL;
    table_part_t *subpart = NULL;
    dc_entity_t *entity = (dc_entity_t *)dc_entity;
    part_table_t *part_table = entity->table.part_table;
    
    if (!subpart_table_find_by_name(part_table, name, &compart, &subpart)) {
        GS_THROW_ERROR(ERR_PARTITION_NOT_EXIST, "table", T2S(name));
        return GS_ERROR;
    }

    *compart_no = compart->part_no;
    *subpart_no = subpart->part_no;

    return GS_SUCCESS;
}
    
status_t db_update_subtabpart_count(knl_session_t *session, uint32 uid, uint32 tid, uint32 compart_id, bool32 is_add)
{
    row_assist_t ra;
    
    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_TABLEPART_ID, IX_SYS_TABLEPART001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &uid,
        sizeof(uint32), IX_COL_SYS_TABLEPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &tid,
        sizeof(uint32), IX_COL_SYS_TABLEPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &compart_id,
        sizeof(uint32), IX_COL_SYS_TABLEPART001_PART_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s", cursor->rowid.file,
                  cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name);
    uint32 subpart_cnt = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLEPART_COL_SUBPART_CNT) + (is_add ? 1 : -1);
    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), UPDATE_COLUMN_COUNT_ONE);
    (void)row_put_int32(&ra, subpart_cnt);
    cursor->update_info.count = UPDATE_COLUMN_COUNT_ONE;
    cursor->update_info.columns[0] = SYS_TABLEPART_COL_SUBPART_CNT;
    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, NULL);

    if (knl_internal_update(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    GS_LOG_DEBUG_INF("update count: uid: %d, tid: %d, ppart id: %d", uid, tid, compart_id);
    GS_LOG_DEBUG_INF("update count: subpartcnt after update is: %d, the operation is(1:add, 0:drop): %d",
                     subpart_cnt, is_add);

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t db_update_subpart_flag(knl_session_t *session, knl_dictionary_t *dc, table_part_t *compart,
    uint32 subpart_id, part_flag_type_e part_flag)
{
    row_assist_t ra;
    knl_table_part_desc_t desc = { 0 };

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_SUB_TABLE_PARTS_ID, IX_SYS_TABLESUBPART001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &compart->desc.uid,
        sizeof(uint32), IX_COL_SYS_TABLESUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &compart->desc.table_id,
        sizeof(uint32), IX_COL_SYS_TABLESUBPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &compart->desc.part_id,
        sizeof(uint32), IX_COL_SYS_TABLESUBPART001_PARENT_PART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &subpart_id,
        sizeof(uint32), IX_COL_SYS_TABLESUBPART001_SUB_PART_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s", cursor->rowid.file,
                  cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name);
    dc_convert_table_part_desc(cursor, &desc);
    db_set_part_flag(&desc, part_flag);

    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), UPDATE_COLUMN_COUNT_ONE);
    (void)row_put_int32(&ra, (int32)desc.flags);
    cursor->update_info.count = UPDATE_COLUMN_COUNT_ONE;
    cursor->update_info.columns[0] = SYS_TABLEPART_COL_FLAGS;

    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, NULL);
    if (knl_internal_update(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static status_t subpart_truncate_sublobpart(knl_session_t *session, knl_dictionary_t *dc, uint32 compart_no,
    uint32 subpart_no, bool32 reuse_storage)
{
    dc_entity_t *entity = DC_ENTITY(dc);

    if (!entity->contain_lob) {
        return GS_SUCCESS;
    }

    knl_column_t *column = NULL;
    lob_t *lob = NULL;
    lob_part_t *lob_part = NULL;
    lob_part_t *lob_subpart = NULL;
    for (uint32 i = 0; i < entity->column_count; i++) {
        column = dc_get_column(entity, i);
        if (!COLUMN_IS_LOB(column)) {
            continue;
        }

        lob = (lob_t *)column->lob;
        lob_part = LOB_GET_PART(lob, compart_no);
        lob_subpart = PART_GET_SUBENTITY(lob->part_lob, lob_part->subparts[subpart_no]);
        if (lob_part_segment_prepare(session, (lob_part_t *)lob_subpart, reuse_storage,
            LOB_TRUNCATE_PART_SEGMENT) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t db_truncate_table_subpart(knl_session_t *session, knl_dictionary_t *dc, table_part_t *table_subpart,
    uint32 compart_no, bool32 reuse_storage)
{
    dc_entity_t *entity = DC_ENTITY(dc);
    
    if (heap_part_segment_prepare(session, (table_part_t *)table_subpart, reuse_storage,
        HEAP_TRUNCATE_PART_SEGMENT) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (subpart_delete_sub_idx_part(session, dc, compart_no, table_subpart->part_no, reuse_storage) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (subpart_truncate_sublobpart(session, dc, compart_no, table_subpart->part_no, reuse_storage) != GS_SUCCESS) {
        return GS_ERROR;
    }

    stats_table_mon_t *table_stats = &entity->entry->appendix->table_smon;
    table_stats->is_change = GS_TRUE;
    table_stats->drop_segments++;
    table_stats->timestamp = cm_now();
    return GS_SUCCESS;
}

status_t db_altable_truncate_subpart(knl_session_t *session, knl_dictionary_t *dc, knl_alt_part_t *def)
{
    table_t *table = DC_TABLE(dc);
    knl_session_t *se = (knl_session_t *)session;

    if (!table->desc.parted || !IS_COMPART_TABLE(table->part_table)) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "alter table truncate subpartition", table->desc.name);
        return GS_ERROR;
    }

    table_part_t *table_compart = NULL;
    table_part_t *table_subpart = NULL;
    if (!subpart_table_find_by_name(table->part_table, &def->name, &table_compart, &table_subpart)) {
        GS_THROW_ERROR(ERR_PARTITION_NOT_EXIST, "table", T2S(&def->name));
        return GS_ERROR;
    }

    if (table_subpart->desc.not_ready) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "trucnate a subpartition");
        return GS_ERROR;
    }
    
    if (db_table_is_referenced(session, table, GS_TRUE)) {
        GS_THROW_ERROR(ERR_TABLE_IS_REFERENCED);
        return GS_ERROR;
    }

    if (table_subpart->heap.segment == NULL) {
        return GS_SUCCESS;
    }

    if (dc->type != DICT_TYPE_TABLE || table_subpart->desc.space_id == SYS_SPACE_ID ||
        def->option != TRUNC_RECYCLE_STORAGE || !se->kernel->attr.recyclebin) {
        return db_truncate_table_subpart(session, dc, table_subpart, table_compart->part_no,
            def->option & TRUNC_REUSE_STORAGE);
    } else {
        return rb_truncate_table_subpart(session, dc, table_subpart, table_compart->part_no);
    }
}

status_t part_redis_get_subpartno(knl_session_t *session, knl_dictionary_t *dc, knl_cursor_t *cursor_delete,
    knl_cursor_t *cursor_insert)
{
    dc_entity_t *entity = DC_ENTITY(dc);
    table_t *table = &entity->table;
    part_table_t *part_table = table->part_table;

    CM_SAVE_STACK(session->stack);
    part_key_t *part_key = (part_key_t *)cm_push(session->stack, GS_MAX_COLUMN_SIZE);
    errno_t ret = memset_sp(part_key, GS_MAX_COLUMN_SIZE, 0, GS_MAX_COLUMN_SIZE);
    knl_securec_check(ret);
    part_key_init(part_key, part_table->desc.subpartkeys);
    
    cm_decode_row((char *)cursor_delete->row, cursor_delete->offsets, cursor_delete->lens, NULL);
    if (subpart_generate_part_key(cursor_delete->row, cursor_delete->offsets, cursor_delete->lens, part_table,
        part_key) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    cursor_insert->part_loc.subpart_no = knl_locate_subpart_key(entity, cursor_insert->part_loc.part_no, part_key);

    /* for hash part coalesce, rows will be relocated into a new partition, but some rows can
     * not be inserted into the new partition because it values not match the boundval of the new partition. in
     * this case we will return error
     */
    if (part_table->desc.parttype == PART_TYPE_HASH && cursor_insert->part_loc.subpart_no == GS_INVALID_ID32) {
        GS_THROW_ERROR(ERR_INVALID_DEST_PART);
        return GS_ERROR;
    }
    
    knl_set_table_part(cursor_insert, cursor_insert->part_loc);
    return GS_SUCCESS;
}

typedef struct st_part_match_cond {
    knl_session_t *session;
    knl_cursor_t *cursor;
    uint32 flags;
}part_match_cond_t;

static status_t part_match_flags_cond(void *handle, bool32 *match)
{
    part_match_cond_t *cond = (part_match_cond_t *)handle;
    knl_cursor_t *cursor = cond->cursor;
    *match = GS_FALSE;
    uint32 flags = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLEPART_COL_FLAGS);
    if (flags & cond->flags) {
        *match = GS_TRUE;
    }
    return GS_SUCCESS;
}

void part_set_garbage_part_scankey(knl_session_t *session, knl_cursor_t *cursor, part_table_t *part_table,
    part_match_cond_t *cond)
{
    knl_init_index_scan(cursor, GS_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &part_table->desc.uid,
        sizeof(uint32), IX_COL_SYS_TABLEPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &part_table->desc.table_id,
        sizeof(uint32), IX_COL_SYS_TABLEPART001_TABLE_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_TABLEPART001_PART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &part_table->desc.uid,
        sizeof(uint32), IX_COL_SYS_TABLEPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &part_table->desc.table_id,
        sizeof(uint32), IX_COL_SYS_TABLEPART001_TABLE_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_TABLEPART001_PART_ID);
    cursor->stmt = (void *)cond;
    session->match_cond = part_match_flags_cond;
    cond->session = session;
    cond->cursor = cursor;
    cond->flags = PARTITON_NOT_READY;
}

status_t part_clean_garbage_partition(knl_session_t *session, knl_dictionary_t *dc)
{
    knl_match_cond_t org_match_cond = session->match_cond;
    knl_altable_def_t def_drop;
    table_t *table = DC_TABLE(dc);
    part_table_t *part_table = table->part_table;
    part_match_cond_t cond;

    knl_set_session_scn(session, GS_INVALID_ID64);
    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_TABLEPART_ID, IX_SYS_TABLEPART001_ID);
    part_set_garbage_part_scankey(session, cursor, part_table, &cond);

    for (;;) {
        session->match_cond = part_match_flags_cond;

        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            session->match_cond = org_match_cond;
            return GS_ERROR;
        }

        if (cursor->eof) {
            break;
        }

        def_drop.action = ALTABLE_DROP_PARTITION;
        def_drop.part_def.name.str = CURSOR_COLUMN_DATA(cursor, SYS_TABLEPART_COL_NAME);
        def_drop.part_def.name.len = CURSOR_COLUMN_SIZE(cursor, SYS_TABLEPART_COL_NAME);
        def_drop.part_def.is_garbage_clean = GS_TRUE;
        def_drop.options = DROP_DIRECTLY;
        session->match_cond = org_match_cond;
        if (db_altable_drop_part(session, dc, &def_drop, GS_FALSE) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            GS_LOG_RUN_ERR("[DB] failed to delete garbage partition %s from system TABLEPART",
                T2S(&def_drop.part_def.name));
            session->match_cond = org_match_cond;
            return GS_ERROR;
        }

        GS_LOG_RUN_INF("[DB] delete one garbage partition from system TABLEPART, the partition name is %s",
            T2S(&def_drop.part_def.name));
    }
    CM_RESTORE_STACK(session->stack);
    session->match_cond = org_match_cond;
    return GS_SUCCESS;
}

status_t subpart_clean_garbage_partition(knl_session_t *session, knl_dictionary_t *dc)
{
    knl_altable_def_t def_drop;
    table_t *table = DC_TABLE(dc);
    part_table_t *part_table = table->part_table;

    knl_set_session_scn(session, GS_INVALID_ID64);
    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_SUB_TABLE_PARTS_ID, IX_SYS_TABLESUBPART001_ID);
    knl_init_index_scan(cursor, GS_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &part_table->desc.uid,
        sizeof(uint32), IX_COL_SYS_TABLESUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &part_table->desc.table_id,
        sizeof(uint32), IX_COL_SYS_TABLESUBPART001_TABLE_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_TABLESUBPART001_PARENT_PART_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_TABLESUBPART001_SUB_PART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &part_table->desc.uid,
        sizeof(uint32), IX_COL_SYS_TABLESUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &part_table->desc.table_id,
        sizeof(uint32), IX_COL_SYS_TABLESUBPART001_TABLE_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_TABLESUBPART001_PARENT_PART_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_TABLESUBPART001_SUB_PART_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    while (!cursor->eof) {
        uint32 flag = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLEPART_COL_FLAGS);
        if (flag & PARTITON_NOT_READY) {
            def_drop.action = ALTABLE_DROP_SUBPARTITION;
            def_drop.part_def.name.str = CURSOR_COLUMN_DATA(cursor, SYS_TABLEPART_COL_NAME);
            def_drop.part_def.name.len = CURSOR_COLUMN_SIZE(cursor, SYS_TABLEPART_COL_NAME);
            def_drop.part_def.is_garbage_clean = GS_TRUE;
            def_drop.options = DROP_DIRECTLY;

            if (db_altable_drop_subpartition(session, dc, &def_drop, GS_FALSE) != GS_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                GS_LOG_RUN_ERR("[DB] failed to delete garbage subpartition %s from system TABLEPART",
                    T2S(&def_drop.part_def.name));
                return GS_ERROR;
            }

            GS_LOG_RUN_INF("[DB] delete one garbage subpartition from system TABLEPART, the partition name is %s",
                T2S(&def_drop.part_def.name));
        }

        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t db_update_part_name(knl_session_t *session, table_part_t *table_part, text_t *new_name)
{
    uint16 size;
    row_assist_t ra;
    char name_buffer[GS_NAME_BUFFER_SIZE] = { 0 };

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_TABLEPART_ID, IX_SYS_TABLEPART001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_scan_key_t *key = &cursor->scan_range.l_key;
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_INTEGER, &table_part->desc.uid,
                     sizeof(uint32), IX_COL_SYS_TABLEPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_INTEGER, &table_part->desc.table_id,
                     sizeof(uint32), IX_COL_SYS_TABLEPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_INTEGER, &table_part->desc.part_id,
                     sizeof(uint32), IX_COL_SYS_TABLEPART001_PART_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s", cursor->rowid.file,
                  cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name);

    cm_text2str(new_name, name_buffer, GS_NAME_BUFFER_SIZE);
    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), UPDATE_COLUMN_COUNT_ONE);
    (void)row_put_str(&ra, name_buffer);
    cursor->update_info.count = UPDATE_COLUMN_COUNT_ONE;
    cursor->update_info.columns[0] = SYS_TABLEPART_COL_NAME;

    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

    if (knl_internal_update(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static status_t db_update_tabpart_id(knl_session_t *session, knl_cursor_t *cursor, table_part_t *table_part,
    uint32 new_partid)
{
    uint16 size;
    row_assist_t ra;
    knl_table_part_desc_t desc = { 0 };

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_TABLEPART_ID, IX_SYS_TABLEPART001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_scan_key_t *key = &cursor->scan_range.l_key;
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_INTEGER, &table_part->desc.uid,
                     sizeof(uint32), IX_COL_SYS_TABLEPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_INTEGER, &table_part->desc.table_id,
                     sizeof(uint32), IX_COL_SYS_TABLEPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_INTEGER, &table_part->desc.part_id,
                     sizeof(uint32), IX_COL_SYS_TABLEPART001_PART_ID);
    
    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }
    
    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s", cursor->rowid.file,
                  cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name);
    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), UPDATE_COLUMN_COUNT_ONE);
    (void)row_put_int32(&ra, (int32)new_partid);
    cursor->update_info.count = UPDATE_COLUMN_COUNT_ONE;
    cursor->update_info.columns[0] = SYS_TABLEPART_COL_PART_ID;
    
    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);
    
    if (knl_internal_update(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    dc_convert_table_part_desc(cursor, &desc);
    if (IS_PARENT_TABPART(&desc)) {
        if (db_update_parent_tabpartid(session, desc.uid, desc.table_id, desc.part_id, new_partid) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t db_update_lobpart_id(knl_session_t *session, knl_cursor_t *cursor, table_part_t *table_part,
    uint32 column_id, uint32 new_partid)
{
    uint16 size;
    row_assist_t ra;

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_LOBPART_ID, IX_SYS_LOBPART001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_scan_key_t *key = &cursor->scan_range.l_key;
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_INTEGER, &table_part->desc.uid,
                     sizeof(uint32), IX_COL_SYS_LOBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_INTEGER, &table_part->desc.table_id,
                     sizeof(uint32), IX_COL_SYS_LOBPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_INTEGER, &column_id,
                     sizeof(uint32), IX_COL_SYS_LOBPART001_COLUMN_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_INTEGER, &table_part->desc.part_id,
                     sizeof(uint32), IX_COL_SYS_LOBPART001_PART_ID);
    
    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }
    
    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s", cursor->rowid.file,
                  cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name);
    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), UPDATE_COLUMN_COUNT_ONE);
    (void)row_put_int32(&ra, (int32)new_partid);
    cursor->update_info.count = UPDATE_COLUMN_COUNT_ONE;
    cursor->update_info.columns[0] = SYS_LOBPART_COL_PART_ID;
    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);
    if (knl_internal_update(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t db_update_lobpart_ids(knl_session_t *session, knl_cursor_t *cursor, table_part_t *table_part,
    knl_dictionary_t *dc, uint32 new_partid)
{
    lob_t *lob = NULL;
    knl_column_t *column = NULL;
    table_t *table = DC_TABLE(dc);
    dc_entity_t *entity = DC_ENTITY(dc);

    for (uint32 i = 0; i < table->desc.column_count; i++) {
        column = dc_get_column(entity, i);
        if (!COLUMN_IS_LOB(column)) {
            continue;
        }

        lob = (lob_t *)column->lob;
        if (db_update_lobpart_id(session, cursor, table_part, lob->desc.column_id, new_partid) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (IS_PARENT_TABPART(&table_part->desc)) {
            if (db_update_parent_lobpartid(session, &lob->desc, table_part->desc.part_id, new_partid) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }

    return GS_SUCCESS;
}

status_t db_update_part_id(knl_session_t *session, knl_dictionary_t *dc, table_part_t *table_part, uint32 new_partid)
{
    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    if (db_update_tabpart_id(session, cursor, table_part, new_partid) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (db_upd_idx_part_ids(session, cursor, table_part, dc, new_partid) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (db_update_lobpart_ids(session, cursor, table_part, dc, new_partid) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

void part_put_logic_log(knl_session_t *session, const knl_dictionary_t *dc)
{
    rd_table_t rd_altable;
    rd_altable.op_type = RD_ALTER_TABLE;
    rd_altable.uid = dc->uid;
    rd_altable.oid = dc->oid;
    log_put(session, RD_LOGIC_OPERATION, &rd_altable, sizeof(rd_table_t), LOG_ENTRY_FLAG_NONE);
}
