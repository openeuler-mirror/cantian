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
 * knl_part_add.c
 *
 *
 * IDENTIFICATION
 * src/kernel/table/knl_part_add.c
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
#include "srv_instance.h"

static status_t part_verify_add_range_key(knl_dictionary_t *dc, knl_part_def_t *part_def)
{
    table_t *table;
    table_part_t *table_part;
    knl_part_column_desc_t *part_column;
    knl_part_key_t part_key;

    table = DC_TABLE(dc);
    table_part = TABLE_GET_PART(table, table->part_table->desc.partcnt - 1);
    part_column = table->part_table->keycols;

    knl_decode_part_key(part_def->partkey, &part_key);

    if (part_compare_range_key(part_column, &part_key.decoder, table_part->desc.groups) <= 0) {
        CT_THROW_ERROR(ERR_INVALID_PART_KEY, "partition bound must collate higher than that of the last partition.");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t part_verify_add_list_key(knl_session_t *session, knl_dictionary_t *dc, knl_part_def_t *part_def)
{
    char *str = NULL;
    uint32 groupcnt, part_no;
    part_decode_key_t *groups = NULL;
    table_t *table = DC_TABLE(dc);
    dc_entity_t *entity = DC_ENTITY(dc);

    uint32 partkeys = table->part_table->desc.partkeys;
    /*
     * the interface will alloc dc for calculating part key, it must be latched by entity->cbo_latch for preventing
     * alloc dc concurrently when delay loading statistics(eg: knl_get_cbo_part_xxx).
     */
    cm_latch_x(&entity->cbo_latch, 0, NULL);
    if (dc_decode_part_key_group(session, entity, partkeys, part_def->partkey, &groups, &groupcnt) != CT_SUCCESS) {
        cm_unlatch(&entity->cbo_latch, NULL);
        return CT_ERROR;
    }
    cm_unlatch(&entity->cbo_latch, NULL);

    for (uint32 i = 0; i < groupcnt; i++) {
        part_no = part_locate_list_key(table->part_table, &groups[i]);
        if (part_no == CT_INVALID_ID32) {
            continue;
        }
        
        table_part_t *table_part = TABLE_GET_PART(table, part_no);
        if (i == PART_KEY_FIRST) {
            str = "st";
        } else if (i == PART_KEY_SECOND) {
            str = "nd";
        } else if (i == PART_KEY_THIRD) {
            str = "rd";
        } else {
            str = "th";
        }
        
        CT_THROW_ERROR(ERR_DUPLICATE_PART_KEY, i + 1, str, table_part->desc.name);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t subpart_check_def_add_partition(part_table_t *part_table, knl_part_obj_def_t *def,
    knl_part_def_t *part_def)
{
    knl_part_def_t *subpart_def = NULL;
    knl_part_def_t *subcmp_def = NULL;
    
    if (def->subpart_type == PART_TYPE_HASH && part_def->subparts.count > CT_MAX_HASH_SUBPART_COUNT) {
        CT_THROW_ERROR(ERR_EXCEED_MAX_SUBPARTCNT, (uint32)CT_MAX_HASH_SUBPART_COUNT);
        return CT_ERROR;
    } else if (part_def->subparts.count > CT_MAX_SUBPART_COUNT) {
        CT_THROW_ERROR(ERR_EXCEED_MAX_SUBPARTCNT, (uint32)ERR_EXCEED_MAX_SUBPARTCNT);
        return CT_ERROR;
    }

    table_part_t *compart = NULL;
    table_part_t *subpart = NULL;
    for (uint32 i = 0; i < part_def->subparts.count; i++) {
        subpart_def = (knl_part_def_t *)cm_galist_get(&part_def->subparts, i);
        if (cm_compare_text(&part_def->name, &subpart_def->name) == 0) {
            CT_THROW_ERROR(ERR_DUPLICATE_PART_NAME);
            return CT_ERROR;
        }
        
        if (part_table_find_by_name(part_table, &subpart_def->name, &compart)) {
            CT_THROW_ERROR(ERR_DUPLICATE_PART_NAME);
            return CT_ERROR;
        }

        if (subpart_table_find_by_name(part_table, &subpart_def->name, &compart, &subpart)) {
            CT_THROW_ERROR(ERR_DUPLICATE_SUBPART_NAME);
            return CT_ERROR;
        }
        
        for (uint32 j = i + 1; j < part_def->subparts.count; j++) {
            subcmp_def = (knl_part_def_t *)cm_galist_get(&part_def->subparts, j);
            if (cm_compare_text(&subpart_def->name, &subcmp_def->name) == 0) {
                CT_THROW_ERROR(ERR_DUPLICATE_SUBPART_NAME);
                return CT_ERROR;
            }
        }
    }

    return CT_SUCCESS;
}

static status_t db_check_add_part_def_valid(knl_part_obj_def_t *def, table_t *table, knl_part_def_t **part_def)
{
    table_part_t *table_part = NULL;
    table_part_t *table_subpart = NULL;

    // for hash partition, the total partition count should less than CT_MAX_PART_COUNT / 2
    if (def->part_type == PART_TYPE_HASH && table->part_table->desc.partcnt + 1 > CT_MAX_HASH_PART_COUNT) {
        CT_THROW_ERROR(ERR_EXCEED_MAX_PARTCNT, CT_MAX_HASH_PART_COUNT);
        return CT_ERROR;
    }
    if (table->part_table->desc.interval_key != NULL) {
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "add interval partition");
        return CT_ERROR;
    }

    if (table->part_table->desc.partcnt + 1 > CT_MAX_PART_COUNT) {
        CT_THROW_ERROR(ERR_EXCEED_MAX_PARTCNT, (uint32)CT_MAX_PART_COUNT);
        return CT_ERROR;
    }

    if (table->part_table->desc.binterval.size != 0) {
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "ADD PARTITION on interval partitioned objects");
        return CT_ERROR;
    }

    knl_panic_log(def->parts.count == 1, "the parts's count is abnormal, panic info: table %s parts count %u",
                  table->desc.name, def->parts.count);
    *part_def = (knl_part_def_t *)cm_galist_get(&def->parts, 0);

    if (part_table_find_by_name(table->part_table, &(*part_def)->name, &table_part)) {
        CT_THROW_ERROR(ERR_DUPLICATE_PART_NAME);
        return CT_ERROR;
    }

    if (subpart_table_find_by_name(table->part_table, &(*part_def)->name, &table_part, &table_subpart)) {
        CT_THROW_ERROR(ERR_DUPLICATE_PART_NAME);
        return CT_ERROR;
    }

    if ((*part_def)->is_parent) {
        if (subpart_check_def_add_partition(table->part_table, def, *part_def) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t db_verify_add_part_def(knl_session_t *session, knl_dictionary_t *dc, knl_part_obj_def_t *def)
{
    table_t *table;
    knl_part_def_t *part_def = NULL;
    status_t status;

    table = DC_TABLE(dc);
    if (!table->desc.parted) {
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "alter table add partition", table->desc.name);
        return CT_ERROR;
    }

    if (db_check_add_part_def_valid(def, table, &part_def) != CT_SUCCESS) {
        return CT_ERROR;
    }

    switch (table->part_table->desc.parttype) {
        case PART_TYPE_RANGE:
            status = part_verify_add_range_key(dc, part_def);
            break;

        case PART_TYPE_LIST:
            status = part_verify_add_list_key(session, dc, part_def);
            break;

        case PART_TYPE_HASH:
            status = CT_SUCCESS;
            break;

        default:
            CT_THROW_ERROR(ERR_INVALID_PART_TYPE, "table", "");
            status = CT_ERROR;
            break;
    }

    return status;
}

status_t db_create_hash_lob_part_segment(knl_session_t *session, knl_dictionary_t *dc, uint32 column_idx)
{
    knl_dictionary_t new_dc;
    if (dc_open_table_private(session, dc->uid, dc->oid, &new_dc) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("open dc private fail, uid %u, oid %u", dc->uid, dc->oid);
        return CT_ERROR;
    }
    dc_entity_t *entity = DC_ENTITY(&new_dc);
    knl_column_t *column = dc_get_column(entity, column_idx);

    if (!COLUMN_IS_LOB(column)) {
        dc_close_table_private(&new_dc);
        return CT_SUCCESS;
    }

    lob_t *lob = (lob_t *)column->lob;
    table_t *table = DC_TABLE(&new_dc);
    uint32 partcnt = table->part_table->desc.partcnt;
    knl_part_locate_t part_loc = { 0 };
    part_loc.part_no = partcnt - 1;
    lob_part_t *lob_part = LOB_GET_PART(lob, part_loc.part_no);
    lob_entity_t *lob_entity = &lob_part->lob_entity;
    status_t ret = CT_SUCCESS;

    if (lob_create_part_segment(session, lob_part) != CT_SUCCESS) {
        dc_close_table_private(&new_dc);
        CT_LOG_RUN_ERR("create hash lob part segment fail, uid %u, oid %u, partno %u",
                       dc->uid, dc->oid, part_loc.part_no);
        return CT_ERROR;
    }

    if (IS_SUB_LOBPART(&lob_part->desc)) {
        ret = db_update_sublobpart_entry(session, &lob_part->desc, lob_part->desc.entry);
    } else {
        ret = db_update_lob_part_entry(session, &lob_part->desc, lob_part->desc.entry);
    }

    if (ret != CT_SUCCESS) {
        lob_drop_part_segment(session, lob_part);
        dc_close_table_private(&new_dc);
        CT_LOG_RUN_ERR("create hash lob part segment fail, uid %u, oid %u, partno %u",
                       dc->uid, dc->oid, part_loc.part_no);
        return CT_ERROR;
    }
    buf_enter_page(session, lob_part->desc.entry, LATCH_MODE_S, ENTER_PAGE_RESIDENT);
    lob_entity->segment = LOB_SEG_HEAD(session);
    buf_leave_page(session, CT_FALSE);

    if (lob_generate_create_undo(session, lob_part->desc.entry, lob_part->desc.space_id,
                                 SPACE_IS_LOGGING(SPACE_GET(session, lob_part->desc.space_id))) != CT_SUCCESS) {
        lob_drop_part_segment(session, lob_part);
        dc_close_table_private(&new_dc);
        CT_LOG_RUN_ERR("create hash lob part segment generate undo fail, uid %u, oid %u, partno %u",
                       dc->uid, dc->oid, part_loc.part_no);
        return CT_ERROR;
    }
    dc_close_table_private(&new_dc);
    return CT_SUCCESS;
}

static status_t db_add_lob_parts(knl_session_t *session, knl_dictionary_t *dc, knl_part_def_t *def, uint32 part_id)
{
    lob_t *lob = NULL;
    uint32 space_id;
    knl_lob_part_desc_t desc = { 0 };
    knl_column_t *column = NULL;
    dc_entity_t *entity = DC_ENTITY(dc);
    table_t *table = &entity->table;

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    cursor->row = (row_head_t *)cursor->buf;

    for (uint32 i = 0; i < table->desc.column_count; i++) {
        column = dc_get_column(entity, i);
        if (!COLUMN_IS_LOB(column)) {
            continue;
        }

        lob = (lob_t *)column->lob;

        if (part_lob_get_space_id(session, lob, def, &space_id) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }

        part_init_lob_part_desc(session, &lob->desc, part_id, space_id, &desc);
        if (def->is_parent) {
            desc.subpart_cnt = def->subparts.count;
            desc.is_parent = CT_TRUE;
        }

        if (part_write_sys_lobpart(session, cursor, &desc) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

status_t db_add_index_parts(knl_session_t *session,
                            knl_dictionary_t *dc,
                            table_t *table,
                            knl_table_part_desc_t *part_desc)
{
    index_t *index = NULL;
    index_part_t *index_part = NULL;
    index_part_t *index_subpart = NULL;
    knl_index_part_desc_t desc;
    text_t text;
    errno_t ret;

    CM_SAVE_STACK(session->stack);
    cm_str2text(part_desc->name, &text);
    knl_cursor_t *cursor = knl_push_cursor(session);

    for (uint32 i = 0; i < table->index_set.total_count; i++) {
        index = table->index_set.items[i];
        if (!IS_PART_INDEX(index)) {
            continue;
        }

        if (db_update_part_count(session, index->desc.uid, index->desc.table_id,
            index->desc.id, CT_TRUE) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }

        part_generate_index_part_desc(session, index, part_desc, &desc);

        // If part index name has duplicated, use sys generated name instead.
        if (part_idx_find_by_name(index->part_index, &text, &index_part) ||
            subpart_idx_find_by_name(index->part_index, &text, &index_subpart)) {
            ret = snprintf_s(desc.name, CT_NAME_BUFFER_SIZE, CT_NAME_BUFFER_SIZE - 1, "SYS_P%llX", desc.org_scn);
            knl_securec_check_ss(ret);
        }

        if (db_write_sys_indexpart(session, cursor, &desc) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }
    if (db_create_index_segment_of_hash_parts(session, dc, table) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }
    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

status_t db_create_hash_part_heap_segment_impl(knl_session_t *session, table_part_t *table_part,
                                               knl_part_locate_t part_loc)
{
    status_t status;
    heap_t *heap = &table_part->heap;

    if (heap_create_part_segment(session, table_part) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (IS_SUB_TABPART(&table_part->desc)) {
        status = db_update_subtabpart_entry(session, &table_part->desc, table_part->desc.entry);
    } else {
        status = db_update_table_part_entry(session, &table_part->desc, table_part->desc.entry);
    }

    if (status != CT_SUCCESS) {
        heap_drop_part_segment(session, table_part);
        return CT_ERROR;
    }

    buf_enter_page(session, table_part->desc.entry, LATCH_MODE_S, ENTER_PAGE_RESIDENT);
    heap->segment = HEAP_SEG_HEAD(session);
    buf_leave_page(session, CT_FALSE);

    return CT_SUCCESS;
}

status_t db_create_hash_part_segment(knl_session_t *session, knl_dictionary_t *dc)
{
    knl_dictionary_t new_dc;
    table_part_t *table_part = NULL;
    if (dc_open_table_private(session, dc->uid, dc->oid, &new_dc) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("open dc private fail, uid %u, oid %u", dc->uid, dc->oid);
        return CT_ERROR;
    }
    table_t *table = DC_TABLE(&new_dc);
    uint32 partcnt = table->part_table->desc.partcnt;
    knl_part_locate_t part_loc = { 0 };
    part_loc.part_no = partcnt - 1;
    table_part = (table_part_t *)TABLE_GET_PART(table, part_loc.part_no);
    if (db_create_hash_part_heap_segment_impl(session, table_part, part_loc) != CT_SUCCESS) {
        dc_close_table_private(&new_dc);
        CT_LOG_RUN_ERR("create hash part segment fail, uid %u, oid %u, partno %u",
                       dc->uid, dc->oid, part_loc.part_no);
        return CT_ERROR;
    }
    SYNC_POINT_GLOBAL_START(CANTIAN_DDL_CREATE_HASH_PART_HEAP_SEG_BEFORE_WRITE_UNDO_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;

    if (heap_generate_create_undo(session, table_part->desc.entry, table_part->desc.space_id,
                                  SPACE_IS_LOGGING(SPACE_GET(session, table_part->desc.space_id))) != CT_SUCCESS) {
        heap_drop_part_segment(session, table_part);
        dc_close_table_private(&new_dc);
        CT_LOG_RUN_ERR("create hash part segment generate undo fail, uid %u, oid %u, partno %u",
                       dc->uid, dc->oid, part_loc.part_no);
        return CT_ERROR;
    }
    SYNC_POINT_GLOBAL_START(CANTIAN_DDL_CREATE_HASH_PART_HEAP_SEG_AFTER_WRITE_UNDO_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;

    dc_close_table_private(&new_dc);
    return CT_SUCCESS;
}

static status_t db_add_table_part(knl_session_t *session, table_t *table, knl_part_def_t *def,
                                  knl_table_part_desc_t *part_desc, uint32 part_id, bool32 is_split)
{
    knl_cursor_t *cursor = NULL;
    bool32 is_encrypt_table = SPACE_IS_ENCRYPT(SPACE_GET(session, table->desc.space_id));

    // only hash partition need to set not ready to CT_TRUE
    if (part_init_table_part_desc(session, table, def, part_id, part_desc, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (def->is_parent) {
        part_desc->subpart_cnt = def->subparts.count;
    }

    if (!check_part_encrypt_allowed(session, is_encrypt_table, part_desc->space_id)) {
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "add partiton", "cases: add encrypt partition to non-encrypt \
part table or add non-encrypt partition to encrypt part table." );
        return CT_ERROR;
    }

    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);

    /*
     * for hash partition, because add a partition would cause data redistribution,
     * so we set a flag which means this is not completed.
     * or if it is called by spliting partition, set it as not ready
     */
    if (table->part_table->desc.parttype == PART_TYPE_HASH || is_split) {
        part_desc->not_ready = PARTITON_NOT_READY;
    }

    if (db_write_sys_tablepart(session, cursor, &table->desc, part_desc) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }
    
    if (part_desc->storaged && db_write_sysstorage(session, cursor, part_desc->org_scn,
        &part_desc->storage_desc) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (part_desc->compress) {
        if (db_write_syscompress(session, cursor, part_desc->space_id, part_desc->org_scn, part_desc->compress_algo,
            COMPRESS_OBJ_TYPE_TABLE_PART) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

static void db_addpart_get_bucket_map(uint32 part_cnt, redis_bucket_map *redis_map)
{
    uint32 bucket_cnt = dc_get_hash_bucket_count(part_cnt);

    // set the pno where data will be redistributed from. the num of redis map used in redis algorithm is 2.
    // in ora_hash algorithm, the count of buckets is an integer power of 2.
    redis_map[0].group_id = (part_cnt - 1 - bucket_cnt / HASH_PART_BUCKET_BASE) / PART_GROUP_SIZE;
    redis_map[0].bucket_id = (part_cnt - 1 - bucket_cnt / HASH_PART_BUCKET_BASE) % PART_GROUP_SIZE;
    redis_map[0].pno = part_cnt - 1 - bucket_cnt / HASH_PART_BUCKET_BASE;

    // set the pno where data will be redistributed to
    redis_map[1].group_id = (part_cnt - 1) / PART_GROUP_SIZE;
    redis_map[1].bucket_id = (part_cnt - 1) % PART_GROUP_SIZE;
    redis_map[1].pno = part_cnt - 1;
}

static uint32 db_get_hash_pno_from_bucket_map(uint32 bucket_cnt, redis_bucket_map *redis_map, uint32 hash_value)
{
    uint32 group_id = hash_value % bucket_cnt / PART_GROUP_SIZE;
    uint32 bucket_id = hash_value % bucket_cnt % PART_GROUP_SIZE;

    if (group_id == redis_map[0].group_id && bucket_id == redis_map[0].bucket_id) {
        return redis_map[0].pno;
    } else {
        return redis_map[1].pno;
    }
}

static status_t part_match_redis_pno(knl_handle_t handle, bool32 *matched)
{
    uint32 column_id;
    variant_t variant_value;
    uint32 hash_value = 0;
    bool32 is_type_ok = CT_FALSE;
    text_t values[CT_MAX_PARTKEY_COLUMNS];
    redistribute_t *redis_cond = (redistribute_t *)handle;
    part_table_t *part_table = redis_cond->part_table;
    knl_cursor_t *cursor_delete = redis_cond->cursor_delete;
    bool32 is_subpart = redis_cond->is_subpart;
    knl_part_column_desc_t *col_desc = is_subpart ? part_table->sub_keycols : part_table->keycols;
    table_t *table = (table_t *)cursor_delete->table;
    uint32 version = table->desc.version;
    uint32 partkeys = is_subpart ? part_table->desc.subpartkeys : part_table->desc.partkeys;

    for (uint32 i = 0; i < partkeys; i++) {
        column_id = col_desc[i].column_id;
        values[i].str = CURSOR_COLUMN_DATA(cursor_delete, column_id);
        values[i].len = CURSOR_COLUMN_SIZE(cursor_delete, column_id);
        if (values[i].len == CT_NULL_VALUE_LEN) {
            values[i].len = 0;
        }
        part_get_hash_key_variant(col_desc[i].datatype, &values[i], &variant_value, version);
        hash_value = part_hash_value_combination(i, hash_value, &variant_value, &is_type_ok, version);
        if (!is_type_ok) {
            CT_THROW_ERROR(ERR_INVALID_PART_TYPE, "key", "");
            return CT_ERROR;
        }
    }

    uint32 new_pno = db_get_hash_pno_from_bucket_map(redis_cond->bucket_cnt, redis_cond->redis_map, hash_value);
    if (new_pno != redis_cond->org_pno) {
        *matched = CT_TRUE;
        return CT_SUCCESS;
    }

    *matched = CT_FALSE;
    return CT_SUCCESS;
}

static status_t part_redis_move_entity(knl_session_t *session, knl_dictionary_t *dc, knl_cursor_t *cursor_delete,
    knl_cursor_t *cursor_insert, bool32 is_subpart)
{
    if (knl_fetch(session, cursor_delete) != CT_SUCCESS) {
        return CT_ERROR;
    }

    while (!cursor_delete->eof) {
        if (is_subpart) {
            /* calc new sub part no for insert */
            if (part_redis_get_subpartno(session, dc, cursor_delete, cursor_insert) != CT_SUCCESS) {
                return CT_ERROR;
            }
        } else {
            knl_set_table_part(cursor_insert, cursor_insert->part_loc);
        }
        
        if (knl_copy_row(session, cursor_delete, cursor_insert) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (knl_internal_delete(session, cursor_delete) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (knl_internal_insert(session, cursor_insert) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (knl_fetch(session, cursor_delete) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t part_redis_move_part(knl_session_t *session, knl_cursor_t *cursor_delete, knl_dictionary_t *dc,
    knl_cursor_t *cursor_insert, bool32 is_parent)
{
    table_t *table = DC_TABLE(dc);

    if (is_parent) {
        table_part_t *compart = TABLE_GET_PART(table, cursor_delete->part_loc.part_no);
        knl_panic_log(IS_PARENT_TABPART(&compart->desc),
            "compart is not parent_tabpart, panic info: table %s compart %s", table->desc.name, compart->desc.name);

        for (uint32 i = 0; i < compart->desc.subpart_cnt; i++) {
            cursor_delete->part_loc.subpart_no = i;
            knl_set_table_part(cursor_delete, cursor_delete->part_loc);
            if (knl_reopen_cursor(session, cursor_delete, dc) != CT_SUCCESS) {
                return CT_ERROR;
            }

            if (part_redis_move_entity(session, dc, cursor_delete, cursor_insert, CT_TRUE) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }
    } else {
        if (part_redis_move_entity(session, dc, cursor_delete, cursor_insert, CT_FALSE) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t db_addpart_redis_data(knl_session_t *session, knl_dictionary_t *dc, uint32 part_id, bool32 is_parent)
{
    table_t *table = DC_TABLE(dc);
    uint32 partcnt = table->part_table->desc.partcnt;
    uint32 bucket_cnt = dc_get_hash_bucket_count(partcnt);
    knl_match_cond_t old_match = session->match_cond;
    table_part_t *delete_part, *insert_part;

    CM_SAVE_STACK(session->stack);
    uint32 stack_size = sizeof(redis_bucket_map) * HASH_PART_BUCKET_BASE;
    redis_bucket_map *map = (redis_bucket_map *)cm_push(session->stack, stack_size);
    db_addpart_get_bucket_map(partcnt, map);
    uint32 org_partno = map[0].pno;

    knl_cursor_t *cursor_delete = knl_push_cursor(session);
    cursor_delete->action = CURSOR_ACTION_DELETE;
    cursor_delete->scan_mode = SCAN_MODE_TABLE_FULL;
    cursor_delete->part_loc.part_no = org_partno;
    if (knl_open_cursor(session, cursor_delete, dc) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    cursor_delete->stmt = cm_push(session->stack, sizeof(redistribute_t));

    knl_cursor_t *cursor_insert = knl_push_cursor(session);
    cursor_insert->scan_mode = SCAN_MODE_TABLE_FULL;
    cursor_insert->action = CURSOR_ACTION_INSERT;
    cursor_insert->part_loc.part_no = partcnt - 1;
    if (knl_open_cursor(session, cursor_insert, dc) != CT_SUCCESS) {
        knl_close_cursor(session, cursor_delete);
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    delete_part = TABLE_GET_PART(table, cursor_delete->part_loc.part_no);
    insert_part = TABLE_GET_PART(table, cursor_insert->part_loc.part_no);
    if (delete_part->desc.is_csf != insert_part->desc.is_csf) {
        CT_THROW_ERROR(ERR_INVALID_OPERATION, ", data redistribute between different partition row types are forbidden");
        knl_close_cursor(session, cursor_delete);
        knl_close_cursor(session, cursor_insert);
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    cursor_insert->row = (row_head_t *)cm_push(session->stack, CT_MAX_ROW_SIZE);
    session->match_cond = part_match_redis_pno;
    redistribute_t *redis_cond = (redistribute_t *)cursor_delete->stmt;

    /* init the match condition struct */
    redis_cond->is_subpart = CT_FALSE;
    redis_cond->bucket_cnt = bucket_cnt;
    redis_cond->cursor_delete = cursor_delete;
    redis_cond->redis_map = map;
    redis_cond->org_pno = org_partno;
    redis_cond->part_table = table->part_table;

    status_t status = part_redis_move_part(session, cursor_delete, dc, cursor_insert, is_parent);
    session->match_cond = old_match;
    knl_close_cursor(session, cursor_delete);
    knl_close_cursor(session, cursor_insert);
    CM_RESTORE_STACK(session->stack);
    if (status != CT_SUCCESS) {
        return CT_ERROR;
    }

    /* set the new part flag to ready status */
    if (db_update_part_flag(session, dc, table->part_table, part_id, PART_FLAG_TYPE_NOTREADY) != CT_SUCCESS) {
        return CT_ERROR;
    }
    
    return CT_SUCCESS;
}

static void part_addhash_drop_garbage_part(knl_session_t *session, knl_dictionary_t *dc, uint32 part_id)
{
    table_part_t *table_part = NULL;
    table_t *table = DC_TABLE(dc);
    part_table_t *part_table = table->part_table;

    for (uint32 i = 0; i < part_table->desc.partcnt; i++) {
        table_part = TABLE_GET_PART(table, i);
        if (!IS_READY_PART(table_part)) {
            continue;
        }

        if (table_part->desc.part_id == part_id) {
            break;
        }
    }

    knl_panic_log(table_part != NULL, "the table_part is NULL, panic info: table %s", table->desc.name);
    if (db_drop_part(session, dc, table_part, CT_TRUE) != CT_SUCCESS) {
        knl_rollback(session, NULL);
        CT_LOG_RUN_ERR("[PART] Failed to drop garbage part %s after data redistribution failure of adding part",
            table_part->desc.name);
    } else {
        knl_commit(session);
    }
}

static status_t db_add_hash_part_redistribute(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def,
    uint32 part_id)
{
    knl_dictionary_t new_dc;
    part_put_logic_log(session, dc);
    knl_commit(session);
    dc_invalidate(session, (dc_entity_t *)dc->handle);
    if (knl_open_dc_by_id(session, dc->uid, dc->oid, &new_dc, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    dc_close(dc);

    errno_t ret = memcpy_sp(dc, sizeof(knl_dictionary_t), &new_dc, sizeof(knl_dictionary_t));
    knl_securec_check(ret);

    if (tx_begin(session) != CT_SUCCESS) {
        return CT_ERROR;
    }

    knl_part_def_t *part_def = (knl_part_def_t *)cm_galist_get(&def->part_def.obj_def->parts, 0);
    if (db_addpart_redis_data(session, dc, part_id, part_def->is_parent) != CT_SUCCESS) {
        knl_rollback(session, NULL);
        part_addhash_drop_garbage_part(session, dc, part_id);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t db_add_hash_part_redistribute2(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def,
                                               uint32 part_id)
{
    knl_dictionary_t new_dc;
    dc_entity_t *entity = DC_ENTITY(dc);
    table_t *table = &entity->table;

    if (db_create_hash_part_segment(session, dc) != CT_SUCCESS) {
        return CT_ERROR;
    }
    for (uint32 i = 0; i < table->desc.column_count; i++) {
        if (db_create_hash_lob_part_segment(session, dc, i) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (dc_open_table_private(session, dc->uid, dc->oid, &new_dc) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("open dc private fail, uid %u, oid %u, part_id %u", dc->uid, dc->oid, part_id);
        return CT_ERROR;
    }
    knl_part_def_t *part_def = (knl_part_def_t *)cm_galist_get(&def->part_def.obj_def->parts, 0);
    if (db_addpart_redis_data(session, &new_dc, part_id, part_def->is_parent) != CT_SUCCESS) {
        dc_close_table_private(&new_dc);
        CT_LOG_RUN_ERR("open dc private fail, uid %u, oid %u, part_id %u", dc->uid, dc->oid, part_id);
        return CT_ERROR;
    }
    dc_close_table_private(&new_dc);
    return CT_SUCCESS;
}

static status_t db_add_table_subpart(knl_session_t *session, table_t *table, knl_table_part_desc_t *desc,
    bool32 not_ready)
{
    bool32 is_encrypt_table = SPACE_IS_ENCRYPT(SPACE_GET(session, table->desc.space_id));
    if (!check_part_encrypt_allowed(session, is_encrypt_table, desc->space_id)) {
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "add partiton", "cases: add encrypt partition to non-encrypt \
part table or add non-encrypt partition to encrypt part table." );
        return CT_ERROR;
    }

    desc->not_ready = not_ready;
    
    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    
    if (db_write_sys_tablesubpart(session, cursor, desc) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

static status_t db_add_lob_subpart(knl_session_t *session, knl_dictionary_t *dc, knl_part_def_t *def, uint32 compart_id,
    uint32 subpart_id)
{
    uint32 space_id;
    lob_t *lob = NULL;
    knl_lob_part_desc_t desc;
    knl_column_t *column = NULL;
    dc_entity_t *entity = DC_ENTITY(dc);
    table_t *table = &entity->table;

    for (uint32 i = 0; i < table->desc.column_count; i++) {
        column = dc_get_column(entity, i);
        if (!COLUMN_IS_LOB(column)) {
            continue;
        }

        lob = (lob_t *)column->lob;
        if (subpart_lob_get_space_id(session, lob, def, &space_id) != CT_SUCCESS) {
            return CT_ERROR;
        }

        part_init_lob_part_desc(session, &lob->desc, subpart_id, space_id, &desc);
        desc.parent_partid = compart_id;
        if (subpart_write_syslob(session, &desc) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t db_altable_addpart_create_subparts(knl_session_t *session, knl_dictionary_t *dc,
    knl_part_def_t *part_def, knl_table_part_desc_t *comdesc)
{
    uint32 subpart_id;
    table_t *table = DC_TABLE(dc);
    knl_table_part_desc_t tab_desc = { 0 };
    knl_part_def_t *subpart_def = NULL;

    for (uint32 i = 0; i < part_def->subparts.count; i++) {
        subpart_def = (knl_part_def_t *)cm_galist_get(&part_def->subparts, i);
        subpart_id = subpart_generate_partid(NULL, NULL, i);
        if (subpart_init_table_part_desc(session, comdesc, subpart_def, subpart_id, &tab_desc) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (db_add_table_subpart(session, table, &tab_desc, CT_FALSE) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (db_add_lob_subpart(session, dc, part_def, comdesc->part_id, subpart_id) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (db_add_index_subpart(session, table, &tab_desc) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t db_altable_add_part(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def)
{
    knl_table_part_desc_t desc;
    knl_alt_part_t *alt_def = &def->part_def;

    if (!IS_COMPATIBLE_MYSQL_INST) {
        if (db_verify_add_part_def(session, dc, alt_def->obj_def) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    /* clean not ready parts */
    if (part_clean_garbage_partition(session, dc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    table_t *table = DC_TABLE(dc);
    uint32 part_id = part_generate_part_id(table, CT_INVALID_ID32);
    knl_part_def_t *part_def = (knl_part_def_t *)cm_galist_get(&alt_def->obj_def->parts, 0);

    if (db_update_part_count(session, table->desc.uid, table->desc.id, CT_INVALID_ID32, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (db_add_table_part(session, table, part_def, &desc, part_id, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (db_add_lob_parts(session, dc, part_def, part_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (db_add_index_parts(session, dc, table, &desc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (part_def->is_parent) {
        if (db_altable_addpart_create_subparts(session, dc, part_def, &desc) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    
    if (db_update_table_chgscn(session, &table->desc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (table->part_table->desc.parttype != PART_TYPE_HASH) {
        return CT_SUCCESS;
    }

    if (DB_ATTR_COMPATIBLE_MYSQL(session)) {
        if (db_add_hash_part_redistribute2(session, dc, def, part_id) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        if (db_add_hash_part_redistribute(session, dc, def, part_id) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t subpart_verify_add_list_key(knl_session_t *session, knl_dictionary_t *dc, table_part_t *compart,
    knl_part_def_t *part_def)
{
    uint32 subpart_no;
    uint32 groupcnt = 0;
    dc_entity_t *entity = DC_ENTITY(dc);
    table_t *table = &entity->table;
    part_decode_key_t *groups = NULL;
    uint32 partkeys = table->part_table->desc.subpartkeys;

    /*
     * the interface will alloc dc for calculating part key, it must be latched by entity->cbo_latch for preventing
     * alloc dc concurrently when delay loading statistics(eg: knl_get_cbo_part_xxx).
     */
    cm_latch_x(&entity->cbo_latch, 0, NULL);
    if (dc_decode_part_key_group(session, entity, partkeys, part_def->partkey, &groups, &groupcnt) != CT_SUCCESS) {
        cm_unlatch(&entity->cbo_latch, NULL);
        return CT_ERROR;
    }
    cm_unlatch(&entity->cbo_latch, NULL);

    table_part_t *subpart = NULL;
    char *str = NULL;
    for (uint32 i = 0; i < groupcnt; i++) {
        subpart_no = subpart_locate_list_key(table->part_table, compart, &groups[i]);
        if (subpart_no != CT_INVALID_ID32) {
            subpart = PART_GET_SUBENTITY(table->part_table, compart->subparts[subpart_no]);
            if (i == PART_KEY_FIRST) {
                str = "st";
            } else if (i == PART_KEY_SECOND) {
                str = "nd";
            } else if (i == PART_KEY_THIRD) {
                str = "rd";
            } else {
                str = "th";
            }
            CT_THROW_ERROR(ERR_DUPLICATE_PART_KEY, i + 1, str, subpart->desc.name);
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t subpart_verify_add_range_key(knl_dictionary_t *dc, knl_part_def_t *part_def, table_part_t *compart)
{
    knl_part_key_t part_key;
    table_t *table = DC_TABLE(dc);
    knl_part_column_desc_t *part_column = table->part_table->sub_keycols;
    table_part_t *subpart = PART_GET_SUBENTITY(table->part_table, compart->subparts[compart->desc.subpart_cnt - 1]);

    knl_decode_part_key(part_def->partkey, &part_key);

    if (part_compare_range_key(part_column, &part_key.decoder, subpart->desc.groups) <= 0) {
        CT_THROW_ERROR(ERR_INVALID_PART_KEY, "partition bound must collate higher than that of the last partition.");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t subpart_add_check_partkey(knl_session_t *session, knl_dictionary_t *dc, table_part_t *compart,
    knl_part_def_t *part_def)
{
    status_t status;
    table_t *table = DC_TABLE(dc);

    switch (table->part_table->desc.subparttype) {
        case PART_TYPE_HASH:
            status = CT_SUCCESS;
            break;
        case PART_TYPE_RANGE:
            status = subpart_verify_add_range_key(dc, part_def, compart);
            break;
        case PART_TYPE_LIST:
            status = subpart_verify_add_list_key(session, dc, compart, part_def);
            break;
        default:
            CT_THROW_ERROR(ERR_INVALID_PART_TYPE, "table", "");
            status = CT_ERROR;
            break;
    }

    return status;
}

static status_t subpart_add_verify_def(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def)
{
    table_t *table = DC_TABLE(dc);
    knl_alt_part_t *alt_def = &def->part_def;
    part_table_t *part_table = table->part_table;
    
    if (!IS_PART_TABLE(table) || !IS_COMPART_TABLE(table->part_table)) {
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "add subpartition", table->desc.name);
        return CT_ERROR;
    }

    table_part_t *compart = NULL;
    if (!part_table_find_by_name(table->part_table, &alt_def->name, &compart)) {
        CT_THROW_ERROR(ERR_PARTITION_NOT_EXIST, "table", T2S(&alt_def->name));
        return CT_ERROR;
    }

    if (part_table->desc.subparttype == PART_TYPE_HASH && compart->desc.subpart_cnt + 1 > CT_MAX_HASH_SUBPART_COUNT) {
        CT_THROW_ERROR(ERR_EXCEED_MAX_SUBPARTCNT, CT_MAX_HASH_SUBPART_COUNT);
        return CT_ERROR;
    }

    if (compart->desc.subpart_cnt + 1 > CT_MAX_SUBPART_COUNT) {
        CT_THROW_ERROR(ERR_EXCEED_MAX_SUBPARTCNT, CT_MAX_SUBPART_COUNT);
        return CT_ERROR;
    }

    knl_part_def_t *part_def = (knl_part_def_t *)cm_galist_get(&alt_def->obj_def->parts, 0);
    part_def = (knl_part_def_t *)cm_galist_get(&part_def->subparts, 0);
    table_part_t *subpart = NULL;
    table_part_t *table_compart = NULL;
    if (part_table_find_by_name(part_table, &part_def->name, &table_compart)) {
        CT_THROW_ERROR(ERR_DUPLICATE_PART_NAME);
        return CT_ERROR;
    }
    
    if (subpart_table_find_by_name(part_table, &part_def->name, &table_compart, &subpart)) {
        CT_THROW_ERROR(ERR_DUPLICATE_SUBPART_NAME);
        return CT_ERROR;
    }

    if (subpart_add_check_partkey(session, dc, compart, part_def) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t db_add_index_subpart(knl_session_t *session, table_t *table, knl_table_part_desc_t *tab_desc)
{
    text_t text;
    errno_t ret;
    index_t *index = NULL;
    index_part_t *index_part = NULL;
    index_part_t *index_subpart = NULL;
    knl_index_part_desc_t desc = { 0 };

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    for (uint32 i = 0; i < table->index_set.total_count; i++) {
        index = table->index_set.items[i];
        if (!IS_PART_INDEX(index) || !IS_COMPART_INDEX(index->part_index)) {
            continue;
        }

        part_generate_index_part_desc(session, index, tab_desc, &desc);

        /* if part index name has duplicated, use sys generated name instead. */
        cm_str2text(desc.name, &text);
        if (part_idx_find_by_name(index->part_index, &text, &index_part) ||
            subpart_idx_find_by_name(index->part_index, &text, &index_subpart)) {
            ret = snprintf_s(desc.name, CT_NAME_BUFFER_SIZE, CT_NAME_BUFFER_SIZE - 1, "SYS_P%llX", desc.org_scn);
            knl_securec_check_ss(ret);
        }

        if (db_write_sys_indsubpart(session, cursor, &desc) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

static void subpart_redis_data_prepare_cursor(table_part_t *compart, uint32 org_subpartno,
    knl_cursor_t *cursor_insert, knl_cursor_t *cursor_delete)
{
    uint32 subpart_cnt = compart->desc.subpart_cnt;

    cursor_delete->action = CURSOR_ACTION_DELETE;
    cursor_delete->scan_mode = SCAN_MODE_TABLE_FULL;
    cursor_delete->part_loc.part_no = compart->part_no;
    cursor_delete->part_loc.subpart_no = org_subpartno;

    cursor_insert->scan_mode = SCAN_MODE_TABLE_FULL;
    cursor_insert->action = CURSOR_ACTION_INSERT;
    cursor_insert->part_loc.part_no = compart->part_no;
    cursor_insert->part_loc.subpart_no = subpart_cnt - 1;
}

status_t db_add_subpart_redis_data(knl_session_t *session, knl_dictionary_t *dc, table_part_t *compart,
    uint32 subpart_id)
{
    table_t *table = DC_TABLE(dc);
    uint32 subpart_cnt = compart->desc.subpart_cnt;
    uint32 bucket_cnt = dc_get_hash_bucket_count(compart->desc.subpart_cnt);
    knl_match_cond_t old_match = session->match_cond;

    CM_SAVE_STACK(session->stack);
    uint32 stack_size = sizeof(redis_bucket_map) * HASH_PART_BUCKET_BASE;
    redis_bucket_map *map = (redis_bucket_map *)cm_push(session->stack, stack_size);
    db_addpart_get_bucket_map(subpart_cnt, map);
    uint32 org_subpartno = map[0].pno;

    knl_cursor_t *cursor_delete = knl_push_cursor(session);
    knl_cursor_t *cursor_insert = knl_push_cursor(session);
    subpart_redis_data_prepare_cursor(compart, org_subpartno, cursor_insert, cursor_delete);
    if (knl_open_cursor(session, cursor_delete, dc) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }
    cursor_delete->stmt = cm_push(session->stack, sizeof(redistribute_t));
    
    if (knl_open_cursor(session, cursor_insert, dc) != CT_SUCCESS) {
        knl_close_cursor(session, cursor_delete);
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    cursor_insert->row = (row_head_t *)cm_push(session->stack, CT_MAX_ROW_SIZE);
    session->match_cond = part_match_redis_pno;
    redistribute_t *redis_cond = (redistribute_t *)cursor_delete->stmt;

    /* init the match condition struct */
    redis_cond->is_subpart = CT_TRUE;
    redis_cond->bucket_cnt = bucket_cnt;
    redis_cond->cursor_delete = cursor_delete;
    redis_cond->redis_map = map;
    redis_cond->org_pno = org_subpartno;
    redis_cond->part_table = table->part_table;

    knl_set_table_part(cursor_insert, cursor_insert->part_loc);
    if (part_redis_move_part(session, cursor_delete, dc, cursor_insert, CT_FALSE) != CT_SUCCESS) {
        session->match_cond = old_match;
        knl_close_cursor(session, cursor_delete);
        knl_close_cursor(session, cursor_insert);
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    session->match_cond = old_match;
    knl_close_cursor(session, cursor_delete);
    knl_close_cursor(session, cursor_insert);
    CM_RESTORE_STACK(session->stack);

    /* set the new subpart to ready status */
    if (db_update_subpart_flag(session, dc, compart, subpart_id, PART_FLAG_TYPE_NOTREADY) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static void subpart_addhash_drop_garbage_part(knl_session_t *session, knl_dictionary_t *dc, table_part_t *compart,
    uint32 subpart_id)
{
    table_part_t *subpart = NULL;
    table_t *table = DC_TABLE(dc);

    for (uint32 i = 0; i < compart->desc.subpart_cnt; i++) {
        subpart = PART_GET_SUBENTITY(table->part_table, compart->subparts[i]);
        if (subpart == NULL) {
            continue;
        }

        if (subpart->desc.part_id == subpart_id) {
            break;
        }
    }

    knl_panic_log(subpart != NULL, "the subpart is NULL, panic info: table %s", table->desc.name);
    if (db_drop_subpartition(session, dc, subpart) != CT_SUCCESS) {
        knl_rollback(session, NULL);
        CT_LOG_RUN_ERR("[PART] Failed to drop garbage subpart %s after data redistribution failure of adding subpart",
            subpart->desc.name);
    } else {
        knl_commit(session);
    }
}

static status_t db_add_hash_subpart_redis(knl_session_t *session, knl_dictionary_t *dc, uint32 compart_no,
    knl_altable_def_t *def, uint32 subpart_id)
{
    knl_dictionary_t new_dc;
    part_put_logic_log(session, dc);
    knl_commit(session);
    dc_invalidate(session, (dc_entity_t *)dc->handle);
    if (knl_open_dc_by_id(session, dc->uid, dc->oid, &new_dc, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    dc_close(dc);
    errno_t ret = memcpy_sp(dc, sizeof(knl_dictionary_t), &new_dc, sizeof(knl_dictionary_t));
    knl_securec_check(ret);

    if (tx_begin(session) != CT_SUCCESS) {
        return CT_ERROR;
    }

    table_t *table = DC_TABLE(dc);
    table_part_t *compart = TABLE_GET_PART(table, compart_no);
    if (db_add_subpart_redis_data(session, dc, compart, subpart_id) != CT_SUCCESS) {
        knl_rollback(session, NULL);
        subpart_addhash_drop_garbage_part(session, dc, compart, subpart_id);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t db_update_subidxpart_count(knl_session_t *session, knl_index_desc_t *desc, uint32 compart_id,
    bool32 is_add)
{
    row_assist_t ra;
    
    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_INDEXPART_ID, IX_SYS_INDEXPART001_ID);
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &desc->uid,
        sizeof(uint32), IX_COL_SYS_INDEXPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &desc->table_id,
        sizeof(uint32), IX_COL_SYS_INDEXPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &desc->id,
        sizeof(uint32), IX_COL_SYS_INDEXPART001_INDEX_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &compart_id,
        sizeof(uint32), IX_COL_SYS_INDEXPART001_PART_ID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s index %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                  ((table_t *)cursor->table)->desc.name, ((index_t *)cursor->index)->desc.name);
    uint32 subpart_cnt = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_INDEXPART_COL_SUBPART_CNT) + (is_add ? 1 : -1);
    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), UPDATE_COLUMN_COUNT_ONE);
    (void)row_put_int32(&ra, subpart_cnt);
    cursor->update_info.count = UPDATE_COLUMN_COUNT_ONE;
    cursor->update_info.columns[0] = SYS_INDEXPART_COL_SUBPART_CNT;
    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, NULL);

    if (knl_internal_update(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    CT_LOG_DEBUG_INF("update count: uid: %d, tid: %d, iid: %d, ppart id: %d", desc->uid, desc->table_id, desc->id,
        compart_id);
    CT_LOG_DEBUG_INF("update count: subpartcnt after update is: %d, the operation is(1:add, 0:drop): %d",
                     subpart_cnt, is_add);

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

static status_t subpart_update_part_count(knl_session_t *session, table_t *table, uint32 compart_id, bool32 is_add)
{
    knl_table_desc_t *desc = &table->desc;
    
    if (db_update_subtabpart_count(session, desc->uid, desc->id, compart_id, is_add) != CT_SUCCESS) {
        return CT_ERROR;
    }

    index_t *index = NULL;
    for (uint32 i = 0; i < table->index_set.total_count; i++) {
        index = table->index_set.items[i];
        if (!IS_PART_INDEX(index)) {
            continue;
        }

        if (db_update_subidxpart_count(session, &index->desc, compart_id, is_add) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t db_altable_add_subpartition(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def)
{
    table_part_t *compart = NULL;
    table_t *table = DC_TABLE(dc);
    knl_table_part_desc_t tab_desc = { 0 };
    
    if (subpart_add_verify_def(session, dc, def) != CT_SUCCESS) {
        return CT_ERROR;
    }

    /* clean not ready subparts */
    if (subpart_clean_garbage_partition(session, dc) != CT_SUCCESS) {
        return CT_ERROR;
    }
    
    if (!part_table_find_by_name(table->part_table, &def->part_def.name, &compart)) {
        CT_THROW_ERROR(ERR_PARTITION_NOT_EXIST, "table", T2S(&def->part_def.name));
        return CT_ERROR;
    }

    uint32 subpart_id = subpart_generate_partid(table->part_table, compart, CT_INVALID_ID32);
    knl_part_def_t *part_def = (knl_part_def_t *)cm_galist_get(&def->part_def.obj_def->parts, 0);
    part_def = (knl_part_def_t *)cm_galist_get(&part_def->subparts, 0);
    if (subpart_init_table_part_desc(session, &compart->desc, part_def, subpart_id, &tab_desc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    tab_desc.parent_partid = compart->desc.part_id;
    bool32 not_ready = (table->part_table->desc.subparttype == PART_TYPE_HASH);
    if (db_add_table_subpart(session, table, &tab_desc, not_ready) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (db_add_lob_subpart(session, dc, part_def, compart->desc.part_id, subpart_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (db_add_index_subpart(session, table, &tab_desc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (subpart_update_part_count(session, table, compart->desc.part_id, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }
    
    if (db_update_table_chgscn(session, &table->desc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (table->part_table->desc.subparttype != PART_TYPE_HASH) {
        return CT_SUCCESS;
    }

    if (db_add_hash_subpart_redis(session, dc, compart->part_no, def, subpart_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

