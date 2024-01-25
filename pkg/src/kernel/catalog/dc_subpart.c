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
 * dc_subpart.c
 *
 *
 * IDENTIFICATION
 * src/kernel/catalog/dc_subpart.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_dc_module.h"
#include "knl_dc.h"
#include "knl_session.h"
#include "knl_context.h"
#include "ostat_load.h"
#include "knl_space_base.h"
#include "knl_table.h"
#include "index_common.h"
#include "dc_part.h"
#include "dc_subpart.h"
#include "knl_sys_part_defs.h"
#include "index_common.h"
#include "dtc_dls.h"

status_t dc_load_subpart_columns(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity)
{
    knl_part_column_desc_t desc;
    table_t *table = &entity->table;
    part_table_t *part_table = table->part_table;
    dc_context_t *dc_ctx = &session->kernel->dc_ctx;
    uint32 memsize = sizeof(knl_part_column_desc_t) * part_table->desc.subpartkeys;
    
    if (dc_alloc_mem(dc_ctx, entity->memory, memsize, (void **)&part_table->sub_keycols) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_DC_BUFFER_FULL);
        return CT_ERROR;
    }

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_SUB_PARTCOLUMN_ID, IX_SYS_PARTCOLUMN001_ID);
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &table->desc.uid,
        sizeof(uint32), IX_COL_SYS_PARTCOLUMN001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &table->desc.id,
        sizeof(uint32), IX_COL_SYS_PARTCOLUMN001_TABLE_ID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        return CT_ERROR;
    }

    while (!cursor->eof) {
        dc_part_convert_column_desc(cursor, &desc);

        knl_panic_log(desc.pos_id < part_table->desc.subpartkeys, "the pos_id is more than part_table's subpartkeys, "
                      "panic info: page %u-%u type %u table %s index %s pos_id %u subpartkeys %u", cursor->rowid.file,
                      cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, table->desc.name,
                      ((index_t *)cursor->index)->desc.name, desc.pos_id, part_table->desc.subpartkeys);
        part_table->sub_keycols[desc.pos_id] = desc;

        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t dc_alloc_subpart_table(knl_session_t *session, dc_entity_t *entity, part_table_t *part_table)
{
    dc_context_t *dc_ctx = &session->kernel->dc_ctx;

    uint32 memsize = CT_SHARED_PAGE_SIZE;
    if (dc_alloc_mem(dc_ctx, entity->memory, memsize, (void **)&part_table->sub_groups) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_DC_BUFFER_FULL);
        return CT_ERROR;
    }

    errno_t ret = memset_sp(part_table->sub_groups, memsize, 0, memsize);
    knl_securec_check(ret);

    if (dc_alloc_mem(dc_ctx, entity->memory, memsize, (void **)&part_table->subno_groups) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_DC_BUFFER_FULL);
        return CT_ERROR;
    }

    ret = memset_sp(part_table->subno_groups, memsize, 0, memsize);
    knl_securec_check(ret);

    if (dc_alloc_mem(dc_ctx, entity->memory, CT_SHARED_PAGE_SIZE, (void **)&part_table->sub_pbuckets) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_DC_BUFFER_FULL);
        return CT_ERROR;
    }

    ret = memset_sp(part_table->sub_pbuckets, CT_SHARED_PAGE_SIZE, 0, CT_SHARED_PAGE_SIZE);
    knl_securec_check(ret);

    for (uint32 i = 0; i < PART_NAME_HASH_SIZE; i++) {
        part_table->sub_pbuckets[i].first = CT_INVALID_ID32;
    }

    if (part_table->desc.subparttype != PART_TYPE_LIST) {
        return CT_SUCCESS;
    }

    if (dc_alloc_mem(dc_ctx, entity->memory, CT_SHARED_PAGE_SIZE, (void **)&part_table->sub_lbuckets) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_DC_BUFFER_FULL);
        return CT_ERROR;
    }

    for (uint32 i = 0; i < LIST_PART_HASH_SIZE; i++) {
        part_table->sub_lbuckets[i].first.id = CT_INVALID_ID32;
        part_table->sub_lbuckets[i].first.offset = CT_INVALID_ID32;
    }

    return CT_SUCCESS;
}

status_t dc_alloc_subpart_index(knl_session_t *session, dc_entity_t *entity, part_index_t *part_index)
{
    dc_context_t *dc_ctx = &session->kernel->dc_ctx;

    if (dc_alloc_mem(dc_ctx, entity->memory, CT_SHARED_PAGE_SIZE, (void **)&part_index->sub_groups) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_DC_BUFFER_FULL);
        return CT_ERROR;
    }

    errno_t ret = memset_sp(part_index->sub_groups, CT_SHARED_PAGE_SIZE, 0, CT_SHARED_PAGE_SIZE);
    knl_securec_check(ret);

    if (dc_alloc_mem(dc_ctx, entity->memory, CT_SHARED_PAGE_SIZE, (void **)&part_index->sub_pbuckets) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_DC_BUFFER_FULL);
        return CT_ERROR;
    }

    ret = memset_sp(part_index->sub_pbuckets, CT_SHARED_PAGE_SIZE, 0, CT_SHARED_PAGE_SIZE);
    knl_securec_check(ret);

    for (uint32 i = 0; i < PART_NAME_HASH_SIZE; i++) {
        part_index->sub_pbuckets[i].first = CT_INVALID_ID32;
    }
    
    return CT_SUCCESS;
}

status_t dc_alloc_table_subparts(knl_session_t *session, dc_entity_t *entity, table_part_t *compart)
{
    dc_context_t *ctx = &session->kernel->dc_ctx;
    uint32 memsize = compart->desc.subpart_cnt * sizeof(uint32);

    if (compart->subparts == NULL) {
        if (dc_alloc_mem(ctx, entity->memory, memsize, (void **)&compart->subparts) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_DC_BUFFER_FULL);
            return CT_ERROR;
        }
    }

    errno_t ret = memset_sp(compart->subparts, memsize, 0XFF, memsize);
    knl_securec_check(ret);
    
    return CT_SUCCESS;
}

static void dc_subpart_table_insert_name(part_table_t *part_table, table_part_t *subpart)
{
    text_t name;

    cm_str2text(subpart->desc.name, &name);
    uint32 hash = dc_cal_part_name_hash(&name);
    part_bucket_t *bucket = &part_table->sub_pbuckets[hash];

    subpart->pnext = bucket->first;
    bucket->first = subpart->global_partno;
}

static status_t dc_alloc_subpart_table_group(knl_session_t *session, dc_entity_t *entity, uint32 gid)
{
    table_t *table = &entity->table;
    part_table_t *part_table = table->part_table;
    dc_context_t *ctx = &session->kernel->dc_ctx;
    
    if (part_table->sub_groups[gid] != NULL) {
        return CT_SUCCESS;
    }

    uint32 memsize = sizeof(table_part_group_t);
    if (dc_alloc_mem(ctx, entity->memory, memsize, (void **)&part_table->sub_groups[gid]) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_DC_BUFFER_FULL);
        return CT_ERROR;
    }

    errno_t ret = memset_sp(part_table->sub_groups[gid], memsize, 0, memsize);
    knl_securec_check(ret);

    memsize = sizeof(part_no_group_t);
    if (dc_alloc_mem(ctx, entity->memory, memsize, (void **)&part_table->subno_groups[gid]) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_DC_BUFFER_FULL);
        return CT_ERROR;
    }

    ret = memset_sp(part_table->subno_groups[gid], memsize, 0xFF, memsize);
    knl_securec_check(ret);

    return CT_SUCCESS;
}

status_t dc_alloc_table_subpart(knl_session_t *session, dc_entity_t *entity, uint32 id)
{
    table_part_t *subpart = NULL;
    table_t *table = &entity->table;
    part_table_t *part_table = table->part_table;
    dc_context_t *ctx = &session->kernel->dc_ctx;

    uint32 gid = id / PART_GROUP_SIZE;
    uint32 eid = id % PART_GROUP_SIZE;
    if (dc_alloc_subpart_table_group(session, entity, gid) != CT_SUCCESS) {
        return CT_ERROR;
    }

    table_part_group_t *group = part_table->sub_groups[gid];
    if (group->entity[eid] == NULL) {
        if (dc_alloc_mem(ctx, entity->memory, sizeof(table_part_t), (void **)&subpart) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_DC_BUFFER_FULL);
            return CT_ERROR;
        }

        errno_t ret = memset_sp(subpart, sizeof(table_part_t), 0, sizeof(table_part_t));
        knl_securec_check(ret);
        subpart->is_ready = CT_FALSE;
        subpart->desc.entry = INVALID_PAGID;
        group->entity[eid] = subpart;
    }

    return CT_SUCCESS;
}

static void dc_init_table_subpart(dc_entity_t *entity, table_part_t *compart, knl_table_part_desc_t *desc,
    table_part_t **subpart, uint32 start_pos)
{
    table_t *table = &entity->table;
    part_table_t *part_table = table->part_table;

    uint32 gid = start_pos / PART_GROUP_SIZE;
    uint32 eid = start_pos % PART_GROUP_SIZE;
    *subpart = part_table->sub_groups[gid]->entity[eid];
    knl_panic_log(*subpart != NULL, "the subpart is NULL, panic info: table %s compart %s", table->desc.name,
                  compart->desc.name);
    uint32 *partnos = &part_table->subno_groups[gid]->nos[eid];
    errno_t ret = memcpy_sp(&(*subpart)->desc, sizeof(knl_table_part_desc_t), desc, sizeof(knl_table_part_desc_t));
    knl_securec_check(ret);
    (*subpart)->global_partno = start_pos;
    (*subpart)->parent_partno = compart->part_no;
    (*subpart)->heap.entry = desc->entry;
    (*subpart)->heap.table = &entity->table;
    (*subpart)->heap.max_pages = desc->storage_desc.max_pages;
    *partnos = (*subpart)->global_partno;
    (*subpart)->desc.cr_mode = compart->desc.cr_mode;
    dls_init_spinlock2(&(*subpart)->heap.lock, DR_TYPE_HEAP_PART, desc->table_id,
                       desc->uid, desc->part_id, (*subpart)->part_no, (*subpart)->parent_partno);
    dls_init_latch2(&(*subpart)->heap.latch, DR_TYPE_HEAP_PART_LATCH, desc->table_id,
                    desc->uid, desc->part_id, (*subpart)->part_no, (*subpart)->parent_partno, 0);

    dc_subpart_table_insert_name(part_table, *subpart);
}

static void dc_subpart_table_insert_list(part_table_t *part_table, table_part_t *subpart, uint32 partkeys)
{
    uint32 hash;
    list_bucket_t *bucket = NULL;
    part_decode_key_t *decoder = NULL;
    text_t values[CT_MAX_PARTKEY_COLUMNS];
    bool32 is_default = CT_FALSE;

    for (uint32 i = 0; i < subpart->desc.groupcnt; i++) {
        decoder = &subpart->desc.groups[i];
        is_default = CT_FALSE;

        for (uint32 j = 0; j < decoder->count; j++) {
            values[j].str = decoder->buf + decoder->offsets[j];

            if (decoder->lens[j] == PART_KEY_DEFAULT_LEN) {
                is_default = CT_TRUE;
            } else if (decoder->lens[j] == PART_KEY_NULL_LEN) {
                values[j].len = 0;
            } else {
                values[j].len = (uint32)decoder->lens[j];
            }
        }

        if (is_default) {
            bucket = &part_table->sub_lbuckets[DEFAULT_PART_LIST];
        } else {
            hash = dc_cal_list_value_hash(values, decoder->count);
            bucket = &part_table->sub_lbuckets[hash];
        }

        subpart->lnext[i] = bucket->first;
        bucket->first.id = subpart->global_partno;
        bucket->first.offset = i;
    }
}

static uint64 subpart_sort_get_scn(part_table_t *part_table, uint32 subpart_no)
{
    table_part_t *entity = NULL;

    if (subpart_no != CT_INVALID_ID32) {
        entity = PART_GET_SUBENTITY(part_table, subpart_no);
        return entity->desc.org_scn;
    }

    return CT_INVALID_ID64;
}

static void dc_subpartno_sort(part_table_t *part_table)
{
    uint32 *curr_no = NULL;
    uint32 *last_no = NULL;
    uint32 *last_no1 = NULL;
    uint64 curr_scn, last_scn;
    int32 left, right, mid;

    for (uint32 i = 1; i < part_table->desc.subpart_cnt; i++) {
        curr_no = &PART_GET_SUBPARTNO(part_table, i);
        curr_scn = subpart_sort_get_scn(part_table, *curr_no);

        left = 0;
        right = i - 1;
        while (left <= right) {
            mid = (left + right) / 2; // get median of left and right
            last_no = &PART_GET_SUBPARTNO(part_table, (uint32)mid);
            last_scn = subpart_sort_get_scn(part_table, *last_no);
            if (last_scn > curr_scn) {
                right = mid - 1;
            } else {
                left = mid + 1;
            }
        }

        for (int32 j = i - 1; j >= left; j--) {
            last_no = &PART_GET_SUBPARTNO(part_table, (uint32)j);
            last_no1 = &PART_GET_SUBPARTNO(part_table, (uint32)j + 1);
            dc_partno_swap(last_no1, last_no);
        }
    }
}

static void dc_refresh_subpart_storage(knl_table_part_desc_t *compart_desc, knl_table_part_desc_t *subpart_desc)
{
    if (compart_desc->storage_desc.initial != 0) {
        subpart_desc->storage_desc.initial = compart_desc->storage_desc.initial;
    }

    if (compart_desc->storage_desc.max_pages != 0) {
        subpart_desc->storage_desc.max_pages = compart_desc->storage_desc.max_pages;
    }
}

static status_t dc_load_table_subpart(knl_session_t *session, dc_entity_t *entity, knl_cursor_t *cursor,
    table_part_t *compart, uint32 *part_pos, uint32 subpart_ind)
{
    knl_table_part_desc_t desc = { 0 };
    table_part_t *subpart = NULL;
    table_t *table = &entity->table;
    part_table_t *part_table = table->part_table;
    uint32 partkeys = part_table->desc.subpartkeys;

    if (dc_get_table_part_desc(session, cursor, entity, partkeys, &desc, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    /* subpart's storage parameter need be refreshed from parent part */
    dc_refresh_subpart_storage(&compart->desc, &desc);
    
    /* empty table entry when nologging table is first loaded(db restart) */
    if (IS_NOLOGGING_BY_TABLE_TYPE(table->desc.type) && entity->entry->need_empty_entry) {
        desc.entry = INVALID_PAGID;
        if (dc_reset_nologging_entry(session, (knl_handle_t)&desc, OBJ_TYPE_TABLE_SUBPART) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (desc.not_ready && part_table->desc.subparttype == PART_TYPE_RANGE) {
        uint32 not_ready_pos = part_table->desc.subpart_cnt - part_table->desc.not_ready_subpartcnt - 1;
        if (dc_alloc_table_subpart(session, entity, not_ready_pos) != CT_SUCCESS) {
            return CT_ERROR;
        }

        dc_init_table_subpart(entity, compart, &desc, &subpart, not_ready_pos);
        compart->subparts[subpart_ind] = not_ready_pos;
        part_table->desc.not_ready_subpartcnt++;
    } else {
        if (dc_alloc_table_subpart(session, entity, *part_pos) != CT_SUCCESS) {
            return CT_ERROR;
        }

        dc_init_table_subpart(entity, compart, &desc, &subpart, *part_pos);
        compart->subparts[subpart_ind] = *part_pos;
        (*part_pos)++;
    }

    subpart->part_no = subpart_ind;
    if (part_table->desc.subparttype == PART_TYPE_LIST) {
        uint32 memsize = sizeof(list_item_t) * subpart->desc.groupcnt;
        if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, memsize, (void **)&subpart->lnext) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_DC_BUFFER_FULL);
            return CT_ERROR;
        }

        dc_subpart_table_insert_list(part_table, subpart, partkeys);
    }

    subpart->is_ready = CT_TRUE;
    CT_LOG_DEBUG_INF("get one sub partition whose status is ready, part name is %s, current ready count is %d",
        desc.name, (*part_pos) + 1);
    
    return CT_SUCCESS;
}

/* load all table subpart of one composite partition table */
static status_t dc_load_subtabparts_of_compart(knl_session_t *session, dc_entity_t *entity, knl_cursor_t *cursor,
    table_part_t *compart, uint32 *part_pos)
{
    uint32 subpart_index = 0;
    table_t *table = &entity->table;

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_SUB_TABLE_PARTS_ID, IX_SYS_TABLESUBPART001_ID);
    knl_init_index_scan(cursor, CT_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &table->desc.uid,
        sizeof(uint32), IX_COL_SYS_TABLESUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &table->desc.id,
        sizeof(uint32), IX_COL_SYS_TABLESUBPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &compart->desc.part_id,
        sizeof(uint32), IX_COL_SYS_TABLESUBPART001_PARENT_PART_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_TABLESUBPART001_SUB_PART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, &table->desc.uid,
        sizeof(uint32), IX_COL_SYS_TABLESUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, &table->desc.id,
        sizeof(uint32), IX_COL_SYS_TABLESUBPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, &compart->desc.part_id,
        sizeof(uint32), IX_COL_SYS_TABLESUBPART001_PARENT_PART_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_TABLESUBPART001_SUB_PART_ID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        return CT_ERROR;
    }

    while (!cursor->eof) {
        if (dc_load_table_subpart(session, entity, cursor, compart, part_pos, subpart_index) != CT_SUCCESS) {
            return CT_ERROR;
        }

        CT_LOG_DEBUG_INF("load table subpart, uid: %d, tid: %d, table subpart(%d-%d)", table->desc.uid,
            table->desc.id, compart->part_no, subpart_index);
        subpart_index++;

        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    knl_panic_log(subpart_index == compart->desc.subpart_cnt, "the subpart_index is not equal to subpart count, "
                  "panic info: page %u-%u type %u table %s table_part %s index %s subpart_index %u subpart_cnt %u",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, table->desc.name,
                  compart->desc.name, ((index_t *)cursor->index)->desc.name, subpart_index, compart->desc.subpart_cnt);
    return CT_SUCCESS;
}

status_t dc_load_table_subparts(knl_session_t *session, dc_entity_t *entity, knl_cursor_t *cursor)
{
    uint32 part_pos = 0;
    table_part_t *compart = NULL;
    table_t *table = &entity->table;
    part_table_t *part_table = table->part_table;

    for (uint32 i = 0; i < part_table->desc.partcnt + part_table->desc.not_ready_partcnt; i++) {
        compart = TABLE_GET_PART(table, i);
        if (!IS_READY_PART(compart)) {
            continue;
        }

        knl_panic_log(IS_PARENT_TABPART(&compart->desc), "the compart is not parent tabpart, panic info: "
                      "page %u-%u type %u table %s compart %s", cursor->rowid.file, cursor->rowid.page,
                      ((page_head_t *)cursor->page_buf)->type, table->desc.name, compart->desc.name);
        if (dc_load_subtabparts_of_compart(session, entity, cursor, compart, &part_pos) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    knl_panic_log(part_pos + part_table->desc.not_ready_subpartcnt == part_table->desc.subpart_cnt,
                  "part_table's subpartcnt is abnormal, panic info: page %u-%u type %u table %s compart %s "
                  "part_pos %u not ready subpartcnt %u subpart_cnt %u", cursor->rowid.file, cursor->rowid.page,
                  ((page_head_t *)cursor->page_buf)->type, table->desc.name, compart->desc.name, part_pos,
                  part_table->desc.not_ready_subpartcnt, part_table->desc.subpart_cnt);
    dc_subpartno_sort(part_table);
    return CT_SUCCESS;
}

table_part_t *dc_get_table_subpart(part_table_t *part_table, uint64 org_scn)
{
    uint32 part_no;
    table_part_t *table_part = NULL;
    
    int32 curr = 0;
    int32 begin = 0;
    int32 end = part_table->desc.subpart_cnt - 1;

    while (begin <= end) {
        curr = ((uint32)(end + begin)) >> 1;
        part_no = PART_GET_SUBPARTNO(part_table, (uint32)curr);
        table_part = PART_GET_SUBENTITY(part_table, part_no);
        if (org_scn < table_part->desc.org_scn) {
            end = curr - 1;
        } else if (org_scn > table_part->desc.org_scn) {
            begin = curr + 1;
        } else {
            return table_part;
        }
    }
    
    return NULL;
}

status_t dc_alloc_index_subparts(knl_session_t *session, dc_entity_t *entity, index_part_t *compart)
{
    dc_context_t *ctx = &session->kernel->dc_ctx;
    uint32 memsize = compart->desc.subpart_cnt * sizeof(uint32);

    if (compart->subparts == NULL) {
        if (dc_alloc_mem(ctx, entity->memory, memsize, (void **)&compart->subparts) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_DC_BUFFER_FULL);
            return CT_ERROR;
        }
    }

    errno_t ret = memset_sp(compart->subparts, memsize, 0XFF, memsize);
    knl_securec_check(ret);

    return CT_SUCCESS;
}

static status_t dc_alloc_subpart_index_group(knl_session_t *session, dc_entity_t *entity, index_t *index, uint32 gid)
{
    dc_context_t *dc_ctx = &session->kernel->dc_ctx;
    part_index_t *part_index = index->part_index;
    
    if (part_index->sub_groups[gid] != NULL) {
        return CT_SUCCESS;
    }

    uint32 memsize = sizeof(index_part_group_t);
    if (dc_alloc_mem(dc_ctx, entity->memory, memsize, (void **)&part_index->sub_groups[gid]) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_DC_BUFFER_FULL);
        return CT_ERROR;
    }

    errno_t ret = memset_sp(part_index->sub_groups[gid], memsize, 0, memsize);
    knl_securec_check(ret);
    
    return CT_SUCCESS;
}

status_t dc_alloc_index_subpart(knl_session_t *session, dc_entity_t *entity, index_t *index, uint32 id)
{
    uint32 gid = id / PART_GROUP_SIZE;
    uint32 eid = id % PART_GROUP_SIZE;
    part_index_t *part_index = index->part_index;
    dc_context_t *dc_ctx = &session->kernel->dc_ctx;

    if (dc_alloc_subpart_index_group(session, entity, index, gid) != CT_SUCCESS) {
        return CT_ERROR;
    }

    index_part_group_t *group = part_index->sub_groups[gid];
    index_part_t *subpart = NULL;
    if (group->entity[eid] == NULL) {
        if (dc_alloc_mem(dc_ctx, entity->memory, sizeof(index_part_t), (void **)&subpart) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_DC_BUFFER_FULL);
            return CT_ERROR;
        }

        errno_t ret = memset_sp(subpart, sizeof(index_part_t), 0, sizeof(index_part_t));
        knl_securec_check(ret);
        subpart->desc.entry = INVALID_PAGID;
        group->entity[eid] = subpart;
    }

    return CT_SUCCESS;
}

static void dc_subpart_index_insert_name(part_index_t *part_index, index_part_t *subpart)
{
    text_t name;
    cm_str2text(subpart->desc.name, &name);
    uint32 hash = dc_cal_part_name_hash(&name);
    part_bucket_t *bucket = &part_index->sub_pbuckets[hash];
    subpart->pnext = bucket->first;
    bucket->first = subpart->global_partno;
}

static status_t dc_init_index_subpart(knl_session_t *session, index_t *index, index_part_t *index_compart,
    knl_index_part_desc_t *desc, uint32 *pos, bool8 is_shadow)
{
    uint32 real_pos = 0;
    dc_entity_t *entity = index->entity;
    table_t *table = &entity->table;
    part_index_t *part_index = index->part_index;
    table_part_t *table_compart = TABLE_GET_PART(table, index_compart->part_no);
    table_part_t *table_subpart = NULL;
    for (uint32 i = 0; i < table_compart->desc.subpart_cnt; i++) {
        table_subpart = PART_GET_SUBENTITY(table->part_table, table_compart->subparts[i]);
        if (table_subpart->desc.part_id == desc->part_id) {
            desc->is_not_ready = table_subpart->desc.not_ready;
            real_pos = table_subpart->global_partno;
            break;
        }
    }

    if (dc_alloc_index_subpart(session, entity, index, real_pos) != CT_SUCCESS) {
        return CT_ERROR;
    }
    
    index_part_t *subpart = PART_GET_SUBENTITY(part_index, real_pos);
    errno_t ret = memcpy_sp(&subpart->desc, sizeof(knl_index_part_desc_t), desc, sizeof(knl_index_part_desc_t));
    knl_securec_check(ret);
    subpart->btree.entry = desc->entry;
    subpart->btree.index = index;
    subpart->btree.is_shadow = is_shadow;
    subpart->part_no = table_subpart->part_no;
    subpart->parent_partno = index_compart->part_no;
    subpart->global_partno = real_pos;
    subpart->desc.cr_mode = index->desc.cr_mode;
    dc_subpart_index_insert_name(part_index, subpart);
    *pos = real_pos;
    dls_init_latch2(&subpart->btree.struct_latch, DR_TYPE_BRTEE_PART_LATCH, subpart->desc.table_id,
                    subpart->desc.uid, subpart->desc.index_id, subpart->part_no, subpart->parent_partno, is_shadow);
    
    return CT_SUCCESS;
}

static status_t dc_load_shwidx_subpart(knl_session_t *session, index_t *index, knl_cursor_t *cursor,
    index_part_t *compart, uint32 *part_pos)
{
    knl_index_part_desc_t desc;
    dc_entity_t *entity = index->entity;
    table_t *table = &entity->table;
    part_index_t *part_index = index->part_index;
    uint32 subpartkeys = part_index->desc.subpartkeys;
    dc_user_t *user = session->kernel->dc_ctx.users[entity->table.desc.uid];

    errno_t ret = memset_sp(&desc, sizeof(knl_index_part_desc_t), 0, sizeof(knl_index_part_desc_t));
    knl_securec_check(ret);

    if (part_convert_index_part_desc(session, cursor, entity, subpartkeys, &desc) != CT_SUCCESS) {
        return CT_ERROR;
    }
    desc.parent_partid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SHADOW_INDEXPART_COL_SUBPART_CNT);

    /* empty table entry when nologging table is first loaded(db restart) */
    if (IS_NOLOGGING_BY_TABLE_TYPE(table->desc.type) && entity->entry->need_empty_entry) {
        desc.entry = INVALID_PAGID;
        if (dc_reset_nologging_entry(session, (knl_handle_t)&desc, OBJ_TYPE_SHADOW_INDEX_SUBPART) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (dc_init_index_subpart(session, index, compart, &desc, part_pos, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    index_part_t *subpart = PART_GET_SUBENTITY(part_index, *part_pos);
    if (dc_load_index_part_segment(session, entity, (index_part_t *)subpart) != CT_SUCCESS) {
        CT_LOG_RUN_WAR("[DC] could not load index partition %s of table %s.%s, segment corrupted",
                       subpart->desc.name, user->desc.name, entity->table.desc.name);
    }

    if (!IS_SYS_TABLE(table)) {
        if (stats_seg_load_entity(session, desc.org_scn, &subpart->btree.stat) != CT_SUCCESS) {
            CT_LOG_RUN_INF("segment statistic failed, there might be some statitics loss.");
        }
    }

    return CT_SUCCESS;
}

static status_t dc_load_shwidx_subparts_compart(knl_session_t *session, knl_cursor_t *cursor, index_t *index,
    index_part_t *compart)
{
    uint32 subpart_idx = 0;
    uint32 subpart_pos = CT_INVALID_ID32;
    
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_SHADOW_INDEXPART_ID, IX_SYS_SHW_INDEXPART001_ID);
    knl_init_index_scan(cursor, CT_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &index->desc.uid,
        sizeof(uint32), IX_COL_SYS_SHW_INDEXPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &index->desc.table_id,
        sizeof(uint32), IX_COL_SYS_SHW_INDEXPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &index->desc.id,
        sizeof(uint32), IX_COL_SYS_SHW_INDEXPART001_INDEX_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER,
        &compart->desc.part_id, sizeof(uint32), IX_COL_SYS_SHW_INDEXPART001_PARENTPART_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_SHW_INDEXPART001_PART_ID);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, &index->desc.uid,
        sizeof(uint32), IX_COL_SYS_SHW_INDEXPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, &index->desc.table_id,
        sizeof(uint32), IX_COL_SYS_SHW_INDEXPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, &index->desc.id,
        sizeof(uint32), IX_COL_SYS_SHW_INDEXPART001_INDEX_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER,
        &compart->desc.part_id, sizeof(uint32), IX_COL_SYS_SHW_INDEXPART001_PARENTPART_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_SHW_INDEXPART001_PART_ID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        return CT_ERROR;
    }

    knl_index_part_desc_t desc;
    while (!cursor->eof) {
        /* skip parent shadow index part */
        desc.flags = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SHADOW_INDEXPART_COL_FLAGS);
        desc.subpart_cnt = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SHADOW_INDEXPART_COL_SUBPART_CNT);
        if (!IS_SUB_IDXPART(&desc)) {
            if (knl_fetch(session, cursor) != CT_SUCCESS) {
                return CT_ERROR;
            }

            continue;
        }
        
        if (dc_load_shwidx_subpart(session, index, cursor, compart, &subpart_pos) != CT_SUCCESS) {
            return CT_ERROR;
        }

        compart->subparts[subpart_idx] = subpart_pos;
        CT_LOG_DEBUG_INF("load index subparts, uid: %d, tid: %d, iid: %d, index subpart(%d-%d)",
            index->desc.uid, index->desc.table_id, index->desc.id, compart->part_no, subpart_idx);
        subpart_idx++;
        
        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    knl_panic_log(subpart_idx == compart->desc.subpart_cnt, "%u subparts has been loaded, but expect %u, compart %s",
        subpart_idx, compart->desc.subpart_cnt, compart->desc.name);
    return CT_SUCCESS;
}

status_t dc_load_shwidx_subparts(knl_session_t *session, knl_cursor_t *cursor, index_t *index)
{
    index_part_t *compart = NULL;
    table_part_t *table_part = NULL;
    part_index_t *part_index = index->part_index;
    table_t *table = &index->entity->table;

    for (uint32 i = 0; i < part_index->desc.partcnt + part_index->desc.not_ready_partcnt; i++) {
        compart = INDEX_GET_PART(index, i);
        table_part = TABLE_GET_PART(table, i);
        if (!IS_READY_PART(table_part) || compart == NULL) {
            continue;
        }
        
        knl_panic_log(IS_PARENT_IDXPART(&compart->desc), "the compart is not parent idxpart, panic info: page %u-%u "
                      "type %u table %s table_part %s index %s index_compart %s",
                      cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                      table->desc.name, table_part->desc.name, index->desc.name, compart->desc.name);
        if (dc_load_shwidx_subparts_compart(session, cursor, index, compart) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    
    return CT_SUCCESS;
}

static void inline dc_load_idx_subpart_empty_stats(knl_session_t *session, knl_cursor_t *cursor,
    index_part_t *idx_part)
{
    if (CURSOR_COLUMN_SIZE(cursor, SYS_INDEXSUBPART_COL_EMPTY_LEAF_BLOCKS) == CT_NULL_VALUE_LEN) {
        return;
    }

    uint32 empty_size = *(uint32*)CURSOR_COLUMN_DATA(cursor, SYS_INDEXSUBPART_COL_EMPTY_LEAF_BLOCKS);
    idx_part->btree.chg_stats.empty_size = MAX(idx_part->btree.chg_stats.empty_size,
        (uint64)empty_size * DEFAULT_PAGE_SIZE(session));
    idx_part->btree.chg_stats.first_empty_size = 0;
}

static status_t dc_load_index_subpart(knl_session_t *session, index_t *index, knl_cursor_t *cursor,
    index_part_t *compart, uint32 *part_pos)
{
    knl_index_part_desc_t desc = { 0 };
    dc_entity_t *entity = index->entity;
    table_t *table = &entity->table;
    part_index_t *part_index = index->part_index;
    uint32 subpartkeys = part_index->desc.subpartkeys;
    dc_user_t *user = session->kernel->dc_ctx.users[entity->table.desc.uid];
    
    if (part_convert_index_part_desc(session, cursor, entity, subpartkeys, &desc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    dc_set_index_part_valid(index, desc);
    /* empty table entry when nologging table is first loaded(db restart) */
    if (IS_NOLOGGING_BY_TABLE_TYPE(table->desc.type) && entity->entry->need_empty_entry) {
        desc.entry = INVALID_PAGID;
        if (dc_reset_nologging_entry(session, (knl_handle_t)&desc, OBJ_TYPE_INDEX_SUBPART) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (dc_init_index_subpart(session, index, compart, &desc, part_pos, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }
    
    index_part_t *subpart = PART_GET_SUBENTITY(part_index, *part_pos);
    if (dc_load_index_part_segment(session, entity, subpart) != CT_SUCCESS) {
        CT_LOG_RUN_WAR("[DC] could not load index sub partition %s of table %s.%s, segment corrupted",
                       subpart->desc.name, user->desc.name, entity->table.desc.name);
    }
    
    if (!IS_SYS_TABLE(table)) {
        if (stats_seg_load_entity(session, desc.org_scn, &subpart->btree.stat) != CT_SUCCESS) {
            CT_LOG_RUN_INF("segment statistic failed, there might be some statitics loss.");
        }
    }

    dc_load_idx_subpart_empty_stats(session, cursor, subpart);

    return CT_SUCCESS;
}

static status_t dc_load_subidxparts_of_compart(knl_session_t *session, knl_cursor_t *cursor, index_t *index,
    index_part_t *compart)
{
    uint32 subpart_ind = 0;
    uint32 subpart_pos = CT_INVALID_ID32;
    
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_SUB_INDEX_PARTS_ID, IX_SYS_INDEXSUBPART001_ID);
    knl_init_index_scan(cursor, CT_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &index->desc.uid,
        sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &index->desc.table_id,
        sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &index->desc.id,
        sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_INDEX_ID);
    knl_panic_log(IS_PARENT_IDXPART(&compart->desc),
        "the compart is not parent idxpart, panic info: page %u-%u type %u table %s, index %s index_compart %s",
        cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
        ((table_t *)cursor->table)->desc.name, index->desc.name, compart->desc.name);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER,
        &compart->desc.part_id, sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_PARENT_PART_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_INDEXSUBPART001_SUB_PART_ID);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, &index->desc.uid,
        sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, &index->desc.table_id,
        sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, &index->desc.id,
        sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_INDEX_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER,
        &compart->desc.part_id, sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_PARENT_PART_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_INDEXSUBPART001_SUB_PART_ID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        return CT_ERROR;
    }

    while (!cursor->eof) {
        if (dc_load_index_subpart(session, index, cursor, compart, &subpart_pos) != CT_SUCCESS) {
            return CT_ERROR;
        }

        compart->subparts[subpart_ind] = subpart_pos;
        CT_LOG_DEBUG_INF("load index subpart, uid: %d, tid: %d, iid: %d, index subpart(%d-%d)", index->desc.uid,
            index->desc.table_id, index->desc.id, compart->part_no, subpart_ind);
        subpart_ind++;
            
        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    knl_panic_log(subpart_ind == compart->desc.subpart_cnt, "subpart_ind is not equal to subpart count, panic info: "
                  "page %u-%u type %u subpart_ind %u subpart_cnt %u table %s index %s compart %s", cursor->rowid.file,
                  cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, subpart_ind, compart->desc.subpart_cnt,
                  ((table_t *)cursor->table)->desc.name, index->desc.name, compart->desc.name);
    return CT_SUCCESS;
}

status_t dc_load_index_subparts(knl_session_t *session, knl_cursor_t *cursor, index_t *index)
{
    index_part_t *compart = NULL;
    table_part_t *table_part = NULL;
    part_index_t *part_index = index->part_index;
    table_t *table = &index->entity->table;

    for (uint32 i = 0; i < part_index->desc.partcnt + part_index->desc.not_ready_partcnt; i++) {
        table_part = TABLE_GET_PART(table, i);
        if (!IS_READY_PART(table_part)) {
            continue;
        }
        
        compart = INDEX_GET_PART(index, i);
        knl_panic_log(IS_PARENT_IDXPART(&compart->desc), "the compart is not parent idxpart, panic info: "
                      "page %u-%u type %u table %s table_part %s index %s index_compart %s", cursor->rowid.file,
                      cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, table->desc.name,
                      table_part->desc.name, index->desc.name, compart->desc.name);
        if (dc_load_subidxparts_of_compart(session, cursor, index, compart) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t dc_alloc_lob_subparts(knl_session_t *session, dc_entity_t *entity, lob_part_t *compart)
{
    dc_context_t *dc_ctx = &session->kernel->dc_ctx;
    uint32 memsize = compart->desc.subpart_cnt * sizeof(uint32);
    
    if (compart->subparts == NULL) {
        if (dc_alloc_mem(dc_ctx, entity->memory, memsize, (void **)&compart->subparts) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_DC_BUFFER_FULL);
            return CT_ERROR;
        }
    }
    
    errno_t ret = memset_sp(compart->subparts, memsize, 0, memsize);
    knl_securec_check(ret);
    return CT_SUCCESS;
}

static status_t dc_alloc_subpart_lob_group(knl_session_t *session, dc_entity_t *entity, lob_t *lob, uint32 gid)
{
    part_lob_t *part_lob = lob->part_lob;
    dc_context_t *dc_ctx = &session->kernel->dc_ctx;
    
    if (part_lob->sub_groups[gid] == NULL) {
        uint32 memsize = sizeof(lob_part_group_t);
        if (dc_alloc_mem(dc_ctx, entity->memory, memsize, (void **)&part_lob->sub_groups[gid]) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_DC_BUFFER_FULL);
            return CT_ERROR;
        }

        errno_t ret = memset_sp(part_lob->sub_groups[gid], memsize, 0, memsize);
        knl_securec_check(ret);
    }
    
    return CT_SUCCESS;
}

status_t dc_alloc_lob_subpart(knl_session_t *session, dc_entity_t *entity, lob_t *lob, uint32 id)
{
    uint32 gid = id / PART_GROUP_SIZE;
    uint32 eid = id % PART_GROUP_SIZE;
    dc_context_t *dc_ctx = &session->kernel->dc_ctx;

    if (dc_alloc_subpart_lob_group(session, entity, lob, gid) != CT_SUCCESS) {
        return CT_ERROR;
    }

    lob_part_t *subpart = NULL;
    lob_part_group_t *group = lob->part_lob->sub_groups[gid];
    if (group->entity[eid] == NULL) {
        if (dc_alloc_mem(dc_ctx, entity->memory, sizeof(lob_part_t), (void **)&subpart) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_DC_BUFFER_FULL);
            return CT_ERROR;
        }

        errno_t ret = memset_sp(subpart, sizeof(lob_part_t), 0, sizeof(lob_part_t));
        knl_securec_check(ret);
        subpart->desc.entry = INVALID_PAGID;
        group->entity[eid] = subpart;
        dls_init_latch2(&subpart->lob_entity.seg_latch, DR_TYPE_LOB_PART_LATCH, lob->desc.table_id, lob->desc.uid,
                        lob->desc.column_id, subpart->part_no, subpart->parent_partno, 0);
    }

    return CT_SUCCESS;
}

status_t dc_init_lob_subpart(knl_session_t *session, dc_entity_t *entity, lob_t *lob, lob_part_t *compart,
    knl_lob_part_desc_t *desc, uint32 *pos)
{
    uint32 real_pos = 0;
    table_t *table = &entity->table;
    table_part_t *table_compart = TABLE_GET_PART(table, compart->part_no);
    table_part_t *table_subpart = NULL;
    for (uint32 i = 0; i < table_compart->desc.subpart_cnt; i++) {
        table_subpart = PART_GET_SUBENTITY(table->part_table, table_compart->subparts[i]);
        if (table_subpart->desc.part_id == desc->part_id) {
            desc->is_not_ready = table_subpart->desc.not_ready;
            real_pos = table_subpart->global_partno;
            break;
        }
    }

    if (dc_alloc_lob_subpart(session, entity, lob, real_pos) != CT_SUCCESS) {
        return CT_ERROR;
    }
    
    lob_part_t *subpart = PART_GET_SUBENTITY(lob->part_lob, real_pos);
    errno_t ret = memcpy_sp(&subpart->desc, sizeof(knl_lob_part_desc_t), desc, sizeof(knl_lob_part_desc_t));
    knl_securec_check(ret);
    subpart->part_no = table_subpart->part_no;
    subpart->parent_partno = compart->part_no;
    subpart->global_partno = real_pos;
    subpart->lob_entity.entry = desc->entry;
    subpart->lob_entity.lob = lob;
    *pos = real_pos;

    return CT_SUCCESS;
}

static status_t dc_load_lob_subpart(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity,
    lob_part_t *lob_compart, uint32 *part_pos)
{
    knl_lob_part_desc_t desc;
    table_t *table = &entity->table;

    knl_column_t *lob_column = dc_get_column(entity, lob_compart->desc.column_id);
    knl_panic_log(COLUMN_IS_LOB(lob_column) || KNL_COLUMN_IS_ARRAY(lob_column),
                  "the lob_column is neither lob nor array, panic info: page %u-%u type %u table %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, table->desc.name);
    lob_t *lob = (lob_t *)lob_column->lob;

    dc_convert_lob_part_desc(cursor, &desc);
    desc.parent_partid = lob_compart->desc.part_id;

    if (IS_NOLOGGING_BY_TABLE_TYPE(table->desc.type) && entity->entry->need_empty_entry) {
        desc.entry = INVALID_PAGID;
        if (dc_reset_nologging_entry(session, (knl_handle_t)&desc, OBJ_TYPE_LOB_SUBPART) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (dc_init_lob_subpart(session, entity, lob, lob_compart, &desc, part_pos) != CT_SUCCESS) {
        return CT_ERROR;
    }

    lob_part_t *subpart = PART_GET_SUBENTITY(lob->part_lob, *part_pos);
    dc_load_lob_part_segment(session, entity, subpart, lob);

    return CT_SUCCESS;
}

static status_t dc_load_sublobparts_of_compart(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity,
    lob_t *lob, lob_part_t *compart)
{
    uint32 subpart_ind = 0;
    uint32 subpart_pos = CT_INVALID_ID32;
    
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_SUB_LOB_PARTS_ID, IX_SYS_LOBSUBPART001_ID);
    knl_init_index_scan(cursor, CT_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &lob->desc.uid,
        sizeof(uint32), IX_COL_SYS_LOBSUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &lob->desc.table_id,
        sizeof(uint32), IX_COL_SYS_LOBSUBPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &compart->desc.part_id,
        sizeof(uint32), IX_COL_SYS_LOBSUBPART001_PARENT_PART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &lob->desc.column_id,
        sizeof(uint32), IX_COL_SYS_LOBSUBPART001_COLUMN_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_LOBSUBPART001_SUB_PART_ID);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, &lob->desc.uid,
        sizeof(uint32), IX_COL_SYS_LOBSUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, &lob->desc.table_id,
        sizeof(uint32), IX_COL_SYS_LOBSUBPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, &compart->desc.part_id,
        sizeof(uint32), IX_COL_SYS_LOBSUBPART001_PARENT_PART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, &lob->desc.column_id,
        sizeof(uint32), IX_COL_SYS_LOBSUBPART001_COLUMN_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_LOBSUBPART001_SUB_PART_ID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        return CT_ERROR;
    }

    while (!cursor->eof) {
        if (dc_load_lob_subpart(session, cursor, entity, compart, &subpart_pos) != CT_SUCCESS) {
            return CT_ERROR;
        }

        CT_LOG_DEBUG_INF("load lob subpart from lobsubpart$, uid: %d, tid: %d, column id: %d, ppart_id: %d",
            lob->desc.uid, lob->desc.table_id, lob->desc.column_id, compart->desc.part_id);
        compart->subparts[subpart_ind] = subpart_pos;
        subpart_ind++;
        
        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    knl_panic_log(subpart_ind == compart->desc.subpart_cnt, "the subpart_ind is not equal to subpart count, panic "
                  "info: page %u-%u type %u subpart_ind %u subpart_cnt %u table %s index %s", cursor->rowid.file,
                  cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, subpart_ind, compart->desc.subpart_cnt,
                  ((table_t *)cursor->table)->desc.name, ((index_t *)cursor->index)->desc.name);
    return CT_SUCCESS;
}

status_t dc_load_lob_subparts(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity, lob_t *lob)
{
    table_t *table = &entity->table;
    lob_part_t *compart = NULL;
    table_part_t *table_part = NULL;

    uint32 part_cnt = table->part_table->desc.partcnt + table->part_table->desc.not_ready_partcnt;
    for (uint32 i = 0; i < part_cnt; i++) {
        table_part = TABLE_GET_PART(table, i);
        compart = LOB_GET_PART(lob, i);
        if (!IS_READY_PART(table_part) || compart == NULL) {
            continue;
        }

        knl_panic_log(IS_PARENT_LOBPART(&compart->desc),
                      "the compart is not parent lobpart, panic info: page %u-%u type %u table %s table_part %s",
                      cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                      table->desc.name, table_part->desc.name);
        if (dc_load_sublobparts_of_compart(session, cursor, entity, lob, compart) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t dc_init_interval_subidxpart(knl_session_t *session, knl_cursor_t *cursor, index_t *index,
    index_part_t *compart_index, bool32 is_shadow)
{
    dc_entity_t *entity = index->entity;
    table_t *table = &entity->table;

    index_part_t *subpart = PART_GET_SUBENTITY(index->part_index, compart_index->subparts[0]);
    knl_index_part_desc_t *desc = &subpart->desc;
    uint32 subpart_keys = table->part_table->desc.subpartkeys;
    if (part_convert_index_part_desc(session, cursor, entity, subpart_keys, desc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (is_shadow) {
        desc->parent_partid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SHADOW_INDEXPART_COL_SUBPART_CNT);
    }
    subpart->part_no = 0;
    subpart->global_partno = compart_index->subparts[0];
    subpart->parent_partno = compart_index->part_no;
    subpart->desc.cr_mode = index->desc.cr_mode;
    subpart->btree.entry = desc->entry;
    subpart->btree.index = index;
    subpart->btree.is_shadow = is_shadow;
    dls_init_latch2(&subpart->btree.struct_latch, DR_TYPE_BRTEE_PART_LATCH, subpart->desc.table_id, subpart->desc.uid,
                    subpart->desc.index_id, subpart->part_no, subpart->parent_partno, subpart->btree.is_shadow);

    dc_subpart_index_insert_name(index->part_index, subpart);
    dc_user_t *user = session->kernel->dc_ctx.users[entity->table.desc.uid];
    if (spc_valid_space_object(session, desc->space_id)) {
        if (!IS_INVALID_PAGID(desc->entry)) {
            if (buf_read_page(session, subpart->desc.entry, LATCH_MODE_S, ENTER_PAGE_RESIDENT) != CT_SUCCESS) {
                entity->corrupted = CT_TRUE;
                CT_LOG_RUN_ERR("[DC CORRUPTED] could not load index partition %s of table %s.%s, segment corrupted",
                    desc->name, user->desc.name, entity->table.desc.name);
            } else {
                page_head_t *head = (page_head_t *)CURR_PAGE(session);
                subpart->btree.segment = BTREE_GET_SEGMENT(session);
                subpart->btree.buf_ctrl = session->curr_page_ctrl;
                if (head->type == PAGE_TYPE_BTREE_HEAD && subpart->btree.segment->org_scn == desc->org_scn) {
                    subpart->btree.cipher_reserve_size = SPACE_GET(session, desc->space_id)->ctrl->cipher_reserve_size;
                    desc->seg_scn = subpart->btree.segment->seg_scn;
                    bt_put_change_stats(&subpart->btree);
                } else {
                    entity->corrupted = CT_TRUE;
                    CT_LOG_RUN_ERR("[DC CORRUPTED] could not load index partition %s of table %s.%s, segment corrupted",
                        desc->name, user->desc.name, entity->table.desc.name);
                }
                buf_leave_page(session, CT_FALSE);
            }
        }
    } else {
        entity->corrupted = CT_TRUE;
        CT_LOG_RUN_ERR("[DC CORRUPTED] could not load index partition %s of table %s.%s, tablespace %s is offline",
            desc->name, user->desc.name, entity->table.desc.name, SPACE_GET(session, desc->space_id)->ctrl->name);
    }

    return CT_SUCCESS;
}

status_t dc_load_interval_index_subpart(knl_session_t *session, knl_cursor_t *cursor, index_t *index,
    index_part_t *compart_index, bool32 is_shadow)
{
    uint32 subpart_id = CT_DFT_PARTID_STEP;
    uint32 parentpart_id = compart_index->desc.part_id;

    if (is_shadow) {
        knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_SHADOW_INDEXPART_ID, IX_SYS_SHW_INDEXPART001_ID);
        knl_init_index_scan(cursor, CT_TRUE);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &index->desc.uid,
            sizeof(uint32), IX_COL_SYS_SHW_INDEXPART001_USER_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &index->desc.table_id,
            sizeof(uint32), IX_COL_SYS_SHW_INDEXPART001_TABLE_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &index->desc.id,
            sizeof(uint32), IX_COL_SYS_SHW_INDEXPART001_INDEX_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &subpart_id,
            sizeof(uint32), IX_COL_SYS_SHW_INDEXPART001_PART_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &parentpart_id,
            sizeof(uint32), IX_COL_SYS_SHW_INDEXPART001_PARENTPART_ID);
    } else {
        knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_SUB_INDEX_PARTS_ID, IX_SYS_INDEXSUBPART001_ID);
        knl_init_index_scan(cursor, CT_TRUE);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &index->desc.uid,
            sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_USER_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &index->desc.table_id,
            sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_TABLE_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &index->desc.id,
            sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_INDEX_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &parentpart_id,
            sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_PARENT_PART_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &subpart_id,
            sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_SUB_PART_ID);
    }

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        return CT_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s index %s index_compart %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                  ((table_t *)cursor->table)->desc.name, index->desc.name, compart_index->desc.name);
    if (dc_init_interval_subidxpart(session, cursor, index, compart_index, is_shadow) != CT_SUCCESS) {
        return CT_SUCCESS;
    }

    index->part_index->desc.subpart_cnt++;
    return CT_SUCCESS;
}

status_t dc_load_interval_lob_subpart(knl_session_t *session, knl_dictionary_t *dc, knl_cursor_t *cursor,
    lob_t *lob, lob_part_t *compart_lob)
{
    dc_entity_t *entity = DC_ENTITY(dc);
    table_t *table = &entity->table;
    uint32 subpart_id = CT_DFT_PARTID_STEP;
    uint32 parentpart_id = compart_lob->desc.part_id;
    knl_lob_part_desc_t *comdesc = &compart_lob->desc;
    
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_SUB_LOB_PARTS_ID, IX_SYS_LOBSUBPART001_ID);
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &comdesc->uid,
        sizeof(uint32), IX_COL_SYS_LOBSUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &comdesc->table_id,
        sizeof(uint32), IX_COL_SYS_LOBSUBPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &parentpart_id,
        sizeof(uint32), IX_COL_SYS_LOBSUBPART001_PARENT_PART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &comdesc->column_id,
        sizeof(uint32), IX_COL_SYS_LOBSUBPART001_COLUMN_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &subpart_id,
        sizeof(uint32), IX_COL_SYS_LOBSUBPART001_SUB_PART_ID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        return CT_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s index %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, table->desc.name,
                  ((index_t *)cursor->index)->desc.name);
    lob_part_t *subpart = PART_GET_SUBENTITY(lob->part_lob, compart_lob->subparts[0]);
    dc_convert_lob_part_desc(cursor, &subpart->desc);
    subpart->desc.parent_partid = compart_lob->desc.part_id;
    subpart->part_no = 0;
    subpart->global_partno = compart_lob->subparts[0];
    subpart->parent_partno = compart_lob->part_no;
    subpart->lob_entity.entry = subpart->desc.entry;
    subpart->lob_entity.lob = lob;
    dls_init_latch2(&subpart->lob_entity.seg_latch, DR_TYPE_LOB_PART_LATCH, lob->desc.table_id, lob->desc.uid,
                    lob->desc.column_id, subpart->part_no, subpart->parent_partno, 0);

    if (!spc_valid_space_object(session, subpart->desc.space_id)) {
        entity->corrupted = CT_TRUE;
        dc_user_t *user = session->kernel->dc_ctx.users[table->desc.uid];
        CT_LOG_RUN_ERR("[DC CORRUPTED] could not load lob partition of column %s of table %s.%s, tablespace %s is offline",
            dc_get_column(entity, lob->desc.column_id)->name, user->desc.name, table->desc.name,
            SPACE_GET(session, lob->desc.space_id)->ctrl->name);
    }
    
    subpart->lob_entity.cipher_reserve_size = SPACE_GET(session, subpart->desc.space_id)->ctrl->cipher_reserve_size;
    return CT_SUCCESS;
}

static status_t dc_init_interval_subtabpart(knl_session_t *session, dc_entity_t *entity, knl_cursor_t *cursor,
    table_part_t *compart_tab)
{
    table_t *table = &entity->table;
    table_part_t *subpart = PART_GET_SUBENTITY(table->part_table, compart_tab->subparts[0]);
    uint32 *subaprt_no = &PART_GET_SUBPARTNO(table->part_table, compart_tab->subparts[0]);
    uint32 subpart_keys = table->part_table->desc.subpartkeys;
    if (dc_get_table_part_desc(session, cursor, entity, subpart_keys, &subpart->desc, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    subpart->part_no = 0;
    subpart->global_partno = compart_tab->subparts[0];
    subpart->parent_partno = compart_tab->part_no;
    subpart->heap.entry = subpart->desc.entry;
    subpart->heap.table = table;
    subpart->desc.cr_mode = table->desc.cr_mode;
    *subaprt_no = subpart->global_partno;

    dc_subpart_table_insert_name(table->part_table, subpart);
    
    if (!spc_valid_space_object(session, subpart->desc.space_id)) {
        entity->corrupted = CT_TRUE;
        dc_user_t *user = session->kernel->dc_ctx.users[table->desc.uid];
        CT_LOG_RUN_ERR("[DC CORRUPTED] could not load table partition %s of table %s.%s, tablespace %s is offline",
            subpart->desc.name, user->desc.name, table->desc.name,
            SPACE_GET(session, subpart->desc.space_id)->ctrl->name);
    }
    
    subpart->heap.cipher_reserve_size = SPACE_GET(session, subpart->desc.space_id)->ctrl->cipher_reserve_size;
    subpart->is_ready = CT_TRUE;
    dls_init_spinlock2(&subpart->heap.lock, DR_TYPE_HEAP_PART, subpart->desc.table_id, subpart->desc.uid,
                       subpart->desc.part_id, subpart->part_no, subpart->parent_partno);
    dls_init_latch2(&subpart->heap.latch, DR_TYPE_HEAP_PART_LATCH, subpart->desc.table_id, subpart->desc.uid,
                    subpart->desc.part_id, subpart->part_no, subpart->parent_partno, 0);

    if (table->part_table->desc.subparttype == PART_TYPE_LIST) {
        if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, sizeof(list_item_t) * subpart->desc.groupcnt,
            (void **)&subpart->lnext) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_DC_BUFFER_FULL);
            return CT_ERROR;
        }

        dc_subpart_table_insert_list(table->part_table, subpart, table->part_table->desc.subpartkeys);
    }

    return CT_SUCCESS;
}

status_t dc_load_interval_table_subpart(knl_session_t *session, knl_dictionary_t *dc, knl_cursor_t *cursor,
    table_part_t *compart_tab)
{
    dc_entity_t *entity = DC_ENTITY(dc);
    uint32 subpart_id = CT_DFT_PARTID_STEP;
    uint32 parentpart_id = compart_tab->desc.part_id;
    knl_table_part_desc_t *comdesc = &compart_tab->desc;
    
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_SUB_TABLE_PARTS_ID, IX_SYS_TABLESUBPART001_ID);
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &comdesc->uid,
        sizeof(uint32), IX_COL_SYS_TABLESUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &comdesc->table_id,
        sizeof(uint32), IX_COL_SYS_TABLESUBPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &parentpart_id,
        sizeof(uint32), IX_COL_SYS_TABLESUBPART001_PARENT_PART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &subpart_id,
        sizeof(uint32), IX_COL_SYS_TABLESUBPART001_SUB_PART_ID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        return CT_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s index %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                  ((table_t *)cursor->table)->desc.name, ((index_t *)cursor->index)->desc.name);

    if (dc_init_interval_subtabpart(session, entity, cursor, compart_tab) != CT_SUCCESS) {
        return CT_ERROR;
    }
    
    return CT_SUCCESS;
}
