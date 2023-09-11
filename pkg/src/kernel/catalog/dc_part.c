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
 * dc_part.c
 *
 *
 * IDENTIFICATION
 * src/kernel/catalog/dc_part.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_dc.h"
#include "knl_session.h"
#include "knl_context.h"
#include "ostat_load.h"
#include "knl_space_base.h"
#include "knl_table.h"
#include "dc_subpart.h"
#include "index_common.h"
#include "knl_sys_part_defs.h"
#include "index_common.h"
#include "dtc_dls.h"

uint32 dc_cal_list_value_hash(const text_t *values, uint32 count)
{
    uint32 val;
    val = cm_hash_multi_text(values, count, INFINITE_HASH_RANGE);
    return val % (LIST_PART_HASH_SIZE - 1);
}

static uint64 part_sort_get_scn(part_table_t *part_table, uint32 part_no)
{
    table_part_t *entity = NULL;

    if (part_no != GS_INVALID_ID32) {
        entity = PART_GET_ENTITY(part_table, part_no);
        return entity->desc.org_scn;
    }

    return GS_INVALID_ID64;
}

void dc_partno_swap(uint32 *a, uint32 *b)
{
    uint32 temp;

    temp = *a;
    *a = *b;
    *b = temp;
}

void dc_partno_sort(part_table_t *part_table)
{
    uint32 *curr_no = NULL;
    uint32 *last_no = NULL;
    uint32 *last_no1 = NULL;
    uint64 curr_scn, last_scn;
    int32 left, right, mid;

    for (uint32 i = 1; i < part_table->desc.real_partcnt; i++) {
        curr_no = &PART_GET_NO(part_table, i);
        curr_scn = part_sort_get_scn(part_table, *curr_no);

        left = 0;
        right = i - 1;
        while (left <= right) {
            mid = (left + right) / 2; // get median of left and right
            curr_no = &PART_GET_NO(part_table, (uint32)mid);
            last_scn = part_sort_get_scn(part_table, *curr_no);
            if (last_scn > curr_scn) {
                right = mid - 1;
            } else {
                left = mid + 1;
            }
        }

        for (int32 j = i - 1; j >= left; j--) {
            last_no = &PART_GET_NO(part_table, (uint32)j);
            last_no1 = &PART_GET_NO(part_table, (uint32)j + 1);
            dc_partno_swap(last_no1, last_no);
        }
    }
}

static uint32 inline dc_get_group_count(knl_part_desc_t *desc)
{
    uint32 group_count = desc->partcnt / PART_GROUP_SIZE;
    uint32 element_count = desc->partcnt % PART_GROUP_SIZE;

    if (element_count != 0) {
        group_count = group_count + 1;
    }
    knl_panic(group_count > 0);
    return group_count;
}

static status_t dc_alloc_partition_hash_buckets(knl_session_t *session, dc_entity_t *entity, knl_part_desc_t *part_desc,
    part_table_t *part_table)
{
    dc_context_t *ctx = &session->kernel->dc_ctx;
    errno_t ret;

    if (dc_alloc_mem(ctx, entity->memory, GS_SHARED_PAGE_SIZE, (void **)&part_table->pbuckets) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_DC_BUFFER_FULL);
        return GS_ERROR;
    }
    ret = memset_sp(part_table->pbuckets, GS_SHARED_PAGE_SIZE, 0xFF, GS_SHARED_PAGE_SIZE);
    knl_securec_check(ret);

    if (part_desc->parttype != PART_TYPE_LIST) {
        return GS_SUCCESS;
    }

    if (dc_alloc_mem(ctx, entity->memory, GS_SHARED_PAGE_SIZE, (void **)&part_table->lbuckets) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_DC_BUFFER_FULL);
        return GS_ERROR;
    }
    ret = memset_sp(part_table->lbuckets, GS_SHARED_PAGE_SIZE, 0xFF, GS_SHARED_PAGE_SIZE);
    knl_securec_check(ret);

    return GS_SUCCESS;
}

static status_t dc_alloc_intval_partition_group(knl_session_t *session, dc_entity_t *entity,
    part_group_t *group)
{
    dc_context_t *dc_ctx = &session->kernel->dc_ctx;
    errno_t ret;

    group->group_cnt = 0;
    if (dc_alloc_mem(dc_ctx, entity->memory, INTERVAL_PART_GROUP_SIZE,
        (void **)&group->group_id) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_DC_BUFFER_FULL);
        return GS_ERROR;
    }
    ret = memset_sp(group->group_id, INTERVAL_PART_GROUP_SIZE, 0XFF, INTERVAL_PART_GROUP_SIZE);
    knl_securec_check(ret);

    if (dc_alloc_mem(dc_ctx, entity->memory, INTERVAL_PART_GROUP_SIZE,
        (void **)&group->group_ready) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_DC_BUFFER_FULL);
        return GS_ERROR;
    }
    ret = memset_sp(group->group_ready, INTERVAL_PART_GROUP_SIZE, 0, INTERVAL_PART_GROUP_SIZE);
    knl_securec_check(ret);

    return GS_SUCCESS;
}

status_t dc_alloc_part_table(knl_session_t *session_ctdb, dc_entity_t *entity_ctdb, knl_part_desc_t *desc,
    part_table_t **part_table_ptr)
{
    part_table_t *part_table = NULL;
    dc_context_t *ctx_ctdb = &session_ctdb->kernel->dc_ctx;
    uint32 group_count = dc_get_group_count(desc);

    if (dc_alloc_mem(ctx_ctdb, entity_ctdb->memory, sizeof(part_table_t), (void **)&part_table) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_DC_BUFFER_FULL);
        return GS_ERROR;
    }

    *part_table_ptr = part_table;
    errno_t ret = memset_sp(part_table, sizeof(part_table_t), 0, sizeof(part_table_t));
    knl_securec_check(ret);
    ret = memcpy_sp(&part_table->desc, sizeof(knl_part_desc_t), desc, sizeof(knl_part_desc_t));
    knl_securec_check(ret);

    uint32 memsize = group_count * sizeof(part_table_ptr);

    // for interval partition
    if (part_table->desc.interval_key != NULL) {
        memsize = GS_SHARED_PAGE_SIZE;
        if (dc_alloc_intval_partition_group(session_ctdb, entity_ctdb, &part_table->part_group) != GS_SUCCESS) { return GS_ERROR; }
    }

    if (dc_alloc_mem(ctx_ctdb, entity_ctdb->memory, memsize, (void **)&part_table->groups) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_DC_BUFFER_FULL);
        return GS_ERROR;
    }
    ret = memset_sp(part_table->groups, memsize, 0, memsize);
    knl_securec_check(ret);

    if (dc_alloc_mem(ctx_ctdb, entity_ctdb->memory, memsize, (void **)&part_table->no_groups) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_DC_BUFFER_FULL);
        return GS_ERROR;
    }
    ret = memset_sp(part_table->no_groups, memsize, 0, memsize);
    knl_securec_check(ret);

    if (dc_alloc_partition_hash_buckets(session_ctdb, entity_ctdb, desc, part_table) != GS_SUCCESS) { return GS_ERROR; }

    if (desc->flags & PART_TABLE_SUBPARTED) {
        if (dc_alloc_subpart_table(session_ctdb, entity_ctdb, part_table) != GS_SUCCESS) { return GS_ERROR; }
    }

    return GS_SUCCESS;
}

static status_t dc_alloc_part_table_group(knl_session_t *session, dc_entity_t *entity, part_table_t *part_table,
                                          uint32 gid)
{
    int32 ret;
    if (part_table->groups[gid] == NULL) {
        if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, sizeof(table_part_group_t),
            (void **)&part_table->groups[gid]) != GS_SUCCESS) {
            GS_THROW_ERROR(ERR_DC_BUFFER_FULL);
            return GS_ERROR;
        }

        ret = memset_sp(part_table->groups[gid], sizeof(table_part_group_t), 0, sizeof(table_part_group_t));
        knl_securec_check(ret);

        if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, sizeof(part_no_group_t),
            (void **)&part_table->no_groups[gid]) != GS_SUCCESS) {
            GS_THROW_ERROR(ERR_DC_BUFFER_FULL);
            return GS_ERROR;
        }

        ret = memset_sp(part_table->no_groups[gid], sizeof(part_no_group_t), 0xFF, sizeof(part_no_group_t));
        knl_securec_check(ret);
    }
    return GS_SUCCESS;
}

status_t part_calc_intval_partition_group(knl_session_t *session, dc_entity_t *entity, uint32 *group_count,
    uint32 *groupid, uint32 *gid)
{
    if (groupid[*gid] != GS_INVALID_ID32) {
        *gid = groupid[*gid];
        return GS_SUCCESS;
    }

    groupid[*gid] = *group_count;
    *gid = *group_count;
    (*group_count)++;

    return GS_SUCCESS;
}

status_t dc_alloc_table_part(knl_session_t *session, dc_entity_t *entity, part_table_t *part_table, uint32 id)
{
    table_part_group_t *group = NULL;
    table_part_t *part = NULL;
    uint32 gid, eid, table_size;
    errno_t ret;

    gid = id / PART_GROUP_SIZE;
    eid = id % PART_GROUP_SIZE;
    if (!PART_CONTAIN_INTERVAL(part_table)) {
        if (dc_alloc_part_table_group(session, entity, part_table, gid) != GS_SUCCESS) {
            return GS_ERROR;
        }
    } else {
        if (part_calc_intval_partition_group(session, entity, &part_table->part_group.group_cnt,
            part_table->part_group.group_id, &gid) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (dc_alloc_part_table_group(session, entity, part_table, gid) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (!part_table->part_group.group_ready[gid]) {
            part_table->part_group.group_ready[gid] = GS_TRUE;
        }
    }

    group = part_table->groups[gid];
    if (group->entity[eid] == NULL) {
        if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, sizeof(table_part_t),
            (void **)&part) != GS_SUCCESS) {
            GS_THROW_ERROR(ERR_DC_BUFFER_FULL);
            return GS_ERROR;
        }

        table_size = sizeof(table_part_t);
        ret = memset_sp(part, table_size, 0, table_size);
        knl_securec_check(ret);
        part->is_ready = GS_FALSE;
        part->desc.entry = INVALID_PAGID;
        group->entity[eid] = part;
    }
    return GS_SUCCESS;
}

uint32 dc_cal_part_name_hash(text_t *name)
{
    uint32 val;
    val = cm_hash_text(name, INFINITE_HASH_RANGE);
    return val % PART_NAME_HASH_SIZE;
}

void dc_part_table_insert_name(part_table_t *part_table, table_part_t *part)
{
    part_bucket_t *bucket = NULL;
    uint32 hash;
    text_t name;

    cm_str2text(part->desc.name, &name);
    hash = dc_cal_part_name_hash(&name);
    bucket = &part_table->pbuckets[hash];

    part->pnext = bucket->first;
    bucket->first = part->part_no;
}

static void part_index_insert_name(part_index_t *part_index, index_part_t *part)
{
    part_bucket_t *bucket = NULL;
    uint32 hash;
    text_t name;
    cm_str2text(part->desc.name, &name);
    hash = dc_cal_part_name_hash(&name);
    bucket = &part_index->pbuckets[hash];
    part->pnext = bucket->first;
    bucket->first = part->part_no;
}

static status_t part_init_decoders(knl_session_t *session, dc_entity_t *entity, part_decode_key_t *decoders,
    uint32 partkeys, part_key_t *key, uint16 count)
{
    uint8 bits;
    uint16 i, j;
    uint16 id = 0;
    uint16 pos, ex_maps;

    ex_maps = PART_BITMAP_EX_SIZE(key->column_count);
    pos = sizeof(part_key_t) + ex_maps;

    for (i = 0; i < count; i++) {
        if (decoders[i].offsets == NULL) {
            if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, sizeof(uint16) * partkeys,
                (void **)&decoders[i].offsets) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        if (decoders[i].lens == NULL) {
            if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, sizeof(uint16) * partkeys,
                (void **)&decoders[i].lens) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        decoders[i].count = partkeys;
        decoders[i].buf = (char *)key;

        for (j = 0; j < partkeys; j++) {
            bits = part_get_key_bits(key, id);
            knl_panic_log(bits != PART_KEY_BITS_MIN, "curr bits is the min value, panic info: table %s",
                          entity->table.desc.name);
            decoders[i].offsets[j] = pos;

            if (bits == PART_KEY_BITS_8) {
                decoders[i].lens[j] = PART_KEY_BITS_8_LEN;
                pos += PART_KEY_BITS_8_LEN;
            } else if (bits == PART_KEY_BITS_4) {
                decoders[i].lens[j] = PART_KEY_BITS_4_LEN;
                pos += PART_KEY_BITS_4_LEN;
            } else if (bits == PART_KEY_BITS_NULL) {
                decoders[i].lens[j] = PART_KEY_NULL_LEN;
            } else if (bits == PART_KEY_BITS_DEFAULT) {
                decoders[i].lens[j] = PART_KEY_DEFAULT_LEN;
            } else if (bits == PART_KEY_BITS_MAX) {
                decoders[i].lens[j] = PART_KEY_MAX_LEN;
            } else {
                decoders[i].lens[j] = *(uint16 *)((char *)key + pos);
                decoders[i].offsets[j] += sizeof(uint16);
                pos += CM_ALIGN4(decoders[i].lens[j] + sizeof(uint16));
            }

            id++;
        }
    }
    return GS_SUCCESS;
}

static status_t part_decode_key_interval(knl_session_t *session, dc_entity_t *entity, part_key_t *key,
    part_decode_key_t **interval_key)
{
    part_decode_key_t *decoders = NULL;
    status_t status;

    CM_POINTER3(entity, key, interval_key);

    if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, sizeof(part_decode_key_t),
        (void **)&decoders) != GS_SUCCESS) {
        return GS_ERROR;
    }

    errno_t ret = memset_sp(decoders, sizeof(part_decode_key_t), 0, sizeof(part_decode_key_t));
    knl_securec_check(ret);
    *interval_key = decoders;

    status = part_init_decoders(session, entity, decoders, 1, key, 1);

    return status;
}

static status_t part_get_interval_spc_count(knl_session_t *session, knl_cursor_t *cursor, table_t *table,
    uint32 *spc_num)
{
    uint32 index_id;
    index_id = GS_INVALID_ID32;

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_PARTSTORE_ID, IX_SYS_PARTSTORE001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &table->desc.uid,
        sizeof(uint32), IX_COL_SYS_PARTSTORE001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &table->desc.id,
        sizeof(uint32), IX_COL_SYS_PARTSTORE001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &index_id, sizeof(uint32),
        IX_COL_SYS_PARTSTORE001_INDEX_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    while (!cursor->eof) {
        (*spc_num)++;

        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

void dc_part_convert_column_desc(knl_cursor_t *cursor, knl_part_column_desc_t *desc)
{
    desc->uid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_PARTCOLUMN_COL_USER_ID);
    desc->table_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_PARTCOLUMN_COL_TABLE_ID);
    desc->column_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_PARTCOLUMN_COL_COLUMN_ID);
    desc->pos_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_PARTCOLUMN_COL_POSITION);
    desc->datatype = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_PARTCOLUMN_COL_DATATYPE);
}

static status_t part_convert_part_object_desc(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity,
    knl_part_desc_t *desc)
{
    uint32 spc_num = 0;
    int32 ret;

    ret = memset_sp(desc, sizeof(knl_part_desc_t), 0, sizeof(knl_part_desc_t));
    knl_securec_check(ret);
    desc->uid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_PARTOBJECT_COL_USER_ID);
    desc->table_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_PARTOBJECT_COL_TABLE_ID);
    desc->index_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_PARTOBJECT_COL_INDEX_ID);
    desc->parttype = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_PARTOBJECT_COL_PARTTYPE);
    desc->subparttype = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_PARTOBJECT_COL_SUBPARTTYPE);
    desc->partcnt = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_PARTOBJECT_COL_PARTCNT);
    desc->partkeys = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_PARTOBJECT_COL_PARTKEYS);
    desc->subpartkeys = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_PARTOBJECT_COL_SUBPARTKEYS);
    desc->flags = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_PARTOBJECT_COL_FLAGS);
    if (CURSOR_COLUMN_SIZE(cursor, SYS_PARTOBJECT_COL_IS_SLICE) != GS_NULL_VALUE_LEN) {
        desc->is_slice = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_PARTOBJECT_COL_IS_SLICE);
    }

    if (dc_copy_column_data(session, cursor, entity, SYS_PARTOBJECT_COL_INTERVAL, &desc->interval, GS_FALSE) !=
        GS_SUCCESS) {
        return GS_ERROR;
    }

    if (dc_copy_column_data(session, cursor, entity, SYS_PARTOBJECT_COL_BINTERVAL, &desc->binterval, GS_FALSE) !=
        GS_SUCCESS) {
        return GS_ERROR;
    }

    if (desc->binterval.size != 0) {
        if (part_decode_key_interval(session, entity, (part_key_t *)desc->binterval.bytes,
            &desc->interval_key) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (part_get_interval_spc_count(session, cursor, &entity->table, &spc_num) != GS_SUCCESS) {
            return GS_ERROR;
        }

        desc->interval_spc_num = spc_num;
    } else {
        desc->interval_key = NULL;
    }

    return GS_SUCCESS;
}

static status_t dc_init_table_part(knl_session_t *session, dc_entity_t *entity, table_t *table,
    knl_table_part_desc_t *desc, table_part_t **part, uint32 start_pos)
{
    part_table_t *part_table = table->part_table;
    uint32 *partnos = NULL;

    if (dc_alloc_table_part(session, entity, part_table, start_pos) != GS_SUCCESS) {
        return GS_ERROR;
    }
        
    *part = PART_GET_ENTITY(part_table, start_pos);
    partnos = &PART_GET_NO(part_table, table->part_table->desc.real_partcnt);
    errno_t ret = memcpy_sp(&(*part)->desc, sizeof(knl_table_part_desc_t), desc, sizeof(knl_table_part_desc_t));
    knl_securec_check(ret);
    (*part)->part_no = start_pos;
    (*part)->parent_partno = GS_INVALID_ID32;
    (*part)->global_partno = GS_INVALID_ID32;
    *partnos = (*part)->part_no;
    (*part)->desc.cr_mode = table->desc.cr_mode;

    if (IS_PARENT_TABPART(desc)) {
        if (dc_alloc_table_subparts(session, entity, *part) != GS_SUCCESS) {
            return GS_ERROR;
        }
    } else {
        (*part)->heap.entry = desc->entry;
        (*part)->heap.table = table;
        (*part)->heap.max_pages = desc->storage_desc.max_pages;
        dls_init_spinlock2(&(*part)->heap.lock, DR_TYPE_HEAP_PART, desc->table_id,
                           desc->uid, desc->part_id, (*part)->part_no, (*part)->parent_partno);
        dls_init_latch2(&(*part)->heap.latch, DR_TYPE_HEAP_PART_LATCH, desc->table_id,
                        desc->uid, desc->part_id, (*part)->part_no, (*part)->parent_partno);
    }

    dc_part_table_insert_name(part_table, *part);

    return GS_SUCCESS;
}

static status_t dc_handle_spliting_part(knl_session_t *session, table_t *table, uint32 count,
    dc_entity_t *entity, knl_table_part_desc_t *desc, table_part_t **part)
{
    // this count includes the "not ready" partition
    uint32 total_pcnt;
    uint32 start_pos;
    part_table_t *part_table = table->part_table;

    total_pcnt = part_table->desc.partcnt;
    start_pos = total_pcnt - count - 1;
    // put the not ready part at the tail
    if (dc_init_table_part(session, entity, table, desc, part, start_pos) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t dc_load_part_columns(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity)
{
    knl_part_column_desc_t desc;
    table_t *table = &entity->table;
    part_table_t *part_table = table->part_table;
    uint32 memsize = sizeof(knl_part_column_desc_t) * part_table->desc.partkeys;
    
    if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, memsize, (void **)&part_table->keycols) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_DC_BUFFER_FULL);
        return GS_ERROR;
    }

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_PARTCOLUMN_ID, IX_SYS_PARTCOLUMN001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &table->desc.uid,
        sizeof(uint32), IX_COL_SYS_PARTCOLUMN001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &table->desc.id,
        sizeof(uint32), IX_COL_SYS_PARTCOLUMN001_TABLE_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    while (!cursor->eof) {
        dc_part_convert_column_desc(cursor, &desc);

        knl_panic_log(desc.pos_id < part_table->desc.partkeys, "the pos_id is not smaller than partkeys, panic info: "
                      "page %u-%u type %u table %s index %s pos_id %u partkeys %u", cursor->rowid.file,
                      cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, table->desc.name,
                      ((index_t *)cursor->index)->desc.name, desc.pos_id, part_table->desc.partkeys);
        part_table->keycols[desc.pos_id] = desc;

        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t part_init_decoder(knl_session_t *session, dc_entity_t *entity, part_decode_key_t *decoders,
    part_key_t *key)
{
    uint8 bits;
    uint16 pos, ex_maps;

    ex_maps = PART_BITMAP_EX_SIZE(key->column_count);
    pos = sizeof(part_key_t) + ex_maps;

    if (decoders->offsets == NULL) {
        if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, sizeof(uint16),
            (void **)&decoders->offsets) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }
    
    if (decoders->lens == NULL) {
        if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, sizeof(uint16),
            (void **)&decoders->lens) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    decoders->count = 1;
    decoders->buf = (char *)key;

    bits = part_get_key_bits(key, 0);
    knl_panic_log(bits == PART_KEY_BITS_DEFAULT, "curr bits is not default value, panic info: table %s bits %u",
                  entity->table.desc.name, bits);

    decoders->offsets[0] = pos;
    decoders->lens[0] = PART_KEY_DEFAULT_LEN;

    return GS_SUCCESS;
}

/*
 * decode part key into decoder group
 * @note default partition should be the last partition in list
 */
status_t dc_decode_part_key_group(knl_session_t *session, dc_entity_t *entity, uint32 partkeys,
    part_key_t *key, part_decode_key_t **groups, uint32 *groupcnt)
{
    part_decode_key_t *decoders = NULL;
    status_t status;

    CM_POINTER4(entity, key, groups, groupcnt);
    knl_panic_log(key->column_count < GS_MAX_COLUMNS, "the column_count is reaching the maximum, panic info: "
                  "table %s column_count %u", entity->table.desc.name, key->column_count);

    uint16 count = key->column_count / partkeys;
    uint16 remained = key->column_count % partkeys;
    knl_panic_log(remained <= 1, "remained is bigger than 1, panic info: table %s remained %u",
                  entity->table.desc.name, remained);
    *groupcnt = count + remained;

    if (*groups == NULL) {
        uint32 mem_size = sizeof(part_decode_key_t) * (*groupcnt);
        if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, mem_size, (void **)&decoders) != GS_SUCCESS) {
            return GS_ERROR;
        }

        *groups = decoders;
        errno_t ret = memset_sp(decoders, mem_size, 0, mem_size);
        knl_securec_check(ret);
    } else {
        decoders = *groups;
    }

    if (remained == 1) {
        // remained must be default list partition
        knl_panic_log(key->column_count == 1, "column_count is not equal to 1, panic info: table %s column_count %u",
                      entity->table.desc.name, key->column_count);
        status = part_init_decoder(session, entity, decoders, key);
        return status;
    }

    status = part_init_decoders(session, entity, decoders, partkeys, key, count);

    return status;
}


status_t dc_get_tablepart_storage_desc(knl_session_t *session, dc_entity_t* entity, knl_table_part_desc_t *part_desc)
{
    errno_t err;
    knl_table_desc_t *table_desc = &entity->table.desc;

    err = memset_sp(&part_desc->storage_desc, sizeof(knl_storage_desc_t), 0, sizeof(knl_storage_desc_t));
    knl_securec_check(err);

    if (!part_desc->storaged) {
        part_desc->storage_desc.max_pages = table_desc->storage_desc.max_pages;
        part_desc->storage_desc.initial = table_desc->storage_desc.initial;
        return GS_SUCCESS;
    }

    if (db_get_storage_desc(session, &part_desc->storage_desc, part_desc->org_scn) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (part_desc->storage_desc.initial == 0 && table_desc->storage_desc.initial != 0) {
        part_desc->storage_desc.initial = table_desc->storage_desc.initial;
    }

    if (part_desc->storage_desc.max_pages == 0 && table_desc->storage_desc.max_pages != 0) {
        part_desc->storage_desc.max_pages = table_desc->storage_desc.max_pages;
    }
    
    return GS_SUCCESS;
}

status_t dc_get_table_part_desc(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity,
    uint32 partkeys, knl_table_part_desc_t *desc, bool32 is_reserved)
{
    part_key_t *key = NULL;

    dc_convert_table_part_desc(cursor, desc);

    if (dc_get_tablepart_storage_desc(session, entity, desc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (desc->compress) {
        if (db_get_compress_algo(session, &desc->compress_algo, desc->org_scn) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    // skip convert hiboundval lens
    if (dc_copy_column_data(session, cursor, entity, SYS_TABLEPART_COL_HIBOUNDVAL, &desc->hiboundval, is_reserved) !=
        GS_SUCCESS) {
        return GS_ERROR;
    }

    if (dc_copy_column_data(session, cursor, entity, SYS_TABLEPART_COL_BHIBOUNDVAL, &desc->bhiboundval, is_reserved) !=
        GS_SUCCESS) {
        return GS_ERROR;
    }

    if (desc->bhiboundval.size != 0) {
        key = (part_key_t *)desc->bhiboundval.bytes;

        if (dc_decode_part_key_group(session, entity, partkeys, key, &desc->groups, &desc->groupcnt) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static void part_table_insert_list(part_table_t *part_table, table_part_t *part, uint32 partkeys)
{
    list_bucket_t *bucket = NULL;
    part_decode_key_t *decoder = NULL;
    text_t values[GS_MAX_PARTKEY_COLUMNS];
    uint32 hash;
    uint32 i, j;
    bool32 is_default = GS_FALSE;

    for (i = 0; i < part->desc.groupcnt; i++) {
        decoder = &part->desc.groups[i];
        is_default = GS_FALSE;

        for (j = 0; j < decoder->count; j++) {
            values[j].str = decoder->buf + decoder->offsets[j];

            if (decoder->lens[j] == PART_KEY_DEFAULT_LEN) {
                is_default = GS_TRUE;
            } else if (decoder->lens[j] == PART_KEY_NULL_LEN) {
                values[j].len = 0;
            } else {
                values[j].len = (uint32)decoder->lens[j];
            }
        }

        if (is_default) {
            bucket = &part_table->lbuckets[DEFAULT_PART_LIST];
        } else {
            hash = dc_cal_list_value_hash(values, decoder->count);
            bucket = &part_table->lbuckets[hash];
        }

        part->lnext[i] = bucket->first;
        bucket->first.id = part->part_no;
        bucket->first.offset = i;
    }
}

index_part_t *dc_get_index_part(knl_handle_t dc_entity, uint32 index_id, uint32 part_no)
{
    dc_entity_t *entity;
    table_t *table;
    index_t *index;
    part_index_t *part_index = NULL;

    entity = (dc_entity_t *)dc_entity;
    table = &entity->table;
    index = table->index_set.items[index_id];
    if (!index->desc.parted) {
        return NULL;
    }

    part_index = index->part_index;
    knl_panic_log(part_no < part_index->desc.partcnt, "the part_no is not smaller than part_index's partcnt, "
                  "panic info: table %s index %s part_no %u partcnt %u", table->desc.name, index->desc.name,
                  part_no, part_index->desc.partcnt);

    return PART_GET_ENTITY(part_index, part_no);
}

status_t part_convert_index_part_desc(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity,
    uint32 partkeys, knl_index_part_desc_t *desc)
{
    part_key_t *key = NULL;

    dc_convert_index_part_desc(cursor, desc);

    // skip convert hiboundval lens
    if (dc_copy_column_data(session, cursor, entity, SYS_INDEXPART_COL_HIBOUNDVAL, &desc->hiboundval, GS_FALSE) !=
        GS_SUCCESS) {
        return GS_ERROR;
    }

    if (dc_copy_column_data(session, cursor, entity, SYS_INDEXPART_COL_BHIBOUNDVAL, &desc->bhiboundval, GS_FALSE) !=
        GS_SUCCESS) {
        return GS_ERROR;
    }

    if (desc->bhiboundval.size != 0) {
        key = (part_key_t *)desc->bhiboundval.bytes;

        if (dc_decode_part_key_group(session, entity, partkeys, key, &desc->groups, &desc->groupcnt) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t dc_alloc_part_index(knl_session_t *session, dc_entity_t *entity, knl_part_desc_t *desc,
    part_index_t **pointer)
{
    part_index_t *part_index = NULL;
    dc_context_t *dc_ctx = &session->kernel->dc_ctx;

    if (dc_alloc_mem(dc_ctx, entity->memory, sizeof(part_index_t), (void **)&part_index) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_DC_BUFFER_FULL);
        return GS_ERROR;
    }

    *pointer = part_index;
    errno_t ret = memset_sp(part_index, sizeof(part_index_t), 0, sizeof(part_index_t));
    knl_securec_check(ret);
    ret = memcpy_sp(&part_index->desc, sizeof(knl_part_desc_t), desc, sizeof(knl_part_desc_t));
    knl_securec_check(ret);

    if (part_index->desc.interval_key != NULL) {
        if (dc_alloc_intval_partition_group(session, entity, &part_index->part_group) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (dc_alloc_mem(dc_ctx, entity->memory, GS_SHARED_PAGE_SIZE, (void **)&part_index->groups) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_DC_BUFFER_FULL);
        return GS_ERROR;
    }
    ret = memset_sp(part_index->groups, GS_SHARED_PAGE_SIZE, 0, GS_SHARED_PAGE_SIZE);
    knl_securec_check(ret);

    if (dc_alloc_mem(dc_ctx, entity->memory, GS_SHARED_PAGE_SIZE, (void **)&part_index->pbuckets) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_DC_BUFFER_FULL);
        return GS_ERROR;
    }
    ret = memset_sp(part_index->pbuckets, GS_SHARED_PAGE_SIZE, 0, GS_SHARED_PAGE_SIZE);
    knl_securec_check(ret);
    
    for (uint32 i = 0; i < PART_NAME_HASH_SIZE; i++) {
        part_index->pbuckets[i].first = GS_INVALID_ID32;
    }

    if (IS_COMPART_INDEX(part_index)) {
        if (dc_alloc_subpart_index(session, entity, part_index) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t dc_alloc_part_index_group(knl_session_t *session, dc_entity_t *entity, part_index_t *part_index,
    uint32 gid)
{
    if (part_index->groups[gid] == NULL) {
        if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, sizeof(index_part_group_t),
            (void **)&part_index->groups[gid]) != GS_SUCCESS) {
            GS_THROW_ERROR(ERR_DC_BUFFER_FULL);
            return GS_ERROR;
        }
        errno_t ret = memset_sp(part_index->groups[gid], sizeof(index_part_group_t), 0, sizeof(index_part_group_t));
        knl_securec_check(ret);
    }

    return GS_SUCCESS;
}

status_t dc_alloc_index_part(knl_session_t *session, dc_entity_t *entity, part_index_t *part_index, uint32 id)
{
    part_table_t *part_table = entity->table.part_table;
    index_part_group_t *group = NULL;
    index_part_t *part = NULL;
    uint32 gid;
    uint32 eid;
    uint32 index_size;
    errno_t ret;

    gid = id / PART_GROUP_SIZE;
    eid = id % PART_GROUP_SIZE;
    if (!PART_CONTAIN_INTERVAL(part_table)) {
        if (dc_alloc_part_index_group(session, entity, part_index, gid) != GS_SUCCESS) {
            return GS_ERROR;
        }
    } else {
        if (part_calc_intval_partition_group(session, entity, &part_index->part_group.group_cnt,
            part_index->part_group.group_id, &gid) != GS_SUCCESS) {
            return GS_ERROR;
        }
        
        if (dc_alloc_part_index_group(session, entity, part_index, gid) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (!part_index->part_group.group_ready[gid]) {
            part_index->part_group.group_ready[gid] = GS_TRUE;
        }
    }

    group = part_index->groups[gid];

    if (group->entity[eid] == NULL) {
        if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, sizeof(index_part_t),
            (void **)&group->entity[eid]) != GS_SUCCESS) {
            GS_THROW_ERROR(ERR_DC_BUFFER_FULL);
            return GS_ERROR;
        }

        part = group->entity[eid];
        index_size = sizeof(index_part_t);
        ret = memset_sp(part, index_size, 0, index_size);
        knl_securec_check(ret);
        part->desc.entry = INVALID_PAGID;
    }

    return GS_SUCCESS;
}

static status_t dc_init_index_part(knl_session_t *session, index_t *index, knl_index_part_desc_t *desc,
    index_part_t **index_part, uint32 pos, bool8 is_shadow)
{
    dc_entity_t *entity = NULL;
    part_index_t *part_index = NULL;
    errno_t ret;

    part_index = index->part_index;
    entity = index->entity;

    if (dc_alloc_index_part(session, entity, part_index, pos) != GS_SUCCESS) {
        return GS_ERROR;
    }

    *index_part = PART_GET_ENTITY(part_index, pos);
    ret = memcpy_sp(&(*index_part)->desc, sizeof(knl_index_part_desc_t), desc, sizeof(knl_index_part_desc_t));
    knl_securec_check(ret);
    (*index_part)->part_no = pos;
    (*index_part)->parent_partno = GS_INVALID_ID32;
    (*index_part)->global_partno = GS_INVALID_ID32;
    (*index_part)->desc.cr_mode = index->desc.cr_mode;
    if (IS_PARENT_IDXPART(desc)) {
        if (dc_alloc_index_subparts(session, entity, *index_part) != GS_SUCCESS) {
            return GS_ERROR;
        }
    } else {
        (*index_part)->btree.entry = desc->entry;
        (*index_part)->btree.index = index;
        (*index_part)->btree.is_shadow = is_shadow;
        dls_init_latch2(&(*index_part)->btree.struct_latch, DR_TYPE_BRTEE_PART_LATCH, (*index_part)->desc.table_id,
                        (*index_part)->desc.uid, (*index_part)->desc.index_id, (*index_part)->part_no,
                        (*index_part)->parent_partno);
    }
    
    part_index_insert_name(part_index, *index_part);
    return GS_SUCCESS;
}

static status_t dc_handle_split_index_part(knl_session_t *session, index_t *index, knl_index_part_desc_t *desc,
    index_part_t **index_part, uint32 pos, bool8 is_shadow)
{
    uint32 partcnt;
    table_part_t *table_part = NULL;
    part_table_t *part_table = NULL;
    uint32 not_ready_partcnt;
    table_t *table = NULL;
    dc_entity_t *entity;

    entity = index->entity;
    table = &entity->table;
    part_table = table->part_table;
    partcnt = part_table->desc.partcnt;
    not_ready_partcnt = part_table->desc.not_ready_partcnt;
    bool32 is_splitable = (part_table->desc.parttype == PART_TYPE_RANGE);

    for (uint32 j = 0; j < not_ready_partcnt && is_splitable; j++) {
        table_part = PART_GET_ENTITY(part_table, partcnt + j);
        if (desc->part_id == table_part->desc.part_id) {
            desc->is_not_ready = GS_TRUE;
            break;
        }
    }

    // if includes not ready part, then need to put the not ready part at the tail
    if (desc->is_not_ready) {
        return dc_init_index_part(session, index, desc, index_part, table_part->part_no, is_shadow);
    } else {
        return dc_init_index_part(session, index, desc, index_part, pos, is_shadow);
    }
}

status_t dc_load_index_part_segment(knl_session_t *session, knl_handle_t dc_entity, index_part_t *part)
{
    status_t status = GS_SUCCESS;
    dls_latch_x(session, &part->btree.struct_latch, session->id, &session->stat_btree);

    if (spc_valid_space_object(session, part->desc.space_id)) {
        if (!IS_INVALID_PAGID(part->desc.entry)) {
            if (buf_read_page(session, part->desc.entry, LATCH_MODE_S, ENTER_PAGE_RESIDENT) != GS_SUCCESS) {
                status = GS_ERROR;
            } else {
                page_head_t *head = (page_head_t *)CURR_PAGE(session);
                part->btree.segment = BTREE_GET_SEGMENT(session);
                if (head->type == PAGE_TYPE_BTREE_HEAD && part->btree.segment->org_scn == part->desc.org_scn) {
                    uint8 cipher_reserve_size = SPACE_GET(session, part->desc.space_id)->ctrl->cipher_reserve_size;
                    part->btree.cipher_reserve_size = cipher_reserve_size;
                    part->desc.seg_scn = part->btree.segment->seg_scn;
                    bt_put_change_stats(&part->btree);
                    knl_panic_log(part->desc.cr_mode == (part->btree.segment)->cr_mode,
                                  "cr_mode is not match, panic info: index_part %s", part->desc.name);
                } else {
                    status = GS_ERROR;
                }
                buf_leave_page(session, GS_FALSE);
            }
        }
    } else {
        status = GS_ERROR;
    }

    if (status != GS_SUCCESS) {
        dls_unlatch(session, &part->btree.struct_latch, &session->stat_btree);
        if (dc_entity == NULL) {
            GS_THROW_ERROR(ERR_DC_CORRUPTED);
        } else {
            dc_entity_t *entity = (dc_entity_t *)dc_entity;
            if (entity->valid) {
                entity->corrupted = GS_TRUE;
                GS_THROW_ERROR(ERR_DC_CORRUPTED);
            } else {
                GS_THROW_ERROR(ERR_OBJECT_ALREADY_DROPPED, "index");
            }
        }
        return GS_ERROR;
    }

    dls_unlatch(session, &part->btree.struct_latch, &session->stat_btree);
    return GS_SUCCESS;
}

void dc_set_index_part_valid(index_t *index, knl_index_part_desc_t desc)
{
    if (index->desc.part_idx_invalid) {
        return;
    }
    index->desc.part_idx_invalid = desc.is_invalid ? GS_TRUE : GS_FALSE;
}

static void inline dc_load_idx_part_empty_stats(knl_session_t *session, knl_cursor_t *cursor,
    index_part_t *idx_part)
{
    if (IS_PARENT_IDXPART(&idx_part->desc)) {
        return;
    }

    if (CURSOR_COLUMN_SIZE(cursor, SYS_INDEXPART_COL_EMPTY_LEAF_BLOCKS) == GS_NULL_VALUE_LEN) {
        return;
    }

    uint32 empty_size = *(uint32*)CURSOR_COLUMN_DATA(cursor, SYS_INDEXPART_COL_EMPTY_LEAF_BLOCKS);
    idx_part->btree.chg_stats.empty_size = MAX(idx_part->btree.chg_stats.empty_size,
        (uint64)empty_size * DEFAULT_PAGE_SIZE(session));
    idx_part->btree.chg_stats.first_empty_size = 0;
}

static status_t dc_load_index_part(knl_session_t *session, knl_cursor_t *cursor, index_t *index,
    knl_index_part_desc_t *desc, uint32 *part_pos)
{
    index_part_t *part = NULL;
    dc_entity_t *entity = index->entity;
    table_t *table = &entity->table;
    part_index_t *part_index = index->part_index;
    uint32 partkeys = part_index->desc.partkeys;

    if (part_convert_index_part_desc(session, cursor, entity, partkeys, desc) != GS_SUCCESS) {
        return GS_ERROR;
    }
    dc_set_index_part_valid(index, *desc);
    /* empty table entry when nologging table is first loaded(db restart) */
    if (!IS_PARENT_IDXPART(desc) && IS_NOLOGGING_BY_TABLE_TYPE(table->desc.type) && entity->entry->need_empty_entry) {
        desc->entry = INVALID_PAGID;
        if (dc_reset_nologging_entry(session, (knl_handle_t)desc, OBJ_TYPE_INDEX_PART) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (PART_CONTAIN_INTERVAL(table->part_table)) {
        if (PART_IS_INTERVAL(desc->part_id)) {
            *part_pos = part_generate_interval_partno(table->part_table, desc->part_id);
        } else {
            part_index->desc.transition_no = *part_pos;
        }
    }

    if (dc_handle_split_index_part(session, index, desc, &part, *part_pos, GS_FALSE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (!part->desc.is_not_ready) {
        part_index->desc.real_partcnt++;
        (*part_pos)++;
    } else {
        part_index->desc.not_ready_partcnt++;
    }

    if (!IS_SYS_TABLE(table) && !IS_PARENT_IDXPART(&desc)) {
        if (stats_seg_load_entity(session, desc->org_scn, &part->btree.stat) != GS_SUCCESS) {
            GS_LOG_RUN_INF("segment statistic failed, there might be some statitics loss.");
        }
    }

    dc_load_idx_part_empty_stats(session, cursor, part);

    return GS_SUCCESS;
}

static status_t dc_load_index_parts(knl_session_t *session, knl_cursor_t *cursor, index_t *index)
{
    uint32 part_pos = 0;
    knl_index_part_desc_t desc;
    dc_entity_t *entity = index->entity;
    table_t *table = &entity->table;

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_INDEXPART_ID, IX_SYS_INDEXPART001_ID);
    knl_init_index_scan(cursor, GS_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &index->desc.uid,
        sizeof(uint32), IX_COL_SYS_INDEXPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &index->desc.table_id,
        sizeof(uint32), IX_COL_SYS_INDEXPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &index->desc.id,
        sizeof(uint32), IX_COL_SYS_INDEXPART001_INDEX_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_INDEXPART001_PART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &index->desc.uid,
        sizeof(uint32), IX_COL_SYS_INDEXPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &index->desc.table_id,
        sizeof(uint32), IX_COL_SYS_INDEXPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &index->desc.id,
        sizeof(uint32), IX_COL_SYS_INDEXPART001_INDEX_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_INDEXPART001_PART_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    while (!cursor->eof) {
        errno_t ret = memset_sp(&desc, sizeof(knl_index_part_desc_t), 0, sizeof(knl_index_part_desc_t));
        knl_securec_check(ret);
        if (dc_load_index_part(session, cursor, index, &desc, &part_pos) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (IS_PARENT_IDXPART(&desc)) {
            index->part_index->desc.subpart_cnt += desc.subpart_cnt;
        }
        
        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    GS_LOG_DEBUG_INF("load index parts: load index parts, uid: %d, tid: %d, iid: %d, index partcnt: %d",
        index->desc.uid, index->desc.table_id, index->desc.id, part_pos);

    knl_panic_log(part_pos == table->part_table->desc.partcnt, "curr part_pos is not equal to table's part count, "
                  "panic info: page %u-%u type %u table %s index %s part_pos %u partcnt %u", cursor->rowid.file,
                  cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, table->desc.name, index->desc.name,
                  part_pos, table->part_table->desc.partcnt);

    if (IS_COMPART_INDEX(index->part_index)) {
        if (dc_load_index_subparts(session, cursor, index) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }
    
    return GS_SUCCESS;
}

status_t dc_load_part_index(knl_session_t *session, index_t *index)
{
    knl_part_desc_t desc;
    dc_entity_t *entity = index->entity;
    
    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_PARTOBJECT_ID, IX_SYS_PARTOBJECT001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &index->desc.uid,
        sizeof(uint32), IX_COL_SYS_PARTOBJECT001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &index->desc.table_id,
        sizeof(uint32), IX_COL_SYS_PARTOBJECT001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &index->desc.id,
        sizeof(uint32), IX_COL_SYS_PARTOBJECT001_INDEX_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s index %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                  entity->table.desc.name, index->desc.name);

    if (part_convert_part_object_desc(session, cursor, entity, &desc) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (dc_alloc_part_index(session, entity, &desc, &index->part_index) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (dc_load_index_parts(session, cursor, index) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);

    return GS_SUCCESS;
}

static status_t dc_load_index_part_segments(knl_session_t *session, dc_entity_t *entity, table_part_t *table_part)
{
    index_t *index = NULL;
    index_part_t *index_part = NULL;
    table_t *table = &entity->table;
    
    for (uint32 i = 0; i < table->index_set.count; i++) {
        index = table->index_set.items[i];
        if (!index->desc.parted) {
            continue;
        }

        if (!IS_SUB_TABPART(&table_part->desc)) {
            index_part = INDEX_GET_PART(index, table_part->part_no);
        } else {
            table_part_t *compart = PART_GET_ENTITY(table->part_table, table_part->parent_partno);
            knl_panic_log(compart != NULL, "compart is NULL, panic info: table %s table_part %s index %s",
                          table->desc.name, table_part->desc.name, index->desc.name);
            index_part = INDEX_GET_PART(index, compart->part_no);
            if (index_part == NULL) {
                continue;
            }
            
            index_part = PART_GET_SUBENTITY(index->part_index, index_part->subparts[table_part->part_no]);
        }
        
        if (index_part == NULL) {
            continue;
        }

        if (dc_load_index_part_segment(session, entity, index_part) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t dc_load_table_part_segment(knl_session_t *session, knl_handle_t dc_entity, table_part_t *part)
{
    status_t status = GS_SUCCESS;

    if (!part->is_ready || part->heap.loaded) {
        return GS_SUCCESS;
    }

    knl_panic_log(!IS_PARENT_TABPART(&part->desc), "load segemnt for parent table part %s", part->desc.name);
    dls_latch_x(session, &part->heap.latch, session->id, &session->stat_heap);
    if (part->heap.loaded) {
        dls_unlatch(session, &part->heap.latch, &session->stat_heap);
        return GS_SUCCESS;
    }

    if (spc_valid_space_object(session, part->desc.space_id)) {
        if (!IS_INVALID_PAGID(part->desc.entry)) {
            if (buf_read_page(session, part->desc.entry, LATCH_MODE_S, ENTER_PAGE_RESIDENT) != GS_SUCCESS) {
                status = GS_ERROR;
            } else {
                page_head_t *head = (page_head_t *)CURR_PAGE(session);
                part->heap.segment = HEAP_SEG_HEAD(session);
                if (head->type == PAGE_TYPE_HEAP_HEAD && part->heap.segment->org_scn == part->desc.org_scn) {
                    part->heap.cipher_reserve_size = SPACE_GET(session, part->desc.space_id)->ctrl->cipher_reserve_size;
                    part->desc.seg_scn = part->heap.segment->seg_scn;
                    knl_panic_log(part->desc.cr_mode == (part->heap.segment)->cr_mode,
                                  "cr_mode is not match, panic info: table_part %s", part->desc.name);
                } else {
                    status = GS_ERROR;
                }
                buf_leave_page(session, GS_FALSE);
            }
        }
    } else {
        status = GS_ERROR;
    }

    if (status != GS_SUCCESS) {
        dls_unlatch(session, &part->heap.latch, &session->stat_heap);
        if (((dc_entity_t *)dc_entity)->valid) {
            ((dc_entity_t *)dc_entity)->corrupted = GS_TRUE;
            GS_THROW_ERROR(ERR_DC_CORRUPTED);
        } else {
            GS_THROW_ERROR(ERR_OBJECT_ALREADY_DROPPED, "table");
        }

        return GS_ERROR;
    }

    if (dc_load_index_part_segments(session, (dc_entity_t *)dc_entity, part) != GS_SUCCESS) {
        dls_unlatch(session, &part->heap.latch, &session->stat_heap);
        return GS_ERROR;
    }

    part->heap.loaded = GS_TRUE;
    dls_unlatch(session, &part->heap.latch, &session->stat_heap);
    return GS_SUCCESS;
}

void dc_load_all_part_segments(knl_session_t *session, knl_handle_t dc_entity)
{
    dc_entity_t *entity = (dc_entity_t *)dc_entity;
    table_t *table = &entity->table;
    table_part_t *table_part = NULL;
    table_part_t *table_subpart = NULL;

    if (!IS_PART_TABLE(table)) {
        return;
    }

    for (uint32 i = 0; i < TOTAL_PARTCNT(&table->part_table->desc); i++) {
        table_part = TABLE_GET_PART(table, i);
        if (!IS_READY_PART(table_part) || table_part->heap.loaded) {
            continue;
        }

        if (IS_PARENT_TABPART(&table_part->desc)) {
            for (uint32 j = 0; j < table_part->desc.subpart_cnt; j++) {
                table_subpart = PART_GET_SUBENTITY(table->part_table, table_part->subparts[j]);
                if (table_subpart == NULL || table_subpart->heap.loaded) {
                    continue;
                }
                
                if (dc_load_table_part_segment(session, entity, (table_part_t *)table_subpart) != GS_SUCCESS) {
                    GS_LOG_RUN_WAR("[DC] could not load table subpartition %s of table %s.%s, segment corrupted",
                        table_subpart->desc.name, session->kernel->dc_ctx.users[table->desc.uid]->desc.name,
                        table->desc.name);
                    cm_reset_error();
                }
            }
        } else {
            if (dc_load_table_part_segment(session, entity, table_part) != GS_SUCCESS) {
                GS_LOG_RUN_WAR("[DC] could not load table partition %s of table %s.%s, segment corrupted",
                    table_part->desc.name, session->kernel->dc_ctx.users[table->desc.uid]->desc.name,
                    table->desc.name);
                cm_reset_error();
            }
        }
    }
}

/*
 * load table partitions
 * scan tablepart$ table, insert the scanned table part into table part group in order.
 * @param kernel session, kernel cursor, dc entity
 */
static status_t dc_load_table_parts(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity)
{
    knl_table_part_desc_t desc;
    table_part_t *part = NULL;
    bool32 has_not_ready = GS_FALSE;
    uint32 not_ready_count = 0;
    uint32 i = 0;
    table_t *table = &entity->table;
    part_table_t *part_table = table->part_table;
    uint32 partkeys = part_table->desc.partkeys;

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_TABLEPART_ID, IX_SYS_TABLEPART001_ID);
    knl_init_index_scan(cursor, GS_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &table->desc.uid,
        sizeof(uint32), IX_COL_SYS_TABLEPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &table->desc.id,
        sizeof(uint32), IX_COL_SYS_TABLEPART001_TABLE_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_TABLEPART001_PART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &table->desc.uid,
        sizeof(uint32), IX_COL_SYS_TABLEPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &table->desc.id,
        sizeof(uint32), IX_COL_SYS_TABLEPART001_TABLE_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_TABLEPART001_PART_ID);

    dls_init_latch2(&part_table->interval_latch, DR_TYPE_INTERVAL_PART_LATCH, part_table->desc.table_id,
                    (uint16)part_table->desc.uid, GS_INVALID_ID32, GS_INVALID_ID32, GS_INVALID_ID32);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    while (!cursor->eof) {
        errno_t ret = memset_sp(&desc, sizeof(knl_table_part_desc_t), 0, sizeof(knl_table_part_desc_t));
        knl_securec_check(ret);
        if (dc_get_table_part_desc(session, cursor, entity, partkeys, &desc, GS_FALSE) != GS_SUCCESS) {
            return GS_ERROR;
        }

        /* empty table entry when nologging table is first loaded(db restart) */
        if (!IS_PARENT_TABPART(&desc) && IS_NOLOGGING_BY_TABLE_TYPE(table->desc.type) &&
            entity->entry->need_empty_entry) {
            desc.entry = INVALID_PAGID;
            if (dc_reset_nologging_entry(session, (knl_handle_t)&desc, OBJ_TYPE_TABLE_PART) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        if (PART_CONTAIN_INTERVAL(part_table)) {
            if (PART_IS_INTERVAL(desc.part_id)) {
                i = part_generate_interval_partno(part_table, desc.part_id);
                part_table->desc.interval_num++;
            } else {
                part_table->desc.transition_no = i;
            }
        }

        // handle not ready partitions: put them at the tail of the part_table dc
        if (desc.not_ready == PARTITON_NOT_READY && part_table->desc.parttype == PART_TYPE_RANGE) {
            has_not_ready = GS_TRUE;

            if (dc_handle_spliting_part(session, table, not_ready_count, entity, &desc, &part) != GS_SUCCESS) {
                return GS_ERROR;
            }
            not_ready_count++;

            GS_LOG_DEBUG_INF("get one partition whose status is not ready, part name is %s, current not ready \
                count is %d", desc.name, not_ready_count);
        } else {
            if (dc_init_table_part(session, entity, table, &desc, &part, i) != GS_SUCCESS) {
                return GS_ERROR;
            }
            GS_LOG_DEBUG_INF("get one partition whose status is ready, part name is %s, current  ready \
                count is %d", desc.name, i + 1);
        }

        if (part_table->desc.parttype == PART_TYPE_LIST) {
            if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, sizeof(list_item_t) * part->desc.groupcnt,
                (void **)&part->lnext) != GS_SUCCESS) {
                GS_THROW_ERROR(ERR_DC_BUFFER_FULL);
                return GS_ERROR;
            }

            part_table_insert_list(part_table, part, partkeys);
        }

        if (!has_not_ready) {
            part_table->desc.real_partcnt++;
            i++;
        }
        part->is_ready = GS_TRUE;
        has_not_ready = GS_FALSE;

        if (!IS_SYS_TABLE(table)) {
            if (stats_seg_load_entity(session, desc.org_scn, &part->heap.stat) != GS_SUCCESS) {
                GS_LOG_RUN_INF("segment statistic failed, there might be some statitics loss.");
            }
        }

        if (IS_PARENT_TABPART(&part->desc)) {
            part_table->desc.subpart_cnt += part->desc.subpart_cnt;
        }
        
        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    knl_panic_log(not_ready_count <= GS_SPLIT_PART_COUNT, "there are more than two not ready parts on the table %s",
        table->desc.name);
    // if has not ready partition for range part table, substract the not ready count
    if (not_ready_count != 0) {
        GS_LOG_DEBUG_INF("not ready partition count is %d, tid is: %d", not_ready_count, table->desc.id);
        part_table->desc.not_ready_partcnt = not_ready_count;
        part_table->desc.partcnt -= not_ready_count;
    }

    GS_LOG_DEBUG_INF("load table parts, uid: %d, tid: %d, partcnt: %d", table->desc.uid, table->desc.id, i);
    knl_panic_log(i == part_table->desc.partcnt, "%u parts has been loaded, but expect %u parts on the table %s",
        i, part_table->desc.partcnt, table->desc.name);

    dc_partno_sort(part_table);
    if (IS_COMPART_TABLE(part_table)) {
        if (dc_load_table_subparts(session, entity, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }
    
    return GS_SUCCESS;
}

/* get the bucket count for hash partition */
uint32 dc_get_hash_bucket_count(uint32 pcnt)
{
    /* the num must be power of 2. */
    double dpcnt = (double)pcnt;
    uint32 num = HASH_PART_BUCKET_BASE << (uint32)(log(dpcnt) / log(HASH_PART_BUCKET_BASE));
    num = (num == pcnt * HASH_PART_BUCKET_BASE ? pcnt : num);

    return num;
}

status_t dc_load_part_table(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity)
{
    knl_part_desc_t desc;
    table_t *table = &entity->table;
    uint32 index_id = GS_INVALID_ID32;

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_PARTOBJECT_ID, IX_SYS_PARTOBJECT001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &table->desc.uid,
        sizeof(uint32), IX_COL_SYS_PARTOBJECT001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &table->desc.id,
        sizeof(uint32), IX_COL_SYS_PARTOBJECT001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &index_id, sizeof(uint32),
        IX_COL_SYS_PARTOBJECT001_INDEX_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s index %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, table->desc.name,
                  ((index_t *)cursor->index)->desc.name);

    if (part_convert_part_object_desc(session, cursor, entity, &desc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (dc_alloc_part_table(session, entity, &desc, &table->part_table) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (dc_load_part_columns(session, cursor, entity) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (IS_COMPART_TABLE(table->part_table)) {
        if (dc_load_subpart_columns(session, cursor, entity) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (IS_PART_TABLE(table)) {
        if (dc_load_table_parts(session, cursor, entity) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

uint32 dc_generate_interval_part_id(uint32 part_lno, uint32 transition_no)
{
    uint32 part_id;

    // PART_INTERVAL_BASE_ID = 0x40000000, the max value for part_lno is 4194304 , the min value for transition_no is 0
    part_id = PART_INTERVAL_BASE_ID + (part_lno - transition_no - 1);

    return part_id;
}

static status_t dc_load_interval_table_part(knl_session_t *session, knl_dictionary_t *dc, knl_cursor_t *cursor,
    uint32 partno)
{
    dc_entity_t *entity = DC_ENTITY(dc);
    table_t *table = &entity->table;

    uint32 part_id = dc_generate_interval_part_id(partno, table->part_table->desc.transition_no);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_TABLEPART_ID, IX_SYS_TABLEPART001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &table->desc.uid,
        sizeof(uint32), IX_COL_SYS_TABLEPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &table->desc.id,
        sizeof(uint32), IX_COL_SYS_TABLEPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &part_id, sizeof(uint32),
        IX_COL_SYS_TABLEPART001_PART_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s index %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, table->desc.name,
                  ((index_t *)cursor->index)->desc.name);
    if (dc_alloc_table_part(session, entity, table->part_table, partno) != GS_SUCCESS) {
        return GS_ERROR;
    }

    table_part_t *part = PART_GET_ENTITY(table->part_table, partno);
    knl_table_part_desc_t *desc = &part->desc;
    if (dc_get_table_part_desc(session, cursor, entity, 1, desc, GS_TRUE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    uint32 *no_i = &PART_GET_NO(table->part_table, table->part_table->desc.real_partcnt);
    part->part_no = partno;
    part->parent_partno = GS_INVALID_ID32;
    part->global_partno = GS_INVALID_ID32;
    part->heap.entry = desc->entry;
    part->heap.table = table;
    part->desc.cr_mode = table->desc.cr_mode;
    *no_i = part->part_no;

    dc_part_table_insert_name(table->part_table, part);

    if (!spc_valid_space_object(session, desc->space_id)) {
        entity->corrupted = GS_TRUE;
        dc_user_t *user = session->kernel->dc_ctx.users[table->desc.uid];
        GS_LOG_RUN_ERR("[DC CORRUPTED] could not load table partition %s of table %s.%s, tablespace %s is offline",
            part->desc.name, user->desc.name, table->desc.name, SPACE_GET(session, desc->space_id)->ctrl->name);
    }
    part->heap.cipher_reserve_size = SPACE_GET(session, desc->space_id)->ctrl->cipher_reserve_size;

    if (IS_COMPART_TABLE(table->part_table)) {
        if (dc_load_interval_table_subpart(session, dc, cursor, part) != GS_SUCCESS) {
            return GS_ERROR;
        }

        table->part_table->desc.subpart_cnt++;
    }

    return GS_SUCCESS;
}

static void dc_get_locate_from_part(index_t *index, index_part_t *index_part, knl_part_locate_t *part_loc)
{
    if (IS_SUB_IDXPART(&index_part->desc)) {
        index_part_t *index_compart = INDEX_GET_PART(index, index_part->parent_partno);
        knl_panic_log(index_compart != NULL, "index get part failed, panic info: index %s index_part %s",
                      index->desc.name, index_part->desc.name);
        part_loc->part_no = index_compart->part_no;
        part_loc->subpart_no = index_part->part_no;
    } else {
        part_loc->part_no = index_part->part_no;
        part_loc->subpart_no = GS_INVALID_ID32;
    }
}

static status_t dc_put_shadow_idx_part(knl_session_t *session, knl_index_part_desc_t *part_desc, dc_entity_t *entity,
    index_t *index)
{
    index_part_t *index_part = NULL;
    table_t *table = &entity->table;
    dc_user_t *user = session->kernel->dc_ctx.users[entity->table.desc.uid];

    errno_t ret = memset_sp(table->shadow_index, sizeof(shadow_index_t), 0, sizeof(shadow_index_t));
    knl_securec_check(ret);
    table->shadow_index->is_valid = GS_TRUE;
    index_part_t *shadow_part = &table->shadow_index->index_part;
    ret = memcpy_sp(&shadow_part->desc, sizeof(knl_index_part_desc_t), part_desc, sizeof(knl_index_part_desc_t));
    knl_securec_check(ret);

    text_t part_name;
    cm_str2text(part_desc->name, &part_name);
    if (IS_COMPART_INDEX(index->part_index)) {
        if (!subpart_idx_find_by_name(index->part_index, &part_name, &index_part)) {
            GS_THROW_ERROR(ERR_PARTITION_NOT_EXIST, "index", T2S_EX(&part_name));
            return GS_ERROR;
        }
    } else {
        if (!part_idx_find_by_name(index->part_index, &part_name, &index_part)) {
            GS_THROW_ERROR(ERR_PARTITION_NOT_EXIST, "index", T2S_EX(&part_name));
            return GS_ERROR;
        }
    }

    knl_part_locate_t *part_loc = &table->shadow_index->part_loc;
    dc_get_locate_from_part(index, index_part, part_loc);
    shadow_part->part_no = (part_loc->subpart_no != GS_INVALID_ID32) ? part_loc->subpart_no : part_loc->part_no;
    shadow_part->btree.entry = part_desc->entry;
    shadow_part->btree.index = index;
    shadow_part->btree.is_shadow = GS_TRUE;
    shadow_part->desc.cr_mode = index->desc.cr_mode;
    dls_init_latch2(&shadow_part->btree.struct_latch, DR_TYPE_BRTEE_PART_LATCH, shadow_part->desc.table_id,
                    shadow_part->desc.uid, shadow_part->desc.index_id, shadow_part->part_no,
                    shadow_part->parent_partno);

    if (spc_valid_space_object(session, part_desc->space_id) && !IS_INVALID_PAGID(part_desc->entry)) {
        buf_enter_page(session, part_desc->entry, LATCH_MODE_S, ENTER_PAGE_RESIDENT);
        page_head_t *head = (page_head_t *)CURR_PAGE(session);
        shadow_part->btree.segment = BTREE_GET_SEGMENT(session);
        if (head->type == PAGE_TYPE_BTREE_HEAD && shadow_part->btree.segment->org_scn == part_desc->org_scn) {
            shadow_part->btree.segment = BTREE_GET_SEGMENT(session);
            bt_put_change_stats(&shadow_part->btree);
            buf_leave_page(session, GS_FALSE);
            shadow_part->btree.cipher_reserve_size = SPACE_GET(session, part_desc->space_id)->ctrl->cipher_reserve_size;
            shadow_part->desc.seg_scn = shadow_part->btree.segment->seg_scn;
            return GS_SUCCESS;
        }
        buf_leave_page(session, GS_FALSE);
    }

    entity->corrupted = GS_TRUE;
    GS_LOG_RUN_ERR("[DC CORRUPTED] could not load shadow index partition %s of table %s.%s",
        shadow_part->desc.name, user->desc.name, entity->table.desc.name);
    GS_THROW_ERROR(ERR_DC_CORRUPTED);
    return GS_ERROR;
}

status_t dc_load_shadow_index_part(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity)
{
    table_t *table = &entity->table;
    knl_index_part_desc_t desc = { 0 };

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_SHADOW_INDEXPART_ID, IX_SYS_SHW_INDEXPART001_ID);
    knl_init_index_scan(cursor, GS_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &table->desc.uid,
        sizeof(uint32), IX_COL_SYS_SHW_INDEXPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &table->desc.id,
        sizeof(uint32), IX_COL_SYS_SHW_INDEXPART001_TABLE_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_SHW_INDEXPART001_INDEX_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_SHW_INDEXPART001_PART_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_SHW_INDEXPART001_PARENTPART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &table->desc.uid,
        sizeof(uint32), IX_COL_SYS_SHW_INDEXPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &table->desc.id,
        sizeof(uint32), IX_COL_SYS_SHW_INDEXPART001_TABLE_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_SHW_INDEXPART001_INDEX_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_SHW_INDEXPART001_PART_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_SHW_INDEXPART001_PARENTPART_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (cursor->eof) {
        return GS_SUCCESS;
    }

    uint32 index_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SHADOW_INDEXPART_COL_INDEX_ID);
    index_t *index = dc_find_index_by_id(entity, index_id);
    knl_panic_log(index != NULL && index->part_index != NULL, "index is NULL or part_index is NULL, panic info: "
                  "page %u-%u type %u table %s index %s", cursor->rowid.file, cursor->rowid.page,
                  ((page_head_t *)cursor->page_buf)->type, table->desc.name, ((index_t *)cursor->index)->desc.name);
    uint32 partkeys = index->part_index->desc.partkeys;
    if (IS_COMPART_INDEX(index->part_index)) {
        partkeys = index->part_index->desc.subpartkeys;
    }
    
    if (part_convert_index_part_desc(session, cursor, entity, partkeys, &desc) != GS_SUCCESS) {
        return GS_ERROR;
    }
    desc.subpart_cnt = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SHADOW_INDEXPART_COL_SUBPART_CNT);
    
    if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, sizeof(shadow_index_t),
        (void **)&table->shadow_index) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (dc_put_shadow_idx_part(session, &desc, entity, index) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t dc_load_shwidx_part(knl_session_t *session, index_t *index, knl_cursor_t *cursor, uint32 *part_pos)
{
    knl_index_part_desc_t desc;
    index_part_t *part = NULL;
    table_t *table = &index->entity->table;
    part_index_t *part_index = index->part_index;
    dc_user_t *user = session->kernel->dc_ctx.users[index->entity->table.desc.uid];

    errno_t ret = memset_sp(&desc, sizeof(knl_index_part_desc_t), 0, sizeof(knl_index_part_desc_t));
    knl_securec_check(ret);
    
    /* skip sub shadow index part */
    desc.flags = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SHADOW_INDEXPART_COL_FLAGS);
    desc.subpart_cnt = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SHADOW_INDEXPART_COL_SUBPART_CNT);
    if (IS_SUB_IDXPART(&desc)) {
        return GS_SUCCESS;
    }
        
    if (part_convert_index_part_desc(session, cursor, index->entity, part_index->desc.partkeys, &desc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    /* desc is get by SYS_INDEXPART_COL, we must update the subpartcnt */
    desc.subpart_cnt = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SHADOW_INDEXPART_COL_SUBPART_CNT);
    
    /* empty table entry when nologging table is first loaded(db restart) */
    if (!IS_PARENT_IDXPART(&desc) && IS_NOLOGGING_BY_TABLE_TYPE(table->desc.type) &&
        index->entity->entry->need_empty_entry) {
        desc.entry = INVALID_PAGID;
        if (dc_reset_nologging_entry(session, (knl_handle_t)&desc, OBJ_TYPE_SHADOW_INDEX_PART) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (PART_CONTAIN_INTERVAL(table->part_table)) {
        if (PART_IS_INTERVAL(desc.part_id)) {
            *part_pos = part_generate_interval_partno(table->part_table, desc.part_id);
        } else {
            part_index->desc.transition_no = *part_pos;
        }
    }

    if (dc_handle_split_index_part(session, index, &desc, &part, *part_pos, GS_TRUE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (!IS_PARENT_IDXPART(&part->desc)) {
        if (dc_load_index_part_segment(session, index->entity, part) != GS_SUCCESS) {
            GS_LOG_RUN_WAR("[DC] could not load index partition %s of table %s.%s, segment corrupted",
                           part->desc.name, user->desc.name, index->entity->table.desc.name);
        }
    }

    if (!part->desc.is_not_ready) {
        (*part_pos)++;
    }

    if (!IS_SYS_TABLE(table) && !IS_PARENT_IDXPART(&desc)) {
        if (stats_seg_load_entity(session, desc.org_scn, &part->btree.stat) != GS_SUCCESS) {
            GS_LOG_RUN_INF("segment statistic failed, there might be some statitics loss.");
        }
    }

    return GS_SUCCESS;
}

status_t dc_load_shadow_indexparts(knl_session_t *session, knl_cursor_t *cursor, index_t *index)
{
    uint32 part_pos = 0;
    knl_part_desc_t desc;

    table_t *table = &index->entity->table;
    part_table_t *part_table = table->part_table;
    errno_t ret = memcpy_sp(&desc, sizeof(knl_part_desc_t), &part_table->desc, sizeof(knl_part_desc_t));
    knl_securec_check(ret);
    desc.index_id = index->desc.id;
    if (dc_alloc_part_index(session, index->entity, &desc, &index->part_index) != GS_SUCCESS) {
        return GS_ERROR;
    }

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_SHADOW_INDEXPART_ID, IX_SYS_SHW_INDEXPART001_ID);
    knl_init_index_scan(cursor, GS_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &index->desc.uid,
        sizeof(uint32), IX_COL_SYS_SHW_INDEXPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &index->desc.table_id,
        sizeof(uint32), IX_COL_SYS_SHW_INDEXPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &index->desc.id,
        sizeof(uint32), IX_COL_SYS_SHW_INDEXPART001_INDEX_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_SHW_INDEXPART001_PART_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_SHW_INDEXPART001_PARENTPART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &index->desc.uid,
        sizeof(uint32), IX_COL_SYS_SHW_INDEXPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &index->desc.table_id,
        sizeof(uint32), IX_COL_SYS_SHW_INDEXPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &index->desc.id,
        sizeof(uint32), IX_COL_SYS_SHW_INDEXPART001_INDEX_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_SHW_INDEXPART001_PART_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_SHW_INDEXPART001_PARENTPART_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    while (!cursor->eof) {
        if (dc_load_shwidx_part(session, index, cursor, &part_pos) != GS_SUCCESS) {
            return GS_ERROR;
        }
        
        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    GS_LOG_DEBUG_INF("load shadow index parts: uid: %d, tid: %d, iid: %d, index partcnt: %d",
        index->desc.uid, index->desc.table_id, index->desc.id, part_pos);
    knl_panic_log(part_pos == part_table->desc.partcnt, "%u parts has been loaded, but expect %u parts on the table %s",
        part_pos, part_table->desc.partcnt, table->desc.name);

    if (!IS_COMPART_INDEX(index->part_index)) {
        return GS_SUCCESS;
    }
    
    return dc_load_shwidx_subparts(session, cursor, index);
}

static status_t dc_load_interval_index_part(knl_session_t *session, knl_cursor_t *cursor, index_t *index,
    uint32 partno, bool8 is_shadow)
{
    knl_index_part_desc_t desc = { 0 };
    dc_entity_t *entity = index->entity;
    table_t *table = &entity->table;
    part_table_t *part_table = table->part_table;
    part_index_t *part_index = index->part_index;
    dc_user_t *user  = session->kernel->dc_ctx.users[entity->table.desc.uid];
    uint32 part_id = dc_generate_interval_part_id(partno, part_table->desc.transition_no);

    if (is_shadow) {
        knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_SHADOW_INDEXPART_ID,
            IX_SYS_SHW_INDEXPART001_ID);
    } else {
        knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_INDEXPART_ID, IX_SYS_INDEXPART001_ID);
    }
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &index->desc.uid,
        sizeof(uint32), IX_COL_SYS_INDEXPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &index->desc.table_id,
        sizeof(uint32), IX_COL_SYS_INDEXPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &index->desc.id,
        sizeof(uint32), IX_COL_SYS_INDEXPART001_INDEX_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &part_id, sizeof(uint32),
        IX_COL_SYS_INDEXPART001_PART_ID);
    if (is_shadow) {
        uint32 subpart_cnt = IS_COMPART_INDEX(part_index) ? 1 : 0;
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &subpart_cnt,
            sizeof(uint32), IX_COL_SYS_SHW_INDEXPART001_PARENTPART_ID);
    }

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s index %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, table->desc.name,
                  ((index_t *)cursor->index)->desc.name);

    if (part_convert_index_part_desc(session, cursor, entity, 1, &desc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (is_shadow) {
        desc.subpart_cnt = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SHADOW_INDEXPART_COL_SUBPART_CNT);
    }
    
    if (dc_alloc_index_part(session, entity, part_index, partno) != GS_SUCCESS) {
        return GS_ERROR;
    }

    index_part_t *part = PART_GET_ENTITY(part_index, partno);
    int32 ret = memcpy_sp(&part->desc, sizeof(knl_index_part_desc_t), &desc, sizeof(knl_index_part_desc_t));
    knl_securec_check(ret);
    part->part_no = partno;
    part->parent_partno = GS_INVALID_ID32;
    part->global_partno = GS_INVALID_ID32;
    part->btree.entry = desc.entry;
    part->btree.index = index;
    part->btree.is_shadow = is_shadow;
    part->desc.cr_mode = index->desc.cr_mode;
    dls_init_latch2(&part->btree.struct_latch, DR_TYPE_BRTEE_PART_LATCH, part->desc.table_id, part->desc.uid,
                    part->desc.index_id, part->part_no, part->parent_partno);

    part_index_insert_name(part_index, part);

    if (spc_valid_space_object(session, desc.space_id)) {
        if (!IS_INVALID_PAGID(desc.entry)) {
            if (buf_read_page(session, desc.entry, LATCH_MODE_S, ENTER_PAGE_RESIDENT) != GS_SUCCESS) {
                entity->corrupted = GS_TRUE;
                GS_LOG_RUN_ERR("[DC CORRUPTED] could not load index partition %s of table %s.%s, segment corrupted",
                    part->desc.name, user->desc.name, entity->table.desc.name);
                cm_reset_error();
            } else {
                page_head_t *head = (page_head_t *)CURR_PAGE(session);
                part->btree.segment = BTREE_GET_SEGMENT(session);
                if (head->type == PAGE_TYPE_BTREE_HEAD && part->btree.segment->org_scn == desc.org_scn) {
                    part->btree.cipher_reserve_size = SPACE_GET(session, desc.space_id)->ctrl->cipher_reserve_size;
                    part->desc.seg_scn = part->btree.segment->seg_scn;
                    bt_put_change_stats(&part->btree);
                } else {
                    entity->corrupted = GS_TRUE;
                    GS_LOG_RUN_ERR("[DC CORRUPTED] could not load index partition %s of table %s.%s, segment corrupted",
                        part->desc.name, user->desc.name, entity->table.desc.name);
                }
                buf_leave_page(session, GS_FALSE);
            }
        }
    } else {
        entity->corrupted = GS_TRUE;
        GS_LOG_RUN_ERR("[DC CORRUPTED] could not load index partition %s of table %s.%s, tablespace %s is offline",
            part->desc.name, user->desc.name, entity->table.desc.name,
            SPACE_GET(session, desc.space_id)->ctrl->name);
    }

    if (IS_COMPART_TABLE(part_table)) {
        if (dc_load_interval_index_subpart(session, cursor, index, part, is_shadow) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t dc_alloc_part_lob(knl_session_t *session, dc_entity_t *entity, lob_t *lob)
{
    dc_context_t *dc_ctx = &session->kernel->dc_ctx;
    if (dc_alloc_mem(dc_ctx, entity->memory, sizeof(part_lob_t), (void **)&lob->part_lob) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_DC_BUFFER_FULL);
        return GS_ERROR;
    }

    errno_t ret = memset_sp(lob->part_lob, sizeof(part_lob_t), 0, sizeof(part_lob_t));
    knl_securec_check(ret);
    part_lob_t *part_lob = lob->part_lob;
    if (dc_alloc_mem(dc_ctx, entity->memory, GS_SHARED_PAGE_SIZE, (void **)&part_lob->groups) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_DC_BUFFER_FULL);
        return GS_ERROR;
    }
    
    ret = memset_sp(lob->part_lob->groups, GS_SHARED_PAGE_SIZE, 0, GS_SHARED_PAGE_SIZE);
    knl_securec_check(ret);

    table_t *table = &entity->table;
    if (IS_COMPART_TABLE(table->part_table)) {
        if (dc_alloc_mem(dc_ctx, entity->memory, GS_SHARED_PAGE_SIZE, (void **)&part_lob->sub_groups) != GS_SUCCESS) {
            return GS_ERROR;
        }

        ret = memset_sp(part_lob->sub_groups, GS_SHARED_PAGE_SIZE, 0, GS_SHARED_PAGE_SIZE);
        knl_securec_check(ret);
    }

    if (table->part_table->desc.interval_key != NULL) {
        if (dc_alloc_intval_partition_group(session, entity, &part_lob->part_group) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t dc_alloc_part_lob_group(knl_session_t *session, dc_entity_t *entity, part_lob_t *part_lob,
                                        uint32 gid)
{
    int32 ret;
    if (part_lob->groups[gid] == NULL) {
        if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, sizeof(lob_part_group_t),
            (void **)&part_lob->groups[gid]) != GS_SUCCESS) {
            GS_THROW_ERROR(ERR_DC_BUFFER_FULL);
            return GS_ERROR;
        }
        ret = memset_sp(part_lob->groups[gid], sizeof(lob_part_group_t), 0, sizeof(lob_part_group_t));
        knl_securec_check(ret);
    }

    return GS_SUCCESS;
}

status_t dc_alloc_lob_part(knl_session_t *session, dc_entity_t *entity, part_lob_t *part_lob, uint32 id)
{
    part_table_t *part_table = entity->table.part_table;
    lob_part_group_t *group = NULL;
    lob_part_t *part = NULL;
    uint32 gid, eid, lob_size;
    errno_t ret;

    gid = id / PART_GROUP_SIZE;
    eid = id % PART_GROUP_SIZE;
    if (!PART_CONTAIN_INTERVAL(part_table)) {
        if (dc_alloc_part_lob_group(session, entity, part_lob, gid) != GS_SUCCESS) {
            return GS_ERROR;
        }
    } else {
        if (part_calc_intval_partition_group(session, entity, &part_lob->part_group.group_cnt,
            part_lob->part_group.group_id, &gid) != GS_SUCCESS) {
                return GS_ERROR;
        }

        if (dc_alloc_part_lob_group(session, entity, part_lob, gid) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (!part_lob->part_group.group_ready[gid]) {
            part_lob->part_group.group_ready[gid] = GS_TRUE;
        }
    }

    group = part_lob->groups[gid];
    if (group->entity[eid] == NULL) {
        if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, sizeof(lob_part_t),
            (void **)&group->entity[eid]) != GS_SUCCESS) {
            GS_THROW_ERROR(ERR_DC_BUFFER_FULL);
            return GS_ERROR;
        }

        part = group->entity[eid];
        lob_size = sizeof(lob_part_t);
        ret = memset_sp(part, lob_size, 0, lob_size);
        knl_securec_check(ret);
        part->desc.entry = INVALID_PAGID;
    }

    return GS_SUCCESS;
}

static status_t dc_load_interval_lob_part(knl_session_t *session, knl_dictionary_t *dc, knl_cursor_t *cursor,
    lob_t *lob, uint32 partno)
{
    dc_entity_t *entity = DC_ENTITY(dc);
    table_t *table = &entity->table;
    part_lob_t *part_lob = lob->part_lob;
    knl_lob_part_desc_t desc = { 0 };
    uint32 part_id = dc_generate_interval_part_id(partno, table->part_table->desc.transition_no);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_LOBPART_ID, IX_SYS_LOBPART001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &lob->desc.uid,
        sizeof(uint32), IX_COL_SYS_LOBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &lob->desc.table_id,
        sizeof(uint32), IX_COL_SYS_LOBPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &lob->desc.column_id,
        sizeof(uint32), IX_COL_SYS_LOBPART001_COLUMN_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &part_id, sizeof(uint32),
        IX_COL_SYS_LOBPART001_PART_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s index %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, table->desc.name,
                  ((index_t *)cursor->index)->desc.name);

    dc_convert_lob_part_desc(cursor, &desc);
    desc.subpart_cnt = IS_COMPART_TABLE(table->part_table) ? 1 : 0;
    if (dc_alloc_lob_part(session, entity, part_lob, partno) != GS_SUCCESS) {
        return GS_ERROR;
    }

    lob_part_t *part = PART_GET_ENTITY(part_lob, partno);
    int32 ret = memcpy_sp(&part->desc, sizeof(knl_lob_part_desc_t), &desc, sizeof(knl_lob_part_desc_t));
    knl_securec_check(ret);
    part->part_no = partno;
    part->parent_partno = GS_INVALID_ID32;
    part->global_partno = GS_INVALID_ID32;
    part->lob_entity.entry = desc.entry;
    part->lob_entity.lob = lob;
    dls_init_latch2(&part->lob_entity.seg_latch, DR_TYPE_LOB_PART_LATCH, lob->desc.table_id, lob->desc.uid,
                    lob->desc.column_id, part->part_no, part->parent_partno);

    if (!spc_valid_space_object(session, desc.space_id)) {
        entity->corrupted = GS_TRUE;
        dc_user_t *user = session->kernel->dc_ctx.users[table->desc.uid];
        GS_LOG_RUN_ERR("[DC CORRUPTED] could not load lob partition of column %s of table %s.%s, tablespace %s is offline",
            dc_get_column(entity, lob->desc.column_id)->name, user->desc.name, table->desc.name,
            SPACE_GET(session, lob->desc.space_id)->ctrl->name);
    }
    part->lob_entity.cipher_reserve_size = SPACE_GET(session, desc.space_id)->ctrl->cipher_reserve_size;

    if (IS_COMPART_TABLE(table->part_table)) {
        if (dc_load_interval_lob_subpart(session, dc, cursor, lob, part) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t dc_load_interval_part(knl_session_t *session, knl_dictionary_t *dc, uint32 part_no)
{
    knl_cursor_t *cursor = NULL;
    dc_entity_t *entity = DC_ENTITY(dc);
    table_t *table = DC_TABLE(dc);
    knl_column_t *column = NULL;
    index_t *index = NULL;
    lob_t *lob = NULL;

    cm_latch_x(&entity->cbo_latch, 0, NULL);

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);
    knl_set_session_scn(session, GS_INVALID_ID64);

    for (uint32 i = 0; i < table->index_set.total_count; i++) {
        index = table->index_set.items[i];
        if (!IS_PART_INDEX(index)) {
            continue;
        }

        if (dc_load_interval_index_part(session, cursor, index, part_no, GS_FALSE) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            cm_unlatch(&entity->cbo_latch, NULL);
            return GS_ERROR;
        }

        if (index->desc.is_invalid) {
            continue;
        }

        if (cbo_load_interval_index_part(session, entity, i, part_no) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            cm_unlatch(&entity->cbo_latch, NULL);
            return GS_ERROR;
        }
    }

    for (uint32 i = 0; i < table->desc.column_count; i++) {
        column = dc_get_column(entity, i);
        if (!COLUMN_IS_LOB(column)) {
            continue;
        }

        lob = (lob_t *)column->lob;

        if (dc_load_interval_lob_part(session, dc, cursor, lob, part_no) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            cm_unlatch(&entity->cbo_latch, NULL);
            return GS_ERROR;
        }
    }

    if (table->shadow_index != NULL && table->shadow_index->is_valid && IS_PART_INDEX(&table->shadow_index->index)) {
        if (dc_load_interval_index_part(session, cursor, &table->shadow_index->index, part_no, GS_TRUE) !=
            GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            cm_unlatch(&entity->cbo_latch, NULL);
            return GS_ERROR;
        }
    }

    if (dc_load_interval_table_part(session, dc, cursor, part_no) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        cm_unlatch(&entity->cbo_latch, NULL);
        return GS_ERROR;
    }

    if (cbo_load_interval_table_part(session, entity, part_no) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        cm_unlatch(&entity->cbo_latch, NULL);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    cm_unlatch(&entity->cbo_latch, NULL);

    return GS_SUCCESS;
}


static status_t dc_init_lob_part(knl_session_t *session, dc_entity_t *entity, knl_lob_part_desc_t *desc,
    lob_t *lob, lob_part_t **part, uint32 pos)
{
    part_lob_t *part_lob = NULL;
    errno_t ret;

    part_lob = lob->part_lob;
    if (dc_alloc_lob_part(session, entity, part_lob, pos) != GS_SUCCESS) {
        return GS_ERROR;
    }

    *part = PART_GET_ENTITY(part_lob, pos);
    ret = memcpy_sp(&(*part)->desc, sizeof(knl_lob_part_desc_t), desc, sizeof(knl_lob_part_desc_t));
    knl_securec_check(ret);
    (*part)->part_no = pos;
    (*part)->parent_partno = GS_INVALID_ID32;
    (*part)->global_partno = GS_INVALID_ID32;
    
    if (desc->is_parent) {
        if (dc_alloc_lob_subparts(session, entity, *part) != GS_SUCCESS) {
            return GS_SUCCESS;
        }
    } else {
        (*part)->lob_entity.entry = desc->entry;
        (*part)->lob_entity.lob = lob;
        dls_init_latch2(&(*part)->lob_entity.seg_latch, DR_TYPE_LOB_PART_LATCH, desc->table_id,
                        desc->uid, desc->column_id, (*part)->part_no, (*part)->parent_partno);
    }

    return GS_SUCCESS;
}

static status_t dc_handle_split_lob_part(knl_session_t *session, dc_entity_t *entity, knl_lob_part_desc_t *desc,
    lob_t *lob, lob_part_t **lob_part, uint32 pos)
{
    uint32 partcnt, not_ready_partcnt;
    table_part_t *table_part = NULL;
    part_table_t *part_table = NULL;
    table_t *table = NULL;

    table = &entity->table;
    part_table = table->part_table;
    partcnt = part_table->desc.partcnt;
    not_ready_partcnt = part_table->desc.not_ready_partcnt;
    bool32 is_splitable = (part_table->desc.parttype == PART_TYPE_RANGE);

    // range partition and includes not ready part
    for (uint32 i = 0; i < not_ready_partcnt && is_splitable; i++) {
        table_part = PART_GET_ENTITY(part_table, partcnt + i);
        if (desc->part_id == table_part->desc.part_id) {
            desc->subpart_cnt = table_part->desc.subpart_cnt;
            desc->is_not_ready = GS_TRUE;
            break;
        }
    }

    // if includes not ready part, then need to put the not ready part at the tail
    if (desc->is_not_ready) {
        return dc_init_lob_part(session, entity, desc, lob, lob_part, table_part->part_no);
    } else {
        return dc_init_lob_part(session, entity, desc, lob, lob_part, pos);
    }
}

void dc_load_lob_part_segment(knl_session_t *session, dc_entity_t *entity, lob_part_t *part, lob_t *lob)
{
    page_head_t *head = NULL;
    knl_lob_part_desc_t desc = part->desc;
    table_t *table = &entity->table;
    dc_user_t *user = session->kernel->dc_ctx.users[table->desc.uid];

    if (spc_valid_space_object(session, desc.space_id)) {
        if (!IS_INVALID_PAGID(desc.entry)) {
            if (buf_read_page(session, desc.entry, LATCH_MODE_S, ENTER_PAGE_RESIDENT) != GS_SUCCESS) {
                entity->corrupted = GS_TRUE;
                GS_LOG_RUN_ERR("[DC CORRUPTED] could not load lob partition of column %s of table %s.%s, "
                    "segment corrupted",
                    dc_get_column(entity, lob->desc.column_id)->name,
                    user->desc.name, table->desc.name);
            } else {
                head = (page_head_t *)CURR_PAGE(session);
                part->lob_entity.segment = LOB_SEG_HEAD(session);
                if (head->type == PAGE_TYPE_LOB_HEAD && part->lob_entity.segment->org_scn == desc.org_scn) {
                    part->lob_entity.cipher_reserve_size = SPACE_GET(session, desc.space_id)->ctrl->cipher_reserve_size;
                    desc.seg_scn = part->lob_entity.segment->seg_scn;
                } else {
                    entity->corrupted = GS_TRUE;
                    GS_LOG_RUN_ERR("[DC CORRUPTED] could not load lob partition of column %s of table %s.%s, "
                        "segment corrupted",
                        dc_get_column(entity, lob->desc.column_id)->name,
                        user->desc.name, table->desc.name);
                }
                buf_leave_page(session, GS_FALSE);
            }
        }
    } else {
        entity->corrupted = GS_TRUE;
        GS_LOG_RUN_ERR("[DC CORRUPTED] could not load lob partition of column %s of table %s.%s, tablespace %s is offline",
            dc_get_column(entity, lob->desc.column_id)->name, user->desc.name, table->desc.name,
            SPACE_GET(session, lob->desc.space_id)->ctrl->name);
    }
}

status_t dc_load_lob_parts(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity, lob_t *lob)
{
    knl_lob_part_desc_t desc = { 0 };
    lob_part_t *part = NULL;
    uint32 i = 0;
    table_t *table = &entity->table;

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_LOBPART_ID, IX_SYS_LOBPART001_ID);
    knl_init_index_scan(cursor, GS_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &lob->desc.uid,
        sizeof(uint32), IX_COL_SYS_LOBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &lob->desc.table_id,
        sizeof(uint32), IX_COL_SYS_LOBPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &lob->desc.column_id,
        sizeof(uint32), IX_COL_SYS_LOBPART001_COLUMN_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_LOBPART001_PART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &lob->desc.uid,
        sizeof(uint32), IX_COL_SYS_LOBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &lob->desc.table_id,
        sizeof(uint32), IX_COL_SYS_LOBPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &lob->desc.column_id,
        sizeof(uint32), IX_COL_SYS_LOBPART001_COLUMN_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_LOBPART001_PART_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    while (!cursor->eof) {
        dc_convert_lob_part_desc(cursor, &desc);

        /* empty table entry when nologging table is first loaded(db restart) */
        if (!IS_PARENT_LOBPART(&desc) && IS_NOLOGGING_BY_TABLE_TYPE(table->desc.type) &&
            entity->entry->need_empty_entry) {
            desc.entry = INVALID_PAGID;
            if (dc_reset_nologging_entry(session, (knl_handle_t)&desc, OBJ_TYPE_LOB_PART) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        if (PART_CONTAIN_INTERVAL(table->part_table) && PART_IS_INTERVAL(desc.part_id)) {
            i = part_generate_interval_partno(table->part_table, desc.part_id);
        }

        table_part_t *table_part = TABLE_GET_PART(table, i);
        desc.subpart_cnt = table_part->desc.subpart_cnt;
        if (dc_handle_split_lob_part(session, entity, &desc, lob, &part, i) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (!part->desc.is_parent) {
            dc_load_lob_part_segment(session, entity, part, lob);
        }
        
        if (!part->desc.is_not_ready) {
            i++;
        }
        
        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    GS_LOG_DEBUG_INF("load lob parts: load lob part from lob part$, uid: %d, tid: %d, column id: %d",
        lob->desc.uid, lob->desc.table_id, lob->desc.column_id);
    knl_panic_log(i == table->part_table->desc.partcnt, "the table's part count is abnormal, panic info: "
                  "page %u-%u type %u table %s index %s curr part count %u partcnt %u", cursor->rowid.file,
                  cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, table->desc.name,
                  ((index_t *)cursor->index)->desc.name, i, table->part_table->desc.partcnt);

    if (IS_COMPART_TABLE(table->part_table)) {
        if (dc_load_lob_subparts(session, cursor, entity, lob) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

table_part_t *dc_get_table_part(part_table_t *part_table, uint64 org_scn)
{
    table_part_t *table_part = NULL;
    int32 begin, end, curr;
    uint32 part_no;

    curr = 0;
    begin = 0;

    if (PART_CONTAIN_INTERVAL(part_table)) {
        end = part_table->desc.real_partcnt - 1;
    } else {
        end = part_table->desc.partcnt - 1;
    }

    while (begin <= end) {
        curr = ((uint32)(end + begin)) >> 1;
        part_no = PART_GET_NO(part_table, (uint32)curr);
        table_part = PART_GET_ENTITY(part_table, part_no);
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
