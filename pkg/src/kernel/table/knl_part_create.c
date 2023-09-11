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
 * knl_part_create.c
 *
 *
 * IDENTIFICATION
 * src/kernel/table/knl_part_create.c
 *
 * -------------------------------------------------------------------------
 */
 
#include "knl_part_output.h"
#include "cm_hash.h"
#include "cm_log.h"
#include "index_common.h"
#include "knl_table.h"
#include "ostat_load.h"
#include "knl_lob.h"
#include "knl_heap.h"
#include "knl_sys_part_defs.h"
#include "knl_part_inner.h"

typedef struct st_part_table_compatible_arr {
    bool32 is_compatible;
    char *err_str_part1;
    char *err_str_part2;
} part_table_compatible_arr_t;

/*
 * the compatible array is:
 * table/partition space    ---------------------------------------------
 *                          |       |common |  temp | temp2(nologging)  |
 *                          ---------------------------------------------
 *                          |common |   1   |   0   |        0          |
 *                          ---------------------------------------------
 *                          |temp   |   1   |   1   |        0          |
 *                          ---------------------------------------------
 *                          |temp2  |   0   |   0   |        1          |
 *                          ---------------------------------------------
 */
part_table_compatible_arr_t g_compatible_arr[][COMPATIBLE_TABLESPACE_COUNT] = {
    {
        {GS_TRUE, NULL, NULL},
        {GS_FALSE, "add logging partition", "temp tablespace"},
        {GS_FALSE, "add logging partition", "nologging tablespace"}
    },
    {
        {GS_TRUE, NULL, NULL},
        {GS_TRUE, NULL, NULL},
        {GS_FALSE, "add partition with nologging tablespace", "temp table"}
    },
    {
        {GS_FALSE, "add nologging partition", "logging tablespace"},
        {GS_FALSE, "add nologging partition", "temp tablespace"},
        {GS_TRUE, NULL, NULL}
    }
};

static void part_init_table_desc(table_t *table, knl_part_obj_def_t *def, knl_part_desc_t *desc)
{
    desc->uid = table->desc.uid;
    desc->table_id = table->desc.id;
    desc->index_id = GS_INVALID_ID32;
    desc->parttype = def->part_type;
    desc->partcnt = def->parts.count;
    desc->partkeys = def->part_keys.count;
    desc->flags = 0;

    if (def->is_composite) {
        desc->flags |= PART_TABLE_SUBPARTED;
    }
    
    desc->interval = def->interval;
    desc->binterval = def->binterval;
    desc->subparttype = def->subpart_type;
    desc->subpartkeys = def->subpart_keys.count;
    desc->is_slice = def->is_slice;
}

status_t db_write_sys_partobject(knl_session_t *session, knl_cursor_t *cursor, knl_part_desc_t *desc)
{
    table_t *table = NULL;
    row_assist_t ra;

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_PARTOBJECT_ID, GS_INVALID_ID32);
    table = (table_t *)cursor->table;

    row_init(&ra, (char *)cursor->row, HEAP_MAX_ROW_SIZE(session), table->desc.column_count);
    (void)row_put_int32(&ra, desc->uid);
    (void)row_put_int32(&ra, desc->table_id);
    (void)row_put_int32(&ra, desc->index_id);
    (void)row_put_int32(&ra, desc->parttype);
    (void)row_put_int32(&ra, desc->partcnt);
    (void)row_put_int32(&ra, desc->partkeys);
    (void)row_put_int32(&ra, desc->flags);
    (void)row_put_text(&ra, &desc->interval);
    (void)row_put_bin(&ra, &desc->binterval);
    (void)row_put_int32(&ra, desc->subpartkeys);
    (void)row_put_int32(&ra, desc->subparttype);
    (void)row_put_int32(&ra, desc->is_slice);

    if (knl_internal_insert(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t part_init_table_part_desc(knl_session_t *session, table_t *table, knl_part_def_t *def,
    uint32 part_id, knl_table_part_desc_t *desc, bool32 not_ready)
{
    desc->uid = table->desc.uid;
    desc->table_id = table->desc.id;
    desc->part_id = part_id;
    desc->subpart_cnt = 0;
    (void)cm_text2str(&def->name, desc->name, GS_NAME_BUFFER_SIZE);
    desc->entry = INVALID_PAGID;
    desc->org_scn = db_inc_scn(session);
    desc->seg_scn = desc->org_scn;
    desc->initrans = (def->initrans == 0) ? table->desc.initrans : def->initrans;
    desc->pctfree = (def->pctfree == GS_INVALID_ID32) ? table->desc.pctfree : def->pctfree;
    desc->flags = 0;
    desc->is_csf = (def->is_csf == GS_INVALID_ID8) ? table->desc.is_csf : def->is_csf;
    if (def->space.len == 0) {
        desc->space_id = table->desc.space_id;
    } else {
        if (GS_SUCCESS != spc_get_space_id(session, &def->space, def->is_for_create_db, &desc->space_id)) {
            return GS_ERROR;
        }
        if (spc_check_by_uid(session, &def->space, desc->space_id, desc->uid) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }
    space_t *space = SPACE_GET(session, desc->space_id);
    desc->compress_algo = COMPRESS_NONE;
    if (def->compress_algo > COMPRESS_NONE) {
        desc->compress_algo = def->compress_algo;
    } else if (table->desc.compress_algo > COMPRESS_NONE) {
        desc->compress_algo = table->desc.compress_algo;
    }
    if (desc->compress_algo > COMPRESS_NONE) {
        if (!IS_SPACE_COMPRESSIBLE(space)) {
            GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "create or add compress part table",
                "non user bitmap tablespace");
            return GS_ERROR;
        }
    }
    desc->compress = (desc->compress_algo > COMPRESS_NONE) ? GS_TRUE : GS_FALSE;

    if (def->is_parent) {
        desc->is_parent = GS_TRUE;
    }
    
    if (not_ready) {
        desc->not_ready = GS_TRUE;
    }
    
    errno_t err = memset_sp(&desc->storage_desc, sizeof(knl_storage_desc_t), 0, sizeof(knl_storage_desc_t));
    knl_securec_check(err);

    if (def->storage_def.initial > 0) {
        if (!dc_is_reserved_entry(table->desc.uid, table->desc.id)) {
            desc->storaged = GS_TRUE;
        }
        desc->storage_desc.initial = CM_CALC_ALIGN((uint64)def->storage_def.initial, space->ctrl->block_size) /
            space->ctrl->block_size;
    }

    // storage maxsize clause will not take effect to sys tables
    if (def->storage_def.maxsize > 0 && !dc_is_reserved_entry(table->desc.uid, table->desc.id)) {
        desc->storaged = GS_TRUE;
        desc->storage_desc.max_pages = CM_CALC_ALIGN((uint64)def->storage_def.maxsize, space->ctrl->block_size) /
            space->ctrl->block_size;
    }

    desc->hiboundval = def->hiboundval;
    desc->bhiboundval.bytes = (uint8 *)def->partkey;
    desc->bhiboundval.size = def->partkey->size;

    desc->cr_mode = table->desc.cr_mode;

    return GS_SUCCESS;
}

status_t db_write_sys_tablepart(knl_session_t *session, knl_cursor_t *cursor, knl_table_desc_t *table_desc,
                                knl_table_part_desc_t *desc)
{
    row_assist_t ra;
    space_t *part_space = SPACE_GET(session, desc->space_id);
    if (!SPACE_IS_ONLINE(part_space)) {
        GS_THROW_ERROR(ERR_SPACE_OFFLINE, part_space->ctrl->name, "space offline and write to tablepart$ failed");
        return GS_ERROR;
    }

    bool32 is_nologging = table_desc->type == TABLE_TYPE_NOLOGGING;
    uint32 table_space_attr = is_nologging ? (COMPATIBLE_TABLESPACE_COUNT - 1) : 0;   // 2: nologging space
    bool32 is_temp = table_desc->type == TABLE_TYPE_TRANS_TEMP || table_desc->type == TABLE_TYPE_SESSION_TEMP;
    table_space_attr |= (uint32)is_temp;

    // temp(swap) is SPACE_TYPE_TEMP | SPACE_TYPE_SWAP | SPACE_TYPE_DEFAULT;
    // temp2(nologging) is SPACE_TYPE_TEMP | SPACE_TYPE_USERS | SPACE_TYPE_DEFAULT;
    bool32 is_user = IS_USER_SPACE(SPACE_GET(session, desc->space_id));
    is_temp = IS_TEMP_SPACE(SPACE_GET(session, desc->space_id));
    uint32 part_space_attr = is_temp ? (COMPATIBLE_TABLESPACE_COUNT - 1) : 0;
    part_space_attr = is_user ? part_space_attr : (uint32)is_temp;

    part_table_compatible_arr_t *item = &g_compatible_arr[table_space_attr][part_space_attr];
    if (!item->is_compatible) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, item->err_str_part1, item->err_str_part2);
        return GS_ERROR;
    }

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_TABLEPART_ID, GS_INVALID_ID32);
    table_t *table = (table_t *)cursor->table;

    row_init(&ra, (char *)cursor->row, HEAP_MAX_ROW_SIZE(session), table->desc.column_count);

    if (desc->hiboundval.len > PART_HIBOUND_VALUE_LENGTH || desc->bhiboundval.size > PART_HIBOUND_VALUE_LENGTH) {
        GS_THROW_ERROR(ERR_ROW_SIZE_TOO_LARGE, ra.max_size);
        return GS_ERROR;
    }

    (void)row_put_int32(&ra, desc->uid);
    (void)row_put_int32(&ra, desc->table_id);
    (void)row_put_int32(&ra, desc->part_id);
    (void)row_put_str(&ra, desc->name);
    (void)row_put_int32(&ra, desc->hiboundval.len);
    (void)row_put_text(&ra, &desc->hiboundval);
    (void)row_put_int32(&ra, desc->space_id);
    (void)row_put_int64(&ra, desc->org_scn);
    (void)row_put_int64(&ra, *(int64 *)&desc->entry);
    (void)row_put_int32(&ra, desc->initrans);
    (void)row_put_int32(&ra, desc->pctfree);
    (void)row_put_int32(&ra, desc->flags);
    (void)row_put_bin(&ra, &desc->bhiboundval);

    row_put_null(&ra);  // row_cnt
    row_put_null(&ra);  // blk_cnt
    row_put_null(&ra);  // emp_cnt
    row_put_null(&ra);  // avg_len
    row_put_null(&ra);  // sample_size
    row_put_null(&ra);  // analyse_time
    (void)row_put_int32(&ra, desc->subpart_cnt);

    status_t status = knl_internal_insert(session, cursor);
    return status;
}

static void part_init_column_desc(uint32 pos_id, table_t *table, knl_part_column_def_t *def,
                                  knl_part_column_desc_t *desc)
{
    desc->uid = table->desc.uid;
    desc->table_id = table->desc.id;
    desc->pos_id = pos_id;
    desc->column_id = def->column_id;
    desc->datatype = def->datatype;
}

status_t db_write_sys_partcolumn(knl_session_t *session, knl_cursor_t *cursor, knl_part_column_desc_t *desc)
{
    table_t *table = NULL;
    row_assist_t ra;

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_PARTCOLUMN_ID, GS_INVALID_ID32);
    table = (table_t *)cursor->table;

    row_init(&ra, (char *)cursor->row, HEAP_MAX_ROW_SIZE(session), table->desc.column_count);
    (void)row_put_int32(&ra, desc->uid);
    (void)row_put_int32(&ra, desc->table_id);
    (void)row_put_int32(&ra, desc->column_id);
    (void)row_put_int32(&ra, desc->pos_id);
    (void)row_put_int32(&ra, desc->datatype);

    if (knl_internal_insert(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static void part_init_part_store_desc(knl_part_desc_t *object_desc, knl_part_store_desc_t *desc, uint32 pos_id,
                                      uint32 space_id)
{
    desc->uid = object_desc->uid;
    desc->table_id = object_desc->table_id;
    desc->index_id = object_desc->index_id;
    desc->pos_id = pos_id;
    desc->space_id = space_id;
}

status_t db_write_sys_partstore(knl_session_t *session, knl_cursor_t *cursor, knl_part_store_desc_t *store_desc)
{
    table_t *table = NULL;
    row_assist_t ra;
    space_t *space;
    status_t status;

    space = SPACE_GET(session, store_desc->space_id);
    if (!SPACE_IS_ONLINE(space)) {
        GS_THROW_ERROR(ERR_SPACE_OFFLINE, space->ctrl->name, "space offline and write to partstore$ failed");
        return GS_ERROR;
    }

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_PARTSTORE_ID, GS_INVALID_ID32);
    table = (table_t *)cursor->table;

    row_init(&ra, cursor->buf, HEAP_MAX_ROW_SIZE(session), table->desc.column_count);
    (void)row_put_int32(&ra, store_desc->uid);
    (void)row_put_int32(&ra, store_desc->table_id);
    (void)row_put_int32(&ra, store_desc->index_id);
    (void)row_put_int32(&ra, store_desc->pos_id);
    (void)row_put_int32(&ra, store_desc->space_id);

    status = knl_internal_insert(session, cursor);

    return status;
}

static status_t db_verify_interval_part_key(knl_part_obj_def_t *def)
{
    knl_part_def_t *part_def;
    date_t *bound = NULL;
    part_key_t *key = NULL;
    knl_part_key_t part_key;
    date_detail_t detail;
    uint32 last = def->parts.count - 1;
    knl_part_column_def_t *column;
    uint8 bits;

    column = (knl_part_column_def_t *)cm_galist_get(&def->part_keys, 0);
    part_def = (knl_part_def_t *)cm_galist_get(&def->parts, last);
    key = part_def->partkey;
    knl_panic(def->part_keys.count == 1);
    bits = part_get_key_bits((part_key_t *)def->binterval.bytes, 0);

    // check interval high bounds for date,
    // it is not permitted to set 29,30,31 day as transition part date bound(eg:2018-7-29 is high bounds)
    if (GS_IS_DATETIME_TYPE(column->datatype)) {
        knl_decode_part_key(key, &part_key);
        bound = (date_t *)PART_GET_INTERVAL_KEY(&part_key.decoder);

        cm_decode_date(*bound, &detail);

        // interval is month and day > 28
        if (bits == PART_KEY_BITS_4 && detail.day > PART_INTERVAL_DAY_HIGH_BOUND) {
            GS_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "specify this interval with existing high bounds");
            return GS_ERROR;
        }
    }

    if (part_check_interval_valid((part_key_t *)def->binterval.bytes) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "interval is zero or less zero");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t db_check_subpart_count_valid(knl_part_obj_def_t *def)
{
    int64 total_subparts = 0;
    knl_part_def_t *part_def = NULL;

    for (uint32 i = 0; i < def->parts.count; i++) {
        part_def = (knl_part_def_t *)cm_galist_get(&def->parts, i);
        if (part_def->subparts.count > GS_MAX_SUBPART_COUNT) {
            GS_THROW_ERROR(ERR_EXCEED_MAX_SUBPARTCNT, (uint32)GS_MAX_SUBPART_COUNT);
            return GS_ERROR;
        }

        if (def->subpart_type == PART_TYPE_HASH && part_def->subparts.count > GS_MAX_HASH_SUBPART_COUNT) {
            GS_THROW_ERROR(ERR_EXCEED_MAX_SUBPARTCNT, (uint32)GS_MAX_HASH_SUBPART_COUNT);
            return GS_ERROR;
        }
        
        total_subparts += part_def->subparts.count;
    }

    if (def->subpart_type == PART_TYPE_HASH && total_subparts > GS_MAX_HASH_PART_COUNT) {
        GS_THROW_ERROR(ERR_EXCEED_MAX_PARTCNT, (uint32)GS_MAX_HASH_PART_COUNT);
        return GS_ERROR;
    } else if (total_subparts > GS_MAX_PART_COUNT) {
        GS_THROW_ERROR(ERR_EXCEED_MAX_PARTCNT, (uint32)GS_MAX_PART_COUNT);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t db_check_part_count_valid(knl_part_obj_def_t *def)
{
    // for hash partition, the total partition count should less than GS_MAX_PART_COUNT / 2
    if (def->part_type == PART_TYPE_HASH && def->parts.count > GS_MAX_HASH_PART_COUNT) {
        GS_THROW_ERROR(ERR_EXCEED_MAX_PARTCNT, (uint32)GS_MAX_HASH_PART_COUNT);
        return GS_ERROR;
    } else if (def->parts.count > GS_MAX_PART_COUNT) {
        GS_THROW_ERROR(ERR_EXCEED_MAX_PARTCNT, (uint32)GS_MAX_PART_COUNT);
        return GS_ERROR;
    } else {
        if (db_check_subpart_count_valid(def) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static bool32 db_compare_subpart_name(knl_part_obj_def_t *def, knl_part_def_t *subpart_def, uint32 com_idx,
    uint32 sub_idx)
{
    knl_part_def_t *cmp_def = NULL;
    knl_part_def_t *sub_cmp_def = NULL;

    for (uint32 m = com_idx; m < def->parts.count; m++) {
        cmp_def = cm_galist_get(&def->parts, m);
        if (cmp_def->subparts.count == 0) {
            continue;
        }
            
        for (uint32 n = 0; n < cmp_def->subparts.count; n++) {
            if (m == com_idx && n == sub_idx) {
                continue;
            }

            sub_cmp_def = (knl_part_def_t *)cm_galist_get(&cmp_def->subparts, n);
            if (cm_compare_text(&subpart_def->name, &sub_cmp_def->name) == 0) {
                return GS_TRUE;
            }
        }
    }

    return GS_FALSE;
}

status_t db_check_subpart_name_duplicate(knl_part_obj_def_t *def)
{
    knl_part_def_t *part_def = NULL;
    knl_part_def_t *sub_part_def = NULL;

    /* check sub part name with other sub part name */
    for (uint32 i = 0; i < def->parts.count; i++) {
        part_def = cm_galist_get(&def->parts, i);
        if (part_def->subparts.count == 0) {
            continue;
        }
            
        for (uint32 j = 0; j < part_def->subparts.count; j++) {
            sub_part_def = (knl_part_def_t *)cm_galist_get(&part_def->subparts, j);
            if (db_compare_subpart_name(def, sub_part_def, i, j)) {
                GS_THROW_ERROR(ERR_DUPLICATE_SUBPART_NAME);
                return GS_ERROR;
            }
        }
    }
    
    return GS_SUCCESS;
}

static status_t db_check_part_name_duplicate(knl_part_obj_def_t *def)
{
    knl_part_def_t *part_def = NULL;
    knl_part_def_t *sub_part_def = NULL;
    knl_part_def_t *cmp_def = NULL;

    /* check part name with other part name and all sub part name */
    for (uint32 i = 0; i < def->parts.count; i++) {
        part_def = (knl_part_def_t *)cm_galist_get(&def->parts, i);

        for (uint32 j = 0; j < def->parts.count; j++) {
            cmp_def = (knl_part_def_t *)cm_galist_get(&def->parts, j);
            if (j > i) {
                if (cm_compare_text(&part_def->name, &cmp_def->name) == 0) {
                    GS_THROW_ERROR(ERR_DUPLICATE_PART_NAME);
                    return GS_ERROR;
                }
            }
            
            if (!cmp_def->is_parent) {
                continue;
            }
            
            for (uint32 m = 0; m < cmp_def->subparts.count; m++) {
                sub_part_def = (knl_part_def_t *)cm_galist_get(&cmp_def->subparts, m);
                if (cm_compare_text(&part_def->name, &sub_part_def->name) == 0) {
                    GS_THROW_ERROR(ERR_DUPLICATE_PART_NAME);
                    return GS_ERROR;
                }
            }
        }
    }

    if (def->is_composite) {
        return db_check_subpart_name_duplicate(def);
    }
    
    return GS_SUCCESS;
}

/*
 * verify part table definition
 * @param kernel session, part table definition
 */
static status_t db_verify_part_table_def(knl_session_t *session, knl_table_def_t *table_def)
{
    knl_part_obj_def_t *def = table_def->part_def;
    knl_part_column_def_t *part_column_def = NULL;
    knl_column_def_t *col_def = NULL;

    if (db_check_part_count_valid(def) != GS_SUCCESS) {
        return GS_ERROR;
    }

    for (uint32 i = 0; i < def->part_keys.count; i++) {
        part_column_def = (knl_part_column_def_t *)cm_galist_get(&def->part_keys, i);
        col_def = (knl_column_def_t *)cm_galist_get(&table_def->columns, part_column_def->column_id);
        if (GS_IS_LOB_TYPE(col_def->datatype) || col_def->typmod.is_array) {
            GS_THROW_ERROR(ERR_LOB_PART_COLUMN);
            return GS_ERROR;
        }
    }

    /* check subpart column type */
    if (def->is_composite) {
        for (uint32 i = 0; i < def->subpart_keys.count; i++) {
            part_column_def = (knl_part_column_def_t *)cm_galist_get(&def->subpart_keys, i);
            col_def = (knl_column_def_t *)cm_galist_get(&table_def->columns, part_column_def->column_id);
            if (GS_IS_LOB_TYPE(col_def->datatype) || col_def->typmod.is_array) {
                GS_THROW_ERROR(ERR_LOB_PART_COLUMN);
                return GS_ERROR;
            }
        }
    }
    
    if (db_check_part_name_duplicate(def) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (def->is_interval) {
        if (db_verify_interval_part_key(def) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

bool32 check_part_encrypt_allowed(knl_session_t *session, bool32 is_encrypt_table, uint32 space_id)
{
    space_t *space = SPACE_GET(session, space_id);
    bool32 is_encrypt_part = SPACE_IS_ENCRYPT(space);
    if (is_encrypt_part != is_encrypt_table) {
        return GS_FALSE;
    }
    return GS_TRUE;
}

static status_t db_write_table_subparts(knl_session_t *session, knl_cursor_t *cursor, knl_table_part_desc_t *comdesc,
    knl_part_def_t *compart_def)
{
    uint32 subpart_id;
    knl_part_def_t *part_def = NULL;
    table_part_t table_subpart;
    bool32 is_encrypt_table = SPACE_IS_ENCRYPT(SPACE_GET(session, comdesc->space_id));

    for (uint32 i = 0; i < compart_def->subparts.count; i++) {
        part_def = (knl_part_def_t *)cm_galist_get(&compart_def->subparts, i);
        subpart_id = subpart_generate_partid(NULL, NULL, i);
        if (subpart_init_table_part_desc(session, comdesc, part_def, subpart_id, &table_subpart.desc) != GS_SUCCESS) {
            return GS_ERROR;
        }
        
        if (!check_part_encrypt_allowed(session, is_encrypt_table, table_subpart.desc.space_id)) {
            GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "create partition", "cases: create encrypt partition on \
non-encrypt part table or create non-encrypt partition on encrypt part table.");
            return GS_ERROR;
        }

        if (IS_SWAP_SPACE(SPACE_GET(session, table_subpart.desc.space_id))) {
            GS_THROW_ERROR(ERR_PERMANENTOBJ_IN_TEMPSPACE);
            return GS_ERROR;
        }

        if (dc_is_reserved_entry(comdesc->uid, comdesc->table_id)) {
            if (heap_create_part_segment(session, &table_subpart) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        if (db_write_sys_tablesubpart(session, cursor, &table_subpart.desc) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t db_write_table_parts(knl_session_t *session, knl_cursor_t *cursor, table_t *table,
                                     knl_part_obj_def_t *def)
{
    uint32 i, part_id;
    knl_part_def_t *part_def = NULL;
    table_part_t table_part;
    bool32 is_encrypt_table = SPACE_IS_ENCRYPT(SPACE_GET(session, table->desc.space_id));

    for (i = 0; i < def->parts.count; i++) {
        part_def = (knl_part_def_t *)cm_galist_get(&def->parts, i);
        part_id = part_generate_part_id(table, i);
        if (part_init_table_part_desc(session, table, part_def, part_id, &table_part.desc, GS_FALSE) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (part_def->is_parent) {
            table_part.desc.subpart_cnt = part_def->subparts.count;
        }
        
        if (!check_part_encrypt_allowed(session, is_encrypt_table, table_part.desc.space_id)) {
            GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "create partition", "cases: create encrypt partition on \
non-encrypt part table or create non-encrypt partition on encrypt part table.");
            return GS_ERROR;
        }

        if (IS_SWAP_SPACE(SPACE_GET(session, table_part.desc.space_id))) {
            GS_THROW_ERROR(ERR_PERMANENTOBJ_IN_TEMPSPACE);
            return GS_ERROR;
        }

        if (IS_SYS_TABLE(table) && !part_def->is_parent) {
            if (heap_create_part_segment(session, &table_part) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        if (db_write_sys_tablepart(session, cursor, &table->desc, &table_part.desc) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (table_part.desc.storaged && db_write_sysstorage(session, cursor, table_part.desc.org_scn,
            &table_part.desc.storage_desc) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (table_part.desc.compress) {
            if (db_write_syscompress(session, cursor, table_part.desc.space_id, table_part.desc.org_scn,
                table_part.desc.compress_algo, COMPRESS_OBJ_TYPE_TABLE_PART) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        if (part_def->is_parent) {
            if (db_write_table_subparts(session, cursor, &table_part.desc, part_def) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }

    return GS_SUCCESS;
}

static status_t db_write_sys_subpartcolumn(knl_session_t *session, knl_cursor_t *cursor, knl_part_column_desc_t *desc)
{
    table_t *table = NULL;
    row_assist_t ra;

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_SUB_PARTCOLUMN_ID, GS_INVALID_ID32);
    table = (table_t *)cursor->table;

    row_init(&ra, (char *)cursor->row, HEAP_MAX_ROW_SIZE(session), table->desc.column_count);
    (void)row_put_int32(&ra, desc->uid);
    (void)row_put_int32(&ra, desc->table_id);
    (void)row_put_int32(&ra, desc->column_id);
    (void)row_put_int32(&ra, desc->pos_id);
    (void)row_put_int32(&ra, desc->datatype);

    if (knl_internal_insert(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t db_create_part_table(knl_session_t *session, knl_cursor_t *cursor, table_t *table, knl_table_def_t *table_def)
{
    uint32 space_id;
    knl_part_desc_t object_desc;
    knl_part_column_desc_t column_desc;
    knl_part_store_desc_t store_desc;
    knl_part_obj_def_t *def = table_def->part_def;

    if (db_verify_part_table_def(session, table_def) != GS_SUCCESS) {
        return GS_ERROR;
    }

    errno_t ret = memset_sp(&object_desc, sizeof(knl_part_desc_t), 0, sizeof(knl_part_desc_t));
    knl_securec_check(ret);
    part_init_table_desc(table, def, &object_desc);

    if (db_write_sys_partobject(session, cursor, &object_desc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (def->is_interval) {
        for (uint32 i = 0; i < def->part_store_in.space_list.count; i++) {
            text_t *name = (text_t *)cm_galist_get(&def->part_store_in.space_list, i);
            if (GS_SUCCESS != spc_get_space_id(session, name, def->is_for_create_db, &space_id)) {
                return GS_ERROR;
            }
            if (spc_check_by_uid(session, name, space_id, table->desc.uid) != GS_SUCCESS) {
                return GS_ERROR;
            }

            part_init_part_store_desc(&object_desc, &store_desc, i, space_id);

            if (db_write_sys_partstore(session, cursor, &store_desc) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }

    for (uint32 i = 0; i < def->part_keys.count; i++) {
        knl_part_column_def_t *column_def = (knl_part_column_def_t *)cm_galist_get(&def->part_keys, i);
        part_init_column_desc(i, table, column_def, &column_desc);

        if (db_write_sys_partcolumn(session, cursor, &column_desc) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (def->is_composite) {
        for (uint32 i = 0; i < def->subpart_keys.count; i++) {
            knl_part_column_def_t *column_def = (knl_part_column_def_t *)cm_galist_get(&def->subpart_keys, i);
            part_init_column_desc(i, table, column_def, &column_desc);

            if (db_write_sys_subpartcolumn(session, cursor, &column_desc) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }

    if (db_write_table_parts(session, cursor, table, def) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static void part_init_index_desc(index_t *index, knl_part_desc_t *part_desc, knl_part_desc_t *desc)
{
    desc->uid = index->desc.uid;
    desc->table_id = index->desc.table_id;
    desc->index_id = index->desc.id;
    desc->parttype = part_desc->parttype;
    desc->subparttype = part_desc->subparttype;
    desc->partcnt = part_desc->partcnt;
    desc->partkeys = part_desc->partkeys;
    desc->subpartkeys = part_desc->subpartkeys;
    desc->flags = part_desc->flags;
    desc->interval = part_desc->interval;
    desc->binterval = part_desc->binterval;
}

static uint32 part_get_index_part_space_id(knl_handle_t knl_index, knl_table_part_desc_t *part_desc)
{
    index_t *index = (index_t *)knl_index;
    part_index_t *part_index = index->part_index;
    index_part_t *compart = NULL;
    table_part_t *table_part = NULL;
    table_t *table = &index->entity->table;
    part_table_t *part_table = table->part_table;

    if (part_index && IS_COMPART_INDEX(part_index) && !IS_PARENT_TABPART(part_desc)) {
        uint32 i = 0;
        for (; i < part_table->desc.partcnt; i++) {
            table_part = TABLE_GET_PART(table, i);
            compart = INDEX_GET_PART(index, i);
            if (!IS_READY_PART(table_part) || compart == NULL) {
                continue;
            }

            if (table_part->desc.part_id == part_desc->parent_partid) {
                return compart->desc.is_stored ?  compart->desc.space_id : part_desc->space_id;
            }
        }
    }

    return (index->desc.is_stored) ? index->desc.space_id : part_desc->space_id;
}

void part_generate_index_part_desc(knl_session_t *session, knl_handle_t knl_index, knl_table_part_desc_t *part_desc,
    knl_index_part_desc_t *desc)
{
    errno_t ret;
    index_t *index = (index_t *)knl_index;

    desc->space_id = part_get_index_part_space_id(knl_index, part_desc);
    desc->uid = index->desc.uid;
    desc->table_id = index->desc.table_id;
    desc->index_id = index->desc.id;
    desc->part_id = part_desc->part_id;
    desc->parent_partid = part_desc->parent_partid;
    ret = memcpy_sp(desc->name, GS_NAME_BUFFER_SIZE, part_desc->name, GS_NAME_BUFFER_SIZE);
    knl_securec_check(ret);
    desc->entry = INVALID_PAGID;
    desc->org_scn = db_inc_scn(session);
    desc->seg_scn = desc->org_scn;
    desc->initrans = index->desc.initrans;
    desc->pctfree = index->desc.pctfree;
    desc->flags = index->desc.flags;
    desc->is_cons = index->desc.is_cons;
    desc->is_disabled = index->desc.is_disabled;
    desc->is_invalid = index->desc.is_invalid;
    desc->is_stored = index->desc.is_stored;
    desc->is_encode = index->desc.is_encode;
    desc->is_func = index->desc.is_func;
    desc->is_parent = IS_PARENT_TABPART(part_desc) ? GS_TRUE : GS_FALSE;
    desc->is_not_ready = part_desc->not_ready;
    
    desc->hiboundval = part_desc->hiboundval;
    desc->bhiboundval = part_desc->bhiboundval;
    desc->cr_mode = index->desc.cr_mode;
}

static status_t part_init_index_part_desc(knl_session_t *session, knl_handle_t knl_index, knl_part_def_t *def,
    knl_table_part_desc_t *tablepart_desc, knl_index_part_desc_t *desc)
{
    index_t *index = (index_t *)knl_index;
    desc->uid = index->desc.uid;
    desc->table_id = index->desc.table_id;
    desc->index_id = index->desc.id;
    desc->part_id = tablepart_desc->part_id;
    desc->subpart_cnt = tablepart_desc->subpart_cnt;
    (void)cm_text2str(&def->name, desc->name, GS_NAME_BUFFER_SIZE);

    if (def->space.len == 0) {
        desc->space_id = (index->desc.is_stored) ? index->desc.space_id : tablepart_desc->space_id;
    } else {
        if (GS_SUCCESS != spc_get_space_id(session, &def->space, def->is_for_create_db, &desc->space_id)) {
            return GS_ERROR;
        }
        if (spc_check_by_uid(session, &def->space, desc->space_id, index->desc.uid) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    desc->entry = INVALID_PAGID;
    desc->org_scn = db_inc_scn(session);
    desc->initrans = (def->initrans == 0) ? index->desc.initrans : def->initrans;
    desc->pctfree = (def->pctfree == GS_INVALID_ID32) ? index->desc.pctfree : def->pctfree;
    desc->flags = index->desc.flags;
    desc->is_cons = index->desc.is_cons;
    desc->is_disabled = index->desc.is_disabled;
    desc->is_invalid = index->desc.is_invalid;
    desc->is_stored = def->space.len != 0;
    desc->is_encode = index->desc.is_encode;
    desc->is_func = index->desc.is_func;
    desc->is_parent = IS_PARENT_TABPART(tablepart_desc) ? GS_TRUE : GS_FALSE;
        
    desc->hiboundval = tablepart_desc->hiboundval;
    desc->bhiboundval = tablepart_desc->bhiboundval;
    desc->cr_mode = index->desc.cr_mode;

    return GS_SUCCESS;
}

status_t db_write_sys_indexpart(knl_session_t *session, knl_cursor_t *cursor, knl_index_part_desc_t *desc)
{
    row_assist_t ra;

    space_t *space = SPACE_GET(session, desc->space_id);
    if (!SPACE_IS_ONLINE(space)) {
        GS_THROW_ERROR(ERR_SPACE_OFFLINE, space->ctrl->name, "space offline and write to indexpart$ failed");
        return GS_ERROR;
    }

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_INDEXPART_ID, GS_INVALID_ID32);
    table_t *table = (table_t *)cursor->table;

    row_init(&ra, (char *)cursor->row, HEAP_MAX_ROW_SIZE(session), table->desc.column_count);
    if (desc->hiboundval.len > PART_HIBOUND_VALUE_LENGTH) {
        GS_THROW_ERROR(ERR_ROW_SIZE_TOO_LARGE, ra.max_size);
        return GS_ERROR;
    }
    if (desc->bhiboundval.size > PART_HIBOUND_VALUE_LENGTH) {
        GS_THROW_ERROR(ERR_ROW_SIZE_TOO_LARGE, ra.max_size);
        return GS_ERROR;
    }
    (void)row_put_int32(&ra, desc->uid);
    (void)row_put_int32(&ra, desc->table_id);
    (void)row_put_int32(&ra, desc->index_id);
    (void)row_put_int32(&ra, desc->part_id);
    (void)row_put_str(&ra, desc->name);
    (void)row_put_int32(&ra, desc->hiboundval.len);
    (void)row_put_text(&ra, &desc->hiboundval);
    (void)row_put_int32(&ra, desc->space_id);
    (void)row_put_int64(&ra, desc->org_scn);
    (void)row_put_int64(&ra, *(int64 *)&desc->entry);
    (void)row_put_int32(&ra, desc->initrans);
    (void)row_put_int32(&ra, desc->pctfree);
    (void)row_put_int32(&ra, desc->flags);
    (void)row_put_bin(&ra, &desc->bhiboundval);
    row_put_null(&ra);  // blevel reserved
    row_put_null(&ra);  // level_block reserved
    row_put_null(&ra);  // distkey reserved
    row_put_null(&ra);  // lblkkey reserved
    row_put_null(&ra);  // dblkkey reserved
    row_put_null(&ra);  // analyzetime reserved
    row_put_null(&ra);  // empty leaf blocks reserved
    row_put_null(&ra);  // clufac reserved
    row_put_null(&ra);  // samplesize reserved
    row_put_null(&ra);  // comb_cols_2_ndv reserved
    row_put_null(&ra);  // comb_cols_3_ndv reserved
    row_put_null(&ra);  // comb_cols_4_ndv reserved
    (void)row_put_int32(&ra, desc->subpart_cnt);

    status_t status = knl_internal_insert(session, cursor);

    return status;
}

status_t part_write_sys_shadowindex_part(knl_session_t *session, knl_index_part_desc_t *desc)
{
    table_t *table = NULL;
    row_assist_t ra;
    knl_cursor_t *cursor = NULL;
    space_t *space;
    status_t status;

    space = SPACE_GET(session, desc->space_id);
    if (!SPACE_IS_ONLINE(space)) {
        GS_THROW_ERROR(ERR_SPACE_OFFLINE, space->ctrl->name, "space offline and write to shadow_indexpart$ failed");
        return GS_ERROR;
    }

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_SHADOW_INDEXPART_ID, GS_INVALID_ID32);
    table = (table_t *)cursor->table;

    row_init(&ra, (char *)cursor->row, HEAP_MAX_ROW_SIZE(session), table->desc.column_count);

    (void)row_put_int32(&ra, desc->uid);
    (void)row_put_int32(&ra, desc->table_id);
    (void)row_put_int32(&ra, desc->index_id);
    (void)row_put_int32(&ra, desc->part_id);
    (void)row_put_str(&ra, desc->name);
    (void)row_put_int32(&ra, desc->hiboundval.len);
    (void)row_put_text(&ra, &desc->hiboundval);
    (void)row_put_int32(&ra, desc->space_id);
    (void)row_put_int64(&ra, desc->org_scn);
    (void)row_put_int64(&ra, *(int64 *)&desc->entry);
    (void)row_put_int32(&ra, desc->initrans);
    (void)row_put_int32(&ra, desc->pctfree);
    (void)row_put_int32(&ra, desc->flags);
    (void)row_put_bin(&ra, &desc->bhiboundval);
    (void)row_put_int32(&ra, desc->parent_partid);

    status = knl_internal_insert(session, cursor);

    CM_RESTORE_STACK(session->stack);
    return status;
}

status_t part_write_shadowindex_part(knl_session_t *session, knl_dictionary_t *dc,
    index_part_t *index_part, bool32 create_segment)
{
    if (create_segment && !IS_PARENT_IDXPART(&index_part->desc)) {
        if (btree_create_part_segment(session, index_part) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (btree_generate_create_undo(session, index_part->desc.entry, index_part->desc.space_id,
            IS_LOGGING_TABLE_BY_TYPE(dc->type)) != GS_SUCCESS) {
            btree_drop_part_segment(session, index_part);
            return GS_ERROR;
        }
    }

    if (part_write_sys_shadowindex_part(session, &index_part->desc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t subpart_create_shadowind_default(knl_session_t *session, knl_dictionary_t *dc, knl_handle_t knl_index,
    uint32 compart_no, rebuild_info_t rebuild_info)
{
    index_part_t index_subpart;
    index_part_t *old_index_subpart = NULL;
    index_part_t *index_compart = NULL;
    index_t *index = (index_t *)knl_index;
    dc_entity_t *entity = index->entity;
    part_table_t *part_table = entity->table.part_table;
    knl_part_locate_t part_loc;

    table_part_t *table_compart = PART_GET_ENTITY(part_table, compart_no);
    for (uint32 i = 0; i < table_compart->desc.subpart_cnt; i++) {
        part_loc.part_no = compart_no;
        part_loc.subpart_no = i;
        bool32 remain = !is_idx_part_existed(&part_loc, rebuild_info.parts_loc, GS_TRUE);
        if (remain || rebuild_info.is_alter) {
            index_compart = INDEX_GET_PART(index, compart_no);
            old_index_subpart = PART_GET_SUBENTITY(index->part_index, index_compart->subparts[i]);
            if (old_index_subpart == NULL) {
                continue;
            }
            
            errno_t ret = memcpy_sp(&index_subpart.desc, sizeof(knl_index_part_desc_t), &old_index_subpart->desc,
                sizeof(knl_index_part_desc_t));
            knl_securec_check(ret);

            if (!remain) {
                index_subpart.desc.entry = INVALID_PAGID;
                index_subpart.desc.pctfree = index->desc.pctfree;
                index_subpart.desc.is_invalid = GS_FALSE;
            }
            if (!remain && rebuild_info.spc_id != GS_INVALID_ID32) {
                index_subpart.desc.space_id = rebuild_info.spc_id;
                index_subpart.desc.is_stored = GS_TRUE;
            }
            if (db_allow_indexpart_rebuild(session, index_subpart.desc.space_id, old_index_subpart) != GS_SUCCESS) {
                return GS_ERROR;
            }
        } else {
            table_compart = PART_GET_ENTITY(part_table, compart_no);
            table_part_t *table_subpart = PART_GET_SUBENTITY(part_table, table_compart->subparts[i]);
            if (table_subpart == NULL) {
                continue;
            }

            part_generate_index_part_desc(session, index, &table_subpart->desc, &index_subpart.desc);
        }

        if (part_write_shadowindex_part(session, dc, (index_part_t *)&index_subpart, !remain) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t part_create_shadowindex_default(knl_session_t *session, knl_dictionary_t *dc,
    index_t *index, rebuild_info_t rebuild_info)
{
    errno_t ret;
    index_part_t index_part;
    dc_entity_t *entity = index->entity;
    part_table_t *part_table = entity->table.part_table;
    knl_part_locate_t part_loc;

    for (uint32 i = 0; i < part_table->desc.partcnt; i++) {
        table_part_t *table_part = PART_GET_ENTITY(part_table, i);
        if (!IS_READY_PART(table_part)) {
            continue;
        }
        
        part_loc.part_no = i;
        part_loc.subpart_no = GS_INVALID_ID32;
        bool32 remain = !is_idx_part_existed(&part_loc, rebuild_info.parts_loc, GS_FALSE);
        if (remain || rebuild_info.is_alter) {
            index_part_t *old_index_part = INDEX_GET_PART(index, i);

            if (old_index_part == NULL) {
                continue;
            }
            ret = memcpy_sp(&index_part.desc, sizeof(knl_index_part_desc_t), &old_index_part->desc,
                sizeof(knl_index_part_desc_t));
            knl_securec_check(ret);

            if (!remain) {
                index_part.desc.entry = INVALID_PAGID;
                index_part.desc.pctfree = index->desc.pctfree;
                index_part.desc.is_invalid = GS_FALSE;
            }

            if (!remain && rebuild_info.spc_id != GS_INVALID_ID32 &&
                rebuild_info.alter_index_type != ALINDEX_TYPE_REBUILD_SUBPART) {
                index_part.desc.space_id = rebuild_info.spc_id;
                index_part.desc.is_stored = GS_TRUE;
            }
            if (db_allow_indexpart_rebuild(session, index_part.desc.space_id, old_index_part) != GS_SUCCESS) {
                return GS_ERROR;
            }
        } else {
            part_generate_index_part_desc(session, index, &table_part->desc, &index_part.desc);
        }

        if (IS_PARENT_TABPART(&table_part->desc)) {
            if (subpart_create_shadowind_default(session, dc, index, table_part->part_no,
                rebuild_info) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        if (part_write_shadowindex_part(session, dc, &index_part, !remain) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t subpart_create_shwidx_with_def(knl_session_t *session, knl_dictionary_t *dc, knl_handle_t knl_index,
    knl_part_def_t *def, uint32 compart_no, bool32 is_alter)
{
    index_part_t index_subpart;
    knl_part_def_t *part_def = NULL;
    index_part_t *index_compart = NULL;
    table_part_t *table_subpart = NULL;
    index_part_t *old_index_subpart = NULL;
    index_t *index = (index_t *)knl_index;
    dc_entity_t *entity = index->entity;
    part_table_t *part_table = entity->table.part_table;

    table_part_t *table_compart = PART_GET_ENTITY(part_table, compart_no);
    if (def->subparts.count != table_compart->desc.subpart_cnt) {
        GS_THROW_ERROR(ERR_PARTCNT_NOT_MATCH);
        return GS_ERROR;
    }

    for (uint32 i = 0; i < def->subparts.count; i++) {
        part_def = (knl_part_def_t *)cm_galist_get(&def->subparts, i);
        table_subpart = PART_GET_SUBENTITY(part_table, table_compart->subparts[i]);
        if (table_subpart == NULL) {
            continue;
        }

        if (part_init_index_part_desc(session, index, part_def, &table_subpart->desc,
            &index_subpart.desc) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (is_alter) {
            index_compart = INDEX_GET_PART(index, compart_no);
            old_index_subpart = PART_GET_SUBENTITY(index->part_index, index_compart->subparts[i]);
            index_subpart.desc.org_scn = old_index_subpart->desc.org_scn;
        }

        if (part_write_shadowindex_part(session, dc, (index_part_t *)&index_subpart, GS_TRUE) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t part_create_shadowindex_with_def(knl_session_t *session, knl_dictionary_t *dc,
    knl_part_obj_def_t *def, index_t *index, bool32 is_alter)
{
    index_part_t index_part;
    table_part_t *table_part = NULL;
    knl_part_def_t *part_def = NULL;
    index_part_t *old_index_part = NULL;
    dc_entity_t *entity = index->entity;
    part_table_t *part_table = entity->table.part_table;

    if (def->parts.count != part_table->desc.partcnt) {
        GS_THROW_ERROR(ERR_PARTCNT_NOT_MATCH);
        return GS_ERROR;
    }

    for (uint32 i = 0; i < def->parts.count; i++) {
        part_def = (knl_part_def_t *)cm_galist_get(&def->parts, i);
        table_part = PART_GET_ENTITY(part_table, i);
        if (table_part == NULL) {
            continue;
        }

        if (part_init_index_part_desc(session, index, part_def, &table_part->desc, &index_part.desc) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (is_alter) {
            old_index_part = INDEX_GET_PART(index, i);
            index_part.desc.org_scn = old_index_part->desc.org_scn;
        }

        if (IS_PARENT_TABPART(&table_part->desc)) {
            if (subpart_create_shwidx_with_def(session, dc, index, part_def, table_part->part_no,
                is_alter) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
        
        if (part_write_shadowindex_part(session, dc, &index_part, GS_TRUE) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t db_create_part_shadow_index(knl_session_t *session, knl_dictionary_t *dc, index_t *index,
    knl_part_obj_def_t *def, rebuild_info_t rebuild_info)
{
    bool32 is_alter = rebuild_info.is_alter;

    if (def == NULL) {
        return part_create_shadowindex_default(session, dc, index, rebuild_info);
    } else {
        return part_create_shadowindex_with_def(session, dc, def, index, is_alter);
    }
}

status_t db_write_partindex(knl_session_t *session, knl_cursor_t *cursor, index_t *index)
{
    knl_part_desc_t object_desc;
    index_part_t *index_part = NULL;
    index_part_t *subpart = NULL;
    table_part_t *table_part = NULL;
    dc_entity_t *entity = index->entity;
    part_table_t *part_table = entity->table.part_table;

    part_init_index_desc(index, &part_table->desc, &object_desc);
    if (db_write_sys_partobject(session, cursor, &object_desc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    for (uint32 i = 0; i < part_table->desc.partcnt; i++) {
        index_part = INDEX_GET_PART(index, i);
        table_part = PART_GET_ENTITY(part_table, i);
        if (!IS_READY_PART(table_part) || index_part == NULL) {
            continue;
        }

        if (db_write_sys_indexpart(session, cursor, &index_part->desc) != GS_SUCCESS) {
            return GS_ERROR;
        }
        
        if (!IS_PARENT_IDXPART(&index_part->desc)) {
            continue;
        }

        for (uint32 j = 0; j < index_part->desc.subpart_cnt; j++) {
            subpart = PART_GET_SUBENTITY(index->part_index, index_part->subparts[j]);
            if (db_write_sys_indsubpart(session, cursor, &subpart->desc) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }

    return GS_SUCCESS;
}

status_t db_update_sub_idxpart_status(knl_session_t *session, index_part_t *index_part,
    bool32 is_invalid, bool32 *is_changed)
{
    row_assist_t ra;
    knl_index_part_desc_t desc;

    CM_SAVE_STACK(session->stack);

    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_SUB_INDEX_PARTS_ID, IX_SYS_INDEXSUBPART001_ID);

    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
        (void *)&index_part->desc.uid, sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
        (void *)&index_part->desc.table_id, sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
        (void *)&index_part->desc.index_id, sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_INDEX_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
        (void *)&index_part->desc.parent_partid, sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_PARENT_PART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
        (void *)&index_part->desc.part_id, sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_SUB_PART_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s index %s index_part %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                  ((table_t *)cursor->table)->desc.name, ((index_t *)cursor->index)->desc.name, index_part->desc.name);

    dc_convert_index_part_desc(cursor, &desc);

    if (!(*is_changed)) {
        *is_changed = desc.is_invalid != is_invalid;
    }

    desc.is_invalid = is_invalid;
    if (is_invalid) {
        row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), UPDATE_COLUMN_COUNT_TWO);
        (void)row_put_int64(&ra, *(int64 *)&INVALID_PAGID);
        (void)row_put_int32(&ra, desc.flags);
        cursor->update_info.count = UPDATE_COLUMN_COUNT_TWO;
        cursor->update_info.columns[0] = SYS_INDEXSUBPART_COL_ENTRY;  // index part entry
        cursor->update_info.columns[1] = SYS_INDEXSUBPART_COL_FLAGS;  // flags
    } else {
        row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), UPDATE_COLUMN_COUNT_ONE);
        (void)row_put_int32(&ra, desc.flags);
        cursor->update_info.count = UPDATE_COLUMN_COUNT_ONE;
        cursor->update_info.columns[0] = SYS_INDEXSUBPART_COL_FLAGS;  // flags
    }

    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, NULL);
    if (knl_internal_update(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t db_update_idxpart_status(knl_session_t *session, index_part_t *index_part,
    bool32 is_invalid, bool32 *is_changed)
{
    row_assist_t ra;
    knl_index_part_desc_t desc;

    CM_SAVE_STACK(session->stack);

    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_INDEXPART_ID, IX_SYS_INDEXPART001_ID);

    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
        (void *)&index_part->desc.uid, sizeof(uint32), IX_COL_SYS_INDEXPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
        (void *)&index_part->desc.table_id, sizeof(uint32), IX_COL_SYS_INDEXPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
        (void *)&index_part->desc.index_id, sizeof(uint32), IX_COL_SYS_INDEXPART001_INDEX_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
        (void *)&index_part->desc.part_id, sizeof(uint32), IX_COL_SYS_INDEXPART001_PART_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s index %s index_part %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                  ((table_t *)cursor->table)->desc.name, ((index_t *)cursor->index)->desc.name, index_part->desc.name);

    dc_convert_index_part_desc(cursor, &desc);

    if (!(*is_changed)) {
        *is_changed = desc.is_invalid != is_invalid;
    }

    desc.is_invalid = is_invalid;

    if (is_invalid) {
        row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), UPDATE_COLUMN_COUNT_TWO);
        (void)row_put_int64(&ra, *(int64 *)&INVALID_PAGID);
        (void)row_put_int32(&ra, desc.flags);
        cursor->update_info.count = UPDATE_COLUMN_COUNT_TWO;
        cursor->update_info.columns[0] = SYS_INDEXPART_COL_ENTRY;  // index part entry
        cursor->update_info.columns[1] = SYS_INDEXPART_COL_FLAGS;  // flags
    } else {
        row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), UPDATE_COLUMN_COUNT_ONE);
        (void)row_put_int32(&ra, desc.flags);
        cursor->update_info.count = UPDATE_COLUMN_COUNT_ONE;
        cursor->update_info.columns[0] = SYS_INDEXPART_COL_FLAGS;  // flags
    }

    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, NULL);
    if (knl_internal_update(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

/*
 * verify part index definition
 * @param kernel session, part table, part index definition
 */
static status_t db_verify_part_index_def(knl_session_t *session, part_table_t *part_table, knl_part_obj_def_t *def)
{
    table_part_t *table_part = NULL;
    knl_part_def_t *part_def = NULL;
    knl_part_def_t *cmp_def = NULL;
    knl_part_def_t *sub_part_def = NULL;

    if (def->parts.count != part_table->desc.partcnt) {
        GS_THROW_ERROR(ERR_PARTCNT_NOT_MATCH);
        return GS_ERROR;
    }

    for (uint32 i = 0; i < def->parts.count - 1; i++) {
        part_def = (knl_part_def_t *)cm_galist_get(&def->parts, i);
        table_part = PART_GET_ENTITY(part_table, i);
        if (IS_PARENT_TABPART(&table_part->desc) && part_def->subparts.count != table_part->desc.subpart_cnt) {
            GS_THROW_ERROR(ERR_PARTCNT_NOT_MATCH);
            return GS_ERROR;
        }

        for (uint32 j = 0; j < def->parts.count; j++) {
            cmp_def = (knl_part_def_t *)cm_galist_get(&def->parts, j);
            if (j > i) {
                if (cm_compare_text(&part_def->name, &cmp_def->name) == 0) {
                    GS_THROW_ERROR(ERR_DUPLICATE_PART_NAME);
                    return GS_ERROR;
                }
            }
            
            if (!def->is_composite) {
                continue;
            }
            for (uint32 m = 0; m < cmp_def->subparts.count; m++) {
                sub_part_def = (knl_part_def_t *)cm_galist_get(&cmp_def->subparts, m);
                if (cm_compare_text(&part_def->name, &sub_part_def->name) == 0) {
                    GS_THROW_ERROR(ERR_DUPLICATE_PART_NAME);
                    return GS_ERROR;
                }
            }
        }
    }

    if (def->is_composite) {
        return db_check_subpart_name_duplicate(def);
    }

    return GS_SUCCESS;
}

static status_t subpart_create_index_default(knl_session_t *session, knl_cursor_t *cursor, knl_handle_t knl_index,
    table_part_t *compart)
{
    index_part_t index_subpart;
    table_part_t *table_subpart = NULL;
    index_t *index = (index_t *)knl_index;
    dc_entity_t *entity = index->entity;
    table_t *table = &entity->table;
    uint32 is_encrypt_table = SPACE_IS_ENCRYPT(SPACE_GET(session, entity->table.desc.space_id));
    
    for (uint32 i = 0; i < compart->desc.subpart_cnt; i++) {
        table_subpart = PART_GET_SUBENTITY(table->part_table, compart->subparts[i]);
        if (table_subpart == NULL) {
            continue;
        }
    
        part_generate_index_part_desc(session, index, &table_subpart->desc, &index_subpart.desc);
    
        if (!check_part_encrypt_allowed(session, is_encrypt_table, index_subpart.desc.space_id)) {
            GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "create part index", "cases: create encrypt part index on \
    non-encrypt part table or create non-encrypt part index on encrypt part table.");
            return GS_ERROR;
        }
    
        if (IS_SYS_TABLE(&entity->table)) {
            if (btree_create_part_segment(session, &index_subpart) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
        
        if (db_write_sys_indsubpart(session, cursor, &index_subpart.desc) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }
    
    return GS_SUCCESS;
}

static status_t part_create_partindex_default(knl_session_t *session, knl_cursor_t *cursor, index_t *index,
    part_table_t *part_table)
{
    index_part_t index_part;
    table_part_t *table_part = NULL;
    dc_entity_t *entity = index->entity;
    uint32 is_encrypt_table = SPACE_IS_ENCRYPT(SPACE_GET(session, entity->table.desc.space_id));

    for (uint32 i = 0; i < part_table->desc.partcnt; i++) {
        table_part = PART_GET_ENTITY(part_table, i);
        if (!IS_READY_PART(table_part)) {
            continue;
        }

        part_generate_index_part_desc(session, index, &table_part->desc, &index_part.desc);

        if (!check_part_encrypt_allowed(session, is_encrypt_table, index_part.desc.space_id)) {
            GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "create part index", "cases: create encrypt part index on \
non-encrypt part table or create non-encrypt part index on encrypt part table.");
            return GS_ERROR;
        }

        if (IS_SYS_TABLE(&entity->table) && !IS_PARENT_TABPART(&table_part->desc)) {
            if (btree_create_part_segment(session, &index_part) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        if (IS_PARENT_TABPART(&table_part->desc)) {
            if (subpart_create_index_default(session, cursor, index, table_part) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
        
        if (db_write_sys_indexpart(session, cursor, &index_part.desc) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}
    
static status_t subpart_create_index_with_def(knl_session_t *session, knl_cursor_t *cursor, knl_handle_t knl_index,
    table_part_t *compart, knl_part_def_t *part_def)
{
    index_part_t subpart;
    knl_part_def_t *subpart_def = NULL;
    table_part_t *table_subpart = NULL;
    index_t *index = (index_t *)knl_index;
    dc_entity_t *entity = index->entity;
    table_t *table = &entity->table;
    uint32 is_encrypt_table = SPACE_IS_ENCRYPT(SPACE_GET(session, entity->table.desc.space_id));

    for (uint32 i = 0; i < part_def->subparts.count; i++) {
        subpart_def = (knl_part_def_t *)cm_galist_get(&part_def->subparts, i);
        table_subpart = PART_GET_SUBENTITY(table->part_table, compart->subparts[i]);
        if (table_subpart == NULL) {
            continue;
        }

        if (part_init_index_part_desc(session, index, subpart_def, &table_subpart->desc, &subpart.desc) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (subpart_def->space.len == 0 && part_def->space.len != 0) {
            if (spc_get_space_id(session, &part_def->space,
                                 part_def->is_for_create_db, &subpart.desc.space_id) != GS_SUCCESS) {
                return GS_ERROR;
            }

            if (spc_check_by_uid(session, &part_def->space, subpart.desc.space_id, index->desc.uid) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        if (!check_part_encrypt_allowed(session, is_encrypt_table, subpart.desc.space_id)) {
            GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "create part index", "cases: create encrypt part index on \
non-encrypt part table or create non-encrypt part index on encrypt part table.");
            return GS_ERROR;
        }

        if (IS_SYS_TABLE(&entity->table)) {
            if (btree_create_part_segment(session, &subpart) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
        
        if (db_write_sys_indsubpart(session, cursor, &subpart.desc) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}
static status_t part_create_partindex_with_def(knl_session_t *session, knl_cursor_t *cursor, index_t *index,
    part_table_t *part_table, knl_part_obj_def_t *def)
{
    index_part_t index_part;
    knl_part_def_t *part_def = NULL;
    table_part_t *table_part = NULL;
    dc_entity_t *entity = index->entity;
    uint32 is_encrypt_table = SPACE_IS_ENCRYPT(SPACE_GET(session, entity->table.desc.space_id));

    if (db_verify_part_index_def(session, part_table, def) != GS_SUCCESS) {
        return GS_ERROR;
    }

    for (uint32 i = 0; i < def->parts.count; i++) {
        part_def = (knl_part_def_t *)cm_galist_get(&def->parts, i);
        table_part = PART_GET_ENTITY(part_table, i);
        if (table_part == NULL) {
            continue;
        }

        if (part_init_index_part_desc(session, index, part_def, &table_part->desc, &index_part.desc) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (!check_part_encrypt_allowed(session, is_encrypt_table, index_part.desc.space_id)) {
            GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "create part index", "cases: create encrypt part index on \
non-encrypt part table or create non-encrypt part index on encrypt part table.");
            return GS_ERROR;
        }

        if (IS_SYS_TABLE(&entity->table) && !IS_PARENT_TABPART(&table_part->desc)) {
            if (btree_create_part_segment(session, &index_part) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        if (IS_PARENT_TABPART(&table_part->desc)) {
            if (part_def->subparts.count != table_part->desc.subpart_cnt) {
                GS_THROW_ERROR(ERR_PARTCNT_NOT_MATCH);
                return GS_ERROR;
            }
            
            if (subpart_create_index_with_def(session, cursor, index, table_part, part_def) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
        
        if (db_write_sys_indexpart(session, cursor, &index_part.desc) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t db_create_part_index(knl_session_t *session, knl_cursor_t *cursor, index_t *index,
                              knl_part_obj_def_t *def)
{
    knl_part_desc_t object_desc;
    dc_entity_t *entity = index->entity;
    part_table_t *part_table = entity->table.part_table;

    part_init_index_desc(index, &part_table->desc, &object_desc);

    if (db_write_sys_partobject(session, cursor, &object_desc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (def == NULL) {
        return part_create_partindex_default(session, cursor, index, part_table);
    } else {
        return part_create_partindex_with_def(session, cursor, index, part_table, def);
    }
}

void part_init_lob_part_desc(knl_session_t *session, knl_handle_t knl_desc, uint32 part_id, uint32 space_id,
    knl_lob_part_desc_t *desc)
{
    knl_lob_desc_t *lob_desc = (knl_lob_desc_t *)knl_desc;
    desc->uid = lob_desc->uid;
    desc->table_id = lob_desc->table_id;
    desc->column_id = lob_desc->column_id;
    desc->part_id = part_id;
    desc->subpart_cnt = 0;
    desc->space_id = space_id;
    desc->org_scn = db_inc_scn(session);
    desc->entry = INVALID_PAGID;
    desc->flags = 0;
    desc->is_parent = GS_FALSE;
}

status_t part_write_sys_lobpart(knl_session_t *session, knl_cursor_t *cursor, knl_lob_part_desc_t *desc)
{
    table_t *table = NULL;
    row_assist_t ra;
    space_t *space;
    status_t status;

    space = SPACE_GET(session, desc->space_id);
    if (!SPACE_IS_ONLINE(space)) {
        GS_THROW_ERROR(ERR_SPACE_OFFLINE, space->ctrl->name, "space offline and write to lobpart$ failed");
        return GS_ERROR;
    }

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_LOBPART_ID, GS_INVALID_ID32);
    table = (table_t *)cursor->table;

    row_init(&ra, (char *)cursor->row, HEAP_MAX_ROW_SIZE(session), table->desc.column_count);
    (void)row_put_int32(&ra, desc->uid);
    (void)row_put_int32(&ra, desc->table_id);
    (void)row_put_int32(&ra, desc->column_id);
    (void)row_put_int32(&ra, desc->part_id);
    (void)row_put_int32(&ra, desc->space_id);
    (void)row_put_int64(&ra, desc->org_scn);
    (void)row_put_int64(&ra, *(int64 *)&desc->entry);
    (void)row_put_int32(&ra, desc->flags);

    status = knl_internal_insert(session, cursor);

    return status;
}

status_t part_lob_get_space_id(knl_session_t *session, lob_t *lob, knl_part_def_t *def,
    uint32 *space_id)
{
    if (lob->desc.is_stored || def->space.len == 0) {
        *space_id = lob->desc.space_id;
    } else {
        if (spc_get_space_id(session, &def->space, def->is_for_create_db, space_id) != GS_SUCCESS) {
            return GS_ERROR;
        }
        if (spc_check_by_uid(session, &def->space, *space_id, lob->desc.uid) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t subpart_create_lob_with_def(knl_session_t *session, knl_handle_t knl_lob, knl_part_def_t *compart_def,
    uint32 compart_id)
{
    uint32 subpart_id, space_id;
    lob_part_t lob_subpart;
    knl_part_def_t *subpart_def = NULL;
    lob_t *lob = (lob_t *)knl_lob;
    
    for (uint32 i = 0; i < compart_def->subparts.count; i++) {
        subpart_def = (knl_part_def_t *)cm_galist_get(&compart_def->subparts, i);
        subpart_id = subpart_generate_partid(NULL, NULL, i);
        if (subpart_lob_get_space_id(session, lob, subpart_def, &space_id) != GS_SUCCESS) {
            return GS_ERROR;
        }

        part_init_lob_part_desc(session, &lob->desc, subpart_id, space_id, &lob_subpart.desc);
        lob_subpart.desc.parent_partid = compart_id;
        
        if (dc_is_reserved_entry(lob->desc.uid, lob->desc.table_id)) {
            if (lob_create_part_segment(session, (lob_part_t *)&lob_subpart) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        if (subpart_write_syslob(session, &lob_subpart.desc) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t part_create_lob_with_def(knl_session_t *session, knl_cursor_t *cursor, table_t *table,
    knl_table_def_t *def, lob_t *lob)
{
    uint32 part_id, space_id;
    lob_part_t lob_part;
    knl_part_def_t *part_def = NULL;

    knl_panic_log(def->part_def != NULL, "the part_def is NULL, panic info: page %u-%u type %u table %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, table->desc.name);
    for (uint32 i = 0; i < def->part_def->parts.count; i++) {
        part_def = (knl_part_def_t *)cm_galist_get(&def->part_def->parts, i);
        part_id = part_generate_part_id(table, i);
        if (part_lob_get_space_id(session, lob, part_def, &space_id) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (lob_check_space(session, table, space_id) != GS_SUCCESS) {
            return GS_ERROR;
        }
        
        part_init_lob_part_desc(session, &lob->desc, part_id, space_id, &lob_part.desc);
        lob_part.desc.is_parent = part_def->is_parent;
        
        if (IS_SYS_TABLE(table) && !part_def->is_parent) {
            if (lob_create_part_segment(session, &lob_part) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        if (part_def->is_parent) {
            if (subpart_create_lob_with_def(session, lob, part_def, part_id) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
        
        if (part_write_sys_lobpart(session, cursor, &lob_part.desc) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t subpart_create_lob_default(knl_session_t *session, part_table_t *part_table, knl_handle_t knl_lob,
    table_part_t *compart)
{
    uint32 space_id;
    lob_part_t lob_subpart;
    table_part_t *table_subpart = NULL;
    lob_t *lob = (lob_t *)knl_lob;

    for (uint32 i = 0; i < compart->desc.subpart_cnt; i++) {
        table_subpart = PART_GET_SUBENTITY(part_table, compart->subparts[i]);
        if (table_subpart == NULL) {
            continue;
        }

        space_id = lob->desc.is_stored ? lob->desc.space_id : table_subpart->desc.space_id;
        part_init_lob_part_desc(session, &lob->desc, table_subpart->desc.part_id, space_id, &lob_subpart.desc);
        lob_subpart.desc.parent_partid = compart->desc.part_id;

        if (dc_is_reserved_entry(lob->desc.uid, lob->desc.table_id)) {
            if (lob_create_part_segment(session, (lob_part_t *)&lob_subpart) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        if (subpart_write_syslob(session, &lob_subpart.desc) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t part_create_lob_default(knl_session_t *session, knl_cursor_t *cursor, table_t *table,
    knl_table_def_t *def, lob_t *lob)
{
    uint32 part_id, space_id;
    lob_part_t lob_part;
    table_part_t *table_part = NULL;
    part_table_t *part_table = table->part_table;
    
    knl_panic_log(part_table != NULL, "the part_table is NULL, panic info: page %u-%u type %u table %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, table->desc.name);
    for (uint32 i = 0; i < part_table->desc.partcnt + part_table->desc.not_ready_partcnt; i++) {
        table_part = PART_GET_ENTITY(part_table, i);
        if (!IS_READY_PART(table_part)) {
            continue;
        }
        
        part_id = table_part->desc.part_id;
        space_id = lob->desc.is_stored ? lob->desc.space_id : table_part->desc.space_id;

        part_init_lob_part_desc(session, &lob->desc, part_id, space_id, &lob_part.desc);
        lob_part.desc.is_parent = table_part->desc.is_parent;

        if (lob_check_space(session, table, lob_part.desc.space_id) != GS_SUCCESS) {
            return GS_ERROR;
        }
        
        if (IS_SYS_TABLE(table) && !IS_PARENT_TABPART(&table_part->desc)) {
            if (lob_create_part_segment(session, &lob_part) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        if (IS_PARENT_TABPART(&table_part->desc)) {
            if (subpart_create_lob_default(session, part_table, lob, table_part) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
        
        if (part_write_sys_lobpart(session, cursor, &lob_part.desc) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t db_create_part_lob(knl_session_t *session, knl_cursor_t *cursor, table_t *table, knl_table_def_t *def,
                            lob_t *lob)
{
    if (def != NULL) {
        if (part_create_lob_with_def(session, cursor, table, def, lob) != GS_SUCCESS) {
            return GS_ERROR;
        }
    } else {
        if (part_create_lob_default(session, cursor, table, def, lob) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

uint32 subpart_generate_partid(part_table_t *part_table, table_part_t *compart, uint32 number)
{
    uint32 num = number;
    table_part_t *table_subpart = NULL;

    if (compart != NULL && part_table != NULL) {
        table_subpart = PART_GET_SUBENTITY(part_table, compart->subparts[compart->desc.subpart_cnt - 1]);
        num = table_subpart->desc.part_id;
        num /= GS_DFT_PARTID_STEP;
    } else {
        knl_panic_log(num != GS_INVALID_ID32, "the num is invalid when the compart or part_table is NULL.");
    }

    return GS_DFT_PARTID_STEP * (num + 1);
}

status_t subpart_init_table_part_desc(knl_session_t *session, knl_table_part_desc_t *comdesc,
    knl_part_def_t *def, uint32 subpart_id, knl_table_part_desc_t *desc)
{
    desc->uid = comdesc->uid;
    desc->table_id = comdesc->table_id;
    desc->parent_partid = comdesc->part_id;
    desc->part_id = subpart_id;
    (void)cm_text2str(&def->name, desc->name, GS_NAME_BUFFER_SIZE);
    desc->entry = INVALID_PAGID;
    desc->org_scn = db_inc_scn(session);
    desc->seg_scn = desc->org_scn;
    desc->initrans = (def->initrans == 0) ? comdesc->initrans : def->initrans;
    desc->pctfree = (def->pctfree == GS_INVALID_ID32) ? comdesc->pctfree : def->pctfree;
    desc->flags = 0;
    desc->not_ready = comdesc->not_ready;
    desc->compress_algo = COMPRESS_NONE;
    desc->compress = GS_FALSE;
    desc->is_csf = comdesc->is_csf;

    if (def->space.len == 0) {
        desc->space_id = comdesc->space_id;
    } else {
        if (GS_SUCCESS != spc_get_space_id(session, &def->space, def->is_for_create_db, &desc->space_id)) {
            return GS_ERROR;
        }

        if (spc_check_by_uid(session, &def->space, desc->space_id, desc->uid) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    space_t *space = SPACE_GET(session, desc->space_id);
    
    errno_t err = memset_sp(&desc->storage_desc, sizeof(knl_storage_desc_t), 0, sizeof(knl_storage_desc_t));
    knl_securec_check(err);

    if (def->storage_def.initial > 0) {
        if (!dc_is_reserved_entry(comdesc->uid, comdesc->table_id)) {
            desc->storaged = GS_TRUE;
        }
        desc->storage_desc.initial = CM_CALC_ALIGN((uint64)def->storage_def.initial, space->ctrl->block_size) /
            space->ctrl->block_size;
    }

    // storage maxsize clause will not take effect to sys tables
    if (def->storage_def.maxsize > 0 && !dc_is_reserved_entry(comdesc->uid, comdesc->table_id)) {
        desc->storaged = GS_TRUE;
        desc->storage_desc.max_pages = CM_CALC_ALIGN((uint64)def->storage_def.maxsize, space->ctrl->block_size) /
            space->ctrl->block_size;
    }

    desc->hiboundval = def->hiboundval;
    desc->bhiboundval.bytes = (uint8 *)def->partkey;
    desc->bhiboundval.size = def->partkey->size;

    desc->cr_mode = comdesc->cr_mode;

    return GS_SUCCESS;
}

status_t db_write_sys_tablesubpart(knl_session_t *session, knl_cursor_t *cursor, knl_table_part_desc_t *subpart_desc)
{
    table_t *table = NULL;
    row_assist_t ra;
    space_t *part_space;
    status_t status;

    part_space = SPACE_GET(session, subpart_desc->space_id);
    if (!SPACE_IS_ONLINE(part_space)) {
        GS_THROW_ERROR(ERR_SPACE_OFFLINE, part_space->ctrl->name, "space offline and write to tablepart$ failed");
        return GS_ERROR;
    }

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_SUB_TABLE_PARTS_ID, GS_INVALID_ID32);
    table = (table_t *)cursor->table;

    row_init(&ra, (char *)cursor->row, HEAP_MAX_ROW_SIZE(session), table->desc.column_count);

    if (subpart_desc->hiboundval.len > PART_HIBOUND_VALUE_LENGTH) {
        GS_THROW_ERROR(ERR_ROW_SIZE_TOO_LARGE, ra.max_size);
        return GS_ERROR;
    }
    
    if (subpart_desc->bhiboundval.size > PART_HIBOUND_VALUE_LENGTH) {
        GS_THROW_ERROR(ERR_ROW_SIZE_TOO_LARGE, ra.max_size);
        return GS_ERROR;
    }
    
    (void)row_put_int32(&ra, subpart_desc->uid);
    (void)row_put_int32(&ra, subpart_desc->table_id);
    (void)row_put_int32(&ra, subpart_desc->part_id);
    (void)row_put_str(&ra, subpart_desc->name);
    (void)row_put_int32(&ra, subpart_desc->hiboundval.len);
    (void)row_put_text(&ra, &subpart_desc->hiboundval);
    (void)row_put_int32(&ra, subpart_desc->space_id);
    (void)row_put_int64(&ra, subpart_desc->org_scn);
    (void)row_put_int64(&ra, *(int64 *)&subpart_desc->entry);
    (void)row_put_int32(&ra, subpart_desc->initrans);
    (void)row_put_int32(&ra, subpart_desc->pctfree);
    (void)row_put_int32(&ra, subpart_desc->flags);
    (void)row_put_bin(&ra, &subpart_desc->bhiboundval);

    row_put_null(&ra);  // row_cnt to do
    row_put_null(&ra);  // blk_cnt to do
    row_put_null(&ra);  // emp_cnt to_do
    row_put_null(&ra);  // avg_len to do
    row_put_null(&ra);  // sample_size to do
    row_put_null(&ra);  // analyse_time to_do
    (void)row_put_int32(&ra, subpart_desc->parent_partid);

    status = knl_internal_insert(session, cursor);

    return status;
}

status_t db_write_sys_indsubpart(knl_session_t *session, knl_cursor_t *cursor, knl_index_part_desc_t *desc)
{
    table_t *table = NULL;
    row_assist_t ra;

    space_t *space = SPACE_GET(session, desc->space_id);
    if (!SPACE_IS_ONLINE(space)) {
        GS_THROW_ERROR(ERR_SPACE_OFFLINE, space->ctrl->name, "space offline and write to indexpart$ failed");
        return GS_ERROR;
    }

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_SUB_INDEX_PARTS_ID, GS_INVALID_ID32);
    table = (table_t *)cursor->table;

    row_init(&ra, (char *)cursor->row, HEAP_MAX_ROW_SIZE(session), table->desc.column_count);
    if (desc->hiboundval.len > PART_HIBOUND_VALUE_LENGTH) {
        GS_THROW_ERROR(ERR_ROW_SIZE_TOO_LARGE, ra.max_size);
        return GS_ERROR;
    }
    if (desc->bhiboundval.size > PART_HIBOUND_VALUE_LENGTH) {
        GS_THROW_ERROR(ERR_ROW_SIZE_TOO_LARGE, ra.max_size);
        return GS_ERROR;
    }
    (void)row_put_int32(&ra, desc->uid);
    (void)row_put_int32(&ra, desc->table_id);
    (void)row_put_int32(&ra, desc->index_id);
    (void)row_put_int32(&ra, desc->part_id);
    (void)row_put_str(&ra, desc->name);
    (void)row_put_int32(&ra, desc->hiboundval.len);
    (void)row_put_text(&ra, &desc->hiboundval);
    (void)row_put_int32(&ra, desc->space_id);
    (void)row_put_int64(&ra, desc->org_scn);
    (void)row_put_int64(&ra, *(int64 *)&desc->entry);
    (void)row_put_int32(&ra, desc->initrans);
    (void)row_put_int32(&ra, desc->pctfree);
    (void)row_put_int32(&ra, desc->flags);
    (void)row_put_bin(&ra, &desc->bhiboundval);
    row_put_null(&ra);  // blevel reserved
    row_put_null(&ra);  // level_block reserved
    row_put_null(&ra);  // distkey reserved
    row_put_null(&ra);  // lblkkey reserved
    row_put_null(&ra);  // dblkkey reserved
    row_put_null(&ra);  // analyzetime reserved
    row_put_null(&ra);  // empty leaf blocks
    row_put_null(&ra);  // clufac
    row_put_null(&ra);  // samplesize
    row_put_null(&ra);  // comb_cols_2_ndv
    row_put_null(&ra);  // comb_cols_3_ndv
    row_put_null(&ra);  // comb_cols_4_ndv
    (void)row_put_int32(&ra, desc->parent_partid);

    return knl_internal_insert(session, cursor);
}

status_t subpart_write_syslob(knl_session_t *session, knl_lob_part_desc_t *desc)
{
    row_assist_t ra;

    space_t *space = SPACE_GET(session, desc->space_id);
    if (!SPACE_IS_ONLINE(space)) {
        GS_THROW_ERROR(ERR_SPACE_OFFLINE, space->ctrl->name, "space offline and write to lobpart$ failed");
        return GS_ERROR;
    }

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_SUB_LOB_PARTS_ID, GS_INVALID_ID32);
    table_t *table = (table_t *)cursor->table;

    row_init(&ra, (char *)cursor->row, HEAP_MAX_ROW_SIZE(session), table->desc.column_count);
    (void)row_put_int32(&ra, desc->uid);
    (void)row_put_int32(&ra, desc->table_id);
    (void)row_put_int32(&ra, desc->column_id);
    (void)row_put_int32(&ra, desc->part_id);
    (void)row_put_int32(&ra, desc->space_id);
    (void)row_put_int64(&ra, desc->org_scn);
    (void)row_put_int64(&ra, *(int64 *)&desc->entry);
    (void)row_put_int32(&ra, desc->flags);
    (void)row_put_int32(&ra, desc->parent_partid);

    if (knl_internal_insert(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }
    
    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t subpart_lob_get_space_id(knl_session_t *session, lob_t *lob, knl_part_def_t *def, uint32 *space_id)
{
    if (lob->desc.is_stored || def->space.len == 0) {
        *space_id = lob->desc.space_id;
    } else {
        if (spc_get_space_id(session, &def->space, def->is_for_create_db, space_id) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}
