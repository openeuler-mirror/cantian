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
 * knl_part_locate.c
 *
 *
 * IDENTIFICATION
 * src/kernel/table/knl_part_locate.c
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
#include "knl_part_inner.h"

static int32 part_compare_key_column(ct_type_t type, part_decode_key_t *key1,
    part_decode_key_t *key2, uint16 col)
{
    char *data1 = NULL;
    char *data2 = NULL;
    int32 result;

    if (key1->lens[col] > PART_KEY_DEFAULT_LEN || key1->lens[col] == PART_KEY_MIN_LEN ||
        key2->lens[col] > PART_KEY_DEFAULT_LEN || key2->lens[col] == PART_KEY_MIN_LEN) {
        result = ((key1->lens[col] > key2->lens[col]) ? 1 : (key1->lens[col] < key2->lens[col] ? -1 : 0));
    } else {
        data1 = key1->buf + key1->offsets[col];
        data2 = key2->buf + key2->offsets[col];

        result = var_compare_data_ex(data1, key1->lens[col], data2, key2->lens[col], type);
    }

    return result;
}

/*
 * partition pruning algorithm
 *
 * 1.cmp_col > range_col, key locates in right partitions, return directly.
 * 2.cmp_col < range_col, key perhaps locates in current partition, return directly.
 * 3.cmp_col = range_col, need to do more detail analysis:
 *     3.1 cmp_col is closed, need to scan next col.
 *     3.2 cmp_col isn't closed, key locates in right partitions return directly(left border) or
           in left partitions return directly(right border).
 * 4.after compare all cols, all cmp_cols are closed and equal to range_cols, key locates in right partition.
 */
int32 part_compare_border(knl_part_column_desc_t *desc, knl_part_key_t *locate_key,
    part_decode_key_t *part_key, bool32 is_left)
{
    part_decode_key_t *cmp_key = &locate_key->decoder;
    int32 result;
    uint16 i;

    knl_panic(cmp_key->count == part_key->count);

    for (i = 0; i < cmp_key->count; i++) {
        result = part_compare_key_column(desc[i].datatype, cmp_key, part_key, i);
        if (result != 0) {
            return result;
        }

        if (!locate_key->closed[i]) {
            return is_left ? 1 : -1;
        }
    }

    return 1;
}
    
int32 part_compare_range_key(knl_part_column_desc_t *desc, part_decode_key_t *cmp_key, part_decode_key_t *range_key)
{
    int32 result;
    uint16 i;

    result = 0;
    knl_panic(cmp_key->count == range_key->count);

    for (i = 0; i < cmp_key->count; i++) {
        result = part_compare_key_column(desc[i].datatype, cmp_key, range_key, i);
        if (result != 0) {
            break;
        }
    }

    return result;
}

static bool32 part_compare_list_key(knl_part_column_desc_t *desc, part_decode_key_t *key1,
    part_decode_key_t *key2)
{
    char *data1 = NULL;
    char *data2 = NULL;
    uint32 i;

    knl_panic(key1->count == key2->count);

    for (i = 0; i < key1->count; i++) {
        if (key1->lens[i] == PART_KEY_UNKNOWN_LEN || key2->lens[i] == PART_KEY_UNKNOWN_LEN) {
            continue;
        } else if (key1->lens[i] >= PART_KEY_NULL_LEN || key2->lens[i] >= PART_KEY_NULL_LEN) {
            if (key1->lens[i] != key2->lens[i]) {
                return CT_FALSE;
            }
        } else {
            data1 = key1->buf + key1->offsets[i];
            data2 = key2->buf + key2->offsets[i];

            if (var_compare_data_ex(data1, key1->lens[i], data2, key2->lens[i], (ct_type_t)desc[i].datatype) != 0) {
                return CT_FALSE;
            }
        }
    }

    return CT_TRUE;
}

/* hash algorithm for hash partition */
static uint32 part_hash_get_pno(part_table_t *part_table, uint32 hash_value)
{
    uint32 part_cnt;
    
    table_part_t *part = PART_GET_ENTITY(part_table, part_table->desc.partcnt - 1);
    knl_panic(part != NULL);
    
    if (part->desc.not_ready) {
        part_cnt = part_table->desc.partcnt - 1;
    } else {
        part_cnt = part_table->desc.partcnt;
    }

    uint32 hbucket_cnt = dc_get_hash_bucket_count(part_cnt);
    uint32 bucket_id = hash_value % hbucket_cnt;
    if (bucket_id < part_cnt) {
        return bucket_id;
    } else {
        return (bucket_id - hbucket_cnt / HASH_PART_BUCKET_BASE);
    }
}

void knl_decode_part_key(part_key_t *key, knl_part_key_t *part_key)
{
    part_key->key = key;
    part_key->decoder.offsets = part_key->offsets;
    part_key->decoder.lens = part_key->lens;
    part_decode_key(key, &part_key->decoder);
}

int32 knl_compare_defined_key(galist_t *part_keys, part_key_t *key1, part_key_t *key2)
{
    knl_part_column_def_t *column = NULL;
    knl_part_key_t part_key1, part_key2;
    part_decode_key_t *decoder1 = NULL;
    part_decode_key_t *decoder2 = NULL;
    int32 result;
    uint16 i;

    knl_decode_part_key(key1, &part_key1);
    decoder1 = &part_key1.decoder;
    knl_decode_part_key(key2, &part_key2);
    decoder2 = &part_key2.decoder;

    result = 0;
    knl_panic(decoder1->count == decoder2->count);

    for (i = 0; i < decoder1->count; i++) {
        column = (knl_part_column_def_t *)cm_galist_get(part_keys, i);

        result = part_compare_key_column(column->datatype, decoder1, decoder2, i);
        if (result != 0) {
            break;
        }
    }

    return result;
}

/*
 * part get range no
 * Using binary search to find the part no which meets the range of condition.
 */
static uint32 part_locate_range_key(part_table_t *part_table, part_decode_key_t *decoder)
{
    table_part_t *table_part = NULL;
    int32 begin, end, curr;
    int32 result;
    uint32 part_no;

    knl_panic_log(part_table->desc.partcnt > 0, "table_part's partcnt is abnormal, panic info: partcnt %u",
                  part_table->desc.partcnt);
    
    if (PART_CONTAIN_INTERVAL(part_table)) {
        part_key_t *part_key = (part_key_t *)decoder->buf;
        table_part = PART_GET_ENTITY(part_table, part_table->desc.transition_no);
        knl_panic_log(table_part->desc.groupcnt == 1,
                      "table_part's groupcnt is abnormal, panic info: table_part %s groupcnt %u",
                      table_part->desc.name, table_part->desc.groupcnt);
        if (part_get_key_bits(part_key, 0) == PART_KEY_BITS_NULL) {
            return CT_INVALID_ID32;
        }

        result = part_compare_range_key(part_table->keycols, decoder, table_part->desc.groups);
        if (result >= 0) {
            return part_locate_interval_key(part_table, table_part->desc.groups, decoder);
        } else {
            end = part_table->desc.transition_no;
        }
    } else {
        end = part_table->desc.partcnt - 1;
    }

    curr = begin = 0;
    part_no = CT_INVALID_ID32;

    while (begin <= end) {
        curr = ((uint32)(end + begin)) >> 1;
        table_part = PART_GET_ENTITY(part_table, (uint32)curr);
        knl_panic_log(table_part->desc.groupcnt == 1,
                      "table_part's groupcnt is abnormal, panic info: table_part %s groupcnt %u",
                      table_part->desc.name, table_part->desc.groupcnt);

        result = part_compare_range_key(part_table->keycols, decoder, table_part->desc.groups);
        if (result < 0) {
            part_no = (uint32)curr;
            end = curr - 1;
        } else {
            begin = curr + 1;
        }
    }

    return part_no;
}

uint32 knl_locate_part_border(knl_handle_t session, knl_handle_t dc_entity, knl_part_key_t *locate_key,
                              bool32 is_left)
{
    dc_entity_t *entity = (dc_entity_t *)dc_entity;
    part_table_t *part_table = entity->table.part_table;
    part_key_t *key = locate_key->key;
    table_part_t *table_part = NULL;
    int32 begin, end, curr;
    int32 result;
    uint32 part_no;

    knl_decode_part_key(key, locate_key);
    knl_panic_log(key->column_count == part_table->desc.partkeys, "the column_count is not equal to part_table's "
                  "partkeys, panic info: table %s column_count %u part_table's partkeys %u",
                  entity->table.desc.name, key->column_count, part_table->desc.partkeys);

    curr = begin = 0;
    part_no = CT_INVALID_ID32;
    knl_panic_log(part_table->desc.partcnt > 0, "part_table's partcnt is abnormal,  panic info: table %s partcnt %u",
                  entity->table.desc.name, part_table->desc.partcnt);

    if (!PART_CONTAIN_INTERVAL(part_table)) {
        end = part_table->desc.partcnt - 1;
    } else {
        knl_panic_log(part_table->desc.partkeys == 1,
                      "part_table's partkeys is abnormal, panic info: table %s partkeys %u", entity->table.desc.name,
                      part_table->desc.partkeys);
        table_part = PART_GET_ENTITY(part_table, part_table->desc.transition_no);

        result = part_compare_border(part_table->keycols, locate_key, table_part->desc.groups, is_left);
        if (result >= 0) {
            return part_locate_interval_border(session, part_table, locate_key, is_left);
        }

        end = part_table->desc.transition_no;
    }

    while (begin <= end) {
        curr = ((uint32)(end + begin)) >> 1;
        table_part = PART_GET_ENTITY(part_table, (uint32)curr);
        result = part_compare_border(part_table->keycols, locate_key, table_part->desc.groups, is_left);
        if (result <= 0) {
            part_no = (uint32)curr;
            end = curr - 1;
        } else {
            begin = curr + 1;
        }
    }

    return part_no;
}

uint32 part_locate_list_key(part_table_t *part_table, part_decode_key_t *decoder)
{
    text_t values[CT_MAX_PARTKEY_COLUMNS];
    part_decode_key_t *curr = NULL;
    table_part_t *part = NULL;
    list_item_t *item = NULL;
    uint32 hash;
    uint16 i;

    if (decoder->lens[0] == PART_KEY_DEFAULT_LEN) {
        item = &part_table->lbuckets[DEFAULT_PART_LIST].first;
        return item->id;
    }

    for (i = 0; i < decoder->count; i++) {
        values[i].str = decoder->buf + decoder->offsets[i];

        if (decoder->lens[i] == PART_KEY_NULL_LEN) {
            values[i].len = 0;
        } else {
            values[i].len = (uint32)decoder->lens[i];
        }
    }

    hash = dc_cal_list_value_hash(values, decoder->count);
    item = &part_table->lbuckets[hash].first;

    while (item->id != CT_INVALID_ID32) {
        part = PART_GET_ENTITY(part_table, item->id);
        curr = &part->desc.groups[item->offset];

        if (part_compare_list_key(part_table->keycols, decoder, curr)) {
            return item->id;
        }

        item = &part->lnext[item->offset];
    }

    item = &part_table->lbuckets[DEFAULT_PART_LIST].first;

    return item->id;
}

static uint32 compute_hash(variant_t *value, bool32 *is_type_ok, uint32 version)
{
    *is_type_ok = CT_TRUE;

    switch (value->type) {
        case CT_TYPE_UINT32:
        case CT_TYPE_INTEGER:
            return cm_hash_uint32_shard((uint32)value->v_int);

        case CT_TYPE_NUMBER:
        case CT_TYPE_NUMBER2:
        case CT_TYPE_NUMBER3:
        case CT_TYPE_DECIMAL: {
            if (version >= TABLE_VERSION_NEW_HASH) {
                return cm_hash_raw((uint8 *)value->v_bin.bytes, value->v_bin.size);
            } else {
                /* These codes are unreasonable for compute the hash value of a decimal
                 * with first four bytes. However, for compatibility, I have to keep the
                 * previous logic and function. */
                dec4_t d4;
                (void)cm_dec_8_to_4(&d4, &value->v_dec);
                return cm_hash_uint32_shard(*(uint32*)&d4);
            }
        }

        case CT_TYPE_INTERVAL_YM:
            return cm_hash_uint32_shard((uint32)value->v_itvl_ym);

        case CT_TYPE_INTERVAL_DS:
            return cm_hash_int64(value->v_itvl_ds);

        case CT_TYPE_DATE:
        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_DATETIME_MYSQL:
        case CT_TYPE_TIME_MYSQL:
        case CT_TYPE_DATE_MYSQL:
            return cm_hash_timestamp((uint64)value->v_bigint);

        case CT_TYPE_UINT64:
            return cm_hash_uint64((uint64)value->v_ubigint);
        case CT_TYPE_BIGINT:
            return cm_hash_int64(value->v_bigint);
        case CT_TYPE_REAL:
            return cm_hash_real(value->v_real);

        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
        case CT_TYPE_STRING:
            return cm_hash_raw((uint8 *)value->v_text.str, value->v_text.len);

        case CT_TYPE_BINARY:
        case CT_TYPE_RAW:
        case CT_TYPE_VARBINARY:
            return cm_hash_bytes((uint8 *)value->v_bin.bytes, value->v_bin.size, INFINITE_HASH_RANGE);

        default:
            *is_type_ok = CT_FALSE;
            return 0;
    }
}

uint32 part_hash_value_combination(uint32 idx, unsigned int hashValue, variant_t *value, bool32 *is_type_ok,
    uint32 version)
{
    unsigned int hashval = hashValue;
    if (value->is_null) {
        *is_type_ok = CT_TRUE;
        return hashval;
    }

    if (idx != 0) {
        hashval = (hashval << 1) | ((hashval & 0x80000000) ? 1 : 0);
        hashval ^= compute_hash(value, is_type_ok, version);
    } else {
        hashval = compute_hash(value, is_type_ok, version);
    }

    return hashval;
}

void part_get_hash_key_variant(ct_type_t datatype, text_t *value, variant_t *variant_value, uint32 version)
{
    variant_value->type = datatype;
    variant_value->is_null = CT_FALSE;

    // the column is NULL
    if (value->len == 0) {
        variant_value->is_null = CT_TRUE;
        return;
    }

    switch (datatype) {
        case CT_TYPE_UINT32:
            variant_value->v_uint32 = *(uint32 *)value->str;
            break;
        case CT_TYPE_INTEGER:
            variant_value->v_int = *(int32 *)value->str;
            break;

        case CT_TYPE_INTERVAL_DS:
            variant_value->v_itvl_ds = *(int64 *)value->str;
            break;

        case CT_TYPE_INTERVAL_YM:
            variant_value->v_itvl_ym = *(int32 *)value->str;
            break;

        case CT_TYPE_BOOLEAN:
            variant_value->v_bool = *(uint32 *)value->str;
            break;

        case CT_TYPE_UINT64:
            variant_value->v_ubigint = *(uint64 *)value->str;
            break;

        case CT_TYPE_BIGINT:
            variant_value->v_bigint = *(int64 *)value->str;
            break;

        case CT_TYPE_DATE:
        case CT_TYPE_DATETIME_MYSQL:
        case CT_TYPE_TIME_MYSQL:
        case CT_TYPE_DATE_MYSQL:
            variant_value->v_date = *(int64 *)value->str;
            break;

        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_LTZ:
            variant_value->v_tstamp = *(int64 *)value->str;
            break;

        case CT_TYPE_REAL:
            variant_value->v_real = *(double *)value->str;
            break;

        case CT_TYPE_NUMBER:
        case CT_TYPE_NUMBER3:
        case CT_TYPE_DECIMAL:
            if (version >= TABLE_VERSION_NEW_HASH) {
                variant_value->v_bin.bytes = (uint8 *)value->str;
                variant_value->v_bin.size = value->len;
            } else {
                (void)cm_dec_4_to_8(&variant_value->v_dec, (dec4_t*)value->str, value->len);
            }
            break;
        case CT_TYPE_NUMBER2:
            if (version >= TABLE_VERSION_NEW_HASH) {
                variant_value->v_bin.bytes = (uint8 *)value->str;
                variant_value->v_bin.size = value->len;
            } else {
                (void)cm_dec_2_to_8(VALUE_PTR(dec8_t, variant_value), (const payload_t *)value->str, value->len);
            }
            break;

        case CT_TYPE_BINARY:
        case CT_TYPE_VARBINARY:
        case CT_TYPE_RAW:
            variant_value->v_bin.bytes = (uint8 *)value->str;
            variant_value->v_bin.size = value->len;
            break;

        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
        case CT_TYPE_STRING:
        default:
            variant_value->v_text = *value;
            break;
    }
}

static status_t part_get_hash_key(knl_handle_t dc_entity, text_t *value, knl_part_column_desc_t *key_col,
    variant_t *variant_value)
{
    dc_entity_t *entity = (dc_entity_t *)dc_entity;
    table_t *table = &entity->table;
    
#ifdef Z_SHARDING
    part_table_t *part_table = table->part_table;
    if (part_table->desc.is_slice == CT_TRUE && table->desc.slice_count > 0) {
        knl_column_t *knl_column = knl_get_column(entity, key_col->column_id);
        part_get_hash_key_variant(knl_column->datatype, value, variant_value, table->desc.version);
        if (var_convert(CT_DEFALUT_SESSION_NLS_PARAMS, variant_value, key_col->datatype, NULL) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
#endif
        part_get_hash_key_variant(key_col->datatype, value, variant_value, table->desc.version);
#ifdef Z_SHARDING
    }
#endif
    return CT_SUCCESS;
}

static uint32 part_locate_hash_key(dc_entity_t *entity, part_table_t *part_table, knl_part_key_t *part_key)
{
    text_t values[CT_MAX_PARTKEY_COLUMNS];
    uint16 i;
    part_decode_key_t *decoder;
    part_key_t *key;
    variant_t variant_value;
    bool32 is_type_ok = CT_FALSE;
    uint32 hash_value = 0;
    table_t *table = &entity->table;
#ifdef Z_SHARDING
    routing_info_t *routing_info = knl_get_table_routing_info(entity);
#endif
    
    decoder = &part_key->decoder;
    key = part_key->key;

    CM_POINTER2(key, decoder);
    knl_panic_log(key->column_count < CT_MAX_COLUMNS,
                  "the column_count is more than the max limit, panic info: table %s column_count %u",
                  table->desc.name, key->column_count);

    for (i = 0; i < decoder->count; i++) {
        values[i].str = decoder->buf + decoder->offsets[i];

        if (decoder->lens[i] == PART_KEY_NULL_LEN) {
            values[i].len = 0;
        } else {
            values[i].len = (uint32)decoder->lens[i];
        }

        if (part_get_hash_key(entity, &values[i], &part_table->keycols[i], &variant_value) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_INVALID_PART_TYPE, "key", "");
            return CT_INVALID_ID32;
        }
#ifdef Z_SHARDING
        if (part_table->desc.is_slice == CT_TRUE && table->desc.slice_count > 0 &&
            routing_info->type == distribute_hash_basic) {
            hash_value = hash_basic_value_combination(i, hash_value, &variant_value, &is_type_ok);
        } else
#endif
        {
            hash_value = part_hash_value_combination(i, hash_value, &variant_value, &is_type_ok, table->desc.version);
        }
        if (!is_type_ok) {
            CT_THROW_ERROR(ERR_INVALID_PART_TYPE, "key", "");
            return CT_INVALID_ID32;
        }
    }
#ifdef Z_SHARDING
    if (part_table->desc.is_slice == CT_TRUE && table->desc.slice_count > 0) {
        uint32 modulo = abs(hash_value) % BUCKETDATALEN;
        uint32 slice_id = modulo % table->desc.slice_count;
        return part_hash_get_pno(part_table, slice_id);
    }
#endif
    // get the part no according to the part key hash value
    return part_hash_get_pno(part_table, hash_value);
}

uint32 part_get_bucket_by_variant(variant_t *data, uint32 part_cnt)
{
    uint32 hash_value;
    bool32 is_type_ok = CT_FALSE;

    hash_value = compute_hash(data, &is_type_ok, TABLE_VERSION_NEW_HASH);
    if (!is_type_ok) {
        CT_THROW_ERROR(ERR_INVALID_PART_TYPE, "key", "");
        return CT_INVALID_ID32;
    }

    if (part_cnt == 0) {
        return 0;
    } else {
        return hash_value % part_cnt;
    }
}

uint32 knl_locate_part_key(knl_handle_t dc_entity, part_key_t *key)
{
    dc_entity_t *entity;
    part_table_t *part_table;
    knl_part_key_t part_key;

    entity = (dc_entity_t *)dc_entity;
    part_table = entity->table.part_table;
    knl_panic_log(key->column_count == part_table->desc.partkeys, "the column_count in key is not equal to "
                  "part_table's partkeys, panic info: table %s column_count %u partkeys %u",
                  entity->table.desc.name, key->column_count, part_table->desc.partkeys);
    knl_decode_part_key(key, &part_key);

    switch (part_table->desc.parttype) {
        case PART_TYPE_RANGE:
            return part_locate_range_key(part_table, &part_key.decoder);

        case PART_TYPE_LIST:
            return part_locate_list_key(part_table, &part_key.decoder);

        case PART_TYPE_HASH:
            return part_locate_hash_key(entity, part_table, &part_key);

        default:
            return CT_INVALID_ID32;
    }
}

static uint32 subpart_locate_range_key(part_table_t *part_table, table_part_t *compart, part_decode_key_t *decoder)
{
    int32 result;
    int32 begin = 0;
    int32 curr = 0;
    uint32 subpart_no = CT_INVALID_ID32;
    int32 end = compart->desc.subpart_cnt - 1;
    table_part_t *table_part = NULL;
    knl_panic_log(compart->desc.subpart_cnt > 0, "subpart_cnt abnormal, panic info: compart_table %s subpart_cnt %u",
                  compart->desc.name, compart->desc.subpart_cnt);

    while (begin <= end) {
        curr = ((uint32)(end + begin)) >> 1;
        table_part = PART_GET_SUBENTITY(part_table, compart->subparts[(uint32)curr]);
        knl_panic_log(table_part->desc.groupcnt == 1,
                      "table_part's groupcnt is abnormal, panic info: table_part %s compart_table %s groupcnt %u",
                      table_part->desc.name, compart->desc.name, table_part->desc.groupcnt);

        result = part_compare_range_key(part_table->sub_keycols, decoder, table_part->desc.groups);
        if (result < 0) {
            subpart_no = (uint32)curr;
            end = curr - 1;
        } else {
            begin = curr + 1;
        }
    }

    return subpart_no;
}

uint32 subpart_locate_list_key(part_table_t *part_table, table_part_t *compart, part_decode_key_t *decoder)
{
    bool32 is_found = CT_FALSE;
    text_t values[CT_MAX_PARTKEY_COLUMNS];
    part_decode_key_t *curr = NULL;
    table_part_t *part = NULL;
    list_item_t *item = NULL;

    if (decoder->lens[0] == PART_KEY_DEFAULT_LEN) {
        item = &part_table->sub_lbuckets[DEFAULT_PART_LIST].first;
        while (item->id != CT_INVALID_ID32) {
            part = PART_GET_SUBENTITY(part_table, item->id);
            if (part->parent_partno == compart->part_no) {
                is_found = CT_TRUE;
                break;
            }

            item = &part->lnext[item->offset];
        }
        
        return (is_found ? part->part_no : CT_INVALID_ID32);
    }

    for (uint16 i = 0; i < decoder->count; i++) {
        values[i].str = decoder->buf + decoder->offsets[i];

        if (decoder->lens[i] == PART_KEY_NULL_LEN) {
            values[i].len = 0;
        } else {
            values[i].len = (uint32)decoder->lens[i];
        }
    }

    uint32 hash = dc_cal_list_value_hash(values, decoder->count);
    item = &part_table->sub_lbuckets[hash].first;

    while (item->id != CT_INVALID_ID32) {
        part = PART_GET_SUBENTITY(part_table, item->id);
        curr = &part->desc.groups[item->offset];

        if (part_compare_list_key(part_table->sub_keycols, decoder, curr) && part->parent_partno == compart->part_no) {
            return part->part_no;
        }

        item = &part->lnext[item->offset];
    }

    item = &part_table->sub_lbuckets[DEFAULT_PART_LIST].first;
    while (item->id != CT_INVALID_ID32) {
        part = PART_GET_SUBENTITY(part_table, item->id);
        if (part->parent_partno == compart->part_no) {
            is_found = CT_TRUE;
            break;
        }

        item = &part->lnext[item->offset];
    }

    return (is_found ? part->part_no : CT_INVALID_ID32);
}

static uint32 subpart_hash_get_pno(part_table_t *part_table, table_part_t *compart, uint32 hash_value)
{
    uint32 part_cnt;

    table_part_t *subpart = PART_GET_SUBENTITY(part_table, compart->subparts[compart->desc.subpart_cnt - 1]);
    knl_panic_log(subpart != NULL, "subpart is NULL, panic info: compart_table %s", compart->desc.name);

    if (subpart->desc.not_ready) {
        part_cnt = compart->desc.subpart_cnt - 1;
    } else {
        part_cnt = compart->desc.subpart_cnt;
    }

    uint32 hbucket_cnt = dc_get_hash_bucket_count(part_cnt);
    uint32 bucket_id = hash_value % hbucket_cnt;
    if (bucket_id < part_cnt) {
        return bucket_id;
    } else {
        return (bucket_id - hbucket_cnt / HASH_PART_BUCKET_BASE);
    }
}

static uint32 subpart_locate_hash_key(dc_entity_t *entity, table_part_t *compart, knl_part_key_t *part_key)
{
    text_t values[CT_MAX_PARTKEY_COLUMNS];
    variant_t variant_value;
    uint32 hash_value = 0;
    bool32 is_type_ok = CT_FALSE;
    part_key_t *key = part_key->key;
    table_t *table = &entity->table;
    part_table_t *part_table = table->part_table;
    part_decode_key_t *decoder = &part_key->decoder;
#ifdef Z_SHARDING
    routing_info_t *routing_info = knl_get_table_routing_info(entity);
#endif

    knl_panic_log(key->column_count < CT_MAX_COLUMNS, "column_count is abnormal, panic info: table %s column_count %u",
                  table->desc.name, key->column_count);
    for (uint16 i = 0; i < decoder->count; i++) {
        values[i].str = decoder->buf + decoder->offsets[i];

        if (decoder->lens[i] == PART_KEY_NULL_LEN) {
            values[i].len = 0;
        } else {
            values[i].len = (uint32)decoder->lens[i];
        }

        if (part_get_hash_key(entity, &values[i], &part_table->sub_keycols[i], &variant_value) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_INVALID_PART_TYPE, "key", "");
            return CT_INVALID_ID32;
        }
        
#ifdef Z_SHARDING
        if (part_table->desc.is_slice == CT_TRUE && table->desc.slice_count > 0 &&
            routing_info->type == distribute_hash_basic) {
            hash_value = hash_basic_value_combination(i, hash_value, &variant_value, &is_type_ok);
        } else
#endif
        {
            hash_value = part_hash_value_combination(i, hash_value, &variant_value, &is_type_ok, table->desc.version);
        }
        
        if (!is_type_ok) {
            CT_THROW_ERROR(ERR_INVALID_PART_TYPE, "key", "");
            return CT_INVALID_ID32;
        }
    }
    
#ifdef Z_SHARDING
    if (part_table->desc.is_slice == CT_TRUE && table->desc.slice_count > 0) {
        uint32 modulo = abs(hash_value) % BUCKETDATALEN;
        uint32 slice_id = modulo % table->desc.slice_count;
        return subpart_hash_get_pno(part_table, compart, slice_id);
    }
#endif

    return subpart_hash_get_pno(part_table, compart, hash_value);
}

uint32 knl_locate_subpart_key(knl_handle_t dc_entity, uint32 compart_no, part_key_t *key)
{
    knl_part_key_t part_key;
    dc_entity_t *entity = (dc_entity_t *)dc_entity;
    part_table_t *part_table = entity->table.part_table;
    table_part_t *compart = PART_GET_ENTITY(part_table, compart_no);
    knl_panic_log(key->column_count == part_table->desc.subpartkeys, "the column count of key is not equal to "
                  "part_table's subpartkeys, panic info: table %s column_count %u subpartkeys %u",
                  entity->table.desc.name, key->column_count, part_table->desc.subpartkeys);
    knl_decode_part_key(key, &part_key);

    switch (part_table->desc.subparttype) {
        case PART_TYPE_RANGE:
            return subpart_locate_range_key(part_table, compart, &part_key.decoder);
        case PART_TYPE_LIST:
            return subpart_locate_list_key(part_table, compart, &part_key.decoder);
        case PART_TYPE_HASH:
            return subpart_locate_hash_key(entity, compart, &part_key);
        default:
            return CT_INVALID_ID32;
    }
}

