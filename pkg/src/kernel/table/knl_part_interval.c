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
 * knl_part_interval.c
 *
 *
 * IDENTIFICATION
 * src/kernel/table/knl_part_interval.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_table_module.h"
#include "knl_part_output.h"
#include "cm_hash.h"
#include "cm_log.h"
#include "index_common.h"
#include "knl_table.h"
#include "ostat_load.h"
#include "dc_part.h"
#include "dc_subpart.h"
#include "knl_lob.h"
#include "knl_heap.h"
#include "knl_sys_part_defs.h"
#include "knl_part_inner.h"
#include "dtc_dls.h"

status_t part_check_interval_valid(part_key_t *interval_key)
{
    knl_part_key_t part_key;
    interval_ym_t *interval_ym = NULL;
    interval_ds_t *interval_ds = NULL;
    dec4_t *interval_num = NULL;
    uint8 bits;
    status_t status = CT_SUCCESS;

    knl_decode_part_key(interval_key, &part_key);
    bits = part_get_key_bits(interval_key, 0);

    switch (bits) {
        case PART_KEY_BITS_4:
            interval_ym = (interval_ym_t *)PART_GET_INTERVAL_KEY(&part_key.decoder);
            if (*interval_ym <= 0) {
                status = CT_ERROR;
            }
            break;

        case PART_KEY_BITS_8:
            interval_ds = (interval_ds_t *)PART_GET_INTERVAL_KEY(&part_key.decoder);
            if (*interval_ds <= 0) {
                status = CT_ERROR;
            }
            break;

        case PART_KEY_BITS_VAR:
            interval_num = (dec4_t *)PART_GET_INTERVAL_KEY(&part_key.decoder);
            if (DECIMAL_IS_ZERO(interval_num)) {
                status = CT_ERROR;
            }
            break;

        default:
            CT_LOG_RUN_ERR("invalid part key bits type %u.", bits);
            status = CT_ERROR;
            break;
    }

    return status;
}

static uint32 interval_calc_partno_int32(part_table_t *part_table, part_decode_key_t *transition_decoder,
                                         part_decode_key_t *decoder)
{
    int32 *base_num;
    int32 *key_num;
    int32 *interval_key;
    uint32 interval_count;

    base_num = (int32 *)PART_GET_INTERVAL_KEY(transition_decoder);
    key_num = (int32 *)PART_GET_INTERVAL_KEY(decoder);
    interval_key = (int32 *)(PART_GET_INTERVAL_KEY(part_table->desc.interval_key));
    interval_count = (uint32)((*key_num - *base_num) / *interval_key);

    return PART_GET_INTERVAL_PARTNO(interval_count, part_table);
}

static uint32 interval_calc_partno_int64(part_table_t *part_table, part_decode_key_t *transition_decoder,
                                         part_decode_key_t *decoder)
{
    int64 *base_num = (int64 *)PART_GET_INTERVAL_KEY(transition_decoder);
    int64 *key_num = (int64 *)PART_GET_INTERVAL_KEY(decoder);
    int64 *interval_key = (int64 *)(PART_GET_INTERVAL_KEY(part_table->desc.interval_key));
    uint32 interval_count = (uint32)((*key_num - *base_num) / *interval_key);
    
    return PART_GET_INTERVAL_PARTNO(interval_count, part_table);
}

static uint32 interval_calc_partno_days(part_table_t *part_table, part_decode_key_t *transition_decoder,
                                        part_decode_key_t *decoder)
{
    date_t *base_date;
    date_t *key_date;
    date_t *interval_key;
    uint32 interval_count;

    base_date = (date_t *)PART_GET_INTERVAL_KEY(transition_decoder);
    key_date = (date_t *)PART_GET_INTERVAL_KEY(decoder);
    interval_key = (date_t *)(PART_GET_INTERVAL_KEY(part_table->desc.interval_key));
    interval_count = (uint32)((*key_date - *base_date) / *interval_key);

    return PART_GET_INTERVAL_PARTNO(interval_count, part_table);
}

/*
 * generate interval count when interval keys are months
 * In order to get the interval count, we use the formula:
 * interval_count = ((date_key.year - date_trans.year) * 12 + (date_key.mon - date_trans.mon))/ interval_key
 * If date_key.day is less than date_trans.day, the interval count should minus one.
 * @param part_table, transition_decoder, decoder
 */
static uint32 interval_calc_partno_months(part_table_t *part_table, part_decode_key_t *transition_decoder,
                                          part_decode_key_t *decoder)
{
    date_t *trans_date;  // transition part key
    date_t *key_date;
    interval_ym_t *interval_key;
    uint32 interval_count;
    date_detail_t date_trans;
    date_detail_t date_key;

    trans_date = (date_t *)PART_GET_INTERVAL_KEY(transition_decoder);
    key_date = (date_t *)PART_GET_INTERVAL_KEY(decoder);
    interval_key = (interval_ym_t *)(PART_GET_INTERVAL_KEY(part_table->desc.interval_key));

    cm_decode_date(*trans_date, &date_trans);
    cm_decode_date(*key_date, &date_key);
    interval_count = PART_GET_YMINTERVAL_COUNT(date_trans, date_key, *interval_key);
    if (date_key.day < date_trans.day) {
        interval_count = interval_count - 1;
    }
    return PART_GET_INTERVAL_PARTNO(interval_count, part_table);
}

static uint32 interval_decimal_do_calc_partno(part_table_t *part_table, dec8_t *trans_dec, dec8_t *partkey_dec,
    dec8_t *interval_dec)
{
    dec8_t sub_result;
    dec8_t div_result;
    int32 interval_count;
    (void)cm_dec_subtract(partkey_dec, trans_dec, &sub_result);
    (void)cm_dec_divide(&sub_result, interval_dec, &div_result);
    if (cm_dec_to_int32(&div_result, &interval_count, ROUND_FLOOR) != CT_SUCCESS) {
        cm_reset_error();
        CT_LOG_RUN_ERR("[PART] The number of interval partitions overflow.");
        return CT_INVALID_ID32;
    }

    return PART_GET_INTERVAL_PARTNO(interval_count, part_table);
}


static uint32 intval_calc_partno_dec2(part_table_t *part_table, part_decode_key_t *transition_decoder,
    part_decode_key_t *decoder)
{
    dec8_t trans_dec;
    dec8_t partkey_dec;
    dec8_t interval_dec;

    (void)cm_dec_2_to_8(&trans_dec, (const payload_t *)PART_GET_INTERVAL_KEY(transition_decoder),
                        (uint8)PART_GET_INTERVAL_KEY_LEN(transition_decoder));
    (void)cm_dec_2_to_8(&partkey_dec, (const payload_t *)PART_GET_INTERVAL_KEY(decoder),
                        (uint8)PART_GET_INTERVAL_KEY_LEN(decoder));
    (void)cm_dec_2_to_8(&interval_dec, (const payload_t *)PART_GET_INTERVAL_KEY(part_table->desc.interval_key),
                        (uint8)PART_GET_INTERVAL_KEY_LEN(part_table->desc.interval_key));

    return interval_decimal_do_calc_partno(part_table, &trans_dec, &partkey_dec, &interval_dec);
}

static uint32 interval_calc_partno_dec(part_table_t *part_table, part_decode_key_t *transition_decoder,
                                       part_decode_key_t *decoder)
{
    dec4_t *transition;
    dec4_t *partkey;
    dec4_t *interval;
    dec8_t trans_dec;
    dec8_t partkey_dec;
    dec8_t interval_dec;

    transition = (dec4_t *)PART_GET_INTERVAL_KEY(transition_decoder);
    partkey = (dec4_t *)PART_GET_INTERVAL_KEY(decoder);
    interval = (dec4_t *)(PART_GET_INTERVAL_KEY(part_table->desc.interval_key));

    (void)cm_dec_4_to_8(&trans_dec, transition, transition_decoder->lens[0]);
    (void)cm_dec_4_to_8(&partkey_dec, partkey, decoder->lens[0]);
    (void)cm_dec_4_to_8(&interval_dec, interval, part_table->desc.interval_key->lens[0]);

    return interval_decimal_do_calc_partno(part_table, &trans_dec, &partkey_dec, &interval_dec);
}

uint32 part_locate_interval_key(part_table_t *part_table, part_decode_key_t *transition_decoder,
    part_decode_key_t *decoder)
{
    uint32 part_lno = CT_INVALID_ID32;
    part_key_t *interval_key = (part_key_t *)part_table->desc.binterval.bytes;
    uint8 bits;

    if (decoder->lens[0] == PART_KEY_MAX_LEN) {
        return CT_INVALID_ID32;
    }

    switch (part_table->keycols->datatype) {
        case CT_TYPE_DATE:
        case CT_TYPE_TIMESTAMP:

            bits = part_get_key_bits(interval_key, 0);
            if (bits == PART_KEY_BITS_4) {
                part_lno = interval_calc_partno_months(part_table, transition_decoder, decoder);
            } else {
                part_lno = interval_calc_partno_days(part_table, transition_decoder, decoder);
            }
            break;

        case CT_TYPE_UINT32:
        case CT_TYPE_INTEGER:
            part_lno = interval_calc_partno_int32(part_table, transition_decoder, decoder);
            break;
        
        case CT_TYPE_UINT64:
        case CT_TYPE_BIGINT:
            part_lno = interval_calc_partno_int64(part_table, transition_decoder, decoder);
            break;

        case CT_TYPE_NUMBER:
            part_lno = interval_calc_partno_dec(part_table, transition_decoder, decoder);
            break;

        case CT_TYPE_NUMBER2:
            part_lno = intval_calc_partno_dec2(part_table, transition_decoder, decoder);
            break;

        default:
            break;
    }

    return (part_lno >= CT_MAX_PART_COUNT) ? CT_INVALID_ID32 : part_lno;
}

static status_t interval_calc_bound_int32(part_decode_key_t *transition_key, part_decode_key_t *interval_key,
                                          uint32 interval_count, part_interval_bound_t *bound)
{
    int32 *transition_boundval;
    int32 *interval_boundval;
    int64 temp_result;

    transition_boundval = (int32 *)PART_GET_INTERVAL_KEY(transition_key);
    interval_boundval = (int32 *)PART_GET_INTERVAL_KEY(interval_key);

    // will check whether overflow
    temp_result = *transition_boundval + (int64)interval_count * (*interval_boundval);
    INT32_OVERFLOW_CHECK(temp_result);

    // if not overflow, then assign it to int_val
    bound->int32_val = (int32)temp_result;

    return CT_SUCCESS;
}

static status_t interval_calc_bound_int64(part_decode_key_t *transition_key, part_decode_key_t *interval_key,
                                          uint32 interval_count, part_interval_bound_t *bound)
{
    int64 temp;
    int64 result;
    int64 *transition_boundval = (int64 *)PART_GET_INTERVAL_KEY(transition_key);
    int64 *interval_boundval = (int64 *)PART_GET_INTERVAL_KEY(interval_key);

    if (CT_MAX_INT64 / (*interval_boundval) < interval_count) {
        CT_THROW_ERROR(ERR_TYPE_OVERFLOW, "BIG INTEGER");
        return CT_ERROR;
    }
   
    temp = (int64)interval_count * (*interval_boundval);
    if (*transition_boundval > 0 && CT_MAX_INT64 - (*transition_boundval) < temp) {
        CT_THROW_ERROR(ERR_TYPE_OVERFLOW, "BIG INTEGER");
        return CT_ERROR;
    }

    if (*transition_boundval < 0 && CT_MIN_INT64 - (*transition_boundval) > temp) {
        CT_THROW_ERROR(ERR_TYPE_OVERFLOW, "BIG INTEGER");
        return CT_ERROR;
    }

    result = *transition_boundval + temp;
   
    // if not overflow, then assign it to int_val
    bound->int64_val = (int64)result;

    return CT_SUCCESS;
}

static void interval_calc_bound_days(part_decode_key_t *transition_key, part_decode_key_t *interval_key,
                                     uint32 interval_count, part_interval_bound_t *bound)
{
    date_t *trans_bound;
    interval_ds_t *ds_interval;

    trans_bound = (date_t *)PART_GET_INTERVAL_KEY(transition_key);
    ds_interval = (interval_ds_t *)PART_GET_INTERVAL_KEY(interval_key);

    // check whether overflow after add in function cm_dsinterval_add
    (void)cm_dsinterval_add(*trans_bound, interval_count * (*ds_interval), &bound->date_val);
}

static status_t interval_calc_bound_months(part_decode_key_t *transition_key, part_decode_key_t *interval_key,
                                           uint32 interval_count, part_interval_bound_t *bound)
{
    date_t *trans_bound;
    interval_ym_t *ym_interval;
    int32 res;

    trans_bound = (date_t *)PART_GET_INTERVAL_KEY(transition_key);
    ym_interval = (interval_ym_t *)PART_GET_INTERVAL_KEY(interval_key);
    // check whether overflow
    if (opr_int32mul_overflow(interval_count, *ym_interval, &res)) {
        CT_THROW_ERROR(ERR_TYPE_OVERFLOW, "INTEGER");
        return CT_ERROR;
    }

    return cm_yminterval_add_date((int32)interval_count * (*ym_interval), *trans_bound, &bound->date_val);
}

static status_t part_genr_intval_date_bound(part_decode_key_t *trans_key, part_decode_key_t *intval_key,
    uint32 intval_count, part_interval_bound_t *intval_bound, part_key_t *intval_num)
{
    uint8 bits = part_get_key_bits(intval_num, 0);
    if (bits == PART_KEY_BITS_4) {
        return interval_calc_bound_months(trans_key, intval_key, intval_count, intval_bound);
    }
    interval_calc_bound_days(trans_key, intval_key, intval_count, intval_bound);
    return CT_SUCCESS;
}

static void part_dec_do_genr_bound(dec8_t *trans, dec8_t *intval, uint32 intval_cnt,
                                       part_interval_bound_t *bound)
{
    dec8_t intervals;
    (void)cm_dec8_mul_int64(intval, (int64)intval_cnt, &intervals);
    (void)cm_dec_add(trans, &intervals, &bound->dec_val);
}

static void part_genr_intval_dec2_bound(part_decode_key_t *trans_key, part_decode_key_t *intval_key,
                                              uint32 intval_cnt, part_interval_bound_t *bound)
{
    dec8_t transition_val;
    dec8_t interval_val;
    (void)cm_dec_2_to_8(&transition_val, (const payload_t *)PART_GET_INTERVAL_KEY(trans_key),
                        (uint8)PART_GET_INTERVAL_KEY_LEN(trans_key));
    (void)cm_dec_2_to_8(&interval_val, (const payload_t *)PART_GET_INTERVAL_KEY(intval_key),
                        (uint8)PART_GET_INTERVAL_KEY_LEN(intval_key));
    part_dec_do_genr_bound(&transition_val, &interval_val, intval_cnt, bound);
}

static void part_generate_interval_dec_bound(part_decode_key_t *transition_key, part_decode_key_t *interval_key,
                                             uint32 interval_count, part_interval_bound_t *bound)
{
    dec4_t *transition;
    dec4_t *interval;
    dec8_t transition_val;
    dec8_t interval_val;

    transition = (dec4_t *)PART_GET_INTERVAL_KEY(transition_key);
    interval = (dec4_t *)PART_GET_INTERVAL_KEY(interval_key);

    (void)cm_dec_4_to_8(&transition_val, transition, transition_key->lens[0]);
    (void)cm_dec_4_to_8(&interval_val, interval, interval_key->lens[0]);

    part_dec_do_genr_bound(&transition_val, &interval_val, interval_count, bound);
}

static status_t part_calc_interval_part_border(part_table_t *part_table, knl_part_key_t *table_key,
                                               part_key_t *intval_part_key, uint32 part_no)
{
    knl_part_key_t intval_key;
    knl_part_key_t trans_key;
    part_interval_bound_t intval_bound;
    uint32 intval_count = part_no - part_table->desc.transition_no;
    status_t status = CT_ERROR;

    table_part_t *trans_part = PART_GET_ENTITY(part_table, part_table->desc.transition_no);
    part_key_t *trans_part_key = (part_key_t *)trans_part->desc.bhiboundval.bytes;
    part_key_t *intval_num = (part_key_t *)part_table->desc.binterval.bytes;

    knl_decode_part_key(trans_part_key, &trans_key);
    knl_decode_part_key(intval_num, &intval_key);

    switch (part_table->keycols->datatype) {
        case CT_TYPE_UINT32:
        case CT_TYPE_INTEGER:
            status = interval_calc_bound_int32(&trans_key.decoder, &intval_key.decoder, intval_count, &intval_bound);
            (void)part_put_int32(intval_part_key, intval_bound.int32_val);
            break;
            
        case CT_TYPE_UINT64:
        case CT_TYPE_BIGINT:
            status = interval_calc_bound_int64(&trans_key.decoder, &intval_key.decoder, intval_count, &intval_bound);
            (void)part_put_int64(intval_part_key, intval_bound.int64_val);
            break;

        case CT_TYPE_NUMBER:
        case CT_TYPE_DECIMAL:
            part_generate_interval_dec_bound(&trans_key.decoder, &intval_key.decoder, intval_count, &intval_bound);
            status = part_put_dec4(intval_part_key, &intval_bound.dec_val);
            break;
        case CT_TYPE_NUMBER2:
            part_genr_intval_dec2_bound(&trans_key.decoder, &intval_key.decoder, intval_count, &intval_bound);
            status = part_put_dec2(intval_part_key, &intval_bound.dec_val);
            break;

        case CT_TYPE_DATE:
        case CT_TYPE_TIMESTAMP:
            if (part_genr_intval_date_bound(&trans_key.decoder, &intval_key.decoder, intval_count, &intval_bound,
                intval_num) != CT_SUCCESS) {
                return CT_ERROR;
            }
            status = part_put_date(intval_part_key, intval_bound.date_val);
            break;

        default:
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "invalid partition key type %u", part_table->keycols->datatype);
            knl_panic(CT_FALSE);
    }

    if (status != CT_SUCCESS) {
        CT_THROW_ERROR_EX(ERR_INVALID_PART_KEY, "invalid partition key value");
    }

    knl_decode_part_key(intval_part_key, table_key);

    return status;
}

/*
 * locate interval part border
 * Get the previous part key to see if it's locate on the previous or current partition
 * @param session handle, part table, locate key, left or not
 */
uint32 part_locate_interval_border(knl_handle_t handle, part_table_t *part_table, knl_part_key_t *locate_key,
    bool32 is_left)
{
    knl_session_t *session = (knl_session_t *)handle;
    table_part_t *table_part;
    uint32 part_no, prev_no;
    part_key_t *key = NULL;
    knl_part_key_t interval;
    int32 result;

    table_part = PART_GET_ENTITY(part_table, part_table->desc.transition_no);
    part_no = part_locate_interval_key(part_table, table_part->desc.groups, &locate_key->decoder);
    if (part_no == CT_INVALID_ID32) {
        return CT_INVALID_ID32;
    }

    prev_no = part_no - 1;
    if (prev_no >= part_table->desc.partcnt) {
        return CT_INVALID_ID32;
    }

    table_part = PART_GET_ENTITY(part_table, prev_no);
    if (table_part != NULL && table_part->is_ready) {
        result = part_compare_border(part_table->keycols, locate_key, table_part->desc.groups, is_left);
    } else {
        key = (part_key_t *)cm_push(session->stack, CT_MAX_PART_COLUMN_SIZE);

        part_key_init(key, 1);
        if (part_calc_interval_part_border(part_table, &interval, key, prev_no) != CT_SUCCESS) {
            cm_pop(session->stack);
            return CT_INVALID_ID32;
        }

        result = part_compare_border(part_table->keycols, locate_key, &interval.decoder, is_left);
        cm_pop(session->stack);
    }

    return (result < 0) ? prev_no : ((part_no >= part_table->desc.partcnt) ? CT_INVALID_ID32 : part_no);
}

static status_t part_convert_interval_range_table(knl_session_t *session, knl_cursor_t *cursor, table_t *table,
    uint32 trans_id, uint32 part_pos)
{
    row_assist_t ra;
    char new_name[CT_NAME_BUFFER_SIZE] = { 0 };
    uint32 old_partid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLEPART_COL_PART_ID);
    errno_t ret = snprintf_s(new_name, CT_NAME_BUFFER_SIZE, CT_NAME_BUFFER_SIZE - 1, "_SYS_%llX_P%u",
        DB_CURR_SCN(session), old_partid - PART_INTERVAL_BASE_ID + 1);
    knl_securec_check_ss(ret);
        
    /* max value for part_pos is: 4194304, max value for trans_id is: 4194304 */
    uint32 new_partid = trans_id + (part_pos + 1) * CT_DFT_PARTID_STEP;
    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), UPDATE_COLUMN_COUNT_TWO);

    (void)row_put_int32(&ra, new_partid);
    (void)row_put_str(&ra, new_name);
    cursor->update_info.count = UPDATE_COLUMN_COUNT_TWO;
    cursor->update_info.columns[0] = SYS_TABLEPART_COL_PART_ID;
    cursor->update_info.columns[1] = SYS_TABLEPART_COL_NAME;
    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, NULL);
    if (knl_internal_update(session, cursor) != CT_SUCCESS) {
        return CT_ERROR;
    }

    /* update parent part id of subpartitions of this part, if it is a parent part */
    if (IS_COMPART_TABLE(table->part_table)) {
        if (db_update_parent_tabpartid(session, table->desc.uid, table->desc.id, old_partid,
            new_partid) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    
    return CT_SUCCESS;
}

static status_t db_convert_interval_table_parts_to_range(knl_session_t *session, knl_cursor_t *cursor, table_t *table)
{
    uint32 part_id;
    uint32 trans_id = 0;  // transition part id
    uint32 part_index = 0;

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_TABLEPART_ID, IX_SYS_TABLEPART001_ID);
    knl_init_index_scan(cursor, CT_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &table->desc.uid,
                     sizeof(uint32), IX_COL_SYS_TABLEPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &table->desc.id,
                     sizeof(uint32), IX_COL_SYS_TABLEPART001_TABLE_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_TABLEPART001_PART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, &table->desc.uid,
                     sizeof(uint32), IX_COL_SYS_TABLEPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, &table->desc.id,
                     sizeof(uint32), IX_COL_SYS_TABLEPART001_TABLE_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_TABLEPART001_PART_ID);

    for (;;) {
        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (cursor->eof) {
            break;
        }

        part_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLEPART_COL_PART_ID);
        if (!PART_IS_INTERVAL(part_id)) {
            trans_id = part_id;
            continue;
        }
        
        knl_panic_log(trans_id != 0, "trans_id is zero, panic info: page %u-%u type %u table %s index %s",
                      cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                      table->desc.name, ((index_t *)cursor->index)->desc.name);
        if (part_convert_interval_range_table(session, cursor, table, trans_id, part_index) != CT_SUCCESS) {
            return CT_ERROR;
        }

        part_index++;
    }

    return CT_SUCCESS;
}

static status_t part_convert_interval_range_index(knl_session_t *session, knl_cursor_t *cursor, index_t *index,
    uint32 trans_id, uint32 part_pos)
{
    row_assist_t ra;
    char new_name[CT_NAME_BUFFER_SIZE] = { 0 };
    uint32 old_partid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_INDEXPART_COL_PART_ID);
    errno_t ret = snprintf_s(new_name, CT_NAME_BUFFER_SIZE, CT_NAME_BUFFER_SIZE - 1, "_SYS_%llX_P%u",
        DB_CURR_SCN(session), old_partid - PART_INTERVAL_BASE_ID + 1);
    knl_securec_check_ss(ret);

    uint32 new_partid = trans_id + (part_pos + 1) * CT_DFT_PARTID_STEP;
    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), UPDATE_COLUMN_COUNT_TWO);
    (void)row_put_int32(&ra, new_partid);
    (void)row_put_str(&ra, new_name);
    cursor->update_info.count = UPDATE_COLUMN_COUNT_TWO;
    cursor->update_info.columns[0] = SYS_INDEXPART_COL_PART_ID;
    cursor->update_info.columns[1] = SYS_INDEXPART_COL_NAME;
    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, NULL);
    
    if (knl_internal_update(session, cursor) != CT_SUCCESS) {
        return CT_ERROR;
    }

    /* update parent part id of subpartitions of this part, if it is a parent part */
    if (IS_COMPART_INDEX(index->part_index)) {
        if (db_upd_parent_idx_partid(session, &index->desc, old_partid, new_partid) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t db_convert_interval_index_part_to_range(knl_session_t *session, knl_cursor_t *cursor,
                                                        index_t *index)
{
    uint32 part_id;
    uint32 trans_id = 0;  // transition part id
    uint32 part_index = 0;

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_INDEXPART_ID, IX_SYS_INDEXPART001_ID);
    knl_init_index_scan(cursor, CT_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &index->desc.uid,
                     sizeof(uint32), IX_COL_SYS_INDEXPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &index->desc.table_id,
                     sizeof(uint32), IX_COL_SYS_INDEXPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &index->desc.id,
                     sizeof(uint32), IX_COL_SYS_INDEXPART001_INDEX_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_INDEXPART001_PART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, &index->desc.uid,
                     sizeof(uint32), IX_COL_SYS_INDEXPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, &index->desc.table_id,
                     sizeof(uint32), IX_COL_SYS_INDEXPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, &index->desc.id,
                     sizeof(uint32), IX_COL_SYS_INDEXPART001_INDEX_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_INDEXPART001_PART_ID);

    for (;;) {
        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (cursor->eof) {
            break;
        }

        part_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_INDEXPART_COL_PART_ID);
        if (!PART_IS_INTERVAL(part_id)) {
            trans_id = part_id;
            continue;
        }

        if (part_convert_interval_range_index(session, cursor, index, trans_id, part_index) != CT_SUCCESS) {
            return CT_ERROR;
        }

        part_index++;
    }
    
    return CT_SUCCESS;
}

static status_t part_convert_interval_range_lob(knl_session_t *session, knl_cursor_t *cursor, lob_t *lob,
    uint32 trans_id, uint32 part_pos)
{
    row_assist_t ra;
    uint32 old_partid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_LOBPART_COL_PART_ID);
    uint32 new_partid = trans_id + (part_pos + 1) * CT_DFT_PARTID_STEP;
    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), UPDATE_COLUMN_COUNT_ONE);
    
    (void)row_put_int32(&ra, new_partid);
    cursor->update_info.count = UPDATE_COLUMN_COUNT_ONE;
    cursor->update_info.columns[0] = SYS_LOBPART_COL_PART_ID;
    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, NULL);
    
    if (knl_internal_update(session, cursor) != CT_SUCCESS) {
        return CT_ERROR;
    }

    /* update parent part id of subpartitions of this part, if it is a parent part */
    knl_lob_part_desc_t desc = { 0 };
    desc.flags = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_LOBPART_COL_FLAGS);
    if (IS_PARENT_LOBPART(&desc)) {
        if (db_update_parent_lobpartid(session, &lob->desc, old_partid, new_partid) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t db_convert_interval_lob_part_to_range(knl_session_t *session, knl_cursor_t *cursor, lob_t *lob)
{
    uint32 part_id;
    uint32 trans_id = 0;  // transition part id
    uint32 part_index = 0;

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_LOBPART_ID, IX_SYS_LOBPART001_ID);
    knl_init_index_scan(cursor, CT_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &lob->desc.uid,
                     sizeof(uint32), IX_COL_SYS_LOBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &lob->desc.table_id,
                     sizeof(uint32), IX_COL_SYS_LOBPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &lob->desc.column_id,
                     sizeof(uint32), IX_COL_SYS_LOBPART001_COLUMN_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_LOBPART001_PART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, &lob->desc.uid,
                     sizeof(uint32), IX_COL_SYS_LOBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, &lob->desc.table_id,
                     sizeof(uint32), IX_COL_SYS_LOBPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, &lob->desc.column_id,
                     sizeof(uint32), IX_COL_SYS_LOBPART001_COLUMN_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_LOBPART001_PART_ID);

    for (;;) {
        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (cursor->eof) {
            break;
        }

        part_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_LOBPART_COL_PART_ID);
        if (!PART_IS_INTERVAL(part_id)) {
            trans_id = part_id;
            continue;
        }

        knl_panic_log(trans_id != 0, "trans_id is zero, panic info: page %u-%u type %u table %s index %s",
                      cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                      ((table_t *)cursor->table)->desc.name, ((index_t *)cursor->index)->desc.name);
        if (part_convert_interval_range_lob(session, cursor, lob, trans_id, part_index) != CT_SUCCESS) {
            return CT_ERROR;
        }

        part_index++;
    }

    return CT_SUCCESS;
}

static status_t db_convert_interval_part_to_range(knl_session_t *session, dc_entity_t *entity)
{
    knl_cursor_t *cursor = NULL;
    table_t *table = &entity->table;
    index_t *index = NULL;
    lob_t *lob = NULL;
    knl_column_t *column = NULL;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);
    if (db_convert_interval_table_parts_to_range(session, cursor, table) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    for (uint32 i = 0; i < table->index_set.total_count; i++) {
        index = table->index_set.items[i];
        if (IS_PART_INDEX(index)) {
            if (db_convert_interval_index_part_to_range(session, cursor, index) != CT_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                return CT_ERROR;
            }
        }
    }

    for (uint32 i = 0; i < entity->column_count; i++) {
        column = dc_get_column(entity, i);
        if (!COLUMN_IS_LOB(column)) {
            continue;
        }

        lob = (lob_t *)column->lob;

        if (IS_PART_TABLE(table)) {
            if (db_convert_interval_lob_part_to_range(session, cursor, lob) != CT_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                return CT_ERROR;
            }
        }
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

static status_t db_update_interval_part_interval(knl_session_t *session, table_t *table, text_t *interval,
    binary_t *binterval, bool32 is_inertval)
{
    row_assist_t ra;
    knl_part_desc_t *part_desc = &table->part_table->desc;

    CM_SAVE_STACK(session->stack);

    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_PARTOBJECT_ID, IX_SYS_PARTOBJECT001_ID);
    knl_init_index_scan(cursor, CT_FALSE);
    knl_index_desc_t *desc = INDEX_DESC(cursor->index);
    knl_scan_key_t *l_key = &cursor->scan_range.l_key;
    knl_scan_key_t *r_key = &cursor->scan_range.r_key;
    knl_set_scan_key(desc, l_key, CT_TYPE_INTEGER, &table->desc.uid, sizeof(uint32), IX_COL_SYS_PARTOBJECT001_USER_ID);
    knl_set_scan_key(desc, l_key, CT_TYPE_INTEGER, &table->desc.id, sizeof(uint32), IX_COL_SYS_PARTOBJECT001_TABLE_ID);
    knl_set_key_flag(l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_PARTOBJECT001_INDEX_ID);
    knl_set_scan_key(desc, r_key, CT_TYPE_INTEGER, &table->desc.uid, sizeof(uint32), IX_COL_SYS_PARTOBJECT001_USER_ID);
    knl_set_scan_key(desc, r_key, CT_TYPE_INTEGER, &table->desc.id, sizeof(uint32), IX_COL_SYS_PARTOBJECT001_TABLE_ID);
    knl_set_key_flag(r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_PARTOBJECT001_INDEX_ID);

    for (;;) {
        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }

        if (cursor->eof) {
            break;
        }

        if (is_inertval) {
            // because element of table part array of part group may be null, when set interval to range,
            // we must change part_cnt to number of no-null elements of table part array
            row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), UPDATE_COLUMN_COUNT_THREE);
            uint32 total_cnt = part_desc->transition_no + 1 + part_desc->interval_num + part_desc->not_ready_partcnt;
            (void)row_put_int32(&ra, total_cnt);
            cursor->update_info.count = UPDATE_COLUMN_COUNT_THREE;
            cursor->update_info.columns[0] = SYS_PARTOBJECT_COL_PARTCNT;
            cursor->update_info.columns[1] = SYS_PARTOBJECT_COL_INTERVAL;
            cursor->update_info.columns[2] = SYS_PARTOBJECT_COL_BINTERVAL;
        } else {
            // when set range to interval,we just set interval on sys table
            row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), UPDATE_COLUMN_COUNT_TWO);
            cursor->update_info.count = UPDATE_COLUMN_COUNT_TWO;
            cursor->update_info.columns[0] = SYS_PARTOBJECT_COL_INTERVAL;
            cursor->update_info.columns[1] = SYS_PARTOBJECT_COL_BINTERVAL;
        }
        
        (void)row_put_text(&ra, interval);
        (void)row_put_bin(&ra, binterval);
        cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, NULL);

        if (knl_internal_update(session, cursor) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

status_t part_check_transition_part_vaild(part_table_t *part_table, part_key_t *new_interval_key)
{
    knl_part_key_t part_key;
    date_detail_t detail;
    uint32 no = part_table->desc.partcnt - 1;
    table_part_t *part = PART_GET_ENTITY(part_table, no);
    part_key_t *key = (part_key_t *)part->desc.bhiboundval.bytes;
    uint8 bits;

    if (part_table->desc.not_ready_partcnt > 0) {
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "convert range partition table to interval partition table \
with not ready partition on the table");
        return CT_ERROR;
    }

    if (CT_IS_DATETIME_TYPE(part_table->keycols->datatype)) {
        bits = part_get_key_bits(new_interval_key, 0);
        knl_decode_part_key(key, &part_key);
        date_t *bound = (date_t *)PART_GET_INTERVAL_KEY(&part_key.decoder);
        cm_decode_date(*bound, &detail);

        // interval is month and day > 28
        if (bits == PART_KEY_BITS_4 && detail.day > PART_INTERVAL_DAY_HIGH_BOUND) {
            CT_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "specify this interval with existing high bounds");
            return CT_ERROR;
        }
    } else {
        bits = part_get_key_bits(key, 0);
    }

    if (bits == PART_KEY_BITS_MAX) {
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "SET INTERVAL on this table");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t db_altable_set_interval_part(knl_session_t *session, knl_dictionary_t *dc, knl_alt_part_t *def)
{
    knl_alt_part_interval_t *interval_def = &def->part_interval;
    dc_entity_t *entity = DC_ENTITY(dc);
    table_t *table = &entity->table;
    part_table_t *part_table = table->part_table;
    part_key_t *new_interval_key = NULL;

    if (part_table->desc.parttype != PART_TYPE_RANGE) {
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "set interval for other partition table except range");
        return CT_ERROR;
    }

    if (interval_def->interval.str != NULL) {
        new_interval_key = (part_key_t *)interval_def->binterval.bytes;
        // convert range to interval or change interval,we need to check interval is valid or not
        if (part_check_interval_valid(new_interval_key) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "interval is zero or less zero");
            return CT_ERROR;
        }

        // convert range to interval,we need to check last part is valid or not
        if (part_check_transition_part_vaild(part_table, new_interval_key) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (PART_CONTAIN_INTERVAL(part_table)) {
        // to convert interval to range or change interval
        if (db_update_interval_part_interval(session, table, &interval_def->interval, &interval_def->binterval,
            CT_TRUE) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (db_convert_interval_part_to_range(session, entity) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        // to convert range to interval
        if (db_update_interval_part_interval(session, table, &interval_def->interval, &interval_def->binterval,
            CT_FALSE) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (db_update_table_chgscn(session, &table->desc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

bool32 is_interval_part_created(knl_session_t *session, knl_dictionary_t *dc, uint32 part_no)
{
    table_part_t *table_part = NULL;
    dc_entity_t *dc_entity = DC_ENTITY(dc);
    part_table_t *part_table = dc_entity->table.part_table;

    if (part_no >= part_table->desc.partcnt) {
        return CT_FALSE;
    }

    table_part = PART_GET_ENTITY(part_table, part_no);
    if (table_part == NULL || !table_part->is_ready) {
        return CT_FALSE;
    }

    return CT_TRUE;
}

static status_t part_get_interval_boundval(part_table_t *part_table, text_t *hiboundval, uint32 hibv_str_max_size,
                                           binary_t *bhiboundval, uint32 part_no)
{
    uint8 bits;
    knl_part_key_t inter_key;
    knl_part_key_t trans_key;
    part_interval_bound_t inter_bound;
    status_t status = CT_ERROR;
    uint32 inter_count = part_no - part_table->desc.transition_no;
    
    table_part_t *trans_part = PART_GET_ENTITY(part_table, part_table->desc.transition_no);
    part_key_t *trans_part_key = (part_key_t *)trans_part->desc.bhiboundval.bytes;
    part_key_t *inter_num_key = (part_key_t *)part_table->desc.binterval.bytes;
    part_key_t *inter_part_key = (part_key_t *)bhiboundval->bytes;
    knl_decode_part_key(trans_part_key, &trans_key);
    knl_decode_part_key(inter_num_key, &inter_key);

    switch (part_table->keycols->datatype) {
        case CT_TYPE_UINT32:
        case CT_TYPE_INTEGER:
            status = interval_calc_bound_int32(&trans_key.decoder, &inter_key.decoder, inter_count, &inter_bound);
            cm_int2text(inter_bound.int32_val, hiboundval);
            (void)part_put_int32(inter_part_key, inter_bound.int32_val);
            return status;
            
        case CT_TYPE_UINT64:
        case CT_TYPE_BIGINT:
            status = interval_calc_bound_int64(&trans_key.decoder, &inter_key.decoder, inter_count, &inter_bound);
            cm_bigint2text(inter_bound.int64_val, hiboundval);
            (void)part_put_int64(inter_part_key, inter_bound.int64_val);
            return status;

        case CT_TYPE_NUMBER:
        case CT_TYPE_DECIMAL:
            part_generate_interval_dec_bound(&trans_key.decoder, &inter_key.decoder, inter_count, &inter_bound);
            (void)cm_dec_to_text(&inter_bound.dec_val, CT_MAX_DEC_OUTPUT_ALL_PREC, hiboundval);
            return part_put_dec4(inter_part_key, &inter_bound.dec_val);
        case CT_TYPE_NUMBER2:
            part_genr_intval_dec2_bound(&trans_key.decoder, &inter_key.decoder, inter_count, &inter_bound);
            (void)cm_dec_to_text(&inter_bound.dec_val, CT_MAX_DEC_OUTPUT_ALL_PREC, hiboundval);
            return part_put_dec2(inter_part_key, &inter_bound.dec_val);

        case CT_TYPE_DATE:
        case CT_TYPE_TIMESTAMP:
            bits = part_get_key_bits(inter_num_key, 0);
            if (bits == PART_KEY_BITS_4) {
                status = interval_calc_bound_months(&trans_key.decoder, &inter_key.decoder, inter_count, &inter_bound);
                if (status != CT_SUCCESS) {
                    return CT_ERROR;
                }
            } else {
                interval_calc_bound_days(&trans_key.decoder, &inter_key.decoder, inter_count, &inter_bound);
            }

            status = cm_date2text(inter_bound.date_val, NULL, hiboundval, hibv_str_max_size);
            if (status != CT_SUCCESS) {
                return CT_ERROR;
            }

            return part_put_date(inter_part_key, inter_bound.date_val);

        default:
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "invalid partition key type");
            return CT_ERROR;
    }
}

static status_t part_get_interval_part_spc(knl_session_t *session, table_t *table,
                                           knl_table_part_desc_t *part_desc, uint32 part_no)
{
    uint32 pos_id;
    uint32 index_id = CT_INVALID_ID32;
    part_table_t *part_table = table->part_table;
    knl_cursor_t *cursor = NULL;
    knl_part_store_desc_t desc;

    if (part_table->desc.interval_spc_num == 0) {
        part_desc->space_id = table->desc.space_id;
        return CT_SUCCESS;
    }

    CM_SAVE_STACK(session->stack);

    pos_id = (part_no - part_table->desc.transition_no) % part_table->desc.interval_spc_num;
    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_PARTSTORE_ID, IX_SYS_PARTSTORE001_ID);
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &part_table->desc.uid,
                     sizeof(uint32), IX_COL_SYS_PARTSTORE001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &part_table->desc.table_id,
                     sizeof(uint32), IX_COL_SYS_PARTSTORE001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &index_id, sizeof(uint32),
                     IX_COL_SYS_PARTSTORE001_INDEX_ID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s table_part %s index %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, table->desc.name,
                  part_desc->name, ((index_t *)cursor->index)->desc.name);

    while (!cursor->eof) {
        dc_convert_part_store_desc(cursor, &desc);

        if (pos_id == desc.pos_id) {
            part_desc->space_id = desc.space_id;
            break;
        }

        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

bool32 knl_verify_interval_part(knl_handle_t entity, uint32 part_id)
{
    part_table_t *part_table = ((dc_entity_t *)entity)->table.part_table;

    if (part_table->desc.parttype != PART_TYPE_RANGE) {
        return CT_FALSE;
    }

    if (!PART_CONTAIN_INTERVAL(part_table)) {
        return CT_FALSE;
    }

    if (part_id <= part_table->desc.transition_no) {
        return CT_FALSE;
    }

    return CT_TRUE;
}

static status_t part_add_interval_index_parts(knl_session_t *session, table_t *table,
                                              knl_table_part_desc_t *part_desc, uint32 part_no)
{
    knl_cursor_t *cursor = NULL;
    index_t *index = NULL;
    index_part_t *index_part = NULL;
    index_part_t *index_subpart = NULL;
    knl_index_part_desc_t desc;
    text_t text;
    uint32 i;
    part_key_t *key = NULL;
    errno_t ret;

    CM_SAVE_STACK(session->stack);

    cm_str2text(part_desc->name, &text);
    cursor = knl_push_cursor(session);

    for (i = 0; i < table->index_set.total_count; i++) {
        index = table->index_set.items[i];

        if (!IS_PART_INDEX(index)) {
            continue;
        }

        if (part_update_interval_part_count(session, table, part_no, index->desc.id, CT_TRUE) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }

        part_generate_index_part_desc(session, index, part_desc, &desc);
        key = (part_key_t *)desc.bhiboundval.bytes;
        knl_panic_log(key->column_count == 1, "column_count is abnormal, panic info: column_count %u page %u-%u "
            "type %u table %s table_part %s index %s", key->column_count, cursor->rowid.file, cursor->rowid.page,
            ((page_head_t *)cursor->page_buf)->type, table->desc.name, part_desc->name, index->desc.name);

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

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

static status_t part_add_interval_lob_parts(knl_session_t *session, knl_dictionary_t *dc,
                                            knl_table_part_desc_t *part_desc, uint32 part_no)
{
    uint32 space_id;
    lob_t *lob = NULL;
    knl_column_t *column = NULL;
    knl_lob_part_desc_t desc = { 0 };
    dc_entity_t *entity = DC_ENTITY(dc);
    table_t *table = &entity->table;

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);

    for (uint32 i = 0; i < table->desc.column_count; i++) {
        column = dc_get_column(entity, i);
        if (!COLUMN_IS_LOB(column)) {
            continue;
        }

        lob = (lob_t *)column->lob;
        space_id = lob->desc.space_id;

        part_init_lob_part_desc(session, &lob->desc, part_desc->part_id, space_id, &desc);
        if (IS_COMPART_TABLE(table->part_table)) {
            desc.is_parent = CT_TRUE;
            desc.subpart_cnt = 1;
        }

        if (part_write_sys_lobpart(session, cursor, &desc) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

static status_t part_add_interval_shadow_index_part(knl_session_t *session, knl_dictionary_t *dc,
                                                    knl_table_part_desc_t *desc, uint32 part_no)
{
    index_part_t index_part;
    table_t *table = DC_TABLE(dc);

    if (table->shadow_index == NULL) {
        return CT_SUCCESS;
    }

    if (!table->shadow_index->is_valid) {
        return CT_SUCCESS;
    }

    if (!IS_PART_INDEX(&table->shadow_index->index)) {
        return CT_SUCCESS;
    }

    index_t *index = &table->shadow_index->index;
    part_generate_index_part_desc(session, index, desc, &index_part.desc);
    if (!IS_PARENT_IDXPART(&index_part.desc)) {
        if (btree_create_part_segment(session, &index_part) != CT_SUCCESS) {
            return CT_ERROR;
        }
        if (btree_generate_create_undo(session, index_part.desc.entry, index_part.desc.space_id,
            IS_LOGGING_TABLE_BY_TYPE(dc->type)) != CT_SUCCESS) {
            btree_drop_part_segment(session, &index_part);
            return CT_ERROR;
        }
    }

    if (part_write_sys_shadowindex_part(session, &index_part.desc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t part_add_interval_table_part(knl_session_t *session, knl_dictionary_t *dc,
                                             knl_table_part_desc_t *part_desc,
                                             uint32 desc_hibdval_max_size, uint32 part_id, uint32 part_no)
{
    dc_entity_t *entity = DC_ENTITY(dc);
    table_t *table = &entity->table;
    part_table_t *part_table = table->part_table;

    part_desc->uid = table->desc.uid;
    part_desc->table_id = table->desc.id;
    part_desc->part_id = part_id;
    part_desc->entry = INVALID_PAGID;
    part_desc->org_scn = db_inc_scn(session);
    part_desc->seg_scn = part_desc->org_scn;
    part_desc->initrans = table->desc.initrans;
    part_desc->pctfree = table->desc.pctfree;
    part_desc->is_csf = table->desc.is_csf;
    part_desc->is_nologging = table->desc.is_nologging;
    part_desc->compress = table->desc.compress;
    part_desc->compress_algo = table->desc.compress_algo;

    part_key_init((part_key_t *)part_desc->bhiboundval.bytes, 1);

    if (part_get_interval_boundval(part_table, &part_desc->hiboundval, desc_hibdval_max_size, &part_desc->bhiboundval,
        part_no) != CT_SUCCESS) {
        return CT_ERROR;
    }

    part_desc->bhiboundval.size = ((part_key_t *)part_desc->bhiboundval.bytes)->size;

    if (part_get_interval_part_spc(session, table, part_desc, part_no) != CT_SUCCESS) {
        return CT_ERROR;
    }

    CM_SAVE_STACK(session->stack);

    knl_cursor_t *cursor = knl_push_cursor(session);
    if (db_write_sys_tablepart(session, cursor, &table->desc, part_desc) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (part_desc->is_nologging) {
        if (db_update_nologobj_cnt(session, CT_TRUE) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
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

static inline void part_generate_interval_part_name(knl_session_t *session, knl_table_part_desc_t *part_desc,
    part_table_t *part_table, uint32 partno)
{
    /* calculate this partition pos relative to the transition partition */
    uint32 pos = partno - part_table->desc.transition_no;

    errno_t ret = snprintf_s(part_desc->name, CT_NAME_BUFFER_SIZE, CT_NAME_BUFFER_SIZE - 1, "_SYS_P%u", pos);
    knl_securec_check_ss(ret);
}

uint32 part_calc_interval_part_count(part_table_t *part_table, uint32 part_no)
{
    uint32 part_cnt = CT_INVALID_ID32;

    if (part_no > part_table->desc.partcnt - 1) {
        knl_panic(part_table->desc.partcnt > 0);
        part_cnt = part_no + 1;

        if (part_cnt > CT_MAX_PART_COUNT) {
            return CT_INVALID_ID32;
        }
    } else {
        part_cnt = part_table->desc.partcnt;
    }

    return part_cnt;
}

static void part_interval_copy_part_desc(knl_table_part_desc_t *dest_desc, knl_table_part_desc_t *src_desc)
{
    text_t text = dest_desc->hiboundval;
    binary_t bin = dest_desc->bhiboundval;
    part_decode_key_t *decoder = dest_desc->groups;

    errno_t ret = memcpy_sp(dest_desc, sizeof(knl_table_part_desc_t), src_desc, sizeof(knl_table_part_desc_t));
    knl_securec_check(ret);

    dest_desc->bhiboundval.bytes = bin.bytes;
    dest_desc->bhiboundval.size = bin.size;
    dest_desc->hiboundval.str = text.str;
    dest_desc->hiboundval.len = text.len;
    dest_desc->groups = decoder;
}

static status_t subpart_generate_interval_name(knl_session_t *session, knl_table_part_desc_t *subpart_desc,
    part_table_t *part_table)
{
    text_t sys;
    text_t name;
    int64 object_id;

    cm_str2text("SYS", &sys);
    cm_str2text("OBJECT_ID$", &name);

    if (knl_seq_nextval(session, &sys, &name, &object_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    errno_t ret = snprintf_s(subpart_desc->name, CT_NAME_BUFFER_SIZE, CT_NAME_BUFFER_SIZE - 1,
        "SYS_SUBP%llX", object_id);
    knl_securec_check_ss(ret);

    return CT_SUCCESS;
}

static status_t subpart_add_interval_tabpart(knl_session_t *session, knl_table_part_desc_t *desc,
    table_part_t *compart, uint32 part_id)
{
    knl_table_part_desc_t *compart_desc = &compart->desc;

    desc->uid = compart_desc->uid;
    desc->table_id = compart_desc->table_id;
    desc->part_id = part_id;
    desc->entry = INVALID_PAGID;
    desc->org_scn = db_inc_scn(session);
    desc->seg_scn = desc->org_scn;
    desc->initrans = compart_desc->initrans;
    desc->pctfree = compart_desc->pctfree;
    desc->space_id = compart_desc->space_id;
    desc->flags = 0;
    desc->is_nologging = compart_desc->is_nologging;
    desc->is_csf = compart_desc->is_csf;

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);

    if (db_write_sys_tablesubpart(session, cursor, desc) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (desc->is_nologging) {
        if (db_update_nologobj_cnt(session, CT_TRUE) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }
    
    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}
    
static status_t subpart_add_interval_idxpart(knl_session_t *session, table_t *table, knl_table_part_desc_t *table_desc)
{
    index_t *index = NULL;
    knl_index_part_desc_t index_desc = { 0 };

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    
    for (uint32 i = 0; i < table->index_set.total_count; i++) {
        index = table->index_set.items[i];
        if (!IS_PART_INDEX(index) || !IS_COMPART_INDEX(index->part_index)) {
            continue;
        }

        part_generate_index_part_desc(session, index, table_desc, &index_desc);
        if (db_write_sys_indsubpart(session, cursor, &index_desc) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

static status_t subpart_add_interval_shwidxpart(knl_session_t *session, knl_dictionary_t *dc,
    knl_table_part_desc_t *table_desc)
{
    index_part_t index_subpart;
    table_t *table = DC_TABLE(dc);
    
    if (table->shadow_index == NULL) {
        return CT_SUCCESS;
    }

    if (!table->shadow_index->is_valid) {
        return CT_SUCCESS;
    }

    index_t *index = &table->shadow_index->index;
    if (!IS_PART_INDEX(index) || !IS_COMPART_INDEX(index->part_index)) {
        return CT_SUCCESS;
    }

    part_generate_index_part_desc(session, index, table_desc, &index_subpart.desc);

    if (btree_create_part_segment(session, &index_subpart) != CT_SUCCESS) {
        btree_drop_part_segment(session, &index_subpart);
        return CT_ERROR;
    }

    if (part_write_shadowindex_part(session, dc, &index_subpart, CT_TRUE) != CT_SUCCESS) {
        btree_drop_part_segment(session, &index_subpart);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t subpart_add_interval_lobpart(knl_session_t *session, knl_dictionary_t *dc,
    knl_table_part_desc_t *table_desc)
{
    uint32 space_id;
    lob_t *lob = NULL;
    knl_column_t *column = NULL;
    dc_entity_t *entity = DC_ENTITY(dc);
    table_t *table = &entity->table;
    knl_lob_part_desc_t lob_desc = { 0 };

    for (uint32 i = 0; i < table->desc.column_count; i++) {
        column = dc_get_column(entity, i);
        if (!COLUMN_IS_LOB(column)) {
            continue;
        }

        lob = (lob_t *)column->lob;
        space_id = lob->desc.space_id;

        part_init_lob_part_desc(session, &lob->desc, table_desc->part_id, space_id, &lob_desc);
        lob_desc.parent_partid = table_desc->parent_partid;
        if (subpart_write_syslob(session, &lob_desc) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static void subpart_interval_clear_old_dc(table_part_t *subpart)
{
    text_t text_temp;
    text_temp.str = subpart->desc.hiboundval.str;
    text_temp.len = subpart->desc.hiboundval.len;

    binary_t bin_temp;
    bin_temp.bytes = subpart->desc.bhiboundval.bytes;
    bin_temp.size = subpart->desc.bhiboundval.size;

    errno_t ret = memset_sp(subpart, sizeof(table_part_t), 0, sizeof(table_part_t));
    knl_securec_check(ret);
    subpart->desc.entry = INVALID_PAGID;
    subpart->desc.hiboundval.len = text_temp.len;
    subpart->desc.hiboundval.str = text_temp.str;
    subpart->desc.bhiboundval.size = bin_temp.size;
    subpart->desc.bhiboundval.bytes = bin_temp.bytes;
}

static status_t subpart_create_interval_part(knl_session_t *session, knl_dictionary_t *dc, table_part_t *compart)
{
    table_t *table = DC_TABLE(dc);
    part_table_t *part_table = table->part_table;
    table_part_t *subpart = PART_GET_SUBENTITY(part_table, compart->subparts[0]);

    /* clear the old info on the reserved dc */
    subpart_interval_clear_old_dc(subpart);
    uint32 subpart_id = subpart_generate_partid(table->part_table, compart, 0);

    if (subpart_generate_interval_name(session, &subpart->desc, part_table) != CT_SUCCESS) {
        return CT_ERROR;
    }
    subpart->desc.parent_partid = compart->desc.part_id;

    if (subpart_add_interval_tabpart(session, &subpart->desc, compart, subpart_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (subpart_add_interval_idxpart(session, table, &subpart->desc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (subpart_add_interval_shwidxpart(session, dc, &subpart->desc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (subpart_add_interval_lobpart(session, dc, &subpart->desc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t part_create_interval_part(knl_session_t *session, knl_dictionary_t *dc, uint32 part_no,
    part_key_t *part_key)
{
    knl_table_part_desc_t desc = { 0 };
    table_t *table = DC_TABLE(dc);
    part_table_t *part_table = table->part_table;
    char buf[CT_MAX_HIBOUND_VALUE_LEN] = { '\0' };
    
    desc.hiboundval.str = buf;
    desc.bhiboundval.bytes = (uint8 *)cm_push(session->stack, CT_MAX_COLUMN_SIZE);
    knl_panic_log(desc.bhiboundval.bytes != NULL, "bhiboundval's bytes is NULL, panic info: table %s",
                  table->desc.name);
    errno_t ret = memset_sp(desc.bhiboundval.bytes, CT_MAX_COLUMN_SIZE, 0, CT_MAX_COLUMN_SIZE);
    knl_securec_check(ret);
    
    /* generate part name : _SYS_PXXXXX */
    part_generate_interval_part_name(session, &desc, part_table, part_no);
    uint32 part_id = dc_generate_interval_part_id(part_no, part_table->desc.transition_no);
    if (IS_COMPART_TABLE(part_table)) {
        desc.is_parent = CT_TRUE;
        desc.subpart_cnt = 1;
    }
    
    if (part_add_interval_table_part(session, dc, &desc, CT_MAX_HIBOUND_VALUE_LEN, part_id, part_no) != CT_SUCCESS) {
        cm_pop(session->stack);
        return CT_ERROR;
    }

    if (part_add_interval_index_parts(session, table, &desc, part_no) != CT_SUCCESS) {
        cm_pop(session->stack);
        return CT_ERROR;
    }

    if (part_add_interval_shadow_index_part(session, dc, &desc, part_no) != CT_SUCCESS) {
        cm_pop(session->stack);
        return CT_ERROR;
    }

    if (part_add_interval_lob_parts(session, dc, &desc, part_no) != CT_SUCCESS) {
        cm_pop(session->stack);
        return CT_ERROR;
    }
    cm_pop(session->stack);
    if (part_update_interval_part_count(session, table, part_no, CT_INVALID_ID32, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (IS_COMPART_TABLE(part_table)) {
        table_part_t *part = TABLE_GET_PART(table, part_no);
        part->part_no = part_no;
        part_interval_copy_part_desc(&part->desc, &desc);
        if (subpart_create_interval_part(session, dc, part) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t db_cal_interval_bound_size(knl_session_t *session, part_table_t *part_table,
    knl_table_part_desc_t *desc, uint32 part_no)
{
    part_key_init((part_key_t *)desc->bhiboundval.bytes, 1);

    if (part_get_interval_boundval(part_table, &desc->hiboundval, CT_MAX_HIBOUND_VALUE_LEN, &desc->bhiboundval,
        part_no) != CT_SUCCESS) {
        return CT_ERROR;
    }

    desc->bhiboundval.size = ((part_key_t *)desc->bhiboundval.bytes)->size;

    return CT_SUCCESS;
}

static status_t db_reserve_interval_decoder_memory(knl_session_t *session, knl_dictionary_t *dc,
    part_key_t *key, uint32 part_no)
{
    dc_entity_t *entity = DC_ENTITY(dc);
    table_t *table = DC_TABLE(dc);
    dc_context_t *dc_ctx = &session->kernel->dc_ctx;
    part_table_t *part_table = table->part_table;
    table_part_t *part = PART_GET_ENTITY(part_table, part_no);
    uint32 mem_size = sizeof(part_decode_key_t) * key->column_count;
    if (part->desc.groups == NULL) {
        if (dc_alloc_mem(dc_ctx, entity->memory, mem_size, (void **)&part->desc.groups) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    errno_t ret = memset_sp(part->desc.groups, mem_size, 0, mem_size);
    knl_securec_check(ret);
    
    part_decode_key_t *decoder = part->desc.groups;
    mem_size = sizeof(uint16) * key->column_count;
    if (decoder->offsets == NULL) {
        if (dc_alloc_mem(dc_ctx, entity->memory, mem_size, (void **)&decoder->offsets) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (decoder->lens == NULL) {
        if (dc_alloc_mem(dc_ctx, entity->memory, mem_size, (void **)&decoder->lens) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t db_reserve_interval_boundval_memory(knl_session_t *session, knl_dictionary_t *dc, uint32 part_no)
{
    knl_table_part_desc_t desc;
    dc_context_t *ctx = &session->kernel->dc_ctx;
    dc_entity_t *entity = DC_ENTITY(dc);
    table_t *table = DC_TABLE(dc);
    part_table_t *part_table = table->part_table;
    char buf[CT_MAX_HIBOUND_VALUE_LEN] = { '\0' };

    desc.hiboundval.str = buf;
    desc.bhiboundval.bytes = (uint8 *)cm_push(session->stack, CT_MAX_COLUMN_SIZE);
    knl_panic_log(desc.bhiboundval.bytes != NULL, "bhiboundval's bytes is NULL, panic info: table %s",
                  table->desc.name);
    errno_t ret = memset_sp(desc.bhiboundval.bytes, CT_MAX_COLUMN_SIZE, 0, CT_MAX_COLUMN_SIZE);
    knl_securec_check(ret);

    if (db_cal_interval_bound_size(session, part_table, &desc, part_no) != CT_SUCCESS) {
        cm_pop(session->stack);
        return CT_ERROR;
    }

    uint32 mem_size = desc.hiboundval.len;
    table_part_t *part = PART_GET_ENTITY(part_table, part_no);
    if (part->desc.hiboundval.str == NULL) {
        if (dc_alloc_mem(ctx, entity->memory, mem_size, (void **)&part->desc.hiboundval.str) != CT_SUCCESS) {
            cm_pop(session->stack);
            return CT_ERROR;
        }
    }

    mem_size = desc.bhiboundval.size;
    if (part->desc.bhiboundval.bytes == NULL) {
        if (dc_alloc_mem(ctx, entity->memory, mem_size, (void **)&part->desc.bhiboundval.bytes) != CT_SUCCESS) {
            cm_pop(session->stack);
            return CT_ERROR;
        }
    }

    part_key_t *key = (part_key_t *)desc.bhiboundval.bytes;
    if (db_reserve_interval_decoder_memory(session, dc, key, part_no) != CT_SUCCESS) {
        cm_pop(session->stack);
        return CT_ERROR;
    }
        
    cm_pop(session->stack);
    return CT_SUCCESS;
}

static status_t dc_reserve_subpart_decoder_memory(knl_session_t *session, dc_entity_t *entity, table_part_t *subpart)
{
    uint32 mem_size = sizeof(part_decode_key_t);
    dc_context_t *dc_ctx = &session->kernel->dc_ctx;

    if (subpart->desc.groups == NULL) {
        if (dc_alloc_mem(dc_ctx, entity->memory, mem_size, (void **)&subpart->desc.groups) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    errno_t ret = memset_sp(subpart->desc.groups, mem_size, 0, mem_size);
    knl_securec_check(ret);
    
    mem_size = sizeof(uint16);
    part_decode_key_t *decoder = subpart->desc.groups;
    if (decoder->offsets == NULL) {
        if (dc_alloc_mem(dc_ctx, entity->memory, mem_size, (void **)&decoder->lens) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (decoder->lens == NULL) {
        if (dc_alloc_mem(dc_ctx, entity->memory, mem_size, (void **)&decoder->offsets) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static void subpart_generate_default_bound(part_table_t *part_table, part_key_t *bhibound, char *hibound)
{
    errno_t ret;

    if (part_table->desc.subparttype == PART_TYPE_RANGE) {
        uint32 subpart_keys = part_table->desc.subpartkeys;
        uint32 hiboundval_len = CT_MAX_PARTKEY_COLUMNS * CT_MAX_HIBOUND_VALUE_LEN;
        part_key_init(bhibound, subpart_keys);
        for (uint32 i = 0; i < subpart_keys; i++) {
            ret = strcat_sp(hibound, hiboundval_len, PART_VALUE_MAX);
            knl_securec_check(ret);
            if (i != subpart_keys - 1) {
                ret = strcat_sp(hibound, hiboundval_len, ", ");
                knl_securec_check(ret);
            } else {
                ret = strcat_sp(hibound, hiboundval_len, "\0");
                knl_securec_check(ret);
            }

            part_put_max(bhibound);
        }
    } else {
        ret = strcpy_sp(hibound, CT_MAX_PARTKEY_COLUMNS * CT_MAX_HIBOUND_VALUE_LEN, PART_VALUE_DEFAULT);
        knl_securec_check(ret);
        ret = strcat_sp(hibound, CT_MAX_PARTKEY_COLUMNS * CT_MAX_HIBOUND_VALUE_LEN, "\0");
        knl_securec_check(ret);
        part_put_default(bhibound);
    }
}

static status_t dc_reserve_subpart_boundval_memory(knl_session_t *session, dc_entity_t *entity, uint32 part_no)
{
    text_t text;
    table_t *table = &entity->table;
    dc_context_t *ctx = &session->kernel->dc_ctx;
    table_part_t *compart = TABLE_GET_PART(table, part_no);
    table_part_t *subpart = PART_GET_SUBENTITY(table->part_table, compart->subparts[0]);
    char hiboundval_buf[CT_MAX_PARTKEY_COLUMNS * CT_MAX_HIBOUND_VALUE_LEN] = { 0 };

    if (table->part_table->desc.subparttype == PART_TYPE_HASH) {
        return CT_SUCCESS;
    }
    
    CM_SAVE_STACK(session->stack);
    part_key_t *part_key = (part_key_t *)cm_push(session->stack, CT_MAX_COLUMN_SIZE);
    part_key_init(part_key, table->part_table->desc.subpartkeys);

    subpart_generate_default_bound(table->part_table, part_key, hiboundval_buf);
    text.str = hiboundval_buf;
    text.len = (uint32)strlen(hiboundval_buf);
    if (subpart->desc.hiboundval.str == NULL) {
        if (dc_alloc_mem(ctx, entity->memory, text.len, (void **)&subpart->desc.hiboundval.str) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }

    errno_t ret = memcpy_sp(subpart->desc.hiboundval.str, text.len, text.str, text.len);
    knl_securec_check(ret);
    subpart->desc.hiboundval.len = text.len;

    if (subpart->desc.bhiboundval.bytes == NULL) {
        if (dc_alloc_mem(ctx, entity->memory, part_key->size,
            (void **)&subpart->desc.bhiboundval.bytes) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }

    ret = memcpy_sp(subpart->desc.bhiboundval.bytes, part_key->size, part_key, part_key->size);
    knl_securec_check(ret);
    subpart->desc.bhiboundval.size = part_key->size;
    
    if (dc_reserve_subpart_decoder_memory(session, entity, subpart) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

static status_t db_reserve_subtabpart_dc_memory(knl_session_t *session, dc_entity_t *entity, uint32 part_no)
{
    table_t *table = &entity->table;
    
    table_part_t *table_part = TABLE_GET_PART(table, part_no);
    table_part->desc.subpart_cnt = 1;
    if (dc_alloc_table_subparts(session, entity, table_part) != CT_SUCCESS) {
        return CT_ERROR;
    }

    table_part->subparts[0] = table->part_table->desc.subpart_cnt;
    if (dc_alloc_table_subpart(session, entity, table->part_table->desc.subpart_cnt) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dc_reserve_subpart_boundval_memory(session, entity, part_no) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t db_reserve_subidxpart_dc_memory(knl_session_t *session, dc_entity_t *entity, uint32 part_no)
{
    index_t *index = NULL;
    table_t *table = &entity->table;
    index_part_t *compart_index = NULL;
    
    for (uint32 i = 0; i < table->index_set.total_count; i++) {
        index = table->index_set.items[i];
        if (!IS_PART_INDEX(index) || !IS_COMPART_INDEX(index->part_index)) {
            continue;
        }

        compart_index = INDEX_GET_PART(index, part_no);
        compart_index->desc.subpart_cnt = 1;    // interval compart has only one subpart
        if (dc_alloc_index_subparts(session, entity, compart_index) != CT_SUCCESS) {
            return CT_ERROR;
        }

        compart_index->subparts[0] = index->part_index->desc.subpart_cnt;
        if (dc_alloc_index_subpart(session, entity, index, index->part_index->desc.subpart_cnt) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (table->shadow_index != NULL && table->shadow_index->is_valid && IS_PART_INDEX(&table->shadow_index->index)) {
        index_t *shwidx = &table->shadow_index->index;
        index_part_t *shwidx_part = INDEX_GET_PART(shwidx, part_no);
        shwidx_part->desc.subpart_cnt = 1;
        if (dc_alloc_index_subparts(session, entity, shwidx_part) != CT_SUCCESS) {
            return CT_ERROR;
        }

        shwidx_part->subparts[0] = shwidx->part_index->desc.subpart_cnt;
        if (dc_alloc_index_subpart(session, entity, shwidx, shwidx->part_index->desc.subpart_cnt) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t db_reserve_sublobpart_dc_memory(knl_session_t *session, dc_entity_t *entity, uint32 part_no)
{
    lob_t *lob = NULL;
    knl_column_t *column = NULL;
    lob_part_t *compart_lob = NULL;
    table_t *table = &entity->table;
    
    for (uint32 i = 0; i < table->desc.column_count; i++) {
        column = dc_get_column(entity, i);
        if (!COLUMN_IS_LOB(column)) {
            continue;
        }

        lob = column->lob;
        compart_lob = LOB_GET_PART(lob, part_no);
        compart_lob->desc.subpart_cnt = 1;
        if (dc_alloc_lob_subparts(session, entity, compart_lob) != CT_SUCCESS) {
            return CT_ERROR;
        }

        compart_lob->subparts[0] = table->part_table->desc.subpart_cnt;
        if (dc_alloc_lob_subpart(session, entity, lob, table->part_table->desc.subpart_cnt) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t db_reserve_subpart_dc_memory(knl_session_t *session, knl_dictionary_t *dc, uint32 part_no)
{
    dc_entity_t *entity = DC_ENTITY(dc);

    if (db_reserve_subtabpart_dc_memory(session, entity, part_no) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (db_reserve_subidxpart_dc_memory(session, entity, part_no) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (db_reserve_sublobpart_dc_memory(session, entity, part_no) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t db_reserve_idxpart_dc_memory(knl_session_t *session, dc_entity_t *entity, uint32 part_no)
{
    index_t *index = NULL;
    part_index_t *part_index = NULL;
    table_t *table = &entity->table;

    /* for index part && cbo index part memory */
    for (uint32 i = 0; i < table->index_set.total_count; i++) {
        index = table->index_set.items[i];
        if (!IS_PART_INDEX(index)) {
            continue;
        }

        part_index = index->part_index;
        if (dc_alloc_index_part(session, entity, part_index, part_no) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (index->desc.is_invalid) {
            continue;
        }

        if (cbo_load_interval_index_part(session, entity, i, part_no) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    /* for shadow index memory */
    if (table->shadow_index != NULL && table->shadow_index->is_valid && IS_PART_INDEX(&table->shadow_index->index)) {
        part_index = table->shadow_index->index.part_index;
        if (dc_alloc_index_part(session, entity, part_index, part_no) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    
    return CT_SUCCESS;
}

static status_t db_reserve_lobpart_dc_memory(knl_session_t *session, dc_entity_t *entity, uint32 part_no)
{
    lob_t *lob = NULL;
    part_lob_t *part_lob = NULL;
    knl_column_t *column = NULL;
    table_t *table = &entity->table;

    for (uint32 i = 0; i < table->desc.column_count; i++) {
        column = dc_get_column(entity, i);
        if (!COLUMN_IS_LOB(column)) {
            continue;
        }

        lob = (lob_t *)column->lob;
        part_lob = lob->part_lob;

        if (dc_alloc_lob_part(session, entity, part_lob, part_no) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t db_reserve_interval_dc_memory(knl_session_t *session, knl_dictionary_t *dc, uint32 part_no)
{
    dc_entity_t *entity = DC_ENTITY(dc);
    table_t *table = DC_TABLE(dc);
    part_table_t *part_table = table->part_table;

    cm_latch_x(&entity->cbo_latch, session->id, NULL);

    /* for index part memory */
    if (db_reserve_idxpart_dc_memory(session, entity, part_no) != CT_SUCCESS) {
        cm_unlatch(&entity->cbo_latch, NULL);
        return CT_ERROR;
    }

    /* for lob part memory */
    if (db_reserve_lobpart_dc_memory(session, entity, part_no) != CT_SUCCESS) {
        cm_unlatch(&entity->cbo_latch, NULL);
        return CT_ERROR;
    }

    /* for table part memory */
    if (dc_alloc_table_part(session, entity, part_table, part_no) != CT_SUCCESS) {
        cm_unlatch(&entity->cbo_latch, NULL);
        return CT_ERROR;
    }

    // for cbo table part memory
    if (cbo_load_interval_table_part(session, entity, part_no) != CT_SUCCESS) {
        cm_unlatch(&entity->cbo_latch, NULL);
        return CT_ERROR;
    }

    // for hibound val memory
    if (db_reserve_interval_boundval_memory(session, dc, part_no) != CT_SUCCESS) {
        cm_unlatch(&entity->cbo_latch, NULL);
        return CT_ERROR;
    }

    if (IS_COMPART_TABLE(part_table)) {
        if (db_reserve_subpart_dc_memory(session, dc, part_no) != CT_SUCCESS) {
            cm_unlatch(&entity->cbo_latch, NULL);
            return CT_ERROR;
        }
    }

    cm_unlatch(&entity->cbo_latch, NULL);
    return CT_SUCCESS;
}

void db_create_interval_update_desc(table_t *table, uint32 part_cnt)
{
    index_t *index = NULL;
    part_table_t *part_table = table->part_table;
    part_table->desc.partcnt = part_cnt;
    part_table->desc.interval_num++;
    part_table->desc.real_partcnt++;

    for (uint32 i = 0; i < table->index_set.total_count; i++) {
        index = table->index_set.items[i];
        if (!IS_PART_INDEX(index)) {
            continue;
        }

        index->part_index->desc.partcnt = part_cnt;
        index->part_index->desc.interval_num++;
        index->part_index->desc.real_partcnt++;
    }
}

status_t db_create_interval_part(knl_session_t *session, knl_dictionary_t *dc, uint32 part_no,
                                 part_key_t *part_key)
{
    if (lock_table_shared(session, dc->handle, LOCK_INF_WAIT) != CT_SUCCESS) {
        return CT_ERROR;
    }

    table_t *table = DC_TABLE(dc);
    part_table_t *part_table = table->part_table;

    dls_latch_x(session, &part_table->interval_latch, session->id, &session->stat_interval);

    /* check physical part is created or not */
    if (is_interval_part_created(session, dc, part_no)) {
        dls_unlatch(session, &part_table->interval_latch, &session->stat_interval);
        return CT_SUCCESS;
    }

    if (db_reserve_interval_dc_memory(session, dc, part_no) != CT_SUCCESS) {
        dls_unlatch(session, &part_table->interval_latch, &session->stat_interval);
        return CT_ERROR;
    }

    uint32 part_cnt = part_calc_interval_part_count(part_table, part_no);
    if (part_cnt == CT_INVALID_ID32) {
        CT_THROW_ERROR(ERR_EXCEED_MAX_PARTCNT, (uint32)CT_MAX_PART_COUNT);
        dls_unlatch(session, &part_table->interval_latch, &session->stat_interval);
        return CT_ERROR;
    }

    if (knl_begin_auton_rm(session) != CT_SUCCESS) {
        dls_unlatch(session, &part_table->interval_latch, &session->stat_interval);
        return CT_ERROR;
    }

    if (part_create_interval_part(session, dc, part_no, part_key) != CT_SUCCESS) {
        knl_end_auton_rm(session, CT_ERROR);
        dls_unlatch(session, &part_table->interval_latch, &session->stat_interval);
        return CT_ERROR;
    }

    if (dc_load_interval_part(session, dc, part_no) != CT_SUCCESS) {
        knl_end_auton_rm(session, CT_ERROR);
        dls_unlatch(session, &part_table->interval_latch, &session->stat_interval);
        return CT_ERROR;
    }

    rd_create_interval_t redo;
    redo.tab_op.op_type = RD_CREATE_INTERVAL;
    redo.tab_op.uid = part_table->desc.uid;
    redo.tab_op.oid = part_table->desc.table_id;
    redo.part_no = part_no;
    redo.part_cnt = part_cnt;
    log_put(session, RD_LOGIC_OPERATION, &redo, sizeof(rd_create_interval_t), LOG_ENTRY_FLAG_NONE);

    knl_end_auton_rm(session, CT_SUCCESS);
    db_create_interval_update_desc(table, part_cnt);
    table_part_t *interval_part = PART_GET_ENTITY(part_table, part_no);
    interval_part->is_ready = CT_TRUE;

    dls_init_spinlock2(&interval_part->heap.lock, DR_TYPE_HEAP_PART, interval_part->desc.table_id,
                       interval_part->desc.uid, interval_part->desc.part_id, interval_part->part_no,
                       interval_part->parent_partno);
    dls_init_latch2(&interval_part->heap.latch, DR_TYPE_HEAP_PART_LATCH, interval_part->desc.table_id,
                    interval_part->desc.uid, interval_part->desc.part_id, interval_part->part_no,
                    interval_part->parent_partno, 0);

    dls_unlatch(session, &part_table->interval_latch, &session->stat_interval);
    return CT_SUCCESS;
}
