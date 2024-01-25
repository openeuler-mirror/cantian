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
 * knl_index.c
 *
 *
 * IDENTIFICATION
 * src/kernel/index/knl_index.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_index_module.h"
#include "knl_index.h"
#include "rcr_btree_scan.h"
#include "knl_context.h"
#include "pcr_btree_scan.h"
#include "knl_table.h"
#include "temp_btree.h"
#include "cm_decimal.h"
#include "dc_subpart.h"
#include "dc_part.h"
#include "dtc_dls.h"
#include "dtc_tran.h"

#define MAX_DUPKEY_MSG_LEN 256
#define MAX_INDEX_COLUMN_MSG_LEN 128
#define MAX_INDEX_COLUMN_STR_LEN 6  // sizeof("65535,")

static text_t g_idx_ts_fmt = { "YYYY-MM-DD HH24:MI:SS.FF", 24 };
static text_t g_idx_tstz_fmt = { "YYYY-MM-DD HH24:MI:SS.FF TZH:TZM", 32 };

/* btree index access method */
idx_accessor_t g_btree_acsor = { (knl_cursor_operator_t)btree_fetch, (knl_cursor_operator_t)btree_insert,
                                 (knl_cursor_operator_t)btree_delete };

/* PCR btree index access method */
idx_accessor_t g_pcr_btree_acsor = { (knl_cursor_operator_t)pcrb_fetch, (knl_cursor_operator_t)pcrb_insert,
                                     (knl_cursor_operator_t)pcrb_delete };

/* temp btree index access method */
idx_accessor_t g_temp_btree_acsor = { (knl_cursor_operator_t)temp_btree_fetch, (knl_cursor_operator_t)temp_btree_insert,
                                      (knl_cursor_operator_t)temp_btree_delete };

/* temp btree index access method */
idx_accessor_t g_invalid_index_acsor = { (knl_cursor_operator_t)db_invalid_cursor_operation,
                                         (knl_cursor_operator_t)db_invalid_cursor_operation,
                                         (knl_cursor_operator_t)db_invalid_cursor_operation };

typedef struct st_idx_data_info {
    idx_put_key_data_t put_method;
    char *key_buf;
    index_t *index;
    uint16 cols;
    uint16 key_size;
    uint16 offset;
} idx_data_info_t;

static void idx_get_varaint_data(variant_t *expr_value, char **data, uint16 *len, dec4_t *d4, dec2_t *d2)
{
    if (expr_value->is_null) {
        *data = NULL;
        *len = CT_NULL_VALUE_LEN;
        return;
    }
    switch (expr_value->type) {
        case CT_TYPE_UINT32:
            *data = (char *)&expr_value->v_uint32;
            *len = sizeof(uint32);
            break;
        case CT_TYPE_INTEGER:
            *data = (char *)&expr_value->v_int;
            *len = sizeof(int32);
            break;

        case CT_TYPE_BOOLEAN:
            *data = (char *)&expr_value->v_bool;
            *len = sizeof(bool32);
            break;

        case CT_TYPE_UINT64:
            *data = (char *)&expr_value->v_ubigint;
            *len = sizeof(uint64);
            break;

        case CT_TYPE_BIGINT:
        case CT_TYPE_DATE:
        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
        case CT_TYPE_TIMESTAMP_LTZ:
        case CT_TYPE_DATETIME_MYSQL:
        case CT_TYPE_TIME_MYSQL:
        case CT_TYPE_DATE_MYSQL:
            *data = (char *)&expr_value->v_bigint;
            *len = sizeof(int64);
            break;

        case CT_TYPE_TIMESTAMP_TZ:
            *data = (char *)&expr_value->v_tstamp_tz;
            *len = sizeof(timestamp_tz_t);
            break;

        case CT_TYPE_INTERVAL_DS:
            *data = (char *)&expr_value->v_itvl_ds;
            *len = sizeof(interval_ds_t);
            break;

        case CT_TYPE_INTERVAL_YM:
            *data = (char *)&expr_value->v_itvl_ym;
            *len = sizeof(interval_ym_t);
            break;

        case CT_TYPE_REAL:
            *data = (char *)&expr_value->v_real;
            *len = sizeof(double);
            break;

        case CT_TYPE_DECIMAL:
        case CT_TYPE_NUMBER3:
        case CT_TYPE_NUMBER:
            (void)cm_dec_8_to_4(d4, (const dec8_t *)&expr_value->v_dec);
            *data = (char *)d4;
            *len = cm_dec4_stor_sz(d4);
            break;
        case CT_TYPE_NUMBER2:
            (void)cm_dec_8_to_2(d2, (const dec8_t *)&expr_value->v_dec);
            *data = (char *)GET_PAYLOAD(d2);
            *len = cm_dec2_stor_sz(d2);
            break;
        case CT_TYPE_BINARY:
        case CT_TYPE_VARBINARY:
        case CT_TYPE_RAW:
            *data = (char *)expr_value->v_bin.bytes;
            *len = expr_value->v_bin.size;
            break;

        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
        case CT_TYPE_STRING:
        default:
            *data = expr_value->v_text.str;
            *len = expr_value->v_text.len;
            break;
    }
}

void idx_decode_row(knl_session_t *session, knl_cursor_t *cursor, uint16 *offsets, uint16 *lens, uint16 *size)
{
    dc_entity_t *entity;
    index_t *index;
    knl_column_t *column = NULL;
    char *key_buf = NULL;
    uint32 i;
    uint16 bitmap;
    uint32 col_id;
    uint32 off;

    index = (index_t *)cursor->index;
    entity = index->entity;

    if (index->desc.cr_mode == CR_PAGE) {
        bitmap = cursor->bitmap;
    } else {
        if (cursor->index_dsc) {
            key_buf = cursor->scan_range.r_key.buf;
        } else {
            key_buf = cursor->scan_range.l_key.buf;
        }

        btree_convert_row(session, &index->desc, key_buf, cursor->row, &bitmap);
    }

    off = sizeof(row_head_t);
    /* elements of offsets, i.e., offsets[i], cannot exceed the upper limit of uint16 */
    for (i = 0; i < index->desc.column_count; i++) {
        col_id = index->desc.columns[i];
        column = dc_get_column(entity, col_id);

        if (!btree_get_bitmap(&bitmap, i)) {
            lens[i] = CT_NULL_VALUE_LEN;
            continue;
        }

        switch (column->datatype) {
            case CT_TYPE_UINT32:
            case CT_TYPE_INTEGER:
            case CT_TYPE_BOOLEAN:
                lens[i] = sizeof(uint32);
                offsets[i] = off;
                off += sizeof(uint32);
                break;
            case CT_TYPE_UINT64:
            case CT_TYPE_BIGINT:
            case CT_TYPE_REAL:
            case CT_TYPE_DATE:
            case CT_TYPE_TIMESTAMP:
            case CT_TYPE_TIMESTAMP_TZ_FAKE:
            case CT_TYPE_TIMESTAMP_LTZ:
            case CT_TYPE_DATETIME_MYSQL:
            case CT_TYPE_TIME_MYSQL:
            case CT_TYPE_DATE_MYSQL:
                lens[i] = sizeof(int64);
                offsets[i] = off;
                off += sizeof(int64);
                break;
            case CT_TYPE_TIMESTAMP_TZ:
                lens[i] = sizeof(timestamp_tz_t);
                offsets[i] = off;
                off += sizeof(timestamp_tz_t);
                break;
            case CT_TYPE_INTERVAL_YM:
                lens[i] = sizeof(interval_ym_t);
                offsets[i] = off;
                off += sizeof(interval_ym_t);
                break;
            case CT_TYPE_INTERVAL_DS:
                lens[i] = sizeof(interval_ds_t);
                offsets[i] = off;
                off += sizeof(interval_ds_t);
                break;
            case CT_TYPE_NUMBER2:
                lens[i] = *(uint8 *)((char *)cursor->row + off);
                offsets[i] = (uint16)sizeof(uint8) + off;
                off += (sizeof(uint8) + lens[i]);
                break;
            case CT_TYPE_DECIMAL:
            case CT_TYPE_NUMBER3:
            case CT_TYPE_NUMBER:
                if (index->desc.cr_mode == CR_PAGE) {
                    lens[i] = DECIMAL_LEN(((char *)cursor->row + off));
                    offsets[i] = off;
                    off += CM_ALIGN4(lens[i]);
                    break;
                }
            // fall-through
            case CT_TYPE_CHAR:
            case CT_TYPE_VARCHAR:
            case CT_TYPE_STRING:
            case CT_TYPE_BINARY:
            case CT_TYPE_VARBINARY:
            case CT_TYPE_RAW:
                lens[i] = *(uint16 *)((char *)cursor->row + off);
                offsets[i] = (uint16)sizeof(uint16) + off;
                off += CM_ALIGN4(lens[i] + sizeof(uint16));
                break;
            default:
                knl_panic_log(0, "column's datatype is unknown, panic info: table %s index %s column datatype %u "
                              "page %u-%u type %u", entity->table.desc.name, index->desc.name, column->datatype,
                              cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type);
        }

        if (SECUREC_UNLIKELY(IS_REVERSE_INDEX(&index->desc))) {
            idx_reverse_key_data(((char*)(cursor->row) + offsets[i]), column->datatype, lens[i]);
        }
    }
}

/* judge index column type which has 2 bytes for column's length */
static inline bool32 index_is_varaint_type(bool32 is_page_cr, uint32 type)
{
    if (type >= CT_TYPE_CHAR && type <= CT_TYPE_VARBINARY) {
        return CT_TRUE;
    }

    if (type == CT_TYPE_RAW) {
        return CT_TRUE;
    }

    if ((type == CT_TYPE_DECIMAL || type == CT_TYPE_NUMBER) && !is_page_cr) {
        return CT_TRUE;
    }

    return CT_FALSE;
}

static inline void index_reverse_print_key(knl_column_t *column, bool32 is_page_cr, char *data)
{
    if (index_is_varaint_type(is_page_cr, column->datatype)) {
        idx_reverse_key_data(data + sizeof(uint16), column->datatype, *(uint16*)data);
    } else if (column->datatype == CT_TYPE_NUMBER2) {
        idx_reverse_key_data(data + sizeof(uint8), column->datatype, *(uint8*)data);
    } else {
        uint16 size = idx_get_col_size(column->datatype, DECIMAL_FORMAT_LEN(data), is_page_cr);
        idx_reverse_key_data(data, column->datatype, size);
    }
}

static void index_print_key(knl_session_t *session, index_t *index, const char *key, char *buf, uint16 buf_len)
{
    dc_entity_t *entity = index->entity;
    knl_column_t *column = NULL;
    uint16 bitmap;
    char *data = NULL;
    uint16 i;
    uint16 col_id;
    text_t value;
    errno_t ret;
    binary_t bin;
    uint16 size_left = buf_len;
    uint16 offset = 0;
    char col_str[MAX_INDEX_COLUMN_MSG_LEN];
    bool32 is_pcr = (index->desc.cr_mode == CR_PAGE);
    uint32 copy_size;

    value.str = (char *)col_str;
    value.len = MAX_INDEX_COLUMN_MSG_LEN;

    CM_SAVE_STACK(session->stack);
    data = (char*)cm_push(session->stack, CT_MAX_KEY_SIZE);

    if (is_pcr) {
        bitmap = ((pcrb_key_t *)key)->bitmap;
        copy_size = ((pcrb_key_t *)key)->size - sizeof(pcrb_key_t);
        ret = memcpy_sp(data, CT_MAX_KEY_SIZE, key + sizeof(pcrb_key_t), copy_size);
        knl_securec_check(ret);
    } else {
        bitmap = ((btree_key_t *)key)->bitmap;
        copy_size = ((btree_key_t *)key)->size - sizeof(btree_key_t);
        ret = memcpy_sp(data, CT_MAX_KEY_SIZE, key + sizeof(btree_key_t), copy_size);
        knl_securec_check(ret);
    }

    for (i = 0; i < index->desc.column_count; i++) {
        col_id = index->desc.columns[i];
        column = dc_get_column(entity, col_id);

        if (!btree_get_bitmap(&bitmap, i)) {
            ret = strcpy_s(value.str, MAX_INDEX_COLUMN_MSG_LEN, "null");
            knl_securec_check(ret);
            value.len = (uint32)strlen("null");
        } else {
            if (SECUREC_UNLIKELY(IS_REVERSE_INDEX(&index->desc))) {
                index_reverse_print_key(column, is_pcr, data);
            }

            switch (column->datatype) {
                case CT_TYPE_UINT32:
                    cm_uint32_to_text(*(uint32 *)data, &value);
                    data += sizeof(uint32);
                    break;
                case CT_TYPE_INTEGER:
                    cm_int2text(*(int32 *)data, &value);
                    data += sizeof(int32);
                    break;
                case CT_TYPE_BOOLEAN:
                    cm_bool2text(*(bool32 *)data, &value);
                    data += sizeof(bool32);
                    break;
                case CT_TYPE_UINT64:
                    cm_uint64_to_text(*(uint64 *)data, &value);
                    data += sizeof(uint64);
                    break;
                case CT_TYPE_BIGINT:
                    cm_bigint2text(*(int64 *)data, &value);
                    data += sizeof(int64);
                    break;
                case CT_TYPE_REAL:
                    cm_real2text(*(double *)data, &value);
                    data += sizeof(double);
                    break;
                case CT_TYPE_DATE_MYSQL:
                case CT_TYPE_DATETIME_MYSQL:
                case CT_TYPE_TIME_MYSQL:
                    (void)cm_date2text_mysql(column->datatype, *(date_t *)data, &g_idx_ts_fmt, &value,
                        MAX_INDEX_COLUMN_MSG_LEN);
                    data += sizeof(date_t);
                    break;
                case CT_TYPE_DATE:
                    (void)cm_date2text(*(date_t *)data, &g_idx_ts_fmt, &value, MAX_INDEX_COLUMN_MSG_LEN);
                    data += sizeof(date_t);
                    break;
                case CT_TYPE_TIMESTAMP:
                case CT_TYPE_TIMESTAMP_TZ_FAKE:
                case CT_TYPE_TIMESTAMP_LTZ:
                    (void)cm_timestamp2text(*(timestamp_t *)data, &g_idx_ts_fmt, &value, MAX_INDEX_COLUMN_MSG_LEN);
                    data += sizeof(timestamp_t);
                    break;
                case CT_TYPE_TIMESTAMP_TZ:
                    (void)cm_timestamp_tz2text((timestamp_tz_t *)data, &g_idx_tstz_fmt, &value,
                                               MAX_INDEX_COLUMN_MSG_LEN);
                    data += sizeof(timestamp_tz_t);
                    break;
                case CT_TYPE_INTERVAL_YM:
                    cm_yminterval2text(*(interval_ym_t *)data, &value);
                    data += sizeof(interval_ym_t);
                    break;
                case CT_TYPE_INTERVAL_DS:
                    cm_dsinterval2text(*(interval_ds_t *)data, &value);
                    data += sizeof(interval_ds_t);
                    break;
                case CT_TYPE_DECIMAL:
                case CT_TYPE_NUMBER3:
                case CT_TYPE_NUMBER: {
                    dec4_t *d4 = NULL;
                    if (index->desc.cr_mode == CR_PAGE) {
                        d4 = (dec4_t *)data;
                        data += DECIMAL_FORMAT_LEN(data);
                    } else {
                        d4 = (dec4_t *)(data + sizeof(uint16));
                        data += CM_ALIGN4(*(uint16 *)data + sizeof(uint16));
                    }
                    (void)cm_dec4_to_text(d4, CT_MAX_DEC_OUTPUT_ALL_PREC, &value);
                    break;
                }
                case CT_TYPE_NUMBER2: {
                    dec2_t d2;
                    cm_dec2_copy_ex(&d2, (const payload_t *)(data + sizeof(uint8)), *(uint8 *)data);
                    data += *(uint8 *)data + sizeof(uint8);
                    (void)cm_dec2_to_text(&d2, CT_MAX_DEC_OUTPUT_ALL_PREC, &value);
                    break;
                }

                // if not, go to varchar branch
                case CT_TYPE_CHAR:
                case CT_TYPE_VARCHAR:
                case CT_TYPE_STRING:
                    value.len = *(uint16 *)data;
                    if (value.len > 0) {
                        value.len = MIN(value.len, MAX_INDEX_COLUMN_MSG_LEN);
                        ret = memcpy_sp(value.str, MAX_INDEX_COLUMN_MSG_LEN, data + sizeof(uint16), value.len);
                        knl_securec_check(ret);
                    }
                    data += CM_ALIGN4(sizeof(uint16) + *(uint16 *)data);
                    break;
                case CT_TYPE_BINARY:
                case CT_TYPE_VARBINARY:
                case CT_TYPE_RAW:
                    bin.size = *(uint16 *)data;

                    /*
                     * the size of binary type is bin.size * 2
                     * and MAX_INDEX_COLUMN_MSG_LEN is a half of MAX_DUPKEY_MSG_LEN
                     * total here maximum size of bin is a quarter of MAX_DUPKEY_MSG_LEN
                     */
                    bin.size = MIN(bin.size, (MAX_DUPKEY_MSG_LEN - 1) / 4);
                    bin.bytes = (uint8 *)data + sizeof(uint16);
                    (void)cm_bin2text(&bin, CT_FALSE, &value);
                    data += CM_ALIGN4(sizeof(uint16) + bin.size);
                    break;
                default:
                    knl_panic_log(0, "column's datatype is unknown, panic info: table %s index %s column datatype %u",
                                  entity->table.desc.name, index->desc.name, column->datatype);
            }
        }

        if (value.len + 1 > size_left) {
            break;
        }

        size_left -= value.len + 1;

        if (i > 0) {
            buf[offset++] = '-';
        }
        if (value.len > 0) {
            ret = memcpy_sp(buf + offset, buf_len - offset, value.str, value.len);
            knl_securec_check(ret);
            offset += value.len;
        }
        value.len = MAX_INDEX_COLUMN_MSG_LEN;
    }
    buf[offset] = '\0';
    CM_RESTORE_STACK(session->stack);
}

status_t idx_generate_dupkey_error(knl_session_t *session, index_t *index, const char *key)
{
    char msg_buf[MAX_DUPKEY_MSG_LEN] = { 0 };
    errno_t ret;

    ret = snprintf_s(msg_buf, MAX_DUPKEY_MSG_LEN, MAX_DUPKEY_MSG_LEN - 1, ", index %s, duplicate key ",
                     index->desc.name);
    knl_securec_check_ss(ret);

    index_print_key(session, index, key, (char *)msg_buf + strlen(msg_buf),
        (uint16)(MAX_DUPKEY_MSG_LEN - strlen(msg_buf)));
    CT_THROW_ERROR(ERR_DUPLICATE_KEY, msg_buf);

    return CT_ERROR;
}

static status_t idx_try_put_key_data(uint16 col_size, uint32 datatype, const char *data, idx_data_info_t *key_info,
                                     uint32 idx_col_slot)
{
    index_t *index = key_info->index;

    key_info->key_size += CM_ALIGN4(sizeof(uint16) + col_size);
    if (key_info->key_size > index->desc.max_key_size) {
        key_info->key_size = (uint16)knl_get_key_size(&index->desc, key_info->key_buf) +
                             btree_max_column_size(datatype, col_size, (index->desc.cr_mode == CR_PAGE));
        if (key_info->key_size > key_info->index->desc.max_key_size) {
            CT_THROW_ERROR(ERR_MAX_KEYLEN_EXCEEDED, index->desc.max_key_size);
            return CT_ERROR;
        }
    }

    key_info->put_method(key_info->key_buf, datatype, data, col_size, idx_col_slot);

    if (SECUREC_UNLIKELY(IS_REVERSE_INDEX(&index->desc))) {
        bool32 is_pcr = (index->desc.cr_mode == CR_PAGE);
        uint16 size = idx_get_col_size(datatype, col_size, is_pcr);
        uint16 offset = is_pcr ? ((pcrb_key_t*)key_info->key_buf)->size - size :
            ((btree_key_t*)key_info->key_buf)->size - size;
        idx_reverse_key_data(key_info->key_buf + offset, datatype, col_size);
    }
    return CT_SUCCESS;
}

static status_t idx_make_virtual_col_data(knl_session_t *session, knl_cursor_t *cursor, index_t *index,
                                          uint32 idx_col_slot, idx_data_info_t *key_info)
{
    knl_column_t *column = dc_get_column(index->entity, index->desc.columns[idx_col_slot]);
    variant_t expr_value;
    char *data = NULL;
    uint16 col_size;
    dec4_t d4;
    dec2_t d2;

    if (g_knl_callback.func_idx_exec(session, (void *)cursor, column->datatype, column->default_expr, &expr_value,
                                     CT_FALSE)) {
        return CT_ERROR;
    }

    if (expr_value.is_null) {
        if (index->desc.primary) {
            CT_THROW_ERROR(ERR_COLUMN_NOT_NULL, column->name);
            return CT_ERROR;
        }

        key_info->put_method(key_info->key_buf, column->datatype, NULL, CT_NULL_VALUE_LEN, idx_col_slot);
        return CT_SUCCESS;
    }

    idx_get_varaint_data(&expr_value, &data, &col_size, &d4, &d2);
    uint32 type = (uint32)expr_value.type;
    return idx_try_put_key_data(col_size, type, data, key_info, idx_col_slot);
}

static status_t idx_make_col_data(knl_session_t *session, knl_cursor_t *cursor, index_t *index, uint32 idx_col_slot,
                                  idx_data_info_t *key_info)
{
    uint32 col_id = index->desc.columns[idx_col_slot];
    knl_column_t *column = dc_get_column(index->entity, col_id);

    if (SECUREC_UNLIKELY(KNL_COLUMN_IS_VIRTUAL(column))) {
        return idx_make_virtual_col_data(session, cursor, index, idx_col_slot, key_info);
    }

    bool32 is_null = (CURSOR_COLUMN_SIZE(cursor, col_id) == CT_NULL_VALUE_LEN);
    if (is_null) {
        if (index->desc.primary) {
            CT_THROW_ERROR(ERR_COLUMN_NOT_NULL, column->name);
            return CT_ERROR;
        }

        key_info->put_method(key_info->key_buf, column->datatype, NULL, CT_NULL_VALUE_LEN, idx_col_slot);
        return CT_SUCCESS;
    }

    uint16 col_size = CURSOR_COLUMN_SIZE(cursor, col_id);
    char *data = CURSOR_COLUMN_DATA(cursor, col_id);
    return idx_try_put_key_data(col_size, column->datatype, data, key_info, idx_col_slot);
}

static void idx_init_key_data(knl_cursor_t *cursor, index_t *index, char *key_buf, idx_data_info_t *key_info)
{
    key_info->key_buf = key_buf;
    key_info->index = index;
    if (index->desc.cr_mode == CR_PAGE) {
        pcrb_init_key((pcrb_key_t *)key_buf, &cursor->rowid);
        key_info->put_method = pcrb_put_key_data;
        key_info->key_size = sizeof(pcrb_key_t);
    } else {
        btree_init_key((btree_key_t *)key_buf, &cursor->rowid);
        key_info->put_method = btree_put_key_data;
        key_info->key_size = sizeof(btree_key_t);
    }
}

status_t knl_make_key(knl_handle_t session, knl_cursor_t *cursor, index_t *index, char *key_buf)
{
    idx_data_info_t key_info;

    idx_init_key_data(cursor, index, key_buf, &key_info);
    /* the max value of index->desc.column_count is 16 */
    for (uint32 i = 0; i < index->desc.column_count; i++) {
        if (idx_make_col_data((knl_session_t *)session, cursor, index, i, &key_info) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    /*
     * append part_id for global index of partitioned table. when stats_make_index_key will use this function
     * its cursor->table is null and not supoort partation table .
     */
    if (cursor->table != NULL && IS_PART_TABLE(cursor->table) && !IS_PART_INDEX(index)) {
        if (index->desc.cr_mode == CR_PAGE) {
            pcrb_put_part_id(key_buf, ((table_part_t *)cursor->table_part)->desc.part_id);
            if (IS_SUB_TABPART(&((table_part_t *)cursor->table_part)->desc)) {
                pcrb_put_part_id(key_buf, ((table_part_t *)cursor->table_part)->desc.parent_partid);
            }
        } else {
            btree_put_part_id(key_buf, ((table_part_t *)cursor->table_part)->desc.part_id);
            if (IS_SUB_TABPART(&((table_part_t *)cursor->table_part)->desc)) {
                btree_put_part_id(key_buf, ((table_part_t *)cursor->table_part)->desc.parent_partid);
            }
        }
    }

    return CT_SUCCESS;
}

static status_t idx_generate_update_keyinfo(knl_session_t *session, knl_cursor_t *cursor, uint16 *map,
                                            uint32 idx_col_slot, idx_data_info_t *key_info)
{
    index_t *index = (index_t *)cursor->index;
    dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;
    knl_update_info_t *ui = &cursor->update_info;
    uint32 col_id = index->desc.columns[idx_col_slot];
    knl_column_t *column = dc_get_column(entity, col_id);
    variant_t expr_value;
    char *data = NULL;
    uint16 col_size;
    uint32 type;
    bool32 is_new = (map[idx_col_slot] != CT_INVALID_ID16);
    dec4_t d4;
    dec2_t d2;

    if (SECUREC_UNLIKELY(KNL_COLUMN_IS_VIRTUAL(column))) {
        if (g_knl_callback.func_idx_exec(session, (void *)cursor, column->datatype, column->default_expr, &expr_value,
                                         is_new) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (is_new && index->desc.primary && expr_value.is_null) {
            CT_THROW_ERROR(ERR_COLUMN_NOT_NULL, index->desc.name);
            return CT_ERROR;
        }
        type = (uint32)expr_value.type;
        idx_get_varaint_data(&expr_value, &data, &col_size, &d4, &d2);
    } else {
        type = column->datatype;
        if (is_new) {
            uint32 uid = map[idx_col_slot];
            if (index->desc.primary && ui->lens[uid] == CT_NULL_VALUE_LEN) {
                CT_THROW_ERROR(ERR_COLUMN_NOT_NULL, index->desc.name);
                return CT_ERROR;
            }
            data = ui->data + ui->offsets[uid];
            col_size = ui->lens[uid];
        } else {
            data = CURSOR_COLUMN_DATA(cursor, col_id);
            col_size = CURSOR_COLUMN_SIZE(cursor, col_id);
        }
    }

    return idx_try_put_key_data(col_size, type, data, key_info, idx_col_slot);
}

status_t knl_make_update_key(knl_handle_t session, knl_cursor_t *cursor, index_t *index, char *key_buf,
                             knl_update_info_t *ui, uint16 *map)
{
    idx_data_info_t key_info;

    idx_init_key_data(cursor, index, key_buf, &key_info);
    /* the max value of index->desc.column_count is 16 */
    for (uint32 i = 0; i < index->desc.column_count; i++) {
        if (idx_generate_update_keyinfo(session, cursor, map, i, &key_info) != CT_SUCCESS) {
            cm_pop(((knl_session_t *)session)->stack);
            return CT_ERROR;
        }
    }

    /* append part_id for global index of partitioned table */
    if (IS_PART_TABLE(cursor->table) && !IS_PART_INDEX(cursor->index)) {
        if (index->desc.cr_mode == CR_PAGE) {
            pcrb_put_part_id(key_buf, ((table_part_t *)cursor->table_part)->desc.part_id);
            if (cursor->part_loc.subpart_no != CT_INVALID_ID32) {
                pcrb_put_part_id(key_buf, ((table_part_t *)cursor->table_part)->desc.parent_partid);
            }
        } else {
            btree_put_part_id(key_buf, ((table_part_t *)cursor->table_part)->desc.part_id);
            if (cursor->part_loc.subpart_no != CT_INVALID_ID32) {
                btree_put_part_id(key_buf, ((table_part_t *)cursor->table_part)->desc.parent_partid);
            }
        }
    }

    return CT_SUCCESS;
}

status_t idx_construct(btree_mt_context_t *ctx)
{
    btree_t *btree;
    index_t *index;

    btree = (btree_t *)ctx->mtrl_ctx.segments[ctx->seg_id]->cmp_items;
    index = btree->index;

    if (index->desc.cr_mode == CR_PAGE) {
        return pcrb_construct(ctx);
    } else {
        return btree_construct(ctx);
    }
}

static table_part_t *idx_get_table_part(knl_session_t *session, knl_dictionary_t *dc,
    table_t *table, index_recycle_item_t *item)
{
    table_part_t *table_part = NULL;

    if (!IS_COMPART_TABLE(table->part_table)) {
        table_part = dc_get_table_part(table->part_table, item->part_org_scn);
    } else {
        table_part = dc_get_table_subpart(table->part_table, item->part_org_scn);
    }

    if (table_part == NULL) {
        return NULL;
    }

    if (!table_part->heap.loaded && !IS_INVALID_PAGID(table_part->heap.entry)) {
        if (dc_load_table_part_segment(session, dc->handle, table_part) != CT_SUCCESS) {
            CT_LOG_RUN_WAR("idx coalesce load segment failed.");
            cm_reset_error();
            return NULL;
        }
    }

    return table_part;
}

static btree_t *idx_get_recycle_btree(knl_session_t *session, knl_dictionary_t *dc,
    index_recycle_item_t *item, knl_part_locate_t *part_loc)
{
    index_t *index = dc_find_index_by_id(DC_ENTITY(dc), item->index_id);
    if (index == NULL) {
        return NULL;
    }

    part_loc->part_no = CT_INVALID_ID32;
    part_loc->subpart_no = CT_INVALID_ID32;

    if (item->part_org_scn == CT_INVALID_ID64) {
        return &index->btree;
    }

    table_t *table = DC_TABLE(dc);
    if (!IS_PART_TABLE(table) || !IS_PART_INDEX(index)) {
        return NULL;
    }

    table_part_t *table_part = idx_get_table_part(session, dc, table, item);
    if (table_part == NULL) {
        return NULL;
    }

    index_part_t *index_part = NULL;
    table_part_t *parent_tabpart = NULL;
    if (IS_SUB_TABPART(&table_part->desc)) {
        parent_tabpart = PART_GET_ENTITY(table->part_table, table_part->parent_partno);
        knl_panic_log(parent_tabpart != NULL, "parent_tabpart is NULL, panic info: table %s table_part %s index %s",
                      table->desc.name, table_part->desc.name, index->desc.name);
        index_part = INDEX_GET_PART(index, parent_tabpart->part_no);
        index_part = PART_GET_SUBENTITY(index->part_index, index_part->subparts[table_part->part_no]);
    } else {
        index_part = INDEX_GET_PART(index, table_part->part_no);
    }

    if (index_part == NULL) {
        return NULL;
    }

    if (parent_tabpart != NULL) {
        part_loc->part_no = parent_tabpart->part_no;
        part_loc->subpart_no = table_part->part_no;
    } else {
        part_loc->part_no = table_part->part_no;
        part_loc->subpart_no = CT_INVALID_ID32;
    }
    
    return &index_part->btree;
}

static bool32 index_need_rebuild(knl_session_t *session, idx_recycle_stats_t *idx_stats, btree_t *btree)
{
    uint16 page_size = bt_alloc_page_size(session, btree);
    uint64 sparse_pages = (uint64)idx_stats->parent_first_leafs + idx_stats->sparse_pages;
    uint64 sparse_size = sparse_pages * page_size;

    if (!session->kernel->attr.idx_auto_rebuild) {
        return CT_FALSE;
    }

    if (sparse_size >= CT_MIN_INDEX_RECYCLE_SIZE) {
        if (sparse_pages > idx_stats->total_leafs * INDEX_NEED_REBUILD_RATION ||
            sparse_size > INDEX_NEED_REBUILD_SIZE) {
            return CT_TRUE;
        }
    }

    CT_LOG_DEBUG_INF("no need rebuild index %s, sparse_pages %llu, sparse size %llu.",
        btree->index->desc.name, sparse_pages, sparse_size);
    return CT_FALSE;
}

static status_t idx_coalesce(knl_session_t *session, knl_dictionary_t *dc, index_recycle_item_t *item,
                             idx_recycle_stats_t *stats)
{
    bool32 lock_inuse = CT_FALSE;
    btree_t *btree = NULL;
    knl_part_locate_t part_loc;

    if (!lock_table_without_xact(session, dc->handle, &lock_inuse)) {
        stats->need_coalesce = CT_TRUE;
        CT_LOG_RUN_INF("coalesce lock table failed.idx_id %u, uid %u, table_id %u, part_org_scn %llu",
            item->index_id, item->uid, item->table_id, item->part_org_scn);
        cm_reset_error();
        return CT_SUCCESS;
    }

    btree = idx_get_recycle_btree(session, dc, item, &part_loc);
    if (btree == NULL || btree->segment == NULL) {
        CT_LOG_RUN_INF("no need coalesce index, segment is null."
            "idx_id %u, uid %u, table_id %u, part_org_scn %llu.",
            item->index_id, item->uid, item->table_id, item->part_org_scn);
        if (btree != NULL) {
            btree->wait_recycle = CT_FALSE;
        }
        stats->need_coalesce = CT_FALSE;
        unlock_table_without_xact(session, dc->handle, lock_inuse);
        return CT_SUCCESS;
    }

    if (btree_coalesce(session, btree, stats, part_loc, CT_TRUE) != CT_SUCCESS) {
        unlock_table_without_xact(session, dc->handle, lock_inuse);
        return CT_ERROR;
    }

    if (index_need_rebuild(session, stats, btree)) {
        auto_rebuild_add_index(session, btree->index, part_loc);
    }

    unlock_table_without_xact(session, dc->handle, lock_inuse);

    return CT_SUCCESS;
}

static status_t idx_recycle_index_pages(knl_session_t *session, index_recycle_item_t *item, idx_recycle_stats_t *stats)
{
    knl_dictionary_t dc;
    status_t status;
    knl_scn_t min_scn = btree_get_recycle_min_scn(session);
    stats->need_coalesce = CT_FALSE;
    stats->initerval_scn = db_time_scn(session, session->kernel->attr.idx_force_recycle_time, 0);
    stats->xid_val = CT_INVALID_ID64;

    if (item->is_tx_active) {
        txn_info_t txn_info;
        itl_t itl = { 0 };

        itl.is_active = 1;
        itl.xid = item->xid;

        if (DB_IS_CLUSTER(session)) {
            dtc_get_txn_info(session, CT_FALSE, itl.xid, &txn_info);
        } else {
            tx_get_info(session, CT_FALSE, itl.xid, &txn_info);
        }

        if (txn_info.status != XACT_END) {
            stats->need_coalesce = CT_TRUE;
            CT_LOG_DEBUG_INF("has active txn, wait coalesce agin."
                "idx_id %u, uid %u, table_id %u, part_org_scn %llu",
                item->index_id, item->uid, item->table_id, item->part_org_scn);
            return CT_SUCCESS;
        }

        item->is_tx_active = CT_FALSE;
        item->scn = txn_info.scn;
    }

    if (!bt_recycle_time_expire(session, stats->initerval_scn, min_scn, item->scn)) {
        stats->need_coalesce = CT_TRUE;

        CT_LOG_DEBUG_INF("coalesce unexpire.idx_id %u, uid %u, table_id %u, part_org_scn %llu",
            item->index_id, item->uid, item->table_id, item->part_org_scn);
        return CT_SUCCESS;
    }

    if (knl_open_dc_by_id(session, item->uid, item->table_id, &dc, CT_TRUE) != CT_SUCCESS) {
        stats->need_coalesce = CT_FALSE;
        CT_LOG_RUN_WAR("coalesce open dc failed.idx_id %u, uid %u, table_id %u, part_org_scn %llu",
            item->index_id, item->uid, item->table_id, item->part_org_scn);
        return CT_ERROR;
    }

    status = idx_coalesce(session, &dc, item, stats);
    if (status == CT_SUCCESS && stats->need_coalesce) {
        item->scn = DB_NOW_TO_SCN(session);
        if (stats->xid_val != CT_INVALID_ID64) {
            item->xid.value = stats->xid_val;
            item->is_tx_active = CT_TRUE;
        }
    }

    dc_close(&dc);

    return status;
}

static void idx_recycle_move_to_tail(knl_session_t *session)
{
    index_recycle_ctx_t *ctx = &session->kernel->index_ctx.recycle_ctx;

    cm_spin_lock(&ctx->lock, NULL);

    uint32 id = ctx->idx_list.first;
    CT_LOG_DEBUG_INF("move item to tail."
        "xid %llu scn %llu part_org_scn %llu table_id %u part_no %u uid %u index_id %u is_tx_active %d",
        ctx->items[id].xid.value, ctx->items[id].scn, ctx->items[id].part_org_scn, ctx->items[id].table_id,
        ctx->items[id].part_no, ctx->items[id].uid, ctx->items[id].index_id, ctx->items[id].is_tx_active);

    if (ctx->idx_list.count == 1) {
        cm_spin_unlock(&ctx->lock);
        return;
    }

    /* the max value of id is 255 */
    ctx->items[ctx->idx_list.last].next = id;
    ctx->idx_list.first = ctx->items[id].next;
    ctx->idx_list.last = id;
    ctx->items[id].next = CT_INVALID_ID32;
    cm_spin_unlock(&ctx->lock);
}

void idx_try_recycle(knl_session_t *session)
{
    index_recycle_ctx_t *ctx = &session->kernel->index_ctx.recycle_ctx;
    index_recycle_item_t *item = NULL;
    idx_recycle_stats_t stats;

    cm_spin_lock(&ctx->lock, NULL);

    if (ctx->idx_list.count == 0) {
        cm_spin_unlock(&ctx->lock);
        return;
    }

    uint32 id = ctx->idx_list.first;
    cm_spin_unlock(&ctx->lock);

    if (id != CT_INVALID_ID32) {
        item = &ctx->items[id];

        if (idx_recycle_index_pages(session, item, &stats) == CT_SUCCESS) {
            if (stats.need_coalesce) {
                idx_recycle_move_to_tail(session);
                return;
            }
        } else {
            CT_LOG_DEBUG_INF("remove uid %u idx_id %u table_id %u part_org_scn %llu",
                item->uid, item->index_id, item->table_id, item->part_org_scn);
            cm_reset_error();
        }

        cm_spin_lock(&ctx->lock, NULL);

        if (ctx->free_list.count == 0) {
            ctx->free_list.first = id;
        } else {
            /* the max value of id is 255 */
            ctx->items[ctx->free_list.last].next = id;
        }

        ctx->free_list.last = id;
        ctx->free_list.count++;
        id = item->next;
        ctx->idx_list.count--;
        ctx->idx_list.first = id;

        if (ctx->idx_list.count == 0) {
            ctx->idx_list.last = CT_INVALID_ID32;
        }

        item->next = CT_INVALID_ID32;
        item->index_id = CT_INVALID_ID32;
        cm_spin_unlock(&ctx->lock);
    }
}

#define RECYCLE_PROC_STIME 100
void idx_recycle_proc(thread_t *thread)
{
    knl_session_t *session = (knl_session_t *)thread->argument;
    index_recycle_ctx_t *ctx = &session->kernel->index_ctx.recycle_ctx;
    switch_ctrl_t *ctrl = &session->kernel->switch_ctrl;
    uint32 count = 0;

    cm_set_thread_name("index_recycle");
    CT_LOG_RUN_INF("index page recycle thread started");
    KNL_SESSION_SET_CURR_THREADID(session, cm_get_current_thread_id());

    ctx->is_working = CT_FALSE;

    while (!thread->closed) {
        if (session->kernel->db.status != DB_STATUS_OPEN) {
            session->status = SESSION_INACTIVE;
            cm_sleep(RECYCLE_PROC_STIME);
            continue;
        }

        if (DB_IS_MAINTENANCE(session) || DB_IS_READONLY(session) || !DB_IS_PRIMARY(&session->kernel->db)) {
            session->status = SESSION_INACTIVE;
            cm_sleep(RECYCLE_PROC_STIME);
            continue;
        }

        if (!session->kernel->dc_ctx.completed || DB_IN_BG_ROLLBACK(session) || ctx->idx_list.count == 0) {
            session->status = SESSION_INACTIVE;
            cm_sleep(RECYCLE_PROC_STIME);
            continue;
        }

        if (session->status == SESSION_INACTIVE) {
            session->status = SESSION_ACTIVE;
        }

        if (count % INDEX_RECY_CLOCK == 0) {
            db_set_with_switchctrl_lock(ctrl, &ctx->is_working);
            if (!ctx->is_working) {
                cm_sleep(RECYCLE_PROC_STIME);
                continue;
            }

            idx_try_recycle(session);
            ctx->is_working = CT_FALSE;
        }

        cm_sleep(RECYCLE_PROC_STIME);
        count++;
    }

    CT_LOG_RUN_INF("index_recycle thread closed");
    KNL_SESSION_CLEAR_THREADID(session);
}

void idx_recycle_close(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    index_recycle_ctx_t *ctx = &kernel->index_ctx.recycle_ctx;
    knl_session_t *recycle_se = kernel->sessions[SESSION_ID_IDX_RECYCLE];

    recycle_se->killed = CT_TRUE;
    cm_close_thread(&ctx->thread);
}

// calculate total count of keys in origin scan range by level
static uint32 idx_cal_keys_count(knl_session_t *session, idx_range_info_t org_info, uint32 level)
{
    uint32 keys = 0;
    btree_page_t *page = NULL;
    page_id_t next_page_id;

    buf_enter_page(session, org_info.l_page[level], LATCH_MODE_S, ENTER_PAGE_NORMAL);
    page = (btree_page_t *)session->curr_page;
    next_page_id = AS_PAGID(page->next);
    if (IS_INVALID_PAGID(next_page_id) || IS_SAME_PAGID(org_info.l_page[level], org_info.r_page[level])) {
        keys += org_info.r_slot[level] - org_info.l_slot[level] + 1;
        buf_leave_page(session, CT_FALSE);
        return keys;
    }

    keys += page->keys - org_info.l_slot[level];
    buf_leave_page(session, CT_FALSE);

    for (;;) {
        buf_enter_page(session, next_page_id, LATCH_MODE_S, ENTER_PAGE_NORMAL);
        page = (btree_page_t *)session->curr_page;

        if (IS_SAME_PAGID(next_page_id, org_info.r_page[level])) {
            keys += org_info.r_slot[level] + 1;
            buf_leave_page(session, CT_FALSE);
            break;
        }
        keys += page->keys;
        next_page_id = AS_PAGID(page->next);
        buf_leave_page(session, CT_FALSE);

        if (IS_INVALID_PAGID(next_page_id)) {
            return keys;
        }
    }

    return keys;
}

void idx_binary_search(index_t *index, char *curr_page, knl_scan_key_t *scan_key, btree_path_info_t *path_info,
                       bool32 cmp_rowid, bool32 *is_same)
{
    btree_page_t *page = (btree_page_t *)curr_page;

    if (index->desc.cr_mode == CR_PAGE) {
        pcrb_binary_search(INDEX_PROFILE(index), page, scan_key, path_info, cmp_rowid, is_same);
    } else {
        btree_binary_search(index, page, scan_key, path_info, cmp_rowid, is_same);
    }
}

status_t idx_get_tree_info(knl_session_t *session, btree_t *btree, knl_scn_t org_scn, knl_tree_info_t *tree_info)
{
    btree_segment_t *segment = NULL;
    page_head_t *head = NULL;

    if (buf_read_page(session, btree->entry, LATCH_MODE_S, ENTER_PAGE_NORMAL) != CT_SUCCESS) {
        return CT_ERROR;
    }
    head = (page_head_t *)session->curr_page;
    segment = BTREE_GET_SEGMENT(session);
    if (head->type != PAGE_TYPE_BTREE_HEAD || segment->org_scn != org_scn) {
        buf_leave_page(session, CT_FALSE);
        CT_THROW_ERROR(ERR_INDEX_ALREADY_DROPPED, btree->index->desc.name);
        return CT_ERROR;
    }

    tree_info->value = cm_atomic_get(&BTREE_SEGMENT(session, btree->entry, btree->segment)->tree_info.value);
    if (!spc_validate_page_id(session, AS_PAGID(tree_info->root))) {
        buf_leave_page(session, CT_FALSE);
        CT_THROW_ERROR(ERR_INDEX_ALREADY_DROPPED, btree->index->desc.name);
        return CT_ERROR;
    }

    buf_leave_page(session, CT_FALSE);
    return CT_SUCCESS;
}

// get left border info and right border info on (root - 1) level from org_key
static void idx_get_org_range(knl_session_t *session, index_t *index, knl_tree_info_t tree_info, knl_scan_key_t org_key,
                              uint32 *slot, page_id_t *page_id)
{
    pcrb_dir_t *pcrb_dir = NULL;
    pcrb_key_t *pcrb_key = NULL;
    btree_dir_t *btree_dir = NULL;
    btree_key_t *btree_key = NULL;
    btree_page_t *page = NULL;
    page_id_t child_page_id;
    btree_path_info_t path_info;
    bool32 is_same = CT_FALSE;

    child_page_id = AS_PAGID(tree_info.root);
    for (;;) {
        buf_enter_page(session, child_page_id, LATCH_MODE_S, ENTER_PAGE_NORMAL);
        page = (btree_page_t *)session->curr_page;

        idx_binary_search(index, session->curr_page, &org_key, &path_info, CT_TRUE, &is_same);
        slot[page->level] = (uint32)path_info.path[page->level].slot;
        page_id[page->level] = AS_PAGID(page->head.id);

        /* level 2 means root level is 1, we split range at least on level 1 */
        if (tree_info.level == 2 || page->level < tree_info.level - 1) {
            buf_leave_page(session, CT_FALSE);
            break;
        }

        if (index->desc.cr_mode == CR_PAGE) {
            pcrb_dir = pcrb_get_dir(page, (uint32)path_info.path[page->level].slot);
            pcrb_key = PCRB_GET_KEY(page, pcrb_dir);
            child_page_id = pcrb_get_child(pcrb_key);
        } else {
            btree_dir = BTREE_GET_DIR(page, (uint32)path_info.path[page->level].slot);
            btree_key = BTREE_GET_KEY(page, btree_dir);
            child_page_id = btree_key->child;
        }

        buf_leave_page(session, CT_FALSE);
    }
}

status_t idx_get_paral_schedule(knl_session_t *session, btree_t *btree, knl_scn_t org_scn,
                                knl_idx_paral_info_t paral_info, knl_index_paral_range_t *sub_ranges)
{
    knl_tree_info_t tree_info;
    idx_range_info_t org_info;
    knl_scan_range_t *org_range = paral_info.org_range;
    uint32 i, root_level;
    errno_t err;

    if (paral_info.workers == 1) {
        sub_ranges->workers = 1;
        return CT_SUCCESS;
    }

    if (idx_get_tree_info(session, btree, org_scn, &tree_info) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (tree_info.level == 1) {
        sub_ranges->workers = 1;
        return CT_SUCCESS;
    }

    root_level = tree_info.level - 1;
    err = memset_sp(&org_info, sizeof(idx_range_info_t), 0, sizeof(idx_range_info_t));
    knl_securec_check(err);

    dls_latch_s(session, &btree->struct_latch, session->id, CT_FALSE, &session->stat_btree);

    idx_get_org_range(session, btree->index, tree_info, org_range->l_key, org_info.l_slot, org_info.l_page);
    idx_get_org_range(session, btree->index, tree_info, org_range->r_key, org_info.r_slot, org_info.r_page);

    for (i = root_level; i >= root_level - 1; i--) {
        org_info.level = i;
        org_info.keys = idx_cal_keys_count(session, org_info, i);
        if (root_level == 1 || org_info.keys >= paral_info.workers) {
            break;
        }
    }

    if (org_info.keys <= 1) {
        sub_ranges->workers = 1;
        dls_unlatch(session, &btree->struct_latch, &session->stat_btree);
        return CT_SUCCESS;
    }
    sub_ranges->workers = (org_info.keys < paral_info.workers) ? org_info.keys : paral_info.workers;

    if (btree->index->desc.cr_mode == CR_PAGE) {
        pcrb_get_parl_schedule(session, btree->index, paral_info, org_info, root_level, sub_ranges);
    } else {
        btree_get_parl_schedule(session, btree->index, paral_info, org_info, root_level, sub_ranges);
    }

    dls_unlatch(session, &btree->struct_latch, &session->stat_btree);

    for (i = 0; i < sub_ranges->workers; i++) {
        sub_ranges->index_range[i]->is_equal = CT_FALSE;
    }
    return CT_SUCCESS;
}

void idx_enter_next_range(knl_session_t *session, page_id_t page_id, uint32 slot, uint32 step, uint32 *border)
{
    btree_page_t *page = NULL;
    page_id_t next_page_id;
    uint32 num = 0;

    buf_enter_page(session, page_id, LATCH_MODE_S, ENTER_PAGE_NORMAL);
    page = BTREE_CURR_PAGE(session);
    if (step + slot < page->keys) {
        *border = step + slot;
        return;
    }

    num += page->keys - slot - 1;
    next_page_id = AS_PAGID(page->next);
    buf_leave_page(session, CT_FALSE);

    for (;;) {
        buf_enter_page(session, next_page_id, LATCH_MODE_S, ENTER_PAGE_NORMAL);
        page = BTREE_CURR_PAGE(session);
        if (num + page->keys > step) {
            knl_panic_log(step > num, "curr step is smaller than num, panic info: page %u-%u type %u step %u num %u",
                          AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type, step, num);
            *border = step - num - 1;
            break;
        } else if (num + page->keys == step) {
            *border = page->keys - 1;
            break;
        }

        num += page->keys;
        next_page_id = AS_PAGID(page->next);
        buf_leave_page(session, CT_FALSE);
    }
}

void idx_reverse_uint8(uint8* key_value)
{
    if (*key_value == 0) {
        return;
    }

    uint8 value = *key_value;
    uint8 result = 0;
    uint8 i;

    for (i = 0; i < UINT8_BITS; i++) {
        if (value == 0) {
            break;
        }
        result = (result << 1) | (value & 0x1);
        value = value >> 1;
    }

    result = result << (UINT8_BITS - i);
    *key_value = result;
}

void idx_reverse_uint16(uint16* key_value)
{
    if (*key_value == 0) {
        return;
    }

    uint16 value = *key_value;
    uint16 result = 0;
    uint16 i;

    for (i = 0; i < UINT16_BITS; i++) {
        if (value == 0) {
            break;
        }
        result = (result << 1) | (value & 0x1);
        value = value >> 1;
    }

    result = result << (UINT16_BITS - i);
    *key_value = result;
}

void idx_reverse_uint32(uint32* key_value)
{
    if (*key_value == 0) {
        return;
    }

    uint32 value = *key_value;
    uint32 result = 0;
    uint16 i;

    for (i = 0; i < UINT32_BITS; i++) {
        if (value == 0) {
            break;
        }
        result = (result << 1) | (value & 0x1);
        value = value >> 1;
    }

    result = result << (UINT32_BITS - i);
    *key_value = result;
}

void idx_reverse_uint64(uint64* key_value)
{
    if (*key_value == 0) {
        return;
    }

    uint64 value = *key_value;
    uint64 result = 0;
    uint16 i;

    for (i = 0; i < UINT64_BITS; i++) {
        if (value == 0) {
            break;
        }
        result = (result << 1) | (value & 0x1);
        value = value >> 1;
    }

    result = result << (UINT64_BITS - i);
    *key_value = result;
}

void idx_reverse_string(char* string, int16 len)
{
    int16 i, j;

    if (len == 0) {
        return;
    }

    for (i = 0, j = len - 1; i < j; i++, j--) {
        char temp = string[i];
        string[i] = string[j];
        string[j] = temp;
    }
}

void idx_reverse_number(dec4_t *key_value)
{
    uint16 i;
    uint16 *value = NULL;

    for (i = 0; i < key_value->ncells; i++) {
        value = (uint16 *)&key_value->cells[i];
        idx_reverse_uint16(value);
    }
}

void idx_reverse_number2(payload_t *key_value, uint8 len)
{
    uint8 i;
    uint8 *value = NULL;

    for (i = 0; i < len - 1; i++) {
        value = (uint8 *)&key_value->cells[i];
        idx_reverse_uint8(value);
    }
}

void idx_reverse_timestamp(timestamp_tz_t *key_value)
{
    uint64 *tstamp = (uint64 *)&key_value->tstamp;

    idx_reverse_uint64(tstamp);
}

uint16 idx_get_col_size(ct_type_t type, uint16 len, bool32 is_pcr)
{
    switch (type) {
        case CT_TYPE_UINT32:
        case CT_TYPE_INTEGER:
        case CT_TYPE_BOOLEAN:
        case CT_TYPE_INTERVAL_YM:
            return sizeof(int32);

        case CT_TYPE_INTERVAL_DS:
        case CT_TYPE_BIGINT:
        case CT_TYPE_DATE:
        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
        case CT_TYPE_TIMESTAMP_LTZ:
        case CT_TYPE_DATETIME_MYSQL:
        case CT_TYPE_TIME_MYSQL:
        case CT_TYPE_DATE_MYSQL:
            return sizeof(int64);

        case CT_TYPE_TIMESTAMP_TZ:
            return sizeof(timestamp_tz_t);

        case CT_TYPE_REAL:
            return sizeof(double);

        case CT_TYPE_NUMBER:
        case CT_TYPE_NUMBER3:
        case CT_TYPE_DECIMAL:
            if (is_pcr) {
                return CM_ALIGN4(len);
            } else {
                return (CM_ALIGN4(len + sizeof(uint16)) - sizeof(uint16));
            }
            
        case CT_TYPE_NUMBER2:
            return len;

        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
        case CT_TYPE_STRING:
        case CT_TYPE_BINARY:
        case CT_TYPE_VARBINARY:
        case CT_TYPE_RAW:
            return (CM_ALIGN4(len + sizeof(uint16)) - sizeof(uint16));

        default:
            return len;
    }
}

void idx_reverse_key_data(char *data, ct_type_t type, uint16 len)
{
    if (data == NULL || len == CT_NULL_VALUE_LEN) {
        return;
    }

    switch (type) {
        case CT_TYPE_UINT32:
        case CT_TYPE_INTEGER:
        case CT_TYPE_BOOLEAN:
        case CT_TYPE_INTERVAL_YM:
            idx_reverse_uint32((uint32*)data);
            break;

        case CT_TYPE_INTERVAL_DS:
        case CT_TYPE_BIGINT:
        case CT_TYPE_DATE:
        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
        case CT_TYPE_TIMESTAMP_LTZ:
        case CT_TYPE_DATETIME_MYSQL:
        case CT_TYPE_TIME_MYSQL:
        case CT_TYPE_DATE_MYSQL:
            idx_reverse_uint64((uint64*)data);
            break;

        case CT_TYPE_TIMESTAMP_TZ:
            idx_reverse_timestamp((timestamp_tz_t*)data);
            break;

        case CT_TYPE_NUMBER:
        case CT_TYPE_NUMBER3:
        case CT_TYPE_DECIMAL:
            idx_reverse_number((dec4_t *)data);
            break;

        case CT_TYPE_NUMBER2:
            idx_reverse_number2((payload_t *)data, len);
            break;

        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
        case CT_TYPE_STRING:
        case CT_TYPE_BINARY:
        case CT_TYPE_VARBINARY:
        case CT_TYPE_RAW:
            idx_reverse_string(data, len);
            break;

        default:
            CT_LOG_RUN_WAR("[PCRB] unknown datatype %u when generate key data", type);
            knl_panic(0);
    }
}

void auto_rebuild_init(knl_session_t *session)
{
    uint32 id;
    auto_rebuild_ctx_t *ctx = &session->kernel->auto_rebuild_ctx;
    auto_rebuild_item_t *item = NULL;

    ctx->idx_list.count = 0;
    ctx->idx_list.first = CT_INVALID_ID32;
    ctx->idx_list.last = CT_INVALID_ID32;

    ctx->free_list.count = CT_MAX_RECYCLE_INDEXES;
    ctx->free_list.first = 0;
    ctx->free_list.last = CT_MAX_RECYCLE_INDEXES - 1;

    for (id = 0; id < CT_MAX_RECYCLE_INDEXES; id++) {
        item = &ctx->items[id];
        errno_t err = memset_sp(item, sizeof(auto_rebuild_item_t), 0, sizeof(auto_rebuild_item_t));
        knl_securec_check(err);
        item->next = (id == (CT_MAX_RECYCLE_INDEXES - 1)) ? CT_INVALID_ID32 : (id + 1);
    }
}

void auto_rebuild_close(knl_session_t *session)
{
    auto_rebuild_ctx_t *ctx = &session->kernel->auto_rebuild_ctx;
    cm_close_thread(&ctx->thread);
}

// reduce the priority of the index
static void auto_rebuild_move_to_tail(knl_session_t *session)
{
    auto_rebuild_ctx_t *ctx = &session->kernel->auto_rebuild_ctx;
    uint32 id;

    cm_spin_lock(&ctx->lock, NULL);
    if (ctx->idx_list.count == 1) {
        cm_spin_unlock(&ctx->lock);
        return;
    }

    id = ctx->idx_list.first;
    ctx->items[ctx->idx_list.last].next = id;
    ctx->idx_list.first = ctx->items[id].next;
    ctx->idx_list.last = id;
    ctx->items[id].next = CT_INVALID_ID32;
    cm_spin_unlock(&ctx->lock);
}

static status_t auto_rebuild_alloc_item(knl_session_t *session, uint32 *id)
{
    auto_rebuild_ctx_t *ctx = &session->kernel->auto_rebuild_ctx;
    cm_spin_lock(&ctx->lock, NULL);

    if (ctx->free_list.count == 0) {
        cm_spin_unlock(&ctx->lock);
        return CT_ERROR;
    }

    *id = ctx->free_list.first;
    auto_rebuild_item_t *item = &ctx->items[*id];

    ctx->free_list.count--;
    ctx->free_list.first = item->next;
    item->next = CT_INVALID_ID32;

    if (ctx->free_list.count == 0) {
        ctx->free_list.last = CT_INVALID_ID32;
    }

    if (ctx->idx_list.count == 0) {
        ctx->idx_list.first = *id;
    } else {
        ctx->items[ctx->idx_list.last].next = *id;
    }

    ctx->idx_list.last = *id;
    ctx->idx_list.count++;

    cm_spin_unlock(&ctx->lock);

    return CT_SUCCESS;
}

void auto_rebuild_release_item(knl_session_t *session, uint32 id_input)
{
    uint32 id = id_input;
    auto_rebuild_ctx_t *ctx = &session->kernel->auto_rebuild_ctx;
    cm_spin_lock(&ctx->lock, NULL);
    if (id != ctx->idx_list.first) {
        cm_spin_unlock(&ctx->lock);
        return;
    }

    auto_rebuild_item_t *item = &ctx->items[id];

    if (ctx->free_list.count == 0) {
        ctx->free_list.first = id;
    } else {
        ctx->items[ctx->free_list.last].next = id;
    }

    ctx->free_list.last = id;
    ctx->free_list.count++;
    id = item->next;
    ctx->idx_list.count--;
    ctx->idx_list.first = id;

    if (ctx->idx_list.count == 0) {
        ctx->idx_list.last = CT_INVALID_ID32;
    }

    item->next = CT_INVALID_ID32;
    item->state = AREBUILD_INDEX_INVALID;

    cm_spin_unlock(&ctx->lock);
}

static bool8 auto_rebuild_index_exist(knl_session_t *session, auto_rebuild_item_t *item)
{
    auto_rebuild_ctx_t *ctx = &session->kernel->auto_rebuild_ctx;
    uint32 cur_index = ctx->idx_list.first;
    auto_rebuild_item_t *cur_item = NULL;

    cm_spin_lock(&ctx->lock, NULL);

    while (cur_index != CT_INVALID_ID32) {
        cur_item = &ctx->items[cur_index];

        if (cm_str_equal(item->name, cur_item->name) &&
            cur_item->uid == item->uid &&
            cur_item->oid == item->oid) {
            if (item->type != ALINDEX_TYPE_REBUILD &&
                !cm_str_equal(item->part_name, cur_item->part_name)) {
                cur_index = cur_item->next;
                continue;
            }

            cm_spin_unlock(&ctx->lock);
            return CT_TRUE;
        }

        cur_index = cur_item->next;
    }

    cm_spin_unlock(&ctx->lock);

    return CT_FALSE;
}

static void auto_rebuild_fill_item(index_t *index, knl_part_locate_t part_loc, auto_rebuild_item_t *item)
{
    index_part_t *index_part = NULL;
    errno_t err;

    if (part_loc.part_no != CT_INVALID_ID32 &&
        part_loc.subpart_no != CT_INVALID_ID32) {
        index_part = INDEX_GET_PART(index, part_loc.part_no);
        index_part = PART_GET_SUBENTITY(index->part_index, index_part->subparts[part_loc.subpart_no]);
        item->type = ALINDEX_TYPE_REBUILD_SUBPART;
        item->scn = index_part->btree.segment->seg_scn;
        item->org_scn = index_part->btree.segment->org_scn;

        err = memcpy_sp((void *)&item->part_name[0], CT_NAME_BUFFER_SIZE, index_part->desc.name, CT_NAME_BUFFER_SIZE);
        knl_securec_check(err);
    } else if (part_loc.part_no != CT_INVALID_ID32) {
        index_part = INDEX_GET_PART(index, part_loc.part_no);
        item->type = ALINDEX_TYPE_REBUILD_PART;
        item->scn = index_part->btree.segment->seg_scn;
        item->org_scn = index_part->btree.segment->org_scn;

        err = memcpy_sp((void *)&item->part_name[0], CT_NAME_BUFFER_SIZE, index_part->desc.name, CT_NAME_BUFFER_SIZE);
        knl_securec_check(err);
    } else {
        item->type = ALINDEX_TYPE_REBUILD;
        item->scn = index->btree.segment->seg_scn;
        item->org_scn = index->btree.segment->org_scn;
    }
}

void auto_rebuild_add_index(knl_session_t *session, index_t *index, knl_part_locate_t part_loc)
{
    auto_rebuild_ctx_t *ctx = &session->kernel->auto_rebuild_ctx;
    status_t alloc_status;
    uint32 item_id;
    errno_t err;
    auto_rebuild_item_t item;
   
    if (dc_is_reserved_entry(index->desc.uid, index->desc.table_id)) {
        CT_LOG_RUN_INF("user_id %u,table_id %u,index_name %s part(%d,%d) system table index rebuild is not supported.",
            index->desc.uid, index->desc.table_id, index->desc.name, part_loc.part_no, part_loc.subpart_no);
        return;
    }

    if (index->desc.is_func) {
        CT_LOG_RUN_INF("user_id %u,table_id %u,index_name %s part(%d,%d) function index rebuild is not supported.",
            index->desc.uid, index->desc.table_id, index->desc.name, part_loc.part_no, part_loc.subpart_no);
        return;
    }

    auto_rebuild_fill_item(index, part_loc, &item);
    item.oid = index->desc.table_id;
    item.uid = index->desc.uid;
    item.state = AREBUILD_INDEX_WAITTING;

    err = memcpy_sp((void *)&item.name[0], CT_NAME_BUFFER_SIZE, index->desc.name, CT_NAME_BUFFER_SIZE);
    knl_securec_check(err);
    
    // index_id multiplex check
    if (auto_rebuild_index_exist(session, &item)) {
        CT_LOG_RUN_INF("user_id %u,table_id %u,index_name %s part(%d,%d) already exist.", index->desc.uid,
            index->desc.table_id, index->desc.name, part_loc.part_no, part_loc.subpart_no);
        return;
    }

    alloc_status = auto_rebuild_alloc_item(session, &item_id);
    if (alloc_status != CT_SUCCESS) {
        CT_LOG_RUN_INF("insufficient memory, user_id %u,table_id %u,index_name %s alloc failure",
            index->desc.uid, index->desc.table_id, index->desc.name);
        return;
    }

    cm_spin_lock(&ctx->lock, NULL);
    auto_rebuild_item_t *new_item = &ctx->items[item_id];
    item.next = new_item->next;
    err = memcpy_sp((void *)new_item, sizeof (auto_rebuild_item_t), &item, sizeof(auto_rebuild_item_t));
    knl_securec_check(err);
    cm_spin_unlock(&ctx->lock);

    CT_LOG_RUN_INF("user_id %u,table_id %u,index_name %s part(%d,%d) added to auto rebuild list.",
        index->desc.uid, index->desc.table_id, index->desc.name, part_loc.part_no, part_loc.subpart_no);
}

static status_t auto_rebuild_entity(knl_session_t *session, knl_alindex_def_t *rebuild_def, auto_rebuild_item_t *item)
{
    errno_t err = memset_sp(rebuild_def, sizeof(knl_alindex_def_t), 0, sizeof(knl_alindex_def_t));
    knl_securec_check(err);
    cm_str2text(item->name, &rebuild_def->name);
    rebuild_def->type = item->type;
    rebuild_def->rebuild.is_online = CT_TRUE;
    rebuild_def->rebuild.pctfree = CT_INVALID_ID32;
    rebuild_def->rebuild.cr_mode = CT_INVALID_ID8;
    rebuild_def->rebuild.lock_timeout = SECONDS_PER_HOUR;
    rebuild_def->rebuild.org_scn = item->org_scn;

    knl_get_user_name(session, item->uid, &rebuild_def->user);
    if (item->type != ALINDEX_TYPE_REBUILD) {
        cm_str2text(item->part_name, &rebuild_def->rebuild.part_name[0]);
        rebuild_def->rebuild.specified_parts = 1;
    }

    item->state = AREBUILD_INDEX_RUNNING;
    if (knl_alter_index(session, NULL, rebuild_def) != CT_SUCCESS) {
        // update the item scn and and lower priority
        if (cm_get_error_code() == ERR_RESOURCE_BUSY) {
            item->scn = DB_CURR_SCN(session);
            item->state = AREBUILD_INDEX_BUSY;
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}
#define AUTO_REBUILD_MIN_INTERVAL   (10 * SECONDS_PER_MIN)
static status_t auto_rebuild(knl_session_t *session)
{
    knl_alindex_def_t rebuild_def;
    auto_rebuild_ctx_t *ctx = &session->kernel->auto_rebuild_ctx;
    uint32 travel_cnt = 0;
    uint32 idx_list_cnt = ctx->idx_list.count;

    for (;;) {
        if (ctx->idx_list.count == 0 || travel_cnt > idx_list_cnt) {
            break;
        }

        if (session->canceled) {
            CT_THROW_ERROR(ERR_OPERATION_CANCELED);
            return CT_ERROR;
        }

        if (session->killed) {
            CT_THROW_ERROR(ERR_OPERATION_KILLED);
            return CT_ERROR;
        }

        knl_scn_t timeout_scn = db_time_scn(session, AUTO_REBUILD_MIN_INTERVAL, 0);
        auto_rebuild_item_t *item = &ctx->items[ctx->idx_list.first];
        travel_cnt++;

        // for efficiency, item->scn and scn must be greater than 1 hour
        if (DB_NOW_TO_SCN(session) - item->scn < timeout_scn) {
            auto_rebuild_move_to_tail(session);
            continue;
        }
        CT_LOG_RUN_INF("user_id %u,table_id %u,index_name %s auto rebuild index started", item->uid,
            item->oid, (item->type == ALINDEX_TYPE_REBUILD) ? item->name : item->part_name);
        if (auto_rebuild_entity(session, &rebuild_def, item) == CT_SUCCESS) {
            auto_rebuild_release_item(session, ctx->idx_list.first);
        }
        CT_LOG_RUN_INF("user_id %u,table_id %u,index_name %s auto rebuild index ended,%u indexes left.result:%d",
            item->uid, item->oid, (item->type == ALINDEX_TYPE_REBUILD) ? item->name : item->part_name,
            ctx->idx_list.count, cm_get_error_code());
        cm_reset_error();
    }

    return CT_SUCCESS;
}

#define MAX_DELAY_REBUILD_TIME  (10 * SECONDS_PER_MIN)
static bool32 idx_auto_rebuild_start(knl_session_t *session)
{
    if (!session->kernel->attr.idx_auto_rebuild) {
        return CT_FALSE;
    }

    date_detail_t detail;
    time_t cur_time = cm_current_time();
    uint32 start_date_second = session->kernel->attr.idx_auto_rebuild_start_date;

    if (start_date_second == CT_INVALID_ID32) {
        return CT_TRUE;
    }

    cm_decode_time(cur_time, &detail);
    uint32 start_seconds = detail.hour * SECONDS_PER_HOUR + detail.min * SECONDS_PER_MIN + detail.sec;

    return (start_seconds >= start_date_second) &&
        (start_seconds - start_date_second < MAX_DELAY_REBUILD_TIME);
}

#define REBUILD_PROC_STIME 200
void idx_auto_rebuild_proc(thread_t *thread)
{
    knl_session_t *session = (knl_session_t *)thread->argument;
    switch_ctrl_t *ctrl = &session->kernel->switch_ctrl;
    auto_rebuild_ctx_t *ctx = &session->kernel->auto_rebuild_ctx;
    auto_rebuild_init(session);

    cm_set_thread_name("arebuild");
    CT_LOG_RUN_INF("index auto rebuild thread started");
    KNL_SESSION_SET_CURR_THREADID(session, cm_get_current_thread_id());

    while (!thread->closed) {
        ctx->working = CT_FALSE;
        session->status = SESSION_INACTIVE;
        cm_sleep(REBUILD_PROC_STIME);

        if (session->kernel->db.status != DB_STATUS_OPEN) {
            continue;
        }

        if (DB_IS_MAINTENANCE(session) || DB_IS_READONLY(session) ||
            ctrl->request != SWITCH_REQ_NONE || !idx_auto_rebuild_start(session) ||
            ctx->idx_list.count == 0) {
            continue;
        }

        session->canceled = CT_FALSE;
        session->killed = CT_FALSE;
        session->status = SESSION_ACTIVE;
        db_set_with_switchctrl_lock(ctrl, &ctx->working);
        if (!ctx->working) {
            continue;
        }

        if (auto_rebuild(session) != CT_SUCCESS) {
            int32 err_code = ERR_ERRNO_BASE;
            const char *err_msg = NULL;

            cm_get_error(&err_code, &err_msg, NULL);
            CT_LOG_RUN_INF("auto rebuild err msg:%s", err_msg);
            cm_reset_error();
        }
    }

    ctx->working = CT_FALSE;
    CT_LOG_RUN_INF("index auto rebuild thread closed");
    KNL_SESSION_CLEAR_THREADID(session);
}
