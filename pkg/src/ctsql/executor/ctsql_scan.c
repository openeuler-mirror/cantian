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
 * ctsql_scan.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/executor/ctsql_scan.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_scan.h"
#include "ctsql_select.h"
#include "plan_rbo.h"
#include "pl_executor.h"
#include "srv_instance.h"
#include "ctsql_json.h"
#include "ctsql_jsonb_table.h"
#include "ctsql_json_table.h"
#include "ctsql_mtrl.h"

#define COMM_FILE_TEXT_LEN 10
#define COMM_PAGE_TEXT_LEN 8

#define DICT_FILE_TEXT_LEN 4
#define DICT_PAGE_TEXT_LEN 10
#define SLOT_TEXT_LEN 4

static inline status_t sql_set_scan_key(knl_index_desc_t *desc, knl_scan_key_t *scan_key, ct_type_t type,
    const void *data, uint16 len, uint16 id)
{
    uint16 key_size =
        (uint16)knl_get_key_size(desc, scan_key->buf) + btree_max_column_size(type, len, (desc->cr_mode == CR_PAGE));
    if (key_size > desc->max_key_size) {
        CT_THROW_ERROR(ERR_MAX_KEYLEN_EXCEEDED, desc->max_key_size);
        return CT_ERROR;
    }

    knl_set_scan_key(desc, scan_key, type, data, len, id);
    return CT_SUCCESS;
}

static status_t sql_put_key(knl_index_desc_t *index_desc, knl_scan_key_t *key, variant_t *var, uint16 cid, uint32 size)
{
    if (size != CT_INVALID_ID32) {
        knl_set_key_size(index_desc, key, size);
    }

    switch (var->type) {
        case CT_TYPE_UINT32:
            CT_RETURN_IFERR(sql_set_scan_key(index_desc, key, var->type, &var->v_uint32, sizeof(uint32), cid));
            break;

        case CT_TYPE_INTEGER:
            CT_RETURN_IFERR(sql_set_scan_key(index_desc, key, var->type, &var->v_int, sizeof(int32), cid));
            break;

        case CT_TYPE_BOOLEAN:
            CT_RETURN_IFERR(sql_set_scan_key(index_desc, key, var->type, &var->v_bool, sizeof(var->v_bool), cid));
            break;

        case CT_TYPE_BIGINT:
            CT_RETURN_IFERR(sql_set_scan_key(index_desc, key, var->type, &var->v_bigint, sizeof(int64), cid));
            break;

        case CT_TYPE_INTERVAL_DS:
            CT_RETURN_IFERR(sql_set_scan_key(index_desc, key, var->type, &var->v_itvl_ds, sizeof(interval_ds_t), cid));
            break;

        case CT_TYPE_INTERVAL_YM:
            CT_RETURN_IFERR(sql_set_scan_key(index_desc, key, var->type, &var->v_itvl_ym, sizeof(interval_ym_t), cid));
            break;

        case CT_TYPE_REAL:
        case CT_TYPE_DATE:
        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
        case CT_TYPE_TIMESTAMP_LTZ:
            CT_RETURN_IFERR(sql_set_scan_key(index_desc, key, var->type, &var->v_real, sizeof(double), cid));
            break;

        case CT_TYPE_TIMESTAMP_TZ:
            CT_RETURN_IFERR(
                sql_set_scan_key(index_desc, key, var->type, &var->v_tstamp_tz, sizeof(timestamp_tz_t), cid));
            break;

        case CT_TYPE_STRING:
        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
            CT_RETURN_IFERR(sql_set_scan_key(index_desc, key, var->type, var->v_text.str, var->v_text.len, cid));
            break;

        case CT_TYPE_NUMBER:
        case CT_TYPE_DECIMAL: {
            dec4_t d4;
            CT_RETURN_IFERR(cm_dec_8_to_4(&d4, &var->v_dec));
            CT_RETURN_IFERR(
                sql_set_scan_key(index_desc, key, var->type, (uint8 *)&d4, (uint16)cm_dec4_stor_sz(&d4), cid));
            break;
        }
        case CT_TYPE_NUMBER2: {
            dec2_t d2;
            CT_RETURN_IFERR(cm_dec_8_to_2(&d2, &var->v_dec));
            CT_RETURN_IFERR(sql_set_scan_key(index_desc, key, var->type, (uint8 *)GET_PAYLOAD(&d2),
                (uint16)cm_dec2_stor_sz(&d2), cid));
            break;
        }
        case CT_TYPE_BINARY:
        case CT_TYPE_VARBINARY:
        case CT_TYPE_RAW:
            CT_RETURN_IFERR(sql_set_scan_key(index_desc, key, var->type, var->v_bin.bytes, var->v_bin.size, cid));
            break;

        default:
            break;
    }
    return CT_SUCCESS;
}

static inline status_t sql_convert_border_l(sql_stmt_t *stmt, knl_index_desc_t *index_desc, scan_border_t *border,
    ct_type_t datatype, uint32 cid, void *index_key)
{
    knl_scan_key_t *key = (knl_scan_key_t *)index_key;

    if (border == NULL || border->type == BORDER_INFINITE_LEFT) {
        knl_set_key_flag(key, SCAN_KEY_LEFT_INFINITE, cid);
        return CT_SUCCESS;
    }

    if (border->type == BORDER_IS_NULL) {
        knl_set_key_flag(key, SCAN_KEY_IS_NULL, cid);
        return CT_SUCCESS;
    }
    CT_RETURN_IFERR(sql_put_key(index_desc, key, &border->var, cid, CT_INVALID_ID32));
    return CT_SUCCESS;
}

static inline status_t sql_convert_border_r(sql_stmt_t *stmt, knl_index_desc_t *index_desc, scan_border_t *border,
    ct_type_t datatype, uint32 cid, void *index_key)
{
    knl_scan_key_t *key = (knl_scan_key_t *)index_key;

    if (border == NULL || border->type == BORDER_INFINITE_RIGHT) {
        knl_set_key_flag(key, SCAN_KEY_RIGHT_INFINITE, cid);
        return CT_SUCCESS;
    }

    if (border->type == BORDER_IS_NULL) {
        knl_set_key_flag(key, SCAN_KEY_IS_NULL, cid);
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(sql_put_key(index_desc, key, &border->var, cid, CT_INVALID_ID32));
    return CT_SUCCESS;
}

void sql_prepare_scan(sql_stmt_t *stmt, knl_dictionary_t *dc, knl_cursor_t *knl_cursor)
{
    knl_cursor->stmt = stmt;
    knl_cursor->query_scn = stmt->query_scn;

    if (dc->type == DICT_TYPE_TEMP_TABLE_SESSION || dc->type == DICT_TYPE_TEMP_TABLE_TRANS) {
        knl_cursor->ssn = stmt->ssn;
    } else {
        knl_cursor->ssn = stmt->xact_ssn;
    }
}

static inline status_t sql_init_knl_scan_key(sql_stmt_t *stmt, knl_index_desc_t *desc, bool32 need_alloc,
    rowid_t *rowid, knl_scan_key_t **key)
{
    if (need_alloc) {
        CT_RETURN_IFERR(sql_push(stmt, KNL_SCAN_KEY_SIZE, (void **)key));
    }
    (*key)->buf = (char *)(*key) + sizeof(knl_scan_key_t);
    knl_init_key(desc, (*key)->buf, rowid);
    return CT_SUCCESS;
}

static inline status_t sql_finalize_scan_key(sql_table_cursor_t *tab_cursor, knl_index_desc_t *desc, knl_scan_key_t *key,
    char **buf)
{
    uint32 key_size = knl_scan_key_size(desc, key);

    CT_RETURN_IFERR(vmc_alloc(&tab_cursor->vmc, key_size, (void **)buf));
    MEMS_RETURN_IFERR(memcpy_sp(*buf, key_size, (char *)key, key_size));
    ((knl_scan_key_t *)(*buf))->buf = *buf + sizeof(knl_scan_key_t);
    return CT_SUCCESS;
}

static status_t sql_generate_scan_key(sql_stmt_t *stmt, sql_table_cursor_t *tab_cursor, scan_list_array_t *ar,
    knl_scan_key_t *key, uint32 rid, rowid_t *rowid)
{
    bool32 closed = CT_FALSE;
    bool32 equal_range = CT_FALSE;
    key_range_t *key_range = NULL;
    knl_index_desc_t *index_desc = tab_cursor->table->index;

    CT_RETURN_IFERR(vmc_alloc(&tab_cursor->vmc, sizeof(key_range_t), (void **)&key_range));

    // left border
    CT_RETURN_IFERR(sql_init_knl_scan_key(stmt, index_desc, CT_FALSE, NULL, &key));
    CT_RETURN_IFERR(sql_make_border_l(stmt, index_desc, ar, rid, key, &closed, sql_convert_border_l));
    if (!closed) {
        knl_set_key_rowid(index_desc, key->buf, rowid);
    }
    CT_RETURN_IFERR(sql_finalize_scan_key(tab_cursor, index_desc, key, &key_range->l_key));

    // right border
    CT_RETURN_IFERR(sql_init_knl_scan_key(stmt, index_desc, CT_FALSE, NULL, &key));
    CT_RETURN_IFERR(sql_make_border_r(stmt, index_desc, ar, rid, key, &closed, &equal_range, sql_convert_border_r));
    if (closed) {
        knl_set_key_rowid(index_desc, key->buf, rowid);
    }
    CT_RETURN_IFERR(sql_finalize_scan_key(tab_cursor, index_desc, key, &key_range->r_key));

    // is_equal
    key_range->is_equal = equal_range;
    return cm_galist_insert((galist_t *)tab_cursor->key_set.key_data, key_range);
}

static inline status_t put_scan_range_to_key(sql_stmt_t *stmt, scan_range_t *range, knl_index_desc_t *desc, uint32 cid,
    uint32 left_size, knl_scan_key_t *left_key, uint32 right_size, knl_scan_key_t *right_key)
{
    // left border
    CT_RETURN_IFERR(sql_put_key(desc, left_key, &range->left.var, cid, left_size));

    // right border
    CT_RETURN_IFERR(sql_put_key(desc, right_key, &range->right.var, cid, right_size));
    return CT_SUCCESS;
}

static inline status_t sql_gen_point_scan_key(sql_table_cursor_t *tab_cursor, knl_scan_key_t *left_key, knl_scan_key_t *right_key,
    bool32 is_equal)
{
    key_range_t *key_range = NULL;
    knl_index_desc_t *desc = tab_cursor->table->index;

    CT_RETURN_IFERR(vmc_alloc(&tab_cursor->vmc, sizeof(key_range_t), (void **)&key_range));

    // left border
    CT_RETURN_IFERR(sql_finalize_scan_key(tab_cursor, desc, left_key, &key_range->l_key));

    // right border
    CT_RETURN_IFERR(sql_finalize_scan_key(tab_cursor, desc, right_key, &key_range->r_key));

    // is_equal
    key_range->is_equal = is_equal;
    return cm_galist_insert((galist_t *)tab_cursor->key_set.key_data, key_range);
}

static inline uint32 sql_get_used_index_col_count(scan_list_array_t *array)
{
    uint32 count = 0;
    scan_range_list_t *scan_ranges = NULL;

    for (uint32 i = 0; i < array->count; i++) {
        scan_ranges = &array->items[i];
        if (scan_ranges->count == 1 && scan_ranges->ranges[0]->type == RANGE_FULL) {
            break;
        }
        count++;
    }
    return count;
}

static inline status_t sql_gen_asc_point_scan_keys(sql_stmt_t *stmt, sql_table_cursor_t *tab_cursor, uint32 cid,
    scan_list_array_t *ar, knl_index_desc_t *desc, knl_scan_key_t *left_key, knl_scan_key_t *right_key)
{
    bool32 is_equal = !(ar->flags & LIST_EXIST_LIST_FULL);
    uint32 used_idx_cnt = sql_get_used_index_col_count(ar);
    CT_RETURN_IFERR(sql_stack_safe(stmt));
    scan_range_list_t *list = &ar->items[cid];
    uint32 left_size = knl_get_key_size(desc, left_key->buf);
    uint32 right_size = knl_get_key_size(desc, right_key->buf);

    if (cid >= used_idx_cnt) {
        scan_border_t *left_border = &(list->ranges[0]->left);
        scan_border_t *right_border = &(list->ranges[list->count - 1]->right);
        CT_RETURN_IFERR(sql_convert_border_l(stmt, desc, left_border, list->datatype, cid, left_key));
        CT_RETURN_IFERR(sql_convert_border_r(stmt, desc, right_border, list->datatype, cid, right_key));
        if (cid >= ar->count - 1) {
            return sql_gen_point_scan_key(tab_cursor, left_key, right_key, is_equal);
        } else {
            return sql_gen_asc_point_scan_keys(stmt, tab_cursor, cid + 1, ar, desc, left_key, right_key);
        }
    }

    for (uint32 i = 0; i < list->count; i++) {
        CT_RETURN_IFERR(put_scan_range_to_key(stmt, list->ranges[i], desc, cid, left_size, left_key, right_size, right_key));
        if (cid >= ar->count - 1) {
            CT_RETURN_IFERR(sql_gen_point_scan_key(tab_cursor, left_key, right_key, is_equal));
            continue;
        }
        CT_RETURN_IFERR(sql_gen_asc_point_scan_keys(stmt, tab_cursor, cid + 1, ar, desc, left_key, right_key));
    }

    return CT_SUCCESS;
}

static inline status_t sql_gen_desc_point_scan_keys(sql_stmt_t *stmt, sql_table_cursor_t *tab_cursor, uint32 cid,
    scan_list_array_t *ar, knl_index_desc_t *desc, knl_scan_key_t *left_key, knl_scan_key_t *right_key)
{
    bool32 is_equal = !(ar->flags & LIST_EXIST_LIST_FULL);
    uint32 used_idx_cnt = sql_get_used_index_col_count(ar);
    CT_RETURN_IFERR(sql_stack_safe(stmt));
    scan_range_list_t *list = &ar->items[cid];
    uint32 left_size = knl_get_key_size(desc, left_key->buf);
    uint32 right_size = knl_get_key_size(desc, right_key->buf);

    if (cid >= used_idx_cnt) {
        scan_border_t *left_border = &(list->ranges[0]->left);
        scan_border_t *right_border = &(list->ranges[list->count - 1]->right);
        CT_RETURN_IFERR(sql_convert_border_l(stmt, desc, left_border, list->datatype, cid, left_key));
        CT_RETURN_IFERR(sql_convert_border_r(stmt, desc, right_border, list->datatype, cid, right_key));
        if (cid >= ar->count - 1) {
            return sql_gen_point_scan_key(tab_cursor, left_key, right_key, is_equal);
        } else {
            return sql_gen_desc_point_scan_keys(stmt, tab_cursor, cid + 1, ar, desc, left_key, right_key);
        }
    }

    for (int32 i = (int32)list->count - 1; i >= 0; --i) {
        CT_RETURN_IFERR(put_scan_range_to_key(stmt, list->ranges[i], desc, cid, left_size, left_key, right_size, right_key));
        if (cid >= ar->count - 1) {
            CT_RETURN_IFERR(sql_gen_point_scan_key(tab_cursor, left_key, right_key, is_equal));
            continue;
        }
        CT_RETURN_IFERR(sql_gen_desc_point_scan_keys(stmt, tab_cursor, cid + 1, ar, desc, left_key, right_key));
    }
    return CT_SUCCESS;
}

static inline status_t sql_create_point_scan_keys(sql_stmt_t *stmt, sql_table_cursor_t *tab_cursor, scan_list_array_t *ar,
    rowid_t *rowid)
{
    knl_scan_key_t *left_key = NULL;
    knl_scan_key_t *right_key = NULL;
    knl_index_desc_t *desc = tab_cursor->table->index;

    CT_RETURN_IFERR(sql_init_knl_scan_key(stmt, desc, CT_TRUE, NULL, &left_key));
    CT_RETURN_IFERR(sql_init_knl_scan_key(stmt, desc, CT_TRUE, rowid, &right_key));

    if (tab_cursor->table->index_dsc) {
        return sql_gen_desc_point_scan_keys(stmt, tab_cursor, 0, ar, desc, left_key, right_key);
    }
    return sql_gen_asc_point_scan_keys(stmt, tab_cursor, 0, ar, desc, left_key, right_key);
}

static status_t sql_gen_desc_range_scan_keys(sql_stmt_t *stmt, sql_table_cursor_t *tab_cursor, scan_list_array_t *ar,
    knl_scan_key_t *key, rowid_t *rowid)
{
    scan_range_list_t *list = &ar->items[0];
    for (int32 i = (int32)list->count - 1; i >= 0; --i) {
        CT_RETURN_IFERR(sql_generate_scan_key(stmt, tab_cursor, ar, key, (uint32)i, rowid));
    }
    return CT_SUCCESS;
}

static status_t sql_gen_asc_range_scan_keys(sql_stmt_t *stmt, sql_table_cursor_t *tab_cursor, scan_list_array_t *ar,
    knl_scan_key_t *key, rowid_t *rowid)
{
    scan_range_list_t *list = &ar->items[0];
    for (uint32 i = 0; i < list->count; i++) {
        CT_RETURN_IFERR(sql_generate_scan_key(stmt, tab_cursor, ar, key, i, rowid));
    }
    return CT_SUCCESS;
}

static inline status_t sql_create_range_scan_keys(sql_stmt_t *stmt, sql_table_cursor_t *tab_cursor, scan_list_array_t *ar,
    rowid_t *rowid)
{
    knl_scan_key_t *key = NULL;
    knl_index_desc_t *index_desc = tab_cursor->table->index;
    CT_RETURN_IFERR(sql_init_knl_scan_key(stmt, index_desc, CT_TRUE, NULL, &key));

    if (tab_cursor->table->index_dsc) {
        return sql_gen_desc_range_scan_keys(stmt, tab_cursor, ar, key, rowid);
    }
    return sql_gen_asc_range_scan_keys(stmt, tab_cursor, ar, key, rowid);
}

static status_t sql_create_index_scan_keys(sql_stmt_t *stmt, sql_table_cursor_t *tab_cursor, scan_list_array_t *ar)
{
    rowid_t rowid;
    key_set_t *set = &tab_cursor->key_set;

    MEMS_RETURN_IFERR(memset_s(&rowid, sizeof(rowid_t), 0xFF, sizeof(rowid_t)));

    set->offset = 0;
    CT_RETURN_IFERR(vmc_alloc(&tab_cursor->vmc, sizeof(galist_t), &set->key_data));
    cm_galist_init((galist_t *)set->key_data, (void *)&tab_cursor->vmc, vmc_alloc);

    if (can_use_point_scan(ar)) {
        return sql_create_point_scan_keys(stmt, tab_cursor, ar, &rowid);
    }
    return sql_create_range_scan_keys(stmt, tab_cursor, ar, &rowid);
}

static status_t sql_put_part_scan_keys_desc(sql_stmt_t *stmt, part_assist_t *part_ass, sql_table_cursor_t *cursor)
{
    cursor->curr_part = part_ass->scan_key[part_ass->count - 1];
    if (part_ass->count == 1) {
        return CT_SUCCESS;
    }

    cursor->part_set.offset = PENDING_HEAD_SIZE;
    uint32 mem_size = sizeof(part_scan_key_t) * (part_ass->count - 1) + PENDING_HEAD_SIZE;
    CT_RETURN_IFERR(vmc_alloc(&cursor->vmc, mem_size, (void **)&cursor->part_set.key_data));
    *(uint32 *)cursor->part_set.key_data = mem_size;

    part_scan_key_t *scan_key = (part_scan_key_t *)((char *)cursor->part_set.key_data + PENDING_HEAD_SIZE);
    for (int32 i = (int32)part_ass->count - 2; i >= 0; --i) {
        scan_key[part_ass->count - 2 - i] = part_ass->scan_key[i];
    }

    return CT_SUCCESS;
}

static status_t sql_put_part_scan_keys_asc(sql_stmt_t *stmt, part_assist_t *part_ass, sql_table_cursor_t *cursor)
{
    cursor->curr_part = part_ass->scan_key[0];
    if (part_ass->count == 1) {
        return CT_SUCCESS;
    }

    cursor->part_set.offset = PENDING_HEAD_SIZE;

    uint32 mem_size = sizeof(part_scan_key_t) * (part_ass->count - 1) + PENDING_HEAD_SIZE;
    CT_RETURN_IFERR(vmc_alloc(&cursor->vmc, mem_size, (void **)&cursor->part_set.key_data));
    *(uint32 *)cursor->part_set.key_data = mem_size;

    part_scan_key_t *scan_key = (part_scan_key_t *)((char *)cursor->part_set.key_data + PENDING_HEAD_SIZE);
    for (uint32 i = 1; i < part_ass->count; ++i) {
        scan_key[i - 1] = part_ass->scan_key[i];
    }
    return CT_SUCCESS;
}

static status_t sql_put_subpart_scan_keys_desc(sql_stmt_t *stmt, part_assist_t *part_ass, vmc_t *vmc, key_set_t *sub_set)
{
    sub_set->offset = PENDING_HEAD_SIZE;
    uint32 mem_size = sizeof(part_scan_key_t) * part_ass->count + PENDING_HEAD_SIZE;
    CT_RETURN_IFERR(vmc_alloc(vmc, mem_size, (void **)&sub_set->key_data));
    *(uint32 *)sub_set->key_data = mem_size;

    part_scan_key_t *scan_key = (part_scan_key_t *)((char *)sub_set->key_data + PENDING_HEAD_SIZE);
    for (int32 i = (int32)part_ass->count - 1; i >= 0; --i) {
        scan_key[part_ass->count - 1 - i] = part_ass->scan_key[i];
    }

    return CT_SUCCESS;
}

static status_t sql_put_subpart_scan_keys_asc(sql_stmt_t *stmt, part_assist_t *part_ass, vmc_t *vmc, key_set_t *sub_set)
{
    sub_set->offset = PENDING_HEAD_SIZE;
    uint32 mem_size = sizeof(part_scan_key_t) * part_ass->count + PENDING_HEAD_SIZE;
    CT_RETURN_IFERR(vmc_alloc(vmc, mem_size, (void **)&sub_set->key_data));
    *(uint32 *)sub_set->key_data = mem_size;

    part_scan_key_t *scan_key = (part_scan_key_t *)((char *)sub_set->key_data + PENDING_HEAD_SIZE);
    for (uint32 i = 0; i < part_ass->count; ++i) {
        scan_key[i] = part_ass->scan_key[i];
    }

    return CT_SUCCESS;
}

static status_t sql_create_full_part_scan_keys(sql_stmt_t *stmt, scan_plan_t *plan, sql_table_cursor_t *cursor,
    knl_handle_t handle, calc_mode_t calc_mode)
{
    cursor->curr_part.left = 0;
    cursor->curr_part.right = knl_part_count(handle);
    if (!knl_is_compart_table(handle)) {
        return CT_SUCCESS;
    }

    return sql_make_subpart_scan_keys(stmt, &plan->subpart_array, cursor->table, &cursor->vmc, &cursor->curr_part,
        calc_mode);
}

static status_t sql_create_part_scan_keys(sql_stmt_t *stmt, scan_plan_t *plan, sql_table_cursor_t *cursor,
    knl_handle_t handle, scan_list_array_t *ar, calc_mode_t calc_mode)
{
    bool32 full_scan = CT_FALSE;
    part_assist_t part_ass = { 0 };

    cursor->curr_subpart.left = CT_INVALID_ID32;
    cursor->curr_subpart.right = CT_INVALID_ID32;
    cursor->curr_subpart.parent_partno = CT_INVALID_ID32;

    if (cursor->part_set.type == KEY_SET_FULL) {
        return sql_create_full_part_scan_keys(stmt, plan, cursor, handle, calc_mode);
    }

    CT_RETURN_IFERR(sql_generate_part_scan_key(stmt, handle, ar, &part_ass, CT_INVALID_ID32, &full_scan));
    if (full_scan) {
        return sql_create_full_part_scan_keys(stmt, plan, cursor, handle, calc_mode);
    } else if (part_ass.count == 0) {
        cursor->part_set.type = KEY_SET_EMPTY;
        return CT_SUCCESS;
    }

    if (knl_is_compart_table(handle)) {
        for (uint32 i = 0; i < part_ass.count; i++) {
            if (sql_make_subpart_scan_keys(stmt, &plan->subpart_array, cursor->table, &cursor->vmc, &part_ass.scan_key[i],
                calc_mode) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }
    }

    if (cursor->table->index_dsc) {
        return sql_put_part_scan_keys_desc(stmt, &part_ass, cursor);
    }

    return sql_put_part_scan_keys_asc(stmt, &part_ass, cursor);
}

static status_t sql_create_full_subpart_scan_keys(knl_handle_t handle, vmc_t *vmc, key_set_t *sub_set,
    uint32 compart_no)
{
    sub_set->offset = PENDING_HEAD_SIZE;
    uint32 mem_size = sizeof(part_scan_key_t) + PENDING_HEAD_SIZE;
    CT_RETURN_IFERR(vmc_alloc(vmc, mem_size, (void **)&sub_set->key_data));
    *(uint32 *)sub_set->key_data = mem_size;
    part_scan_key_t *scan_key = (part_scan_key_t *)((char *)sub_set->key_data + PENDING_HEAD_SIZE);
    scan_key->left = 0;
    scan_key->right = knl_subpart_count(handle, compart_no);
    scan_key->parent_partno = compart_no;
    return CT_SUCCESS;
}

static status_t sql_create_subpart_scan_keys(sql_stmt_t *stmt, sql_table_t *table, vmc_t *vmc, scan_list_array_t *subar,
    key_set_t *sub_set, uint32 compart_no)
{
    bool32 full_scan = CT_FALSE;
    part_assist_t part_ass = { 0 };
    knl_handle_t handle = table->entry->dc.handle;

    if (sub_set->type == KEY_SET_FULL) {
        return sql_create_full_subpart_scan_keys(handle, vmc, sub_set, compart_no);
    }

    CT_RETURN_IFERR(sql_generate_part_scan_key(stmt, handle, subar, &part_ass, compart_no, &full_scan));
    if (full_scan) {
        return sql_create_full_subpart_scan_keys(handle, vmc, sub_set, compart_no);
    } else if (part_ass.count == 0) {
        sub_set->type = KEY_SET_EMPTY;
        return CT_SUCCESS;
    }

    if (table->index_dsc) {
        return sql_put_subpart_scan_keys_desc(stmt, &part_ass, vmc, sub_set);
    }

    return sql_put_subpart_scan_keys_asc(stmt, &part_ass, vmc, sub_set);
}

bool32 sql_load_index_scan_key(sql_table_cursor_t *cursor)
{
    knl_scan_key_t *left_key = NULL;
    knl_scan_key_t *right_key = NULL;
    knl_index_desc_t *index_desc = cursor->table->index;
    knl_scan_range_t *scan_range = &cursor->knl_cur->scan_range;

    if (cursor->key_set.key_data == NULL) {
        return CT_FALSE;
    }

    galist_t *key_ranges = (galist_t *)cursor->key_set.key_data;
    if (cursor->key_set.offset >= key_ranges->count) {
        return CT_FALSE;
    }

    key_range_t *key_range = (key_range_t *)cm_galist_get(key_ranges, cursor->key_set.offset);

    // left border
    left_key = (knl_scan_key_t *)key_range->l_key;
    scan_range->l_key = *left_key;
    scan_range->l_key.buf = scan_range->l_buf;
    if (knl_get_key_size(index_desc, left_key->buf) != 0) {
        MEMS_RETURN_IFERR(
            memcpy_s(scan_range->l_buf, CT_KEY_BUF_SIZE, left_key->buf, knl_get_key_size(index_desc, left_key->buf)));
    }
    // right border
    right_key = (knl_scan_key_t *)key_range->r_key;
    scan_range->r_key = *right_key;
    scan_range->r_key.buf = scan_range->r_buf;
    if (knl_get_key_size(index_desc, right_key->buf) != 0) {
        MEMS_RETURN_IFERR(
            memcpy_s(scan_range->r_buf, CT_KEY_BUF_SIZE, right_key->buf, knl_get_key_size(index_desc, right_key->buf)));
    }
    // is_equal
    scan_range->is_equal = key_range->is_equal;
    cursor->key_set.offset++;
    return CT_TRUE;
}

static bool32 sql_load_part_scan_key(sql_table_cursor_t *table_cur)
{
    char *buf = NULL;
    uint32 len;

    if (table_cur->part_set.key_data == NULL) {
        return CT_FALSE;
    }

    buf = (char *)table_cur->part_set.key_data;
    len = *(uint32 *)buf;

    if (table_cur->part_set.offset >= len) {
        return CT_FALSE;
    }

    table_cur->curr_part = *(part_scan_key_t *)(buf + table_cur->part_set.offset);
    table_cur->part_set.offset += sizeof(part_scan_key_t);

    knl_handle_t handle = table_cur->table->entry->dc.handle;
    if (knl_is_compart_table(handle)) {
        if (table_cur->table->index_dsc) {
            table_cur->part_scan_index = table_cur->curr_part.sub_scan_key->count - 1;
        } else {
            table_cur->part_scan_index = 0;
        }
    }

    return CT_TRUE;
}

static bool32 sql_load_subscan_key(sql_table_cursor_t *table_cur, bool32 is_asc)
{
    knl_handle_t handle = table_cur->table->entry->dc.handle;
    uint32 load_part = is_asc ? table_cur->curr_part.left : table_cur->curr_part.right - 1;
    if (!knl_is_parent_part(handle, load_part)) {
        table_cur->curr_subpart.left = CT_INVALID_ID32;
        table_cur->curr_subpart.right = CT_INVALID_ID32;
        table_cur->curr_subpart.parent_partno = CT_INVALID_ID32;
        return CT_FALSE;
    }

    if (table_cur->curr_part.sub_scan_key == NULL) {
        return CT_FALSE;
    }

    key_set_t *key_set = (key_set_t *)cm_galist_get(table_cur->curr_part.sub_scan_key, table_cur->part_scan_index);
    if (key_set->type == KEY_SET_EMPTY) {
        return CT_FALSE;
    }

    uint32 len = *(uint32 *)key_set->key_data;
    if (key_set->offset >= len) {
        return CT_FALSE;
    }

    part_scan_key_t *subscan_key = (part_scan_key_t *)((char *)key_set->key_data + key_set->offset);
    if (is_asc) {
        table_cur->curr_part.left = subscan_key->parent_partno;
    } else {
        table_cur->curr_part.right = subscan_key->parent_partno + 1;
    }
    table_cur->curr_subpart = *subscan_key;
    key_set->offset += sizeof(part_scan_key_t);
    return CT_TRUE;
}

static bool32 sql_switch_next_parent_part(sql_table_cursor_t *table_cur, bool32 is_asc, bool32 *is_next_part_set)
{
    if (table_cur->curr_part.left < table_cur->curr_part.right) {
        if (is_asc) {
            table_cur->curr_part.left++;
        } else {
            table_cur->curr_part.right--;
        }
    }
    if (table_cur->curr_part.left >= table_cur->curr_part.right) {
        /* try to switch to next part key set */
        *is_next_part_set = CT_TRUE;
        return sql_load_part_scan_key(table_cur);
    }
    return CT_TRUE;
}

static bool32 sql_switch_parent_part(sql_table_cursor_t *table_cur, bool32 is_asc)
{
    uint32 parent_part;
    bool32 is_next_part_set = CT_FALSE;

    if (table_cur->curr_part.left >= table_cur->curr_part.right &&
        !sql_switch_next_parent_part(table_cur, is_asc, &is_next_part_set)) {
        return CT_FALSE;
    }

    while (table_cur->curr_part.left < table_cur->curr_part.right) {
        parent_part = is_asc ? table_cur->curr_part.left : (table_cur->curr_part.right - 1);
        /* skip empty interval part */
        if (knl_get_parent_part(table_cur->table->entry->dc.handle, parent_part) == NULL) {
            if (!sql_switch_next_parent_part(table_cur, is_asc, &is_next_part_set)) {
                return CT_FALSE;
            }
            continue;
        }
        if (is_asc && !is_next_part_set) {
            table_cur->part_scan_index++;
        } else if (!is_next_part_set) {
            table_cur->part_scan_index--;
        }
        is_next_part_set = CT_FALSE;
        /* skip empty scan part */
        if (!sql_load_subscan_key(table_cur, is_asc)) {
            if (!sql_switch_next_parent_part(table_cur, is_asc, &is_next_part_set)) {
                return CT_FALSE;
            }
            continue;
        }
        break;
    }
    return CT_TRUE;
}

static knl_part_locate_t sql_fetch_next_subpart_asc(sql_table_cursor_t *table_cur)
{
    knl_part_locate_t part_loc;
    part_loc.part_no = CT_INVALID_ID32;
    part_loc.subpart_no = CT_INVALID_ID32;

    if (table_cur->curr_subpart.left < table_cur->curr_subpart.right) {
        part_loc.part_no = table_cur->curr_part.left;
        part_loc.subpart_no = table_cur->curr_subpart.left++;
        return part_loc;
    }

    /* try to switch next sub ket set */
    if (table_cur->curr_subpart.left != CT_INVALID_ID32 && table_cur->curr_part.left < table_cur->curr_part.right) {
        if (sql_load_subscan_key(table_cur, CT_TRUE)) {
            part_loc.part_no = table_cur->curr_part.left;
            part_loc.subpart_no = table_cur->curr_subpart.left++;
            return part_loc;
        }
    }

    if (table_cur->curr_part.left < table_cur->curr_part.right) {
        /* the current parent part has been scaned, switch next */
        table_cur->curr_part.left++;
    }
    if (!sql_switch_parent_part(table_cur, CT_TRUE)) {
        return part_loc;
    }

    part_loc.part_no = table_cur->curr_part.left;
    part_loc.subpart_no =
        (table_cur->curr_subpart.left == CT_INVALID_ID32) ? CT_INVALID_ID32 : table_cur->curr_subpart.left++;

    return part_loc;
}

static knl_part_locate_t sql_fetch_next_part_asc(sql_table_cursor_t *table_cur)
{
    knl_handle_t handle = table_cur->table->entry->dc.handle;
    knl_part_locate_t part_loc = {
        .part_no = CT_INVALID_ID32,
        .subpart_no = CT_INVALID_ID32
    };

    if (knl_is_compart_table(handle)) {
        return sql_fetch_next_subpart_asc(table_cur);
    }

    if (table_cur->curr_part.left >= table_cur->curr_part.right) {
        if (!sql_load_part_scan_key(table_cur)) {
            return part_loc;
        }
    }

    while (table_cur->curr_part.left < table_cur->curr_part.right) {
        part_loc.part_no = table_cur->curr_part.left++;
        if (IS_REAL_PART(table_cur->table->entry->dc.handle, part_loc.part_no)) {
            break;
        }
    }
    part_loc.subpart_no = CT_INVALID_ID32;
    return part_loc;
}

static knl_part_locate_t sql_fetch_next_subpart_dsc(sql_table_cursor_t *table_cur)
{
    knl_part_locate_t part_loc;
    part_loc.part_no = CT_INVALID_ID32;
    part_loc.subpart_no = CT_INVALID_ID32;

    if (table_cur->curr_subpart.right > table_cur->curr_subpart.left) {
        part_loc.part_no = table_cur->curr_part.right - 1;
        part_loc.subpart_no = --table_cur->curr_subpart.right;
        return part_loc;
    }

    /* try to switch next sub ket set */
    if (table_cur->curr_subpart.right != CT_INVALID_ID32 && table_cur->curr_part.left < table_cur->curr_part.right) {
        if (sql_load_subscan_key(table_cur, CT_FALSE)) {
            part_loc.part_no = table_cur->curr_part.right - 1;
            part_loc.subpart_no = --table_cur->curr_subpart.right;
            return part_loc;
        }
    }

    /* the current parent part has been scaned, switch next */
    if (table_cur->curr_part.left < table_cur->curr_part.right) {
        table_cur->curr_part.right--;
    }
    if (!sql_switch_parent_part(table_cur, CT_FALSE)) {
        return part_loc;
    }

    part_loc.part_no = table_cur->curr_part.right - 1;
    part_loc.subpart_no =
        (table_cur->curr_subpart.right == CT_INVALID_ID32) ? CT_INVALID_ID32 : --table_cur->curr_subpart.right;

    return part_loc;
}

static knl_part_locate_t sql_fetch_next_part_dsc(sql_table_cursor_t *table_cur)
{
    knl_handle_t handle = table_cur->table->entry->dc.handle;
    knl_part_locate_t part_loc = {
        .part_no = CT_INVALID_ID32,
        .subpart_no = CT_INVALID_ID32
    };

    if (knl_is_compart_table(handle)) {
        return sql_fetch_next_subpart_dsc(table_cur);
    }

    if (table_cur->curr_part.right <= table_cur->curr_part.left) {
        if (!sql_load_part_scan_key(table_cur)) {
            return part_loc;
        }
    }

    while (table_cur->curr_part.right > table_cur->curr_part.left) {
        part_loc.part_no = --table_cur->curr_part.right;
        if (IS_REAL_PART(table_cur->table->entry->dc.handle, part_loc.part_no)) {
            break;
        }
    }
    part_loc.subpart_no = CT_INVALID_ID32;
    return part_loc;
}

knl_part_locate_t sql_fetch_next_part(sql_table_cursor_t *table_cur)
{
    knl_part_locate_t part_loc = {
        .part_no = CT_INVALID_ID32,
        .subpart_no = CT_INVALID_ID32
    };

    if (table_cur->part_set.type == KEY_SET_EMPTY) {
        return part_loc;
    }

    if (table_cur->table->index_dsc) {
        return sql_fetch_next_part_dsc(table_cur);
    }

    return sql_fetch_next_part_asc(table_cur);
}

static bool32 sql_set_table_scan_key(sql_table_cursor_t *table_cur)
{
    knl_part_locate_t part_loc;

    if (table_cur->knl_cur->scan_mode == SCAN_MODE_INDEX && !table_cur->multi_parts_info.stop_index_key) {
        if (!sql_load_index_scan_key(table_cur)) {
            return CT_FALSE;
        }
    }

    if (!knl_is_part_table(table_cur->table->entry->dc.handle)) {
        return CT_TRUE;
    }

    if (table_cur->knl_cur->scan_mode == SCAN_MODE_INDEX && !table_cur->table->index->parted) {
        if (table_cur->table->part_info.type == SPECIFY_PART_NONE) {
            return CT_TRUE;
        }

        if (knl_is_compart_table(table_cur->table->entry->dc.handle) && table_cur->table->part_info.is_subpart) {
            table_cur->knl_cur->restrict_subpart = CT_TRUE;
        }

        if (!knl_is_compart_table(table_cur->table->entry->dc.handle) || !table_cur->table->part_info.is_subpart) {
            table_cur->knl_cur->restrict_part = CT_TRUE;
        }

        part_loc = sql_fetch_next_part(table_cur);
        if (part_loc.part_no == CT_INVALID_ID32) {
            return CT_FALSE;
        }

        table_cur->knl_cur->part_loc = part_loc;
        return CT_TRUE;
    }

    part_loc = sql_fetch_next_part(table_cur);
    if (part_loc.part_no == CT_INVALID_ID32) {
        return CT_FALSE;
    }

    table_cur->knl_cur->part_loc = part_loc;
    return CT_TRUE;
}

static status_t sql_execute_index_scan(sql_stmt_t *stmt, sql_table_cursor_t *table_cur, plan_node_t *plan)
{
    knl_cursor_t *knl_cur;
    scan_plan_t *scan = &plan->scan_p;
    knl_dictionary_t *dc = &table_cur->table->entry->dc;

    knl_cur = table_cur->knl_cur;
    knl_cur->scan_mode = SCAN_MODE_INDEX;
    knl_cur->index_dsc = table_cur->table->index_dsc;
    knl_cur->index_slot = (uint8)scan->table->index->slot;
    if (knl_cur->action == CURSOR_ACTION_SELECT) {
        knl_cur->index_only = INDEX_ONLY_SCAN(table_cur->table->scan_flag);
        knl_cur->index_ffs = table_cur->table->index_ffs;
        knl_cur->index_ss = scan->table->index_skip_scan ? CT_TRUE : CT_FALSE;
        knl_cur->index_prefetch_row = INDEX_NL_PREFETCH(table_cur->table->scan_flag);
        knl_cur->skip_index_match = table_cur->table->skip_index_match;
    }

    if (!sql_set_table_scan_key(table_cur)) {
        knl_cur->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    if (table_cur->scan_flag == PAR_SQL_SCAN) {
        knl_cur->part_loc = table_cur->range.part_loc;
    }

    if (knl_open_cursor(&stmt->session->knl_session, knl_cur, dc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (table_cur->scan_flag == PAR_SQL_SCAN) {
        knl_set_index_scan_range(knl_cur, table_cur->range.idx_scan_range);
        knl_cur->index_paral = CT_TRUE;
    }

    sql_prepare_scan(stmt, dc, knl_cur);

    return CT_SUCCESS;
}

static inline status_t pre_set_knl_cur(sql_stmt_t *stmt, sql_table_cursor_t *tab_cursor, knl_cursor_t *knl_cur)
{
    // table func set partno
    if ((tab_cursor->table->func.desc != NULL) &&
        (tab_cursor->table->func.desc->pre_set_parms != NULL)) { // table function parallel scan
        return tab_cursor->table->func.desc->pre_set_parms(stmt, knl_cur, tab_cursor->table);
    }

    // sql parallel scan set partno
    if (tab_cursor->scan_flag > SEQ_TFM_SCAN) {
        knl_cur->part_loc = tab_cursor->range.part_loc;
    }

    return CT_SUCCESS;
}

static inline status_t set_knl_cur(sql_stmt_t *stmt, sql_table_cursor_t *tab_cursor, knl_session_t *knl_ses,
    knl_cursor_t *knl_cur)
{
    // table func set scan range
    if ((tab_cursor->table->func.desc != NULL) &&
        (tab_cursor->table->func.desc->reset_parms != NULL)) { // table function parallel scan
        return tab_cursor->table->func.desc->reset_parms(stmt, knl_cur, knl_ses, tab_cursor->table);
    }

    // sql parallel scan set scan range
    if (tab_cursor->scan_flag > SEQ_TFM_SCAN) {
        knl_set_table_scan_range(knl_ses, knl_cur, *(page_id_t *)(&tab_cursor->range.l_page),
            *(page_id_t *)(&tab_cursor->range.r_page));
    }

    return CT_SUCCESS;
}

status_t sql_execute_table_scan(sql_stmt_t *stmt, sql_table_cursor_t *table_cur)
{
    if (CT_IS_SUBSELECT_TABLE(table_cur->table->type)) {
        return sql_execute_select_plan(stmt, table_cur->sql_cur, table_cur->sql_cur->plan->select_p.next);
    }

    knl_dictionary_t *dc = &table_cur->table->entry->dc;
    knl_cursor_t *knl_cur = table_cur->knl_cur;
    knl_cur->scan_mode = SCAN_MODE_TABLE_FULL;
    knl_cur->index_slot = INVALID_INDEX_SLOT;
    knl_cur->index_flag = 0;

    if (!sql_set_table_scan_key(table_cur)) {
        knl_cur->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    // scan as table function
    CT_RETURN_IFERR(pre_set_knl_cur(stmt, table_cur, knl_cur));

    CT_RETURN_IFERR(knl_open_cursor(&stmt->session->knl_session, knl_cur, dc));

    CT_RETURN_IFERR(set_knl_cur(stmt, table_cur, &stmt->session->knl_session, knl_cur));

    sql_prepare_scan(stmt, dc, knl_cur);

    if (table_cur->scn != CT_INVALID_ID64) {
        if (table_cur->scn <= dc->chg_scn) {
            CT_THROW_ERROR(ERR_DEF_CHANGED, T2S(&table_cur->table->user), T2S_EX(&table_cur->table->name));
            return CT_ERROR;
        }

        /* * for flashback query, we should not run under transaction */
        knl_cur->xid = CT_INVALID_ID64;
        knl_cur->query_scn = table_cur->scn;
        if (knl_cur->isolevel == (uint8)ISOLATION_CURR_COMMITTED) {
            knl_cur->isolevel = (uint8)ISOLATION_READ_COMMITTED;
        }
    }

    return CT_SUCCESS;
}

#define IS_ROWID_CHAR(c) ((c) >= '0' && (c) <= '9')

static inline bool32 is_valid_rowid_var(const variant_t *var)
{
    uint32 i;

    if (!CT_IS_STRING_TYPE(var->type) || var->v_text.len != ROWID_LENGTH) {
        return CT_FALSE;
    }

    for (i = 0; i < (uint32)ROWID_LENGTH; i++) {
        if (!IS_ROWID_CHAR(var->v_text.str[i])) {
            return CT_FALSE;
        }
    }

    return CT_TRUE;
}

/* the dual function is @sql_rowid2str */
status_t sql_var2rowid(const variant_t *var, rowid_t *rowid, knl_dict_type_t dc_type)
{
    int32 value = 0;
    text_t file_text;
    text_t page_text;
    text_t slot_text;

    CM_POINTER2(var, rowid);

    if (!is_valid_rowid_var(var)) {
        CT_THROW_ERROR(ERR_INVALID_ROWID);
        return CT_ERROR;
    }

    if (dc_type == DICT_TYPE_TABLE || dc_type == DICT_TYPE_TABLE_NOLOGGING) {
        file_text.str = var->v_text.str;
        file_text.len = DICT_FILE_TEXT_LEN;

        page_text.str = var->v_text.str + DICT_FILE_TEXT_LEN;
        page_text.len = DICT_PAGE_TEXT_LEN;

        slot_text.str = var->v_text.str + DICT_FILE_TEXT_LEN + DICT_PAGE_TEXT_LEN;
        slot_text.len = SLOT_TEXT_LEN;

        CT_RETURN_IFERR(cm_text2int(&file_text, &value));
        rowid->file = value;

        CT_RETURN_IFERR(cm_text2int(&page_text, &value));
        rowid->page = value;

        CT_RETURN_IFERR(cm_text2int(&slot_text, &value));
        rowid->slot = value;
    } else {
        file_text.str = var->v_text.str;
        file_text.len = COMM_FILE_TEXT_LEN;

        page_text.str = var->v_text.str + COMM_FILE_TEXT_LEN;
        page_text.len = COMM_PAGE_TEXT_LEN;

        CT_RETURN_IFERR(cm_text2int(&file_text, &value));
        rowid->vmid = value;

        CT_RETURN_IFERR(cm_text2int(&page_text, &value));
        rowid->vm_slot = value;
        rowid->vm_tag = 0;
    }

    if (sql_is_invalid_rowid(rowid, dc_type)) {
        CT_THROW_ERROR(ERR_INVALID_ROWID);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t sql_prepare_rowid_set(sql_stmt_t *stmt, plan_rowid_set_t *p_ridset, rowid_t *s_ridset, uint16 *rid_cnt,
    knl_dict_type_t dc_type)
{
    uint16 i, j;
    variant_t var;
    rowid_t rid;
    bool32 is_found = CT_FALSE;

    if (p_ridset->array.count > KNL_ROWID_ARRAY_SIZE) {
        CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "p_ridset->array.count(%u) <= KNL_ROWID_ARRAY_SIZE(%u)",
            p_ridset->array.count, KNL_ROWID_ARRAY_SIZE);
        return CT_ERROR;
    }

    *rid_cnt = 0;
    for (i = 0; i < (uint16)p_ridset->array.count; i++) {
        expr_tree_t *rowid_expr_tree = (expr_tree_t *)sql_array_get(&p_ridset->array, i);

        if (sql_exec_expr(stmt, rowid_expr_tree, &var) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (var.is_null) {
            continue;
        }

        if (sql_var2rowid(&var, &rid, dc_type) != CT_SUCCESS) {
            return CT_ERROR;
        }

        is_found = CT_FALSE;
        for (j = 0; j < *rid_cnt; j++) {
            if (IS_SAME_ROWID(rid, s_ridset[j])) {
                is_found = CT_TRUE;
                break;
            }
        }

        /* if rid is not found in rowid set, then it is appended in the last */
        if (!is_found) {
            ROWID_COPY(s_ridset[*rid_cnt], rid);
            (*rid_cnt)++;
        }
    }

    return CT_SUCCESS;
}

status_t sql_execute_rowid_scan(sql_stmt_t *stmt, sql_table_cursor_t *cursor, plan_node_t *plan)
{
    knl_cursor_t *knl_cursor = NULL;
    knl_dictionary_t *dc = NULL;
    CM_POINTER3(stmt, cursor, plan);

    dc = &cursor->table->entry->dc;
    knl_cursor = cursor->knl_cur;
    knl_cursor->scan_mode = SCAN_MODE_ROWID;
    knl_cursor->index_slot = INVALID_INDEX_SLOT;

    if (sql_prepare_rowid_set(stmt, plan->scan_p.rowid_set, knl_cursor->rowid_array, &knl_cursor->rowid_count, dc->type) !=
        CT_SUCCESS) {
        return CT_ERROR;
    }

    if (knl_open_cursor(&stmt->session->knl_session, knl_cursor, dc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    sql_prepare_scan(stmt, dc, knl_cursor);

    return CT_SUCCESS;
}

status_t sql_make_index_scan_keys(sql_stmt_t *stmt, scan_plan_t *plan, sql_cursor_t *sql_cursor,
    sql_table_cursor_t *table_cur)
{
    scan_list_array_t array = { 0 };
    int32 code;
    const char *message = NULL;
    bool32 is_parallel = (sql_cursor == NULL || sql_cursor->par_ctx.par_mgr != NULL ||
        sql_cursor->par_ctx.par_exe_flag || table_cur->scan_flag > SEQ_TFM_SCAN);

    table_cur->key_set.key_data = NULL;
    array.count = table_cur->table->index->column_count;

    galist_t **list = NULL;
    if (sql_cursor != NULL) {
        list = &sql_cursor->exec_data.index_scan_range_ar;
    }

    if (sql_finalize_scan_range(stmt, &plan->index_array, &array, table_cur->table, sql_cursor, list, CALC_IN_EXEC) !=
        CT_SUCCESS) {
        return CT_ERROR;
    }

    if (array.flags & LIST_EXIST_LIST_EMPTY) {
        table_cur->key_set.type = KEY_SET_EMPTY;
        return CT_SUCCESS;
    }
    if (!is_parallel && !IS_BETTER_INDEX_SCAN(table_cur->table->scan_flag, RBO_INDEX_NONE_FLAG) &&
        array.items[0].type == RANGE_LIST_FULL) {
        // if index rowid scan and the first index column's scan range is RANGE_LIST_FULL,
        // then change table scan mode to TABLE_ACCESS_FULL
        table_cur->key_set.type = KEY_SET_FULL;
        return CT_SUCCESS;
    }
    table_cur->key_set.type = KEY_SET_NORMAL;
    /* set KEY_SET_EMPTY if came to ERR_MAX_KEYLEN_EXCEEDED */
    if (sql_create_index_scan_keys(stmt, table_cur, &array) == CT_SUCCESS) {
        return CT_SUCCESS;
    }
    cm_get_error(&code, &message, NULL);
    if (code == ERR_MAX_KEYLEN_EXCEEDED) {
        table_cur->key_set.type = KEY_SET_EMPTY;
        return CT_SUCCESS;
    }
    return CT_ERROR;
}

static inline status_t sql_calc_part_id_with_name(knl_handle_t handle, text_t *part_name, uint32 *part_num)
{
    return knl_find_table_part_by_name(handle, part_name, part_num);
}

static inline status_t sql_calc_subpart_id_with_name(knl_handle_t handle, text_t *part_name, uint32 *part_num,
    uint32 *subpart_num)
{
    return knl_find_subpart_by_name(handle, part_name, part_num, subpart_num);
}

static inline status_t sql_calc_part_id_with_value(sql_stmt_t *stmt, knl_handle_t handle, galist_t *values,
    uint32 *part_no)
{
    uint16 col_id, partkeys;
    variant_t val;
    part_key_t *key = NULL;
    expr_tree_t *expr = NULL;
    knl_column_t *knl_col = NULL;

    CT_RETURN_IFERR(sql_push(stmt, CT_MAX_COLUMN_SIZE, (void **)&key));
    partkeys = knl_part_key_count(handle);
    part_key_init(key, partkeys);

    for (uint16 i = 0; i < partkeys; i++) {
        col_id = knl_part_key_column_id(handle, i);
        knl_col = knl_get_column(handle, col_id);
        expr = (expr_tree_t *)cm_galist_get(values, i);

        CT_RETURN_IFERR(sql_exec_expr(stmt, expr, &val));

        CT_RETURN_IFERR(sql_check_border_variant(stmt, &val, knl_col->datatype, knl_col->size));

        CT_RETURN_IFERR(sql_part_put_scan_key(stmt, &val, knl_col->datatype, key));
    }
    *part_no = knl_locate_part_key(handle, key);
    return CT_SUCCESS;
}

static status_t sql_exec_partname_byid(sql_stmt_t *stmt, text_t *part_name)
{
    text_t *name = part_name;
    variant_t *res = NULL;
    text_t block, id;
    int32 i32;
    plv_id_t vid;

    name->str++;
    name->len--;

    cm_split_text(name, '_', '\0', &block, &id);

    if (cm_text2int(&block, &i32) != CT_SUCCESS) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "illegal partition-extended table name syntax %s", T2S(part_name));
        return CT_ERROR;
    }

    vid.block = (int16)i32;

    if (cm_text2int(&id, &i32) != CT_SUCCESS) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "illegal partition-extended table name syntax %s", T2S(part_name));
        return CT_ERROR;
    }

    vid.id = (uint16)i32;

    if (stmt->pl_exec == NULL) {
        CT_THROW_ERROR(ERR_UNEXPECTED_PL_VARIANT);
        return CT_ERROR;
    }
    res = ple_get_value(stmt, vid);
    if (!CT_IS_STRING_TYPE(res->type)) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "illegal partition-extended table name syntax %s, res type %d",
            T2S(part_name), res->type);
        return CT_ERROR;
    }

    *part_name = res->v_text;
    return CT_SUCCESS;
}

static status_t sql_calc_subpart_id_with_value(sql_stmt_t *stmt, knl_handle_t handle, galist_t *values,
    uint32 *compart_no, uint32 *subpart_no)
{
    variant_t value;
    part_key_t *com_key = NULL;
    part_key_t *sub_key = NULL;
    expr_tree_t *expr = NULL;
    knl_column_t *knl_column = NULL;
    uint16 col_id, part_keys, subpart_keys;

    CT_RETURN_IFERR(sql_push(stmt, CT_MAX_COLUMN_SIZE, (void **)&com_key));
    CT_RETURN_IFERR(sql_push(stmt, CT_MAX_COLUMN_SIZE, (void **)&sub_key));
    part_keys = knl_part_key_count(handle);
    subpart_keys = knl_subpart_key_count(handle);
    part_key_init(com_key, part_keys);
    part_key_init(sub_key, subpart_keys);

    for (uint16 i = 0; i < part_keys; i++) {
        col_id = knl_part_key_column_id(handle, i);
        knl_column = knl_get_column(handle, col_id);
        expr = (expr_tree_t *)cm_galist_get(values, i);

        CT_RETURN_IFERR(sql_exec_expr(stmt, expr, &value));

        CT_RETURN_IFERR(sql_check_border_variant(stmt, &value, knl_column->datatype, knl_column->size));

        CT_RETURN_IFERR(sql_part_put_scan_key(stmt, &value, knl_column->datatype, com_key));
    }

    *compart_no = knl_locate_part_key(handle, com_key);
    if (*compart_no == CT_INVALID_ID32) {
        *subpart_no = CT_INVALID_ID32;
        return CT_SUCCESS;
    }
    for (uint16 i = 0; i < subpart_keys; i++) {
        col_id = knl_subpart_key_column_id(handle, i);
        knl_column = knl_get_column(handle, col_id);
        expr = (expr_tree_t *)cm_galist_get(values, i + part_keys);

        CT_RETURN_IFERR(sql_exec_expr(stmt, expr, &value));

        CT_RETURN_IFERR(sql_check_border_variant(stmt, &value, knl_column->datatype, knl_column->size));

        CT_RETURN_IFERR(sql_part_put_scan_key(stmt, &value, knl_column->datatype, sub_key));
    }

    *subpart_no = knl_locate_subpart_key(handle, *compart_no, sub_key);
    return CT_SUCCESS;
}

static status_t sql_get_partid_with_name(sql_stmt_t *stmt, sql_table_t *table, knl_handle_t handle, uint32 *part_no,
    uint32 *subpart_no, sql_table_cursor_t *cursor)
{
    text_t part_name = table->part_info.part_name;
    if (part_name.len > 1 && part_name.str[0] == '@') {
        // pl variant name callback
        CT_RETURN_IFERR(sql_exec_partname_byid(stmt, &part_name));
    }

    if (table->part_info.is_subpart) {
        CT_RETURN_IFERR(sql_calc_subpart_id_with_name(handle, &part_name, part_no, subpart_no));
    } else {
        CT_RETURN_IFERR(sql_calc_part_id_with_name(handle, &part_name, part_no));
        if (knl_is_parent_part(handle, *part_no)) {
            cursor->curr_subpart.left = 0;
            cursor->curr_subpart.right = knl_subpart_count(handle, *part_no);
            cursor->curr_subpart.parent_partno = *part_no;
        }
    }

    return CT_SUCCESS;
}

static status_t sql_calc_part_id_with_specify(sql_stmt_t *stmt, sql_table_cursor_t *table_cur)
{
    uint32 part_no = CT_INVALID_ID32;
    uint32 subpart_no = CT_INVALID_ID32;
    sql_table_t *table = table_cur->table;
    knl_handle_t handle = table->entry->dc.handle;

    if (table->part_info.type == SPECIFY_PART_NAME) {
        CT_RETURN_IFERR(sql_get_partid_with_name(stmt, table, handle, &part_no, &subpart_no, table_cur));
    } else {
        CTSQL_SAVE_STACK(stmt);
        if (table->part_info.is_subpart) {
            if (sql_calc_subpart_id_with_value(stmt, handle, table->part_info.values, &part_no, &subpart_no) !=
                CT_SUCCESS) {
                CTSQL_RESTORE_STACK(stmt);
                return CT_ERROR;
            }
        } else {
            if (sql_calc_part_id_with_value(stmt, handle, table->part_info.values, &part_no) != CT_SUCCESS) {
                CTSQL_RESTORE_STACK(stmt);
                return CT_ERROR;
            }
        }
        CTSQL_RESTORE_STACK(stmt);
    }

    if (part_no == CT_INVALID_ID32 || (table->part_info.is_subpart && subpart_no == CT_INVALID_ID32)) {
        table_cur->part_set.type = KEY_SET_EMPTY;
        return CT_SUCCESS;
    }

    table_cur->curr_part.left = part_no;
    table_cur->curr_part.right = part_no + 1;
    table_cur->curr_part.parent_partno = CT_INVALID_ID32;
    if (table->part_info.is_subpart) {
        table_cur->curr_subpart.left = subpart_no;
        table_cur->curr_subpart.right = subpart_no + 1;
        table_cur->curr_subpart.parent_partno = part_no;
    }

    return CT_SUCCESS;
}

static void sql_init_part_scan_keys(sql_table_cursor_t *table_cur)
{
    table_cur->part_set.type = KEY_SET_NORMAL;
    table_cur->part_set.key_data = NULL;
    table_cur->part_scan_index = 0;
    table_cur->curr_part.left = CT_INVALID_ID32;
    table_cur->curr_part.right = CT_INVALID_ID32;
    table_cur->curr_part.parent_partno = CT_INVALID_ID32;
    table_cur->curr_part.sub_scan_key = NULL;
    table_cur->curr_subpart.left = CT_INVALID_ID32;
    table_cur->curr_subpart.right = CT_INVALID_ID32;
    table_cur->curr_subpart.parent_partno = CT_INVALID_ID32;
}

static bool32 sql_check_part_full_scan(sql_table_t *table, scan_list_array_t *part_arrays, bool32 is_subpart)
{
    if (part_arrays->flags & (LIST_EXIST_LIST_UNKNOWN | LIST_EXIST_LIST_ANY)) {
        return CT_TRUE;
    }

    knl_handle_t handle = table->entry->dc.handle;
    part_type_t part_type = is_subpart ? knl_subpart_table_type(handle) : knl_part_table_type(handle);
    if (part_type == PART_TYPE_RANGE) {
        return (part_arrays->items[0].type == RANGE_LIST_FULL);
    } else if (part_type == PART_TYPE_HASH) {
        return (part_arrays->flags & (LIST_EXIST_RANGE_UNEQUAL | LIST_EXIST_LIST_FULL));
    }

    // for PART_TYPE_LIST
    bool32 full_scan = CT_TRUE;
    for (uint32 i = 0; i < part_arrays->count; i++) {
        if (part_arrays->items[i].type != RANGE_LIST_FULL) {
            full_scan = CT_FALSE;
        } else {
            part_arrays->flags |= LIST_EXIST_RANGE_UNEQUAL;
        }
    }
    return full_scan;
}

static void sql_init_subpart_scan_key(sql_table_cursor_t *table_cur)
{
    if (table_cur->table->index_dsc) {
        table_cur->part_scan_index = table_cur->curr_part.sub_scan_key->count - 1;
    }
    while (table_cur->curr_part.left < table_cur->curr_part.right &&
        knl_get_parent_part(table_cur->table->entry->dc.handle, table_cur->curr_part.left) == NULL) {
        table_cur->curr_part.left++;
    }

    while (table_cur->curr_part.left < table_cur->curr_part.right &&
        knl_get_parent_part(table_cur->table->entry->dc.handle, table_cur->curr_part.right - 1) == NULL) {
        table_cur->curr_part.right--;
    }

    if (table_cur->curr_part.left >= table_cur->curr_part.right || !sql_load_subscan_key(table_cur, !table_cur->table->index_dsc)) {
        table_cur->curr_subpart.left = CT_INVALID_ID32;
        table_cur->curr_subpart.right = CT_INVALID_ID32;
        table_cur->curr_subpart.parent_partno = CT_INVALID_ID32;
    }
}

static bool32 inline array_is_exist_empty(uint32 flags, sql_table_cursor_t *table_cur)
{
    if (flags & LIST_EXIST_LIST_EMPTY) {
        table_cur->part_set.type = KEY_SET_EMPTY;
        return CT_TRUE;
    }
    return CT_FALSE;
}

status_t sql_make_part_scan_keys(sql_stmt_t *stmt, scan_plan_t *plan, sql_table_cursor_t *table_cur,
    sql_cursor_t *sql_cursor, calc_mode_t calc_mode)
{
    galist_t **list = NULL;
    scan_list_array_t part_array = { 0 };
    knl_handle_t handle = table_cur->table->entry->dc.handle;

    sql_init_part_scan_keys(table_cur);
    if (table_cur->table->part_info.type != SPECIFY_PART_NONE) {
        CT_RETURN_IFERR(sql_calc_part_id_with_specify(stmt, table_cur));
        if (table_cur->part_set.type != KEY_SET_EMPTY && knl_is_parent_part(handle, table_cur->curr_part.left) &&
            !table_cur->table->part_info.is_subpart) {
            CT_RETURN_IFERR(sql_make_subpart_scan_keys(stmt, &plan->subpart_array, table_cur->table, &table_cur->vmc,
                &table_cur->curr_part, calc_mode));
            sql_init_subpart_scan_key(table_cur);
        }

        return CT_SUCCESS;
    }

    if (plan->part_array.count == 0) {
        table_cur->part_set.type = KEY_SET_FULL;
        CT_RETURN_IFERR(sql_create_part_scan_keys(stmt, plan, table_cur, handle, &part_array, calc_mode));
        if (!knl_is_compart_table(handle)) {
            return CT_SUCCESS;
        }

        sql_init_subpart_scan_key(table_cur);
        return CT_SUCCESS;
    }

    part_array.count = knl_part_key_count(handle);

    if (sql_cursor != NULL) {
        list = &sql_cursor->exec_data.part_scan_range_ar;
    }

    CT_RETURN_IFERR(sql_finalize_scan_range(stmt, &plan->part_array, &part_array, table_cur->table, sql_cursor, list,
        CALC_IN_EXEC_PART_KEY));

    CT_RETSUC_IFTRUE(array_is_exist_empty(part_array.flags, table_cur));

    if (sql_check_part_full_scan(table_cur->table, &part_array, CT_FALSE)) {
        table_cur->part_set.type = KEY_SET_FULL;
    }

    CT_RETURN_IFERR(sql_create_part_scan_keys(stmt, plan, table_cur, handle, &part_array, calc_mode));
    if (knl_is_compart_table(handle) && table_cur->part_set.type != KEY_SET_EMPTY) {
        sql_init_subpart_scan_key(table_cur);
    }

    return CT_SUCCESS;
}

static inline void sql_init_key_set(key_set_t *key)
{
    key->type = KEY_SET_NORMAL;
    key->key_data = NULL;
    key->offset = PENDING_HEAD_SIZE;
}

status_t sql_make_subpart_scan_keys(sql_stmt_t *stmt, sql_array_t *subpart, sql_table_t *table, vmc_t *vmc,
    part_scan_key_t *part_scan_key, calc_mode_t calc_mode)
{
    key_set_t *curr_sub_set = NULL;
    scan_list_array_t subpart_arrays = { 0 };
    knl_handle_t handle = table->entry->dc.handle;
    CT_RETURN_IFERR(vmc_alloc(vmc, sizeof(galist_t), (void **)&part_scan_key->sub_scan_key));
    cm_galist_init(part_scan_key->sub_scan_key, vmc, vmc_alloc);

    for (uint32 i = part_scan_key->left; i < part_scan_key->right; i++) {
        if (!knl_is_parent_part(handle, i)) {
            continue;
        }

        CT_RETURN_IFERR(cm_galist_new(part_scan_key->sub_scan_key, sizeof(key_set_t), (void **)&curr_sub_set));
        sql_init_key_set(curr_sub_set);
        CTSQL_SAVE_STACK(stmt);
        if (subpart->count == 0) {
            curr_sub_set->type = KEY_SET_FULL;
            if (sql_create_subpart_scan_keys(stmt, table, vmc, &subpart_arrays, curr_sub_set, i) != CT_SUCCESS) {
                CTSQL_RESTORE_STACK(stmt);
                return CT_ERROR;
            }
            continue;
        }

        subpart_arrays.count = knl_subpart_key_count(handle);
        CT_RETURN_IFERR(sql_finalize_scan_range(stmt, subpart, &subpart_arrays, table, NULL, NULL, calc_mode));

        if (subpart_arrays.flags & LIST_EXIST_LIST_EMPTY) {
            curr_sub_set->type = KEY_SET_EMPTY;
            continue;
        } else if ((subpart_arrays.flags & LIST_EXIST_LIST_UNKNOWN) && table->scan_part_info != NULL) {
            table->scan_part_info->scan_type = SCAN_SUBPART_UNKNOWN;
            break;
        } else if ((subpart_arrays.flags & LIST_EXIST_LIST_ANY) && table->scan_part_info != NULL) {
            table->scan_part_info->scan_type = SCAN_SUBPART_ANY;
            break;
        }

        if (sql_check_part_full_scan(table, &subpart_arrays, CT_TRUE)) {
            curr_sub_set->type = KEY_SET_FULL;
        } else if (table->scan_part_info != NULL) {
            table->scan_part_info->scan_type = SCAN_SUBPART_SPECIFIED;
        }

        if (sql_create_subpart_scan_keys(stmt, table, vmc, &subpart_arrays, curr_sub_set, i) != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            return CT_ERROR;
        }

        CTSQL_RESTORE_STACK(stmt);
    }

    return CT_SUCCESS;
}

static uint32 sql_get_trim_parts_count(sql_table_cursor_t *table_cur)
{
    char *buf = NULL;
    uint32 len;
    uint32 count = table_cur->curr_part.right - table_cur->curr_part.left;
    part_scan_key_t curr_part;
    uint32 offset = table_cur->part_set.offset;

    if (table_cur->part_set.key_data == NULL) {
        return count;
    }

    buf = (char *)table_cur->part_set.key_data;
    len = *(uint32 *)buf;

    while (offset < len) {
        curr_part = *(part_scan_key_t *)(buf + offset);
        offset += sizeof(part_scan_key_t);
        count += curr_part.right - curr_part.left;
    }
    return count;
}

static status_t sql_init_knlcur_list(vmc_t *vmc, galist_t **knlcur_list)
{
    CT_RETURN_IFERR(vmc_alloc(vmc, sizeof(galist_t), (void **)knlcur_list));
    cm_galist_init(*knlcur_list, vmc, vmc_alloc);
    return CT_SUCCESS;
}

static status_t sql_get_knlcur_info(sql_table_cursor_t *tab_cursor)
{
    mps_knlcur_t *knlcur_info = NULL;
    CT_RETURN_IFERR(vmc_alloc(&tab_cursor->vmc, sizeof(mps_knlcur_t), (void **)&knlcur_info));
    knlcur_info->knl_cursor = tab_cursor->knl_cur;
    knlcur_info->offset = tab_cursor->key_set.offset;
    CT_RETURN_IFERR(cm_galist_insert(tab_cursor->multi_parts_info.knlcur_list, knlcur_info));

    return CT_SUCCESS;
}

static status_t sql_alloc_part_knlcur(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_table_t *table,
    sql_table_cursor_t *tab_cursor, knl_scan_range_t scan_range, uint32 offset_tmp)
{
    knl_cursor_t *knl_cursor = NULL;
    uint32 knl_cursor_size = g_instance->kernel.attr.cursor_size;
    CT_RETURN_IFERR(vmc_alloc_mem(&tab_cursor->vmc, knl_cursor_size, (void **)&knl_cursor));
    KNL_INIT_CURSOR(knl_cursor);
    knl_cursor->stmt = stmt;
    knl_init_cursor_buf(&stmt->session->knl_session, knl_cursor);

    knl_cursor->rowid = g_invalid_rowid;
    knl_cursor->scn = KNL_INVALID_SCN;
    knl_cursor->action =
        (IF_LOCK_IN_FETCH(cursor->query) && table->for_update) ? CURSOR_ACTION_UPDATE : CURSOR_ACTION_SELECT;
    knl_cursor->for_update_fetch = table->for_update;
    knl_cursor->rowmark.type = cursor->select_ctx->for_update_params.type;
    knl_cursor->rowmark.wait_seconds = cursor->select_ctx->for_update_params.wait_seconds;
    knl_cursor->update_info.count = 0;
    knl_cursor->global_cached = cursor->global_cached || table->global_cached;
    knl_cursor->decode_count = sql_get_decode_count(table);
    knl_cursor->scan_mode = SCAN_MODE_INDEX;
    knl_cursor->scan_range = scan_range;
    knl_cursor->scan_range.l_key.buf = knl_cursor->scan_range.l_buf;
    knl_cursor->scan_range.r_key.buf = knl_cursor->scan_range.r_buf;
    knl_cursor->scan_range.org_key.buf = knl_cursor->scan_range.org_buf;
    tab_cursor->key_set.offset = offset_tmp;
    tab_cursor->knl_cur = knl_cursor;

    return CT_SUCCESS;
}

static status_t sql_alloc_sort_array(sql_table_cursor_t *tab_cursor, uint32 count)
{
    mps_sort_t *sort_info = NULL;
    CT_RETURN_IFERR(vmc_alloc_mem(&tab_cursor->vmc, sizeof(mps_sort_t), (void **)&sort_info));
    tab_cursor->multi_parts_info.sort_info = sort_info;

    uint32 *sort_array = NULL;
    uint32 sort_array_length = count * sizeof(uint32);
    CT_RETURN_IFERR(vmc_alloc_mem(&tab_cursor->vmc, sort_array_length, (void **)&sort_array));
    tab_cursor->multi_parts_info.sort_info->count = 0;
    tab_cursor->multi_parts_info.sort_info->sort_array = sort_array;
    tab_cursor->multi_parts_info.sort_info->sort_array_length = sort_array_length;

    return CT_SUCCESS;
};

static status_t sql_move_sort_array(sql_table_cursor_t *tab_cursor, int32 pos, uint32 knlcur_id)
{
    uint32 count = tab_cursor->multi_parts_info.sort_info->count;
    uint32 *sort_array = tab_cursor->multi_parts_info.sort_info->sort_array;
    uint32 mov_size = (count - pos) * sizeof(uint32);
    uint32 buf_size = tab_cursor->multi_parts_info.sort_info->sort_array_length - (pos + 1) * sizeof(uint32);

    if (pos < count) {
        MEMS_RETURN_IFERR(memmove_s(sort_array + (pos + 1), buf_size, sort_array + pos, mov_size));
    }

    sort_array[pos] = knlcur_id;
    tab_cursor->multi_parts_info.sort_info->count++;

    return CT_SUCCESS;
}

static status_t sql_get_sorted_row_and_cmp(sql_stmt_t *stmt, plan_node_t *plan, sql_table_cursor_t *tab_cursor, char *buf,
    row_assist_t insert_ra, int32 pos, int32 *result)
{
    row_assist_t temp_ra;
    mps_sort_t *sort_info = tab_cursor->multi_parts_info.sort_info;
    mtrl_segment_t segment;
    segment.cmp_items = plan->scan_p.sort_items;
    segment.type = MTRL_SEGMENT_QUERY_SORT;
    segment.pending_type_buf = NULL;
    galist_t *knlcur_list = tab_cursor->multi_parts_info.knlcur_list;
    mps_knlcur_t *knlcur_info = (mps_knlcur_t *)cm_galist_get(knlcur_list, sort_info->sort_array[pos]);
    tab_cursor->knl_cur = knlcur_info->knl_cursor;
    row_init(&temp_ra, buf, CT_MAX_ROW_SIZE, plan->scan_p.sort_items->count);
    CT_RETURN_IFERR(sql_make_mtrl_sort_row(stmt, NULL, plan->scan_p.sort_items, &temp_ra));
    CT_RETURN_IFERR(sql_mtrl_sort_cmp(&segment, insert_ra.buf, temp_ra.buf, result));

    return CT_SUCCESS;
}

static status_t sql_sort_4_multi_parts_scan(sql_stmt_t *stmt, plan_node_t *plan, sql_table_cursor_t *tab_cursor,
    uint32 knlcur_id)
{
    mps_sort_t *sort_info = tab_cursor->multi_parts_info.sort_info;
    char *buf = NULL;
    row_assist_t insert_ra;

    if (sort_info->count == 0) {
        sort_info->sort_array[0] = knlcur_id;
        sort_info->count++;
        return CT_SUCCESS;
    }

    CTSQL_SAVE_STACK(stmt);
    CT_RETURN_IFERR(sql_push(stmt, CT_MAX_ROW_SIZE, (void **)&buf));
    row_init(&insert_ra, buf, CT_MAX_ROW_SIZE, plan->scan_p.sort_items->count);
    CT_RETURN_IFERR(sql_make_mtrl_sort_row(stmt, NULL, plan->scan_p.sort_items, &insert_ra));
    CT_RETURN_IFERR(sql_push(stmt, CT_MAX_ROW_SIZE, (void **)&buf));

    uint32 left = 0;
    uint32 right = sort_info->count - 1;
    int32 result = 0;
    uint32 mid = 0;
    CT_RETURN_IFERR(sql_get_sorted_row_and_cmp(stmt, plan, tab_cursor, buf, insert_ra, right, &result));
    if (result <= 0) {
        CT_RETURN_IFERR(sql_move_sort_array(tab_cursor, right + 1, knlcur_id));
        CTSQL_RESTORE_STACK(stmt);
        return CT_SUCCESS;
    }

    while (left < right) {
        mid = (left + right) >> 1;
        CT_RETURN_IFERR(sql_get_sorted_row_and_cmp(stmt, plan, tab_cursor, buf, insert_ra, mid, &result));
        if (result == 0) {
            break;
        } else if (result > 0) {
            right = mid;
        } else {
            left = mid + 1;
        }
    }

    if (result < 0) {
        CT_RETURN_IFERR(sql_move_sort_array(tab_cursor, mid + 1, knlcur_id));
    } else {
        CT_RETURN_IFERR(sql_move_sort_array(tab_cursor, mid, knlcur_id));
    }

    CTSQL_RESTORE_STACK(stmt);
    return CT_SUCCESS;
}

static bool32 sql_get_knlcur_pos(mps_sort_t *sort_info, uint32 *pos)
{
    if (sort_info->count == 0) {
        return CT_FALSE;
    }

    *pos = sort_info->sort_array[--sort_info->count];
    return CT_TRUE;
}

static status_t sql_execute_mutil_parts_index_scan(sql_stmt_t *stmt, sql_table_cursor_t *tab_cursor, plan_node_t *plan,
    sql_cursor_t *cursor)
{
    sql_table_t *table = tab_cursor->table;
    mps_ctx_t *multi_parts_info = &tab_cursor->multi_parts_info;
    CT_RETURN_IFERR(sql_init_knlcur_list(&tab_cursor->vmc, &multi_parts_info->knlcur_list));
    CT_RETURN_IFERR(sql_execute_index_scan(stmt, tab_cursor, plan));
    CT_RETURN_IFERR(sql_get_knlcur_info(tab_cursor));

    uint32 count = sql_get_trim_parts_count(tab_cursor); // the number of parts is count + 1
    CT_RETURN_IFERR(sql_alloc_sort_array(tab_cursor, count + 1));

    knl_scan_range_t scan_range = tab_cursor->knl_cur->scan_range;
    uint32 range_offset_tmp = tab_cursor->key_set.offset;
    // make sure sql_execute_index_scan() can not get next index scan range
    tab_cursor->multi_parts_info.stop_index_key = CT_TRUE;

    for (uint32 i = 1; i <= count; i++) {
        CT_RETURN_IFERR(sql_alloc_part_knlcur(stmt, cursor, table, tab_cursor, scan_range, range_offset_tmp));
        CT_RETURN_IFERR(sql_execute_index_scan(stmt, tab_cursor, plan));
        CT_RETURN_IFERR(sql_fetch_one_part(stmt, tab_cursor, table));
        CT_RETURN_IFERR(sql_get_knlcur_info(tab_cursor));

        if (!tab_cursor->knl_cur->eof) {
            CT_RETURN_IFERR(sql_sort_4_multi_parts_scan(stmt, plan, tab_cursor, i));
        }
    }

    tab_cursor->multi_parts_info.stop_index_key = CT_FALSE; // recovery flag
    mps_knlcur_t *first_info = (mps_knlcur_t *)cm_galist_get(multi_parts_info->knlcur_list, 0);
    tab_cursor->knl_cur = first_info->knl_cursor;
    tab_cursor->key_set.offset = first_info->offset;
    tab_cursor->multi_parts_info.knlcur_id = 0;

    return CT_SUCCESS;
}

static status_t sql_execute_table_index(sql_stmt_t *stmt, sql_table_cursor_t *tab_cursor, plan_node_t *plan,
    sql_cursor_t *cursor)
{
    CTSQL_SAVE_STACK(stmt);

    if (sql_make_index_scan_keys(stmt, &plan->scan_p, cursor, tab_cursor) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }

    CTSQL_RESTORE_STACK(stmt);

    tab_cursor->knl_cur->scan_mode = SCAN_MODE_INDEX;

    if (tab_cursor->key_set.type == KEY_SET_EMPTY) {
        tab_cursor->knl_cur->eof = CT_TRUE;
    } else if (tab_cursor->key_set.type == KEY_SET_FULL && !IS_BETTER_INDEX_SCAN(tab_cursor->table->scan_flag, 0)) {
        CT_RETURN_IFERR(sql_execute_table_scan(stmt, tab_cursor));
    } else if (tab_cursor->table->multi_parts_scan) {
        CT_RETURN_IFERR(sql_execute_mutil_parts_index_scan(stmt, tab_cursor, plan, cursor));
    } else {
        CT_RETURN_IFERR(sql_execute_index_scan(stmt, tab_cursor, plan));
    }
    return CT_SUCCESS;
}

static status_t sql_execute_json_table(sql_stmt_t *stmt, sql_table_cursor_t *tab_cursor)
{
    json_path_t *basic_path = tab_cursor->table->json_table_info->basic_path;
    json_path_step_t *last_step = &basic_path->steps[basic_path->count - 1];
    uint32 loc_size = basic_path->count * sizeof(json_step_loc_t);
    json_table_exec_t *exec = &tab_cursor->json_table_exec;

    CT_RETURN_IFERR(vmc_alloc(&tab_cursor->vmc, CT_MAX_ROW_SIZE + sizeof(row_head_t), (void **)&tab_cursor->knl_cur->row));
    tab_cursor->knl_cur->eof = CT_FALSE;
    exec->last_extend =
        (last_step->index_pairs_count > 0 || (last_step->index_flag & JSON_PATH_INDEX_IS_STAR)) ? CT_TRUE : CT_FALSE;
    exec->table_ready = CT_FALSE;
    exec->end = CT_FALSE;
    exec->ordinality = 1;
    exec->basic_path = tab_cursor->table->json_table_info->basic_path;
    CT_RETURN_IFERR(vmc_alloc(&tab_cursor->vmc, loc_size, (void **)&exec->loc));
    MEMS_RETURN_IFERR(memset_s(exec->loc, loc_size, 0, loc_size));
    CT_RETURN_IFERR(vmc_alloc(&tab_cursor->vmc, sizeof(json_assist_t), &exec->json_assist));
    JSON_ASSIST_INIT((json_assist_t *)exec->json_assist, stmt);
    return vmc_alloc(&tab_cursor->vmc, sizeof(json_value_t), &exec->json_value);
}

static status_t sql_scan_mapped_table(sql_stmt_t *stmt, sql_table_t *table, sql_table_cursor_t *tab_cursor,
    plan_node_t *plan)
{
    switch (table->type) {
        case FUNC_AS_TABLE:
            return sql_exec_table_func(stmt, &table->func, tab_cursor->knl_cur);

        case VIEW_AS_TABLE:
            if (knl_check_dc(stmt->session, &table->entry->dc) != CT_SUCCESS) {
                return CT_ERROR;
            }
            return sql_execute_select_plan(stmt, tab_cursor->sql_cur, tab_cursor->sql_cur->plan->select_p.next);

        case JSON_TABLE:
            return sql_execute_json_table(stmt, tab_cursor);

        case SUBSELECT_AS_TABLE:
        case WITH_AS_TABLE:
        default:
            return sql_execute_select_plan(stmt, tab_cursor->sql_cur, tab_cursor->sql_cur->plan->select_p.next);
    }
}

status_t sql_scan_normal_table(sql_stmt_t *stmt, sql_table_t *table, sql_table_cursor_t *tab_cursor, plan_node_t *plan,
    sql_cursor_t *cursor)
{
    if (knl_is_part_table(table->entry->dc.handle)) {
        CTSQL_SAVE_STACK(stmt);

        if (sql_make_part_scan_keys(stmt, &plan->scan_p, tab_cursor, cursor, CALC_IN_EXEC) != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            return CT_ERROR;
        }
        CTSQL_RESTORE_STACK(stmt);
    }

    if (table->scan_mode == SCAN_MODE_INDEX) {
        return sql_execute_table_index(stmt, tab_cursor, plan, cursor);
    } else if (table->scan_mode == SCAN_MODE_TABLE_FULL) {
        return sql_execute_table_scan(stmt, tab_cursor);
    } else if (table->scan_mode == SCAN_MODE_ROWID) {
        return sql_execute_rowid_scan(stmt, tab_cursor, plan);
    }
    return CT_SUCCESS;
}

status_t sql_execute_scan(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    CM_TRACE_BEGIN;
    sql_table_t *table = plan->scan_p.table;
    sql_table_cursor_t *tab_cursor = &cursor->tables[table->id];

    CT_RETURN_IFERR(sql_stack_safe(stmt));
    tab_cursor->table = table;
    tab_cursor->scan_mode = table->scan_mode;
    if (table->type != NORMAL_TABLE) {
        CT_RETURN_IFERR(sql_scan_mapped_table(stmt, table, tab_cursor, plan));
    } else {
        CT_RETURN_IFERR(sql_scan_normal_table(stmt, table, tab_cursor, plan, cursor));
    }
    CM_TRACE_END(stmt, plan->plan_id);
    return CT_SUCCESS;
}

status_t sql_get_trig_kernel_value(sql_stmt_t *stmt, row_head_t *row, uint16 *offsets, uint16 *lens,
    var_column_t *v_col, variant_t *value)
{
    char *ptr = NULL;
    uint32 len;

    value->is_null = CT_FALSE;
    len = v_col->col >= ROW_COLUMN_COUNT(row) ? CT_NULL_VALUE_LEN : lens[v_col->col];
    ptr = (char *)row + offsets[v_col->col];

    return sql_get_row_value(stmt, ptr, len, v_col, value, CT_TRUE);
}

static inline status_t sql_get_lob_row_value(char *ptr, uint32 len, variant_t *value, bool8 set_lob_nodeid)
{
    value->v_lob.type = *(uint32 *)(ptr + sizeof(uint32));

    if (value->v_lob.type == CT_LOB_FROM_KERNEL) {
        value->v_lob.knl_lob.bytes = (uint8 *)ptr;
        value->v_lob.knl_lob.size = len;
        value->v_lob.knl_lob.is_hex_const = CT_FALSE;
    } else if (value->v_lob.type == CT_LOB_FROM_VMPOOL) {
        value->v_lob.vm_lob = *(vm_lob_t *)ptr;
    } else {
        CT_THROW_ERROR(ERR_UNKNOWN_LOB_TYPE, "get lob row value");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

/* f1 int[], methods to get array value of f1 can be: f1 or f1[n] or f1[n:m] */
static status_t sql_get_array_value(sql_stmt_t *stmt, var_column_t *v_col, bool8 is_array_elem, variant_t *value,
    char *ptr, uint32 len)
{
    uint32 lob_type = *(uint32 *)(ptr + sizeof(uint32));
    vm_lob_t vlob;

    /* get element or sub array value, like f1[n] or f1 or f1[n:m] */
    if (lob_type == CT_LOB_FROM_KERNEL) {
        CT_RETURN_IFERR(sql_get_array_from_knl_lob(stmt, (knl_handle_t)ptr, &vlob));
    } else if (lob_type == CT_LOB_FROM_VMPOOL) {
        vlob = *(vm_lob_t *)ptr;
    } else {
        CT_THROW_ERROR(ERR_UNKNOWN_LOB_TYPE, "get array row value");
        return CT_ERROR;
    }

    array_assist_t aa;
    ARRAY_INIT_ASSIST_INFO(&aa, stmt);
    if (is_array_elem) {
        return sql_get_element_to_value(stmt, &aa, &vlob, v_col->ss_start, v_col->ss_end, v_col->datatype, value);
    } else {
        return sql_get_subarray_to_value(&aa, &vlob, v_col->ss_start, v_col->ss_end, v_col->datatype, value);
    }
}

status_t sql_get_subarray_by_col(sql_stmt_t *stmt, var_column_t *v_col, variant_t *value, variant_t *result)
{
    vm_lob_t *vlob = NULL;
    array_assist_t aa;

    if (value->is_null) {
        result->is_null = CT_TRUE;
        result->type = value->type;
        return CT_SUCCESS;
    }

    if (value->v_array.value.type == CT_LOB_FROM_KERNEL) {
        vm_lob_t temp_vlob;
        temp_vlob.node_id = 0;
        temp_vlob.unused = 0;
        CT_RETURN_IFERR(
            sql_get_array_from_knl_lob(stmt, (knl_handle_t)(value->v_array.value.knl_lob.bytes), &temp_vlob));
        value->v_array.value.vm_lob = temp_vlob;
        value->v_array.value.type = CT_LOB_FROM_VMPOOL;
    }

    ARRAY_INIT_ASSIST_INFO(&aa, stmt);
    vlob = &value->v_array.value.vm_lob;
    if (VAR_COL_IS_ARRAY_ELEMENT(v_col)) {
        return sql_get_element_to_value(stmt, &aa, vlob, v_col->ss_start, v_col->ss_end, v_col->datatype, result);
    } else {
        return sql_get_subarray_to_value(&aa, vlob, v_col->ss_start, v_col->ss_end, v_col->datatype, result);
    }
}

static inline ct_type_t sql_get_value_type(var_column_t *v_col, bool8 is_array_elem, void *ptr)
{
    if (SECUREC_UNLIKELY(v_col->is_array == CT_TRUE)) {
        return CT_TYPE_ARRAY;
    }

    if (SECUREC_UNLIKELY(is_array_elem == CT_TRUE)) {
        uint32 lob_type = *(uint32 *)((char *)ptr + sizeof(uint32));
        if (lob_type == CT_LOB_FROM_KERNEL || lob_type == CT_LOB_FROM_VMPOOL) {
            return CT_TYPE_ARRAY;
        }
    }

    return v_col->datatype;
}

status_t sql_get_row_value(sql_stmt_t *stmt, char *ptr, uint32 len, var_column_t *v_col, variant_t *value,
    bool8 set_lob_nodeid)
{
    bool8 is_array_elem = VAR_COL_IS_ARRAY_ELEMENT(v_col);

    /* get data type of value */
    value->type = sql_get_value_type(v_col, is_array_elem, ptr);

    /* value is null */
    if (len == CT_NULL_VALUE_LEN) {
        if (SECUREC_UNLIKELY(is_array_elem == CT_TRUE)) {
            /* for example, f1 int[] is array type and f1[1] is int type */
            value->type = v_col->datatype;
        }
        value->is_null = CT_TRUE;
        return CT_SUCCESS;
    }

    /* value is not null */
    value->is_null = CT_FALSE;
    switch ((ct_type_t)value->type) {
        case CT_TYPE_UINT32:
            VALUE(uint32, value) = *(uint32 *)ptr;
            break;

        case CT_TYPE_INTEGER:
            VALUE(int32, value) = *(int32 *)ptr;
            break;

        case CT_TYPE_BOOLEAN:
            VALUE(bool32, value) = *(bool32 *)ptr;
            break;

        case CT_TYPE_BIGINT:
            if (len == sizeof(int32)) {
                VALUE(int64, value) = (int64)(*(int32 *)ptr);
                break;
            }
            // fall through
        case CT_TYPE_DATE:
        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
            VALUE(int64, value) = *(int64 *)ptr;
            break;

        case CT_TYPE_TIMESTAMP_LTZ:
            VALUE(timestamp_ltz_t, value) = *(timestamp_ltz_t *)ptr;
            break;

        case CT_TYPE_TIMESTAMP_TZ:
            VALUE(timestamp_tz_t, value) = *(timestamp_tz_t *)ptr;
            break;

        case CT_TYPE_INTERVAL_DS:
            VALUE(interval_ds_t, value) = *(interval_ds_t *)ptr;
            break;

        case CT_TYPE_INTERVAL_YM:
            VALUE(interval_ym_t, value) = *(interval_ym_t *)ptr;
            break;

        case CT_TYPE_REAL:
            VALUE(double, value) = *(double *)ptr;
            break;

        case CT_TYPE_NUMBER:
        case CT_TYPE_DECIMAL:
            (void)cm_dec_4_to_8(VALUE_PTR(dec8_t, value), (dec4_t *)ptr, len);
            break;
        case CT_TYPE_NUMBER2:
            CT_RETURN_IFERR(cm_dec_2_to_8(VALUE_PTR(dec8_t, value), (const payload_t *)ptr, len));
            break;

        case CT_TYPE_STRING:
        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
            VALUE_PTR(text_t, value)->str = ptr;
            VALUE_PTR(text_t, value)->len = len;
            break;

        case CT_TYPE_CLOB:
        case CT_TYPE_BLOB:
        case CT_TYPE_IMAGE:
            CT_RETURN_IFERR(sql_get_lob_row_value(ptr, len, value, set_lob_nodeid));
            break;

        case CT_TYPE_ARRAY:
            CT_RETURN_IFERR(sql_get_array_value(stmt, v_col, is_array_elem, value, ptr, len));
            break;

        default:
            VALUE_PTR(binary_t, value)->bytes = (uint8 *)ptr;
            VALUE_PTR(binary_t, value)->size = len;
            VALUE_PTR(binary_t, value)->is_hex_const = CT_FALSE;
            break;
    }

    return CT_SUCCESS;
}

static inline status_t sql_get_ddm_value(sql_stmt_t *stmt, sql_table_t *table, var_column_t *v_col, variant_t *value)
{
    if (SECUREC_UNLIKELY(v_col->is_ddm_col && stmt->need_send_ddm) && table->type == NORMAL_TABLE &&
        KNL_SESSION(stmt)->uid != 0 &&
        !knl_check_sys_priv_by_uid(KNL_SESSION(stmt), KNL_SESSION(stmt)->uid, EXEMPT_REDACTION_POLICY)) {
        knl_column_t *column = dc_get_column(DC_ENTITY(&table->entry->dc), v_col->col);
        if (column->ddm_expr != NULL) {
            return sql_exec_expr(stmt, (expr_tree_t *)column->ddm_expr, value);
        }
    }
    return CT_SUCCESS;
}

status_t sql_get_ddm_kernel_value(sql_stmt_t *stmt, sql_table_t *table, knl_cursor_t *knl_cur, var_column_t *v_col,
    variant_t *value)
{
    CT_RETURN_IFERR(sql_get_kernel_value(stmt, table, knl_cur, v_col, value));
    return sql_get_ddm_value(stmt, table, v_col, value);
}

status_t sql_get_kernel_value(sql_stmt_t *stmt, sql_table_t *table, knl_cursor_t *knl_cursor, var_column_t *v_col,
    variant_t *value)
{
    bool32 exist = CT_FALSE;
    uint32 i = 0;
    char *ptr = NULL;
    uint32 len;
    uint16 id;

    /* knl_cursor is eof, return NULL value */
    if (knl_cursor->eof) {
        value->type = (v_col->is_array == CT_TRUE) ? CT_TYPE_ARRAY : v_col->datatype;
        value->is_null = CT_TRUE;
        return CT_SUCCESS;
    }

    id = (knl_cursor->index_only && table != NULL) ? table->idx_col_map[v_col->col] : v_col->col;

    if (knl_cursor->action == CURSOR_ACTION_UPDATE && stmt->is_check) {
        knl_update_info_t *ui = &knl_cursor->update_info;
        for (i = 0; i < ui->count; i++) {
            if (id == ui->columns[i]) {
                exist = CT_TRUE;
                break;
            }
        }
    }

    if (exist) {
        len = CURSOR_UPDATE_COLUMN_SIZE(knl_cursor, i);
        ptr = CURSOR_UPDATE_COLUMN_DATA(knl_cursor, i);
    } else {
        len = CURSOR_COLUMN_SIZE(knl_cursor, id);
        ptr = CURSOR_COLUMN_DATA(knl_cursor, id);
    }

    bool8 is_array_elem = VAR_COL_IS_ARRAY_ELEMENT(v_col);
    /* get data type of value */
    value->type = sql_get_value_type(v_col, is_array_elem, ptr);

    /* value is null */
    if (len == CT_NULL_VALUE_LEN) {
        if (SECUREC_UNLIKELY(is_array_elem == CT_TRUE)) {
            /* for example, f1 int[] is array type and f1[1] is int type */
            value->type = v_col->datatype;
        }
        value->is_null = CT_TRUE;
        return CT_SUCCESS;
    }

    /* value is not null */
    value->is_null = CT_FALSE;
    switch ((ct_type_t)value->type) {
        case CT_TYPE_UINT32:
            VALUE(uint32, value) = *(uint32 *)ptr;
            break;

        case CT_TYPE_INTEGER:
            VALUE(int32, value) = *(int32 *)ptr;
            break;

        case CT_TYPE_BOOLEAN:
            VALUE(bool32, value) = *(bool32 *)ptr;
            break;

        case CT_TYPE_BIGINT:
            if (len == sizeof(int32)) {
                VALUE(int64, value) = (int64)(*(int32 *)ptr);
                break;
            }
            // fall through
        case CT_TYPE_DATE:
        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
            VALUE(int64, value) = *(int64 *)ptr;
            break;

        case CT_TYPE_TIMESTAMP_LTZ:
            VALUE(timestamp_ltz_t, value) = *(timestamp_ltz_t *)ptr;
            break;

        case CT_TYPE_TIMESTAMP_TZ:
            VALUE(timestamp_tz_t, value) = *(timestamp_tz_t *)ptr;
            break;

        case CT_TYPE_INTERVAL_DS:
            VALUE(interval_ds_t, value) = *(interval_ds_t *)ptr;
            break;

        case CT_TYPE_INTERVAL_YM:
            VALUE(interval_ym_t, value) = *(interval_ym_t *)ptr;
            break;

        case CT_TYPE_REAL:
            VALUE(double, value) = *(double *)ptr;
            break;

        case CT_TYPE_NUMBER:
        case CT_TYPE_DECIMAL:
        case CT_TYPE_NUMBER3:
            (void)cm_dec_4_to_8(VALUE_PTR(dec8_t, value), (dec4_t *)ptr, len);
            break;

        case CT_TYPE_NUMBER2:
            CT_RETURN_IFERR(cm_dec_2_to_8(VALUE_PTR(dec8_t, value), (const payload_t *)ptr, len));
            break;

        case CT_TYPE_STRING:
        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
            VALUE_PTR(text_t, value)->str = ptr;
            VALUE_PTR(text_t, value)->len = len;
            break;

        case CT_TYPE_CLOB:
        case CT_TYPE_BLOB:
        case CT_TYPE_IMAGE:
            CT_RETURN_IFERR(sql_get_lob_row_value(ptr, len, value, CT_TRUE));
            break;

        case CT_TYPE_ARRAY:
            CT_RETURN_IFERR(sql_get_array_value(stmt, v_col, is_array_elem, value, ptr, len));
            break;

        default:
            VALUE_PTR(binary_t, value)->bytes = (uint8 *)ptr;
            VALUE_PTR(binary_t, value)->size = len;
            VALUE_PTR(binary_t, value)->is_hex_const = CT_FALSE;
            break;
    }
    return CT_SUCCESS;
}

status_t sql_fetch_scan_subselect(sql_stmt_t *stmt, struct st_sql_cursor *sql_cur, bool32 *eof)
{
    for (;;) {
        CTSQL_SAVE_STACK(stmt);
        if (SQL_CURSOR_PUSH(stmt, sql_cur) != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            return CT_ERROR;
        }
        if (sql_fetch_cursor(stmt, sql_cur, sql_cur->plan->select_p.next, &sql_cur->eof) != CT_SUCCESS) {
            SQL_CURSOR_POP(stmt);
            CTSQL_RESTORE_STACK(stmt);
            return CT_ERROR;
        }
        SQL_CURSOR_POP(stmt);

        *eof = sql_cur->eof;

        if (*eof) {
            CTSQL_RESTORE_STACK(stmt);
            return CT_SUCCESS;
        }

        bool32 is_found = CT_FALSE;
        if (sql_match_cond(stmt, &is_found) != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            return CT_ERROR;
        }

        if (is_found) {
            return CT_SUCCESS; // should not invoke CTSQL_RESTORE_STACK
        }
        CTSQL_RESTORE_STACK(stmt);
    }
}

bool32 sql_try_fetch_next_part(sql_table_cursor_t *cursor)
{
    knl_part_locate_t part_loc;
    knl_handle_t dc_entity = cursor->table->entry->dc.handle;

    if (!knl_is_part_table(dc_entity) ||
        (cursor->knl_cur->scan_mode == SCAN_MODE_INDEX && !cursor->table->index->parted) ||
        (cursor->knl_cur->scan_mode == SCAN_MODE_ROWID) || (cursor->scan_flag > SEQ_TFM_SCAN)) {
        return CT_FALSE;
    }

    part_loc = sql_fetch_next_part(cursor);
    if (part_loc.part_no == CT_INVALID_ID32) {
        return CT_FALSE;
    }
    cursor->knl_cur->part_loc = part_loc;

    if (cursor->knl_cur->scan_mode == SCAN_MODE_INDEX) {
        cursor->key_set.offset = 0;
        return sql_load_index_scan_key(cursor);
    }
    return CT_TRUE;
}

status_t sql_try_switch_part(sql_stmt_t *stmt, sql_table_cursor_t *tab_cursor, sql_table_t *table, bool32 *result)
{
    *result = sql_try_fetch_next_part(tab_cursor);
    if (!(*result)) {
        return CT_SUCCESS;
    }
    return knl_reopen_cursor(KNL_SESSION(stmt), tab_cursor->knl_cur, &table->entry->dc);
}

static bool32 sql_try_fetch_next_key(sql_table_cursor_t *cursor)
{
    if (cursor->scan_mode != SCAN_MODE_INDEX ||
        ((knl_is_part_table(cursor->table->entry->dc.handle) ||
        (knl_is_compart_table(cursor->table->entry->dc.handle))) &&
        cursor->part_set.type == KEY_SET_EMPTY) ||
        cursor->scan_flag == PAR_SQL_SCAN) {
        return CT_FALSE;
    }
    return sql_load_index_scan_key(cursor);
}

status_t sql_fetch_one_part(sql_stmt_t *stmt, sql_table_cursor_t *tab_cursor, sql_table_t *table)
{
    for (;;) {
        CT_RETURN_IFERR(knl_fetch(KNL_SESSION(stmt), tab_cursor->knl_cur));
        if (tab_cursor->knl_cur->eof) {
            if (sql_try_fetch_next_key(tab_cursor)) {
                CT_RETURN_IFERR(knl_reopen_cursor(KNL_SESSION(stmt), tab_cursor->knl_cur, &table->entry->dc));
                continue;
            }
        }
        return CT_SUCCESS;
    }
}

static status_t sql_fetch_table_scan(sql_stmt_t *stmt, sql_table_cursor_t *tab_cursor, sql_table_t *table)
{
    bool32 result = CT_FALSE;

    for (;;) {
        CT_RETURN_IFERR(sql_fetch_one_part(stmt, tab_cursor, table));
        if (tab_cursor->knl_cur->eof) {
            CT_RETURN_IFERR(sql_try_switch_part(stmt, tab_cursor, table, &result));
            if (result) {
                continue;
            }
            sql_free_varea_set(tab_cursor);
        }
        return CT_SUCCESS;
    }
}

static status_t sql_fetch_multi_parts_sort_scan(sql_stmt_t *stmt, plan_node_t *plan, sql_table_cursor_t *tab_cursor,
    sql_table_t *table)
{
    mps_knlcur_t *knlcur_info = NULL;
    uint32 pos;
    mps_ctx_t *multi_parts_info = &tab_cursor->multi_parts_info;

    CT_RETURN_IFERR(sql_fetch_one_part(stmt, tab_cursor, table));
    knlcur_info = (mps_knlcur_t *)cm_galist_get(multi_parts_info->knlcur_list, multi_parts_info->knlcur_id);
    knlcur_info->offset = tab_cursor->key_set.offset;

    if (!tab_cursor->knl_cur->eof) {
        CT_RETURN_IFERR(sql_sort_4_multi_parts_scan(stmt, plan, tab_cursor, multi_parts_info->knlcur_id));
    }
    if (!sql_get_knlcur_pos(multi_parts_info->sort_info, &pos)) {
        return CT_SUCCESS;
    }

    knlcur_info = (mps_knlcur_t *)cm_galist_get(multi_parts_info->knlcur_list, pos);
    tab_cursor->knl_cur = knlcur_info->knl_cursor;
    tab_cursor->key_set.offset = knlcur_info->offset;
    tab_cursor->multi_parts_info.knlcur_id = pos;

    return CT_SUCCESS;
}

static status_t sql_calc_json_table_record(sql_stmt_t *stmt, sql_table_cursor_t *tab_cursor)
{
    row_assist_t ra;
    json_table_info_t *json_table_info = tab_cursor->table->json_table_info;
    json_table_exec_t *exec = &tab_cursor->json_table_exec;
    rs_column_t *col = NULL;
    variant_t result;

    CTSQL_SAVE_STACK(stmt);
    row_init(&ra, (char *)tab_cursor->knl_cur->row, CT_MAX_ROW_SIZE, json_table_info->columns.count);
    for (uint32 i = 0; i < json_table_info->columns.count; i++) {
        col = (rs_column_t *)cm_galist_get(&json_table_info->columns, i);
        if (sql_calc_json_table_column_result(exec->json_assist, col, exec, &result) != CT_SUCCESS) {
            if (!IS_JSON_ERR(cm_get_error_code()) || json_table_info->json_error_info.type != JSON_RETURN_DEFAULT) {
                return CT_ERROR;
            }
            cm_reset_error();
            CT_RETURN_IFERR(sql_exec_expr(stmt, json_table_info->json_error_info.default_value, &result));
        }
        CT_RETURN_IFERR(sql_put_row_value(stmt, NULL, &ra, col->datatype, &result));
        CTSQL_RESTORE_STACK(stmt);
    }
    return CT_SUCCESS;
}

status_t sql_fetch_json_table_check(knl_cursor_t *json_table_cursor, json_error_type_t error_type,
    variant_t *json_result, variant_t *result)
{
    if (result->type == CT_TYPE_COLUMN) {
        CT_THROW_ERROR(ERR_ASSERT_ERROR, "wrong join tree");
        return CT_ERROR;
    }
    if (json_result->is_null || json_result->v_text.len == 0 ||
        (json_result->v_text.str[0] != '{' && json_result->v_text.str[0] != '[')) {
        if (error_type == JSON_RETURN_ERROR) {
            CT_THROW_ERROR(ERR_JSON_SYNTAX_ERROR, "expect non-scalar");
            return CT_ERROR;
        }
        json_table_cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    return CT_SUCCESS;
}

status_t sql_fetch_json_table_one_record(sql_stmt_t *stmt, sql_table_cursor_t *tab_cursor)
{
    bool32 switched = CT_FALSE;
    json_error_type_t error_type = tab_cursor->table->json_table_info->json_error_info.type;
    json_table_exec_t *exec = &tab_cursor->json_table_exec;
    knl_cursor_t *json_table_cursor = tab_cursor->knl_cur;
    json_assist_t *ja = exec->json_assist;
    variant_t json_result;
    variant_t result;

    if (!exec->table_ready) {
        JSON_ASSIST_INIT(ja, stmt);
        ja->vmc = &tab_cursor->vmc;

        if (tab_cursor->table->is_jsonb_table) { // jsonb binary data
            CT_RETURN_IFERR(
                sql_func_jsonb_to_jv(ja, tab_cursor->table->json_table_info->data_expr, exec->json_value, &result));
        } else { // json text data
            CT_RETURN_IFERR(
                sql_exec_json_func_arg(ja, tab_cursor->table->json_table_info->data_expr, &json_result, &result));
            CT_RETURN_IFERR(sql_fetch_json_table_check(json_table_cursor, error_type, &json_result, &result));
            if (json_table_cursor->eof) {
                return CT_SUCCESS;
            }
            if (json_parse(ja, &json_result.v_text, exec->json_value,
                tab_cursor->table->json_table_info->data_expr->loc) != CT_SUCCESS) {
                return handle_json_table_data_error(ja, error_type, &json_table_cursor->eof);
            }
        }
        CT_RETURN_IFERR(
            sql_visit_json_value(stmt, exec->json_value, exec, 0, &switched, sql_try_switch_json_array_loc));
        if (!switched) {
            json_table_cursor->eof = CT_TRUE;
            return CT_SUCCESS;
        }
        exec->table_ready = CT_TRUE;
    }

    CT_RETURN_IFERR(sql_calc_json_table_record(stmt, tab_cursor));

    switched = CT_FALSE;
    CT_RETURN_IFERR(sql_visit_json_value(stmt, exec->json_value, exec, 0, &switched, sql_try_switch_json_array_loc));
    exec->ordinality++;
    exec->end = !switched;
    cm_decode_row_ex((char *)json_table_cursor->row, json_table_cursor->offsets, json_table_cursor->lens,
        json_table_cursor->decode_count, &json_table_cursor->data_size, &json_table_cursor->decode_cln_total);
    return CT_SUCCESS;
}

void sql_release_json_table(sql_table_cursor_t *tab_cursor)
{
    json_table_exec_t *exec = &tab_cursor->json_table_exec;

    if (exec->json_assist != NULL) {
        JSON_ASSIST_DESTORY((json_assist_t *)exec->json_assist);
    }
    tab_cursor->knl_cur->eof = CT_TRUE;
    exec->json_value = NULL;
    exec->json_assist = NULL;
    exec->loc = NULL;
    exec->table_ready = CT_FALSE;
    tab_cursor->knl_cur->eof = CT_TRUE;
    vmc_free(&tab_cursor->vmc);
}

status_t sql_fetch_json_table(sql_stmt_t *stmt, sql_table_cursor_t *tab_cursor)
{
    bool32 result = CT_FALSE;
    status_t status = CT_SUCCESS;
    json_table_exec_t *exec = &tab_cursor->json_table_exec;
    cond_tree_t *cond = CTSQL_CURR_CURSOR(stmt)->cond;

    CTSQL_SAVE_STACK(stmt);
    while (!exec->end) {
        if (sql_fetch_json_table_one_record(stmt, tab_cursor) != CT_SUCCESS) {
            status = CT_ERROR;
            break;
        }
        if (tab_cursor->knl_cur->eof) {
            break;
        }
        if (cond == NULL) {
            CTSQL_RESTORE_STACK(stmt);
            return CT_SUCCESS;
        }
        if (sql_match_cond_node(stmt, cond->root, &result) != CT_SUCCESS) {
            status = CT_ERROR;
            break;
        }
        if (result) {
            CTSQL_RESTORE_STACK(stmt);
            return CT_SUCCESS;
        }
    }
    sql_release_json_table(tab_cursor);
    CTSQL_RESTORE_STACK(stmt);
    return status;
}

static status_t sql_fetch_mapped_scan(sql_stmt_t *stmt, sql_table_t *table, sql_table_cursor_t *tab_cursor, bool32 *eof)
{
    switch (table->type) {
        case FUNC_AS_TABLE:
            return sql_fetch_table_func(stmt, &table->func, tab_cursor->knl_cur, eof);
        case JSON_TABLE:
            CT_RETURN_IFERR(sql_fetch_json_table(stmt, tab_cursor));
            *eof = tab_cursor->knl_cur->eof;
            return CT_SUCCESS;
        case SUBSELECT_AS_TABLE:
        case VIEW_AS_TABLE:
        case WITH_AS_TABLE:
        default:
            return sql_fetch_scan_subselect(stmt, tab_cursor->sql_cur, eof);
    }
}

static inline status_t sql_fetch_multi_parts_scan(sql_stmt_t *stmt, plan_node_t *plan, sql_table_t *table,
    sql_table_cursor_t *tab_cursor, bool32 *eof)
{
    if (!tab_cursor->knl_cur->eof) {
        CT_RETURN_IFERR(sql_fetch_multi_parts_sort_scan(stmt, plan, tab_cursor, table));
    }
    *eof = (bool32)tab_cursor->knl_cur->eof;

    return CT_SUCCESS;
}

static inline status_t sql_fetch_normal_scan(sql_stmt_t *stmt, sql_table_t *table, sql_table_cursor_t *tab_cursor,
    bool32 *eof)
{
    CT_RETURN_IFERR(sql_fetch_table_scan(stmt, tab_cursor, table));
    *eof = (bool32)tab_cursor->knl_cur->eof;

    return CT_SUCCESS;
}

status_t sql_fetch_scan(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof)
{
    sql_table_t *table = plan->scan_p.table;
    sql_table_cursor_t *tab_cursor = &cursor->tables[table->id];
    CM_TRACE_BEGIN;

    if (cursor->eof) {
        *eof = CT_TRUE;
        return CT_SUCCESS;
    }

    SQL_CHECK_SESSION_VALID_FOR_RETURN(stmt);

    if (table->type != NORMAL_TABLE) {
        CT_RETURN_IFERR(sql_fetch_mapped_scan(stmt, table, tab_cursor, eof));
    } else if (table->multi_parts_scan) {
        CT_RETURN_IFERR(sql_fetch_multi_parts_scan(stmt, plan, table, tab_cursor, eof));
    } else {
        CT_RETURN_IFERR(sql_fetch_normal_scan(stmt, table, tab_cursor, eof));
    }
    CM_TRACE_END(stmt, plan->plan_id);
    return CT_SUCCESS;
}

bool32 can_print_subpart_no(sql_table_cursor_t *cursor)
{
    if (!knl_is_compart_table(cursor->table->entry->dc.handle)) {
        return CT_FALSE;
    }
    char *buffer = (char *)cursor->part_set.key_data;
    if ((buffer != NULL && cursor->part_set.offset >= *(uint32 *)buffer) ||
        (cursor->curr_part.right - cursor->curr_part.left != 1)) {
        return CT_FALSE;
    }
    if (cursor->curr_subpart.right - cursor->curr_subpart.left == 1) {
        return CT_TRUE;
    }
    return CT_FALSE;
}

void sql_print_part_info(sql_table_cursor_t *table_cur, char *buf, uint32 size, uint32 *offset)
{
    int32 iret_snprintf;
    do {
        iret_snprintf = snprintf_s(buf + *offset, size - *offset, size - *offset - 1, "[%u,%u),",
            table_cur->curr_part.left, table_cur->curr_part.right);
        if (iret_snprintf == -1) {
            CT_THROW_ERROR(ERR_SYSTEM_CALL, iret_snprintf);
            break;
        }
        *offset += iret_snprintf;
    } while (sql_load_part_scan_key(table_cur));
    buf[*offset - 1] = '\0';
}

void sql_print_subpart_info(sql_table_cursor_t *table_cur, char *buf, uint32 size, uint32 *offset)
{
    int32 iret_snprintf;
    iret_snprintf = snprintf_s(buf + *offset, size - *offset, size - *offset - 1, "{[%u,%u):[%u,%u)}",
        table_cur->curr_part.left, table_cur->curr_part.right, table_cur->curr_subpart.left, table_cur->curr_subpart.right);
    if (iret_snprintf == -1) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, iret_snprintf);
        return;
    }
    (*offset) += iret_snprintf;
    buf[(*offset)++] = '\0';
}

void sql_part_get_print(sql_stmt_t *stmt, scan_plan_t *plan, char *buffer, uint32 size)
{
    uint32 offset;
    int iret_snprintf;
    sql_table_cursor_t table_cur;
    sql_table_t table;

    CTSQL_SAVE_STACK(stmt);
    do {
        table_cur.table = &table;
        table = *plan->table;
        table.scan_part_info = NULL;
        table_cur.part_set.key_data = NULL;
        vmc_init(&stmt->session->vmp, &table_cur.vmc);

        if (sql_make_part_scan_keys(stmt, plan, &table_cur, NULL, CALC_IN_PLAN) != CT_SUCCESS) {
            iret_snprintf = snprintf_s(buffer, size, size - 1, "Filter:ERROR");
            if (iret_snprintf == -1) {
                CT_THROW_ERROR(ERR_SYSTEM_CALL, iret_snprintf);
            }
            break;
        }

        if (table_cur.part_set.type == KEY_SET_EMPTY) {
            iret_snprintf = snprintf_s(buffer, size, size - 1, "Filter:N/A");
            if (iret_snprintf == -1) {
                CT_THROW_ERROR(ERR_SYSTEM_CALL, iret_snprintf);
            }
            break;
        }

        iret_snprintf = snprintf_s(buffer, size, size - 1, "Filter:");
        if (iret_snprintf == -1) {
            CT_THROW_ERROR(ERR_SYSTEM_CALL, iret_snprintf);
            break;
        }
        offset = (uint32)iret_snprintf;
        if (!can_print_subpart_no(&table_cur)) {
            sql_print_part_info(&table_cur, buffer, size, &offset);
        } else {
            sql_print_subpart_info(&table_cur, buffer, size, &offset);
        }
    } while (CT_FALSE);

    CTSQL_RESTORE_STACK(stmt);

    vmc_free(&table_cur.vmc);
}

static status_t sql_adjust_ancestor_in_col(visit_assist_t *va, expr_node_t **node)
{
    if ((*node)->type == EXPR_NODE_COLUMN) {
        (*node)->value.v_col.ancestor = 0;
    }
    return CT_SUCCESS;
}

void rbo_adjust_ancestor_in_expr(sql_stmt_t *stmt, expr_node_t **node)
{
    visit_assist_t visit_ass;
    sql_init_visit_assist(&visit_ass, stmt, NULL);
    (void)visit_expr_node(&visit_ass, node, sql_adjust_ancestor_in_col);
}

bool32 sql_match_func_index_col(sql_stmt_t *stmt, expr_node_t *node, knl_index_desc_t *index, sql_table_t *table,
    uint32 *index_col)
{
    knl_column_t *col = NULL;
    expr_node_t *default_node = NULL;
    expr_node_t *func_expr = NULL;

    CTSQL_SAVE_STACK(stmt);
    if (sql_clone_expr_node(stmt, node, &func_expr, sql_stack_alloc) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_FALSE;
    }

    rbo_adjust_ancestor_in_expr(stmt, &func_expr);
    uint32 vcol = 0;
    for (uint32 i = 0; i < index->column_count; i++) {
        if (index->columns[i] >= DC_VIRTUAL_COL_START) {
            col = dc_get_column(table->entry->dc.handle, index->columns[i]);
            expr_node_t *col_node = ((expr_tree_t *)col->default_expr)->root;
            if (sql_clone_expr_node(stmt, col_node, &default_node, sql_stack_alloc) != CT_SUCCESS) {
                CTSQL_RESTORE_STACK(stmt);
                return CT_FALSE;
            }
            rbo_update_column_in_func(stmt, &default_node, table->id);

            if (sql_expr_node_equal(stmt, default_node, func_expr, NULL)) {
                (*index_col) = vcol;
                CTSQL_RESTORE_STACK(stmt);
                return CT_TRUE;
            }
            vcol++;
        }
    }

    CTSQL_RESTORE_STACK(stmt);
    return CT_FALSE;
}

static inline bool32 if_sql_status_is_ready(sql_stmt_t *stmt)
{
    if (stmt->status < STMT_STATUS_PREPARED) {
        return CT_FALSE;
    }

    if (stmt->context->type == CTSQL_TYPE_SELECT ||
        (stmt->context->type == CTSQL_TYPE_INSERT && ((sql_insert_t *)stmt->context->entry)->select_ctx != NULL) ||
        (stmt->context->type == CTSQL_TYPE_CREATE_TABLE && stmt->context->supplement != NULL)) {
        return CT_TRUE;
    }

    return CT_FALSE;
}

status_t sql_try_get_result_from_cache(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_table_cursor_t *tab_cursor,
    expr_node_t *node, variant_t *result, bool32 *ready)
{
    uint32 i;
    idx_func_cache_t *info = NULL;

    if (cursor->idx_func_cache == NULL) {
        CT_RETURN_IFERR(vmc_alloc(&cursor->vmc, sizeof(galist_t), (void **)&cursor->idx_func_cache));
        cm_galist_init(cursor->idx_func_cache, &cursor->vmc, vmc_alloc);
        return CT_SUCCESS;
    }

    galist_t *cache = cursor->idx_func_cache;
    for (i = 0; i < cache->count; i++) {
        info = cm_galist_get(cache, i);
        if (node == info->node) {
            break;
        }
    }

    if (i >= cache->count) {
        return CT_SUCCESS;
    }

    *ready = CT_TRUE;
    if (SECUREC_UNLIKELY(cursor->table_count != 1 && tab_cursor->table->plan_id > cursor->last_table)) {
        result->type = CT_TYPE_COLUMN;
        result->is_null = CT_FALSE;
        return CT_SUCCESS;
    }

    var_column_t v_col = { 0 };
    v_col.tab = info->tab;
    v_col.col = info->col;
    v_col.datatype = node->datatype;
    return sql_get_kernel_value(stmt, tab_cursor->table, tab_cursor->knl_cur, &v_col, result);
}

status_t sql_cache_matched_info(sql_cursor_t *cursor, expr_node_t *node, uint16 tab, uint16 col)
{
    galist_t *cache = cursor->idx_func_cache;
    idx_func_cache_t *info = NULL;

    for (uint32 i = 0; i < cache->count; i++) {
        info = cm_galist_get(cache, i);
        if (node == info->node) {
            return CT_SUCCESS;
        }
    }

    CT_RETURN_IFERR(vmc_alloc(&cursor->vmc, sizeof(idx_func_cache_t), (void **)&info));
    info->node = node;
    info->tab = tab;
    info->col = col;
    return cm_galist_insert(cursor->idx_func_cache, (void *)info);
}

status_t sql_try_get_value_from_index(sql_stmt_t *stmt, expr_node_t *node, variant_t *result, bool32 *ready)
{
    uint32 index_col;
    var_column_t v_col = { 0 };
    sql_table_t *table = NULL;
    sql_table_cursor_t *tab_cursor = NULL;

    if (!if_sql_status_is_ready(stmt)) {
        return CT_SUCCESS;
    }

    v_col.tab = CT_INVALID_ID16;
    CT_RETURN_IFERR(sql_get_expr_unique_table(stmt, node, &v_col.tab, &v_col.ancestor));
    if (v_col.tab == CT_INVALID_ID16) {
        return CT_SUCCESS;
    }

    sql_cursor_t *cursor = CTSQL_CURR_CURSOR(stmt);
    cursor = sql_get_proj_cursor(cursor);
    CT_RETURN_IFERR(sql_get_ancestor_cursor(cursor, v_col.ancestor, &cursor));

    tab_cursor = &cursor->tables[v_col.tab];
    CT_RETURN_IFERR(sql_try_get_result_from_cache(stmt, cursor, tab_cursor, node, result, ready));
    if (*ready) {
        return CT_SUCCESS;
    }

    table = tab_cursor->table;
    if (table == NULL || table->type != NORMAL_TABLE || table->index == NULL || !table->index->is_func ||
        !tab_cursor->knl_cur->index_only) {
        return CT_SUCCESS;
    }

    if (sql_match_func_index_col(stmt, node, table->index, table, &index_col)) {
        *ready = CT_TRUE;
        if (SECUREC_UNLIKELY(cursor->table_count != 1 && tab_cursor->table->plan_id > cursor->last_table)) {
            result->type = CT_TYPE_COLUMN;
            result->is_null = CT_FALSE;
            return CT_SUCCESS;
        }
        v_col.col = knl_get_column_count(table->entry->dc.handle) + index_col;
        v_col.datatype = node->datatype;
        CT_RETURN_IFERR(sql_cache_matched_info(cursor, node, v_col.tab, v_col.col));
        return sql_get_kernel_value(stmt, table, tab_cursor->knl_cur, &v_col, result);
    }

    return CT_SUCCESS;
}
