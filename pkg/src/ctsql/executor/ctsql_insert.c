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
 * ctsql_insert.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/executor/ctsql_insert.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_insert.h"
#include "ctsql_update.h"
#include "ctsql_select.h"
#include "ctsql_proj.h"
#include "srv_instance.h"
#include "ctsql_scan.h"

status_t sql_insert_try_ignore(sql_insert_t *insert_ctx)
{
    int32 err_code;
    const char *err_msg = NULL;
    cm_get_error(&err_code, &err_msg, NULL);
    if ((insert_ctx->syntax_flag & INSERT_IS_IGNORE) && err_code == ERR_DUPLICATE_KEY) {
        cm_reset_error();
        return CT_SUCCESS;
    }
    return CT_ERROR;
}

status_t sql_open_insert_cursor(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_insert_t *ctx)
{
    if (cursor->is_open) {
        sql_close_cursor(stmt, cursor);
    }
    CT_RETURN_IFERR(sql_alloc_table_cursors(cursor, 1));

    if (sql_open_cursor_for_update(stmt, ctx->table, &ctx->ssa, cursor, CURSOR_ACTION_INSERT) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_alloc_knl_cursor(stmt, &cursor->exec_data.ext_knl_cur) != CT_SUCCESS) {
        return CT_ERROR;
    }
    cursor->exec_data.ext_knl_cur->scan_mode = SCAN_MODE_ROWID;

    cursor->cond = NULL;
    cursor->plan = ctx->plan;
    cursor->insert_ctx = ctx;
    return CT_SUCCESS;
}

status_t sql_exec_column_default(sql_stmt_t *stmt, knl_dictionary_t *dc, knl_column_t *column, variant_t *val)
{
    val->type = column->datatype;

    if (column->flags & KNL_COLUMN_FLAG_SERIAL) {
        return sql_get_serial_value(stmt, dc, val);
    }

    if (column->default_expr == NULL || KNL_COLUMN_IS_DELETED(column)) {
        val->type = CT_TYPE_STRING; // default datatype
        val->is_null = CT_TRUE;
        return CT_SUCCESS;
    }

    return sql_exec_expr(stmt, (expr_tree_t *)column->default_expr, val);
}

static status_t sql_insert_get_col_value(sql_stmt_t *stmt, knl_dictionary_t *dc, sql_insert_t *insert,
    sql_cursor_t *cur_select, knl_column_t *knl_col, variant_t *val)
{
    uint32 pair_id;
    column_value_pair_t *value_pair = NULL;
    expr_tree_t *expr = NULL;
    rs_column_t *rs_column = NULL;

    pair_id = insert->col_map[knl_col->id];

    /* insert/replace into noselect */
    if (cur_select == NULL) {
        /* exec replace value */
        if (SECUREC_UNLIKELY(stmt->default_info.default_on == CT_TRUE)) {
            sql_get_default_value(stmt, knl_col->id, val);
            return CT_SUCCESS;
        }

        /* exec insert value */
        value_pair = (column_value_pair_t *)((pair_id == CT_INVALID_ID32) ? NULL : cm_galist_get(insert->pairs, pair_id));
        if (value_pair == NULL) {
            return sql_exec_column_default(stmt, dc, knl_col, val);
        }
        stmt->default_column = knl_col;
        expr = (expr_tree_t *)cm_galist_get(value_pair->exprs, stmt->pairs_pos);
        CT_RETURN_IFERR(sql_exec_expr(stmt, expr, val));
    } else {
        /* sql: insert into t1(f1, f2) select f1 from t2;
        f2 is clob or blob, has default value
        */
        if (pair_id == CT_INVALID_ID32) {
            return sql_exec_column_default(stmt, dc, knl_col, val);
        }

        // simply check val_from of value from sub_select
        rs_column = cm_galist_get(insert->select_ctx->first_query->rs_columns, pair_id);
        if (rs_column->type == RS_COL_CALC) {
            CT_RETURN_IFERR(sql_get_rs_value(stmt, cur_select, pair_id, val));
        } else {
            CT_RETURN_IFERR(sql_get_col_rs_value(stmt, cur_select, pair_id, &rs_column->v_col, val));
        }
    }

    if (knl_col->flags & KNL_COLUMN_FLAG_SERIAL) {
        if (val->is_null || (knl_col->datatype == CT_TYPE_INTEGER && val->v_int == 0) ||
            (knl_col->datatype == CT_TYPE_BIGINT && val->v_bigint == 0) ||
            (knl_col->datatype == CT_TYPE_UINT32 && val->v_uint32 == 0)) {
            return sql_get_serial_value(stmt, dc, val);
        }
    }

    return CT_SUCCESS;
}

static status_t sql_calc_part_for_insert(sql_stmt_t *stmt, part_key_t *part_key, uint32 *part_id,
    insert_assist_t *assist)
{
    uint16 col_id, part_keys;
    variant_t value;
    knl_column_t *knl_column = NULL;
    knl_dictionary_t *dc = &assist->insert_ctx->table->entry->dc;

    part_keys = knl_part_key_count(dc->handle);
    part_key_init(part_key, part_keys);

    for (uint16 i = 0; i < part_keys; i++) {
        col_id = knl_part_key_column_id(dc->handle, i);
        knl_column = knl_get_column(dc->handle, col_id);

        CT_RETURN_IFERR(sql_insert_get_col_value(stmt, dc, assist->insert_ctx, assist->cur_select, knl_column, &value));

        CT_RETURN_IFERR(sql_part_put_key(stmt, &value, knl_column->datatype, knl_column->size,
            KNL_COLUMN_IS_CHARACTER(knl_column), knl_column->precision, knl_column->scale, part_key));
    }

    *part_id = knl_locate_part_key(dc->handle, part_key);
    return CT_SUCCESS;
}

static status_t sql_calc_subpart_for_insert(sql_stmt_t *stmt, part_key_t *part_key, uint32 compart_no,
    uint32 *subpart_id, insert_assist_t *assist)
{
    uint16 col_id;
    variant_t value;
    knl_column_t *knl_column = NULL;
    knl_dictionary_t *dc = &assist->insert_ctx->table->entry->dc;

    uint16 part_keys = knl_subpart_key_count(dc->handle);
    part_key_init(part_key, part_keys);

    for (uint16 i = 0; i < part_keys; i++) {
        col_id = knl_subpart_key_column_id(dc->handle, i);
        knl_column = knl_get_column(dc->handle, col_id);

        CT_RETURN_IFERR(sql_insert_get_col_value(stmt, dc, assist->insert_ctx, assist->cur_select, knl_column, &value));

        CT_RETURN_IFERR(sql_part_put_key(stmt, &value, knl_column->datatype, knl_column->size,
            KNL_COLUMN_IS_CHARACTER(knl_column), knl_column->precision, knl_column->scale, part_key));
    }

    *subpart_id = knl_locate_subpart_key(dc->handle, compart_no, part_key);
    return CT_SUCCESS;
}

static void sql_set_partition_nologging_insert(sql_stmt_t *stmt, knl_handle_t dc_entity, knl_cursor_t *knl_cur,
    knl_part_locate_t part_loc)
{
    if (knl_part_nologging_enabled(dc_entity, part_loc) || stmt->session->nologging_enable) {
        if (!DB_IS_SINGLE(&stmt->session->knl_session) ||
            (DB_IS_RCY_CHECK_PCN(&stmt->session->knl_session) && stmt->session->nologging_enable)) {
            CT_LOG_DEBUG_WAR("forbid to nologging load when database in HA mode or \
                when _RCY_CHECK_PCN is TRUE on session_level nologging insert");
            knl_cur->logging = CT_TRUE;
            stmt->session->knl_session.rm->logging = CT_TRUE;
            knl_cur->nologging_type = LOGGING_LEVEL;
            stmt->session->knl_session.rm->nolog_type = LOGGING_LEVEL;
        } else {
            knl_cur->logging = CT_FALSE;
            stmt->session->knl_session.rm->logging = CT_FALSE;
            knl_cur->nologging_type = knl_part_nologging_enabled(dc_entity, part_loc) ? TABLE_LEVEL : SESSION_LEVEL;
            stmt->session->knl_session.rm->nolog_type = knl_cur->nologging_type;
        }
    } else {
        knl_cur->logging = CT_TRUE;
        stmt->session->knl_session.rm->logging = CT_TRUE;
        knl_cur->nologging_type = LOGGING_LEVEL;
        stmt->session->knl_session.rm->nolog_type = LOGGING_LEVEL;
    }
}

status_t sql_route_part_table(sql_stmt_t *stmt, knl_cursor_t *knl_cur, part_key_t *part_key, insert_assist_t *assist)
{
    knl_part_locate_t part_loc = {
        .part_no = CT_INVALID_ID32,
        .subpart_no = CT_INVALID_ID32
    };
    knl_dictionary_t *dc = &assist->insert_ctx->table->entry->dc;

    if (sql_calc_part_for_insert(stmt, part_key, &part_loc.part_no, assist) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (part_loc.part_no == CT_INVALID_ID32) {
        CT_THROW_ERROR(ERR_INVALID_PART_KEY, "inserted partition key does not map to any partition");
        return CT_ERROR;
    }

    if (knl_verify_interval_part(dc->handle, part_loc.part_no) &&
        knl_create_interval_part(&stmt->session->knl_session, dc, part_loc.part_no, part_key) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (knl_is_parent_part(dc->handle, part_loc.part_no)) {
        part_key_t *subpart_key = NULL;
        CTSQL_SAVE_STACK(stmt);
        if (sql_push(stmt, CT_MAX_COLUMN_SIZE, (void **)&subpart_key) != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            stmt->default_info.default_on = CT_FALSE;
            return CT_ERROR;
        }

        if (sql_calc_subpart_for_insert(stmt, subpart_key, part_loc.part_no, &part_loc.subpart_no, assist) !=
            CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            return CT_ERROR;
        }

        if (part_loc.subpart_no == CT_INVALID_ID32) {
            CT_THROW_ERROR(ERR_INVALID_PART_KEY, "inserted partition key does not map to any subpartition");
            CTSQL_RESTORE_STACK(stmt);
            return CT_ERROR;
        }
        CTSQL_RESTORE_STACK(stmt);
    }

    knl_set_table_part(knl_cur, part_loc);
    sql_set_partition_nologging_insert(stmt, dc->handle, knl_cur, part_loc);
    return CT_SUCCESS;
}

static inline bool32 sql_try_get_part_key_value(knl_part_key_t *decode_key, sql_insert_t *insert, knl_column_t *knl_col,
    variant_t *value)
{
    char *ptr = NULL;
    uint16 len, id;

    CT_RETVALUE_IFTRUE(!knl_is_part_table(insert->table->entry->dc.handle), CT_FALSE);

    id = insert->part_key_map[knl_col->id];
    if (id == CT_INVALID_ID16) {
        return CT_FALSE;
    }
    value->is_null = CT_FALSE;
    value->type = knl_col->datatype;

    len = decode_key->decoder.lens[id];
    if (len == PART_KEY_NULL_LEN) {
        value->is_null = CT_TRUE;
        return CT_TRUE;
    }

    ptr = decode_key->decoder.buf + decode_key->decoder.offsets[id];

    switch (knl_col->datatype) {
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
        case CT_TYPE_DATE:
        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
        case CT_TYPE_TIMESTAMP_LTZ:
            VALUE(int64, value) = *(int64 *)ptr;
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
            (void)cm_dec_2_to_8(VALUE_PTR(dec8_t, value), (const payload_t *)ptr, len);
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
            VALUE_PTR(var_lob_t, value)->type = CT_LOB_FROM_KERNEL;
            VALUE_PTR(var_lob_t, value)->knl_lob.bytes = (uint8 *)ptr;
            VALUE_PTR(var_lob_t, value)->knl_lob.size = len;
            VALUE_PTR(var_lob_t, value)->knl_lob.is_hex_const = CT_FALSE;
            break;

        default:
            VALUE_PTR(binary_t, value)->bytes = (uint8 *)ptr;
            VALUE_PTR(binary_t, value)->size = len;
            VALUE_PTR(binary_t, value)->is_hex_const = CT_FALSE;
            break;
    }
    return CT_TRUE;
}

status_t sql_try_construct_insert_data(sql_stmt_t *stmt, knl_cursor_t *knl_cur, knl_part_key_t *decode_key,
    insert_assist_t *ass)
{
    knl_column_t *knl_column = NULL;
    knl_dictionary_t *dc = &ass->insert_ctx->table->entry->dc;

    knl_column = knl_get_column(dc->handle, ass->col_id);
    if (KNL_COLUMN_IS_DELETED(knl_column)) {
        ass->value.is_null = CT_TRUE;
        if (sql_set_table_value(stmt, knl_cur, &ass->ra, knl_column, &ass->value) != CT_SUCCESS) {
            return CT_ERROR;
        }
        return CT_SUCCESS;
    }

    if (!sql_try_get_part_key_value(decode_key, ass->insert_ctx, knl_column, &ass->value)) {
        if (sql_insert_get_col_value(stmt, dc, ass->insert_ctx, ass->cur_select, knl_column, &ass->value) !=
            CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (sql_set_table_value(stmt, knl_cur, &ass->ra, knl_column, &ass->value) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (knl_column->flags & KNL_COLUMN_FLAG_SERIAL) {
        ass->has_serial = CT_TRUE;
        if (ass->value.type == CT_TYPE_BIGINT) {
            ass->max_serial_val = MAX(ass->max_serial_val, ass->value.v_bigint);
            ass->serial_val = ass->value.v_bigint;
        } else if (ass->value.type == CT_TYPE_UINT32) {
            ass->max_serial_val = MAX(ass->max_serial_val, ass->value.v_uint32);
            ass->serial_val = ass->value.v_uint32;
        } else {
            ass->max_serial_val = MAX(ass->max_serial_val, ass->value.v_int);
            ass->serial_val = ass->value.v_int;
        }
    }

    return CT_SUCCESS;
}

void sql_get_default_value(sql_stmt_t *stmt, uint32 col_id, variant_t *res)
{
    *res = stmt->default_info.default_values[col_id];
}

status_t sql_update_default_values(sql_stmt_t *stmt, uint32 col_id, variant_t *val)
{
    variant_t *set_cols_data = &stmt->default_info.default_values[col_id];
    *set_cols_data = *val;

    if (val->is_null) {
        return CT_SUCCESS;
    }

    /* deep copy string buffer */
    if (!sql_var_cankeep(stmt, val)) {
        return var_deep_copy(val, set_cols_data, (var_malloc_t)cm_push, (var_malloc_handle_t *)stmt->session->stack);
    }
    sql_keep_stack_variant(stmt, val);
    return CT_SUCCESS;
}

static status_t sql_init_default_values(sql_stmt_t *stmt, knl_dictionary_t *dc, uint32 column_count)
{
    knl_column_t *knl_column = NULL;
    variant_t value;
    uint32 i;

    CT_RETURN_IFERR(sql_push(stmt, column_count * sizeof(variant_t), (void **)&stmt->default_info.default_values));

    for (i = 0; i < column_count; i++) {
        knl_column = knl_get_column(dc->handle, i);
        CT_RETURN_IFERR(sql_exec_column_default(stmt, dc, knl_column, &value));
        CT_RETURN_IFERR(sql_update_default_values(stmt, i, &value));
    }

    return CT_SUCCESS;
}

static status_t sql_gen_insert_default_values(sql_stmt_t *stmt, sql_insert_t *insert)
{
    uint32 i;
    knl_dictionary_t *dc = &insert->table->entry->dc;
    uint32 col_count = knl_get_column_count(dc->handle);
    uint32 val_count = insert->pairs->count;
    column_value_pair_t *value_pair = NULL;
    expr_tree_t *expr = NULL;
    variant_t value;

    CT_RETURN_IFERR(sql_init_default_values(stmt, dc, col_count));

    for (i = 0; i < val_count; i++) {
        value_pair = (column_value_pair_t *)cm_galist_get(insert->pairs, i);
        stmt->default_column = value_pair->column;
        expr = (expr_tree_t *)cm_galist_get(value_pair->exprs, stmt->pairs_pos);
        CT_RETURN_IFERR(sql_exec_expr(stmt, expr, &value));

        if (value_pair->column->flags & KNL_COLUMN_FLAG_SERIAL) {
            if (value.is_null || (value_pair->column->datatype == CT_TYPE_INTEGER && value.v_int == 0) ||
                (value_pair->column->datatype == CT_TYPE_BIGINT && value.v_bigint == 0) ||
                (value_pair->column->datatype == CT_TYPE_UINT32 && value.v_uint32 == 0)) {
                CT_RETURN_IFERR(sql_get_serial_value(stmt, dc, &value));
            }
        }

        CT_RETURN_IFERR(sql_update_default_values(stmt, value_pair->column->id, &value));
    }

    return CT_SUCCESS;
}

status_t sql_init_and_gen_default_values(sql_stmt_t *stmt, insert_assist_t *assist, knl_cursor_t *knl_cursor)
{
    stmt->serial_value = 0;
    knl_cursor->vnc_column = NULL;
    knl_cursor->lob_inline_num = 0;

    if (assist->insert_ctx->ret_columns != NULL ||
        (stmt->context->type == CTSQL_TYPE_REPLACE && assist->cur_select == NULL)) {
        stmt->default_info.default_on = CT_TRUE;
        if (sql_gen_insert_default_values(stmt, assist->insert_ctx) != CT_SUCCESS) {
            stmt->default_info.default_on = CT_FALSE;
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t sql_handle_part_key(sql_stmt_t *stmt, insert_assist_t *assist, knl_cursor_t *knl_cur,
    knl_part_key_t *decode_key)
{
    part_key_t *part_key = NULL;
    knl_dictionary_t *dc = &assist->insert_ctx->table->entry->dc;
    uint32 col_count = knl_get_column_count(dc->handle);

    if (knl_is_part_table(dc->handle)) {
        if (sql_push(stmt, CT_MAX_COLUMN_SIZE, (void **)&part_key) != CT_SUCCESS) {
            stmt->default_info.default_on = CT_FALSE;
            return CT_ERROR;
        }
        if (sql_route_part_table(stmt, knl_cur, part_key, assist) != CT_SUCCESS) {
            stmt->default_info.default_on = CT_FALSE;
            return CT_ERROR;
        }
        knl_decode_part_key(part_key, decode_key);
    }

    bool32 is_csf = knl_is_table_csf(dc->handle, knl_cur->part_loc);
    uint32 max_row_len = knl_table_max_row_len(dc->handle, g_instance->kernel.attr.max_row_size, knl_cur->part_loc);
    cm_row_init(&assist->ra, (char *)knl_cur->row, max_row_len, col_count, is_csf);

    return CT_SUCCESS;
}

status_t sql_generate_insert_data(sql_stmt_t *stmt, knl_cursor_t *knl_cursor, insert_assist_t *assist)
{
    knl_part_key_t decode_key;
    knl_dictionary_t *dc = &assist->insert_ctx->table->entry->dc;
    uint32 col_count = knl_get_column_count(dc->handle);
    uint32 scan_id = 0;
    int32 code;
    const char *msg = NULL;

    /* generate default values by sql order */
    CT_RETURN_IFERR(sql_init_and_gen_default_values(stmt, assist, knl_cursor));

    CTSQL_SAVE_STACK(stmt);
    if (sql_handle_part_key(stmt, assist, knl_cursor, &decode_key) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }

    while (assist->col_id < col_count) {
        CTSQL_SAVE_STACK(stmt);
        if (sql_try_construct_insert_data(stmt, knl_cursor, &decode_key, assist) != CT_SUCCESS) {
            // all insert information should be putted to row buffer.
            CTSQL_RESTORE_STACK(stmt);

            cm_get_error(&code, &msg, NULL);

            if (code != ERR_ROW_SIZE_TOO_LARGE) {
                CTSQL_RESTORE_STACK(stmt);
                stmt->default_info.default_on = CT_FALSE;
                return CT_ERROR;
            }

            if (knl_is_lob_table(dc) && knl_cursor->lob_inline_num > 0) {
                cm_decode_row((char *)knl_cursor->row, knl_cursor->offsets, knl_cursor->lens, NULL);
                if (knl_reconstruct_lob_row(&stmt->session->knl_session, dc->handle, knl_cursor, &scan_id,
                    assist->col_id) != CT_SUCCESS) {
                    CTSQL_RESTORE_STACK(stmt);
                    stmt->default_info.default_on = CT_FALSE;
                    return CT_ERROR;
                }

                cm_reset_error();
                continue;
            } else {
                CTSQL_RESTORE_STACK(stmt);
                stmt->default_info.default_on = CT_FALSE;
                return CT_ERROR;
            }
        }
        // all insert information should be putted to row buffer.
        CTSQL_RESTORE_STACK(stmt);

        assist->col_id++;
    }

    row_end(&assist->ra);
    cm_decode_row((char *)knl_cursor->row, knl_cursor->offsets, knl_cursor->lens, NULL);
    CTSQL_RESTORE_STACK(stmt);
    stmt->default_info.default_on = CT_FALSE;

    if (assist->has_serial && stmt->pairs_pos == 0) {
        stmt->session->last_insert_id = assist->serial_val;
    }

    return CT_SUCCESS;
}

status_t sql_execute_insert_trigs(sql_stmt_t *stmt, trig_set_t *set, uint32 type, void *knl_cur, void *insert_data)
{
    trig_item_t *trig_item = NULL;
    pl_dc_t pl_dc;

    CTSQL_SAVE_STACK(stmt);
    for (uint32 i = 0; i < set->trig_count; ++i) {
        trig_item = &set->items[i];
        if (!trig_item->trig_enable) {
            continue;
        }

        if ((uint32)trig_item->trig_type != type || (trig_item->trig_event & TRIG_EVENT_INSERT) == 0) {
            continue;
        }

        if (pl_dc_open_trig_by_entry(stmt, &pl_dc, trig_item) != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            return CT_ERROR;
        }

        if (ple_exec_trigger(stmt, pl_dc.entity, TRIG_EVENT_INSERT, knl_cur, insert_data) != CT_SUCCESS) {
            ple_check_exec_trigger_error(stmt, pl_dc.entity);
            pl_dc_close(&pl_dc);
            CTSQL_RESTORE_STACK(stmt);
            return CT_ERROR;
        }
        pl_dc_close(&pl_dc);
    }

    CTSQL_RESTORE_STACK(stmt);
    return CT_SUCCESS;
}


static status_t sql_fetch_insert_update(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_insert_t *insert_ctx,
    knl_cursor_t *knl_cur, bool32 *is_found)
{
    upd_object_t *upd_obj = NULL;

    // may call sql_match_cond in knl_match_cond, need used current cursor in sql_match_cond
    CT_RETURN_IFERR(SQL_CURSOR_PUSH(stmt, cursor));
    CT_RETURN_IFERR(knl_fetch_by_rowid(KNL_SESSION(stmt), knl_cur, is_found));

    if (!(*is_found)) {
        SQL_CURSOR_POP(stmt);
        return CT_SUCCESS;
    }

    upd_obj = (upd_object_t *)cm_galist_get(insert_ctx->update_ctx->objects, 0);
    CT_RETURN_IFERR(sql_execute_update_table(stmt, cursor, knl_cur, upd_obj));

    cursor->total_rows++;
    SQL_CURSOR_POP(stmt);
    return CT_SUCCESS;
}

status_t sql_execute_insert_update(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_insert_t *insert_ctx,
    knl_dictionary_t *dc, bool32 *is_found)
{
    knl_cursor_t *insert_knl_cur = cursor->tables[0].knl_cur;
    knl_cursor_t *update_knl_cur = cursor->exec_data.ext_knl_cur;
    status_t status;
    errno_t ret;

    update_knl_cur->action = CURSOR_ACTION_UPDATE;
    CT_RETURN_IFERR(knl_open_cursor(KNL_SESSION(stmt), update_knl_cur, dc));
    CT_RETURN_IFERR(sql_push(stmt, CT_MAX_ROW_SIZE, (void **)&update_knl_cur->row));
    ret = memset_sp(update_knl_cur->row, CT_MAX_ROW_SIZE, 0, CT_MAX_ROW_SIZE);
    if (ret != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        CTSQL_POP(stmt);
        return CT_ERROR;
    }

    // set statement ssn when insert on duplicate key and before do insert update
    sql_set_ssn(stmt);

    // insert update only set ssn
    if (dc->type == DICT_TYPE_TEMP_TABLE_SESSION || dc->type == DICT_TYPE_TEMP_TABLE_TRANS) {
        update_knl_cur->ssn = stmt->ssn;
    } else {
        update_knl_cur->ssn = stmt->xact_ssn;
    }
    update_knl_cur->query_scn = insert_knl_cur->query_scn;

    ROWID_COPY(update_knl_cur->rowid, insert_knl_cur->conflict_rid);
    update_knl_cur->insert_info = insert_knl_cur->insert_info;
    cursor->tables[0].knl_cur = update_knl_cur;
    status = sql_fetch_insert_update(stmt, cursor, insert_ctx, update_knl_cur, is_found);
    cursor->tables[0].knl_cur = insert_knl_cur;

    CTSQL_POP(stmt);
    return status;
}


static inline status_t sql_keep_cursor_insert_info(sql_stmt_t *stmt, knl_cursor_t *knl_cursor, sql_insert_t *insert_ctx)
{
    if (SECUREC_LIKELY(insert_ctx->update_ctx == NULL)) {
        return CT_SUCCESS;
    }

    uint32 max_column_count = stmt->session->knl_session.kernel->attr.max_column_count;
    uint32 size = CT_MAX_ROW_SIZE + max_column_count * sizeof(uint16) * 2;
    char *ptr = NULL;

    CT_RETURN_IFERR(sql_push(stmt, size, (void **)&ptr));

    knl_cursor->insert_info.data = ptr;
    MEMS_RETURN_IFERR(memcpy_sp(knl_cursor->insert_info.data, CT_MAX_ROW_SIZE, knl_cursor->row, knl_cursor->row->size));

    knl_cursor->insert_info.lens = (uint16 *)(ptr + CT_MAX_ROW_SIZE);
    MEMS_RETURN_IFERR(memcpy_sp(knl_cursor->insert_info.lens, max_column_count * sizeof(uint16), knl_cursor->lens,
        ROW_COLUMN_COUNT(knl_cursor->row) * sizeof(uint16)));

    knl_cursor->insert_info.offsets = (uint16 *)(ptr + CT_MAX_ROW_SIZE + max_column_count * sizeof(uint16));
    MEMS_RETURN_IFERR(memcpy_sp(knl_cursor->insert_info.offsets, max_column_count * sizeof(uint16), knl_cursor->offsets,
        ROW_COLUMN_COUNT(knl_cursor->row) * sizeof(uint16)));

    return CT_SUCCESS;
}

static inline void sql_reset_cursor_insert_info(sql_stmt_t *stmt, knl_cursor_t *knl_cursor, sql_insert_t *insert_ctx)
{
    if (SECUREC_LIKELY(insert_ctx->update_ctx == NULL)) {
        return;
    }

    knl_cursor->insert_info.data = NULL;
    knl_cursor->insert_info.lens = NULL;
    knl_cursor->insert_info.offsets = NULL;

    return;
}

static status_t sql_send_insert_return_row(sql_stmt_t *stmt, galist_t *ret_columns)
{
    status_t status;

    stmt->default_info.default_on = CT_TRUE;
    status = sql_send_return_row(stmt, ret_columns, CT_FALSE);
    stmt->default_info.default_on = CT_FALSE;

    return status;
}

status_t sql_store_row_if_trigger_modify(insert_data_t *insert_data, knl_cursor_t *knl_cur, char *buf)
{
    if ((insert_data->row_modify) && (knl_cur->row->size != 0)) {
        errno_t errcode = memcpy_s(buf, g_instance->kernel.attr.max_row_size, knl_cur->row, knl_cur->row->size);
        if (errcode != EOK) {
            CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

status_t sql_restore_row_if_trigger_modify(insert_data_t *insert_data, knl_cursor_t *knl_cur, const char *buf,
    sql_stmt_t *stmt, insert_assist_t *assist)
{
    if ((insert_data->row_modify) && (((const row_head_t *)buf)->size != 0)) {
        errno_t errcode = memcpy_s(knl_cur->row, CT_MAX_ROW_SIZE, buf, ((const row_head_t *)buf)->size);
        if (errcode != EOK) {
            CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return CT_ERROR;
        }
    } else {
        sql_reset_insert_assist(assist);
        CT_RETURN_IFERR(sql_generate_insert_data(stmt, knl_cur, assist));
    }
    return CT_SUCCESS;
}

status_t sql_insert_inner(sql_stmt_t *stmt, sql_cursor_t *cursor, knl_cursor_t *knl_cur, insert_assist_t *assist,
    status_t *status)
{
    // may call sql_match_cond in knl_insrt(check, knl_verify_check_cons),
    // need used current cursor in sql_match_cond
    CT_RETURN_IFERR(SQL_CURSOR_PUSH(stmt, cursor) != CT_SUCCESS);
    *status = knl_insert(&stmt->session->knl_session, knl_cur);
    SQL_CURSOR_POP(stmt);

    if (*status == CT_SUCCESS) {
        CT_RETURN_IFERR(
            sql_execute_insert_triggers(stmt, assist->insert_ctx->table, TRIG_AFTER_EACH_ROW, knl_cur, NULL));
        CT_RETURN_IFERR(knl_verify_ref_integrities(&stmt->session->knl_session, knl_cur));

        if (assist->has_serial) {
            CT_RETURN_IFERR(
                knl_update_serial_value(&stmt->session->knl_session, knl_cur->dc_entity,
                                        assist->max_serial_val, CT_FALSE));
            CT_RETURN_IFERR(sql_send_generated_key_row(stmt, &assist->serial_val));
        }
    }

    return CT_SUCCESS;
}

static status_t sql_insert_single_row_core(sql_stmt_t *stmt, sql_cursor_t *cursor, knl_dictionary_t *dc,
    knl_cursor_t *knl_cur, insert_assist_t *assist)
{
    char *buf = NULL;
    status_t status = CT_ERROR;
    bool32 is_found = CT_FALSE;
    insert_data_t insert_data = {
        .cur_select = assist->cur_select,
        .row_modify = CT_FALSE
    };

    CT_RETURN_IFERR(sql_execute_insert_triggers(stmt, assist->insert_ctx->table, TRIG_BEFORE_EACH_ROW, knl_cur,
        (void *)&insert_data));

    CT_RETURN_IFERR(sql_push(stmt, g_instance->kernel.attr.max_row_size, (void **)&buf));

    /* execute insert */
    do {
        CT_BREAK_IF_ERROR(sql_insert_inner(stmt, cursor, knl_cur, assist, &status));

        // knl_insert return success
        if (status == CT_SUCCESS) {
            CTSQL_POP(stmt);
            return CT_SUCCESS;
        }

        // for on duplicate key update
        CT_BREAK_IF_TRUE(CT_ERRNO != ERR_DUPLICATE_KEY || assist->insert_ctx->update_ctx == NULL);

        // to release lob insert page when  insert failed result from primary key
        // or unique key  violation using sql "on duplicate key"
        CT_BREAK_IF_ERROR(knl_recycle_lob_insert_pages(&stmt->session->knl_session, knl_cur));

        // row has been modified by trigger, store it
        CT_BREAK_IF_ERROR(sql_store_row_if_trigger_modify(&insert_data, knl_cur, buf));

        // execute insert update
        cm_reset_error();

        CT_BREAK_IF_ERROR(sql_keep_cursor_insert_info(stmt, knl_cur, assist->insert_ctx));
        status = sql_execute_insert_update(stmt, cursor, assist->insert_ctx, dc, &is_found);
        sql_reset_cursor_insert_info(stmt, knl_cur, assist->insert_ctx);
        CT_BREAK_IF_ERROR(status);
        if (is_found) {
            CTSQL_POP(stmt);
            return CT_SUCCESS;
        }

        // row has been modified by trigger, restore it
        CT_BREAK_IF_ERROR(sql_restore_row_if_trigger_modify(&insert_data, knl_cur, buf, stmt, assist));

        SQL_CHECK_SESSION_VALID_FOR_RETURN(stmt);
    } while (CT_TRUE);

    CTSQL_POP(stmt);
    return CT_ERROR;
}

static status_t sql_insert_single_row(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_insert_t *insert_ctx,
    knl_dictionary_t *dc, knl_cursor_t *knl_cur, sql_cursor_t *cur_select)
{
    status_t status = CT_ERROR;
    insert_data_t insert_data = {
        .cur_select = cur_select,
        .row_modify = CT_FALSE
    };
    insert_assist_t assist;

    sql_init_insert_assist(&assist, &insert_data, insert_ctx, cur_select);

    /* generate insert values by dc order */
    CT_RETURN_IFERR(sql_generate_insert_data(stmt, knl_cur, &assist));

    if (insert_ctx->table->type == VIEW_AS_TABLE) {
        status = sql_insteadof_triggers(stmt, insert_ctx->table, knl_cur, &insert_data, TRIG_EVENT_INSERT);
    } else {
        status = sql_insert_single_row_core(stmt, cursor, dc, knl_cur, &assist);
    }
    CT_RETURN_IFERR(status);

    /* gen return values if has return columns */
    if (insert_ctx->ret_columns != NULL) {
        status = sql_send_insert_return_row(stmt, insert_ctx->ret_columns);
    }

    return status;
}

bool32 sql_batch_insert_enable(sql_stmt_t *stmt, sql_insert_t *insert_ctx)
{
    if (IS_COORDINATOR && IS_APP_CONN(stmt->session)) {
        return CT_FALSE;
    }

    if (stmt->allowed_batch_errs > 0) {
        return CT_FALSE;
    }

    if (insert_ctx->update_ctx != NULL || (insert_ctx->syntax_flag & INSERT_IS_IGNORE)) {
        return CT_FALSE;
    }

    if (stmt->return_generated_key) {
        return CT_FALSE;
    }

    return knl_batch_insert_enabled(stmt->session, &insert_ctx->table->entry->dc, stmt->session->triggers_disable);
}

static status_t sql_batch_insert_rows(sql_stmt_t *stmt, sql_cursor_t *cursor, knl_cursor_t *knl_cursor)
{
    if (knl_cursor->rowid_count == 0) {
        return CT_SUCCESS;
    }

    if (SQL_CURSOR_PUSH(stmt, cursor) != CT_SUCCESS) {
        return CT_ERROR;
    }

    uint32 row_count = knl_cursor->rowid_count;
    status_t status = knl_insert(&stmt->session->knl_session, knl_cursor);
    SQL_CURSOR_POP(stmt);
    if (status == CT_SUCCESS) {
        cursor->total_rows += row_count;
    } else {
        cursor->total_rows += knl_cursor->rowid_count;
        knl_cursor->rowid_count = 0;
    }

    SQL_CHECK_SESSION_VALID_FOR_RETURN(stmt);

    return status;
}

static status_t sql_try_batch_insert(sql_stmt_t *stmt, sql_cursor_t *cursor, knl_cursor_t *knl_cursor,
    knl_part_locate_t org_part_loc, row_head_t *curr_row)
{
    if (curr_row->size < KNL_MIN_ROW_SIZE) {
        curr_row->size = KNL_MIN_ROW_SIZE;
    }

    if (knl_cursor->rowid_count > 0) {
        if (knl_is_part_table(knl_cursor->dc_entity) && (knl_cursor->part_loc.part_no != org_part_loc.part_no ||
            knl_cursor->part_loc.subpart_no != org_part_loc.subpart_no)) {
            knl_part_locate_t curr_part_loc = knl_cursor->part_loc;
            knl_set_table_part(knl_cursor, org_part_loc);
            sql_set_partition_nologging_insert(stmt, knl_cursor->dc_entity, knl_cursor, org_part_loc);
            if (sql_batch_insert_rows(stmt, cursor, knl_cursor) != CT_SUCCESS) {
                return CT_ERROR;
            }

            knl_set_table_part(knl_cursor, curr_part_loc);
            sql_set_partition_nologging_insert(stmt, knl_cursor->dc_entity, knl_cursor, curr_part_loc);
        } else if ((uint32)(curr_row->size + knl_cursor->row_offset) > CT_MAX_ROW_SIZE ||
            knl_cursor->rowid_count == KNL_ROWID_ARRAY_SIZE) {
            if (sql_batch_insert_rows(stmt, cursor, knl_cursor) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }
    }

    errno_t errcode = memcpy_s((char *)knl_cursor->row + knl_cursor->row_offset, CT_MAX_ROW_SIZE - knl_cursor->row_offset,
        curr_row, curr_row->size);
    if (errcode != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return CT_ERROR;
    }

    knl_cursor->row_offset += curr_row->size;
    knl_cursor->rowid_count++;
    return CT_SUCCESS;
}

static status_t sql_prepare_batch_insert(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_insert_t *insert_ctx,
    knl_cursor_t *knl_cursor, sql_cursor_t *cur_select)
{
    row_head_t *org_row = knl_cursor->row;
    row_head_t *curr_row = NULL;
    knl_part_locate_t part_loc = knl_cursor->part_loc;
    insert_data_t insert_data = {
        .cur_select = cur_select,
        .row_modify = CT_FALSE
    };
    insert_assist_t assist;

    CTSQL_SAVE_STACK(stmt);
    if (sql_push(stmt, CT_MAX_ROW_SIZE, (void **)&curr_row) != CT_SUCCESS) {
        return CT_ERROR;
    }
    knl_cursor->row = curr_row;

    sql_init_insert_assist(&assist, &insert_data, insert_ctx, cur_select);
    if (sql_generate_insert_data(stmt, knl_cursor, &assist) != CT_SUCCESS) {
        knl_cursor->row = org_row;
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }
    knl_cursor->row = org_row;
    if (knl_cursor->vnc_column != NULL) {
        CT_THROW_ERROR(ERR_COLUMN_NOT_NULL, knl_cursor->vnc_column);
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }
    if (assist.has_serial) {
        if (knl_update_serial_value(&stmt->session->knl_session, knl_cursor->dc_entity, assist.max_serial_val, CT_FALSE) !=
            CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            return CT_ERROR;
        }
    }

    if (sql_try_batch_insert(stmt, cursor, knl_cursor, part_loc, curr_row) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }

    CTSQL_RESTORE_STACK(stmt);

    SQL_CHECK_SESSION_VALID_FOR_RETURN(stmt);
    return CT_SUCCESS;
}

static void subcursor_init(sql_cursor_t *sub_cur, plan_node_t *plan, sql_insert_t *insert_ctx)
{
    sub_cur->plan = plan;
    sub_cur->select_ctx = insert_ctx->select_ctx;
    sub_cur->scn = CT_INVALID_ID64;
}

static status_t sql_execute_insert_all_pairs(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_insert_t *insert_ctx,
    knl_dictionary_t *dc, knl_cursor_t *knl_cur, bool32 is_batch)
{
    status_t status = CT_SUCCESS;

    for (uint32 i = 0; i < insert_ctx->pairs_count; i++) {
        stmt->pairs_pos = i;

        CTSQL_SAVE_STACK(stmt);
        status = is_batch ? sql_prepare_batch_insert(stmt, cursor, insert_ctx, knl_cur, NULL) :
                            sql_insert_single_row(stmt, cursor, insert_ctx, dc, knl_cur, NULL);
        CTSQL_RESTORE_STACK(stmt);

        if (status != CT_SUCCESS) {
            break;
        }

        if (!is_batch) {
            cursor->total_rows++;
        }
    }

    return status;
}

static status_t sql_execute_insert_all(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_insert_t *insert_ctx,
    knl_dictionary_t *dc, knl_cursor_t *knl_cur)
{
    sql_cursor_t *sub_cursor = NULL;
    bool32 eof = CT_FALSE;
    plan_node_t *plan = insert_ctx->select_ctx->plan;
    bool32 is_batch = sql_batch_insert_enable(stmt, insert_ctx);
    status_t status = CT_SUCCESS;

    if (sql_alloc_cursor(stmt, &sub_cursor) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_execute_select_plan(stmt, sub_cursor, plan->select_p.next) != CT_SUCCESS) {
        sql_free_cursor(stmt, sub_cursor);
        return CT_ERROR;
    }

    if (SQL_CURSOR_PUSH(stmt, sub_cursor) != CT_SUCCESS) {
        sql_free_cursor(stmt, sub_cursor);
        return CT_ERROR;
    }

    for (;;) {
        CTSQL_SAVE_STACK(stmt);
        if (sql_fetch_cursor(stmt, sub_cursor, plan->select_p.next, &eof) != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            status = CT_ERROR;
            break;
        }

        if (eof) {
            if (is_batch) {
                status = sql_batch_insert_rows(stmt, cursor, knl_cur);
            }
            CTSQL_RESTORE_STACK(stmt);
            break;
        }

        // subselect may apear in values(),like values(subselect,1,2)
        // so must push the insert cursor for later use
        if (SQL_CURSOR_PUSH(stmt, cursor) != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            status = CT_ERROR;
            break;
        }
        status = sql_execute_insert_all_pairs(stmt, cursor, insert_ctx, dc, knl_cur, is_batch);
        SQL_CURSOR_POP(stmt);

        if (status != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            break;
        }
        CTSQL_RESTORE_STACK(stmt);
    }

    SQL_CURSOR_POP(stmt);
    sql_free_cursor(stmt, sub_cursor);
    return status;
}

static status_t sql_execute_insert_select_plan(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_insert_t *insert_ctx,
    knl_dictionary_t *dc, knl_cursor_t *knl_cur)
{
    sql_cursor_t *sub_cursor = NULL;
    bool32 eof = CT_FALSE;
    plan_node_t *plan = insert_ctx->select_ctx->plan;
    status_t status = CT_SUCCESS;
    bool32 is_batch = sql_batch_insert_enable(stmt, insert_ctx);

    if (sql_alloc_cursor(stmt, &sub_cursor) != CT_SUCCESS) {
        return CT_ERROR;
    }
    subcursor_init(sub_cursor, plan, insert_ctx);

    if (sql_execute_select_plan(stmt, sub_cursor, sub_cursor->plan->select_p.next) != CT_SUCCESS) {
        sql_free_cursor(stmt, sub_cursor);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(SQL_CURSOR_PUSH(stmt, sub_cursor));

    for (;;) {
        CTSQL_SAVE_STACK(stmt);
        if (sql_fetch_cursor(stmt, sub_cursor, sub_cursor->plan->select_p.next, &eof) != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            status = CT_ERROR;
            break;
        }

        if (eof) {
            if (is_batch) {
                status = sql_batch_insert_rows(stmt, cursor, knl_cur);
            }
            CTSQL_RESTORE_STACK(stmt);
            break;
        }

        status = is_batch ? sql_prepare_batch_insert(stmt, cursor, insert_ctx, knl_cur, sub_cursor) :
                            sql_insert_single_row(stmt, cursor, insert_ctx, dc, knl_cur, sub_cursor);
        if (status != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            status = sql_insert_try_ignore(insert_ctx);
            if (status == CT_SUCCESS) {
                continue;
            }
            break;
        }
        CTSQL_RESTORE_STACK(stmt);
        if (!is_batch) {
            cursor->total_rows++;
        }
    }

    SQL_CURSOR_POP(stmt);
    sql_free_cursor(stmt, sub_cursor);
    return status;
}

static status_t sql_handle_batch_error(sql_stmt_t *stmt, uint16 id)
{
    CT_RETURN_IFERR(sql_try_put_dml_batch_error(stmt, id, g_tls_error.code, g_tls_error.message));
    stmt->actual_batch_errs++;
    stmt->param_info.paramset_offset++;
    return CT_SUCCESS;
}

static status_t sql_execute_batch_insert(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_insert_t *insert_ctx,
    knl_cursor_t *knl_cur)
{
    status_t status = CT_SUCCESS;

    for (uint16 i = stmt->param_info.paramset_offset; i < stmt->param_info.paramset_size; i++) {
        // do read params from req packet
        status = sql_read_params(stmt);
        if (status != CT_SUCCESS) {
            // try allowed batch errors if execute error
            CT_LOG_DEBUG_ERR("failed to read param when issue dml, paramset index: %u", i);
            if (stmt->allowed_batch_errs > 0) {
                status = CT_SUCCESS;
                if (++stmt->actual_batch_errs <= stmt->allowed_batch_errs) {
                    CT_RETURN_IFERR(sql_handle_batch_error(stmt, i));
                    continue;
                }
            }
            (void)sql_batch_insert_rows(stmt, cursor, knl_cur);
            break;
        }

        // need clean value with the previous parameters
        sql_reset_first_exec_vars(stmt);
        sql_reset_sequence(stmt);

        for (uint32 j = 0; j < insert_ctx->pairs_count; j++) {
            stmt->pairs_pos = j;
            status = sql_prepare_batch_insert(stmt, cursor, insert_ctx, knl_cur, NULL);
            if (status != CT_SUCCESS) {
                break;
            }
        }

        if (status == CT_SUCCESS && i == stmt->param_info.paramset_size - 1) {
            status = sql_batch_insert_rows(stmt, cursor, knl_cur);
        }

        if (status != CT_SUCCESS) {
            CT_LOG_DEBUG_ERR("failed to execute dml when issue dml, paramset index: %u", i);
            // try allowed batch errors if execute error
            if (stmt->allowed_batch_errs > 0) {
                status = CT_SUCCESS;
                if (++stmt->actual_batch_errs <= stmt->allowed_batch_errs) {
                    CT_RETURN_IFERR(sql_handle_batch_error(stmt, i));
                    continue;
                }
            }
            break;
        }

        stmt->param_info.paramset_offset++;
    }

    if (status != CT_SUCCESS) {
        (void)sql_batch_insert_rows(stmt, cursor, knl_cur);
    }

    return status;
}

static status_t sql_execute_insert_pairs(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_insert_t *insert_ctx,
    knl_dictionary_t *dc, knl_cursor_t *knl_cur)
{
    bool32 is_batch = (insert_ctx->pairs_count > 1) && sql_batch_insert_enable(stmt, insert_ctx);
    status_t status = CT_SUCCESS;

    for (uint32 i = 0; i < insert_ctx->pairs_count; i++) {
        stmt->pairs_pos = i;

        CTSQL_SAVE_STACK(stmt);
        status = is_batch ? sql_prepare_batch_insert(stmt, cursor, insert_ctx, knl_cur, NULL) :
                            sql_insert_single_row(stmt, cursor, insert_ctx, dc, knl_cur, NULL);
        CTSQL_RESTORE_STACK(stmt);

        if (status != CT_SUCCESS) {
            status = sql_insert_try_ignore(insert_ctx);
            if (status == CT_SUCCESS) {
                continue;
            }
            break;
        }

        if (!is_batch) {
            cursor->total_rows++;
        }
    }
    if (status == CT_SUCCESS && is_batch) {
        status = sql_batch_insert_rows(stmt, cursor, knl_cur);
    }

    return status;
}

status_t sql_execute_insert_plan(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_insert_t *insert_ctx)
{
    status_t status = CT_SUCCESS;
    knl_dictionary_t *dc = &cursor->tables[0].table->entry->dc;
    knl_cursor_t *knl_cursor = cursor->tables[0].knl_cur;
    bool32 table_nologging_enabled = knl_table_nologging_enabled(dc->handle);
    if (stmt->context->type == CTSQL_TYPE_INSERT && (stmt->session->nologging_enable || table_nologging_enabled)) {
        if (!DB_IS_SINGLE(&stmt->session->knl_session) ||
            (DB_IS_RCY_CHECK_PCN(&stmt->session->knl_session) && stmt->session->nologging_enable)) {
            CT_LOG_DEBUG_WAR("forbid to nologging load when database in HA mode or \
                when _RCY_CHECK_PCN is TRUE on session_level nologging insert");
            knl_cursor->logging = CT_TRUE;
            knl_cursor->nologging_type = LOGGING_LEVEL;
            stmt->session->knl_session.rm->logging = CT_TRUE;
            stmt->session->knl_session.rm->nolog_type = knl_cursor->nologging_type;
        } else {
            knl_cursor->logging = CT_FALSE;
            stmt->session->knl_session.rm->logging = CT_FALSE;
            knl_cursor->nologging_type = knl_table_nologging_enabled(dc->handle) ? TABLE_LEVEL : SESSION_LEVEL;
            stmt->session->knl_session.rm->nolog_type = knl_cursor->nologging_type;
        }
    } else {
        knl_cursor->logging = CT_TRUE;
        stmt->session->knl_session.rm->logging = CT_TRUE;
        knl_cursor->nologging_type = LOGGING_LEVEL;
        stmt->session->knl_session.rm->nolog_type = knl_cursor->nologging_type;
    }

    CT_RETURN_IFERR(knl_open_cursor(&stmt->session->knl_session, knl_cursor, dc));
    CT_RETURN_IFERR(sql_push(stmt, CT_MAX_ROW_SIZE, (void **)&knl_cursor->row));

    sql_prepare_scan(stmt, dc, knl_cursor);

    if (CT_BIT_TEST(insert_ctx->syntax_flag, INSERT_IS_ALL)) {
        status = sql_execute_insert_all(stmt, cursor, insert_ctx, dc, knl_cursor);
    } else if (insert_ctx->select_ctx != NULL) {
        status = sql_execute_insert_select_plan(stmt, cursor, insert_ctx, dc, knl_cursor);
    } else {
        if (stmt->is_batch_insert) {
            status = sql_execute_batch_insert(stmt, cursor, insert_ctx, knl_cursor);
        } else {
            status = sql_execute_insert_pairs(stmt, cursor, insert_ctx, dc, knl_cursor);
        }
    }

    CTSQL_POP(stmt);

    stmt->default_column = NULL;
    return status;
}

status_t sql_execute_insert_with_ctx(sql_stmt_t *stmt, sql_insert_t *insert_ctx)
{
    sql_cursor_t *cursor = CTSQL_ROOT_CURSOR(stmt);
    status_t status;

    cursor->scn = CT_INVALID_ID64;

    CT_RETURN_IFERR(sql_execute_insert_triggers(stmt, insert_ctx->table, TRIG_BEFORE_STATEMENT, NULL, NULL));

    // set statement ssn after the before statement triggers executed
    sql_set_scn(stmt);
    sql_set_ssn(stmt);

    CT_RETURN_IFERR(sql_open_insert_cursor(stmt, cursor, insert_ctx));
    status = sql_execute_insert_plan(stmt, cursor, insert_ctx);
    stmt->session->knl_session.rm->logging = CT_TRUE;
    CT_RETURN_IFERR(status);
    CT_RETURN_IFERR(sql_execute_insert_triggers(stmt, insert_ctx->table, TRIG_AFTER_STATEMENT, NULL, NULL));

    stmt->eof = CT_TRUE;
    cursor->eof = CT_TRUE;
    return CT_SUCCESS;
}

static status_t sql_execute_insert_core(sql_stmt_t *stmt)
{
    uint64 conflicts = 0;
    /*
     * reset index conflicts to 0, and check it after stmt
     * to see if unique constraints violated.
     */
    knl_init_index_conflicts(KNL_SESSION(stmt), &conflicts);
    CT_RETURN_IFERR(sql_execute_insert_with_ctx(stmt, (sql_insert_t *)stmt->context->entry));
    return knl_check_index_conflicts(KNL_SESSION(stmt), conflicts);
}

status_t sql_execute_insert(sql_stmt_t *stmt)
{
    status_t status = CT_ERROR;
    knl_savepoint_t savepoint;

    do {
        knl_savepoint(KNL_SESSION(stmt), &savepoint);
        status = sql_execute_insert_core(stmt);
        // execute dml failed when shrink table, need restart
        if (status == CT_ERROR && cm_get_error_code() == ERR_NEED_RESTART) {
            CT_LOG_RUN_INF("insert failed when shrink table, inset restart");
            cm_reset_error();
            knl_rollback(KNL_SESSION(stmt), &savepoint);
            sql_set_scn(stmt);
            continue;
        } else {
            break;
        }
    } while (CT_TRUE);

    return status;
}

status_t sql_calc_part_print(sql_stmt_t *stmt, char *buf, uint32 size)
{
    uint32 i;
    uint32 part_id = CT_INVALID_ID32;
    sql_insert_t *insert = (sql_insert_t *)stmt->context->entry;
    char *left_buffer = buf;
    char *flag_buffer = (char *)"...)";
    uint32 flag_len = (uint32)strlen(flag_buffer);
    uint32 left_size = size - (flag_len + 1);
    int32 offset;
    part_key_t *key = NULL;
    knl_dictionary_t *dc = &insert->table->entry->dc;
    insert_assist_t ass;

    if (insert->select_ctx != NULL) {
        PRTS_RETURN_IFERR(snprintf_s(buf, size, size - 1, "(Filter:N/A)"));
        return CT_SUCCESS;
    }

    if (size <= (flag_len + 1)) {
        return CT_SUCCESS;
    }

    offset = snprintf_s(left_buffer, left_size, left_size - 1, "(Filter:id=");
    if (offset < 0) {
        return CT_SUCCESS;
    } else {
        left_buffer = left_buffer + offset;
        left_size -= offset;
        if (left_size - 1 == 0) {
            return CT_SUCCESS;
        }
    }
    CTSQL_SAVE_STACK(stmt);
    CT_RETURN_IFERR(sql_push(stmt, CT_MAX_COLUMN_SIZE, (void **)&key));
    sql_init_insert_assist(&ass, NULL, insert, NULL);
    for (i = 0; i < insert->pairs_count; i++) {
        stmt->pairs_pos = i;
        if (sql_calc_part_for_insert(stmt, key, &part_id, &ass) != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            return CT_ERROR;
        }
        if (part_id == CT_INVALID_ID32) {
            offset = snprintf_s(left_buffer, left_size, left_size - 1, ((i == 0) ? "N/A" : ",N/A"));
        } else {
            if (knl_verify_interval_part(dc->handle, part_id) &&
                knl_create_interval_part(&stmt->session->knl_session, dc, part_id, key) != CT_SUCCESS) {
                CTSQL_RESTORE_STACK(stmt);
                return CT_ERROR;
            }
            offset = snprintf_s(left_buffer, left_size, left_size - 1, ((i == 0) ? "%u" : ",%u"), part_id);
        }

        if (offset < 0) {
            break;
        } else {
            left_buffer = left_buffer + offset;
            left_size -= offset;
            if (left_size - 1 == 0) {
                break;
            }
        }
    }
    CTSQL_RESTORE_STACK(stmt);
    left_size += flag_len;
    offset = snprintf_s(left_buffer, left_size, left_size - 1,
        (insert->pairs_count > 1 && i < insert->pairs_count) ? flag_buffer : ")");
    if (offset < 0) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, offset);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_prepare_view_row_insteadof(sql_stmt_t *stmt, sql_table_cursor_t *tab_cursor, knl_cursor_t *knl_cursor)
{
    rs_column_t *rs_column = NULL;
    variant_t value;
    sql_cursor_t *cursor = tab_cursor->sql_cur;
    sql_table_t *table = tab_cursor->table;
    row_assist_t ra;
    knl_column_t *knl_col = NULL;
    status_t status;
    knl_dictionary_t *dc = &table->entry->dc;
    uint32 col_count = knl_get_column_count(dc->handle);

    row_init(&ra, (char *)knl_cursor->row, CT_MAX_ROW_SIZE, cursor->columns->count);
    CT_RETURN_IFERR(SQL_CURSOR_PUSH(stmt, cursor));
    for (uint32 i = 0; i < col_count; i++) {
        rs_column = (rs_column_t *)cm_galist_get(cursor->columns, i);
        if (rs_column->type == RS_COL_COLUMN) {
            status = sql_get_table_value(stmt, &rs_column->v_col, &value);
        } else {
            status = sql_exec_expr(stmt, rs_column->expr, &value);
        }

        if (status != CT_SUCCESS) {
            SQL_CURSOR_POP(stmt);
            return CT_ERROR;
        }

        knl_col = knl_get_column(dc->handle, i);
        if (sql_set_table_value(stmt, knl_cursor, &ra, knl_col, &value) != CT_SUCCESS) {
            SQL_CURSOR_POP(stmt);
            return CT_ERROR;
        }
    }
    knl_cursor->rowid = cursor->tables[0].knl_cur->rowid;
    cm_decode_row((char *)knl_cursor->row, knl_cursor->offsets, knl_cursor->lens, NULL);
    SQL_CURSOR_POP(stmt);
    return CT_SUCCESS;
}

status_t sql_execute_insteadof_triggers_core(sql_stmt_t *stmt, trig_set_t *set, void *knl_cur, void *data,
    trig_dml_type_t dml_type)
{
    pl_dc_t pl_dc;
    trig_item_t *trig_item = NULL;
    trig_desc_t *trig_desc = NULL;

    CTSQL_SAVE_STACK(stmt);
    for (uint32 i = 0; i < set->trig_count; ++i) {
        trig_item = &set->items[i];
        if (!trig_item->trig_enable) {
            continue;
        }

        if ((uint32)trig_item->trig_type != TRIG_INSTEAD_OF || (trig_item->trig_event & dml_type) == 0) {
            continue;
        }

        CT_BREAK_IF_ERROR(pl_dc_open_trig_by_entry(stmt, &pl_dc, trig_item));

        trig_desc = &pl_dc.entity->trigger->desc;
        if (dml_type == TRIG_EVENT_UPDATE) {
            upd_object_t *obj = data;
            if (!sql_find_trigger_column(obj->pairs, &trig_desc->columns)) {
                pl_dc_close(&pl_dc);
                continue;
            }
        }

        if (ple_exec_trigger(stmt, (void *)pl_dc.entity, dml_type, knl_cur, data) != CT_SUCCESS) {
            ple_check_exec_trigger_error(stmt, pl_dc.entity);
            pl_dc_close(&pl_dc);
            CTSQL_RESTORE_STACK(stmt);
            return CT_ERROR;
        }

        pl_dc_close(&pl_dc);
    }
    CTSQL_RESTORE_STACK(stmt);
    return CT_SUCCESS;
}


status_t sql_insteadof_triggers(sql_stmt_t *stmt, sql_table_t *table, void *knl_cur, void *data,
    trig_dml_type_t dml_type)
{
    knl_dictionary_t *dc = &table->entry->dc;
    dc_entity_t *dc_entity = (dc_entity_t *)dc->handle;
    dc_entry_t *dc_entry = dc_entity->entry;
    bool8 __logging;
    status_t status;

    if (stmt->session->triggers_disable) {
        return CT_SUCCESS;
    }

    if (dc_entity->trig_set.trig_count == 0) {
        return CT_SUCCESS;
    }

    /* add TS lock, controls trigger concurrency */
    if (lock_table_shared(KNL_SESSION(stmt), dc_entity, LOCK_INF_WAIT) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!dc_entry_visible(dc_entry, dc)) {
        CT_THROW_ERROR(ERR_INVALID_DC, T2S(&table->name.value));
        return CT_ERROR;
    }

    /* do not support nologging in triggers */
    __logging = stmt->session->knl_session.rm->logging;
    stmt->session->knl_session.rm->logging = CT_TRUE;

    status = sql_execute_insteadof_triggers_core(stmt, &dc_entity->trig_set, knl_cur, data, dml_type);

    stmt->session->knl_session.rm->logging = __logging;
    return status;
}
