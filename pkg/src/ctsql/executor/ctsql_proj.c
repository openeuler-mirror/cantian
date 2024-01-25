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
 * ctsql_proj.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/executor/ctsql_proj.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_proj.h"
#include "ctsql_scan.h"
#include "srv_instance.h"
#include "pl_executor.h"


status_t sql_get_rs_table_val(sql_stmt_t *stmt, rs_column_t *rs_col, variant_t *value)
{
    return sql_get_table_value(stmt, &rs_col->v_col, value);
}

status_t sql_get_rs_expr_val(sql_stmt_t *stmt, rs_column_t *rs_col, variant_t *value)
{
    return sql_exec_expr(stmt, rs_col->expr, value);
}

typedef status_t (*sql_get_rs_val_t)(sql_stmt_t *stmt, rs_column_t *rs_col, variant_t *value);

// function index match 'rs_column_type_t'
static sql_get_rs_val_t g_rs_val_func[] = { NULL, sql_get_rs_expr_val, sql_get_rs_table_val };

ct_type_t sql_make_pending_column_def(sql_stmt_t *stmt, char *pending_buf, ct_type_t type, uint32 col_id,
    variant_t *value)
{
    uint32 count;
    ct_type_t *types = NULL;

    if (pending_buf == NULL) {
        return CT_TYPE_VARCHAR;
    }

    count = (*(uint32 *)pending_buf - PENDING_HEAD_SIZE) / sizeof(ct_type_t);
    if (col_id >= count) {
        return CT_TYPE_VARCHAR;
    }

    types = (ct_type_t *)(pending_buf + PENDING_HEAD_SIZE);
    if (types[col_id] == CT_TYPE_UNKNOWN) {
        types[col_id] = (value->type == CT_TYPE_UNKNOWN) ? CT_TYPE_VARCHAR : value->type;
        if (types[col_id] == CT_TYPE_ARRAY) {
            types[col_id] = value->v_array.type;
        }
    }

    return types[col_id];
}

static status_t sql_send_value_type(sql_stmt_t *stmt, variant_t *value)
{
    switch (value->type) {
        case CT_TYPE_UINT32:
            return my_sender(stmt)->send_column_uint32(stmt, VALUE(uint32, value));

        case CT_TYPE_INTEGER:
            return my_sender(stmt)->send_column_int32(stmt, VALUE(int32, value));

        case CT_TYPE_BIGINT:
            return my_sender(stmt)->send_column_int64(stmt, VALUE(int64, value));

        case CT_TYPE_REAL:
            return my_sender(stmt)->send_column_real(stmt, VALUE(double, value));

        case CT_TYPE_DATE:
            return my_sender(stmt)->send_column_date(stmt, VALUE(date_t, value));

        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
            return my_sender(stmt)->send_column_ts(stmt, VALUE(date_t, value));

        case CT_TYPE_TIMESTAMP_LTZ:
            return my_sender(stmt)->send_column_tsltz(stmt, VALUE(timestamp_ltz_t, value));

        case CT_TYPE_TIMESTAMP_TZ:
            return my_sender(stmt)->send_column_tstz(stmt, VALUE_PTR(timestamp_tz_t, value));

        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
        case CT_TYPE_STRING:
            return my_sender(stmt)->send_column_text(stmt, VALUE_PTR(text_t, value));

        case CT_TYPE_CLOB:
        case CT_TYPE_IMAGE:
            return my_sender(stmt)->send_column_clob(stmt, VALUE_PTR(var_lob_t, value));

        case CT_TYPE_BLOB:
            return my_sender(stmt)->send_column_blob(stmt, VALUE_PTR(var_lob_t, value));

        case CT_TYPE_BINARY:
        case CT_TYPE_VARBINARY:
            return my_sender(stmt)->send_column_bin(stmt, VALUE_PTR(binary_t, value));
        case CT_TYPE_RAW:
            return my_sender(stmt)->send_column_raw(stmt, VALUE_PTR(binary_t, value));

        case CT_TYPE_NUMBER:
        case CT_TYPE_DECIMAL:
            return my_sender(stmt)->send_column_decimal(stmt, VALUE_PTR(dec8_t, value));
        case CT_TYPE_NUMBER2:
            return my_sender(stmt)->send_column_decimal2(stmt, VALUE_PTR(dec8_t, value));

        case CT_TYPE_BOOLEAN:
            return my_sender(stmt)->send_column_bool(stmt, VALUE(bool32, value));

        case CT_TYPE_INTERVAL_YM:
            return my_sender(stmt)->send_column_ymitvl(stmt, VALUE(interval_ym_t, value));

        case CT_TYPE_INTERVAL_DS:
            return my_sender(stmt)->send_column_dsitvl(stmt, VALUE(interval_ds_t, value));

        case CT_TYPE_CURSOR:
            return my_sender(stmt)->send_column_null(stmt, CT_TYPE_CURSOR);

        case CT_TYPE_ARRAY:
            return my_sender(stmt)->send_column_array(stmt, VALUE_PTR(var_array_t, value));

        default:
            break;
    }
    return CT_SUCCESS;
}

status_t sql_send_value(sql_stmt_t *stmt, char *pending_buf, ct_type_t temp_type, typmode_t *typmod, variant_t *value)
{
    // try make pending column definition when project column
    ct_type_t type = temp_type;
    if (type == CT_TYPE_UNKNOWN) {
        type = sql_make_pending_column_def(stmt, pending_buf, type, stmt->ra.col_id, value);
    }

    if (value->is_null) {
        return my_sender(stmt)->send_column_null(stmt, (uint32)type);
    }

    if ((value->type != type) && (my_sender(stmt) != sql_get_pl_sender())) {
        if (typmod->is_array == CT_TRUE) {
            if (typmod->datatype != CT_TYPE_UNKNOWN) {
                CT_RETURN_IFERR(sql_convert_to_array(stmt, value, typmod, CT_FALSE));
            }
        } else {
            CT_RETURN_IFERR(sql_convert_variant(stmt, value, type));
        }
    }

    return sql_send_value_type(stmt, value);
}

status_t sql_send_column(sql_stmt_t *stmt, sql_cursor_t *cursor, rs_column_t *rs_col, variant_t *value)
{
    sql_table_cursor_t *tab_cursor = NULL;

    cursor = CTSQL_CURR_CURSOR(stmt);

    tab_cursor = &cursor->tables[rs_col->v_col.tab];

    if (CT_IS_SUBSELECT_TABLE(tab_cursor->table->type)) {
        return sql_get_col_rs_value(stmt, tab_cursor->sql_cur, rs_col->v_col.col, &rs_col->v_col, value);
    } else {
        return sql_get_ddm_kernel_value(stmt, tab_cursor->table, tab_cursor->knl_cur, &rs_col->v_col, value);
    }
}

status_t sql_send_calc_column(sql_stmt_t *stmt, rs_column_t *rs_col, variant_t *value)
{
    sql_stmt_t *sub_stmt = NULL;

    value->is_null = CT_TRUE;

    if (sql_exec_expr(stmt, rs_col->expr, value) != CT_SUCCESS) {
        return CT_ERROR;
    }

    /* If the return type is cursor, send the cursor id to client. */
    if (value->type == CT_TYPE_CURSOR) {
        sub_stmt = ple_ref_cursor_get(stmt, (pl_cursor_slot_t *)value->v_cursor.ref_cursor);
        if (sub_stmt == NULL || (sub_stmt->cursor_info.has_fetched && sub_stmt->eof)) {
            CT_THROW_ERROR(ERR_INVALID_CURSOR);
            return CT_ERROR;
        }
        sub_stmt->cursor_info.is_returned = CT_TRUE;
        sub_stmt->cursor_info.rrs_sn = stmt->session->rrs_sn;
        sub_stmt->is_sub_stmt = CT_FALSE;
        CT_RETURN_IFERR(g_instance->sql.pl_sender.send_return_result(stmt, sub_stmt->id));
    }

    return CT_SUCCESS;
}

static void sql_free_array_vm_list(sql_stmt_t *stmt, sql_cursor_t *cursor)
{
    for (uint32 i = 0; i < cursor->columns->count; i++) {
        if (stmt->vm_lob_ids[i].entry_vmid == CT_INVALID_ID32) {
            break;
        }
        sql_free_array_vm(stmt, stmt->vm_lob_ids[i].entry_vmid, stmt->vm_lob_ids[i].last_vmid);
    }
    stmt->vm_lob_ids = NULL;
}

status_t sql_send_row(sql_stmt_t *stmt, sql_cursor_t *cursor, bool32 *is_full)
{
    uint32 i;
    rs_column_t *rs_column = NULL;
    vm_lob_id_t *vm_lob_ids = NULL;
    variant_t value;

    sql_cursor_t *tmp_cursor = sql_get_proj_cursor(cursor);
    uint32 mem_size = sizeof(vm_lob_id_t) * tmp_cursor->columns->count;

    CT_RETURN_IFERR(sql_push(stmt, mem_size, (void **)&vm_lob_ids));
    MEMS_RETURN_IFERR(memset_s(vm_lob_ids, mem_size, 0xFF, mem_size));
    stmt->vm_lob_ids = vm_lob_ids;

    SQL_CURSOR_PUSH(stmt, tmp_cursor);

    CT_RETURN_IFERR(my_sender(stmt)->send_row_begin(stmt, tmp_cursor->columns->count));

    for (i = 0; i < tmp_cursor->columns->count; i++) {
        rs_column = (rs_column_t *)cm_galist_get(tmp_cursor->columns, i);
        if (rs_column->type == RS_COL_COLUMN) {
            CT_RETURN_IFERR(sql_send_column(stmt, tmp_cursor, rs_column, &value));
        } else {
            CT_RETURN_IFERR(sql_send_calc_column(stmt, rs_column, &value));
        }

        CT_RETURN_IFERR(sql_send_value(stmt, tmp_cursor->mtrl.rs.buf, rs_column->datatype, &rs_column->typmod, &value));
    }

    SQL_CURSOR_POP(stmt);

    CT_RETURN_IFERR(my_sender(stmt)->send_row_end(stmt, is_full));
    sql_inc_rows(stmt, cursor);
    sql_free_array_vm_list(stmt, tmp_cursor);
    CTSQL_POP(stmt);
    return CT_SUCCESS;
}

status_t sql_send_ori_row(sql_stmt_t *stmt, sql_cursor_t *cursor, bool32 *is_full)
{
    sql_table_cursor_t *tab_cursor = &cursor->tables[0];
    sql_table_t *sql_table = tab_cursor->table;
    knl_cursor_t *knl_cur = tab_cursor->knl_cur;

    if (sql_table->has_hidden_columns || IS_INDEX_ONLY_SCAN(knl_cur) || knl_cur->row->is_csf || sql_is_pl_exec(stmt)) {
        return sql_send_row(stmt, cursor, is_full);
    }

    char *pack_buffer = NULL;
    uint32 ack_offset;
    uint32 row_size = cm_get_row_size((char *)(knl_cur->row));
    cs_packet_t *send_pack = stmt->session->send_pack;

    CT_RETURN_IFERR(cs_reserve_space(send_pack, row_size, &ack_offset));
    pack_buffer = (char *)CS_RESERVE_ADDR(send_pack, ack_offset);

    MEMS_RETURN_IFERR(memcpy_s(pack_buffer, CT_MAX_ROW_SIZE, knl_cur->row, row_size));

    *is_full = sql_send_check_is_full(stmt);
    stmt->session->stat.fetched_rows++;

    sql_inc_rows(stmt, cursor);

    return CT_SUCCESS;
}

status_t sql_send_return_row(sql_stmt_t *stmt, galist_t *ret_columns, bool8 gen_null)
{
    uint32 i;
    query_column_t *ret_col = NULL;
    variant_t value;
    bool32 is_full = CT_FALSE;

    if (stmt->plsql_mode != PLSQL_STATIC && stmt->plsql_mode != PLSQL_DYNSQL) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "unexpected returning columns occurs");
        return CT_ERROR;
    }

    pl_executor_t *exec = (pl_executor_t *)stmt->pl_exec;
    pl_line_sql_t *sql = (pl_line_sql_t *)exec->curr_line;
    pl_into_t *into = &sql->into;

    if (into->is_bulk == CT_FALSE && stmt->batch_rows > 0) {
        CT_THROW_ERROR(ERR_INVALID_OPERATION, ", exact fetch returns more than requested number of rows");
        return CT_ERROR;
    }

    if (into->is_bulk && gen_null) {
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(my_sender(stmt)->send_row_begin(stmt, ret_columns->count));

    for (i = 0; i < ret_columns->count; i++) {
        ret_col = (query_column_t *)cm_galist_get(ret_columns, i);
        if (gen_null) {
            value.type = ret_col->expr->root->datatype;
            value.is_null = CT_TRUE;
        } else {
            CT_RETURN_IFERR(sql_exec_expr(stmt, ret_col->expr, &value));
        }
        CT_RETURN_IFERR(my_sender(stmt)->send_return_value(stmt, ret_col->expr->root->datatype,
            &ret_col->expr->root->typmod, &value));
    }

    CT_RETURN_IFERR(my_sender(stmt)->send_row_end(stmt, &is_full));
    stmt->batch_rows++;

    return CT_SUCCESS;
}

/*
 * NOTES: return generated keys can't beyond packet size(64K), one generated key occupy 16B.
 * It has 2 problems:
 * 1)if insert .. select .. occurs many rows, response packet can't store all generated keys, it will discard left keys;
 * 2)if insert .. values .. execute batch, when one batch bind param less than 16B,
 * the response packet will alse have no enough space to store all generated keys;
 * example: insert into t1 (f_int2) values (?); the bind params occupy the whole request packet,
 * then the reponse packet will have no
 * enough space to store generated keys.
 *
 * need to materialize generated keys (can't sort) to resolve these two problems!
 */
status_t sql_send_generated_key_row(sql_stmt_t *stmt, int64 *serial_val)
{
    if (!stmt->return_generated_key) {
        return CT_SUCCESS;
    }

    if (stmt->context->type != CTSQL_TYPE_INSERT && stmt->context->type != CTSQL_TYPE_MERGE) {
        return CT_SUCCESS;
    }

    bool32 is_full = sql_send_check_is_full(stmt);
    bool32 is_full_tmp = CT_FALSE;
    if (!is_full) {
        CT_RETURN_IFERR(my_sender(stmt)->send_row_begin(stmt, 1));
        variant_t var;
        var.is_null = CT_FALSE;
        var.type = CT_TYPE_BIGINT;
        var.v_bigint = *serial_val;
        typmode_t typmod = {
            .is_array = 0
        };
        CT_RETURN_IFERR(sql_send_value(stmt, NULL, CT_TYPE_BIGINT, &typmod, &var));
        CT_RETURN_IFERR(my_sender(stmt)->send_row_end(stmt, &is_full_tmp));
        stmt->batch_rows++;
        return CT_SUCCESS;
    }

    return CT_SUCCESS;
}

status_t sql_get_rs_value(sql_stmt_t *stmt, sql_cursor_t *cursor, uint32 id, variant_t *value)
{
    status_t status;
    rs_column_t *rs_col = NULL;

    /* get value from par cursor */
    cursor = sql_get_proj_cursor(cursor);
    if (cursor->eof) {
        // when cursor is eof, cursor->columns perhaps is NULL.
        if (cursor->columns != NULL) {
            rs_col = (rs_column_t *)cm_galist_get(cursor->columns, id);
        }

        value->type = (rs_col != NULL && rs_col->datatype != CT_TYPE_UNKNOWN) ? rs_col->datatype : CT_TYPE_STRING;
        value->is_null = CT_TRUE;
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(SQL_CURSOR_PUSH(stmt, cursor));
    rs_col = (rs_column_t *)cm_galist_get(cursor->columns, id);
    status = g_rs_val_func[rs_col->type](stmt, rs_col, value);
    SQL_CURSOR_POP(stmt);

    return status;
}

status_t sql_get_col_rs_value(sql_stmt_t *stmt, sql_cursor_t *cursor, uint16 col, var_column_t *v_col, variant_t *value)
{
    variant_t tmp_var;

    if (sql_get_rs_value(stmt, cursor, col, value) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (value->type == CT_TYPE_ARRAY && v_col->ss_start > 0) {
        tmp_var = *value;
        return sql_get_subarray_by_col(stmt, v_col, &tmp_var, value);
    }

    return CT_SUCCESS;
}
