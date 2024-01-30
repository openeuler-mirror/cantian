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
 * pl_context.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/pl_context.c
 *
 * -------------------------------------------------------------------------
 */

#include "pl_context.h"
#include "pl_executor.h"
#include "pl_compiler.h"
#include "ctsql_proj.h"
#include "ctsql_mtrl.h"
#include "srv_instance.h"
#include "pl_udt.h"

#define PL_TYPE_NUM (PL_ANONYMOUS_BLOCK + 1)
text_t g_pl_type_name[PL_TYPE_NUM] = {
    { "PROCEDURE", 9 },
    { "FUNCTION",  8 },
    { "PACKAGE",  7 },
    { "PACKAGE BODY",  12 },
    { "TRIGGER",   7 },
    { "",          0 },
};

void pl_init_sender(session_t *session) {}

status_t pl_send_result_success(session_t *session)
{
    return CT_SUCCESS;
}

status_t pl_send_result_error(session_t *session)
{
    return CT_SUCCESS;
}

void pl_init_sender_row(sql_stmt_t *stmt, char *buffer, uint32 size, uint32 column_count) {}

status_t pl_send_parsed_stmt(sql_stmt_t *stmt)
{
    return CT_SUCCESS;
}

status_t pl_send_exec_begin(sql_stmt_t *stmt)
{
    if (stmt->pl_exec) {
        CT_RETURN_IFERR(pl_send_returning_begin(stmt));
    }
    return sql_push(stmt, sizeof(cs_execute_ack_t), (void **)&stmt->exec_ack);
}

void pl_send_exec_end(sql_stmt_t *stmt)
{
    CTSQL_POP(stmt);
}

status_t pl_send_import_rows(sql_stmt_t *stmt)
{
    return CT_SUCCESS;
}

status_t pl_trim_coll(sql_stmt_t *stmt, pl_into_t *into, pl_executor_t *exec)
{
    ple_var_t *left = NULL;
    for (uint32 i = 0; i < into->output->count; i++) {
        CT_RETURN_IFERR(ple_get_output_plvar(exec, into, &left, i));

        CM_ASSERT(left->decl->type == PLV_COLLECTION);
        if (!left->value.is_null) {
            CT_RETURN_IFERR(
                g_coll_intr_method[left->value.v_collection.type][METHOD_INTR_TRIM](stmt, &left->value, NULL));
        } else {
            udt_constructor_t v_construct;
            v_construct.is_coll = CT_TRUE;
            v_construct.arg_cnt = 0;
            v_construct.meta = (void *)left->decl->collection;

            CT_RETURN_IFERR(udt_invoke_coll_construct(stmt, &v_construct, NULL, &left->value));
        }
    }

    return CT_SUCCESS;
}

status_t pl_send_returning_begin(sql_stmt_t *stmt)
{
    pl_executor_t *exec = (pl_executor_t *)stmt->pl_exec;
    pl_line_ctrl_t *line_ctrl = exec->curr_line;

    switch (line_ctrl->type) {
        case LINE_FETCH: {
            pl_line_fetch_t *sql = (pl_line_fetch_t *)line_ctrl;
            stmt->into = &sql->into;
            break;
        }
        case LINE_SQL: {
            pl_line_sql_t *sql = (pl_line_sql_t *)line_ctrl;
            stmt->into = &sql->into;
            break;
        }
        case LINE_FOR: {
            pl_line_for_t *sql = (pl_line_for_t *)line_ctrl;
            CT_RETSUC_IFTRUE(!sql->is_cur);
            stmt->into = &sql->into;
            break;
        }
        case LINE_EXECUTE: {
            pl_line_execute_t *sql = (pl_line_execute_t *)line_ctrl;
            CT_RETSUC_IFTRUE(sql->into.output == NULL || sql->into.output->count == 0);
            stmt->into = &sql->into;
            sql_stmt_t *parent = (sql_stmt_t *)stmt->parent_stmt;
            exec = (pl_executor_t *)parent->pl_exec;
            break;
        }
        default:
            return CT_SUCCESS;
    }

    pl_into_t *into = (pl_into_t *)stmt->into;
    switch ((plv_into_type_t)into->into_type) {
        case INTO_AS_COLL:
        case INTO_AS_COLL_REC:
            // returning coll to PL, vm_ctx should be parent_stmt's vm_ctx since it is stored in  parent_stmt's vm_ctx
            CM_ASSERT(stmt->parent_stmt != NULL);
            CT_RETURN_IFERR(pl_trim_coll((sql_stmt_t *)stmt->parent_stmt, into, exec));
            break;

        default:
            // INTO_AS_VALUE / INTO_AS_RECORD NO NEED TO RESET VM MEMORY
            return CT_SUCCESS;
    }
    return CT_SUCCESS;
}

status_t pl_send_fetch_begin(sql_stmt_t *stmt)
{
    CT_RETSUC_IFTRUE(stmt->context->type != CTSQL_TYPE_SELECT);
    CT_RETURN_IFERR(pl_send_returning_begin(stmt));
    return CT_SUCCESS;
}

void pl_send_fetch_end(sql_stmt_t *stmt) {}

static inline bool32 pl_send_check_is_full(sql_stmt_t *stmt)
{
    if (stmt->batch_rows + 1 >= stmt->prefetch_rows) {
        return CT_TRUE;
    }
    return CT_FALSE;
}

status_t pl_send_begin_extend_coll(sql_stmt_t *stmt, pl_executor_t *exec, pl_into_t *into, uint32 column_count)
{
    ple_var_t *left = NULL;
    sql_stmt_t *parent_stmt = NULL;
    // Cursor's stmt and outer PL stmt are mutually independent. When passing params from cursor to PL variants,
    // we need pass the outer vm_ctx to save the complex variants.
    CM_ASSERT(stmt->parent_stmt != NULL);
    parent_stmt = (sql_stmt_t *)stmt->parent_stmt;

    for (uint32 i = 0; i < column_count; i++) {
        CT_RETURN_IFERR(ple_get_output_plvar(exec, into, &left, i));
        CM_ASSERT(left->decl->type == PLV_COLLECTION);

        if (left->decl->collection->type != UDT_HASH_TABLE) {
            if (left->decl->collection->attr_type != UDT_SCALAR) {
                CT_THROW_ERROR(ERR_RESULT_NOT_MATCH);
                return CT_ERROR;
            }
            CT_RETURN_IFERR(g_coll_methods[left->value.v_collection.type][METHOD_EXTEND].invoke(parent_stmt,
                &left->value, NULL, NULL));
        }
    }
    return CT_SUCCESS;
}

status_t pl_send_begin_extend_coll_rec(sql_stmt_t *stmt, pl_executor_t *exec, pl_into_t *pl_into)
{
    ple_var_t *left = NULL;
    sql_stmt_t *parent_stmt = NULL;
    plv_collection_t *coll_meta = NULL;
    mtrl_rowid_t row_id = g_invalid_entry;

    CM_ASSERT(stmt->parent_stmt != NULL);
    parent_stmt = (sql_stmt_t *)stmt->parent_stmt;
    CT_RETURN_IFERR(ple_get_output_plvar(exec, pl_into, &left, 0));

    coll_meta = left->value.v_collection.coll_meta;
    if (left->decl->collection->type != UDT_HASH_TABLE) {
        CT_RETURN_IFERR(
            g_coll_methods[left->value.v_collection.type][METHOD_EXTEND].invoke(parent_stmt, &left->value, NULL, NULL));
    }
    /* anonymous record type can not assigned to global record */
    CT_RETURN_IFERR(udt_record_alloc_mtrl_head(parent_stmt, UDT_GET_TYPE_DEF_RECORD(coll_meta->elmt_type), &row_id));
    MAKE_REC_VAR(&left->temp, coll_meta->elmt_type, row_id);
    left->temp.v_record.is_constructed = CT_TRUE;
    return CT_SUCCESS;
}

status_t pl_send_row_begin(sql_stmt_t *stmt, uint32 column_count)
{
    pl_into_t *pl_into = (pl_into_t *)stmt->into;
    pl_executor_t *exec = (pl_executor_t *)stmt->pl_exec;
    stmt->ra.col_id = 0;
    if (!IS_DML_INTO_PL_VAR(stmt->context->type) || stmt->context->rs_columns == NULL || pl_into == NULL || exec == NULL) {
        return CT_SUCCESS;
    }

    if (exec->curr_line->type == LINE_EXECUTE) {
        sql_stmt_t *parent = (sql_stmt_t *)stmt->parent_stmt;
        exec = (pl_executor_t *)parent->pl_exec;
    }

    switch ((plv_into_type_t)pl_into->into_type) {
        case INTO_AS_COLL:
            if (pl_send_begin_extend_coll(stmt, exec, pl_into, column_count) != CT_SUCCESS) {
                return CT_ERROR;
            }
            break;
        case INTO_AS_COLL_REC:
            if (pl_send_begin_extend_coll_rec(stmt, exec, pl_into) != CT_SUCCESS) {
                return CT_ERROR;
            }
            break;
        default:
            return CT_SUCCESS;
    }
    return CT_SUCCESS;
}

status_t pl_send_end_coll_rec(sql_stmt_t *stmt, pl_executor_t *exec, pl_into_t *pl_into)
{
    ple_var_t *left = NULL;
    sql_stmt_t *parent_stmt = NULL;
    variant_t index;

    CM_ASSERT(stmt->parent_stmt != NULL);
    parent_stmt = (sql_stmt_t *)stmt->parent_stmt;
    CT_RETURN_IFERR(ple_get_output_plvar(exec, pl_into, &left, 0));
    index.is_null = CT_FALSE;
    index.type = CT_TYPE_INTEGER;
    index.v_int = stmt->batch_rows + 1;
    return udt_coll_elemt_address(parent_stmt, &left->value, &index, NULL, &left->temp);
}

status_t pl_send_row_end(sql_stmt_t *stmt, bool32 *is_full)
{
    pl_into_t *pl_into = (pl_into_t *)stmt->into;
    pl_executor_t *exec = (pl_executor_t *)stmt->pl_exec;
    *is_full = pl_send_check_is_full(stmt);
    stmt->session->stat.fetched_rows++;

    if (!IS_DML_INTO_PL_VAR(stmt->context->type) || stmt->context->rs_columns == NULL || pl_into == NULL || exec == NULL) {
        return CT_SUCCESS;
    }

    if (exec->curr_line->type == LINE_EXECUTE) {
        sql_stmt_t *parent = (sql_stmt_t *)stmt->parent_stmt;
        exec = (pl_executor_t *)parent->pl_exec;
    }

    if ((plv_into_type_t)pl_into->into_type == INTO_AS_COLL_REC) {
        CT_RETURN_IFERR(pl_send_end_coll_rec(stmt, exec, pl_into));
    }

    return CT_SUCCESS;
}

static status_t pl_column2var(sql_stmt_t *stmt, variant_t *right)
{
    pl_into_t *pl_into = (pl_into_t *)stmt->into;
    pl_executor_t *exec = (pl_executor_t *)stmt->pl_exec;

    if (!IS_DML_INTO_PL_VAR(stmt->context->type) || stmt->context->rs_columns == NULL || pl_into == NULL || exec == NULL) {
        return CT_SUCCESS;
    }

    if (exec->curr_line->type == LINE_EXECUTE) {
        sql_stmt_t *parent = (sql_stmt_t *)stmt->parent_stmt;
        exec = (pl_executor_t *)parent->pl_exec;
    }

    CTSQL_SAVE_STACK(stmt);
    sql_keep_stack_variant(stmt, right);

    status_t status = CT_ERROR;
    switch ((plv_into_type_t)pl_into->into_type) {
        case INTO_AS_VALUE:
            status = udt_into_as_value(stmt, pl_into, exec, right);
            break;

        case INTO_AS_COLL:
            status = udt_into_as_coll(stmt, pl_into, exec, right);
            break;

        case INTO_AS_REC:
            status = udt_into_as_record(stmt, pl_into, exec, right);
            break;

        case INTO_AS_COLL_REC:
            status = udt_into_as_coll_rec(stmt, pl_into, exec, right);
            break;

        default:
            CT_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "unexpect into type");
            break;
    }
    CTSQL_RESTORE_STACK(stmt);
    return status;
}

status_t pl_send_row_entire(sql_stmt_t *stmt, char *row, bool32 *is_full)
{
    uint8 bits;
    bool8 is_array = CT_FALSE;
    row_assist_t ra;

    cm_attach_row(&ra, row);

    // sql_push is used in pl_send_row_begin
    CT_RETURN_IFERR(pl_send_row_begin(stmt, ROW_COLUMN_COUNT(ra.head)));

    for (uint16 i = 0; i < ROW_COLUMN_COUNT(ra.head); i++) {
        rs_column_t *rs_column = (rs_column_t *)cm_galist_get(stmt->context->rs_columns, i);
        sql_cursor_t *sql_cursor = CTSQL_CURR_CURSOR(stmt);
        sql_mtrl_handler_t *mtrl_handle = &sql_cursor->mtrl;
        variant_t value;
        ct_type_t type = rs_column->datatype;
        // to print predicate information when printing execution plans
        if (stmt->lang_type == LANG_EXPLAIN &&
            sql_cursor->mtrl.cursor.rs_vmid != stmt->mtrl.segments[sql_cursor->mtrl.rs.sid]->vm_list.first) {
            type = CT_TYPE_VARCHAR;
        }
        if (type == CT_TYPE_UNKNOWN) {
            value.type = CT_TYPE_UNKNOWN;
            type = sql_make_pending_column_def(stmt, mtrl_handle->rs.buf, type, i, &value);
        }

        bits = row_get_column_bits(&ra, i);
        if (bits == COL_BITS_NULL) {
            CT_RETURN_IFERR(pl_send_column_null(stmt, (uint32)type));
        } else {
            value.is_null = CT_TRUE;
            if (mtrl_handle->cursor.row.data != NULL) {
                mtrl_row_assist_t row_assist;
                mtrl_row_init(&row_assist, &mtrl_handle->cursor.row);
                is_array = (rs_column->type == RS_COL_COLUMN) ? rs_column->v_col.is_array :
                                                                rs_column->expr->root->typmod.is_array;
                CT_RETURN_IFERR(mtrl_get_column_value(&row_assist, mtrl_handle->cursor.eof, i, type, is_array, &value));
            }
            if (pl_column2var(stmt, &value) != CT_SUCCESS) {
                return CT_ERROR;
            }
            stmt->ra.col_id++;
        }
    }

    CT_RETURN_IFERR(pl_send_row_end(stmt, is_full));
    return CT_SUCCESS;
}

status_t pl_send_column_null(sql_stmt_t *stmt, uint32 type)
{
    variant_t val;

    val.ctrl = 0;
    val.type = type;
    val.is_null = CT_TRUE;

    if (pl_column2var(stmt, &val) != CT_SUCCESS) {
        return CT_ERROR;
    }
    stmt->ra.col_id++;
    return CT_SUCCESS;
}

status_t pl_send_column_int32(sql_stmt_t *stmt, int32 v)
{
    variant_t val;

    val.ctrl = 0;
    val.type = CT_TYPE_INTEGER;
    VALUE(int32, &val) = v;

    if (pl_column2var(stmt, &val) != CT_SUCCESS) {
        return CT_ERROR;
    }
    stmt->ra.col_id++;
    return CT_SUCCESS;
}

status_t pl_send_column_uint32(sql_stmt_t *stmt, uint32 v)
{
    variant_t val;

    val.ctrl = 0;
    val.type = CT_TYPE_UINT32;
    VALUE(uint32, &val) = v;

    if (pl_column2var(stmt, &val) != CT_SUCCESS) {
        return CT_ERROR;
    }
    stmt->ra.col_id++;
    return CT_SUCCESS;
}

status_t pl_send_column_int64(sql_stmt_t *stmt, int64 v)
{
    variant_t val;

    val.ctrl = 0;
    val.type = CT_TYPE_BIGINT;
    VALUE(int64, &val) = v;

    if (pl_column2var(stmt, &val) != CT_SUCCESS) {
        return CT_ERROR;
    }
    stmt->ra.col_id++;
    return CT_SUCCESS;
}

status_t pl_send_column_dsinterval(sql_stmt_t *stmt, interval_ds_t v)
{
    variant_t val;

    val.ctrl = 0;
    val.type = CT_TYPE_INTERVAL_DS;
    VALUE(interval_ds_t, &val) = v;

    if (pl_column2var(stmt, &val) != CT_SUCCESS) {
        return CT_ERROR;
    }
    stmt->ra.col_id++;
    return CT_SUCCESS;
}

status_t pl_send_column_yminterval(sql_stmt_t *stmt, interval_ym_t v)
{
    variant_t val;

    val.ctrl = 0;
    val.type = CT_TYPE_INTERVAL_YM;
    VALUE(interval_ym_t, &val) = v;

    if (pl_column2var(stmt, &val) != CT_SUCCESS) {
        return CT_ERROR;
    }
    stmt->ra.col_id++;
    return CT_SUCCESS;
}

status_t pl_send_column_real(sql_stmt_t *stmt, double v)
{
    variant_t val;
    val.ctrl = 0;
    val.type = CT_TYPE_REAL;
    VALUE(double, &val) = v;

    if (pl_column2var(stmt, &val) != CT_SUCCESS) {
        return CT_ERROR;
    }
    stmt->ra.col_id++;
    return CT_SUCCESS;
}

status_t pl_send_column_date(sql_stmt_t *stmt, date_t v)
{
    variant_t val;
    val.ctrl = 0;
    val.type = CT_TYPE_DATE;
    VALUE(date_t, &val) = v;

    if (pl_column2var(stmt, &val) != CT_SUCCESS) {
        return CT_ERROR;
    }
    stmt->ra.col_id++;
    return CT_SUCCESS;
}

status_t pl_send_column_ts(sql_stmt_t *stmt, date_t v)
{
    variant_t val;
    val.ctrl = 0;
    val.type = CT_TYPE_TIMESTAMP;
    VALUE(timestamp_t, &val) = v;

    if (pl_column2var(stmt, &val) != CT_SUCCESS) {
        return CT_ERROR;
    }
    stmt->ra.col_id++;
    return CT_SUCCESS;
}

status_t pl_send_column_tstz(sql_stmt_t *stmt, timestamp_tz_t *v)
{
    variant_t val;
    val.ctrl = 0;
    val.type = CT_TYPE_TIMESTAMP_TZ;
    val.v_tstamp_tz.tstamp = v->tstamp;
    val.v_tstamp_tz.tz_offset = v->tz_offset;

    if (pl_column2var(stmt, &val) != CT_SUCCESS) {
        return CT_ERROR;
    }
    stmt->ra.col_id++;
    return CT_SUCCESS;
}

status_t pl_send_column_tsltz(sql_stmt_t *stmt, timestamp_ltz_t v)
{
    return pl_send_column_ts(stmt, v);
}

status_t pl_send_column_str(sql_stmt_t *stmt, char *str)
{
    variant_t val;
    val.ctrl = 0;
    val.type = CT_TYPE_STRING;
    val.v_text.str = str;
    val.v_text.len = (uint32)strlen(str);

    if (pl_column2var(stmt, &val) != CT_SUCCESS) {
        return CT_ERROR;
    }
    stmt->ra.col_id++;

    return CT_SUCCESS;
}

status_t pl_send_column_text(sql_stmt_t *stmt, text_t *text)
{
    variant_t val;
    val.ctrl = 0;
    val.type = CT_TYPE_STRING;
    val.v_text.str = text->str;
    val.v_text.len = text->len;

    if (pl_column2var(stmt, &val) != CT_SUCCESS) {
        return CT_ERROR;
    }
    stmt->ra.col_id++;

    return CT_SUCCESS;
}

status_t pl_send_column_bin(sql_stmt_t *stmt, binary_t *bin)
{
    variant_t val;

    val.ctrl = 0;
    val.type = CT_TYPE_BINARY;
    val.v_bin.bytes = bin->bytes;
    val.v_bin.size = bin->size;
    val.v_bin.is_hex_const = CT_FALSE;

    if (pl_column2var(stmt, &val) != CT_SUCCESS) {
        return CT_ERROR;
    }
    stmt->ra.col_id++;

    return CT_SUCCESS;
}

status_t pl_send_column_raw(sql_stmt_t *stmt, binary_t *bin)
{
    variant_t val;

    val.ctrl = 0;
    val.type = CT_TYPE_RAW;
    val.v_bin.bytes = bin->bytes;
    val.v_bin.size = bin->size;

    if (pl_column2var(stmt, &val) != CT_SUCCESS) {
        return CT_ERROR;
    }
    stmt->ra.col_id++;

    return CT_SUCCESS;
}

status_t pl_send_column_decimal(sql_stmt_t *stmt, dec8_t *dec)
{
    variant_t val;
    val.ctrl = 0;
    val.type = CT_TYPE_NUMBER;
    VALUE(dec8_t, &val) = (*dec);

    if (pl_column2var(stmt, &val) != CT_SUCCESS) {
        return CT_ERROR;
    }
    stmt->ra.col_id++;

    return CT_SUCCESS;
}

status_t pl_send_column_clob(sql_stmt_t *stmt, var_lob_t *bin)
{
    variant_t val;

    val.is_null = CT_FALSE;
    val.type = CT_TYPE_CLOB;
    val.v_lob = (*bin);

    if (pl_column2var(stmt, &val) != CT_SUCCESS) {
        return CT_ERROR;
    }
    stmt->ra.col_id++;

    return CT_SUCCESS;
}

status_t pl_send_column_blob(sql_stmt_t *stmt, var_lob_t *bin)
{
    variant_t val;

    val.is_null = CT_FALSE;
    val.type = CT_TYPE_BLOB;
    val.v_lob = (*bin);

    if (pl_column2var(stmt, &val) != CT_SUCCESS) {
        return CT_ERROR;
    }
    stmt->ra.col_id++;

    return CT_SUCCESS;
}

status_t pl_send_column_cursor(sql_stmt_t *stmt, cursor_t *cursor)
{
    return CT_SUCCESS;
}
status_t pl_send_column_def(sql_stmt_t *stmt, cursor_t *cursor)
{
    return CT_SUCCESS;
}

status_t pl_send_column_array(sql_stmt_t *stmt, var_array_t *v)
{
    variant_t val;

    val.is_null = CT_FALSE;
    val.type = CT_TYPE_ARRAY;
    val.v_array = *v;

    if (pl_column2var(stmt, &val) != CT_SUCCESS) {
        return CT_ERROR;
    }

    stmt->ra.col_id++;
    return CT_SUCCESS;
}

status_t pl_send_return_value(sql_stmt_t *stmt, ct_type_t type, typmode_t *typmod, variant_t *v)
{
    CT_RETURN_IFERR(pl_column2var(stmt, v));
    stmt->ra.col_id++;
    return CT_SUCCESS;
}

status_t pl_send_nls_feedback(sql_stmt_t *stmt, nlsparam_id_t id, text_t *value)
{
    return CT_SUCCESS;
}

status_t pl_send_session_tz_feedback(sql_stmt_t *stmt, timezone_info_t client_timezone)
{
    return CT_SUCCESS;
}

static inline void pl_cs_init_packet(plc_cs_packet_t *pack, uint32 max_packet_size, uint32 options)
{
    CM_POINTER(pack);
    pack->offset = 0;
    pack->max_buf_size = max_packet_size;
    pack->buf_size = max_packet_size;
    pack->buf = pack->init_buf;
    pack->head = (cs_packet_head_t *)pack->buf;
    pack->options = options;
}

status_t pl_send_serveroutput(sql_stmt_t *stmt, text_t *output)
{
    plc_cs_packet_t send_pack;
    status_t status;
    cs_packet_t *cs_send_pack = (cs_packet_t *)&send_pack;

    if (!stmt->is_srvoutput_on || stmt->session->pipe == NULL) {
        return CT_SUCCESS;
    }

    if (CT_SUCCESS != sql_push(stmt, CT_MAX_PL_PACKET_SIZE, (void **)&send_pack.init_buf)) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)CT_MAX_PL_PACKET_SIZE, "serveroutput pack");
        return CT_ERROR;
    }

    do {
        pl_cs_init_packet(&send_pack, CT_MAX_PL_PACKET_SIZE, stmt->session->recv_pack->options);
        cs_init_set(cs_send_pack, stmt->session->call_version);
        send_pack.head->cmd = stmt->session->recv_pack->head->cmd;
        send_pack.head->result = (uint8)CT_SUCCESS;

        status = cs_put_text(cs_send_pack, output);
        CT_BREAK_IF_ERROR(status);

        send_pack.head->flags = CS_FLAG_SERVEROUPUT;
        send_pack.head->serial_number = stmt->session->recv_pack->head->serial_number;
        status = cs_call(stmt->session->pipe, cs_send_pack, cs_send_pack);
        if (stmt->session->call_version >= CS_VERSION_11) {
            stmt->session->recv_pack->head->serial_number = cs_send_pack->head->serial_number;
        }
        stmt->trace_disabled = CT_TRUE;
    } while (0);

    CTSQL_POP(stmt);

    return status;
}

/*
 * pl_send_return_result
 *
 * This function is used to send the result set cursor to the client.
 */
status_t pl_send_return_result(sql_stmt_t *stmt, uint32 stmt_id)
{
    plc_cs_packet_t send_pack;
    uint64 cursor;
    status_t status;
    cs_packet_t *cs_send_pack = (cs_packet_t *)&send_pack;

    JOB_CHECK_SESSION_RETURN_ERROR(stmt->session);
    if (CT_SUCCESS != sql_push(stmt, CT_MAX_PL_PACKET_SIZE, (void **)&send_pack.init_buf)) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)CT_MAX_PL_PACKET_SIZE, "return result pack");
        return CT_ERROR;
    }

    do {
        pl_cs_init_packet(&send_pack, CT_MAX_PL_PACKET_SIZE, stmt->session->recv_pack->options);
        cs_init_set(cs_send_pack, stmt->session->call_version);
        send_pack.head->cmd = stmt->session->recv_pack->head->cmd;
        send_pack.head->result = (uint8)CT_SUCCESS;

        // open cursor has exec sql,fetch mode must be 2
        cursor = ((uint64)stmt_id << 32) + (uint64)CS_FETCH_WITH_PREP; // not overflow
        status = cs_put_int64(cs_send_pack, cursor);
        CT_BREAK_IF_ERROR(status);

        send_pack.head->flags = CS_FLAG_RETURNRESULT;
        send_pack.head->serial_number = stmt->session->recv_pack->head->serial_number;
        status = cs_call(stmt->session->pipe, cs_send_pack, cs_send_pack);
        if (stmt->session->call_version >= CS_VERSION_11) {
            stmt->session->recv_pack->head->serial_number = cs_send_pack->head->serial_number;
        }
        stmt->trace_disabled = CT_TRUE;
    } while (0);

    CTSQL_POP(stmt);

    return status;
}
