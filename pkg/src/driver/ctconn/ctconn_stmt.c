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
 * ctconn_stmt.c
 *
 *
 * IDENTIFICATION
 * src/driver/ctconn/ctconn_stmt.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctconn_common.h"
#include "ctconn_stmt.h"
#include "ctconn_fetch.h"
#include "ctconn_lob.h"
#include "cm_row.h"

#ifdef __cplusplus
extern "C" {
#endif

static void clt_destory_column_list(clt_stmt_t *stmt)
{
    clt_column_t *column = NULL;
    uint32 i;

    for (i = 0; i < stmt->columns.count; i++) {
        column = (clt_column_t *)cm_list_get(&stmt->columns, i);
        if (column->inline_lob.cache_buf.len == 0) {
            continue;
        }
        CM_FREE_PTR(column->inline_lob.cache_buf.str);
        column->inline_lob.cache_buf.len = 0;
        column->inline_lob.used_pos = 0;
    }

    cm_destroy_list(&stmt->columns);
}

static void clt_destory_param_list(clt_stmt_t *stmt)
{
    clt_param_t *param = NULL;
    for (uint32 i = 0; i < stmt->params.count; i++) {
        param = (clt_param_t *)cm_list_get(&stmt->params, i);
        CM_FREE_PTR(param->lob_ptr);
        param->lob_ptr_size = 0;
    }
    cm_destroy_list(&stmt->params);
}

static void clt_reset_outparams(list_t *outparams)
{
    clt_outparam_t *outparam = NULL;
    uint32 i;

    for (i = 0; i < outparams->count; i++) {
        outparam = (clt_outparam_t *)cm_list_get(outparams, i);
        if (outparam->sub_stmt != NULL) {
            clt_free_stmt(outparam->sub_stmt);
            outparam->sub_stmt = NULL;
        }
    }
}

static void clt_destory_outparams(list_t *outparams)
{
    clt_reset_outparams(outparams);
    cm_destroy_list(outparams);
}

static void clt_destory_serveroutput(clt_serveroutput_t *serveroutput)
{
    uint32 i;
    clt_output_item_t *item = NULL;

    for (i = 0; i < serveroutput->output_data.count; i++) {
        item = (clt_output_item_t *)cm_list_get(&serveroutput->output_data, i);
        if (item->output.str) {
            free(item->output.str);
            item->output.str = NULL;
        }
    }

    cm_destroy_list(&serveroutput->output_data);
    serveroutput->output_count = 0;
    serveroutput->pos = 0;
}

status_t clt_prepare_stmt_pack(clt_stmt_t *stmt)
{
    if (stmt->cache_pack != NULL) {
        return CT_SUCCESS;
    }

    return clt_alloc_pack(stmt->conn, &stmt->cache_pack);
}

static void clt_destory_resultset(clt_stmt_t *stmt, clt_resultset_t *resultset)
{
    cs_packet_t *req_pack = NULL;
    cs_packet_t *ack_pack = NULL;
    clt_stmt_t *sub_stmt = NULL;
    clt_rs_stmt_t *rs_stmt = NULL;
    uint32 i, id;

    if (clt_prepare_stmt_pack(stmt) != CT_SUCCESS) {
        return;
    }
    ack_pack = &stmt->cache_pack->pack;

    // free server stmt
    for (i = 0; i < resultset->stmt_ids.count; i++) {
        rs_stmt = (clt_rs_stmt_t *)cm_list_get(&resultset->stmt_ids, i);
        req_pack = &stmt->conn->pack;
        cs_init_set(req_pack, stmt->conn->call_version);
        req_pack->head->cmd = CS_CMD_FREE_STMT;
        if (cs_put_int16(req_pack, rs_stmt->stmt_id) == CT_SUCCESS) {
            (void)clt_remote_call(stmt->conn, req_pack, ack_pack);
        }
    }

    cm_destroy_list(&resultset->stmt_ids);

    // free client stmt
    for (i = 0; i < resultset->ids.count; i++) {
        id = *(uint32 *)cm_list_get(&resultset->ids, i);
        sub_stmt = (clt_stmt_t *)cm_ptlist_get(&stmt->conn->stmts, id);
        if (sub_stmt != NULL) {
            sub_stmt->stmt_id = CT_INVALID_ID16;
            clt_free_stmt(sub_stmt);
        }
    }

    cm_destroy_list(&resultset->ids);

    resultset->pos = 0;
}

static void clt_free_stmt_transcode_buf(clt_stmt_t *stmt)
{
    if (stmt->ctrl != NULL) {
        CM_FREE_PTR(stmt->ctrl);
    }
}

void clt_recycle_stmt_pack(clt_stmt_t *stmt)
{
    if (stmt->cache_pack == NULL) {
        return;
    }
    clt_free_pack(stmt->conn, stmt->cache_pack);
    stmt->cache_pack = NULL;
}

static inline void clt_destory_batch_errs(clt_stmt_t *stmt)
{
    cm_destroy_list(&stmt->batch_errs.err_list);
    stmt->batch_errs.actual_count = 0;
    stmt->batch_errs.allowed_count = 0;
}

void clt_free_stmt(clt_stmt_t *stmt)
{
    cs_packet_t *req_pack = NULL;
    cs_packet_t *ack_pack = NULL;

    if (stmt == NULL) {
        CT_THROW_ERROR(ERR_CLT_OBJECT_IS_NULL, "statement");
        return;
    }

    if (clt_prepare_stmt_pack(stmt) != CT_SUCCESS) {
        return;
    }
    ack_pack = &stmt->cache_pack->pack;

    if (stmt->stmt_id != CT_INVALID_ID16) {
        req_pack = &stmt->conn->pack;
        cs_init_set(req_pack, stmt->conn->call_version);
        req_pack->head->cmd = CS_CMD_FREE_STMT;
        if (cs_put_int16(req_pack, stmt->stmt_id) == CT_SUCCESS) {
            (void)clt_remote_call(stmt->conn, req_pack, ack_pack);
        }
    }

    clt_destory_column_list(stmt);
    clt_destory_param_list(stmt);
    clt_destory_outparams(&stmt->outparams);
    clt_destory_serveroutput(&stmt->serveroutput);
    clt_destory_resultset(stmt, &stmt->resultset);
    clt_destory_batch_errs(stmt);
#ifdef Z_SHARDING
    CM_FREE_PTR(stmt->batch_bnd_ptr);
#endif
    clt_recycle_stmt_pack(stmt);
    clt_free_stmt_transcode_buf(stmt);
    cm_ptlist_set(&stmt->conn->stmts, (uint32)stmt->id, NULL);
    CM_FREE_PTR(stmt);
}

status_t clt_alloc_stmt(clt_conn_t *conn, clt_stmt_t **stmt)
{
    uint32 i;
    clt_stmt_t *statement = NULL;

    if (stmt == NULL) {
        CT_THROW_ERROR(ERR_CLT_OBJECT_IS_NULL, "stmt");
        return CT_ERROR;
    }

    if (conn->ready != CT_TRUE) {
        CLT_THROW_ERROR(conn, ERR_CLT_CONN_CLOSE);
        return CT_ERROR;
    }

    statement = (clt_stmt_t *)malloc(sizeof(clt_stmt_t));
    if (statement == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)sizeof(clt_stmt_t), "creating new client statement");
        return CT_ERROR;
    }

    errno_t errcode = memset_s(statement, sizeof(clt_stmt_t), 0, sizeof(clt_stmt_t));
    if (errcode != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        CM_FREE_PTR(statement);
        return CT_ERROR;
    }

    statement->conn = conn;
    statement->id = CT_INVALID_ID16;
    statement->stmt_id = CT_INVALID_ID16;
    statement->paramset_size = 1;
    statement->fetch_size = 1;
    statement->prefetch_rows = 0;
    statement->ctrl = NULL;
    statement->cache_pack = NULL;

    cm_create_list2(&statement->columns, LIST_EXTENT_SIZE, CT_MAX_COLUMNS / LIST_EXTENT_SIZE, sizeof(clt_column_t));
    cm_create_list2(&statement->params, LIST_EXTENT_SIZE, CT_MAX_SQL_PARAM_COUNT / LIST_EXTENT_SIZE,
        sizeof(clt_param_t));
    cm_create_list2(&statement->outparams, LIST_EXTENT_SIZE, CT_MAX_SQL_PARAM_COUNT / LIST_EXTENT_SIZE,
        sizeof(clt_outparam_t));
    cm_create_list(&statement->serveroutput.output_data, sizeof(clt_output_item_t));
    cm_create_list(&statement->resultset.stmt_ids, sizeof(clt_rs_stmt_t));
    cm_create_list(&statement->resultset.ids, sizeof(uint32));
    cm_create_list(&statement->batch_errs.err_list, sizeof(clt_batch_error_t));

#ifdef Z_SHARDING
    statement->batch_bnd_ptr = NULL;
#endif

    for (i = 0; i < conn->stmts.count; i++) {
        if (cm_ptlist_get(&conn->stmts, i) == NULL) {
            statement->id = i;
            break;
        }
    }

    if (statement->id != CT_INVALID_ID16) {
        cm_ptlist_set(&conn->stmts, (uint32)statement->id, statement);
    } else {
        statement->id = (uint16)conn->stmts.count;

        if (cm_ptlist_add(&conn->stmts, statement) != CT_SUCCESS) {
            CM_FREE_PTR(statement);
            clt_copy_local_error(conn);
            return CT_ERROR;
        }
    }
    if (clt_reset_stmt_transcode_buf(statement) != CT_SUCCESS) {
        free(statement);
        return CT_ERROR;
    }

    statement->status = CLI_STMT_IDLE;
    *stmt = statement;
    return CT_SUCCESS;
}

status_t ctconn_alloc_stmt(ctconn_conn_t pconn, ctconn_stmt_t *pstmt)
{
    status_t status;
    clt_conn_t *conn = (clt_conn_t *)pconn;

    CTCONN_CHECK_OBJECT_NULL_GS(conn, "connection");
    CTCONN_CHECK_OBJECT_NULL_CLT(conn, pstmt, "statement");

    CT_RETURN_IFERR(clt_lock_conn(conn));
    status = clt_alloc_stmt(conn, (clt_stmt_t **)pstmt);
    clt_unlock_conn(conn);
    return status;
}

void ctconn_free_stmt(ctconn_stmt_t pstmt)
{
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;
    clt_conn_t *conn = NULL;

    if (SECUREC_UNLIKELY(stmt == NULL)) {
        CT_THROW_ERROR(ERR_CLT_OBJECT_IS_NULL, "statement");
        return;
    }

    if (SECUREC_UNLIKELY(stmt->conn == NULL)) {
        CT_THROW_ERROR(ERR_CLT_OBJECT_IS_NULL, "connection");
        return;
    }

    conn = stmt->conn;

    CT_RETVOID_IFERR(clt_lock_conn(conn));

    clt_free_stmt(stmt);

    clt_unlock_conn(conn);
}

static status_t clt_set_stmt_attr(clt_stmt_t *stmt, int attr, const void *data, uint32 len)
{
    switch (attr) {
        case CTCONN_ATTR_PREFETCH_ROWS:
            stmt->prefetch_rows = *(uint32 *)data;
            break;

        case CTCONN_ATTR_PREFETCH_BUFFER:
            stmt->prefetch_buf = *(uint32 *)data;
            break;

        case CTCONN_ATTR_PARAMSET_SIZE:
            stmt->paramset_size = *(uint32 *)data;
            break;
#ifdef Z_SHARDING
        case CTCONN_ATTR_PARAM_COUNT:
            stmt->param_count = *(uint32 *)data;
            break;

        case CTCONN_ATTR_SHARD_DML_ID:
            stmt->shard_dml_id = *(uint32 *)data;
            break;

#endif

        case CTCONN_ATTR_ALLOWED_BATCH_ERRS:
            stmt->batch_errs.allowed_count = *(uint32 *)data;
            break;

        case CTCONN_ATTR_FETCH_SIZE:
            stmt->fetch_size = *(uint32 *)data;
            break;

        default:
            CLT_THROW_ERROR(stmt->conn, ERR_CLT_INVALID_VALUE, "statement attribute id", (uint32)attr);
            return CT_ERROR;
    }

    return CT_SUCCESS;
}
status_t ctconn_set_stmt_attr(ctconn_stmt_t pstmt, int attr, const void *data, uint32 len)
{
    status_t status;
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;

    CTCONN_CHECK_OBJECT_NULL_GS(stmt, "statement");
    CTCONN_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");
    CTCONN_CHECK_OBJECT_NULL_CLT(stmt->conn, data, "value of statement attribute to set");

    CT_RETURN_IFERR(clt_lock_conn(stmt->conn));
    status = clt_set_stmt_attr(stmt, attr, data, len);
    clt_unlock_conn(stmt->conn);
    return status;
}

status_t clt_get_stmt_attr(clt_stmt_t *stmt, int attr, const void *data, uint32 buf_len, uint32 *len)
{
    if (buf_len < sizeof(uint32)) {
        CT_THROW_ERROR(ERR_CLT_INVALID_VALUE, "statement attribute buffer len", buf_len);
        return CT_ERROR;
    }

    if (len != NULL) {
        *len = sizeof(uint32);
    }

    switch (attr) {
        case CTCONN_ATTR_PREFETCH_ROWS:
            *(uint32 *)data = stmt->prefetch_rows;
            break;

        case CTCONN_ATTR_PREFETCH_BUFFER:
            *(uint32 *)data = stmt->prefetch_buf;
            break;

        case CTCONN_ATTR_PARAMSET_SIZE:
            *(uint32 *)data = stmt->paramset_size;
            break;

        case CTCONN_ATTR_FETCHED_ROWS:
            *(uint32 *)data = stmt->fetched_rows;
            break;

        case CTCONN_ATTR_AFFECTED_ROWS:
            *(uint32 *)data = stmt->affected_rows;
            break;

        case CTCONN_ATTR_RESULTSET_EXISTS:
            *(uint32 *)data = (stmt->column_count > 0);
            break;

        case CTCONN_ATTR_COLUMN_COUNT:
            *(uint32 *)data = stmt->column_count;
            break;

        case CTCONN_ATTR_STMT_TYPE:
            *(uint32 *)data = stmt->stmt_type;
            break;

        case CTCONN_ATTR_PARAM_COUNT:
            *(uint32 *)data = stmt->param_count;
            break;

        case CTCONN_ATTR_MORE_ROWS:
            *(bool32 *)data = (bool32)stmt->more_rows;
            break;

        case CTCONN_ATTR_STMT_EOF:
            *(bool32 *)data = (bool32)stmt->eof;
            break;

        case CTCONN_ATTR_OUTPARAM_COUNT:
            *(uint32 *)data = stmt->outparam_count;
            break;

        case CTCONN_ATTR_SEROUTPUT_EXISTS:
            *(uint32 *)data = (stmt->serveroutput.output_count > 0) ? 1 : 0;
            break;

        case CTCONN_ATTR_RETURNRESULT_EXISTS:
            *(uint32 *)data = (stmt->resultset.stmt_ids.count > 0) ? 1 : 0;
            break;

        case CTCONN_ATTR_LOB_LOCATOR_SIZE:
            if (stmt->conn == NULL) {
                CT_THROW_ERROR(ERR_CLT_OBJECT_IS_NULL, "connection");
                return CT_ERROR;
            }
            *(uint32 *)data = (uint32)stmt->conn->server_info.locator_size;
            break;

        case CTCONN_ATTR_ALLOWED_BATCH_ERRS:
            *(uint32 *)data = stmt->batch_errs.allowed_count;
            break;

        case CTCONN_ATTR_ACTUAL_BATCH_ERRS:
            *(uint32 *)data = stmt->batch_errs.actual_count;
            break;

        case CTCONN_ATTR_FETCH_SIZE:
            *(uint32 *)data = stmt->fetch_size;
            break;

        default:
            CT_THROW_ERROR(ERR_CLT_INVALID_VALUE, "statement attribute id", (uint32)attr);
            return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t ctconn_get_stmt_attr(ctconn_stmt_t pstmt, int attr, const void *data, uint32 buf_len, uint32 *len)
{
    status_t status;
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;

    CTCONN_CHECK_OBJECT_NULL_GS(stmt, "statement");
    CTCONN_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");
    CTCONN_CHECK_OBJECT_NULL_CLT(stmt->conn, data, "value of statement attribute to get");

    CT_RETURN_IFERR(clt_lock_conn(stmt->conn));
    status = clt_get_stmt_attr(stmt, attr, data, buf_len, len);
    clt_unlock_conn(stmt->conn);
    return status;
}

static void clt_reset_stmt(clt_stmt_t *stmt)
{
    stmt->affected_rows = 0;
    stmt->return_rows = 0;
    stmt->fetched_times = 0;
    stmt->fetched_rows = 0;
    stmt->fetch_pos = 0;
    stmt->row_index = 0;

    stmt->serveroutput.output_count = 0;
    stmt->serveroutput.pos = 0;

    if (stmt->resultset.stmt_ids.count > 0) {
        clt_destory_resultset(stmt, &stmt->resultset);
        cm_create_list(&stmt->resultset.stmt_ids, sizeof(clt_rs_stmt_t));
        cm_create_list(&stmt->resultset.ids, sizeof(uint32));
    }

    clt_reset_outparams(&stmt->outparams);

    stmt->batch_errs.pos = 0;
    stmt->batch_errs.actual_count = 0;
}

static status_t clt_receive_returnresult(clt_stmt_t *stmt, cs_packet_t *ack)
{
    uint32 stmt_id;
    uint32 fetch_mode;
    int64 cursor;
    clt_rs_stmt_t *rs_stmt = NULL;

    cs_init_get(ack);
    CT_RETURN_IFERR(cs_get_int64(ack, (int64 *)&cursor));
    stmt_id = (uint32)((uint64)cursor >> 32);
    fetch_mode = (uint32)((uint64)cursor & 0xFFFFFFFF);

    CT_RETURN_IFERR(cm_list_new(&stmt->resultset.stmt_ids, (void **)&rs_stmt));
    rs_stmt->stmt_id = stmt_id;
    rs_stmt->fetch_mode = fetch_mode;
    return CT_SUCCESS;
}

static void cs_set_req_flags(clt_stmt_t *stmt, cs_packet_t *req_pack, cs_prepare_req_t *req)
{
    req->flags = 0;
    if (stmt->conn->autotrace) {
        req->flags = CS_PREP_AUTOTRACE;
    }
    if (stmt->conn->ctsql_in_altpwd) {
        req->flags |= CS_CTSQL_IN_ALTPWD;
    }
}

status_t clt_prepare(clt_stmt_t *stmt, const text_t *sql)
{
    uint32 sql_size, total_size, req_offset;
    cs_packet_t *ack_pack = NULL;
    cs_packet_t *req_pack = NULL;
    cs_prepare_req_t *req = NULL;

    /* reset stmt before prepare sql */
    stmt->column_count = 0;
    stmt->param_count = 0;
    stmt->outparam_count = 0;
    stmt->paramset_size = 1;
    stmt->fetch_size = 1;
    stmt->status = CLI_STMT_IDLE;
    clt_reset_stmt(stmt);
    clt_reset_error(stmt->conn);

    ack_pack = &stmt->cache_pack->pack;
    req_pack = &stmt->conn->pack;

    cs_init_set(req_pack, stmt->conn->call_version);
    req_pack->head->cmd = CS_CMD_PREPARE;
    CT_RETURN_IFERR(cs_reserve_space(req_pack, sizeof(cs_prepare_req_t), &req_offset));
    req = (cs_prepare_req_t *)CS_RESERVE_ADDR(req_pack, req_offset);
    req->stmt_id = stmt->stmt_id;
    if (stmt->conn->call_version >= CS_VERSION_11) {
        if (stmt->conn->node_type == CS_TYPE_DN) {
            CT_RETURN_IFERR(cs_put_alter_set(req_pack, stmt));
        } else {
            CT_RETURN_IFERR(cs_put_int32(req_pack, 0));
        }
    }
    cs_set_req_flags(stmt, req_pack, req);
    cs_putted_prepare_req(req_pack, req_offset);
    sql_size = sql->len;
    total_size = sql_size;

    do {
        CT_RETURN_IFERR(ctconn_write_sql(stmt, sql->str, total_size, &sql_size, req_pack));
        CT_RETURN_IFERR(clt_remote_call(stmt->conn, req_pack, ack_pack));

        cs_init_set(req_pack, stmt->conn->call_version);
        req_pack->head->cmd = CS_CMD_PREPARE;
    } while (sql_size > 0);

    CT_RETURN_IFERR(clt_get_prepare_ack(stmt, ack_pack, sql));

    /* DDL of PL may has warning info from prepare ack */
    if (stmt->stmt_type == CTCONN_STMT_DDL && CS_HAS_MORE(ack_pack)) {
        CT_RETURN_IFERR(clt_get_error_message(stmt->conn, ack_pack, stmt->conn->message));
    }

    stmt->status = CLI_STMT_PREPARED;
    return CT_SUCCESS;
}

status_t ctconn_prepare(ctconn_stmt_t pstmt, const char *sql)
{
    status_t status;
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;
    text_t sql_text;

    CTCONN_CHECK_OBJECT_NULL_GS(stmt, "statement");
    CTCONN_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");
    CTCONN_CHECK_OBJECT_NULL_CLT(stmt->conn, sql, "sql");

    sql_text.str = (char *)sql;
    sql_text.len = (uint32)strlen(sql);

    CT_RETURN_IFERR(clt_lock_conn(stmt->conn));

    if (clt_prepare_stmt_pack(stmt) != CT_SUCCESS) {
        clt_unlock_conn(stmt->conn);
        return CT_ERROR;
    }

    status = clt_prepare(stmt, &sql_text);

    clt_recycle_stmt_pack(stmt);
    // Clear SQL to prevent sensitive information from being contained in packets.
    errno_t errcode = memset_s(stmt->conn->pack.buf, stmt->conn->pack.buf_size, 0, stmt->conn->pack.buf_size);
    if (errcode != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        status = CT_ERROR;
    }

    clt_unlock_conn(stmt->conn);

    return status;
}

/* A date in binary format contains 7 bytes */
static status_t clt_encode_date(clt_conn_t *conn, uint8 *bnd_ptr, uint32 bnd_size, date_t *date)
{
    if (bnd_size != CLT_DATE_BINARY_SIZE) {
        CLT_THROW_ERROR(conn, ERR_CLT_INVALID_VALUE, "bound size of date", bnd_size);
        return CT_ERROR;
    }

    /* century [100,*) */
    if (bnd_ptr[ORA_DATE_IDX_CENTURY] < 100) {
        CLT_THROW_ERROR(conn, ERR_CLT_INVALID_VALUE, "century of date", bnd_ptr[ORA_DATE_IDX_CENTURY]);
        return CT_ERROR;
    }

    /* year [100,200) */
    if (bnd_ptr[ORA_DATE_IDX_YEAR] < 100 || bnd_ptr[ORA_DATE_IDX_YEAR] >= 200) {
        CLT_THROW_ERROR(conn, ERR_CLT_INVALID_VALUE, "year of date", bnd_ptr[ORA_DATE_IDX_YEAR]);
        return CT_ERROR;
    }

    /* support year [1, 9999] */
    uint32 year = (bnd_ptr[ORA_DATE_IDX_CENTURY] - 100) * 100 + (bnd_ptr[ORA_DATE_IDX_YEAR] - 100);
    if (!CM_IS_VALID_YEAR(year)) {
        CLT_THROW_ERROR(conn, ERR_CLT_INVALID_VALUE, "year", year);
        return CT_ERROR;
    }

    /* month [1,12] */
    if (bnd_ptr[ORA_DATE_IDX_MONTH] < 1 || bnd_ptr[ORA_DATE_IDX_MONTH] > 12) {
        CLT_THROW_ERROR(conn, ERR_CLT_INVALID_VALUE, "month of date", bnd_ptr[ORA_DATE_IDX_MONTH]);
        return CT_ERROR;
    }

    /* day [1,31] */
    if (bnd_ptr[ORA_DATE_IDX_DAY] < 1 || bnd_ptr[ORA_DATE_IDX_DAY] > 31) {
        CLT_THROW_ERROR(conn, ERR_CLT_INVALID_VALUE, "day of date", bnd_ptr[ORA_DATE_IDX_DAY]);
        return CT_ERROR;
    }

    /* hour [1,24] */
    if (bnd_ptr[ORA_DATE_IDX_HOUR] < 1 || bnd_ptr[ORA_DATE_IDX_HOUR] > 24) {
        CLT_THROW_ERROR(conn, ERR_CLT_INVALID_VALUE, "hour of date", bnd_ptr[ORA_DATE_IDX_HOUR]);
        return CT_ERROR;
    }

    /* minute [1,60] */
    if (bnd_ptr[ORA_DATE_IDX_MINUTE] < 1 || bnd_ptr[ORA_DATE_IDX_MINUTE] > 60) {
        CLT_THROW_ERROR(conn, ERR_CLT_INVALID_VALUE, "minute of date", bnd_ptr[ORA_DATE_IDX_MINUTE]);
        return CT_ERROR;
    }

    /* second [1,60] */
    if (bnd_ptr[ORA_DATE_IDX_SECOND] < 1 || bnd_ptr[ORA_DATE_IDX_SECOND] > 60) {
        CLT_THROW_ERROR(conn, ERR_CLT_INVALID_VALUE, "second of date", bnd_ptr[ORA_DATE_IDX_SECOND]);
        return CT_ERROR;
    }

    *date = cm_encode_ora_date(bnd_ptr);
    return CT_SUCCESS;
}

static uint32 clt_total_ucs2len(const char *str, uint32 bnd_size)
{
    uint32 len;
    // One character corresponds to two bytes
    for (len = 0; len + 1 < bnd_size; len += 2) {
        if (str[len] == '\0' && str[len + 1] == '\0') {
            break;
        }
    }

    return len;
}

static status_t clt_put_param_value(clt_stmt_t *stmt, cs_packet_t *req, uint32 offset, clt_param_t *param)
{
    uint32 size;
    text_t text;
    ctconn_lob_t *bnd_lob = NULL;
    date_t date;

    switch ((ctconn_type_t)param->bnd_type) {
        case CTCONN_TYPE_UINT32:
        case CTCONN_TYPE_INTEGER:
        case CTCONN_TYPE_BOOLEAN:
            CT_RETURN_IFERR(cs_put_int32(req, *(uint32 *)param->curr_ptr));
            break;

        case CTCONN_TYPE_BIGINT:
            CT_RETURN_IFERR(cs_put_int64(req, *(uint64 *)param->curr_ptr));
            break;

        case CTCONN_TYPE_REAL:
            CT_RETURN_IFERR(cs_put_real(req, *(double *)param->curr_ptr));
            break;

        case CTCONN_TYPE_DATE:
            CT_RETURN_IFERR(clt_encode_date(stmt->conn, (uint8 *)param->curr_ptr, param->bnd_size, &date));
            CT_RETURN_IFERR(cs_put_date(req, date));
            break;

        case CTCONN_TYPE_TIMESTAMP:
        case CTCONN_TYPE_TIMESTAMP_TZ_FAKE:
        case CTCONN_TYPE_TIMESTAMP_LTZ:
            /* CTCONN_TYPE_TIMESTAMP_LTZ formatted in 'ctconn_datetime_construct', just put value into request packet */
        case CTCONN_TYPE_NATIVE_DATE:
            CT_RETURN_IFERR(cs_put_date(req, *(date_t *)param->curr_ptr));
            break;

        case CTCONN_TYPE_TIMESTAMP_TZ:
            CT_RETURN_IFERR(cs_put_data(req, (timestamp_tz_t *)param->curr_ptr, sizeof(timestamp_tz_t)));
            break;

        case CTCONN_TYPE_NUMBER:
        case CTCONN_TYPE_NUMBER2:
        case CTCONN_TYPE_DECIMAL:
        case CTCONN_TYPE_CHAR:
        case CTCONN_TYPE_VARCHAR:
        case CTCONN_TYPE_STRING:
            text.str = param->curr_ptr;
            if (param->ind_ptr != NULL) {
                text.len = MIN(param->ind_ptr[offset], param->bnd_size);
            } else {
                if (param->is_W_CType) {
                    text.len = clt_total_ucs2len(text.str, param->bnd_size);
                } else {
                    text.len = (uint32)strlen(text.str);
                }
                if (text.len > param->bnd_size) {
                    CLT_THROW_ERROR(stmt->conn, ERR_CLT_INVALID_VALUE, "string param length", text.len);
                    return CT_ERROR;
                }
            }

            transcode_func_t transcode_func = stmt->conn->send_trans_func;
            if (param->is_W_CType) {
                transcode_func = cm_from_transcode_func_ucs2(stmt->conn->server_info.server_charset);
            }
            if (CTCONN_IS_STRING_TYPE(param->bnd_type) && transcode_func != NULL) {
                CT_RETURN_IFERR(clt_transcode_column(stmt, &text.str, &text.len, transcode_func));
                CT_RETURN_IFERR(cs_put_text(req, &text));
                CT_RETURN_IFERR(clt_reset_stmt_transcode_buf(stmt));
            } else {
                CT_RETURN_IFERR(cs_put_text(req, &text));
            }
            break;

        case CTCONN_TYPE_INTERVAL_DS:
            CT_RETURN_IFERR(cs_put_int64(req, *(interval_ds_t *)param->curr_ptr));
            break;

        case CTCONN_TYPE_INTERVAL_YM:
            CT_RETURN_IFERR(cs_put_int32(req, *(interval_ym_t *)param->curr_ptr));
            break;

        case CTCONN_TYPE_CLOB:
        case CTCONN_TYPE_BLOB:
        case CTCONN_TYPE_IMAGE:
        case CTCONN_TYPE_ARRAY:
            bnd_lob = (ctconn_lob_t *)param->bnd_ptr;
            if (bnd_lob == NULL) {
                CLT_THROW_ERROR(stmt->conn, ERR_CLT_OBJECT_IS_NULL, "the pointer bnd_lob");
                return CT_ERROR;
            }
            CT_RETURN_IFERR(cs_put_data(req, &bnd_lob[offset], sizeof(ctconn_lob_t)));
            clt_reset_lob(&bnd_lob[offset]);
            break;

        default:
            if (param->ind_ptr != NULL) {
                size = MIN(param->ind_ptr[offset], param->bnd_size);
                CT_RETURN_IFERR(cs_put_int32(req, (uint16)param->ind_ptr[offset]));
                CT_RETURN_IFERR(cs_put_data(req, param->curr_ptr, size));
            } else {
                CT_RETURN_IFERR(cs_put_int32(req, (uint16)param->bnd_size));
                CT_RETURN_IFERR(cs_put_data(req, param->curr_ptr, param->bnd_size));
            }
            break;
    }

    return CT_SUCCESS;
}

static status_t clt_put_large_str_param_value(cs_packet_t *req, uint32 offset, clt_param_t *param)
{
    return cs_put_data(req, &(((ctconn_lob_t *)param->lob_ptr)[offset]), sizeof(ctconn_lob_t));
}

static status_t clt_write_large_str_param_value(clt_stmt_t *stmt, uint32 pos, uint32 offset)
{
    clt_param_t *param = NULL;
    ctconn_lob_t *vm_lob = NULL;
    text_t large_str;
    char *org_bnd_ptr = NULL;
    uint32 write_len = 0;
    uint32 nchars = 0;
    status_t status = CT_SUCCESS;

    param = (clt_param_t *)cm_list_get(&stmt->params, pos);
    // lob_ptr is prepared by 'clt_prepare_param_lob_ptr', offset must be less than stmt.paramset_size
    vm_lob = (ctconn_lob_t *)(param->lob_ptr + sizeof(ctconn_lob_t) * offset);

    // get large str bind data
    large_str.str = param->bnd_ptr + param->bnd_size * offset;
    if (param->ind_ptr != NULL) {
        if (param->ind_ptr[offset] == CTCONN_NULL) {
            return CT_SUCCESS;
        }
        large_str.len = MIN(param->ind_ptr[offset], param->bnd_size);
    } else {
        large_str.len = (uint32)strlen(large_str.str);
        if (large_str.len > param->bnd_size) {
            CLT_THROW_ERROR(stmt->conn, ERR_CLT_INVALID_VALUE, "large string param length", large_str.len);
            return CT_ERROR;
        }
    }

    // bind large str with clob type
    clt_reset_lob(vm_lob);
    org_bnd_ptr = param->bnd_ptr;
    param->bnd_ptr = (char *)vm_lob;

    while (write_len < large_str.len) {
        status = clt_write_clob(stmt, pos, 0, large_str.str + write_len, large_str.len - write_len, &nchars);
        if (status != CT_SUCCESS) {
            break;
        }
        write_len += nchars;
    }

    param->bnd_ptr = org_bnd_ptr;
    return status;
}

#ifdef Z_SHARDING
/* put params efficiently:
types | total_len flags param ... param | ... | total_len flags param ... param
*/
static status_t clt_put_params_batch_eff(clt_stmt_t *stmt, uint32 offset, bool32 add_bytes)
{
    uint32 i, size, req_begin;
    uint32 types_offset = 0;
    uint32 total_len_offset, flags_offset;
    cs_param_head_t *head = NULL;
    int8 *types = NULL;
    uint32 *total_len = NULL;
    uint8 *flags = NULL;
    cs_packet_t *req = NULL;

    req = &stmt->conn->pack;

    if (add_bytes) {
        CT_RETURN_IFERR(cs_reserve_space(req, CM_ALIGN4(stmt->param_count), &types_offset));
    }

    req_begin = req->head->size;

    CT_RETURN_IFERR(cs_reserve_space(req, sizeof(uint32), &total_len_offset));
    CT_RETURN_IFERR(cs_reserve_space(req, CM_ALIGN4(stmt->param_count), &flags_offset));

    clt_param_t param;
    for (i = 0; i < stmt->param_count; i++) {
        head = (cs_param_head_t *)(stmt->batch_curr_ptr);
        stmt->batch_curr_ptr += sizeof(cs_param_head_t);

        if (add_bytes) {
            types = (int8 *)CS_RESERVE_ADDR(req, types_offset);
            types[i] = head->type;
        }

        flags = (uint8 *)CS_RESERVE_ADDR(req, flags_offset);
        flags[i] = head->flag;

        if ((flags[i] & 0x01) == CT_FALSE) {
            param.bnd_ptr = NULL;
            param.ind_ptr = NULL;
            param.bnd_size = head->len;
            param.bnd_type = (head->type == CTCONN_TYPE_DATE) ? CTCONN_TYPE_NATIVE_DATE : head->type;
            param.curr_ptr = stmt->batch_curr_ptr;
            param.is_W_CType = CT_FALSE;
            if (CTCONN_IS_LOB_TYPE(param.bnd_type)) {
                param.bnd_ptr = param.curr_ptr;
                CT_RETURN_IFERR(clt_put_param_value(stmt, req, 0, &param));
            } else {
                CT_RETURN_IFERR(clt_put_param_value(stmt, req, offset, &param));
            }

            stmt->batch_curr_ptr += param.bnd_size;
        }
    }

    size = req->head->size - req_begin;

    total_len = (uint32 *)CS_RESERVE_ADDR(req, total_len_offset);
    *total_len = cs_format_endian_i32(req->options, size);
    return CT_SUCCESS;
}

static status_t clt_put_params_batch(clt_stmt_t *stmt, uint32 offset, bool32 add_bytes)
{
    uint32 i, size, req_begin, item_begin;
    uint16 item_size;
    uint32 *total_len = NULL;
    uint32 total_len_offset;
    cs_param_head_t *head = NULL;
    uint32 head_offset;
    cs_packet_t *req = NULL;

    if (stmt->conn->call_version >= CS_VERSION_7) {
        /* put params efficiently */
        return clt_put_params_batch_eff(stmt, offset, add_bytes);
    }

    req = &stmt->conn->pack;
    req_begin = req->head->size;
    CT_RETURN_IFERR(cs_reserve_space(req, sizeof(uint32), &total_len_offset));

    CM_POINTER(stmt->batch_bnd_ptr);

    clt_param_t param;
    for (i = 0; i < stmt->param_count; i++) {
        item_begin = req->head->size;

        CT_RETURN_IFERR(cs_reserve_space(req, sizeof(cs_param_head_t), &head_offset));
        head = (cs_param_head_t *)CS_RESERVE_ADDR(req, head_offset);
        *head = *(cs_param_head_t *)(stmt->batch_curr_ptr);
        stmt->batch_curr_ptr += sizeof(cs_param_head_t);

        if (head->flag & 0x01) {
            item_size = (uint16)sizeof(cs_param_head_t);
            head->len = item_size;
        } else {
            param.bnd_ptr = NULL;
            param.ind_ptr = NULL;
            param.bnd_size = head->len;
            param.bnd_type = (head->type == CTCONN_TYPE_DATE) ? CTCONN_TYPE_NATIVE_DATE : head->type;
            param.curr_ptr = stmt->batch_curr_ptr;
            param.is_W_CType = CT_FALSE;
            if (CTCONN_IS_LOB_TYPE(param.bnd_type)) {
                param.bnd_ptr = param.curr_ptr;
                CT_RETURN_IFERR(clt_put_param_value(stmt, req, 0, &param));
            } else {
                CT_RETURN_IFERR(clt_put_param_value(stmt, req, offset, &param));
            }

            stmt->batch_curr_ptr += param.bnd_size;

            item_size = (uint16)(req->head->size - item_begin);

            // packet address of head need get again because it may changed in clt_put_param_value!
            head = (cs_param_head_t *)CS_RESERVE_ADDR(req, head_offset);
            head->len = item_size;
        }
        cs_putted_param_head(req, head_offset);
    }

    size = req->head->size - req_begin;
    total_len = (uint32 *)CS_RESERVE_ADDR(req, total_len_offset);
    *total_len = cs_format_endian_i32(req->options, size);
    return CT_SUCCESS;
}

#endif

static void clt_set_param_isnull(clt_param_t *param, uint32 offset, uint8 *flag)
{
    // param not bound or with output mode means bind NULL
    if (param->curr_ptr == NULL || param->direction == CTCONN_OUTPUT) {
        *flag |= 0x01;
        return;
    }

    if (param->ind_ptr != NULL) {
        *flag |= (param->ind_ptr[offset] == CTCONN_NULL) ? 0x01 : 0x00;
    } else {
        *flag |= 0x00;
    }
}

void clt_set_param_direction(uint8 direction, uint8 *flag)
{
    if (direction == CTCONN_INPUT) {
        *flag |= 0x40;
    } else if (direction == CTCONN_OUTPUT) {
        *flag |= 0x80;
    } else if (direction == CTCONN_INOUT) {
        *flag |= 0x40;
        *flag |= 0x80;
    }
}

static status_t clt_params_eff(clt_stmt_t *stmt, cs_packet_t *req, uint32 offset, uint32 flags_offset,
    uint32 types_offset, bool32 add_types)
{
    clt_param_t *param = NULL;
    int8 *types = NULL;
    uint8 *flags = NULL;
    bool8 large_str = CT_FALSE;

    for (uint32 i = 0; i < stmt->param_count; i++) {
        param = (clt_param_t *)cm_list_get(&stmt->params, i);
        CM_POINTER(param);

        if (offset == 0) {
            param->curr_ptr = param->bnd_ptr;
        }

        // bind type convert to clob if is large str data
        large_str = CTCONN_IS_STRING_TYPE(param->bnd_type) && param->bnd_size > CT_MAX_COLUMN_SIZE;

        if (add_types) {
            types = (int8 *)CS_RESERVE_ADDR(req, types_offset);
            types[i] = (param->bnd_type == CTCONN_TYPE_NATIVE_DATE) ? CTCONN_TYPE_DATE : param->bnd_type;
            if (large_str) {
                types[i] = CTCONN_TYPE_CLOB;
            }
        }

        flags = (uint8 *)CS_RESERVE_ADDR(req, flags_offset);
        flags[i] = 0;
        clt_set_param_isnull(param, offset, &flags[i]);
        clt_set_param_direction(param->direction, &flags[i]);

        if ((flags[i] & 0x01) == CT_FALSE) {
            if (large_str) {
                CT_RETURN_IFERR(clt_put_large_str_param_value(req, offset, param));
            } else {
                CT_RETURN_IFERR(clt_put_param_value(stmt, req, offset, param));
            }
        }

        param->curr_ptr += param->bnd_size;
    }
    return CT_SUCCESS;
}

/* put params efficiently:
types | total_len flags param ... param | ... | total_len flags param ... param
*/
static status_t clt_put_params_eff(clt_stmt_t *stmt, uint32 offset, bool32 add_types)
{
    uint32 types_offset = 0;
    uint32 total_len_offset, flags_offset;

    cs_packet_t *req = &stmt->conn->pack;

    if (add_types) {
        CT_RETURN_IFERR(cs_reserve_space(req, CM_ALIGN4(stmt->param_count), &types_offset));
    }

    uint32 req_begin = req->head->size;

    CT_RETURN_IFERR(cs_reserve_space(req, sizeof(uint32), &total_len_offset));
    CT_RETURN_IFERR(cs_reserve_space(req, CM_ALIGN4(stmt->param_count), &flags_offset));

    CT_RETURN_IFERR(clt_params_eff(stmt, req, offset, flags_offset, types_offset, add_types));

    if (req->head->size > req->buf_size) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_INVALID_VALUE, "req pack head size", req->head->size);
        return CT_ERROR;
    }

    uint32 size = req->head->size - req_begin;

    uint32 *total_len = (uint32 *)CS_RESERVE_ADDR(req, total_len_offset);
    *total_len = cs_format_endian_i32(req->options, size);
    return CT_SUCCESS;
}

// cs_packet_head_t + cs_execute_req_t + total_len(4) + clt_param_t + ... + clt_param_t
status_t clt_put_params(clt_stmt_t *stmt, uint32 offset, bool32 add_types)
{
#ifdef Z_SHARDING
    // for CN do batch insert
    if (stmt->batch_bnd_ptr != NULL) {
        return clt_put_params_batch(stmt, offset, add_types);
    }
#endif

    if (stmt->conn->call_version >= CS_VERSION_7) {
        /* put params efficiently */
        return clt_put_params_eff(stmt, offset, add_types);
    }

    uint32 i, size, req_begin, item_begin, total_len_offset, head_offset;
    uint16 item_size;
    uint32 *total_len = NULL;
    clt_param_t *param = NULL;
    cs_param_head_t *head = NULL;
    cs_packet_t *req = NULL;
    bool8 large_str = CT_FALSE;

    req = &stmt->conn->pack;
    req_begin = req->head->size;
    CT_RETURN_IFERR(cs_reserve_space(req, sizeof(uint32), &total_len_offset));

    for (i = 0; i < stmt->param_count; i++) {
        param = (clt_param_t *)cm_list_get(&stmt->params, i);
        CM_POINTER(param);

        if (offset == 0) {
            param->curr_ptr = param->bnd_ptr;
        }

        item_begin = req->head->size;

        CT_RETURN_IFERR(cs_reserve_space(req, sizeof(cs_param_head_t), &head_offset));
        head = (cs_param_head_t *)CS_RESERVE_ADDR(req, head_offset);
        head->type = (param->bnd_type == CTCONN_TYPE_NATIVE_DATE) ? CTCONN_TYPE_DATE : param->bnd_type;
        head->flag = 0;

        // bind type convert to clob if is large str data
        large_str = CTCONN_IS_STRING_TYPE(param->bnd_type) && param->bnd_size > CT_MAX_COLUMN_SIZE;
        if (large_str) {
            head->type = CTCONN_TYPE_CLOB;
        }

        clt_set_param_isnull(param, offset, &head->flag);
        clt_set_param_direction(param->direction, &head->flag);

        if (head->flag & 0x01) {
            param->curr_ptr += param->bnd_size;
            item_size = (uint16)sizeof(cs_param_head_t);
            head->len = item_size;
        } else {
            if (large_str) {
                CT_RETURN_IFERR(clt_put_large_str_param_value(req, offset, param));
            } else {
                CT_RETURN_IFERR(clt_put_param_value(stmt, req, offset, param));
            }

            param->curr_ptr += param->bnd_size;
            item_size = (uint16)(req->head->size - item_begin);

            // packet address of head need get again because it may changed in put param value!
            head = (cs_param_head_t *)CS_RESERVE_ADDR(req, head_offset);
            head->len = item_size;
        }
        cs_putted_param_head(req, head_offset);
    }

    if (req->head->size > req->buf_size) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_INVALID_VALUE, "req pack head size", req->head->size);
        return CT_ERROR;
    }

    size = req->head->size - req_begin;

    total_len = (uint32 *)CS_RESERVE_ADDR(req, total_len_offset);
    *total_len = cs_format_endian_i32(req->options, size);
    return CT_SUCCESS;
}

static status_t clt_handle_execution_ack(clt_stmt_t *stmt, cs_packet_t *ack_pack, uint32 line_offset)
{
    // if error happened, receive error package, see sql_send_result_error
    if (CS_HAS_EXEC_ERROR(ack_pack)) {
        uint32 rows;
        CT_RETURN_IFERR(cs_get_int32(ack_pack, (int32 *)&rows)); // read total_rows
        stmt->affected_rows += rows;
        CT_RETURN_IFERR(cs_get_int32(ack_pack, (int32 *)&rows)); // read batch_rows
        stmt->return_rows += rows;
        return CT_SUCCESS;
    }

    // if the stmt returns success, then receive the cs_execute_ack_t package
    cs_execute_ack_t *exec_ack = NULL;

    // accumulate the affected_rows
    CT_RETURN_IFERR(cs_get_exec_ack(&stmt->cache_pack->pack, &exec_ack));
    stmt->affected_rows += exec_ack->total_rows;
    stmt->return_rows += exec_ack->batch_rows;
    stmt->more_rows = exec_ack->rows_more;
    stmt->conn->xact_status = (ctconn_xact_status_t)exec_ack->xact_status;

    // try get batch error message
    CT_RETURN_IFERR(clt_try_get_batch_error(stmt, exec_ack, line_offset));

    return CT_SUCCESS;
}

bool32 clt_has_large_string(clt_stmt_t *stmt)
{
    uint32 i;
    clt_param_t *param = NULL;

    for (i = 0; i < stmt->param_count; i++) {
        param = (clt_param_t *)cm_list_get(&stmt->params, i);
        if (CTCONN_IS_STRING_TYPE(param->bnd_type) && (param->bnd_size > CT_MAX_COLUMN_SIZE)) {
            return CT_TRUE;
        }
    }

    return CT_FALSE;
}

status_t clt_write_large_string(clt_stmt_t *stmt)
{
    clt_param_t *param = NULL;
    uint32 param_index;
    uint32 paramset_index;

    for (param_index = 0; param_index < stmt->param_count; param_index++) {
        param = (clt_param_t *)cm_list_get(&stmt->params, param_index);
        if (CTCONN_IS_STRING_TYPE(param->bnd_type) && (param->bnd_size > CT_MAX_COLUMN_SIZE)) {
            if (param->lob_ptr == NULL || param->lob_ptr_size < stmt->paramset_size) {
                CM_FREE_PTR(param->lob_ptr);
                param->lob_ptr_size = stmt->paramset_size;
                param->lob_ptr = (char *)malloc(sizeof(ctconn_lob_t) * param->lob_ptr_size);
                if (param->lob_ptr == NULL) {
                    CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)(sizeof(ctconn_lob_t) * param->lob_ptr_size),
                        "create large string bind lob");
                    return CT_ERROR;
                }
            }

            for (paramset_index = 0; paramset_index < stmt->paramset_size; paramset_index++) {
                CT_RETURN_IFERR(clt_write_large_str_param_value(stmt, param_index, paramset_index));
            }
        }
    }

    return CT_SUCCESS;
}

/**
 * Reset the execution request in the packet, and return the pointer of
 * execution request.

 */
static inline status_t clt_reset_execbatch_request(clt_stmt_t *stmt, uint32 *exec_req_offset)
{
    cs_execute_req_t *exec_req = NULL;
    cs_packet_t *req_pack = &stmt->conn->pack;

    cs_init_set(req_pack, stmt->conn->call_version);
    req_pack->head->cmd = CS_CMD_EXECUTE;

    CT_RETURN_IFERR(cs_reserve_space(req_pack, sizeof(cs_execute_req_t), exec_req_offset));
    exec_req = (cs_execute_req_t *)CS_RESERVE_ADDR(req_pack, *exec_req_offset);
    exec_req->stmt_id = stmt->stmt_id;
    exec_req->paramset_size = 0;
    exec_req->prefetch_rows = clt_prefetch_rows(stmt);
    exec_req->auto_commit = stmt->conn->auto_commit;
    exec_req->reserved = 0;

    return CT_SUCCESS;
}

// after execute request, try to receive data(put_line or return_result) from pl process
status_t clt_try_receive_pl_proc_data(clt_stmt_t *stmt, cs_packet_t *ack)
{
    bool32 has_serveroutput = (ack->head->flags & CS_FLAG_SERVEROUPUT) != 0;
    bool32 has_returnresult = (ack->head->flags & CS_FLAG_RETURNRESULT) != 0;

    while (has_serveroutput || has_returnresult) {
        // get and save serveroutput ack
        if (has_serveroutput) {
            (void)clt_receive_serveroutput(stmt, ack);
        } else if (has_returnresult) {
            (void)clt_receive_returnresult(stmt, ack);
        }

        // receive more ack
        cs_init_set(ack, stmt->conn->call_version);
        CT_RETURN_IFERR(clt_remote_call(stmt->conn, ack, ack));

        has_serveroutput = (ack->head->flags & CS_FLAG_SERVEROUPUT) != 0;
        has_returnresult = (ack->head->flags & CS_FLAG_RETURNRESULT) != 0;
    }

    return CT_SUCCESS;
}

static status_t clt_execute_batch(clt_stmt_t *stmt)
{
    cs_execute_req_t *exec_req = NULL;
    cs_packet_t *req_pack = &stmt->conn->pack;
    cs_packet_t *ack_pack = &stmt->cache_pack->pack;
    uint32 offset = 0;
    uint32 exec_req_offset, once_paramset_size;
    uint32 max_row_bndsz = clt_get_total_row_bndsz(stmt); // the maximal binding size of a row
    status_t status;
    bool32 add_types = CT_TRUE;
    uint32 line_offset = 0;

    cs_init_set(req_pack, stmt->conn->call_version);
    req_pack->head->cmd = CS_CMD_EXECUTE;
    req_pack->head->result = 0;
    req_pack->head->flags = stmt->conn->serveroutput ? CS_FLAG_SERVEROUPUT : 0;

    CT_RETURN_IFERR(clt_reset_execbatch_request(stmt, &exec_req_offset));

    if (stmt->batch_errs.allowed_count > 0) {
        req_pack->head->flags |= CT_FLAG_ALLOWED_BATCH_ERRS;
        CT_RETURN_IFERR(cs_put_int32(req_pack, stmt->batch_errs.allowed_count));
    }

    /* to ignore do realloc send pack many times in batch clt_put_params */
    if (stmt->paramset_size > 1) {
        once_paramset_size = (req_pack->max_buf_size - req_pack->head->size) / CM_ALIGN_8K(max_row_bndsz);
        once_paramset_size = MIN(once_paramset_size, stmt->paramset_size);
        (void)cs_try_realloc_send_pack(req_pack, once_paramset_size * max_row_bndsz);
    }

    while (offset < stmt->paramset_size) {
        CT_RETURN_IFERR(clt_put_params(stmt, offset, add_types));
        add_types = CT_FALSE;

        exec_req = (cs_execute_req_t *)CS_RESERVE_ADDR(req_pack, exec_req_offset);
        exec_req->paramset_size++;
        offset++;

        if ((req_pack->max_buf_size >= CM_REALLOC_SEND_PACK_SIZE(req_pack, max_row_bndsz)) &&
            (offset < stmt->paramset_size && exec_req->paramset_size < CT_MAX_UINT16)) {
            continue;
        }

        cs_putted_execute_req(req_pack, exec_req_offset);

        status = clt_remote_call(stmt->conn, req_pack, ack_pack);
        if (status == CT_SUCCESS) {
            CT_RETURN_IFERR(clt_try_receive_pl_proc_data(stmt, ack_pack));

            cs_init_get(ack_pack);
            CT_RETURN_IFERR(clt_try_process_feedback(stmt, ack_pack));
        }

        CT_RETURN_IFERR(clt_handle_execution_ack(stmt, ack_pack, line_offset));

        if (status == CT_ERROR) {
            return CT_ERROR;
        }

        if (offset == stmt->paramset_size) {
            break;
        }

        /* reset req packet for next batch execute */
        CT_RETURN_IFERR(clt_reset_execbatch_request(stmt, &exec_req_offset));
        req_pack->head->flags = stmt->conn->serveroutput ? CS_FLAG_SERVEROUPUT : 0;
        if (stmt->batch_errs.allowed_count - stmt->batch_errs.actual_count > 0) {
            req_pack->head->flags |= CT_FLAG_ALLOWED_BATCH_ERRS;
            CT_RETURN_IFERR(cs_put_int32(req_pack, stmt->batch_errs.allowed_count - stmt->batch_errs.actual_count));
        }

        add_types = CT_TRUE;
        line_offset = offset;
    }

    stmt->fetched_rows = 0;
    stmt->row_index = 0;
    stmt->eof = (stmt->return_rows == 0);
    stmt->status = CLI_STMT_EXECUTED;
    return CT_SUCCESS;
}

static status_t clt_execute_single(clt_stmt_t *stmt)
{
    cs_execute_req_t *exec_req = NULL;
    cs_packet_t *req_pack = &stmt->conn->pack;
    cs_packet_t *ack_pack = &stmt->cache_pack->pack;
    uint32 exec_req_offset;

    cs_init_set(req_pack, stmt->conn->call_version);
    req_pack->head->cmd = CS_CMD_EXECUTE;
    req_pack->head->flags = stmt->conn->serveroutput ? CS_FLAG_SERVEROUPUT : 0;

    CT_RETURN_IFERR(cs_reserve_space(req_pack, sizeof(cs_execute_req_t), &exec_req_offset));
    exec_req = (cs_execute_req_t *)CS_RESERVE_ADDR(req_pack, exec_req_offset);
    exec_req->stmt_id = stmt->stmt_id;
    exec_req->paramset_size = 1;
    exec_req->prefetch_rows = clt_prefetch_rows(stmt);
    exec_req->auto_commit = stmt->conn->auto_commit;
    exec_req->reserved = 0;
    cs_putted_execute_req(req_pack, exec_req_offset);

    if (stmt->batch_errs.allowed_count > 0) {
        req_pack->head->flags |= CT_FLAG_ALLOWED_BATCH_ERRS;
        CT_RETURN_IFERR(cs_put_int32(req_pack, stmt->batch_errs.allowed_count));
    }

    /* put param values */
    if (stmt->param_count != 0) {
        CT_RETURN_IFERR(clt_put_params(stmt, 0, CT_TRUE));
    }

    CT_RETURN_IFERR(clt_remote_call(stmt->conn, req_pack, ack_pack));
    CT_RETURN_IFERR(clt_try_receive_pl_proc_data(stmt, ack_pack));

    cs_init_get(&stmt->cache_pack->pack);
    CT_RETURN_IFERR(clt_try_process_feedback(stmt, ack_pack));
    CT_RETURN_IFERR(clt_get_execute_ack(stmt));
    
    /* DDL of DELETE ARCHIVELOG may has echo to display remove_list */
    if (stmt->stmt_type == CTCONN_STMT_DDL && CS_HAS_MORE(ack_pack)) {
        CT_RETURN_IFERR(clt_get_error_message(stmt->conn, ack_pack, stmt->conn->message));
    }

    /* DCL of backup may has echo to display badblock warning */
    if (stmt->stmt_type == CTCONN_STMT_DCL && CS_HAS_MORE(ack_pack)) {
        CT_RETURN_IFERR(clt_get_error_message(stmt->conn, ack_pack, stmt->conn->message));
    }

    stmt->status = CLI_STMT_EXECUTED;
    return CT_SUCCESS;
}

static status_t clt_execute(clt_stmt_t *stmt)
{
    status_t status;

    if (SECUREC_UNLIKELY(stmt->status < CLI_STMT_PREPARED)) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_OUT_OF_API_SEQUENCE, "statement is not prepared");
        return CT_ERROR;
    }

    clt_reset_stmt(stmt);

    if (clt_has_large_string(stmt)) {
        /* string to lob bind type column data will be writed to server here */
        CT_RETURN_IFERR(clt_write_large_string(stmt));
    }

    if (stmt->paramset_size <= 1 || stmt->param_count == 0) {
        status = clt_execute_single(stmt);
    } else {
        status = clt_execute_batch(stmt);
    }

    CT_RETURN_IFERR(clt_reset_stmt_transcode_buf(stmt));
    return status;
}

status_t ctconn_execute(ctconn_stmt_t pstmt)
{
    status_t status;
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;

    CTCONN_CHECK_OBJECT_NULL_GS(stmt, "statement");
    CTCONN_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");

    CT_RETURN_IFERR(clt_lock_conn(stmt->conn));

    if (clt_prepare_stmt_pack(stmt) != CT_SUCCESS) {
        clt_unlock_conn(stmt->conn);
        return CT_ERROR;
    }

    status = clt_execute(stmt);

    if (stmt->eof) {
        // no resultset in packet, free packet object.
        clt_recycle_stmt_pack(stmt);
    }
    clt_unlock_conn(stmt->conn);
    return status;
}

int32 clt_prepare_fetch(ctconn_stmt_t pstmt, unsigned int *rows, bool32 fetch_ori_row)
{
    status_t status;
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;
    uint32 temp_rows = 0;

    CTCONN_CHECK_OBJECT_NULL_GS(stmt, "statement");
    CTCONN_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");

    CT_RETURN_IFERR(clt_lock_conn(stmt->conn));

    if (clt_prepare_stmt_pack(stmt) != CT_SUCCESS) {
        clt_unlock_conn(stmt->conn);
        return CT_ERROR;
    }

    status = clt_fetch(stmt, &temp_rows, fetch_ori_row);

    if (temp_rows == 0) {
        clt_recycle_stmt_pack(stmt);
    }

    if (SECUREC_LIKELY(rows != NULL)) {
        *rows = temp_rows;
    }

    clt_unlock_conn(stmt->conn);
    return status;
}

static uint32 clt_fetch_serveroutput(clt_stmt_t *stmt, char **data, uint32 *len)
{
    clt_output_item_t *item = NULL;

    if (stmt->serveroutput.pos + 1 > stmt->serveroutput.output_count) {
        return 0;
    }

    item = (clt_output_item_t *)cm_list_get(&stmt->serveroutput.output_data, stmt->serveroutput.pos);

    if (SECUREC_LIKELY(data != NULL)) {
        *data = item->output.str;
    }

    if (SECUREC_LIKELY(len != NULL)) {
        *len = item->output.len;
    }

    stmt->serveroutput.pos++;
    return 1;
}

int ctconn_fetch_ori_row(ctconn_stmt_t pstmt, unsigned int *rows)
{
    return clt_prepare_fetch(pstmt, rows, CT_TRUE);
}

int32 ctconn_fetch(ctconn_stmt_t pstmt, uint32 *rows)
{
    return clt_prepare_fetch(pstmt, rows, CT_FALSE);
}

int32 ctconn_fetch_serveroutput(ctconn_stmt_t pstmt, char **data, uint32 *len)
{
    uint32 rows;
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;

    if (SECUREC_UNLIKELY(stmt == NULL)) {
        CT_THROW_ERROR(ERR_CLT_OBJECT_IS_NULL, "statement");
        return 0;
    }

    if (SECUREC_UNLIKELY(stmt->conn == NULL)) {
        CT_THROW_ERROR(ERR_CLT_OBJECT_IS_NULL, "connection");
        return 0;
    }

    if (clt_lock_conn(stmt->conn) != CT_SUCCESS) {
        return 0;
    }
    rows = clt_fetch_serveroutput(stmt, data, len);
    clt_unlock_conn(stmt->conn);
    return (int32)rows;
}

static status_t clt_decode_row(char *row_addr, bool32 diff_endian, uint16 *offsets, uint32 offsets_size, uint16 *lens)
{
    uint8 bits;
    uint32 i, pos, ex_maps;
    row_assist_t ra;

    cm_attach_row(&ra, row_addr);

    if (diff_endian) {
        ra.head->column_count = cs_reverse_int16(ra.head->column_count);
        if (IS_SPRS_ROW(ra.head)) {
            ra.head->sprs_count = cs_reverse_int16(ra.head->sprs_count);
        }

        ra.head->size = cs_reverse_int16(ra.head->size);
    }

    ex_maps = ROW_BITMAP_EX_SIZE(ra.head);
    pos = sizeof(row_head_t) + ex_maps;

    if (offsets_size < ROW_COLUMN_COUNT(ra.head)) {
        return CT_ERROR;
    }
    for (i = 0; i < ROW_COLUMN_COUNT(ra.head); i++) {
        bits = row_get_column_bits(&ra, i);
        offsets[i] = pos;

        if (bits == COL_BITS_8) {
            lens[i] = 8;
            pos += 8;
        } else if (bits == COL_BITS_4) {
            lens[i] = 4;
            pos += 4;
        } else if (bits == COL_BITS_NULL) {
            lens[i] = CTCONN_NULL;
        } else {
            lens[i] = *(uint16 *)(row_addr + pos);
            offsets[i] += sizeof(uint16);
            if (diff_endian) {
                lens[i] = cs_reverse_int16(lens[i]);
            }

            pos += CM_ALIGN4(lens[i] + sizeof(uint16));
        }
    }

    return CT_SUCCESS;
}

static status_t clt_read_output_row(clt_stmt_t *stmt)
{
    clt_outparam_t *outparam = NULL;
    char *row_addr = CS_READ_ADDR(&stmt->cache_pack->pack);
    uint16 row_size = *(uint16 *)row_addr;
    uint32 outparam_count = ROW_COLUMN_COUNT((row_head_t *)row_addr);
    uint16 offsets[CT_MAX_COLUMNS] = { 0 };
    uint16 lens[CT_MAX_COLUMNS] = { 0 };
    uint32 i, size;

    CT_RETURN_IFERR(clt_reset_stmt_transcode_buf(stmt));

    row_size = cs_format_endian_i16(stmt->cache_pack->pack.options, row_size);

    if (outparam_count != stmt->outparam_count) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_INVALID_COLUMN, outparam_count, "outparam", stmt->outparam_count);
        return CT_ERROR;
    }

    stmt->cache_pack->pack.offset += row_size;
    CT_RETURN_IFERR(
        clt_decode_row(row_addr, CS_DIFFERENT_ENDIAN(stmt->cache_pack->pack.options), offsets, CT_MAX_COLUMNS, lens));

    for (i = 0; i < stmt->outparam_count; i++) {
        outparam = cm_list_get(&stmt->outparams, i);
        outparam->size = lens[i];
        outparam->ptr = row_addr + offsets[i];

        if (outparam->size == CTCONN_NULL) {
            continue;
        }

        if (CTCONN_IS_STRING_TYPE(outparam->def.datatype) && stmt->conn->recv_trans_func != NULL) {
            size = outparam->size;
            if (clt_transcode_column(stmt, &outparam->ptr, &size, stmt->conn->recv_trans_func) != CT_SUCCESS) {
                CLT_THROW_ERROR(stmt->conn, ERR_CLT_TRANS_CHARSET, outparam->def.name, outparam->ptr);
                return CT_ERROR;
            }
            outparam->size = (uint16)size;
        }
    }

    return CT_SUCCESS;
}

static status_t clt_fetch_outparam(clt_stmt_t *stmt, uint32 *rows)
{
    CTCONN_CHECK_FETCH_STATUS(stmt);

    stmt->status = CLI_STMT_FETCHING;

    if (stmt->outparam_count == 0 || stmt->row_index >= 1) {
        stmt->eof = CT_TRUE;
        *rows = 0;
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(clt_read_output_row(stmt));
    stmt->row_index++;
    *rows = 1;

    return CT_SUCCESS;
}
status_t ctconn_fetch_outparam(ctconn_stmt_t pstmt, uint32 *rows)
{
    status_t status;
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;
    uint32 temp_rows = 0;

    CTCONN_CHECK_OBJECT_NULL_GS(stmt, "statement");
    CTCONN_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");

    CT_RETURN_IFERR(clt_lock_conn(stmt->conn));

    if (clt_prepare_stmt_pack(stmt) != CT_SUCCESS) {
        clt_unlock_conn(stmt->conn);
        return CT_ERROR;
    }

    status = clt_fetch_outparam(stmt, &temp_rows);

    if (temp_rows == 0) {
        clt_recycle_stmt_pack(stmt);
    }

    if (SECUREC_LIKELY(rows != NULL)) {
        *rows = temp_rows;
    }

    clt_unlock_conn(stmt->conn);
    return status;
}

static status_t clt_get_autotrace_result(clt_stmt_t *stmt)
{
    clt_reset_stmt(stmt);
    cs_packet_t *ack = &stmt->cache_pack->pack;

    CT_RETURN_IFERR(clt_async_get_ack(stmt->conn, ack));
    cs_init_get(ack);
    CT_RETURN_IFERR(clt_get_prepare_ack(stmt, ack, NULL));
    CT_RETURN_IFERR(clt_get_execute_ack(stmt));

    stmt->status = CLI_STMT_EXECUTED;
    return CT_SUCCESS;
}

status_t ctconn_get_autotrace_result(ctconn_stmt_t pstmt)
{
    status_t status;
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;

    CTCONN_CHECK_OBJECT_NULL_GS(stmt, "statement");
    CTCONN_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");

    CT_RETURN_IFERR(clt_lock_conn(stmt->conn));

    if (clt_prepare_stmt_pack(stmt) != CT_SUCCESS) {
        clt_unlock_conn(stmt->conn);
        return CT_ERROR;
    }

    status = clt_get_autotrace_result(stmt);

    clt_recycle_stmt_pack(stmt);
    clt_unlock_conn(stmt->conn);
    return status;
}

status_t ctconn_write_clob(ctconn_stmt_t pstmt, uint32 id, const void *data, uint32 size, uint32 *nchars)
{
    status_t status;
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;

    CTCONN_CHECK_OBJECT_NULL_GS(stmt, "statement");
    CTCONN_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");
    CTCONN_CHECK_OBJECT_NULL_CLT(stmt->conn, data, "clob data bound");

    if (stmt->paramset_size > 1) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_INVALID_BIND, "interface doesn't support bind batch clob");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(clt_lock_conn(stmt->conn));

    if (clt_prepare_stmt_pack(stmt) != CT_SUCCESS) {
        clt_unlock_conn(stmt->conn);
        return CT_ERROR;
    }

    status = clt_write_clob(stmt, id, 0, (const char *)data, size, nchars);

    clt_recycle_stmt_pack(stmt);
    clt_unlock_conn(stmt->conn);
    return status;
}

status_t ctconn_write_blob(ctconn_stmt_t pstmt, uint32 id, const void *data, uint32 size)
{
    status_t status;
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;

    CTCONN_CHECK_OBJECT_NULL_GS(stmt, "statement");
    CTCONN_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");
    CTCONN_CHECK_OBJECT_NULL_CLT(stmt->conn, data, "blob data bound");

    if (stmt->paramset_size > 1) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_INVALID_BIND, "interface doesn't support bind batch blob");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(clt_lock_conn(stmt->conn));

    if (clt_prepare_stmt_pack(stmt) != CT_SUCCESS) {
        clt_unlock_conn(stmt->conn);
        return CT_ERROR;
    }

    status = clt_write_blob(stmt, id, 0, (const char *)data, size);

    clt_recycle_stmt_pack(stmt);
    clt_unlock_conn(stmt->conn);
    return status;
}

status_t ctconn_write_batch_clob(ctconn_stmt_t pstmt, uint32 id, uint32 piece, const void *data, uint32 size, uint32 *nchars)
{
    status_t status;
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;

    CTCONN_CHECK_OBJECT_NULL_GS(stmt, "statement");
    CTCONN_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");
    CTCONN_CHECK_OBJECT_NULL_CLT(stmt->conn, data, "clob data bound");

    if (SECUREC_UNLIKELY(piece >= stmt->paramset_size)) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_INVALID_BIND, "invalid batch pos to bind clob");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(clt_lock_conn(stmt->conn));

    if (clt_prepare_stmt_pack(stmt) != CT_SUCCESS) {
        clt_unlock_conn(stmt->conn);
        return CT_ERROR;
    }

    status = clt_write_clob(stmt, id, piece, (const char *)data, size, nchars);

    clt_recycle_stmt_pack(stmt);
    clt_unlock_conn(stmt->conn);
    return status;
}

status_t ctconn_write_batch_blob(ctconn_stmt_t pstmt, uint32 id, uint32 piece, const void *data, uint32 size)
{
    status_t status;
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;

    CTCONN_CHECK_OBJECT_NULL_GS(stmt, "statement");
    CTCONN_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");
    CTCONN_CHECK_OBJECT_NULL_CLT(stmt->conn, data, "blob data bound");

    if (SECUREC_UNLIKELY(piece >= stmt->paramset_size)) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_INVALID_BIND, "invalid batch pos to bind blob");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(clt_lock_conn(stmt->conn));

    if (clt_prepare_stmt_pack(stmt) != CT_SUCCESS) {
        clt_unlock_conn(stmt->conn);
        return CT_ERROR;
    }

    status = clt_write_blob(stmt, id, piece, (const char *)data, size);

    clt_recycle_stmt_pack(stmt);
    clt_unlock_conn(stmt->conn);
    return status;
}

status_t clt_get_outparam_by_id(clt_stmt_t *stmt, uint32 id, void **data, uint32 *size, bool32 *is_null)
{
    clt_outparam_t *outparam = NULL;
    bool32 is_null_val;
    clt_stmt_t *sub_stmt = NULL;

    if (SECUREC_UNLIKELY(stmt->status < CLI_STMT_FETCHING)) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_OUT_OF_API_SEQUENCE, "statement is not fetched");
        return CT_ERROR;
    }

    if (SECUREC_UNLIKELY(id >= stmt->outparam_count || id >= stmt->outparams.count)) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_OUT_OF_INDEX, "outparam");
        return CT_ERROR;
    }

    outparam = (clt_outparam_t *)cm_list_get(&stmt->outparams, id);
    is_null_val = (outparam->size == CTCONN_NULL);

    if (SECUREC_LIKELY(size != NULL)) {
        *size = outparam->size;
    }

    if (SECUREC_LIKELY(is_null != NULL)) {
        *is_null = is_null_val;
    }

    if (SECUREC_LIKELY(data != NULL)) {
        *data = is_null_val ? NULL : outparam->ptr;

        // alloc stmt for open cursor in PL
        if (!is_null_val && outparam->def.datatype == CTCONN_TYPE_CURSOR) {
            if (outparam->sub_stmt != NULL) {
                *data = outparam->sub_stmt;
                return CT_SUCCESS;
            }

            CT_RETURN_IFERR(clt_alloc_stmt(stmt->conn, &sub_stmt));
            uint64 cursor_info = *(uint64 *)outparam->ptr;
            sub_stmt->stmt_id = (uint16)((cursor_info >> 32) & CT_TYPE_MASK_ALL);
            sub_stmt->fetch_mode = (uint8)(cursor_info & CT_TYPE_MASK_ALL);

            if (clt_prepare_stmt_pack(sub_stmt) != CT_SUCCESS || clt_remote_fetch(sub_stmt) != CT_SUCCESS) {
                clt_free_stmt(sub_stmt);
                return CT_ERROR;
            }
            sub_stmt->status = CLI_STMT_EXECUTED;
            sub_stmt->fetch_mode = 0;

            outparam->sub_stmt = sub_stmt;
            *data = sub_stmt;
        }
    }

    return CT_SUCCESS;
}
status_t ctconn_get_outparam_by_id(ctconn_stmt_t pstmt, uint32 id, void **data, uint32 *size, bool32 *is_null)
{
    status_t status;
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;

    CTCONN_CHECK_OBJECT_NULL_GS(stmt, "statement");
    CTCONN_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");

    CT_RETURN_IFERR(clt_lock_conn(stmt->conn));
    status = clt_get_outparam_by_id(stmt, id, data, size, is_null);
    clt_unlock_conn(stmt->conn);
    return status;
}

static status_t clt_get_outparam_by_name(clt_stmt_t *stmt, const char *name, void **data, uint32 *size, uint32 *is_null)
{
    clt_outparam_t *outparam = NULL;
    uint32 i;

    for (i = 0; i < stmt->outparam_count && i < stmt->outparams.count; i++) {
        // get the i-th outparam
        outparam = (clt_outparam_t *)cm_list_get(&stmt->outparams, i);
        if (cm_str_equal_ins(name, outparam->def.name)) {
            return clt_get_outparam_by_id(stmt, i, data, size, is_null);
        }
    }

    CLT_THROW_ERROR(stmt->conn, ERR_CLT_INVALID_ATTR, "outparam name", name);
    return CT_ERROR;
}
status_t ctconn_get_outparam_by_name(ctconn_stmt_t pstmt, const char *name, void **data, uint32 *size, uint32 *is_null)
{
    status_t status;
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;

    CTCONN_CHECK_OBJECT_NULL_GS(stmt, "statement");
    CTCONN_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");
    CTCONN_CHECK_OBJECT_NULL_CLT(stmt->conn, name, "name");

    CT_RETURN_IFERR(clt_lock_conn(stmt->conn));
    status = clt_get_outparam_by_name(stmt, name, data, size, is_null);
    clt_unlock_conn(stmt->conn);
    return status;
}

#ifdef __cplusplus
}
#endif
