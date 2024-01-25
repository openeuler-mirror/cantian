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
 * gsc_shard.c
 *
 *
 * IDENTIFICATION
 * src/driver/gsc/gsc_shard.c
 *
 * -------------------------------------------------------------------------
 */
#include "gsc_shard.h"
#include "gsc_stmt.h"
#include "gsc_fetch.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef Z_SHARDING
status_t gsc_fetch_raw(gsc_stmt_t pstmt)
{
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;

    GSC_CHECK_OBJECT_NULL_GS(stmt, "statement");
    GSC_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");

    return clt_remote_fetch(stmt);
}

status_t gsc_fetch_data(gsc_stmt_t pstmt, uint32 *rows)
{
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;

    GSC_CHECK_OBJECT_NULL_GS(stmt, "statement");
    GSC_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");
    GSC_CHECK_FETCH_STATUS(stmt);

    stmt->status = CLI_STMT_FETCHING;

    if (stmt->row_index < stmt->return_rows) {
        *rows = stmt->return_rows;
        stmt->row_index = stmt->return_rows;
        return CT_SUCCESS;
    }

    if (stmt->more_rows) {
        CT_RETURN_IFERR(clt_remote_fetch(stmt));
    } else {
        *rows = 0;
        return CT_SUCCESS;
    }

    if (stmt->eof) {
        *rows = 0;
        return CT_SUCCESS;
    }

    *rows = stmt->return_rows;
    stmt->row_index = stmt->return_rows;
    return CT_SUCCESS;
}

status_t gsc_fetch_data_ack(gsc_stmt_t pstmt, char **data, uint32 *size)
{
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;

    GSC_CHECK_OBJECT_NULL_GS(stmt, "statement");

    *data = CS_READ_ADDR(&stmt->cache_pack->pack);
    *size = stmt->cache_pack->pack.head->size - stmt->cache_pack->pack.offset;
    return CT_SUCCESS;
}

status_t gsc_fetch_data_attr_ack(gsc_stmt_t pstmt, uint32 *options, uint32 *return_rows)
{
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;
    if (stmt == NULL) {
        CT_THROW_ERROR(ERR_CLT_OBJECT_IS_NULL, "statement");
        return CT_ERROR;
    }
    *options = stmt->cache_pack->pack.options;
    *return_rows = stmt->return_rows;
    return CT_SUCCESS;
}

static status_t clt_realloc_batch_buf(clt_stmt_t *clt_stmt, uint32 expect_size)
{
    uint32 buf_used = (uint32)(clt_stmt->batch_curr_ptr - clt_stmt->batch_bnd_ptr);
    errno_t errcode;

    if (buf_used + expect_size > clt_stmt->max_batch_buf_size) {
        uint32 new_buf_size = buf_used + (expect_size / SIZE_K(8) + 1) * SIZE_K(8); // expand buf memory in units of 8K
        if (new_buf_size == 0) {
            CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)new_buf_size, "batch operation");
            return CT_ERROR;
        }

        char *new_buf = (char *)malloc(new_buf_size);
        if (new_buf == NULL) {
            CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)new_buf_size, "batch operation");
            return CT_ERROR;
        }
        if (buf_used != 0) {
            errcode = memcpy_s(new_buf, new_buf_size, clt_stmt->batch_bnd_ptr, buf_used);
            if (errcode != EOK) {
                CM_FREE_PTR(new_buf);
                CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
                return CT_ERROR;
            }
        }

        CM_FREE_PTR(clt_stmt->batch_bnd_ptr);
        clt_stmt->batch_bnd_ptr = new_buf;
        clt_stmt->batch_curr_ptr = clt_stmt->batch_bnd_ptr + buf_used;
        clt_stmt->max_batch_buf_size = new_buf_size;
    }

    return CT_SUCCESS;
}

status_t gsc_init_paramset_length(gsc_stmt_t pstmt)
{
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;

    GSC_CHECK_OBJECT_NULL_GS(stmt, "statement");

    CT_RETURN_IFERR(clt_realloc_batch_buf(stmt, sizeof(uint32)));

    // a row format: total_len(4bytes) + [cs_param_head_t + value] + ... + [cs_param_head_t + value]
    stmt->paramset_len_offset = (uint32)(stmt->batch_curr_ptr - stmt->batch_bnd_ptr);
    *((uint32 *)stmt->batch_curr_ptr) = sizeof(uint32); // total length when put_param
    stmt->batch_curr_ptr += sizeof(uint32);

    return CT_SUCCESS;
}

#define PARAMSET_LENGTH_ADD(stmt, value) *(uint32 *)((stmt)->batch_bnd_ptr + (stmt)->paramset_len_offset) += (value);

status_t gsc_bind_by_pos_batch(gsc_stmt_t pstmt, uint32 pos, int32 type, const void *data, uint32 size, bool32 is_null)
{
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;

    GSC_CHECK_OBJECT_NULL_GS(stmt, "statement");

    if (stmt->status != CLI_STMT_PRE_PARAMS) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_OUT_OF_API_SEQUENCE, "sql is not in preprocess params for batch");
        return CT_ERROR;
    }

    if (pos >= stmt->param_count) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_OUT_OF_INDEX, "parameter");
        return CT_ERROR;
    }

    PARAMSET_LENGTH_ADD(stmt, sizeof(cs_param_head_t));
    PARAMSET_LENGTH_ADD(stmt, CM_ALIGN4(size));

    CT_RETURN_IFERR(clt_realloc_batch_buf(stmt, sizeof(cs_packet_head_t) + size));

    cs_param_head_t *head = (cs_param_head_t *)stmt->batch_curr_ptr;
    stmt->batch_curr_ptr += sizeof(cs_param_head_t);

    // Hint : this head->len is different with clt_put_param
    head->len = size;
    head->type = type;
    head->flag = 0;
    clt_set_param_direction(GSC_INPUT, &head->flag);

    if (is_null == CT_TRUE) {
        head->flag |= 0x01;
    } else {
        // copy the data...
        if (size != 0) {
            MEMS_RETURN_IFERR(memcpy_s(stmt->batch_curr_ptr, size, data, size));
        }
        // add a terminator '\0' for string
        if (type == GSC_TYPE_STRING || type == GSC_TYPE_VARCHAR || type == GSC_TYPE_CHAR) {
            stmt->batch_curr_ptr[size - 1] = '\0';
        }
        stmt->batch_curr_ptr += size;
    }

    return CT_SUCCESS;
}

// DML for CN bind params to DN
status_t gsc_init_params(gsc_stmt_t pstmt, uint32 param_count, bool32 is_batch)
{
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;

    GSC_CHECK_OBJECT_NULL_GS(stmt, "statement");

    stmt->paramset_size = 0;
    stmt->param_count = param_count;

    if (is_batch == CT_TRUE) {
        // if not point to an available buffer (default buffer or dynamicly extended buffer) already.
        // use the default buffer.
        if (stmt->batch_bnd_ptr == NULL) {
            stmt->batch_bnd_ptr = (char *)malloc(CT_MAX_PACKET_SIZE);
            if (stmt->batch_bnd_ptr == NULL) {
                CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)CT_MAX_PACKET_SIZE, "batch bind parameters");
                return CT_ERROR;
            }
            stmt->max_batch_buf_size = CT_MAX_PACKET_SIZE;
        }
    } else {
        // free the dynamicly extended buffer
        CM_FREE_PTR(stmt->batch_bnd_ptr);
        stmt->max_batch_buf_size = 0;
    }

    stmt->batch_curr_ptr = stmt->batch_bnd_ptr;
    stmt->paramset_len_offset = 0;

    // in case of (SQL + parameters) large than CT_MAX_PACKET_SIZE
    stmt->offset = 0;
    stmt->can_read_ack = CT_FALSE;

    cm_destroy_list(&stmt->batch_errs.err_list);
    stmt->batch_errs.actual_count = 0;
    stmt->batch_errs.allowed_count = 0;

    if (stmt->param_count == 0) {
        return CT_SUCCESS;
    }

    // beacuse of stmt reuse. maybe stmt->params has no enough space.
    if (stmt->params.count < stmt->param_count) {
        CT_RETURN_IFERR(clt_extend_param_list(stmt, stmt->param_count));
    }

    // for batch operation, this initialize of clt_param is useless.
    clt_param_t *param = NULL;
    for (uint32 i = 0; i < stmt->param_count; i++) {
        param = (clt_param_t *)cm_list_get(&stmt->params, i);
        param->bnd_ptr = NULL;
        param->ind_ptr = NULL;
        param->bnd_type = GSC_TYPE_INTEGER;
        param->bnd_size = 0;
        CM_FREE_PTR(param->lob_ptr);
        param->lob_ptr_size = 0;
    }

    stmt->status = CLI_STMT_PRE_PARAMS;

    return CT_SUCCESS;
}

void gsc_paramset_size_inc(gsc_stmt_t pstmt)
{
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;
    stmt->paramset_size++;
}

status_t gsc_pe_prepare(gsc_stmt_t pstmt, const char *sql, uint64 *scn)
{
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;
    cs_packet_t *req_pack = NULL;
    uint32 req_offset;

    GSC_CHECK_OBJECT_NULL_GS(stmt, "statement");
    GSC_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");
    GSC_CHECK_OBJECT_NULL_CLT(stmt->conn, sql, "sql");

    req_pack = &stmt->conn->pack;

    cs_init_set(req_pack, stmt->conn->call_version);
    req_pack->head->cmd = CS_CMD_PREP_AND_EXEC;

    CT_RETURN_IFERR(cs_reserve_space(req_pack, sizeof(cs_prepare_req_t), &req_offset));
    stmt->req = (cs_prepare_req_t *)CS_RESERVE_ADDR(req_pack, req_offset);
    stmt->req->flags = 0;
    stmt->req->stmt_id = stmt->stmt_id;
    cs_putted_prepare_req(req_pack, req_offset);
    if (stmt->conn->call_version >= CS_VERSION_11) {
        CT_RETURN_IFERR(cs_put_alter_set(req_pack, stmt));
    }

    /* strong consistency */
    if (scn != NULL) {
        req_pack->head->flags |= CS_FLAG_WITH_TS;
        CT_RETURN_IFERR(cs_put_scn(req_pack, scn));
    }

    if (stmt->conn->call_version >= CS_VERSION_17) {
        stmt->req->flags |= CS_CN_DML_ID;
        CT_RETURN_IFERR(cs_put_int32(req_pack, stmt->shard_dml_id));
    }

    text_t text;
    text.str = (char *)sql;
    text.len = (uint32)strlen(sql);
    CT_RETURN_IFERR(cs_put_text(req_pack, &text));

    if (stmt->status != CLI_STMT_PRE_PARAMS) {
        stmt->param_count = 0;
    }

    stmt->status = CLI_STMT_PREPARED;
    return CT_SUCCESS;
}

status_t gsc_pe_async_execute(gsc_stmt_t pstmt, uint32 *more_param)
{
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;
    cs_packet_t *req_pack = NULL;
    cs_prep_exec_param *exe_param = NULL;
    uint32 exe_param_offset;
    bool32 add_types = CT_TRUE;

    GSC_CHECK_OBJECT_NULL_GS(stmt, "statement");
    GSC_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");
    CT_RETURN_IFERR(clt_prepare_stmt_pack(stmt));
    if (clt_has_large_string(stmt)) {
        /* string to lob bind type column data will be writed to server here */
        CT_RETURN_IFERR(clt_write_large_string(stmt));
        if (stmt->req != NULL && stmt->stmt_id != CT_INVALID_ID16) {
            stmt->req->stmt_id = stmt->stmt_id;
        }
    }

    req_pack = &stmt->conn->pack;

    *more_param = CT_FALSE;

    CT_RETURN_IFERR(cs_reserve_space(req_pack, sizeof(cs_prep_exec_param), &exe_param_offset));
    exe_param = (cs_prep_exec_param *)CS_RESERVE_ADDR(req_pack, exe_param_offset);
    GSC_INIT_PREP_EXEC_PARAM(exe_param, stmt);

    if (stmt->batch_errs.allowed_count > 0) {
        req_pack->head->flags |= CT_FLAG_ALLOWED_BATCH_ERRS;
        CT_RETURN_IFERR(cs_put_int32(req_pack, stmt->batch_errs.allowed_count));
    }

    while (stmt->offset < stmt->paramset_size) {
        // Hint: at least one parameter-set with a SQ statementL; SQL + 1 parameter
        // / 1. the package cat store at least one parameter-set with a SQ statementL; SQL + 1 parameter
        // / 2. for batch operation, if it satisfy 1, split the batch parameter set;
        // only for batch operation;
        if (stmt->batch_bnd_ptr != NULL) {
            if (stmt->offset == 0) {
                stmt->batch_curr_ptr = stmt->batch_bnd_ptr;
            }

            // the maximal binding size of a row
            uint32 max_row_bndsz =
                *((uint32 *)stmt->batch_curr_ptr) + (sizeof(cs_param_head_t) + sizeof(int32)) * stmt->param_count;
            // at least one row;
            if (CM_REALLOC_SEND_PACK_SIZE(req_pack, max_row_bndsz) > req_pack->max_buf_size && stmt->offset != 0) {
                *more_param = CT_TRUE;
                break;
            }
            stmt->batch_curr_ptr += sizeof(uint32);
        }

        if (clt_put_params(stmt, stmt->offset, add_types) != CT_SUCCESS) {
            clt_copy_local_error(stmt->conn);
            return CT_ERROR;
        }
        add_types = CT_FALSE;
        /* after "clt_put_params" exe_param should be refresh by "CS_RESERVE_ADDR" */
        exe_param = (cs_prep_exec_param *)CS_RESERVE_ADDR(req_pack, exe_param_offset);
        exe_param->paramset_size++;
        stmt->offset++;
    }

    CS_SERIAL_NUMBER_INC(stmt->conn, req_pack);
    if (cs_write(&stmt->conn->pipe, req_pack) != CT_SUCCESS) {
        clt_copy_local_error(stmt->conn);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t gsc_pe_async_execute_ack(gsc_stmt_t pstmt, const char *sql, uint64 *ack_scn)
{
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;
    cs_packet_t *ack_pack = NULL;
    text_t sql_text;

    GSC_CHECK_OBJECT_NULL_GS(stmt, "statement");
    GSC_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");
    GSC_CHECK_OBJECT_NULL_CLT(stmt->conn, sql, "sql");

    sql_text.str = (char *)sql;
    sql_text.len = (uint32)strlen(sql);

    CT_RETURN_IFERR(clt_prepare_stmt_pack(stmt));
    ack_pack = &stmt->cache_pack->pack;
    CT_RETURN_IFERR(clt_async_get_ack(stmt->conn, ack_pack));

    cs_init_get(ack_pack);
    CT_RETURN_IFERR(clt_get_prepare_ack(stmt, ack_pack, &sql_text));
    CT_RETURN_IFERR(clt_get_execute_ack(stmt));

    if (CS_XACT_WITH_TS(ack_pack->head->flags)) {
        if (ack_scn == NULL) {
            return CT_ERROR;
        }
        *ack_scn = stmt->scn;
    }

    stmt->status = CLI_STMT_EXECUTED;
    return CT_SUCCESS;
}

status_t gsc_async_execute(gsc_stmt_t pstmt, bool32 *more_param, uint64 *scn)
{
    cs_packet_t *req_pack = NULL;
    cs_execute_req_t *exec_req = NULL;
    uint32 exec_req_offset;
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;
    bool32 add_types = CT_TRUE;

    GSC_CHECK_OBJECT_NULL_GS(stmt, "statement");
    GSC_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");

    req_pack = &stmt->conn->pack;

    *more_param = CT_FALSE;

    // 1. no param -- request
    // 2. no more param -- no request
    // for the splitting package from CN to DN
    if (stmt->offset == stmt->paramset_size && stmt->offset != 0) {
        // done , all paramsets' request has handled
        stmt->can_read_ack = CT_FALSE;
        return CT_SUCCESS;
    }

    cs_init_set(req_pack, stmt->conn->call_version);
    CS_SERIAL_NUMBER_INC(stmt->conn, req_pack);
    req_pack->head->cmd = CS_CMD_EXECUTE;
    req_pack->head->result = 0;
    req_pack->head->flags = 0;

    /* strong consistency */
    if (scn != NULL) {
        req_pack->head->flags |= CS_FLAG_WITH_TS;
        CT_RETURN_IFERR(cs_put_scn(req_pack, scn));
    }

    CT_RETURN_IFERR(cs_reserve_space(req_pack, sizeof(cs_execute_req_t), &exec_req_offset));
    exec_req = (cs_execute_req_t *)CS_RESERVE_ADDR(req_pack, exec_req_offset);
    exec_req->stmt_id = stmt->stmt_id;
    exec_req->paramset_size = 0;
    exec_req->prefetch_rows = clt_prefetch_rows(stmt);
    exec_req->auto_commit = stmt->conn->auto_commit;
    exec_req->reserved = 0;

    if (stmt->batch_errs.allowed_count > 0) {
        req_pack->head->flags |= CT_FLAG_ALLOWED_BATCH_ERRS;
        CT_RETURN_IFERR(cs_put_int32(req_pack, stmt->batch_errs.allowed_count));
    }

    uint32 send_count = 0;
    while (stmt->offset < stmt->paramset_size) {
        // Hint: at least one parameter-set with a SQ statementL; SQL + 1 parameter
        // / 1. the package cat store at least one parameter-set with a SQ statementL; SQL + 1 parameter
        // / 2. for batch operation, if it satisfy 1, split the batch parameter set;
        // only for batch operation;
        if (stmt->batch_bnd_ptr != NULL) {
            /* format
            paramset :  | paramset_length (uint32) | param_info_1 | param_info_2 | ... | param_info_n |
            param_info: | cs_param_head_t | param_value (string contains terminator '\0') |
            */
            if (stmt->offset == 0) {
                stmt->batch_curr_ptr = stmt->batch_bnd_ptr;
            }

            // the maximal binding size of a row
            uint32 max_row_bndsz =
                *((uint32 *)stmt->batch_curr_ptr) + (sizeof(cs_param_head_t) + sizeof(int32)) * stmt->param_count;
            // at least one row
            if (send_count != 0 && CM_REALLOC_SEND_PACK_SIZE(req_pack, max_row_bndsz) > req_pack->max_buf_size) {
                *more_param = CT_TRUE;
                break;
            }
            stmt->batch_curr_ptr += sizeof(uint32);
        }

        CT_RETURN_IFERR(clt_put_params(stmt, stmt->offset, add_types));
        add_types = CT_FALSE;

        /* after "clt_put_params" exec_req should be refresh by "CS_RESERVE_ADDR" */
        exec_req = (cs_execute_req_t *)CS_RESERVE_ADDR(req_pack, exec_req_offset);
        exec_req->paramset_size++;
        stmt->offset++;
        send_count++;
    }

    cs_putted_execute_req(req_pack, exec_req_offset);

    if (cs_write(&stmt->conn->pipe, req_pack) != CT_SUCCESS) {
        clt_copy_local_error(stmt->conn);
        return CT_ERROR;
    }

    stmt->can_read_ack = CT_TRUE;

    return CT_SUCCESS;
}

status_t gsc_async_execute_ack(gsc_stmt_t pstmt, uint64 *ack_scn)
{
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;
    cs_packet_t *ack_pack = NULL;

    GSC_CHECK_OBJECT_NULL_GS(stmt, "statement");
    GSC_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");

    CT_RETURN_IFERR(clt_prepare_stmt_pack(stmt));
    ack_pack = &stmt->cache_pack->pack;

    if (!stmt->can_read_ack) {
        stmt->affected_rows = 0;
        return CT_SUCCESS;
    }
    // reset the flag before read ack;
    stmt->can_read_ack = CT_FALSE;

    CT_RETURN_IFERR(clt_async_get_ack(stmt->conn, ack_pack));

    cs_init_get(ack_pack);
    CT_RETURN_IFERR(clt_get_execute_ack(stmt));

    if (CS_XACT_WITH_TS(ack_pack->head->flags)) {
        if (ack_scn == NULL) {
            return CT_ERROR;
        }
        *ack_scn = stmt->scn;
    }

    stmt->status = CLI_STMT_EXECUTED;
    return CT_SUCCESS;
}

static status_t send_cmd(gsc_conn_t pconn, uint8 cmd)
{
    clt_conn_t *conn = (clt_conn_t *)pconn;
    cs_packet_t *req_pack = NULL;

    GSC_CHECK_OBJECT_NULL_GS(conn, "connection");

    req_pack = &conn->pack;
    cs_init_set(req_pack, conn->call_version);
    req_pack->head->cmd = cmd;
    CS_SERIAL_NUMBER_INC(conn, req_pack);

    if (cs_write(&conn->pipe, req_pack) != CT_SUCCESS) {
        clt_copy_local_error(conn);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t gsc_async_commit(gsc_conn_t pconn)
{
    return send_cmd(pconn, CS_CMD_COMMIT);
}

status_t gsc_async_commit_ack(gsc_conn_t pconn)
{
    return clt_async_get_ack((clt_conn_t *)pconn, &((clt_conn_t *)pconn)->pack);
}

status_t gsc_async_rollback(gsc_conn_t pconn)
{
    return send_cmd(pconn, CS_CMD_ROLLBACK);
}

status_t gsc_async_rollback_ack(gsc_conn_t pconn)
{
    return clt_async_get_ack((clt_conn_t *)pconn, &((clt_conn_t *)pconn)->pack);
}

status_t gsc_statement_rollback(gsc_conn_t pconn, uint32 dml_id)
{
    clt_conn_t *conn = (clt_conn_t *)pconn;
    cs_packet_t *req_pack = NULL;
    cs_packet_t *ack_pack = NULL;

    GSC_CHECK_OBJECT_NULL_GS(conn, "connection");

    req_pack = &conn->pack;
    ack_pack = &conn->pack;
    cs_init_set(req_pack, conn->call_version);
    req_pack->head->cmd = CS_CMD_STMT_ROLLBACK;

    CT_RETURN_IFERR(cs_put_int32(req_pack, dml_id));

    return clt_remote_call(conn, req_pack, ack_pack);
}

status_t gsc_gts(gsc_conn_t pconn, uint64 *scn)
{
    clt_conn_t *conn = (clt_conn_t *)pconn;
    cs_packet_t *req_pack = NULL;
    cs_packet_t *ack_pack = NULL;

    GSC_CHECK_OBJECT_NULL_GS(conn, "connection");

    req_pack = &conn->pack;
    ack_pack = &conn->pack;

    cs_init_set(req_pack, conn->call_version);
    req_pack->head->cmd = CS_CMD_GTS;
    CT_RETURN_IFERR(clt_remote_call(conn, req_pack, ack_pack));

    cs_init_get(ack_pack);
    return cs_get_scn(ack_pack, scn);
}

status_t gsc_shard_prepare(gsc_stmt_t pstmt, const char *sql)
{
    return gsc_prepare(pstmt, sql);
}

status_t gsc_shard_execute(gsc_stmt_t pstmt)
{
    return gsc_execute(pstmt);
}

status_t gsc_fetch_sequence(gsc_stmt_t pstmt, text_t *user, text_t *seq_name, gsc_sequence_t *gsc_seq)
{
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;
    cs_packet_t *req_pack = NULL;
    cs_packet_t *ack_pack = NULL;

    GSC_CHECK_OBJECT_NULL_GS(stmt, "statement");
    GSC_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");

    req_pack = &stmt->conn->pack;
    ack_pack = &stmt->conn->pack;
    cs_init_set(req_pack, stmt->conn->call_version);
    req_pack->head->cmd = CS_CMD_SEQUENCE;

    CT_RETURN_IFERR(cs_put_int32(req_pack, SEQ_FETCH_CACHE));
    CT_RETURN_IFERR(cs_put_text(req_pack, user));
    CT_RETURN_IFERR(cs_put_text(req_pack, seq_name));
    CT_RETURN_IFERR(cs_put_int32(req_pack, gsc_seq->group_order));
    CT_RETURN_IFERR(cs_put_int32(req_pack, gsc_seq->group_cnt));
    CT_RETURN_IFERR(cs_put_int32(req_pack, gsc_seq->size));

    CT_RETURN_IFERR(clt_remote_call(stmt->conn, req_pack, ack_pack));

    cs_init_get(ack_pack);
    CT_RETURN_IFERR(cs_get_int64(ack_pack, (int64 *)&gsc_seq->start_val));
    CT_RETURN_IFERR(cs_get_int64(ack_pack, (int64 *)&gsc_seq->step));
    CT_RETURN_IFERR(cs_get_int64(ack_pack, (int64 *)&gsc_seq->end_val));

    return CT_SUCCESS;
}

status_t gsc_set_sequence_nextval(gsc_stmt_t pstmt, text_t *user, text_t *seq_name, int64 currval)
{
    status_t status = CT_SUCCESS;
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;
    cs_packet_t *req_pack = NULL;
    cs_packet_t *ack_pack = NULL;

    GSC_CHECK_OBJECT_NULL_GS(stmt, "statement");
    GSC_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");
    CT_RETURN_IFERR(clt_lock_conn(stmt->conn));

    req_pack = &stmt->conn->pack;
    ack_pack = &stmt->conn->pack;
    cs_init_set(req_pack, stmt->conn->call_version);
    req_pack->head->cmd = CS_CMD_SEQUENCE;

    do {
        status = cs_put_int32(req_pack, SEQ_SET_NEXTVAL);
        CT_BREAK_IF_ERROR(status);

        status = cs_put_text(req_pack, user);
        CT_BREAK_IF_ERROR(status);

        status = cs_put_text(req_pack, seq_name);
        CT_BREAK_IF_ERROR(status);

        status = cs_put_int64(req_pack, currval);
        CT_BREAK_IF_ERROR(status);
    } while (0);

    if (status != CT_SUCCESS) {
        clt_unlock_conn(stmt->conn);
        return CT_ERROR;
    }

    status = clt_remote_call(stmt->conn, req_pack, ack_pack);
    clt_unlock_conn(stmt->conn);
    return status;
}

status_t gsc_get_sequence_nextval(gsc_stmt_t pstmt, text_t *user, text_t *seq_name, int64 *value)
{
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;
    cs_packet_t *req_pack = NULL;
    cs_packet_t *ack_pack = NULL;

    GSC_CHECK_OBJECT_NULL_GS(stmt, "statement");
    GSC_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");

    req_pack = &stmt->conn->pack;
    ack_pack = &stmt->conn->pack;
    cs_init_set(req_pack, stmt->conn->call_version);
    req_pack->head->cmd = CS_CMD_SEQUENCE;

    CT_RETURN_IFERR(cs_put_int32(req_pack, SEQ_GET_NEXTVAL));
    CT_RETURN_IFERR(cs_put_text(req_pack, user));
    CT_RETURN_IFERR(cs_put_text(req_pack, seq_name));
    CT_RETURN_IFERR(clt_remote_call(stmt->conn, req_pack, ack_pack));

    cs_init_get(ack_pack);
    CT_RETURN_IFERR(cs_get_int64(ack_pack, (int64 *)value));

    return CT_SUCCESS;
}

status_t gsc_get_cn_nextval(gsc_stmt_t pstmt, text_t *user, text_t *seq_name, bool32 *empty_cache, int64 *value)
{
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;
    cs_packet_t *req_pack = NULL;
    cs_packet_t *ack_pack = NULL;

    GSC_CHECK_OBJECT_NULL_GS(stmt, "statement");
    GSC_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");

    req_pack = &stmt->conn->pack;
    ack_pack = &stmt->conn->pack;
    cs_init_set(req_pack, stmt->conn->call_version);
    req_pack->head->cmd = CS_CMD_SEQUENCE;

    CT_RETURN_IFERR(cs_put_int32(req_pack, SEQ_GET_CN_NEXTVAL));
    CT_RETURN_IFERR(cs_put_text(req_pack, user));
    CT_RETURN_IFERR(cs_put_text(req_pack, seq_name));
    CT_RETURN_IFERR(clt_remote_call(stmt->conn, req_pack, ack_pack));

    cs_init_get(ack_pack);
    CT_RETURN_IFERR(cs_get_int32(ack_pack, (int32 *)empty_cache));
    CT_RETURN_IFERR(cs_get_int64(ack_pack, (int64 *)value));
    return CT_SUCCESS;
}

status_t gsc_notify_cn_update_cache(gsc_stmt_t pstmt, text_t *user, text_t *seq_name)
{
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;
    cs_packet_t *req_pack = NULL;
    cs_packet_t *ack_pack = NULL;

    GSC_CHECK_OBJECT_NULL_GS(stmt, "statement");
    GSC_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");

    req_pack = &stmt->conn->pack;
    ack_pack = &stmt->conn->pack;
    cs_init_set(req_pack, stmt->conn->call_version);
    req_pack->head->cmd = CS_CMD_SEQUENCE;

    CT_RETURN_IFERR(cs_put_int32(req_pack, SEQ_ALTER_NOTIFY));
    CT_RETURN_IFERR(cs_put_text(req_pack, user));
    CT_RETURN_IFERR(cs_put_text(req_pack, seq_name));

    return clt_remote_call(stmt->conn, req_pack, ack_pack);
}

status_t gsc_decode_scn(clt_conn_t *conn, cs_packet_t *ack_pack, uint64 *scn)
{
    if (!CS_XACT_WITH_TS(ack_pack->head->flags)) {
        return CT_SUCCESS;
    }

    if (scn == NULL) {
        return CT_ERROR;
    }

    cs_init_get(ack_pack);
    return cs_get_scn(ack_pack, scn);
}

static status_t gsc_commit_with_ts_core(clt_conn_t *conn, uint64 *scn)
{
    cs_packet_t *req_pack = NULL;
    cs_packet_t *ack_pack = NULL;
    req_pack = &conn->pack;
    ack_pack = &conn->pack;

    cs_init_set(req_pack, conn->call_version);
    req_pack->head->cmd = CS_CMD_COMMIT;

    if (scn != NULL) {
        req_pack->head->flags |= CS_FLAG_WITH_TS;
        CT_RETURN_IFERR(cs_put_scn(req_pack, scn));
    } else {
        CT_BIT_RESET(req_pack->head->flags, CS_FLAG_WITH_TS);
    }

    if (clt_remote_call(conn, req_pack, ack_pack) != CT_SUCCESS) {
        clt_copy_local_error(conn);
        return CT_ERROR;
    }

    return gsc_decode_scn(conn, ack_pack, scn);
}

status_t gsc_commit_with_ts(gsc_conn_t pconn, uint64 *scn)
{
    status_t status;
    clt_conn_t *conn = (clt_conn_t *)pconn;

    GSC_CHECK_OBJECT_NULL_GS(conn, "connection");

    CT_RETURN_IFERR(clt_lock_conn(conn));
    status = gsc_commit_with_ts_core(conn, scn);
    clt_unlock_conn(conn);
    return status;
}

int32 gsc_set_pipe_timeout(gsc_conn_t conn, uint32 timeout)
{
    clt_conn_t *clt_conn = (clt_conn_t *)conn;
    uint32 timeout_ms;
    if (opr_uint32mul_overflow(timeout, CT_TIME_THOUSAND_UN, &timeout_ms) || timeout_ms > CT_MAX_INT32) {
        CLT_THROW_ERROR(clt_conn, ERR_CLT_INVALID_VALUE, "socket timeout value", timeout);
        return CT_ERROR;
    }

    clt_conn->pipe.socket_timeout = (timeout_ms == 0) ? (-1) : ((int32)timeout_ms);
    return CT_SUCCESS;
}

void gsc_reset_pipe_timeout(gsc_conn_t conn)
{
    clt_conn_t *clt_conn = (clt_conn_t *)conn;
    int32 origin = clt_conn->options.socket_timeout;
    clt_conn->pipe.socket_timeout = (origin == -1) ? origin : origin * CT_TIME_THOUSAND;
}

void gsc_force_close_pipe(gsc_conn_t conn)
{
    clt_conn_t *clt_conn = (clt_conn_t *)conn;
    cs_disconnect(&clt_conn->pipe);
}

void gsc_shutdown_pipe(gsc_conn_t conn)
{
    clt_conn_t *clt_conn = (clt_conn_t *)conn;
    cs_shutdown(&clt_conn->pipe);
}

cli_db_role_t gsc_get_db_role(gsc_conn_t conn)
{
    clt_conn_t *clt_conn = (clt_conn_t *)conn;
    return clt_conn->server_info.db_role;
}

#endif

#ifdef __cplusplus
}
#endif
