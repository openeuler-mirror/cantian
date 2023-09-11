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
 * gsc_common.c
 *
 *
 * IDENTIFICATION
 * src/driver/gsc/gsc_common.c
 *
 * -------------------------------------------------------------------------
 */
#include "gsc_common.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t clt_alloc_pack(clt_conn_t *conn, clt_packet_t **clt_pack)
{
    clt_packet_t *new_clt_pack = NULL;
    for (uint32 i = 0; i < conn->pack_list.count; i++) {
        new_clt_pack = (clt_packet_t *)cm_list_get(&conn->pack_list, i);
        if (!new_clt_pack->used) {
            new_clt_pack->used = GS_TRUE;
            *clt_pack = new_clt_pack;
            return GS_SUCCESS;
        }
    }

    GS_RETURN_IFERR(cm_list_new(&conn->pack_list, (void **)&new_clt_pack));
    new_clt_pack->id = conn->pack_list.count - 1;
    new_clt_pack->used = GS_TRUE;
    cs_init_packet(&new_clt_pack->pack, conn->pipe.options);
    new_clt_pack->pack.max_buf_size = conn->server_info.server_max_pack_size;
    *clt_pack = new_clt_pack;
    return GS_SUCCESS;
}

void clt_free_pack(clt_conn_t *conn, clt_packet_t *clt_pack)
{
    CM_ASSERT(clt_pack->id < conn->pack_list.count);
    clt_pack->used = GS_FALSE;
}

int gsc_encrypt_password(char *orig_pswd, unsigned int orig_len, char *rand_local_key, char *rand_factor_key,
    char *cipher, unsigned int *cipher_len)
{
    char base64_pswd[GS_PASSWORD_BUFFER_SIZE * 2] = { 0 };
    uint32 base64_pswd_len = GS_PASSWORD_BUFFER_SIZE * 2;
    GS_RETURN_IFERR(cm_base64_encode((uchar *)orig_pswd, (uint32)orig_len, base64_pswd, &base64_pswd_len));

    *cipher_len = GS_PASSWORD_BUFFER_SIZE * 2;
    status_t ret = cm_encrypt_passwd(GS_TRUE, base64_pswd, base64_pswd_len, cipher, (uint32 *)&cipher_len,
        rand_local_key, rand_factor_key);
    MEMS_RETURN_IFERR(memset_s(base64_pswd, GS_PASSWORD_BUFFER_SIZE * 2, 0, GS_PASSWORD_BUFFER_SIZE * 2));

    return ret;
}

int gsc_decrypt_password(char *pswd, unsigned int len, char *rand_local_key, char *rand_factor_key, char *cipher,
    unsigned int cipher_len)
{
    if (pswd == NULL || len == 0) {
        return GS_ERROR;
    }

    char base64_pswd[GS_PASSWORD_BUFFER_SIZE * 2] = { 0 };
    uint32 base64_pswd_len = GS_PASSWORD_BUFFER_SIZE * 2;

    if (cm_decrypt_passwd(GS_TRUE, cipher, (uint32)cipher_len, base64_pswd, &base64_pswd_len, rand_local_key,
        rand_factor_key) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (cm_base64_decode(base64_pswd, base64_pswd_len, (uchar *)pswd, (uint32)len) == 0) {
        MEMS_RETURN_IFERR(memset_s(base64_pswd, GS_PASSWORD_BUFFER_SIZE * 2, 0, GS_PASSWORD_BUFFER_SIZE * 2));
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t gsc_get_locator_info(gsc_stmt_t pstmt, void *locator, uint32 *outline, uint32 *really_sz, uint32 *loc_sz)
{
    clt_lob_head_t *head = (clt_lob_head_t *)locator;
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;

    GSC_CHECK_OBJECT_NULL_GS(stmt, "statement");
    GSC_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");
    GSC_CHECK_OBJECT_NULL_CLT(stmt->conn, head, "LOB locator");

    if (outline != NULL) {
        *outline = head->is_outline;
    }

    if (really_sz != NULL) {
        *really_sz = head->size;
    }

    if (loc_sz != NULL) {
        *loc_sz = (uint32)stmt->conn->server_info.locator_size;
    }

    return GS_SUCCESS;
}

status_t gsc_write_sql(clt_stmt_t *stmt, const char *sql, uint32 total_size, uint32 *curr_size, cs_packet_t *req_pack)
{
    if (stmt->conn->send_trans_func != NULL) {
        uint32 *addr = NULL;
        uint32 addr_offset;
        bool32 eof = GS_FALSE;
        int32 len;
        GS_RETURN_IFERR(cs_reserve_space(req_pack, sizeof(uint32), &addr_offset));
        addr = (uint32 *)CS_RESERVE_ADDR(req_pack, addr_offset);
        len = stmt->conn->send_trans_func(sql + total_size - (*curr_size), curr_size, CS_WRITE_ADDR(req_pack),
            CM_ALIGN4_FLOOR(CS_REMAIN_SIZE(req_pack)), &eof);
        if (len < 0) {
            return GS_ERROR;
        }
        if ((*curr_size) > 0 && eof) {
            CLT_THROW_ERROR(stmt->conn, ERR_CLT_INVALID_ATTR, "sql", sql);
            return GS_ERROR;
        }
        *addr = cs_format_endian_i32(req_pack->options, (uint32)len);
        GS_RETURN_IFERR(cs_inc_head_size(req_pack, (uint32)len));
        req_pack->head->flags = ((*curr_size) == 0) ? 0 : CS_FLAG_MORE_DATA;
    } else {
        uint32 remain_size = CM_ALIGN4_FLOOR(CS_REMAIN_SIZE(req_pack) - sizeof(uint32));
        text_t text;
        text.str = (char *)sql + total_size - (*curr_size);

        if ((*curr_size) <= remain_size) {
            text.len = *curr_size;
            req_pack->head->flags = 0;
        } else {
            text.len = remain_size;
            req_pack->head->flags |= CS_FLAG_MORE_DATA;
        }
        GS_RETURN_IFERR(cs_put_text(req_pack, &text));
        *curr_size -= text.len;
    }
    return GS_SUCCESS;
}

int32 gsc_transcode_ucs2(gsc_stmt_t pstmt, const void *src, uint32 *src_len, void *dst, uint32 dst_len, bool32 *eof)
{
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;
    transcode_func_t func = cm_get_transcode_func_ucs2(stmt->conn->local_charset);
    return func(src, src_len, dst, dst_len, eof);
}

status_t clt_set_conn_transcode_func(clt_conn_t *conn)
{
    // reset trans func
    conn->send_trans_func = cm_get_transcode_func(conn->local_charset, conn->server_info.server_charset);
    conn->recv_trans_func = cm_get_transcode_func(conn->server_info.server_charset, conn->local_charset);
    return GS_SUCCESS;
}

int gsc_set_charset(gsc_stmt_t pstmt, uint16 charset_id)
{
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;
    if (charset_id == GS_INVALID_ID16) {
        CLT_THROW_ERROR(stmt->conn, ERR_INVALID_CHARSET, "unsupported charset");
        return GS_ERROR;
    }

    stmt->conn->local_charset = charset_id;
    return clt_set_conn_transcode_func(stmt->conn);
}

status_t clt_receive_serveroutput(clt_stmt_t *stmt, cs_packet_t *ack)
{
    clt_output_item_t *item = NULL;
    text_t output;
    uint32 assign_len;

    cs_init_get(ack);
    GS_RETURN_IFERR(cs_get_text(ack, &output));

    /* get idle item to output */
    if (stmt->serveroutput.output_count >= stmt->serveroutput.output_data.count) {
        GS_RETURN_IFERR(cm_list_new(&stmt->serveroutput.output_data, (void **)&item));
        MEMS_RETURN_IFERR(memset_s(item, sizeof(clt_output_item_t), 0, sizeof(clt_output_item_t)));
    } else {
        item = (clt_output_item_t *)cm_list_get(&stmt->serveroutput.output_data, stmt->serveroutput.output_count);
    }

    stmt->serveroutput.output_count++;

    /* output content must contains '\0' */
    GS_RETURN_IFERR(cm_get_transcode_length(&output, stmt->conn->server_info.server_charset, stmt->conn->local_charset,
        &assign_len));

    if (item->cache_len != 0 && assign_len + 1 > item->cache_len) {
        free(item->output.str);
        item->output.str = NULL;
        item->cache_len = 0;
    }

    if (item->cache_len == 0) {
        item->output.str = (char *)malloc(assign_len + 1);
        if (item->output.str == NULL) {
            GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)(assign_len + 1), "output item");
            return GS_ERROR;
        }
        item->cache_len = assign_len + 1;
    }

    if (output.len != 0) {
        GS_RETURN_IFERR(cm_transcode(stmt->conn->server_info.server_charset, stmt->conn->local_charset, output.str,
            &output.len, item->output.str, &assign_len, GS_FALSE));
    }
    item->output.str[assign_len] = '\0';
    item->output.len = assign_len;
    return GS_SUCCESS;
}

static status_t clt_prepare_stmt_transcode_buf(clt_stmt_t *stmt)
{
    stmt->ctrl = (cli_buf_ctrl_t *)malloc(sizeof(cli_buf_ctrl_t));
    if (stmt->ctrl == NULL) {
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)sizeof(cli_buf_ctrl_t), "creating statement charset transcode buffer");
        return GS_ERROR;
    }
    stmt->ctrl->offset = 0;
    stmt->ctrl->size = sizeof(stmt->ctrl->data);
    return GS_SUCCESS;
}

status_t clt_reset_stmt_transcode_buf(clt_stmt_t *stmt)
{
    if (stmt->conn->local_charset != stmt->conn->server_info.server_charset) {
        if (stmt->ctrl == NULL) {
            GS_RETURN_IFERR(clt_prepare_stmt_transcode_buf(stmt));
        }

        stmt->ctrl->offset = 0;
        stmt->ctrl->size = sizeof(stmt->ctrl->data);
    }

    return GS_SUCCESS;
}

status_t clt_transcode_column(clt_stmt_t *stmt, char **data, uint32 *size, transcode_func_t transcode_func)
{
    int32 len;
    bool32 eof;
    uint32 buf_size;
    char *buf = NULL;

    if (stmt->ctrl == NULL) {
        GS_RETURN_IFERR(clt_prepare_stmt_transcode_buf(stmt));
    }

    buf = stmt->ctrl->data + stmt->ctrl->offset;
    buf_size = stmt->ctrl->size - stmt->ctrl->offset;

    len = transcode_func(*data, size, buf, buf_size, &eof);
    if (len < 0) {
        return GS_ERROR;
    }
    if (*size != 0) {
        return GS_ERROR;
    }

    *data = buf;
    *size = (uint32)len;
    stmt->ctrl->offset += (uint32)len;
    return GS_SUCCESS;
}

static inline status_t clt_read_column_def(clt_stmt_t *stmt, clt_column_t *column, cs_packet_t *pack,
    const cs_column_def_t *c_def)
{
    char *name = NULL;
    uint32 def_name_len = (uint32)c_def->name_len;
    uint32 column_name_len = sizeof(column->def.name) - 1;

    column->def.size = c_def->size;
    column->def.precision = c_def->precision;
    column->def.scale = c_def->scale;
    column->def.datatype = (c_def->datatype == (uint16)GS_TYPE_UNKNOWN) ? GSC_TYPE_UNKNOWN : c_def->datatype;
    column->def.nullable = GS_COLUMN_IS_NULLABLE(c_def);
    column->def.auto_increment = GS_COLUMN_IS_AUTO_INCREMENT(c_def);
    column->def.is_character = GS_COLUMN_IS_CHARACTER(c_def);
    column->def.is_array = GS_COLUMN_IS_ARRAY(c_def);
    column->def.is_jsonb = GS_COLUMN_IS_JSONB(c_def);
    column->def.name_len = c_def->name_len;
    GS_RETURN_IFERR(cs_get_data(pack, c_def->name_len, (void **)&name));

    if (c_def->name_len >= GS_NAME_BUFFER_SIZE) {
        GS_THROW_ERROR(ERR_OUT_OF_INDEX, "reading column", GS_NAME_BUFFER_SIZE);
        return GS_ERROR;
    }

    if (c_def->name_len != 0) {
        GS_RETURN_IFERR(cm_transcode(stmt->conn->server_info.server_charset, stmt->conn->local_charset, name,
            &def_name_len, column->def.name, &column_name_len, GS_TRUE));
    }

    column->def.name[column_name_len] = '\0';
    return GS_SUCCESS;
}

static inline void clt_init_inline_lob_cache(clt_column_t *column)
{
    bool8 need_clear = GS_FALSE;

    if (GSC_IS_LOB_TYPE(column->def.datatype)) {
        need_clear = (column->inline_lob.cache_buf.len > SIZE_K(8)); // denote 8K
    } else {
        need_clear = GS_TRUE;
    }

    if (need_clear) {
        CM_FREE_PTR(column->inline_lob.cache_buf.str);
        column->inline_lob.cache_buf.len = 0;
    }

    column->inline_lob.used_pos = 0;
}

static status_t clt_extend_column_list(clt_stmt_t *stmt, uint32 count)
{
    uint32 i;

    for (i = stmt->columns.count; i < count; i++) {
        if (cm_list_new(&stmt->columns, NULL) != GS_SUCCESS) {
            clt_copy_local_error(stmt->conn);
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t clt_read_column_defs(clt_stmt_t *stmt, cs_packet_t *pack)
{
    uint32 i;
    cs_column_def_t *c_def = NULL;
    clt_column_t *column = NULL;

    if (stmt->column_count == 0) {
        return GS_SUCCESS;
    }

    GS_RETURN_IFERR(clt_extend_column_list(stmt, stmt->column_count));

    for (i = 0; i < stmt->column_count; i++) {
        GS_RETURN_IFERR(cs_get_column_def(pack, &c_def));
        column = (clt_column_t *)cm_list_get(&stmt->columns, i);
        column->id = i;
        column->size = 0;
        column->ptr = NULL;
        column->bnd_size = 0;
        column->bnd_type = GSC_TYPE_INTEGER;
        column->bnd_ptr = NULL;
        column->ind_ptr = NULL;

        GS_RETURN_IFERR(clt_read_column_def(stmt, column, pack, c_def));

        // init inline lob cache
        if (column->inline_lob.cache_buf.len != 0 && stmt->fetch_size > 1) {
            clt_init_inline_lob_cache(column);
        }
    }

    return GS_SUCCESS;
}

status_t clt_extend_param_list(clt_stmt_t *stmt, uint32 count)
{
    for (uint32 i = stmt->params.count; i < count; i++) {
        if (cm_list_new(&stmt->params, NULL) != GS_SUCCESS) {
            clt_copy_local_error(stmt->conn);
            return GS_ERROR;
        }

        clt_param_t *param = (clt_param_t *)cm_list_get(&stmt->params, i);
        param->lob_ptr = NULL; // init lob_ptr
    }
    return GS_SUCCESS;
}

static status_t clt_get_param_name_old(clt_stmt_t *stmt, cs_packet_t *pack, const text_t *sql, cs_param_def_t *p_def,
    clt_param_t *param)
{
    GS_RETURN_IFERR(cs_get_param_def(pack, &p_def));
    if (sql != NULL) {
        if (p_def->len > GS_NAME_BUFFER_SIZE - 1) {
            p_def->len = GS_NAME_BUFFER_SIZE - 1;
        }

        if (p_def->len != 0) {
            if (p_def->offset >= sql->len || p_def->offset + p_def->len > sql->len) {
                CLT_THROW_ERROR(stmt->conn, ERR_CLT_INVALID_BIND, "parameter name is invalid");
                return GS_ERROR;
            }
            MEMS_RETURN_IFERR(memcpy_s(param->name, GS_NAME_BUFFER_SIZE, sql->str + p_def->offset, p_def->len));
        }
        param->name[p_def->len] = '\0';
    }
    return GS_SUCCESS;
}

static status_t clt_get_param_name_new(clt_stmt_t *stmt, cs_packet_t *pack, cs_param_def_new_t *p_def_new,
    clt_param_t *param)
{
    char *name = NULL;
    GS_RETURN_IFERR(cs_get_param_def_new(pack, &p_def_new));
    uint32 column_name_len = sizeof(param->name) - 1;
    if (p_def_new->len > GS_NAME_BUFFER_SIZE - 1) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_INVALID_BIND, "the length of parameter name is invalid");
        return GS_ERROR;
    }
    GS_RETURN_IFERR(cs_get_data(pack, p_def_new->len, (void **)&name));
    GS_RETURN_IFERR(cm_transcode(stmt->conn->server_info.server_charset, stmt->conn->local_charset, name,
        &p_def_new->len, param->name, &column_name_len, GS_TRUE));
    param->name[column_name_len] = '\0';
    return GS_SUCCESS;
}

static status_t clt_read_param_defs(clt_stmt_t *stmt, cs_packet_t *pack, const text_t *sql)
{
    uint32 i;
    cs_param_def_t *p_def = NULL;
    cs_param_def_new_t *p_def_new = NULL;
    clt_param_t *param = NULL;

    if (stmt->param_count == 0) {
        return GS_SUCCESS;
    }

    GS_RETURN_IFERR(clt_extend_param_list(stmt, stmt->param_count));

    for (i = 0; i < stmt->param_count; i++) {
        param = (clt_param_t *)cm_list_get(&stmt->params, i);
        if (stmt->conn->call_version >= CS_VERSION_23) {
            GS_RETURN_IFERR(clt_get_param_name_new(stmt, pack, p_def_new, param));
        } else {
            GS_RETURN_IFERR(clt_get_param_name_old(stmt, pack, sql, p_def, param));
        }

        param->direction = GSC_INPUT;
        param->bnd_type = GSC_TYPE_STRING;
        param->bnd_size = 0;
        param->bnd_ptr = NULL;
        param->ind_ptr = NULL;
        param->curr_ptr = NULL;
        CM_FREE_PTR(param->lob_ptr);
        param->lob_ptr_size = 0;
    }

    return GS_SUCCESS;
}

/* for sharding */
status_t clt_read_ack(clt_conn_t *conn, cs_packet_t *ack)
{
    bool32 ready = GS_FALSE;
    cs_pipe_t *pipe = &conn->pipe;

    GS_RETURN_IFERR(cs_wait(pipe, CS_WAIT_FOR_READ, pipe->socket_timeout, &ready));

    if (!ready) {
        GS_THROW_ERROR(ERR_SOCKET_TIMEOUT, pipe->socket_timeout / GS_TIME_THOUSAND_UN);
        return GS_ERROR;
    }

    return cs_read(pipe, ack, GS_TRUE);
}

static status_t clt_extend_outparam_list(clt_stmt_t *stmt, uint32 count)
{
    uint32 i;
    clt_outparam_t *outparam = NULL;

    for (i = stmt->outparams.count; i < count; i++) {
        if (cm_list_new(&stmt->outparams, (void **)&outparam) != GS_SUCCESS) {
            clt_copy_local_error(stmt->conn);
            return GS_ERROR;
        }
        MEMS_RETURN_IFERR(memset_s(outparam, sizeof(clt_outparam_t), 0, sizeof(clt_outparam_t)));
    }

    return GS_SUCCESS;
}

static status_t clt_read_outparam_defs(clt_stmt_t *stmt, cs_packet_t *pack)
{
    uint32 i;
    cs_outparam_def_t *o_def = NULL;
    clt_outparam_t *outparam = NULL;

    stmt->outparam_count = 0;

    if (stmt->stmt_type != GSC_STMT_PL) {
        return GS_SUCCESS;
    }

    GS_RETURN_IFERR(cs_get_int32(pack, (int32 *)&stmt->outparam_count));
    if (stmt->outparam_count == 0) {
        return GS_SUCCESS;
    }

    GS_RETURN_IFERR(clt_extend_outparam_list(stmt, stmt->outparam_count));

    for (i = 0; i < stmt->outparam_count; i++) {
        GS_RETURN_IFERR(cs_get_outparam_def(pack, &o_def));

        outparam = (clt_outparam_t *)cm_list_get(&stmt->outparams, i);
        MEMS_RETURN_IFERR(memcpy_s(outparam->def.name, GS_NAME_BUFFER_SIZE, o_def->name, GS_NAME_BUFFER_SIZE));
        outparam->def.size = o_def->size;
        outparam->def.direction = o_def->direction;
        outparam->def.datatype = o_def->datatype;
        outparam->size = 0;
        outparam->ptr = NULL;
        outparam->sub_stmt = NULL;
    }

    return GS_SUCCESS;
}

status_t clt_get_prepare_ack(clt_stmt_t *stmt, cs_packet_t *pack, const text_t *sql)
{
    cs_prepare_ack_t *ack = NULL;

    cs_init_get(pack);

    GS_RETURN_IFERR(cs_get_prepare_ack(pack, &ack));

    stmt->stmt_id = ack->stmt_id;
    stmt->stmt_type = ACK_LANG_TYPE(ack->stmt_type);
    stmt->sql_type = ACK_SQL_TYPE(ack->stmt_type);
    stmt->column_count = ack->column_count;
    stmt->param_count = ack->param_count;

    GS_RETURN_IFERR(clt_read_param_defs(stmt, pack, sql));
    GS_RETURN_IFERR(clt_read_column_defs(stmt, pack));
    return clt_read_outparam_defs(stmt, pack);
}

static status_t clt_extend_batch_errors_list(clt_stmt_t *stmt, uint32 count)
{
    uint32 i;

    for (i = stmt->batch_errs.err_list.count; i < count; i++) {
        if (cm_list_new(&stmt->batch_errs.err_list, NULL) != GS_SUCCESS) {
            clt_copy_local_error(stmt->conn);
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t clt_copy_batch_error(clt_stmt_t *stmt, char *dst, uint32 dst_len, char *src, uint32 src_len)
{
    if (src_len == 0) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_INVALID_VALUE, "batch error message length", 0);
        return GS_ERROR;
    }
    MEMS_RETURN_IFERR(strncpy_s(dst, dst_len, src, src_len));
    return GS_SUCCESS;
}

status_t clt_try_get_batch_error(clt_stmt_t *stmt, cs_execute_ack_t *exec_ack, uint32 line_offset)
{
    clt_batch_error_t *batch_error = NULL;
    uint32 i = 0;
    text_t errmsg_txt;
    char *err_message = NULL;

    if (exec_ack->batch_errs > 0) {
        GS_RETURN_IFERR(clt_extend_batch_errors_list(stmt, stmt->batch_errs.actual_count + exec_ack->batch_errs));

        if (stmt->conn->call_version >= CS_VERSION_10) {
            for (i = 0; i < exec_ack->batch_errs; i++) {
                batch_error =
                    (clt_batch_error_t *)cm_list_get(&stmt->batch_errs.err_list, stmt->batch_errs.actual_count + i);
                GS_RETURN_IFERR(cs_get_int32(&stmt->cache_pack->pack, (int32 *)&batch_error->line));
                batch_error->line += line_offset;
                GS_RETURN_IFERR(cs_get_int32(&stmt->cache_pack->pack, (int32 *)&batch_error->err_code));
                GS_RETURN_IFERR(cs_get_text(&stmt->cache_pack->pack, &errmsg_txt));
                GS_RETURN_IFERR(clt_copy_batch_error(stmt, batch_error->err_message, GS_MESSAGE_BUFFER_SIZE,
                    errmsg_txt.str, errmsg_txt.len));
            }
        } else {
            for (i = 0; i < exec_ack->batch_errs; i++) {
                batch_error = (clt_batch_error_t *)cm_list_get(&stmt->batch_errs.err_list, i);
                GS_RETURN_IFERR(cs_get_int32(&stmt->cache_pack->pack, (int32 *)&batch_error->line));
                batch_error->line += line_offset;
                GS_RETURN_IFERR(cs_get_str(&stmt->cache_pack->pack, &err_message));
                GS_RETURN_IFERR(clt_copy_batch_error(stmt, batch_error->err_message, GS_MESSAGE_BUFFER_SIZE,
                    err_message, strlen(err_message)));
            }
        }

        stmt->batch_errs.actual_count += exec_ack->batch_errs;
        stmt->batch_errs.actual_count = MIN(stmt->batch_errs.actual_count, stmt->batch_errs.allowed_count);
    }

    return GS_SUCCESS;
}

status_t clt_get_execute_ack(clt_stmt_t *stmt)
{
    cs_execute_ack_t *exec_ack = NULL;
    cs_final_column_def_t *column_def = NULL;
    clt_column_t *column = NULL;
    uint32 i;

    stmt->fetched_rows = 0;
    stmt->row_index = 0;

    if (stmt->stmt_type == GSC_STMT_DML || stmt->stmt_type == GSC_STMT_EXPLAIN || stmt->stmt_type == GSC_STMT_PL) {
        GS_RETURN_IFERR(cs_get_exec_ack(&stmt->cache_pack->pack, &exec_ack));
        stmt->affected_rows = exec_ack->total_rows;
        stmt->return_rows = exec_ack->batch_rows;
        stmt->more_rows = exec_ack->rows_more;
        stmt->eof = (stmt->return_rows == 0);
        stmt->conn->xact_status = (gsc_xact_status_t)exec_ack->xact_status;

        // select: try make pending column definition after get execute response package
        for (i = 0; i < (uint32)exec_ack->pending_col_count; i++) {
            GS_RETURN_IFERR(cs_get_final_column_def(&stmt->cache_pack->pack, &column_def));
            if (column_def->col_id >= stmt->columns.count) {
                CLT_THROW_ERROR(stmt->conn, ERR_CLT_INVALID_COLUMN, (uint32)(column_def->col_id + 1), "pending columns",
                    stmt->columns.count);
                return GS_ERROR;
            }
            column = (clt_column_t *)cm_list_get(&stmt->columns, column_def->col_id);
            column->def.datatype =
                (column_def->datatype == (uint16)GS_TYPE_UNKNOWN) ? GSC_TYPE_UNKNOWN : column_def->datatype;
            column->def.size = column_def->size;
        }

        // try get batch error message
        GS_RETURN_IFERR(clt_try_get_batch_error(stmt, exec_ack, 0));
    } else {
        stmt->affected_rows = 0;
        stmt->return_rows = 0;
        stmt->more_rows = GS_FALSE;
        stmt->eof = GS_TRUE;
        if (stmt->stmt_type == GSC_STMT_DDL) {
            // DDL will commit or rollback the active transaction in connection
            stmt->conn->xact_status = GSC_XACT_END;
        }

        if ((stmt->stmt_type == GSC_STMT_DDL) && ((CS_CREATE_TABLE_AS(stmt->cache_pack->pack.head->flags)))) {
            GS_RETURN_IFERR(cs_get_exec_ack(&stmt->cache_pack->pack, &exec_ack));
            stmt->affected_rows = exec_ack->total_rows;
        }
    }

    return GS_SUCCESS;
}

static status_t clt_get_till_sn(clt_conn_t *conn, cs_packet_t *ack)
{
    bool32 ready = GS_FALSE;

    if (conn->call_version < CS_VERSION_11) {
        // do not check serial_number
        return GS_SUCCESS;
    }

    do {
        if (conn->serial_number_send == ack->head->serial_number) {
            return GS_SUCCESS;
        } else if (conn->serial_number_send < ack->head->serial_number) {
            GS_THROW_ERROR(ERR_INVALID_TCP_PACKET, "serial number check error", conn->serial_number_send,
                ack->head->serial_number);
            return GS_ERROR;
        }

        GS_RETURN_IFERR(cs_wait(&conn->pipe, CS_WAIT_FOR_READ, conn->pipe.socket_timeout, &ready));

        if (!ready) {
            GS_THROW_ERROR(ERR_SOCKET_TIMEOUT, conn->pipe.socket_timeout / GS_TIME_THOUSAND_UN);
            return GS_ERROR;
        }

        GS_RETURN_IFERR(cs_read(&conn->pipe, ack, GS_TRUE));
    } while (GS_TRUE);
}

static status_t clt_check_ack_error(clt_conn_t *conn, cs_packet_t *ack)
{
    GS_RETURN_IFERR(clt_get_till_sn(conn, ack));

    if (CS_HAS_EXEC_ERROR(ack)) {
        cs_init_get(ack);
        GS_RETURN_IFERR(cs_get_int32(ack, &conn->error_code));
        GS_RETURN_IFERR(cs_get_int16(ack, (int16 *)(&conn->loc.line)));
        GS_RETURN_IFERR(cs_get_int16(ack, (int16 *)(&conn->loc.column)));
        GS_RETURN_IFERR(clt_get_error_message(conn, ack, conn->message));
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t clt_remote_call(clt_conn_t *conn, cs_packet_t *req, cs_packet_t *ack)
{
    CS_SERIAL_NUMBER_INC(conn, req);
    uint8 req_cmd = req->head->cmd;
    if (cs_call_ex(&conn->pipe, req, ack) != GS_SUCCESS) {
        clt_copy_local_error(conn);
        return GS_ERROR;
    }

    GS_RETURN_IFERR(clt_check_ack_error(conn, ack));

    if (req_cmd != ack->head->cmd) {
        CLT_THROW_ERROR(conn, ERR_CLT_UNEXPECTED_CMD, req_cmd, (uint32)ack->head->cmd);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t clt_async_get_ack(clt_conn_t *conn, cs_packet_t *ack)
{
    if (clt_read_ack(conn, ack) != GS_SUCCESS) {
        clt_copy_local_error(conn);
        return GS_ERROR;
    }

    return clt_check_ack_error(conn, ack);
}

void clt_copy_local_error(clt_conn_t *conn)
{
    int32 code;
    const char *message = NULL;
    errno_t errcode;

    cm_get_error(&code, &message, NULL);

    GS_RETVOID_IFTRUE(code == 0);
    conn->error_code = code;
    errcode = strncpy_s(conn->message, GS_MESSAGE_BUFFER_SIZE, message, strlen(message));
    if (errcode != EOK) {
        GS_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return;
    }
}

status_t clt_desc_column_by_id(clt_stmt_t *stmt, uint32 id, gsc_column_desc_t *desc)
{
    clt_column_t *column = NULL;

    if (SECUREC_UNLIKELY(id >= stmt->column_count || id >= stmt->columns.count)) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_OUT_OF_INDEX, "column");
        return GS_ERROR;
    }

    if (desc != NULL) {
        column = (clt_column_t *)cm_list_get(&stmt->columns, id);
        desc->name = column->def.name;
        desc->type = column->def.datatype;
        desc->size = column->def.size;
        desc->precision = column->def.precision;
        desc->scale = column->def.scale;
        desc->nullable = column->def.nullable;
        desc->is_character = column->def.is_character;
    }

    return GS_SUCCESS;
}

status_t clt_get_column_by_id(clt_stmt_t *stmt, uint32 id, void **data, uint32 *size, bool32 *is_null)
{
    clt_column_t *column = NULL;
    bool32 is_null_val;

    if (SECUREC_UNLIKELY(stmt->status < CLI_STMT_FETCHING)) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_OUT_OF_API_SEQUENCE, "statement is not fetched");
        return GS_ERROR;
    }

    if (SECUREC_UNLIKELY(id >= stmt->column_count || id >= stmt->columns.count)) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_OUT_OF_INDEX, "column");
        return GS_ERROR;
    }

    column = (clt_column_t *)cm_list_get(&stmt->columns, id);

    is_null_val = (column->size == GSC_NULL);

    if (SECUREC_LIKELY(data != NULL)) {
        *data = is_null_val ? NULL : ((column->bnd_ptr == NULL) ? column->ptr : column->bnd_ptr);
    }

    if (SECUREC_LIKELY(size != NULL)) {
        *size = column->size;
    }

    if (SECUREC_LIKELY(is_null != NULL)) {
        *is_null = is_null_val;
    }

    return GS_SUCCESS;
}

static inline status_t clt_session_nlsparam_seter(clt_stmt_t *stmt, nlsparam_id_t id, text_t *text)
{
    clt_conn_t *conn = stmt->conn;
    CM_SET_NLSPARAM(&(conn->nls_params.nlsvalues[id]), text);
    return GS_SUCCESS;
}

/* * @see sql_send_nls_feedback */
static inline status_t clt_process_nls_feedback(clt_stmt_t *stmt, cs_packet_t *ack)
{
    uint32 id;
    text_t param_value;

    GS_RETURN_IFERR(cs_get_int32(ack, (int32 *)&id));
    GS_RETURN_IFERR(cs_get_text(ack, &param_value));
    GS_RETURN_IFERR(clt_session_nlsparam_seter(stmt, (nlsparam_id_t)id, &param_value));
    return GS_SUCCESS;
}

/* * @see clt_process_tz_feedback */
static inline status_t clt_process_tz_feedback(clt_stmt_t *stmt, cs_packet_t *ack)
{
    uint32 tz;

    GS_RETURN_IFERR(cs_get_int32(ack, (int32 *)&tz));
    stmt->conn->local_sessiontz = (int16)tz;

    return GS_SUCCESS;
}

status_t clt_try_process_feedback(clt_stmt_t *stmt, cs_packet_t *ack)
{
    uint32 fd_type;

    if (!CS_HAS_FEEDBACK_MSG(ack->head)) {
        return GS_SUCCESS;
    }

    GS_RETURN_IFERR(cs_get_int32(ack, (int32 *)&fd_type));

    switch ((feedback_t)fd_type) {
        case FB_ALTSESSION_SET_NLS:
            return clt_process_nls_feedback(stmt, ack);
        case FB_ALTSESSION_SET_SESSIONTZ:
            return clt_process_tz_feedback(stmt, ack);
        default:
            break;
    }
    return GS_SUCCESS;
}

status_t clt_verify_lob(clt_stmt_t *stmt, uint32 pos, clt_param_t **param)
{
    if (SECUREC_UNLIKELY(stmt->status < CLI_STMT_PREPARED)) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_OUT_OF_API_SEQUENCE, "statement is not prepared");
        return GS_ERROR;
    }

    if (SECUREC_UNLIKELY(pos >= stmt->param_count || pos >= stmt->params.count)) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_OUT_OF_INDEX, "binding");
        return GS_ERROR;
    }

    *param = (clt_param_t *)cm_list_get(&stmt->params, pos);
    if ((*param)->bnd_ptr == NULL) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_INVALID_BIND, "lob locator need bound before write lob data");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t cs_put_alter_set(cs_packet_t *req_pack, clt_stmt_t *stmt)
{
    alter_set_info_t tmp;
    text_t text;
    text_t tmp_schema;
    text_t tmp_user;
    uint32 alter_se_lenth; // the total lenth of session attributes
    tmp.commit_batch = stmt->conn->alter_set_info.commit_batch;
    tmp.commit_nowait = stmt->conn->alter_set_info.commit_nowait;
    tmp.lock_wait_timeout = stmt->conn->alter_set_info.lock_wait_timeout;
    if (stmt->sql_type != GS_SQL_TYPE_CREATE_USER) {
        MEMS_RETURN_IFERR(
            strcpy_s(tmp.curr_schema, GS_NAME_BUFFER_SIZE, (const char *)stmt->conn->alter_set_info.curr_schema));
    } else {
        MEMS_RETURN_IFERR(memset_s(tmp.curr_schema, GS_NAME_BUFFER_SIZE, 0, GS_NAME_BUFFER_SIZE));
    }
    MEMS_RETURN_IFERR(
        strcpy_s(tmp.curr_user2, GS_NAME_BUFFER_SIZE, (const char *)stmt->conn->alter_set_info.curr_user2));
    tmp.nologging_enable = stmt->conn->alter_set_info.nologging_enable;
    tmp.isolevel = stmt->conn->alter_set_info.isolevel;
    cm_str2text(tmp.curr_schema, &tmp_schema);
    cm_str2text(tmp.curr_user2, &tmp_user);

    alter_se_lenth =
        OFFSET_OF(alter_set_info_t, curr_schema) + sizeof(uint32) + tmp_schema.len + sizeof(uint32) + tmp_user.len;
    alter_se_lenth = alter_se_lenth + sizeof(uint32) * 5 + stmt->conn->nls_params.nlsvalues[NLS_DATE_FORMAT].len +
        stmt->conn->nls_params.nlsvalues[NLS_TIMESTAMP_FORMAT].len +
        stmt->conn->nls_params.nlsvalues[NLS_TIMESTAMP_TZ_FORMAT].len +
        stmt->conn->nls_params.nlsvalues[NLS_TIME_FORMAT].len +
        stmt->conn->nls_params.nlsvalues[NLS_TIME_TZ_FORMAT].len + sizeof(int16);

    GS_RETURN_IFERR(cs_put_int32(req_pack, alter_se_lenth));
    GS_RETURN_IFERR(cs_put_data(req_pack, &tmp, OFFSET_OF(alter_set_info_t, curr_schema)));
    GS_RETURN_IFERR(cs_put_text(req_pack, &tmp_schema));

    cm_nlsvalue2text(&(stmt->conn->nls_params.nlsvalues[NLS_DATE_FORMAT]), &text);
    GS_RETURN_IFERR(cs_put_text(req_pack, &text));
    cm_nlsvalue2text(&(stmt->conn->nls_params.nlsvalues[NLS_TIMESTAMP_FORMAT]), &text);
    GS_RETURN_IFERR(cs_put_text(req_pack, &text));
    cm_nlsvalue2text(&(stmt->conn->nls_params.nlsvalues[NLS_TIMESTAMP_TZ_FORMAT]), &text);
    GS_RETURN_IFERR(cs_put_text(req_pack, &text));
    cm_nlsvalue2text(&(stmt->conn->nls_params.nlsvalues[NLS_TIME_FORMAT]), &text);
    GS_RETURN_IFERR(cs_put_text(req_pack, &text));
    cm_nlsvalue2text(&(stmt->conn->nls_params.nlsvalues[NLS_TIME_TZ_FORMAT]), &text);
    GS_RETURN_IFERR(cs_put_text(req_pack, &text));
    GS_RETURN_IFERR((cs_put_int16(req_pack, stmt->conn->local_sessiontz)));
    GS_RETURN_IFERR(cs_put_text(req_pack, &tmp_user));
    return GS_SUCCESS;
}

void gsc_get_charset(gsc_stmt_t pstmt, uint16 *charset_id)
{
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;
    *charset_id = stmt->conn->local_charset;
}

status_t clt_get_error_message(clt_conn_t *conn, cs_packet_t *pack, char *err_msg)
{
    char *msg_buf = NULL;
    uint32 msg_len;
    text_t msg_text;
    uint32 max_len = GS_MESSAGE_BUFFER_SIZE - 1;
    uint32 version = (conn->has_auth ? conn->call_version : conn->pipe.version);

    if (version >= CS_VERSION_23) {
        GS_RETURN_IFERR(cs_get_text(pack, &msg_text));
        msg_buf = msg_text.str;
        msg_len = msg_text.len;
    } else {
        GS_RETURN_IFERR(cs_get_str(pack, &msg_buf));
        msg_len = (uint32)strlen(msg_buf);
    }

    if (msg_len > max_len || msg_len == 0) {
        CLT_THROW_ERROR(conn, ERR_CLT_INVALID_VALUE, "error message length", msg_len);
        return GS_ERROR;
    }

    GS_RETURN_IFERR(cm_transcode(conn->server_info.server_charset, conn->local_charset, msg_buf, &msg_len, err_msg,
        &max_len, GS_TRUE));
    err_msg[max_len] = '\0';
    return GS_SUCCESS;
}

#ifdef __cplusplus
}
#endif
