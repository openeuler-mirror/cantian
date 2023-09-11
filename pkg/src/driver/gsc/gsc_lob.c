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
 * gsc_lob.c
 *
 *
 * IDENTIFICATION
 * src/driver/gsc/gsc_lob.c
 *
 * -------------------------------------------------------------------------
 */
#include "gsc_lob.h"

#ifdef __cplusplus
extern "C" {
#endif

static status_t clt_read_lob(clt_stmt_t *stmt, const void *locator, uint32 offset, uint32 size, clt_packet_t *ack_pack)
{
    cs_packet_t *req_pack = &stmt->conn->pack;
    lob_read_req_t *req = NULL;
    uint32 req_offset, loc_offset;
    uint32 req_size = (size > MAX_LOB_BATCH_SIZE) ? MAX_LOB_BATCH_SIZE : size;
    char *lob_locator = NULL;

    cs_init_set(req_pack, stmt->conn->call_version);
    req_pack->head->cmd = CS_CMD_LOB_READ;

    GS_RETURN_IFERR(cs_reserve_space(req_pack, sizeof(lob_read_req_t), &req_offset));
    req = (lob_read_req_t *)CS_RESERVE_ADDR(req_pack, req_offset);
    req->stmt_id = stmt->stmt_id;
    req->offset = offset;
    req->size = req_size;
    cs_putted_lob_read_req(req_pack, req_offset);

    if (locator == NULL) {
        ack_pack->pack.head->size = 0;
        return GS_SUCCESS;
    }

    GS_RETURN_IFERR(cs_reserve_space(req_pack, stmt->conn->server_info.locator_size, &loc_offset));
    lob_locator = CS_RESERVE_ADDR(req_pack, loc_offset);
    if (stmt->conn->server_info.locator_size != 0) {
        MEMS_RETURN_IFERR(
            memcpy_s(lob_locator, req_pack->max_buf_size - loc_offset, locator, stmt->conn->server_info.locator_size));
    }

    return clt_remote_call(stmt->conn, req_pack, &ack_pack->pack);
}

static status_t clt_get_lob_locator(clt_stmt_t *stmt, uint32 id, void **locator, uint32 *is_null)
{
    uint32 loc_size;
    gsc_column_desc_t desc = { 0 };

    GS_RETURN_IFERR(clt_desc_column_by_id(stmt, id, &desc));

    if (!GSC_IS_LOB_TYPE(desc.type)) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_INVALID_VALUE, "column type", id);
        return GS_ERROR;
    }

    return clt_get_column_by_id(stmt, id, locator, &loc_size, is_null);
}

static status_t clt_read_blob_by_id(clt_stmt_t *stmt, uint32 id, uint32 offset, void *buffer, uint32 size,
    uint32 *nbytes, uint32 *eof)
{
    void *locator = NULL;
    uint32 is_null;
    uint32 read_nbytes = 0;
    void *tmp_buffer = buffer;
    uint32 tmp_nbytes = 0;
    uint32 tmp_eof;

    GS_RETURN_IFERR(clt_get_lob_locator(stmt, id, &locator, &is_null));

    if (is_null) {
        if (nbytes != NULL) {
            *nbytes = 0;
        }

        if (eof != NULL) {
            *eof = GS_TRUE;
        }

        return GS_SUCCESS;
    }

    do {
        GS_RETURN_IFERR(
            clt_read_blob(stmt, locator, offset + read_nbytes, tmp_buffer, size - read_nbytes, &tmp_nbytes, &tmp_eof));
        read_nbytes += tmp_nbytes;
        tmp_buffer = (void *)((char *)tmp_buffer + tmp_nbytes);
    } while (tmp_eof == GS_FALSE && read_nbytes < size);

    if (nbytes != NULL) {
        *nbytes = read_nbytes;
    }

    if (eof != NULL) {
        *eof = tmp_eof;
    }

    return GS_SUCCESS;
}

static status_t clt_decode_inline_lob(clt_stmt_t *stmt, void *locator, char **data)
{
    clt_cache_lob_t *cache_lob = (clt_cache_lob_t *)locator;
    clt_column_t *column = NULL;
    uint32 actual_len;

    /* decode inline lob value and get actual data,
    content is clt_cache_lob_t(clt_lob_head_t + fetched_times + column_id + offset) */
    if (cache_lob->fetched_times != stmt->fetched_times) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_OUT_OF_API_SEQUENCE, "inline lob is over fetched");
        return GS_ERROR;
    }

    if (cache_lob->column_id >= stmt->column_count) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_OUT_OF_INDEX, "column");
        return GS_ERROR;
    }

    column = (clt_column_t *)cm_list_get(&stmt->columns, cache_lob->column_id);

    actual_len = GSC_INLINE_LOB_ENCODE_LEN + cache_lob->lob_head.size;
    if ((cache_lob->offset > column->inline_lob.used_pos) ||
        (cache_lob->offset + actual_len > column->inline_lob.used_pos)) {
        GS_THROW_ERROR(ERR_CLT_INVALID_VALUE, "lob locator value", cache_lob->offset);
        return GS_ERROR;
    }

    *data = column->inline_lob.cache_buf.str + cache_lob->offset + GSC_INLINE_LOB_ENCODE_LEN;

    return GS_SUCCESS;
}

static status_t clt_find_inline_lob(clt_stmt_t *stmt, const void *locator, char **data)
{
    uint32 i;
    clt_column_t *column = NULL;

    for (i = 0; i < stmt->columns.count; i++) {
        column = (clt_column_t *)cm_list_get(&stmt->columns, i);
        if (column->size == GSC_NULL) {
            continue;
        }

        if (((char *)locator == column->bnd_ptr) || ((char *)locator == column->ptr)) {
            *data = column->ptr + sizeof(clt_lob_head_t);
            break;
        }
    }

    if (*data == NULL) {
        GS_THROW_ERROR(ERR_CLT_INVALID_VALUE, "lob locator value", 0);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t clt_get_inline_lob_data(clt_stmt_t *stmt, void *locator, char **data)
{
    if (stmt->fetch_size > 1) {
        /* decode inline lob data and get actual data */
        return clt_decode_inline_lob(stmt, locator, data);
    } else {
        /* get inline lob data from column->ptr */
        return clt_find_inline_lob(stmt, locator, data);
    }
}

static status_t clt_read_inline_blob(clt_stmt_t *stmt, void *locator, uint32 offset, void *buffer, uint32 size,
    uint32 *nbytes, uint32 *eof)
{
    clt_lob_head_t *head = (clt_lob_head_t *)locator;
    uint32 len = (head->size > offset) ? MIN(size, head->size - offset) : 0;
    char *data = NULL;

    if (offset > head->size) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_OUT_OF_INDEX, "inline lob offset");
        return GS_ERROR;
    }

    CM_SET_VALUE_IF_NOTNULL(eof, ((offset + size) >= head->size));
    CM_SET_VALUE_IF_NOTNULL(nbytes, len);

    if (buffer == NULL || len == 0) {
        return GS_SUCCESS;
    }

    GS_RETURN_IFERR(clt_get_inline_lob_data(stmt, locator, &data));
    MEMS_RETURN_IFERR(memcpy_s(buffer, size, data + offset, len));
    return GS_SUCCESS;
}

static status_t clt_read_blob_by_pack(clt_stmt_t *stmt, void *locator, uint32 offset, void *buffer, uint32 size,
    uint32 *nbytes, uint32 *eof)
{
    clt_packet_t *ack_pack = NULL;
    status_t ret = GS_SUCCESS;
    errno_t errcode = 0;
    lob_read_ack_t *ack = NULL;

    do {
        GS_RETURN_IFERR(clt_alloc_pack(stmt->conn, &ack_pack));

        ret = clt_read_lob(stmt, locator, offset, size, ack_pack);
        GS_BREAK_IF_ERROR(ret);

        cs_init_get(&ack_pack->pack);
        ret = cs_get_lob_read_ack(&ack_pack->pack, &ack);
        GS_BREAK_IF_ERROR(ret);

        if (nbytes != NULL) {
            *nbytes = ack->size;

            if (*nbytes > 0 && buffer != NULL) {
                errcode = memcpy_s(buffer, size, CS_READ_ADDR(&ack_pack->pack), *nbytes);
                if (errcode != EOK) {
                    ret = GS_ERROR;
                    break;
                }
            }
        }

        if (eof != NULL) {
            *eof = ack->eof;
        }
    } while (0);

    clt_free_pack(stmt->conn, ack_pack);
    return ret;
}

status_t clt_read_blob(clt_stmt_t *stmt, void *locator, uint32 offset, void *buffer, uint32 size, uint32 *nbytes,
    uint32 *eof)
{
    clt_lob_head_t *head = (clt_lob_head_t *)locator;

    if (stmt->status < CLI_STMT_FETCHING) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_OUT_OF_API_SEQUENCE, "statement is not fetched");
        return GS_ERROR;
    }

    if (size < 1) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_BUF_SIZE_TOO_SMALL, "fetch blob data");
        return GS_ERROR;
    }

    if (CLT_LOB_INLINE(head) && stmt->conn->call_version >= CS_VERSION_3) {
        return clt_read_inline_blob(stmt, locator, offset, buffer, size, nbytes, eof);
    } else {
        return clt_read_blob_by_pack(stmt, locator, offset, buffer, size, nbytes, eof);
    }
}

status_t gsc_read_blob(gsc_stmt_t pstmt, void *locator, uint32 offset, void *buffer, uint32 size, uint32 *nbytes,
    uint32 *eof)
{
    status_t status;
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;

    GSC_CHECK_OBJECT_NULL_GS(stmt, "statement");
    GSC_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");

    GS_RETURN_IFERR(clt_lock_conn(stmt->conn));
    status = clt_read_blob(stmt, locator, offset, buffer, size, nbytes, eof);
    clt_unlock_conn(stmt->conn);
    return status;
}

status_t gsc_read_blob_by_id(gsc_stmt_t pstmt, uint32 id, uint32 offset, void *buffer, uint32 size, uint32 *nbytes,
    uint32 *eof)
{
    status_t status;
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;

    GSC_CHECK_OBJECT_NULL_GS(stmt, "statement");
    GSC_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");

    GS_RETURN_IFERR(clt_lock_conn(stmt->conn));
    status = clt_read_blob_by_id(stmt, id, offset, buffer, size, nbytes, eof);
    clt_unlock_conn(stmt->conn);
    return status;
}

static status_t clt_copy_clob(clt_stmt_t *stmt, char *data, void *buffer, uint32 buf_size, uint32 *nchars,
    uint32 *nbytes, uint32 *eof)
{
    if (*eof == GS_FALSE) {
        text_t text;
        text.str = data;
        text.len = *nbytes;
        uint16 charset_id = stmt->conn->server_info.server_charset;
        (void)CM_CHARSET_FUNC(charset_id).length_ignore_truncated_bytes(&text);
        *nbytes = text.len;
    }

    MEMS_RETURN_IFERR(memcpy_s(buffer, buf_size, data, *nbytes));

    if (nchars != NULL) {
        *nchars = *nbytes;
    }

    return GS_SUCCESS;
}

static status_t clt_copy_and_transcode_clob(clt_stmt_t *stmt, char *data, void *buffer, uint32 data_size,
    uint32 buf_size, uint32 *nchars, uint32 *nbytes, uint32 *eof)
{
    if (nchars != NULL) {
        *nchars = data_size;
    }

    if (nbytes == NULL || buffer == NULL) {
        return GS_SUCCESS;
    }
    *nbytes = data_size;

    if (stmt->conn->recv_trans_func != NULL) {
        bool32 trans_eof = GS_FALSE;
        int32 trans_len = stmt->conn->recv_trans_func(data, &data_size, buffer, buf_size, &trans_eof);
        if (trans_len < 0) {
            return GS_ERROR;
        }
        *nbytes -= data_size;

        if (nchars != NULL) {
            *nchars = (uint32)trans_len;
        }

        *eof = trans_eof && *eof;
        return GS_SUCCESS;
    }

    if (*nbytes > 0) {
        return clt_copy_clob(stmt, data, buffer, buf_size, nchars, nbytes, eof);
    }

    return GS_SUCCESS;
}

static status_t gsc_read_inline_clob(clt_stmt_t *stmt, void *locator, uint32 offset, void *buffer, uint32 size,
    uint32 *nchars, uint32 *nbytes, uint32 *eof)
{
    clt_lob_head_t *head = (clt_lob_head_t *)locator;
    uint32 len = (head->size > offset) ? MIN(size, head->size - offset) : 0;
    char *data = NULL;

    if (offset > head->size) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_OUT_OF_INDEX, "inline lob offset");
        return GS_ERROR;
    }

    CM_SET_VALUE_IF_NOTNULL(eof, ((offset + size) >= head->size));

    if (len == 0) {
        CM_SET_VALUE_IF_NOTNULL(nchars, 0);
        CM_SET_VALUE_IF_NOTNULL(nbytes, 0);
        return GS_SUCCESS;
    }

    GS_RETURN_IFERR(clt_get_inline_lob_data(stmt, locator, &data));

    return clt_copy_and_transcode_clob(stmt, data + offset, buffer, len, size, nchars, nbytes, eof);
}

status_t clt_read_clob(clt_stmt_t *stmt, void *locator, uint32 offset, void *buffer, uint32 size, uint32 *nchars,
    uint32 *nbytes, uint32 *eof)
{
    status_t ret = GS_SUCCESS;
    uint32 len;
    uint32 actual_eof = GS_FALSE;
    clt_packet_t *ack_pack = NULL;
    lob_read_ack_t *ack = NULL;
    clt_lob_head_t *head = (clt_lob_head_t *)locator;

    if (stmt->status < CLI_STMT_FETCHING) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_OUT_OF_API_SEQUENCE, "statement is not fetched");
        return GS_ERROR;
    }

    if (size < 1) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_BUF_SIZE_TOO_SMALL, "fetch clob data");
        return GS_ERROR;
    }

    if (CLT_LOB_INLINE(head) && stmt->conn->call_version >= CS_VERSION_3) {
        ret = gsc_read_inline_clob(stmt, locator, offset, buffer, size, nchars, nbytes, &actual_eof);
        CM_SET_VALUE_IF_NOTNULL(eof, actual_eof);
        return ret;
    }

    do {
        GS_RETURN_IFERR(clt_alloc_pack(stmt->conn, &ack_pack));

        ret = clt_read_lob(stmt, locator, offset, size, ack_pack);
        GS_BREAK_IF_ERROR(ret);

        cs_init_get(&ack_pack->pack);
        ret = cs_get_lob_read_ack(&ack_pack->pack, &ack);
        GS_BREAK_IF_ERROR(ret);

        len = ack->size;
        actual_eof = ack->eof;
        ret = clt_copy_and_transcode_clob(stmt, CS_READ_ADDR(&ack_pack->pack), buffer, len, size, nchars, nbytes,
            &actual_eof);
        CM_SET_VALUE_IF_NOTNULL(eof, actual_eof);
    } while (0);

    clt_free_pack(stmt->conn, ack_pack);
    return ret;
}

status_t gsc_read_clob(gsc_stmt_t pstmt, void *locator, uint32 offset, void *buffer, uint32 size, uint32 *nchars,
    uint32 *nbytes, uint32 *eof)
{
    status_t status;
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;

    GSC_CHECK_OBJECT_NULL_GS(stmt, "statement");
    GSC_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");

    GS_RETURN_IFERR(clt_lock_conn(stmt->conn));
    status = clt_read_clob(stmt, locator, offset, buffer, size, nchars, nbytes, eof);
    clt_unlock_conn(stmt->conn);
    return status;
}

static status_t clt_read_clob_by_id(clt_stmt_t *stmt, uint32 id, uint32 offset, void *buffer, uint32 size,
    uint32 *nchars, uint32 *nbytes, uint32 *eof)
{
    void *locator = NULL;
    uint32 is_null;
    uint32 read_nbytes = 0;
    void *tmp_buffer = buffer;
    uint32 tmp_nchars = 0;
    uint32 read_nchars = 0;
    uint32 tmp_nbytes = 0;
    uint32 tmp_eof;

    GS_RETURN_IFERR(clt_get_lob_locator(stmt, id, &locator, &is_null));

    if (is_null) {
        if (eof != NULL) {
            *eof = GS_TRUE;
        }

        if (nbytes != NULL) {
            *nbytes = 0;
        }

        if (nchars != NULL) {
            *nchars = 0;
        }

        return GS_SUCCESS;
    }

    do {
        GS_RETURN_IFERR(clt_read_clob(stmt, locator, offset + read_nbytes, tmp_buffer, size - read_nchars, &tmp_nchars,
            &tmp_nbytes, &tmp_eof));
        if (tmp_nchars == 0 && tmp_nbytes == 0) {
            break;
        }
        read_nbytes += tmp_nbytes;
        tmp_buffer = (void *)((char *)tmp_buffer + tmp_nchars);
        read_nchars += tmp_nchars;
    } while (tmp_eof == GS_FALSE && read_nchars < size);

    if (eof != NULL) {
        *eof = tmp_eof;
    }

    if (nbytes != NULL) {
        *nbytes = read_nbytes;
    }

    if (nchars != NULL) {
        *nchars = read_nchars;
    }

    return GS_SUCCESS;
}

status_t gsc_read_clob_by_id(gsc_stmt_t pstmt, uint32 id, uint32 offset, void *buffer, uint32 size, uint32 *nchars,
    uint32 *nbytes, uint32 *eof)
{
    status_t status;
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;

    GSC_CHECK_OBJECT_NULL_GS(stmt, "statement");
    GSC_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");

    GS_RETURN_IFERR(clt_lock_conn(stmt->conn));
    status = clt_read_clob_by_id(stmt, id, offset, buffer, size, nchars, nbytes, eof);
    clt_unlock_conn(stmt->conn);
    return status;
}

static status_t clt_get_lob_size_by_id(clt_stmt_t *stmt, void *locator, uint32 id, uint32 *size)
{
    uint32 is_null;

    GS_RETURN_IFERR(clt_get_lob_locator(stmt, id, &locator, &is_null));

    if (is_null) {
        if (size != NULL) {
            *size = 0;
        }

        return GS_SUCCESS;
    }

    if (locator == NULL) {
        GS_THROW_ERROR(ERR_CLT_OBJECT_IS_NULL, "LOB locator");
        return GS_ERROR;
    }

    if (size != NULL) {
        *size = ((clt_lob_head_t *)locator)->size;
    }

    return GS_SUCCESS;
}

status_t gsc_get_lob_size_by_id(gsc_stmt_t pstmt, uint32 id, uint32 *size)
{
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;
    void *locator = NULL;
    status_t status;

    GSC_CHECK_OBJECT_NULL_GS(stmt, "statement");
    GSC_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");

    GS_RETURN_IFERR(clt_lock_conn(stmt->conn));
    status = clt_get_lob_size_by_id(stmt, locator, id, size);
    clt_unlock_conn(stmt->conn);

    return status;
}

#define CLT_MIN_CONVERT_BUFFER_SIZE (uint32)128
#define CLT_BLOB_BUFFER_SIZE (CLT_MIN_CONVERT_BUFFER_SIZE / 2)
#define CLT_LOB_MORE *(uint32 *)"..."

status_t clt_blob_as_string(clt_stmt_t *stmt, void *locator, char *str, uint32 buf_size, uint32 *strl_len)
{
    uint32 read_size = 0;
    uint32 offset;
    uint8 buf[CLT_BLOB_BUFFER_SIZE];
    binary_t bin;
    uint32 eof = GS_FALSE;

    if (stmt->conn->autotrace) {
        *(uint32 *)str = CLT_LOB_MORE;
        *strl_len = (uint32)strlen(str);
        return GS_SUCCESS;
    }
    if (clt_read_blob(stmt, locator, 0, buf, CLT_BLOB_BUFFER_SIZE, &read_size, &eof) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (read_size >= CLT_BLOB_BUFFER_SIZE) {
        bin.bytes = buf;
        bin.size = CLT_BLOB_BUFFER_SIZE - 2;
        GS_RETURN_IFERR(cm_bin2str(&bin, GS_FALSE, str, buf_size));
        offset = (CLT_BLOB_BUFFER_SIZE * 2) - sizeof(uint32);
        *(uint32 *)(str + offset) = CLT_LOB_MORE;
    } else {
        bin.bytes = buf;
        bin.size = read_size;
        GS_RETURN_IFERR(cm_bin2str(&bin, GS_FALSE, str, buf_size));
    }

    *strl_len = (uint32)strlen(str);

    return GS_SUCCESS;
}

status_t clt_clob_as_string(clt_stmt_t *stmt, void *locator, char *str, uint32 buf_size, uint32 *read_size)
{
    bool32 eof = GS_TRUE;
    *read_size = 0;
    uint32 offset;
    uint32 buf_len = 0;

    if (buf_size <= 1) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_BUF_SIZE_TOO_SMALL, "fetch clob data");
        return GS_ERROR;
    }

    if (stmt->conn->autotrace) {
        *(uint32 *)str = CLT_LOB_MORE;
        return GS_SUCCESS;
    }

    if (clt_read_clob(stmt, locator, 0, str, buf_size - 1, &buf_len, read_size, &eof) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (!eof && (buf_len > sizeof(uint32))) {
        offset = buf_len - sizeof(uint32);
        *(uint32 *)(str + offset) = CLT_LOB_MORE;
    }

    str[buf_len] = '\0';
    return GS_SUCCESS;
}

status_t clt_image_as_string(clt_stmt_t *stmt, void *locator, char *str, uint32 buf_size, uint32 *read_size)
{
    bool32 eof = GS_TRUE;
    uint32 offset;
    *read_size = 0;

    if (buf_size <= 1) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_BUF_SIZE_TOO_SMALL, "fetch image data");
        return GS_ERROR;
    }

    if (stmt->conn->autotrace) {
        *(uint32 *)str = CLT_LOB_MORE;
        return GS_SUCCESS;
    }

    if (clt_read_blob(stmt, locator, 0, str, buf_size - 1, read_size, &eof) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (!eof && (*read_size > sizeof(uint32))) {
        offset = *read_size - sizeof(uint32);
        *(uint32 *)(str + offset) = CLT_LOB_MORE;
    }

    str[*read_size] = '\0';
    return GS_SUCCESS;
}

static inline status_t clt_recv_lob_write_ack(clt_stmt_t *stmt, cs_packet_t *ack_pack, gsc_lob_t *bnd_lob_piece)
{
    char *buf = NULL;
    cs_init_get(ack_pack);
    GS_RETURN_IFERR(cs_get_int16(ack_pack, (int16 *)&stmt->stmt_id));
    /* the client does not perceive vlob cursors and does not need endian conversion. */
    GS_RETURN_IFERR(cs_get_data(ack_pack, sizeof(gsc_lob_t), (void **)&buf));
    *bnd_lob_piece = *(gsc_lob_t *)buf;

    return GS_SUCCESS;
}

static inline status_t clt_pre_lob_write_req(clt_stmt_t *stmt, clt_packet_t *req_pack, lob_write_req_t **req,
    uint32 *req_offset, vm_cli_lob_t *bnd_lob_piece)
{
    GS_RETURN_IFERR(cs_reserve_space(&req_pack->pack, sizeof(lob_write_req_t), req_offset));
    *req = (lob_write_req_t *)CS_RESERVE_ADDR(&req_pack->pack, *req_offset);
    (*req)->vlob = *bnd_lob_piece;
    (*req)->stmt_id = stmt->stmt_id;

    return GS_SUCCESS;
}

static inline status_t clt_init_clob_write_req_size(lob_write_req_t *req, clt_packet_t *req_pack, int32 *len,
    const char *data_offset, uint32 *size, bool32 *eof, transcode_func_t transcode_func)
{
    *len = transcode_func(data_offset, size, CS_WRITE_ADDR(&req_pack->pack), MAX_LOB_BATCH_SIZE, eof);
    if (*len < 0) {
        return GS_ERROR;
    }
    req->size = (uint32)*len;
    return GS_SUCCESS;
}

static inline void clt_set_clob_write_size(uint32 *write_size, status_t ret, uint32 temp_write_size, uint32 size)
{
    uint32 t_size;
    if (ret == GS_SUCCESS) {
        t_size = temp_write_size - size;
    } else {
        t_size = temp_write_size;
    }

    if (write_size != NULL) {
        *write_size = t_size;
    }
}

static status_t clt_do_write_clob(clt_stmt_t *stmt, clt_param_t *param, uint32 piece, const char *data, uint32 size,
    uint32 *write_size, transcode_func_t transcode_func)
{
    status_t ret = GS_SUCCESS;
    int32 len;
    bool32 eof = GS_FALSE;
    clt_packet_t *req_pack = NULL;
    cs_packet_t *ack_pack = &stmt->cache_pack->pack;
    lob_write_req_t *req = NULL;
    uint32 req_offset;
    uint32 temp_write_size = size;
    gsc_lob_t *bnd_lob = (gsc_lob_t *)param->bnd_ptr;

    GS_RETURN_IFERR(clt_alloc_pack(stmt->conn, &req_pack));
    req_pack->pack.head->cmd = CS_CMD_LOB_WRITE;

    while (!eof) {
        // 1) init common head of request packet
        cs_init_set(&req_pack->pack, stmt->conn->call_version);

        // 2) put head of lob write packet into request packet
        ret = clt_pre_lob_write_req(stmt, req_pack, &req, &req_offset, &((vm_cli_lob_t *)bnd_lob)[piece]);
        GS_BREAK_IF_ERROR(ret);
        ret = clt_init_clob_write_req_size(req, req_pack, &len, data + temp_write_size - size, &size, &eof,
            transcode_func);
        GS_BREAK_IF_ERROR(ret);

        // 3) update head size of request packet
        ret = cs_inc_head_size(&req_pack->pack, (uint32)len);
        GS_BREAK_IF_ERROR(ret);

        // 4) update stmt_id and lob size in request packet if client's endian is different from server's endian
        cs_putted_lob_write_req(&req_pack->pack, req_offset);

        // 5) send request packet to server
        ret = clt_remote_call(stmt->conn, &req_pack->pack, ack_pack);
        GS_BREAK_IF_ERROR(ret);

        // 6) receive ack from server
        ret = clt_recv_lob_write_ack(stmt, ack_pack, &bnd_lob[piece]);
        GS_BREAK_IF_ERROR(ret);
    }

    clt_free_pack(stmt->conn, req_pack);

    clt_set_clob_write_size(write_size, ret, temp_write_size, size);

    return ret;
}


static inline void clt_init_lob_write_req_size(lob_write_req_t *req, uint32 remain_size)
{
    req->size = (remain_size > MAX_LOB_BATCH_SIZE) ? MAX_LOB_BATCH_SIZE : remain_size;
}

static inline void clt_update_lob_rsize_offset(clt_packet_t *req_pack, lob_write_req_t **req, uint32 *remain_size,
    uint32 *offset, uint32 req_offset)
{
    *req = (lob_write_req_t *)CS_RESERVE_ADDR(&req_pack->pack, req_offset);
    *remain_size -= (*req)->size;
    *offset += (*req)->size;
}

static status_t clt_do_write_lob(clt_stmt_t *stmt, clt_param_t *param, uint32 piece, const char *data, uint32 size)
{
    status_t ret = GS_SUCCESS;
    clt_packet_t *req_pack = NULL;
    cs_packet_t *ack_pack = &stmt->cache_pack->pack;
    lob_write_req_t *req = NULL;
    uint32 req_offset;
    uint32 remain_size = size;
    uint32 offset = 0;
    gsc_lob_t *bnd_lob = (gsc_lob_t *)param->bnd_ptr;

    GS_RETURN_IFERR(clt_alloc_pack(stmt->conn, &req_pack));
    req_pack->pack.head->cmd = CS_CMD_LOB_WRITE;

    while (remain_size > 0) {
        // 1) init common head of request packet
        cs_init_set(&req_pack->pack, stmt->conn->call_version);

        // 2) put head of lob write packet into request packet
        ret = clt_pre_lob_write_req(stmt, req_pack, &req, &req_offset, &((vm_cli_lob_t *)bnd_lob)[piece]);
        GS_BREAK_IF_ERROR(ret);
        clt_init_lob_write_req_size(req, remain_size);

        // 3) put lob data into request packet
        ret = cs_put_data(&req_pack->pack, data + offset, req->size);
        GS_BREAK_IF_ERROR(ret);

        // 4) update remain_size of lob and offset of lob after 3)
        // notice: packet address of req need get again because it may changed in cs_put_data!
        clt_update_lob_rsize_offset(req_pack, &req, &remain_size, &offset, req_offset);

        // 5) update stmt_id and lob size in request packet if client's endian is different from server's endian
        cs_putted_lob_write_req(&req_pack->pack, req_offset);

        // 6) send request packet to server
        ret = clt_remote_call(stmt->conn, &req_pack->pack, ack_pack);
        GS_BREAK_IF_ERROR(ret);

        // 7) receive ack from server
        ret = clt_recv_lob_write_ack(stmt, ack_pack, &bnd_lob[piece]);
        GS_BREAK_IF_ERROR(ret);
    }

    clt_free_pack(stmt->conn, req_pack);
    return ret;
}

status_t clt_write_clob(clt_stmt_t *stmt, uint32 id, uint32 piece, const char *data, uint32 size, uint32 *nchars)
{
    clt_param_t *param = NULL;
    transcode_func_t transcode_func;

    if (clt_verify_lob(stmt, id, &param) != GS_SUCCESS) {
        return GS_ERROR;
    }

    transcode_func = stmt->conn->send_trans_func;
    if (param->is_W_CType) {
        transcode_func = cm_from_transcode_func_ucs2(stmt->conn->server_info.server_charset);
    }

    if (transcode_func != NULL) {
        return clt_do_write_clob(stmt, param, piece, data, size, nchars, transcode_func);
    } else {
        if (nchars != NULL) {
            *nchars = size;
        }
        return clt_do_write_lob(stmt, param, piece, data, size);
    }
}

status_t clt_write_blob(clt_stmt_t *stmt, uint32 id, uint32 piece, const char *data, uint32 size)
{
    clt_param_t *param = NULL;

    if (clt_verify_lob(stmt, id, &param) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return clt_do_write_lob(stmt, param, piece, data, size);
}

#ifdef __cplusplus
}
#endif
