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
 * gsc_fetch.c
 *
 *
 * IDENTIFICATION
 * src/driver/gsc/gsc_fetch.c
 *
 * -------------------------------------------------------------------------
 */
#include "gsc_fetch.h"
#include "cm_row.h"
#include "gsc_lob.h"

#ifdef __cplusplus
extern "C" {
#endif

static status_t clt_remote_fetch_core(clt_stmt_t *stmt, cs_packet_t *req_pack, cs_packet_t *ack_pack)
{
    CT_RETURN_IFERR(clt_remote_call(stmt->conn, req_pack, ack_pack));

    do {
        if (ack_pack->head->flags & CS_FLAG_SERVEROUPUT) {
            (void)clt_receive_serveroutput(stmt, ack_pack);
            CT_RETURN_IFERR(clt_remote_call(stmt->conn, ack_pack, ack_pack));
            continue;
        } else if (ack_pack->head->flags & ~CS_FLAG_SERVEROUPUT) {
            CLT_THROW_ERROR(stmt->conn, ERR_CLT_FETCH_INVALID_FLAGS);
            return CT_ERROR;
        }
        break;
    } while (CT_TRUE);

    cs_init_get(&stmt->cache_pack->pack);
    return CT_SUCCESS;
}

status_t clt_remote_fetch(clt_stmt_t *stmt)
{
    cs_fetch_req_t *req = NULL;
    cs_fetch_ack_t *ack = NULL;
    cs_packet_t *req_pack = &stmt->conn->pack;
    cs_packet_t *ack_pack = &stmt->cache_pack->pack;
    uint32 req_offset;

    req_pack->head->cmd = CS_CMD_FETCH;

    cs_init_set(req_pack, stmt->conn->call_version);

    CT_RETURN_IFERR(cs_reserve_space(req_pack, sizeof(cs_fetch_req_t), &req_offset));
    req = (cs_fetch_req_t *)CS_RESERVE_ADDR(req_pack, req_offset);
    req->stmt_id = stmt->stmt_id;
    req->fetch_mode = stmt->fetch_mode;
    cs_putted_fetch_req(req_pack, req_offset);

    CT_RETURN_IFERR(clt_remote_fetch_core(stmt, req_pack, ack_pack));

    // get metadata of open cursor in PL
    if (req->fetch_mode == CS_FETCH_NORMAL) {
        CT_RETURN_IFERR(cs_get_fetch_ack(ack_pack, &ack));
        stmt->row_index = 0;
        stmt->affected_rows = ack->total_rows;
        stmt->return_rows = ack->batch_rows;
        stmt->more_rows = ack->rows_more;
        stmt->eof = (stmt->return_rows == 0);
    } else if (req->fetch_mode == CS_FETCH_WITH_PREP_EXEC) {
        CT_RETURN_IFERR(clt_get_prepare_ack(stmt, ack_pack, NULL));
        CT_RETURN_IFERR(clt_get_execute_ack(stmt));
        return CT_SUCCESS;
    } else if (req->fetch_mode == CS_FETCH_WITH_PREP) {
        CT_RETURN_IFERR(clt_get_prepare_ack(stmt, ack_pack, NULL));
        CT_RETURN_IFERR(cs_get_fetch_ack(ack_pack, &ack));
        stmt->row_index = 0;
        stmt->affected_rows = ack->total_rows;
        stmt->return_rows = ack->batch_rows;
        stmt->more_rows = ack->rows_more;
        stmt->eof = (stmt->return_rows == 0);
    }

    return CT_SUCCESS;
}

#define CLT_CHECK_BIND_SIZE(column, size)                                                            \
    do {                                                                                             \
        if ((column)->bnd_ptr != NULL && (column)->bnd_size < (size)) {                              \
            CLT_THROW_ERROR(stmt->conn, ERR_CLT_COL_SIZE_TOO_SMALL, (uint32)(column)->id, "binding", \
                (uint32)(column)->bnd_size, (uint32)(size));                                         \
            return CT_ERROR;                                                                         \
        }                                                                                            \
    } while (0)

static inline void clt_get_row_assist(clt_stmt_t *stmt, char *row_addr, bool8 diff_endian, row_assist_t *ra)
{
    cm_attach_row(ra, row_addr);

    if (diff_endian) {
        ra->head->size = cs_reverse_int16(ra->head->size);
        ra->head->column_count = cs_reverse_int16(ra->head->column_count);
        if (IS_SPRS_ROW(ra->head)) {
            ra->head->sprs_count = cs_reverse_int16(ra->head->sprs_count);
        }
    }

    stmt->cache_pack->pack.offset += ra->head->size;
}

static status_t clt_save_inline_lob(clt_stmt_t *stmt, clt_column_t *column)
{
    clt_lob_head_t *head = (clt_lob_head_t *)column->ptr;
    clt_inline_lob_t *lob = NULL;
    clt_cache_lob_t *cache_lob = NULL;
    uint32 need_len, new_buf_size, value_pos;
    char *new_buf = NULL;

    if (!(CLT_LOB_INLINE(head) && stmt->conn->call_version >= CS_VERSION_3)) {
        return CT_SUCCESS;
    }

    lob = &column->inline_lob;

    /* reset pos of inline lob cache if fetch next */
    if (stmt->fetch_pos == 0) {
        lob->used_pos = 0;
    }

    need_len = lob->used_pos + (GSC_INLINE_LOB_ENCODE_LEN + head->size);

    /* try extend inline lob cache buf */
    if (need_len > lob->cache_buf.len) {
        new_buf_size = CM_ALIGN_8K(need_len);
        new_buf = (char *)malloc(new_buf_size);
        if (new_buf == NULL) {
            CT_THROW_ERROR(ERR_ALLOC_MEMORY, new_buf_size, "inline lob cache buffer");
            return CT_ERROR;
        }

        if (lob->used_pos > 0) {
            errno_t err = memcpy_s(new_buf, new_buf_size, lob->cache_buf.str, lob->used_pos);
            if (err != EOK) {
                CM_FREE_PTR(new_buf);
                CT_THROW_ERROR(ERR_SYSTEM_CALL, err);
            }
        }
        CM_FREE_PTR(lob->cache_buf.str);
        lob->cache_buf.str = new_buf;
        lob->cache_buf.len = new_buf_size;
    }

    /* encode inline lob data, contains clt_cache_lob_t(clt_lob_head_t + fetched_times + column_id + offset) */
    value_pos = lob->used_pos;

    cache_lob = (clt_cache_lob_t *)(lob->cache_buf.str + lob->used_pos);
    cache_lob->lob_head = *head;
    cache_lob->fetched_times = stmt->fetched_times;
    cache_lob->column_id = column->id;
    cache_lob->offset = value_pos;
    lob->used_pos += GSC_INLINE_LOB_ENCODE_LEN;

    if (head->size > 0) {
        MEMS_RETURN_IFERR(memcpy_s(lob->cache_buf.str + lob->used_pos, lob->cache_buf.len - lob->used_pos,
            column->ptr + sizeof(clt_lob_head_t), head->size));
        lob->used_pos += head->size;
    }

    column->ptr = lob->cache_buf.str + value_pos;
    return CT_SUCCESS;
}

static void clt_set_offset(clt_stmt_t *stmt, clt_column_t *column, bool8 diff_endian, uint8 bits, uint32 *pos,
    const char *row_addr)
{
    bool8 not_shd_dn = (stmt->conn->node_type != CS_TYPE_DN);
    timestamp_ltz_t *ltz = NULL;

    if (bits == COL_BITS_4) {
        column->size = 4;
        *pos += 4;
    } else if (bits == COL_BITS_8) {
        column->size = 8;

        if (not_shd_dn && GSC_IS_TIMESTAMP_LTZ_TYPE(column->def.datatype)) {
            ltz = (timestamp_ltz_t *)column->ptr;
            *ltz = cm_adjust_date_between_two_tzs(*ltz, stmt->conn->server_info.server_dbtimezone,
                stmt->conn->local_sessiontz);
        }
        *pos += 8;
    } else {
        column->size = *(uint16 *)(row_addr + *pos);
        if (diff_endian) {
            column->size = cs_reverse_int16(column->size);
        }
        column->ptr += sizeof(uint16);
        *pos += CM_ALIGN4(column->size + sizeof(uint16));
    }

    if (column->ind_ptr != NULL) {
        column->ind_ptr[stmt->fetch_pos] = column->size;
    }
}

static status_t clt_read_row(clt_stmt_t *stmt, bool32 fetch_ori_row)
{
    char *row_addr = CS_READ_ADDR(&stmt->cache_pack->pack);
    bool8 diff_endian = CS_DIFFERENT_ENDIAN(stmt->cache_pack->pack.options);
    row_assist_t ra;

    clt_get_row_assist(stmt, row_addr, diff_endian, &ra);

    if (fetch_ori_row == CT_TRUE) {
        stmt->ori_row = row_addr;
        return CT_SUCCESS;
    }

    // check whether column count in row is equals to prepare ack
    if (stmt->fetch_pos == 0 && stmt->column_count != ROW_COLUMN_COUNT(ra.head)) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_INVALID_COLUMN, (uint32)ROW_COLUMN_COUNT(ra.head), "column",
            stmt->column_count);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(clt_reset_stmt_transcode_buf(stmt));

    uint32 pos = sizeof(row_head_t) + ROW_BITMAP_EX_SIZE(ra.head);

    for (uint32 i = 0; i < stmt->column_count; ++i) {
        clt_column_t *column = (clt_column_t *)cm_list_get(&stmt->columns, i);
        uint8 bits = row_get_column_bits(&ra, i);
        column->ptr = row_addr + pos;

        if (bits == COL_BITS_NULL) {
            column->size = GSC_NULL;
            if (column->ind_ptr != NULL) {
                column->ind_ptr[stmt->fetch_pos] = column->size;
            }
            continue;
        } else {
            clt_set_offset(stmt, column, diff_endian, bits, &pos, row_addr);
        }

        /* try trans charset for string value */
        if (stmt->conn->recv_trans_func != NULL && GSC_IS_STRING_TYPE(column->def.datatype)) {
            uint32 size = column->size;
            if (clt_transcode_column(stmt, &column->ptr, &size, stmt->conn->recv_trans_func) != CT_SUCCESS) {
                CLT_THROW_ERROR(stmt->conn, ERR_CLT_TRANS_CHARSET, column->def.name, column->ptr);
                return CT_ERROR;
            }
            column->size = (uint16)size;
        }

        /* cache inline lob data */
        if (stmt->fetch_size > 1 && GSC_IS_LOB_TYPE(column->def.datatype)) {
            CT_RETURN_IFERR(clt_save_inline_lob(stmt, column));
        }

        /* try fill fetched column value into memory bound */
        if (column->bnd_ptr == NULL) {
            continue;
        }
        CT_RETURN_IFERR(column->cp_func(stmt, column));
    }

    return CT_SUCCESS;
}

#define COPY_NATIVE_VAL(type, stmt, column)                                         \
    do {                                                                            \
        char *bnd_ptr = (column)->bnd_ptr + (column)->bnd_size * (stmt)->fetch_pos; \
        *(type *)bnd_ptr = *(type *)(column)->ptr;                                  \
    } while (0)

#define COPY_NATIVE_VAL_REVERSE(type, stmt, column, reverser)                       \
    do {                                                                            \
        char *bnd_ptr = (column)->bnd_ptr + (column)->bnd_size * (stmt)->fetch_pos; \
        *(type *)bnd_ptr = reverser(*(type *)(column)->ptr);                        \
    } while (0)
static status_t copy_uint32_val(clt_stmt_t *stmt, clt_column_t *column)
{
    COPY_NATIVE_VAL(uint32, stmt, column);
    return CT_SUCCESS;
}

static status_t copy_int32_val(clt_stmt_t *stmt, clt_column_t *column)
{
    COPY_NATIVE_VAL(int32, stmt, column);
    return CT_SUCCESS;
}

static status_t copy_uint32_val_reverse(clt_stmt_t *stmt, clt_column_t *column)
{
    COPY_NATIVE_VAL_REVERSE(uint32, stmt, column, cs_reverse_uint32);
    return CT_SUCCESS;
}

static status_t copy_int32_val_reverse(clt_stmt_t *stmt, clt_column_t *column)
{
    COPY_NATIVE_VAL_REVERSE(int32, stmt, column, cs_reverse_int32);
    return CT_SUCCESS;
}

static status_t copy_int64_val(clt_stmt_t *stmt, clt_column_t *column)
{
    COPY_NATIVE_VAL(int64, stmt, column);
    return CT_SUCCESS;
}

static status_t copy_int64_val_reverse(clt_stmt_t *stmt, clt_column_t *column)
{
    COPY_NATIVE_VAL_REVERSE(int64, stmt, column, cs_reverse_int64);
    return CT_SUCCESS;
}

static status_t copy_double_val(clt_stmt_t *stmt, clt_column_t *column)
{
    COPY_NATIVE_VAL(double, stmt, column);
    return CT_SUCCESS;
}

static status_t copy_double_val_reverse(clt_stmt_t *stmt, clt_column_t *column)
{
    COPY_NATIVE_VAL_REVERSE(double, stmt, column, cs_reverse_real);
    return CT_SUCCESS;
}

static status_t copy_timestamp_tz_val(clt_stmt_t *stmt, clt_column_t *column)
{
    char *bnd_ptr = column->bnd_ptr + column->bnd_size * stmt->fetch_pos;

    MEMS_RETURN_IFERR(memcpy_s(bnd_ptr, column->bnd_size, column->ptr, sizeof(timestamp_tz_t)));

    if (column->ind_ptr) {
        column->ind_ptr[stmt->fetch_pos] = sizeof(timestamp_tz_t);
    }

    return CT_SUCCESS;
}

static status_t copy_timestamp_tz_val_reverse(clt_stmt_t *stmt, clt_column_t *column)
{
    timestamp_tz_t *dst = (timestamp_tz_t *)(column->bnd_ptr + column->bnd_size * stmt->fetch_pos);
    timestamp_tz_t *src = (timestamp_tz_t *)column->ptr;

    dst->tstamp = cs_reverse_int64(src->tstamp);
    dst->tz_offset = cs_reverse_int16(src->tz_offset);

    if (column->ind_ptr) {
        column->ind_ptr[stmt->fetch_pos] = sizeof(timestamp_tz_t);
    }

    return CT_SUCCESS;
}

static status_t copy_str_val(clt_stmt_t *stmt, clt_column_t *column)
{
    char *bnd_ptr = column->bnd_ptr + column->bnd_size * stmt->fetch_pos;
    uint16 col_len = column->size;

    if (col_len != 0) {
        MEMS_RETURN_IFERR(memcpy_s(bnd_ptr, column->size, column->ptr, col_len));
    }
    return CT_SUCCESS;
}

static status_t copy_digit_val_reverse(clt_stmt_t *stmt, clt_column_t *column)
{
    dec4_t *dst = (dec4_t *)(column->bnd_ptr + column->bnd_size * stmt->fetch_pos);
    uint16 col_len = column->size;
    dec4_t *src = (dec4_t *)column->ptr;
    if (col_len != 0) {
        cm_reverse_dec4(dst, src);
    }
    return CT_SUCCESS;
}


#define copy_digit2_val_reverse copy_str_val
#define copy_digit_val copy_str_val


static status_t copy_lob_val(clt_stmt_t *stmt, clt_column_t *column)
{
    char *bnd_ptr = column->bnd_ptr + column->bnd_size * stmt->fetch_pos;
    uint16 col_len;

    if (CLT_LOB_INLINE((clt_lob_head_t *)column->ptr) && stmt->fetch_size > 1 &&
        stmt->conn->call_version >= CS_VERSION_3) {
        col_len = (uint16)GSC_INLINE_LOB_ENCODE_LEN;
    } else {
        col_len = column->size;
    }

    if (col_len != 0) {
        MEMS_RETURN_IFERR(
            memcpy_s(bnd_ptr, column->bnd_size, column->ptr, MIN(stmt->conn->server_info.locator_size, col_len)));
    }
    return CT_SUCCESS;
}

static status_t copy_default_type_val(clt_stmt_t *stmt, clt_column_t *column)
{
    char *bnd_ptr = column->bnd_ptr + column->bnd_size * stmt->fetch_pos;
    uint16 col_len = column->size;

    if (column->bnd_size <= col_len) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_COL_SIZE_TOO_SMALL, (uint32)column->id, "binding", (uint32)column->bnd_size,
            (uint32)(col_len + 1));

        if (column->bnd_size == 0) {
            return CT_ERROR;
        }
        col_len = column->bnd_size - 1;
    }

    if (col_len != 0) {
        MEMS_RETURN_IFERR(memcpy_s(bnd_ptr, column->bnd_size, column->ptr, col_len));
    }
    bnd_ptr[col_len] = '\0';
    return CT_SUCCESS;
}

static inline status_t chk_and_cp_null_str(clt_stmt_t *stmt, clt_column_t *column, char *bnd_ptr)
{
    if (column->bnd_size <= 1) {
        if (column->bnd_size == 1) {
            bnd_ptr[0] = '\0';
            return CT_SUCCESS;
        }

        CLT_THROW_ERROR(stmt->conn, ERR_CLT_BIND_SIZE_SMALL, (uint32)column->id, (char *)column->def.name,
            (uint32)column->bnd_size);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

#define COPY_NATIVE_VAL_2STR(type, print_fmt, stmt, column, bnd_ptr)                                         \
    do {                                                                                                     \
        if (chk_and_cp_null_str((stmt), (column), (bnd_ptr)) != CT_SUCCESS) {                                \
            return CT_ERROR;                                                                                 \
        }                                                                                                    \
        type value = *(type *)(column)->ptr;                                                                 \
        int32 ret = snprintf_s((bnd_ptr), (column)->bnd_size, (column)->bnd_size - 1, (print_fmt), value);   \
        PRTS_RETURN_IFERR(ret);                                                                              \
        if ((column)->ind_ptr) {                                                                             \
            (column)->ind_ptr[(stmt)->fetch_pos] = ret;                                                      \
        }                                                                                                    \
    } while (0)

#define COPY_NATIVE_VAL_2STR_REVERSE(type, print_fmt, stmt, column, reverser, bnd_ptr)                      \
    do {                                                                                                    \
        if (chk_and_cp_null_str((stmt), (column), (bnd_ptr)) != CT_SUCCESS) {                               \
            return CT_ERROR;                                                                                \
        }                                                                                                   \
        type value = (reverser)(*(type *)(column)->ptr);                                                    \
        int32 ret = snprintf_s((bnd_ptr), (column)->bnd_size, (column)->bnd_size - 1, (print_fmt), value);  \
        PRTS_RETURN_IFERR(ret);                                                                             \
        if ((column)->ind_ptr) {                                                                            \
            (column)->ind_ptr[(stmt)->fetch_pos] = ret;                                                     \
        }                                                                                                   \
    } while (0)

static status_t copy_int32_val_2str(clt_stmt_t *stmt, clt_column_t *column)
{
    char *bnd_ptr = column->bnd_ptr + column->bnd_size * stmt->fetch_pos;

    if (chk_and_cp_null_str(stmt, column, bnd_ptr) != CT_SUCCESS) {
        return CT_ERROR;
    }
    COPY_NATIVE_VAL_2STR(int32, PRINT_FMT_INTEGER, stmt, column, bnd_ptr);
    return CT_SUCCESS;
}

static status_t copy_int32_val_2str_reverse(clt_stmt_t *stmt, clt_column_t *column)
{
    char *bnd_ptr = column->bnd_ptr + column->bnd_size * stmt->fetch_pos;

    if (chk_and_cp_null_str(stmt, column, bnd_ptr) != CT_SUCCESS) {
        return CT_ERROR;
    }
    COPY_NATIVE_VAL_2STR_REVERSE(int32, PRINT_FMT_INTEGER, stmt, column, cs_reverse_int32, bnd_ptr);
    return CT_SUCCESS;
}

static status_t copy_uint32_val_2str(clt_stmt_t *stmt, clt_column_t *column)
{
    char *bnd_ptr = column->bnd_ptr + column->bnd_size * stmt->fetch_pos;

    if (chk_and_cp_null_str(stmt, column, bnd_ptr) != CT_SUCCESS) {
        return CT_ERROR;
    }
    COPY_NATIVE_VAL_2STR(uint32, PRINT_FMT_UINT32, stmt, column, bnd_ptr);
    return CT_SUCCESS;
}

static status_t copy_uint32_val_2str_reverse(clt_stmt_t *stmt, clt_column_t *column)
{
    char *bnd_ptr = column->bnd_ptr + column->bnd_size * stmt->fetch_pos;

    if (chk_and_cp_null_str(stmt, column, bnd_ptr) != CT_SUCCESS) {
        return CT_ERROR;
    }
    COPY_NATIVE_VAL_2STR_REVERSE(uint32, PRINT_FMT_UINT32, stmt, column, cs_reverse_uint32, bnd_ptr);
    return CT_SUCCESS;
}

static status_t copy_int64_val_2str(clt_stmt_t *stmt, clt_column_t *column)
{
    char *bnd_ptr = column->bnd_ptr + column->bnd_size * stmt->fetch_pos;

    if (chk_and_cp_null_str(stmt, column, bnd_ptr) != CT_SUCCESS) {
        return CT_ERROR;
    }
    COPY_NATIVE_VAL_2STR(int64, PRINT_FMT_BIGINT, stmt, column, bnd_ptr);
    return CT_SUCCESS;
}

static status_t copy_int64_val_2str_reverse(clt_stmt_t *stmt, clt_column_t *column)
{
    char *bnd_ptr = column->bnd_ptr + column->bnd_size * stmt->fetch_pos;

    if (chk_and_cp_null_str(stmt, column, bnd_ptr) != CT_SUCCESS) {
        return CT_ERROR;
    }
    COPY_NATIVE_VAL_2STR_REVERSE(int64, PRINT_FMT_BIGINT, stmt, column, cs_reverse_int64, bnd_ptr);
    return CT_SUCCESS;
}

static status_t copy_double_val_2str(clt_stmt_t *stmt, clt_column_t *column)
{
    int32 ret;
    char *bnd_ptr = column->bnd_ptr + column->bnd_size * stmt->fetch_pos;
    double value = *(double *)column->ptr;

    if (chk_and_cp_null_str(stmt, column, bnd_ptr) != CT_SUCCESS) {
        return CT_ERROR;
    }
    CM_SNPRINTF_REAL(ret, bnd_ptr, value, column->bnd_size);
    PRTS_RETURN_IFERR(ret);
    if (column->ind_ptr) {
        column->ind_ptr[stmt->fetch_pos] = ret;
    }
    return CT_SUCCESS;
}

static status_t copy_double_val_2str_reverse(clt_stmt_t *stmt, clt_column_t *column)
{
    int32 ret;
    char *bnd_ptr = column->bnd_ptr + column->bnd_size * stmt->fetch_pos;
    double value = cs_reverse_real(*(double *)column->ptr);

    CT_RETURN_IFERR(chk_and_cp_null_str(stmt, column, bnd_ptr));
    CM_SNPRINTF_REAL(ret, bnd_ptr, value, column->bnd_size);
    PRTS_RETURN_IFERR(ret);
    if (column->ind_ptr) {
        column->ind_ptr[stmt->fetch_pos] = ret;
    }
    return CT_SUCCESS;
}
static status_t copy_number_val_2str_reverse(clt_stmt_t *stmt, clt_column_t *column)
{
    char *bnd_ptr = column->bnd_ptr + column->bnd_size * stmt->fetch_pos;

    CT_RETURN_IFERR(chk_and_cp_null_str(stmt, column, bnd_ptr));

    text_t text;
    text.str = bnd_ptr;
    text.len = 0;

    if (column->bnd_size > 1) {
        dec4_t dst;
        cm_reverse_dec4(&dst, (dec4_t *)column->ptr);
        if (cm_dec4_to_text((dec4_t *)&dst, column->bnd_size - 1, &text) != CT_SUCCESS) {
            CLT_THROW_ERROR(stmt->conn, ERR_CLT_BIND_SIZE_SMALL, (uint32)column->id, (char *)column->def.name,
                (uint32)column->bnd_size);
            return CT_ERROR;
        }
        bnd_ptr[text.len] = '\0';
    }

    if (column->ind_ptr) {
        column->ind_ptr[stmt->fetch_pos] = (uint16)text.len;
    }

    return CT_SUCCESS;
}

static status_t copy_number_val_2str(clt_stmt_t *stmt, clt_column_t *column)
{
    char *bnd_ptr = column->bnd_ptr + column->bnd_size * stmt->fetch_pos;

    CT_RETURN_IFERR(chk_and_cp_null_str(stmt, column, bnd_ptr));

    text_t text;
    text.str = bnd_ptr;
    text.len = 0;

    if (column->bnd_size > 1) {
        /* max write size of text.str is column->bnd_size-1 */
        if (cm_dec4_to_text((dec4_t *)column->ptr, column->bnd_size - 1, &text) != CT_SUCCESS) {
            CLT_THROW_ERROR(stmt->conn, ERR_CLT_BIND_SIZE_SMALL, (uint32)column->id, (char *)column->def.name,
                (uint32)column->bnd_size);
            return CT_ERROR;
        }
        text.str[text.len] = '\0';
    }

    if (column->ind_ptr) {
        column->ind_ptr[stmt->fetch_pos] = (uint16)text.len;
    }

    return CT_SUCCESS;
}

static status_t copy_number2_val_2str(clt_stmt_t *stmt, clt_column_t *column)
{
    char *bnd_ptr = column->bnd_ptr + column->bnd_size * stmt->fetch_pos;

    CT_RETURN_IFERR(chk_and_cp_null_str(stmt, column, bnd_ptr));

    if (column->bnd_size > 1) {
        dec2_t dec2;
        cm_dec2_copy_ex(&dec2, (const payload_t *)column->ptr, (uint8)column->size);
        if (cm_dec2_to_str(&dec2, column->bnd_size, bnd_ptr) != CT_SUCCESS) {
            CLT_THROW_ERROR(stmt->conn, ERR_CLT_BIND_SIZE_SMALL, (uint32)column->id, (char *)column->def.name,
                (uint32)column->bnd_size);
            return CT_ERROR;
        }
    }

    if (column->ind_ptr) {
        column->ind_ptr[stmt->fetch_pos] = (uint16)strlen(bnd_ptr);
    }

    return CT_SUCCESS;
}

static status_t copy_boolean_val_2str(clt_stmt_t *stmt, clt_column_t *column)
{
    char *bnd_ptr = column->bnd_ptr + column->bnd_size * stmt->fetch_pos;

    CT_RETURN_IFERR(chk_and_cp_null_str(stmt, column, bnd_ptr));

    int32 int_value = *(int32 *)column->ptr;
    uint32 len = cm_bool2str((bool32)int_value, bnd_ptr);
    if (column->ind_ptr) {
        column->ind_ptr[stmt->fetch_pos] = (uint16)len;
    }

    return CT_SUCCESS;
}

static status_t copy_boolean_val_2str_reverse(clt_stmt_t *stmt, clt_column_t *column)
{
    char *bnd_ptr = column->bnd_ptr + column->bnd_size * stmt->fetch_pos;

    CT_RETURN_IFERR(chk_and_cp_null_str(stmt, column, bnd_ptr));

    int32 int_value = cs_reverse_int32(*(int32 *)column->ptr);
    uint32 len = cm_bool2str((bool32)int_value, bnd_ptr);
    if (column->ind_ptr) {
        column->ind_ptr[stmt->fetch_pos] = (uint16)len;
    }

    return CT_SUCCESS;
}

static status_t copy_date_val_2str(clt_stmt_t *stmt, clt_column_t *column)
{
    char *bnd_ptr = column->bnd_ptr + column->bnd_size * stmt->fetch_pos;
    text_t fmt_text;

    CT_RETURN_IFERR(chk_and_cp_null_str(stmt, column, bnd_ptr));

    clt_session_nlsparam_geter(stmt, NLS_DATE_FORMAT, &fmt_text);
    CLT_CHECK_BIND_SIZE(column, fmt_text.len + 1);
    int64 bigint_value = *(int64 *)column->ptr;
    text_t date_text;
    date_text.str = bnd_ptr;
    date_text.len = 0;

    CT_RETURN_IFERR(cm_date2text_ex((date_t)bigint_value, &fmt_text, 0, &date_text, column->bnd_size));

    if (column->ind_ptr) {
        column->ind_ptr[stmt->fetch_pos] = (uint16)date_text.len;
    }

    return CT_SUCCESS;
}

static status_t copy_date_val_2str_reverse(clt_stmt_t *stmt, clt_column_t *column)
{
    char *bnd_ptr = column->bnd_ptr + column->bnd_size * stmt->fetch_pos;
    text_t fmt_text;

    CT_RETURN_IFERR(chk_and_cp_null_str(stmt, column, bnd_ptr));

    clt_session_nlsparam_geter(stmt, NLS_DATE_FORMAT, &fmt_text);
    CLT_CHECK_BIND_SIZE(column, fmt_text.len + 1);
    int64 bigint_value = cs_reverse_int64(*(int64 *)column->ptr);
    text_t date_text;
    date_text.str = bnd_ptr;
    date_text.len = 0;

    CT_RETURN_IFERR(cm_date2text_ex((date_t)bigint_value, &fmt_text, 0, &date_text, column->bnd_size));

    if (column->ind_ptr) {
        column->ind_ptr[stmt->fetch_pos] = (uint16)date_text.len;
    }

    return CT_SUCCESS;
}

static status_t copy_timestamp_val_2str(clt_stmt_t *stmt, clt_column_t *column)
{
    char *bnd_ptr = column->bnd_ptr + column->bnd_size * stmt->fetch_pos;
    text_t fmt_text;

    CT_RETURN_IFERR(chk_and_cp_null_str(stmt, column, bnd_ptr));

    clt_session_nlsparam_geter(stmt, NLS_TIMESTAMP_FORMAT, &fmt_text);
    CLT_CHECK_BIND_SIZE(column, fmt_text.len + 7);
    int64 bigint_value = *(int64 *)column->ptr;
    text_t tmstamp_text;
    tmstamp_text.str = bnd_ptr;
    tmstamp_text.len = 0;

    CT_RETURN_IFERR(cm_timestamp2text_ex((timestamp_t)bigint_value, &fmt_text, column->def.precision, &tmstamp_text,
        column->bnd_size));

    if (column->ind_ptr) {
        column->ind_ptr[stmt->fetch_pos] = (uint16)tmstamp_text.len;
    }

    return CT_SUCCESS;
}

static status_t copy_timestamp_val_2str_reverse(clt_stmt_t *stmt, clt_column_t *column)
{
    char *bnd_ptr = column->bnd_ptr + column->bnd_size * stmt->fetch_pos;
    text_t fmt_text;

    CT_RETURN_IFERR(chk_and_cp_null_str(stmt, column, bnd_ptr));

    clt_session_nlsparam_geter(stmt, NLS_TIMESTAMP_FORMAT, &fmt_text);
    CLT_CHECK_BIND_SIZE(column, fmt_text.len + 7);
    int64 bigint_value = cs_reverse_int64(*(int64 *)column->ptr);
    text_t tmstamp_text;
    tmstamp_text.str = bnd_ptr;
    tmstamp_text.len = 0;

    CT_RETURN_IFERR(cm_timestamp2text_ex((timestamp_t)bigint_value, &fmt_text, column->def.precision, &tmstamp_text,
        column->bnd_size));

    if (column->ind_ptr) {
        column->ind_ptr[stmt->fetch_pos] = (uint16)tmstamp_text.len;
    }

    return CT_SUCCESS;
}

static status_t copy_timestamp_tz_val_2str(clt_stmt_t *stmt, clt_column_t *column)
{
    char *bnd_ptr = column->bnd_ptr + column->bnd_size * stmt->fetch_pos;
    text_t fmt_text;
    text_t tmstamp_tz_text;

    CT_RETURN_IFERR(chk_and_cp_null_str(stmt, column, bnd_ptr));

    clt_session_nlsparam_geter(stmt, NLS_TIMESTAMP_TZ_FORMAT, &fmt_text);
    CLT_CHECK_BIND_SIZE(column, fmt_text.len + 7);

    tmstamp_tz_text.str = bnd_ptr;
    tmstamp_tz_text.len = 0;

    CT_RETURN_IFERR(cm_timestamp_tz2text_ex((timestamp_tz_t *)column->ptr, &fmt_text, column->def.precision,
        &tmstamp_tz_text, column->bnd_size));

    if (column->ind_ptr) {
        column->ind_ptr[stmt->fetch_pos] = (uint16)tmstamp_tz_text.len;
    }

    return CT_SUCCESS;
}

static status_t copy_timestamp_tz_val_2str_reverse(clt_stmt_t *stmt, clt_column_t *column)
{
    char *bnd_ptr = column->bnd_ptr + column->bnd_size * stmt->fetch_pos;
    text_t fmt_text;
    text_t tmstamp_tz_text;
    timestamp_tz_t timestamp_tz;

    CT_RETURN_IFERR(chk_and_cp_null_str(stmt, column, bnd_ptr));

    clt_session_nlsparam_geter(stmt, NLS_TIMESTAMP_TZ_FORMAT, &fmt_text);
    CLT_CHECK_BIND_SIZE(column, fmt_text.len + 7);

    tmstamp_tz_text.str = bnd_ptr;
    tmstamp_tz_text.len = 0;

    timestamp_tz.tstamp = cs_reverse_int64(((timestamp_tz_t *)column->ptr)->tstamp);
    timestamp_tz.tz_offset = cs_reverse_int16(((timestamp_tz_t *)column->ptr)->tz_offset);

    CT_RETURN_IFERR(
        cm_timestamp_tz2text_ex(&timestamp_tz, &fmt_text, column->def.precision, &tmstamp_tz_text, column->bnd_size));

    if (column->ind_ptr) {
        column->ind_ptr[stmt->fetch_pos] = (uint16)tmstamp_tz_text.len;
    }

    return CT_SUCCESS;
}

static status_t copy_yminterval_val_2str(clt_stmt_t *stmt, clt_column_t *column)
{
    char *bnd_ptr = column->bnd_ptr + column->bnd_size * stmt->fetch_pos;

    CT_RETURN_IFERR(chk_and_cp_null_str(stmt, column, bnd_ptr));

    int32 int_value = *(int32 *)column->ptr;
    uint32 len = cm_yminterval2str((interval_ym_t)int_value, bnd_ptr);
    if (column->ind_ptr) {
        column->ind_ptr[stmt->fetch_pos] = (uint16)len;
    }

    return len == 0 ? CT_ERROR : CT_SUCCESS;
}

static status_t copy_yminterval_val_2str_reverse(clt_stmt_t *stmt, clt_column_t *column)
{
    char *bnd_ptr = column->bnd_ptr + column->bnd_size * stmt->fetch_pos;

    CT_RETURN_IFERR(chk_and_cp_null_str(stmt, column, bnd_ptr));

    int32 int_value = cs_reverse_int32(*(int32 *)column->ptr);
    uint32 len = cm_yminterval2str((interval_ym_t)int_value, bnd_ptr);
    if (column->ind_ptr) {
        column->ind_ptr[stmt->fetch_pos] = (uint16)len;
    }

    return len == 0 ? CT_ERROR : CT_SUCCESS;
}

static status_t copy_dsinterval_val_2str(clt_stmt_t *stmt, clt_column_t *column)
{
    char *bnd_ptr = column->bnd_ptr + column->bnd_size * stmt->fetch_pos;

    CT_RETURN_IFERR(chk_and_cp_null_str(stmt, column, bnd_ptr));

    int64 bigint_value = *(int64 *)column->ptr;
    uint32 len = cm_dsinterval2str((interval_ds_t)bigint_value, bnd_ptr, column->bnd_size);
    if (column->ind_ptr) {
        column->ind_ptr[stmt->fetch_pos] = (uint16)len;
    }

    return len == 0 ? CT_ERROR : CT_SUCCESS;
}

static status_t copy_dsinterval_val_2str_reverse(clt_stmt_t *stmt, clt_column_t *column)
{
    char *bnd_ptr = column->bnd_ptr + column->bnd_size * stmt->fetch_pos;

    CT_RETURN_IFERR(chk_and_cp_null_str(stmt, column, bnd_ptr));

    int64 bigint_value = cs_reverse_int64(*(int64 *)column->ptr);
    uint32 len = cm_dsinterval2str((interval_ds_t)bigint_value, bnd_ptr, column->bnd_size);
    if (column->ind_ptr) {
        column->ind_ptr[stmt->fetch_pos] = (uint16)len;
    }

    return len == 0 ? CT_ERROR : CT_SUCCESS;
}

static status_t copy_raw_val_2str(clt_stmt_t *stmt, clt_column_t *column)
{
    uint16 col_len = column->size;
    char *bnd_ptr = column->bnd_ptr + column->bnd_size * stmt->fetch_pos;
    binary_t bin_value;

    CT_RETURN_IFERR(chk_and_cp_null_str(stmt, column, bnd_ptr));

    bin_value.bytes = (uint8 *)column->ptr;
    bin_value.size = col_len;
    text_t tmp_text = {
        .str = bnd_ptr,
        .len = column->bnd_size
    };

    CT_RETURN_IFERR(cm_bin2text(&bin_value, CT_FALSE, &tmp_text));

    if (column->ind_ptr) {
        column->ind_ptr[stmt->fetch_pos] = (uint16)tmp_text.len;
    }

    return CT_SUCCESS;
}

static status_t copy_clob_val_2str(clt_stmt_t *stmt, clt_column_t *column)
{
    uint32 read_size;
    char *bnd_ptr = column->bnd_ptr + column->bnd_size * stmt->fetch_pos;

    CT_RETURN_IFERR(clt_clob_as_string(stmt, (void *)column->ptr, bnd_ptr, column->bnd_size, &read_size));

    if (column->ind_ptr) {
        column->ind_ptr[stmt->fetch_pos] = (uint16)read_size;
    }

    return CT_SUCCESS;
}

static status_t copy_blob_val_2str(clt_stmt_t *stmt, clt_column_t *column)
{
    uint32 read_size;
    char *bnd_ptr = column->bnd_ptr + column->bnd_size * stmt->fetch_pos;

    CT_RETURN_IFERR(clt_blob_as_string(stmt, (void *)column->ptr, bnd_ptr, column->bnd_size, &read_size));
    if (column->ind_ptr) {
        column->ind_ptr[stmt->fetch_pos] = (uint16)read_size;
    }

    return CT_SUCCESS;
}

static status_t copy_image_val_2str(clt_stmt_t *stmt, clt_column_t *column)
{
    uint32 read_size;
    char *bnd_ptr = column->bnd_ptr + column->bnd_size * stmt->fetch_pos;

    CT_RETURN_IFERR(clt_image_as_string(stmt, (void *)column->ptr, bnd_ptr, column->bnd_size, &read_size));

    if (column->ind_ptr) {
        column->ind_ptr[stmt->fetch_pos] = (uint16)read_size;
    }

    return CT_SUCCESS;
}

static status_t copy_binary_val_2str(clt_stmt_t *stmt, clt_column_t *column)
{
    uint16 col_len = column->size;
    char *bnd_ptr = column->bnd_ptr + column->bnd_size * stmt->fetch_pos;

    if (column->bnd_size <= col_len) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_COL_SIZE_TOO_SMALL, (uint32)column->id, "binding", (uint32)column->bnd_size,
            (uint32)(col_len + 1));

        if (column->bnd_size == 0) {
            return CT_ERROR;
        }
        col_len = column->bnd_size - 1;
    }

    if (col_len != 0) {
        MEMS_RETURN_IFERR(memcpy_s(bnd_ptr, col_len, column->ptr, col_len));
    }
    bnd_ptr[col_len] = '\0';

    if (column->ind_ptr) {
        column->ind_ptr[stmt->fetch_pos] = col_len;
    }

    return CT_SUCCESS;
}

static inline status_t copy_str_2int64(clt_column_t *column, char *col_data, char *bnd_ptr)
{
    text_t temp_str;
    double temp_real1, temp_real2;

    temp_str.str = col_data;
    temp_str.len = column->size;
    num_errno_t err_no = cm_text2real_ex(&temp_str, &temp_real1);
    CM_TRY_THROW_NUM_ERR(err_no);
    temp_real2 = cm_round_real(temp_real1, ROUND_HALF_UP);
    int64 temp_bigint = (int64)temp_real2;
    if (REAL2INT64_IS_OVERFLOW(temp_bigint, temp_real2)) {
        CT_THROW_ERROR(ERR_TYPE_OVERFLOW, "BIGINT");
        return CT_ERROR;
    }
    *(int64 *)bnd_ptr = temp_bigint;
    return CT_SUCCESS;
}

static status_t copy_val_2bigint(clt_stmt_t *stmt, clt_column_t *column)
{
    char *bnd_ptr = column->bnd_ptr + column->bnd_size * stmt->fetch_pos;
    dec2_t dec2;
    switch (column->def.datatype) {
        case GSC_TYPE_UINT32: {
            uint32 temp_int = *(uint32 *)column->ptr;
            *(int64 *)bnd_ptr = (int64)temp_int;
            break;
        }
        case GSC_TYPE_INTEGER:
        case GSC_TYPE_BOOLEAN: {
            int32 temp_int = *(int32 *)column->ptr;
            *(int64 *)bnd_ptr = (int64)temp_int;
            break;
        }
        case GSC_TYPE_REAL: {
            double temp_real1 = *(double *)column->ptr;
            double temp_real2 = cm_round_real(temp_real1, ROUND_HALF_UP);
            int64 temp_bigint = (int64)temp_real2;
            if (REAL2INT64_IS_OVERFLOW(temp_bigint, temp_real2)) {
                CT_THROW_ERROR(ERR_TYPE_OVERFLOW, "BIGINT");
                return CT_ERROR;
            }
            *(int64 *)bnd_ptr = temp_bigint;
            break;
        }
        case GSC_TYPE_NUMBER2:
            cm_dec2_copy_ex(&dec2, (const payload_t *)column->ptr, (uint8)column->size);
            CT_RETURN_IFERR(cm_dec2_to_int64(&dec2, (int64 *)bnd_ptr, ROUND_HALF_UP));
            break;
        case GSC_TYPE_NUMBER:
        case GSC_TYPE_DECIMAL: {
            CT_RETURN_IFERR(cm_dec4_to_int64((dec4_t *)column->ptr, (int64 *)bnd_ptr, ROUND_HALF_UP));
            break;
        }
        case GSC_TYPE_CHAR:
        case GSC_TYPE_VARCHAR:
        case GSC_TYPE_STRING:
        default:
            CT_RETURN_IFERR(copy_str_2int64(column, column->ptr, bnd_ptr));
    }

    if (column->ind_ptr) {
        column->ind_ptr[stmt->fetch_pos] = (uint16)sizeof(int64);
    }

    return CT_SUCCESS;
}

static status_t copy_val_2bigint_reverse(clt_stmt_t *stmt, clt_column_t *column)
{
    char *bnd_ptr = column->bnd_ptr + column->bnd_size * stmt->fetch_pos;

    switch (column->def.datatype) {
        case GSC_TYPE_UINT32: {
            uint32 temp_int = cs_reverse_uint32(*(uint32 *)column->ptr);
            *(int64 *)bnd_ptr = (int64)temp_int;
            break;
        }
        case GSC_TYPE_INTEGER:
        case GSC_TYPE_BOOLEAN: {
            int32 temp_int = cs_reverse_int32(*(int32 *)column->ptr);
            *(int64 *)bnd_ptr = (int64)temp_int;
            break;
        }
        case GSC_TYPE_REAL: {
            double temp_real1 = cs_reverse_real(*(double *)column->ptr);
            double temp_real2 = cm_round_real(temp_real1, ROUND_HALF_UP);
            int64 temp_bigint = (int64)temp_real2;
            if (REAL2INT64_IS_OVERFLOW(temp_bigint, temp_real2)) {
                CT_THROW_ERROR(ERR_TYPE_OVERFLOW, "BIGINT");
                return CT_ERROR;
            }
            *(int64 *)bnd_ptr = temp_bigint;
            break;
        }
        case GSC_TYPE_NUMBER2: {
            dec2_t dec2;
            cm_dec2_copy_ex(&dec2, (const payload_t *)column->ptr, (uint8)column->size);
            CT_RETURN_IFERR(cm_dec2_to_int64(&dec2, (int64 *)bnd_ptr, ROUND_HALF_UP));
            break;
        }
        case GSC_TYPE_NUMBER:
        case GSC_TYPE_DECIMAL: {
            dec4_t dec4;
            cm_reverse_dec4(&dec4, (dec4_t *)column->ptr);
            CT_RETURN_IFERR(cm_dec4_to_int64(&dec4, (int64 *)bnd_ptr, ROUND_HALF_UP));
            break;
        }
        case GSC_TYPE_CHAR:
        case GSC_TYPE_VARCHAR:
        case GSC_TYPE_STRING:
        default:
            CT_RETURN_IFERR(copy_str_2int64(column, column->ptr, bnd_ptr));
    }

    if (column->ind_ptr) {
        column->ind_ptr[stmt->fetch_pos] = (uint16)sizeof(int64);
    }

    return CT_SUCCESS;
}

static status_t copy_val_2double(clt_stmt_t *stmt, clt_column_t *column)
{
    char *bnd_ptr = column->bnd_ptr + column->bnd_size * stmt->fetch_pos;

    switch (column->def.datatype) {
        case GSC_TYPE_UINT32: {
            uint32 temp_int = *(uint32 *)column->ptr;
            *(double *)bnd_ptr = (double)temp_int;
            break;
        }
        case GSC_TYPE_INTEGER:
        case GSC_TYPE_BOOLEAN: {
            int32 temp_int = *(int32 *)column->ptr;
            *(double *)bnd_ptr = (double)temp_int;
            break;
        }
        case GSC_TYPE_BIGINT: {
            int64 temp_bigint = *(int64 *)column->ptr;
            *(double *)bnd_ptr = (double)temp_bigint;
            break;
        }
        case GSC_TYPE_NUMBER:
        case GSC_TYPE_DECIMAL: {
            *(double *)bnd_ptr = cm_dec4_to_real((dec4_t *)column->ptr);
            break;
        }
        case GSC_TYPE_NUMBER2: {
            dec2_t dec2;
            cm_dec2_copy_ex(&dec2, (const payload_t *)column->ptr, (uint8)column->size);
            *(double *)bnd_ptr = cm_dec2_to_real(&dec2);
            break;
        }
        case GSC_TYPE_CHAR:
        case GSC_TYPE_VARCHAR:
        case GSC_TYPE_STRING:
        default: {
            text_t temp_str;
            temp_str.str = column->ptr;
            temp_str.len = column->size;
            CT_RETURN_IFERR(cm_text2real(&temp_str, (double *)bnd_ptr));
        }
    }

    if (column->ind_ptr) {
        column->ind_ptr[stmt->fetch_pos] = (uint16)sizeof(double);
    }

    return CT_SUCCESS;
}

static status_t copy_val_2double_reverse(clt_stmt_t *stmt, clt_column_t *column)
{
    char *bnd_ptr = column->bnd_ptr + column->bnd_size * stmt->fetch_pos;

    switch (column->def.datatype) {
        case GSC_TYPE_UINT32: {
            uint32 temp_int = cs_reverse_uint32(*(uint32 *)column->ptr);
            *(double *)bnd_ptr = (double)temp_int;
            break;
        }
        case GSC_TYPE_INTEGER:
        case GSC_TYPE_BOOLEAN: {
            int32 temp_int = cs_reverse_int32(*(int32 *)column->ptr);
            *(double *)bnd_ptr = (double)temp_int;
            break;
        }
        case GSC_TYPE_BIGINT: {
            int64 temp_bigint = cs_reverse_int32(*(int32 *)column->ptr);
            *(double *)bnd_ptr = (double)temp_bigint;
            break;
        }
        case GSC_TYPE_NUMBER:
        case GSC_TYPE_DECIMAL: {
            dec4_t dec4;
            cm_reverse_dec4(&dec4, (dec4_t *)column->ptr);
            *(double *)bnd_ptr = cm_dec4_to_real(&dec4);
            break;
        }
        case GSC_TYPE_NUMBER2: {
            dec2_t dec2;
            cm_dec2_copy_ex(&dec2, (const payload_t *)column->ptr, (uint8)column->size);
            *(double *)bnd_ptr = cm_dec2_to_real(&dec2);
            break;
        }
        case GSC_TYPE_CHAR:
        case GSC_TYPE_VARCHAR:
        case GSC_TYPE_STRING:
        default: {
            text_t temp_str;
            temp_str.str = column->ptr;
            temp_str.len = column->size;
            CT_RETURN_IFERR(cm_text2real(&temp_str, (double *)bnd_ptr));
        }
    }

    if (column->ind_ptr) {
        column->ind_ptr[stmt->fetch_pos] = (uint16)sizeof(double);
    }

    return CT_SUCCESS;
}

static status_t copy_val_2number(clt_stmt_t *stmt, clt_column_t *column)
{
    char *bnd_ptr = column->bnd_ptr + column->bnd_size * stmt->fetch_pos;
    uint16 col_len = column->size;
    uint32 temp_uint32;
    int32 temp_int;
    int64 temp_bigint;
    double temp_real;
    text_t temp_str;

    switch (column->def.datatype) {
        case GSC_TYPE_UINT32:
            temp_uint32 = *(uint32 *)column->ptr;
            cm_uint32_to_dec4(temp_uint32, (dec4_t *)bnd_ptr);
            return CT_SUCCESS;
        case GSC_TYPE_INTEGER:
        case GSC_TYPE_BOOLEAN:
            temp_int = *(int32 *)column->ptr;
            cm_int32_to_dec4(temp_int, (dec4_t *)bnd_ptr);
            return CT_SUCCESS;

        case GSC_TYPE_BIGINT:
            temp_bigint = *(int64 *)column->ptr;
            cm_int64_to_dec4(temp_bigint, (dec4_t *)bnd_ptr);
            return CT_SUCCESS;

        case GSC_TYPE_REAL:
            temp_real = *(double *)column->ptr;
            return cm_real_to_dec4(temp_real, (dec4_t *)bnd_ptr);
        case GSC_TYPE_NUMBER2:
            if (col_len != 0) {
                dec4_t dec4;
                dec2_t dec2;
                cm_dec2_copy_ex(&dec2, (const payload_t *)column->ptr, (uint8)column->size);
                cm_dec_2_to_4(&dec2, &dec4);
                MEMS_RETURN_IFERR(memcpy_s(bnd_ptr, column->bnd_size, &dec4, cm_dec4_stor_sz(&dec4)));
            }
            return CT_SUCCESS;
        case GSC_TYPE_NUMBER:
        case GSC_TYPE_DECIMAL:
            if (col_len != 0) {
                MEMS_RETURN_IFERR(memcpy_s(bnd_ptr, column->size, column->ptr, col_len));
            }
            return CT_SUCCESS;

        case GSC_TYPE_CHAR:
        case GSC_TYPE_VARCHAR:
        case GSC_TYPE_STRING:
        default:
            temp_str.str = column->ptr;
            temp_str.len = column->size;
            return cm_text_to_dec4(&temp_str, (dec4_t *)bnd_ptr);
    }
}

static inline status_t copy_number2_2number_reverse(clt_column_t *column, uint16 col_len, char *bnd_ptr)
{
    if (col_len == 0) {
        return CT_SUCCESS;
    }

    dec4_t dec4;
    dec2_t dec2;
    cm_dec2_copy_ex(&dec2, (const payload_t *)column->ptr, (uint8)column->size);
    cm_dec_2_to_4(&dec2, &dec4);
    MEMS_RETURN_IFERR(memcpy_s(bnd_ptr, column->bnd_size, (const void *)&dec4, cm_dec4_stor_sz(&dec4)));
    return CT_SUCCESS;
}

static status_t copy_val_2number_reverse(clt_stmt_t *stmt, clt_column_t *column)
{
    char *bnd_ptr = column->bnd_ptr + column->bnd_size * stmt->fetch_pos;
    uint16 col_len = column->size;
    uint32 temp_uint32;
    int32 temp_int;
    int64 temp_bigint;
    double temp_real;
    text_t temp_str;

    switch (column->def.datatype) {
        case GSC_TYPE_UINT32:
            temp_uint32 = cs_reverse_uint32(*(uint32 *)column->ptr);
            cm_uint32_to_dec4(temp_uint32, (dec4_t *)bnd_ptr);
            return CT_SUCCESS;
        case GSC_TYPE_INTEGER:
        case GSC_TYPE_BOOLEAN:
            temp_int = cs_reverse_int32(*(int32 *)column->ptr);
            cm_int32_to_dec4(temp_int, (dec4_t *)bnd_ptr);
            return CT_SUCCESS;

        case GSC_TYPE_BIGINT:
            temp_bigint = cs_reverse_int64(*(int64 *)column->ptr);
            cm_int64_to_dec4(temp_bigint, (dec4_t *)bnd_ptr);
            return CT_SUCCESS;

        case GSC_TYPE_REAL:
            temp_real = cs_reverse_real(*(double *)column->ptr);
            return cm_real_to_dec4(temp_real, (dec4_t *)bnd_ptr);

        case GSC_TYPE_NUMBER2:
            return copy_number2_2number_reverse(column, col_len, bnd_ptr);

        case GSC_TYPE_NUMBER:
        case GSC_TYPE_DECIMAL:
            if (col_len != 0) {
                dec4_t dec4;
                cm_reverse_dec4(&dec4, (dec4_t *)column->ptr);
                MEMS_RETURN_IFERR(memcpy_s(bnd_ptr, column->size, (const void *)&dec4, cm_dec4_stor_sz(&dec4)));
            }
            return CT_SUCCESS;

        case GSC_TYPE_CHAR:
        case GSC_TYPE_VARCHAR:
        case GSC_TYPE_STRING:
        default:
            temp_str.str = column->ptr;
            temp_str.len = column->size;
            return cm_text_to_dec4(&temp_str, (dec4_t *)bnd_ptr);
    }
}

static inline status_t copy_number2_2number2_reverse(clt_stmt_t *stmt, clt_column_t *column, uint16 col_len,
    char *bnd_ptr)
{
    if (col_len == 0) {
        cm_zero_payload((uint8 *)(&column->ind_ptr[stmt->fetch_pos]), (payload_t *)bnd_ptr);
    } else {
        MEMS_RETURN_IFERR(memcpy_s(bnd_ptr, column->bnd_size, (const void *)column->ptr, col_len));
    }
    return CT_SUCCESS;
}

static status_t copy_val_2number2_reverse(clt_stmt_t *stmt, clt_column_t *column)
{
    char *bnd_ptr = column->bnd_ptr + column->bnd_size * stmt->fetch_pos;
    uint16 col_len = column->size;
    text_t txt;
    dec2_t dec2 = { 0 };
    dec4_t dec4;

    switch (column->def.datatype) {
        case GSC_TYPE_UINT32:
            cm_uint32_to_dec2(cs_reverse_uint32(*(uint32 *)column->ptr), &dec2);
            break;
        case GSC_TYPE_INTEGER:
        case GSC_TYPE_BOOLEAN:
            cm_int32_to_dec2(cs_reverse_int32(*(int32 *)column->ptr), &dec2);
            break;
        case GSC_TYPE_BIGINT:
            cm_int64_to_dec2(cs_reverse_int64(*(int64 *)column->ptr), &dec2);
            break;
        case GSC_TYPE_REAL:
            cm_real_to_dec2(cs_reverse_real(*(double *)column->ptr), &dec2);
            break;
        case GSC_TYPE_NUMBER2:
            return copy_number2_2number2_reverse(stmt, column, col_len, bnd_ptr);

        case GSC_TYPE_NUMBER:
        case GSC_TYPE_DECIMAL:
            if (col_len == 0) {
                cm_zero_payload((uint8 *)(&column->ind_ptr[stmt->fetch_pos]), (payload_t *)bnd_ptr);
                return CT_SUCCESS;
            }
            cm_reverse_dec4(&dec4, (dec4_t *)column->ptr);
            CT_RETURN_IFERR(cm_dec_4_to_2((const dec4_t *)&dec4, col_len, &dec2));
            break;

        case GSC_TYPE_CHAR:
        case GSC_TYPE_VARCHAR:
        case GSC_TYPE_STRING:
        default:
            txt.str = column->ptr;
            txt.len = column->size;
            CT_RETURN_IFERR(cm_text_to_dec2(&txt, &dec2));
            break;
    }
    MEMS_RETURN_IFERR(memcpy_s(bnd_ptr, column->bnd_size, GET_PAYLOAD(&dec2), cm_dec2_stor_sz(&dec2)));
    if (column->ind_ptr) {
        column->ind_ptr[stmt->fetch_pos] = cm_dec2_stor_sz(&dec2);
    }
    return CT_SUCCESS;
}

static status_t copy_val_2number2(clt_stmt_t *stmt, clt_column_t *column)
{
    char *bnd_ptr = column->bnd_ptr + column->bnd_size * stmt->fetch_pos;
    uint16 col_len = column->size;
    text_t txt;
    dec2_t dec2 = { 0 };
    switch (column->def.datatype) {
        case GSC_TYPE_UINT32:
            cm_uint32_to_dec2(*(uint32 *)column->ptr, &dec2);
            break;
        case GSC_TYPE_INTEGER:
        case GSC_TYPE_BOOLEAN:
            cm_int32_to_dec2(*(int32 *)column->ptr, &dec2);
            break;
        case GSC_TYPE_BIGINT:
            cm_int64_to_dec2(*(int64 *)column->ptr, &dec2);
            break;
        case GSC_TYPE_REAL:
            CT_RETURN_IFERR(cm_real_to_dec2(*(double *)column->ptr, &dec2));
            break;
        case GSC_TYPE_NUMBER2:
            if (col_len == 0) {
                cm_zero_payload((uint8 *)(&column->ind_ptr[stmt->fetch_pos]), (payload_t *)bnd_ptr);
            } else {
                MEMS_RETURN_IFERR(memcpy_s(bnd_ptr, column->bnd_size, column->ptr, col_len));
            }
            return CT_SUCCESS;
        case GSC_TYPE_NUMBER:
        case GSC_TYPE_DECIMAL:
            if (col_len == 0) {
                cm_zero_payload((uint8 *)(&column->ind_ptr[stmt->fetch_pos]), (payload_t *)bnd_ptr);
                return CT_SUCCESS;
            }
            cm_dec_4_to_2((dec4_t *)column->ptr, col_len, &dec2);
            break;

        case GSC_TYPE_CHAR:
        case GSC_TYPE_VARCHAR:
        case GSC_TYPE_STRING:
        default:
            txt.str = column->ptr;
            txt.len = column->size;
            cm_text_to_dec2(&txt, &dec2);
            break;
    }
    MEMS_RETURN_IFERR(memcpy_s(bnd_ptr, column->bnd_size, GET_PAYLOAD(&dec2), cm_dec2_stor_sz(&dec2)));
    if (column->ind_ptr) {
        column->ind_ptr[stmt->fetch_pos] = cm_dec2_stor_sz(&dec2);
    }
    return CT_SUCCESS;
}


static inline status_t copy_str_2int32(clt_column_t *column, char *col_data, char *bnd_ptr)
{
    text_t temp_str;
    double temp_real;
    temp_str.str = col_data;
    temp_str.len = column->size;
    num_errno_t err_no = cm_text2real_ex(&temp_str, &temp_real);
    CM_TRY_THROW_NUM_ERR(err_no);
    double temp_value = cm_round_real(temp_real, ROUND_HALF_UP);
    INT32_OVERFLOW_CHECK(temp_value);
    *(int32 *)bnd_ptr = (int32)temp_value;
    return CT_SUCCESS;
}

static status_t copy_val_2int32(clt_stmt_t *stmt, clt_column_t *column)
{
    char *bnd_ptr = column->bnd_ptr + column->bnd_size * stmt->fetch_pos;

    switch (column->def.datatype) {
        case GSC_TYPE_UINT32: {
            uint32 temp_uint32 = *(uint32 *)column->ptr;
            CT_RETURN_IFERR(var_to_int32_check_overflow(temp_uint32));
            *(int32 *)bnd_ptr = (int32)temp_uint32;
            break;
        }
        case GSC_TYPE_INTEGER:
        case GSC_TYPE_BOOLEAN:
            *(int32 *)bnd_ptr = *(int32 *)column->ptr;
            break;
        case GSC_TYPE_BIGINT: {
            int64 temp_bigint = *(int64 *)column->ptr;
            INT32_OVERFLOW_CHECK(temp_bigint);
            *(int32 *)bnd_ptr = (int32)temp_bigint;
            break;
        }
        case GSC_TYPE_REAL: {
            double temp_real = *(double *)column->ptr;
            INT32_OVERFLOW_CHECK(temp_real);
            *(int32 *)bnd_ptr = (int32)cm_round_real(temp_real, ROUND_HALF_UP);
            break;
        }
        case GSC_TYPE_NUMBER2: {
            dec2_t dec2;
            cm_dec2_copy_ex(&dec2, (const payload_t *)column->ptr, (uint8)column->size);
            CT_RETURN_IFERR(cm_dec2_to_int32(&dec2, (int32 *)bnd_ptr, ROUND_HALF_UP));
            break;
        }
        case GSC_TYPE_NUMBER:
        case GSC_TYPE_DECIMAL:
            CT_RETURN_IFERR(cm_dec4_to_int32((dec4_t *)column->ptr, (int32 *)bnd_ptr, ROUND_HALF_UP));
            break;

        case GSC_TYPE_CHAR:
        case GSC_TYPE_VARCHAR:
        case GSC_TYPE_STRING:
        default:
            CT_RETURN_IFERR(copy_str_2int32(column, column->ptr, bnd_ptr));
            break;
    }

    if (column->bnd_type == GSC_TYPE_BOOLEAN) {
        *(int32 *)bnd_ptr = (*(int32 *)bnd_ptr != 0);
    }

    if (column->ind_ptr) {
        column->ind_ptr[stmt->fetch_pos] = (uint16)sizeof(int32);
    }

    return CT_SUCCESS;
}

static status_t copy_val_2int32_reverse(clt_stmt_t *stmt, clt_column_t *column)
{
    char *bnd_ptr = column->bnd_ptr + column->bnd_size * stmt->fetch_pos;
    uint32 temp_uint32;
    int64 temp_bigint;
    double temp_real;
    dec4_t dec4;
    switch (column->def.datatype) {
        case GSC_TYPE_UINT32:
            temp_uint32 = cs_reverse_uint32(*(uint32 *)column->ptr);
            CT_RETURN_IFERR(var_to_int32_check_overflow(temp_uint32));
            *(int32 *)bnd_ptr = (int32)temp_uint32;
            break;
        case GSC_TYPE_INTEGER:
        case GSC_TYPE_BOOLEAN:
            *(int32 *)bnd_ptr = cs_reverse_int32(*(int32 *)column->ptr);
            break;
        case GSC_TYPE_BIGINT:
            temp_bigint = cs_reverse_int64(*(int64 *)column->ptr);
            INT32_OVERFLOW_CHECK(temp_bigint);
            *(int32 *)bnd_ptr = (int32)temp_bigint;
            break;
        case GSC_TYPE_REAL:
            temp_real = cs_reverse_real(*(double *)column->ptr);
            INT32_OVERFLOW_CHECK(temp_real);
            *(int32 *)bnd_ptr = (int32)cm_round_real(temp_real, ROUND_HALF_UP);
            break;
        case GSC_TYPE_NUMBER2: {
            dec2_t dec2;
            cm_dec2_copy_ex(&dec2, (const payload_t *)column->ptr, (uint8)column->size);
            CT_RETURN_IFERR(cm_dec2_to_int32(&dec2, (int32 *)bnd_ptr, ROUND_HALF_UP));
            break;
        }
        case GSC_TYPE_NUMBER:
        case GSC_TYPE_DECIMAL:
            cm_reverse_dec4(&dec4, (dec4_t *)column->ptr);
            CT_RETURN_IFERR(cm_dec4_to_int32(&dec4, (int32 *)bnd_ptr, ROUND_HALF_UP));
            break;
        case GSC_TYPE_CHAR:
        case GSC_TYPE_VARCHAR:
        case GSC_TYPE_STRING:
        default:
            CT_RETURN_IFERR(copy_str_2int32(column, column->ptr, bnd_ptr));
            break;
    }

    if (column->bnd_type == GSC_TYPE_BOOLEAN) {
        *(int32 *)bnd_ptr = (*(int32 *)bnd_ptr != 0);
    }

    if (column->ind_ptr) {
        column->ind_ptr[stmt->fetch_pos] = (uint16)sizeof(int32);
    }

    return CT_SUCCESS;
}

static inline status_t copy_str_2uint32(clt_column_t *column, char *col_data, char *bnd_ptr)
{
    text_t temp_str;
    double temp_real;
    temp_str.str = col_data;
    temp_str.len = column->size;
    num_errno_t err_no = cm_text2real_ex(&temp_str, &temp_real);
    CM_TRY_THROW_NUM_ERR(err_no);
    double temp_value = cm_round_real(temp_real, ROUND_HALF_UP);
    TO_UINT32_OVERFLOW_CHECK(temp_value, double);
    *(uint32 *)bnd_ptr = (uint32)temp_value;
    return CT_SUCCESS;
}

static inline status_t copy_number2_2uint32(clt_column_t *column, char *bnd_ptr)
{
    dec2_t dec2;
    cm_dec2_copy_ex(&dec2, (const payload_t *)column->ptr, (uint8)column->size);
    return cm_dec2_to_uint32(&dec2, (uint32 *)bnd_ptr, ROUND_HALF_UP);
}

static status_t copy_val_2uint32(clt_stmt_t *stmt, clt_column_t *column)
{
    char *bnd_ptr = column->bnd_ptr + column->bnd_size * stmt->fetch_pos;
    int32 temp_int32;
    int64 temp_bigint;
    double temp_real;

    switch (column->def.datatype) {
        case GSC_TYPE_UINT32:
            *(uint32 *)bnd_ptr = *(uint32 *)column->ptr;
            break;
        case GSC_TYPE_INTEGER:
        case GSC_TYPE_BOOLEAN:
            temp_int32 = *(int32 *)column->ptr;
            TO_UINT32_OVERFLOW_CHECK(temp_int32, int64);
            *(uint32 *)bnd_ptr = (uint32)temp_int32;
            break;
        case GSC_TYPE_BIGINT:
            temp_bigint = *(int64 *)column->ptr;
            TO_UINT32_OVERFLOW_CHECK(temp_bigint, int64);
            *(uint32 *)bnd_ptr = (uint32)temp_bigint;
            break;
        case GSC_TYPE_REAL:
            temp_real = *(double *)column->ptr;
            TO_UINT32_OVERFLOW_CHECK(temp_real, double);
            *(uint32 *)bnd_ptr = (uint32)(int32)cm_round_real(temp_real, ROUND_HALF_UP);
            break;
        case GSC_TYPE_NUMBER2:
            CT_RETURN_IFERR(copy_number2_2uint32(column, bnd_ptr));
            break;
        case GSC_TYPE_NUMBER:
        case GSC_TYPE_DECIMAL: {
            CT_RETURN_IFERR(cm_dec4_to_uint32((dec4_t *)column->ptr, (uint32 *)bnd_ptr, ROUND_HALF_UP));
            break;
        }
        case GSC_TYPE_CHAR:
        case GSC_TYPE_VARCHAR:
        case GSC_TYPE_STRING:
        default:
            CT_RETURN_IFERR(copy_str_2uint32(column, column->ptr, bnd_ptr));
            break;
    }

    if (column->bnd_type == GSC_TYPE_BOOLEAN) {
        *(uint32 *)bnd_ptr = (*(uint32 *)bnd_ptr != 0);
    }

    if (column->ind_ptr) {
        column->ind_ptr[stmt->fetch_pos] = (uint16)sizeof(uint32);
    }
    return CT_SUCCESS;
}

static status_t copy_val_2uint32_reverse(clt_stmt_t *stmt, clt_column_t *column)
{
    char *bnd_ptr = column->bnd_ptr + column->bnd_size * stmt->fetch_pos;
    int32 temp_int32;
    int64 temp_bigint;
    double temp_real;
    dec4_t dec4;
    switch (column->def.datatype) {
        case GSC_TYPE_UINT32:
            *(uint32 *)bnd_ptr = cs_reverse_uint32(*(uint32 *)column->ptr);
            break;
        case GSC_TYPE_INTEGER:
        case GSC_TYPE_BOOLEAN:
            temp_int32 = cs_reverse_int32(*(int32 *)column->ptr);
            TO_UINT32_OVERFLOW_CHECK(temp_int32, int64);
            *(uint32 *)bnd_ptr = (uint32)temp_int32;
            break;
        case GSC_TYPE_BIGINT:
            temp_bigint = cs_reverse_int64(*(int64 *)column->ptr);
            TO_UINT32_OVERFLOW_CHECK(temp_bigint, int64);
            *(uint32 *)bnd_ptr = (uint32)temp_bigint;
            break;
        case GSC_TYPE_REAL:
            temp_real = cs_reverse_real(*(double *)column->ptr);
            TO_UINT32_OVERFLOW_CHECK(temp_real, double);
            *(uint32 *)bnd_ptr = (uint32)(int32)cm_round_real(temp_real, ROUND_HALF_UP);
            break;
        case GSC_TYPE_NUMBER:
        case GSC_TYPE_DECIMAL:
            cm_reverse_dec4(&dec4, (dec4_t *)column->ptr);
            CT_RETURN_IFERR(cm_dec4_to_uint32(&dec4, (uint32 *)bnd_ptr, ROUND_HALF_UP));
            break;
        case GSC_TYPE_NUMBER2:
            CT_RETURN_IFERR(copy_number2_2uint32(column, bnd_ptr));
            break;

        case GSC_TYPE_CHAR:
        case GSC_TYPE_VARCHAR:
        case GSC_TYPE_STRING:
        default:
            CT_RETURN_IFERR(copy_str_2uint32(column, column->ptr, bnd_ptr));
            break;
    }

    if (column->bnd_type == GSC_TYPE_BOOLEAN) {
        *(uint32 *)bnd_ptr = (*(uint32 *)bnd_ptr != 0);
    }

    if (column->ind_ptr) {
        column->ind_ptr[stmt->fetch_pos] = (uint16)sizeof(uint32);
    }
    return CT_SUCCESS;
}

static status_t copy_date_val_2date(clt_stmt_t *stmt, clt_column_t *column)
{
    char *bnd_ptr = column->bnd_ptr + column->bnd_size * stmt->fetch_pos;
    clt_decode_date(*(int64 *)column->ptr, (uint8 *)bnd_ptr);
    if (column->ind_ptr) {
        column->ind_ptr[stmt->fetch_pos] = CLT_DATE_BINARY_SIZE;
    }
    return CT_SUCCESS;
}

static status_t copy_date_val_2date_reverse(clt_stmt_t *stmt, clt_column_t *column)
{
    char *bnd_ptr = column->bnd_ptr + column->bnd_size * stmt->fetch_pos;
    date_t date;

    date = cs_reverse_int64(*(int64 *)column->ptr);
    clt_decode_date(date, (uint8 *)bnd_ptr);
    if (column->ind_ptr) {
        column->ind_ptr[stmt->fetch_pos] = CLT_DATE_BINARY_SIZE;
    }
    return CT_SUCCESS;
}

static status_t copy_other_val_2date(clt_stmt_t *stmt, clt_column_t *column)
{
    char *bnd_ptr = column->bnd_ptr + column->bnd_size * stmt->fetch_pos;
    text_t temp_date;
    text_t fmt_text;
    date_t date;

    temp_date.str = column->ptr;
    temp_date.len = column->size;
    clt_session_nlsparam_geter(stmt, NLS_DATE_FORMAT, &fmt_text);
    CT_RETURN_IFERR(cm_text2date(&temp_date, NULL, &date));
    clt_decode_date(date, (uint8 *)bnd_ptr);
    if (column->ind_ptr) {
        column->ind_ptr[stmt->fetch_pos] = CLT_DATE_BINARY_SIZE;
    }
    return CT_SUCCESS;
}

static status_t copy_date_val_2timestamp(clt_stmt_t *stmt, clt_column_t *column)
{
    char *bnd_ptr = column->bnd_ptr + column->bnd_size * stmt->fetch_pos;
    *(int64 *)bnd_ptr = *(int64 *)column->ptr;
    if (column->ind_ptr) {
        column->ind_ptr[stmt->fetch_pos] = (uint16)sizeof(int64);
    }
    return CT_SUCCESS;
}

static status_t copy_date_val_2timestamp_reverse(clt_stmt_t *stmt, clt_column_t *column)
{
    char *bnd_ptr = column->bnd_ptr + column->bnd_size * stmt->fetch_pos;
    *(int64 *)bnd_ptr = cs_reverse_int64(*(int64 *)column->ptr);
    if (column->ind_ptr) {
        column->ind_ptr[stmt->fetch_pos] = (uint16)sizeof(int64);
    }
    return CT_SUCCESS;
}

static status_t copy_other_val_2timestamp(clt_stmt_t *stmt, clt_column_t *column)
{
    char *bnd_ptr = column->bnd_ptr + column->bnd_size * stmt->fetch_pos;
    text_t temp_date;
    text_t fmt_text;

    temp_date.str = column->ptr;
    temp_date.len = column->size;
    clt_session_nlsparam_geter(stmt, NLS_TIMESTAMP_FORMAT, &fmt_text);
    CT_RETURN_IFERR(cm_text2date(&temp_date, &fmt_text, (int64 *)bnd_ptr));
    if (column->ind_ptr) {
        column->ind_ptr[stmt->fetch_pos] = (uint16)sizeof(int64);
    }
    return CT_SUCCESS;
}

static status_t init_cp_func_no_mapping(clt_stmt_t *stmt, clt_column_t *column)
{
    switch (column->def.datatype) {
        case GSC_TYPE_UINT32:
            CLT_CHECK_BIND_SIZE(column, sizeof(uint32));
            column->cp_func =
                CS_DIFFERENT_ENDIAN(stmt->cache_pack->pack.options) ? copy_uint32_val_reverse : copy_uint32_val;
            return CT_SUCCESS;
        case GSC_TYPE_INTEGER:
        case GSC_TYPE_BOOLEAN:
            CLT_CHECK_BIND_SIZE(column, sizeof(int32));
            column->cp_func =
                CS_DIFFERENT_ENDIAN(stmt->cache_pack->pack.options) ? copy_int32_val_reverse : copy_int32_val;
            return CT_SUCCESS;
        case GSC_TYPE_BIGINT:
        case GSC_TYPE_TIMESTAMP:
        case GSC_TYPE_TIMESTAMP_TZ_FAKE:
        case GSC_TYPE_TIMESTAMP_LTZ:
            CLT_CHECK_BIND_SIZE(column, sizeof(int64));
            column->cp_func =
                CS_DIFFERENT_ENDIAN(stmt->cache_pack->pack.options) ? copy_int64_val_reverse : copy_int64_val;
            return CT_SUCCESS;
        case GSC_TYPE_TIMESTAMP_TZ:
            CLT_CHECK_BIND_SIZE(column, sizeof(timestamp_tz_t));
            column->cp_func = CS_DIFFERENT_ENDIAN(stmt->cache_pack->pack.options) ? copy_timestamp_tz_val_reverse :
                                                                                    copy_timestamp_tz_val;
            return CT_SUCCESS;
        case GSC_TYPE_REAL:
            CLT_CHECK_BIND_SIZE(column, sizeof(double));
            column->cp_func =
                CS_DIFFERENT_ENDIAN(stmt->cache_pack->pack.options) ? copy_double_val_reverse : copy_double_val;
            return CT_SUCCESS;

        case GSC_TYPE_INTERVAL_YM:
        case GSC_TYPE_INTERVAL_DS:
            CLT_CHECK_BIND_SIZE(column, column->def.size);
            column->cp_func = copy_str_val;
            return CT_SUCCESS;
        case GSC_TYPE_NUMBER:
        case GSC_TYPE_DECIMAL:
            CLT_CHECK_BIND_SIZE(column, column->def.size);
            column->cp_func =
                CS_DIFFERENT_ENDIAN(stmt->cache_pack->pack.options) ? copy_digit_val_reverse : copy_digit_val;
            return CT_SUCCESS;
        case GSC_TYPE_NUMBER2:
            CLT_CHECK_BIND_SIZE(column, column->def.size);
            column->cp_func =
                CS_DIFFERENT_ENDIAN(stmt->cache_pack->pack.options) ? copy_digit2_val_reverse : copy_digit_val;
            return CT_SUCCESS;
        case GSC_TYPE_DATE:
            CLT_CHECK_BIND_SIZE(column, CLT_DATE_BINARY_SIZE);
            column->cp_func =
                CS_DIFFERENT_ENDIAN(stmt->cache_pack->pack.options) ? copy_date_val_2date_reverse : copy_date_val_2date;
            return CT_SUCCESS;
        case GSC_TYPE_CLOB:
        case GSC_TYPE_BLOB:
        case GSC_TYPE_IMAGE:
            CLT_CHECK_BIND_SIZE(column, stmt->conn->server_info.locator_size);
            column->cp_func = copy_lob_val;
            return CT_SUCCESS;
        default:
            column->cp_func = copy_default_type_val;
            return CT_SUCCESS;
    }
}

static status_t init_cp_func_2str(clt_stmt_t *stmt, clt_column_t *column, bool32 to_hex)
{
    switch (column->def.datatype) {
        case GSC_TYPE_UINT32:
            column->cp_func = CS_DIFFERENT_ENDIAN(stmt->cache_pack->pack.options) ? copy_uint32_val_2str_reverse :
                                                                                    copy_uint32_val_2str;
            return CT_SUCCESS;
        case GSC_TYPE_INTEGER:
            column->cp_func =
                CS_DIFFERENT_ENDIAN(stmt->cache_pack->pack.options) ? copy_int32_val_2str_reverse : copy_int32_val_2str;
            return CT_SUCCESS;
        case GSC_TYPE_BIGINT:
            column->cp_func =
                CS_DIFFERENT_ENDIAN(stmt->cache_pack->pack.options) ? copy_int64_val_2str_reverse : copy_int64_val_2str;
            return CT_SUCCESS;
        case GSC_TYPE_REAL:
            column->cp_func = CS_DIFFERENT_ENDIAN(stmt->cache_pack->pack.options) ? copy_double_val_2str_reverse :
                                                                                    copy_double_val_2str;
            return CT_SUCCESS;
        case GSC_TYPE_NUMBER:
        case GSC_TYPE_DECIMAL:
            column->cp_func = CS_DIFFERENT_ENDIAN(stmt->cache_pack->pack.options) ? copy_number_val_2str_reverse :
                                                                                    copy_number_val_2str;
            return CT_SUCCESS;
        case GSC_TYPE_NUMBER2:
            // no need to byte order conversion
            column->cp_func = copy_number2_val_2str;
            return CT_SUCCESS;
        case GSC_TYPE_BOOLEAN:
            CLT_CHECK_BIND_SIZE(column, GSC_BOOL_BOUND_SIZE);
            column->cp_func = CS_DIFFERENT_ENDIAN(stmt->cache_pack->pack.options) ? copy_boolean_val_2str_reverse :
                                                                                    copy_boolean_val_2str;
            return CT_SUCCESS;
        case GSC_TYPE_DATE:
            CLT_CHECK_BIND_SIZE(column, GSC_TIME_BOUND_SIZE);
            column->cp_func =
                CS_DIFFERENT_ENDIAN(stmt->cache_pack->pack.options) ? copy_date_val_2str_reverse : copy_date_val_2str;
            return CT_SUCCESS;
        case GSC_TYPE_TIMESTAMP:
        case GSC_TYPE_TIMESTAMP_TZ_FAKE:
        case GSC_TYPE_TIMESTAMP_LTZ:
            CLT_CHECK_BIND_SIZE(column, GSC_TIME_BOUND_SIZE);
            column->cp_func = CS_DIFFERENT_ENDIAN(stmt->cache_pack->pack.options) ? copy_timestamp_val_2str_reverse :
                                                                                    copy_timestamp_val_2str;
            return CT_SUCCESS;

        case GSC_TYPE_TIMESTAMP_TZ:
            CLT_CHECK_BIND_SIZE(column, GSC_TIME_BOUND_SIZE);
            column->cp_func = CS_DIFFERENT_ENDIAN(stmt->cache_pack->pack.options) ? copy_timestamp_tz_val_2str_reverse :
                                                                                    copy_timestamp_tz_val_2str;
            return CT_SUCCESS;

        case GSC_TYPE_INTERVAL_YM:
            CLT_CHECK_BIND_SIZE(column, GSC_YM_INTERVAL_BOUND_SIZE);
            column->cp_func = CS_DIFFERENT_ENDIAN(stmt->cache_pack->pack.options) ? copy_yminterval_val_2str_reverse :
                                                                                    copy_yminterval_val_2str;
            return CT_SUCCESS;
        case GSC_TYPE_INTERVAL_DS:
            CLT_CHECK_BIND_SIZE(column, GSC_DS_INTERVAL_BOUND_SIZE);
            column->cp_func = CS_DIFFERENT_ENDIAN(stmt->cache_pack->pack.options) ? copy_dsinterval_val_2str_reverse :
                                                                                    copy_dsinterval_val_2str;
            return CT_SUCCESS;
        case GSC_TYPE_RAW:
            CLT_CHECK_BIND_SIZE(column, column->def.size + 1);
            column->cp_func = copy_raw_val_2str;
            return CT_SUCCESS;
        case GSC_TYPE_CLOB:
            column->cp_func = copy_clob_val_2str;
            return CT_SUCCESS;
        case GSC_TYPE_BLOB:
            column->cp_func = to_hex ? copy_blob_val_2str : copy_image_val_2str;
            return CT_SUCCESS;
        case GSC_TYPE_IMAGE:
            column->cp_func = copy_image_val_2str;
            return CT_SUCCESS;
        case GSC_TYPE_BINARY:
        case GSC_TYPE_VARBINARY:
        default:
            column->cp_func = copy_binary_val_2str;
            return CT_SUCCESS;
    }
}

static status_t init_cp_func_2digit(clt_stmt_t *stmt, clt_column_t *column)
{
    switch (column->bnd_type) {
        case GSC_TYPE_UINT32:
            CLT_CHECK_BIND_SIZE(column, sizeof(uint32));
            column->cp_func =
                CS_DIFFERENT_ENDIAN(stmt->cache_pack->pack.options) ? copy_val_2uint32_reverse : copy_val_2uint32;
            return CT_SUCCESS;
        case GSC_TYPE_INTEGER:
        case GSC_TYPE_BOOLEAN:
            CLT_CHECK_BIND_SIZE(column, sizeof(int32));
            column->cp_func =
                CS_DIFFERENT_ENDIAN(stmt->cache_pack->pack.options) ? copy_val_2int32_reverse : copy_val_2int32;
            return CT_SUCCESS;
        case GSC_TYPE_BIGINT:
            CLT_CHECK_BIND_SIZE(column, sizeof(int64));
            column->cp_func =
                CS_DIFFERENT_ENDIAN(stmt->cache_pack->pack.options) ? copy_val_2bigint_reverse : copy_val_2bigint;
            return CT_SUCCESS;
        case GSC_TYPE_REAL:
            CLT_CHECK_BIND_SIZE(column, sizeof(double));
            column->cp_func =
                CS_DIFFERENT_ENDIAN(stmt->cache_pack->pack.options) ? copy_val_2double_reverse : copy_val_2double;
            return CT_SUCCESS;
        case GSC_TYPE_NUMBER2:
            CLT_CHECK_BIND_SIZE(column, column->def.size);
            column->cp_func =
                CS_DIFFERENT_ENDIAN(stmt->cache_pack->pack.options) ? copy_val_2number2_reverse : copy_val_2number2;
            return CT_SUCCESS;
        case GSC_TYPE_NUMBER:
        case GSC_TYPE_DECIMAL:
        default:
            CLT_CHECK_BIND_SIZE(column, column->def.size);
            column->cp_func =
                CS_DIFFERENT_ENDIAN(stmt->cache_pack->pack.options) ? copy_val_2number_reverse : copy_val_2number;
            return CT_SUCCESS;
    }
}

static status_t init_cp_func_2date(clt_stmt_t *stmt, clt_column_t *column)
{
    CLT_CHECK_BIND_SIZE(column, CLT_DATE_BINARY_SIZE);

    switch (column->def.datatype) {
        case GSC_TYPE_DATE:
        case GSC_TYPE_TIMESTAMP:
            column->cp_func =
                CS_DIFFERENT_ENDIAN(stmt->cache_pack->pack.options) ? copy_date_val_2date_reverse : copy_date_val_2date;
            return CT_SUCCESS;
        case GSC_TYPE_CHAR:
        case GSC_TYPE_VARCHAR:
        case GSC_TYPE_STRING:
            column->cp_func = copy_other_val_2date;
            return CT_SUCCESS;
        default:
            CLT_THROW_ERROR(stmt->conn, ERR_CLT_INVALID_BIND, "bind type do not match with column type");
            return CT_ERROR;
    }
}

static status_t init_cp_func_2timestamp(clt_stmt_t *stmt, clt_column_t *column)
{
    CLT_CHECK_BIND_SIZE(column, sizeof(int64));

    switch (column->def.datatype) {
        case GSC_TYPE_DATE:
        case GSC_TYPE_TIMESTAMP:
            column->cp_func = CS_DIFFERENT_ENDIAN(stmt->cache_pack->pack.options) ? copy_date_val_2timestamp_reverse :
                                                                                    copy_date_val_2timestamp;
            return CT_SUCCESS;
        case GSC_TYPE_CHAR:
        case GSC_TYPE_VARCHAR:
        case GSC_TYPE_STRING:
            column->cp_func = copy_other_val_2timestamp;
            return CT_SUCCESS;
        default:
            CLT_THROW_ERROR(stmt->conn, ERR_CLT_INVALID_BIND, "bind type do not match with column type");
            return CT_ERROR;
    }
}

static status_t init_cp_func(clt_stmt_t *stmt, clt_column_t *column)
{
    if (column->bnd_type == column->def.datatype) {
        return init_cp_func_no_mapping(stmt, column);
    } else if (GSC_IS_STRING_TYPE(column->bnd_type)) {
        return init_cp_func_2str(stmt, column, CT_TRUE);
    } else if (GSC_IS_BINARY_TYPE(column->bnd_type)) {
        return init_cp_func_2str(stmt, column, CT_FALSE);
    } else if (GSC_IS_NUMBER_TYPE(column->bnd_type)) {
        return init_cp_func_2digit(stmt, column);
    } else if (column->bnd_type == GSC_TYPE_DATE) {
        return init_cp_func_2date(stmt, column);
    } else if (column->bnd_type == GSC_TYPE_TIMESTAMP || column->bnd_type == GSC_TYPE_TIMESTAMP_TZ_FAKE) {
        return init_cp_func_2timestamp(stmt, column);
    }

    CLT_THROW_ERROR(stmt->conn, ERR_CLT_INVALID_BIND, "bind type do not match with column type");
    return CT_ERROR;
}

static inline status_t init_cp_func_of_cols(clt_stmt_t *stmt)
{
    list_t *columns = &stmt->columns;

    for (uint32 i = 0; i < stmt->column_count; ++i) {
        clt_column_t *column = (clt_column_t *)cm_list_get(columns, i);
        CT_RETURN_IFERR(init_cp_func(stmt, column));
    }
    return CT_SUCCESS;
}

int32 clt_fetch(clt_stmt_t *stmt, uint32 *rows, bool32 fetch_ori_row)
{
    GSC_CHECK_FETCH_STATUS(stmt);

    if (SECUREC_UNLIKELY(stmt->status < CLI_STMT_EXECUTED)) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_OUT_OF_API_SEQUENCE, "statement is not executed");
        return CT_ERROR;
    }

    stmt->status = CLI_STMT_FETCHING;
    stmt->fetched_times++;

    /* fetch over */
    if (stmt->eof) {
        *rows = 0;
        return CT_SUCCESS;
    }

    if (stmt->fetched_rows == 0 && init_cp_func_of_cols(stmt) != CT_SUCCESS) {
        return CT_ERROR;
    }

    for (stmt->fetch_pos = 0; stmt->fetch_pos < stmt->fetch_size; ++stmt->fetch_pos) {
        /* try do remote fetch if fetch over from the last package */
        if (stmt->row_index == stmt->return_rows) {
            if (!stmt->more_rows) {
                stmt->eof = CT_TRUE;
                break;
            }

            CT_RETURN_IFERR(clt_remote_fetch(stmt));

            if (stmt->eof) {
                break;
            }
            stmt->row_index = 0;
        }

        /* read row fetched */
        CT_RETURN_IFERR(clt_read_row(stmt, fetch_ori_row));

        stmt->row_index++;
        stmt->fetched_rows++;
    }

    if (SECUREC_LIKELY(rows != NULL)) {
        *rows = stmt->fetch_pos;
    }
    return CT_SUCCESS;
}

#ifdef __cplusplus
}
#endif
