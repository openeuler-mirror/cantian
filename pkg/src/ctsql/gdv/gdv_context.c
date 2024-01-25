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
 * gdv_context.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/gdv/gdv_context.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_log.h"
#include "cs_packet.h"
#include "ctsql_stmt.h"
#include "cms_interface.h"
#include "gdv_context.h"


/* send flow
    gdv_send_fetch_begin
        gdv_init_sender_row
        gdv_send_row_begin
        gdv_send_row_end
    gdv_send_fetch_end
*/


void gdv_init_sender(session_t *session) {}


status_t gdv_send_result_success(session_t *session)
{
    return CT_SUCCESS;
}

status_t gdv_send_result_error(session_t *session)
{
    return CT_SUCCESS;
}


status_t gdv_send_exec_begin(sql_stmt_t *stmt)
{
    return CT_SUCCESS;
}


void gdv_send_exec_end(sql_stmt_t *stmt) {}


status_t gdv_send_fetch_begin(sql_stmt_t *stmt)
{
    return cs_reserve_space(stmt->session->send_pack, sizeof(cs_fetch_ack_t), &stmt->fetch_ack_offset);
}

void gdv_send_fetch_end(sql_stmt_t *stmt)
{
    cs_fetch_ack_t *fetch_ack = (cs_fetch_ack_t *)CS_RESERVE_ADDR(stmt->session->send_pack, stmt->fetch_ack_offset);
    fetch_ack->total_rows = stmt->total_rows;
    fetch_ack->batch_rows = stmt->batch_rows;
    fetch_ack->rows_more = !stmt->eof;
}


void gdv_init_sender_row(sql_stmt_t *stmt, char *buffer, uint32 size, uint32 column_count)
{
    // row_init(&stmt->ra, buffer, size, column_count);
}

status_t gdv_send_row_begin(sql_stmt_t *stmt, uint32 column_count)
{
    char *buf = NULL;
    CM_CHECK_SEND_PACK_FREE(stmt->session->send_pack, CT_MAX_ROW_SIZE);

    buf = CS_WRITE_ADDR(stmt->session->send_pack);
    row_init(&stmt->ra, buf, CT_MAX_ROW_SIZE, column_count);
    return CT_SUCCESS;
}

status_t gdv_send_row_end(sql_stmt_t *stmt, bool32 *is_full)
{
    cs_packet_t *send_pack = stmt->session->send_pack;
    CT_RETURN_IFERR(cs_reserve_space(send_pack, stmt->ra.head->size, NULL));
    *is_full = sql_send_check_is_full(stmt);
    stmt->session->stat.fetched_rows++;
    return CT_SUCCESS;
}

status_t gdv_send_row_entire(sql_stmt_t *stmt, char *row)
{
    return CT_SUCCESS;
}

void gdv_send_parsed_stmt_debug(sql_stmt_t *stmt, cs_prepare_ack_t *ack)
{
    CT_LOG_DEBUG_INF("ack info: stmt_id = %d, stmt_type = %d, column_count = %d, para_count = %d ", ack->stmt_id,
        ack->stmt_type, ack->column_count, ack->param_count);
    uint32 column_def_offset = 0;
    char *name_ptr = NULL;
    cs_packet_t *send_pack = stmt->session->send_pack;
    cs_column_def_t *def = NULL;
    char name[CT_MAX_NAME_LEN + 1];

    for (int i = 0; i < ack->column_count; i++) {
        def = (cs_column_def_t *)(send_pack->buf + column_def_offset);
        name_ptr = (char *)def + CM_ALIGN4(sizeof(cs_column_def_t));
        errno_t errcode = memcpy_s(name, CT_MAX_NAME_LEN, name_ptr, def->name_len);
        MEMS_RETVOID_IFERR(errcode);
        name[def->name_len] = '\0';

        CT_LOG_DEBUG_INF("Column NO.= %d: name_len = %d, name = %s", i, def->name_len, name);
        column_def_offset += CM_ALIGN4(sizeof(cs_column_def_t)) + CM_ALIGN4(def->name_len);
    }
}


status_t gdv_send_parsed_stmt(sql_stmt_t *stmt)
{
    cs_prepare_ack_t *ack = NULL;
    cs_packet_t *send_pack = stmt->session->send_pack;
    uint32 ack_offset;

    // reserve space for cs_prepare_ack_t
    CT_RETURN_IFERR(cs_reserve_space(send_pack, sizeof(cs_prepare_ack_t), &ack_offset));
    ack = (cs_prepare_ack_t *)CS_RESERVE_ADDR(send_pack, ack_offset);
    ack->stmt_id = stmt->id;
    if (stmt->context == NULL) {
        CT_THROW_ERROR(ERR_INVALID_CURSOR);
        return CT_ERROR;
    }
    ack->stmt_type = ACK_STMT_TYPE(stmt->lang_type, stmt->context->type);
    CT_RETURN_IFERR(sql_send_parsed_stmt_normal(stmt, ack->column_count));
    gdv_send_parsed_stmt_debug(stmt, ack);

    return CT_SUCCESS;
}

bool32 gdv_is_active_db(knl_handle_t se, uint32 inst_id)
{
    session_t *session = (session_t *)se;
    cms_res_status_list_t *res_status = &session->res_status;

    int i;

    for (i = 0; i < res_status->inst_count; i++) {
        if ((inst_id == res_status->inst_list[i].inst_id)) {
            if (res_status->inst_list[i].stat == CMS_RES_ONLINE) {
                return CT_TRUE;
            } else {
                return CT_FALSE;
            }
        }
    }
    return CT_FALSE;
}
