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
 * gsc_stmt.h
 *
 *
 * IDENTIFICATION
 * src/driver/gsc/gsc_stmt.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __GSC_STMT_H__
#define __GSC_STMT_H__
#include "gsc_common.h"
#ifdef __cplusplus
extern "C" {
#endif

#define ORA_DATE_IDX_CENTURY 0
#define ORA_DATE_IDX_YEAR 1
#define ORA_DATE_IDX_MONTH 2
#define ORA_DATE_IDX_DAY 3
#define ORA_DATE_IDX_HOUR 4
#define ORA_DATE_IDX_MINUTE 5
#define ORA_DATE_IDX_SECOND 6

status_t gsc_alloc_stmt(gsc_conn_t pconn, gsc_stmt_t *pstmt);
status_t clt_alloc_stmt(clt_conn_t *conn, clt_stmt_t **stmt);
void clt_free_stmt(clt_stmt_t *stmt);
status_t clt_prepare_stmt_pack(clt_stmt_t *stmt);
status_t clt_prepare(clt_stmt_t *stmt, const text_t *sql);
status_t clt_get_execute_ack(clt_stmt_t *stmt);
status_t clt_try_receive_pl_proc_data(clt_stmt_t *stmt, cs_packet_t *ack);
status_t clt_reset_stmt_transcode_buf(clt_stmt_t *stmt);
void clt_recycle_stmt_pack(clt_stmt_t *stmt);
status_t clt_reset_stmt_transcode_buf(clt_stmt_t *stmt);
status_t clt_transcode_column(clt_stmt_t *stmt, char **data, uint32 *size, transcode_func_t transcode_func);
status_t clt_get_stmt_attr(clt_stmt_t *stmt, int attr, const void *data, uint32 buf_len, uint32 *len);
status_t clt_get_outparam_by_id(clt_stmt_t *stmt, uint32 id, void **data, uint32 *size, bool32 *is_null);
bool32 clt_has_large_string(clt_stmt_t *stmt);
status_t clt_write_large_string(clt_stmt_t *stmt);
void clt_set_param_direction(uint8 direction, uint8 *flag);
status_t clt_put_params(clt_stmt_t *stmt, uint32 offset, bool32 add_types);
int gsc_fetch_ori_row(gsc_stmt_t pstmt, unsigned int *rows);

/* the maximal binding size of a row at current statement */
static inline uint32 clt_get_total_row_bndsz(clt_stmt_t *stmt)
{
    uint32 bnd_size = 0;
    clt_param_t *param = NULL;
    uint32 actual_bnd_size;

    for (uint32 i = 0; i < stmt->param_count; i++) {
        param = (clt_param_t *)cm_list_get(&stmt->params, i);
        actual_bnd_size =
            GSC_IS_TYPE_NEED_EXTRA(param->bnd_type) ? (sizeof(uint32) + CM_ALIGN4(param->bnd_size)) : param->bnd_size;
        if (GSC_IS_STRING_TYPE(param->bnd_type) && param->bnd_size > CT_MAX_COLUMN_SIZE) {
            actual_bnd_size = sizeof(gsc_lob_t);
        }
        bnd_size += actual_bnd_size;
    }

    if (stmt->conn->call_version >= CS_VERSION_7) {
        // value length + flags lengths + row size length + types lengths
        return bnd_size + CM_ALIGN4(stmt->param_count) + sizeof(uint32) + CM_ALIGN4(stmt->param_count);
    } else {
        // value length + row size length + param head lengths
        return bnd_size + sizeof(uint32) + sizeof(cs_param_head_t) * stmt->param_count;
    }
}

#ifdef __cplusplus
}
#endif

#endif // __GSC_STMT_H__