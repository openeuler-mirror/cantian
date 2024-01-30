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
 * ctconn_fetch.h
 *
 *
 * IDENTIFICATION
 * src/driver/ctconn/ctconn_fetch.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CTCONN_FETCH_H__
#define __CTCONN_FETCH_H__
#include "ctconn_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CTCONN_IS_TIMESTAMP_LTZ_TYPE(type) ((type) == CTCONN_TYPE_TIMESTAMP_LTZ)

int32 clt_fetch(clt_stmt_t *stmt, uint32 *rows, bool32 fetch_ori_row);
status_t clt_remote_fetch(clt_stmt_t *stmt);

static inline void clt_decode_date(date_t date, uint8 *bnd_ptr)
{
    cm_decode_ora_date(date, bnd_ptr);
}

static inline void cm_reverse_dec4(dec4_t *dst, dec4_t *src)
{
    dst->sign = src->sign;
    dst->ncells = src->ncells;
    dst->expn = src->expn;
    for (uint32 i = 0; i < src->ncells; i++) {
        dst->cells[i] = cs_reverse_int16(src->cells[i]);
    }
}

#ifdef __cplusplus
}
#endif

#endif // __CTCONN_FETCH_H__
