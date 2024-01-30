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
 * ctconn_lob.h
 *
 *
 * IDENTIFICATION
 * src/driver/ctconn/ctconn_lob.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CTCONN_LOB_H__
#define __CTCONN_LOB_H__
#include "ctconn_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_LOB_BATCH_SIZE (uint32)(CT_MAX_PACKET_SIZE - SIZE_K(1)) // 64K

status_t clt_blob_as_string(clt_stmt_t *stmt, void *locator, char *str, uint32 buf_size, uint32 *strl_len);
status_t clt_clob_as_string(clt_stmt_t *stmt, void *locator, char *str, uint32 buf_size, uint32 *read_size);
status_t clt_image_as_string(clt_stmt_t *stmt, void *locator, char *str, uint32 buf_size, uint32 *read_size);
status_t clt_read_blob(clt_stmt_t *stmt, void *locator, uint32 offset, void *buffer, uint32 size, uint32 *nbytes,
    uint32 *eof);
status_t clt_read_clob(clt_stmt_t *stmt, void *locator, uint32 offset, void *buffer, uint32 size, uint32 *nchars,
    uint32 *nbytes, uint32 *eof);
status_t clt_write_clob(clt_stmt_t *stmt, uint32 id, uint32 piece, const char *data, uint32 size, uint32 *nchars);
status_t clt_write_blob(clt_stmt_t *stmt, uint32 id, uint32 piece, const char *data, uint32 size);

#ifdef __cplusplus
}
#endif

#endif // __CTCONN_LOB_H__
