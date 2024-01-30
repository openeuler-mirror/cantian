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
 * gsc_conn.h
 *
 *
 * IDENTIFICATION
 * src/driver/gsc/gsc_conn.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __GSC_CONN_H__
#define __GSC_CONN_H__
#include "gsc_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CLT_CONN_PACK_EXTEND_STEP 4

void gsc_set_autocommit(gsc_conn_t pconn, bool32 auto_commit);
status_t clt_connect(clt_conn_t *conn, const char *url, const char *user, const char *password, const char *tenant,
    uint32 version);
status_t clt_set_conn_attr(clt_conn_t *conn, int32 attr, const void *data, uint32 len);

#ifdef __cplusplus
}

#endif

#endif // __GSC_CONN_H__
