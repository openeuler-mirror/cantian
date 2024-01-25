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
 * gsc_client.h
 *
 *
 * IDENTIFICATION
 * src/driver/gsc/gsc_client.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __GSC_CLIENT_H__
#define __GSC_CLIENT_H__
#include "cm_base.h"
#include "cm_thread.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CLT_MAX_BOUND_SIZE (CT_MAX_PACKET_SIZE - 256)
extern void gsc_set_paramset_size(gsc_stmt_t pstmt, uint32 sz);

#ifdef __cplusplus
}

#endif

#endif