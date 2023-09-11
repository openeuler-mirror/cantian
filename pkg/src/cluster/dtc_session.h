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
 * dtc_session.h
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_session.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DTC_SESSION_H__
#define __DTC_SESSION_H__

#include "knl_session.h"
#include "knl_context.h"
#include "srv_session.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DTC_SQL_SESSION_NUM (2)
#define DTC_KNL_SESSION_NUM (GS_DTC_MAX_TASK_NUM + GS_MES_MAX_CHANNEL_NUM) // GS_MES_MAX_CHANNEL_NUM is used for message receive thread session.

typedef struct st_dtc_session_pool {
    spinlock_t lock;
    uint32 max_sessions;
    session_t *sessions[DTC_SQL_SESSION_NUM];
    knl_session_t *kernel_sessions[DTC_KNL_SESSION_NUM];
    biqueue_t idle_sessions;
    atomic_t  service_count;
} dtc_session_pool_t;

status_t    dtc_init_proc_sessions(void);
session_t *dtc_alloc_sql_session(void);
void        dtc_free_sql_session(session_t *session);

#ifdef __cplusplus
}
#endif


#endif
