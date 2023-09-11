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
 * dtc_dmon.h
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_dmon.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef KNL_DMON_H
#define KNL_DMON_H

#include "cm_types.h"
#include "cm_defs.h"
#include "cm_thread.h"
#include "knl_session.h"
#include "mes_func.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_mes_scn_bcast {
    mes_message_head_t head;
    knl_scn_t scn;
    knl_scn_t min_scn;
    atomic_t  lsn;
    timeval_t cur_time;
} mes_scn_bcast_t;

typedef struct st_mes_lsn_bcast {
    mes_message_head_t head;
    atomic_t lsn;
} mes_lsn_bcast_t;

typedef struct st_dmon_context {
    thread_t thread;
    knl_session_t *session;
    volatile bool32 working;
} dmon_context_t;

status_t dmon_startup(void);
void dmon_close(void);

knl_scn_t dtc_get_min_scn(knl_scn_t cur_min_scn);

EXTER_ATTACK void dtc_process_scn_req(void *sess, mes_message_t *msg);
EXTER_ATTACK void dtc_process_scn_broadcast(void *sess, mes_message_t *msg);
EXTER_ATTACK void dtc_process_lsn_broadcast(void *sess, mes_message_t *msg);

#ifdef __cplusplus
}
#endif

#endif
