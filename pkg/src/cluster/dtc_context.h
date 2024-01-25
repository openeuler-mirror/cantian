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
 * dtc_context.h
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_context.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef DTC_CONTEXT_H
#define DTC_CONTEXT_H

//MES = Message Exchange service

#include "knl_session.h"
#include "knl_context.h"
#include "mes_func.h"
#include "mes_config.h"
#include "dtc_dmon.h"
#include "dtc_recovery.h"
#include "dtc_reform.h"
#include "dtc_session.h"
#include "cm_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DTC_RUN_WITH_REFORM

typedef struct st_dtc_profile {
    uint32 mes_pool_size;
    uint32 node_count;
    char nodes[CT_MAX_INSTANCES][CT_MAX_INST_IP_LEN];
    uint16 ports[CT_MAX_INSTANCES];
    knl_scn_t min_scn[CT_MAX_INSTANCES];
    uint32 inst_id;
    uint32 channel_num;
    uint32 reactor_thread_num;
    uint32 task_num;
    cs_pipe_type_t pipe_type;
    bool32 conn_by_profile;
    uint32 upgrade_time_ms;
    uint32 degrade_time_ms;
    uint32 ctstore_max_open_files;
    bool32 enable_rmo_cr;
    uint32 remote_access_limit;
    uint32 gdv_sql_sess_tmout; // seconds
    double ckpt_notify_task_ratio;
    double clean_edp_task_ratio;
    double txn_info_task_ratio;
} dtc_profile_t;

typedef struct st_dtc_instance {
    knl_instance_t *kernel;
    dtc_profile_t profile;
    reform_ctx_t rf_ctx;
    dmon_context_t dmon_ctx;
    dtc_rcy_context_t dtc_rcy_ctx;
    dtc_session_pool_t session_pool;
} dtc_instance_t;

typedef void (*dtc_message_proc_t)(void *session, mes_message_t *message);

typedef struct st_dtc_processor {
    dtc_message_proc_t  proc;
    bool32              is_enqueue;
    char                name[CT_MAX_NAME_LEN];
} dtc_processor_t;

extern dtc_processor_t g_processors[];
#define MES_CMD2NAME(cmdid) (((cmdid) >= 0 && (cmdid) < MES_CMD_CEIL) ? g_processors[(cmdid)].name : "INVALID")

status_t dtc_startup(void);
void dtc_shutdown(knl_session_t *session, bool32 need_ckpt);

extern dtc_instance_t *g_dtc;

#ifdef __cplusplus
}
#endif


#endif
