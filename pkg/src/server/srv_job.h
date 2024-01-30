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
 * srv_job.h
 *
 *
 * IDENTIFICATION
 * src/server/srv_job.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SRV_JOB_H__
#define __SRV_JOB_H__

#include "cm_thread.h"
#include "ctsql_job.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_job_master_ctx {
    thread_t thread;
} job_master_ctx_t;

/* the job manager of instance */
typedef struct st_job_mgr {
    spinlock_t lock;
    uint32 running_count;                       /* running job count */
    job_run_t running_jobs[CT_MAX_JOB_THREADS]; /* running job list */
} job_mgr_t;

void jobs_proc(thread_t *thread);

#ifdef __cplusplus
}
#endif

#endif
