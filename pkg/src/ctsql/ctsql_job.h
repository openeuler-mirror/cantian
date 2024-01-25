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
 * ctsql_job.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/ctsql_job.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_JOB_H__
#define __SQL_JOB_H__

#include "cm_defs.h"
#include "cm_list.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_LENGTH_WHAT 4000
#define WHAT_BUFFER_LENGTH (MAX_LENGTH_WHAT + 14)
#define MAX_LENGTH_INTERVAL 200
#define INTERVAL_BUFFER_LENGTH (MAX_LENGTH_INTERVAL + 2)

typedef enum st_job_status {
    JOB_STATUS_NORMAL = 0,
    JOB_STATUS_BROKEN = 1,
} job_status_t;

typedef struct st_job_def {
    int64 job_id;
    char powner[CT_NAME_BUFFER_SIZE];
    char cowner[CT_NAME_BUFFER_SIZE];
    uint32 powner_id;
    int64 this_date;
    int64 next_date;
    int32 total;
    int32 failures;
    int32 is_broken;
    char interval[INTERVAL_BUFFER_LENGTH];
    char what[WHAT_BUFFER_LENGTH];
} job_info_t;

typedef struct st_job_info {
    int64 job_id;
    uint32 session_id;
    uint32 serial_id;
} job_run_t;

#ifdef __cplusplus
}
#endif

#endif
