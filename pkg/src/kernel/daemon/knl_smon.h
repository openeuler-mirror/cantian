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
 * knl_smon.h
 *
 *
 * IDENTIFICATION
 * src/kernel/daemon/knl_smon.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_SMON_H__
#define __KNL_SMON_H__

#include "cm_defs.h"
#include "cm_thread.h"
#include "knl_session.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_smon {
    thread_t thread;
    volatile bool32 undo_shrinking;
    volatile bool32 nolog_alarm;
    volatile bool32 shrink_inactive;
} smon_t;

#define SMON_ENABLE(session)        ((session)->kernel->smon_ctx.disable = CT_FALSE)
#define SMON_CHECK_DISABLE(session) ((session)->kernel->smon_ctx.disable)
#define SMON_UNDO_SHRINK_CLOCK    60000
#define SMON_INDEX_RECY_CLOCK     100000
#define SMON_CHECK_SPC_USAGE_CLOCK 3000
#define SMON_CHECK_XA_CLOCK        1000
#define SMON_CHECK_NOLOGGING       60000

void smon_sql_init(knl_session_t *session, text_t *sql_text);
void smon_record_deadlock_time(void);
EXTER_ATTACK knl_session_t *get_xid_session(knl_session_t *session, xid_t xid);

void smon_proc(thread_t *thread);
void smon_close(knl_session_t *session);
status_t smon_start(knl_session_t *session);

#ifdef __cplusplus
}
#endif

#endif
