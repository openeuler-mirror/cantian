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
 * cse_stats.h
 *
 *
 * IDENTIFICATION
 * src/ctc/cse_stats.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CSE_STATS_H__
#define __CSE_STATS_H__

#include <sys/time.h>
#include "cm_defs.h"
#include "ctc_srv.h"
#include "cm_io_record.h"

#ifdef __cplusplus
extern "C" {
#endif
extern io_record_wait_t g_ctc_io_record_event_wait[CTC_FUNC_TYPE_NUMBER];
extern io_record_event_desc_t g_ctc_io_record_event_desc[CTC_FUNC_TYPE_NUMBER];

#define INIT_CTC_EVENT_TRACKING(TYPE) uint64_t tv_begin_##TYPE
#define BEGIN_CTC_EVENT_TRACKING(TYPE) mysql_record_io_stat_begin(TYPE, &tv_begin_##TYPE)
#define END_CTC_EVENT_TRACKING(TYPE) mysql_record_io_stat_end(TYPE, &tv_begin_##TYPE)

typedef enum {
    CANTIAN_EVENT_TRACKING  = 0,
    CTC_EVENT_TRACKING = 1
} event_tracking_module;


EXTER_ATTACK static inline void mysql_record_io_stat_begin(enum CTC_FUNC_TYPE type, uint64_t *tv_begin)
{
    if (!g_cm_ctc_event_tracking_open) {
        return;
    }
    atomic_t *start = &g_ctc_io_record_event_wait[type].detail.start;
    record_io_stat_begin(tv_begin, start);
}

EXTER_ATTACK static inline void mysql_record_io_stat_end(enum CTC_FUNC_TYPE event, uint64_t *tv_begin)
{
    if (!g_cm_ctc_event_tracking_open) {
        return;
    }
    io_record_detail_t *detail = &(g_ctc_io_record_event_wait[event].detail);
    record_io_stat_end(tv_begin, detail);
}

status_t ctc_record_io_state_reset(void);
#ifdef __cplusplus
}
#endif

#endif

