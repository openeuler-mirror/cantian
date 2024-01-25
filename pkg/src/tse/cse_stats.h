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
 * src/tse/cse_stats.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CSE_STATS_H__
#define __CSE_STATS_H__

#include <sys/time.h>
#include "cm_defs.h"
#include "tse_srv.h"
#include "cm_io_record.h"

#ifdef __cplusplus
extern "C" {
#endif
extern io_record_wait_t g_tse_io_record_event_wait[TSE_FUNC_TYPE_NUMBER];
extern io_record_event_desc_t g_tse_io_record_event_desc[TSE_FUNC_TYPE_NUMBER];

EXTER_ATTACK static inline void mysql_record_io_stat_begin(enum TSE_FUNC_TYPE type, timeval_t *tv_begin)
{
#ifdef DB_DEBUG_VERSION
    atomic_t *start = &g_tse_io_record_event_wait[type].detail.start;
    record_io_stat_begin(tv_begin, start);
#endif
}

EXTER_ATTACK static inline void mysql_record_io_stat_end(enum TSE_FUNC_TYPE event, timeval_t *tv_begin, int stat)
{
#ifdef DB_DEBUG_VERSION
    io_record_detail_t *detail = &(g_tse_io_record_event_wait[event].detail);
    record_io_stat_end(tv_begin, stat, detail);
#endif
}
void tse_record_io_state_reset(void);
#ifdef __cplusplus
}
#endif

#endif

