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
 * cm_io_record.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_io_record.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_common_module.h"
#include "cm_io_record.h"
#include "cm_defs.h"
#include "cm_atomic.h"
#include "cm_log.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
volatile bool32 g_cm_io_record_open = CT_FALSE;

io_record_wait_t g_io_record_event_wait[IO_RECORD_EVENT_COUNT];

io_record_event_desc_t g_io_record_event_desc[IO_RECORD_EVENT_COUNT] = {
    { "remaster recover ckpt", ""},
    { "remaster recover rebuild", ""},

    { "cms uds get stat list1", ""},
    { "cms uds set data new", ""},
    { "cms uds get data new", ""},
    { "cms uds cli hb", ""},
    { "cms uds iof kick res", ""},
    { "cms uds unregister", ""},
    { "cms uds set work stat", ""},

    { "knl create table", ""},
    { "knl alter table", ""},
    { "knl drop table", ""},
    { "knl truncate table", ""},
    { "knl create space", ""},
    { "knl alter space", ""},
    { "knl drop space", ""},
    { "knl create user", ""},
    { "knl drop user", ""},
    { "knl insert", ""},
    { "knl update", ""},
    { "knl delete", ""},
    { "pcrb fetch", ""},
    { "pcrh fetch", ""},
    { "knl fetch by rowid", ""},
    { "recovery read online log", ""},
    { "ns batch read ulog", ""},

    { "ns create page pool", ""},
    { "ns open page pool", ""},
    { "ns close page pool", ""},
    { "ns extent page pool", ""},
    { "ns write page pool", ""},
    { "ns read page pool", ""},
    { "ns create ulog", ""},
    { "ns open ulog", ""},
    { "ns read ulog", ""},
    { "ns write ulog", ""},
    { "ns truncate ulog", ""},
    { "ns close ulog", ""},
    { "ns put page", ""},
    { "ns sync page", ""},

    { "bak read data", ""},
    { "bak read checksum", ""},
    { "bak read filter", ""},
    { "bak write local", ""},
    { "bak read log", ""},
    { "bak fsync file", ""},

    { "arch get capacity", ""},
    { "arch read log", ""},
    { "arch write local", ""},
};

status_t record_io_stat_reset(void)
{
    status_t ret = CT_SUCCESS;
    io_record_wait_t *event_wait;
    for (uint32 i = 0; i < IO_RECORD_EVENT_COUNT; i++) {
        event_wait = &g_io_record_event_wait[i];
        ret = memset_s(&(event_wait->detail), sizeof(io_record_detail_t), 0, sizeof(io_record_detail_t));
        if (ret != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[io record] init io record failed, event %u", i);
            return ret;
        }
        event_wait->detail.min_time = CT_INVALID_ID64;
    }
    return ret;
}

status_t record_io_stat_init(void)
{
    return record_io_stat_reset();
}

void record_io_stat_begin(timeval_t *tv_begin, atomic_t *start)
{
    if (!g_cm_io_record_open) {
        return;
    }
    (void)cm_gettimeofday(tv_begin);
    cm_atomic_inc(start);
}

void record_io_stat_end(timeval_t *tv_begin, int stat, io_record_detail_t *detail)
{
    if (!g_cm_io_record_open || cm_atomic_get(&(detail->start)) == 0) {
        return;
    }
    timeval_t tv_end;
    (void)cm_gettimeofday(&tv_end);
    uint64 cost_time = TIMEVAL_DIFF_US(tv_begin, &tv_end);

    cm_atomic_add(&(detail->total_time), cost_time);
    if (detail->max_time < cost_time) {
        cm_atomic_set(&(detail->max_time), cost_time);
    }
    if (detail->min_time > cost_time) {
        cm_atomic_set(&(detail->min_time), cost_time);
    }

    if (stat == IO_STAT_SUCCESS) {
        cm_atomic_add(&(detail->total_good_time), cost_time);
        cm_atomic_inc(&(detail->back_good));
    } else {
        cm_atomic_add(&(detail->total_bad_time), cost_time);
        cm_atomic_inc(&(detail->back_bad));
    }
}

void record_io_stat_print(void)
{
    io_record_detail_t detail;
    for (uint32 i = 0; i < IO_RECORD_EVENT_COUNT; i++) {
        detail = g_io_record_event_wait[i].detail;
        if (detail.back_good + detail.back_bad != 0) {
            printf("id:%u  start:%lld  back_good:%lld  back_bad:%lld  not_back:%lld  avg:%lld  "
                "max:%lld  min:%lld  total:%lld \n",
                i, detail.start, detail.back_good, detail.back_bad, detail.start - detail.back_bad - detail.back_good,
                detail.total_time / (detail.back_good + detail.back_bad),
                detail.max_time, detail.min_time, detail.total_time);
        }
    }
    printf("\n");
}

volatile bool32 get_iorecord_status(void)
{
    return g_cm_io_record_open;
}

void set_iorecord_status(bool32 is_open)
{
    if (g_cm_io_record_open == CT_TRUE && is_open == CT_TRUE) {
        return;
    }
    if (is_open == CT_TRUE) {
        record_io_stat_reset();
    }
    g_cm_io_record_open = is_open;
}

#ifdef __cplusplus
}
#endif /* __cplusplus */

