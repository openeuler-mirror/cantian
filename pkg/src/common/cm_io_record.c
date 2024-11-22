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
#include "cse_stats.h"

#if (defined __x86_64__)
#include <x86intrin.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

bool32 g_cm_cantian_event_tracking_open = CT_FALSE;
bool32 g_cm_ctc_event_tracking_open = CT_FALSE;

uint64_t clock_frequency = 0;

io_record_wait_t g_io_record_event_wait[IO_RECORD_EVENT_COUNT][EVENT_TRACKING_GROUP];

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

    // 记录创表（函数：knl_create_table）的时间
    { "knl create table", ""},
    // 记录修改表定义（函数：knl_alter_table）的时间
    { "knl alter table", ""},
    // 记录删表（函数：knl_drop_table）的时间
    { "knl drop table", ""},
    { "knl truncate table", ""},
    { "knl create space", ""},
    { "knl alter space", ""},
    { "knl drop space", ""},
    // 记录创建用户（函数：knl_create_user_internal）的时间
    { "knl create user", ""},
    // 记录删除用户（函数：knl_drop_user_internal）的时间
    { "knl drop user", ""},
    // 记录insert操作（函数：knl_insert）的时间
    { "knl insert", ""},
    // 记录delete操作（函数：knl_internal_delete）的时间
    { "knl delete", ""},
    // 记录update插入操作（函数：knl_internal_update）的时间
    { "knl update", ""},
    // 记录查索引（函数：pcrb_fetch）的时间
    { "pcrb fetch", ""},
    // 记录查heap（函数：pcrh_fetch_inter）的时间
    { "pcrh fetch", ""},
    // 记录得到特定一批row id（函数：pcrh_fetch_by_rid）的时间
    { "knl fetch by rowid", ""},

    // 记录插入heap（函数：pcrh_insert）的时间
    {"pcrh insert", ""},
    // 记录插入索引（函数：pcrb_insert）的时间
    {"pcrb insert", ""},
    // 记录修改heap（函数：pcrh_update）的时间
    {"pcrh update", ""},
    // 记录删除heap（函数：pcrh_delete）的时间
    {"pcrh delete", ""},
    // 记录删除索引（函数：pcrb_delete）的时间
    {"pcrb delete", ""},

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

#if (defined __x86_64__)
uint64_t rdtsc()
{
    return __rdtsc();
}
#else
uint64_t rdtsc()
{
    uint64_t tsc;
    __asm__ volatile ("mrs %0, cntvct_el0" : "=r" (tsc));
    return tsc;
}
#endif

status_t record_io_stat_reset(void)
{
    status_t ret = CT_SUCCESS;
    io_record_wait_t *event_wait;
    for (uint32 i = 0; i < IO_RECORD_EVENT_COUNT; i++) {
        for (uint32 hash_id = 0; hash_id < EVENT_TRACKING_GROUP; hash_id++) {
            event_wait = &g_io_record_event_wait[i][hash_id];
            ret = memset_s(&(event_wait->detail), sizeof(io_record_detail_t), 0, sizeof(io_record_detail_t));
            if (ret != CT_SUCCESS) {
                CT_LOG_RUN_ERR("[io record] init io record failed, event %u", i);
                return ret;
            }
        }
    }
    return ret;
}

status_t record_io_stat_init(void)
{
    return record_io_stat_reset();
}

void record_io_stat_begin(uint64_t *tv_begin, atomic_t *start)
{
    cm_atomic_inc(start);
}

void record_io_stat_end(uint64_t *tv_begin, io_record_detail_t *detail)
{
    if (cm_atomic_get(&(detail->start)) == 0) {
        return;
    }

    if (clock_frequency == 0) {
        CT_LOG_RUN_ERR("[IO RECORD] clcok frequency is not initialized.");
        return;
    }
    uint64_t tv_end;
    tv_end = rdtsc();
    uint64_t clocks_diff = (tv_end - *tv_begin) * 1e6;
    uint64 cost_time = clocks_diff/clock_frequency;

    cm_atomic_add(&(detail->total_time), cost_time);
}

void record_io_stat_print(void)
{
    io_record_detail_t detail;
    for (uint32 i = 0; i < IO_RECORD_EVENT_COUNT; i++) {
        for (uint32 hash_id; hash_id < EVENT_TRACKING_GROUP; hash_id++) {
            detail = g_io_record_event_wait[i][hash_id].detail;
            if (detail.start != 0) {
                printf("id:%u  start:%lld  avg:%lld  total:%lld \n",
                    i, detail.start, detail.total_time / detail.start, detail.total_time);
            }
        }
    }
    printf("\n");
}

volatile bool32 get_iorecord_status(void)
{
    return g_cm_cantian_event_tracking_open;
}

#if (defined __x86_64__)
status_t get_clock_frequency(void)
{
    FILE *fp = fopen("/proc/cpuinfo", "r");
    if (!fp) {
        CT_LOG_RUN_ERR("[IO RECORD] Failed to open 'proc/cpuinfo");
        return CT_ERROR;
    }
    char line[100];
    double freq = 0;
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (sscanf(line, "cpu MHz : %lf", &freq) == 1) {
            fclose(fp);
            clock_frequency = freq * 1e6;
            return CT_SUCCESS;
        }
    }
    CT_LOG_RUN_ERR("[IO RECORD] failed to get cpu frequency.");
    return CT_ERROR;
}
#else
status_t get_clock_frequency(void)
{
    uint64_t freq;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(freq));
    clock_frequency = freq;
    return CT_SUCCESS;
}
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

