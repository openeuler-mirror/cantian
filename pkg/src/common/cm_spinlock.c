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
 * cm_spinlock.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_spinlock.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_spinlock.h"
#include "cm_date.h"

#ifdef WIN32
__declspec(thread) uint64 g_tls_spin_sleeps = 0;
#else
__thread uint64 g_tls_spin_sleeps = 0;
#endif

void cm_spin_sleep_and_stat(spin_statis_t *stat)
{
    uint64 usecs;
    timeval_t tv_begin, tv_end;

    (void)cm_gettimeofday(&tv_begin);
    cm_spin_sleep();
    (void)cm_gettimeofday(&tv_end);
    usecs = TIMEVAL_DIFF_US(&tv_begin, &tv_end);
    if (stat != NULL) {
        stat->wait_usecs = usecs;
    }

    /* tls_spin_sleeps can overflow only if a thread sleep 0xffffffffffffffff us. But this will not take place. */
    g_tls_spin_sleeps += usecs;
}

void cm_spin_sleep_and_stat2(uint32 ms)
{
    uint64 usecs;
    timeval_t tv_begin, tv_end;

    (void)cm_gettimeofday(&tv_begin);
    cm_sleep(ms);
    (void)cm_gettimeofday(&tv_end);
    usecs = TIMEVAL_DIFF_US(&tv_begin, &tv_end);
    g_tls_spin_sleeps += usecs;
}

uint64 cm_total_spin_usecs(void)
{
    return g_tls_spin_sleeps;
}