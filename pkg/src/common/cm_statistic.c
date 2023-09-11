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
 * cm_statistic.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_statistic.c
 *
 * -------------------------------------------------------------------------
 */
#ifdef TIME_STATISTIC
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "cm_file.h"
#include "cm_statistic.h"


clock_t cm_cal_time_bengin()
{
    clock_t start = clock();

    return start;
}

double cm_cal_time_end(clock_t start)
{
    clock_t finish = clock();
    double duration = (double)(finish - start) / CLOCKS_PER_SEC;

    return duration;
}

#endif
