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
 * cm_statistic.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_statistic.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_STATISTIC_H__
#define __CM_STATISTIC_H__

#include <time.h>
#include "cm_defs.h"

clock_t cm_cal_time_bengin(void);
double cm_cal_time_end(clock_t start);

#endif