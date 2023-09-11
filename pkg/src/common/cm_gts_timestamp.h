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
 * cm_gts_timestamp.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_gts_timestamp.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef CM_GTS_TIMESTAMP_H
#define CM_GTS_TIMESTAMP_H

#include "cm_atomic.h"
#include "cm_date.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef Z_SHARDING
#define GTS_INVALID_TIMESTAMP 0
#define GTS_INVALID_SCN 0
#define GTS_INTERVAL_TO_LOCAL_TIMESTAMP_MAX 60 // seconds

void gts_init_lcl_timestamp(bool32 is_gts_free);

/**
 * 1. in DN, if its local timestamp is LT timestamp from CN, update DN's local timestamp
 * 2. if get a new timestamp from GTS, update local timestamp;
 * every time after update local timestamp, postpone the timer to get a new timestamp from GTS.
 */
bool32 gts_update_lcl_timestamp(uint64 *new_scn);
status_t gts_get_lcl_timestamp(uint64 *gts_scn);
status_t gts_get_lcl_motorial_ts(uint64 *gts_scn);
bool32 gts_is_lcl_ts_motorial(void);
void gts_set_lcl_ts_motorial(bool32 is_motorial);
void gts_timestamp_cas(uint64 *left_scn, uint64 *right_scn);
bool32 gts_is_free(void);
#endif

#ifdef __cplusplus
}
#endif

#endif
