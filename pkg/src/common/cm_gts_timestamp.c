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
 * cm_gts_timestamp.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_gts_timestamp.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_gts_timestamp.h"
#include "cm_spinlock.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef Z_SHARDING
#define GTS_LOCAL_VERSION_NUM 4

typedef union un_gts_tm_val {
    uint64 scn_val;
    struct {
        uint64 scn_serial : 12;
        uint64 scn_usec : 20;
        uint64 scn_sec : 32;
    };
} gts_tm_val_t;

typedef struct st_gts_timestamp {
    atomic_t scn_val;
    spinlock_t lock;
} gts_timestamp_t;

// / local timestamp manager
typedef struct st_gts_lcl_tms_mgr {
    atomic_t curr_version;  // used to update mutil-version timestamp;
    gts_timestamp_t local_tms[GTS_LOCAL_VERSION_NUM];
    bool32 is_gts_free;
    bool32 is_ts_motorial;  // local timestamp is not too old (10s), keep getting valid timestamp from gts.
} gts_lcl_tms_mgr_t;

static gts_lcl_tms_mgr_t gts_lcl_times_mgr;

void gts_init_lcl_timestamp(bool32 is_gts_free)
{
    gts_lcl_times_mgr.curr_version = 0;
    gts_lcl_times_mgr.is_gts_free = is_gts_free;
    gts_lcl_times_mgr.is_ts_motorial = GS_FALSE;

    // initialize
    for (uint32 i = 0; i < GTS_LOCAL_VERSION_NUM; i++) {
        (void)cm_atomic_set(&gts_lcl_times_mgr.local_tms[i].scn_val, GTS_INVALID_SCN);
        cm_spin_unlock(&gts_lcl_times_mgr.local_tms[i].lock);
    }
}

bool32 gts_update_lcl_timestamp(uint64 *new_scn)
{
    int64 scn_version;
    uint64 old_scn;

    if (gts_lcl_times_mgr.is_gts_free || new_scn == NULL) {
        return GS_FALSE;
    }

    scn_version = cm_atomic_inc(&gts_lcl_times_mgr.curr_version) % GTS_LOCAL_VERSION_NUM;
    old_scn = (uint64)cm_atomic_get(&gts_lcl_times_mgr.local_tms[scn_version].scn_val);
    if (old_scn < *new_scn) {
        cm_spin_lock(&gts_lcl_times_mgr.local_tms[scn_version].lock, NULL);
        if ((uint64)gts_lcl_times_mgr.local_tms[scn_version].scn_val <= *new_scn) {
            cm_atomic_set(&gts_lcl_times_mgr.local_tms[scn_version].scn_val, (int64)*new_scn);
            cm_spin_unlock(&gts_lcl_times_mgr.local_tms[scn_version].lock);
            return GS_TRUE;
        } else {
            cm_spin_unlock(&gts_lcl_times_mgr.local_tms[scn_version].lock);
            return GS_FALSE;
        }
    }

    /* if is same time, we treat it as updated result */
    return (old_scn == *new_scn);
}

static status_t gts_try_get_lcl_timestamp(uint64 *gts_scn)
{
    if (gts_lcl_times_mgr.is_gts_free) {
        *gts_scn = GTS_INVALID_SCN;
        return GS_SUCCESS;
    }

    uint64 max_scn = (uint64)cm_atomic_get(&gts_lcl_times_mgr.local_tms[0].scn_val);
    for (uint32 i = 1; i < GTS_LOCAL_VERSION_NUM; i++) {
        uint64 curr_scn = (uint64)cm_atomic_get(&gts_lcl_times_mgr.local_tms[i].scn_val);
        if (max_scn < curr_scn) {
            max_scn = curr_scn;
        }
    }

    *gts_scn = max_scn;

    if (max_scn == GTS_INVALID_SCN) {
        GS_THROW_ERROR(ERR_GTS_GETTIME_FAILED, "there is no valid local timestamp");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t gts_get_lcl_timestamp(uint64 *gts_scn)
{
    return gts_try_get_lcl_timestamp(gts_scn);
}

status_t gts_get_lcl_motorial_ts(uint64 *gts_scn)
{
    if (!gts_is_lcl_ts_motorial()) {
        GS_THROW_ERROR(ERR_GTS_GETTIME_FAILED, "the timestamp is motionless");
        return GS_ERROR;
    }

    return gts_try_get_lcl_timestamp(gts_scn);
}

bool32 gts_is_lcl_ts_motorial(void)
{
    return gts_lcl_times_mgr.is_gts_free || gts_lcl_times_mgr.is_ts_motorial;
}

void gts_set_lcl_ts_motorial(bool32 is_motorial)
{
    gts_lcl_times_mgr.is_ts_motorial = is_motorial;
}

// / if left_scn < right_scn, update left_scn as right_scn, keep left_scn as the larger one.
void gts_timestamp_cas(uint64 *left_scn, uint64 *right_scn)
{
    if (gts_lcl_times_mgr.is_gts_free) {
        return;
    }

    if (*left_scn < *right_scn) {
        *left_scn = *right_scn;
    }
}

bool32 gts_is_free(void)
{
    return gts_lcl_times_mgr.is_gts_free;
}

#endif

#ifdef __cplusplus
}
#endif
