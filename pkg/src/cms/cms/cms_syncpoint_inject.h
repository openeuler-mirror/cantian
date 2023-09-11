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
 * cms_syncpoint_inject.h
 *
 *
 * IDENTIFICATION
 * src/cms/cms/cms_syncpoint_inject.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CMS_SYNCPOINT_H
#define CMS_SYNCPOINT_H

#include "cm_defs.h"
#include "cm_types.h"
#include "cm_text.h"
#include "cm_spinlock.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CMS_MAX_SYNCPOINT_NAME_LEN 64
#define CMS_MAX_SYNCPOINT_NUM 10
#define CMS_MEMORY_LEAK_SIZE (1024 * 1024 * 100)

typedef enum {
    CMS_MEMORY_LEAK = 0,
    CMS_GET_ERROR_ABORT,
    CMS_RES_OFFLINE_TO_ONLINE_ABORT,
    CMS_RES_REFORM_TO_JOINED_ABORT,
    CMS_RES_LOCAL_TO_OFFLINE_ABORT,
    CMS_RES_OTHER_TO_OFFLINE_ABORT,
    CMS_SPLIT_BRAIN_BEBFORE_VOTING_ABORT,
    CMS_SPLIT_BRAIN_VOTING_ABORT,
    CMS_SPLIT_BRAIN_AFTER_VOTING_ABORT,
    CMS_SPLIT_BRAIN_BEFORE_GET_VOTE_ABORT,
    CMS_SPLIT_BRAIN_AFTER_SET_VOTE_ABORT,
    CMS_SPLIT_BRAIN_AFTER_GET_VOTE_ABORT,
    CMS_BEFORE_IO_FENCE_ABORT,
    CMS_AFTER_IO_FENCE_ABORT,
    CMS_BEFORE_BROADCAST_OFFLINE_ABORT,
    CMS_AFTER_BROADCAST_OFFLINE_ABORT,
    CMS_REG_ONLINE_BEFORE_INCVER_ABORT,
    CMS_SET_JOINED_BEFORE_INCVER_ABORT,
    CMS_DETECT_OFFLINE_BEFORE_INCVER_ABORT,
    CMS_SET_OTHER_NODE_OFFLINE_BEFORE_INCVER_ABORT,
    CMS_SET_START_RES_FAILED_ABORT,
    CMS_DETECT_NEW_VOTE_ROUND_FAIL,
    CMS_SET_VOTE_DATA_FAIL,
    CMS_DEAMON_STOP_PULL_FAIL,
    CMS_EXECUTE_IOFENCE_FAIL,
    CMS_REFRESH_NEW_CLUSTER_INFO_FAIL,
    CMS_SEND_HEARTBEAT_MESSAGE_FAIL,
    CMS_GET_CLUSTER_STAT_FAIL,
    CMS_IOFENCE_KICK_NODE_FAIL,
    CMS_DISK_LOCK_FILE_LOCK_FAIL,
    CMS_DISK_LOCK_FILE_SEEK_FAIL,
    CMS_DISK_LOCK_FILE_WRITE_FAIL,
    CMS_DISK_UNLOCK_FILE_SEEK_FAIL,
    CMS_DISK_UNLOCK_FILE_WRITE_FAIL,
    CMS_DISK_UNLOCK_FILE_UNLOCK_FAIL,
    CMS_DISK_GET_INST_FILE_SEEK_FAIL,
    CMS_DISK_GET_INST_FILE_READ_FAIL,
    CMS_DISK_GET_DATA_FILE_SEEK_FAIL,
    CMS_DISK_GET_DATA_FILE_READ_FAIL,
    CMS_DISK_REOPEN_SLEEP,
    CMS_SYNCPOINT_COUNT,
} cms_syncpoint_id;

#ifdef DB_DEBUG_VERSION
typedef void (*cms_syncpoint_callback)(int32 *param, int32 ret);
typedef struct st_cms_syncpoint_def {
    uint32 id;
    bool32 flag;
    char name[CMS_MAX_SYNCPOINT_NAME_LEN];
    uint32 count; // match count
    cms_syncpoint_callback op;
    spinlock_t lock;
} cms_global_syncpoint_def;

typedef struct st_sp_ctrl_def {
    uint32 raise_count;
    text_t enable;
    text_t signal;
    text_t wait_for;
    text_t syncpoint_name;
} cms_sp_ctrl_def_t;

extern cms_global_syncpoint_def g_cms_syncpoint[];

void cms_syncpoint_inject_errcode(int32 *user_param, int32 ret);
bool32 cms_sp_get_global_syncpoint_flag(uint32 sp_id);
status_t cms_sp_set_global_syncpoint(uint32 inx, uint16 execution_num, char *use_type);
status_t cms_sp_exec_global_syncpoint(uint32 sp_id, int32 *user_param, int32 ret);

#define CMS_SYNC_POINT_GLOBAL_START(sp_id, user_param, ret)           \
    do {                                                          \
        if (cms_sp_get_global_syncpoint_flag(sp_id)) {            \
            cms_sp_exec_global_syncpoint(sp_id, user_param, ret); \
        } else {
#define CMS_SYNC_POINT_GLOBAL_END \
        }                         \
    } while (0)
#else
#define CMS_SYNC_POINT_GLOBAL_START(sp_id, user_param, ret)
#define CMS_SYNC_POINT_GLOBAL_END
#endif /* DB_DEBUG_VERSION */

#ifdef __cplusplus
}
#endif

// CMS_SYNCPOINT_H
#endif