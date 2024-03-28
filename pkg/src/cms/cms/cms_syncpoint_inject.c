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
 * cms_syncpoint_inject.c
 *
 *
 * IDENTIFICATION
 * src/cms/cms/cms_syncpoint_inject.c
 *
 * -------------------------------------------------------------------------
 */
#include "cms_log_module.h"
#include "cms_syncpoint_inject.h"
#include "cms_log.h"
#include "cm_malloc.h"

#ifdef DB_DEBUG_VERSION

void cms_syncpoint_inject_errcode(int32 *user_param, int32 ret)
{
    if (user_param == NULL) {
        CMS_LOG_DEBUG_ERR("[SYNCPOINT] cms inject code err param");
        return;
    }
    *user_param = ret;
    CMS_LOG_DEBUG_INF("[SYNCPOINT] cms inject errcode %d", ret);
}

void cms_syncpoint_inject_errno11(int32 *user_param, int32 ret)
{
    cms_syncpoint_inject_errcode(user_param, ret);
    errno = EAGAIN;
}

void cms_syncpoint_inject_errno5(int32 *user_param, int32 ret)
{
    cms_syncpoint_inject_errcode(user_param, ret);
    errno = EIO;
}

void cms_syncpoint_inject_sleep5(int32 *user_param, int32 ret)
{
    uint32 interval = 5000;
    cm_sleep(interval);
    if (user_param == NULL) {
        CMS_LOG_DEBUG_ERR("[SYNCPOINT] cms inject code err param");
        return;
    }
    *user_param = ret;
    CMS_LOG_DEBUG_INF("[SYNCPOINT] cms inject errcode %d", ret);
}

void cms_syncpoint_inject_sleep30(int32 *user_param, int32 ret)
{
    uint32 interval = 30000;
    cm_sleep(interval);
    if (user_param == NULL) {
        CMS_LOG_DEBUG_ERR("[SYNCPOINT] cms inject code err param");
        return;
    }
    *user_param = ret;
    CMS_LOG_DEBUG_INF("[SYNCPOINT] cms inject errcode %d", ret);
}

void cms_syncpoint_inject_abort(int32 *user_param, int32 ret)
{
    CM_ABORT(0, "[SYNCPOINT] inject abort!");
}

void cms_syncpoint_inject_mem_leak(int32 *user_param, int32 ret)
{
    char* mem = (char*)cm_malloc(CMS_MEMORY_LEAK_SIZE);
    if (mem == NULL) {
        CT_LOG_RUN_ERR("[SYNCPOINT] cms inject memory leak failed.");
        return;
    }
    errno_t err = memset_s(mem, CMS_MEMORY_LEAK_SIZE, 0, CMS_MEMORY_LEAK_SIZE);
    if (EOK != err) {
        CT_LOG_RUN_ERR("[SYNCPOINT] cms inject memory leak failed, Secure C lib has thrown an error %d", (err));
        return;
    }
    CMS_LOG_DEBUG_INF("[SYNCPOINT] cms inject memory leak");
}

cms_global_syncpoint_def g_cms_syncpoint[] = {
    {CMS_MEMORY_LEAK, CT_FALSE, "CMS_MEMORY_LEAK", 0, cms_syncpoint_inject_mem_leak, 0},
    {CMS_GET_ERROR_ABORT, CT_FALSE, "CMS_GET_ERROR_ABORT", 0, cms_syncpoint_inject_abort, 0},
    // 上线过程
    {CMS_RES_OFFLINE_TO_ONLINE_ABORT, CT_FALSE, "CMS_RES_OFFLINE_TO_ONLINE_ABORT", 0, cms_syncpoint_inject_abort, 0},
    {CMS_RES_REFORM_TO_JOINED_ABORT, CT_FALSE, "CMS_RES_REFORM_TO_JOINED_ABORT", 0, cms_syncpoint_inject_abort, 0},
    // ABORT过程
    {CMS_RES_LOCAL_TO_OFFLINE_ABORT, CT_FALSE, "CMS_RES_LOCAL_TO_OFFLINE_ABORT", 0, cms_syncpoint_inject_abort, 0},
    {CMS_RES_OTHER_TO_OFFLINE_ABORT, CT_FALSE, "CMS_RES_OTHER_TO_OFFLINE_ABORT", 0, cms_syncpoint_inject_abort, 0},
    // 脑裂投票阶段
    {CMS_SPLIT_BRAIN_BEBFORE_VOTING_ABORT, CT_FALSE, "CMS_SPLIT_BRAIN_BEBFORE_VOTING_ABORT", 0,
        cms_syncpoint_inject_abort, 0},
    {CMS_SPLIT_BRAIN_VOTING_ABORT, CT_FALSE, "CMS_SPLIT_BRAIN_VOTING_ABORT", 0, cms_syncpoint_inject_abort, 0},
    {CMS_SPLIT_BRAIN_AFTER_VOTING_ABORT, CT_FALSE, "CMS_SPLIT_BRAIN_AFTER_VOTING_ABORT", 0,
        cms_syncpoint_inject_abort, 0},
    // 脑裂计票阶段
    {CMS_SPLIT_BRAIN_BEFORE_GET_VOTE_ABORT, CT_FALSE, "CMS_SPLIT_BRAIN_BEFORE_GET_VOTE_ABORT", 0,
        cms_syncpoint_inject_abort, 0},
    {CMS_SPLIT_BRAIN_AFTER_SET_VOTE_ABORT, CT_FALSE, "CMS_SPLIT_BRAIN_AFTER_SET_VOTE_ABORT", 0,
        cms_syncpoint_inject_abort, 0},
    {CMS_SPLIT_BRAIN_AFTER_GET_VOTE_ABORT, CT_FALSE, "CMS_SPLIT_BRAIN_AFTER_GET_VOTE_ABORT", 0,
        cms_syncpoint_inject_abort, 0},
    // 执行iofence阶段
    {CMS_BEFORE_IO_FENCE_ABORT, CT_FALSE, "CMS_BEFORE_IO_FENCE_ABORT", 0, cms_syncpoint_inject_abort, 0},
    {CMS_AFTER_IO_FENCE_ABORT, CT_FALSE, "CMS_AFTER_IO_FENCE_ABORT", 0, cms_syncpoint_inject_abort, 0},
    // 踢出其他节点
    {CMS_BEFORE_BROADCAST_OFFLINE_ABORT, CT_FALSE, "CMS_BEFORE_BROADCAST_OFFLINE_ABORT", 0,
        cms_syncpoint_inject_abort, 0},
    {CMS_AFTER_BROADCAST_OFFLINE_ABORT, CT_FALSE, "CMS_AFTER_BROADCAST_OFFLINE_ABORT", 0,
        cms_syncpoint_inject_abort, 0},
    // offline/online与inc version之间添加TP点
    {CMS_REG_ONLINE_BEFORE_INCVER_ABORT, CT_FALSE, "CMS_REG_ONLINE_BEFORE_INCVER_ABORT", 0,
        cms_syncpoint_inject_abort, 0},
    {CMS_SET_JOINED_BEFORE_INCVER_ABORT, CT_FALSE, "CMS_SET_JOINED_BEFORE_INCVER_ABORT", 0,
        cms_syncpoint_inject_abort, 0},
    {CMS_DETECT_OFFLINE_BEFORE_INCVER_ABORT, CT_FALSE, "CMS_DETECT_OFFLINE_BEFORE_INCVER_ABORT", 0,
        cms_syncpoint_inject_abort, 0},
    {CMS_SET_OTHER_NODE_OFFLINE_BEFORE_INCVER_ABORT, CT_FALSE, "CMS_SET_OTHER_NODE_OFFLINE_BEFORE_INCVER_ABORT", 0,
        cms_syncpoint_inject_abort, 0},
    // {CMS_SET_LEFT_BEFORE_INCVER_ABORT}
    // {CMS_UNREG_OFFLINE_BEFORE_INCVER_ABORT}
    {CMS_SET_START_RES_FAILED_ABORT, CT_FALSE, "CMS_SET_START_RES_FAILED_ABORT", 0,
        cms_syncpoint_inject_abort, 0},
    {CMS_DETECT_NEW_VOTE_ROUND_FAIL, CT_FALSE, "CMS_DETECT_NEW_VOTE_ROUND_FAIL", 0,
        cms_syncpoint_inject_errcode, 0},
    {CMS_SET_VOTE_DATA_FAIL, CT_FALSE, "CMS_SET_VOTE_DATA_FAIL", 0,
        cms_syncpoint_inject_errcode, 0},
    {CMS_DEAMON_STOP_PULL_FAIL, CT_FALSE, "CMS_DEAMON_STOP_PULL_FAIL", 0,
        cms_syncpoint_inject_errcode, 0},
    {CMS_EXECUTE_IOFENCE_FAIL, CT_FALSE, "CMS_EXECUTE_IOFENCE_FAIL", 0,
        cms_syncpoint_inject_errcode, 0},
    {CMS_REFRESH_NEW_CLUSTER_INFO_FAIL, CT_FALSE, "CMS_REFRESH_NEW_CLUSTER_INFO_FAIL", 0,
        cms_syncpoint_inject_errcode, 0},
    {CMS_SEND_HEARTBEAT_MESSAGE_FAIL, CT_FALSE, "CMS_SEND_HEARTBEAT_MESSAGE_FAIL", 0,
        cms_syncpoint_inject_errcode, 0},
    {CMS_GET_CLUSTER_STAT_FAIL, CT_FALSE, "CMS_GET_CLUSTER_STAT_FAIL", 0,
        cms_syncpoint_inject_errcode, 0},
    {CMS_IOFENCE_KICK_NODE_FAIL, CT_FALSE, "CMS_IOFENCE_KICK_NODE_FAIL", 0,
        cms_syncpoint_inject_errcode, 0},
    {CMS_DISK_LOCK_FILE_LOCK_FAIL, CT_FALSE, "CMS_DISK_LOCK_FILE_LOCK_FAIL", 0,
        cms_syncpoint_inject_errno11, 0},
    {CMS_DISK_LOCK_FILE_SEEK_FAIL, CT_FALSE, "CMS_DISK_LOCK_FILE_SEEK_FAIL", 0,
        cms_syncpoint_inject_errno5, 0},
    {CMS_DISK_LOCK_FILE_WRITE_FAIL, CT_FALSE, "CMS_DISK_LOCK_FILE_WRITE_FAIL", 0,
        cms_syncpoint_inject_errno5, 0},
    {CMS_DISK_UNLOCK_FILE_SEEK_FAIL, CT_FALSE, "CMS_DISK_UNLOCK_FILE_SEEK_FAIL", 0,
        cms_syncpoint_inject_errno5, 0},
    {CMS_DISK_UNLOCK_FILE_WRITE_FAIL, CT_FALSE, "CMS_DISK_UNLOCK_FILE_WRITE_FAIL", 0,
        cms_syncpoint_inject_errno5, 0},
    {CMS_DISK_UNLOCK_FILE_UNLOCK_FAIL, CT_FALSE, "CMS_DISK_UNLOCK_FILE_UNLOCK_FAIL", 0,
        cms_syncpoint_inject_errno5, 0},
    {CMS_DISK_GET_INST_FILE_SEEK_FAIL, CT_FALSE, "CMS_DISK_GET_INTST_FILE_SEEK_FAIL", 0,
        cms_syncpoint_inject_errno5, 0},
    {CMS_DISK_GET_INST_FILE_READ_FAIL, CT_FALSE, "CMS_DISK_GET_INTST_FILE_READ_FAIL", 0,
        cms_syncpoint_inject_errno5, 0},
    {CMS_DISK_GET_DATA_FILE_SEEK_FAIL, CT_FALSE, "CMS_DISK_GET_DATA_FILE_SEEK_FAIL", 0,
        cms_syncpoint_inject_errno5, 0},
    {CMS_DISK_GET_DATA_FILE_READ_FAIL, CT_FALSE, "CMS_DISK_GET_DATA_FILE_READ_FAIL", 0,
        cms_syncpoint_inject_errno5, 0},
    {CMS_DISK_REOPEN_SLEEP, CT_FALSE, "CMS_DISK_REOPEN_SLEEP", 0,
        cms_syncpoint_inject_sleep30, 0},
    {CMS_UPGRADE_CTD_VERSION_FAIL, CT_FALSE, "CMS_UPGRADE_CTD_VERSION_FAIL", 0,
        cms_syncpoint_inject_errcode, 0},
    {CMS_UPGRADE_VERSION_ABORT, CT_FALSE, "CMS_UPGRADE_VERSION_ABORT", 0,
        cms_syncpoint_inject_abort, 0},
    {CMS_UPGRADE_VERSION_WRITE_GCC_FAIL, CT_FALSE, "CMS_UPGRADE_VERSION_WRITE_GCC_FAIL", 0,
        cms_syncpoint_inject_errcode, 0},
    {CMS_UPGRADE_VERSION_WRITE_GCC_ABORT, CT_FALSE, "CMS_UPGRADE_VERSION_WRITE_GCC_ABORT", 0,
        cms_syncpoint_inject_abort, 0},
    {CMS_UPGRADE_VERSION_SEND_SYNC_FAIL, CT_FALSE, "CMS_UPGRADE_VERSION_SEND_SYNC_FAIL", 0,
        cms_syncpoint_inject_errcode, 0},
    {CMS_DISK_LOCK_FILE_RANGE_LOCK_FAIL, CT_FALSE, "CMS_DISK_LOCK_FILE_RANGE_LOCK_FAIL", 0,
        cms_syncpoint_inject_errcode, 0},
    {CMS_RES_CONN_SLEEP, CT_FALSE, "CMS_RES_CONN_SLEEP", 0,
        cms_syncpoint_inject_sleep5, 0},
};

bool32 cms_sp_get_global_syncpoint_flag(uint32 sp_id)
{
    if (sp_id >= CMS_SYNCPOINT_COUNT) {
        CMS_LOG_DEBUG_ERR("[SYNCPOINT] cms exec syncpoint error id:%u", sp_id);
        return CT_FALSE;
    }

    cm_spin_lock(&g_cms_syncpoint[sp_id].lock, NULL);
    bool32 ret = g_cms_syncpoint[sp_id].flag && g_cms_syncpoint[sp_id].count > 0;
    cm_spin_unlock(&g_cms_syncpoint[sp_id].lock);
    return ret;
}

status_t cms_sp_exec_global_syncpoint(uint32 sp_id, int32 *user_param, int32 ret)
{
    if (sp_id >= CMS_SYNCPOINT_COUNT) {
        CMS_LOG_DEBUG_ERR("[SYNCPOINT] cms exec syncpoint error id:%u", sp_id);
        return CT_ERROR;
    }
    cm_spin_lock(&g_cms_syncpoint[sp_id].lock, NULL);
    if (!g_cms_syncpoint[sp_id].flag || g_cms_syncpoint[sp_id].count == 0) {
        cm_spin_unlock(&g_cms_syncpoint[sp_id].lock);
        return CT_SUCCESS;
    }
    CMS_LOG_WAR("cms execute syncpoint id:%u, name:%s, count:%u.", sp_id, g_cms_syncpoint[sp_id].name,
        g_cms_syncpoint[sp_id].count);
    if (g_cms_syncpoint[sp_id].count > 0) {
        g_cms_syncpoint[sp_id].count--;
    }
    if (g_cms_syncpoint[sp_id].count == 0) {
        g_cms_syncpoint[sp_id].flag = CT_FALSE;
    }
    g_cms_syncpoint[sp_id].op(user_param, ret);
    cm_spin_unlock(&g_cms_syncpoint[sp_id].lock);
    return CT_SUCCESS;
}

status_t cms_sp_set_global_syncpoint(uint32 inx, uint16 execution_num, char *use_type)
{
    cm_spin_lock(&g_cms_syncpoint[inx].lock, NULL);
    if (!cm_strcmpni(use_type, "enable", strlen("enable"))) {
        g_cms_syncpoint[inx].flag = CT_TRUE;
        g_cms_syncpoint[inx].count = execution_num;
    } else if (!cm_strcmpni(use_type, "disable", strlen("disable"))) {
        g_cms_syncpoint[inx].flag = CT_FALSE;
        g_cms_syncpoint[inx].count = 0;
    } else {
        CMS_LOG_DEBUG_ERR("[SYNCPOINT] cms add syncpoint type:%u, error use type str:%s", inx, use_type);
        cm_spin_unlock(&g_cms_syncpoint[inx].lock);
        return CT_ERROR;
    }
    cm_spin_unlock(&g_cms_syncpoint[inx].lock);
    CMS_LOG_DEBUG_INF("[SYNCPOINT] cms add syncpoint type:%u, raise_count:%u, enable:%s", inx, execution_num, use_type);
    return CT_SUCCESS;
}
#endif /* DB_DEBUG_VERSION */