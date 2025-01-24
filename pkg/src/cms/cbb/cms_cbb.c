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
 * cms_cbb.c
 *
 *
 * IDENTIFICATION
 * src/cms/cbb/cms_cbb.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_defs.h"
#include "cms_cbb.h"
#include "cbb_disklock.h"
#include "cbb_test_log.h"

#define CM_MAX_RES_NAME_LENGTH 32
#define CM_MAX_INST_COUNTS 64
#define MAX_EXIT_STATUS 128

#define DSS_RES_DATA_LOCK_PATH "/dev/gcc-disk"
#define DSS_RES_DATA_LOCK_POS (1073741824)

unsigned int g_lock_id = 0;

int CmInit(unsigned int instance_id, const char *res_name, cm_notify_func_t func)
{
    int ret = cm_dl_alloc(DSS_RES_DATA_LOCK_PATH, DSS_RES_DATA_LOCK_POS, instance_id);
    if (ret == CM_INVALID_LOCK_ID) {
        LOG("cm_dl_alloc failed with ret: %d", ret);
        return CT_ERROR;
    }
    g_lock_id = ret;
    LOG("CmInit completed, g_lock_id: %u", g_lock_id);
    return CT_SUCCESS;
}

char* CmGetResStats(void)
{
    const char *json_data = 
    "{"
        "\"res_name\": \"example\","
        "\"version\": 0,"
        "\"inst_count\": 2,"
        "\"inst_status\": ["
            "{"
                "\"node_id\": 0,"
                "\"res_instance_id\": 0,"
                "\"is_work_member\": 1,"
                "\"status\": 1"
            "},"
            "{"
                "\"node_id\": 1,"
                "\"res_instance_id\": 1,"
                "\"is_work_member\": 1,"
                "\"status\": 1"
            "}"
        "]"
    "}";

    char *result = (char *)malloc(strlen(json_data) + 1);
    if (result == NULL) {
        LOG("Memory allocation failed in CmGetResStats");
        return NULL;
    }
    
    strcpy(result, json_data);
    LOG("CmGetResStats completed, JSON data allocated.");
    return result;
}

void CmFreeResStats(char *res_stat)
{
    if (res_stat != NULL) {
        res_stat = NULL;
        LOG("res_stat memory freed.");
    }
}

int CmResLock(const char *lock_name)
{
    int ret = cm_dl_lock(g_lock_id, 1000);
    if (ret == 0) {
        LOG("cm_dl_lock succeeded");
        return CT_SUCCESS;
    }

    unsigned long long lockTime = 0;
    ret = cm_dl_getlocktime(g_lock_id, &lockTime);
    if (ret != 0) {
        LOG("cm_dl_getlocktime failed with ret: %d", ret);
        return CT_ERROR;
    }

    int result = (int)(lockTime % MAX_EXIT_STATUS);
    LOG("CmResLock completed, lockTime: %llu, result: %d", lockTime, result);

    return result == CT_SUCCESS ? CT_ERROR : result;
}

int CmResUnlock(const char *lock_name)
{
    int ret = cm_dl_unlock(g_lock_id);
    
    if (ret != 0) {
        LOG("CmResUnlock failed with ret: %d", ret);
        return CT_ERROR;
    }
    
    LOG("CmResUnlock succeeded");
    return CT_SUCCESS;
}

int CmResGetLockOwner(const char *lock_name, unsigned int *inst_id)
{
    if (inst_id == NULL) {
        LOG("CmResGetLockOwner failed due to NULL inst_id pointer");
        return CT_ERROR;
    }

    unsigned long long temp_inst_id;
    int ret = cm_dl_getowner(g_lock_id, &temp_inst_id);
    if (ret != 0) {
        LOG("cm_dl_getowner failed with ret: %d", ret);
        return ret;
    }

    *inst_id = (unsigned int)temp_inst_id;
    LOG("CmResGetLockOwner completed, inst_id: %u", *inst_id);

    return CT_SUCCESS;
}

int CmResTransLock(const char *lock_name, unsigned int inst_id)
{
    int ret = cm_dl_unlock(g_lock_id);
    if (ret != 0) {
        LOG("CmResTransLock failed to unlock, ret: %d", ret);
        return CT_ERROR;
    }

    LOG("CmResTransLock completed successfully");
    return CT_SUCCESS;
}