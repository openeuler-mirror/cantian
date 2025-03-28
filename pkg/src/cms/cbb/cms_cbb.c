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
#include <string.h>
#include "cm_defs.h"
#include "cms_cbb.h"
#include "cbb_disklock.h"
#include "cbb_test_log.h"

#define CM_MAX_RES_NAME_LENGTH 32
#define CM_MAX_INST_COUNTS 64
#define MAX_EXIT_STATUS 128
#define DSS_STAT_MAX_LEN 13
#define JSON_DATA_MAX_LEN 2000
#define NODE_DATA_MAX_LEN 100

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

status_t GetDssStat(dss_res_data *dss_res)
{
    FILE *fp = NULL;
    char line[DSS_STAT_MAX_LEN];
    char cmd_cms_stat[CT_MAX_CMD_LEN] = "cms stat -res dss | awk '{print $1, $3, $6}' | grep -v 'NODE_ID'";
    char status[8];
    int node_id, is_work_member;
    fp = popen(cmd_cms_stat, "r");
    if (fp == NULL) {
        LOG("Fail to get dss stat.");
        return CT_ERROR;
    }
    dss_res->inst_count = 0;
    while (fgets(line, sizeof(line), fp) != NULL) {
        int result = sscanf(line, "%d %s %d", &node_id, status, &is_work_member);
        if (result == SSCANF_ERROR) {
            LOG("Fail to scan dss stat.");
            return CT_ERROR;
        }
        dss_res->node[dss_res->inst_count].is_work_member = is_work_member;
        if (strcmp(status, "UNKNOWN") == 0) {
            dss_res->node[dss_res->inst_count].status = DSS_UNKNOWN;
        }
        else if (strcmp(status, "ONLINE") == 0) {
            dss_res->node[dss_res->inst_count].status = DSS_ONLINE;
        }
        else if (strcmp(status, "OFFLINE") == 0) {
            dss_res->node[dss_res->inst_count].status = DSS_OFFLINE;
        }
        dss_res->inst_count++;        
    }
    pclose(fp);
    return CT_SUCCESS;
}

char* CmGetResStats(void)
{
    dss_res_data *dss_res = (dss_res_data*)malloc(sizeof(dss_res_data));    
    if (dss_res == NULL) {
        LOG("Here is no dss node.");
        return NULL;
    }
    memset_s(dss_res, sizeof(dss_res_data), 0, sizeof(dss_res_data));
    if (GetDssStat(dss_res) != CT_SUCCESS) {
        free(dss_res);
        return NULL;
    }
    char json_data[JSON_DATA_MAX_LEN];
    int result = snprintf_s(json_data, JSON_DATA_MAX_LEN, JSON_DATA_MAX_LEN - 1, "{"
                            "\"res_name\": \"dss\","
                            "\"version\": 0,"
                            "\"inst_count\": %u,"
                            "\"inst_status\": [", dss_res->inst_count);
    if (result == SSPRINTF_ERROR) {
        LOG("Fail to use snprintf_s on json_data.");
        free(dss_res);
        return NULL;
    }
    for (uint i = 0; i < dss_res->inst_count; i++) {
        char node_data[NODE_DATA_MAX_LEN];
        int result = snprintf_s(node_data, NODE_DATA_MAX_LEN, NODE_DATA_MAX_LEN, "{"
                                "\"node_id\": %u,"
                                "\"res_instance_id\": %u,"
                                "\"is_work_member\": %u,"
                                "\"status\": %u"
                                "}",i , i, dss_res->node[i].is_work_member, dss_res->node[i].status);
        if (result == SSPRINTF_ERROR) {
            LOG("Fail to use snprintf_s on node_data.");
            free(dss_res);
            return NULL;
        }
        errno_t error = strcat_s(json_data, JSON_DATA_MAX_LEN, node_data);
        if (error != STRCAT_SUCCESS) {
            LOG("Fail to use strcat_s on json_data.");
            free(dss_res);
            return NULL;
        }
        if (i < dss_res->inst_count - 1) {
            errno_t error = strcat_s(json_data, JSON_DATA_MAX_LEN, ",");
            if (error != STRCAT_SUCCESS) {
                LOG("Fail to use strcat_s on json_data.");
                free(dss_res);
                return NULL;
            }
        }
    }
    errno_t error = strcat_s(json_data, JSON_DATA_MAX_LEN, "]}");
    if (error != STRCAT_SUCCESS) {
        LOG("Fail to use strcat_s on json_data.");
        free(dss_res);
        return NULL;
    }
    free(dss_res);

    char *malloc_result = (char *)malloc(strlen(json_data) + 1);
    if (malloc_result == NULL) {
        LOG("Memory allocation failed in CmGetResStats");
        return NULL;
    }
    memset_s(malloc_result, strlen(json_data) + 1, 0, strlen(json_data) + 1);
    
    strcpy(malloc_result, json_data);
    LOG("CmGetResStats completed, JSON data allocated.");
    return malloc_result;
}

void CmFreeResStats(char *res_stat)
{
    if (res_stat != NULL) {
        free(res_stat);
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