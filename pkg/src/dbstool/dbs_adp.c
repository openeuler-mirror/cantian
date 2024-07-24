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
 * dbs_adp.c
 *
 *
 * IDENTIFICATION
 * src/dbstool/dbs_adp.c
 *
 * -------------------------------------------------------------------------
 */

#include <stdio.h>
#include <sys/file.h>
#include <dirent.h>
#include "dbs_adp.h"
#include "cm_date.h"
#include "cm_error.h"
#include "cm_file.h"
#include "cm_dbstore.h"
#include "cm_dbs_defs.h"
#include "cm_log.h"
#include "cm_dbs_intf.h"

#define DBS_CONFIG_FILE_NAME_LEN 32
#define DBS_WAIT_CONFIG_RETRY_NUM 2
#define DBS_WAIT_CONFIG_INTERVAL_TIME 2000
#define DBS_CONFIG_MAX_PARAM 256
#define DBS_CLUSTER_UUID_LEN 37

#define DBS_TOOL_CONFIG_PATH "/opt/cantian/dbstor/conf/dbs"
#define DBS_HOME_PATH "/opt/cantian"

int32 g_lockConfigHandle = CT_INVALID_HANDLE;

status_t dbs_get_and_flock_conf_file(char *config_name)
{
    char dbs_conf_dir_path[CT_FILE_NAME_BUFFER_SIZE] = DBS_TOOL_CONFIG_PATH;

    DIR *dir_ptr;
    struct dirent *entry;

    dir_ptr = opendir(dbs_conf_dir_path);
    if (dir_ptr == NULL) {
        printf("open dbs_conf_dir_path failed!\n");
        return CT_ERROR;
    }

    int32 ret = 0;
    char dbs_conf_file_path[CT_FILE_NAME_BUFFER_SIZE] = { 0 };
    while ((entry = readdir(dir_ptr)) != NULL) {
        if (strstr(entry->d_name, "tool") == NULL) {
            continue;
        }
        ret = memset_s(dbs_conf_file_path, CT_FILE_NAME_BUFFER_SIZE, 0, CT_FILE_NAME_BUFFER_SIZE);
        if (ret != EOK) {
            printf("memset_s dbs_conf_file_path failed!\n");
            break;
        }
        ret = sprintf_s(dbs_conf_file_path, CT_FILE_NAME_BUFFER_SIZE, "%s/%s", dbs_conf_dir_path, entry->d_name);
        if (ret == -1) {
            printf("Failed to assemble the dbstor conf file path by instance home(%s).\n", dbs_conf_dir_path);
            break;
        }
        if (cm_open_file(dbs_conf_file_path, O_RDWR, &g_lockConfigHandle) != CT_SUCCESS) {
            printf("open dbs_conf_file failed!\n");
            break;
        }
        if (flock(g_lockConfigHandle, LOCK_EX | LOCK_NB) == 0) {
            ret = strcpy_s(config_name, DBS_CONFIG_FILE_NAME_LEN, entry->d_name);
            if (ret != EOK) {
                printf("strcpy_s config_name failed!\n");
                closedir(dir_ptr);
                return CT_ERROR;
            }
            closedir(dir_ptr);
            return CT_SUCCESS;
        }
        cm_close_file(g_lockConfigHandle);
    }

    closedir(dir_ptr);
    return CT_ERROR;
}

status_t dbs_alloc_conf_file_retry(char *config_name)
{
    uint32_t retry_num = DBS_WAIT_CONFIG_RETRY_NUM;
    do {
        int32_t ret = memset_s(config_name, DBS_CONFIG_FILE_NAME_LEN, 0, DBS_CONFIG_FILE_NAME_LEN);
        if (ret != EOK) {
            CT_LOG_RUN_ERR("memset_s config_name failed!");
            return CT_ERROR;
        }
        if (dbs_get_and_flock_conf_file(config_name) == CT_SUCCESS) {
            return CT_SUCCESS;
        }
        retry_num--;
        cm_sleep(DBS_WAIT_CONFIG_INTERVAL_TIME);
    } while (retry_num > 0);

    printf("Get free dbstor config file timeout, please wait a while and try again.\n");
    return CT_ERROR;
}

status_t dbs_get_uuid_lsid_from_config(char* cfg_name, uint32* lsid, char* uuid)
{
    char file_path[CT_FILE_NAME_BUFFER_SIZE];
    char line[DBS_CONFIG_MAX_PARAM];
    errno_t ret = sprintf_s(file_path, CT_FILE_NAME_BUFFER_SIZE, "%s/%s",
                            DBS_TOOL_CONFIG_PATH, cfg_name);
    PRTS_RETURN_IFERR(ret);
    FILE* fp = fopen(file_path, "r");
    if (fp == NULL) {
        CT_LOG_RUN_ERR("Failed to open file %s\n", file_path);
        return CT_ERROR;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        char *context = NULL;
        if (strstr(line, "INST_ID") != NULL) {
            text_t lsid_t;
            lsid_t.str = strtok_s(line, "=", &context);
            lsid_t.str = strtok_s(NULL, "\n", &context);
            lsid_t.len = strlen(lsid_t.str);
            cm_trim_text(&lsid_t);
            ret = cm_str2uint32((const char *)lsid_t.str, lsid);
            if (ret != CT_SUCCESS) {
                CT_LOG_RUN_ERR("Str2uint32 failed %d.", ret);
                break;
            }
        } else if (strstr(line, "DBS_TOOL_UUID") != NULL) {
            text_t uuid_t;
            uuid_t.str = strtok_s(line, "=", &context);
            uuid_t.str = strtok_s(NULL, "\n", &context);
            uuid_t.len = strlen(uuid_t.str);
            cm_trim_text(&uuid_t);
            ret = strcpy_s(uuid, DBS_CLUSTER_UUID_LEN, uuid_t.str);
            if (ret != CT_SUCCESS) {
                CT_LOG_RUN_ERR("strcpy_s failed %d.", ret);
                break;
            }
        }
    }
    fclose(fp);
    return ret;
}

status_t dbs_client_init(char* cfg_name)
{
    int64_t start_time = cm_now();
    status_t ret = dbs_init_lib();
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Init dbs lib failed(%d).", ret);
        return ret;
    }

    uint32 lsid;
    char uuid[DBS_CLUSTER_UUID_LEN] = { 0 };

    CT_LOG_RUN_INF("dbstor client is inited by config file %s", cfg_name);
    if (dbs_get_uuid_lsid_from_config(cfg_name, &lsid, uuid) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("cms get uuid lsid from config(%s) failed.\n", cfg_name);
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("uuid:%s, lsid:%u", uuid, lsid);
    cm_set_dbs_uuid_lsid((const char*)uuid, lsid);

    cm_dbs_cfg_s *cfg = cm_dbs_get_cfg();
    cfg->enable = CT_TRUE;

    ret = cm_dbs_init(DBS_HOME_PATH, cfg_name, DBS_RUN_DBS_TOOL);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Dbs init failed(%d).", ret);
    }
    int64_t end_time = cm_now();
    CT_LOG_RUN_INF("dbstor client init time %ld (ns)", end_time - start_time);
    return ret;
}

status_t dbstool_init()
{
    char dbs_cfg_name[DBS_CONFIG_FILE_NAME_LEN] = { 0 };
    if (dbs_alloc_conf_file_retry(dbs_cfg_name) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Init dbs havn't dbs chain.");
        return CT_ERROR;
    }

    if (dbs_client_init(dbs_cfg_name) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Init dbs failed.");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

int32 dbs_test_func(int32 argc, char *argv[]) 
{
    for (int32 i = 0; i < argc; i++) {
        printf("arg(%d):%s.\n", i, argv[i]);
    }
    int32 ret = dbstool_init();
    printf("dbstool init ret=%d.\n", ret);

    // 自定义命令执行
    return ret;
}