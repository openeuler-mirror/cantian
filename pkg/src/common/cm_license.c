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
 * cm_license.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_license.c
 *
 * -------------------------------------------------------------------------
 */
#ifndef WIN32
#include "cm_common_module.h"
#include "cm_license.h"

const text_t g_date_fmt1 = { "YYYY-MM-DD", 10 };
thread_t g_lic_thread;
lic_cfg_t g_lic_inst;

status_t cm_get_env_path(char *env_name, char *env_path, uint32 max_env_path_size)
{
    bool32 is_exist_special;
    bool32 is_home_exist;
    char real_path[CT_MAX_FILE_PATH_LENGH];
    uint32 path_len;

    char *path = getenv(env_name);
    if (path == NULL) {
        CT_LOG_DEBUG_INF("[LICENSE]the env name(%s)is not define.", env_name);
        return CT_ERROR;
    }

    is_exist_special = cm_check_exist_special_char(path, (uint32)strlen(path));
    if (is_exist_special == CT_TRUE) {
        CT_LOG_DEBUG_INF("[LICENSE]the env path(name:%s) has special char.", env_name);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(realpath_file(path, real_path, CT_MAX_FILE_PATH_LENGH));
    path_len = strlen(real_path);
    is_home_exist = cm_dir_exist(real_path);
    if (is_home_exist == CT_FALSE) {
        CT_LOG_DEBUG_INF("[LICENSE]the env path(name:%s) is not exist. ", real_path);
        return CT_ERROR;
    }

    if (path_len > max_env_path_size - 1) {
        CT_LOG_DEBUG_INF("[LICENSE]the env name(name:%s) is too long. ", real_path);
        return CT_ERROR;
    }

    cm_trim_home_path(real_path, path_len);
    MEMS_RETURN_IFERR(strcpy_s(env_path, max_env_path_size, real_path));
    return CT_SUCCESS;
}

status_t cm_get_lic_conf_mod_time(time_t *mod_time)
{
    struct stat statbuf;
    char env_path[CT_MAX_PATH_BUFFER_SIZE];
    
    if (strlen(g_lic_inst.lic_conf_path) == 0) {
        if (cm_get_env_path(CT_LIC_FILE_PATH_ENV, env_path, CT_MAX_PATH_BUFFER_SIZE) != CT_SUCCESS) {
            cm_close_thread_nowait(&g_lic_thread);
            return CT_ERROR;
        }
        PRTS_RETURN_IFERR(snprintf_s(g_lic_inst.lic_conf_path, CT_FILE_NAME_BUFFER_SIZE, CT_FILE_NAME_BUFFER_SIZE - 1,
            "%s/protect/license.conf", env_path));
    }
    
    if (cm_access_file(g_lic_inst.lic_conf_path, F_OK | R_OK) != CT_SUCCESS) {
        cm_close_thread_nowait(&g_lic_thread);
        CT_LOG_DEBUG_INF("[LICENSE] License file does not exist or cannot be read.");
        return CT_ERROR;
    }

    if (stat(g_lic_inst.lic_conf_path, &statbuf) != CT_SUCCESS) {
        cm_close_thread_nowait(&g_lic_thread);
        CT_LOG_DEBUG_INF("[LICENSE] get License file last modify time failed.");
        return CT_ERROR;
    }

    *mod_time = statbuf.st_ctime;
    return CT_SUCCESS;
}

status_t cm_insert_lic_data(char *date, license_item item)
{
    time_t time_stamp;

    if (item >= LICENSE_TYPE_END) {
        return CT_ERROR;
    }

    if (cm_str_equal(date, CT_LIC_DEADLINE_PERM)) {
        if (g_lic_inst.item[item].status != LICENSE_STATUS_PERMANENT) {
            g_lic_inst.item[item].status = LICENSE_STATUS_PERMANENT;
            g_lic_inst.item[item].validity_time = 0;
            CT_LOG_RUN_INF("[LICENSE]license item:%d, value is permanent", item);
        }
    } else {
        if (cm_str2time(date, &g_date_fmt1, &time_stamp) != CT_SUCCESS) {
            cm_reset_error();
            CT_LOG_RUN_ERR("[LICENSE]str to time failed.date info :%s", date);
            return CT_ERROR;
        }
        if (g_lic_inst.item[item].validity_time != time_stamp) {
            g_lic_inst.item[item].status = LICENSE_STATUS_VALID;
            g_lic_inst.item[item].validity_time = time_stamp;
            CT_LOG_RUN_INF("[LICENSE]license item:%d, value is %lld", item, (int64)time_stamp);
        }
    }
    return CT_SUCCESS;
}

status_t cm_parse_lic_conf(time_t mod_time)
{
    char line[CT_LIC_CONF_LINE_BUF];
    char date[CT_LIC_CONF_LINE_BUF];
    errno_t errcode;

    FILE *fp = fopen(g_lic_inst.lic_conf_path, "r");
    if (fp == NULL) {
        CT_LOG_DEBUG_ERR("[LICENSE] the licesne.conf(%s)can not read.", g_lic_inst.lic_conf_path);
        return CT_ERROR;
    }

    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, LICENSE_VAILD_TIME_STR) != NULL) {
            SSC_CONTINUE_IF_ERR(sscanf_s(line, "GASS10010A00=%s", date, sizeof(date)), "scanf GASS10010A00 failed.");
            CT_CONTINUE_IF_ERROR(cm_insert_lic_data(date, LICENSE_VALIDITY_TIME));
        } else if (strstr(line, LICENSE_PARTITION_100) != NULL) {
            SSC_CONTINUE_IF_ERR(sscanf_s(line, "GASS10010B06=%s", date, sizeof(date)), "scanf GASS10010B06 failed.");
            CT_CONTINUE_IF_ERROR(cm_insert_lic_data(date, LICENSE_PARTITION));
        } else if (strstr(line, LICENSE_PARTITION_T110) != NULL) {
            SSC_CONTINUE_IF_ERR(sscanf_s(line, "GASS100SA005=%s", date, sizeof(date)), "scanf GASS100SA005 failed.");
            CT_CONTINUE_IF_ERROR(cm_insert_lic_data(date, LICENSE_PARTITION));
        } else if (strstr(line, LICENSE_PARTITION_T130) != NULL) {
            SSC_CONTINUE_IF_ERR(sscanf_s(line, "GASS100DA005=%s", date, sizeof(date)), "scanf GASS100DA005 failed.");
            CT_CONTINUE_IF_ERROR(cm_insert_lic_data(date, LICENSE_PARTITION));
        }
        errcode = memset_s(date, sizeof(date), 0x00, sizeof(date));
        if (errcode != EOK) {
            fclose(fp);
            CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return CT_ERROR;
        }
    }

    g_lic_inst.mod_time = mod_time;

    fclose(fp);
    return CT_SUCCESS;
}

void cm_refresh_lic_item_proc(thread_t *thread)
{
    status_t ret;
    time_t mod_time;
    
    while (!thread->closed) {
        ret = cm_get_lic_conf_mod_time(&mod_time);
        if ((ret == CT_SUCCESS) && (mod_time != g_lic_inst.mod_time)) {
            (void)cm_parse_lic_conf(mod_time);
        }
        cm_sleep(CT_LIC_SLEEP_TIME);
    }
    return;
}

status_t cm_lic_init(void)
{
    MEMS_RETURN_IFERR(memset_s(&g_lic_inst, sizeof(lic_cfg_t), 0, sizeof(lic_cfg_t)));
    if (cm_create_thread(cm_refresh_lic_item_proc, 0, NULL, &g_lic_thread) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[LICENSE] create pthread failed.");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t cm_lic_check(license_item item_num)
{
    time_t cur_t = cm_current_time();
    if (item_num >= LICENSE_TYPE_END) {
        return CT_ERROR;
    }

    if (g_lic_inst.item[item_num].status == LICENSE_STATUS_VALID &&
        cur_t >= g_lic_inst.item[item_num].validity_time) {
        CT_LOG_DEBUG_ERR("[LICENSE] license check failed,current time(%lld), item id(%d), item valid time(%lld)",
            (int64)cur_t, item_num, (int64)g_lic_inst.item[item_num].validity_time);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

#endif
