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
 * cms_gcc_exp.c
 *
 *
 * IDENTIFICATION
 * src/cms/cms/cms_gcc_exp.c
 *
 * -------------------------------------------------------------------------
 */
#include "cms_log_module.h"
#include <dirent.h>
#include "cms_defs.h"
#include "cm_file.h"
#include "cms_gcc.h"
#include "cms_param.h"
#include "cms_instance.h"
#include "cm_malloc.h"
#include "cm_defs.h"
#include "cms_log.h"

static status_t cms_export_gcc_head(int32 file)
{
    errno_t ret;
    const cms_gcc_t* gcc;
    const cms_gcc_head_t* gcc_head;
    char* attrs_name = "#GCC_HEAD#\nMETA_VER,NODE_COUNT,DATA_VER,CHECKSUM\n";
    char buf[CMS_EXP_ROW_BUFFER_SIZE] = { '\0' };

    CT_RETURN_IFERR(cm_write_file(file, attrs_name, (int)strlen(attrs_name)));

    gcc = cms_get_read_gcc();
    gcc_head = &gcc->head;

    if (gcc_head->magic != CMS_GCC_HEAD_MAGIC) {
        CT_THROW_ERROR(ERR_CMS_GCC_EXPORT, "gcc head");
        cms_release_gcc(&gcc);
        return CT_ERROR;
    }

    ret = snprintf_s(buf, CMS_EXP_ROW_BUFFER_SIZE, CMS_EXP_ROW_BUFFER_SIZE - 1, "%u,%u,%u,%u\n",
        gcc_head->meta_ver, gcc_head->node_count, gcc_head->data_ver, gcc_head->cheksum);
    cms_release_gcc(&gcc);
    PRTS_RETURN_IFERR(ret);

    CT_RETURN_IFERR(cm_write_file(file, buf, (int)strlen(buf)));

    return CT_SUCCESS;
}

static status_t cms_export_node_attrs(int32 file)
{
    errno_t ret;
    const cms_gcc_t* gcc;
    const cms_node_def_t* node_def;
    char* attrs_name = "#GCC_NODE#\nNODE_ID,NAME,IP,PORT\n";
    char buf[CMS_EXP_ROW_BUFFER_SIZE] = { '\0' };

    CT_RETURN_IFERR(cm_write_file(file, attrs_name, (int)strlen(attrs_name)));

    uint32 node_count = cms_get_gcc_node_count();
    for (uint32 i = 0; i < node_count; i++) {
        gcc = cms_get_read_gcc();
        node_def = &gcc->node_def[i];
        if (node_def->magic != CMS_GCC_NODE_MAGIC) {
            CT_THROW_ERROR(ERR_CMS_GCC_EXPORT, "gcc node attrs");
            cms_release_gcc(&gcc);
            continue;
        }

        ret = snprintf_s(buf, CMS_EXP_ROW_BUFFER_SIZE, CMS_EXP_ROW_BUFFER_SIZE - 1, "%u,%s,%s,%u\n",
            node_def->node_id, node_def->name, node_def->ip, node_def->port);
        cms_release_gcc(&gcc);
        PRTS_RETURN_IFERR(ret);

        CT_RETURN_IFERR(cm_write_file(file, buf, (int)strlen(buf)));
    }

    return CT_SUCCESS;
}

static status_t cms_export_votedisk_attrs(int32 file)
{
    errno_t ret;
    const cms_gcc_t* gcc;
    const cms_votedisk_t* votedisk;
    char* attrs_name = "#VOTEDISK#\nPATH\n";
    char buf[CMS_EXP_ROW_BUFFER_SIZE] = { '\0' };

    CT_RETURN_IFERR(cm_write_file(file, attrs_name, (int)strlen(attrs_name)));

    for (uint32 i = 0; i < CMS_MAX_VOTEDISK_COUNT; i++) {
        gcc = cms_get_read_gcc();
        votedisk = &gcc->votedisks[i];
        if (votedisk->magic != CMS_GCC_VOTEDISK_MAGIC) {
            CT_THROW_ERROR(ERR_CMS_GCC_EXPORT, "gcc votedisk attrs");
            cms_release_gcc(&gcc);
            continue;
        }

        ret = snprintf_s(buf, CMS_EXP_ROW_BUFFER_SIZE, CMS_EXP_ROW_BUFFER_SIZE - 1, "%s\n", votedisk->path);
        cms_release_gcc(&gcc);
        PRTS_RETURN_IFERR(ret);

        CT_RETURN_IFERR(cm_write_file(file, buf, (int)strlen(buf)));
    }
    return CT_SUCCESS;
}

static status_t cms_export_resgrp_attrs(int32 file)
{
    errno_t ret;
    const cms_gcc_t* gcc;
    const cms_resgrp_t* resgrp = NULL;
    char* attrs_name = "#RES_GRP #\nGROUP_ID,NAME\n";
    char buf[CMS_EXP_ROW_BUFFER_SIZE] = { '\0' };

    CT_RETURN_IFERR(cm_write_file(file, attrs_name, (int)strlen(attrs_name)));

    for (uint32 i = 0; i < CMS_MAX_RESOURCE_GRP_COUNT; i++) {
        gcc = cms_get_read_gcc();
        resgrp = &gcc->resgrp[i];
        if (resgrp->magic != CMS_GCC_RES_GRP_MAGIC) {
            CT_THROW_ERROR(ERR_CMS_GCC_EXPORT, "gcc resgrp attrs");
            cms_release_gcc(&gcc);
            continue;
        }

        ret = snprintf_s(buf, CMS_EXP_ROW_BUFFER_SIZE, CMS_EXP_ROW_BUFFER_SIZE - 1, "%u,%s\n", resgrp->grp_id, resgrp->name);
        cms_release_gcc(&gcc);
        PRTS_RETURN_IFERR(ret);

        CT_RETURN_IFERR(cm_write_file(file, buf, (int)strlen(buf)));
    }
    return CT_SUCCESS;
}

static status_t cms_export_res_attrs(int32 file)
{
    errno_t ret;
    const cms_gcc_t* gcc;
    const cms_res_t* res = NULL;
    char* attrs_name =
        "#GCC_RES #\nRES_ID,NAME,GROUP_ID,TYPE,LEVEL,AUTO_START,START_TIMEOUT,STOP_TIMEOUT,CHECK_TIMEOUT,HB_TIMEOUT,CHECK_INTERVAL,RESTART_TIMES,SCRIPT\n";
    char buf[CMS_EXP_ROW_BUFFER_SIZE] = { '\0' };

    CT_RETURN_IFERR(cm_write_file(file, attrs_name, (int)strlen(attrs_name)));

    for (uint32 i = 0; i < CMS_MAX_RESOURCE_COUNT; i++) {
        gcc = cms_get_read_gcc();
        res = &gcc->res[i];
        if (res->magic != CMS_GCC_RES_MAGIC) {
            CT_THROW_ERROR(ERR_CMS_GCC_EXPORT, "gcc res attrs");
            cms_release_gcc(&gcc);
            continue;
        }

        ret = snprintf_s(buf, CMS_EXP_ROW_BUFFER_SIZE, CMS_EXP_ROW_BUFFER_SIZE - 1, "%u,%s,%u,%s,%u,%u,%u,%u,%u,%u,%u,%d,%s\n",
            res->res_id, res->name, res->grp_id, res->type, res->level, res->auto_start,
            res->start_timeout, res->stop_timeout, res->check_timeout, res->hb_timeout,
            res->check_interval, res->restart_times, res->script);
        cms_release_gcc(&gcc);
        PRTS_RETURN_IFERR(ret);

        CT_RETURN_IFERR(cm_write_file(file, buf, (int)strlen(buf)));
    }

    return CT_SUCCESS;
}

status_t cms_export_gcc(const char* path)
{
    CT_RETURN_IFERR(cms_load_gcc());
    int32 file;

    if (cm_create_file(path, O_RDWR | O_TRUNC | O_BINARY | O_CREAT, &(file)) != CT_SUCCESS) {
        CMS_LOG_ERR("failed to create file %s", path);
        return CT_ERROR;
    }
    if (cm_chmod_file(FILE_PERM_OF_DATA, file) != CT_SUCCESS) {
        cm_close_file(file);
        CMS_LOG_ERR("failed to chmod export file ");
        return CT_ERROR;
    }

    if (cms_export_gcc_head(file) != CT_SUCCESS) {
        cm_close_file(file);
        CMS_LOG_ERR("export gcc head attributes error");
        return CT_ERROR;
    }
    if (cms_export_node_attrs(file) != CT_SUCCESS) {
        cm_close_file(file);
        CMS_LOG_ERR("export node attributes error");
        return CT_ERROR;
    }
    if (cms_export_votedisk_attrs(file) != CT_SUCCESS) {
        cm_close_file(file);
        CMS_LOG_ERR("export votedisk attributes error");
        return CT_ERROR;
    }
    if (cms_export_resgrp_attrs(file) != CT_SUCCESS) {
        cm_close_file(file);
        CMS_LOG_ERR("export resource group attributes error");
        return CT_ERROR;
    }
    if (cms_export_res_attrs(file) != CT_SUCCESS) {
        cm_close_file(file);
        CMS_LOG_ERR("export resource attributes error");
        return CT_ERROR;
    }

    cm_close_file(file);
    return CT_SUCCESS;
}

static inline status_t cms_backup_binary_gcc(const char* file_name)
{
    cms_gcc_t* temp_gcc;
    int32 handle;
    errno_t ret;

    if (cm_create_file(file_name, O_RDWR | O_TRUNC | O_BINARY | O_CREAT, &(handle)) != CT_SUCCESS) {
        CMS_LOG_ERR("failed to create file %s", file_name);
        return CT_ERROR;
    }
    if (cm_chmod_file(FILE_PERM_OF_DATA, handle) != CT_SUCCESS) {
        cm_close_file(handle);
        CMS_LOG_ERR("failed to chmod gcc backup file ");
        return CT_ERROR;
    }

    temp_gcc = (cms_gcc_t*)cm_malloc_align(CMS_BLOCK_SIZE, sizeof(cms_gcc_t));
    if (temp_gcc == NULL) {
        cm_close_file(handle);
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, sizeof(cms_gcc_t), "backuping gcc");
        return CT_ERROR;
    }

    const cms_gcc_t* gcc = cms_get_read_gcc();
    ret = memcpy_sp(temp_gcc, sizeof(cms_gcc_t), gcc, sizeof(cms_gcc_t));
    if (ret != EOK) {
        cms_release_gcc(&gcc);
        CM_FREE_PTR(temp_gcc);
        cm_close_file(handle);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CT_ERROR;
    }
    cms_release_gcc(&gcc);

    if (cm_pwrite_file(handle, (const char *)temp_gcc, sizeof(cms_gcc_t), 0) != CT_SUCCESS) {
        CM_FREE_PTR(temp_gcc);
        cm_close_file(handle);
        CMS_LOG_ERR("failed to write file, file_name(%s)", file_name);
        return CT_ERROR;
    }

    CM_FREE_PTR(temp_gcc);
    cm_close_file(handle);
    return CT_SUCCESS;
}

static inline int32 cms_get_interval_days(date_t dt1, date_t dt2)
{
    int32 days = (int32)(dt1 / UNITS_PER_DAY - dt2 / UNITS_PER_DAY);

    return days < 0 ? -days : days;
}

int cms_find_oldest_file(time_t times[], uint32 recent_num)
{
    int oldest = 0;
    for (int i = 1; i < recent_num; i++) {
        if (times[i] < times[oldest]) {
            oldest = i;
        }
    }
    return oldest;
}

void cms_remove_old_files(char* dirname, char *prefix)
{
    DIR *dirp;
    struct dirent *dp;
    struct stat statbuf;
    int count = 0;
    time_t times[CMS_GCC_BACKUP_NUM];
    char *file_name[CMS_GCC_BACKUP_NUM];
    uint32 prefix_len = strlen(prefix);

    // Open the directory
    if ((dirp = opendir(dirname)) == NULL) {
        CMS_LOG_ERR("couldn't open %s, error code %d.", dirname, errno);
        return;
    }

    while ((dp = readdir(dirp)) != NULL) {
        // Filter files by prefix
        if (strncmp(dp->d_name, prefix, prefix_len) != 0) {
            continue;
        }
        if (lstat(dp->d_name, &statbuf) != 0) {
            continue;
        }
        if (count < CMS_GCC_BACKUP_NUM) {
            times[count] = statbuf.st_mtime;
            file_name[count] = dp->d_name;
        } else {
            // Find the oldest file
            int oldest = cms_find_oldest_file(times, CMS_GCC_BACKUP_NUM);
            // Replace it with the new file if it is more recent
            if (statbuf.st_mtime > times[oldest]) {
                times[oldest] = statbuf.st_mtime;
                cm_remove_file(file_name[oldest]);
                file_name[oldest] = dp->d_name;
            } else {
                cm_remove_file(dp->d_name);
            }
        }
        count++;
    }
    (void)closedir(dirp);
    return;
}

status_t cms_keep_recent_files(const char *bak_path, char *prefix)
{
    char dirname[CMS_FILE_NAME_BUFFER_SIZE] = { 0 };
    errno_t ret = snprintf_s(dirname, CMS_FILE_NAME_BUFFER_SIZE, CMS_MAX_FILE_NAME_LEN, "%s/gcc_backup/", bak_path);
    PRTS_RETURN_IFERR(ret);

    char buffer[CMS_FILE_NAME_BUFFER_SIZE];
    char *cwdir = getcwd(buffer, CMS_FILE_NAME_BUFFER_SIZE);
    if (cwdir == NULL) {
        CT_LOG_RUN_ERR("get current work directory failed, error code %d.", errno);
        return CT_ERROR;
    }

    if (chdir(dirname) == -1) {
        CT_LOG_RUN_ERR("change current work directory to %s failed, error code %d.", dirname, errno);
        return CT_ERROR;
    }

    cms_remove_old_files(dirname, prefix);
    
    if (chdir(cwdir) == -1) {
        CT_LOG_RUN_ERR("change current work directory to %s failed, error code %d.", cwdir, errno);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t cms_create_gcc_backup_files(date_t bak_time, const char *bak_type, const char *home_path)
{
    char file_name[CMS_FILE_NAME_BUFFER_SIZE] = { 0 };
    char time_str[CT_MAX_TIME_STRLEN] = { 0 };
    int ret;

    ret = snprintf_s(file_name, CMS_FILE_NAME_BUFFER_SIZE, CMS_MAX_FILE_NAME_LEN, "%s/gcc_backup/",
        home_path);
    PRTS_RETURN_IFERR(ret);

    if (!cm_dir_exist(file_name)) {
        CT_RETURN_IFERR(cm_create_dir(file_name));
    }

    CT_RETURN_IFERR(cm_date2str(bak_time, "YYYYMMDDHH24MISS", time_str, CT_MAX_TIME_STRLEN));

    ret = snprintf_s(file_name, CMS_FILE_NAME_BUFFER_SIZE, CMS_MAX_FILE_NAME_LEN, "%s/gcc_backup/%s_%s.exp",
        home_path, bak_type, time_str);
    PRTS_RETURN_IFERR(ret);

    CT_RETURN_IFERR(cms_export_gcc(file_name));

    ret = memset_sp(file_name, CMS_FILE_NAME_BUFFER_SIZE, 0, CMS_FILE_NAME_BUFFER_SIZE);
    MEMS_RETURN_IFERR(ret);

    ret = snprintf_s(file_name, CMS_FILE_NAME_BUFFER_SIZE, CMS_MAX_FILE_NAME_LEN, "%s/gcc_backup/%s_%s",
        home_path, bak_type, time_str);
    PRTS_RETURN_IFERR(ret);

    CT_RETURN_IFERR(cms_backup_binary_gcc(file_name));

    return CT_SUCCESS;
}

status_t cms_backup_gcc_remote(date_t bak_time, const char *bak_type)
{
    CMS_LOG_INF("cms gcc_bak: %s, cms_home:%s", g_cms_param->cms_gcc_bak, g_cms_param->cms_home);
    if (strcmp(g_cms_param->cms_gcc_bak, g_cms_param->cms_home) == 0) {
        CMS_LOG_INF("cms_gcc_bak is not exist");
        return CT_SUCCESS;
    }

    if (cms_create_gcc_backup_files(bak_time, bak_type, g_cms_param->cms_gcc_bak) != CT_SUCCESS) {
        CMS_LOG_ERR("cms backup gcc in remote disk failed");
        return CT_ERROR;
    }
    g_cms_inst->gcc_auto_bak.latest_bak = bak_time;
    return cms_keep_recent_files(g_cms_param->cms_gcc_bak, "auto");
}

status_t cms_backup_gcc_local(date_t bak_time, const char *bak_type)
{
    if (cms_create_gcc_backup_files(bak_time, bak_type, g_cms_param->cms_home) != CT_SUCCESS) {
        CMS_LOG_ERR("cms backup gcc in local disk failed");
        return CT_ERROR;
    }
    g_cms_inst->gcc_auto_bak.latest_bak = bak_time;
    return cms_keep_recent_files(g_cms_param->cms_home, "auto");
}

status_t cms_backup_gcc(void)
{
    date_t bak_time = cm_now();

    CT_RETURN_IFERR(cms_backup_gcc_local(bak_time, "bak"));

    return cms_backup_gcc_remote(bak_time, "bak");
}

status_t cms_backup_gcc_auto(void)
{
    date_t bak_time = cm_now();

    CT_RETURN_IFERR(cms_backup_gcc_local(bak_time, "auto"));
    CT_RETURN_IFERR(cms_backup_gcc_remote(bak_time, "auto"));

    return CT_SUCCESS;
}


void cms_gcc_backup_entry(thread_t * thread)
{
    while (!thread->closed) {
        date_t now_time = cm_now();
        if (g_cms_inst->gcc_auto_bak.is_backuping == CT_FALSE ||
            now_time - g_cms_inst->gcc_auto_bak.latest_bak >= CMS_GCC_BACKUP_INTERVAL) {
            if (cms_backup_gcc_auto() != CT_SUCCESS) {
                CMS_LOG_ERR("backup gcc failed");
                g_cms_inst->gcc_auto_bak.is_backuping = CT_FALSE;
            } else {
                g_cms_inst->gcc_auto_bak.is_backuping = CT_TRUE;
            }
        }
        cm_sleep(1000);
    }
}
