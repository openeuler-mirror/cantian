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
 * cms_main.c
 *
 *
 * IDENTIFICATION
 * src/cms/cms/cms_main.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_defs.h"
#include "cms_instance.h"
#include "cms_cmd_imp.h"
#include "cm_timer.h"
#include "cm_file.h"
#include "cms_param.h"
#include "cms_interface.h"
#include "cms_persistent.h"
#include "cms_log.h"

typedef enum e_proc_type_t {
    CMS_SERVER,
    CMS_TOOLS,
}proc_type_t;

typedef struct st_cms_log_def_t {
    log_id_t    log_id;
    proc_type_t proc_type;
    char        log_filename[CMS_NAME_BUFFER_SIZE];
}cms_log_def_t;

cms_log_def_t g_cms_log[] = {
    { LOG_OPER, CMS_SERVER, "oper/cms_srv.olog" },
    { LOG_RUN, CMS_SERVER, "run/cms_srv.rlog" },
    { LOG_DEBUG, CMS_SERVER, "run/cms_srv.dlog" },
    { LOG_OPTINFO, CMS_SERVER, "run/cms_srv.hblog" },
    { LOG_BLACKBOX, CMS_SERVER, "blackbox/cms_srv.blog" },
    { LOG_OPER, CMS_TOOLS, "oper/cms_adm.olog" },
    { LOG_RUN, CMS_TOOLS, "run/cms_adm.rlog" },
    { LOG_DEBUG, CMS_TOOLS, "run/cms_adm.dlog" },
};

status_t cms_init_loggers(proc_type_t proc_type)
{
    int32 iret_snprintf = 0;

    char file_name[CMS_FILE_NAME_BUFFER_SIZE];
    log_param_t *log_param = cm_log_param_instance();
    log_param->log_level = 0;
    // register error callback function
    cm_init_error_handler(cm_set_sql_error);

    char *home = getenv(CMS_ENV_CMS_HOME);
    iret_snprintf = snprintf_s(log_param->log_home, CMS_PATH_BUFFER_SIZE, CMS_MAX_PATH_LEN, "%s/log", home);
    PRTS_RETURN_IFERR(iret_snprintf);

    if (!cm_dir_exist(log_param->log_home) || 0 != access(log_param->log_home, W_OK | R_OK)) {
        printf("invalid log home dir:%s", log_param->log_home);
        return GS_ERROR;
    }

    log_param->log_backup_file_count = g_cms_param->log_backup_file_count;
    log_param->audit_backup_file_count = g_cms_param->log_backup_file_count;
    log_param->max_log_file_size = g_cms_param->max_log_file_size;
    log_param->max_audit_file_size = g_cms_param->max_log_file_size;
    cm_log_set_file_permissions(GS_DEF_LOG_FILE_PERMISSIONS_640);
    cm_log_set_path_permissions(GS_DEF_LOG_PATH_PERMISSIONS_750);
    log_param->log_level = g_cms_param->log_level;

    for (int32 i = 0; i < LOG_COUNT; i++) {
        iret_snprintf = snprintf_s(file_name, CMS_FILE_NAME_BUFFER_SIZE, CMS_MAX_FILE_NAME_LEN, "%s/%s",
            log_param->log_home, "cms.log");
        PRTS_RETURN_IFERR(iret_snprintf);
        cm_log_init(i, file_name);
    }

    for (size_t i = 0; i < sizeof(g_cms_log) / sizeof(cms_log_def_t); i++) {
        if (proc_type != g_cms_log[i].proc_type) {
            continue;
        }

        iret_snprintf = snprintf_s(file_name, CMS_FILE_NAME_BUFFER_SIZE, CMS_MAX_FILE_NAME_LEN, "%s/%s",
            log_param->log_home, g_cms_log[i].log_filename);
        PRTS_RETURN_IFERR(iret_snprintf);
        cm_log_init(g_cms_log[i].log_id, file_name);
    }

    if (cm_start_timer(g_timer()) != GS_SUCCESS) {
        printf("Aborted due to starting timer thread");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

typedef int32(*cmd_pro_func_t)(int32 argc, char* argv[]);

typedef struct st_cms_cmd_def {
    char*            param[CMS_MAX_CMD_PARAM_COUNT];
    cmd_pro_func_t    cmd_pro_func;
    char*            desc;
}cms_cmd_def_t;

EXTER_ATTACK int32 cms_cmd_help(int32 argc, char* argv[]);
cms_cmd_def_t    g_cms_cmd_defs[] = {
    {{"-h"}, cms_cmd_help, "print cms command parameters"},
    {{"-help"}, cms_cmd_help, "print cms command parameters"},
    {{"server", "-start"}, cms_server_start, "start cms server"},
    {{"server", "-stop"}, cms_server_stop, "stop cms server"},
    {{"gcc",   "-list"}, cms_gcc_list, "list gcc path"},
    {{"gcc",   "-reset"}, cms_gcc_reset, "reset gcc's data"},
    {{"gcc",   "-reset", "-f"}, cms_gcc_reset_force, "reset gcc's data"},
    {{"gcc",   "-exp", "*[OUTPUT FILE PATH]"}, cms_gcc_export, "export gcc to format file"},
    {{"gcc",   "-imp", "*[INPUT FILE PATH]"}, cms_gcc_import, "import gcc from format file"},
    {{"gcc",   "-backup"}, cms_gcc_backup, "backup current gcc with a binary file and a export file in cms home"},
    {{"gcc",   "-restore", "*[BACKUP FILE PATH]"}, cms_gcc_restore, "restore gcc from backup file"},
    {{"node",  "-add", "*[NAME]", "*[IP]", "*[PORT]"}, cms_node_add, "add a node to gcc"},
    {{"node",  "-add", "*[NODE_ID]", "*[NAME]", "*[IP]", "*[PORT]"}, cms_node_add_with_id, "add a node with node_id to gcc"},
    {{"node",  "-del", "*[NODE_ID]"}, cms_node_del, "delete a node from gcc"},
    {{"node",  "-list"}, cms_node_list, "list all node in gcc"},
    {{"node",  "-connected"}, cms_node_connected, "list all connected alive node in cluster"},
    {{"resgrp",  "-list"}, cms_resgrp_list, "list all resource group in gcc"},
    {{"resgrp",  "-add", "*[RESOURCE GROUP NAME]"}, cms_resgrp_add, "add a resource group in gcc"},
    {{"resgrp",  "-del", "*[RESOURCE GROUP NAME]"}, cms_resgrp_del, "delete a resource group in gcc"},
    {{"resgrp",  "-del", "-r", "*[RESOURCE GROUP NAME]" }, cms_resgrp_recursive_del, " delete a resouce group and its resources in gcc recursively" },
    {{"res",  "-list"}, cms_res_list, "list all resource in gcc"},
    {{"res",  "-list", "*[RESOURCE GROUP NAME]"}, cms_res_list, "list resource with resource group in gcc"},
    {{"res",  "-add", "*[RESOURCE NAME]", "-type", "*[RESOURCE TYPE]", "-attr", "*[ATTRIBUTE PAIRS]"}, cms_res_add, "add a resource in gcc"},
    {{"res",  "-add", "*[RESOURCE NAME]", "-type", "*[RESOURCE TYPE]", "-grp", "*[RESOURCE_GROUP_NAME]", "-attr", "*[ATTRIBUTE PAIRS]"}, cms_res_add_with_grp, "add a resource in gcc"},
    {{"res",  "-add", "*[RESOURCE NAME]", "-type", "*[RESOURCE TYPE]"}, cms_res_add_without_attr, "add a resource in gcc"},
    {{"res",  "-add", "*[RESOURCE NAME]", "-type", "*[RESOURCE TYPE]", "-grp", "*[RESOURCE_GROUP_NAME]"}, cms_res_add_with_grp_without_attr, "add a resource in gcc"},
    {{"res",  "-edit", "*[RESOURCE NAME]", "-attr", "*[ATTRIBUTE PAIRS]"}, cms_res_edit, "modify a resource in gcc"},
    {{"res",  "-del", "*[RESOURCE NAME]"}, cms_res_del, "delete a resource in gcc"},
    {{"res",  "-start", "*[RESOURCE NAME]"}, cms_res_start_cmd, "start a resource"},
    {{"res",  "-start", "*[RESOURCE NAME]", "*[TIMEOUT]"}, cms_res_start_cmd, "user specifies the timeout period at start a resource"},
    {{"res",  "-start", "*[RESOURCE NAME]", "-node", "*[NODE_ID]"}, cms_res_start_with_node, "start a resource in a specified node"},
    {{"res",  "-stop", "*[RESOURCE NAME]"}, cms_res_stop_cmd, "stop a resource"},
    {{"res",  "-stop", "*[RESOURCE NAME]", "-node", "*[NODE_ID]"}, cms_res_stop_with_node, "stop a resource in a specified node"},
    {{"stat"}, cms_stat_cluster, "display the cluster's status"},
    {{"stat", "-res"}, cms_stat_res, "display the all resource's status"},
    {{"stat", "-res", "*[RESOURCE NAME]"}, cms_stat_res, "display the resource's status"},
    {{"stat", "-node"}, cms_stat_node, "display the all node's status"},
    {{"stat", "-node", "*[NODE ID]"}, cms_stat_node, "display the node's status"},
    {{"stat", "-server"}, cms_stat_server, "display all server's status"},
    {{"stat", "-server", "*[NODE ID]"}, cms_stat_server, "display the server's status"},
    {{"iostat"}, cms_iostat, "display message statistics."},
    {{"iostat", "-reset"}, cms_iostat_reset, "reset cms statistics."},
    {{"diskiostat"}, cms_local_disk_iostat, "display local disk io message statistics."},
#ifdef DB_DEBUG_VERSION
    {{"syncpoint", "-enable", "*[INJECTION TYPE]", "*[EXECUTION NUM]"}, cms_enable_inject, "enable specified fault injection effective"},
#endif
};

int32 cms_cmd_help(int32 argc, char* argv[])
{
#ifndef _WIN32
    printf("cms version:%s\n", cantiand_get_dbversion());
#endif
    for (int32 i = 0; i < sizeof(g_cms_cmd_defs) / sizeof(cms_cmd_def_t); i++) {
        cms_cmd_def_t* cmd_def = &g_cms_cmd_defs[i];
        printf("cms");
        for (int32 p = 0; p < CMS_MAX_CMD_PARAM_COUNT; p++) {
            if (cmd_def->param[p] == NULL) {
                break;
            }

            if (cmd_def->param[p][0] == '*') {
                printf(" %s", cmd_def->param[p] + 1);
            } else {
                printf(" %s", cmd_def->param[p]);
            }
        }

        printf(",%s\n", cmd_def->desc);
    }
    return GS_SUCCESS;
}

status_t cms_alloc_g_invalid_lock(void)
{
    if (g_invalid_lock == NULL) {
        g_invalid_lock = (cms_flock_t*)cm_malloc_align(CMS_BLOCK_SIZE, sizeof(cms_flock_t));
        GS_RETVALUE_IFTRUE((g_invalid_lock == NULL), GS_ERROR);
        errno_t err = memset_s(g_invalid_lock, sizeof(cms_flock_t), 0, sizeof(cms_flock_t));
        if (err != EOK) {
            CM_FREE_PTR(g_invalid_lock);
            printf("memset_s failed, err %d, errno %d[%s].\n", err, errno, strerror(errno));
            return GS_ERROR;
        }
        g_invalid_lock->magic = CMS_STAT_LOCK_MAGIC;
        g_invalid_lock->node_id = (uint8)-1;
        g_invalid_lock->lock_time = 0;
    }
    return GS_SUCCESS;
}

static void cms_info_log_print(cms_cmd_def_t* cmd_def)
{
    if (cmd_def->cmd_pro_func == cms_local_disk_iostat || cmd_def->cmd_pro_func == cms_node_connected) {
        return;
    }
    GS_LOG_RUN_INF("CMS NODE_ID:%d", (int32)g_cms_param->node_id);
    GS_LOG_RUN_INF("CMS CMS_HOME:%s", g_cms_param->cms_home);
    GS_LOG_RUN_INF("CMS GCC_HOME:%s", g_cms_param->gcc_home);
    GS_LOG_RUN_INF("CMS GCC_TYPPE:%s", g_cms_param->gcc_type == CMS_DEV_TYPE_SD ? "SD" : "FILE");
    GS_LOG_RUN_INF("CMS CMD: %s", cmd_def->desc);
}

EXTER_ATTACK int32 main(int32 argc, char *argv[])
{
    int32 cmd_count = sizeof(g_cms_cmd_defs) / sizeof(cms_cmd_def_t);
    cms_cmd_def_t* cmd_def = NULL;
    int32 i = 0;
    for (; i < cmd_count; i++) {
        cmd_def = &g_cms_cmd_defs[i];
        int32 p = 0;
        for (; p < CMS_MAX_CMD_PARAM_COUNT && p + 1 < argc; p++) {
            if (cmd_def->param[p] == NULL) {
                break;
            }

            if (cmd_def->param[p][0] == '*') {
                continue;
            }

            if (strcmp(argv[p + 1], cmd_def->param[p]) != 0) {
                break;
            }
        }

        if (p == argc - 1 && cmd_def->param[p] == NULL) {
            break;
        }
    }

    if (i == cmd_count) {
        printf("invalid argument\n");
        return GS_ERROR;
    }
    GS_RETURN_IFERR(cms_load_param());
    if (cmd_def->cmd_pro_func == cms_server_start) {
        GS_RETURN_IFERR(cms_init_loggers(CMS_SERVER));
    } else {
        GS_RETURN_IFERR(cms_init_loggers(CMS_TOOLS));
    }

    cms_info_log_print(cmd_def);
    int32 ret = GS_ERROR;
    do {
        if (cms_alloc_g_invalid_lock() != GS_SUCCESS) {
            printf("alloc global invalid lock failed.\n");
            CMS_LOG_ERR("alloc global invalid lock failed.");
            break;
        }

        if (cms_init_gcc_disk_lock() != GS_SUCCESS) {
            printf("initialize gcc disk lock failed.\n");
            CMS_LOG_ERR("initialize gcc disk lock failed.");
            break;
        }

        if (cms_uds_cli_init(g_cms_param->node_id, g_cms_param->cms_home) != GS_SUCCESS) {
            printf("initialize uds client failed.\n");
            CMS_LOG_ERR("initialize uds client failed.");
            break;
        }
        ret = cmd_def->cmd_pro_func(argc, argv);
    } while (0);
    CMS_LOG_INF("%s, ret is %d", cmd_def->desc, ret);
    return ret;
}
