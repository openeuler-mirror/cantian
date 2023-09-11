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
 * cms_cmd_imp.c
 *
 *
 * IDENTIFICATION
 * src/cms/cms/cms_cmd_imp.c
 *
 * -------------------------------------------------------------------------
 */
#include "cms_cmd_imp.h"
#include "cms_instance.h"
#include "cs_tcp.h"
#include "cms_msg_def.h"
#include "cms_gcc.h"
#include "cms_uds_server.h"
#include "cms_param.h"
#include "cms_stat.h"
#include "cms_client.h"
#include "cms_comm.h"
#include "cm_file.h"
#include "cms_iofence.h"
#include "cm_defs.h"
#include "cms_vote.h"
#include "cms_log.h"

static const char *g_cms_lock_file = "cms_server.lck";

cms_msg_iostat_contrast_t g_cms_iostat_type[CMS_IO_COUNT] = {
    {"CMS_CLI_MSG_REQ_GET_RES_STAT"},
    {"CMS_CLI_MSG_REQ_SET_RES_DATA"},
    {"CMS_CLI_MSG_REQ_GET_RES_DATA"},
    {"CMS_CLI_MSG_REQ_HB"},
    {"CMS_CLI_MSG_RES_IOF_KICK"},
    {"CMS_CLI_MSG_REQ_DIS_CONN"},
    {"CMS_CLI_MSG_REQ_SET_WORK_STAT"},
    {"CMS_STATISTIC_TRY_BE_MASTER"},
    {"CMS_STATISTIC_DETECT_DISK"},
    {"CMS_STATISTIC_HB_AYNC_TIME_GAP"},
};

static status_t cms_check_server_status(bool32 *is_start)
{
    char file_name[CMS_FILE_NAME_BUFFER_SIZE] = {0};
    int32 server_lock_fd = -1;
    int32 ret = 0;
    ret = snprintf_s(file_name, CMS_FILE_NAME_BUFFER_SIZE, CMS_MAX_FILE_NAME_LEN, "%s/%s",
        g_cms_param->cms_home, g_cms_lock_file);
    if (ret == -1) {
        return GS_ERROR;
    }

    if (cm_open_file(file_name, O_CREAT | O_RDWR | O_BINARY | O_CLOEXEC | O_SYNC | O_DIRECT,
        &server_lock_fd) != GS_SUCCESS) {
        return GS_ERROR;
    }
    
    if (cm_lockw_file_fd(server_lock_fd) == GS_SUCCESS) {
        *is_start = GS_FALSE;
        cm_unlock_file_fd(server_lock_fd);
    } else {
        *is_start = GS_TRUE;
    }
    cm_close_file(server_lock_fd);
    return GS_SUCCESS;
}

int32 cms_server_start(int32 argc, char* argv[])
{
    int32 err_code = 0;
    const char *err_msg = NULL;
    printf("NODE_ID     = %hu\n", g_cms_param->node_id);
    printf("CMS_HOME    = %s\n", g_cms_param->cms_home);
    printf("GCC_HOME    = %s\n", g_cms_param->gcc_home);
    printf("GCC_TYPE    = %s\n", g_cms_param->gcc_type == CMS_DEV_TYPE_SD ? "SD" : "FILE");
#ifndef _WIN32
    printf("VERSION     = %s\n", cantiand_get_dbversion());
#endif
    printf("cms startup...\n");
    if (cms_startup() != GS_SUCCESS) {
        cm_get_error(&err_code, &err_msg, NULL);
        printf("cms startup failed:%s.\n", err_msg);
        return 0;
    }

    return GS_SUCCESS;
}


int32 cms_gcc_list(int32 argc, char* argv[])
{
    printf("gcc:%s\n", g_cms_param->gcc_home);

    return 0;
}

int32 cms_gcc_reset_force(int32 argc, char* argv[])
{
    if (cms_reset_gcc() == GS_SUCCESS) {
        printf("reset gcc succeed.\n");
    } else {
        printf("reset gcc failed.\n");
    }

    return GS_SUCCESS;
}

int32 cms_gcc_reset(int32 argc, char* argv[])
{
    printf("The operation will reset all data on gcc, are you sure?(y/n)\n");
    char confirm = getc(stdin);
    if (confirm == 'Y' || confirm == 'y') {
        if (cms_reset_gcc() == GS_SUCCESS) {
            printf("reset gcc succeed.\n");
        } else {
            printf("reset gcc failed.\n");
        }
    }

    return 0;
}

int32 cms_gcc_export(int32 argc, char* argv[])
{
    int32 err_code = 0;
    const char *err_msg = NULL;
    char *path = argv[3];
    if (cm_access_file(path, F_OK) == GS_SUCCESS) {
        printf("The operation will overwrite the current file, are you sure?(y/n)\n");
        char confirm = getc(stdin);
        CMS_LOG_INF("Input is %c.", confirm);
        if (confirm != 'Y' && confirm != 'y') {
            return 0;
        }
    } else {
        cm_reset_error();
    }

    if (cms_export_gcc(path) == GS_SUCCESS) {
        printf("export gcc to file %s succeed.\n", path);
        CMS_LOG_INF("export gcc to file %s succeed.", path);
    } else {
        cm_get_error(&err_code, &err_msg, NULL);
        printf("%s, export gcc to file %s failed.\n", err_msg, path);
        CMS_LOG_ERR("%s, export gcc to file %s failed.", err_msg, path);
    }
    return GS_SUCCESS;
}

int32 cms_gcc_import(int32 argc, char* argv[])
{
    int32 err_code = 0;
    const char *err_msg = NULL;
    source_location_t loc = { 0, 0 };
    printf("The operation will replace all data on gcc and can not rollback, are you sure?(y/n)\n");
    char confirm = getc(stdin);
    const char* file_name = argv[3];
    CMS_LOG_INF("input is %c.", confirm);
    if (confirm == 'Y' || confirm == 'y') {
        if (cms_import_gcc(file_name) == GS_SUCCESS) {
            printf("import gcc from file %s succeed.\n", file_name);
            CMS_LOG_INF("import gcc from file %s succeed.", file_name);
        } else {
            cm_get_error(&err_code, &err_msg, &loc);
            if (loc.line > 0) {
                printf("%s (file row:%u), import gcc from file %s failed.\n", err_msg,
                    (uint32)loc.line, file_name);
            } else {
                printf("%s, import gcc from file %s failed.\n", err_msg, file_name);
            }
            CMS_LOG_ERR("%s, import gcc from file %s failed.", err_msg, file_name);
        }
    }
    return 0;
}

int32 cms_gcc_backup(int32 argc, char* argv[])
{
    int32 err_code = 0;
    const char *err_msg = NULL;
    if (cms_backup_gcc() == GS_SUCCESS) {
        printf("backup gcc succeed.\n");
    } else {
        cm_get_error(&err_code, &err_msg, NULL);
        printf("%s, backup gcc failed.\n", err_msg);
    }
    return GS_SUCCESS;
}

status_t cms_tool_init(void)
{
    if (cms_load_gcc() != GS_SUCCESS) {
        printf("cms load gcc failed.\n");
        GS_LOG_RUN_ERR("cms load gcc failed.");
        return GS_ERROR;
    }
    GS_RETURN_IFERR(cms_instance_init());
    return GS_SUCCESS;
}

int32 cms_gcc_restore(int32 argc, char* argv[])
{
    uint64 cms_online_bitmap = 0;
    const char* file_name = argv[3];
    if (cms_tool_init() == GS_SUCCESS && (cms_get_node_view(&cms_online_bitmap) == GS_SUCCESS)) {
        if (cms_online_bitmap != 0) {
            cms_print_online_node_info(&cms_online_bitmap);
            printf("restore gcc failed. Please retry after %us\n", g_cms_param->detect_disk_timeout);
            CMS_LOG_ERR("restore gcc from file %s failed.", file_name);
            return GS_ERROR;
        }
    } else {
        printf(
            "cms check server stat failed, please ensure all nodes in the cluster are stopped, are you sure?(y/n)\n");
        CMS_LOG_WAR("cms check server stat failed.");
        char ack = getc(stdin);
        CMS_LOG_INF("input is %c.", ack);
        if (ack != 'Y' && ack != 'y') {
            return GS_ERROR;
        }
    }

    int32 err_code = 0;
    const char *err_msg = NULL;
    printf("The operation will replace all data on gcc and can not rollback, are you sure?(y/n)\n");
    char confirm = getc(stdin);
    CMS_LOG_INF("input is %c.", confirm);
    
    if (confirm == 'Y' || confirm == 'y') {
        if (cms_restore_gcc(file_name) == GS_SUCCESS) {
            printf("restore gcc from file %s succeed.\n", file_name);
            CMS_LOG_INF("restore gcc from file %s succeed.", file_name);
        } else {
            cm_get_error(&err_code, &err_msg, NULL);
            printf("%s, restore gcc from file %s failed.\n", err_msg, file_name);
            CMS_LOG_ERR("%s, restore gcc from file %s failed.", err_msg, file_name);
        }
    }

    return GS_SUCCESS;
}


int32 cms_node_list(int32 argc, char* argv[])
{
    if (cms_load_gcc() != GS_SUCCESS) {
        printf("cms load gcc failed.\n");
        GS_LOG_RUN_ERR("cms load gcc failed.");
        return GS_SUCCESS;
    }
    const cms_gcc_t* gcc = cms_get_read_gcc();
    if (gcc->head.magic != CMS_GCC_HEAD_MAGIC) {
        printf("gcc is invalid.");
        GS_LOG_RUN_ERR("gcc is invalid.");
        cms_release_gcc(&gcc);
        return GS_SUCCESS;
    }

    printf("%-12s%-40s%-40s%-5s\n",
        "NODE_ID", "NODE NAME", "IP", "PORT");
    for (uint32 i = 0; i < gcc->head.node_count; i++) {
        const cms_node_def_t* node_def = &gcc->node_def[i];
        if (node_def->magic != CMS_GCC_NODE_MAGIC) {
            continue;
        }
        printf("%7u     %-40s%-39s%5u\n", i, node_def->name, node_def->ip, node_def->port);
    }
    cms_release_gcc(&gcc);
    GS_LOG_RUN_INF("cms node -list succ.");
    return GS_SUCCESS;
}

status_t cms_get_server_vote_result(uint64* cluster_bitmap, bool32* cluster_is_voting, char* err_info)
{
    status_t ret = GS_SUCCESS;
    cms_tool_msg_req_vote_result_t req = {0};
    cms_tool_msg_res_vote_result_t res = {0};

    req.head.msg_type = CMS_TOOL_MSG_REQ_VOTE_RESULT;
    req.head.msg_size = sizeof(cms_tool_msg_req_vote_result_t);
    req.head.msg_version = CMS_MSG_VERSION;
    req.head.msg_seq = cms_uds_cli_get_msg_seq();
    req.head.src_msg_seq = 0;
    ret = cms_send_to_server(&req.head, &res.head, sizeof(cms_tool_msg_res_vote_result_t),
        CMS_CLIENT_REQUEST_TIMEOUT, err_info);
    *cluster_bitmap = res.cluster_bitmap;
    *cluster_is_voting = res.cluster_is_voting;
    return ret;
}

static inline bool32 cm_bitmap64_exist(uint64 *bitmap, uint8 num)
{
    uint64 position;
    CM_ASSERT(num < GS_MAX_INSTANCES);

    position = (uint64)1 << num;

    position = *bitmap & position;

    return 0 != position;
}

int32 cms_node_connected(int32 argc, char *argv[])
{
    char err_info[CMS_INFO_BUFFER_SIZE] = {0};
    uint64 cluster_bitmap = 0;
    bool32 cluster_is_voting = GS_FALSE;
    if (cms_get_server_vote_result(&cluster_bitmap, &cluster_is_voting, err_info) != GS_SUCCESS) {
        printf("%s, cms get vote result failed.\n", err_info);
        return GS_ERROR;
    }

    if (cms_load_gcc() != GS_SUCCESS) {
        printf("cms load gcc failed.\n");
        return GS_ERROR;
    }
    const cms_gcc_t *gcc = cms_get_read_gcc();
    if (gcc->head.magic != CMS_GCC_HEAD_MAGIC) {
        printf("gcc is invalid.\n");
        cms_release_gcc(&gcc);
        return GS_ERROR;
    }

    printf("%-12s%-40s%-40s%-12s%-5s\n", "NODE_ID", "NODE_NAME", "IP", "PORT", "VOTING");
    for (uint32 i = 0; i < gcc->head.node_count; i++) {
        const cms_node_def_t *node_def = &gcc->node_def[i];
        if (node_def->magic != CMS_GCC_NODE_MAGIC) {
            continue;
        }
        if (!cm_bitmap64_exist(&cluster_bitmap, i)) {
            continue;
        }
        printf("%7u     %-40s%-40s%-12u%-5s\n", i, node_def->name, node_def->ip, node_def->port,
            cluster_is_voting == GS_TRUE ? "TRUE" : "FALSE");
    }

    cms_release_gcc(&gcc);
    return GS_SUCCESS;
}

int32 cms_resgrp_list(int32 argc, char* argv[])
{
    if (cms_load_gcc() != GS_SUCCESS) {
        printf("cms load gcc failed.\n");
        return GS_SUCCESS;
    }
    const cms_gcc_t* gcc = cms_get_read_gcc();
    if (gcc->head.magic != CMS_GCC_HEAD_MAGIC) {
        printf("gcc is invalid.");
        cms_release_gcc(&gcc);
        return GS_SUCCESS;
    }

    printf("RESOURCE_GROUP\n");
    for (uint32 i = 0; i < CMS_MAX_RESOURCE_GRP_COUNT; i++) {
        const cms_resgrp_t* resgrp = &gcc->resgrp[i];
        if (resgrp->magic != CMS_GCC_RES_GRP_MAGIC) {
            continue;
        }
        printf("%s\n", resgrp->name);
    }

    cms_release_gcc(&gcc);
    return GS_SUCCESS;
}

int32 cms_res_list(int32 argc, char* argv[])
{
    if (cms_load_gcc() != GS_SUCCESS) {
        printf("cms load gcc failed.\n");
        GS_LOG_RUN_ERR("cms load gcc failed.");
        return GS_SUCCESS;
    }
    const cms_gcc_t* gcc = cms_get_read_gcc();
    if (gcc->head.magic != CMS_GCC_HEAD_MAGIC) {
        printf("gcc is invalid.");
        GS_LOG_RUN_ERR("gcc is invalid.");
        cms_release_gcc(&gcc);
        return GS_SUCCESS;
    }

    printf("%-20s%-20s%-24s%-20s%-20s%-20s%-20s%-20s%-20s%-20s%s\n",
        "RESOURCE_NAME",
        "RESOURCE_TYPE",
        "RESOURCE_GROUP_NAME",
        "START_TIMEOUT(ms)",
        "STOP_TIMEOUT(ms)",
        "CHECK_TIMEOUT(ms)",
        "CHECK_INTERVAL(ms)",
        "HB_TIMEOUT(ms)",
        "RESTART_TIMES",
        "RESTART_INTERVAL",
        "SCRIPT");

    for (uint32 i = 0; i < CMS_MAX_RESOURCE_COUNT; i++) {
        const cms_res_t* res = &gcc->res[i];
        if (res->magic != CMS_GCC_RES_MAGIC) {
            continue;
        }

        if (argc == 4 && (strcmp(gcc->resgrp[res->grp_id].name, argv[3]) != 0)) {
            continue;
        }

        printf("%-20s%-20s%-24s%17u   %16u    %17u   %18u  %14u  %13d  %16u      %s\n",
            res->name,
            res->type,
            gcc->resgrp[res->grp_id].name,
            res->start_timeout,
            res->stop_timeout,
            res->check_timeout,
            res->check_interval,
            res->hb_timeout,
            res->restart_times,
            res->restart_interval,
            res->script);
    }

    cms_release_gcc(&gcc);
    GS_LOG_RUN_INF("cms res -list succ.");
    return GS_SUCCESS;
}

int32 cms_stat_cluster(int32 argc, char* argv[])
{
    cms_res_stat_t res_stat;
    if (cms_load_gcc() != GS_SUCCESS) {
        printf("cms load gcc failed.\n");
        return GS_SUCCESS;
    }
    GS_RETURN_IFERR(cms_instance_init());

    printf("%-9s%-10s%-8s%-12s%-14s%-12s%-13s%-14s%-9s%-24s%-24s%s\n",
           "NODE_ID", "NAME", "STAT", "PRE_STAT", "TARGET_STAT", "WORK_STAT", "SESSION_ID", "INSTANCE_ID",
           "ROLE", "LAST_CHECK", "HB_TIME", "STAT_CHANGE");
    const cms_gcc_t* gcc = cms_get_read_gcc();
    for (uint32 res_id = 0; res_id < CMS_MAX_RESOURCE_COUNT; res_id++) {
        const cms_res_t* res = &gcc->res[res_id];
        if (res->magic != CMS_GCC_RES_MAGIC) {
            continue;
        }

        uint8 master_node_id = -1;
        (void)cms_get_res_master(res_id, &master_node_id);

        for (uint32 node_id = 0; node_id < gcc->head.node_count; node_id++) {
            const cms_node_def_t* node_def = &gcc->node_def[node_id];
            if (node_def->magic != CMS_GCC_NODE_MAGIC) {
                continue;
            }
            if (get_res_stat(node_id, res_id, &res_stat) != GS_SUCCESS) {
                cms_release_gcc(&gcc);
                printf("get resource stat failed.");
                return GS_ERROR;
            }

            if (cm_now() > res_stat.last_check + res->hb_timeout * MICROSECS_PER_MILLISEC) {
                res_stat.cur_stat = CMS_RES_UNKNOWN;
            }

            char last_check[32], stat_change[32], hb_time[32];
            cms_date2str(res_stat.last_check, last_check, sizeof(last_check));
            cms_date2str(res_stat.last_stat_change, stat_change, sizeof(stat_change));
            cms_date2str(res_stat.hb_time, hb_time, sizeof(hb_time));
            printf("%7u  %-10s%-8s%-12s%-14s%9d   %10llu   %11llu   %-9s%-24s%-24s%s\n",
                   node_id, res->name, cms_stat_str(res_stat.cur_stat), cms_stat_str(res_stat.pre_stat),
                   cms_stat_str(res_stat.target_stat), (int32)res_stat.work_stat, res_stat.session_id, res_stat.inst_id,
                   master_node_id == node_id ? "REFORMER" : "",
                   last_check, hb_time, stat_change);
        }
    }

    cms_release_gcc(&gcc);
    return GS_SUCCESS;
}

int32 cms_stat_res(int32 argc, char* argv[])
{
    char last_check[32], stat_change[32];
    cms_res_stat_t res_stat;

    if (cms_load_gcc() != GS_SUCCESS) {
        printf("cms load gcc failed.\n");
        return GS_SUCCESS;
    }
    GS_RETURN_IFERR(cms_instance_init());

    char* name = NULL;
    if (argc == 4) {
        name = argv[3];
    }

    const cms_gcc_t* gcc = cms_get_read_gcc();
    uint32 res_id = CMS_MAX_RESOURCE_COUNT;
    if (name != NULL) {
        const cms_res_t* res = cms_find_res(gcc, name);
        if (res == NULL) {
            printf("resource [%s] not found.\n", name);
            cms_release_gcc(&gcc);
            return GS_ERROR;
        }
        res_id = res->res_id;
    }

    printf("%-10s%-32s%-12s%-12s%-14s%-12s%-27s%s\n",
           "NODE_ID", "RESOURCE_NAME", "STAT", "PRE_STAT", "TARGET_STAT", "WORK_STAT", "LAST_CHECK", "STAT_CHANGE");

    for (uint32 id = 0; id < CMS_MAX_RESOURCE_COUNT; id++) {
        if (gcc->res[id].magic != CMS_GCC_RES_MAGIC ||
            (res_id != CMS_MAX_RESOURCE_COUNT && res_id != id)) {
            continue;
        }

        for (uint32 node_id = 0; node_id < gcc->head.node_count; node_id++) {
            const cms_node_def_t *node_def = &gcc->node_def[node_id];
            if (node_def->magic != CMS_GCC_NODE_MAGIC) {
                continue;
            }
            const cms_res_t* res = &gcc->res[id];
            
            if (get_res_stat(node_id, id, &res_stat) != GS_SUCCESS) {
                cms_release_gcc(&gcc);
                printf("get resource stat failed.");
                return GS_ERROR;
            }

            if (res_stat.cur_stat != CMS_RES_OFFLINE && cm_now() > res_stat.last_check + res->hb_timeout * MICROSECS_PER_MILLISEC) {
                res_stat.cur_stat = CMS_RES_UNKNOWN;
            }

            cms_date2str(res_stat.last_check, last_check, sizeof(last_check));
            cms_date2str(res_stat.last_stat_change, stat_change, sizeof(stat_change));
            printf("%-10u%-32s%-12s%-12s%-14s%-12d%-27s%s\n",
                   node_id, res->name, cms_stat_str(res_stat.cur_stat), cms_stat_str(res_stat.pre_stat),
                   cms_stat_str(res_stat.target_stat), (int32)res_stat.work_stat, last_check, stat_change);
        }
    }

    cms_release_gcc(&gcc);
    return GS_SUCCESS;
}

int32 cms_stat_node(int32 argc, char* argv[])
{
    if (cms_load_gcc() != GS_SUCCESS) {
        printf("cms load gcc failed.\n");
        return GS_SUCCESS;
    }
    GS_RETURN_IFERR(cms_instance_init());
    uint32 sp_node_id = CMS_MAX_NODE_COUNT;
    if (argc == 4) {
        sp_node_id = atoi(argv[3]);
    }

    printf("%-10s%-32s%-14s\n",
           "NODE_ID", "NODE_NAME", "ROLE");

    uint16 master;
    if (cms_get_master_node(&master) != GS_SUCCESS) {
        master = -1;
    }

    const cms_gcc_t* gcc = cms_get_read_gcc();
    for (uint32 node_id = 0; node_id < gcc->head.node_count; node_id++) {
        const cms_node_def_t* node_def = &gcc->node_def[node_id];
        if (node_def->magic != CMS_GCC_NODE_MAGIC ||
           (sp_node_id != CMS_MAX_NODE_COUNT && node_id != sp_node_id)) {
            continue;
        }
        printf("%7u   %-32s%-14s\n",
            node_id, node_def->name, master == node_id ? "server" : "agent");
    }

    cms_release_gcc(&gcc);
    return GS_SUCCESS;
}

int32 cms_stat_server(int32 argc, char* argv[])
{
    cms_tool_msg_req_get_srv_stat_t req = {0};
    cms_tool_msg_res_get_srv_stat_t res = {0};
    char err_info[CMS_INFO_BUFFER_SIZE] = {0};
    uint16 sp_node_id = CMS_MAX_NODE_COUNT;
    if (argc == 4) {
        if (cm_str2uint16(argv[3], &sp_node_id) != GS_SUCCESS) {
            printf("node_id is invalid, get server stat failed.\n");
            return GS_SUCCESS;
        }
        if (sp_node_id >= CMS_MAX_NODE_COUNT) {
            printf("node_id is out of range, get server stat failed.\n");
            return GS_SUCCESS;
        }
    }

    GS_RETURN_IFERR(cms_load_gcc());
    const cms_gcc_t* gcc = cms_get_read_gcc();
    req.head.msg_type = CMS_TOOL_MSG_REQ_GET_SRV_STAT;
    req.head.msg_size = sizeof(cms_tool_msg_req_get_srv_stat_t);
    req.head.msg_version = CMS_MSG_VERSION;

    printf("%-10s%-10s%-10s%-10s%-12s\n", "NODE_ID", "SRV_READY", "SEND_QUE", "RECV_QUE", "TIME_GAP(ms)");
    for (uint32 node_id = 0; node_id < gcc->head.node_count; node_id++) {
        if (gcc->node_def[node_id].magic != CMS_GCC_NODE_MAGIC ||
            (sp_node_id != CMS_MAX_NODE_COUNT && node_id != sp_node_id)) {
            continue;
        }
        req.target_node = node_id;
        if (cms_send_to_server(&req.head, &res.head, sizeof(cms_tool_msg_res_get_srv_stat_t),
            CMS_CLIENT_REQUEST_TIMEOUT, err_info) != GS_SUCCESS || res.result != GS_SUCCESS) {
            continue;
        }

        printf("%-10u%-10s%-10llu%-10llu%-12lld\n", node_id, res.server_stat_ready == GS_TRUE ? "TRUE" : "FALSE",
            res.send_que_count, res.recv_que_count, res.cluster_gap / 1000);
    }
    cms_release_gcc(&gcc);
    return GS_SUCCESS;
}

void cms_print_iostat_inner(cms_tool_msg_res_iostat_t *res, char *msg_name, uint8 msg_type)
{
    if ((res->detail[msg_type].back_good + res->detail[msg_type].back_bad) != 0) {
        printf("%-35s  %-12lld  %-12lld  %-12lld  %-20lld  "
            "%-20lld  %-20lld  %-20lld \n",
            msg_name, res->detail[msg_type].start, res->detail[msg_type].back_good, res->detail[msg_type].back_bad,
            res->detail[msg_type].total_time / (res->detail[msg_type].back_good + res->detail[msg_type].back_bad),
            res->detail[msg_type].max_time, res->detail[msg_type].min_time, res->detail[msg_type].total_time);
    } else {
        printf("%-35s  %-12lld  %-12lld  %-12lld  %-20lld  "
            "%-20lld  %-20lld  %-20lld \n",
            msg_name, res->detail[msg_type].start, res->detail[msg_type].back_good, res->detail[msg_type].back_bad,
            res->detail[msg_type].total_time / (res->detail[msg_type].back_good + res->detail[msg_type].back_bad + 1),
            res->detail[msg_type].max_time, res->detail[msg_type].min_time, res->detail[msg_type].total_time);
    }
}

void cms_print_iostat(cms_tool_msg_res_iostat_t *res_msg, uint8 msg_type)
{
    cms_print_iostat_inner(res_msg, g_cms_iostat_type[msg_type].msg_name, msg_type);
}

void cms_print_index(void)
{
    char *msg_type = "MSG_TYPE";
    char *msg_all = "MSG_ALL";
    char *back_good = "BACK_GOOD";
    char *back_bad = "BACK_BAD";
    char *avg_us = "AVG_US";
    char *max_us = "MAX_US";
    char *min_us = "MIN_US";
    char *total_us = "TOTAL_US";
    printf("%-35s  %-12s  %-12s  %-12s  %-20s  %-20s  %-20s  %-20s \n", msg_type, msg_all, back_good, back_bad, avg_us,
        max_us, min_us, total_us);
}

void cms_print_disk_iostat(cms_tool_msg_res_disk_iostat_t *res_msg)
{
    if (res_msg->detail.disk_io_slow == GS_TRUE) {
        printf("%llu\n", res_msg->detail.avg_ms);
    } else {
        printf("0\n");
    }
}

int32 cms_iostat(int32 argc, char *argv[])
{
    status_t ret = GS_SUCCESS;
    cms_tool_msg_req_iostat_t req = {0};
    cms_tool_msg_res_iostat_t res = {0};
    char err_info[CMS_INFO_BUFFER_SIZE] = {0};

    req.head.msg_type = CMS_TOOL_MSG_REQ_GET_IOSTAT;
    req.head.msg_size = sizeof(cms_tool_msg_req_iostat_t);
    req.head.msg_version = CMS_MSG_VERSION;
    req.head.msg_seq = cms_uds_cli_get_msg_seq();
    ret = cms_send_to_server(&req.head, &res.head, sizeof(cms_tool_msg_res_iostat_t),
        CMS_CLIENT_REQUEST_TIMEOUT, err_info);
    if (ret != GS_SUCCESS) {
        printf("%s, iostat failed.\n", err_info);
        return GS_ERROR;
    }
    if (res.result != GS_SUCCESS) {
        printf("get iostat failed.\n");
        return GS_ERROR;
    }

    cms_print_index();
    for (uint8 i = 0; i < CMS_IO_COUNT; i++) {
        cms_print_iostat(&res, i);
    }
    return GS_SUCCESS;
}

int32 cms_iostat_reset(int32 argc, char *argv[])
{
    status_t ret = GS_SUCCESS;
    cms_tool_msg_req_reset_iostat_t req = {0};
    cms_tool_msg_res_reset_iostat_t res = {0};
    char err_info[CMS_INFO_BUFFER_SIZE] = {0};

    req.head.msg_type = CMS_TOOL_MSG_REQ_RESET_IOSTAT;
    req.head.msg_size = sizeof(cms_tool_msg_req_reset_iostat_t);
    req.head.msg_version = CMS_MSG_VERSION;
    req.head.msg_seq = cms_uds_cli_get_msg_seq();
    ret = cms_send_to_server(&req.head, &res.head, sizeof(cms_tool_msg_res_reset_iostat_t),
        CMS_CLIENT_REQUEST_TIMEOUT, err_info);
    if (ret != GS_SUCCESS) {
        printf("%s, reset iostat failed.\n", err_info);
        return GS_ERROR;
    }
    if (res.result != GS_SUCCESS) {
        printf("reset iostat failed.\n");
        return GS_ERROR;
    }
    printf("reset cms iostat success.\n");
    return GS_SUCCESS;
}

int32 cms_local_disk_iostat(int32 argc, char *argv[])
{
    status_t ret = GS_SUCCESS;
    cms_tool_msg_req_disk_iostat_t req = {0};
    cms_tool_msg_res_disk_iostat_t res = {0};
    char err_info[CMS_INFO_BUFFER_SIZE] = {0};
    req.head.msg_type = CMS_TOOL_MSG_REQ_GET_DISK_IOSTAT;
    req.head.msg_size = sizeof(cms_tool_msg_req_disk_iostat_t);
    req.head.msg_version = CMS_MSG_VERSION;
    req.head.msg_seq = cms_uds_cli_get_msg_seq();
    ret = cms_send_to_server(&req.head, &res.head, sizeof(cms_tool_msg_res_disk_iostat_t),
        CMS_CLIENT_REQUEST_TIMEOUT, err_info);
    if (ret != GS_SUCCESS) {
        printf("%s, disk iostat failed.\n", err_info);
        return GS_ERROR;
    }
    if (res.result != GS_SUCCESS) {
        printf("get disk iostat failed.\n");
        return GS_ERROR;
    }
    cms_print_disk_iostat(&res);
    return GS_SUCCESS;
}

status_t cms_cmd_proc_start_res(const char* name, cms_msg_scope_t scope, uint16 target_node, uint32 timeout_ms)
{
    CMS_LOG_INF("start resource, name:%s, target_node:%u", name, target_node);
    status_t ret = GS_SUCCESS;
    errno_t err = EOK;
    char err_info[CMS_INFO_BUFFER_SIZE] = {0};
    cms_tool_msg_req_start_res_t req = {0};
    cms_tool_msg_res_start_res_t res = {0};

    req.head.msg_type = CMS_TOOL_MSG_REQ_START_RES;
    req.head.msg_size = sizeof(cms_tool_msg_req_start_res_t);
    req.head.msg_version = CMS_MSG_VERSION;
    req.head.msg_seq = cms_uds_cli_get_msg_seq();
    req.head.src_msg_seq = 0;
    req.scope = scope;
    req.target_node = target_node;
    req.timeout = timeout_ms;
    err = strcpy_sp(req.name, CMS_NAME_BUFFER_SIZE, name);
    if (err != EOK) {
        printf("strcpy name failed, start resource failed.\n");
        return GS_ERROR;
    }

    ret = cms_send_to_server(&req.head, &res.head, sizeof(cms_tool_msg_res_start_res_t),
        timeout_ms, err_info);
    if (ret != GS_SUCCESS) {
        printf("%s, start resource failed.\n", err_info);
        return ret;
    }
    if (res.result != GS_SUCCESS) {
        printf("%s, start resource failed.\n", res.info);
        return GS_ERROR;
    }
    printf("start resource succeed.\n");
    return GS_SUCCESS;
}

int32 cms_res_start_cmd(int32 argc, char *argv[])
{
    uint32 timeout = CMS_CMD_START_ALL_TMOUT_MS;
    cms_res_t res = {0};
    const char* name = argv[3];
    
    uint32 name_len = (uint32)strlen(name);
    if (name_len > CMS_MAX_NAME_LEN) {
        printf("resource name is too long (maximum %u).\n", CMS_MAX_NAME_LEN);
        CMS_LOG_ERR("resource name is too long (maximum %u).", CMS_MAX_NAME_LEN);
        return GS_ERROR;
    }
    if (!cms_check_name_valid(name, name_len)) {
        printf("resource name is invalid.\n");
        CMS_LOG_ERR("resource name is invalid.");
        return GS_ERROR;
    }

    // param 5 is the user-specified timeout period
    if (argc == 5) {
        // Parameter 4 indicates the timeout period set by the user.
        if (cm_str2uint32(argv[4], &timeout) != GS_SUCCESS) {
            printf("timeout value is invalid.\n");
            return GS_ERROR;
        }
    }

    if (cms_load_gcc() != GS_SUCCESS) {
        printf("cms load gcc failed.\n");
        CMS_LOG_INF("cms load gcc failed.");
        return GS_ERROR;
    }
    if (cms_get_res_by_name(name, &res) != GS_SUCCESS) {
        printf("resource does not exist.\n");
        return GS_ERROR;
    }

    status_t ret = cms_cmd_proc_start_res(name, CMS_MSG_SCOPE_CLUSTER, GS_MAX_UINT16, timeout);
    if (ret == GS_ERROR) {
        CMS_LOG_ERR("start resource %s failed.\n", name);
    }
    return ret;
}

int32 cms_res_start_with_node(int32 argc, char* argv[])
{
    uint16 node_id = -1;
    cms_res_t res = {0};
    cms_res_stat_t res_stat = {0};
    const char* name = argv[3];

    uint32 name_len = (uint32)strlen(name);
    if (name_len > CMS_MAX_NAME_LEN) {
        printf("resource name is too long (maximum %u).\n", CMS_MAX_NAME_LEN);
        return GS_ERROR;
    }
    
    if (!cms_check_name_valid(name, name_len)) {
        printf("resource name is invalid.\n");
        return GS_ERROR;
    }

    if (cm_str2uint16(argv[5], &node_id) != GS_SUCCESS) {
        printf("node id is invalid.\n");
        return GS_ERROR;
    }

    if (cms_load_gcc() != GS_SUCCESS) {
        printf("cms load gcc failed.\n");
        return GS_ERROR;
    }

    if (cms_get_res_by_name(name, &res) != GS_SUCCESS) {
        printf("resource does not exist.\n");
        return GS_ERROR;
    }
    
    GS_RETURN_IFERR(cms_instance_init());
    if (get_res_stat(node_id, res.res_id, &res_stat) != GS_SUCCESS) {
        printf("get resource stat failed.\n");
        return GS_ERROR;
    }
    
    if (res_stat.cur_stat == CMS_RES_ONLINE) {
        if (res_stat.work_stat == RC_JOINING) {
            printf("resource is being started.\n");
            return GS_SUCCESS;
        }
        if (res_stat.work_stat == RC_JOINED) {
            printf("resource has been started already.\n");
            return GS_SUCCESS;
        }
    }

    return cms_cmd_proc_start_res(name, CMS_MSG_SCOPE_NODE, node_id, CMS_CMD_START_ALL_TMOUT_MS);
}

status_t cms_cmd_proc_stop_res(const char* name, cms_msg_scope_t scope, uint16 target_node)
{
    CMS_LOG_INF("start stop resource, name:%s, target_node:%u", name, target_node);
    status_t ret = GS_SUCCESS;
    errno_t err = EOK;
    char err_info[CMS_INFO_BUFFER_SIZE] = {0};
    cms_tool_msg_req_stop_res_t req = {0};
    cms_tool_msg_res_stop_res_t res = {0};

    req.head.msg_type = CMS_TOOL_MSG_REQ_STOP_RES;
    req.head.msg_size = sizeof(cms_tool_msg_req_stop_res_t);
    req.head.msg_version = CMS_MSG_VERSION;
    req.head.msg_seq = cms_uds_cli_get_msg_seq();
    req.head.src_msg_seq = 0;
    req.scope = scope;
    req.target_node = target_node;
    err = strcpy_sp(req.name, CMS_NAME_BUFFER_SIZE, name);
    if (err != EOK) {
        printf("strcpy name failed, stop resource failed.\n");
        return GS_ERROR;
    }

    ret = cms_send_to_server(&req.head, &res.head, sizeof(cms_tool_msg_res_stop_res_t),
        CMS_CLIENT_REQUEST_TIMEOUT, err_info);
    if (ret != GS_SUCCESS) {
        printf("%s, stop resource failed.\n", err_info);
        return ret;
    }
    if (res.result != GS_SUCCESS) {
        printf("%s, stop resource failed.\n", res.info);
        return GS_ERROR;
    }
    printf("stop resource succeed.\n");
    CMS_LOG_INF("stop resource succeed");
    return GS_SUCCESS;
}

int32 cms_res_stop_cmd(int32 argc, char* argv[])
{
    cms_res_t res = {0};
    const char* name = argv[3];
    uint32 name_len = (uint32)strlen(name);
    if (name_len > CMS_MAX_NAME_LEN) {
        printf("resource name is too long (maximum %u), stop resource failed.\n", CMS_MAX_NAME_LEN);
        return GS_SUCCESS;
    }

    if (!cms_check_name_valid(name, name_len)) {
        printf("resource name is invalid, stop resource failed.\n");
        return GS_SUCCESS;
    }

    if (cms_load_gcc() != GS_SUCCESS) {
        printf("cms load gcc failed.\n");
        return GS_SUCCESS;
    }
    if (cms_get_res_by_name(name, &res) != GS_SUCCESS) {
        printf("resource does not exist.\n");
        return GS_ERROR;
    }
    
    return cms_cmd_proc_stop_res(name, CMS_MSG_SCOPE_CLUSTER, GS_MAX_UINT16);
}

int32 cms_res_stop_with_node(int32 argc, char* argv[])
{
    uint16 node_id = -1;
    cms_res_t res = {0};
    cms_res_stat_t res_stat = {0};
    const char* name = argv[3];

    uint32 name_len = (uint32)strlen(name);
    if (name_len > CMS_MAX_NAME_LEN) {
        printf("resource name is too long (maximum %u).\n", CMS_MAX_NAME_LEN);
        return GS_ERROR;
    }
    
    if (!cms_check_name_valid(name, name_len)) {
        printf("resource name is invalid.\n");
        return GS_ERROR;
    }

    if (cm_str2uint16(argv[5], &node_id) != GS_SUCCESS) {
        printf("node id is invalid.\n");
        return GS_ERROR;
    }

    if (cms_load_gcc() != GS_SUCCESS) {
        printf("cms load gcc failed.\n");
        return GS_ERROR;
    }

    if (cms_get_res_by_name(name, &res) != GS_SUCCESS) {
        printf("resource does not exist.\n");
        return GS_ERROR;
    }

    GS_RETURN_IFERR(cms_instance_init());
    if (get_res_stat(node_id, res.res_id, &res_stat) != GS_SUCCESS) {
        printf("get resource stat failed.\n");
        return GS_ERROR;
    }
    
    if (res_stat.cur_stat == CMS_RES_OFFLINE && res_stat.work_stat == RC_JOINING) {
        printf("resource has been already stopped.\n");
        return GS_SUCCESS;
    }

    return cms_cmd_proc_stop_res(name, CMS_MSG_SCOPE_NODE, node_id);
}

// This function is reserved for optimizing stop server
status_t cms_stop_server(char* err_info)
{
    CMS_LOG_INF("start stop server");
    status_t ret = GS_SUCCESS;
    errno_t err = EOK;
    cms_tool_msg_req_stop_srv_t req = {0};
    cms_tool_msg_res_stop_srv_t res = {0};
    req.head.msg_type = CMS_TOOL_MSG_REQ_STOP_SRV;
    req.head.msg_size = sizeof(cms_tool_msg_req_stop_srv_t);
    req.head.msg_version = CMS_MSG_VERSION;
    req.head.msg_seq = cms_uds_cli_get_msg_seq();
    req.head.src_msg_seq = 0;

    ret = cms_send_to_server(&req.head, &res.head, sizeof(cms_tool_msg_res_stop_srv_t),
        CMS_CLIENT_REQUEST_TIMEOUT, err_info);
    if (ret == GS_SUCCESS && res.result != GS_SUCCESS) {
        err = strcpy_sp(err_info, CMS_MAX_INFO_LEN, res.info);
        cms_securec_check(err);
        return GS_ERROR;
    }
    CMS_LOG_INF("start stop server success");
    return ret;
}

int32 cms_server_stop(int32 argc, char* argv[])
{
    status_t ret = GS_SUCCESS;
    bool32 is_start = GS_FALSE;

    ret = cms_check_server_status(&is_start);
    if (ret != GS_SUCCESS) {
        printf("get cms server status failed.\n");
        return ret;
    }

    if (!is_start) {
        printf("cms server is not start.\n");
        return GS_SUCCESS;
    }

    ret = system("ps -ef | grep 'cms server -start' | grep -v grep | awk '{print $2}' | xargs kill -9 2>/dev/null");
    if (ret != 0) {
        printf("stop cms server failed.\n");
        return GS_ERROR;
    }
    printf("stop cms server succeed.\n");
    return GS_SUCCESS;
}

status_t cms_add_res_local(cms_res_desc_t* cms_res_desc)
{
    status_t ret = GS_SUCCESS;
    const char *err_msg = NULL;
    errno_t err = EOK;
    int32 err_code = 0;
    if (cms_lock_gcc_disk() != GS_SUCCESS) {
        CMS_LOG_ERR("cms lock gcc disk failed");
        printf("cms lock gcc disk failed. \n");
        return GS_ERROR;
    }
    ret = cms_add_res(cms_res_desc->name, cms_res_desc->type, cms_res_desc->group, cms_res_desc->attrs);
    cms_unlock_gcc_disk();
    if (ret == GS_ERROR) {
        cm_get_error(&err_code, &err_msg, NULL);
        err = strcpy_sp(cms_res_desc->err_info, CMS_INFO_BUFFER_SIZE, err_msg);
        cms_securec_check(err);
        return ret;
    }
    return GS_SUCCESS;
}

status_t cms_add_res_server(cms_res_desc_t* cms_res_desc)
{
    status_t ret = GS_SUCCESS;
    errno_t err = EOK;
    cms_tool_msg_req_add_res_t req = {0};
    cms_tool_msg_res_add_res_t res = {0};

    req.head.msg_type = CMS_TOOL_MSG_REQ_ADD_RES;
    req.head.msg_size = sizeof(cms_tool_msg_req_add_res_t);
    req.head.msg_version = CMS_MSG_VERSION;
    req.head.msg_seq = cms_uds_cli_get_msg_seq();
    req.head.src_msg_seq = 0;
    err = strcpy_sp(req.name, CMS_NAME_BUFFER_SIZE, cms_res_desc->name);
    if (err != EOK) {
        err = strcpy_sp(cms_res_desc->err_info, CMS_INFO_BUFFER_SIZE, "strcpy name failed");
        cms_securec_check(err);
        return GS_ERROR;
    }
    err = strcpy_sp(req.type, CMS_NAME_BUFFER_SIZE, cms_res_desc->type);
    if (err != EOK) {
        err = strcpy_sp(cms_res_desc->err_info, CMS_INFO_BUFFER_SIZE, "strcpy type failed");
        cms_securec_check(err);
        return GS_ERROR;
    }
    err = strcpy_sp(req.group, CMS_NAME_BUFFER_SIZE, cms_res_desc->group);
    if (err != EOK) {
        err = strcpy_sp(cms_res_desc->err_info, CMS_INFO_BUFFER_SIZE, "strcpy group failed");
        cms_securec_check(err);
        return GS_ERROR;
    }
    err = strcpy_sp(req.attrs, CMS_RES_ATTRS_BUFFER_SIZE, cms_res_desc->attrs);
    if (err != EOK) {
        err = strcpy_sp(cms_res_desc->err_info, CMS_INFO_BUFFER_SIZE, "strcpy attrs failed");
        cms_securec_check(err);
        return GS_ERROR;
    }
    ret = cms_send_to_server(&req.head, &res.head, sizeof(cms_tool_msg_res_add_res_t),
        CMS_CLIENT_REQUEST_TIMEOUT, cms_res_desc->err_info);
    if (ret == GS_SUCCESS && res.result != GS_SUCCESS) {
        err = strcpy_sp(cms_res_desc->err_info, CMS_INFO_BUFFER_SIZE, res.info);
        cms_securec_check(err);
        return GS_ERROR;
    }
    return ret;
}

int32 cms_cmd_proc_add_res(char* name, char* type, char* group, char* attrs)
{
    CMS_LOG_INF("start add resource, name:%s, type:%s, group:%s, attrs:%s", name, type, group, attrs);
    cms_disk_lock_t master_lock = {0};
    status_t ret = GS_SUCCESS;
    char err_info[CMS_INFO_BUFFER_SIZE] = {0};

    if (cms_check_master_lock_status(&master_lock) != GS_SUCCESS) {
        cms_disk_lock_destroy(&master_lock);
        printf("check master_lock failed, add resource failed.\n");
        return GS_SUCCESS;
    }

    // inst_id equals -1 means that no master is currently aviliable
    // when the master is faulty, inst_id equals old_master_id util new master emerges
    if (master_lock.inst_id == -1) {
        cms_res_desc_t cms_res_desc = { name, type, group, attrs, err_info };
        ret = cms_add_res_local(&cms_res_desc);
        if (ret != GS_SUCCESS) {
            printf("%s, add resource failed.\n", err_info);
            cms_disk_lock_destroy(&master_lock);
            return ret;
        }
    } else {
        cms_res_desc_t cms_res_desc = { name, type, group, attrs, err_info };
        ret = cms_add_res_server(&cms_res_desc);
        if (ret != GS_SUCCESS) {
            printf("%s, add resource failed.\n", err_info);
            cms_disk_lock_destroy(&master_lock);
            return ret;
        }
    }
    printf("add resource succeed.\n");
    cms_disk_lock_destroy(&master_lock);
    CMS_LOG_INF("add resource succeed");
    return GS_SUCCESS;
}

int32 cms_res_add(int32 argc, char* argv[])
{
    char* name = argv[3];
    char* type = argv[5];
    char* attrs = argv[7];
    uint32 name_len = (uint32)strlen(name);
    uint32 type_len = (uint32)strlen(type);

    if (name_len > CMS_MAX_NAME_LEN) {
        printf("resource name is too long (maximum %u), add resource failed.\n", CMS_MAX_NAME_LEN);
        return GS_SUCCESS;
    }

    if (!cms_check_name_valid(name, name_len)) {
        printf("resource name is invalid, add resource failed.\n");
        return GS_SUCCESS;
    }

    if (type_len > CMS_MAX_NAME_LEN) {
        printf("resource type name is too long (maximum %u), add resource failed.\n", CMS_MAX_NAME_LEN);
        return GS_SUCCESS;
    }

    if (!cms_check_name_valid(type, type_len)) {
        printf("resource type name is invalid, add resource failed.\n");
        return GS_SUCCESS;
    }

    if ((uint32)strlen(attrs) > CMS_MAX_RES_ATTRS_LEN) {
        printf("attribute text is too long (maximum %u), add resource failed.\n", CMS_MAX_RES_ATTRS_LEN);
        return GS_SUCCESS;
    }

    return cms_cmd_proc_add_res(name, type, "default", attrs);
}

int32 cms_res_add_without_attr(int32 argc, char* argv[])
{
    char* name = argv[3];
    char* type = argv[5];
    uint32 name_len = (uint32)strlen(name);
    uint32 type_len = (uint32)strlen(type);

    if (name_len > CMS_MAX_NAME_LEN) {
        printf("resource name is too long (maximum %u), add resource failed.\n", CMS_MAX_NAME_LEN);
        return GS_SUCCESS;
    }

    if (!cms_check_name_valid(name, name_len)) {
        printf("node name is invalid, add resource failed.\n");
        return GS_SUCCESS;
    }

    if (type_len > CMS_MAX_NAME_LEN) {
        printf("resource type name is too long (maximum %u), add resource failed.\n", CMS_MAX_NAME_LEN);
        return GS_SUCCESS;
    }

    if (!cms_check_name_valid(type, type_len)) {
        printf("resource type name is invalid, add resource failed.\n");
        return GS_SUCCESS;
    }

    return cms_cmd_proc_add_res(name, type, "default", "");
}

int32 cms_res_add_with_grp(int32 argc, char* argv[])
{
    char* name = argv[3];
    char* type = argv[5];
    char* group = argv[7];
    char* attrs = argv[9];
    uint32 name_len = (uint32)strlen(name);
    uint32 type_len = (uint32)strlen(type);
    uint32 group_len = (uint32)strlen(group);
    if (name_len > CMS_MAX_NAME_LEN) {
        printf("resource name is too long (maximum %u), add resource failed.\n", CMS_MAX_NAME_LEN);
        return GS_SUCCESS;
    }
    if (!cms_check_name_valid(name, name_len)) {
        printf("resource name is invalid, add res failed.\n");
        return GS_SUCCESS;
    }

    if (type_len > CMS_MAX_NAME_LEN) {
        printf("resource type name is too long (maximum %u), add resource failed.\n", CMS_MAX_NAME_LEN);
        return GS_SUCCESS;
    }
    if (!cms_check_name_valid(type, type_len)) {
        printf("resource type name is invalid, add resource failed.\n");
        return GS_SUCCESS;
    }

    if (group_len > CMS_MAX_NAME_LEN) {
        printf("resource group name is too long (maximum %u), add resource failed.\n", CMS_MAX_NAME_LEN);
        return GS_SUCCESS;
    }

    if (!cms_check_name_valid(group, group_len)) {
        printf("resource group name is invalid, add resource failed.\n");
        return GS_SUCCESS;
    }

    if ((uint32)strlen(attrs) > CMS_MAX_RES_ATTRS_LEN) {
        printf("attribute text is too long (maximum %u), add resource failed.\n", CMS_MAX_RES_ATTRS_LEN);
        return GS_SUCCESS;
    }

    return cms_cmd_proc_add_res(name, type, group, attrs);
}

int32 cms_res_add_with_grp_without_attr(int32 argc, char* argv[])
{
    char* name = argv[3];
    char* type = argv[5];
    char* group = argv[7];
    uint32 name_len = (uint32)strlen(name);
    uint32 type_len = (uint32)strlen(type);
    uint32 group_len = (uint32)strlen(group);

    if (name_len > CMS_MAX_NAME_LEN) {
        printf("resource name is too long (maximum %u), add resource failed.\n", CMS_MAX_NAME_LEN);
        return GS_SUCCESS;
    }

    if (!cms_check_name_valid(name, name_len)) {
        printf("node name is invalid, add res failed.\n");
        return GS_SUCCESS;
    }

    if (type_len > CMS_MAX_NAME_LEN) {
        printf("resource type name is too long (maximum %u), add resource failed.\n", CMS_MAX_NAME_LEN);
        return GS_SUCCESS;
    }

    if (!cms_check_name_valid(type, type_len)) {
        printf("resource type name is invalid, add resource failed.\n");
        return GS_SUCCESS;
    }

    if (group_len > CMS_MAX_NAME_LEN) {
        printf("resource group name is too long (maximum %u), add resource failed.\n", CMS_MAX_NAME_LEN);
        return GS_SUCCESS;
    }

    if (!cms_check_name_valid(group, group_len)) {
        printf("resource group name is invalid, add resource failed.\n");
        return GS_SUCCESS;
    }

    return cms_cmd_proc_add_res(name, type, group, "");
}

status_t cms_edit_res_local(char* name, char* attrs, char* err_info, uint32 err_len)
{
    status_t ret = GS_SUCCESS;
    const char* err_msg = NULL;
    int32 err_code = 0;
    errno_t err = EOK;
    if (cms_lock_gcc_disk() != GS_SUCCESS) {
        CMS_LOG_ERR("cms lock gcc disk failed");
        printf("cms lock gcc disk failed. \n");
        return GS_ERROR;
    }
    ret = cms_edit_res(name, attrs);
    cms_unlock_gcc_disk();
    if (ret == GS_ERROR) {
        cm_get_error(&err_code, &err_msg, NULL);
        err = strcpy_sp(err_info, err_len, err_msg);
        cms_securec_check(err);
        return ret;
    }
    return GS_SUCCESS;
}

status_t cms_edit_res_server(char* name, char* attrs, char* err_info, uint32 err_len)
{
    status_t ret = GS_SUCCESS;
    errno_t err = EOK;
    cms_tool_msg_req_edit_res_t req = {0};
    cms_tool_msg_res_edit_res_t res = {0};

    req.head.msg_type = CMS_TOOL_MSG_REQ_EDIT_RES;
    req.head.msg_size = sizeof(cms_tool_msg_req_edit_res_t);
    req.head.msg_version = CMS_MSG_VERSION;
    req.head.msg_seq = cms_uds_cli_get_msg_seq();
    req.head.src_msg_seq = 0;
    err = strcpy_sp(req.name, CMS_NAME_BUFFER_SIZE, name);
    if (err != EOK) {
        err = strcpy_sp(err_info, err_len, "strcpy name failed");
        cms_securec_check(err);
        return GS_ERROR;
    }
    err = strcpy_sp(req.attrs, CMS_RES_ATTRS_BUFFER_SIZE, attrs);
    if (err != EOK) {
        err = strcpy_sp(err_info, err_len, "strcpy attrs failed");
        cms_securec_check(err);
        return GS_ERROR;
    }
    ret = cms_send_to_server(&req.head, &res.head, sizeof(cms_tool_msg_res_edit_res_t),
        CMS_CLIENT_REQUEST_TIMEOUT, err_info);
    if (ret == GS_SUCCESS && res.result != GS_SUCCESS) {
        err = strcpy_sp(err_info, err_len, res.info);
        cms_securec_check(err);
        return GS_ERROR;
    }
    return ret;
}

int32 cms_cmd_proc_edit_res(char* name, char* attrs)
{
    CMS_LOG_INF("start modify resource, name:%s, attrs:%s", name, attrs);
    status_t ret = GS_SUCCESS;
    char err_info[CMS_INFO_BUFFER_SIZE] = {0};
    cms_disk_lock_t master_lock = {0};

    if (cms_check_master_lock_status(&master_lock) != GS_SUCCESS) {
        cms_disk_lock_destroy(&master_lock);
        printf("check master_lock failed, modify resource failed.\n");
        return GS_SUCCESS;
    }

    if (master_lock.inst_id == -1) {
        ret = cms_edit_res_local(name, attrs, err_info, CMS_INFO_BUFFER_SIZE);
        if (ret != GS_SUCCESS) {
            cms_disk_lock_destroy(&master_lock);
            printf("%s, modify resource failed.\n", err_info);
            return ret;
        }
    } else {
        ret = cms_edit_res_server(name, attrs, err_info, CMS_INFO_BUFFER_SIZE);
        if (ret != GS_SUCCESS) {
            cms_disk_lock_destroy(&master_lock);
            printf("%s, modify resource failed.\n", err_info);
            return ret;
        }
    }
    cms_disk_lock_destroy(&master_lock);
    printf("modify resource succeed.\n");
    CMS_LOG_INF("modify resource succeed");
    return GS_SUCCESS;
}

int32 cms_res_edit(int32 argc, char* argv[])
{
    char* name = argv[3];
    char* attrs = argv[5];
    uint32 name_len = (uint32)strlen(name);
    if (name_len > CMS_MAX_NAME_LEN) {
        printf("resource name is too long (maximum %u), modify resource failed.\n", CMS_MAX_NAME_LEN);
        return GS_SUCCESS;
    }

    if (!cms_check_name_valid(name, name_len)) {
        printf("resource name is invalid, modify resource failed.\n");
        return GS_SUCCESS;
    }

    if ((uint32)strlen(attrs) > CMS_MAX_RES_ATTRS_LEN) {
        printf("attribute text is too long (maximum %u), modify resource failed.\n", CMS_MAX_RES_ATTRS_LEN);
        return GS_SUCCESS;
    }

    return cms_cmd_proc_edit_res(name, attrs);
}

status_t cms_del_res_local(char* name, char* err_info, uint32 err_len)
{
    status_t ret = GS_SUCCESS;
    const char* err_msg = NULL;
    int32 err_code = 0;
    errno_t err = EOK;

    if (cms_lock_gcc_disk() != GS_SUCCESS) {
        CMS_LOG_ERR("cms lock gcc disk failed");
        printf("cms lock gcc disk failed. \n");
        return GS_ERROR;
    }
    ret = cms_del_res(name);
    cms_unlock_gcc_disk();
    if (ret != GS_SUCCESS) {
        cm_get_error(&err_code, &err_msg, NULL);
        err = strcpy_sp(err_info, err_len, err_msg);
        cms_securec_check(err);
        return ret;
    }
    return GS_SUCCESS;
}

status_t cms_del_res_server(char* name, char* err_info, uint32 err_len)
{
    status_t ret = GS_SUCCESS;
    errno_t err = EOK;
    cms_tool_msg_req_del_res_t req = {0};
    cms_tool_msg_res_del_res_t res = {0};

    req.head.msg_type = CMS_TOOL_MSG_REQ_DEL_RES;
    req.head.msg_size = sizeof(cms_tool_msg_req_del_res_t);
    req.head.msg_version = CMS_MSG_VERSION;
    req.head.msg_seq = cms_uds_cli_get_msg_seq();
    req.head.src_msg_seq = 0;
    err = strcpy_sp(req.name, CMS_NAME_BUFFER_SIZE, name);
    if (err != EOK) {
        err = strcpy_sp(err_info, err_len, "strcpy name failed");
        cms_securec_check(err);
        return GS_ERROR;
    }
    ret = cms_send_to_server(&req.head, &res.head, sizeof(cms_tool_msg_res_del_res_t),
        CMS_CLIENT_REQUEST_TIMEOUT, err_info);
    if (ret == GS_SUCCESS && res.result != GS_SUCCESS) {
        err = strcpy_sp(err_info, err_len, res.info);
        cms_securec_check(err);
        return GS_ERROR;
    }
    return ret;
}

static int32 cms_cmd_proc_del_res(char* name)
{
    CMS_LOG_INF("start delete resource, name:%s", name);
    status_t ret = GS_SUCCESS;
    char err_info[CMS_INFO_BUFFER_SIZE] = {0};
    cms_disk_lock_t master_lock = {0};

    if (cms_check_master_lock_status(&master_lock) != GS_SUCCESS) {
        cms_disk_lock_destroy(&master_lock);
        printf("check master_lock failed, delete resource failed.\n");
        return GS_SUCCESS;
    }

    if (master_lock.inst_id == -1) {
        ret = cms_del_res_local(name, err_info, CMS_INFO_BUFFER_SIZE);
        if (ret != GS_SUCCESS) {
            cms_disk_lock_destroy(&master_lock);
            printf("%s, delete resource failed.\n", err_info);
            return ret;
        }
    } else {
        ret = cms_del_res_server(name, err_info, CMS_INFO_BUFFER_SIZE);
        if (ret != GS_SUCCESS) {
            cms_disk_lock_destroy(&master_lock);
            printf("%s, delete resource failed.\n", err_info);
            return ret;
        }
    }
    cms_disk_lock_destroy(&master_lock);
    printf("delete resource succeed.\n");
    CMS_LOG_INF("delete resource succeed");
    return GS_SUCCESS;
}

int32 cms_res_del(int32 argc, char* argv[])
{
    char* name = argv[3];
    uint32 name_len = (uint32)strlen(name);
    if (name_len > CMS_MAX_NAME_LEN) {
        printf("resource name is too long (maximum %u), delete resource failed.\n", CMS_MAX_NAME_LEN);
        return GS_SUCCESS;
    }

    if (!cms_check_name_valid(name, name_len)) {
        printf("resource name is invalid, delete resource failed.\n");
        return GS_SUCCESS;
    }
    
    return cms_cmd_proc_del_res(name);
}

status_t cms_add_resgrp_local(char* group, char* err_info, uint32 err_len)
{
    status_t ret = GS_SUCCESS;
    const char* err_msg = NULL;
    int32 err_code = 0;
    errno_t err = EOK;
    if (cms_lock_gcc_disk() != GS_SUCCESS) {
        CMS_LOG_ERR("cms lock gcc disk failed");
        printf("cms lock gcc disk failed. \n");
        return GS_ERROR;
    }
    ret = cms_add_resgrp(group);
    cms_unlock_gcc_disk();
    if (ret != GS_SUCCESS) {
        cm_get_error(&err_code, &err_msg, NULL);
        err = strcpy_sp(err_info, err_len, err_msg);
        cms_securec_check(err);
        return ret;
    }
    return GS_SUCCESS;
}

status_t cms_add_resgrp_server(char* group, char* err_info, uint32 err_len)
{
    status_t ret = GS_SUCCESS;
    errno_t err = EOK;
    cms_tool_msg_req_add_grp_t req = {0};
    cms_tool_msg_res_add_grp_t res = {0};

    req.head.msg_type = CMS_TOOL_MSG_REQ_ADD_GRP;
    req.head.msg_size = sizeof(cms_tool_msg_req_add_grp_t);
    req.head.msg_version = CMS_MSG_VERSION;
    req.head.msg_seq = cms_uds_cli_get_msg_seq();
    req.head.src_msg_seq = 0;
    err = strcpy_sp(req.group, CMS_NAME_BUFFER_SIZE, group);
    if (err != EOK) {
        err = strcpy_sp(err_info, CMS_MAX_INFO_LEN, "strcpy group failed");
        cms_securec_check(err);
        return GS_ERROR;
    }
    ret = cms_send_to_server(&req.head, &res.head, sizeof(cms_tool_msg_res_add_grp_t),
        CMS_CLIENT_REQUEST_TIMEOUT, err_info);
    if (ret == GS_SUCCESS && res.result != GS_SUCCESS) {
        err = strcpy_sp(err_info, CMS_MAX_INFO_LEN, res.info);
        cms_securec_check(err);
        return GS_ERROR;
    }
    return ret;
}

int32 cms_cmd_proc_add_resgrp(char* group)
{
    CMS_LOG_INF("start add resource group:%s", group);
    status_t ret = GS_SUCCESS;
    cms_disk_lock_t master_lock = {0};
    char err_info[CMS_INFO_BUFFER_SIZE] = {0};

    if (cms_check_master_lock_status(&master_lock) != GS_SUCCESS) {
        cms_disk_lock_destroy(&master_lock);
        printf("check master_lock failed, add resource group failed.\n");
        return GS_SUCCESS;
    }

    if (master_lock.inst_id == -1) {
        ret = cms_add_resgrp_local(group, err_info, CMS_INFO_BUFFER_SIZE);
        if (ret != GS_SUCCESS) {
            printf("%s, add resource group failed.\n", err_info);
            cms_disk_lock_destroy(&master_lock);
            return ret;
        }
    } else {
        ret = cms_add_resgrp_server(group, err_info, CMS_INFO_BUFFER_SIZE);
        if (ret != GS_SUCCESS) {
            printf("%s, add resource group failed.\n", err_info);
            cms_disk_lock_destroy(&master_lock);
            return ret;
        }
    }
    printf("add resource group succeed.\n");
    cms_disk_lock_destroy(&master_lock);
    CMS_LOG_INF("add resource group succeed");
    return GS_SUCCESS;
}

int32 cms_resgrp_add(int32 argc, char* argv[])
{
    char* group = argv[3];
    uint32 group_len = (uint32)strlen(group);
    if (group_len > CMS_MAX_NAME_LEN) {
        printf("resource group name is too long (maximum %u), add resource group failed.\n", CMS_MAX_NAME_LEN);
        return GS_SUCCESS;
    }

    if (!cms_check_name_valid(group, group_len)) {
        printf("resource group name is invalid, add resource group failed.\n");
        return GS_SUCCESS;
    }

    return cms_cmd_proc_add_resgrp(group);
}

status_t cms_del_resgrp_local(char* group, bool32 force, char* err_info, uint32 err_len)
{
    int32 err_code = 0;
    const char *err_msg = NULL;
    status_t ret = GS_SUCCESS;
    errno_t err = EOK;
    if (cms_lock_gcc_disk() != GS_SUCCESS) {
        CMS_LOG_ERR("cms lock gcc disk failed");
        printf("cms lock gcc disk failed. \n");
        return GS_ERROR;
    }

    if (force) {
        ret = cms_del_resgrp_force(group);
    } else {
        ret = cms_del_resgrp(group);
    }
    cms_unlock_gcc_disk();
    if (ret != GS_SUCCESS) {
        cm_get_error(&err_code, &err_msg, NULL);
        err = strcpy_sp(err_info, err_len, err_msg);
        cms_securec_check(err);
        return ret;
    }
    return GS_SUCCESS;
}

status_t cms_del_resgrp_server(char* group, bool32 force, char* err_info, uint32 err_len)
{
    status_t ret = GS_SUCCESS;
    errno_t err = EOK;
    cms_tool_msg_req_del_grp_t req = {0};
    cms_tool_msg_res_del_grp_t res = {0};

    req.head.msg_type = CMS_TOOL_MSG_REQ_DEL_GRP;
    req.head.msg_size = sizeof(cms_tool_msg_req_del_grp_t);
    req.head.msg_version = CMS_MSG_VERSION;
    req.head.msg_seq = cms_uds_cli_get_msg_seq();
    req.head.src_msg_seq = 0;
    req.force = force;
    err = strcpy_sp(req.group, CMS_NAME_BUFFER_SIZE, group);
    if (err != EOK) {
        err = strcpy_sp(err_info, err_len, "strcpy group failed");
        cms_securec_check(err);
        return GS_ERROR;
    }
    ret = cms_send_to_server(&req.head, &res.head, sizeof(cms_tool_msg_res_del_grp_t),
        CMS_CLIENT_REQUEST_TIMEOUT, err_info);
    if (ret == GS_SUCCESS && res.result != GS_SUCCESS) {
        err = strcpy_sp(err_info, err_len, res.info);
        cms_securec_check(err);
        return GS_ERROR;
    }
    return ret;
}

int32 cms_cmd_proc_del_resgrp(char* group, bool32 force)
{
    CMS_LOG_INF("start delete resource group:%s", group);
    cms_disk_lock_t master_lock = {0};
    status_t ret = GS_SUCCESS;
    char err_info[CMS_INFO_BUFFER_SIZE] = {0};

    if (cms_check_master_lock_status(&master_lock) != GS_SUCCESS) {
        cms_disk_lock_destroy(&master_lock);
        printf("check master_lock failed, delete resource group failed.\n");
        return GS_SUCCESS;
    }

    if (master_lock.inst_id == -1) {
        ret = cms_del_resgrp_local(group, force, err_info, CMS_INFO_BUFFER_SIZE);
        if (ret != GS_SUCCESS) {
            cms_disk_lock_destroy(&master_lock);
            printf("%s, delete resource group failed.\n", err_info);
            return ret;
        }
    } else {
        ret = cms_del_resgrp_server(group, force, err_info, CMS_INFO_BUFFER_SIZE);
        if (ret != GS_SUCCESS) {
            cms_disk_lock_destroy(&master_lock);
            printf("%s, delete resource group failed.\n", err_info);
            return ret;
        }
    }
    printf("delete resource group succeed.\n");
    cms_disk_lock_destroy(&master_lock);
    CMS_LOG_INF("delete resource group succeed");
    return GS_SUCCESS;
}

int32 cms_resgrp_del(int32 argc, char* argv[])
{
    char* group = argv[3];
    uint32 group_len = (uint32)strlen(group);
    if (group_len > CMS_MAX_NAME_LEN) {
        printf("resource group name is too long (maximum %u), delete resource group failed.\n", CMS_MAX_NAME_LEN);
        return GS_SUCCESS;
    }

    if (!cms_check_name_valid(group, group_len)) {
        printf("resource group name is invalid, delete resource group failed.\n");
        return GS_SUCCESS;
    }

    if (cm_strcmpi(group, "default") == 0) {
        printf("the resource group 'default' can't be deleted, delete resource group failed.\n");
        return GS_SUCCESS;
    }

    return cms_cmd_proc_del_resgrp(group, GS_FALSE);
}

int32 cms_resgrp_recursive_del(int32 argc, char* argv[])
{
    char* group = argv[4];
    uint32 group_len = (uint32)strlen(group);
    if (group_len > CMS_MAX_NAME_LEN) {
        printf("resource group name is too long (maximum %u), delete resource group failed.\n", CMS_MAX_NAME_LEN);
        return GS_SUCCESS;
    }

    if (cms_load_gcc() != GS_SUCCESS) {
        printf("cms load gcc failed.\n");
        return GS_SUCCESS;
    }

    if (!cms_check_name_valid(group, group_len)) {
        printf("resource group name is invalid, delete resource group failed.\n");
        return GS_SUCCESS;
    }

    if (cm_strcmpi(group, "default") == 0) {
        printf("the resource group 'default' can't be deleted, delete resource group failed.\n");
        return GS_SUCCESS;
    }

    const cms_gcc_t* gcc = cms_get_read_gcc();
    const cms_resgrp_t* resgrp = cms_find_resgrp(gcc, group);
    if (resgrp == NULL) {
        printf("the resource group is not find, delete resource group failed.\n");
        cms_release_gcc(&gcc);
        return GS_SUCCESS;
    }

    if (strcmp(resgrp->name, "default") == 0) {
        printf("the resource group 'default' can't be deleted, delete resource group failed.\n");
        cms_release_gcc(&gcc);
        return GS_SUCCESS;
    }

    char confirm;
    if (cms_check_resgrp_has_res(gcc, group)) {
        printf("the resource group has resource(s), delete anyway? (y/n):\n");
        confirm = getc(stdin);
        if (confirm != 'Y' && confirm != 'y') {
            cms_release_gcc(&gcc);
            return GS_SUCCESS;
        }
    }
    cms_release_gcc(&gcc);
    return cms_cmd_proc_del_resgrp(group, GS_TRUE);
}

status_t cms_add_node_server(uint32 node_id, const char* name, const char* ip, uint32 port, char* err_info)
{
    status_t ret = GS_SUCCESS;
    errno_t err = EOK;
    cms_tool_msg_req_add_node_t req = {0};
    cms_tool_msg_res_add_node_t res = {0};

    req.head.msg_type = CMS_TOOL_MSG_REQ_ADD_NODE;
    req.head.msg_size = sizeof(cms_tool_msg_req_add_node_t);
    req.head.msg_version = CMS_MSG_VERSION;
    req.head.msg_seq = cms_uds_cli_get_msg_seq();
    req.head.src_msg_seq = 0;
    req.port = port;
    req.node_id = node_id;
    err = strcpy_sp(req.name, CMS_NAME_BUFFER_SIZE, name);
    if (err != EOK) {
        err = strcpy_sp(err_info, CMS_MAX_INFO_LEN, "strcpy name failed");
        cms_securec_check(err);
        return GS_ERROR;
    }
    err = strcpy_sp(req.ip, CMS_IP_BUFFER_SIZE, ip);
    if (err != EOK) {
        err = strcpy_sp(err_info, CMS_MAX_INFO_LEN, "strcpy ip failed");
        cms_securec_check(err);
        return GS_ERROR;
    }
    ret = cms_send_to_server(&req.head, &res.head, sizeof(cms_tool_msg_res_add_node_t),
        CMS_CLIENT_REQUEST_TIMEOUT, err_info);
    if (ret == GS_SUCCESS && res.result != GS_SUCCESS) {
        err = strcpy_sp(err_info, CMS_MAX_INFO_LEN, res.info);
        cms_securec_check(err);
        return GS_ERROR;
    }
    return ret;
}

status_t cms_add_node_local(uint32 node_id, const char* name, const char* ip, uint32 port, char* err_info)
{
    int32 err_code = 0;
    const char *err_msg = NULL;
    status_t ret = GS_SUCCESS;
    errno_t err = EOK;

    if (cms_lock_gcc_disk() != GS_SUCCESS) {
        CMS_LOG_ERR("cms lock gcc disk failed");
        printf("cms lock gcc disk failed. \n");
        return GS_ERROR;
    }

    if (node_id == GS_MAX_UINT32) {
        ret = cms_add_node(name, ip, port);
    } else {
        ret = cms_insert_node(node_id, name, ip, port);
    }
    cms_unlock_gcc_disk();
    if (ret != GS_SUCCESS) {
        cm_get_error(&err_code, &err_msg, NULL);
        err = strcpy_sp(err_info, CMS_MAX_INFO_LEN, err_msg);
        cms_securec_check(err);
        return ret;
    }
    return GS_SUCCESS;
}

status_t cms_cmd_proc_add_node(uint32 node_id, const char* name, const char* ip, uint32 port)
{
    CMS_LOG_INF("start add node, node id:%u, name:%s, ip:%s, port:%u", node_id, name, ip, port);
    status_t ret = GS_SUCCESS;
    cms_disk_lock_t master_lock = {0};
    char err_info[CMS_INFO_BUFFER_SIZE] = {0};

    if (cms_check_master_lock_status(&master_lock) != GS_SUCCESS) {
        cms_disk_lock_destroy(&master_lock);
        printf("check master_lock failed, add node failed.\n");
        return GS_SUCCESS;
    }

    if (master_lock.inst_id == -1) {
        ret = cms_add_node_local(node_id, name, ip, port, err_info);
        if (ret != GS_SUCCESS) {
            printf("%s, add node failed.\n", err_info);
            cms_disk_lock_destroy(&master_lock);
            return ret;
        }
    } else {
        ret = cms_add_node_server(node_id, name, ip, port, err_info);
        if (ret != GS_SUCCESS) {
            printf("%s, add node failed.\n", err_info);
            cms_disk_lock_destroy(&master_lock);
            return ret;
        }
    }
    printf("add node succeed.\n");
    cms_disk_lock_destroy(&master_lock);
    CMS_LOG_INF("add node succeed");
    return GS_SUCCESS;
}

int32 cms_node_add(int32 argc, char* argv[])
{
    uint32 node_id = GS_MAX_UINT32;
    char* name = argv[3];
    uint32 name_len = (uint32)strlen(name);
    char* ip = argv[4];
    uint32 port;
    
    if (name_len > CMS_MAX_NAME_LEN) {
        printf("node name is too long (maximum %u), add node failed.\n", CMS_MAX_NAME_LEN);
        return GS_SUCCESS;
    }

    if (!cms_check_name_valid(name, name_len)) {
        printf("node name is invalid, add node failed.\n");
        return GS_SUCCESS;
    }

    if (!cm_check_ip_valid(ip)) {
        printf("ip is invalid, add node failed.\n");
        return GS_SUCCESS;
    }
    if (cm_str2uint32(argv[5], &port) != GS_SUCCESS) {
        printf("port is invalid, add node failed.\n");
        return GS_SUCCESS;
    }
    if (port == 0 || port > GS_MAX_UINT16) {
        printf("port is out of range, add node failed.\n");
        return GS_SUCCESS;
    }

    return cms_cmd_proc_add_node(node_id, name, ip, port);
}

int32 cms_node_add_with_id(int32 argc, char* argv[])
{
    uint32 node_id;
    char* name = argv[4];
    uint32 name_len = (uint32)strlen(name);
    char* ip = argv[5];
    uint32 port;
    if (cm_str2uint32(argv[3], &node_id) != GS_SUCCESS) {
        printf("node id is invalid, add node failed.\n");
        return GS_SUCCESS;
    }

    if (node_id >= CMS_MAX_NODE_COUNT) {
        printf("node id exceeds the maximum %d, add node failed.\n", CMS_MAX_NODE_COUNT - 1);
        return GS_SUCCESS;
    }

    if (name_len > CMS_MAX_NAME_LEN) {
        printf("node name is too long (maximum %u), add node failed.\n", CMS_MAX_NAME_LEN);
        return GS_SUCCESS;
    }

    if (!cms_check_name_valid(name, name_len)) {
        printf("node name is invalid, add node failed.\n");
        return GS_SUCCESS;
    }

    if (!cm_check_ip_valid(ip)) {
        printf("ip is invalid, add node failed.\n");
        return GS_SUCCESS;
    }

    if (cm_str2uint32(argv[6], &port) != GS_SUCCESS) {
        printf("port is invalid, add node failed.\n");
        return GS_SUCCESS;
    }

    if (port == 0 || port > GS_MAX_UINT16) {
        printf("port is out of range, add node failed.\n");
        return GS_SUCCESS;
    }

    return cms_cmd_proc_add_node(node_id, name, ip, port);
}

status_t cms_del_node_local(uint32 node_id, char* err_info)
{
    status_t ret = GS_SUCCESS;
    int32 err_code = 0;
    const char *err_msg = NULL;
    errno_t err = EOK;

    if (cms_lock_gcc_disk() != GS_SUCCESS) {
        CMS_LOG_ERR("cms lock gcc disk failed");
        printf("cms lock gcc disk failed. \n");
        return GS_ERROR;
    }
    ret = cms_del_node(node_id);
    cms_unlock_gcc_disk();
    if (ret == GS_ERROR) {
        cm_get_error(&err_code, &err_msg, NULL);
        err = strcpy_sp(err_info, CMS_MAX_INFO_LEN, err_msg);
        cms_securec_check(err);
        return ret;
    }
    return GS_SUCCESS;
}

status_t cms_del_node_server(uint32 node_id, char* err_info)
{
    status_t ret = GS_SUCCESS;
    errno_t err = EOK;
    cms_tool_msg_req_del_node_t req = {0};
    cms_tool_msg_res_del_node_t res = {0};

    req.head.msg_type = CMS_TOOL_MSG_REQ_DEL_NODE;
    req.head.msg_size = sizeof(cms_tool_msg_req_del_node_t);
    req.head.msg_version = CMS_MSG_VERSION;
    req.head.msg_seq = cms_uds_cli_get_msg_seq();
    req.head.src_msg_seq = 0;
    req.node_id = node_id;
    ret = cms_send_to_server(&req.head, &res.head, sizeof(cms_tool_msg_res_del_node_t),
        CMS_CLIENT_REQUEST_TIMEOUT, err_info);
    if (ret == GS_SUCCESS && res.result != GS_SUCCESS) {
        err = strcpy_sp(err_info, CMS_MAX_INFO_LEN, res.info);
        cms_securec_check(err);
        return GS_ERROR;
    }
    return ret;
}

status_t cms_cmd_proc_del_node(uint32 node_id)
{
    CMS_LOG_INF("start delete node, node_id:%u", node_id);
    status_t ret = GS_SUCCESS;
    cms_disk_lock_t master_lock = {0};
    char err_info[CMS_INFO_BUFFER_SIZE] = {0};

    if (cms_check_master_lock_status(&master_lock) != GS_SUCCESS) {
        cms_disk_lock_destroy(&master_lock);
        printf("check master_lock failed, delete node failed.\n");
        return GS_SUCCESS;
    }

    if (master_lock.inst_id == -1) {
        ret = cms_del_node_local(node_id, err_info);
        if (ret != GS_SUCCESS) {
            printf("%s, delete node failed.\n", err_info);
            cms_disk_lock_destroy(&master_lock);
            return ret;
        }
    } else {
        ret = cms_del_node_server(node_id, err_info);
        if (ret != GS_SUCCESS) {
            printf("%s, delete node failed.\n", err_info);
            cms_disk_lock_destroy(&master_lock);
            return ret;
        }
    }
    printf("delete node succeed.\n");
    cms_disk_lock_destroy(&master_lock);
    CMS_LOG_INF("delete node succeed");
    return GS_SUCCESS;
}

int32 cms_node_del(int32 argc, char* argv[])
{
    uint16 node_id;

    if (cm_str2uint16(argv[3], &node_id) != GS_SUCCESS) {
        printf("node_id is invalid, delete node failed.\n");
        return GS_SUCCESS;
    }

    if (node_id >= CMS_MAX_NODE_COUNT) {
        printf("node id exceeds the maximum %d, delete node failed.\n", CMS_MAX_NODE_COUNT - 1);
        return GS_SUCCESS;
    }
    
    return cms_cmd_proc_del_node(node_id);
}

void cms_date2str(date_t date, char* str, uint32 max_size)
{
    text_t date_text = {str, 0};
    text_t format = {"YYYY-MM-DD HH24:MI:SS.FF", 24};
    cm_date2text_ex(date, &format, 3, &date_text, max_size - 1);
    str[max_size - 1] = 0;
}

#ifdef DB_DEBUG_VERSION
static int32 cms_enable_inject_cmd(int32 argc, uint32 syncpoint_type, uint32 timeout_ms, uint16 execution_num)
{
    status_t ret = GS_SUCCESS;
    cms_tool_msg_req_enable_inject_t req = {0};
    cms_tool_msg_res_enable_inject_t res = {0};
    char err_info[CMS_INFO_BUFFER_SIZE] = {0};

    req.head.msg_type = CMS_TOOL_MSG_REQ_ENABLE_REJECT;
    req.head.msg_size = sizeof(cms_tool_msg_req_enable_inject_t);
    req.head.msg_version = CMS_MSG_VERSION;
    req.head.msg_seq = cms_uds_cli_get_msg_seq();
    req.head.src_msg_seq = 0;
    req.raise_num = execution_num;
    req.syncpoint_type = syncpoint_type;
    ret = cms_send_to_server(&req.head, &res.head, sizeof(cms_tool_msg_res_enable_inject_t),
        CMS_CLIENT_REQUEST_TIMEOUT, err_info);
    if (ret != GS_SUCCESS) {
        printf("%s, enable inject failed, please use 'cms stat' to check res stat.\n", err_info);
        return GS_ERROR;
    }
    if (res.result != GS_SUCCESS) {
        printf("enable inject failed.\n");
        return GS_ERROR;
    }
    printf("enable inject succeed.\n");
    return GS_SUCCESS;
}

int32 cms_enable_inject(int32 argc, char *argv[])
{
    uint16 execution_num = 0;
    uint32 idx = 0;
    char *input_inject_type = argv[3]; // Parameter 3 indicates the fault injection type.
    for (; idx < CMS_SYNCPOINT_COUNT; idx++) {
        if (strcmp(input_inject_type, g_cms_syncpoint[idx].name) == 0) {
            break;
        }
    }
    if (idx == CMS_SYNCPOINT_COUNT) {
        printf("input invalid inject type, try again.\n");
        return GS_ERROR;
    }
    if (cm_str2uint16(argv[4], &execution_num) != GS_SUCCESS) { // Parameter 4 is the number of executions
        printf("execution num is invalid.\n");
        return GS_ERROR;
    }
    return cms_enable_inject_cmd(argc, idx, CMS_CMD_START_ALL_TMOUT_MS, execution_num);
}
#endif

status_t cms_send_to_server(cms_packet_head_t *req, cms_packet_head_t *res, uint32 res_size, int32 timeout_ms,
    char* err_info)
{
    status_t ret = GS_SUCCESS;
    errno_t err = EOK;
    char CMS_TOOL_RES_TYPE[CMS_MAX_RES_TYPE_LEN] = "TOOL";
    cms_uds_cli_info_t cms_uds_cli_info = { CMS_TOOL_RES_TYPE, CMS_TOOL_INST_ID, GS_FALSE, CMS_CLI_TOOL };
    ret = cms_uds_cli_connect(&cms_uds_cli_info, NULL);
    if (ret != GS_SUCCESS) {
        if (err_info != NULL) {
            err = strcpy_sp(err_info, CMS_MAX_INFO_LEN, "connect to server failed");
            cms_securec_check(err);
        }
        return ret;
    }

    ret = cms_uds_cli_request_sync(req, res, res_size, timeout_ms);
    if (ret != GS_SUCCESS) {
        if (err_info != NULL) {
            err = strcpy_sp(err_info, CMS_MAX_INFO_LEN, "send message to server failed");
            cms_securec_check(err);
        }
        cms_uds_cli_disconnect();
        return ret;
    }
    cms_uds_cli_disconnect();
    return GS_SUCCESS;
}

void cms_print_online_node_info(uint64 *cms_online_bitmap)
{
    for (int i = 0; i < GS_MAX_INSTANCES; i++) {
        if (cm_bitmap64_exist(cms_online_bitmap, i)) {
            printf("cms server in node %d is runing, ", i);
            CMS_LOG_INF("cms server in node %d is runing", i);
        }
    }
    return;
}