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
 * cms_cmd_upgrade.c
 *
 *
 * IDENTIFICATION
 * src/cms/cms/cms_cmd_upgrade.c
 *
 * -------------------------------------------------------------------------
 */
#include "cms_log_module.h"
#include "cms_cmd_upgrade.h"
#include "cms_instance.h"
#include "cs_tcp.h"
#include "cms_msg_def.h"
#include "cms_gcc.h"
#include "cms_uds_server.h"
#include "cms_param.h"
#include "cms_client.h"
#include "cms_comm.h"
#include "cm_file.h"
#include "cm_defs.h"
#include "cms_log.h"

// cms tool发给cms升级消息
status_t cms_cmd_proc_upgrade(uint16 main_ver, uint16 major_ver, uint16 revision, uint16 inner, char* err_info)
{
    status_t ret = CT_SUCCESS;
    errno_t err = EOK;
    cms_tool_msg_req_upgrade_t req = {0};
    cms_tool_msg_res_upgrade_t res = {0};

    req.head.msg_type = CMS_TOOL_MSG_REQ_UPGRADE;
    req.head.msg_size = sizeof(cms_tool_msg_req_upgrade_t);
    req.head.msg_version = CMS_MSG_VERSION;
    req.head.msg_seq = cms_uds_cli_get_msg_seq();
    req.head.src_msg_seq = 0;
    req.main_ver = main_ver;
    req.major_ver = major_ver;
    req.revision = revision;
    req.inner = inner;

    ret = cms_send_to_server(&req.head, &res.head, sizeof(cms_tool_msg_res_upgrade_t), CMS_CLIENT_REQUEST_TIMEOUT,
        err_info);
    if (ret != CT_SUCCESS) {
        CMS_LOG_ERR("cms send to server failed, try again.");
        return CT_ERROR;
    }
    if (ret == CT_SUCCESS && res.result != CT_SUCCESS) {
        err = strcpy_sp(err_info, CMS_MAX_INFO_LEN, res.info);
        cms_securec_check(err);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

// cms tool升级入口
int32 cms_upgrade(int32 argc, char* argv[])
{
    CMS_LOG_INF("cms start upgrade.");
    char err_info[CMS_INFO_BUFFER_SIZE] = {0};
    uint16 main_ver;
    uint16 major_ver;
    uint16 revision;
    status_t ret = CT_SUCCESS;

    // 3:subscript of the third input parameter
    if (cm_str2uint16(argv[3], &main_ver) != CT_SUCCESS) {
        printf("main version is invalid, cms upgrade failed.\n");
        return CT_SUCCESS;
    }

    // 4:subscript of the fourth input parameter
    if (cm_str2uint16(argv[4], &major_ver) != CT_SUCCESS) {
        printf("major version is invalid, cms upgrade failed.\n");
        return CT_SUCCESS;
    }

    // 5:subscript of the fifth input parameter
    if (cm_str2uint16(argv[5], &revision) != CT_SUCCESS) {
        printf("revision is invalid, cms upgrade failed.\n");
        return CT_SUCCESS;
    }

    ret = cms_cmd_proc_upgrade(main_ver, major_ver, revision, CMS_DEFAULT_INNNER_VERSION, err_info);
    if (ret != CT_SUCCESS) {
        printf("cms proc upgrade failed, %s.\n", err_info);
        return ret;
    }
    printf("cms upgrade succeed, main_ver=%u, major_ver=%u, revision=%u, inner=%u.\n", main_ver, major_ver, revision,
        CMS_DEFAULT_INNNER_VERSION);
    return CT_SUCCESS;
}

status_t cms_get_version_server(void)
{
    status_t ret = CT_SUCCESS;
    cms_tool_msg_req_version_t req = {0};
    cms_tool_msg_res_version_t res = {0};
    char err_info[CMS_INFO_BUFFER_SIZE] = {0};

    req.head.msg_type = CMS_TOOL_MSG_REQ_VERSION;
    req.head.msg_size = sizeof(cms_tool_msg_req_version_t);
    req.head.msg_version = CMS_MSG_VERSION;
    req.head.msg_seq = cms_uds_cli_get_msg_seq();
    req.head.src_msg_seq = 0;

    ret = cms_send_to_server(&req.head, &res.head, sizeof(cms_tool_msg_res_version_t), CMS_CLIENT_REQUEST_TIMEOUT,
        err_info);
    if (ret != CT_SUCCESS) {
        printf("%s, cms send to server failed, try again.\n", err_info);
        return CT_ERROR;
    }
    if (ret == CT_SUCCESS && res.result != CT_SUCCESS) {
        printf("cms get version failed, %s.\n", res.info);
        return CT_ERROR;
    }

    printf("mem version:%u.%u.%u.\ngcc version:%u.%u.%u.\n", res.mem_main_ver, res.mem_major_ver, res.mem_revision,
        res.gcc_main_ver, res.gcc_major_ver, res.gcc_revision);
    return CT_SUCCESS;
}

status_t cms_get_version_local(void)
{
    uint16 main_ver = 0;
    uint16 major_ver = 0;
    uint16 revision = 0;
    uint16 inner = 0;
    // 更新gcc的版本号
    if (cms_get_gcc_ver(&main_ver, &major_ver, &revision, &inner) != CT_SUCCESS) {
        printf("get disk gcc ver local failed\n");
        return CT_ERROR;
    }
    printf("gcc version:%u.%u.%u.\n", main_ver, major_ver, revision);
    return CT_SUCCESS;
}

// 获取cms的版本号入口
int32 cms_get_version(int32 argc, char* argv[])
{
    CMS_LOG_INF("cms start get upgrade version.");
    cms_disk_lock_t master_lock = {0};
    status_t ret = CT_SUCCESS;

    if (cms_check_master_lock_status(&master_lock) != CT_SUCCESS) {
        cms_disk_lock_destroy(&master_lock);
        printf("check master_lock failed, get version failed.\n");
        return CT_ERROR;
    }

    CMS_LOG_INF("cms get master lock id = %lld.", master_lock.inst_id);
    if (master_lock.inst_id == -1) {
        if (g_cms_param->gcc_type == CMS_DEV_TYPE_DBS &&
            cms_instance_init_with_dbs(DBS_RUN_CMS_LOCAL) != CT_SUCCESS) {
            printf("cms instance init with dbs, get version failed.\n");
            cms_disk_lock_destroy(&master_lock);
            return CT_ERROR;
        }
        ret = cms_get_version_local();
    } else {
        ret = cms_get_version_server();
    }
    if (ret != CT_SUCCESS) {
        cms_disk_lock_destroy(&master_lock);
        return ret;
    }
    cms_disk_lock_destroy(&master_lock);
    CMS_LOG_INF("cms end get upgrade version.");
    return CT_SUCCESS;
}

status_t cms_degrade_local(uint16 main_ver, uint16 major_ver, uint16 revision, uint16 inner, char* err_info)
{
    status_t ret = CT_SUCCESS;
    errno_t err = EOK;
    // 更新gcc的版本号
    if (cms_lock_gcc_disk() != CT_SUCCESS) {
        CMS_LOG_ERR("cms degrade local lock gcc disk failed.");
        err = strcpy_sp(err_info, CMS_MAX_INFO_LEN, "cms degrade local lock gcc disk failed.");
        cms_securec_check(err);
        return CT_ERROR;
    }
    ret = cms_update_gcc_ver(main_ver, major_ver, revision, inner);
    if (ret != CT_SUCCESS) {
        cms_unlock_gcc_disk();
        CMS_LOG_ERR("cms degrade local update gcc ver failed.");
        err = strcpy_sp(err_info, CMS_MAX_INFO_LEN, "cms degrade local update gcc ver failed.");
        cms_securec_check(err);
        return CT_ERROR;
    }
    cms_unlock_gcc_disk();
    return CT_SUCCESS;
}

status_t cms_cmd_proc_degrade(uint16 main_ver, uint16 major_ver, uint16 revision, uint16 inner, char* err_info)
{
    CMS_LOG_INF("start degrade version, main_ver=%u, major_ver=%u, revision=%u, inner=%u.\n", main_ver,
        major_ver, revision, inner);
    status_t ret = CT_SUCCESS;
    errno_t err = EOK;
    cms_disk_lock_t master_lock = {0};

    if (cms_check_master_lock_status(&master_lock) != CT_SUCCESS) {
        cms_disk_lock_destroy(&master_lock);
        err = strcpy_sp(err_info, CMS_MAX_INFO_LEN, "check master_lock failed, degrade version failed.");
        cms_securec_check(err);
        CMS_LOG_ERR("check master_lock failed, degrade version failed.");
        return CT_ERROR;
    }

    if (master_lock.inst_id == -1) {
        ret = cms_degrade_local(main_ver, major_ver, revision, inner, err_info);
        if (ret != CT_SUCCESS) {
            CMS_LOG_ERR("%s, degrade version failed.", err_info);
            cms_disk_lock_destroy(&master_lock);
            return ret;
        }
    } else {
        cms_disk_lock_destroy(&master_lock);
        err = strcpy_sp(err_info, CMS_MAX_INFO_LEN, "master is valid, wait 10s and try again.");
        cms_securec_check(err);
        CMS_LOG_ERR("master is valid %lld, wait 10s and try again.", master_lock.inst_id);
        return CT_ERROR;
    }
    cms_disk_lock_destroy(&master_lock);
    CMS_LOG_INF("degrade version succeed");
    return CT_SUCCESS;
}

int32 cms_degrade_force(int32 argc, char* argv[])
{
    CMS_LOG_INF("cms start degrade.");
    char err_info[CMS_INFO_BUFFER_SIZE] = {0};
    uint16 main_ver;
    uint16 major_ver;
    uint16 revision;
    status_t ret = CT_SUCCESS;

    // 4:subscript of the fourth input parameter
    if (cm_str2uint16(argv[4], &main_ver) != CT_SUCCESS) {
        printf("main version is invalid, cms degrade failed.\n");
        return CT_SUCCESS;
    }

    // 5:subscript of the fifth input parameter
    if (cm_str2uint16(argv[5], &major_ver) != CT_SUCCESS) {
        printf("major version is invalid, cms degrade failed.\n");
        return CT_SUCCESS;
    }

    // 6:subscript of the sixth input parameter
    if (cm_str2uint16(argv[6], &revision) != CT_SUCCESS) {
        printf("revision is invalid, cms degrade failed.\n");
        return CT_SUCCESS;
    }

    ret = cms_cmd_proc_degrade(main_ver, major_ver, revision, CMS_DEFAULT_INNNER_VERSION, err_info);
    if (ret != CT_SUCCESS) {
        printf("cms proc degrade failed, %s.\n", err_info);
        return ret;
    }
    printf("cms degrade succeed, main_ver=%u, major_ver=%u, revision=%u, inner=%u.\n", main_ver, major_ver, revision,
        CMS_DEFAULT_INNNER_VERSION);
    CMS_LOG_INF("cms degrade succeed, main_ver=%u, major_ver=%u, revision=%u, inner=%u.", main_ver, major_ver, revision,
        CMS_DEFAULT_INNNER_VERSION);
    return CT_SUCCESS;
}

#ifdef DB_DEBUG_VERSION
bool32 cms_cur_version_is_higher_or_equal(cms_version_t cur_version, cms_version_t local_version)
{
    if (cur_version.main_ver != local_version.main_ver) {
        return cur_version.main_ver > local_version.main_ver;
    } else if (cur_version.major_ver != local_version.major_ver) {
        return cur_version.major_ver > local_version.major_ver;
    } else if (cur_version.revision != local_version.revision) {
        return cur_version.revision > local_version.revision;
    } else {
        return cur_version.inner >= local_version.inner;
    }
}
#endif