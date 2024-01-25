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
 * cms_interface.c
 *
 *
 * IDENTIFICATION
 * src/cms/interface/cms_interface.c
 *
 * -------------------------------------------------------------------------
 */
#include "cms_log_module.h"
#include "cm_config.h"
#include "cms_interface.h"
#include "cm_thread.h"
#include "cm_sync.h"
#include "cm_ip.h"
#include "cs_tcp.h"
#include "cms_client.h"
#include "cms_comm.h"
#include "cms_socket.h"
#include "cm_malloc.h"
#include "cm_file.h"
#include "cm_dbs_iofence.h"
#include "cm_dbs_ctrl.h"
#include "cms_msgque.h"
#include "cm_hashmap.h"
#include "cm_hash.h"
#include "cm_signal.h"
#include "cm_io_record.h"
#include "cm_dbs_intf.h"
#include "cm_file_iofence.h"

const char* g_stat_str[] = {
    "UNKNOWN",
    "ONLINE",
    "OFFLINE"
};

static char                 g_res_type[CMS_MAX_RES_TYPE_LEN] = {0};
int8                        g_inst_id = -1;
static cms_notify_func_t    g_notify_func;
static cms_master_op_t      g_master_func;
static cms_upgrade_op_t     g_upgrade_func;
static thread_t             g_cli_hb_thread;
static bool32               g_cli_hbt_term = CT_TRUE;
static thread_t             g_cli_recv_thread;
static bool32               g_cli_recvt_term = CT_TRUE;
static bool32               g_cli_conn_try = CT_TRUE;
static thread_t             g_cli_worker_thread;
static bool32               g_cli_workert_term = CT_TRUE;
static char                 g_cms_home[CT_MAX_PATH_LEN] = {0};
static uint16               g_node_id = -1;
static thread_lock_t        g_cli_lock;
static cms_que_t            g_cli_recv_que;
static config_item_t        g_cms_params[] = {
    {"NODE_ID", CT_TRUE, CT_TRUE, "", NULL, NULL, "-", "-", "CT_TYPE_INTEGER", NULL, 0, \
        EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_IP", CT_TRUE, CT_FALSE, "", NULL, NULL, "-", "-", "CT_TYPE_STRING", NULL, 0, \
        EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_PORT", CT_TRUE, CT_FALSE, "", NULL, NULL, "-", "-", "CT_TYPE_STRING", NULL, 0, \
        EFFECT_REBOOT, CFG_INS, NULL, NULL},
};

const char* cms_stat_str(cms_stat_t stat)
{
    if ((uint32)stat < 0 || (uint32)stat >= sizeof(g_stat_str) / sizeof(char*)) {
        return "INVALID STAT";
    }

    return g_stat_str[stat];
}

static status_t cms_get_cms_home(char* cms_home)
{
    bool32 is_home_exist = CT_TRUE;

    const char *cms_home_env = getenv(CMS_ENV_CMS_HOME);
    if (cms_home_env == NULL) {
        CT_LOG_RUN_ERR("env $CMS_HOME not exists");
        return CT_ERROR;
    }

    errno_t err = strcpy_s(cms_home, CT_MAX_PATH_LEN, cms_home_env);
    MEMS_RETURN_IFERR(err);

    is_home_exist = cm_dir_exist(cms_home);
    if (is_home_exist == CT_FALSE) {
        CT_LOG_RUN_ERR("CMS_HOME[%s] not exists", cms_home);
        return CT_ERROR;
    }
    is_home_exist = cm_check_exist_special_char(cms_home, (uint32)strlen(cms_home));
    if (is_home_exist == CT_TRUE) {
        CT_LOG_RUN_ERR("CMS_HOME[%s] not exists", cms_home);
        return CT_ERROR;
    }
    uint32 path_len = strlen(cms_home);
    if (path_len > CT_MAX_PATH_BUFFER_SIZE - 1) {
        CT_LOG_RUN_ERR("cms home[%s] is too long", cms_home);
        return CT_ERROR;
    }
    cm_trim_home_path(cms_home, path_len);

    CT_LOG_RUN_INF("get cms home succ, cms home %s", cms_home);
    return CT_SUCCESS;
}

static status_t cms_load_param(void)
{
    char* value = NULL;
    int64 size = 0;
    errno_t err = EOK;
    char config_name[CT_FILE_NAME_BUFFER_SIZE] = {0};

    // get config info
    err = snprintf_s(config_name, CT_FILE_NAME_BUFFER_SIZE, CT_FILE_NAME_BUFFER_SIZE - 1,
        "%s/cfg/%s", g_cms_home, CMS_CFG_FILENAME);
    PRTS_RETURN_IFERR(err);

    config_t cfg;
    cm_init_config(g_cms_params, sizeof(g_cms_params) / sizeof(config_item_t), &cfg);
    cfg.ignore = CT_TRUE;
    if (cm_read_config(config_name, &cfg) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("read config failed");
        return CT_ERROR;
    }

    value = cm_get_config_value(&cfg, "NODE_ID");
    if (value == NULL || cm_str2bigint(value, &size) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_CTSTORE_INVALID_PARAM, "invalid parameter value of 'NODE_ID'");
        CT_LOG_RUN_ERR("invalid parameter value of 'NODE_ID'");
        return CT_ERROR;
    }

    if (size < 0 || size >= CT_MAX_INSTANCES) {
        CT_THROW_ERROR(ERR_CTSTORE_INVALID_PARAM, "invalid parameter value[%lld] of 'NODE_ID'", size);
        CT_LOG_RUN_ERR("invalid parameter value[%lld] of 'NODE_ID'", size);
        return CT_ERROR;
    }

    g_node_id = (uint16)size;
    CT_LOG_RUN_INF("CMS NODE_ID:%d", (int32)g_node_id);

    return CT_SUCCESS;
}

status_t cms_env_init(void)
{
    if (g_cms_home[0] == 0) {
        if (cms_get_cms_home(g_cms_home) != CT_SUCCESS) {
            g_cms_home[0] = 0;
            CT_LOG_RUN_ERR("get cms home failed");
            return CT_ERROR;
        }

        if (cms_load_param() != CT_SUCCESS) {
            g_cms_home[0] = 0;
            CT_LOG_RUN_ERR("load param failed");
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t cms_cli_init(void)
{
    status_t ret = CT_SUCCESS;
    
    cm_init_thread_lock(&g_cli_lock);
    ret = cms_env_init();
    if (ret != CT_SUCCESS) {
        cm_destroy_thread_lock(&g_cli_lock);
        CT_LOG_RUN_ERR("env init failed, ret %d", ret);
        return ret;
    }

    ret = cms_init_que(&g_cli_recv_que);
    if (ret != CT_SUCCESS) {
        cm_destroy_thread_lock(&g_cli_lock);
        CT_LOG_RUN_ERR("init cli recv queue failed, ret %d", ret);
        return ret;
    }

    ret = cms_uds_cli_init(g_node_id, g_cms_home);
    if (ret != CT_SUCCESS) {
        cm_destroy_thread_lock(&g_cli_lock);
        CT_LOG_RUN_ERR("uds cli init failed, ret %d", ret);
        return ret;
    }
    CT_LOG_RUN_INF("cms cli init succ");
    return CT_SUCCESS;
}

static status_t cms_cli_hb(void)
{
    status_t ret = CT_SUCCESS;
    static date_t last_check_time = 0;
    date_t check_time = cm_monotonic_now();
    if (check_time - last_check_time > CMS_CLI_HB_INTERVAL) {
        cms_cli_msg_req_hb_t req;
        req.head.msg_size = sizeof(cms_cli_msg_req_hb_t);
        req.head.msg_type = CMS_CLI_MSG_REQ_HB;
        req.head.msg_version = CMS_MSG_VERSION;
        req.head.msg_seq = cms_uds_cli_get_msg_seq();
        req.head.src_msg_seq = 0;
        req.head.dest_node = g_node_id;
        req.head.src_node = g_node_id;
        errno_t err = strcpy_s(req.res_type, CMS_MAX_RES_TYPE_LEN, g_res_type);
        PRTS_RETURN_IFERR(err);

        timeval_t tv_begin;
        cantian_record_io_stat_begin(IO_RECORD_EVENT_CMS_UDS_CLI_HB, &tv_begin);
        ret = cms_uds_cli_send(&req.head, CMS_CLI_UDS_SEND_TMOUT);
        if (ret != CT_SUCCESS) {
            CT_LOG_RUN_ERR("send hb msg failed");
            cantian_record_io_stat_end(IO_RECORD_EVENT_CMS_UDS_CLI_HB, &tv_begin, IO_STAT_FAILED);
            return ret;
        }
        cantian_record_io_stat_end(IO_RECORD_EVENT_CMS_UDS_CLI_HB, &tv_begin, IO_STAT_SUCCESS);
        last_check_time = check_time;

        CT_LOG_DEBUG_INF("cms cli send hb msg, msg type %u, msg seq %llu", req.head.msg_type, req.head.msg_seq);
    }

    return CT_SUCCESS;
}

static void cms_cli_proc_msg_res_stat_chg(cms_packet_head_t* msg)
{
    if (g_notify_func != NULL) {
        CT_LOG_RUN_INF_LIMIT(LOG_PRINT_INTERVAL_SECOND_20,
            "begin proc res stat chg msg, msg type %u, msg size %u, msg seq %llu, msg src seq %llu",
            msg->msg_type, msg->msg_size, msg->msg_seq, msg->src_msg_seq);
        cms_cli_msg_res_stat_chg_t* chg_msg = (cms_cli_msg_res_stat_chg_t*)msg;
        if (msg->msg_size != sizeof(cms_cli_msg_res_stat_chg_t)) {
            CT_LOG_RUN_ERR("proc msg res stat chg msg size %u invalid.", msg->msg_size);
            return;
        }
        CT_LOG_DEBUG_INF("begin invoke notify function");
        g_notify_func(&chg_msg->stat);
        CT_LOG_DEBUG_INF("end invoke notify function");
        CT_LOG_RUN_INF_LIMIT(LOG_PRINT_INTERVAL_SECOND_20,
            "end proc res stat chg msg, msg type %u, msg size %u, msg seq %llu, msg src seq %llu",
            msg->msg_type, msg->msg_size, msg->msg_seq, msg->src_msg_seq);
    }
}

static void cms_cli_proc_msg_get_res_stat(cms_packet_head_t* msg)
{
    CT_LOG_DEBUG_INF("begin proc get res stat res msg, msg type %u, msg size %u, msg seq %llu, msg src seq %llu",
        msg->msg_type, msg->msg_size, msg->msg_seq, msg->src_msg_seq);

    if (msg->msg_size > sizeof(cms_cli_msg_res_get_res_stat_t)) {
        CT_LOG_RUN_ERR("invalid msg size, msg size = %u", msg->msg_size);
        return;
    }

    cms_cli_msg_res_get_res_stat_t* res = malloc(sizeof(cms_cli_msg_res_get_res_stat_t));
    if (res == NULL) {
        CT_LOG_RUN_ERR("malloc failed, size %d", (int32)sizeof(cms_cli_msg_res_get_res_stat_t));
        return;
    }

    errno_t err = memcpy_s(res, sizeof(cms_cli_msg_res_get_res_stat_t), msg, msg->msg_size);
    if (err != EOK) {
        CT_LOG_RUN_ERR("memcpy_s failed, err %d, errno %d[%s], msg type %u, msg size %u, msg seq %llu, "
            "msg src seq %llu", err, errno, strerror(errno), msg->msg_type,
            msg->msg_size, msg->msg_seq, msg->src_msg_seq);
        CM_FREE_PTR(res);
        return;
    }
    status_t ret = cms_uds_cli_wakeup_sender(&res->head);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("can't find wait sender, msg type %u, msg size %u, msg seq %llu, msg src seq %llu",
            res->head.msg_type, res->head.msg_size, res->head.msg_seq, res->head.src_msg_seq);
        CM_FREE_PTR(res);
        return;
    }
    CT_LOG_DEBUG_INF("end proc get res stat res msg, msg type %u, msg size %u, msg seq %llu, msg src seq %llu",
        msg->msg_type, msg->msg_size, msg->msg_seq, msg->src_msg_seq);
}

static void cms_cli_proc_msg_set_res_data(cms_packet_head_t* msg)
{
    CT_LOG_DEBUG_INF("begin proc set res data res msg, msg type %u, msg size %u, msg seq %llu, msg src seq %llu",
        msg->msg_type, msg->msg_size, msg->msg_seq, msg->src_msg_seq);
    if (msg->msg_size > sizeof(cms_cli_msg_res_set_data_t)) {
        CT_LOG_RUN_ERR("invalid msg size, msg size = %u", msg->msg_size);
        return;
    }
    cms_cli_msg_res_set_data_t* res = malloc(sizeof(cms_cli_msg_res_set_data_t));
    if (res == NULL) {
        CT_LOG_RUN_ERR("malloc failed, size %d", (int32)sizeof(cms_cli_msg_res_set_data_t));
        return;
    }

    errno_t err = memcpy_s(res, sizeof(cms_cli_msg_res_set_data_t), msg, msg->msg_size);
    if (err != EOK) {
        CT_LOG_RUN_ERR("memcpy_s failed, err %d, errno %d[%s], msg type %u, msg size %u, msg seq %llu, "
            "msg src seq %llu", err, errno, strerror(errno), msg->msg_type,
            msg->msg_size, msg->msg_seq, msg->src_msg_seq);
        CM_FREE_PTR(res);
        return;
    }
    status_t ret = cms_uds_cli_wakeup_sender(&res->head);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("can't find wait sender, msg type %u, msg size %u, msg seq %llu, msg src seq %llu",
            res->head.msg_type, res->head.msg_size, res->head.msg_seq, res->head.src_msg_seq);
        CM_FREE_PTR(res);
        return;
    }
    CT_LOG_DEBUG_INF("end proc set res data res msg, msg type %u, msg size %u, msg seq %llu, msg src seq %llu",
        msg->msg_type, msg->msg_size, msg->msg_seq, msg->src_msg_seq);
}

static void cms_cli_proc_msg_set_work_stat(cms_packet_head_t* msg)
{
    CT_LOG_DEBUG_INF("begin proc set work stat res msg, msg type %u, msg size %u, msg seq %llu, msg src seq %llu",
        msg->msg_type, msg->msg_size, msg->msg_seq, msg->src_msg_seq);
    if (msg->msg_size > sizeof(cms_cli_msg_res_set_work_stat_t)) {
        CT_LOG_RUN_ERR("invalid msg size, msg size = %u", msg->msg_size);
        return;
    }

    cms_cli_msg_res_set_work_stat_t* res = malloc(sizeof(cms_cli_msg_res_set_work_stat_t));
    if (res == NULL) {
        CT_LOG_RUN_ERR("malloc failed, size %d", (int32)sizeof(cms_cli_msg_res_set_work_stat_t));
        return;
    }

    errno_t err = memcpy_s(res, sizeof(cms_cli_msg_res_set_work_stat_t), msg, msg->msg_size);
    if (err != EOK) {
        CT_LOG_RUN_ERR("memcpy_s failed, err %d, errno %d[%s], msg type %u, msg size %u, msg seq %llu, "
            "msg src seq %llu", err, errno, strerror(errno), msg->msg_type,
            msg->msg_size, msg->msg_seq, msg->src_msg_seq);
        CM_FREE_PTR(res);
        return;
    }

    status_t ret = cms_uds_cli_wakeup_sender(&res->head);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("can't find wait sender, msg type %u, msg size %u, msg seq %llu, msg src seq %llu",
            res->head.msg_type, res->head.msg_size, res->head.msg_seq, res->head.src_msg_seq);
        CM_FREE_PTR(res);
        return;
    }
    CT_LOG_DEBUG_INF("end proc set work stat res msg, msg type %u, msg size %u, msg seq %llu, msg src seq %llu",
        msg->msg_type, msg->msg_size, msg->msg_seq, msg->src_msg_seq);
}

static void cms_cli_proc_msg_res_disconn(cms_packet_head_t* msg)
{
    CT_LOG_RUN_INF("begin proc disconn res msg, msg type %u, msg size %u, msg seq %llu, msg src seq %llu",
        msg->msg_type, msg->msg_size, msg->msg_seq, msg->src_msg_seq);

    if (msg->msg_size > sizeof(cms_cli_msg_res_dis_conn_t)) {
        CT_LOG_RUN_ERR("invalid msg size, msg size = %u", msg->msg_size);
        return;
    }
    cms_cli_msg_res_dis_conn_t* res = malloc(sizeof(cms_cli_msg_res_dis_conn_t));
    if (res == NULL) {
        CT_LOG_RUN_ERR("malloc failed, size %d", (int32)sizeof(cms_cli_msg_res_dis_conn_t));
        return;
    }

    errno_t err = memcpy_s(res, sizeof(cms_cli_msg_res_dis_conn_t), msg, msg->msg_size);
    if (err != EOK) {
        CT_LOG_RUN_ERR("memcpy_s failed, err %d, errno %d[%s], msg type %u, msg size %u, msg seq %llu, "
            "msg src seq %llu", err, errno, strerror(errno), msg->msg_type,
            msg->msg_size, msg->msg_seq, msg->src_msg_seq);
        CM_FREE_PTR(res);
        return;
    }

    status_t ret = cms_uds_cli_wakeup_sender(&res->head);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("can't find wait sender, msg type %u, msg size %u, msg seq %llu, msg src seq %llu",
            res->head.msg_type, res->head.msg_size, res->head.msg_seq, res->head.src_msg_seq);
        CM_FREE_PTR(res);
        return;
    }
    CT_LOG_RUN_INF("end proc disconn res msg, msg type %u, msg size %u, msg seq %llu, msg src seq %llu",
        msg->msg_type, msg->msg_size, msg->msg_seq, msg->src_msg_seq);
}

status_t cms_res_upgrade(uint16 main_ver, uint16 major_ver, uint16 revision, uint16 inner)
{
    if (g_upgrade_func == NULL) {
        CT_LOG_RUN_ERR("cantian upgrade failed, upgrade interface not register");
        return CT_ERROR;
    }

    status_t ret = CT_SUCCESS;
    upgrade_version_t version = { 0 };
    version.main = main_ver;
    version.major = major_ver;
    version.revision = revision;
    version.inner = inner;
    ret = g_upgrade_func((void *)&version);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("cantian upgrade version failed");
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("cantian version upgrade success, main_ver=%u, major_ver=%u, revision=%u, inner=%u", main_ver,
        major_ver, revision, inner);
    return CT_SUCCESS;
}

// cms client处理cms server发送给参天的消息
void cms_cli_proc_msg_req_upgrade(cms_packet_head_t* msg)
{
    CT_LOG_RUN_INF("cms cli start upgrade");
    status_t ret = CT_SUCCESS;
    cms_cli_msg_req_upgrade_t *req = (cms_cli_msg_req_upgrade_t *)msg;
    if (msg->msg_size != sizeof(cms_cli_msg_req_upgrade_t)) {
        CT_LOG_RUN_ERR("proc msg req upgrade msg_size %u invalid.", msg->msg_size);
        return;
    }
    // cantian执行升级
    ret = cms_res_upgrade(req->main_ver, req->major_ver, req->revision, req->inner);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("cantian upgrade failed, msg type %u, msg req %llu", msg->msg_type, msg->msg_seq);
    }
    cms_cli_msg_res_upgrade_t res;
    res.head.msg_size = sizeof(cms_cli_msg_res_upgrade_t);
    res.head.msg_type = CMS_CLI_MSG_RES_UPGRADE;
    res.head.msg_version = CMS_MSG_VERSION;
    res.head.msg_seq = cms_uds_cli_get_msg_seq();
    res.head.src_msg_seq = req->head.msg_seq;
    res.head.dest_node = g_node_id;
    res.head.src_node = g_node_id;
    res.result = ret;

    ret = cms_uds_cli_send(&res.head, CMS_CLI_UDS_SEND_TMOUT);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("cantian send upgrade res msg failed");
    }
    CT_LOG_RUN_INF("send upgrade res msg succeed, msg type %u, msg seq %llu, src_msg_seq %llu", res.head.msg_type,
        res.head.msg_seq, res.head.src_msg_seq);
}

static void cms_cli_proc_msg_get_res_data(cms_packet_head_t* msg)
{
    CT_LOG_DEBUG_INF("begin proc get res data res msg, msg type %u, msg size %u, msg seq %llu, msg src seq %llu",
        msg->msg_type, msg->msg_size, msg->msg_seq, msg->src_msg_seq);
    if (msg->msg_size > sizeof(cms_cli_msg_res_get_data_t)) {
        CT_LOG_RUN_ERR("invalid msg size, msg size = %u", msg->msg_size);
        return;
    }
    cms_cli_msg_res_get_data_t* res = malloc(sizeof(cms_cli_msg_res_get_data_t));
    if (res == NULL) {
        CT_LOG_RUN_ERR("malloc failed, size %d", (int32)sizeof(cms_cli_msg_res_get_data_t));
        return;
    }

    errno_t err = memcpy_s(res, sizeof(cms_cli_msg_res_get_data_t), msg, msg->msg_size);
    if (err != EOK) {
        CT_LOG_RUN_ERR("memcpy_s failed, err %d, errno %d[%s], msg type %u, msg size %u, msg seq %llu, "
            "msg src seq %llu", err, errno, strerror(errno), msg->msg_type,
            msg->msg_size, msg->msg_seq, msg->src_msg_seq);
        CM_FREE_PTR(res);
        return;
    }
    status_t ret = cms_uds_cli_wakeup_sender(&res->head);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("can't find wait sender, msg type %u, msg size %u, msg seq %llu, msg src seq %llu",
            res->head.msg_type, res->head.msg_size, res->head.msg_seq, res->head.src_msg_seq);
        CM_FREE_PTR(res);
        return;
    }
    CT_LOG_DEBUG_INF("end proc get res data res msg, msg type %u, msg size %u, msg seq %llu, msg src seq %llu",
        msg->msg_type, msg->msg_size, msg->msg_seq, msg->src_msg_seq);
}

static void cms_cli_proc_msg_res_hb(cms_packet_head_t* msg)
{
    static uint64 version = CT_INVALID_ID64;
    CT_LOG_DEBUG_INF("begin proc hb res msg, msg type %u, msg size %u, msg seq %llu, msg src seq %llu",
        msg->msg_type, msg->msg_size, msg->msg_seq, msg->src_msg_seq);
    cms_cli_msg_res_hb_t* res = (cms_cli_msg_res_hb_t*)msg;
    if (msg->msg_size != sizeof(cms_cli_msg_res_hb_t)) {
        CT_LOG_RUN_ERR("proc msg res hb msg size %u invalid.", msg->msg_size);
        return;
    }
    if (version != res->version && res->version != 0) {
        cms_res_status_list_t* res_list = cm_malloc(sizeof(cms_res_status_list_t));
        if (res_list == NULL) {
            CT_LOG_RUN_ERR("alloc memory faild.");
            return;
        }

        if (cms_get_res_stat_list(res_list) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("cms get res stat list faild");
            cm_free(res_list);
            return;
        }

        version = res_list->version;

        if (g_notify_func != NULL) {
            CT_LOG_DEBUG_INF("begin invoke notify function");
            g_notify_func(res_list);
            CT_LOG_DEBUG_INF("end invoke notify function");
        }

        cm_free(res_list);
    }
    CT_LOG_DEBUG_INF("end proc hb res msg, msg type %u, msg size %u, msg seq %llu, msg src seq %llu",
        msg->msg_type, msg->msg_size, msg->msg_seq, msg->src_msg_seq);
}

static status_t cms_cli_iof_kick_res(status_t result)
{
    cms_cli_msg_res_iof_kick_t res;
    res.head.msg_size = sizeof(cms_cli_msg_res_iof_kick_t);
    res.head.msg_type = CMS_CLI_MSG_RES_IOF_KICK;
    res.head.msg_version = CMS_MSG_VERSION;
    res.head.msg_seq = cms_uds_cli_get_msg_seq();
    res.head.src_msg_seq = 0;
    res.head.dest_node = g_node_id;
    res.head.src_node = g_node_id;
    res.result = result;

    timeval_t tv_begin;
    cantian_record_io_stat_begin(IO_RECORD_EVENT_CMS_UDS_IOF_KICK_RES, &tv_begin);
    status_t ret = cms_uds_cli_send(&res.head, 1000);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("send iof kick res msg failed");
        cantian_record_io_stat_end(IO_RECORD_EVENT_CMS_UDS_IOF_KICK_RES, &tv_begin, IO_STAT_FAILED);
        return CT_ERROR;
    }
    cantian_record_io_stat_end(IO_RECORD_EVENT_CMS_UDS_IOF_KICK_RES, &tv_begin, IO_STAT_SUCCESS);
    CT_LOG_RUN_INF("send iof kick res msg succeed, msg type %u, msg seq %llu", res.head.msg_type, res.head.msg_seq);
    return CT_SUCCESS;
}

static void cms_cli_proc_msg_req_dbs_iof_kick(cms_packet_head_t* msg)
{
    int32 ret = CT_SUCCESS;
    iof_info_t iof = {0};
    cms_cli_msg_req_iof_kick_t* req = (cms_cli_msg_req_iof_kick_t*)msg;
    if (msg->msg_size != sizeof(cms_cli_msg_req_iof_kick_t)) {
        CT_LOG_RUN_ERR("proc msg req iof kick msg size %u invalid.", msg->msg_size);
        return;
    }
    CT_LOG_DEBUG_INF("begin proc msg req iof kick");
    iof.nodeid = req->node_id;
    iof.sn = req->sn;
    cm_dbs_cfg_s *cfg = cm_dbs_get_cfg();
    ret = cm_dbs_get_ns_name(DEV_TYPE_PGPOOL, &iof.nsName);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("get dbstore page pool nsid failed, namespace name %s, ret %d.", cfg->ns, ret);
        return;
    }

    iof.termid = 0;
    ret = cm_dbs_iof_kick(&iof);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("proc msg req iof kick failed, kick node %u, namespace name %s, ret %d.", req->node_id, cfg->ns,
            ret);
    }

    (void)cms_cli_iof_kick_res(ret);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("proc msg req iof kick failed.");
        return;
    }
    CT_LOG_DEBUG_INF("proc msg req iof kick succ");
}

static void cms_cli_proc_msg_req_file_iof_kick(cms_packet_head_t* msg)
{
    int32 ret = CT_SUCCESS;
    cms_cli_msg_req_iof_kick_t* req = (cms_cli_msg_req_iof_kick_t*)msg;

    CT_LOG_DEBUG_INF("begin proc msg req iof kick");
    ret = cm_file_iof_kick_by_inst_id(req->node_id);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("proc msg req iof kick failed, kick node %u, ret %d.", req->node_id, ret);
    }

    (void)cms_cli_iof_kick_res(ret);
    CT_LOG_DEBUG_INF("proc msg req iof kick succ");
}

static void cms_cli_proc_msg_req_iof_kick(cms_packet_head_t* msg)
{
    if (cm_dbs_is_enable_dbs() == CT_TRUE) {
        cms_cli_proc_msg_req_dbs_iof_kick(msg);
    } else {
        cms_cli_proc_msg_req_file_iof_kick(msg);
    }
}

static void cms_cli_proc_msg(cms_packet_head_t* msg)
{
    switch (msg->msg_type) {
        case CMS_CLI_MSG_RES_STAT_CHG: {
            cms_cli_proc_msg_res_stat_chg(msg);
            break;
        }
        case CMS_CLI_MSG_RES_HB: {
            cms_cli_proc_msg_res_hb(msg);
            break;
        }
        case CMS_CLI_MSG_RES_GET_RES_STAT: {
            cms_cli_proc_msg_get_res_stat(msg);
            break;
        }
        case CMS_CLI_MSG_RES_SET_RES_DATA: {
            cms_cli_proc_msg_set_res_data(msg);
            break;
        }
        case CMS_CLI_MSG_RES_GET_RES_DATA: {
            cms_cli_proc_msg_get_res_data(msg);
            break;
        }
        case CMS_CLI_MSG_RES_SET_WORK_STAT: {
            cms_cli_proc_msg_set_work_stat(msg);
            break;
        }
        case CMS_CLI_MSG_REQ_IOF_KICK: {
            cms_cli_proc_msg_req_iof_kick(msg);
            break;
        }
        case CMS_CLI_MSG_RES_DIS_CONN: {
            cms_cli_proc_msg_res_disconn(msg);
            break;
        }
        case CMS_CLI_MSG_REQ_UPGRADE: {
            cms_cli_proc_msg_req_upgrade(msg);
            break;
        }
        default:
            CT_LOG_RUN_ERR("unknown message type:%d", (int32)msg->msg_type);
    }
}

static void cms_uds_cli_retry_conn(void)
{
    status_t ret = CT_SUCCESS;
    for (int32 i = 0; i < CMS_RETRY_CONN_COUNT; i++) {
        if (g_cli_conn_try == CT_FALSE) {
            return;
        }
        cms_uds_cli_info_t cms_uds_cli_info = { g_res_type, g_inst_id, CT_TRUE, CMS_CLI_RES };
        ret = cms_uds_cli_connect(&cms_uds_cli_info, NULL);
        if (ret == CT_SUCCESS) {
            CT_LOG_RUN_ERR("cms cli retry conn succ, i %d", i);
            return;
        }
        CT_LOG_RUN_ERR("cms cli retry conn failed, ret %d, i %d", ret, i);
        cm_sleep(CMS_RETRY_CONN_INTERVAL);
    }
    
    CM_ABORT_REASONABLE(0, "[CMS_CLI] ABORT INFO: cms cli conn retry failed");
}

static void cms_cli_hb_entry(thread_t *thread)
{
    g_cli_hbt_term = CT_FALSE;
    thread->closed = CT_FALSE;
    status_t ret = CT_SUCCESS;

    CT_LOG_RUN_INF("start cli hb etnry thread");
    while (!thread->closed) {
        ret = cms_cli_hb();
        if (ret != CT_SUCCESS) {
            CT_LOG_RUN_ERR("cms cli send hb failed");
        }
        cm_sleep(CMS_CLI_UDS_HB_INTERVAL);
    }

    g_cli_hbt_term = CT_TRUE;
    CT_LOG_RUN_INF("end cli hb etnry thread");
}

static void cms_cli_recv_entry(thread_t *thread)
{
    g_cli_recvt_term = CT_FALSE;
    thread->closed = CT_FALSE;
    static char msg_buf[CMS_MAX_MSG_SIZE] = {0};
    status_t ret = CT_SUCCESS;

    CT_LOG_RUN_INF("start cli recv etnry thread");
    while (!thread->closed) {
        CT_LOG_DEBUG_INF("begin cms cli recv msg");
        ret = cms_uds_cli_recv((cms_packet_head_t*)msg_buf, CMS_MAX_MSG_SIZE, CMS_CLI_UDS_RECV_TMOUT);
        if (ret != CT_SUCCESS) {
            CT_LOG_RUN_ERR("cms cli recv msg failed, ret %d", ret);
            cms_uds_cli_sock_close();
            cms_uds_cli_retry_conn();
            continue;
        }

        cms_packet_head_t* head = (cms_packet_head_t*)msg_buf;
        CT_LOG_DEBUG_INF("cms cli recv msg, msg type %u, msg seg %llu, msg src seq %llu, msg size %u",
            head->msg_type, head->msg_seq, head->src_msg_seq, head->msg_size);
        biqueue_node_t* node = cms_que_alloc_node_ex((char*)head, head->msg_size);
        if (node == NULL) {
            CT_LOG_RUN_ERR("cms que alloc node failed");
            continue;
        }
        cms_enque(&g_cli_recv_que, node);
    }

    g_cli_recvt_term = CT_TRUE;
    CT_LOG_RUN_INF("end cli recv etnry thread");
}

static void cms_cli_worker_entry(thread_t *thread)
{
    g_cli_workert_term = CT_FALSE;
    thread->closed = CT_FALSE;
    biqueue_node_t *node = NULL;
    cms_packet_head_t* msg = NULL;

    CT_LOG_DEBUG_INF("start cli worker entry thread");
    while (!thread->closed) {
        node = cms_deque(&g_cli_recv_que);
        if (node == NULL) {
            CT_LOG_DEBUG_INF("cms cli worker entry get nothing, continue to loop");
            continue;
        }

        msg = (cms_packet_head_t*)cms_que_node_data(node);
        CT_LOG_DEBUG_INF("cms cli worker etnry proc msg, msg type %u, msg seq %llu, msg src seq %llu",
            msg->msg_type, msg->msg_seq, msg->src_msg_seq);
        cms_cli_proc_msg(msg);
        cms_que_free_node(node);
    }

    g_cli_workert_term = CT_TRUE;
    CT_LOG_DEBUG_INF("end cli worker entry thread");
}

static status_t cms_res_inst_register_inner(const char res_type[CMS_MAX_RES_TYPE_LEN], uint8 inst_id,
    res_init_info_t *res_init_info, cms_notify_func_t notify_func, cms_master_op_t master_func)
{
    status_t ret = CT_SUCCESS;
    errno_t err = EOK;

    if (g_inst_id == inst_id) {
        CT_LOG_RUN_ERR("resource is already registered, instance id %d", (int32)g_inst_id);
        return CT_ERROR;
    }

    err = strcpy_s(g_res_type, CMS_MAX_RES_TYPE_LEN, res_type);
    MEMS_RETURN_IFERR(err);
    g_inst_id = inst_id;
    g_notify_func = notify_func;
    g_master_func = master_func;

    cms_uds_cli_info_t cms_uds_cli_info = { res_type, inst_id, CT_FALSE, CMS_CLI_RES };
    ret = cms_uds_cli_connect(&cms_uds_cli_info, res_init_info);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("cms cli connect to server failed, ret %d", ret);
        return ret;
    }

    ret = cm_create_thread(cms_cli_hb_entry, CT_DFLT_THREAD_STACK_SIZE, NULL, &g_cli_hb_thread);
    if (ret != CT_SUCCESS) {
        cms_uds_cli_sock_close();
        CT_LOG_RUN_ERR("start cms cli hb entry thread create failed, ret %d", ret);
        return ret;
    }

    ret = cm_create_thread(cms_cli_recv_entry, CT_DFLT_THREAD_STACK_SIZE, NULL, &g_cli_recv_thread);
    if (ret != CT_SUCCESS) {
        cms_uds_cli_sock_close();
        CT_LOG_RUN_ERR("start cms cli recv entry thread create failed, ret %d", ret);
        return ret;
    }

    for (uint32 i = 0; i < CMS_CLI_WORK_ENTRY_COUNT; i++) {
        ret = cm_create_thread(cms_cli_worker_entry, CT_DFLT_THREAD_STACK_SIZE, NULL, &g_cli_worker_thread);
        if (ret != CT_SUCCESS) {
            cms_uds_cli_sock_close();
            CT_LOG_RUN_ERR("start cms cli worker entry thread create failed, ret %d", ret);
            return ret;
        }
    }
    CT_LOG_RUN_INF("register res to cms succ");
    return CT_SUCCESS;
}

status_t cms_res_inst_register(const char res_type[CMS_MAX_RES_TYPE_LEN], uint8 inst_id, res_init_info_t *res_init_info,
    cms_notify_func_t notify_func, cms_master_op_t master_func)
{
    cm_thread_lock(&g_cli_lock);
    status_t ret = cms_res_inst_register_inner(res_type, inst_id, res_init_info, notify_func, master_func);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("register resource failed, res type %s, instance id %d", g_res_type, (int)g_inst_id);
        g_res_type[0] = 0;
        g_inst_id = -1;
        g_notify_func = NULL;
        g_master_func = NULL;
    } else {
        CT_LOG_RUN_INF("register resource successful, res type %s, instance id %d", g_res_type, (int)g_inst_id);
    }
    cm_thread_unlock(&g_cli_lock);

    return ret;
}

status_t cms_send_disconn_req(void)
{
    status_t ret = CT_SUCCESS;
    errno_t err = EOK;

    CT_LOG_RUN_INF("begin send disconnect req to cms");
    cms_cli_msg_req_dis_conn_t req;
    req.head.msg_size = sizeof(cms_cli_msg_req_dis_conn_t);
    req.head.msg_type = CMS_CLI_MSG_REQ_DIS_CONN;
    req.head.msg_version = CMS_MSG_VERSION;
    req.head.msg_seq = cms_uds_cli_get_msg_seq();
    req.head.src_msg_seq = 0;
    req.head.dest_node = g_node_id;
    req.head.src_node = g_node_id;
    err = strcpy_s(req.res_type, CMS_MAX_RES_TYPE_LEN, g_res_type);
    if (err != EOK) {
        CT_LOG_RUN_ERR("strcpy_s failed, err %d, errno %d[%s]", err, errno, strerror(errno));
        return CT_ERROR;
    }
    req.inst_id = g_inst_id;

    timeval_t tv_begin;
    cms_cli_msg_res_dis_conn_t res;
    cantian_record_io_stat_begin(IO_RECORD_EVENT_CMS_UDS_UNREGISTER, &tv_begin);
    ret = cms_uds_cli_request(&req.head, &res.head, sizeof(cms_cli_msg_res_dis_conn_t),
        CMS_CLIENT_REQUEST_TIMEOUT);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("cms cli uds request failed, ret %d", ret);
        cantian_record_io_stat_end(IO_RECORD_EVENT_CMS_UDS_UNREGISTER, &tv_begin, IO_STAT_FAILED);
        return ret;
    }
    cantian_record_io_stat_end(IO_RECORD_EVENT_CMS_UDS_UNREGISTER, &tv_begin, IO_STAT_SUCCESS);
    if (res.result != CT_SUCCESS) {
        CT_LOG_RUN_ERR("send disconnect msg failed, result %d", res.result);
        return CT_ERROR;
    }

    CT_LOG_RUN_INF("disconnect from cms succ");
    return CT_SUCCESS;
}

status_t cms_res_inst_unregister_inner(void)
{
    status_t ret = CT_SUCCESS;

    g_cli_conn_try = CT_FALSE;
    ret = cms_send_disconn_req();
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("cms send disconnect req to cms failed, ret %d", ret);
    }

    g_cli_recv_thread.closed = CT_TRUE;
    while (!g_cli_recvt_term) {
        cm_sleep(CMS_CLI_SLEEP_INTERVAL);
    }

    g_cli_worker_thread.closed = CT_TRUE;
    while (!g_cli_workert_term) {
        cm_sleep(CMS_CLI_SLEEP_INTERVAL);
    }

    g_cli_hb_thread.closed = CT_TRUE;
    while (!g_cli_hbt_term) {
        cm_sleep(CMS_CLI_SLEEP_INTERVAL);
    }

    cms_uds_cli_destory();
    g_res_type[0] = '\0';
    g_inst_id = -1;
    g_notify_func = NULL;
    g_master_func = NULL;

    CT_LOG_RUN_INF("unregister from cms succ");
    return CT_SUCCESS;
}

status_t cms_res_inst_unregister(void)
{
    cm_thread_lock(&g_cli_lock);
    status_t ret = cms_res_inst_unregister_inner();
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("unregister resource failed");
    } else {
        CT_LOG_RUN_INF("unregister resource successful");
    }
    cm_thread_unlock(&g_cli_lock);
    return ret;
}

status_t cms_set_res_work_stat(uint8 stat)
{
    if (g_inst_id == -1) {
        CT_LOG_RUN_ERR("resource instance not be registered");
        return CT_ERROR;
    }

    cms_cli_msg_req_set_work_stat_t req;
    req.head.msg_size = sizeof(cms_cli_msg_req_set_work_stat_t);
    req.head.msg_type = CMS_CLI_MSG_REQ_SET_WORK_STAT;
    req.head.msg_version = CMS_MSG_VERSION;
    req.head.msg_seq = cms_uds_cli_get_msg_seq();
    req.head.src_msg_seq = 0;
    req.head.dest_node = g_node_id;
    req.head.src_node = g_node_id;
    errno_t err = strcpy_s(req.res_type, CMS_MAX_RES_TYPE_LEN, g_res_type);
    MEMS_RETURN_IFERR(err);
    req.inst_id = g_inst_id;
    req.work_stat = stat;

    cms_cli_msg_res_set_work_stat_t res;
    timeval_t tv_begin;
    cantian_record_io_stat_begin(IO_RECORD_EVENT_CMS_UDS_SET_WORK_STAT, &tv_begin);

    status_t ret = cms_uds_cli_request(&req.head, &res.head, sizeof(cms_cli_msg_res_set_work_stat_t),
        CMS_CLIENT_REQUEST_TIMEOUT);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("cms set res work stat msg failed");
        cantian_record_io_stat_end(IO_RECORD_EVENT_CMS_UDS_SET_WORK_STAT, &tv_begin, IO_STAT_FAILED);
        return ret;
    }
    cantian_record_io_stat_end(IO_RECORD_EVENT_CMS_UDS_SET_WORK_STAT, &tv_begin, IO_STAT_SUCCESS);

    if (res.result != CT_SUCCESS) {
        CT_LOG_RUN_ERR("set data failed, work stat %d, msg type %u, msg req %llu",
            (int32)stat, res.head.msg_type, res.head.msg_seq);
        return CT_ERROR;
    }

    CT_LOG_RUN_INF("set work stat succ, stat %d", (int32)stat);
    return CT_SUCCESS;
}

status_t cms_get_res_stat_list(cms_res_status_list_t * res_list)
{
    if (g_inst_id == -1) {
        CT_LOG_RUN_ERR("resource instance not be registered");
        return CT_ERROR;
    }

    return cms_get_res_stat_list1(g_res_type, res_list);
}

status_t cms_get_res_stat_list1(const char* res_type, cms_res_status_list_t* res_list)
{
    static date_t last_call = 0;
    date_t now = cm_monotonic_now();
    if (now < last_call + MICROSECS_PER_SECOND) {
        cm_sleep((last_call + MICROSECS_PER_SECOND - now) / MICROSECS_PER_MILLISEC);
    }
    last_call = cm_monotonic_now();

    cms_cli_msg_req_get_res_stat_t req;
    req.head.msg_size = sizeof(cms_cli_msg_req_get_res_stat_t);
    req.head.msg_type = CMS_CLI_MSG_REQ_GET_RES_STAT;
    req.head.msg_version = CMS_MSG_VERSION;
    req.head.msg_seq = cms_uds_cli_get_msg_seq();
    req.head.src_msg_seq = 0;
    req.head.dest_node = g_node_id;
    req.head.src_node = g_node_id;
    errno_t err = strcpy_s(req.res_type, CMS_MAX_RES_TYPE_LEN, res_type);
    MEMS_RETURN_IFERR(err);

    cms_cli_msg_res_get_res_stat_t res_stat;
    timeval_t tv_begin;
    cantian_record_io_stat_begin(IO_RECORD_EVENT_CMS_UDS_GET_STAT_LIST1, &tv_begin);
    status_t ret = cms_uds_cli_request(&req.head, &res_stat.head, sizeof(cms_cli_msg_res_get_res_stat_t),
        CMS_CLIENT_REQUEST_TIMEOUT);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("cms cli uds request failed");
        cantian_record_io_stat_end(IO_RECORD_EVENT_CMS_UDS_GET_STAT_LIST1, &tv_begin, IO_STAT_FAILED);
        return ret;
    }
    cantian_record_io_stat_end(IO_RECORD_EVENT_CMS_UDS_GET_STAT_LIST1, &tv_begin, IO_STAT_SUCCESS);
    if (res_stat.result != CT_SUCCESS) {
        CT_LOG_RUN_ERR("cms cli get res stat failed, result %d", res_stat.result);
        return CT_ERROR;
    }

    err = memcpy_s(res_list, sizeof(cms_res_status_list_t), &res_stat.stat, sizeof(cms_res_status_list_t));
    MEMS_RETURN_IFERR(err);

    CT_LOG_DEBUG_INF("get res stat succ, version %lld, inst count %d", res_list->version, res_list->inst_count);
    for (int32 i = 0; i < res_list->inst_count; i++) {
        CT_LOG_DEBUG_INF("res stat, instid %d, node id %d, stat %d, wrok stat %d",
            (int32)res_list->inst_list[i].inst_id, (int32)res_list->inst_list[i].node_id,
            (int32)res_list->inst_list[i].stat, (int32)res_list->inst_list[i].work_stat);
    }

    return CT_SUCCESS;
}

cms_cli_msg_req_set_data_t* cms_get_new_set_data_req(uint32 slot_id, char* data, uint32 size, uint64 old_version)
{
    cms_cli_msg_req_set_data_t* req = malloc(sizeof(cms_cli_msg_req_set_data_t));
    if (req == NULL) {
        CT_LOG_RUN_ERR("malloc failed, size %u", (uint32)sizeof(cms_cli_msg_req_set_data_t));
        return NULL;
    }
    req->head.msg_type = CMS_CLI_MSG_REQ_SET_RES_DATA;
    req->head.msg_size = sizeof(cms_cli_msg_req_set_data_t) - (sizeof(req->data) - size);
    req->head.msg_version = CMS_MSG_VERSION;
    req->head.msg_seq = cms_uds_cli_get_msg_seq();
    req->head.src_msg_seq = 0;
    req->head.dest_node = g_node_id;
    req->head.src_node = g_node_id;

    errno_t err = strcpy_s(req->res_type, CMS_MAX_RES_TYPE_LEN, g_res_type);
    if (err != EOK) {
        CT_LOG_RUN_ERR("strcpy_s failed, err %d", err);
        CM_FREE_PTR(req);
        return NULL;
    }
    err = memcpy_s(req->data, CMS_MAX_RES_DATA_SIZE, data, size);
    if (err != EOK) {
        CT_LOG_RUN_ERR("memcpy_s failed, err %d", err);
        CM_FREE_PTR(req);
        return NULL;
    }
    req->slot_id = slot_id;
    req->data_size = size;
    req->old_version = old_version;

    return req;
}

status_t cms_set_res_data_new(uint32 slot_id, char* data, uint32 size, uint64 old_version)
{
    if (g_inst_id == -1) {
        CT_LOG_RUN_ERR("resource instance not be registered");
        return CT_ERROR;
    }

    if (slot_id >= CMS_MAX_RES_SLOT_COUNT) {
        CT_LOG_RUN_ERR("invalid slot id, slot id %u", slot_id);
        return CT_ERROR;
    }

    if (size >= CMS_MAX_RES_DATA_SIZE) {
        CT_LOG_RUN_ERR("invalid size, size %u", size);
        return CT_ERROR;
    }

    cms_cli_msg_req_set_data_t* req = cms_get_new_set_data_req(slot_id, data, size, old_version);
    if (req == NULL) {
        CT_LOG_RUN_ERR("get new set data req failed");
        return CT_ERROR;
    }

    cms_cli_msg_res_set_data_t res;
    errno_t err = memset_s(&res, sizeof(cms_cli_msg_res_set_data_t), 0, sizeof(cms_cli_msg_res_set_data_t));
    if (err != EOK) {
        CT_LOG_RUN_ERR("memset_s failed, err %d", err);
        CM_FREE_PTR(req);
        return CT_ERROR;
    }

    timeval_t tv_begin;
    cantian_record_io_stat_begin(IO_RECORD_EVENT_CMS_UDS_SET_DATA_NEW, &tv_begin);
    status_t ret = cms_uds_cli_request(&req->head, &res.head, sizeof(cms_cli_msg_res_set_data_t),
        CMS_CLIENT_REQUEST_TIMEOUT);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("cms socket send msg failed, ret %d", ret);
        CM_FREE_PTR(req);
        cantian_record_io_stat_end(IO_RECORD_EVENT_CMS_UDS_SET_DATA_NEW, &tv_begin, IO_STAT_FAILED);
        return ret;
    }
    cantian_record_io_stat_end(IO_RECORD_EVENT_CMS_UDS_SET_DATA_NEW, &tv_begin, IO_STAT_SUCCESS);
    CM_FREE_PTR(req);

    if (res.result != CT_SUCCESS) {
        CT_LOG_RUN_ERR("set data failed, res info %s", res.info);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t cms_handle_get_data_res(cms_cli_msg_res_get_data_t *res, char* data, uint32 max_size,
    uint32 *size, uint64 *version)
{
    errno_t err = EOK;

    if (res->result != CT_SUCCESS) {
        CT_LOG_RUN_ERR("get resource data failed");
        return CT_ERROR;
    }

    err = memcpy_s(data, max_size, res->data, res->data_size);
    if (err != EOK) {
        CT_LOG_RUN_ERR("memcpy_s failed, err %d, errno %d[%s]",
            err, errno, strerror(errno));
        return CT_ERROR;
    }

    if (size != NULL) {
        *size = res->data_size;
    }

    if (version != NULL) {
        *version = res->version;
    }
    return CT_SUCCESS;
}

status_t cms_get_res_data_new(uint32 slot_id, char* data, uint32 max_size, uint32* size, uint64* new_version)
{
    if (g_inst_id == -1) {
        CT_LOG_RUN_ERR("resource instance not be registered");
        return CT_ERROR;
    }

    if (slot_id >= CMS_MAX_RES_SLOT_COUNT) {
        CT_LOG_RUN_ERR("invalid slot id, slot id %u", slot_id);
        return CT_ERROR;
    }

    cms_cli_msg_req_get_data_t req;
    req.head.msg_size = sizeof(cms_cli_msg_req_get_data_t);
    req.head.msg_type = CMS_CLI_MSG_REQ_GET_RES_DATA;
    req.head.msg_version = CMS_MSG_VERSION;
    req.head.msg_seq = cms_uds_cli_get_msg_seq();
    req.head.src_msg_seq = 0;
    req.head.dest_node = g_node_id;
    req.head.src_node = g_node_id;
    req.slot_id = slot_id;
    errno_t ret = strcpy_s(req.res_type, CMS_MAX_RES_TYPE_LEN, g_res_type);
    MEMS_RETURN_IFERR(ret);

    cms_cli_msg_res_get_data_t* res = malloc(sizeof(cms_cli_msg_res_get_data_t));
    if (res == NULL) {
        CT_LOG_RUN_ERR("malloc failed, size %u", (uint32)sizeof(cms_cli_msg_res_get_data_t));
        return CT_ERROR;
    }
    ret = memset_s(res, sizeof(cms_cli_msg_res_get_data_t), 0, sizeof(cms_cli_msg_res_get_data_t));
    if (ret != EOK) {
        CT_LOG_RUN_ERR("memset_s failed, ret %d", ret);
        CM_FREE_PTR(res);
        return CT_ERROR;
    }

    timeval_t tv_begin;
    cantian_record_io_stat_begin(IO_RECORD_EVENT_CMS_UDS_GET_DATA_NEW, &tv_begin);
    ret = cms_uds_cli_request(&req.head, &res->head, sizeof(cms_cli_msg_res_get_data_t), CMS_CLIENT_REQUEST_TIMEOUT);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("cms socket send msg failed, ret %d", ret);
        CM_FREE_PTR(res);
        cantian_record_io_stat_end(IO_RECORD_EVENT_CMS_UDS_GET_DATA_NEW, &tv_begin, IO_STAT_FAILED);
        return ret;
    }
    cantian_record_io_stat_end(IO_RECORD_EVENT_CMS_UDS_GET_DATA_NEW, &tv_begin, IO_STAT_SUCCESS);

    ret = cms_handle_get_data_res(res, data, max_size, size, new_version);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("cms handle get data res failed, ret %d", ret);
        CM_FREE_PTR(res);
        return ret;
    }
    CM_FREE_PTR(res);
    return CT_SUCCESS;
}

status_t cms_set_res_data(uint32 slot_id, char* data, uint32 size)
{
    return cms_set_res_data_new(slot_id, data, size, CT_INVALID_ID64);
}

status_t cms_get_res_data(uint32 slot_id, char* data, uint32 max_size, uint32* size)
{
    return cms_get_res_data_new(slot_id, data, max_size, size, NULL);
}

void cms_res_inst_register_upgrade(cms_upgrade_op_t upgrade_func)
{
    g_upgrade_func = upgrade_func;
}