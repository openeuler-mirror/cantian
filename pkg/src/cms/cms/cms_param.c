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
 * cms_param.c
 *
 *
 * IDENTIFICATION
 * src/cms/cms/cms_param.c
 *
 * -------------------------------------------------------------------------
 */
#include "cms_interface.h"
#include "cms_param.h"
#include "cms_mes.h"
#include "cm_config.h"
#include "cms_defs.h"
#include "cm_system.h"
#include "cm_file.h"
#include "cs_pipe.h"
#include "mes_func.h"
#include "cm_io_record.h"
#include "mes_config.h"
#include "mes_func.h"
#include "cm_dbs_intf.h"
#include "cms_log.h"
#include "cm_file_iofence.h"

config_item_t g_cms_params[] = {
    // name (30B)               isdefault readonly  defaultvalue value runtime_value description range        datatype
    // comment
    // -------------            --------- --------  ------------ ----- ------------- ----------- -----        --------
    // -----
    { "NODE_ID",                GS_TRUE,  ATTR_NONE, "",          NULL, NULL,          "-",       "-",        "GS_TYPE_INTEGER", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    { "GCC_TYPE",               GS_TRUE,  ATTR_NONE, "",          NULL, NULL,          "-",       "-",        "GS_TYPE_STRING",  NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    { "GCC_HOME",               GS_TRUE,  ATTR_NONE, "",          NULL, NULL,          "-",       "-",        "GS_TYPE_STRING",  NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    { "_IP",                    GS_TRUE,  ATTR_NONE, "",          NULL, NULL,          "-",       "-",        "GS_TYPE_STRING",  NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    { "_PORT",                  GS_TRUE,  ATTR_NONE, "",          NULL, NULL,          "-",       "-",        "GS_TYPE_STRING",  NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_LOG_BACKUP_FILE_COUNT",  GS_TRUE,  ATTR_NONE, "10",        NULL, NULL,          "-",       "[0,128]",  "GS_TYPE_INTEGER", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_AUDIT_BACKUP_FILE_COUNT", GS_TRUE,  ATTR_NONE, "10",        NULL, NULL,          "-",       "[0,128]",  "GS_TYPE_INTEGER", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_LOG_MAX_FILE_SIZE",      GS_TRUE,  ATTR_NONE, "10M",       NULL, NULL,          "-",       "[1M,4G]",  "GS_TYPE_INTEGER", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_AUDIT_MAX_FILE_SIZE",    GS_TRUE,  ATTR_NONE, "10M",       NULL, NULL,          "-",       "[1M,4G]",  "GS_TYPE_INTEGER", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_LOG_LEVEL",              GS_TRUE,  ATTR_NONE, "255",       NULL, NULL,          "-",       "[0,-)",    "GS_TYPE_INTEGER", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_LOG_FILE_PERMISSIONS",   GS_TRUE,  ATTR_NONE, "640",       NULL, NULL,          "-",       "[600-777]", "GS_TYPE_INTEGER", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_LOG_PATH_PERMISSIONS",   GS_TRUE,  ATTR_NONE, "750",       NULL, NULL,          "-",       "[700-777]", "GS_TYPE_INTEGER", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"WORKER_THREAD_COUNT",     GS_TRUE,  ATTR_NONE, "20",        NULL, NULL,          "-",       "[1,64]",   "GS_TYPE_INTEGER", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"UDS_WORKER_THREAD_COUNT", GS_TRUE,  ATTR_NONE, "20",        NULL, NULL,          "-",       "[1,64]",   "GS_TYPE_INTEGER", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_SPLIT_BRAIN",            GS_TRUE,  ATTR_NONE, "FALSE",     NULL, NULL,          "-",       "-",        "GS_TYPE_STRING",  NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_DETECT_DISK_TIMEOUT",    GS_TRUE,  ATTR_NONE, "3600",         NULL, NULL,          "-",       "-",        "GS_TYPE_INTEGER", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_DISK_DETECT_FILE",       GS_TRUE,  ATTR_NONE, "",          NULL, NULL,          "-",       "-",        "GS_TYPE_INTEGER", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_STOP_RERUN_CMS_SCRIPT",  GS_TRUE,  ATTR_NONE, "",          NULL, NULL,          "-",       "-",        "GS_TYPE_STRING",  NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_EXIT_NUM_COUNT_FILE",    GS_TRUE,  ATTR_NONE, "",          NULL, NULL,          "-",       "-",        "GS_TYPE_STRING",  NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_CMS_NODE_FAULT_THRESHOLD", GS_TRUE,  ATTR_NONE, "5",         NULL, NULL,          "-",       "-",        "GS_TYPE_INTEGER", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_CMS_MES_THREAD_NUM",     GS_TRUE,  ATTR_NONE, "5",         NULL, NULL,          "-",       "-",        "GS_TYPE_INTEGER", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_CMS_MES_MAX_SESSION_NUM", GS_TRUE,  ATTR_NONE, "40",       NULL, NULL,          "-",       "-",        "GS_TYPE_INTEGER", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_CMS_MES_MESSAGE_POOL_COUNT", GS_TRUE,  ATTR_NONE, "1",     NULL, NULL,          "-",       "-",        "GS_TYPE_INTEGER", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_CMS_MES_MESSAGE_QUEUE_COUNT", GS_TRUE,  ATTR_NONE, "1",    NULL, NULL,          "-",       "-",        "GS_TYPE_INTEGER", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_CMS_MES_MESSAGE_BUFF_COUNT", GS_TRUE,  ATTR_NONE, "4096",  NULL, NULL,          "-",       "-",        "GS_TYPE_INTEGER", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_CMS_MES_MESSAGE_CHANNEL_NUM", GS_TRUE,  ATTR_NONE, "1",    NULL, NULL,          "-",       "-",        "GS_TYPE_INTEGER", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_CMS_GCC_BAK",               GS_TRUE,  ATTR_NONE, "NULL",          NULL, NULL,          "-",       "-",        "GS_TYPE_STRING",  NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_USE_DBSTOR",            GS_TRUE,  ATTR_NONE, "FALSE",     NULL, NULL,          "-",       "-",        "GS_TYPE_STRING",  NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_DBSTOR_NAMESPACE",      GS_TRUE,  ATTR_NONE, "",          NULL, NULL,          "-",       "-",        "GS_TYPE_STRING",  NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_CMS_MES_PIPE_TYPE", GS_TRUE,  ATTR_NONE, "TCP",    NULL, NULL,          "-",       "-",        "GS_TYPE_STRING", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_CLUSTER_ID", GS_TRUE,  ATTR_NONE, "0",    NULL, NULL,          "-",       "-",        "GS_TYPE_INTEGER", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_CMS_MES_CRC_CHECK_SWITCH", GS_TRUE,  ATTR_NONE, "TRUE",    NULL, NULL,          "-",       "-",        "GS_TYPE_BOOLEAN", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    { "SHARED_PATH",          GS_TRUE,  ATTR_NONE, "",          NULL, NULL,          "-",       "-",        "GS_TYPE_STRING",  NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_CMS_MES_SSL_SWITCH",        GS_TRUE,  ATTR_NONE, "FALSE",    NULL, NULL,       "-",       "-",        "GS_TYPE_BOOLEAN", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_CMS_MES_SSL_CRT_KEY_PATH",  GS_TRUE,  ATTR_NONE, "",         NULL, NULL,       "-",       "-",        "GS_TYPE_STRING",  NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_CMS_MES_SSL_KEY_PWD",       GS_TRUE,  ATTR_NONE, "",         NULL, NULL,       "-",       "-",         "GS_TYPE_STRING", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL}
};

cms_param_t  g_param;
const cms_param_t* g_cms_param = &g_param;

status_t cms_get_cms_home(void)
{
    int32 is_home_exist;

    errno_t ret = strcpy_s(g_param.cms_home, sizeof(g_param.cms_home), getenv(CMS_ENV_CMS_HOME));
    if (ret != EOK) {
        return GS_ERROR;
    }

    is_home_exist = cm_dir_exist(g_param.cms_home);
    if (is_home_exist == GS_FALSE) {
        GS_THROW_ERROR(ERR_HOME_PATH_NOT_FOUND, CMS_ENV_CMS_HOME);
        return GS_ERROR;
    }
    is_home_exist = cm_check_exist_special_char(g_param.cms_home, (uint32)strlen(g_param.cms_home));
    if (is_home_exist == GS_TRUE) {
        GS_THROW_ERROR(ERR_INVALID_DIR, CMS_ENV_CMS_HOME);
        return GS_ERROR;
    }
    uint32 path_len = strlen(g_param.cms_home);
    if (path_len > CMS_MAX_PATH_LEN) {
        GS_THROW_ERROR(ERR_FILE_PATH_TOO_LONG, CMS_MAX_PATH_LEN);
        return GS_ERROR;
    }
    cm_trim_home_path(g_param.cms_home, path_len);

    return GS_SUCCESS;
}

status_t cms_get_gcc_home_type(const char* gcc_home, cms_dev_type_t* type)
{
    status_t ret;
#ifdef _WIN32
    struct _stat stat_buf;
    ret = _stat(gcc_home, &stat_buf);
    if (ret != 0) {
        CMS_LOG_ERR("stat failed.errno=%d,%s.", errno, strerror(errno));
        return GS_FALSE;
    }

    if (_S_IFREG == (stat_buf.st_mode & _S_IFREG)) {
        *type = CMS_DEV_TYPE_FILE;
    } else {
        CMS_LOG_ERR("gcc_home is not file.");
        return GS_ERROR;
    }
#else
    struct stat stat_buf;
    ret = stat(gcc_home, &stat_buf);
    if (ret != 0) {
        CMS_LOG_ERR("stat failed.errno=%d,%s.", errno, strerror(errno));
        return GS_FALSE;
    }

    if (S_ISREG(stat_buf.st_mode)) {
        *type = CMS_DEV_TYPE_FILE;
    } else if (S_ISBLK(stat_buf.st_mode)) {
        *type = CMS_DEV_TYPE_SD;
    } else if (S_ISLNK(stat_buf.st_mode)) {
        char path[CMS_FILE_NAME_BUFFER_SIZE];
        ssize_t nbytes = readlink(gcc_home, path, CMS_MAX_FILE_NAME_LEN);
        if (nbytes == -1) {
            CMS_LOG_ERR("readlink failed.errno=%d,%s.", errno, strerror(errno));
            return GS_ERROR;
        }

        return cms_get_gcc_home_type(path, type);
    } else {
        CMS_LOG_ERR("gcc_home is not file,block device or symbol link.");
        return GS_ERROR;
    }
#endif

    return GS_SUCCESS;
}

void cms_get_mes_str_config_value(config_t *cfg)
{
    char *pipe_value = cm_get_config_value(cfg, "_CMS_MES_PIPE_TYPE");
    if (pipe_value == NULL || cm_strcmpi(pipe_value, "UC") == 0) {
        g_param.cms_mes_pipe_type = CS_TYPE_UC;
    } else if (cm_strcmpi(pipe_value, "TCP") == 0) {
        g_param.cms_mes_pipe_type = CS_TYPE_TCP;
    } else {
        g_param.cms_mes_pipe_type = CS_TYPE_TCP;
    }
    CMS_LOG_INF("cms get mes config pipe type is %d", g_param.cms_mes_pipe_type);

    char *switch_value = cm_get_config_value(cfg, "_CMS_MES_CRC_CHECK_SWITCH");
    if (switch_value == NULL || cm_strcmpi(switch_value, "TRUE") == 0) {
        g_param.cms_mes_crc_check_switch = GS_TRUE;
    } else if (cm_strcmpi(switch_value, "FALSE") == 0) {
        g_param.cms_mes_crc_check_switch = GS_FALSE;
    } else {
        g_param.cms_mes_crc_check_switch = GS_TRUE;
    }
    CMS_LOG_INF("cms get mes config crc check switch is %d", g_param.cms_mes_crc_check_switch);
}

status_t cms_get_value_is_valid(char* value, uint32 *val_uint32)
{
    if (value == NULL || cm_str2uint32(value, val_uint32) != GS_SUCCESS) {
        return GS_ERROR;
    } else {
        return GS_SUCCESS;
    }
}

void cms_get_mes_config_value(config_t *cfg)
{
    uint32 val_uint32;
    status_t ret;

    char* value = cm_get_config_value(cfg, "_CMS_MES_THREAD_NUM");
    ret = cms_get_value_is_valid(value, &val_uint32);
    g_param.cms_mes_thread_num = val_uint32;
    if (ret != GS_SUCCESS) {
        g_param.cms_mes_thread_num = CMS_MES_THREAD_NUM;
    }

    value = cm_get_config_value(cfg, "_CMS_MES_MAX_SESSION_NUM");
    ret = cms_get_value_is_valid(value, &val_uint32);
    g_param.cms_mes_max_session_num = val_uint32;
    if (ret != GS_SUCCESS) {
        g_param.cms_mes_max_session_num = MES_MAX_SESSION_NUM;
    }

    value = cm_get_config_value(cfg, "_CMS_MES_MESSAGE_POOL_COUNT");
    ret = cms_get_value_is_valid(value, &val_uint32);
    g_param.cms_mes_msg_pool_count = val_uint32;
    if (ret != GS_SUCCESS) {
        g_param.cms_mes_msg_pool_count = MES_MESSAGE_POOL_COUNT;
    }

    value = cm_get_config_value(cfg, "_CMS_MES_MESSAGE_QUEUE_COUNT");
    ret = cms_get_value_is_valid(value, &val_uint32);
    g_param.cms_mes_msg_queue_count = val_uint32;
    if (ret != GS_SUCCESS) {
        g_param.cms_mes_msg_queue_count = MES_MESSAGE_QUEUE_COUNT;
    }

    value = cm_get_config_value(cfg, "_CMS_MES_MESSAGE_BUFF_COUNT");
    ret = cms_get_value_is_valid(value, &val_uint32);
    g_param.cms_mes_msg_buff_count = val_uint32;
    if (ret != GS_SUCCESS) {
        g_param.cms_mes_msg_buff_count = MES_MESSAGE_BUFF_COUNT;
    }

    value = cm_get_config_value(cfg, "_CMS_MES_MESSAGE_CHANNEL_NUM");
    ret = cms_get_value_is_valid(value, &val_uint32);
    g_param.cms_mes_msg_channel_num = val_uint32;
    if (ret != GS_SUCCESS) {
        g_param.cms_mes_msg_channel_num = MES_MESSAGE_CHANNEL_NUM;
    }

    cms_get_mes_str_config_value(cfg);
}

status_t cms_get_mes_ssl_config(config_t *cfg)
{
    char *ssl_switch_value = cm_get_config_value(cfg, "_CMS_MES_SSL_SWITCH");
    if (ssl_switch_value == NULL || cm_strcmpi(ssl_switch_value, "FALSE") == 0) {
        mes_set_ssl_switch(GS_FALSE);
    } else if (cm_strcmpi(ssl_switch_value, "TRUE") == 0) {
        mes_set_ssl_switch(GS_TRUE);
        char *ssl_crt_key_path = cm_get_config_value(cfg, "_CMS_MES_SSL_CRT_KEY_PATH");
        if (ssl_crt_key_path == NULL) {
            return GS_ERROR;
        }
        char ca_file_path[GS_FILE_NAME_BUFFER_SIZE];
        PRTS_RETURN_IFERR(snprintf_s(ca_file_path, GS_FILE_NAME_BUFFER_SIZE, GS_MAX_FILE_NAME_LEN, "%s/ca.crt", ssl_crt_key_path));
        char cert_file_path[GS_FILE_NAME_BUFFER_SIZE];
        PRTS_RETURN_IFERR(snprintf_s(cert_file_path, GS_FILE_NAME_BUFFER_SIZE, GS_MAX_FILE_NAME_LEN, "%s/mes.crt", ssl_crt_key_path));
        char key_file_path[GS_FILE_NAME_BUFFER_SIZE];
        PRTS_RETURN_IFERR(snprintf_s(key_file_path, GS_FILE_NAME_BUFFER_SIZE, GS_MAX_FILE_NAME_LEN, "%s/mes.key", ssl_crt_key_path));
        GS_RETURN_IFERR(mes_set_ssl_crt_file(ca_file_path, cert_file_path, key_file_path));
        mes_set_ssl_verify_peer(GS_TRUE, GS_FALSE);
        mes_set_ssl_verify_peer(GS_TRUE, GS_TRUE);
        char *enc_pwd = cm_get_config_value(cfg, "_CMS_MES_SSL_KEY_PWD");
        GS_RETURN_IFERR(mes_set_ssl_key_pwd(enc_pwd));
    } else {
        mes_set_ssl_switch(GS_FALSE);
    }
    return GS_SUCCESS;
}

status_t cms_get_dbstore_config_value(config_t *cfg)
{
    char* value;
    status_t ret;
    bool32 enable = GS_FALSE;
    // dataPgSize is not used in the cms
    uint32 dataPgSize = GS_MAX_UINT32;

    value = cm_get_config_value(cfg, "_USE_DBSTOR");
    if (value == NULL || cm_strcmpi(value, "FALSE") == 0) {
        enable = GS_FALSE;
        CMS_LOG_INF("DBStore is not enabled");
        return cm_dbs_set_cfg(enable, dataPgSize, GS_DFLT_CTRL_BLOCK_SIZE, value, 0, GS_FALSE);
    } else if (cm_strcmpi(value, "TRUE") == 0) {
        enable = GS_TRUE;
    } else {
        CMS_LOG_ERR("invalid parameter value of '_USE_DBSTOR':%s", value);
        return GS_ERROR;
    }

    value = cm_get_config_value(cfg, "_DBSTOR_NAMESPACE");
    if (value == NULL) {
        CMS_LOG_ERR("invalid parameter value of '_DBSTOR_NAMESPACE'");
        return GS_ERROR;
    }
    ret = cm_dbs_set_cfg(enable, dataPgSize, GS_DFLT_CTRL_BLOCK_SIZE, value, 0, GS_FALSE);
    if (ret != GS_SUCCESS) {
        CMS_LOG_ERR("cms set dbstore config failed");
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t cms_load_param(void)
{
    char file_name[CMS_FILE_NAME_BUFFER_SIZE];
    errno_t ret;
    char* value;
    uint64 size;
    uint32 val_uint32;
    int64 val_int64;

    GS_RETURN_IFERR(cms_get_cms_home());
    g_cm_io_record_open = GS_TRUE;

    // get config info
    ret = snprintf_s(file_name, CMS_FILE_NAME_BUFFER_SIZE, CMS_MAX_FILE_NAME_LEN, "%s/cfg/%s", g_param.cms_home,
        CMS_CFG_FILENAME);
    PRTS_RETURN_IFERR(ret);

    config_t cfg;
    if (cm_load_config(g_cms_params, sizeof(g_cms_params) / sizeof(config_item_t), file_name, &cfg, GS_FALSE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    value = cm_get_config_value(&cfg, "NODE_ID");
    if (value == NULL || cm_str2uint64(value, &size) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_GSS_INVALID_PARAM, "invalid parameter value of 'NODE_ID'");
        return GS_ERROR;
    }

    if (size < 0 || size >= CMS_MAX_NODES) {
        GS_THROW_ERROR(ERR_GSS_INVALID_PARAM, "invalid parameter value[%lld] of 'NODE_ID'", size);
        return GS_ERROR;
    }

    g_param.node_id = (uint16)size;

    value = cm_get_config_value(&cfg, "GCC_HOME");
    if (value == NULL) {
        GS_THROW_ERROR(ERR_GSS_INVALID_PARAM, "invalid parameter value of 'GCC_HOME'");
        return GS_ERROR;
    }
    ret = strncpy_sp(g_param.gcc_home, CMS_FILE_NAME_BUFFER_SIZE, value, CMS_MAX_FILE_NAME_LEN);
    MEMS_RETURN_IFERR(ret);

    value = cm_get_config_value(&cfg, "GCC_TYPE");
    if (value == NULL || value[0] == '\0') {
        //g_param.gcc_type = CMS_DEV_TYPE_FILE;
        GS_RETURN_IFERR(cms_get_gcc_home_type(g_param.gcc_home, &g_param.gcc_type));
    } else {
        if (cm_strcmpi(value, "SD") == 0) {
            g_param.gcc_type = CMS_DEV_TYPE_SD;
        } else if (cm_strcmpi(value, "FILE") == 0) {
            g_param.gcc_type = CMS_DEV_TYPE_FILE;
        } else {
            CMS_LOG_ERR("invalid parameter value of 'GCC_TYPE':%s", value);
            GS_THROW_ERROR(ERR_GSS_INVALID_PARAM, "invalid parameter value of 'GCC_TYPE':%s", value);
            return GS_ERROR;
        }
    }

    value = cm_get_config_value(&cfg, "_LOG_BACKUP_FILE_COUNT");
    if (value == NULL || cm_str2uint32(value, &val_uint32) != GS_SUCCESS) {
        g_param.log_backup_file_count = 10;
    } else if (val_uint32 > GS_MAX_LOG_FILE_COUNT) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_LOG_BACKUP_FILE_COUNT", (int64)GS_MAX_LOG_FILE_COUNT);
        return GS_ERROR;
    } else {
        g_param.log_backup_file_count = val_uint32;
    }

    value = cm_get_config_value(&cfg, "_LOG_MAX_FILE_SIZE");
    if (value == NULL || cm_str2size(value, &val_int64) != GS_SUCCESS || val_int64 < 0) {
        g_param.max_log_file_size = CMS_LOGFILE_SIZE;
    } else {
        g_param.max_log_file_size = (uint64)val_int64;
    }

    value = cm_get_config_value(&cfg, "_LOG_LEVEL");
    if (value == NULL ||
       cm_str2int(value, &g_param.log_level) != GS_SUCCESS ||
       g_param.log_level < 0 ||
       g_param.log_level > 255) {
        g_param.log_level = CMS_LOG_LEVEL;
    }

    value = cm_get_config_value(&cfg, "WORKER_THREAD_COUNT");
    if (value == NULL) {
        g_param.worker_thread_count = CMS_DFT_WORKER_THREAD_COUNT;
    } else {
        if (cm_str2size(value, &val_int64) != GS_SUCCESS) {
            GS_THROW_ERROR(ERR_GSS_INVALID_PARAM, "invalid parameter value of 'WORKER_THREAD_COUNT':%s", value);
            return GS_ERROR;
        }

        if (val_int64 > CMS_MAX_WORKER_THREAD_COUNT || val_int64 < 1) {
            GS_THROW_ERROR(ERR_GSS_INVALID_PARAM, "invalid parameter value of 'WORKER_THREAD_COUNT':%,expect[1,%d]",
                value, CMS_MAX_WORKER_THREAD_COUNT);
            return GS_ERROR;
        }

        g_param.worker_thread_count = (uint32)val_int64;
    }

    value = cm_get_config_value(&cfg, "UDS_WORKER_THREAD_COUNT");
    if (value == NULL) {
        g_param.uds_worker_thread_count = CMS_DFT_WORKER_THREAD_COUNT;
    } else {
        if (cm_str2size(value, &val_int64) != GS_SUCCESS) {
            GS_THROW_ERROR(ERR_GSS_INVALID_PARAM, "invalid parameter value of 'UDS_WORKER_THREAD_COUNT':%s", value);
            return GS_ERROR;
        }

        if (val_int64 > CMS_MAX_WORKER_THREAD_COUNT || val_int64 < 1) {
            GS_THROW_ERROR(ERR_GSS_INVALID_PARAM, "invalid parameter value of 'UDS_WORKER_THREAD_COUNT':%,expect[1,%d]",
                value, CMS_MAX_WORKER_THREAD_COUNT);
            return GS_ERROR;
        }

        g_param.uds_worker_thread_count = (uint32)val_int64;
    }

    value = cm_get_config_value(&cfg, "_SPLIT_BRAIN");
    if (value == NULL || cm_strcmpi(value, "FALSE") == 0) {
        g_param.split_brain = CMS_OPEN_WITHOUT_SPLIT_BRAIN;
    } else if (cm_strcmpi(value, "TRUE") == 0) {
        g_param.split_brain = CMS_OPEN_WITH_SPLIT_BRAIN;
    } else {
        CMS_LOG_ERR("invalid parameter value of '_SPLIT_BRAIN':%s", value);
        GS_THROW_ERROR(ERR_GSS_INVALID_PARAM, "invalid parameter value of '_SPLIT_BRAIN':%s", value);
        return GS_ERROR;
    }

    value = cm_get_config_value(&cfg, "_DETECT_DISK_TIMEOUT");
    if (value == NULL || cm_str2uint32(value, &val_uint32) != GS_SUCCESS) {
        g_param.detect_disk_timeout = 3600; // The default timeout period is 3600 seconds.
    } else {
        g_param.detect_disk_timeout = val_uint32;
    }

    value = cm_get_config_value(&cfg, "_DISK_DETECT_FILE");
    if (value == NULL) {
        CMS_LOG_INF("cms disk detect file is NULL.");
    }
    if (cms_init_detect_file(value) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_GSS_INVALID_PARAM, "invalid parameter value of '_DISK_DETECT_FILE':%s", value);
        return GS_ERROR;
    }

    value = cm_get_config_value(&cfg, "_STOP_RERUN_CMS_SCRIPT");
    if (value != NULL) {
        ret = strncpy_sp(g_param.stop_rerun_script, CMS_FILE_NAME_BUFFER_SIZE, value, CMS_MAX_FILE_NAME_LEN);
        PRTS_RETURN_IFERR(ret);
    }

    value = cm_get_config_value(&cfg, "_EXIT_NUM_COUNT_FILE");
    if (value != NULL) {
        ret = strncpy_sp(g_param.exit_num_file, CMS_FILE_NAME_BUFFER_SIZE, value, CMS_MAX_FILE_NAME_LEN);
        PRTS_RETURN_IFERR(ret);
    }

    value = cm_get_config_value(&cfg, "_CMS_NODE_FAULT_THRESHOLD");
    if (value == NULL || cm_str2uint32(value, &val_uint32) != GS_SUCCESS) {
        g_param.cms_node_fault_thr = CMS_NODE_FAULT_THRESHOLD; // The default cms hb lost_cnt is 5 seconds.
    } else {
        g_param.cms_node_fault_thr = val_uint32;
    }

    value = cm_get_config_value(&cfg, "_CMS_GCC_BAK");
    if (value == NULL || cm_strcmpi(value, "NULL") == 0) {
        ret = strncpy_sp(g_param.cms_gcc_bak, CMS_FILE_NAME_BUFFER_SIZE, g_param.cms_home, CMS_PATH_BUFFER_SIZE);
        MEMS_RETURN_IFERR(ret);
    } else {
        ret = strncpy_sp(g_param.cms_gcc_bak, CMS_FILE_NAME_BUFFER_SIZE, value, CMS_MAX_FILE_NAME_LEN);
        MEMS_RETURN_IFERR(ret);
    }

    bool32 enable = GS_FALSE;
    value = cm_get_config_value(&cfg, "_USE_DBSTOR");
    if (value == NULL || cm_strcmpi(value, "FALSE") == 0) {
        enable = GS_FALSE;
        CMS_LOG_INF("DBStore is not enabled");
    } else if (cm_strcmpi(value, "TRUE") == 0) {
        enable = GS_TRUE;
    } else {
        CMS_LOG_ERR("invalid parameter value of '_USE_DBSTOR':%s", value);
        return GS_ERROR;
    }
    mes_set_dbstor_enable(enable);
    value = cm_get_config_value(&cfg, "_CLUSTER_ID");
    if (value == NULL) {
        CMS_LOG_ERR("invalid parameter of _CLUSTER_ID");
        return GS_ERROR;
    }
    ret = cms_get_value_is_valid(value, &val_uint32);
    MEMS_RETURN_IFERR(ret);

    if (enable) {
        if (set_all_inst_lsid(val_uint32, 1) != GS_SUCCESS) {
            CMS_LOG_ERR("cms generate lsid failed");
            return GS_ERROR;
        }
    } else {
        value = cm_get_config_value(&cfg, "SHARED_PATH");
        if (value == NULL) {
            CMS_LOG_ERR("invalid parameter value of 'SHARED_PATH'.");
            return GS_ERROR;
        }
        if (cm_set_file_iof_cfg(val_uint32, 1, value) != GS_SUCCESS) {
            CMS_LOG_ERR("cms set file iof cfg failed.");
            return GS_ERROR;
        }
    }
    cms_get_mes_config_value(&cfg);
    if (cms_get_mes_ssl_config(&cfg) != GS_SUCCESS) {
        return GS_ERROR;
    }

    GS_RETURN_IFERR(cms_get_dbstore_config_value(&cfg));
    return GS_SUCCESS;
}

status_t cms_init_detect_file(char *detect_file_all)
{
    if (strlen(detect_file_all) > CMS_MAX_DETECT_FILE_NAME) {
        printf("detect file is invalid, the file name is too long, len %lu", strlen(detect_file_all));
        return GS_ERROR;
    }
    char *gcc_file = "gcc_file";
    char gcc_dir[CMS_MAX_DETECT_FILE_NAME] = {0};
    if (cms_get_gcc_dir(gcc_dir, CMS_MAX_DETECT_FILE_NAME, gcc_file, strlen(gcc_file)) != GS_SUCCESS) {
        return GS_ERROR;
    }
    if (cms_get_detect_file(detect_file_all, strlen(detect_file_all), gcc_dir, strlen(gcc_file)) != GS_SUCCESS) {
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t cms_get_detect_file(char *detect_file_all, uint32 detect_file_all_len, char *gcc_dir, uint32 gcc_dir_len)
{
    char file_be_detected[CMS_MAX_DETECT_FILE_NAME] = {0};
    char *split_symbol = ",";
    char *buf = NULL;
    char *file_name = strtok_s(detect_file_all, split_symbol, &buf);
    int detect_file_mark = 0;
    if (file_name == NULL) {
        return GS_ERROR;
    }
    while (file_name) {
        errno_t ret_dir = strcpy_sp(file_be_detected, CMS_MAX_DETECT_FILE_NAME, gcc_dir);
        if (ret_dir != EOK) {
            return GS_ERROR;
        }
        errno_t ret_file = strcat_sp(file_be_detected, CMS_MAX_DETECT_FILE_NAME, file_name);
        if (ret_file != EOK) {
            return GS_ERROR;
        }
        if (g_cms_param->gcc_type == CMS_DEV_TYPE_FILE) {
            if (access(file_be_detected, 0) == -1) { // 0 indicates whether the file exists.
                return GS_ERROR;
            }
        }
        errno_t ret_detect_file =
            strcpy_sp(g_param.wait_detect_file[detect_file_mark], CMS_MAX_DETECT_FILE_NAME, file_be_detected);
        if (ret_detect_file != EOK) {
            return GS_ERROR;
        }
        file_name = strtok_s(NULL, split_symbol, &buf);
        detect_file_mark++;
    }
    g_param.wait_detect_file_num = detect_file_mark;
    return GS_SUCCESS;
}

status_t cms_get_gcc_dir(char *gcc_dir, uint32 gcc_dir_len, char *gcc_file, uint32 gcc_file_len)
{
    char *split_symbol = "/";
    char gcc_home[CMS_MAX_DETECT_FILE_NAME] = {0};
    errno_t ret_gcc_home = strcpy_sp(gcc_home, CMS_MAX_DETECT_FILE_NAME, g_cms_param->gcc_home);
    if (ret_gcc_home != EOK) {
        return GS_ERROR;
    }
    errno_t ret_gcc_dir = strcat_sp(gcc_dir, gcc_dir_len, split_symbol);
    if (ret_gcc_dir != EOK) {
        return GS_ERROR;
    }
    char *tmp_buf = NULL;
    char *file_dir = strtok_s(gcc_home, split_symbol, &tmp_buf);
    if (file_dir == NULL) {
        return GS_ERROR;
    }
    // Obtain the directory where the gcc_file file resides and save to gcc_dir.
    while (file_dir) {
        if (strcmp(file_dir, gcc_file) != 0) {
            errno_t ret_gcc_dir_tmp = strcat_sp(gcc_dir, gcc_dir_len, file_dir);
            errno_t ret_symbol = strcat_sp(gcc_dir, gcc_dir_len, split_symbol);
            if (ret_gcc_dir_tmp != EOK || ret_symbol != EOK) {
                return GS_ERROR;
            }
        }
        file_dir = strtok_s(NULL, split_symbol, &tmp_buf);
    }
    return GS_SUCCESS;
}

status_t cms_update_param(const char* param_name, const char* value)
{
    char file_name[CMS_FILE_NAME_BUFFER_SIZE];
    errno_t ret;

    GS_RETURN_IFERR(cms_get_cms_home());

    // get config info
    ret = snprintf_s(file_name, CMS_FILE_NAME_BUFFER_SIZE, CMS_MAX_FILE_NAME_LEN, "%s/cfg/%s", g_param.cms_home,
        CMS_CFG_FILENAME);
    PRTS_RETURN_IFERR(ret);

    config_t cfg;
    if (cm_load_config(g_cms_params, sizeof(g_cms_params) / sizeof(config_item_t), file_name,
        &cfg, GS_FALSE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    char* old_value = cm_get_config_value(&cfg, param_name);
    if (old_value == NULL || strcmp(old_value, value) != 0) {
        if (cm_alter_config(&cfg, param_name, value, CONFIG_SCOPE_DISK, GS_TRUE) != GS_SUCCESS) {
            CMS_LOG_ERR("set param failed:%s = %s,errno=%d,%s", param_name, value, errno, strerror(errno));
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}
