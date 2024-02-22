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
 * cms_param.c
 *
 *
 * IDENTIFICATION
 * src/cms/cms/cms_param.c
 *
 * -------------------------------------------------------------------------
 */
#include "cms_log_module.h"
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
#include "cm_kmc.h"
#include "cm_encrypt.h"
#include "cm_file_iofence.h"

config_item_t g_cms_params[] = {
    // name (30B)               isdefault readonly  defaultvalue value runtime_value description range        datatype
    // comment
    // -------------            --------- --------  ------------ ----- ------------- ----------- -----        --------
    // -----
    { "NODE_ID",                CT_TRUE,  ATTR_NONE, "",          NULL, NULL,          "-",       "-",        "CT_TYPE_INTEGER", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    { "GCC_TYPE",               CT_TRUE,  ATTR_NONE, "",          NULL, NULL,          "-",       "-",        "CT_TYPE_STRING",  NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    { "GCC_HOME",               CT_TRUE,  ATTR_NONE, "",          NULL, NULL,          "-",       "-",        "CT_TYPE_STRING",  NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    { "GCC_DIR",                CT_TRUE,  ATTR_NONE, "",          NULL, NULL,          "-",       "-",        "CT_TYPE_STRING",  NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    { "FS_NAME",                CT_TRUE,  ATTR_NONE, "",          NULL, NULL,          "-",       "-",        "CT_TYPE_STRING",  NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    { "CLUSTER_NAME",           CT_TRUE,  ATTR_NONE, "",          NULL, NULL,          "-",       "-",        "CT_TYPE_STRING",  NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    { "_IP",                    CT_TRUE,  ATTR_NONE, "",          NULL, NULL,          "-",       "-",        "CT_TYPE_STRING",  NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    { "_PORT",                  CT_TRUE,  ATTR_NONE, "",          NULL, NULL,          "-",       "-",        "CT_TYPE_STRING",  NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_LOG_BACKUP_FILE_COUNT",  CT_TRUE,  ATTR_NONE, "10",        NULL, NULL,          "-",       "[0,128]",  "CT_TYPE_INTEGER", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_AUDIT_BACKUP_FILE_COUNT", CT_TRUE,  ATTR_NONE, "10",        NULL, NULL,          "-",       "[0,128]",  "CT_TYPE_INTEGER", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_LOG_MAX_FILE_SIZE",      CT_TRUE,  ATTR_NONE, "10M",       NULL, NULL,          "-",       "[1M,4G]",  "CT_TYPE_INTEGER", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_AUDIT_MAX_FILE_SIZE",    CT_TRUE,  ATTR_NONE, "10M",       NULL, NULL,          "-",       "[1M,4G]",  "CT_TYPE_INTEGER", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_LOG_LEVEL",              CT_TRUE,  ATTR_NONE, "255",       NULL, NULL,          "-",       "[0,-)",    "CT_TYPE_INTEGER", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_LOG_FILE_PERMISSIONS",   CT_TRUE,  ATTR_NONE, "640",       NULL, NULL,          "-",       "[600-777]", "CT_TYPE_INTEGER", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_LOG_PATH_PERMISSIONS",   CT_TRUE,  ATTR_NONE, "750",       NULL, NULL,          "-",       "[700-777]", "CT_TYPE_INTEGER", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"WORKER_THREAD_COUNT",     CT_TRUE,  ATTR_NONE, "20",        NULL, NULL,          "-",       "[1,64]",   "CT_TYPE_INTEGER", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"UDS_WORKER_THREAD_COUNT", CT_TRUE,  ATTR_NONE, "20",        NULL, NULL,          "-",       "[1,64]",   "CT_TYPE_INTEGER", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_SPLIT_BRAIN",            CT_TRUE,  ATTR_NONE, "FALSE",     NULL, NULL,          "-",       "-",        "CT_TYPE_STRING",  NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_DETECT_DISK_TIMEOUT",    CT_TRUE,  ATTR_NONE, "3600",         NULL, NULL,          "-",       "-",        "CT_TYPE_INTEGER", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_DISK_DETECT_FILE",       CT_TRUE,  ATTR_NONE, "",          NULL, NULL,          "-",       "-",        "CT_TYPE_INTEGER", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_STOP_RERUN_CMS_SCRIPT",  CT_TRUE,  ATTR_NONE, "",          NULL, NULL,          "-",       "-",        "CT_TYPE_STRING",  NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_EXIT_NUM_COUNT_FILE",    CT_TRUE,  ATTR_NONE, "",          NULL, NULL,          "-",       "-",        "CT_TYPE_STRING",  NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_CMS_NODE_FAULT_THRESHOLD", CT_TRUE,  ATTR_NONE, "5",         NULL, NULL,          "-",       "-",        "CT_TYPE_INTEGER", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_CMS_MES_THREAD_NUM",     CT_TRUE,  ATTR_NONE, "5",         NULL, NULL,          "-",       "-",        "CT_TYPE_INTEGER", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_CMS_MES_MAX_SESSION_NUM", CT_TRUE,  ATTR_NONE, "40",       NULL, NULL,          "-",       "-",        "CT_TYPE_INTEGER", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_CMS_MES_MESSAGE_POOL_COUNT", CT_TRUE,  ATTR_NONE, "1",     NULL, NULL,          "-",       "-",        "CT_TYPE_INTEGER", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_CMS_MES_MESSAGE_QUEUE_COUNT", CT_TRUE,  ATTR_NONE, "1",    NULL, NULL,          "-",       "-",        "CT_TYPE_INTEGER", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_CMS_MES_MESSAGE_BUFF_COUNT", CT_TRUE,  ATTR_NONE, "4096",  NULL, NULL,          "-",       "-",        "CT_TYPE_INTEGER", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_CMS_MES_MESSAGE_CHANNEL_NUM", CT_TRUE,  ATTR_NONE, "1",    NULL, NULL,          "-",       "-",        "CT_TYPE_INTEGER", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_CMS_GCC_BAK",               CT_TRUE,  ATTR_NONE, "NULL",          NULL, NULL,          "-",       "-",        "CT_TYPE_STRING",  NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_USE_DBSTOR",            CT_TRUE,  ATTR_NONE, "FALSE",     NULL, NULL,          "-",       "-",        "CT_TYPE_STRING",  NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_DBSTOR_NAMESPACE",      CT_TRUE,  ATTR_NONE, "",          NULL, NULL,          "-",       "-",        "CT_TYPE_STRING",  NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_CMS_MES_PIPE_TYPE", CT_TRUE,  ATTR_NONE, "TCP",    NULL, NULL,          "-",       "-",        "CT_TYPE_STRING", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_CLUSTER_ID", CT_TRUE,  ATTR_NONE, "0",    NULL, NULL,          "-",       "-",        "CT_TYPE_INTEGER", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_CMS_MES_CRC_CHECK_SWITCH", CT_TRUE,  ATTR_NONE, "TRUE",    NULL, NULL,          "-",       "-",        "CT_TYPE_BOOLEAN", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_CMS_MES_SSL_SWITCH",        CT_TRUE,  ATTR_NONE, "FALSE",    NULL, NULL,       "-",       "-",        "CT_TYPE_BOOLEAN", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_CMS_MES_SSL_CRT_KEY_PATH",  CT_TRUE,  ATTR_NONE, "",         NULL, NULL,       "-",       "-",        "CT_TYPE_STRING",  NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_CMS_MES_SSL_KEY_PWD",       CT_TRUE,  ATTR_NONE, "",         NULL, NULL,       "-",       "-",         "CT_TYPE_STRING", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"KMC_KEY_FILES",           CT_TRUE,  ATTR_READONLY, "",         NULL, NULL,       "-",       "-",    "CT_TYPE_STRING",  NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"SHARED_PATH",          CT_TRUE,  ATTR_NONE, "",          NULL, NULL,          "-",       "-",        "CT_TYPE_STRING",  NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL},
};

cms_param_t  g_param;
const cms_param_t* g_cms_param = &g_param;

keyfile_item_t g_kmc_key_files[CT_KMC_MAX_KEYFILE_NUM];

status_t cms_get_cms_home(void)
{
    int32 is_home_exist;

    errno_t ret = strcpy_s(g_param.cms_home, sizeof(g_param.cms_home), getenv(CMS_ENV_CMS_HOME));
    if (ret != EOK) {
        return CT_ERROR;
    }

    is_home_exist = cm_dir_exist(g_param.cms_home);
    if (is_home_exist == CT_FALSE) {
        CT_THROW_ERROR(ERR_HOME_PATH_NOT_FOUND, CMS_ENV_CMS_HOME);
        return CT_ERROR;
    }
    is_home_exist = cm_check_exist_special_char(g_param.cms_home, (uint32)strlen(g_param.cms_home));
    if (is_home_exist == CT_TRUE) {
        CT_THROW_ERROR(ERR_INVALID_DIR, CMS_ENV_CMS_HOME);
        return CT_ERROR;
    }
    uint32 path_len = strlen(g_param.cms_home);
    if (path_len > CMS_MAX_PATH_LEN) {
        CT_THROW_ERROR(ERR_FILE_PATH_TOO_LONG, CMS_MAX_PATH_LEN);
        return CT_ERROR;
    }
    cm_trim_home_path(g_param.cms_home, path_len);

    return CT_SUCCESS;
}

status_t cms_get_gcc_home_type(const char* gcc_home, cms_dev_type_t* type)
{
    status_t ret;
#ifdef _WIN32
    struct _stat stat_buf;
    ret = _stat(gcc_home, &stat_buf);
    if (ret != 0) {
        CMS_LOG_ERR("stat failed.errno=%d,%s.", errno, strerror(errno));
        return CT_FALSE;
    }

    if (_S_IFREG == (stat_buf.st_mode & _S_IFREG)) {
        *type = CMS_DEV_TYPE_FILE;
    } else {
        CMS_LOG_ERR("gcc_home is not file.");
        return CT_ERROR;
    }
#else
    struct stat stat_buf;
    ret = stat(gcc_home, &stat_buf);
    if (ret != 0) {
        CMS_LOG_ERR("stat failed.errno=%d,%s.", errno, strerror(errno));
        return CT_FALSE;
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
            return CT_ERROR;
        }

        return cms_get_gcc_home_type(path, type);
    } else {
        CMS_LOG_ERR("gcc_home is not file,block device or symbol link.");
        return CT_ERROR;
    }
#endif

    return CT_SUCCESS;
}

static status_t cms_keyfile_config_prepare(void)
{
    text_t name;
    uint32 idx = 0;

    errno_t ret = snprintf_s(g_kmc_key_files[idx].name, CT_FILE_NAME_BUFFER_SIZE, CT_FILE_NAME_BUFFER_SIZE - 1,
        "%s/cms_protect/%s", g_cms_param->cms_home, CT_KMC_FILENAMEA);
    PRTS_RETURN_IFERR(ret);

    cm_str2text(g_kmc_key_files[idx].name, &name);
    cm_convert_os_path(&name);
    idx++;

    if (idx > CT_KMC_MAX_KEYFILE_NUM) {
        CT_LOG_RUN_ERR("[LOAD KMC KEYFILES ERROR]key idx more than CT_MAX_KEYFILE_NUM.");
        return CT_ERROR;
    }
    ret = snprintf_s(g_kmc_key_files[idx].name, CT_FILE_NAME_BUFFER_SIZE, CT_FILE_NAME_BUFFER_SIZE - 1,
        "%s/cms_protect/%s", g_cms_param->cms_home, CT_KMC_FILENAMEB);
    PRTS_RETURN_IFERR(ret);

    cm_str2text(g_kmc_key_files[idx].name, &name);
    cm_convert_os_path(&name);
    return CT_SUCCESS;
}

status_t cms_parse_keyfiles(text_t *value, char **files)
{
    text_t name;
    uint32 idx = 0;
    errno_t ret;
    while (CT_TRUE) {
        if (!cm_fetch_text(value, ',', '\0', &name)) {
            break;
        }

        if (idx == CT_KMC_MAX_KEYFILE_NUM) {
            CT_THROW_ERROR(ERR_INVALID_PARAMETER, "KMC_KEY_FILES");
            return CT_ERROR;
        }

        cm_trim_text(&name);
        if (name.str[0] == '\'') {
            name.str++;
            name.len -= CM_SINGLE_QUOTE_LEN;
            cm_trim_text(&name);
        }

        cm_convert_os_path(&name);
        ret = snprintf_s(files[idx], CT_FILE_NAME_BUFFER_SIZE, CT_FILE_NAME_BUFFER_SIZE - 1, "%s", T2S(&name));
        PRTS_RETURN_IFERR(ret);
        idx++;
    }

    return CT_SUCCESS;
}

status_t cms_update_keyfiles_config(config_t *cfg)
{
    char buf[CT_MAX_CONFIG_LINE_SIZE] = { 0 };
    text_t file_list = {
        .len = 0,
        .str = buf
    };
    text_t file_name;

    if (cm_concat_string(&file_list, CT_MAX_CONFIG_LINE_SIZE, "(") != CT_SUCCESS) {
        return CT_ERROR;
    }

    for (uint32 i = 0; i < CT_KMC_MAX_KEYFILE_NUM; i++) {
        cm_str2text(g_kmc_key_files[i].name, &file_name);
        cm_concat_text(&file_list, CT_MAX_CONFIG_LINE_SIZE, &file_name);
        if (i != CT_KMC_MAX_KEYFILE_NUM - 1) {
            if (cm_concat_string(&file_list, CT_MAX_CONFIG_LINE_SIZE, ", ") != CT_SUCCESS) {
                return CT_ERROR;
            }
        }
    }

    if (cm_concat_string(&file_list, CT_MAX_CONFIG_LINE_SIZE, ")\0") != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (cm_alter_config(cfg, "KMC_KEY_FILES", buf, CONFIG_SCOPE_MEMORY, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t cms_init_kmc(void)
{
    uint32 domain;
    if (cm_kmc_init(CT_SERVER, g_kmc_key_files[0].name, g_kmc_key_files[1].name) != CT_SUCCESS) {
        return CT_ERROR;
    }

    for (domain = CT_KMC_DOMAIN_BEGIN + 1; domain < CT_KMC_DOMAIN_END; domain++) {
        if (cm_kmc_init_domain(domain) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t cms_create_keyfiles_path(void)
{
    char path[CT_MAX_FILE_PATH_LENGH];
    uint32 idx;

    for (idx = 0; idx < CT_KMC_MAX_KEYFILE_NUM; idx++) {
        cm_trim_filename(g_kmc_key_files[idx].name, CT_MAX_FILE_PATH_LENGH, path);
        if (!cm_dir_exist(path)) {
            if (cm_create_dir(path) != CT_SUCCESS) {
                CT_LOG_RUN_ERR("failed to create keyfile dir %s,check if parent dir exist.error code %d", path, errno);
                return CT_ERROR;
            }
        }
    }

    return cms_init_kmc();
}

status_t cms_load_keyfiles(void)
{
    char file_name[CMS_FILE_NAME_BUFFER_SIZE];
    // get config info
    int ret = snprintf_s(file_name, CMS_FILE_NAME_BUFFER_SIZE, CMS_MAX_FILE_NAME_LEN, "%s/cfg/%s", g_param.cms_home,
        CMS_CFG_FILENAME);
    PRTS_RETURN_IFERR(ret);

    config_t cfg;
    if (cm_load_config(g_cms_params, sizeof(g_cms_params) / sizeof(config_item_t), file_name, &cfg, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    uint32 idx;
    text_t files;

    char *value = cm_get_config_value(&cfg, "KMC_KEY_FILES");
    char *key_files[CT_KMC_MAX_KEYFILE_NUM];

    if (CM_IS_EMPTY_STR(value)) {
        if (cms_keyfile_config_prepare() != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        cm_str2text(value, &files);
        cm_remove_brackets(&files);

        for (idx = 0; idx < CT_KMC_MAX_KEYFILE_NUM; idx++) {
            key_files[idx] = g_kmc_key_files[idx].name;
        }

        if (cms_parse_keyfiles(&files, key_files) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (cms_update_keyfiles_config(&cfg) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return cms_create_keyfiles_path();
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
        g_param.cms_mes_crc_check_switch = CT_TRUE;
    } else if (cm_strcmpi(switch_value, "FALSE") == 0) {
        g_param.cms_mes_crc_check_switch = CT_FALSE;
    } else {
        g_param.cms_mes_crc_check_switch = CT_TRUE;
    }
    CMS_LOG_INF("cms get mes config crc check switch is %d", g_param.cms_mes_crc_check_switch);
}

status_t cms_get_value_is_valid(char* value, uint32 *val_uint32)
{
    if (value == NULL || cm_str2uint32(value, val_uint32) != CT_SUCCESS) {
        return CT_ERROR;
    } else {
        return CT_SUCCESS;
    }
}

void cms_get_mes_config_value(config_t *cfg)
{
    uint32 val_uint32;
    status_t ret;

    char* value = cm_get_config_value(cfg, "_CMS_MES_THREAD_NUM");
    ret = cms_get_value_is_valid(value, &val_uint32);
    g_param.cms_mes_thread_num = val_uint32;
    if (ret != CT_SUCCESS) {
        g_param.cms_mes_thread_num = CMS_MES_THREAD_NUM;
    }

    value = cm_get_config_value(cfg, "_CMS_MES_MAX_SESSION_NUM");
    ret = cms_get_value_is_valid(value, &val_uint32);
    g_param.cms_mes_max_session_num = val_uint32;
    if (ret != CT_SUCCESS) {
        g_param.cms_mes_max_session_num = MES_MAX_SESSION_NUM;
    }

    value = cm_get_config_value(cfg, "_CMS_MES_MESSAGE_POOL_COUNT");
    ret = cms_get_value_is_valid(value, &val_uint32);
    g_param.cms_mes_msg_pool_count = val_uint32;
    if (ret != CT_SUCCESS) {
        g_param.cms_mes_msg_pool_count = MES_MESSAGE_POOL_COUNT;
    }

    value = cm_get_config_value(cfg, "_CMS_MES_MESSAGE_QUEUE_COUNT");
    ret = cms_get_value_is_valid(value, &val_uint32);
    g_param.cms_mes_msg_queue_count = val_uint32;
    if (ret != CT_SUCCESS) {
        g_param.cms_mes_msg_queue_count = MES_MESSAGE_QUEUE_COUNT;
    }

    value = cm_get_config_value(cfg, "_CMS_MES_MESSAGE_BUFF_COUNT");
    ret = cms_get_value_is_valid(value, &val_uint32);
    g_param.cms_mes_msg_buff_count = val_uint32;
    if (ret != CT_SUCCESS) {
        g_param.cms_mes_msg_buff_count = MES_MESSAGE_BUFF_COUNT;
    }

    value = cm_get_config_value(cfg, "_CMS_MES_MESSAGE_CHANNEL_NUM");
    ret = cms_get_value_is_valid(value, &val_uint32);
    g_param.cms_mes_msg_channel_num = val_uint32;
    if (ret != CT_SUCCESS) {
        g_param.cms_mes_msg_channel_num = MES_MESSAGE_CHANNEL_NUM;
    }

    cms_get_mes_str_config_value(cfg);
}

status_t cms_get_mes_ssl_config(config_t *cfg)
{
    char *ssl_switch_value = cm_get_config_value(cfg, "_CMS_MES_SSL_SWITCH");
    if (ssl_switch_value == NULL || cm_strcmpi(ssl_switch_value, "FALSE") == 0) {
        mes_set_ssl_switch(CT_FALSE);
    } else if (cm_strcmpi(ssl_switch_value, "TRUE") == 0) {
        mes_set_ssl_switch(CT_TRUE);
        char *ssl_crt_key_path = cm_get_config_value(cfg, "_CMS_MES_SSL_CRT_KEY_PATH");
        if (ssl_crt_key_path == NULL) {
            return CT_ERROR;
        }
        char ca_file_path[CT_FILE_NAME_BUFFER_SIZE];
        PRTS_RETURN_IFERR(snprintf_s(ca_file_path, CT_FILE_NAME_BUFFER_SIZE, CT_MAX_FILE_NAME_LEN, "%s/ca.crt", ssl_crt_key_path));
        char cert_file_path[CT_FILE_NAME_BUFFER_SIZE];
        PRTS_RETURN_IFERR(snprintf_s(cert_file_path, CT_FILE_NAME_BUFFER_SIZE, CT_MAX_FILE_NAME_LEN, "%s/mes.crt", ssl_crt_key_path));
        char key_file_path[CT_FILE_NAME_BUFFER_SIZE];
        PRTS_RETURN_IFERR(snprintf_s(key_file_path, CT_FILE_NAME_BUFFER_SIZE, CT_MAX_FILE_NAME_LEN, "%s/mes.key", ssl_crt_key_path));
        char crl_file_path[CT_FILE_NAME_BUFFER_SIZE];
        PRTS_RETURN_IFERR(snprintf_s(crl_file_path, CT_FILE_NAME_BUFFER_SIZE, CT_MAX_FILE_NAME_LEN, "%s/mes.crl", ssl_crt_key_path));
        CT_RETURN_IFERR(mes_set_ssl_crt_file(ca_file_path, cert_file_path, key_file_path, crl_file_path));
        mes_set_ssl_verify_peer(CT_TRUE);
        char *enc_pwd = cm_get_config_value(cfg, "_CMS_MES_SSL_KEY_PWD");
        CT_RETURN_IFERR(mes_set_ssl_key_pwd(enc_pwd));
    } else {
        mes_set_ssl_switch(CT_FALSE);
    }
    return CT_SUCCESS;
}

status_t cms_get_dbstore_config_value(config_t *cfg)
{
    char* value;
    status_t ret;
    bool32 enable = CT_FALSE;
    // dataPgSize is not used in the cms
    uint32 dataPgSize = CT_MAX_UINT32;

    value = cm_get_config_value(cfg, "_USE_DBSTOR");
    if (value == NULL || cm_strcmpi(value, "FALSE") == 0) {
        enable = CT_FALSE;
        CMS_LOG_INF("DBStore is not enabled");
        return cm_dbs_set_cfg(enable, dataPgSize, CT_DFLT_CTRL_BLOCK_SIZE, value, 0, CT_FALSE);
    } else if (cm_strcmpi(value, "TRUE") == 0) {
        enable = CT_TRUE;
    } else {
        CMS_LOG_ERR("invalid parameter value of '_USE_DBSTOR':%s", value);
        return CT_ERROR;
    }

    value = cm_get_config_value(cfg, "_DBSTOR_NAMESPACE");
    if (value == NULL) {
        CMS_LOG_ERR("invalid parameter value of '_DBSTOR_NAMESPACE'");
        return CT_ERROR;
    }
    ret = cm_dbs_set_cfg(enable, dataPgSize, CT_DFLT_CTRL_BLOCK_SIZE, value, 0, CT_FALSE);
    if (ret != CT_SUCCESS) {
        CMS_LOG_ERR("cms set dbstore config failed");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t cms_load_param(void)
{
    char file_name[CMS_FILE_NAME_BUFFER_SIZE];
    errno_t ret;
    char* value;
    uint64 size;
    uint32 val_uint32;
    int64 val_int64;

    CT_RETURN_IFERR(cms_get_cms_home());
    g_cm_io_record_open = CT_TRUE;

    // get config info
    ret = snprintf_s(file_name, CMS_FILE_NAME_BUFFER_SIZE, CMS_MAX_FILE_NAME_LEN, "%s/cfg/%s", g_param.cms_home,
        CMS_CFG_FILENAME);
    PRTS_RETURN_IFERR(ret);

    config_t cfg;
    if (cm_load_config(g_cms_params, sizeof(g_cms_params) / sizeof(config_item_t), file_name, &cfg, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    value = cm_get_config_value(&cfg, "NODE_ID");
    if (value == NULL || cm_str2uint64(value, &size) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_CTSTORE_INVALID_PARAM, "invalid parameter value of 'NODE_ID'");
        return CT_ERROR;
    }

    if (size < 0 || size >= CMS_MAX_NODES) {
        CT_THROW_ERROR(ERR_CTSTORE_INVALID_PARAM, "invalid parameter value[%lld] of 'NODE_ID'", size);
        return CT_ERROR;
    }

    g_param.node_id = (uint16)size;

    value = cm_get_config_value(&cfg, "FS_NAME");
    if (value == NULL) {
        CT_THROW_ERROR(ERR_CTSTORE_INVALID_PARAM, "invalid parameter value of 'FS_NAME'");
        return CT_ERROR;
    }
    ret = strncpy_sp(g_param.fs_name, CMS_FILE_NAME_BUFFER_SIZE, value, CMS_MAX_FILE_NAME_LEN);
    MEMS_RETURN_IFERR(ret);

    value = cm_get_config_value(&cfg, "GCC_HOME");
    if (value == NULL) {
        CT_THROW_ERROR(ERR_CTSTORE_INVALID_PARAM, "invalid parameter value of 'GCC_HOME'");
        return CT_ERROR;
    }
    ret = strncpy_sp(g_param.gcc_home, CMS_FILE_NAME_BUFFER_SIZE, value, CMS_MAX_FILE_NAME_LEN);
    MEMS_RETURN_IFERR(ret);

    value = cm_get_config_value(&cfg, "GCC_DIR");
    if (value == NULL) {
        CT_THROW_ERROR(ERR_CTSTORE_INVALID_PARAM, "invalid parameter value of 'GCC_DIR'");
        return CT_ERROR;
    }
    ret = strncpy_sp(g_param.gcc_dir, CMS_FILE_NAME_BUFFER_SIZE, value, CMS_MAX_FILE_NAME_LEN);
    MEMS_RETURN_IFERR(ret);

    value = cm_get_config_value(&cfg, "CLUSTER_NAME");
    if (value == NULL) {
        CT_THROW_ERROR(ERR_CTSTORE_INVALID_PARAM, "invalid parameter value of 'CLUSTER_NAME'");
        return CT_ERROR;
    }
    ret = strncpy_sp(g_param.cluster_name, CMS_FILE_NAME_BUFFER_SIZE, value, CMS_MAX_FILE_NAME_LEN);
    MEMS_RETURN_IFERR(ret);

    value = cm_get_config_value(&cfg, "GCC_TYPE");
    if (value == NULL || value[0] == '\0') {
        //g_param.gcc_type = CMS_DEV_TYPE_FILE;
        CT_RETURN_IFERR(cms_get_gcc_home_type(g_param.gcc_home, &g_param.gcc_type));
    } else {
        if (cm_strcmpi(value, "SD") == 0) {
            g_param.gcc_type = CMS_DEV_TYPE_SD;
        } else if (cm_strcmpi(value, "FILE") == 0) {
            g_param.gcc_type = CMS_DEV_TYPE_FILE;
        } else if (cm_strcmpi(value, "NFS") == 0) {
            g_param.gcc_type = CMS_DEV_TYPE_NFS;
        } else if (cm_strcmpi(value, "DBS") == 0) {
            g_param.gcc_type = CMS_DEV_TYPE_DBS;
        } else {
            CMS_LOG_ERR("invalid parameter value of 'GCC_TYPE':%s", value);
            CT_THROW_ERROR(ERR_CTSTORE_INVALID_PARAM, "invalid parameter value of 'GCC_TYPE':%s", value);
            return CT_ERROR;
        }
    }

    value = cm_get_config_value(&cfg, "_LOG_BACKUP_FILE_COUNT");
    if (value == NULL || cm_str2uint32(value, &val_uint32) != CT_SUCCESS) {
        g_param.log_backup_file_count = 10;
    } else if (val_uint32 > CT_MAX_LOG_FILE_COUNT) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_LOG_BACKUP_FILE_COUNT", (int64)CT_MAX_LOG_FILE_COUNT);
        return CT_ERROR;
    } else {
        g_param.log_backup_file_count = val_uint32;
    }

    value = cm_get_config_value(&cfg, "_LOG_MAX_FILE_SIZE");
    if (value == NULL || cm_str2size(value, &val_int64) != CT_SUCCESS || val_int64 < 0) {
        g_param.max_log_file_size = CMS_LOGFILE_SIZE;
    } else {
        g_param.max_log_file_size = (uint64)val_int64;
    }

    value = cm_get_config_value(&cfg, "_LOG_LEVEL");
    if (value == NULL ||
       cm_str2int(value, &g_param.log_level) != CT_SUCCESS ||
       g_param.log_level < 0 ||
       g_param.log_level > 255) {
        g_param.log_level = CMS_LOG_LEVEL;
    }

    value = cm_get_config_value(&cfg, "WORKER_THREAD_COUNT");
    if (value == NULL) {
        g_param.worker_thread_count = CMS_DFT_WORKER_THREAD_COUNT;
    } else {
        if (cm_str2size(value, &val_int64) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_CTSTORE_INVALID_PARAM, "invalid parameter value of 'WORKER_THREAD_COUNT':%s", value);
            return CT_ERROR;
        }

        if (val_int64 > CMS_MAX_WORKER_THREAD_COUNT || val_int64 < 1) {
            CT_THROW_ERROR(ERR_CTSTORE_INVALID_PARAM, "invalid parameter value of 'WORKER_THREAD_COUNT':%,expect[1,%d]",
                value, CMS_MAX_WORKER_THREAD_COUNT);
            return CT_ERROR;
        }

        g_param.worker_thread_count = (uint32)val_int64;
    }

    value = cm_get_config_value(&cfg, "UDS_WORKER_THREAD_COUNT");
    if (value == NULL) {
        g_param.uds_worker_thread_count = CMS_DFT_WORKER_THREAD_COUNT;
    } else {
        if (cm_str2size(value, &val_int64) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_CTSTORE_INVALID_PARAM, "invalid parameter value of 'UDS_WORKER_THREAD_COUNT':%s", value);
            return CT_ERROR;
        }

        if (val_int64 > CMS_MAX_WORKER_THREAD_COUNT || val_int64 < 1) {
            CT_THROW_ERROR(ERR_CTSTORE_INVALID_PARAM, "invalid parameter value of 'UDS_WORKER_THREAD_COUNT':%,expect[1,%d]",
                value, CMS_MAX_WORKER_THREAD_COUNT);
            return CT_ERROR;
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
        CT_THROW_ERROR(ERR_CTSTORE_INVALID_PARAM, "invalid parameter value of '_SPLIT_BRAIN':%s", value);
        return CT_ERROR;
    }

    value = cm_get_config_value(&cfg, "_DETECT_DISK_TIMEOUT");
    if (value == NULL || cm_str2uint32(value, &val_uint32) != CT_SUCCESS) {
        g_param.detect_disk_timeout = 3600; // The default timeout period is 3600 seconds.
    } else {
        g_param.detect_disk_timeout = val_uint32;
    }

    value = cm_get_config_value(&cfg, "_DISK_DETECT_FILE");
    if (value == NULL) {
        CMS_LOG_INF("cms disk detect file is NULL.");
    }
    ret = strncpy_sp(g_param.detect_file, CMS_FILE_NAME_BUFFER_SIZE, value, CMS_MAX_FILE_NAME_LEN);
    MEMS_RETURN_IFERR(ret);

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
    if (value == NULL || cm_str2uint32(value, &val_uint32) != CT_SUCCESS) {
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

    bool32 enable = CT_FALSE;
    value = cm_get_config_value(&cfg, "_USE_DBSTOR");
    if (value == NULL || cm_strcmpi(value, "FALSE") == 0) {
        enable = CT_FALSE;
        CMS_LOG_INF("DBStore is not enabled");
    } else if (cm_strcmpi(value, "TRUE") == 0) {
        enable = CT_TRUE;
        cms_set_recv_timeout();
    } else {
        CMS_LOG_ERR("invalid parameter value of '_USE_DBSTOR':%s", value);
        return CT_ERROR;
    }
    mes_set_dbstor_enable(enable);
    value = cm_get_config_value(&cfg, "_CLUSTER_ID");
    if (value == NULL) {
        CMS_LOG_ERR("invalid parameter of _CLUSTER_ID");
        return CT_ERROR;
    }
    ret = cms_get_value_is_valid(value, &val_uint32);
    MEMS_RETURN_IFERR(ret);

    if (!enable) {
        value = cm_get_config_value(&cfg, "SHARED_PATH");
        if (value == NULL) {
            CMS_LOG_ERR("invalid parameter value of 'SHARED_PATH'.");
            return CT_ERROR;
        }
        if (cm_set_file_iof_cfg(val_uint32, 1, value) != CT_SUCCESS) {
            CMS_LOG_ERR("cms set file iof cfg failed.");
            return CT_ERROR;
        }
    }
    cms_get_mes_config_value(&cfg);
    if (cms_get_mes_ssl_config(&cfg) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (g_param.cms_mes_pipe_type == CS_TYPE_UC || g_param.cms_mes_pipe_type == CS_TYPE_UC_RDMA || enable) {
        CT_RETURN_IFERR(set_all_inst_lsid(val_uint32, 1));
    }

    CT_RETURN_IFERR(cms_get_dbstore_config_value(&cfg));
    return CT_SUCCESS;
}

status_t cms_init_detect_file(char *detect_file_all)
{
    if (strlen(detect_file_all) > CMS_MAX_DETECT_FILE_NAME) {
        printf("detect file is invalid, the file name is too long, len %lu", strlen(detect_file_all));
        return CT_ERROR;
    }
    char *gcc_file = "gcc_file";
    char gcc_dir[CMS_MAX_DETECT_FILE_NAME] = {0};
    if (cms_get_gcc_dir(gcc_dir, CMS_MAX_DETECT_FILE_NAME, gcc_file, strlen(gcc_file)) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (cms_get_detect_file(detect_file_all, strlen(detect_file_all), gcc_dir, strlen(gcc_file)) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (cms_open_detect_file() != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t cms_get_detect_file(char *detect_file_all, uint32 detect_file_all_len, char *gcc_dir, uint32 gcc_dir_len)
{
    char file_be_detected[CMS_MAX_DETECT_FILE_NAME] = {0};
    char *split_symbol = ",";
    char *buf = NULL;
    char *file_name = strtok_s(detect_file_all, split_symbol, &buf);
    int detect_file_mark = 0;
    if (file_name == NULL) {
        return CT_ERROR;
    }
    while (file_name) {
        errno_t ret_dir = strcpy_sp(file_be_detected, CMS_MAX_DETECT_FILE_NAME, gcc_dir);
        if (ret_dir != EOK) {
            return CT_ERROR;
        }
        errno_t ret_file = strcat_sp(file_be_detected, CMS_MAX_DETECT_FILE_NAME, file_name);
        if (ret_file != EOK) {
            return CT_ERROR;
        }
        if (g_cms_param->gcc_type == CMS_DEV_TYPE_FILE) {
            if (access(file_be_detected, 0) == -1) { // 0 indicates whether the file exists.
                return CT_ERROR;
            }
        }
        errno_t ret_detect_file =
            strcpy_sp(g_param.wait_detect_file[detect_file_mark], CMS_MAX_DETECT_FILE_NAME, file_be_detected);
        if (ret_detect_file != EOK) {
            return CT_ERROR;
        }
        file_name = strtok_s(NULL, split_symbol, &buf);
        detect_file_mark++;
    }
    g_param.wait_detect_file_num = detect_file_mark;
    return CT_SUCCESS;
}

status_t cms_get_gcc_dir(char *gcc_dir, uint32 gcc_dir_len, char *gcc_file, uint32 gcc_file_len)
{
    char *split_symbol = "/";
    char gcc_home[CMS_MAX_DETECT_FILE_NAME] = {0};
    errno_t ret_gcc_home = strcpy_sp(gcc_home, CMS_MAX_DETECT_FILE_NAME, g_cms_param->gcc_home);
    if (ret_gcc_home != EOK) {
        return CT_ERROR;
    }
    errno_t ret_gcc_dir = strcat_sp(gcc_dir, gcc_dir_len, split_symbol);
    if (ret_gcc_dir != EOK) {
        return CT_ERROR;
    }
    char *tmp_buf = NULL;
    char *file_dir = strtok_s(gcc_home, split_symbol, &tmp_buf);
    if (file_dir == NULL) {
        return CT_ERROR;
    }
    // Obtain the directory where the gcc_file file resides and save to gcc_dir.
    while (file_dir) {
        if (strcmp(file_dir, gcc_file) != 0) {
            errno_t ret_gcc_dir_tmp = strcat_sp(gcc_dir, gcc_dir_len, file_dir);
            errno_t ret_symbol = strcat_sp(gcc_dir, gcc_dir_len, split_symbol);
            if (ret_gcc_dir_tmp != EOK || ret_symbol != EOK) {
                return CT_ERROR;
            }
        }
        file_dir = strtok_s(NULL, split_symbol, &tmp_buf);
    }
    return CT_SUCCESS;
}

status_t cms_update_param(const char* param_name, const char* value)
{
    char file_name[CMS_FILE_NAME_BUFFER_SIZE];
    errno_t ret;

    CT_RETURN_IFERR(cms_get_cms_home());

    // get config info
    ret = snprintf_s(file_name, CMS_FILE_NAME_BUFFER_SIZE, CMS_MAX_FILE_NAME_LEN, "%s/cfg/%s", g_param.cms_home,
        CMS_CFG_FILENAME);
    PRTS_RETURN_IFERR(ret);

    config_t cfg;
    if (cm_load_config(g_cms_params, sizeof(g_cms_params) / sizeof(config_item_t), file_name,
        &cfg, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    char* old_value = cm_get_config_value(&cfg, param_name);
    if (old_value == NULL || strcmp(old_value, value) != 0) {
        if (cm_alter_config(&cfg, param_name, value, CONFIG_SCOPE_DISK, CT_TRUE) != CT_SUCCESS) {
            CMS_LOG_ERR("set param failed:%s = %s,errno=%d,%s", param_name, value, errno, strerror(errno));
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}
